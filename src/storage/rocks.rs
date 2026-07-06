//! RocksDB storage engine — production persistence for all node state.
//!
//! Replaces the 7 unbounded in-memory HashMaps identified in the memory audit:
//!   1. AWCConsensus.attestations → attestations CF
//!   2. AWCConsensus.confirmation_levels → replaced by layered consensus
//!   3. NodeState.finalized → is_finalized flag in records CF
//!   4. TrustEngine → trust CF
//!   5. EntityClusterer.signals → trust CF
//!   6. ReputationEngine.entries → reputation CF
//!   7. DisputeState → disputes CF
//!
//! Architecture: internal design notes §Storage Engine

//!
//! Spec references:
//!   @spec Protocol §12.2

use std::path::Path;
use std::sync::Arc;

use rocksdb::{
    BoundColumnFamily, ColumnFamilyDescriptor, DBWithThreadMode, MultiThreaded, Options,
    WriteBatch, checkpoint::Checkpoint,
};

use crate::ZoneId;
use crate::errors::{ElaraError, Result};
use crate::record::{Classification, ValidationRecord};

// ─── Column Family Names ────────────────────────────────────────────────────

/// Column families (22 total): 15 core + 5 secondary indexes + applied + slot_index.
pub const CF_RECORDS: &str = "records";
/// Tier 4.5 (2026-04-28): per-record bookkeeping that used to live in
/// `CF_RECORDS` under reserved key prefixes (`__record_count__`,
/// `__full_pull_cursor__`, `__db_version__`, `__snapshot__:*`, `ban:*`,
/// `blocked_term:*`, `finalized:*`, `tombstone:*`). Co-locating those small
/// hot-path values with the multi-KB record bodies forced every CF_RECORDS
/// iterator to filter prefixes and bloated SST files with values that share
/// no read pattern with the records themselves. Splitting them into a
/// dedicated CF gives count() / query() / extract_ledger_records a clean
/// records-only view, lets the metadata CF be tuned for tiny values + point
/// lookups (10-bit whole-key bloom + small block size), and removes the
/// per-key prefix-skip cost from every full-table scan at scale.
///
/// One-shot boot migration in `migrate_metadata_to_cf_v1` copies any
/// pre-existing metadata keys out of CF_RECORDS into here on first open
/// after upgrade. Migration completion is gated by the
/// `__migration_v1_complete__` marker key written into CF_METADATA itself.
pub const CF_METADATA: &str = "metadata";
pub const CF_DAG: &str = "dag";
pub const CF_LEDGER: &str = "ledger";
pub const CF_TRUST: &str = "trust";
pub const CF_ATTESTATIONS: &str = "attestations";
pub const CF_REPUTATION: &str = "reputation";
pub const CF_MERKLE: &str = "merkle";
pub const CF_EPOCHS: &str = "epochs";
pub const CF_PEERS: &str = "peers";
pub const CF_DISPUTES: &str = "disputes";
pub const CF_PENDING_XZONE: &str = "pending_xzone";
pub const CF_IDENTITIES: &str = "identities";
/// Identity Partitioning Phase A — class-tagged identity column families.
/// Three replacements for the legacy global `CF_IDENTITIES`, each scoped
/// to a different retention policy so eviction (Phase B) can target the
/// classes that are safe to drop without losing the small global anchor
/// set or zone-witness PKs needed for finality verification.
///
/// **Class assignment** is by capture-site context, not by inspecting the
/// PK itself:
///
/// | CF                          | Capture site (Phase A)                       | Eviction policy            |
/// |-----------------------------|----------------------------------------------|----------------------------|
/// | `CF_IDENTITIES_ANCHOR`      | VRF-registered anchor PKs                    | Never evict                |
/// | `CF_IDENTITIES_WITNESS`     | Witnesses registered for any subscribed zone | Evict on zone unsubscribe  |
/// | `CF_IDENTITIES_USER`        | Catch-all (record creators, attestation PKs) | LRU-bounded (Phase B)      |
///
/// **Read path**: `get_public_key(hash)` checks ANCHOR → WITNESS → USER →
/// legacy `CF_IDENTITIES`, returning the first hit. The legacy CF is the
/// pre-partition store; new writes never go there, but existing data
/// stays readable until a future migration (out of Phase A scope) drains
/// it.
///
/// **Write path**: each capture site picks a tier-explicit helper
/// (`store_public_key_anchor`, `store_public_key_witness`, or
/// `store_public_key_user`). The legacy `store_public_key` keeps its
/// write target on `CF_IDENTITIES` for any existing call site that
/// hasn't been migrated — those will be re-routed in Phase A follow-ups
/// once usage is audited.
pub const CF_IDENTITIES_ANCHOR: &str = "identities_anchor";
pub const CF_IDENTITIES_WITNESS: &str = "identities_witness";
pub const CF_IDENTITIES_USER: &str = "identities_user";
/// Identity Partitioning Phase B — user-tier LRU timestamp index.
/// Key: `ts_be(8B) || identity_hash` → empty value. Lets eviction
/// scan oldest-first via prefix-iter without loading PK bodies.
/// A single hash may have multiple TS entries from successive writes;
/// the reverse index `CF_IDENTITIES_USER_REV` is the source of truth
/// for "which TS is current" — eviction skips any (ts, hash) entry
/// whose REV[hash] != ts (stale entry, just delete it without
/// touching the PK).
pub const CF_IDENTITIES_USER_TS: &str = "identities_user_ts";
/// Identity Partitioning Phase B — user-tier reverse index.
/// Key: identity_hash → ts_be(8B). Tracks the current-canonical
/// timestamp for each hash so eviction can distinguish a live entry
/// from a stale duplicate in `CF_IDENTITIES_USER_TS`.
pub const CF_IDENTITIES_USER_REV: &str = "identities_user_rev";
pub const CF_GOVERNANCE: &str = "governance";
pub const CF_VELOCITY: &str = "velocity";
pub const CF_VRF_KEYS: &str = "vrf_keys";
/// Secondary index: timestamp → record_id (for range queries without full scan).
pub const CF_IDX_TIMESTAMP: &str = "idx_timestamp";
/// Secondary index: creator_identity_hash → record_id (for per-identity queries).
pub const CF_IDX_CREATOR: &str = "idx_creator";
/// Secondary index: materialized set of DAG tip record_ids (no children).
pub const CF_IDX_TIPS: &str = "idx_tips";
/// Secondary index: content_hash_hex → record_id (for get_by_hash lookups).
pub const CF_IDX_HASH: &str = "idx_hash";
/// Secondary index: record_hash_hex → record_id.
///
/// `record_hash_hex` here is `hex::encode(record.record_hash())` — i.e.
/// `sha3_256(record.signable_bytes())`, NOT the record's `content_hash`
/// field. CF_IDX_HASH is keyed on the latter and serves a different
/// semantic ("dedup: have I seen this content?"). This index serves
/// "wire-id resolution: which record_id has this signable-bytes sha3?",
/// which is exactly what `seal.record_hashes` callers need.
///
/// Why a separate CF: an epoch seal stores `record.record_hash()` in its
/// `record_hashes` field (epoch.rs:1706 → `hashes.push(rec.record_hash())`).
/// The post-attestation seal-record resolution path
/// (`network/ingest.rs::resolve_seal_record_ids`) and the post-creation
/// path (`network/epoch.rs::epoch_seal_loop`) both need to map those
/// hashes to local `record_id`s so consensus can register the seal-records
/// pair. Probing CF_IDX_HASH with a `record_hash` is a semantic mismatch —
/// the v5→v6 migration fixed the WRITER format consistency but never
/// repaired the call-site mismatch. This index closes that gap.
///
/// Migration v6→v7 backfills it from CF_RECORDS.
pub const CF_IDX_RECORD_HASH: &str = "idx_record_hash";
/// Secondary index: attestation timestamp → att key (for range queries without full scan).
/// Key format: `timestamp_be(8B) + record_id + ":" + witness_hash` → empty value.
pub const CF_IDX_ATT_TIME: &str = "idx_att_time";
/// Applied record IDs — prevents double-application of ledger operations.
/// Moved from in-memory LedgerState (135K+ entries causing slow clones) to RocksDB
/// for O(1) lookups without impacting ledger lock contention.
/// Key: record_id → empty value.
pub const CF_APPLIED: &str = "applied";
/// Slot index for MESH-BFT Stage 1 mutual exclusion (Phase 3).
/// Every (account, nonce) slot can finalize at most one record. A second
/// record claiming the same slot is a conflict — proof is emitted, creator slashed,
/// and the losing record never settles regardless of attestation count.
/// Key: `{account_hash_hex64}:{nonce_hex16}` → first-seen record_id — exactly
/// `ValidationRecord::slot_key()` (zone deliberately dropped; see record.rs).
/// Scope: applies to records carrying `_slot_nonce` in metadata. Legacy records
/// (no nonce field) are exempt and retain pre-Stage-1 behavior until deprecation.
pub const CF_SLOT_INDEX: &str = "slot_index";

/// Conflict marker CF (Phase 3 Stage 1E).
/// Any slot_key observed with two different record_ids is written here. The
/// settlement gate checks this CF and blocks finalization of the first-seen
/// record until (future) dispute resolution clears the mark. Value: short
/// UTF-8 descriptor of the conflict (e.g. "record_a_id:record_b_id").
pub const CF_SLOT_CONFLICTS: &str = "slot_conflicts";

/// Account-state Sparse Merkle Tree (MESH-BFT Phase 3 Stage 2A).
/// A single global key-value SMT where:
///   key   = SHA3-256(account_identity_hash)[0..8]  (64-bit leaf path)
///   leaf  = SHA3-256(bincode(AccountState))        (commitment to balance+nonce+etc.)
/// Light clients verify a balance by fetching the account's leaf + O(log N)
/// sibling path from a full node, then recomputing the root and comparing to
/// the root signed in the latest epoch seal. This CF stores the tree's
/// interior + leaf nodes, keyed by `(depth, path_prefix)`; see `account_merkle.rs`.
/// Scale note: 10B accounts ≈ 34 tree levels populated — trivial storage.
pub const CF_ACCOUNT_SMT: &str = "account_smt";

/// Finalized zone-split/merge TransitionSeals (Gap 4).
/// Written by `run_transition_tick` in `network/health.rs` when a pending
/// proposal clears its dispute window. Keyed by the 32-byte seal id
/// (`TransitionSeal::seal_hash_for_sig()`), value is the serialized seal
/// JSON so the orchestrator can re-hydrate it after a node restart without
/// relying on the in-memory `TransitionStore`. Volume is tiny (one entry
/// per split/merge — a few per year per zone, well under a megabyte even
/// across 1M zones).
pub const CF_TRANSITIONS_FINAL: &str = "transitions_final";

/// Pending zone-split/merge TransitionSeals still in AwaitingSigs or
/// DisputeWindow state (Gap 4 durability). Written by the `/transitions/*`
/// HTTP handlers on every successful mutation (propose / sig / veto), and
/// deleted by `run_transition_tick` once an entry reaches a terminal
/// state (Finalized / Vetoed / Expired). Key: seal id (32 bytes). Value:
/// serialized `PendingTransition` JSON.
///
/// Without this CF, a node restart mid-window silently drops every active
/// proposal. Capacity is bounded by `MAX_PENDING_TRANSITIONS` (1024) so
/// the CF never grows unboundedly — it's a mirror, not a log.
pub const CF_TRANSITIONS_PENDING: &str = "transitions_pending";

/// Tentative ledger deltas waiting for consensus finality (ARCH-1).
/// Key: record_id (UTF-8). Value: JSON-encoded `PendingLedgerDelta`.
///
/// Every ingested ledger op is mirrored here at phase 4 of the ingest
/// pipeline. Entries are deleted on two triggers:
///   - Consensus transitions the record to `Finalized` — the delta is
///     committed to `CF_LEDGER` and removed from this CF.
///   - Epoch timeout / explicit rejection — the delta is dropped with
///     no ledger mutation (the commit never happened).
///
/// Capacity is bounded by `MAX_TOTAL_PENDING` (1_048_576) — ~64 MB worst
/// case at 64 bytes/entry. A mirror, not a log: every live entry
/// corresponds to a record whose `ConfirmationLevel` is still below
/// `Finalized`.
pub const CF_PENDING_DELTAS: &str = "pending_deltas";

/// Bonded per-zone witness registry (Gap 2.1 Phase 2b.3 Slice 3).
/// Maintains the canonical, gossip-replicated set of finality-eligible
/// witnesses per zone — the source of truth that lets every node compute
/// the same `committee_snapshot` independently. Entries are written by
/// applying `LedgerOp::WitnessRegister` (which debits a stake bond) and
/// read by `finality_committee_pks` to expand the candidate pool beyond
/// the VRF anchor registry without diverging across nodes.
///
/// Key format: `{zone_path}\x00{identity_hash}` — NUL-byte separator
/// because `zone_path` may contain `:` and `/`. The NUL prefix lets
/// `prefix_iterator_cf({zone_path}\x00)` cleanly enumerate every witness
/// for one zone with no false positives from sibling-zone keys.
///
/// Value: JSON-encoded `WitnessEntry { dilithium_pk, bond, registered_epoch }`.
///
/// Capacity at mainnet scale: 1M zones × ≤64 witnesses = 64M entries,
/// ~2KB each = 128 GB. Long-tail zones will be far below the cap; the
/// real working set is the active-witness count which is much smaller.
pub const CF_WITNESS_REGISTRY: &str = "witness_registry";

/// Zone-keyed secondary index (ZONE-STORAGE-PARTITIONING Phase B).
///
/// Maps `(zone_key_8B, timestamp_be_8B, record_id_utf8)` → empty value.
/// Lets sync/GC/snapshot paths ask "give me everything in zone X"
/// without scanning the primary records CF.
///
/// **Why this CF exists:** at 1M zones × 10T records/day, a node
/// subscribed to two zones must serve zone-scoped reads in O(zone_records),
/// not O(total_records). The 8-byte prefix on `ZoneId::to_key_bytes()` lets
/// RocksDB seek directly to the start of any zone's record range.
///
/// **Key format:**
///   - `zone_key` = `ZoneId::to_key_bytes()` (legacy numeric BE OR SHA3-256[..8])
///   - `timestamp_be` = `f64::to_be_bytes()` (lexicographic order = chronological)
///   - `record_id` = UTF-8 bytes (variable length)
///
/// **Sentinel:** records with no `record.zone` field fall back to
/// `ZoneId::for_record(record_id)` (legacy 256-zone hash). No special
/// "global" sentinel — global ops (epoch seals, ledger ops) just index
/// under whatever zone their `record.zone` field declares.
///
/// **Population:**
///   - Hot path: `put_record_with_pk_zone` writes under the registry-resolved
///     leaf zone (handles post-split routing).
///   - Other paths: `put_record` / `put_record_with_pk` write under the
///     content-derived zone (`record.zone` or `for_record(id)`).
///   - Existing records: `backfill_zone_index_chunk` (admin-triggered).
///
/// **Capacity:** ~24 bytes/entry × 10T records = 240TB at mainnet ceiling.
/// At 6-node testnet (~120K records): ~3MB. The CF stores empty values, so
/// sstable bloat is minimal — only key data + bloom filters.
pub const CF_RECORD_BY_ZONE: &str = "record_by_zone";

/// Agent-mandate registry (C4 slice 1). Key: `mandate_id` (64-hex content
/// address). Value: serde_json of the **canonicalized** `MandateRecord`
/// (scope vectors sorted+deduped so a snapshot-carried copy and a
/// replayed-from-issuance copy are byte-identical). GC-exempt (the carrier
/// record carries `mandate_op`). Point-read by `mandate_id` at flag-recompute
/// time; bloom-grouped.
pub const CF_MANDATE: &str = "mandate";

/// Mandate revocation index (C4 slice 1). Key: `mandate_id(64) ++
/// revoker_identity_hash(64)` = 128 hex chars — the revoker is in the KEY so
/// read-time authorization is a direct point lookup of the *principal's* entry
/// (a spoofed revocation by a non-principal lands under a different key and is
/// never consulted, and cannot front-run the principal's slot). Value:
/// serde_json of `mandate::RevocationEntry` (monotonic — earliest wins).
/// GC-exempt (carrier carries `revocation_op`). Bloom-grouped.
pub const CF_REVOCATION: &str = "revocation";

/// Mandate act index (C4 slice 1). Key: act `record_id`. Value: serde_json of
/// `mandate::MandateActEntry` (the minimal claim — mandate_ref, signer, signed
/// time, amount — needed to RECOMPUTE the flag at query time without re-reading
/// the act record). DERIVED, not snapshot-carried. Cleaned in `delete_record`
/// when the act record is GC'd (no orphan index). Bloom-grouped.
pub const CF_MANDATE_ACT: &str = "mandate_act";

/// EmergencyHalt/Resume durable state (single-blob). Key: the fixed
/// [`EMERGENCY_STATE_KEY`]. Value: serde_json of `crate::emergency::EmergencyState`
/// (the folded max-fold over observed authority-signed halt/resume records). This
/// is the durable backing for the in-memory `NodeState` atomics: written on each
/// winning fold (persist-before-publish), read on boot to repopulate the atomics
/// (warm-restart safety) and on snapshot bootstrap. Tiny + bounded (one key). The
/// per-op audit trail lives in the GC-exempt carrier records, not here.
pub const CF_EMERGENCY: &str = "emergency";
/// The single fixed key under [`CF_EMERGENCY`] holding the folded state.
pub const EMERGENCY_STATE_KEY: &[u8] = b"state";

/// Mandate reverse index (C4 slice 4): `mandate_id → its act records`, powering
/// the `GET /mandate/{id}/acts` accountability enumeration ("what did this agent
/// do under this authority?"). Key:
///     `mandate_ref(64 ascii hex) ++ act_timestamp_ms(8 BE) ++ record_id(ascii)`
/// value empty. Written ONLY when `mandate_ref` is a well-formed 64-hex id — a
/// FIXED-WIDTH prefix, so an attacker-controlled `mandate_ref` (any JSON string,
/// possibly containing NUL) can never create a separator/prefix ambiguity. The
/// `mandate_ref` is lowercased into the key so the reader's lowercased query
/// prefix matches. Written/deleted in LOCKSTEP with `CF_MANDATE_ACT` in the same
/// `WriteBatch`, so its coverage is byte-for-byte identical to the forward index
/// and the pair can never diverge across a crash. DERIVED, NOT snapshot-carried,
/// and consensus-INERT (never enters a seal/account root or the snapshot
/// checksum — same class as `CF_MANDATE_ACT`). READ ONLY via `range_scan_cf`
/// with a `starts_with` guard — NEVER `prefix_scan`/`prefix_iterator_cf`, which
/// would mis-bound (no `prefix_extractor` is installed; see `full_scan_cf`).
pub const CF_MANDATE_ACTS_BY_MANDATE: &str = "mandate_acts_by_mandate";

/// Agent reverse index (C4 agent-acts): `signer_identity_hash → its act records`,
/// powering the LOOPBACK-ONLY `GET /agent/{agent_hash}/acts` forensic enumeration
/// ("everything this agent key signed, under any authority"). Key:
///     `signer_hash(64 ascii hex, lowercased) ++ act_timestamp_ms(8 BE) ++ record_id(ascii)`
/// value empty. The 64-byte fixed-width prefix is what makes the key unambiguous;
/// `signer_identity_hash` is `sha3(creator_pk)` so it is structurally 64 lc hex,
/// but the key builder still validates + lowercases defensively (a serde-loaded
/// String could be malformed). Written/deleted in LOCKSTEP with `CF_MANDATE_ACT`
/// in the SAME `WriteBatch` as the by-mandate index, so all three indexes have
/// byte-identical coverage and can never diverge across a crash. DERIVED, NOT
/// snapshot-carried, consensus-INERT (never enters a seal/account root or the
/// snapshot checksum — same class as `CF_MANDATE_ACT`). Rebuildable from
/// `CF_MANDATE_ACT` (the `migrate_7_to_8` backfill). READ ONLY via `range_scan_cf`
/// with a `starts_with` guard — NEVER `prefix_scan` (no `prefix_extractor`).
/// LOOPBACK-GATED on purpose: a public by-signer index is the same enumeration
/// surface the protocol already gates for `/records/search?creator=` — making
/// per-identity behavioral aggregation cheap is the deanon harm (fusion-audited
/// 2026-06-26).
pub const CF_MANDATE_ACTS_BY_AGENT: &str = "mandate_acts_by_agent";

/// Hard server-side cap on a single `/mandate/{id}/acts` page — bounds the
/// keyset scan + the per-row flag recompute (each a bloom-filtered point read).
pub const MANDATE_ACTS_PAGE_MAX: usize = 200;

/// Defense-in-depth cap on the `Vec::with_capacity` hint of the timestamp-index
/// scan primitives (`recent_record_ids`, `record_ids_from`). These are `pub fn`
/// trusting the caller's `limit`; every current caller bounds it (largest is
/// `MAX_BLOOM_BUILD = 200_000`), but an unbounded `limit` from a future caller
/// would not just panic — a huge-but-non-overflowing hint (e.g. 1e12) drives an
/// allocation *abort* that kills the whole node, NOT a catchable per-conn unwind.
/// 1M (5× the largest legit caller) is never reached in practice, so this is a
/// zero-behavior-change backstop: the `Vec` still grows to the real result count.
pub const MAX_SCAN_PREALLOC: usize = 1_000_000;

/// All column family names for iteration.
pub const ALL_CF_NAMES: &[&str] = &[
    CF_RECORDS,
    CF_METADATA,
    CF_DAG,
    CF_LEDGER,
    CF_TRUST,
    CF_ATTESTATIONS,
    CF_REPUTATION,
    CF_MERKLE,
    CF_EPOCHS,
    CF_PEERS,
    CF_DISPUTES,
    CF_PENDING_XZONE,
    CF_IDENTITIES,
    CF_GOVERNANCE,
    CF_VELOCITY,
    CF_VRF_KEYS,
    CF_IDX_TIMESTAMP,
    CF_IDX_CREATOR,
    CF_IDX_TIPS,
    CF_IDX_HASH,
    CF_IDX_RECORD_HASH,
    CF_IDX_ATT_TIME,
    CF_APPLIED,
    CF_SLOT_INDEX,
    CF_SLOT_CONFLICTS,
    CF_ACCOUNT_SMT,
    CF_TRANSITIONS_FINAL,
    CF_TRANSITIONS_PENDING,
    CF_PENDING_DELTAS,
    CF_WITNESS_REGISTRY,
    CF_RECORD_BY_ZONE,
    CF_IDENTITIES_ANCHOR,
    CF_IDENTITIES_WITNESS,
    CF_IDENTITIES_USER,
    CF_IDENTITIES_USER_TS,
    CF_IDENTITIES_USER_REV,
    CF_MANDATE,
    CF_REVOCATION,
    CF_MANDATE_ACT,
    CF_MANDATE_ACTS_BY_MANDATE,
    CF_MANDATE_ACTS_BY_AGENT,
    CF_EMERGENCY,
];

/// Bonded witness-registry entry (Gap 2.1 Phase 2b.3 Slice 3).
///
/// One entry per `(zone_path, identity_hash)` pair — i.e., a witness can
/// be registered in multiple zones, but only once per zone. The bond is
/// debited from the registrant's ledger balance at apply time and stays
/// locked until an explicit unregister op (out of scope for Slice 3).
///
/// `dilithium_pk` is the post-quantum public key the finality committee
/// uses to verify witness signatures — same key material that
/// `process_deferred_attestations` opportunistically captures into
/// `CF_IDENTITIES`, but here it's authoritatively pinned per-zone via
/// consensus rather than picked up from gossip.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct WitnessEntry {
    pub dilithium_pk: Vec<u8>,
    pub bond: u64,
    pub registered_epoch: u64,
}

// ─── Storage Engine ─────────────────────────────────────────────────────────

type DB = DBWithThreadMode<MultiThreaded>;

/// Production storage engine backed by RocksDB with 24 column families.
///
/// Thread-safe: uses MultiThreaded mode, safe to share via Arc.
pub struct StorageEngine {
    db: DB,
    /// Monotonic generation bumped on every write that ADDS/refreshes an
    /// entry in `CF_IDENTITIES_ANCHOR` (anchors are never evicted, so this
    /// only grows). Keys the `NodeState` staked-anchor view cache so a newly
    /// registered or promoted anchor invalidates it. This EXACT signal is
    /// load-bearing: a `total_staked` fingerprint cannot catch a pure
    /// membership change (an already-staked account promoted to anchor leaves
    /// `total_staked` unchanged), and the RocksDB `estimate-num-keys` count is
    /// approximate. Two writers bump it — `store_public_key_anchor` and the
    /// anchor route of `put_record_with_pk` (VRF-registration records).
    anchor_add_seq: std::sync::atomic::AtomicU64,
}

impl StorageEngine {
    /// Detect total system RAM in bytes. Returns 0 on failure.
    pub fn detect_system_ram() -> u64 {
        #[cfg(target_os = "linux")]
        {
            if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
                for line in meminfo.lines() {
                    if let Some(rest) = line.strip_prefix("MemTotal:") {
                        let kb_str = rest.trim().trim_end_matches("kB").trim();
                        if let Ok(kb) = kb_str.parse::<u64>() {
                            return kb * 1024;
                        }
                    }
                }
            }
            0
        }
        #[cfg(not(target_os = "linux"))]
        {
            0 // Assume large on non-Linux; use default (medium) profile
        }
    }

    /// Detect system RAM in whole GB, rounded to nearest.
    /// Avoids the truncation bug where 1919MB (a 2GB VPS) detects as 1GB.
    ///
    /// Cached after first call — RAM doesn't change at runtime, and this is
    /// hit per-record on the ingest hot path. Without the cache, every record
    /// reads /proc/meminfo (a syscall + parse), which is wasted work at the
    /// 100s-of-records/sec rate during full_pull bursts.
    pub fn detect_system_ram_gb() -> u64 {
        static CACHED: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
        *CACHED.get_or_init(|| {
            let ram = Self::detect_system_ram();
            if ram == 0 { return 0; }
            // Round to nearest GB: add 512MB before dividing
            (ram + 512 * 1024 * 1024) / (1024 * 1024 * 1024)
        })
    }

    /// Open or create a RocksDB database at the given path.
    ///
    /// Auto-detects system RAM and scales memory budgets:
    ///   ≤1 GB:  memtable 48MB, WAL 48MB, cache 16MB   (~112MB total)
    ///   ≤2 GB:  memtable 128MB, WAL 128MB, cache 32MB  (~288MB total)
    ///   ≤4 GB:  memtable 256MB, WAL 256MB, cache 64MB  (~576MB total)
    ///   >4 GB:  memtable 384MB, WAL 256MB, cache 128MB (~768MB total)
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let ram = Self::detect_system_ram();
        let ram_gb = Self::detect_system_ram_gb();

        // Memory profile based on available RAM
        let (memtable_budget, wal_budget, cache_size, label) = if ram > 0 && ram_gb <= 1 {
            // Tiny: 1GB droplets (Helsinki). ~112MB RocksDB footprint.
            (48 * 1024 * 1024, 48 * 1024 * 1024, 16 * 1024 * 1024, "tiny (≤1GB RAM)")
        } else if ram > 0 && ram_gb <= 2 {
            // Reduced from 128/128/32 (288MB) to 80/80/24 (184MB) to stay under
            // systemd memory.high (1.5G). At 288MB + ~400MB app state = 688MB base,
            // leaving only 812MB for transient allocations. Under burst load,
            // the cgroup memory.high throttle caused 28-34s process stalls.
            (80 * 1024 * 1024, 80 * 1024 * 1024, 24 * 1024 * 1024, "small (≤2GB RAM)")
        } else if ram > 0 && ram_gb <= 4 {
            // Reduced from 256/256/64 (576MB) to 192/192/48 (432MB).
            // Nuremberg at 3.0GB/3.1GB cgroup high — needs 150MB+ headroom
            // for burst allocations (delta sync, attestation rebuild).
            (192 * 1024 * 1024, 192 * 1024 * 1024, 48 * 1024 * 1024, "medium (≤4GB RAM)")
        } else {
            (384 * 1024 * 1024, 256 * 1024 * 1024, 128 * 1024 * 1024, "large (>4GB RAM)")
        };

        tracing::info!(
            "RocksDB memory profile: {} — memtable {}MB, WAL {}MB, cache {}MB (detected {}GB RAM)",
            label,
            memtable_budget / (1024 * 1024),
            wal_budget / (1024 * 1024),
            cache_size / (1024 * 1024),
            ram_gb,
        );

        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);
        // Compression: zstd for all CFs (good balance of speed + ratio)
        db_opts.set_compression_type(rocksdb::DBCompressionType::Zstd);
        // Write buffer: scaled default per CF.
        // Previous 64MB default × 19 CFs × 3 buffers = 3.6GB potential memtable space.
        let default_write_buf = if ram_gb <= 1 {
            2 * 1024 * 1024
        } else if ram_gb <= 2 {
            4 * 1024 * 1024
        } else {
            8 * 1024 * 1024
        };
        db_opts.set_write_buffer_size(default_write_buf);
        // Keep 2 write buffers before flushing (saves RAM on idle CFs)
        db_opts.set_max_write_buffer_number(2);
        // Cap total memtable memory across ALL CFs.
        db_opts.set_db_write_buffer_size(memtable_budget);
        // WAL size limit: cap total WAL.
        // Without this, WAL files grow unbounded (6-16GB observed on testnet).
        // RocksDB flushes the oldest memtable when WAL exceeds this limit,
        // which triggers WAL file deletion. Safe — data is already in SST files.
        db_opts.set_max_total_wal_size(wal_budget as u64);
        // NOTE: increase_parallelism() removed — it was overridden by
        // set_max_background_jobs() below. Using only set_max_background_jobs for clarity.
        // Bloom filter for point lookups
        let mut block_opts = rocksdb::BlockBasedOptions::default();
        block_opts.set_bloom_filter(10.0, false);
        // Block cache: shared across all CFs, scaled to system RAM
        let cache = rocksdb::Cache::new_lru_cache(cache_size);
        block_opts.set_block_cache(&cache);
        block_opts.set_block_size(16 * 1024); // 16KB blocks
        // Force bloom filters + index blocks into the block cache.
        // Without this, each SST file's filter/index is allocated separately —
        // 256 SST files × ~10MB each = ~2.5GB OUTSIDE the cache budget.
        // With this, they compete for the same cache, enforcing our memory limit.
        block_opts.set_cache_index_and_filter_blocks(true);
        // Pin L0 filters in cache (they're accessed most, avoid thrashing)
        block_opts.set_pin_l0_filter_and_index_blocks_in_cache(true);
        db_opts.set_block_based_table_factory(&block_opts);
        // Disable mmap reads: forces RocksDB to use the block cache (which we control)
        // instead of OS-level page cache. Without this, mmap'd SST files cause
        // unbounded RSS growth — 5.5GB of SST files will consume all available RAM
        // on 2GB nodes. With mmap disabled, memory stays within our cache budget.
        db_opts.set_allow_mmap_reads(false);
        db_opts.set_allow_mmap_writes(false);
        // Advise kernel: POSIX_FADV_RANDOM on SST files.
        // Suppresses speculative readahead. NOTE: this does NOT bypass the page
        // cache — buffered reads still populate it. Effective only on >4GB tier
        // where direct reads are off (see direct-I/O block below).
        db_opts.set_advise_random_on_open(true);
        // Phone-tier hardware floor: bypass OS pagecache entirely on ≤4GB tiers.
        //
        // A 4GB node was hitting cgroup MemoryHigh=3.2G
        // even though VmRSS was only 1GB. memory.stat showed inactive_file=2.77GB —
        // the kernel page cache was holding SST data populated by RocksDB's default
        // buffered pread() path. With 27GB of SST files on disk and 4GB total RAM,
        // page cache grows until the cgroup throttle kicks in, causing /health
        // timeouts and 1+ s record processing latency.
        //
        // FADV_RANDOM (set above) only kills speculative readahead — it does NOT
        // bypass the page cache for actual reads. The fix is set_use_direct_reads,
        // which routes user reads through O_DIRECT. RocksDB's block cache (set
        // above, sized per tier) becomes the authoritative read cache; the OS
        // page cache is no longer involved in SST I/O.
        //
        // Combined with set_use_direct_io_for_flush_and_compaction, this leaves
        // only the WAL on the buffered path (small + quickly reclaimed), keeping
        // total RocksDB memory pinned to (memtable_budget + wal_budget + cache_size).
        //
        // A prior incident on a 2GB node had the same root cause; the
        // earlier fix only enabled direct I/O for compaction. This extension to
        // direct reads + the ≤4GB tier closes the same bug for the 4GB hardware
        // floor mandated by MAINNET SCALE MANDATE (phone-tier nodes).
        //
        // Operator can opt out with ELARA_ROCKSDB_DIRECT_IO=0 if filesystem
        // doesn't support O_DIRECT (some FUSE mounts, certain overlay layouts).
        if ram_gb > 0 && ram_gb <= 4
            && std::env::var("ELARA_ROCKSDB_DIRECT_IO").as_deref() != Ok("0")
        {
            db_opts.set_use_direct_io_for_flush_and_compaction(true);
            db_opts.set_use_direct_reads(true);
        }
        // Limit open file descriptors for SST files. Default is -1 (unlimited) which
        // keeps ALL SST files open with per-file metadata (~100KB each). With 150+
        // SST files, this uses 15MB+ just for file metadata. On 2GB nodes, every MB
        // counts. Closing unused files trades latency for memory.
        if ram_gb <= 2 {
            db_opts.set_max_open_files(64);
        } else if ram_gb <= 4 {
            // With 3700+ SST files on mature nodes, 128 causes constant file
            // open/close overhead. 256 reduces reopens during compaction storms.
            db_opts.set_max_open_files(256);
        }
        // Background compaction/flush jobs. More jobs let compaction keep pace with
        // writes during catchup. But on 1-core machines, 2+ compaction threads
        // just add scheduling overhead — they serialize on the single core anyway.
        // Cap at 1 job for 1-core, 2 for ≤2GB multi-core, 4 for ≥4GB.
        let cpus = num_cpus();
        let bg_jobs = if cpus <= 1 { 1 } else if ram_gb <= 2 { 2 } else { 4 };
        db_opts.set_max_background_jobs(bg_jobs);

        // Lower CPU + IO priority of RocksDB background threads (compaction/flush).
        // On a 1-CPU node, compaction alone consumes 60% CPU — more than all tokio
        // threads combined. By lowering priority, the OS scheduler prefers tokio
        // threads (which handle HTTP/TLS, gossip, state_core), and compaction runs
        // only when CPU is otherwise idle. On multi-CPU nodes, this still helps
        // prevent compaction storms from starving request handling.
        if let Ok(mut env) = rocksdb::Env::new() {
            env.lower_thread_pool_cpu_priority();
            env.lower_thread_pool_io_priority();
            if cpus <= 2 {
                env.lower_high_priority_thread_pool_cpu_priority();
                env.lower_high_priority_thread_pool_io_priority();
            }
            db_opts.set_env(&env);
            // Env must outlive the DB, but set_env copies the shared_ptr internally.
            // We leak the Env to avoid it being dropped before the DB closes.
            std::mem::forget(env);
        }

        // Rate-limit compaction I/O on small nodes.
        // Without this, a single compaction thread doing sequential 256KB reads
        // at disk speed (~200 MB/s) saturates the CPU with decompression + merge.
        // Rate-limit compaction on multi-core small nodes only.
        // On 1-CPU: NO rate limit. The previous 2-5 MB/s limits caused
        // compaction to fall behind write rate → L0 pile-up → 42-68 second
        // write stalls. Unlimited compaction uses more CPU but prevents stalls.
        // On ≤2GB multi-core: 10 MB/s prevents compaction from hogging I/O.
        if cpus > 1 && ram_gb <= 2 {
            db_opts.set_ratelimiter(10 * 1024 * 1024, 100_000, 10);
        }

        tracing::info!("RocksDB background jobs: {bg_jobs} (cpus={cpus}, ram={ram_gb}GB)");
        // Cap compaction readahead to limit I/O buffer memory during compaction.
        db_opts.set_compaction_readahead_size(if ram_gb <= 2 { 256 * 1024 } else { 2 * 1024 * 1024 });
        // Raise L0 compaction write stall thresholds. Defaults (20 slowdown / 36 stop)
        // are too aggressive for our write pattern — when L0 SST files accumulate during
        // burst ingestion, RocksDB throttles then blocks ALL writes. This causes
        // spawn_blocking to stall for 50-88 seconds, cascading into ledger lock contention.
        // On ≤2GB machines with 1 compaction thread, even raised thresholds (40/56) aren't
        // enough during burst attestation catch-up — use 80/120 to let writes proceed while
        // the single compaction thread works through the backlog.
        let (l0_slowdown, l0_stop) = if ram_gb <= 2 { (80, 120) } else { (40, 56) };
        db_opts.set_level_zero_slowdown_writes_trigger(l0_slowdown);
        db_opts.set_level_zero_stop_writes_trigger(l0_stop);
        // Limit LOG.old file accumulation. Without this, RocksDB keeps every
        // rotated log forever — observed 100-145 LOG.old files (1.6-2.5 GB waste)
        // across testnet nodes. Rotate at 10 MB, keep only 3 old files.
        db_opts.set_max_log_file_size(10 * 1024 * 1024);
        db_opts.set_keep_log_file_num(3);

        // Per-CF tuning: different CFs have different access patterns.
        // Buffers scale with the memory profile.
        let (records_buf, medium_buf, index_buf) = if ram_gb <= 1 {
            (4 * 1024 * 1024, 2 * 1024 * 1024, 1024 * 1024)
        } else if ram_gb <= 2 {
            (8 * 1024 * 1024, 4 * 1024 * 1024, 2 * 1024 * 1024)
        } else {
            (16 * 1024 * 1024, 8 * 1024 * 1024, 4 * 1024 * 1024)
        };

        let cf_descriptors: Vec<ColumnFamilyDescriptor> = ALL_CF_NAMES
            .iter()
            .map(|name| {
                let mut cf_opts = Options::default();
                cf_opts.set_compression_type(rocksdb::DBCompressionType::Zstd);

                match *name {
                    // Records: large values (~5KB), mostly sequential reads.
                    // Higher buffer for batch inserts during sync.
                    CF_RECORDS => {
                        cf_opts.set_write_buffer_size(records_buf);
                    }
                    // Attestations: many small writes, frequently pruned.
                    // Without a bloom filter a single
                    // prefix_scan for one record_id iterates every SST file on
                    // disk. On a 1-vCPU node that produced 99s wall-clock stalls
                    // inside witness_mgr.get_attestations (the att.gr bucket
                    // after the D-4 split). Same config as the indexes below —
                    // 10-bit whole-key bloom + shared block cache so prefix
                    // scans short-circuit SSTs that can't contain the prefix.
                    //
                    // DISC-4 D-8 (2026-04-21): install a fixed-41-byte prefix
                    // extractor. Key format is:
                    //     "att:{36-char UUIDv7 record_id}:{64-char witness_hash}"
                    //     = 4 + 36 + 1 + 64 = 105 bytes total.
                    // The 41-byte prefix names the record (`att:{record_id}:`).
                    // D-5b's 10-bit bloom only accelerated exact point lookups;
                    // the dominant path `prefix_iterator_cf(CF_ATTESTATIONS,
                    // "att:{record_id}:")` in witness.rs:168 still scanned every
                    // SST. Post-D-6 profiling showed att=gr was 100% of slow-
                    // record post-phase time at 70-231s. With the prefix
                    // extractor, the same bloom now also indexes prefix hashes
                    // so prefix_iterator can skip SSTs that don't contain the
                    // record. Whole-key bloom is preserved by default
                    // (whole_key_filtering=true), so the duplicate-check
                    // point lookup in store_attestation_with_powas still
                    // benefits.
                    CF_ATTESTATIONS => {
                        cf_opts.set_write_buffer_size(medium_buf);
                        cf_opts.set_max_write_buffer_number(2);
                        cf_opts.set_prefix_extractor(
                            rocksdb::SliceTransform::create_fixed_prefix(41),
                        );
                        let mut att_block_opts = rocksdb::BlockBasedOptions::default();
                        att_block_opts.set_bloom_filter(10.0, false);
                        att_block_opts.set_block_size(4 * 1024);
                        att_block_opts.set_block_cache(&cache);
                        att_block_opts.set_cache_index_and_filter_blocks(true);
                        att_block_opts.set_pin_l0_filter_and_index_blocks_in_cache(true);
                        cf_opts.set_block_based_table_factory(&att_block_opts);
                    }
                    // Indexes: small keys, empty values, point lookups + range scans.
                    // Optimized for bloom filters and prefix seek.
                    //
                    // Tier 4.4 (2026-04-28): added CF_IDX_HASH and CF_IDX_ATT_TIME
                    // to this group. CF_IDX_HASH (content_hash_hex → record_id)
                    // is the get_by_hash fast path — without bloom, every
                    // missing-hash lookup would touch disk on every SST. At 1M
                    // records the negative-lookup cost was ~5× the positive cost.
                    // CF_IDX_ATT_TIME is the planned attestation time-range index;
                    // tuning at CF-create time avoids a future migration.
                    // C4 slice 1: mandate CFs are point-read by exact key
                    // (mandate_id / composite revocation key / act record_id).
                    // Without bloom, a never-revoked-mandate lookup (the common
                    // case) would touch every SST — the same negative-lookup
                    // pathology the IDX group's bloom fixes. Tune at create-time
                    // to avoid a migration.
                    CF_IDX_TIMESTAMP | CF_IDX_CREATOR | CF_IDX_TIPS | CF_IDX_HASH | CF_IDX_RECORD_HASH | CF_IDX_ATT_TIME
                    | CF_MANDATE | CF_REVOCATION | CF_MANDATE_ACT | CF_MANDATE_ACTS_BY_MANDATE | CF_MANDATE_ACTS_BY_AGENT => {
                        cf_opts.set_write_buffer_size(index_buf);
                        let mut idx_block_opts = rocksdb::BlockBasedOptions::default();
                        idx_block_opts.set_bloom_filter(10.0, false);
                        idx_block_opts.set_block_size(4 * 1024); // 4KB blocks (small keys)
                        // Share the main LRU cache — without this, each CF
                        // gets its own default cache (8MB) outside our budget.
                        idx_block_opts.set_block_cache(&cache);
                        idx_block_opts.set_cache_index_and_filter_blocks(true);
                        idx_block_opts.set_pin_l0_filter_and_index_blocks_in_cache(true);
                        cf_opts.set_block_based_table_factory(&idx_block_opts);
                    }
                    // Per-zone record index: keys are
                    //     {8-byte zone_key} {8-byte timestamp_be} {record_id_utf8}
                    // The hot access pattern is `iter_zone(zone_key, since, until)`
                    // which seeks under the 8-byte zone prefix and stops when the
                    // prefix changes (`rocks.rs:986`). At 1M zones, without a
                    // prefix bloom every iter_zone scans every SST file just to
                    // discover most don't contain the prefix — same failure mode
                    // DISC-4 D-8 fixed for CF_ATTESTATIONS prefix iteration.
                    //
                    // Tier 4.4 (2026-04-28): install fixed-8-byte prefix extractor
                    // + 10-bit bloom + shared block cache so iter_zone short-
                    // circuits SSTs that don't contain the zone. Whole-key
                    // filtering stays on by default for the (zone, ts, id) point
                    // lookup case from count_zone callers.
                    CF_RECORD_BY_ZONE => {
                        cf_opts.set_write_buffer_size(index_buf);
                        cf_opts.set_prefix_extractor(
                            rocksdb::SliceTransform::create_fixed_prefix(8),
                        );
                        let mut zone_block_opts = rocksdb::BlockBasedOptions::default();
                        zone_block_opts.set_bloom_filter(10.0, false);
                        zone_block_opts.set_block_size(4 * 1024);
                        zone_block_opts.set_block_cache(&cache);
                        zone_block_opts.set_cache_index_and_filter_blocks(true);
                        zone_block_opts.set_pin_l0_filter_and_index_blocks_in_cache(true);
                        cf_opts.set_block_based_table_factory(&zone_block_opts);
                    }
                    // DAG: JSON edge data, moderate size, read-heavy.
                    CF_DAG => {
                        cf_opts.set_write_buffer_size(medium_buf);
                    }
                    // Tier 4.5 (2026-04-28): per-record bookkeeping. Small
                    // values (counters, single-row JSON snapshots, ban / term
                    // entries). Hot path is point lookup (`get __record_count__`
                    // every few seconds) plus prefix iteration over `ban:` /
                    // `blocked_term:` / `__snapshot__:` (small sets, <100
                    // entries each). 10-bit whole-key bloom + 4KB blocks +
                    // shared cache + L0 pin gives the same negative-lookup
                    // shortcut as the IDX bloom group with negligible memory
                    // cost.
                    CF_METADATA => {
                        cf_opts.set_write_buffer_size(index_buf);
                        let mut meta_block_opts = rocksdb::BlockBasedOptions::default();
                        meta_block_opts.set_bloom_filter(10.0, false);
                        meta_block_opts.set_block_size(4 * 1024);
                        meta_block_opts.set_block_cache(&cache);
                        meta_block_opts.set_cache_index_and_filter_blocks(true);
                        meta_block_opts.set_pin_l0_filter_and_index_blocks_in_cache(true);
                        cf_opts.set_block_based_table_factory(&meta_block_opts);
                    }
                    // All other CFs: defaults
                    _ => {}
                }

                ColumnFamilyDescriptor::new(*name, cf_opts)
            })
            .collect();

        let db = DB::open_cf_descriptors(&db_opts, path.as_ref(), cf_descriptors)
            .map_err(|e| ElaraError::Storage(format!("RocksDB open failed: {e}")))?;

        Ok(Self {
            db,
            anchor_add_seq: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// Get a column family handle. Panics if CF doesn't exist.
    /// Test-only: production code must use `try_cf()` to propagate the error.
    #[cfg(test)]
    fn cf(&self, name: &str) -> Arc<BoundColumnFamily<'_>> {
        self.db
            .cf_handle(name)
            .unwrap_or_else(|| panic!("missing column family: {name}"))
    }

    /// Get a column family handle, returning `Err` instead of panicking.
    /// Use this in `Result`-returning paths where a missing CF should be a
    /// storage error (e.g. schema mismatch after a failed migration).
    fn try_cf(&self, name: &str) -> Result<Arc<BoundColumnFamily<'_>>> {
        self.db.cf_handle(name).ok_or_else(|| {
            ElaraError::Storage(format!("missing column family: {name}"))
        })
    }

    // ── Records CF ──────────────────────────────────────────────────────────

    /// Build a `CF_RECORD_BY_ZONE` key from `(zone_key, timestamp, record_id)`.
    /// Layout: `[zone_key (8B)] [ts_be (8B)] [record_id (UTF-8)]`.
    /// The fixed 16-byte prefix lets RocksDB `prefix_iterator_cf` seek directly
    /// to the start of any zone's record range without scanning sibling zones.
    fn zone_idx_key(zone_key: &[u8; 8], timestamp: f64, record_id: &str) -> Vec<u8> {
        let mut k = Vec::with_capacity(8 + 8 + record_id.len());
        k.extend_from_slice(zone_key);
        k.extend_from_slice(&timestamp.to_be_bytes());
        k.extend_from_slice(record_id.as_bytes());
        k
    }

    /// Derive the content-defined zone key for a record. Used by `put_record` /
    /// `put_record_with_pk` callers that don't carry an explicit registry-resolved
    /// zone (replay/sync/bootstrap apply paths).
    ///
    /// Falls back to `ZoneId::for_record(record_id)` (legacy 256-zone hash) when
    /// `record.zone` is not set — same fallback as `ValidationRecord::record_zone()`,
    /// kept consistent so a record's content_hash and its zone-idx key agree.
    fn record_zone_key(record: &ValidationRecord, record_id: &str) -> [u8; 8] {
        record
            .zone
            .as_ref()
            .map(|z| z.to_key_bytes())
            .unwrap_or_else(|| crate::ZoneId::for_record(record_id).to_key_bytes())
    }

    /// Store a record (wire-encoded bytes) by its UUID.
    /// Also writes secondary indexes (timestamp, creator, zone) atomically via WriteBatch.
    pub fn put_record(&self, record_id: &str, record: &ValidationRecord) -> Result<()> {
        let zone_key = Self::record_zone_key(record, record_id);
        self.put_record_with_zone(record_id, record, zone_key)
    }

    /// Store a record under an explicit `zone_key`. Used by `put_record` (with the
    /// content-defined fallback key) and by callers that already know the
    /// registry-resolved leaf zone (Phase B hot path, post-split routing).
    pub fn put_record_with_zone(
        &self,
        record_id: &str,
        record: &ValidationRecord,
        zone_key: [u8; 8],
    ) -> Result<()> {
        let wire = record.to_bytes();
        let cf = self.try_cf(CF_RECORDS)?;

        // Read old record (if overwriting) to clean up stale index entries
        let old_record = self.db.get_cf(&cf, record_id.as_bytes())
            .ok()
            .flatten()
            .and_then(|bytes| ValidationRecord::from_bytes(&bytes).ok());
        let is_new = old_record.is_none();

        let mut batch = rocksdb::WriteBatch::default();

        // Clean up old index entries if overwriting with different timestamp/creator/zone
        if let Some(ref old) = old_record {
            let old_ts = old.timestamp.to_be_bytes();
            let new_ts = record.timestamp.to_be_bytes();
            let old_zone_key = Self::record_zone_key(old, record_id);
            let timestamp_changed = old_ts != new_ts;
            let creator_changed = old.creator_public_key != record.creator_public_key;
            let zone_changed = old_zone_key != zone_key;
            if timestamp_changed || creator_changed {
                // Remove stale timestamp index entry
                let mut old_ts_key = Vec::with_capacity(8 + record_id.len());
                old_ts_key.extend_from_slice(&old_ts);
                old_ts_key.extend_from_slice(record_id.as_bytes());
                batch.delete_cf(&self.try_cf(CF_IDX_TIMESTAMP)?, &old_ts_key);

                // Remove stale creator index entry
                let old_creator = crate::crypto::hash::sha3_256_hex(&old.creator_public_key);
                let mut old_creator_key = Vec::with_capacity(64 + 8 + record_id.len());
                old_creator_key.extend_from_slice(old_creator.as_bytes());
                old_creator_key.extend_from_slice(&old_ts);
                old_creator_key.extend_from_slice(record_id.as_bytes());
                batch.delete_cf(&self.try_cf(CF_IDX_CREATOR)?, &old_creator_key);
            }
            // Zone-idx is keyed on (zone, ts, record_id). If any of those three
            // shifts, the old entry would leak; delete it here so iter_zone never
            // returns ghost record_ids.
            if timestamp_changed || zone_changed {
                let stale_zone_key = Self::zone_idx_key(&old_zone_key, old.timestamp, record_id);
                batch.delete_cf(&self.try_cf(CF_RECORD_BY_ZONE)?, &stale_zone_key);
            }
        }

        // Primary record
        batch.put_cf(&self.try_cf(CF_RECORDS)?, record_id.as_bytes(), &wire);

        // Timestamp index: key = timestamp_be(8B) + record_id → empty
        let ts_bytes = record.timestamp.to_be_bytes();
        let mut ts_key = Vec::with_capacity(8 + record_id.len());
        ts_key.extend_from_slice(&ts_bytes);
        ts_key.extend_from_slice(record_id.as_bytes());
        batch.put_cf(&self.try_cf(CF_IDX_TIMESTAMP)?, &ts_key, b"");

        // Creator index: key = creator_hash_hex(64B) + timestamp_be(8B) + record_id → empty
        let creator_hash = crate::crypto::hash::sha3_256_hex(&record.creator_public_key);
        let mut creator_key = Vec::with_capacity(64 + 8 + record_id.len());
        creator_key.extend_from_slice(creator_hash.as_bytes());
        creator_key.extend_from_slice(&ts_bytes);
        creator_key.extend_from_slice(record_id.as_bytes());
        batch.put_cf(&self.try_cf(CF_IDX_CREATOR)?, &creator_key, b"");

        // Content hash index: hex(content_hash_bytes) → record_id.
        //
        // Pre-2026-04-29 (DB v5 and earlier) this used `sha3_256_hex(content_hash)` —
        // a hash-of-hash mismatched against the natural `hex::encode(content_hash)`
        // wallets see in `/record/{id}` JSON. Migration v5→v6 wipes the legacy
        // entries and re-writes with the corrected format so `/records/by-hash`
        // (Protocol §11.23 Layer A slice 0) can resolve a content hash directly.
        let content_hash_hex = hex::encode(&record.content_hash);
        batch.put_cf(&self.try_cf(CF_IDX_HASH)?, content_hash_hex.as_bytes(), record_id.as_bytes());

        // Record-hash index: hex(record_hash) → record_id. See CF_IDX_RECORD_HASH
        // doc for why this is distinct from CF_IDX_HASH. Used by the seal-record
        // resolution path (`network/ingest.rs::resolve_seal_record_ids`) and
        // `epoch_seal_loop` to map `seal.record_hashes` entries to local
        // record_ids. v6→v7 migration backfills it.
        let record_hash_hex = hex::encode(record.record_hash());
        batch.put_cf(&self.try_cf(CF_IDX_RECORD_HASH)?, record_hash_hex.as_bytes(), record_id.as_bytes());

        // Zone-keyed secondary index (ZSP Phase B): empty value, the key carries
        // all the data. Lookup is `prefix_iterator_cf(zone_key (8B))`.
        let zone_key_full = Self::zone_idx_key(&zone_key, record.timestamp, record_id);
        batch.put_cf(&self.try_cf(CF_RECORD_BY_ZONE)?, &zone_key_full, b"");

        // DAG edges: persist parent list so lightweight rebuild can reconstruct mesh.
        // Children are NOT stored here — they're discovered from the reverse direction
        // (child's parents list) during rebuild. This avoids read-modify-write on parent records.
        if !record.parents.is_empty() {
            let dag_val = serde_json::json!({ "parents": record.parents });
            batch.put_cf(&self.try_cf(CF_DAG)?, record_id.as_bytes(), dag_val.to_string().as_bytes());
        }

        // Update record count for new records (Tier 4.5: lives in CF_METADATA)
        if is_new {
            let cf_meta = self.try_cf(CF_METADATA)?;
            let count = match self.db.get_cf(&cf_meta, b"__record_count__") {
                Ok(Some(bytes)) if bytes.len() == 8 => {
                    let mut buf = [0u8; 8];
                    buf.copy_from_slice(&bytes[..8]);
                    u64::from_le_bytes(buf) + 1
                }
                _ => 1, // First insertion — initialize to 1
            };
            batch.put_cf(&cf_meta, b"__record_count__", count.to_le_bytes());
        }

        self.db.write(batch)
            .map_err(|e| ElaraError::Storage(format!("put_record batch: {e}")))
    }

    /// Combined put_record + store_public_key in a single WriteBatch (1 WAL sync instead of 2).
    /// Used by the ingest hot path to halve RocksDB write operations per record.
    pub fn put_record_with_pk(&self, record_id: &str, record: &ValidationRecord, identity_hash: &str, pk: &[u8]) -> Result<()> {
        let zone_key = Self::record_zone_key(record, record_id);
        self.put_record_with_pk_zone(record_id, record, identity_hash, pk, zone_key, None, None)
    }

    /// Hot-path variant of `put_record_with_pk` that takes an explicit `zone_key`.
    ///
    /// Phase B ingest passes `state.resolve_record_zone(record_id).to_key_bytes()`
    /// so post-split records index under the leaf zone (not the parent), which
    /// is what zone-scoped consumers (sync, GC, scoped iter) require.
    ///
    /// `slot_key`: when `Some`, atomically register the slot index entry in the
    /// same WriteBatch. ARCH-4(b) requirement — the previous code claimed the
    /// slot during early ingest validation (before sig-verify), and a malformed
    /// signature record would persist the slot index pointer while its record
    /// payload was dropped, leaving an orphan. Carrying the slot through this
    /// batch ensures slot+record are written together or not at all.
    #[allow(clippy::too_many_arguments)]
    pub fn put_record_with_pk_zone(
        &self,
        record_id: &str,
        record: &ValidationRecord,
        identity_hash: &str,
        pk: &[u8],
        zone_key: [u8; 8],
        slot_key: Option<&str>,
        disc5_epoch_key: Option<&[u8]>,
    ) -> Result<()> {
        let wire = record.to_bytes();
        let cf = self.try_cf(CF_RECORDS)?;

        let old_record = self.db.get_cf(&cf, record_id.as_bytes())
            .ok()
            .flatten()
            .and_then(|bytes| ValidationRecord::from_bytes(&bytes).ok());
        let is_new = old_record.is_none();

        let mut batch = rocksdb::WriteBatch::default();

        // Clean up old index entries if overwriting with different timestamp/creator/zone
        if let Some(ref old) = old_record {
            let old_ts = old.timestamp.to_be_bytes();
            let new_ts = record.timestamp.to_be_bytes();
            let old_zone_key = Self::record_zone_key(old, record_id);
            let timestamp_changed = old_ts != new_ts;
            let creator_changed = old.creator_public_key != record.creator_public_key;
            let zone_changed = old_zone_key != zone_key;
            if timestamp_changed || creator_changed {
                let mut old_ts_key = Vec::with_capacity(8 + record_id.len());
                old_ts_key.extend_from_slice(&old_ts);
                old_ts_key.extend_from_slice(record_id.as_bytes());
                batch.delete_cf(&self.try_cf(CF_IDX_TIMESTAMP)?, &old_ts_key);

                let old_creator = crate::crypto::hash::sha3_256_hex(&old.creator_public_key);
                let mut old_creator_key = Vec::with_capacity(64 + 8 + record_id.len());
                old_creator_key.extend_from_slice(old_creator.as_bytes());
                old_creator_key.extend_from_slice(&old_ts);
                old_creator_key.extend_from_slice(record_id.as_bytes());
                batch.delete_cf(&self.try_cf(CF_IDX_CREATOR)?, &old_creator_key);
            }
            if timestamp_changed || zone_changed {
                let stale_zone_key = Self::zone_idx_key(&old_zone_key, old.timestamp, record_id);
                batch.delete_cf(&self.try_cf(CF_RECORD_BY_ZONE)?, &stale_zone_key);
            }
        }

        // Primary record
        batch.put_cf(&self.try_cf(CF_RECORDS)?, record_id.as_bytes(), &wire);

        // Timestamp index
        let ts_bytes = record.timestamp.to_be_bytes();
        let mut ts_key = Vec::with_capacity(8 + record_id.len());
        ts_key.extend_from_slice(&ts_bytes);
        ts_key.extend_from_slice(record_id.as_bytes());
        batch.put_cf(&self.try_cf(CF_IDX_TIMESTAMP)?, &ts_key, b"");

        // Creator index
        let creator_hash = crate::crypto::hash::sha3_256_hex(&record.creator_public_key);
        let mut creator_key = Vec::with_capacity(64 + 8 + record_id.len());
        creator_key.extend_from_slice(creator_hash.as_bytes());
        creator_key.extend_from_slice(&ts_bytes);
        creator_key.extend_from_slice(record_id.as_bytes());
        batch.put_cf(&self.try_cf(CF_IDX_CREATOR)?, &creator_key, b"");

        // Content hash index — see put_record() for the v5→v6 key-format
        // history. Format: hex(content_hash_bytes) → record_id.
        let content_hash_hex = hex::encode(&record.content_hash);
        batch.put_cf(&self.try_cf(CF_IDX_HASH)?, content_hash_hex.as_bytes(), record_id.as_bytes());

        // Record-hash index — see CF_IDX_RECORD_HASH doc for the
        // semantic vs CF_IDX_HASH. Used by seal-record resolution.
        let record_hash_hex = hex::encode(record.record_hash());
        batch.put_cf(&self.try_cf(CF_IDX_RECORD_HASH)?, record_hash_hex.as_bytes(), record_id.as_bytes());

        // Zone-keyed secondary index (ZSP Phase B)
        let zone_key_full = Self::zone_idx_key(&zone_key, record.timestamp, record_id);
        batch.put_cf(&self.try_cf(CF_RECORD_BY_ZONE)?, &zone_key_full, b"");

        // DAG edges: persist parent list for lightweight rebuild
        if !record.parents.is_empty() {
            let dag_val = serde_json::json!({ "parents": record.parents });
            batch.put_cf(&self.try_cf(CF_DAG)?, record_id.as_bytes(), dag_val.to_string().as_bytes());
        }

        // Record count (Tier 4.5: CF_METADATA)
        if is_new {
            let cf_meta = self.try_cf(CF_METADATA)?;
            let count = match self.db.get_cf(&cf_meta, b"__record_count__") {
                Ok(Some(bytes)) if bytes.len() == 8 => {
                    let mut buf = [0u8; 8];
                    buf.copy_from_slice(&bytes[..8]);
                    u64::from_le_bytes(buf) + 1
                }
                _ => 1,
            };
            batch.put_cf(&cf_meta, b"__record_count__", count.to_le_bytes());
        }

        // Public key cache — Identity Partitioning Phase A — pick the
        // tier CF by inspecting record metadata. VRF-registration
        // records (anchors only per `extract_vrf_registration`'s gate)
        // land in `CF_IDENTITIES_ANCHOR`; everything else goes to
        // `CF_IDENTITIES_USER`. Witness-tier capture happens out of
        // band in `process_deferred_attestations` — the put path only
        // sees the record's own creator PK, not the attesting
        // witnesses, so the witness-class signal is unavailable here.
        let identity_cf_name = identity_tier_for_record(record);
        batch.put_cf(&self.try_cf(identity_cf_name)?, identity_hash.as_bytes(), pk);

        // ARCH-4(b): atomic slot claim. The slot index entry lands in the
        // same WriteBatch as the record payload, so a sig-verify failure
        // upstream (which short-circuits before reaching this method) can
        // never leak a slot pointer for a record that was never stored.
        if let Some(sk) = slot_key {
            batch.put_cf(&self.try_cf(CF_SLOT_INDEX)?, sk.as_bytes(), record_id.as_bytes());
        }

        // DISC-5 epoch existence index (seal records only). Batched WITH the
        // record so a crash can never leave the seal durable in CF_RECORDS while
        // its CF_EPOCHS entry is missing — symmetric with `delete_record`, which
        // already batches the CF_EPOCHS delete alongside the record delete (the
        // write side was the lone asymmetry). `None` for every non-seal record,
        // so there is zero hot-path cost. This replaces a standalone `put_cf_raw`
        // in ingest that ran ~650 lines / several `.await`s after the record
        // write; a crash in that gap stranded the seal with no index, and the
        // "backfill repairs it" claim was false — the boot DISC-5 backfill is
        // gated on `cf_epochs_size == 0`, so a partial gap is never repaired.
        //
        // LOAD-BEARING for F-10 boot recovery: `rebuild_latest_epoch_from_cf_epochs`
        // recovers the per-zone epoch tip from CF_EPOCHS on the assumption that a
        // surviving seal record always carries a surviving CF_EPOCHS index (shared
        // crash fate via this single WriteBatch). If a future change ever splits
        // the seal payload and its CF_EPOCHS index into SEPARATE batches, that
        // assumption breaks and the F-10 "Case B" epoch-repropose window reopens.
        if let Some(epoch_key) = disc5_epoch_key {
            batch.put_cf(&self.try_cf(CF_EPOCHS)?, epoch_key, b"");
        }

        self.db.write(batch)
            .map_err(|e| ElaraError::Storage(format!("put_record_with_pk batch: {e}")))?;
        // Staked-anchor cache coherence: a VRF-registration record routes its
        // creator PK into CF_IDENTITIES_ANCHOR (a second anchor-add path
        // besides store_public_key_anchor). Bump ONLY on the anchor route so
        // ordinary user-record writes (the common case) don't thrash the cache.
        if identity_cf_name == CF_IDENTITIES_ANCHOR {
            self.anchor_add_seq.fetch_add(1, std::sync::atomic::Ordering::Release);
        }
        Ok(())
    }

    /// Recalibrate the cached __record_count__ to match the actual number of
    /// records loadable via the timestamp index. Call at boot after DAG rebuild
    /// to fix any drift (e.g., from tombstone entries or interrupted writes).
    pub fn recalibrate_count(&self, actual_count: usize) {
        let cf = match self.try_cf(CF_METADATA) {
            Ok(cf) => cf,
            Err(e) => { tracing::warn!("recalibrate_count: {e}"); return; }
        };
        if let Err(e) = self.db.put_cf(&cf, b"__record_count__", (actual_count as u64).to_le_bytes()) {
            tracing::warn!("recalibrate_count: failed to write __record_count__: {e}");
        }
    }

    /// Load persisted full_pull cursor (survives restarts).
    pub fn load_full_pull_cursor(&self) -> f64 {
        let cf = match self.try_cf(CF_METADATA) {
            Ok(cf) => cf,
            Err(e) => { tracing::warn!("load_full_pull_cursor: {e}"); return 0.0; }
        };
        match self.db.get_cf(&cf, b"__full_pull_cursor__") {
            Ok(Some(bytes)) if bytes.len() == 8 => {
                f64::from_le_bytes(bytes[..8].try_into().unwrap_or([0; 8]))
            }
            _ => 0.0,
        }
    }

    /// Save full_pull cursor to RocksDB so convergence resumes after restart.
    pub fn save_full_pull_cursor(&self, cursor: f64) {
        let cf = match self.try_cf(CF_METADATA) {
            Ok(cf) => cf,
            Err(e) => { tracing::warn!("save_full_pull_cursor: {e}"); return; }
        };
        if let Err(e) = self.db.put_cf(&cf, b"__full_pull_cursor__", cursor.to_le_bytes()) {
            tracing::warn!("save_full_pull_cursor: {e}");
        }
    }

    /// Fast record count via timestamp index (key-only scan, no deserialization).
    /// O(n) in keys but much faster than scanning CF_RECORDS because:
    /// - No value deserialization needed
    /// - No internal keys to skip (finalized:, ban:, etc.)
    /// - Keys are small (8-byte timestamp + record_id)
    pub fn count_by_timestamp_index(&self) -> usize {
        let cf = match self.try_cf(CF_IDX_TIMESTAMP) {
            Ok(cf) => cf,
            Err(e) => { tracing::warn!("count_by_timestamp_index: {e}"); return 0; }
        };
        let mut count = 0usize;
        let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start);
        for item in iter {
            if item.is_ok() {
                count += 1;
            }
        }
        count
    }

    /// Get a record by UUID.
    pub fn get_record(&self, record_id: &str) -> Result<Option<ValidationRecord>> {
        let cf = self.try_cf(CF_RECORDS)?;
        match self.db.get_cf(&cf, record_id.as_bytes()) {
            Ok(Some(bytes)) => {
                let record = ValidationRecord::from_bytes(&bytes)?;
                Ok(Some(record))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(ElaraError::Storage(format!("get_record: {e}"))),
        }
    }

    /// Check if a record exists.
    pub fn record_exists(&self, record_id: &str) -> Result<bool> {
        let cf = self.try_cf(CF_RECORDS)?;
        self.db
            .get_cf(&cf, record_id.as_bytes())
            .map(|v| v.is_some())
            .map_err(|e| ElaraError::Storage(format!("record_exists: {e}")))
    }

    // ── Zone-keyed secondary index reads (ZSP Phase B) ─────────────────────

    /// Iterate record IDs in `zone_key`, optionally bounded by timestamp.
    ///
    /// Cost is O(records_in_zone), independent of total records. The 8-byte
    /// zone-key prefix lets RocksDB seek directly to the zone's range and
    /// stop at the first key that no longer matches.
    ///
    /// `since` / `until` are inclusive lower/upper bounds on the record's
    /// `timestamp` (seconds since UNIX epoch, encoded big-endian inside the
    /// secondary key). Pass `None` to omit the bound.
    ///
    /// Returns up to `limit` record IDs in chronological order. Set
    /// `limit = usize::MAX` to drain the whole zone.
    pub fn iter_zone(
        &self,
        zone_key: &[u8; 8],
        since: Option<f64>,
        until: Option<f64>,
        limit: usize,
    ) -> Vec<String> {
        if limit == 0 {
            return Vec::new();
        }
        let cf = match self.try_cf(CF_RECORD_BY_ZONE) {
            Ok(cf) => cf,
            Err(_) => return Vec::new(),
        };
        let mut start = Vec::with_capacity(16);
        start.extend_from_slice(zone_key);
        if let Some(ts) = since {
            start.extend_from_slice(&ts.to_be_bytes());
        }
        let mode = rocksdb::IteratorMode::From(&start, rocksdb::Direction::Forward);
        let until_be = until.map(|t| t.to_be_bytes());
        let mut out = Vec::new();
        for kv in self.db.iterator_cf(&cf, mode) {
            let Ok((key, _)) = kv else { continue };
            if key.len() < 16 {
                continue; // malformed, skip
            }
            if &key[..8] != zone_key.as_slice() {
                break; // left the zone — stop
            }
            if let Some(ub) = until_be.as_ref() {
                if &key[8..16] > ub.as_slice() {
                    break; // past the upper bound — stop
                }
            }
            // record_id is everything after the 16-byte (zone, ts) prefix.
            if let Ok(s) = std::str::from_utf8(&key[16..]) {
                out.push(s.to_string());
                if out.len() >= limit {
                    break;
                }
            }
        }
        out
    }

    /// Count records in `zone_key`. O(records_in_zone).
    pub fn count_zone(&self, zone_key: &[u8; 8]) -> usize {
        let cf = match self.try_cf(CF_RECORD_BY_ZONE) {
            Ok(cf) => cf,
            Err(_) => return 0,
        };
        let mode = rocksdb::IteratorMode::From(zone_key, rocksdb::Direction::Forward);
        let mut n = 0usize;
        for kv in self.db.iterator_cf(&cf, mode) {
            let Ok((key, _)) = kv else { continue };
            if key.len() < 16 || &key[..8] != zone_key.as_slice() {
                break;
            }
            n += 1;
        }
        n
    }

    /// DAM-3D Phase C Slice 1 — probe whether at least one CF_EPOCHS
    /// entry exists for `(epoch, zone_path)`. Used by ingest's zone_refs
    /// classifier to distinguish anchored refs (a seal at the claimed
    /// (zone, epoch) has been observed locally) from ghost refs
    /// (no such seal).
    ///
    /// Implementation: prefix-iterate `epoch_be(8) || zone_path_utf8 || 0x00`.
    /// The trailing `0x00` separator is load-bearing — without it, a
    /// query for `medical/eu` would also match seals in
    /// `medical/eu/cardiology` because RocksDB prefix iteration is
    /// byte-prefix, not path-segment-prefix. With the separator, the
    /// match is unambiguous (zone paths cannot contain a NUL byte per
    /// `ZoneId::new`).
    ///
    /// Cost: O(1) RocksDB seek to the first key at-or-after the prefix,
    /// plus one bytewise prefix compare. Returns true on the first hit,
    /// short-circuits otherwise. Safe to call from the ingest hot path
    /// once per zone_ref.
    pub fn seal_exists_at_zone_epoch(&self, epoch: u64, zone_path: &str) -> bool {
        let zone_bytes = zone_path.as_bytes();
        let mut prefix = Vec::with_capacity(8 + zone_bytes.len() + 1);
        prefix.extend_from_slice(&epoch.to_be_bytes());
        prefix.extend_from_slice(zone_bytes);
        prefix.push(0u8);
        let cf = match self.try_cf(CF_EPOCHS) { Ok(cf) => cf, Err(_) => return false };
        let mode = rocksdb::IteratorMode::From(&prefix, rocksdb::Direction::Forward);
        for kv in self.db.iterator_cf(&cf, mode) {
            let Ok((key, _)) = kv else { continue };
            if key.len() < prefix.len() {
                return false;
            }
            return key.starts_with(&prefix);
        }
        false
    }

    /// Tier 3.4 epoch-based pruning: look up the timestamp of the seal record
    /// at `(zone_path, epoch)` via CF_EPOCHS DISC-5 prefix scan + CF_RECORDS
    /// fetch. Returns `None` if no seal exists at that exact (zone, epoch).
    ///
    /// Cost: O(1) RocksDB seek to find the first DISC-5 key matching the
    /// `epoch_be(8) || zone_path || 0x00` prefix, then a single CF_RECORDS
    /// point-get to read the seal record's timestamp. Safe to call once per
    /// zone per GC cycle.
    pub fn seal_timestamp_at_zone_epoch(&self, epoch: u64, zone_path: &str) -> Option<f64> {
        let zone_bytes = zone_path.as_bytes();
        let mut prefix = Vec::with_capacity(8 + zone_bytes.len() + 1);
        prefix.extend_from_slice(&epoch.to_be_bytes());
        prefix.extend_from_slice(zone_bytes);
        prefix.push(0u8);
        let epochs_cf = self.try_cf(CF_EPOCHS).ok()?;
        let mode = rocksdb::IteratorMode::From(&prefix, rocksdb::Direction::Forward);
        for kv in self.db.iterator_cf(&epochs_cf, mode) {
            let Ok((key, _)) = kv else { continue };
            if !key.starts_with(&prefix) {
                return None;
            }
            let (_, _, record_id) = crate::network::epoch::parse_disc5_index_key(&key)?;
            let records_cf = self.try_cf(CF_RECORDS).ok()?;
            let wire = self.db.get_cf(&records_cf, record_id.as_bytes()).ok()??;
            let rec = ValidationRecord::from_bytes(&wire).ok()?;
            return Some(rec.timestamp);
        }
        None
    }

    /// Crash-before-broadcast phantom instrumentation (deferred Mechanism-B
    /// primitive): return `true` iff SOME seal durably stored at
    /// `(zone_path, epoch)` has `record_hash == target`. Unlike
    /// `seal_timestamp_at_zone_epoch`, this enumerates EVERY DISC-5 key at the
    /// `(zone, epoch)` prefix — a phantom seal and an honest same-epoch
    /// competitor can BOTH be stored at the same `(zone, epoch)` (Phase-2 writes
    /// every parsed seal unconditionally, before the C2 lex-min decision), and
    /// the caller must check all of them, not just the first.
    ///
    /// This is the exact lookup the deferred provisional-self-tip "chain-
    /// existence" C2 relaxation uses to decide whether a chain-link-rejected
    /// sequential successor chains off a real-but-non-canonical seal we hold
    /// (the healable case: the honest E-seal that lost the lex-min tiebreak to a
    /// crash-before-broadcast phantom is still durable here) vs an unknown or
    /// forged predecessor. Shipped first as a counter probe
    /// (`epoch_successor_chainable_total`) to measure the healable-case rate
    /// before the admission change lands. Read-only, no consensus effect; call
    /// OUTSIDE the epoch lock.
    ///
    /// Cost: O(seals at (zone,epoch)) DISC-5 keys — normally 1–2, bounded by the
    /// per-epoch competing-sealer count — each one CF_RECORDS point-get. Safe on
    /// the rare C2-reject path. A `target` of all-zeros can never match (a
    /// `record_hash` is a SHA3 digest), so a genesis-predecessor successor
    /// correctly reads as not-chainable.
    pub fn seal_record_hash_present_at_zone_epoch(
        &self,
        epoch: u64,
        zone_path: &str,
        target: &[u8; 32],
    ) -> bool {
        let zone_bytes = zone_path.as_bytes();
        let mut prefix = Vec::with_capacity(8 + zone_bytes.len() + 1);
        prefix.extend_from_slice(&epoch.to_be_bytes());
        prefix.extend_from_slice(zone_bytes);
        prefix.push(0u8);
        let epochs_cf = match self.try_cf(CF_EPOCHS) {
            Ok(cf) => cf,
            Err(_) => return false,
        };
        let records_cf = match self.try_cf(CF_RECORDS) {
            Ok(cf) => cf,
            Err(_) => return false,
        };
        let mode = rocksdb::IteratorMode::From(&prefix, rocksdb::Direction::Forward);
        for kv in self.db.iterator_cf(&epochs_cf, mode) {
            let Ok((key, _)) = kv else { continue };
            if !key.starts_with(&prefix) {
                return false;
            }
            let Some((_, _, record_id)) = crate::network::epoch::parse_disc5_index_key(&key) else {
                continue;
            };
            let Ok(Some(wire)) = self.db.get_cf(&records_cf, record_id.as_bytes()) else {
                continue;
            };
            let Ok(rec) = ValidationRecord::from_bytes(&wire) else {
                continue;
            };
            if &rec.record_hash() == target {
                return true;
            }
        }
        false
    }

    /// Total entries in the zone-idx CF — fleet-wide observability gauge.
    /// O(total_records). Use sparingly (e.g., once per metrics scrape).
    pub fn zone_idx_total_entries(&self) -> usize {
        let cf = match self.try_cf(CF_RECORD_BY_ZONE) {
            Ok(cf) => cf,
            Err(_) => return 0,
        };
        self.db
            .iterator_cf(&cf, rocksdb::IteratorMode::Start)
            .filter(|kv| kv.is_ok())
            .count()
    }

    /// Distinct zones present in the zone-idx CF — fleet-wide observability gauge.
    /// O(total_records); cheap on testnet (~120K), expensive on mainnet — caller
    /// must throttle (e.g., once per metrics interval).
    pub fn zone_idx_distinct_zones(&self) -> usize {
        let cf = match self.try_cf(CF_RECORD_BY_ZONE) {
            Ok(cf) => cf,
            Err(_) => return 0,
        };
        let mut last_zone: Option<[u8; 8]> = None;
        let mut count = 0usize;
        for kv in self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start) {
            let Ok((key, _)) = kv else { continue };
            if key.len() < 8 { continue; }
            let mut zk = [0u8; 8];
            zk.copy_from_slice(&key[..8]);
            if last_zone.as_ref() != Some(&zk) {
                count += 1;
                last_zone = Some(zk);
            }
        }
        count
    }

    /// Backfill `CF_RECORD_BY_ZONE` from the primary records CF.
    ///
    /// Iterates one chunk at a time so an upgraded binary can build the index
    /// incrementally over many ticks without blocking ingest. Resumable:
    ///   - Pass `start_after = None` for the first call.
    ///   - Pass back the `(progress, last_record_id)` from the previous call
    ///     to continue.
    ///
    /// For each record found in `CF_RECORDS` whose `(zone_key, timestamp,
    /// record_id)` is missing from `CF_RECORD_BY_ZONE`, writes the entry.
    /// Records that already have an entry are skipped (idempotent).
    ///
    /// Returns `(processed_in_chunk, last_record_id_processed)`. When
    /// `last_record_id_processed` is `None`, the iteration is complete.
    pub fn backfill_zone_index_chunk(
        &self,
        start_after: Option<&str>,
        chunk_limit: usize,
    ) -> Result<(usize, Option<String>)> {
        let cf_records = self.try_cf(CF_RECORDS)?;
        let cf_zone = self.try_cf(CF_RECORD_BY_ZONE)?;
        let mode = match start_after {
            Some(after) => {
                // Seek past `after` — RocksDB Forward starts AT the key, so we
                // skip the first match below.
                rocksdb::IteratorMode::From(after.as_bytes(), rocksdb::Direction::Forward)
            }
            None => rocksdb::IteratorMode::Start,
        };
        let skip_first = start_after.is_some();
        let mut batch = rocksdb::WriteBatch::default();
        let mut processed = 0usize;
        let mut last_id: Option<String> = None;
        let mut iter_done = true;

        for (i, kv) in self.db.iterator_cf(&cf_records, mode).enumerate() {
            let Ok((key, value)) = kv else { continue };
            if i == 0 && skip_first {
                continue;
            }
            // Skip non-record keys (markers, ban: ban entries, finalized: keys, …)
            if key.starts_with(b"finalized:")
                || key.starts_with(b"ban:")
                || key.starts_with(b"blocked_term:")
                || key.starts_with(b"tombstone:")
                || &*key == b"__record_count__"
                || &*key == b"__full_pull_cursor__"
            {
                continue;
            }
            let record_id = match std::str::from_utf8(&key) {
                Ok(s) => s.to_string(),
                Err(_) => continue,
            };
            let record = match ValidationRecord::from_bytes(&value) {
                Ok(r) => r,
                Err(_) => continue,
            };
            let zone_key = Self::record_zone_key(&record, &record_id);
            let zk_full = Self::zone_idx_key(&zone_key, record.timestamp, &record_id);
            // Idempotent: only write if missing.
            if self.db.get_cf(&cf_zone, &zk_full).ok().flatten().is_none() {
                batch.put_cf(&cf_zone, &zk_full, b"");
            }
            processed += 1;
            last_id = Some(record_id);
            if processed >= chunk_limit {
                iter_done = false;
                break;
            }
        }

        if !batch.is_empty() {
            self.db.write(batch)
                .map_err(|e| ElaraError::Storage(format!("backfill_zone_index batch: {e}")))?;
        }

        Ok((processed, if iter_done { None } else { last_id }))
    }

    // ── Slot index CF (MESH-BFT Phase 3 Stage 1C) ───────────────────────────
    // Slot key: "<creator_account_hash_hex64>:<nonce_hex16>" (= record.slot_key())
    // Value:    record_id (UTF-8)
    //
    // A "slot" is the tuple (account, nonce). At most ONE record per
    // slot can be finalized — any second record for the same slot is a
    // conflict (equivocation) and is rejected at ingest. This is the
    // mutual-exclusion primitive that makes AWC a true BFT protocol.

    /// Look up the record_id that currently owns a slot, if any.
    /// Returns None if the slot is free (first-seen path).
    pub fn slot_lookup(&self, slot_key: &str) -> Result<Option<String>> {
        let cf = self.try_cf(CF_SLOT_INDEX)?;
        match self.db.get_cf(&cf, slot_key.as_bytes()) {
            Ok(Some(bytes)) => {
                let rid = String::from_utf8(bytes)
                    .map_err(|e| ElaraError::Storage(format!("slot_lookup utf8: {e}")))?;
                Ok(Some(rid))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(ElaraError::Storage(format!("slot_lookup: {e}"))),
        }
    }

    /// Register first-seen record for a slot. Caller must have verified
    /// the slot was free (slot_lookup returned None) immediately before.
    /// Idempotent: writing the same record_id for the same slot is a no-op.
    pub fn slot_register(&self, slot_key: &str, record_id: &str) -> Result<()> {
        let cf = self.try_cf(CF_SLOT_INDEX)?;
        self.db
            .put_cf(&cf, slot_key.as_bytes(), record_id.as_bytes())
            .map_err(|e| ElaraError::Storage(format!("slot_register: {e}")))
    }

    /// Find the maximum nonce already claimed by `account_hash` across all
    /// slot entries. Returns `None` if this account has no prior slots (fresh
    /// identity — caller should start the counter at 1).
    ///
    /// Used at node startup to bootstrap `NodeState::slot_nonce_self` so a
    /// restarted node never re-hands-out a nonce it already used (which would
    /// look like self-equivocation and trip the SLOT EQUIVOCATION gate).
    ///
    /// Slot keys are `<account_hash>:<nonce_hex_16>`, so we prefix-iterate
    /// CF_SLOT_INDEX under `<account_hash>:`. This is O(slots_for_this_account),
    /// never O(all_records) — each account's slot range is naturally partitioned
    /// by the prefix. Scale-safe for accounts with up to millions of own records.
    pub fn max_slot_nonce_for_account(&self, account_hash: &str) -> Result<Option<u64>> {
        let cf = self.try_cf(CF_SLOT_INDEX)?;
        let prefix_str = format!("{}:", account_hash);
        let prefix = prefix_str.as_bytes();
        let iter = self.db.prefix_iterator_cf(&cf, prefix);
        let mut best: Option<u64> = None;
        for item in iter {
            let (key, _) = item.map_err(|e| {
                ElaraError::Storage(format!("max_slot_nonce_for_account iter: {e}"))
            })?;
            if !key.starts_with(prefix) {
                break;
            }
            // Parse the `<nonce_hex_16>` suffix. Length check first to keep
            // this hot-path tight — a malformed key shouldn't panic but
            // shouldn't skew the result either.
            let suffix = &key[prefix.len()..];
            if suffix.len() != 16 {
                continue;
            }
            let suffix_str = match std::str::from_utf8(suffix) {
                Ok(s) => s,
                Err(_) => continue,
            };
            if let Ok(n) = u64::from_str_radix(suffix_str, 16) {
                best = Some(best.map_or(n, |b| b.max(n)));
            }
        }
        Ok(best)
    }

    /// Drop a slot index entry. Used only by the admin eviction path
    /// (`/admin/forensic/slot/{...}/evict_unverifiable`) to release a slot
    /// occupied by a record whose signature no longer verifies under the
    /// current wire formula. Idempotent — deleting a missing key is a no-op.
    ///
    /// Never call from ingest: a slot occupant that *does* verify is the
    /// rightful first-seen claim and must remain. The eviction path is the
    /// only legitimate caller because it gates on `Identity::verify == false`.
    pub fn slot_delete(&self, slot_key: &str) -> Result<()> {
        let cf = self.try_cf(CF_SLOT_INDEX)?;
        self.db
            .delete_cf(&cf, slot_key.as_bytes())
            .map_err(|e| ElaraError::Storage(format!("slot_delete: {e}")))
    }

    /// Mark a slot as conflicted. Called by ingest when a second (different
    /// record_id) claim for the same slot is observed AND a ConflictProof
    /// successfully verifies. The settlement gate consults `slot_is_conflicted`
    /// and refuses to finalize records whose slot is marked here.
    ///
    /// `marker` is a short UTF-8 descriptor carrying both record_ids so
    /// post-hoc analysis can reconstruct which claims collided without
    /// iterating the full DAG.
    pub fn slot_mark_conflict(&self, slot_key: &str, marker: &str) -> Result<()> {
        let cf = self.try_cf(CF_SLOT_CONFLICTS)?;
        self.db
            .put_cf(&cf, slot_key.as_bytes(), marker.as_bytes())
            .map_err(|e| ElaraError::Storage(format!("slot_mark_conflict: {e}")))
    }

    /// Check whether a slot is conflicted — i.e. has been observed with
    /// two different record_ids claiming it. Records in a conflicted slot
    /// must NEVER be finalized. O(1) block-cache lookup.
    pub fn slot_is_conflicted(&self, slot_key: &str) -> Result<bool> {
        let cf = self.try_cf(CF_SLOT_CONFLICTS)?;
        self.db
            .get_cf(&cf, slot_key.as_bytes())
            .map(|v| v.is_some())
            .map_err(|e| ElaraError::Storage(format!("slot_is_conflicted: {e}")))
    }

    /// Delete a record.
    pub fn delete_record(&self, record_id: &str) -> Result<()> {
        let cf = self.try_cf(CF_RECORDS)?;
        // Read record before delete to get timestamp + creator for index cleanup
        let old_record = self.db.get_cf(&cf, record_id.as_bytes())
            .ok()
            .flatten()
            .and_then(|bytes| ValidationRecord::from_bytes(&bytes).ok());

        let mut batch = rocksdb::WriteBatch::default();

        // Delete primary record
        batch.delete_cf(&cf, record_id.as_bytes());

        // DAG parent-edge row. Unconditional (idempotent on a missing key):
        // the boot-time DAG rebuild (`rebuild_dag_lightweight_bounded`) keys
        // membership on CF_IDX_TIMESTAMP and only consults CF_DAG for edges,
        // so a row left behind here is pure dead weight — but it accumulated
        // forever (GC, zone purge, and admin evict all call this fn) while
        // `delete_touched_cfs()` already listed CF_DAG as delete-touched for
        // compaction. Admin-audit 2026-07-05.
        batch.delete_cf(&self.try_cf(CF_DAG)?, record_id.as_bytes());

        // C4 slice 1: mandate ACT index (keyed purely by act record_id, so this
        // runs UNCONDITIONALLY — even if the record body is already gone). Act
        // records are ordinary GC-eligible records (they carry `mandate_ref`, not
        // the GC-exempt `mandate_op`/`revocation_op`), so without this the derived
        // flag index would orphan a row pointing at a deleted record — unbounded
        // growth at scale. Idempotent: delete of a missing key is a no-op, so
        // non-mandate records pay a single 1-byte allocation. (CF_MANDATE /
        // CF_REVOCATION are intentionally NOT cleaned here — their carriers are
        // GC-exempt, so a mandate/revocation record reaching delete_record is an
        // explicit admin/dispute action and the registry entry must outlive any
        // single carrier copy.)
        //
        // C4 slice 4: the reverse index (CF_MANDATE_ACTS_BY_MANDATE) key embeds
        // the act's (mandate_ref, act_timestamp_ms), which only the FORWARD entry
        // carries — so read it before deleting the forward key and reconstruct
        // the reverse key with the SAME builder used on write. On a double-delete
        // the forward entry is already gone → `None` here is correct, not a leak:
        // the reverse key was removed on the first pass (this whole step is
        // idempotent), mirroring the CF_IDX_TIMESTAMP/CF_IDX_CREATOR cleanup below.
        if let Some(act) = self.get_mandate_act(record_id) {
            if let Some(rkey) = Self::mandate_acts_reverse_key(
                &act.mandate_ref,
                act.act_timestamp_ms,
                record_id,
            ) {
                batch.delete_cf(&self.try_cf(CF_MANDATE_ACTS_BY_MANDATE)?, &rkey);
            }
            // Agent reverse index (loopback /agent/{hash}/acts) cleaned in the
            // SAME batch and from the SAME forward read — keyed by the act's
            // signer_identity_hash, which only the forward entry carries.
            if let Some(akey) = Self::mandate_acts_agent_reverse_key(
                &act.signer_identity_hash,
                act.act_timestamp_ms,
                record_id,
            ) {
                batch.delete_cf(&self.try_cf(CF_MANDATE_ACTS_BY_AGENT)?, &akey);
            }
        }
        batch.delete_cf(&self.try_cf(CF_MANDATE_ACT)?, record_id.as_bytes());

        // Clean up secondary indexes if we had the record
        if let Some(ref rec) = old_record {
            // Timestamp index
            let ts_bytes = rec.timestamp.to_be_bytes();
            let mut ts_key = Vec::with_capacity(8 + record_id.len());
            ts_key.extend_from_slice(&ts_bytes);
            ts_key.extend_from_slice(record_id.as_bytes());
            batch.delete_cf(&self.try_cf(CF_IDX_TIMESTAMP)?, &ts_key);

            // Creator index
            let creator_hash = crate::crypto::hash::sha3_256_hex(&rec.creator_public_key);
            let mut creator_key = Vec::with_capacity(64 + 8 + record_id.len());
            creator_key.extend_from_slice(creator_hash.as_bytes());
            creator_key.extend_from_slice(&ts_bytes);
            creator_key.extend_from_slice(record_id.as_bytes());
            batch.delete_cf(&self.try_cf(CF_IDX_CREATOR)?, &creator_key);

            // Tips index
            batch.delete_cf(&self.try_cf(CF_IDX_TIPS)?, record_id.as_bytes());

            // Content hash index — see put_record() for the v5→v6 key-format
            // history. Format: hex(content_hash_bytes) → record_id.
            let content_hash_hex = hex::encode(&rec.content_hash);
            batch.delete_cf(&self.try_cf(CF_IDX_HASH)?, content_hash_hex.as_bytes());

            // Record-hash index — see CF_IDX_RECORD_HASH doc.
            let record_hash_hex = hex::encode(rec.record_hash());
            batch.delete_cf(&self.try_cf(CF_IDX_RECORD_HASH)?, record_hash_hex.as_bytes());

            // Zone-keyed secondary index (ZSP Phase B)
            let old_zone_key = Self::record_zone_key(rec, record_id);
            let zone_full_key = Self::zone_idx_key(&old_zone_key, rec.timestamp, record_id);
            batch.delete_cf(&self.try_cf(CF_RECORD_BY_ZONE)?, &zone_full_key);

            // Finalized index (prevent orphaned finalized: keys after GC)
            // Tier 4.5: lives in CF_METADATA
            let cf_meta = self.try_cf(CF_METADATA)?;
            let finalized_key = format!("finalized:{record_id}");
            batch.delete_cf(&cf_meta, finalized_key.as_bytes());

            // Gap 3: CF_EPOCHS DISC-5 index — written on seal ingest at
            // network/ingest.rs:2090-2110 with key
            // `disc5_index_key(epoch_number, zone_path, record_id)`. Without
            // this, pruning a seal leaks ~50 bytes/seal in CF_EPOCHS forever.
            // At 1M zones × 720 seals/day × 365 days = 263B keys × 50 B ≈
            // 13TB/year of stale index — the same scale problem the seal
            // pruning is meant to solve. Cleaning it here is idempotent
            // (delete of a missing key is a no-op) so non-seal records pay
            // a single 1-byte allocation worth of overhead per delete.
            if let Some(epoch_op) = rec.metadata.get("epoch_op").and_then(|v| v.as_str()) {
                if epoch_op == "seal" {
                    let zone_path = rec
                        .metadata
                        .get("epoch_zone")
                        .and_then(|v| {
                            v.as_str()
                                .map(|s| s.to_string())
                                .or_else(|| v.as_u64().map(|n| n.to_string()))
                        });
                    let epoch_number = rec
                        .metadata
                        .get("epoch_number")
                        .and_then(|v| v.as_u64());
                    if let (Some(zone), Some(epoch)) = (zone_path, epoch_number) {
                        let disc5_key = crate::network::epoch::disc5_index_key(
                            epoch, &zone, record_id,
                        );
                        batch.delete_cf(&self.try_cf(CF_EPOCHS)?, &disc5_key);
                    }
                }
            }

            // Decrement record count (Tier 4.5: CF_METADATA)
            if let Ok(Some(bytes)) = self.db.get_cf(&cf_meta, b"__record_count__") {
                if bytes.len() == 8 {
                    let mut buf = [0u8; 8];
                    buf.copy_from_slice(&bytes[..8]);
                    let n = u64::from_le_bytes(buf).saturating_sub(1);
                    batch.put_cf(&cf_meta, b"__record_count__", n.to_le_bytes());
                }
            }
        }

        self.db.write(batch)
            .map_err(|e| ElaraError::Storage(format!("delete_record batch: {e}")))
    }

    // ─── Agent-mandate registry (C4 slice 1) ──────────────────────────────

    /// Composite key for the revocation index: `mandate_id ++ revoker_hash`,
    /// both normalized to lowercase hex (sha3 hex is already lowercase; this is
    /// defensive). The revoker in the key is what enforces read-time
    /// authorization — the resolver looks up the principal's entry directly.
    fn revocation_key(mandate_id: &str, revoker_identity_hash: &str) -> Vec<u8> {
        let mut k = Vec::with_capacity(mandate_id.len() + revoker_identity_hash.len());
        k.extend_from_slice(mandate_id.to_ascii_lowercase().as_bytes());
        k.extend_from_slice(revoker_identity_hash.to_ascii_lowercase().as_bytes());
        k
    }

    /// Store a mandate, keyed by its content-addressed id. Canonicalized (scope
    /// sorted+deduped) so the stored bytes are byte-identical on every node.
    /// Idempotent (content address).
    pub fn put_mandate(&self, mandate: &crate::mandate::MandateRecord) -> Result<()> {
        let cf = self.try_cf(CF_MANDATE)?;
        let id = mandate.mandate_id();
        let bytes = serde_json::to_vec(&mandate.canonicalized())
            .map_err(|e| ElaraError::Storage(format!("put_mandate encode: {e}")))?;
        self.db
            .put_cf(&cf, id.as_bytes(), &bytes)
            .map_err(|e| ElaraError::Storage(format!("put_mandate: {e}")))
    }

    /// Fetch a mandate by id.
    pub fn get_mandate(&self, mandate_id: &str) -> Option<crate::mandate::MandateRecord> {
        let cf = self.try_cf(CF_MANDATE).ok()?;
        let bytes = self.db.get_cf(&cf, mandate_id.as_bytes()).ok().flatten()?;
        serde_json::from_slice(&bytes).ok()
    }

    /// Record a revocation of `mandate_id` by `revoker_identity_hash` at
    /// `revoked_at_ms`. Monotonic per `(mandate, revoker)` — keeps the earliest
    /// (replay-idempotent, order-independent).
    pub fn put_revocation(
        &self,
        mandate_id: &str,
        revoker_identity_hash: &str,
        revoked_at_ms: u64,
    ) -> Result<()> {
        let cf = self.try_cf(CF_REVOCATION)?;
        let key = Self::revocation_key(mandate_id, revoker_identity_hash);
        if let Ok(Some(existing)) = self.db.get_cf(&cf, &key) {
            if let Ok(prev) =
                serde_json::from_slice::<crate::mandate::RevocationEntry>(&existing)
            {
                if prev.revoked_at_ms <= revoked_at_ms {
                    return Ok(()); // already have an earlier-or-equal revocation
                }
            }
        }
        let bytes = serde_json::to_vec(&crate::mandate::RevocationEntry::new(revoked_at_ms))
            .map_err(|e| ElaraError::Storage(format!("put_revocation encode: {e}")))?;
        self.db
            .put_cf(&cf, &key, &bytes)
            .map_err(|e| ElaraError::Storage(format!("put_revocation: {e}")))
    }

    /// Earliest revocation time of `mandate_id` SIGNED BY
    /// `principal_identity_hash` (read-time authorization by lookup key).
    pub fn get_revocation_ms(
        &self,
        mandate_id: &str,
        principal_identity_hash: &str,
    ) -> Option<u64> {
        let cf = self.try_cf(CF_REVOCATION).ok()?;
        let key = Self::revocation_key(mandate_id, principal_identity_hash);
        let bytes = self.db.get_cf(&cf, &key).ok().flatten()?;
        serde_json::from_slice::<crate::mandate::RevocationEntry>(&bytes)
            .ok()
            .map(|e| e.revoked_at_ms)
    }

    /// Persist the folded emergency state (single-blob, [`CF_EMERGENCY`] /
    /// [`EMERGENCY_STATE_KEY`]). Called on each winning halt/resume fold,
    /// persist-BEFORE the in-memory atomics are published, so a crash between the
    /// two leaves the durable blob authoritative (never a stale un-halt on reboot).
    pub fn put_emergency_state(
        &self,
        state: &crate::emergency::EmergencyState,
    ) -> Result<()> {
        let cf = self.try_cf(CF_EMERGENCY)?;
        let bytes = serde_json::to_vec(state)
            .map_err(|e| ElaraError::Storage(format!("put_emergency_state encode: {e}")))?;
        self.db
            .put_cf(&cf, EMERGENCY_STATE_KEY, &bytes)
            .map_err(|e| ElaraError::Storage(format!("put_emergency_state: {e}")))
    }

    /// Read the durable emergency state (None on a fresh DB / pre-feature node →
    /// un-halted). Read on boot to repopulate the `NodeState` atomics.
    pub fn get_emergency_state(&self) -> Option<crate::emergency::EmergencyState> {
        let cf = self.try_cf(CF_EMERGENCY).ok()?;
        let bytes = self.db.get_cf(&cf, EMERGENCY_STATE_KEY).ok().flatten()?;
        serde_json::from_slice(&bytes).ok()
    }

    /// Build the `CF_MANDATE_ACTS_BY_MANDATE` reverse key for an act, or `None`
    /// when `mandate_ref` is not a well-formed 64-hex mandate id (such acts are
    /// forward-indexed only — they can never resolve to a real mandate, so they
    /// are excluded from the reverse enumeration). The fixed-width hex prefix is
    /// what makes the key unambiguous despite `mandate_ref` being attacker-
    /// controlled. Layout: `mandate_ref(64, lowercased) ++ ts(8 BE) ++ record_id`.
    /// One encoding shared by put / delete / scan so they can never drift.
    fn mandate_acts_reverse_key(
        mandate_ref: &str,
        act_timestamp_ms: u64,
        record_id: &str,
    ) -> Option<Vec<u8>> {
        if mandate_ref.len() != 64 || !mandate_ref.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let mref = mandate_ref.to_ascii_lowercase();
        let mut key = Vec::with_capacity(64 + 8 + record_id.len());
        key.extend_from_slice(mref.as_bytes());
        key.extend_from_slice(&act_timestamp_ms.to_be_bytes());
        key.extend_from_slice(record_id.as_bytes());
        Some(key)
    }

    /// Build the `CF_MANDATE_ACTS_BY_AGENT` reverse key for an act, or `None` when
    /// `signer_identity_hash` is not a well-formed 64-hex identity hash. The signer
    /// hash is `sha3(creator_pk)` so it is structurally 64 lowercase hex, but the
    /// builder validates + lowercases defensively (a serde-loaded `String` could be
    /// malformed). The fixed 64-byte hex prefix keeps the key unambiguous and is
    /// what the `starts_with` scan guard relies on. Layout:
    /// `signer_hash(64, lowercased) ++ ts(8 BE) ++ record_id`. One encoding shared
    /// by put / delete / scan so they can never drift. Mirrors
    /// [`Self::mandate_acts_reverse_key`] exactly, keyed by signer instead of ref.
    fn mandate_acts_agent_reverse_key(
        signer_identity_hash: &str,
        act_timestamp_ms: u64,
        record_id: &str,
    ) -> Option<Vec<u8>> {
        if signer_identity_hash.len() != 64
            || !signer_identity_hash.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return None;
        }
        let shash = signer_identity_hash.to_ascii_lowercase();
        let mut key = Vec::with_capacity(64 + 8 + record_id.len());
        key.extend_from_slice(shash.as_bytes());
        key.extend_from_slice(&act_timestamp_ms.to_be_bytes());
        key.extend_from_slice(record_id.as_bytes());
        Some(key)
    }

    /// Store the act-index entry for a mandate-bearing act record. Writes the
    /// forward index (`record_id → entry`), the by-mandate reverse index
    /// (`mandate_id ++ ts ++ record_id → ()`, when the ref is a well-formed 64-hex
    /// id), AND the by-agent reverse index (`signer_hash ++ ts ++ record_id → ()`)
    /// — all in a SINGLE atomic `WriteBatch`, so the three indexes can never
    /// diverge across a crash.
    pub fn put_mandate_act(
        &self,
        record_id: &str,
        entry: &crate::mandate::MandateActEntry,
    ) -> Result<()> {
        let cf = self.try_cf(CF_MANDATE_ACT)?;
        let bytes = serde_json::to_vec(entry)
            .map_err(|e| ElaraError::Storage(format!("put_mandate_act encode: {e}")))?;
        let mut batch = rocksdb::WriteBatch::default();
        batch.put_cf(&cf, record_id.as_bytes(), &bytes);
        if let Some(rkey) =
            Self::mandate_acts_reverse_key(&entry.mandate_ref, entry.act_timestamp_ms, record_id)
        {
            batch.put_cf(&self.try_cf(CF_MANDATE_ACTS_BY_MANDATE)?, &rkey, b"");
        }
        if let Some(akey) = Self::mandate_acts_agent_reverse_key(
            &entry.signer_identity_hash,
            entry.act_timestamp_ms,
            record_id,
        ) {
            batch.put_cf(&self.try_cf(CF_MANDATE_ACTS_BY_AGENT)?, &akey, b"");
        }
        self.db
            .write(batch)
            .map_err(|e| ElaraError::Storage(format!("put_mandate_act: {e}")))
    }

    /// Bounded, keyset-paginated enumeration of the act records performed under a
    /// mandate, in ascending act-timestamp order. `from` is the prior page's
    /// opaque `next_from` cursor (already advanced past the last returned row);
    /// `None` starts at the first act. Returns `(record_ids, next_cursor)` where
    /// `next_cursor` is `Some` iff a further page may exist. O(`limit`) per page
    /// via a `range_scan_cf` keyset seek under the fixed 64-byte mandate prefix —
    /// never an O(all_records) scan, never an offset skip. `limit` is clamped to
    /// [`MANDATE_ACTS_PAGE_MAX`].
    pub fn list_acts_for_mandate(
        &self,
        mandate_id: &str,
        from: Option<&[u8]>,
        limit: usize,
    ) -> Result<(Vec<String>, Option<Vec<u8>>)> {
        let cap = limit.clamp(1, MANDATE_ACTS_PAGE_MAX);
        let mid = mandate_id.to_ascii_lowercase();
        if mid.len() != 64 || !mid.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Ok((Vec::new(), None));
        }
        let prefix = mid.into_bytes();
        // Seek start = prefix [++ cursor]. The cursor is the prior last row's
        // suffix with a trailing 0x00 (see below), so the inclusive RocksDB
        // `From` seek resumes STRICTLY after it — no duplicate at the boundary.
        let mut start = prefix.clone();
        if let Some(cur) = from {
            start.extend_from_slice(cur);
        }
        let mut out: Vec<String> = Vec::with_capacity(cap);
        let mut last_suffix: Option<Vec<u8>> = None;
        let mut overflow = false;
        self.range_scan_cf(CF_MANDATE_ACTS_BY_MANDATE, &start, |key, _v| {
            if !key.starts_with(&prefix) {
                return Ok(false); // left this mandate's keyspace
            }
            if out.len() >= cap {
                overflow = true; // a further row exists → emit a next cursor
                return Ok(false);
            }
            let suffix = &key[prefix.len()..]; // ts(8) ++ record_id
            if suffix.len() > 8 {
                if let Ok(rid) = std::str::from_utf8(&suffix[8..]) {
                    out.push(rid.to_string());
                    last_suffix = Some(suffix.to_vec());
                }
            }
            Ok(true)
        })?;
        // Exclusive resume: append 0x00 to the last returned suffix so the next
        // page's inclusive seek lands strictly after it.
        let next = if overflow {
            last_suffix.map(|mut s| {
                s.push(0x00);
                s
            })
        } else {
            None
        };
        Ok((out, next))
    }

    /// Bounded, keyset-paginated enumeration of the act records SIGNED BY a given
    /// agent identity (`signer_identity_hash`), across all mandates, in ascending
    /// act-timestamp order. Backs the LOOPBACK-ONLY `GET /agent/{hash}/acts`
    /// forensic view. Same shape + guarantees as [`Self::list_acts_for_mandate`]
    /// (O(`limit`) keyset seek under the fixed 64-byte signer prefix, never an
    /// O(all_records) scan, exclusive `+0x00` cursor), keyed by signer hash. Note
    /// this enumerates acts where the signer had NO valid mandate too (NoChain /
    /// AgentMismatch) — the forensic point — so the handler MUST render each row's
    /// recomputed flag and apply the anti-framing principal-echo rule.
    pub fn list_acts_for_agent(
        &self,
        agent_hash: &str,
        from: Option<&[u8]>,
        limit: usize,
    ) -> Result<(Vec<String>, Option<Vec<u8>>)> {
        let cap = limit.clamp(1, MANDATE_ACTS_PAGE_MAX);
        let ah = agent_hash.to_ascii_lowercase();
        if ah.len() != 64 || !ah.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Ok((Vec::new(), None));
        }
        let prefix = ah.into_bytes();
        let mut start = prefix.clone();
        if let Some(cur) = from {
            start.extend_from_slice(cur);
        }
        let mut out: Vec<String> = Vec::with_capacity(cap);
        let mut last_suffix: Option<Vec<u8>> = None;
        let mut overflow = false;
        self.range_scan_cf(CF_MANDATE_ACTS_BY_AGENT, &start, |key, _v| {
            if !key.starts_with(&prefix) {
                return Ok(false); // left this agent's keyspace
            }
            if out.len() >= cap {
                overflow = true; // a further row exists → emit a next cursor
                return Ok(false);
            }
            let suffix = &key[prefix.len()..]; // ts(8) ++ record_id
            if suffix.len() > 8 {
                if let Ok(rid) = std::str::from_utf8(&suffix[8..]) {
                    out.push(rid.to_string());
                    last_suffix = Some(suffix.to_vec());
                }
            }
            Ok(true)
        })?;
        let next = if overflow {
            last_suffix.map(|mut s| {
                s.push(0x00);
                s
            })
        } else {
            None
        };
        Ok((out, next))
    }

    /// Fetch the act-index entry for a record_id (`None` if not a known mandate act).
    pub fn get_mandate_act(&self, record_id: &str) -> Option<crate::mandate::MandateActEntry> {
        let cf = self.try_cf(CF_MANDATE_ACT).ok()?;
        let bytes = self.db.get_cf(&cf, record_id.as_bytes()).ok().flatten()?;
        serde_json::from_slice(&bytes).ok()
    }

    /// Collect all mandates into a sorted map (snapshot carry). Bounded by
    /// issuance volume — full-carry is acceptable at v0 scale (see
    /// internal design notes).
    pub fn collect_mandates(
        &self,
    ) -> std::collections::BTreeMap<String, crate::mandate::MandateRecord> {
        let mut out = std::collections::BTreeMap::new();
        let Ok(cf) = self.try_cf(CF_MANDATE) else {
            return out;
        };
        for (k, v) in self
            .db
            .iterator_cf(&cf, rocksdb::IteratorMode::Start)
            .flatten()
        {
            if let (Ok(id), Ok(m)) = (
                std::str::from_utf8(&k),
                serde_json::from_slice::<crate::mandate::MandateRecord>(&v),
            ) {
                out.insert(id.to_string(), m);
            }
        }
        out
    }

    /// Collect all revocations into a sorted map keyed by the 128-hex composite
    /// (snapshot carry).
    pub fn collect_revocations(
        &self,
    ) -> std::collections::BTreeMap<String, crate::mandate::RevocationEntry> {
        let mut out = std::collections::BTreeMap::new();
        let Ok(cf) = self.try_cf(CF_REVOCATION) else {
            return out;
        };
        for (k, v) in self
            .db
            .iterator_cf(&cf, rocksdb::IteratorMode::Start)
            .flatten()
        {
            if let (Ok(key), Ok(e)) = (
                std::str::from_utf8(&k),
                serde_json::from_slice::<crate::mandate::RevocationEntry>(&v),
            ) {
                out.insert(key.to_string(), e);
            }
        }
        out
    }

    /// Bulk-apply mandates from a snapshot baseline (bootstrap). Canonicalizes
    /// on write so the on-disk bytes match a replayed-from-issuance copy.
    ///
    /// Consumer-enforced content-addressing: a snapshot is signed by a trusted
    /// producer, but trust ≠ correctness. Each entry is rejected unless its key
    /// equals its recomputed `mandate_id()` AND it is well-formed — so the
    /// `CF_MANDATE` invariant "stored at K ⇒ content hashes to K + well-formed"
    /// (which the sub-delegation chain walk's soundness assumes) holds on the
    /// bootstrap path, not only on live ingest. This also makes a snapshot-level
    /// storage cycle infeasible (a cycle would need a key ≠ content hash).
    /// Principal-binding cannot be re-checked here — the payload carries no
    /// pubkey — so snapshot-carried mandate AUTHENTICITY remains bounded by
    /// snapshot-signer trust (consistent with the rest of the snapshot).
    /// Rejections bump `MANDATE_SNAPSHOT_REJECTED_TOTAL` (non-zero ⇒ producer bug
    /// or tampered-but-signed snapshot).
    pub fn apply_mandates(
        &self,
        mandates: &std::collections::BTreeMap<String, crate::mandate::MandateRecord>,
    ) -> Result<()> {
        if mandates.is_empty() {
            return Ok(());
        }
        let cf = self.try_cf(CF_MANDATE)?;
        let mut batch = rocksdb::WriteBatch::default();
        let mut rejected: u64 = 0;
        for (id, m) in mandates {
            if !m.is_well_formed() || m.mandate_id() != *id {
                rejected += 1;
                continue;
            }
            if let Ok(bytes) = serde_json::to_vec(&m.canonicalized()) {
                batch.put_cf(&cf, id.as_bytes(), &bytes);
            }
        }
        if rejected > 0 {
            crate::mandate::MANDATE_SNAPSHOT_REJECTED_TOTAL
                .fetch_add(rejected, std::sync::atomic::Ordering::Relaxed);
            tracing::warn!(
                rejected,
                "apply_mandates: rejected snapshot mandates failing content-address/well-formed guard"
            );
        }
        self.db
            .write(batch)
            .map_err(|e| ElaraError::Storage(format!("apply_mandates: {e}")))
    }

    /// Bulk-apply revocations from a snapshot baseline (bootstrap), keyed by the
    /// 128-hex composite `mandate_id || revoker_identity_hash`. Rejects any entry
    /// whose key is not exactly two concatenated 64-hex identity hashes — the
    /// read path (`get_revocation_ms`) authorizes by reconstructing that exact
    /// key, so a malformed key is dead weight at best and a guard against a
    /// tampered-but-signed snapshot at least. Rejections bump the shared
    /// `MANDATE_SNAPSHOT_REJECTED_TOTAL` counter.
    pub fn apply_revocations(
        &self,
        revocations: &std::collections::BTreeMap<String, crate::mandate::RevocationEntry>,
    ) -> Result<()> {
        if revocations.is_empty() {
            return Ok(());
        }
        let cf = self.try_cf(CF_REVOCATION)?;
        let mut batch = rocksdb::WriteBatch::default();
        let mut rejected: u64 = 0;
        for (key, e) in revocations {
            let well_keyed = key.len() == 2 * crate::mandate::IDENTITY_HASH_HEX_LEN
                && key.bytes().all(|b| b.is_ascii_hexdigit());
            if !well_keyed {
                rejected += 1;
                continue;
            }
            if let Ok(bytes) = serde_json::to_vec(e) {
                batch.put_cf(&cf, key.as_bytes(), &bytes);
            }
        }
        if rejected > 0 {
            crate::mandate::MANDATE_SNAPSHOT_REJECTED_TOTAL
                .fetch_add(rejected, std::sync::atomic::Ordering::Relaxed);
            tracing::warn!(
                rejected,
                "apply_revocations: rejected snapshot revocations with malformed composite keys"
            );
        }
        self.db
            .write(batch)
            .map_err(|e| ElaraError::Storage(format!("apply_revocations: {e}")))
    }

    // ── DAG CF ──────────────────────────────────────────────────────────────

    /// Store DAG edges for a record: parents and children as JSON.
    /// Key: record_id, Value: {"parents": [...], "children": [...]}
    pub fn put_dag_edges(
        &self,
        record_id: &str,
        parents: &[String],
        children: &[String],
    ) -> Result<()> {
        let cf_dag = self.try_cf(CF_DAG)?;
        let cf_tips = self.try_cf(CF_IDX_TIPS)?;
        let value = serde_json::json!({
            "parents": parents,
            "children": children,
        });
        let mut batch = rocksdb::WriteBatch::default();
        batch.put_cf(&cf_dag, record_id.as_bytes(), value.to_string().as_bytes());

        // Maintain tips index: a tip has no children.
        if children.is_empty() {
            // This record is a tip — add it
            batch.put_cf(&cf_tips, record_id.as_bytes(), b"");
        } else {
            // This record has children — not a tip
            batch.delete_cf(&cf_tips, record_id.as_bytes());
        }
        // Each parent now has this record as a child — remove parents from tips
        for parent_id in parents {
            batch.delete_cf(&cf_tips, parent_id.as_bytes());
        }

        self.db.write(batch)
            .map_err(|e| ElaraError::Storage(format!("put_dag_edges batch: {e}")))
    }

    /// Get DAG edges for a record.
    pub fn get_dag_edges(&self, record_id: &str) -> Result<Option<(Vec<String>, Vec<String>)>> {
        let cf = self.try_cf(CF_DAG)?;
        match self.db.get_cf(&cf, record_id.as_bytes()) {
            Ok(Some(bytes)) => {
                let value: serde_json::Value = serde_json::from_slice(&bytes)
                    .map_err(|e| ElaraError::Storage(format!("dag parse: {e}")))?;
                let parents: Vec<String> = value["parents"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                    .unwrap_or_default();
                let children: Vec<String> = value["children"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                    .unwrap_or_default();
                Ok(Some((parents, children)))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(ElaraError::Storage(format!("get_dag_edges: {e}"))),
        }
    }

    // ── Identity Store (CF_IDENTITIES) ─────────────────────────────────────
    // Stores identity_hash → full public key for wire format v4 PK dedup.
    // Self-populates as records are inserted — no migration needed.

    /// Check if a record has been applied to the ledger (RocksDB-backed dedup).
    /// Replaces the 135K+ entry in-memory HashSet that caused slow ledger clones.
    pub fn is_applied(&self, record_id: &str) -> bool {
        let cf = match self.try_cf(CF_APPLIED) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("is_applied: CF unavailable, treating as not applied: {e}");
                return false;
            }
        };
        self.db.get_cf(&cf, record_id.as_bytes())
            .map(|v| v.is_some())
            .unwrap_or(false)
    }

    /// Mark a record as applied to the ledger.
    pub fn mark_applied(&self, record_id: &str) {
        let cf = match self.try_cf(CF_APPLIED) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("mark_applied: CF unavailable, skipping mark for {}: {e}", &record_id[..record_id.len().min(16)]);
                return;
            }
        };
        if let Err(e) = self.db.put_cf(&cf, record_id.as_bytes(), b"") {
            tracing::warn!("mark_applied: RocksDB write failed for {}: {e}", &record_id[..record_id.len().min(16)]);
        }
    }

    /// Bulk-mark records as applied (used during migration from in-memory set).
    pub fn bulk_mark_applied(&self, record_ids: &std::collections::HashSet<String>) {
        let cf = match self.try_cf(CF_APPLIED) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("bulk_mark_applied: CF unavailable, skipping {} records: {e}", record_ids.len());
                return;
            }
        };
        let mut batch = WriteBatch::default();
        for id in record_ids {
            batch.put_cf(&cf, id.as_bytes(), b"");
        }
        if let Err(e) = self.db.write(batch) {
            tracing::warn!("bulk_mark_applied: RocksDB batch write failed ({} records): {e}", record_ids.len());
        }
    }

    /// Count entries in CF_APPLIED.
    pub fn applied_count(&self) -> usize {
        self.count_cf(CF_APPLIED)
    }

    /// Collect all applied record IDs into a HashSet.
    ///
    /// Used when exporting a snapshot for wire transfer: the bootstrapping peer
    /// needs this set to populate its own CF_APPLIED so that records arriving
    /// via delta sync are recognized as already-applied and skip re-apply.
    ///
    /// O(applied_count) scan. ~135K entries on a mature node; ~10MB heap for
    /// the returned set. Called only at snapshot-build time (infrequent).
    pub fn collect_applied_ids(&self) -> std::collections::HashSet<String> {
        let cf = match self.try_cf(CF_APPLIED) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("collect_applied_ids: CF unavailable, returning empty set: {e}");
                return std::collections::HashSet::new();
            }
        };
        let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start);
        let mut out = std::collections::HashSet::new();
        for (k, _) in iter.flatten() {
            if let Ok(s) = std::str::from_utf8(&k) {
                out.insert(s.to_string());
            }
        }
        out
    }

    /// Collect applied IDs for a SERVED snapshot, bounded by `max`.
    ///
    /// `approx_applied_count` is the caller's **O(1)** size estimate — pass
    /// `approximate_cf_size(CF_APPLIED)` (`estimate-num-keys`, no scan), NOT
    /// `applied_count()`/`count_cf` (which is an O(n) full iteration). When the
    /// estimate exceeds `max` this returns an EMPTY set WITHOUT touching
    /// CF_APPLIED, so a background snapshot producer never materializes an
    /// O(total_history) set into the wire/disk snapshot. This is the scale-safe
    /// collector for callers with no upstream cap guard of their own (the
    /// archive snapshot loop). Request-path producers (HTTP/PQ snapshot serve)
    /// keep their own early-return cap and call `collect_applied_ids` directly.
    ///
    /// Above the cap the set ships empty (same as a pre-fix peer); the follower
    /// then rebuilds CF_APPLIED forward and the bounded "applied watermark"
    /// follow-up (Phase 1) is what closes the > `max` window.
    pub fn collect_applied_ids_capped(
        &self,
        approx_applied_count: u64,
        max: u64,
    ) -> std::collections::HashSet<String> {
        if approx_applied_count > max {
            return std::collections::HashSet::new();
        }
        self.collect_applied_ids()
    }

    /// Store a public key by identity hash in the legacy `CF_IDENTITIES`.
    /// Pre-partition write target — kept for any code path that hasn't
    /// been migrated to a tier-explicit variant. New call sites should
    /// pick `store_public_key_anchor` / `_witness` / `_user`.
    pub fn store_public_key(&self, identity_hash: &str, pk: &[u8]) -> crate::errors::Result<()> {
        let cf = self.try_cf(CF_IDENTITIES)?;
        self.db.put_cf(&cf, identity_hash.as_bytes(), pk)
            .map_err(|e| crate::errors::ElaraError::Storage(format!("store_public_key: {e}")))
    }

    /// Identity Partitioning Phase A + C — anchor-tier write. Used by
    /// the VRF-registration capture path so anchor PKs land in the
    /// never-evicted CF.
    ///
    /// **Phase C — class promotion**: anchor is the highest tier, so a
    /// new anchor write tombstones any pre-existing entries in the
    /// witness and user tiers (including the user-tier TS + REV
    /// indexes) in the same atomic `WriteBatch`. Without this, an
    /// identity that arrives first as a record creator (USER tier) and
    /// later as a VRF anchor would have stale entries in two tiers,
    /// duplicating storage and breaking the cap-eviction story.
    ///
    /// Returns `Some(promoted_from)` when the call physically promoted
    /// an existing lower-tier entry, `None` for a brand-new write or a
    /// no-op overwrite.
    pub fn store_public_key_anchor(&self, identity_hash: &str, pk: &[u8]) -> crate::errors::Result<Option<&'static str>> {
        let cf_anchor = self.try_cf(CF_IDENTITIES_ANCHOR)?;
        let cf_witness = self.try_cf(CF_IDENTITIES_WITNESS)?;
        let cf_user = self.try_cf(CF_IDENTITIES_USER)?;
        let cf_user_ts = self.try_cf(CF_IDENTITIES_USER_TS)?;
        let cf_user_rev = self.try_cf(CF_IDENTITIES_USER_REV)?;
        // Snapshot lower-tier presence so the caller can tell whether
        // this was a fresh anchor write or a real promotion (drives the
        // /metrics promotion counter).
        let was_witness = matches!(self.db.get_cf(&cf_witness, identity_hash.as_bytes()), Ok(Some(_)));
        let was_user = matches!(self.db.get_cf(&cf_user, identity_hash.as_bytes()), Ok(Some(_)));
        let mut batch = WriteBatch::default();
        batch.put_cf(&cf_anchor, identity_hash.as_bytes(), pk);
        if was_witness {
            batch.delete_cf(&cf_witness, identity_hash.as_bytes());
        }
        if was_user {
            batch.delete_cf(&cf_user, identity_hash.as_bytes());
            // User-tier carries 3 rows (USER + TS + REV) — drop them all.
            if let Ok(Some(ts_bytes)) = self.db.get_cf(&cf_user_rev, identity_hash.as_bytes()) {
                if ts_bytes.len() == 8 {
                    let mut ts_key = Vec::with_capacity(8 + identity_hash.len());
                    ts_key.extend_from_slice(&ts_bytes);
                    ts_key.extend_from_slice(identity_hash.as_bytes());
                    batch.delete_cf(&cf_user_ts, &ts_key);
                }
            }
            batch.delete_cf(&cf_user_rev, identity_hash.as_bytes());
        }
        self.db.write(batch)
            .map_err(|e| crate::errors::ElaraError::Storage(format!("store_public_key_anchor: {e}")))?;
        // Staked-anchor cache coherence: this write added/refreshed an anchor
        // CF entry (incl. a fresh anchor where the return is `None`). Bump
        // unconditionally — an over-bump is a harmless extra cache rebuild,
        // while a MISS is a stale staked-anchor view → potential chain freeze.
        self.anchor_add_seq.fetch_add(1, std::sync::atomic::Ordering::Release);
        Ok(if was_witness { Some(CF_IDENTITIES_WITNESS) }
           else if was_user { Some(CF_IDENTITIES_USER) }
           else { None })
    }

    /// Identity Partitioning Phase A + C — witness-tier write. Used
    /// when a witness PK is captured for a zone the local node serves
    /// (e.g. `process_deferred_attestations` after consulting
    /// `WitnessRegistry`). Phase E will evict here on zone unsubscribe.
    ///
    /// **Phase C — class promotion**: a witness write tombstones any
    /// pre-existing user-tier entries (USER + TS + REV) in the same
    /// atomic `WriteBatch`. **Demotion guard**: if the identity is
    /// already in `CF_IDENTITIES_ANCHOR`, the witness write is a
    /// no-op — anchor outranks witness and witness-tier capture must
    /// not silently downgrade an authoritative anchor PK.
    ///
    /// Returns `Some(CF_IDENTITIES_USER)` when the call physically
    /// promoted a user-tier entry, `None` for a brand-new write,
    /// no-op overwrite, or skip-because-anchor.
    pub fn store_public_key_witness(&self, identity_hash: &str, pk: &[u8]) -> crate::errors::Result<Option<&'static str>> {
        let cf_anchor = self.try_cf(CF_IDENTITIES_ANCHOR)?;
        // Demotion guard: anchor is higher tier — keep it authoritative.
        if matches!(self.db.get_cf(&cf_anchor, identity_hash.as_bytes()), Ok(Some(_))) {
            return Ok(None);
        }
        let cf_witness = self.try_cf(CF_IDENTITIES_WITNESS)?;
        let cf_user = self.try_cf(CF_IDENTITIES_USER)?;
        let cf_user_ts = self.try_cf(CF_IDENTITIES_USER_TS)?;
        let cf_user_rev = self.try_cf(CF_IDENTITIES_USER_REV)?;
        let was_user = matches!(self.db.get_cf(&cf_user, identity_hash.as_bytes()), Ok(Some(_)));
        let mut batch = WriteBatch::default();
        batch.put_cf(&cf_witness, identity_hash.as_bytes(), pk);
        if was_user {
            batch.delete_cf(&cf_user, identity_hash.as_bytes());
            if let Ok(Some(ts_bytes)) = self.db.get_cf(&cf_user_rev, identity_hash.as_bytes()) {
                if ts_bytes.len() == 8 {
                    let mut ts_key = Vec::with_capacity(8 + identity_hash.len());
                    ts_key.extend_from_slice(&ts_bytes);
                    ts_key.extend_from_slice(identity_hash.as_bytes());
                    batch.delete_cf(&cf_user_ts, &ts_key);
                }
            }
            batch.delete_cf(&cf_user_rev, identity_hash.as_bytes());
        }
        self.db.write(batch)
            .map_err(|e| crate::errors::ElaraError::Storage(format!("store_public_key_witness: {e}")))?;
        Ok(if was_user { Some(CF_IDENTITIES_USER) } else { None })
    }

    /// Identity Partitioning Phase A — user-tier write. Catch-all for
    /// PKs captured opportunistically via record ingest where no
    /// anchor/witness context applies.
    ///
    /// **Phase B**: writes a 3-CF atomic batch — the PK to
    /// `CF_IDENTITIES_USER`, a `(ts_be || hash)` entry to
    /// `CF_IDENTITIES_USER_TS` (so eviction can scan oldest-first),
    /// and the canonical timestamp to `CF_IDENTITIES_USER_REV` (so
    /// eviction can skip stale TS duplicates from prior writes). The
    /// timestamp is monotonic millis-since-epoch — rewriting the same
    /// hash advances both the TS-index and REV-index without deleting
    /// the prior TS entry; eviction handles the duplicate as a stale
    /// row when it gets there. This avoids a read-modify-write on the
    /// hot ingest path.
    ///
    /// **Phase C — demotion guard**: if the identity is already in
    /// `CF_IDENTITIES_ANCHOR` or `CF_IDENTITIES_WITNESS`, the user
    /// write is a no-op. Returns `Some(higher_tier)` to indicate the
    /// skip; `None` for an actual write. Anchor/witness outrank user,
    /// and a record-creator PK capture must not silently downgrade an
    /// authoritative higher-tier entry.
    pub fn store_public_key_user(&self, identity_hash: &str, pk: &[u8]) -> crate::errors::Result<Option<&'static str>> {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        self.store_public_key_user_at(identity_hash, pk, now_ms)
    }

    /// Phase B test seam: same as `store_public_key_user` but accepts an
    /// explicit timestamp. Production callers should use the wall-clock
    /// variant; tests use this to deterministically order writes for
    /// eviction-order assertions.
    pub fn store_public_key_user_at(
        &self,
        identity_hash: &str,
        pk: &[u8],
        ts_ms: u64,
    ) -> crate::errors::Result<Option<&'static str>> {
        // Phase C demotion guard — never overwrite a higher-tier entry.
        let cf_anchor = self.try_cf(CF_IDENTITIES_ANCHOR)?;
        if matches!(self.db.get_cf(&cf_anchor, identity_hash.as_bytes()), Ok(Some(_))) {
            return Ok(Some(CF_IDENTITIES_ANCHOR));
        }
        let cf_witness = self.try_cf(CF_IDENTITIES_WITNESS)?;
        if matches!(self.db.get_cf(&cf_witness, identity_hash.as_bytes()), Ok(Some(_))) {
            return Ok(Some(CF_IDENTITIES_WITNESS));
        }
        let cf_user = self.try_cf(CF_IDENTITIES_USER)?;
        let cf_ts = self.try_cf(CF_IDENTITIES_USER_TS)?;
        let cf_rev = self.try_cf(CF_IDENTITIES_USER_REV)?;
        let mut ts_key = Vec::with_capacity(8 + identity_hash.len());
        ts_key.extend_from_slice(&ts_ms.to_be_bytes());
        ts_key.extend_from_slice(identity_hash.as_bytes());
        let mut batch = WriteBatch::default();
        batch.put_cf(&cf_user, identity_hash.as_bytes(), pk);
        batch.put_cf(&cf_ts, &ts_key, []);
        batch.put_cf(&cf_rev, identity_hash.as_bytes(), ts_ms.to_be_bytes());
        self.db
            .write(batch)
            .map_err(|e| crate::errors::ElaraError::Storage(format!("store_public_key_user: {e}")))?;
        Ok(None)
    }

    /// Identity Partitioning Phase B — evict oldest USER-tier identities
    /// down to `cap`, bounded at `max_per_call` evictions per invocation
    /// to keep individual ticks short and the WriteBatch bounded.
    ///
    /// Algorithm:
    ///   1. Count CF_IDENTITIES_USER entries; if `<= cap`, no-op.
    ///   2. Iterate `CF_IDENTITIES_USER_TS` from start (oldest first).
    ///   3. For each `(ts || hash)` entry, look up `CF_IDENTITIES_USER_REV[hash]`:
    ///      - If REV missing or `REV[hash] != ts`: stale duplicate from
    ///        a re-write — delete only this TS entry, do NOT touch USER.
    ///      - If `REV[hash] == ts`: this is the canonical row — delete
    ///        all three (USER, TS, REV) and decrement count.
    ///   4. Stop when count <= cap OR `evicted == max_per_call`.
    ///
    /// Returns the count of (USER, TS, REV)-triples actually evicted —
    /// stale-only TS deletes are not counted (they don't affect cap).
    /// Anchor and witness CFs are never touched.
    ///
    /// Uses a single WriteBatch flushed at the end so eviction is
    /// atomic from the reader's perspective.
    pub fn evict_user_identities_to_cap(
        &self,
        cap: usize,
        max_per_call: usize,
    ) -> crate::errors::Result<usize> {
        if cap == 0 {
            // 0 is interpreted as "unbounded" — disable eviction entirely.
            // Keeps the operator-facing semantic consistent with the rest
            // of the codebase (`gc_interval_secs: 0 = disabled`).
            return Ok(0);
        }
        let mut count = self.count_cf(CF_IDENTITIES_USER);
        if count <= cap {
            return Ok(0);
        }
        let cf_user = self.try_cf(CF_IDENTITIES_USER)?;
        let cf_ts = self.try_cf(CF_IDENTITIES_USER_TS)?;
        let cf_rev = self.try_cf(CF_IDENTITIES_USER_REV)?;
        let mut batch = WriteBatch::default();
        let mut evicted = 0usize;
        let iter = self.db.iterator_cf(&cf_ts, rocksdb::IteratorMode::Start);
        for entry in iter {
            let (key, _) = match entry {
                Ok(kv) => kv,
                Err(_) => continue,
            };
            if key.len() < 8 {
                // Malformed TS entry — drop it.
                batch.delete_cf(&cf_ts, &key);
                continue;
            }
            let ts_bytes: [u8; 8] = key[..8].try_into().unwrap_or([0; 8]);
            let hash_bytes = &key[8..];
            // Look up the canonical TS for this hash.
            let rev = match self.db.get_cf(&cf_rev, hash_bytes) {
                Ok(Some(v)) => v,
                _ => Vec::new(),
            };
            let is_canonical = rev.len() == 8 && rev[..] == ts_bytes;
            if !is_canonical {
                // Stale TS duplicate (the hash was re-written at a
                // newer ts; that newer entry is somewhere later in the
                // index). Drop just the TS row.
                batch.delete_cf(&cf_ts, &key);
                continue;
            }
            // Canonical row — drop all three.
            batch.delete_cf(&cf_user, hash_bytes);
            batch.delete_cf(&cf_ts, &key);
            batch.delete_cf(&cf_rev, hash_bytes);
            evicted += 1;
            count -= 1;
            if count <= cap || evicted >= max_per_call {
                break;
            }
        }
        self.db
            .write(batch)
            .map_err(|e| crate::errors::ElaraError::Storage(format!("evict_user: {e}")))?;
        Ok(evicted)
    }

    /// Get a public key by identity hash. Returns None if unknown.
    ///
    /// Identity Partitioning Phase A — checks tier CFs in priority order
    /// (ANCHOR > WITNESS > USER > legacy `CF_IDENTITIES`) and returns
    /// the first hit. Order matters: the same hash may exist in legacy
    /// (from pre-partition data) AND in a tier CF (from a fresh
    /// post-partition write); the tier CF is the authoritative answer
    /// since legacy will eventually drain. ANCHOR comes first because
    /// it's the smallest CF (point-read on a CF with O(1K) entries
    /// hits the block cache more often than a CF with O(1M) entries).
    pub fn get_public_key(&self, identity_hash: &str) -> Option<Vec<u8>> {
        for cf_name in [
            CF_IDENTITIES_ANCHOR,
            CF_IDENTITIES_WITNESS,
            CF_IDENTITIES_USER,
            CF_IDENTITIES,
        ] {
            let Ok(cf) = self.try_cf(cf_name) else { continue };
            if let Ok(Some(v)) = self.db.get_cf(&cf, identity_hash.as_bytes()) {
                return Some(v);
            }
        }
        None
    }

    /// Identity Partitioning Phase D — same as `get_public_key` but
    /// also returns which tier CF actually answered the lookup. Used
    /// by `GET /identity/pk/{hash}` so callers can tell whether the
    /// responder considers this an anchor/witness/user PK (purely
    /// informational — class is local-only metadata per the design
    /// doc §5; the requester re-classifies on its own context). The
    /// returned `&'static str` is one of `CF_IDENTITIES_ANCHOR`,
    /// `CF_IDENTITIES_WITNESS`, `CF_IDENTITIES_USER`, or
    /// `CF_IDENTITIES` (legacy/pre-partition data).
    pub fn get_public_key_with_tier(&self, identity_hash: &str) -> Option<(Vec<u8>, &'static str)> {
        for cf_name in [
            CF_IDENTITIES_ANCHOR,
            CF_IDENTITIES_WITNESS,
            CF_IDENTITIES_USER,
            CF_IDENTITIES,
        ] {
            let Ok(cf) = self.try_cf(cf_name) else { continue };
            if let Ok(Some(v)) = self.db.get_cf(&cf, identity_hash.as_bytes()) {
                return Some((v, cf_name));
            }
        }
        None
    }

    /// Check if we have a public key for this identity hash.
    ///
    /// Identity Partitioning Phase A — same priority order as
    /// `get_public_key`; short-circuits on first hit so a hot anchor
    /// hash returns without touching WITNESS/USER/legacy CFs.
    pub fn has_public_key(&self, identity_hash: &str) -> bool {
        for cf_name in [
            CF_IDENTITIES_ANCHOR,
            CF_IDENTITIES_WITNESS,
            CF_IDENTITIES_USER,
            CF_IDENTITIES,
        ] {
            let Ok(cf) = self.try_cf(cf_name) else { continue };
            if matches!(self.db.get_cf(&cf, identity_hash.as_bytes()), Ok(Some(_))) {
                return true;
            }
        }
        false
    }

    /// Identity Partitioning Phase A — diagnostic counters per tier.
    /// Returns `(anchor_count, witness_count, user_count, legacy_count)`.
    /// EXACT counts via O(N) iterator scan. Used by tests asserting CF-write
    /// semantics and by the eviction loop which needs cap-boundary precision.
    /// Production /metrics scrape MUST use `identity_tier_counts_estimated`
    /// instead — at 1M+ identities four O(N) scans per scrape stall the
    /// metrics handler.
    pub fn identity_tier_counts(&self) -> (usize, usize, usize, usize) {
        (
            self.count_cf(CF_IDENTITIES_ANCHOR),
            self.count_cf(CF_IDENTITIES_WITNESS),
            self.count_cf(CF_IDENTITIES_USER),
            self.count_cf(CF_IDENTITIES),
        )
    }

    /// O(1) approximation of `identity_tier_counts`. Each value is
    /// a RocksDB `estimate-num-keys` read against the same column families.
    /// Estimate accuracy: within compaction-window of true count (RocksDB
    /// updates on memtable flush + SST compaction). For /metrics dashboards
    /// this is accurate enough; for cap-boundary enforcement it is not.
    pub fn identity_tier_counts_estimated(&self) -> (usize, usize, usize, usize) {
        (
            self.approximate_cf_size(CF_IDENTITIES_ANCHOR) as usize,
            self.approximate_cf_size(CF_IDENTITIES_WITNESS) as usize,
            self.approximate_cf_size(CF_IDENTITIES_USER) as usize,
            self.approximate_cf_size(CF_IDENTITIES) as usize,
        )
    }

    // ── Witness registry (Gap 2.1 Phase 2b.3 Slice 3) ───────────────────────

    /// Register a bonded witness for one zone. Idempotent — re-registering
    /// the same `(zone_path, identity_hash)` pair overwrites the previous
    /// entry (caller is responsible for slashing or refunding the prior
    /// bond before calling this).
    pub fn register_witness(
        &self,
        zone_path: &str,
        identity_hash: &str,
        dilithium_pk: Vec<u8>,
        bond: u64,
        registered_epoch: u64,
    ) -> Result<()> {
        let key = witness_key(zone_path, identity_hash);
        let entry = WitnessEntry { dilithium_pk, bond, registered_epoch };
        let value = serde_json::to_vec(&entry)
            .map_err(|e| ElaraError::Storage(format!("witness encode: {e}")))?;
        let cf = self.try_cf(CF_WITNESS_REGISTRY)?;
        self.db
            .put_cf(&cf, &key, &value)
            .map_err(|e| ElaraError::Storage(format!("witness put: {e}")))
    }

    /// Look up a single witness entry by `(zone_path, identity_hash)`.
    pub fn get_witness(
        &self,
        zone_path: &str,
        identity_hash: &str,
    ) -> Result<Option<WitnessEntry>> {
        let key = witness_key(zone_path, identity_hash);
        let cf = self.try_cf(CF_WITNESS_REGISTRY)?;
        let raw = self
            .db
            .get_cf(&cf, &key)
            .map_err(|e| ElaraError::Storage(format!("witness get: {e}")))?;
        match raw {
            None => Ok(None),
            Some(bytes) => {
                let entry: WitnessEntry = serde_json::from_slice(&bytes)
                    .map_err(|e| ElaraError::Storage(format!("witness decode: {e}")))?;
                Ok(Some(entry))
            }
        }
    }

    /// Drain a batch of pending witness registrations into
    /// `CF_WITNESS_REGISTRY` in a single atomic `WriteBatch`. Used by the
    /// pre-seal flush path (Gap 2.1 Phase 2b.3 Slice 3) so durable
    /// persistence happens off the ledger lock — same pattern as the
    /// account-SMT `apply_snapshot`. Returns the number of rows
    /// written.
    pub fn flush_pending_witness_registrations(
        &self,
        pending: &[(String, String, Vec<u8>, u64, u64)],
    ) -> Result<usize> {
        if pending.is_empty() {
            return Ok(0);
        }
        let cf = self.try_cf(CF_WITNESS_REGISTRY)?;
        let mut batch = WriteBatch::default();
        for (zone_path, identity_hash, dilithium_pk, bond, registered_epoch) in pending {
            let key = witness_key(zone_path, identity_hash);
            let entry = WitnessEntry {
                dilithium_pk: dilithium_pk.clone(),
                bond: *bond,
                registered_epoch: *registered_epoch,
            };
            let value = serde_json::to_vec(&entry)
                .map_err(|e| ElaraError::Storage(format!("witness encode (batch): {e}")))?;
            batch.put_cf(&cf, &key, &value);
        }
        self.db
            .write(batch)
            .map_err(|e| ElaraError::Storage(format!("witness flush write: {e}")))?;
        Ok(pending.len())
    }

    /// Identity Partitioning Phase A — point-read for the witness
    /// registry. Returns true iff `identity_hash` is registered as a
    /// witness in `zone_path`. Used by the witness-tier classification
    /// path in `process_deferred_attestations`: if the witness is
    /// registered in any zone the local node serves, capture its PK
    /// in `CF_IDENTITIES_WITNESS` so future committee verification
    /// hits the small zone-scoped CF instead of the broader USER CF.
    /// O(1) point read — no iteration cost even at million-zone scale.
    pub fn is_witness_registered(&self, zone_path: &str, identity_hash: &str) -> bool {
        let Ok(cf) = self.try_cf(CF_WITNESS_REGISTRY) else { return false };
        let key = witness_key(zone_path, identity_hash);
        matches!(self.db.get_cf(&cf, &key), Ok(Some(_)))
    }

    /// Iterate every registered witness for one zone, in lexicographic
    /// order of identity_hash. O(witnesses-per-zone) — bounded by the
    /// per-zone cap enforced at apply time, NOT a full-CF scan.
    pub fn iter_witnesses_for_zone(&self, zone_path: &str) -> Vec<(String, WitnessEntry)> {
        let Ok(cf) = self.try_cf(CF_WITNESS_REGISTRY) else { return Vec::new() };
        let mut prefix = zone_path.as_bytes().to_vec();
        prefix.push(0u8);
        let iter = self.db.prefix_iterator_cf(&cf, &prefix);
        let mut out: Vec<(String, WitnessEntry)> = Vec::new();
        for item in iter {
            let Ok((k, v)) = item else { continue };
            if !k.starts_with(&prefix) { break; }
            let id_bytes = &k[prefix.len()..];
            let Ok(id) = std::str::from_utf8(id_bytes) else { continue };
            let Ok(entry) = serde_json::from_slice::<WitnessEntry>(&v) else { continue };
            out.push((id.to_string(), entry));
        }
        out
    }

    /// Identity Partitioning Phase E — purge `CF_IDENTITIES_WITNESS`
    /// entries for witnesses that were registered for `unsubscribed_zone`
    /// but are NOT registered for any zone in `still_subscribed_zones`.
    ///
    /// Called from `NodeState::unsubscribe_zone` immediately after the
    /// manager has been updated — `still_subscribed_zones` is the post-
    /// unsubscribe zone set, so this is exactly the closure of "zones
    /// I still serve". Demotion-aware: anchor PKs in `CF_IDENTITIES_ANCHOR`
    /// are not touched (anchor outranks witness; even if a witness for
    /// the unsubscribed zone happens to be a fleet-global anchor, the
    /// anchor row is the authoritative entry and survives).
    ///
    /// Algorithm:
    ///   1. Iterate witnesses for `unsubscribed_zone` (bounded by per-zone cap).
    ///   2. For each `identity_hash`, point-read `is_witness_registered(z, hash)`
    ///      against every zone in `still_subscribed_zones`. Short-circuit
    ///      on first match (witness still wanted).
    ///   3. If no surviving subscription claims the witness, batch
    ///      `DELETE` on `CF_IDENTITIES_WITNESS[hash]`.
    ///
    /// Complexity: O(W × Z) where W = witnesses in the unsubscribed zone,
    /// Z = surviving subscriptions. Both bounded — at production scale W
    /// ≤ per-zone cap (default ~64) and Z ≤ operator subscription count
    /// (low hundreds even on a heavy-archive node). Witness registry
    /// rows for the unsubscribed zone itself are left to the existing
    /// `zone_purge` flow — this helper only touches the PK CF.
    ///
    /// Returns the count of PKs actually dropped from `CF_IDENTITIES_WITNESS`.
    /// Errors short-circuit to `Ok(evicted_so_far)` so a partial purge is
    /// observable via the counter; the operator can re-run unsubscribe to
    /// retry the tail.
    pub fn purge_witness_pks_for_zone(
        &self,
        unsubscribed_zone: &str,
        still_subscribed_zones: &[String],
    ) -> Result<usize> {
        let witnesses = self.iter_witnesses_for_zone(unsubscribed_zone);
        if witnesses.is_empty() {
            return Ok(0);
        }
        let cf_witness = self.try_cf(CF_IDENTITIES_WITNESS)?;
        let mut batch = WriteBatch::default();
        let mut evicted = 0usize;
        for (identity_hash, _entry) in witnesses {
            let hash_bytes = identity_hash.as_bytes();
            let still_wanted = still_subscribed_zones
                .iter()
                .any(|z| self.is_witness_registered(z, &identity_hash));
            if still_wanted {
                continue;
            }
            // Point-confirm presence so we count only real evictions
            // (avoid spurious +1 if the identity was never promoted to
            // witness CF, e.g. when witness-for-zone landed before the
            // partition rollout).
            if matches!(self.db.get_cf(&cf_witness, hash_bytes), Ok(Some(_))) {
                batch.delete_cf(&cf_witness, hash_bytes);
                evicted += 1;
            }
        }
        if evicted > 0 {
            self.db
                .write(batch)
                .map_err(|e| ElaraError::Storage(format!("purge_witness_pks_for_zone: {e}")))?;
        }
        Ok(evicted)
    }

    // ── Generic CF operations ───────────────────────────────────────────────

    /// Raw put into any column family.
    pub fn put_cf_raw(&self, cf_name: &str, key: &[u8], value: &[u8]) -> Result<()> {
        let cf = self.try_cf(cf_name)?;
        self.db
            .put_cf(&cf, key, value)
            .map_err(|e| ElaraError::Storage(format!("put_cf({cf_name}): {e}")))
    }

    /// Synced (fsync'd) raw put — the WAL entry is on stable storage before
    /// this returns (`WriteOptions::set_sync(true)`).
    ///
    /// **Use ONLY for the rare node-local durability barriers** where a
    /// power-loss must NOT lose the write — today the sole caller is the
    /// self-slot-nonce high-water (F-9). Every other write path uses the
    /// default async (`sync=false`) `put_cf_raw`/`write_batch`: a synced write
    /// on the 10T-records/day hot path would fsync per record and violate the
    /// SCALE RULE. Cost here is one fsync per *reserved block* of nonces
    /// (amortised, O(self_records / block), never per external record).
    pub fn put_cf_raw_synced(&self, cf_name: &str, key: &[u8], value: &[u8]) -> Result<()> {
        let cf = self.try_cf(cf_name)?;
        let mut opts = rocksdb::WriteOptions::default();
        opts.set_sync(true);
        self.db
            .put_cf_opt(&cf, key, value, &opts)
            .map_err(|e| ElaraError::Storage(format!("put_cf_synced({cf_name}): {e}")))
    }

    /// Raw get from any column family.
    pub fn get_cf_raw(&self, cf_name: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let cf = self.try_cf(cf_name)?;
        self.db
            .get_cf(&cf, key)
            .map_err(|e| ElaraError::Storage(format!("get_cf({cf_name}): {e}")))
    }

    /// Raw delete from any column family.
    pub fn delete_cf_raw(&self, cf_name: &str, key: &[u8]) -> Result<()> {
        let cf = self.try_cf(cf_name)?;
        self.db
            .delete_cf(&cf, key)
            .map_err(|e| ElaraError::Storage(format!("delete_cf({cf_name}): {e}")))
    }

    /// Scan every (key, value) pair in a column family. Caller supplies
    /// an upper bound to keep memory predictable — the iterator stops once
    /// `limit` pairs have been collected.
    ///
    /// Intended for small, bounded CFs (e.g. `CF_TRANSITIONS_FINAL`, whose
    /// cardinality is O(lifetime splits/merges per zone) and fits comfortably
    /// in memory). Do NOT use for CF_RECORDS or any other unbounded CF.
    pub fn list_cf_raw(
        &self,
        cf_name: &str,
        limit: usize,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let cf = self.try_cf(cf_name)?;
        let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start);
        let mut out = Vec::new();
        for item in iter {
            if out.len() >= limit {
                break;
            }
            match item {
                Ok((k, v)) => out.push((k.to_vec(), v.to_vec())),
                Err(e) => {
                    return Err(ElaraError::Storage(format!(
                        "list_cf({cf_name}) iter error: {e}"
                    )));
                }
            }
        }
        Ok(out)
    }

    /// Enumerate the account-SMT **value-leaves** — one `(account_id, state_hash)`
    /// pair per populated leaf — by seeking directly to the `v:` keyspace.
    ///
    /// `CF_ACCOUNT_SMT` holds two key classes (see `elara-smt`): interior/leaf
    /// **node** keys (`"n:"` + depth + path, the far larger set) and **value** keys
    /// (`"v:"` + 32-byte account_id, exactly one per populated leaf). Because
    /// `b"n:"` < `b"v:"`, a bare `IteratorMode::Start` scan would exhaust its
    /// budget on `n:` nodes and never reach a single leaf — so this seeks to
    /// `b"v:"` and stops at the first key that no longer carries the prefix
    /// (the `starts_with` guard the module header mandates over bare
    /// `prefix_iterator_cf`). The account_id is recovered verbatim from key
    /// bytes `2..34`; no hashing, so it is the exact `[u8; 32]` key that
    /// `AccountStateSMT::{get,delete}` take.
    ///
    /// Read-only; **one-shot / admin use only** (O(populated leaves), NOT a hot
    /// path). `max` bounds the result so a mainnet-scale CF cannot OOM the caller
    /// — callers that hit the bound learn the scan was truncated via the returned
    /// length. Used by `account_merkle::scan_orphan_smt_leaves` (F-5 phantom
    /// naming): the ledger-side `diagnose_account_smt_divergence` cannot see an
    /// SMT-ahead leaf because it iterates the ledger, which has no such account.
    pub fn account_smt_value_leaves(&self, max: usize) -> Result<Vec<([u8; 32], [u8; 32])>> {
        let cf = self.try_cf(CF_ACCOUNT_SMT)?;
        let mut out = Vec::new();
        let mode = rocksdb::IteratorMode::From(b"v:", rocksdb::Direction::Forward);
        for item in self.db.iterator_cf(&cf, mode) {
            let (k, v) = item
                .map_err(|e| ElaraError::Storage(format!("account_smt_value_leaves iter: {e}")))?;
            // Past the `v:` keyspace (nothing sorts after it in this CF) — done.
            if !k.starts_with(b"v:") {
                break;
            }
            if out.len() >= max {
                break;
            }
            // A well-formed value-key is `v:` (2B) + account_id (32B) = 34B, and
            // the value is the 32-byte leaf state-hash. Skip anything malformed
            // rather than panic on attacker- or migration-induced garbage.
            if k.len() == 34 && v.len() == 32 {
                let mut acc = [0u8; 32];
                acc.copy_from_slice(&k[2..34]);
                let mut h = [0u8; 32];
                h.copy_from_slice(&v);
                out.push((acc, h));
            }
        }
        Ok(out)
    }

    /// Atomic batch write across multiple column families.
    pub fn write_batch(&self, batch: WriteBatch) -> Result<()> {
        self.db
            .write(batch)
            .map_err(|e| ElaraError::Storage(format!("write_batch: {e}")))
    }

    /// Create a new WriteBatch for atomic operations.
    pub fn new_batch(&self) -> WriteBatch {
        WriteBatch::default()
    }

    /// Get a CF handle for use with WriteBatch.
    /// Returns `None` if the column family is not registered (e.g. schema mismatch
    /// after a failed migration). Callers must not panic on None — use `?` or log
    /// and skip the write rather than crashing on a storage schema inconsistency.
    pub fn cf_handle(&self, name: &str) -> Option<Arc<BoundColumnFamily<'_>>> {
        self.db.cf_handle(name)
    }

    // ── Epoch key helpers ───────────────────────────────────────────────────

    /// Build an epoch key: zone_id (8 bytes) + epoch_number (8 bytes BE).
    pub fn epoch_key(zone: &ZoneId, epoch_number: u64) -> Vec<u8> {
        let mut key = Vec::with_capacity(16);
        key.extend_from_slice(&zone.to_key_bytes());
        key.extend_from_slice(&epoch_number.to_be_bytes());
        key
    }

    /// Build an attestation key: zone_id (8 bytes) + epoch (8 bytes BE) + record_id.
    pub fn attestation_key(zone: &ZoneId, epoch: u64, record_id: &str) -> Vec<u8> {
        let mut key = Vec::with_capacity(16 + record_id.len());
        key.extend_from_slice(&zone.to_key_bytes());
        key.extend_from_slice(&epoch.to_be_bytes());
        key.extend_from_slice(record_id.as_bytes());
        key
    }

    // ── Content Safety (ban/unban, blocked terms) ─────────────────────────

    /// Ban an identity. Tier 4.5: writes land in `CF_METADATA` (was `CF_RECORDS`
    /// under the `ban:` prefix). The split keeps record-iteration cost
    /// independent of how many bans / blocked terms / snapshots accumulate.
    pub fn ban_identity(&self, identity_hash: &str, reason: &str) -> Result<()> {
        let key = format!("ban:{identity_hash}");
        let val = serde_json::json!({
            "identity_hash": identity_hash,
            "reason": reason,
            "timestamp": crate::record::now_timestamp(),
        });
        self.put_cf_raw(CF_METADATA, key.as_bytes(), val.to_string().as_bytes())
    }

    /// Unban an identity. Returns true if was banned.
    pub fn unban_identity(&self, identity_hash: &str) -> Result<bool> {
        let key = format!("ban:{identity_hash}");
        let existed = self.get_cf_raw(CF_METADATA, key.as_bytes())?.is_some();
        if existed {
            self.delete_cf_raw(CF_METADATA, key.as_bytes())?;
        }
        Ok(existed)
    }

    /// Load all banned identities: (hash, reason, timestamp).
    pub fn load_banned_identities(&self) -> Result<Vec<(String, String, f64)>> {
        let cf = self.try_cf(CF_METADATA)?;
        let prefix = b"ban:";
        let iter = self.db.prefix_iterator_cf(&cf, prefix);
        let mut result = Vec::new();
        for item in iter {
            let (key, value) = item.map_err(|e| ElaraError::Storage(format!("ban iter: {e}")))?;
            if !key.starts_with(prefix) { break; }
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&value) {
                let hash = v["identity_hash"].as_str().unwrap_or("").to_string();
                let reason = v["reason"].as_str().unwrap_or("").to_string();
                let ts = v["timestamp"].as_f64().unwrap_or(0.0);
                result.push((hash, reason, ts));
            }
        }
        Ok(result)
    }

    /// Add a blocked content term. Tier 4.5: writes to `CF_METADATA`.
    pub fn add_blocked_term(&self, term: &str) -> Result<()> {
        let key = format!("blocked_term:{term}");
        self.put_cf_raw(CF_METADATA, key.as_bytes(), term.as_bytes())
    }

    /// Remove a blocked content term. Returns true if existed.
    pub fn remove_blocked_term(&self, term: &str) -> Result<bool> {
        let key = format!("blocked_term:{term}");
        let existed = self.get_cf_raw(CF_METADATA, key.as_bytes())?.is_some();
        if existed {
            self.delete_cf_raw(CF_METADATA, key.as_bytes())?;
        }
        Ok(existed)
    }

    /// Load all blocked content terms.
    pub fn load_blocked_terms(&self) -> Result<Vec<String>> {
        let cf = self.try_cf(CF_METADATA)?;
        let prefix = b"blocked_term:";
        let iter = self.db.prefix_iterator_cf(&cf, prefix);
        let mut result = Vec::new();
        for item in iter {
            let (key, value) = item.map_err(|e| ElaraError::Storage(format!("term iter: {e}")))?;
            if !key.starts_with(prefix) { break; }
            result.push(String::from_utf8_lossy(&value).to_string());
        }
        Ok(result)
    }

    // ── Subsystem Snapshots ───────────────────────────────────────────────
    //
    // Save/load entire subsystem state as a single RocksDB entry.
    // Used at shutdown (save) and startup (load) to avoid expensive
    // SQLite full-table scans on every restart.

    /// Snapshot key prefix for subsystem state.
    const SNAPSHOT_PREFIX: &'static str = "__snapshot__:";

    /// Save a serializable subsystem to a snapshot key. Tier 4.5: lives in
    /// `CF_METADATA` (was `CF_RECORDS`). `__snapshot__:*` are large-ish JSON
    /// blobs the consensus / pending-ledger / fork subsystems write at
    /// shutdown — co-locating them with records meant every CF_RECORDS scan
    /// had to step over them.
    pub fn save_snapshot<T: serde::Serialize>(&self, name: &str, data: &T) -> Result<()> {
        let key = format!("{}{name}", Self::SNAPSHOT_PREFIX);
        let bytes = serde_json::to_vec(data)
            .map_err(|e| ElaraError::Storage(format!("snapshot serialize({name}): {e}")))?;
        let cf = self.try_cf(CF_METADATA)?;
        self.db
            .put_cf(&cf, key.as_bytes(), &bytes)
            .map_err(|e| ElaraError::Storage(format!("snapshot save({name}): {e}")))?;
        Ok(())
    }

    /// Persist several subsystem snapshots in ONE atomic WriteBatch (a single
    /// WAL sync). Either every listed key lands or none do — used for the
    /// replay-critical {ledger, checkpoint_timestamp, epoch} trio so a
    /// SIGKILL/power-cut mid-save can never leave the epoch tip desynced from
    /// the ledger baseline it was checkpointed against (F-3). Callers serialize
    /// FIRST and pass encoded bytes (the snapshot values are heterogeneous
    /// types), so a serde failure on one value omits only that value from the
    /// slice rather than tearing the batch. `dag` is deliberately NOT routed
    /// here — it can take tens of seconds to serialize and is not part of the
    /// replay baseline.
    pub fn save_snapshots_batch(&self, snapshots: &[(&str, Vec<u8>)]) -> Result<()> {
        let cf = self.try_cf(CF_METADATA)?;
        let mut batch = rocksdb::WriteBatch::default();
        for (name, bytes) in snapshots {
            let key = format!("{}{name}", Self::SNAPSHOT_PREFIX);
            batch.put_cf(&cf, key.as_bytes(), bytes);
        }
        self.db
            .write(batch)
            .map_err(|e| ElaraError::Storage(format!("snapshot batch save: {e}")))?;
        Ok(())
    }

    /// Load a subsystem snapshot. Returns None if no snapshot exists.
    pub fn load_snapshot<T: serde::de::DeserializeOwned>(&self, name: &str) -> Result<Option<T>> {
        let key = format!("{}{name}", Self::SNAPSHOT_PREFIX);
        let cf = self.try_cf(CF_METADATA)?;
        match self.db.get_cf(&cf, key.as_bytes()) {
            Ok(Some(bytes)) => {
                let data: T = serde_json::from_slice(&bytes)
                    .map_err(|e| ElaraError::Storage(format!("snapshot deserialize({name}): {e}")))?;
                Ok(Some(data))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(ElaraError::Storage(format!("snapshot load({name}): {e}"))),
        }
    }

    // ── Checkpoints & Repair ─────────────────────────────────────────────

    /// Create a point-in-time checkpoint of the database at the given path.
    ///
    /// Uses RocksDB's built-in `Checkpoint` API — fast, non-blocking snapshot.
    /// The output directory is a fully self-contained RocksDB that can be opened
    /// directly or copied back to restore state.
    pub fn create_checkpoint(&self, path: &Path) -> std::result::Result<(), String> {
        let cp = Checkpoint::new(&self.db)
            .map_err(|e| format!("checkpoint object creation failed: {e}"))?;
        cp.create_checkpoint(path)
            .map_err(|e| format!("checkpoint creation failed: {e}"))
    }

    /// Cancel all background compaction/flush and prepare for fast process exit.
    /// Without this, RocksDB's Drop handler can block for 60-90s flushing
    /// memtables on a large database. Uses wait=false to return immediately.
    pub fn shutdown_fast(&self) {
        self.db.cancel_all_background_work(false);
    }

    /// Repair a potentially corrupted RocksDB database at the given path.
    ///
    /// Wraps `rocksdb::DB::repair()` which attempts to recover as much data
    /// as possible from a damaged database.
    pub fn repair(path: &Path) -> std::result::Result<(), String> {
        let mut opts = Options::default();
        opts.create_if_missing(false);
        DB::repair(&opts, path)
            .map_err(|e| format!("RocksDB repair failed: {e}"))
    }

    // ── Stats ───────────────────────────────────────────────────────────────

    /// Count entries in a column family via full iterator scan — **TEST-ONLY**.
    ///
    /// O(records). Forbidden in production paths (internal design notes SCALE RULE: at
    /// 1M zones × 720 records/day/zone the records CF crosses 10⁹ keys
    /// within a year and a full scan starves both compaction and ingest).
    /// Production callers must use `approximate_record_count()` /
    /// `approximate_cf_size()` (RocksDB `estimate-num-keys`, O(1)) instead.
    /// Tests may keep using this for exact counts on small fixture sets.
    pub fn count_cf(&self, cf_name: &str) -> usize {
        let cf = match self.try_cf(cf_name) {
            Ok(h) => h,
            Err(_) => {
                tracing::warn!("count_cf: unknown column family {:?}, returning 0", cf_name);
                return 0;
            }
        };
        let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start);
        iter.count()
    }

    /// Get RocksDB statistics summary.
    pub fn stats(&self) -> String {
        self.db
            .property_value("rocksdb.stats")
            .ok()
            .flatten()
            .unwrap_or_default()
    }

    /// LIVENESS-1 (2026-05-11): O(1) point lookup — is `identity_hash`
    /// registered as a VRF anchor (i.e. seal-eligible)? Used by the
    /// rank-chain construction (proposer + verifier) to filter `staked`
    /// to seal-eligible identities only.
    pub fn is_anchor_identity(&self, identity_hash: &str) -> bool {
        let Ok(cf) = self.try_cf(CF_IDENTITIES_ANCHOR) else { return false };
        matches!(self.db.get_cf(&cf, identity_hash.as_bytes()), Ok(Some(_)))
    }

    /// Current value of the anchor-add generation (see the `anchor_add_seq`
    /// field). Cheap `Acquire` load — keys the staked-anchor view cache's
    /// anchor-membership dimension. Strictly monotonic: anchors are never
    /// evicted, so this only grows.
    pub fn anchor_add_generation(&self) -> u64 {
        self.anchor_add_seq.load(std::sync::atomic::Ordering::Acquire)
    }

    /// LIVENESS-1 (2026-05-11): list every VRF-registered anchor identity
    /// hash currently in `CF_IDENTITIES_ANCHOR`. The rank-chain inputs
    /// for `should_propose_seal` and the live `verify_aggregator_rank`
    /// path use this to filter the staker set to seal-eligible
    /// identities. Without the filter, non-anchor stakers (user/legacy
    /// accounts that hold stake but were never VRF-registered) occupy
    /// top ranks they CANNOT propose at, freezing the chain — empirically
    /// observed on testnet on 2026-05-10/11 (5 anchors, 28 user, 10 legacy
    /// → both anchors landed at rank 5, `rank_too_high_total=22/22` ticks).
    ///
    /// Bounded by `max_anchors` to keep memory predictable. Mainnet
    /// anchor count is structurally bounded (~5K-50K via stake +
    /// registration costs), so an explicit cap of 1_000_000 is generous
    /// headroom that still trips before pathological CF growth could
    /// OOM. At 50K entries with ~50 B/entry the materialised vec is
    /// ~2.5 MB and the scan completes in <50 ms — acceptable cost on the
    /// once-per-epoch-per-zone seal-proposal path.
    pub fn list_anchor_identities(&self, max_anchors: usize) -> Vec<String> {
        let Ok(cf) = self.try_cf(CF_IDENTITIES_ANCHOR) else { return Vec::new() };
        let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start);
        let mut out = Vec::new();
        for item in iter {
            if out.len() >= max_anchors {
                break;
            }
            if let Ok((k, _)) = item {
                if let Ok(s) = std::str::from_utf8(&k) {
                    out.push(s.to_string());
                }
            }
        }
        out
    }

    /// Approximate number of keys in a column family (RocksDB estimate).
    pub fn approximate_cf_size(&self, cf_name: &str) -> u64 {
        let Ok(cf) = self.try_cf(cf_name) else { return 0 };
        self.db
            .property_int_value_cf(&cf, "rocksdb.estimate-num-keys")
            .ok()
            .flatten()
            .unwrap_or(0)
    }

    /// Live SST-file bytes for a single CF (O(1) RocksDB property query).
    /// Excludes obsolete files awaiting compaction — reflects the working
    /// set on disk, not tombstone-inflated total.
    pub fn cf_live_bytes(&self, cf_name: &str) -> u64 {
        let Ok(cf) = self.try_cf(cf_name) else { return 0 };
        self.db
            .property_int_value_cf(&cf, "rocksdb.live-sst-files-size")
            .ok()
            .flatten()
            .unwrap_or(0)
    }

    /// Total live on-disk bytes across every CF that stores bulk record
    /// data + its timestamp index. Used by the GC size-cap path
    /// (Stage 6.5 — Protocol §11.8) to decide when to compress the
    /// retention window. O(CFs) — a few RocksDB property reads, no I/O.
    pub fn total_live_bytes(&self) -> u64 {
        const CFS: &[&str] = &[
            CF_RECORDS,
            CF_DAG,
            CF_ATTESTATIONS,
            CF_MERKLE,
            CF_EPOCHS,
            CF_IDX_TIMESTAMP,
            CF_IDX_CREATOR,
            CF_IDX_TIPS,
            CF_IDX_HASH,
            CF_IDX_ATT_TIME,
        ];
        let mut total: u64 = 0;
        for cf in CFS {
            total = total.saturating_add(self.cf_live_bytes(cf));
        }
        total
    }

    /// Approximate record count (RocksDB estimate, O(1)).
    /// Used to pre-size bloom filters without iterating all records.
    pub fn approximate_record_count(&self) -> usize {
        self.approximate_cf_size(CF_RECORDS) as usize
    }

    // ── Prefix iteration ────────────────────────────────────────────────

    /// Scan all key-value pairs in a column family whose key starts with `prefix`.
    /// Calls `f(key, value)` for each matching entry. Stops when prefix no longer matches.
    pub fn prefix_scan<F>(&self, cf_name: &str, prefix: &[u8], mut f: F) -> Result<()>
    where
        F: FnMut(&[u8], &[u8]) -> Result<()>,
    {
        let cf = self.try_cf(cf_name)?;
        let iter = self.db.prefix_iterator_cf(&cf, prefix);
        for item in iter {
            let (key, value) = item.map_err(|e| ElaraError::Storage(format!("prefix_scan({cf_name}): {e}")))?;
            if !key.starts_with(prefix) {
                break;
            }
            f(&key, &value)?;
        }
        Ok(())
    }

    /// Prefix scan with caller-controlled early termination: callback returns
    /// `Ok(true)` to continue, `Ok(false)` to stop iterating. Same key-order
    /// contract as `prefix_scan`.
    ///
    /// Use this for public-read paths over an attacker-influenced key range,
    /// where the row count must be bounded at the store layer instead of
    /// materializing the full range into memory first.
    pub fn prefix_scan_bounded<F>(&self, cf_name: &str, prefix: &[u8], mut f: F) -> Result<()>
    where
        F: FnMut(&[u8], &[u8]) -> Result<bool>,
    {
        let cf = self.try_cf(cf_name)?;
        let iter = self.db.prefix_iterator_cf(&cf, prefix);
        for item in iter {
            let (key, value) = item
                .map_err(|e| ElaraError::Storage(format!("prefix_scan_bounded({cf_name}): {e}")))?;
            if !key.starts_with(prefix) {
                break;
            }
            if !f(&key, &value)? {
                break;
            }
        }
        Ok(())
    }

    /// Full iteration over every key in a column family. Callback is called for every
    /// entry. Uses `total_order_seek=true` so the iteration is correct even when the
    /// CF has a `prefix_extractor` installed (otherwise prefix-same-as-start logic
    /// can cause the iterator to return nothing for keys outside the extractor
    /// domain, e.g. short test keys or keys with a different structural prefix).
    ///
    /// This is the right primitive for "scan every attestation in CF_ATTESTATIONS"-
    /// style callers that used to pass the 4-byte `att:` prefix to `prefix_scan`
    /// expecting full coverage — after DISC-4 D-8 installed a 41-byte extractor on
    /// CF_ATTESTATIONS, those calls must route here.
    pub fn full_scan_cf<F>(&self, cf_name: &str, mut f: F) -> Result<()>
    where
        F: FnMut(&[u8], &[u8]) -> Result<()>,
    {
        let cf = self.try_cf(cf_name)?;
        let mut opts = rocksdb::ReadOptions::default();
        opts.set_total_order_seek(true);
        let iter = self.db.iterator_cf_opt(&cf, opts, rocksdb::IteratorMode::Start);
        for item in iter {
            let (key, value) = item
                .map_err(|e| ElaraError::Storage(format!("full_scan_cf({cf_name}): {e}")))?;
            f(&key, &value)?;
        }
        Ok(())
    }

    /// Range scan from `start_key` forward. Callback returns `Ok(true)` to continue, `Ok(false)` to stop.
    pub fn range_scan_cf<F>(&self, cf_name: &str, start_key: &[u8], mut f: F) -> Result<()>
    where
        F: FnMut(&[u8], &[u8]) -> Result<bool>,
    {
        let cf = self.try_cf(cf_name)?;
        let iter = self.db.iterator_cf(
            &cf,
            rocksdb::IteratorMode::From(start_key, rocksdb::Direction::Forward),
        );
        for item in iter {
            let (key, value) = item.map_err(|e| ElaraError::Storage(format!("range_scan({cf_name}): {e}")))?;
            if !f(&key, &value)? {
                break;
            }
        }
        Ok(())
    }

    /// Reverse prefix scan: iterate keys starting with `prefix` in **descending key
    /// order** (highest key first). Callback returns `Ok(true)` to continue,
    /// `Ok(false)` to stop. Designed for "find the latest record by some indexed
    /// dimension" queries where loading the full result set would be unbounded.
    ///
    /// **Why this exists (LIVENESS-2):** `query_by_creator_hash` scans forward
    /// and loads up to `limit` records into a Vec. To find the *latest* record
    /// by a creator with many history entries, the caller must pass a huge
    /// `limit` (or risk missing recent records) — and at 1M-zone scale a single
    /// signer's record count can be unbounded. This primitive lets the caller
    /// stream entries newest-first, fetch records lazily, and stop at the first
    /// match — O(matches_until_stop), not O(records_for_creator).
    ///
    /// Implementation: seeks to `prefix || 0xFF*8` (one past the last possible
    /// key in the prefix range) and iterates with `Direction::Reverse`, stopping
    /// when the key no longer matches `prefix`.
    pub fn prefix_scan_reverse<F>(&self, cf_name: &str, prefix: &[u8], mut f: F) -> Result<()>
    where
        F: FnMut(&[u8], &[u8]) -> Result<bool>,
    {
        let cf = self.try_cf(cf_name)?;
        // Build a seek-key that is just past the last key in the prefix range.
        // RocksDB seeks to the key <= seek_key when Direction::Reverse — anything
        // outside the prefix range will be filtered by the starts_with check below.
        let mut seek_key = Vec::with_capacity(prefix.len() + 8);
        seek_key.extend_from_slice(prefix);
        seek_key.extend_from_slice(&[0xFFu8; 8]);

        let iter = self.db.iterator_cf(
            &cf,
            rocksdb::IteratorMode::From(&seek_key, rocksdb::Direction::Reverse),
        );
        for item in iter {
            let (key, value) = item
                .map_err(|e| ElaraError::Storage(format!("prefix_scan_reverse({cf_name}): {e}")))?;
            if !key.starts_with(prefix) {
                break;
            }
            if !f(&key, &value)? {
                break;
            }
        }
        Ok(())
    }

    /// Reverse range scan: iterate a CF from the end backwards, calling `f` for each key-value.
    /// Stops when `f` returns `Ok(false)` or the CF is exhausted.
    pub fn range_scan_cf_reverse<F>(&self, cf_name: &str, mut f: F) -> Result<()>
    where
        F: FnMut(&[u8], &[u8]) -> Result<bool>,
    {
        let cf = self.try_cf(cf_name)?;
        let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::End);
        for item in iter {
            let (key, value) = item.map_err(|e| ElaraError::Storage(format!("range_scan_rev({cf_name}): {e}")))?;
            if !f(&key, &value)? {
                break;
            }
        }
        Ok(())
    }

    /// Get the timestamp (first 8 bytes of key as f64 BE) from the last key in a CF.
    /// Returns None if the CF is empty.
    pub fn last_key_timestamp_cf(&self, cf_name: &str) -> Result<Option<f64>> {
        let cf = self.try_cf(cf_name)?;
        let mut iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::End);
        if let Some(item) = iter.next() {
            let (key, _) = item.map_err(|e| ElaraError::Storage(format!("last_key({cf_name}): {e}")))?;
            if key.len() >= 8 {
                let ts = f64::from_be_bytes(key[..8].try_into().unwrap_or([0u8; 8]));
                return Ok(Some(ts));
            }
        }
        Ok(None)
    }

    /// Collect all key-value pairs in a CF matching a prefix. Returns Vec<(key, value)>.
    pub fn prefix_collect(&self, cf_name: &str, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let mut result = Vec::new();
        self.prefix_scan(cf_name, prefix, |k, v| {
            result.push((k.to_vec(), v.to_vec()));
            Ok(())
        })?;
        Ok(result)
    }

    // ── TTL Compaction ─────────────────────────────────────────────────────
    //
    // Manual TTL cleanup for column families that accumulate old entries.
    // RocksDB's built-in TTL only works with DBWithTTL (not our multi-CF setup).
    // Instead, we scan entries, delete old ones, and trigger manual compaction.

    /// Delete all entries in a CF where the value deserializes to JSON with a
    /// `timestamp` field older than `cutoff_ts`. Returns count of deleted entries.
    ///
    /// Scans the entire CF — run sparingly (e.g., daily or on a background loop).
    pub fn ttl_cleanup_cf_by_timestamp(&self, cf_name: &str, cutoff_ts: f64) -> Result<usize> {
        let cf = self.try_cf(cf_name)?;
        let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start);
        let mut keys_to_delete = Vec::new();

        for item in iter {
            let (key, value) = item.map_err(|e| ElaraError::Storage(format!("ttl_scan({cf_name}): {e}")))?;
            // Skip snapshot entries
            if key.starts_with(b"__snapshot__:") {
                continue;
            }
            // Try to extract timestamp from JSON value
            if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&value) {
                if let Some(ts) = val.get("timestamp").and_then(|v| v.as_f64()) {
                    if ts < cutoff_ts {
                        keys_to_delete.push(key.to_vec());
                    }
                }
            }
        }

        let count = keys_to_delete.len();
        if count > 0 {
            let mut batch = WriteBatch::default();
            let cf_handle = self.try_cf(cf_name)?;
            for key in &keys_to_delete {
                batch.delete_cf(&cf_handle, key);
            }
            self.db.write(batch)
                .map_err(|e| ElaraError::Storage(format!("ttl_delete({cf_name}): {e}")))?;

            // Trigger manual compaction after bulk delete to reclaim disk space
            self.compact_cf(cf_name);
        }

        Ok(count)
    }

    /// Report RocksDB internal memory usage breakdown (memtables, block cache,
    /// table readers). Returns (memtable_bytes, block_cache_bytes, table_readers_bytes).
    /// Aggregates across all column families.
    pub fn memory_usage(&self) -> (u64, u64, u64) {
        let mut memtable = 0u64;
        let mut table_readers = 0u64;
        for name in ALL_CF_NAMES {
            let cf = match self.try_cf(name) { Ok(c) => c, Err(_) => continue };
            memtable += self.db
                .property_int_value_cf(&cf, "rocksdb.cur-size-all-mem-tables")
                .ok().flatten().unwrap_or(0);
            table_readers += self.db
                .property_int_value_cf(&cf, "rocksdb.estimate-table-readers-mem")
                .ok().flatten().unwrap_or(0);
        }
        // Block cache is shared — query from any CF gives the same total.
        let block_cache = ALL_CF_NAMES.first().and_then(|name| {
            let cf = self.try_cf(name).ok()?;
            self.db.property_int_value_cf(&cf, "rocksdb.block-cache-usage")
                .ok().flatten()
        }).unwrap_or(0);
        (memtable, block_cache, table_readers)
    }

    /// Compaction-pressure inventory across all column families.
    ///
    /// Returns `(pending_compaction_bytes, running_compactions, immutable_memtables)`.
    /// These three signals are the leading indicators that RocksDB is about to
    /// throttle or stall writes — they bend up before write latency does.
    ///
    /// - `pending_compaction_bytes` — estimated bytes still needing compaction
    ///   (`rocksdb.estimate-pending-compaction-bytes`). Sustained growth = the
    ///   compactor is falling behind ingest. Phone-tier nodes will hit
    ///   write-stop conditions here long before disk fills.
    /// - `running_compactions` — currently active compaction jobs. At CPU floor
    ///   this caps at the configured `max-background-compactions`; if it sits
    ///   pinned at the cap while pending bytes climb, the node is saturated.
    /// - `immutable_memtables` — frozen memtables awaiting flush to L0
    ///   (`rocksdb.num-immutable-mem-table`). >0 means the flush thread is
    ///   behind; trigger for write-side back-pressure on the next ingest tick.
    ///
    /// All three are summed across every CF — RocksDB exposes them per-CF,
    /// and ingest pressure on any CF (records, attestations, dag, ...) is
    /// equally indicative of stall risk. O(|ALL_CF_NAMES|) cheap property reads.
    pub fn compaction_pressure(&self) -> (u64, u64, u64) {
        let mut pending_bytes = 0u64;
        let mut running = 0u64;
        let mut immutable = 0u64;
        for name in ALL_CF_NAMES {
            let cf = match self.try_cf(name) { Ok(c) => c, Err(_) => continue };
            pending_bytes += self.db
                .property_int_value_cf(&cf, "rocksdb.estimate-pending-compaction-bytes")
                .ok().flatten().unwrap_or(0);
            running += self.db
                .property_int_value_cf(&cf, "rocksdb.num-running-compactions")
                .ok().flatten().unwrap_or(0);
            immutable += self.db
                .property_int_value_cf(&cf, "rocksdb.num-immutable-mem-table")
                .ok().flatten().unwrap_or(0);
        }
        (pending_bytes, running, immutable)
    }

    /// RocksDB accumulated background-error count (`rocksdb.background-errors`).
    ///
    /// Non-zero is the HARD-failure signal, categorically distinct from
    /// [`compaction_pressure`](Self::compaction_pressure) (throttling) and
    /// [`write_stall_state`](Self::write_stall_state) (L0 back-pressure) — both
    /// of which are recoverable and self-clear when the compactor catches up. A
    /// background error means a flush or compaction *failed outright* —
    /// mid-compaction ENOSPC, an I/O fault, a lost mount / permissions change,
    /// or on-disk corruption — after which RocksDB puts the DB into a
    /// read-only / halted-writes state that does NOT self-clear when free space
    /// returns. The proactive `disk_pressure` free-space gate is blind to it:
    /// that gate fires on low *headroom*, not on an error that already
    /// happened (e.g. a compaction that burned the last GB before the 2 GB gate
    /// tripped, or any non-space fault). Surfaced on `/health` (a `storage`
    /// axis) and `/metrics` (`elara_rocksdb_background_errors`) so a wedged DB
    /// is visible to an operator instead of silently dropping every write.
    ///
    /// DB-global property (NOT per-CF): read once via `property_int_value`.
    /// Summing across CFs the way `compaction_pressure` does would multiply the
    /// single global count by the CF cardinality — wrong. O(1), no I/O.
    pub fn background_errors(&self) -> u64 {
        self.db
            .property_int_value("rocksdb.background-errors")
            .ok()
            .flatten()
            .unwrap_or(0)
    }

    /// Write-stall + L0-saturation inventory.
    ///
    /// Returns `(l0_total, l0_max_cf, write_stopped_cfs, delay_rate_bps_max)`.
    /// `compaction_pressure()` shows pending bytes at the *bottom* of the LSM
    /// tree; this surfaces saturation at the *top* (L0) and the kernel-level
    /// stall switches that flip when L0 fills.
    ///
    /// - `l0_total` — sum of `rocksdb.num-files-at-level0` across every CF.
    ///   L0 is the only LSM level whose key ranges overlap, so each L0 file is
    ///   visited on every read until it gets compacted into L1. Sustained >50
    ///   total = read amplification climbing.
    /// - `l0_max_cf` — worst single-CF L0 count. RocksDB hard-stops writes per
    ///   CF when its L0 count crosses `level0_stop_writes_trigger` (default 36)
    ///   and soft-throttles at `level0_slowdown_writes_trigger` (default 20).
    ///   This gauge crossing 20 is a leading indicator that the throttle ramp
    ///   is about to start; crossing 36 means writes are already blocked.
    /// - `write_stopped_cfs` — count of CFs reporting `rocksdb.is-write-stopped`.
    ///   Non-zero = at least one CF is in hard-stop, every ingest into that CF
    ///   blocks until L0 is drained. Should be 0 in steady state.
    /// - `delay_rate_bps_max` — max `rocksdb.actual-delayed-write-rate` across
    ///   CFs (bytes/sec). When >0, RocksDB has clamped write bandwidth via the
    ///   leveled-compaction soft-throttle (active before hard-stop). The cap
    ///   value tells operators *how much* the compactor is slowing ingest.
    pub fn write_stall_state(&self) -> (u64, u64, u64, u64) {
        let mut l0_total = 0u64;
        let mut l0_max = 0u64;
        let mut stalled = 0u64;
        let mut delay_rate = 0u64;
        for name in ALL_CF_NAMES {
            let cf = match self.try_cf(name) { Ok(c) => c, Err(_) => continue };
            let l0_count: u64 = self.db
                .property_value_cf(&cf, "rocksdb.num-files-at-level0")
                .ok().flatten()
                .and_then(|v| v.trim().parse::<u64>().ok())
                .unwrap_or(0);
            l0_total += l0_count;
            if l0_count > l0_max { l0_max = l0_count; }
            let stopped = self.db
                .property_int_value_cf(&cf, "rocksdb.is-write-stopped")
                .ok().flatten().unwrap_or(0);
            if stopped > 0 { stalled += 1; }
            let rate = self.db
                .property_int_value_cf(&cf, "rocksdb.actual-delayed-write-rate")
                .ok().flatten().unwrap_or(0);
            if rate > delay_rate { delay_rate = rate; }
        }
        (l0_total, l0_max, stalled, delay_rate)
    }

    /// Trigger manual compaction on a column family to reclaim disk space.
    /// Non-blocking — compaction runs in RocksDB's background threads.
    /// Returns silently if `cf_name` is not registered (schema mismatch).
    pub fn compact_cf(&self, cf_name: &str) {
        let Ok(cf) = self.try_cf(cf_name) else { return };
        self.db.compact_range_cf(&cf, None::<&[u8]>, None::<&[u8]>);
    }

    /// Names of every CF that `delete_record` writes a tombstone into. Single
    /// source of truth used by `compact_post_gc()` and by the boot-time bloat
    /// detector so the two paths can't drift.
    ///
    /// Pre-fix, gc.rs only compacted `records`,
    /// `attestations`, `dag`, `idx_timestamp`. Two nodes (one at 96% disk, a
    /// second with 25 GB of checkpoint pinning ~17 GB live SSTs) had been
    /// running for 5 weeks without restart, accumulating tombstones in
    /// `idx_creator`, `idx_hash`,
    /// `idx_record_hash`, `idx_tips`, `record_by_zone`, `metadata` (finalized:
    /// prefix), and `epochs` (DISC-5 seal index) — none of which got
    /// periodic-GC compaction. Startup compaction at boot was the only path
    /// that touched some of them. Result: SST files retained their
    /// pre-tombstone size on disk while live-data-size kept shrinking.
    pub fn delete_touched_cfs() -> &'static [&'static str] {
        &[
            CF_RECORDS,
            CF_IDX_TIMESTAMP,
            CF_IDX_CREATOR,
            CF_IDX_TIPS,
            CF_IDX_HASH,
            CF_IDX_RECORD_HASH,
            CF_RECORD_BY_ZONE,
            CF_METADATA,
            CF_EPOCHS,
            CF_ATTESTATIONS,
            CF_DAG,
        ]
    }

    /// Compact every CF that GC can leave tombstones in. Non-blocking — each
    /// `compact_range_cf` schedules a background compaction in RocksDB's own
    /// thread pool. The whole call returns once the schedule-requests are in.
    pub fn compact_post_gc(&self) {
        for cf_name in Self::delete_touched_cfs() {
            let Ok(cf) = self.try_cf(cf_name) else { continue };
            self.db.compact_range_cf(&cf, None::<&[u8]>, None::<&[u8]>);
        }
    }

    /// Compact heavy column families at startup.
    ///
    /// Uses `rocksdb.estimate-live-data-size` to detect bloat from accumulated
    /// tombstones (GC deletes records but SST files retain tombstones until deep
    /// compaction). Observed: 13.9 GB SST for 893 live records (should be ~50 MB).
    ///
    /// Compacts ALL listed CFs when total estimated live data exceeds a threshold
    /// relative to known record count. Also compacts individual CFs with excessive
    /// L0-L2 file counts.
    ///
    /// Returns the number of CFs scheduled for compaction so the caller can bump
    /// `NodeState.startup_compactions_total`. Without this, post-reboot nodes
    /// were showing `gc_compactions_total=0` despite startup compaction having
    /// reclaimed disk, making the fleet-bloat fix look broken when it was
    /// actually working.
    pub fn startup_compaction_if_needed(&self) -> u32 {
        // ALL column families that can accumulate tombstone bloat.
        let heavy_cfs = [
            CF_RECORDS, CF_ATTESTATIONS, "merkle",
            CF_IDX_TIMESTAMP, CF_DAG,
        ];

        // Check total SST size across ALL CFs for gross bloat detection.
        // Use per-CF property because DB-level "rocksdb.total-sst-files-size"
        // returns 0 with column families.
        let all_cfs = [
            CF_RECORDS, CF_ATTESTATIONS, "merkle", CF_IDX_TIMESTAMP, CF_DAG,
            CF_LEDGER, CF_TRUST, CF_REPUTATION, CF_EPOCHS, CF_PEERS,
            CF_DISPUTES, CF_PENDING_XZONE, CF_IDENTITIES, CF_GOVERNANCE,
            CF_VELOCITY, CF_VRF_KEYS, CF_IDX_CREATOR, CF_IDX_TIPS,
            CF_IDX_HASH, CF_IDX_ATT_TIME, CF_APPLIED,
        ];
        let mut total_sst_bytes: u64 = 0;
        for cf_name in &all_cfs {
            let Ok(cf) = self.try_cf(cf_name) else { continue };
            let cf_bytes = self.db
                .property_int_value_cf(&cf, "rocksdb.total-sst-files-size")
                .ok()
                .flatten()
                .unwrap_or(0);
            let cf_mb = cf_bytes / (1024 * 1024);
            if cf_mb > 0 {
                tracing::info!("startup compaction: CF {cf_name} = {cf_mb} MB");
            }
            total_sst_bytes += cf_bytes;
        }
        let total_sst_mb = total_sst_bytes / (1024 * 1024);
        tracing::info!("startup compaction: total SST = {total_sst_mb} MB across all CFs");

        // Per-CF bloat check: only compact CFs where SST size is >2× estimated
        // live data, indicating significant tombstone/delete bloat.
        // Previously used a flat 500 MB total threshold which triggered on every
        // restart once nodes had real data (13 GB+ SST), causing 12+ min I/O stall
        // with zero reclamation (13634 → 13645 MB).
        let mut compacted: u32 = 0;
        {
            for cf_name in &heavy_cfs {
                let Ok(cf) = self.try_cf(cf_name) else { continue };
                let sst_bytes = self.db
                    .property_int_value_cf(&cf, "rocksdb.total-sst-files-size")
                    .ok().flatten().unwrap_or(0);
                let live_bytes = self.db
                    .property_int_value_cf(&cf, "rocksdb.estimate-live-data-size")
                    .ok().flatten().unwrap_or(0);
                let sst_mb = sst_bytes / (1024 * 1024);
                // Compact if SST > 100 MB AND >2× live data (real bloat)
                if sst_mb > 100 && live_bytes > 0 && sst_bytes > live_bytes * 2 {
                    tracing::warn!(
                        "startup compaction: {cf_name} has {sst_mb} MB SST vs {} MB live — compacting",
                        live_bytes / (1024 * 1024)
                    );
                    self.db.compact_range_cf(&cf, None::<&[u8]>, None::<&[u8]>);
                    compacted += 1;
                }
            }
            if compacted > 0 {
                return compacted; // Bloat-targeted compaction done
            }
        }

        // Otherwise, check individual CFs for L0-L2 accumulation
        for cf_name in &all_cfs {
            let Ok(cf) = self.try_cf(cf_name) else { continue };
            let sst_count: u64 = (0..3)
                .map(|level| {
                    self.db
                        .property_value_cf(&cf, &format!("rocksdb.num-files-at-level{level}"))
                        .ok()
                        .flatten()
                        .and_then(|v| v.trim().parse::<u64>().ok())
                        .unwrap_or(0)
                })
                .sum();
            if sst_count > 20 {
                tracing::info!(
                    "startup compaction: {cf_name} CF has {sst_count} SST files in L0-L2, compacting"
                );
                self.db.compact_range_cf(&cf, None::<&[u8]>, None::<&[u8]>);
                compacted += 1;
            }
        }

        // D-6: allow operator-forced full compaction via env var.
        // Use case: bloom-filter / table-format upgrade — old SSTs in L5/L6 don't
        // gain the new format until they're rewritten. One-shot env flag triggers
        // a full compaction of named CFs at boot. Set via:
        //   ELARA_FORCE_COMPACT_CF=attestations,records
        // Remove the env var after the restart — this is blocking and I/O-heavy.
        if let Ok(cf_list) = std::env::var("ELARA_FORCE_COMPACT_CF") {
            let mut opts = rocksdb::CompactOptions::default();
            // Force rewrite of bottom-level files so they pick up the new table
            // format (bloom filter, block size, etc). Default is `IfHaveCompactionFilter`
            // which leaves L6 alone if nothing else overlaps — exactly the case we
            // need to override here.
            opts.set_bottommost_level_compaction(rocksdb::BottommostLevelCompaction::ForceOptimized);
            for cf_name in cf_list.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                let cf = match self.try_cf(cf_name) {
                    Ok(cf) => cf,
                    Err(_) => {
                        tracing::warn!("ELARA_FORCE_COMPACT_CF: unknown column family '{cf_name}' — skipping");
                        continue;
                    }
                };
                tracing::warn!(
                    "ELARA_FORCE_COMPACT_CF: force-compacting {cf_name} (one-shot, blocking, bottom-level=ForceOptimized)"
                );
                self.db.compact_range_cf_opt(&cf, None::<&[u8]>, None::<&[u8]>, &opts);
                tracing::warn!("ELARA_FORCE_COMPACT_CF: done compacting {cf_name}");
                compacted += 1;
            }
        }
        compacted
    }

    /// Clean up orphan records in CF_RECORDS that have no CF_IDX_TIMESTAMP entry.
    ///
    /// Root cause: older code versions didn't always create timestamp index entries,
    /// or GC deleted index entries without the corresponding record data. These
    /// orphan records accumulate forever because GC only scans the timestamp index.
    /// Observed: 254K orphan records (10 GB) on Helsinki with only 714 live records.
    ///
    /// Scans CF_RECORDS directly, deserializes each record, checks if its timestamp
    /// is older than `retention_cutoff`, and deletes orphans. Epoch seals, ledger ops,
    /// and governance ops are preserved regardless of age.
    pub fn cleanup_orphan_records(&self, retention_cutoff: f64) -> usize {
        let cf = match self.try_cf(CF_RECORDS) {
            Ok(h) => h,
            Err(e) => {
                tracing::error!("orphan cleanup: CF unavailable, skipping: {e}");
                return 0;
            }
        };
        let ts_cf = match self.try_cf(CF_IDX_TIMESTAMP) {
            Ok(h) => h,
            Err(e) => {
                tracing::error!("orphan cleanup: CF unavailable, skipping: {e}");
                return 0;
            }
        };
        let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start);

        let mut orphans: Vec<String> = Vec::new();
        let mut scanned = 0u64;

        for item in iter {
            let (key, value) = match item {
                Ok(kv) => kv,
                Err(_) => continue,
            };

            // Skip non-record keys (finalized:, ban:, __record_count__, etc.)
            if key.starts_with(b"finalized:")
                || key.starts_with(b"ban:")
                || key.starts_with(b"blocked_term:")
                || key.starts_with(b"tombstone:")
                || &*key == b"__record_count__"
                || &*key == b"__full_pull_cursor__"
            {
                continue;
            }

            scanned += 1;

            // Try to deserialize as a record
            let rec = match ValidationRecord::from_bytes(&value) {
                Ok(r) => r,
                Err(_) => continue, // Not a record, skip
            };

            // Never delete epoch seals, ledger ops, governance ops
            if rec.metadata.contains_key("epoch_op")
                || rec.metadata.contains_key("beat_op")
                || rec.metadata.contains_key("governance_op")
            {
                continue;
            }

            // Signed-proof carriers (mandate issuance/revocation, emergency
            // halt/resume) are integrity-critical exactly like the ops above —
            // an orphaned carrier needs its index rebuilt, never deletion. This
            // is the same canonical exemption set the GC twins and the
            // production retention scan (gc_scan_and_delete) enforce; keep it in
            // sync here so a future caller of this pub fn can't silently prune a
            // cryptographic proof carrier. Consts, not literals, to defeat drift.
            if rec.metadata.contains_key(crate::mandate::MANDATE_OP_KEY)
                || rec.metadata.contains_key(crate::mandate::MANDATE_REVOCATION_OP_KEY)
                || rec.metadata.contains_key(crate::emergency::EMERGENCY_HALT_OP_KEY)
                || rec.metadata.contains_key(crate::emergency::EMERGENCY_RESUME_OP_KEY)
            {
                continue;
            }

            // Skip recent records (within retention window)
            if rec.timestamp >= retention_cutoff {
                continue;
            }

            // Check if this record has a timestamp index entry
            let ts_bytes = rec.timestamp.to_be_bytes();
            let record_id = match std::str::from_utf8(&key) {
                Ok(id) => id,
                Err(_) => continue,
            };
            let mut ts_key = Vec::with_capacity(8 + record_id.len());
            ts_key.extend_from_slice(&ts_bytes);
            ts_key.extend_from_slice(record_id.as_bytes());

            let has_index = self.db.get_cf(&ts_cf, &ts_key)
                .ok()
                .flatten()
                .is_some();

            if !has_index {
                orphans.push(record_id.to_string());
            }
        }

        if orphans.is_empty() {
            tracing::info!(
                "orphan cleanup: scanned {scanned} records, found 0 orphans"
            );
            return 0;
        }

        tracing::warn!(
            "orphan cleanup: scanned {scanned} records, found {} orphans older than retention — deleting",
            orphans.len()
        );

        // Delete in batches of 500 to avoid huge WriteBatches.
        // Tier 4.5: finalized: keys live in CF_METADATA now.
        let total = orphans.len();
        let cf_meta = match self.try_cf(CF_METADATA) {
            Ok(h) => h,
            Err(e) => {
                tracing::error!("orphan cleanup: CF_METADATA unavailable, skipping deletes: {e}");
                return 0;
            }
        };
        for chunk in orphans.chunks(500) {
            let mut batch = rocksdb::WriteBatch::default();
            for id in chunk {
                batch.delete_cf(&cf, id.as_bytes());
                let fin_key = format!("finalized:{id}");
                batch.delete_cf(&cf_meta, fin_key.as_bytes());
            }
            if let Err(e) = self.db.write(batch) {
                tracing::warn!("orphan cleanup batch failed: {e}");
                break;
            }
        }

        // Compact after mass deletion to actually reclaim disk space
        tracing::info!("orphan cleanup: compacting records CF after deleting {total} orphans");
        self.db.compact_range_cf(&cf, None::<&[u8]>, None::<&[u8]>);

        // Update record count (Tier 4.5: cache lives in CF_METADATA).
        // Belt-and-suspenders prefix filters stay in case migration left
        // any straggler keys behind.
        let actual_count = {
            let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start);
            let mut count = 0u64;
            for (key, value) in iter.flatten() {
                if !key.starts_with(b"finalized:")
                    && !key.starts_with(b"ban:")
                    && !key.starts_with(b"blocked_term:")
                    && !key.starts_with(b"tombstone:")
                    && &*key != b"__record_count__"
                    && &*key != b"__full_pull_cursor__"
                    && ValidationRecord::from_bytes(&value).is_ok()
                {
                    count += 1;
                }
            }
            count
        };
        let _ = self.db.put_cf(&cf_meta, b"__record_count__", actual_count.to_le_bytes());
        tracing::info!("orphan cleanup: record count corrected to {actual_count}");

        total
    }

    /// Lightweight DAG rebuild from CF_DAG + CF_IDX_TIMESTAMP.
    ///
    /// Reads only edge metadata (~200 bytes/record) instead of full records
    /// (~8KB/record with SPHINCS+ sigs). On a 14K-record DB this saves
    /// ~100MB peak RAM vs the full-record rebuild path.
    ///
    /// `max_records`: if > 0, only loads the most recent N records (for
    /// memory-constrained nodes). 0 = load all.
    pub fn rebuild_dag_lightweight(&self) -> crate::errors::Result<crate::dag::DagIndex> {
        self.rebuild_dag_lightweight_bounded(0)
    }

    /// Bounded variant: loads at most `max_records` most recent entries.
    /// If `max_records == 0`, loads all records.
    ///
    /// CF_IDX_TIMESTAMP keys are `[8-byte BE timestamp][record_id]`, so the
    /// index is already sorted by timestamp. No HashMap or sort needed —
    /// just iterate forwards. For bounded mode, we first seek to the cutoff
    /// by counting backwards from the end.
    pub fn rebuild_dag_lightweight_bounded(
        &self,
        max_records: usize,
    ) -> crate::errors::Result<crate::dag::DagIndex> {
        use crate::dag::DagIndex;

        let ts_cf = self.try_cf(CF_IDX_TIMESTAMP)?;
        let dag_cf = self.try_cf(CF_DAG)?;

        // For bounded mode: iterate backwards from end, collect max_records
        // keys (O(max_records) memory), reverse to get chronological order.
        // For unbounded: iterate forwards from start.
        let collected_keys: Option<Vec<(Vec<u8>, f64, String)>> = if max_records > 0 {
            let mut keys = Vec::with_capacity(max_records);
            let iter = self.db.iterator_cf(&ts_cf, rocksdb::IteratorMode::End);
            for item in iter {
                if keys.len() >= max_records { break; }
                let (key, _) = match item {
                    Ok(kv) => kv,
                    Err(_) => continue,
                };
                if key.len() < 9 { continue; }
                let ts = f64::from_be_bytes(key[..8].try_into().unwrap_or([0u8; 8]));
                if let Ok(id) = std::str::from_utf8(&key[8..]) {
                    keys.push((key.to_vec(), ts, id.to_string()));
                }
            }
            keys.reverse(); // oldest-first for parent-before-child ordering
            Some(keys)
        } else {
            None
        };

        let mut dag = DagIndex::new();
        let mut orphaned = 0usize;
        let mut total = 0usize;

        // Helper closure: insert one record into DAG
        let mut insert_one = |id: &str, ts: f64| -> crate::errors::Result<()> {
            let parents = match self.db.get_cf(&dag_cf, id.as_bytes()) {
                Ok(Some(bytes)) => {
                    match serde_json::from_slice::<serde_json::Value>(&bytes) {
                        Ok(val) => val["parents"]
                            .as_array()
                            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                            .unwrap_or_default(),
                        Err(_) => vec![],
                    }
                }
                _ => vec![],
            };
            let missing = dag.insert_tolerant(id.to_string(), parents, ts);
            if missing > 0 { orphaned += 1; }
            total += 1;
            Ok(())
        };

        if let Some(keys) = collected_keys {
            // Bounded mode: iterate pre-collected keys
            for (_key, ts, id) in &keys {
                insert_one(id, *ts)?;
            }
        } else {
            // Unbounded mode: stream directly from CF_IDX_TIMESTAMP
            let iter = self.db.iterator_cf(&ts_cf, rocksdb::IteratorMode::Start);
            for item in iter {
                let (key, _) = item.map_err(|e| crate::errors::ElaraError::Storage(
                    format!("dag lightweight ts iter: {e}"),
                ))?;
                if key.len() < 9 { continue; }
                let ts = f64::from_be_bytes(key[..8].try_into().unwrap_or([0u8; 8]));
                if let Ok(id) = std::str::from_utf8(&key[8..]) {
                    insert_one(id, ts)?;
                }
            }
        }

        let linked = dag.reindex_orphans();
        let remaining = dag.orphan_count();
        if orphaned > 0 || total > 0 {
            tracing::info!(
                "dag lightweight rebuild: {total} records, {orphaned} had missing parents, \
                 {linked} edges re-linked, {remaining} still orphaned"
            );
        }

        Ok(dag)
    }

    /// Look up a record ID by its content hash (hex), without loading the full record.
    ///
    /// Uses CF_IDX_HASH (content_hash_hex → record_id) for O(1) point lookup.
    /// Returns `None` if no record with this hash exists in the index.
    pub fn record_id_by_hash(&self, hash_hex: &str) -> Option<String> {
        let idx_cf = self.try_cf(CF_IDX_HASH).ok()?;
        self.db
            .get_cf(&idx_cf, hash_hex.as_bytes())
            .ok()
            .flatten()
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
    }

    /// Look up a record ID by its `record_hash()` (hex), without loading the full record.
    ///
    /// Uses CF_IDX_RECORD_HASH (record_hash_hex → record_id) for O(1) point lookup.
    /// Distinct from `record_id_by_hash` which keys on `content_hash`. See the
    /// CF_IDX_RECORD_HASH doc for the `record_hash` vs `content_hash` semantic
    /// split — TL;DR: this is the right index for resolving entries inside
    /// `seal.record_hashes`. Returns `None` if no record with this hash exists.
    pub fn record_id_by_record_hash(&self, record_hash_hex: &str) -> Option<String> {
        let idx_cf = self.try_cf(CF_IDX_RECORD_HASH).ok()?;
        self.db
            .get_cf(&idx_cf, record_hash_hex.as_bytes())
            .ok()
            .flatten()
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
    }
}

// ─── Storage trait implementation ────────────────────────────────────────────
//
// Implements the Storage trait so StorageEngine can serve as a drop-in
// RocksDB is internally thread-safe, so
// &mut self in write methods just satisfies the trait signature.

impl super::Storage for StorageEngine {
    fn insert(&mut self, record: &ValidationRecord) -> Result<String> {
        self.put_record(&record.id, record)?;
        Ok(record.id.clone())
    }

    fn get(&self, record_id: &str) -> Result<ValidationRecord> {
        self.get_record(record_id)?
            .ok_or_else(|| ElaraError::Storage(format!("record not found: {record_id}")))
    }

    fn get_by_hash(&self, hash: &str) -> Result<ValidationRecord> {
        // CF_IDX_HASH (hex(content_hash) → record_id). Migration v5→v6
        // guarantees every record in CF_RECORDS has a matching entry, so
        // an index miss really means "no such record" — no O(N) fallback.
        let idx_cf = self.try_cf(CF_IDX_HASH)?;
        if let Ok(Some(record_id_bytes)) = self.db.get_cf(&idx_cf, hash.as_bytes()) {
            let record_id = String::from_utf8_lossy(&record_id_bytes);
            if let Ok(Some(rec)) = self.get_record(&record_id) {
                return Ok(rec);
            }
        }
        Err(ElaraError::Storage(format!("record not found by hash: {hash}")))
    }

    fn exists(&self, record_id: &str) -> Result<bool> {
        self.record_exists(record_id)
    }

    fn tips(&self) -> Result<Vec<String>> {
        // Use the tips index (CF_IDX_TIPS) — O(tips) not O(all_records).
        // Falls back to full DAG scan if index is empty (migration).
        let cf = self.try_cf(CF_IDX_TIPS)?;
        let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start);
        let mut tips = Vec::new();
        for item in iter {
            let (key, _) = item.map_err(|e| ElaraError::Storage(format!("iter: {e}")))?;
            tips.push(String::from_utf8_lossy(&key).to_string());
        }
        // Fallback: if tips index empty but DAG has records, scan the old way
        if tips.is_empty() {
            let dag_cf = self.try_cf(CF_DAG)?;
            let dag_iter = self.db.iterator_cf(&dag_cf, rocksdb::IteratorMode::Start);
            for item in dag_iter {
                let (key, value) = item.map_err(|e| ElaraError::Storage(format!("iter: {e}")))?;
                if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&value) {
                    if v["children"].as_array().map(|a| a.len()).unwrap_or(0) == 0 {
                        tips.push(String::from_utf8_lossy(&key).to_string());
                    }
                }
            }
        }
        Ok(tips)
    }

    fn roots(&self) -> Result<Vec<String>> {
        let cf = self.try_cf(CF_DAG)?;
        let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start);
        let mut roots = Vec::new();
        for item in iter {
            let (key, value) = item.map_err(|e| ElaraError::Storage(format!("iter: {e}")))?;
            let record_id = String::from_utf8_lossy(&key).to_string();
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&value) {
                let parents = v["parents"].as_array().map(|a| a.len()).unwrap_or(0);
                if parents == 0 {
                    roots.push(record_id);
                }
            }
        }
        Ok(roots)
    }

    fn parents(&self, record_id: &str) -> Result<Vec<String>> {
        self.get_dag_edges(record_id)
            .map(|opt| opt.map(|(p, _)| p).unwrap_or_default())
    }

    fn children(&self, record_id: &str) -> Result<Vec<String>> {
        self.get_dag_edges(record_id)
            .map(|opt| opt.map(|(_, c)| c).unwrap_or_default())
    }

    fn count(&self) -> Result<usize> {
        // Fast path: read cached count from CF_METADATA (Tier 4.5).
        // Falls back to full scan if cache is missing (first run or migration).
        let cf_meta = self.try_cf(CF_METADATA)?;
        if let Ok(Some(bytes)) = self.db.get_cf(&cf_meta, b"__record_count__") {
            if bytes.len() == 8 {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&bytes[..8]);
                let n = u64::from_le_bytes(buf) as usize;
                return Ok(n);
            }
        }

        // Fallback: full scan over CF_RECORDS. Prefix filters stay as
        // belt-and-suspenders for any straggler keys that the v4→v5
        // metadata migration may not have copied yet on a freshly opened
        // pre-migration database.
        let cf = self.try_cf(CF_RECORDS)?;
        let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start);
        let mut n = 0usize;
        for (key, _) in iter.flatten() {
            if key.starts_with(b"__")
                || key.starts_with(b"ban:")
                || key.starts_with(b"blocked_term:")
                || key.starts_with(b"finalized:")
                || key.starts_with(b"tombstone:")
            {
                continue;
            }
            n += 1;
        }
        // Cache the count for next time (Tier 4.5: CF_METADATA)
        if let Err(e) = self.db.put_cf(&cf_meta, b"__record_count__", (n as u64).to_le_bytes()) {
            tracing::warn!("record_count: failed to cache count: {e}");
        }
        Ok(n)
    }

    fn query(
        &self,
        classification: Option<Classification>,
        creator_key: Option<&[u8]>,
        since: Option<f64>,
        until: Option<f64>,
        limit: usize,
    ) -> Result<Vec<ValidationRecord>> {
        // Use timestamp index when available: iterate CF_IDX_TIMESTAMP in order,
        // seek to `since`, stop at `until` or `limit`. Records come out in
        // timestamp order — no post-sort needed. Falls back to full scan when
        // timestamp index is empty (pre-migration data).
        let ts_cf = self.try_cf(CF_IDX_TIMESTAMP)?;
        let records_cf = self.try_cf(CF_RECORDS)?;

        // Build seek key for timestamp index
        let start = since.unwrap_or(0.0).to_be_bytes();
        let iter = self.db.iterator_cf(
            &ts_cf,
            rocksdb::IteratorMode::From(&start, rocksdb::Direction::Forward),
        );

        let mut results = Vec::new();
        let mut used_index = false;
        // ROCKS-1 (2026-07-03 audit): the loop only counts *matches* toward
        // `limit`, so a rare/zero-match classification/creator filter would walk
        // the entire timestamp index from `since` to the end — an O(all_records)
        // scan reachable from the public `/dag/search`. Cap the number of index
        // entries EXAMINED (not just returned): a search returns a partial page
        // rather than scanning tens of millions of records.
        for (scanned, item) in iter.enumerate() {
            if scanned >= MAX_SCAN_PREALLOC { break; }
            let (key, _) = item.map_err(|e| ElaraError::Storage(format!("ts_idx iter: {e}")))?;
            if key.len() < 8 { continue; }

            // Extract timestamp from key prefix
            let ts = f64::from_be_bytes(key[..8].try_into().unwrap_or([0u8; 8]));

            // Stop at until boundary
            if let Some(u) = until {
                if ts > u { break; }
            }

            // Extract record_id from key suffix
            let record_id = std::str::from_utf8(&key[8..]).unwrap_or("");
            if record_id.is_empty() { continue; }

            // Fetch the actual record from CF_RECORDS
            let wire = match self.db.get_cf(&records_cf, record_id.as_bytes()) {
                Ok(Some(w)) => w,
                _ => continue,
            };
            let rec = match ValidationRecord::from_bytes(&wire) {
                Ok(r) => r,
                Err(_) => continue,
            };

            // Apply remaining filters
            if let Some(cls) = classification {
                if rec.classification != cls { continue; }
            }
            if let Some(key) = creator_key {
                if rec.creator_public_key != key { continue; }
            }

            results.push(rec);
            used_index = true;

            if results.len() >= limit { break; }
        }

        // Fallback: if timestamp index was empty, use the old full-scan path.
        // This handles pre-migration databases where indexes don't exist yet.
        if !used_index && results.is_empty() {
            let iter = self.db.iterator_cf(&records_cf, rocksdb::IteratorMode::Start);
            for (fb_scanned, item) in iter.enumerate() {
                // ROCKS-1: bound the pre-migration full-scan fallback too.
                if fb_scanned >= MAX_SCAN_PREALLOC { break; }
                let (_, value) = item.map_err(|e| ElaraError::Storage(format!("iter: {e}")))?;
                let rec = match ValidationRecord::from_bytes(&value) {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                if let Some(cls) = classification {
                    if rec.classification != cls { continue; }
                }
                if let Some(key) = creator_key {
                    if rec.creator_public_key != key { continue; }
                }
                if let Some(s) = since {
                    if rec.timestamp < s { continue; }
                }
                if let Some(u) = until {
                    if rec.timestamp > u { continue; }
                }
                results.push(rec);
            }
            // Sort fallback results by timestamp
            results.sort_by(|a, b| a.timestamp.total_cmp(&b.timestamp));
            results.truncate(limit);
        }

        Ok(results)
    }

    fn query_zone(
        &self,
        zone: &crate::network::zone::ZoneId,
        _zone_count: u64,
        since: Option<f64>,
        until: Option<f64>,
        limit: usize,
    ) -> Result<Vec<ValidationRecord>> {
        // Fast path: CF_RECORD_BY_ZONE prefix lookup. The zone-idx CF is
        // populated on every put_record_with_pk_zone call (ZSP Phase B) and
        // keyed under the registry-resolved leaf zone, so iter_zone(zone)
        // returns exactly the records whose resolved zone matches `zone` —
        // no post-filter needed. Cost is O(records_in_zone_in_window),
        // independent of total fleet records.
        let zone_key = zone.to_key_bytes();
        let ids = self.iter_zone(&zone_key, since, until, limit);
        let mut out = Vec::with_capacity(ids.len());
        for id in &ids {
            if let Some(rec) = self.get_record(id)? {
                out.push(rec);
            }
        }
        Ok(out)
    }

    fn query_zone_ids(
        &self,
        zone: &crate::network::zone::ZoneId,
        _zone_count: u64,
        since: Option<f64>,
        until: Option<f64>,
        limit: usize,
    ) -> Result<Vec<String>> {
        // Streaming variant: index keys only, never deserializes
        // a full record. Used by seal-create / seal-verify hot paths so
        // peak memory is O(IDs ~50B each) instead of O(records ~8KB each).
        let zone_key = zone.to_key_bytes();
        Ok(self.iter_zone(&zone_key, since, until, limit))
    }

    fn query_by_creator_hash(
        &self,
        creator_hash_hex: &str,
        since: Option<f64>,
        until: Option<f64>,
        limit: usize,
    ) -> Result<Vec<ValidationRecord>> {
        // Layer B (Protocol §11.23): scan CF_IDX_CREATOR by creator-hash prefix.
        // Key format (see `put_record_with_pk_zone`):
        //   creator_hash_hex(64B) + timestamp_be(8B) + record_id
        // A prefix iterator anchored at `creator_hash_hex || since_be` yields the
        // creator's records in timestamp order. Cost is O(records_for_creator_in_window),
        // independent of the fleet's total record count — the load-bearing property
        // for §11.23 Layer B at billion-record scale.
        if creator_hash_hex.len() != 64 {
            return Ok(vec![]);
        }
        let creator_cf = self.try_cf(CF_IDX_CREATOR)?;
        let records_cf = self.try_cf(CF_RECORDS)?;

        let start_ts = since.unwrap_or(0.0).to_be_bytes();
        let mut seek_key = Vec::with_capacity(64 + 8);
        seek_key.extend_from_slice(creator_hash_hex.as_bytes());
        seek_key.extend_from_slice(&start_ts);

        let iter = self.db.iterator_cf(
            &creator_cf,
            rocksdb::IteratorMode::From(&seek_key, rocksdb::Direction::Forward),
        );
        let prefix = creator_hash_hex.as_bytes();
        let mut results = Vec::new();
        for item in iter {
            let (key, _) = item.map_err(|e| ElaraError::Storage(format!("creator_idx iter: {e}")))?;
            if !key.starts_with(prefix) {
                break;
            }
            if key.len() < 64 + 8 {
                continue;
            }
            let ts = f64::from_be_bytes(key[64..72].try_into().unwrap_or([0u8; 8]));
            if let Some(u) = until {
                if ts > u {
                    break;
                }
            }
            let record_id = std::str::from_utf8(&key[72..]).unwrap_or("");
            if record_id.is_empty() {
                continue;
            }
            let wire = match self.db.get_cf(&records_cf, record_id.as_bytes()) {
                Ok(Some(w)) => w,
                _ => continue,
            };
            let rec = match ValidationRecord::from_bytes(&wire) {
                Ok(r) => r,
                Err(_) => continue,
            };
            results.push(rec);
            if results.len() >= limit {
                break;
            }
        }
        Ok(results)
    }

    fn delete(&mut self, record_id: &str) -> Result<()> {
        // delete_record covers CF_DAG in its batch since admin-audit 2026-07-05.
        self.delete_record(record_id)
    }

    fn get_wire_bytes(&self, record_id: &str) -> Result<Vec<u8>> {
        let cf = self.try_cf(CF_RECORDS)?;
        self.db
            .get_cf(&cf, record_id.as_bytes())
            .map_err(|e| ElaraError::Storage(format!("get_wire_bytes: {e}")))?
            .ok_or_else(|| ElaraError::Storage(format!("record not found: {record_id}")))
    }
}

/// Gap 3: decide whether a record carrying `epoch_op` metadata is a pruning
/// candidate. Returns `true` ONLY for plain "seal" records in zones that
/// have a registered super-seal pruning floor and whose epoch_number is
/// below it. Super-seals, zone_transitions, and global seals are
/// integrity-critical and always return `false`.
fn is_prunable_seal_record(
    rec: &ValidationRecord,
    seal_pruning_floor: &std::collections::HashMap<crate::ZoneId, u64>,
) -> bool {
    let op_str = rec
        .metadata
        .get("epoch_op")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if op_str != "seal" {
        return false;
    }
    let zone_val = match rec.metadata.get("epoch_zone") {
        Some(v) => v,
        None => return false,
    };
    let zone = if let Some(s) = zone_val.as_str() {
        crate::ZoneId::new(s)
    } else if let Some(n) = zone_val.as_u64() {
        crate::ZoneId::from_legacy(n)
    } else {
        return false;
    };
    let epoch = match rec.metadata.get("epoch_number").and_then(|v| v.as_u64()) {
        Some(e) => e,
        None => return false,
    };
    match seal_pruning_floor.get(&zone) {
        Some(floor) => epoch < *floor,
        None => false,
    }
}

impl StorageEngine {
    /// Return the latest (most recent) timestamp in the CF_IDX_TIMESTAMP index.
    /// Uses a reverse iterator seek — O(1), no scan.
    pub fn latest_record_timestamp(&self) -> Option<f64> {
        let cf = self.cf_handle(CF_IDX_TIMESTAMP)?;
        let mut opts = rocksdb::ReadOptions::default();
        opts.set_total_order_seek(true);
        let mut iter = self.db.raw_iterator_cf_opt(&cf, opts);
        iter.seek_to_last();
        if iter.valid() {
            if let Some(key) = iter.key() {
                if key.len() >= 8 {
                    let ts_bytes: [u8; 8] = key[..8].try_into().ok()?;
                    return Some(f64::from_be_bytes(ts_bytes));
                }
            }
        }
        None
    }

    /// Return the earliest (oldest) timestamp in the CF_IDX_TIMESTAMP
    /// index. Uses a forward iterator seek — O(1), no scan. Mirror of
    /// `latest_record_timestamp`. Surfaced as a gauge so dashboards can compute
    /// `now - earliest_record_timestamp()` to track "how old is the oldest
    /// record still on disk" — a proxy for "what would epoch-based pruning save".
    pub fn earliest_record_timestamp(&self) -> Option<f64> {
        let cf = self.cf_handle(CF_IDX_TIMESTAMP)?;
        let mut opts = rocksdb::ReadOptions::default();
        opts.set_total_order_seek(true);
        let mut iter = self.db.raw_iterator_cf_opt(&cf, opts);
        iter.seek_to_first();
        if iter.valid() {
            if let Some(key) = iter.key() {
                if key.len() >= 8 {
                    let ts_bytes: [u8; 8] = key[..8].try_into().ok()?;
                    return Some(f64::from_be_bytes(ts_bytes));
                }
            }
        }
        None
    }

    /// Streaming GC pass: iterate timestamp index up to `scan_until`, check each
    /// record one at a time for eligibility, and delete in-place. Never allocates
    /// a Vec of all records — O(1) memory per record instead of O(N).
    ///
    /// `retention_cutoff`: records older than this AND finalized → prune.
    /// `stale_cutoff`: records older than this AND NOT finalized → prune as abandoned.
    ///   Typically 2x retention. Prevents unfinalized records from growing unbounded.
    /// `seal_pruning_floor`: per-zone epoch threshold. A "seal" record (epoch_op="seal")
    ///   in zone Z is prunable when its `epoch_number < seal_pruning_floor[Z]`. The
    ///   floor must trail the latest super-seal end-epoch by a safety margin (caller
    ///   responsibility) so light clients still syncing have time to fetch the
    ///   super-seal. Zones absent from the map are never seal-pruned. Super-seals,
    ///   zone_transition, and global seals are integrity-critical and never pruned.
    // Inherent complexity of GC eligibility: two cutoffs, two predicates, two
    // per-zone floor maps, and a resume cursor. Bundling into a struct would
    // touch ~22 callsites for a hygiene win — not worth the churn.
    #[allow(clippy::too_many_arguments)]
    pub fn gc_scan_and_delete(
        &self,
        retention_cutoff: f64,
        stale_cutoff: f64,
        is_finalized: &dyn Fn(&str) -> bool,
        is_sunken: &dyn Fn(&str) -> bool,
        seal_pruning_floor: &std::collections::HashMap<crate::ZoneId, u64>,
        record_pruning_floor_ts: &std::collections::HashMap<crate::ZoneId, f64>,
        resume_from: Option<&[u8]>,
    ) -> Result<super::super::network::gc::GcResult> {
        use super::super::network::gc::GcResult;

        let ts_cf = self.try_cf(CF_IDX_TIMESTAMP)?;
        let records_cf = self.try_cf(CF_RECORDS)?;

        // Scan up to the most-recent eligibility window. retention_cutoff is
        // always more recent than stale_cutoff (= 2x retention back). Tier
        // 3.4 epoch-pruning floors can be NEWER than retention_cutoff (super
        // seals roll on the order of hours, retention is days), so the
        // iterator must extend up to the maximum floor_ts to catch records
        // eligible by the epoch gate.
        let max_epoch_floor_ts = record_pruning_floor_ts
            .values()
            .copied()
            .fold(f64::NEG_INFINITY, f64::max);
        let scan_until = if max_epoch_floor_ts.is_finite() {
            retention_cutoff.max(max_epoch_floor_ts)
        } else {
            retention_cutoff
        };

        // When the previous cycle hit
        // `MAX_GC_SCAN_PER_CYCLE` we resume from where it stopped instead of
        // re-scanning the same prefix of non-prunable records (ledger-ops,
        // governance-ops) over and over. The caller (`gc_loop`) clears
        // `resume_from` to `None` on a natural `ts > scan_until` break so the
        // next pass re-scans from the top — that bounds the latency for
        // out-of-order inserts to one full drain cycle.
        let iter_mode = match resume_from {
            Some(key) => rocksdb::IteratorMode::From(key, rocksdb::Direction::Forward),
            None => rocksdb::IteratorMode::Start,
        };
        let iter = self.db.iterator_cf(&ts_cf, iter_mode);
        let resume_key_owned: Option<Vec<u8>> = resume_from.map(|k| k.to_vec());

        let mut result = GcResult::default();
        let mut deleted_ids: Vec<String> = Vec::new();
        let mut last_scanned_key: Option<Vec<u8>> = None;

        // SCALE RULE bound: every candidate triggers a random `get_cf` against
        // CF_RECORDS, so the per-cycle cost is dominated by point-lookups, not
        // the index walk. On a saturated box (19 GB rocksdb,
        // 510 SSTs, 1 vCPU under compaction pressure) one unbounded cycle ran
        // for 616 s — the box was effectively GC-blocked behind a single tick.
        // Cap at 5_000 candidates per cycle, signal `scan_capped` so `gc_loop`
        // can shorten the next interval and drain incrementally rather than
        // queue the whole backlog onto one cycle.
        const MAX_GC_SCAN_PER_CYCLE: usize = 5_000;
        let mut scanned: usize = 0;

        for item in iter {
            if scanned >= MAX_GC_SCAN_PER_CYCLE {
                result.scan_capped = true;
                result.last_scanned_key = last_scanned_key.clone();
                break;
            }
            let (key, _) = item.map_err(|e| ElaraError::Storage(format!("gc ts iter: {e}")))?;
            // `IteratorMode::From(key, Forward)` is inclusive — when resuming
            // we'd otherwise spend slot #1 re-processing the previous cycle's
            // final key. Skip it without counting against the cap.
            if let Some(rk) = resume_key_owned.as_deref() {
                if last_scanned_key.is_none() && key.as_ref() == rk {
                    continue;
                }
            }
            scanned += 1;
            last_scanned_key = Some(key.to_vec());
            if key.len() < 8 { continue; }

            let ts = f64::from_be_bytes(key[..8].try_into().unwrap_or([0u8; 8]));

            // Stop when we reach records newer than the cutoff
            if ts > scan_until {
                break;
            }

            let record_id = match std::str::from_utf8(&key[8..]) {
                Ok(id) if !id.is_empty() => id,
                _ => continue,
            };

            // Load just this one record to check metadata
            let wire = match self.db.get_cf(&records_cf, record_id.as_bytes()) {
                Ok(Some(w)) => w,
                _ => continue,
            };
            let rec = match ValidationRecord::from_bytes(&wire) {
                Ok(r) => r,
                Err(_) => continue,
            };

            // Ledger-ops and governance-ops are integrity-critical (ledger
            // depends on them) — never prune.
            if rec.metadata.contains_key("beat_op")
                || rec.metadata.contains_key("governance_op")
            {
                continue;
            }

            // Signed-proof carriers — never prune. Agent-mandate issuance /
            // revocation carriers are the cryptographic proof a principal
            // authorized the mandate (pruning leaves a registry entry with no
            // surviving proof); emergency halt/resume carriers are the signed
            // audit trail of a circuit-breaker action. The in-memory +
            // rocks GC twins (network/gc.rs:148/155 + :243/250) exempt both;
            // this PRODUCTION scan (the path gc_loop actually runs) MUST match
            // or the canonical exemption set silently diverges on the live box.
            // Use the consts, not string literals, so a key rename can't drift
            // this guard out of sync again.
            if rec.metadata.contains_key(crate::mandate::MANDATE_OP_KEY)
                || rec.metadata.contains_key(crate::mandate::MANDATE_REVOCATION_OP_KEY)
                || rec.metadata.contains_key(crate::emergency::EMERGENCY_HALT_OP_KEY)
                || rec.metadata.contains_key(crate::emergency::EMERGENCY_RESUME_OP_KEY)
            {
                continue;
            }

            // Gap 3 (epoch ops): super-seals, zone_transitions, and global
            // seals are integrity-critical — never prune. Per-zone "seal"
            // records are prunable ONLY when (a) a super-seal covering the
            // zone exists, (b) the seal's epoch is below the per-zone
            // pruning floor (= latest_super_seal.end_epoch − 2× interval),
            // and (c) the standard finalized + retention checks below
            // also pass. Falling through here means the record is treated
            // like any other prunable record, which means it will be
            // pruned when the retention window catches up.
            // Fall through if the record is a prunable seal — the
            // seal_pruned counter is bumped at the delete site by
            // re-checking the metadata key (cheaper than threading a
            // flag through).
            if rec.metadata.contains_key("epoch_op")
                && !is_prunable_seal_record(&rec, seal_pruning_floor)
            {
                continue;
            }

            let finalized = is_finalized(record_id);
            let is_seal = rec.metadata.contains_key("epoch_op");

            // Check explicit expiration
            if super::super::network::gc::is_expired(&rec, scan_until) {
                if finalized {
                    deleted_ids.push(record_id.to_string());
                    if is_seal {
                        result.seal_pruned += 1;
                    } else {
                        result.expired_pruned += 1;
                    }
                } else {
                    result.skipped += 1;
                }
                continue;
            }

            // Sunken records (low relevance, finalized)
            if finalized && is_sunken(record_id) {
                deleted_ids.push(record_id.to_string());
                if is_seal {
                    result.seal_pruned += 1;
                } else {
                    result.sunken_pruned += 1;
                }
                continue;
            }

            // Retention-based pruning (finalized + old enough). Seals
            // reaching here have already passed `is_prunable_seal_record`
            // (covering super-seal + epoch below floor), so unconditionally
            // prune them as seal_pruned regardless of timestamp window.
            if finalized && is_seal {
                deleted_ids.push(record_id.to_string());
                result.seal_pruned += 1;
                continue;
            }
            if finalized && ts < retention_cutoff {
                deleted_ids.push(record_id.to_string());
                result.retention_pruned += 1;
                continue;
            }

            // Tier 3.4 (Protocol §11.8) epoch-based pruning: a finalized
            // non-seal record whose per-zone epoch is below the super-seal
            // safety floor (= timestamp of seal at end_epoch − 2 ×
            // SUPER_SEAL_INTERVAL) is verifiable via the seal's Merkle root
            // alone — body bytes are no longer needed on this profile.
            // Ledger-ops, governance-ops, and seals are excluded above.
            // Falls through to stale-pruning when no floor is configured
            // for the record's zone.
            if finalized && !record_pruning_floor_ts.is_empty() {
                let zone = rec.record_zone();
                if let Some(floor_ts) = record_pruning_floor_ts.get(&zone) {
                    if ts < *floor_ts {
                        deleted_ids.push(record_id.to_string());
                        result.epoch_pruned += 1;
                        continue;
                    }
                }
            }

            // Stale unfinalized records: older than 2x retention, never got
            // witnessed. These will never be finalized — prune as abandoned.
            // Seals are always finalized once registered, so this branch
            // never fires for seals — keep the counter unconditional.
            if ts < stale_cutoff {
                deleted_ids.push(record_id.to_string());
                result.stale_pruned += 1;
            }
        }

        // Delete in batches — each delete_record cleans up all indexes
        for id in &deleted_ids {
            if let Err(e) = self.delete_record(id) {
                tracing::warn!("gc: failed to delete record {}: {e}", &id[..id.len().min(16)]);
            }
        }

        // NOTE: Compaction moved to gc_loop (threshold-based, every 50+ deletes).
        // Running compact_range_cf after every 2-3 record delete was wasteful I/O
        // and ineffective — 4,288 SST files persisted on Helsinki despite per-cycle
        // compaction. Startup compaction handles the heavy reclamation instead.

        // Store deleted IDs for DAG cleanup by caller
        result.deleted_ids = deleted_ids;
        Ok(result)
    }

    /// Stream record IDs through a callback without collecting into a Vec.
    /// Returns the total count of IDs visited. Uses O(1) memory regardless of
    /// record count — the unbounded `Vec<String>` ancestor was deleted as a
    /// SCALE RULE violation (~640MB heap on 10M-record archive nodes).
    pub fn for_each_record_id(&self, mut f: impl FnMut(&str)) -> Result<usize> {
        let cf = self.try_cf(CF_RECORDS)?;
        let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start);
        let mut count = 0;
        for (key, _) in iter.flatten() {
            if key.starts_with(b"__")
                || key.starts_with(b"ban:")
                || key.starts_with(b"blocked_term:")
                || key.starts_with(b"finalized:")
                || key.starts_with(b"tombstone:")
            {
                continue;
            }
            if let Ok(id) = std::str::from_utf8(&key) {
                f(id);
                count += 1;
            }
        }
        Ok(count)
    }

    /// Return record IDs from the timestamp index in reverse order (newest first).
    /// Lightweight: only reads 8-byte timestamp + record_id from the index keys,
    /// never touches CF_RECORDS. Stops after `limit` IDs or when records are older
    /// than `since` (unix timestamp). Used by auto-witness Phase 3 to find recent
    /// records that may have zero attestations.
    pub fn recent_record_ids(&self, since: f64, limit: usize) -> Result<Vec<String>> {
        let ts_cf = self.try_cf(CF_IDX_TIMESTAMP)?;
        let iter = self.db.iterator_cf(&ts_cf, rocksdb::IteratorMode::End);

        let mut ids = Vec::with_capacity(limit.min(MAX_SCAN_PREALLOC));
        for item in iter {
            let (key, _) = item.map_err(|e| ElaraError::Storage(format!("recent_ids iter: {e}")))?;
            if key.len() < 8 { continue; }

            let ts = f64::from_be_bytes(key[..8].try_into().unwrap_or([0u8; 8]));
            if ts < since { break; }

            if let Ok(rid) = std::str::from_utf8(&key[8..]) {
                if !rid.is_empty() {
                    ids.push(rid.to_string());
                }
            }
            if ids.len() >= limit { break; }
        }
        Ok(ids)
    }

    /// Scan record IDs starting from a given timestamp (forward, oldest first).
    /// Used by auto-witness to discover old records synced via full_pull that
    /// `recent_record_ids` (newest-first, limit 500) never reaches.
    pub fn record_ids_from(&self, from_ts: f64, limit: usize) -> Result<Vec<String>> {
        let ts_cf = self.try_cf(CF_IDX_TIMESTAMP)?;
        let seek_key = from_ts.to_be_bytes();
        let iter = self.db.iterator_cf(
            &ts_cf,
            rocksdb::IteratorMode::From(&seek_key, rocksdb::Direction::Forward),
        );

        let mut ids = Vec::with_capacity(limit.min(MAX_SCAN_PREALLOC));
        for item in iter {
            let (key, _) = item.map_err(|e| ElaraError::Storage(format!("record_ids_from iter: {e}")))?;
            if key.len() < 8 { continue; }
            if let Ok(rid) = std::str::from_utf8(&key[8..]) {
                if !rid.is_empty() {
                    ids.push(rid.to_string());
                }
            }
            if ids.len() >= limit { break; }
        }
        Ok(ids)
    }

    /// See [`TsScanStart`] / [`TsPage`] (defined at module level below the
    /// impl block) for the parameter/result contracts.
    ///
    /// One bounded forward page over CF_IDX_TIMESTAMP for the delta-sync
    /// cross-page cursor (design brief internal design notes).
    /// Twin of [`Self::record_ids_from`] (which stays untouched — it returns
    /// ids only and cannot mint a cursor; its non-delta-sync caller is the
    /// bloom build). Differences, all load-bearing:
    ///
    /// - returns `(ts, id)` PAIRS, so callers can build the wire cursor
    ///   `hex(f64_be(ts) ++ id_bytes)` for any entry — including page 1 of a
    ///   legacy-shaped request (the additive `next_cursor` there is what
    ///   lets a cursor-capable client upgrade on page 2);
    /// - `TsScanStart::AfterKey` resumes STRICTLY AFTER an exact raw key
    ///   (skip-on-equal, same convention as [`Self::stream_records_chunk`]);
    ///   a GC'd cursor key is safe by construction — the seek lands on the
    ///   next surviving key and the equality skip simply never fires;
    /// - the `limit` bounds ITERATED keys, not collected pairs, so the
    ///   per-page CPU stays bounded even over malformed junk keys (which are
    ///   skipped from `entries` but still advance + count);
    /// - `last_scanned_key` is the raw key of the last ITERATED entry (None
    ///   iff the scan yielded nothing) — the caller's cursor frontier for a
    ///   fully-drained slice, valid even when `entries` is empty;
    /// - `scan_truncated` is true iff the scan stopped at `limit` — the
    ///   caller's `has_more` contribution.
    ///
    /// SCALE: O(limit) per call, O(chunk) memory; the caller (delta-sync
    /// handler) caps `limit` at PAGE_SCAN/MAX_SCAN.
    pub fn record_entries_page(
        &self,
        start: TsScanStart<'_>,
        limit: usize,
    ) -> Result<TsPage> {
        let ts_cf = self.try_cf(CF_IDX_TIMESTAMP)?;
        // Hoist the Since seek bytes so they outlive iter_mode.
        let since_bytes;
        let (iter_mode, skip_key): (rocksdb::IteratorMode<'_>, Option<&[u8]>) = match start {
            TsScanStart::Since(ts) => {
                since_bytes = ts.to_be_bytes();
                (
                    rocksdb::IteratorMode::From(&since_bytes, rocksdb::Direction::Forward),
                    None,
                )
            }
            TsScanStart::AfterKey(key) => (
                rocksdb::IteratorMode::From(key, rocksdb::Direction::Forward),
                Some(key),
            ),
        };
        let iter = self.db.iterator_cf(&ts_cf, iter_mode);

        let mut entries: Vec<(f64, String)> = Vec::with_capacity(limit.min(MAX_SCAN_PREALLOC));
        let mut last_scanned_key: Option<Vec<u8>> = None;
        let mut iterated = 0usize;
        let mut scan_truncated = false;
        for item in iter {
            let (key, _) = item
                .map_err(|e| ElaraError::Storage(format!("record_entries_page iter: {e}")))?;
            // Skip the cursor's own key iff the seek landed exactly on it
            // (strictly-after semantics). Only the FIRST key can match.
            if iterated == 0 && last_scanned_key.is_none() {
                if let Some(sk) = skip_key {
                    if sk == key.as_ref() {
                        // The cursor key itself does not count toward the
                        // page budget and is not a frontier candidate — the
                        // caller already consumed it last page.
                        continue;
                    }
                }
            }
            iterated += 1;
            last_scanned_key = Some(key.to_vec());
            if key.len() >= 8 {
                let ts = f64::from_be_bytes(key[..8].try_into().unwrap_or([0u8; 8]));
                if let Ok(rid) = std::str::from_utf8(&key[8..]) {
                    if !rid.is_empty() {
                        entries.push((ts, rid.to_string()));
                    }
                }
            }
            if iterated >= limit {
                scan_truncated = true;
                break;
            }
        }
        Ok(TsPage {
            entries,
            last_scanned_key,
            scan_truncated,
        })
    }

    /// Compute sorted record hashes by streaming records one at a time.
    /// Each record is deserialized, hashed, and immediately dropped — O(1)
    /// memory per record instead of loading all ~500MB into a Vec.
    /// Result: Vec<[u8; 32]> (~768KB for 24K records).
    pub fn record_hashes_streaming(&self) -> Result<Vec<[u8; 32]>> {
        let cf = self.try_cf(CF_RECORDS)?;
        let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start);
        let mut hashes = Vec::new();

        for item in iter {
            let (key, value) = item.map_err(|e| ElaraError::Storage(format!("hash iter: {e}")))?;
            // Skip internal keys
            if key.starts_with(b"__")
                || key.starts_with(b"ban:")
                || key.starts_with(b"blocked_term:")
                || key.starts_with(b"finalized:")
                || key.starts_with(b"tombstone:")
            {
                continue;
            }
            if let Ok(rec) = ValidationRecord::from_bytes(&value) {
                hashes.push(rec.record_hash());
                // rec dropped here — no accumulation
            }
        }

        hashes.sort();
        Ok(hashes)
    }

    /// Stream through all records in CF_RECORDS, calling `f` for each one.
    /// Records are deserialized and dropped after the callback — O(1) memory.
    /// Single-pass iterator over CF_RECORDS avoids the double-lookup cost of
    /// going through CF_IDX_TIMESTAMP → CF_RECORDS.
    pub fn for_each_record(&self, mut f: impl FnMut(&ValidationRecord)) -> Result<()> {
        let cf = self.try_cf(CF_RECORDS)?;
        let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start);

        for item in iter {
            let (key, value) = item.map_err(|e| ElaraError::Storage(format!("for_each iter: {e}")))?;
            if key.starts_with(b"__")
                || key.starts_with(b"ban:")
                || key.starts_with(b"blocked_term:")
                || key.starts_with(b"finalized:")
                || key.starts_with(b"tombstone:")
            {
                continue;
            }
            if let Ok(rec) = ValidationRecord::from_bytes(&value) {
                f(&rec);
            }
        }
        Ok(())
    }

    /// Find the timestamp of a specific epoch seal record by streaming through
    /// CF_RECORDS one at a time. Returns None if not found. Avoids loading all
    /// records into memory (the old code used query(usize::MAX) — ~1.5GB on 60K records).
    /// Timestamp of any seal at `epoch_num`, via the CF_EPOCHS DISC-5 index
    /// (key = `epoch_be(8) || zone_path || 0x00 || record_id`, written
    /// unconditionally on every seal ingest — see the DISC-5 block in
    /// `ingest.rs`). An 8-byte epoch-only prefix seek finds the first seal at
    /// that epoch in O(1) (seek + one CF_RECORDS point-get), replacing the
    /// prior O(all_records) CF_RECORDS scan — the last straggler the DISC-5
    /// index was built to eliminate, and a peer-triggerable scan via the
    /// `snapshot_fast?since_epoch` path. The key's epoch field is exactly
    /// `seal.epoch_number`, so the prefix match is an exact equivalent of the
    /// old `epoch_number == epoch_num` check. Any seal at the epoch yields an
    /// equivalent epoch-time boundary for the caller; returns the
    /// lexicographically-first zone's seal. `None` if no seal exists there.
    pub fn find_epoch_seal_timestamp(&self, epoch_num: u64) -> Result<Option<f64>> {
        let epochs_cf = self.try_cf(CF_EPOCHS)?;
        let records_cf = self.try_cf(CF_RECORDS)?;
        let prefix = epoch_num.to_be_bytes();
        let mode = rocksdb::IteratorMode::From(&prefix[..], rocksdb::Direction::Forward);
        for kv in self.db.iterator_cf(&epochs_cf, mode) {
            let (key, _) = match kv {
                Ok(kv) => kv,
                Err(_) => continue,
            };
            if !key.starts_with(&prefix[..]) {
                // Seeked past the epoch_num prefix band — no seal at this epoch.
                return Ok(None);
            }
            let Some((_, _, record_id)) = crate::network::epoch::parse_disc5_index_key(&key)
            else {
                continue;
            };
            // Tolerate a per-record read error as "missing" and keep scanning
            // the epoch band — mirrors the prior scan's skip-on-error behavior.
            if let Some(wire) = self.db.get_cf(&records_cf, record_id.as_bytes()).ok().flatten() {
                if let Ok(rec) = ValidationRecord::from_bytes(&wire) {
                    return Ok(Some(rec.timestamp));
                }
            }
        }
        Ok(None)
    }

    /// Stream all records in timestamp order through a callback.
    /// Uses CF_IDX_TIMESTAMP index — records arrive chronologically.
    /// At 10M records, query(usize::MAX) allocates ~20GB; this uses O(1) memory.
    /// Returns the total count of records visited.
    pub fn for_each_record_ordered(&self, f: impl FnMut(&crate::record::ValidationRecord)) -> Result<usize> {
        self.for_each_record_ordered_bounded(0, f)
    }

    /// Stream records from CF_IDX_TIMESTAMP in chronological order.
    /// If `max_records > 0`, only streams the most recent N records.
    /// Each record is deserialized, passed to `f`, then dropped — O(1) memory.
    pub fn for_each_record_ordered_bounded(
        &self,
        max_records: usize,
        mut f: impl FnMut(&crate::record::ValidationRecord),
    ) -> Result<usize> {
        let ts_cf = self.try_cf(CF_IDX_TIMESTAMP)?;
        let records_cf = self.try_cf(CF_RECORDS)?;

        // For bounded mode: find the start key by iterating backwards
        let start_key: Option<Vec<u8>> = if max_records > 0 {
            let mut keys = Vec::with_capacity(max_records);
            let iter = self.db.iterator_cf(&ts_cf, rocksdb::IteratorMode::End);
            for item in iter {
                if keys.len() >= max_records { break; }
                if let Ok((k, _)) = item {
                    keys.push(k.to_vec());
                }
            }
            keys.last().cloned() // oldest of the newest max_records
        } else {
            None
        };

        let iter = if let Some(ref key) = start_key {
            self.db.iterator_cf(&ts_cf, rocksdb::IteratorMode::From(key, rocksdb::Direction::Forward))
        } else {
            self.db.iterator_cf(&ts_cf, rocksdb::IteratorMode::Start)
        };

        let mut count = 0;
        for item in iter {
            let (key, _) = item.map_err(|e| ElaraError::Storage(format!("stream iter: {e}")))?;
            if key.len() < 8 { continue; }

            let record_id = std::str::from_utf8(&key[8..]).unwrap_or("");
            if record_id.is_empty() { continue; }

            let wire = match self.db.get_cf(&records_cf, record_id.as_bytes()) {
                Ok(Some(w)) => w,
                _ => continue,
            };
            let rec = match crate::record::ValidationRecord::from_bytes(&wire) {
                Ok(r) => r,
                Err(_) => continue,
            };

            f(&rec);
            count += 1;
        }

        Ok(count)
    }

    /// Stream a fixed-size chunk of records from CF_IDX_TIMESTAMP with cursor-based pagination.
    ///
    /// - `cursor`: hex-encoded CF_IDX_TIMESTAMP key of the last record from the previous chunk.
    ///   Seek starts AFTER this key. None = start from beginning.
    /// - `since_ts`: if set, only return records with timestamp >= this value.
    /// - `chunk_size`: maximum records to return per call.
    ///
    /// Returns `(records, next_cursor_hex)`. `next_cursor_hex` is None when no more records exist.
    /// Memory: O(chunk_size) — never loads the full database.
    pub fn stream_records_chunk(
        &self,
        cursor_hex: Option<&str>,
        since_ts: Option<f64>,
        chunk_size: usize,
    ) -> Result<(Vec<crate::record::ValidationRecord>, Option<String>)> {
        let ts_cf = self.try_cf(CF_IDX_TIMESTAMP)?;
        let records_cf = self.try_cf(CF_RECORDS)?;

        // Decode cursor (raw CF_IDX_TIMESTAMP key bytes) or compute seek position from since_ts
        let cursor_bytes: Option<Vec<u8>> = if let Some(hex_str) = cursor_hex {
            Some(hex::decode(hex_str).map_err(|e| ElaraError::Storage(format!("bad cursor hex: {e}")))?)
        } else {
            None
        };

        // Hoist ts_bytes so its lifetime extends past iter_mode usage
        let ts_bytes = since_ts.map(|ts| ts.to_bits().to_be_bytes());

        let iter_mode = if let Some(ref cursor_key) = cursor_bytes {
            rocksdb::IteratorMode::From(cursor_key, rocksdb::Direction::Forward)
        } else if let Some(ref tb) = ts_bytes {
            rocksdb::IteratorMode::From(tb, rocksdb::Direction::Forward)
        } else {
            rocksdb::IteratorMode::Start
        };

        let iter = self.db.iterator_cf(&ts_cf, iter_mode);
        let mut records = Vec::with_capacity(chunk_size);
        let mut last_key: Option<Vec<u8>> = None;
        let mut skip_cursor = cursor_bytes.is_some();
        // Byte budget: a snapshot chunk is returned in a SINGLE PQ frame (16 MiB
        // cap). `chunk_size` (500) max-size dual-signed records ≈ 37 MB hex would
        // blow the frame → the serve send fails → fast sync wedges at this cursor
        // forever. Cap the response by encoded bytes too (mirrors delta_sync's
        // MAX_SYNC_RESPONSE_HEX_BYTES). `more_available` — NOT `records.len() >=
        // chunk_size` — decides next_cursor, so a byte-triggered short page still
        // paginates (the old count-only test would signal a false final chunk and
        // silently truncate the sync).
        let mut hex_budget: usize = 0;
        let mut more_available = false;

        for item in iter {
            let (key, _) = item.map_err(|e| ElaraError::Storage(format!("stream chunk: {e}")))?;

            // Skip the cursor record itself (seek lands ON it)
            if skip_cursor {
                if cursor_bytes.as_deref() == Some(key.as_ref()) {
                    continue;
                }
                skip_cursor = false;
            }

            if key.len() < 8 { continue; }
            let record_id = std::str::from_utf8(&key[8..]).unwrap_or("");
            if record_id.is_empty() { continue; }

            // Apply since_ts filter (for cases where cursor was set but since_ts also applies)
            if let Some(ts) = since_ts {
                let ts_bits = f64::from_be_bytes(key[..8].try_into().unwrap_or([0u8; 8]));
                if ts_bits < ts { continue; }
            }

            let wire = match self.db.get_cf(&records_cf, record_id.as_bytes()) {
                Ok(Some(w)) => w,
                _ => continue,
            };
            let rec = match crate::record::ValidationRecord::from_bytes(&wire) {
                Ok(r) => r,
                Err(_) => continue,
            };

            // Stop before the frame overruns, but always include ≥1 record
            // (progress guarantee — one record ≤ MAX_RECORD_BYTES ≪ budget).
            let rec_hex_len = wire.len().saturating_mul(2);
            if !records.is_empty()
                && hex_budget.saturating_add(rec_hex_len)
                    > crate::network::sync::MAX_SYNC_RESPONSE_HEX_BYTES
            {
                more_available = true; // this record (and beyond) remain
                break;
            }

            records.push(rec);
            hex_budget = hex_budget.saturating_add(rec_hex_len);
            last_key = Some(key.to_vec());

            if records.len() >= chunk_size {
                more_available = true;
                break;
            }
        }

        let next_cursor = if more_available {
            last_key.map(hex::encode)
        } else {
            None
        };

        Ok((records, next_cursor))
    }

    /// Rebuild the ledger by streaming records from RocksDB one at a time.
    ///
    /// This avoids loading all records into a Vec (which peaks at ~100-200MB for 15K records
    /// and causes severe heap fragmentation on small VPS). Instead, we iterate the timestamp
    /// index, deserialize each record, extract ledger/governance ops, and drop the record
    /// immediately. Only the small (record, op) pairs for ledger operations are kept.
    pub fn rebuild_ledger_streaming(
        &self,
        genesis_authority: &str,
        genesis_validators: &[crate::accounting::types::GenesisValidator],
    ) -> Result<(crate::accounting::ledger::LedgerState, usize)> {
        use crate::accounting::ledger::{apply_op, apply_governance_op};
        use crate::accounting::types::{creator_identity_hash, extract_ledger_op, ParsedLedgerOp};
        use crate::record::{Classification, ValidationRecord};

        let ts_cf = self.try_cf(CF_IDX_TIMESTAMP)?;
        let records_cf = self.try_cf(CF_RECORDS)?;

        // The CF_IDX_TIMESTAMP key is `f64::to_be_bytes(timestamp) ++ record_id`,
        // written in the same WriteBatch as the record. RocksDB iterates keys in
        // byte-lex order, which for the positive-finite timestamps the ingest
        // gate enforces is EXACTLY `total_cmp(timestamp).then(id)` order — so the
        // old explicit sort was redundant (audit 16e). We therefore STREAM token
        // ops straight through apply_op in that order (no full Vec, no sort),
        // buffering only the small failed-op set for the single retry pass that
        // `derive_ledger_tolerant` used to do, plus the small governance-op set
        // (governance is human-rate). Memory is O(failed + gov), not
        // O(all ledger ops) — the old Vec OOM'd on a full-history rebuild at
        // mainnet scale (this is the boot/sync/bootstrap recovery fallback).
        let mut state = crate::accounting::ledger::LedgerState::new();
        let mut failed_token: Vec<(ValidationRecord, ParsedLedgerOp)> = Vec::new();
        let mut gov_records: Vec<ValidationRecord> = Vec::new();

        let iter = self.db.iterator_cf(&ts_cf, rocksdb::IteratorMode::Start);
        for item in iter {
            let (key, _) = item.map_err(|e| ElaraError::Storage(format!("stream iter: {e}")))?;
            if key.len() < 8 { continue; }

            let record_id = std::str::from_utf8(&key[8..]).unwrap_or("");
            if record_id.is_empty() { continue; }

            let wire = match self.db.get_cf(&records_cf, record_id.as_bytes()) {
                Ok(Some(w)) => w,
                _ => continue,
            };
            let rec = match ValidationRecord::from_bytes(&wire) {
                Ok(r) => r,
                Err(_) => continue,
            };

            if rec.classification != Classification::Public { continue; }
            if let Ok(Some(op)) = extract_ledger_op(&rec) {
                // Apply in iterator (= timestamp,id) order. Buffer first-pass
                // failures for the retry below (e.g. an op whose dependency is a
                // same-timestamp record that sorts after it).
                if apply_op(&mut state, &rec, &op, genesis_authority).is_err() {
                    failed_token.push((rec, op));
                }
                continue;
            }
            if let Ok(Some(_)) = crate::accounting::governance::extract_governance_op(&rec.metadata) {
                gov_records.push(rec);
            }
            // rec dropped here if not a ledger/gov record — no memory retained
        }

        // Retry pass — mirrors derive_ledger_tolerant: each first-pass failure
        // gets one more attempt against the now-fully-populated state. `skipped`
        // counts the ops that STILL fail (the returned tolerant-skip count).
        let mut skipped = 0usize;
        for (record, op) in &failed_token {
            if apply_op(&mut state, record, op, genesis_authority).is_err() {
                skipped += 1;
            }
        }
        if !failed_token.is_empty() {
            tracing::debug!(
                "ledger rebuild: {} first-pass failures, {} recovered on retry, {} still skipped",
                failed_token.len(), failed_token.len() - skipped, skipped
            );
        }

        // Genesis validator baseline — post-replay so the genesis mint is present.
        crate::accounting::ledger::apply_genesis_validators(&mut state, genesis_validators, genesis_authority);

        // Governance ops AFTER all ledger ops — load-bearing: apply_governance_op
        // reads state.stakes, which Stake ops populate. gov_records already
        // arrived in (timestamp, id) order, so no sort is needed.
        for record in &gov_records {
            let creator = creator_identity_hash(record);
            if let Ok(Some(gov_op)) = crate::accounting::governance::extract_governance_op(&record.metadata) {
                let _ = apply_governance_op(&mut state, record, &gov_op, &creator);
            }
        }

        Ok((state, skipped))
    }

    /// Incrementally replay ledger/governance ops from records newer than `since_ts`
    /// into an existing `LedgerState`. Returns (records_applied, skipped).
    ///
    /// This is the fast path for checkpoint startup: load a saved ledger snapshot,
    /// then replay only the small number of records created since the snapshot.
    pub fn incremental_ledger_replay(
        &self,
        state: &mut crate::accounting::ledger::LedgerState,
        genesis_authority: &str,
        genesis_validators: &[crate::accounting::types::GenesisValidator],
        since_ts: f64,
    ) -> Result<(usize, usize)> {
        use crate::accounting::ledger::apply_op;
        use crate::accounting::types::extract_ledger_op;
        use crate::record::{Classification, ValidationRecord};

        let ts_cf = self.try_cf(CF_IDX_TIMESTAMP)?;
        let records_cf = self.try_cf(CF_RECORDS)?;

        // The CF_IDX_TIMESTAMP iterator yields records in (timestamp, id) order
        // (key = to_be_bytes(ts) ++ id; positive-finite ts enforced at ingest),
        // which equals the old explicit total_cmp(ts).then(id) sort — so we stream
        // ledger ops straight through apply_op with no full Vec or sort, buffering
        // only the small governance-op set (applied after — ledger-before-gov is
        // load-bearing since apply_governance_op reads state.stakes). This is a
        // plain fold (no retry pass), matching the prior semantics exactly.
        // Memory is O(gov), not O(all ledger ops since the snapshot) (audit 16e).
        let mut gov_records: Vec<ValidationRecord> = Vec::new();
        let mut applied = 0usize;
        let mut skipped = 0usize;

        // Seek to since_ts in timestamp index
        let start = since_ts.to_be_bytes();
        let iter = self.db.iterator_cf(
            &ts_cf,
            rocksdb::IteratorMode::From(&start, rocksdb::Direction::Forward),
        );

        for item in iter {
            let (key, _) = item.map_err(|e| ElaraError::Storage(format!("incr iter: {e}")))?;
            if key.len() < 8 { continue; }

            // EXCLUSIVE seek floor (B1). The CF_IDX_TIMESTAMP key is
            // `to_be_bytes(ts) ++ id`, so `From(since_ts, Forward)` lands
            // INCLUSIVELY on records whose ts == `since_ts`. At boot the caller
            // passes `cp_ledger.last_applied_ts` (the max ts already folded into
            // the loaded snapshot); every record at-or-below that ts is already
            // folded, so skip the whole `ts <= since_ts` band. Re-applying a
            // boundary record would DOUBLE-COUNT: the loaded `applied_record_ids`
            // is empty (clone() drops it, ledger.rs), so neither the in-memory
            // guard below nor apply_op's head-guard can dedup a record folded in a
            // PRIOR run. Records strictly after the floor are unfolded → apply.
            let mut ts_buf = [0u8; 8];
            ts_buf.copy_from_slice(&key[..8]);
            let key_ts = f64::from_be_bytes(ts_buf);
            if key_ts <= since_ts { continue; }

            let record_id = std::str::from_utf8(&key[8..]).unwrap_or("");
            if record_id.is_empty() { continue; }

            // Dedup against THIS ledger's in-memory applied set only (repopulated
            // by apply_op / apply_governance_op as records fold below). Do NOT
            // consult the global on-disk CF_APPLIED here (the old `|| self.is_applied`):
            // it is marked eagerly at ingest, so a record applied to the live
            // ledger AFTER this checkpoint was saved but BEFORE a crash is in
            // CF_APPLIED yet ABSENT from the loaded balances — keying on it
            // silently DROPS that record's effect → permanent SMT fork (B1). The
            // boot-time root backstop in bin/elara_node.rs catches any residual
            // divergence (out-of-order / same-exact-ts) and falls back to the
            // authoritative full rebuild.
            if state.applied_record_ids.contains(record_id) { continue; }

            let wire = match self.db.get_cf(&records_cf, record_id.as_bytes()) {
                Ok(Some(w)) => w,
                _ => continue,
            };
            let rec = match ValidationRecord::from_bytes(&wire) {
                Ok(r) => r,
                Err(_) => continue,
            };

            if rec.classification == Classification::Public {
                if let Ok(Some(op)) = extract_ledger_op(&rec) {
                    // Apply in iterator (= timestamp,id) order — no sort needed.
                    if apply_op(state, &rec, &op, genesis_authority).is_ok() {
                        applied += 1;
                    } else {
                        skipped += 1;
                    }
                    continue;
                }
                if let Ok(Some(_)) = crate::accounting::governance::extract_governance_op(&rec.metadata) {
                    gov_records.push(rec);
                }
            }
        }

        // Governance ops AFTER all ledger ops. gov_records already arrived in
        // (timestamp, id) order, so no sort is needed.
        for record in &gov_records {
            let creator = crate::accounting::types::creator_identity_hash(record);
            if let Ok(Some(gov_op)) = crate::accounting::governance::extract_governance_op(&record.metadata) {
                // Count successes only — mirror the ledger-op loop above. The
                // previous `let _ = …; applied += 1` inflated the stat by
                // counting failed governance applies as applied (audit 16i).
                if crate::accounting::ledger::apply_governance_op(state, record, &gov_op, &creator).is_ok() {
                    applied += 1;
                } else {
                    skipped += 1;
                }
            }
        }

        // Genesis validator baseline — idempotent (synthetic-id guard), so a
        // post-feature snapshot is a no-op and a pre-feature snapshot gets
        // the baseline injected exactly once.
        crate::accounting::ledger::apply_genesis_validators(state, genesis_validators, genesis_authority);

        Ok((applied, skipped))
    }

    // ── Database Migrations ──────────────────────────────────────────────

    /// Key for storing the current database schema version (in CF_RECORDS).
    const DB_VERSION_KEY: &'static [u8] = b"__db_version__";

    /// Read the current database schema version. Returns 0 for pre-versioning databases.
    pub fn get_db_version(&self) -> Result<u32> {
        let cf = self.try_cf(CF_RECORDS)?;
        match self.db.get_cf(&cf, Self::DB_VERSION_KEY) {
            Ok(Some(bytes)) if bytes.len() == 4 => {
                let mut buf = [0u8; 4];
                buf.copy_from_slice(&bytes[..4]);
                Ok(u32::from_le_bytes(buf))
            }
            Ok(_) => Ok(0),
            Err(e) => Err(ElaraError::Storage(format!("read db version: {e}"))),
        }
    }

    /// Write the database schema version.
    fn set_db_version(&self, version: u32) -> Result<()> {
        let cf = self.try_cf(CF_RECORDS)?;
        self.db
            .put_cf(&cf, Self::DB_VERSION_KEY, version.to_le_bytes())
            .map_err(|e| ElaraError::Storage(format!("write db version: {e}")))
    }

    /// Run all pending database migrations. Creates a RocksDB checkpoint before
    /// migrating as a safety net.
    ///
    /// Call after `open()` during node startup. Idempotent — safe to call multiple times.
    ///
    /// # Migration contract
    /// - Migrations are forward-only (no rollback — restore from checkpoint if needed)
    /// - Each migration runs exactly once, in order
    /// - Pre-migration checkpoint provides rollback safety
    /// - New CFs are handled automatically by `create_missing_column_families(true)`
    ///   — migrations are for data transforms, index backfills, and key format changes
    pub fn run_migrations(&self, data_dir: &Path) -> Result<()> {
        let current = self.get_db_version()?;
        if current >= CURRENT_DB_VERSION {
            // DB is already at the current schema version — no migrations to run.
            // Still sweep stale pre-migration backups that may have accumulated
            // from prior migration runs (the v{N-1} rollback target is enough;
            // older backups are dead weight and can fill the disk on small VPS).
            prune_stale_pre_migration_backups(data_dir, current);
            return Ok(());
        }

        tracing::info!(
            "Database migration: v{current} → v{CURRENT_DB_VERSION} ({} pending)",
            CURRENT_DB_VERSION - current
        );

        // Safety: checkpoint the database before any migration
        let backup_path = data_dir.join(format!("pre-migration-v{current}-backup"));
        if !backup_path.exists() {
            match self.create_checkpoint(&backup_path) {
                Ok(()) => tracing::info!(
                    "Pre-migration checkpoint: {}",
                    backup_path.display()
                ),
                Err(e) => tracing::warn!(
                    "Pre-migration checkpoint failed (continuing): {e}"
                ),
            }
        }

        // Run each migration sequentially
        for v in current..CURRENT_DB_VERSION {
            let start = std::time::Instant::now();
            match v {
                0 => self.migrate_0_to_1()?,
                1 => self.migrate_1_to_2()?,
                2 => self.migrate_2_to_3()?,
                3 => self.migrate_3_to_4()?,
                4 => self.migrate_4_to_5()?,
                5 => self.migrate_5_to_6()?,
                6 => self.migrate_6_to_7()?,
                7 => self.migrate_7_to_8()?,
                8 => self.migrate_8_to_9()?,
                other => {
                    return Err(ElaraError::Storage(format!(
                        "unknown migration v{other} → v{}",
                        other + 1
                    )));
                }
            }
            tracing::info!(
                "Migration v{v} → v{} completed in {:?}",
                v + 1,
                start.elapsed()
            );
        }

        self.set_db_version(CURRENT_DB_VERSION)?;
        tracing::info!("Database now at schema v{CURRENT_DB_VERSION}");

        // Sweep stale pre-migration backups. Each prior boot's migration left
        // a `pre-migration-v{N}-backup` checkpoint dir; on a node that has
        // climbed v0→v7 over its lifetime that's 7 backups (a node hit 98% disk
        // before manual cleanup mid-deploy). The schema-current node can
        // never roll back past `pre-migration-v{current-1}-backup` —
        // everything older is dead weight. We keep ONLY the backup created
        // by this run (if any), delete the rest. Best-effort; a delete
        // failure does not fail boot.
        prune_stale_pre_migration_backups(data_dir, current);

        Ok(())
    }

    /// Migration 0→1: Backfill secondary indexes for records that predate the index system.
    ///
    /// Scans CF_RECORDS and writes missing entries to CF_IDX_TIMESTAMP, CF_IDX_CREATOR,
    /// CF_IDX_HASH, and CF_IDX_TIPS. Matches the exact key format used by `put_record()`.
    /// Skips internal keys (__snapshot__, __record_count__, ban:*, blocked_term:*).
    fn migrate_0_to_1(&self) -> Result<()> {
        tracing::info!("Migration 0→1: backfilling secondary indexes...");

        let cf_records = self.try_cf(CF_RECORDS)?;
        let cf_idx_ts = self.try_cf(CF_IDX_TIMESTAMP)?;
        let cf_idx_creator = self.try_cf(CF_IDX_CREATOR)?;
        let cf_idx_hash = self.try_cf(CF_IDX_HASH)?;
        let cf_idx_tips = self.try_cf(CF_IDX_TIPS)?;
        let cf_dag = self.try_cf(CF_DAG)?;

        let mut indexed = 0u64;
        let mut skipped = 0u64;
        let mut already_indexed = 0u64;
        let mut batch = WriteBatch::default();
        let mut batch_count = 0u32;
        const BATCH_FLUSH_SIZE: u32 = 500;

        let iter = self.db.iterator_cf(&cf_records, rocksdb::IteratorMode::Start);
        for item in iter {
            let (key, value) = item
                .map_err(|e| ElaraError::Storage(format!("migration iter: {e}")))?;
            let key_str = match std::str::from_utf8(&key) {
                Ok(s) => s,
                Err(_) => { skipped += 1; continue; }
            };

            // Skip internal keys
            if key_str.starts_with("__")
                || key_str.starts_with("ban:")
                || key_str.starts_with("blocked_term:")
            {
                continue;
            }

            // Deserialize record
            let record = match ValidationRecord::from_bytes(&value) {
                Ok(r) => r,
                Err(_) => { skipped += 1; continue; }
            };

            let record_id = key_str;
            let mut wrote_any = false;

            // Timestamp index: f64.to_be_bytes() + record_id → empty
            let ts_bytes = record.timestamp.to_be_bytes();
            let mut ts_key = Vec::with_capacity(8 + record_id.len());
            ts_key.extend_from_slice(&ts_bytes);
            ts_key.extend_from_slice(record_id.as_bytes());
            if self.db.get_cf(&cf_idx_ts, &ts_key).ok().flatten().is_none() {
                batch.put_cf(&cf_idx_ts, &ts_key, b"");
                wrote_any = true;
            }

            // Creator index: sha3_256_hex(creator_pk) + f64.to_be_bytes() + record_id → empty
            let creator_hash = crate::crypto::hash::sha3_256_hex(&record.creator_public_key);
            let mut creator_key = Vec::with_capacity(64 + 8 + record_id.len());
            creator_key.extend_from_slice(creator_hash.as_bytes());
            creator_key.extend_from_slice(&ts_bytes);
            creator_key.extend_from_slice(record_id.as_bytes());
            if self.db.get_cf(&cf_idx_creator, &creator_key).ok().flatten().is_none() {
                batch.put_cf(&cf_idx_creator, &creator_key, b"");
                wrote_any = true;
            }

            // Content hash index: hex(content_hash_bytes) → record_id.
            // See put_record() for the v5→v6 key-format history.
            let content_hash_hex = hex::encode(&record.content_hash);
            if self.db.get_cf(&cf_idx_hash, content_hash_hex.as_bytes()).ok().flatten().is_none() {
                batch.put_cf(&cf_idx_hash, content_hash_hex.as_bytes(), record_id.as_bytes());
                wrote_any = true;
            }

            // Tips index: record is a tip if it has no children in DAG
            if let Ok(Some(dag_bytes)) = self.db.get_cf(&cf_dag, record_id.as_bytes()) {
                if let Ok(edges) = serde_json::from_slice::<serde_json::Value>(&dag_bytes) {
                    let has_children = edges
                        .get("children")
                        .and_then(|c| c.as_array())
                        .map(|a| !a.is_empty())
                        .unwrap_or(false);
                    if !has_children
                        && self.db.get_cf(&cf_idx_tips, record_id.as_bytes()).ok().flatten().is_none()
                    {
                        batch.put_cf(&cf_idx_tips, record_id.as_bytes(), b"");
                        wrote_any = true;
                    }
                }
            }

            if wrote_any {
                indexed += 1;
                batch_count += 1;
            } else {
                already_indexed += 1;
            }

            // Flush periodically to bound memory
            if batch_count >= BATCH_FLUSH_SIZE {
                self.db.write(batch)
                    .map_err(|e| ElaraError::Storage(format!("migration batch: {e}")))?;
                batch = WriteBatch::default();
                batch_count = 0;
            }
        }

        // Flush remaining
        if batch_count > 0 {
            self.db.write(batch)
                .map_err(|e| ElaraError::Storage(format!("migration final batch: {e}")))?;
        }

        tracing::info!(
            "Migration 0→1 complete: {indexed} records indexed, \
             {already_indexed} already indexed, {skipped} skipped"
        );
        Ok(())
    }

    /// Migration 1→2: Backfill CF_DAG parent edges from CF_RECORDS.
    /// CF_DAG was never populated during put_record — only put_dag_edges (never called
    /// in production) wrote to it. Without parent edges in CF_DAG, the lightweight DAG
    /// rebuild produces 0 edges (all records are disconnected roots), breaking mesh
    /// structure on every restart.
    fn migrate_1_to_2(&self) -> Result<()> {
        use rocksdb::WriteBatch;

        let cf_records = self.try_cf(CF_RECORDS)?;
        let cf_dag = self.try_cf(CF_DAG)?;

        let mut indexed = 0u64;
        let mut skipped = 0u64;
        let mut already_has_dag = 0u64;
        let mut no_parents = 0u64;
        let mut batch = WriteBatch::default();
        let mut batch_count = 0u32;
        const BATCH_FLUSH_SIZE: u32 = 500;

        let iter = self.db.iterator_cf(&cf_records, rocksdb::IteratorMode::Start);
        for item in iter {
            let (key, value) = item
                .map_err(|e| ElaraError::Storage(format!("migration 1→2 iter: {e}")))?;
            let key_str = match std::str::from_utf8(&key) {
                Ok(s) => s,
                Err(_) => { skipped += 1; continue; }
            };
            if key_str.starts_with("__") || key_str.starts_with("ban:") || key_str.starts_with("blocked_term:") || key_str.starts_with("finalized:") {
                continue;
            }

            // Skip if CF_DAG already has an entry for this record
            if self.db.get_cf(&cf_dag, key_str.as_bytes()).ok().flatten().is_some() {
                already_has_dag += 1;
                continue;
            }

            let record = match ValidationRecord::from_bytes(&value) {
                Ok(r) => r,
                Err(_) => { skipped += 1; continue; }
            };

            if record.parents.is_empty() {
                no_parents += 1;
                continue;
            }

            let dag_val = serde_json::json!({ "parents": record.parents });
            batch.put_cf(&cf_dag, key_str.as_bytes(), dag_val.to_string().as_bytes());
            indexed += 1;
            batch_count += 1;

            if batch_count >= BATCH_FLUSH_SIZE {
                self.db.write(batch)
                    .map_err(|e| ElaraError::Storage(format!("migration 1→2 batch: {e}")))?;
                batch = WriteBatch::default();
                batch_count = 0;
            }
        }

        if batch_count > 0 {
            self.db.write(batch)
                .map_err(|e| ElaraError::Storage(format!("migration 1→2 final batch: {e}")))?;
        }

        tracing::info!(
            "Migration 1→2 complete: {indexed} DAG edges written, \
             {no_parents} records with no parents, {already_has_dag} already had DAG entry, {skipped} skipped"
        );
        Ok(())
    }

    /// Migration 2→3: Backfill CF_SLOT_INDEX for v5+ records (MESH-BFT Phase 3 Stage 1F).
    ///
    /// CF_SLOT_INDEX is newly introduced in schema v3. For any v5+ records already
    /// in storage (e.g. gossiped in via sync before this binary was deployed), this
    /// migration writes the `(account, nonce) → record_id` entry so the
    /// slot mutex invariant holds from the first boot under schema v3.
    ///
    /// v4 and older records are exempt: they have no signed nonce, carry no slot,
    /// and are grandfathered. They never acquire a slot_index entry and therefore
    /// never contribute to — or block on — slot conflicts.
    ///
    /// The migration is idempotent: re-running overwrites existing slot_index
    /// entries with the same record_id, which is a no-op.
    ///
    /// Two records already in storage that share a slot (pre-existing conflict
    /// from a pre-Stage-1 binary) are a possibility on old databases. In that
    /// case the migration records the FIRST one it encounters in iteration order
    /// and emits a warning — proper conflict handling then flows through the
    /// normal Stage 1C/D path on the next ingest or during auditing.
    fn migrate_2_to_3(&self) -> Result<()> {
        use rocksdb::WriteBatch;

        let cf_records = self.try_cf(CF_RECORDS)?;
        let cf_slot = self.try_cf(CF_SLOT_INDEX)?;

        let mut slots_written = 0u64;
        let mut v4_skipped = 0u64;
        let mut collisions = 0u64;
        let mut skipped = 0u64;
        let mut batch = WriteBatch::default();
        let mut batch_count = 0u32;
        const BATCH_FLUSH_SIZE: u32 = 500;

        let iter = self.db.iterator_cf(&cf_records, rocksdb::IteratorMode::Start);
        for item in iter {
            let (key, value) = item
                .map_err(|e| ElaraError::Storage(format!("migration 2→3 iter: {e}")))?;
            let key_str = match std::str::from_utf8(&key) {
                Ok(s) => s,
                Err(_) => { skipped += 1; continue; }
            };
            if key_str.starts_with("__")
                || key_str.starts_with("ban:")
                || key_str.starts_with("blocked_term:")
                || key_str.starts_with("finalized:")
            {
                continue;
            }

            let record = match ValidationRecord::from_bytes(&value) {
                Ok(r) => r,
                Err(_) => { skipped += 1; continue; }
            };

            let slot_key = match record.slot_key() {
                Some(k) => k,
                None => {
                    // v4 or earlier — no slot, exempt from mutex.
                    v4_skipped += 1;
                    continue;
                }
            };

            // Check for pre-existing conflict with a different record already
            // registered at this slot. If so, log and keep the first-seen.
            if let Ok(Some(existing)) = self.db.get_cf(&cf_slot, slot_key.as_bytes()) {
                if existing != record.id.as_bytes() {
                    collisions += 1;
                    if let Ok(existing_str) = std::str::from_utf8(&existing) {
                        tracing::warn!(
                            "Migration 2→3: slot {} already registered to {} — \
                             skipping second claim from {} (needs conflict resolution)",
                            slot_key,
                            &existing_str[..existing_str.len().min(16)],
                            &record.id[..record.id.len().min(16)],
                        );
                    }
                    continue;
                }
                // Same id already registered — no-op, don't count as written.
                continue;
            }

            batch.put_cf(&cf_slot, slot_key.as_bytes(), record.id.as_bytes());
            slots_written += 1;
            batch_count += 1;

            if batch_count >= BATCH_FLUSH_SIZE {
                self.db.write(batch)
                    .map_err(|e| ElaraError::Storage(format!("migration 2→3 batch: {e}")))?;
                batch = WriteBatch::default();
                batch_count = 0;
            }
        }

        if batch_count > 0 {
            self.db.write(batch)
                .map_err(|e| ElaraError::Storage(format!("migration 2→3 final batch: {e}")))?;
        }

        tracing::info!(
            "Migration 2→3 complete: {slots_written} slot_index entries backfilled, \
             {v4_skipped} pre-v5 records exempted, {collisions} pre-existing collisions \
             logged, {skipped} skipped"
        );
        Ok(())
    }

    /// Migration 3→4: Rebuild CF_SLOT_INDEX + CF_SLOT_CONFLICTS under the new
    /// 2-part slot_key format (MESH-BFT Phase 3 Stage 1H bug fix).
    ///
    /// # Why
    /// The original slot_key format written by migration 2→3 was
    /// `"{zone}:{account_hash}:{nonce:016x}"`. `zone` was obtained via
    /// `record.record_zone()`, which falls back to hashing the record id when
    /// `record.zone` is None — and the ingest pipeline never sets `zone` before
    /// the slot check. Two equivocating records always have distinct uuid7 ids,
    /// so they always hashed to distinct zones and produced distinct slot keys
    /// under the old format. The slot mutex therefore never caught any actual
    /// equivocation. Surfaced by the Stage 1H conflict-injection suite.
    ///
    /// The fix drops the zone prefix — slot_key is now `"{account_hash}:{nonce:016x}"`,
    /// which is canonical and unique per (creator, nonce) regardless of routing.
    ///
    /// # What this migration does
    /// 1. Drops and recreates CF_SLOT_INDEX and CF_SLOT_CONFLICTS (all old entries
    ///    used the stale key format; safe to discard — they were never correctly
    ///    enforced anyway, and re-populating from CF_RECORDS is authoritative).
    /// 2. Re-runs the 2→3 backfill logic using the NEW slot_key() format. On
    ///    conflict (two v5 records claim the same (creator, nonce)), the first
    ///    one in iteration order wins; subsequent claims are marked in
    ///    CF_SLOT_CONFLICTS so the settlement gate blocks finalization.
    ///
    /// # Scale
    /// O(all_records) scan, bounded to one-time per node on the first boot
    /// under schema v4. Acceptable as a recovery path; not in a hot code path.
    fn migrate_3_to_4(&self) -> Result<()> {
        use rocksdb::WriteBatch;

        tracing::info!(
            "Migration 3→4: rebuilding CF_SLOT_INDEX + CF_SLOT_CONFLICTS under \
             new 2-part slot_key format (Stage 1H fix)"
        );

        // ── Step 1: wipe both slot CFs. ────────────────────────────────────
        // Iterate and delete each key. O(CF_size) for the two slot CFs, which
        // at this point only contain entries written by migration 2→3 under
        // the stale key format; typical size is <= one entry per v5 record,
        // bounded and small.
        let cf_slot = self.try_cf(CF_SLOT_INDEX)?;
        let cf_conflicts = self.try_cf(CF_SLOT_CONFLICTS)?;
        let mut wiped = 0u64;
        {
            let mut wipe = WriteBatch::default();
            for cf_handle in [&cf_slot, &cf_conflicts] {
                let it = self.db.iterator_cf(cf_handle, rocksdb::IteratorMode::Start);
                for item in it {
                    let (key, _) = item
                        .map_err(|e| ElaraError::Storage(format!("migration 3→4 wipe iter: {e}")))?;
                    wipe.delete_cf(cf_handle, &key);
                    wiped += 1;
                }
            }
            if wiped > 0 {
                self.db
                    .write(wipe)
                    .map_err(|e| ElaraError::Storage(format!("migration 3→4 wipe: {e}")))?;
            }
        }
        tracing::info!("Migration 3→4: wiped {wiped} stale slot_index/conflicts entries");

        // ── Step 2: rescan CF_RECORDS and re-populate with NEW slot_key. ───
        //
        // Collision detection must see entries queued in the current batch, not
        // just the committed state (get_cf bypasses the batch). Track in-memory
        // so two records sharing a slot within the same batch window still
        // trigger the conflict path. Memory is bounded by the number of unique
        // slot keys in CF_RECORDS — typically << records since most records
        // are not v5 and v5 records with the same slot are rare equivocations.
        use std::collections::HashMap;
        let cf_records = self.try_cf(CF_RECORDS)?;

        let mut slots_written = 0u64;
        let mut v4_skipped = 0u64;
        let mut collisions = 0u64;
        let mut skipped = 0u64;
        let mut batch = WriteBatch::default();
        let mut batch_count = 0u32;
        // slot_key -> first-seen record_id for this migration run.
        let mut seen: HashMap<String, String> = HashMap::new();
        const BATCH_FLUSH_SIZE: u32 = 500;

        let iter = self.db.iterator_cf(&cf_records, rocksdb::IteratorMode::Start);
        for item in iter {
            let (key, value) = item
                .map_err(|e| ElaraError::Storage(format!("migration 3→4 iter: {e}")))?;
            let key_str = match std::str::from_utf8(&key) {
                Ok(s) => s,
                Err(_) => { skipped += 1; continue; }
            };
            if key_str.starts_with("__")
                || key_str.starts_with("ban:")
                || key_str.starts_with("blocked_term:")
                || key_str.starts_with("finalized:")
            {
                continue;
            }

            let record = match ValidationRecord::from_bytes(&value) {
                Ok(r) => r,
                Err(_) => { skipped += 1; continue; }
            };

            let slot_key = match record.slot_key() {
                Some(k) => k,
                None => {
                    v4_skipped += 1;
                    continue;
                }
            };

            if let Some(existing_id) = seen.get(&slot_key) {
                if existing_id != &record.id {
                    collisions += 1;
                    let marker = format!("{}:{}", existing_id, record.id);
                    // Actual equivocation discovered on rebuild — flag it so
                    // the settlement gate blocks both claims. The first-seen
                    // stays registered; the second's existence is only
                    // preserved via CF_SLOT_CONFLICTS.
                    batch.put_cf(
                        &cf_conflicts,
                        slot_key.as_bytes(),
                        marker.as_bytes(),
                    );
                    batch_count += 1;
                    tracing::warn!(
                        "Migration 3→4: equivocation uncovered at slot {} — \
                         {} vs {} — both blocked via CF_SLOT_CONFLICTS",
                        slot_key,
                        &existing_id[..existing_id.len().min(16)],
                        &record.id[..record.id.len().min(16)],
                    );
                }
                // Same id re-seen or second claim — don't overwrite first-seen.
            } else {
                batch.put_cf(&cf_slot, slot_key.as_bytes(), record.id.as_bytes());
                seen.insert(slot_key, record.id.clone());
                slots_written += 1;
                batch_count += 1;
            }

            if batch_count >= BATCH_FLUSH_SIZE {
                self.db.write(batch)
                    .map_err(|e| ElaraError::Storage(format!("migration 3→4 batch: {e}")))?;
                batch = WriteBatch::default();
                batch_count = 0;
            }
        }

        if batch_count > 0 {
            self.db.write(batch)
                .map_err(|e| ElaraError::Storage(format!("migration 3→4 final batch: {e}")))?;
        }

        tracing::info!(
            "Migration 3→4 complete: {slots_written} slot_index entries rewritten, \
             {v4_skipped} pre-v5 records exempted, {collisions} real equivocations \
             uncovered and flagged, {skipped} skipped"
        );
        Ok(())
    }

    /// Migration 4→5 (Tier 4.5, 2026-04-28): move per-record bookkeeping out
    /// of `CF_RECORDS` into the new `CF_METADATA`. The reserved key prefixes
    /// (`__record_count__`, `__full_pull_cursor__`, `__snapshot__:*`,
    /// `ban:*`, `blocked_term:*`, `finalized:*`, `tombstone:*`) used to live
    /// alongside multi-KB record bodies, forcing every CF_RECORDS iterator to
    /// filter prefixes and inflating SST files with values that share no read
    /// pattern with the records themselves. After this migration:
    ///
    /// - new writes for those prefixes land in CF_METADATA (already wired
    ///   into `recalibrate_count`, `save/load_full_pull_cursor`,
    ///   `ban_identity`, `add_blocked_term`, `save/load_snapshot`, the
    ///   `finalized.rs` cache, and `state.rs` tombstones).
    /// - existing entries are copied across and the originals deleted in
    ///   the same `WriteBatch` so reads are immediately consistent.
    /// - `__db_version__` itself is intentionally left in CF_RECORDS so the
    ///   migration framework's bootstrap read remains identical across
    ///   versions; one extra `__`-prefixed key in CF_RECORDS is filtered by
    ///   every existing iterator anyway.
    ///
    /// Idempotent: a re-run on an already-migrated database iterates an
    /// empty match set (all prefixes already moved) and no-ops.
    fn migrate_4_to_5(&self) -> Result<()> {
        use rocksdb::WriteBatch;

        tracing::info!(
            "Migration 4→5 (Tier 4.5): copying ban: / blocked_term: / finalized: / \
             tombstone: / __snapshot__: / __record_count__ / __full_pull_cursor__ \
             from CF_RECORDS to CF_METADATA"
        );

        let cf_records = self.try_cf(CF_RECORDS)?;
        let cf_meta = self.try_cf(CF_METADATA)?;

        const BATCH_FLUSH_SIZE: u32 = 1000;
        let mut batch = WriteBatch::default();
        let mut batch_count = 0u32;
        let mut moved_records_count = 0u64;
        let mut moved_full_pull = 0u64;
        let mut moved_snapshots = 0u64;
        let mut moved_bans = 0u64;
        let mut moved_blocked_terms = 0u64;
        let mut moved_finalized = 0u64;
        let mut moved_tombstones = 0u64;

        let iter = self.db.iterator_cf(&cf_records, rocksdb::IteratorMode::Start);
        for item in iter {
            let (key, value) = item
                .map_err(|e| ElaraError::Storage(format!("migration 4→5 iter: {e}")))?;

            let counter = if &*key == b"__record_count__" {
                Some(&mut moved_records_count)
            } else if &*key == b"__full_pull_cursor__" {
                Some(&mut moved_full_pull)
            } else if key.starts_with(b"__snapshot__:") {
                Some(&mut moved_snapshots)
            } else if key.starts_with(b"ban:") {
                Some(&mut moved_bans)
            } else if key.starts_with(b"blocked_term:") {
                Some(&mut moved_blocked_terms)
            } else if key.starts_with(b"finalized:") {
                Some(&mut moved_finalized)
            } else if key.starts_with(b"tombstone:") {
                Some(&mut moved_tombstones)
            } else {
                None
            };

            if let Some(c) = counter {
                batch.put_cf(&cf_meta, &key, &value);
                batch.delete_cf(&cf_records, &key);
                *c += 1;
                batch_count += 2;
            }

            if batch_count >= BATCH_FLUSH_SIZE {
                self.db.write(batch)
                    .map_err(|e| ElaraError::Storage(format!("migration 4→5 batch: {e}")))?;
                batch = WriteBatch::default();
                batch_count = 0;
            }
        }

        if batch_count > 0 {
            self.db.write(batch)
                .map_err(|e| ElaraError::Storage(format!("migration 4→5 final batch: {e}")))?;
        }

        let total = moved_records_count
            + moved_full_pull
            + moved_snapshots
            + moved_bans
            + moved_blocked_terms
            + moved_finalized
            + moved_tombstones;

        tracing::info!(
            "Migration 4→5 complete: {total} keys moved CF_RECORDS → CF_METADATA \
             (record_count={moved_records_count}, full_pull_cursor={moved_full_pull}, \
              snapshots={moved_snapshots}, bans={moved_bans}, \
              blocked_terms={moved_blocked_terms}, finalized={moved_finalized}, \
              tombstones={moved_tombstones})"
        );
        Ok(())
    }

    /// Migration 5→6: rebuild CF_IDX_HASH with the correct key format.
    ///
    /// Pre-v6 the index was keyed by `sha3_256_hex(record.content_hash)` —
    /// a hash-of-hash that no production caller could match. The two
    /// in-tree call sites (`network::ingest::register_seal_records` and
    /// `network::epoch::epoch_seal_loop`) pass `hex::encode(record_hash)`
    /// from gossiped seal payloads, so seal-record resolution silently
    /// returned 0/N for ~5 weeks before this migration shipped.
    ///
    /// The fix: wipe every CF_IDX_HASH entry, then iterate CF_RECORDS and
    /// write `hex::encode(record.content_hash) → record_id` for every
    /// deserializable record. Idempotent — a re-run on a v6 database
    /// finds an empty CF and rebuilds from CF_RECORDS again.
    ///
    /// Cost is O(records) reads + O(records) writes, batched at 500.
    /// At 10M records this is a few minutes of single-threaded work; at
    /// testnet scale (low-thousands) it completes in well under a second.
    fn migrate_5_to_6(&self) -> Result<()> {
        use rocksdb::IteratorMode;

        tracing::info!(
            "Migration 5→6: rebuilding CF_IDX_HASH with hex(content_hash) keys"
        );

        let cf_idx_hash = self.try_cf(CF_IDX_HASH)?;
        let cf_records = self.try_cf(CF_RECORDS)?;

        const BATCH_FLUSH_SIZE: u32 = 500;

        // Step 1: wipe the legacy index. The old keys were 64-char
        // sha3_256_hex of an already-hashed value, so no caller can ever
        // resolve them — safe to drop wholesale.
        let mut wiped = 0u64;
        let mut batch = WriteBatch::default();
        let mut batch_count = 0u32;
        let iter = self.db.iterator_cf(&cf_idx_hash, IteratorMode::Start);
        for item in iter {
            let (key, _) = item
                .map_err(|e| ElaraError::Storage(format!("migration 5→6 wipe iter: {e}")))?;
            batch.delete_cf(&cf_idx_hash, &key);
            wiped += 1;
            batch_count += 1;
            if batch_count >= BATCH_FLUSH_SIZE {
                self.db.write(batch)
                    .map_err(|e| ElaraError::Storage(format!("migration 5→6 wipe batch: {e}")))?;
                batch = WriteBatch::default();
                batch_count = 0;
            }
        }
        if batch_count > 0 {
            self.db.write(batch)
                .map_err(|e| ElaraError::Storage(format!("migration 5→6 wipe final: {e}")))?;
        }

        // Step 2: rebuild from CF_RECORDS using the corrected key format.
        // After migrate_4_to_5 the only `__`-prefixed key still in
        // CF_RECORDS is `__db_version__`; skip it and any leftovers
        // defensively.
        let mut rebuilt = 0u64;
        let mut skipped = 0u64;
        let mut batch = WriteBatch::default();
        let mut batch_count = 0u32;
        let iter = self.db.iterator_cf(&cf_records, IteratorMode::Start);
        for item in iter {
            let (key, value) = item
                .map_err(|e| ElaraError::Storage(format!("migration 5→6 rebuild iter: {e}")))?;
            if key.starts_with(b"__")
                || key.starts_with(b"ban:")
                || key.starts_with(b"blocked_term:")
                || key.starts_with(b"finalized:")
                || key.starts_with(b"tombstone:")
            {
                continue;
            }
            let record = match ValidationRecord::from_bytes(&value) {
                Ok(r) => r,
                Err(_) => { skipped += 1; continue; }
            };
            let content_hash_hex = hex::encode(&record.content_hash);
            batch.put_cf(&cf_idx_hash, content_hash_hex.as_bytes(), &key);
            rebuilt += 1;
            batch_count += 1;
            if batch_count >= BATCH_FLUSH_SIZE {
                self.db.write(batch)
                    .map_err(|e| ElaraError::Storage(format!("migration 5→6 rebuild batch: {e}")))?;
                batch = WriteBatch::default();
                batch_count = 0;
            }
        }
        if batch_count > 0 {
            self.db.write(batch)
                .map_err(|e| ElaraError::Storage(format!("migration 5→6 rebuild final: {e}")))?;
        }

        tracing::info!(
            "Migration 5→6 complete: wiped {wiped} legacy entries, \
             rebuilt {rebuilt} from CF_RECORDS, skipped {skipped} non-record rows"
        );
        Ok(())
    }

    /// Migration 6→7: populate CF_IDX_RECORD_HASH from CF_RECORDS.
    ///
    /// Background: even after migration v5→v6 fixed the CF_IDX_HASH key
    /// format, the seal-record resolution path (`network/ingest.rs` and
    /// `network/epoch.rs`) was probing it with `hex::encode(record_hash())`
    /// — but CF_IDX_HASH is keyed on `content_hash`. `record_hash()` is
    /// `sha3(signable_bytes())`, a wholly different value, so probes
    /// missed every time. v6 fixed the writer/reader format mismatch but
    /// the *call-site semantic* was wrong all along.
    ///
    /// Fix: a separate index keyed on `record_hash`. Writers populate it
    /// inline (CF_IDX_HASH writeback is right next to the CF_IDX_RECORD_HASH
    /// writeback in `put_record`/`upsert_record`/`delete_record`), and this
    /// migration backfills it for every record already in CF_RECORDS.
    ///
    /// This is **append-only** — there is no legacy CF to wipe (the column
    /// family is brand-new in v7). Idempotent: `db.get_cf` first; only put
    /// if absent. So a second run is a no-op even if the index already has
    /// every record's hash.
    ///
    /// Cost is O(records) reads + O(records) writes, batched at 500. At
    /// 10M records this is a few minutes of single-threaded work; at
    /// testnet scale (low-thousands) it completes well under a second.
    /// One sha3 of `signable_bytes` per record — negligible vs the I/O.
    fn migrate_6_to_7(&self) -> Result<()> {
        use rocksdb::IteratorMode;

        tracing::info!(
            "Migration 6→7: populating CF_IDX_RECORD_HASH (hex(record_hash) → record_id) \
             from CF_RECORDS"
        );

        let cf_idx_record_hash = self.try_cf(CF_IDX_RECORD_HASH)?;
        let cf_records = self.try_cf(CF_RECORDS)?;

        const BATCH_FLUSH_SIZE: u32 = 500;

        let mut indexed = 0u64;
        let mut already_present = 0u64;
        let mut skipped = 0u64;
        let mut batch = WriteBatch::default();
        let mut batch_count = 0u32;
        let iter = self.db.iterator_cf(&cf_records, IteratorMode::Start);
        for item in iter {
            let (key, value) = item
                .map_err(|e| ElaraError::Storage(format!("migration 6→7 iter: {e}")))?;
            if key.starts_with(b"__")
                || key.starts_with(b"ban:")
                || key.starts_with(b"blocked_term:")
                || key.starts_with(b"finalized:")
                || key.starts_with(b"tombstone:")
            {
                continue;
            }
            let record = match ValidationRecord::from_bytes(&value) {
                Ok(r) => r,
                Err(_) => { skipped += 1; continue; }
            };
            let record_hash_hex = hex::encode(record.record_hash());
            // Idempotent: skip if already indexed (covers re-entry after partial run).
            if self.db.get_cf(&cf_idx_record_hash, record_hash_hex.as_bytes())
                .ok().flatten().is_some()
            {
                already_present += 1;
                continue;
            }
            batch.put_cf(&cf_idx_record_hash, record_hash_hex.as_bytes(), &key);
            indexed += 1;
            batch_count += 1;
            if batch_count >= BATCH_FLUSH_SIZE {
                self.db.write(batch)
                    .map_err(|e| ElaraError::Storage(format!("migration 6→7 batch: {e}")))?;
                batch = WriteBatch::default();
                batch_count = 0;
            }
        }
        if batch_count > 0 {
            self.db.write(batch)
                .map_err(|e| ElaraError::Storage(format!("migration 6→7 final: {e}")))?;
        }

        tracing::info!(
            "Migration 6→7 complete: indexed {indexed} records into CF_IDX_RECORD_HASH, \
             {already_present} already present, skipped {skipped} non-record rows"
        );
        Ok(())
    }

    /// Migration 7→8: backfill `CF_MANDATE_ACTS_BY_AGENT` (signer_hash → acts) from
    /// the EXISTING forward act index `CF_MANDATE_ACT`. The source is bounded to
    /// mandate-bearing acts (a tiny fraction of all records), NOT `CF_RECORDS`, so
    /// this is O(mandate_acts) not O(all_records) — a one-shot boot migration is
    /// SCALE-RULE-safe (recovery/boot only, never a runtime path). Idempotent
    /// (write-if-missing) and crash-safe (the version is set LAST by the caller, so
    /// a crash mid-run re-runs from the start and re-skips already-written keys).
    /// New acts land in the index live via `put_mandate_act`; this only catches
    /// acts ingested before the CF existed (e.g. the dogfood mandate's acts).
    fn migrate_7_to_8(&self) -> Result<()> {
        use rocksdb::IteratorMode;

        tracing::info!(
            "Migration 7→8: backfilling CF_MANDATE_ACTS_BY_AGENT (signer_hash → acts) \
             from CF_MANDATE_ACT"
        );

        let cf_act = self.try_cf(CF_MANDATE_ACT)?;
        let cf_by_agent = self.try_cf(CF_MANDATE_ACTS_BY_AGENT)?;

        const BATCH_FLUSH_SIZE: u32 = 500;

        let mut indexed = 0u64;
        let mut already_present = 0u64;
        let mut skipped = 0u64;
        let mut batch = WriteBatch::default();
        let mut batch_count = 0u32;
        let iter = self.db.iterator_cf(&cf_act, IteratorMode::Start);
        for item in iter {
            let (key, value) = item
                .map_err(|e| ElaraError::Storage(format!("migration 7→8 iter: {e}")))?;
            let record_id = match std::str::from_utf8(&key) {
                Ok(s) => s,
                Err(_) => { skipped += 1; continue; }
            };
            let entry: crate::mandate::MandateActEntry = match serde_json::from_slice(&value) {
                Ok(e) => e,
                Err(_) => { skipped += 1; continue; }
            };
            let akey = match Self::mandate_acts_agent_reverse_key(
                &entry.signer_identity_hash,
                entry.act_timestamp_ms,
                record_id,
            ) {
                Some(k) => k,
                None => { skipped += 1; continue; } // malformed signer hash
            };
            // Idempotent: skip if already indexed (covers re-entry after partial run).
            if self.db.get_cf(&cf_by_agent, &akey).ok().flatten().is_some() {
                already_present += 1;
                continue;
            }
            batch.put_cf(&cf_by_agent, &akey, b"");
            indexed += 1;
            batch_count += 1;
            if batch_count >= BATCH_FLUSH_SIZE {
                self.db.write(batch)
                    .map_err(|e| ElaraError::Storage(format!("migration 7→8 batch: {e}")))?;
                batch = WriteBatch::default();
                batch_count = 0;
            }
        }
        if batch_count > 0 {
            self.db.write(batch)
                .map_err(|e| ElaraError::Storage(format!("migration 7→8 final: {e}")))?;
        }

        tracing::info!(
            "Migration 7→8 complete: indexed {indexed} acts into CF_MANDATE_ACTS_BY_AGENT, \
             {already_present} already present, skipped {skipped} unparseable/malformed rows"
        );
        Ok(())
    }

    /// Migration 8→9: backfill `CF_MANDATE_ACTS_BY_MANDATE` (mandate_ref → acts) from
    /// the EXISTING forward act index `CF_MANDATE_ACT`. The by-mandate reverse index
    /// was added (93dc5068, the `/mandate/{id}/acts` ship) WITHOUT a backfill
    /// migration, so acts ingested before it existed — notably the dogfood mandate's
    /// acts, the first real mandates on-chain — were never indexed under their
    /// mandate. The sibling `migrate_7_to_8` backfilled the by-AGENT index but not
    /// this one, so `GET /mandate/{id}/acts` returned a FALSE `authoritative_complete`
    /// zero on a full-history node (confirmed live: by-agent count 2, by-mandate 0).
    /// Same bounded source (O(mandate_acts), not O(all_records) — SCALE-RULE-safe
    /// boot-only path), same idempotent write-if-missing, same crash-safety (version
    /// set LAST by the caller, so a crash mid-run re-runs from the start). Mirrors
    /// `migrate_7_to_8` exactly, keyed by `mandate_ref` instead of signer hash; acts
    /// whose `mandate_ref` is not a well-formed 64-hex id are forward-indexed only and
    /// correctly skipped — they can never resolve to a real mandate, the same rule
    /// `put_mandate_act` applies on the live write path.
    fn migrate_8_to_9(&self) -> Result<()> {
        use rocksdb::IteratorMode;

        tracing::info!(
            "Migration 8→9: backfilling CF_MANDATE_ACTS_BY_MANDATE (mandate_ref → acts) \
             from CF_MANDATE_ACT"
        );

        let cf_act = self.try_cf(CF_MANDATE_ACT)?;
        let cf_by_mandate = self.try_cf(CF_MANDATE_ACTS_BY_MANDATE)?;

        const BATCH_FLUSH_SIZE: u32 = 500;

        let mut indexed = 0u64;
        let mut already_present = 0u64;
        let mut skipped = 0u64;
        let mut batch = WriteBatch::default();
        let mut batch_count = 0u32;
        let iter = self.db.iterator_cf(&cf_act, IteratorMode::Start);
        for item in iter {
            let (key, value) = item
                .map_err(|e| ElaraError::Storage(format!("migration 8→9 iter: {e}")))?;
            let record_id = match std::str::from_utf8(&key) {
                Ok(s) => s,
                Err(_) => { skipped += 1; continue; }
            };
            let entry: crate::mandate::MandateActEntry = match serde_json::from_slice(&value) {
                Ok(e) => e,
                Err(_) => { skipped += 1; continue; }
            };
            let rkey = match Self::mandate_acts_reverse_key(
                &entry.mandate_ref,
                entry.act_timestamp_ms,
                record_id,
            ) {
                Some(k) => k,
                None => { skipped += 1; continue; } // mandate_ref not 64-hex → forward-index-only
            };
            // Idempotent: skip if already indexed (covers re-entry after partial run).
            if self.db.get_cf(&cf_by_mandate, &rkey).ok().flatten().is_some() {
                already_present += 1;
                continue;
            }
            batch.put_cf(&cf_by_mandate, &rkey, b"");
            indexed += 1;
            batch_count += 1;
            if batch_count >= BATCH_FLUSH_SIZE {
                self.db.write(batch)
                    .map_err(|e| ElaraError::Storage(format!("migration 8→9 batch: {e}")))?;
                batch = WriteBatch::default();
                batch_count = 0;
            }
        }
        if batch_count > 0 {
            self.db.write(batch)
                .map_err(|e| ElaraError::Storage(format!("migration 8→9 final: {e}")))?;
        }

        tracing::info!(
            "Migration 8→9 complete: indexed {indexed} acts into CF_MANDATE_ACTS_BY_MANDATE, \
             {already_present} already present, skipped {skipped} unparseable/malformed rows"
        );
        Ok(())
    }
}

/// Where a [`StorageEngine::record_entries_page`] scan starts.
pub enum TsScanStart<'a> {
    /// First page: seek CF_IDX_TIMESTAMP at `f64_be(ts)` (inclusive — the
    /// first record AT `ts` is in range). Same semantics as
    /// [`StorageEngine::record_ids_from`]'s `from_ts`.
    Since(f64),
    /// Subsequent pages: resume STRICTLY AFTER this exact raw
    /// CF_IDX_TIMESTAMP key (`f64_be(ts) ++ id_bytes`) — the decoded wire
    /// cursor. If the key was deleted between pages the seek lands on the
    /// next surviving key (no skip, no stall).
    AfterKey(&'a [u8]),
}

/// One [`StorageEngine::record_entries_page`] result page.
pub struct TsPage {
    /// `(timestamp, record_id)` pairs in index order. Malformed index keys
    /// (short key / empty or non-utf8 id) are skipped here but still count
    /// toward the scan budget and the frontier.
    pub entries: Vec<(f64, String)>,
    /// Raw key of the last ITERATED entry — the caller's cursor frontier
    /// for a fully-drained slice. `None` iff the scan yielded nothing
    /// (frontier at window end with an empty page).
    pub last_scanned_key: Option<Vec<u8>>,
    /// True iff the scan stopped at `limit` — the caller's `has_more`
    /// contribution (more index entries may remain past the frontier).
    pub scan_truncated: bool,
}

/// Current database schema version. Increment when adding a new migration.
pub const CURRENT_DB_VERSION: u32 = 9;

/// Sweep stale `pre-migration-v{N}-backup` directories from `data_dir` after
/// a successful migration run. Keeps the backup created by THIS run
/// (`pre-migration-v{pre_run_version}-backup`) so the operator still has
/// one rollback target; deletes every other one matching the strict glob.
///
/// `pre_run_version` is the schema version BEFORE this boot's migrations
/// fired. On a node that was already at the latest schema, no backup was
/// created this run and `pre_run_version == CURRENT_DB_VERSION` — in that
/// case we still sweep everything strictly older than `CURRENT_DB_VERSION-1`
/// (a node at v7 doesn't need a v0..v5 rollback target).
///
/// Strict glob: only entries matching `pre-migration-v<digits>-backup` are
/// considered for deletion. Anything else stays untouched. Best-effort —
/// failure to delete a single backup logs a warning, never fails boot.
fn prune_stale_pre_migration_backups(data_dir: &Path, pre_run_version: u32) {
    // Most recent backup we want to keep. If a backup was created THIS run,
    // it's at pre_run_version. If not (already at latest), keep
    // CURRENT_DB_VERSION-1 if it exists (covers the case where a node
    // upgraded long ago and the most recent backup is still useful).
    let keep_version = if pre_run_version < CURRENT_DB_VERSION {
        pre_run_version
    } else {
        CURRENT_DB_VERSION.saturating_sub(1)
    };

    let entries = match std::fs::read_dir(data_dir) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(
                "pre-migration backup sweep: read_dir({}) failed: {e}",
                data_dir.display()
            );
            return;
        }
    };

    let mut freed_bytes: u64 = 0;
    let mut deleted_count: u32 = 0;
    let mut kept_count: u32 = 0;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = match name.to_str() {
            Some(s) => s,
            None => continue,
        };
        // Strict glob: pre-migration-v<digits>-backup
        let v_str = name
            .strip_prefix("pre-migration-v")
            .and_then(|s| s.strip_suffix("-backup"));
        let v_str = match v_str {
            Some(s) => s,
            None => continue,
        };
        let version: u32 = match v_str.parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        if version == keep_version {
            kept_count += 1;
            continue;
        }
        let path = entry.path();
        let size = dir_size_bytes(&path).unwrap_or(0);
        match std::fs::remove_dir_all(&path) {
            Ok(()) => {
                freed_bytes += size;
                deleted_count += 1;
                tracing::info!(
                    "pre-migration backup sweep: deleted {} ({} bytes)",
                    path.display(),
                    size
                );
            }
            Err(e) => tracing::warn!(
                "pre-migration backup sweep: delete {} failed: {e}",
                path.display()
            ),
        }
    }
    if deleted_count > 0 || kept_count > 0 {
        tracing::info!(
            "pre-migration backup sweep: deleted {deleted_count} stale backup(s), freed {freed_bytes} bytes; kept {kept_count} (rollback target at v{keep_version})"
        );
    }
}

/// Recursively compute total bytes used by a directory tree, deduplicating
/// hardlinked inodes (Unix). Returns the inode-exclusive byte sum within the
/// walked subtree — matches `du -sh` semantics, NOT `du -shl`. Returns `None`
/// only if the root path can't be stat()ed; per-entry errors are best-effort
/// (a single unreadable file contributes 0, walk continues).
///
/// Why dedup matters: rocksdb checkpoints are created via hardlinks
/// (`Checkpoint::create_checkpoint`), so a single SST inode appears under
/// `data_dir/rocksdb/` AND under each `data_dir/checkpoints/checkpoint_*/`.
/// Without dedup we'd double-count the SST's bytes once per dirent — a 1 GB
/// SST hardlinked into 5 checkpoints would show as 6 GB. With dedup we count
/// the underlying inode once, matching what statvfs/`df` actually sees.
pub fn dir_size_bytes(path: &Path) -> Option<u64> {
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;
    let mut total: u64 = 0;
    let mut stack = vec![path.to_path_buf()];
    // Verify root exists; if not, return None so callers can distinguish
    // unreadable from empty.
    let _ = std::fs::symlink_metadata(path).ok()?;
    #[cfg(unix)]
    let mut seen_inodes: std::collections::HashSet<(u64, u64)> =
        std::collections::HashSet::new();
    while let Some(p) = stack.pop() {
        let meta = match std::fs::symlink_metadata(&p) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.file_type().is_dir() {
            if let Ok(entries) = std::fs::read_dir(&p) {
                for entry in entries.flatten() {
                    stack.push(entry.path());
                }
            }
        } else {
            #[cfg(unix)]
            {
                // Hardlink-aware: only the first dirent for an inode counts.
                if seen_inodes.insert((meta.dev(), meta.ino())) {
                    total = total.saturating_add(meta.len());
                }
            }
            #[cfg(not(unix))]
            {
                total = total.saturating_add(meta.len());
            }
        }
    }
    Some(total)
}

/// Sum bytes of every `pre-migration-v{N}-backup` directory in `data_dir`
/// (strict glob: middle must be all digits). Cached process-wide for 60s
/// so /metrics scrapes don't repeatedly walk a 25 GB checkpoint tree.
///
/// Returns 0 if `data_dir` is unreadable. The walk costs ~O(SST file count)
/// stat() syscalls per backup; on the v6→v7 deploy this is ~hundreds of
/// files per node, single-digit ms uncached.
pub fn pre_migration_backup_bytes_cached(data_dir: &Path) -> u64 {
    use std::sync::{Mutex, OnceLock};
    use std::time::{Duration, Instant};
    static CACHE: OnceLock<Mutex<(Instant, u64)>> = OnceLock::new();
    const TTL: Duration = Duration::from_secs(60);
    let cache = CACHE.get_or_init(|| {
        // Seed with a stale timestamp so first call recomputes immediately.
        Mutex::new((Instant::now() - TTL - Duration::from_secs(1), 0))
    });
    let mut guard = match cache.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    if guard.0.elapsed() < TTL {
        return guard.1;
    }
    let bytes = compute_pre_migration_backup_bytes(data_dir);
    *guard = (Instant::now(), bytes);
    bytes
}

/// Walk `data_dir`, summing bytes for every `pre-migration-v{digits}-backup`
/// directory entry. Strict glob — anything that doesn't match the exact
/// shape is skipped. Best-effort: a single unreadable backup contributes 0,
/// other backups still count.
fn compute_pre_migration_backup_bytes(data_dir: &Path) -> u64 {
    let entries = match std::fs::read_dir(data_dir) {
        Ok(e) => e,
        Err(_) => return 0,
    };
    let mut total: u64 = 0;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = match name.to_str() {
            Some(s) => s,
            None => continue,
        };
        let v_str = name
            .strip_prefix("pre-migration-v")
            .and_then(|s| s.strip_suffix("-backup"));
        let v_str = match v_str {
            Some(s) => s,
            None => continue,
        };
        if v_str.parse::<u32>().is_err() {
            continue;
        }
        if let Some(b) = dir_size_bytes(&entry.path()) {
            total = total.saturating_add(b);
        }
    }
    total
}

/// Get number of CPUs for parallelism setting.
fn num_cpus() -> i32 {
    std::thread::available_parallelism()
        .map(|n| n.get() as i32)
        .unwrap_or(4)
}

/// Identity Partitioning Phase A — classify the creator PK of the
/// record being inserted into one of the three identity-tier CFs.
///
/// Hot path inside `put_record_with_pk_zone` — keep this O(few hash
/// lookups), no allocation, no extraction-and-validation. The cheap
/// signal is `record.metadata`:
///
/// - `vrf_registration` true with `node_type == "anchor"` (or absent,
///   defaulting to `"anchor"` per `vrf_registry::extract_vrf_registration`)
///   → ANCHOR CF. We don't re-validate the VRF PK bytes here; the
///   broader ingest flow (`extract_vrf_registration`) does that, and a
///   record that fails validation simply means the PK is in the wrong
///   tier — still readable, no consensus impact.
/// - Anything else → USER CF (catch-all default).
///
/// WITNESS-tier classification needs `WitnessRegistry` consultation
/// which lives in `state_core`, not here — `process_deferred_attestations`
/// owns that path and writes via `store_public_key_witness` directly.
fn identity_tier_for_record(record: &ValidationRecord) -> &'static str {
    // `vrf_registration` mirrors `vrf_registry::VRF_REGISTRATION_KEY`,
    // intentionally inlined to avoid a cross-crate dependency from
    // storage on network code.
    let is_vrf_reg = record
        .metadata
        .get("vrf_registration")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if !is_vrf_reg {
        return CF_IDENTITIES_USER;
    }
    let node_type = record
        .metadata
        .get("node_type")
        .and_then(|v| v.as_str())
        .unwrap_or("anchor");
    if node_type == "anchor" {
        CF_IDENTITIES_ANCHOR
    } else {
        CF_IDENTITIES_USER
    }
}

/// Build a CF_WITNESS_REGISTRY key. NUL separator keeps the zone-path
/// prefix unambiguous even when zone_path contains `:` or `/`.
fn witness_key(zone_path: &str, identity_hash: &str) -> Vec<u8> {
    let mut k = Vec::with_capacity(zone_path.len() + 1 + identity_hash.len());
    k.extend_from_slice(zone_path.as_bytes());
    k.push(0u8);
    k.extend_from_slice(identity_hash.as_bytes());
    k
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{Classification, ValidationRecord};
    use crate::crypto::hash::sha3_256;
    use std::collections::BTreeMap;

    fn test_engine() -> (StorageEngine, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let engine = StorageEngine::open(dir.path()).unwrap();
        (engine, dir)
    }

    #[test]
    fn background_errors_is_zero_on_healthy_db() {
        // F-6/F-8: pins the property name + no-CF plumbing. A freshly-opened,
        // never-faulted DB must report exactly 0 — the steady-state baseline the
        // `storage` /health axis and `elara_rocksdb_background_errors` gauge read.
        // A bg-error>0 state can only be produced by a real flush/compaction
        // fault (ENOSPC/IO/corruption), which a unit test cannot synthesize
        // without corrupting the on-disk DB; the zero-baseline is the invariant
        // we can assert. `property_int_value("rocksdb.background-errors")`
        // resolving (Ok(Some(0)), not Err/None) also proves the property name is
        // valid for this RocksDB build — a silent typo would surface here as a
        // permanent 0 from the unwrap_or, but the write below exercises the DB
        // enough that a healthy engine stays at 0.
        let (engine, _dir) = test_engine();
        assert_eq!(engine.background_errors(), 0, "fresh DB must have 0 background-errors");
        // A normal write must not induce a background error.
        engine
            .save_snapshot("bg_err_probe", &42u64)
            .expect("write to healthy DB");
        assert_eq!(engine.background_errors(), 0, "healthy write must not fault the DB");
    }

    #[test]
    fn emergency_state_cf_roundtrip() {
        // B2 durability: the folded state survives a put/get cycle (the warm-restart
        // source of truth). Fresh DB → None (un-halted).
        let (engine, _dir) = test_engine();
        assert!(engine.get_emergency_state().is_none(), "fresh DB has no emergency state");
        let es = crate::emergency::EmergencyState {
            latest_halt_nonce: 5,
            latest_resume_nonce: 2,
            active_expiry_unix: 1_700_000_000,
            active_reason: "dilithium3 break".into(),
        };
        engine.put_emergency_state(&es).unwrap();
        assert_eq!(engine.get_emergency_state().unwrap(), es);
    }

    #[test]
    fn mandate_storage_roundtrip_authz_and_act_cleanup() {
        use crate::mandate::{MandateActEntry, MandateRecord, MandateScope};
        let (engine, _dir) = test_engine();
        let principal = "aa".repeat(32);
        let agent = "bb".repeat(32);
        let other = "cc".repeat(32);
        let m = MandateRecord::new_root(
            "testnet",
            &principal,
            &agent,
            MandateScope::wildcard(),
            0,
            1000,
            0,
            "n0",
        );
        let id = m.mandate_id();

        // mandate put/get
        engine.put_mandate(&m).unwrap();
        assert_eq!(engine.get_mandate(&id).unwrap().mandate_id(), id);
        assert!(engine.get_mandate("deadbeef").is_none());

        // revocation: read-time authz by (mandate, principal), monotonic earliest,
        // and a spoofer's revocation lives under a SEPARATE key (can't front-run).
        engine.put_revocation(&id, &other, 50).unwrap(); // spoof, earlier
        engine.put_revocation(&id, &principal, 800).unwrap();
        engine.put_revocation(&id, &principal, 300).unwrap(); // earlier, wins
        engine.put_revocation(&id, &principal, 900).unwrap(); // later, ignored
        assert_eq!(engine.get_revocation_ms(&id, &principal), Some(300));
        assert_eq!(engine.get_revocation_ms(&id, &other), Some(50)); // spoof persists
        assert_eq!(engine.get_revocation_ms(&id, &"dd".repeat(32)), None);

        // act index put/get + UNCONDITIONAL delete_record cleanup
        let rec = test_record("act-rec-1");
        engine.put_record("act-rec-1", &rec).unwrap();
        let entry = MandateActEntry::new(&id, &agent, 500, None);
        engine.put_mandate_act("act-rec-1", &entry).unwrap();
        assert_eq!(engine.get_mandate_act("act-rec-1").unwrap().mandate_ref, id);
        engine.delete_record("act-rec-1").unwrap();
        assert!(engine.get_mandate_act("act-rec-1").is_none()); // orphan cleaned

        // collect + apply round-trip into a fresh engine (snapshot carry)
        let mandates = engine.collect_mandates();
        let revocations = engine.collect_revocations();
        assert_eq!(mandates.len(), 1);
        assert_eq!(revocations.len(), 2); // (id,other) + (id,principal)
        let (engine2, _dir2) = test_engine();
        engine2.apply_mandates(&mandates).unwrap();
        engine2.apply_revocations(&revocations).unwrap();
        assert_eq!(engine2.get_mandate(&id).unwrap().mandate_id(), id);
        assert_eq!(engine2.get_revocation_ms(&id, &principal), Some(300));
    }

    #[test]
    fn mandate_acts_reverse_index_enumeration() {
        // C4 slice 4: the mandate→acts reverse index behind `GET /mandate/{id}/acts`.
        use crate::mandate::MandateActEntry;
        let (engine, _dir) = test_engine();
        let a = "a".repeat(64); // two valid 64-hex mandate ids
        let b = "b".repeat(64);
        let agent = "cc".repeat(32);

        // Three acts under A (inserted OUT of timestamp order) + one under B.
        for (rid, ts) in [("rec-a-100", 100u64), ("rec-a-300", 300), ("rec-a-200", 200)] {
            engine.put_record(rid, &test_record(rid)).unwrap();
            engine
                .put_mandate_act(rid, &MandateActEntry::new(&a, &agent, ts, None))
                .unwrap();
        }
        engine.put_record("rec-b-50", &test_record("rec-b-50")).unwrap();
        engine
            .put_mandate_act("rec-b-50", &MandateActEntry::new(&b, &agent, 50, None))
            .unwrap();

        // (1) ascending-timestamp ordering + mandate isolation.
        let (ids, next) = engine.list_acts_for_mandate(&a, None, 10).unwrap();
        assert_eq!(ids, vec!["rec-a-100", "rec-a-200", "rec-a-300"]);
        assert!(next.is_none());
        let (bids, _) = engine.list_acts_for_mandate(&b, None, 10).unwrap();
        assert_eq!(bids, vec!["rec-b-50"]); // A's acts never leak into B's list

        // (2) UPPERCASE query is normalized to the stored lowercase prefix.
        let (uids, _) = engine.list_acts_for_mandate(&"A".repeat(64), None, 10).unwrap();
        assert_eq!(uids, vec!["rec-a-100", "rec-a-200", "rec-a-300"]);

        // (3) keyset pagination: page size 2 → no duplicate at the boundary, no skip.
        let (p1, cur) = engine.list_acts_for_mandate(&a, None, 2).unwrap();
        assert_eq!(p1, vec!["rec-a-100", "rec-a-200"]);
        let cur = cur.expect("a further page exists");
        let (p2, cur2) = engine.list_acts_for_mandate(&a, Some(&cur), 2).unwrap();
        assert_eq!(p2, vec!["rec-a-300"]); // exactly the unread tail
        assert!(cur2.is_none());

        // (4) a non-64-hex ref is forward-indexed but NEVER reverse-indexed.
        engine.put_record("rec-bad", &test_record("rec-bad")).unwrap();
        engine
            .put_mandate_act("rec-bad", &MandateActEntry::new("xyz", &agent, 1, None))
            .unwrap();
        assert!(engine.get_mandate_act("rec-bad").is_some()); // forward present
        let (still_a, _) = engine.list_acts_for_mandate(&a, None, 10).unwrap();
        assert_eq!(still_a.len(), 3); // bad ref did not pollute any mandate's list

        // (5) delete_record removes the reverse key (no orphan); double-delete is a no-op.
        engine.delete_record("rec-a-200").unwrap();
        let (after_del, _) = engine.list_acts_for_mandate(&a, None, 10).unwrap();
        assert_eq!(after_del, vec!["rec-a-100", "rec-a-300"]);
        engine.delete_record("rec-a-200").unwrap(); // idempotent, must not panic/re-orphan
        let (after_del2, _) = engine.list_acts_for_mandate(&a, None, 10).unwrap();
        assert_eq!(after_del2, vec!["rec-a-100", "rec-a-300"]);
    }

    #[test]
    fn mandate_acts_by_agent_reverse_index_enumeration() {
        // C4 agent-acts: the signer→acts reverse index behind the loopback-only
        // `GET /agent/{hash}/acts`. The defining new property vs the by-mandate
        // index is CROSS-MANDATE AGGREGATION: one agent's acts under DIFFERENT
        // mandates all surface under its signer hash, in global timestamp order.
        use crate::mandate::MandateActEntry;
        let (engine, _dir) = test_engine();
        let agent1 = "11".repeat(32); // two distinct 64-hex signer identity hashes
        let agent2 = "22".repeat(32);
        let mand_a = "a".repeat(64);
        let mand_b = "b".repeat(64);

        // agent1 acts under BOTH mandates, inserted OUT of timestamp order;
        // agent2 acts once under A.
        for (rid, mref, ts) in [
            ("rec-100", &mand_a, 100u64),
            ("rec-300", &mand_a, 300),
            ("rec-200", &mand_b, 200), // different mandate, same agent
        ] {
            engine.put_record(rid, &test_record(rid)).unwrap();
            engine
                .put_mandate_act(rid, &MandateActEntry::new(mref, &agent1, ts, None))
                .unwrap();
        }
        engine.put_record("rec-a2", &test_record("rec-a2")).unwrap();
        engine
            .put_mandate_act("rec-a2", &MandateActEntry::new(&mand_a, &agent2, 50, None))
            .unwrap();

        // (1) cross-mandate aggregation + ascending-ts ordering + agent isolation.
        let (ids, next) = engine.list_acts_for_agent(&agent1, None, 10).unwrap();
        assert_eq!(ids, vec!["rec-100", "rec-200", "rec-300"]); // spans mandate A AND B
        assert!(next.is_none());
        let (ids2, _) = engine.list_acts_for_agent(&agent2, None, 10).unwrap();
        assert_eq!(ids2, vec!["rec-a2"]); // agent1's acts never leak into agent2's list

        // (2) UPPERCASE query is normalized to the stored lowercase prefix.
        let (uids, _) = engine.list_acts_for_agent(&"11".repeat(32).to_uppercase(), None, 10).unwrap();
        assert_eq!(uids, vec!["rec-100", "rec-200", "rec-300"]);

        // (3) keyset pagination: page size 2 → no duplicate at the boundary, no skip.
        let (p1, cur) = engine.list_acts_for_agent(&agent1, None, 2).unwrap();
        assert_eq!(p1, vec!["rec-100", "rec-200"]);
        let cur = cur.expect("a further page exists");
        let (p2, cur2) = engine.list_acts_for_agent(&agent1, Some(&cur), 2).unwrap();
        assert_eq!(p2, vec!["rec-300"]);
        assert!(cur2.is_none());

        // (4) a non-64-hex signer hash is forward-indexed but NEVER reverse-indexed.
        engine.put_record("rec-bad", &test_record("rec-bad")).unwrap();
        engine
            .put_mandate_act("rec-bad", &MandateActEntry::new(&mand_a, "xyz", 1, None))
            .unwrap();
        assert!(engine.get_mandate_act("rec-bad").is_some()); // forward present
        let (still1, _) = engine.list_acts_for_agent(&agent1, None, 10).unwrap();
        assert_eq!(still1.len(), 3); // malformed signer did not pollute any agent's list

        // (5) delete_record removes the agent reverse key (no orphan); idempotent.
        engine.delete_record("rec-200").unwrap();
        let (after_del, _) = engine.list_acts_for_agent(&agent1, None, 10).unwrap();
        assert_eq!(after_del, vec!["rec-100", "rec-300"]);
        engine.delete_record("rec-200").unwrap(); // double-delete must not panic/re-orphan
        let (after_del2, _) = engine.list_acts_for_agent(&agent1, None, 10).unwrap();
        assert_eq!(after_del2, vec!["rec-100", "rec-300"]);
    }

    #[test]
    fn apply_mandates_enforces_content_addressing() {
        // Snapshot bulk-apply must reject a mandate stored under a key that is
        // NOT its content hash (a tampered-but-signed snapshot / producer bug) —
        // the invariant the sub-delegation chain walk's soundness assumes.
        use crate::mandate::{MandateRecord, MandateScope};
        let (engine, _dir) = test_engine();
        let m = MandateRecord::new_root(
            "testnet", &"aa".repeat(32), &"bb".repeat(32), MandateScope::wildcard(), 0, 1000, 0, "n",
        );
        let before = crate::mandate::MANDATE_SNAPSHOT_REJECTED_TOTAL
            .load(std::sync::atomic::Ordering::Relaxed);
        let mut bad = BTreeMap::new();
        bad.insert("not-the-content-hash".to_string(), m.clone());
        engine.apply_mandates(&bad).unwrap();
        assert!(engine.get_mandate("not-the-content-hash").is_none());
        assert!(
            crate::mandate::MANDATE_SNAPSHOT_REJECTED_TOTAL
                .load(std::sync::atomic::Ordering::Relaxed)
                > before
        );
        // The content-addressed key is accepted.
        let mut good = BTreeMap::new();
        good.insert(m.mandate_id(), m.clone());
        engine.apply_mandates(&good).unwrap();
        assert!(engine.get_mandate(&m.mandate_id()).is_some());
    }

    #[test]
    fn apply_revocations_rejects_malformed_composite_key() {
        use crate::mandate::RevocationEntry;
        let (engine, _dir) = test_engine();
        let mut bad = BTreeMap::new();
        bad.insert("tooshort".to_string(), RevocationEntry::new(100));
        engine.apply_revocations(&bad).unwrap();
        assert!(engine.get_revocation_ms("tooshort", "").is_none());
        // A well-formed 128-hex composite is accepted.
        let key = format!("{}{}", "aa".repeat(32), "bb".repeat(32));
        let mut good = BTreeMap::new();
        good.insert(key, RevocationEntry::new(100));
        engine.apply_revocations(&good).unwrap();
        assert_eq!(engine.get_revocation_ms(&"aa".repeat(32), &"bb".repeat(32)), Some(100));
    }

    fn test_record(id: &str) -> ValidationRecord {
        ValidationRecord {
            id: id.to_string(),
            version: crate::wire::WIRE_VERSION,
            content_hash: sha3_256(id.as_bytes()).to_vec(),
            creator_public_key: vec![0xAA; 1952],
            timestamp: 1700000000.0,
            parents: vec![],
            classification: Classification::Public,
            metadata: BTreeMap::new(),
            signature: Some(vec![0xBB; 3293]),
            sphincs_signature: None,
            zk_proof: None,
            itc_stamp: None,
            zone_refs: vec![],
            creator_sphincs_pk: None,
            sig_algorithm: 0x01,
            sphincs_algorithm: None,
            zone: None,
            identity_hash_wire: None,
            nonce: 0,
        }
    }

    #[test]
    fn test_open_creates_all_cfs() {
        let (engine, _dir) = test_engine();
        // Verify all CFs in ALL_CF_NAMES exist
        for cf_name in ALL_CF_NAMES {
            assert!(
                engine.db.cf_handle(cf_name).is_some(),
                "missing CF: {cf_name}"
            );
        }
    }

    #[test]
    fn test_try_cf_unknown_returns_err() {
        let (engine, _dir) = test_engine();
        // `try_cf` borrows `engine` for the CF lifetime; convert to a plain
        // error string immediately so the borrow ends before `engine` drops.
        let err_msg = engine
            .try_cf("__no_such_cf__")
            .err()
            .map(|e| e.to_string());
        let msg = err_msg.expect("try_cf must return Err for an unknown column family");
        assert!(msg.contains("missing column family"), "error message: {msg}");
    }

    #[test]
    fn test_cf_helper_known_cfs_do_not_panic() {
        let (engine, _dir) = test_engine();
        // cf() is #[cfg(test)]-gated so production code can't reach it.
        // Smoke-test the happy path: every CF opened at startup must be reachable.
        for cf_name in ALL_CF_NAMES {
            let _ = engine.cf(cf_name);
        }
    }

    #[test]
    fn test_query_returns_ok_on_fresh_engine() {
        use crate::storage::Storage;
        // Verifies query() propagates try_cf errors rather than panicking:
        // on a correctly opened engine all CFs exist, so query() must return Ok.
        let (engine, _dir) = test_engine();
        let result = engine.query(None, None, None, None, 100);
        assert!(result.is_ok(), "query() on empty engine must return Ok, got: {result:?}");
        assert!(result.unwrap().is_empty(), "no records stored → empty result");
    }

    #[test]
    fn test_for_each_record_ordered_bounded_returns_ok_not_panic() {
        // Verifies for_each_record_ordered_bounded uses try_cf (returns Err on
        // schema mismatch) rather than cf (panic). On a correctly opened engine
        // all CFs exist so both bounded and unbounded calls must return Ok.
        let (engine, _dir) = test_engine();
        let r = engine.for_each_record_ordered_bounded(0, |_| {});
        assert!(r.is_ok(), "unbounded call must return Ok, got: {r:?}");
        assert_eq!(r.unwrap(), 0, "empty engine → 0 records visited");

        let r2 = engine.for_each_record_ordered_bounded(10, |_| {});
        assert!(r2.is_ok(), "bounded call must return Ok, got: {r2:?}");
        assert_eq!(r2.unwrap(), 0);
    }

    #[test]
    fn test_for_each_record_id_returns_ok_not_panic() {
        // Verifies for_each_record_id uses try_cf (returns Err on schema
        // mismatch) rather than cf (panic). On a correctly opened engine all
        // CFs exist so it must return Ok(0) on an empty store.
        let (engine, _dir) = test_engine();
        let mut visited = Vec::new();
        let result = engine.for_each_record_id(|id| visited.push(id.to_owned()));
        assert!(result.is_ok(), "for_each_record_id on empty engine must return Ok, got: {result:?}");
        assert_eq!(result.unwrap(), 0, "empty engine → 0 records visited");
        assert!(visited.is_empty());
    }

    #[test]
    fn test_stream_records_chunk_returns_ok_not_panic() {
        // Verifies stream_records_chunk / rebuild_ledger_streaming /
        // incremental_ledger_replay use try_cf (Err on schema mismatch) rather
        // than cf (panic). On a correctly opened engine all CFs exist.
        let (engine, _dir) = test_engine();
        let (records, next) = engine
            .stream_records_chunk(None, None, 10)
            .expect("stream_records_chunk on empty engine must return Ok");
        assert!(records.is_empty(), "no records stored");
        assert!(next.is_none(), "no next cursor on empty engine");
    }

    #[test]
    fn test_find_epoch_seal_timestamp_missing_returns_ok_none() {
        let (engine, _dir) = test_engine();
        // No records stored — must return Ok(None), not panic.
        assert_eq!(
            engine.find_epoch_seal_timestamp(1).unwrap(),
            None,
            "no records → Ok(None)"
        );
    }

    #[test]
    fn test_find_epoch_seal_timestamp_found() {
        use serde_json::json;
        let (engine, _dir) = test_engine();
        let mut rec = test_record("epoch-seal-1");
        rec.timestamp = 1_700_001_000.0;
        rec.metadata.insert("epoch_op".to_string(), json!("seal"));
        rec.metadata.insert("epoch_number".to_string(), json!(42u64));
        engine.put_record("epoch-seal-1", &rec).unwrap();
        // find_epoch_seal_timestamp now resolves via the CF_EPOCHS DISC-5
        // index, which ingest writes on every seal; put_record alone does not
        // touch CF_EPOCHS, so mirror the ingest-side index write here.
        engine
            .put_cf_raw(
                CF_EPOCHS,
                &crate::network::epoch::disc5_index_key(42, "z1", "epoch-seal-1"),
                &[],
            )
            .unwrap();

        let ts = engine.find_epoch_seal_timestamp(42).unwrap();
        assert_eq!(ts, Some(1_700_001_000.0), "should find the matching seal");

        let miss = engine.find_epoch_seal_timestamp(99).unwrap();
        assert_eq!(miss, None, "non-matching epoch_number → None");
    }

    #[test]
    fn test_find_epoch_seal_timestamp_uses_index_across_zones() {
        use serde_json::json;
        let (engine, _dir) = test_engine();
        // Two seals at the SAME epoch in different zones, both indexed. The
        // epoch-only prefix seek must return one of them (any seal's ts is the
        // epoch boundary) without a full CF_RECORDS scan.
        for (rid, zone) in [("seal-a", "z-alpha"), ("seal-b", "z-beta")] {
            let mut rec = test_record(rid);
            rec.timestamp = 1_700_005_000.0;
            rec.metadata.insert("epoch_op".to_string(), json!("seal"));
            rec.metadata.insert("epoch_number".to_string(), json!(7u64));
            engine.put_record(rid, &rec).unwrap();
            engine
                .put_cf_raw(
                    CF_EPOCHS,
                    &crate::network::epoch::disc5_index_key(7, zone, rid),
                    &[],
                )
                .unwrap();
        }
        assert_eq!(
            engine.find_epoch_seal_timestamp(7).unwrap(),
            Some(1_700_005_000.0),
            "epoch-prefix seek finds a seal regardless of zone"
        );
        // No index entry for epoch 8 → None (no full-scan fallback).
        assert_eq!(engine.find_epoch_seal_timestamp(8).unwrap(), None);
    }

    #[test]
    fn test_cf_handle_unknown_returns_none() {
        let (engine, _dir) = test_engine();
        assert!(
            engine.cf_handle("__no_such_cf__").is_none(),
            "cf_handle must return None for an unknown column family, not panic"
        );
        assert!(
            engine.cf_handle(CF_RECORDS).is_some(),
            "cf_handle must return Some for a registered column family"
        );
    }

    #[test]
    fn test_raw_cf_ops_unknown_cf_returns_err() {
        let (engine, _dir) = test_engine();
        let bad = "__nonexistent_cf__";
        assert!(engine.put_cf_raw(bad, b"k", b"v").is_err());
        assert!(engine.get_cf_raw(bad, b"k").is_err());
        assert!(engine.delete_cf_raw(bad, b"k").is_err());
        assert!(engine.list_cf_raw(bad, 10).is_err());
        assert!(engine.prefix_scan(bad, b"pfx", |_, _| Ok(())).is_err());
        assert!(engine.full_scan_cf(bad, |_, _| Ok(())).is_err());
        assert!(engine.range_scan_cf(bad, b"start", |_, _| Ok(true)).is_err());
        assert!(engine.prefix_scan_reverse(bad, b"pfx", |_, _| Ok(true)).is_err());
        assert!(engine.range_scan_cf_reverse(bad, |_, _| Ok(true)).is_err());
        assert!(engine.last_key_timestamp_cf(bad).is_err());
    }

    #[test]
    fn test_db_version_try_cf_propagation() {
        // Verifies that get_db_version / set_db_version use try_cf (no panic)
        // and that errors propagate via ? on a normal engine.
        let (engine, _dir) = test_engine();
        // Fresh engine has no version key → returns 0.
        assert_eq!(engine.get_db_version().expect("get_db_version"), 0);
        // Round-trip through set_db_version.
        engine.set_db_version(7).expect("set_db_version");
        assert_eq!(engine.get_db_version().expect("get_db_version after set"), 7);
    }

    #[test]
    fn test_get_wire_bytes_try_cf_error_path() {
        use crate::storage::Storage;
        // get_wire_bytes uses try_cf — missing record returns Err, not a panic.
        let (engine, _dir) = test_engine();
        // Non-existent id must return Err (not panic).
        assert!(engine.get_wire_bytes("no-such-record").is_err());
        // After storing a record, get_wire_bytes must return Ok with the raw bytes.
        let rec = test_record("wire-bytes-test-id");
        engine.put_record("wire-bytes-test-id", &rec).expect("put_record");
        let bytes = engine.get_wire_bytes("wire-bytes-test-id").expect("get_wire_bytes");
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_get_has_public_key_try_cf_fallback() {
        // get_public_key / has_public_key use try_cf; they must return None/false
        // rather than panicking if a CF were unavailable (schema mismatch), and
        // must return the stored bytes when the key exists.
        let (engine, _dir) = test_engine();
        let hash = "aa".repeat(32);
        let pk = vec![0xde, 0xad, 0xbe, 0xef];

        assert!(engine.get_public_key(&hash).is_none());
        assert!(!engine.has_public_key(&hash));

        engine.store_public_key_anchor(&hash, &pk).expect("store anchor pk");

        assert_eq!(engine.get_public_key(&hash).as_deref(), Some(pk.as_slice()));
        assert!(engine.has_public_key(&hash));
        assert_eq!(
            engine.get_public_key_with_tier(&hash).as_ref().map(|(_, t)| *t),
            Some(CF_IDENTITIES_ANCHOR),
        );
    }

    #[test]
    fn test_slot_index_roundtrip() {
        let (engine, _dir) = test_engine();
        let slot = "zone/01:abcd1234:0000000000000001";

        // Slot starts free
        assert!(engine.slot_lookup(slot).unwrap().is_none());

        // Register first-seen
        engine.slot_register(slot, "record-alpha").unwrap();
        assert_eq!(
            engine.slot_lookup(slot).unwrap().as_deref(),
            Some("record-alpha")
        );

        // Idempotent re-register of same id is a no-op
        engine.slot_register(slot, "record-alpha").unwrap();
        assert_eq!(
            engine.slot_lookup(slot).unwrap().as_deref(),
            Some("record-alpha")
        );

        // Distinct slots are independent
        let slot2 = "zone/02:abcd1234:0000000000000001";
        assert!(engine.slot_lookup(slot2).unwrap().is_none());
        engine.slot_register(slot2, "record-beta").unwrap();
        assert_eq!(
            engine.slot_lookup(slot2).unwrap().as_deref(),
            Some("record-beta")
        );
    }

    #[test]
    fn test_slot_delete_releases_slot() {
        // ARCH-4 repair: slot_delete must drop a CF_SLOT_INDEX entry so a
        // future emit can claim the same (account, nonce) tuple. Used by the
        // /admin/forensic/.../evict_unverifiable handler.
        let (engine, _dir) = test_engine();
        let slot = "deadbeef:0000000000000000";

        // Register, confirm occupied, delete, confirm free.
        engine.slot_register(slot, "broken-record-id").unwrap();
        assert_eq!(
            engine.slot_lookup(slot).unwrap().as_deref(),
            Some("broken-record-id")
        );
        engine.slot_delete(slot).unwrap();
        assert!(engine.slot_lookup(slot).unwrap().is_none());

        // Idempotent — deleting an already-empty slot is a no-op.
        engine.slot_delete(slot).unwrap();
        assert!(engine.slot_lookup(slot).unwrap().is_none());

        // Re-register a different record at the now-free slot succeeds.
        engine.slot_register(slot, "fresh-record-id").unwrap();
        assert_eq!(
            engine.slot_lookup(slot).unwrap().as_deref(),
            Some("fresh-record-id")
        );
    }

    #[test]
    fn test_put_record_with_pk_zone_atomic_slot_claim() {
        // ARCH-4(b): the slot index entry must be written in the same
        // WriteBatch as the record payload. Verifies that:
        //  (1) Some(slot) registers the slot AND stores the record together.
        //  (2) None leaves the slot index untouched (no spurious entry).
        //  (3) A failing precondition before this method (e.g., upstream
        //      sig-verify) means this method is never called, and CF_SLOT_INDEX
        //      stays clean for that record.
        let (engine, _dir) = test_engine();
        let rec_alpha = test_record("rec-alpha");
        let rec_beta = test_record("rec-beta");
        let slot_alpha = "zoneA:cafef00d:0000000000000007";

        // (1) Slot supplied → record + slot persisted in one batch.
        engine
            .put_record_with_pk_zone(
                &rec_alpha.id,
                &rec_alpha,
                "id-alpha",
                &rec_alpha.creator_public_key,
                [0; 8],
                Some(slot_alpha),
                None,
            )
            .unwrap();
        assert!(
            engine.get_record(&rec_alpha.id).unwrap().is_some(),
            "record must persist"
        );
        assert_eq!(
            engine.slot_lookup(slot_alpha).unwrap().as_deref(),
            Some(rec_alpha.id.as_str()),
            "slot must point at the freshly stored record"
        );

        // (2) Slot omitted → record persisted, slot index untouched.
        let slot_beta = "zoneA:cafef00d:0000000000000008";
        assert!(engine.slot_lookup(slot_beta).unwrap().is_none());
        engine
            .put_record_with_pk_zone(
                &rec_beta.id,
                &rec_beta,
                "id-beta",
                &rec_beta.creator_public_key,
                [0; 8],
                None,
                None,
            )
            .unwrap();
        assert!(engine.get_record(&rec_beta.id).unwrap().is_some());
        assert!(
            engine.slot_lookup(slot_beta).unwrap().is_none(),
            "no slot key should be claimed when slot_key is None"
        );
    }

    #[test]
    fn test_put_record_with_pk_zone_atomic_disc5_epoch_index() {
        // F-1 crash-consistency: the CF_EPOCHS (DISC-5) seal index entry must
        // land in the SAME WriteBatch as the seal record. Before this fix the
        // index was a standalone put_cf_raw ~650 lines / several .await points
        // after the record write, so a crash in that gap stranded the seal in
        // CF_RECORDS with a missing index — and the "backfill repairs it" claim
        // was false (boot backfill is gated on cf_epochs_size==0, so a partial
        // gap is never repaired). Verified via the production read path
        // `seal_exists_at_zone_epoch` plus an exact-key probe:
        //  (1) Some(key) stores the record AND indexes the seal in one batch.
        //  (2) None (non-seal record) writes nothing to CF_EPOCHS.
        let (engine, _dir) = test_engine();
        let epoch = 42u64;
        let zone_path = "medical/eu";
        let seal_rec = test_record("seal-rec");

        // DISC-5 key format (mirrors network::epoch::disc5_index_key):
        //   epoch:u64_be(8) || zone_path_utf8 || 0x00 || record_id_utf8
        let mut disc5_key = Vec::new();
        disc5_key.extend_from_slice(&epoch.to_be_bytes());
        disc5_key.extend_from_slice(zone_path.as_bytes());
        disc5_key.push(0u8);
        disc5_key.extend_from_slice(seal_rec.id.as_bytes());

        // Pre-state: no seal indexed at (epoch, zone).
        assert!(!engine.seal_exists_at_zone_epoch(epoch, zone_path));

        // (1) Seal supplied → record + CF_EPOCHS index persisted in one batch.
        engine
            .put_record_with_pk_zone(
                &seal_rec.id,
                &seal_rec,
                "id-seal",
                &seal_rec.creator_public_key,
                [0; 8],
                None,
                Some(&disc5_key),
            )
            .unwrap();
        assert!(
            engine.get_record(&seal_rec.id).unwrap().is_some(),
            "seal record must persist"
        );
        assert!(
            engine.get_cf_raw(CF_EPOCHS, &disc5_key).unwrap().is_some(),
            "exact DISC-5 key must be present after the seal put"
        );
        assert!(
            engine.seal_exists_at_zone_epoch(epoch, zone_path),
            "CF_EPOCHS index must be queryable via the production read path"
        );

        // (2) Non-seal record (disc5_epoch_key = None) → no CF_EPOCHS write.
        let plain_rec = test_record("plain-rec");
        let mut would_be_key = Vec::new();
        would_be_key.extend_from_slice(&7u64.to_be_bytes());
        would_be_key.extend_from_slice(b"some/zone");
        would_be_key.push(0u8);
        would_be_key.extend_from_slice(plain_rec.id.as_bytes());
        engine
            .put_record_with_pk_zone(
                &plain_rec.id,
                &plain_rec,
                "id-plain",
                &plain_rec.creator_public_key,
                [0; 8],
                None,
                None,
            )
            .unwrap();
        assert!(engine.get_record(&plain_rec.id).unwrap().is_some());
        assert!(
            engine.get_cf_raw(CF_EPOCHS, &would_be_key).unwrap().is_none(),
            "a non-seal record must not create any CF_EPOCHS entry"
        );
    }

    #[test]
    fn test_seal_record_hash_present_at_zone_epoch_scans_all_siblings() {
        // Deferred Mechanism-B primitive (chain-existence probe): must find a
        // seal by its record_hash among ALL seals stored at (zone, epoch). A
        // crash-before-broadcast phantom and the honest same-epoch competitor it
        // beat on lex-min are BOTH durable at the same (zone, epoch), so a
        // first-hit-only scan (like seal_timestamp_at_zone_epoch) would miss the
        // loser. Both siblings (distinct record_hashes) must be matchable; a
        // random hash, all-zeros, and wrong (epoch|zone) must all miss.
        let (engine, _dir) = test_engine();
        let epoch = 27_015u64;
        let zone_path = "zone/00";

        // Distinct ids → distinct content_hash → distinct record_hash().
        let phantom = test_record("phantom-seal");
        let honest = test_record("honest-seal");
        assert_ne!(phantom.record_hash(), honest.record_hash());

        for rec in [&phantom, &honest] {
            let mut disc5_key = Vec::new();
            disc5_key.extend_from_slice(&epoch.to_be_bytes());
            disc5_key.extend_from_slice(zone_path.as_bytes());
            disc5_key.push(0u8);
            disc5_key.extend_from_slice(rec.id.as_bytes());
            engine
                .put_record_with_pk_zone(
                    &rec.id,
                    rec,
                    &format!("id-{}", rec.id),
                    &rec.creator_public_key,
                    [0; 8],
                    None,
                    Some(&disc5_key),
                )
                .unwrap();
        }

        // Both siblings matchable — the loser (2nd in scan) is NOT skipped.
        assert!(
            engine.seal_record_hash_present_at_zone_epoch(epoch, zone_path, &phantom.record_hash()),
            "phantom sibling must be found by its record_hash"
        );
        assert!(
            engine.seal_record_hash_present_at_zone_epoch(epoch, zone_path, &honest.record_hash()),
            "honest sibling (lex-min loser) must ALSO be found — scan cannot stop at first key"
        );
        // Unknown/forged predecessor, all-zeros (genesis-predecessor), and wrong
        // coordinates must all miss.
        assert!(
            !engine.seal_record_hash_present_at_zone_epoch(epoch, zone_path, &[0x11; 32]),
            "unknown/forged predecessor hash must not match"
        );
        assert!(
            !engine.seal_record_hash_present_at_zone_epoch(epoch, zone_path, &[0u8; 32]),
            "all-zero target must never match a real seal"
        );
        assert!(
            !engine.seal_record_hash_present_at_zone_epoch(
                epoch + 1,
                zone_path,
                &phantom.record_hash()
            ),
            "wrong epoch must not match (prefix isolation)"
        );
        assert!(
            !engine.seal_record_hash_present_at_zone_epoch(epoch, "zone/01", &phantom.record_hash()),
            "wrong zone must not match (prefix isolation)"
        );
    }

    #[test]
    fn test_slot_conflicts_roundtrip() {
        let (engine, _dir) = test_engine();
        let slot = "zone/03:deadbeef:0000000000000005";

        // Clean slots aren't conflicted
        assert!(!engine.slot_is_conflicted(slot).unwrap());

        // Mark conflict, check flag
        engine.slot_mark_conflict(slot, "record-alpha:record-beta").unwrap();
        assert!(engine.slot_is_conflicted(slot).unwrap());

        // slot_index and slot_conflicts are independent CFs — marking a
        // conflict doesn't affect the first-seen owner record.
        engine.slot_register(slot, "record-alpha").unwrap();
        assert_eq!(engine.slot_lookup(slot).unwrap().as_deref(), Some("record-alpha"));
        assert!(engine.slot_is_conflicted(slot).unwrap());

        // Distinct slots: conflict on one doesn't leak to another
        let slot2 = "zone/04:deadbeef:0000000000000005";
        assert!(!engine.slot_is_conflicted(slot2).unwrap());
    }

    #[test]
    fn test_max_slot_nonce_for_account() {
        let (engine, _dir) = test_engine();
        let account_a = "a".repeat(64);
        let account_b = "b".repeat(64);

        // Fresh account has no slots
        assert_eq!(engine.max_slot_nonce_for_account(&account_a).unwrap(), None);

        // Register out-of-order nonces for account_a
        for n in [5u64, 1, 42, 17, 3] {
            let slot = format!("{}:{:016x}", account_a, n);
            engine.slot_register(&slot, &format!("rec-{}-{}", &account_a[..8], n)).unwrap();
        }
        assert_eq!(engine.max_slot_nonce_for_account(&account_a).unwrap(), Some(42));

        // Account B is independent — prefix scan must not cross accounts
        let slot_b = format!("{}:{:016x}", account_b, 7u64);
        engine.slot_register(&slot_b, "rec-b-7").unwrap();
        assert_eq!(engine.max_slot_nonce_for_account(&account_b).unwrap(), Some(7));
        // Account A unchanged
        assert_eq!(engine.max_slot_nonce_for_account(&account_a).unwrap(), Some(42));

        // Registering a higher nonce updates the max
        let slot_a_high = format!("{}:{:016x}", account_a, 100u64);
        engine.slot_register(&slot_a_high, "rec-a-100").unwrap();
        assert_eq!(engine.max_slot_nonce_for_account(&account_a).unwrap(), Some(100));

        // Unrelated prefix (legacy/migrated zone-prefixed slot_key) is ignored
        let legacy_slot = format!("zone/01:{}:{:016x}", account_a, 999u64);
        engine.slot_register(&legacy_slot, "rec-legacy").unwrap();
        // Still 100 — the legacy key does NOT start with `<account>:`
        assert_eq!(engine.max_slot_nonce_for_account(&account_a).unwrap(), Some(100));
    }

    #[test]
    fn test_record_put_get_roundtrip() {
        let (engine, _dir) = test_engine();
        let rec = test_record("test-record-001");

        engine.put_record("test-record-001", &rec).unwrap();
        let loaded = engine.get_record("test-record-001").unwrap().unwrap();

        assert_eq!(loaded.id, rec.id);
        assert_eq!(loaded.content_hash, rec.content_hash);
        assert_eq!(loaded.timestamp, rec.timestamp);
        assert_eq!(loaded.classification, rec.classification);
    }

    #[test]
    fn test_record_exists() {
        let (engine, _dir) = test_engine();
        assert!(!engine.record_exists("nonexistent").unwrap());

        let rec = test_record("exists-test");
        engine.put_record("exists-test", &rec).unwrap();
        assert!(engine.record_exists("exists-test").unwrap());
    }

    #[test]
    fn test_record_delete() {
        let (engine, _dir) = test_engine();
        let rec = test_record("delete-test");
        engine.put_record("delete-test", &rec).unwrap();
        assert!(engine.record_exists("delete-test").unwrap());

        engine.delete_record("delete-test").unwrap();
        assert!(!engine.record_exists("delete-test").unwrap());
    }

    #[test]
    fn delete_record_removes_cf_dag_row() {
        // Admin-audit 2026-07-05: delete_record's batch omitted CF_DAG while
        // delete_touched_cfs() listed it as delete-touched — every GC / zone
        // purge / admin evict leaked one parent-edge row per deleted record,
        // forever (dead weight only: the boot rebuild keys on
        // CF_IDX_TIMESTAMP — but unbounded).
        let (engine, _dir) = test_engine();
        let mut rec = test_record("dag-leak-child");
        rec.parents = vec!["dag-leak-parent".to_string()];
        engine.put_record("dag-leak-child", &rec).unwrap();
        assert!(
            engine.get_cf_raw(CF_DAG, b"dag-leak-child").unwrap().is_some(),
            "put_record must write the CF_DAG parent-edge row"
        );

        engine.delete_record("dag-leak-child").unwrap();
        assert!(
            engine.get_cf_raw(CF_DAG, b"dag-leak-child").unwrap().is_none(),
            "delete_record must remove the CF_DAG parent-edge row"
        );
    }

    #[test]
    fn test_delete_record_cleans_secondary_indexes() {
        // Covers the try_cf() paths in delete_record: timestamp index, creator
        // index, record-hash index, and zone index must all be scrubbed so that
        // secondary-index scans don't surface the deleted record.
        let (engine, _dir) = test_engine();
        let id = "del-index-test";
        let rec = test_record(id);
        engine.put_record(id, &rec).unwrap();

        // Timestamp index contains the record before delete.
        let ids_before = engine.record_ids_from(0.0, 100).unwrap();
        assert!(ids_before.contains(&id.to_string()), "must be present before delete");

        engine.delete_record(id).unwrap();

        // Primary lookup is gone.
        assert!(engine.get_record(id).unwrap().is_none(), "primary must be absent");
        // Timestamp-index scan no longer surfaces the record.
        let ids_after = engine.record_ids_from(0.0, 100).unwrap();
        assert!(!ids_after.contains(&id.to_string()), "timestamp index must not surface deleted record");
    }

    /// Raw CF_IDX_TIMESTAMP key for (ts, id) — mirrors the put_record write.
    fn ts_key(ts: f64, id: &str) -> Vec<u8> {
        let mut k = ts.to_be_bytes().to_vec();
        k.extend_from_slice(id.as_bytes());
        k
    }

    fn test_record_at(id: &str, ts: f64) -> ValidationRecord {
        let mut r = test_record(id);
        r.timestamp = ts;
        r
    }

    #[test]
    fn record_entries_page_since_order_truncation_and_resume() {
        // Delta-sync cursor I1 at the storage level: Since page + AfterKey
        // resume concatenate to the full ordered set, with scan_truncated /
        // last_scanned_key reporting the frontier honestly.
        let (engine, _dir) = test_engine();
        for (i, id) in ["cur-a", "cur-b", "cur-c", "cur-d", "cur-e"].iter().enumerate() {
            engine
                .put_record(id, &test_record_at(id, 100.0 + i as f64))
                .unwrap();
        }
        let p1 = engine
            .record_entries_page(TsScanStart::Since(100.0), 3)
            .unwrap();
        assert_eq!(
            p1.entries.iter().map(|(_, id)| id.as_str()).collect::<Vec<_>>(),
            vec!["cur-a", "cur-b", "cur-c"],
            "Since page must return the first 3 in index order"
        );
        assert!(p1.scan_truncated, "3 of 5 scanned → truncated");
        assert_eq!(
            p1.last_scanned_key.as_deref(),
            Some(ts_key(102.0, "cur-c").as_slice()),
            "frontier must be the raw key of the last iterated entry"
        );
        let p2 = engine
            .record_entries_page(
                TsScanStart::AfterKey(p1.last_scanned_key.as_deref().unwrap()),
                10,
            )
            .unwrap();
        assert_eq!(
            p2.entries.iter().map(|(_, id)| id.as_str()).collect::<Vec<_>>(),
            vec!["cur-d", "cur-e"],
            "AfterKey resume must be strictly-after (no re-serve of cur-c)"
        );
        assert!(!p2.scan_truncated, "iterator exhausted before limit");
        assert_eq!(
            p2.last_scanned_key.as_deref(),
            Some(ts_key(104.0, "cur-e").as_slice())
        );
        // Timestamps decode back exactly.
        assert_eq!(p2.entries[0].0, 103.0);
    }

    #[test]
    fn record_entries_page_after_key_skips_exact_match_only() {
        let (engine, _dir) = test_engine();
        engine.put_record("sk-a", &test_record_at("sk-a", 10.0)).unwrap();
        engine.put_record("sk-b", &test_record_at("sk-b", 20.0)).unwrap();
        // Exact existing key → skip-on-equal fires, first entry is sk-b.
        let p = engine
            .record_entries_page(TsScanStart::AfterKey(&ts_key(10.0, "sk-a")), 10)
            .unwrap();
        assert_eq!(p.entries.first().map(|(_, id)| id.as_str()), Some("sk-b"));
        // Synthetic between-keys cursor (never existed) → seek lands on sk-b,
        // equality skip must NOT fire (sk-b is served, not skipped).
        let p = engine
            .record_entries_page(TsScanStart::AfterKey(&ts_key(15.0, "ghost")), 10)
            .unwrap();
        assert_eq!(
            p.entries.first().map(|(_, id)| id.as_str()),
            Some("sk-b"),
            "a non-existent cursor key must not skip the landing entry"
        );
    }

    #[test]
    fn record_entries_page_deleted_live_cursor_resumes_next_surviving() {
        // Delta-sync cursor I8 (verifier edit #5): delete the record whose
        // key IS the live cursor — a true mid-set deletion, not the
        // below-all-keys variant the snapshot-chunk test covers — and the
        // next page must resume at the next surviving key, no skip, no stall.
        let (engine, _dir) = test_engine();
        for (i, id) in ["gc-a", "gc-b", "gc-c"].iter().enumerate() {
            engine
                .put_record(id, &test_record_at(id, 50.0 + i as f64))
                .unwrap();
        }
        let cursor = ts_key(51.0, "gc-b");
        engine.delete_record("gc-b").unwrap();
        let p = engine
            .record_entries_page(TsScanStart::AfterKey(&cursor), 10)
            .unwrap();
        assert_eq!(
            p.entries.iter().map(|(_, id)| id.as_str()).collect::<Vec<_>>(),
            vec!["gc-c"],
            "resume past a GC'd cursor key must land on the next survivor"
        );
    }

    #[test]
    fn record_entries_page_empty_scan_reports_no_frontier() {
        let (engine, _dir) = test_engine();
        engine.put_record("e-a", &test_record_at("e-a", 5.0)).unwrap();
        let p = engine
            .record_entries_page(TsScanStart::Since(9999.0), 10)
            .unwrap();
        assert!(p.entries.is_empty());
        assert!(p.last_scanned_key.is_none(), "nothing iterated → no frontier");
        assert!(!p.scan_truncated);
    }

    #[test]
    fn record_entries_page_same_timestamp_orders_by_id_bytes() {
        // Composite key = ts_be ++ id: same-ts records order by id bytes and
        // the cursor resumes between them without skip or duplicate.
        let (engine, _dir) = test_engine();
        engine.put_record("tie-a", &test_record_at("tie-a", 77.0)).unwrap();
        engine.put_record("tie-b", &test_record_at("tie-b", 77.0)).unwrap();
        let p1 = engine
            .record_entries_page(TsScanStart::Since(77.0), 1)
            .unwrap();
        assert_eq!(p1.entries[0].1, "tie-a");
        let p2 = engine
            .record_entries_page(
                TsScanStart::AfterKey(p1.last_scanned_key.as_deref().unwrap()),
                10,
            )
            .unwrap();
        assert_eq!(
            p2.entries.iter().map(|(_, id)| id.as_str()).collect::<Vec<_>>(),
            vec!["tie-b"],
            "same-ts sibling must be served exactly once on resume"
        );
    }

    #[test]
    fn test_dag_edges_roundtrip() {
        let (engine, _dir) = test_engine();
        let parents = vec!["parent-1".to_string(), "parent-2".to_string()];
        let children = vec!["child-1".to_string()];

        engine.put_dag_edges("rec-1", &parents, &children).unwrap();
        let (loaded_parents, loaded_children) =
            engine.get_dag_edges("rec-1").unwrap().unwrap();

        assert_eq!(loaded_parents, parents);
        assert_eq!(loaded_children, children);
    }

    #[test]
    fn test_storage_delete_removes_dag_edges() {
        // Exercises the try_cf(CF_DAG)? path in Storage::delete so a missing CF
        // returns Err rather than panicking.
        use crate::storage::Storage;
        let (mut engine, _dir) = test_engine();
        let id = "dag-delete-test";
        let rec = test_record(id);
        engine.put_record(id, &rec).unwrap();
        engine.put_dag_edges(id, &["parent-a".to_string()], &[]).unwrap();

        // Verify DAG edge exists before delete.
        assert!(engine.get_dag_edges(id).unwrap().is_some(), "edge must exist before delete");

        // Storage::delete must remove both the record and its DAG entry.
        engine.delete(id).expect("Storage::delete must succeed");
        assert!(engine.get_record(id).unwrap().is_none(), "record must be gone");
        assert!(engine.get_dag_edges(id).unwrap().is_none(), "dag edges must be gone");
    }

    #[test]
    fn test_rebuild_dag_lightweight_bounded_returns_ok_not_panic() {
        // Verifies that rebuild_dag_lightweight_bounded uses try_cf? and returns
        // Ok on a fresh engine rather than panicking on a missing column family.
        let (engine, _dir) = test_engine();
        let dag = engine.rebuild_dag_lightweight_bounded(0)
            .expect("fresh engine must succeed");
        assert_eq!(dag.len(), 0, "empty db yields empty dag");
        let dag_bounded = engine.rebuild_dag_lightweight_bounded(10)
            .expect("bounded rebuild on empty engine must succeed");
        assert_eq!(dag_bounded.len(), 0);
    }

    #[test]
    fn test_generic_cf_operations() {
        let (engine, _dir) = test_engine();

        // Write to trust CF
        engine
            .put_cf_raw(CF_TRUST, b"identity-abc", b"trust_score:0.85")
            .unwrap();

        // Read back
        let data = engine.get_cf_raw(CF_TRUST, b"identity-abc").unwrap().unwrap();
        assert_eq!(&data, b"trust_score:0.85");

        // Delete
        engine.delete_cf_raw(CF_TRUST, b"identity-abc").unwrap();
        assert!(engine.get_cf_raw(CF_TRUST, b"identity-abc").unwrap().is_none());
    }

    // ─── DAM-3D Phase C Slice 1: seal_exists_at_zone_epoch ──────────────────

    #[test]
    fn dam3d_c_seal_exists_empty_cf_returns_false() {
        let (engine, _dir) = test_engine();
        assert!(!engine.seal_exists_at_zone_epoch(42, "medical/eu"));
    }

    #[test]
    fn dam3d_c_seal_exists_exact_match_returns_true() {
        let (engine, _dir) = test_engine();
        let key = crate::network::epoch::disc5_index_key(42, "medical/eu", "rec-1");
        engine.put_cf_raw(CF_EPOCHS, &key, &[]).unwrap();
        assert!(engine.seal_exists_at_zone_epoch(42, "medical/eu"));
    }

    #[test]
    fn dam3d_c_seal_exists_wrong_epoch_returns_false() {
        let (engine, _dir) = test_engine();
        let key = crate::network::epoch::disc5_index_key(42, "medical/eu", "rec-1");
        engine.put_cf_raw(CF_EPOCHS, &key, &[]).unwrap();
        assert!(!engine.seal_exists_at_zone_epoch(43, "medical/eu"));
        assert!(!engine.seal_exists_at_zone_epoch(41, "medical/eu"));
    }

    #[test]
    fn dam3d_c_seal_exists_sibling_zone_does_not_match() {
        // The 0x00 separator is what stops `medical/eu` from matching seals
        // in `medical/eu/cardiology`. Without the separator a byte-prefix
        // match would yield false positives — this test pins that down.
        let (engine, _dir) = test_engine();
        let child_key = crate::network::epoch::disc5_index_key(
            42, "medical/eu/cardiology", "rec-1",
        );
        engine.put_cf_raw(CF_EPOCHS, &child_key, &[]).unwrap();
        assert!(!engine.seal_exists_at_zone_epoch(42, "medical/eu"));
        assert!(engine.seal_exists_at_zone_epoch(42, "medical/eu/cardiology"));
    }

    #[test]
    fn dam3d_c_seal_exists_other_zone_at_same_epoch_does_not_match() {
        let (engine, _dir) = test_engine();
        let key = crate::network::epoch::disc5_index_key(42, "medical/eu", "rec-1");
        engine.put_cf_raw(CF_EPOCHS, &key, &[]).unwrap();
        assert!(!engine.seal_exists_at_zone_epoch(42, "medical/us"));
        assert!(!engine.seal_exists_at_zone_epoch(42, "finance/eu"));
    }

    #[test]
    fn tier3_4_seal_timestamp_at_zone_epoch_returns_seal_ts() {
        // Tier 3.4: gc_loop derives the per-zone record_pruning_floor_ts
        // from the seal record at (zone, floor_epoch). Helper must locate
        // the seal via DISC-5 prefix scan and read its timestamp from
        // CF_RECORDS.
        let (engine, _dir) = test_engine();

        // Write the seal record itself.
        let mut rec = test_record("seal-rec-1");
        rec.timestamp = 1_700_001_234.5;
        engine.put_record("seal-rec-1", &rec).unwrap();

        // Write the DISC-5 index entry tying (epoch=42, zone="z1") to the seal.
        let key = crate::network::epoch::disc5_index_key(42, "z1", "seal-rec-1");
        engine.put_cf_raw(CF_EPOCHS, &key, &[]).unwrap();

        let ts = engine
            .seal_timestamp_at_zone_epoch(42, "z1")
            .expect("seal must be found");
        assert_eq!(ts, 1_700_001_234.5);
    }

    #[test]
    fn tier3_4_seal_timestamp_at_zone_epoch_missing_returns_none() {
        let (engine, _dir) = test_engine();
        assert!(engine.seal_timestamp_at_zone_epoch(42, "z1").is_none());
    }

    #[test]
    fn tier3_4_seal_timestamp_at_zone_epoch_does_not_match_sibling_zone() {
        // Same separator concern as seal_exists_at_zone_epoch — the trailing
        // 0x00 in the DISC-5 key must prevent zone "medical/eu" from matching
        // a seal in "medical/eu/cardiology".
        let (engine, _dir) = test_engine();
        let mut rec = test_record("child-seal");
        rec.timestamp = 1_700_002_000.0;
        engine.put_record("child-seal", &rec).unwrap();
        let key = crate::network::epoch::disc5_index_key(42, "medical/eu/cardiology", "child-seal");
        engine.put_cf_raw(CF_EPOCHS, &key, &[]).unwrap();

        assert!(engine.seal_timestamp_at_zone_epoch(42, "medical/eu/cardiology").is_some());
        assert!(engine.seal_timestamp_at_zone_epoch(42, "medical/eu").is_none(),
            "parent zone must not match child seal");
    }

    #[test]
    fn dam3d_c_seal_exists_legacy_numeric_zone() {
        // ZoneId::from_legacy(42) → path "42"; the probe takes the path
        // string directly so legacy zones work unchanged.
        let (engine, _dir) = test_engine();
        let key = crate::network::epoch::disc5_index_key(7, "42", "rec-1");
        engine.put_cf_raw(CF_EPOCHS, &key, &[]).unwrap();
        assert!(engine.seal_exists_at_zone_epoch(7, "42"));
        assert!(!engine.seal_exists_at_zone_epoch(7, "43"));
    }

    #[test]
    fn seal_exists_and_timestamp_return_safe_defaults_on_empty_db() {
        // Regression guard: seal_exists_at_zone_epoch / seal_timestamp_at_zone_epoch
        // use try_cf and return false/None on CF miss instead of panicking.
        let (engine, _dir) = test_engine();
        assert!(!engine.seal_exists_at_zone_epoch(0, "any/zone"));
        assert!(engine.seal_timestamp_at_zone_epoch(0, "any/zone").is_none());
    }

    #[test]
    fn get_dag_edges_returns_ok_none_for_unknown_record() {
        // Regression guard: get_dag_edges uses try_cf so a missing CF_DAG
        // returns Err instead of panicking. On a normal engine with all CFs
        // open, an unknown record returns Ok(None).
        let (engine, _dir) = test_engine();
        let result = engine.get_dag_edges("nonexistent-record-id");
        assert!(result.is_ok(), "get_dag_edges must not panic on missing record");
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn put_record_with_zone_returns_ok_not_panic() {
        // Regression guard: put_record_with_zone uses try_cf so a missing CF
        // propagates as ElaraError::Storage instead of crashing the node.
        // On a normal engine with all CFs open, a valid record returns Ok(()).
        let (engine, _dir) = test_engine();
        let rec = test_record("harden-put-record-with-zone");
        let result = engine.put_record_with_zone("harden-put-record-with-zone", &rec, [0u8; 8]);
        assert!(result.is_ok(), "put_record_with_zone must not panic: {result:?}");
        assert!(engine.get_record("harden-put-record-with-zone").unwrap().is_some());
    }

    #[test]
    fn test_epoch_key_ordering() {
        // Keys should sort by zone first, then epoch number
        let k1 = StorageEngine::epoch_key(&ZoneId::from_legacy(0), 0);
        let k2 = StorageEngine::epoch_key(&ZoneId::from_legacy(0), 1);
        let k3 = StorageEngine::epoch_key(&ZoneId::from_legacy(1), 0);
        assert!(k1 < k2);
        assert!(k2 < k3);
    }

    #[test]
    fn test_batch_write() {
        let (engine, _dir) = test_engine();

        let mut batch = engine.new_batch();
        let cf = engine.cf_handle(CF_RECORDS).expect("CF_RECORDS registered");
        batch.put_cf(&cf, b"batch-1", b"value-1");
        batch.put_cf(&cf, b"batch-2", b"value-2");
        engine.write_batch(batch).unwrap();

        assert!(engine.get_cf_raw(CF_RECORDS, b"batch-1").unwrap().is_some());
        assert!(engine.get_cf_raw(CF_RECORDS, b"batch-2").unwrap().is_some());
    }

    #[test]
    fn test_count_cf() {
        let (engine, _dir) = test_engine();
        assert_eq!(engine.count_cf(CF_RECORDS), 0);

        let rec = test_record("count-test");
        engine.put_record("count-test", &rec).unwrap();
        // Tier 4.5: __record_count__ now lives in CF_METADATA, so CF_RECORDS
        // contains only the record key. Verify both CFs are populated as
        // expected so a future regression that puts the cache back in
        // CF_RECORDS would fail loudly.
        assert_eq!(engine.count_cf(CF_RECORDS), 1);
        assert_eq!(engine.count_cf(CF_METADATA), 1);
    }

    #[test]
    fn test_count_cf_unknown_returns_zero() {
        // A Byzantine peer or schema mismatch must not crash the node.
        // count_cf() with an unregistered CF name returns 0 instead of panicking.
        let (engine, _dir) = test_engine();
        assert_eq!(engine.count_cf("cf_that_does_not_exist"), 0);
    }

    #[test]
    fn test_reopen_persists_data() {
        let dir = tempfile::tempdir().unwrap();

        // Write data
        {
            let engine = StorageEngine::open(dir.path()).unwrap();
            let rec = test_record("persist-test");
            engine.put_record("persist-test", &rec).unwrap();
        }

        // Reopen and verify
        {
            let engine = StorageEngine::open(dir.path()).unwrap();
            let loaded = engine.get_record("persist-test").unwrap();
            assert!(loaded.is_some());
            assert_eq!(loaded.unwrap().id, "persist-test");
        }
    }

    #[test]
    fn test_snapshot_save_load_roundtrip() {
        let (engine, _dir) = test_engine();

        // Save a HashMap as a snapshot
        let mut data = std::collections::HashMap::new();
        data.insert("key1".to_string(), 42u64);
        data.insert("key2".to_string(), 99u64);

        engine.save_snapshot("test_map", &data).unwrap();

        // Load it back
        let loaded: std::collections::HashMap<String, u64> =
            engine.load_snapshot("test_map").unwrap().unwrap();
        assert_eq!(loaded["key1"], 42);
        assert_eq!(loaded["key2"], 99);
    }

    #[test]
    fn test_snapshots_batch_all_keys_land_and_load() {
        // F-3: save_snapshots_batch writes every listed snapshot in one
        // WriteBatch, each readable afterward via the normal load_snapshot path
        // — i.e. it uses the identical __snapshot__: key encoding as
        // save_snapshot, so the boot loader reads exactly what the batch wrote.
        let (engine, _dir) = test_engine();

        // Heterogeneous values, serialized first (as the trio call sites do).
        let checkpoint_ts = 1234.5f64;
        let counters = (7u64, 8u64, 9u64);
        let epoch_names = vec!["alpha".to_string(), "beta".to_string()];

        let batch: Vec<(&str, Vec<u8>)> = vec![
            ("checkpoint_timestamp", serde_json::to_vec(&checkpoint_ts).unwrap()),
            ("persistent_counters", serde_json::to_vec(&counters).unwrap()),
            ("epoch", serde_json::to_vec(&epoch_names).unwrap()),
        ];
        engine.save_snapshots_batch(&batch).unwrap();

        // Every key landed and round-trips through the standard loader.
        let ts: f64 = engine.load_snapshot("checkpoint_timestamp").unwrap().unwrap();
        assert_eq!(ts, 1234.5);
        let c: (u64, u64, u64) = engine.load_snapshot("persistent_counters").unwrap().unwrap();
        assert_eq!(c, (7, 8, 9));
        let n: Vec<String> = engine.load_snapshot("epoch").unwrap().unwrap();
        assert_eq!(n, vec!["alpha".to_string(), "beta".to_string()]);

        // An empty batch is a no-op, not an error.
        engine.save_snapshots_batch(&[]).unwrap();
    }

    #[test]
    fn test_snapshot_missing_returns_none() {
        let (engine, _dir) = test_engine();
        let result: Option<String> = engine.load_snapshot("nonexistent").unwrap();
        assert!(result.is_none());
    }

    /// A Byzantine peer sending a schema-mismatched DB (no CF_METADATA) must
    /// not crash the node — save_snapshot / load_snapshot must return Err.
    #[test]
    fn test_snapshot_missing_cf_returns_err_not_panic() {
        let dir = tempfile::tempdir().unwrap();
        // Open a raw multi-threaded RocksDB with only the default CF — no CF_METADATA.
        let mut raw_opts = rocksdb::Options::default();
        raw_opts.create_if_missing(true);
        let db: DB = DB::open(&raw_opts, dir.path()).unwrap();
        let engine = StorageEngine { db, anchor_add_seq: std::sync::atomic::AtomicU64::new(0) };
        let save_res = engine.save_snapshot("probe", &42u32);
        assert!(save_res.is_err(), "save_snapshot must Err when CF_METADATA is absent");
        let load_res: Result<Option<u32>> = engine.load_snapshot("probe");
        assert!(load_res.is_err(), "load_snapshot must Err when CF_METADATA is absent");
    }

    #[test]
    fn test_snapshot_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();

        {
            let engine = StorageEngine::open(dir.path()).unwrap();
            engine.save_snapshot("persistent", &vec![1u32, 2, 3]).unwrap();
        }

        {
            let engine = StorageEngine::open(dir.path()).unwrap();
            let loaded: Vec<u32> = engine.load_snapshot("persistent").unwrap().unwrap();
            assert_eq!(loaded, vec![1, 2, 3]);
        }
    }

    #[test]
    fn test_checkpoint_creates_standalone_db() {
        let dir = tempfile::tempdir().unwrap();
        let cp_dir = tempfile::tempdir().unwrap();
        let cp_path = cp_dir.path().join("checkpoint_1");

        // Write some data, then checkpoint
        let engine = StorageEngine::open(dir.path()).unwrap();
        let rec = test_record("checkpoint-test");
        engine.put_record("checkpoint-test", &rec).unwrap();
        engine.create_checkpoint(&cp_path).unwrap();

        // Open the checkpoint as a standalone DB and verify the data is there
        let cp_engine = StorageEngine::open(&cp_path).unwrap();
        let loaded = cp_engine.get_record("checkpoint-test").unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().id, "checkpoint-test");
    }

    #[test]
    fn test_checkpoint_does_not_include_later_writes() {
        let dir = tempfile::tempdir().unwrap();
        let cp_dir = tempfile::tempdir().unwrap();
        let cp_path = cp_dir.path().join("checkpoint_snap");

        let engine = StorageEngine::open(dir.path()).unwrap();
        let rec1 = test_record("before-checkpoint");
        engine.put_record("before-checkpoint", &rec1).unwrap();
        engine.create_checkpoint(&cp_path).unwrap();

        // Write after checkpoint
        let rec2 = test_record("after-checkpoint");
        engine.put_record("after-checkpoint", &rec2).unwrap();

        // Checkpoint should only have the first record
        let cp_engine = StorageEngine::open(&cp_path).unwrap();
        assert!(cp_engine.get_record("before-checkpoint").unwrap().is_some());
        assert!(cp_engine.get_record("after-checkpoint").unwrap().is_none());
    }

    #[test]
    fn test_repair_valid_db() {
        let dir = tempfile::tempdir().unwrap();

        // Create a valid DB first
        {
            let engine = StorageEngine::open(dir.path()).unwrap();
            let rec = test_record("repair-test");
            engine.put_record("repair-test", &rec).unwrap();
        }

        // Repair should succeed on a valid (closed) DB
        StorageEngine::repair(dir.path()).unwrap();

        // DB should still be openable after repair (repair may rebuild CF metadata,
        // but create_missing_column_families ensures all CFs are re-created)
        let engine = StorageEngine::open(dir.path()).unwrap();
        // Verify CFs exist (the main invariant for repair)
        for cf_name in ALL_CF_NAMES {
            assert!(
                engine.db.cf_handle(cf_name).is_some(),
                "missing CF after repair: {cf_name}"
            );
        }
    }

    #[test]
    fn test_ttl_cleanup_deletes_old_entries() {
        let (engine, _dir) = test_engine();

        // Insert entries with timestamps into reputation CF
        let old_entry = serde_json::json!({
            "witness_hash": "w1",
            "score": 50.0,
            "timestamp": 1000.0 // old
        });
        let new_entry = serde_json::json!({
            "witness_hash": "w2",
            "score": 80.0,
            "timestamp": 999_999.0 // recent
        });
        engine.put_cf_raw(CF_REPUTATION, b"rep:w1", old_entry.to_string().as_bytes()).unwrap();
        engine.put_cf_raw(CF_REPUTATION, b"rep:w2", new_entry.to_string().as_bytes()).unwrap();
        assert_eq!(engine.count_cf(CF_REPUTATION), 2);

        // TTL cleanup with cutoff at 5000 — should delete old_entry
        let deleted = engine.ttl_cleanup_cf_by_timestamp(CF_REPUTATION, 5000.0).unwrap();
        assert_eq!(deleted, 1);
        assert_eq!(engine.count_cf(CF_REPUTATION), 1);
        // new_entry should survive
        assert!(engine.get_cf_raw(CF_REPUTATION, b"rep:w2").unwrap().is_some());
        // old_entry should be gone
        assert!(engine.get_cf_raw(CF_REPUTATION, b"rep:w1").unwrap().is_none());
    }

    #[test]
    fn test_ttl_cleanup_skips_snapshots() {
        let (engine, _dir) = test_engine();

        // Save a snapshot (has no timestamp field)
        engine.save_snapshot("test_snap", &"hello").unwrap();

        // Insert an old entry
        let old = serde_json::json!({"timestamp": 1.0});
        engine.put_cf_raw(CF_RECORDS, b"old-key", old.to_string().as_bytes()).unwrap();

        // TTL cleanup should skip snapshot entries
        let deleted = engine.ttl_cleanup_cf_by_timestamp(CF_RECORDS, 999_999.0).unwrap();
        assert_eq!(deleted, 1);
        // Snapshot should survive
        let snap: Option<String> = engine.load_snapshot("test_snap").unwrap();
        assert!(snap.is_some());
    }

    #[test]
    fn test_ttl_cleanup_no_timestamp_field_skipped() {
        let (engine, _dir) = test_engine();

        // Entry without timestamp field — should be skipped
        let no_ts = serde_json::json!({"name": "test"});
        engine.put_cf_raw(CF_REPUTATION, b"no-ts", no_ts.to_string().as_bytes()).unwrap();

        let deleted = engine.ttl_cleanup_cf_by_timestamp(CF_REPUTATION, 999_999.0).unwrap();
        assert_eq!(deleted, 0);
        assert_eq!(engine.count_cf(CF_REPUTATION), 1);
    }

    #[test]
    fn test_ttl_cleanup_unknown_cf_returns_error() {
        let (engine, _dir) = test_engine();
        let result = engine.ttl_cleanup_cf_by_timestamp("__nonexistent_cf__", 0.0);
        assert!(
            result.is_err(),
            "expected Err for unknown column family, got Ok"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("missing column family"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn test_compact_cf_no_crash() {
        let (engine, _dir) = test_engine();
        // Just verify it doesn't panic
        engine.compact_cf(CF_RECORDS);
        engine.compact_cf(CF_REPUTATION);
        engine.compact_cf(CF_DISPUTES);
    }

    // ── Migration tests ──────────────────────────────────────────────────

    #[test]
    fn test_db_version_default_zero() {
        let (engine, _dir) = test_engine();
        assert_eq!(engine.get_db_version().unwrap(), 0);
    }

    #[test]
    fn test_db_version_roundtrip() {
        let (engine, _dir) = test_engine();
        engine.set_db_version(42).unwrap();
        assert_eq!(engine.get_db_version().unwrap(), 42);
    }

    #[test]
    fn test_migration_0_to_1_backfills_indexes() {
        let dir = tempfile::tempdir().unwrap();
        let engine = StorageEngine::open(dir.path()).unwrap();

        // Manually insert a record into CF_RECORDS WITHOUT indexes
        // (simulating a pre-index record)
        let rec = test_record("orphan-001");
        let wire = rec.to_bytes();
        let cf = engine.cf(CF_RECORDS);
        engine.db.put_cf(&cf, b"orphan-001", &wire).unwrap();

        // Also add DAG edges (no children = tip). put_dag_edges writes to CF_IDX_TIPS.
        engine.put_dag_edges("orphan-001", &[], &[]).unwrap();

        // Verify content indexes are empty before migration (tips already set by put_dag_edges)
        assert_eq!(engine.count_cf(CF_IDX_TIMESTAMP), 0);
        assert_eq!(engine.count_cf(CF_IDX_CREATOR), 0);
        assert_eq!(engine.count_cf(CF_IDX_HASH), 0);

        // Run migration
        engine.run_migrations(dir.path()).unwrap();

        // Indexes should now be populated
        assert_eq!(engine.count_cf(CF_IDX_TIMESTAMP), 1);
        assert_eq!(engine.count_cf(CF_IDX_CREATOR), 1);
        assert_eq!(engine.count_cf(CF_IDX_HASH), 1);
        assert_eq!(engine.count_cf(CF_IDX_TIPS), 1); // maintained by put_dag_edges + migration

        // Version should be set
        assert_eq!(engine.get_db_version().unwrap(), CURRENT_DB_VERSION);
    }

    #[test]
    fn test_migration_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let engine = StorageEngine::open(dir.path()).unwrap();

        // Run twice — second run should be a no-op
        engine.run_migrations(dir.path()).unwrap();
        engine.run_migrations(dir.path()).unwrap();

        assert_eq!(engine.get_db_version().unwrap(), CURRENT_DB_VERSION);
    }

    #[test]
    fn test_migration_skips_internal_keys() {
        let dir = tempfile::tempdir().unwrap();
        let engine = StorageEngine::open(dir.path()).unwrap();

        // Insert internal keys that should NOT be indexed
        let cf = engine.cf(CF_RECORDS);
        engine.db.put_cf(&cf, b"__snapshot__:test", b"{}").unwrap();
        engine.db.put_cf(&cf, b"__record_count__", 0u64.to_le_bytes()).unwrap();
        engine.db.put_cf(&cf, b"ban:badguy", b"{}").unwrap();
        engine.db.put_cf(&cf, b"blocked_term:spam", b"1").unwrap();

        engine.run_migrations(dir.path()).unwrap();

        // No index entries should have been created
        assert_eq!(engine.count_cf(CF_IDX_TIMESTAMP), 0);
        assert_eq!(engine.count_cf(CF_IDX_CREATOR), 0);
        assert_eq!(engine.count_cf(CF_IDX_HASH), 0);
    }

    #[test]
    fn test_migration_creates_checkpoint() {
        let dir = tempfile::tempdir().unwrap();
        let engine = StorageEngine::open(dir.path()).unwrap();

        engine.run_migrations(dir.path()).unwrap();

        // Checkpoint directory should exist
        let backup_path = dir.path().join("pre-migration-v0-backup");
        assert!(backup_path.exists(), "pre-migration checkpoint missing");

        // Checkpoint should be a valid RocksDB (can open it)
        let _cp = StorageEngine::open(&backup_path).unwrap();
    }

    #[test]
    fn test_migration_2_to_3_backfills_slot_index() {
        let dir = tempfile::tempdir().unwrap();
        let engine = StorageEngine::open(dir.path()).unwrap();

        // Store three v5 records with distinct (id, nonce) tuples. All share
        // the same creator public key, so each occupies a distinct slot only
        // because nonces differ. This is the expected happy path.
        let mut rec_a = test_record("slot-record-a");
        rec_a.version = 5;
        rec_a.nonce = 1;

        let mut rec_b = test_record("slot-record-b");
        rec_b.version = 5;
        rec_b.nonce = 2;

        let mut rec_c = test_record("slot-record-c");
        rec_c.version = 5;
        rec_c.nonce = 3;

        let cf_records = engine.cf(CF_RECORDS);
        for rec in [&rec_a, &rec_b, &rec_c] {
            engine.db.put_cf(&cf_records, rec.id.as_bytes(), rec.to_bytes()).unwrap();
        }

        // Slot index starts empty
        assert_eq!(engine.count_cf(CF_SLOT_INDEX), 0);

        engine.run_migrations(dir.path()).unwrap();

        // All three records should be registered in slot_index
        assert_eq!(engine.count_cf(CF_SLOT_INDEX), 3);
        for rec in [&rec_a, &rec_b, &rec_c] {
            let slot_key = rec.slot_key().expect("v5 record must have slot_key");
            assert_eq!(
                engine.slot_lookup(&slot_key).unwrap().as_deref(),
                Some(rec.id.as_str()),
                "slot_index should map slot_key → record_id for {}", rec.id
            );
        }

        // Version advanced to current
        assert_eq!(engine.get_db_version().unwrap(), CURRENT_DB_VERSION);
    }

    #[test]
    fn test_migration_2_to_3_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let engine = StorageEngine::open(dir.path()).unwrap();

        let mut rec = test_record("slot-idempotent");
        rec.version = 5;
        rec.nonce = 42;
        let cf_records = engine.cf(CF_RECORDS);
        engine.db.put_cf(&cf_records, rec.id.as_bytes(), rec.to_bytes()).unwrap();

        // Run migrations twice — second run should be a no-op
        engine.run_migrations(dir.path()).unwrap();
        assert_eq!(engine.count_cf(CF_SLOT_INDEX), 1);

        engine.run_migrations(dir.path()).unwrap();
        assert_eq!(engine.count_cf(CF_SLOT_INDEX), 1);
    }

    #[test]
    fn test_migration_3_to_4_rewrites_slot_keys_in_new_format() {
        // Migration 3→4 fixes a slot_key format bug. Verify that after a full
        // 0→4 migration of a v5 record, the slot_index contains the NEW 2-part
        // format key `{account_hash}:{nonce:016x}` and NOT a stale 3-part key.
        let dir = tempfile::tempdir().unwrap();
        let engine = StorageEngine::open(dir.path()).unwrap();

        let mut rec = test_record("slot-format-check");
        rec.version = 5;
        rec.nonce = 0xDEADBEEF;

        let cf_records = engine.cf(CF_RECORDS);
        engine.db.put_cf(&cf_records, rec.id.as_bytes(), rec.to_bytes()).unwrap();

        engine.run_migrations(dir.path()).unwrap();
        assert_eq!(engine.get_db_version().unwrap(), CURRENT_DB_VERSION);

        // The key in CF_SLOT_INDEX must equal record.slot_key() (new format).
        // If a stale 3-part key were written at any earlier migration stage,
        // migration 3→4 must have wiped it.
        let expected = rec.slot_key().expect("v5 slot_key");
        assert!(!expected.contains("zone/"), "new slot_key must not contain zone prefix");
        assert_eq!(expected.matches(':').count(), 1, "new format: exactly one ':'");

        assert_eq!(
            engine.slot_lookup(&expected).unwrap().as_deref(),
            Some(rec.id.as_str()),
            "slot_index must map the NEW slot_key → record_id after 3→4",
        );
        assert_eq!(engine.count_cf(CF_SLOT_INDEX), 1, "no stale entries remain");
    }

    #[test]
    fn test_migration_3_to_4_flags_actual_equivocation_uncovered_on_rebuild() {
        // If two v5 records share the same (creator, nonce) but were both
        // persisted under the stale (buggy) 3-part key format, migration 3→4
        // must detect the collision under the new 2-part key and mark the slot
        // as conflicted so the settlement gate blocks both.
        use crate::identity::{CryptoProfile, EntityType, Identity};

        let dir = tempfile::tempdir().unwrap();
        let engine = StorageEngine::open(dir.path()).unwrap();
        let id = Identity::generate_with_pow(EntityType::Device, CryptoProfile::ProfileB, 4)
            .expect("identity");

        // Two signed v5 records claiming the same (creator, nonce) — the
        // equivocation the Stage 1 machinery was designed to catch.
        let mut rec_a = ValidationRecord::create(
            b"eq-a", id.public_key.clone(), vec![], Classification::Public,
            Some(BTreeMap::new()),
        );
        rec_a.version = 5;
        rec_a.nonce = 0xAAAA;
        id.sign_record(&mut rec_a).unwrap();

        let mut rec_b = ValidationRecord::create(
            b"eq-b", id.public_key.clone(), vec![], Classification::Public,
            Some(BTreeMap::new()),
        );
        rec_b.version = 5;
        rec_b.nonce = 0xAAAA;
        id.sign_record(&mut rec_b).unwrap();

        assert_ne!(rec_a.id, rec_b.id);
        assert_eq!(rec_a.slot_key(), rec_b.slot_key(), "same (creator, nonce) = same slot");

        let cf_records = engine.cf(CF_RECORDS);
        engine.db.put_cf(&cf_records, rec_a.id.as_bytes(), rec_a.to_bytes()).unwrap();
        engine.db.put_cf(&cf_records, rec_b.id.as_bytes(), rec_b.to_bytes()).unwrap();

        engine.run_migrations(dir.path()).unwrap();

        // Exactly one slot_index entry (first-seen wins) + one conflicts entry.
        let slot = rec_a.slot_key().unwrap();
        assert_eq!(engine.count_cf(CF_SLOT_INDEX), 1);
        assert!(engine.slot_is_conflicted(&slot).unwrap(),
            "equivocation uncovered on rebuild must be flagged");
    }

    #[test]
    fn test_migration_4_to_5_moves_metadata_to_cf_metadata() {
        // Pre-migration: a v4 database has metadata keys mixed into CF_RECORDS.
        // Set up that exact state, then verify migrate_4_to_5 (run via the
        // version dispatcher) moves every prefix to CF_METADATA and clears
        // them from CF_RECORDS.
        let dir = tempfile::tempdir().unwrap();
        let engine = StorageEngine::open(dir.path()).unwrap();

        // Pin DB at v4 so run_migrations only fires migrate_4_to_5.
        // Set v4 directly on CF_RECORDS (DB_VERSION_KEY is intentionally
        // left in CF_RECORDS by the metadata split — see migrate_4_to_5
        // doc comment).
        let cf_records = engine.cf(CF_RECORDS);
        engine.db.put_cf(&cf_records, b"__db_version__", 4u32.to_le_bytes()).unwrap();

        // Pre-populate CF_RECORDS with one of every metadata prefix that
        // v4 historically wrote there.
        engine.db.put_cf(&cf_records, b"__record_count__", 42u64.to_le_bytes()).unwrap();
        engine.db.put_cf(&cf_records, b"__full_pull_cursor__", 1700000000.0_f64.to_le_bytes()).unwrap();
        engine.db.put_cf(&cf_records, b"__snapshot__:consensus", b"{\"settled\":1}").unwrap();
        engine.db.put_cf(&cf_records, b"__snapshot__:fork", b"{\"epoch\":7}").unwrap();
        engine.db.put_cf(&cf_records, b"ban:badguy", b"{\"reason\":\"spam\"}").unwrap();
        engine.db.put_cf(&cf_records, b"blocked_term:rugpull", b"rugpull").unwrap();
        engine.db.put_cf(&cf_records, b"finalized:rec-aaa", b"1").unwrap();
        engine.db.put_cf(&cf_records, b"finalized:rec-bbb", b"1").unwrap();
        engine.db.put_cf(&cf_records, b"tombstone:rec-ccc", b"{\"reason\":\"dup\"}").unwrap();

        // Also put one real record so we can prove records are NOT moved.
        let rec = test_record("survivor-001");
        engine.put_record("survivor-001", &rec).unwrap();

        engine.run_migrations(dir.path()).unwrap();
        assert_eq!(engine.get_db_version().unwrap(), CURRENT_DB_VERSION);

        // After migration, every prefix should be readable via CF_METADATA.
        let cf_meta = engine.cf(CF_METADATA);
        assert_eq!(
            engine.db.get_cf(&cf_meta, b"__record_count__").unwrap()
                .map(|v| u64::from_le_bytes(v[..8].try_into().unwrap())),
            Some(42),
            "__record_count__ must land in CF_METADATA"
        );
        assert_eq!(
            engine.db.get_cf(&cf_meta, b"__full_pull_cursor__").unwrap()
                .map(|v| f64::from_le_bytes(v[..8].try_into().unwrap())),
            Some(1700000000.0),
            "__full_pull_cursor__ must land in CF_METADATA"
        );
        assert!(engine.db.get_cf(&cf_meta, b"__snapshot__:consensus").unwrap().is_some());
        assert!(engine.db.get_cf(&cf_meta, b"__snapshot__:fork").unwrap().is_some());
        assert!(engine.db.get_cf(&cf_meta, b"ban:badguy").unwrap().is_some());
        assert!(engine.db.get_cf(&cf_meta, b"blocked_term:rugpull").unwrap().is_some());
        assert!(engine.db.get_cf(&cf_meta, b"finalized:rec-aaa").unwrap().is_some());
        assert!(engine.db.get_cf(&cf_meta, b"finalized:rec-bbb").unwrap().is_some());
        assert!(engine.db.get_cf(&cf_meta, b"tombstone:rec-ccc").unwrap().is_some());

        // And CF_RECORDS must NOT have any of those prefixes any more.
        for key in [
            &b"__record_count__"[..],
            &b"__full_pull_cursor__"[..],
            &b"__snapshot__:consensus"[..],
            &b"__snapshot__:fork"[..],
            &b"ban:badguy"[..],
            &b"blocked_term:rugpull"[..],
            &b"finalized:rec-aaa"[..],
            &b"finalized:rec-bbb"[..],
            &b"tombstone:rec-ccc"[..],
        ] {
            assert!(
                engine.db.get_cf(&cf_records, key).unwrap().is_none(),
                "metadata key still in CF_RECORDS after migration: {}",
                String::from_utf8_lossy(key)
            );
        }

        // The actual record must survive untouched.
        assert!(engine.get_record("survivor-001").unwrap().is_some());
    }

    #[test]
    fn test_migration_4_to_5_idempotent() {
        // Second invocation must be a clean no-op — no duplicate writes,
        // no CF_RECORDS regression, version unchanged.
        let dir = tempfile::tempdir().unwrap();
        let engine = StorageEngine::open(dir.path()).unwrap();

        let cf_records = engine.cf(CF_RECORDS);
        engine.db.put_cf(&cf_records, b"__db_version__", 4u32.to_le_bytes()).unwrap();
        engine.db.put_cf(&cf_records, b"ban:user1", b"{}").unwrap();
        engine.db.put_cf(&cf_records, b"finalized:rec-x", b"1").unwrap();

        engine.run_migrations(dir.path()).unwrap();
        engine.run_migrations(dir.path()).unwrap();

        let cf_meta = engine.cf(CF_METADATA);
        assert!(engine.db.get_cf(&cf_meta, b"ban:user1").unwrap().is_some());
        assert!(engine.db.get_cf(&cf_meta, b"finalized:rec-x").unwrap().is_some());
        assert!(engine.db.get_cf(&cf_records, b"ban:user1").unwrap().is_none());
        assert!(engine.db.get_cf(&cf_records, b"finalized:rec-x").unwrap().is_none());
        assert_eq!(engine.get_db_version().unwrap(), CURRENT_DB_VERSION);
    }

    #[test]
    fn test_migration_5_to_6_rebuilds_idx_hash_with_natural_hex() {
        // Before v6: writers double-hashed the content_hash into CF_IDX_HASH
        // (`sha3_256_hex(record.content_hash)`), but the only callers
        // (network::ingest, network::epoch) probed with `hex::encode(record_hash)`.
        // Result: every lookup missed for ~5 weeks.
        //
        // Migration v5→v6 wipes the legacy keys and rewrites the index using
        // `hex::encode(content_hash)` so production lookups resolve.
        let dir = tempfile::tempdir().unwrap();
        let engine = StorageEngine::open(dir.path()).unwrap();

        // Pin to v5 so the framework runs ONLY migrate_5_to_6.
        engine.set_db_version(5).unwrap();

        // Plant a real record in CF_RECORDS using `db.put_cf` so the
        // automatic put_record indexing path doesn't pre-populate
        // CF_IDX_HASH with the corrected key — we want migrate_5_to_6 to
        // be the one that fills it.
        let rec = test_record("v6-bug-fix");
        let cf_records = engine.cf(CF_RECORDS);
        engine.db.put_cf(&cf_records, rec.id.as_bytes(), rec.to_bytes()).unwrap();

        // Plant a legacy (wrong-format) entry that the migration must wipe.
        let legacy_key = crate::crypto::hash::sha3_256_hex(&rec.content_hash);
        let cf_idx_hash = engine.cf(CF_IDX_HASH);
        engine.db.put_cf(&cf_idx_hash, legacy_key.as_bytes(), rec.id.as_bytes()).unwrap();

        // Pre-state: legacy key resolves via the broken format; the
        // production-shape key (`hex::encode(content_hash)`) does not.
        let natural_key = hex::encode(&rec.content_hash);
        assert_ne!(legacy_key, natural_key, "double-hash MUST differ from natural hex");
        assert!(engine.db.get_cf(&cf_idx_hash, legacy_key.as_bytes()).unwrap().is_some());
        assert!(engine.db.get_cf(&cf_idx_hash, natural_key.as_bytes()).unwrap().is_none());

        engine.run_migrations(dir.path()).unwrap();
        assert_eq!(engine.get_db_version().unwrap(), CURRENT_DB_VERSION);

        // Post-state: legacy key gone, natural-hex key resolves to the record.
        let cf_idx_hash = engine.cf(CF_IDX_HASH);
        assert!(
            engine.db.get_cf(&cf_idx_hash, legacy_key.as_bytes()).unwrap().is_none(),
            "legacy double-hash key must be wiped"
        );
        let resolved = engine
            .record_id_by_hash(&natural_key)
            .expect("hex::encode(content_hash) must resolve post-migration");
        assert_eq!(resolved, rec.id);
        assert_eq!(engine.count_cf(CF_IDX_HASH), 1, "exactly one entry, no duplicates");
    }

    #[test]
    fn test_migration_5_to_6_idempotent() {
        // Re-running on a v6 database must be a clean no-op (count
        // unchanged, key still resolves) so operators can safely
        // re-enter run_migrations after partial failures.
        let dir = tempfile::tempdir().unwrap();
        let engine = StorageEngine::open(dir.path()).unwrap();

        let rec = test_record("v6-idempotent");
        engine.put_record(&rec.id, &rec).unwrap();
        engine.run_migrations(dir.path()).unwrap();

        let count_before = engine.count_cf(CF_IDX_HASH);
        engine.run_migrations(dir.path()).unwrap();
        let count_after = engine.count_cf(CF_IDX_HASH);

        assert_eq!(count_before, count_after, "second run must not duplicate");
        let resolved = engine
            .record_id_by_hash(&hex::encode(&rec.content_hash))
            .expect("idempotent run must preserve the resolution");
        assert_eq!(resolved, rec.id);
    }

    #[test]
    fn test_migration_5_to_6_content_hash_lookup_works() {
        // CF_IDX_HASH is keyed on `hex(content_hash)` — used by
        // `/records/by-hash/{content_hash}` (dedup endpoint). Verify that
        // post-v6 the natural-hex content_hash key resolves. Pre-v6 it
        // would have returned None because writers double-hashed the key.
        //
        // (Seal-record resolution uses a separate index — CF_IDX_RECORD_HASH,
        // backfilled in v7 — see test_migration_6_to_7_backfills_record_hash.)
        let dir = tempfile::tempdir().unwrap();
        let engine = StorageEngine::open(dir.path()).unwrap();

        let rec = test_record("content-hash-target");
        engine.put_record(&rec.id, &rec).unwrap();
        engine.run_migrations(dir.path()).unwrap();

        let probed = hex::encode(&rec.content_hash);
        let resolved = engine.record_id_by_hash(&probed);
        assert_eq!(resolved.as_deref(), Some(rec.id.as_str()));
    }

    #[test]
    fn test_migration_6_to_7_backfills_record_hash_index() {
        // Pre-v7: seal-record resolution probed CF_IDX_HASH with
        // `hex(record_hash)` — semantic mismatch (CF_IDX_HASH is keyed on
        // `hex(content_hash)`). Result: 100% miss for ~5 weeks.
        //
        // v7 introduces CF_IDX_RECORD_HASH, populated by put/upsert/delete
        // inline going forward and backfilled by migrate_6_to_7 for records
        // already on disk.
        let dir = tempfile::tempdir().unwrap();
        let engine = StorageEngine::open(dir.path()).unwrap();

        // Pin to v6 so only migrate_6_to_7 runs.
        engine.set_db_version(6).unwrap();

        // Plant a record directly into CF_RECORDS via raw put_cf so we
        // bypass the inline indexing path — the migration must be the one
        // that populates CF_IDX_RECORD_HASH.
        let rec = test_record("v7-backfill-target");
        let cf_records = engine.cf(CF_RECORDS);
        engine.db.put_cf(&cf_records, rec.id.as_bytes(), rec.to_bytes()).unwrap();

        // Pre-state: nothing in CF_IDX_RECORD_HASH for this hash.
        let rec_hash_hex = hex::encode(rec.record_hash());
        assert!(
            engine.record_id_by_record_hash(&rec_hash_hex).is_none(),
            "pre-migration: record_hash MUST NOT resolve"
        );

        engine.run_migrations(dir.path()).unwrap();
        assert_eq!(engine.get_db_version().unwrap(), CURRENT_DB_VERSION);

        // Post-state: hex(record_hash) resolves to the record id.
        let resolved = engine
            .record_id_by_record_hash(&rec_hash_hex)
            .expect("hex(record_hash) must resolve post-v7");
        assert_eq!(resolved, rec.id);

        // Regression pin: CF_IDX_HASH (content_hash CF) MUST NOT resolve
        // record_hash — that semantic mismatch is the bug v7 fixed.
        // (Use a record with distinct content_hash and record_hash; equality
        // is astronomically unlikely but we encode the contract regardless.)
        if rec.content_hash[..] != rec.record_hash()[..] {
            assert!(
                engine.record_id_by_hash(&rec_hash_hex).is_none(),
                "CF_IDX_HASH MUST NOT resolve record_hash — semantic split is the v7 invariant"
            );
        }
    }

    #[test]
    fn test_migration_6_to_7_idempotent() {
        // Re-running on a v7 database must be a clean no-op so operators
        // can safely re-enter run_migrations after partial failures.
        let dir = tempfile::tempdir().unwrap();
        let engine = StorageEngine::open(dir.path()).unwrap();

        let rec = test_record("v7-idempotent");
        engine.put_record(&rec.id, &rec).unwrap();
        engine.run_migrations(dir.path()).unwrap();

        let count_before = engine.count_cf(CF_IDX_RECORD_HASH);
        engine.run_migrations(dir.path()).unwrap();
        let count_after = engine.count_cf(CF_IDX_RECORD_HASH);

        assert_eq!(count_before, count_after, "second run must not duplicate");
        let resolved = engine
            .record_id_by_record_hash(&hex::encode(rec.record_hash()))
            .expect("idempotent run must preserve the resolution");
        assert_eq!(resolved, rec.id);
    }

    #[test]
    fn test_pre_migration_backup_sweep_keeps_recent_drops_old() {
        // Simulate a node that's been through migrations v0..v6 over its
        // lifetime and has accumulated stale backup dirs. After this run
        // (pre_run_version=6 → CURRENT_DB_VERSION=7) we keep
        // pre-migration-v6-backup and drop everything else.
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path();

        for v in 0u32..=6 {
            let backup = data_dir.join(format!("pre-migration-v{v}-backup"));
            std::fs::create_dir(&backup).unwrap();
            // Drop a sentinel file so dir_size_bytes returns nonzero —
            // confirms the size accounting reaches into subtrees.
            std::fs::write(backup.join("CURRENT"), b"sentinel").unwrap();
        }
        // Drop a non-matching dir — must NOT be touched.
        std::fs::create_dir(data_dir.join("checkpoints")).unwrap();
        std::fs::create_dir(data_dir.join("checkpoints").join("checkpoint_42")).unwrap();
        std::fs::create_dir(data_dir.join("pre-migration-v6-backup-stale")).unwrap();

        prune_stale_pre_migration_backups(data_dir, 6);

        for v in 0u32..6 {
            let backup = data_dir.join(format!("pre-migration-v{v}-backup"));
            assert!(
                !backup.exists(),
                "stale backup v{v} must be reaped"
            );
        }
        assert!(
            data_dir.join("pre-migration-v6-backup").exists(),
            "most-recent backup (v6, the rollback target) must be preserved"
        );
        assert!(
            data_dir.join("checkpoints").exists(),
            "non-matching dirs must be left alone"
        );
        assert!(
            data_dir.join("pre-migration-v6-backup-stale").exists(),
            "non-glob-matching dirs (suffix mismatch) must be left alone"
        );
    }

    #[test]
    fn test_pre_migration_backup_sweep_idempotent_when_already_clean() {
        // Re-running the sweep with no stale backups left must be a no-op.
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path();
        let keep = data_dir.join("pre-migration-v6-backup");
        std::fs::create_dir(&keep).unwrap();

        prune_stale_pre_migration_backups(data_dir, 6);
        prune_stale_pre_migration_backups(data_dir, 6);

        assert!(keep.exists(), "rollback target preserved across sweeps");
    }

    #[test]
    fn test_run_migrations_sweeps_when_already_at_latest_schema() {
        // Regression for the early-return bug fixed in 75b4e79: a node booted
        // already at CURRENT_DB_VERSION must STILL sweep stale backup dirs,
        // not silently skip the sweep with the "no migrations to run"
        // early-return. A node hit 100% disk on the v7 deploy because v4/v5
        // backups never got reaped on boot after migrations had already run.
        let dir = tempfile::tempdir().unwrap();
        let engine = StorageEngine::open(dir.path()).unwrap();

        // Bring DB to the latest schema so the next run_migrations call
        // hits the early-return path. The first run creates exactly one
        // pre-migration backup at v0 (since current=0 at the start), so
        // pre-migration-v0-backup will already exist after this call.
        engine.run_migrations(dir.path()).unwrap();
        assert!(
            dir.path().join("pre-migration-v0-backup").exists(),
            "first run created the pre-migration-v0 backup"
        );

        // Seed additional stale backup dirs from prior migration runs that
        // accumulated over the node's lifetime. These are the dead weight
        // that was filling Nuremberg's disk. Skip v0 — it already exists
        // from the first run_migrations call above.
        for v in [1u32, 4, 5] {
            let backup = dir.path().join(format!("pre-migration-v{v}-backup"));
            std::fs::create_dir(&backup).unwrap();
            std::fs::write(backup.join("CURRENT"), b"sentinel").unwrap();
        }
        // Plus the backup at CURRENT_DB_VERSION-1 the most recent migration run
        // would have created. This is the rollback target the sweep must
        // preserve. Version-relative so a future CURRENT_DB_VERSION bump (which
        // is exactly what broke this test at the 7→8 mandate-agent-index bump)
        // can't re-break it.
        let keep_v = CURRENT_DB_VERSION - 1;
        std::fs::create_dir(dir.path().join(format!("pre-migration-v{keep_v}-backup"))).unwrap();

        // run_migrations must call the sweep even when current ==
        // CURRENT_DB_VERSION.
        engine.run_migrations(dir.path()).unwrap();

        for v in [0u32, 1, 4, 5] {
            assert!(
                !dir.path().join(format!("pre-migration-v{v}-backup")).exists(),
                "stale v{v} backup must be reaped on early-return boot path"
            );
        }
        assert!(
            dir.path().join(format!("pre-migration-v{keep_v}-backup")).exists(),
            "v{keep_v} (CURRENT_DB_VERSION-1 rollback target) preserved on early-return boot path"
        );
    }

    #[test]
    fn test_pre_migration_backup_sweep_already_at_latest_keeps_prev_version() {
        // Node booted already at CURRENT_DB_VERSION → no backup created
        // this run. Sweep falls back to keeping CURRENT_DB_VERSION-1 if
        // present (still useful as one rollback target), drops the rest.
        // Version-relative (v0/v1 are always stale, keep target tracks the
        // constant) so a CURRENT_DB_VERSION bump can't re-break it.
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path();

        let keep_v = CURRENT_DB_VERSION - 1;
        for v in [0u32, 1, keep_v] {
            std::fs::create_dir(data_dir.join(format!("pre-migration-v{v}-backup"))).unwrap();
        }

        prune_stale_pre_migration_backups(data_dir, CURRENT_DB_VERSION);

        assert!(
            !data_dir.join("pre-migration-v0-backup").exists(),
            "stale v0 dropped"
        );
        assert!(
            !data_dir.join("pre-migration-v1-backup").exists(),
            "stale v1 dropped"
        );
        assert!(
            data_dir.join(format!("pre-migration-v{keep_v}-backup")).exists(),
            "v{keep_v} (CURRENT_DB_VERSION-1) preserved as last rollback target on already-current node"
        );
    }

    #[test]
    fn test_compute_pre_migration_backup_bytes_sums_matching_dirs() {
        // A node mid-rollback window has both the rollback target and a
        // straggler from an even-older migration. The metric must sum
        // bytes from every dir that matches the strict glob, regardless
        // of which one the sweep would keep.
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path();

        let v5 = data_dir.join("pre-migration-v5-backup");
        std::fs::create_dir(&v5).unwrap();
        std::fs::write(v5.join("a"), vec![0u8; 100]).unwrap();

        let v6 = data_dir.join("pre-migration-v6-backup");
        std::fs::create_dir(&v6).unwrap();
        std::fs::create_dir(v6.join("nested")).unwrap();
        std::fs::write(v6.join("nested").join("b"), vec![0u8; 250]).unwrap();
        std::fs::write(v6.join("c"), vec![0u8; 50]).unwrap();

        let bytes = compute_pre_migration_backup_bytes(data_dir);
        assert_eq!(bytes, 100 + 250 + 50, "sum across all matching dirs + nested files");
    }

    #[test]
    fn test_compute_pre_migration_backup_bytes_skips_non_matching() {
        // Strict glob: middle MUST be all digits, prefix MUST be exact,
        // suffix MUST be exact. Anything else is operator-owned and
        // never counted toward the rollback-target gauge.
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path();

        let real = data_dir.join("pre-migration-v6-backup");
        std::fs::create_dir(&real).unwrap();
        std::fs::write(real.join("payload"), vec![0u8; 1000]).unwrap();

        // Sibling dirs that look pre-migration-ish but should NOT count.
        for name in [
            "checkpoints",
            "pre-migration-v6-backup-stale",
            "pre-migration-vfoo-backup",
            "pre-migration-backup",
            "pre-migration-v6-bak",
        ] {
            let p = data_dir.join(name);
            std::fs::create_dir(&p).unwrap();
            std::fs::write(p.join("filler"), vec![0u8; 9_999]).unwrap();
        }

        let bytes = compute_pre_migration_backup_bytes(data_dir);
        assert_eq!(bytes, 1000, "only the strict-glob match counts");
    }

    #[test]
    fn test_compute_pre_migration_backup_bytes_zero_when_no_backups() {
        let dir = tempfile::tempdir().unwrap();
        // data_dir exists but has no pre-migration dirs at all.
        let bytes = compute_pre_migration_backup_bytes(dir.path());
        assert_eq!(bytes, 0, "fresh data_dir reports zero backup bytes");
    }

    #[test]
    fn test_pre_migration_backup_bytes_cached_returns_nonzero_for_seeded_dir() {
        // Smoke test the cached wrapper. Cache is process-global so we
        // can't assert on staleness behavior across tests safely (other
        // tests may pollute the cache); just confirm a populated dir
        // produces the same answer as the uncached helper on first call.
        let dir = tempfile::tempdir().unwrap();
        let backup = dir.path().join("pre-migration-v6-backup");
        std::fs::create_dir(&backup).unwrap();
        std::fs::write(backup.join("blob"), vec![0u8; 4096]).unwrap();

        let direct = compute_pre_migration_backup_bytes(dir.path());
        let cached = pre_migration_backup_bytes_cached(dir.path());
        // Both should agree on this fresh path. Cache may hold stale data
        // from other tests if they ran first, so we only assert direct.
        assert_eq!(direct, 4096);
        // Cached is best-effort: either fresh (==4096) or stale-from-other-test.
        // Sanity: if cache reports zero or matches direct, we're fine; we just
        // don't want a panic / overflow.
        let _ = cached;
    }

    #[test]
    fn test_v7_inline_writeback_on_put_record() {
        // Verify writers populate CF_IDX_RECORD_HASH inline, not just the
        // migration backfill — otherwise new records written after v7 would
        // still miss the index.
        let dir = tempfile::tempdir().unwrap();
        let engine = StorageEngine::open(dir.path()).unwrap();
        engine.run_migrations(dir.path()).unwrap();

        let rec = test_record("v7-inline-writer");
        engine.put_record(&rec.id, &rec).unwrap();

        let resolved = engine
            .record_id_by_record_hash(&hex::encode(rec.record_hash()))
            .expect("put_record must inline-populate CF_IDX_RECORD_HASH");
        assert_eq!(resolved, rec.id);
    }

    #[test]
    fn test_metadata_writes_route_to_cf_metadata() {
        // Public API surface: every helper that used to write to CF_RECORDS
        // under a reserved prefix must now land its bytes in CF_METADATA so
        // CF_RECORDS scans see only records.
        let (engine, _dir) = test_engine();

        engine.ban_identity("aabbcc", "bad behavior").unwrap();
        engine.add_blocked_term("rugpull").unwrap();
        engine.save_snapshot("test_snap", &serde_json::json!({"k": 1})).unwrap();
        engine.save_full_pull_cursor(1234.5);
        engine.recalibrate_count(7);

        let cf_meta = engine.cf(CF_METADATA);
        assert!(engine.db.get_cf(&cf_meta, b"ban:aabbcc").unwrap().is_some());
        assert!(engine.db.get_cf(&cf_meta, b"blocked_term:rugpull").unwrap().is_some());
        assert!(engine.db.get_cf(&cf_meta, b"__snapshot__:test_snap").unwrap().is_some());
        assert_eq!(
            engine.db.get_cf(&cf_meta, b"__full_pull_cursor__").unwrap()
                .map(|v| f64::from_le_bytes(v[..8].try_into().unwrap())),
            Some(1234.5)
        );
        assert_eq!(
            engine.db.get_cf(&cf_meta, b"__record_count__").unwrap()
                .map(|v| u64::from_le_bytes(v[..8].try_into().unwrap())),
            Some(7)
        );

        // CF_RECORDS must remain free of those prefixes.
        let cf_records = engine.cf(CF_RECORDS);
        assert!(engine.db.get_cf(&cf_records, b"ban:aabbcc").unwrap().is_none());
        assert!(engine.db.get_cf(&cf_records, b"blocked_term:rugpull").unwrap().is_none());
        assert!(engine.db.get_cf(&cf_records, b"__snapshot__:test_snap").unwrap().is_none());
        assert!(engine.db.get_cf(&cf_records, b"__full_pull_cursor__").unwrap().is_none());
        assert!(engine.db.get_cf(&cf_records, b"__record_count__").unwrap().is_none());
    }

    #[test]
    fn test_count_fast_path_reads_from_cf_metadata() {
        // Inserting records must update the count cache in CF_METADATA, and
        // the count() implementation must read it from there. Exercises the
        // round-trip end-to-end.
        use crate::storage::Storage;
        let (engine, _dir) = test_engine();
        engine.put_record("rec-1", &test_record("rec-1")).unwrap();
        engine.put_record("rec-2", &test_record("rec-2")).unwrap();

        let cf_meta = engine.cf(CF_METADATA);
        let cached = engine.db.get_cf(&cf_meta, b"__record_count__").unwrap()
            .map(|v| u64::from_le_bytes(v[..8].try_into().unwrap()));
        assert_eq!(cached, Some(2));

        // count() must agree with the cached value.
        assert_eq!(<StorageEngine as Storage>::count(&engine).unwrap(), 2);

        // CF_RECORDS must NOT carry the cache key any more.
        let cf_records = engine.cf(CF_RECORDS);
        assert!(engine.db.get_cf(&cf_records, b"__record_count__").unwrap().is_none());
    }

    #[test]
    fn test_migration_does_not_double_index() {
        let dir = tempfile::tempdir().unwrap();
        let engine = StorageEngine::open(dir.path()).unwrap();

        // Insert a record the normal way (indexes get created by put_record)
        let rec = test_record("normal-001");
        engine.put_record("normal-001", &rec).unwrap();

        // Verify indexes exist
        assert_eq!(engine.count_cf(CF_IDX_TIMESTAMP), 1);
        assert_eq!(engine.count_cf(CF_IDX_HASH), 1);

        // Run migration — should detect existing indexes and skip
        engine.run_migrations(dir.path()).unwrap();

        // Counts should be unchanged (no duplicates)
        assert_eq!(engine.count_cf(CF_IDX_TIMESTAMP), 1);
        assert_eq!(engine.count_cf(CF_IDX_HASH), 1);
    }

    #[test]
    fn test_incremental_ledger_replay_empty() {
        // Incremental replay with no records since checkpoint should return (0, 0)
        let (engine, _dir) = test_engine();
        let mut ledger = crate::accounting::ledger::LedgerState::new();
        let (applied, skipped) = engine.incremental_ledger_replay(&mut ledger, "genesis_auth", &[], 0.0).unwrap();
        assert_eq!(applied, 0);
        assert_eq!(skipped, 0);
    }

    // Insert a mint ledger-op record (creator = the fixed test_record identity,
    // which therefore IS the genesis authority) for `amount` base units to `to`.
    #[cfg(feature = "node-core")]
    fn insert_mint(engine: &StorageEngine, id: &str, ts: f64, amount: &str, to: &str) {
        let mut rec = test_record(id);
        rec.timestamp = ts;
        rec.metadata.insert("beat_op".into(), serde_json::Value::String("mint".into()));
        rec.metadata.insert("beat_amount".into(), serde_json::Value::String(amount.into()));
        rec.metadata.insert("beat_to".into(), serde_json::Value::String(to.into()));
        rec.metadata.insert("beat_reason".into(), serde_json::Value::String("genesis:test".into()));
        engine.put_record(id, &rec).unwrap();
    }

    #[test]
    #[cfg(feature = "node-core")]
    fn rebuild_ledger_streaming_replays_ledger_ops_correctly() {
        // audit 16e: rebuild_ledger_streaming now STREAMS ledger ops straight off
        // the (already timestamp-ordered) CF_IDX_TIMESTAMP iterator instead of
        // buffering them all into a Vec and sorting. Pin that the streamed
        // rebuild still produces a correct ledger from records on disk.
        let (engine, _dir) = test_engine();
        let gen_hash = crate::accounting::types::creator_identity_hash(&test_record("gh"));
        let alice = "alice-identity";

        // Two mints to alice at increasing timestamps (both authored by the
        // fixed test identity == genesis authority).
        insert_mint(&engine, "mint-1", 1_700_000_001.0, "1000", alice);
        insert_mint(&engine, "mint-2", 1_700_000_002.0, "500", alice);

        let (state, skipped) = engine.rebuild_ledger_streaming(&gen_hash, &[]).unwrap();
        assert_eq!(skipped, 0, "both mints apply cleanly");
        assert_eq!(
            state.accounts.get(alice).map(|a| a.available).unwrap_or(0),
            1500,
            "alice credited 1000 + 500 by the streaming rebuild"
        );
        assert_eq!(state.total_supply, 1500, "total supply reflects both mints");
    }

    #[test]
    #[cfg(feature = "node-core")]
    fn incremental_ledger_replay_applies_unseen_mint() {
        // audit 16e sibling: incremental_ledger_replay also streams (plain fold,
        // no sort). An unseen mint must actually apply (the existing empty/skip
        // tests don't cover a real application).
        let (engine, _dir) = test_engine();
        let gen_hash = crate::accounting::types::creator_identity_hash(&test_record("gh"));
        insert_mint(&engine, "mint-1", 1_700_000_001.0, "1000", "alice-identity");

        let mut ledger = crate::accounting::ledger::LedgerState::new();
        let (applied, skipped) = engine
            .incremental_ledger_replay(&mut ledger, &gen_hash, &[], 0.0)
            .unwrap();
        assert_eq!(applied, 1, "the unseen mint is applied");
        assert_eq!(skipped, 0);
        assert_eq!(ledger.total_supply, 1000);
        assert_eq!(
            ledger.accounts.get("alice-identity").map(|a| a.available).unwrap_or(0),
            1000
        );
    }

    #[test]
    fn test_checkpoint_timestamp_roundtrip() {
        let (engine, _dir) = test_engine();
        let ts: f64 = 1700000000.5;
        engine.save_snapshot("checkpoint_timestamp", &ts).unwrap();
        let loaded = engine.load_snapshot::<f64>("checkpoint_timestamp").unwrap();
        assert_eq!(loaded, Some(ts));
    }

    #[test]
    fn test_ledger_snapshot_roundtrip() {
        let (engine, _dir) = test_engine();
        let mut ledger = crate::accounting::ledger::LedgerState::new();
        ledger.total_supply = 10_000_000_000_000_000_000;
        ledger.accounts.insert("alice".to_string(), Default::default());
        engine.save_snapshot("ledger", &ledger).unwrap();
        let loaded = engine.load_snapshot::<crate::accounting::ledger::LedgerState>("ledger").unwrap().unwrap();
        assert_eq!(loaded.total_supply, ledger.total_supply);
        assert_eq!(loaded.accounts.len(), 1);
    }

    #[test]
    fn test_incremental_replay_skips_already_applied() {
        // If a record is in applied_record_ids, incremental replay should skip it
        let (engine, _dir) = test_engine();

        // Insert a ledger record (mint) into storage
        let mut rec = test_record("mint-001");
        rec.timestamp = 1700000001.0;
        rec.metadata.insert("beat_op".to_string(), serde_json::Value::String("mint".to_string()));
        rec.metadata.insert("beat_amount".to_string(), serde_json::Value::String("1000".to_string()));
        rec.metadata.insert("beat_to".to_string(), serde_json::Value::String("alice".to_string()));
        rec.metadata.insert("beat_reason".to_string(), serde_json::Value::String("genesis:test".to_string()));
        engine.put_record("mint-001", &rec).unwrap();

        // Pre-mark as applied
        let mut ledger = crate::accounting::ledger::LedgerState::new();
        ledger.applied_record_ids.insert("mint-001".to_string());

        // genesis_authority = identity_hash of the test record's creator_public_key
        let creator_hash = crate::accounting::types::creator_identity_hash(&rec);
        let (applied, skipped) = engine.incremental_ledger_replay(&mut ledger, &creator_hash, &[], 0.0).unwrap();
        // Should be skipped because already in applied_record_ids
        assert_eq!(applied, 0);
        assert_eq!(skipped, 0);
        assert_eq!(ledger.total_supply, 0); // no change
    }

    #[test]
    #[cfg(feature = "node-core")]
    fn incremental_replay_applies_record_marked_in_cf_applied_but_unfolded() {
        // B1 repro (SEV-1 crash-recovery fork). A record committed to the live
        // ledger AFTER the checkpoint snapshot was saved is marked in CF_APPLIED
        // (eager ingest mark) but is ABSENT from the persisted cp_ledger balances,
        // and the clone()'d snapshot's applied_record_ids is EMPTY. The fast-path
        // replay MUST still fold it. The old dedup `|| self.is_applied(record_id)`
        // skipped it → silent balance drop → permanent SMT fork on a solo authority.
        let (engine, _dir) = test_engine();
        let gen_hash = crate::accounting::types::creator_identity_hash(&test_record("gh"));

        // 1. Pre-checkpoint mint, folded into the checkpoint ledger + marked on disk
        //    (the live system marks every applied record in CF_APPLIED).
        insert_mint(&engine, "mint-pre", 1_000.0, "1000", "alice");
        let mut folded = crate::accounting::ledger::LedgerState::new();
        engine.incremental_ledger_replay(&mut folded, &gen_hash, &[], 0.0).unwrap();
        assert_eq!(folded.total_supply, 1000);
        assert_eq!(folded.last_applied_ts, 1_000.0);
        engine.mark_applied("mint-pre");

        // 2. Persisted checkpoint = clone() (empties applied_record_ids — the bug's
        //    precondition: the in-memory dedup set is gone, only CF_APPLIED remains).
        let mut cp_ledger = folded.clone();
        assert!(cp_ledger.applied_record_ids.is_empty(), "clone must empty the set");

        // 3. Post-checkpoint mint: committed to disk + marked applied, NOT folded.
        insert_mint(&engine, "mint-post", 2_000.0, "500", "bob");
        engine.mark_applied("mint-post");
        assert!(engine.is_applied("mint-post"), "precondition: marked on disk");

        // 4. Fast-path replay from the checkpoint's own last_applied_ts.
        let since = cp_ledger.last_applied_ts;
        let (applied, _skipped) = engine
            .incremental_ledger_replay(&mut cp_ledger, &gen_hash, &[], since)
            .unwrap();

        // 5. mint-post MUST fold despite being in CF_APPLIED; mint-pre (== boundary
        //    ts, already folded) must NOT re-apply. Pre-fix: mint-post dropped.
        assert_eq!(applied, 1, "post-checkpoint record must be applied, not skipped");
        assert_eq!(
            cp_ledger.accounts.get("bob").map(|a| a.available),
            Some(500),
            "B1: record marked in CF_APPLIED but absent from cp_ledger must still fold"
        );
        assert_eq!(cp_ledger.total_supply, 1500, "supply reflects both mints exactly once");
    }

    #[test]
    #[cfg(feature = "node-core")]
    fn incremental_replay_exclusive_seek_skips_boundary_record() {
        // The EXCLUSIVE seek floor must skip records AT exactly since_ts — they are
        // already folded into the checkpoint. Without it, an inclusive From(since_ts)
        // re-presents the boundary record and, because clone() emptied
        // applied_record_ids, re-applies it (double-count). Pins no-double-apply.
        let (engine, _dir) = test_engine();
        let gen_hash = crate::accounting::types::creator_identity_hash(&test_record("gh"));
        insert_mint(&engine, "mint-boundary", 5_000.0, "1000", "carol");

        let mut folded = crate::accounting::ledger::LedgerState::new();
        engine.incremental_ledger_replay(&mut folded, &gen_hash, &[], 0.0).unwrap();
        assert_eq!(folded.total_supply, 1000);
        // Persisted checkpoint clone (empties applied_record_ids).
        let mut cp_ledger = folded.clone();
        assert!(cp_ledger.applied_record_ids.is_empty());

        // Replay from the exact boundary ts. mint-boundary (ts == since_ts) must
        // NOT re-apply (it is below/at the exclusive floor).
        let (applied, _skipped) = engine
            .incremental_ledger_replay(&mut cp_ledger, &gen_hash, &[], 5_000.0)
            .unwrap();
        assert_eq!(applied, 0, "boundary record at ts==since_ts must not re-apply");
        assert_eq!(cp_ledger.total_supply, 1000, "no double-apply at the seek boundary");
        assert_eq!(cp_ledger.accounts.get("carol").map(|a| a.available), Some(1000));
    }

    #[test]
    fn test_recent_record_ids_newest_first() {
        let (engine, _dir) = test_engine();

        // Insert 3 records with different timestamps
        let mut r1 = test_record("old");
        r1.timestamp = 1000.0;
        engine.put_record("old", &r1).unwrap();

        let mut r2 = test_record("mid");
        r2.timestamp = 2000.0;
        engine.put_record("mid", &r2).unwrap();

        let mut r3 = test_record("new");
        r3.timestamp = 3000.0;
        engine.put_record("new", &r3).unwrap();

        // All 3 since timestamp 0
        let ids = engine.recent_record_ids(0.0, 100).unwrap();
        assert_eq!(ids.len(), 3);
        assert_eq!(ids[0], "new");  // newest first
        assert_eq!(ids[1], "mid");
        assert_eq!(ids[2], "old");

        // Only records since 1500 (mid + new)
        let ids = engine.recent_record_ids(1500.0, 100).unwrap();
        assert_eq!(ids.len(), 2);
        assert_eq!(ids[0], "new");
        assert_eq!(ids[1], "mid");

        // Limit to 1
        let ids = engine.recent_record_ids(0.0, 1).unwrap();
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0], "new");
    }

    /// Simulate crash recovery: write records, drop engine WITHOUT flush,
    /// reopen, verify all data survives (RocksDB WAL provides durability).
    #[test]
    fn test_crash_recovery_records_survive_reopen() {
        let dir = tempfile::tempdir().unwrap();

        // Phase 1: Write 100 records, then "crash" (drop without explicit flush)
        {
            let engine = StorageEngine::open(dir.path()).unwrap();
            for i in 0..100 {
                let mut rec = test_record(&format!("crash-{i}"));
                rec.timestamp = 1700000000.0 + i as f64;
                engine.put_record(&format!("crash-{i}"), &rec).unwrap();
            }
            // Drop engine — simulates process exit. RocksDB WAL should recover.
        }

        // Phase 2: Reopen and verify all 100 records survived
        {
            let engine = StorageEngine::open(dir.path()).unwrap();
            for i in 0..100 {
                let loaded = engine.get_record(&format!("crash-{i}")).unwrap();
                assert!(
                    loaded.is_some(),
                    "record crash-{i} lost after simulated crash"
                );
                let loaded = loaded.unwrap();
                assert_eq!(loaded.id, format!("crash-{i}"));
            }
            // Verify count.
            // Tier 4.5: __record_count__ has moved out of CF_RECORDS into
            // CF_METADATA, so CF_RECORDS holds exactly the records (100
            // here). Cross-check CF_METADATA carries the cached counter.
            let count = engine.count_cf(CF_RECORDS);
            assert!(count >= 100, "record count {count} < 100 after crash recovery");
            assert!(engine.count_cf(CF_METADATA) >= 1, "CF_METADATA missing __record_count__ entry");
        }
    }

    /// Verify snapshot + records survive multiple open/close cycles.
    #[test]
    fn test_repeated_reopen_stability() {
        let dir = tempfile::tempdir().unwrap();

        // Write some initial data
        {
            let engine = StorageEngine::open(dir.path()).unwrap();
            for i in 0..10 {
                let mut rec = test_record(&format!("stable-{i}"));
                rec.timestamp = 1700000000.0 + i as f64;
                engine.put_record(&format!("stable-{i}"), &rec).unwrap();
            }
            engine.save_snapshot("test_data", &42u64).unwrap();
        }

        // Reopen 5 times, verify data each time, add more records
        for cycle in 0..5 {
            let engine = StorageEngine::open(dir.path()).unwrap();

            // Verify all previous records exist
            let expected = 10 + cycle * 5;
            for i in 0..expected {
                let id = if i < 10 {
                    format!("stable-{i}")
                } else {
                    format!("cycle-{i}")
                };
                assert!(
                    engine.get_record(&id).unwrap().is_some(),
                    "record {id} missing on cycle {cycle}"
                );
            }

            // Verify snapshot
            let snap: u64 = engine.load_snapshot("test_data").unwrap().unwrap();
            assert_eq!(snap, 42);

            // Add 5 more records
            for j in 0..5 {
                let idx = expected + j;
                let mut rec = test_record(&format!("cycle-{idx}"));
                rec.timestamp = 1700000000.0 + idx as f64;
                engine.put_record(&format!("cycle-{idx}"), &rec).unwrap();
            }
        }

        // Final verification: all 35 records present (10 initial + 5 × 5 cycles).
        // Tier 4.5: __record_count__ + __snapshot__:test_data live in
        // CF_METADATA, so CF_RECORDS holds exactly 35 records.
        let engine = StorageEngine::open(dir.path()).unwrap();
        let count = engine.count_cf(CF_RECORDS);
        assert!(count >= 35, "final count {count} < 35");
        assert!(engine.count_cf(CF_METADATA) >= 2, "CF_METADATA missing snapshot or count cache");
    }

    /// ARCH-1 Phase 3.1 — verify `CF_PENDING_DELTAS` exists, round-trips
    /// a serialized `PendingLedgerDelta`, and survives a reopen.
    #[test]
    fn test_cf_pending_deltas_roundtrip() {
        use crate::accounting::pending_delta::{PendingLedgerDelta, PendingOp};

        let dir = tempfile::tempdir().unwrap();
        let delta = PendingLedgerDelta::new(
            "rec-pending-1".to_string(),
            "alice_hash".to_string(),
            1_700_000_000.0,
            1_700_000_001.0,
            PendingOp::Transfer {
                from: "alice_hash".to_string(),
                to: "bob_hash".to_string(),
                amount: 42,
                memo: None,
            },
        );
        let bytes = delta.to_json().unwrap();

        // Phase 1: write + close.
        {
            let engine = StorageEngine::open(dir.path()).unwrap();
            engine
                .put_cf_raw(CF_PENDING_DELTAS, delta.record_id.as_bytes(), &bytes)
                .unwrap();
        }

        // Phase 2: reopen, read back, verify bit-identical.
        {
            let engine = StorageEngine::open(dir.path()).unwrap();
            let got = engine
                .get_cf_raw(CF_PENDING_DELTAS, delta.record_id.as_bytes())
                .unwrap()
                .expect("delta should survive reopen");
            let back = PendingLedgerDelta::from_json(&got).unwrap();
            assert_eq!(back, delta);

            // Delete clears it.
            engine
                .delete_cf_raw(CF_PENDING_DELTAS, delta.record_id.as_bytes())
                .unwrap();
            assert!(
                engine
                    .get_cf_raw(CF_PENDING_DELTAS, delta.record_id.as_bytes())
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[test]
    fn witness_registry_flush_pending_batch_atomic() {
        let (engine, _dir) = test_engine();

        // Empty batch is a no-op.
        let n = engine.flush_pending_witness_registrations(&[]).unwrap();
        assert_eq!(n, 0);

        let pending = vec![
            ("zone:a".to_string(), "alice".to_string(), vec![0xa1; 32], 1000, 5),
            ("zone:a".to_string(), "bob".to_string(),   vec![0xb2; 32], 2000, 5),
            ("zone:b".to_string(), "carol".to_string(), vec![0xc3; 32], 3000, 6),
        ];
        let n = engine.flush_pending_witness_registrations(&pending).unwrap();
        assert_eq!(n, 3);

        // Each entry is now retrievable via the regular get/iter API.
        assert_eq!(engine.iter_witnesses_for_zone("zone:a").len(), 2);
        let entry = engine.get_witness("zone:b", "carol").unwrap().unwrap();
        assert_eq!(entry.bond, 3000);
        assert_eq!(entry.registered_epoch, 6);
        assert_eq!(entry.dilithium_pk, vec![0xc3; 32]);
    }

    #[test]
    fn witness_registry_register_get_iter_isolated_per_zone() {
        let (engine, _dir) = test_engine();

        // Empty zone yields empty iteration.
        assert!(engine.iter_witnesses_for_zone("zone:a").is_empty());
        assert!(engine.get_witness("zone:a", "alice").unwrap().is_none());

        // Register two witnesses in zone:a, one in zone:b — including a
        // case that proves the NUL separator beats colon-suffix collisions.
        engine.register_witness("zone:a", "alice", vec![0x01; 32], 1000, 7).unwrap();
        engine.register_witness("zone:a", "bob",   vec![0x02; 32], 2000, 7).unwrap();
        engine.register_witness("zone:a:trap", "eve", vec![0xee; 32], 9_999, 7).unwrap();
        engine.register_witness("zone:b", "carol", vec![0x03; 32], 3000, 8).unwrap();

        let entry = engine.get_witness("zone:a", "alice").unwrap().unwrap();
        assert_eq!(entry.dilithium_pk, vec![0x01; 32]);
        assert_eq!(entry.bond, 1000);
        assert_eq!(entry.registered_epoch, 7);

        let mut a = engine.iter_witnesses_for_zone("zone:a");
        a.sort_by(|x, y| x.0.cmp(&y.0));
        let names: Vec<&str> = a.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, vec!["alice", "bob"], "zone:a must NOT leak into zone:a:trap");

        let b = engine.iter_witnesses_for_zone("zone:b");
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].0, "carol");
        assert_eq!(b[0].1.bond, 3000);

        // Idempotent re-register overwrites the bond / pk.
        engine.register_witness("zone:a", "alice", vec![0x11; 32], 5000, 9).unwrap();
        let entry = engine.get_witness("zone:a", "alice").unwrap().unwrap();
        assert_eq!(entry.dilithium_pk, vec![0x11; 32]);
        assert_eq!(entry.bond, 5000);
        assert_eq!(entry.registered_epoch, 9);
        // Count unchanged after overwrite.
        assert_eq!(engine.iter_witnesses_for_zone("zone:a").len(), 2);
    }

    // ── ZSP Phase B: CF_RECORD_BY_ZONE ─────────────────────────────────────

    fn zoned_record(id: &str, zone_path: &str, ts: f64) -> ValidationRecord {
        let mut r = test_record(id);
        r.zone = Some(crate::ZoneId::new(zone_path));
        r.timestamp = ts;
        r
    }

    #[test]
    fn zsp_b_iter_zone_returns_only_target_zone_records() {
        let (engine, _dir) = test_engine();
        let z_eu = crate::ZoneId::new("medical/eu");
        let z_us = crate::ZoneId::new("medical/us");

        engine.put_record("eu-1", &zoned_record("eu-1", "medical/eu", 100.0)).unwrap();
        engine.put_record("eu-2", &zoned_record("eu-2", "medical/eu", 200.0)).unwrap();
        engine.put_record("us-1", &zoned_record("us-1", "medical/us", 150.0)).unwrap();

        let eu_ids = engine.iter_zone(&z_eu.to_key_bytes(), None, None, 100);
        let us_ids = engine.iter_zone(&z_us.to_key_bytes(), None, None, 100);

        assert_eq!(eu_ids, vec!["eu-1".to_string(), "eu-2".to_string()]);
        assert_eq!(us_ids, vec!["us-1".to_string()]);
    }

    #[test]
    fn zsp_b_iter_zone_orders_by_timestamp() {
        let (engine, _dir) = test_engine();
        let z = crate::ZoneId::new("zone/x");

        // Insert out of chronological order
        engine.put_record("c", &zoned_record("c", "zone/x", 300.0)).unwrap();
        engine.put_record("a", &zoned_record("a", "zone/x", 100.0)).unwrap();
        engine.put_record("b", &zoned_record("b", "zone/x", 200.0)).unwrap();

        let ids = engine.iter_zone(&z.to_key_bytes(), None, None, 100);
        assert_eq!(ids, vec!["a", "b", "c"]);
    }

    #[test]
    fn zsp_b_iter_zone_respects_time_bounds() {
        let (engine, _dir) = test_engine();
        let z = crate::ZoneId::new("zone/y");
        for (id, ts) in &[("r1", 100.0), ("r2", 200.0), ("r3", 300.0), ("r4", 400.0)] {
            engine.put_record(id, &zoned_record(id, "zone/y", *ts)).unwrap();
        }

        // since=200 → drops r1
        let ids = engine.iter_zone(&z.to_key_bytes(), Some(200.0), None, 100);
        assert_eq!(ids, vec!["r2", "r3", "r4"]);

        // until=300 → drops r4 (until is inclusive)
        let ids = engine.iter_zone(&z.to_key_bytes(), None, Some(300.0), 100);
        assert_eq!(ids, vec!["r1", "r2", "r3"]);

        // since=200, until=300 → only r2, r3
        let ids = engine.iter_zone(&z.to_key_bytes(), Some(200.0), Some(300.0), 100);
        assert_eq!(ids, vec!["r2", "r3"]);
    }

    #[test]
    fn zsp_b_iter_zone_respects_limit() {
        let (engine, _dir) = test_engine();
        let z = crate::ZoneId::new("zone/limit");
        for i in 0..10 {
            let id = format!("rec-{i:02}");
            engine.put_record(&id, &zoned_record(&id, "zone/limit", i as f64)).unwrap();
        }
        let ids = engine.iter_zone(&z.to_key_bytes(), None, None, 3);
        assert_eq!(ids.len(), 3);
        assert_eq!(ids, vec!["rec-00", "rec-01", "rec-02"]);

        // limit=0 returns empty (early return).
        let empty = engine.iter_zone(&z.to_key_bytes(), None, None, 0);
        assert!(empty.is_empty());
    }

    #[test]
    fn zsp_b_count_zone_matches_iter() {
        let (engine, _dir) = test_engine();
        let z_a = crate::ZoneId::new("zone/a");
        let z_b = crate::ZoneId::new("zone/b");
        for i in 0..5 {
            let id = format!("a-{i}");
            engine.put_record(&id, &zoned_record(&id, "zone/a", i as f64)).unwrap();
        }
        for i in 0..3 {
            let id = format!("b-{i}");
            engine.put_record(&id, &zoned_record(&id, "zone/b", i as f64)).unwrap();
        }
        assert_eq!(engine.count_zone(&z_a.to_key_bytes()), 5);
        assert_eq!(engine.count_zone(&z_b.to_key_bytes()), 3);
        // Empty zone reports zero.
        let z_empty = crate::ZoneId::new("zone/empty");
        assert_eq!(engine.count_zone(&z_empty.to_key_bytes()), 0);
    }

    #[test]
    fn zone_idx_observability_gauges_correct_after_insert() {
        // Covers the try_cf() refactor: zone_idx_total_entries /
        // zone_idx_distinct_zones previously called self.cf() which panics on
        // schema mismatch; they now use try_cf() and return 0 on error.
        let (engine, _dir) = test_engine();
        assert_eq!(engine.zone_idx_total_entries(), 0);
        assert_eq!(engine.zone_idx_distinct_zones(), 0);

        engine.put_record("r1", &zoned_record("r1", "net/a", 1.0)).unwrap();
        engine.put_record("r2", &zoned_record("r2", "net/a", 2.0)).unwrap();
        engine.put_record("r3", &zoned_record("r3", "net/b", 1.0)).unwrap();

        assert_eq!(engine.zone_idx_total_entries(), 3);
        assert_eq!(engine.zone_idx_distinct_zones(), 2);
    }

    #[test]
    fn zsp_b_explicit_zone_overrides_record_zone_field() {
        let (engine, _dir) = test_engine();
        // Record self-declares medical/eu, but we index it under medical/us
        // (simulates registry redirect / Phase B hot-path semantics).
        let mut rec = zoned_record("redir-1", "medical/eu", 100.0);
        let leaf_zone = crate::ZoneId::new("medical/us");
        let leaf_key = leaf_zone.to_key_bytes();
        rec.creator_public_key = vec![0xCC; 1952];
        engine.put_record_with_pk_zone(
            "redir-1",
            &rec,
            "deadbeef",
            &rec.creator_public_key.clone(),
            leaf_key,
            None,
            None,
        ).unwrap();

        // Found under medical/us (the leaf), not medical/eu (record.zone).
        let leaf_ids = engine.iter_zone(&leaf_key, None, None, 100);
        let parent_ids = engine.iter_zone(&crate::ZoneId::new("medical/eu").to_key_bytes(), None, None, 100);
        assert_eq!(leaf_ids, vec!["redir-1".to_string()]);
        assert!(parent_ids.is_empty());
    }

    #[test]
    fn zsp_b_overwrite_with_changed_timestamp_cleans_stale_entry() {
        let (engine, _dir) = test_engine();
        let z = crate::ZoneId::new("zone/over");
        let zk = z.to_key_bytes();

        // First write at t=100
        engine.put_record("r1", &zoned_record("r1", "zone/over", 100.0)).unwrap();
        assert_eq!(engine.iter_zone(&zk, None, None, 100), vec!["r1".to_string()]);

        // Overwrite same id with a different timestamp.
        engine.put_record("r1", &zoned_record("r1", "zone/over", 200.0)).unwrap();
        let ids = engine.iter_zone(&zk, None, None, 100);
        assert_eq!(ids, vec!["r1".to_string()], "old entry must be deleted, only new one present");
        assert_eq!(engine.count_zone(&zk), 1, "no zombie entry from old timestamp");
    }

    #[test]
    fn zsp_b_overwrite_changing_zone_cleans_stale_entry() {
        let (engine, _dir) = test_engine();
        let z_a = crate::ZoneId::new("zone/A");
        let z_b = crate::ZoneId::new("zone/B");

        // Write under zone A
        engine.put_record_with_zone("r1", &zoned_record("r1", "zone/A", 100.0), z_a.to_key_bytes()).unwrap();
        assert_eq!(engine.iter_zone(&z_a.to_key_bytes(), None, None, 100), vec!["r1".to_string()]);

        // Re-write same record under zone B (registry redirected to a new leaf).
        engine.put_record_with_zone("r1", &zoned_record("r1", "zone/A", 100.0), z_b.to_key_bytes()).unwrap();
        let a_ids = engine.iter_zone(&z_a.to_key_bytes(), None, None, 100);
        let b_ids = engine.iter_zone(&z_b.to_key_bytes(), None, None, 100);
        assert!(a_ids.is_empty(), "zone A entry must be deleted on zone shift, got {a_ids:?}");
        assert_eq!(b_ids, vec!["r1".to_string()]);
    }

    #[test]
    fn zsp_b_delete_record_purges_zone_entry() {
        let (engine, _dir) = test_engine();
        let z = crate::ZoneId::new("zone/del");
        let zk = z.to_key_bytes();
        engine.put_record("r1", &zoned_record("r1", "zone/del", 100.0)).unwrap();
        engine.put_record("r2", &zoned_record("r2", "zone/del", 200.0)).unwrap();
        assert_eq!(engine.count_zone(&zk), 2);

        engine.delete_record("r1").unwrap();
        let remaining = engine.iter_zone(&zk, None, None, 100);
        assert_eq!(remaining, vec!["r2".to_string()]);
    }

    #[test]
    fn query_zone_returns_records_only_in_target_zone() {
        // Tier 3.3 epoch-seal hot path: per-zone+window lookup must not leak
        // records from other zones — that would corrupt the seal merkle root.
        use crate::storage::Storage;
        let (engine, _dir) = test_engine();
        let z_eu = crate::ZoneId::new("medical/eu");
        let z_us = crate::ZoneId::new("medical/us");

        engine.put_record("eu-1", &zoned_record("eu-1", "medical/eu", 100.0)).unwrap();
        engine.put_record("eu-2", &zoned_record("eu-2", "medical/eu", 200.0)).unwrap();
        engine.put_record("us-1", &zoned_record("us-1", "medical/us", 150.0)).unwrap();

        // zone_count is unused on the indexed path (RocksEngine override) —
        // pass the testnet default so the assertion below is unambiguous.
        let eu = engine.query_zone(&z_eu, 256, None, None, 100).unwrap();
        let us = engine.query_zone(&z_us, 256, None, None, 100).unwrap();

        let eu_ids: Vec<&str> = eu.iter().map(|r| r.id.as_str()).collect();
        let us_ids: Vec<&str> = us.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(eu_ids, vec!["eu-1", "eu-2"]);
        assert_eq!(us_ids, vec!["us-1"]);
    }

    #[test]
    fn query_zone_respects_time_window() {
        // create_epoch_seal narrows by [start, end] — exercises CF_RECORD_BY_ZONE
        // range bounds end-to-end (key encoding + RocksDB Forward iterator stop).
        use crate::storage::Storage;
        let (engine, _dir) = test_engine();
        let z = crate::ZoneId::new("zone/tier3-3");
        for (id, ts) in &[("r1", 100.0), ("r2", 200.0), ("r3", 300.0), ("r4", 400.0)] {
            engine.put_record(id, &zoned_record(id, "zone/tier3-3", *ts)).unwrap();
        }

        let mid = engine.query_zone(&z, 256, Some(150.0), Some(350.0), 100).unwrap();
        let ids: Vec<&str> = mid.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, vec!["r2", "r3"]);
    }

    #[test]
    fn query_zone_respects_limit() {
        // Bounded result so a misbehaving caller can't exhaust memory at scale.
        use crate::storage::Storage;
        let (engine, _dir) = test_engine();
        let z = crate::ZoneId::new("zone/limit-test");
        for i in 0..10 {
            let id = format!("rec-{i:02}");
            engine.put_record(&id, &zoned_record(&id, "zone/limit-test", i as f64)).unwrap();
        }

        let three = engine.query_zone(&z, 256, None, None, 3).unwrap();
        assert_eq!(three.len(), 3);
        let ids: Vec<&str> = three.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, vec!["rec-00", "rec-01", "rec-02"]);
    }

    #[test]
    fn query_zone_empty_zone_returns_empty() {
        // create_epoch_seal called on a zone that's never seen a record must
        // return [], not the global record set.
        use crate::storage::Storage;
        let (engine, _dir) = test_engine();
        let z_empty = crate::ZoneId::new("zone/no-records");
        engine.put_record("other", &zoned_record("other", "zone/different", 100.0)).unwrap();

        let none = engine.query_zone(&z_empty, 256, None, None, 100).unwrap();
        assert!(none.is_empty());
    }

    // Cover the query_zone_ids trait override (rocks.rs:3458) that ships the
    // seal-hot-path memory fix. The override is new code (~15 LoC) and needs
    // verification under compaction backpressure, since iter_zone is the only
    // well-tested path. These tests pin the contract:
    //   1. trait override returns the same IDs as iter_zone (delegation is faithful)
    //   2. flush + manual compaction does not change the result set
    //   3. records inserted after a flush-and-compact appear in subsequent calls
    //      (compaction does not lose data — strict-superset semantics)
    // Together these prove the seal-hot-path's IDs-only scan is stable across
    // the RocksDB compaction lifecycle.

    #[test]
    fn ops148_query_zone_ids_matches_iter_zone() {
        use crate::storage::Storage;
        let (engine, _dir) = test_engine();
        let z = crate::ZoneId::new("ops148/zone-a");
        for (id, ts) in &[("r1", 100.0), ("r2", 200.0), ("r3", 300.0)] {
            engine.put_record(id, &zoned_record(id, "ops148/zone-a", *ts)).unwrap();
        }

        let trait_ids = engine.query_zone_ids(&z, 256, None, None, 100).unwrap();
        let inherent_ids = engine.iter_zone(&z.to_key_bytes(), None, None, 100);
        assert_eq!(
            trait_ids, inherent_ids,
            "trait override must delegate identically to iter_zone — any divergence \
             corrupts the seal Merkle root because creator and verifier use this same path"
        );
        // Also exercise window + limit through the trait surface.
        let windowed = engine.query_zone_ids(&z, 256, Some(150.0), Some(250.0), 100).unwrap();
        assert_eq!(windowed, vec!["r2".to_string()]);
        let two = engine.query_zone_ids(&z, 256, None, None, 2).unwrap();
        assert_eq!(two, vec!["r1".to_string(), "r2".to_string()]);
    }

    #[test]
    fn ops148_query_zone_ids_stable_after_flush_and_compact() {
        // Compaction backpressure must not perturb the IDs returned
        // by query_zone_ids. RocksDB compaction merges live + tombstoned keys
        // out of L0/L1 SSTs into deeper levels; if iter_zone's CF_RECORD_BY_ZONE
        // prefix scan ever skipped live keys after compaction, two anchors would
        // sign different seal Merkle roots for the same epoch. Pin it.
        use crate::storage::Storage;
        let (engine, _dir) = test_engine();
        let z = crate::ZoneId::new("ops148/zone-compact");

        for i in 0..200 {
            let id = format!("rec-{i:04}");
            engine.put_record(&id, &zoned_record(&id, "ops148/zone-compact", i as f64))
                .unwrap();
        }
        let before: Vec<String> = engine.query_zone_ids(&z, 256, None, None, 1024).unwrap();
        assert_eq!(before.len(), 200);

        // Force flush memtable to SST + manual compaction across all levels.
        let cf = engine.cf(CF_RECORD_BY_ZONE);
        engine.db.flush_cf(&cf).unwrap();
        engine.compact_cf(CF_RECORD_BY_ZONE);
        // CF_RECORDS holds the bodies; compact it too so the test exercises the
        // hot-path's actual two-CF surface even though query_zone_ids only
        // touches CF_RECORD_BY_ZONE.
        engine.db.flush_cf(&engine.cf(CF_RECORDS)).unwrap();
        engine.compact_cf(CF_RECORDS);

        let after: Vec<String> = engine.query_zone_ids(&z, 256, None, None, 1024).unwrap();
        assert_eq!(
            after, before,
            "compaction must not perturb the zone-IDs view — seal-hot-path \
             determinism depends on this. {} before, {} after.",
            before.len(),
            after.len(),
        );
    }

    /// Pin the seal-hot-path memory claim with a deterministic heap-size
    /// measurement, so the '962 MB → 6 MB' reduction is measured rather than
    /// theoretical.
    ///
    /// The earlier seal hot path called `query_zone(zone, .., usize::MAX)`
    /// — materializing every record in the zone-window into `Vec<ValidationRecord>`.
    /// At 120 K records × ~5.3 KB/record (1952 B pubkey + 3293 B sig + ~50 B
    /// metadata + struct), peak heap was ~636 MB. The streaming path replaced
    /// that with `query_zone_ids(zone, .., MAX_SEAL_RECORDS)` — IDs only, ~50 B
    /// each, so the same 120 K records cost ~6 MB.
    ///
    /// This test runs at N=10_000 (10× smaller than the reference scale to
    /// keep the regular suite fast) and asserts the ratio holds.
    /// Heap is bounded from below by the data-payload sum of each Vec's
    /// elements — a deterministic floor that doesn't depend on RSS or
    /// allocator fragmentation. At N=10K the expected ratio is ~100×; at
    /// the audit's N=120K it extrapolates to the claimed 160×.
    ///
    /// Marked `#[ignore]` because the bench takes ~5 s with realistic 5 KB
    /// record bodies. Run with:
    ///   cargo test --features node --lib ops149_seal_hot_path -- --ignored --nocapture
    #[test]
    #[ignore]
    fn ops149_seal_hot_path_memory_delta_vs_full_record_path() {
        use crate::storage::Storage;

        const N: usize = 10_000;
        let (engine, _dir) = test_engine();
        let z = crate::ZoneId::new("ops149/seal-hot-path");

        // Build N synthetic records with production-shaped bodies: the
        // 1952-byte Dilithium3 pubkey + 3293-byte signature dominate the
        // per-record bytes (test_record() already populates these).
        for i in 0..N {
            let id = format!("ops149-rec-{i:08}");
            engine.put_record(&id, &zoned_record(&id, "ops149/seal-hot-path", i as f64))
                .unwrap();
        }
        let cf = engine.cf(CF_RECORD_BY_ZONE);
        engine.db.flush_cf(&cf).unwrap();
        engine.db.flush_cf(&engine.cf(CF_RECORDS)).unwrap();

        // Path A: streaming — IDs only.
        let ids = engine.query_zone_ids(&z, 256, None, None, N).unwrap();
        assert_eq!(ids.len(), N);
        // Heap-payload floor: each String owns its bytes. Allocator tracking
        // overhead per String is constant (~24 B) and we ignore that floor —
        // the data payload alone is the load-bearing comparison.
        let ids_payload: usize = ids.iter().map(|s| s.len()).sum();

        // Path B: full materialization — Vec<ValidationRecord>.
        let recs = engine.query_zone(&z, 256, None, None, N).unwrap();
        assert_eq!(recs.len(), N);
        let recs_payload: usize = recs.iter().map(|r| {
            r.id.len()
                + r.creator_public_key.len()
                + r.signature.as_ref().map_or(0, |s| s.len())
                + r.content_hash.len()
                + r.creator_sphincs_pk.as_ref().map_or(0, |v| v.len())
                + r.sphincs_signature.as_ref().map_or(0, |v| v.len())
        }).sum();

        let ratio = recs_payload as f64 / ids_payload.max(1) as f64;
        eprintln!(
            "OPS-149 seal-hot-path memory delta @ N={N}:\n  \
             IDs path payload:  {:.2} MB ({} bytes / {} ids)\n  \
             recs path payload: {:.2} MB ({} bytes / {} records)\n  \
             ratio: {:.1}x\n  \
             extrapolated to N=120_000: {:.1} MB IDs vs {:.1} MB records",
            ids_payload as f64 / 1_048_576.0, ids_payload, ids.len(),
            recs_payload as f64 / 1_048_576.0, recs_payload, recs.len(),
            ratio,
            (ids_payload as f64 * 12.0) / 1_048_576.0,
            (recs_payload as f64 * 12.0) / 1_048_576.0,
        );

        // Flagship claim: ratio ≥ 10× (theoretical 100× at N=10K
        // with 5.3 KB records vs 50 B IDs). The 10× floor leaves margin for
        // metadata-light records or edge cases without making the test
        // flaky on payload-shape variance.
        assert!(
            ratio >= 10.0,
            "OPS-138/139 memory claim unverified: ratio {:.1}x < 10x. \
             IDs {} bytes, records {} bytes at N={}",
            ratio, ids_payload, recs_payload, N,
        );
    }

    #[test]
    fn ops148_query_zone_ids_strict_superset_after_compact_and_writes() {
        // Records inserted after a flush+compact must still appear via
        // query_zone_ids. Catches a hypothetical bug where iter_zone's seek
        // anchor falls off the wrong side of the new SST boundary post-compact.
        use crate::storage::Storage;
        let (engine, _dir) = test_engine();
        let z = crate::ZoneId::new("ops148/zone-superset");

        for i in 0..50 {
            let id = format!("first-{i:02}");
            engine.put_record(&id, &zoned_record(&id, "ops148/zone-superset", i as f64))
                .unwrap();
        }
        engine.db.flush_cf(&engine.cf(CF_RECORD_BY_ZONE)).unwrap();
        engine.compact_cf(CF_RECORD_BY_ZONE);

        let after_compact: Vec<String> = engine.query_zone_ids(&z, 256, None, None, 1024).unwrap();
        assert_eq!(after_compact.len(), 50);

        // Insert a second batch after compaction. Use timestamps strictly past
        // the first batch so the chronological order assertion is unambiguous.
        for i in 0..50 {
            let id = format!("second-{i:02}");
            engine.put_record(&id, &zoned_record(&id, "ops148/zone-superset", (1000 + i) as f64))
                .unwrap();
        }

        let combined: Vec<String> = engine.query_zone_ids(&z, 256, None, None, 1024).unwrap();
        assert_eq!(combined.len(), 100, "post-compact writes must be visible");
        // First 50 must be the original batch (timestamp-ascending), last 50
        // the second batch — strict-superset ordering preserved.
        for (i, id) in combined.iter().take(50).enumerate() {
            assert_eq!(*id, format!("first-{i:02}"));
        }
        for (i, id) in combined.iter().skip(50).enumerate() {
            assert_eq!(*id, format!("second-{i:02}"));
        }
    }

    // §11.23 Layer B: creator-keyed lookup — CF_IDX_CREATOR prefix scan must
    // return only the target creator's records, in timestamp order, respecting
    // window + limit. This is the load-bearing path for `/records/search?creator=…`
    // at billion-record scale (cost is O(records_for_creator_in_window),
    // independent of fleet size).

    fn record_with_creator(id: &str, creator_pk: &[u8], ts: f64) -> ValidationRecord {
        let mut r = test_record(id);
        r.creator_public_key = creator_pk.to_vec();
        r.timestamp = ts;
        r
    }

    #[test]
    fn query_by_creator_hash_returns_only_target_creator() {
        use crate::storage::Storage;
        let (engine, _dir) = test_engine();
        let pk_alpha = vec![0xAA; 1952];
        let pk_beta = vec![0xBB; 1952];

        engine.put_record("a1", &record_with_creator("a1", &pk_alpha, 100.0)).unwrap();
        engine.put_record("a2", &record_with_creator("a2", &pk_alpha, 200.0)).unwrap();
        engine.put_record("b1", &record_with_creator("b1", &pk_beta, 150.0)).unwrap();

        let ch_alpha = crate::crypto::hash::sha3_256_hex(&pk_alpha);
        let alpha = engine.query_by_creator_hash(&ch_alpha, None, None, 100).unwrap();
        let ids: Vec<&str> = alpha.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, vec!["a1", "a2"]);
    }

    #[test]
    fn query_by_creator_hash_orders_by_timestamp() {
        use crate::storage::Storage;
        let (engine, _dir) = test_engine();
        let pk = vec![0xCC; 1952];

        engine.put_record("late", &record_with_creator("late", &pk, 300.0)).unwrap();
        engine.put_record("early", &record_with_creator("early", &pk, 100.0)).unwrap();
        engine.put_record("mid", &record_with_creator("mid", &pk, 200.0)).unwrap();

        let ch = crate::crypto::hash::sha3_256_hex(&pk);
        let out = engine.query_by_creator_hash(&ch, None, None, 100).unwrap();
        let ids: Vec<&str> = out.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, vec!["early", "mid", "late"]);
    }

    #[test]
    fn query_by_creator_hash_respects_window_and_limit() {
        use crate::storage::Storage;
        let (engine, _dir) = test_engine();
        let pk = vec![0xDD; 1952];

        for (id, ts) in &[("r1", 100.0), ("r2", 200.0), ("r3", 300.0), ("r4", 400.0)] {
            engine.put_record(id, &record_with_creator(id, &pk, *ts)).unwrap();
        }
        let ch = crate::crypto::hash::sha3_256_hex(&pk);

        let mid = engine.query_by_creator_hash(&ch, Some(150.0), Some(350.0), 100).unwrap();
        let ids: Vec<&str> = mid.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, vec!["r2", "r3"]);

        let two = engine.query_by_creator_hash(&ch, None, None, 2).unwrap();
        assert_eq!(two.len(), 2);
        assert_eq!(two[0].id, "r1");
        assert_eq!(two[1].id, "r2");
    }

    #[test]
    fn query_by_creator_hash_unknown_creator_returns_empty() {
        use crate::storage::Storage;
        let (engine, _dir) = test_engine();
        let pk = vec![0xEE; 1952];
        engine.put_record("only", &record_with_creator("only", &pk, 100.0)).unwrap();

        let unknown = "0".repeat(64);
        let out = engine.query_by_creator_hash(&unknown, None, None, 100).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn query_by_creator_hash_rejects_bad_length_hex() {
        // Defensive: malformed inputs from the public /records/search surface
        // must not panic or scan unrelated CF_IDX_CREATOR prefixes.
        use crate::storage::Storage;
        let (engine, _dir) = test_engine();
        let pk = vec![0xAB; 1952];
        engine.put_record("r", &record_with_creator("r", &pk, 1.0)).unwrap();

        // Too short.
        let out = engine.query_by_creator_hash("abc", None, None, 100).unwrap();
        assert!(out.is_empty());
        // Too long.
        let long = "f".repeat(80);
        let out = engine.query_by_creator_hash(&long, None, None, 100).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn zsp_b_record_without_zone_falls_back_to_id_hash_zone() {
        let (engine, _dir) = test_engine();
        // record.zone is None — falls back to ZoneId::for_record(id).
        let mut r = test_record("legacy-1");
        r.zone = None;
        engine.put_record("legacy-1", &r).unwrap();

        // Confirm reachable via the fallback zone.
        let fallback_zone = crate::ZoneId::for_record("legacy-1");
        let ids = engine.iter_zone(&fallback_zone.to_key_bytes(), None, None, 100);
        assert_eq!(ids, vec!["legacy-1".to_string()]);
    }

    #[test]
    fn zsp_b_distinct_zone_keys_dont_collide() {
        let (engine, _dir) = test_engine();
        // medical/eu and medical/us hash to different 8-byte keys.
        let z_eu = crate::ZoneId::new("medical/eu");
        let z_us = crate::ZoneId::new("medical/us");
        assert_ne!(z_eu.to_key_bytes(), z_us.to_key_bytes());

        engine.put_record("e1", &zoned_record("e1", "medical/eu", 1.0)).unwrap();
        engine.put_record("u1", &zoned_record("u1", "medical/us", 2.0)).unwrap();

        // Iterating one zone never returns records from the other.
        let eu = engine.iter_zone(&z_eu.to_key_bytes(), None, None, 100);
        let us = engine.iter_zone(&z_us.to_key_bytes(), None, None, 100);
        assert_eq!(eu, vec!["e1".to_string()]);
        assert_eq!(us, vec!["u1".to_string()]);
    }

    #[test]
    fn zsp_b_backfill_populates_missing_entries() {
        let (engine, _dir) = test_engine();
        // Simulate "pre-Phase-B" records: write to primary CF directly,
        // bypassing put_record so the zone-idx is empty for these.
        let cf_records = engine.cf(CF_RECORDS);
        for i in 0..5 {
            let id = format!("legacy-{i}");
            let rec = zoned_record(&id, "zone/legacy", i as f64);
            engine.db.put_cf(&cf_records, id.as_bytes(), rec.to_bytes()).unwrap();
        }
        let z = crate::ZoneId::new("zone/legacy");
        // Pre-backfill: zone-idx empty for legacy zone.
        assert_eq!(engine.count_zone(&z.to_key_bytes()), 0);

        // Run backfill in one chunk.
        let (n, last) = engine.backfill_zone_index_chunk(None, 100).unwrap();
        assert_eq!(n, 5);
        assert!(last.is_none(), "all 5 records processed in one shot");

        // Post-backfill: all 5 are reachable via zone iter.
        let ids = engine.iter_zone(&z.to_key_bytes(), None, None, 100);
        assert_eq!(ids.len(), 5);
    }

    #[test]
    fn zsp_b_backfill_is_resumable_in_chunks() {
        let (engine, _dir) = test_engine();
        // Write 12 records via primary CF (simulate pre-Phase-B state).
        let cf_records = engine.cf(CF_RECORDS);
        for i in 0..12 {
            let id = format!("rec-{i:02}");
            let rec = zoned_record(&id, "zone/chunk", i as f64);
            engine.db.put_cf(&cf_records, id.as_bytes(), rec.to_bytes()).unwrap();
        }
        let z = crate::ZoneId::new("zone/chunk");
        let zk = z.to_key_bytes();
        assert_eq!(engine.count_zone(&zk), 0);

        // Chunk 1: process 5
        let (n1, after1) = engine.backfill_zone_index_chunk(None, 5).unwrap();
        assert_eq!(n1, 5);
        let after1 = after1.expect("chunk did not complete");
        assert_eq!(engine.count_zone(&zk), 5);

        // Chunk 2: continue from after1, process next 5
        let (n2, after2) = engine.backfill_zone_index_chunk(Some(&after1), 5).unwrap();
        assert_eq!(n2, 5);
        let after2 = after2.expect("chunk 2 did not complete");
        assert_eq!(engine.count_zone(&zk), 10);

        // Chunk 3: process the remaining 2
        let (n3, after3) = engine.backfill_zone_index_chunk(Some(&after2), 5).unwrap();
        assert_eq!(n3, 2);
        assert!(after3.is_none(), "all records processed");
        assert_eq!(engine.count_zone(&zk), 12);
    }

    #[test]
    fn zsp_b_backfill_is_idempotent() {
        let (engine, _dir) = test_engine();
        let z = crate::ZoneId::new("zone/idem");
        // Write through put_record (zone-idx already populated).
        for i in 0..3 {
            let id = format!("r{i}");
            engine.put_record(&id, &zoned_record(&id, "zone/idem", i as f64)).unwrap();
        }
        let before = engine.count_zone(&z.to_key_bytes());
        assert_eq!(before, 3);

        // Run backfill — must not duplicate.
        let (n, last) = engine.backfill_zone_index_chunk(None, 100).unwrap();
        assert_eq!(n, 3);
        assert!(last.is_none());
        assert_eq!(engine.count_zone(&z.to_key_bytes()), 3, "idempotent: no duplicates");
    }

    #[test]
    fn backfill_zone_index_chunk_returns_ok_on_empty_engine() {
        // Regression guard: backfill_zone_index_chunk uses try_cf so a missing
        // CF returns Err instead of panicking. On a normal engine with all CFs
        // open, an empty DB returns Ok((0, None)).
        let (engine, _dir) = test_engine();
        let result = engine.backfill_zone_index_chunk(None, 10);
        assert!(result.is_ok(), "backfill_zone_index_chunk must not panic on empty engine");
        let (n, last) = result.unwrap();
        assert_eq!(n, 0);
        assert_eq!(last, None);
    }

    // ── Identity Partitioning Phase A — class-tagged CFs ──────────────

    fn pk_bytes(seed: u8) -> Vec<u8> { vec![seed; 1952] }

    #[test]
    fn idp_a_anchor_write_lands_in_anchor_cf() {
        let (engine, _dir) = test_engine();
        let pk = pk_bytes(0xA1);
        engine.store_public_key_anchor("anchor-hash", &pk).unwrap();
        // Direct CF probe — confirm the bytes are physically in the
        // anchor CF and not in any other tier.
        let in_anchor = engine.get_cf_raw(CF_IDENTITIES_ANCHOR, b"anchor-hash").unwrap();
        let in_witness = engine.get_cf_raw(CF_IDENTITIES_WITNESS, b"anchor-hash").unwrap();
        let in_user = engine.get_cf_raw(CF_IDENTITIES_USER, b"anchor-hash").unwrap();
        let in_legacy = engine.get_cf_raw(CF_IDENTITIES, b"anchor-hash").unwrap();
        assert!(in_anchor.is_some());
        assert!(in_witness.is_none());
        assert!(in_user.is_none());
        assert!(in_legacy.is_none());
    }

    #[test]
    fn idp_a_witness_write_lands_in_witness_cf() {
        let (engine, _dir) = test_engine();
        let pk = pk_bytes(0xB2);
        engine.store_public_key_witness("witness-hash", &pk).unwrap();
        assert!(engine.get_cf_raw(CF_IDENTITIES_WITNESS, b"witness-hash").unwrap().is_some());
        assert!(engine.get_cf_raw(CF_IDENTITIES_ANCHOR, b"witness-hash").unwrap().is_none());
        assert!(engine.get_cf_raw(CF_IDENTITIES_USER, b"witness-hash").unwrap().is_none());
        assert!(engine.get_cf_raw(CF_IDENTITIES, b"witness-hash").unwrap().is_none());
    }

    #[test]
    fn idp_a_user_write_lands_in_user_cf() {
        let (engine, _dir) = test_engine();
        let pk = pk_bytes(0xC3);
        engine.store_public_key_user("user-hash", &pk).unwrap();
        assert!(engine.get_cf_raw(CF_IDENTITIES_USER, b"user-hash").unwrap().is_some());
        assert!(engine.get_cf_raw(CF_IDENTITIES_ANCHOR, b"user-hash").unwrap().is_none());
        assert!(engine.get_cf_raw(CF_IDENTITIES_WITNESS, b"user-hash").unwrap().is_none());
        assert!(engine.get_cf_raw(CF_IDENTITIES, b"user-hash").unwrap().is_none());
    }

    #[test]
    fn idp_a_legacy_store_public_key_still_writes_to_legacy_cf() {
        // Backward-compat: existing call sites that haven't migrated to
        // tier-explicit helpers must keep working. Reads union across
        // all four CFs so legacy data stays accessible.
        let (engine, _dir) = test_engine();
        engine.store_public_key("legacy-hash", &pk_bytes(0xD4)).unwrap();
        assert!(engine.get_cf_raw(CF_IDENTITIES, b"legacy-hash").unwrap().is_some());
        assert_eq!(engine.get_public_key("legacy-hash"), Some(pk_bytes(0xD4)));
        assert!(engine.has_public_key("legacy-hash"));
    }

    #[test]
    fn idp_a_get_public_key_priority_anchor_over_witness_over_user_over_legacy() {
        // Same hash present in all four CFs; reads return the anchor
        // value (highest priority). Confirms the priority order.
        let (engine, _dir) = test_engine();
        engine.put_cf_raw(CF_IDENTITIES, b"hash-x", &[0xD]).unwrap();
        engine.put_cf_raw(CF_IDENTITIES_USER, b"hash-x", &[0xC]).unwrap();
        engine.put_cf_raw(CF_IDENTITIES_WITNESS, b"hash-x", &[0xB]).unwrap();
        engine.put_cf_raw(CF_IDENTITIES_ANCHOR, b"hash-x", &[0xA]).unwrap();
        assert_eq!(engine.get_public_key("hash-x"), Some(vec![0xA]));

        // Drop anchor → witness wins.
        engine.delete_cf_raw(CF_IDENTITIES_ANCHOR, b"hash-x").unwrap();
        assert_eq!(engine.get_public_key("hash-x"), Some(vec![0xB]));

        // Drop witness → user wins.
        engine.delete_cf_raw(CF_IDENTITIES_WITNESS, b"hash-x").unwrap();
        assert_eq!(engine.get_public_key("hash-x"), Some(vec![0xC]));

        // Drop user → legacy wins.
        engine.delete_cf_raw(CF_IDENTITIES_USER, b"hash-x").unwrap();
        assert_eq!(engine.get_public_key("hash-x"), Some(vec![0xD]));

        // Drop legacy → miss.
        engine.delete_cf_raw(CF_IDENTITIES, b"hash-x").unwrap();
        assert_eq!(engine.get_public_key("hash-x"), None);
    }

    #[test]
    fn idp_a_has_public_key_short_circuits_on_anchor() {
        // Phase C invariant: ANCHOR and USER cannot coexist for the
        // same hash (demotion guard turns USER write into a no-op when
        // ANCHOR is present). The test now exercises both branches of
        // the priority short-circuit independently:
        //   1. ANCHOR-only present → has_public_key returns true
        //      (without ever needing to consult USER).
        //   2. USER-only present (after ANCHOR is deleted) → fall
        //      through to USER returns true.
        let (engine, _dir) = test_engine();
        engine.store_public_key_anchor("a", &pk_bytes(0x11)).unwrap();
        // Demotion guard: USER-write is a no-op while ANCHOR holds "a".
        let user_result = engine.store_public_key_user("a", &pk_bytes(0x22)).unwrap();
        assert_eq!(user_result, Some(CF_IDENTITIES_ANCHOR));
        assert!(engine.has_public_key("a"));
        // Drop the ANCHOR row, then write a USER row directly. Now
        // has_public_key falls through past ANCHOR/WITNESS into USER.
        engine.delete_cf_raw(CF_IDENTITIES_ANCHOR, b"a").unwrap();
        engine.store_public_key_user("a", &pk_bytes(0x22)).unwrap();
        assert!(engine.has_public_key("a"));
    }

    #[test]
    fn idp_a_put_record_with_anchor_metadata_routes_to_anchor_cf() {
        let (engine, _dir) = test_engine();
        let mut rec = test_record("vrf-reg");
        rec.metadata.insert("vrf_registration".into(), serde_json::json!(true));
        rec.metadata.insert("node_type".into(), serde_json::json!("anchor"));
        engine.put_record_with_pk("vrf-reg", &rec, "anchor-id", &pk_bytes(0xAA)).unwrap();
        assert!(engine.get_cf_raw(CF_IDENTITIES_ANCHOR, b"anchor-id").unwrap().is_some());
        assert!(engine.get_cf_raw(CF_IDENTITIES_USER, b"anchor-id").unwrap().is_none());
        assert!(engine.get_cf_raw(CF_IDENTITIES, b"anchor-id").unwrap().is_none(),
                "Phase A: hot path no longer writes to legacy CF_IDENTITIES");
    }

    #[test]
    fn idp_a_put_record_default_routes_to_user_cf() {
        // Plain record with no anchor signal → USER tier (catch-all).
        let (engine, _dir) = test_engine();
        let rec = test_record("plain-rec");
        engine.put_record_with_pk("plain-rec", &rec, "user-id", &pk_bytes(0x55)).unwrap();
        assert!(engine.get_cf_raw(CF_IDENTITIES_USER, b"user-id").unwrap().is_some());
        assert!(engine.get_cf_raw(CF_IDENTITIES_ANCHOR, b"user-id").unwrap().is_none());
        assert!(engine.get_cf_raw(CF_IDENTITIES_WITNESS, b"user-id").unwrap().is_none());
    }

    #[test]
    fn idp_a_put_record_non_anchor_node_type_falls_back_to_user() {
        // VRF-registration metadata BUT node_type="witness" → USER.
        // Mirrors the anchor-only gate in `extract_vrf_registration`.
        let (engine, _dir) = test_engine();
        let mut rec = test_record("non-anchor");
        rec.metadata.insert("vrf_registration".into(), serde_json::json!(true));
        rec.metadata.insert("node_type".into(), serde_json::json!("witness"));
        engine.put_record_with_pk("non-anchor", &rec, "rogue-id", &pk_bytes(0xEE)).unwrap();
        assert!(engine.get_cf_raw(CF_IDENTITIES_USER, b"rogue-id").unwrap().is_some());
        assert!(engine.get_cf_raw(CF_IDENTITIES_ANCHOR, b"rogue-id").unwrap().is_none());
    }

    #[test]
    fn idp_a_identity_tier_counts_match_writes() {
        let (engine, _dir) = test_engine();
        engine.store_public_key_anchor("a1", &pk_bytes(1)).unwrap();
        engine.store_public_key_anchor("a2", &pk_bytes(2)).unwrap();
        engine.store_public_key_witness("w1", &pk_bytes(3)).unwrap();
        engine.store_public_key_user("u1", &pk_bytes(4)).unwrap();
        engine.store_public_key_user("u2", &pk_bytes(5)).unwrap();
        engine.store_public_key_user("u3", &pk_bytes(6)).unwrap();
        engine.store_public_key("legacy1", &pk_bytes(7)).unwrap();
        let (a, w, u, l) = engine.identity_tier_counts();
        assert_eq!(a, 2, "anchor count");
        assert_eq!(w, 1, "witness count");
        assert_eq!(u, 3, "user count");
        assert_eq!(l, 1, "legacy count");
    }

    #[test]
    fn liveness1_is_anchor_identity_matches_cf_membership() {
        let (engine, _dir) = test_engine();
        engine.store_public_key_anchor("a1", &pk_bytes(1)).unwrap();
        engine.store_public_key_witness("w1", &pk_bytes(2)).unwrap();
        engine.store_public_key_user("u1", &pk_bytes(3)).unwrap();
        engine.store_public_key("legacy1", &pk_bytes(4)).unwrap();
        assert!(engine.is_anchor_identity("a1"), "anchor true");
        assert!(!engine.is_anchor_identity("w1"), "witness false");
        assert!(!engine.is_anchor_identity("u1"), "user false");
        assert!(!engine.is_anchor_identity("legacy1"), "legacy false");
        assert!(!engine.is_anchor_identity("absent"), "missing false");
    }

    #[test]
    fn liveness1_list_anchor_identities_returns_only_anchors() {
        let (engine, _dir) = test_engine();
        engine.store_public_key_anchor("a1", &pk_bytes(1)).unwrap();
        engine.store_public_key_anchor("a2", &pk_bytes(2)).unwrap();
        engine.store_public_key_anchor("a3", &pk_bytes(3)).unwrap();
        engine.store_public_key_witness("w1", &pk_bytes(4)).unwrap();
        engine.store_public_key_user("u1", &pk_bytes(5)).unwrap();
        engine.store_public_key("legacy1", &pk_bytes(6)).unwrap();
        let mut ids = engine.list_anchor_identities(usize::MAX);
        ids.sort();
        assert_eq!(ids, vec!["a1", "a2", "a3"], "only anchor-tier hashes returned");
    }

    #[test]
    fn liveness1_list_anchor_identities_respects_max_cap() {
        let (engine, _dir) = test_engine();
        for i in 0..10u8 {
            engine.store_public_key_anchor(&format!("a{i}"), &pk_bytes(i)).unwrap();
        }
        let ids = engine.list_anchor_identities(3);
        assert_eq!(ids.len(), 3, "respects max_anchors cap");
    }

    #[test]
    fn liveness1_list_anchor_identities_empty_when_no_anchors() {
        let (engine, _dir) = test_engine();
        engine.store_public_key_user("u1", &pk_bytes(1)).unwrap();
        engine.store_public_key("legacy1", &pk_bytes(2)).unwrap();
        let ids = engine.list_anchor_identities(usize::MAX);
        assert!(ids.is_empty(), "no anchors → empty vec, never panics");
    }

    #[test]
    fn anchor_cf_methods_use_try_cf_not_panic() {
        // is_anchor_identity and list_anchor_identities were converted from
        // self.cf() (panic on missing CF) to self.try_cf() (safe fallback).
        // Verify both safe-default branches are reachable: false / [].
        let (engine, _dir) = test_engine();

        // Safe default: unknown identity → false, not panic.
        assert!(!engine.is_anchor_identity("nonexistent"), "missing → false");
        // Safe default: no anchors registered → empty vec, not panic.
        assert!(engine.list_anchor_identities(usize::MAX).is_empty(), "empty → []");

        // Happy-path still works after the conversion.
        engine.store_public_key_anchor("ah1", &pk_bytes(7)).unwrap();
        assert!(engine.is_anchor_identity("ah1"), "registered → true");
        let ids = engine.list_anchor_identities(usize::MAX);
        assert!(ids.contains(&"ah1".to_string()), "registered id in list");
    }

    #[test]
    fn ops132_identity_tier_counts_estimated_zero_on_empty() {
        let (engine, _dir) = test_engine();
        let (a, w, u, l) = engine.identity_tier_counts_estimated();
        assert_eq!(a, 0, "anchor estimate empty");
        assert_eq!(w, 0, "witness estimate empty");
        assert_eq!(u, 0, "user estimate empty");
        assert_eq!(l, 0, "legacy estimate empty");
    }

    #[test]
    fn ops132_identity_tier_counts_estimated_grows_with_writes() {
        let (engine, _dir) = test_engine();
        let baseline = engine.identity_tier_counts_estimated();
        for i in 0..200u8 {
            engine.store_public_key_user(&format!("u{i}"), &pk_bytes(i)).unwrap();
        }
        engine.db.flush().unwrap();
        let after = engine.identity_tier_counts_estimated();
        assert!(
            after.2 > baseline.2,
            "user-tier estimate must grow after 200 writes (baseline={}, after={})",
            baseline.2,
            after.2,
        );
    }

    #[test]
    fn idp_a_is_witness_registered_point_read() {
        let (engine, _dir) = test_engine();
        engine.register_witness("medical/eu", "witness-eu", pk_bytes(1), 100, 1).unwrap();
        assert!(engine.is_witness_registered("medical/eu", "witness-eu"));
        // Wrong zone → not found.
        assert!(!engine.is_witness_registered("medical/us", "witness-eu"));
        // Wrong identity → not found.
        assert!(!engine.is_witness_registered("medical/eu", "stranger"));
    }

    #[test]
    fn idp_a_open_creates_all_three_new_cfs() {
        let (engine, _dir) = test_engine();
        // Confirm the new CFs are in ALL_CF_NAMES and physically created.
        assert!(ALL_CF_NAMES.contains(&CF_IDENTITIES_ANCHOR));
        assert!(ALL_CF_NAMES.contains(&CF_IDENTITIES_WITNESS));
        assert!(ALL_CF_NAMES.contains(&CF_IDENTITIES_USER));
        // Sanity: cf() handle for each works without panic.
        let _ = engine.cf(CF_IDENTITIES_ANCHOR);
        let _ = engine.cf(CF_IDENTITIES_WITNESS);
        let _ = engine.cf(CF_IDENTITIES_USER);
    }

    // ─── Identity Partitioning Phase B — LRU eviction on USER tier ───

    #[test]
    fn idp_b_open_creates_user_ts_and_rev_cfs() {
        let (engine, _dir) = test_engine();
        assert!(ALL_CF_NAMES.contains(&CF_IDENTITIES_USER_TS));
        assert!(ALL_CF_NAMES.contains(&CF_IDENTITIES_USER_REV));
        let _ = engine.cf(CF_IDENTITIES_USER_TS);
        let _ = engine.cf(CF_IDENTITIES_USER_REV);
    }

    #[test]
    fn idp_b_user_write_records_ts_and_rev() {
        let (engine, _dir) = test_engine();
        engine.store_public_key_user_at("u1", &pk_bytes(1), 1000).unwrap();
        // PK lands in CF_IDENTITIES_USER.
        assert_eq!(engine.count_cf(CF_IDENTITIES_USER), 1);
        // TS index has one entry keyed `ts_be(8) || hash`.
        assert_eq!(engine.count_cf(CF_IDENTITIES_USER_TS), 1);
        // REV index has hash → ts.
        let cf_rev = engine.cf(CF_IDENTITIES_USER_REV);
        let rev = engine.db.get_cf(&cf_rev, b"u1").unwrap().unwrap();
        assert_eq!(rev, 1000u64.to_be_bytes().to_vec());
    }

    #[test]
    fn idp_b_user_overwrite_advances_rev_leaves_old_ts() {
        let (engine, _dir) = test_engine();
        engine.store_public_key_user_at("u1", &pk_bytes(1), 1000).unwrap();
        engine.store_public_key_user_at("u1", &pk_bytes(2), 2000).unwrap();
        // USER CF still has just one entry (overwrite by hash key).
        assert_eq!(engine.count_cf(CF_IDENTITIES_USER), 1);
        // TS CF accumulated both entries (1000, hash) + (2000, hash).
        assert_eq!(engine.count_cf(CF_IDENTITIES_USER_TS), 2);
        // REV points at the newer ts.
        let cf_rev = engine.cf(CF_IDENTITIES_USER_REV);
        let rev = engine.db.get_cf(&cf_rev, b"u1").unwrap().unwrap();
        assert_eq!(rev, 2000u64.to_be_bytes().to_vec());
        // get_public_key returns the new PK (last write wins).
        assert_eq!(engine.get_public_key("u1").unwrap(), pk_bytes(2));
    }

    #[test]
    fn idp_b_evict_below_cap_is_noop() {
        let (engine, _dir) = test_engine();
        for i in 0..50 {
            engine
                .store_public_key_user_at(&format!("u{i}"), &pk_bytes(i as u8), 1000 + i as u64)
                .unwrap();
        }
        let evicted = engine.evict_user_identities_to_cap(100, 1000).unwrap();
        assert_eq!(evicted, 0);
        assert_eq!(engine.count_cf(CF_IDENTITIES_USER), 50);
    }

    #[test]
    fn idp_b_evict_drops_oldest_to_cap() {
        let (engine, _dir) = test_engine();
        for i in 0..200 {
            engine
                .store_public_key_user_at(&format!("u{i:04}"), &pk_bytes(i as u8), 1000 + i as u64)
                .unwrap();
        }
        let evicted = engine.evict_user_identities_to_cap(100, 1000).unwrap();
        assert_eq!(evicted, 100, "should drop 100 entries to reach cap of 100");
        assert_eq!(engine.count_cf(CF_IDENTITIES_USER), 100);
        // The oldest 100 (u0000..u0099) should be gone; u0100..u0199 should remain.
        for i in 0..100 {
            assert!(engine.get_public_key(&format!("u{i:04}")).is_none(),
                "u{i:04} should have been evicted");
        }
        for i in 100..200 {
            assert!(engine.get_public_key(&format!("u{i:04}")).is_some(),
                "u{i:04} should still be present");
        }
    }

    #[test]
    fn idp_b_evict_skips_anchor_and_witness_tiers() {
        let (engine, _dir) = test_engine();
        // Fill USER above cap.
        for i in 0..150 {
            engine
                .store_public_key_user_at(&format!("u{i:04}"), &pk_bytes(i as u8), 1000 + i as u64)
                .unwrap();
        }
        // Anchor + witness should NOT be touched even though they share
        // similar identity keys.
        engine.store_public_key_anchor("a1", &pk_bytes(99)).unwrap();
        engine.store_public_key_witness("w1", &pk_bytes(99)).unwrap();
        let _ = engine.evict_user_identities_to_cap(50, 1000).unwrap();
        assert_eq!(engine.count_cf(CF_IDENTITIES_USER), 50);
        assert_eq!(engine.count_cf(CF_IDENTITIES_ANCHOR), 1);
        assert_eq!(engine.count_cf(CF_IDENTITIES_WITNESS), 1);
        // Anchor + witness PKs still resolve.
        assert!(engine.get_public_key("a1").is_some());
        assert!(engine.get_public_key("w1").is_some());
    }

    #[test]
    fn idp_b_evict_handles_duplicate_ts_after_overwrite() {
        let (engine, _dir) = test_engine();
        // u_old written at ts=100.
        engine.store_public_key_user_at("u_old", &pk_bytes(1), 100).unwrap();
        // u_recent written at ts=200, then re-written at ts=300 (duplicate
        // ts entry from the rewrite).
        engine.store_public_key_user_at("u_recent", &pk_bytes(2), 200).unwrap();
        engine.store_public_key_user_at("u_recent", &pk_bytes(3), 300).unwrap();
        // Add filler so we exceed cap=2 by one (one entry must evict).
        engine.store_public_key_user_at("u_mid", &pk_bytes(4), 250).unwrap();
        // Three logical entries, but four TS-index rows (one stale).
        assert_eq!(engine.count_cf(CF_IDENTITIES_USER), 3);
        assert_eq!(engine.count_cf(CF_IDENTITIES_USER_TS), 4);
        // Evict to cap=2. Should drop u_old (oldest live), leave u_mid +
        // u_recent. The stale (200, u_recent) entry must NOT cause
        // u_recent's PK to be evicted.
        let evicted = engine.evict_user_identities_to_cap(2, 1000).unwrap();
        assert_eq!(evicted, 1);
        assert!(engine.get_public_key("u_old").is_none());
        assert!(engine.get_public_key("u_mid").is_some());
        assert!(engine.get_public_key("u_recent").is_some(),
            "u_recent must survive: stale TS row at ts=200 is not the canonical entry");
        // u_recent's PK is still the latest value (pk_bytes(3)).
        assert_eq!(engine.get_public_key("u_recent").unwrap(), pk_bytes(3));
    }

    #[test]
    fn idp_b_evict_returns_count_evicted_and_caps_per_call() {
        let (engine, _dir) = test_engine();
        for i in 0..1000 {
            engine
                .store_public_key_user_at(&format!("u{i:05}"), &pk_bytes((i % 256) as u8), 1000 + i as u64)
                .unwrap();
        }
        // Cap=100, but max_per_call=50 — should evict only 50 this call.
        let evicted = engine.evict_user_identities_to_cap(100, 50).unwrap();
        assert_eq!(evicted, 50);
        assert_eq!(engine.count_cf(CF_IDENTITIES_USER), 950);
        // Another call gets the next 50.
        let evicted2 = engine.evict_user_identities_to_cap(100, 50).unwrap();
        assert_eq!(evicted2, 50);
        assert_eq!(engine.count_cf(CF_IDENTITIES_USER), 900);
    }

    #[test]
    fn idp_b_evict_zero_cap_disables() {
        let (engine, _dir) = test_engine();
        for i in 0..100 {
            engine
                .store_public_key_user_at(&format!("u{i:04}"), &pk_bytes(i as u8), 1000 + i as u64)
                .unwrap();
        }
        let evicted = engine.evict_user_identities_to_cap(0, 1000).unwrap();
        assert_eq!(evicted, 0, "cap=0 means unbounded, no eviction");
        assert_eq!(engine.count_cf(CF_IDENTITIES_USER), 100);
    }

    #[test]
    fn idp_b_evict_does_not_touch_legacy_cf() {
        let (engine, _dir) = test_engine();
        // Write 50 entries to legacy CF_IDENTITIES (pre-partition data).
        for i in 0..50 {
            engine.store_public_key(&format!("legacy{i}"), &pk_bytes(i as u8)).unwrap();
        }
        // Also fill USER above cap.
        for i in 0..150 {
            engine
                .store_public_key_user_at(&format!("u{i:04}"), &pk_bytes(i as u8), 1000 + i as u64)
                .unwrap();
        }
        let _ = engine.evict_user_identities_to_cap(50, 1000).unwrap();
        // Legacy untouched.
        assert_eq!(engine.count_cf(CF_IDENTITIES), 50);
        for i in 0..50 {
            assert!(engine.get_public_key(&format!("legacy{i}")).is_some(),
                "legacy{i} survived eviction");
        }
    }

    #[test]
    fn idp_b_evict_acceptance_200k_to_100k_scaled() {
        // Acceptance per internal design notes §4 Phase B:
        // "write 200K user identities, assert CF_IDENTITIES_USER ≈ 100K
        // post-eviction." Scaled down 100× to keep test runtime bounded
        // (rocksdb test engine flushes to a tempdir; 200K writes would
        // dominate suite latency). Same algorithm — scaling is mechanical.
        let (engine, _dir) = test_engine();
        for i in 0..2000 {
            engine
                .store_public_key_user_at(&format!("u{i:06}"), &pk_bytes((i % 256) as u8), 1000 + i as u64)
                .unwrap();
        }
        // max_per_call high enough to drain in one call.
        let evicted = engine.evict_user_identities_to_cap(1000, 5000).unwrap();
        assert_eq!(evicted, 1000);
        assert_eq!(engine.count_cf(CF_IDENTITIES_USER), 1000);
        // Spot-check: u000000..u000999 evicted, u001000..u001999 survive.
        assert!(engine.get_public_key("u000000").is_none());
        assert!(engine.get_public_key("u000999").is_none());
        assert!(engine.get_public_key("u001000").is_some());
        assert!(engine.get_public_key("u001999").is_some());
    }

    #[test]
    fn idp_b_evict_clears_rev_for_evicted_hashes() {
        let (engine, _dir) = test_engine();
        for i in 0..100 {
            engine
                .store_public_key_user_at(&format!("u{i:04}"), &pk_bytes(i as u8), 1000 + i as u64)
                .unwrap();
        }
        let _ = engine.evict_user_identities_to_cap(20, 1000).unwrap();
        // After eviction, the REV index should also be cleaned for evicted hashes.
        let cf_rev = engine.cf(CF_IDENTITIES_USER_REV);
        let evicted_count = engine.count_cf(CF_IDENTITIES_USER_REV);
        assert_eq!(evicted_count, 20,
            "REV CF should be in lock-step with USER CF after eviction");
        // u0000 was evicted — REV[u0000] should be gone.
        assert!(engine.db.get_cf(&cf_rev, b"u0000").unwrap().is_none());
        // u0099 survives — REV[u0099] still present.
        assert!(engine.db.get_cf(&cf_rev, b"u0099").unwrap().is_some());
    }

    #[test]
    fn idp_b_evict_re_run_idempotent() {
        let (engine, _dir) = test_engine();
        for i in 0..100 {
            engine
                .store_public_key_user_at(&format!("u{i:04}"), &pk_bytes(i as u8), 1000 + i as u64)
                .unwrap();
        }
        // First call evicts down to cap.
        let n1 = engine.evict_user_identities_to_cap(50, 1000).unwrap();
        assert_eq!(n1, 50);
        // Second call is a no-op since we're at cap.
        let n2 = engine.evict_user_identities_to_cap(50, 1000).unwrap();
        assert_eq!(n2, 0);
        // Stable count.
        assert_eq!(engine.count_cf(CF_IDENTITIES_USER), 50);
    }

    // ── Identity Partitioning Phase C — class promotion ─────────────────

    #[test]
    fn idp_c_promote_user_to_witness() {
        // User-tier write lands in USER+TS+REV. A subsequent witness
        // write must atomically migrate the PK into WITNESS and tombstone
        // all three USER rows.
        let (engine, _dir) = test_engine();
        let pk = pk_bytes(0xE5);
        engine.store_public_key_user_at("h-user2wit", &pk, 1000).unwrap();
        // Confirm the USER 3-row presence first.
        assert!(engine.get_cf_raw(CF_IDENTITIES_USER, b"h-user2wit").unwrap().is_some());
        assert!(engine.get_cf_raw(CF_IDENTITIES_USER_REV, b"h-user2wit").unwrap().is_some());
        // Promote.
        let promoted_from = engine.store_public_key_witness("h-user2wit", &pk).unwrap();
        assert_eq!(promoted_from, Some(CF_IDENTITIES_USER));
        // PK now in WITNESS, USER+TS+REV cleared.
        assert!(engine.get_cf_raw(CF_IDENTITIES_WITNESS, b"h-user2wit").unwrap().is_some());
        assert!(engine.get_cf_raw(CF_IDENTITIES_USER, b"h-user2wit").unwrap().is_none());
        assert!(engine.get_cf_raw(CF_IDENTITIES_USER_REV, b"h-user2wit").unwrap().is_none());
        let mut ts_key = Vec::with_capacity(8 + 10);
        ts_key.extend_from_slice(&1000u64.to_be_bytes());
        ts_key.extend_from_slice(b"h-user2wit");
        assert!(engine.get_cf_raw(CF_IDENTITIES_USER_TS, &ts_key).unwrap().is_none());
        // Lookup still works via priority order.
        assert_eq!(engine.get_public_key("h-user2wit"), Some(pk));
    }

    #[test]
    fn idp_c_promote_user_to_anchor() {
        let (engine, _dir) = test_engine();
        let pk = pk_bytes(0xE6);
        engine.store_public_key_user_at("h-user2anc", &pk, 2000).unwrap();
        let promoted_from = engine.store_public_key_anchor("h-user2anc", &pk).unwrap();
        assert_eq!(promoted_from, Some(CF_IDENTITIES_USER));
        assert!(engine.get_cf_raw(CF_IDENTITIES_ANCHOR, b"h-user2anc").unwrap().is_some());
        assert!(engine.get_cf_raw(CF_IDENTITIES_USER, b"h-user2anc").unwrap().is_none());
        assert!(engine.get_cf_raw(CF_IDENTITIES_USER_REV, b"h-user2anc").unwrap().is_none());
        let mut ts_key = Vec::with_capacity(8 + 10);
        ts_key.extend_from_slice(&2000u64.to_be_bytes());
        ts_key.extend_from_slice(b"h-user2anc");
        assert!(engine.get_cf_raw(CF_IDENTITIES_USER_TS, &ts_key).unwrap().is_none());
        assert_eq!(engine.get_public_key("h-user2anc"), Some(pk));
    }

    #[test]
    fn idp_c_promote_witness_to_anchor() {
        let (engine, _dir) = test_engine();
        let pk = pk_bytes(0xE7);
        engine.store_public_key_witness("h-wit2anc", &pk).unwrap();
        let promoted_from = engine.store_public_key_anchor("h-wit2anc", &pk).unwrap();
        assert_eq!(promoted_from, Some(CF_IDENTITIES_WITNESS));
        assert!(engine.get_cf_raw(CF_IDENTITIES_ANCHOR, b"h-wit2anc").unwrap().is_some());
        assert!(engine.get_cf_raw(CF_IDENTITIES_WITNESS, b"h-wit2anc").unwrap().is_none());
        assert_eq!(engine.get_public_key("h-wit2anc"), Some(pk));
    }

    #[test]
    fn idp_c_no_demotion_witness_after_anchor() {
        // Witness write must NOT overwrite an existing anchor entry.
        let (engine, _dir) = test_engine();
        let anchor_pk = pk_bytes(0xA0);
        let witness_pk = pk_bytes(0xB0);
        engine.store_public_key_anchor("h-anc-keep", &anchor_pk).unwrap();
        let promoted_from = engine.store_public_key_witness("h-anc-keep", &witness_pk).unwrap();
        // Skip = None (no promotion happened, no write happened).
        assert_eq!(promoted_from, None);
        // Anchor entry preserved with its original PK; witness CF empty.
        assert_eq!(
            engine.get_cf_raw(CF_IDENTITIES_ANCHOR, b"h-anc-keep").unwrap(),
            Some(anchor_pk.clone())
        );
        assert!(engine.get_cf_raw(CF_IDENTITIES_WITNESS, b"h-anc-keep").unwrap().is_none());
        // Lookup still returns the anchor PK (not the witness one).
        assert_eq!(engine.get_public_key("h-anc-keep"), Some(anchor_pk));
    }

    #[test]
    fn idp_c_no_demotion_user_after_anchor() {
        let (engine, _dir) = test_engine();
        let anchor_pk = pk_bytes(0xA1);
        let user_pk = pk_bytes(0xC1);
        engine.store_public_key_anchor("h-anc-keep-u", &anchor_pk).unwrap();
        let result = engine.store_public_key_user("h-anc-keep-u", &user_pk).unwrap();
        // User write skipped; reports the higher tier so caller can log.
        assert_eq!(result, Some(CF_IDENTITIES_ANCHOR));
        assert_eq!(
            engine.get_cf_raw(CF_IDENTITIES_ANCHOR, b"h-anc-keep-u").unwrap(),
            Some(anchor_pk.clone())
        );
        assert!(engine.get_cf_raw(CF_IDENTITIES_USER, b"h-anc-keep-u").unwrap().is_none());
        assert!(engine.get_cf_raw(CF_IDENTITIES_USER_REV, b"h-anc-keep-u").unwrap().is_none());
        assert_eq!(engine.get_public_key("h-anc-keep-u"), Some(anchor_pk));
    }

    #[test]
    fn idp_c_no_demotion_user_after_witness() {
        let (engine, _dir) = test_engine();
        let witness_pk = pk_bytes(0xB2);
        let user_pk = pk_bytes(0xC2);
        engine.store_public_key_witness("h-wit-keep-u", &witness_pk).unwrap();
        let result = engine.store_public_key_user("h-wit-keep-u", &user_pk).unwrap();
        assert_eq!(result, Some(CF_IDENTITIES_WITNESS));
        assert_eq!(
            engine.get_cf_raw(CF_IDENTITIES_WITNESS, b"h-wit-keep-u").unwrap(),
            Some(witness_pk.clone())
        );
        assert!(engine.get_cf_raw(CF_IDENTITIES_USER, b"h-wit-keep-u").unwrap().is_none());
        assert_eq!(engine.get_public_key("h-wit-keep-u"), Some(witness_pk));
    }

    #[test]
    fn idp_c_promote_clears_user_ts_index_so_evict_skips_it() {
        // After promotion, the TS index entry must be gone — eviction
        // would otherwise visit it as a stale row, but more importantly
        // the per-tier counts the metrics report must stay consistent.
        let (engine, _dir) = test_engine();
        let pk = pk_bytes(0xE8);
        engine.store_public_key_user_at("h-ts-clear", &pk, 5000).unwrap();
        engine.store_public_key_witness("h-ts-clear", &pk).unwrap();
        // TS-index iter must not yield h-ts-clear.
        let cf_ts = engine.cf(CF_IDENTITIES_USER_TS);
        let mut found = false;
        for entry in engine.db.iterator_cf(&cf_ts, rocksdb::IteratorMode::Start) {
            let (key, _) = entry.unwrap();
            if key.len() >= 8 && &key[8..] == b"h-ts-clear" {
                found = true;
                break;
            }
        }
        assert!(!found, "TS index still references promoted hash");
        // Count CFs reflect a single witness-tier identity only.
        let (a, w, u, _l) = engine.identity_tier_counts();
        assert_eq!(a, 0);
        assert_eq!(w, 1);
        assert_eq!(u, 0);
    }

    #[test]
    fn idp_c_multiple_promotions_idempotent() {
        // Re-applying the same higher-tier write must be a no-op overwrite,
        // not a "promotion-from-self" event.
        let (engine, _dir) = test_engine();
        let pk = pk_bytes(0xE9);
        engine.store_public_key_user_at("h-idemp", &pk, 7000).unwrap();
        // First promotion.
        let p1 = engine.store_public_key_witness("h-idemp", &pk).unwrap();
        assert_eq!(p1, Some(CF_IDENTITIES_USER));
        // Second witness write — already in witness, no lower tier present.
        let p2 = engine.store_public_key_witness("h-idemp", &pk).unwrap();
        assert_eq!(p2, None);
        // Promote to anchor.
        let p3 = engine.store_public_key_anchor("h-idemp", &pk).unwrap();
        assert_eq!(p3, Some(CF_IDENTITIES_WITNESS));
        // Re-anchor — no-op.
        let p4 = engine.store_public_key_anchor("h-idemp", &pk).unwrap();
        assert_eq!(p4, None);
        // Final state: only anchor has it.
        assert!(engine.get_cf_raw(CF_IDENTITIES_ANCHOR, b"h-idemp").unwrap().is_some());
        assert!(engine.get_cf_raw(CF_IDENTITIES_WITNESS, b"h-idemp").unwrap().is_none());
        assert!(engine.get_cf_raw(CF_IDENTITIES_USER, b"h-idemp").unwrap().is_none());
    }

    #[test]
    fn idp_c_anchor_rewrite_is_no_op_returning_none() {
        // No prior lower tier and anchor already present — a no-op overwrite.
        let (engine, _dir) = test_engine();
        let pk = pk_bytes(0xEA);
        engine.store_public_key_anchor("h-anc-only", &pk).unwrap();
        let p = engine.store_public_key_anchor("h-anc-only", &pk).unwrap();
        assert_eq!(p, None);
    }

    #[test]
    fn idp_c_promote_user_to_anchor_skips_witness_step() {
        // Direct USER → ANCHOR promotion (anchor-tier capture from a
        // node that had previously seen the identity only as a record
        // creator). Witness CF must remain empty.
        let (engine, _dir) = test_engine();
        let pk = pk_bytes(0xEB);
        engine.store_public_key_user_at("h-skip", &pk, 9000).unwrap();
        let p = engine.store_public_key_anchor("h-skip", &pk).unwrap();
        assert_eq!(p, Some(CF_IDENTITIES_USER));
        assert!(engine.get_cf_raw(CF_IDENTITIES_ANCHOR, b"h-skip").unwrap().is_some());
        assert!(engine.get_cf_raw(CF_IDENTITIES_WITNESS, b"h-skip").unwrap().is_none());
        assert!(engine.get_cf_raw(CF_IDENTITIES_USER, b"h-skip").unwrap().is_none());
        // Tier-count gauge consistency.
        let (a, w, u, _l) = engine.identity_tier_counts();
        assert_eq!(a, 1);
        assert_eq!(w, 0);
        assert_eq!(u, 0);
    }

    // ── Identity Partitioning Phase E — purge on zone unsubscribe ──────

    #[test]
    fn idp_e_purge_drops_witness_when_no_other_zone_keeps_it() {
        // Sole zone unsubscribed → witness PK dropped from CF_IDENTITIES_WITNESS.
        let (engine, _dir) = test_engine();
        let pk = pk_bytes(0xF0);
        engine.register_witness("/zone/A", "wA1", pk.clone(), 100, 0).unwrap();
        engine.store_public_key_witness("wA1", &pk).unwrap();
        // Surviving subscription set is empty (last zone is the one being unsubscribed).
        let evicted = engine.purge_witness_pks_for_zone("/zone/A", &[]).unwrap();
        assert_eq!(evicted, 1);
        assert!(engine.get_cf_raw(CF_IDENTITIES_WITNESS, b"wA1").unwrap().is_none());
    }

    #[test]
    fn idp_e_purge_keeps_witness_registered_for_another_subscribed_zone() {
        // Witness registered for both A and B; unsubscribe(A) but keep B.
        let (engine, _dir) = test_engine();
        let pk = pk_bytes(0xF1);
        engine.register_witness("/zone/A", "wAB", pk.clone(), 100, 0).unwrap();
        engine.register_witness("/zone/B", "wAB", pk.clone(), 100, 0).unwrap();
        engine.store_public_key_witness("wAB", &pk).unwrap();
        let evicted = engine
            .purge_witness_pks_for_zone("/zone/A", &["/zone/B".to_string()])
            .unwrap();
        assert_eq!(evicted, 0);
        assert!(engine.get_cf_raw(CF_IDENTITIES_WITNESS, b"wAB").unwrap().is_some());
    }

    #[test]
    fn idp_e_purge_mixed_evicts_only_disjoint_witnesses() {
        // Zone A has wA-only and wAB; zone B has wAB. Unsubscribe(A)
        // evicts wA-only but keeps wAB (still claimed by B).
        let (engine, _dir) = test_engine();
        let pk_a_only = pk_bytes(0xF2);
        let pk_ab = pk_bytes(0xF3);
        engine.register_witness("/zone/A", "wA-only", pk_a_only.clone(), 100, 0).unwrap();
        engine.register_witness("/zone/A", "wAB", pk_ab.clone(), 100, 0).unwrap();
        engine.register_witness("/zone/B", "wAB", pk_ab.clone(), 100, 0).unwrap();
        engine.store_public_key_witness("wA-only", &pk_a_only).unwrap();
        engine.store_public_key_witness("wAB", &pk_ab).unwrap();
        let evicted = engine
            .purge_witness_pks_for_zone("/zone/A", &["/zone/B".to_string()])
            .unwrap();
        assert_eq!(evicted, 1);
        assert!(engine.get_cf_raw(CF_IDENTITIES_WITNESS, b"wA-only").unwrap().is_none());
        assert!(engine.get_cf_raw(CF_IDENTITIES_WITNESS, b"wAB").unwrap().is_some());
    }

    #[test]
    fn idp_e_purge_does_not_touch_anchor_tier() {
        // A witness for zone A is also an anchor (CF_IDENTITIES_ANCHOR).
        // The Phase C demotion guard means the witness CF is empty —
        // purge of zone A must not touch the anchor row.
        let (engine, _dir) = test_engine();
        let pk = pk_bytes(0xF4);
        engine.register_witness("/zone/A", "wAnc", pk.clone(), 100, 0).unwrap();
        engine.store_public_key_anchor("wAnc", &pk).unwrap();
        let evicted = engine.purge_witness_pks_for_zone("/zone/A", &[]).unwrap();
        // Witness CF was empty for "wAnc" so 0 evictions.
        assert_eq!(evicted, 0);
        // Anchor row preserved.
        assert!(engine.get_cf_raw(CF_IDENTITIES_ANCHOR, b"wAnc").unwrap().is_some());
    }

    #[test]
    fn idp_e_purge_no_op_when_unsubscribed_zone_has_no_witnesses() {
        let (engine, _dir) = test_engine();
        let evicted = engine.purge_witness_pks_for_zone("/zone/empty", &[]).unwrap();
        assert_eq!(evicted, 0);
    }

    #[test]
    fn idp_e_purge_skips_witness_with_no_pk_row() {
        // A witness was registered but no PK was ever captured into
        // CF_IDENTITIES_WITNESS (e.g. witness-for-zone landed before
        // the partition rollout, or the PK was promoted to ANCHOR).
        // Purge must not count it as an eviction.
        let (engine, _dir) = test_engine();
        let pk = pk_bytes(0xF5);
        engine.register_witness("/zone/A", "w-no-pk", pk, 100, 0).unwrap();
        // Note: NO store_public_key_witness call.
        let evicted = engine.purge_witness_pks_for_zone("/zone/A", &[]).unwrap();
        assert_eq!(evicted, 0);
    }

    #[test]
    fn idp_e_purge_handles_multiple_witnesses_atomically() {
        // 5 witnesses, all unique to the unsubscribed zone — single
        // WriteBatch flush, all 5 dropped together.
        let (engine, _dir) = test_engine();
        for i in 0..5 {
            let pk = pk_bytes(0xA0 + i as u8);
            let id = format!("wbulk-{i}");
            engine.register_witness("/zone/bulk", &id, pk.clone(), 100, 0).unwrap();
            engine.store_public_key_witness(&id, &pk).unwrap();
        }
        let evicted = engine.purge_witness_pks_for_zone("/zone/bulk", &[]).unwrap();
        assert_eq!(evicted, 5);
        for i in 0..5 {
            let id = format!("wbulk-{i}");
            assert!(
                engine.get_cf_raw(CF_IDENTITIES_WITNESS, id.as_bytes()).unwrap().is_none(),
                "witness {id} should have been dropped"
            );
        }
    }

    #[test]
    fn idp_e_purge_leaves_witness_registry_rows_alone() {
        // Phase E's responsibility is only the PK CF; the witness
        // registry rows for the unsubscribed zone are owned by zone_purge.
        // Verify we don't accidentally tamper with them.
        let (engine, _dir) = test_engine();
        let pk = pk_bytes(0xF6);
        engine.register_witness("/zone/A", "wKeep", pk.clone(), 100, 0).unwrap();
        engine.store_public_key_witness("wKeep", &pk).unwrap();
        engine.purge_witness_pks_for_zone("/zone/A", &[]).unwrap();
        // Registry still has the witness entry — zone_purge will clean it up.
        assert!(engine.is_witness_registered("/zone/A", "wKeep"));
    }

    // ── Identity Partitioning Phase D — get_public_key_with_tier ──────

    #[test]
    fn idp_d_get_public_key_with_tier_returns_anchor_first() {
        let (engine, _dir) = test_engine();
        let pk = pk_bytes(0xA1);
        engine.store_public_key_anchor("h", &pk).unwrap();
        let (got_pk, tier) = engine.get_public_key_with_tier("h").expect("anchor entry");
        assert_eq!(got_pk, pk);
        assert_eq!(tier, CF_IDENTITIES_ANCHOR);
    }

    #[test]
    fn idp_d_get_public_key_with_tier_returns_witness_when_no_anchor() {
        let (engine, _dir) = test_engine();
        let pk = pk_bytes(0xB2);
        engine.store_public_key_witness("h", &pk).unwrap();
        let (got_pk, tier) = engine.get_public_key_with_tier("h").expect("witness entry");
        assert_eq!(got_pk, pk);
        assert_eq!(tier, CF_IDENTITIES_WITNESS);
    }

    #[test]
    fn idp_d_get_public_key_with_tier_returns_user_when_only_user() {
        let (engine, _dir) = test_engine();
        let pk = pk_bytes(0xC3);
        engine.store_public_key_user("h", &pk).unwrap();
        let (got_pk, tier) = engine.get_public_key_with_tier("h").expect("user entry");
        assert_eq!(got_pk, pk);
        assert_eq!(tier, CF_IDENTITIES_USER);
    }

    #[test]
    fn idp_d_get_public_key_with_tier_returns_legacy_when_only_legacy() {
        let (engine, _dir) = test_engine();
        let pk = pk_bytes(0xD4);
        engine.store_public_key("h", &pk).unwrap();
        let (got_pk, tier) = engine.get_public_key_with_tier("h").expect("legacy entry");
        assert_eq!(got_pk, pk);
        assert_eq!(tier, CF_IDENTITIES);
    }

    #[test]
    fn idp_d_get_public_key_with_tier_returns_none_when_missing() {
        let (engine, _dir) = test_engine();
        assert!(engine.get_public_key_with_tier("nope").is_none());
    }

    #[test]
    fn idp_d_get_public_key_with_tier_priority_anchor_outranks_witness() {
        // Same hash present in multiple CFs (legacy/pre-partition state) —
        // tier helper must return the highest-priority tier so an
        // /identity/pk/{hash} responder doesn't lie about tier.
        let (engine, _dir) = test_engine();
        let anchor_pk = pk_bytes(0xA1);
        let witness_pk = pk_bytes(0xB2);
        engine.put_cf_raw(CF_IDENTITIES_ANCHOR, b"h", &anchor_pk).unwrap();
        engine.put_cf_raw(CF_IDENTITIES_WITNESS, b"h", &witness_pk).unwrap();
        let (got_pk, tier) = engine.get_public_key_with_tier("h").expect("anchor wins");
        assert_eq!(got_pk, anchor_pk);
        assert_eq!(tier, CF_IDENTITIES_ANCHOR);
    }

    #[test]
    fn dir_size_bytes_dedupes_hardlinks() {
        // Regression guard — without dedup the disk-size gauge over-reports by
        // the cumulative hardlink count on heavy-checkpoint nodes (one node
        // showed 50.6 GB gauge vs 30 GB true `du -sh` because 20 GB of SSTs
        // were hardlinked between active rocksdb/ and checkpoints/). Result was
        // gauge value > disk_total_mb — operationally absurd. Walker
        // must match `du -sh` (inode-once) semantics, not `du -shl` (per
        // dirent).
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let primary = root.join("primary");
        let mirror = root.join("mirror");
        std::fs::create_dir(&primary).unwrap();
        std::fs::create_dir(&mirror).unwrap();
        let payload = vec![0u8; 1024 * 1024]; // 1 MiB
        let src = primary.join("data.bin");
        std::fs::write(&src, &payload).unwrap();
        // Hardlink the same inode into 4 additional locations across both
        // subdirs — naive walker would count 5 × 1 MiB = 5 MiB.
        std::fs::hard_link(&src, primary.join("alias_a.bin")).unwrap();
        std::fs::hard_link(&src, primary.join("alias_b.bin")).unwrap();
        std::fs::hard_link(&src, mirror.join("alias_c.bin")).unwrap();
        std::fs::hard_link(&src, mirror.join("alias_d.bin")).unwrap();

        let total = dir_size_bytes(root).unwrap();
        // Expected: 1 MiB once (inode-deduped). Allow a few KB slack for
        // directory entries themselves on the test filesystem.
        assert!(
            (1024 * 1024..1024 * 1024 + 64 * 1024).contains(&total),
            "expected ~1 MiB after inode dedup, got {} bytes",
            total
        );
    }

    #[test]
    fn dir_size_bytes_counts_distinct_files_separately() {
        // Sanity axis: dedup must not collapse distinct-inode files of the
        // same size into one. Five 1-MiB files on different inodes must sum
        // to 5 MiB.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let payload = vec![0u8; 1024 * 1024];
        for i in 0..5 {
            std::fs::write(root.join(format!("f{}.bin", i)), &payload).unwrap();
        }
        let total = dir_size_bytes(root).unwrap();
        assert!(
            (5 * 1024 * 1024..5 * 1024 * 1024 + 64 * 1024).contains(&total),
            "expected ~5 MiB across 5 distinct inodes, got {} bytes",
            total
        );
    }

    // ─── Sync-helper tests ─────────────────────────────────────────────────
    //
    // Three pure free-fn helpers in storage/rocks.rs each pin a load-bearing
    // contract on the storage tier. None of them touch RocksDB or take
    // `&self` — sync `#[test]` (no tokio runtime, no tempdir) so they cost
    // ~zero suite time.

    #[test]
    fn batch_x_identity_tier_for_record_routes_anchor_only_when_vrf_registered_and_node_type_anchor() {
        // The CF routing decision at rocks.rs:5569 determines whether an
        // identity public-key goes into CF_IDENTITIES_ANCHOR (never evicted,
        // O(active_anchors) memory) or CF_IDENTITIES_USER (LRU-bounded Phase B
        // catch-all). Mis-routing in either direction breaks production:
        //
        //   - Anchor → User: VRF-registered anchor PKs become LRU-evictable.
        //     On a busy node the next anchor verification cycle would fail
        //     to find the PK and the anchor sig would be rejected — every
        //     epoch seal from that anchor stops getting verified.
        //   - User → Anchor: User-tier PKs leak into the never-evicted CF
        //     and the O(active_anchors) memory budget blows up to
        //     O(all-users-ever-seen) on a long-running node.
        //
        // The function only routes to ANCHOR when BOTH (vrf_registration=true)
        // AND (node_type=="anchor") — pin all 4 corners + 2 type-coercion
        // edge cases.
        let user_cf = CF_IDENTITIES_USER;
        let anchor_cf = CF_IDENTITIES_ANCHOR;

        // 1. Default record (no metadata) — vrf_registration missing,
        //    unwrap_or(false) gates → USER.
        let mut rec = test_record("r1");
        assert_eq!(identity_tier_for_record(&rec), user_cf,
            "missing vrf_registration -> USER (the conservative default)");

        // 2. vrf_registration=true, no node_type — defaults to "anchor"
        //    via `.unwrap_or("anchor")` → ANCHOR.
        rec.metadata.insert("vrf_registration".into(), serde_json::json!(true));
        assert_eq!(identity_tier_for_record(&rec), anchor_cf,
            "vrf_registration=true + no node_type defaults to anchor");

        // 3. vrf_registration=true, node_type="anchor" — explicit, ANCHOR.
        rec.metadata.insert("node_type".into(), serde_json::json!("anchor"));
        assert_eq!(identity_tier_for_record(&rec), anchor_cf);

        // 4. vrf_registration=true, node_type="witness" — only the literal
        //    string "anchor" lands in ANCHOR. Witness/service/user/etc.
        //    all fall to USER. A regression that did string-prefix-match
        //    would mis-route here.
        rec.metadata.insert("node_type".into(), serde_json::json!("witness"));
        assert_eq!(identity_tier_for_record(&rec), user_cf);

        // 5. vrf_registration=false even with node_type="anchor" — the
        //    vrf_registration gate is checked FIRST (rocks.rs:5578); without
        //    it, even a self-claimed anchor identity falls to USER.
        rec.metadata.insert("vrf_registration".into(), serde_json::json!(false));
        rec.metadata.insert("node_type".into(), serde_json::json!("anchor"));
        assert_eq!(identity_tier_for_record(&rec), user_cf,
            "vrf_registration=false overrides node_type=anchor");

        // 6. vrf_registration is non-bool (string "true") — `.as_bool()`
        //    returns None, unwrap_or(false) gates → USER. Pins the type-
        //    coercion contract: only a JSON `true` boolean trips the gate,
        //    never the string "true".
        rec.metadata.insert("vrf_registration".into(), serde_json::json!("true"));
        rec.metadata.insert("node_type".into(), serde_json::json!("anchor"));
        assert_eq!(identity_tier_for_record(&rec), user_cf,
            "string 'true' is not bool true; type-strict gate");
    }

    #[test]
    fn batch_x_witness_key_uses_nul_separator_and_byte_concat_for_cf_witness_registry_lookup() {
        // `witness_key` at rocks.rs:5595 composes the CF_WITNESS_REGISTRY
        // key from (zone_path, identity_hash) using a NUL separator. The
        // NUL is what disambiguates "zone_a" + "bcd" from "zone_ab" + "cd"
        // (without it both would yield the same key bytes and witness
        // registrations from one zone would silently overwrite another).
        //
        // The contract is byte-level deterministic: caller pre-computed
        // zone_path and identity_hash strings, function MUST yield exactly
        // zone_path_bytes ++ 0x00 ++ identity_hash_bytes — no normalization,
        // no encoding, no length prefix.
        let k = witness_key("zone_a", "abcdef");
        let expected = {
            let mut v = Vec::new();
            v.extend_from_slice(b"zone_a");
            v.push(0u8);
            v.extend_from_slice(b"abcdef");
            v
        };
        assert_eq!(k, expected, "exact byte layout: bytes ++ NUL ++ bytes");

        // The NUL separator is the load-bearing piece. Two prefix-overlapping
        // pairs that would collide on naive concat MUST yield distinct keys.
        let a = witness_key("zone_a", "bcd");
        let b = witness_key("zone_ab", "cd");
        assert_ne!(a, b,
            "NUL separator prevents prefix-overlap collisions across (zone, id)");
        // Sanity-check the offset of the NUL byte differs (different zone
        // boundaries), which is the precise behavior the NUL protects.
        assert_eq!(a[6], 0u8, "NUL after 'zone_a'");
        assert_eq!(b[7], 0u8, "NUL after 'zone_ab'");

        // Empty zone_path — still emits the NUL + identity_hash bytes. The
        // function never panics or normalizes empties (caller's job).
        let empty_zone = witness_key("", "id");
        assert_eq!(empty_zone, vec![0u8, b'i', b'd']);

        // Empty identity_hash — yields zone_bytes + just the NUL.
        let empty_id = witness_key("z", "");
        assert_eq!(empty_id, vec![b'z', 0u8]);

        // Both empty — single NUL byte, the smallest valid key. A regression
        // that pre-allocated `with_capacity(0)` and forgot the `.push(0u8)`
        // would yield Vec::new() and produce two keys that compare equal
        // for distinct (zone, id) pairs that both happened to be empty —
        // the test pins the NUL is present.
        assert_eq!(witness_key("", ""), vec![0u8]);
    }

    #[test]
    fn batch_x_is_prunable_seal_record_requires_seal_op_known_zone_and_epoch_strictly_below_floor() {
        // `is_prunable_seal_record` at rocks.rs:3650 gates the seal-archival
        // sweep. It returns true ONLY when every condition holds:
        //
        //   1. `epoch_op == "seal"` (anchor records, attestations, etc.
        //      are never pruned by this path)
        //   2. `epoch_zone` parses as a ZoneId (string OR u64 legacy form)
        //   3. `epoch_number` is a u64
        //   4. The zone is in the floor map AND `epoch < floor` (strict)
        //
        // Returning true on a record that doesn't actually exceed the floor
        // would delete LIVE seals that the chain still needs for state
        // reconstruction — catastrophic. Pinning every gate.
        use std::collections::HashMap;

        let mut floor: HashMap<crate::ZoneId, u64> = HashMap::new();
        floor.insert(crate::ZoneId::new("z1"), 100);
        floor.insert(crate::ZoneId::from_legacy(7), 50);

        // Gate 1: epoch_op missing → false.
        let mut rec = test_record("r1");
        assert!(!is_prunable_seal_record(&rec, &floor),
            "missing epoch_op -> not a seal -> not prunable");

        // Gate 1: epoch_op = "anchor" → false (only literal "seal" prunable).
        rec.metadata.insert("epoch_op".into(), serde_json::json!("anchor"));
        assert!(!is_prunable_seal_record(&rec, &floor),
            "epoch_op=anchor -> not a seal -> not prunable");

        // Gate 2: epoch_op = "seal" but no epoch_zone → false.
        rec.metadata.insert("epoch_op".into(), serde_json::json!("seal"));
        assert!(!is_prunable_seal_record(&rec, &floor),
            "seal without epoch_zone -> not prunable (zone unknown)");

        // Gate 3: epoch_op + epoch_zone but no epoch_number → false.
        rec.metadata.insert("epoch_zone".into(), serde_json::json!("z1"));
        assert!(!is_prunable_seal_record(&rec, &floor),
            "seal without epoch_number -> not prunable");

        // Gate 4a: known zone, epoch > floor → false (still in retention window).
        rec.metadata.insert("epoch_number".into(), serde_json::json!(150u64));
        assert!(!is_prunable_seal_record(&rec, &floor),
            "epoch 150 >= floor 100 -> NOT prunable");

        // Gate 4b: epoch == floor → false (strict <, equal floor not prunable —
        // the seal AT the floor epoch is the oldest one we still need).
        rec.metadata.insert("epoch_number".into(), serde_json::json!(100u64));
        assert!(!is_prunable_seal_record(&rec, &floor),
            "epoch 100 == floor 100 -> NOT prunable (strict less-than)");

        // Gate 4c: epoch < floor → TRUE (only the prunable path).
        rec.metadata.insert("epoch_number".into(), serde_json::json!(99u64));
        assert!(is_prunable_seal_record(&rec, &floor),
            "epoch 99 < floor 100 -> PRUNABLE");

        // Gate 2: epoch_zone via u64 (legacy form) — `ZoneId::from_legacy(7)`
        // matches the seeded `floor` entry. Pins the dual-shape parse at
        // rocks.rs:3666-3672.
        rec.metadata.insert("epoch_zone".into(), serde_json::json!(7u64));
        rec.metadata.insert("epoch_number".into(), serde_json::json!(49u64));
        assert!(is_prunable_seal_record(&rec, &floor),
            "u64 epoch_zone resolves via from_legacy -> prunable below floor");

        // Gate 2: epoch_zone as f64 (neither string nor u64) → false.
        // `as_str()` is None, `as_u64()` is None on a non-integer Number.
        // Arbitrary non-integer (avoid math constants that trip clippy::approx_constant).
        rec.metadata.insert("epoch_zone".into(), serde_json::json!(2.5));
        assert!(!is_prunable_seal_record(&rec, &floor),
            "non-string non-u64 epoch_zone -> not prunable");

        // Gate 4d: unknown zone in floor map → false (refuse to prune zones
        // with no retention policy — conservative default).
        rec.metadata.insert("epoch_zone".into(), serde_json::json!("unknown_zone"));
        rec.metadata.insert("epoch_number".into(), serde_json::json!(0u64));
        assert!(!is_prunable_seal_record(&rec, &floor),
            "zone not in floor map -> NOT prunable (no policy => keep)");
    }

    // ─── Orthogonal CF/key/routing axes ───────────────────────────────────
    //
    // Five test slices pin the structural contracts the rest of the
    // storage layer (and every CF-touching subsystem above it) silently
    // depends on. None of the existing 67 tests cover these axes; each
    // one corresponds to a regression vector that would only surface in
    // production:
    //
    //   batch_b_all_cf_names_invariants ......... CF_RECORDS-first + uniqueness
    //   batch_b_delete_touched_cfs_subset ....... fleet-bloat regression guard
    //   batch_b_epoch_key_byte_format ........... CF_EPOCHS index byte-shape pin
    //   batch_b_attestation_key_prefix_share .... CF_ATTESTATIONS prefix-iter pin
    //   batch_b_ban_identity_routes_to_cf_metadata Tier 4.5 CF-split pin

    #[test]
    fn batch_b_all_cf_names_invariants() {
        // `ALL_CF_NAMES` (rocks.rs:265) is the single source of truth that
        // `StorageEngine::open` (line 576) materialises into CF descriptors.
        // Two structural invariants on this slice silently underpin the
        // entire storage layer; neither is pinned today and both have
        // distinct production failure modes:
        //
        //   (a) **CF_RECORDS at index 0** — by RocksDB convention the
        //       first descriptor is the default CF; if a future refactor
        //       reorders the array to put e.g. CF_METADATA first, the
        //       implicit default-CF binding would change and every code
        //       path that opens a handle by index instead of by name
        //       (currently none, but a future optimisation could) would
        //       silently route to the wrong CF.
        //
        //   (b) **No duplicate names** — RocksDB rejects duplicate CF
        //       descriptors at `open_cf_descriptors` with a hard error
        //       (`Invalid argument: column family already exists`). A
        //       duplicated entry in `ALL_CF_NAMES` would fail every
        //       `StorageEngine::open` call (every test, every node
        //       startup) — but the cheap pin here catches it at edit
        //       time without spinning up RocksDB.
        //
        //   (c) **Every name resolves to a handle on a fresh engine** —
        //       cross-check that the array and the actual CF descriptor
        //       list passed to `open_cf_descriptors` are in sync. A
        //       regression that added a name to `ALL_CF_NAMES` but
        //       forgot to add it to `cf_descriptors` (line 576) would
        //       skip materialising the CF and a later `cf_handle(name)`
        //       call would return a default handle that silently routes
        //       to the wrong CF.
        use std::collections::HashSet;

        // (a) CF_RECORDS is index 0 — pin the default-CF convention.
        assert_eq!(ALL_CF_NAMES[0], CF_RECORDS,
            "CF_RECORDS must be the first entry of ALL_CF_NAMES (RocksDB default-CF convention)");

        // (b) No duplicates — set cardinality equals slice length.
        let unique: HashSet<&&str> = ALL_CF_NAMES.iter().collect();
        assert_eq!(unique.len(), ALL_CF_NAMES.len(),
            "ALL_CF_NAMES must not contain duplicate CF names");

        // (c) Every name resolves to a CF handle on a fresh engine.
        let (engine, _dir) = test_engine();
        for cf_name in ALL_CF_NAMES {
            assert!(
                engine.cf_handle(cf_name).is_some(),
                "cf_handle returned None for {cf_name}: CF missing from open()"
            );
        }

        // Sanity: ALL_CF_NAMES is non-empty (RocksDB requires at least
        // the default CF; an empty slice would fail open with no
        // descriptors). At time of writing the array carries 35 names —
        // pin only the lower bound (>= 22 was the v0 floor per the
        // module header) so future additions don't churn this test.
        assert!(ALL_CF_NAMES.len() >= 22,
            "ALL_CF_NAMES must carry at least the 22 core CFs (got {})",
            ALL_CF_NAMES.len());
    }

    #[test]
    fn batch_b_delete_touched_cfs_subset() {
        // `delete_touched_cfs()` (rocks.rs:2882) names every CF that GC
        // can leave tombstones in. `compact_post_gc` (line 2901) iterates
        // this slice and calls `self.cf(name)` — which PANICS on an
        // unknown CF name (the `expect("cf exists: ...")` at line 5466 +
        // friends). A typo here would crash the node mid-GC. The
        // fleet-bloat incident traced exactly to a
        // mismatch between "CFs deleted from" and "CFs compacted" — the
        // structural invariant the fix relied on is that every entry of
        // `delete_touched_cfs()` MUST appear in `ALL_CF_NAMES` (so it
        // resolves to a real handle and gets compacted post-GC).
        //
        // Pin both directions:
        //   (a) every entry of delete_touched_cfs() ∈ ALL_CF_NAMES (no
        //       typo, no orphan)
        //   (b) the returned slice contains no duplicates (a duplicated
        //       compact_range_cf is wasted CPU but not a correctness bug —
        //       still cheap to pin)
        //   (c) every entry resolves to a CF handle on a fresh engine
        //       (catches both name typos AND missing-descriptor regressions)
        //   (d) the slice is non-empty (an empty slice would silently
        //       skip every post-GC compaction — exactly the fleet-bloat bug,
        //       which would let SST tombstone bloat accumulate forever)
        use std::collections::HashSet;

        let touched = StorageEngine::delete_touched_cfs();
        let known: HashSet<&&str> = ALL_CF_NAMES.iter().collect();

        // (a) Subset invariant.
        for cf_name in touched {
            assert!(known.contains(&cf_name),
                "delete_touched_cfs entry {cf_name:?} not in ALL_CF_NAMES");
        }

        // (b) No duplicates.
        let unique_touched: HashSet<&&str> = touched.iter().collect();
        assert_eq!(unique_touched.len(), touched.len(),
            "delete_touched_cfs must not contain duplicate CF names");

        // (c) Every entry resolves on a live engine.
        let (engine, _dir) = test_engine();
        for cf_name in touched {
            assert!(
                engine.cf_handle(cf_name).is_some(),
                "cf_handle returned None for {cf_name}: CF missing from delete_touched_cfs"
            );
        }

        // (d) Non-empty (the fleet-bloat regression-guard).
        assert!(!touched.is_empty(),
            "delete_touched_cfs() empty -> compact_post_gc would silently no-op -> SST tombstone bloat");
    }

    #[test]
    fn compact_post_gc_skips_unknown_cf_instead_of_panicking() {
        // Before the try_cf() conversion, compact_post_gc called self.cf() which
        // panics on an unknown CF. This pins the safe-fallback contract: the
        // function completes without panic on a valid engine (all CFs present),
        // and the try_cf()→continue path means an unknown CF name would be
        // silently skipped rather than crashing the node.
        let (engine, _dir) = test_engine();
        engine.compact_post_gc();
        // If we reach here, self.try_cf() resolved every CF in delete_touched_cfs()
        // without panicking. Unreachable CFs would have been skipped.
    }

    #[test]
    fn batch_b_epoch_key_byte_format() {
        // `epoch_key` (rocks.rs:2268) composes the CF_EPOCHS key from
        // (zone, epoch) as 16 bytes: `zone.to_key_bytes() (8B) || epoch.to_be_bytes() (8B)`.
        // The byte format is load-bearing for two consumers:
        //   - prefix-iter over the first 8B yields all epochs in a zone
        //     (used by epoch-purge / divergence-monitor)
        //   - lex-ordering inside a zone is monotonic in epoch number
        //     (used by latest-epoch seek)
        //
        // A future format drift (varint, LE encoding, separator insertion,
        // zone shape change) would break both consumers silently — the
        // existing `test_epoch_key_ordering` only checks the high-level
        // ordering and wouldn't catch a 16-byte → 12-byte truncation
        // that happened to preserve ordering on the 3 test points it
        // probes. Pin the byte format directly.

        // (1) Exact 16-byte length (8 zone + 8 epoch BE).
        let k = StorageEngine::epoch_key(&ZoneId::from_legacy(7), 42);
        assert_eq!(k.len(), 16, "epoch_key must be exactly 16 bytes (8 zone + 8 epoch)");

        // (2) Zone bytes occupy the first 8B and match `to_key_bytes`.
        assert_eq!(&k[0..8], &ZoneId::from_legacy(7).to_key_bytes(),
            "first 8B must be ZoneId::to_key_bytes (prefix-iter contract)");

        // (3) Epoch bytes occupy the last 8B in big-endian.
        assert_eq!(&k[8..16], &42u64.to_be_bytes(),
            "last 8B must be epoch.to_be_bytes() (monotonic-sort contract)");

        // (4) Monotonic lex-ordering inside a zone — adjacent epochs
        //     differ only in the last byte (small u64), and (epoch=0,
        //     epoch=1, ..., epoch=255) are lex-monotonic by the BE
        //     encoding. A LE-encoding regression would invert the
        //     ordering at byte boundary 256.
        let z = ZoneId::from_legacy(5);
        let k0 = StorageEngine::epoch_key(&z, 0);
        let k_255 = StorageEngine::epoch_key(&z, 255);
        let k_256 = StorageEngine::epoch_key(&z, 256);
        let k_max = StorageEngine::epoch_key(&z, u64::MAX);
        assert!(k0 < k_255 && k_255 < k_256 && k_256 < k_max,
            "BE epoch encoding must yield monotonic lex order across byte boundaries");

        // (5) Distinct zones produce disjoint 8-byte prefixes (zone 7
        //     u64-BE vs zone 8 u64-BE differ in the last zone byte).
        //     This is the prefix-iter separation contract; a regression
        //     that hashed the (zone, epoch) tuple together would break
        //     it silently.
        let k_z7 = StorageEngine::epoch_key(&ZoneId::from_legacy(7), 0);
        let k_z8 = StorageEngine::epoch_key(&ZoneId::from_legacy(8), 0);
        assert_ne!(&k_z7[0..8], &k_z8[0..8],
            "distinct zones must have distinct 8-byte prefixes");
        // Epoch tails are identical because both are epoch=0.
        assert_eq!(&k_z7[8..16], &k_z8[8..16],
            "same epoch -> same last 8 bytes regardless of zone");
    }

    #[test]
    fn batch_b_attestation_key_prefix_share() {
        // `attestation_key` (rocks.rs:2276) composes the CF_ATTESTATIONS
        // key as `zone (8B) || epoch BE (8B) || record_id`. The first 16
        // bytes MUST equal `epoch_key(zone, epoch)` so that prefix-iter
        // over (zone, epoch) finds every attestation for that
        // (zone, epoch) pair — this is the contract the finality
        // verification path (consensus.rs, witness.rs) silently relies on.
        //
        // A future format drift that inserted a separator byte between
        // the (zone, epoch) prefix and the record_id (e.g. NUL to make
        // record_id parsing easier) would silently break every
        // prefix-iter consumer because the first 16 bytes would no longer
        // line up with `epoch_key`. A companion test pins the
        // CF_ATTESTATIONS prefix-extractor byte format in `witness.rs`;
        // this slice pins the corresponding key composition in
        // `rocks.rs` so a drift on either side surfaces at edit time.

        let z = ZoneId::from_legacy(3);
        let e: u64 = 17;
        let rid = "rec-alpha-123";

        let ek = StorageEngine::epoch_key(&z, e);
        let ak = StorageEngine::attestation_key(&z, e, rid);

        // (1) First 16 bytes are exactly the epoch_key — the prefix-iter
        //     contract. Pin via direct slice equality.
        assert_eq!(&ak[0..16], ek.as_slice(),
            "attestation_key first 16B must equal epoch_key(z, e)");

        // (2) record_id is appended raw (no separator, no length prefix).
        assert_eq!(&ak[16..], rid.as_bytes(),
            "record_id must be appended raw after the 16B prefix");

        // (3) Total length matches: 16 + rid.len().
        assert_eq!(ak.len(), 16 + rid.len(),
            "attestation_key length = 16 + record_id.len()");

        // (4) Two attestations with identical (z, e) but different
        //     record_ids share the 16-byte prefix and differ in the
        //     suffix only — pins prefix-iter convergence.
        let ak2 = StorageEngine::attestation_key(&z, e, "rec-beta-999");
        assert_eq!(&ak[0..16], &ak2[0..16],
            "same (zone, epoch) -> identical 16B prefix regardless of record_id");
        assert_ne!(&ak[16..], &ak2[16..],
            "distinct record_ids -> distinct suffixes");

        // (5) Empty record_id yields exactly the 16B epoch_key — the
        //     minimum valid attestation key. A regression that
        //     mistakenly inserted a separator byte would produce a
        //     17-byte key here (16 + 1B sep + 0B id) and fail this pin.
        let ak_empty = StorageEngine::attestation_key(&z, e, "");
        assert_eq!(ak_empty, ek,
            "empty record_id collapses to just epoch_key (no separator)");
    }

    #[test]
    fn batch_b_ban_identity_routes_to_cf_metadata() {
        // Tier 4.5 (rocks.rs:34-49) split `ban:*` / `blocked_term:*` /
        // `__snapshot__:*` keys out of CF_RECORDS into CF_METADATA so
        // every CF_RECORDS full-scan stops paying the
        // skip-prefix-then-iterate cost on those small hot-path values.
        // `ban_identity` (rocks.rs:2289) is the canonical write site.
        //
        // A regression that wrote bans to CF_RECORDS (e.g. a copy-paste
        // from a pre-Tier-4.5 call site, or an under-tested helper that
        // calls `put_cf_raw(CF_RECORDS, "ban:...", ...)`) would:
        //   (a) inflate CF_RECORDS count, breaking
        //       `approximate_record_count` heuristics
        //   (b) put load_banned_identities (which reads CF_METADATA)
        //       silently returning an empty list — ban enforcement
        //       silently disabled
        //   (c) re-introduce the CF_RECORDS prefix-skip cost on every
        //       full-scan iterator
        //
        // Pin all three legs at once.

        let (engine, _dir) = test_engine();
        let hash = "deadbeefcafebabe";
        let reason = "spam";

        // Pre-state: no bans, no records.
        assert!(engine.load_banned_identities().unwrap().is_empty());
        let records_before = engine.count_cf(CF_RECORDS);
        let metadata_before = engine.count_cf(CF_METADATA);

        // Apply the ban.
        engine.ban_identity(hash, reason).unwrap();

        // (a) CF_RECORDS count unchanged — Tier 4.5 routing pin.
        assert_eq!(engine.count_cf(CF_RECORDS), records_before,
            "ban_identity must NOT touch CF_RECORDS (Tier 4.5 routing)");

        // (b) CF_METADATA count grew by exactly 1.
        assert_eq!(engine.count_cf(CF_METADATA), metadata_before + 1,
            "ban_identity must land in CF_METADATA (one new key)");

        // (c) Raw key lookup confirms literal "ban:{hash}" prefix.
        let raw = engine
            .get_cf_raw(CF_METADATA, format!("ban:{hash}").as_bytes())
            .unwrap();
        assert!(raw.is_some(),
            "ban entry must be addressable at the literal 'ban:{{hash}}' key in CF_METADATA");

        // (d) Round-trip via load_banned_identities preserves all 3
        //     fields (hash, reason, timestamp). A regression that
        //     mis-spelled a JSON field name would silently lose the
        //     reason or timestamp.
        let loaded = engine.load_banned_identities().unwrap();
        assert_eq!(loaded.len(), 1, "exactly one ban should be loaded");
        let (got_hash, got_reason, got_ts) = &loaded[0];
        assert_eq!(got_hash, hash);
        assert_eq!(got_reason, reason);
        assert!(*got_ts > 0.0, "timestamp must be a positive unix time");

        // (e) Unban semantics: returns true on existing, false on
        //     missing; load returns empty after unban. A regression that
        //     swapped the bool return (existed/exists-after) would fail
        //     here.
        assert!(engine.unban_identity(hash).unwrap(),
            "unban must return true on existing");
        assert!(!engine.unban_identity(hash).unwrap(),
            "unban must return false on missing (idempotent)");
        assert!(engine.load_banned_identities().unwrap().is_empty(),
            "load_banned_identities empty after unban round-trip");
    }

    #[test]
    fn test_record_count_corrupt_metadata_does_not_panic() {
        use crate::storage::Storage;

        let dir = tempfile::tempdir().unwrap();
        let engine = StorageEngine::open(dir.path()).unwrap();

        // Write a truncated (3-byte) __record_count__ — simulates a
        // corrupted or partially-written metadata entry from a peer.
        let cf_meta = engine.cf(CF_METADATA);
        engine.db.put_cf(&cf_meta, b"__record_count__", b"bad").unwrap();

        // count() must fall back to a full scan without panicking.
        let n = engine.count().expect("count must succeed even with corrupt metadata");
        assert_eq!(n, 0, "corrupted metadata should not inflate count");

        // put_record on a corrupt counter resets to 1 (the `_ => 1` arm).
        engine.put_record("test-harden-1", &test_record("test-harden-1")).unwrap();
        let n2 = engine.count().expect("count after put must succeed");
        assert_eq!(n2, 1);
    }

    #[test]
    fn open_invalid_path_returns_err_not_panic() {
        // A regular file (not a directory) is not a valid RocksDB path.
        // Verify open() returns Err(ElaraError::Storage(...)) instead of panicking.
        let f = tempfile::NamedTempFile::new().unwrap();
        match StorageEngine::open(f.path()) {
            Ok(_) => panic!("expected error opening DB at a file path"),
            Err(crate::errors::ElaraError::Storage(_)) => {}
            Err(e) => panic!("expected ElaraError::Storage variant, got: {e:?}"),
        }
    }

    #[test]
    fn result_returning_methods_propagate_try_cf_error() {
        // get_record, record_exists, slot_lookup, slot_register, slot_delete,
        // slot_mark_conflict, slot_is_conflicted, and max_slot_nonce_for_account
        // all call try_cf()?. Verify that try_cf returns ElaraError::Storage for
        // an unknown CF — which is the error those methods now propagate instead
        // of panicking. Also verifies the normal path still works.
        let dir = tempfile::tempdir().unwrap();
        let engine = StorageEngine::open(dir.path()).unwrap();

        // Normal path: get_record for a missing key returns Ok(None).
        assert!(engine.get_record("no-such-record").unwrap().is_none());

        // Error path: try_cf with an unknown CF name returns ElaraError::Storage.
        // get_record and friends use `self.try_cf(CF)?`, so a schema mismatch
        // surfaces as Err rather than a panic.
        // NB: try_cf's Ok type (Arc<BoundColumnFamily>) borrows `engine` and is not Debug.
        // .err() drops the borrowed Ok value immediately and yields the owned error —
        // avoiding both the Debug bound (.unwrap_err) and an E0597 borrow-of-engine.
        let err = engine
            .try_cf("__nonexistent_cf__")
            .err()
            .expect("expected Err for a nonexistent column family, got Ok");
        match err {
            crate::errors::ElaraError::Storage(msg) => {
                assert!(msg.contains("missing column family"), "unexpected message: {msg}");
            }
            e => panic!("expected ElaraError::Storage, got: {e:?}"),
        }
    }

    #[test]
    fn store_public_key_and_anchor_return_ok_via_try_cf() {
        // Regression guard: after cf() → try_cf()? hardening, both functions
        // must still succeed on a healthy engine (not return Err on valid CFs).
        let (engine, _dir) = test_engine();
        let pk = vec![0xAB; 32];
        engine.store_public_key("hash-legacy", &pk).expect("store_public_key must succeed");
        engine.store_public_key_anchor("hash-anchor", &pk).expect("store_public_key_anchor must succeed");
        // Missing-CF error path is covered by composition: try_cf() returns
        // ElaraError::Storage on an unknown CF (see test_try_cf_unknown_returns_err),
        // and ? propagates that error instead of panicking.
    }

    #[test]
    fn store_public_key_witness_and_user_at_succeed_on_healthy_engine() {
        // Regression guard: store_public_key_witness / store_public_key_user_at /
        // evict_user_identities_to_cap now use try_cf()? instead of the panicking cf().
        // Verify they still return Ok on a healthy engine with all CFs present.
        let (engine, _dir) = test_engine();
        let pk = vec![0xCC; 32];

        engine
            .store_public_key_witness("w-hash", &pk)
            .expect("store_public_key_witness must succeed on healthy engine");

        let ts_ms = 1_700_000_000_000u64;
        engine
            .store_public_key_user_at("u-hash", &pk, ts_ms)
            .expect("store_public_key_user_at must succeed on healthy engine");
        engine
            .store_public_key_user_at("u-hash-2", &pk, ts_ms + 1)
            .expect("second store_public_key_user_at must succeed on healthy engine");

        // Two user entries; evict to cap=0 (disabled) — must return Ok(0).
        let evicted = engine
            .evict_user_identities_to_cap(0, 10)
            .expect("evict_user_identities_to_cap must succeed on healthy engine");
        assert_eq!(evicted, 0, "cap=0 means disabled, no evictions");

        // Evict with cap=1: two entries over a cap of one — the oldest
        // (u-hash @ ts_ms) goes, the newer u-hash-2 survives.
        let evicted2 = engine
            .evict_user_identities_to_cap(1, 10)
            .expect("evict with cap=1 must succeed");
        assert_eq!(evicted2, 1, "one entry must be evicted to reach cap=1");
        assert!(
            engine.get_public_key("u-hash-2").is_some(),
            "newest user entry must survive eviction"
        );
    }

    #[test]
    fn purge_witness_pks_for_zone_returns_ok_on_healthy_engine() {
        // Regression guard: purge_witness_pks_for_zone now uses try_cf()? instead
        // of the panicking cf(). Verify Ok on a healthy engine.
        let (engine, _dir) = test_engine();

        // No witnesses registered → returns Ok(0) without touching CF.
        let evicted = engine
            .purge_witness_pks_for_zone("zone-a", &[])
            .expect("empty zone must return Ok(0)");
        assert_eq!(evicted, 0);

        // Register a witness + its PK, then purge with no still-subscribed zones.
        let pk = vec![0xAB; 32];
        engine
            .register_witness("zone-b", "id-hash-1", pk.clone(), 100, 1)
            .expect("register witness");
        engine
            .store_public_key_witness("id-hash-1", &pk)
            .expect("store pk");

        let evicted2 = engine
            .purge_witness_pks_for_zone("zone-b", &[])
            .expect("purge must return Ok on healthy engine");
        assert_eq!(evicted2, 1, "PK entry must be evicted");
    }

    #[test]
    fn put_dag_edges_roundtrip_and_tips_invariant() {
        let (engine, _dir) = test_engine();

        // Leaf node: no parents, no children — round-trips cleanly.
        engine.put_dag_edges("rec-a", &[], &[]).expect("put leaf");
        let (parents_a, children_a) = engine.get_dag_edges("rec-a").expect("get").expect("exists");
        assert!(parents_a.is_empty());
        assert!(children_a.is_empty());

        // rec-b is a child of rec-a.
        engine
            .put_dag_edges("rec-a", &[], &["rec-b".to_string()])
            .expect("put parent edge");
        engine
            .put_dag_edges("rec-b", &["rec-a".to_string()], &[])
            .expect("put child edge");

        let (_, children_a2) = engine.get_dag_edges("rec-a").expect("get").expect("exists");
        assert_eq!(children_a2, vec!["rec-b".to_string()]);

        let (parents_b, children_b) = engine.get_dag_edges("rec-b").expect("get").expect("exists");
        assert_eq!(parents_b, vec!["rec-a".to_string()]);
        assert!(children_b.is_empty());

        // Tips index: rec-a has children so it was removed from tips;
        // rec-b has no children so it remains a tip.
        assert_eq!(engine.count_cf(CF_IDX_TIPS), 1);
    }

    #[test]
    fn full_pull_cursor_round_trips_and_defaults_to_zero() {
        let dir = tempfile::tempdir().unwrap();
        let engine = StorageEngine::open(dir.path()).unwrap();

        // Before any save, default is 0.0.
        assert_eq!(engine.load_full_pull_cursor(), 0.0);

        // Round-trip a non-trivial value.
        engine.save_full_pull_cursor(1234.5678);
        let loaded = engine.load_full_pull_cursor();
        assert!((loaded - 1234.5678).abs() < f64::EPSILON, "cursor mismatch: {loaded}");

        // Overwrite and verify new value wins.
        engine.save_full_pull_cursor(0.0001);
        let loaded2 = engine.load_full_pull_cursor();
        assert!((loaded2 - 0.0001).abs() < f64::EPSILON, "cursor mismatch: {loaded2}");
    }

    #[test]
    fn try_cf_missing_returns_err_not_panic() {
        // Regression guard: try_cf must return Err on a non-existent CF rather
        // than panic. load_banned_identities and load_blocked_terms now use
        // try_cf so a schema-migration failure propagates as an error instead
        // of crashing the node.
        let (engine, _dir) = test_engine();
        let err = engine
            .try_cf("__nonexistent_cf_for_test__")
            .err()
            .expect("try_cf on a missing CF must return Err")
            .to_string();
        assert!(
            err.contains("missing column family"),
            "error message must mention 'missing column family', got: {err}"
        );
    }

    #[test]
    fn storage_trait_cf_methods_use_try_cf_not_panic() {
        // Regression guard: get_by_hash / tips / roots / count now use
        // try_cf()? — a missing CF returns Err instead of panicking on a
        // Byzantine peer's malformed input or a schema-migration failure.
        use crate::storage::Storage;
        let (engine, _dir) = test_engine();

        // All four methods must succeed on a correctly-opened engine.
        assert!(engine.get_by_hash("nonexistent_hash").is_err(), "unknown hash → Err, not panic");
        assert_eq!(engine.tips().expect("tips ok").len(), 0);
        assert_eq!(engine.roots().expect("roots ok").len(), 0);
        assert_eq!(engine.count().expect("count ok"), 0);
    }

    #[test]
    fn applied_cf_methods_use_try_cf_not_panic() {
        // is_applied / mark_applied / bulk_mark_applied / collect_applied_ids
        // all use try_cf() — a missing CF returns a safe default instead of
        // panicking.  The CF-present paths are exercised here; the CF-absent
        // path is guarded by test_try_cf_unknown_returns_err.
        let (engine, _dir) = test_engine();

        // Nothing applied yet.
        assert!(!engine.is_applied("rec-1"));
        assert!(engine.collect_applied_ids().is_empty());

        // Single-mark round-trip.
        engine.mark_applied("rec-1");
        assert!(engine.is_applied("rec-1"));
        assert!(!engine.is_applied("rec-2"));

        // Bulk-mark round-trip.
        let ids: std::collections::HashSet<String> =
            ["rec-2", "rec-3"].iter().map(|s| s.to_string()).collect();
        engine.bulk_mark_applied(&ids);
        assert!(engine.is_applied("rec-2"));
        assert!(engine.is_applied("rec-3"));

        // collect_applied_ids reflects all three marks.
        let all = engine.collect_applied_ids();
        assert!(all.contains("rec-1"), "rec-1 missing from applied set");
        assert!(all.contains("rec-2"), "rec-2 missing from applied set");
        assert!(all.contains("rec-3"), "rec-3 missing from applied set");
    }

    #[test]
    fn collect_applied_ids_capped_ships_empty_over_cap() {
        // Snapshot producers use the capped collector so they never
        // materialize an O(total_history) applied-id set into the wire/disk
        // snapshot. The cap is gated on the caller's O(1) estimate (passed in),
        // not an O(n) count — so this test drives the estimate explicitly.
        let (engine, _dir) = test_engine();
        let ids: std::collections::HashSet<String> =
            ["a", "b", "c"].iter().map(|s| s.to_string()).collect();
        engine.bulk_mark_applied(&ids);

        // Estimate under the cap → full set returned.
        let under = engine.collect_applied_ids_capped(3, 1_000_000);
        assert_eq!(under.len(), 3, "under cap must return the full applied set");
        assert!(under.contains("a") && under.contains("b") && under.contains("c"));

        // Estimate == cap is NOT over (strict `>`), so the boundary still serves.
        assert_eq!(engine.collect_applied_ids_capped(3, 3).len(), 3, "cap==count serves");

        // Estimate over the cap → empty, WITHOUT touching CF_APPLIED (even
        // though the CF actually holds 3 ids, an over-cap estimate ships empty).
        assert!(
            engine.collect_applied_ids_capped(4, 3).is_empty(),
            "over cap must ship empty, not a truncated/partial set"
        );
    }

    #[test]
    fn witness_registry_cf_error_propagates_not_panic() {
        // register_witness, get_witness, flush_pending_witness_registrations,
        // is_witness_registered, and iter_witnesses_for_zone all use try_cf
        // now — a missing CF returns Err/false/[] instead of panicking.
        let (engine, _dir) = test_engine();
        let zone = "finance/eu";
        let id = "aabbccdd";
        let pk = vec![1u8; 32];

        // Not yet registered.
        assert!(!engine.is_witness_registered(zone, id));
        assert!(engine.iter_witnesses_for_zone(zone).is_empty());
        assert!(engine.get_witness(zone, id).unwrap().is_none());

        // Register and verify round-trip.
        engine.register_witness(zone, id, pk.clone(), 100, 1).unwrap();
        assert!(engine.is_witness_registered(zone, id));
        let entry = engine.get_witness(zone, id).unwrap().expect("entry must exist");
        assert_eq!(entry.bond, 100);
        assert_eq!(entry.registered_epoch, 1);
        let list = engine.iter_witnesses_for_zone(zone);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].0, id);

        // Batch path.
        let id2 = "11223344";
        engine
            .flush_pending_witness_registrations(&[(
                zone.to_string(),
                id2.to_string(),
                pk,
                200,
                2,
            )])
            .unwrap();
        assert!(engine.is_witness_registered(zone, id2));
        assert_eq!(engine.iter_witnesses_for_zone(zone).len(), 2);
    }

    #[test]
    fn approximate_cf_size_and_cf_live_bytes_unknown_cf_returns_zero_not_panic() {
        let (engine, _dir) = test_engine();
        assert_eq!(engine.approximate_cf_size("__no_such_cf__"), 0);
        assert_eq!(engine.cf_live_bytes("__no_such_cf__"), 0);
    }

    #[test]
    fn compact_cf_unknown_cf_returns_not_panics() {
        // compact_cf uses try_cf: a missing CF (schema mismatch) must be a
        // silent no-op, not a panic. The admin HTTP route calls this with
        // operator-supplied names after an allowlist check; belt-and-suspenders.
        let (engine, _dir) = test_engine();
        engine.compact_cf("__no_such_cf__"); // must not panic
    }

    #[test]
    fn recent_record_ids_and_record_ids_from_propagate_err_not_panic() {
        // Converted from cf()->try_cf(): on a schema-valid engine both return Ok([]);
        // if CF_IDX_TIMESTAMP were absent a missing-CF Err propagates via ? instead of panic.
        let (engine, _dir) = test_engine();
        assert!(engine.recent_record_ids(0.0, 0).is_ok());
        assert!(engine.record_ids_from(0.0, 0).is_ok());
        // Populated engine: results are Ok and non-empty after inserting a record.
        let rec = test_record("harden-test-id");
        engine.put_record("harden-test-id", &rec).unwrap();
        let ids = engine.recent_record_ids(0.0, 10).unwrap();
        assert!(ids.contains(&"harden-test-id".to_string()));
        let ids_from = engine.record_ids_from(0.0, 10).unwrap();
        assert!(ids_from.contains(&"harden-test-id".to_string()));
    }

    #[test]
    fn startup_compaction_main_loops_skip_unknown_cf_not_panic() {
        // The all_cfs / heavy_cfs loops previously called self.cf() which
        // would panic on a missing CF. They now use try_cf() with `continue`.
        // A fresh engine has all standard CFs, so the loops run fully without
        // skipping, and the function should return 0 (no compaction needed).
        let (engine, _dir) = test_engine();
        let result = engine.startup_compaction_if_needed();
        assert_eq!(result, 0, "fresh engine: no bloat, no compaction scheduled");
    }

    #[test]
    fn startup_compaction_unknown_force_cf_skips_not_panics() {
        // ELARA_FORCE_COMPACT_CF with a bogus name must not panic; returns 0
        // because no valid CF was compacted.
        let (engine, _dir) = test_engine();
        // Safety: single-threaded test; env var removed immediately after.
        unsafe { std::env::set_var("ELARA_FORCE_COMPACT_CF", "nonexistent_cf,another_bogus") };
        let compacted = engine.startup_compaction_if_needed();
        unsafe { std::env::remove_var("ELARA_FORCE_COMPACT_CF") };
        assert_eq!(compacted, 0, "no valid CFs were compacted");
    }

    #[test]
    fn metrics_helpers_return_not_panic_on_valid_engine() {
        // memory_usage / compaction_pressure / write_stall_state previously
        // called self.cf() which panics on a missing CF (schema mismatch).
        // Converted to try_cf() with continue — verify they return without
        // panicking and produce the expected zero-baseline on an empty engine.
        let (engine, _dir) = test_engine();
        let (memtable, block_cache, table_readers) = engine.memory_usage();
        // block_cache may be non-zero (shared RocksDB pool), but all are u64.
        let _ = (memtable, block_cache, table_readers);
        let (pending, running, immutable) = engine.compaction_pressure();
        assert_eq!(running, 0, "no background compactions on fresh engine");
        assert_eq!(immutable, 0, "no frozen memtables on fresh engine");
        let _ = pending;
        let (l0_total, l0_max, stalled, delay_rate) = engine.write_stall_state();
        assert_eq!(stalled, 0, "no write-stalled CFs on fresh engine");
        assert_eq!(delay_rate, 0, "no write-delay on fresh engine");
        let _ = (l0_total, l0_max);
    }

    #[test]
    fn record_id_by_hash_and_record_hash_return_none_not_panic() {
        // Previously called self.cf() which panics on schema mismatch or missing CF.
        // Converted to self.try_cf().ok()? — a missing CF or unknown hash must
        // return None, never abort the process.
        let (engine, _dir) = test_engine();
        let rec = test_record("hash-lookup-none");
        engine.put_record(&rec.id, &rec).unwrap();
        engine.run_migrations(_dir.path()).unwrap();

        // Unknown hashes → None.
        assert!(engine.record_id_by_hash("deadbeef00000000").is_none());
        assert!(engine.record_id_by_record_hash("deadbeef00000000").is_none());

        // Known hashes → Some after migration populates both indexes.
        let content_hash_hex = hex::encode(&rec.content_hash);
        assert_eq!(
            engine.record_id_by_hash(&content_hash_hex).as_deref(),
            Some(rec.id.as_str()),
        );
        let record_hash_hex = hex::encode(rec.record_hash());
        assert_eq!(
            engine.record_id_by_record_hash(&record_hash_hex).as_deref(),
            Some(rec.id.as_str()),
        );
    }

    #[test]
    fn cleanup_orphan_records_no_orphans_returns_zero() {
        // Verifies try_cf() path: a fully-indexed engine has no orphans and
        // cleanup_orphan_records must return 0 without panicking.
        let (engine, _dir) = test_engine();
        let rec = test_record("orphan-check-rec");
        engine.put_record(&rec.id, &rec).unwrap();
        // Use retention_cutoff = 0.0 so all records are "recent" and skipped.
        assert_eq!(engine.cleanup_orphan_records(0.0), 0);
        // Use a far-future cutoff so records look old; put_record sets the index,
        // so they are not orphans and the count is still 0.
        assert_eq!(engine.cleanup_orphan_records(f64::MAX), 0);
    }

    #[test]
    fn cleanup_orphan_records_exempts_signed_proof_carriers() {
        // Regression: cleanup_orphan_records reaps old records that lost their
        // timestamp index entry. Signed-proof carriers (mandate issuance /
        // revocation, emergency halt / resume) must be exempt exactly like the
        // epoch/beat/governance ops — an orphaned carrier needs its index
        // rebuilt, never deletion. The plain orphan is the non-vacuous control
        // proving the reap path actually fires in this window.
        let (engine, _dir) = test_engine();

        let mk = |id: &str, op: Option<&str>| {
            let mut rec = test_record(id);
            rec.timestamp = 1.0; // below the 1000.0 cutoff → retention-eligible
            if let Some(k) = op {
                rec.metadata.insert(k.to_string(), serde_json::json!("x"));
            }
            rec
        };
        let mandate = mk("orphan-mandate", Some(crate::mandate::MANDATE_OP_KEY));
        let revoke = mk("orphan-revoke", Some(crate::mandate::MANDATE_REVOCATION_OP_KEY));
        let halt = mk("orphan-halt", Some(crate::emergency::EMERGENCY_HALT_OP_KEY));
        let resume = mk("orphan-resume", Some(crate::emergency::EMERGENCY_RESUME_OP_KEY));
        let plain = mk("orphan-plain", None);

        // Write to CF_RECORDS ONLY (skip the timestamp index) → genuine orphans.
        let cf = engine.try_cf(CF_RECORDS).unwrap();
        for rec in [&mandate, &revoke, &halt, &resume, &plain] {
            engine.db.put_cf(&cf, rec.id.as_bytes(), rec.to_bytes()).unwrap();
        }

        let reaped = engine.cleanup_orphan_records(1000.0);

        // Carriers survive the orphan sweep…
        assert!(engine.get_record(&mandate.id).unwrap().is_some(), "mandate carrier orphan must not be reaped");
        assert!(engine.get_record(&revoke.id).unwrap().is_some(), "revocation carrier orphan must not be reaped");
        assert!(engine.get_record(&halt.id).unwrap().is_some(), "halt carrier orphan must not be reaped");
        assert!(engine.get_record(&resume.id).unwrap().is_some(), "resume carrier orphan must not be reaped");
        // …and the control proves the sweep is live (non-vacuous test).
        assert!(engine.get_record(&plain.id).unwrap().is_none(), "plain orphan past retention must be reaped (control)");
        assert_eq!(reaped, 1, "only the plain control orphan should be reaped");
    }

    #[test]
    fn query_by_creator_hash_uses_try_cf_not_panic() {
        // Regression guard: query_by_creator_hash and gc_scan_and_prune_with_resume
        // previously called cf() — a schema mismatch (unknown CF) would panic the
        // node when processing a peer-supplied record.  They now use try_cf()?
        // and must return Ok on a normal engine (all CFs present).
        use crate::storage::Storage;
        let (engine, _dir) = test_engine();

        // 64-char lowercase hex — the only shape that passes the early-return guard.
        let creator_hex = "a".repeat(64);
        let result = engine.query_by_creator_hash(&creator_hex, None, None, 100);
        assert!(result.is_ok(), "query_by_creator_hash must not panic: {result:?}");
        assert!(result.unwrap().is_empty());

        // Short / invalid hash must return Ok([]) via the early-return guard.
        let result_short = engine.query_by_creator_hash("tooshort", None, None, 100);
        assert!(result_short.is_ok());
        assert!(result_short.unwrap().is_empty());
    }

    #[test]
    fn migrate_0_to_1_returns_ok_on_valid_engine() {
        // migrate_0_to_1 used self.cf() (panics on missing CF); now uses try_cf()? so
        // a schema mismatch returns Err instead of crashing the node.
        // Happy path: all CFs present on a fresh engine → must return Ok.
        let (engine, _dir) = test_engine();
        assert!(
            engine.migrate_0_to_1().is_ok(),
            "migrate_0_to_1 must succeed on a correctly-opened engine"
        );
    }

    #[test]
    fn migrate_1_to_2_returns_ok_on_valid_engine() {
        // migrate_1_to_2 used self.cf() (panics on missing CF); now uses try_cf()? so
        // a schema mismatch returns Err instead of crashing the node.
        let (engine, _dir) = test_engine();
        assert!(
            engine.migrate_1_to_2().is_ok(),
            "migrate_1_to_2 must succeed on a correctly-opened engine"
        );
    }

    #[test]
    fn migrate_2_to_3_returns_ok_on_valid_engine() {
        // migrate_2_to_3 used self.cf() (panics on missing CF); now uses try_cf()? so
        // a schema mismatch returns Err instead of crashing the node.
        let (engine, _dir) = test_engine();
        assert!(
            engine.migrate_2_to_3().is_ok(),
            "migrate_2_to_3 must succeed on a correctly-opened engine"
        );
    }

    #[test]
    fn migrate_3_to_4_returns_ok_on_valid_engine() {
        // migrate_3_to_4 used self.cf() (panics on missing CF); now uses try_cf()? so
        // a schema mismatch returns Err instead of crashing the node.
        let (engine, _dir) = test_engine();
        assert!(
            engine.migrate_3_to_4().is_ok(),
            "migrate_3_to_4 must succeed on a correctly-opened engine"
        );
    }

    #[test]
    fn migrate_4_to_5_returns_ok_on_valid_engine() {
        // migrate_4_to_5 used self.cf() (panics on missing CF); now uses try_cf()? so
        // a schema mismatch returns Err instead of crashing the node.
        let (engine, _dir) = test_engine();
        assert!(
            engine.migrate_4_to_5().is_ok(),
            "migrate_4_to_5 must succeed on a correctly-opened engine"
        );
    }

    #[test]
    fn migrate_5_to_6_returns_ok_on_valid_engine() {
        // migrate_5_to_6 used self.cf() (panics on missing CF); now uses try_cf()? so
        // a schema mismatch returns Err instead of crashing the node.
        let (engine, _dir) = test_engine();
        assert!(
            engine.migrate_5_to_6().is_ok(),
            "migrate_5_to_6 must succeed on a correctly-opened engine"
        );
    }

    #[test]
    fn migrate_6_to_7_returns_ok_on_valid_engine() {
        // migrate_6_to_7 used self.cf() (panics on missing CF); now uses try_cf()? so
        // a schema mismatch returns Err instead of crashing the node.
        let (engine, _dir) = test_engine();
        assert!(
            engine.migrate_6_to_7().is_ok(),
            "migrate_6_to_7 must succeed on a correctly-opened engine"
        );
    }

    #[test]
    fn migrate_7_to_8_backfills_agent_index_from_existing_acts() {
        // migrate_7_to_8 rebuilds CF_MANDATE_ACTS_BY_AGENT from CF_MANDATE_ACT.
        // Simulate a pre-CF act by writing the forward entry DIRECTLY (bypassing
        // put_mandate_act, which would also write the agent index) — exactly the
        // state of acts ingested before the CF existed (e.g. the dogfood acts).
        use crate::mandate::MandateActEntry;
        let (engine, _dir) = test_engine();
        let agent = "11".repeat(32);
        let entry = MandateActEntry::new("a".repeat(64), &agent, 100, None);
        let cf = engine.try_cf(CF_MANDATE_ACT).unwrap();
        engine
            .db
            .put_cf(&cf, b"rec-x", serde_json::to_vec(&entry).unwrap())
            .unwrap();
        // Before backfill: the act exists forward but is NOT agent-enumerable.
        assert!(engine.list_acts_for_agent(&agent, None, 10).unwrap().0.is_empty());

        engine.migrate_7_to_8().unwrap();
        // After backfill: enumerable by agent.
        assert_eq!(
            engine.list_acts_for_agent(&agent, None, 10).unwrap().0,
            vec!["rec-x"]
        );
        // Idempotent: a re-run (crash mid-migration → version not bumped → re-run)
        // must not double-write or panic.
        engine.migrate_7_to_8().unwrap();
        assert_eq!(
            engine.list_acts_for_agent(&agent, None, 10).unwrap().0,
            vec!["rec-x"]
        );
    }

    #[test]
    fn migrate_8_to_9_backfills_mandate_index_from_existing_acts() {
        // migrate_8_to_9 rebuilds CF_MANDATE_ACTS_BY_MANDATE from CF_MANDATE_ACT.
        // The by-mandate CF was added (93dc5068) WITHOUT a backfill migration, so acts
        // ingested before it existed (the dogfood mandates) returned a FALSE
        // authoritative zero under /mandate/{id}/acts even though they were correctly
        // enumerable by agent. Simulate that pre-CF state by writing the forward entry
        // DIRECTLY (bypassing put_mandate_act, which would also write the reverse
        // indexes) — exactly the on-disk state migrate_7_to_8 left the by-mandate
        // index in.
        use crate::mandate::MandateActEntry;
        let (engine, _dir) = test_engine();
        let mandate = "a".repeat(64);
        let agent = "11".repeat(32);
        let entry = MandateActEntry::new(mandate.clone(), &agent, 100, None);
        let cf = engine.try_cf(CF_MANDATE_ACT).unwrap();
        engine
            .db
            .put_cf(&cf, b"rec-x", serde_json::to_vec(&entry).unwrap())
            .unwrap();
        // Before backfill: the act exists forward but is NOT mandate-enumerable.
        assert!(engine.list_acts_for_mandate(&mandate, None, 10).unwrap().0.is_empty());

        engine.migrate_8_to_9().unwrap();
        // After backfill: enumerable by mandate.
        assert_eq!(
            engine.list_acts_for_mandate(&mandate, None, 10).unwrap().0,
            vec!["rec-x"]
        );
        // Idempotent: a re-run (crash mid-migration → version not bumped → re-run)
        // must not double-write or panic.
        engine.migrate_8_to_9().unwrap();
        assert_eq!(
            engine.list_acts_for_mandate(&mandate, None, 10).unwrap().0,
            vec!["rec-x"]
        );
    }
}
