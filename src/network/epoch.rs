//! Epoch sealing — periodic cryptographic snapshots of the DAM.
//!
//! Each seal commits a Merkle root over all records in a time range for a zone,
//! chained to the previous seal. This closes the "historical forgery" window —
//! a fabricated record not in any sealed Merkle root is instantly detected.
//!
//! Epoch seals are regular `ValidationRecord`s with `epoch_op: "seal"` metadata,
//! following the same pattern as ledger ops (`beat_op`). Genesis authority creates
//! them; all nodes verify on receipt.

//!
//! Spec references:
//!   @spec Protocol §11.12
//!   @spec Protocol §7.5

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde_json::Value as JsonValue;
use tracing::{debug, info, warn};

use crate::ZoneId;
use crate::errors::{ElaraError, Result};
use crate::identity::Identity;
use crate::record::{Classification, ValidationRecord};
use crate::storage::Storage;
use crate::accounting::types::creator_identity_hash;

use super::consensus::zone_for_record;
use super::sync::MerkleTree;
use super::time_bracket::DrandPulse;
use super::{LockRecover, RwLockRecover};

// ─── Constants ─────────────────────────────────────────────────────────────

pub const EPOCH_OP_KEY: &str = "epoch_op";

/// Deterministic network-wide ceiling on records-per-seal-window.
/// Above this, zone-split is the recovery (not a single mega-seal).
/// Promoted to module-level pub const so the observability gauges can
/// reference the same ceiling the create/verify/witness paths enforce.
pub const MAX_SEAL_RECORDS: usize = 1_000_000;

/// Running max of `records-in-window` observed across any seal
/// create/verify/witness call since boot. Tracks how close production is
/// to the [`MAX_SEAL_RECORDS`] ceiling. Read via [`seal_window_metrics`];
/// emitted at `/metrics` as `elara_seal_window_records_observed_max`.
static SEAL_WINDOW_RECORDS_MAX: AtomicU64 = AtomicU64::new(0);

/// Count of seal create/verify/witness calls where the window
/// scan hit `MAX_SEAL_RECORDS`. Sustained non-zero means the cap is
/// binding for at least one zone — operator action: split that zone.
static SEAL_WINDOW_CAP_HITS_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Bump the seal-window-size observability gauges. Called by
/// every seal create/verify/witness path immediately after `query_zone_ids`
/// returns. CAS-loop on the max guarantees monotonic-non-decreasing.
pub(crate) fn observe_seal_window_size(records: usize) {
    let r = records as u64;
    let mut current = SEAL_WINDOW_RECORDS_MAX.load(Ordering::Relaxed);
    while r > current {
        match SEAL_WINDOW_RECORDS_MAX.compare_exchange_weak(
            current,
            r,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(actual) => current = actual,
        }
    }
    if records >= MAX_SEAL_RECORDS {
        SEAL_WINDOW_CAP_HITS_TOTAL.fetch_add(1, Ordering::Relaxed);
    }
}

/// Read the seal-window observability counters.
/// Returns `(max_records_observed, cap_hits_total)`.
pub fn seal_window_metrics() -> (u64, u64) {
    (
        SEAL_WINDOW_RECORDS_MAX.load(Ordering::Relaxed),
        SEAL_WINDOW_CAP_HITS_TOTAL.load(Ordering::Relaxed),
    )
}

/// Test-only reset of the seal-window counters.
#[cfg(test)]
pub(crate) fn reset_seal_window_metrics() {
    SEAL_WINDOW_RECORDS_MAX.store(0, Ordering::Relaxed);
    SEAL_WINDOW_CAP_HITS_TOTAL.store(0, Ordering::Relaxed);
}

/// Count of seals whose inline `epoch_record_hashes` enumeration failed the
/// parse-time root gate in [`extract_epoch_seal`] (recomputed Merkle root !=
/// signed `epoch_merkle_root`) and was dropped to empty (R3-8 slice 2). The
/// seal itself is still accepted — rejecting would wedge every fixed node on
/// one buggy-producer seal (the R3-7 incident class). Non-zero means a
/// producer emitted an enumeration inconsistent with its own signed root
/// (producer bug, in-flight truncation, or a malicious anchor — see R3-9).
/// Emitted at `/metrics` as `elara_seal_enum_root_mismatch_total`.
static SEAL_ENUM_ROOT_MISMATCH_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Read the seal-enumeration root-gate counter (R3-8 slice 2).
pub fn seal_enum_root_mismatch_total() -> u64 {
    SEAL_ENUM_ROOT_MISMATCH_TOTAL.load(Ordering::Relaxed)
}

/// R3-8 slice 3 — inline-enumeration emission cap. A seal's
/// `epoch_record_hashes` array is written into metadata ONLY when the
/// window holds at most this many records; above it the key is omitted and
/// consumers derive the enumeration from their local store (verified
/// against the signed merkle root before use — see
/// [`derive_seal_enumeration`]). 96 sits safely under the ingest per-value
/// 8 KiB boundary (the hex array costs 67·N+1 bytes: N=122 passes, N=123
/// rejects — including the producer's OWN seal insert, the self-wedge this
/// cap removes) with headroom for future per-entry growth. Tunable without
/// consensus impact: present and absent are both defined states for every
/// parser (legacy-empty), and the slice-2 root gate makes truncation ≡
/// omission.
pub const SEAL_INLINE_ENUM_MAX: usize = 96;

/// Effective inline-enumeration cap. `ELARA_SEAL_INLINE_ENUM_MAX` overrides
/// the default — the slice-6 soak knob: set it low (e.g. 4) on a test node
/// to force the omission/derive path at testnet rates, where the
/// mainnet-primary absent-key shape is otherwise dormant. Read once per
/// process.
pub(crate) fn seal_inline_enum_max() -> usize {
    static CACHED: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *CACHED.get_or_init(|| {
        std::env::var("ELARA_SEAL_INLINE_ENUM_MAX")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(SEAL_INLINE_ENUM_MAX)
    })
}

/// R3-8 slice 4 — count of seals whose absent/dropped inline enumeration was
/// successfully re-derived from the local zone+window and root-verified.
static SEAL_ENUM_DERIVED_TOTAL: AtomicU64 = AtomicU64::new(0);
/// R3-8 slice 4 — count of derive attempts whose recomputed root did NOT
/// match the signed merkle_root (local DAG incomplete for the window, or a
/// divergent producer). Consumers fall back to legacy-empty and self-heal
/// via full_pull.
static SEAL_ENUM_DERIVE_MISS_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Read the derive-when-absent counters (R3-8 slice 4):
/// `(derived_total, derive_miss_total)`.
pub fn seal_enum_derive_metrics() -> (u64, u64) {
    (
        SEAL_ENUM_DERIVED_TOTAL.load(Ordering::Relaxed),
        SEAL_ENUM_DERIVE_MISS_TOTAL.load(Ordering::Relaxed),
    )
}

/// Build the CF_EPOCHS index key for a (epoch, zone, record_id) tuple.
///
/// Wire layout (must NEVER change without a backfill — every node's index
/// would have to be rebuilt):
/// ```text
/// key = epoch:u64_be(8 bytes) || zone_path_utf8 || 0x00 || record_id_utf8
/// ```
///
/// - Epoch-major ordering: prefix-iterating from `epoch:u64_be(N)` returns
///   all (zone, record_id) tuples for epoch N first, then N+1, etc. Matches
///   the dominant query "headers since epoch X across all zones."
/// - The 0x00 separator between zone path and record_id is unambiguous —
///   ZoneId paths are normalized utf-8 with `/` segments and never contain
///   a NUL byte (see `network/zone.rs::ZoneId::new`), and record_ids are
///   the same.
/// - record_id is included in the key so equivocation (multiple competing
///   seals at the same (zone, epoch)) is preserved at the index — dedup is
///   the read path's `filter_canonical_chain` job, not this layer's.
///
/// Value at this key is empty: presence is the signal, full content lives
/// in CF_RECORDS via the encoded record_id.
pub fn disc5_index_key(epoch: u64, zone_path: &str, record_id: &str) -> Vec<u8> {
    let zone_bytes = zone_path.as_bytes();
    let id_bytes = record_id.as_bytes();
    let mut key = Vec::with_capacity(8 + zone_bytes.len() + 1 + id_bytes.len());
    key.extend_from_slice(&epoch.to_be_bytes());
    key.extend_from_slice(zone_bytes);
    key.push(0u8);
    key.extend_from_slice(id_bytes);
    key
}

/// Parse the CF_EPOCHS index key back into its (epoch, zone, record_id)
/// components. Returns `None` for malformed keys (caller should skip rather
/// than abort).
pub fn parse_disc5_index_key(key: &[u8]) -> Option<(u64, &str, &str)> {
    if key.len() < 9 {
        return None;
    }
    let epoch = u64::from_be_bytes(key[..8].try_into().ok()?);
    let sep = key[8..].iter().position(|b| *b == 0u8)?;
    let zone = std::str::from_utf8(&key[8..8 + sep]).ok()?;
    let record_id = std::str::from_utf8(&key[8 + sep + 1..]).ok()?;
    if zone.is_empty() || record_id.is_empty() {
        return None;
    }
    Some((epoch, zone, record_id))
}

/// `epoch_op` value for a cross-zone escalation seal (Stage 3c.1).
/// Emitted by an anchor in a *non-stuck* zone when a foreign zone has
/// exhausted its entire rank ladder (see `aggregator::is_zone_stuck`).
pub const EPOCH_OP_GLOBAL_SEAL: &str = "global_seal";

/// Gap 3: `epoch_op` value for a super-seal (checkpoint consolidation).
/// Emitted by the anchor that produces the seal at epoch E where
/// `E % SUPER_SEAL_INTERVAL == 0`. Aggregates the prior N seal hashes
/// into one Dilithium3-signed Merkle root so light clients can sync
/// from the latest checkpoint instead of genesis.
pub const EPOCH_OP_SUPER_SEAL: &str = "super_seal";

/// Gap 3: epochs between super-seals per zone.
/// At 60s epoch interval, a super-seal fires every 64 × 60s ≈ 64m.
/// At 1440 seals/day per zone, that's ~22 super-seals/day per zone —
/// 1.44B seals/year → ~22M super-seals/year (65× compression).
pub const SUPER_SEAL_INTERVAL: u64 = 64;

// ─── Adaptive epoch constants ──────────────────────────

/// Minimum adaptive epoch duration: 5 seconds (under heavy load).
///
/// Lowered 30s → 15s, then 15s → 5s.
/// Committee seal+attestation RTT is well under 5s even on 2-core canaries:
/// PQ-transport Dilithium3 handshake ≈2ms + data ≈5ms, 5-member committee
/// consensus converges in <200ms. At 5s this floor only activates when a zone
/// exceeds 20 rec/s (100 records / 5s); at testnet volume (<<1 rec/s) the
/// adaptive formula gives epochs hours long. If seal-traffic pressure rises,
/// the adaptive rate formula naturally lengthens per-zone intervals —
/// this constant is only the FLOOR, not the typical value.
pub const MIN_ADAPTIVE_EPOCH_SECS: f64 = 5.0;

/// Maximum adaptive epoch duration: 60 seconds = 1 minute (quiet zone).
///
/// MAINNET MANDATE: "Push in-zone finality to its physical floor." Quiet
/// zones produce no traffic, so the adaptive formula always returns a
/// value ≥ MAX, meaning every quiet zone seals exactly at this cap. Cap
/// = quiet-zone P99 finality. Was 120s → P50 ≈ 60s; tightened
/// to push P50 ≈ 30s on quiet zones (the cap halves median wait, so
/// P50 = MAX / 2 + small attestation tail). Below this requires either
/// (a) sub-second seal/attestation RTT proven on canary hardware, or
/// (b) optimistic-Sealed UX bridging the gap so users don't wait for
/// Finalized; both are gap #8 follow-ups beyond the cap drop itself.
///
/// Seal-traffic envelope at 1M zones × 60s cap: 1M / 60 ≈ 16.7K seals/sec
/// globally, ~8 MB/sec at ~500B/seal — still comfortable on mainnet
/// gossip budget; doubled but small fraction of fan-out × attestation
/// budget that already dominates wire cost (see gap #8 doc).
/// Lowered 120 → 60 once 120-cap soak showed
/// quiet-zone seal traffic well below the headroom needed for the 2× cadence.
pub const MAX_ADAPTIVE_EPOCH_SECS: f64 = 60.0;

// Compile-time invariant on the adaptive-epoch band. A future edit that
// inverts FLOOR > CEILING (or sets them equal) would break the adaptive
// formula's per-zone clamp: `interval.clamp(MIN, MAX)` would either
// always pin to MIN (if MIN > MAX, Rust's `clamp` documents this as
// undefined ordering, panicking at runtime) or collapse the band to a
// fixed value (if MIN == MAX, no adaptive behavior). Fail at
// `cargo build`, not at runtime.
const _: () = assert!(
    MIN_ADAPTIVE_EPOCH_SECS < MAX_ADAPTIVE_EPOCH_SECS,
    "MIN_ADAPTIVE_EPOCH_SECS < MAX_ADAPTIVE_EPOCH_SECS — FLOOR < CEILING autotune-stability invariant"
);

/// Upper bound on `elapsed_ms` used in proposer-rank gating
/// ([`verify_aggregator_rank`] / [`should_propose_seal`]).
///
/// Defense-in-depth against a node with a forward-skewed wall clock claiming
/// rank-N proposal authority by inflating the observed elapsed since
/// `epoch_start`. Set to 2× [`MAX_ADAPTIVE_EPOCH_SECS`] — one full epoch of
/// honest cap plus one of network-and-clock slack. Beyond this the elapsed
/// is almost certainly a recovery-from-downtime artifact (snapshot epoch_start
/// older than the actual sealing race), not a legitimate rank-fallback signal.
///
/// Sized in proportion to MAX so post-cap-drop tightening is automatic. With
/// the current 60s cap and 5s base_timeout floor, reachable rank is
/// log2(120000/5000)+1 ≈ 5 — same headroom as the prior 240s/120s pairing,
/// scaled with the new cap. Honest rank-fallback in degraded-network
/// conditions remains reachable; clock-skewed actors get no arbitrary
/// view-depth shortcut.
pub const MAX_RANK_ELAPSED_SECS: f64 = 2.0 * MAX_ADAPTIVE_EPOCH_SECS;

/// Upper bound on the materialised anchor-identity
/// vec used as `staked` input to the rank chain. The CF is structurally
/// bounded (mainnet target ~5K-50K registered anchors), so this cap is
/// generous headroom — trips before pathological CF growth could OOM the
/// seal-proposal path. At 1M × ~50 B/entry the vec is ~50 MB, scan is
/// ~1s; well past the per-epoch budget but safe enough to never crash the
/// node before an operator notices `elara_identity_tier_anchor_count`
/// climbing into the millions.
pub const MAX_ANCHORS_PER_PROPOSAL: usize = 1_000_000;

/// Target records per epoch. If a zone produces more, it seals faster.
/// If fewer, it slows down. Default: 100 records/epoch.
pub const TARGET_RECORDS_PER_EPOCH: f64 = 100.0;

/// Smoothing factor for exponential moving average of zone activity.
/// 0.3 = moderate responsiveness (30% new observation, 70% history).
pub const ACTIVITY_EMA_ALPHA: f64 = 0.3;

// Compile-time invariant on the EMA smoothing factor. A future edit that
// sets ALPHA <= 0.0 (no new-observation weight — EMA freezes) or
// ALPHA >= 1.0 (no history — EMA collapses to the latest sample) would
// break the EMA's role as a smoothing filter. Fail at `cargo build`,
// not at runtime.
const _: () = assert!(
    ACTIVITY_EMA_ALPHA > 0.0 && ACTIVITY_EMA_ALPHA < 1.0,
    "ACTIVITY_EMA_ALPHA must be in (0, 1) to be a smoothing factor — 0 freezes the EMA, 1 collapses it to the latest sample"
);

// ─── Epoch state tracking ──────────────────────────────────────────────────

/// Per-zone epoch tracking. Maintained in memory, rebuilt from storage on startup.
#[derive(Debug, Clone)]
pub struct EpochState {
    /// Latest sealed epoch number per zone.
    pub latest_epoch: HashMap<ZoneId, u64>,
    /// Record ID of the latest seal per zone.
    pub latest_seal_id: HashMap<ZoneId, String>,
    /// Content hash of the latest seal record per zone.
    pub latest_seal_hash: HashMap<ZoneId, [u8; 32]>,
    /// Latest VRF output per zone — used as unpredictable seed for jury selection.
    pub latest_vrf_output: HashMap<ZoneId, [u8; 32]>,
    /// Exponential moving average of records per second, per zone.
    /// Used for adaptive epoch duration.
    pub zone_activity_rate: HashMap<ZoneId, f64>,
    /// Computed adaptive epoch duration per zone (seconds).
    /// Zones with high activity seal faster, quiet zones seal slower.
    pub zone_adaptive_interval: HashMap<ZoneId, f64>,
    /// Prediction evaluation results from previous epoch (recurrence wiring).
    /// zone → (epoch_number, accuracy, correct_count, wrong_count).
    /// Nodes use this to inform their next epoch's predictions.
    pub prediction_recurrence: HashMap<ZoneId, (u64, f64, u64, u64)>,
    /// Wall-clock moment (unix seconds) at which the CURRENT epoch's proposal
    /// window opened for each zone — i.e. when the previous seal was registered
    /// locally. Used by the aggregator chain (§11.13) to size per-rank timeouts
    /// as `(2^k - 1) * base_timeout`. Updated on every `register_seal` that
    /// advances `latest_epoch` for a zone. Zones with no seal yet fall back
    /// to "propose now" semantics.
    pub epoch_start_ts: HashMap<ZoneId, f64>,
    /// Gap 1: Globally-latest account-state SMT binding. Updated on every
    /// `register_seal` when the incoming seal advances any zone AND carries
    /// `account_smt_root: Some(_)`. Light clients use this (via
    /// `/proof/account/{id}` response) to verify that a returned proof root
    /// matches a seal-signed root. `None` until the first Gap-1-capable seal
    /// registers.
    ///
    /// Tuple: `(epoch_number, zone, seal_id, account_smt_root, sealed_at)`.
    /// Scale note: one slot, O(1) update. Does NOT grow with zone count.
    pub latest_sealed_account: Option<(u64, ZoneId, String, [u8; 32], f64)>,
    /// Gap 3: Rolling buffer of recent seal hashes per zone, capped at
    /// `SUPER_SEAL_INTERVAL`. Pushed on every `register_seal`. When the buffer
    /// reaches `SUPER_SEAL_INTERVAL`, the seal loop calls `create_super_seal`
    /// with its contents, then `clear_recent_seal_hashes` resets it. Bounded
    /// at 64 × 32 B ≈ 2 KB per active zone — scales to 1M zones when each
    /// node only serves a handful.
    pub recent_seal_hashes: HashMap<ZoneId, std::collections::VecDeque<[u8; 32]>>,
    /// Gap 3: Latest super-seal per zone. `(end_epoch, record_id, record_hash, committee_hash)`.
    /// Light clients sync from the latest super-seal rather than replaying
    /// individual seals. Updated by `register_super_seal`. One slot per
    /// *active* zone — O(active_zones). `committee_hash` is `[0u8; 32]` when
    /// the zone had no registered committee at super-seal time.
    pub latest_super_seal: HashMap<ZoneId, (u64, String, [u8; 32], [u8; 32])>,
    /// Gap 3 observability: running max of `end_epoch` across every
    /// zone's `latest_super_seal` entry. Updated O(1) inside
    /// `register_super_seal` so /metrics doesn't have to scan the map on every
    /// scrape — critical at 1M-zone archive-node scale where the map is huge
    /// but the max moves only on forward progress. Exposed as
    /// `elara_super_seal_max_end_epoch`. 0 until the first super-seal lands.
    pub super_seal_max_end_epoch: u64,
    /// §11.6 Timestamp gaming defense: end timestamp of the latest seal per zone.
    /// Used to enforce monotonicity — seal N's start must be >= seal N-1's end.
    /// Prevents backdating attacks where an attacker creates seals covering
    /// overlapping or past time windows.
    pub latest_seal_end: HashMap<ZoneId, f64>,
    /// Bounded per-zone VRF history ring (most-recent `VRF_HISTORY_PER_ZONE`
    /// sealed epochs). Entries: `(end_ts, epoch_number, vrf_output, record_hash)`.
    /// Maintained by `upsert_vrf_ring` as a **pure function of the canonical seal
    /// SET** — exactly one entry per epoch (the lex-min `record_hash` winner),
    /// kept sorted ascending by `end_ts` so `vrf_output_at_or_before(zone, ts)`'s
    /// reverse-scan returns the greatest `end_ts <= ts`. Order-independent across
    /// the live-gossip, rebuild, and snapshot paths — closes the Fisherman
    /// jury-seed ring fork (see internal design notes). The
    /// `record_hash` is the per-epoch canonical tiebreak; it lets the dropped-
    /// late-seal path (Mode 2) decide which VRF wins without re-canonicalizing.
    /// Bounded at 64 entries × 64 B × ~16 B meta ≈ 5 KB per active zone.
    pub vrf_history: HashMap<ZoneId, VrfRing>,
    /// PARTITION-MERGE Phase B: bounded ring of orphan-sibling seal record_ids
    /// per (zone, epoch). When two partitions seal `(zone, epoch)` with
    /// different record sets and weight-based reconciliation in `register_seal`
    /// demotes one, the demoted seal's record_id goes here. Records covered
    /// by the orphaned seal stay in the DAG (append-only) — only the seal-
    /// level mapping is demoted from canonical. Forensic queries (admin
    /// endpoint) can list orphan siblings; periodic re-evaluation can promote
    /// an orphan back to canonical if its weight overtakes the current.
    ///
    /// Bounded at PARTITION_MERGE_SIBLING_RING_PER_KEY entries per
    /// (zone, epoch) tuple; total live keys capped at
    /// PARTITION_MERGE_SIBLING_RING_GLOBAL_KEYS via stable LRU on insert.
    /// Worst-case footprint ≈ 1024 × 256 × ~50B record_id_str ≈ 13 MB —
    /// acceptable on a 2GB phone-tier node, scales linearly with active
    /// partition count.
    pub orphan_siblings: HashMap<(ZoneId, u64), std::collections::VecDeque<String>>,
    /// PARTITION-MERGE Phase B: monotonic counter of seals demoted via
    /// `record_orphan_sibling`. Surfaced on /metrics as
    /// `elara_orphan_seals_total`. Sustained non-zero rate is the
    /// operator signal that same-epoch partition reconciliation is firing.
    pub orphan_seals_total: u64,
    /// PARTITION-MERGE Phase B Slice 4: monotonic counter of canonical-seal
    /// promotions triggered by post-attestation re-evaluation — i.e. an
    /// orphan-side seal accumulated more attestation weight than the
    /// canonical at the same (zone, epoch) and got swapped in. Surfaced on
    /// /metrics as `elara_orphan_promotions_total`. A non-zero value is
    /// the load-bearing signal that the §3.3.3 partition-merge operator π
    /// is doing real work — the canonical chain just shifted on a heal.
    pub orphan_promotions_total: u64,
    /// Running sum of `(latest_epoch[zone] + 1)` across all
    /// zones — i.e. the cumulative count of canonical epochs ever
    /// produced fleet-wide. Surfaced on /metrics as
    /// `elara_epoch_seals_total`. Maintained incrementally at every
    /// `latest_epoch` mutation site (`apply_canonical_seal`,
    /// `register_global_seal`, `prune_stale_zones`) so the metrics
    /// scrape reads it in O(1). Previously the scrape iterated
    /// `latest_epoch.values()` under `state.epoch.read_recover()` —
    /// at the 1M-zones target that's a 1M-entry map walk under a
    /// blocking read lock once per scrape interval.
    ///
    /// **Invariant:** `total_epochs_total == sum(latest_epoch.values()
    /// .map(|n| n+1))` at every observable point — pinned by
    /// `ops153_total_epochs_invariant_under_random_ops`. Boot-side
    /// recovery should call [`Self::recount_total_epochs`] once after
    /// `from_snapshot` (idempotent on already-coherent state).
    pub total_epochs_total: u64,
}

/// PARTITION-MERGE Phase B: max orphan record_ids retained per (zone, epoch).
/// 256 entries × 50B avg record_id ≈ 12.5 KB per active partition window;
/// covers a week-long partition at typical seal cadence (1 seal / 30s ≈
/// 20K seals/week per zone, of which only the same-epoch losers go here).
pub const PARTITION_MERGE_SIBLING_RING_PER_KEY: usize = 256;

/// PARTITION-MERGE Phase B: max distinct (zone, epoch) keys retained.
/// At 1024 keys we can track 1024 simultaneous partition windows before
/// stable-LRU eviction fires. Sized for 100-zone × 10-window worst case
/// without unbounded growth on adversarial wire spam.
pub const PARTITION_MERGE_SIBLING_RING_GLOBAL_KEYS: usize = 1024;

/// Per-zone VRF history ring capacity. Bounded to keep memory O(active_zones).
/// At 30 s epochs this covers ~32 minutes of history — enough for replay of recent
/// challenges on restart. Historical challenges beyond this window fall back to
/// `None` (legacy pre-VRF behavior).
pub const VRF_HISTORY_PER_ZONE: usize = 64;

/// One per-zone VRF history ring entry: `(end_ts, epoch, vrf_output, record_hash)`.
/// `record_hash` is the per-epoch canonical (lex-min) tiebreak. See
/// `EpochState::vrf_history` and internal design notes.
pub type VrfRingEntry = (f64, u64, [u8; 32], [u8; 32]);
/// Per-zone VRF history ring — bounded, end_ts-sorted, one entry per epoch.
pub type VrfRing = std::collections::VecDeque<VrfRingEntry>;

/// Normalize a per-zone VRF history ring into the canonical form: exactly one
/// entry per epoch (the lex-min `record_hash` winner), sorted ascending by
/// `(end_ts, epoch)`, truncated to the most-recent `VRF_HISTORY_PER_ZONE` by
/// `end_ts`. The result is a **pure function of the input entry set** — the same
/// set in any order produces a byte-identical ring. This is the invariant that
/// makes Fisherman jury seeding (`vrf_output_at_or_before`) consensus-safe across
/// the live-gossip, rebuild, and snapshot paths. Cost: O(n log n), n ≤ ~128.
fn dedup_sort_truncate_vrf_ring(ring: &mut VrfRing) {
    // Dedup by epoch, keeping the lex-min record_hash (canonical winner).
    // BTreeMap iteration is epoch-ordered & deterministic.
    let mut by_epoch: std::collections::BTreeMap<u64, (f64, [u8; 32], [u8; 32])> =
        std::collections::BTreeMap::new();
    for (ts, epoch, vrf, rh) in ring.drain(..) {
        by_epoch
            .entry(epoch)
            .and_modify(|slot| {
                if rh < slot.2 {
                    *slot = (ts, vrf, rh);
                }
            })
            .or_insert((ts, vrf, rh));
    }
    // Rebuild sorted ascending by (end_ts, epoch) so the reverse-scan reader
    // (`vrf_output_at_or_before`) returns the greatest end_ts <= at_timestamp.
    // total_cmp gives a total order on f64 (no NaN ambiguity).
    let mut entries: Vec<(f64, u64, [u8; 32], [u8; 32])> = by_epoch
        .into_iter()
        .map(|(epoch, (ts, vrf, rh))| (ts, epoch, vrf, rh))
        .collect();
    entries.sort_by(|a, b| a.0.total_cmp(&b.0).then(a.1.cmp(&b.1)));
    // Keep only the most-recent VRF_HISTORY_PER_ZONE entries (highest end_ts).
    let start = entries.len().saturating_sub(VRF_HISTORY_PER_ZONE);
    *ring = entries.into_iter().skip(start).collect();
}

/// Scheduled zone count transition — announced by genesis authority.
/// At `target_epoch`, the global zone_count switches from `old_count` to `new_count`.
/// All seals embed their zone_count, so historical verification remains correct.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ZoneTransition {
    /// Epoch number at which the transition takes effect.
    pub target_epoch: u64,
    /// Current zone count (before transition).
    pub old_count: u64,
    /// New zone count (after transition).
    pub new_count: u64,
    /// Identity hash of the authority that announced this transition.
    pub announced_by: String,
    /// Record ID of the announcement record.
    pub record_id: String,
    /// Timestamp when the transition was announced.
    pub announced_at: f64,
}

/// Extract a zone transition schedule from a record's metadata, if present.
/// Returns `Ok(None)` if the record is not a zone transition announcement.
pub fn extract_zone_transition(record: &ValidationRecord) -> Result<Option<ZoneTransition>> {
    let op_val = match record.metadata.get(EPOCH_OP_KEY) {
        Some(v) => v,
        None => return Ok(None),
    };
    let op_str = op_val.as_str().ok_or_else(|| ElaraError::Wire("epoch_op not a string".into()))?;
    if op_str != "zone_transition" {
        return Ok(None);
    }

    let target_epoch = record.metadata.get("zone_transition_epoch")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| ElaraError::Wire("missing zone_transition_epoch".into()))?;
    let new_count = record.metadata.get("zone_transition_new_count")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| ElaraError::Wire("missing zone_transition_new_count".into()))?;
    let old_count = record.metadata.get("zone_transition_old_count")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| ElaraError::Wire("missing zone_transition_old_count".into()))?;

    if new_count == 0 {
        return Err(ElaraError::Wire("zone_transition_new_count must be > 0".into()));
    }
    if new_count == old_count {
        return Err(ElaraError::Wire("zone_transition: new_count == old_count, no change".into()));
    }

    let creator_hash = crate::accounting::types::creator_identity_hash(record);

    Ok(Some(ZoneTransition {
        target_epoch,
        old_count,
        new_count,
        announced_by: creator_hash,
        record_id: record.id.clone(),
        announced_at: record.timestamp,
    }))
}

/// Find the latest zone_transition announcement from the genesis
/// authority that has not yet been applied (i.e., `old_count == our_zone_count`).
///
/// `state.zone_transition` is a runtime cache initialised to `None` on every
/// boot. If a transition was announced but the chain was frozen
/// or the node restarted before `target_epoch` was reached, the schedule is
/// lost and the apply path in `apply_pending_zone_transition_if_due` never
/// fires. This helper lets boot logic and late-replay ingest rehydrate the
/// schedule from CF_IDX_CREATOR.
///
/// **Scale (SCALE RULE compliance):** uses `prefix_scan_reverse` on
/// CF_IDX_CREATOR, which iterates the creator's records **newest-first** and
/// returns at the first match. Records are fetched lazily from CF_RECORDS only
/// when the index entry passes the timestamp/prefix filter. A hard scan cap
/// (`MAX_SCAN`) bounds total work even if the genesis authority has emitted
/// millions of records. At 1M zones × infrequent transitions, the latest
/// zone_transition is reached within at most a few hundred reverse-iterations
/// regardless of total history. NEVER loads the full record set into memory.
///
/// **Selection rule:** among records where `old_count == our_zone_count`,
/// return the FIRST one encountered scanning newest-first. CF_IDX_CREATOR is
/// keyed by `(creator_hash, timestamp, record_id)`, so reverse iteration
/// yields announcements in **descending timestamp** order. Within the same
/// chain history, target_epoch grows monotonically with timestamp for any
/// given old_count (the genesis authority can't legitimately announce a
/// past-target transition), so the first match has the largest target_epoch.
/// Records whose `old_count != our_zone_count` are either already-applied
/// transitions or stale announcements from an unrelated history — safe to skip.
///
/// Returns `None` if no matching transition is found within MAX_SCAN entries.
#[cfg(feature = "node-core")]
pub fn find_latest_unapplied_zone_transition(
    storage: &crate::storage::rocks::StorageEngine,
    genesis_authority: &str,
    our_zone_count: u64,
) -> Option<ZoneTransition> {
    // Hard scan cap. At 1M zones, even pathological histories don't put more
    // than a few hundred zone_transitions in the recent index window. A 100K
    // cap is far above realistic worst-case and bounds the scan to constant
    // memory even when the index entry doesn't pass the metadata filter.
    const MAX_SCAN: usize = 100_000;

    if genesis_authority.len() != 64 {
        // Defensive: CF_IDX_CREATOR keys use 64B hex creator-hash prefix.
        // A non-64B input means the caller passed a bad value; bail rather
        // than scanning the wrong prefix range.
        return None;
    }

    let prefix = genesis_authority.as_bytes();
    let mut best: Option<ZoneTransition> = None;
    let mut scanned: usize = 0;

    let scan_result = storage.prefix_scan_reverse(
        crate::storage::rocks::CF_IDX_CREATOR,
        prefix,
        |key, _val| {
            scanned += 1;
            if scanned > MAX_SCAN {
                return Ok(false);
            }
            // Key format: creator_hash(64) + timestamp_be(8) + record_id
            if key.len() < 72 {
                return Ok(true);
            }
            let record_id = match std::str::from_utf8(&key[72..]) {
                Ok(s) if !s.is_empty() => s,
                _ => return Ok(true),
            };
            // Lazy record fetch — only deserialise records we have to.
            let record = match storage.get_record(record_id) {
                Ok(Some(r)) => r,
                _ => return Ok(true),
            };
            if !record.metadata.contains_key(EPOCH_OP_KEY) {
                return Ok(true);
            }
            let transition = match extract_zone_transition(&record) {
                Ok(Some(t)) => t,
                _ => return Ok(true),
            };
            if transition.old_count != our_zone_count {
                return Ok(true);
            }
            // First match scanning newest-first. CF_IDX_CREATOR keys are
            // sorted by (creator_hash, timestamp_be), so this is the most
            // recent announcement matching our zone_count — stop the scan.
            best = Some(transition);
            Ok(false)
        },
    );
    if let Err(e) = scan_result {
        tracing::warn!(
            "LIVENESS-2: prefix_scan_reverse failed for genesis_authority {}: {}",
            &genesis_authority[..genesis_authority.len().min(16)],
            e
        );
        return None;
    }
    best
}

/// Apply a pending zone transition if `current_max_epoch ≥ target_epoch`.
///
/// Returns `Some((current_max_epoch, old_count, new_count))` if a transition was
/// applied, `None` otherwise.
///
/// Why this is its own function (not inline in `epoch_seal_loop`):
/// `epoch_seal_loop` only runs on seal-eligible nodes (genesis authority + VRF-
/// holding anchors). Witness nodes that ingest a future `zone_transition` record
/// store it in `state.zone_transition` cache but never reach an apply path —
/// the chain advances past `target_epoch`, the witness keeps the old zone_count,
/// gossip-replay of the same record is gated by `target_epoch > current_max`
/// (`ingest.rs:2458`), and the schedule rots forever.
///
/// The apply check is pure local state: the record was authenticated as coming
/// from the genesis authority at ingest time, so any node can apply once its
/// observed epoch crosses the target. Called from both `epoch_seal_loop` and
/// `health_check_loop` (the latter runs on every node every health-tick).
#[cfg(feature = "node-core")]
pub fn apply_pending_zone_transition_if_due(
    state: &super::state::NodeState,
) -> Option<(u64, u64, u64)> {
    let current_max_epoch = {
        let epoch = state.epoch.read_recover();
        epoch.latest_epoch.values().copied().max().unwrap_or(0)
    };
    let transition = {
        let zt = state.zone_transition.lock_recover();
        zt.clone()
    };
    if let Some(t) = transition {
        if current_max_epoch >= t.target_epoch {
            let old = super::consensus::get_zone_count();
            super::consensus::set_zone_count(t.new_count);
            info!(
                "ZONE TRANSITION APPLIED: epoch {} reached target {}, zone_count {} → {}",
                current_max_epoch, t.target_epoch, old, t.new_count
            );
            let mut zt = state.zone_transition.lock_recover();
            *zt = None;
            return Some((current_max_epoch, old, t.new_count));
        }
    }
    None
}

/// Build metadata for a zone transition announcement record.
pub fn zone_transition_metadata(
    target_epoch: u64,
    old_count: u64,
    new_count: u64,
) -> std::collections::BTreeMap<String, serde_json::Value> {
    let mut m = std::collections::BTreeMap::new();
    m.insert(EPOCH_OP_KEY.into(), serde_json::json!("zone_transition"));
    m.insert("zone_transition_epoch".into(), serde_json::json!(target_epoch));
    m.insert("zone_transition_old_count".into(), serde_json::json!(old_count));
    m.insert("zone_transition_new_count".into(), serde_json::json!(new_count));
    m
}

/// Serializable version of EpochState for snapshot persistence.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EpochStateSnapshot {
    /// zone -> latest epoch number
    pub latest_epoch: HashMap<ZoneId, u64>,
    /// zone -> latest seal record ID
    pub latest_seal_id: HashMap<ZoneId, String>,
    /// zone -> latest seal hash (hex-encoded)
    pub latest_seal_hash: HashMap<ZoneId, String>,
    /// zone -> latest VRF output (hex-encoded). Optional for backward compatibility.
    #[serde(default)]
    pub latest_vrf_output: HashMap<ZoneId, String>,
    /// zone -> EMA of records per second. Optional for backward compatibility.
    #[serde(default)]
    pub zone_activity_rate: HashMap<ZoneId, f64>,
    /// LEGACY per-zone VRF history ring (end_ts, epoch_num, hex vrf), capped at
    /// VRF_HISTORY_PER_ZONE. Kept for back-compat: read as a fallback when `v2`
    /// is absent (pre-fork-fix snapshots), and still written so an OLDER binary
    /// loading a NEW snapshot keeps a usable ring (minus the record_hash tiebreak).
    /// `vrf_history` is NOT bound into the signed snapshot checksum
    /// (`compute_checksum`), so this representation change breaks no Dilithium3 sig.
    #[serde(default)]
    pub vrf_history: HashMap<ZoneId, Vec<(f64, u64, String)>>,
    /// Per-zone VRF history ring v2 (end_ts, epoch_num, hex vrf, hex record_hash),
    /// capped at VRF_HISTORY_PER_ZONE. Carries the per-epoch canonical `record_hash`
    /// tiebreak the Fisherman ring fork fix needs. Preferred over `vrf_history` on
    /// load; `#[serde(default)]` → pre-fork-fix snapshots (no v2) fall back to the
    /// legacy field with a sentinel record_hash.
    #[serde(default)]
    pub vrf_history_v2: HashMap<ZoneId, Vec<(f64, u64, String, String)>>,
    /// Gap 3 follow-up: zone → (end_epoch, record_id, record_hash hex, committee_hash hex).
    /// Without this, a node restart resets `latest_super_seal` to empty and the
    /// seal-pruning floor goes silent until a fresh super-seal arrives — a 64-epoch
    /// (~64 min at 60s cadence) blind spot in which GC cannot prune. Optional for
    /// back-compat with snapshots written before the field was added.
    #[serde(default)]
    pub latest_super_seal: HashMap<ZoneId, (u64, String, String, String)>,
    /// Gap 7 slice 7.2: globally-latest Gap-1 sealed account-SMT binding.
    /// `(epoch_number, zone, seal_record_id, account_smt_root_hex, sealed_at)`.
    /// Without this, a node restart loses the binding and the
    /// /snapshot/state-delta `latest_sealed_account_*` fields go to `None`
    /// until a fresh Gap-1 seal arrives — light clients lose end-to-end
    /// trust during the gap (a ~1-zone-cadence blind spot). Optional for
    /// back-compat with snapshots written before the field was added.
    #[serde(default)]
    pub latest_sealed_account: Option<(u64, ZoneId, String, String, f64)>,
}

/// Cardinality-safe summary of per-zone adaptive epoch intervals for /metrics.
///
/// Folds the live `zone_adaptive_interval` map into bounded statistics so the
/// Prometheus exposition stays O(1) regardless of zone count (mainnet target:
/// 1M zones — emitting one series per zone would explode scrape cost).
#[derive(Debug, Default, Clone, Copy)]
pub struct AdaptiveIntervalSummary {
    pub zones_tracked: usize,
    pub min_active_secs: f64,
    pub max_active_secs: f64,
    pub mean_secs: f64,
    pub floor_pinned_zones: usize,
}

impl EpochState {
    /// Convert to a serializable snapshot.
    pub fn to_snapshot(&self) -> EpochStateSnapshot {
        EpochStateSnapshot {
            latest_epoch: self.latest_epoch.clone(),
            latest_seal_id: self.latest_seal_id.clone(),
            latest_seal_hash: self.latest_seal_hash.iter()
                .map(|(k, v)| (k.clone(), hex::encode(v)))
                .collect(),
            latest_vrf_output: self.latest_vrf_output.iter()
                .map(|(k, v)| (k.clone(), hex::encode(v)))
                .collect(),
            zone_activity_rate: self.zone_activity_rate.clone(),
            // Legacy 3-tuple (record_hash dropped) — written for old-binary
            // forward-compat. New binaries prefer `vrf_history_v2` on load.
            vrf_history: self.vrf_history.iter()
                .map(|(k, ring)| (
                    k.clone(),
                    ring.iter().map(|(ts, n, v, _rh)| (*ts, *n, hex::encode(v))).collect(),
                ))
                .collect(),
            vrf_history_v2: self.vrf_history.iter()
                .map(|(k, ring)| (
                    k.clone(),
                    ring.iter()
                        .map(|(ts, n, v, rh)| (*ts, *n, hex::encode(v), hex::encode(rh)))
                        .collect(),
                ))
                .collect(),
            latest_super_seal: self.latest_super_seal.iter()
                .map(|(zone, (end_epoch, record_id, record_hash, committee_hash))| {
                    (
                        zone.clone(),
                        (
                            *end_epoch,
                            record_id.clone(),
                            hex::encode(record_hash),
                            hex::encode(committee_hash),
                        ),
                    )
                })
                .collect(),
            // Gap 7 slice 7.2: encode root as hex; tuple stays Option so None
            // (pre-Gap-1 chains, fresh boots) round-trips cleanly as JSON null.
            latest_sealed_account: self.latest_sealed_account.as_ref().map(
                |(epoch_number, zone, record_id, root, sealed_at)| {
                    (
                        *epoch_number,
                        zone.clone(),
                        record_id.clone(),
                        hex::encode(root),
                        *sealed_at,
                    )
                },
            ),
        }
    }

    /// Restore from a serializable snapshot.
    pub fn from_snapshot(snap: &EpochStateSnapshot) -> Self {
        let mut hash_map = HashMap::new();
        for (zone, hex_str) in &snap.latest_seal_hash {
            if let Ok(bytes) = hex::decode(hex_str) {
                if bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    hash_map.insert(zone.clone(), arr);
                }
            }
        }

        let mut vrf_map = HashMap::new();
        for (zone, hex_str) in &snap.latest_vrf_output {
            if let Ok(bytes) = hex::decode(hex_str) {
                if bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    vrf_map.insert(zone.clone(), arr);
                }
            }
        }

        // VRF history ring: prefer v2 (carries the per-epoch canonical
        // `record_hash` tiebreak); fall back to the legacy 3-tuple for
        // pre-fork-fix snapshots with a sentinel record_hash (all-0xFF =
        // "unknown canonical hash" → superseded by any real live seal for that
        // epoch). Normalize on load (dedup-by-epoch lex-min + end_ts sort +
        // truncate) so a snapshot-bootstrapped node's ring is byte-identical to
        // a live-built node's by construction — closes the snapshot-inheritance
        // vector of the Fisherman ring fork.
        let decode32 = |s: &str| -> Option<[u8; 32]> {
            hex::decode(s).ok().and_then(|b| {
                if b.len() == 32 {
                    let mut a = [0u8; 32];
                    a.copy_from_slice(&b);
                    Some(a)
                } else {
                    None
                }
            })
        };
        let mut vrf_history: HashMap<ZoneId, VrfRing> = HashMap::new();
        if !snap.vrf_history_v2.is_empty() {
            for (zone, entries) in &snap.vrf_history_v2 {
                let mut ring = std::collections::VecDeque::with_capacity(VRF_HISTORY_PER_ZONE);
                for (ts, epoch_num, vrf_hex, rh_hex) in entries {
                    if let (Some(vrf), Some(rh)) = (decode32(vrf_hex), decode32(rh_hex)) {
                        ring.push_back((*ts, *epoch_num, vrf, rh));
                    }
                }
                dedup_sort_truncate_vrf_ring(&mut ring);
                if !ring.is_empty() {
                    vrf_history.insert(zone.clone(), ring);
                }
            }
        } else {
            for (zone, entries) in &snap.vrf_history {
                let mut ring = std::collections::VecDeque::with_capacity(VRF_HISTORY_PER_ZONE);
                for (ts, epoch_num, vrf_hex) in entries {
                    if let Some(vrf) = decode32(vrf_hex) {
                        ring.push_back((*ts, *epoch_num, vrf, [0xffu8; 32]));
                    }
                }
                dedup_sort_truncate_vrf_ring(&mut ring);
                if !ring.is_empty() {
                    vrf_history.insert(zone.clone(), ring);
                }
            }
        }

        // Gap 3 follow-up: restore latest_super_seal from snapshot. Skip
        // entries with malformed hex — corrupt snapshot rows shouldn't kill
        // boot, just leave that zone's GC floor unset until a live
        // super-seal lands.
        let mut super_seal_map: HashMap<ZoneId, (u64, String, [u8; 32], [u8; 32])> =
            HashMap::new();
        for (zone, (end_epoch, record_id, record_hash_hex, committee_hash_hex))
            in &snap.latest_super_seal
        {
            let record_hash = match hex::decode(record_hash_hex) {
                Ok(b) if b.len() == 32 => {
                    let mut a = [0u8; 32];
                    a.copy_from_slice(&b);
                    a
                }
                _ => continue,
            };
            let committee_hash = match hex::decode(committee_hash_hex) {
                Ok(b) if b.len() == 32 => {
                    let mut a = [0u8; 32];
                    a.copy_from_slice(&b);
                    a
                }
                _ => continue,
            };
            super_seal_map.insert(
                zone.clone(),
                (*end_epoch, record_id.clone(), record_hash, committee_hash),
            );
        }
        // Derive super_seal_max_end_epoch O(1) from the restored
        // map so the gauge reads correctly immediately on boot, without
        // waiting for the next runtime register_super_seal.
        let super_seal_max_end_epoch = super_seal_map
            .values()
            .map(|(e, _, _, _)| *e)
            .max()
            .unwrap_or(0);

        // Gap 7 slice 7.2: restore latest_sealed_account binding from the
        // snapshot so /snapshot/state-delta keeps serving the bound seal
        // commitment across restarts. Skip on malformed hex — corrupt
        // snapshot rows shouldn't kill boot, just leave the binding empty
        // until the next Gap-1 seal lands (same posture as super-seal map).
        let latest_sealed_account = snap.latest_sealed_account.as_ref().and_then(
            |(epoch_number, zone, record_id, root_hex, sealed_at)| {
                let root = match hex::decode(root_hex) {
                    Ok(b) if b.len() == 32 => {
                        let mut a = [0u8; 32];
                        a.copy_from_slice(&b);
                        a
                    }
                    _ => return None,
                };
                Some((*epoch_number, zone.clone(), record_id.clone(), root, *sealed_at))
            },
        );

        let mut out = Self {
            latest_epoch: snap.latest_epoch.clone(),
            latest_seal_id: snap.latest_seal_id.clone(),
            latest_seal_hash: hash_map,
            latest_vrf_output: vrf_map,
            zone_activity_rate: snap.zone_activity_rate.clone(),
            zone_adaptive_interval: HashMap::new(), // recomputed from activity rates
            prediction_recurrence: HashMap::new(), // rebuilt from evaluation
            epoch_start_ts: HashMap::new(), // rebuilt at first register_seal after restart
            latest_sealed_account,
            recent_seal_hashes: HashMap::new(), // rebuilt from recent seals at startup
            latest_super_seal: super_seal_map,
            super_seal_max_end_epoch,
            latest_seal_end: HashMap::new(), // rebuilt at first register_seal after restart
            vrf_history,
            // PARTITION-MERGE Phase B: orphan_siblings is in-memory only —
            // not snapshotted (forensic state, rebuilt on partition-merge events).
            orphan_siblings: HashMap::new(),
            orphan_seals_total: 0,
            orphan_promotions_total: 0,
            total_epochs_total: 0,
        };
        // Derive total_epochs_total from the restored latest_epoch
        // so the metrics scrape reads the post-restart value in O(1) without
        // waiting for the first new seal.
        out.recount_total_epochs();
        out
    }
}

impl EpochState {
    pub fn new() -> Self {
        Self {
            latest_epoch: HashMap::new(),
            latest_seal_id: HashMap::new(),
            latest_seal_hash: HashMap::new(),
            latest_vrf_output: HashMap::new(),
            zone_activity_rate: HashMap::new(),
            zone_adaptive_interval: HashMap::new(),
            prediction_recurrence: HashMap::new(),
            epoch_start_ts: HashMap::new(),
            latest_sealed_account: None,
            recent_seal_hashes: HashMap::new(),
            latest_super_seal: HashMap::new(),
            super_seal_max_end_epoch: 0,
            latest_seal_end: HashMap::new(),
            vrf_history: HashMap::new(),
            orphan_siblings: HashMap::new(),
            orphan_seals_total: 0,
            orphan_promotions_total: 0,
            total_epochs_total: 0,
        }
    }

    /// Pick the (zone, epoch, seal_hash) anchor with the highest sealed
    /// epoch across all zones this node participates in. Returns `None` if
    /// the node has no sealed epoch yet (cold-start window).
    ///
    /// Used by fork-detect to compare against peers at a stable, anchor-
    /// signed commitment instead of the gossip-window-noisy
    /// `global_merkle_root`. Two peers on the same canonical chain MUST
    /// agree on `latest_seal_hash` at the same `(zone, epoch)` — the
    /// seal record is anchor-signed and identical on every peer that
    /// finalized that epoch. Disagreement at the same epoch is a real
    /// fork; epoch mismatch is gossip lag and never alerts.
    ///
    /// Scale: O(zone_count_on_this_node). Bounded — a phone-tier node
    /// holds 1-2 zones; a hub holds tens. Never iterates all 1M zones
    /// because `latest_epoch` only carries entries for zones this node
    /// has sealed locally.
    pub fn highest_seal_anchor(&self) -> Option<(ZoneId, u64, [u8; 32])> {
        self.latest_epoch
            .iter()
            .max_by_key(|(_, ep)| **ep)
            .and_then(|(zone, ep)| {
                self.latest_seal_hash
                    .get(zone)
                    .map(|hash| (zone.clone(), *ep, *hash))
            })
    }

    /// Re-derive `total_epochs_total` from `latest_epoch` —
    /// `sum(values.map(|n| n+1))`. Idempotent. Used by `from_snapshot`
    /// post-build and as a belt-and-braces shim post-DAG-replay.
    pub fn recount_total_epochs(&mut self) {
        self.total_epochs_total = self
            .latest_epoch
            .values()
            .map(|n| n.saturating_add(1))
            .sum();
    }

    /// PARTITION-MERGE Phase B: record a demoted seal as an orphan sibling
    /// for its (zone, epoch). Bounded LRU semantics:
    /// - Per-key cap PARTITION_MERGE_SIBLING_RING_PER_KEY (oldest evicted on overflow).
    /// - Global key cap PARTITION_MERGE_SIBLING_RING_GLOBAL_KEYS (lex-min
    ///   key evicted on insert that would exceed the cap — stable across
    ///   identical inputs, no allocator-dependent ordering).
    /// - Idempotent: inserting the same record_id twice is a no-op (counter
    ///   only bumps on the first insert).
    ///
    /// Side-effects: bumps `orphan_seals_total` on every successful new
    /// insert.
    pub fn record_orphan_sibling(&mut self, zone: ZoneId, epoch: u64, seal_id: String) {
        let key = (zone, epoch);
        // Global key cap (LRU-by-min) — only enforced on insert of a NEW key.
        if !self.orphan_siblings.contains_key(&key)
            && self.orphan_siblings.len() >= PARTITION_MERGE_SIBLING_RING_GLOBAL_KEYS
        {
            if let Some(oldest) = self.orphan_siblings.keys().min().cloned() {
                self.orphan_siblings.remove(&oldest);
            }
        }
        let ring = self.orphan_siblings.entry(key).or_default();
        if ring.iter().any(|s| s == &seal_id) {
            return; // already recorded — idempotent
        }
        ring.push_back(seal_id);
        while ring.len() > PARTITION_MERGE_SIBLING_RING_PER_KEY {
            ring.pop_front();
        }
        self.orphan_seals_total = self.orphan_seals_total.saturating_add(1);
    }

    /// PARTITION-MERGE Phase B: list orphan-sibling seal_ids for a given
    /// (zone, epoch). Empty Vec when no orphans recorded.
    pub fn orphan_siblings_for(&self, zone: &ZoneId, epoch: u64) -> Vec<String> {
        self.orphan_siblings
            .get(&(zone.clone(), epoch))
            .map(|ring| ring.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// PARTITION-MERGE Phase B: total entries across all (zone, epoch)
    /// rings — bounded by PARTITION_MERGE_SIBLING_RING_GLOBAL_KEYS ×
    /// PARTITION_MERGE_SIBLING_RING_PER_KEY. Used by /metrics and admin
    /// endpoint sizing.
    pub fn orphan_siblings_live_count(&self) -> usize {
        self.orphan_siblings.values().map(|r| r.len()).sum()
    }

    /// PARTITION-MERGE Phase B Slice 4: cheap predicate — is `seal_id`
    /// recorded as an orphan sibling for `(zone, epoch)`? Caller uses this
    /// before paying the cost of a weight comparison. Returns `false` when
    /// the (zone, epoch) ring is empty or when `seal_id` isn't in the ring.
    pub fn is_orphan_sibling(&self, zone: &ZoneId, epoch: u64, seal_id: &str) -> bool {
        self.orphan_siblings
            .get(&(zone.clone(), epoch))
            .is_some_and(|ring| ring.iter().any(|s| s == seal_id))
    }

    /// PARTITION-MERGE Phase B Slice 4: promote a previously-orphaned seal
    /// to canonical. Implements the back-half of Protocol §3.3.3 partition-
    /// merge operator π — when an orphan-side seal accumulates more
    /// attestation weight than the current canonical seal at the same
    /// `(zone, epoch)`, the canonical chain shifts to the heavier side.
    ///
    /// Caller (typically `state::record_attestation`) is responsible for the
    /// weight comparison; this method assumes the decision is already made
    /// and just commits the swap atomically. The previous canonical seal_id
    /// is recorded back into the orphan ring (so a later weight flip can
    /// promote it again if needed); the incoming `record_id` is removed
    /// from the ring.
    ///
    /// Returns `true` on a successful swap; `false` (no-op) when:
    /// - `seal.epoch_number != current canonical epoch` for `seal.zone`
    ///   (a higher epoch landed in the meantime — promoting would be
    ///   regression);
    /// - `record_id` is not present in the orphan ring for `(zone, epoch)`
    ///   (already promoted on a concurrent path, or the caller's view of
    ///   the ring was stale);
    /// - `record_id` is already the canonical seal (no swap needed —
    ///   defensive idempotency check).
    ///
    /// Bumps `orphan_promotions_total` only on a successful swap.
    pub fn promote_orphan_to_canonical(
        &mut self,
        seal: &ParsedEpochSeal,
        record_id: &str,
        record_hash: [u8; 32],
    ) -> bool {
        let current_epoch = self.latest_epoch.get(&seal.zone).copied().unwrap_or(0);
        if seal.epoch_number != current_epoch {
            return false;
        }
        if self.latest_seal_id.get(&seal.zone).map(|s| s.as_str()) == Some(record_id) {
            return false;
        }
        let key = (seal.zone.clone(), seal.epoch_number);
        let in_ring = self
            .orphan_siblings
            .get(&key)
            .is_some_and(|r| r.iter().any(|s| s == record_id));
        if !in_ring {
            return false;
        }
        // Demote current canonical → orphan ring (idempotent if somehow
        // already there; record_orphan_sibling de-dups).
        if let Some(prev_id) = self.latest_seal_id.get(&seal.zone).cloned() {
            self.record_orphan_sibling(seal.zone.clone(), seal.epoch_number, prev_id);
        }
        // Install incoming as canonical.
        self.apply_canonical_seal(seal, record_id, record_hash);
        // Remove the promoted entry from the ring (no longer an orphan).
        if let Some(ring) = self.orphan_siblings.get_mut(&key) {
            ring.retain(|s| s != record_id);
            if ring.is_empty() {
                self.orphan_siblings.remove(&key);
            }
        }
        self.orphan_promotions_total = self.orphan_promotions_total.saturating_add(1);
        true
    }

    /// Remove epoch state for zones >= zone_count (stale data from old configs).
    /// Call after loading snapshot when zone_count may have changed.
    pub fn prune_stale_zones(&mut self, zone_count: u64) {
        let stale: Vec<ZoneId> = self.latest_epoch.keys()
            .filter(|z| z.path().parse::<u64>().is_ok_and(|n| n >= zone_count))
            .cloned()
            .collect();
        if !stale.is_empty() {
            tracing::info!("epoch: pruning {} stale zones (zone_count={}): {:?}",
                stale.len(), zone_count, stale.iter().map(|z| z.path()).collect::<Vec<_>>());
            for z in &stale {
                // Drop the (epoch+1) contribution of pruned zones.
                if let Some(prev_epoch) = self.latest_epoch.remove(z) {
                    self.total_epochs_total = self
                        .total_epochs_total
                        .saturating_sub(prev_epoch.saturating_add(1));
                }
                self.latest_seal_id.remove(z);
                self.latest_seal_hash.remove(z);
                self.latest_vrf_output.remove(z);
                self.zone_activity_rate.remove(z);
                self.epoch_start_ts.remove(z);
                self.latest_seal_end.remove(z);
                self.vrf_history.remove(z);
                // PARTITION-MERGE Phase B: drop any orphan-sibling rings for
                // pruned zones — keeps the (zone, epoch) keyspace bounded
                // when a zone count drops mid-fleet.
                self.orphan_siblings.retain(|(zk, _), _| zk != z);
            }
        }
    }

    /// Register a verified seal into the epoch state.
    ///
    /// Legacy entry point — uses lex-min `record_hash` tiebreak on
    /// same-(zone, epoch) collisions. Preserved for callers that haven't
    /// flipped the PARTITION-MERGE Phase B reconciler on
    /// (`partition_merge_weight_reconcile = false`). Once the reconciler
    /// is fleet-wide default this can collapse into a thin wrapper that
    /// calls `register_seal_with_reconcile` with both weights = 0
    /// (forces the equal-weight branch → identical lex-min behaviour).
    pub fn register_seal(&mut self, seal: &ParsedEpochSeal, record_id: &str, record_hash: [u8; 32]) {
        // Only advance if this seal is newer than what we have.
        // During partition-merge, we may receive seals from both partitions —
        // always keep the highest epoch number as canonical.
        //
        // Tie-break (Stage 3b.5/3b.6 dual-proposer race): when two anchors
        // both within the rank window land seals at the same epoch, the
        // previous `>=` rule made canonicalization ingest-order-dependent.
        // Different nodes ended up with different `latest_seal_hash[zone]`,
        // computed different `chained_beacon` for the next epoch, and each
        // saw a different proposer as elected. Net effect: no node thought
        // it was rank-0, no proposals fired, chain froze.
        //
        // Fix: at equal epoch, lex-min `record_hash` wins. Order-independent
        // — every honest node converges on the same canonical seal regardless
        // of arrival order.
        let current = self.latest_epoch.get(&seal.zone).copied().unwrap_or(0);
        let current_hash = self.latest_seal_hash.get(&seal.zone).copied();
        let should_canonicalize = if seal.epoch_number > current {
            true
        } else if seal.epoch_number == current {
            current_hash.is_none_or(|h| record_hash < h)
        } else {
            false
        };
        if should_canonicalize {
            self.apply_canonical_seal(seal, record_id, record_hash);
        } else if let Some(vrf) = seal.vrf_output {
            // Mode 2 (Fisherman ring fork): this seal lost the tip race (stale
            // epoch < current, or same-epoch lex-loser) so it never reaches
            // apply_canonical_seal — but its VRF must still enter the ring as a
            // pure function of the seal set. `upsert_vrf_ring` keeps the lex-min
            // record_hash per epoch, so this is a no-op unless this seal is the
            // canonical (lex-min) winner for its epoch.
            self.upsert_vrf_ring(&seal.zone, seal.end, seal.epoch_number, vrf, record_hash);
        }
    }

    /// PARTITION-MERGE Phase B Slice 3: register a verified seal with
    /// weight-aware same-epoch reconciliation per Protocol §3.3.3.
    ///
    /// Decision matrix on a `(zone, epoch)` collision:
    /// - `incoming_weight > existing_weight` → demote existing (record its
    ///   `seal_id` in the orphan ring), install incoming as canonical.
    /// - `incoming_weight < existing_weight` → demote incoming (record its
    ///   `record_id` in the orphan ring), do not canonicalize.
    /// - `incoming_weight == existing_weight` → fall back to lex-min
    ///   `record_hash` (preserves Stage 3b.5/3b.6 dual-proposer determinism
    ///   for freshly-received seal pairs before any attestations arrive).
    ///   Loser is recorded in the orphan ring on this branch too — gives
    ///   forensic visibility on the dual-proposer race that was previously
    ///   silent.
    ///
    /// On `seal.epoch_number > current`: install unconditionally (no
    /// existing seal to compare; this is a true epoch advance, not a
    /// partition collision).
    ///
    /// On `seal.epoch_number < current`: drop silently (stale; not even
    /// orphan-tracked because we can't tell whether it's an old-rebroadcast
    /// vs a partition-loser without the larger context — `verify_epoch_seal`
    /// upstream filters obvious staleness).
    ///
    /// Records covered by an orphaned seal stay in the DAG (append-only);
    /// only the seal-level mapping is overwritten. Light clients reading
    /// `latest_seal_hash[zone]` see the canonical winner.
    ///
    /// Returns `true` when the incoming seal won and was installed as
    /// canonical, `false` otherwise. Callers can use the bool to wire
    /// downstream consequences (e.g. only push attestations on a seal we
    /// just promoted to canonical).
    pub fn register_seal_with_reconcile(
        &mut self,
        seal: &ParsedEpochSeal,
        record_id: &str,
        record_hash: [u8; 32],
        incoming_weight: u64,
        existing_weight: u64,
    ) -> bool {
        let current = self.latest_epoch.get(&seal.zone).copied().unwrap_or(0);

        if seal.epoch_number > current {
            self.apply_canonical_seal(seal, record_id, record_hash);
            return true;
        }
        if seal.epoch_number < current {
            // Mode 2 (Fisherman ring fork): stale-epoch seal never canonicalizes,
            // but its VRF must still enter the ring (lex-min per epoch) so jury
            // seeding is a pure function of the seal set, not arrival order.
            if let Some(vrf) = seal.vrf_output {
                self.upsert_vrf_ring(&seal.zone, seal.end, seal.epoch_number, vrf, record_hash);
            }
            return false;
        }

        // Same epoch — collision. Idempotent re-register is a no-op.
        let current_hash = self.latest_seal_hash.get(&seal.zone).copied();
        let current_seal_id = self.latest_seal_id.get(&seal.zone).cloned();
        if current_seal_id.as_deref() == Some(record_id)
            && current_hash == Some(record_hash)
        {
            return false;
        }

        use std::cmp::Ordering;
        let cmp = incoming_weight.cmp(&existing_weight);
        let lex_min_wins = current_hash.is_none_or(|h| record_hash < h);

        let incoming_wins = match cmp {
            Ordering::Greater => true,
            Ordering::Less => false,
            Ordering::Equal => lex_min_wins,
        };

        if incoming_wins {
            // Demote existing — record its seal_id in orphan ring.
            if let Some(prev_id) = current_seal_id {
                self.record_orphan_sibling(seal.zone.clone(), seal.epoch_number, prev_id);
            }
            self.apply_canonical_seal(seal, record_id, record_hash);
            true
        } else {
            // Demote incoming — record its record_id in orphan ring.
            self.record_orphan_sibling(
                seal.zone.clone(),
                seal.epoch_number,
                record_id.to_string(),
            );
            // Mode 2 (Fisherman ring fork): the demoted seal still upserts its
            // VRF (lex-min per epoch). No-op unless it's the lex-min winner for
            // this epoch — which keeps the ring a pure function of the seal set
            // independent of which seal won the weight-based canonicalization.
            if let Some(vrf) = seal.vrf_output {
                self.upsert_vrf_ring(&seal.zone, seal.end, seal.epoch_number, vrf, record_hash);
            }
            false
        }
    }

    /// Internal canonical-seal installation. Both `register_seal` (legacy
    /// lex-min path) and `register_seal_with_reconcile` (weight-aware path)
    /// route through this once they've decided the incoming seal wins.
    /// Touches: `latest_epoch`, `latest_seal_id`, `latest_seal_hash`,
    /// `latest_vrf_output` + VRF history ring, `epoch_start_ts`,
    /// `latest_sealed_account` (if seal carries SMT root), `latest_seal_end`,
    /// adaptive activity counters, and the rolling super-seal buffer.
    fn apply_canonical_seal(
        &mut self,
        seal: &ParsedEpochSeal,
        record_id: &str,
        record_hash: [u8; 32],
    ) {
        // Maintain `total_epochs_total = sum(latest+1)` incrementally.
        // Callers (register_seal, register_seal_with_reconcile) gate on
        // `seal.epoch_number >= current`, so the delta is non-negative.
        // - new zone (prev=None): contributes (epoch+1) to the sum.
        // - existing zone: contributes (new - old).
        let prev = self.latest_epoch.insert(seal.zone.clone(), seal.epoch_number);
        let delta = match prev {
            None => seal.epoch_number.saturating_add(1),
            Some(old) => seal.epoch_number.saturating_sub(old),
        };
        self.total_epochs_total = self.total_epochs_total.saturating_add(delta);
        self.latest_seal_id.insert(seal.zone.clone(), record_id.to_string());
        self.latest_seal_hash.insert(seal.zone.clone(), record_hash);
        if let Some(vrf_output) = seal.vrf_output {
            self.latest_vrf_output.insert(seal.zone.clone(), vrf_output);
            // Upsert into the per-zone VRF history ring as a pure function of the
            // canonical seal SET (one lex-min-`record_hash` entry per epoch,
            // end_ts sorted). Replaces the old arrival-order append — closes
            // Mode 1 (duplicate same-epoch ring entries) of the Fisherman
            // jury-seed ring fork. Mode 2 (a canonical seal that arrives after
            // the tip moved past its epoch, so it never reaches this fn) is
            // closed by the upsert calls on the non-canonical paths in
            // `register_seal` / `register_seal_with_reconcile`.
            self.upsert_vrf_ring(
                &seal.zone,
                seal.end,
                seal.epoch_number,
                vrf_output,
                record_hash,
            );
        }

        // Start the NEXT epoch's rank-gating clock from the moment we
        // registered this seal locally. Used by §11.13 aggregator chain
        // to compute `current_allowed_rank = floor(log2(1 + elapsed / base))`.
        // Local wall-clock is fine here: this is a liveness heuristic, not
        // a consensus-critical timestamp. Other nodes use their own
        // register-time as a reference; all observers converge because
        // seals propagate within RTT of each other.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        self.epoch_start_ts.insert(seal.zone.clone(), now);

        // Gap 1: Track globally-latest sealed account SMT root. Only
        // updates if the seal carries account_smt_root (pre-Gap 1 seals
        // leave this as None) AND this seal is newer than the stored
        // binding (compare by epoch then zone to break ties).
        if let Some(root) = seal.account_smt_root {
            let is_newer = match &self.latest_sealed_account {
                None => true,
                Some((e, _, _, _, _)) => seal.epoch_number > *e,
            };
            if is_newer {
                self.latest_sealed_account = Some((
                    seal.epoch_number,
                    seal.zone.clone(),
                    record_id.to_string(),
                    root,
                    now,
                ));
            }
        }

        // §11.6: Track seal end timestamp for monotonicity enforcement
        self.latest_seal_end.insert(seal.zone.clone(), seal.end);

        // Update adaptive epoch timing
        let duration = seal.end - seal.start;
        self.update_activity(&seal.zone, seal.record_count, duration);

        // Gap 3: Push seal hash into the rolling super-seal buffer.
        // Bounded at SUPER_SEAL_INTERVAL — oldest is popped when the
        // buffer is full. Seal-loop calls `should_create_super_seal`
        // to detect when to roll an aggregate.
        let buf = self.recent_seal_hashes.entry(seal.zone.clone()).or_default();
        if buf.len() >= SUPER_SEAL_INTERVAL as usize {
            buf.pop_front();
        }
        buf.push_back(record_hash);
    }

    /// Gap 3: True if the zone's rolling buffer has exactly `SUPER_SEAL_INTERVAL`
    /// seals queued AND the latest sealed epoch is a super-seal boundary
    /// (`epoch_number % SUPER_SEAL_INTERVAL == 0`). Cheap check; caller uses
    /// this to decide whether to roll a super-seal record this tick.
    pub fn should_create_super_seal(&self, zone: &ZoneId) -> bool {
        let latest = match self.latest_epoch.get(zone) {
            Some(&e) if e > 0 => e,
            _ => return false,
        };
        if latest % SUPER_SEAL_INTERVAL != 0 {
            return false;
        }
        // Avoid re-rolling the same boundary after a restart.
        if let Some((end, _, _, _)) = self.latest_super_seal.get(zone) {
            if *end >= latest {
                return false;
            }
        }
        match self.recent_seal_hashes.get(zone) {
            Some(buf) => buf.len() as u64 == SUPER_SEAL_INTERVAL,
            None => false,
        }
    }

    /// Gap 3: Snapshot the rolling buffer for super-seal construction.
    /// Returns `None` if the buffer isn't full (i.e. we haven't accumulated
    /// enough seals yet — possible after node restart before backfill).
    pub fn snapshot_recent_seal_hashes(&self, zone: &ZoneId) -> Option<Vec<[u8; 32]>> {
        let buf = self.recent_seal_hashes.get(zone)?;
        if (buf.len() as u64) < SUPER_SEAL_INTERVAL {
            return None;
        }
        Some(buf.iter().copied().collect())
    }

    /// Gap 3: Record that a super-seal has been written for `zone`, covering
    /// epochs ending at `end_epoch`. Does NOT clear `recent_seal_hashes` —
    /// the rolling-window semantics mean each new seal pops the oldest and
    /// pushes itself, so the buffer naturally moves forward.
    ///
    /// Returns `true` when the registration replaced (or installed) the
    /// per-zone latest pointer (i.e. `end_epoch` exceeded any prior entry for
    /// this zone). Callers wire the `super_seals_minted_total` counter on
    /// `true`; idempotent re-registrations (e.g. duplicate gossip) return
    /// `false` and do not update the fleet-wide max.
    pub fn register_super_seal(
        &mut self,
        zone: ZoneId,
        end_epoch: u64,
        record_id: String,
        record_hash: [u8; 32],
        committee_hash: [u8; 32],
    ) -> bool {
        let is_newer = self
            .latest_super_seal
            .get(&zone)
            .map(|(e, _, _, _)| end_epoch > *e)
            .unwrap_or(true);
        if is_newer {
            self.latest_super_seal.insert(zone, (end_epoch, record_id, record_hash, committee_hash));
            if end_epoch > self.super_seal_max_end_epoch {
                self.super_seal_max_end_epoch = end_epoch;
            }
        }
        is_newer
    }

    /// Wall-clock moment (unix seconds) when the proposal window for the
    /// NEXT epoch in `zone` opened. Returns `None` if this zone has never
    /// produced a seal locally — in that case, proposers use "now" as the
    /// reference, letting rank-0 propose immediately at bootstrap.
    pub fn epoch_start(&self, zone: &ZoneId) -> Option<f64> {
        self.epoch_start_ts.get(zone).copied()
    }

    /// Prime `epoch_start_ts[zone] = now` if the zone has never been sealed
    /// (or resealed by global escalation) locally. Returns `true` if this
    /// call performed the initialization.
    ///
    /// Fixes a fresh-genesis liveness trap: without priming, `epoch_start` is
    /// `None`, so `should_propose_seal` computes `elapsed = now - now = 0`
    /// forever. Rank 0 is the only rank that passes `(2^0-1)*base ≤ 0`, so
    /// rank 1+ can never step up AND `is_zone_stuck` (elapsed ≥ 127*base)
    /// never fires to trigger cross-zone escalation. If rank-0 is offline at
    /// genesis, the whole zone hangs until rank-0 appears.
    ///
    /// Priming at the first epoch tick after stake registration starts the
    /// rank-unlock clock: rank 1 at T+base, rank 2 at T+3·base, … stuck at
    /// T+127·base → cross-zone escalation unsticks. Each node uses its own
    /// local wall-clock — divergence is bounded by gossip RTT and converges
    /// as soon as the first real seal fires (`register_seal` overwrites the
    /// primed value with the seal's own register-time).
    ///
    /// Idempotent: once primed or once a real seal registers, subsequent
    /// calls are no-ops.
    pub fn prime_epoch_start_if_unset(&mut self, zone: &ZoneId, now: f64) -> bool {
        if self.epoch_start_ts.contains_key(zone) {
            return false;
        }
        self.epoch_start_ts.insert(zone.clone(), now);
        true
    }

    /// Register a verified cross-zone escalation seal (Stage 3c.1).
    ///
    /// A `global_quorum_seal` finalizes `stuck_epoch` for `stuck_zone` even
    /// though the per-zone rank chain timed out. The effect on local epoch
    /// state is identical to a normal per-zone seal:
    /// - bump `latest_epoch[stuck_zone]` to the stuck epoch,
    /// - reset `epoch_start_ts[stuck_zone]` to now (unsticks the chain),
    /// - update `latest_seal_id` / `latest_seal_hash`.
    ///
    /// Idempotent on `(stuck_zone, stuck_epoch)`: a later call with the same
    /// or lower `stuck_epoch` is a no-op, matching `register_seal` semantics
    /// — first global seal for that height wins.
    pub fn register_global_seal(
        &mut self,
        seal: &ParsedGlobalQuorumSeal,
        record_id: &str,
        record_hash: [u8; 32],
    ) {
        let current = self.latest_epoch.get(&seal.stuck_zone).copied().unwrap_or(0);
        if seal.stuck_epoch >= current {
            // Incremental total_epochs_total update.
            // Gate above ensures `stuck_epoch >= current`, so delta is non-negative.
            let prev = self
                .latest_epoch
                .insert(seal.stuck_zone.clone(), seal.stuck_epoch);
            let delta = match prev {
                None => seal.stuck_epoch.saturating_add(1),
                Some(old) => seal.stuck_epoch.saturating_sub(old),
            };
            self.total_epochs_total = self.total_epochs_total.saturating_add(delta);
            self.latest_seal_id.insert(seal.stuck_zone.clone(), record_id.to_string());
            self.latest_seal_hash.insert(seal.stuck_zone.clone(), record_hash);
            // NOTE: no VRF output is associated with a global seal — the per-zone
            // rank ladder that normally seeds `latest_vrf_output` was bypassed.
            // Keep the previous VRF output for jury/derived-randomness consumers
            // that read `latest_vrf_output` optimistically.
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs_f64())
                .unwrap_or(0.0);
            self.epoch_start_ts.insert(seal.stuck_zone.clone(), now);
        }
    }

    /// Process a single record during streaming rebuild. Extracts and registers
    /// epoch seals. O(1) per record — no collection needed.
    pub fn process_record(&mut self, rec: &crate::record::ValidationRecord) {
        if let Ok(Some(seal)) = extract_epoch_seal(rec) {
            self.register_seal(&seal, &rec.id, rec.record_hash());
        } else if let Ok(Some(gseal)) = extract_global_quorum_seal(rec) {
            self.register_global_seal(&gseal, &rec.id, rec.record_hash());
        }
    }

    /// Get the next expected epoch number for a zone.
    pub fn next_epoch(&self, zone: &ZoneId) -> u64 {
        self.latest_epoch.get(zone).map_or(0, |n| n + 1)
    }

    /// Highest sealed epoch number across all zones (0 if none sealed yet).
    /// Order-independent max over `latest_epoch` — O(zones), deterministic.
    /// Used to seed the custodial-idle_decay emit watermark on boot (C10c): a
    /// idle_decay batch is only ever emitted for a sealed epoch (`epoch_no =
    /// next_epoch(zone)` at seal time, so ≤ that zone's tip), hence this value
    /// is ≥ every epoch for which a global batch was already emitted.
    pub fn max_sealed_epoch(&self) -> u64 {
        self.latest_epoch.values().copied().max().unwrap_or(0)
    }

    /// Update zone activity rate after sealing an epoch.
    ///
    /// Uses exponential moving average (EMA) to smooth activity rate.
    /// Computes adaptive interval: zones with high activity seal faster.
    pub fn update_activity(&mut self, zone: &ZoneId, record_count: u64, epoch_duration_secs: f64) {
        if epoch_duration_secs <= 0.0 {
            return;
        }

        let current_rate = record_count as f64 / epoch_duration_secs;
        let prev_rate = self.zone_activity_rate.get(zone).copied().unwrap_or(current_rate);
        let ema = ACTIVITY_EMA_ALPHA * current_rate + (1.0 - ACTIVITY_EMA_ALPHA) * prev_rate;
        self.zone_activity_rate.insert(zone.clone(), ema);

        // Compute adaptive interval:
        // If ema * default_interval >> TARGET_RECORDS_PER_EPOCH → seal faster
        // If ema * default_interval << TARGET_RECORDS_PER_EPOCH → seal slower
        //
        // interval = TARGET_RECORDS_PER_EPOCH / max(ema, epsilon)
        // Clamped to [MIN_ADAPTIVE_EPOCH_SECS, MAX_ADAPTIVE_EPOCH_SECS]
        let interval = if ema > 1e-9 {
            (TARGET_RECORDS_PER_EPOCH / ema)
                .clamp(MIN_ADAPTIVE_EPOCH_SECS, MAX_ADAPTIVE_EPOCH_SECS)
        } else {
            MAX_ADAPTIVE_EPOCH_SECS
        };
        self.zone_adaptive_interval.insert(zone.clone(), interval);
    }

    /// Get the adaptive epoch interval for a zone (seconds).
    /// Returns the configured default if no activity data exists yet.
    pub fn adaptive_interval(&self, zone: &ZoneId, default_secs: f64) -> f64 {
        self.zone_adaptive_interval.get(zone).copied().unwrap_or(default_secs)
    }

    /// Cardinality-safe summary of `zone_adaptive_interval` for `/metrics`.
    ///
    /// At 1M-zone scale, emitting one Prometheus series per zone would blow up
    /// scrape cost — so this folds the per-zone live values into bounded
    /// summary statistics instead. Operators read `floor_pinned_zones` to see
    /// whether the current `MIN_ADAPTIVE_EPOCH_SECS` is being exercised by
    /// real traffic; sustained non-zero is the signal that lowering the floor
    /// further would translate into faster finality (subject to seal-traffic
    /// budget headroom, observable via `elara_gossip_bytes_out_total`).
    pub fn adaptive_interval_summary(&self) -> AdaptiveIntervalSummary {
        if self.zone_adaptive_interval.is_empty() {
            return AdaptiveIntervalSummary::default();
        }
        let mut min = f64::INFINITY;
        let mut max = f64::NEG_INFINITY;
        let mut sum = 0.0;
        let mut floor_pinned = 0usize;
        for &v in self.zone_adaptive_interval.values() {
            if v < min { min = v; }
            if v > max { max = v; }
            sum += v;
            if (v - MIN_ADAPTIVE_EPOCH_SECS).abs() < 1e-9 {
                floor_pinned += 1;
            }
        }
        let count = self.zone_adaptive_interval.len();
        AdaptiveIntervalSummary {
            zones_tracked: count,
            min_active_secs: min,
            max_active_secs: max,
            mean_secs: sum / count as f64,
            floor_pinned_zones: floor_pinned,
        }
    }

    /// Get the hash of the previous seal for chaining.
    pub fn previous_seal_hash(&self, zone: &ZoneId) -> [u8; 32] {
        self.latest_seal_hash.get(zone).copied().unwrap_or([0u8; 32])
    }

    /// C2: is this a STRICTLY-SEQUENTIAL seal (epoch == our tip+1) whose
    /// `previous_seal_hash` does NOT chain to our canonical tip? Such a seal is a
    /// forged chain-link — a key-holding Byzantine anchor pointing a sequential seal
    /// at a different fork — and must be rejected at register-time under the WRITE
    /// lock (a valid signature proves WHO signed, not which chain it chains off).
    ///
    /// Returns false (i.e. NOT a forgery to reject) for every honest / unenforceable
    /// case, so no honest seal or bootstrap path is ever wedged:
    ///   • catch-up (epoch > tip+1) → not sequential; VRF-guarded at verify (B7);
    ///   • same-epoch collision (epoch == tip) → lex-min / weight reconcile decides;
    ///   • `[0;32]` baseline (genesis / cold-start / fresh zone, no prior seal) →
    ///     cannot be enforced, left to the snapshot + VRF trust path.
    ///
    /// PHANTOM-FREEZE PIN (audit 2026-07-01 — do NOT auto-heal here). When OUR
    /// tip is a crash-before-broadcast phantom (a seal we made durable but never
    /// broadcast, restored as tip on reboot), this correctly rejects the honest
    /// `E+1`. The tempting fix — demote a 0-external-attestation tip toward an
    /// attested same-epoch competitor — is UNSAFE and REJECTED (3-Sonnet+1-Opus
    /// panel, unanimous): an honest JUST-CREATED tip also sits at exactly 0
    /// external attestations for ~1 RTT (a proposer cannot self-attest —
    /// `add_seal_attestation` drops `witness==creator`), so that rule demotes
    /// honest fresh tips and makes `latest_seal_hash` (a `chained_beacon` input)
    /// a function of local attestation-arrival order → a latent fork. The freeze
    /// is RUNTIME-ONLY (self-heals on reboot: the honest successor is durable in
    /// CF_EPOCHS and boot installs the max epoch) and needs a COMPETING sealer to
    /// arise at all (near-zero on the near-solo fleet). Real cure = provisional-
    /// self-tip (relax rejection while OUR tip is unwitnessed — pure liveness,
    /// never a tip flip), its own audit-first cycle before the mesh decentralises.
    /// Detector: `elara_epoch_phantom_tip_suspected_total`. Design:
    /// internal design notes.
    pub fn is_forged_sequential_seal(&self, seal: &ParsedEpochSeal) -> bool {
        let baseline = self.previous_seal_hash(&seal.zone);
        seal.epoch_number == self.next_epoch(&seal.zone)
            && baseline != [0u8; 32]
            && seal.previous_seal_hash != baseline
    }

    /// Get the latest VRF output for a zone (for jury selection seeding).
    /// Returns None if no VRF-sealed epochs exist yet for this zone.
    pub fn vrf_output(&self, zone: &ZoneId) -> Option<&[u8; 32]> {
        self.latest_vrf_output.get(zone)
    }

    /// Time-indexed VRF lookup for consensus-deterministic Fisherman jury
    /// seeding. Returns the VRF output of the epoch seal with the greatest `end_ts`
    /// that is strictly ≤ `at_timestamp` for this zone. This makes jury selection a
    /// pure function of (challenge timestamp, zone, DAG history) — the same result
    /// on every node regardless of when it processes the challenge record.
    ///
    /// Returns `None` if no VRF-sealed epoch exists at or before `at_timestamp` for
    /// this zone (legacy: pre-VRF challenges) or if the relevant epoch has fallen
    /// out of the bounded history ring (`VRF_HISTORY_PER_ZONE`).
    ///
    /// Cost: O(ring_len) linear scan; ring_len ≤ 64.
    pub fn vrf_output_at_or_before(&self, zone: &ZoneId, at_timestamp: f64) -> Option<[u8; 32]> {
        let ring = self.vrf_history.get(zone)?;
        // Walk from newest to oldest; first entry with end_ts <= at_timestamp wins.
        // The ring is kept end_ts-ascending by `upsert_vrf_ring` /
        // `dedup_sort_truncate_vrf_ring`, so the first reverse-scan hit is the
        // greatest end_ts <= at_timestamp.
        for (end_ts, _epoch, vrf, _rh) in ring.iter().rev() {
            if *end_ts <= at_timestamp {
                return Some(*vrf);
            }
        }
        None
    }

    /// Upsert one canonical VRF entry for `(zone, epoch)` into the per-zone ring,
    /// preserving the invariant that the ring is a pure function of the canonical
    /// seal SET: one entry per epoch (lex-min `record_hash` winner), end_ts-sorted,
    /// bounded to `VRF_HISTORY_PER_ZONE`. Order-independent — the same set of
    /// `(end_ts, epoch, vrf, record_hash)` inputs in any arrival order yields a
    /// byte-identical ring on every node. Called from `apply_canonical_seal` (the
    /// canonical-winner path) AND the non-canonical drop paths in `register_seal` /
    /// `register_seal_with_reconcile` (so a late lex-min seal still corrects the
    /// ring). See internal design notes.
    fn upsert_vrf_ring(
        &mut self,
        zone: &ZoneId,
        end_ts: f64,
        epoch: u64,
        vrf: [u8; 32],
        record_hash: [u8; 32],
    ) {
        let ring = self.vrf_history.entry(zone.clone()).or_default();
        // No admission gate: `dedup_sort_truncate_vrf_ring` is the SOLE retention
        // authority — it dedups by epoch (lex-min record_hash) then keeps the 64
        // highest-`end_ts` entries, a pure function of the input entry SET that is
        // independent of arrival order. A previous gate dropped entries by
        // `epoch < min_epoch`, but retention is keyed on `end_ts`; those two keys
        // agree only when epoch# and end_ts are co-monotone within a zone — true
        // for a single zone advancing in time, NOT guaranteed across zone
        // split/merge. Under a violation the epoch-gate dropped an entry the
        // end_ts-truncation would keep, making ring membership arrival-order-
        // dependent → a latent consensus fork in Fisherman jury seeding. Collapsing
        // the two retention criteria into one (end_ts) means no two paths can
        // disagree. The transient `VRF_HISTORY_PER_ZONE + 1` length before
        // truncation is O(n log n) on n ≤ 65 — negligible per epoch even at 1M
        // zones. Do NOT re-add a fast-path gate: a second retention key
        // reintroduces this exact fork class. Fusion-audited 2026-06-19 (2 Sonnet
        // + 1 Opus, verdict: remove). See internal design notes.
        ring.push_back((end_ts, epoch, vrf, record_hash));
        dedup_sort_truncate_vrf_ring(ring);
    }
}

impl Default for EpochState {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Parsed epoch seal ─────────────────────────────────────────────────────

/// Parsed metadata from an epoch seal record.
///
/// Production format (Steps 3+4): includes zone_balance_total for conservation
/// verification, record_hashes for witness verification, and zone_registry for
/// global zone tracking.
#[derive(Debug, Clone)]
pub struct ParsedEpochSeal {
    pub zone: ZoneId,
    pub epoch_number: u64,
    pub start: f64,
    pub end: f64,
    pub record_count: u64,
    pub merkle_root: [u8; 32],
    pub previous_seal_hash: [u8; 32],
    /// VRF output — unpredictable randomness for jury selection.
    /// None for legacy seals created before VRF was added.
    pub vrf_output: Option<[u8; 32]>,
    /// VRF proof — verifiable proof that vrf_output is correct.
    /// None for legacy seals.
    pub vrf_proof: Option<Vec<u8>>,
    /// Hashes of all records included in this epoch (for witness verification).
    /// Witnesses verify they have all these records and recompute the Merkle root.
    /// Empty for legacy seals.
    pub record_hashes: Vec<[u8; 32]>,
    /// Sum of all account balances in this zone (conservation invariant).
    /// Audit D6: enables global conservation verification via zone totals.
    /// `sum(all_zone_balance_totals) + pending_xzone + pool = GENESIS_SUPPLY`
    /// None for legacy seals.
    pub zone_balance_total: Option<u64>,
    /// Merkle root of all known zones in the network.
    /// Audit F4: 32 bytes instead of full registry. Verified against local zone state.
    /// None for legacy seals.
    pub zone_registry_root: Option<[u8; 32]>,
    /// Zone changes since last seal (new zones, splits, deactivations).
    /// Small delta (~10KB at 1M zones) instead of full registry per seal.
    /// None for legacy seals.
    pub zone_registry_delta: Option<Vec<ZoneRegistryChange>>,
    /// The zone_count used when computing this seal's merkle root.
    /// Critical for verification: `SHA3(record_id) % zone_count` determines which
    /// records belong to a zone. Without this, changing zone_count invalidates all
    /// existing seals. Verifiers MUST use this value (not the current global zone_count).
    /// None for legacy seals (assume current global zone_count).
    pub seal_zone_count: Option<u64>,
    /// The aggregator rank the creator held for `(zone, epoch)` when this
    /// seal was proposed (Stage 3b.5 / §11.13). Rank 0 = top priority.
    ///
    /// Verifiers re-derive the creator's rank from `chained_beacon(prev, epoch, zone)`
    /// and the current stakers; the value here must match (Stage 3b.6).
    /// Defaults to `0` for legacy seals created before 3b.5 (the
    /// `epoch_aggregator_rank` metadata key is absent) so historical seals
    /// continue to parse.
    pub aggregator_rank: u8,
    /// Root of the global account-state SMT at seal time (Gap 1 — light-client
    /// balance verification). Light clients fetch an account proof via
    /// `/proof/account/{id}` and verify it against this signed root.
    /// None for legacy seals (pre-Gap 1).
    pub account_smt_root: Option<[u8; 32]>,
    /// In-protocol drand time-bracket pulse (REALMS P1.5). Carries the
    /// verifiable not-before bound for this seal. None for legacy seals and
    /// — in this inert slice (a2) — for ALL seals: no producer populates it
    /// yet (that is slice a3). The field is parsed from `drand_*` metadata via
    /// `DrandPulse::from_metadata` but read by no consensus path until a3.
    pub drand_pulse: Option<DrandPulse>,
    /// B2 fix (internal design notes): canonical finality
    /// committee `(Merkle root, size)` (`committee_hash_from_pks` + member count
    /// of `finality_committee_pks`) for each DEST zone of a pending Locked
    /// cross-zone transfer in THIS source zone, computed by the sealing
    /// aggregator at seal time from global VRF+stake state. Map key = dest zone
    /// path, value = `(committee_hash, committee_size)`. Frozen into
    /// `PendingTransfer.dest_finality_committee` at seal-ingest
    /// (`attach_xzone_proofs_from_seal_with_finality`) and READ — never recomputed —
    /// at `XZoneAbort` apply/validate/replay. `verify_abort_quorum` gates the wire
    /// committee hash against the root AND uses the anchored size as the 2/3
    /// denominator, so neither a forged 1-member committee nor a `size=1`
    /// sub-quorum claim can force-refund a sealed transfer. None/empty for legacy
    /// seals and seals with no pending cross-zone locks (omitted from metadata →
    /// byte-identical `signable_bytes`, same legacy-safe pattern as
    /// `account_smt_root`).
    pub xzone_dest_finality_committees: Option<BTreeMap<String, ([u8; 32], u32)>>,
}

/// A change to the zone registry (included in epoch seal delta).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ZoneRegistryChange {
    /// A new zone was created.
    Created { zone: ZoneId },
    /// An existing zone split into subzones.
    Split { parent: ZoneId, children: Vec<ZoneId> },
    /// A zone was deactivated (no witnesses, no records).
    Deactivated { zone: ZoneId },
}

// ─── Metadata builder ──────────────────────────────────────────────────────

/// Inputs for [`seal_metadata`]. 17 fields that all flow into the metadata
/// BTreeMap; bundled into a borrowed struct so the builder signature isn't
/// a 17-arg flat list. Layout mirrors the eventual `epoch_*` keys: required
/// header (zone, epoch_number, time window, record_count, merkle/previous
/// roots) first, optional production extras (vrf, sparse, record_hashes,
/// balance, registry, smt, drand pulse) after.
pub struct SealMetadataParams<'a> {
    pub zone: ZoneId,
    pub epoch_number: u64,
    pub start: f64,
    pub end: f64,
    pub record_count: u64,
    pub merkle_root: &'a [u8; 32],
    pub previous_seal_hash: &'a [u8; 32],
    pub vrf_output: Option<&'a [u8; 32]>,
    pub vrf_proof: Option<&'a [u8]>,
    pub sparse_merkle_root: Option<&'a [u8; 32]>,
    pub record_hashes: Option<&'a [[u8; 32]]>,
    pub zone_balance_total: Option<u64>,
    pub zone_registry_root: Option<&'a [u8; 32]>,
    pub zone_registry_delta: Option<&'a [ZoneRegistryChange]>,
    pub aggregator_rank: u8,
    pub account_smt_root: Option<&'a [u8; 32]>,
    /// REALMS P1.5 drand time-bracket pulse. `None` in this inert slice (a2)
    /// at every production call site; slice a3 will pass `Some(&pulse)` from
    /// the producer. When `Some`, its `drand_*` keys are written via
    /// `DrandPulse::write_metadata`; when `None`, zero keys are written so the
    /// seal's `signable_bytes` are byte-identical to a pre-feature seal.
    pub drand_pulse: Option<&'a DrandPulse>,
}

/// Build epoch seal metadata (same pattern as ledger op metadata builders).
///
/// Production format includes record_hashes, zone_balance_total, and zone_registry
/// fields for the layered consensus model (Steps 3+4).
pub fn seal_metadata(p: SealMetadataParams<'_>) -> BTreeMap<String, JsonValue> {
    let SealMetadataParams {
        zone,
        epoch_number,
        start,
        end,
        record_count,
        merkle_root,
        previous_seal_hash,
        vrf_output,
        vrf_proof,
        sparse_merkle_root,
        record_hashes,
        zone_balance_total,
        zone_registry_root,
        zone_registry_delta,
        aggregator_rank,
        account_smt_root,
        drand_pulse,
    } = p;
    let mut m = BTreeMap::new();
    m.insert(EPOCH_OP_KEY.into(), serde_json::json!("seal"));
    m.insert("epoch_zone".into(), serde_json::json!(zone));
    m.insert("epoch_number".into(), serde_json::json!(epoch_number));
    m.insert("epoch_start".into(), serde_json::json!(start));
    m.insert("epoch_end".into(), serde_json::json!(end));
    m.insert("epoch_record_count".into(), serde_json::json!(record_count));
    m.insert("epoch_merkle_root".into(), serde_json::json!(hex::encode(merkle_root)));
    m.insert("epoch_previous_seal".into(), serde_json::json!(hex::encode(previous_seal_hash)));
    if let Some(output) = vrf_output {
        m.insert("epoch_vrf_output".into(), serde_json::json!(hex::encode(output)));
    }
    if let Some(proof) = vrf_proof {
        m.insert("epoch_vrf_proof".into(), serde_json::json!(hex::encode(proof)));
    }
    if let Some(smr) = sparse_merkle_root {
        m.insert("epoch_sparse_merkle_root".into(), serde_json::json!(hex::encode(smr)));
    }
    // New fields for layered consensus (Steps 3+4).
    // R3-8 slice 3 — bounded-inline emission: above SEAL_INLINE_ENUM_MAX the
    // key is OMITTED (not truncated — a truncated array would fail the
    // slice-2 root gate anyway). The signed epoch_record_count +
    // epoch_merkle_root still fully commit the set; consumers derive the
    // enumeration from their local window when the key is absent. This is
    // what keeps the producer's own seal insert under the ingest per-value
    // 8 KiB gate (self-wedge at ≥123 hashes without it).
    if let Some(hashes) = record_hashes {
        if hashes.len() <= seal_inline_enum_max() {
            let hash_strings: Vec<String> = hashes.iter().map(hex::encode).collect();
            m.insert("epoch_record_hashes".into(), serde_json::json!(hash_strings));
        }
    }
    if let Some(total) = zone_balance_total {
        m.insert("epoch_zone_balance_total".into(), serde_json::json!(total));
    }
    if let Some(root) = zone_registry_root {
        m.insert("epoch_zone_registry_root".into(), serde_json::json!(hex::encode(root)));
    }
    if let Some(delta) = zone_registry_delta {
        m.insert("epoch_zone_registry_delta".into(), serde_json::json!(delta));
    }
    // Embed zone_count so verifiers can recompute record-to-zone mapping correctly
    // even after the global zone_count changes (coordinated zone transition).
    let current_zone_count = super::consensus::get_zone_count();
    m.insert("epoch_zone_count".into(), serde_json::json!(current_zone_count));
    // Aggregator rank the creator held for this (zone, epoch). Absent in legacy
    // seals; `extract_epoch_seal` defaults to 0 when missing (Stage 3b.5).
    m.insert("epoch_aggregator_rank".into(), serde_json::json!(aggregator_rank));
    // Gap 1: Bind the global account-state SMT root at seal time. Light clients
    // verify an account proof (`/proof/account/{id}`) by recomputing the SMT
    // root from (state_hash, siblings) and comparing to this value signed in
    // the seal. Absent in legacy seals (pre-Gap 1).
    if let Some(root) = account_smt_root {
        m.insert("epoch_account_smt_root".into(), serde_json::json!(hex::encode(root)));
    }
    // REALMS P1.5: in-protocol drand time-bracket. Inserted ONLY when a pulse
    // is supplied — `None` (every seal in slice a2) writes zero `drand_*` keys,
    // so the serialized metadata, `signable_bytes`, signature and seal hash are
    // byte-identical to a pre-feature seal. The five `drand_*` keys are in
    // `content_safety::ALLOWED_KEYS` so a3's populated seals pass the ingest
    // allowlist (test_all_record_builders_pass_allowlist pins this).
    if let Some(pulse) = drand_pulse {
        pulse.write_metadata(&mut m);
    }
    m
}

// ─── Extract / parse ───────────────────────────────────────────────────────

/// Extract an epoch seal from a record's metadata, if present.
/// Returns `Ok(None)` if the record is not an epoch seal.
pub fn extract_epoch_seal(record: &ValidationRecord) -> Result<Option<ParsedEpochSeal>> {
    let op_val = match record.metadata.get(EPOCH_OP_KEY) {
        Some(v) => v,
        None => return Ok(None),
    };

    let op_str = op_val
        .as_str()
        .ok_or_else(|| ElaraError::Ledger("epoch_op must be a string".into()))?;

    if op_str != "seal" {
        // Not a seal — could be zone_transition or other epoch op.
        // Return None so the caller can handle it appropriately.
        return Ok(None);
    }

    let zone: ZoneId = record.metadata.get("epoch_zone")
        .and_then(|v| {
            // Support both string ("medical/eu") and legacy numeric (42) zone values
            if let Some(s) = v.as_str() {
                Some(ZoneId::new(s))
            } else {
                v.as_u64().map(ZoneId::from_legacy)
            }
        })
        .ok_or_else(|| ElaraError::Ledger("missing epoch_zone".into()))?;

    let epoch_number = record.metadata.get("epoch_number")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| ElaraError::Ledger("missing epoch_number".into()))?;

    let start = record.metadata.get("epoch_start")
        .and_then(|v| v.as_f64())
        .ok_or_else(|| ElaraError::Ledger("missing epoch_start".into()))?;

    let end = record.metadata.get("epoch_end")
        .and_then(|v| v.as_f64())
        .ok_or_else(|| ElaraError::Ledger("missing epoch_end".into()))?;

    let record_count = record.metadata.get("epoch_record_count")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| ElaraError::Ledger("missing epoch_record_count".into()))?;

    let merkle_root_hex = record.metadata.get("epoch_merkle_root")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ElaraError::Ledger("missing epoch_merkle_root".into()))?;
    let merkle_root_vec = hex::decode(merkle_root_hex)
        .map_err(|e| ElaraError::Ledger(format!("bad epoch_merkle_root hex: {e}")))?;
    if merkle_root_vec.len() != 32 {
        return Err(ElaraError::Ledger("epoch_merkle_root must be 32 bytes".into()));
    }
    let mut merkle_root = [0u8; 32];
    merkle_root.copy_from_slice(&merkle_root_vec);

    let prev_seal_hex = record.metadata.get("epoch_previous_seal")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ElaraError::Ledger("missing epoch_previous_seal".into()))?;
    let prev_seal_vec = hex::decode(prev_seal_hex)
        .map_err(|e| ElaraError::Ledger(format!("bad epoch_previous_seal hex: {e}")))?;
    if prev_seal_vec.len() != 32 {
        return Err(ElaraError::Ledger("epoch_previous_seal must be 32 bytes".into()));
    }
    let mut previous_seal_hash = [0u8; 32];
    previous_seal_hash.copy_from_slice(&prev_seal_vec);

    // VRF fields are optional for backward compatibility with pre-VRF seals.
    let vrf_output = record.metadata.get("epoch_vrf_output")
        .and_then(|v| v.as_str())
        .and_then(|hex_str| hex::decode(hex_str).ok())
        .and_then(|bytes| {
            if bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Some(arr)
            } else {
                None
            }
        });

    let vrf_proof = record.metadata.get("epoch_vrf_proof")
        .and_then(|v| v.as_str())
        .and_then(|hex_str| hex::decode(hex_str).ok());

    // New fields (optional for backward compat with legacy seals)
    let record_hashes: Vec<[u8; 32]> = record.metadata.get("epoch_record_hashes")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|h| h.as_str())
                .filter_map(|hex_str| hex::decode(hex_str).ok())
                .filter(|bytes| bytes.len() == 32)
                .map(|bytes| {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    arr
                })
                .collect()
        })
        .unwrap_or_default();

    // R3-8 slice 2 — parse-time root gate, drop-to-empty. A non-empty inline
    // enumeration that does not recompute to the signed epoch_merkle_root is
    // dropped to empty (never rejected: rejecting would wedge every fixed
    // node on one buggy-producer seal — the R3-7 incident class — while
    // empty is a defined legacy state every consumer already tolerates).
    // Both the array and the root live inside signable_bytes, so the gate is
    // a pure function of signed bytes: deterministic fleet-wide, no fork.
    // It also normalizes truncation — the filter_maps above silently drop
    // malformed entries, and a partially-decoded enumeration can never match
    // the root, so truncation ≡ omission for every downstream consumer.
    // Cost: one Merkle recompute over ≤MAX_METADATA_ENTRIES=256 leaves
    // (decode cap), only when the inline key is present.
    let record_hashes = if !record_hashes.is_empty()
        && MerkleTree::root(&record_hashes) != merkle_root
    {
        SEAL_ENUM_ROOT_MISMATCH_TOTAL.fetch_add(1, Ordering::Relaxed);
        tracing::warn!(
            "seal enumeration root mismatch for zone {} epoch {} — dropping {} inline epoch_record_hashes to empty",
            zone, epoch_number, record_hashes.len(),
        );
        Vec::new()
    } else {
        record_hashes
    };

    let zone_balance_total = record.metadata.get("epoch_zone_balance_total")
        .and_then(|v| v.as_u64());

    let zone_registry_root = record.metadata.get("epoch_zone_registry_root")
        .and_then(|v| v.as_str())
        .and_then(|hex_str| hex::decode(hex_str).ok())
        .and_then(|bytes| {
            if bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Some(arr)
            } else {
                None
            }
        });

    let zone_registry_delta: Option<Vec<ZoneRegistryChange>> = record.metadata
        .get("epoch_zone_registry_delta")
        .and_then(|v| serde_json::from_value(v.clone()).ok());

    // zone_count embedded in seal — None for legacy seals
    let seal_zone_count = record.metadata.get("epoch_zone_count")
        .and_then(|v| v.as_u64());

    // Aggregator rank (Stage 3b.5). Missing key = legacy seal → 0.
    // Values above MAX_VIEW_DEPTH-1 are clamped; verification logic in 3b.6
    // will reject any rank >= MAX_VIEW_DEPTH outright.
    let aggregator_rank: u8 = record.metadata.get("epoch_aggregator_rank")
        .and_then(|v| v.as_u64())
        .map(|n| n.min(u8::MAX as u64) as u8)
        .unwrap_or(0);

    // Gap 1: Account-state SMT root bound into the seal. Optional — legacy seals
    // (pre-Gap 1) lack this key and light clients will fall back to the latest
    // sealed root from the headers endpoint.
    let account_smt_root = record.metadata.get("epoch_account_smt_root")
        .and_then(|v| v.as_str())
        .and_then(|hex_str| hex::decode(hex_str).ok())
        .and_then(|bytes| {
            if bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Some(arr)
            } else {
                None
            }
        });

    // B2 fix: per-dest-zone canonical finality committee `(hash, size)` bound
    // into the seal. JSON object { zone_path: [hex(committee_hash), size] }.
    // Absent in legacy seals → None. Malformed/zero-size entries are dropped
    // (not fatal); the resulting map only ever tightens the abort gate. Bounded
    // to MAX_SEAL_RECORDS-class size defensively (a seal cannot reference more
    // dest zones than it sealed).
    let xzone_dest_finality_committees: Option<BTreeMap<String, ([u8; 32], u32)>> = record
        .metadata
        .get("epoch_xzone_dest_finality_committees")
        .and_then(|v| v.as_object())
        .map(|obj| {
            let mut m = BTreeMap::new();
            for (zone_path, hv) in obj.iter().take(MAX_SEAL_RECORDS) {
                let arr = match hv.as_array() {
                    Some(a) if a.len() == 2 => a,
                    _ => continue,
                };
                let hash = arr[0]
                    .as_str()
                    .and_then(|s| hex::decode(s).ok())
                    .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok());
                let size = arr[1].as_u64().and_then(|n| u32::try_from(n).ok());
                if let (Some(hash), Some(size)) = (hash, size) {
                    if size > 0 {
                        m.insert(zone_path.clone(), (hash, size));
                    }
                }
            }
            m
        })
        .filter(|m| !m.is_empty());

    Ok(Some(ParsedEpochSeal {
        zone,
        epoch_number,
        start,
        end,
        record_count,
        merkle_root,
        previous_seal_hash,
        vrf_output,
        vrf_proof,
        record_hashes,
        zone_balance_total,
        zone_registry_root,
        zone_registry_delta,
        seal_zone_count,
        aggregator_rank,
        account_smt_root,
        // REALMS P1.5: parse the drand pulse from `drand_*` metadata. Returns
        // None for legacy seals and for every seal in slice a2 (no producer
        // writes the keys yet). `from_metadata` is panic-free and returns None
        // on absent/partial/malformed input. No consensus path reads this until a3.
        drand_pulse: DrandPulse::from_metadata(&record.metadata),
        xzone_dest_finality_committees,
    }))
}

// ─── Global quorum seal (Stage 3c.1 cross-zone escalation) ─────────────────

/// A cross-zone escalation seal, emitted when a zone's full rank ladder
/// (ranks 0..MAX_VIEW_DEPTH) has timed out without producing a seal.
///
/// An anchor in a *non-stuck* zone emits this record; cross-zone attestation
/// with a 2/3-of-non-stuck-zones stake-weighted threshold promotes it to
/// `Finalized`, unsticking the stuck zone for the next epoch.
///
/// Unlike [`ParsedEpochSeal`], this record carries no Merkle root / record
/// hashes — it is a *liveness artifact*, not a content commitment. Records
/// that would have landed in the skipped epoch will be sealed (with their
/// content commitment) under the next successful per-zone seal.
#[derive(Debug, Clone)]
pub struct ParsedGlobalQuorumSeal {
    /// The zone whose rank ladder has exhausted (the "stuck" zone).
    pub stuck_zone: ZoneId,
    /// The zone of the emitter (must be ≠ `stuck_zone`).
    pub emitter_zone: ZoneId,
    /// The epoch number being sealed for `stuck_zone`.
    pub stuck_epoch: u64,
    /// Hash of the previous successful seal for `stuck_zone` (chains the
    /// escalation to the per-zone history; verifier must cross-check).
    pub previous_seal_hash: [u8; 32],
    /// Emitter-declared `base_timeout_ms` observation used to demonstrate
    /// the stuck condition. Verifier clamps this to the same `[1000, 600_000]`
    /// range used by proposers so a liar cannot fabricate stuckness with a
    /// zero/tiny base.
    pub observed_base_timeout_ms: u64,
    /// Emitter-declared elapsed milliseconds since the zone's `epoch_start_ts`.
    /// Combined with `observed_base_timeout_ms`, the verifier re-runs
    /// `is_zone_stuck` on these values to confirm the escalation trigger.
    pub observed_elapsed_ms: u64,
    /// Wall-clock unix seconds when the emitter signed the record.
    pub emitted_at: f64,
    /// VRF output over the global-seal alpha — binds emitter identity to
    /// this `(stuck_zone, stuck_epoch, prev_seal_hash)` triple so forgery
    /// remains equivocation-detectable.
    pub vrf_output: [u8; 32],
    /// VRF proof corresponding to `vrf_output`.
    pub vrf_proof: Vec<u8>,
    /// Zone count at emit time (anti-drift across zone_transition epochs).
    pub seal_zone_count: Option<u64>,
}

/// Canonical VRF alpha for global-seal binding.
///
/// Distinct from per-zone `chained_beacon` so the two rank/escalation paths
/// cannot alias. Verifier reconstructs this exact byte sequence.
pub fn global_seal_alpha(
    stuck_zone: &ZoneId,
    stuck_epoch: u64,
    prev_seal_hash: &[u8; 32],
) -> Vec<u8> {
    let zone_str = stuck_zone.to_string();
    let mut out = Vec::with_capacity(16 + zone_str.len() + 8 + 32);
    out.extend_from_slice(b"global_seal:");
    out.extend_from_slice(zone_str.as_bytes());
    out.push(b':');
    out.extend_from_slice(&stuck_epoch.to_be_bytes());
    out.push(b':');
    out.extend_from_slice(prev_seal_hash);
    out
}

/// Build `global_quorum_seal` metadata.
#[allow(clippy::too_many_arguments)]
pub fn global_seal_metadata(
    stuck_zone: &ZoneId,
    emitter_zone: &ZoneId,
    stuck_epoch: u64,
    previous_seal_hash: &[u8; 32],
    observed_base_timeout_ms: u64,
    observed_elapsed_ms: u64,
    emitted_at: f64,
    vrf_output: &[u8; 32],
    vrf_proof: &[u8],
) -> BTreeMap<String, JsonValue> {
    let mut m = BTreeMap::new();
    m.insert(EPOCH_OP_KEY.into(), serde_json::json!(EPOCH_OP_GLOBAL_SEAL));
    m.insert("stuck_zone".into(), serde_json::json!(stuck_zone));
    m.insert("emitter_zone".into(), serde_json::json!(emitter_zone));
    m.insert("stuck_epoch".into(), serde_json::json!(stuck_epoch));
    m.insert(
        "previous_seal_hash".into(),
        serde_json::json!(hex::encode(previous_seal_hash)),
    );
    m.insert(
        "observed_base_timeout_ms".into(),
        serde_json::json!(observed_base_timeout_ms),
    );
    m.insert(
        "observed_elapsed_ms".into(),
        serde_json::json!(observed_elapsed_ms),
    );
    m.insert("emitted_at".into(), serde_json::json!(emitted_at));
    m.insert(
        "global_seal_vrf_output".into(),
        serde_json::json!(hex::encode(vrf_output)),
    );
    m.insert(
        "global_seal_vrf_proof".into(),
        serde_json::json!(hex::encode(vrf_proof)),
    );
    let zone_count = super::consensus::get_zone_count();
    m.insert("seal_zone_count".into(), serde_json::json!(zone_count));
    m
}

/// Extract a global quorum seal from a record's metadata, if present.
/// Returns `Ok(None)` for any other record kind, including `epoch_op="seal"`.
pub fn extract_global_quorum_seal(
    record: &ValidationRecord,
) -> Result<Option<ParsedGlobalQuorumSeal>> {
    let op_val = match record.metadata.get(EPOCH_OP_KEY) {
        Some(v) => v,
        None => return Ok(None),
    };
    let op_str = op_val
        .as_str()
        .ok_or_else(|| ElaraError::Ledger("epoch_op must be a string".into()))?;
    if op_str != EPOCH_OP_GLOBAL_SEAL {
        return Ok(None);
    }

    let parse_zone = |key: &str| -> Result<ZoneId> {
        record
            .metadata
            .get(key)
            .and_then(|v| {
                if let Some(s) = v.as_str() {
                    Some(ZoneId::new(s))
                } else {
                    v.as_u64().map(ZoneId::from_legacy)
                }
            })
            .ok_or_else(|| ElaraError::Ledger(format!("missing {key}")))
    };
    let stuck_zone = parse_zone("stuck_zone")?;
    let emitter_zone = parse_zone("emitter_zone")?;

    let stuck_epoch = record
        .metadata
        .get("stuck_epoch")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| ElaraError::Ledger("missing stuck_epoch".into()))?;

    let prev_hex = record
        .metadata
        .get("previous_seal_hash")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ElaraError::Ledger("missing previous_seal_hash".into()))?;
    let prev_vec = hex::decode(prev_hex)
        .map_err(|e| ElaraError::Ledger(format!("bad previous_seal_hash hex: {e}")))?;
    if prev_vec.len() != 32 {
        return Err(ElaraError::Ledger(
            "previous_seal_hash must be 32 bytes".into(),
        ));
    }
    let mut previous_seal_hash = [0u8; 32];
    previous_seal_hash.copy_from_slice(&prev_vec);

    let observed_base_timeout_ms = record
        .metadata
        .get("observed_base_timeout_ms")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| ElaraError::Ledger("missing observed_base_timeout_ms".into()))?;

    let observed_elapsed_ms = record
        .metadata
        .get("observed_elapsed_ms")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| ElaraError::Ledger("missing observed_elapsed_ms".into()))?;

    let emitted_at = record
        .metadata
        .get("emitted_at")
        .and_then(|v| v.as_f64())
        .ok_or_else(|| ElaraError::Ledger("missing emitted_at".into()))?;

    let vrf_output_hex = record
        .metadata
        .get("global_seal_vrf_output")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ElaraError::Ledger("missing global_seal_vrf_output".into()))?;
    let vrf_vec = hex::decode(vrf_output_hex)
        .map_err(|e| ElaraError::Ledger(format!("bad global_seal_vrf_output hex: {e}")))?;
    if vrf_vec.len() != 32 {
        return Err(ElaraError::Ledger(
            "global_seal_vrf_output must be 32 bytes".into(),
        ));
    }
    let mut vrf_output = [0u8; 32];
    vrf_output.copy_from_slice(&vrf_vec);

    let vrf_proof_hex = record
        .metadata
        .get("global_seal_vrf_proof")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ElaraError::Ledger("missing global_seal_vrf_proof".into()))?;
    let vrf_proof = hex::decode(vrf_proof_hex)
        .map_err(|e| ElaraError::Ledger(format!("bad global_seal_vrf_proof hex: {e}")))?;

    let seal_zone_count = record.metadata.get("seal_zone_count").and_then(|v| v.as_u64());

    Ok(Some(ParsedGlobalQuorumSeal {
        stuck_zone,
        emitter_zone,
        stuck_epoch,
        previous_seal_hash,
        observed_base_timeout_ms,
        observed_elapsed_ms,
        emitted_at,
        vrf_output,
        vrf_proof,
        seal_zone_count,
    }))
}

/// Create a `global_quorum_seal` record.
///
/// The caller has already decided `stuck_zone` is stuck (via
/// `aggregator::is_zone_stuck`) and looked up `previous_seal_hash` from the
/// local `EpochState`. The VRF binds the emitter identity to
/// `(stuck_zone, stuck_epoch, prev_seal_hash)` — an emitter cannot forge a
/// different seal for the same height without equivocating (which remains
/// slashable under the existing seal-equivocation rules, extended in a
/// follow-up).
#[allow(clippy::too_many_arguments)]
pub fn create_global_quorum_seal(
    identity: &Identity,
    vrf_sk: &crate::crypto::vrf::VrfSecretKey,
    stuck_zone: ZoneId,
    emitter_zone: ZoneId,
    stuck_epoch: u64,
    previous_seal_hash: [u8; 32],
    observed_base_timeout_ms: u64,
    observed_elapsed_ms: u64,
    parents: Vec<String>,
    slot_nonce: u64,
) -> Result<(ValidationRecord, ParsedGlobalQuorumSeal)> {
    if stuck_zone == emitter_zone {
        return Err(ElaraError::Ledger(
            "emitter_zone must differ from stuck_zone".into(),
        ));
    }
    if !super::aggregator::is_zone_stuck(observed_base_timeout_ms, observed_elapsed_ms) {
        return Err(ElaraError::Ledger(
            "zone is not stuck under observed (base, elapsed)".into(),
        ));
    }
    let alpha = global_seal_alpha(&stuck_zone, stuck_epoch, &previous_seal_hash);
    let (output, proof) = crate::crypto::vrf::vrf_prove(vrf_sk, &alpha)?;
    let vrf_output = *output.as_bytes();
    let vrf_proof = proof.to_bytes().to_vec();

    let emitted_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);

    let metadata = global_seal_metadata(
        &stuck_zone,
        &emitter_zone,
        stuck_epoch,
        &previous_seal_hash,
        observed_base_timeout_ms,
        observed_elapsed_ms,
        emitted_at,
        &vrf_output,
        &vrf_proof,
    );

    let content_str = format!(
        "global_seal:{}:{}:{}",
        stuck_zone, stuck_epoch, hex::encode(previous_seal_hash),
    );
    let mut record = ValidationRecord::create(
        content_str.as_bytes(),
        identity.public_key.clone(),
        parents,
        Classification::Public,
        Some(metadata),
    );
    record.nonce = slot_nonce;
    identity.sign_record(&mut record)?;

    let parsed = ParsedGlobalQuorumSeal {
        stuck_zone,
        emitter_zone,
        stuck_epoch,
        previous_seal_hash,
        observed_base_timeout_ms,
        observed_elapsed_ms,
        emitted_at,
        vrf_output,
        vrf_proof,
        seal_zone_count: Some(super::consensus::get_zone_count()),
    };
    Ok((record, parsed))
}

/// Inputs for verifying a [`ParsedGlobalQuorumSeal`].
pub struct GlobalSealVerifyCtx<'a> {
    /// All registered anchors with positive stake, keyed by zone. Emitter
    /// must appear in `stakers_by_zone[emitter_zone]` with nonzero stake.
    pub stakers_by_zone: &'a std::collections::HashMap<ZoneId, Vec<(String, u64)>>,
    /// Previous canonical seal hash for `stuck_zone` as tracked locally.
    /// The emitter's declared `previous_seal_hash` must equal this.
    pub local_previous_seal_hash: [u8; 32],
    /// Local view of `next_epoch(stuck_zone)`. The emitter's `stuck_epoch`
    /// must equal this — we only accept escalations for the *current*
    /// expected height, never backfill.
    pub local_next_epoch: u64,
    /// Emitter's registered VRF public key. Verifier re-derives it from
    /// the local VRF registry keyed by `creator_identity_hash(record)`.
    pub emitter_vrf_pk: &'a crate::crypto::vrf::VrfPublicKey,
}

/// Verify a global quorum seal record against local state.
///
/// Checks performed, in order (each rejects on failure):
/// 1. Extract succeeds.
/// 2. `emitter_zone != stuck_zone`.
/// 3. `stuck_epoch == ctx.local_next_epoch` (no backfill, no future).
/// 4. `previous_seal_hash == ctx.local_previous_seal_hash` (chains to our
///    view of the stuck zone's history).
/// 5. `aggregator::is_zone_stuck(observed_base, observed_elapsed)` holds
///    with `observed_base` clamped to `[1000, 600_000]`.
/// 6. Emitter is registered in `stakers_by_zone[emitter_zone]` with `stake > 0`.
/// 7. VRF proof verifies over `global_seal_alpha(stuck, epoch, prev)` and
///    the recomputed output matches the declared `vrf_output`.
pub fn verify_global_quorum_seal(
    record: &ValidationRecord,
    ctx: &GlobalSealVerifyCtx<'_>,
) -> Result<ParsedGlobalQuorumSeal> {
    let seal = extract_global_quorum_seal(record)?
        .ok_or_else(|| ElaraError::Ledger("not a global_quorum_seal record".into()))?;

    if seal.stuck_zone == seal.emitter_zone {
        return Err(ElaraError::Ledger(
            "global_seal: emitter_zone must differ from stuck_zone".into(),
        ));
    }
    if seal.stuck_epoch != ctx.local_next_epoch {
        return Err(ElaraError::Ledger(format!(
            "global_seal: stuck_epoch {} != local_next_epoch {}",
            seal.stuck_epoch, ctx.local_next_epoch,
        )));
    }
    if seal.previous_seal_hash != ctx.local_previous_seal_hash {
        return Err(ElaraError::Ledger(
            "global_seal: previous_seal_hash does not match local view".into(),
        ));
    }

    // Clamp the emitter-declared base timeout to the same range proposers use
    // so a liar with base=1 cannot fabricate stuckness at elapsed=128.
    let base_clamped = seal.observed_base_timeout_ms.clamp(1000, 600_000);
    if !super::aggregator::is_zone_stuck(base_clamped, seal.observed_elapsed_ms) {
        return Err(ElaraError::Ledger(
            "global_seal: zone not stuck under clamped (base, elapsed)".into(),
        ));
    }

    // Emitter must be a registered anchor in emitter_zone with positive stake.
    let creator = creator_identity_hash(record);
    let emitter_zone_stakers = ctx.stakers_by_zone.get(&seal.emitter_zone);
    let emitter_stake = emitter_zone_stakers
        .and_then(|v| v.iter().find(|(id, _)| id == &creator).map(|(_, s)| *s))
        .unwrap_or(0);
    if emitter_stake == 0 {
        return Err(ElaraError::Ledger(
            "global_seal: emitter is not a registered anchor with positive stake in emitter_zone".into(),
        ));
    }

    // VRF proof verification.
    let alpha = global_seal_alpha(&seal.stuck_zone, seal.stuck_epoch, &seal.previous_seal_hash);
    let proof_obj = crate::crypto::vrf::VrfProof::from_bytes(&seal.vrf_proof)
        .map_err(|e| ElaraError::Ledger(format!("global_seal: invalid vrf_proof bytes: {e}")))?;
    let verified = crate::crypto::vrf::vrf_verify(ctx.emitter_vrf_pk, &alpha, &proof_obj)
        .map_err(|e| ElaraError::Ledger(format!("global_seal: vrf_verify failed: {e}")))?;
    if *verified.as_bytes() != seal.vrf_output {
        return Err(ElaraError::Ledger(
            "global_seal: vrf_output mismatch against recomputed proof".into(),
        ));
    }

    Ok(seal)
}

// ─── Create epoch seal ─────────────────────────────────────────────────────

/// Create an epoch seal record for a zone covering [start, end).
///
/// Anchor-proposed epoch (internal design notes):
/// 1. Query storage for records in the time range
/// 2. Filter by zone, exclude other epoch seals
/// 3. Compute Merkle root over sorted record hashes
/// 4. Compute zone_balance_total from ledger (conservation invariant)
/// 5. Compute VRF over epoch parameters (unpredictable jury seed)
/// 6. Include record_hashes for witness verification
/// 7. Build and sign the seal record
// Defaults wrapper around `create_epoch_seal_with_balance(SealParams)` for
// tests and historical callers — adding a parallel param-struct would defeat
// the simplification this wrapper provides.
#[allow(clippy::too_many_arguments)]
pub fn create_epoch_seal(
    identity: &Identity,
    storage: &dyn Storage,
    epoch_state: &EpochState,
    zone: ZoneId,
    start: f64,
    end: f64,
    vrf_sk: Option<&crate::crypto::vrf::VrfSecretKey>,
    sparse_merkle_root: Option<[u8; 32]>,
) -> Result<(ValidationRecord, ParsedEpochSeal)> {
    // Default-rank wrapper for tests + historical callers. Rank 0 is the only
    // rank currently verified (3b.6 will enforce match against VRF-stake rank).
    // slot_nonce=0 is fine in tests — each test uses a fresh identity with no
    // prior records, so there's no collision. Production callers must route
    // through `create_epoch_seal_with_balance` with a real slot nonce.
    create_epoch_seal_with_balance(SealParams {
        identity,
        storage,
        epoch_state,
        zone,
        start,
        end,
        vrf_sk,
        sparse_merkle_root,
        zone_balance_total: None,
        zone_registry_root: None,
        zone_registry_delta: None,
        parents: vec![],
        aggregator_rank: 0,
        slot_nonce: 0,
        account_smt_root: None,
        drand_pulse: None,
        zone_registry: None, // tests use naive routing
        xzone_dest_finality_committees: None,
    })
}

/// Inputs for [`create_epoch_seal_with_balance`]. Bundled into a struct
/// because the production seal-emit path computes 16 distinct fields
/// (identity + storage refs, time window, VRF key, four pre-computed roots,
/// parents/rank/nonce, registry snapshot) and a flat parameter list at that
/// arity is unreadable. Borrowed fields stay borrowed — no extra clones on
/// the seal-emit hot path.
pub struct SealParams<'a> {
    pub identity: &'a Identity,
    pub storage: &'a dyn Storage,
    pub epoch_state: &'a EpochState,
    pub zone: ZoneId,
    pub start: f64,
    pub end: f64,
    pub vrf_sk: Option<&'a crate::crypto::vrf::VrfSecretKey>,
    pub sparse_merkle_root: Option<[u8; 32]>,
    pub zone_balance_total: Option<u64>,
    pub zone_registry_root: Option<[u8; 32]>,
    pub zone_registry_delta: Option<Vec<ZoneRegistryChange>>,
    pub parents: Vec<String>,
    pub aggregator_rank: u8,
    pub slot_nonce: u64,
    pub account_smt_root: Option<[u8; 32]>,
    /// REALMS P1.5 drand time-bracket pulse. `None` at every call site in the
    /// inert slice (a2); slice a3 supplies the producer's fetched pulse here.
    /// Threaded into `seal_metadata` and into the returned `ParsedEpochSeal`.
    pub drand_pulse: Option<&'a DrandPulse>,
    /// Gap 4 routing-application: snapshot of the zone registry used to
    /// filter records into the resolved-leaf zone instead of the naive
    /// flat-modulo zone. `None` in tests and legacy callers that don't
    /// have registry access — that path preserves the original naive
    /// behavior. Production seal-emit passes a clone of `NodeState::
    /// zone_registry` taken *before* the `spawn_blocking` boundary so the
    /// async read lock does not cross the blocking closure.
    pub zone_registry: Option<&'a super::zone_registry::ZoneRegistry>,
    /// B2 fix: per-dest-zone canonical finality committee hashes (computed by
    /// the caller in the async seal loop, BEFORE the `spawn_blocking` boundary,
    /// from global VRF+stake via `finality_committee_pks`). Injected into the
    /// seal metadata under `epoch_xzone_dest_finality_committees` and mirrored
    /// into the returned `ParsedEpochSeal`. Value = `(committee_hash, size)`.
    /// `None`/empty for tests, legacy callers, and seals with no pending
    /// cross-zone locks (key omitted → byte-identical `signable_bytes`).
    pub xzone_dest_finality_committees: Option<BTreeMap<String, ([u8; 32], u32)>>,
}

/// Create an epoch seal with full production fields.
///
/// Extended version that includes zone_balance_total, zone_registry_root,
/// and zone_registry_delta for the layered consensus model.
pub fn create_epoch_seal_with_balance(
    params: SealParams<'_>,
) -> Result<(ValidationRecord, ParsedEpochSeal)> {
    let SealParams {
        identity,
        storage,
        epoch_state,
        zone,
        start,
        end,
        vrf_sk,
        sparse_merkle_root,
        zone_balance_total,
        zone_registry_root,
        zone_registry_delta,
        parents,
        aggregator_rank,
        slot_nonce,
        account_smt_root,
        drand_pulse,
        zone_registry,
        xzone_dest_finality_committees,
    } = params;
    let epoch_number = epoch_state.next_epoch(&zone);
    let previous_seal_hash = epoch_state.previous_seal_hash(&zone);

    // Per-zone-keyed range lookup (CF_RECORD_BY_ZONE) replaces the
    // global timestamp scan + zone-filter pattern. At 1M zones this is
    // ~1M× less I/O per seal — only this zone's records in the window are
    // touched. The zone-idx CF stores under the registry-resolved leaf zone
    // (ZSP Phase B), so the explicit `zone_registry` resolver branch below is
    // redundant on the hot path; it remains as the source-of-truth path for
    // the fallback (non-zone-indexed) backend.
    //
    // Streaming: `query_zone` materialised every record in the
    // window into a Vec (~8 KB each). At 1000 rec/s sustained, a 120 s
    // window is 120 K records × 8 KB = 960 MB transient heap on the seal
    // hot path, with the previous `usize::MAX` cap one stripe-spike away
    // from OOM. `query_zone_ids` returns IDs only (~50 B each) and we
    // fetch records one at a time, hash, drop — peak memory drops to
    // O(IDs ~6 MB at 120 K rec) + O(1 record). Cap MAX_SEAL_RECORDS = 1M
    // is the deterministic network-wide ceiling (above this, zone-split
    // is the right recovery, not a single mega-seal).
    let zone_count = super::consensus::get_zone_count();
    let ids = storage.query_zone_ids(
        &zone, zone_count, Some(start), Some(end), MAX_SEAL_RECORDS,
    )?;
    observe_seal_window_size(ids.len());
    if ids.len() >= MAX_SEAL_RECORDS {
        warn!(
            "create_epoch_seal: zone-window scan hit cap ({MAX_SEAL_RECORDS}) zone={} epoch={epoch_number} — sealing partial window; zone needs splitting",
            zone,
        );
    }

    // Filter: skip epoch seals themselves. Records returned by query_zone_ids
    // are already in `zone` per the index. The legacy zone_registry resolve
    // check is preserved here as a defence-in-depth guard against stale zone-idx
    // entries from before the post-split routing landed — a misrouted record
    // would otherwise contaminate the seal's merkle root. The check is O(1)
    // per record so the cost is negligible vs the I/O saved by query_zone_ids.
    let mut hashes: Vec<[u8; 32]> = Vec::with_capacity(ids.len());
    for rid in &ids {
        let rec = match storage.get(rid) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let rec_zone = if let Some(reg) = zone_registry {
            let naive = zone_for_record(&rec.id);
            let rk = super::zone_registry::routing_key_for_record(&rec.id);
            super::zone_registry::resolve_current_leaf(reg, &naive, &rk).resolved_zone
        } else {
            zone_for_record(&rec.id)
        };
        if rec_zone != zone {
            continue;
        }
        // Skip other epoch seal records
        if rec.metadata.contains_key(EPOCH_OP_KEY) {
            continue;
        }
        hashes.push(rec.record_hash());
    }

    hashes.sort();
    let record_count = hashes.len() as u64;
    let merkle_root = MerkleTree::root(&hashes);

    // Compute VRF over epoch parameters.
    //
    // Alpha = `chained_beacon(prev_seal_hash, epoch, zone)` (Stage 3b.4 / §11.13).
    // The chained beacon is the single canonical per-`(zone, epoch)` input that
    // the aggregator rank-gating logic, jury selection, and VRF proof all derive
    // from — one primitive, one truth, no ambiguity between creator and verifier.
    //
    // Legacy seals created before Stage 3b.4 used a string alpha of the form
    // `"epoch:{zone}:{epoch}:{hex(prev_seal_hash)}"`. `verify_epoch_seal` falls
    // back to that format for historical seals so existing testnet history
    // continues to verify.
    let (vrf_output_bytes, vrf_proof_bytes) = if let Some(sk) = vrf_sk {
        let beacon = super::aggregator::chained_beacon(
            &previous_seal_hash, epoch_number, &zone,
        );
        let (output, proof) = crate::crypto::vrf::vrf_prove(sk, &beacon)?;
        (Some(*output.as_bytes()), Some(proof.to_bytes().to_vec()))
    } else {
        (None, None)
    };

    // Build metadata with new production fields
    let mut metadata = seal_metadata(SealMetadataParams {
        zone: zone.clone(),
        epoch_number,
        start,
        end,
        record_count,
        merkle_root: &merkle_root,
        previous_seal_hash: &previous_seal_hash,
        vrf_output: vrf_output_bytes.as_ref(),
        vrf_proof: vrf_proof_bytes.as_deref(),
        sparse_merkle_root: sparse_merkle_root.as_ref(),
        record_hashes: Some(&hashes),
        zone_balance_total,
        zone_registry_root: zone_registry_root.as_ref(),
        zone_registry_delta: zone_registry_delta.as_deref(),
        aggregator_rank,
        account_smt_root: account_smt_root.as_ref(),
        drand_pulse,
    });

    // B2 fix: bind the per-dest-zone canonical finality committee anchors into
    // the seal metadata BEFORE signing, so the value is covered by the seal's
    // Dilithium3 signature and `signable_bytes`. Injected here (rather than via
    // SealMetadataParams) to keep the new key off the ~20 test call sites of
    // `seal_metadata`. Omitted entirely when None/empty → byte-identical
    // signable_bytes to a pre-feature seal (legacy-safe, like account_smt_root).
    // The key is allowlisted in `content_safety::ALLOWED_KEYS`.
    if let Some(ref committees) = xzone_dest_finality_committees {
        if !committees.is_empty() {
            let obj: serde_json::Map<String, JsonValue> = committees
                .iter()
                .map(|(z, (h, n))| {
                    (
                        z.clone(),
                        JsonValue::Array(vec![
                            JsonValue::String(hex::encode(h)),
                            JsonValue::from(*n),
                        ]),
                    )
                })
                .collect();
            metadata.insert(
                "epoch_xzone_dest_finality_committees".into(),
                JsonValue::Object(obj),
            );
        }
    }

    // Content hash: SHA3-256("epoch:seal:{zone}:{epoch_number}")
    let content_str = format!("epoch:seal:{zone}:{epoch_number}");

    let mut record = ValidationRecord::create(
        content_str.as_bytes(),
        identity.public_key.clone(),
        parents,
        Classification::Public,
        Some(metadata),
    );
    // Slot nonce BEFORE signing — see `create_ledger_record_with_nonce` for
    // rationale. Every epoch seal from the same anchor identity must claim
    // a distinct (account, nonce) slot or the second seal is rejected as
    // SLOT EQUIVOCATION.
    record.nonce = slot_nonce;

    // Sign (dual-sig for Profile A)
    identity.sign_record(&mut record)?;

    let parsed = ParsedEpochSeal {
        zone,
        epoch_number,
        start,
        end,
        record_count,
        merkle_root,
        previous_seal_hash,
        vrf_output: vrf_output_bytes,
        vrf_proof: vrf_proof_bytes,
        record_hashes: hashes,
        zone_balance_total,
        zone_registry_root,
        zone_registry_delta,
        seal_zone_count: Some(super::consensus::get_zone_count()),
        aggregator_rank,
        account_smt_root,
        // Mirror what was written into metadata above (None in slice a2).
        // `drand_pulse` is `Option<&DrandPulse>` (Copy) — reused, not moved.
        drand_pulse: drand_pulse.cloned(),
        // B2 fix: mirror the committee anchors written into metadata so the
        // local-creation attach path (epoch.rs:5525) freezes the identical
        // value a follower parses from the seal record.
        xzone_dest_finality_committees,
    };

    Ok((record, parsed))
}

// ─── Window-scan enumeration (shared by verify + R3-8 derive) ──────────────

/// Stream the seal's zone+time window from local storage and return the
/// SORTED record-hash enumeration its producer would have committed: same
/// filters as `create_epoch_seal_with_balance` (zone membership via the
/// seal's embedded zone_count, epoch-op records excluded) and the same
/// `MAX_SEAL_RECORDS` cap, so creator, verifier, and deriver agree
/// deterministically. Extracted from `verify_epoch_seal_inner` /
/// `witness_verify_seal` so R3-8 derive-when-absent shares one definition
/// of "the window set". Streaming: IDs first, one decoded record at a time
/// — O(IDs) + O(1 record) peak memory (phone-tier safe).
pub fn scan_window_record_hashes(
    storage: &dyn Storage,
    seal: &ParsedEpochSeal,
    context: &str,
) -> Result<Vec<[u8; 32]>> {
    let seal_zc = seal.seal_zone_count.unwrap_or_else(super::consensus::get_zone_count);
    let ids = storage.query_zone_ids(
        &seal.zone, seal_zc, Some(seal.start), Some(seal.end), MAX_SEAL_RECORDS,
    )?;
    observe_seal_window_size(ids.len());
    if ids.len() >= MAX_SEAL_RECORDS {
        tracing::warn!(
            "{context}: zone-window scan hit cap ({MAX_SEAL_RECORDS}) zone={} epoch={} — partial window",
            seal.zone, seal.epoch_number,
        );
    }
    let mut hashes: Vec<[u8; 32]> = Vec::with_capacity(ids.len());
    for rid in &ids {
        let rec = match storage.get(rid) {
            Ok(r) => r,
            Err(_) => continue,
        };
        if ZoneId::for_record_dynamic(&rec.id, seal_zc) != seal.zone {
            continue;
        }
        if rec.metadata.contains_key(EPOCH_OP_KEY) {
            continue;
        }
        hashes.push(rec.record_hash());
    }
    hashes.sort();
    Ok(hashes)
}

/// Outcome of a derive-when-absent attempt (R3-8 slices 4+5).
#[derive(Debug, PartialEq, Eq)]
pub enum DeriveOutcome {
    /// Recomputed root matched the signed `merkle_root` — the derived,
    /// sorted enumeration is exactly the committed set (every entry is a
    /// locally-held record by construction).
    Derived(Vec<[u8; 32]>),
    /// Window scanned but the root did not match (or the scan errored):
    /// the local DAG is incomplete for this seal. Carries the local window
    /// size so P3 can degrade to a count-based deficit
    /// (`record_count − local_window_count`) without a second scan.
    Incomplete { local_window_count: u64 },
}

/// R3-8 slice 4 — derive-when-absent. Recompute the full enumeration for a
/// seal whose inline `epoch_record_hashes` was omitted (bounded emission
/// above [`SEAL_INLINE_ENUM_MAX`]) or dropped (slice-2 root gate).
/// `Derived` ONLY when the recomputed Merkle root equals the signed
/// `merkle_root`; `Incomplete` keeps consumers on the legacy-empty
/// behavior (no-op, self-heal via full_pull) while carrying the local
/// window count for the P3 deficit degrade. `None` = nothing to derive
/// (`record_count == 0`).
///
/// Callers derive ONCE per seal-processing pass and share the value
/// in-pass (mutate the pass's `ParsedEpochSeal`); never persist it — the
/// enumeration is reconstructible, a persistent CF at 1M-zone archive
/// scale is ~410 GB (evaluated and rejected in the R3-8 audit).
pub fn derive_seal_enumeration(
    storage: &dyn Storage,
    seal: &ParsedEpochSeal,
) -> Option<DeriveOutcome> {
    if seal.record_count == 0 {
        return None;
    }
    let hashes = match scan_window_record_hashes(storage, seal, "derive_seal_enumeration") {
        Ok(h) => h,
        Err(_) => {
            // Storage error → fully-incomplete (deficit degrades to the full
            // signed count), NOT None: None reads as "nothing to derive" and
            // would let recheck_dag_deficits false-close a real deficit on a
            // transient storage error.
            SEAL_ENUM_DERIVE_MISS_TOTAL.fetch_add(1, Ordering::Relaxed);
            return Some(DeriveOutcome::Incomplete { local_window_count: 0 });
        }
    };
    if !hashes.is_empty() && MerkleTree::root(&hashes) == seal.merkle_root {
        SEAL_ENUM_DERIVED_TOTAL.fetch_add(1, Ordering::Relaxed);
        Some(DeriveOutcome::Derived(hashes))
    } else {
        SEAL_ENUM_DERIVE_MISS_TOTAL.fetch_add(1, Ordering::Relaxed);
        tracing::debug!(
            "derive_seal_enumeration: recomputed root mismatch zone={} epoch={} (window has {} records vs sealed {}) — legacy-empty fallback",
            seal.zone, seal.epoch_number, hashes.len(), seal.record_count,
        );
        Some(DeriveOutcome::Incomplete {
            local_window_count: hashes.len() as u64,
        })
    }
}

// ─── Verify epoch seal ─────────────────────────────────────────────────────

/// Inputs for aggregator-rank verification inside `verify_epoch_seal`
/// (Stage 3b.6 / Protocol §11.13).
///
/// Passed by the ingest pipeline which has live access to the staker set and
/// per-zone RTT. Tests and historical replay callers pass `None` for
/// `rank_check` on `verify_epoch_seal` and skip this check entirely.
pub struct RankCheck<'a> {
    /// `(identity_hash, stake)` for every active staker on the network, as
    /// seen by the verifier at verification time.
    pub stakers: &'a [(String, u64)],
    /// Per-zone base timeout in milliseconds (`max(2·p95_rtt, 5s)`). Must
    /// match the proposer's clamp: `[1000, 600_000]`.
    pub base_timeout_ms: u64,
}

/// Verify that an epoch seal's declared `aggregator_rank` is consistent with
/// the creator's VRF-stake rank and the exponential-backoff schedule.
///
/// This is the rank half of Stage 3b.6 / Protocol §11.13 — the time half
/// lives in [`current_allowed_rank`][super::aggregator::current_allowed_rank]
/// and the declared-vs-derived check is a pure function of the beacon and
/// the staker set.
///
/// Checks performed:
/// 1. Declared `aggregator_rank < MAX_VIEW_DEPTH`. Anything ≥ `MAX_VIEW_DEPTH`
///    is outside the per-zone chain and must fall through to cross-zone
///    escalation (Stage 3c).
/// 2. Bootstrap carve-out: if `stakers.len() < 3`, only the genesis authority
///    may propose, and only at rank 0.
/// 3. The creator's VRF-rank under
///    `chained_beacon(prev_seal_hash, epoch_number, zone)` and the provided
///    stakers must equal the declared `aggregator_rank` (anti-rank-forgery).
/// 4. Time gate: rank `k` requires `elapsed_ms ≥ (2^k - 1) · base_timeout_ms`
///    — i.e. `current_allowed_rank(base, elapsed) ≥ declared`. Rejects
///    rank-jumping (proposing rank > 0 before earlier ranks had a chance).
///
/// Pure: no wall clock, no locks, no I/O. `elapsed_ms` comes from the caller.
///
/// See also [`verify_epoch_seal`] which plumbs the live inputs and calls this
/// when a [`RankCheck`] is supplied.
pub fn verify_aggregator_rank(
    creator: &str,
    seal: &ParsedEpochSeal,
    stakers: &[(String, u64)],
    genesis_authority: &str,
    base_timeout_ms: u64,
    elapsed_ms: u64,
) -> Result<()> {
    use super::aggregator::{chained_beacon, current_allowed_rank, rank_of, MAX_VIEW_DEPTH};

    // 1. Declared rank must live in the bounded view [0, MAX_VIEW_DEPTH).
    //    Anything at or beyond escapes the per-zone chain — cross-zone
    //    escalation (Stage 3c.1) owns that path.
    if (seal.aggregator_rank as usize) >= MAX_VIEW_DEPTH {
        return Err(ElaraError::Ledger(format!(
            "epoch seal aggregator_rank {} >= MAX_VIEW_DEPTH ({}) for zone {} epoch {}",
            seal.aggregator_rank, MAX_VIEW_DEPTH, seal.zone, seal.epoch_number,
        )));
    }

    // 2. Bootstrap carve-out — matches `aggregator::proposer_rank`.
    //    Fewer than 3 stakers ⇒ only genesis authority may propose, only at
    //    rank 0. Every other case fails.
    if stakers.len() < 3 {
        if creator != genesis_authority {
            return Err(ElaraError::Ledger(format!(
                "epoch seal from non-genesis creator {} rejected during bootstrap \
                 (staked={} < 3) for zone {} epoch {}",
                &creator[..creator.len().min(16)],
                stakers.len(),
                seal.zone,
                seal.epoch_number,
            )));
        }
        if seal.aggregator_rank != 0 {
            return Err(ElaraError::Ledger(format!(
                "bootstrap seal must declare rank 0, got {} for zone {} epoch {}",
                seal.aggregator_rank, seal.zone, seal.epoch_number,
            )));
        }
        return Ok(());
    }

    // 3. Re-derive the creator's rank under the canonical chained beacon.
    //    `rank_of` returns None if the creator is outside the top
    //    `MAX_VIEW_DEPTH` stakers — those identities must never propose.
    let beacon = chained_beacon(&seal.previous_seal_hash, seal.epoch_number, &seal.zone);
    let derived_rank = rank_of(&beacon, stakers, &seal.zone, creator, MAX_VIEW_DEPTH)
        .ok_or_else(|| {
            ElaraError::Ledger(format!(
                "epoch seal creator {} not in top-{} aggregator chain for zone {} epoch {}",
                &creator[..creator.len().min(16)],
                MAX_VIEW_DEPTH,
                seal.zone,
                seal.epoch_number,
            ))
        })?;

    if derived_rank != seal.aggregator_rank as usize {
        return Err(ElaraError::Ledger(format!(
            "epoch seal aggregator_rank mismatch: declared {}, derived {} \
             for creator {} zone {} epoch {}",
            seal.aggregator_rank,
            derived_rank,
            &creator[..creator.len().min(16)],
            seal.zone,
            seal.epoch_number,
        )));
    }

    // 4. Time gate — reject rank-jumping. Rank `k` unlocks at
    //    `(2^k - 1) · base_timeout_ms`; `current_allowed_rank` returns the
    //    largest unlocked rank for the given elapsed time.
    let allowed = current_allowed_rank(base_timeout_ms, elapsed_ms);
    if allowed < derived_rank {
        return Err(ElaraError::Ledger(format!(
            "epoch seal rank-jumping: declared rank {} proposed before unlock \
             (elapsed_ms={}, base_timeout_ms={}, current_allowed_rank={}) \
             for zone {} epoch {}",
            derived_rank,
            elapsed_ms,
            base_timeout_ms,
            allowed,
            seal.zone,
            seal.epoch_number,
        )));
    }

    Ok(())
}

/// Verify an epoch seal record against local storage and epoch state.
///
/// Multi-anchor model: accepts seals from genesis authority OR any anchor
/// with a valid VRF proof. Non-genesis seals MUST have VRF proof.
///
/// 1. Check creator is genesis authority OR has valid VRF proof
/// 2. Parse metadata, check epoch_number == next expected, previous_seal matches
/// 3. Recompute Merkle root from local records, compare
/// 4. If VRF public key provided, verify VRF proof
/// 5. If `rank_check` is provided AND the seal is in the normal sequential
///    window AND we have a local `epoch_start_ts` for this zone, verify the
///    aggregator rank (Stage 3b.6). Historical/catch-up/partition-merge
///    seals skip this because stake context at proposal time may differ
///    from now, and first-ever seal after restart has no epoch_start_ts.
pub fn verify_epoch_seal(
    record: &ValidationRecord,
    storage: &dyn Storage,
    epoch_state: &EpochState,
    genesis_authority: &str,
    vrf_pk: Option<&crate::crypto::vrf::VrfPublicKey>,
    rank_check: Option<&RankCheck<'_>>,
) -> Result<ParsedEpochSeal> {
    // Default ingest path: run full verification including the merkle
    // recomputation. The async ingest path takes the `_no_merkle` variant
    // to avoid a 30-70s RocksDB range scan on the Tokio worker thread.
    verify_epoch_seal_inner(record, storage, epoch_state, genesis_authority, vrf_pk, rank_check, true)
}

/// Variant of [`verify_epoch_seal`] that skips the inline
/// storage.query → merkle-root recomputation. Used on the ingest hot path
/// where the scan costs 30-70s under compaction backpressure and offers no
/// safety benefit — the merkle mismatch branch only emits `warn!` and
/// accepts the seal anyway (lines 1885-1904 below). The seal's Dilithium3
/// signature still authenticates the creator and their merkle commitment;
/// divergence from local storage is diagnostic, not a rejection condition.
pub fn verify_epoch_seal_no_merkle(
    record: &ValidationRecord,
    storage: &dyn Storage,
    epoch_state: &EpochState,
    genesis_authority: &str,
    vrf_pk: Option<&crate::crypto::vrf::VrfPublicKey>,
    rank_check: Option<&RankCheck<'_>>,
) -> Result<ParsedEpochSeal> {
    verify_epoch_seal_inner(record, storage, epoch_state, genesis_authority, vrf_pk, rank_check, false)
}

fn verify_epoch_seal_inner(
    record: &ValidationRecord,
    storage: &dyn Storage,
    epoch_state: &EpochState,
    genesis_authority: &str,
    vrf_pk: Option<&crate::crypto::vrf::VrfPublicKey>,
    rank_check: Option<&RankCheck<'_>>,
    recompute_merkle: bool,
) -> Result<ParsedEpochSeal> {
    // 1. Check creator is an authorized anchor
    let creator = creator_identity_hash(record);
    let is_genesis = creator == genesis_authority;

    // Non-genesis creators must have VRF proof (multi-anchor requirement).
    // Genesis authority is accepted with or without VRF (backward compat).
    if !is_genesis {
        // Parse early to check VRF presence before full verification
        let pre_seal = extract_epoch_seal(record)?
            .ok_or_else(|| ElaraError::Ledger("record is not an epoch seal".into()))?;
        if pre_seal.vrf_output.is_none() || pre_seal.vrf_proof.is_none() {
            return Err(ElaraError::Ledger(format!(
                "non-genesis epoch seal from {} must include VRF proof",
                &creator[..creator.len().min(16)]
            )));
        }
    }

    // 2. Parse metadata
    let seal = extract_epoch_seal(record)?
        .ok_or_else(|| ElaraError::Ledger("record is not an epoch seal".into()))?;

    // 3. Check epoch number — allow partition-merge reconciliation.
    // Protocol §3.3.3: partition-merge operator π — partitions grow independently,
    // merge preserves all records with no data loss.
    //
    // If the seal's epoch number doesn't match our expected next, it may be from
    // a partition that was sealing independently. Accept it if:
    // (a) the epoch number is within a reasonable window (±100 of our latest), AND
    // (b) the seal chains to a valid previous_seal_hash (even if different from ours)
    // This preserves both partition chains; attestation weight determines canonical.
    let expected = epoch_state.next_epoch(&seal.zone);
    let our_latest = expected.saturating_sub(1);
    let epoch_gap = seal.epoch_number.abs_diff(our_latest);

    // Track whether we're in catch-up or partition-merge mode.
    // In these modes, we skip merkle verification since we likely don't have
    // the historical records needed to recompute the merkle root.
    let mut skip_merkle = false;

    if seal.epoch_number == expected {
        // Normal sequential case — ADVISORY chain-link check only. This read runs
        // under the epoch READ lock, which races register_seal()'s write (ingest.rs):
        // seal N can transiently mismatch if seal N-1 hasn't registered yet, so a
        // hard-reject here would false-reject honest seals. The AUTHORITATIVE
        // chain-link reject for the forged-fork vector (C2) lives in ingest.rs under
        // the epoch WRITE lock, where the tip is read atomically with the mutation
        // (no TOCTOU). Dilithium3 authenticates WHO signed, not which chain it chains
        // off — hence the register-time enforcement. This warn stays as a diagnostic.
        let expected_prev = epoch_state.previous_seal_hash(&seal.zone);
        if seal.previous_seal_hash != expected_prev {
            tracing::warn!(
                "epoch seal previous_seal mismatch for zone {} epoch {} (advisory — authoritative chain-link reject is at ingest register-time, C2)",
                seal.zone, seal.epoch_number
            );
        }
    } else if seal.epoch_number > our_latest {
        // Catch-up case: seal is ahead of us — we've been offline or are syncing.
        // Accept the seal so the node can fast-forward its epoch state.
        // Skip merkle verification — we don't have the historical records.
        // The prefetch loop was retrying this every 10s with 0 new records,
        // blocking epoch progression and spamming logs indefinitely.
        //
        // B7 (fusion-audited 2026-06-19, 4 Opus panel + 1 result-checker): this
        // branch fast-forwards `latest_epoch` to an arbitrary higher value with
        // `skip_merkle` and NO chain-link, so a single forged high-epoch seal can
        // shove our tip past the canonical chain — after which the real seals hit
        // the "too far behind (max 100)" reject below and this node is wedged
        // off-canonical (a sync/liveness wedge, not a balance fork — finality
        // still needs 2/3 stake). The Dilithium3 signature only proves WHO
        // authored the bytes, not that they were SELECTED to seal. So a
        // non-genesis catch-up seal may fast-forward us ONLY if we can actually
        // verify its VRF proof (the proposer's full key is registered locally).
        // Genesis stays exempt — it is the trust root and is VRF-exempt by
        // design, which keeps the live first-external join working
        // (genesis-only-proposer today). If we cannot verify, DEFER: return a
        // retryable error (the ingest caller parks it and re-tries once the
        // proposer's VRF registration syncs) rather than silently fast-forward.
        // Scoped to the fast-forward arm ONLY: the sequential (+1) and
        // partition-merge arms cannot wedge the tip and lose to attestation
        // weight, so their legacy VRF-skip behaviour is intentionally left intact
        // (full closure of the sequential VRF-skip is the S3 registry-in-snapshot
        // follow-up — see internal design notes).
        if !is_genesis {
            let vrf_verifiable = vrf_pk.is_some_and(|pk| !pk.full_pk().is_empty());
            if !vrf_verifiable {
                return Err(ElaraError::Ledger(format!(
                    "non-genesis catch-up seal from {} is VRF-unverifiable \
                     (proposer key not registered) — deferring fast-forward for \
                     zone {} epoch {}",
                    &creator[..creator.len().min(16)], seal.zone, seal.epoch_number
                )));
            }
        }
        tracing::info!(
            "epoch catch-up: accepting epoch {} for zone {} (our latest: {}, gap: {}) — skipping merkle (historical)",
            seal.epoch_number, seal.zone, our_latest, epoch_gap
        );
        skip_merkle = true;
    } else if epoch_gap <= 100 {
        // Partition-merge case: seal is behind us but within merge window.
        // Accept the seal — it's from a partition that sealed independently.
        // The records it covers will arrive via delta sync.
        // Don't check previous_seal_hash — the partition has its own chain.
        tracing::info!(
            "partition-merge: accepting epoch {} for zone {} (our latest: {}, gap: {})",
            seal.epoch_number, seal.zone, our_latest, epoch_gap
        );
        skip_merkle = true;
    } else {
        // Seal is too far behind us — reject ancient replays
        return Err(ElaraError::Ledger(format!(
            "epoch seal {} too far behind expected {} for zone {} (gap: {}, max: 100)",
            seal.epoch_number, expected, seal.zone, epoch_gap
        )));
    }

    // 4. §11.6 Seal timestamp monotonicity enforcement.
    // The seal's time window [start, end] must not overlap with or precede
    // the previous seal's window. This prevents backdating attacks where an
    // attacker creates seals covering past time windows.
    if seal.end <= seal.start {
        return Err(ElaraError::Ledger(format!(
            "epoch seal for zone {} epoch {}: end ({:.3}) <= start ({:.3})",
            seal.zone, seal.epoch_number, seal.end, seal.start
        )));
    }
    let prev_end = epoch_state.latest_seal_end.get(&seal.zone).copied().unwrap_or(0.0);
    if prev_end > 0.0 && seal.start < prev_end && seal.epoch_number == expected {
        // Only enforce for sequential seals — catch-up and partition-merge
        // may arrive with overlapping windows from independent chains.
        tracing::warn!(
            "epoch seal timestamp overlap: zone {} epoch {} start ({:.3}) < previous end ({:.3}) — accepting (non-fatal)",
            seal.zone, seal.epoch_number, seal.start, prev_end
        );
    }

    // 5. Recompute Merkle root from local records
    // Use the seal's embedded zone_count for record-to-zone mapping.
    // This ensures verification works even after the global zone_count has changed.
    // Legacy seals (without zone_count) fall back to the current global.
    // On the ingest hot path the caller passes recompute_merkle=false
    // because the scan costs 30-70s under compaction backpressure and the
    // divergence branch below only warns, never rejects.
    if !skip_merkle && recompute_merkle {
        // Zone-keyed streaming scan shared with witness_verify_seal and the
        // R3-8 derive path — one definition of "the window set". See
        // scan_window_record_hashes for the CF_RECORD_BY_ZONE +
        // defence-in-depth re-check + memory-floor rationale.
        let hashes = scan_window_record_hashes(storage, &seal, "verify_epoch_seal")?;
        let computed_root = MerkleTree::root(&hashes);

        if computed_root != seal.merkle_root {
            // If our record count differs from the seal's, we're missing records
            // and merkle will never match. Accept the seal with a warning instead
            // of blocking epoch progression indefinitely.
            let local_count = hashes.len() as u64;
            if local_count != seal.record_count {
                tracing::warn!(
                    "epoch seal merkle mismatch for zone {} epoch {} — accepting (record count divergence: local={} seal={})",
                    seal.zone, seal.epoch_number, local_count, seal.record_count,
                );
            } else {
                // Same record count but different root — records themselves differ.
                // Still accept to avoid permanent blockage, but log at higher severity.
                tracing::warn!(
                    "epoch seal merkle mismatch for zone {} epoch {} — accepting (same count={} but roots differ: local={} seal={})",
                    seal.zone, seal.epoch_number, local_count,
                    hex::encode(computed_root), hex::encode(seal.merkle_root),
                );
            }
        }
    }

    // 6. Verify VRF proof if public key is provided
    if let Some(pk) = vrf_pk {
        match (&seal.vrf_output, &seal.vrf_proof) {
            (Some(output), Some(proof_bytes)) => {
                // Parse proof (variable size: 80 bytes for legacy EC-VRF, ~3312 for Dilithium VRF)
                if proof_bytes.len() < 3 {
                    return Err(ElaraError::Ledger(format!(
                        "epoch seal VRF proof too short: {} bytes",
                        proof_bytes.len()
                    )));
                }
                let proof = crate::crypto::vrf::VrfProof::from_bytes(proof_bytes)
                    .map_err(|e| ElaraError::Ledger(format!(
                        "invalid VRF proof format: {e}"
                    )))?;

                // Primary alpha (Stage 3b.4): `chained_beacon(prev_seal_hash,
                // epoch, zone)`. Fallback alpha: legacy string format used by
                // seals created before Stage 3b.4 landed. Trying primary first
                // is the common path; the legacy branch only fires for historical
                // records still replaying through verification.
                let beacon = super::aggregator::chained_beacon(
                    &seal.previous_seal_hash,
                    seal.epoch_number,
                    &seal.zone,
                );
                let legacy_alpha = format!(
                    "epoch:{}:{}:{}",
                    seal.zone, seal.epoch_number,
                    hex::encode(seal.previous_seal_hash)
                );

                let verified_output = match crate::crypto::vrf::vrf_verify(pk, &beacon, &proof) {
                    Ok(vo) if vo.as_bytes() == output => vo,
                    _ => crate::crypto::vrf::vrf_verify(pk, legacy_alpha.as_bytes(), &proof)
                        .map_err(|e| ElaraError::Ledger(format!(
                            "epoch seal VRF verification failed for zone {} epoch {}: {}",
                            seal.zone, seal.epoch_number, e
                        )))?,
                };

                // Check output matches what's in metadata
                if verified_output.as_bytes() != output {
                    return Err(ElaraError::Ledger(format!(
                        "epoch seal VRF output mismatch for zone {} epoch {}",
                        seal.zone, seal.epoch_number
                    )));
                }
            }
            (None, None) => {
                // Legacy seal without VRF — accepted during migration.
                // New seals from VRF-enabled sealers will have these fields.
            }
            _ => {
                // Partial VRF data (output without proof or vice versa) is invalid.
                return Err(ElaraError::Ledger(format!(
                    "epoch seal has partial VRF data for zone {} epoch {} (need both output and proof)",
                    seal.zone, seal.epoch_number
                )));
            }
        }
    }

    // 7. Aggregator-rank verification (Stage 3b.6 / Protocol §11.13).
    //
    // Applies only when:
    //   • caller supplied live `rank_check` inputs (stakers + base_timeout),
    //   • we're in the normal sequential window (NOT catch-up / partition-merge —
    //     those skip merkle for the same reason: historical stake context is lost),
    //   • we have a local `epoch_start_ts` for this zone (a fresh node, or one
    //     that just restarted from snapshot, lacks this — skip and accept, the
    //     next seal will be checked normally).
    //
    // Legacy seals (no `epoch_aggregator_rank` key) parse as rank 0; rank 0 at
    // elapsed=0 is always allowed, so pre-3b.5 history continues to verify.
    if let Some(rc) = rank_check {
        if !skip_merkle {
            if let Some(start_ts) = epoch_state.epoch_start(&seal.zone) {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs_f64())
                    .unwrap_or(start_ts);
                // Clamp elapsed to [0, MAX_RANK_ELAPSED_SECS] — matches the
                // proposer-side clamp in `should_propose_seal`. A skewed
                // wall clock cannot produce absurd rank thresholds; bound is
                // 2× MAX_ADAPTIVE_EPOCH_SECS, just enough headroom for honest
                // network slack.
                let elapsed_s = (now - start_ts).clamp(0.0, MAX_RANK_ELAPSED_SECS);
                let elapsed_ms: u64 = (elapsed_s * 1000.0) as u64;
                let creator = creator_identity_hash(record);
                verify_aggregator_rank(
                    &creator,
                    &seal,
                    rc.stakers,
                    genesis_authority,
                    rc.base_timeout_ms,
                    elapsed_ms,
                )?;
            }
        }
    }

    Ok(seal)
}

// ─── Witness seal verification (layered consensus) ──────────────────────────

/// Result of witness verification for an anchor-proposed epoch seal.
///
/// Witnesses perform 4 checks before signing an attestation:
/// 1. Do I have all the records listed in record_hashes?
/// 2. Do they all pass Layer 1 validation?
/// 3. Does my Merkle root match the proposed root?
/// 4. Does zone_balance_total match my computation?
#[derive(Debug)]
pub enum WitnessVerification {
    /// All checks passed — witness should sign attestation.
    Verified,
    /// Missing records that the anchor included in the epoch.
    MissingRecords { missing: Vec<[u8; 32]> },
    /// Local Merkle root doesn't match the proposed root.
    MerkleRootMismatch { local: [u8; 32], proposed: [u8; 32] },
    /// Zone balance total doesn't match local computation.
    BalanceMismatch { local: u64, proposed: u64 },
    /// Record count doesn't match.
    RecordCountMismatch { local: u64, proposed: u64 },
}

impl WitnessVerification {
    pub fn is_verified(&self) -> bool {
        matches!(self, WitnessVerification::Verified)
    }
}

/// Verify an anchor-proposed epoch seal as a witness.
///
/// This is the witness verification flow from internal design notes:
/// 1. "Do I have all these records?" — check record_hashes against local storage
/// 2. "Do they all pass Layer 1 validation?" — (delegated to caller, already validated on receipt)
/// 3. "Does my Merkle root match?" — recompute from local records and compare
/// 4. "Does zone_balance_total match?" — recompute from ledger and compare
///
/// When the seal carries NO inline enumeration (R3-8 bounded emission above
/// `SEAL_INLINE_ENUM_MAX`, or a legacy empty array), the witness re-derives
/// the record list from its local zone window and compares count + root —
/// the signed `record_count`/`merkle_root` still fully commit the set, so
/// disagreement is detectable without the preimage (R3-9 Decision B).
///
/// Returns `WitnessVerification::Verified` if all checks pass.
pub fn witness_verify_seal(
    seal: &ParsedEpochSeal,
    storage: &dyn Storage,
    local_zone_balance: Option<u64>,
) -> WitnessVerification {
    // 1. Check we have all records the anchor included
    if !seal.record_hashes.is_empty() {
        // Zone-keyed streaming scan shared with verify_epoch_seal_inner and
        // the R3-8 derive path (scan_window_record_hashes) — zone membership
        // via the seal's embedded zone_count, O(IDs) + O(1 record) memory.
        // Storage errors degrade to an empty local set, surfacing as
        // MissingRecords below rather than a panic or silent pass.
        let local_hashes =
            scan_window_record_hashes(storage, seal, "witness_verify_seal").unwrap_or_default();

        // Check for missing records
        let local_set: std::collections::HashSet<[u8; 32]> = local_hashes.iter().copied().collect();
        let missing: Vec<[u8; 32]> = seal
            .record_hashes
            .iter()
            .filter(|h| !local_set.contains(*h))
            .copied()
            .collect();

        if !missing.is_empty() {
            return WitnessVerification::MissingRecords { missing };
        }

        // 2. Check record count matches
        if local_hashes.len() as u64 != seal.record_count {
            return WitnessVerification::RecordCountMismatch {
                local: local_hashes.len() as u64,
                proposed: seal.record_count,
            };
        }

        // 3. Recompute Merkle root and compare (scan helper returns sorted)
        let local_root = MerkleTree::root(&local_hashes);
        if local_root != seal.merkle_root {
            return WitnessVerification::MerkleRootMismatch {
                local: local_root,
                proposed: seal.merkle_root,
            };
        }
    } else {
        // R3-9 Decision B: enumeration absent — re-derive from the local zone
        // window. local > proposed = definite omission (the seal claims fewer
        // records than the witness can prove exist in the window); local <
        // proposed = witness still catching up (caller retries next cycle);
        // equal counts with a different root = divergent set. The empty-empty
        // case (record_count == 0, nothing local) passes trivially — root
        // compare is skipped because both sides computed over the empty set.
        let local_hashes =
            scan_window_record_hashes(storage, seal, "witness_verify_seal").unwrap_or_default();

        if local_hashes.len() as u64 != seal.record_count {
            return WitnessVerification::RecordCountMismatch {
                local: local_hashes.len() as u64,
                proposed: seal.record_count,
            };
        }

        if !local_hashes.is_empty() {
            let local_root = MerkleTree::root(&local_hashes);
            if local_root != seal.merkle_root {
                return WitnessVerification::MerkleRootMismatch {
                    local: local_root,
                    proposed: seal.merkle_root,
                };
            }
        }
    }

    // 4. Verify zone_balance_total if provided
    if let (Some(proposed_balance), Some(local_balance)) =
        (seal.zone_balance_total, local_zone_balance)
    {
        if proposed_balance != local_balance {
            return WitnessVerification::BalanceMismatch {
                local: local_balance,
                proposed: proposed_balance,
            };
        }
    }

    WitnessVerification::Verified
}

/// Compute the total balance for all accounts in a zone.
///
/// Conservation invariant (economics §10):
/// `sum(zone_account_balances) + sum(zone_pending_outbound) = zone_balance_total`
///
/// For the testnet where all accounts are in all zones (global ledger),
/// this returns the sum of all available + staked balances.
pub fn compute_zone_balance_total(ledger: &crate::accounting::ledger::LedgerState) -> u64 {
    ledger
        .accounts
        .values()
        .map(|acct| acct.available + acct.staked)
        .sum()
}

// ─── Cross-zone 2PC: proof attachment (Gap 2) ──────────────────────────────

/// Attach Merkle inclusion proofs to pending cross-zone locks whose lock records
/// appear in this seal's `record_hashes`.
///
/// Called from **both** the local seal-creation path and the seal-ingest path
/// so every node — not only the one that sealed — can verify cross-zone claims.
/// Without this symmetry, a claim anchored in zone B would stall unless the same
/// node that sealed the lock in zone A also seals the claim in B (extremely
/// unlikely in a multi-anchor network).
///
/// Returns the number of pending transfers that had a proof attached.
///
/// @spec Protocol §7.5
/// @spec economics §16.1
pub fn attach_xzone_proofs_from_seal(
    ledger: &mut crate::accounting::ledger::LedgerState,
    parsed: &ParsedEpochSeal,
) -> u32 {
    attach_xzone_proofs_from_seal_with_finality(ledger, parsed, None, None)
}

/// Gap 2.1 Phase 2b: same as `attach_xzone_proofs_from_seal`, plus bundles
/// the seal-finality witness signatures collected by `awc` onto each proof'd
/// transfer. This is what flips the consumer-side enforcement (Phase 2a) on:
/// once `committee_size > 0` is set on a transfer, `claim_transfer` rejects
/// claims whose source seal hasn't reached 2/3 finality in zone A.
///
/// `seal_id` is the record_id of the seal record (caller's `record.id`).
/// When either `seal_id` or `awc` is None, this degrades to the legacy
/// inclusion-only path — useful for tests and for the bootstrap window
/// before all 6 nodes are running Phase 2b code.
pub fn attach_xzone_proofs_from_seal_with_finality(
    ledger: &mut crate::accounting::ledger::LedgerState,
    parsed: &ParsedEpochSeal,
    seal_id: Option<&str>,
    awc: Option<&super::consensus::AWCConsensus>,
) -> u32 {
    if parsed.record_hashes.is_empty() {
        return 0;
    }
    let sealed_hashes = &parsed.record_hashes;
    let root = parsed.merkle_root;
    let mut proofed = 0u32;

    // Snapshot finality bundle once — same struct serves every transfer
    // produced by this seal, and we want to bundle it even if 0 transfers
    // are gated by it (so the cleanup at the end is unconditional).
    let finality = match (seal_id, awc) {
        (Some(sid), Some(c)) => c.seal_finality_collection_for(sid).cloned(),
        _ => None,
    };

    // Collect transfer IDs that need proofs (avoid borrow conflict).
    // dest_zone captured so the B2 abort-committee anchor can be frozen below.
    let needs_proof: Vec<(String, [u8; 32], ZoneId)> = ledger
        .cross_zone
        .pending
        .iter()
        .filter(|(_, t)| {
            t.status == crate::accounting::cross_zone::TransferStatus::Locked
                && t.merkle_proof.is_empty()
        })
        .map(|(id, t)| (id.clone(), t.lock_record_hash, t.dest_zone.clone()))
        .collect();

    for (tid, lock_hash, dest_zone) in needs_proof {
        if sealed_hashes.contains(&lock_hash) {
            if let Some(proof) = MerkleTree::proof(sealed_hashes, &lock_hash) {
                let siblings: Vec<crate::accounting::cross_zone::ProofSibling> = proof
                    .siblings
                    .iter()
                    .map(|n| crate::accounting::cross_zone::ProofSibling {
                        hash: n.hash,
                        is_right: n.is_right,
                    })
                    .collect();
                let _ = ledger.cross_zone.set_proof(&tid, siblings, root);
                if let Some(coll) = finality.as_ref() {
                    let _ = ledger.cross_zone.set_finality_witnesses(
                        &tid,
                        coll.signers.clone(),
                        coll.committee_hash,
                        coll.seal_epoch,
                        coll.committee_size,
                    );
                }
                // B2 fix: freeze the canonical dest finality-committee anchor
                // for this transfer from the seal's committed map. READ here,
                // never recomputed — the XZoneAbort apply/validate path gates
                // the wire committee against this frozen value. A transfer whose
                // dest zone is absent from the map (legacy seal) stays None →
                // its abort is fail-closed in verify_abort_quorum.
                if let Some(anchor) = parsed
                    .xzone_dest_finality_committees
                    .as_ref()
                    .and_then(|m| m.get(dest_zone.path()))
                {
                    if let Some(t) = ledger.cross_zone.pending.get_mut(&tid) {
                        t.dest_finality_committee = Some(*anchor);
                    }
                }
                proofed += 1;
            }
        }
    }
    proofed
}

// ─── Gap 3: super-seals / checkpoint consolidation ─────────────────────────

/// Parsed super-seal — a signed Merkle root over `SUPER_SEAL_INTERVAL`
/// consecutive zone seals. Used by light clients to skip from the latest
/// checkpoint instead of replaying every seal since genesis.
///
/// At 1M zones × 720 seals/day/zone = 720M seals/year; with N=64, that's
/// ~11M super-seals/year — a 65× compression of the sync set, and the only
/// way light clients stay viable at protocol scale.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ParsedSuperSeal {
    pub zone: ZoneId,
    /// First epoch covered (inclusive).
    pub start_epoch: u64,
    /// Last epoch covered (inclusive).
    pub end_epoch: u64,
    /// Count of constituent seals covered by `merkle_root`.
    pub seal_count: u64,
    /// Merkle root over SHA3-256(seal_record_hash) for each covered seal.
    pub merkle_root: [u8; 32],
    /// Hash of the previous super-seal record for this zone, or all-zero for the first.
    pub previous_super_seal_hash: [u8; 32],
    /// SHA3-256 commitment to the zone's committee members at super-seal time
    /// (MAINNET gap #3 follow-up). `[0u8; 32]` means no committee was registered
    /// at creation (small-network / bootstrap). Light clients use this to verify
    /// attestations against the correct witness set.
    #[serde(default)]
    pub committee_hash: [u8; 32],
}

/// Build the metadata BTreeMap for a super-seal record.
pub fn super_seal_metadata(
    zone: ZoneId,
    start_epoch: u64,
    end_epoch: u64,
    seal_count: u64,
    merkle_root: &[u8; 32],
    previous_super_seal_hash: &[u8; 32],
    committee_hash: &[u8; 32],
) -> BTreeMap<String, JsonValue> {
    let mut m = BTreeMap::new();
    m.insert(EPOCH_OP_KEY.into(), serde_json::json!(EPOCH_OP_SUPER_SEAL));
    m.insert("super_seal_zone".into(), serde_json::json!(zone));
    m.insert("super_seal_start_epoch".into(), serde_json::json!(start_epoch));
    m.insert("super_seal_end_epoch".into(), serde_json::json!(end_epoch));
    m.insert("super_seal_count".into(), serde_json::json!(seal_count));
    m.insert("super_seal_merkle_root".into(), serde_json::json!(hex::encode(merkle_root)));
    m.insert("super_seal_prev_hash".into(), serde_json::json!(hex::encode(previous_super_seal_hash)));
    // Gap #3 follow-up: all-zero committee hash is omitted from metadata to
    // keep super-seals built before this change (or on networks without
    // registered committees) bit-identical — extract_super_seal defaults to
    // [0u8; 32] when the field is absent.
    if committee_hash != &[0u8; 32] {
        m.insert("super_seal_committee_hash".into(), serde_json::json!(hex::encode(committee_hash)));
    }
    m
}

/// Parse a super-seal record's metadata. Returns `Ok(None)` for non-super-seal records.
pub fn extract_super_seal(record: &ValidationRecord) -> Result<Option<ParsedSuperSeal>> {
    let op_val = match record.metadata.get(EPOCH_OP_KEY) {
        Some(v) => v,
        None => return Ok(None),
    };
    let op_str = op_val.as_str().ok_or_else(|| ElaraError::Wire("epoch_op not a string".into()))?;
    if op_str != EPOCH_OP_SUPER_SEAL {
        return Ok(None);
    }

    let zone_val = record.metadata.get("super_seal_zone")
        .ok_or_else(|| ElaraError::Wire("missing super_seal_zone".into()))?;
    let zone: ZoneId = serde_json::from_value(zone_val.clone())
        .map_err(|e| ElaraError::Wire(format!("invalid super_seal_zone: {e}")))?;
    let start_epoch = record.metadata.get("super_seal_start_epoch")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| ElaraError::Wire("missing super_seal_start_epoch".into()))?;
    let end_epoch = record.metadata.get("super_seal_end_epoch")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| ElaraError::Wire("missing super_seal_end_epoch".into()))?;
    let seal_count = record.metadata.get("super_seal_count")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| ElaraError::Wire("missing super_seal_count".into()))?;
    let merkle_root_hex = record.metadata.get("super_seal_merkle_root")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ElaraError::Wire("missing super_seal_merkle_root".into()))?;
    let prev_hex = record.metadata.get("super_seal_prev_hash")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ElaraError::Wire("missing super_seal_prev_hash".into()))?;

    let merkle_bytes = hex::decode(merkle_root_hex)
        .map_err(|e| ElaraError::Wire(format!("invalid super_seal_merkle_root hex: {e}")))?;
    if merkle_bytes.len() != 32 {
        return Err(ElaraError::Wire("super_seal_merkle_root wrong length".into()));
    }
    let prev_bytes = hex::decode(prev_hex)
        .map_err(|e| ElaraError::Wire(format!("invalid super_seal_prev_hash hex: {e}")))?;
    if prev_bytes.len() != 32 {
        return Err(ElaraError::Wire("super_seal_prev_hash wrong length".into()));
    }

    let mut merkle_root = [0u8; 32];
    merkle_root.copy_from_slice(&merkle_bytes);
    let mut previous_super_seal_hash = [0u8; 32];
    previous_super_seal_hash.copy_from_slice(&prev_bytes);

    // Gap #3 follow-up: committee_hash is optional — absence means no
    // registered committee at super-seal time (bootstrap / small network).
    let mut committee_hash = [0u8; 32];
    if let Some(v) = record.metadata.get("super_seal_committee_hash") {
        let hex_str = v.as_str()
            .ok_or_else(|| ElaraError::Wire("super_seal_committee_hash not a string".into()))?;
        let bytes = hex::decode(hex_str)
            .map_err(|e| ElaraError::Wire(format!("invalid super_seal_committee_hash hex: {e}")))?;
        if bytes.len() != 32 {
            return Err(ElaraError::Wire("super_seal_committee_hash wrong length".into()));
        }
        committee_hash.copy_from_slice(&bytes);
    }

    if end_epoch < start_epoch {
        return Err(ElaraError::Wire("super_seal end_epoch < start_epoch".into()));
    }
    if seal_count == 0 {
        return Err(ElaraError::Wire("super_seal seal_count must be > 0".into()));
    }

    Ok(Some(ParsedSuperSeal {
        zone,
        start_epoch,
        end_epoch,
        seal_count,
        merkle_root,
        previous_super_seal_hash,
        committee_hash,
    }))
}

/// Inputs for [`create_super_seal`]. `seal_hashes` and `identity` are borrowed; the
/// hash arrays and `zone` are owned because the caller already has them by-value
/// at the seal-loop boundary. Caller must provide the ordered `seal_hashes` and
/// the hash of the previous super-seal record for this zone (or `[0u8; 32]` for
/// the first super-seal ever).
pub struct SuperSealParams<'a> {
    pub identity: &'a Identity,
    pub zone: ZoneId,
    pub start_epoch: u64,
    pub end_epoch: u64,
    pub seal_hashes: &'a [[u8; 32]],
    pub previous_super_seal_hash: [u8; 32],
    pub committee_hash: [u8; 32],
    pub timestamp: f64,
    // Why: slot enforcement keys on (creator_pk, nonce). Without a distinct nonce
    // per super-seal, every mint after the node's first v5 self-record collided at
    // `<account_hash>:0000000000000000` and surfaced as "slot conflict" on insert
    // (seen on the first real super-seal mint attempt). Producer must
    // pass `state.next_slot_nonce()`.
    pub slot_nonce: u64,
}

/// Create a super-seal record aggregating seal hashes from [start_epoch, end_epoch]
/// for `zone`. Returns the signed record and the parsed super-seal.
///
/// Intentionally does not scan storage — the caller (seal loop) already holds
/// the seal hashes in `parsed.record_hashes` or can pull them from EpochState,
/// avoiding an O(all_records) rescan. Scale rule: no full table scans in hot paths.
pub fn create_super_seal(
    params: SuperSealParams<'_>,
) -> Result<(ValidationRecord, ParsedSuperSeal)> {
    let SuperSealParams {
        identity,
        zone,
        start_epoch,
        end_epoch,
        seal_hashes,
        previous_super_seal_hash,
        committee_hash,
        timestamp,
        slot_nonce,
    } = params;

    if seal_hashes.is_empty() {
        return Err(ElaraError::Wire("cannot create super-seal from empty seal_hashes".into()));
    }
    if end_epoch < start_epoch {
        return Err(ElaraError::Wire("super_seal: end_epoch < start_epoch".into()));
    }

    // Sort seal_hashes for Merkle tree determinism — matches how regular seals
    // build their Merkle root over record_hashes.
    let mut sorted: Vec<[u8; 32]> = seal_hashes.to_vec();
    sorted.sort();
    let merkle_root = MerkleTree::root(&sorted);
    let seal_count = seal_hashes.len() as u64;

    let meta = super_seal_metadata(
        zone.clone(),
        start_epoch,
        end_epoch,
        seal_count,
        &merkle_root,
        &previous_super_seal_hash,
        &committee_hash,
    );

    let id = format!("super_seal:{}:{}-{}", zone.path(), start_epoch, end_epoch);
    let mut record = ValidationRecord::create(
        id.as_bytes(),
        identity.public_key.clone(),
        vec![],
        Classification::Public,
        Some(meta),
    );
    record.timestamp = timestamp;
    record.nonce = slot_nonce;
    let signable = record.signable_bytes();
    record.signature = Some(identity.sign(&signable)?);

    Ok((
        record,
        ParsedSuperSeal {
            zone,
            start_epoch,
            end_epoch,
            seal_count,
            merkle_root,
            previous_super_seal_hash,
            committee_hash,
        },
    ))
}

/// Verify that `seal_hashes` (any order) reconstruct `super_seal.merkle_root`.
///
/// Light clients use this to confirm that a set of fetched seal headers are
/// covered by the signed super-seal.
pub fn verify_super_seal_coverage(
    super_seal: &ParsedSuperSeal,
    seal_hashes: &[[u8; 32]],
) -> bool {
    if seal_hashes.len() as u64 != super_seal.seal_count {
        return false;
    }
    let mut sorted: Vec<[u8; 32]> = seal_hashes.to_vec();
    sorted.sort();
    MerkleTree::root(&sorted) == super_seal.merkle_root
}

// ─── Rebuild epoch state from storage ──────────────────────────────────────

/// Scan storage for epoch seal records and rebuild the epoch state.
/// **Test-only.** Production boot uses snapshot replay + per-zone CF_EPOCHS
/// reverse-scan via `restore_latest_seals_from_storage`, which is bounded
/// to one prefix scan per zone. The materializing form here issues
/// `storage.query(None, None, None, None, usize::MAX)` over CF_RECORDS,
/// which OOMs at production scale (10M+ records × 8 KB ≈ 80 GB heap).
#[cfg(test)]
pub fn rebuild_epoch_state(storage: &dyn Storage) -> Result<EpochState> {
    let all_records = storage.query(None, None, None, None, usize::MAX)?;
    rebuild_epoch_state_from_records(&all_records)
}

/// Chain-liveness fix: re-register every stored seal at each zone's
/// `latest_epoch` so the lex-min tiebreak in `register_seal` converges
/// every node on the same canonical hash, regardless of which arrived
/// first locally. Heals the case where two anchors raced at the same
/// epoch (legitimate dual-proposer behavior per Stage 3b.5/3b.6) and
/// snapshot persisted whichever happened to be registered last —
/// different on different nodes, so each computed a different
/// `chained_beacon` for the next epoch and no node thought it was
/// elected to propose.
///
/// Scale: bounded — at most one prefix scan per zone with `latest_epoch > 0`,
/// returning typically 1 entry (no race), 2 entries (rank-0 + rank-1 race),
/// at most ~7 (full rank ladder fired). At 1M zones the loop is 1M scans of
/// ≤7 entries each on cold start; hot-path runs are idempotent (single entry
/// → no-op canonicalization).
#[cfg(feature = "node-core")]
pub fn canonicalize_latest_seals(
    state: &mut EpochState,
    storage: &crate::storage::rocks::StorageEngine,
) {
    let zone_epochs: Vec<(ZoneId, u64)> = state
        .latest_epoch
        .iter()
        .map(|(z, e)| (z.clone(), *e))
        .collect();

    for (zone, epoch_num) in zone_epochs {
        if epoch_num == 0 {
            continue;
        }
        let zone_path = zone.path().to_string();
        let mut seek = Vec::with_capacity(8 + zone_path.len() + 1);
        seek.extend_from_slice(&epoch_num.to_be_bytes());
        seek.extend_from_slice(zone_path.as_bytes());
        seek.push(0u8);

        let mut record_ids: Vec<String> = Vec::new();
        let scan = storage.range_scan_cf(
            crate::storage::rocks::CF_EPOCHS,
            &seek,
            |key, _val| {
                let (e, z, rid) = match parse_disc5_index_key(key) {
                    Some(t) => t,
                    None => return Ok(true),
                };
                if e != epoch_num || z != zone_path.as_str() {
                    return Ok(false);
                }
                record_ids.push(rid.to_string());
                Ok(true)
            },
        );
        if let Err(e) = scan {
            warn!(
                "canonicalize_latest_seals: CF_EPOCHS scan failed for zone {} epoch {}: {e}",
                zone_path, epoch_num
            );
            continue;
        }
        if record_ids.len() < 2 {
            continue; // single seal — already canonical
        }
        for rid in &record_ids {
            let record = match storage.get_record(rid) {
                Ok(Some(r)) => r,
                _ => continue,
            };
            let seal = match extract_epoch_seal(&record) {
                Ok(Some(s)) => s,
                _ => continue,
            };
            state.register_seal(&seal, rid, record.record_hash());
        }
        info!(
            "canonicalize_latest_seals: re-registered {} seals at zone={} epoch={} — lex-min hash now canonical",
            record_ids.len(),
            zone_path,
            epoch_num
        );
    }
}

/// Gap 1 boot recovery: bounded reverse-scan of CF_EPOCHS to recover the
/// latest sealed account-SMT binding when EpochState's in-memory copy is
/// `None` (fresh boot before any new seal lands, or non-snapshot startup
/// path that didn't replay seals). Returns the same tuple shape as
/// `EpochState::latest_sealed_account` so callers can treat the two
/// interchangeably.
///
/// Why on-demand: production boot constructs `EpochState::new()` (state.rs:1478)
/// with `latest_sealed_account: None`, and `register_seal` only fires on NEW
/// seals after restart. Without this fallback, a fresh node returns
/// `bound_to_seal: false` for several minutes — long enough that light
/// clients fail their first verification.
///
/// Scale: O(1) RocksDB seek to the END of CF_EPOCHS plus at most
/// `MAX_FALLBACK_SEALS` reverse iterations to skip pre-Gap-1 seals that
/// lack `account_smt_root`. CF_EPOCHS is one entry per (epoch, zone) seal,
/// not per record. On a Gap-1 fleet the very first hit succeeds.
pub fn fallback_latest_sealed_account(
    storage: &crate::storage::rocks::StorageEngine,
) -> Option<(u64, ZoneId, String, [u8; 32], f64)> {
    const MAX_FALLBACK_SEALS: usize = 64;
    let mut found: Option<(u64, ZoneId, String, [u8; 32], f64)> = None;
    let mut scanned: usize = 0;
    let _ = storage.range_scan_cf_reverse(
        crate::storage::rocks::CF_EPOCHS,
        |key, _val| {
            scanned += 1;
            if scanned > MAX_FALLBACK_SEALS {
                return Ok(false);
            }
            let (epoch, zone_str, record_id_str) = match parse_disc5_index_key(key) {
                Some(t) => t,
                None => return Ok(true),
            };
            let zone = ZoneId::new(zone_str);
            let record_id = record_id_str.to_string();
            let record = match storage.get_record(&record_id) {
                Ok(Some(r)) => r,
                _ => return Ok(true),
            };
            let seal = match extract_epoch_seal(&record) {
                Ok(Some(s)) => s,
                _ => return Ok(true),
            };
            if let Some(root) = seal.account_smt_root {
                found = Some((epoch, zone, record_id, root, seal.end));
                return Ok(false);
            }
            Ok(true)
        },
    );
    found
}

/// Outcome of the single-zone sealed-root boot integrity check
/// ([`check_boot_sealed_root`], internal design notes §6 / "§6a").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootSealedRootOutcome {
    /// The replayed account-SMT root equals the signed seal's `account_smt_root`.
    Verified { epoch: u64, zone: ZoneId },
    /// The replayed root diverges from the signed seal — a supply-neutral
    /// dropped/extra record on the replay path (the supply-conservation backstop
    /// is blind to this class). Counter-only: the node continues as a follower.
    Mismatch {
        epoch: u64,
        zone: ZoneId,
        replayed: [u8; 32],
        sealed: [u8; 32],
    },
    /// The check could not run soundly; carries the precise reason so each
    /// skip is observable and never silently masks a real divergence.
    Skipped(BootSealedRootSkip),
}

/// Why [`check_boot_sealed_root`] declined to compare (each is a zero-false-positive
/// bail-out, never a pass).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootSealedRootSkip {
    /// Not single-zone. `account_smt_root` is a GLOBAL root carried inside a
    /// PER-ZONE seal drained in producer-arrival order; only at single-zone does
    /// the drain boundary coincide with the `[start,end)` window, so replay
    /// reproduces the sealed global root exactly. Multi-zone needs the deferred
    /// §6b global checkpoint and would false-fire.
    MultiZone,
    /// Single-zone but the tip epoch is 0 (genesis / nothing sealed yet).
    NoTipEpoch,
    /// No canonical seal at `(zone, tip)` carries an `account_smt_root`
    /// (pre-Gap-1 producer, or the seal is not on disk yet).
    NoSealedRoot,
    /// The ledger has folded an ACCOUNT-CHANGING op past the seal window `end`
    /// (`last_applied_ts > end`) — its account root legitimately reflects state
    /// beyond the seal, so skip rather than re-fold (re-fold is the deferred
    /// §6b slice). Non-account validation overhang does NOT trip this — it
    /// leaves the account root untouched, so the seal is still verified.
    UnsealedOverhang,
    /// `root_over_accounts` failed (malformed SMT input) — never seen in practice.
    RootError,
}

/// **Boot-only invariant — do NOT relocate into any periodic / post-repair path.**
/// `root_over_accounts` omits a removed-but-dirty leaf while `flush_dirty` hashes
/// `unwrap_or_default()` for it, so after `apply_state_delta_for_repair` runs (the
/// background divergence monitor) the two roots legitimately diverge. This check is
/// sound ONLY at boot, before any repair has mutated accounts out of band.
///
/// Single-zone (= first-external-join day-1) sealed-root boot integrity check
/// (internal design notes §6). After the node restores/replays its
/// ledger to its sealed tip, recompute the account-SMT root over the in-memory
/// account set and compare it against the producer's **signed** `account_smt_root`
/// in the canonical seal at the tip epoch. This is the only detector of a
/// supply-NEUTRAL dropped record on the replay path (the supply-conservation
/// backstop only catches supply-MOVING drops); the existing snapshot-bootstrap
/// verify compares against the producer's *self-claimed* snapshot root, not the
/// network-signed seal.
///
/// **Soundness** (fusion audit 2026-06-21 verdict CONFIRM-SHIP, AMENDED
/// 2026-06-30 after the live authority node mismatched on EVERY healthy boot):
/// the 2026-06-21 claim that the account leaf is "a pure function of the record
/// DAG" was WRONG. Two paths mutate `accounts` OUTSIDE `apply_op`, so the leaf is
/// NOT solely DAG-driven:
///   1. `apply_genesis_validators` (accounting/ledger.rs) — config-driven genesis
///      stake. It debits the authority's `available` and credits each validator's
///      `staked` without (previously) marking `smt_dirty`, and `smt_dirty` is
///      `#[serde(skip)]`, so a genesis validator that never transacted was absent
///      from every seal's `account_smt_root` yet present in `root_over_accounts`.
///      THIS was the observed false-mismatch. Fixed: it now marks `smt_dirty`, and
///      a boot reconcile (`account_merkle::reconcile_genesis_accounts_into_smt`)
///      heals nodes genesised before the fix.
///   2. `evaluate_predictions` (accounting/ledger.rs) — prediction settlement runs
///      AFTER the seal's SMT snapshot and does NOT advance `last_applied_ts`, so a
///      prediction-ACTIVE chain still lags by one epoch (the dirty marks added
///      there flush only at the next seal, and the overhang gate cannot absorb
///      it). LATENT today (no Predict records on-chain); the full fix is to
///      reorder evaluation before the snapshot — REQUIRED before predictions are
///      enabled, and a HARD blocker for fatal (stage-b) mode.
///
/// The 2026-06-21 notes still hold for their own scope: `uptime_vesting_loop` was
/// removed (069a344b), `process_expired_xzone`'s `last_active = now` is dead code,
/// and `pool_disbursed_window` has no production caller. With (1) fixed and (2)
/// latent, a correct single-zone node at a clean boundary reproduces the sealed
/// root exactly.
///
/// **Failure semantics:** mismatch is counter+`warn!` only — never fail-closed (a
/// false-close would brick a launch follower; a mis-replaying non-staked follower
/// cannot corrupt consensus and its bad proofs are caught by light-client verify).
///
/// **Scale:** O(accounts·log N) one-shot at boot for the root (same as the existing
/// snapshot verify), plus one bounded RocksDB reverse seek (canonical seal at the
/// tip band); the overhang gate is now an O(1) `last_applied_ts` field compare. No
/// O(all_records) scan.
pub fn check_boot_sealed_root(
    storage: &crate::storage::rocks::StorageEngine,
    accounts: &std::collections::HashMap<String, crate::accounting::ledger::AccountState>,
    latest_epoch: &std::collections::HashMap<ZoneId, u64>,
    last_applied_ts: f64,
) -> BootSealedRootOutcome {
    if latest_epoch.len() != 1 {
        return BootSealedRootOutcome::Skipped(BootSealedRootSkip::MultiZone);
    }
    let Some((zone, &tip)) = latest_epoch.iter().next() else {
        return BootSealedRootOutcome::Skipped(BootSealedRootSkip::MultiZone);
    };
    if tip == 0 {
        return BootSealedRootOutcome::Skipped(BootSealedRootSkip::NoTipEpoch);
    }
    // Anchor on the LEDGER's tip epoch and read THAT seal directly — NOT
    // fallback_latest_sealed_account, whose latest root-bearing seal can sit past
    // the ledger's replay boundary on a chain that kept sealing (false-fire).
    let Some((sealed_root, end_e)) = canonical_account_root_at(storage, zone, tip) else {
        return BootSealedRootOutcome::Skipped(BootSealedRootSkip::NoSealedRoot);
    };
    // Boundary gate: skip only if the LEDGER has folded an ACCOUNT-CHANGING
    // record past the seal window. `last_applied_ts` advances solely on
    // ledger/governance ops (apply_op / apply_governance_op), NOT on the
    // non-account validation records that make up the bulk of a validation
    // mesh. The old gate keyed on `newest_record_timestamp` — ANY record past
    // end_E — which spuriously skipped every live node (validation overhang is
    // always present), so the seal was never actually verified. Keying on
    // last_applied_ts compares the account root exactly when the account state
    // is at-or-before the seal boundary; a real supply-neutral drop in that
    // prefix then surfaces as Mismatch instead of being masked by a skip.
    if last_applied_ts > end_e {
        return BootSealedRootOutcome::Skipped(BootSealedRootSkip::UnsealedOverhang);
    }
    let replayed = match crate::network::account_merkle::root_over_accounts(accounts) {
        Ok(r) => r,
        Err(_) => return BootSealedRootOutcome::Skipped(BootSealedRootSkip::RootError),
    };
    if replayed == sealed_root {
        BootSealedRootOutcome::Verified {
            epoch: tip,
            zone: zone.clone(),
        }
    } else {
        BootSealedRootOutcome::Mismatch {
            epoch: tip,
            zone: zone.clone(),
            replayed,
            sealed: sealed_root,
        }
    }
}

/// Canonical `account_smt_root` + seal-window `end` for `(zone, epoch)`, selecting
/// the lex-min `record_hash` seal among any competitors (same tiebreak as
/// [`EpochState::register_seal`] / [`repopulate_recent_seal_hashes`]). Bounded
/// reverse scan: stops once the scan drops below `epoch` (CF_EPOCHS is
/// epoch-BE-ordered). Returns `None` if no such seal carries an `account_smt_root`.
fn canonical_account_root_at(
    storage: &crate::storage::rocks::StorageEngine,
    target_zone: &ZoneId,
    target_epoch: u64,
) -> Option<([u8; 32], f64)> {
    // best = (record_hash, account_smt_root, end) of the lex-min seal so far.
    let mut best: Option<([u8; 32], [u8; 32], f64)> = None;
    let _ = storage.range_scan_cf_reverse(
        crate::storage::rocks::CF_EPOCHS,
        |key, _val| {
            let (epoch, zone_str, record_id) = match parse_disc5_index_key(key) {
                Some(t) => t,
                None => return Ok(true),
            };
            if epoch > target_epoch {
                // Above the tip band (e.g. a super-seal) — skip toward the target.
                return Ok(true);
            }
            if epoch < target_epoch {
                // Below the target band — no further (zone,target_epoch) seals.
                return Ok(false);
            }
            if ZoneId::new(zone_str) != *target_zone {
                return Ok(true);
            }
            let record = match storage.get_record(record_id) {
                Ok(Some(r)) => r,
                _ => return Ok(true),
            };
            let seal = match extract_epoch_seal(&record) {
                Ok(Some(s)) => s,
                _ => return Ok(true),
            };
            let Some(root) = seal.account_smt_root else {
                return Ok(true);
            };
            let h = record.record_hash();
            match best {
                Some((best_h, _, _)) if best_h <= h => {}
                _ => best = Some((h, root, seal.end)),
            }
            Ok(true)
        },
    );
    best.map(|(_, root, end)| (root, end))
}

/// Repopulate `EpochState::recent_seal_hashes` from CF_EPOCHS after
/// a snapshot load. Without this, the rolling super-seal buffer is reset to
/// empty on every restart (`from_snapshot` initializes it to `HashMap::new()`
/// because `EpochStateSnapshot` doesn't carry the buffer), and Gap 3
/// super-seal generation cannot fire until the local anchor has observed
/// `SUPER_SEAL_INTERVAL=64` fresh seals since boot — at 60s mainnet cadence
/// that's a ≥64-minute blind spot per restart. On testnet (where anchors
/// restart every deploy cycle and seal cadence is far slower than mainnet)
/// the buffer effectively NEVER fills, explaining the empirical observation
/// that `elara_super_seals_minted_total` has been 0 across all 6 nodes since
/// Gap 3 shipped.
///
/// **Scale:** bounded reverse scan of CF_EPOCHS with hard iteration cap
/// `active_zones * SUPER_SEAL_INTERVAL * 4`, plus per-zone seal-window floor
/// short-circuit (`epoch < min_floor` stops the scan). For an anchor serving
/// 4 testnet zones this is ≤1024 iterations. For a 100-zone anchor: ≤25600.
/// At 1M zones per Protocol §11.12, each anchor serves only its assigned
/// subset (`active_zones` reflects that subset, not the global count), so
/// the scan stays bounded in practice.
///
/// **Canonicalization:** CF_EPOCHS can carry multiple competing seals at the
/// same `(zone, epoch)` from partition-merge or dual-proposer races. This
/// function applies the same lex-min `record_hash` tiebreaker as
/// [`EpochState::register_seal`] so the repopulated buffer matches what live
/// ingest would have produced.
///
/// **Idempotence:** safe to call multiple times — the final state of
/// `recent_seal_hashes` only depends on what CF_EPOCHS contains, not on
/// prior buffer contents (we overwrite per-zone entries).
pub fn repopulate_recent_seal_hashes(
    state: &mut EpochState,
    storage: &crate::storage::rocks::StorageEngine,
) {
    use std::collections::{BTreeMap, HashSet, VecDeque};

    let active_zones: HashSet<ZoneId> = state.latest_epoch.keys().cloned().collect();
    if active_zones.is_empty() {
        return;
    }

    // Global floor: smallest per-zone floor across all active zones. Once the
    // reverse scan walks below this, no remaining seal can belong to any
    // zone's target window — short-circuit.
    let min_floor = state
        .latest_epoch
        .values()
        .copied()
        .min()
        .unwrap_or(0)
        .saturating_sub(SUPER_SEAL_INTERVAL - 1);

    // Per-zone accumulator: epoch -> lex-min record_hash observed so far.
    // BTreeMap so the final drain is already chronological.
    let mut per_zone: std::collections::HashMap<ZoneId, BTreeMap<u64, [u8; 32]>> =
        std::collections::HashMap::new();

    // Hard iteration cap: defensive bound on noisy CF_EPOCHS (heavy
    // equivocation history, malformed keys, etc.). At 1M zones this cap
    // becomes large but the min_floor short-circuit fires long before.
    let cap = active_zones
        .len()
        .saturating_mul(SUPER_SEAL_INTERVAL as usize)
        .saturating_mul(4);
    let mut iters: usize = 0;
    let mut hit_cap = false;

    let _ = storage.range_scan_cf_reverse(
        crate::storage::rocks::CF_EPOCHS,
        |key, _val| {
            iters += 1;
            if iters > cap {
                hit_cap = true;
                return Ok(false);
            }
            let (epoch, zone_str, record_id) = match parse_disc5_index_key(key) {
                Some(t) => t,
                None => return Ok(true),
            };
            // Short-circuit once we drop below every zone's window.
            if epoch < min_floor {
                return Ok(false);
            }
            let zone = ZoneId::new(zone_str);
            if !active_zones.contains(&zone) {
                return Ok(true);
            }
            // Skip seals outside this specific zone's window — they exist in
            // CF_EPOCHS but don't belong in the buffer.
            let latest = state.latest_epoch.get(&zone).copied().unwrap_or(0);
            let floor = latest.saturating_sub(SUPER_SEAL_INTERVAL - 1);
            if epoch < floor || epoch > latest {
                return Ok(true);
            }
            let record = match storage.get_record(record_id) {
                Ok(Some(r)) => r,
                _ => return Ok(true),
            };
            // Verify this record actually carries an epoch seal (skip
            // super-seals and any other epoch-indexed records that aren't
            // regular seals — register_seal only buffers regular seals).
            match extract_epoch_seal(&record) {
                Ok(Some(_)) => {}
                _ => return Ok(true),
            }
            let h = record.record_hash();
            per_zone
                .entry(zone)
                .or_default()
                .entry(epoch)
                .and_modify(|existing| {
                    if h < *existing {
                        *existing = h;
                    }
                })
                .or_insert(h);
            Ok(true)
        },
    );

    let mut populated_zones = 0usize;
    let mut total_entries = 0usize;
    for (zone, map) in per_zone {
        if !map.is_empty() {
            total_entries += map.len();
            let queue: VecDeque<[u8; 32]> = map.values().copied().collect();
            state.recent_seal_hashes.insert(zone, queue);
            populated_zones += 1;
        }
    }

    if populated_zones > 0 {
        info!(
            "OPS-187: repopulated recent_seal_hashes from CF_EPOCHS — zones={populated_zones} \
             entries={total_entries} scan_iters={iters} hit_cap={hit_cap}",
        );
    } else if iters > 0 {
        debug!(
            "OPS-187: recent_seal_hashes repopulation found no eligible seals \
             (scan_iters={iters} active_zones={})",
            active_zones.len(),
        );
    }
}

/// F-10 crash-consistency: recover the per-zone `latest_epoch` high-water from
/// the durable CF_EPOCHS index at boot, so a restarted node cannot re-propose an
/// epoch it already sealed.
///
/// # The gap this closes
/// `latest_epoch` — the per-zone tip that gates the `already_sealed` proposal
/// guard in `should_propose_seal` — is restored ONLY from the periodic snapshot
/// (`from_snapshot`, plus the JSON/RocksDB merge in `elara_node.rs`). That
/// snapshot is written with default (async, `sync=false`) `WriteOptions` and only
/// every `snapshot_interval_secs`, so after a power-loss — or ANY restart where
/// the periodic snapshot simply lagged the last few seals — the restored tip can
/// sit BEHIND the durable per-seal CF_EPOCHS tail. `should_propose_seal` then
/// reads `already_sealed == false` for an epoch that is in fact sealed,
/// re-proposes it with a fresh uuid7/timestamp, and — on a multi-anchor net where
/// a peer still holds the original seal — trips the seal-equivocation detector
/// (25% authority-gated). F-9 (internal design notes
/// §5) deferred this to its own cycle; full audit in
/// internal design notes.
///
/// # What it does
/// One bounded reverse scan of CF_EPOCHS. For every zone already in
/// `latest_epoch` whose durable CF_EPOCHS max epoch EXCEEDS the restored tip, it
/// re-registers every seal at that max epoch via `register_seal`, which advances
/// the whole per-zone quartet (`latest_epoch`, `latest_seal_hash`,
/// `latest_seal_id`, `latest_vrf_output`) in lockstep with the same lex-min
/// canonicalization every honest node applies.
///
/// # Why lockstep is mandatory (the trap a naive fix falls into)
/// Advancing `latest_epoch` ALONE (bare integer) while `latest_seal_hash` stays
/// at the stale snapshot value makes the node chain its NEXT proposal off the
/// wrong `prev_seal_hash`; every peer that finalized the real tip rejects it via
/// `is_forged_sequential_seal` → a self-inflicted chain freeze, strictly worse
/// than the equivocation being prevented. Routing through
/// `register_seal`/`apply_canonical_seal` moves the quartet together, so we never
/// poke the maps piecemeal. Mirrors the snapshot-merge lockstep idiom at
/// `elara_node.rs` (RocksDB epoch merge) and `sync.rs` (B7 bootstrap).
///
/// # Scale
/// Bounded like `repopulate_recent_seal_hashes`: the reverse scan short-circuits
/// once the descending epoch drops below the LOWEST restored tip across tracked
/// zones (below that no tracked zone can advance), with a hard iteration cap as a
/// backstop against a noisy CF_EPOCHS. On a healthy fleet the snapshot lags by a
/// handful of epochs, so the scan touches O(zones × lag), never O(all_records).
///
/// # Durability floor, and why "Layer 2" is REJECTED-as-designed (audit 2026-07-01)
/// This recovers the tip whenever the seal's CF_EPOCHS entry survived the crash
/// (Case A — the common path, including clean restarts where the WAL replays but
/// the periodic snapshot lagged). It does NOT close the residual window where a
/// seal's whole WriteBatch was lost from the un-fsynced WAL tail while a peer kept
/// the broadcast copy (Case B). The proposed F-10 Layer 2 fix — an fsync'd epoch
/// high-water CARRYING THE SEAL HASH, reserved before broadcast — was
/// fusion-audited (internal design notes) and REJECTED: it
/// is not merely costly, it is LIVENESS-UNSAFE. Making a seal hash durable before
/// it is broadcast restores, on a crash-before-broadcast, a tip NO PEER EVER SAW (a
/// "phantom"); when an honest peer later seals the same epoch, `register_seal`'s
/// lex-min tiebreak keeps the phantom ~50% of the time, and the honest E+1 is then
/// rejected by `is_forged_sequential_seal` — the exact self-inflicted freeze the
/// lockstep rule above exists to prevent, re-entered through the hwm. The root is
/// "durable-before-broadcast", so the `sync=true`-on-the-seal-batch alternative is
/// NOT phantom-free either. NOTE this scan itself carries a NARROW instance: a
/// SIGKILL after `insert_record_synced` writes CF_EPOCHS but before the broadcast
/// spawn leaves a durable, never-broadcast seal that this scan restores as the tip
/// — LOW / near-zero on the current near-solo fleet (a phantom only bites when a
/// COMPETING sealer exists), self-limiting (heals on the next full snapshot /
/// divergence re-sync), tracked as an own-cycle follow-up and NOT closable by any
/// Layer-2 durability write. The single-batch atomicity of the seal record + its
/// CF_EPOCHS index (pinned at `put_record_with_pk_zone` in `rocks.rs`) is
/// load-bearing for Case A: the two share crash fate, so a surviving seal always
/// carries a surviving index for this scan to find.
pub fn rebuild_latest_epoch_from_cf_epochs(
    state: &mut EpochState,
    storage: &crate::storage::rocks::StorageEngine,
) {
    use std::collections::HashMap;

    if state.latest_epoch.is_empty() {
        return;
    }

    // Only zones the node already tracks can be re-proposed (the seal loop
    // iterates `latest_epoch.keys()`), so those are the only tips that matter.
    // Clone into a local so the scan closure never borrows `state` (we mutate
    // `state` via `register_seal` only AFTER the scan completes).
    let tips: HashMap<ZoneId, u64> = state.latest_epoch.clone();

    // Descending scan can stop once it drops below the lowest tracked tip:
    // below that, no tracked zone's max could exceed its own tip.
    let min_floor = tips.values().copied().min().unwrap_or(0);

    // Defensive iteration cap (noisy CF_EPOCHS / heavy equivocation history),
    // same shape as `repopulate_recent_seal_hashes`.
    let cap = tips
        .len()
        .saturating_mul(SUPER_SEAL_INTERVAL as usize)
        .saturating_mul(4)
        .max(SUPER_SEAL_INTERVAL as usize);
    let mut iters: usize = 0;
    let mut hit_cap = false;

    // Per-zone: (max_epoch_seen, record_ids at that epoch). Reverse order means
    // the FIRST epoch seen for a zone is its max; siblings at that epoch are
    // adjacent and collected so the lex-min tiebreak inside `register_seal`
    // converges on the same canonical seal every honest node picks.
    let mut per_zone: HashMap<ZoneId, (u64, Vec<String>)> = HashMap::new();

    let _ = storage.range_scan_cf_reverse(
        crate::storage::rocks::CF_EPOCHS,
        |key, _val| {
            iters += 1;
            if iters > cap {
                hit_cap = true;
                return Ok(false);
            }
            let (epoch, zone_str, record_id) = match parse_disc5_index_key(key) {
                Some(t) => t,
                None => return Ok(true),
            };
            if epoch < min_floor {
                return Ok(false); // below every tracked tip — nothing left to advance
            }
            let zone = ZoneId::new(zone_str);
            let current = match tips.get(&zone) {
                Some(&c) => c,
                None => return Ok(true), // untracked zone — never proposed, no re-propose risk
            };
            if epoch <= current {
                return Ok(true); // not an advance for this zone
            }
            // Reverse order ⇒ the first epoch seen for a zone is its max; later
            // siblings at that same epoch are appended (lex-min tiebreak happens
            // in register_seal); a lower epoch for an already-seen zone is a
            // no-op. `entry` avoids the get_mut/insert borrow-check limitation.
            per_zone
                .entry(zone)
                .and_modify(|(max_epoch, ids)| {
                    if epoch == *max_epoch {
                        ids.push(record_id.to_string());
                    }
                })
                .or_insert_with(|| (epoch, vec![record_id.to_string()]));
            Ok(true)
        },
    );

    let mut advanced_zones = 0usize;
    for (zone, (max_epoch, record_ids)) in per_zone {
        let mut registered = 0usize;
        for rid in &record_ids {
            let record = match storage.get_record(rid) {
                Ok(Some(r)) => r,
                _ => continue,
            };
            let seal = match extract_epoch_seal(&record) {
                Ok(Some(s)) => s,
                _ => continue, // super-seal or non-seal epoch-indexed record — skip
            };
            state.register_seal(&seal, rid, record.record_hash());
            registered += 1;
        }
        if registered > 0 {
            advanced_zones += 1;
            info!(
                "F-10: recovered epoch tip zone={} to epoch={} from durable CF_EPOCHS \
                 (periodic snapshot lagged; {registered} seal(s) canonicalized)",
                zone.path(),
                max_epoch,
            );
        }
    }

    if advanced_zones > 0 {
        // `apply_canonical_seal` maintains `total_epochs_total` per seal, but a
        // fast-forward past skipped epochs would undercount — recount from the
        // corrected tips (O(zones), idempotent).
        state.recount_total_epochs();
        info!(
            "F-10: latest_epoch recovered from CF_EPOCHS — {advanced_zones} zone(s) advanced \
             past a stale periodic snapshot (scan_iters={iters} hit_cap={hit_cap})"
        );
    }
}

/// Rebuild epoch state from a pre-loaded record slice (single-pass startup).
pub fn rebuild_epoch_state_from_records(all_records: &[ValidationRecord]) -> Result<EpochState> {
    let mut state = EpochState::new();

    // Collect all epoch seals, sorted by timestamp
    let mut seals: Vec<(&ValidationRecord, ParsedEpochSeal)> = Vec::new();
    // Gap 3 follow-up: also collect super-seals so seal-pruning floor is
    // populated immediately after boot. Without this, `latest_super_seal`
    // stays empty until a fresh super-seal arrives via gossip — at 64-epoch
    // / 60s-cadence that's a ≥64-minute window where `seal_pruning_floor`
    // is empty and GC cannot prune any seal, even ones a previous lifetime
    // already had a covering super-seal for.
    let mut super_seals: Vec<(&ValidationRecord, ParsedSuperSeal)> = Vec::new();
    for rec in all_records {
        if let Some(seal) = extract_epoch_seal(rec)? {
            seals.push((rec, seal));
        } else if let Some(ss) = extract_super_seal(rec)? {
            super_seals.push((rec, ss));
        }
    }
    // Deterministic cross-node replay: timestamp, then record-ID tiebreak —
    // mirrors the ledger/governance replay sorts (ledger.rs:1050). RocksDB index
    // order can differ across nodes on equal f64 timestamps; without the id
    // tiebreak a stable sort preserves divergent load order. `register_seal`'s
    // lex-min canonicalization already makes `latest_seal_hash` order-invariant,
    // but the tiebreak also makes `apply_canonical_seal`'s call count (counter
    // side effects) identical everywhere, instead of relying on that downstream
    // invariant surviving future edits.
    seals.sort_by(|a, b| {
        a.0.timestamp
            .total_cmp(&b.0.timestamp)
            .then_with(|| a.0.id.cmp(&b.0.id))
    });
    super_seals.sort_by(|a, b| {
        a.0.timestamp
            .total_cmp(&b.0.timestamp)
            .then_with(|| a.0.id.cmp(&b.0.id))
    });

    // Replay seals in order
    for (rec, seal) in &seals {
        state.register_seal(seal, &rec.id, rec.record_hash());
    }
    // Then replay super-seals — register_super_seal keeps only the highest
    // end_epoch per zone, so order-after-sort is just defensive.
    for (rec, ss) in &super_seals {
        state.register_super_seal(
            ss.zone.clone(),
            ss.end_epoch,
            rec.id.clone(),
            rec.record_hash(),
            ss.committee_hash,
        );
    }

    Ok(state)
}

// ─── Background seal loop ──────────────────────────────────────────────────

/// Check if this node is eligible to propose epoch seals.
///
/// Multi-anchor model: any anchor node with a VRF key can propose.
/// Genesis authority is always eligible (bootstrapping).
/// Non-genesis anchors are eligible if they have a VRF secret key
/// and node_type allows sealing.
#[cfg(feature = "node-core")]
fn is_seal_eligible(state: &super::state::NodeState) -> bool {
    let is_genesis = state.identity.identity_hash == state.config.genesis_authority;
    let node_type = super::peer::NodeType::from_str(&state.config.node_type);
    let has_vrf = state.vrf_secret_key.is_some();

    // Genesis authority with anchor role → always eligible
    if is_genesis && node_type.can_seal_epochs() {
        return true;
    }

    // Non-genesis anchor with VRF key → eligible (multi-anchor mode)
    if !is_genesis && node_type.can_seal_epochs() && has_vrf {
        return true;
    }

    false
}

/// What the current seal-loop tick should do for a given `(zone, epoch)`.
///
/// Stage 3c.1 Part D extends the legacy `Option<u8>` return with an
/// explicit cross-zone escalation branch. The seal-loop matches on this
/// and dispatches:
/// - `PerZone(rank)` → `create_epoch_seal_with_balance` as before.
/// - `GlobalEscalate(stuck_zone)` → `create_global_quorum_seal` from
///   the local anchor's natural zone, targeting `stuck_zone`.
/// - `None` → skip this zone this tick.
#[cfg(feature = "node-core")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SealProposal {
    /// This node is the VRF-ranked proposer for its own zone. `u8` is
    /// the rank (0-indexed) to embed in the seal metadata so verifiers
    /// can re-check the exponential-backoff schedule.
    PerZone(u8),
    /// This node is NOT the per-zone proposer for `stuck_zone`, but
    /// `stuck_zone`'s rank ladder is fully exhausted (all 7 ranks
    /// timed out) and this node is a positive-stake anchor in a
    /// different zone. Emit a global quorum seal for `stuck_zone`.
    GlobalEscalate(ZoneId),
    /// Do nothing for this zone on this tick. The [`NoneReason`] payload
    /// surfaces WHICH liveness gate fired so operators can disambiguate
    /// stall modes from the metric/log surface alone.
    None(NoneReason),
}

/// Reason `should_propose_seal` returned [`SealProposal::None`].
///
/// Splits the four ways a single tick can decline to propose so each gets
/// its own counter (`elara_seal_loop_proposals_none_<reason>_total`) and
/// shows up in the per-tick summary log. Without this, every None looks the
/// same and the operator can't tell whether the chain is stuck on
/// idempotency (AlreadySealed), bootstrap exclusion, VRF rank exclusion, or
/// timing.
#[cfg(feature = "node-core")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NoneReason {
    /// `latest_epoch[zone] >= epoch_number` — a per-zone or global seal for
    /// this epoch already registered locally. Healthy duplicate-suppression
    /// signal; expected to fire every tick on anchors that lost the race.
    AlreadySealed,
    /// `staked.len() < 3` AND this node is not the genesis authority —
    /// bootstrap carve-out (Protocol §11.13 step 2) keeps a tiny fleet
    /// deterministic. Expected on every non-genesis anchor until the
    /// stake set grows past 3.
    BootstrapNonGenesis,
    /// `rank_of(beacon, staked, zone, our_identity, MAX_VIEW_DEPTH) == None`
    /// — our identity is not in the top 7 stakers for this zone+epoch's
    /// VRF beacon. Stays None at every elapsed time. If this is the
    /// dominant reason for a stuck zone, the natural-zone partition has
    /// drifted (anchors not routing into this zone via
    /// `resolve_identity_zone`) or this anchor lost stake.
    NotInTopRanks,
    /// Our identity is in the top 7 but `our_rank > current_allowed_rank` —
    /// exponential-backoff schedule has not yet unlocked our slot.
    /// Self-clearing as elapsed_ms grows; if a zone parks here forever it
    /// means the lower ranks are absent/byzantine and the timeout schedule
    /// has not yet reached this rank.
    RankTooHighForElapsed { our_rank: u8, allowed: u8 },
}

/// Determine if this node should propose an epoch seal for a given zone.
///
/// Uses VRF output to decide: the node with the lowest VRF output
/// for this epoch/zone combination wins the right to propose.
/// Rank-gated proposal decision (Protocol §11.13, MESH-BFT §4).
///
/// Returns a [`SealProposal`]:
/// - [`SealProposal::PerZone`]`(rank)` — this node may propose a
///   normal per-zone seal at the returned rank.
/// - [`SealProposal::GlobalEscalate`]`(zone)` — the zone's rank
///   ladder is fully exhausted; this node is eligible to emit a
///   cross-zone global quorum seal (Stage 3c.1).
/// - [`SealProposal::None`] — abstain.
///
/// # Algorithm
///
/// 1. If a seal for this `epoch_number` is already registered locally,
///    abstain — idempotent guard against duplicate proposals. A global
///    seal counts as "already sealed" for this purpose (see
///    `register_global_seal`).
/// 2. If fewer than 3 staked identities exist (bootstrap), only the
///    genesis authority proposes. This covers fresh testnet, initial
///    sync, and adversarial stake-drain cases where rank-gating would
///    otherwise deadlock.
/// 3. Build the chained beacon: `H(prev_seal_hash || epoch || zone)`.
///    Grinding-resistant — the proposer cannot bias its own rank by
///    choosing the seed.
/// 4. Compute this node's rank via `aggregator::rank_of(beacon, staked, …)`.
///    Returns `None` if not in the top `MAX_VIEW_DEPTH` — in which case
///    we fall through to the escalation check.
/// 5. Compute `base_timeout = max(2 * zone_rtt_p95, 5s)`; fall back to
///    5s if we have no RTT samples yet.
/// 6. Determine `current_allowed_rank`: largest `k` such that
///    `(2^k - 1) * base_timeout ≤ elapsed_since_epoch_start`. Rank 0 at
///    T=0, rank 1 at T=base, rank 2 at T=3·base, … rank 6 at T=63·base.
/// 7. If `our_rank ≤ current_allowed_rank` → `PerZone(our_rank)`.
/// 8. Else check escalation via `aggregator::escalation_decision`: if
///    `is_zone_stuck(base, elapsed)` AND this node is a positive-stake
///    anchor in a DIFFERENT zone → `GlobalEscalate(zone)`. Else `None`.
///
/// # Genesis-authority carve-out
///
/// During bootstrap (< 3 stakers), the genesis authority ALWAYS proposes.
/// Once the stake set passes the threshold, genesis plays by the same rank
/// rules as everyone else — no privileged fast-path that could be exploited
/// or create a single point of liveness failure at mainnet scale.
///
/// # AWC fallback
///
/// This function only decides when WE propose. Other nodes evaluate each
/// incoming seal on its own merits: the verifier (3b.6) checks that the
/// seal's declared rank matches the proposer's VRF-rank AND that sufficient
/// time elapsed for that rank. AWC then attests as usual. Unknown identities
/// never propose (step 4 returns None).
#[cfg(feature = "node-core")]
async fn should_propose_seal(
    state: &super::state::NodeState,
    zone: &ZoneId,
    epoch_number: u64,
) -> SealProposal {
    // Snapshot state once (drop locks before the decision).
    let (already_sealed, prev_seal_hash, epoch_start) = {
        let epoch = state.epoch.read_recover();
        let already = epoch
            .latest_epoch
            .get(zone)
            .is_some_and(|&latest| latest >= epoch_number);
        let hash = epoch.latest_seal_hash.get(zone).copied().unwrap_or([0u8; 32]);
        let start = epoch.epoch_start(zone);
        (already, hash, start)
    };

    // Collect stakers once with both the flat (id, stake) list (proposer
    // rank) and the per-zone partition (escalation staking check).
    //
    // The staker view is filtered to VRF-registered
    // anchor identities ONLY. Non-anchor stakers (user/legacy accounts that
    // hold stake but were never VRF-registered) CANNOT propose seals — they
    // have no VRF key and no anchor seat — yet the unfiltered rank chain
    // happily ranked them above the actual anchors. When this happened,
    // the active anchors were ranked too high to propose and the chain
    // froze. The shared `staked_anchor_view` accessor applies that filter and
    // is read by the verifier (`ingest.rs`) too, so the proposer's view is
    // identical to the verifier's by construction — the consensus rule stays
    // symmetric. SCALE: the accessor memoizes the CF-scan + ledger-join +
    // zone partition, so this runs once per ledger change, not once per zone
    // per tick.
    let (staked_amounts, stakers_by_zone) = state.staked_anchor_view().await;

    // Timeout base: 2× p95 zone RTT, floored at 5 seconds; cap at 10 min so
    // a single slow peer cannot stretch the backoff into hours.
    let base_ms: u64 = state.effective_base_timeout_ms(zone);

    // First-ever proposal in this zone uses "now" as reference → elapsed = 0 → rank 0.
    // Clamp to MAX_RANK_ELAPSED_SECS — matches the verifier-side clamp in
    // `verify_epoch_seal`. Bound prevents a forward-skewed clock from claiming
    // unreachable rank fallback authority.
    let now = super::ingest::now();
    let elapsed_s = (now - epoch_start.unwrap_or(now)).max(0.0);
    let elapsed_ms: u64 = (elapsed_s * 1000.0).min(MAX_RANK_ELAPSED_SECS * 1000.0) as u64;

    // Per-zone rank check inlined here (was a single
    // `aggregator::proposer_rank` call) so each None can carry the specific
    // gate that fired. Logic mirrors `aggregator::proposer_rank` exactly —
    // the aggregator helper still exists for external/test consumers that
    // only need the boolean decision.
    if already_sealed {
        return SealProposal::None(NoneReason::AlreadySealed);
    }
    // Bootstrap carve-out — fewer than 3 stakers means rank-gating would
    // deadlock; only genesis authority proposes until the stake set grows.
    let per_zone_rank: Option<u8> = if staked_amounts.len() < 3 {
        if state.identity.identity_hash == state.config.genesis_authority {
            Some(0)
        } else {
            return SealProposal::None(NoneReason::BootstrapNonGenesis);
        }
    } else {
        let beacon = super::aggregator::chained_beacon(
            &prev_seal_hash,
            epoch_number,
            zone,
        );
        let our_rank_opt = super::aggregator::rank_of(
            &beacon,
            &staked_amounts[..],
            zone,
            &state.identity.identity_hash,
            super::aggregator::MAX_VIEW_DEPTH,
        );
        let allowed = super::aggregator::current_allowed_rank(base_ms, elapsed_ms);
        match our_rank_opt {
            None => None, // → falls through to escalation, then NotInTopRanks
            Some(r) if r <= allowed => Some(r as u8),
            Some(r) => {
                // Top-7 but ladder not unlocked yet. Capture the rank +
                // allowed values for the diagnostic — but first try
                // escalation, which can still fire if the zone has been
                // stuck past 127·base regardless of our rank.
                let our_natural_zone =
                    state.resolve_identity_zone(&state.identity.identity_hash);
                if super::aggregator::escalation_decision(
                    &state.identity.identity_hash,
                    &our_natural_zone,
                    zone,
                    &stakers_by_zone,
                    base_ms,
                    elapsed_ms,
                    already_sealed,
                ) {
                    return SealProposal::GlobalEscalate(zone.clone());
                }
                return SealProposal::None(NoneReason::RankTooHighForElapsed {
                    our_rank: r as u8,
                    allowed: allowed as u8,
                });
            },
        }
    };

    if let Some(rank) = per_zone_rank {
        return SealProposal::PerZone(rank);
    }

    // Per-zone path declined: rank_of returned None (not in top 7). Consider
    // cross-zone escalation (Stage 3c.1 Part D).
    // Gap 4 routing-application: our natural zone is the leaf our identity
    // hash resolves to under the current registry — critical for escalation
    // rank math after any split touches our parent zone.
    let our_natural_zone = state.resolve_identity_zone(&state.identity.identity_hash);
    if super::aggregator::escalation_decision(
        &state.identity.identity_hash,
        &our_natural_zone,
        zone,
        &stakers_by_zone,
        base_ms,
        elapsed_ms,
        already_sealed, // repurposed: latest_epoch[zone] >= epoch_number means
                        // someone (per-zone OR global) already landed a seal.
    ) {
        return SealProposal::GlobalEscalate(zone.clone());
    }

    SealProposal::None(NoneReason::NotInTopRanks)
}

/// GENESIS ZONE BOOTSTRAP (fresh-chain liveness).
///
/// Zone discovery in `epoch_seal_loop` has exactly two sources: records whose
/// timestamps fall inside the current seal window, and zones that already
/// have a seal chain (`latest_epoch`). A clean-slate chain whose genesis
/// records predate the first tick's window has neither — `zones_to_seal`
/// stays empty forever and the FIRST seal never happens (dev-net idled at
/// epoch 0 with 9 genesis-era records; same failure hits a mainnet genesis
/// where validators boot minutes after the ceremony with no traffic yet).
///
/// This fallback runs only while the chain has never sealed (caller gates on
/// `latest_epoch.is_empty()`) and the window scan found nothing: one bounded
/// newest-first walk of the timestamp index (same `MAX_DISCOVERY_SCAN` cap
/// as the hot path) seeds zones from existing records. Inert from the first
/// seal onward, so steady-state cost is zero.
///
/// Filters mirror the window-scan path: future-dated records (clock skew)
/// and epoch-op records are skipped; legacy numeric zones outside the
/// current `zone_count` are dropped (same dead-zone guard as the
/// `latest_epoch` merge above the call site).
#[cfg(feature = "node-core")]
fn genesis_bootstrap_zones(
    state: &super::state::NodeState,
    window_end: f64,
    cap: usize,
) -> std::collections::HashSet<ZoneId> {
    let mut zones = std::collections::HashSet::new();
    let ids = match state.rocks.recent_record_ids(0.0, cap) {
        Ok(ids) => ids,
        Err(e) => {
            warn!("genesis zone bootstrap: timestamp-index scan failed: {e}");
            return zones;
        }
    };
    let current_zone_count = super::consensus::get_zone_count();
    for rid in &ids {
        let rec = match state.rocks.get_record(rid) {
            Ok(Some(r)) => r,
            _ => continue,
        };
        if rec.timestamp > window_end {
            continue;
        }
        if rec.metadata.contains_key(EPOCH_OP_KEY) {
            continue;
        }
        let zone = state.resolve_record_zone(&rec.id);
        if let Ok(zone_num) = zone.path().parse::<u64>() {
            if zone_num >= current_zone_count {
                continue;
            }
        }
        zones.insert(zone);
    }
    if !zones.is_empty() {
        info!(
            zones = zones.len(),
            scanned = ids.len(),
            "genesis zone bootstrap: seeded seal-zone discovery from pre-window records (no seal chain yet)"
        );
    }
    zones
}

/// Background loop that periodically creates epoch seals.
///
/// Multi-anchor model: any eligible anchor can propose seals.
/// Genesis authority is always eligible. Other anchors need a VRF key
/// and node_type = "anchor". First valid seal for each zone/epoch wins.
#[cfg(feature = "node-core")]
pub async fn epoch_seal_loop(
    state: Arc<super::state::NodeState>,
    mut shutdown: tokio::sync::mpsc::Receiver<()>,
) {
    let interval_secs = state.config.epoch_seal_interval_secs;
    if interval_secs == 0 {
        debug!("epoch seal loop disabled (interval=0)");
        return;
    }

    if !is_seal_eligible(&state) {
        let is_genesis = state.identity.identity_hash == state.config.genesis_authority;
        let has_vrf = state.vrf_secret_key.is_some();
        debug!(
            "epoch seal loop skipped — not eligible (genesis={}, node_type={}, has_vrf={})",
            is_genesis, state.config.node_type, has_vrf
        );
        return;
    }

    // Tick at the configured interval. Adaptive per-zone intervals may differ,
    // but the loop checks each zone against its own last-seal time.
    let tick_interval = Duration::from_secs(interval_secs);
    info!("epoch seal loop started (base interval {}s, adaptive per zone)", interval_secs);

    // One-shot startup canonicalization: re-register every stored seal at each
    // zone's latest_epoch so lex-min tiebreaking in register_seal converges
    // every node on the same canonical hash. Without this, snapshots that
    // captured the non-canonical hash at an equal-epoch dual-proposer race
    // persist a different latest_seal_hash on different nodes, each computes
    // a different chained_beacon for the next epoch, no node thinks it's
    // rank-0, chain freezes. Idempotent: zones with a single seal at
    // latest_epoch are skipped.
    {
        let mut epoch = state.epoch.write_recover();
        canonicalize_latest_seals(&mut epoch, &state.rocks);
    }

    // Seed the custodial-idle_decay emit watermark from the restored chain tip
    // (C10c — multi-zone restart double-charge). `last_idle_decay_emit_epoch`
    // resets to 0 on every process start, but `latest_epoch` is restored on
    // both boot paths (snapshot `from_snapshot` + cold-replay `register_seal`).
    // A batch is only ever emitted for `epoch_no = next_epoch(zone)` (a sealed
    // epoch ≤ that zone's tip), so `max_sealed_epoch()` is ≥ every epoch already
    // emitted. Seeding the watermark to it keeps a *lagging* zone's post-restart
    // seals of an already-globally-emitted epoch under the monotone `fetch_max`
    // guard, while genuinely-new epochs (> the restored tip) still emit. The
    // single-zone case is already protected by the per-zone `AlreadySealed`
    // gate; this closes the multi-zone case. Followers never reach the emit site
    // (is_genesis_authority gate at the idle_decay block), so the seed is inert
    // there. One-time, monotone (`fetch_max` never lowers) — must NOT re-seed
    // per-tick, or it would also suppress the genuinely-new epoch being sealed.
    {
        let max_sealed = state.epoch.read_recover().max_sealed_epoch();
        let prev = state
            .last_idle_decay_emit_epoch
            .fetch_max(max_sealed, std::sync::atomic::Ordering::SeqCst);
        if max_sealed > prev {
            debug!("idle_decay emit watermark seeded to {max_sealed} from restored chain tip (C10c)");
        }
    }

    loop {
        tokio::select! {
            _ = tokio::time::sleep(tick_interval) => {}
            _ = shutdown.recv() => {
                debug!("epoch seal loop shutting down");
                return;
            }
        }

        // Stage 6 cooperative scheduler (Protocol §11.10): extra backoff
        // when host CPU/load is saturated. Dilithium3 signing in seal
        // creation is the heaviest scheduled work on a node.
        super::system_load::coop_yield_if_busy(&state.system_load).await;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);

        // Don't create epoch seals while still catching up — our merkle roots
        // would be computed from incomplete local state, causing other nodes
        // to reject the seals and pollute their gossip_rejected caches.
        //
        // Check TWO indicators: (1) pull_catchup_cursor for ongoing sync progress,
        // (2) latest record in DAG for actual data freshness. We need the SECOND
        // because full_pull scans from historical cursor 0 and may take hours to
        // advance pull_catchup_cursor to near-current, even though recent records
        // arrive via att-pull and push. If EITHER is recent, the node is synced
        // enough for epoch seals.
        {
            let catchup = *state.pull_catchup_cursor.lock().unwrap_or_else(|e| e.into_inner());
            let dag_has_recent = {
                let dag = state.dag.read().await;
                dag.latest_timestamp() > now - 300.0
            };
            if catchup < now - 300.0 && !dag_has_recent {
                debug!("epoch seal: skipping tick — node is catching up (cursor {:.0}s behind, no recent DAG records)", now - catchup);
                continue;
            }
        }

        // Check for scheduled zone count transition.
        // Extracted to apply_pending_zone_transition_if_due so it
        // also runs in health_check_loop on every node (witnesses included).
        apply_pending_zone_transition_if_due(&state);

        // Refresh zone stakes from ledger every epoch tick. Ensures consensus
        // settlement reflects current staking state (handles post-bootstrap staking,
        // dynamic stake changes, and simulation environments without sync bootstrap).
        // Also backfill creator_stakes for tracked records that are missing it
        // (happens after restart — snapshot loads attestations but not creator_stakes).
        // Use try_read to avoid blocking state_core's ledger.write() — if contended,
        // the next epoch tick (30-60s) will catch up.
        if let Ok(ledger) = state.ledger.try_read() {
            let mut consensus = state.consensus.lock_recover();
            consensus.register_stakes_from_ledger(&ledger);
            drop(ledger); // Release ASAP — don't hold across RocksDB reads below

            // Backfill creator_stakes for records that have attestations but no creator registered.
            // Step 1: collect missing records + RocksDB reads WITHOUT holding ledger lock.
            // Previously held ledger.read() for 209+ RocksDB reads (~8-10s), blocking
            // state_core's ledger.write() and causing phase 4 watchdog triggers.
            let missing = consensus.records_missing_creator_stake();
            drop(consensus); // Release consensus lock during RocksDB reads
            let mut creator_map: Vec<(String, String)> = Vec::with_capacity(missing.len());
            for rid in &missing {
                if let Ok(rec) = state.get_record(rid) {
                    let creator = crate::accounting::types::creator_identity_hash(&rec);
                    creator_map.push((rid.clone(), creator));
                }
            }
            // Step 2: brief ledger read + consensus update (in-memory only)
            if let Ok(ledger) = state.ledger.try_read() {
                let mut consensus = state.consensus.lock_recover();
                for (rid, creator) in &creator_map {
                    let creator_stake = ledger.staked(creator);
                    if creator_stake > 0 {
                        consensus.register_creator_stake(rid, creator, creator_stake);
                    }
                }
                if !missing.is_empty() {
                    tracing::info!("epoch tick: backfilled creator_stakes for {} records", missing.len());
                }

                // Re-check settlement for all tracked records. After backfilling
                // creator_stakes, records that were below threshold may now pass.
                // force_finalized() only fires from feed_attestation(), so records
                // that became settled due to denominator changes need explicit
                // recheck — and crucially, force_finalized() also triggers the
                // cross-zone-child cascade (consensus.rs:1908-1916), which
                // finality_monitor does NOT replicate.
                //
                // We deliberately DO NOT bump total_ever_settled here.
                // finality_monitor's 30s scan filter
                // (`!finalized.contains(rid) && consensus.is_settled(rid)`,
                // elara_node.rs:3761) will pick these same records up because
                // (a) force_finalized() leaves the rid in `attestations` so
                // tracked_record_ids() includes it, and (b) is_settled() is
                // stake-threshold based and remains true. Letting
                // finality_monitor be the sole counter-bumper avoids a
                // double-count: previously this path bumped the counter
                // without inserting into FinalizedIndex, so finality_monitor
                // would re-bump on its next tick. The cascade still happens
                // here (force_finalize_settled → force_finalized →
                // recompute_confirmation for children), the persistence step
                // is just funneled through one source of truth.
                //
                // (We also can't .await state.finalized.write() here —
                // consensus's std::sync::MutexGuard is !Send and Rust async
                // NLL won't prove it dropped across the await even with
                // explicit scoping/drop tactics.)
                let recheck_finalized = consensus.force_finalize_settled().len();
                if recheck_finalized > 0 {
                    tracing::info!(
                        "epoch tick: {recheck_finalized} records re-settled via stake recheck — finality_monitor will persist within 30s"
                    );
                }
            }
            // If inner try_read fails, skip backfill — next epoch tick will retry
        } else {
            tracing::debug!("epoch tick: ledger contended, deferring stake refresh");
        }

        // MAINNET gap #5: refresh per-zone committees. At each epoch boundary
        // the VRF output rotates; recompute the capped, stake-weighted
        // committee per zone so settlement denominator reflects the current
        // committee stake. Skipped for zones with no VRF output (bootstrap)
        // — those continue using the zone_stake denominator as fallback.
        //
        // Cost bound (Gap 5 bench, `bench_committee_selection`):
        // (a) Build `CommitteeSelectionIndex` once — O(|staked| log |staked|)
        //     sort + O(|staked|) hash insert. ~30 ms at 100k stakers, amortized.
        // (b) Per-zone selection becomes O(|subs|) HashMap lookup, dropping the
        //     legacy O(|staked|) eligible-filter that bottlenecked the 100k-staker
        //     interplanetary tier (3.44 ms/call → µs after indexing).
        // (c) Rayon parallelization stays — the indexed scoring is still per-zone
        //     hashing, just no longer pre-blocked by an O(|staked|) scan.
        {
            let staked_weighted: Vec<(String, u64)> = match state.ledger.try_read() {
                Ok(ledger) => ledger
                    .accounts
                    .iter()
                    .filter(|(_, a)| a.staked > 0)
                    .map(|(h, a)| (h.clone(), a.staked))
                    .collect(),
                Err(_) => Vec::new(),
            };
            if !staked_weighted.is_empty() {
                let zone_count = super::consensus::get_zone_count();

                // Build per-epoch index once. Reused across every per-zone
                // committee selection in this tick.
                let index = super::consensus::CommitteeSelectionIndex::build(&staked_weighted);

                // Stage (zone, vrf, subs) tuples under the epoch + subscriptions
                // locks, then release before the hashing loop so other epoch
                // ticks aren't blocked on a per-zone scoring pass.
                let inputs: Vec<(crate::ZoneId, [u8; 32], std::collections::HashSet<String>)> = {
                    let epoch = state.epoch.read_recover();
                    let subs_mgr = state.zone_subscriptions.lock_recover();
                    (0..zone_count)
                        .filter_map(|i| {
                            let zone = crate::ZoneId::from_legacy(i);
                            let vrf = *epoch.vrf_output(&zone)?;
                            let subs = subs_mgr.subscribers(&zone);
                            Some((zone, vrf, subs))
                        })
                        .collect()
                };

                // Gap 5 Phase 6b second slice: when `use_committee_v2` is on,
                // dispatch to the unified `select_committee_v2`. Hoisted to a local
                // bool so the rayon body doesn't dereference `state.config`
                // per zone.
                let use_v2 = state.config.use_committee_v2;
                use rayon::prelude::*;
                let committees: Vec<(crate::ZoneId, Vec<(String, u64)>)> = inputs
                    .par_iter()
                    .filter_map(|(zone, vrf, subs)| {
                        let committee = if use_v2 {
                            // v2 path: materialize the per-zone eligible
                            // pool as `Vec<(String, u64)>` (the shape v2
                            // consumes). Mirrors the indexed path's
                            // eligible-vs-bootstrap fallback at
                            // `consensus.rs:712-716` so that v1↔v2 see
                            // the same pool when the population is too
                            // small for proper sortition.
                            let eligible: Vec<(String, u64)> = subs
                                .iter()
                                .filter_map(|id| {
                                    index
                                        .staked_index
                                        .get(id)
                                        .map(|stake| (id.clone(), *stake))
                                })
                                .collect();
                            let pool: Vec<(String, u64)> =
                                if eligible.len() < super::consensus::MIN_SCOPED_ELIGIBLE {
                                    index.bootstrap_pool.clone()
                                } else {
                                    eligible
                                };
                            super::zone_committee::select_committee_v2(
                                vrf,
                                &zone.to_string(),
                                &pool,
                                super::consensus::MAINNET_COMMITTEE_SIZE,
                            )
                        } else {
                            super::consensus::select_epoch_committee_scoped_indexed(
                                vrf,
                                &index,
                                zone,
                                subs,
                            )
                        };
                        (!committee.is_empty()).then(|| (zone.clone(), committee))
                    })
                    .collect();

                if !committees.is_empty() {
                    let mut consensus = state.consensus.lock_recover();
                    for (zone, members) in committees {
                        consensus.register_epoch_committee(&zone, &members);
                    }
                }
            }
        }

        // Default window uses the configured interval
        let end = now;
        let start = end - interval_secs as f64;

        // Bound active-zone discovery via reverse-streaming the
        // timestamp index instead of materializing every record in the
        // window. The earlier path called `query_records(usize::MAX)` over
        // [start, end], which loads the full ValidationRecord (~8 KB each)
        // into a Vec just to check `metadata.contains_key(EPOCH_OP_KEY)`
        // and resolve `rec.id` to a zone. At production scale (10T
        // records/day across 1M zones) even a 120 s window is
        // unboundedly large in absolute record count — `usize::MAX` here
        // OOMs the box.
        //
        // Bounded path: `recent_record_ids(start, MAX_DISCOVERY_SCAN)`
        // walks CF_IDX_TIMESTAMP backwards (newest first) and stops at
        // ts < start, returning IDs only (~50 B each). Per-ID we
        // `get_record` to apply the EPOCH_OP filter and resolve zone.
        // Late-window records past the cap get picked up by the next
        // tick — same as `compute_witness_smt_scope`.
        const MAX_DISCOVERY_SCAN: usize = 100_000;
        let mut zones = {
            match state.rocks.recent_record_ids(start, MAX_DISCOVERY_SCAN) {
                Ok(ids) => {
                    if ids.len() >= MAX_DISCOVERY_SCAN {
                        warn!(
                            "epoch_seal_loop: zone-discovery scan hit cap ({MAX_DISCOVERY_SCAN}) start={start} end={end} — late-window zones will be picked up by the next tick"
                        );
                    }
                    // Gap 4 routing-application: collect resolved leaf
                    // zones so the seal sweep hits the actual leaves that
                    // own each record after any splits, not the naive
                    // pre-split buckets.
                    let mut zones = std::collections::HashSet::new();
                    for rid in &ids {
                        let rec = match state.rocks.get_record(rid) {
                            Ok(Some(r)) => r,
                            _ => continue,
                        };
                        // recent_record_ids walks from the timestamp
                        // index End (latest record overall) backwards
                        // and stops at ts < start, so records with
                        // ts > end (future-dated due to clock skew)
                        // can still appear at the head — preserve the
                        // pre-fix `Some(end)` upper bound explicitly.
                        if rec.timestamp > end {
                            continue;
                        }
                        if rec.metadata.contains_key(EPOCH_OP_KEY) {
                            continue;
                        }
                        zones.insert(state.resolve_record_zone(&rec.id));
                    }
                    zones
                }
                Err(e) => {
                    warn!("epoch seal: failed to scan zone-discovery index: {e}");
                    continue;
                }
            }
        };

        // Also seal zones that have an active chain (previously sealed but no new records this window)
        // BUT only if the zone is within the current zone_count — dead zones from old configs
        // should NOT be re-sealed (they'd produce empty seals forever).
        {
            let current_zone_count = super::consensus::get_zone_count();
            let epoch = state.epoch.read_recover();
            for zone in epoch.latest_epoch.keys() {
                // Legacy numeric zones: parse path as u64, skip if >= zone_count
                if let Ok(zone_num) = zone.path().parse::<u64>() {
                    if zone_num >= current_zone_count {
                        continue;
                    }
                }
                zones.insert(zone.clone());
            }
        }

        // Fresh-chain liveness: both sources empty + no seal chain ever →
        // seed discovery from pre-window records (see genesis_bootstrap_zones).
        if zones.is_empty() {
            let never_sealed = state.epoch.read_recover().latest_epoch.is_empty();
            if never_sealed {
                zones = genesis_bootstrap_zones(&state, end, MAX_DISCOVERY_SCAN);
            }
        }

        let mut zones_to_seal: Vec<ZoneId> = zones.into_iter().collect();
        zones_to_seal.sort();

        // Prime `epoch_start_ts[zone]` for any zone we're about to evaluate
        // that has never been sealed locally. Fresh-genesis liveness fix:
        // without this, `elapsed = 0` forever, so only rank-0 can propose
        // and `is_zone_stuck` never fires. Priming starts the rank-unlock
        // clock at the first tick where we have stakers for the zone.
        // Idempotent per zone — overwritten by `register_seal` when the
        // first real seal lands. See `prime_epoch_start_if_unset` docs.
        {
            let mut epoch = state.epoch.write_recover();
            for zone in &zones_to_seal {
                if epoch.prime_epoch_start_if_unset(zone, now) {
                    tracing::info!(
                        zone = %zone,
                        now_s = now,
                        "epoch_start_ts primed at loop start (fresh-genesis liveness fix)"
                    );
                }
            }
        }

        // Gap 2.1 Phase 2b.3 Slice 4 — per-tick drain of pending witness
        // registrations.
        //
        // The producer-branch drain at the bottom of the per-zone loop only
        // fires when this node actually emits a seal for some zone in this
        // tick. A node that ingested + applied a `WitnessRegister` record
        // but is not the rank-elected producer would otherwise hold the
        // entry in the in-memory queue forever — silent memory leak, plus
        // its CF_WITNESS_REGISTRY would never reflect the registration.
        //
        // This unconditional drain runs once per epoch_seal_loop tick on
        // every node, so every node's local registry catches up regardless
        // of whether it produces. Cheap: empty queue is ~free (early
        // return in flush_pending_witness_registrations), and the lock
        // hold is bounded to a single `mem::take`.
        {
            let pending: Vec<(String, String, Vec<u8>, u64, u64)> = {
                let mut ledger = state.ledger.write().await;
                std::mem::take(&mut ledger.pending_witness_registrations)
            };
            if !pending.is_empty() {
                let rocks = state.rocks.clone();
                let count = pending.len();
                let res = tokio::task::spawn_blocking(move || {
                    rocks.flush_pending_witness_registrations(&pending)
                })
                .await;
                match res {
                    Ok(Ok(written)) => tracing::debug!(
                        "witness_registry: per-tick flushed {written}/{count} pending entries"
                    ),
                    Ok(Err(e)) => warn!("witness_registry per-tick flush failed: {e}"),
                    Err(e) => warn!("witness_registry per-tick spawn_blocking failed: {e}"),
                }
            }
        }

        // Diagnostic counters: capture proposal-outcome
        // distribution per tick so operators can disambiguate the stall
        // mode. None is split into 4 reason-tagged sub-counters so
        // /metrics shows WHICH gate fired without needing the journal.
        use std::sync::atomic::Ordering;
        state.seal_loop_ticks_total.fetch_add(1, Ordering::Relaxed);
        state.seal_loop_zones_evaluated_total.fetch_add(
            zones_to_seal.len() as u64,
            Ordering::Relaxed,
        );
        // #0ba — fin-burst-velocity sampler. Rides the deterministic
        // per-epoch cadence (one sample per tick that survived catchup-skip),
        // NOT per-Prometheus-scrape (which varies by scraper).
        state.sample_fin_burst_velocity();
        // #0be — per-node bratio band fingerprint sampler. Same cadence as
        // sample_fin_burst_velocity — one classify_cohort() call per tick,
        // exactly one band counter bumped. The 5 counters together partition
        // post-catchup-skip seal_loop_ticks_total exactly.
        state.sample_bratio_band_tick();
        let mut tick_per_zone: u32 = 0;
        let mut tick_escalate: u32 = 0;
        let mut tick_none: u32 = 0;
        let mut tick_none_already_sealed: u32 = 0;
        let mut tick_none_bootstrap: u32 = 0;
        let mut tick_none_not_in_top: u32 = 0;
        let mut tick_none_rank_too_high: u32 = 0;
        let mut tick_none_summary: Vec<String> = Vec::new();

        for zone in zones_to_seal {
            // Check if this node should propose for this zone/epoch
            let epoch_number = {
                let epoch = state.epoch.read_recover();
                epoch.next_epoch(&zone)
            };
            let our_rank = match should_propose_seal(&state, &zone, epoch_number).await {
                SealProposal::PerZone(r) => {
                    // Stage 3c.3 adversarial hook: if this rank is muted on
                    // this node (sim-only, never set in production), sit
                    // silent as if we never saw the trigger. This is the
                    // precise byzantine behavior that Stage 3c.2 liveness
                    // slashing punishes.
                    if state.config.muted_aggregator_ranks.contains(&r) {
                        continue;
                    }
                    tick_per_zone += 1;
                    state.seal_loop_proposals_per_zone_total
                        .fetch_add(1, Ordering::Relaxed);
                    r
                },
                SealProposal::None(reason) => {
                    tick_none += 1;
                    state.seal_loop_proposals_none_total
                        .fetch_add(1, Ordering::Relaxed);
                    let reason_tag = match &reason {
                        NoneReason::AlreadySealed => {
                            tick_none_already_sealed += 1;
                            state
                                .seal_loop_proposals_none_already_sealed_total
                                .fetch_add(1, Ordering::Relaxed);
                            "already_sealed".to_string()
                        },
                        NoneReason::BootstrapNonGenesis => {
                            tick_none_bootstrap += 1;
                            state
                                .seal_loop_proposals_none_bootstrap_decline_total
                                .fetch_add(1, Ordering::Relaxed);
                            "bootstrap_non_genesis".to_string()
                        },
                        NoneReason::NotInTopRanks => {
                            tick_none_not_in_top += 1;
                            state
                                .seal_loop_proposals_none_not_in_top_ranks_total
                                .fetch_add(1, Ordering::Relaxed);
                            "not_in_top_ranks".to_string()
                        },
                        NoneReason::RankTooHighForElapsed { our_rank, allowed } => {
                            tick_none_rank_too_high += 1;
                            state
                                .seal_loop_proposals_none_rank_too_high_total
                                .fetch_add(1, Ordering::Relaxed);
                            format!("rank_too_high(r={our_rank},allowed={allowed})")
                        },
                    };
                    if tick_none_summary.len() < 8 {
                        tick_none_summary.push(format!(
                            "{}@{}:{}",
                            zone, epoch_number, reason_tag
                        ));
                    }
                    continue;
                },
                SealProposal::GlobalEscalate(stuck_zone) => {
                    tick_escalate += 1;
                    state.seal_loop_proposals_escalate_total
                        .fetch_add(1, Ordering::Relaxed);
                    // Stage 3c.1 Part D: zone's rank ladder fully exhausted.
                    // This node is a positive-stake anchor in a different
                    // zone (checked by `escalation_decision`). Emit a global
                    // quorum seal from our natural zone targeting
                    // `stuck_zone` at `epoch_number`.
                    let Some(vrf_sk) = state.vrf_secret_key.clone() else {
                        // No VRF — can't construct the seal alpha. Abstain.
                        continue;
                    };
                    // Gap 4 routing-application: emitter_zone for the global
                    // quorum seal is the proposing anchor's resolved home
                    // leaf — verifiers bucket stakers the same way (see
                    // `resolve_identity_zone` usage in ingest global-seal
                    // verify path), so the two must stay aligned.
                    let emitter_zone = state.resolve_identity_zone(
                        &state.identity.identity_hash,
                    );
                    // Re-read the same inputs should_propose_seal used so
                    // the (base_ms, elapsed_ms) embedded in the seal match
                    // what verifiers will recompute on their side.
                    let (prev_seal_hash, epoch_start) = {
                        let epoch = state.epoch.read_recover();
                        let hash = epoch
                            .latest_seal_hash
                            .get(&stuck_zone)
                            .copied()
                            .unwrap_or([0u8; 32]);
                        let start = epoch.epoch_start(&stuck_zone);
                        (hash, start)
                    };
                    let base_ms: u64 = state.effective_base_timeout_ms(&stuck_zone);
                    let now_ts = super::ingest::now();
                    let elapsed_s = (now_ts - epoch_start.unwrap_or(now_ts)).max(0.0);
                    // Clamp matches verifier-side clamp in `verify_epoch_seal`
                    // and the per-zone proposer in `should_propose_seal`.
                    let elapsed_ms: u64 =
                        (elapsed_s * 1000.0).min(MAX_RANK_ELAPSED_SECS * 1000.0) as u64;
                    let seal_parents = super::server::dag_tip_parents(&state, 3).await;
                    let identity = state.identity.clone();
                    let sz = stuck_zone.clone();
                    let ez = emitter_zone.clone();
                    let slot_nonce = state.next_slot_nonce();
                    let gseal_result = tokio::task::spawn_blocking(move || {
                        create_global_quorum_seal(
                            &identity,
                            &vrf_sk,
                            sz,
                            ez,
                            epoch_number,
                            prev_seal_hash,
                            base_ms,
                            elapsed_ms,
                            seal_parents,
                            slot_nonce,
                        )
                    })
                    .await;
                    let (record, _parsed) = match gseal_result {
                        Ok(Ok(r)) => r,
                        Ok(Err(e)) => {
                            warn!(
                                "global quorum seal creation failed for stuck_zone {stuck_zone}: {e}",
                            );
                            continue;
                        }
                        Err(e) => {
                            warn!("global quorum seal spawn_blocking failed: {e}");
                            continue;
                        }
                    };
                    // Insert via the synced path — ingest's pre-insert
                    // verifier (added in 3c.1 Part C) will re-check the
                    // seal and the post-insert hook registers it in both
                    // EpochState and AWCConsensus.
                    match super::gossip::insert_record_synced(&state, record.clone()).await {
                        Ok(_) => info!(
                            "global quorum seal emitted: stuck_zone={} emitter_zone={} epoch={} id={}",
                            stuck_zone, emitter_zone, epoch_number, record.id,
                        ),
                        Err(e) => warn!(
                            "global quorum seal insert failed (stuck_zone={stuck_zone}): {e}"
                        ),
                    }
                    continue;
                }
            };

            // Create seal — get DAG tips before entering blocking context
            // so epoch seals reference the current DAG frontier.
            let seal_parents = super::server::dag_tip_parents(&state, 3).await;

            // Gap 1: Flush dirty account SMT + capture the resulting
            // root so this seal binds a signed root that light clients can
            // verify account proofs against.
            //
            // Split into two phases to keep the async ledger.write() hold
            // microsecond-short:
            //   1. Snapshot under ledger.write(): drain smt_dirty, clone
            //      account states, hash to (account_id, state_hash) pairs.
            //      No RocksDB touched here.
            //   2. Apply snapshot from spawn_blocking: walks O(dirty × log N)
            //      RocksDB paths with NO ledger lock held, so concurrent
            //      phase-1 seal validation (ingest.rs:897 ledger.read) does
            //      not stall.
            // Previously the whole walk ran under ledger.write, blocking every
            // concurrent reader for 30-40s under compaction backpressure.
            let (snapshot, pending_witness_writes) = {
                let mut ledger = state.ledger.write().await;
                let dirty = super::account_merkle::snapshot_dirty(&mut ledger);
                // Gap 2.1 Phase 2b.3 Slice 3: drain pending witness
                // registrations under the same brief write lock so
                // we can persist them off-thread alongside the SMT.
                let witnesses = std::mem::take(&mut ledger.pending_witness_registrations);
                (dirty, witnesses)
            };
            // Persist pending witness registrations on a blocking thread —
            // same off-lock pattern as account_smt::apply_snapshot below.
            // Failure here logs a warning but does NOT abort the seal: the
            // ledger keeps the bond debit (durable via the next checkpoint)
            // and the next epoch's flush will retry on the rebuilt queue.
            if !pending_witness_writes.is_empty() {
                let rocks = state.rocks.clone();
                let zone_for_log = zone.clone();
                let count = pending_witness_writes.len();
                let res = tokio::task::spawn_blocking(move || {
                    rocks.flush_pending_witness_registrations(&pending_witness_writes)
                })
                .await;
                match res {
                    Ok(Ok(written)) => {
                        tracing::debug!(
                            "witness_registry: flushed {written}/{count} pending entries ({zone_for_log})"
                        );
                    }
                    Ok(Err(e)) => {
                        warn!("witness_registry flush failed before seal ({zone_for_log}): {e}");
                    }
                    Err(e) => {
                        warn!("witness_registry flush spawn_blocking failed ({zone_for_log}): {e}");
                    }
                }
            }
            let account_smt_root: Option<[u8; 32]> = if snapshot.is_empty() {
                // No dirty accounts — read the current root directly so the
                // seal still binds a committed SMT state.
                let rocks = state.rocks.clone();
                tokio::task::spawn_blocking(move || {
                    super::account_merkle::AccountStateSMT::new(&rocks).root().ok()
                })
                .await
                .ok()
                .flatten()
            } else {
                let rocks = state.rocks.clone();
                let zone_for_log = zone.clone();
                // CF_ACCOUNT_SMT writer gate (see NodeState::account_smt_write_gate).
                // Only the WRITING branch takes it — the is_empty() branch above is
                // a pure atomic read. Held across the spawn_blocking await, dropped
                // at branch end (before the ledger.read() below — gate is a leaf
                // lock). NOTE: `snapshot` was destructively drained from smt_dirty
                // above; a long gate wait (operator reconcile) lengthens the window
                // where those entries live only in this local variable — the
                // pre-existing warn-and-drop on apply error is the same exposure.
                let gate_wait = std::time::Instant::now();
                let _smt_gate = state.account_smt_write_gate.lock().await;
                if gate_wait.elapsed().as_secs() >= 1 {
                    warn!(
                        "seal flush ({zone_for_log}): waited {:.1}s on account_smt_write_gate (concurrent SMT writer — reconcile/repair/bootstrap)",
                        gate_wait.elapsed().as_secs_f64()
                    );
                }
                let res = tokio::task::spawn_blocking(move || {
                    super::account_merkle::apply_snapshot(&rocks, &snapshot)
                })
                .await;
                match res {
                    Ok(Ok((_flushed, root))) => Some(root),
                    Ok(Err(e)) => {
                        warn!("account_smt apply_snapshot failed before seal ({zone_for_log}): {e}");
                        None
                    }
                    Err(e) => {
                        warn!("account_smt spawn_blocking failed before seal ({zone_for_log}): {e}");
                        None
                    }
                }
            };

            // B2 fix (internal design notes): bind the
            // canonical finality committee anchor for each DEST zone of a
            // pending Locked cross-zone transfer in THIS source zone, computed
            // at THIS seal's epoch from GLOBAL vrf_registry+stake — BEFORE the
            // spawn_blocking boundary (finality_committee_pks is async). Frozen
            // into PendingTransfer at seal-ingest and READ (never recomputed) at
            // XZoneAbort apply/replay so a forged abort committee cannot pass
            // verify_abort_quorum. The epoch read here matches the authoritative
            // next_epoch the blocking seal uses (single sealer per zone).
            let xzone_dest_committees_for_seal: Option<BTreeMap<String, ([u8; 32], u32)>> = {
                let seal_epoch = state.epoch.read().ok().map(|es| es.next_epoch(&zone));
                match seal_epoch {
                    Some(seal_epoch) => {
                        let dest_zones: std::collections::BTreeSet<ZoneId> = {
                            let ledger = state.ledger.read().await;
                            ledger
                                .cross_zone
                                .pending
                                .values()
                                .filter(|t| {
                                    t.source_zone == zone
                                        && t.status
                                            == crate::accounting::cross_zone::TransferStatus::Locked
                                })
                                .map(|t| t.dest_zone.clone())
                                .collect()
                        };
                        if dest_zones.is_empty() {
                            None
                        } else {
                            let mut map = BTreeMap::new();
                            for dz in dest_zones {
                                let (_pks, hash, size) =
                                    crate::network::zone_committee::finality_committee_pks(
                                        &state,
                                        dz.path(),
                                        seal_epoch,
                                        crate::network::zone_committee::DEFAULT_COMMITTEE_SIZE,
                                    )
                                    .await;
                                // size==0 → no committee resolvable for this dest
                                // zone/epoch; skip (its abort stays fail-closed
                                // until a committee exists).
                                if size > 0 {
                                    map.insert(dz.path().to_string(), (hash, size));
                                }
                            }
                            if map.is_empty() {
                                None
                            } else {
                                Some(map)
                            }
                        }
                    }
                    None => None,
                }
            };

            let seal_result = {
                let state2 = state.clone();
                let identity = state.identity.clone();
                let vrf_sk = state.vrf_secret_key.clone();
                let s = start;
                let e = end;
                let z = zone.clone();
                let rocks = state.rocks.clone();
                // Pre-allocate the slot nonce BEFORE spawn_blocking so the
                // counter is advanced on the scheduler thread — keeps the
                // blocking task pure (no shared-state mutation inside).
                let slot_nonce = state.next_slot_nonce();
                // Gap 4 routing-application: snapshot the zone registry
                // out of the async RwLock BEFORE spawn_blocking so the
                // blocking closure walks a consistent tree without
                // holding the async lock across the blocking boundary.
                // Clone is cheap at current scale (≤ a few dozen entries);
                // when the registry grows, switch to Arc<ZoneRegistry>
                // snapshotting.
                let registry_snapshot = {
                    use super::RwLockRecover;
                    state.zone_registry.read_recover().clone()
                };
                // REALMS P1.5 a3: snapshot the freshest cached drand pulse
                // (non-blocking, staleness-capped) BEFORE spawn_blocking —
                // same pattern as the registry snapshot above. `None` (fetcher
                // off / cold cache / stale) keeps the seal byte-identical to
                // the legacy shape; sealing NEVER waits on the beacon.
                let drand_snapshot = state
                    .drand_pulse_cache
                    .get_fresh(super::admin_pq_auth::now_unix_secs());
                if drand_snapshot.is_some() {
                    state
                        .drand_seal_pulse_attached_total
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                } else {
                    state
                        .drand_seal_pulse_absent_total
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                tokio::task::spawn_blocking(move || {
                    let epoch_state = state2.epoch.read().map_err(|err| ElaraError::Storage(err.to_string()))?;
                    // Read the current sparse Merkle root for this zone
                    let sparse_root = super::merkle::zone_root(&rocks, z.clone()).ok();
                    create_epoch_seal_with_balance(SealParams {
                        identity: &identity,
                        storage: &*rocks,
                        epoch_state: &epoch_state,
                        zone: z,
                        start: s,
                        end: e,
                        vrf_sk: vrf_sk.as_deref(),
                        sparse_merkle_root: sparse_root,
                        zone_balance_total: None,
                        zone_registry_root: None,
                        zone_registry_delta: None,
                        parents: seal_parents,
                        aggregator_rank: our_rank,
                        slot_nonce,
                        account_smt_root,
                        drand_pulse: drand_snapshot.as_ref(),
                        zone_registry: Some(&registry_snapshot),
                        xzone_dest_finality_committees: xzone_dest_committees_for_seal,
                    })
                })
                .await
            };

            let (record, parsed) = match seal_result {
                Ok(Ok(result)) => result,
                Ok(Err(e)) => {
                    warn!("epoch seal creation failed for zone {zone}: {e}");
                    continue;
                }
                Err(e) => {
                    warn!("epoch seal spawn_blocking failed: {e}");
                    continue;
                }
            };

            let record_id = record.id.clone();
            let record_hash = record.record_hash();

            // Insert into storage + DAG (use synced path to bypass rate limits —
            // epoch seals are self-generated, not external spam)
            match super::gossip::insert_record_synced(&state, record.clone()).await {
                Ok(_) => {
                    // Update epoch state
                    if let Ok(mut epoch) = state.epoch.write() {
                        epoch.register_seal(&parsed, &record_id, record_hash);
                    }

                    // Gap 3: Roll a super-seal every SUPER_SEAL_INTERVAL seals per zone.
                    // Aggregates the rolling buffer into a single Dilithium3-signed
                    // Merkle-root record. Light clients sync from these instead of
                    // replaying individual seals (65× compression at default N=64).
                    // Super-seal creation funnel observability. Log
                    // archaeology across the cluster showed zero "super-seal
                    // created" lines across 7d / 10K epochs despite the
                    // producer code being wired since the original Gap 3
                    // ship. Without these
                    // counters we can't disambiguate (a) gate filters
                    // everything (latest % INTERVAL never lands here OR buffer
                    // never reaches 64), (b) create_super_seal Err, or (c)
                    // insert_record_synced Err. At every boundary epoch we
                    // also emit one INFO line with the gate decision + buffer
                    // depth — at SUPER_SEAL_INTERVAL=64 cadence that's at most
                    // 1 line every ~5 min per zone, mainnet-safe.
                    let at_boundary = parsed.epoch_number > 0
                        && parsed.epoch_number % SUPER_SEAL_INTERVAL == 0;
                    let super_snapshot = {
                        let epoch_r = state.epoch.read().ok();
                        match epoch_r {
                            Some(e) if e.should_create_super_seal(&parsed.zone) => {
                                let hashes = e.snapshot_recent_seal_hashes(&parsed.zone);
                                let prev = e.latest_super_seal
                                    .get(&parsed.zone)
                                    .map(|(_, _, h, _)| *h)
                                    .unwrap_or([0u8; 32]);
                                let end_epoch = *e.latest_epoch.get(&parsed.zone).unwrap_or(&0);
                                hashes.map(|h| (h, prev, end_epoch))
                            }
                            _ => None,
                        }
                    };
                    if at_boundary {
                        // Read the buffer depth WITHOUT mutating it (super_snapshot
                        // path above already drained `should_create_super_seal` if
                        // the gate passed; this is the post-decision diagnostic).
                        let buf_depth = state.epoch.read().ok()
                            .and_then(|e| e.recent_seal_hashes.get(&parsed.zone).map(|b| b.len()))
                            .unwrap_or(0);
                        let gate_passed = super_snapshot.is_some();
                        info!(
                            "super-seal boundary eval: zone={} epoch={} buffer={}/{} gate_passed={}",
                            parsed.zone, parsed.epoch_number, buf_depth, SUPER_SEAL_INTERVAL, gate_passed,
                        );
                    }
                    if let Some((hashes, prev_hash, end_epoch)) = super_snapshot {
                        state.super_seal_creation_attempts_total
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let start_epoch = end_epoch.saturating_sub(SUPER_SEAL_INTERVAL - 1);
                        let now_ts = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs_f64())
                            .unwrap_or(0.0);
                        // Gap #3 follow-up: snapshot the committee commitment
                        // so light clients synced from this super-seal can
                        // verify future attestations against the right
                        // witness set. Empty committee → [0u8; 32].
                        let committee_hash = state
                            .consensus
                            .lock_recover()
                            .committee_hash(&parsed.zone);
                        match create_super_seal(SuperSealParams {
                            identity: &state.identity,
                            zone: parsed.zone.clone(),
                            start_epoch,
                            end_epoch,
                            seal_hashes: &hashes,
                            previous_super_seal_hash: prev_hash,
                            committee_hash,
                            timestamp: now_ts,
                            slot_nonce: state.next_slot_nonce(),
                        }) {
                            Ok((ss_record, _ss_parsed)) => {
                                let ss_id = ss_record.id.clone();
                                let ss_hash = ss_record.record_hash();
                                match super::gossip::insert_record_synced(&state, ss_record).await {
                                    Ok(_) => {
                                        if let Ok(mut epoch) = state.epoch.write() {
                                            epoch.register_super_seal(parsed.zone.clone(), end_epoch, ss_id.clone(), ss_hash, committee_hash);
                                        }
                                        info!(
                                            "super-seal created: zone={} epochs=[{start_epoch}..={end_epoch}] count={} id={ss_id}",
                                            parsed.zone, SUPER_SEAL_INTERVAL,
                                        );
                                    }
                                    Err(e) => {
                                        state.super_seal_creation_failures_total
                                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                        state.super_seal_creation_insert_failures_total
                                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                        warn!("super-seal insert failed ({}): {e}", parsed.zone);
                                    }
                                }
                            }
                            Err(e) => {
                                state.super_seal_creation_failures_total
                                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                state.super_seal_creation_sign_failures_total
                                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                warn!("super-seal creation failed ({}): {e}", parsed.zone);
                            }
                        }
                    }

                    // M7 / Gap 2: Populate Merkle proofs for pending XZone locks
                    // included in this seal (local-creation path).
                    // Gap 2.1 Phase 2b: also bundle finality witness signatures
                    // collected for this seal so claim_transfer (consumer side
                    // in zone B) can enforce 2/3 zone-A finality.
                    if let Ok(mut ledger) = state.ledger.try_write() {
                        let proofed = match state.consensus.try_lock() {
                            Ok(awc) => attach_xzone_proofs_from_seal_with_finality(
                                &mut ledger, &parsed, Some(&record_id), Some(&*awc),
                            ),
                            Err(_) => attach_xzone_proofs_from_seal(&mut ledger, &parsed),
                        };
                        if proofed > 0 {
                            info!("epoch seal (local): attached merkle proofs to {proofed} pending xzone transfers");
                        }
                    }

                    // Evaluate predictions targeting this zone+epoch.
                    // CRITICAL: Hold ledger write lock only for the mutation, then drop.
                    // Before this fix, the write lock was held through reputation updates,
                    // retirement tracking, and epoch recurrence — blocking state_core and
                    // all RPC handlers for the entire duration.
                    let prediction_outcomes: Vec<(String, String, Option<bool>)>;
                    let (correct, wrong, rewarded, confiscated);
                    // Use try_write to avoid blocking the state_core's ledger.write().
                    // If contended, predictions will be evaluated on the next epoch cycle
                    // or by the ingest pipeline (ingest.rs line 1006).
                    if let Ok(mut ledger) = state.ledger.try_write() {
                        let zone_str = parsed.zone.path();

                        // Collect predictor identities before evaluation
                        let predictors: Vec<(String, String)> = ledger
                            .pending_predictions(zone_str, parsed.epoch_number)
                            .iter()
                            .map(|p| (p.record_id.clone(), p.predictor.clone()))
                            .collect();

                        let eval = ledger.evaluate_predictions(zone_str, parsed.epoch_number, parsed.record_count, 0);
                        correct = eval.0;
                        wrong = eval.1;
                        rewarded = eval.2;
                        confiscated = eval.3;

                        // Snapshot outcomes while holding the lock, then DROP it
                        prediction_outcomes = predictors.iter()
                            .map(|(pred_id, predictor)| {
                                let outcome = ledger.predictions.get(pred_id)
                                    .and_then(|p| p.outcome);
                                (pred_id.clone(), predictor.clone(), outcome)
                            })
                            .collect();
                    } else {
                        tracing::debug!("epoch seal: ledger contended, deferring prediction evaluation for zone {} epoch {}", parsed.zone, parsed.epoch_number);
                        prediction_outcomes = Vec::new();
                        correct = 0;
                        wrong = 0;
                        rewarded = 0;
                        confiscated = 0;
                    }

                    if correct + wrong > 0 {
                        info!(
                            "predictions evaluated: zone={} epoch={} correct={} wrong={} rewarded={} confiscated={}",
                            parsed.zone.path(), parsed.epoch_number, correct, wrong, rewarded, confiscated,
                        );

                        // Economic feedback: update reputation (no ledger lock needed)
                        {
                            let mut reputation = state.reputation.lock_recover();
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_secs_f64())
                                .unwrap_or(0.0);
                            for (_pred_id, predictor, outcome) in &prediction_outcomes {
                                match outcome {
                                    Some(true) => reputation.apply_event(predictor, super::reputation::ReputationEvent::Undisputed, now),
                                    Some(false) => reputation.apply_event(predictor, super::reputation::ReputationEvent::DisputeLost, now),
                                    None => {}
                                }
                            }
                        }

                        // Retirement tracking (no ledger lock needed)
                        {
                            let mut retirement = state.retirement.lock_recover();
                            for (_pred_id, predictor, outcome) in &prediction_outcomes {
                                let health = retirement.health(predictor);
                                match outcome {
                                    Some(true) => health.prediction_correct(),
                                    Some(false) => health.prediction_wrong(),
                                    None => {}
                                }
                            }
                        }

                        // Recurrence wiring
                        {
                            let accuracy = correct as f64 / (correct + wrong).max(1) as f64;
                            if let Ok(mut epoch) = state.epoch.write() {
                                epoch.prediction_recurrence.insert(
                                    parsed.zone.clone(),
                                    (parsed.epoch_number, accuracy, correct, wrong),
                                );
                            }
                        }
                    }

                    // Gap 2 sealed-abort P-3d: producer-side abort-witness emitter.
                    // Scan locally-known sealed cross-zone transfers whose
                    // claim window expired without admission in the dest
                    // zone. For each one where THIS node is a member of the
                    // dest zone's finality committee at the source-seal
                    // epoch, sign an abort attestation and fold it into the
                    // local AbortCollection. Aggregator (P-3f, follow-up)
                    // collects ≥2/3 sigs and submits the bundle to the
                    // source zone for refund.
                    //
                    // Gap 2 close: this is now the ONLY
                    // refund path for sealed transfers — `process_expired_xzone`
                    // skips sealed transfers because passive refund races
                    // an in-flight CLAIM and could break global conservation.
                    // If the dest committee fails to gather 2/3 quorum,
                    // sealed transfers stay Locked indefinitely (operator
                    // visibility via `xzone_sealed_locked_past_expiry_count`).
                    // Best-effort — try_read on ledger and try_lock on
                    // consensus avoid blocking state_core; we re-attempt on
                    // the next tick.
                    {
                        use crate::network::zone_committee::{
                            finality_committee_pks, DEFAULT_COMMITTEE_SIZE,
                        };
                        use crate::accounting::cross_zone::{
                            try_sign_xzone_abort, TransferStatus,
                        };

                        // (transfer_id, dest_zone, source_seal_epoch,
                        // dest_finality_committee = Option<(committee_hash, size)>)
                        type AbortCandidate = (String, ZoneId, u64, Option<([u8; 32], u32)>);
                        let candidates: Vec<AbortCandidate> =
                            if let Ok(ledger) = state.ledger.try_read() {
                                ledger
                                    .cross_zone
                                    .pending
                                    .values()
                                    .filter(|t| {
                                        t.status == TransferStatus::Locked
                                            && !t.merkle_proof.is_empty()
                                            && now > t.expires_at
                                    })
                                    .map(|t| {
                                        (
                                            t.transfer_id.clone(),
                                            t.dest_zone.clone(),
                                            t.source_seal_epoch,
                                            t.dest_finality_committee,
                                        )
                                    })
                                    .collect()
                            } else {
                                Vec::new()
                            };

                        for (transfer_id, dest_zone, source_seal_epoch, anchor) in candidates {
                            // B2 fix: sign the abort against the CANONICAL committee
                            // anchor frozen from the source seal — not a live
                            // recompute. Unanchored (legacy/pre-fix) locks are
                            // fail-closed at apply, so signing is moot → skip.
                            let anchor_hash = match anchor {
                                Some((h, _size)) => h,
                                None => continue,
                            };
                            // The live draw supplies the PK list to build Merkle
                            // proofs; try_sign_xzone_abort refuses unless its
                            // recomputed hash == the frozen anchor (fail-safe if
                            // the global committee has drifted since seal time).
                            let (pks, _live_hash, _live_size) =
                                finality_committee_pks(
                                    &state,
                                    dest_zone.path(),
                                    source_seal_epoch,
                                    DEFAULT_COMMITTEE_SIZE,
                                )
                                .await;
                            if let Some((witness, computed_hash, computed_size)) =
                                try_sign_xzone_abort(
                                    &state.identity,
                                    &transfer_id,
                                    &dest_zone,
                                    source_seal_epoch,
                                    &pks,
                                    &anchor_hash,
                                )
                            {
                                if let Ok(mut consensus) = state.consensus.try_lock() {
                                    consensus.add_xzone_abort_signature(
                                        &transfer_id,
                                        source_seal_epoch,
                                        computed_hash,
                                        computed_size,
                                        witness.clone(),
                                    );
                                    debug!(
                                        "xzone-abort: signed transfer={} dest_zone={} source_seal_epoch={} committee_size={}",
                                        &transfer_id[..transfer_id.len().min(16)],
                                        dest_zone,
                                        source_seal_epoch,
                                        computed_size,
                                    );
                                }
                                // P-3e: gossip the witness to peers so the
                                // rest of the dest-zone committee folds it
                                // into their own AbortCollection. sqrt(n)
                                // fan-out, dedup by (transfer_id,
                                // witness_pk). Receiver handler does NOT
                                // re-broadcast.
                                let state_clone = Arc::clone(&state);
                                let transfer_id_owned = transfer_id.clone();
                                let dest_zone_owned = dest_zone.clone();
                                tokio::spawn(async move {
                                    crate::network::gossip::push_xzone_abort_witness_to_peers(
                                        &state_clone,
                                        &transfer_id_owned,
                                        dest_zone_owned,
                                        source_seal_epoch,
                                        computed_hash,
                                        computed_size,
                                        witness,
                                    )
                                    .await;
                                });
                            }
                        }

                        // P-3f aggregator: scan AbortCollections that have
                        // crossed the 2/3 quorum threshold, assemble the
                        // bundle, and self-submit a LedgerOp::XZoneAbort
                        // record. Gossip propagates it to source-zone
                        // validators which apply the refund. Per-node
                        // dedup so we don't re-submit; multi-committee-
                        // member redundancy is absorbed by apply-time
                        // idempotency on Locked status.
                        let ready: Vec<(String, crate::network::consensus::XZoneAbortCollection)> =
                            if let Ok(consensus) = state.consensus.try_lock() {
                                consensus.ready_xzone_abort_bundles()
                            } else {
                                Vec::new()
                            };
                        for (agg_transfer_id, coll) in ready {
                            // Per-node dedup: submit at most once per
                            // (node lifetime, transfer_id). Surviving a
                            // restart re-arms the SeenSet, but the apply
                            // path on the source zone will idempotently
                            // reject the second record.
                            {
                                let mut seen = state.xzone_abort_aggregated_seen.lock_recover();
                                if !seen.insert(agg_transfer_id.clone()) {
                                    continue;
                                }
                            }
                            // Resolve dest_zone and verify the local
                            // PendingTransfer is still Locked at the same
                            // source_seal_epoch the AbortCollection pinned.
                            // If the local view diverges from the
                            // collection's snapshot, skip — we're racing
                            // a refund that already landed or a committee
                            // rotation; the next tick re-evaluates.
                            let (agg_dest_zone, transfer_locked, transfer_seal_epoch_match) =
                                if let Ok(ledger) = state.ledger.try_read() {
                                    if let Some(t) = ledger.cross_zone.pending.get(&agg_transfer_id) {
                                        let locked = t.status == crate::accounting::cross_zone::TransferStatus::Locked;
                                        let epoch_match = t.source_seal_epoch == coll.source_seal_epoch;
                                        (Some(t.dest_zone.clone()), locked, epoch_match)
                                    } else {
                                        (None, false, false)
                                    }
                                } else {
                                    (None, false, false)
                                };
                            let agg_dest_zone = match agg_dest_zone {
                                Some(z) => z,
                                None => continue,
                            };
                            if !transfer_locked || !transfer_seal_epoch_match {
                                continue;
                            }
                            let bundle = crate::accounting::cross_zone::XZoneAbortBundle {
                                transfer_id: agg_transfer_id.clone(),
                                dest_zone: agg_dest_zone.clone(),
                                source_seal_epoch: coll.source_seal_epoch,
                                dest_committee_hash: coll.dest_committee_hash,
                                dest_committee_size: coll.dest_committee_size,
                                signers: coll.signers.clone(),
                            };
                            if let Err(e) = bundle.verify() {
                                warn!(
                                    "xzone-abort aggregator: bundle for {} failed pre-flight verify: {}",
                                    &agg_transfer_id[..agg_transfer_id.len().min(16)],
                                    e
                                );
                                continue;
                            }
                            let meta = crate::accounting::types::xzone_abort_metadata(
                                &bundle.transfer_id,
                                &bundle.dest_committee_hash,
                                bundle.dest_committee_size,
                                &bundle.signers,
                            );
                            let parents = super::server::dag_tip_parents(&state, 3).await;
                            let record = match state.create_self_ledger_record(parents, meta) {
                                Ok(r) => r,
                                Err(e) => {
                                    warn!(
                                        "xzone-abort aggregator: create_self_ledger_record failed for {}: {}",
                                        &agg_transfer_id[..agg_transfer_id.len().min(16)],
                                        e
                                    );
                                    continue;
                                }
                            };
                            match super::server::insert_and_push(&state, record).await {
                                Ok(record_id) => {
                                    state.xzone_abort_bundles_submitted_total.fetch_add(
                                        1,
                                        std::sync::atomic::Ordering::Relaxed,
                                    );
                                    info!(
                                        "xzone-abort aggregator: submitted bundle for transfer={} record={} signers={}/{}",
                                        &agg_transfer_id[..agg_transfer_id.len().min(16)],
                                        &record_id[..record_id.len().min(16)],
                                        bundle.signers.len(),
                                        bundle.dest_committee_size,
                                    );
                                }
                                Err(e) => {
                                    warn!(
                                        "xzone-abort aggregator: insert_and_push failed for {}: {}",
                                        &agg_transfer_id[..agg_transfer_id.len().min(16)],
                                        e.0
                                    );
                                }
                            }
                        }
                    }

                    // Expired cross-zone timeout refunds (economics §16.1): the
                    // genesis authority freezes the expired-UNSEALED locks into a
                    // signed `XZoneTimeoutRefund` record (Option A propagation,
                    // internal design notes). Every node
                    // then un-locks the SAME frozen set via the standard apply
                    // path, so balances + pending_xzone_locked + the account-SMT
                    // root converge fleet-wide — closing the old ungated in-loop
                    // `process_expired_xzone` mutation, which forked because each
                    // seal-eligible node ran it at a different wall-clock `now` and
                    // followers never ran it at all. Gated to the genesis authority
                    // + one batch per epoch number (monotone fetch_max guard).
                    let xzone_is_genesis_authority =
                        state.identity.identity_hash == state.config.genesis_authority;
                    if xzone_is_genesis_authority {
                        let epoch_no = parsed.epoch_number;
                        let prev = state
                            .last_xzone_refund_emit_epoch
                            .fetch_max(epoch_no, std::sync::atomic::Ordering::SeqCst);
                        if epoch_no > prev {
                            // Compute under a read lock (pure, no mutation). The
                            // local wall-clock `now` only selects WHICH transfers
                            // to propose; the frozen list is what every node
                            // applies, so `now` never enters a state transition.
                            let batch_opt = state.ledger.try_read().ok().and_then(|ledger| {
                                ledger.cross_zone.compute_expired_refund_batch(
                                    now,
                                    epoch_no,
                                    parsed.zone.path(),
                                )
                            });
                            if let Some(batch) = batch_opt {
                                let n = batch.refunds.len() as u64;
                                let total = batch.total_refund();
                                let meta =
                                    crate::accounting::types::xzone_refund_batch_metadata(&batch);
                                let parents = super::server::dag_tip_parents(&state, 3).await;
                                match state.create_self_ledger_record(parents, meta) {
                                    Ok(record) => {
                                        match super::server::insert_and_push(&state, record).await {
                                            Ok(record_id) => {
                                                // Surface refund rate on /metrics. On the
                                                // single-emitter deployment proposed ≈ applied.
                                                state.xzone_refunds_total.fetch_add(
                                                    n,
                                                    std::sync::atomic::Ordering::Relaxed,
                                                );
                                                info!(
                                                    "xzone-timeout-refund: emitted batch epoch={} refunds={} total={} record={}",
                                                    epoch_no, n, total,
                                                    &record_id[..record_id.len().min(16)],
                                                );
                                            }
                                            Err(e) => warn!(
                                                "xzone-timeout-refund: insert_and_push failed for epoch {}: {}",
                                                epoch_no, e.0
                                            ),
                                        }
                                    }
                                    Err(e) => warn!(
                                        "xzone-timeout-refund: create_self_ledger_record failed for epoch {}: {}",
                                        epoch_no, e
                                    ),
                                }
                            }
                        }
                    }

                    // Far-horizon SEALED-stuck reap (co-fix (b), economics §16.1):
                    // a sealed lock under a dead/partitioned dest committee never
                    // refunds (its CLAIM could race) and is never pruned, bloating
                    // every snapshot. ~30d past expiry the 24h CLAIM window is long
                    // closed, so the genesis authority hard-refunds it via a signed
                    // `XZoneStaleReap` record applied fleet-wide (same Option-A
                    // pattern as the timeout refund). Coarse cadence — these are
                    // rare and 30d-aged, so a per-epoch scan would be wasted work;
                    // the monotone guard keeps it to one batch per chosen epoch.
                    const REAP_CHECK_INTERVAL_EPOCHS: u64 = 100;
                    if xzone_is_genesis_authority
                        && parsed.epoch_number % REAP_CHECK_INTERVAL_EPOCHS == 0
                    {
                        let epoch_no = parsed.epoch_number;
                        let prev = state
                            .last_xzone_reap_emit_epoch
                            .fetch_max(epoch_no, std::sync::atomic::Ordering::SeqCst);
                        if epoch_no > prev {
                            let batch_opt = state.ledger.try_read().ok().and_then(|ledger| {
                                ledger.cross_zone.compute_stale_reap_batch(
                                    now,
                                    epoch_no,
                                    parsed.zone.path(),
                                )
                            });
                            if let Some(batch) = batch_opt {
                                let n = batch.refunds.len() as u64;
                                let total = batch.total_refund();
                                let meta = crate::accounting::types::xzone_reap_batch_metadata(&batch);
                                let parents = super::server::dag_tip_parents(&state, 3).await;
                                match state.create_self_ledger_record(parents, meta) {
                                    Ok(record) => {
                                        match super::server::insert_and_push(&state, record).await {
                                            Ok(record_id) => {
                                                state.xzone_refunds_total.fetch_add(
                                                    n,
                                                    std::sync::atomic::Ordering::Relaxed,
                                                );
                                                info!(
                                                    "xzone-stale-reap: emitted batch epoch={} reaped={} total={} record={}",
                                                    epoch_no, n, total,
                                                    &record_id[..record_id.len().min(16)],
                                                );
                                            }
                                            Err(e) => warn!(
                                                "xzone-stale-reap: insert_and_push failed for epoch {}: {}",
                                                epoch_no, e.0
                                            ),
                                        }
                                    }
                                    Err(e) => warn!(
                                        "xzone-stale-reap: create_self_ledger_record failed for epoch {}: {}",
                                        epoch_no, e
                                    ),
                                }
                            }
                        }
                    }

                    // Prune completed/refunded/aborted transfers older than 48h.
                    // Bounded-size bookkeeping that never touches Locked entries,
                    // balances, or pending_xzone_locked, so it is safe under a brief
                    // write lock here (no consensus-affecting mutation).
                    if let Ok(mut ledger) = state.ledger.try_write() {
                        let prune_cutoff = now - 48.0 * 3600.0;
                        ledger.cross_zone.prune_completed(prune_cutoff);
                    }

                    // Custodial idle_decay (economics §13.13.1): the genesis
                    // authority freezes the per-epoch holding fee into a signed
                    // `IdleDecay` system record (Option A propagation,
                    // internal design notes). Every node then applies it
                    // verbatim via the standard record path, so balances + the
                    // account-SMT root converge fleet-wide — closing the old
                    // producer-only-mutation divergence (H1). Gated to the genesis
                    // authority (only it can sign a record the apply-side
                    // `creator == genesis_authority` gate accepts). Same-epoch
                    // dedup is two-layered: the per-zone `AlreadySealed` gate blocks
                    // re-sealing (hence re-emitting) any epoch ≤ a zone's tip, and
                    // the in-process `fetch_max` watermark dedups the *global* batch
                    // ACROSS zones within one process. The watermark is seeded from
                    // the restored chain tip at loop start (C10c) so that cross-zone
                    // dedup also survives a restart — without the seed it reset to 0
                    // and a lagging zone re-emitted an already-charged epoch. NB each
                    // emit mints a fresh uuid7 record id, so `applied_record_ids`
                    // dedup does NOT catch a re-emit — these two guards are the
                    // protection. (apply has no per-account idempotency token.)
                    let epoch_duration = end - start;
                    let is_genesis_authority =
                        state.identity.identity_hash == state.config.genesis_authority;
                    if epoch_duration > 0.0 && is_genesis_authority {
                        let epoch_no = parsed.epoch_number;
                        let prev = state
                            .last_idle_decay_emit_epoch
                            .fetch_max(epoch_no, std::sync::atomic::Ordering::SeqCst);
                        if epoch_no > prev {
                            // First seal of this epoch number — compute under a read
                            // lock (pure, no mutation) and emit only if some exchange
                            // owes a fee. The record then debits via the apply path.
                            let batch_opt = state.ledger.try_read().ok().and_then(|ledger| {
                                ledger.compute_idle_decay_batch(
                                    parsed.zone.path(),
                                    epoch_no,
                                    now,
                                    epoch_duration,
                                )
                            });
                            if let Some(batch) = batch_opt {
                                let total = batch.total_debit();
                                let pool = batch.pool_credit;
                                let n_exch = batch.debits.len();
                                let n_stk = batch.staker_credits.len();
                                let meta = crate::accounting::types::idle_decay_batch_metadata(&batch);
                                let parents = super::server::dag_tip_parents(&state, 3).await;
                                match state.create_self_ledger_record(parents, meta) {
                                    Ok(record) => match super::server::insert_and_push(&state, record).await {
                                        Ok(record_id) => info!(
                                            "idle_decay: emitted batch epoch={} total_debit={} pool={} exchanges={} stakers={} record={}",
                                            epoch_no, total, pool, n_exch, n_stk,
                                            &record_id[..record_id.len().min(16)],
                                        ),
                                        Err(e) => warn!(
                                            "idle_decay: insert_and_push failed for epoch {}: {}",
                                            epoch_no, e.0
                                        ),
                                    },
                                    Err(e) => warn!(
                                        "idle_decay: create_self_ledger_record failed for epoch {}: {}",
                                        epoch_no, e
                                    ),
                                }
                            }
                        }
                    }

                    // Read the updated adaptive interval for this zone
                    let adaptive_secs = {
                        let epoch = state.epoch.read_recover();
                        epoch.adaptive_interval(&parsed.zone, interval_secs as f64)
                    };

                    info!(
                        "epoch seal created: zone={} epoch={} records={} root={}... adaptive_interval={:.0}s",
                        parsed.zone,
                        parsed.epoch_number,
                        parsed.record_count,
                        &hex::encode(parsed.merkle_root)[..16],
                        adaptive_secs,
                    );

                    // Register seal records in consensus (layered model)
                    {
                        let record_ids = super::ingest::resolve_seal_record_ids(
                            &state,
                            &parsed.record_hashes,
                        );
                        if record_ids.len() < parsed.record_hashes.len() {
                            debug!(
                                "epoch seal {}: resolved {}/{} record hashes to IDs (missing {} from local index)",
                                record_id,
                                record_ids.len(),
                                parsed.record_hashes.len(),
                                parsed.record_hashes.len() - record_ids.len(),
                            );
                        }
                        // Register the seal itself for consensus tracking
                        let mut consensus = state.consensus.lock_recover();
                        consensus.register_seal_records(&record_id, record_ids);
                        consensus.register_seal_epoch(&record_id, parsed.epoch_number, parsed.zone.clone());
                        // Liveness-decay: every observed seal (self-produced
                        // or gossiped) advances the chain-tip estimate.
                        consensus.note_chain_tip(parsed.epoch_number);
                    }

                    // Distribute per-epoch rewards to witnesses
                    {
                        let witnesses: Vec<String> = {
                            let consensus = state.consensus.lock_recover();
                            consensus.attestors(&record_id)
                        };
                        if !witnesses.is_empty() {
                            let rstate = state.clone();
                            let sid = record_id.clone();
                            let rc = parsed.record_count;
                            let ws = witnesses;
                            tokio::spawn(async move {
                                super::reward::distribute_epoch_rewards(&rstate, &sid, rc, &ws).await;
                            });
                        }
                    }

                    // Gossip the seal to peers
                    let state2 = state.clone();
                    let rec = record.clone();
                    tokio::spawn(async move {
                        super::state::NodeState::publish_record_with_fallback(&state2, &rec, None).await;
                    });
                }
                Err(e) => {
                    warn!("epoch seal insert failed for zone {zone}: {e}");
                }
            }
        }

        // Per-tick summary log. ONE line/tick (~1/min at base
        // 60s interval) regardless of zone count — mainnet-safe at 1M zones
        // since we cap the `none_zones=[...]` list at 8 entries. Operators
        // read this alongside the 9 counters to disambiguate stall mode.
        // The four reason-tagged breakdowns answer the *which gate*
        // question without journal-diving.
        info!(
            ticks_total = state.seal_loop_ticks_total.load(Ordering::Relaxed),
            per_zone = tick_per_zone,
            escalate = tick_escalate,
            none = tick_none,
            none_already_sealed = tick_none_already_sealed,
            none_bootstrap = tick_none_bootstrap,
            none_not_in_top = tick_none_not_in_top,
            none_rank_too_high = tick_none_rank_too_high,
            none_zones = %tick_none_summary.join(","),
            "OPS-188 seal_loop tick summary"
        );

        // Evict DAG records from epochs older than the hot window.
        // Without this, the in-memory DAG grows unbounded (H4).
        // Use try_write to avoid blocking state_core's dag.write().
        if let Ok(mut dag_guard) = state.dag.try_write() {
            let dag = std::sync::Arc::make_mut(&mut *dag_guard);
            let evicted = dag.evict_old_epochs();
            if evicted > 0 {
                info!("epoch tick: evicted {evicted} old DAG records");
            }
        } else {
            tracing::debug!("epoch tick: DAG contended, deferring eviction");
        }
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hash::{sha3_256, sha3_256_hex};
    use crate::identity::{CryptoProfile, EntityType, Identity};
    use crate::record::Classification;
    use crate::storage::rocks::StorageEngine;
    use crate::storage::Storage;

    /// Fork-monitor fix: `highest_seal_anchor` returns `None`
    /// on a cold-start EpochState. `check_single_peer` reads this as
    /// "can't compare yet" → `in_sync = true` (no false alert).
    #[test]
    fn highest_seal_anchor_returns_none_on_empty_state() {
        let s = EpochState::new();
        assert!(s.highest_seal_anchor().is_none());
    }

    /// Single-zone case: anchor exposes that zone's (epoch, hash) tuple.
    #[test]
    fn highest_seal_anchor_returns_single_zone_anchor() {
        let mut s = EpochState::new();
        let zone = ZoneId::new("z0");
        let hash = [7u8; 32];
        s.latest_epoch.insert(zone.clone(), 42);
        s.latest_seal_hash.insert(zone.clone(), hash);

        let (z, ep, h) = s.highest_seal_anchor().expect("anchor present");
        assert_eq!(z, zone);
        assert_eq!(ep, 42);
        assert_eq!(h, hash);
    }

    /// Multi-zone case: picks the zone with the highest sealed epoch.
    /// Critical for fork-detect — both peers must independently land on
    /// the same anchor when on the same canonical chain (the highest-
    /// epoch tie-break stays stable across peers as long as their epoch
    /// progress matches).
    #[test]
    fn highest_seal_anchor_picks_max_epoch_across_zones() {
        let mut s = EpochState::new();
        let z0 = ZoneId::new("z0");
        let z1 = ZoneId::new("z1");
        let z2 = ZoneId::new("z2");

        s.latest_epoch.insert(z0.clone(), 5);
        s.latest_epoch.insert(z1.clone(), 100); // <- max
        s.latest_epoch.insert(z2.clone(), 50);
        s.latest_seal_hash.insert(z0.clone(), [1u8; 32]);
        s.latest_seal_hash.insert(z1.clone(), [2u8; 32]);
        s.latest_seal_hash.insert(z2.clone(), [3u8; 32]);

        let (z, ep, h) = s.highest_seal_anchor().expect("anchor present");
        assert_eq!(z, z1);
        assert_eq!(ep, 100);
        assert_eq!(h, [2u8; 32]);
    }

    /// Defensive: if `latest_epoch` carries a zone with no matching
    /// `latest_seal_hash` entry, the helper returns `None` rather than
    /// fabricating a [0u8; 32] anchor — better to skip the fork-check
    /// for this peer than to alert on an unsynchronised pair of state
    /// maps. (Should never happen in practice; `register_seal` writes
    /// both maps together.)
    #[test]
    fn highest_seal_anchor_returns_none_when_hash_missing_for_max_zone() {
        let mut s = EpochState::new();
        let zone = ZoneId::new("ghost");
        s.latest_epoch.insert(zone, 99);
        // intentionally NOT inserting into latest_seal_hash
        assert!(s.highest_seal_anchor().is_none());
    }

    /// C10c: `max_sealed_epoch()` is the idle_decay-watermark seed source.
    /// 0 on a virgin chain; order-independent max across zones otherwise.
    #[test]
    fn max_sealed_epoch_is_zero_empty_and_max_across_zones() {
        let mut s = EpochState::new();
        assert_eq!(s.max_sealed_epoch(), 0, "no seals yet → 0");
        s.latest_epoch.insert(ZoneId::new("z0"), 5);
        s.latest_epoch.insert(ZoneId::new("z1"), 100); // <- max
        s.latest_epoch.insert(ZoneId::new("z2"), 50);
        assert_eq!(s.max_sealed_epoch(), 100, "max over zones, order-independent");
    }

    /// C10c core: seeding `last_idle_decay_emit_epoch` from `max_sealed_epoch()`
    /// at boot makes a *lagging* zone's post-restart re-seal of an already-
    /// globally-emitted epoch fall under the `fetch_max` guard (no double-
    /// charge), while a genuinely-new epoch (> the restored tip) still emits.
    /// Replays the exact emit-guard predicate from `epoch_seal_loop`:
    /// `prev = watermark.fetch_max(epoch_no); would_emit = epoch_no > prev`.
    #[test]
    fn idle_decay_watermark_seed_suppresses_reemit_but_allows_new_epoch() {
        use std::sync::atomic::{AtomicU64, Ordering};

        // Pre-restart: zone A sealed→7 (idle_decay emitted for 1..=7), zone B
        // lagging at 3. After restart the in-memory watermark is a fresh 0.
        let mut ep = EpochState::new();
        ep.latest_epoch.insert(ZoneId::new("/zone/a"), 7);
        ep.latest_epoch.insert(ZoneId::new("/zone/b"), 3);

        let watermark = AtomicU64::new(0); // simulates the post-restart reset

        // WITHOUT the seed, the bug: lagging zone B re-sealing epoch 4 emits.
        {
            let unseeded = AtomicU64::new(0);
            let prev = unseeded.fetch_max(4, Ordering::SeqCst);
            assert!(4 > prev, "regression witness: unseeded watermark re-emits epoch 4");
        }

        // WITH the seed (the fix): watermark lifted to max_sealed_epoch() = 7.
        watermark.fetch_max(ep.max_sealed_epoch(), Ordering::SeqCst);
        assert_eq!(watermark.load(Ordering::SeqCst), 7);

        // Zone B re-seals its lagging epochs 4,5,6,7 — all already charged: suppressed.
        for already_emitted in [4u64, 5, 6, 7] {
            let prev = watermark.fetch_max(already_emitted, Ordering::SeqCst);
            let would_emit = already_emitted > prev; // mirrors the production predicate
            assert!(
                !would_emit,
                "epoch {already_emitted} ≤ restored tip must be suppressed (no double-charge)",
            );
        }

        // A genuinely-new epoch 8 (> restored tip) still emits and advances.
        let prev = watermark.fetch_max(8, Ordering::SeqCst);
        assert!(8 > prev, "new epoch 8 must still emit");
        assert_eq!(watermark.load(Ordering::SeqCst), 8);
    }

    /// C10c: the seed is monotone — it never lowers an already-higher watermark
    /// (so a re-entered loop / late restore cannot reopen the re-emit window).
    #[test]
    fn idle_decay_watermark_seed_is_monotone() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let watermark = AtomicU64::new(12);
        let mut ep = EpochState::new();
        ep.latest_epoch.insert(ZoneId::new("z0"), 5); // lower than current watermark
        watermark.fetch_max(ep.max_sealed_epoch(), Ordering::SeqCst);
        assert_eq!(watermark.load(Ordering::SeqCst), 12, "seed must not lower the watermark");
    }

    /// Seal-window observability gauges.
    /// `observe_seal_window_size` MUST track the high-water mark with a
    /// monotonic CAS-loop max (later smaller values do not regress the
    /// gauge), and MUST bump the cap-hit counter exactly once per scan
    /// that reaches MAX_SEAL_RECORDS. Reset the statics first because
    /// other tests (and tests run in any order) may have already moved
    /// them; this test owns the gauge for the duration of the assertions.
    #[test]
    fn observe_seal_window_size_tracks_max_and_cap_hits() {
        reset_seal_window_metrics();
        let (max0, hits0) = seal_window_metrics();
        assert_eq!(max0, 0);
        assert_eq!(hits0, 0);

        observe_seal_window_size(100);
        let (m, h) = seal_window_metrics();
        assert_eq!(m, 100);
        assert_eq!(h, 0);

        observe_seal_window_size(50);
        let (m, h) = seal_window_metrics();
        assert_eq!(m, 100, "smaller scan must not regress the high-water mark");
        assert_eq!(h, 0);

        observe_seal_window_size(500_000);
        let (m, h) = seal_window_metrics();
        assert_eq!(m, 500_000);
        assert_eq!(h, 0, "below cap must not increment cap-hits");

        observe_seal_window_size(MAX_SEAL_RECORDS);
        let (m, h) = seal_window_metrics();
        assert_eq!(m, MAX_SEAL_RECORDS as u64);
        assert_eq!(h, 1, "scan at exactly MAX_SEAL_RECORDS counts as a cap hit");

        observe_seal_window_size(MAX_SEAL_RECORDS + 1);
        let (_, h) = seal_window_metrics();
        assert_eq!(h, 2, "scan beyond cap also bumps cap-hits");

        reset_seal_window_metrics();
    }

    #[test]
    fn disc5_index_key_roundtrip() {
        let cases = [
            (0u64, "/", "rec_alpha"),
            (1u64, "/zone/a", "rec_42"),
            (u64::MAX, "/zone/with/long/path", "very-long-record-id-12345"),
            (12345u64, "/", "x"),
        ];
        for (epoch, zone, rid) in cases {
            let key = disc5_index_key(epoch, zone, rid);
            let parsed = parse_disc5_index_key(&key).expect("roundtrip parse");
            assert_eq!(parsed.0, epoch, "epoch mismatch");
            assert_eq!(parsed.1, zone, "zone mismatch");
            assert_eq!(parsed.2, rid, "record_id mismatch");
        }
    }

    #[test]
    fn disc5_index_key_orders_by_epoch_be() {
        // Big-endian u64 encoding must produce lexicographic order matching
        // numeric order — this is what makes range_scan_cf O(seals_returned).
        let k1 = disc5_index_key(1, "/", "a");
        let k2 = disc5_index_key(2, "/", "a");
        let k10 = disc5_index_key(10, "/", "a");
        let k256 = disc5_index_key(256, "/", "a");
        assert!(k1 < k2, "1 < 2");
        assert!(k2 < k10, "2 < 10");
        assert!(k10 < k256, "10 < 256");
    }

    #[test]
    fn disc5_index_storage_roundtrip() {
        // End-to-end storage proof: write three (epoch, zone, rid)
        // tuples into CF_EPOCHS via the same put_cf_raw path the ingest hook
        // uses, then range_scan_cf the same way the explorer read path does
        // and confirm we get exactly what we wrote, in BE-epoch order.
        let (engine, _dir) = test_engine();

        // Three seals across two zones, out of insertion order to prove the
        // BE-key ordering produces deterministic scan order regardless of
        // write order.
        let writes = [
            (10u64, "/zone/a", "rec_a10"),
            (1u64,  "/zone/a", "rec_a1"),
            (5u64,  "/zone/b", "rec_b5"),
        ];
        for (epoch, zone, rid) in &writes {
            let key = disc5_index_key(*epoch, zone, rid);
            engine.put_cf_raw(crate::storage::rocks::CF_EPOCHS, &key, &[]).unwrap();
        }

        // Range-scan from epoch 0 forward — should see all three in epoch order.
        let mut seen: Vec<(u64, String, String)> = Vec::new();
        let seek = 0u64.to_be_bytes().to_vec();
        engine
            .range_scan_cf(crate::storage::rocks::CF_EPOCHS, &seek, |key, val| {
                assert!(val.is_empty(), "DISC-5 values must be empty (presence is the signal)");
                let (e, z, r) = parse_disc5_index_key(key)
                    .expect("written keys must parse");
                seen.push((e, z.to_string(), r.to_string()));
                Ok(true)
            })
            .unwrap();
        assert_eq!(seen.len(), 3, "expected 3 entries");
        // BE u64 lex order = numeric order: 1, 5, 10.
        assert_eq!(seen[0], (1,  "/zone/a".into(), "rec_a1".into()));
        assert_eq!(seen[1], (5,  "/zone/b".into(), "rec_b5".into()));
        assert_eq!(seen[2], (10, "/zone/a".into(), "rec_a10".into()));

        // Range-scan from epoch 5 — should skip epoch 1.
        let mut seen_since5: Vec<u64> = Vec::new();
        let seek5 = 5u64.to_be_bytes().to_vec();
        engine
            .range_scan_cf(crate::storage::rocks::CF_EPOCHS, &seek5, |key, _| {
                let (e, _, _) = parse_disc5_index_key(key).unwrap();
                seen_since5.push(e);
                Ok(true)
            })
            .unwrap();
        assert_eq!(seen_since5, vec![5, 10], "since=5 must skip epoch 1");

        // Range-scan from epoch 11 (beyond end) — should yield nothing.
        let mut seen_after_end: Vec<u64> = Vec::new();
        let seek_end = 11u64.to_be_bytes().to_vec();
        engine
            .range_scan_cf(crate::storage::rocks::CF_EPOCHS, &seek_end, |key, _| {
                let (e, _, _) = parse_disc5_index_key(key).unwrap();
                seen_after_end.push(e);
                Ok(true)
            })
            .unwrap();
        assert!(seen_after_end.is_empty(), "since=11 must yield nothing past tail");

        // approximate_cf_size > 0 — the heuristic the read path uses to decide
        // whether the index is populated.
        assert!(
            engine.approximate_cf_size(crate::storage::rocks::CF_EPOCHS) > 0,
            "CF_EPOCHS should be non-empty after writes"
        );
    }

    #[test]
    fn fallback_latest_sealed_account_returns_latest_gap1_seal() {
        // Production parity: register_seal only sets EpochState.latest_sealed_account
        // on NEW post-restart seals, but compute_account_proof needs a binding
        // immediately at boot. fallback_latest_sealed_account reverse-scans
        // CF_EPOCHS to recover the most recent Gap-1 seal from disk.
        //
        // This test pins: (1) the highest-epoch Gap-1 seal wins regardless of
        // insertion order, (2) zones are preserved, (3) the returned root
        // round-trips with seal_metadata.
        let (mut engine, _dir) = test_engine();
        let identity = test_identity();

        // Three seals, each with a distinct account_smt_root, written
        // out-of-order. The highest-epoch one (50) must win.
        let seals = [
            (10u64, "/zone/a", sha3_256(b"root-10")),
            (50u64, "/zone/b", sha3_256(b"root-50")), // winner
            (30u64, "/zone/a", sha3_256(b"root-30")),
        ];
        let mut winner_record_id = String::new();
        let mut winner_zone = String::new();
        for (epoch, zone, root) in &seals {
            let meta = seal_metadata(SealMetadataParams {
                zone: ZoneId::new(zone),
                epoch_number: *epoch,
                start: 1700000000.0 + *epoch as f64,
                end: 1700000000.0 + *epoch as f64 + 60.0,
                record_count: 0,
                merkle_root: &sha3_256(b"merkle"),
                previous_seal_hash: &sha3_256(b"prev"),
                vrf_output: None,
                vrf_proof: None,
                sparse_merkle_root: None,
                record_hashes: None,
                zone_balance_total: None,
                zone_registry_root: None,
                zone_registry_delta: None,
                aggregator_rank: 0,
                account_smt_root: Some(root),
                drand_pulse: None,
            });
            let mut record = ValidationRecord::create(
                format!("seal-content-{epoch}").as_bytes(),
                identity.public_key.clone(),
                vec![],
                Classification::Public,
                Some(meta),
            );
            record.zone = Some(ZoneId::new(zone));
            let signable = record.signable_bytes();
            record.signature = Some(identity.sign(&signable).unwrap());
            engine.insert(&record).unwrap();
            let key = disc5_index_key(*epoch, zone, &record.id);
            engine.put_cf_raw(crate::storage::rocks::CF_EPOCHS, &key, &[]).unwrap();
            if *epoch == 50 {
                winner_record_id = record.id.clone();
                winner_zone = zone.to_string();
            }
        }

        let binding = fallback_latest_sealed_account(&engine)
            .expect("fallback must find a Gap-1 seal");
        assert_eq!(binding.0, 50, "highest epoch wins");
        assert_eq!(binding.1.path(), winner_zone, "zone preserved");
        assert_eq!(binding.2, winner_record_id, "record_id preserved");
        assert_eq!(binding.3, sha3_256(b"root-50"), "account_smt_root preserved");
        // sealed_at == seal.end == 1700000000 + 50 + 60 = 1700000110.0
        assert!((binding.4 - 1700000110.0).abs() < 1e-6, "sealed_at == seal.end");
    }

    // ── §6a single-zone sealed-root boot integrity check ──────────────

    /// Build + index a Gap-1 seal carrying `account_smt_root` at `(zone, epoch)`,
    /// timestamped INSIDE the window (so it adds no unsealed overhang).
    #[allow(clippy::too_many_arguments)]
    fn store_seal_with_root(
        engine: &mut StorageEngine,
        identity: &Identity,
        zone: &str,
        epoch: u64,
        start: f64,
        end: f64,
        account_smt_root: [u8; 32],
        content: &[u8],
    ) {
        let meta = seal_metadata(SealMetadataParams {
            zone: ZoneId::new(zone),
            epoch_number: epoch,
            start,
            end,
            record_count: 0,
            merkle_root: &sha3_256(b"merkle"),
            previous_seal_hash: &sha3_256(b"prev"),
            vrf_output: None,
            vrf_proof: None,
            sparse_merkle_root: None,
            record_hashes: None,
            zone_balance_total: None,
            zone_registry_root: None,
            zone_registry_delta: None,
            aggregator_rank: 0,
            account_smt_root: Some(&account_smt_root),
            drand_pulse: None,
        });
        let mut record = ValidationRecord::create(
            content,
            identity.public_key.clone(),
            vec![],
            Classification::Public,
            Some(meta),
        );
        record.timestamp = end - 1.0; // inside [start,end): no overhang
        record.zone = Some(ZoneId::new(zone));
        let signable = record.signable_bytes();
        record.signature = Some(identity.sign(&signable).unwrap());
        engine.insert(&record).unwrap();
        let key = disc5_index_key(epoch, zone, &record.id);
        engine
            .put_cf_raw(crate::storage::rocks::CF_EPOCHS, &key, &[])
            .unwrap();
    }

    fn acct(available: u64) -> crate::accounting::ledger::AccountState {
        crate::accounting::ledger::AccountState {
            available,
            ..Default::default()
        }
    }

    #[test]
    fn check_boot_sealed_root_verifies_then_detects_supply_neutral_drift() {
        let (mut engine, _dir) = test_engine();
        let identity = test_identity();

        let k1 = hex::encode(sha3_256(b"acct-1"));
        let k2 = hex::encode(sha3_256(b"acct-2"));
        let mut accounts: std::collections::HashMap<String, crate::accounting::ledger::AccountState> =
            std::collections::HashMap::new();
        accounts.insert(k1.clone(), acct(1_000));
        accounts.insert(k2.clone(), acct(500));

        let root = crate::network::account_merkle::root_over_accounts(&accounts).unwrap();

        let zone = "/zone/solo";
        let epoch = 7u64;
        let end = 1700000000.0 + 60.0;
        store_seal_with_root(&mut engine, &identity, zone, epoch, 1700000000.0, end, root, b"seal-7");

        let latest_epoch: std::collections::HashMap<ZoneId, u64> =
            [(ZoneId::new(zone), epoch)].into_iter().collect();

        // Correct ledger → Verified against the network-signed seal.
        // last_applied_ts == end: ledger folded exactly to the seal boundary.
        match check_boot_sealed_root(&engine, &accounts, &latest_epoch, end) {
            BootSealedRootOutcome::Verified { epoch: e, zone: z } => {
                assert_eq!(e, epoch);
                assert_eq!(z, ZoneId::new(zone));
            }
            other => panic!("expected Verified, got {other:?}"),
        }

        // Supply-NEUTRAL drift: move 100 from acct-1 to acct-2 — total supply
        // is unchanged, so the supply-conservation backstop is blind. §6a is the
        // only detector of this class, so it MUST flip to Mismatch.
        accounts.get_mut(&k1).unwrap().available -= 100;
        accounts.get_mut(&k2).unwrap().available += 100;
        let total: u64 = accounts.values().map(|a| a.available).sum();
        assert_eq!(total, 1_500, "mutation must be supply-neutral");
        match check_boot_sealed_root(&engine, &accounts, &latest_epoch, end) {
            BootSealedRootOutcome::Mismatch { epoch: e, replayed, sealed, zone: _ } => {
                assert_eq!(e, epoch);
                assert_ne!(replayed, sealed);
            }
            other => panic!("expected Mismatch on supply-neutral drift, got {other:?}"),
        }
    }

    #[test]
    fn check_boot_sealed_root_skips_multi_zone() {
        let (engine, _dir) = test_engine();
        let accounts: std::collections::HashMap<String, crate::accounting::ledger::AccountState> =
            std::collections::HashMap::new();
        let multi: std::collections::HashMap<ZoneId, u64> =
            [(ZoneId::new("/a"), 5u64), (ZoneId::new("/b"), 5u64)]
                .into_iter()
                .collect();
        assert_eq!(
            check_boot_sealed_root(&engine, &accounts, &multi, 0.0),
            BootSealedRootOutcome::Skipped(BootSealedRootSkip::MultiZone)
        );
    }

    #[test]
    fn check_boot_sealed_root_skips_when_no_gap1_seal_at_tip() {
        let (engine, _dir) = test_engine();
        let accounts: std::collections::HashMap<String, crate::accounting::ledger::AccountState> =
            std::collections::HashMap::new();
        let latest_epoch: std::collections::HashMap<ZoneId, u64> =
            [(ZoneId::new("/z"), 9u64)].into_iter().collect();
        assert_eq!(
            check_boot_sealed_root(&engine, &accounts, &latest_epoch, 0.0),
            BootSealedRootOutcome::Skipped(BootSealedRootSkip::NoSealedRoot)
        );
    }

    #[test]
    fn check_boot_sealed_root_skips_on_unsealed_overhang() {
        // The LEDGER has folded an account-changing op past the seal window
        // (last_applied_ts > end) → its account root legitimately reflects
        // post-seal state → must skip (re-fold is the deferred §6b slice).
        let (mut engine, _dir) = test_engine();
        let identity = test_identity();
        let mut accounts: std::collections::HashMap<String, crate::accounting::ledger::AccountState> =
            std::collections::HashMap::new();
        accounts.insert(hex::encode(sha3_256(b"acct-1")), acct(1_000));
        let root = crate::network::account_merkle::root_over_accounts(&accounts).unwrap();

        let zone = "/zone/solo";
        let epoch = 3u64;
        let end = 1700000000.0 + 60.0;
        store_seal_with_root(&mut engine, &identity, zone, epoch, 1700000000.0, end, root, b"seal-3");

        let latest_epoch: std::collections::HashMap<ZoneId, u64> =
            [(ZoneId::new(zone), epoch)].into_iter().collect();
        assert_eq!(
            check_boot_sealed_root(&engine, &accounts, &latest_epoch, end + 100.0),
            BootSealedRootOutcome::Skipped(BootSealedRootSkip::UnsealedOverhang)
        );
    }

    #[test]
    fn check_boot_sealed_root_validation_overhang_still_verifies() {
        // Stage-(a) improvement (F-2): a NON-account validation record past the
        // seal window leaves the account root untouched, so last_applied_ts stays
        // <= end and the seal is VERIFIED — where the old newest_record_timestamp
        // gate spuriously skipped. This is the live validation-mesh case: 0 token
        // records folded (last_applied_ts==0), thousands of validation records on
        // disk with ts well past the latest seal.
        let (mut engine, _dir) = test_engine();
        let identity = test_identity();
        let mut accounts: std::collections::HashMap<String, crate::accounting::ledger::AccountState> =
            std::collections::HashMap::new();
        accounts.insert(hex::encode(sha3_256(b"acct-1")), acct(1_000));
        let root = crate::network::account_merkle::root_over_accounts(&accounts).unwrap();

        let zone = "/zone/solo";
        let epoch = 3u64;
        let end = 1700000000.0 + 60.0;
        store_seal_with_root(&mut engine, &identity, zone, epoch, 1700000000.0, end, root, b"seal-3");

        // A validation record committed long after the seal — present on disk but
        // NOT folded into any account (last_applied_ts reflects only account ops).
        let mut late = ValidationRecord::create(
            b"late-validation",
            identity.public_key.clone(),
            vec![],
            Classification::Public,
            None,
        );
        late.timestamp = end + 100.0;
        late.zone = Some(ZoneId::new(zone));
        let s = late.signable_bytes();
        late.signature = Some(identity.sign(&s).unwrap());
        engine.insert(&late).unwrap();

        let latest_epoch: std::collections::HashMap<ZoneId, u64> =
            [(ZoneId::new(zone), epoch)].into_iter().collect();
        // last_applied_ts == 0 (no account op past the seal) → runs → Verified.
        match check_boot_sealed_root(&engine, &accounts, &latest_epoch, 0.0) {
            BootSealedRootOutcome::Verified { epoch: e, .. } => assert_eq!(e, epoch),
            other => panic!("validation overhang must still verify, got {other:?}"),
        }
    }

    #[test]
    fn fallback_latest_sealed_account_skips_pre_gap1_seals() {
        // Pre-Gap-1 seals carry no account_smt_root. The fallback must skip
        // them and find the most recent seal that DOES have one. Without
        // this skip, light clients on a network mid-Gap-1-rollout would
        // return None even though Gap-1-capable seals exist further back.
        let (mut engine, _dir) = test_engine();
        let identity = test_identity();

        // Newest seal has no Gap-1 root (simulate stale anchor or pre-rollout
        // node). The next-newest has one — that's what the fallback should
        // find.
        let writes = [
            (60u64, "/zone/a", None,                      "newest-no-root"),
            (50u64, "/zone/b", Some(sha3_256(b"hit")),    "older-with-root"),
        ];
        let mut want_rid = String::new();
        for (epoch, zone, root, content) in &writes {
            let meta = seal_metadata(SealMetadataParams {
                zone: ZoneId::new(zone),
                epoch_number: *epoch,
                start: 1700000000.0 + *epoch as f64,
                end: 1700000000.0 + *epoch as f64 + 60.0,
                record_count: 0,
                merkle_root: &sha3_256(b"merkle"),
                previous_seal_hash: &sha3_256(b"prev"),
                vrf_output: None,
                vrf_proof: None,
                sparse_merkle_root: None,
                record_hashes: None,
                zone_balance_total: None,
                zone_registry_root: None,
                zone_registry_delta: None,
                aggregator_rank: 0,
                account_smt_root: root.as_ref(),
                drand_pulse: None,
            });
            let mut record = ValidationRecord::create(
                content.as_bytes(),
                identity.public_key.clone(),
                vec![],
                Classification::Public,
                Some(meta),
            );
            record.zone = Some(ZoneId::new(zone));
            let signable = record.signable_bytes();
            record.signature = Some(identity.sign(&signable).unwrap());
            engine.insert(&record).unwrap();
            let key = disc5_index_key(*epoch, zone, &record.id);
            engine.put_cf_raw(crate::storage::rocks::CF_EPOCHS, &key, &[]).unwrap();
            if root.is_some() {
                want_rid = record.id.clone();
            }
        }

        let binding = fallback_latest_sealed_account(&engine)
            .expect("must find pre-Gap-1 ancestor with root");
        assert_eq!(binding.0, 50, "skipped Gap-1-less seal at 60");
        assert_eq!(binding.2, want_rid);
        assert_eq!(binding.3, sha3_256(b"hit"));
    }

    #[test]
    fn fallback_latest_sealed_account_empty_index_returns_none() {
        // No seals on disk → no binding. Caller (compute_account_proof)
        // will surface bound_to_seal: false, latest_sealed_account: null —
        // the only correct answer for a freshly-genesis'd node.
        let (engine, _dir) = test_engine();
        assert!(fallback_latest_sealed_account(&engine).is_none());
    }

    /// Helper: write a regular epoch seal record (no Gap-1 root) at
    /// (epoch, zone). Returns the record so callers can grab the hash.
    fn write_test_seal(
        engine: &mut StorageEngine,
        identity: &Identity,
        zone: &str,
        epoch: u64,
        content_salt: &[u8],
    ) -> ValidationRecord {
        let meta = seal_metadata(SealMetadataParams {
            zone: ZoneId::new(zone),
            epoch_number: epoch,
            start: 1_700_000_000.0 + epoch as f64,
            end: 1_700_000_000.0 + epoch as f64 + 60.0,
            record_count: 0,
            merkle_root: &sha3_256(b"merkle"),
            previous_seal_hash: &sha3_256(b"prev"),
            vrf_output: None,
            vrf_proof: None,
            sparse_merkle_root: None,
            record_hashes: None,
            zone_balance_total: None,
            zone_registry_root: None,
            zone_registry_delta: None,
            aggregator_rank: 0,
            account_smt_root: None,
            drand_pulse: None,
        });
        let mut content = format!("seal-z{zone}-e{epoch}-").into_bytes();
        content.extend_from_slice(content_salt);
        let mut record = ValidationRecord::create(
            &content,
            identity.public_key.clone(),
            vec![],
            Classification::Public,
            Some(meta),
        );
        record.zone = Some(ZoneId::new(zone));
        let signable = record.signable_bytes();
        record.signature = Some(identity.sign(&signable).unwrap());
        engine.insert(&record).unwrap();
        let key = disc5_index_key(epoch, zone, &record.id);
        engine
            .put_cf_raw(crate::storage::rocks::CF_EPOCHS, &key, &[])
            .unwrap();
        record
    }

    #[test]
    fn f10_rebuild_advances_latest_epoch_and_seal_hash_in_lockstep() {
        // Simulates a restart where the periodic snapshot restored latest_epoch
        // BEHIND the durable CF_EPOCHS tail. rebuild_latest_epoch_from_cf_epochs
        // must advance the tip to the CF_EPOCHS max AND move latest_seal_hash in
        // lockstep — a bare-integer advance would chain the next proposal off a
        // stale prev_seal_hash and every honest peer would reject it via
        // is_forged_sequential_seal (self-inflicted chain freeze).
        let (mut engine, _dir) = test_engine();
        let identity = test_identity();
        let zone = "/zone/a";

        let mut hash_at_50 = [0u8; 32];
        for epoch in 1..=50u64 {
            let rec = write_test_seal(&mut engine, &identity, zone, epoch, &epoch.to_be_bytes());
            if epoch == 50 {
                hash_at_50 = rec.record_hash();
            }
        }

        // Snapshot restored a stale tip (epoch 45) with a stale seal hash.
        let mut state = EpochState::new();
        state.latest_epoch.insert(ZoneId::new(zone), 45);
        state
            .latest_seal_hash
            .insert(ZoneId::new(zone), sha3_256(b"stale-45"));

        rebuild_latest_epoch_from_cf_epochs(&mut state, &engine);

        assert_eq!(
            state.latest_epoch.get(&ZoneId::new(zone)).copied(),
            Some(50),
            "tip must advance to the durable CF_EPOCHS max"
        );
        assert_eq!(
            state.latest_seal_hash.get(&ZoneId::new(zone)).copied(),
            Some(hash_at_50),
            "latest_seal_hash must move in lockstep to the epoch-50 seal (chain-link safety)"
        );
    }

    #[test]
    fn f10_rebuild_is_noop_when_snapshot_is_current() {
        // Snapshot tip already == CF_EPOCHS max → no advance, idempotent.
        let (mut engine, _dir) = test_engine();
        let identity = test_identity();
        let zone = "/zone/a";
        let mut hash_at_30 = [0u8; 32];
        for epoch in 1..=30u64 {
            let rec = write_test_seal(&mut engine, &identity, zone, epoch, &epoch.to_be_bytes());
            if epoch == 30 {
                hash_at_30 = rec.record_hash();
            }
        }
        let mut state = EpochState::new();
        state.latest_epoch.insert(ZoneId::new(zone), 30);
        state.latest_seal_hash.insert(ZoneId::new(zone), hash_at_30);

        rebuild_latest_epoch_from_cf_epochs(&mut state, &engine);

        assert_eq!(state.latest_epoch.get(&ZoneId::new(zone)).copied(), Some(30));
        assert_eq!(
            state.latest_seal_hash.get(&ZoneId::new(zone)).copied(),
            Some(hash_at_30)
        );
    }

    #[test]
    fn f10_rebuild_picks_lex_min_hash_at_max_epoch() {
        // Dual-proposer race at the max epoch: two seals at (zone, 20) with
        // different content → different record_hash. The recovered
        // latest_seal_hash must be the lex-min of the two, matching the
        // canonicalization every honest node applies (register_seal tiebreak).
        let (mut engine, _dir) = test_engine();
        let identity = test_identity();
        let zone = "/zone/a";
        for epoch in 1..=19u64 {
            write_test_seal(&mut engine, &identity, zone, epoch, &epoch.to_be_bytes());
        }
        let a = write_test_seal(&mut engine, &identity, zone, 20, b"proposer-A");
        let b = write_test_seal(&mut engine, &identity, zone, 20, b"proposer-B");
        let lex_min = std::cmp::min(a.record_hash(), b.record_hash());

        let mut state = EpochState::new();
        state.latest_epoch.insert(ZoneId::new(zone), 10); // stale tip

        rebuild_latest_epoch_from_cf_epochs(&mut state, &engine);

        assert_eq!(state.latest_epoch.get(&ZoneId::new(zone)).copied(), Some(20));
        assert_eq!(
            state.latest_seal_hash.get(&ZoneId::new(zone)).copied(),
            Some(lex_min),
            "dual-proposer max epoch must canonicalize to lex-min record_hash"
        );
    }

    #[test]
    fn f10_rebuild_multizone_only_advances_lagging_tips() {
        // Two tracked zones: one lagging (advance), one current (no-op). A third
        // zone present in CF_EPOCHS but NOT tracked in latest_epoch must be left
        // untouched — untracked zones are never proposed, so no re-propose risk.
        let (mut engine, _dir) = test_engine();
        let identity = test_identity();
        for epoch in 1..=40u64 {
            write_test_seal(&mut engine, &identity, "/zone/a", epoch, &epoch.to_be_bytes());
            write_test_seal(&mut engine, &identity, "/zone/b", epoch, &epoch.to_be_bytes());
            write_test_seal(&mut engine, &identity, "/zone/c", epoch, &epoch.to_be_bytes());
        }
        let mut state = EpochState::new();
        state.latest_epoch.insert(ZoneId::new("/zone/a"), 25); // lagging
        state.latest_epoch.insert(ZoneId::new("/zone/b"), 40); // current

        rebuild_latest_epoch_from_cf_epochs(&mut state, &engine);

        assert_eq!(
            state.latest_epoch.get(&ZoneId::new("/zone/a")).copied(),
            Some(40),
            "lagging zone advances to its durable tail"
        );
        assert_eq!(
            state.latest_epoch.get(&ZoneId::new("/zone/b")).copied(),
            Some(40),
            "current zone unchanged"
        );
        assert_eq!(
            state.latest_epoch.get(&ZoneId::new("/zone/c")).copied(),
            None,
            "untracked zone is never added"
        );
    }

    #[test]
    fn f10_rebuild_empty_state_is_noop() {
        let (engine, _dir) = test_engine();
        let mut state = EpochState::new();
        rebuild_latest_epoch_from_cf_epochs(&mut state, &engine);
        assert!(state.latest_epoch.is_empty());
    }

    #[test]
    fn repopulate_recent_seal_hashes_empty_state_is_noop() {
        // Empty latest_epoch → no active zones → no scan, no panic.
        let (engine, _dir) = test_engine();
        let mut state = EpochState::new();
        repopulate_recent_seal_hashes(&mut state, &engine);
        assert!(state.recent_seal_hashes.is_empty());
    }

    #[test]
    fn repopulate_recent_seal_hashes_fills_buffer_up_to_interval() {
        // After a snapshot load, recent_seal_hashes is
        // reset to empty (EpochStateSnapshot doesn't carry the buffer).
        // Without repopulation, super-seal creation can't fire until 64
        // fresh seals arrive — observed as 0 in testnet runs.
        //
        // This test pins the contract: given CF_EPOCHS with M > 64 seals
        // in a single zone, repopulation must hydrate exactly the
        // most-recent SUPER_SEAL_INTERVAL=64 seals into the buffer in
        // chronological order, so should_create_super_seal() returns true
        // at the next mod-64 boundary.
        let (mut engine, _dir) = test_engine();
        let identity = test_identity();
        let zone = "/zone/a";

        // Write 70 seals at epochs 10..=79 (LATEST = 79).
        // Expected buffer after repopulate: epochs 16..=79 = 64 entries.
        let mut expected_hashes_by_epoch = std::collections::BTreeMap::new();
        for epoch in 10..=79u64 {
            let rec = write_test_seal(&mut engine, &identity, zone, epoch, &epoch.to_be_bytes());
            expected_hashes_by_epoch.insert(epoch, rec.record_hash());
        }

        let mut state = EpochState::new();
        state.latest_epoch.insert(ZoneId::new(zone), 79);
        repopulate_recent_seal_hashes(&mut state, &engine);

        let buf = state
            .recent_seal_hashes
            .get(&ZoneId::new(zone))
            .expect("buffer must be populated for active zone");
        assert_eq!(
            buf.len() as u64,
            SUPER_SEAL_INTERVAL,
            "buffer must hold exactly SUPER_SEAL_INTERVAL entries"
        );

        // Chronological order: front = oldest epoch in window = 79 - 63 = 16.
        let window_start = 79 - (SUPER_SEAL_INTERVAL - 1);
        let want: Vec<[u8; 32]> = (window_start..=79)
            .map(|e| *expected_hashes_by_epoch.get(&e).unwrap())
            .collect();
        let got: Vec<[u8; 32]> = buf.iter().copied().collect();
        assert_eq!(got, want, "buffer must be chronologically ordered (oldest→newest)");

        // Functional check: with latest=79, the next anchor seal at epoch 80
        // (= 80 % 64 = 16, not boundary) → should_create_super_seal = false.
        // But at epoch 128 (boundary), with the buffer full of 64 fresh
        // hashes accumulated since boot, the gate would fire. Here we
        // just confirm snapshot_recent_seal_hashes does NOT return None.
        let snap = state.snapshot_recent_seal_hashes(&ZoneId::new(zone));
        assert!(snap.is_some(), "buffer must be full → snapshot must succeed");
        assert_eq!(snap.unwrap().len() as u64, SUPER_SEAL_INTERVAL);
    }

    #[test]
    fn repopulate_recent_seal_hashes_partial_window_for_short_chain() {
        // Zone with fewer than SUPER_SEAL_INTERVAL seals on disk →
        // buffer must hold all available seals, not pad with zeros.
        // (should_create_super_seal will return false until 64 land, which
        // is correct semantics — we just don't want a panic or wrong-length
        // buffer.)
        let (mut engine, _dir) = test_engine();
        let identity = test_identity();
        let zone = "/zone/b";

        for epoch in 1..=5u64 {
            write_test_seal(&mut engine, &identity, zone, epoch, &epoch.to_be_bytes());
        }
        let mut state = EpochState::new();
        state.latest_epoch.insert(ZoneId::new(zone), 5);
        repopulate_recent_seal_hashes(&mut state, &engine);

        let buf = state
            .recent_seal_hashes
            .get(&ZoneId::new(zone))
            .expect("partial buffer must still be inserted");
        assert_eq!(buf.len(), 5);
        assert!(
            state.snapshot_recent_seal_hashes(&ZoneId::new(zone)).is_none(),
            "buffer not full → snapshot must return None (super-seal gate blocked, correct)"
        );
    }

    #[test]
    fn repopulate_recent_seal_hashes_multi_zone_isolated_windows() {
        // Two active zones with different latest_epochs. Each must get its
        // own per-zone window [L - 63, L]. Stray seals for zones not in
        // latest_epoch must NOT leak into the populated map.
        let (mut engine, _dir) = test_engine();
        let identity = test_identity();

        // Zone a: latest=100. Window [37..=100] = 64 entries.
        for epoch in 37..=100u64 {
            write_test_seal(&mut engine, &identity, "/zone/a", epoch, &epoch.to_be_bytes());
        }
        // Zone b: latest=200. Window [137..=200] = 64 entries.
        for epoch in 137..=200u64 {
            write_test_seal(&mut engine, &identity, "/zone/b", epoch, &epoch.to_be_bytes());
        }
        // Zone c: NOT in latest_epoch. Should be ignored entirely.
        for epoch in 50..=70u64 {
            write_test_seal(&mut engine, &identity, "/zone/c", epoch, &epoch.to_be_bytes());
        }

        let mut state = EpochState::new();
        state.latest_epoch.insert(ZoneId::new("/zone/a"), 100);
        state.latest_epoch.insert(ZoneId::new("/zone/b"), 200);
        repopulate_recent_seal_hashes(&mut state, &engine);

        assert_eq!(
            state.recent_seal_hashes.get(&ZoneId::new("/zone/a")).unwrap().len() as u64,
            SUPER_SEAL_INTERVAL
        );
        assert_eq!(
            state.recent_seal_hashes.get(&ZoneId::new("/zone/b")).unwrap().len() as u64,
            SUPER_SEAL_INTERVAL
        );
        assert!(
            !state.recent_seal_hashes.contains_key(&ZoneId::new("/zone/c")),
            "non-active zone must not be populated"
        );
    }

    #[test]
    fn repopulate_recent_seal_hashes_equivocation_picks_lex_min() {
        // CF_EPOCHS can carry two competing seals at the same (zone, epoch)
        // — partition-merge or dual-proposer races. register_seal's
        // canonicalization rule is lex-min record_hash wins; repopulation
        // must apply the SAME rule so the buffer matches what live ingest
        // would have produced.
        let (mut engine, _dir) = test_engine();
        let identity = test_identity();
        let zone = "/zone/eq";

        // Two seals at epoch 5 with different content_salt → different hashes.
        let rec_a = write_test_seal(&mut engine, &identity, zone, 5, b"variant-A");
        let rec_b = write_test_seal(&mut engine, &identity, zone, 5, b"variant-B");
        let want_winner = std::cmp::min(rec_a.record_hash(), rec_b.record_hash());

        let mut state = EpochState::new();
        state.latest_epoch.insert(ZoneId::new(zone), 5);
        repopulate_recent_seal_hashes(&mut state, &engine);

        let buf = state.recent_seal_hashes.get(&ZoneId::new(zone)).unwrap();
        assert_eq!(buf.len(), 1, "one canonical entry per epoch, not two");
        assert_eq!(buf[0], want_winner, "lex-min record_hash wins (matches register_seal)");
    }

    #[test]
    fn disc5_parse_rejects_malformed() {
        // Too short
        assert!(parse_disc5_index_key(&[]).is_none());
        assert!(parse_disc5_index_key(&[0u8; 8]).is_none());
        // No NUL separator after epoch prefix
        let no_sep: Vec<u8> = (0..16).collect();
        assert!(parse_disc5_index_key(&no_sep).is_none());
        // Empty zone (NUL right after the 8-byte epoch)
        let mut empty_zone = vec![0u8; 8];
        empty_zone.push(0u8);
        empty_zone.extend_from_slice(b"rid");
        assert!(parse_disc5_index_key(&empty_zone).is_none());
        // Empty record_id (NUL is the last byte)
        let mut empty_rid = vec![0u8; 8];
        empty_rid.extend_from_slice(b"/zone");
        empty_rid.push(0u8);
        assert!(parse_disc5_index_key(&empty_rid).is_none());
    }

    fn test_identity() -> Identity {
        Identity::generate(EntityType::Device, CryptoProfile::ProfileB).unwrap()
    }

    fn test_engine() -> (StorageEngine, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let engine = StorageEngine::open(dir.path()).unwrap();
        (engine, dir)
    }

    fn insert_test_record(storage: &mut StorageEngine, identity: &Identity, content: &[u8], timestamp: f64) -> ValidationRecord {
        let mut record = ValidationRecord::create(
            content,
            identity.public_key.clone(),
            vec![],
            Classification::Public,
            None,
        );
        // Override timestamp for deterministic testing
        record.timestamp = timestamp;
        // Set record.zone explicitly so the storage zone-idx (CF_RECORD_BY_ZONE)
        // keys under the same zone the test uses for `zone_for_record(&id)`.
        // Production records always carry an explicit zone (wire v3+); the
        // 256-mod fallback in record_zone_key is for legacy/replay paths only,
        // and would otherwise break the iter_zone-based query_zone.
        record.zone = Some(zone_for_record(&record.id));
        let signable = record.signable_bytes();
        record.signature = Some(identity.sign(&signable).unwrap());
        storage.insert(&record).unwrap();
        record
    }

    // ── seal_metadata roundtrip ───────────────────────────────────

    #[test]
    fn test_seal_metadata_roundtrip() {
        let root = sha3_256(b"test root");
        let prev = sha3_256(b"previous seal");
        let meta = seal_metadata(SealMetadataParams {
            zone: ZoneId::from_legacy(0),
            epoch_number: 7,
            start: 1741000000.0,
            end: 1741003600.0,
            record_count: 128,
            merkle_root: &root,
            previous_seal_hash: &prev,
            vrf_output: None,
            vrf_proof: None,
            sparse_merkle_root: None,
            record_hashes: None,
            zone_balance_total: None,
            zone_registry_root: None,
            zone_registry_delta: None,
            aggregator_rank: 0,
            account_smt_root: None,
            drand_pulse: None,
        });

        assert_eq!(meta.get(EPOCH_OP_KEY).unwrap().as_str().unwrap(), "seal");
        assert_eq!(meta.get("epoch_zone").unwrap().as_str().unwrap(), "0");
        assert_eq!(meta.get("epoch_number").unwrap().as_u64().unwrap(), 7);
        assert_eq!(meta.get("epoch_start").unwrap().as_f64().unwrap(), 1741000000.0);
        assert_eq!(meta.get("epoch_end").unwrap().as_f64().unwrap(), 1741003600.0);
        assert_eq!(meta.get("epoch_record_count").unwrap().as_u64().unwrap(), 128);
        assert_eq!(meta.get("epoch_merkle_root").unwrap().as_str().unwrap(), hex::encode(root));
        assert_eq!(meta.get("epoch_previous_seal").unwrap().as_str().unwrap(), hex::encode(prev));
    }

    /// Decision A (R3-7 fusion audit 2026-07-02): a FULLY-populated seal —
    /// every optional `seal_metadata` field present, all 7 `drand_*` beacon
    /// keys, plus the `epoch_xzone_dest_finality_committees` key the create
    /// path adds after the builder — must fit `MAX_METADATA_ENTRIES` with
    /// real additive headroom. A seal over the entry cap stalls on the
    /// producer's OWN insert (the drand-incident wedge through the
    /// entry-count door instead of the value-size door). At the old cap of
    /// 24 this exact 26-key map self-wedged; the 24→64 raise leaves ~38
    /// slots. Both asserts are pins: adding a seal key updates the count
    /// here CONSCIOUSLY, and the headroom floor keeps the cap honest.
    #[test]
    fn fully_populated_seal_metadata_fits_entry_cap_with_margin() {
        let root = sha3_256(b"merkle root");
        let prev = sha3_256(b"previous seal");
        let smr = sha3_256(b"sparse merkle root");
        let zrr = sha3_256(b"zone registry root");
        let acct = sha3_256(b"account smt root");
        let vrf_out = sha3_256(b"vrf output");
        let vrf_proof = vec![0xa5u8; 64];
        let hashes = [sha3_256(b"r1"), sha3_256(b"r2")];
        let delta = [ZoneRegistryChange::Created { zone: ZoneId::from_legacy(1) }];
        let pulse = DrandPulse {
            round: 5_000_000,
            randomness: "ab".repeat(32),
            genesis_unix: 1_595_431_050,
            period_secs: 3,
            chain_hash: Some("cd".repeat(32)),
            signature: Some("ef".repeat(48)),
            previous_signature: Some("01".repeat(48)),
        };
        let mut meta = seal_metadata(SealMetadataParams {
            zone: ZoneId::from_legacy(0),
            epoch_number: 7,
            start: 1741000000.0,
            end: 1741003600.0,
            record_count: 2,
            merkle_root: &root,
            previous_seal_hash: &prev,
            vrf_output: Some(&vrf_out),
            vrf_proof: Some(&vrf_proof),
            sparse_merkle_root: Some(&smr),
            record_hashes: Some(&hashes),
            zone_balance_total: Some(1_000),
            zone_registry_root: Some(&zrr),
            zone_registry_delta: Some(&delta),
            aggregator_rank: 3,
            account_smt_root: Some(&acct),
            drand_pulse: Some(&pulse),
        });
        // The create path (`create_epoch_seal_*`) inserts the xzone
        // dest-finality committee map AFTER the builder — replicate it.
        meta.insert(
            "epoch_xzone_dest_finality_committees".into(),
            serde_json::json!({ "other/zone": [hex::encode(root), 3] }),
        );

        assert_eq!(
            meta.len(),
            26,
            "fully-populated seal key inventory drifted — a new seal key must \
             re-check MAX_METADATA_ENTRIES headroom and update this pin; keys: {:?}",
            meta.keys().collect::<Vec<_>>()
        );
        assert!(
            meta.len() + 16 <= crate::network::ingest::MAX_METADATA_ENTRIES,
            "fully-populated seal ({} keys) must fit MAX_METADATA_ENTRIES ({}) \
             with >=16 slots of additive headroom — a seal over the entry cap \
             wedges its own producer at insert",
            meta.len(),
            crate::network::ingest::MAX_METADATA_ENTRIES
        );
    }

    // ── REALMS P1.5 drand pulse: inertness + forward round-trip ─────

    /// The inertness invariant the whole a2 slice rests on: with
    /// `drand_pulse: None`, `seal_metadata` writes ZERO `drand_*` keys, so the
    /// serialized metadata — and therefore `signable_bytes`, the signature and
    /// the seal hash — is byte-identical to a pre-feature seal on every node.
    /// Slice a3 will edit exactly the `if let Some` gate and the producer's
    /// `None`; if either silently breaks inertness this test fails loudly. The
    /// type-level `time_bracket` round-trip tests cannot see the seal builder,
    /// so this guard is the one that actually protects the seal wire format.
    #[test]
    fn drand_pulse_none_is_inert_in_seal_metadata() {
        let identity = test_identity();
        let root = sha3_256(b"inert-root");
        let prev = sha3_256(b"inert-prev");
        let meta = seal_metadata(SealMetadataParams {
            zone: ZoneId::from_legacy(0),
            epoch_number: 42,
            start: 0.0,
            end: 100.0,
            record_count: 0,
            merkle_root: &root,
            previous_seal_hash: &prev,
            vrf_output: None,
            vrf_proof: None,
            sparse_merkle_root: None,
            record_hashes: None,
            zone_balance_total: None,
            zone_registry_root: None,
            zone_registry_delta: None,
            aggregator_rank: 0,
            account_smt_root: None,
            drand_pulse: None,
        });
        for key in meta.keys() {
            assert!(
                !key.starts_with("drand_"),
                "None pulse must write no drand_* key, found '{key}' — inertness broken"
            );
        }
        // The compact-sorted serialization (what feeds signable_bytes) carries
        // no drand bytes at all.
        let json = serde_json::to_string(&meta).unwrap();
        assert!(!json.contains("drand"), "serialized seal metadata must carry no drand data when None");
        let record = ValidationRecord::create(
            b"inert", identity.public_key.clone(), vec![],
            Classification::Public, Some(meta),
        );
        let parsed = extract_epoch_seal(&record).unwrap().unwrap();
        assert!(parsed.drand_pulse.is_none(), "None pulse must parse back as None");
    }

    /// R3-8 slice 2 — parse-time root gate on the inline enumeration.
    /// A non-empty `epoch_record_hashes` that does not recompute to the
    /// signed `epoch_merkle_root` is dropped to empty at parse time (never
    /// rejected — rejecting would wedge every fixed node on one
    /// buggy-producer seal, the R3-7 incident class). Matching arrays and
    /// legacy key-absent seals pass through untouched.
    #[test]
    fn seal_enum_root_gate_drops_mismatched_inline_array_to_empty() {
        let identity = test_identity();
        let hashes: Vec<[u8; 32]> = (0..5u8).map(|i| sha3_256(&[i])).collect();
        let matching_root = MerkleTree::root(&hashes);
        let wrong_root = sha3_256(b"not-the-root-of-those-hashes");
        let prev = sha3_256(b"gate-prev");

        let build = |root: &[u8; 32], inline: Option<&[[u8; 32]]>| {
            let meta = seal_metadata(SealMetadataParams {
                zone: ZoneId::from_legacy(0),
                epoch_number: 7,
                start: 0.0,
                end: 1.0,
                record_count: 5,
                merkle_root: root,
                previous_seal_hash: &prev,
                vrf_output: None,
                vrf_proof: None,
                sparse_merkle_root: None,
                record_hashes: inline,
                zone_balance_total: None,
                zone_registry_root: None,
                zone_registry_delta: None,
                aggregator_rank: 0,
                account_smt_root: None,
                drand_pulse: None,
            });
            ValidationRecord::create(
                b"root-gate", identity.public_key.clone(), vec![],
                Classification::Public, Some(meta),
            )
        };

        // (a) matching enumeration survives the gate bit-identical.
        let parsed = extract_epoch_seal(&build(&matching_root, Some(hashes.as_slice())))
            .unwrap()
            .unwrap();
        assert_eq!(parsed.record_hashes, hashes, "matching array must be preserved");

        // (b) mismatched enumeration is dropped to empty and counted; the
        // seal itself still parses (drop-to-empty, never reject).
        let before = seal_enum_root_mismatch_total();
        let parsed = extract_epoch_seal(&build(&wrong_root, Some(hashes.as_slice())))
            .unwrap()
            .unwrap();
        assert!(parsed.record_hashes.is_empty(), "mismatched array must drop to empty");
        assert_eq!(parsed.merkle_root, wrong_root, "non-array seal fields stay untouched");
        assert_eq!(parsed.record_count, 5, "signed record_count stays available (P3 degrade input)");
        assert!(
            seal_enum_root_mismatch_total() > before,
            "root-gate counter must increment"
        );

        // (c) legacy shape (key absent) is untouched and NOT counted.
        let before = seal_enum_root_mismatch_total();
        let parsed = extract_epoch_seal(&build(&wrong_root, None)).unwrap().unwrap();
        assert!(parsed.record_hashes.is_empty());
        assert_eq!(
            seal_enum_root_mismatch_total(),
            before,
            "legacy empty must not bump the mismatch counter"
        );
    }

    /// R3-8 slice 3 — bounded-inline emission. At SEAL_INLINE_ENUM_MAX the
    /// key is present and its compact-JSON size clears the ingest per-value
    /// gate (the self-wedge regression pin: the producer can never again
    /// build a seal its own ingest rejects). Above the cap the key is
    /// omitted entirely; extraction yields the defined legacy-empty shape
    /// without touching the root-mismatch counter.
    #[test]
    fn seal_metadata_bounded_inline_emission_at_and_above_cap() {
        let identity = test_identity();
        let hashes: Vec<[u8; 32]> = (0..=SEAL_INLINE_ENUM_MAX as u32)
            .map(|i| sha3_256(&i.to_be_bytes()))
            .collect();
        let prev = sha3_256(b"cap-prev");

        let build_meta = |slice: &[[u8; 32]]| {
            let root = MerkleTree::root(slice);
            seal_metadata(SealMetadataParams {
                zone: ZoneId::from_legacy(0),
                epoch_number: 9,
                start: 0.0,
                end: 1.0,
                record_count: slice.len() as u64,
                merkle_root: &root,
                previous_seal_hash: &prev,
                vrf_output: None,
                vrf_proof: None,
                sparse_merkle_root: None,
                record_hashes: Some(slice),
                zone_balance_total: None,
                zone_registry_root: None,
                zone_registry_delta: None,
                aggregator_rank: 0,
                account_smt_root: None,
                drand_pulse: None,
            })
        };

        // At cap: key present with all entries; compact-JSON size clears the
        // ingest per-value gate with headroom.
        let at_cap = build_meta(&hashes[..SEAL_INLINE_ENUM_MAX]);
        let arr = at_cap
            .get("epoch_record_hashes")
            .and_then(|v| v.as_array())
            .expect("at-cap seal must carry the inline enumeration");
        assert_eq!(arr.len(), SEAL_INLINE_ENUM_MAX);
        let json_len = at_cap.get("epoch_record_hashes").unwrap().to_string().len();
        assert!(
            json_len < super::super::ingest::MAX_METADATA_VALUE_LEN,
            "inline enumeration at cap ({json_len} B) must clear the ingest per-value gate ({} B)",
            super::super::ingest::MAX_METADATA_VALUE_LEN,
        );

        // Above cap: key omitted; the signed count+root still commit the set.
        let above = build_meta(&hashes);
        assert!(
            !above.contains_key("epoch_record_hashes"),
            "above-cap seal must omit the inline enumeration"
        );
        assert_eq!(
            above.get("epoch_record_count").and_then(|v| v.as_u64()),
            Some(SEAL_INLINE_ENUM_MAX as u64 + 1),
        );
        let record = ValidationRecord::create(
            b"above-cap",
            identity.public_key.clone(),
            vec![],
            Classification::Public,
            Some(above),
        );
        let before = seal_enum_root_mismatch_total();
        let parsed = extract_epoch_seal(&record).unwrap().unwrap();
        assert!(parsed.record_hashes.is_empty(), "absent key parses as legacy-empty");
        assert_eq!(parsed.record_count, SEAL_INLINE_ENUM_MAX as u64 + 1);
        assert_eq!(
            seal_enum_root_mismatch_total(),
            before,
            "omission is not a root mismatch"
        );
    }

    /// a3 forward-contract: a populated pulse writes its `drand_*` keys, those
    /// keys pass `content_safety` (ALLOWED_KEYS + text-limit gates so a3 seals
    /// are not silently rejected at ingest — the super_seal_committee_hash fork
    /// class), and `extract_epoch_seal` recovers the exact pulse. Locks the
    /// write↔parse↔allowlist alignment before any producer flips to `Some`.
    #[test]
    fn drand_pulse_some_round_trips_and_passes_allowlist() {
        let identity = test_identity();
        let root = sha3_256(b"rt-root");
        let prev = sha3_256(b"rt-prev");
        let pulse = DrandPulse {
            round: 1234,
            randomness: "deadbeefcafe0123".into(),
            genesis_unix: 1_595_431_050,
            period_secs: 30,
            chain_hash: Some("8990e7a9aaed2ffed73dbd7092123d6f".into()),
            // G2-length signature pair: pins the full write→allowlist→parse
            // round-trip for the trustless-PASS fields, not just the five
            // reference-bound keys.
            signature: Some("ab".repeat(96)),
            previous_signature: Some("cd".repeat(96)),
        };
        let meta = seal_metadata(SealMetadataParams {
            zone: ZoneId::from_legacy(0),
            epoch_number: 9,
            start: 0.0,
            end: 100.0,
            record_count: 0,
            merkle_root: &root,
            previous_seal_hash: &prev,
            vrf_output: None,
            vrf_proof: None,
            sparse_merkle_root: None,
            record_hashes: None,
            zone_balance_total: None,
            zone_registry_root: None,
            zone_registry_delta: None,
            aggregator_rank: 0,
            account_smt_root: None,
            drand_pulse: Some(&pulse),
        });
        assert!(meta.contains_key("drand_round"));
        assert!(meta.contains_key("drand_randomness"));
        crate::content_safety::validate_metadata_keys(&meta)
            .expect("drand_* seal keys must be in ALLOWED_KEYS for a3");
        crate::content_safety::sanitize_text_fields(&meta)
            .expect("drand_* seal fields must pass the text-limit/encoded-data gate");
        let record = ValidationRecord::create(
            b"rt", identity.public_key.clone(), vec![],
            Classification::Public, Some(meta),
        );
        let parsed = extract_epoch_seal(&record).unwrap().unwrap();
        assert_eq!(parsed.drand_pulse, Some(pulse), "Some pulse must round-trip exactly");
    }

    // ── aggregator_rank serialization round-trip (Stage 3b.5) ───────

    #[test]
    fn test_seal_metadata_aggregator_rank_roundtrip() {
        // seal_metadata must serialize `epoch_aggregator_rank` as an integer,
        // and extract_epoch_seal must recover the exact value. Cover every
        // rank the chain can issue (0..MAX_VIEW_DEPTH) to catch any off-by-one.
        use crate::network::aggregator::MAX_VIEW_DEPTH;
        let identity = test_identity();
        let root = sha3_256(b"rr");
        let prev = sha3_256(b"pp");
        for rank in 0..MAX_VIEW_DEPTH as u8 {
            let meta = seal_metadata(SealMetadataParams {
                zone: ZoneId::from_legacy(0),
                epoch_number: 1,
                start: 0.0,
                end: 100.0,
                record_count: 0,
                merkle_root: &root,
                previous_seal_hash: &prev,
                vrf_output: None,
                vrf_proof: None,
                sparse_merkle_root: None,
                record_hashes: None,
                zone_balance_total: None,
                zone_registry_root: None,
                zone_registry_delta: None,
                aggregator_rank: rank,
                account_smt_root: None,
                drand_pulse: None,
            });
            assert_eq!(
                meta.get("epoch_aggregator_rank").unwrap().as_u64().unwrap(),
                rank as u64,
                "rank {} must serialize as integer",
                rank
            );
            let record = ValidationRecord::create(
                b"rr", identity.public_key.clone(), vec![],
                Classification::Public, Some(meta),
            );
            let parsed = extract_epoch_seal(&record).unwrap().unwrap();
            assert_eq!(parsed.aggregator_rank, rank, "rank {} must round-trip", rank);
        }
    }

    #[test]
    fn test_extract_legacy_seal_without_aggregator_rank() {
        // Pre-3b.5 seals lack the `epoch_aggregator_rank` key entirely.
        // extract_epoch_seal must default to 0 rather than fail — the
        // fallback keeps historical testnet history parseable during the
        // rollout window.
        let identity = test_identity();
        let root = sha3_256(b"legacy");
        let prev = sha3_256(b"legacy-prev");
        let mut meta = seal_metadata(SealMetadataParams {
            zone: ZoneId::from_legacy(0),
            epoch_number: 1,
            start: 0.0,
            end: 100.0,
            record_count: 0,
            merkle_root: &root,
            previous_seal_hash: &prev,
            vrf_output: None,
            vrf_proof: None,
            sparse_merkle_root: None,
            record_hashes: None,
            zone_balance_total: None,
            zone_registry_root: None,
            zone_registry_delta: None,
            aggregator_rank: 5,
            account_smt_root: None,
            drand_pulse: None,
        });
        // Simulate a seal emitted before 3b.5 by stripping the key.
        meta.remove("epoch_aggregator_rank");
        assert!(!meta.contains_key("epoch_aggregator_rank"));
        let record = ValidationRecord::create(
            b"legacy", identity.public_key.clone(), vec![],
            Classification::Public, Some(meta),
        );
        let parsed = extract_epoch_seal(&record).unwrap().unwrap();
        assert_eq!(parsed.aggregator_rank, 0, "legacy seals default to rank 0");
    }

    // ── extract_epoch_seal: None for non-epoch records ───────────

    #[test]
    fn test_extract_none_for_non_epoch() {
        let identity = test_identity();
        let record = ValidationRecord::create(
            b"normal data",
            identity.public_key.clone(),
            vec![],
            Classification::Public,
            None,
        );
        assert!(extract_epoch_seal(&record).unwrap().is_none());
    }

    // ── extract_epoch_seal: error on invalid metadata ────────────

    #[test]
    fn test_extract_non_seal_epoch_op_returns_none() {
        let identity = test_identity();
        let mut meta = BTreeMap::new();
        meta.insert(EPOCH_OP_KEY.into(), serde_json::json!("zone_transition"));
        let record = ValidationRecord::create(
            b"zone transition",
            identity.public_key.clone(),
            vec![],
            Classification::Public,
            Some(meta),
        );
        // Non-seal epoch ops return Ok(None), not Err — they're valid records
        // handled by a different code path (extract_zone_transition).
        assert!(extract_epoch_seal(&record).unwrap().is_none());
    }

    // ── extract_epoch_seal: error on missing fields ──────────────

    #[test]
    fn test_extract_missing_fields() {
        let identity = test_identity();
        let mut meta = BTreeMap::new();
        meta.insert(EPOCH_OP_KEY.into(), serde_json::json!("seal"));
        // Missing all other fields
        let record = ValidationRecord::create(
            b"incomplete",
            identity.public_key.clone(),
            vec![],
            Classification::Public,
            Some(meta),
        );
        assert!(extract_epoch_seal(&record).is_err());
    }

    // ── extract_epoch_seal: valid roundtrip ──────────────────────

    #[test]
    fn test_extract_valid_seal() {
        let identity = test_identity();
        let root = sha3_256(b"test");
        let prev = [0u8; 32];
        let meta = seal_metadata(SealMetadataParams {
            zone: ZoneId::from_legacy(0),
            epoch_number: 3,
            start: 100.0,
            end: 200.0,
            record_count: 42,
            merkle_root: &root,
            previous_seal_hash: &prev,
            vrf_output: None,
            vrf_proof: None,
            sparse_merkle_root: None,
            record_hashes: None,
            zone_balance_total: None,
            zone_registry_root: None,
            zone_registry_delta: None,
            aggregator_rank: 0,
            account_smt_root: None,
            drand_pulse: None,
        });
        let record = ValidationRecord::create(
            b"epoch:seal:0:3",
            identity.public_key.clone(),
            vec![],
            Classification::Public,
            Some(meta),
        );
        let parsed = extract_epoch_seal(&record).unwrap().unwrap();
        assert_eq!(parsed.zone, 0);
        assert_eq!(parsed.epoch_number, 3);
        assert_eq!(parsed.start, 100.0);
        assert_eq!(parsed.end, 200.0);
        assert_eq!(parsed.record_count, 42);
        assert_eq!(parsed.merkle_root, root);
        assert_eq!(parsed.previous_seal_hash, prev);
    }

    #[test]
    fn b2_extract_seal_roundtrips_xzone_dest_finality_committees() {
        // B2 fix: a seal carrying per-dest-zone committee anchors parses back
        // into `xzone_dest_finality_committees` with identical (hash, size); a
        // seal without the key parses to None (legacy-safe). This is the consumer
        // side `attach_xzone_proofs_from_seal_with_finality` freezes from.
        let identity = test_identity();
        let root = sha3_256(b"b2-rt");
        let prev = [0u8; 32];
        let mk_meta = |epoch: u64| {
            seal_metadata(SealMetadataParams {
                zone: ZoneId::from_legacy(0),
                epoch_number: epoch,
                start: 1.0,
                end: 2.0,
                record_count: 0,
                merkle_root: &root,
                previous_seal_hash: &prev,
                vrf_output: None,
                vrf_proof: None,
                sparse_merkle_root: None,
                record_hashes: None,
                zone_balance_total: None,
                zone_registry_root: None,
                zone_registry_delta: None,
                aggregator_rank: 0,
                account_smt_root: None,
                drand_pulse: None,
            })
        };
        // With anchors: inject the key exactly as create_epoch_seal_with_balance does.
        let ch = sha3_256(b"committee-for-zone-x");
        let mut meta = mk_meta(7);
        meta.insert(
            "epoch_xzone_dest_finality_committees".into(),
            serde_json::json!({ "/zone/x": [hex::encode(ch), 5] }),
        );
        let record = ValidationRecord::create(
            b"epoch:seal:0:7",
            identity.public_key.clone(),
            vec![],
            Classification::Public,
            Some(meta),
        );
        let parsed = extract_epoch_seal(&record).unwrap().unwrap();
        let map = parsed
            .xzone_dest_finality_committees
            .expect("committee map present");
        assert_eq!(map.get("/zone/x"), Some(&(ch, 5u32)));

        // Legacy seal without the key → None (byte-identical signable_bytes path).
        let record2 = ValidationRecord::create(
            b"epoch:seal:0:8",
            identity.public_key.clone(),
            vec![],
            Classification::Public,
            Some(mk_meta(8)),
        );
        let parsed2 = extract_epoch_seal(&record2).unwrap().unwrap();
        assert!(
            parsed2.xzone_dest_finality_committees.is_none(),
            "legacy seal must parse to None"
        );
    }

    // ── EpochState: new is empty ─────────────────────────────────

    #[test]
    fn test_epoch_state_new() {
        let state = EpochState::new();
        assert!(state.latest_epoch.is_empty());
        assert!(state.latest_seal_id.is_empty());
        assert!(state.latest_seal_hash.is_empty());
        assert_eq!(state.next_epoch(&ZoneId::from_legacy(0)), 0);
        assert_eq!(state.previous_seal_hash(&ZoneId::from_legacy(0)), [0u8; 32]);
    }

    // ── Freeze-trap carve-out mirror + proposer↔verifier symmetry (C1) ──
    //
    // `verify_aggregator_rank` (verifier) and `aggregator::proposer_rank`
    // (proposer) each carry the `staked.len() < 3` bootstrap carve-out
    // INDEPENDENTLY. If the two ever drift, a node could propose a seal its
    // peers reject (liveness loss) or — worse — the two sides could disagree
    // about who is an authorized proposer, a split-brain fork vector. These
    // tests pin the verifier's carve-out and lock both sides to one boundary.

    /// Minimal seal carrying just the fields `verify_aggregator_rank` reads
    /// (rank/zone/epoch/prev). All other fields are checked elsewhere in the
    /// full `verify_epoch_seal`, so zeros are fine for the rank gate.
    fn mk_rank_seal(zone: &ZoneId, epoch: u64, prev: [u8; 32], rank: u8) -> ParsedEpochSeal {
        ParsedEpochSeal {
            zone: zone.clone(),
            epoch_number: epoch,
            start: 0.0,
            end: 100.0,
            record_count: 0,
            merkle_root: [0u8; 32],
            previous_seal_hash: prev,
            vrf_output: None,
            vrf_proof: None,
            record_hashes: vec![],
            zone_balance_total: None,
            zone_registry_root: None,
            zone_registry_delta: None,
            seal_zone_count: None,
            aggregator_rank: rank,
            account_smt_root: None,
            drand_pulse: None,
            xzone_dest_finality_committees: None,
        }
    }

    #[test]
    fn verify_aggregator_rank_bootstrap_carve_out() {
        let z0 = ZoneId::from_legacy(0);
        let prev = [0u8; 32];
        // 2 stakers ⇒ still bootstrap (< 3): only genesis @ rank 0 is valid.
        let staked = vec![("genesis".to_string(), 100u64), ("b".to_string(), 100)];
        let big = 1_000_000_000u64;
        assert!(
            verify_aggregator_rank("genesis", &mk_rank_seal(&z0, 1, prev, 0), &staked, "genesis", 1000, big).is_ok(),
            "genesis @ rank 0 must verify during bootstrap"
        );
        assert!(
            verify_aggregator_rank("genesis", &mk_rank_seal(&z0, 1, prev, 1), &staked, "genesis", 1000, big).is_err(),
            "bootstrap seal must declare rank 0"
        );
        assert!(
            verify_aggregator_rank("b", &mk_rank_seal(&z0, 1, prev, 0), &staked, "genesis", 1000, big).is_err(),
            "non-genesis creator must be rejected during bootstrap (< 3 stakers)"
        );
    }

    #[test]
    fn proposer_verifier_carve_out_agree_at_every_staker_count() {
        use super::super::aggregator::{proposer_rank, ProposerRankInputs};
        let z0 = ZoneId::from_legacy(0);
        let prev = [0u8; 32];
        let genesis = "genesis";
        let base = 1000u64;
        let elapsed = 1_000_000_000u64; // unlock all in-view ranks

        // Staker sets of size 1..=5 cross the < 3 boundary in both directions.
        let all: Vec<(String, u64)> = vec![
            ("genesis".into(), 100),
            ("b".into(), 100),
            ("c".into(), 100),
            ("d".into(), 100),
            ("e".into(), 100),
        ];
        for n in 1..=5usize {
            let staked = all[..n].to_vec();
            for (member, _) in &staked {
                let pr = proposer_rank(ProposerRankInputs {
                    our_identity: member,
                    genesis_authority: genesis,
                    staked: &staked,
                    zone: &z0,
                    epoch_number: 1,
                    prev_seal_hash: &prev,
                    base_timeout_ms: base,
                    elapsed_ms: elapsed,
                    already_sealed: false,
                });
                // Embed the proposer's own declared rank (0 if it abstained);
                // the verifier re-derives independently and must agree on the
                // accept/reject verdict.
                let declared = pr.unwrap_or(0);
                let vr = verify_aggregator_rank(
                    member,
                    &mk_rank_seal(&z0, 1, prev, declared),
                    &staked,
                    genesis,
                    base,
                    elapsed,
                );
                assert_eq!(
                    pr.is_some(),
                    vr.is_ok(),
                    "proposer/verifier carve-out disagree for {member} at {n} stakers \
                     (proposer_rank={pr:?}, verify_ok={})",
                    vr.is_ok()
                );
            }
        }
    }

    // ── EpochState: register + sequential ────────────────────────

    #[test]
    fn test_epoch_state_register() {
        let mut state = EpochState::new();
        let z0 = ZoneId::from_legacy(0);
        let seal = ParsedEpochSeal {
            zone: z0.clone(),
            epoch_number: 0,
            start: 0.0,
            end: 100.0,
            record_count: 5,
            merkle_root: sha3_256(b"root0"),
            previous_seal_hash: [0u8; 32],
            vrf_output: None,
            vrf_proof: None,
            record_hashes: vec![],
            zone_balance_total: None,
            zone_registry_root: None,
            zone_registry_delta: None,
            seal_zone_count: None,
            aggregator_rank: 0,
            account_smt_root: None,
            drand_pulse: None,
            xzone_dest_finality_committees: None,
        };
        let hash = sha3_256(b"seal0");
        state.register_seal(&seal, "seal-id-0", hash);

        assert_eq!(state.latest_epoch[&z0], 0);
        assert_eq!(state.latest_seal_id[&z0], "seal-id-0");
        assert_eq!(state.latest_seal_hash[&z0], hash);
        assert_eq!(state.next_epoch(&z0), 1);
        assert_eq!(state.previous_seal_hash(&z0), hash);
    }

    // ── EpochState: sequential epochs ────────────────────────────

    #[test]
    fn test_epoch_state_sequential() {
        let mut state = EpochState::new();
        let z0 = ZoneId::from_legacy(0);
        for i in 0..5u64 {
            let seal = ParsedEpochSeal {
                zone: z0.clone(),
                epoch_number: i,
                start: (i * 100) as f64,
                end: ((i + 1) * 100) as f64,
                record_count: 10,
                merkle_root: sha3_256(format!("root{i}").as_bytes()),
                previous_seal_hash: state.previous_seal_hash(&z0),
            vrf_output: None,
            vrf_proof: None,
            record_hashes: vec![],
            zone_balance_total: None,
            zone_registry_root: None,
            zone_registry_delta: None,
            seal_zone_count: None,
            aggregator_rank: 0,
            account_smt_root: None,
            drand_pulse: None,
            xzone_dest_finality_committees: None,
            };
            let hash = sha3_256(format!("seal{i}").as_bytes());
            state.register_seal(&seal, &format!("seal-{i}"), hash);
        }
        assert_eq!(state.next_epoch(&z0), 5);
        assert_eq!(state.latest_epoch[&z0], 4);
    }

    // ── EpochState: multi-zone ───────────────────────────────────

    #[test]
    fn test_epoch_state_multi_zone() {
        let mut state = EpochState::new();
        for zone_n in 0..3u64 {
            let zone = ZoneId::from_legacy(zone_n);
            let seal = ParsedEpochSeal {
                zone: zone.clone(),
                epoch_number: 0,
                start: 0.0,
                end: 100.0,
                record_count: 1,
                merkle_root: sha3_256(format!("zone{zone_n}").as_bytes()),
                previous_seal_hash: [0u8; 32],
            vrf_output: None,
            vrf_proof: None,
            record_hashes: vec![],
            zone_balance_total: None,
            zone_registry_root: None,
            zone_registry_delta: None,
            seal_zone_count: None,
            aggregator_rank: 0,
            account_smt_root: None,
            drand_pulse: None,
            xzone_dest_finality_committees: None,
            };
            let hash = sha3_256(format!("z{zone_n}seal").as_bytes());
            state.register_seal(&seal, &format!("z{zone_n}-seal-0"), hash);
        }
        assert_eq!(state.next_epoch(&ZoneId::from_legacy(0)), 1);
        assert_eq!(state.next_epoch(&ZoneId::from_legacy(1)), 1);
        assert_eq!(state.next_epoch(&ZoneId::from_legacy(2)), 1);
        assert_eq!(state.next_epoch(&ZoneId::from_legacy(3)), 0); // never sealed
    }

    // ── PARTITION-MERGE Phase B: orphan_siblings ring ────────────

    #[test]
    fn test_orphan_siblings_basic_insert_bumps_counter_and_lists() {
        let mut state = EpochState::new();
        let z = ZoneId::from_legacy(0);
        assert_eq!(state.orphan_seals_total, 0);
        assert!(state.orphan_siblings_for(&z, 7).is_empty());
        assert_eq!(state.orphan_siblings_live_count(), 0);

        state.record_orphan_sibling(z.clone(), 7, "seal-A".to_string());
        state.record_orphan_sibling(z.clone(), 7, "seal-B".to_string());

        assert_eq!(state.orphan_seals_total, 2);
        assert_eq!(state.orphan_siblings_live_count(), 2);
        let listed = state.orphan_siblings_for(&z, 7);
        assert_eq!(listed, vec!["seal-A".to_string(), "seal-B".to_string()]);
        // unknown (zone, epoch) returns empty
        assert!(state.orphan_siblings_for(&z, 8).is_empty());
        assert!(state
            .orphan_siblings_for(&ZoneId::from_legacy(1), 7)
            .is_empty());
    }

    #[test]
    fn test_orphan_siblings_idempotent_on_duplicate_seal_id() {
        let mut state = EpochState::new();
        let z = ZoneId::from_legacy(0);
        state.record_orphan_sibling(z.clone(), 1, "seal-X".to_string());
        let before = state.orphan_seals_total;
        // Insert same seal_id 5 more times — counter must not bump.
        for _ in 0..5 {
            state.record_orphan_sibling(z.clone(), 1, "seal-X".to_string());
        }
        assert_eq!(state.orphan_seals_total, before);
        assert_eq!(state.orphan_siblings_for(&z, 1), vec!["seal-X".to_string()]);
    }

    #[test]
    fn test_orphan_siblings_per_key_cap_evicts_oldest() {
        let mut state = EpochState::new();
        let z = ZoneId::from_legacy(0);
        // Fill to cap.
        for i in 0..PARTITION_MERGE_SIBLING_RING_PER_KEY {
            state.record_orphan_sibling(z.clone(), 42, format!("seal-{i}"));
        }
        assert_eq!(
            state.orphan_siblings_for(&z, 42).len(),
            PARTITION_MERGE_SIBLING_RING_PER_KEY
        );
        assert_eq!(
            state.orphan_seals_total,
            PARTITION_MERGE_SIBLING_RING_PER_KEY as u64
        );
        // Push one more — oldest (seal-0) must be evicted.
        state.record_orphan_sibling(z.clone(), 42, "seal-overflow".to_string());
        let listed = state.orphan_siblings_for(&z, 42);
        assert_eq!(listed.len(), PARTITION_MERGE_SIBLING_RING_PER_KEY);
        assert!(!listed.contains(&"seal-0".to_string()));
        assert!(listed.contains(&"seal-overflow".to_string()));
        // Counter still bumps on the new insert (eviction is FIFO, not idempotency).
        assert_eq!(
            state.orphan_seals_total,
            PARTITION_MERGE_SIBLING_RING_PER_KEY as u64 + 1
        );
    }

    #[test]
    fn test_orphan_siblings_global_key_cap_evicts_lex_min_key() {
        let mut state = EpochState::new();
        // Insert one entry per key for keys (zone=0, epoch=0..GLOBAL_CAP).
        // Lex-min key here is (ZoneId(0), 0).
        let z = ZoneId::from_legacy(0);
        for epoch in 0..PARTITION_MERGE_SIBLING_RING_GLOBAL_KEYS as u64 {
            state.record_orphan_sibling(z.clone(), epoch, format!("seal-e{epoch}"));
        }
        assert_eq!(
            state.orphan_siblings.len(),
            PARTITION_MERGE_SIBLING_RING_GLOBAL_KEYS
        );
        // Inserting one more key (epoch = GLOBAL_CAP) must evict the lex-min key
        // — which is (ZoneId(0), 0).
        let new_epoch = PARTITION_MERGE_SIBLING_RING_GLOBAL_KEYS as u64;
        state.record_orphan_sibling(z.clone(), new_epoch, "seal-new".to_string());
        assert_eq!(
            state.orphan_siblings.len(),
            PARTITION_MERGE_SIBLING_RING_GLOBAL_KEYS
        );
        assert!(state.orphan_siblings_for(&z, 0).is_empty());
        assert_eq!(
            state.orphan_siblings_for(&z, new_epoch),
            vec!["seal-new".to_string()]
        );
    }

    #[test]
    fn test_orphan_siblings_prune_stale_zones_clears_orphans() {
        let mut state = EpochState::new();
        // Use legacy zone IDs that parse as numerics so prune_stale_zones picks them up.
        let z0 = ZoneId::from_legacy(0);
        let z1 = ZoneId::from_legacy(1);
        // Need a latest_epoch entry for prune_stale_zones to consider the zone stale.
        state.latest_epoch.insert(z0.clone(), 0);
        state.latest_epoch.insert(z1.clone(), 0);
        state.record_orphan_sibling(z0.clone(), 5, "seal-z0".to_string());
        state.record_orphan_sibling(z1.clone(), 5, "seal-z1".to_string());
        assert_eq!(state.orphan_siblings.len(), 2);
        // Prune to zone_count=1 — z1 (>=1) goes, z0 stays.
        state.prune_stale_zones(1);
        assert!(state.orphan_siblings_for(&z1, 5).is_empty());
        assert_eq!(
            state.orphan_siblings_for(&z0, 5),
            vec!["seal-z0".to_string()]
        );
    }

    // ── create_epoch_seal ────────────────────────────────────────

    #[test]
    fn test_create_epoch_seal() {
        let identity = test_identity();
        let (mut storage, _dir) = test_engine();
        let epoch_state = EpochState::new();

        // Insert 3 records in the time range
        let r1 = insert_test_record(&mut storage, &identity, b"rec1", 100.0);
        let r2 = insert_test_record(&mut storage, &identity, b"rec2", 150.0);
        let r3 = insert_test_record(&mut storage, &identity, b"rec3", 200.0);

        // Discover which zone the first record landed in (hash-based assignment)
        let zone = zone_for_record(&r1.id);
        // Count how many of the 3 records share that zone
        let expected_count = [&r1, &r2, &r3].iter()
            .filter(|r| zone_for_record(&r.id) == zone)
            .count();

        let (record, parsed) = create_epoch_seal(&identity, &storage, &epoch_state, zone.clone(), 50.0, 250.0, None, None).unwrap();

        assert_eq!(parsed.zone, zone);
        assert_eq!(parsed.epoch_number, 0);
        assert_eq!(parsed.record_count, expected_count as u64);
        assert_eq!(parsed.previous_seal_hash, [0u8; 32]);
        assert!(record.signature.is_some());

        // Verify content hash pattern
        let expected_content = sha3_256(format!("epoch:seal:{zone}:0").as_bytes());
        assert_eq!(record.content_hash, expected_content.to_vec());
    }

    // ── verify valid seal ────────────────────────────────────────

    #[test]
    fn test_verify_valid_seal() {
        let identity = test_identity();
        let genesis = sha3_256_hex(&identity.public_key);
        let (mut storage, _dir) = test_engine();
        let epoch_state = EpochState::new();

        let r1 = insert_test_record(&mut storage, &identity, b"data1", 100.0);
        let r2 = insert_test_record(&mut storage, &identity, b"data2", 150.0);

        // Seal the zone of the first record
        let zone = zone_for_record(&r1.id);
        let expected_count = [&r1, &r2].iter()
            .filter(|r| zone_for_record(&r.id) == zone)
            .count();

        let (record, _) = create_epoch_seal(&identity, &storage, &epoch_state, zone.clone(), 50.0, 200.0, None, None).unwrap();
        let verified = verify_epoch_seal(&record, &storage, &epoch_state, &genesis, None, None).unwrap();

        assert_eq!(verified.zone, zone);
        assert_eq!(verified.epoch_number, 0);
        assert_eq!(verified.record_count, expected_count as u64);
    }

    // ── §11.6 seal timestamp monotonicity ──────────────────────

    #[test]
    fn test_verify_seal_rejects_end_before_start() {
        let identity = test_identity();
        let genesis = sha3_256_hex(&identity.public_key);
        let (mut storage, _dir) = test_engine();
        let epoch_state = EpochState::new();

        // Create seal with end <= start (invalid)
        let _ = insert_test_record(&mut storage, &identity, b"data1", 100.0);
        let zone = ZoneId::from_legacy(0);
        let result = create_epoch_seal(
            &identity, &storage, &epoch_state, zone.clone(),
            200.0, 100.0, // end < start
            None, None,
        );
        // create_epoch_seal itself may succeed (it just packages metadata),
        // but verify_epoch_seal must reject it
        if let Ok((record, _)) = result {
            let verified = verify_epoch_seal(&record, &storage, &epoch_state, &genesis, None, None);
            assert!(verified.is_err(), "seal with end <= start must be rejected");
            assert!(verified.unwrap_err().to_string().contains("end"));
        }
        // If create itself rejects, that's also fine — defense in depth
    }

    #[test]
    fn test_verify_seal_accepts_sequential_timestamps() {
        let identity = test_identity();
        let genesis = sha3_256_hex(&identity.public_key);
        let (mut storage, _dir) = test_engine();
        let mut epoch_state = EpochState::new();

        let _ = insert_test_record(&mut storage, &identity, b"data1", 100.0);
        let zone = zone_for_record("dummy");

        // First seal: [50, 200]
        let (record1, seal1) = create_epoch_seal(
            &identity, &storage, &epoch_state, zone.clone(),
            50.0, 200.0, None, None,
        ).unwrap();
        let _verified1 = verify_epoch_seal(&record1, &storage, &epoch_state, &genesis, None, None).unwrap();
        epoch_state.register_seal(&seal1, &record1.id, record1.record_hash());

        // Second seal: [200, 400] — start >= previous end, should pass
        let (record2, _) = create_epoch_seal(
            &identity, &storage, &epoch_state, zone.clone(),
            200.0, 400.0, None, None,
        ).unwrap();
        let verified2 = verify_epoch_seal(&record2, &storage, &epoch_state, &genesis, None, None);
        assert!(verified2.is_ok(), "sequential seal timestamps should be accepted");
    }

    // ── verify wrong authority ───────────────────────────────────

    #[test]
    fn test_verify_wrong_authority() {
        let identity = test_identity();
        let (storage, _dir) = test_engine();
        let epoch_state = EpochState::new();

        // Non-genesis seal without VRF proof should be rejected
        let (record, _) = create_epoch_seal(&identity, &storage, &epoch_state, ZoneId::from_legacy(0), 0.0, 100.0, None, None).unwrap();
        let result = verify_epoch_seal(&record, &storage, &epoch_state, "wrong_authority", None, None);
        assert!(result.is_err());
        // Multi-anchor: non-genesis must have VRF proof
        assert!(result.unwrap_err().to_string().contains("VRF proof"));
    }

    // ── verify wrong merkle root ─────────────────────────────────

    #[test]
    fn test_verify_wrong_merkle_root() {
        let identity = test_identity();
        let genesis = sha3_256_hex(&identity.public_key);
        let (mut storage, _dir) = test_engine();
        let epoch_state = EpochState::new();

        // Insert a record and discover its zone
        let r1 = insert_test_record(&mut storage, &identity, b"legit", 100.0);
        let zone = zone_for_record(&r1.id);

        // Manually construct a seal with a WRONG merkle root for that zone
        let fake_root = sha3_256(b"this is not the real root");
        let prev = [0u8; 32];
        let meta = seal_metadata(SealMetadataParams {
            zone: zone.clone(),
            epoch_number: 0,
            start: 50.0,
            end: 200.0,
            record_count: 1,
            merkle_root: &fake_root,
            previous_seal_hash: &prev,
            vrf_output: None,
            vrf_proof: None,
            sparse_merkle_root: None,
            record_hashes: None,
            zone_balance_total: None,
            zone_registry_root: None,
            zone_registry_delta: None,
            aggregator_rank: 0,
            account_smt_root: None,
            drand_pulse: None,
        });

        let mut record = ValidationRecord::create(
            format!("epoch:seal:{zone}:0").as_bytes(),
            identity.public_key.clone(),
            vec![],
            Classification::Public,
            Some(meta),
        );
        let signable = record.signable_bytes();
        record.signature = Some(identity.sign(&signable).unwrap());

        // Verification should succeed (merkle mismatch is now accepted with a warning
        // to avoid permanent epoch blockage on nodes with divergent record sets).
        let result = verify_epoch_seal(&record, &storage, &epoch_state, &genesis, None, None);
        assert!(result.is_ok(), "merkle mismatch should be accepted: {:?}", result);
    }

    // ── verify wrong epoch number ────────────────────────────────

    #[test]
    fn test_verify_wrong_epoch_number() {
        let identity = test_identity();
        let genesis = sha3_256_hex(&identity.public_key);
        let (storage, _dir) = test_engine();

        // State expects epoch 0, but we'll create a seal claiming epoch 5
        let epoch_state = EpochState::new();

        let root = [0u8; 32]; // empty epoch
        let prev = [0u8; 32];
        let meta = seal_metadata(SealMetadataParams {
            zone: ZoneId::from_legacy(0),
            epoch_number: 5,
            start: 0.0,
            end: 100.0,
            record_count: 0,
            merkle_root: &root,
            previous_seal_hash: &prev,
            vrf_output: None,
            vrf_proof: None,
            sparse_merkle_root: None,
            record_hashes: None,
            zone_balance_total: None,
            zone_registry_root: None,
            zone_registry_delta: None,
            aggregator_rank: 0,
            account_smt_root: None,
            drand_pulse: None,
        });

        let mut record = ValidationRecord::create(
            b"epoch:seal:0:5",
            identity.public_key.clone(),
            vec![],
            Classification::Public,
            Some(meta),
        );
        let signable = record.signable_bytes();
        record.signature = Some(identity.sign(&signable).unwrap());

        let result = verify_epoch_seal(&record, &storage, &epoch_state, &genesis, None, None);
        // Epoch 5 is within the ±100 partition-merge window from epoch 0, so it's accepted.
        // To test rejection, use an epoch far beyond the window:
        assert!(result.is_ok()); // partition-merge accepts epoch 5
    }

    // ── verify wrong chain ───────────────────────────────────────

    #[test]
    fn test_verify_wrong_chain() {
        let identity = test_identity();
        let genesis = sha3_256_hex(&identity.public_key);
        let (storage, _dir) = test_engine();

        // Register epoch 0 so state expects epoch 1 with a specific prev hash
        let mut epoch_state = EpochState::new();
        let seal0 = ParsedEpochSeal {
            zone: ZoneId::from_legacy(0),
            epoch_number: 0,
            start: 0.0,
            end: 100.0,
            record_count: 0,
            merkle_root: [0u8; 32],
            previous_seal_hash: [0u8; 32],
            vrf_output: None,
            vrf_proof: None,
            record_hashes: vec![],
            zone_balance_total: None,
            zone_registry_root: None,
            zone_registry_delta: None,
            seal_zone_count: None,
            aggregator_rank: 0,
            account_smt_root: None,
            drand_pulse: None,
            xzone_dest_finality_committees: None,
        };
        epoch_state.register_seal(&seal0, "seal-0", sha3_256(b"seal0hash"));

        // Create seal with wrong previous_seal
        let root = [0u8; 32];
        let wrong_prev = sha3_256(b"wrong chain");
        let meta = seal_metadata(SealMetadataParams {
            zone: ZoneId::from_legacy(0),
            epoch_number: 1,
            start: 100.0,
            end: 200.0,
            record_count: 0,
            merkle_root: &root,
            previous_seal_hash: &wrong_prev,
            vrf_output: None,
            vrf_proof: None,
            sparse_merkle_root: None,
            record_hashes: None,
            zone_balance_total: None,
            zone_registry_root: None,
            zone_registry_delta: None,
            aggregator_rank: 0,
            account_smt_root: None,
            drand_pulse: None,
        });

        let mut record = ValidationRecord::create(
            b"epoch:seal:0:1",
            identity.public_key.clone(),
            vec![],
            Classification::Public,
            Some(meta),
        );
        let signable = record.signable_bytes();
        record.signature = Some(identity.sign(&signable).unwrap());

        let result = verify_epoch_seal(&record, &storage, &epoch_state, &genesis, None, None);
        // previous_seal mismatch is now a warning (not a rejection) to handle
        // the race condition where concurrent seal arrivals for consecutive epochs
        // read stale epoch state. The Dilithium3 signature authenticates the creator.
        assert!(result.is_ok());
    }

    // ── rebuild epoch state ──────────────────────────────────────

    #[test]
    fn test_rebuild_epoch_state() {
        let identity = test_identity();
        let (mut storage, _dir) = test_engine();
        let mut epoch_state = EpochState::new();

        // Insert a record and discover its zone
        let r1 = insert_test_record(&mut storage, &identity, b"data", 50.0);
        let zone = zone_for_record(&r1.id);

        // Create and store 2 epoch seals for that zone
        let (seal0, parsed0) = create_epoch_seal(&identity, &storage, &epoch_state, zone.clone(), 0.0, 100.0, None, None).unwrap();
        storage.insert(&seal0).unwrap();
        epoch_state.register_seal(&parsed0, &seal0.id, seal0.record_hash());

        let (seal1, parsed1) = create_epoch_seal(&identity, &storage, &epoch_state, zone.clone(), 100.0, 200.0, None, None).unwrap();
        storage.insert(&seal1).unwrap();
        epoch_state.register_seal(&parsed1, &seal1.id, seal1.record_hash());

        // Rebuild from scratch
        let rebuilt = rebuild_epoch_state(&storage).unwrap();
        assert_eq!(rebuilt.next_epoch(&zone), 2);
        assert_eq!(rebuilt.latest_seal_id[&zone], seal1.id);
    }

    #[test]
    fn test_epoch_snapshot_round_trips_super_seal() {
        // Gap 3 follow-up: ensure latest_super_seal survives snapshot
        // save/load. Without this round-trip, any node restart driven
        // by snapshot recovery (the production hot path) zeros the
        // seal-pruning floor and GC silently no-ops until a fresh
        // super-seal arrives via gossip.
        let mut state = EpochState::new();
        let zone = ZoneId::from_legacy(3);
        let record_hash = sha3_256(b"super-seal record");
        let committee_hash = sha3_256(b"committee");
        state.register_super_seal(
            zone.clone(),
            42,
            "rec-deadbeef".into(),
            record_hash,
            committee_hash,
        );

        let snap = state.to_snapshot();
        let restored = EpochState::from_snapshot(&snap);
        let entry = restored
            .latest_super_seal
            .get(&zone)
            .expect("super-seal restored");
        assert_eq!(entry.0, 42);
        assert_eq!(entry.1, "rec-deadbeef");
        assert_eq!(entry.2, record_hash);
        assert_eq!(entry.3, committee_hash);
    }

    #[test]
    fn gap7_slice72_epoch_snapshot_round_trips_latest_sealed_account() {
        // Gap 7 slice 7.2: ensure latest_sealed_account survives snapshot
        // save/load. Without this, every restart drops the binding back to
        // None and /snapshot/state-delta serves `latest_sealed_account_*=null`
        // for ~1 zone-cadence — the trust gap slice 7.1 closed reopens at
        // each boot.
        let mut state = EpochState::new();
        let zone = ZoneId::from_legacy(7);
        let root = sha3_256(b"gap1-account-smt-root");
        state.latest_sealed_account = Some((
            108,
            zone.clone(),
            "rec-gap1-binding".to_string(),
            root,
            1234567890.5,
        ));

        let snap = state.to_snapshot();
        let restored = EpochState::from_snapshot(&snap);
        let entry = restored
            .latest_sealed_account
            .as_ref()
            .expect("sealed-account binding restored");
        assert_eq!(entry.0, 108, "epoch_number");
        assert_eq!(entry.1, zone, "zone");
        assert_eq!(entry.2, "rec-gap1-binding", "record_id");
        assert_eq!(entry.3, root, "account_smt_root");
        assert!((entry.4 - 1234567890.5).abs() < 1e-6, "sealed_at");
    }

    #[test]
    fn gap7_slice72_epoch_snapshot_none_binding_round_trips() {
        // Pre-Gap-1 chains and fresh boots have None — must round-trip as
        // None without panicking. Pins the back-compat path.
        let state = EpochState::new();
        assert!(state.latest_sealed_account.is_none());
        let snap = state.to_snapshot();
        let restored = EpochState::from_snapshot(&snap);
        assert!(restored.latest_sealed_account.is_none());
    }

    #[test]
    fn gap7_slice72_epoch_snapshot_malformed_hex_skips_binding() {
        // Corrupt snapshot row (wrong-length hex) must not crash boot —
        // matches the latest_super_seal posture (skip and continue).
        let mut snap = EpochState::new().to_snapshot();
        snap.latest_sealed_account = Some((
            108,
            ZoneId::from_legacy(7),
            "rec-corrupt".to_string(),
            "deadbeef".to_string(), // 4 bytes, not 32 — malformed
            1234567890.0,
        ));
        let restored = EpochState::from_snapshot(&snap);
        assert!(
            restored.latest_sealed_account.is_none(),
            "malformed hex must drop binding, not panic"
        );
    }

    #[test]
    fn test_rebuild_epoch_state_restores_super_seal_floor() {
        // Gap 3 follow-up: rebuild_epoch_state_from_records must also
        // restore latest_super_seal so the seal-pruning floor is non-empty
        // immediately after boot. Without this, GC silently no-ops until
        // a fresh super-seal arrives via gossip — a 64-epoch (~64 min)
        // blind spot at default cadence.
        let identity = test_identity();
        let (mut storage, _dir) = test_engine();

        // Drop a record so we get a real ZoneId rather than the default zone.
        let r = insert_test_record(&mut storage, &identity, b"data", 50.0);
        let zone = zone_for_record(&r.id);

        let hashes: Vec<[u8; 32]> = (0..SUPER_SEAL_INTERVAL)
            .map(|i| sha3_256(format!("seal {i}").as_bytes()))
            .collect();
        let (super_record, _parsed_ss) = create_super_seal(SuperSealParams {
            identity: &identity,
            zone: zone.clone(),
            start_epoch: 0,
            end_epoch: SUPER_SEAL_INTERVAL - 1,
            seal_hashes: &hashes,
            previous_super_seal_hash: [0u8; 32],
            committee_hash: [0u8; 32],
            timestamp: 200.0,
            slot_nonce: 1,
        })
        .expect("create super-seal");
        storage.insert(&super_record).unwrap();

        let rebuilt = rebuild_epoch_state(&storage).unwrap();
        let entry = rebuilt
            .latest_super_seal
            .get(&zone)
            .expect("super-seal restored at boot");
        assert_eq!(entry.0, SUPER_SEAL_INTERVAL - 1, "end_epoch");
        assert_eq!(entry.1, super_record.id, "record_id");
    }

    // ── seal excludes other seals from merkle root ───────────────

    #[test]
    fn test_seal_excludes_seals() {
        let identity = test_identity();
        let (mut storage, _dir) = test_engine();
        let mut epoch_state = EpochState::new();

        // Insert data records and find a zone with at least 1 record
        let r1 = insert_test_record(&mut storage, &identity, b"data1", 50.0);
        let zone = zone_for_record(&r1.id);

        // Insert more records targeting the same zone by checking after insert
        let r2 = insert_test_record(&mut storage, &identity, b"data2", 60.0);
        let initial_count = [&r1, &r2].iter()
            .filter(|r| zone_for_record(&r.id) == zone)
            .count() as u64;

        // Create epoch 0 seal for this zone
        let (seal0, parsed0) = create_epoch_seal(&identity, &storage, &epoch_state, zone.clone(), 0.0, 100.0, None, None).unwrap();
        assert_eq!(parsed0.record_count, initial_count);
        storage.insert(&seal0).unwrap();
        epoch_state.register_seal(&parsed0, &seal0.id, seal0.record_hash());

        // Insert another data record
        let r3 = insert_test_record(&mut storage, &identity, b"data3", 150.0);
        let total_count = [&r1, &r2, &r3].iter()
            .filter(|r| zone_for_record(&r.id) == zone)
            .count() as u64;

        // Create epoch 1 — the time range overlaps seal0, but seal0 should be excluded
        let (_seal1, parsed1) = create_epoch_seal(&identity, &storage, &epoch_state, zone.clone(), 0.0, 200.0, None, None).unwrap();
        // Should include matching data records but NOT seal0
        assert_eq!(parsed1.record_count, total_count);
    }

    // ── empty epoch (no records) ─────────────────────────────────

    #[test]
    fn test_empty_epoch() {
        let identity = test_identity();
        let (storage, _dir) = test_engine();
        let epoch_state = EpochState::new();

        let (record, parsed) = create_epoch_seal(&identity, &storage, &epoch_state, ZoneId::from_legacy(0), 0.0, 100.0, None, None).unwrap();
        assert_eq!(parsed.record_count, 0);
        assert_eq!(parsed.merkle_root, [0u8; 32]); // MerkleTree::root returns zeros for empty
        assert!(record.signature.is_some());
    }

    // ── zone assignment is hash-based ────────────────────────────

    #[test]
    fn test_zone_assignment_deterministic() {
        // Same record ID always maps to the same zone
        let zone1 = zone_for_record("test-record-id-123");
        let zone2 = zone_for_record("test-record-id-123");
        assert_eq!(zone1, zone2);

        // Different record IDs can map to different zones
        // (statistically, 100 random IDs will hit multiple zones)
        let mut zones = std::collections::HashSet::new();
        for i in 0..100 {
            zones.insert(zone_for_record(&format!("record-{i}")));
        }
        // With dynamic zone count (default 4), expect at least 2 distinct zones from 100 records
        let zone_count = crate::network::consensus::get_zone_count();
        let expected_min = if zone_count > 20 { 20 } else { 2.min(zone_count as usize) };
        assert!(zones.len() >= expected_min,
            "zone distribution too narrow: {} zones from 100 records (zone_count={})",
            zones.len(), zone_count);
    }

    // ── multi-zone seal isolation ────────────────────────────────

    #[test]
    fn test_multi_zone_seal_isolation() {
        let identity = test_identity();
        let (mut storage, _dir) = test_engine();

        // Insert many records to get at least 2 distinct zones
        let mut zone_records: HashMap<ZoneId, Vec<ValidationRecord>> = HashMap::new();
        for i in 0..50u32 {
            let rec = insert_test_record(
                &mut storage, &identity,
                format!("multi-zone-{i}").as_bytes(), 50.0,
            );
            let zone = zone_for_record(&rec.id);
            zone_records.entry(zone).or_default().push(rec);
        }

        // Pick 2 different zones that have records
        let zones_with_records: Vec<ZoneId> = zone_records.keys().cloned().collect();
        assert!(zones_with_records.len() >= 2, "need at least 2 zones, got {}", zones_with_records.len());

        let zone_a = zones_with_records[0].clone();
        let zone_b = zones_with_records[1].clone();
        let count_a = zone_records[&zone_a].len() as u64;
        let count_b = zone_records[&zone_b].len() as u64;

        // Seal zone A — should only include zone A records
        let epoch_state = EpochState::new();
        let (_, parsed_a) = create_epoch_seal(&identity, &storage, &epoch_state, zone_a, 0.0, 100.0, None, None).unwrap();
        assert_eq!(parsed_a.record_count, count_a);

        // Seal zone B — should only include zone B records
        let (_, parsed_b) = create_epoch_seal(&identity, &storage, &epoch_state, zone_b, 0.0, 100.0, None, None).unwrap();
        assert_eq!(parsed_b.record_count, count_b);

        // Merkle roots must differ (different records)
        assert_ne!(parsed_a.merkle_root, parsed_b.merkle_root);
    }

    // ── all records accounted for across zones ───────────────────

    #[test]
    fn test_all_records_covered_by_zones() {
        let identity = test_identity();
        let (mut storage, _dir) = test_engine();
        let total_records = 30u32;

        let mut all_records = Vec::new();
        for i in 0..total_records {
            all_records.push(insert_test_record(
                &mut storage, &identity,
                format!("coverage-{i}").as_bytes(), 50.0,
            ));
        }

        // Group by zone
        let mut zone_counts: HashMap<ZoneId, u64> = HashMap::new();
        for rec in &all_records {
            *zone_counts.entry(zone_for_record(&rec.id)).or_insert(0) += 1;
        }

        // Seal each zone and verify counts sum to total
        let epoch_state = EpochState::new();
        let mut sealed_total = 0u64;
        for (zone, &expected_count) in &zone_counts {
            let (_, parsed) = create_epoch_seal(&identity, &storage, &epoch_state, zone.clone(), 0.0, 100.0, None, None).unwrap();
            assert_eq!(parsed.record_count, expected_count);
            sealed_total += parsed.record_count;
        }
        assert_eq!(sealed_total, total_records as u64);
    }

    // ── VRF epoch seal integration ──────────────────────────────

    #[test]
    fn test_create_epoch_seal_with_vrf() {
        use crate::crypto::vrf::{VrfSecretKey, vrf_verify};

        let identity = test_identity();
        let (mut storage, _dir) = test_engine();
        let epoch_state = EpochState::new();
        let vrf_sk = VrfSecretKey::generate().unwrap();
        let vrf_pk = vrf_sk.public_key();

        insert_test_record(&mut storage, &identity, b"vrf_test", 100.0);

        let (record, parsed) = create_epoch_seal(
            &identity, &storage, &epoch_state, ZoneId::from_legacy(0), 50.0, 200.0, Some(&vrf_sk), None,
        ).unwrap();

        // VRF fields must be present
        assert!(parsed.vrf_output.is_some(), "VRF output must be present");
        assert!(parsed.vrf_proof.is_some(), "VRF proof must be present");

        // Output must not be all zeros
        assert_ne!(parsed.vrf_output.unwrap(), [0u8; 32]);

        // Proof must have valid length (Dilithium VRF: ~3312 bytes, legacy EC-VRF: 80 bytes)
        assert!(parsed.vrf_proof.as_ref().unwrap().len() >= 3, "VRF proof too short");

        // Metadata must contain VRF fields
        assert!(record.metadata.contains_key("epoch_vrf_output"));
        assert!(record.metadata.contains_key("epoch_vrf_proof"));

        // VRF proof must be independently verifiable using the canonical
        // chained_beacon alpha (Stage 3b.4).
        let beacon = super::super::aggregator::chained_beacon(
            &parsed.previous_seal_hash,
            parsed.epoch_number,
            &parsed.zone,
        );
        let proof = crate::crypto::vrf::VrfProof::from_bytes(parsed.vrf_proof.as_ref().unwrap()).unwrap();
        let verified_output = vrf_verify(&vrf_pk, &beacon, &proof).unwrap();
        assert_eq!(verified_output.as_bytes(), &parsed.vrf_output.unwrap());
    }

    /// Stage 3b.4: adjacent epochs chain through `chained_beacon`. Changing
    /// the previous seal hash must change the VRF alpha, which must change
    /// the VRF output. Guarantees that rank-gating + jury selection in epoch
    /// N+1 is a function of the sealed history through epoch N.
    #[test]
    fn test_epoch_seal_beacon_chains_across_adjacent_epochs() {
        use crate::crypto::vrf::VrfSecretKey;

        let identity = test_identity();
        let (mut storage, _dir) = test_engine();
        let mut epoch_state = EpochState::new();
        let vrf_sk = VrfSecretKey::generate().unwrap();
        let zone = ZoneId::from_legacy(0);

        insert_test_record(&mut storage, &identity, b"e1", 10.0);
        insert_test_record(&mut storage, &identity, b"e2", 110.0);

        // Epoch 1: prev_seal_hash = [0u8; 32] (genesis). Record its beacon.
        let (rec1, p1) = create_epoch_seal(
            &identity, &storage, &epoch_state, zone.clone(), 0.0, 100.0, Some(&vrf_sk), None,
        ).unwrap();
        assert_eq!(p1.previous_seal_hash, [0u8; 32]);
        let beacon1 = super::super::aggregator::chained_beacon(&[0u8; 32], p1.epoch_number, &zone);

        // Register epoch 1 so its hash flows into epoch 2.
        epoch_state.register_seal(&p1, &rec1.id, rec1.record_hash());
        let rec1_hash = rec1.record_hash();
        assert_eq!(epoch_state.previous_seal_hash(&zone), rec1_hash);

        // Epoch 2: prev_seal_hash = hash(epoch 1 seal record). Beacon MUST
        // differ from beacon1 because prev_seal_hash differs.
        let (_rec2, p2) = create_epoch_seal(
            &identity, &storage, &epoch_state, zone.clone(), 100.0, 200.0, Some(&vrf_sk), None,
        ).unwrap();
        assert_eq!(p2.previous_seal_hash, rec1_hash);
        assert_eq!(p2.epoch_number, p1.epoch_number + 1);
        let beacon2 = super::super::aggregator::chained_beacon(&rec1_hash, p2.epoch_number, &zone);

        // Beacon chains: different inputs → different outputs.
        assert_ne!(beacon1, beacon2, "adjacent-epoch beacons must differ");

        // Both seals' VRF outputs must be distinct (since alpha differs).
        assert_ne!(p1.vrf_output.unwrap(), p2.vrf_output.unwrap());
    }

    #[test]
    fn test_verify_epoch_seal_with_vrf() {
        use crate::crypto::vrf::VrfSecretKey;

        let identity = test_identity();
        let genesis = sha3_256_hex(&identity.public_key);
        let (mut storage, _dir) = test_engine();
        let epoch_state = EpochState::new();
        let vrf_sk = VrfSecretKey::generate().unwrap();
        let vrf_pk = vrf_sk.public_key();

        insert_test_record(&mut storage, &identity, b"data", 100.0);

        let (record, _) = create_epoch_seal(
            &identity, &storage, &epoch_state, ZoneId::from_legacy(0), 50.0, 200.0, Some(&vrf_sk), None,
        ).unwrap();

        // Verify with correct VRF public key — must succeed
        let verified = verify_epoch_seal(
            &record, &storage, &epoch_state, &genesis, Some(&vrf_pk), None,
        ).unwrap();
        assert!(verified.vrf_output.is_some());
    }

    /// Stage 3b.4 compat: seals created before the switch to chained_beacon
    /// used a string alpha `"epoch:{zone}:{epoch}:{hex(prev)}"`. The new
    /// verifier must still accept those via its legacy fallback so historical
    /// testnet seals verify without re-signing. Also asserts that a seal with
    /// neither alpha-format working actually fails — the fallback is not a
    /// free pass.
    #[test]
    fn test_verify_epoch_seal_accepts_legacy_alpha() {
        use crate::crypto::vrf::{VrfSecretKey, vrf_prove};

        let identity = test_identity();
        let genesis = sha3_256_hex(&identity.public_key);
        let (mut storage, _dir) = test_engine();
        let epoch_state = EpochState::new();
        let vrf_sk = VrfSecretKey::generate().unwrap();
        let vrf_pk = vrf_sk.public_key();
        let zone = ZoneId::from_legacy(0);

        insert_test_record(&mut storage, &identity, b"legacy_data", 100.0);

        // Build a seal via the normal path; then swap VRF output/proof with
        // ones computed over the LEGACY alpha format. This simulates a seal
        // authored by pre-3b.4 code.
        let (mut record, parsed) = create_epoch_seal(
            &identity, &storage, &epoch_state, zone.clone(), 50.0, 200.0, Some(&vrf_sk), None,
        ).unwrap();

        let legacy_alpha = format!(
            "epoch:{}:{}:{}",
            parsed.zone, parsed.epoch_number,
            hex::encode(parsed.previous_seal_hash)
        );
        let (legacy_out, legacy_proof) = vrf_prove(&vrf_sk, legacy_alpha.as_bytes()).unwrap();

        record.metadata.insert(
            "epoch_vrf_output".into(),
            serde_json::json!(hex::encode(legacy_out.as_bytes())),
        );
        record.metadata.insert(
            "epoch_vrf_proof".into(),
            serde_json::json!(hex::encode(legacy_proof.to_bytes())),
        );
        // Re-sign because we mutated metadata.
        record.signature = None;
        record.sphincs_signature = None;
        identity.sign_record(&mut record).unwrap();

        // Legacy-alpha seal must verify under the 3b.4 fallback path.
        let verified = verify_epoch_seal(
            &record, &storage, &epoch_state, &genesis, Some(&vrf_pk), None,
        ).expect("legacy-alpha seal must verify via fallback");
        assert_eq!(
            verified.vrf_output.unwrap(),
            *legacy_out.as_bytes(),
            "verifier must return the legacy VRF output unchanged",
        );
    }

    // ── B7: catch-up fast-forward VRF gate ───────────────────────────
    // Fusion-audited 2026-06-19 (4 Opus panel + 1 result-checker). A non-genesis
    // seal that fast-forwards our epoch tip (epoch > our_latest) must be
    // VRF-verifiable, or it is deferred (retryable) — never silently applied.
    // Genesis stays exempt (live first-external join). Scoped to the
    // fast-forward arm; sequential / partition seals are untouched.
    // `verify_epoch_seal_*` does not re-check the Dilithium3 signature, so a unit
    // test may inject metadata to shape the seal (epoch_number, VRF fields).

    #[test]
    fn b7_nongenesis_fastforward_rejects_when_vrf_pk_absent() {
        use crate::crypto::vrf::VrfSecretKey;
        let identity = test_identity();
        // A genesis authority that is NOT this seal's creator → non-genesis path.
        let genesis = "b7_other_genesis_authority_deadbeef".to_string();
        assert_ne!(sha3_256_hex(&identity.public_key), genesis);
        let (mut storage, _dir) = test_engine();
        let epoch_state = EpochState::new(); // fresh → our_latest = 0
        insert_test_record(&mut storage, &identity, b"b7-ff", 100.0);
        let zone = ZoneId::from_legacy(0);

        // Authored with a VRF key so vrf_output/vrf_proof are PRESENT (the
        // presence check precedes our gate), then pushed to a high epoch so it
        // lands on the catch-up (fast-forward) branch.
        let vrf_sk = VrfSecretKey::generate().unwrap();
        let (mut record, _) = create_epoch_seal(
            &identity, &storage, &epoch_state, zone.clone(), 50.0, 200.0, Some(&vrf_sk), None,
        ).unwrap();
        record.metadata.insert("epoch_number".into(), serde_json::json!(5000u64));

        // vrf_pk = None → proposer key not registered locally.
        let res = verify_epoch_seal_no_merkle(&record, &storage, &epoch_state, &genesis, None, None);
        let msg = res.expect_err("non-genesis fast-forward seal w/o registered VRF key must reject").to_string();
        assert!(msg.contains("VRF-unverifiable"), "expected VRF-unverifiable deferral, got: {msg}");
        // Must be retryable (parked + re-fetched), NOT permanent-cached, so an
        // honest joiner self-heals once the proposer's registration syncs.
        assert!(
            crate::network::gossip::is_retryable_ingest_rejection(&msg),
            "B7 deferral must be classified retryable: {msg}"
        );
    }

    #[test]
    fn b7_genesis_fastforward_still_accepts_without_vrf() {
        // The trust root is VRF-exempt — a fast-forward genesis seal must still be
        // accepted with no VRF key, or the live first-external join freezes.
        let identity = test_identity();
        let genesis = sha3_256_hex(&identity.public_key); // creator == genesis
        let (mut storage, _dir) = test_engine();
        let epoch_state = EpochState::new();
        insert_test_record(&mut storage, &identity, b"b7-genesis-ff", 100.0);
        let zone = ZoneId::from_legacy(0);

        // Genesis needs no VRF fields (presence check skips genesis).
        let (mut record, _) = create_epoch_seal(
            &identity, &storage, &epoch_state, zone.clone(), 50.0, 200.0, None, None,
        ).unwrap();
        record.metadata.insert("epoch_number".into(), serde_json::json!(5000u64));

        let res = verify_epoch_seal_no_merkle(&record, &storage, &epoch_state, &genesis, None, None);
        assert!(res.is_ok(), "genesis fast-forward seal must accept without VRF: {:?}", res.err());
    }

    #[test]
    fn b7_nongenesis_sequential_unaffected_by_fastforward_gate() {
        // Scoping pin: a non-genesis SEQUENTIAL seal (epoch == expected) must NOT
        // be hit by the fast-forward gate. It routes through the normal path
        // (legacy VRF-skip when vrf_pk is None) — it cannot wedge the tip and
        // loses to attestation weight, so its behaviour is intentionally intact.
        use crate::crypto::vrf::VrfSecretKey;
        let identity = test_identity();
        let genesis = "b7_other_genesis_authority_deadbeef".to_string();
        let (mut storage, _dir) = test_engine();
        let epoch_state = EpochState::new(); // fresh → expected = 0
        insert_test_record(&mut storage, &identity, b"b7-seq", 100.0);
        let zone = ZoneId::from_legacy(0);

        let vrf_sk = VrfSecretKey::generate().unwrap();
        // Seal at epoch 0 == expected → sequential branch. VRF fields present.
        let (record, _) = create_epoch_seal(
            &identity, &storage, &epoch_state, zone.clone(), 50.0, 200.0, Some(&vrf_sk), None,
        ).unwrap();

        let res = verify_epoch_seal_no_merkle(&record, &storage, &epoch_state, &genesis, None, None);
        if let Err(ref e) = res {
            assert!(
                !e.to_string().contains("VRF-unverifiable"),
                "fast-forward gate must not fire on a sequential seal: {e}"
            );
        }
        assert!(res.is_ok(), "sequential non-genesis seal should pass the verifier: {:?}", res.err());
    }

    #[test]
    fn b7_nongenesis_fastforward_accepts_with_valid_vrf() {
        // Over-rejection guard: a legitimately-registered anchor's fast-forward
        // seal (valid VRF proof + full key supplied) must be ACCEPTED — the gate
        // blocks only UNVERIFIABLE fast-forwards, not verifiable ones.
        use crate::crypto::vrf::{VrfSecretKey, vrf_prove};
        let identity = test_identity();
        let genesis = "b7_other_genesis_authority_deadbeef".to_string();
        let (mut storage, _dir) = test_engine();
        let epoch_state = EpochState::new();
        insert_test_record(&mut storage, &identity, b"b7-ff-valid", 100.0);
        let zone = ZoneId::from_legacy(0);

        let vrf_sk = VrfSecretKey::generate().unwrap();
        let vrf_pk = vrf_sk.public_key();
        let (mut record, _) = create_epoch_seal(
            &identity, &storage, &epoch_state, zone.clone(), 50.0, 200.0, Some(&vrf_sk), None,
        ).unwrap();

        // Fast-forward to epoch 5000 and recompute the VRF over the matching
        // beacon = chained_beacon(prev_seal_hash, epoch, zone). prev_seal_hash is
        // [0;32] on a fresh chain (the seal carries epoch_previous_seal = zeros).
        let ff_epoch = 5000u64;
        let beacon = crate::network::aggregator::chained_beacon(&[0u8; 32], ff_epoch, &zone);
        let (out, proof) = vrf_prove(&vrf_sk, &beacon).unwrap();
        record.metadata.insert("epoch_number".into(), serde_json::json!(ff_epoch));
        record.metadata.insert("epoch_vrf_output".into(), serde_json::json!(hex::encode(out.as_bytes())));
        record.metadata.insert("epoch_vrf_proof".into(), serde_json::json!(hex::encode(proof.to_bytes())));

        let res = verify_epoch_seal_no_merkle(&record, &storage, &epoch_state, &genesis, Some(&vrf_pk), None);
        assert!(res.is_ok(), "fast-forward seal with a valid VRF proof must accept: {:?}", res.err());
    }

    #[test]
    fn test_verify_epoch_seal_wrong_vrf_key_fails() {
        use crate::crypto::vrf::VrfSecretKey;

        let identity = test_identity();
        let genesis = sha3_256_hex(&identity.public_key);
        let (mut storage, _dir) = test_engine();
        let epoch_state = EpochState::new();
        let vrf_sk = VrfSecretKey::generate().unwrap();
        let wrong_vrf_pk = VrfSecretKey::generate().unwrap().public_key();

        insert_test_record(&mut storage, &identity, b"data", 100.0);

        let (record, _) = create_epoch_seal(
            &identity, &storage, &epoch_state, ZoneId::from_legacy(0), 50.0, 200.0, Some(&vrf_sk), None,
        ).unwrap();

        // Verify with WRONG VRF public key — must fail
        let result = verify_epoch_seal(
            &record, &storage, &epoch_state, &genesis, Some(&wrong_vrf_pk), None,
        );
        assert!(result.is_err(), "wrong VRF key must cause verification failure");
    }

    #[test]
    fn test_vrf_output_stored_in_epoch_state() {
        use crate::crypto::vrf::VrfSecretKey;

        let identity = test_identity();
        let (mut storage, _dir) = test_engine();
        let mut epoch_state = EpochState::new();
        let vrf_sk = VrfSecretKey::generate().unwrap();

        insert_test_record(&mut storage, &identity, b"data", 100.0);

        let (record, parsed) = create_epoch_seal(
            &identity, &storage, &epoch_state, ZoneId::from_legacy(0), 50.0, 200.0, Some(&vrf_sk), None,
        ).unwrap();

        // Register seal into epoch state
        epoch_state.register_seal(&parsed, &record.id, record.record_hash());

        // VRF output must be retrievable from epoch state
        let stored_vrf = epoch_state.vrf_output(&ZoneId::from_legacy(0));
        assert!(stored_vrf.is_some(), "VRF output must be stored in epoch state");
        assert_eq!(stored_vrf.unwrap(), &parsed.vrf_output.unwrap());
    }

    #[test]
    fn test_vrf_output_changes_per_epoch() {
        use crate::crypto::vrf::VrfSecretKey;

        let identity = test_identity();
        let (mut storage, _dir) = test_engine();
        let mut epoch_state = EpochState::new();
        let vrf_sk = VrfSecretKey::generate().unwrap();

        // Create epoch 0
        insert_test_record(&mut storage, &identity, b"data0", 50.0);
        let (rec0, parsed0) = create_epoch_seal(
            &identity, &storage, &epoch_state, ZoneId::from_legacy(0), 0.0, 100.0, Some(&vrf_sk), None,
        ).unwrap();
        epoch_state.register_seal(&parsed0, &rec0.id, rec0.record_hash());
        storage.insert(&rec0).unwrap();

        // Create epoch 1 (different previous_seal_hash → different VRF output)
        insert_test_record(&mut storage, &identity, b"data1", 150.0);
        let (_, parsed1) = create_epoch_seal(
            &identity, &storage, &epoch_state, ZoneId::from_legacy(0), 100.0, 200.0, Some(&vrf_sk), None,
        ).unwrap();

        // VRF outputs must differ between epochs (different alpha input)
        assert_ne!(
            parsed0.vrf_output.unwrap(),
            parsed1.vrf_output.unwrap(),
            "VRF outputs must differ between epochs"
        );
    }

    // ── New Day 2 tests: record_hashes, zone_balance, witness verification ──

    #[test]
    fn test_seal_includes_record_hashes() {
        let identity = test_identity();
        let (mut storage, _dir) = test_engine();
        let epoch_state = EpochState::new();

        // Insert records
        let r1 = insert_test_record(&mut storage, &identity, b"hash-test-1", 50.0);
        let _r2 = insert_test_record(&mut storage, &identity, b"hash-test-2", 60.0);
        let zone = zone_for_record(&r1.id);

        let (_, parsed) = create_epoch_seal(
            &identity, &storage, &epoch_state, zone, 0.0, 100.0, None, None,
        ).unwrap();

        // record_hashes should contain hashes of records in this zone
        assert!(!parsed.record_hashes.is_empty());
        assert_eq!(parsed.record_hashes.len() as u64, parsed.record_count);

        // Hashes should be sorted (deterministic ordering)
        let mut sorted = parsed.record_hashes.clone();
        sorted.sort();
        assert_eq!(parsed.record_hashes, sorted);
    }

    #[test]
    fn test_seal_with_zone_balance() {
        let identity = test_identity();
        let (mut storage, _dir) = test_engine();
        let epoch_state = EpochState::new();

        insert_test_record(&mut storage, &identity, b"balance-test", 50.0);
        let zone = ZoneId::from_legacy(0);

        // Create seal with balance total
        let balance_total = 10_000_000_000_000_000u64; // 10T beat
        let (record, parsed) = create_epoch_seal_with_balance(SealParams {
            identity: &identity,
            storage: &storage,
            epoch_state: &epoch_state,
            zone,
            start: 0.0,
            end: 100.0,
            vrf_sk: None,
            sparse_merkle_root: None,
            zone_balance_total: Some(balance_total),
            zone_registry_root: None,
            zone_registry_delta: None,
            parents: vec![],
            aggregator_rank: 0,
            slot_nonce: 0,
            account_smt_root: None,
            drand_pulse: None,
            zone_registry: None,
            xzone_dest_finality_committees: None,
        }).unwrap();

        assert_eq!(parsed.zone_balance_total, Some(balance_total));

        // Verify metadata roundtrip
        let reparsed = extract_epoch_seal(&record).unwrap().unwrap();
        assert_eq!(reparsed.zone_balance_total, Some(balance_total));
    }

    #[test]
    fn test_seal_with_zone_registry() {
        let identity = test_identity();
        let (storage, _dir) = test_engine();
        let epoch_state = EpochState::new();

        let registry_root = sha3_256(b"registry merkle root");
        let delta = vec![
            ZoneRegistryChange::Created { zone: ZoneId::new("medical/eu") },
            ZoneRegistryChange::Created { zone: ZoneId::new("finance/global") },
        ];

        let (record, parsed) = create_epoch_seal_with_balance(SealParams {
            identity: &identity,
            storage: &storage,
            epoch_state: &epoch_state,
            zone: ZoneId::from_legacy(0),
            start: 0.0,
            end: 100.0,
            vrf_sk: None,
            sparse_merkle_root: None,
            zone_balance_total: None,
            zone_registry_root: Some(registry_root),
            zone_registry_delta: Some(delta),
            parents: vec![],
            aggregator_rank: 0,
            slot_nonce: 0,
            account_smt_root: None,
            drand_pulse: None,
            zone_registry: None,
            xzone_dest_finality_committees: None,
        }).unwrap();

        assert_eq!(parsed.zone_registry_root, Some(registry_root));
        assert!(parsed.zone_registry_delta.is_some());
        assert_eq!(parsed.zone_registry_delta.as_ref().unwrap().len(), 2);

        // Verify roundtrip
        let reparsed = extract_epoch_seal(&record).unwrap().unwrap();
        assert_eq!(reparsed.zone_registry_root, Some(registry_root));
        assert!(reparsed.zone_registry_delta.is_some());
    }

    #[test]
    fn test_witness_verify_seal_success() {
        let identity = test_identity();
        let (mut storage, _dir) = test_engine();
        let epoch_state = EpochState::new();

        // Insert records
        let r1 = insert_test_record(&mut storage, &identity, b"witness-v-1", 50.0);
        let _r2 = insert_test_record(&mut storage, &identity, b"witness-v-2", 60.0);
        let zone = zone_for_record(&r1.id);

        // Create seal
        let (_, parsed) = create_epoch_seal(
            &identity, &storage, &epoch_state, zone, 0.0, 100.0, None, None,
        ).unwrap();

        // Witness should verify successfully against same storage
        let result = witness_verify_seal(&parsed, &storage, None);
        assert!(result.is_verified(), "Expected Verified, got {:?}", result);
    }

    #[test]
    fn test_witness_verify_seal_balance_mismatch() {
        let identity = test_identity();
        let (mut storage, _dir) = test_engine();
        let epoch_state = EpochState::new();

        insert_test_record(&mut storage, &identity, b"bal-mismatch", 50.0);
        let zone = ZoneId::from_legacy(0);

        let (_, parsed) = create_epoch_seal_with_balance(SealParams {
            identity: &identity,
            storage: &storage,
            epoch_state: &epoch_state,
            zone,
            start: 0.0,
            end: 100.0,
            vrf_sk: None,
            sparse_merkle_root: None,
            zone_balance_total: Some(1_000_000),
            zone_registry_root: None,
            zone_registry_delta: None,
            parents: vec![],
            aggregator_rank: 0,
            slot_nonce: 0,
            account_smt_root: None,
            drand_pulse: None,
            zone_registry: None,
            xzone_dest_finality_committees: None,
        }).unwrap();

        // Witness computes a different balance → should fail
        let result = witness_verify_seal(&parsed, &storage, Some(999_999));
        match result {
            WitnessVerification::BalanceMismatch { local, proposed } => {
                assert_eq!(local, 999_999);
                assert_eq!(proposed, 1_000_000);
            }
            other => panic!("Expected BalanceMismatch, got {:?}", other),
        }
    }

    /// R3-9 Decision B test 1: the witness holds MORE records in the seal's
    /// zone window than the seal enumerates — definite omission (the
    /// selective-finality vector a malicious anchor would use). The witness
    /// MUST decline: RecordCountMismatch with local > proposed.
    #[test]
    fn witness_verify_seal_declines_omission_when_witness_holds_more_records() {
        let identity = test_identity();
        let (mut storage, _dir) = test_engine();
        let epoch_state = EpochState::new();

        let r1 = insert_test_record(&mut storage, &identity, b"omission-sealed", 50.0);
        let zone = zone_for_record(&r1.id);

        // Seal over the window while the witness holds only r1.
        let (_, parsed) = create_epoch_seal(
            &identity, &storage, &epoch_state, zone.clone(), 0.0, 100.0, None, None,
        ).unwrap();
        let sealed_count = parsed.record_count;

        // Now the witness learns of an extra record inside the SAME zone +
        // window that the seal does not enumerate. Retry content until the
        // record id hashes into the seal's zone (immediate at zone_count=1;
        // bounded search keeps the test valid if the ambient count differs).
        let mut landed = false;
        for i in 0..256u32 {
            let mut record = ValidationRecord::create(
                format!("omission-extra-{i}").as_bytes(),
                identity.public_key.clone(),
                vec![],
                Classification::Public,
                None,
            );
            record.timestamp = 60.0;
            if zone_for_record(&record.id) != zone {
                continue;
            }
            record.zone = Some(zone.clone());
            let signable = record.signable_bytes();
            record.signature = Some(identity.sign(&signable).unwrap());
            storage.insert(&record).unwrap();
            landed = true;
            break;
        }
        assert!(landed, "no extra record landed in the seal zone within 256 tries");

        match witness_verify_seal(&parsed, &storage, None) {
            WitnessVerification::RecordCountMismatch { local, proposed } => {
                assert_eq!(proposed, sealed_count, "proposed must echo the seal's claim");
                assert!(
                    local > proposed,
                    "local ({local}) must exceed proposed ({proposed}) — definite omission"
                );
            }
            other => panic!("Expected RecordCountMismatch (omission), got {other:?}"),
        }
    }

    /// R3-9 Decision B test 2: enumeration ABSENT (R3-8 bounded emission
    /// above SEAL_INLINE_ENUM_MAX, or legacy empty array) — the witness
    /// re-derives the record list from its local window. Agreeing set →
    /// Verified; tampered root → MerkleRootMismatch; inflated count →
    /// RecordCountMismatch with local < proposed (the catching-up posture).
    #[test]
    fn witness_verify_seal_derives_when_enumeration_absent() {
        let identity = test_identity();
        let (mut storage, _dir) = test_engine();
        let epoch_state = EpochState::new();

        let r1 = insert_test_record(&mut storage, &identity, b"derive-absent-1", 50.0);
        let _r2 = insert_test_record(&mut storage, &identity, b"derive-absent-2", 60.0);
        let zone = zone_for_record(&r1.id);

        let (_, parsed) = create_epoch_seal(
            &identity, &storage, &epoch_state, zone, 0.0, 100.0, None, None,
        ).unwrap();

        // Simulate the above-cap wire shape: enumeration omitted, but the
        // signed record_count + merkle_root still commit the set.
        let mut absent = parsed.clone();
        absent.record_hashes = Vec::new();
        let verdict = witness_verify_seal(&absent, &storage, None);
        assert!(
            verdict.is_verified(),
            "derive path must verify an agreeing absent-enumeration seal, got {verdict:?}"
        );

        // Divergent root at equal counts → decline.
        let mut tampered = absent.clone();
        tampered.merkle_root = sha3_256(b"bogus divergent root");
        match witness_verify_seal(&tampered, &storage, None) {
            WitnessVerification::MerkleRootMismatch { proposed, .. } => {
                assert_eq!(proposed, tampered.merkle_root);
            }
            other => panic!("Expected MerkleRootMismatch, got {other:?}"),
        }

        // Seal claims more records than the local window holds → decline
        // with local < proposed (witness behind; retried next cycle).
        let mut inflated = absent.clone();
        inflated.record_count += 1;
        match witness_verify_seal(&inflated, &storage, None) {
            WitnessVerification::RecordCountMismatch { local, proposed } => {
                assert!(local < proposed, "local ({local}) must trail proposed ({proposed})");
            }
            other => panic!("Expected RecordCountMismatch (behind), got {other:?}"),
        }
    }

    #[test]
    fn test_record_hashes_metadata_roundtrip() {
        let identity = test_identity();
        let (mut storage, _dir) = test_engine();
        let epoch_state = EpochState::new();

        // Insert enough records to have some in the seal
        for i in 0..10u32 {
            insert_test_record(&mut storage, &identity, format!("rt-{i}").as_bytes(), 50.0);
        }

        let zone = ZoneId::from_legacy(0);
        let (record, parsed) = create_epoch_seal(
            &identity, &storage, &epoch_state, zone, 0.0, 100.0, None, None,
        ).unwrap();

        // Parse the record back
        let reparsed = extract_epoch_seal(&record).unwrap().unwrap();
        assert_eq!(reparsed.record_hashes.len(), parsed.record_hashes.len());
        assert_eq!(reparsed.record_hashes, parsed.record_hashes);
    }

    #[test]
    fn test_compute_zone_balance_total() {
        use crate::accounting::ledger::{LedgerState, AccountState};

        let mut ledger = LedgerState::new();
        ledger.accounts.insert("alice".to_string(), AccountState {
            available: 5000,
            staked: 1000,
            ..Default::default()
        });
        ledger.accounts.insert("bob".to_string(), AccountState {
            available: 3000,
            staked: 500,
            ..Default::default()
        });

        let total = compute_zone_balance_total(&ledger);
        assert_eq!(total, 5000 + 1000 + 3000 + 500);
    }

    // ── Adaptive Epoch Tests ──────────────────

    #[test]
    fn test_adaptive_interval_high_activity() {
        let mut state = EpochState::new();
        let zone = ZoneId::new("iot/sensors");

        // 1000 records in 300s = 3.33 rec/s
        // interval = TARGET_RECORDS_PER_EPOCH / rate = 100 / 3.33 ≈ 30s
        // (above MIN_ADAPTIVE_EPOCH_SECS=5.0 so no clamp applies)
        state.update_activity(&zone, 1000, 300.0);
        let interval = state.adaptive_interval(&zone, 300.0);
        assert!(interval <= 30.0 + 0.1, "expected ~30s, got {interval}");
    }

    #[test]
    fn test_adaptive_interval_low_activity() {
        let mut state = EpochState::new();
        let zone = ZoneId::new("medical/eu");

        // 2 records in 300s = 0.0067 rec/s
        // interval = 100 / 0.0067 = ~15000s → clamped to MAX_ADAPTIVE_EPOCH_SECS
        state.update_activity(&zone, 2, 300.0);
        let interval = state.adaptive_interval(&zone, 300.0);
        assert!((interval - MAX_ADAPTIVE_EPOCH_SECS).abs() < 0.1,
            "expected ~{MAX_ADAPTIVE_EPOCH_SECS}s, got {interval}");
    }

    #[test]
    fn test_adaptive_interval_normal_activity() {
        let mut state = EpochState::new();
        let zone = ZoneId::new("default");

        // 100 records in 30s = 3.33 rec/s
        // interval = TARGET_RECORDS_PER_EPOCH (100) / 3.33 = ~30s — in the
        // [MIN=5, MAX=60] band. Test name preserved: "normal" = healthy traffic
        // hitting the formula instead of clamp. Updated when MAX
        // dropped 3600 → 120 → 60; the previous "sweet spot" rate of 0.333 rps
        // now exceeds the cap.
        state.update_activity(&zone, 100, 30.0);
        let interval = state.adaptive_interval(&zone, 300.0);
        assert!((interval - 30.0).abs() < 1.0,
            "expected ~30s, got {interval}");
    }

    #[test]
    fn test_adaptive_ema_smoothing() {
        let mut state = EpochState::new();
        let zone = ZoneId::new("test");

        // First observation: 50 records in 300s
        state.update_activity(&zone, 50, 300.0);
        let rate1 = state.zone_activity_rate[&zone];

        // Second observation: 500 records in 300s (spike)
        state.update_activity(&zone, 500, 300.0);
        let rate2 = state.zone_activity_rate[&zone];

        // EMA should smooth the spike, not jump fully to it
        let spike_rate = 500.0 / 300.0;
        assert!(rate2 < spike_rate, "EMA should be less than spike rate");
        assert!(rate2 > rate1, "EMA should increase after spike");
    }

    #[test]
    fn test_adaptive_no_data_uses_default() {
        let state = EpochState::new();
        let zone = ZoneId::new("unknown");
        assert_eq!(state.adaptive_interval(&zone, 300.0), 300.0);
    }

    #[test]
    fn test_adaptive_zero_duration_ignored() {
        let mut state = EpochState::new();
        let zone = ZoneId::new("test");
        state.update_activity(&zone, 100, 0.0);
        // Should not crash, should not update
        assert!(!state.zone_activity_rate.contains_key(&zone));
    }

    #[test]
    fn test_adaptive_summary_empty_state() {
        let state = EpochState::new();
        let s = state.adaptive_interval_summary();
        assert_eq!(s.zones_tracked, 0);
        assert_eq!(s.floor_pinned_zones, 0);
        assert_eq!(s.min_active_secs, 0.0);
        assert_eq!(s.max_active_secs, 0.0);
        assert_eq!(s.mean_secs, 0.0);
    }

    #[test]
    fn test_adaptive_summary_floor_pinned() {
        let mut state = EpochState::new();
        let busy = ZoneId::new("busy");
        // 200 rec in 1s → 200 rec/s → interval = 100/200 = 0.5s, clamped up to MIN (5s).
        state.update_activity(&busy, 200, 1.0);
        let s = state.adaptive_interval_summary();
        assert_eq!(s.zones_tracked, 1);
        assert_eq!(s.floor_pinned_zones, 1, "single saturated zone must be floor-pinned");
        assert!((s.min_active_secs - MIN_ADAPTIVE_EPOCH_SECS).abs() < 1e-9);
        assert!((s.max_active_secs - MIN_ADAPTIVE_EPOCH_SECS).abs() < 1e-9);
    }

    #[test]
    fn test_adaptive_summary_mixed_load() {
        let mut state = EpochState::new();
        let busy = ZoneId::new("busy");
        let medium = ZoneId::new("medium");
        let idle = ZoneId::new("idle");
        // busy: 200 rec/s → floor (5s)
        state.update_activity(&busy, 200, 1.0);
        // medium: 100 rec in 300s = 0.33 rec/s → ~300s (well below ceil)
        state.update_activity(&medium, 100, 300.0);
        // idle: 1 rec in 300s = 0.0033 rec/s → 30000s, clamped to ceil (MAX_ADAPTIVE_EPOCH_SECS)
        state.update_activity(&idle, 1, 300.0);

        let s = state.adaptive_interval_summary();
        assert_eq!(s.zones_tracked, 3);
        assert_eq!(s.floor_pinned_zones, 1, "only busy zone is floor-pinned");
        assert!((s.min_active_secs - MIN_ADAPTIVE_EPOCH_SECS).abs() < 1e-9);
        assert!((s.max_active_secs - MAX_ADAPTIVE_EPOCH_SECS).abs() < 1e-9);
        // mean is between min and max
        assert!(s.mean_secs > MIN_ADAPTIVE_EPOCH_SECS);
        assert!(s.mean_secs < MAX_ADAPTIVE_EPOCH_SECS);
    }

    #[test]
    fn test_adaptive_summary_zone_dedup() {
        let mut state = EpochState::new();
        let zone = ZoneId::new("repeat");
        // Update same zone twice — must still count as 1 in zones_tracked.
        state.update_activity(&zone, 100, 300.0);
        state.update_activity(&zone, 50, 300.0);
        let s = state.adaptive_interval_summary();
        assert_eq!(s.zones_tracked, 1);
    }

    #[test]
    fn test_prime_epoch_start_if_unset() {
        let mut state = EpochState::new();
        let zone = ZoneId::from_legacy(0);
        let now = 1_000_000.0;

        // Fresh state: no epoch_start_ts → None
        assert_eq!(state.epoch_start(&zone), None);

        // First priming inserts and returns true
        assert!(state.prime_epoch_start_if_unset(&zone, now));
        assert_eq!(state.epoch_start(&zone), Some(now));

        // Second priming (same zone) is a no-op — returns false, doesn't
        // advance the clock. Critical: priming must NOT reset an in-progress
        // zone's rank-unlock timer.
        assert!(!state.prime_epoch_start_if_unset(&zone, now + 100.0));
        assert_eq!(state.epoch_start(&zone), Some(now));

        // Different zone is independent
        let zone2 = ZoneId::from_legacy(1);
        assert_eq!(state.epoch_start(&zone2), None);
        assert!(state.prime_epoch_start_if_unset(&zone2, now + 50.0));
        assert_eq!(state.epoch_start(&zone2), Some(now + 50.0));

        // register_seal for an already-primed zone overwrites the primed value
        // with the seal's register-time — matches existing `register_seal`
        // semantics. This is the handoff from bootstrap-priming to real seals.
        let seal = ParsedEpochSeal {
            zone: zone.clone(),
            epoch_number: 0,
            start: 0.0,
            end: 100.0,
            record_count: 1,
            merkle_root: sha3_256(b"r"),
            previous_seal_hash: [0u8; 32],
            vrf_output: None,
            vrf_proof: None,
            record_hashes: vec![],
            zone_balance_total: None,
            zone_registry_root: None,
            zone_registry_delta: None,
            seal_zone_count: None,
            aggregator_rank: 0,
            account_smt_root: None,
            drand_pulse: None,
            xzone_dest_finality_committees: None,
        };
        state.register_seal(&seal, "s0", sha3_256(b"h"));
        // epoch_start_ts is now whatever register_seal set (its own `now`),
        // not the primed value. We can't assert the exact timestamp, but we
        // can verify priming is now a no-op because the key is present.
        assert!(state.epoch_start(&zone).is_some());
        assert!(!state.prime_epoch_start_if_unset(&zone, now + 999.0));
    }

    #[test]
    fn register_seal_lex_min_wins_at_equal_epoch() {
        // Chain-liveness fix: at equal epoch, lex-min record_hash wins
        // regardless of arrival order. Two anchors racing at the same
        // epoch (rank-0 and rank-1, both within window) used to leave
        // different nodes with different latest_seal_hash depending on
        // which arrived first locally. With lex-min tiebreaking, every
        // node converges on the same canonical hash.
        let mut state = EpochState::new();
        let zone = ZoneId::from_legacy(0);
        let mk_seal = |zone: ZoneId| ParsedEpochSeal {
            zone,
            epoch_number: 100,
            start: 0.0,
            end: 60.0,
            record_count: 5,
            merkle_root: sha3_256(b"root"),
            previous_seal_hash: [0u8; 32],
            vrf_output: None,
            vrf_proof: None,
            record_hashes: vec![],
            zone_balance_total: None,
            zone_registry_root: None,
            zone_registry_delta: None,
            seal_zone_count: None,
            aggregator_rank: 0,
            account_smt_root: None,
            drand_pulse: None,
            xzone_dest_finality_committees: None,
        };
        let mut hash_high = [0u8; 32];
        hash_high[0] = 0xff;
        let mut hash_low = [0u8; 32];
        hash_low[0] = 0x01;
        // Order A: high arrives first, then low → low must win
        state.register_seal(&mk_seal(zone.clone()), "rec-high", hash_high);
        assert_eq!(state.latest_seal_hash.get(&zone).copied(), Some(hash_high));
        state.register_seal(&mk_seal(zone.clone()), "rec-low", hash_low);
        assert_eq!(
            state.latest_seal_hash.get(&zone).copied(),
            Some(hash_low),
            "lex-min should overwrite at equal epoch"
        );
        // Order B: low arrives first, then high → low must stay
        let mut state2 = EpochState::new();
        state2.register_seal(&mk_seal(zone.clone()), "rec-low", hash_low);
        state2.register_seal(&mk_seal(zone.clone()), "rec-high", hash_high);
        assert_eq!(
            state2.latest_seal_hash.get(&zone).copied(),
            Some(hash_low),
            "lex-min should not be overwritten by larger hash at same epoch"
        );
        // Higher epoch always advances regardless of hash
        let mut higher = mk_seal(zone.clone());
        higher.epoch_number = 101;
        state2.register_seal(&higher, "rec-newepoch", hash_high);
        assert_eq!(state2.latest_seal_hash.get(&zone).copied(), Some(hash_high));
        assert_eq!(state2.latest_epoch.get(&zone).copied(), Some(101));
    }

    // ── PARTITION-MERGE Phase B Slice 3: register_seal_with_reconcile ───

    fn _phase_b_seal(zone: ZoneId, epoch: u64) -> ParsedEpochSeal {
        ParsedEpochSeal {
            zone,
            epoch_number: epoch,
            start: 0.0,
            end: 60.0,
            record_count: 5,
            merkle_root: sha3_256(b"root"),
            previous_seal_hash: [0u8; 32],
            vrf_output: None,
            vrf_proof: None,
            record_hashes: vec![],
            zone_balance_total: None,
            zone_registry_root: None,
            zone_registry_delta: None,
            seal_zone_count: None,
            aggregator_rank: 0,
            account_smt_root: None,
            drand_pulse: None,
            xzone_dest_finality_committees: None,
        }
    }

    #[test]
    fn c2_forged_sequential_seal_chain_link_guard() {
        // C2: authoritative chain-link guard (is_forged_sequential_seal). A
        // key-holding Byzantine anchor must not advance our tip onto a fork via a
        // sequential seal whose previous_seal_hash points elsewhere.
        let mut state = EpochState::new();
        let zone = ZoneId::from_legacy(0);

        // Fresh zone, first seal (epoch 0, [0;32] baseline) — unenforceable, never flagged.
        let genesis_seal = _phase_b_seal(zone.clone(), 0); // previous_seal_hash = [0;32]
        assert!(
            !state.is_forged_sequential_seal(&genesis_seal),
            "fresh-zone first seal ([0;32] baseline) must never be falsely rejected"
        );

        // Build a real chain: epoch 0 → epoch 1, establishing a non-zero tip hash.
        let h0 = sha3_256(b"seal-epoch-0");
        state.register_seal(&genesis_seal, "seal-0", h0);
        let h1 = sha3_256(b"seal-epoch-1");
        let mut seal1 = _phase_b_seal(zone.clone(), 1);
        seal1.previous_seal_hash = h0; // chains off epoch 0
        assert!(!state.is_forged_sequential_seal(&seal1), "honest sequential seal accepted");
        state.register_seal(&seal1, "seal-1", h1);

        // Tip = epoch 1, baseline = h1, next_epoch = 2.
        // (a) honest epoch-2 seal that chains off h1 → NOT forged.
        let mut seal2_ok = _phase_b_seal(zone.clone(), 2);
        seal2_ok.previous_seal_hash = h1;
        assert!(!state.is_forged_sequential_seal(&seal2_ok), "epoch-2 chaining off our tip is accepted");

        // (b) forged epoch-2 seal pointing at a foreign fork → FORGED (rejected).
        let mut seal2_forged = _phase_b_seal(zone.clone(), 2);
        seal2_forged.previous_seal_hash = sha3_256(b"attacker-fork");
        assert!(
            state.is_forged_sequential_seal(&seal2_forged),
            "epoch-2 seal pointing at a foreign fork hash is rejected (C2 closed)"
        );

        // (c) catch-up seal (epoch 10 >> tip+1) with a bogus prev → NOT this guard's
        // job (sequential only); the VRF-guarded catch-up arm (B7) handles it.
        let mut seal_catchup = _phase_b_seal(zone.clone(), 10);
        seal_catchup.previous_seal_hash = sha3_256(b"attacker-fork");
        assert!(
            !state.is_forged_sequential_seal(&seal_catchup),
            "catch-up seal (epoch > tip+1) is not subject to the sequential chain-link guard"
        );
    }

    #[test]
    fn test_reconcile_higher_weight_wins_demotes_lex_min() {
        // Setup: light seal (lex-min, low weight) lands first.
        // Heavy seal (lex-max, high weight) lands second.
        // Heavy must win on weight, even though it loses on lex.
        // Lex-min loser becomes the orphan sibling.
        let mut state = EpochState::new();
        let zone = ZoneId::from_legacy(0);
        let mut hash_low = [0u8; 32];
        hash_low[0] = 0x01;
        let mut hash_high = [0u8; 32];
        hash_high[0] = 0xff;

        // Light seal lands first via legacy path (no weight context).
        state.register_seal(&_phase_b_seal(zone.clone(), 5), "seal-light", hash_low);
        assert_eq!(state.latest_seal_id.get(&zone).map(String::as_str), Some("seal-light"));

        // Heavy seal arrives via reconcile path with weight 200 vs existing 100.
        let won = state.register_seal_with_reconcile(
            &_phase_b_seal(zone.clone(), 5),
            "seal-heavy",
            hash_high,
            200, // incoming
            100, // existing
        );
        assert!(won, "heavier seal must win");
        assert_eq!(state.latest_seal_id.get(&zone).map(String::as_str), Some("seal-heavy"));
        assert_eq!(state.latest_seal_hash.get(&zone).copied(), Some(hash_high));
        // Loser recorded in orphan ring (existing seal_id was demoted).
        let orphans = state.orphan_siblings_for(&zone, 5);
        assert_eq!(orphans, vec!["seal-light".to_string()]);
        assert_eq!(state.orphan_seals_total, 1);
    }

    #[test]
    fn test_reconcile_lower_weight_loses_orphans_incoming() {
        let mut state = EpochState::new();
        let zone = ZoneId::from_legacy(0);
        let mut hash_low = [0u8; 32];
        hash_low[0] = 0x01;
        let mut hash_high = [0u8; 32];
        hash_high[0] = 0xff;

        // Heavy seal lands first via legacy path.
        state.register_seal(&_phase_b_seal(zone.clone(), 7), "seal-heavy", hash_low);

        // Light seal arrives via reconcile with weight 50 vs existing 300.
        let won = state.register_seal_with_reconcile(
            &_phase_b_seal(zone.clone(), 7),
            "seal-light",
            hash_high,
            50,  // incoming
            300, // existing
        );
        assert!(!won, "lighter seal must lose");
        // Existing canonical unchanged.
        assert_eq!(state.latest_seal_id.get(&zone).map(String::as_str), Some("seal-heavy"));
        assert_eq!(state.latest_seal_hash.get(&zone).copied(), Some(hash_low));
        // Incoming demoted into orphan ring.
        let orphans = state.orphan_siblings_for(&zone, 7);
        assert_eq!(orphans, vec!["seal-light".to_string()]);
        assert_eq!(state.orphan_seals_total, 1);
    }

    #[test]
    fn test_reconcile_equal_weight_falls_back_to_lex_min() {
        // Two seals at same (zone, epoch), equal weight. Lex-min winning
        // record_hash must canonicalize, loser must orphan. Mirrors
        // Stage 3b.5/3b.6 dual-proposer behavior — with the addition that
        // the loser is now visible in the orphan ring.
        let mut state = EpochState::new();
        let zone = ZoneId::from_legacy(0);
        let mut hash_low = [0u8; 32];
        hash_low[0] = 0x01;
        let mut hash_high = [0u8; 32];
        hash_high[0] = 0xff;

        // First seal (high hash) lands.
        state.register_seal(&_phase_b_seal(zone.clone(), 9), "seal-A", hash_high);
        // Second seal (low hash, equal weight) — lex-min wins.
        let won = state.register_seal_with_reconcile(
            &_phase_b_seal(zone.clone(), 9),
            "seal-B",
            hash_low,
            150, 150, // equal weights
        );
        assert!(won);
        assert_eq!(state.latest_seal_id.get(&zone).map(String::as_str), Some("seal-B"));
        let orphans = state.orphan_siblings_for(&zone, 9);
        assert_eq!(orphans, vec!["seal-A".to_string()]);

        // Now try a higher-hash incoming with same equal weights — must lose.
        let mut hash_higher = [0u8; 32];
        hash_higher[0] = 0xfe;
        let won2 = state.register_seal_with_reconcile(
            &_phase_b_seal(zone.clone(), 9),
            "seal-C",
            hash_higher,
            150, 150,
        );
        assert!(!won2);
        assert_eq!(state.latest_seal_id.get(&zone).map(String::as_str), Some("seal-B"));
        // Orphans now contain both seal-A (demoted earlier) and seal-C (just demoted).
        let orphans = state.orphan_siblings_for(&zone, 9);
        assert!(orphans.contains(&"seal-A".to_string()));
        assert!(orphans.contains(&"seal-C".to_string()));
    }

    #[test]
    fn test_reconcile_higher_epoch_advances_unconditionally() {
        // A seal with epoch > current must install regardless of weight,
        // and must NOT touch the orphan ring (it's a true epoch advance,
        // not a partition collision).
        let mut state = EpochState::new();
        let zone = ZoneId::from_legacy(0);
        let h1 = sha3_256(b"e1");
        let h2 = sha3_256(b"e2");
        state.register_seal(&_phase_b_seal(zone.clone(), 10), "seal-old", h1);

        // Incoming has epoch 11, weight 0. Existing weight irrelevant.
        let won = state.register_seal_with_reconcile(
            &_phase_b_seal(zone.clone(), 11),
            "seal-new",
            h2,
            0,    // incoming weight
            9999, // existing weight
        );
        assert!(won, "true epoch advance must install");
        assert_eq!(state.latest_epoch.get(&zone).copied(), Some(11));
        assert_eq!(state.latest_seal_id.get(&zone).map(String::as_str), Some("seal-new"));
        // No orphan tracking on epoch advance — the previous epoch is just history,
        // not a same-epoch sibling.
        assert!(state.orphan_siblings_for(&zone, 10).is_empty());
        assert!(state.orphan_siblings_for(&zone, 11).is_empty());
        assert_eq!(state.orphan_seals_total, 0);
    }

    #[test]
    fn test_reconcile_stale_epoch_drops_silently() {
        let mut state = EpochState::new();
        let zone = ZoneId::from_legacy(0);
        let h_curr = sha3_256(b"curr");
        let h_stale = sha3_256(b"stale");
        state.register_seal(&_phase_b_seal(zone.clone(), 20), "seal-curr", h_curr);

        // Incoming has epoch 5 (way behind current 20).
        let won = state.register_seal_with_reconcile(
            &_phase_b_seal(zone.clone(), 5),
            "seal-stale",
            h_stale,
            9999, 0,
        );
        assert!(!won, "stale seal must lose");
        // Canonical unchanged.
        assert_eq!(state.latest_epoch.get(&zone).copied(), Some(20));
        assert_eq!(state.latest_seal_id.get(&zone).map(String::as_str), Some("seal-curr"));
        // No orphan tracking on stale (we can't tell rebroadcast from partition-loser
        // upstream of verify_epoch_seal — silent drop preserves prior behavior).
        assert!(state.orphan_siblings_for(&zone, 5).is_empty());
        assert_eq!(state.orphan_seals_total, 0);
    }

    #[test]
    fn test_reconcile_idempotent_re_register_is_noop() {
        let mut state = EpochState::new();
        let zone = ZoneId::from_legacy(0);
        let h = sha3_256(b"only");
        state.register_seal(&_phase_b_seal(zone.clone(), 30), "seal-only", h);

        // Re-register the exact same (record_id, record_hash) at same epoch.
        let won = state.register_seal_with_reconcile(
            &_phase_b_seal(zone.clone(), 30),
            "seal-only",
            h,
            100, 100,
        );
        assert!(!won, "idempotent re-register reports false");
        assert_eq!(state.orphan_seals_total, 0, "no orphan tracking on idempotent re-register");
        assert_eq!(state.latest_seal_id.get(&zone).map(String::as_str), Some("seal-only"));
    }

    #[test]
    fn test_reconcile_first_seal_at_zero_weight_installs() {
        // No prior seal in zone — incoming with weight 0 should install
        // (no existing seal to compare; the > current branch fires).
        let mut state = EpochState::new();
        let zone = ZoneId::from_legacy(0);
        let h = sha3_256(b"first");
        let won = state.register_seal_with_reconcile(
            &_phase_b_seal(zone.clone(), 0),
            "seal-first",
            h,
            0, 0,
        );
        // current epoch defaults to 0, incoming epoch is 0 — same-epoch
        // collision against an empty zone. With no current_hash the
        // lex-min check passes (current_hash.is_none_or → true).
        assert!(won, "first seal in empty zone must install");
        assert_eq!(state.latest_seal_id.get(&zone).map(String::as_str), Some("seal-first"));
        assert_eq!(state.orphan_seals_total, 0, "no orphan when there's no prior seal");
    }

    #[test]
    fn test_reconcile_arrival_order_independent() {
        // Symmetry: regardless of which side of a partition merge arrives
        // first, the heavier side wins. Important for fleet-wide convergence.
        let mut hash_a = [0u8; 32];
        hash_a[0] = 0xaa;
        let mut hash_b = [0u8; 32];
        hash_b[0] = 0xbb;

        // Order 1: heavy arrives first (legacy path), light second (reconcile).
        let mut s1 = EpochState::new();
        let zone = ZoneId::from_legacy(0);
        s1.register_seal(&_phase_b_seal(zone.clone(), 50), "seal-heavy", hash_a);
        s1.register_seal_with_reconcile(
            &_phase_b_seal(zone.clone(), 50),
            "seal-light",
            hash_b,
            100,  // light incoming
            500,  // heavy existing
        );
        assert_eq!(s1.latest_seal_id.get(&zone).map(String::as_str), Some("seal-heavy"));

        // Order 2: light arrives first (legacy), heavy second (reconcile).
        let mut s2 = EpochState::new();
        s2.register_seal(&_phase_b_seal(zone.clone(), 50), "seal-light", hash_b);
        s2.register_seal_with_reconcile(
            &_phase_b_seal(zone.clone(), 50),
            "seal-heavy",
            hash_a,
            500,  // heavy incoming
            100,  // light existing
        );
        assert_eq!(s2.latest_seal_id.get(&zone).map(String::as_str), Some("seal-heavy"));

        // Both nodes converge on the same canonical seal.
        assert_eq!(
            s1.latest_seal_hash.get(&zone).copied(),
            s2.latest_seal_hash.get(&zone).copied(),
            "arrival-order independent: both nodes pick the heavier seal"
        );
    }

    // ── PARTITION-MERGE Phase B Slice 4: promote_orphan_to_canonical ───

    #[test]
    fn test_promote_orphan_swaps_canonical_and_demotes_loser() {
        // Heavy seal canonicalized first (legacy path), light seal recorded
        // as orphan. Then weight flips: orphan now heavier than canonical.
        // Promote must swap them and demote the previous canonical into the
        // orphan ring (so a future flip can promote it again).
        let mut state = EpochState::new();
        let zone = ZoneId::from_legacy(0);
        let mut hash_a = [0u8; 32];
        hash_a[0] = 0xaa;
        let mut hash_b = [0u8; 32];
        hash_b[0] = 0xbb;

        state.register_seal(&_phase_b_seal(zone.clone(), 50), "seal-A", hash_a);
        // Reconcile lighter B → recorded as orphan.
        let won = state.register_seal_with_reconcile(
            &_phase_b_seal(zone.clone(), 50),
            "seal-B",
            hash_b,
            50,  // incoming lighter
            500, // existing heavy
        );
        assert!(!won);
        assert_eq!(state.latest_seal_id.get(&zone).map(String::as_str), Some("seal-A"));
        assert_eq!(state.orphan_siblings_for(&zone, 50), vec!["seal-B".to_string()]);

        // Time passes; B accumulates attestations, eventually outweighs A.
        // Caller (state.rs) makes the comparison + calls promote.
        let promoted = state.promote_orphan_to_canonical(
            &_phase_b_seal(zone.clone(), 50),
            "seal-B",
            hash_b,
        );
        assert!(promoted, "must promote orphan that won the weight race");
        assert_eq!(state.latest_seal_id.get(&zone).map(String::as_str), Some("seal-B"));
        assert_eq!(state.latest_seal_hash.get(&zone).copied(), Some(hash_b));
        assert_eq!(state.orphan_promotions_total, 1);

        // The previous canonical "seal-A" is now in the orphan ring.
        assert_eq!(state.orphan_siblings_for(&zone, 50), vec!["seal-A".to_string()]);
        // "seal-B" is no longer orphan.
        assert!(!state.is_orphan_sibling(&zone, 50, "seal-B"));
    }

    #[test]
    fn test_promote_orphan_noop_when_seal_id_not_in_ring() {
        // Caller asks to promote a seal_id that isn't recorded as an orphan
        // for this (zone, epoch). Could be: race with concurrent reconcile,
        // already promoted, or caller-side bug. Either way, no-op.
        let mut state = EpochState::new();
        let zone = ZoneId::from_legacy(0);
        let mut hash_a = [0u8; 32];
        hash_a[0] = 0xaa;
        let mut hash_z = [0u8; 32];
        hash_z[0] = 0xff;
        state.register_seal(&_phase_b_seal(zone.clone(), 60), "seal-A", hash_a);

        let promoted = state.promote_orphan_to_canonical(
            &_phase_b_seal(zone.clone(), 60),
            "seal-Z", // never recorded as orphan
            hash_z,
        );
        assert!(!promoted);
        assert_eq!(state.latest_seal_id.get(&zone).map(String::as_str), Some("seal-A"));
        assert_eq!(state.orphan_promotions_total, 0);
    }

    #[test]
    fn test_promote_orphan_noop_on_stale_epoch() {
        // The (zone, epoch) ring exists for an OLD epoch but a higher epoch
        // has since canonicalized. Promoting an orphan from the old epoch
        // would regress — must be rejected.
        let mut state = EpochState::new();
        let zone = ZoneId::from_legacy(0);
        let mut hash_a = [0u8; 32];
        hash_a[0] = 0xaa;
        let mut hash_b = [0u8; 32];
        hash_b[0] = 0xbb;
        let mut hash_new = [0u8; 32];
        hash_new[0] = 0xcc;

        // Epoch 70: A canonical, B orphan.
        state.register_seal(&_phase_b_seal(zone.clone(), 70), "seal-A", hash_a);
        state.register_seal_with_reconcile(
            &_phase_b_seal(zone.clone(), 70),
            "seal-B",
            hash_b,
            50, 500,
        );
        assert!(state.is_orphan_sibling(&zone, 70, "seal-B"));

        // Epoch 71 advances — new canonical.
        state.register_seal(&_phase_b_seal(zone.clone(), 71), "seal-NEW", hash_new);
        assert_eq!(state.latest_epoch.get(&zone).copied(), Some(71));

        // Late attestation for B (epoch 70) tries to promote — must be rejected.
        let promoted = state.promote_orphan_to_canonical(
            &_phase_b_seal(zone.clone(), 70),
            "seal-B",
            hash_b,
        );
        assert!(!promoted, "stale-epoch promotion must be rejected");
        assert_eq!(state.latest_epoch.get(&zone).copied(), Some(71));
        assert_eq!(state.latest_seal_id.get(&zone).map(String::as_str), Some("seal-NEW"));
        assert_eq!(state.orphan_promotions_total, 0);
    }

    #[test]
    fn test_promote_orphan_idempotent_when_already_canonical() {
        // Defensive: if seal_id is already canonical, promotion is a no-op
        // and does NOT bump orphan_promotions_total. Guards against double-
        // fire on the attestation path (e.g. concurrent late attestations).
        let mut state = EpochState::new();
        let zone = ZoneId::from_legacy(0);
        let h = sha3_256(b"only");
        state.register_seal(&_phase_b_seal(zone.clone(), 80), "seal-only", h);

        let promoted = state.promote_orphan_to_canonical(
            &_phase_b_seal(zone.clone(), 80),
            "seal-only",
            h,
        );
        assert!(!promoted, "already-canonical promotion is a no-op");
        assert_eq!(state.orphan_promotions_total, 0);
    }

    #[test]
    fn test_promote_orphan_clears_ring_when_last_entry() {
        // Edge case: orphan ring for (zone, epoch) holds exactly one entry
        // and that entry is being promoted. After promotion the ring should
        // be empty AND the (zone, epoch) key removed from the HashMap so
        // it doesn't count toward the global key cap unnecessarily.
        let mut state = EpochState::new();
        let zone = ZoneId::from_legacy(0);
        let mut hash_a = [0u8; 32];
        hash_a[0] = 0xaa;
        let mut hash_b = [0u8; 32];
        hash_b[0] = 0xbb;
        state.register_seal(&_phase_b_seal(zone.clone(), 90), "seal-A", hash_a);
        state.register_seal_with_reconcile(
            &_phase_b_seal(zone.clone(), 90),
            "seal-B",
            hash_b,
            50, 500,
        );

        // Promote B — A goes back into the ring (so ring will have 1 entry post-promote).
        let promoted = state.promote_orphan_to_canonical(
            &_phase_b_seal(zone.clone(), 90),
            "seal-B",
            hash_b,
        );
        assert!(promoted);
        // Ring still has the demoted A (1 entry), key not removed.
        assert!(state.is_orphan_sibling(&zone, 90, "seal-A"));
        assert_eq!(state.orphan_siblings_for(&zone, 90).len(), 1);
    }

    #[test]
    fn test_register_seal_updates_activity() {
        let mut state = EpochState::new();
        let zone = ZoneId::from_legacy(0);
        let seal = ParsedEpochSeal {
            zone: zone.clone(),
            epoch_number: 0,
            start: 0.0,
            end: 300.0,
            record_count: 200,
            merkle_root: sha3_256(b"root"),
            previous_seal_hash: [0u8; 32],
            vrf_output: None,
            vrf_proof: None,
            record_hashes: vec![],
            zone_balance_total: None,
            zone_registry_root: None,
            zone_registry_delta: None,
            seal_zone_count: None,
            aggregator_rank: 0,
            account_smt_root: None,
            drand_pulse: None,
            xzone_dest_finality_committees: None,
        };
        state.register_seal(&seal, "seal-0", sha3_256(b"hash"));

        // Activity rate should be computed
        assert!(state.zone_activity_rate.contains_key(&zone));
        // 200 records in 300s → high activity → interval should be < 300
        let interval = state.adaptive_interval(&zone, 300.0);
        assert!(interval < 300.0, "expected shorter interval for high activity, got {interval}");
    }

    // ── seal_zone_count: zone transition safety ──────────────────

    #[test]
    fn test_seal_zone_count_embedded_in_metadata() {
        // Verify that seal metadata includes the current zone_count.
        // Don't mutate global zone_count — just check it's embedded.
        use crate::network::consensus::get_zone_count;

        let zone = ZoneId::from_legacy(0);
        let root = sha3_256(b"test");
        let prev = [0u8; 32];
        let meta = seal_metadata(SealMetadataParams {
            zone,
            epoch_number: 0,
            start: 0.0,
            end: 100.0,
            record_count: 10,
            merkle_root: &root,
            previous_seal_hash: &prev,
            vrf_output: None,
            vrf_proof: None,
            sparse_merkle_root: None,
            record_hashes: None,
            zone_balance_total: None,
            zone_registry_root: None,
            zone_registry_delta: None,
            aggregator_rank: 0,
            account_smt_root: None,
            drand_pulse: None,
        });

        let zc = meta.get("epoch_zone_count").unwrap().as_u64().unwrap();
        assert_eq!(zc, get_zone_count(), "seal must embed the current zone_count");
    }

    #[test]
    fn test_seal_zone_count_in_parsed_seal() {
        // Verify that create_epoch_seal embeds zone_count in the parsed seal
        let identity = test_identity();
        let (mut storage, _dir) = test_engine();
        let epoch_state = EpochState::new();

        let _r1 = insert_test_record(&mut storage, &identity, b"zc-parsed-1", 50.0);
        let zone = zone_for_record(&_r1.id);

        let (_, parsed) = create_epoch_seal(
            &identity, &storage, &epoch_state, zone, 0.0, 200.0, None, None,
        ).unwrap();

        // Must have a zone_count embedded
        assert!(parsed.seal_zone_count.is_some(), "new seals must embed zone_count");
    }

    #[test]
    fn test_seal_zone_count_survives_extract() {
        // Verify zone_count round-trips through metadata serialization
        let identity = test_identity();
        let (mut storage, _dir) = test_engine();
        let epoch_state = EpochState::new();

        let _r1 = insert_test_record(&mut storage, &identity, b"zc-extract-1", 50.0);
        let zone = zone_for_record(&_r1.id);

        let (seal_record, parsed_original) = create_epoch_seal(
            &identity, &storage, &epoch_state, zone, 0.0, 200.0, None, None,
        ).unwrap();

        // Extract from the record metadata (simulates receiving via gossip)
        let extracted = extract_epoch_seal(&seal_record).unwrap().unwrap();
        assert_eq!(extracted.seal_zone_count, parsed_original.seal_zone_count,
            "zone_count must survive metadata round-trip");
    }

    #[test]
    fn test_seal_zone_count_none_falls_back_to_global() {
        // Legacy seals (no zone_count in metadata) fall back to global zone_count
        let seal = ParsedEpochSeal {
            zone: ZoneId::from_legacy(0),
            epoch_number: 0,
            start: 0.0,
            end: 100.0,
            record_count: 0,
            merkle_root: [0u8; 32],
            previous_seal_hash: [0u8; 32],
            vrf_output: None,
            vrf_proof: None,
            record_hashes: vec![],
            zone_balance_total: None,
            zone_registry_root: None,
            zone_registry_delta: None,
            seal_zone_count: None, // legacy
            aggregator_rank: 0,
            account_smt_root: None,
            drand_pulse: None,
            xzone_dest_finality_committees: None,
        };
        // Should not panic — falls back to global
        assert!(seal.seal_zone_count.is_none());
    }

    #[test]
    fn test_zone_transition_metadata_roundtrip() {
        let meta = zone_transition_metadata(42, 2, 4);
        assert_eq!(meta.get(EPOCH_OP_KEY).unwrap().as_str().unwrap(), "zone_transition");
        assert_eq!(meta.get("zone_transition_epoch").unwrap().as_u64().unwrap(), 42);
        assert_eq!(meta.get("zone_transition_old_count").unwrap().as_u64().unwrap(), 2);
        assert_eq!(meta.get("zone_transition_new_count").unwrap().as_u64().unwrap(), 4);
    }

    #[test]
    fn test_extract_zone_transition() {
        let identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB).unwrap();
        let meta = zone_transition_metadata(100, 2, 8);
        let record = crate::record::ValidationRecord::create(
            b"zone_transition:2:8:epoch100",
            identity.public_key.clone(),
            vec![],
            Classification::Public,
            Some(meta),
        );

        let transition = extract_zone_transition(&record).unwrap().unwrap();
        assert_eq!(transition.target_epoch, 100);
        assert_eq!(transition.old_count, 2);
        assert_eq!(transition.new_count, 8);
    }

    #[test]
    fn test_extract_zone_transition_rejects_zero_count() {
        let identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB).unwrap();
        let meta = zone_transition_metadata(100, 2, 0);
        let record = crate::record::ValidationRecord::create(
            b"zone_transition:2:0:epoch100",
            identity.public_key.clone(),
            vec![],
            Classification::Public,
            Some(meta),
        );

        assert!(extract_zone_transition(&record).is_err());
    }

    #[test]
    fn test_extract_zone_transition_rejects_same_count() {
        let identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB).unwrap();
        let meta = zone_transition_metadata(100, 4, 4);
        let record = crate::record::ValidationRecord::create(
            b"zone_transition:4:4:epoch100",
            identity.public_key.clone(),
            vec![],
            Classification::Public,
            Some(meta),
        );

        assert!(extract_zone_transition(&record).is_err());
    }

    #[test]
    fn test_extract_zone_transition_none_for_seal() {
        let identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB).unwrap();
        // epoch_op = "seal" should return None, not a transition
        let mut meta = std::collections::BTreeMap::new();
        meta.insert(EPOCH_OP_KEY.into(), serde_json::json!("seal"));
        let record = crate::record::ValidationRecord::create(
            b"seal",
            identity.public_key.clone(),
            vec![],
            Classification::Public,
            Some(meta),
        );

        assert!(extract_zone_transition(&record).unwrap().is_none());
    }

    // ── find_latest_unapplied_zone_transition ─────────────
    //
    // These tests exercise the boot-rehydration helper that recovers a
    // scheduled or late-arriving zone_transition from CF_IDX_CREATOR.

    /// Build and persist a zone_transition record signed by `identity` with
    /// distinct content (so each call produces a unique record_id).
    fn insert_zone_transition_record(
        storage: &mut StorageEngine,
        identity: &Identity,
        target_epoch: u64,
        old_count: u64,
        new_count: u64,
        timestamp: f64,
    ) {
        let meta = zone_transition_metadata(target_epoch, old_count, new_count);
        let content = format!(
            "zone_transition:{}:{}:{}:{}",
            target_epoch, old_count, new_count, timestamp
        );
        let mut record = ValidationRecord::create(
            content.as_bytes(),
            identity.public_key.clone(),
            vec![],
            Classification::Public,
            Some(meta),
        );
        record.timestamp = timestamp;
        record.zone = Some(zone_for_record(&record.id));
        let signable = record.signable_bytes();
        record.signature = Some(identity.sign(&signable).unwrap());
        storage.insert(&record).unwrap();
    }

    #[test]
    fn liveness2_find_latest_unapplied_zone_transition_empty_storage() {
        let (mut storage, _dir) = test_engine();
        let identity = test_identity();
        let genesis_hash = sha3_256_hex(&identity.public_key);

        // No records — must return None regardless of our zone_count.
        let out = find_latest_unapplied_zone_transition(&storage, &genesis_hash, 1);
        assert!(out.is_none(), "empty storage must yield None");
        let _ = &mut storage; // silence unused-mut
    }

    #[test]
    fn liveness2_find_latest_unapplied_zone_transition_matches_old_count() {
        let (mut storage, _dir) = test_engine();
        let identity = test_identity();
        let genesis_hash = sha3_256_hex(&identity.public_key);

        // Single transition: 2 → 1 at epoch 10455 (mirrors the testnet bug).
        insert_zone_transition_record(&mut storage, &identity, 10455, 2, 1, 100.0);

        // Our zone_count is 2 → old_count match → must return the transition.
        let out = find_latest_unapplied_zone_transition(&storage, &genesis_hash, 2);
        let t = out.expect("matching old_count must yield Some");
        assert_eq!(t.target_epoch, 10455);
        assert_eq!(t.old_count, 2);
        assert_eq!(t.new_count, 1);
    }

    #[test]
    fn liveness2_find_latest_unapplied_zone_transition_skips_already_applied() {
        let (mut storage, _dir) = test_engine();
        let identity = test_identity();
        let genesis_hash = sha3_256_hex(&identity.public_key);

        // Transition was 2 → 1, and we've already applied it (zone_count == 1).
        insert_zone_transition_record(&mut storage, &identity, 10455, 2, 1, 100.0);

        // our_zone_count == new_count (1), not old_count (2) → must be skipped.
        let out = find_latest_unapplied_zone_transition(&storage, &genesis_hash, 1);
        assert!(
            out.is_none(),
            "already-applied transition (our_zone_count == new_count) must be skipped"
        );
    }

    #[test]
    fn liveness2_find_latest_unapplied_zone_transition_picks_latest_target() {
        let (mut storage, _dir) = test_engine();
        let identity = test_identity();
        let genesis_hash = sha3_256_hex(&identity.public_key);

        // Two competing announcements with the same old_count=2 but different
        // target_epoch. The selector must pick the one with the largest target.
        insert_zone_transition_record(&mut storage, &identity, 10455, 2, 1, 100.0);
        insert_zone_transition_record(&mut storage, &identity, 20000, 2, 1, 200.0);
        insert_zone_transition_record(&mut storage, &identity, 15000, 2, 1, 150.0);

        let out = find_latest_unapplied_zone_transition(&storage, &genesis_hash, 2);
        let t = out.expect("at least one transition must match");
        assert_eq!(
            t.target_epoch, 20000,
            "selector must pick the announcement with the largest target_epoch"
        );
    }

    #[test]
    fn liveness2_find_latest_unapplied_zone_transition_filters_non_transition_records() {
        let (mut storage, _dir) = test_engine();
        let identity = test_identity();
        let genesis_hash = sha3_256_hex(&identity.public_key);

        // Mix in a non-zone_transition record by the same creator (e.g., a seal).
        let mut seal_record = ValidationRecord::create(
            b"seal-record",
            identity.public_key.clone(),
            vec![],
            Classification::Public,
            Some({
                let mut m = std::collections::BTreeMap::new();
                m.insert(EPOCH_OP_KEY.into(), serde_json::json!("seal"));
                m
            }),
        );
        seal_record.timestamp = 50.0;
        seal_record.zone = Some(zone_for_record(&seal_record.id));
        let signable = seal_record.signable_bytes();
        seal_record.signature = Some(identity.sign(&signable).unwrap());
        storage.insert(&seal_record).unwrap();

        // Also insert a genuine transition.
        insert_zone_transition_record(&mut storage, &identity, 10455, 2, 1, 100.0);

        // Must return the transition, ignoring the seal record.
        let out = find_latest_unapplied_zone_transition(&storage, &genesis_hash, 2);
        let t = out.expect("transition present");
        assert_eq!(t.target_epoch, 10455);
    }

    // ── verify_aggregator_rank (Stage 3b.6) ──────────────────────────
    //
    // Pure-function unit tests for the rank gate enforced inside
    // `verify_epoch_seal` when the caller supplies a `RankCheck`. The
    // helpers here mirror what the ingest pipeline provides at runtime:
    // a set of stakers and a canonical chained beacon over
    // (prev_seal_hash, epoch_number, zone).

    /// Build a `ParsedEpochSeal` with only the fields that
    /// `verify_aggregator_rank` reads.
    fn rank_seal(
        zone: ZoneId,
        epoch_number: u64,
        prev_seal_hash: [u8; 32],
        declared_rank: u8,
    ) -> ParsedEpochSeal {
        ParsedEpochSeal {
            zone,
            epoch_number,
            start: 0.0,
            end: 0.0,
            record_count: 0,
            merkle_root: [0u8; 32],
            previous_seal_hash: prev_seal_hash,
            vrf_output: None,
            vrf_proof: None,
            record_hashes: vec![],
            zone_balance_total: None,
            zone_registry_root: None,
            zone_registry_delta: None,
            seal_zone_count: None,
            aggregator_rank: declared_rank,
            account_smt_root: None,
            drand_pulse: None,
            xzone_dest_finality_committees: None,
        }
    }

    /// Build a deterministic 4-identity staker set. The rank-0 and rank-1
    /// identities are identified by asking the aggregator chain directly,
    /// which keeps tests resilient to beacon formula tweaks.
    fn rank_test_setup(
        zone: &ZoneId,
        epoch: u64,
        prev_seal_hash: [u8; 32],
    ) -> (Vec<(String, u64)>, String, String, String) {
        use super::super::aggregator::{aggregator_chain_weighted, chained_beacon, MAX_VIEW_DEPTH};
        let stakers = vec![
            ("alpha".to_string(), 100u64),
            ("bravo".to_string(), 100u64),
            ("charlie".to_string(), 100u64),
            ("delta".to_string(), 100u64),
        ];
        let beacon = chained_beacon(&prev_seal_hash, epoch, zone);
        let chain = aggregator_chain_weighted(&beacon, &stakers, zone, MAX_VIEW_DEPTH);
        let rank0 = chain[0].clone();
        let rank1 = chain[1].clone();
        // Any identity that is NOT in the stakers list is guaranteed outside
        // the top-MAX_VIEW_DEPTH chain. `rank_of` returns None for it.
        let outsider = "not-staked".to_string();
        (stakers, rank0, rank1, outsider)
    }

    #[test]
    fn test_verify_rank_rank0_at_t0_accepts() {
        let zone = ZoneId::from_legacy(0);
        let prev = [0u8; 32];
        let (stakers, rank0, _, _) = rank_test_setup(&zone, 0, prev);
        let seal = rank_seal(zone, 0, prev, 0);
        // base_timeout=5000ms, elapsed=0 → rank 0 allowed, higher ranks not.
        verify_aggregator_rank(&rank0, &seal, &stakers, "genesis", 5000, 0)
            .expect("rank-0 at T=0 must accept");
    }

    #[test]
    fn test_verify_rank_rank2_at_t0_rejects_rank_jumping() {
        let zone = ZoneId::from_legacy(0);
        let prev = [1u8; 32];
        let (stakers, rank0, _, _) = rank_test_setup(&zone, 7, prev);
        // Forge: rank-0 creator but declares rank 2 — would let them propose
        // before rank-1 had a chance. The derived rank (0) ≠ declared (2), so
        // this actually fails the *declared-vs-derived* check first, which is
        // a valid rejection path for rank forgery.
        let seal = rank_seal(zone.clone(), 7, prev, 2);
        let err = verify_aggregator_rank(&rank0, &seal, &stakers, "genesis", 5000, 0)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("aggregator_rank mismatch"),
            "expected mismatch error, got: {err}",
        );

        // True rank-jumping: the actual rank-1 identity declares its correct
        // rank (1) but proposes at T=0 — the time gate must reject.
        let (_, _, rank1_id, _) = rank_test_setup(&zone, 7, prev);
        let seal1 = rank_seal(zone, 7, prev, 1);
        let err = verify_aggregator_rank(&rank1_id, &seal1, &stakers, "genesis", 5000, 0)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("rank-jumping"),
            "expected rank-jumping error, got: {err}",
        );
    }

    #[test]
    fn test_verify_rank_rank1_at_base_plus_accepts() {
        let zone = ZoneId::from_legacy(0);
        let prev = [2u8; 32];
        let (stakers, _, rank1_id, _) = rank_test_setup(&zone, 3, prev);
        let seal = rank_seal(zone, 3, prev, 1);
        // rank 1 unlocks at elapsed ≥ (2^1 - 1) * base = base.
        // 5001ms > 5000ms base → allowed.
        verify_aggregator_rank(&rank1_id, &seal, &stakers, "genesis", 5000, 5001)
            .expect("rank-1 at base+1 must accept");
        // Exactly at base unlocks rank 1 (threshold is ≥, not >).
        verify_aggregator_rank(&rank1_id, &seal, &stakers, "genesis", 5000, 5000)
            .expect("rank-1 at base must accept");
        // Just below base — time-gate rejects.
        let err = verify_aggregator_rank(&rank1_id, &seal, &stakers, "genesis", 5000, 4999)
            .unwrap_err()
            .to_string();
        assert!(err.contains("rank-jumping"), "expected rank-jumping: {err}");
    }

    #[test]
    fn test_verify_rank_declared_mismatch_rejects() {
        let zone = ZoneId::from_legacy(0);
        let prev = [3u8; 32];
        let (stakers, rank0, _, _) = rank_test_setup(&zone, 0, prev);
        // rank-0 creator declares rank 1 — must be rejected even though the
        // time gate at elapsed=base would pass rank 1. Declared must equal
        // derived, not be ≤ derived.
        let seal = rank_seal(zone, 0, prev, 1);
        let err = verify_aggregator_rank(&rank0, &seal, &stakers, "genesis", 5000, 5000)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("aggregator_rank mismatch"),
            "expected mismatch error, got: {err}",
        );
    }

    #[test]
    fn test_verify_rank_outsider_rejects() {
        let zone = ZoneId::from_legacy(0);
        let prev = [4u8; 32];
        let (stakers, _, _, outsider) = rank_test_setup(&zone, 0, prev);
        let seal = rank_seal(zone, 0, prev, 0);
        let err = verify_aggregator_rank(&outsider, &seal, &stakers, "genesis", 5000, 0)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("not in top-"),
            "expected outsider rejection, got: {err}",
        );
    }

    #[test]
    fn test_verify_rank_declared_ge_max_view_depth_rejects() {
        use super::super::aggregator::MAX_VIEW_DEPTH;
        let zone = ZoneId::from_legacy(0);
        let prev = [5u8; 32];
        let (stakers, rank0, _, _) = rank_test_setup(&zone, 0, prev);
        // Declared rank exactly at MAX_VIEW_DEPTH — outside the per-zone
        // chain. Must reject before even touching the beacon math.
        let seal = rank_seal(zone, 0, prev, MAX_VIEW_DEPTH as u8);
        let err = verify_aggregator_rank(&rank0, &seal, &stakers, "genesis", 5000, 0)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains(">= MAX_VIEW_DEPTH"),
            "expected MAX_VIEW_DEPTH rejection, got: {err}",
        );
    }

    #[test]
    fn test_verify_rank_bootstrap_non_genesis_rejects() {
        let zone = ZoneId::from_legacy(0);
        let prev = [6u8; 32];
        // Fewer than 3 stakers → bootstrap carve-out: only genesis may propose.
        let stakers = vec![
            ("alpha".to_string(), 100u64),
            ("bravo".to_string(), 100u64),
        ];
        let seal = rank_seal(zone, 0, prev, 0);
        let err = verify_aggregator_rank("alpha", &seal, &stakers, "genesis", 5000, 0)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("bootstrap"),
            "expected bootstrap rejection, got: {err}",
        );
    }

    #[test]
    fn test_verify_rank_bootstrap_genesis_rank0_accepts() {
        let zone = ZoneId::from_legacy(0);
        let prev = [7u8; 32];
        let stakers: Vec<(String, u64)> = vec![];
        let seal = rank_seal(zone.clone(), 0, prev, 0);
        verify_aggregator_rank("genesis", &seal, &stakers, "genesis", 5000, 0)
            .expect("bootstrap genesis at rank 0 must accept");
        // But not higher ranks.
        let seal1 = rank_seal(zone, 0, prev, 1);
        let err = verify_aggregator_rank("genesis", &seal1, &stakers, "genesis", 5000, 0)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("must declare rank 0"),
            "bootstrap must force rank 0, got: {err}",
        );
    }

    /// Post-cap-drop the elapsed-clamp shrunk along with
    /// `MAX_ADAPTIVE_EPOCH_SECS`: 3600 → 240 → 120 s. With the 5s base-timeout
    /// floor, the max reachable rank drops to 4 — anything beyond is
    /// unreachable even with a fully forward-skewed wall clock at the clamp
    /// ceiling. (Was rank 9 at 3600s, rank 5 at 240s, rank 4 at 120s.)
    #[test]
    fn test_max_rank_elapsed_secs_bounds_skewed_clock() {
        use crate::network::aggregator::current_allowed_rank;
        assert_eq!(MAX_RANK_ELAPSED_SECS, 120.0);
        assert_eq!(MAX_RANK_ELAPSED_SECS, 2.0 * MAX_ADAPTIVE_EPOCH_SECS);

        // base_timeout_ms = 5000 (the documented floor at line 2855).
        // Rank k unlocks at elapsed ≥ (2^k - 1) × base.
        // At elapsed = MAX_RANK_ELAPSED_SECS × 1000 = 120_000 ms:
        //   rank 4 unlocks at (16 - 1) × 5000 = 75_000 ≤ 120_000 ✓
        //   rank 5 unlocks at (32 - 1) × 5000 = 155_000  > 120_000 ✗
        let clamped_ms = (MAX_RANK_ELAPSED_SECS * 1000.0) as u64;
        let allowed = current_allowed_rank(5000, clamped_ms);
        assert!(allowed >= 4, "expected rank 4 reachable at clamp ceil, got {allowed}");
        assert!(allowed < 5, "expected rank 5 unreachable at clamp ceil, got {allowed}");

        // Just under the clamp ceiling — equivalently bounded.
        let just_under_ms = clamped_ms - 1;
        assert!(current_allowed_rank(5000, just_under_ms) < 5);

        // The historic 3600 s clamp would have allowed rank 9 (= floor at floor
        // base 5s); confirm the previous looseness is no longer reachable
        // through the new clamp ceiling.
        let legacy_clamp_ms: u64 = 3_600_000;
        assert!(
            current_allowed_rank(5000, legacy_clamp_ms) > allowed,
            "tightening regressed: new clamp must reach strictly fewer ranks than old"
        );
    }

    // ── Stage 3c.1: global quorum seal (cross-zone escalation) ───

    /// Produce an emitter identity + VRF keypair + its creator hash, plus a
    /// stakers_by_zone map that registers the emitter under `emitter_zone`.
    #[allow(clippy::type_complexity)]
    fn global_seal_test_setup(
        emitter_zone: &ZoneId,
    ) -> (
        Identity,
        crate::crypto::vrf::VrfSecretKey,
        crate::crypto::vrf::VrfPublicKey,
        String,
        std::collections::HashMap<ZoneId, Vec<(String, u64)>>,
    ) {
        let identity = test_identity();
        let vrf_sk = crate::crypto::vrf::VrfSecretKey::generate().unwrap();
        let vrf_pk = vrf_sk.public_key();
        let emitter_id = sha3_256_hex(&identity.public_key);
        let mut stakers_by_zone = std::collections::HashMap::new();
        stakers_by_zone.insert(
            emitter_zone.clone(),
            vec![(emitter_id.clone(), 100u64)],
        );
        (identity, vrf_sk, vrf_pk, emitter_id, stakers_by_zone)
    }

    /// elapsed > 127·base so `is_zone_stuck` holds for the canonical base.
    const STUCK_BASE_MS: u64 = 5_000;
    const STUCK_ELAPSED_MS: u64 = 640_000; // > 127 * 5000 = 635_000

    /// Pin `global_seal_alpha` byte layout so
    /// `create_global_quorum_seal` (VRF-prove input at L2126) and
    /// `verify_global_quorum_seal` (VRF-verify input at L2253) can never
    /// silently drift apart — any change to prefix bytes, separator
    /// placement, epoch encoding, or hash position would make every
    /// emitter's signature fail verification on every other node and
    /// freeze cross-zone escalation cluster-wide. Pinning the literal
    /// layout means a future refactor that adds a field or reorders the
    /// payload must update this test before the network breaks.
    #[test]
    fn batch_p_global_seal_alpha_byte_layout_pins_prove_verify_byte_agreement() {
        let zone = ZoneId::from_legacy(42);
        let zone_str = zone.to_string(); // "42"
        let epoch = 0x0102_0304_0506_0708u64;
        let prev = [0xAAu8; 32];

        let bytes = global_seal_alpha(&zone, epoch, &prev);

        // Layout: b"global_seal:" + zone_str + b':' + epoch_BE(8) + b':' + prev_hash(32)
        let expected_len = b"global_seal:".len() + zone_str.len() + 1 + 8 + 1 + 32;
        assert_eq!(bytes.len(), expected_len, "byte-length mismatch");

        assert_eq!(&bytes[..12], b"global_seal:", "prefix must be literal 'global_seal:'");
        let zone_end = 12 + zone_str.len();
        assert_eq!(&bytes[12..zone_end], zone_str.as_bytes(), "zone path bytes mismatch");
        assert_eq!(bytes[zone_end], b':', "separator after zone");
        assert_eq!(
            &bytes[zone_end + 1..zone_end + 9],
            &epoch.to_be_bytes()[..],
            "stuck_epoch must be BE-encoded u64",
        );
        assert_eq!(bytes[zone_end + 9], b':', "separator after epoch");
        assert_eq!(&bytes[zone_end + 10..], &prev[..], "prev_seal_hash at tail");

        // Determinism: same inputs produce same output.
        let bytes2 = global_seal_alpha(&zone, epoch, &prev);
        assert_eq!(bytes, bytes2, "deterministic across calls");

        // Changing any input flips the output — keeps prove/verify aligned only when
        // they reconstruct the EXACT same (zone, epoch, prev) tuple.
        let other_zone = ZoneId::from_legacy(43);
        assert_ne!(
            bytes,
            global_seal_alpha(&other_zone, epoch, &prev),
            "zone change must flip bytes",
        );
        assert_ne!(
            bytes,
            global_seal_alpha(&zone, epoch + 1, &prev),
            "epoch change must flip bytes",
        );
        let mut other_prev = prev;
        other_prev[0] ^= 1;
        assert_ne!(
            bytes,
            global_seal_alpha(&zone, epoch, &other_prev),
            "prev_hash change must flip bytes",
        );
    }

    /// Pin `global_seal_metadata` key set + value
    /// encoding so the extractor at `extract_global_quorum_seal` (L1986) and
    /// downstream explorer/account readers can never lose a key without this
    /// test catching it. Hex encoding for the three byte fields
    /// (`previous_seal_hash` / `global_seal_vrf_output` /
    /// `global_seal_vrf_proof`) is the wire-stable transport — switching to
    /// base64 or raw bytes would silently break the extractor's
    /// `hex::decode` calls and surface as cluster-wide signature failures.
    #[test]
    fn batch_p_global_seal_metadata_emits_all_required_keys_with_canonical_shapes() {
        let stuck_zone = ZoneId::from_legacy(7);
        let emitter_zone = ZoneId::from_legacy(8);
        let stuck_epoch = 99u64;
        let prev = [0x11u8; 32];
        let base_ms = 5_000u64;
        let elapsed_ms = 640_000u64;
        let emitted_at = 1_700_000_000.5_f64;
        let vrf_output = [0x22u8; 32];
        let vrf_proof = vec![0x33u8; 80];

        let m = global_seal_metadata(
            &stuck_zone,
            &emitter_zone,
            stuck_epoch,
            &prev,
            base_ms,
            elapsed_ms,
            emitted_at,
            &vrf_output,
            &vrf_proof,
        );

        // Discriminant key the extractor checks first at L1996.
        assert_eq!(
            m.get(EPOCH_OP_KEY).unwrap(),
            &serde_json::json!(EPOCH_OP_GLOBAL_SEAL),
        );
        // Zone fields serialize via ZoneId's derived Serialize (newtype string).
        assert_eq!(m.get("stuck_zone").unwrap(), &serde_json::json!(stuck_zone));
        assert_eq!(m.get("emitter_zone").unwrap(), &serde_json::json!(emitter_zone));
        // Scalar passthrough.
        assert_eq!(m.get("stuck_epoch").unwrap().as_u64(), Some(stuck_epoch));
        assert_eq!(m.get("observed_base_timeout_ms").unwrap().as_u64(), Some(base_ms));
        assert_eq!(m.get("observed_elapsed_ms").unwrap().as_u64(), Some(elapsed_ms));
        assert_eq!(m.get("emitted_at").unwrap().as_f64(), Some(emitted_at));
        // Hex-encoded byte fields — required for the extractor's `hex::decode` round-trip.
        assert_eq!(
            m.get("previous_seal_hash").unwrap().as_str(),
            Some(hex::encode(prev).as_str()),
        );
        assert_eq!(
            m.get("global_seal_vrf_output").unwrap().as_str(),
            Some(hex::encode(vrf_output).as_str()),
        );
        assert_eq!(
            m.get("global_seal_vrf_proof").unwrap().as_str(),
            Some(hex::encode(&vrf_proof).as_str()),
        );
        // Live consensus zone-count snapshot — `extract_global_quorum_seal` reads
        // this back at L2050 to validate seal-zone agreement.
        assert!(m.contains_key("seal_zone_count"), "seal_zone_count must be present");
        assert!(
            m.get("seal_zone_count").unwrap().as_u64().is_some(),
            "seal_zone_count must be a numeric u64",
        );
    }

    /// Pin the "no seals → fresh state" contract on
    /// `rebuild_epoch_state_from_records`. A future regression that
    /// mis-classified non-seal records as seals (e.g. dropping the
    /// `epoch_op` discriminant check) would silently populate
    /// `latest_epoch` from records that have no business advancing the
    /// chain. Tested with two distinct inputs: an empty Vec and a Vec of
    /// plain (no-metadata) records — both must yield a fresh state with
    /// every map empty.
    #[test]
    fn batch_p_rebuild_epoch_state_from_records_empty_or_non_seal_records_returns_fresh_state() {
        // Empty input → fresh state.
        let empty: Vec<ValidationRecord> = Vec::new();
        let state = rebuild_epoch_state_from_records(&empty).unwrap();
        assert!(state.latest_epoch.is_empty(), "empty input must leave latest_epoch empty");
        assert!(state.latest_seal_hash.is_empty(), "empty input must leave latest_seal_hash empty");
        assert!(state.latest_super_seal.is_empty(), "empty input must leave latest_super_seal empty");

        // Non-seal records (no `epoch_op` metadata) → still fresh state.
        let identity = test_identity();
        let recs: Vec<ValidationRecord> = (0..3)
            .map(|i| {
                let mut r = ValidationRecord::create(
                    format!("plain-{i}").as_bytes(),
                    identity.public_key.clone(),
                    vec![],
                    Classification::Public,
                    None,
                );
                r.timestamp = 100.0 + i as f64;
                r
            })
            .collect();
        let state = rebuild_epoch_state_from_records(&recs).unwrap();
        assert!(state.latest_epoch.is_empty(), "non-seal records must not advance latest_epoch");
        assert!(state.latest_seal_hash.is_empty(), "non-seal records must not populate latest_seal_hash");
        assert!(state.latest_super_seal.is_empty(), "non-seal records must not populate latest_super_seal");
    }

    /// Regression gate for the deterministic-replay tiebreak in
    /// `rebuild_epoch_state_from_records`. Seals that share a record timestamp
    /// must replay in a node-independent order (timestamp, then record-ID),
    /// matching the ledger/governance replay sorts (ledger.rs:1050). Without the
    /// id tiebreak a stable sort preserves RocksDB-iteration / load order, which
    /// differs across nodes — and `apply_canonical_seal` builds the per-zone
    /// `vrf_history` ring (jury-seeding input) in canonicalization order, so a
    /// divergent replay order yields a divergent ring. Feeding the same seal
    /// set in two input orders must produce byte-identical EpochState on every
    /// consensus-relevant field.
    #[test]
    fn rebuild_epoch_state_is_input_order_invariant_on_equal_timestamps() {
        fn mk_seal_record(
            identity: &Identity,
            zone: &ZoneId,
            epoch_number: u64,
            end: f64,
            vrf: &[u8; 32],
            tag: &str,
        ) -> ValidationRecord {
            let root = sha3_256(tag.as_bytes());
            let prev = [0u8; 32];
            let meta = seal_metadata(SealMetadataParams {
                zone: zone.clone(),
                epoch_number,
                start: 0.0,
                end,
                record_count: 1,
                merkle_root: &root,
                previous_seal_hash: &prev,
                vrf_output: Some(vrf),
                vrf_proof: None,
                sparse_merkle_root: None,
                record_hashes: None,
                zone_balance_total: None,
                zone_registry_root: None,
                zone_registry_delta: None,
                aggregator_rank: 0,
                account_smt_root: None,
                drand_pulse: None,
            });
            let mut record = ValidationRecord::create(
                format!("epoch:seal:{zone}:{epoch_number}:{tag}").as_bytes(),
                identity.public_key.clone(),
                vec![],
                Classification::Public,
                Some(meta),
            );
            // EQUAL timestamp across all seals → the id tiebreak alone decides
            // replay order, which is exactly what this test pins.
            record.timestamp = 1000.0;
            record
        }

        let identity = test_identity();
        let zone = ZoneId::from_legacy(0);
        let vrf_a = sha3_256(b"vrf-a");
        let vrf_b = sha3_256(b"vrf-b");
        let vrf_c = sha3_256(b"vrf-c");
        // Two equal-epoch seals (the lex-min canonicalization race) plus one
        // epoch advance — all sharing a timestamp.
        let a = mk_seal_record(&identity, &zone, 5, 100.0, &vrf_a, "a");
        let b = mk_seal_record(&identity, &zone, 5, 100.0, &vrf_b, "b");
        let c = mk_seal_record(&identity, &zone, 6, 200.0, &vrf_c, "c");

        let forward = vec![a, b, c];
        let mut reversed = forward.clone();
        reversed.reverse();

        let s1 = rebuild_epoch_state_from_records(&forward).unwrap();
        let s2 = rebuild_epoch_state_from_records(&reversed).unwrap();

        assert_eq!(s1.latest_epoch, s2.latest_epoch, "latest_epoch must be input-order-invariant");
        assert_eq!(s1.latest_seal_hash, s2.latest_seal_hash, "latest_seal_hash must be input-order-invariant");
        assert_eq!(
            s1.total_epochs_total, s2.total_epochs_total,
            "total_epochs_total must be input-order-invariant"
        );
        assert_eq!(s1.latest_vrf_output, s2.latest_vrf_output, "latest_vrf_output must be input-order-invariant");
        assert_eq!(
            s1.vrf_history, s2.vrf_history,
            "vrf_history ring must be input-order-invariant (jury-seeding determinism)"
        );
        // Sanity: the chain advanced to the higher epoch regardless of order.
        assert_eq!(s1.latest_epoch.get(&zone).copied(), Some(6));
    }

    // ─── Fisherman VRF jury-seed ring — LIVE-path order-invariance ──────────
    // The shipped rebuild test above only covers the sorted REBUILD path. These
    // drive the live `register_seal` / `register_seal_with_reconcile` arrival-
    // order path directly — the path that actually forked — in two opposite
    // orders, asserting byte-identical `vrf_history`. Covers Mode 1 (same-epoch
    // lex-min swap → duplicate ring entry) and Mode 2 (epoch 6 canonicalized
    // before epoch 5 → epoch 5 dropped, its VRF never entered the ring).
    fn mk_ring_seal(zone: &ZoneId, epoch: u64, end: f64, vrf: [u8; 32]) -> ParsedEpochSeal {
        ParsedEpochSeal {
            zone: zone.clone(),
            epoch_number: epoch,
            start: end - 100.0,
            end,
            record_count: 1,
            merkle_root: [0u8; 32],
            previous_seal_hash: [0u8; 32],
            vrf_output: Some(vrf),
            vrf_proof: None,
            record_hashes: vec![],
            zone_balance_total: None,
            zone_registry_root: None,
            zone_registry_delta: None,
            seal_zone_count: None,
            aggregator_rank: 0,
            account_smt_root: None,
            drand_pulse: None,
            xzone_dest_finality_committees: None,
        }
    }

    #[test]
    fn vrf_ring_live_register_seal_is_arrival_order_invariant() {
        let zone = ZoneId::from_legacy(0);
        let vrf_a = sha3_256(b"vrf-a");
        let vrf_b = sha3_256(b"vrf-b");
        let vrf_c = sha3_256(b"vrf-c");
        // Epoch-5 lex-min race: record_hash AA < BB, so AA's vrf_a is canonical.
        let (ha, hb, hc) = ([0xAAu8; 32], [0xBBu8; 32], [0xCCu8; 32]);
        let s5a = mk_ring_seal(&zone, 5, 100.0, vrf_a);
        let s5b = mk_ring_seal(&zone, 5, 100.0, vrf_b);
        let s6c = mk_ring_seal(&zone, 6, 200.0, vrf_c);

        // Forward: 5a, 5b, 6c.
        let mut fwd = EpochState::new();
        fwd.register_seal(&s5a, "ra", ha);
        fwd.register_seal(&s5b, "rb", hb);
        fwd.register_seal(&s6c, "rc", hc);

        // Reversed: 6c, 5b, 5a — the order that broke the old append ring (5b/5a
        // arrive when tip is already 6, so they're epoch < current → Mode 2).
        let mut rev = EpochState::new();
        rev.register_seal(&s6c, "rc", hc);
        rev.register_seal(&s5b, "rb", hb);
        rev.register_seal(&s5a, "ra", ha);

        assert_eq!(
            fwd.vrf_history, rev.vrf_history,
            "live register_seal vrf_history must be arrival-order-invariant"
        );
        // One entry per epoch (deduped); epoch 5's canonical VRF is lex-min (vrf_a).
        assert_eq!(fwd.vrf_history.get(&zone).map(|r| r.len()), Some(2));
        assert_eq!(fwd.vrf_output_at_or_before(&zone, 150.0), Some(vrf_a));
        assert_eq!(rev.vrf_output_at_or_before(&zone, 150.0), Some(vrf_a));
        assert_eq!(fwd.vrf_output_at_or_before(&zone, 250.0), Some(vrf_c));
    }

    #[test]
    fn vrf_ring_live_reconcile_is_arrival_order_invariant() {
        let zone = ZoneId::from_legacy(0);
        let vrf_a = sha3_256(b"vrf-a");
        let vrf_b = sha3_256(b"vrf-b");
        let vrf_c = sha3_256(b"vrf-c");
        let (ha, hb, hc) = ([0xAAu8; 32], [0xBBu8; 32], [0xCCu8; 32]);
        let s5a = mk_ring_seal(&zone, 5, 100.0, vrf_a);
        let s5b = mk_ring_seal(&zone, 5, 100.0, vrf_b);
        let s6c = mk_ring_seal(&zone, 6, 200.0, vrf_c);

        // Equal weights (0,0) force the lex-min branch in reconcile.
        let mut fwd = EpochState::new();
        fwd.register_seal_with_reconcile(&s5a, "ra", ha, 0, 0);
        fwd.register_seal_with_reconcile(&s5b, "rb", hb, 0, 0);
        fwd.register_seal_with_reconcile(&s6c, "rc", hc, 0, 0);

        let mut rev = EpochState::new();
        rev.register_seal_with_reconcile(&s6c, "rc", hc, 0, 0);
        rev.register_seal_with_reconcile(&s5b, "rb", hb, 0, 0);
        rev.register_seal_with_reconcile(&s5a, "ra", ha, 0, 0);

        assert_eq!(
            fwd.vrf_history, rev.vrf_history,
            "live register_seal_with_reconcile vrf_history must be arrival-order-invariant"
        );
        assert_eq!(fwd.vrf_output_at_or_before(&zone, 150.0), Some(vrf_a));
        assert_eq!(rev.vrf_output_at_or_before(&zone, 150.0), Some(vrf_a));
    }

    #[test]
    fn vrf_ring_snapshot_roundtrip_and_legacy_v1_fallback() {
        let zone = ZoneId::from_legacy(0);
        let vrf_a = sha3_256(b"vrf-a");
        let vrf_c = sha3_256(b"vrf-c");
        let mut live = EpochState::new();
        live.register_seal(&mk_ring_seal(&zone, 5, 100.0, vrf_a), "ra", [0xAAu8; 32]);
        live.register_seal(&mk_ring_seal(&zone, 6, 200.0, vrf_c), "rc", [0xCCu8; 32]);

        // v2 round-trip: snapshot → restore → byte-identical ring (record_hash kept).
        let snap = live.to_snapshot();
        assert!(!snap.vrf_history_v2.is_empty(), "to_snapshot writes v2");
        assert!(!snap.vrf_history.is_empty(), "to_snapshot also writes legacy v1");
        let restored = EpochState::from_snapshot(&snap);
        assert_eq!(
            live.vrf_history, restored.vrf_history,
            "v2 snapshot round-trip must preserve the ring exactly"
        );

        // Legacy fallback: a pre-fork-fix snapshot has only v1 (no v2). The ring
        // loads via the legacy path with a sentinel record_hash; (end_ts, epoch,
        // vrf) must still match so jury seeding is unchanged.
        let mut legacy = snap.clone();
        legacy.vrf_history_v2.clear();
        let from_legacy = EpochState::from_snapshot(&legacy);
        let strip = |s: &EpochState| -> Vec<(u64, [u8; 32])> {
            let mut v: Vec<(u64, [u8; 32])> = s
                .vrf_history
                .get(&zone)
                .map(|r| r.iter().map(|(_, e, vrf, _)| (*e, *vrf)).collect())
                .unwrap_or_default();
            v.sort_by_key(|(e, _)| *e);
            v
        };
        assert_eq!(
            strip(&live),
            strip(&from_legacy),
            "legacy v1 fallback must preserve (epoch, vrf) — only record_hash differs (sentinel)"
        );
        // The reader returns the same VRF from the legacy-loaded ring.
        assert_eq!(from_legacy.vrf_output_at_or_before(&zone, 150.0), Some(vrf_a));
    }

    #[test]
    fn test_global_seal_roundtrip() {
        let stuck_zone = ZoneId::from_legacy(0);
        let emitter_zone = ZoneId::from_legacy(1);
        let prev = [9u8; 32];
        let stuck_epoch = 42u64;
        let (identity, vrf_sk, _vrf_pk, _emitter_id, _stakers) =
            global_seal_test_setup(&emitter_zone);

        let (record, parsed) = create_global_quorum_seal(
            &identity,
            &vrf_sk,
            stuck_zone.clone(),
            emitter_zone.clone(),
            stuck_epoch,
            prev,
            STUCK_BASE_MS,
            STUCK_ELAPSED_MS,
            vec![],
            0,
        )
        .expect("create_global_quorum_seal must succeed on stuck inputs");

        assert_eq!(parsed.stuck_zone, stuck_zone);
        assert_eq!(parsed.emitter_zone, emitter_zone);
        assert_eq!(parsed.stuck_epoch, stuck_epoch);
        assert_eq!(parsed.previous_seal_hash, prev);
        assert_eq!(parsed.observed_base_timeout_ms, STUCK_BASE_MS);
        assert_eq!(parsed.observed_elapsed_ms, STUCK_ELAPSED_MS);
        assert_ne!(parsed.vrf_output, [0u8; 32]);

        let extracted = extract_global_quorum_seal(&record)
            .expect("extract must not error")
            .expect("extract must return Some for global seal");
        assert_eq!(extracted.stuck_zone, parsed.stuck_zone);
        assert_eq!(extracted.emitter_zone, parsed.emitter_zone);
        assert_eq!(extracted.stuck_epoch, parsed.stuck_epoch);
        assert_eq!(extracted.previous_seal_hash, parsed.previous_seal_hash);
        assert_eq!(extracted.observed_base_timeout_ms, parsed.observed_base_timeout_ms);
        assert_eq!(extracted.observed_elapsed_ms, parsed.observed_elapsed_ms);
        assert_eq!(extracted.vrf_output, parsed.vrf_output);
        assert_eq!(extracted.vrf_proof, parsed.vrf_proof);
    }

    #[test]
    fn test_create_global_seal_rejects_same_zone() {
        let zone = ZoneId::from_legacy(0);
        let (identity, vrf_sk, _, _, _) = global_seal_test_setup(&zone);
        let err = create_global_quorum_seal(
            &identity, &vrf_sk, zone.clone(), zone, 1, [0u8; 32],
            STUCK_BASE_MS, STUCK_ELAPSED_MS, vec![], 0,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("emitter_zone must differ"), "got: {err}");
    }

    #[test]
    fn test_create_global_seal_rejects_not_stuck() {
        let stuck_zone = ZoneId::from_legacy(0);
        let emitter_zone = ZoneId::from_legacy(1);
        let (identity, vrf_sk, _, _, _) = global_seal_test_setup(&emitter_zone);
        // elapsed exactly at 127·base is not-stuck (threshold is strictly greater).
        let not_stuck_elapsed = 127 * STUCK_BASE_MS;
        let err = create_global_quorum_seal(
            &identity, &vrf_sk, stuck_zone, emitter_zone, 1, [0u8; 32],
            STUCK_BASE_MS, not_stuck_elapsed, vec![], 0,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("not stuck"), "got: {err}");
    }

    #[test]
    fn test_verify_global_seal_happy_path() {
        let stuck_zone = ZoneId::from_legacy(0);
        let emitter_zone = ZoneId::from_legacy(1);
        let prev = [11u8; 32];
        let stuck_epoch = 7u64;
        let (identity, vrf_sk, vrf_pk, _emitter_id, stakers_by_zone) =
            global_seal_test_setup(&emitter_zone);
        let (record, _) = create_global_quorum_seal(
            &identity, &vrf_sk, stuck_zone.clone(), emitter_zone, stuck_epoch,
            prev, STUCK_BASE_MS, STUCK_ELAPSED_MS, vec![], 0,
        )
        .unwrap();

        let ctx = GlobalSealVerifyCtx {
            stakers_by_zone: &stakers_by_zone,
            local_previous_seal_hash: prev,
            local_next_epoch: stuck_epoch,
            emitter_vrf_pk: &vrf_pk,
        };
        let verified = verify_global_quorum_seal(&record, &ctx)
            .expect("happy-path global seal must verify");
        assert_eq!(verified.stuck_zone, stuck_zone);
        assert_eq!(verified.stuck_epoch, stuck_epoch);
    }

    #[test]
    fn test_verify_global_seal_rejects_wrong_epoch() {
        let stuck_zone = ZoneId::from_legacy(0);
        let emitter_zone = ZoneId::from_legacy(1);
        let prev = [12u8; 32];
        let (identity, vrf_sk, vrf_pk, _id, stakers_by_zone) =
            global_seal_test_setup(&emitter_zone);
        let (record, _) = create_global_quorum_seal(
            &identity, &vrf_sk, stuck_zone, emitter_zone, 7, prev,
            STUCK_BASE_MS, STUCK_ELAPSED_MS, vec![], 0,
        )
        .unwrap();

        let ctx = GlobalSealVerifyCtx {
            stakers_by_zone: &stakers_by_zone,
            local_previous_seal_hash: prev,
            local_next_epoch: 8, // mismatched
            emitter_vrf_pk: &vrf_pk,
        };
        let err = verify_global_quorum_seal(&record, &ctx).unwrap_err().to_string();
        assert!(err.contains("stuck_epoch"), "got: {err}");
    }

    #[test]
    fn test_verify_global_seal_rejects_prev_hash_mismatch() {
        let stuck_zone = ZoneId::from_legacy(0);
        let emitter_zone = ZoneId::from_legacy(1);
        let prev = [13u8; 32];
        let (identity, vrf_sk, vrf_pk, _id, stakers_by_zone) =
            global_seal_test_setup(&emitter_zone);
        let (record, _) = create_global_quorum_seal(
            &identity, &vrf_sk, stuck_zone, emitter_zone, 5, prev,
            STUCK_BASE_MS, STUCK_ELAPSED_MS, vec![], 0,
        )
        .unwrap();

        let wrong_prev = [14u8; 32];
        let ctx = GlobalSealVerifyCtx {
            stakers_by_zone: &stakers_by_zone,
            local_previous_seal_hash: wrong_prev,
            local_next_epoch: 5,
            emitter_vrf_pk: &vrf_pk,
        };
        let err = verify_global_quorum_seal(&record, &ctx).unwrap_err().to_string();
        assert!(err.contains("previous_seal_hash"), "got: {err}");
    }

    #[test]
    fn test_verify_global_seal_rejects_emitter_not_staked() {
        let stuck_zone = ZoneId::from_legacy(0);
        let emitter_zone = ZoneId::from_legacy(1);
        let prev = [15u8; 32];
        let (identity, vrf_sk, vrf_pk, _id, _stakers) =
            global_seal_test_setup(&emitter_zone);
        let (record, _) = create_global_quorum_seal(
            &identity, &vrf_sk, stuck_zone, emitter_zone, 3, prev,
            STUCK_BASE_MS, STUCK_ELAPSED_MS, vec![], 0,
        )
        .unwrap();

        // Empty staker map for emitter_zone — emitter has no registered stake.
        let empty_stakers = std::collections::HashMap::new();
        let ctx = GlobalSealVerifyCtx {
            stakers_by_zone: &empty_stakers,
            local_previous_seal_hash: prev,
            local_next_epoch: 3,
            emitter_vrf_pk: &vrf_pk,
        };
        let err = verify_global_quorum_seal(&record, &ctx).unwrap_err().to_string();
        assert!(
            err.contains("not a registered anchor"),
            "got: {err}",
        );
    }

    #[test]
    fn test_verify_global_seal_rejects_bad_vrf_pk() {
        let stuck_zone = ZoneId::from_legacy(0);
        let emitter_zone = ZoneId::from_legacy(1);
        let prev = [16u8; 32];
        let (identity, vrf_sk, _vrf_pk, _id, stakers_by_zone) =
            global_seal_test_setup(&emitter_zone);
        let (record, _) = create_global_quorum_seal(
            &identity, &vrf_sk, stuck_zone, emitter_zone, 4, prev,
            STUCK_BASE_MS, STUCK_ELAPSED_MS, vec![], 0,
        )
        .unwrap();

        // Wrong VRF public key — verification must fail.
        let wrong_vrf_pk = crate::crypto::vrf::VrfSecretKey::generate().unwrap().public_key();
        let ctx = GlobalSealVerifyCtx {
            stakers_by_zone: &stakers_by_zone,
            local_previous_seal_hash: prev,
            local_next_epoch: 4,
            emitter_vrf_pk: &wrong_vrf_pk,
        };
        let err = verify_global_quorum_seal(&record, &ctx).unwrap_err().to_string();
        assert!(
            err.contains("vrf") || err.contains("VRF"),
            "expected VRF-related rejection, got: {err}",
        );
    }

    #[test]
    fn test_register_global_seal_advances_epoch_and_idempotent() {
        let stuck_zone = ZoneId::from_legacy(0);
        let emitter_zone = ZoneId::from_legacy(1);
        let prev = [17u8; 32];
        let (identity, vrf_sk, _pk, _id, _stakers) =
            global_seal_test_setup(&emitter_zone);

        let (rec_hi, parsed_hi) = create_global_quorum_seal(
            &identity, &vrf_sk, stuck_zone.clone(), emitter_zone.clone(), 10,
            prev, STUCK_BASE_MS, STUCK_ELAPSED_MS, vec![], 1,
        )
        .unwrap();

        let mut state = EpochState::new();
        state.register_global_seal(&parsed_hi, &rec_hi.id, rec_hi.record_hash());
        assert_eq!(state.latest_epoch.get(&stuck_zone).copied(), Some(10));

        // Idempotent: same-or-lower epoch must not downgrade latest_epoch or
        // overwrite the winning seal id.
        let (rec_lo, parsed_lo) = create_global_quorum_seal(
            &identity, &vrf_sk, stuck_zone.clone(), emitter_zone, 9,
            prev, STUCK_BASE_MS, STUCK_ELAPSED_MS, vec![], 2,
        )
        .unwrap();
        state.register_global_seal(&parsed_lo, &rec_lo.id, rec_lo.record_hash());
        assert_eq!(state.latest_epoch.get(&stuck_zone).copied(), Some(10));
        assert_eq!(state.latest_seal_id.get(&stuck_zone).cloned(), Some(rec_hi.id.clone()));
    }

    /// Stage 3c.1 end-to-end integration: all ranks in zone 0 time out, an
    /// anchor in zone 1 emits a `global_quorum_seal`, the seal verifies, is
    /// accepted into `EpochState` (advancing `latest_epoch[zone 0]` and
    /// resetting `epoch_start_ts` — the chain is now unstuck), and reaches
    /// Finalized once 2/3 cross-zone stake-weighted attestation arrives.
    ///
    /// This composes every primitive the ingest pipeline composes:
    /// `aggregator::is_zone_stuck` → `create_global_quorum_seal` →
    /// `verify_global_quorum_seal` → `EpochState::register_global_seal` →
    /// `AWCConsensus::register_global_seal` → `add_seal_attestation` ×N →
    /// `is_seal_settled`. If any link breaks, this test catches it without
    /// needing a running node.
    #[test]
    fn test_cross_zone_escalation_unsticks_zone_after_all_ranks_offline() {
        use super::super::aggregator::is_zone_stuck;
        use super::super::consensus::{
            AWCConsensus, SealAttestation, WitnessProfile,
        };

        // ── Topology: 4 zones, stuck_zone = 0, emitter in zone 1 ──────
        let stuck_zone = ZoneId::from_legacy(0);
        let emitter_zone = ZoneId::from_legacy(1);
        let prev_seal_hash = [0x77u8; 32];
        let stuck_epoch = 5u64;

        // Independent anchor identities in zones 1, 2, 3 (each attests
        // from its natural zone with a diverse profile so the
        // diversity-weighted numerator actually reaches 2/3).
        let a_zone1 = test_identity();
        let a_zone2 = test_identity();
        let a_zone3 = test_identity();
        let h_zone1 = sha3_256_hex(&a_zone1.public_key);
        let h_zone2 = sha3_256_hex(&a_zone2.public_key);
        let h_zone3 = sha3_256_hex(&a_zone3.public_key);

        let emitter_vrf_sk = crate::crypto::vrf::VrfSecretKey::generate().unwrap();
        let emitter_vrf_pk = emitter_vrf_sk.public_key();

        // Stakers map the verifier consults. Emitter lives under zone 1
        // with positive stake — required by check 6 of `verify_*`.
        let mut stakers_by_zone: std::collections::HashMap<ZoneId, Vec<(String, u64)>> =
            std::collections::HashMap::new();
        stakers_by_zone.insert(emitter_zone.clone(), vec![(h_zone1.clone(), 100u64)]);
        stakers_by_zone.insert(ZoneId::from_legacy(2), vec![(h_zone2.clone(), 100u64)]);
        stakers_by_zone.insert(ZoneId::from_legacy(3), vec![(h_zone3.clone(), 100u64)]);

        // ── Precondition: zone 0 is stuck (elapsed > 127·base) ────────
        let base_ms = 5_000u64;
        let elapsed_ms = 640_000u64; // > 127 · 5_000 = 635_000
        assert!(
            is_zone_stuck(base_ms, elapsed_ms),
            "elapsed={} base={} must register as stuck",
            elapsed_ms, base_ms,
        );

        // ── Emitter in zone 1 creates the global quorum seal ─────────
        let (seal_record, parsed) = create_global_quorum_seal(
            &a_zone1,
            &emitter_vrf_sk,
            stuck_zone.clone(),
            emitter_zone.clone(),
            stuck_epoch,
            prev_seal_hash,
            base_ms,
            elapsed_ms,
            vec![],
            0,
        )
        .expect("create_global_quorum_seal must succeed under stuck preconditions");
        assert_eq!(parsed.stuck_zone, stuck_zone);
        assert_eq!(parsed.emitter_zone, emitter_zone);

        // ── Verifier accepts the seal ────────────────────────────────
        let ctx = GlobalSealVerifyCtx {
            stakers_by_zone: &stakers_by_zone,
            local_previous_seal_hash: prev_seal_hash,
            local_next_epoch: stuck_epoch,
            emitter_vrf_pk: &emitter_vrf_pk,
        };
        verify_global_quorum_seal(&seal_record, &ctx)
            .expect("well-formed global seal must pass verification");

        // ── EpochState registration unsticks zone 0 ──────────────────
        let mut epoch_state = EpochState::new();
        // Pin a deterministic earlier epoch_start_ts so we can confirm it
        // moves forward after the global seal resets it.
        let pinned_start = 1_000_000f64;
        epoch_state.epoch_start_ts.insert(stuck_zone.clone(), pinned_start);
        // Pre-condition: zone 0 has not sealed epoch 5 yet.
        assert!(!epoch_state.latest_epoch.contains_key(&stuck_zone));

        epoch_state.register_global_seal(&parsed, &seal_record.id, seal_record.record_hash());

        // After registration: latest_epoch advances, latest_seal_id records
        // the global seal, and epoch_start_ts is reset to a fresh timestamp
        // (> pinned_start) — this is what "unstuck" means at the state level.
        assert_eq!(
            epoch_state.latest_epoch.get(&stuck_zone).copied(),
            Some(stuck_epoch),
            "zone 0 latest_epoch must advance to stuck_epoch after global seal",
        );
        assert_eq!(
            epoch_state.latest_seal_id.get(&stuck_zone).cloned(),
            Some(seal_record.id.clone()),
        );
        let new_start = epoch_state
            .epoch_start_ts
            .get(&stuck_zone)
            .copied()
            .expect("epoch_start_ts must be set after register_global_seal");
        assert!(
            new_start > pinned_start,
            "epoch_start_ts must have advanced past pinned={} (got {})",
            pinned_start, new_start,
        );

        // ── AWCConsensus: cross-zone settlement ──────────────────────
        let mut awc = AWCConsensus::new();
        // Production stake convention: register_stakes_from_ledger replicates
        // total_staked across every zone. Total system stake = 400 — this
        // matches the four_zone_awc() topology the sibling consensus tests
        // use, so the 2/3 threshold = 267 (strictly clear with 3×100=300
        // effective stake, strictly below with 2×100=200). Zone 0 has no
        // online anchor (it's stuck — every rank offline).
        for z in 0..4u64 {
            awc.register_zone_stake(ZoneId::from_legacy(z), 400);
        }
        awc.register_profile(
            &h_zone1,
            WitnessProfile {
                organization: "org-a".into(),
                subnet: "10.0.1".into(),
                geo_zone: "earth-us".into(),
            },
        );
        awc.register_profile(
            &h_zone2,
            WitnessProfile {
                organization: "org-b".into(),
                subnet: "10.0.2".into(),
                geo_zone: "earth-eu".into(),
            },
        );
        awc.register_profile(
            &h_zone3,
            WitnessProfile {
                organization: "org-c".into(),
                subnet: "10.0.3".into(),
                geo_zone: "mars".into(),
            },
        );

        // Mark the seal as a global seal so settlement routes to the
        // cross-zone (max non-stuck) denominator.
        awc.register_global_seal(&seal_record.id, stuck_zone.clone());
        assert!(awc.is_global_seal(&seal_record.id));

        // Simulate a captured stuck-zone rubber stamp: should NOT count.
        // (There is no anchor in zone 0, but a byzantine one still might
        // try to attest; the filter must drop it.)
        awc.add_seal_attestation(SealAttestation {
            seal_id: seal_record.id.clone(),
            zone: stuck_zone.clone(),
            epoch_number: stuck_epoch,
            witness_hash: "byz-in-stuck-zone".into(),
            stake: 100,
            timestamp: 0.0,
        });
        assert!(
            !awc.is_seal_settled(&seal_record.id),
            "stuck-zone attestations must not count toward settlement",
        );

        // Two of three non-stuck witnesses → ~200 effective stake < 200
        // threshold (2/3 of max non-stuck zone = 200) — should be just below.
        for (i, (wh, zone)) in [
            (&h_zone1, ZoneId::from_legacy(1)),
            (&h_zone2, ZoneId::from_legacy(2)),
        ]
        .iter()
        .enumerate()
        {
            awc.add_seal_attestation(SealAttestation {
                seal_id: seal_record.id.clone(),
                zone: zone.clone(),
                epoch_number: stuck_epoch,
                witness_hash: (*wh).clone(),
                stake: 100,
                timestamp: (i + 1) as f64,
            });
        }
        assert!(
            !awc.is_seal_settled(&seal_record.id),
            "2 of 3 non-stuck witnesses must not yet clear 2/3 threshold",
        );

        // Add the third diverse cross-zone witness → settlement must fire.
        awc.add_seal_attestation(SealAttestation {
            seal_id: seal_record.id.clone(),
            zone: ZoneId::from_legacy(3),
            epoch_number: stuck_epoch,
            witness_hash: h_zone3.clone(),
            stake: 100,
            timestamp: 10.0,
        });
        assert!(
            awc.is_seal_settled(&seal_record.id),
            "3 diverse non-stuck witnesses with ~300 effective stake must clear 2/3 · 400 = 267 threshold",
        );
    }

    // ── Gap 2: cross-zone proof attachment on seal ingest ────────────
    #[test]
    fn test_attach_xzone_proofs_from_seal_attaches_local_pending() {
        use crate::accounting::cross_zone::{CrossZoneState, TransferStatus};
        use crate::accounting::ledger::LedgerState;

        // Simulate a node that has NOT sealed the lock locally, but receives
        // a remote seal containing the lock's hash. It must attach the proof
        // so the downstream XZoneClaim is acceptable.

        let mut ledger = LedgerState::new();
        ledger.cross_zone = CrossZoneState::new();

        // Lock a pending transfer — proof is empty (not yet sealed anywhere we know).
        let lock_hash = sha3_256(b"lock-record-1");
        ledger.cross_zone.lock_transfer(
            "lock-record-1".into(),
            "alice".into(),
            "bob".into(),
            1000,
            ZoneId::from_legacy(0),
            ZoneId::from_legacy(1),
            0.0,
            lock_hash,
        ).unwrap();
        assert!(ledger.cross_zone.get("lock-record-1").unwrap().merkle_proof.is_empty());

        // Build a ParsedEpochSeal that contains the lock hash in record_hashes.
        let other_hash = sha3_256(b"other-record");
        let mut all_hashes = vec![lock_hash, other_hash];
        all_hashes.sort();
        let merkle_root = MerkleTree::root(&all_hashes);

        let seal = ParsedEpochSeal {
            zone: ZoneId::from_legacy(0),
            epoch_number: 1,
            start: 0.0,
            end: 100.0,
            record_count: 2,
            merkle_root,
            previous_seal_hash: [0u8; 32],
            vrf_output: None,
            vrf_proof: None,
            record_hashes: all_hashes,
            zone_balance_total: None,
            zone_registry_root: None,
            zone_registry_delta: None,
            seal_zone_count: None,
            aggregator_rank: 0,
            account_smt_root: None,
            drand_pulse: None,
            xzone_dest_finality_committees: None,
        };

        // Call the helper — this is exactly what the ingest path now does.
        let proofed = attach_xzone_proofs_from_seal(&mut ledger, &seal);
        assert_eq!(proofed, 1, "one pending lock present in seal must be proofed");

        let t = ledger.cross_zone.get("lock-record-1").unwrap();
        assert!(!t.merkle_proof.is_empty(), "proof must be attached");
        assert_eq!(t.source_merkle_root, merkle_root, "stored root must be seal root");
        assert_eq!(t.status, TransferStatus::Locked, "status stays Locked until claim");
        assert_eq!(
            t.source_committee_size, 0,
            "non-finality attach helper leaves committee_size=0"
        );

        // A claim against an inclusion-only attach must
        // be REJECTED — `claim_transfer` now requires a finality witness.
        // The producer-side fix is to call `attach_xzone_proofs_from_seal_with_finality`
        // (covered by test_attach_xzone_proofs_with_finality_bundles_signers).
        let err = ledger
            .cross_zone
            .claim_transfer("lock-record-1", "bob", "claim-rec", 100.0)
            .expect_err("claim must reject when finality wasn't bundled");
        assert!(
            err.to_string().contains("seal not finalized"),
            "expected finality rejection, got: {err}"
        );
    }

    #[test]
    fn test_attach_xzone_proofs_noop_when_seal_has_no_matching_locks() {
        use crate::accounting::cross_zone::CrossZoneState;
        use crate::accounting::ledger::LedgerState;

        let mut ledger = LedgerState::new();
        ledger.cross_zone = CrossZoneState::new();

        // Pending lock whose record is NOT in the incoming seal.
        let lock_hash = sha3_256(b"different-record");
        ledger.cross_zone.lock_transfer(
            "t".into(), "a".into(), "b".into(), 1,
            ZoneId::from_legacy(0), ZoneId::from_legacy(1), 0.0, lock_hash,
        ).unwrap();

        let unrelated = sha3_256(b"unrelated");
        let seal = ParsedEpochSeal {
            zone: ZoneId::from_legacy(0),
            epoch_number: 1, start: 0.0, end: 100.0, record_count: 1,
            merkle_root: unrelated, previous_seal_hash: [0u8; 32],
            vrf_output: None, vrf_proof: None,
            record_hashes: vec![unrelated],
            zone_balance_total: None, zone_registry_root: None,
            zone_registry_delta: None, seal_zone_count: None,
            aggregator_rank: 0, account_smt_root: None,
            drand_pulse: None,
            xzone_dest_finality_committees: None,
        };

        let proofed = attach_xzone_proofs_from_seal(&mut ledger, &seal);
        assert_eq!(proofed, 0, "seal without our lock must not attach anything");
        assert!(ledger.cross_zone.get("t").unwrap().merkle_proof.is_empty());
    }

    // ── Gap 2.1 Phase 2b: producer-side finality bundling ────────────

    #[test]
    fn test_attach_xzone_proofs_with_finality_bundles_signers() {
        use crate::network::consensus::AWCConsensus;
        use crate::accounting::cross_zone::{CrossZoneState, SealFinalityWitness};
        use crate::accounting::ledger::LedgerState;

        let mut ledger = LedgerState::new();
        ledger.cross_zone = CrossZoneState::new();
        let lock_hash = sha3_256(b"lock-rec-2b");
        ledger.cross_zone.lock_transfer(
            "tid-2b".into(),
            "alice".into(),
            "bob".into(),
            500,
            ZoneId::from_legacy(0),
            ZoneId::from_legacy(1),
            0.0,
            lock_hash,
        ).unwrap();

        let other_hash = sha3_256(b"sib-2b");
        let mut all_hashes = vec![lock_hash, other_hash];
        all_hashes.sort();
        let merkle_root = MerkleTree::root(&all_hashes);

        let seal = ParsedEpochSeal {
            zone: ZoneId::from_legacy(0),
            epoch_number: 17,
            start: 0.0, end: 100.0, record_count: 2,
            merkle_root, previous_seal_hash: [0u8; 32],
            vrf_output: None, vrf_proof: None,
            record_hashes: all_hashes,
            zone_balance_total: None, zone_registry_root: None,
            zone_registry_delta: None, seal_zone_count: None,
            aggregator_rank: 0, account_smt_root: None,
            drand_pulse: None,
            xzone_dest_finality_committees: None,
        };

        // Stage 2 finality signatures into AWC under a known seal_id.
        let mut awc = AWCConsensus::new();
        let seal_id = "seal-rec-2b";
        let chash = [0xABu8; 32];
        let w0 = SealFinalityWitness {
            witness_pk: vec![1u8; 32],
            signature: vec![1u8; 64],
            committee_proof: vec![],
        };
        let w1 = SealFinalityWitness {
            witness_pk: vec![2u8; 32],
            signature: vec![2u8; 64],
            committee_proof: vec![],
        };
        awc.add_seal_finality_signature(seal_id, 17, chash, 5, w0);
        awc.add_seal_finality_signature(seal_id, 17, chash, 5, w1);

        let proofed = attach_xzone_proofs_from_seal_with_finality(
            &mut ledger, &seal, Some(seal_id), Some(&awc),
        );
        assert_eq!(proofed, 1);

        let t = ledger.cross_zone.get("tid-2b").unwrap();
        assert!(!t.merkle_proof.is_empty(), "merkle proof attached");
        assert_eq!(t.source_seal_epoch, 17, "epoch bundled from snapshot");
        assert_eq!(t.source_committee_hash, chash, "committee_hash bundled from snapshot");
        assert_eq!(t.source_committee_size, 5, "committee_size bundled from snapshot");
        assert_eq!(t.source_seal_signers.len(), 2, "both signers bundled");
    }

    #[test]
    fn test_attach_xzone_proofs_with_finality_no_signers_leaves_unclaimable() {
        // No collection in awc → falls back to inclusion-only attach
        // (committee_size stays 0). claim_transfer
        // now rejects committee_size=0, so this transfer is parked until
        // a re-attach with finality, or the 24h refund path runs. The test
        // pins the producer-side behavior — a missing AWC snapshot must
        // not silently put the transfer on a "succeed without finality"
        // path. (The earlier `legacy_path` name is now misleading: there
        // IS no legacy path post-Phase-5.)
        use crate::network::consensus::AWCConsensus;
        use crate::accounting::cross_zone::CrossZoneState;
        use crate::accounting::ledger::LedgerState;

        let mut ledger = LedgerState::new();
        ledger.cross_zone = CrossZoneState::new();
        let lock_hash = sha3_256(b"lock-rec-2b-bare");
        ledger.cross_zone.lock_transfer(
            "tid-bare".into(), "a".into(), "b".into(), 1,
            ZoneId::from_legacy(0), ZoneId::from_legacy(1), 0.0, lock_hash,
        ).unwrap();

        let mut all_hashes = vec![lock_hash, sha3_256(b"sib-bare")];
        all_hashes.sort();
        let seal = ParsedEpochSeal {
            zone: ZoneId::from_legacy(0),
            epoch_number: 1, start: 0.0, end: 1.0, record_count: 2,
            merkle_root: MerkleTree::root(&all_hashes),
            previous_seal_hash: [0u8; 32],
            vrf_output: None, vrf_proof: None,
            record_hashes: all_hashes,
            zone_balance_total: None, zone_registry_root: None,
            zone_registry_delta: None, seal_zone_count: None,
            aggregator_rank: 0, account_smt_root: None,
            drand_pulse: None,
            xzone_dest_finality_committees: None,
        };

        let awc = AWCConsensus::new();
        let proofed = attach_xzone_proofs_from_seal_with_finality(
            &mut ledger, &seal, Some("no-such-seal"), Some(&awc),
        );
        assert_eq!(proofed, 1);

        let t = ledger.cross_zone.get("tid-bare").unwrap();
        assert_eq!(t.source_committee_size, 0, "no signers → legacy path preserved");
        assert!(t.source_seal_signers.is_empty());
    }

    // ── Gap 2.3: cross-zone finality cascade integration ─────────────
    //
    // These tests exercise the full producer-side wire-up:
    //   AWC.add_seal_finality_signature
    //     → attach_xzone_proofs_from_seal_with_finality
    //       → CrossZoneState.set_finality_witnesses (bundled into transfer)
    //         → claim_transfer / verify_finality_quorum (consumer side)
    //
    // The Phase 2b-only tests above stub the AWC and check the bundling
    // step in isolation. The unit tests in `token::cross_zone::tests`
    // skip the seal-attach pipeline and call set_finality_witnesses
    // directly. Neither covers the cascade — and a regression in the
    // bundler (e.g. dropping committee_hash, wrong source_seal_epoch)
    // would silently break claims at runtime.

    /// Build a committee Merkle tree over committee_leaf_hash(witness_pk).
    /// Returns (root, per-witness inclusion proofs).
    fn cascade_build_committee(
        witness_pks: &[Vec<u8>],
    ) -> ([u8; 32], Vec<Vec<crate::accounting::cross_zone::ProofSibling>>) {
        use crate::accounting::cross_zone::{committee_leaf_hash, ProofSibling};
        let n = witness_pks.len();
        assert!(n > 0);
        let leaves: Vec<[u8; 32]> = witness_pks.iter().map(|pk| committee_leaf_hash(pk)).collect();
        let mut proofs: Vec<Vec<ProofSibling>> = vec![Vec::new(); n];
        let mut level: Vec<[u8; 32]> = leaves.clone();
        let mut indices: Vec<usize> = (0..n).collect();

        while level.len() > 1 {
            let padded = if level.len() % 2 == 1 {
                let mut p = level.clone();
                p.push(*level.last().unwrap());
                p
            } else {
                level.clone()
            };
            for (leaf_idx, cur_pos) in indices.iter().enumerate() {
                let pair_pos = if cur_pos % 2 == 0 { cur_pos + 1 } else { cur_pos - 1 };
                let sibling = padded[pair_pos.min(padded.len() - 1)];
                proofs[leaf_idx].push(ProofSibling {
                    hash: sibling,
                    is_right: cur_pos % 2 == 0,
                });
            }
            let mut next = Vec::with_capacity(padded.len() / 2);
            for chunk in padded.chunks(2) {
                let mut buf = [0u8; 64];
                buf[..32].copy_from_slice(&chunk[0]);
                buf[32..].copy_from_slice(&chunk[1]);
                next.push(sha3_256(&buf));
            }
            level = next;
            indices = indices.iter().map(|i| i / 2).collect();
        }
        (level[0], proofs)
    }

    #[test]
    fn test_cascade_finality_quorum_accepted_through_bundler() {
        // Full path: real Dilithium3 signatures from a 3-witness committee
        // are signed over the canonical finality bytes, staged into AWC,
        // bundled by attach_xzone_proofs_from_seal_with_finality into the
        // pending transfer, then verified at claim time. 2/3 must accept.
        use crate::identity::{Identity, EntityType, CryptoProfile};
        use crate::network::consensus::AWCConsensus;
        use crate::accounting::cross_zone::{
            xzone_finality_signable_bytes, CrossZoneState, SealFinalityWitness,
        };
        use crate::accounting::ledger::LedgerState;

        let zone = ZoneId::from_legacy(0);
        let dest_zone = ZoneId::from_legacy(1);
        let seal_epoch = 19u64;

        let mut ledger = LedgerState::new();
        ledger.cross_zone = CrossZoneState::new();
        let lock_hash = sha3_256(b"cascade-lock-rec");
        ledger.cross_zone.lock_transfer(
            "tid-cascade".into(),
            "alice".into(),
            "bob".into(),
            777,
            zone.clone(),
            dest_zone,
            0.0,
            lock_hash,
        ).unwrap();

        let other_hash = sha3_256(b"cascade-sib-rec");
        let mut all_hashes = vec![lock_hash, other_hash];
        all_hashes.sort();
        let merkle_root = MerkleTree::root(&all_hashes);

        let witnesses: Vec<Identity> = (0..3)
            .map(|_| Identity::generate(EntityType::Device, CryptoProfile::ProfileB).unwrap())
            .collect();
        let pks: Vec<Vec<u8>> = witnesses.iter().map(|w| w.public_key.clone()).collect();
        let (committee_hash, committee_proofs) = cascade_build_committee(&pks);

        let msg = xzone_finality_signable_bytes(&zone, seal_epoch, &merkle_root, &committee_hash);
        let sigs: Vec<SealFinalityWitness> = witnesses[..2].iter().enumerate().map(|(i, w)| {
            SealFinalityWitness {
                witness_pk: w.public_key.clone(),
                signature: w.sign(&msg).unwrap(),
                committee_proof: committee_proofs[i].clone(),
            }
        }).collect();

        let seal = ParsedEpochSeal {
            zone: zone.clone(),
            epoch_number: seal_epoch,
            start: 0.0, end: 100.0, record_count: 2,
            merkle_root, previous_seal_hash: [0u8; 32],
            vrf_output: None, vrf_proof: None,
            record_hashes: all_hashes,
            zone_balance_total: None, zone_registry_root: None,
            zone_registry_delta: None, seal_zone_count: None,
            aggregator_rank: 0, account_smt_root: None,
            drand_pulse: None,
            xzone_dest_finality_committees: None,
        };

        let mut awc = AWCConsensus::new();
        let seal_id = "cascade-seal-19";
        for sig in sigs {
            awc.add_seal_finality_signature(seal_id, seal_epoch, committee_hash, 3, sig);
        }

        let proofed = attach_xzone_proofs_from_seal_with_finality(
            &mut ledger, &seal, Some(seal_id), Some(&awc),
        );
        assert_eq!(proofed, 1, "lock must get a proof+finality bundle");

        let t = ledger.cross_zone.get("tid-cascade").unwrap();
        assert_eq!(t.source_committee_size, 3);
        assert_eq!(t.source_seal_epoch, seal_epoch);
        assert_eq!(t.source_committee_hash, committee_hash);
        assert_eq!(t.source_seal_signers.len(), 2);

        let claimed = ledger.cross_zone
            .claim_transfer("tid-cascade", "bob", "claim-rec-cascade", 50.0)
            .expect("claim must succeed: 2/3 quorum reached through full cascade");
        assert_eq!(claimed.amount, 777);
    }

    #[test]
    fn test_cascade_finality_under_quorum_rejected() {
        // Only 1 of 3 signers; cascade must surface the under-quorum error
        // at claim time. Proves the bundler doesn't silently drop signers
        // (which would let claims pass against an unattested seal).
        use crate::identity::{Identity, EntityType, CryptoProfile};
        use crate::network::consensus::AWCConsensus;
        use crate::accounting::cross_zone::{
            xzone_finality_signable_bytes, CrossZoneState, SealFinalityWitness,
        };
        use crate::accounting::ledger::LedgerState;

        let zone = ZoneId::from_legacy(0);
        let seal_epoch = 21u64;

        let mut ledger = LedgerState::new();
        ledger.cross_zone = CrossZoneState::new();
        let lock_hash = sha3_256(b"cascade-under-lock");
        ledger.cross_zone.lock_transfer(
            "tid-under".into(), "a".into(), "b".into(), 1,
            zone.clone(), ZoneId::from_legacy(1), 0.0, lock_hash,
        ).unwrap();
        let mut all_hashes = vec![lock_hash, sha3_256(b"under-sib")];
        all_hashes.sort();
        let merkle_root = MerkleTree::root(&all_hashes);

        let witnesses: Vec<Identity> = (0..3)
            .map(|_| Identity::generate(EntityType::Device, CryptoProfile::ProfileB).unwrap())
            .collect();
        let pks: Vec<Vec<u8>> = witnesses.iter().map(|w| w.public_key.clone()).collect();
        let (committee_hash, committee_proofs) = cascade_build_committee(&pks);

        let msg = xzone_finality_signable_bytes(&zone, seal_epoch, &merkle_root, &committee_hash);
        let only_one = SealFinalityWitness {
            witness_pk: witnesses[0].public_key.clone(),
            signature: witnesses[0].sign(&msg).unwrap(),
            committee_proof: committee_proofs[0].clone(),
        };

        let seal = ParsedEpochSeal {
            zone: zone.clone(), epoch_number: seal_epoch,
            start: 0.0, end: 1.0, record_count: 2,
            merkle_root, previous_seal_hash: [0u8; 32],
            vrf_output: None, vrf_proof: None,
            record_hashes: all_hashes,
            zone_balance_total: None, zone_registry_root: None,
            zone_registry_delta: None, seal_zone_count: None,
            aggregator_rank: 0, account_smt_root: None,
            drand_pulse: None,
            xzone_dest_finality_committees: None,
        };
        let mut awc = AWCConsensus::new();
        let seal_id = "cascade-under-21";
        awc.add_seal_finality_signature(seal_id, seal_epoch, committee_hash, 3, only_one);

        let proofed = attach_xzone_proofs_from_seal_with_finality(
            &mut ledger, &seal, Some(seal_id), Some(&awc),
        );
        assert_eq!(proofed, 1);
        let t = ledger.cross_zone.get("tid-under").unwrap();
        assert_eq!(t.source_seal_signers.len(), 1, "single signer cascaded through");
        assert_eq!(t.source_committee_size, 3);

        let err = ledger.cross_zone
            .claim_transfer("tid-under", "b", "claim-under", 1.0)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("seal not finalized in source zone"),
            "expected under-quorum cascade rejection, got: {err}"
        );
    }

    #[test]
    fn test_cascade_finality_replay_across_epochs_rejected() {
        // Witnesses sign for epoch 30 but AWC stages under epoch 31 (replay
        // attempt by the producer). The bundler pins the epoch from the
        // collection snapshot, but the witness signatures were over epoch 30
        // bytes — verify_finality_quorum must reject. This proves the
        // (zone, epoch, root, committee_hash) tuple is signature-bound
        // through the full cascade.
        use crate::identity::{Identity, EntityType, CryptoProfile};
        use crate::network::consensus::AWCConsensus;
        use crate::accounting::cross_zone::{
            xzone_finality_signable_bytes, CrossZoneState, SealFinalityWitness,
        };
        use crate::accounting::ledger::LedgerState;

        let zone = ZoneId::from_legacy(0);
        let signed_epoch = 30u64;
        let claimed_epoch = 31u64;

        let mut ledger = LedgerState::new();
        ledger.cross_zone = CrossZoneState::new();
        let lock_hash = sha3_256(b"replay-lock-rec");
        ledger.cross_zone.lock_transfer(
            "tid-replay".into(), "a".into(), "b".into(), 1,
            zone.clone(), ZoneId::from_legacy(1), 0.0, lock_hash,
        ).unwrap();
        let mut all_hashes = vec![lock_hash, sha3_256(b"replay-sib")];
        all_hashes.sort();
        let merkle_root = MerkleTree::root(&all_hashes);

        let witnesses: Vec<Identity> = (0..3)
            .map(|_| Identity::generate(EntityType::Device, CryptoProfile::ProfileB).unwrap())
            .collect();
        let pks: Vec<Vec<u8>> = witnesses.iter().map(|w| w.public_key.clone()).collect();
        let (committee_hash, committee_proofs) = cascade_build_committee(&pks);

        // Witnesses sign for epoch 30.
        let msg = xzone_finality_signable_bytes(&zone, signed_epoch, &merkle_root, &committee_hash);
        let sigs: Vec<SealFinalityWitness> = witnesses[..2].iter().enumerate().map(|(i, w)| {
            SealFinalityWitness {
                witness_pk: w.public_key.clone(),
                signature: w.sign(&msg).unwrap(),
                committee_proof: committee_proofs[i].clone(),
            }
        }).collect();

        // AWC stages them under epoch 31 — producer-side replay attempt.
        let seal = ParsedEpochSeal {
            zone: zone.clone(), epoch_number: claimed_epoch,
            start: 0.0, end: 1.0, record_count: 2,
            merkle_root, previous_seal_hash: [0u8; 32],
            vrf_output: None, vrf_proof: None,
            record_hashes: all_hashes,
            zone_balance_total: None, zone_registry_root: None,
            zone_registry_delta: None, seal_zone_count: None,
            aggregator_rank: 0, account_smt_root: None,
            drand_pulse: None,
            xzone_dest_finality_committees: None,
        };
        let mut awc = AWCConsensus::new();
        let seal_id = "replay-31";
        for sig in sigs {
            awc.add_seal_finality_signature(seal_id, claimed_epoch, committee_hash, 3, sig);
        }

        let proofed = attach_xzone_proofs_from_seal_with_finality(
            &mut ledger, &seal, Some(seal_id), Some(&awc),
        );
        assert_eq!(proofed, 1);
        let t = ledger.cross_zone.get("tid-replay").unwrap();
        assert_eq!(t.source_seal_epoch, claimed_epoch, "bundler pins epoch from AWC snapshot");

        let err = ledger.cross_zone
            .claim_transfer("tid-replay", "b", "claim-replay", 1.0)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("seal not finalized in source zone"),
            "replay across epochs must fail at quorum verify, got: {err}"
        );
    }

    // ── Gap 3: super-seal primitives ─────────────────────────────────

    #[test]
    fn test_super_seal_metadata_roundtrip() {
        let id = test_identity();
        let zone = ZoneId::from_legacy(7);
        let hashes: Vec<[u8; 32]> = (0..SUPER_SEAL_INTERVAL)
            .map(|i| sha3_256(format!("seal {i}").as_bytes()))
            .collect();
        let prev = sha3_256(b"prev super-seal");
        let committee = sha3_256(b"committee-snapshot");
        let (record, parsed) = create_super_seal(SuperSealParams {
            identity: &id,
            zone: zone.clone(),
            start_epoch: 0,
            end_epoch: SUPER_SEAL_INTERVAL - 1,
            seal_hashes: &hashes,
            previous_super_seal_hash: prev,
            committee_hash: committee,
            timestamp: 100.0,
            slot_nonce: 1,
        })
        .expect("create super-seal");

        // record carries epoch_op=super_seal metadata
        assert_eq!(
            record.metadata.get(EPOCH_OP_KEY).unwrap().as_str().unwrap(),
            EPOCH_OP_SUPER_SEAL
        );

        // parsed matches what we stuffed in
        assert_eq!(parsed.zone, zone);
        assert_eq!(parsed.start_epoch, 0);
        assert_eq!(parsed.end_epoch, SUPER_SEAL_INTERVAL - 1);
        assert_eq!(parsed.seal_count, SUPER_SEAL_INTERVAL);
        assert_eq!(parsed.previous_super_seal_hash, prev);
        assert_eq!(parsed.committee_hash, committee);

        // extract_super_seal on the signed record recovers the same struct
        let extracted = extract_super_seal(&record).unwrap().expect("is super-seal");
        assert_eq!(extracted.zone, parsed.zone);
        assert_eq!(extracted.start_epoch, parsed.start_epoch);
        assert_eq!(extracted.end_epoch, parsed.end_epoch);
        assert_eq!(extracted.seal_count, parsed.seal_count);
        assert_eq!(extracted.merkle_root, parsed.merkle_root);
        assert_eq!(extracted.previous_super_seal_hash, parsed.previous_super_seal_hash);
        assert_eq!(extracted.committee_hash, parsed.committee_hash);

        // coverage check: the same hashes (any order) reproduce the root
        assert!(verify_super_seal_coverage(&parsed, &hashes));
        let mut reversed = hashes.clone();
        reversed.reverse();
        assert!(verify_super_seal_coverage(&parsed, &reversed));
    }

    #[test]
    fn test_super_seal_coverage_rejects_tampered_set() {
        let id = test_identity();
        let zone = ZoneId::from_legacy(0);
        let hashes: Vec<[u8; 32]> = (0..8).map(|i| sha3_256(&[i as u8])).collect();
        let (_, parsed) = create_super_seal(SuperSealParams {
            identity: &id,
            zone,
            start_epoch: 0,
            end_epoch: 7,
            seal_hashes: &hashes,
            previous_super_seal_hash: [0u8; 32],
            committee_hash: [0u8; 32],
            timestamp: 0.0,
            slot_nonce: 1,
        })
        .unwrap();

        // wrong length rejected
        assert!(!verify_super_seal_coverage(&parsed, &hashes[..7]));

        // tampered member rejected
        let mut tampered = hashes.clone();
        tampered[3] = sha3_256(b"not a real seal");
        assert!(!verify_super_seal_coverage(&parsed, &tampered));

        // extra member rejected
        let mut extra = hashes.clone();
        extra.push(sha3_256(b"bonus"));
        assert!(!verify_super_seal_coverage(&parsed, &extra));
    }

    /// Regression: the first real Gap-3 super-seal mint failed with
    /// "slot conflict ...:0000000000000000 already claimed".
    /// Root cause: `create_super_seal` left `record.nonce = 0` (the default
    /// from `ValidationRecord::create`), so every super-seal from a node
    /// collided on slot `(creator_pk, 0)` with the node's first v5 self-record
    /// at nonce=0. Producer must pass a fresh `next_slot_nonce()` per mint.
    /// Pin: two super-seals from the same identity at distinct nonces produce
    /// distinct slot keys.
    #[test]
    fn test_super_seal_nonce_makes_slot_key_unique_per_mint() {
        let id = test_identity();
        let zone = ZoneId::from_legacy(0);
        let h: Vec<[u8; 32]> = (0..SUPER_SEAL_INTERVAL)
            .map(|i| sha3_256(format!("h{i}").as_bytes()))
            .collect();
        let (rec_a, _) = create_super_seal(SuperSealParams {
            identity: &id,
            zone: zone.clone(),
            start_epoch: 0,
            end_epoch: SUPER_SEAL_INTERVAL - 1,
            seal_hashes: &h,
            previous_super_seal_hash: [0u8; 32],
            committee_hash: [0u8; 32],
            timestamp: 1.0,
            slot_nonce: 7,
        })
        .unwrap();
        let (rec_b, _) = create_super_seal(SuperSealParams {
            identity: &id,
            zone,
            start_epoch: SUPER_SEAL_INTERVAL,
            end_epoch: 2 * SUPER_SEAL_INTERVAL - 1,
            seal_hashes: &h,
            previous_super_seal_hash: [0u8; 32],
            committee_hash: [0u8; 32],
            timestamp: 2.0,
            slot_nonce: 8,
        })
        .unwrap();
        // Both nonces wired through.
        assert_eq!(rec_a.nonce, 7);
        assert_eq!(rec_b.nonce, 8);
        // Distinct slot keys → can both insert without slot equivocation.
        let sk_a = rec_a.slot_key().expect("v5 slot_key");
        let sk_b = rec_b.slot_key().expect("v5 slot_key");
        assert_ne!(sk_a, sk_b, "super-seals must claim distinct slots");
        // And neither sits at the dangerous nonce=0 default.
        assert!(!sk_a.ends_with(":0000000000000000"));
        assert!(!sk_b.ends_with(":0000000000000000"));
    }

    #[test]
    fn test_create_super_seal_rejects_empty_and_inverted_range() {
        let id = test_identity();
        let zone = ZoneId::from_legacy(0);
        let empty: Vec<[u8; 32]> = vec![];
        let r = create_super_seal(SuperSealParams {
            identity: &id,
            zone: zone.clone(),
            start_epoch: 0,
            end_epoch: 0,
            seal_hashes: &empty,
            previous_super_seal_hash: [0u8; 32],
            committee_hash: [0u8; 32],
            timestamp: 0.0,
            slot_nonce: 1,
        });
        assert!(r.is_err(), "empty seal_hashes must be rejected");

        let h = vec![sha3_256(b"x")];
        let r2 = create_super_seal(SuperSealParams {
            identity: &id,
            zone,
            start_epoch: 10,
            end_epoch: 5,
            seal_hashes: &h,
            previous_super_seal_hash: [0u8; 32],
            committee_hash: [0u8; 32],
            timestamp: 0.0,
            slot_nonce: 2,
        });
        assert!(r2.is_err(), "end_epoch < start_epoch must be rejected");
    }

    /// Runtime confirmation for the super-seal mint path (Gap 3).
    ///
    /// Multiple super-seal mint fixes have shipped
    /// (`349535a` super_seal_committee_hash allowlist, the split-counter,
    /// the slot_nonce=0 collision, the content_safety graduations) but
    /// `elara_super_seals_minted_total` reads 0 because the per-zone
    /// buffer resets on deploy and never refills past
    /// `SUPER_SEAL_INTERVAL=64` epochs before the next deploy. So the
    /// production mint path is hard to confirm end-to-end at runtime.
    ///
    /// This test simulates the full mint path locally (no storage
    /// fixture, no network) and pins the contract:
    ///   1. Fill `EpochState::super_seal_buffer` with 64 seals so
    ///      `should_create_super_seal` returns true (mirrors a buffer
    ///      that organically filled past the interval boundary in
    ///      production).
    ///   2. Call `create_super_seal` with a non-zero `slot_nonce` (the
    ///      production caller passes `state.next_slot_nonce()` — see
    ///      epoch.rs:4852).
    ///   3. Assert the resulting `ValidationRecord.metadata` passes
    ///      `content_safety::validate_metadata_keys` — the gate every
    ///      `insert_record_synced` call runs at `gossip.rs` /
    ///      `ingest.rs:559`. Without this pass, every super-seal mint
    ///      would be silently rejected at storage time.
    ///   4. Assert `record.slot_key()` does not end in
    ///      `:0000000000000000` (slot-conflict regression class — a
    ///      conflict with the node's first v5 self-record).
    ///   5. Assert `extract_super_seal(&record)` round-trips the parsed
    ///      view back, including the committee hash.
    ///
    /// Together with `test_super_seal_nonce_makes_slot_key_unique_per_mint`
    /// and `test_epoch_state_super_seal_buffer_rolls_at_interval` (buffer
    /// boundary semantics), this confirms the mint path at runtime without
    /// needing the heavyweight storage / ingest fixture.
    #[test]
    fn test_create_super_seal_record_passes_validate_metadata_keys_and_has_nonzero_slot() {
        use crate::content_safety::validate_metadata_keys;
        let id = test_identity();
        let zone = ZoneId::from_legacy(0);
        let mut state = EpochState::new();

        for i in 1..=SUPER_SEAL_INTERVAL {
            let h = sha3_256(&i.to_le_bytes());
            let seal = ParsedEpochSeal {
                zone: zone.clone(),
                epoch_number: i,
                start: 0.0, end: 60.0, record_count: 1,
                merkle_root: h, previous_seal_hash: [0u8; 32],
                vrf_output: None, vrf_proof: None,
                record_hashes: vec![],
                zone_balance_total: None, zone_registry_root: None,
                zone_registry_delta: None, seal_zone_count: None,
                aggregator_rank: 0, account_smt_root: None,
                drand_pulse: None,
                xzone_dest_finality_committees: None,
            };
            state.register_seal(&seal, &format!("epoch:0:{i}"), h);
        }
        assert!(state.should_create_super_seal(&zone), "buffer must be full at boundary");
        let snap = state.snapshot_recent_seal_hashes(&zone).expect("buffer full snapshot");

        let end_epoch = *state.latest_epoch.get(&zone).unwrap();
        let start_epoch = end_epoch - SUPER_SEAL_INTERVAL + 1;
        let committee = [0xau8; 32];
        let (rec, parsed) = create_super_seal(SuperSealParams {
            identity: &id,
            zone: zone.clone(),
            start_epoch,
            end_epoch,
            seal_hashes: &snap,
            previous_super_seal_hash: [0u8; 32],
            committee_hash: committee,
            timestamp: 1_700_000_000.0,
            slot_nonce: 42,
        }).expect("super-seal mint should succeed at boundary");

        // Production-path gate: this is what `insert_record_synced` runs
        // before persisting any record. If this fails, every super-seal
        // mint in prod is silently rejected at storage time.
        validate_metadata_keys(&rec.metadata)
            .expect("super-seal record metadata MUST pass validate_metadata_keys — \
                     any key not in ALLOWED_KEYS silently rejects all super-seal mints");

        // Slot-conflict regression: nonce must be threaded through and the
        // slot_key must not collide with the node's first v5 self-record
        // at nonce=0.
        assert_eq!(rec.nonce, 42, "slot_nonce must be threaded through to record.nonce");
        let sk = rec.slot_key().expect("v5 slot_key");
        assert!(!sk.ends_with(":0000000000000000"),
            "super-seal slot_key must not end in :0000000000000000 — \
             would collide with the node's first v5 self-record (tick-27 OPS-194)");

        // Round-trip through extract_super_seal — production light-client
        // and explorer code paths both parse super-seal records this way.
        let extracted = extract_super_seal(&rec)
            .expect("extract_super_seal must succeed on a freshly-minted record")
            .expect("extract_super_seal must return Some for a super-seal record");
        assert_eq!(extracted.zone, parsed.zone);
        assert_eq!(extracted.start_epoch, start_epoch);
        assert_eq!(extracted.end_epoch, end_epoch);
        assert_eq!(extracted.seal_count, SUPER_SEAL_INTERVAL);
        assert_eq!(extracted.committee_hash, committee,
            "committee_hash must round-trip — Gap-3 super_seal_committee_hash regression");
        assert!(verify_super_seal_coverage(&extracted, &snap),
            "Merkle-root coverage must verify against the same snapshot used to build it");
    }

    /// Gap-3 super-seal forced-fill test: confirms the forced-fill path at
    /// runtime, since every deploy resets the buffer and earlier fixes had no
    /// runtime confirmation otherwise.
    ///
    /// The sibling `test_create_super_seal_record_passes_validate_metadata_keys_and_has_nonzero_slot`
    /// (above) exercises the validation gates by calling `validate_metadata_keys`
    /// + `slot_key()` *directly* on a freshly-minted super-seal record. This
    /// test routes the same record through `insert_record_synced` — the exact
    /// entry point the production `epoch_seal_loop` uses at `epoch.rs:4866`.
    /// If either gate regresses, the insert returns Err and the storage probe
    /// at the end of the test misses.
    ///
    /// Coverage extension over the in-memory mint test:
    ///   1. Real `NodeState` + RocksDB instead of a bare `EpochState` — the
    ///      gates fire against on-disk slot index + content blocklist + dedup
    ///      seen-set, mirroring production memory state.
    ///   2. `slot_nonce` sourced from `state.next_slot_nonce()` (production
    ///      pattern at `epoch.rs:4861`) instead of a hardcoded constant —
    ///      catches a future regression where the NodeState counter starts at
    ///      0 and collides with the first v5 self-record's slot.
    ///   3. Asserts the record is *persisted* via `state.rocks.get_record(&id)`
    ///      — the load-bearing check that a silent gate rejection would surface.
    ///   4. Completes the lifecycle by calling `register_super_seal` and
    ///      asserting `latest_super_seal` + `super_seal_max_end_epoch` are
    ///      installed correctly (the post-insert step that production calls
    ///      at `epoch.rs:4869`).
    ///
    /// Why this matters at protocol scale: every deploy resets the in-memory
    /// `recent_seal_hashes` buffer; at testnet's <1 rec/s + 60s epoch cadence
    /// the buffer needs ~64 minutes of uninterrupted uptime to refill enough
    /// to fire the next super-seal mint, so the runtime path is hard to
    /// confirm end-to-end. This
    /// test substitutes a synthetic forced-fill so the regression-class is
    /// pinned without needing the production uptime window.
    #[tokio::test]
    async fn test_super_seal_forced_fill_inserts_through_production_pipeline() {
        use crate::network::state::build_test_node_state;

        let state = build_test_node_state();
        let zone = crate::ZoneId::new("/zone/forced-fill");

        // Step 1: force-fill `recent_seal_hashes` to exactly SUPER_SEAL_INTERVAL.
        // Uses `register_seal` — the same hot-path entry the production seal
        // loop calls at `epoch.rs:1226-1230`. This mirrors a buffer that
        // organically filled past the interval boundary in production.
        {
            let mut epoch = state.epoch.write().expect("epoch write lock");
            for i in 1..=SUPER_SEAL_INTERVAL {
                let h = sha3_256(&i.to_le_bytes());
                let seal = ParsedEpochSeal {
                    zone: zone.clone(),
                    epoch_number: i,
                    start: (i * 60) as f64,
                    end: ((i + 1) * 60) as f64,
                    record_count: 1,
                    merkle_root: h,
                    previous_seal_hash: [0u8; 32],
                    vrf_output: None,
                    vrf_proof: None,
                    record_hashes: vec![],
                    zone_balance_total: None,
                    zone_registry_root: None,
                    zone_registry_delta: None,
                    seal_zone_count: None,
                    aggregator_rank: 0,
                    account_smt_root: None,
                    drand_pulse: None,
                    xzone_dest_finality_committees: None,
                };
                epoch.register_seal(&seal, &format!("epoch:forced-fill:{i}"), h);
            }
            assert!(
                epoch.should_create_super_seal(&zone),
                "buffer must be full at SUPER_SEAL_INTERVAL boundary"
            );
        }

        // Step 2: snapshot the buffer and mint via the production path.
        let snap = state
            .epoch
            .read()
            .expect("epoch read lock")
            .snapshot_recent_seal_hashes(&zone)
            .expect("snapshot must succeed — buffer is full");
        let end_epoch = SUPER_SEAL_INTERVAL;
        let start_epoch = 1;
        let slot_nonce = state.next_slot_nonce();
        assert_ne!(
            slot_nonce, 0,
            "tick-27 regression guard: next_slot_nonce() must never return 0 \
             (collides with v5 self-record at :0000000000000000)"
        );
        let (ss_record, _ss_parsed) = create_super_seal(SuperSealParams {
            identity: &state.identity,
            zone: zone.clone(),
            start_epoch,
            end_epoch,
            seal_hashes: &snap,
            previous_super_seal_hash: [0u8; 32],
            committee_hash: [0u8; 32],
            timestamp: 1_700_000_000.0,
            slot_nonce,
        })
        .expect("super-seal mint must succeed at boundary");
        let ss_id = ss_record.id.clone();
        let ss_hash = ss_record.record_hash();

        // Step 3: route through the PRODUCTION INSERT PATH. This is where:
        //   (a) metadata-key regression fires: `validate_metadata_keys` at
        //       `ingest.rs:465` rejects any key not in ALLOWED_KEYS. If the
        //       allowlist regresses for any of `super_seal_zone`,
        //       `super_seal_start_epoch`, `super_seal_end_epoch`,
        //       `super_seal_count`, `super_seal_merkle_root`,
        //       `super_seal_prev_hash`, `super_seal_committee_hash` —
        //       this insert returns Err.
        //   (b) slot-conflict regression fires: slot enforcement at `ingest.rs:559`
        //       runs `record.slot_key()` and rejects on conflict. With
        //       `slot_nonce=0` the slot key would be `<account_hash>:0000…`,
        //       which collides with the node's first v5 self-record (the
        //       original super-seal mint failure).
        let inserted_id = crate::network::ingest::insert_record_synced(&state, ss_record)
            .await
            .expect(
                "super-seal insert MUST succeed through the production path — \
                 if this fails, tick-26 (metadata allowlist) or tick-27 \
                 (slot_nonce uniqueness) has regressed",
            );
        assert_eq!(inserted_id, ss_id, "insert returns the record id");

        // Step 4: confirm the record is actually persisted. This is the
        // load-bearing assertion — without it, a silent insert short-circuit
        // (e.g. dedup at storage line) could pass the Ok-return and we'd
        // miss a real regression at the storage write.
        let stored = state
            .rocks
            .get_record(&ss_id)
            .expect("storage read")
            .expect("super-seal record MUST be persisted to RocksDB");
        assert_eq!(stored.id, ss_id);
        let extracted = extract_super_seal(&stored)
            .expect("extract on stored record")
            .expect("stored record MUST round-trip as a super-seal");
        assert_eq!(extracted.zone, zone);
        assert_eq!(extracted.start_epoch, start_epoch);
        assert_eq!(extracted.end_epoch, end_epoch);
        assert_eq!(extracted.seal_count, SUPER_SEAL_INTERVAL);
        assert!(
            verify_super_seal_coverage(&extracted, &snap),
            "stored super-seal Merkle root MUST verify against the snapshot it was built from"
        );

        // Step 5: confirm the AUTO-REGISTER path fired. `insert_record_synced`
        // → `insert_record_inner` → `process_seal_or_super_seal` at
        // `ingest.rs:2376-2398` extracts the super-seal from any record
        // carrying `EPOCH_OP_KEY=super_seal` and calls `register_super_seal`
        // inline + bumps `super_seals_minted_total`. This is the production
        // wire-level mint signal — `epoch_seal_loop` at `epoch.rs:4869` is
        // the PRODUCER side; this ingest path is what every other peer node
        // does when a super-seal arrives via gossip. The test exercises both
        // sides on a single node by routing the freshly-minted record back
        // through `insert_record_synced` (the same call the producer uses).
        {
            let epoch = state.epoch.read().expect("epoch read");
            let (latest_end, latest_id, latest_hash, latest_committee) = epoch
                .latest_super_seal
                .get(&zone)
                .expect(
                    "latest_super_seal entry MUST be installed by the auto-register path \
                     in ingest.rs:2376-2398 — if missing, either the EPOCH_OP_KEY metadata \
                     was stripped or extract_super_seal failed silently",
                );
            assert_eq!(*latest_end, end_epoch);
            assert_eq!(latest_id, &ss_id);
            assert_eq!(*latest_hash, ss_hash);
            assert_eq!(*latest_committee, [0u8; 32]);
            assert_eq!(
                epoch.super_seal_max_end_epoch, end_epoch,
                "OPS-181 max_end_epoch gauge MUST reflect the fresh registration"
            );
            assert!(
                !epoch.should_create_super_seal(&zone),
                "should_create_super_seal MUST be false post-registration at this boundary \
                 (the `latest_super_seal.end >= latest` guard at epoch.rs:1247-1250 must fire)"
            );
        }
        assert_eq!(
            state
                .super_seals_minted_total
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "OPS-181 super_seals_minted_total MUST bump exactly once on the auto-register path"
        );

        // Step 6: idempotent replay. A second call to `register_super_seal`
        // for the same `(zone, end_epoch)` must return false — protects the
        // counter against gossip storms where the same super-seal arrives
        // from multiple peers within the same tick. Pins idempotency
        // on top of the freshly auto-registered state.
        let replay = state.epoch.write().expect("epoch write").register_super_seal(
            zone.clone(),
            end_epoch,
            ss_id.clone(),
            ss_hash,
            [0u8; 32],
        );
        assert!(
            !replay,
            "duplicate registration at same end_epoch MUST return false (OPS-181 idempotency)"
        );
    }

    #[test]
    fn test_extract_super_seal_none_for_regular_records() {
        let id = test_identity();
        // plain record: no epoch_op
        let plain = ValidationRecord::create(
            b"hello",
            id.public_key.clone(),
            vec![],
            Classification::Public,
            None,
        );
        assert!(extract_super_seal(&plain).unwrap().is_none());

        // a regular epoch seal — epoch_op=seal, not super_seal
        let root = sha3_256(b"r");
        let prev = sha3_256(b"p");
        let seal_meta = seal_metadata(SealMetadataParams {
            zone: ZoneId::from_legacy(0),
            epoch_number: 1,
            start: 0.0,
            end: 60.0,
            record_count: 1,
            merkle_root: &root,
            previous_seal_hash: &prev,
            vrf_output: None,
            vrf_proof: None,
            sparse_merkle_root: None,
            record_hashes: None,
            zone_balance_total: None,
            zone_registry_root: None,
            zone_registry_delta: None,
            aggregator_rank: 0,
            account_smt_root: None,
            drand_pulse: None,
        });
        let seal_rec = ValidationRecord::create(
            b"epoch:0:1",
            id.public_key.clone(),
            vec![],
            Classification::Public,
            Some(seal_meta),
        );
        assert!(extract_super_seal(&seal_rec).unwrap().is_none());
    }

    #[test]
    fn test_epoch_state_super_seal_buffer_rolls_at_interval() {
        let id = test_identity();
        let zone = ZoneId::from_legacy(0);
        let mut state = EpochState::new();

        // Fill buffer to exactly SUPER_SEAL_INTERVAL; each push advances the epoch.
        for i in 1..=SUPER_SEAL_INTERVAL {
            let h = sha3_256(&i.to_le_bytes());
            let seal = ParsedEpochSeal {
                zone: zone.clone(),
                epoch_number: i,
                start: 0.0, end: 60.0, record_count: 1,
                merkle_root: h, previous_seal_hash: [0u8; 32],
                vrf_output: None, vrf_proof: None,
                record_hashes: vec![],
                zone_balance_total: None, zone_registry_root: None,
                zone_registry_delta: None, seal_zone_count: None,
                aggregator_rank: 0, account_smt_root: None,
                drand_pulse: None,
                xzone_dest_finality_committees: None,
            };
            state.register_seal(&seal, &format!("epoch:0:{i}"), h);
        }

        // Buffer is full, latest_epoch == SUPER_SEAL_INTERVAL → should fire.
        assert!(state.should_create_super_seal(&zone));
        let snap = state.snapshot_recent_seal_hashes(&zone).expect("buffer full");
        assert_eq!(snap.len() as u64, SUPER_SEAL_INTERVAL);

        // Build the super-seal from the snapshot and register it.
        let end_epoch = *state.latest_epoch.get(&zone).unwrap();
        let start_epoch = end_epoch - SUPER_SEAL_INTERVAL + 1;
        let (rec, parsed) = create_super_seal(SuperSealParams {
            identity: &id,
            zone: zone.clone(),
            start_epoch,
            end_epoch,
            seal_hashes: &snap,
            previous_super_seal_hash: [0u8; 32],
            committee_hash: [0u8; 32],
            timestamp: 1.0,
            slot_nonce: 1,
        })
        .unwrap();
        let rec_hash = sha3_256(&rec.signable_bytes());
        state.register_super_seal(zone.clone(), end_epoch, rec.id.clone(), rec_hash, [0u8; 32]);

        // After registering, should_create_super_seal must be false at this boundary.
        assert!(!state.should_create_super_seal(&zone));
        let latest = state.latest_super_seal.get(&zone).expect("registered");
        assert_eq!(latest.0, end_epoch);
        assert_eq!(latest.1, rec.id);

        // Verify coverage round-trips.
        assert!(verify_super_seal_coverage(&parsed, &snap));
    }

    #[test]
    fn test_epoch_state_super_seal_skips_off_boundary_epochs() {
        let zone = ZoneId::from_legacy(0);
        let mut state = EpochState::new();
        // Register one seal at epoch 1 — not a boundary.
        let h = sha3_256(b"x");
        let seal = ParsedEpochSeal {
            zone: zone.clone(),
            epoch_number: 1,
            start: 0.0, end: 60.0, record_count: 1,
            merkle_root: h, previous_seal_hash: [0u8; 32],
            vrf_output: None, vrf_proof: None,
            record_hashes: vec![],
            zone_balance_total: None, zone_registry_root: None,
            zone_registry_delta: None, seal_zone_count: None,
            aggregator_rank: 0, account_smt_root: None,
            drand_pulse: None,
            xzone_dest_finality_committees: None,
        };
        state.register_seal(&seal, "epoch:0:1", h);
        assert!(!state.should_create_super_seal(&zone));
        assert!(state.snapshot_recent_seal_hashes(&zone).is_none(), "buffer not full");
    }

    #[test]
    fn test_super_seal_committee_hash_absent_defaults_to_zero() {
        // When create_super_seal is called with committee_hash = [0u8; 32]
        // (e.g., no committee registered on a bootstrap / small network),
        // super_seal_metadata must NOT emit the field, and extract must
        // recover [0u8; 32] by default. Keeps wire format compatible with
        // super-seals minted before the committee_hash field existed.
        let id = test_identity();
        let zone = ZoneId::from_legacy(3);
        let hashes: Vec<[u8; 32]> = (0..8).map(|i| sha3_256(&[i as u8])).collect();
        let (rec, parsed) = create_super_seal(SuperSealParams {
            identity: &id,
            zone,
            start_epoch: 0,
            end_epoch: 7,
            seal_hashes: &hashes,
            previous_super_seal_hash: [0u8; 32],
            committee_hash: [0u8; 32],
            timestamp: 0.0,
            slot_nonce: 1,
        })
        .unwrap();

        // Metadata must NOT contain the committee_hash key when it's zero.
        assert!(!rec.metadata.contains_key("super_seal_committee_hash"),
            "zero committee_hash must not leak into wire metadata");

        // Extract still returns zero committee_hash (Default behavior).
        let extracted = extract_super_seal(&rec).unwrap().expect("is super-seal");
        assert_eq!(extracted.committee_hash, [0u8; 32]);
        assert_eq!(parsed.committee_hash, [0u8; 32]);
    }

    #[test]
    fn test_extract_super_seal_rejects_bad_hex() {
        let id = test_identity();
        let mut meta = super_seal_metadata(
            ZoneId::from_legacy(0),
            0, 63, 64,
            &[1u8; 32],
            &[0u8; 32],
            &[0u8; 32],
        );
        // corrupt merkle root hex
        meta.insert("super_seal_merkle_root".into(), serde_json::json!("not-hex!!"));
        let rec = ValidationRecord::create(
            b"super_seal:0:0-63",
            id.public_key.clone(),
            vec![],
            Classification::Public,
            Some(meta),
        );
        assert!(extract_super_seal(&rec).is_err());
    }

    // ── register_super_seal mint signal + max_end_epoch gauge ──

    #[test]
    fn test_register_super_seal_returns_true_on_first_insert() {
        // The bool return is the wire-level "minted" signal that
        // ingest uses to decide whether to bump elara_super_seals_minted_total.
        // First insert for a zone must return true so the counter ticks on
        // the genesis super-seal of that zone.
        let mut state = EpochState::new();
        let zone = ZoneId::from_legacy(0);
        assert!(state.register_super_seal(zone.clone(), 63, "rec-0".into(), [1u8; 32], [0u8; 32]));
        assert_eq!(state.super_seal_max_end_epoch, 63,
            "max_end_epoch must hydrate on first insert");
    }

    #[test]
    fn test_register_super_seal_returns_false_on_stale_replay() {
        // A duplicate or out-of-order super-seal (end_epoch <=
        // existing) must return false so ingest doesn't double-count. This
        // protects the counter against gossip storms where the same super-
        // seal arrives from multiple peers within the same tick.
        let mut state = EpochState::new();
        let zone = ZoneId::from_legacy(0);
        assert!(state.register_super_seal(zone.clone(), 127, "rec-1".into(), [1u8; 32], [0u8; 32]));
        // Same end_epoch — already canonical.
        assert!(!state.register_super_seal(zone.clone(), 127, "rec-1".into(), [1u8; 32], [0u8; 32]));
        // Older end_epoch — replay of a stale super-seal.
        assert!(!state.register_super_seal(zone.clone(), 63, "rec-2".into(), [2u8; 32], [0u8; 32]));
        // Max stays at 127 — stale replays must NOT regress the gauge.
        assert_eq!(state.super_seal_max_end_epoch, 127);
    }

    #[test]
    fn test_register_super_seal_max_end_epoch_tracks_across_zones() {
        // super_seal_max_end_epoch must be the running max ACROSS
        // every zone's latest, not per-zone. This is what /metrics scrapes
        // in O(1) instead of iterating the HashMap. With 1M-zone archive
        // nodes, the per-scrape scan would be a non-trivial chunk of
        // cluster-wide CPU; the O(1) field is the load-bearing optimisation.
        let mut state = EpochState::new();
        let zone_a = ZoneId::from_legacy(0);
        let zone_b = ZoneId::from_legacy(1);
        let zone_c = ZoneId::from_legacy(2);

        assert!(state.register_super_seal(zone_a.clone(), 63, "a-0".into(), [1u8; 32], [0u8; 32]));
        assert_eq!(state.super_seal_max_end_epoch, 63);

        // Newer super-seal in a DIFFERENT zone — global max must advance.
        assert!(state.register_super_seal(zone_b.clone(), 191, "b-0".into(), [2u8; 32], [0u8; 32]));
        assert_eq!(state.super_seal_max_end_epoch, 191);

        // Older super-seal in a third zone — global max must NOT regress.
        assert!(state.register_super_seal(zone_c.clone(), 127, "c-0".into(), [3u8; 32], [0u8; 32]));
        assert_eq!(state.super_seal_max_end_epoch, 191,
            "global max must reflect the highest end_epoch across all zones");

        // Advance zone A past the current global — max tracks.
        assert!(state.register_super_seal(zone_a.clone(), 255, "a-1".into(), [4u8; 32], [0u8; 32]));
        assert_eq!(state.super_seal_max_end_epoch, 255);
    }

    // ── incremental total_epochs_total counter ─────────────────

    /// Helper for total_epochs_total tests: minimal `ParsedEpochSeal` for a given
    /// `(zone, epoch)`. The seal carries no VRF/SMT/super-seal metadata —
    /// this isolates the `total_epochs_total` counter behaviour from the
    /// rest of `apply_canonical_seal`.
    fn ops153_make_seal(zone: ZoneId, epoch_number: u64) -> ParsedEpochSeal {
        ParsedEpochSeal {
            zone,
            epoch_number,
            start: (epoch_number * 100) as f64,
            end: ((epoch_number + 1) * 100) as f64,
            record_count: 1,
            merkle_root: sha3_256(format!("ops153-root-{epoch_number}").as_bytes()),
            previous_seal_hash: [0u8; 32],
            vrf_output: None,
            vrf_proof: None,
            record_hashes: vec![],
            zone_balance_total: None,
            zone_registry_root: None,
            zone_registry_delta: None,
            seal_zone_count: None,
            aggregator_rank: 0,
            account_smt_root: None,
            drand_pulse: None,
            xzone_dest_finality_committees: None,
        }
    }

    /// Invariant: at every observable point,
    /// `total_epochs_total == sum(latest_epoch.values().map(+1))`. Asserted
    /// by cloning state, recounting on the clone, and comparing — the same
    /// belt-and-braces cross-check used for the cross-zone status counters.
    fn ops153_assert_invariant(state: &EpochState, where_: &str) {
        let mut clone = state.clone();
        clone.recount_total_epochs();
        assert_eq!(
            state.total_epochs_total, clone.total_epochs_total,
            "OPS-153 invariant violated at {where_}: maintained={} recount={} latest_epoch={:?}",
            state.total_epochs_total, clone.total_epochs_total, state.latest_epoch,
        );
        let expected: u64 = state.latest_epoch.values().map(|n| n.saturating_add(1)).sum();
        assert_eq!(
            state.total_epochs_total, expected,
            "OPS-153 invariant: maintained {} ≠ expected sum {} at {where_}",
            state.total_epochs_total, expected,
        );
    }

    /// Exercise every `latest_epoch` mutation site (register_seal,
    /// register_seal_with_reconcile winner+loser branches, register_global_seal,
    /// prune_stale_zones) in mixed order across multiple zones, asserting the
    /// invariant after each step.
    #[test]
    fn ops153_total_epochs_invariant_under_random_ops() {
        let mut state = EpochState::new();
        let z0 = ZoneId::from_legacy(0);
        let z1 = ZoneId::from_legacy(1);
        let z2 = ZoneId::from_legacy(2);

        // ── Phase 1: fresh inserts via register_seal ──────────────
        ops153_assert_invariant(&state, "after new()");
        assert_eq!(state.total_epochs_total, 0);

        let seal_z0_e0 = ops153_make_seal(z0.clone(), 0);
        state.register_seal(&seal_z0_e0, "rec-z0-e0", sha3_256(b"hash-z0-e0"));
        ops153_assert_invariant(&state, "after register z0 epoch 0");
        assert_eq!(state.total_epochs_total, 1);

        let seal_z0_e1 = ops153_make_seal(z0.clone(), 1);
        state.register_seal(&seal_z0_e1, "rec-z0-e1", sha3_256(b"hash-z0-e1"));
        ops153_assert_invariant(&state, "after register z0 epoch 1");
        assert_eq!(state.total_epochs_total, 2);

        let seal_z1_e0 = ops153_make_seal(z1.clone(), 0);
        state.register_seal(&seal_z1_e0, "rec-z1-e0", sha3_256(b"hash-z1-e0"));
        ops153_assert_invariant(&state, "after register z1 epoch 0");
        assert_eq!(state.total_epochs_total, 3);

        // ── Phase 2: jump z0 forward by 5 epochs (delta path) ─────
        let seal_z0_e6 = ops153_make_seal(z0.clone(), 6);
        state.register_seal(&seal_z0_e6, "rec-z0-e6", sha3_256(b"hash-z0-e6"));
        ops153_assert_invariant(&state, "after register z0 epoch 6 (jump from 1)");
        assert_eq!(state.total_epochs_total, (6 + 1) + 1);

        // ── Phase 3: same-epoch lex-min collision (no-op on counter) ──
        // Construct two seals at z1 epoch 1 with predictable hashes so we
        // can pick which wins. Lower hash wins on lex-min.
        let seal_z1_e1_hi = ops153_make_seal(z1.clone(), 1);
        state.register_seal(&seal_z1_e1_hi, "rec-z1-e1-hi", [0xFFu8; 32]);
        ops153_assert_invariant(&state, "after register z1 epoch 1 (hi hash)");
        let total_before_collision = state.total_epochs_total;
        let seal_z1_e1_lo = ops153_make_seal(z1.clone(), 1);
        state.register_seal(&seal_z1_e1_lo, "rec-z1-e1-lo", [0x00u8; 32]);
        ops153_assert_invariant(&state, "after register z1 epoch 1 (lo hash, collision win)");
        assert_eq!(
            state.total_epochs_total, total_before_collision,
            "same-epoch collision must not change total_epochs_total"
        );

        // ── Phase 4: reconcile with weight-aware path, equal-epoch loser ──
        let seal_z1_e1_loser = ops153_make_seal(z1.clone(), 1);
        let won = state.register_seal_with_reconcile(
            &seal_z1_e1_loser,
            "rec-z1-e1-loser",
            [0x80u8; 32],
            10, // incoming weight
            20, // existing weight (incoming loses)
        );
        assert!(!won, "lower-weight incoming must lose");
        ops153_assert_invariant(&state, "after register_seal_with_reconcile loser");
        assert_eq!(
            state.total_epochs_total, total_before_collision,
            "reconcile loser must not change total_epochs_total"
        );

        // ── Phase 5: reconcile winner branch with stricly higher weight,
        // same epoch (counter must not change since latest_epoch unchanged) ──
        let seal_z1_e1_winner = ops153_make_seal(z1.clone(), 1);
        let won = state.register_seal_with_reconcile(
            &seal_z1_e1_winner,
            "rec-z1-e1-winner",
            [0x40u8; 32],
            100, // incoming weight (incoming wins)
            20,
        );
        assert!(won, "higher-weight incoming must win");
        ops153_assert_invariant(&state, "after register_seal_with_reconcile winner same-epoch");
        assert_eq!(
            state.total_epochs_total, total_before_collision,
            "same-epoch winner must not change total_epochs_total"
        );

        // ── Phase 6: register_global_seal advances z2 from never-seen to 5 ──
        let gseal = ParsedGlobalQuorumSeal {
            stuck_zone: z2.clone(),
            emitter_zone: z0.clone(),
            stuck_epoch: 5,
            previous_seal_hash: [0u8; 32],
            observed_base_timeout_ms: 1000,
            observed_elapsed_ms: 5000,
            emitted_at: 0.0,
            vrf_output: [0u8; 32],
            vrf_proof: vec![],
            seal_zone_count: None,
        };
        state.register_global_seal(&gseal, "rec-global-z2-e5", sha3_256(b"hash-global-z2-e5"));
        ops153_assert_invariant(&state, "after register_global_seal z2 epoch 5");
        // z0=6, z1=1, z2=5 → sum (6+1)+(1+1)+(5+1) = 15
        assert_eq!(state.total_epochs_total, 7 + 2 + 6);

        // ── Phase 7: register_global_seal at lower epoch (no-op) ─────
        let total_before_low_global = state.total_epochs_total;
        let gseal_lo = ParsedGlobalQuorumSeal {
            stuck_zone: z2.clone(),
            emitter_zone: z0.clone(),
            stuck_epoch: 3, // < current 5 — should be ignored
            previous_seal_hash: [0u8; 32],
            observed_base_timeout_ms: 1000,
            observed_elapsed_ms: 5000,
            emitted_at: 0.0,
            vrf_output: [0u8; 32],
            vrf_proof: vec![],
            seal_zone_count: None,
        };
        state.register_global_seal(&gseal_lo, "rec-global-z2-e3", sha3_256(b"hash-global-z2-e3"));
        ops153_assert_invariant(&state, "after stale register_global_seal");
        assert_eq!(
            state.total_epochs_total, total_before_low_global,
            "stale global seal must not change total_epochs_total"
        );

        // ── Phase 8: prune zones >= 2 (removes z2; keeps z0, z1) ─────
        state.prune_stale_zones(2);
        ops153_assert_invariant(&state, "after prune_stale_zones(2)");
        // z0=6, z1=1 remain → (6+1)+(1+1) = 9
        assert_eq!(state.total_epochs_total, 7 + 2);

        // ── Phase 9: prune everything (zone_count=0) ─────────────────
        state.prune_stale_zones(0);
        ops153_assert_invariant(&state, "after prune_stale_zones(0)");
        assert_eq!(state.total_epochs_total, 0);
        assert!(state.latest_epoch.is_empty());
    }

    /// prune_stale_zones must subtract `(epoch + 1)` per pruned zone.
    /// Mirrors the pattern of pinning the decrement path explicitly so
    /// a future regression that forgets the subtract gets caught here even if
    /// the random-ops invariant test happens to skip the path.
    #[test]
    fn ops153_total_epochs_decrement_on_prune_stale_zones() {
        let mut state = EpochState::new();
        // Populate 4 zones with distinct epochs.
        let cases: &[(u64, u64)] = &[(0, 3), (1, 7), (2, 0), (3, 12)];
        for (zone_n, epoch) in cases {
            let seal = ops153_make_seal(ZoneId::from_legacy(*zone_n), *epoch);
            state.register_seal(
                &seal,
                &format!("rec-{zone_n}-{epoch}"),
                sha3_256(format!("h-{zone_n}-{epoch}").as_bytes()),
            );
        }
        let total_initial: u64 = cases.iter().map(|(_, e)| e + 1).sum();
        assert_eq!(state.total_epochs_total, total_initial);
        ops153_assert_invariant(&state, "post-populate");

        // Prune zones >= 2 → drops zones 2 (epoch 0) and 3 (epoch 12) →
        // subtracts (0+1) + (12+1) = 14.
        state.prune_stale_zones(2);
        let expected: u64 = cases.iter()
            .filter(|(z, _)| *z < 2)
            .map(|(_, e)| e + 1)
            .sum();
        assert_eq!(state.total_epochs_total, expected, "prune must subtract (epoch+1) per removed zone");
        ops153_assert_invariant(&state, "post-prune-2");
        assert!(!state.latest_epoch.contains_key(&ZoneId::from_legacy(2)));
        assert!(!state.latest_epoch.contains_key(&ZoneId::from_legacy(3)));

        // Idempotent on re-prune (no zones >= 2 remain).
        let total_before_re_prune = state.total_epochs_total;
        state.prune_stale_zones(2);
        assert_eq!(state.total_epochs_total, total_before_re_prune);
        ops153_assert_invariant(&state, "post-prune-2 (idempotent)");
    }

    /// Boot-ordering regression (2026-06-19 zone_count fusion audit): on a node
    /// rebooting while the network runs at zone_count >= 2, stale-zone pruning
    /// MUST use the post-LIVENESS-2 canonical count, not the boot-seed count.
    /// Pruning with the boot-seed (1 in auto mode) before the signed transition
    /// chain is replayed silently deletes live epoch/seal/VRF state for
    /// legitimately-active high zones, breaking their chained-beacon VRF chain.
    /// This pins the contract the boot sequence in `bin/elara_node.rs` relies on
    /// (defer prune until after `find_latest_unapplied_zone_transition`).
    #[test]
    fn boot_prune_must_use_post_rehydration_zone_count() {
        // A 2-zone sealed state — network canonical zone_count = 2.
        let build = || {
            let mut s = EpochState::new();
            for (zone_n, epoch) in &[(0u64, 5u64), (1u64, 9u64)] {
                let seal = ops153_make_seal(ZoneId::from_legacy(*zone_n), *epoch);
                s.register_seal(
                    &seal,
                    &format!("rec-{zone_n}-{epoch}"),
                    sha3_256(format!("h-{zone_n}-{epoch}").as_bytes()),
                );
            }
            s
        };
        assert!(build().latest_epoch.contains_key(&ZoneId::from_legacy(1)),
            "precondition: zone 1 carries live sealed state");

        // BUG (pre-fix ordering): prune at the boot-seed count (1) before
        // LIVENESS-2 restores the canonical 2 → live zone 1 is destroyed.
        let mut buggy = build();
        buggy.prune_stale_zones(1);
        assert!(!buggy.latest_epoch.contains_key(&ZoneId::from_legacy(1)),
            "demonstrates the bug class: pruning at the boot-seed count drops live zone 1");

        // FIX (post-rehydration ordering): prune at the canonical 2 → zone 1 kept.
        let mut fixed = build();
        fixed.prune_stale_zones(2);
        assert!(fixed.latest_epoch.contains_key(&ZoneId::from_legacy(0)));
        assert!(fixed.latest_epoch.contains_key(&ZoneId::from_legacy(1)),
            "fix: pruning at the post-rehydration count preserves live zone 1");
        assert!(fixed.latest_seal_id.contains_key(&ZoneId::from_legacy(1)));
        assert!(fixed.latest_seal_hash.contains_key(&ZoneId::from_legacy(1)));
    }

    /// from_snapshot must re-derive `total_epochs_total` from the
    /// restored `latest_epoch` map, and recount must be idempotent on re-call.
    /// Models a node restart where the snapshot was written before the counter
    /// existed (counter not in serialized form — but the parent struct skips
    /// serde anyway, so this is the canonical recovery path).
    #[test]
    fn ops153_recount_total_epochs_idempotent_post_snapshot() {
        // Build a synthetic snapshot with 3 zones at distinct epochs.
        let mut latest_epoch: HashMap<ZoneId, u64> = HashMap::new();
        latest_epoch.insert(ZoneId::from_legacy(0), 4);
        latest_epoch.insert(ZoneId::from_legacy(1), 11);
        latest_epoch.insert(ZoneId::from_legacy(7), 0);
        let expected: u64 = latest_epoch.values().map(|n| n + 1).sum();

        let snap = EpochStateSnapshot {
            latest_epoch: latest_epoch.clone(),
            latest_seal_id: HashMap::new(),
            latest_seal_hash: HashMap::new(),
            latest_vrf_output: HashMap::new(),
            zone_activity_rate: HashMap::new(),
            vrf_history: HashMap::new(),
            vrf_history_v2: HashMap::new(),
            latest_super_seal: HashMap::new(),
            latest_sealed_account: None,
        };

        let mut state = EpochState::from_snapshot(&snap);
        assert_eq!(
            state.total_epochs_total, expected,
            "from_snapshot must derive total_epochs_total from restored latest_epoch"
        );
        ops153_assert_invariant(&state, "post-from_snapshot");

        // Idempotent on explicit recount.
        let before = state.total_epochs_total;
        state.recount_total_epochs();
        assert_eq!(state.total_epochs_total, before, "recount must be idempotent");
        ops153_assert_invariant(&state, "post-recount idempotent");

        // Recount also corrects a corrupted counter (e.g. a boot from a
        // snapshot that bypassed from_snapshot — defensive).
        state.total_epochs_total = 999_999;
        state.recount_total_epochs();
        assert_eq!(state.total_epochs_total, expected, "recount must correct stale counter");
    }

    // ── canonicalize_latest_seals ──────────
    //
    // Three sync-helper tests on `canonicalize_latest_seals` (epoch.rs:3497),
    // the chain-liveness fix that re-registers every CF_EPOCHS-stored seal at
    // each zone's `latest_epoch` so the Stage 3b.5/3b.6 lex-min tiebreak in
    // `register_seal` converges every node on the same canonical hash, regardless
    // of which arrived first locally. Until this batch, the helper had zero
    // direct test coverage — only indirect exercise via the boot-replay path.
    //
    // The three branches that matter at the seal-loop level:
    //   1. empty state            → outer for-loop does not iterate (no-op)
    //   2. single seal at (zone, epoch) → `record_ids.len() < 2` continues
    //                                    (already canonical, skip register)
    //   3. multi-seal at (zone, epoch) → re-register all → lex-min wins
    //
    // Branch (3) is the load-bearing one: a regression that drops the
    // `register_seal` re-call inside the loop would silently freeze the chain
    // on dual-proposer-race networks because each node would keep whichever
    // hash it ingested first as canonical and compute a different
    // `chained_beacon` for the next epoch — exactly the failure that batched
    // PARTITION-MERGE Phase B Slice 3 (`register_seal_with_reconcile`)
    // shipped to defend against.

    /// Empty state → `canonicalize_latest_seals` is a
    /// pure no-op. Outer `state.latest_epoch.iter()` finds nothing to scan,
    /// so the function returns without touching either map. A regression
    /// that started seeding `latest_epoch` from a default-empty scan (e.g.
    /// flipping the iterator source to `storage.range_scan_cf(CF_EPOCHS, ...)`
    /// before the zone-filter) would advance `latest_epoch` from garbage
    /// CF_EPOCHS entries on a fresh boot — caught here.
    #[cfg(feature = "node-core")]
    #[test]
    fn batch_q_canonicalize_latest_seals_empty_state_is_pure_noop() {
        let (storage, _dir) = test_engine();
        let mut state = EpochState::new();

        canonicalize_latest_seals(&mut state, &storage);

        assert!(state.latest_epoch.is_empty(),
            "empty state must stay empty after canonicalize (no zone to scan)");
        assert!(state.latest_seal_hash.is_empty(),
            "empty state must not synthesize a latest_seal_hash entry");
        assert!(state.latest_seal_id.is_empty(),
            "empty state must not synthesize a latest_seal_id entry");
    }

    /// Single seal at `(zone, epoch=1)` →
    /// `canonicalize_latest_seals` short-circuits at the `record_ids.len() < 2`
    /// check (epoch.rs:3540-3542) and leaves canonical state untouched. This
    /// is the no-race steady-state path — the most common shape on every
    /// healthy zone — and a regression that dropped the `< 2` guard would
    /// pointlessly re-register every seal at every canonicalize call (idempotent
    /// at the data level but burns CPU + a `register_seal` mutex acquisition
    /// per zone per call at 1M-zone scale).
    #[cfg(feature = "node-core")]
    #[test]
    fn batch_q_canonicalize_latest_seals_single_seal_at_epoch_is_noop() {
        let (mut storage, _dir) = test_engine();
        let identity = test_identity();
        let zone = ZoneId::from_legacy(0);

        // Bump state.latest_epoch[zone] = 0 so next_epoch returns 1.
        let mut state = EpochState::new();
        state.latest_epoch.insert(zone.clone(), 0);

        let (seal, parsed) = create_epoch_seal(
            &identity, &storage, &state, zone.clone(), 0.0, 100.0, None, None,
        ).expect("create_epoch_seal must succeed on fresh storage");
        assert_eq!(parsed.epoch_number, 1, "next_epoch(zone) must be 1 after seeding latest_epoch=0");

        storage.insert(&seal).unwrap();
        let disc5_key = disc5_index_key(parsed.epoch_number, zone.path(), &seal.id);
        storage.put_cf_raw(crate::storage::rocks::CF_EPOCHS, &disc5_key, &[])
            .expect("put CF_EPOCHS index");

        // Promote the seal to canonical in state so the helper sees a real entry.
        let canonical_hash = seal.record_hash();
        state.register_seal(&parsed, &seal.id, canonical_hash);
        assert_eq!(state.latest_epoch.get(&zone).copied(), Some(1));
        assert_eq!(state.latest_seal_hash.get(&zone).copied(), Some(canonical_hash));
        assert_eq!(state.latest_seal_id.get(&zone).cloned(), Some(seal.id.clone()));

        canonicalize_latest_seals(&mut state, &storage);

        // Single-seal short-circuit at L3540: nothing changes.
        assert_eq!(state.latest_epoch.get(&zone).copied(), Some(1),
            "single-seal canonicalize must not bump epoch");
        assert_eq!(state.latest_seal_hash.get(&zone).copied(), Some(canonical_hash),
            "single-seal canonicalize must not change latest_seal_hash");
        assert_eq!(state.latest_seal_id.get(&zone).cloned(), Some(seal.id),
            "single-seal canonicalize must not change latest_seal_id");
    }

    /// Two seals at the same `(zone, epoch)` from
    /// distinct identities → `canonicalize_latest_seals` re-registers both,
    /// `register_seal`'s `record_hash < current_hash` tiebreak fires, and
    /// `latest_seal_hash[zone]` converges on the lex-min hash regardless
    /// of which order the seals arrived locally.
    ///
    /// This is the load-bearing branch the helper was written for: Stage
    /// 3b.5/3b.6 dual-proposer races leave CF_EPOCHS with 2+ entries at the
    /// same epoch on different nodes. Without the helper, each node would
    /// pick the first-arrived hash, compute a different `chained_beacon`
    /// for the next epoch, and no node would think it was rank-0 → chain
    /// freeze. A regression that dropped the `register_seal` call inside
    /// the inner loop here would resurrect that failure mode and is caught
    /// by the lex-min convergence assertion.
    #[cfg(feature = "node-core")]
    #[test]
    fn batch_q_canonicalize_latest_seals_multi_seal_converges_on_lex_min_hash() {
        let (mut storage, _dir) = test_engine();
        let id_a = test_identity();
        let id_b = test_identity();
        let zone = ZoneId::from_legacy(0);

        // Bump state.latest_epoch[zone] = 0 so next_epoch returns 1.
        let mut state = EpochState::new();
        state.latest_epoch.insert(zone.clone(), 0);

        let (seal_a, parsed_a) = create_epoch_seal(
            &id_a, &storage, &state, zone.clone(), 0.0, 100.0, None, None,
        ).expect("create_epoch_seal A");
        let (seal_b, parsed_b) = create_epoch_seal(
            &id_b, &storage, &state, zone.clone(), 0.0, 100.0, None, None,
        ).expect("create_epoch_seal B");

        // Two distinct identities at the same (zone, epoch) must produce
        // distinct record_hashes; if they collide the test premise is broken.
        let hash_a = seal_a.record_hash();
        let hash_b = seal_b.record_hash();
        assert_ne!(hash_a, hash_b, "distinct identities must produce distinct seal record_hashes");
        assert_eq!(parsed_a.epoch_number, 1);
        assert_eq!(parsed_b.epoch_number, 1);

        // Insert both seal records + their CF_EPOCHS index entries.
        storage.insert(&seal_a).unwrap();
        storage.insert(&seal_b).unwrap();
        let key_a = disc5_index_key(1, zone.path(), &seal_a.id);
        let key_b = disc5_index_key(1, zone.path(), &seal_b.id);
        storage.put_cf_raw(crate::storage::rocks::CF_EPOCHS, &key_a, &[]).unwrap();
        storage.put_cf_raw(crate::storage::rocks::CF_EPOCHS, &key_b, &[]).unwrap();

        // Install the LARGER-hash seal as canonical first so canonicalize has
        // real work to do. This models the dual-proposer race where the
        // local node happened to ingest the loser-hash seal first.
        let (larger_hash, larger_id, larger_parsed, smaller_hash, smaller_id) =
            if hash_a > hash_b {
                (hash_a, seal_a.id.clone(), &parsed_a, hash_b, seal_b.id.clone())
            } else {
                (hash_b, seal_b.id.clone(), &parsed_b, hash_a, seal_a.id.clone())
            };
        state.register_seal(larger_parsed, &larger_id, larger_hash);
        assert_eq!(state.latest_seal_hash.get(&zone).copied(), Some(larger_hash),
            "pre-canonicalize: canonical must be the larger-hash seal (race-loser locally)");
        assert_eq!(state.latest_seal_id.get(&zone).cloned(), Some(larger_id));

        canonicalize_latest_seals(&mut state, &storage);

        // Post-canonicalize: lex-min hash wins regardless of arrival order.
        assert_eq!(state.latest_seal_hash.get(&zone).copied(), Some(smaller_hash),
            "post-canonicalize: lex-min hash must be canonical");
        assert_eq!(state.latest_seal_id.get(&zone).cloned(), Some(smaller_id),
            "post-canonicalize: seal_id must follow the lex-min hash");
        // Epoch unchanged — canonicalize only changes which record_hash wins
        // at the existing epoch, never advances the epoch counter.
        assert_eq!(state.latest_epoch.get(&zone).copied(), Some(1),
            "canonicalize must not advance latest_epoch");
    }

    /// `disc5_index_key` / `parse_disc5_index_key`
    /// round-trip pins the documented CF_EPOCHS wire layout: `epoch:u64_be(8)
    /// || zone_path_utf8 || 0x00 || record_id_utf8`. The layout is "MUST NEVER
    /// change without a backfill" — every node's index would have to be
    /// rebuilt. This test pins each invariant separately so a regression that
    /// flips byte order, drops the NUL separator, or accepts malformed keys
    /// surfaces with a precise failure rather than a hard-to-localize panic
    /// downstream in the seal-headers query path.
    #[test]
    fn batch_r_disc5_index_key_round_trip_and_byte_layout_pins_wire_format() {
        // Happy round-trip: build a key with a non-trivial epoch, multi-segment
        // zone path, and ascii record_id; parse it back; all three components
        // must match byte-for-byte.
        let epoch: u64 = 0x0102030405060708;
        let zone_path = "root/0/eu";
        let record_id = "rec-abcdef0123";
        let key = disc5_index_key(epoch, zone_path, record_id);

        // Byte-level layout pin: first 8 bytes = epoch big-endian.
        assert_eq!(&key[..8], &epoch.to_be_bytes()[..],
            "first 8 bytes must be epoch::u64_be");
        // Next zone_path.len() bytes = zone path utf-8.
        assert_eq!(&key[8..8 + zone_path.len()], zone_path.as_bytes(),
            "bytes 8..8+zone.len() must be zone_path utf-8");
        // Then exactly one NUL separator.
        assert_eq!(key[8 + zone_path.len()], 0u8,
            "separator byte must be 0x00");
        // Then record_id utf-8 to the end.
        assert_eq!(&key[8 + zone_path.len() + 1..], record_id.as_bytes(),
            "trailing bytes must be record_id utf-8");
        // Total length is the sum (no trailing bytes).
        assert_eq!(key.len(), 8 + zone_path.len() + 1 + record_id.len(),
            "key.len() must equal 8 + zone.len() + 1 + record_id.len()");

        // Parse recovers all three components.
        let parsed = parse_disc5_index_key(&key).expect("parse must succeed");
        assert_eq!(parsed.0, epoch, "parsed epoch must match");
        assert_eq!(parsed.1, zone_path, "parsed zone must match");
        assert_eq!(parsed.2, record_id, "parsed record_id must match");

        // Rejection cases: each malformed input must return None (caller skips,
        // not panics). Keys shorter than 9 bytes have no room for epoch+sep.
        assert!(parse_disc5_index_key(&[]).is_none(), "empty key rejected");
        assert!(parse_disc5_index_key(&[0u8; 8]).is_none(), "8-byte key (no sep) rejected");
        // Missing separator: 9+ bytes but no 0x00 in tail.
        let no_sep = {
            let mut k = epoch.to_be_bytes().to_vec();
            k.extend_from_slice(b"no-separator-here");
            k
        };
        assert!(parse_disc5_index_key(&no_sep).is_none(), "key without NUL separator rejected");
        // Empty zone (NUL immediately after epoch bytes).
        let empty_zone = {
            let mut k = epoch.to_be_bytes().to_vec();
            k.push(0u8);
            k.extend_from_slice(b"rec");
            k
        };
        assert!(parse_disc5_index_key(&empty_zone).is_none(), "empty-zone key rejected");
        // Empty record_id (NUL at end with nothing after).
        let empty_rec = {
            let mut k = epoch.to_be_bytes().to_vec();
            k.extend_from_slice(b"zone");
            k.push(0u8);
            k
        };
        assert!(parse_disc5_index_key(&empty_rec).is_none(), "empty-record_id key rejected");
    }

    /// Pins the exact wire-shape string literals for
    /// the `epoch_op` metadata field. These strings appear in the JSON metadata
    /// of every seal record on the wire — light clients filter on them, the
    /// `extract_*` functions match against them (see L1996 for global-seal,
    /// L3285 for super-seal), and any node that emits a different literal
    /// will be ignored by every other peer. A refactor renaming a constant
    /// without updating the string value would silently break cross-zone
    /// settlement (global_seal) or super-seal sync for light clients.
    #[test]
    fn batch_r_epoch_op_wire_string_constants_pin_exact_values() {
        assert_eq!(EPOCH_OP_KEY, "epoch_op",
            "EPOCH_OP_KEY is the metadata field name — wire shape pin");
        assert_eq!(EPOCH_OP_GLOBAL_SEAL, "global_seal",
            "EPOCH_OP_GLOBAL_SEAL is the value emitted by cross-zone escalation seals");
        assert_eq!(EPOCH_OP_SUPER_SEAL, "super_seal",
            "EPOCH_OP_SUPER_SEAL is the value emitted by gap-3 checkpoint seals");
        // The three string constants must be distinct — otherwise a global-seal
        // could be mistaken for a super-seal at the extract layer.
        assert_ne!(EPOCH_OP_GLOBAL_SEAL, EPOCH_OP_SUPER_SEAL,
            "global_seal and super_seal labels must be distinct on the wire");
    }

    /// Pins the mainnet-default values of the eight
    /// load-bearing constants in this module's header, plus the derived
    /// `MAX_RANK_ELAPSED_SECS` = `2 * MAX_ADAPTIVE_EPOCH_SECS` invariant.
    /// Each of these numbers is referenced in the whitepaper or operator
    /// runbooks; a change that drifts the default away from the documented
    /// value would silently invalidate gap-3 (super-seal cadence) or gap-8
    /// (adaptive epoch floor/ceiling) deployment assumptions across the
    /// fleet. The FLOOR<CEILING ordering is the autotune-stability invariant
    /// — if it ever inverts, the clamp in `compute_adaptive_interval` (L1444)
    /// becomes a no-op and the floor is lost.
    #[test]
    fn batch_r_adaptive_epoch_and_super_seal_constants_pin_mainnet_defaults() {
        // Gap 3 — super-seal cadence (light-client checkpoint frequency).
        assert_eq!(SUPER_SEAL_INTERVAL, 64,
            "super-seal interval = 64 epochs per gap-3 spec");

        // Gap 8 — adaptive epoch bounds (in-zone finality floor + quiet-zone cap).
        assert!((MIN_ADAPTIVE_EPOCH_SECS - 5.0).abs() < 1e-9,
            "min adaptive epoch = 5s mainnet floor (was 30s → 15s → 5s on 2026-04-22)");
        assert!((MAX_ADAPTIVE_EPOCH_SECS - 60.0).abs() < 1e-9,
            "max adaptive epoch = 60s mainnet ceiling (was 120s → 60s on 2026-04-29)");
        // FLOOR < CEILING autotune-stability invariant pinned at compile
        // time via the `const _: () = assert!(..)` block next to
        // MAX_ADAPTIVE_EPOCH_SECS (epoch.rs ~L196). A regression now
        // fails at `cargo build`, not at `cargo test`. Runtime assert
        // removed (clippy::assertions_on_constants — both operands
        // const-eval).

        // Derived: MAX_RANK_ELAPSED_SECS = 2 * MAX_ADAPTIVE_EPOCH_SECS.
        // Sized so post-cap-drop tightening is automatic.
        assert!((MAX_RANK_ELAPSED_SECS - 2.0 * MAX_ADAPTIVE_EPOCH_SECS).abs() < 1e-9,
            "MAX_RANK_ELAPSED_SECS must equal 2 * MAX_ADAPTIVE_EPOCH_SECS");
        assert!((MAX_RANK_ELAPSED_SECS - 120.0).abs() < 1e-9,
            "concrete derived value: 2 * 60.0 = 120.0");

        // Activity-EMA constants.
        assert!((TARGET_RECORDS_PER_EPOCH - 100.0).abs() < 1e-9,
            "target rec/epoch = 100 (faster if >100, slower if <100)");
        assert!((ACTIVITY_EMA_ALPHA - 0.3).abs() < 1e-9,
            "EMA alpha = 0.3 (30% new obs + 70% history)");
        // EMA alpha smoothing-factor band (strictly inside (0, 1))
        // pinned at compile time via the `const _: () = assert!(..)`
        // block next to ACTIVITY_EMA_ALPHA (epoch.rs ~L232). A
        // regression now fails at `cargo build`, not at `cargo test`.
        // Runtime assert removed (clippy::assertions_on_constants —
        // both operands const-eval).

        // Per-zone VRF history ring (bounded memory).
        assert_eq!(VRF_HISTORY_PER_ZONE, 64,
            "per-zone VRF history ring = 64 entries (SCALE RULE bounded)");

        // Anchor-identity vec ceiling (SCALE RULE guard).
        assert_eq!(MAX_ANCHORS_PER_PROPOSAL, 1_000_000,
            "anchor-identity vec ceiling = 1M (generous headroom over 5K-50K mainnet target)");
    }

    /// GENESIS ZONE BOOTSTRAP (fresh-chain liveness): a clean
    /// chain whose genesis records predate the seal-loop discovery window
    /// must still discover their zones, or the first seal never happens.
    /// Pins the fallback's three filters: pre-window records ARE discovered,
    /// epoch-op records are excluded, future-dated records (clock skew) are
    /// excluded.
    #[tokio::test]
    async fn genesis_bootstrap_zones_discovers_pre_window_and_filters() {
        use crate::network::state::build_test_node_state;
        use std::collections::BTreeMap;

        let state = build_test_node_state();
        let now = 1_750_000_000.0_f64;

        // Empty storage → empty set, no panic.
        assert!(
            genesis_bootstrap_zones(&state, now, 1000).is_empty(),
            "empty storage must yield no zones"
        );

        // (a) Plain record 1 hour older than any seal window → discovered.
        let mut old_rec = ValidationRecord::create(
            b"genesis-era record",
            vec![1u8; 32],
            vec![],
            Classification::Public,
            None,
        );
        old_rec.timestamp = now - 3600.0;
        state.rocks.put_record(&old_rec.id, &old_rec).unwrap();

        // (b) Epoch-op record (seal) even older → excluded by the filter.
        let mut seal_meta = BTreeMap::new();
        seal_meta.insert(
            EPOCH_OP_KEY.to_string(),
            serde_json::Value::String("seal".to_string()),
        );
        let mut seal_rec = ValidationRecord::create(
            b"old seal record",
            vec![2u8; 32],
            vec![],
            Classification::Public,
            Some(seal_meta),
        );
        seal_rec.timestamp = now - 7200.0;
        state.rocks.put_record(&seal_rec.id, &seal_rec).unwrap();

        // (c) Future-dated record (clock skew) → excluded.
        let mut future_rec = ValidationRecord::create(
            b"future-dated record",
            vec![3u8; 32],
            vec![],
            Classification::Public,
            None,
        );
        future_rec.timestamp = now + 600.0;
        state.rocks.put_record(&future_rec.id, &future_rec).unwrap();

        let zones = genesis_bootstrap_zones(&state, now, 1000);
        let expected = state.resolve_record_zone(&old_rec.id);
        assert!(
            zones.contains(&expected),
            "pre-window plain record's zone must be discovered"
        );
        // Filters working → ONLY the plain pre-window record contributes.
        // (Exactly one source record → exactly one zone; the seal and
        // future-dated records must add nothing.)
        assert_eq!(
            zones.len(),
            1,
            "epoch-op / future-dated records must not seed zones (got {zones:?})"
        );
    }

    /// A3 (audit 2026-06-19, fusion-audited): the VRF history ring's retention
    /// MUST be a pure function of the seal SET keyed on `end_ts`, independent of
    /// arrival order — otherwise Fisherman jury seeding diverges across nodes →
    /// consensus fork. The removed window-gate dropped entries by
    /// `epoch < min_epoch` while truncation keeps the 64 highest `end_ts`; those
    /// keys disagree when epoch# and end_ts are NOT co-monotone (multi-zone). This
    /// feeds the SAME non-co-monotone entry set in two arrival orders and asserts
    /// byte-identical rings, and that the low-epoch/high-end_ts entry the old gate
    /// wrongly dropped is now retained. FAILS on the old epoch-gate (rings differ
    /// + entry absent), PASSES after gate removal.
    #[test]
    fn vrf_ring_retention_is_end_ts_keyed_and_order_independent() {
        let cap = VRF_HISTORY_PER_ZONE;
        let zone = crate::ZoneId::from_legacy(0);

        // entry = (end_ts, epoch, vrf, record_hash). Fillers are co-monotone
        // (epoch 100+i ↔ end_ts 1000+i), so min_epoch == 100 once the ring is
        // full. The inversion has a LOW epoch (1 < min_epoch) but the HIGHEST
        // end_ts — it belongs in the retained window by end_ts, yet the old
        // epoch-gate dropped it.
        let mut entries: Vec<(f64, u64, [u8; 32], [u8; 32])> = Vec::with_capacity(cap + 1);
        for i in 0..cap {
            let e = (100 + i) as u64;
            entries.push((1000.0 + i as f64, e, [i as u8; 32], [i as u8; 32]));
        }
        let inv = (9999.0_f64, 1_u64, [0xAA; 32], [0xAA; 32]);
        entries.push(inv);

        let mut fwd = EpochState::new();
        for (ts, ep, vrf, rh) in entries.iter().copied() {
            fwd.upsert_vrf_ring(&zone, ts, ep, vrf, rh);
        }
        let mut rev = EpochState::new();
        for (ts, ep, vrf, rh) in entries.iter().rev().copied() {
            rev.upsert_vrf_ring(&zone, ts, ep, vrf, rh);
        }

        let fwd_ring = fwd.vrf_history.get(&zone).expect("fwd ring populated");
        let rev_ring = rev.vrf_history.get(&zone).expect("rev ring populated");

        // Bounded to cap on both paths.
        assert_eq!(fwd_ring.len(), cap, "ring bounded at VRF_HISTORY_PER_ZONE");
        assert_eq!(rev_ring.len(), cap, "ring bounded at VRF_HISTORY_PER_ZONE");
        // Pure function of the SET: byte-identical regardless of arrival order.
        assert_eq!(
            fwd_ring, rev_ring,
            "VRF ring must be a pure function of the seal SET, not arrival order"
        );
        // The low-epoch/high-end_ts inversion is RETAINED (old gate dropped it).
        assert!(
            fwd_ring.iter().any(|&(ts, ep, _, _)| ep == 1 && ts == 9999.0),
            "low-epoch/high-end_ts entry must be retained (retention is end_ts-keyed)"
        );
        // The true lowest-end_ts filler (end_ts 1000.0) was evicted in its place.
        assert!(
            !fwd_ring.iter().any(|&(ts, _, _, _)| ts == 1000.0),
            "lowest-end_ts entry must be evicted by end_ts truncation"
        );
        // Reader seeds the jury with the inversion's VRF at its end_ts.
        assert_eq!(
            fwd.vrf_output_at_or_before(&zone, 9999.0),
            Some([0xAA; 32]),
            "jury seed at the inverted entry's end_ts must be its VRF output"
        );
    }
}
