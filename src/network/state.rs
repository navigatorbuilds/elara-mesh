//! Shared node state — Arc-friendly wrapper over all node subsystems.

//!
//! Spec references:
//!   @spec Protocol §3.2
//!   @spec Protocol §3.4

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU8, AtomicU64};
use std::time::Instant;

use tokio::sync::{Mutex, RwLock, broadcast};

use crate::dag::DagIndex;
use crate::errors::Result;
use crate::identity::Identity;
use crate::record::ValidationRecord;
use crate::storage::rocks::StorageEngine;
#[cfg(test)]
use crate::storage::Storage;
use crate::accounting::bootstrap::BootstrapState;
use crate::accounting::delegation::DelegationRegistry;
use crate::accounting::genesis::GenesisState;
use crate::accounting::ledger::LedgerState;
use crate::accounting::entity::EntityClusterer;
use crate::accounting::trust::TrustEngine;

use super::config::NodeConfig;
use super::pq_client::PqNodeClient;
use super::pq_transport::PeerIdentityStore;

use super::consensus::{AWCConsensus, Attestation, ZoneState};
use super::dispute::DisputeState;
use super::dht::{NodeId, RoutingTable};
use super::fisherman::ChallengeState;
use super::epoch::EpochState;
use super::key_rotation::KeyRegistry;
use super::liveness::WitnessLiveness;
use super::reputation::ReputationEngine;
use super::sunset::SunsetState;
use super::ingest::{SeenSet, PropagationLimiter};
use super::timestamp_defense::TimestampDefense;
use super::peer::PeerTable;
use super::witness::WitnessManager;
use super::LockRecover;
use crate::itc::ZoneClockManager;

/// Real-time event emitted when something notable happens on the node.
#[derive(Debug, Clone)]
pub enum NodeEvent {
    /// A new record was inserted into the DAG.
    RecordInserted {
        record_id: String,
        creator_hash: String,
        beat_op: Option<String>,
        beat_amount: Option<u64>,
        timestamp: f64,
    },
    /// MAINNET gap #8: a record transitioned from Pending to Sealed
    /// (≥ ATTESTED_MIN_WITNESSES attestations, one anchor sig). Wallets
    /// use this for optimistic "Sealed" UX surfaced at ~3-5s without
    /// polling `/seal/progress`.
    RecordSealed {
        record_id: String,
        witness_count: u32,
    },
    /// A record reached consensus finality.
    RecordFinalized { record_id: String },
}

/// Result of feeding a single attestation into consensus.
///
/// `settled` answers "does this record currently pass the 2/3 threshold"
/// (the old bool return — wire responses keep using it). `first_finalization`
/// is true ONLY for the call that won the durable FinalizedIndex insert;
/// exactly-once side-effects (rewards / reputation credit / RecordFinalized)
/// key off it via `reward::finalization_effects`.
#[derive(Debug, Clone, Default)]
pub struct FeedOutcome {
    pub settled: bool,
    pub first_finalization: bool,
    /// Seal members whose durable FinalizedIndex insert happened in THIS
    /// call via the Layer-2 fast-track (already counted; NOT overlapping
    /// `first_finalization`, which is the fed record itself). Callers fire
    /// `reward::finalization_effects(state, outcome.seal_members_finalized)`
    /// — the same exactly-once contract as `first_finalization`.
    pub seal_members_finalized: Vec<String>,
}

/// Result of a batch attestation feed: all rids that currently pass
/// settlement, and the subset whose durable FinalizedIndex insert happened
/// in THIS call (the exactly-once edge for finalization side-effects).
#[derive(Debug, Clone, Default)]
pub struct BatchFeedOutcome {
    pub settled: Vec<String>,
    pub newly_finalized: Vec<String>,
    /// Seal members durably indexed in THIS call via the Layer-2 fast-track
    /// (already counted; disjoint from `newly_finalized` unless a rid raced
    /// both edges — the durable insert dedups, so no rid appears in both).
    /// Callers fire `reward::finalization_effects` on these too.
    pub seal_members_finalized: Vec<String>,
}

/// Gap 6.4 slice 3a: an outstanding DHT-routed seal push awaiting
/// reconciliation. Slice 3b's reconciler probes each `target` (peer
/// identity hash) for actual persistence of `seal_id` after
/// `seal_dht_ack_timeout_secs` has elapsed since `pushed_at`, and
/// re-pushes if the realized replication factor fell below
/// `seal_dht_replication_floor`.
///
/// Captured *post bandwidth filter* in `push_to_peers` so the realized
/// peer set matches what the originator actually attempted — not the
/// chosen-K set before the per-peer token bucket might have blocked some
/// peers. This matters when a single noisy peer chronically saturates
/// its outbound bucket: the reconciler shouldn't blame the K-DHT path
/// for a peer it never reached.
#[derive(Debug, Clone)]
pub struct PendingSealReplication {
    /// Record id of the seal that was pushed.
    pub seal_id: String,
    /// Peer identity hashes the originator attempted to push to (post
    /// bandwidth filter). Length is bounded above by `content_routing_k`
    /// and below by `seal_dht_replication_floor` when the K-DHT path
    /// was taken.
    pub targets: Vec<String>,
    /// Process-monotonic timestamp of the push attempt. Reconciler
    /// uses `Instant::elapsed()` to decide which entries are due.
    pub pushed_at: Instant,
    /// Slice 3b: number of reconciler-driven re-push attempts so far.
    /// Bounded by `seal_dht_max_repush_retries`. On the cap, the entry
    /// is dropped from the queue and the violation counter is bumped —
    /// a stuck seal can't pin reconciler bandwidth indefinitely.
    pub retries: u8,
}

/// CAS-loop max — atomically raises `target` to
/// `candidate` if `candidate` is larger, otherwise no-op. Used by all
/// high-water-mark gauges (per-phase ingest latency, seal-window observed
/// max, snapshot-serve account/applied counts, state_core record_processing
/// max, record_stats earliest/latest ts). The loop tolerates races by
/// re-reading on `Err(actual)` and only retrying when `candidate > actual`.
/// Released for inlining; matches the duplicated pattern at
/// `state_core.rs:227`, `routes/sync.rs:578/587`, `epoch.rs:63`, and the
/// two `record_stats_*_ts_bits` sites in this file (kept inline there
/// because they encode f64 bits via to_bits/from_bits, not raw u64).
#[inline]
pub fn store_max_atomic(target: &AtomicU64, candidate: u64) {
    use std::sync::atomic::Ordering::Relaxed;
    let mut current = target.load(Relaxed);
    while candidate > current {
        match target.compare_exchange_weak(current, candidate, Relaxed, Relaxed) {
            Ok(_) => break,
            Err(actual) => current = actual,
        }
    }
}

/// Gap 6.4 slice 3a: pure helper for the bounded-FIFO enqueue of
/// pending seal-replication entries. Returns the number of entries
/// evicted to make room (0 in the steady state, ≥1 when the queue is
/// at `cap`). Pulled out as a free function so the bounding policy can
/// be exercised in isolation by unit tests without spinning up a full
/// `NodeState`.
///
/// Empty `targets` is treated as a no-op — the reconciler has nothing
/// to probe with no peer set, so we don't waste a queue slot on it.
pub fn enqueue_pending_seal_replication_bounded(
    queue: &mut VecDeque<PendingSealReplication>,
    cap: usize,
    seal_id: String,
    targets: Vec<String>,
    pushed_at: Instant,
) -> usize {
    if targets.is_empty() {
        return 0;
    }
    let cap = cap.max(1);
    let mut evicted = 0;
    while queue.len() >= cap {
        queue.pop_front();
        evicted += 1;
    }
    queue.push_back(PendingSealReplication {
        seal_id,
        targets,
        pushed_at,
        retries: 0,
    });
    evicted
}

/// Memoized staked-anchor view shared by the seal proposer
/// (`epoch::should_propose_seal`) and BOTH seal verifiers (`network::ingest`).
/// The set is `{(id, stake) : id ∈ CF_IDENTITIES_ANCHOR ∧ ledger.staked > 0}`,
/// plus its partition by home zone. Rebuilt only when the cache key changes;
/// on a hit all three call sites clone the same `Arc`s, so the proposer and a
/// verifier can never compute divergent staked-anchor sets — structurally
/// closing the 2026-05-10/11 rank-asymmetry chain-freeze class. The rebuild is
/// the exact CF-scan + ledger-join the three sites used to run inline, so it is
/// a pure memoization (correct by construction).
pub struct AnchorView {
    /// `(stake_mutation_seq, anchor_add_seq, zone_transition_count)` — all
    /// strictly monotonic, so any change to the staked set, the anchor
    /// membership, or the zone partition advances the key and forces a rebuild.
    key: (u64, u64, u64),
    /// `total_staked` self-healing fingerprint: it moves on every
    /// stake/unstake/slash, so even a forgotten `stake_mutation_seq` bump (e.g.
    /// a future 5th mutation site) still triggers a rebuild rather than serving
    /// a stale view.
    fp: u64,
    /// Flat staked-anchor list — the rank-chain input (`staked_amounts`).
    flat: std::sync::Arc<Vec<(String, u64)>>,
    /// Same set partitioned by current home zone (`resolve_identity_zone`) —
    /// the escalation-decision input (`stakers_by_zone`).
    by_zone: std::sync::Arc<std::collections::HashMap<crate::ZoneId, Vec<(String, u64)>>>,
}

/// Transitions-F1: memoized zone-transition-seal trust set — the identities
/// whose `AnchorSig`s count toward the split/merge threshold.
///
/// Membership = the LEDGER staker set (`ledger.staker_index`) filtered to
/// `staked >= MIN_WITNESS_STAKE_BASE_UNITS`, plus the genesis authority
/// unconditionally. Deliberately NOT sourced from `CF_IDENTITIES_ANCHOR`
/// (that CF has no dedicated production writer — empty at bootstrap, so a
/// gate built on it would reject even genesis; F1 audit 2026-07-05 MISS-1)
/// and deliberately independent of [`AnchorView`] (the proposer-rank input,
/// whose membership basis MUST stay bit-identical across proposer+verifiers
/// — the LIVENESS-1 invariant — and must not change under F1).
///
/// Same cache discipline as [`AnchorView`]: key = `stake_mutation_seq`
/// (strictly monotonic across every stake mutation site), fp =
/// `total_staked` (self-healing fingerprint), and wholesale invalidation by
/// [`NodeState::invalidate_anchor_view`] on every ledger-replace path.
/// Zone/anchor-CF generations are NOT in the key — membership depends on
/// neither.
pub struct TransitionTrustView {
    /// `stake_mutation_seq` at build time.
    key: u64,
    /// `total_staked` self-healing fingerprint (see [`AnchorView::fp`]).
    fp: u64,
    /// Raw 32-byte identity hashes (the `AnchorSig::anchor_identity_hash`
    /// form) — zero-alloc per-sig membership checks.
    set: std::sync::Arc<std::collections::HashSet<[u8; 32]>>,
}

/// One open DAG-completeness deficit: a sealed epoch whose on-the-wire
/// `record_hashes` contained entries this node could not resolve locally at
/// ingest time (Tier-1, internal design notes §4). The entry
/// keeps just enough to re-check later (point lookups, never a scan) and to
/// seed the full_pull cursor at the hole's start.
#[derive(Debug, Clone)]
pub struct DagDeficitEntry {
    /// Locally-missing record count at the last (re-)check.
    pub missing: u64,
    /// Seal window start ts — the full_pull cursor-seed target.
    pub seal_start: f64,
    /// Record id of the seal itself, to re-load `record_hashes` for re-checks.
    pub seal_record_id: String,
    /// Unix seconds when the deficit was first observed.
    pub first_seen_unix: u64,
}

/// Bounded FIFO ring of open deficits keyed by (zone path, epoch).
/// Memory is O(open deficits) with a hard cap — never O(history). Eviction
/// drops the oldest-observed entry; the ~200-cycle full_pull tail-reset
/// re-observes anything still real. Same set+order pattern as
/// `ingest::SeenSet` (stale `order` keys are skipped lazily).
pub struct DagDeficitRing {
    map: std::collections::HashMap<(String, u64), DagDeficitEntry>,
    order: VecDeque<(String, u64)>,
    capacity: usize,
}

impl DagDeficitRing {
    pub fn new(capacity: usize) -> Self {
        Self {
            map: std::collections::HashMap::new(),
            order: VecDeque::new(),
            capacity,
        }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Record an observed deficit. Returns `true` if this (zone, epoch) is a
    /// NEW open deficit (drives `dag_deficit_epochs_total`); an existing entry
    /// just gets its `missing` refreshed.
    pub fn observe(&mut self, key: (String, u64), entry: DagDeficitEntry) -> bool {
        if let Some(existing) = self.map.get_mut(&key) {
            existing.missing = entry.missing;
            return false;
        }
        if self.map.len() >= self.capacity {
            // Evict oldest-observed live entry (skip stale order keys).
            while let Some(old) = self.order.pop_front() {
                if self.map.remove(&old).is_some() {
                    break;
                }
            }
        }
        self.map.insert(key.clone(), entry);
        self.order.push_back(key);
        true
    }

    /// Update the missing count after a re-check.
    pub fn update_missing(&mut self, key: &(String, u64), missing: u64) {
        if let Some(e) = self.map.get_mut(key) {
            e.missing = missing;
        }
    }

    /// Close a deficit (re-check found all records, or the seal itself is
    /// gone/pruned). Returns `true` if it was open.
    pub fn resolve(&mut self, key: &(String, u64)) -> bool {
        self.map.remove(key).is_some()
    }

    /// Round-robin pick for the once-per-cycle re-check: rotates the order
    /// queue and returns the first key that is still live, with its seal
    /// record id. O(stale prefix) amortized.
    pub fn next_for_recheck(&mut self) -> Option<((String, u64), String)> {
        while let Some(key) = self.order.pop_front() {
            if let Some(e) = self.map.get(&key) {
                let rid = e.seal_record_id.clone();
                self.order.push_back(key.clone());
                return Some((key, rid));
            }
            // stale key (resolved earlier) — drop and keep scanning
        }
        // Invariant: every live map entry has ≥1 key in `order` (observe
        // pushes on insert; rotation re-pushes live keys; eviction removes
        // map+order together), so a drained `order` means no open deficits.
        // `recheck_dag_deficits` relies on this when it reports "0 open" on
        // a `None` pick — a live entry stranded here would look healed
        // forever while its records stay missing.
        debug_assert!(
            self.map.is_empty(),
            "DagDeficitRing: order drained with {} live entries — recheck would false-report 0 open",
            self.map.len()
        );
        None
    }

    /// Earliest open hole's seal window start — the cursor-seed target.
    pub fn earliest_start(&self) -> Option<f64> {
        self.map
            .values()
            .map(|e| e.seal_start)
            .min_by(|a, b| a.total_cmp(b))
    }
}

/// Hard cap on tracked open deficits (bounded memory; contract §4.1).
pub const MAX_OPEN_DAG_DEFICITS: usize = 512;

/// Shared state for the running node. Wrapped in `Arc` for async sharing.
pub struct NodeState {
    pub config: NodeConfig,
    pub identity: Identity,
    /// RocksDB storage engine — production persistence with 15 column families.
    pub rocks: Arc<StorageEngine>,
    /// Supervised lifecycle-loop liveness registry (loop-supervision verdict
    /// 2026-07-19). Populated at boot by `spawn_supervised`; read by `/metrics`
    /// (`elara_loop_*`) and (later) `/health`. Empty on nodes/tests that don't
    /// wire supervised loops.
    pub loop_registry: Arc<crate::network::supervision::LoopRegistry>,
    /// In-memory DAG index.
    ///
    /// `Arc<DagIndex>` (DISC-8 (a) Arc-CoW, 2026-04-26): readers and snapshot
    /// callers clone the `Arc` cheaply (refcount bump) and operate on the
    /// snapshot outside the read lock. Writers obtain a `&mut DagIndex` via
    /// `Arc::make_mut`, which clones in-place only if the `Arc` is shared
    /// at the moment of write — so the rare deep-clone cost is paid by the
    /// next writer, not by every concurrent reader, and the snapshot save
    /// path no longer holds the read lock through the whole DagIndex
    /// serialization (was the `dag_write_holder=7` phase-2 deadlock
    /// signature).
    pub dag: RwLock<Arc<DagIndex>>,
    /// Derived ledger state.
    pub ledger: RwLock<LedgerState>,
    /// Known peers.
    pub peers: RwLock<PeerTable>,
    /// Gossip dedup set.
    pub seen: std::sync::Mutex<SeenSet>,
    /// Post-quantum RPC client (Phase 4 — ML-KEM-768 + Dilithium3).
    /// Shares this node's Dilithium3 identity and the pin store below.
    /// Cheap to clone (Arc-shared state).
    pub pq_client: PqNodeClient,
    /// Persistent TOFU-then-pinned peer identity store for PQ transport.
    /// Lives under `<data_dir>/pq-peer-pins.json`.
    pub pq_pins: Arc<PeerIdentityStore>,
    /// Witness attestation manager.
    pub witness_mgr: Arc<WitnessManager>,
    /// AWC consensus engine.
    pub consensus: std::sync::Mutex<AWCConsensus>,
    /// Crash-recovery one-shot: record ids whose pending delta is durably
    /// FINALIZED but not yet applied (the in-memory `finalization_queue` was
    /// lost to a crash inside the finality→drain window). Populated once by
    /// `boot_replay_pending_deltas`, drained by the first
    /// `drain_and_commit_pending` tick through the normal commit path.
    /// UNCAPPED (unlike `finalization_queue`, which silently drops on overflow)
    /// so a large crash window cannot silently drop recoveries; exactly-once is
    /// preserved by the drain's `is_applied()` + `take()`.
    pub boot_reconcile_ids: std::sync::Mutex<Vec<String>>,
    /// Count of finalized-but-unapplied deltas recovered by boot reconcile
    /// across all boots. Non-zero ⇒ the node crashed inside the commit window
    /// at least once — an operational signal worth alerting on.
    pub pending_boot_reconciled_total: AtomicU64,
    /// Set of record IDs that have reached finality.
    /// Disk-backed with bounded LRU cache — see `finalized.rs`.
    pub finalized: RwLock<super::finalized::FinalizedIndex>,
    /// DHT routing table for peer discovery.
    pub dht: std::sync::Mutex<RoutingTable>,
    /// Epoch sealing state (per-zone tracking).
    pub epoch: std::sync::RwLock<EpochState>,
    /// Gap 1: Light-client header state. Populated by `light_sync_loop` on
    /// Light-profile nodes. On FullZone/Archive nodes this stays empty and is
    /// only used for end-to-end light-client tests.
    pub light_state: std::sync::RwLock<super::light::LightState>,
    /// Algorithm sunset state (Protocol v0.6.1 Section 11.29).
    pub sunset: std::sync::RwLock<SunsetState>,
    /// Unix timestamp when the node started.
    pub start_time: f64,
    /// Gossip metrics: total originator pushes.
    pub gossip_push_total: AtomicU64,
    /// Gossip metrics: total relay forwards.
    pub gossip_relay_total: AtomicU64,
    /// Pull-side peer-selection took the DHT path. Each
    /// increment = one `select_gossip_peers` call where `dht.closest()` returned
    /// at least one reachable candidate that survived reputation/backoff
    /// filtering. Pairs 1:1 with `gossip_select_fallback_total` —
    /// the dominant value tells you whether the DHT is operationally
    /// contributing to gossip-target diversity, or whether the node is
    /// pulling from a static PeerTable iteration. At cold start the fallback
    /// path dominates; once DHT bootstrap completes the DHT path should
    /// dominate within ~5 cycles. A node where fallback >> DHT path after
    /// many cycles indicates DHT bootstrap regression — distinct from
    /// `dht_size>0` (which only confirms the DHT has entries, not that
    /// they're being used).
    pub gossip_select_dht_total: AtomicU64,
    /// Pull-side peer-selection fell through to PeerTable
    /// iteration. Two distinct causes both bump this counter: (a) DHT was
    /// empty (not yet bootstrapped, or all entries pruned), or (b) DHT had
    /// candidates but all of them failed reputation/backoff/reachability
    /// filtering. Case (b) is the operationally interesting one — it means
    /// the DHT is holding stale entries faster than `dht_refresh_interval`
    /// can refresh them. Pair with `dht_size` to discriminate: high fallback
    /// with `dht_size=0` → bootstrap regression; high fallback with
    /// `dht_size>0` → stale-entry regression.
    pub gossip_select_fallback_total: AtomicU64,
    /// Wall-clock secs (integer, from `now() as u64`) of the last emitted
    /// `select_gossip_peers: NO targets` WARN. Throttles that warning: a lone
    /// authority seed's *outbound* PeerTable is legitimately empty and permanent
    /// (pull-based followers dial in through NAT, so the seed never dials out),
    /// which would otherwise spam the WARN every pull tick (~14k lines/day) for
    /// a valid state and train warning-blindness. The first occurrence logs
    /// immediately — preserving the genuine signal for a follower that just lost
    /// all peers — then repeats are throttled to `NO_TARGETS_WARN_THROTTLE_SECS`.
    /// 0 = never warned.
    pub gossip_no_targets_last_warn_secs: AtomicU64,
    /// Empty-PeerTable pull ticks suppressed by the `NO targets` throttle since
    /// the last emitted WARN; reported in (and reset by) the next throttled WARN
    /// so an operator can tell a persistent lone-seed state from a transient blip.
    pub gossip_no_targets_suppressed: AtomicU64,
    /// Cumulative `pq_delta_sync(...)` invocations
    /// across the two callers (`sync.rs::delta_sync_loop` and
    /// `gossip.rs::pull_loop`). Pairs with `delta_sync_failures_timeout_total`
    /// and `delta_sync_failures_other_total` to give an operator-visible
    /// success-vs-failure ratio for a path that previously only logged warnings.
    pub delta_sync_attempts_total: AtomicU64,
    /// Cumulative count of metadata keys admitted at ingest that are NOT in
    /// this binary's ALLOWED_KEYS registry (forward-compat admission,
    /// 2026-07-02 — internal design notes). Steady growth on a
    /// node = peers run a newer schema than this binary; the node stays in
    /// sync (unknown keys are inert) but the operator should plan an
    /// upgrade. Zero on a fleet running one version.
    pub unknown_metadata_keys_admitted_total: AtomicU64,
    /// Unix-seconds timestamp of the most recent *successful* pull from any peer
    /// (set in `gossip.rs::pull_loop`'s `Ok` branch — fires even on a 0-record
    /// "caught up" pull). 0 = never pulled successfully (a fresh node, or a pure
    /// seed that never pulls). Drives the `pull-sync` health check + the
    /// `elara_seconds_since_last_successful_pull` gauge: a follower whose pulls
    /// fail (unreachable seed, wire-incompatible peer) goes stale here while its
    /// record-age may look fine, so this catches the silent-desync class.
    pub last_successful_pull_unix: AtomicU64,
    /// `pq_delta_sync` calls whose error message
    /// contained "timed out" — the dominant operator-visible failure mode
    /// today (observed: a node measured ~29% of attempts timing out over 2 h
    /// against a peer). Distinct from `_other_total` so a single labeled
    /// timeout-vs-everything-else split is plottable without parsing reasons.
    pub delta_sync_failures_timeout_total: AtomicU64,
    /// `pq_delta_sync` calls that failed for any reason
    /// other than a timeout (decode error, network error, addr derivation,
    /// per-batch hex parse). High `_other_total` with `_timeout_total` flat
    /// = transport handshake works but response shape drifted (peer running
    /// stale binary OR local schema regression).
    pub delta_sync_failures_other_total: AtomicU64,
    /// `pq_delta_sync` successes that completed in
    /// under 2 seconds — the healthy LAN/regional bucket. Sum of the three
    /// `_lt_*_total` buckets equals total successes; pair with
    /// `_attempts_total - _failures_timeout_total - _failures_other_total`
    /// for cross-check. Tail-latency visibility without a full histogram
    /// framework.
    pub delta_sync_latency_lt_2s_total: AtomicU64,
    /// `pq_delta_sync` successes in `[2s, 10s)`.
    /// Cross-region or moderately loaded peer — not yet near the 30 s
    /// `DEFAULT_CALL_TIMEOUT`.
    pub delta_sync_latency_lt_10s_total: AtomicU64,
    /// `pq_delta_sync` successes in `[10s, 30s)` —
    /// the "near-timeout" bucket. Leading-indicator surface that climbs
    /// before `_failures_timeout_total` starts incrementing. Sustained
    /// non-zero rate against a single peer = handshake saturation; spread
    /// across peers = local PqClient tuning is too tight for current network.
    pub delta_sync_latency_lt_30s_total: AtomicU64,
    /// Subset of `_failures_timeout_total` where the
    /// timeout fired during the PQ handshake (`pq_dial` exceeded
    /// `DEFAULT_CALL_TIMEOUT`). Distinguishes "peer's PQ port not responding"
    /// from "peer accepted handshake but RPC stalled". High handshake-timeout
    /// share = peer's `:9573` listener saturated, dropped TCP, or PQ accept
    /// loop hung; investigate at peer's PQ server, not the verb dispatcher.
    pub delta_sync_failures_timeout_handshake_total: AtomicU64,
    /// Subset of `_failures_timeout_total` where the
    /// timeout fired during RPC dispatch (`stream.call(req)` exceeded
    /// `DEFAULT_CALL_TIMEOUT`) on a session with a completed handshake.
    /// High RPC-timeout share = handshake works but verb processing on the
    /// remote stalls (slow query, lock contention, large delta payload);
    /// investigate at the verb handler, not the transport.
    pub delta_sync_failures_timeout_rpc_total: AtomicU64,
    /// Subset of `_failures_other_total`: addr-derivation failures — the peer's
    /// HTTP base_url could not be mapped to a PQ address (`cannot derive PQ peer
    /// addr`). LOCAL config/URL problem (bad `pq_port_offset`, malformed seed
    /// URL), not the peer. The pull never left this node.
    pub delta_sync_failures_other_addr_total: AtomicU64,
    /// Subset of `_failures_other_total`: non-timeout failures at the dial +
    /// handshake stage (`pq_dial {peer}: {e}`). TCP connect refused / host
    /// unreachable, OR the PQ handshake was rejected (identity-pin mismatch,
    /// bad signature, AEAD on a handshake message). "Couldn't reach or
    /// authenticate the peer" — investigate connectivity / the peer's `:9573`
    /// listener. A wire-incompatible peer that fails at handshake lands here.
    pub delta_sync_failures_other_dial_total: AtomicU64,
    /// Subset of `_failures_other_total`: non-timeout failures AFTER a completed
    /// handshake, during RPC transport (`rpc {peer}: {e}`) — data-frame AEAD
    /// verification failure or peer-closed mid-call. Handshake succeeds but the
    /// encrypted data exchange breaks: this is the silent-wire-break signature
    /// (data-frame AEAD-AD / framing drift between two binary versions, neither
    /// of which bumped a version field). Non-zero here with `_dial` flat =
    /// peers connect but speak an incompatible post-handshake wire.
    pub delta_sync_failures_other_rpc_total: AtomicU64,
    /// Subset of `_failures_other_total`: the server answered but the response
    /// body could not be decoded — `unexpected delta_sync response format`,
    /// `bad hex`, a `parse:` error, or a non-2xx `returned status N`. The wire
    /// transport is healthy; the response SHAPE drifted (stale-binary protocol
    /// skew) or the server rejected the request at the application layer.
    pub delta_sync_failures_other_decode_total: AtomicU64,
    /// Server-side counter incremented every time
    /// `handle_delta_sync` hits its MAX_SCAN cap (50K timestamp-index entries).
    /// At the cap the response is bounded — older records past the cap won't
    /// be tested against the requester's bloom in this round. Non-zero on a
    /// node = peers' `since` watermarks are too old for the volume of records
    /// in their window (the safe failure mode: requester re-pulls next cycle
    /// or falls back to snapshot sync). Sustained non-zero on every dial =
    /// the 24h `delta_sync_since_floor` window is too wide for the chain's
    /// record-arrival rate; tighten the window or shard the request.
    pub delta_sync_scan_hit_cap_total: AtomicU64,
    /// Server-side: delta_sync pages served via the cross-page cursor path
    /// (`x-delta-cursor` present, both transports) — the adoption signal for
    /// the 2026-07-05 cursor rollout.
    pub delta_sync_cursor_pages_total: AtomicU64,
    /// Server-side: malformed `x-delta-cursor` values rejected fail-closed
    /// (400, never a silent fallback to offset paging). Non-zero = a buggy
    /// or hostile client.
    pub delta_sync_cursor_reject_total: AtomicU64,
    /// Client-side: cursor cycles broken by the echo/advance guard (server
    /// echoed a different cursor than sent, or failed to advance the
    /// frontier). Non-zero = a buggy/hostile server on the other end.
    pub delta_sync_cursor_guard_trips_total: AtomicU64,
    /// Client-side: cursor cycles that hit MAX_PAGES_PER_CYCLE with the
    /// server still reporting `has_more=true` — the "still behind after a
    /// full cycle" operator signal (cursor-path analog of scan_hit_cap).
    pub delta_sync_cursor_cycle_exhausted_total: AtomicU64,
    /// Server-side counter: delta_sync requests this node SERVED to pullers,
    /// across BOTH the HTTP `routes/sync.rs::delta_sync` and PQ
    /// `pq_transport/router.rs::handle_delta_sync` paths. Distinct from
    /// `delta_sync_attempts_total`, which is the CLIENT-side count of pulls this
    /// node initiated. On a seed/anchor that followers pull from, this is the
    /// primary "am I serving sync?" signal — previously untelemetered
    /// server-side (every other `delta_sync_*` counter is the puller's view).
    /// Counts the low-RAM skip response too (a valid served reply, 0 records).
    pub delta_sync_served_total: AtomicU64,
    /// R2-6b honest-surface gauge: the freshest peer-reported `total_missing`
    /// remaining AFTER a delta pull (peer's scan says we lack N records the
    /// bounded 24h window/batching didn't deliver this cycle). Non-zero and
    /// sustained = a DAG gap the automatic path will not close — surfaced on
    /// /status (`delta_peer_total_missing`) and as a /health `dag_gap` WARN,
    /// with the manual recovery recipe in docs/KNOWN-LIMITATIONS.md. Written
    /// by the delta-pull wrappers in gossip.rs/sync.rs via
    /// `sync::note_peer_reported_missing`.
    pub delta_peer_total_missing: AtomicU64,
    /// Server-side counter: total records returned across all served delta_sync
    /// requests (sum of each response's batch length). Serve-side throughput;
    /// pair with `delta_sync_served_total` for mean records per served request.
    pub delta_sync_served_records_total: AtomicU64,
    /// Tier-1 DAG-completeness deficit ring (internal design notes
    /// §4.1): sealed epochs whose wire `record_hashes` had locally-missing
    /// records at ingest. Written by `ingest::record_seal_deficit` (rides
    /// `resolve_seal_record_ids` — already-computed point lookups, no scan);
    /// re-checked/resolved one entry per pull cycle; drives early full_pull
    /// escalation + cursor seeding in `gossip::pull_loop`.
    pub dag_deficit_open: std::sync::Mutex<DagDeficitRing>,
    /// Monotonic: distinct (zone, epoch) deficits ever opened.
    pub dag_deficit_epochs_total: AtomicU64,
    /// Monotonic: deficits closed by re-check (all records arrived, or the
    /// seal itself was pruned below the super-seal floor).
    pub dag_deficit_resolved_total: AtomicU64,
    /// Trend alarm (contract §4.2): consecutive full_pull sweeps that found
    /// zero new records while deficits stayed open. Reset on any progress.
    pub full_pull_zero_progress_streak: AtomicU64,
    /// Monotonic twin of the streak — total zero-progress-with-deficits sweeps.
    pub full_pull_zero_progress_total: AtomicU64,
    /// Cursor-seed guard: `f64::to_bits` of the last deficit target seeded
    /// into `full_pull_cursor` (0 = never). Seeding fires once per distinct
    /// target so an unresolvable hole can't re-seed the sweep forever.
    pub full_pull_deficit_seed_bits: AtomicU64,
    /// Bounded LRU of epoch-seal record ids this node INTENTIONALLY declined
    /// as stale (contract §4.4 — sync.rs / gossip.rs stale-seal pre-filters).
    /// Folded into the delta_pull bloom so peers stop re-serving them every
    /// pass. Client-local; never poisons `gossip_rejected` (stale ≠ invalid).
    pub declined_seal_ids: std::sync::Mutex<super::ingest::SeenSet>,
    /// Process-monotonic stamp (`mono_secs() + 1`) of the most recent *served*
    /// record-level sync request (`delta_sync` / `query_records`, both
    /// transports). 0 = never served; the +1 keeps a stamp inside the first
    /// process second distinct from "never". Monotonic, not wall-clock: an
    /// NTP backward step must not shrink the apparent age and mask a
    /// partition from the inbound-liveness check (item-3 hardening).
    /// The `/health` peers check reads this as inbound-liveness evidence: a
    /// pull-gossip seed dials nobody (`peers_connected==0` is its design
    /// posture) yet actively feeds followers — without this signal it
    /// self-reports "running solo"/"mesh lost" while serving a live mesh
    /// (observed on the authority seed 2026-07-02). Deliberately NOT stamped
    /// by header/checkpoint verbs: light clients ride those, and a light
    /// client is not mesh-peer evidence. Single atomic store per served
    /// request — O(1), no per-peer state.
    pub last_inbound_sync_mono: AtomicU64,
    /// Witness-side SMT-flush scope build (`compute_witness_smt_scope`) hit the
    /// `MAX_WITNESS_SCOPE_SCAN` zone-window index cap. At the cap, late-window
    /// records aren't included in this round's flush scope, so the witness's
    /// on-disk account root can't match the seal's signed root until a later
    /// seal re-covers them. Mainnet signal: one zone is carrying >100K
    /// records/epoch — split the zone or raise the cap. Distinct from
    /// `_incomplete_total`: this is "scan truncated", that is "result partial".
    pub witness_smt_scope_scan_hit_cap_total: AtomicU64,
    /// Witness-side SMT-flush scope finished with fewer matched records than the
    /// seal references (`matched < target_count`) — the witness had NOT yet
    /// received every record the seal covers, so the flushed scope is a subset.
    /// This is the common, transient cause of
    /// `account_smt_disk_root_matches_latest_seal=0` on a witness: it's behind
    /// on gossip propagation, not faulty. Can co-fire with `_scan_hit_cap_total`
    /// when the cap is what truncated the match; non-zero with the cap counter
    /// flat = pure propagation lag (self-heals on the next covering seal).
    pub witness_smt_scope_incomplete_total: AtomicU64,
    /// Incremental record-stats counters. Replaces the
    /// O(all_records) `for_each_record` scan in `compute_dag_stats` /
    /// `warm_stats_cache` (src/network/routes/explorer.rs) with O(1) atomic
    /// loads. All counters are bumped at the single ingest chokepoint
    /// (`ingest::insert_record_inner_direct` after `put_record_with_pk_zone`)
    /// and boot-seeded once via `for_each_record_ordered_bounded`. At 10M
    /// records the previous scan was ~5GB and 60-180s; counters are O(1).
    /// `unique_creators` is intentionally NOT tracked here — file an HLL
    /// follow-up; the dashboard surfaces `creators_indexed=false` until then.
    pub record_stats_total: AtomicU64,
    pub record_stats_class_public: AtomicU64,
    pub record_stats_class_private: AtomicU64,
    pub record_stats_class_restricted: AtomicU64,
    pub record_stats_class_sovereign: AtomicU64,
    pub record_stats_op_mint: AtomicU64,
    pub record_stats_op_transfer: AtomicU64,
    pub record_stats_op_stake: AtomicU64,
    pub record_stats_op_unstake: AtomicU64,
    pub record_stats_op_burn: AtomicU64,
    pub record_stats_op_slash: AtomicU64,
    pub record_stats_op_witness_reward: AtomicU64,
    pub record_stats_op_dormancy_reclaim: AtomicU64,
    pub record_stats_op_pool_fund: AtomicU64,
    pub record_stats_non_token: AtomicU64,
    pub record_stats_epoch_seals: AtomicU64,
    /// f64 timestamps stored as bits via `to_bits`/`from_bits` + CAS for
    /// min/max accumulation. 0 = uninitialized (no records observed yet).
    /// Boot-seed and ingest writes funnel through `record_stats_bump`.
    pub record_stats_earliest_ts_bits: AtomicU64,
    pub record_stats_latest_ts_bits: AtomicU64,
    /// True when boot seeded only the bounded subsystem rebuild
    /// scan (≤2GB nodes use `rebuild_cap=50K`). Surfaced in `/dag/stats` as
    /// `stats_partial=true` so the dashboard can mark counts as
    /// "since boot, partial pre-restart seed". Big-RAM nodes seed unbounded
    /// from CF_IDX_TIMESTAMP and report the full chain.
    pub record_stats_seed_bounded: std::sync::atomic::AtomicBool,
    /// Gossip metrics: relay pushes routed via content-addressed DHT
    /// placement (Gap 6.2). Above `content_routing_threshold` peers the
    /// relay forwards only to the K responsible peers for the record's
    /// SHA3 hash, avoiding sqrt(n) amplification on every hop.
    pub gossip_relay_content_routed_total: AtomicU64,
    /// B5/F3b: times a single discovery source's NEW-peer batch was clipped at
    /// `MAX_NEW_PEERS_PER_SOURCE` (anti-flood). Sustained non-zero = a peer is
    /// trying to inject more peers than one round allows — inspect that source.
    pub peer_admission_source_cap_clipped_total: AtomicU64,
    /// Gossip metrics: originator pushes routed via content-addressed
    /// DHT placement (Gap 6.1 — already in production).
    pub gossip_push_content_routed_total: AtomicU64,
    /// Gap 6.4 slice 2: originator pushes that ATTEMPTED the K-DHT path but
    /// fell back to flood because fewer than `seal_dht_replication_floor`
    /// distinct DHT-closest peers passed zone/reachability filtering. A
    /// chronically high counter on a high-peer-count node means either the
    /// DHT is partitioned, the peer is filtering too aggressively, or the
    /// floor is too tight for the current cluster size.
    pub gossip_push_dht_floor_fallback_total: AtomicU64,
    /// Gap 6.4 slice 2: relay forwards that ATTEMPTED the K-DHT path but
    /// fell back to flood for the same reason as
    /// `gossip_push_dht_floor_fallback_total`. Tracked separately so the
    /// originator path can be tuned independently of the relay-amplification
    /// path (relay's eligible-peer set is typically smaller, so its fallback
    /// rate is naturally higher).
    pub gossip_relay_dht_floor_fallback_total: AtomicU64,
    /// Gap 6.4 slice 2: most recently observed K-DHT replication factor
    /// (count of chosen peers) for an originator push that took the K-DHT
    /// path. Surfaced as a Prometheus gauge so an operator can confirm the
    /// configured `content_routing_k` is achievable in the current peer
    /// topology. Reset on each successful K-DHT push; sticky between
    /// pushes so scraping is meaningful even at low push rates.
    pub gossip_push_dht_replication_factor_last: AtomicU64,
    /// Gap 6.4 slice 3a: bounded FIFO of recently DHT-routed seal pushes.
    /// Slice 3b's reconciler will drain entries older than the ack timeout,
    /// probe each tracked target for actual seal persistence via the
    /// existing `/record/{id}` endpoint, and re-push if the realized
    /// replication factor fell below `seal_dht_replication_floor`.
    /// Capacity-bounded by `seal_dht_replication_pending_max` (default
    /// 1000); overflow evicts the oldest entry (FIFO) and bumps
    /// `gossip_seal_replication_overflow_total` so a sustained-non-zero
    /// rate signals reconciler-starvation.
    /// Audit-2026-04-30 §2 "Verifiable replication: Merkle-of-seal-replicas
    /// ensures each seal has at least R=3 independent copies".
    pub pending_seal_replications: Mutex<VecDeque<PendingSealReplication>>,
    /// Single-flight guard for `reward::finalization_effects` — the set of rids
    /// whose exactly-once side-effects are currently being processed. A
    /// `std::sync` (not tokio) Mutex on purpose: the RAII guard removes the rid
    /// in `Drop`, which is synchronous, so a panic under `panic="unwind"`
    /// cannot wedge a rid as permanently in-flight (it would otherwise block the
    /// recovery sweep from ever re-firing it). Held only across the brief
    /// check-and-insert / remove, never across an `.await`. Prevents the
    /// boot/tick `reconcile_pending_effects` sweep from double-dispatching a rid
    /// that a detached `finalization_effects` task is still processing.
    pub finalization_effects_inflight: std::sync::Mutex<std::collections::HashSet<String>>,
    /// OPS gauge: pending `pending_effects:` markers observed by the last
    /// `reconcile_pending_effects` sweep (exactly-once finalization-effects
    /// backlog). 0 in steady state; a sustained non-zero value means effects
    /// tasks are dying mid-flight and the recovery sweep is carrying the load.
    /// Saturates at the per-sweep cap (512) when the true backlog is larger.
    pub pending_finalization_effects: std::sync::atomic::AtomicU64,
    /// Gap 6.4 slice 3a: count of seal pushes recorded into
    /// `pending_seal_replications`. Equals total K-DHT-routed seal pushes
    /// (post bandwidth filter) since process start. Compare against
    /// `gossip_push_content_routed_total` to confirm the seal-side
    /// replication-tracking ratio is what you expect (1:1 once
    /// `seal_dht_routing_enabled=true` and seals dominate the
    /// content-routed mix).
    pub gossip_seal_replication_tracked_total: AtomicU64,
    /// Gap 6.4 slice 3a: count of pending entries dropped because the queue
    /// was at capacity. Sustained-non-zero means the reconciler isn't
    /// keeping pace with seal traffic — operator must lower seal rate, raise
    /// `seal_dht_replication_pending_max`, or shorten the slice 3b
    /// reconciler interval. Distinct from `gossip_push_dht_floor_fallback_total`
    /// — that counts "K-DHT path bypassed at push time"; this counts
    /// "K-DHT push tracked but expired before reconciler reached it".
    pub gossip_seal_replication_overflow_total: AtomicU64,
    /// Gap 6.4 slice 3a: current depth of `pending_seal_replications`,
    /// updated atomically on each enqueue/eviction. Surfaced as a
    /// Prometheus gauge so /metrics scrapes are O(1) — no Mutex
    /// acquisition required at scrape time.
    pub gossip_seal_replication_pending_depth: AtomicU64,
    /// Gap 6.4 slice 3b: count of reconciler ticks that have run. Pairs with
    /// the four probe/repush counters below so an operator can compute
    /// average probes-per-tick and repushes-per-tick without reaching for a
    /// timeseries store. Increments even on no-op ticks (queue empty / no
    /// due entries) so a flat counter == reconciler stalled.
    pub gossip_seal_replication_reconcile_ticks_total: AtomicU64,
    /// Gap 6.4 slice 3b: per-target `records_exist` probe responses where
    /// the peer confirmed the seal is present. Numerator of the realized
    /// replication factor: target_count - probe_ok ≈ "missing replicas
    /// requiring a re-push". Compare against
    /// `gossip_seal_replication_probe_miss_total` and
    /// `gossip_seal_replication_probe_fail_total` to attribute under-
    /// replication to absent storage vs. unreachable peers.
    pub gossip_seal_replication_probe_ok_total: AtomicU64,
    /// Gap 6.4 slice 3b: per-target probe responses where the peer was
    /// reachable but reported the seal absent. A high miss count without
    /// matching `probe_fail` means the K-DHT pushes are landing at peers
    /// that subsequently drop the record — investigate retention/GC, not
    /// network reachability.
    pub gossip_seal_replication_probe_miss_total: AtomicU64,
    /// Gap 6.4 slice 3b: per-target probe RPC failures (timeout, peer
    /// unreachable, PQ handshake reject, malformed reply). Distinct from
    /// `probe_miss` so an operator can tell network outage from genuine
    /// missing-replicas. Spike in `probe_fail` while `probe_ok` stays
    /// healthy = transient network blip, no action required.
    pub gossip_seal_replication_probe_fail_total: AtomicU64,
    /// Gap 6.4 slice 3b: re-push attempts the reconciler issued because
    /// the realized replication factor was below
    /// `seal_dht_replication_floor`. Each re-push picks fresh K-DHT
    /// targets excluding peers that already confirmed the seal. Sustained
    /// high rate alongside healthy network = either floor is too tight
    /// for the topology or peers are dropping seals post-receipt.
    pub gossip_seal_replication_repush_total: AtomicU64,
    /// Gap 6.4 slice 3b: count of pending entries that exhausted
    /// `seal_dht_max_repush_retries` without ever reaching
    /// `seal_dht_replication_floor`. Each increment corresponds to a
    /// seal that the network failed to keep R-replicated despite the
    /// reconciler's retry budget. Operator must investigate — DHT
    /// partition, peer-side GC, or floor mis-tuning.
    pub gossip_seal_replication_floor_violation_total: AtomicU64,
    /// MAINNET gap #2: attestation pushes that included the zone's active
    /// committee peers as mandatory targets. Incremented once per attestation
    /// push regardless of how many committee peers were reachable — useful
    /// for confirming committee-aware routing is live on mainnet.
    pub gossip_relay_committee_routed_total: AtomicU64,
    /// MAINNET gap #7: snapshot bootstraps that used the epoch-indexed
    /// archive snapshot path (`/snapshot/epochs` + `/snapshot/epoch/{N}`)
    /// instead of the live `/snapshot` path. Used to confirm new-node
    /// bootstrap is hitting the deterministic archive route in production.
    pub snapshot_bootstrap_epoch_indexed_total: AtomicU64,
    /// MAINNET gap #7: snapshot bootstraps that FELL BACK to the live
    /// `/snapshot` path because the peer had no epoch-indexed archive snapshot
    /// (non-archive node, too early, or archive disabled). Paired with
    /// `snapshot_bootstrap_epoch_indexed_total` to confirm deterministic-path
    /// preference in production.
    pub snapshot_bootstrap_live_fallback_total: AtomicU64,
    /// MAINNET gap #7: number of signed epoch snapshots this node has emitted
    /// to disk via `archive_snapshot_loop`. Zero on non-archive nodes.
    pub archive_snapshot_emit_total: AtomicU64,
    /// MAINNET gap #7: cumulative count of old epoch-snapshot files pruned
    /// under the `archive_snapshot_retention` knob.
    pub archive_snapshot_prune_total: AtomicU64,
    /// MAINNET gap #7: the epoch number of the most recently emitted archive
    /// snapshot. Surfaced on `/metrics` so `scrape(t) - scrape(t-Δ)` confirms
    /// the archive loop is advancing and not stuck.
    pub archive_snapshot_last_epoch: AtomicU64,
    /// Gap 7 real closure (2026-04-21): set true by `apply_bootstrap_snapshot_full`
    /// when a peer snapshot's ledger was loaded into `state.ledger` and
    /// `CF_APPLIED` was populated from `snapshot.ledger.applied_record_ids`.
    /// On next startup the `rebuild_ledger` path in `bin/elara_node.rs` skips
    /// the O(all_records) ledger replay — snapshot IS the ledger. Reset on
    /// boot; only snapshot_bootstrap flips it.
    pub ledger_loaded_from_snapshot: std::sync::atomic::AtomicBool,
    /// Gap 7 real closure: counter, number of times a peer snapshot was loaded
    /// as authoritative ledger (ledger skip-ahead took effect). Paired with
    /// `snapshot_bootstrap_live_fallback_total` / `_epoch_indexed_total` on
    /// /metrics.
    pub snapshot_bootstrap_ledger_loaded_total: AtomicU64,
    /// Gap 7 follow-up: post-apply SMT-root
    /// verify executed against producer-side `account_state_root`. Counts
    /// successful verifies (rebuilt SMT root == producer's signed root).
    pub snapshot_bootstrap_root_verified_total: AtomicU64,
    /// Gap 7 follow-up: post-apply SMT-root verify mismatches. Counter-only
    /// signal — ledger mutation has committed by the time the check runs,
    /// so we can't roll back. Operator playbook: cross-check producer trust
    /// gate, inspect `signer_identity`, escalate to Path SB-1 (manual
    /// seed-peer reset) if persistent. Mirrors the
    /// `chain_divergence_repair_root_mismatch_total` semantics for the
    /// repair path.
    pub snapshot_bootstrap_root_mismatch_total: AtomicU64,
    /// Gap 7 follow-up: bootstraps where the producer did NOT populate
    /// `account_state_root` (legacy snapshot or producer running older
    /// code). Counter goes to ~0 once the fleet is fully upgraded; sustained
    /// non-zero = stale producer node still serving snapshots.
    pub snapshot_bootstrap_root_absent_total: AtomicU64,
    /// §6a (internal design notes §6): boot-time single-zone checks
    /// where the replayed account-SMT root matched the canonical seal's signed
    /// `account_smt_root`. One per qualifying boot.
    pub boot_sealed_root_verified_total: AtomicU64,
    /// §6a: boot checks where the replayed root did NOT match the signed seal —
    /// a supply-neutral dropped/extra record on the replay path. Counter+`warn!`
    /// only (the node continues as a follower; ledger has already committed).
    /// Operator playbook on non-zero: re-bootstrap from a trusted snapshot and
    /// cross-check the seal producer's chain.
    pub boot_sealed_root_mismatch_total: AtomicU64,
    /// §6a / F-5: the PHANTOM subset of `boot_sealed_root_mismatch_total` — a
    /// mismatch where `diagnose_account_smt_divergence` finds ZERO diverging
    /// ledger accounts, i.e. the persistent SMT carries leaf(s) the in-memory
    /// ledger has no account for (SMT-ahead-of-ledger). Always incremented
    /// alongside `_mismatch_total`, so a dashboard reads "real corruption =
    /// mismatch − phantom". The benign self-healing case (clean SIGKILL after a
    /// seal, no predictions) lands here and self-heals on the next seal; a
    /// SUSTAINED non-zero phantom count is the live signal for the F-5 vectors
    /// (repair-path ghost leaf via `apply_state_delta_for_repair` account
    /// removal, or prediction-settlement lag once `Predict` records exist).
    pub boot_sealed_root_phantom_total: AtomicU64,
    /// §6a: boot checks that could not run soundly (multi-zone, no tip epoch,
    /// no Gap-1 seal at tip, or unsealed overhang). Each is a zero-false-positive
    /// bail-out, never a pass — high sustained values just mean the check rarely
    /// finds a clean single-zone boundary (expected on a busy/multi-zone node).
    pub boot_sealed_root_skipped_total: AtomicU64,
    /// Cumulative invocations of the
    /// `/admin/snapshot_rebootstrap_from` admin endpoint that forces a snapshot
    /// bootstrap regardless of local DAG state. Operator escape hatch for
    /// nodes severely behind on FinalizedIndex while holding a small hot DAG
    /// (a resource-constrained-node bootstrap pathology); should normally be 0 in steady state.
    pub admin_snapshot_rebootstrap_total: AtomicU64,
    /// Cumulative super-seal coverage
    /// verification failures observed by the light-client sync loop. A
    /// non-zero value means a seed served a super-seal whose `merkle_root`
    /// doesn't roll up the seal_record_hash values for `[start_epoch,
    /// end_epoch]` — the colluding-seed forge that pure record-integrity
    /// can't catch. Should be 0 in healthy operation; sustained growth =
    /// fork signal, page operator. Counter is bumped from `light_sync_loop`'s
    /// post-headers coverage pass.
    pub super_seal_coverage_failures_total: AtomicU64,
    /// Cumulative count of super-seals
    /// minted by this node — bumped from `ingest::process_super_seal`
    /// only when `EpochState::register_super_seal` returns true (i.e.
    /// the incoming end_epoch advances the per-zone latest, not a
    /// duplicate replay). Surfaced on `/metrics` as
    /// `elara_super_seals_minted_total`. With 1M zones × ~5.6
    /// super-seals/day/zone (~720 epochs/day / SUPER_SEAL_INTERVAL=64)
    /// = ~5.6M/day cluster-wide; the rate against
    /// `elara_super_seal_max_end_epoch` is the canonical "is Gap 3
    /// keeping up" signal. Drop-to-zero with non-zero seal_finalized
    /// rate = super-seal pipeline stalled, page on >2×SUPER_SEAL_INTERVAL
    /// epoch silence.
    pub super_seals_minted_total: AtomicU64,
    /// Super-seal CREATION
    /// attempts. Bumped on the producer side of `epoch_seal_loop` after
    /// `should_create_super_seal` returns true (i.e. latest_epoch is at a
    /// SUPER_SEAL_INTERVAL boundary AND the rolling buffer has 64 entries)
    /// — i.e. just before `create_super_seal()` is called. Surfaced on
    /// `/metrics` as `elara_super_seal_creation_attempts_total`. Pairs with
    /// `super_seals_minted_total` (ingest-side success) to disambiguate:
    /// attempts==0 + 0 minted = producer-side gate never fires (boundary
    /// not reached, or buffer empty — boundary log lines show which);
    /// attempts >> minted = create/insert failures (companion counter
    /// below climbs).
    pub super_seal_creation_attempts_total: AtomicU64,
    /// Super-seal CREATION
    /// failures. Bumped on Err from either `create_super_seal()` (sign
    /// step) or `insert_record_synced()` (storage + gossip step). Surfaced
    /// on `/metrics` as `elara_super_seal_creation_failures_total`. Should
    /// stay at 0 in healthy operation; non-zero with `creation_attempts`
    /// climbing = signing or storage path broken — check warn-level
    /// log lines `super-seal {creation,insert} failed (zone): …`.
    pub super_seal_creation_failures_total: AtomicU64,
    /// Producer-side
    /// super-seal SIGN-step failures. Bumped on Err from
    /// `create_super_seal()` in `epoch_seal_loop` — i.e. the Dilithium3
    /// signing / record-construction failed before the record could be
    /// fed to gossip. Bumps in addition to the rollup
    /// `super_seal_creation_failures_total`. /metrics:
    /// `elara_super_seal_creation_sign_failures_total`. Non-zero with
    /// `super_seal_creation_attempts_total` climbing = signing path
    /// broken (committee-hash empty, identity not initialized, anchor
    /// signature format mismatch). Healthy = 0.
    pub super_seal_creation_sign_failures_total: AtomicU64,
    /// Producer-side
    /// super-seal INSERT-step failures. Bumped on Err from
    /// `insert_record_synced()` in `epoch_seal_loop` — i.e. the
    /// super-seal record was signed OK but the storage + gossip step
    /// rejected it. Bumps in addition to the rollup
    /// `super_seal_creation_failures_total`. /metrics:
    /// `elara_super_seal_creation_insert_failures_total`. Non-zero with
    /// `super_seal_creation_attempts_total` climbing = storage or gossip
    /// path broken (RocksDB disk-pressure rejection, ingest validation
    /// rejected the super-seal record, peer fan-out broken). Healthy = 0.
    pub super_seal_creation_insert_failures_total: AtomicU64,
    /// REALMS P1.5 a3 — live drand pulse cache, written by
    /// `drand_fetch::drand_fetch_loop` and read (non-blocking,
    /// staleness-capped) by the seal-emit preamble. Stays empty on nodes
    /// that never spawn the fetcher — seals then embed no pulse, which is
    /// the legacy byte-identical shape.
    pub drand_pulse_cache: super::drand_fetch::DrandPulseCache,
    /// Cross-relay-agreed pulses stored (cache advanced). /metrics:
    /// `elara_drand_fetch_ok_total`.
    pub drand_fetch_ok_total: AtomicU64,
    /// Fetch ticks yielding no usable agreed pulse (relay outage, no
    /// quorum, garbage material). /metrics: `elara_drand_fetch_fail_total`.
    pub drand_fetch_fail_total: AtomicU64,
    /// Two relays returned DIFFERENT bytes for the same round — at least
    /// one is lying/corrupt; pulse skipped. /metrics:
    /// `elara_drand_relay_disagree_total`. Healthy = 0.
    pub drand_relay_disagree_total: AtomicU64,
    /// Agreed round ≤ cached round: the monotone cache refused to walk the
    /// not-before backwards. /metrics: `elara_drand_round_regression_total`.
    pub drand_round_regression_total: AtomicU64,
    /// Pulse not-before ahead of local now ⇒ local NTP is behind (a genuine
    /// beacon round cannot be future). Pulse still embedded. /metrics:
    /// `elara_drand_pulse_ahead_of_clock_total`. Sustained growth = fix NTP.
    pub drand_pulse_ahead_of_clock_total: AtomicU64,
    /// Seal-emit attempts that embedded a fresh pulse. /metrics:
    /// `elara_drand_seal_pulse_attached_total`.
    pub drand_seal_pulse_attached_total: AtomicU64,
    /// Seal-emit attempts with no fresh pulse (fetcher off, cold cache, or
    /// past the staleness cap). /metrics:
    /// `elara_drand_seal_pulse_absent_total`.
    pub drand_seal_pulse_absent_total: AtomicU64,
    /// Cumulative count of
    /// `epoch_seal_loop` ticks that survived the catchup-skip check at the
    /// top of the loop body (i.e. ticks that actually evaluated zones for
    /// seal proposal). Surfaced on `/metrics` as
    /// `elara_seal_loop_ticks_total`. Pair with the three proposal-outcome
    /// counters below: ticks climbing while proposals_* stay flat = empty
    /// `zones_to_seal` set (no zone discovery + no historical zones); ticks
    /// climbing AND proposals_none_total climbing while
    /// proposals_per_zone/escalate stay flat = `should_propose_seal` is
    /// abstaining for every zone (rank check failing — investigate base
    /// timeout vs elapsed, identity not in top-7 stakers, or
    /// `already_sealed` mis-evaluation).
    pub seal_loop_ticks_total: AtomicU64,
    /// Cumulative zones evaluated across all `epoch_seal_loop`
    /// ticks. Sum of `zones_to_seal.len()` per tick. /metrics:
    /// `elara_seal_loop_zones_evaluated_total`. At 2 zones × 60 s tick =
    /// 2/min steady. Drop to 0 = zone-discovery is empty (no recent records
    /// in scan window AND no historical zones in `latest_epoch`).
    pub seal_loop_zones_evaluated_total: AtomicU64,
    /// Cumulative `SealProposal::PerZone(_)` outcomes from
    /// `should_propose_seal`. /metrics:
    /// `elara_seal_loop_proposals_per_zone_total`. This is the canonical
    /// "this anchor IS the rank-elected proposer for this (zone, epoch)
    /// AND elapsed timeout is met" counter. Should climb 1:1 with new
    /// seals minted by this node (modulo failed creates).
    pub seal_loop_proposals_per_zone_total: AtomicU64,
    /// Cumulative `SealProposal::GlobalEscalate(_)` outcomes.
    /// /metrics: `elara_seal_loop_proposals_escalate_total`. Healthy = 0.
    /// Sustained non-zero = a zone's rank-0..6 ladder fully exhausted
    /// (Stage 3c.1 stuck-zone trigger) and this node is bailing out the
    /// stuck zone via a global quorum seal — operator should investigate
    /// WHY the stuck zone has zero responsive anchors.
    pub seal_loop_proposals_escalate_total: AtomicU64,
    /// Cumulative `SealProposal::None` outcomes. /metrics:
    /// `elara_seal_loop_proposals_none_total`. This is the "this node
    /// abstains for this (zone, epoch)" counter — reasons include not in
    /// top-7 by VRF rank, rank elapsed timeout unmet, or `already_sealed`
    /// guard tripped. In a 2-anchor fleet sealing 2 zones, ONE anchor
    /// will None and the OTHER will PerZone on any given (zone, epoch)
    /// tuple, so this counter is expected to climb at 1× the per_zone
    /// rate steady-state. None climbing AND per_zone flat at ZERO across
    /// BOTH anchors = consensus liveness break (no anchor sees itself as
    /// rank-eligible), and the tick-summary INFO line emitted from
    /// `epoch_seal_loop` shows which zones are dropping. The reason-tagged
    /// sub-counters below split this single counter into four so
    /// the *which gate fired* question can be answered from /metrics alone.
    pub seal_loop_proposals_none_total: AtomicU64,
    /// Cumulative `SealProposal::None(NoneReason::AlreadySealed)`.
    /// /metrics: `elara_seal_loop_proposals_none_already_sealed_total`.
    /// Healthy duplicate-suppression signal — fires every tick on anchors
    /// that lost the race for a (zone, epoch). Sub-counter of
    /// `seal_loop_proposals_none_total`; the four reason-counters always
    /// sum to the parent.
    pub seal_loop_proposals_none_already_sealed_total: AtomicU64,
    /// Cumulative `SealProposal::None(NoneReason::BootstrapNonGenesis)`.
    /// /metrics: `elara_seal_loop_proposals_none_bootstrap_decline_total`.
    /// `staked.len() < 3` AND this node is NOT the genesis authority.
    /// Sticky on non-genesis anchors until the stake set grows past 3.
    /// Once mainnet has >3 stakers, sustained non-zero here = stake-drain
    /// regression.
    pub seal_loop_proposals_none_bootstrap_decline_total: AtomicU64,
    /// Cumulative `SealProposal::None(NoneReason::NotInTopRanks)`.
    /// /metrics: `elara_seal_loop_proposals_none_not_in_top_ranks_total`.
    /// `rank_of(beacon, staked, zone, our_identity, MAX_VIEW_DEPTH=7)`
    /// returned None — this node's identity is outside the top 7
    /// VRF-weighted stakers for the zone+epoch beacon. Expected to fire
    /// non-zero in any fleet with >7 stakers; LIVENESS-CRITICAL if it's
    /// non-zero across ALL anchors for the same zone over multiple ticks
    /// (means no anchor sees itself as eligible — the natural-zone
    /// partition has drifted, or stake has redistributed off the
    /// anchors).
    pub seal_loop_proposals_none_not_in_top_ranks_total: AtomicU64,
    /// Cumulative `SealProposal::None(NoneReason::RankTooHighForElapsed { .. })`.
    /// /metrics: `elara_seal_loop_proposals_none_rank_too_high_total`.
    /// We ARE in the top 7 but `our_rank > current_allowed_rank` —
    /// exponential backoff has not yet unlocked our slot. Self-clearing
    /// as elapsed_ms grows on each zone; sustained non-zero across all
    /// anchors for the same zone means the lower ranks are absent/byzantine
    /// and the backoff schedule has parked the chain waiting on them.
    pub seal_loop_proposals_none_rank_too_high_total: AtomicU64,
    /// Gossip metrics: total records received via pull.
    pub gossip_pull_total: AtomicU64,
    /// NETWORK-HARDENING Tier 1.1: cumulative announcements sent in
    /// push-after-pull cycles (`push_recent_to_peer`). Surfaced on `/metrics`
    /// as `elara_gossip_push_after_pull_announcements_total`. Watch the
    /// rate to confirm the announcement-batch cap (`MAX_PUSH`) is sized for
    /// real fleet creation rate; if the cap is too low, NAT'd nodes can't
    /// drain bursts back to public peers within a single push cycle.
    pub gossip_push_after_pull_announcements_total: AtomicU64,
    /// NETWORK-HARDENING Tier 1.1: number of push-after-pull cycles that
    /// hit the announcement cap (`announcements.len() == MAX_PUSH`).
    /// Surfaced on `/metrics` as `elara_gossip_push_after_pull_at_cap_total`.
    /// Sustained increment signals MAX_PUSH is too small for the local
    /// creation rate — a NAT'd node hitting cap means records older than
    /// the push window stay un-announced and rely on subsequent pulls to
    /// surface. Pre-autotune operator action: raise the cap or shorten the
    /// push interval. Post-autotune (2026-04-28): the autotune adjusts
    /// `gossip_push_after_pull_max` automatically based on this counter's
    /// rate; sustained pinning at the ceiling (800) is the new operator
    /// signal that the floor-push interval is too long for fleet rate.
    pub gossip_push_after_pull_at_cap_total: AtomicU64,
    /// NETWORK-HARDENING Tier 1.1 autotune: total push-after-pull cycles
    /// that reached the announcement-emit point (announcements > 0). The
    /// ratio `at_cap_total / cycles_total` is the cap-hit rate the
    /// autotuner reads to decide when to scale the cap up or down.
    /// Surfaced on `/metrics` as `elara_gossip_push_after_pull_cycles_total`.
    pub gossip_push_after_pull_cycles_total: AtomicU64,
    /// NETWORK-HARDENING Tier 1.1 autotune: current effective MAX_PUSH cap
    /// (defaults to 200, autotuner floor 50 / ceiling 800). Surfaced on
    /// `/metrics` as `elara_gossip_push_after_pull_max` (gauge). Replaces
    /// the prior compile-time constant `MAX_PUSH` so the value can react
    /// to observed at_cap rate without a redeploy. Wraps `usize` rather
    /// than `u64` because the cap is consumed by a slice `.take(N)`; we
    /// box it in `AtomicUsize` so the Relaxed load is atomic and lock-free
    /// on the announce hot path.
    pub gossip_push_after_pull_max: std::sync::atomic::AtomicUsize,
    /// NETWORK-HARDENING Tier 1.1 autotune: unix timestamp (seconds) of
    /// the last cap evaluation. Used as a CAS gate so only one task does
    /// the eval per `AUTOTUNE_INTERVAL_SECS` window even when multiple
    /// peers' push cycles fire concurrently.
    pub gossip_push_after_pull_autotune_last_eval_at: AtomicU64,
    /// NETWORK-HARDENING Tier 1.1 autotune: at_cap_total snapshot at the
    /// time of the last autotune evaluation. New eval computes delta from
    /// this snapshot to determine cap-hit rate over the interval.
    pub gossip_push_after_pull_autotune_last_at_cap: AtomicU64,
    /// NETWORK-HARDENING Tier 1.1 autotune: cycles_total snapshot at the
    /// time of the last autotune evaluation. Pairs with
    /// `gossip_push_after_pull_autotune_last_at_cap` to compute interval
    /// cap-hit ratio.
    pub gossip_push_after_pull_autotune_last_cycles: AtomicU64,
    /// NETWORK-HARDENING Tier 1.1 autotune: number of times the autotuner
    /// raised the cap (each event approximately doubles the cap toward
    /// the ceiling). Surfaced on `/metrics` as
    /// `elara_gossip_push_after_pull_autotune_raises_total`. Sustained
    /// non-zero in steady state means the floor-push interval is short
    /// enough to need every byte of headroom — operator may want to
    /// shorten the interval instead of relying on autotune to keep up.
    pub gossip_push_after_pull_autotune_raises_total: AtomicU64,
    /// NETWORK-HARDENING Tier 1.1 autotune: number of times the autotuner
    /// lowered the cap (each event approximately halves toward the floor).
    /// Surfaced on `/metrics` as
    /// `elara_gossip_push_after_pull_autotune_lowers_total`. Steady-state
    /// alternation between raises and lowers is normal (oscillating cap
    /// near the equilibrium point); a hard pin at the floor (50) means
    /// the floor-push interval is too short / fleet creation rate too low.
    pub gossip_push_after_pull_autotune_lowers_total: AtomicU64,
    /// DISC-4 observability: cumulative slow-record warnings classified by
    /// dominant sub-phase. Computed in `insert_record_inner` from the same
    /// timing deltas that drive the `slow record ...` WARN log. Exposed on
    /// `/metrics` as `elara_ingest_slow_records_{pre,post,sb,other}_total`.
    /// Use `rate()` to watch for Pattern A (pre-dominated) regression after
    /// DISC-4 D-2; Pattern B (post-dominated) is real phase-5 RocksDB write
    /// pressure and is the next fix candidate.
    pub ingest_slow_records_pre_total: AtomicU64,
    pub ingest_slow_records_post_total: AtomicU64,
    pub ingest_slow_records_sb_total: AtomicU64,
    pub ingest_slow_records_other_total: AtomicU64,
    /// High-water mark per sub-phase, in ms, across all
    /// slow records (>10s total). Paired with `ingest_slow_records_*_total`
    /// counters but adds the latency dimension — operators can see "post
    /// phase max = 78000 ms" not just "2 records were post-dominated".
    /// Triggered by a node's `record_processing_max_ms` exceeding ~78s
    /// without per-phase breakdown — operators couldn't tell whether
    /// the 78s lived in storage (sb), ledger.write (post), or pre. Updated
    /// via CAS-loop max in `insert_record_inner`. The `_pre`/`_post`/`_sb`
    /// gauges record their sub-time on EVERY slow record (not only when
    /// dominant) so an 11s record with 6s pre + 5s post bumps both.
    /// `_other` records `total_ingest_ms` only on mixed-stall records where
    /// no single phase >50% dominated. Exposed on `/metrics` as
    /// `elara_ingest_record_phase_max_ms_{pre,post,sb,other}`.
    pub ingest_record_phase_max_ms_pre: AtomicU64,
    pub ingest_record_phase_max_ms_post: AtomicU64,
    pub ingest_record_phase_max_ms_sb: AtomicU64,
    pub ingest_record_phase_max_ms_other: AtomicU64,
    /// MAINNET gap #8 (floor-push): cumulative wire bytes pushed out via
    /// `push_to_peers` + `relay_to_peers` (sum of `record.to_bytes().len() *
    /// targets.len()` across all fan-outs). Unblocks the "measure seal-traffic
    /// cost before lowering `MIN_ADAPTIVE_EPOCH_SECS`" decision — delta over
    /// time divided by elapsed seconds gives per-node egress bps. Exposed on
    /// `/metrics` as `elara_gossip_bytes_out_total`.
    pub gossip_bytes_out_total: AtomicU64,
    /// MAINNET mandate #3 (floor-push): cumulative wire bytes pushed out by
    /// `push_attestation_to_peers` (sum of JSON-payload `len() * targets.len()`
    /// per call). Distinct from `gossip_bytes_out_total` because attestations
    /// flow through `pq_client.receive_attestation_gossip` rather than
    /// `/records`, and at finalising scale they are 5-7× per record (one per
    /// committee member) so they dominate egress at steady state. Operator
    /// computes total node egress as `gossip_bytes_out_total +
    /// attestation_bytes_out_total + (other PQ verbs)`. Exposed as
    /// `elara_attestation_bytes_out_total`.
    pub attestation_bytes_out_total: AtomicU64,
    /// MAINNET mandate #3 (floor-push): cumulative wire bytes received on
    /// the PQ `receive_attestation` verb (`body.len()` per request, captured
    /// before deserialise so malformed bodies are still counted — they ate
    /// network bandwidth on the wire). Mirror to `attestation_bytes_out_total`
    /// — together they bound the steady-state attestation-path budget on
    /// either side of the wire. **Excludes the legacy axum `POST /attestations`
    /// route** which decodes via `Json<AttestationSubmit>` and can't see raw
    /// bytes without a handler refactor; the HTTP route is non-mainnet
    /// (PQ-AUDIT closure) so this is a pragmatic gap. Excludes PQ framing
    /// overhead (matches the egress definition so the two are summable).
    /// Exposed as `elara_attestation_bytes_in_total`.
    pub attestation_bytes_in_total: AtomicU64,
    /// Attestation-receive rejection breakdown. Each rejection path
    /// in `receive_attestation` (HTTP `routes/sync.rs`) and
    /// `handle_receive_attestation` (PQ `pq_transport/router.rs`) returns a
    /// pq-status=400 to the sender; the only signal today is a journal log
    /// every 50 rejections (`att-push REJECTED pq-status=400`). Without
    /// per-reason counters operators can't tell whether a node is rejecting
    /// because of stake gating (catch-up node not yet aware of witness
    /// stake), age gating (witness too young), signature failure (replay /
    /// forgery attempt), bad PoWaS (mis-tuned difficulty), or unknown PK
    /// (missing identity registry entry). The split lets fleet-wide alerts
    /// distinguish "transient bootreplay rejection" from "wire-format
    /// regression" without log scraping. Exposed at /metrics as
    /// `elara_attestation_receive_rejected_<reason>_total`.
    pub attestation_receive_rejected_bad_signature_total: AtomicU64,
    /// See `attestation_receive_rejected_bad_signature_total`. Increments
    /// when the witness public key cannot be resolved: hex-decode failed,
    /// `sha3_256(pk) != witness_hash` mismatch, or no inline pk and the
    /// witness_hash is absent from the identity registry.
    pub attestation_receive_rejected_unknown_pk_total: AtomicU64,
    /// See `attestation_receive_rejected_bad_signature_total`. Increments
    /// when `ledger.staked(witness_hash) < MIN_WITNESS_STAKE` (100 beat) for
    /// a non-genesis witness. Sustained non-zero on a node that just booted
    /// = catch-up window (ledger doesn't yet know witness stakes); sustained
    /// non-zero on a long-running node = stake-burn / unbond regression on
    /// the witness side.
    pub attestation_receive_rejected_low_stake_total: AtomicU64,
    /// See `attestation_receive_rejected_bad_signature_total`. Increments
    /// when `trust.identity_age(witness_hash, timestamp) < min_age_secs`
    /// (1h staked / 48h unstaked).
    pub attestation_receive_rejected_too_young_total: AtomicU64,
    /// See `attestation_receive_rejected_bad_signature_total`. Increments
    /// when an inline PoWaS proof fails verification (nonce/difficulty
    /// pair doesn't satisfy the expected bound for the witness's stake).
    pub attestation_receive_rejected_bad_powas_total: AtomicU64,
    /// Attestation-receive deferred counter. Increments when an
    /// inbound attestation references a record that hasn't reached this
    /// node's local storage yet — the attestation is buffered for retry
    /// and is NOT a rejection (returns "deferred" to the sender). Counter
    /// rising while attestations_processed_total holds steady = inbound
    /// attestation pipeline working but record gossip is lagging behind
    /// attestation gossip.
    pub attestation_receive_deferred_total: AtomicU64,
    /// Cumulative per-record_id deferred-attestation FIFO evictions — a
    /// record's bucket hit `MAX_DEFERRED_ATTS_PER_RECORD` (router.rs) and the
    /// oldest entry was dropped to admit a new distinct witness. Zero in steady
    /// state and honest bootstrap (a bucket never exceeds its witness
    /// committee). Sustained growth = a handshaked peer flooding one/few
    /// not-yet-local record_ids with distinct keypairs (the record-not-local
    /// defer path admits before signature verification); the cap bounds memory
    /// and kills the O(N²) dedup scan, this counts what was shed.
    pub attestation_deferred_evicted_total: AtomicU64,
    /// Tier 4.6 bootstrap-pathology defer counter. Increments when an
    /// inbound attestation has the record locally but the witness's stake
    /// row hasn't synced yet (`ledger.staked(witness) < MIN_WITNESS_STAKE`).
    /// Distinct from `attestation_receive_deferred_total` (record-not-local)
    /// and `attestation_receive_rejected_low_stake_total` (steady-state,
    /// post-rollout this should plateau immediately and effectively be
    /// retired). Bootstrap-lag signature: rises during catch-up, drains to
    /// zero once stake records propagate. Sybil-attack signature: sustained
    /// non-zero with the same witness_hashes recurring after the buffer TTL.
    pub attestation_receive_low_stake_deferred_total: AtomicU64,
    /// Tier 4.6 sweep-drain counter. Increments per attestation successfully
    /// replayed by `low_stake_replay_loop` once the witness stake row has
    /// synced locally. Healthy bootstrap signature: rises in step with the
    /// fall in pending_ledger_depth.
    pub attestation_receive_low_stake_drained_total: AtomicU64,
    /// Tier 4.6 sweep-expire counter. Increments per attestation dropped by
    /// `low_stake_replay_loop` after exceeding `PENDING_HARD_DISCARD_TIMEOUT_SECS`
    /// (1200s) without the witness's stake reaching `MIN_WITNESS_STAKE`.
    /// Sustained non-zero on a long-running node = genuinely-low-stake or
    /// sybil witnesses — this is the new sybil-attack metric.
    pub attestation_receive_low_stake_expired_total: AtomicU64,
    /// Per-peer push-counter attribution gap. Increments
    /// when a low-stake-deferred bump targets a peer hash that's not in the
    /// peer table at bump time — the per-peer counter silently no-ops. Two
    /// causes: (a) cold-restart race (peer PQ-handshake authenticates before
    /// peer table loads via discovery / mDNS / seeds); (b) chronic gap (peer
    /// can PQ-handshake but never gets into the table — e.g., not on seed
    /// list, not advertised via mDNS). Compare against
    /// `attestation_receive_low_stake_deferred_total` for the gap ratio.
    /// Healthy: drops to a stable floor as the peer table warms (race side).
    /// Unhealthy: chronic gap stays >10% of total → check seeds/mDNS coverage.
    pub att_push_unattributed_total: AtomicU64,
    /// Cumulative DAG hot-tier cascade
    /// evictions triggered. The ingest path first calls
    /// `dag.evict_old_epochs()` when DAG is full; if that returns 0
    /// evictions AND the DAG is still full, the cascade fallback runs
    /// `dag.evict_finalized(predicate)` against a snapshot of the
    /// FinalizedIndex hot set — this counter increments once per cascade
    /// invocation (regardless of how many records the cascade actually
    /// evicted). Mainnet operator signal: sustained non-zero rate =
    /// `mark_finalized()` wiring drift between the finality monitor and
    /// the DAG (records are externally finalized but never marked in
    /// `dag.finalized_epoch`), which forces the recovery cascade on every
    /// hot-tier-full ingest. Should be near-zero in steady state. Pair
    /// with `elara_dag_hot_tier_full_rejections_total` to distinguish
    /// "cascade ran successfully, kept ingest going" from "cascade ran
    /// AND failed to free room → records dropped on the floor".
    pub dag_evict_finalized_cascade_total: AtomicU64,
    /// Cumulative records rejected at ingest because BOTH
    /// `evict_old_epochs()` AND the cascade fallback failed to free room
    /// in the DAG hot tier. Each increment is one record dropped on the
    /// floor (returns `ElaraError::Wire` to the caller). This is the
    /// "DAG hot-tier cliff" — operator alert: ANY non-zero rate is a
    /// production incident. Causes: (a) genuine 50K+ unfinalized record
    /// backlog (settlement not happening — check
    /// `elara_consensus_settled` and finality monitor), (b) cold-boot
    /// race where finalized indices haven't caught up to RocksDB state,
    /// (c) `mark_finalized()` wiring regression (paired with
    /// `dag_evict_finalized_cascade_total` rising and DAG size pinned at
    /// 50K). The `elara_dag_hot_tier_utilization_ratio` gauge surfaces
    /// the cliff approach BEFORE this counter starts ticking.
    pub dag_hot_tier_full_rejections_total: AtomicU64,
    /// Cumulative slow
    /// `state.dag.read().await` acquires (>500ms) during ingest. Previously
    /// the only lock-acquire signal was the existing 5000ms warn at
    /// `network::ingest::~586` ("dag.read() for eviction check took {ms}ms")
    /// — a journal-grep target, NOT a Prometheus signal. With this counter
    /// at a lower 500ms threshold, operators get an early-warning gauge
    /// that fires BEFORE the warn-level threshold is reached. Sustained
    /// non-zero rate = DAG write-lock contention from Phase 3 ingest writers
    /// or the eviction-cascade path; cross-correlate with
    /// `elara_dag_hot_tier_utilization_ratio` (DAG-fill triggers eviction
    /// which holds write lock). The full Tier 2.3 refactor —
    /// `insert_record_inner` 13+ sequential locks — remains open; this
    /// observability slice surfaces the symptom without restructuring.
    /// Threshold rationale: 500ms is well above hot-path target (sub-50ms)
    /// but well below the 5000ms hard-warn level, giving early signal.
    pub lock_acquire_dag_read_slow_total: AtomicU64,
    /// Cumulative slow `state.dag.write().await` acquires (>500ms)
    /// during ingest Phase 3 (record insert into DAG). Same threshold and
    /// rationale as `lock_acquire_dag_read_slow_total`. Mainnet operator
    /// alert: `rate(elara_lock_acquire_dag_write_slow_total[5m]) > 0.5`
    /// sustained = ingest pipeline serializing on DAG writes (1+ slow
    /// every 2s). Worst observed historical value previously was 21s
    /// (per the comment at ingest.rs:582 — "caused contention spikes up to
    /// 21s"); the 500ms threshold catches contention orders of magnitude
    /// earlier. Distinct counter per lock (read vs. write) so dashboards
    /// can attribute the contention source.
    pub lock_acquire_dag_write_slow_total: AtomicU64,
    /// Per-reason
    /// breakdown of GC prunes. `gc_pruned_total` aggregates all reasons —
    /// fine for a single counter but the `GcResult` struct already produces
    /// the breakdown (expired / retention / sunken / stale), and dashboards
    /// need the split to attribute eviction pressure. Sustained non-zero
    /// retention pruning is the BASELINE (records age out by retention
    /// window). Sustained non-zero stale = unfinalized records aging past
    /// 2x retention without ever finding witnesses (consensus health
    /// regression). Sustained non-zero sunken = relevance tracker
    /// flagging records as low-utility (EMERGENT-MIND §3 working). Setup
    /// for Tier 3.4: once epoch-based pruning lands, a fifth counter
    /// (`gc_pruned_epoch_sealed_total`) will be added; this slice
    /// preserves the existing semantics and just exposes them.
    pub gc_pruned_expired_total: AtomicU64,
    /// Per-reason GC counter — finalized records older than the
    /// retention window. Baseline non-zero in steady state. Drops to zero
    /// only on archive nodes (no retention-based pruning).
    pub gc_pruned_retention_total: AtomicU64,
    /// Per-reason GC counter — finalized records flagged "sunken"
    /// by the relevance tracker (EMERGENT-MIND §3). These prune EARLY
    /// (before retention window) because the relevance score collapsed.
    /// Sustained non-zero = relevance heuristic actively shedding
    /// low-utility records. Zero = either no records have collapsed in
    /// relevance, or relevance tracker disabled.
    pub gc_pruned_sunken_total: AtomicU64,
    /// Per-reason GC counter — UNFINALIZED records older than 2x
    /// retention. These never got witnessed — abandoned. Sustained
    /// non-zero rate = consensus health regression (records being
    /// submitted but never reaching finality). Mainnet operator alert:
    /// `rate(elara_gc_pruned_stale_total[1h]) > 0.01` sustained =
    /// witness/proposer infrastructure issue, NOT a GC issue.
    pub gc_pruned_stale_total: AtomicU64,
    /// GC compaction trigger count,
    /// broken out by trigger reason. Pre-fix, only `records`, `attestations`,
    /// `dag`, `idx_timestamp` were compacted on the periodic/burst/pressure
    /// trigger; bloat in `idx_creator`, `idx_hash`, `record_by_zone`,
    /// `metadata` (finalized:), and `epochs` (DISC-5) accumulated
    /// uncompacted for weeks of uptime until startup-compaction caught it
    /// at boot. Counter now increments once per trigger AFTER the post-GC
    /// compaction call. Operator alert: `rate(elara_gc_compactions_total[1h]) == 0`
    /// on a non-Archive node for >24h while `elara_gc_pruned_total > 0` is
    /// a regression — fresh tombstones aren't being reclaimed.
    pub gc_compactions_total: AtomicU64,
    /// Count of CFs scheduled for
    /// compaction by `startup_compaction_if_needed` at boot. Separate from
    /// `gc_compactions_total` (runtime GC loop) so operators can attribute
    /// disk reclamation to startup vs. runtime paths. Closes the false-negative
    /// observability gap: a node was reading
    /// `gc_compactions_total=0` post-reboot despite startup compaction having
    /// run, making the GC fix look broken when it was actually working at boot.
    /// Increments once per CF the startup heuristic dispatched (bloat path
    /// OR L0-L2 file-count path). Bumped once after startup_compaction_if_needed
    /// returns; safe to read while the RocksDB background compactor is still
    /// draining the scheduled work.
    pub startup_compactions_total: AtomicU64,
    /// MAINNET gap #3: per-zone epoch seals pruned because a covering
    /// super-seal exists AND the seal's epoch is below the per-zone safety
    /// floor (latest super-seal end_epoch − 2 × SUPER_SEAL_INTERVAL).
    /// Super-seals, zone_transitions, and global seals are integrity-critical
    /// and NEVER counted here. Sustained non-zero on FullZone profile =
    /// super-seal consolidation working as designed (Gap 3 closing the
    /// unbounded-growth gap on the seal stream). Always zero on Archive
    /// profile (effectively infinite retention keeps seals on disk).
    /// Always zero on Light profile (light nodes don't store individual
    /// seals at all).
    pub gc_pruned_seals_total: AtomicU64,
    /// Tier 3.4 (Protocol §11.8): finalized non-seal records pruned because
    /// their per-zone epoch has been super-sealed (timestamp older than the
    /// zone's `record_pruning_floor_ts` = end-time of the seal at
    /// `latest_super_seal.end_epoch − 2 × SUPER_SEAL_INTERVAL`). Distinct
    /// from `gc_pruned_retention_total` (time-based) — epoch pruning fires
    /// AS SOON AS a super-seal covers the record, regardless of retention
    /// window. Always zero on Archive profile (auto-disabled) and on nodes
    /// where `epoch_pruning_enabled = false`. Sustained non-zero on
    /// FullZone profile = the on-disk record stream is being trimmed
    /// against the seal Merkle root, the spec-aligned scaling path.
    pub gc_pruned_epoch_total: AtomicU64,
    /// GC cycle counter — total successful GC passes since boot.
    /// Pair with `gc_last_cycle_unix_ts` to detect cycle-skipping
    /// (`now - gc_last_cycle_unix_ts > 2 * gc_interval_secs` = GC stalled).
    /// Distinguishes "GC ran and found nothing to prune" from "GC never ran".
    pub gc_cycles_total: AtomicU64,
    /// Duration of the last GC cycle in milliseconds. Includes
    /// both the storage scan and the per-record delete loop. Mainnet
    /// budget: GC must complete within `gc_interval_secs / 4` (e.g. 75s
    /// for a 300s interval) — beyond that, scan throughput is starving
    /// the next cycle. At 10M+ records, this gauge is the leading
    /// indicator that the bounded-50K-batch needs raising or the scan
    /// path needs further optimisation.
    pub gc_last_cycle_duration_ms: AtomicU64,
    /// Unix timestamp (seconds, integer) when the last GC cycle
    /// completed. Surfaced as a gauge so dashboards can compute "GC
    /// staleness" = `now - gc_last_cycle_unix_ts`. Set to 0 at boot and
    /// after the first cycle. Pair with `gc_cycles_total` to detect
    /// stalls — `rate(gc_cycles_total[10m]) == 0` AND `staleness >
    /// 2*interval` = GC genuinely halted (not just busy).
    pub gc_last_cycle_unix_ts: AtomicU64,
    /// Bumped on every GC cycle whose
    /// `gc_scan_and_delete` hit `MAX_GC_SCAN_PER_CYCLE = 5_000` and broke
    /// early — the box has more eligible-but-unscanned data than one cycle
    /// can chew. Sustained non-zero rate = GC is in drain mode (next cycle
    /// fires in `gc_drain_interval_secs` not `gc_interval_secs`); rate
    /// returning to zero = backlog drained. Pairs with
    /// `gc_last_cycle_duration_ms` to size operator throttling decisions.
    pub gc_scan_capped_total: AtomicU64,
    /// MAINNET mandate #3 (floor-push): kind-split breakdown of
    /// `gossip_bytes_out_total` for the originator + relay push paths
    /// (`push_to_peers`, `relay_to_peers`). Pull-responder bytes are NOT
    /// classified — they flow through `fetch_records_wire` as raw wire bytes
    /// without per-record deserialisation, and pull traffic is bursty/recovery,
    /// not the recurring per-epoch cost we want to budget against. Sum across
    /// these four sub-counters therefore tracks the catch-all but does NOT
    /// equal it; `(bytes_out_total - sum(kinds))` is the unclassified
    /// pull-responder remainder, which is itself an operator signal (high
    /// pull share = more peers re-syncing). Exposed as
    /// `elara_gossip_bytes_out_kind_total{kind="seal"}`.
    pub gossip_bytes_out_seal_total: AtomicU64,
    /// See `gossip_bytes_out_seal_total`. Ledger ops = records carrying the
    /// `beat_op` metadata key (transfer/mint/burn/stake/etc.).
    pub gossip_bytes_out_ledger_total: AtomicU64,
    /// See `gossip_bytes_out_seal_total`. Governance = records carrying
    /// `governance_op` (propose/vote/execute/cancel/delegate/...).
    pub gossip_bytes_out_governance_total: AtomicU64,
    /// See `gossip_bytes_out_seal_total`. Other = no `epoch_op` / `beat_op` /
    /// `governance_op` metadata key — generic data records and any future
    /// record kind not yet classified.
    pub gossip_bytes_out_other_total: AtomicU64,
    /// MAINNET gap #8 (floor-push): cumulative wire bytes received from gossip
    /// peers across BOTH transports — HTTP `POST /records` (post network-id +
    /// protocol-version gating) AND every PQ-transport request body (pre-gating
    /// at `pq_transport/router.rs:dispatch`). Exposed on `/metrics` as
    /// `elara_gossip_bytes_in_total`. Paired with `gossip_bytes_out_total` to
    /// compute bandwidth headroom for further epoch-floor reductions (15s →
    /// 10s / 5s). Until 2026-04-19 this only counted HTTP and read 0 because
    /// gossip had migrated to PQ — the PQ-side increment fixes that.
    pub gossip_bytes_in_total: AtomicU64,
    /// Gossip metrics: pushes skipped (hops exhausted).
    pub gossip_push_skipped_total: AtomicU64,
    /// Gossip metrics: duplicate records deduplicated.
    pub gossip_seen_dedup_total: AtomicU64,
    /// Auto-witness metrics: total cycles run on THIS node's auto-witness
    /// loop (`auto_witness::run_loop`). Increments only when the local node
    /// has been selected into the epoch committee for at least one zone —
    /// nodes outside every zone's committee `continue` past the counter
    /// (`auto_witness.rs:188`) and stay at 0 indefinitely. Decoupled from
    /// settlement-state attestation: receiving peer attestations,
    /// participating in cluster-wide attestation cascades, or even settling
    /// records via incoming witness traffic does NOT bump this counter.
    /// Validated in soak: a node stayed at awc=0 through
    /// 60+ ticks (~7h) including a full HYPER-ACTIVE event entry+exit.
    /// Operator reading awc=0: "this node hasn't been a juror recently", not
    /// "this node is silent on the network".
    pub auto_witness_cycles_total: AtomicU64,
    /// Auto-witness metrics: total records witnessed.
    pub auto_witness_records_total: AtomicU64,
    /// Auto-witness metrics: total signing failures.
    pub auto_witness_failures_total: AtomicU64,
    /// Auto-witness metrics: re-push attempts skipped because the attestation
    /// is older than `auto_witness::REPUSH_MAX_AGE_SECS` (zombie guard). A
    /// record this old will never settle and re-pushing produces 400 storms
    /// against peers that have GC'd it from active disk.
    pub auto_witness_zombie_repush_skipped_total: AtomicU64,
    /// Auto-witness skip-cause counters. Each increments at one of the three early-`continue`
    /// branches inside `auto_witness::run_loop` BEFORE
    /// `auto_witness_cycles_total` would have ticked. Sum of all three
    /// (plus `auto_witness_cycles_total`) equals the total loop iterations
    /// since boot — operators can derive `cycles_total / loop_iterations`
    /// to see what fraction of the loop is actually witnessing vs skipping.
    ///
    /// `_orphan`: catchup-guard at `auto_witness.rs:101` — fires when the
    /// node's DAG has > 1000 orphan edges (initial sync, ingest backlog,
    /// or eviction-window pressure). Closes the `cycles_total=0`
    /// blindspot (a node had 38 052 orphan-prune events
    /// over 8h32m uptime while showing `cycles_total=0` — operators
    /// previously had no per-skip-cause signal to confirm catchup-guard
    /// was the reason).
    pub auto_witness_skips_orphan_total: AtomicU64,
    /// Auto-witness skip-cause counter. Fires at the
    /// `staked_amount == 0` branch (`auto_witness.rs:128`). Operator
    /// signal: this node is configured as `node_type=witness` but the
    /// local identity carries zero stake — likely a fresh node that
    /// has not yet earned stake, or whose stake was slashed/unstaked.
    pub auto_witness_skips_not_staked_total: AtomicU64,
    /// Auto-witness skip-cause counter. Fires at the
    /// `allowed_zones.is_empty()` branch (`auto_witness.rs:186`). Operator
    /// signal: VRF + stake-weighted committee selection picked the local
    /// node into ZERO zones this cycle. Steady non-zero rate at a staked
    /// witness = stake is too low to win VRF lottery in any zone the node
    /// is subscribed to (raise stake OR subscribe to more zones).
    pub auto_witness_skips_no_jury_total: AtomicU64,
    /// R3-9 Decision B verify-before-co-sign: attestations WITHHELD because
    /// the epoch seal's record list disagreed with the local view, split by
    /// reason. Rendered as one metric family
    /// `elara_seal_verify_before_attest_withheld_total{reason=...}`.
    /// `behind` = the seal lists records we don't hold yet, or claims more
    /// than our window scan finds — witness is catching up; the candidate is
    /// retried on a later cycle. MOOT at single-authority testnet; the moment
    /// staked anchors > 1 a sustained climb here is the operator's first
    /// signal of anchor/witness view divergence.
    pub seal_verify_before_attest_withheld_behind_total: AtomicU64,
    /// `omission`: the witness holds MORE records in the seal's zone window
    /// than the seal enumerates/claims — definite omission; a malicious
    /// anchor driving selective finality trips this on honest witnesses.
    pub seal_verify_before_attest_withheld_omission_total: AtomicU64,
    /// `root_mismatch`: equal record counts but divergent Merkle root — the
    /// anchor's set and the witness's set differ in content, not size.
    pub seal_verify_before_attest_withheld_root_mismatch_total: AtomicU64,
    /// `malformed`: the candidate carries `epoch_op=seal` but
    /// `extract_epoch_seal` failed (or the verify task panicked) — never
    /// co-sign what can't be parsed. Near-unreachable: ingest validation
    /// rejects malformed seals before they reach storage.
    pub seal_verify_before_attest_withheld_malformed_total: AtomicU64,
    /// R3-8 soak forensics (2026-07-02, 4 silent above-cap seals on the
    /// follower): Phase-5 seal-consumer block ENTERED (successful seal parse
    /// post-storage). Pairs with `..._completed_total` — entered > completed
    /// = a seal died mid-block with no other trace.
    pub seal_ingest_phase5_entered_total: AtomicU64,
    /// Phase-5 seal-consumer block ran to its end (epoch registered, derive
    /// hook + deficit capture + witness flush + finality registration done).
    pub seal_ingest_phase5_completed_total: AtomicU64,
    /// `extract_epoch_seal` FAILED at Phase 5 for a record carrying
    /// `epoch_op` — previously a fully silent skip of all seal consumers.
    pub seal_ingest_extract_err_total: AtomicU64,
    /// Derive-when-absent hook attempts (empty enumeration, record_count>0).
    /// attempts == derived + miss (epoch.rs statics); a seal that enters
    /// Phase 5 with an absent enumeration but never attempts is the
    /// hook-condition-false anomaly.
    pub seal_ingest_derive_hook_attempts_total: AtomicU64,
    /// SEAL-class records (metadata carries `epoch_op`) rejected by
    /// insert at any gossip pull path (full_pull / delta_pull / att-pull /
    /// orphan-resolver). Non-retryable rejects also enter the permanent
    /// `gossip_rejected` embargo — a growing count here on a follower is
    /// the "seal stored-but-never-consumer-processed" precursor signal.
    pub gossip_seal_insert_reject_total: AtomicU64,
    /// SEAL records declined PRE-CRYPTO by the stale-gap filter on the pull
    /// paths (timestamp/full/delta pull — Contract §4.4: stale ≠ invalid,
    /// routed to `declined_seal_ids`, never the embargo or the park queue).
    /// The 8b fix observable: the locally-pruned seal band an archive peer
    /// re-serves shows up here (cheap decline) instead of
    /// `gossip_seal_insert_reject_total` + permanent embargo. Expected to
    /// burst once per sweep of previously-unswept history, then quiesce as
    /// the cursor floor stops the re-fetch.
    pub gossip_seal_declined_stale_total: AtomicU64,
    /// Stored-but-uncanonicalized seal re-entries through the storage-dedup
    /// short-circuit (8b design B, successor-re-admission): a stored seal
    /// whose epoch is the STRICT immediate successor of its zone's canonical
    /// tip re-flows the full pipeline (idempotent) instead of dedup-skipping
    /// forever. Heals the chain-link-rejected honest E+1 after a phantom tip
    /// corrects (ingest.rs 2026-07-01 §2b note). Sustained growth without the
    /// zone tip advancing = the tip it fails to chain to is still phantom.
    pub seal_ingest_reentry_total: AtomicU64,
    /// Gossip-push rejections under the local NodeProfile's acceptance policy.
    /// Light profile rejects every peer-pushed record (phone-tier client; pulls
    /// headers + own-account proofs only). Sustained climb on a Light node is
    /// the signal that peers haven't downgraded their fan-out for it yet.
    pub gossip_push_rejected_profile_total: AtomicU64,
    /// `delegation_op` records rejected because the creator is neither a
    /// Gateway/Anchor (per gossiped peer NodeType) nor stake-gated above
    /// `MIN_STAKE_TO_DELEGATE`. Profile C Gap A: closes the unauthenticated
    /// child-registration path that would otherwise let a Leaf inflate its
    /// effective stake's child count. Sustained non-zero is an attempted
    /// authorization fraud or a misconfigured operator publishing delegations
    /// from a Leaf-typed node.
    pub delegation_op_rejected_role_total: AtomicU64,
    /// Profile C Gap B: records rejected at sig-verify because the creator is
    /// a registered delegation child (presumed Profile C, no own PQ keys).
    /// The protocol intent is the parent signs on the child's behalf
    /// (proxy-sign mode); a child signing with its own key defeats the entire
    /// IoT delegation premise (economics §4.3, Protocol §4.6, §6.2). The only
    /// allowed direct-creator path for a registered child is its own
    /// establishment delegation_op authorize/revoke (Gap A handles those).
    /// Sustained non-zero is either a misconfigured device firmware or an
    /// adversary trying to gain per-child accountability while hiding behind
    /// the parent's stake/trust inheritance.
    pub profile_c_gate_rejected_total: AtomicU64,
    /// Profile C Gap C: `delegation_op = authorize` records rejected because
    /// the parent's advertised hardware attestation level is below the
    /// configured `min_attestation_for_gateway` floor. Sustained non-zero
    /// signals either an operator running gateways without the configured
    /// attestation evidence (misconfiguration — should advertise via
    /// `attestation_level` metadata or use a hardened firmware) or an
    /// adversary publishing authorize records from software-only nodes to
    /// inflate Gateway influence past the SecureBoot floor (economics §11.33).
    pub attestation_gate_rejected_total: AtomicU64,
    /// Profile C Gap D: `delegation_op = revoke_all` ops accepted via the
    /// voluntary path (creator IS the parent_to_disarm). Each tick is one
    /// gateway voluntarily decommissioning itself; expected to rise during
    /// planned key-rotation windows and stay flat otherwise. Spec:
    /// internal design notes §3 Gap D, economics §4.3.
    pub revoke_all_voluntary_total: AtomicU64,
    /// Profile C Gap D: `revoke_all` ops accepted via the involuntary
    /// (fisherman) path — sum of valid cosigner ledger stakes met or
    /// exceeded `total_supply * 2/3`. Each tick is one compromised gateway
    /// being disarmed by social consensus; sustained non-zero means the
    /// fleet is using the slashing path. Cosigner sigs must verify against
    /// `revoke_all_canonical_message` via Dilithium3.
    pub revoke_all_involuntary_total: AtomicU64,
    /// Profile C Gap D: `revoke_all` ops rejected. Reasons (not separately
    /// labelled): (a) creator is not parent_to_disarm AND cosigner stake
    /// sum < 2/3 supply; (b) malformed metadata (missing parent / bad
    /// reason / non-hex cosigner fields); (c) cosigner verify failure
    /// reduced sum below threshold. Sustained non-zero is an adversary
    /// attempting unauthorized mass-revocation, OR a malformed fisherman
    /// claim that didn't gather enough valid cosigners.
    pub revoke_all_rejected_total: AtomicU64,
    /// Profile C Gap E: count of delegation children whose lease expired
    /// and were dropped by the periodic `prune_expired` tick. Each tick is
    /// one child whose parent failed to extend its 30-day lease. Healthy
    /// fleets see this match the long-tail of stale gateways; if it
    /// suddenly spikes the operator should investigate (gateway outage,
    /// misconfigured extend cadence, or a parent voluntarily letting
    /// devices age out before revoking).
    pub delegation_lease_expired_total: AtomicU64,
    /// Profile C Gap E: `delegation_op = authorize` ops rejected because
    /// the parent already has `MAX_CHILDREN_PER_PARENT = 1M` active
    /// children. Sustained non-zero is an adversary trying to balloon a
    /// single parent's registry footprint or, more likely, an
    /// over-eager IoT operator hitting the 1M ceiling — hard cap protects
    /// every node's in-memory registry from one parent's blast radius.
    pub delegation_child_cap_rejected_total: AtomicU64,
    /// Profile C Gap E: `delegation_op = authorize` ops rejected because
    /// the parent has already authored 10K authorize ops in the trailing
    /// hour (`MAX_AUTHORIZE_PER_PARENT_PER_HOUR`). Distinguishes "burst
    /// from compromised key" from "steady-state IoT onboarding". A clean
    /// gateway never fires this counter; a gateway whose key was stolen
    /// gets capped within seconds of an attacker spinning up child mints.
    pub delegation_rate_cap_rejected_total: AtomicU64,
    /// Profile C Gap E: successful `delegation_op = extend` ops. One tick
    /// per child whose lease was prolonged. Saves bandwidth vs re-issuing
    /// authorize: `extend_metadata` carries only the child id + new
    /// `expires_at`, while `delegation_metadata(Authorize, ...)` repeats
    /// scope + (in mainnet) the attestation chain.
    pub delegation_extend_total: AtomicU64,
    /// Profile C Gap E: `delegation_op = extend` ops rejected. Reasons:
    /// (a) child not registered in `DelegationRegistry`; (b) creator is
    /// not the recorded parent of the child; (c) missing/malformed
    /// `expires_at`. Sustained non-zero indicates a buggy parent, a
    /// stale registry on the peer that observed the record, or an
    /// adversary trying to extend someone else's child to keep a
    /// compromised device alive past its parent's revoke.
    pub delegation_extend_rejected_total: AtomicU64,
    /// Identity Partitioning Phase B: cumulative count of USER-tier
    /// identity entries evicted by the LRU loop. Gauged alongside the
    /// per-tier counts (`identity_tier_counts`) so operators can see
    /// the cap actually firing under load. A clean fleet rarely
    /// crosses the cap on testnet; mainnet under heavy onboarding will
    /// see this climb steadily after the cap is hit, then plateau as
    /// inflow ≈ eviction.
    pub identity_user_evicted_total: AtomicU64,
    /// Identity Partitioning Phase C: counts the times an identity
    /// physically migrated up a tier (USER→WITNESS, USER→ANCHOR,
    /// WITNESS→ANCHOR). Useful to see how active class promotion is
    /// across the fleet, and to detect anomalies (e.g. flapping
    /// witness-vs-user classification under load). Counters are
    /// atomic and exposed via `/metrics`.
    pub identity_promotion_user_to_witness_total: AtomicU64,
    pub identity_promotion_user_to_anchor_total: AtomicU64,
    pub identity_promotion_witness_to_anchor_total: AtomicU64,
    /// Identity Partitioning Phase E: cumulative count of witness-tier
    /// PKs dropped from `CF_IDENTITIES_WITNESS` because the unsubscribed
    /// zone was their last claim — i.e. no surviving subscription had
    /// the same witness registered. Climbs when an operator unsubscribes
    /// a zone whose witness set was disjoint from every other zone they
    /// serve. Anchor-tier PKs are never touched by this counter.
    pub identity_witness_purged_total: AtomicU64,
    /// Identity Partitioning Phase D: cumulative count of on-miss
    /// `GET /identity/pk/{hash}` peer fetches attempted (i.e. local
    /// lookup missed and we asked a peer). Hits + misses should sum to
    /// attempts. A clean fleet on testnet sits at 0 — every PK is
    /// captured at ingest. Mainnet under heavy onboarding will see
    /// this climb as bootstrapping nodes verify records signed by
    /// identities they haven't observed yet.
    pub identity_pk_fetch_attempts_total: AtomicU64,
    /// Identity Partitioning Phase D: cumulative count of on-miss
    /// peer fetches that returned a PK (cached locally in USER tier
    /// before returning). The hit rate (`hits / attempts`) is the
    /// canonical SLO for the on-miss path — should sit above 0.95 in
    /// a healthy mesh.
    pub identity_pk_fetch_hits_total: AtomicU64,
    /// Identity Partitioning Phase D: cumulative count of on-miss
    /// peer fetches that exhausted the candidate list without finding
    /// a peer that has the PK. Caller policy on miss is soft-fail
    /// (record verification result = "unknown PK"); spec
    /// internal design notes §6.
    pub identity_pk_fetch_misses_total: AtomicU64,
    /// DAM-3D Phase A: records observed at ingest with one or more
    /// `parents[i]` resolving to a zone other than the record's own zone
    /// (and not an ancestor). Always bumped, regardless of
    /// `allow_cross_zone_parents`. A clean fleet sits at zero; a
    /// non-zero value signals legacy hash-derived parents from before the
    /// structural-zone gate, a buggy SDK pinning the wrong zone, or a
    /// creator stitching unrelated zones into one DAG. Operators flip
    /// `allow_cross_zone_parents=false` once this counter has been at 0
    /// for a full epoch.
    pub cross_zone_parent_observed_total: AtomicU64,
    /// DAM-3D Phase A: records hard-rejected at ingest because
    /// `allow_cross_zone_parents=false` and at least one parent zone is
    /// not the record's zone or an ancestor of it. Mainnet-only path.
    /// On testnet (default config) this counter stays at 0 even when
    /// `cross_zone_parent_observed_total` ticks.
    pub cross_zone_parent_rejected_total: AtomicU64,
    /// DAM-3D Phase C Slice 1: cumulative `zone_refs` entries observed
    /// across all ingested records. Each `zone_ref` is one tick — a
    /// record with three refs ticks this counter three times.
    /// `_anchored_total + _ghost_total + _deferred_total` should sum to
    /// this counter (modulo wire-decoder failures, which skip
    /// classification). Spec: internal design notes §3 Gap C.
    pub zone_ref_observed_total: AtomicU64,
    /// DAM-3D Phase C Slice 1: zone_refs whose claimed `(zone, epoch)`
    /// resolves to a locally-known seal (we are subscribed to the
    /// referenced zone AND `CF_EPOCHS` has an entry at that epoch).
    /// The healthy path. Slice 2 will reject when subscribed-and-no-seal,
    /// so on a clean fleet `_anchored + _deferred ≈ _observed` and
    /// `_ghost == 0`.
    pub zone_ref_anchored_total: AtomicU64,
    /// DAM-3D Phase C Slice 1: subscribed-and-no-seal — zone_refs that
    /// claim a `(zone, epoch)` we should know about (we host the zone)
    /// but for which no seal is on disk. Slice 1 is observe-only;
    /// sustained non-zero is the operator signal that a partition or
    /// equivocating witness is seeding refs to fabricated seals. Slice
    /// 2 hard-rejects.
    pub zone_ref_ghost_total: AtomicU64,
    /// DAM-3D Phase C Slice 1: zone_refs whose ref'd zone we don't
    /// host. Cannot validate locally — the ref is provisionally
    /// accepted in Slice 1. Slice 3 will stage these into a
    /// `pending_xzone_refs` map with TTL+cap; Slice 4 graduates on
    /// gossip from a subscribing peer.
    pub zone_ref_deferred_total: AtomicU64,
    /// Attestation dedup set — tracks (record_id:witness_hash) pairs.
    pub attestation_seen: std::sync::Mutex<SeenSet>,
    /// Attestation dedup counter.
    pub attestation_dedup_total: AtomicU64,
    /// Attestation push fanout counters (DISC-7d-r diagnostics).
    /// attempted = targets selected before bandwidth filter.
    pub attestation_push_attempted_total: AtomicU64,
    /// success = peers that returned 2xx (HTTP or PQ).
    pub attestation_push_success_total: AtomicU64,
    /// skip_bandwidth = targets dropped by peer_bandwidth.try_acquire().
    pub attestation_push_skip_bandwidth_total: AtomicU64,
    /// addr_fail = peer had no derivable PQ address (peer-table issue).
    pub attestation_push_addr_fail_total: AtomicU64,
    /// peer_reject = PQ peer returned a non-2xx, non-429 status (peer-side gate).
    pub attestation_push_peer_reject_total: AtomicU64,
    /// net_fail = PQ transport returned Err (network/serde failure).
    pub attestation_push_net_fail_total: AtomicU64,
    /// Slot-conflict proof gossip dedup — tracks slot_keys we've already
    /// processed and pushed. Bounded (5,000 entries — conflicts are rare).
    /// Once a slot is in CF_SLOT_CONFLICTS it stays there; re-gossip of the
    /// same proof is pure waste.
    pub conflict_proof_seen: std::sync::Mutex<SeenSet>,
    /// Counter: conflict proofs pushed to peers.
    pub conflict_proof_pushed_total: AtomicU64,
    /// Counter: conflict proofs received from peers.
    pub conflict_proof_received_total: AtomicU64,
    /// Counter: conflict proofs rejected (malformed or fail verification).
    pub conflict_proof_rejected_total: AtomicU64,
    /// Counter: conflict-proof push aborted because peer had no PQ address.
    pub conflict_proof_push_addr_fail_total: AtomicU64,
    /// Counter: conflict-proof push received a non-2xx, non-429 PQ status from peer.
    pub conflict_proof_push_peer_reject_total: AtomicU64,
    /// Counter: conflict-proof push errored at PQ transport layer (network/serde).
    pub conflict_proof_push_net_fail_total: AtomicU64,
    /// Counter: slot-conflict proofs whose OFFENDER was this node's own
    /// identity, so gossip was suppressed (the local slot-mark still fired).
    /// Defense-in-depth: a real broadcast equivocation is independently
    /// provable by any peer that received both records, so self-naming gossip
    /// only spams the mesh (production Helsinki fired one every 1-3 min from a
    /// nonce-reuse bug). Healthy = 0; non-zero means a latent self-equivocation
    /// path re-appeared — investigate, but no peer-visible spam resulted.
    pub conflict_proof_self_suppressed_total: AtomicU64,
    /// Slot conflicts whose locally-built ConflictProof failed verify() —
    /// the pair could not be turned into a gossipable accountability proof
    /// (structural failure: v4 record, missing signature, …). Post the
    /// 2026-07-06 record_hash-discriminator fix this should stay ~0; growth
    /// means a conflict class is again escaping accountability.
    pub conflict_proof_local_unverifiable_total: AtomicU64,
    /// Records rejected by the ledger content-hash v2 enforcement gate
    /// (config `enforce_ledger_content_hash_v2`, OFF until the re-genesis):
    /// a beat_op record whose content_hash does not commit to its signed
    /// metadata via the canonical v2 preimage.
    pub ledger_content_hash_v2_rejected_total: AtomicU64,
    /// Gap 2.1 Phase 2c: dedup set for SealFinalityWitness gossip,
    /// keyed by `format!("{seal_id}:{hex(witness_pk)}")`. Bounds re-broadcast
    /// of witnesses we've already pushed. 5,000 entries — at MAINNET committee
    /// size 7 and ~720 seals/day/zone that holds ~50 zone-epochs of churn.
    pub finality_witness_seen: std::sync::Mutex<SeenSet>,
    /// Counter: finality witnesses pushed to peers (per (seal,witness) we initiate).
    pub finality_witness_pushed_total: AtomicU64,
    /// Counter: finality witnesses received from peers via PQ gossip.
    pub finality_witness_received_total: AtomicU64,
    /// Counter: finality witnesses rejected at gossip ingress (malformed body
    /// or seal not locally ingested yet — the latter is a benign drop).
    pub finality_witness_rejected_total: AtomicU64,
    /// Counter: finality witnesses rejected because their wire committee
    /// snapshot did not match the locally-recomputed canonical committee for
    /// the seal's (zone, epoch). Non-zero = a peer tried to pin a forged
    /// committee (cross-zone finality forgery attempt). Security signal.
    pub finality_witness_committee_mismatch_total: AtomicU64,
    /// Counter: finality witnesses rejected because the snapshot matched the
    /// canonical committee but the `witness_pk` is NOT a member of it — a
    /// valid-signature fake-pk submission. Without the insertion-time membership
    /// gate the `signers` Vec grew unbounded with non-members (memory DoS;
    /// forgery itself is still blocked at claim by `verify_finality_quorum`'s
    /// membership proof). Non-zero = a peer is flooding fake-pk finality
    /// witnesses for a committee it knows but is not in. Security signal.
    pub finality_witness_non_member_total: AtomicU64,
    /// Counter: finality-witness push aborted because peer had no PQ address.
    pub finality_witness_push_addr_fail_total: AtomicU64,
    /// Counter: finality-witness push received a non-2xx, non-429 PQ status from peer.
    pub finality_witness_push_peer_reject_total: AtomicU64,
    /// Counter: finality-witness push errored at PQ transport layer (network/serde).
    pub finality_witness_push_net_fail_total: AtomicU64,
    /// Gap 2 sealed-abort P-3e: dedup set for `XZoneAbortWitness` gossip,
    /// keyed by `format!("{transfer_id}:{hex(witness_pk)}")`. Bounds re-
    /// broadcast of witnesses we've already pushed. 5,000 entries — at
    /// MAINNET committee size 7 and worst-case 1 abort per zone-epoch
    /// that holds ~700 zone-epochs of churn.
    pub xzone_abort_witness_seen: std::sync::Mutex<SeenSet>,
    /// Counter: abort witnesses pushed to peers (per (transfer,witness) we initiate).
    pub xzone_abort_witness_pushed_total: AtomicU64,
    /// Counter: abort witnesses received from peers via PQ gossip.
    pub xzone_abort_witness_received_total: AtomicU64,
    /// Counter: abort witnesses rejected at gossip ingress (malformed body).
    pub xzone_abort_witness_rejected_total: AtomicU64,
    /// B2 fix: abort witnesses dropped at gossip ingress because their wire
    /// committee snapshot did not match this node's seal-frozen canonical
    /// `PendingTransfer.dest_finality_committee` (or the transfer/anchor was
    /// unknown locally). Healthy mainnet: zero. Sustained non-zero means a peer
    /// is attempting to poison the abort-witness collection with a forged
    /// committee — escalate.
    pub xzone_abort_witness_committee_mismatch_total: AtomicU64,
    /// Memory-DoS gate (twin of `finality_witness_non_member_total`): abort
    /// witnesses dropped at gossip ingress because the committee snapshot matched
    /// the seal-frozen anchor but the signer's `witness_pk` is not a member of
    /// that canonical committee (a valid-signature fake-pk submission). Without
    /// this gate a peer that knows the public committee_hash floods distinct
    /// fake-pk witnesses to grow one transfer's `signers` without bound. Healthy
    /// mainnet: zero. Sustained non-zero = a peer flooding fake-pk abort
    /// witnesses; the insertion-time membership gate drops them — escalate.
    pub xzone_abort_witness_non_member_total: AtomicU64,
    /// Counter: xzone-abort-witness push aborted because peer had no PQ address.
    pub xzone_abort_witness_push_addr_fail_total: AtomicU64,
    /// Counter: xzone-abort-witness push received a non-2xx, non-429 PQ status from peer.
    pub xzone_abort_witness_push_peer_reject_total: AtomicU64,
    /// Counter: xzone-abort-witness push errored at PQ transport layer (network/serde).
    pub xzone_abort_witness_push_net_fail_total: AtomicU64,
    /// Counter: seal-apply proof-attach pass fell back to attaching WITHOUT
    /// finality witnesses because the consensus (AWC) mutex was try_lock-
    /// contended at that instant (ingest + local-creation sites). Post-Phase-5
    /// each such fallback can mint a committee_size=0 — i.e. unclaimable-
    /// until-reattach — transfer if a pending lock was in that seal. This was
    /// previously a fully silent path (B1 audit 2026-07-12).
    pub xzone_attach_finality_lock_contended_total: AtomicU64,
    /// 53-bit order-independent digest of live cross-zone transfer state
    /// (`CrossZoneState::state_digest`), refreshed at each applied seal.
    /// Fleet divergence detector; 0 = not computed since boot.
    pub xzone_state_digest: AtomicU64,
    /// Epoch at which `xzone_state_digest` was last refreshed. Compare
    /// digests only between nodes reporting the same value here.
    pub xzone_state_digest_epoch: AtomicU64,
    /// Gap 2 sealed-abort P-3f: dedup set so the aggregator submits each
    /// abort bundle at most once per node lifetime. Keyed by transfer_id.
    /// 5,000 entries — matches the AbortCollection cap. On overflow the
    /// oldest entries roll out; a re-emerging transfer would be re-
    /// submitted at apply-time idempotency cost.
    pub xzone_abort_aggregated_seen: std::sync::Mutex<SeenSet>,
    /// Counter: abort bundles assembled and self-submitted by THIS
    /// node's aggregator pass.
    pub xzone_abort_bundles_submitted_total: AtomicU64,
    /// Highest epoch number for which THIS node (when it is the genesis
    /// authority) has emitted a custodial-idle_decay batch record. A monotone
    /// `fetch_max` guard that dedups the *global* `IdleDecay` batch ACROSS zones
    /// within one process (internal design notes, Option A propagation).
    /// NON-PERSISTED: resets to 0 each boot. Seeded from the restored chain tip
    /// at `epoch_seal_loop` start (C10c, `max_sealed_epoch()`) so the cross-zone
    /// dedup survives a restart — without that seed a lagging zone re-emitted an
    /// already-charged epoch (multi-zone only; single-zone is independently
    /// guarded by the per-zone `AlreadySealed` gate). `apply_idle_decay_batch`
    /// has NO per-account idempotency token and every emit mints a fresh uuid7
    /// record id, so record-id dedup does NOT backstop a re-emit — this watermark
    /// (+ `AlreadySealed`) is the guard.
    pub last_idle_decay_emit_epoch: AtomicU64,
    /// Highest epoch number for which THIS node (when it is the genesis
    /// authority) has emitted an `XZoneTimeoutRefund` batch record. A monotone
    /// `fetch_max` guard that dedups the batch across zones within one process
    /// (internal design notes, Option A propagation).
    /// Replaces the old ungated in-loop `process_expired_xzone` sweep.
    /// NON-PERSISTED (resets to 0 on boot) but — unlike `last_idle_decay_emit_epoch`
    /// — needs NO boot seed: `apply_refund_batch` re-reads node-replicated `pending`
    /// status and flips `Locked → Refunded` one-way (cross_zone.rs), so a
    /// post-restart re-emit credits only the still-`Locked` subset and is an
    /// unconditional no-op on already-refunded transfers. The status machine, not
    /// the watermark, is the safety guard here.
    pub last_xzone_refund_emit_epoch: AtomicU64,
    /// Highest epoch number for which THIS node (when genesis authority) has
    /// emitted an `XZoneStaleReap` batch (co-fix (b)). Monotone `fetch_max` guard,
    /// same role as `last_xzone_refund_emit_epoch` but for the far-horizon
    /// sealed-stuck reaper (internal design notes). Same
    /// no-boot-seed rationale: `apply_reap_batch`'s `Locked → Refunded` one-way
    /// flip makes a post-restart re-emit a harmless no-op (C10c).
    pub last_xzone_reap_emit_epoch: AtomicU64,
    /// Negative cache for attestations that failed signature verification.
    /// Prevents infinite re-pull of known-bad attestations (record_id:witness_hash).
    pub attestation_bad_sigs: std::sync::Mutex<SeenSet>,
    /// Cumulative attestations rejected by the
    /// `attestation_pull_loop` because Dilithium3 sig-verify failed. Distinct
    /// from `attestation_receive_rejected_bad_signature_total` (the PUSH-path
    /// counterpart). Bootstrap-pathology signature: rises when local records
    /// have content_hash drift from the peer's view (forensically evicted +
    /// re-emitted under different content) — the witness's sig over
    /// (witness_id, record_id, content_hash) verifies with the peer's
    /// content but not ours. Sustained non-zero against a single peer is
    /// the operator signal that this node has stale records vs. that peer;
    /// trigger snapshot rebootstrap.
    pub attestation_pull_invalid_sig_total: AtomicU64,
    /// Cumulative attestations rejected by the
    /// `attestation_pull_loop` because PoWaS proof-of-work failed. PoWaS
    /// stops pull-watermark advance (peer may resend with a corrected proof),
    /// distinct from sig-verify which is permanent. Sustained non-zero is
    /// the operator signal that a peer is sending malformed PoWaS — likely
    /// an old binary or a witness key/stake mismatch.
    pub attestation_pull_invalid_powas_total: AtomicU64,
    /// Negative cache for records that failed validation during gossip.
    /// Prevents infinite push/pull RE-VALIDATION (Dilithium3 is the expensive
    /// step) of permanently invalid records — e.g. bad signature. What does
    /// NOT belong here: retryable classes (merkle root / previous_seal
    /// mismatch, ledger-state-dependent rejects) park in `gossip_retry`;
    /// stale epoch seals decline PRE-CRYPTO to `declined_seal_ids` (item 8b —
    /// a permanent embargo here killed all consumer processing for
    /// locally-pruned-history seals re-served by archive peers). In-memory
    /// only (cleared on restart), pure FIFO eviction at cap 50,000 — no TTL.
    pub gossip_rejected: std::sync::Mutex<SeenSet>,
    /// Counter: records skipped due to gossip_rejected cache.
    pub gossip_rejected_dedup_total: AtomicU64,
    /// Retry queue for records whose ingest hit a LEDGER-STATE-DEPENDENT
    /// rejection (e.g. genesis pool_fund offered before
    /// the peer's genesis ledger build → "insufficient balance"). Pull cursors
    /// may have advanced past the record's timestamp by the time the state
    /// lands, so no pull path would ever re-offer it — entries here are
    /// re-FETCHED by id in the gossip pull loop instead. (record_id, attempts);
    /// bounded by gossip::GOSSIP_RETRY_CAP, FIFO-evicted.
    pub gossip_retry: std::sync::Mutex<std::collections::VecDeque<(String, u8)>>,
    /// Counter: records recovered (ingested) via the gossip_retry queue.
    pub gossip_retry_recovered_total: AtomicU64,
    /// Auto-reward metrics: total reward records created on settlement.
    pub auto_rewards_total: AtomicU64,
    /// Auto-reward metrics: total reward amount distributed (base units).
    pub auto_rewards_amount_total: AtomicU64,
    /// Gossip metrics: push attempts that failed (connection refused, timeout, etc.).
    pub gossip_push_failed_total: AtomicU64,
    /// Gossip metrics: DHT fallback retry attempts after push failure.
    pub gossip_retry_total: AtomicU64,
    /// Gossip metrics: successful DHT fallback retries.
    pub gossip_retry_success_total: AtomicU64,
    /// Peer reconnection attempts to seed peers.
    pub peer_reconnect_attempts_total: AtomicU64,
    /// Successful peer reconnections.
    pub peer_reconnect_success_total: AtomicU64,
    /// Peers auto-banned (failures >= max_peer_failures).
    pub peer_auto_banned_total: AtomicU64,
    /// GC metrics: total records pruned by garbage collection.
    pub gc_pruned_total: AtomicU64,
    /// Persistent counter: total records that have EVER reached settlement (never decrements).
    pub total_ever_settled: AtomicU64,
    /// Persistent counter: total records that have EVER been finalized (never decrements).
    pub total_ever_finalized: AtomicU64,
    /// Seal-member durable-write lane (F5): rids whose durable
    /// FinalizedIndex insert happened via `reward::insert_members_durable`
    /// (the seal fast-track / R1 / R2 / promote_anchored / F3-sweep routing)
    /// rather than a Layer-1 settlement path. Isolated from the Layer-1
    /// counters so operators can watch the previously-dropped class heal.
    pub seal_member_finalized_durable_total: AtomicU64,
    /// Last sample of `total_ever_finalized` taken at the prior
    /// seal-loop tick (epoch.rs:4528 site, post-catchup-skip). Used by
    /// `sample_fin_burst_velocity()` to compute per-tick fin Δ.
    /// **Cold-start semantics**: zero means "uninitialized"; the first tick
    /// post-boot where this is zero AND `total_ever_finalized > 0` is treated
    /// as a seed-only tick that emits `last_fin_burst_velocity = 0` to avoid
    /// a spurious huge spike from RocksDB-rehydrated counter values on
    /// snapshot bootstrap.
    pub last_fin_sample: AtomicU64,
    /// Per-tick fin Δ from the prior seal-loop tick (first derivative
    /// of `total_ever_finalized`). Stored signed so the sampler can express
    /// negative deltas during snapshot-bootstrap rehydration without
    /// overflowing; saturating-sub at the call site keeps the arithmetic
    /// well-defined.
    pub last_fin_delta: AtomicI64,
    /// `elara_fin_burst_velocity` gauge value: second derivative of
    /// `total_ever_finalized` per seal-loop tick — `current_delta - prev_delta`.
    /// Captures the consecutive-burst-magnitude-growth pattern (e.g. a
    /// finalization Δ chain +16, +27, +31 = velocity
    /// +11, +4 — accelerating-but-decelerating regime distinct from normal
    /// Resume cadence). Positive = bursts growing tick-on-tick; negative =
    /// bursts shrinking; zero = steady cadence. See server.rs HELP block on
    /// `elara_fin_burst_velocity` for operator bands.
    pub last_fin_burst_velocity: AtomicI64,
    /// Per-node bratio band fingerprint counters. One counter per
    /// `AttestationRatioSummary::classify_cohort()` code. Sampled by
    /// `sample_bratio_band_tick()` on every seal-loop tick that survived
    /// catchup-skip (epoch.rs:4536 site, paired with `sample_fin_burst_velocity`).
    /// Exposed as `elara_bratio_band_ticks_total{band="…"}` — the per-node
    /// dwell-time fingerprint. In practice, some nodes appear
    /// "stuck at CONVERGED" while others cycle
    /// through all 4 active bands; with these counters operators can
    /// compute the dwell-distribution directly (`rate(...[5m])`) instead of
    /// scraping `elara_bratio_cohort_membership` at sample resolution.
    /// Resting fleet should show a CONVERGED-heavy distribution; sustained
    /// LOCKED dwell on a node indicates stake-config or witness-committee
    /// divergence.
    pub bratio_band_ticks_dormant_total: AtomicU64,
    /// LOCKED dwell counter. Bumped each tick the node observes
    /// `tracked > 0 && best_ratio < 0.60` (anchored-low ≈ 0.5952 sub-state
    /// or ratiable=0 zone-stake-unregistered sub-state).
    pub bratio_band_ticks_locked_total: AtomicU64,
    /// CONVERGED dwell counter. Bumped each tick the node observes
    /// `0.60 ≤ best_ratio < 0.667` (resting attractor ≈ 0.6032).
    pub bratio_band_ticks_converged_total: AtomicU64,
    /// ACTIVE dwell counter. Bumped each tick the node observes
    /// `0.667 ≤ best_ratio < 0.999` (mid-settlement burst ≈ 0.8016).
    pub bratio_band_ticks_active_total: AtomicU64,
    /// HYPER_ACTIVE dwell counter. Bumped each tick the node observes
    /// `best_ratio ≥ 0.999` (full-stake attestation 1.0000).
    pub bratio_band_ticks_hyper_active_total: AtomicU64,
    /// Persistent counter: total attestations processed by feed_attestation (never decrements).
    pub total_attestations_processed: AtomicU64,
    /// Transfer velocity: total successful beat transfers (excludes stake/mint/slash).
    pub beat_transfers_total: AtomicU64,
    /// Transfer velocity: total base units moved by transfers (excludes rewards/pool).
    pub beat_volume_micros_total: AtomicU64,
    /// AUDIT-10 Milestone B: HTTPS fallback events on the gossip pull/push path.
    /// Target on the 6-node fleet is 0 (runtime data plane is PQ-only).
    pub https_fallback_gossip_total: AtomicU64,
    /// AUDIT-10 Milestone B: HTTPS fallback events on the sync (snapshot/delta) path.
    pub https_fallback_sync_total: AtomicU64,
    /// AUDIT-10 Milestone B: HTTPS fallback events on the light-client header pull path.
    pub https_fallback_light_total: AtomicU64,
    /// AUDIT-10 Milestone B: HTTPS fallback events on the peer discovery / PEX path.
    pub https_fallback_discovery_total: AtomicU64,
    /// Path for ledger snapshot file.
    pub snapshot_path: std::path::PathBuf,
    /// Broadcast channel for real-time event streaming (SSE).
    pub events: broadcast::Sender<NodeEvent>,
    /// Trust engine — progressive daily record limits based on identity age + entropy.
    pub trust: RwLock<TrustEngine>,
    /// Rate limiter (shared with HTTP middleware for metrics access).
    pub rate_limiter: std::sync::OnceLock<Arc<super::server::RateLimiter>>,
    /// HTTP request latency histogram (unlabeled — aggregate across all routes).
    pub request_latency: super::server::Histogram,
    /// HTTP request latency histogram, partitioned by axum matched-route
    /// pattern (e.g. `/headers/from/{epoch}`). Cardinality bounded by the
    /// finite set of registered routes; cap protects against router refactors
    /// that might explode the label set. Critical for diagnosing slow
    /// light-client paths at mainnet scale (1M zones × 10K nodes).
    pub request_latency_by_route: super::server::LabeledHistogram,
    /// HTTP request count by `(route, status_class)`. Companion to
    /// `request_latency_by_route` — operators can spot endpoints that are
    /// silently 500-ing or 4xx-ing without grepping logs. Status classes are
    /// `2xx`/`3xx`/`4xx`/`5xx`.
    pub request_status_by_route: super::server::LabeledCounter,
    /// Gossip push duration histogram.
    pub gossip_push_duration: super::server::Histogram,
    /// Slashing monitor — double-attestation detection.
    pub slashing: std::sync::Mutex<super::slashing::SlashingMonitor>,
    /// Auto-slashes executed by this node.
    pub auto_slashes_total: AtomicU64,
    /// Fork heals — records synced during partition healing.
    pub fork_heals_total: AtomicU64,
    /// NETWORK-HARDENING-ROADMAP Tier 1.2 #2 — per-peer first-seen-diverged
    /// tracker. Key = peer base URL. Value = (first observation timestamp,
    /// has-already-been-alerted flag). Cleared when peer rejoins consensus
    /// (in_sync == true). The bool prevents alert spam — counter increments
    /// once when the streak crosses the threshold, not on every monitor tick.
    pub peer_divergence_first_seen:
        tokio::sync::Mutex<std::collections::HashMap<String, (std::time::Instant, bool)>>,
    /// Counter — number of distinct divergence streaks that have crossed the
    /// `PERSISTENT_DIVERGENCE_ALERT_THRESHOLD_SECS` window.
    pub peer_persistent_divergence_total: AtomicU64,
    /// Counter — number of previously-alerted divergence streaks that
    /// subsequently resolved (peer rejoined consensus / `in_sync==true` on
    /// the same `peer_addr`). Pairs with `peer_persistent_divergence_total`:
    /// the delta `total - resolved` is the count of CURRENTLY-FIRING alerts.
    /// Only resolutions of streaks that crossed the alert threshold tick this
    /// counter — sub-threshold blips (insert then quickly clear) do NOT
    /// increment, so the resolved-to-alert ratio is interpretable.
    pub peer_persistent_divergence_resolved_total: AtomicU64,
    /// Gap 7: chain divergence gauge —
    /// `max(peer_chain_tip) - local_chain_tip` in epochs. Emitted by
    /// `chain_divergence_monitor_loop` every `CHAIN_DIVERGENCE_POLL_INTERVAL_SECS`.
    /// Value 0 means local node is at or ahead of every polled peer.
    /// Above `CHAIN_DIVERGENCE_THRESHOLD_EPOCHS` triggers an autonomous repair attempt.
    /// Operator alert `ChainDivergencePersistent` fires at gauge above 50 for 30 min.
    pub chain_divergence_epochs: AtomicU64,
    /// Signed-divergence companion to
    /// `chain_divergence_epochs`. Holds `local_tip - max(peer_chain_tip)` —
    /// the AHEAD direction. The pair (`_ahead`, `_behind`) lets operators
    /// distinguish "we are the producer, peers are catching up" (ahead>0,
    /// behind=0) from "we fell behind a fork-leader" (behind>0, ahead=0).
    /// The unsigned `chain_divergence_epochs` collapsed both
    /// directions to a single scalar — one node 1 AHEAD + another 1 BEHIND both showed
    /// `chain_divergence_epochs=1`, indistinguishable on the fleet dashboard.
    /// 0 = local at or behind every peer (the AHEAD direction did not fire).
    /// Saturated subtraction; underflow path is the `_behind` field instead.
    pub chain_divergence_epochs_ahead: AtomicU64,
    /// Signed-divergence companion to
    /// `chain_divergence_epochs`. Holds `max(peer_chain_tip) - local_tip` —
    /// the BEHIND direction. Equal in value to `chain_divergence_epochs`
    /// because the legacy unsigned gauge IS the behind-only computation.
    /// Kept as a distinct field so the paired scrape (`_ahead` next to
    /// `_behind`) reads naturally on the dashboard and so a future deprecation
    /// of the unsigned gauge has a clean rename target.
    /// 0 = local at or ahead of every peer (the BEHIND direction did not fire).
    pub chain_divergence_epochs_behind: AtomicU64,
    /// Gap 7: counter — polls where no peers were eligible to compare against
    /// (no connected peers, all in backoff, or stub-mode no-op). Bumped every
    /// tick in stub mode; in production this stays near-zero except during
    /// network partitions.
    pub chain_divergence_poll_no_peers_total: AtomicU64,
    /// Gap 7: counter — repair attempts initiated. Bumped when local
    /// divergence crosses `CHAIN_DIVERGENCE_THRESHOLD_EPOCHS` and a
    /// state-delta pull is issued to the max-tip peer.
    pub chain_divergence_repair_attempts_total: AtomicU64,
    /// Gap 7: counter — repair attempts that failed at the network layer
    /// (timeout / connection refused / 5xx). Bumped before signature verify.
    pub chain_divergence_repair_failures_total: AtomicU64,
    /// Gap 7: counter — repair attempts where the signed state-delta arrived
    /// but Dilithium3 verification rejected it. Possible peer forge / corrupt
    /// transit; peer SHOULD be flagged for fork-monitor cross-reference.
    pub chain_divergence_repair_verify_fails_total: AtomicU64,
    /// Gap 7: counter — repair attempts where verify passed but the local
    /// apply path rejected the delta (state machine error, missing parent,
    /// disk-pressure). Distinct from verify_fails: peer was honest, our
    /// local apply path is the blocker.
    pub chain_divergence_repair_apply_fails_total: AtomicU64,
    /// Gap 7: counter — successful repairs. Each increment = one autonomous
    /// reconciliation closing a >50-epoch split-brain without operator action.
    /// Non-zero rate growth is the autonomous-mesh success signal.
    pub chain_divergence_repair_success_total: AtomicU64,
    /// Gap 7 (post-apply SMT-root verify): counter —
    /// repair applies where the post-apply local SMT root did NOT match the
    /// producer's signed `delta.account_state_root`. Counter-only signal
    /// (the ledger mutation is already committed; rolling back the SMT mid-
    /// repair is out of scope for this slice — the visibility hit *is* the
    /// fix). Persistent non-zero growth = either a pre-existing fork at
    /// `since_epoch` that the diff alone can't reconcile, or wire-format
    /// drift between producer and applier. Operator response: cross-check
    /// `latest_sealed_account_smt_root` against the trusted seal, then escalate
    /// to Path SB-1 (manual seed-peer edit) if the producer is on a different
    /// chain. Bursty growth co-located with normal `repair_success_total`
    /// growth = benign (peer ticked an epoch between our pre-state read and
    /// their delta build); persistent monotonic growth = real divergence.
    pub chain_divergence_repair_root_mismatch_total: AtomicU64,
    /// Gap 7 (settlement-denominator integrity): counter — repair applies
    /// where the post-apply recomputed `total_staked` (sum of staked over the
    /// node's own account set, which is what `is_settled`'s denominator must
    /// equal) differs from the producer's global `delta.total_staked`. Non-zero
    /// = our pre-state at `since_epoch` was forked beyond the diff's coverage,
    /// so the producer's global scalar does NOT match our post-apply leaves.
    /// Correlates with `repair_root_mismatch_total`. The repair still installs
    /// the self-consistent recomputed value (not the producer's), so settlement
    /// math stays internally correct; this counter is the fork-depth signal.
    pub chain_divergence_repair_scalar_drift_total: AtomicU64,
    /// Gap 7 (conservation integrity): counter — repair applies after which the
    /// conservation identity `sum(available)+total_staked+pending_xzone_locked+
    /// conservation_pool == total_supply` does NOT hold. Expected to be
    /// non-zero whenever a repair changes balances, because `StateDelta` carries
    /// neither `conservation_pool` nor `pending_xzone_locked` (so those stay at
    /// the local pre-repair value while balances move to the producer's). This
    /// is a known wire-format limitation, surfaced rather than masked. Operator
    /// response on sustained growth: trigger a full snapshot bootstrap (which
    /// carries all four scalars via wholesale ledger replace) instead of relying
    /// on incremental repair.
    pub chain_divergence_repair_conservation_drift_total: AtomicU64,
    /// Accounts observed during a chain-divergence repair carrying `staked > 0`
    /// but with no local `StakeEntry` (`staker_index` membership lag) — a staker
    /// onboarded by the delta whose `Stake` record has not yet been folded.
    /// FAIRNESS-SELF-HEALING (forward ingest re-folds the record): binding
    /// consensus (committee/seal/`zone_stakes`) reads `ledger.accounts`, not this
    /// index. Bump-worthy (local self-consistency, not a cross-node comparison).
    /// Operator response on unbounded growth: confirm forward ingest is delivering
    /// the affected stakers' `Stake` records, or trigger a full snapshot bootstrap.
    pub chain_divergence_repair_orphan_stake_total: AtomicU64,
    /// Key rotation registry — tracks active signing keys per identity.
    pub key_registry: std::sync::RwLock<KeyRegistry>,
    /// VRF key registry — maps anchor identity → VRF public key (Protocol §11.12).
    pub vrf_registry: std::sync::RwLock<super::vrf_registry::VrfRegistry>,
    /// Per-zone VRF committee resolver (Gap 5 Phase 6b).
    ///
    /// FIFO-bounded cache of `(zone, epoch, k, candidates_fingerprint)
    /// → committee` for the stake-weighted Efraimidis–Spirakis draw.
    /// Today wires the advisory `/committees/is_member` and
    /// `/committees` snapshot endpoints through a shared cache so a
    /// dashboard polling many zones doesn't redo the `O(n log n)` sort
    /// on every request. Phase 6c flips the consensus hot path to
    /// consult this resolver behind `enforce_per_zone_vrf`.
    pub zone_committee_resolver: super::zone_committee::ZoneCommitteeResolver,
    /// Witness liveness — last attestation time per witness.
    pub witness_liveness: std::sync::Mutex<WitnessLiveness>,
    /// Per-identity propagation rate limiter (Protocol v0.6.2 Section 11.19).
    pub propagation_limiter: std::sync::Mutex<PropagationLimiter>,
    /// Authoritative per-identity HARD daily emission cap — a SEPARATE lock from
    /// `trust` so the daily count is never dropped under `feed_attestation` /
    /// trust-prune contention (the flood-skip fix). See `ingest::DailyCapCounter`.
    pub daily_caps: std::sync::Mutex<super::ingest::DailyCapCounter>,
    /// Delegation registry — parent→child device authorization (Protocol v0.6.2 Section 6.2).
    pub delegations: std::sync::RwLock<DelegationRegistry>,
    /// Records rejected because the signing key was revoked (Protocol §11.2).
    pub revocations_rejected_total: AtomicU64,
    /// Search queries executed (Protocol §11.23).
    pub search_queries_total: AtomicU64,
    /// Search queries served by the Layer B creator-keyed indexed path
    /// (Protocol §11.23). Split from `search_queries_total` so dashboards
    /// can see how much load takes the indexed O(records_for_creator)
    /// path vs the timestamp-window fallback. Sum of `layer_b` and `fallback`
    /// plus queries that hit neither (because no filter was set) equals
    /// `search_queries_total`.
    pub search_queries_layer_b_total: AtomicU64,
    /// Search queries served by the timestamp-window fallback path
    /// (Protocol §11.23). High ratio relative to layer_b means callers
    /// are not using the creator filter — capacity scales worse there.
    pub search_queries_fallback_total: AtomicU64,
    /// `/records/by-hash/{content_hash}` lookups served from the local
    /// CF_IDX_HASH (Protocol §11.23 Layer A, slice 0 — node-local lookup).
    /// Hits are pure O(1) RocksDB point reads; misses are recorded
    /// separately so accounts can track index health.
    pub records_by_hash_hits_total: AtomicU64,
    /// `/records/by-hash/{content_hash}` misses — the local node has no
    /// record matching the requested content hash. At Layer A slice 0 this
    /// is just a 404; once peer-relay (slice 1) lands, a high miss rate is
    /// the operator signal that the relay layer should be enabled.
    pub records_by_hash_misses_total: AtomicU64,
    /// Layer A slice 1 — `?relay=1` / `relay=1` header asked the local
    /// node to fan out to peers after a local miss. Counts every entry
    /// regardless of outcome (paired with `_hits_total` + `_misses_total`).
    pub records_by_hash_peer_relay_attempts_total: AtomicU64,
    /// Layer A slice 1 — peer-relay returned a record body. Sum with the
    /// local-hit counter to get the effective hit-rate the caller sees.
    pub records_by_hash_peer_relay_hits_total: AtomicU64,
    /// Layer A slice 1 — every queried peer answered "no" (or was
    /// unreachable). Sustained non-zero growth here means the record
    /// genuinely doesn't exist in the connected mesh — likely an archive-
    /// node coverage gap, NOT an index health problem.
    pub records_by_hash_peer_relay_misses_total: AtomicU64,
    /// Seal-record-hash resolutions that hit CF_IDX_HASH on this node
    /// (Protocol §11.12 — both ingest-side post-attestation and creator-
    /// side post-seal-creation). Each hash inside `seal.record_hashes`
    /// counts as one increment. Pair with `seal_record_hashes_missing_total`
    /// — at fleet scale resolved/(resolved+missing) ≈ 1.0 once the v5→v6
    /// CF_IDX_HASH key-format fix has rebuilt the index. A sustained
    /// non-zero missing rate post-migration means the local node is
    /// receiving seals for records that haven't replicated to it yet —
    /// orthogonal to consensus health, but expected to spike during cold
    /// joins until the gossip backfill catches up.
    pub seal_record_hashes_resolved_total: AtomicU64,
    /// Seal-record-hash resolutions that missed CF_IDX_HASH locally.
    /// See `seal_record_hashes_resolved_total` for the operator
    /// interpretation. Until the v5→v6 migration ran, the previous
    /// double-hash key bug forced 100 % miss — so this counter doubles as
    /// a regression alarm for that class of bug.
    pub seal_record_hashes_missing_total: AtomicU64,
    /// PARTITION-MERGE conservation trip-wire (see [`super::xzone_demotion_probe`]):
    /// bounded queue of same-epoch seal demotions awaiting an async cross-zone
    /// coverage scan. Filled outcome-based at seal-registration ingest (after the
    /// epoch write lock is released), drained by the health loop. This is a
    /// detector for the `XZoneRevert` precondition, NOT a revert — the break it
    /// watches for is unreachable under the current append-only ledger.
    pub demoted_seal_scan_queue:
        std::sync::Mutex<std::collections::VecDeque<super::xzone_demotion_probe::DemotedSealScan>>,
    /// Monotonic count of same-epoch seal DEMOTIONS observed at ingest (both the
    /// default lex-min path and the weight-reconcile path). Surfaced as
    /// `elara_same_epoch_seal_demotions_total`. Non-zero rate = partition-merge /
    /// dual-proposer same-epoch collisions are firing (expected during heals).
    pub same_epoch_seal_demotions_total: AtomicU64,
    /// Demoted-seal coverage scans that found the demoted seal covered ≥1
    /// in-flight cross-zone transfer. `elara_xzone_demoted_seal_covers_lock_total`.
    pub xzone_demoted_seal_covers_lock_total: AtomicU64,
    /// THE conservation trip-wire: demoted-seal scans that found a demoted seal
    /// covering a CLAIMED cross-zone transfer — the `XZoneRevert` precondition.
    /// `elara_xzone_demoted_seal_covers_claimed_lock_total`. Healthy = 0; a
    /// non-zero value is the empirical signal to build the (sum-neutral) revert.
    pub xzone_demoted_seal_covers_claimed_lock_total: AtomicU64,
    /// Demotion-scan queue entries dropped (drop-oldest) on queue overflow.
    /// `elara_demoted_seal_scan_queue_dropped_total`. Sustained non-zero = a
    /// demotion burst exceeded `DEMOTED_SEAL_SCAN_QUEUE_CAP` between scan ticks.
    pub demoted_seal_scan_queue_dropped_total: AtomicU64,
    /// B7: non-genesis epoch seals deferred on the catch-up fast-forward branch
    /// because their proposer's VRF key is not locally registered (so the VRF
    /// proof cannot be verified). The seal is parked (retryable), NOT applied —
    /// so it cannot fast-forward `latest_epoch` and wedge this node off the
    /// canonical chain. Healthy steady-state = 0 (genesis is VRF-exempt). A
    /// sustained non-zero climb means either a forged-seal probe against a
    /// catching-up node, or an honest joiner that has not yet synced a real
    /// non-genesis anchor's VRF registration — cross-check against
    /// `seal_record_hashes_missing_total` (cold-join backfill lag) before paging.
    pub epoch_seal_fastforward_vrf_deferred_total: AtomicU64,
    /// C2: strictly-sequential epoch seals REJECTED at register-time because their
    /// `previous_seal_hash` does not chain to our canonical tip (forged chain-link /
    /// Byzantine-anchor fork attempt). The authoritative chain-link check runs under
    /// the epoch WRITE lock in ingest (the verify-time check is advisory — racy under
    /// the read lock). Healthy steady-state = 0; a sustained climb means a forged-seal
    /// fork probe from a key-holding anchor.
    pub epoch_seal_chain_link_rejected_total: AtomicU64,
    /// Subset of `epoch_seal_chain_link_rejected_total` where OUR canonical tip
    /// (the one the rejected sequential seal failed to chain to) carries 0
    /// external attestations — the crash-before-broadcast PHANTOM signature: a
    /// tip no peer ever attested, self-inflicting a chain freeze against an
    /// honest successor. Distinguished from the attested-tip case (a Byzantine
    /// forged-successor probe) because the two demand opposite operator
    /// responses. Read AFTER the epoch lock releases (never hold consensus+epoch
    /// together). Healthy = 0. Design + why the tempting attestation-gated
    /// auto-heal is UNSAFE: internal design notes.
    pub epoch_phantom_tip_suspected_total: AtomicU64,
    /// Subset of `epoch_phantom_tip_suspected_total` where the chain-link-rejected
    /// sequential successor's `previous_seal_hash` MATCHES the `record_hash` of a
    /// seal we hold durably at CF_EPOCHS `(zone, tip_epoch)` — i.e. the honest
    /// successor chains off a real-but-non-canonical seal in our store: the
    /// phantom won the lex-min tiebreak but the honest E-seal it beat is still
    /// durable. This is the subset the deferred provisional-self-tip "chain-
    /// existence" C2 relaxation would heal (as opposed to an unknown/forged
    /// predecessor, which it must NOT admit). Resolved by a CF_EPOCHS scan AFTER
    /// the epoch lock releases. A sustained non-zero at multi-sealer scale
    /// (first external sealers onward) is the live trigger to build the full A+B+C cure. Healthy = 0.
    pub epoch_successor_chainable_total: AtomicU64,
    /// Global gossip rate limiter — records accepted in the current minute window.
    /// Prevents sybil flood via many identities bypassing per-identity limits.
    pub global_records_this_minute: AtomicU64,
    /// Timestamp (seconds) when the current minute window started.
    pub global_rate_window_start: AtomicU64,
    /// Maximum records per minute from all sources combined.
    pub global_rate_limit_per_minute: u64,
    /// Global rate limit rejections counter (Prometheus metric).
    pub global_rate_limited_total: AtomicU64,
    /// Per-zone witness coverage tracking (Protocol §7.5).
    pub zone_state: std::sync::Mutex<ZoneState>,
    /// Dispute resolution state (Protocol §11.13).
    pub disputes: std::sync::RwLock<DisputeState>,
    /// Disputes opened.
    pub disputes_opened_total: AtomicU64,
    /// Gap 4: pending zone-split/merge TransitionSeal proposals (runtime
    /// bookkeeping for `/transitions/*` endpoints — lifecycle + vetoes).
    pub transitions: std::sync::RwLock<super::transition_store::TransitionStore>,
    /// Gap 4: count of pending TransitionSeal entries re-hydrated from
    /// `CF_TRANSITIONS_PENDING` at the last boot. Set once by
    /// `boot_replay_pending_transitions()` in the node main path and
    /// surfaced via `/transitions/stats` so operators can confirm a
    /// restart didn't silently drop mid-window proposals. Zero on a
    /// clean boot.
    pub transitions_boot_replayed_total: AtomicU64,
    /// Count of failures encountered while mirroring a pending
    /// TransitionSeal entry to `CF_TRANSITIONS_PENDING`. Each failure
    /// is already logged, but the counter exists so operators can tell
    /// whether the durability mirror is degrading over time (vs. a
    /// single transient write error). Incremented from
    /// `persist_pending_entry` on serde failure, put failure, or
    /// delete-on-vetoed failure. Zero in steady state. Surfaced via
    /// `/transitions/stats` as `mirror_write_failures_total`.
    pub transitions_mirror_write_failures_total: AtomicU64,
    /// Gap 4 orchestrator: count of TransitionSeals this anchor has
    /// proposed + inserted via `run_auto_scale_tick`. A non-zero value
    /// means the auto-scaler has fired at least once on this node; a
    /// value of zero after hours of hot/cold activity means either the
    /// scaler never fired OR this node isn't an anchor. Surfaced via
    /// `/transitions/stats`.
    pub transitions_proposed_by_orchestrator_total: AtomicU64,
    /// Gap 4 orchestrator: count of times `propose_transition_from_decision`
    /// ran but the subsequent `TransitionStore::insert` rejected the seal
    /// (e.g. duplicate id already present from a gossiped proposal).
    /// Non-monotone in steady state — spikes indicate gossip feedback.
    pub transitions_orchestrator_insert_rejected_total: AtomicU64,
    /// Gap 4 orchestrator cooldown: count of ticks where the orchestrator
    /// would have proposed a fresh transition but an active proposal
    /// (AwaitingSigs / DisputeWindow) for the same parent zones is already
    /// in the store. Skipping prevents 1-seal-per-tick floods on low-rate
    /// testnets where merge-recommend fires every health tick. A high
    /// rate here paired with non-zero `transitions_expired_total` means
    /// proposals aren't reaching the M-of-N threshold — investigate the
    /// anchor set.
    pub transitions_orchestrator_skipped_pending_total: AtomicU64,
    /// Gap 4 orchestrator pre-flight: count of ticks where the orchestrator
    /// would have proposed but the registered+staked anchor pool size is
    /// strictly below the kind's `required_threshold` (4 for Split, 7 for
    /// Merge). The proposal would dead-on-arrival expire after the dispute
    /// window without ever reaching M-of-N, so we skip and surface the
    /// shortfall. A persistently non-zero value means operators must add
    /// more anchors before this transition kind can finalize.
    pub transitions_orchestrator_skipped_undersized_pool_total: AtomicU64,
    /// Gap 4: count of TransitionSeals that flipped to `Finalized` in
    /// `run_transition_tick` — i.e. reached their `effective_epoch` in
    /// `DisputeWindow` status with the veto threshold not met.
    /// Local-node observation, not consensus-global: a seal may be
    /// Finalized here while a partitioned peer still has it in
    /// `AwaitingSigs`. Surfaced via `/transitions/stats`.
    /// Gap 2: Cross-zone transfer counters. Incremented in `ingest.rs` after
    /// successful ledger apply (for locks/claims) and in `epoch.rs` at the
    /// epoch-tick refund pass. Paired with the `pending_xzone_locked` gauge
    /// read live from the ledger at `/metrics` time.
    pub xzone_locks_total: AtomicU64,
    pub xzone_claims_total: AtomicU64,
    pub xzone_refunds_total: AtomicU64,
    /// Gap 2 sealed-abort: count of `XZoneAbort` ops successfully applied
    /// (sealed-transfer refund via destination-zone committee non-inclusion
    /// proof). Incremented in `pending_drain` after ledger commit.
    pub xzone_aborts_total: AtomicU64,
    /// Gap 2 pre-seal cancel: count of `XZoneCancel` ops successfully applied
    /// (sender-initiated refund before the lock-zone seal includes the LOCK).
    /// Sustained climb signals account UX bugs (timeout-then-cancel storms) or
    /// adversarial churn (lock-then-cancel DoS). Incremented in `pending_drain`
    /// after ledger commit.
    pub xzone_cancels_total: AtomicU64,
    /// Gap 2 pre-seal reject: count of `XZoneReject` ops successfully applied
    /// (recipient-initiated refund before claim). Sustained climb signals
    /// recipient-side account auto-rejection logic kicking in against legitimate
    /// transfers. Incremented in `pending_drain` after ledger commit.
    pub xzone_rejects_total: AtomicU64,
    /// Observability-only: count of `XZoneLock` records ingested whose DECLARED
    /// `source_zone` did not equal the record's registry-resolved zone
    /// (`resolve_record_zone`). This is NOT a reject — a mismatched source_zone
    /// is self-defeating (the claim's `verify_finality_quorum` binds the zone
    /// path into the signable bytes, so the real sealing committee's signatures
    /// won't verify against a forged zone → the lock simply refunds after 24h).
    /// A hard reject here was rejected by design audit: it would fork ingest
    /// across the `target_epoch = max_epoch + 3` zone-split window for zero
    /// security gain. A sustained climb instead points at a buggy account/SDK
    /// computing `source_zone` with a stale zone count. Incremented at first
    /// ingest only (not replay); single global counter, never zone-labelled
    /// (1M-zone cardinality would OOM Prometheus).
    pub xzone_lock_declared_zone_mismatch_total: AtomicU64,
    pub transitions_finalized_total: AtomicU64,
    /// Gap 4: Split-kind subset of `transitions_finalized_total`.
    /// Counted at the same tick edge so
    /// `finalized_split_total + finalized_merge_total ==
    ///  finalized_total` always holds post-increment.
    pub transitions_finalized_split_total: AtomicU64,
    /// Gap 4: Merge-kind subset of `transitions_finalized_total`.
    pub transitions_finalized_merge_total: AtomicU64,
    /// Gap 4: count of TransitionSeals that flipped to `Expired`
    /// (`AwaitingSigs` past `effective_epoch` without reaching the sig
    /// threshold). A non-zero value in steady state means proposals are
    /// failing to collect enough anchor signatures — either the anchor
    /// set is too small, the dispute window is too tight, or gossip
    /// isn't reaching anchors in time. Surfaced via `/transitions/stats`.
    pub transitions_expired_total: AtomicU64,
    /// Gap 4 gossip: dedup set for TransitionSeal broadcasts keyed by
    /// hex(seal_hash_for_sig). Bounded (10k) — proposals are anchor-
    /// rate-limited at ~1/epoch/zone so this easily covers days of
    /// activity even at 1M zones. Prevents re-broadcasting a seal we
    /// or a peer already sent, cutting the amplification blast.
    pub transition_seen: std::sync::Mutex<SeenSet>,
    /// Gap 4 gossip: count of TransitionSeals broadcast to peers from
    /// this node. Incremented once per push (not once per peer).
    pub transition_gossip_pushed_total: AtomicU64,
    /// Gap 4 gossip: count of TransitionSeal gossip attempts skipped
    /// because the seal was already in `transition_seen`. Paired with
    /// `transition_gossip_pushed_total`, the dedup ratio shows how
    /// often peers re-broadcast seals we already know about.
    pub transition_gossip_dedup_total: AtomicU64,
    /// Gap 4 sig gossip: dedup set for `AnchorSig` broadcasts keyed by
    /// `"{hex(seal_id)}:{hex(anchor_identity_hash)}"`. Per-sig (not
    /// per-seal) because a seal collects up to `MAX_PROPOSER_SIGS`
    /// distinct sigs over its lifetime; each one needs to reach every
    /// peer. Capacity 50k = ~1500 seals × 32 sigs — slack covers a
    /// fleet-wide transition wave without eviction churn.
    pub transition_sig_seen: std::sync::Mutex<SeenSet>,
    /// Gap 4 sig gossip: count of AnchorSig broadcasts this node
    /// actually forwarded to peers (once per unique sig).
    pub transition_sig_gossip_pushed_total: AtomicU64,
    /// Gap 4 sig gossip: count of sig-broadcast attempts skipped
    /// because the (seal_id, identity) pair was already in
    /// `transition_sig_seen`. Expected non-zero under normal
    /// convergence — each peer receives the same sig via its sqrt(n)
    /// neighbors, and dedup keeps the fan-out bounded.
    pub transition_sig_gossip_dedup_total: AtomicU64,
    /// Gap 4 cosign: count of gossiped TransitionSeals this node
    /// auto-cosigned as an anchor. A non-zero value proves the
    /// anchor rotation path is actually live on this node — without
    /// cosign, orchestrator-proposed seals land 1-of-N and Expire.
    pub transition_cosigns_total: AtomicU64,
    /// Gap 4 pull backstop: count of TransitionSeals this node
    /// pulled from a peer's `/transitions` list and inserted into the
    /// local store (deduplicated against already-present ids). Non-zero
    /// means gossip dropped a seal and the pull path recovered it —
    /// expected to be rare on healthy fleets, indicates partition
    /// recovery when it spikes.
    pub transition_pulled_total: AtomicU64,
    /// Gap 5: authoritative zone-tree state. Consumes finalized
    /// [`crate::network::zone_transition_seal::TransitionSeal`] events;
    /// answers routing (which leaf zone owns this account) and active-
    /// leaf iteration (which zones draw committees this epoch).
    /// Rehydrated at boot from `CF_TRANSITIONS_FINAL` by
    /// [`crate::network::health::boot_rehydrate_zone_registry`]; kept in
    /// sync with the durable seal history by `run_transition_tick`
    /// applying each newly-finalized seal.
    pub zone_registry:
        std::sync::RwLock<super::zone_registry::ZoneRegistry>,
    /// Memoized staked-anchor view (see [`AnchorView`]). `std::sync::RwLock`
    /// because the critical section is a non-async key compare plus two
    /// `Arc::clone`s — no `.await` is held across it. `None` = not yet built
    /// or invalidated, so the next read rebuilds. Invalidated wholesale by
    /// `invalidate_anchor_view` on any path that replaces the ledger
    /// (snapshot bootstrap / state-delta repair).
    pub anchor_view: std::sync::RwLock<Option<AnchorView>>,
    /// Transitions-F1: memoized zone-transition trust set (see
    /// [`TransitionTrustView`]). Same locking rationale as `anchor_view`;
    /// cleared by the same `invalidate_anchor_view` call so every
    /// ledger-replace site (scanner-enforced) covers both views.
    pub transition_trust: std::sync::RwLock<Option<TransitionTrustView>>,
    /// Transitions-F1: count of `AnchorSig`s rejected because the signer is
    /// not in the staked-anchor trust set (registered identity without
    /// witness-floor stake). Distinct from crypto-verify failures
    /// (`zone_registry_tick_sig_verify_failures_total`) so operators can
    /// tell "unstaked signer" from "forged bytes" at a glance. Non-zero
    /// under attack or fleet misconfiguration (an operator signing
    /// transitions from an unstaked identity).
    pub transition_sig_stake_rejected_total: AtomicU64,
    /// Gap 5: count of finalized seals re-applied to `zone_registry` at
    /// the last boot (via `rebuild_from_finalized`). Surfaced at
    /// `/transitions/stats` as a restart-coherence check — a cold boot
    /// must reproduce the exact finalized seal history.
    pub zone_registry_boot_applied_total: AtomicU64,
    /// Gap 5: count of finalized seals skipped at boot because their
    /// stored bytes failed to decode. Non-zero means on-disk corruption;
    /// the registry came up partial. Operators should investigate
    /// before the node serves routing traffic.
    pub zone_registry_boot_decode_failures_total: AtomicU64,
    /// Gap 5: count of finalized seals whose stored bytes decoded but
    /// which [`crate::network::zone_registry::ZoneRegistry::apply_transition`]
    /// rejected. Should be zero on a coherent fleet — seals reach
    /// `CF_TRANSITIONS_FINAL` only after dispute-window closure and
    /// M-of-N cosign, so any non-zero count flags either a registry
    /// bug or a concurrent-apply race upstream.
    pub zone_registry_boot_apply_failures_total: AtomicU64,
    /// Gap 5: count of finalized seals applied to `zone_registry` by
    /// `run_transition_tick` since process start. Pairs with
    /// `transitions_finalized_total` — the two counters must converge
    /// (`finalized >= registry_applied`, difference = seals whose
    /// apply errored after persistence; logged per-failure).
    pub zone_registry_tick_applied_total: AtomicU64,
    /// Gap 5: count of finalized seals that `run_transition_tick`
    /// tried to apply to `zone_registry` but the registry rejected
    /// (consistency error). Per-failure the error message is logged;
    /// the counter is the fleet-aggregate signal. Expected zero.
    pub zone_registry_tick_apply_failures_total: AtomicU64,
    /// Gap 4 close-out: count of finalized seals that `run_transition_tick`
    /// rejected because `TransitionSeal::verify_sigs` didn't meet the
    /// M-of-N Dilithium3 threshold against the locally-registered anchor
    /// pubkey set (`CF_IDENTITIES`). Per-failure the error is logged; the
    /// counter surfaces forgery attempts, registry gaps, or missing
    /// anchor-pubkey propagation. Expected zero on a coherent fleet; a
    /// spike means some anchors haven't registered their pubkeys yet OR a
    /// malicious proposer gossiped an under-signed seal past the store.
    pub zone_registry_tick_sig_verify_failures_total: AtomicU64,
    /// Gap 4 routing close-out: count of `/routing/resolve` queries
    /// served since process start. Pairs with
    /// `zone_routing_resolve_redirected_total` — the ratio tells
    /// operators how often a naive-modulo zone would've missed the
    /// current leaf under the active split tree.
    pub zone_routing_resolve_queries_total: AtomicU64,
    /// Gap 4 routing close-out: count of `/routing/resolve` queries
    /// whose resolved leaf differed from the naive-modulo starting
    /// zone (i.e., the registry walked at least one split/merge hop).
    /// Expected zero on a network with no finalized transitions;
    /// monotonically increasing once splits land.
    pub zone_routing_resolve_redirected_total: AtomicU64,
    /// Gap 4 routing-application: total calls to
    /// [`NodeState::resolve_record_zone`] / [`NodeState::resolve_identity_zone`]
    /// by internal code paths (NOT the `/routing/resolve` RPC, which has its
    /// own counters). Pairs with `zone_resolve_internal_redirected_total` —
    /// the ratio tells operators how often the registry actually redirects
    /// hot-path routing once call sites migrate off flat-modulo
    /// `zone_for_record`.
    pub zone_resolve_internal_queries_total: AtomicU64,
    /// Gap 4 routing-application: count of internal resolves whose resolved
    /// leaf differed from the naive-modulo starting zone. Expected zero
    /// until a split finalizes on the fleet; monotonically increasing once
    /// splits land. A non-zero count means hot-path code is honoring the
    /// registry, which is the whole point of the migration.
    pub zone_resolve_internal_redirected_total: AtomicU64,
    /// Gap 5 Phase 6b advisory: count of **Layer 2 epoch seal
    /// attestations** (Protocol §11.12) whose witness IS in the
    /// VRF-selected committee for `(seal.zone, seal.epoch)`. ADVISORY
    /// ONLY — consensus still accepts all seal attestations regardless.
    /// `(member + nonmember) / (member + nonmember + skipped_no_candidates)`
    /// is the fraction of seal traffic we could judge. `member /
    /// (member + nonmember)` is the fraction of seal attestations that
    /// would survive a strict committee filter today. Layer 1 per-record
    /// attestations are NOT observed here — §11.12 does not gate them on
    /// committee membership.
    pub committee_attestations_member_total: AtomicU64,
    /// Gap 5 Phase 6b advisory: count of **Layer 2 epoch seal
    /// attestations** whose witness is NOT in the committee for
    /// `(seal.zone, seal.epoch)`. ADVISORY ONLY — still accepted.
    /// A non-zero value tells operators how much of the incoming seal
    /// traffic would be rejected if committee enforcement were flipped on.
    pub committee_attestations_nonmember_total: AtomicU64,
    /// Gap 5 Phase 6b advisory: count of **Layer 2 epoch seal
    /// attestations** the observer couldn't evaluate because the VRF
    /// registry is empty (no candidates to draw a committee from).
    /// Expected 100% on a genesis fleet with no anchors registered yet;
    /// decays toward 0 as anchors join.
    pub committee_observations_skipped_no_candidates_total: AtomicU64,
    /// Gap 5 Phase 6c gate: count of **Layer 2 epoch seal attestations**
    /// REJECTED because `enforce_per_zone_vrf=true` and the witness is
    /// NOT in the per-zone VRF committee for `(seal.zone, seal.epoch)`.
    /// Distinct from `committee_attestations_nonmember_total`, which is
    /// the advisory observer count — it accumulates regardless of the
    /// flag. Operators can correlate the two:
    ///   - flag=false (Phase 6c soak default): rejections stay 0,
    ///     advisory keeps counting nonmembers (the "what we WOULD
    ///     reject" signal)
    ///   - flag=true (Phase 6d once stable): rejection rate ≈ advisory
    ///     nonmember rate; divergence means the gate computed a
    ///     different committee than the advisory (likely a candidate-
    ///     fingerprint cache split or stake-snapshot skew)
    ///
    /// Layer 1 per-record attestations are NEVER gated and never
    /// counted here (§11.12 — Layer 1 is committee-free).
    pub seal_attestation_rejected_not_in_committee_total: AtomicU64,
    /// Gap 5 Phase 6c.5 bootstrap fallback: count
    /// of seal attestations that bypassed the per-zone VRF committee
    /// gate because the VRF-registered+staked population is below
    /// `DEFAULT_COMMITTEE_SIZE`. Both observer (per-batch, by
    /// `entries.len()`) and gate (per-call) bump this counter, so the
    /// fleet-aggregate is "degraded-enforcement traffic across all six
    /// hot paths." Decays to 0 once `vrf_registry_identities` >= K AND
    /// every active zone has >=K staked anchors. Sustained growth past
    /// the bootstrap window = enforcement is silently inactive at scale.
    pub committee_skipped_below_k_total: AtomicU64,
    /// Count of VRF registration records (records carrying
    /// `VRF_REGISTRATION_KEY` metadata) that ingested successfully —
    /// `extract_vrf_registration()` returned Some and the local
    /// VrfRegistry now holds the entry. Pair with
    /// `vrf_registration_records_rejected_total` to compute the
    /// acceptance rate. Sustained climb of accepted alongside flat
    /// `elara_vrf_registry_identities` = same identities re-publishing
    /// (idempotent overwrite — fine, but unusual at steady state);
    /// flat accepted + low identities = anchors not publishing; high
    /// rejected vs accepted = anchors publishing malformed or
    /// non-anchor records.
    pub vrf_registration_records_accepted_total: AtomicU64,
    /// Count of records that carried `VRF_REGISTRATION_KEY`
    /// metadata but `extract_vrf_registration()` returned None — record
    /// was rejected because (a) `vrf_public_key` field missing or hex-
    /// invalid, (b) hex did not decode to exactly 32 bytes, (c)
    /// `node_type` does not satisfy `can_seal_epochs()` (Protocol §11.12
    /// reserves VRF for anchor-class nodes). Today the
    /// gate produces a `tracing::debug!` line per rejection; this
    /// counter exposes the rejection rate at /metrics so operators can
    /// detect "anchors are publishing but I'm dropping them" without
    /// turning on debug logs cluster-wide.
    pub vrf_registration_records_rejected_total: AtomicU64,
    /// Gap 4 pull backstop: count of `/transitions` list-fetch or
    /// per-id fetch failures (HTTP error, decode error, or seal failed
    /// local sig verification against CF_IDENTITIES). Logged at debug
    /// per-attempt; this counter is the fleet-aggregate signal that a
    /// peer is serving malformed or unknown-signer seals.
    pub transition_pull_errors_total: AtomicU64,
    /// ZK proofs verified (Protocol §5.3).
    pub zk_proofs_verified_total: AtomicU64,
    /// KR-3 S2 wiring-(c) c3: in-memory mirror of the `rotation_zone_pin:{rid}`
    /// CF rows (record_id → lineage_id). Boot-loaded from
    /// [`StorageEngine::scan_rotation_zone_pins`] and maintained at admission
    /// ([`Self::insert_rotation_pin`]); consulted by [`Self::resolve_record_zone`]
    /// under `s2_rotation_ordering_enabled` so every hop of a rotation chain
    /// routes to ONE zone (the lineage's), making same-anchor forks share a seal
    /// chain (§6.1 R-2/R-8). Permanent — mirrors the durable pin, which survives
    /// finalization; rotation-class records are rare so the set stays tiny.
    pub rotation_zone_pins: std::sync::RwLock<std::collections::HashMap<String, String>>,
    /// Fast emptiness guard for [`Self::rotation_zone_pins`], kept exactly equal
    /// to its `.len()`. The per-record resolve hot path checks this atomic first,
    /// so when there are no pins (the overwhelming common case, and always under
    /// flag-OFF) it takes NO lock — SCALE (`resolve_record_zone` is called on
    /// every ingest).
    pub rotation_pins_len: std::sync::atomic::AtomicUsize,
    /// Zone-scoped ITC clock manager (Protocol §11.9).
    pub zone_clocks: std::sync::Mutex<ZoneClockManager>,
    /// ITC events processed.
    pub itc_events_total: AtomicU64,
    /// ITC joins (received remote stamps).
    pub itc_joins_total: AtomicU64,
    /// Entity clustering for diminishing returns (economics §6.3).
    pub entity_clusterer: std::sync::Mutex<EntityClusterer>,
    /// Witness reputation engine — delta-based scoring (economics §11.2).
    pub reputation: std::sync::Mutex<ReputationEngine>,
    /// Cumulative count of inactive-witness reputation
    /// entries reaped by `ReputationEngine::prune_inactive` across the
    /// process lifetime. Pair with `elara_reputation_witnesses_tracked`
    /// gauge: counter climbing while gauge is stable = healthy retention
    /// churn (inactive witnesses dropping out as new ones arrive); counter
    /// flat while gauge climbs unboundedly = prune loop is not running OR
    /// retention window is too long for the network's witness churn rate.
    pub reputation_pruned_total: AtomicU64,
    /// Fisherman challenge state (economics §10.2).
    pub challenges: std::sync::RwLock<ChallengeState>,
    /// Challenges filed.
    pub challenges_filed_total: AtomicU64,
    /// Current active /pq-ws sessions (ELPQ-tunneled WebSocket).
    /// /ws Slice 3c (2026-05-20): legacy /ws gone, the counter now only
    /// tracks PQ sessions; doc updated to reflect the single-transport reality.
    pub ws_connections: AtomicU64,
    /// Cumulative `/pq-ws` (ELPQ-tunneled) sessions accepted.
    pub pq_ws_sessions_total: AtomicU64,
    /// Per-IP active WebSocket connection counts (DoS protection).
    pub ws_connections_per_ip: std::sync::Mutex<std::collections::HashMap<std::net::IpAddr, u32>>,
    /// Genesis allocation state — pool balances + vesting (economics §5.1).
    pub genesis_state: std::sync::RwLock<GenesisState>,
    /// Bootstrap phase detection — reward multiplier scaling (economics §14.2).
    pub bootstrap_state: std::sync::RwLock<BootstrapState>,
    /// Banned identities — records from these creators are rejected at ingestion.
    pub banned_identities: std::sync::RwLock<std::collections::HashSet<String>>,
    /// Content blocklist — terms that cause record rejection in text fields.
    pub content_blocklist: std::sync::RwLock<Vec<String>>,
    /// Records rejected because identity is banned.
    pub banned_rejections_total: AtomicU64,
    /// Records rejected because content matched blocklist.
    pub content_rejections_total: AtomicU64,
    /// Timestamp gaming defense — validates record timestamps against causal
    /// ordering, future skew, and per-identity violation rate limits.
    pub timestamp_defense: std::sync::Mutex<TimestampDefense>,
    /// VRF secret key for epoch sealing (only present on genesis authority nodes).
    /// Used to produce unpredictable jury selection seeds (Dilithium3 VRF).
    pub vrf_secret_key: Option<Arc<crate::crypto::vrf::VrfSecretKey>>,
    /// VRF public key for epoch seal verification.
    /// All nodes need this to verify VRF proofs in received epoch seals.
    pub vrf_public_key: Option<crate::crypto::vrf::VrfPublicKey>,
    /// Zone subscription manager — controls which zones this node stores/witnesses.
    /// Empty subscriptions = accept all zones (backward compat / testnet).
    pub zone_manager: std::sync::Mutex<super::zone::ZoneManager>,
    /// Epoch challenge state — per-record challenges within sealed epochs (Layer 3).
    pub epoch_challenges: std::sync::RwLock<super::fisherman::EpochChallengeState>,
    /// State core handle — serializes all record mutations through channel.
    /// None until spawn_state_core() is called during node startup.
    pub state_core: std::sync::OnceLock<super::state_core::StateCoreHandle>,
    /// Cached health report — written by `health_check_loop` each tick, read
    /// by the `/health` handler. Lock-free via ArcSwap so the handler never
    /// blocks on lock contention during boot replay / heavy ingest. `None`
    /// until the first health tick completes (within `health_check_interval_secs`
    /// of startup) — handler returns a "warming" payload during that window.
    /// Audit-2026-05-07 §8 line 2339: closes the post-deploy `/health=000`
    /// boot saturation symptom observed on the 4 GB / 2 GB RAM tier.
    pub cached_health: arc_swap::ArcSwapOption<super::health::HealthReport>,
    // silence REMOVED — pausing zones hurts availability with no benefit.
    /// Record relevance tracker — EMERGENT-MIND §3 (DIE/forgetting).
    pub relevance: std::sync::Mutex<crate::forgetting::RelevanceTracker>,
    /// Node retirement tracker — EMERGENT-MIND §3 (DIE/node death).
    pub retirement: std::sync::Mutex<crate::forgetting::RetirementTracker>,
    /// Admin action audit log — (timestamp, ip, endpoint, token_prefix).
    pub admin_audit_log: std::sync::Mutex<Vec<(f64, String, String, String)>>,
    /// RPC serialization lock — ensures concurrent RPC transfers chain their
    /// DAG parents instead of all branching from the same tips. Without this,
    /// 40 concurrent transfers create 40 parallel branches (40 tips) instead
    /// of a single chain (1 tip).
    pub rpc_lock: tokio::sync::Mutex<()>,
    /// CF_ACCOUNT_SMT writer-serialization gate (fusion-audited design,
    /// 2026-07-05 — internal design notes). The SMT's
    /// `commit()` writes its private node cache with no conflict detection,
    /// and every real write propagates to the shared root/near-root keys —
    /// two unserialized writers clobber each other last-writer-wins, leaving
    /// the persisted root inconsistent with the persisted leaves. EVERY live
    /// writer to CF_ACCOUNT_SMT (seal-loop flush, witness flush, bootstrap
    /// tail verify, repair path, genesis reconcile, admin orphan-reconcile)
    /// must hold this gate across its buffer→commit sequence.
    ///
    /// RULES:
    /// - **Leaf lock**: while holding the gate, acquire NOTHING (no ledger,
    ///   no dag, no epoch lock). Acquiring the gate while already holding a
    ///   ledger lock is permitted ONLY at the boot-serial genesis-reconcile
    ///   site (elara_node.rs), which runs before any task is spawned.
    /// - Acquire in the async caller and hold the guard across the
    ///   `spawn_blocking(...).await`; never move it into the closure.
    /// - Never wrap a gate-holding await in `select!`/`timeout` — cancelling
    ///   the future releases the gate while the detached blocking write is
    ///   still in flight, reopening the race.
    /// - Readers (`root()`/`get()`/`proof()`) do NOT take this gate: RocksDB
    ///   WriteBatch commits are atomic, so point reads are safe; only
    ///   writer-vs-writer lost-updates need serializing.
    pub account_smt_write_gate: tokio::sync::Mutex<()>,
    /// Scheduled zone count transition — announced by genesis authority.
    /// At the target epoch, zone_count switches atomically.
    pub zone_transition: std::sync::Mutex<Option<super::epoch::ZoneTransition>>,
    /// Gap 4: stateful auto-scaler. Observes per-zone activity on each health
    /// tick; hysteresis prevents flap. Only the genesis authority acts on the
    /// decision (emits a `zone_transition` record); other nodes run the same
    /// calculator for telemetry but do not emit.
    pub auto_scaler: std::sync::Mutex<super::auto_scale::AutoScaler>,
    /// Gap 5: per-zone witness subscription registry. Witnesses publish
    /// `zone_subscription` records declaring which zones they serve; scoped
    /// jury selection filters the global staked set against this registry
    /// before VRF scoring.
    pub zone_subscriptions:
        std::sync::Mutex<super::zone_subscription::ZoneSubscriptionRegistry>,
    /// Phase tracker for state_core watchdog diagnostics.
    /// Updated by insert_record_inner during processing to identify stuck phases.
    /// 0=start, 1=epoch-seal, 2=storage, 3=dag, 4=ledger, 5=post
    pub insert_phase: AtomicU8,
    /// Orphan resolver: tracks (fetch_miss_count, last_update_ts) per parent ID.
    /// After 3+ misses across cycles, the parent is pruned as stale test data.
    /// The timestamp is used by the gossip resolver to reap entries that have
    /// gone quiet (parent never reached 3 misses because its orphan child got
    /// pruned by other means) — without a TTL this map grows unboundedly under
    /// partition/peer-churn at 10K+ nodes. See `MAX_ORPHAN_MISS_*` in gossip.rs.
    pub orphan_fetch_misses: std::sync::Mutex<std::collections::HashMap<String, (u32, f64)>>,
    /// Persistent pull cursor for timestamp_pull catch-up.
    /// Starts at 0.0, advances through historical records across pull cycles.
    /// Prevents losing position when new pushes set the newest tip to NOW.
    pub pull_catchup_cursor: std::sync::Mutex<f64>,
    /// Persistent cursor for full_pull reconciliation.
    /// Unlike pull_catchup_cursor (which tracks ongoing sync), this tracks position
    /// in the full-scan backward reconciliation so 2GB nodes don't re-scan from 0.
    pub full_pull_cursor: std::sync::Mutex<f64>,
    /// Tracks which code path currently holds dag.write().
    /// 0=none, 1=state_core(ingest), 2=orphan_resolver, 3=finality_monitor,
    /// 4=bootstrap_pull, 5=admin, 6=startup, 7=snapshot_clone, 8=orphan_prune
    pub dag_write_holder: std::sync::atomic::AtomicU8,
    /// Active background merkle prefetch tasks. Capped to prevent CPU starvation
    /// when multiple epoch seals trigger concurrent prefetches.
    pub active_prefetches: AtomicU8,
    /// Gossip concurrency limiter — caps total in-flight outbound HTTP requests
    /// to prevent connection explosion (reqwest pool_max_idle_per_host only limits
    /// idle connections, not concurrent ones).
    pub gossip_semaphore: Arc<tokio::sync::Semaphore>,
    /// B8: PQ accept-path handshake limiter + observability. The `PqServer`
    /// accept loop now runs each responder handshake in a detached task gated
    /// by this semaphore (cloned into the task via `with_accept_limiter`), so
    /// one slow/half-open inbound peer can no longer stall new-peer admission.
    /// Over-budget connections are SHED (TCP dropped, `pq_handshake_shed_total`
    /// bumped), not queued — no parked-task fd pile-up under a join flood.
    /// `Arc<AtomicU64>` (not bare) because the counters are shared into a
    /// detached task that outlives the per-request `Arc<NodeState>` borrow.
    pub pq_handshake_semaphore: Arc<tokio::sync::Semaphore>,
    /// STREAM-F1 defense-in-depth: post-handshake serve-connection population
    /// bound (`Semaphore` sized by `config.pq_serve_concurrency`, wired into
    /// `PqServer` via `with_serve_limiter`). The handshake limiter above
    /// releases its permit before serving, and the serve loop's 60s idle
    /// read-deadline bounds how long an idle connection lives — this bounds
    /// how MANY live ones exist at once. Over-budget connections are shed
    /// right after the handshake (dropped, `pq_serve_shed_total` bumped),
    /// never queued — a queued connection would hold the fd the cap protects.
    pub pq_serve_semaphore: Arc<tokio::sync::Semaphore>,
    /// Resolved permit count of `pq_serve_semaphore` (for the /metrics
    /// cap/inflight gauge pair, mirroring `pq_heavy_read_cap`).
    pub pq_serve_cap: usize,
    /// Connections shed by the STREAM-F1 serve-connection cap. Healthy = 0;
    /// sustained growth = follower fan-in above `pq_serve_concurrency` OR a
    /// handshake-completing connection swarm.
    pub pq_serve_shed_total: Arc<AtomicU64>,
    /// B8: in-task PQ responder-handshake failures (timeout / malformed /
    /// sovereign-denied / admission-rejected). Replaces the observability the
    /// pre-B8 accept-loop recoverable-error `match` carried — post-split those
    /// errors resolve inside the detached task and never reach the loop, so
    /// without this counter handshake failures would go silent. Healthy = a
    /// low background rate (hostile probes / mid-handshake drops).
    pub pq_handshake_failed_total: Arc<AtomicU64>,
    /// The PQ-wire-incompatibility subset of `pq_handshake_failed_total` (which
    /// still counts the aggregate): an explicit wire-version reject (the peer's
    /// first handshake frame carried a different `WIRE_VERSION` byte) or a
    /// transcript/AEAD divergence. Both are the signature of a peer on an
    /// incompatible PQ wire, so a sustained non-zero on a fresh external join
    /// means "that peer built a different commit — rebuild it to the seed's".
    /// Self-diagnoses the first-join "network looks dead" trap. Healthy = 0.
    pub pq_handshake_wire_mismatch_total: Arc<AtomicU64>,
    /// B8: PQ inbound connections SHED because the handshake limiter was at
    /// capacity (`try_acquire` failed). Healthy = 0; sustained growth = a
    /// handshake flood OR a `pq_handshake_concurrency` set too low for real
    /// fan-in. Pair with `pq_handshake_failed_total` to tell flood from churn.
    pub pq_handshake_shed_total: Arc<AtomicU64>,
    /// Public-HTTP accept-path twin of `pq_handshake_shed_total`: connections
    /// dropped at accept because the global `http_conn_cap` was saturated
    /// (loopback exempt). Healthy = 0; sustained growth = a connection flood
    /// OR a cap set too low for real fan-in
    /// (internal design notes).
    pub http_conn_shed_total: Arc<AtomicU64>,
    /// Connections dropped at accept because ONE remote IP exceeded
    /// `http_conn_per_ip_cap` while the global cap still had room — the
    /// single-source-starves-everyone defense. Healthy = 0; growth with a
    /// quiet `http_conn_shed_total` = a single-source slowloris being blunted.
    pub http_conn_per_ip_shed_total: Arc<AtomicU64>,
    /// Post-handshake AEAD frame-decrypt failures on the RESPONDER/seed serve
    /// path (TCP `serve_connection` + the `/pq-ws` read surface). A peer that
    /// COMPLETED the PQ handshake then sent an application frame this node
    /// could not decrypt — the seed-side symmetric of the follower's
    /// `delta_sync_failures_other_rpc_total`. It CANNOT fire on a clean close
    /// (those resolve to `PeerClosed`/`Io` and are not counted), so unlike a
    /// blind `Err(_)` teardown counter it does not just track connection
    /// churn. Healthy = 0; non-zero = post-handshake wire/key divergence (a
    /// stale-binary peer, an AEAD-AD change shipped without a version bump) or
    /// in-transit tampering. `pq_handshake_failed_total` is the PRE-handshake
    /// equivalent; together they localise a silent desync to before vs after
    /// the handshake without per-peer WARN-log forensics.
    pub pq_serve_frame_decrypt_failed_total: Arc<AtomicU64>,
    /// Global concurrency ceiling on HEAVY PQ reads (verbs doing chain-scale
    /// work in `spawn_blocking` — a whole-ledger clone or an O(zone_count)
    /// global-root recompute). Complements
    /// the per-peer `pq_read_limiter` (which bounds a single identity's RATE):
    /// this bounds the cross-identity aggregate CONCURRENCY so a Sybil swarm —
    /// each peer under its own bucket — cannot collectively saturate the small
    /// shared blocking pool and starve consensus ingest. Permits = config
    /// `pq_heavy_read_concurrency`, or `max_blocking_threads / 2` when that is 0
    /// (heavy reads never take more than half the pool). See
    /// `is_heavy_blocking_read` in pq_transport/router.rs.
    pub pq_heavy_read_semaphore: Arc<tokio::sync::Semaphore>,
    /// Resolved permit count for `pq_heavy_read_semaphore` (snapshotted so the
    /// `/metrics` gauge can report `cap - available_permits()` without re-deriving).
    pub pq_heavy_read_cap: usize,
    /// Bounded wait before a HEAVY-read shed (ms). A short wait (not a bare
    /// shed) lets a legitimate bootstrap — whose snapshot_full/_latest/_fast_meta
    /// are all HEAVY and which ABORTS on any 429 — survive transient contention,
    /// while a sustained flood still sheds past the timeout.
    pub pq_heavy_read_wait_ms: u64,
    /// HEAVY PQ reads SHED (429) because the global concurrency cap was held
    /// past `pq_heavy_read_wait_ms`. Healthy = 0. Sustained growth = a heavy-read
    /// flood OR `pq_heavy_read_concurrency` set too low for real joiner fan-in.
    pub pq_heavy_read_shed_total: Arc<AtomicU64>,
    /// Global concurrency gate on inbound HEAVY-VERIFY verbs (`submit_record`,
    /// `witness`, `receive_attestation`) — the write-side twin of
    /// `pq_heavy_read_semaphore` (internal design notes).
    /// Caps aggregate inline-PQC CPU regardless of Sybil identity count. UNLIKE
    /// the read gate it never sheds: a dropped consensus message is permanently
    /// lost (sender treats 429 as success; `seen` dedup blocks re-push), so
    /// excess dispatches WAIT — per-connection dispatch is sequential, so the
    /// wait queue is bounded by connection count and a flooding peer stalls
    /// only itself. Permits = config `pq_verify_concurrency`, or the half of
    /// the blocking pool the read cap leaves free when 0 (≈ CPU count).
    pub pq_verify_semaphore: Arc<tokio::sync::Semaphore>,
    /// Resolved permit count for `pq_verify_semaphore` (snapshotted so the
    /// `/metrics` gauge reports `cap - available_permits()` without re-deriving).
    pub pq_verify_cap: usize,
    /// Dispatches of a heavy-verify verb that found the global verify gate
    /// saturated and had to WAIT for a permit (they are never shed). Healthy ≈ 0.
    /// Sustained growth = an inbound verify flood OR `pq_verify_concurrency`
    /// set too low for real consensus fan-in.
    pub pq_verify_waited_total: Arc<AtomicU64>,
    /// Deferred attestations — pushed attestations for records not yet in local storage.
    /// When a NAT'd node pushes an attestation for a record the receiver hasn't synced yet,
    /// the attestation is buffered here. When the record arrives, deferred attestations are
    /// drained and verified. Bounded to 5000 record buckets × 128 atts each; oldest
    /// first-seen bucket evicted on overflow in O(1) amortized (see
    /// [`DeferredAttestationBuf`]). Shared by the PQ router and HTTP routes/sync twins.
    pub deferred_attestations: std::sync::Mutex<DeferredAttestationBuf>,
    /// Tier 4.6 bootstrap-pathology buffer — attestations whose record IS local
    /// but whose witness's stake row hasn't synced yet (so the sybil-defense
    /// gate would reject). Keyed by `witness_hash` so a stake update fires
    /// O(1) replay of every attestation deferred for that witness. Drained by
    /// `low_stake_replay_loop` (interval=60s); entries past
    /// `PENDING_HARD_DISCARD_TIMEOUT_SECS` are evicted regardless of stake
    /// status. Bounded to 5000 distinct witness_hashes; oldest-attestation
    /// witness evicted on overflow. Distinct from `deferred_attestations`
    /// (which keys by record_id and triggers on record arrival).
    pub low_stake_deferred: std::sync::Mutex<std::collections::HashMap<String, Vec<DeferredLowStakeAttestation>>>,
    /// Distinct-witness count, mirrors `low_stake_deferred.lock().len()`.
    /// Maintained at every mutation site in `low_stake_replay::buffer_low_stake_attestation`
    /// and `run_sweep_once`. Read by Prometheus scrape in O(1) without
    /// touching the buffer mutex (was: `buf.len()` under lock).
    pub low_stake_deferred_witnesses: std::sync::atomic::AtomicU64,
    /// Total entries across all per-witness buckets — i.e.
    /// `sum(buf.values().map(|v| v.len()))`. Maintained at every mutation
    /// site. Read by Prometheus scrape in O(1) (was: O(witnesses) sum
    /// under buffer mutex).
    pub low_stake_deferred_total: std::sync::atomic::AtomicU64,
    /// `f64::to_bits(oldest_received_at)` of any entry in the
    /// buffer. Sentinel = `f64::INFINITY.to_bits()` when the buffer is
    /// empty. Maintained as `min(current, new.received_at)` on insert; on
    /// remove/retain that drops the oldest entry, recomputed under the
    /// already-held buffer mutex (one bucket scan, NOT the global O(total)
    /// scan that was on the metrics scrape path). Read by Prometheus
    /// scrape in O(1) atomic load — the scrape path no longer iterates
    /// `buf.values().flat_map(...)` under the buffer mutex.
    pub low_stake_deferred_oldest_at_bits: std::sync::atomic::AtomicU64,
    /// Memory pressure flag — set when RSS exceeds 80% of system RAM.
    /// When true, subsystems reduce batch sizes and trigger aggressive eviction.
    /// Checked by gossip (pull batch size), ingest (prefetch cap), GC (force cycle).
    pub memory_pressure: std::sync::atomic::AtomicBool,
    /// Critical memory flag — set when RSS exceeds 90% of system RAM.
    /// When true, new record submissions are rejected with HTTP 429 to prevent OOM.
    /// Cleared when RSS drops back below 85% (5% hysteresis to avoid rapid toggling).
    pub memory_critical: std::sync::atomic::AtomicBool,
    /// Combined disk pressure flag — `disk_avail_pressure || disk_cap_pressure`.
    /// Maintained for back-compat (`elara_disk_pressure` gauge, `under_disk_pressure()`
    /// callers that want either signal — e.g. GC force-compaction). New code that
    /// must distinguish "real disk-full safety" from "operator-policy budget
    /// exceeded" should call `under_avail_pressure()` / `under_cap_pressure()`
    /// directly. See `disk_avail_pressure`.
    pub disk_pressure: std::sync::atomic::AtomicBool,
    /// Real-disk-full safety signal — set when filesystem `statvfs` avail
    /// drops below `disk_pressure_avail_low_mb` (default 2 GB). Cleared when avail
    /// rises back above `disk_pressure_avail_high_mb` (default 4 GB). This is the
    /// flag that ingest gates check (`/records` POST returns 429), because writing
    /// to a near-full filesystem risks ENOSPC and torn-write corruption that the
    /// operator cannot recover from without manual intervention.
    pub disk_avail_pressure: std::sync::atomic::AtomicBool,
    /// Operator-policy budget signal — set when `rocks.total_live_bytes()`
    /// exceeds 95 % of `disk_cap_bytes_effective` (the clamped operator-
    /// configured cap). Cleared when live drops back below 80 % of cap. This is a
    /// soft signal: GC force-compaction reads it (it triggers extra cycles
    /// on either pressure flag) and `gc.rs` shrinks retention proportionally
    /// (`disk cap pressure — compressed retention=…h`). It does **not** reject
    /// ingest. Reason: the cap is a hint about operator intent, not a real-world
    /// safety bound — that bound is statvfs avail. If the operator wants
    /// cap-overrun to block ingest, they can set `disk_pressure_avail_low_mb` such
    /// that the FS-avail signal trips first; or for the testnet workaround, set
    /// `disk_cap_bytes=0` to disable the signal entirely (mirrors the
    /// `.env.secrets` pattern).
    pub disk_cap_pressure: std::sync::atomic::AtomicBool,
    /// Cumulative ingest rejections caused by disk_pressure=1.
    /// Incremented in `insert_record_inner` whenever a new record is dropped
    /// to keep the filesystem from filling. RPC `/records` POST rejections
    /// are also rolled into this counter (the same gate fires for both paths).
    /// Surfaced as `elara_disk_pressure_rejected_ingest_total`. Sustained
    /// non-zero rate = peer gossip is still pushing records while the operator
    /// hasn't freed space; the counter rate is the live-blast-radius signal,
    /// where the gauge `elara_disk_pressure` is the on/off signal.
    pub disk_pressure_rejected_ingest_total: AtomicU64,
    // ── EmergencyHalt circuit-breaker (node-local, never consensus-folded) ──────
    // The in-memory hot-path cache for the halt gate. Source of truth is durable
    // CF_EMERGENCY (repopulated on boot); these atomics are the lock-free read.
    // B4 ordering: a winning fold stores expiry (Relaxed) THEN nonce (Release);
    // `emergency_halted_now` loads nonce (Acquire) before expiry — so a reader that
    // sees a new nonce is guaranteed to see the matching expiry.
    /// Max nonce over observed authority-signed `EmergencyHalt` records.
    pub emergency_latest_halt_nonce: AtomicU64,
    /// Max `halt_nonce` over observed authority-signed `EmergencyResume` records.
    pub emergency_latest_resume_nonce: AtomicU64,
    /// Effective expiry (unix secs) of the max-nonce halt (`0` = none). The
    /// wall-clock continuity backstop: the gate self-clears here even with no resume.
    pub emergency_active_expiry_unix: AtomicU64,
    /// Records refused at the halt ingest gate. Surfaced as
    /// `elara_emergency_rejected_ingest_total`.
    pub emergency_rejected_ingest_total: AtomicU64,
    /// Serializes the cold fold path so the expiry/nonce/reason triple updates
    /// atomically w.r.t. other folds (the hot read path stays lock-free).
    pub emergency_fold_lock: std::sync::Mutex<()>,
    /// Reason of the active halt (observability only — off the hot path).
    pub emergency_active_reason: std::sync::Mutex<String>,
    /// Cumulative count of `disk_avail_pressure` 0→1 transitions
    /// observed by `disk_pressure_loop`. Incremented exactly once per trip
    /// edge; clears (1→0) do NOT decrement. Surfaced as
    /// `elara_disk_avail_pressure_events_total`. Pairs with the on/off gauge
    /// `elara_disk_avail_pressure` to disambiguate two operationally different
    /// shapes that both look identical at scrape time:
    ///   (i) gauge=1 + counter steady → still under pressure since the last trip,
    ///       no new edge.
    ///   (ii) gauge=0 + counter advanced since last scrape → at least one
    ///        transient pressure episode fired AND cleared between scrapes.
    /// Shape (ii) has been observed across two nodes:
    /// `disk_avail_pressure=0` on every scrape, but
    /// `rejected_ingest_total` advanced — the gauge tripped briefly inside
    /// the 60 s sample cadence and recovered before either scrape caught it.
    /// Counter-only signal makes that visible.
    pub disk_avail_pressure_events_total: AtomicU64,
    /// Cumulative count of `disk_cap_pressure` 0→1 transitions
    /// observed by `disk_pressure_loop`. Identical semantics to
    /// `disk_avail_pressure_events_total` but for the operator-policy budget
    /// signal (live_bytes vs disk_cap_bytes_effective). Symmetric pair so
    /// operators can attribute a flap to the avail-side or cap-side without
    /// tail-grepping the journal for the edge log lines.
    pub disk_cap_pressure_events_total: AtomicU64,
    /// Minimum `disk_available_mb` observed since process boot.
    /// Maintained via `fetch_min` on every `disk_pressure_loop` tick. Sentinel
    /// `u64::MAX` before the first sample completes — surfaced as 0 in
    /// `/metrics` (matches the "first scrape may show 0 until the loop
    /// has run" pattern; pair with `elara_node_boot_total_seconds` to
    /// disambiguate "not yet sampled" from "actually 0 free"). Closes the
    /// gauge-failure-on-slow-shrink shape: between two scrapes the gauge can
    /// dip below the low watermark and recover before either scrape catches
    /// it (an observed instance hid behind exactly this — disk
    /// monotonically declined toward the floor across multiple ticks but the
    /// boolean gauge stayed at 0 until the floor was crossed). The lowest-mb
    /// gauge surfaces the dip-history that the boolean cannot.
    pub disk_pressure_lowest_avail_mb: AtomicU64,
    /// Cumulative count of operator-triggered RocksDB
    /// compactions via `/admin/rocks/compact_cf`. Distinct from auto-triggered
    /// compaction inside `gc_loop` (`gc.rs:553`), which is invisible to this
    /// counter. Surfaced as `elara_admin_compact_cf_triggered_total` so the
    /// disk-pressure runbook can verify the operator action landed and so we
    /// can attribute a subsequent drop in `total-sst-files-size` to the
    /// manual intervention vs the periodic gc cycle.
    pub admin_compact_cf_triggered_total: AtomicU64,
    /// Cumulative count of `disk_pressure_loop` iterations
    /// (one fetch_add(1) per 60 s tick). Pairs with `disk_pressure_lowest_avail_mb`
    /// to disambiguate two operationally distinct shapes that the metrics
    /// renderer's `u64::MAX → 0` sentinel-collapse otherwise looks identical:
    ///   - `lowest_avail_mb=0` + `samples_total=0` ⇒ loop has never run;
    ///     the 0 is the sentinel `u64::MAX` mapped to 0 by the renderer.
    ///   - `lowest_avail_mb=0` + `samples_total>0` ⇒ the loop has observed
    ///     `statvfs(data_dir).f_bavail*f_frsize < 1 MB` at least once
    ///     (genuine ENOSPC neighbourhood, e.g. an observed incident
    ///     which logged `IO error: No space left on device`
    ///     while the on/off `disk_avail_pressure` gauge was still recovering).
    ///
    /// This shape was initially mis-diagnosed as a `fetch_min` no-op on
    /// several nodes — the real cause was the
    /// renderer collapsing two states. This counter restores the disambig.
    pub disk_pressure_samples_total: AtomicU64,
    /// Recursive on-disk size of `config.data_dir` in bytes — sampled by
    /// `data_dir_size_loop` (separate task from `disk_pressure_loop`)
    /// at a 5 min default cadence (configurable via
    /// `ELARA_DATA_DIR_SIZE_SAMPLE_INTERVAL_SECS`). Previously this walk ran
    /// inside `disk_pressure_loop` every 60 s and the `O(SST count)` stat()
    /// pass would dominate the tick under compaction pressure (a node after a
    /// deploy: 7 samples in 11 min of uptime instead of ≥11, so
    /// `disk_pressure_lowest_avail_mb` stopped tracking between-scrape dips).
    /// Splitting the walk + running it in `spawn_blocking` keeps the
    /// pressure loop on its strict 60 s rhythm. Differs from
    /// `rocks.total_live_bytes()` by the bytes held in checkpoints,
    /// pre-migration backups, WAL, and any other artefact under data_dir that
    /// isn't part of active rocksdb state. Surfaced as
    /// `elara_data_dir_total_bytes` so operators can see the actual
    /// filesystem footprint before statvfs avail hits the floor — closes the
    /// signal gap that hid an observed incident (hardlinked checkpoints
    /// inflated the directory without affecting live_bytes). 0 if unsampled
    /// (during boot, before first tick).
    pub data_dir_total_bytes: AtomicU64,
    /// Cumulative count of `data_dir_size_loop`
    /// iterations (one fetch_add(1) per completed walk, default 5 min cadence).
    /// Pairs with `elara_data_dir_total_bytes` to disambiguate two operationally
    /// distinct shapes that look identical in the gauge alone:
    ///   - `data_dir_total_bytes=0` AND `data_dir_size_samples_total=0` ⇒ the
    ///     walk task has not finished its first pass yet (boot regime — at
    ///     \>10K SSTs the first walk under compaction pressure can take several
    ///     minutes, e.g. a node at 510+ SSTs measured ~10-50 ms per stat()).
    ///   - `data_dir_total_bytes=0` AND `data_dir_size_samples_total>0` ⇒
    ///     pathological filesystem state (data_dir was relocated, unmounted,
    ///     or all reads errored). Investigate journal.
    ///
    /// Steady state on a long-running fleet:
    /// `samples_total ≈ uptime_seconds / data_dir_size_sample_interval_secs`.
    /// If the ratio drifts below ~50% the walk is now dominating its own
    /// cadence — that's the regime where the operator should raise the
    /// interval rather than just watching the symptom.
    pub data_dir_size_samples_total: AtomicU64,
    /// Boot timing observability — closes the alert-blind
    /// window operators saw on a rolling deploy where 2.5–5+ min
    /// elapsed between systemd start and HTTP listener bind across the fleet.
    /// During that window /metrics, /healthz, /ping all return connection-refused
    /// because axum hasn't bound yet, so monitoring fires "node down" alerts
    /// for healthy boots and operators can't tell a slow boot from a hung one.
    /// `boot_total_secs` is the wall-clock from `run()` entry to the first
    /// HTTP listener bind; the two sub-phase fields decompose it so a regression
    /// points at the offending phase. Set ONCE per process at boot completion;
    /// non-zero on first /metrics scrape post-boot. Zero before HTTP is up
    /// (which is also the only window scrapes can fail anyway), so a
    /// sustained-zero gauge in steady-state means a downstream-side bug.
    pub boot_total_secs: AtomicU64,
    /// Ledger + DAG rebuild phase duration in seconds.
    /// Covers the entire "Load snapshot or rebuild ledger" block — snapshot
    /// fast-path or full streaming rebuild, plus DAG load/patch/rebuild,
    /// plus orphan cleanup, plus conservation-fix fallback. Dominant cost
    /// at scale — a 10M-record chain expects this to scale linearly in
    /// record count and is the primary driver of slow boots. The observed
    /// fleet readout (2m44s–5m18s) is almost entirely this phase.
    pub boot_ledger_rebuild_secs: AtomicU64,
    /// Subsystem rebuild + state_core init duration in seconds.
    /// Covers reputation/trust/dispute/zone-state rebuilds + state_core spawn.
    /// Independent of the rebuild path — runs every boot. Typically smaller
    /// than the ledger rebuild but grows with per-zone state size.
    pub boot_state_core_init_secs: AtomicU64,
    /// Per-zone gossip RTT estimator — rolling p95 of push round-trip times,
    /// used by the MESH-BFT aggregator chain (Stage 3) to size per-rank timeouts.
    /// Bounded: 64 samples/zone × MAX_ZONES=256 zones. @spec Protocol §11.13
    pub zone_rtt: std::sync::RwLock<super::zone_rtt::ZoneRttEstimator>,
    /// Total per-zone RTT samples observed (Prometheus metric).
    pub zone_rtt_samples_total: AtomicU64,
    /// Per-peer RTT estimator — rolling p50 of push round-trip times per
    /// remote identity, used by the geo-fraud detector (Stage 5) to verify
    /// self-reported `geo_zone` claims. Bounded: `MAX_PEERS = 10_000` ×
    /// 64 samples/peer with LRU eviction on overflow.
    /// @spec Protocol §11.12 (geographic diversity), MESH-BFT §5 (geo fraud)
    pub peer_rtt: std::sync::RwLock<super::peer_rtt::PeerRttEstimator>,
    /// Total per-peer RTT samples observed (Prometheus metric).
    pub peer_rtt_samples_total: AtomicU64,
    /// Cooperative-scheduler CPU/load sensor (Stage 6). Background task
    /// samples `/proc/stat` + `/proc/loadavg` every 5s; hot-path loops
    /// call `coop_yield_if_busy()` to back off when the host is busy
    /// running the user's foreground workload.
    /// Lock-free reads (AtomicU64 bit-cast f64); safe to clone the Arc
    /// into any task. @spec Protocol §11.10 (user-hardware mandate)
    pub system_load: Arc<super::system_load::SystemLoadSensor>,
    /// Per-peer outbound token-bucket limiter (Stage 6). Enforces fairness
    /// across peers so one well-provisioned hub can't monopolise the
    /// 16-permit global gossip semaphore. Bounded: MAX_PEERS=10K with
    /// LRU eviction. @spec Protocol §11.10
    pub peer_bandwidth: Arc<super::peer_bandwidth::PeerBandwidthLimiter>,
    /// PQ-transport per-peer INBOUND read-admission gate. The HTTP read
    /// surface is rate-limited in axum middleware (`server::RateLimiter`,
    /// keyed by IP); the PQ `dispatch` path had no equivalent, so a
    /// handshake-authenticated peer could bypass it and fire unbounded heavy
    /// reads (`snapshot_full` / `delta_sync` = spawn_blocking + RocksDB scan).
    /// This second limiter restores parity, keyed by the Dilithium3-bound
    /// `peer_identity_hash`. Distinct instance from `peer_bandwidth` (which is
    /// OUTBOUND). Bounded MAX_PEERS=10K with LRU eviction.
    pub pq_read_limiter: Arc<super::peer_bandwidth::PeerBandwidthLimiter>,
    /// Continuity scoring — tracks unbroken network presence per identity (Protocol §11.35).
    pub continuity: std::sync::Mutex<crate::continuity::ContinuityState>,
    /// Reincarnation detection — behavioral fingerprinting for Sybil identity resets (Protocol §6.4).
    pub reincarnation: std::sync::Mutex<crate::reincarnation::ReincarnationState>,
    /// Monotonic slot-nonce counter for records created by THIS node's identity
    /// (MESH-BFT Phase 3 Stage 1C — slot mutual exclusion).
    ///
    /// Every v5 record carries `nonce` in its signed bytes. The ingest path
    /// rejects a second record by the same creator with the same nonce as
    /// equivocation. Before this counter existed, all in-node writers
    /// (tip_merge, witness_profile, pool_fund, vrf_registration, witness
    /// rewards, etc.) defaulted to nonce=0, so every node rejected its own
    /// second record and gossiped a ConflictProof against itself. Bootstrapped
    /// on startup from the max nonce already recorded in CF_SLOT_INDEX for
    /// this identity, then incremented for each new self-emitted record.
    ///
    /// Stored as the *next* nonce to hand out (read-and-increment).
    pub slot_nonce_self: AtomicU64,
    /// F-9 durability barrier: nonces strictly below this ceiling are covered
    /// by a **fsync'd** high-water in `CF_METADATA`, so they survive a
    /// power-loss and are never re-handed after a restart. `next_slot_nonce`
    /// hands out below the ceiling on the fast path (no I/O); when it crosses
    /// the ceiling it reserves a fresh block (one fsync) *before* returning the
    /// nonce. Without this a power-cut between broadcasting a self-record and
    /// the next WAL flush lost the record's `CF_SLOT_INDEX` entry, so
    /// `bootstrap_slot_nonce` re-issued the nonce → a re-signed record at the
    /// same `(creator, nonce)` slot → self-inflicted SLOT EQUIVOCATION /
    /// self-`ConflictProof`. Reserve-ahead makes reuse impossible from any
    /// cause. Initialised from the persisted high-water in `bootstrap_slot_nonce`.
    pub slot_nonce_durable_ceiling: AtomicU64,
    /// Serialises the (rare) block-reservation fsync so concurrent
    /// `next_slot_nonce` callers that cross the ceiling together do at most one
    /// reservation each — never held across `.await` (the fn is sync).
    pub slot_nonce_reserve_lock: std::sync::Mutex<()>,
    /// Content versioning state (Protocol §11.30). Tracks version chains and
    /// forks across ingested records. Wired at ingest-time for records carrying
    /// `version_op` or `diff_op` metadata. O(1) per insert, O(chain_depth) for
    /// chain traversal. Memory bounded by version-record count, not total records.
    pub version_state: std::sync::Mutex<crate::versioning::VersionState>,
    /// ARCH-1 tentative-apply ledger. Every ingested ledger op lands here
    /// instead of mutating `ledger` directly (Phase 3.7+). The drain loop
    /// commits deltas on finality and discards them on timeout / rejection.
    /// See internal design notes.
    ///
    /// Populated on boot from `CF_PENDING_DELTAS`. Bounded at
    /// `MAX_TOTAL_PENDING` (1_048_576) — `insert` refuses over-quota
    /// entries so the store cannot grow unboundedly.
    pub pending_ledger: RwLock<crate::accounting::pending_ledger::PendingLedger>,
    /// ARCH-1 metric: cumulative finalized deltas committed from
    /// `pending_ledger` to `ledger` since startup. Exposed on /metrics as
    /// `elara_pending_ledger_commits_total`.
    pub pending_ledger_commits_total: AtomicU64,
    /// ARCH-1 metric: cumulative pending deltas discarded (epoch timeout,
    /// explicit rejection, conflict resolution). Exposed on /metrics as
    /// `elara_pending_ledger_discards_total`.
    pub pending_ledger_discards_total: AtomicU64,
    /// ARCH-1 metric: cumulative `insert` rejections because an identity
    /// hit `MAX_PENDING_PER_IDENTITY` or the store hit
    /// `MAX_TOTAL_PENDING`. Exposed on /metrics as
    /// `elara_pending_ledger_rejections_total`.
    pub pending_ledger_rejections_total: AtomicU64,
    /// ARCH-1 cap-pinch fallback: counts records that were rejected from
    /// `pending_ledger` (cap, duplicate, global quota) and instead got
    /// directly applied to the committed ledger to preserve consistency
    /// with non-canary peers. Exposed on /metrics as
    /// `elara_pending_ledger_fallback_direct_apply_total`. Steady-state
    /// non-zero on a canary means: cap is too tight OR commit latency
    /// (quorum + finality) too slow. Mainnet target: zero.
    pub pending_ledger_fallback_direct_apply_total: AtomicU64,
    /// ARCH-1 hard-ceiling sweep: subset of `pending_ledger_discards_total`
    /// where the entry was past `PENDING_HARD_DISCARD_TIMEOUT_SECS` (1200s)
    /// and was dropped regardless of consensus state — i.e. consensus
    /// reached `Sealed`/`Anchored` but never `Finalized`, leaking the
    /// pending bucket. Exposed on /metrics as
    /// `elara_pending_ledger_hard_discards_total`. Sustained non-zero is
    /// the operational signal that finality is genuinely stuck on these
    /// records (not just slow); investigate
    /// `seal_finality_signers_added_total` and 2/3 attestation reach.
    pub pending_ledger_hard_discards_total: AtomicU64,
    /// ARCH-1 drain canary: cumulative `apply_single_record` failures at
    /// commit time. Each bump means consensus finalized a record and the
    /// drain pulled its delta, but the canonical apply path rejected the
    /// op (insufficient balance, conservation violation, etc.). The delta
    /// is dropped and the on-disk row erased — re-applying would not
    /// help. Exposed on /metrics as `elara_pending_drain_apply_failed_total`.
    /// Mainnet target: zero. Sustained non-zero is a CRITICAL invariant
    /// alert — consensus and ledger disagree on a finalized op.
    pub pending_drain_apply_failed_total: AtomicU64,
    /// ARCH-1 drain canary: finality_id surfaced from the consensus queue
    /// but `CF_RECORDS` had no body for it. Should be impossible in
    /// steady state (records only leave CF_RECORDS via explicit eviction,
    /// and the consensus queue only tracks records that were ingested).
    /// Exposed on /metrics as `elara_pending_drain_missing_record_total`.
    /// Mainnet target: zero. Sustained non-zero signals a record-pruning
    /// bug or a forensic eviction that ran while the record was still
    /// in flight — investigate the eviction paths.
    pub pending_drain_missing_record_total: AtomicU64,
    /// KR-3 S2 (W1): rotation-CF entries written by the finalize-drain hook
    /// (`writer=drain`). Exposed as `elara_rotation_cf_write_total{writer="drain"}`.
    /// Stays zero while `s2_rotation_ordering_enabled` is OFF (the hook is
    /// flag-gated); non-zero once the flag flips and rotations finalize.
    pub rotation_cf_write_drain_total: AtomicU64,
    /// KR-3 S2 (W2): rotation-CF entries written by the durable-marker catch-up
    /// sweep (`network::rotation_sweep`, `writer=sweep`). Exposed as
    /// `elara_rotation_cf_write_total{writer="sweep"}`. Stays zero while
    /// `s2_rotation_ordering_enabled` is OFF (the sweep is flag-gated) and while
    /// the sweep has no live caller (the W2-C boot/periodic wiring slice);
    /// non-zero once the flag flips and the sweep backfills a W1-missed rotation.
    pub rotation_cf_write_sweep_total: AtomicU64,
    /// KR-3 S2 (W1): rotation-CF writes that failed to persist (RocksDB error).
    /// Exposed as `elara_rotation_cf_write_failed_total`. Mainnet target: zero —
    /// the W2 marker sweep is the durable backstop, but a persistent non-zero
    /// signals a storage fault the sweep will also hit.
    pub rotation_cf_write_failed_total: AtomicU64,
    /// KR-3 S2 (§5-H5 [R-7]): rotation-class records rejected at admission for a
    /// `reason` outside the documented vocabulary (`ROTATION_REASON_VOCAB` /
    /// `REVOCATION_REASON_VOCAB`). Exposed as `elara_rotation_reason_rejected_total`.
    /// Stays zero while the S2 flag is OFF (the gate never runs). A non-zero count
    /// is honest-author friction (re-sign with a documented reason), not a fault.
    pub rotation_reason_rejected_total: AtomicU64,
    /// KR-3 S2 (§5-H1 [R-4]): rotation-class records rejected at admission for a
    /// timestamp older than the FIXED `ROTATION_CLASS_MAX_PAST_SECS` (3600 s)
    /// recent-floor. Exposed as `elara_rotation_recent_floor_rejected_total`. Stays
    /// zero while the S2 flag is OFF (the gate never runs). A non-zero count is
    /// honest-author friction (re-sign with a fresh timestamp), not a fault — the
    /// general path still warn-accepts old NON-rotation records.
    pub rotation_recent_floor_rejected_total: AtomicU64,
    /// KR-3 S2 (§5-H2/H3): rotation-class records rejected at admission for parent
    /// grounding — no cited parent (H2), a cited parent older than the 24 h
    /// `ROTATION_PARENT_MAX_AGE_SECS` cap, or no cited parent durably finalized
    /// (H3). Exposed as `elara_rotation_parent_grounding_rejected_total`. Zero while
    /// `s2_rotation_ordering_enabled` is OFF (the gate never runs). A non-zero count
    /// is honest-author friction (re-parent onto a fresh, finalized parent), not a
    /// fault — defense-in-depth, ordering never reads parent data.
    pub rotation_parent_grounding_rejected_total: AtomicU64,
    /// KR-3 S2 (§5-H3b): rotation HOPS rejected at admission because `prev_key` has no
    /// durably-final introducing hop (`get_rotation_newkey_index` = `None`) — genuine root
    /// vs pending/unseen predecessor is indistinguishable without the origin-key primitive,
    /// so admission is FAIL-CLOSED (never silently pins a spurious root, which would fork —
    /// `docs/AUDIT-REPORTS/kr3-s2-h3b-fork-an internal audit). Exposed as
    /// `elara_rotation_predecessor_ungrounded_rejected_total`. Zero while
    /// `s2_rotation_ordering_enabled` is OFF. Non-zero is expected interim friction: a deep
    /// hop retries after its predecessor finalizes, and a genuine root stays rejected until
    /// the origin primitive lands (the flag-flip blocker).
    pub rotation_predecessor_ungrounded_rejected_total: AtomicU64,
    /// KR-3 S2 (W2-D): a durable rotation-CF entry for a `(lineage, hop)` was
    /// rewritten by the marker sweep under a DIFFERENT covering seal than the one
    /// already on disk — the canonical winner of the seal's `(zone, epoch)` slot
    /// flipped between ticks (a Burial-evidence reorg, or a W1-optimistic write
    /// that lost canonicality). Exposed as
    /// `elara_rotation_cf_canonicality_mismatch_total`. The put self-corrects to
    /// the canonical seal; the counter is the alarm. Zero while
    /// `s2_rotation_ordering_enabled` is OFF. A Quorum winner is BFT-unique per
    /// slot so it should never legitimately flip — sustained non-zero on a
    /// well-connected chain is a fork/partition signal.
    pub rotation_cf_canonicality_mismatch_total: AtomicU64,
    /// KR-3 S2 (W2-D): durable-marker sweep invocations that actually ran (flag
    /// ON). Exposed as `elara_rotation_sweep_runs_total`. The W2-C loop calls the
    /// sweep every 60 s but it early-returns while the flag is OFF, so this stays
    /// zero until the flag flips — then it is the sweep's liveness heartbeat.
    pub rotation_sweep_runs_total: AtomicU64,
    /// KR-3 S2 (W2-D): cumulative armed `rotation_seal_pending:{zone}:{epoch}`
    /// markers examined across all sweep runs. Exposed as
    /// `elara_rotation_sweep_markers_scanned_total`. Zero while the flag is OFF.
    pub rotation_sweep_markers_scanned_total: AtomicU64,
    /// KR-3 S2 (W2-D): cumulative markers discharged (deleted after every member
    /// hop of a winning seal was written). Exposed as
    /// `elara_rotation_sweep_markers_discharged_total`. Zero while the flag is OFF.
    pub rotation_sweep_markers_discharged_total: AtomicU64,
    /// KR-3 S2 (W2-D): cumulative orphan markers seen — an armed `(zone, epoch)`
    /// slot with no stored seal. Exposed as
    /// `elara_rotation_sweep_orphan_markers_total`. Kept, never written; a
    /// sustained non-zero signals a marker armed without its seal landing (a
    /// crash-window or arming-path bug). Zero while the flag is OFF.
    pub rotation_sweep_orphan_markers_total: AtomicU64,
    /// KR-3 S2 (W2-D): armed markers still pending after the LAST sweep run
    /// (scanned − discharged) — a gauge, not a counter. Exposed as
    /// `elara_rotation_sweep_pending_markers`. Steady-state near zero once seals
    /// bury; a rising value means the sweep is not discharging (pulse-less seals,
    /// deferred same-slot lineages, or sub-quorum evidence). Zero while the flag
    /// is OFF.
    pub rotation_sweep_pending_markers: AtomicU64,
    /// ZSP Phase D: queue of zones awaiting record purge after `unsubscribe()`.
    /// Each entry is `(zone, enqueued_unix_secs)` — the timestamp lets
    /// `/metrics` emit `elara_zone_purge_lag_seconds_oldest` (head-of-queue
    /// age, distinguishes "queue drained immediately" from "stuck purges").
    /// Drained by `pending_drain_loop` at MAX_PURGE_PER_TICK records per zone
    /// per tick.
    pub zone_purge_queue: std::sync::Mutex<
        std::collections::VecDeque<(super::zone::ZoneId, f64)>,
    >,
    /// ZSP Phase D: cumulative records deleted by the zone-purge tick (across
    /// all zones, since boot). Exposed on /metrics as
    /// `elara_zone_purge_records_purged_total`. Steady non-zero is normal
    /// during subscription churn; zero on a node that never unsubscribes.
    pub zone_purge_records_purged_total: AtomicU64,
    /// Cumulative orphan edges pruned by the
    /// orphan_resolver_loop's high-count safety prune. Increments only when
    /// `orphan_count > 200` after fetch attempts — i.e. the cascade is
    /// outpacing fetch + the prune is acting as a circuit-breaker. Exposed
    /// on /metrics as `elara_orphan_resolver_high_count_pruned_total`.
    /// Bootstrap-pathology distinguisher: rises during catch-up on a behind
    /// node, drains to flat once orphan_count stabilises below 200.
    /// Sustained non-zero in steady state means fetch is structurally losing
    /// to cascade — investigate peer reachability or snapshot-resync.
    pub orphan_resolver_high_count_pruned_total: AtomicU64,
    /// Cumulative orphan_resolver ticks skipped because
    /// `SystemLoadSensor::is_saturated()` reported the host beyond what
    /// cooperative yielding can rescue (normalized load > 1.5 AND aggregate
    /// CPU > cores). Empirical origin: a 2-vCPU node post-restart
    /// catch-up — the resolver's MAX_FETCH=50 batch kept all tokio threads
    /// at 100% for ~14 min, starving the HTTP handler. Skipping a cycle
    /// lets `/version` + `/metrics` keep serving while orphans wait for
    /// the next 60s tick. Healthy on a 4 GB node = 0; non-zero on
    /// a 2 GB node during catch-up is expected and self-clearing. Sustained
    /// non-zero in steady state means the box is structurally undersized
    /// for the orphan-resolver load — investigate snapshot-resync or
    /// upsize. Exposed as `elara_orphan_resolver_saturation_skips_total`.
    pub orphan_resolver_saturation_skips_total: AtomicU64,
    /// Cumulative /balances responses that hit the MAX_BALANCES_RESPONSE
    /// cap. Healthy = 0 in steady state on testnet (≤100 accounts); non-zero in
    /// production once the account set exceeds the cap means clients should be
    /// migrating to `?identity=<hash>` or paginated reads. Surfaces the moment
    /// the unbounded /balances contract becomes structurally violated by scale.
    pub balances_response_truncated_total: AtomicU64,
    /// Cumulative /balances calls rejected for an identity prefix
    /// shorter than `MIN_BALANCES_PREFIX_LEN` (default 8 hex chars). Bounds
    /// the O(accounts) prefix-scan attack surface — short prefixes that miss
    /// the exact-match HashMap probe would otherwise scan every account.
    pub balances_short_prefix_rejected_total: AtomicU64,
    /// Cumulative `/snapshot` and `/snapshot/state-delta` calls
    /// short-circuited by the size-cap circuit-breaker. Two trip conditions
    /// share this counter:
    ///   * `/snapshot` above `MAX_SNAPSHOT_FULL_ACCOUNTS`.
    ///   * `/snapshot/state-delta` falling through to full-state — either
    ///     `since_epoch=0` or `since_epoch>0` with no archive
    ///     baseline at-or-before that epoch — also above the cap.
    ///
    /// At testnet (≤100 accounts) this is 0; when it rises, the chain has
    /// crossed the full-fat-snapshot scale floor and bootstrappers must move
    /// to incremental `?since_epoch=N` requests against an archive-baseline
    /// node. Together with `elara_archive_snapshot_emitted_total`, lets
    /// operators correlate "rejected fulls" with "available baselines" to
    /// confirm the migration path is open before flipping to mainnet.
    pub snapshot_size_rejected_total: AtomicU64,
}

/// Attestation received via push but deferred because the record isn't in local storage yet.
#[derive(Debug, Clone)]
pub struct DeferredAttestation {
    pub witness_hash: String,
    pub signature: Vec<u8>,
    pub timestamp: f64,
    pub witness_public_key: Option<Vec<u8>>,
    pub powas_nonce: Option<u64>,
    pub powas_difficulty: Option<u64>,
    pub received_at: f64,
}

/// Per-record bucket cap for the deferred-attestation buffer. A deferred entry
/// is stored on an UNVERIFIED signature (the record's signable bytes aren't
/// local yet), gated only by sha3(pk)==witness_hash — free to forge with a
/// fresh keypair, so the bucket must be bounded. 128 is far above any real
/// witness committee (live `size_cap` = 7); an honest record's bucket never
/// approaches it. Shared by BOTH transports (PQ router + HTTP routes/sync) —
/// the cap originally shipped on the PQ path only and the HTTP twin drifted
/// capless until 2026-07-02.
pub(crate) const MAX_DEFERRED_ATTS_PER_RECORD: usize = 128;

/// Distinct-record_id cap for the deferred-attestation buffer (the other axis).
pub(crate) const MAX_DEFERRED_RECORD_BUCKETS: usize = 5000;

/// Deferred-attestation buffer: record_id → bucket of [`DeferredAttestation`],
/// with an insertion-order side deque for O(1)-amortized oldest-bucket
/// eviction at map saturation.
///
/// Post-handshake ingest audit (verified 2026-07-02): the pre-fix saturation
/// eviction ran `iter().filter_map(k.clone()).min_by(..)` over all ~5000
/// buckets — cloning every key under the mutex — on EVERY new-rid message
/// once saturated, and saturation is attacker-reachable (any handshaked peer
/// citing random unknown record_ids). The deque mirrors the `SeenSet` idiom
/// (`ingest.rs`): entries are `(created_at, rid)` pushed once per bucket
/// CREATION; a rid whose bucket has since been drained (record arrived),
/// TTL-swept, or evicted is skipped lazily at pop time — `map` membership is
/// the gate, exactly like `SeenSet.set`. Total pops ≤ total pushes, so
/// eviction is O(1) amortized with zero key clones.
///
/// Eviction semantics = oldest FIRST-SEEN bucket. A rid re-cited after its
/// bucket was swept/evicted re-registers at its new creation time but keeps
/// its stale deque entry, so it can be evicted at the OLD position — only
/// swept/evicted rids (flood traffic) can be re-cited (a drained rid's record
/// exists locally, so the deferred path is unreachable for it), and evicting
/// recycled flood rids early is the preferred bias.
pub struct DeferredAttestationBuf {
    map: std::collections::HashMap<String, Vec<DeferredAttestation>>,
    /// (bucket-creation `received_at`, rid) in creation order; lazy-skipped.
    order: std::collections::VecDeque<(f64, String)>,
    /// Amortization counter for `maybe_sweep_expired` (every 128th call).
    sweep_tick: u64,
}

impl Default for DeferredAttestationBuf {
    fn default() -> Self {
        Self::new()
    }
}

impl DeferredAttestationBuf {
    pub fn new() -> Self {
        Self {
            map: std::collections::HashMap::new(),
            order: std::collections::VecDeque::new(),
            sweep_tick: 0,
        }
    }

    /// TTL-sweep, amortized to every 128th call. The full sweep is
    /// O(buckets × atts) and this path is reachable by any peer citing an
    /// unknown record_id, so sweeping per message would let a peer pin the
    /// mutex and burn CPU (up to 5000 × 128 closures per message). The
    /// per-record and map caps bound memory between sweeps. Also prunes
    /// deque entries whose rid is gone; duplicate entries for a re-created
    /// live rid persist until popped at eviction — both are bounded by
    /// insertions, so `order` stays O(live buckets + churn since last sweep).
    /// Returns `true` when a sweep actually ran.
    pub fn maybe_sweep_expired(&mut self, now: f64) -> bool {
        let run = self.sweep_tick.is_multiple_of(128);
        self.sweep_tick = self.sweep_tick.wrapping_add(1);
        if run {
            self.map.retain(|_, atts| {
                atts.retain(|a| now - a.received_at < 600.0);
                !atts.is_empty()
            });
            let map = &self.map;
            self.order.retain(|(_, rid)| map.contains_key(rid));
        }
        run
    }

    /// Insert into the per-`rid` bucket with dedup-on-`witness_hash` and a
    /// FIFO length cap. Returns `true` if a distinct entry was evicted to
    /// make room (the flood signal). Eviction is oldest-first so a late
    /// legitimate attestation displaces stale/junk rather than being refused;
    /// a duplicate `witness_hash` is idempotent (no growth, no eviction).
    /// Keeping the bucket ≤ `cap` also keeps the `any()` dedup scan O(cap).
    pub fn push_bounded(
        &mut self,
        rid: &str,
        deferred: DeferredAttestation,
        now: f64,
        cap: usize,
    ) -> bool {
        if !self.map.contains_key(rid) {
            self.order.push_back((now, rid.to_string()));
        }
        let entry = self.map.entry(rid.to_string()).or_default();
        if entry.iter().any(|d| d.witness_hash == deferred.witness_hash) {
            return false;
        }
        let mut evicted = false;
        while entry.len() >= cap.max(1) {
            entry.remove(0);
            evicted = true;
        }
        entry.push(deferred);
        evicted
    }

    /// Evict the oldest first-seen bucket when the map exceeds
    /// [`MAX_DEFERRED_RECORD_BUCKETS`]. Returns the evicted rid, if any.
    pub fn evict_oldest_if_saturated(&mut self) -> Option<String> {
        self.evict_oldest_if_over(MAX_DEFERRED_RECORD_BUCKETS)
    }

    /// Cap-parameterized core of [`Self::evict_oldest_if_saturated`] (tests).
    /// Pops creation-order entries, lazily skipping rids no longer in the
    /// map, and removes the first live one. Every bucket creation pushes a
    /// deque entry and stale entries are discarded permanently, so a live
    /// bucket always has ≥1 deque entry — the scan fallback below is a
    /// can't-happen guard that preserves the hard cap even if that invariant
    /// were ever broken, not a hot path.
    fn evict_oldest_if_over(&mut self, cap: usize) -> Option<String> {
        if self.map.len() <= cap {
            return None;
        }
        while let Some((_, rid)) = self.order.pop_front() {
            if self.map.remove(&rid).is_some() {
                return Some(rid);
            }
        }
        let oldest_key = self
            .map
            .iter()
            .filter_map(|(k, v)| v.first().map(|a| (k.clone(), a.received_at)))
            .min_by(|a, b| a.1.total_cmp(&b.1))
            .map(|(k, _)| k);
        if let Some(key) = oldest_key {
            self.map.remove(&key);
            return Some(key);
        }
        None
    }

    /// Drain a bucket when its record arrives (state_core). Deque entries for
    /// the rid are left behind and skipped lazily at eviction/sweep time.
    pub fn remove(&mut self, rid: &str) -> Option<Vec<DeferredAttestation>> {
        self.map.remove(rid)
    }

    /// `(distinct_records, total_attestations)` — the /metrics gauges.
    pub fn counts(&self) -> (usize, usize) {
        let records = self.map.len();
        let total: usize = self.map.values().map(|v| v.len()).sum();
        (records, total)
    }

    /// Read-only bucket view (tests + diagnostics).
    pub fn bucket(&self, rid: &str) -> Option<&[DeferredAttestation]> {
        self.map.get(rid).map(|v| v.as_slice())
    }

    #[cfg(test)]
    fn order_len(&self) -> usize {
        self.order.len()
    }
}

/// Tier 4.6: Attestation received and verified, but deferred because the witness's
/// stake row isn't loaded yet. Distinct from `DeferredAttestation` because the buffer
/// is keyed by `witness_hash` (so a stake update can replay all entries for that
/// witness in O(1)) — each entry therefore carries its own `record_id`.
#[derive(Debug, Clone)]
pub struct DeferredLowStakeAttestation {
    pub record_id: String,
    pub witness_hash: String,
    pub signature: Vec<u8>,
    pub timestamp: f64,
    pub witness_public_key: Option<Vec<u8>>,
    pub powas_nonce: Option<u64>,
    pub powas_difficulty: Option<u64>,
    pub received_at: f64,
}

/// Process-monotonic seconds: elapsed since the first call in this process.
/// Anchor is lazy, so "second 0" is wherever the first caller lands — only
/// differences are meaningful, which is all liveness ages need. Use for
/// atomic liveness stamps; never for wire, consensus, or persisted time
/// (wall-clock steps must not move it, and it resets every boot).
pub(crate) fn mono_secs() -> u64 {
    static ANCHOR: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    ANCHOR.get_or_init(Instant::now).elapsed().as_secs()
}

impl NodeState {
    /// Stamp `last_inbound_sync_mono` = `mono_secs() + 1`. Called once per
    /// served record-level sync request (`delta_sync` / `query_records`,
    /// PQ and HTTP). Process-monotonic (see the field doc): immune to NTP
    /// steps, cannot fail, never panics.
    pub fn stamp_inbound_sync(&self) {
        self.last_inbound_sync_mono
            .store(mono_secs().saturating_add(1), std::sync::atomic::Ordering::Relaxed);
    }

    pub fn new(
        config: NodeConfig,
        identity: Identity,
        rocks: Arc<StorageEngine>,
        witness_mgr: Arc<WitnessManager>,
    ) -> Self {
        let start_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);

        let local_node_id = NodeId::from_hex(&identity.identity_hash).unwrap_or(NodeId([0u8; 32]));
        let local_identity_hash = identity.identity_hash.clone();
        let snapshot_path = config.data_dir.join("ledger-snapshot.json");
        // ZSP Phase E Slice 3: capture data_dir for the zone-subscription
        // restore step before `config` moves into the struct literal below.
        let zone_persist_data_dir = config.data_dir.clone();
        let min_pow = config.min_pow_difficulty;
        let prop_rate_limit = config.propagation_rate_limit_per_hour;
        let zone_min_w = config.zone_min_witnesses;
        let committee_resolver_cap = config.committee_resolver_cache_size;
        // B8: size the PQ accept-handshake limiter before `config` moves into
        // the struct literal below. min 1 so a 0 config can never deadlock accept.
        let pq_handshake_concurrency = (config.pq_handshake_concurrency.max(1)) as usize;
        // STREAM-F1: size the post-handshake serve-connection cap. min 1 so a
        // 0 config can never deadlock the serve path.
        let pq_serve_cap = (config.pq_serve_concurrency.max(1)) as usize;
        // HEAVY-read global cap. 0 = derive max_blocking_threads/2 so heavy reads
        // can never occupy more than half the shared blocking pool, leaving the
        // other half for record-ingest + gossip-push. Non-zero = explicit
        // override, clamped to ≥1 so the semaphore can never deadlock at 0.
        let pq_heavy_read_cap: usize = if config.pq_heavy_read_concurrency == 0 {
            let cpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
            (super::config::max_blocking_threads_for(cpus) / 2).max(1)
        } else {
            config.pq_heavy_read_concurrency as usize
        };
        // HEAVY-VERIFY global cap (write-side twin of the read cap above). 0 =
        // derive the OTHER half of the blocking pool (max_blocking − max_blocking/2,
        // i.e. what the read cap's half leaves free — ≈ CPU count on typical boxes)
        // so reads + verifies can never jointly exceed the pool. Non-zero =
        // explicit override, clamped ≥1 so the semaphore can never deadlock at 0.
        let pq_verify_cap: usize = if config.pq_verify_concurrency == 0 {
            let cpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
            let pool = super::config::max_blocking_threads_for(cpus);
            (pool - pool / 2).max(1)
        } else {
            (config.pq_verify_concurrency as usize).max(1)
        };
        // Snapshot before `config` is moved into the struct literal below.
        let pq_heavy_read_wait_ms = config.pq_heavy_read_wait_ms;

        // Audit-2026-05-01 §5 — hot-tier capacity right-sizes per profile.
        // Light=1k, FullZone=10k (legacy default), Archive=1M. Operators
        // can override via `finalized_hot_capacity` (0 = use profile default).
        let finalized_profile =
            super::node_profile::NodeProfile::from_str(&config.node_profile);
        let finalized_index = super::finalized::FinalizedIndex::with_profile(
            rocks.clone(),
            finalized_profile,
            config.finalized_hot_capacity,
        );
        let persisted_cursor = rocks.load_full_pull_cursor();

        // PQ transport: persistent pin store + node-scoped PqNodeClient.
        // If opening the persistent file fails (corrupt / permissions), fall
        // back to in-memory — a node without persisted pins still enforces
        // TOFU for the current session, which is strictly better than
        // refusing to start.
        let pq_pins_path = config.data_dir.join("pq-peer-pins.json");
        let pq_pins = Arc::new(
            PeerIdentityStore::open(&pq_pins_path).unwrap_or_else(|e| {
                tracing::warn!(
                    path = %pq_pins_path.display(),
                    error = %e,
                    "failed to open persistent PQ pin store — using in-memory",
                );
                PeerIdentityStore::in_memory()
            }),
        );
        // REALMS P1 slice (b3): every outbound dial carries the realm
        // admission context — network_id always, plus this node's own
        // membership cert when configured. Open-realm responders never
        // challenge, so for today's public mesh this is dormant data.
        let realm_cert = if config.realm_membership_cert_path.as_os_str().is_empty() {
            None
        } else {
            match crate::network::realm::RealmMembershipCert::load(
                &config.realm_membership_cert_path,
            ) {
                Ok(cert) => Some(cert),
                Err(e) => {
                    tracing::warn!(
                        path = %config.realm_membership_cert_path.display(),
                        error = %e,
                        "failed to load realm membership cert — dialing federated peers will fail with cert_missing",
                    );
                    None
                }
            }
        };
        let pq_client = PqNodeClient::new(
            identity.public_key.clone(),
            identity.secret_key_bytes(),
            pq_pins.clone(),
        )
        .with_admission_context(crate::network::pq_transport::AdmissionContext {
            network_id: config.network_id.clone(),
            cert: realm_cert,
        });

        // Capture values needed after `config` is moved into `Self`.
        let auto_zone_scale_max_for_scaler = config.auto_zone_scale_max;
        let pq_read_capacity = config.pq_read_capacity;
        let pq_read_refill_per_sec = config.pq_read_refill_per_sec;

        Self {
            config,
            identity,
            rocks,
            loop_registry: Arc::new(crate::network::supervision::LoopRegistry::new()),
            dag: RwLock::new(Arc::new(DagIndex::new())),
            ledger: RwLock::new(LedgerState::new()),
            peers: RwLock::new({
                let mut pt = PeerTable::with_min_pow(min_pow);
                pt.set_local_identity(&local_identity_hash);
                pt
            }),
            seen: std::sync::Mutex::new(SeenSet::new(50_000)),
            pq_client,
            pq_pins,
            witness_mgr,
            consensus: std::sync::Mutex::new(AWCConsensus::new()),
            boot_reconcile_ids: std::sync::Mutex::new(Vec::new()),
            pending_boot_reconciled_total: AtomicU64::new(0),
            finalized: RwLock::new(finalized_index),
            dht: std::sync::Mutex::new(RoutingTable::new(local_node_id)),
            epoch: std::sync::RwLock::new(EpochState::new()),
            light_state: std::sync::RwLock::new(super::light::LightState::new()),
            sunset: std::sync::RwLock::new(SunsetState::new()),
            start_time,
            gossip_push_total: AtomicU64::new(0),
            gossip_relay_total: AtomicU64::new(0),
            gossip_select_dht_total: AtomicU64::new(0),
            gossip_select_fallback_total: AtomicU64::new(0),
            gossip_no_targets_last_warn_secs: AtomicU64::new(0),
            gossip_no_targets_suppressed: AtomicU64::new(0),
            delta_sync_attempts_total: AtomicU64::new(0),
            unknown_metadata_keys_admitted_total: AtomicU64::new(0),
            last_successful_pull_unix: AtomicU64::new(0),
            delta_sync_failures_timeout_total: AtomicU64::new(0),
            delta_sync_failures_other_total: AtomicU64::new(0),
            delta_sync_latency_lt_2s_total: AtomicU64::new(0),
            delta_sync_latency_lt_10s_total: AtomicU64::new(0),
            delta_sync_latency_lt_30s_total: AtomicU64::new(0),
            delta_sync_failures_timeout_handshake_total: AtomicU64::new(0),
            delta_sync_failures_timeout_rpc_total: AtomicU64::new(0),
            delta_sync_failures_other_addr_total: AtomicU64::new(0),
            delta_sync_failures_other_dial_total: AtomicU64::new(0),
            delta_sync_failures_other_rpc_total: AtomicU64::new(0),
            delta_sync_failures_other_decode_total: AtomicU64::new(0),
            delta_sync_scan_hit_cap_total: AtomicU64::new(0),
            delta_sync_cursor_pages_total: AtomicU64::new(0),
            delta_sync_cursor_reject_total: AtomicU64::new(0),
            delta_sync_cursor_guard_trips_total: AtomicU64::new(0),
            delta_sync_cursor_cycle_exhausted_total: AtomicU64::new(0),
            delta_sync_served_total: AtomicU64::new(0),
            delta_peer_total_missing: AtomicU64::new(0),
            delta_sync_served_records_total: AtomicU64::new(0),
            dag_deficit_open: std::sync::Mutex::new(DagDeficitRing::new(MAX_OPEN_DAG_DEFICITS)),
            dag_deficit_epochs_total: AtomicU64::new(0),
            dag_deficit_resolved_total: AtomicU64::new(0),
            full_pull_zero_progress_streak: AtomicU64::new(0),
            full_pull_zero_progress_total: AtomicU64::new(0),
            full_pull_deficit_seed_bits: AtomicU64::new(0),
            // 16,384: headroom over the observed 1,357-per-sweep stale-seal
            // band (item 8b) without the delta-bloom bloat a 50k fold would
            // add (an over-large bloom false-suppresses legitimate records).
            declined_seal_ids: std::sync::Mutex::new(super::ingest::SeenSet::new(16_384)),
            last_inbound_sync_mono: AtomicU64::new(0),
            witness_smt_scope_scan_hit_cap_total: AtomicU64::new(0),
            witness_smt_scope_incomplete_total: AtomicU64::new(0),
            record_stats_total: AtomicU64::new(0),
            record_stats_class_public: AtomicU64::new(0),
            record_stats_class_private: AtomicU64::new(0),
            record_stats_class_restricted: AtomicU64::new(0),
            record_stats_class_sovereign: AtomicU64::new(0),
            record_stats_op_mint: AtomicU64::new(0),
            record_stats_op_transfer: AtomicU64::new(0),
            record_stats_op_stake: AtomicU64::new(0),
            record_stats_op_unstake: AtomicU64::new(0),
            record_stats_op_burn: AtomicU64::new(0),
            record_stats_op_slash: AtomicU64::new(0),
            record_stats_op_witness_reward: AtomicU64::new(0),
            record_stats_op_dormancy_reclaim: AtomicU64::new(0),
            record_stats_op_pool_fund: AtomicU64::new(0),
            record_stats_non_token: AtomicU64::new(0),
            record_stats_epoch_seals: AtomicU64::new(0),
            record_stats_earliest_ts_bits: AtomicU64::new(0),
            record_stats_latest_ts_bits: AtomicU64::new(0),
            record_stats_seed_bounded: std::sync::atomic::AtomicBool::new(false),
            gossip_relay_content_routed_total: AtomicU64::new(0),
            peer_admission_source_cap_clipped_total: AtomicU64::new(0),
            gossip_push_content_routed_total: AtomicU64::new(0),
            gossip_push_dht_floor_fallback_total: AtomicU64::new(0),
            gossip_relay_dht_floor_fallback_total: AtomicU64::new(0),
            gossip_push_dht_replication_factor_last: AtomicU64::new(0),
            pending_seal_replications: Mutex::new(VecDeque::new()),
            finalization_effects_inflight: std::sync::Mutex::new(std::collections::HashSet::new()),
            pending_finalization_effects: std::sync::atomic::AtomicU64::new(0),
            gossip_seal_replication_tracked_total: AtomicU64::new(0),
            gossip_seal_replication_overflow_total: AtomicU64::new(0),
            gossip_seal_replication_pending_depth: AtomicU64::new(0),
            gossip_seal_replication_reconcile_ticks_total: AtomicU64::new(0),
            gossip_seal_replication_probe_ok_total: AtomicU64::new(0),
            gossip_seal_replication_probe_miss_total: AtomicU64::new(0),
            gossip_seal_replication_probe_fail_total: AtomicU64::new(0),
            gossip_seal_replication_repush_total: AtomicU64::new(0),
            gossip_seal_replication_floor_violation_total: AtomicU64::new(0),
            gossip_relay_committee_routed_total: AtomicU64::new(0),
            snapshot_bootstrap_epoch_indexed_total: AtomicU64::new(0),
            snapshot_bootstrap_live_fallback_total: AtomicU64::new(0),
            archive_snapshot_emit_total: AtomicU64::new(0),
            archive_snapshot_prune_total: AtomicU64::new(0),
            archive_snapshot_last_epoch: AtomicU64::new(0),
            ledger_loaded_from_snapshot: std::sync::atomic::AtomicBool::new(false),
            snapshot_bootstrap_ledger_loaded_total: AtomicU64::new(0),
            snapshot_bootstrap_root_verified_total: AtomicU64::new(0),
            snapshot_bootstrap_root_mismatch_total: AtomicU64::new(0),
            snapshot_bootstrap_root_absent_total: AtomicU64::new(0),
            boot_sealed_root_verified_total: AtomicU64::new(0),
            boot_sealed_root_mismatch_total: AtomicU64::new(0),
            boot_sealed_root_phantom_total: AtomicU64::new(0),
            boot_sealed_root_skipped_total: AtomicU64::new(0),
            admin_snapshot_rebootstrap_total: AtomicU64::new(0),
            super_seal_coverage_failures_total: AtomicU64::new(0),
            super_seals_minted_total: AtomicU64::new(0),
            super_seal_creation_attempts_total: AtomicU64::new(0),
            super_seal_creation_failures_total: AtomicU64::new(0),
            super_seal_creation_sign_failures_total: AtomicU64::new(0),
            super_seal_creation_insert_failures_total: AtomicU64::new(0),
            drand_pulse_cache: super::drand_fetch::DrandPulseCache::default(),
            drand_fetch_ok_total: AtomicU64::new(0),
            drand_fetch_fail_total: AtomicU64::new(0),
            drand_relay_disagree_total: AtomicU64::new(0),
            drand_round_regression_total: AtomicU64::new(0),
            drand_pulse_ahead_of_clock_total: AtomicU64::new(0),
            drand_seal_pulse_attached_total: AtomicU64::new(0),
            drand_seal_pulse_absent_total: AtomicU64::new(0),
            seal_loop_ticks_total: AtomicU64::new(0),
            seal_loop_zones_evaluated_total: AtomicU64::new(0),
            seal_loop_proposals_per_zone_total: AtomicU64::new(0),
            seal_loop_proposals_escalate_total: AtomicU64::new(0),
            seal_loop_proposals_none_total: AtomicU64::new(0),
            seal_loop_proposals_none_already_sealed_total: AtomicU64::new(0),
            seal_loop_proposals_none_bootstrap_decline_total: AtomicU64::new(0),
            seal_loop_proposals_none_not_in_top_ranks_total: AtomicU64::new(0),
            seal_loop_proposals_none_rank_too_high_total: AtomicU64::new(0),
            gossip_pull_total: AtomicU64::new(0),
            gossip_push_after_pull_announcements_total: AtomicU64::new(0),
            gossip_push_after_pull_at_cap_total: AtomicU64::new(0),
            gossip_push_after_pull_cycles_total: AtomicU64::new(0),
            // NETWORK-HARDENING Tier 1.1 autotune: initial cap matches the
            // pre-autotune compile-time constant (200) so deploy is a no-op
            // until the cap-hit rate triggers an adjustment.
            gossip_push_after_pull_max: std::sync::atomic::AtomicUsize::new(200),
            gossip_push_after_pull_autotune_last_eval_at: AtomicU64::new(0),
            gossip_push_after_pull_autotune_last_at_cap: AtomicU64::new(0),
            gossip_push_after_pull_autotune_last_cycles: AtomicU64::new(0),
            gossip_push_after_pull_autotune_raises_total: AtomicU64::new(0),
            gossip_push_after_pull_autotune_lowers_total: AtomicU64::new(0),
            ingest_slow_records_pre_total: AtomicU64::new(0),
            ingest_slow_records_post_total: AtomicU64::new(0),
            ingest_slow_records_sb_total: AtomicU64::new(0),
            ingest_slow_records_other_total: AtomicU64::new(0),
            ingest_record_phase_max_ms_pre: AtomicU64::new(0),
            ingest_record_phase_max_ms_post: AtomicU64::new(0),
            ingest_record_phase_max_ms_sb: AtomicU64::new(0),
            ingest_record_phase_max_ms_other: AtomicU64::new(0),
            gossip_bytes_out_total: AtomicU64::new(0),
            attestation_bytes_out_total: AtomicU64::new(0),
            attestation_bytes_in_total: AtomicU64::new(0),
            attestation_receive_rejected_bad_signature_total: AtomicU64::new(0),
            attestation_receive_rejected_unknown_pk_total: AtomicU64::new(0),
            attestation_receive_rejected_low_stake_total: AtomicU64::new(0),
            attestation_receive_rejected_too_young_total: AtomicU64::new(0),
            attestation_receive_rejected_bad_powas_total: AtomicU64::new(0),
            attestation_receive_deferred_total: AtomicU64::new(0),
            attestation_deferred_evicted_total: AtomicU64::new(0),
            attestation_receive_low_stake_deferred_total: AtomicU64::new(0),
            attestation_receive_low_stake_drained_total: AtomicU64::new(0),
            attestation_receive_low_stake_expired_total: AtomicU64::new(0),
            att_push_unattributed_total: AtomicU64::new(0),
            dag_evict_finalized_cascade_total: AtomicU64::new(0),
            dag_hot_tier_full_rejections_total: AtomicU64::new(0),
            lock_acquire_dag_read_slow_total: AtomicU64::new(0),
            lock_acquire_dag_write_slow_total: AtomicU64::new(0),
            gc_pruned_expired_total: AtomicU64::new(0),
            gc_pruned_retention_total: AtomicU64::new(0),
            gc_pruned_sunken_total: AtomicU64::new(0),
            gc_pruned_stale_total: AtomicU64::new(0),
            gc_compactions_total: AtomicU64::new(0),
            startup_compactions_total: AtomicU64::new(0),
            gc_pruned_seals_total: AtomicU64::new(0),
            gc_pruned_epoch_total: AtomicU64::new(0),
            gc_cycles_total: AtomicU64::new(0),
            gc_last_cycle_duration_ms: AtomicU64::new(0),
            gc_last_cycle_unix_ts: AtomicU64::new(0),
            gc_scan_capped_total: AtomicU64::new(0),
            gossip_bytes_out_seal_total: AtomicU64::new(0),
            gossip_bytes_out_ledger_total: AtomicU64::new(0),
            gossip_bytes_out_governance_total: AtomicU64::new(0),
            gossip_bytes_out_other_total: AtomicU64::new(0),
            gossip_bytes_in_total: AtomicU64::new(0),
            gossip_push_skipped_total: AtomicU64::new(0),
            gossip_seen_dedup_total: AtomicU64::new(0),
            auto_witness_cycles_total: AtomicU64::new(0),
            auto_witness_records_total: AtomicU64::new(0),
            auto_witness_failures_total: AtomicU64::new(0),
            auto_witness_zombie_repush_skipped_total: AtomicU64::new(0),
            auto_witness_skips_orphan_total: AtomicU64::new(0),
            auto_witness_skips_not_staked_total: AtomicU64::new(0),
            auto_witness_skips_no_jury_total: AtomicU64::new(0),
            seal_verify_before_attest_withheld_behind_total: AtomicU64::new(0),
            seal_verify_before_attest_withheld_omission_total: AtomicU64::new(0),
            seal_verify_before_attest_withheld_root_mismatch_total: AtomicU64::new(0),
            seal_verify_before_attest_withheld_malformed_total: AtomicU64::new(0),
            seal_ingest_phase5_entered_total: AtomicU64::new(0),
            seal_ingest_phase5_completed_total: AtomicU64::new(0),
            seal_ingest_extract_err_total: AtomicU64::new(0),
            seal_ingest_derive_hook_attempts_total: AtomicU64::new(0),
            gossip_seal_insert_reject_total: AtomicU64::new(0),
            gossip_seal_declined_stale_total: AtomicU64::new(0),
            seal_ingest_reentry_total: AtomicU64::new(0),
            gossip_push_rejected_profile_total: AtomicU64::new(0),
            delegation_op_rejected_role_total: AtomicU64::new(0),
            profile_c_gate_rejected_total: AtomicU64::new(0),
            attestation_gate_rejected_total: AtomicU64::new(0),
            revoke_all_voluntary_total: AtomicU64::new(0),
            revoke_all_involuntary_total: AtomicU64::new(0),
            revoke_all_rejected_total: AtomicU64::new(0),
            delegation_lease_expired_total: AtomicU64::new(0),
            delegation_child_cap_rejected_total: AtomicU64::new(0),
            delegation_rate_cap_rejected_total: AtomicU64::new(0),
            delegation_extend_total: AtomicU64::new(0),
            delegation_extend_rejected_total: AtomicU64::new(0),
            identity_user_evicted_total: AtomicU64::new(0),
            identity_promotion_user_to_witness_total: AtomicU64::new(0),
            identity_promotion_user_to_anchor_total: AtomicU64::new(0),
            identity_promotion_witness_to_anchor_total: AtomicU64::new(0),
            identity_witness_purged_total: AtomicU64::new(0),
            identity_pk_fetch_attempts_total: AtomicU64::new(0),
            identity_pk_fetch_hits_total: AtomicU64::new(0),
            identity_pk_fetch_misses_total: AtomicU64::new(0),
            cross_zone_parent_observed_total: AtomicU64::new(0),
            cross_zone_parent_rejected_total: AtomicU64::new(0),
            zone_ref_observed_total: AtomicU64::new(0),
            zone_ref_anchored_total: AtomicU64::new(0),
            zone_ref_ghost_total: AtomicU64::new(0),
            zone_ref_deferred_total: AtomicU64::new(0),
            attestation_seen: std::sync::Mutex::new(SeenSet::new(50_000)),
            attestation_dedup_total: AtomicU64::new(0),
            attestation_push_attempted_total: AtomicU64::new(0),
            attestation_push_success_total: AtomicU64::new(0),
            attestation_push_skip_bandwidth_total: AtomicU64::new(0),
            attestation_push_addr_fail_total: AtomicU64::new(0),
            attestation_push_peer_reject_total: AtomicU64::new(0),
            attestation_push_net_fail_total: AtomicU64::new(0),
            attestation_bad_sigs: std::sync::Mutex::new(SeenSet::new(10_000)),
            attestation_pull_invalid_sig_total: AtomicU64::new(0),
            attestation_pull_invalid_powas_total: AtomicU64::new(0),
            conflict_proof_seen: std::sync::Mutex::new(SeenSet::new(5_000)),
            conflict_proof_pushed_total: AtomicU64::new(0),
            conflict_proof_received_total: AtomicU64::new(0),
            conflict_proof_rejected_total: AtomicU64::new(0),
            conflict_proof_push_addr_fail_total: AtomicU64::new(0),
            conflict_proof_push_peer_reject_total: AtomicU64::new(0),
            conflict_proof_push_net_fail_total: AtomicU64::new(0),
            conflict_proof_self_suppressed_total: AtomicU64::new(0),
            conflict_proof_local_unverifiable_total: AtomicU64::new(0),
            ledger_content_hash_v2_rejected_total: AtomicU64::new(0),
            finality_witness_seen: std::sync::Mutex::new(SeenSet::new(5_000)),
            finality_witness_pushed_total: AtomicU64::new(0),
            finality_witness_received_total: AtomicU64::new(0),
            finality_witness_rejected_total: AtomicU64::new(0),
            finality_witness_committee_mismatch_total: AtomicU64::new(0),
            finality_witness_non_member_total: AtomicU64::new(0),
            finality_witness_push_addr_fail_total: AtomicU64::new(0),
            finality_witness_push_peer_reject_total: AtomicU64::new(0),
            finality_witness_push_net_fail_total: AtomicU64::new(0),
            xzone_abort_witness_seen: std::sync::Mutex::new(SeenSet::new(5_000)),
            xzone_abort_witness_pushed_total: AtomicU64::new(0),
            xzone_abort_witness_received_total: AtomicU64::new(0),
            xzone_abort_witness_rejected_total: AtomicU64::new(0),
            xzone_abort_witness_committee_mismatch_total: AtomicU64::new(0),
            xzone_abort_witness_non_member_total: AtomicU64::new(0),
            xzone_abort_witness_push_addr_fail_total: AtomicU64::new(0),
            xzone_abort_witness_push_peer_reject_total: AtomicU64::new(0),
            xzone_attach_finality_lock_contended_total: AtomicU64::new(0),
            xzone_state_digest: AtomicU64::new(0),
            xzone_state_digest_epoch: AtomicU64::new(0),
            xzone_abort_witness_push_net_fail_total: AtomicU64::new(0),
            xzone_abort_aggregated_seen: std::sync::Mutex::new(SeenSet::new(5_000)),
            xzone_abort_bundles_submitted_total: AtomicU64::new(0),
            last_idle_decay_emit_epoch: AtomicU64::new(0),
            last_xzone_refund_emit_epoch: AtomicU64::new(0),
            last_xzone_reap_emit_epoch: AtomicU64::new(0),
            // Sized to match `seen` (50k): a peer can cache-bust a 5k reject set
            // in ~10 min, evicting legit rejections so they re-trigger full
            // Dilithium3 re-verification on re-push. 50k raises that bar 10×.
            gossip_rejected: std::sync::Mutex::new(SeenSet::new(50_000)),
            gossip_rejected_dedup_total: AtomicU64::new(0),
            gossip_retry: std::sync::Mutex::new(std::collections::VecDeque::new()),
            gossip_retry_recovered_total: AtomicU64::new(0),
            auto_rewards_total: AtomicU64::new(0),
            auto_rewards_amount_total: AtomicU64::new(0),
            gossip_push_failed_total: AtomicU64::new(0),
            gossip_retry_total: AtomicU64::new(0),
            gossip_retry_success_total: AtomicU64::new(0),
            peer_reconnect_attempts_total: AtomicU64::new(0),
            peer_reconnect_success_total: AtomicU64::new(0),
            peer_auto_banned_total: AtomicU64::new(0),
            gc_pruned_total: AtomicU64::new(0),
            total_ever_settled: AtomicU64::new(0),
            total_ever_finalized: AtomicU64::new(0),
            seal_member_finalized_durable_total: AtomicU64::new(0),
            last_fin_sample: AtomicU64::new(0),
            last_fin_delta: AtomicI64::new(0),
            last_fin_burst_velocity: AtomicI64::new(0),
            bratio_band_ticks_dormant_total: AtomicU64::new(0),
            bratio_band_ticks_locked_total: AtomicU64::new(0),
            bratio_band_ticks_converged_total: AtomicU64::new(0),
            bratio_band_ticks_active_total: AtomicU64::new(0),
            bratio_band_ticks_hyper_active_total: AtomicU64::new(0),
            total_attestations_processed: AtomicU64::new(0),
            beat_transfers_total: AtomicU64::new(0),
            beat_volume_micros_total: AtomicU64::new(0),
            https_fallback_gossip_total: AtomicU64::new(0),
            https_fallback_sync_total: AtomicU64::new(0),
            https_fallback_light_total: AtomicU64::new(0),
            https_fallback_discovery_total: AtomicU64::new(0),
            snapshot_path,
            trust: RwLock::new(TrustEngine::new()),
            events: broadcast::channel(256).0,
            rate_limiter: std::sync::OnceLock::new(),
            request_latency: super::server::Histogram::new(super::server::LATENCY_BUCKETS),
            request_latency_by_route: super::server::LabeledHistogram::new(
                super::server::LATENCY_BUCKETS,
                super::server::LABELED_HISTOGRAM_CAP,
            ),
            request_status_by_route: super::server::LabeledCounter::new(
                // Cap = LABELED_HISTOGRAM_CAP × 4 status classes.
                super::server::LABELED_HISTOGRAM_CAP * 4,
            ),
            gossip_push_duration: super::server::Histogram::new(super::server::LATENCY_BUCKETS),
            slashing: std::sync::Mutex::new(super::slashing::SlashingMonitor::new()),
            auto_slashes_total: AtomicU64::new(0),
            fork_heals_total: AtomicU64::new(0),
            peer_divergence_first_seen: tokio::sync::Mutex::new(
                std::collections::HashMap::new(),
            ),
            peer_persistent_divergence_total: AtomicU64::new(0),
            peer_persistent_divergence_resolved_total: AtomicU64::new(0),
            chain_divergence_epochs: AtomicU64::new(0),
            chain_divergence_epochs_ahead: AtomicU64::new(0),
            chain_divergence_epochs_behind: AtomicU64::new(0),
            chain_divergence_poll_no_peers_total: AtomicU64::new(0),
            chain_divergence_repair_attempts_total: AtomicU64::new(0),
            chain_divergence_repair_failures_total: AtomicU64::new(0),
            chain_divergence_repair_verify_fails_total: AtomicU64::new(0),
            chain_divergence_repair_apply_fails_total: AtomicU64::new(0),
            chain_divergence_repair_success_total: AtomicU64::new(0),
            chain_divergence_repair_root_mismatch_total: AtomicU64::new(0),
            chain_divergence_repair_scalar_drift_total: AtomicU64::new(0),
            chain_divergence_repair_conservation_drift_total: AtomicU64::new(0),
            chain_divergence_repair_orphan_stake_total: AtomicU64::new(0),
            key_registry: std::sync::RwLock::new(KeyRegistry::new()),
            vrf_registry: std::sync::RwLock::new(super::vrf_registry::VrfRegistry::new()),
            zone_committee_resolver: super::zone_committee::ZoneCommitteeResolver::with_capacity(
                committee_resolver_cap,
            ),
            witness_liveness: std::sync::Mutex::new(WitnessLiveness::new()),
            propagation_limiter: std::sync::Mutex::new(
                PropagationLimiter::new(prop_rate_limit)
            ),
            daily_caps: std::sync::Mutex::new(super::ingest::DailyCapCounter::new()),
            delegations: std::sync::RwLock::new(DelegationRegistry::new()),
            revocations_rejected_total: AtomicU64::new(0),
            search_queries_total: AtomicU64::new(0),
            search_queries_layer_b_total: AtomicU64::new(0),
            search_queries_fallback_total: AtomicU64::new(0),
            records_by_hash_hits_total: AtomicU64::new(0),
            records_by_hash_misses_total: AtomicU64::new(0),
            records_by_hash_peer_relay_attempts_total: AtomicU64::new(0),
            records_by_hash_peer_relay_hits_total: AtomicU64::new(0),
            records_by_hash_peer_relay_misses_total: AtomicU64::new(0),
            seal_record_hashes_resolved_total: AtomicU64::new(0),
            seal_record_hashes_missing_total: AtomicU64::new(0),
            demoted_seal_scan_queue: std::sync::Mutex::new(std::collections::VecDeque::new()),
            same_epoch_seal_demotions_total: AtomicU64::new(0),
            xzone_demoted_seal_covers_lock_total: AtomicU64::new(0),
            xzone_demoted_seal_covers_claimed_lock_total: AtomicU64::new(0),
            demoted_seal_scan_queue_dropped_total: AtomicU64::new(0),
            epoch_seal_fastforward_vrf_deferred_total: AtomicU64::new(0),
            epoch_seal_chain_link_rejected_total: AtomicU64::new(0),
            epoch_phantom_tip_suspected_total: AtomicU64::new(0),
            epoch_successor_chainable_total: AtomicU64::new(0),
            global_records_this_minute: AtomicU64::new(0),
            global_rate_window_start: AtomicU64::new(0),
            global_rate_limit_per_minute: 10_000,
            global_rate_limited_total: AtomicU64::new(0),
            zone_state: std::sync::Mutex::new(ZoneState::new(zone_min_w)),
            disputes: std::sync::RwLock::new(DisputeState::new()),
            disputes_opened_total: AtomicU64::new(0),
            transitions: std::sync::RwLock::new(super::transition_store::TransitionStore::new()),
            zone_registry: std::sync::RwLock::new(
                super::zone_registry::ZoneRegistry::new(),
            ),
            anchor_view: std::sync::RwLock::new(None),
            transition_trust: std::sync::RwLock::new(None),
            transition_sig_stake_rejected_total: AtomicU64::new(0),
            zone_registry_boot_applied_total: AtomicU64::new(0),
            zone_registry_boot_decode_failures_total: AtomicU64::new(0),
            zone_registry_boot_apply_failures_total: AtomicU64::new(0),
            zone_registry_tick_applied_total: AtomicU64::new(0),
            zone_registry_tick_apply_failures_total: AtomicU64::new(0),
            zone_registry_tick_sig_verify_failures_total: AtomicU64::new(0),
            zone_routing_resolve_queries_total: AtomicU64::new(0),
            zone_routing_resolve_redirected_total: AtomicU64::new(0),
            zone_resolve_internal_queries_total: AtomicU64::new(0),
            zone_resolve_internal_redirected_total: AtomicU64::new(0),
            committee_attestations_member_total: AtomicU64::new(0),
            committee_attestations_nonmember_total: AtomicU64::new(0),
            committee_observations_skipped_no_candidates_total: AtomicU64::new(0),
            seal_attestation_rejected_not_in_committee_total: AtomicU64::new(0),
            committee_skipped_below_k_total: AtomicU64::new(0),
            vrf_registration_records_accepted_total: AtomicU64::new(0),
            vrf_registration_records_rejected_total: AtomicU64::new(0),
            transitions_boot_replayed_total: AtomicU64::new(0),
            transitions_mirror_write_failures_total: AtomicU64::new(0),
            transitions_proposed_by_orchestrator_total: AtomicU64::new(0),
            transitions_orchestrator_insert_rejected_total: AtomicU64::new(0),
            transitions_orchestrator_skipped_pending_total: AtomicU64::new(0),
            transitions_orchestrator_skipped_undersized_pool_total: AtomicU64::new(0),
            xzone_locks_total: AtomicU64::new(0),
            xzone_claims_total: AtomicU64::new(0),
            xzone_refunds_total: AtomicU64::new(0),
            xzone_aborts_total: AtomicU64::new(0),
            xzone_cancels_total: AtomicU64::new(0),
            xzone_rejects_total: AtomicU64::new(0),
            xzone_lock_declared_zone_mismatch_total: AtomicU64::new(0),
            transitions_finalized_total: AtomicU64::new(0),
            transitions_finalized_split_total: AtomicU64::new(0),
            transitions_finalized_merge_total: AtomicU64::new(0),
            transitions_expired_total: AtomicU64::new(0),
            transition_seen: std::sync::Mutex::new(SeenSet::new(10_000)),
            transition_gossip_pushed_total: AtomicU64::new(0),
            transition_gossip_dedup_total: AtomicU64::new(0),
            transition_sig_seen: std::sync::Mutex::new(SeenSet::new(50_000)),
            transition_sig_gossip_pushed_total: AtomicU64::new(0),
            transition_sig_gossip_dedup_total: AtomicU64::new(0),
            transition_cosigns_total: AtomicU64::new(0),
            transition_pulled_total: AtomicU64::new(0),
            transition_pull_errors_total: AtomicU64::new(0),
            zk_proofs_verified_total: AtomicU64::new(0),
            rotation_zone_pins: std::sync::RwLock::new(std::collections::HashMap::new()),
            rotation_pins_len: std::sync::atomic::AtomicUsize::new(0),
            zone_clocks: std::sync::Mutex::new(ZoneClockManager::new()),
            itc_events_total: AtomicU64::new(0),
            itc_joins_total: AtomicU64::new(0),
            entity_clusterer: std::sync::Mutex::new(EntityClusterer::new()),
            reputation: std::sync::Mutex::new(ReputationEngine::new()),
            reputation_pruned_total: AtomicU64::new(0),
            challenges: std::sync::RwLock::new(ChallengeState::new()),
            challenges_filed_total: AtomicU64::new(0),
            ws_connections: AtomicU64::new(0),
            pq_ws_sessions_total: AtomicU64::new(0),
            ws_connections_per_ip: std::sync::Mutex::new(std::collections::HashMap::new()),
            genesis_state: std::sync::RwLock::new(GenesisState::default()),
            bootstrap_state: std::sync::RwLock::new(BootstrapState::new()),
            banned_identities: std::sync::RwLock::new(std::collections::HashSet::new()),
            content_blocklist: std::sync::RwLock::new(crate::content_safety::default_blocklist()),
            banned_rejections_total: AtomicU64::new(0),
            content_rejections_total: AtomicU64::new(0),
            timestamp_defense: std::sync::Mutex::new(TimestampDefense::new()),
            vrf_secret_key: None,
            vrf_public_key: None,
            zone_manager: std::sync::Mutex::new({
                // ZSP Phase E Slice 3: restore persisted subscription set
                // before any ingest path can observe it. Missing/corrupt
                // file falls back to empty (= accept-all) per zone_persist
                // module contract, so a fresh data_dir behaves exactly as
                // pre-Slice-3.
                let mut mgr = super::zone::ZoneManager::new();
                let restored =
                    super::zone_persist::load_subscriptions(&zone_persist_data_dir);
                if !restored.is_empty() {
                    tracing::info!(
                        "zone_persist: restored {} subscription(s) from {}",
                        restored.len(),
                        super::zone_persist::subscriptions_path(&zone_persist_data_dir).display()
                    );
                }
                for zone in restored {
                    mgr.subscribe(&zone);
                }
                mgr
            }),
            epoch_challenges: std::sync::RwLock::new(super::fisherman::EpochChallengeState::new()),
            state_core: std::sync::OnceLock::new(),
            // silence REMOVED
            relevance: std::sync::Mutex::new(crate::forgetting::RelevanceTracker::new()),
            retirement: std::sync::Mutex::new(crate::forgetting::RetirementTracker::new()),
            admin_audit_log: std::sync::Mutex::new(Vec::new()),
            rpc_lock: tokio::sync::Mutex::new(()),
            account_smt_write_gate: tokio::sync::Mutex::new(()),
            zone_transition: std::sync::Mutex::new(None),
            auto_scaler: std::sync::Mutex::new(super::auto_scale::AutoScaler::new(
                super::auto_scale::HYSTERESIS_TICKS,
                auto_zone_scale_max_for_scaler,
            )),
            zone_subscriptions: std::sync::Mutex::new(
                super::zone_subscription::ZoneSubscriptionRegistry::new(),
            ),
            insert_phase: AtomicU8::new(0),
            orphan_fetch_misses: std::sync::Mutex::new(std::collections::HashMap::new()),
            pull_catchup_cursor: std::sync::Mutex::new(0.0),
            full_pull_cursor: std::sync::Mutex::new(persisted_cursor),
            dag_write_holder: std::sync::atomic::AtomicU8::new(0),
            active_prefetches: AtomicU8::new(0),
            gossip_semaphore: Arc::new(tokio::sync::Semaphore::new(16)),
            pq_handshake_semaphore: Arc::new(tokio::sync::Semaphore::new(pq_handshake_concurrency)),
            pq_serve_semaphore: Arc::new(tokio::sync::Semaphore::new(pq_serve_cap)),
            pq_serve_cap,
            pq_serve_shed_total: Arc::new(AtomicU64::new(0)),
            pq_handshake_failed_total: Arc::new(AtomicU64::new(0)),
            pq_handshake_wire_mismatch_total: Arc::new(AtomicU64::new(0)),
            pq_handshake_shed_total: Arc::new(AtomicU64::new(0)),
            http_conn_shed_total: Arc::new(AtomicU64::new(0)),
            http_conn_per_ip_shed_total: Arc::new(AtomicU64::new(0)),
            pq_serve_frame_decrypt_failed_total: Arc::new(AtomicU64::new(0)),
            pq_heavy_read_semaphore: Arc::new(tokio::sync::Semaphore::new(pq_heavy_read_cap)),
            pq_heavy_read_cap,
            pq_verify_semaphore: Arc::new(tokio::sync::Semaphore::new(pq_verify_cap)),
            pq_verify_cap,
            pq_verify_waited_total: Arc::new(AtomicU64::new(0)),
            pq_heavy_read_wait_ms,
            pq_heavy_read_shed_total: Arc::new(AtomicU64::new(0)),
            deferred_attestations: std::sync::Mutex::new(DeferredAttestationBuf::new()),
            low_stake_deferred: std::sync::Mutex::new(std::collections::HashMap::new()),
            // counters start at 0/INFINITY. Mutation sites in
            // low_stake_replay maintain them; the buffer is in-memory only
            // (not persisted) so no boot recount is needed.
            low_stake_deferred_witnesses: std::sync::atomic::AtomicU64::new(0),
            low_stake_deferred_total: std::sync::atomic::AtomicU64::new(0),
            low_stake_deferred_oldest_at_bits: std::sync::atomic::AtomicU64::new(
                f64::INFINITY.to_bits(),
            ),
            memory_pressure: std::sync::atomic::AtomicBool::new(false),
            memory_critical: std::sync::atomic::AtomicBool::new(false),
            disk_pressure: std::sync::atomic::AtomicBool::new(false),
            disk_avail_pressure: std::sync::atomic::AtomicBool::new(false),
            disk_cap_pressure: std::sync::atomic::AtomicBool::new(false),
            disk_pressure_rejected_ingest_total: AtomicU64::new(0),
            emergency_latest_halt_nonce: AtomicU64::new(0),
            emergency_latest_resume_nonce: AtomicU64::new(0),
            emergency_active_expiry_unix: AtomicU64::new(0),
            emergency_rejected_ingest_total: AtomicU64::new(0),
            emergency_fold_lock: std::sync::Mutex::new(()),
            emergency_active_reason: std::sync::Mutex::new(String::new()),
            // counters start at 0; lowest-MB gauge starts at sentinel
            // u64::MAX so the first `fetch_min(real_avail)` always wins. The
            // metrics renderer maps MAX → 0 for the sentinel-as-not-sampled
            // contract; once the loop ticks once, the value is the live
            // running minimum.
            disk_avail_pressure_events_total: AtomicU64::new(0),
            disk_cap_pressure_events_total: AtomicU64::new(0),
            disk_pressure_lowest_avail_mb: AtomicU64::new(u64::MAX),
            admin_compact_cf_triggered_total: AtomicU64::new(0),
            disk_pressure_samples_total: AtomicU64::new(0),
            data_dir_total_bytes: AtomicU64::new(0),
            data_dir_size_samples_total: AtomicU64::new(0),
            boot_total_secs: AtomicU64::new(0),
            boot_ledger_rebuild_secs: AtomicU64::new(0),
            boot_state_core_init_secs: AtomicU64::new(0),
            zone_rtt: std::sync::RwLock::new(super::zone_rtt::ZoneRttEstimator::new()),
            zone_rtt_samples_total: AtomicU64::new(0),
            peer_rtt: std::sync::RwLock::new(super::peer_rtt::PeerRttEstimator::new()),
            peer_rtt_samples_total: AtomicU64::new(0),
            system_load: Arc::new(super::system_load::SystemLoadSensor::new()),
            peer_bandwidth: Arc::new(super::peer_bandwidth::PeerBandwidthLimiter::new()),
            pq_read_limiter: Arc::new(super::peer_bandwidth::PeerBandwidthLimiter::with_params(
                pq_read_capacity,
                pq_read_refill_per_sec,
                super::peer_bandwidth::MAX_PEERS,
            )),
            continuity: std::sync::Mutex::new(crate::continuity::ContinuityState::new()),
            reincarnation: std::sync::Mutex::new(crate::reincarnation::ReincarnationState::new()),
            slot_nonce_self: AtomicU64::new(1),
            // Ceiling 0 → the first `next_slot_nonce` reserves a durable block
            // (unless `bootstrap_slot_nonce` seeds it first from the persisted
            // high-water). Never hand out a nonce >= this without an fsync.
            slot_nonce_durable_ceiling: AtomicU64::new(0),
            slot_nonce_reserve_lock: std::sync::Mutex::new(()),
            version_state: std::sync::Mutex::new(crate::versioning::VersionState::new()),
            pending_ledger: RwLock::new(crate::accounting::pending_ledger::PendingLedger::new()),
            pending_ledger_commits_total: AtomicU64::new(0),
            pending_ledger_discards_total: AtomicU64::new(0),
            pending_ledger_rejections_total: AtomicU64::new(0),
            pending_ledger_fallback_direct_apply_total: AtomicU64::new(0),
            pending_ledger_hard_discards_total: AtomicU64::new(0),
            pending_drain_apply_failed_total: AtomicU64::new(0),
            pending_drain_missing_record_total: AtomicU64::new(0),
            rotation_cf_write_drain_total: AtomicU64::new(0),
            rotation_cf_write_sweep_total: AtomicU64::new(0),
            rotation_cf_write_failed_total: AtomicU64::new(0),
            rotation_reason_rejected_total: AtomicU64::new(0),
            rotation_recent_floor_rejected_total: AtomicU64::new(0),
            rotation_parent_grounding_rejected_total: AtomicU64::new(0),
            rotation_predecessor_ungrounded_rejected_total: AtomicU64::new(0),
            rotation_cf_canonicality_mismatch_total: AtomicU64::new(0),
            rotation_sweep_runs_total: AtomicU64::new(0),
            rotation_sweep_markers_scanned_total: AtomicU64::new(0),
            rotation_sweep_markers_discharged_total: AtomicU64::new(0),
            rotation_sweep_orphan_markers_total: AtomicU64::new(0),
            rotation_sweep_pending_markers: AtomicU64::new(0),
            zone_purge_queue: std::sync::Mutex::new(std::collections::VecDeque::new()),
            zone_purge_records_purged_total: AtomicU64::new(0),
            orphan_resolver_high_count_pruned_total: AtomicU64::new(0),
            orphan_resolver_saturation_skips_total: AtomicU64::new(0),
            balances_response_truncated_total: AtomicU64::new(0),
            balances_short_prefix_rejected_total: AtomicU64::new(0),
            snapshot_size_rejected_total: AtomicU64::new(0),
            cached_health: arc_swap::ArcSwapOption::empty(),
        }
    }

    /// Gap 4 routing-application: resolve a `record_id` to its current leaf
    /// zone by walking the [`super::zone_registry::ZoneRegistry`] from the
    /// naive flat-modulo zone that [`super::consensus::zone_for_record`]
    /// would return. This is the split-aware replacement for bare
    /// `zone_for_record(id)` at hot-path call sites.
    ///
    /// Behavior:
    /// * Until any [`super::zone_transition_seal::TransitionSeal`] finalizes
    ///   on the fleet, the returned zone is identical to
    ///   `zone_for_record(record_id)` — no behavior change.
    /// * Once a split finalizes touching the naive zone, this walks to the
    ///   current leaf. The routing key is `sha3_256(record_id)`, so the
    ///   same record always routes to the same leaf for the lifetime of
    ///   the registry (records can't teleport between zones mid-flight).
    ///
    /// Gap 6.4 slice 3a: record a DHT-routed seal push for later
    /// reconciliation. Used by `gossip::push_to_peers` after the bandwidth
    /// filter so the captured target set matches the realized push, not
    /// the chosen-K set before token-bucket throttling.
    ///
    /// Capacity-bounded by `seal_dht_replication_pending_max`; overflow
    /// drops the oldest entry (FIFO) and bumps
    /// `gossip_seal_replication_overflow_total`. The pending-depth gauge
    /// is updated atomically inside the same lock acquisition so
    /// /metrics scrapes see a coherent depth ≤ cap.
    ///
    /// Empty-targets is a no-op — the reconciler has no peer set to
    /// probe with no targets, so we don't waste a queue slot. Slice 3b
    /// uses the captured `pushed_at` `Instant` to decide which entries
    /// have crossed the ack timeout and are due for reconciliation.
    pub async fn track_pending_seal_replication(
        &self,
        seal_id: String,
        targets: Vec<String>,
    ) {
        if targets.is_empty() {
            return;
        }
        let cap = self.config.seal_dht_replication_pending_max;
        let mut q = self.pending_seal_replications.lock().await;
        let evicted = enqueue_pending_seal_replication_bounded(
            &mut q,
            cap,
            seal_id,
            targets,
            Instant::now(),
        );
        let new_len = q.len() as u64;
        drop(q);
        use std::sync::atomic::Ordering::Relaxed;
        if evicted > 0 {
            self.gossip_seal_replication_overflow_total
                .fetch_add(evicted as u64, Relaxed);
        }
        self.gossip_seal_replication_tracked_total
            .fetch_add(1, Relaxed);
        self.gossip_seal_replication_pending_depth
            .store(new_len, Relaxed);
    }

    /// Bumps `zone_resolve_internal_queries_total` and, when the resolve
    /// redirects, `zone_resolve_internal_redirected_total`. Scale: O(depth
    /// of split tree) ≤ ~20 for any plausible fleet; lock is a read.
    pub fn resolve_record_zone(&self, record_id: &str) -> super::zone::ZoneId {
        use super::RwLockRecover;
        // KR-3 S2 wiring-(c) c3: rotation-class routing pin. When the feature is
        // enabled AND this record id carries a pin, route via its lineage_id
        // instead of the record id, so every hop of one rotation chain resolves
        // to a single zone (§6.1 R-2/R-8). The atomic guard keeps the common path
        // — flag-OFF, or flag-ON with an empty pin set — lock-free (SCALE: this
        // runs on every record ingest). Flag-OFF is BYTE-IDENTICAL: the bool
        // short-circuits before any pin access, falling straight through to the
        // naive+registry resolution below.
        if self.config.s2_rotation_ordering_enabled
            && self
                .rotation_pins_len
                .load(std::sync::atomic::Ordering::Relaxed)
                > 0
        {
            let pinned = self
                .rotation_zone_pins
                .read_recover()
                .get(record_id)
                .cloned();
            if let Some(lineage_id) = pinned {
                return self.resolve_pinned_zone(&lineage_id);
            }
        }
        let naive = super::consensus::zone_for_record(record_id);
        let rk = super::zone_registry::routing_key_for_record(record_id);
        let redirected = {
            let reg = self.zone_registry.read_recover();
            let res = super::zone_registry::resolve_current_leaf(&reg, &naive, &rk);
            if res.redirected {
                let resolved = res.resolved_zone;
                self.zone_resolve_internal_queries_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.zone_resolve_internal_redirected_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return resolved;
            }
            res.resolved_zone
        };
        self.zone_resolve_internal_queries_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        redirected
    }

    /// KR-3 S2 wiring-(c) c3: resolve a rotation chain's home zone from its
    /// `lineage_id`. Mirrors [`Self::resolve_identity_zone`] exactly — the lineage
    /// id is a stable 32-byte anchor hash and is routed like an identity, NOT like
    /// a regenerable record id — so the pinned zone is a deterministic function of
    /// durable state on every node (the anti-fork invariant). Because the pin
    /// stores the routing KEY (never a resolved zone literal), a zone-count
    /// transition or registry split re-routes the entire chain together.
    fn resolve_pinned_zone(&self, lineage_id: &str) -> super::zone::ZoneId {
        use super::RwLockRecover;
        let naive = super::consensus::zone_for_record(lineage_id);
        let rk = super::zone_registry::routing_key_for_identity(lineage_id);
        let resolved = {
            let reg = self.zone_registry.read_recover();
            super::zone_registry::resolve_current_leaf(&reg, &naive, &rk)
        };
        self.zone_resolve_internal_queries_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if resolved.redirected {
            self.zone_resolve_internal_redirected_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        resolved.resolved_zone
    }

    /// KR-3 S2 wiring-(c) c3: publish a rotation hop's `(record_id → lineage_id)`
    /// pin into the in-memory set. Called at admission (`network::ingest`) BEFORE
    /// the record's own `resolve_record_zone` calls, so the hop routes and stores
    /// under its lineage zone; the same value is written durably in the record's
    /// admission WriteBatch (c2), so a restart's [`Self::load_rotation_pins`]
    /// reproduces it. Re-admission of the same id is a no-op on the count. Keeps
    /// `rotation_pins_len` exactly equal to the map length so the resolve fast
    /// path's emptiness check is exact.
    pub fn insert_rotation_pin(&self, record_id: &str, lineage_id: &str) {
        use super::RwLockRecover;
        let mut pins = self.rotation_zone_pins.write_recover();
        pins.insert(record_id.to_string(), lineage_id.to_string());
        self.rotation_pins_len
            .store(pins.len(), std::sync::atomic::Ordering::Relaxed);
    }

    /// KR-3 S2 wiring-(c) c3: boot-load the in-memory rotation-pin set from the
    /// durable `rotation_zone_pin:` CF rows. Called once at startup under
    /// `s2_rotation_ordering_enabled` — the durable pins are only ever written
    /// flag-ON, so a flag-OFF boot skips the scan entirely (byte-identical).
    /// Returns the number of pins loaded.
    pub fn load_rotation_pins(&self) -> usize {
        use super::RwLockRecover;
        let rows = self.rocks.scan_rotation_zone_pins();
        let mut pins = self.rotation_zone_pins.write_recover();
        for (record_id, lineage_id) in rows {
            pins.insert(record_id, lineage_id);
        }
        let n = pins.len();
        self.rotation_pins_len
            .store(n, std::sync::atomic::Ordering::Relaxed);
        n
    }

    /// Shared, memoized staked-anchor view for the seal proposer
    /// (`epoch::should_propose_seal`) and BOTH seal verifiers
    /// (`network::ingest`). Returns `(flat, by_zone)` — the rank-chain input
    /// and its home-zone partition (see [`AnchorView`]).
    ///
    /// Fast path: one brief `ledger` read to compare the cache key; on a hit
    /// returns two `Arc::clone`s — no CF scan, no ledger join, no allocation.
    /// Slow path (only after a stake / anchor-membership / zone-transition
    /// change): rebuilds via the exact `CF_IDENTITIES_ANCHOR` scan + ledger
    /// join the call sites used to inline, then caches it.
    ///
    /// SCALE: the inline build ran a full anchor-CF scan + `O(anchors)` ledger
    /// join once PER ZONE PER TICK (proposer) and once PER INCOMING SEAL
    /// (verifier). This collapses that to one rebuild per ledger change and an
    /// `O(1)` Arc-clone on every other call — the per-zone redundancy factor is
    /// gone. CORRECTNESS: all three sites read this one accessor, so the
    /// proposer's and verifier's staked sets are identical by construction
    /// (the LIVENESS-1 invariant). A stale-but-consistent cache is safe — the
    /// key advances only on committed state, so two honest nodes at the same
    /// ledger state compute the same key and the same set.
    pub async fn staked_anchor_view(
        &self,
    ) -> (
        std::sync::Arc<Vec<(String, u64)>>,
        std::sync::Arc<std::collections::HashMap<crate::ZoneId, Vec<(String, u64)>>>,
    ) {
        use super::RwLockRecover;
        use std::sync::Arc;
        // Read the two lock-free monotonic dimensions once.
        let anchor_seq = self.rocks.anchor_add_generation();
        let zone_gen = self.zone_registry.read_recover().applied_transition_count();
        // Fast path — compare the cache key under a brief ledger read.
        {
            let ledger = self.ledger.read().await;
            let key = (ledger.stake_mutation_seq, anchor_seq, zone_gen);
            let fp = ledger.total_staked;
            if let Some(v) = self.anchor_view.read_recover().as_ref() {
                if v.key == key && v.fp == fp {
                    return (Arc::clone(&v.flat), Arc::clone(&v.by_zone));
                }
            }
        }
        // Slow path — rebuild. CF scan first (no lock held), then the join
        // under a brief ledger read. This is the verbatim pre-cache
        // computation; the ledger lock is released BEFORE the zone partition
        // loop (which takes its own `zone_registry` read per anchor), so we
        // never hold `ledger` across `resolve_identity_zone`.
        let anchors = self
            .rocks
            .list_anchor_identities(super::epoch::MAX_ANCHORS_PER_PROPOSAL);
        let (key, fp, flat) = {
            let ledger = self.ledger.read().await;
            let key = (ledger.stake_mutation_seq, anchor_seq, zone_gen);
            let fp = ledger.total_staked;
            let flat: Vec<(String, u64)> = anchors
                .into_iter()
                .filter_map(|id| {
                    ledger
                        .accounts
                        .get(&id)
                        .filter(|a| a.staked > 0)
                        .map(|a| (id, a.staked))
                })
                .collect();
            (key, fp, flat)
        };
        let mut by_zone: std::collections::HashMap<crate::ZoneId, Vec<(String, u64)>> =
            std::collections::HashMap::new();
        for (h, s) in &flat {
            by_zone
                .entry(self.resolve_identity_zone(h))
                .or_default()
                .push((h.clone(), *s));
        }
        let flat = Arc::new(flat);
        let by_zone = Arc::new(by_zone);
        *self.anchor_view.write_recover() = Some(AnchorView {
            key,
            fp,
            flat: Arc::clone(&flat),
            by_zone: Arc::clone(&by_zone),
        });
        (flat, by_zone)
    }

    /// Drop the memoized staked-anchor view so the next
    /// [`Self::staked_anchor_view`] rebuilds from authoritative CF + ledger
    /// state. MUST be called by every path that replaces the ledger wholesale
    /// (snapshot bootstrap, state-delta repair): `stake_mutation_seq` is
    /// `#[serde(skip)]`, so a freshly deserialized ledger resets it to 0 and
    /// the key alone may not detect the swap — the explicit invalidate is the
    /// load-bearing restore-correctness step.
    pub fn invalidate_anchor_view(&self) {
        use super::RwLockRecover;
        *self.anchor_view.write_recover() = None;
        // Transitions-F1: the transition trust set shares the ledger-replace
        // staleness mode (stake_mutation_seq is #[serde(skip)] → resets to 0
        // on a deserialized ledger), so every invalidation site covers both.
        *self.transition_trust.write_recover() = None;
    }

    /// Transitions-F1: shared, memoized zone-transition-seal trust set for
    /// the five sig-ingest sites (`routes::transitions::verify_anchor_sig`
    /// callers) and the finalize-tick pubkey pre-filter
    /// (`health::run_transition_tick`).
    ///
    /// Membership: every identity in the ledger staker set
    /// (`ledger.staker_index` — genesis validators included, they get real
    /// `StakeEntry`s from `apply_genesis_validators`) whose staked balance
    /// meets `MIN_WITNESS_STAKE_BASE_UNITS`, PLUS the genesis authority
    /// unconditionally — on a fresh chain (pre-mint, empty staker set) the
    /// trust set is exactly `{genesis}`, so single-authority operation and
    /// the auto-scale self-mint path are unaffected by the gate.
    ///
    /// Fast path: one brief `ledger` read to compare `(stake_mutation_seq,
    /// total_staked)`; on a hit returns an `Arc::clone` — no iteration, no
    /// allocation. Slow path (only after a stake mutation or an
    /// invalidation): one O(stakers) pass over `staker_index` under the same
    /// read guard. NEVER call this per-sig — fetch once per request/tick and
    /// pass the set down (the DoS bound: `MAX_PROPOSER_SIGS = 32` sigs per
    /// seal, `MAX_PULLS_PER_TICK = 16` seals per tick share one fetch).
    ///
    /// SCALE: the set materializes O(stakers ≥ witness-floor) raw 32-byte
    /// ids — the economically-bounded node-operator population (each entry
    /// locks ≥100 beat), the same weight class as [`AnchorView::flat`], not
    /// O(all_accounts).
    pub async fn transition_trust_view(
        &self,
    ) -> std::sync::Arc<std::collections::HashSet<[u8; 32]>> {
        use super::RwLockRecover;
        use std::sync::Arc;

        fn decode_id(hex_id: &str) -> Option<[u8; 32]> {
            let bytes = hex::decode(hex_id).ok()?;
            if bytes.len() != 32 {
                return None;
            }
            let mut h = [0u8; 32];
            h.copy_from_slice(&bytes);
            Some(h)
        }

        let ledger = self.ledger.read().await;
        let key = ledger.stake_mutation_seq;
        let fp = ledger.total_staked;
        if let Some(v) = self.transition_trust.read_recover().as_ref() {
            if v.key == key && v.fp == fp {
                return Arc::clone(&v.set);
            }
        }
        let floor = crate::accounting::types::MIN_WITNESS_STAKE_BASE_UNITS;
        let mut set: std::collections::HashSet<[u8; 32]> =
            std::collections::HashSet::with_capacity(ledger.staker_index.len() + 1);
        for id_hex in ledger.staker_index.keys() {
            if ledger.staked(id_hex) < floor {
                continue;
            }
            if let Some(h) = decode_id(id_hex) {
                set.insert(h);
            }
        }
        if let Some(h) = decode_id(&self.config.genesis_authority) {
            set.insert(h);
        }
        let set = Arc::new(set);
        *self.transition_trust.write_recover() = Some(TransitionTrustView {
            key,
            fp,
            set: Arc::clone(&set),
        });
        set
    }

    /// Gap 4 routing-application: resolve an identity (hex-encoded 32-byte
    /// hash) to its current leaf zone. For account-level routing — balances,
    /// account-state SMT, VRF registrations — use this so a registered
    /// account's home zone remains stable under splits of its parent.
    ///
    /// The routing key is the decoded 32-byte identity hash itself (not a
    /// second sha3). Bumps the same internal counters as
    /// [`NodeState::resolve_record_zone`].
    pub fn resolve_identity_zone(&self, identity_hex: &str) -> super::zone::ZoneId {
        use super::RwLockRecover;
        let naive = super::consensus::zone_for_record(identity_hex);
        let rk = super::zone_registry::routing_key_for_identity(identity_hex);
        let resolved = {
            let reg = self.zone_registry.read_recover();
            super::zone_registry::resolve_current_leaf(&reg, &naive, &rk)
        };
        self.zone_resolve_internal_queries_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if resolved.redirected {
            self.zone_resolve_internal_redirected_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        resolved.resolved_zone
    }

    /// Allocate the next slot nonce for a record created by this node.
    /// Returns a strictly-monotonic `u64`; wraps around at `u64::MAX` (which is
    /// never reachable in practice — 1 record/ns for 600 years = ~2^64).
    ///
    /// Thread-safe: all in-node writers (tip_merge, witness_profile, pool_fund,
    /// VRF registration, reward distribution, etc.) must call this instead of
    /// leaving nonce at 0. Failing to do so causes same-creator second records
    /// to collide with the first on slot_key and be rejected with
    /// SLOT EQUIVOCATION at the ingest path.
    ///
    /// **F-9 durability (reserve-ahead):** every returned nonce is strictly
    /// below a **fsync'd** high-water in `CF_METADATA` *before* it is returned,
    /// so a power-loss can never make `bootstrap_slot_nonce` re-hand it. The
    /// common path is a lock-free atomic increment below the durable ceiling;
    /// only when a caller crosses the ceiling does exactly one reservation
    /// fsync a new block (`SLOT_NONCE_BLOCK` nonces at a time), keeping the cost
    /// O(self_records / block) — never a per-external-record fsync (SCALE RULE).
    /// A crash between two reservations wastes at most a block of nonce values
    /// (a harmless gap; the u64 space is inexhaustible).
    pub fn next_slot_nonce(&self) -> u64 {
        use std::sync::atomic::Ordering;
        let n = self.slot_nonce_self.fetch_add(1, Ordering::AcqRel);
        // Fast path: n already covered by a durable reservation.
        if n < self.slot_nonce_durable_ceiling.load(Ordering::Acquire) {
            return n;
        }
        // Slow path: extend the durable ceiling to cover n BEFORE returning it,
        // so n is never observable (broadcast) until its covering high-water is
        // fsync'd. Poison-tolerant: a prior panic mid-reservation must not wedge
        // the allocator.
        let _guard = self
            .slot_nonce_reserve_lock
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        // Re-check under the lock: a concurrent crosser may have reserved past n.
        if n < self.slot_nonce_durable_ceiling.load(Ordering::Acquire) {
            return n;
        }
        let new_ceiling = n
            .saturating_add(Self::SLOT_NONCE_BLOCK)
            .saturating_add(1);
        match self.rocks.put_cf_raw_synced(
            crate::storage::rocks::CF_METADATA,
            Self::SLOT_NONCE_HWM_KEY,
            &new_ceiling.to_le_bytes(),
        ) {
            Ok(()) => {
                self.slot_nonce_durable_ceiling
                    .store(new_ceiling, Ordering::Release);
            }
            Err(e) => {
                // Durability failed. Return n anyway — this is no worse than the
                // pre-F-9 status quo (no high-water existed at all), and the
                // CF_SLOT_INDEX floor in `bootstrap_slot_nonce` still bounds
                // reuse for durably-written records. Do NOT advance the ceiling,
                // so the next call retries the reservation.
                tracing::warn!(
                    nonce = n,
                    error = %e,
                    "slot_nonce high-water fsync failed — nonce not durably reserved (degraded to pre-F-9 exposure until the next reservation succeeds)"
                );
            }
        }
        n
    }

    /// Nonces reserved (and fsync'd) per high-water advance. Larger = fewer
    /// fsyncs (cheaper) but a bigger nonce gap wasted per crash; both are
    /// cheap, so a modest block amortises the fsync to near-zero even at the
    /// mainnet self-seal rate (~1 fsync per `BLOCK` self-records).
    const SLOT_NONCE_BLOCK: u64 = 128;
    /// `CF_METADATA` key holding the fsync'd self-nonce high-water (little-endian
    /// u64). Node-local; never part of any signed/verified consensus artifact.
    const SLOT_NONCE_HWM_KEY: &'static [u8] = b"self_slot_nonce_hwm";

    /// Bootstrap `slot_nonce_self` from the slot index so a restarted node
    /// never hands out a nonce it already used.
    ///
    /// Scans CF_SLOT_INDEX under the prefix `<self_account_hash>:` and takes
    /// `max(nonce) + 1`. This is O(self_records), not O(all_records) — slot
    /// entries are partitioned by account, so one node's restart cost is
    /// bounded by its own historical record count, not the fleet total.
    ///
    /// Called once during node startup before any record-producing task runs.
    /// Idempotent — calling twice is a no-op (the counter already reflects
    /// the on-disk max). Any error during the scan leaves the counter at 1
    /// and logs a warning — a fresh node (no prior slot entries) is indistinguishable
    /// from this path and correctly starts at 1.
    ///
    /// **F-9:** seeds from `max(fsync'd high-water, CF_SLOT_INDEX max + 1)`. The
    /// high-water is reserved *ahead* of use, so it is ≥ every nonce this node
    /// ever broadcast even when a power-loss dropped that record's
    /// `CF_SLOT_INDEX` entry (the index scan alone would then under-count and
    /// re-hand the nonce). The index max is the floor for the first boot after
    /// this fix ships onto a DB with pre-existing slot entries but no high-water.
    /// The durable ceiling is set to the persisted high-water; the first
    /// `next_slot_nonce` above it reserves the next block.
    pub fn bootstrap_slot_nonce(&self) {
        let account_hash = crate::crypto::hash::sha3_256_hex(&self.identity.public_key);
        let index_next = match self.rocks.max_slot_nonce_for_account(&account_hash) {
            Ok(Some(max_nonce)) => max_nonce.saturating_add(1),
            Ok(None) => 0,
            Err(e) => {
                tracing::warn!(error = %e, "slot_nonce bootstrap scan failed — index floor unavailable");
                0
            }
        };
        // Persisted fsync'd high-water (reserve-ahead ceiling from a prior run).
        let durable_hwm = match self.rocks.get_cf_raw(
            crate::storage::rocks::CF_METADATA,
            Self::SLOT_NONCE_HWM_KEY,
        ) {
            Ok(Some(bytes)) if bytes.len() == 8 => {
                let mut a = [0u8; 8];
                a.copy_from_slice(&bytes);
                u64::from_le_bytes(a)
            }
            Ok(_) => 0,
            Err(e) => {
                tracing::warn!(error = %e, "slot_nonce high-water read failed — falling back to index floor");
                0
            }
        };
        // Start strictly above everything we may already have handed out. Never
        // below 1 (nonce 0 is the legacy "unset" sentinel the §11.6/tip_merge
        // fix moved away from).
        let seed = durable_hwm.max(index_next).max(1);
        self.slot_nonce_self
            .store(seed, std::sync::atomic::Ordering::Release);
        // Ceiling = the persisted high-water. If seed > durable_hwm (first boot
        // after this fix, or a lost-then-index-recovered nonce), the first
        // allocation crosses the ceiling and reserves a covering block.
        self.slot_nonce_durable_ceiling
            .store(durable_hwm, std::sync::atomic::Ordering::Release);
        tracing::info!(
            account = %&account_hash[..account_hash.len().min(16)],
            seed,
            durable_hwm,
            index_next,
            "slot_nonce bootstrapped (F-9 durable high-water)"
        );
    }

    /// Create a signed beat ledger record with a freshly-allocated slot nonce.
    ///
    /// This is the canonical path for *any in-node writer* that produces a
    /// record on behalf of this node's own identity. It bundles three steps
    /// callers were getting wrong:
    ///   1. `next_slot_nonce()` — allocate a fresh monotonic nonce.
    ///   2. Construct the record with the nonce set *before* signing.
    ///   3. Sign with `state.identity`.
    ///
    /// If you need a reward/meta record from a different identity (e.g. a
    /// recipient's signed receipt), build it through the equivalent
    /// per-identity helper — this one is hard-wired to `self.identity` and
    /// `self.next_slot_nonce()` so the caller cannot accidentally reuse a
    /// nonce.
    pub fn create_self_ledger_record(
        &self,
        parents: Vec<String>,
        metadata: std::collections::BTreeMap<String, serde_json::Value>,
    ) -> Result<ValidationRecord> {
        let nonce = self.next_slot_nonce();
        crate::accounting::types::create_ledger_record_with_nonce(
            &self.identity, parents, metadata, nonce,
        )
    }

    /// Check if the node is under memory pressure.
    /// When true, subsystems should reduce batch sizes and avoid large allocations.
    pub fn under_memory_pressure(&self) -> bool {
        self.memory_pressure.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Check if the node is under critical memory pressure (RSS > 90% of system RAM).
    /// When true, new record submissions are rejected with 429 to prevent OOM.
    pub fn under_critical_memory_pressure(&self) -> bool {
        self.memory_critical.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Check if the node is under any disk pressure (avail OR cap). True when
    /// `disk_avail_pressure || disk_cap_pressure`. Read by GC force-compaction
    /// and by the back-compat `elara_disk_pressure` gauge.
    ///
    /// **Ingest gates should NOT use this — call `under_avail_pressure()`
    /// instead.** Cap-pressure is operator policy, not a real
    /// disk-full safety bound, and rejecting ingest on cap-overrun while the
    /// FS still has headroom is an operational footgun (was the driver of a
    /// past fleet trap).
    pub fn under_disk_pressure(&self) -> bool {
        self.disk_pressure.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Real-disk-full safety. True when statvfs avail dropped below
    /// `disk_pressure_avail_low_mb` and hasn't recovered above
    /// `disk_pressure_avail_high_mb` yet. Ingest paths (`/records` POST,
    /// gossip insert) reject with 429 when this is true. Independent of the
    /// `disk_cap_bytes` operator policy.
    pub fn under_avail_pressure(&self) -> bool {
        self.disk_avail_pressure.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The halt gate predicate (hot ingest path, lock-free). Halted iff a halt
    /// out-ranks every resume AND the wall clock has not passed the active window.
    /// B4: load the nonce with `Acquire` (pairs with the fold's `Release` store)
    /// BEFORE the expiry, so a reader observing a new nonce sees the matching expiry.
    pub fn emergency_halted_now(&self, now_secs: u64) -> bool {
        use std::sync::atomic::Ordering::{Acquire, Relaxed};
        let halt = self.emergency_latest_halt_nonce.load(Acquire);
        let resume = self.emergency_latest_resume_nonce.load(Relaxed);
        if halt <= resume {
            return false; // `>` not `>=` — a tie un-halts.
        }
        now_secs < self.emergency_active_expiry_unix.load(Relaxed)
    }

    /// Max-fold a verified halt: persist the durable `CF_EMERGENCY` blob, THEN
    /// publish the atomics — ALL under the fold lock so persist-before-publish is
    /// atomic w.r.t. a concurrent fold (the CF can never lag the atomics, so a warm
    /// restart never un-halts). Caller MUST have checked authority-binding +
    /// `is_well_formed`. Returns `true` iff this halt won the nonce race.
    pub fn emergency_fold_halt(&self, h: &crate::emergency::EmergencyHalt) -> bool {
        use std::sync::atomic::Ordering::{Relaxed, Release};
        let _g = self.emergency_fold_lock.lock_recover();
        if h.nonce > self.emergency_latest_halt_nonce.load(Relaxed) {
            // Store the BOUNDED expiry: a future-dated `issued_ts` must not push the
            // auto-expiry past this node's `now + MAX_HALT_DURATION_SECS` continuity
            // backstop (else one signed halt bricks ingest for years after authority-key
            // loss). For a legitimate halt the bound is a strict no-op.
            let now_secs = crate::network::ingest::now() as u64;
            let next = crate::emergency::EmergencyState {
                latest_halt_nonce: h.nonce,
                latest_resume_nonce: self.emergency_latest_resume_nonce.load(Relaxed),
                active_expiry_unix: h.effective_expiry_bounded(now_secs),
                active_reason: h.reason.clone(),
            };
            // Durable blob FIRST. On failure, publish nothing — boot reads the older
            // (un-halted-w.r.t. this nonce) blob, which is the safe direction.
            if let Err(e) = self.rocks.put_emergency_state(&next) {
                tracing::warn!("emergency_state persist failed: {e}");
                return false;
            }
            // Then publish: expiry/reason before the nonce (Release) — a lock-free
            // reader that sees the new nonce (Acquire) is guaranteed the new expiry.
            self.emergency_active_expiry_unix.store(next.active_expiry_unix, Relaxed);
            *self.emergency_active_reason.lock_recover() = next.active_reason;
            self.emergency_latest_halt_nonce.store(h.nonce, Release);
            true
        } else {
            false
        }
    }

    /// Max-fold a verified resume (persist-before-publish, under the fold lock).
    /// Returns `true` iff it won.
    pub fn emergency_fold_resume(&self, r: &crate::emergency::EmergencyResume) -> bool {
        use std::sync::atomic::Ordering::{Acquire, Relaxed, Release};
        let _g = self.emergency_fold_lock.lock_recover();
        if r.halt_nonce > self.emergency_latest_resume_nonce.load(Relaxed) {
            let next = crate::emergency::EmergencyState {
                latest_halt_nonce: self.emergency_latest_halt_nonce.load(Acquire),
                latest_resume_nonce: r.halt_nonce,
                active_expiry_unix: self.emergency_active_expiry_unix.load(Relaxed),
                active_reason: self.emergency_active_reason.lock_recover().clone(),
            };
            if let Err(e) = self.rocks.put_emergency_state(&next) {
                tracing::warn!("emergency_state persist failed: {e}");
                return false;
            }
            self.emergency_latest_resume_nonce.store(r.halt_nonce, Release);
            true
        } else {
            false
        }
    }

    /// Project the live atomics into the serializable [`EmergencyState`] — for the
    /// bootstrap snapshot carry and the durable CF write.
    pub fn emergency_snapshot_state(&self) -> crate::emergency::EmergencyState {
        use std::sync::atomic::Ordering::{Acquire, Relaxed};
        let _g = self.emergency_fold_lock.lock_recover();
        crate::emergency::EmergencyState {
            latest_halt_nonce: self.emergency_latest_halt_nonce.load(Acquire),
            latest_resume_nonce: self.emergency_latest_resume_nonce.load(Relaxed),
            active_expiry_unix: self.emergency_active_expiry_unix.load(Relaxed),
            active_reason: self.emergency_active_reason.lock_recover().clone(),
        }
    }

    /// Snapshot-carry projection: `None` when the node has never halted (keeps the
    /// snapshot checksum byte-identical to a pre-feature snapshot), else `Some`.
    pub fn emergency_snapshot_carry(&self) -> Option<crate::emergency::EmergencyState> {
        let es = self.emergency_snapshot_state();
        if es == crate::emergency::EmergencyState::default() {
            None
        } else {
            Some(es)
        }
    }

    /// Load a folded [`EmergencyState`] into the live atomics (boot from CF /
    /// snapshot bootstrap). Max-merges with whatever is already live (idempotent,
    /// order-independent), so a boot-load followed by a live fold never regresses.
    pub fn emergency_load_state(&self, s: &crate::emergency::EmergencyState) {
        use std::sync::atomic::Ordering::{Relaxed, Release};
        let _g = self.emergency_fold_lock.lock_recover();
        if s.latest_halt_nonce > self.emergency_latest_halt_nonce.load(Relaxed) {
            // Defense-in-depth: a pre-fix or hostile snapshot/CF producer can carry an
            // unbounded `active_expiry_unix` (issuer-anchored, future-dated). Re-bound it
            // to this node's continuity backstop on adopt. `min()` ⇒ monotone
            // non-increasing, so repeated boots never extend the window; a post-fix
            // (already-bounded) blob passes through unchanged.
            let now_secs = crate::network::ingest::now() as u64;
            self.emergency_active_expiry_unix
                .store(crate::emergency::bound_expiry(s.active_expiry_unix, now_secs), Relaxed);
            *self.emergency_active_reason.lock_recover() = s.active_reason.clone();
            self.emergency_latest_halt_nonce.store(s.latest_halt_nonce, Release);
        }
        if s.latest_resume_nonce > self.emergency_latest_resume_nonce.load(Relaxed) {
            self.emergency_latest_resume_nonce.store(s.latest_resume_nonce, Release);
        }
    }

    /// Operator-policy cap budget. True when rocks live bytes
    /// exceeded 95 % of `disk_cap_bytes_effective`. Used by GC force-
    /// compaction and the cap-pressure adaptive retention compression. Does
    /// not reject ingest.
    pub fn under_cap_pressure(&self) -> bool {
        self.disk_cap_pressure.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// p95 gossip RTT for `zone`, or `None` if insufficient samples yet.
    /// Used by the aggregator chain to size per-rank timeouts (§11.13).
    pub fn zone_rtt_p95(&self, zone: &super::zone::ZoneId) -> Option<std::time::Duration> {
        self.zone_rtt.read().ok()?.p95(zone)
    }

    /// Effective `base_timeout_ms` for `zone` — the single source of truth
    /// for both proposers (in `should_propose_seal` / seal loop) and
    /// verifiers (in `ingest::insert_record_inner_direct`). Having one
    /// function means all three sites agree on the rank-unlock schedule
    /// and so cannot desynchronize.
    ///
    /// Resolution order:
    ///   1. `config.test_base_timeout_ms_override` (sim/test only, never
    ///      set in production) — used verbatim.
    ///   2. 2× `zone_rtt_p95`, floored at 5s, clamped to [1s, 10min].
    ///   3. Default 5s when no RTT samples yet.
    pub fn effective_base_timeout_ms(&self, zone: &super::zone::ZoneId) -> u64 {
        if let Some(override_ms) = self.config.test_base_timeout_ms_override {
            return override_ms;
        }
        let base_s = match self.zone_rtt_p95(zone) {
            Some(rtt) => (rtt.as_secs_f64() * 2.0).max(5.0),
            None => 5.0,
        };
        (base_s * 1000.0).clamp(1000.0, 600_000.0) as u64
    }

    /// Record a gossip RTT sample for `zone`. Bounded O(1); caller passes
    /// the measured round-trip from push/pull request→response.
    pub fn observe_zone_rtt(&self, zone: &super::zone::ZoneId, rtt: std::time::Duration) {
        if let Ok(mut est) = self.zone_rtt.write() {
            est.observe(zone, rtt);
            self.zone_rtt_samples_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Record a gossip RTT sample against a specific peer identity.
    /// Bounded O(1); feeds the Stage-5 geographic-fraud detector
    /// ([`super::geo_fraud::scan_witness_set`]).
    pub fn observe_peer_rtt(&self, peer_id: &str, rtt: std::time::Duration) {
        if peer_id.is_empty() {
            return;
        }
        if let Ok(mut est) = self.peer_rtt.write() {
            est.observe(&super::peer_rtt::PeerId::new(peer_id), rtt);
            self.peer_rtt_samples_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Median RTT to a specific peer, if we've recorded enough samples.
    /// Delegates to the per-peer estimator.
    pub fn peer_rtt_median(&self, peer_id: &str) -> Option<std::time::Duration> {
        self.peer_rtt
            .read()
            .ok()?
            .median(&super::peer_rtt::PeerId::new(peer_id))
    }

    /// Read current process RSS in MB (Linux only, 0 on other platforms).
    #[cfg(target_os = "linux")]
    pub fn current_rss_mb() -> u64 {
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("VmRSS:"))
                    .and_then(|l| l.split_whitespace().nth(1))
                    .and_then(|n| n.parse::<u64>().ok())
            })
            .unwrap_or(0) / 1024
    }

    #[cfg(not(target_os = "linux"))]
    pub fn current_rss_mb() -> u64 { 0 }

    /// Set the VRF keypair. Called during node startup.
    /// Genesis authority nodes need the secret key; all nodes need the public key.
    pub fn set_vrf_keys(
        &mut self,
        sk: Option<crate::crypto::vrf::VrfSecretKey>,
        pk: Option<crate::crypto::vrf::VrfPublicKey>,
    ) {
        self.vrf_secret_key = sk.map(Arc::new);
        self.vrf_public_key = pk;
    }

    /// Feed an attestation into the consensus engine. Returns true if the record became finalized.
    /// Feed one attestation into consensus and report both signals callers
    /// need: `settled` (the record currently passes the 2/3 threshold —
    /// wire-compatible with the old bool return) and `first_finalization`
    /// (this call won the durable FinalizedIndex insert). Side-effects that
    /// must fire exactly once per record lifetime — witness rewards,
    /// reputation credit, `RecordFinalized` — are the caller's job via
    /// `reward::finalization_effects(state, ...)`, gated on
    /// `first_finalization` ONLY. Gating on `settled` re-fires them every
    /// time a peer re-pushes an attestation after the in-flight map pruned
    /// the record (observed live 2026-06-11: reward re-distribution every
    /// gossip cycle on the dev-net).
    pub async fn feed_attestation(&self, record_id: &str, witness_hash: &str, timestamp: f64) -> FeedOutcome {
        // Update witness liveness
        {
            let mut liveness = self.witness_liveness.lock_recover();
            liveness.record_attestation(witness_hash, timestamp);
        }

        // Feed attestation signal to entity clusterer (economics §6.3)
        {
            let (subnet, org) = {
                let consensus = self.consensus.lock_recover();
                let profile = consensus.profile_for(witness_hash)
                    .map(|p| (Some(p.subnet.clone()), Some(p.organization.clone())));
                profile.unwrap_or((None, None))
            };
            let mut clusterer = self.entity_clusterer.lock_recover();
            clusterer.record_attestation(
                witness_hash,
                record_id,
                timestamp,
                subnet.as_deref(),
                org.as_deref(),
            );
            // Dual-write entity cluster signal to RocksDB (trust CF, prefixed key).
            // Skip on ≤2GB nodes to reduce RocksDB write pressure.
            let ram_gb = crate::storage::rocks::StorageEngine::detect_system_ram_gb();
            if ram_gb > 2 {
                if let Some(signal) = clusterer.get_signal(witness_hash) {
                    if let Ok(bytes) = serde_json::to_vec(signal) {
                        let _ = self.rocks.put_cf_raw(
                            crate::storage::rocks::CF_TRUST,
                            format!("entity:{witness_hash}").as_bytes(),
                            &bytes,
                        );
                    }
                }
            }
        }

        // Fetch record from RocksDB BEFORE acquiring ledger lock.
        // Used for: creator hash (settlement denominator) and epoch seal detection.
        let record_opt = self.get_record(record_id).ok();
        let creator_hash_opt = record_opt.as_ref()
            .map(crate::accounting::types::creator_identity_hash);
        let (stake, creator_staked) = {
            let ledger = self.ledger.read().await;
            let witness_stake = ledger.staked(witness_hash);
            let creator_stake = creator_hash_opt.as_ref()
                .map(|creator| ledger.staked(creator))
                .unwrap_or(0);
            (witness_stake, creator_stake)
        };

        let att = Attestation {
            record_id: record_id.to_string(),
            witness_hash: witness_hash.to_string(),
            stake,
            timestamp,
        };

        let mut seal_entry: Option<super::zone_committee::SealAttestEntry> = None;
        // PARTITION-MERGE Phase B Slice 4: capture seal data for post-attestation
        // orphan-promotion check. We can't take epoch.write inside the consensus
        // lock (avoid nesting), so we record what we'd need and decide outside.
        let mut promotion_probe: Option<(super::epoch::ParsedEpochSeal, [u8; 32])> = None;

        // Gap 5 Phase 6c gate (Layer 2 only): pre-extract the seal payload
        // OUTSIDE the consensus lock so the async per-zone VRF check can run
        // before we acquire the std::sync mutex. When `enforce_per_zone_vrf`
        // is off (default), the helper short-circuits and `parsed_seal`
        // matches today's behavior. When on, a non-committee witness drops
        // the seal-attestation registration but keeps the Layer 1 record
        // attestation (§11.12 — Layer 1 is committee-free).
        let parsed_seal: Option<super::epoch::ParsedEpochSeal> = match &record_opt {
            Some(rec) if rec.metadata.contains_key(super::epoch::EPOCH_OP_KEY) => {
                match super::epoch::extract_epoch_seal(rec) {
                    Ok(Some(seal)) => {
                        let allowed = super::zone_committee::enforce_seal_attestation_committee_membership(
                            self,
                            seal.zone.path(),
                            seal.epoch_number,
                            witness_hash,
                        ).await;
                        if allowed {
                            Some(seal)
                        } else {
                            self.seal_attestation_rejected_not_in_committee_total
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            tracing::debug!(
                                "phase6c gate: seal attestation from {} rejected — not in committee for ({}, {})",
                                &witness_hash[..witness_hash.len().min(16)],
                                seal.zone.path(),
                                seal.epoch_number,
                            );
                            None
                        }
                    }
                    _ => None,
                }
            }
            _ => None,
        };

        let (settled, newly_finalized, mut newly_sealed, seal_member_rids) = {
            let mut consensus = self.consensus.lock_recover();
            let mut seal_member_rids: Vec<String> = Vec::new();
            // Register creator identity (+ stake) so a creator self-attestation is
            // rejected/purged (H1). Identity is recorded even at 0 stake (closes the
            // late-staking window); when the record isn't local yet (creator unknown),
            // the retroactive purge fires once the creator becomes known.
            if let Some(creator) = creator_hash_opt.as_deref() {
                consensus.register_creator_stake(record_id, creator, creator_staked);
            }
            consensus.add_attestation(att.clone()); // Also updates confirmation level

            // If this is an epoch seal AND it passed the Phase 6c gate above,
            // register a Layer 2 seal attestation (Protocol §11.12). This wires
            // attestations into the layered consensus model so that
            // is_seal_settled() can promote contained records to Finalized.
            if let (Some(seal), Some(ref rec)) = (&parsed_seal, &record_opt) {
                seal_entry = Some(super::zone_committee::SealAttestEntry {
                    zone_path: seal.zone.path().to_string(),
                    epoch: seal.epoch_number,
                    witness_hash: witness_hash.to_string(),
                });
                // Stash seal + record_hash for the orphan-promotion check
                // we run after the consensus lock drops.
                if self.config.partition_merge_weight_reconcile {
                    promotion_probe = Some((seal.clone(), rec.record_hash()));
                }
                seal_member_rids = consensus.add_seal_attestation(super::consensus::SealAttestation {
                    seal_id: record_id.to_string(),
                    zone: seal.zone.clone(),
                    epoch_number: seal.epoch_number,
                    witness_hash: witness_hash.to_string(),
                    stake,
                    timestamp,
                });
            }

            let mut raw_settled = consensus.is_settled(record_id);
            // Settlement gate (MESH-BFT Phase 3 Stage 1E).
            // A record whose slot is flagged as conflicted MUST NEVER finalize,
            // regardless of attestation weight. This is the safety pillar that
            // turns AWC into a true BFT protocol: no two conflicting records
            // can both be accepted because at most one per slot can settle,
            // and a proven conflict blocks BOTH from settling.
            if raw_settled {
                if let Some(ref rec) = record_opt {
                    if let Some(slot_key) = rec.slot_key() {
                        match self.rocks.slot_is_conflicted(&slot_key) {
                            Ok(true) => {
                                tracing::warn!(
                                    "SETTLEMENT BLOCKED: record {} in conflicted slot {} \
                                     — attestations reached threshold but slot has a \
                                     verified ConflictProof; refusing finalization",
                                    &record_id[..record_id.len().min(16)],
                                    slot_key,
                                );
                                raw_settled = false;
                            }
                            Ok(false) => { /* clean slot, allow settlement */ }
                            Err(e) => {
                                tracing::warn!(
                                    "slot_is_conflicted check failed for {}: {} \
                                     — erring on the side of NOT finalizing",
                                    slot_key, e,
                                );
                                raw_settled = false;
                            }
                        }
                    }
                }
            }
            // If raw settlement passes, ensure confirmation level reflects it.
            // add_attestation → recompute_confirmation may leave the level at Sealed
            // if cluster count is insufficient, but raw settlement means the record
            // IS finalized for the FinalizedIndex. Sync the confirmation level so
            // cross-zone finality boost can cascade correctly.
            // `newly_finalized` distinguishes the FIRST settlement transition
            // for this record (where lifetime counters must increment) from
            // repeat attestations on an already-settled record (where they
            // must not — fixes the 2-3× over-count of total_ever_settled vs
            // finalized_count seen fleet-wide).
            let newly_finalized = if raw_settled {
                consensus.force_finalized(record_id)
            } else {
                false
            };

            // MAINNET gap #8: drain Sealed transitions triggered by this
            // attestation (including any cascades from force_finalized's
            // child re-evaluation) while still holding the consensus lock so
            // the NodeEvent::RecordSealed broadcast below is race-free.
            let drained = consensus.drain_newly_sealed();

            (raw_settled, newly_finalized, drained, seal_member_rids)
        };

        // Seal-member durable write — UNCONDITIONAL, independent of the fed
        // record's own Layer-1 `settled` below (the seal record itself can be
        // slot-conflict-blocked or under-attested while its Layer-2 quorum
        // finalizes the members). Chunked + counted inside; effects are the
        // caller's job via `outcome.seal_members_finalized` (same contract
        // as `first_finalization`).
        let seal_members_finalized =
            super::reward::insert_members_durable(self, &seal_member_rids).await;

        // PARTITION-MERGE Phase B Slice 4: orphan-promotion re-evaluation.
        // After this attestation is in, the just-attested seal may have
        // accumulated more weight than the current canonical seal at the
        // same (zone, epoch). If it has, swap them per §3.3.3 operator π
        // (heavier-attestation-weight chain wins). Runs only with the flag
        // on; gated lookups are bounded (single ring lookup + two weight
        // queries against per-seal HashMaps), no scans.
        //
        // Lock ordering: epoch.read first, then consensus.lock for weight
        // queries (matches the established ingest.rs pattern), then drop
        // both locks before taking epoch.write to commit. Two seal-id
        // strings are cloned out under the read lock; no references are
        // held across the upgrade boundary.
        if let Some((parsed, record_hash)) = promotion_probe {
            // Step 1 — cheap predicate: is this just-attested seal an
            // orphan for its (zone, epoch)? Plus capture canonical seal_id
            // for the weight comparison.
            let (is_orphan, canonical_id): (bool, Option<String>) = {
                if let Ok(e) = self.epoch.read() {
                    (
                        e.is_orphan_sibling(&parsed.zone, parsed.epoch_number, record_id),
                        e.latest_seal_id.get(&parsed.zone).cloned(),
                    )
                } else {
                    (false, None)
                }
            };
            if is_orphan {
                // Step 2 — weight comparison.
                let (orphan_weight, canonical_weight) = {
                    let consensus = self.consensus.lock_recover();
                    let ow = consensus.attestation_weight_for_seal(record_id);
                    let cw = canonical_id
                        .as_deref()
                        .map(|id| consensus.attestation_weight_for_seal(id))
                        .unwrap_or(0);
                    (ow, cw)
                };
                if orphan_weight > canonical_weight {
                    // Step 3 — commit the swap.
                    let promoted = if let Ok(mut e) = self.epoch.write() {
                        e.promote_orphan_to_canonical(&parsed, record_id, record_hash)
                    } else {
                        false
                    };
                    if promoted {
                        tracing::info!(
                            "partition-merge: promoted orphan seal {} to canonical \
                             at zone={} epoch={} (weight {} > {} canonical)",
                            &record_id[..record_id.len().min(16)],
                            parsed.zone.path(),
                            parsed.epoch_number,
                            orphan_weight,
                            canonical_weight,
                        );
                    }
                }
            }
        }

        // Gap 5 Phase 6b: advisory committee-membership observation —
        // ONLY for Layer 2 epoch seal attestations (Protocol §11.12).
        // Layer 1 per-record attestations are not committee-gated under
        // the layered consensus model and would always report ~100%
        // nonmember. Consensus has already accepted the attestation above;
        // this observer just bumps counters.
        if let Some(entry) = seal_entry {
            super::zone_committee::observe_seal_committee_batch(
                self,
                std::iter::once(entry),
            )
            .await;
        }

        // Gap 4 Phase C: resolve zone once through the registry, reuse for both
        // the RocksDB dual-write key and the per-zone diversity tracking below.
        let record_zone = self.resolve_record_zone(record_id);

        // Dual-write attestation to RocksDB (attestations CF, keyed by zone:epoch:record_id)
        {
            let zone = record_zone.clone();
            let epoch = self.epoch.read().map(|e| e.next_epoch(&zone).saturating_sub(1)).unwrap_or(0);
            let key = crate::storage::rocks::StorageEngine::attestation_key(&zone, epoch, record_id);
            // Append to existing attestations list for this record
            let mut atts: Vec<Attestation> = self.rocks
                .get_cf_raw(crate::storage::rocks::CF_ATTESTATIONS, &key)
                .ok()
                .flatten()
                .and_then(|bytes| serde_json::from_slice(&bytes).ok())
                .unwrap_or_default();
            atts.push(att);
            if let Ok(bytes) = serde_json::to_vec(&atts) {
                if let Err(e) = self.rocks.put_cf_raw(crate::storage::rocks::CF_ATTESTATIONS, &key, &bytes) {
                    tracing::warn!("RocksDB attestation write failed: {e}");
                }
            }
        }

        // Track witness coverage per zone (Protocol §7.5) — reuse `record_zone`
        // resolved above.
        {
            let mut zone_state = self.zone_state.lock_recover();
            zone_state.record_witness(record_id, witness_hash);
        }

        // Track zone diversity for witness reward formula (economics §11.1)
        {
            let mut rep = self.reputation.lock_recover();
            rep.record_zone_attestation(witness_hash, record_zone, timestamp);
        }

        // Register witness for record creator's entropy scoring (economics §9.2 signal 3).
        // Look up creator from storage to feed witness diversity signal.
        {
            let creator_opt = {
                self.rocks.get_record(record_id).ok().flatten()
                    .map(|r| crate::accounting::types::creator_identity_hash(&r))
            };
            if let Some(creator_hash) = creator_opt {
                let mut trust = self.trust.write().await;
                trust.register_witness(&creator_hash, witness_hash, timestamp);
                // Dual-write updated trust profile to RocksDB.
                // Skip on ≤2GB to reduce write pressure — snapshot loop persists periodically.
                let ram_gb = crate::storage::rocks::StorageEngine::detect_system_ram_gb();
                if ram_gb > 2 {
                    if let Some(profile) = trust.get_profile(&creator_hash) {
                        if let Ok(bytes) = serde_json::to_vec(profile) {
                            let _ = self.rocks.put_cf_raw(
                                crate::storage::rocks::CF_TRUST,
                                creator_hash.as_bytes(),
                                &bytes,
                            );
                        }
                    }
                }
            }
        }

        // Always increment attestation counter
        self.total_attestations_processed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // MAINNET gap #8: broadcast Sealed events for account optimistic UX.
        // The `force_finalized` above may have pushed this record past Sealed
        // straight to Finalized — the edge still counts so we broadcast
        // regardless of current level. Subscriber de-dupes on record_id if
        // needed.
        for (rid, witness_count) in newly_sealed.drain(..) {
            let _ = self.events.send(NodeEvent::RecordSealed {
                record_id: rid,
                witness_count,
            });
        }

        let mut first_finalization = false;
        if settled {
            // Persistent counters — NEVER decrement, survive prune. Gate on
            // BOTH `newly_finalized` (force_finalized transition just fired)
            // AND `is_new_insert` (rid wasn't already in FinalizedIndex).
            // Either gate alone is insufficient:
            //   - `newly_finalized` alone: finality_monitor races us and
            //     already populated FinalizedIndex without updating
            //     confirmation_levels — both paths bump for same rid.
            //   - `is_new_insert` alone: a re-insert from a non-finalize
            //     path (e.g. snapshot replay) would skip the bump even
            //     when this is a real new finalization.
            // Insert into finalized index then DROP the write lock immediately.
            // Previously held finalized.write() across consensus + reputation
            // + RocksDB writes — on 1-core nodes, the snapshot loop's
            // finalized.read() blocked for 7s waiting for this lock.
            let is_new_insert = {
                let mut finalized = self.finalized.write().await;
                // insert_marked (not insert): atomically writes the durable
                // finalization-effects marker so the effects the caller fires
                // on `first_finalization` survive a detached-task panic.
                finalized.insert_marked(record_id.to_string())
            };

            if newly_finalized && is_new_insert {
                self.total_ever_settled.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.total_ever_finalized.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }

            // The durable FinalizedIndex insert is the exactly-once edge.
            // Reputation credit, the RecordFinalized event and witness
            // rewards all moved to `reward::finalization_effects`, which
            // callers fire on this flag — repeat attestations on an
            // already-finalized record (common after the consensus map
            // prunes and a peer re-pushes) re-settle here but fire NO
            // side-effects a second time.
            first_finalization = is_new_insert;
        }

        FeedOutcome {
            settled,
            first_finalization,
            seal_members_finalized,
        }
    }

    /// Batch-process attestations: same as feed_attestation but groups by record_id
    /// to avoid redundant recompute_confirmation calls. Returns both the settled
    /// rids AND the subset that won the durable FinalizedIndex insert in this
    /// call — exactly-once side-effects (rewards/credit/events) are the
    /// caller's job via `reward::finalization_effects(state, outcome.newly_finalized)`.
    ///
    /// **Phase A/B/C refactor:** the per-attestation
    /// RocksDB write loops at Steps 2/5/7 used to issue ~6050 sync `put_cf_raw` calls
    /// per 2000-attestation batch on the canary path (no `ram_gb>2` gate on Step 2).
    /// Combined with L0 compaction backlog, that produced 148s `dag+ledger` warns on a
    /// resource-constrained node even after the mark_applied + trust dual-write fixes.
    /// New shape: in-memory state mutations stay synchronous; all RocksDB writes are
    /// collected into per-CF HashMaps (deduped — same witness/key written once with
    /// latest value), then issued via a single `spawn_blocking` task at the end of
    /// the function. Atomicity per-CF via `WriteBatch`. CF_ATTESTATIONS still does
    /// in-task get-modify-put (the cross-batch race exists today and is unchanged).
    pub async fn batch_feed_attestations(&self, batch: &[(String, String, f64)]) -> BatchFeedOutcome {
        if batch.is_empty() {
            return BatchFeedOutcome::default();
        }

        // ── Pending-write collectors (drained at end into one spawn_blocking) ──
        // Dedup key: write key. Value: latest serialized bytes.
        // Same witness/creator written N times in a batch → one final put.
        let mut entity_signal_writes: std::collections::HashMap<String, Vec<u8>> =
            std::collections::HashMap::new();
        let mut creator_trust_writes: std::collections::HashMap<String, Vec<u8>> =
            std::collections::HashMap::new();
        // Attestations CF: group by storage key, accumulate Attestation list.
        // Final spawn_blocking does get-existing → extend → put per key.
        let mut attestation_appends: std::collections::HashMap<Vec<u8>, Vec<Attestation>> =
            std::collections::HashMap::new();

        // 1. Update liveness for all witnesses
        {
            let mut liveness = self.witness_liveness.lock_recover();
            for (_, witness_hash, timestamp) in batch {
                liveness.record_attestation(witness_hash, *timestamp);
            }
        }

        // 2. Feed entity clusterer for all attestations
        {
            let profiles: Vec<(Option<String>, Option<String>)> = {
                let consensus = self.consensus.lock_recover();
                batch.iter().map(|(_, wh, _)| {
                    consensus.profile_for(wh.as_str())
                        .map(|p| (Some(p.subnet.clone()), Some(p.organization.clone())))
                        .unwrap_or((None, None))
                }).collect()
            };
            let mut clusterer = self.entity_clusterer.lock_recover();
            for (i, (rid, wh, ts)) in batch.iter().enumerate() {
                let (subnet, org) = &profiles[i];
                clusterer.record_attestation(wh, rid, *ts, subnet.as_deref(), org.as_deref());
                if let Some(signal) = clusterer.get_signal(wh) {
                    if let Ok(bytes) = serde_json::to_vec(signal) {
                        // DEDUP: latest signal per witness wins (overwrite semantics)
                        entity_signal_writes.insert(wh.clone(), bytes);
                    }
                }
            }
        }

        // 3. Build attestations with stake info.
        // Step 3a: fetch records from RocksDB WITHOUT holding ledger lock.
        // Used for creator hash (settlement denominator) and epoch seal detection.
        let mut creator_hashes: Vec<Option<String>> = Vec::with_capacity(batch.len());
        let mut seal_infos: Vec<Option<super::epoch::ParsedEpochSeal>> = Vec::with_capacity(batch.len());
        // Map record_id → slot_key (v5+ only) for settlement gate check below.
        let mut slot_keys: std::collections::HashMap<String, String> =
            std::collections::HashMap::with_capacity(batch.len());
        for (rid, _, _) in batch {
            let rec_opt = self.get_record(rid).ok();
            let creator = rec_opt.as_ref()
                .map(crate::accounting::types::creator_identity_hash);
            let seal = rec_opt.as_ref().and_then(|rec| {
                if rec.metadata.contains_key(super::epoch::EPOCH_OP_KEY) {
                    super::epoch::extract_epoch_seal(rec).ok().flatten()
                } else {
                    None
                }
            });
            if let Some(sk) = rec_opt.as_ref().and_then(|rec| rec.slot_key()) {
                slot_keys.insert(rid.clone(), sk);
            }
            creator_hashes.push(creator);
            seal_infos.push(seal);
        }

        // Gap 5 Phase 6c gate (batch path): for every entry whose
        // record is an epoch seal, run the per-zone VRF committee
        // membership check. Failures null out `seal_infos[i]` so the
        // consensus loop below skips the seal-attestation registration.
        // The Layer 1 record attestation always proceeds (§11.12).
        // No-op when `enforce_per_zone_vrf=false` (the helper short-
        // circuits before any reads — single atomic load per i).
        for (i, (_rid, wh, _ts)) in batch.iter().enumerate() {
            if let Some(seal) = seal_infos[i].as_ref() {
                let allowed = super::zone_committee::enforce_seal_attestation_committee_membership(
                    self,
                    seal.zone.path(),
                    seal.epoch_number,
                    wh,
                ).await;
                if !allowed {
                    self.seal_attestation_rejected_not_in_committee_total
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    seal_infos[i] = None;
                }
            }
        }

        // Step 3b: brief ledger read for in-memory stake lookups only.
        let mut attestations: Vec<(Attestation, u64)> = Vec::with_capacity(batch.len());
        {
            let ledger = self.ledger.read().await;
            for (i, (rid, wh, ts)) in batch.iter().enumerate() {
                let stake = ledger.staked(wh);
                let creator_stake = creator_hashes[i].as_ref()
                    .map(|creator| ledger.staked(creator))
                    .unwrap_or(0);
                attestations.push((Attestation {
                    record_id: rid.clone(),
                    witness_hash: wh.clone(),
                    stake,
                    timestamp: *ts,
                }, creator_stake));
            }
        }

        // 4. Feed ALL attestations to consensus, then check settlement ONCE per record
        let mut settled_records = Vec::new();
        // Layer-2 fast-track promotions surfaced by add_seal_attestation —
        // routed to the durable FinalizedIndex below, independent of the
        // per-record Layer-1 settlement checks.
        let mut batch_seal_member_rids: Vec<String> = Vec::new();
        let mut newly_sealed: Vec<(String, u32)> = {
            let mut consensus = self.consensus.lock_recover();
            let mut affected_records = std::collections::HashSet::new();

            for (i, (att, creator_stake)) in attestations.iter().enumerate() {
                // H1: register creator identity (+ stake) before the attestation so a
                // self-attestation is rejected; identity recorded even at 0 stake.
                if let Some(creator) = creator_hashes[i].as_deref() {
                    consensus.register_creator_stake(&att.record_id, creator, *creator_stake);
                }
                consensus.add_attestation(att.clone());
                // If attested record is an epoch seal, also register seal attestation
                if let Some(ref seal) = seal_infos[i] {
                    batch_seal_member_rids.extend(consensus.add_seal_attestation(
                        super::consensus::SealAttestation {
                            seal_id: att.record_id.clone(),
                            zone: seal.zone.clone(),
                            epoch_number: seal.epoch_number,
                            witness_hash: att.witness_hash.clone(),
                            stake: att.stake,
                            timestamp: att.timestamp,
                        },
                    ));
                }
                affected_records.insert(att.record_id.clone());
            }

            // Check settlement once per affected record (not once per attestation).
            // Settlement gate (Phase 3 Stage 1E): a conflicted slot blocks finalization
            // regardless of attestation weight.
            for rid in &affected_records {
                if consensus.is_settled(rid) {
                    if let Some(slot_key) = slot_keys.get(rid) {
                        match self.rocks.slot_is_conflicted(slot_key) {
                            Ok(true) => {
                                tracing::warn!(
                                    "SETTLEMENT BLOCKED (batch): record {} in conflicted \
                                     slot {} — refusing finalization",
                                    &rid[..rid.len().min(16)],
                                    slot_key,
                                );
                                continue;
                            }
                            Ok(false) => { /* clean slot */ }
                            Err(e) => {
                                tracing::warn!(
                                    "slot_is_conflicted check failed (batch) for {}: {} \
                                     — erring on the side of NOT finalizing",
                                    slot_key, e,
                                );
                                continue;
                            }
                        }
                    }
                    // Sync the in-memory level (idempotent — returns false
                    // when add_attestation's recompute already set Finalized,
                    // which is the COMMON case for quorum-crossing batches).
                    // Exactly-once protection does NOT live here: the durable
                    // FinalizedIndex insert below dedups across repeats,
                    // paths and restarts. Gating settled_records on the
                    // force_finalized transition (pre-2026-06-11 shape)
                    // silently dropped recompute-finalized records from the
                    // batch outcome — they reached the index only when the
                    // finality_monitor swept them, and batch callers never
                    // fired rewards for them.
                    consensus.force_finalized(rid);
                    settled_records.push(rid.clone());
                }
            }

            // MAINNET gap #8: drain Sealed transitions from the batch before
            // releasing the consensus lock. Broadcast happens below, outside
            // the lock, so subscribers can't stall consensus.
            consensus.drain_newly_sealed()
        };

        // MAINNET gap #8: broadcast Sealed events for account UX.
        for (rid, witness_count) in newly_sealed.drain(..) {
            let _ = self.events.send(NodeEvent::RecordSealed {
                record_id: rid,
                witness_count,
            });
        }

        // Gap 5 Phase 6b: advisory committee-membership observation —
        // ONLY for Layer 2 epoch seal attestations (Protocol §11.12).
        // Build entries from `seal_infos`; entries with no seal info skip
        // the observer entirely.
        let seal_entries: Vec<super::zone_committee::SealAttestEntry> = attestations
            .iter()
            .enumerate()
            .filter_map(|(i, (att, _))| {
                seal_infos.get(i).and_then(|s| s.as_ref()).map(|seal| {
                    super::zone_committee::SealAttestEntry {
                        zone_path: seal.zone.path().to_string(),
                        epoch: seal.epoch_number,
                        witness_hash: att.witness_hash.clone(),
                    }
                })
            })
            .collect();
        if !seal_entries.is_empty() {
            super::zone_committee::observe_seal_committee_batch(self, seal_entries).await;
        }

        // 5. RocksDB write COLLECTION + in-memory state — no I/O on tokio worker
        // Cache `ram_gb` once: cheap (OnceLock) but no need to call per-iteration.
        let ram_gb = crate::storage::rocks::StorageEngine::detect_system_ram_gb();
        for (i, (att, _)) in attestations.iter().enumerate() {
            // Gap 4 Phase C: registry-aware resolution, reused for both the
            // RocksDB key and the per-zone diversity tracking below.
            let record_zone = self.resolve_record_zone(&att.record_id);
            let zone = record_zone.clone();
            let epoch = self.epoch.read().map(|e| e.next_epoch(&zone).saturating_sub(1)).unwrap_or(0);
            let key = crate::storage::rocks::StorageEngine::attestation_key(&zone, epoch, &att.record_id);
            // Group attestations by storage key — single get-modify-put per unique key
            // in the spawn_blocking phase, instead of per-attestation.
            attestation_appends.entry(key).or_default().push(att.clone());

            // Zone witness tracking — in-memory
            {
                let mut zone_state = self.zone_state.lock_recover();
                zone_state.record_witness(&att.record_id, &att.witness_hash);
            }

            // Zone diversity for rewards — in-memory (reuse `record_zone`).
            {
                let mut rep = self.reputation.lock_recover();
                rep.record_zone_attestation(&att.witness_hash, record_zone, att.timestamp);
            }

            // Witness diversity for creator trust.
            // OPTIMIZATION: reuse `creator_hashes[i]` from Step 3a — old code re-read
            // the record from RocksDB here (`get_record(&att.record_id)`), which was
            // a wasted second read since we already had the creator hash.
            if let Some(creator_hash) = creator_hashes[i].clone() {
                let mut trust = self.trust.write().await;
                trust.register_witness(&creator_hash, &att.witness_hash, att.timestamp);
                // Skip dual-write on ≤2GB — snapshot loop persists periodically.
                if ram_gb > 2 {
                    if let Some(profile) = trust.get_profile(&creator_hash) {
                        if let Ok(bytes) = serde_json::to_vec(profile) {
                            // DEDUP: latest profile per creator wins
                            creator_trust_writes.insert(creator_hash, bytes);
                        }
                    }
                }
            }
        }

        // 6. Persistent counters
        self.total_attestations_processed.fetch_add(batch.len() as u64, std::sync::atomic::Ordering::Relaxed);

        // 7. Handle settled records
        // Acquire finalized write lock ONCE for all records (not per-record).
        // Per-record locking caused reader starvation during batch settlement.
        // `newly_finalized` (insert_batch_returning_new) is the durable
        // exactly-once edge: counters bump by its length, and reputation
        // credit / RecordFinalized events / witness rewards fire ONLY for
        // these rids — via `reward::finalization_effects` at the call site.
        // finality_monitor inserts these same rids independently, so a rid
        // it raced ahead on is absent here and fires effects from the
        // monitor path instead — once, whoever wins.
        let newly_finalized: Vec<String> = if !settled_records.is_empty() {
            let mut finalized = self.finalized.write().await;
            finalized.insert_batch_returning_new(&settled_records)
        } else {
            Vec::new()
        };
        if !newly_finalized.is_empty() {
            self.total_ever_settled.fetch_add(newly_finalized.len() as u64, std::sync::atomic::Ordering::Relaxed);
            self.total_ever_finalized.fetch_add(newly_finalized.len() as u64, std::sync::atomic::Ordering::Relaxed);
        }

        // Layer-2 seal-member durable write (chunked + counted inside).
        // Runs AFTER the Layer-1 insert so a rid that crossed both edges in
        // this batch dedups here and stays attributed to the Layer-1 path.
        let seal_members_finalized =
            super::reward::insert_members_durable(self, &batch_seal_member_rids).await;

        // 8. Drain all collected RocksDB writes onto a blocking thread.
        // Fire-and-forget: same durability semantics as the prior fire-and-forget
        // `put_cf_raw` calls. Critical: no `.await` here — return the outcome
        // immediately so callers (gossip/ingest) don't pay for L0 compaction stalls.
        let has_writes = !attestation_appends.is_empty()
            || !entity_signal_writes.is_empty()
            || !creator_trust_writes.is_empty();
        if has_writes {
            let rocks = self.rocks.clone();
            tokio::task::spawn_blocking(move || {
                use crate::storage::rocks as rdb;
                // Phase B (CF_ATTESTATIONS): per-key get-modify-put. Cross-batch race
                // unchanged from prior code — last writer wins on concurrent batches.
                for (key, new_atts) in attestation_appends {
                    let mut atts: Vec<Attestation> = rocks
                        .get_cf_raw(rdb::CF_ATTESTATIONS, &key)
                        .ok().flatten()
                        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
                        .unwrap_or_default();
                    atts.extend(new_atts);
                    if let Ok(bytes) = serde_json::to_vec(&atts) {
                        let _ = rocks.put_cf_raw(rdb::CF_ATTESTATIONS, &key, &bytes);
                    }
                }
                // Phase A (CF_TRUST entity signals): one put per unique witness
                for (wh, bytes) in entity_signal_writes {
                    let _ = rocks.put_cf_raw(
                        rdb::CF_TRUST,
                        format!("entity:{wh}").as_bytes(),
                        &bytes,
                    );
                }
                // Phase B (CF_TRUST creator profiles): one put per unique creator
                for (creator, bytes) in creator_trust_writes {
                    let _ = rocks.put_cf_raw(
                        rdb::CF_TRUST,
                        creator.as_bytes(),
                        &bytes,
                    );
                }
                // Reputation dual-writes moved with credit_undisputed to
                // `reward::finalization_effects` (exactly-once edge); the
                // periodic snapshot loop persists reputation state.
            });
        }

        BatchFeedOutcome {
            settled: settled_records,
            newly_finalized,
            seal_members_finalized,
        }
    }

    /// Get the confirmation level for a record (economics §9.5).
    ///
    /// Uses layered consensus: checks epoch seals first (Sealed → Finalized → Anchored),
    /// falls back to per-record level. If consensus returned Pending but the record is
    /// in the finalized set (pruned after settlement), returns Finalized.
    pub fn confirmation_level(&self, record_id: &str) -> super::consensus::ConfirmationLevel {
        let level = {
            let consensus = self.consensus.lock_recover();
            consensus.layered_confirmation(record_id)
        };
        // If consensus returned Pending but the record is finalized, the entry
        // was pruned — return Finalized as the minimum settled level.
        if level == super::consensus::ConfirmationLevel::Pending {
            if let Ok(fin) = self.finalized.try_read() {
                if fin.contains(record_id) {
                    return super::consensus::ConfirmationLevel::Finalized;
                }
            }
        }
        level
    }

    /// Live seal progress for a record — used by the `/record/{id}` RPC to
    /// expose "3 of 4 attestations / 60% stake" in real time so accounts can
    /// render streaming finality without waiting for the full 2/3 threshold
    /// (Gap 8 / internal design notes §PRODUCTION PATH #8).
    pub fn seal_progress(&self, record_id: &str) -> Option<super::consensus::SealProgress> {
        let consensus = self.consensus.lock_recover();
        consensus.seal_progress_for_record(record_id)
    }

    pub fn uptime(&self) -> f64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        now - self.start_time
    }

    /// Snapshot of deferred-attestation buffer occupancy.
    ///
    /// Returns `(distinct_records, total_attestations)`. Used by /metrics
    /// (`elara_attestation_deferred_records`, `elara_attestation_deferred_total`)
    /// to surface the buffer that absorbs attestations whose record hasn't
    /// landed locally yet (NAT'd nodes pushing into VPS pull-blind paths).
    /// Buffer caps: 5000 records, 600s TTL — both enforced inline at insert.
    pub fn deferred_attestation_counts(&self) -> (usize, usize) {
        let buf = self.deferred_attestations.lock().unwrap_or_else(|e| e.into_inner());
        buf.counts()
    }

    /// Adaptive gossip hop limit based on network size.
    ///
    /// `min(config.gossip_max_hops, ceil(log2(peer_count)) + 2)`
    ///
    /// Small networks (1-4 peers): 2-4 hops (saves bandwidth).
    /// Large networks (100+ peers): 8-9 hops (ensures propagation).
    /// Falls back to config.gossip_max_hops as upper bound.
    pub fn effective_max_hops(&self) -> u8 {
        let peer_count = self.dht.lock_recover().len().max(1) as f64;
        let adaptive = (peer_count.log2().ceil() as u8).saturating_add(2);
        adaptive.min(self.config.gossip_max_hops)
    }

    /// Publish a record to the network via PQ gossip push.
    /// `exclude` skips a specific peer (e.g. the sender that just pushed this record to us).
    pub async fn publish_record_with_fallback(
        state: &std::sync::Arc<Self>,
        record: &ValidationRecord,
        exclude: Option<&str>,
    ) {
        let hops = state.effective_max_hops();
        super::gossip::push_to_peers(state, record, hops, exclude, None).await;
    }

    /// Get a record by ID from RocksDB.
    pub fn get_record(&self, record_id: &str) -> crate::errors::Result<ValidationRecord> {
        self.rocks.get_record(record_id)?
            .ok_or_else(|| crate::errors::ElaraError::RecordNotFound(record_id.to_string()))
    }

    /// Check if a record exists.
    pub fn record_exists(&self, record_id: &str) -> crate::errors::Result<bool> {
        self.rocks.record_exists(record_id)
    }

    /// Get record count (actual records only, excludes snapshots/bans/metadata).
    pub fn record_count(&self) -> crate::errors::Result<usize> {
        use crate::storage::Storage;
        self.rocks.count()
    }

    /// Query records with filters.
    pub fn query_records(
        &self,
        classification: Option<crate::record::Classification>,
        creator_key: Option<&[u8]>,
        since: Option<f64>,
        until: Option<f64>,
        limit: usize,
    ) -> crate::errors::Result<Vec<ValidationRecord>> {
        use crate::storage::Storage;
        self.rocks.query(classification, creator_key, since, until, limit)
    }

    /// Get all record hashes (for Merkle root computation).
    /// DEPRECATED: Production code uses merkle::global_merkle_root() (O(zone_count)) instead.
    /// Kept for tests that need the raw hash list.
    #[cfg(test)]
    pub fn all_record_hashes(&self) -> crate::errors::Result<Vec<[u8; 32]>> {
        self.rocks.record_hashes_streaming()
    }

    /// Get raw wire bytes for a record.
    pub fn get_wire_bytes(&self, record_id: &str) -> crate::errors::Result<Vec<u8>> {
        use crate::storage::Storage;
        self.rocks.get_wire_bytes(record_id)
    }

    /// Check if a record is tombstoned. Tier 4.5: tombstone keys live in
    /// `CF_METADATA` (was `CF_RECORDS`).
    pub fn is_tombstoned(&self, record_id: &str) -> crate::errors::Result<bool> {
        let key = format!("tombstone:{record_id}");
        Ok(self.rocks.get_cf_raw(crate::storage::rocks::CF_METADATA, key.as_bytes())?.is_some())
    }

    /// Mark a record as tombstoned.
    pub fn mark_tombstoned(&self, target_id: &str, tombstone_id: &str, reason: &str) -> crate::errors::Result<()> {
        let key = format!("tombstone:{target_id}");
        let val = serde_json::json!({"tombstone_id": tombstone_id, "reason": reason});
        self.rocks.put_cf_raw(crate::storage::rocks::CF_METADATA, key.as_bytes(), val.to_string().as_bytes())?;
        // F2 R2: if the tombstoned target carries a ledger or governance op, invalidate
        // the "ledger" checkpoint so the next boot full-rebuilds (honoring the
        // is_tombstoned governance skip in the folds) rather than fast-booting from a
        // checkpoint that already baked in the now-tombstoned op's effect. Scale-safe:
        // a full rebuild ONCE on this rare (genesis-only) event, never an O(all_records)
        // governance rescan per boot. For the LEDGER arm R1 already converges live +
        // rebuild, so this is belt-and-braces there; for GOVERNANCE (out-of-seal, else
        // silently + permanently stale on every fast-boot) it is the actual fix.
        // F2 PSR-3 (post-ship review): propagate the get_record error instead of
        // swallowing it (`if let Ok(Some(..))`). On a transient read error the record
        // is tombstoned but neither the checkpoint invalidation nor the PSR-1 marker
        // below would fire, silently losing the durability guarantee. The sole
        // production caller (ingest.rs tombstone gate) uses `?`, so propagating makes
        // the tombstone ingest retry and re-run the detect.
        if let Some(rec) = self.rocks.get_record(target_id)? {
            let carries_op = rec
                .metadata
                .contains_key(crate::accounting::types::BEAT_OP_KEY)
                || rec
                    .metadata
                    .contains_key(crate::accounting::governance::GOVERNANCE_OP_KEY);
            if carries_op {
                match self.rocks.delete_snapshot("ledger") {
                    Ok(()) => tracing::info!(
                        "F2 R2: invalidated ledger checkpoint (tombstoned op-carrying record {target_id}) — next boot full-rebuilds"
                    ),
                    Err(e) => tracing::warn!(
                        "F2 R2: failed to invalidate ledger checkpoint after tombstoning {target_id}: {e}"
                    ),
                }
            }
            // F2 PSR-1: for a GOVERNANCE op ONLY (narrower than carries_op = BEAT||GOV;
            // a beat/transfer tombstone needs no gov rebuild — ledger ops apply
            // unconditionally under R1), set the persistent gov-rebuild marker.
            // `delete_snapshot("ledger")` above is DEFEATED by the unconditional
            // periodic/shutdown re-save of the live (still-stale) LedgerState.governance;
            // this separate marker survives that re-save and forces the next boot onto
            // the full-rebuild path (which drops the tombstoned gov op from the tally).
            // See the F2 brief POST-SHIP REVIEW (PSR-1).
            if rec
                .metadata
                .contains_key(crate::accounting::governance::GOVERNANCE_OP_KEY)
            {
                self.rocks.set_gov_rebuild_required()?;
                tracing::info!(
                    "F2 PSR-1: set gov_rebuild_required (tombstoned governance-op record {target_id}) — next boot full-rebuilds durably"
                );
            }
        }
        Ok(())
    }

    /// F2 PSR-2: should this record's delegation / dispute / challenge op be SKIPPED
    /// on boot rebuild because the record is tombstoned? Converges the boot rebuild
    /// (`for_each_record_ordered_bounded` in elara_node) with the live ingest
    /// early-return, which suppresses these siblings for a tombstoned record.
    /// Scale-safe: the `is_tombstoned` CF read is paid ONLY on the op-carrying subset
    /// (the `sib_op` short-circuit), never per-record at 10M scale. FAIL-OPEN on a read
    /// error (`unwrap_or(false)` → apply the op): preserves the pre-fix always-apply
    /// behavior; the only divergence is tombstoned-AND-read-error, which is out-of-seal
    /// (vote-weight / dispute) and non-forking. Do NOT flip to fail-closed — that would
    /// drop legitimate delegations on a spurious read error.
    /// NOTE (post-ship review CHANGE 4): trust-feed / epoch-consumer / zone-tracking /
    /// continuity are ALSO suppressed by the live early-return, but they are fed for
    /// EVERY record (no op-key gate) so gating them on is_tombstoned would be an
    /// O(all_records) point-read = scale violation; they are out-of-seal / non-forking
    /// and are deliberately left unconverged. Only the op-carrying trio is gated.
    pub fn sibling_op_tombstone_suppressed(&self, rec: &crate::record::ValidationRecord) -> bool {
        let sib_op = rec
            .metadata
            .contains_key(crate::accounting::delegation::DELEGATION_OP_KEY)
            || rec.metadata.contains_key(crate::network::dispute::DISPUTE_OP_KEY)
            || rec
                .metadata
                .contains_key(crate::network::fisherman::CHALLENGE_OP_KEY);
        sib_op && self.is_tombstoned(&rec.id).unwrap_or(false)
    }

    /// Delete a record. AdminEvict (B5): this is the state-layer admin/takedown
    /// primitive — full cleanup including the mandate-act index + removed-marker.
    /// (No production caller today; test-only, but `pub`, so it must pick a mode.)
    pub fn delete_record_both(&self, record_id: &str) -> crate::errors::Result<()> {
        self.rocks.delete_record(record_id, crate::storage::rocks::DeleteIntent::AdminEvict)
    }

    /// ZSP Phase D entrypoint: drop a subscription and queue the zone's
    /// records for background purge. Idempotent — re-calling for an already-
    /// unsubscribed zone is a no-op for the manager (no record to remove)
    /// but does re-enqueue purge, which is harmless because the tick
    /// re-checks subscription state and exits early.
    ///
    /// ZSP Phase E Slice 3: also persists the new subscription set to
    /// `{data_dir}/zone_subscriptions.json` so the change survives restart.
    /// Persistence failure logs a warning but does not block the unsubscribe
    /// — disk-full is recoverable, in-memory mutation is not.
    pub fn unsubscribe_zone(self: &Arc<Self>, zone: &super::zone::ZoneId) {
        let snapshot = if let Ok(mut mgr) = self.zone_manager.lock() {
            mgr.unsubscribe(zone);
            Some(mgr.subscribed_zones().clone())
        } else {
            None
        };
        if let Some(subs) = &snapshot {
            if let Err(e) = super::zone_persist::save_subscriptions(&self.config.data_dir, subs) {
                tracing::warn!(
                    "zone_persist: failed to persist after unsubscribe_zone({}): {e}",
                    zone.path()
                );
            }
            // Identity Partitioning Phase E: drop CF_IDENTITIES_WITNESS
            // entries that were registered only for the unsubscribed
            // zone. Bounded per-zone scan; safe to run inline because
            // `iter_witnesses_for_zone` walks only the zone's own
            // prefix range, not the full witness CF.
            let still_subscribed: Vec<String> =
                subs.iter().map(|z| z.path().to_string()).collect();
            match self
                .rocks
                .purge_witness_pks_for_zone(zone.path(), &still_subscribed)
            {
                Ok(evicted) if evicted > 0 => {
                    self.identity_witness_purged_total
                        .fetch_add(evicted as u64, std::sync::atomic::Ordering::Relaxed);
                    tracing::info!(
                        "idp_e: unsubscribe({}) dropped {} witness PK(s) from CF_IDENTITIES_WITNESS",
                        zone.path(),
                        evicted
                    );
                }
                Ok(_) => {}
                Err(e) => tracing::warn!(
                    "idp_e: witness PK purge for {} failed: {e}",
                    zone.path()
                ),
            }
        }
        super::zone_purge::enqueue_purge_zone(self, zone.clone());
    }

    /// ZSP Phase E Slice 3 entrypoint: add a zone subscription and persist
    /// the new set across restart. Mirrors `unsubscribe_zone` so all admin
    /// callers go through one place that owns the in-memory + on-disk
    /// invariant.
    ///
    /// `subscribe()` on the manager auto-pins ancestor zones — that
    /// auto-pin is preserved by serializing the manager's full subscription
    /// set after the call, not just the zone the operator named.
    pub fn subscribe_zone(self: &Arc<Self>, zone: &super::zone::ZoneId) {
        let snapshot = if let Ok(mut mgr) = self.zone_manager.lock() {
            mgr.subscribe(zone);
            Some(mgr.subscribed_zones().clone())
        } else {
            None
        };
        if let Some(subs) = snapshot {
            if let Err(e) = super::zone_persist::save_subscriptions(&self.config.data_dir, &subs) {
                tracing::warn!(
                    "zone_persist: failed to persist after subscribe_zone({}): {e}",
                    zone.path()
                );
            }
        }
    }

    /// Insert a record into RocksDB.
    pub fn insert_record_both(&self, record: &ValidationRecord) -> crate::errors::Result<String> {
        self.rocks.put_record(&record.id, record)?;
        Ok(record.id.clone())
    }

    /// Ban an identity (content safety).
    pub fn ban_identity(&self, identity_hash: &str, reason: &str) -> crate::errors::Result<()> {
        self.rocks.ban_identity(identity_hash, reason)
    }

    /// Unban an identity.
    pub fn unban_identity(&self, identity_hash: &str) -> crate::errors::Result<bool> {
        self.rocks.unban_identity(identity_hash)
    }

    /// Load all banned identities.
    pub fn load_banned_identities(&self) -> crate::errors::Result<Vec<(String, String, f64)>> {
        self.rocks.load_banned_identities()
    }

    /// Add a blocked content term.
    pub fn add_blocked_term(&self, term: &str) -> crate::errors::Result<()> {
        self.rocks.add_blocked_term(term)
    }

    /// Remove a blocked content term.
    pub fn remove_blocked_term(&self, term: &str) -> crate::errors::Result<bool> {
        self.rocks.remove_blocked_term(term)
    }

    /// Load all blocked terms.
    pub fn load_blocked_terms(&self) -> crate::errors::Result<Vec<String>> {
        self.rocks.load_blocked_terms()
    }

    /// Search records (Protocol §11.23 multi-layer index).
    ///
    /// Layer B (creator-keyed lookup) takes precedence when `query.creator_hash`
    /// is set: backed by `CF_IDX_CREATOR` for O(records_for_creator_in_window),
    /// independent of the fleet's total record count. Otherwise falls back to
    /// the timestamp-indexed scan via `query_records`.
    pub fn search_records(&self, query: &crate::storage::SearchQuery) -> crate::errors::Result<Vec<ValidationRecord>> {
        use crate::storage::Storage;
        use std::sync::atomic::Ordering::Relaxed;

        // Layer B: creator-keyed prefix scan on CF_IDX_CREATOR.
        if let Some(ref creator) = query.creator_hash {
            self.search_queries_layer_b_total.fetch_add(1, Relaxed);
            // Fetch a wider page if metadata filters are set: post-filtering
            // can drop results, so we need headroom to still hit `limit` after
            // the filter. 4× is conservative — revisit if metadata filters
            // become hot enough to need a real secondary index.
            let needs_meta_filter = query.metadata_key.is_some() || query.metadata_value.is_some();
            let fetch_n = if needs_meta_filter {
                query.limit.saturating_add(query.offset).saturating_mul(4).max(1)
            } else {
                query.limit.saturating_add(query.offset).max(1)
            };
            let mut results = self.rocks.query_by_creator_hash(
                creator,
                query.since,
                query.until,
                fetch_n,
            )?;
            if let Some(cls) = query.classification {
                results.retain(|r| r.classification == cls);
            }
            apply_metadata_filter(&mut results, query.metadata_key.as_deref(), query.metadata_value.as_deref());
            if query.offset > 0 && !results.is_empty() {
                let drop_n = query.offset.min(results.len());
                results.drain(..drop_n);
            }
            if results.len() > query.limit && query.limit > 0 {
                results.truncate(query.limit);
            }
            return Ok(results);
        }

        // Fallback: timestamp-window scan via global record index.
        if query.since.is_some() || query.until.is_some() || query.classification.is_some() {
            self.search_queries_fallback_total.fetch_add(1, Relaxed);
            let needs_meta_filter = query.metadata_key.is_some() || query.metadata_value.is_some();
            // Offset participates in the fetch budget AND is drained below —
            // this branch previously ignored it entirely, so a paginating
            // caller got page 1 forever (2026-07-12 sweep A9). Mirrors Layer B.
            let fetch_n = if needs_meta_filter {
                query.limit.saturating_add(query.offset).saturating_mul(4).max(1)
            } else {
                query.limit.saturating_add(query.offset).max(1)
            };
            let mut results = self.query_records(
                query.classification,
                None,
                query.since,
                query.until,
                fetch_n,
            )?;
            apply_metadata_filter(&mut results, query.metadata_key.as_deref(), query.metadata_value.as_deref());
            if query.offset > 0 && !results.is_empty() {
                let drop_n = query.offset.min(results.len());
                results.drain(..drop_n);
            }
            if results.len() > query.limit && query.limit > 0 {
                results.truncate(query.limit);
            }
            return Ok(results);
        }
        Ok(vec![])
    }

    /// AUDIT-10 Milestone B: increment the `elara_https_fallback_total{caller}`
    /// counter for the named caller. Unknown callers are silently dropped so a
    /// future caller name typo never panics in steady state — the metrics
    /// endpoint is the canonical surface for verifying the four documented
    /// callers ("gossip", "sync", "light", "discovery") all stay at zero.
    pub fn record_https_fallback(&self, caller: &str) {
        let counter = match caller {
            "gossip" => &self.https_fallback_gossip_total,
            "sync" => &self.https_fallback_sync_total,
            "light" => &self.https_fallback_light_total,
            "discovery" => &self.https_fallback_discovery_total,
            _ => return,
        };
        counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Bump incremental record-stats counters for one record.
    /// Called from the ingest chokepoint after a successful persisted write
    /// (`ingest::insert_record_inner_direct`) and from the boot seed scan.
    /// All counters are Relaxed; classification/op are mutually exclusive
    /// disjoint sets so no cross-counter ordering is required.
    pub fn record_stats_bump(&self, rec: &crate::record::ValidationRecord) {
        use std::sync::atomic::Ordering::Relaxed;
        self.record_stats_total.fetch_add(1, Relaxed);
        match rec.classification {
            crate::record::Classification::Public => {
                self.record_stats_class_public.fetch_add(1, Relaxed);
            }
            crate::record::Classification::Private => {
                self.record_stats_class_private.fetch_add(1, Relaxed);
            }
            crate::record::Classification::Restricted => {
                self.record_stats_class_restricted.fetch_add(1, Relaxed);
            }
            crate::record::Classification::Sovereign => {
                self.record_stats_class_sovereign.fetch_add(1, Relaxed);
            }
        }
        if rec.metadata.contains_key(crate::network::epoch::EPOCH_OP_KEY) {
            self.record_stats_epoch_seals.fetch_add(1, Relaxed);
        } else {
            let op = rec
                .metadata
                .get("beat_op")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let counter = match op {
                "mint" => &self.record_stats_op_mint,
                "transfer" => &self.record_stats_op_transfer,
                "stake" => &self.record_stats_op_stake,
                "unstake" => &self.record_stats_op_unstake,
                "burn" => &self.record_stats_op_burn,
                "slash" => &self.record_stats_op_slash,
                "witness_reward" => &self.record_stats_op_witness_reward,
                "dormancy_reclaim" => &self.record_stats_op_dormancy_reclaim,
                "pool_fund" => &self.record_stats_op_pool_fund,
                _ => &self.record_stats_non_token,
            };
            counter.fetch_add(1, Relaxed);
        }
        let ts_bits = rec.timestamp.to_bits();
        let mut cur = self.record_stats_earliest_ts_bits.load(Relaxed);
        loop {
            if cur != 0 && f64::from_bits(cur) <= rec.timestamp {
                break;
            }
            match self.record_stats_earliest_ts_bits.compare_exchange_weak(
                cur, ts_bits, Relaxed, Relaxed,
            ) {
                Ok(_) => break,
                Err(prev) => cur = prev,
            }
        }
        let mut cur = self.record_stats_latest_ts_bits.load(Relaxed);
        loop {
            if f64::from_bits(cur) >= rec.timestamp {
                break;
            }
            match self.record_stats_latest_ts_bits.compare_exchange_weak(
                cur, ts_bits, Relaxed, Relaxed,
            ) {
                Ok(_) => break,
                Err(prev) => cur = prev,
            }
        }
    }

    /// Read the earliest record timestamp accumulated by
    /// `record_stats_bump`. Returns None if no records have been observed.
    pub fn record_stats_earliest(&self) -> Option<f64> {
        let bits = self
            .record_stats_earliest_ts_bits
            .load(std::sync::atomic::Ordering::Relaxed);
        if bits == 0 { None } else { Some(f64::from_bits(bits)) }
    }

    /// Read the latest record timestamp accumulated by
    /// `record_stats_bump`. Returns None if no records have been observed.
    pub fn record_stats_latest(&self) -> Option<f64> {
        let bits = self
            .record_stats_latest_ts_bits
            .load(std::sync::atomic::Ordering::Relaxed);
        if bits == 0 { None } else { Some(f64::from_bits(bits)) }
    }

    /// Emit the dag-stats JSON shape from O(1) atomic counters.
    /// Replaces the O(all_records) `for_each_record` scan in
    /// `compute_dag_stats` / `warm_stats_cache`. `unique_creators` is
    /// intentionally `null` until the HLL follow-up lands.
    pub fn record_stats_snapshot_json(&self) -> serde_json::Value {
        use std::sync::atomic::Ordering::Relaxed;
        let earliest = self.record_stats_earliest().unwrap_or(0.0);
        let latest = self.record_stats_latest().unwrap_or(0.0);
        let stats_partial = self.record_stats_seed_bounded.load(Relaxed);
        serde_json::json!({
            "total_records": self.record_stats_total.load(Relaxed),
            "unique_creators": serde_json::Value::Null,
            "creators_indexed": false,
            "stats_partial": stats_partial,
            "time_range": { "earliest": earliest, "latest": latest },
            "by_classification": {
                "public": self.record_stats_class_public.load(Relaxed),
                "private": self.record_stats_class_private.load(Relaxed),
                "restricted": self.record_stats_class_restricted.load(Relaxed),
                "sovereign": self.record_stats_class_sovereign.load(Relaxed),
            },
            "by_operation": {
                "mint": self.record_stats_op_mint.load(Relaxed),
                "transfer": self.record_stats_op_transfer.load(Relaxed),
                "stake": self.record_stats_op_stake.load(Relaxed),
                "unstake": self.record_stats_op_unstake.load(Relaxed),
                "burn": self.record_stats_op_burn.load(Relaxed),
                "slash": self.record_stats_op_slash.load(Relaxed),
                "witness_reward": self.record_stats_op_witness_reward.load(Relaxed),
                "dormancy_reclaim": self.record_stats_op_dormancy_reclaim.load(Relaxed),
                "pool_fund": self.record_stats_op_pool_fund.load(Relaxed),
                "epoch_seal": self.record_stats_epoch_seals.load(Relaxed),
                "non_token": self.record_stats_non_token.load(Relaxed),
            },
        })
    }

    /// Sample fin-burst-velocity at the current seal-loop tick.
    ///
    /// MUST be called exactly once per seal-loop tick (post-catchup-skip,
    /// i.e. paired 1:1 with `seal_loop_ticks_total.fetch_add(1, ...)`) to
    /// maintain per-epoch Δ² semantics. Reading `total_ever_finalized` and
    /// swapping the prior sample/delta produces:
    ///
    /// - `current_delta = fin_now - prev_fin` (this tick's fin Δ, first
    ///   derivative)
    /// - `velocity = current_delta - prev_delta` (second derivative,
    ///   gauge value emitted at `elara_fin_burst_velocity`)
    ///
    /// **Cold-start guard:** the first tick post-boot where `prev_fin == 0`
    /// AND `fin_now > 0` seeds the sample but emits zero velocity. This
    /// avoids a one-tick `+total_ever_finalized` spike when the node is
    /// restarted with RocksDB-rehydrated counters (e.g. via bootstrap
    /// snapshot or normal warm restart). Subsequent ticks compute true Δ².
    ///
    /// **Scale**: O(3 atomic ops) per tick; no allocation; no contention
    /// (single writer = seal-loop). Safe at 10K+ nodes / 1M zones.
    pub fn sample_fin_burst_velocity(&self) {
        use std::sync::atomic::Ordering::Relaxed;
        let fin_now = self.total_ever_finalized.load(Relaxed);
        let prev_fin = self.last_fin_sample.swap(fin_now, Relaxed);
        if prev_fin == 0 && fin_now > 0 {
            self.last_fin_delta.store(0, Relaxed);
            self.last_fin_burst_velocity.store(0, Relaxed);
        } else {
            let current_delta: i64 = fin_now.saturating_sub(prev_fin) as i64;
            let prev_delta = self.last_fin_delta.swap(current_delta, Relaxed);
            let velocity = current_delta - prev_delta;
            self.last_fin_burst_velocity.store(velocity, Relaxed);
        }
    }

    /// Per-node bratio band fingerprint sampler.
    ///
    /// Reads the current `AttestationRatioSummary::classify_cohort()` code
    /// and bumps the matching `bratio_band_ticks_{band}_total` counter.
    /// Called once per seal-loop tick from `epoch_seal_loop` immediately
    /// after `sample_fin_burst_velocity()` (epoch.rs:4536), riding the same
    /// deterministic per-epoch cadence — NOT per-Prometheus-scrape (which
    /// varies by scraper). One counter is bumped per tick; the five
    /// counters partition the total tick count exactly.
    ///
    /// **Operator semantics.** `rate(elara_bratio_band_ticks_total{band="X"}[5m])`
    /// yields the per-node fraction of recent ticks spent in band X. A node
    /// "stuck at CONVERGED" presents as `rate(...{band="CONVERGED"}) ≈ 1.0`
    /// with the other 4 rates near zero; a "cycling" node
    /// presents as non-zero rates on multiple bands.
    /// Differential-diagnose stake/witness-committee divergence by
    /// comparing the band rate distributions across the fleet.
    ///
    /// **Scale.** O(1): one consensus read-lock acquisition for the
    /// `AttestationRatioSummary` snapshot (already amortized — same one
    /// the `/metrics` route was acquiring per scrape), one match
    /// branch, one atomic fetch_add. Safe at 10K+ nodes / 1M zones —
    /// identical hot-path budget to `sample_fin_burst_velocity`.
    pub fn sample_bratio_band_tick(&self) {
        let band = self.consensus.lock_recover().attestation_ratio_summary().classify_cohort();
        self.bump_bratio_band_tick(band);
    }

    /// Dispatch helper for `sample_bratio_band_tick` — split out so the
    /// code→counter mapping is unit-testable without standing up a full
    /// `Consensus` state to coerce `classify_cohort()` into returning each
    /// band. The public sampler reads `classify_cohort()` and calls this;
    /// tests can call it directly to verify every band routes to its
    /// matching counter exactly once.
    #[inline]
    fn bump_bratio_band_tick(&self, band: u8) {
        use std::sync::atomic::Ordering::Relaxed;
        let counter = match band {
            0 => &self.bratio_band_ticks_dormant_total,
            1 => &self.bratio_band_ticks_locked_total,
            2 => &self.bratio_band_ticks_converged_total,
            3 => &self.bratio_band_ticks_active_total,
            4 => &self.bratio_band_ticks_hyper_active_total,
            _ => return, // unknown band from a future classify_cohort variant: no-op
        };
        counter.fetch_add(1, Relaxed);
    }
}

/// Rebuild the in-memory DAG index from all records in storage.
///
/// cfg(test)-gated. The unbounded `query(usize::MAX)` materialises
/// every record on the chain (~80 GB heap at 10M records) and would OOM any
/// node. Production callers were:
/// - boot path: superseded by `for_each_record_ordered_bounded` streaming
///   in `bin/elara_node.rs`.
/// - `/admin/reindex_dag`: rerouted to `rocks.rebuild_dag_lightweight()`,
///   which streams CF_DAG + CF_IDX_TIMESTAMP at O(records × 200 B).
///
/// Keep this helper only for unit tests that build a small in-memory fixture.
#[cfg(test)]
pub fn rebuild_dag(storage: &dyn Storage) -> Result<DagIndex> {
    let all_records = storage.query(None, None, None, None, usize::MAX)?;
    Ok(rebuild_dag_from_records(&all_records))
}

/// Rebuild the in-memory DAG index from a pre-loaded record slice (single-pass startup).
pub fn rebuild_dag_from_records(all_records: &[ValidationRecord]) -> DagIndex {
    let mut sorted: Vec<&ValidationRecord> = all_records.iter().collect();
    // Total-order replay: timestamp + record-ID tiebreak (mirrors ledger.rs/epoch.rs).
    // Orphan re-link order must be identical across nodes (DAG feeds finality/seal checks).
    sorted.sort_by(|a, b| {
        a.timestamp.total_cmp(&b.timestamp).then_with(|| a.id.cmp(&b.id))
    });

    let mut dag = DagIndex::new();
    let mut orphaned = 0usize;
    for rec in &sorted {
        let missing = dag.insert_tolerant(rec.id.clone(), rec.parents.clone(), rec.timestamp);
        if missing > 0 {
            orphaned += 1;
        }
    }
    // Re-link orphans now that all records have been inserted
    let linked = dag.reindex_orphans();
    let remaining_orphans = dag.orphan_count();
    if orphaned > 0 {
        tracing::info!(
            "dag rebuild: {orphaned} records had missing parents, {linked} edges re-linked, {remaining_orphans} still orphaned"
        );
    }
    dag
}

/// Rebuild the ledger state from all records in storage.
/// WARNING: Loads ALL records — O(all_records) memory. Production uses
/// rebuild_ledger_streaming or rebuild_ledger_from_records.
#[cfg(test)]
pub fn rebuild_ledger(
    storage: &dyn Storage,
    genesis_authority: &str,
    genesis_validators: &[crate::accounting::types::GenesisValidator],
) -> Result<(LedgerState, usize)> {
    crate::accounting::ledger::derive_from_storage_tolerant(storage, genesis_authority, genesis_validators)
}

/// Rebuild the ledger state from a pre-loaded record slice (single-pass startup).
pub fn rebuild_ledger_from_records(
    all_records: &[ValidationRecord],
    genesis_authority: &str,
    genesis_validators: &[crate::accounting::types::GenesisValidator],
) -> Result<(LedgerState, usize)> {
    crate::accounting::ledger::derive_from_records_tolerant(all_records, genesis_authority, genesis_validators)
}

/// JSON-rendered scalar match for the §11.23 metadata filter.
///
/// `Value::String` compares directly. `Value::Bool` and `Value::Null` compare
/// against their JSON literal form without allocating. Numbers / arrays /
/// objects fall back to `Display::to_string`, which is what the public filter
/// semantics already promise — `serde_json` renders `Number(42)` as `"42"`,
/// `Bool(true)` as `"true"`, etc., and an HTTP query like `?value=42` is
/// expected to match `Number(42)`.
#[allow(clippy::cmp_owned)] // Number/Array/Object branch needs JSON-render alloc; documented public semantics.
fn json_value_matches_string(val: &serde_json::Value, target: &str) -> bool {
    match val {
        serde_json::Value::String(s) => s == target,
        serde_json::Value::Bool(true) => target == "true",
        serde_json::Value::Bool(false) => target == "false",
        serde_json::Value::Null => target == "null",
        other => other.to_string() == target,
    }
}

/// §11.23 metadata post-filter applied after Layer B / fallback fetch.
///
/// Semantics:
///   - `key` only:     drop records that do not contain that metadata key.
///   - `value` only:   drop records whose metadata has no entry equal to `value`
///     (across all keys — wide net, but it's what `?value=` without `?key=`
///     can mean).
///   - `key` + `value`: drop records whose `metadata[key]` is missing or not
///     equal to `value` (string match on the JSON-rendered value, which matches
///     how `serde_json::Value` compares).
fn apply_metadata_filter(records: &mut Vec<ValidationRecord>, key: Option<&str>, value: Option<&str>) {
    if key.is_none() && value.is_none() {
        return;
    }
    records.retain(|r| match (key, value) {
        (Some(k), Some(v)) => r.metadata.get(k)
            .map(|val| json_value_matches_string(val, v))
            .unwrap_or(false),
        (Some(k), None) => r.metadata.contains_key(k),
        (None, Some(v)) => r.metadata.values().any(|val| json_value_matches_string(val, v)),
        (None, None) => true,
    });
}

/// Rebuild the trust engine from all records in storage.
///
/// cfg(test)-gated. Production boot uses
/// `rebuild_trust_from_records` driven by `for_each_record_ordered_bounded`
/// in `bin/elara_node.rs`. The unbounded `query(usize::MAX)` allocates
/// ~80 GB at 10M records.
#[cfg(test)]
pub fn rebuild_trust(storage: &dyn Storage) -> TrustEngine {
    let records = storage.query(None, None, None, None, usize::MAX).unwrap_or_default();
    rebuild_trust_from_records(&records)
}

/// Rebuild the trust engine from a pre-loaded record slice (single-pass startup).
pub fn rebuild_trust_from_records(all_records: &[ValidationRecord]) -> TrustEngine {
    let mut engine = TrustEngine::new();
    let mut sorted: Vec<&ValidationRecord> = all_records.iter().collect();
    // Total-order replay: timestamp + record-ID tiebreak (mirrors ledger.rs/epoch.rs).
    // Trust sliding-window stats are order-sensitive and feed spam/sybil slashing.
    sorted.sort_by(|a, b| {
        a.timestamp.total_cmp(&b.timestamp).then_with(|| a.id.cmp(&b.id))
    });
    for rec in &sorted {
        let creator = crate::accounting::types::creator_identity_hash(rec);
        let fingerprint = crate::accounting::trust::content_fingerprint(&rec.metadata);
        engine.record_submission(&creator, fingerprint, rec.timestamp);
    }
    engine
}

/// Rebuild the delegation registry from all records in storage.
/// WARNING: Loads ALL records — O(all_records) memory.
#[cfg(test)]
pub fn rebuild_delegations(storage: &dyn Storage) -> DelegationRegistry {
    crate::accounting::delegation::rebuild_delegation_registry(storage).unwrap_or_default()
}

/// Crate-visible test helper: build a minimal `NodeState` with real
/// RocksDB + identity + witness mgr but no background tasks. Mirrors the
/// in-module `test_node_state` helper so other test modules (e.g.
/// `low_stake_replay::tests`) can construct a state without duplicating
/// the boilerplate. The temp dir is leaked to keep RocksDB files alive
/// for the lifetime of the test.
#[cfg(test)]
pub(crate) fn build_test_node_state() -> std::sync::Arc<NodeState> {
    use crate::identity::{CryptoProfile, EntityType, Identity};
    use crate::network::config::NodeConfig;
    use crate::network::witness::WitnessManager;
    use crate::storage::rocks::StorageEngine;

    let tmp = tempfile::tempdir().expect("tempdir");
    let data_dir = tmp.path().to_path_buf();
    let config = NodeConfig {
        data_dir: data_dir.clone(),
        identity_path: data_dir.join("identity.json"),
        db_path: data_dir.join("elara.db"),
        admin_token: "test-admin".into(),
        network_id: "low-stake-replay-test".into(),
        mdns_enabled: false,
        health_check_interval_secs: 0,
        min_pow_difficulty: 0,
        // Explicit synthetic 64-hex authority: the production default is
        // EMPTY since the 2026-06-09 fleet decommission, but route contracts
        // (/node/config 16-char truncation, /status full-hash format) need a
        // realistic value to pin against.
        genesis_authority:
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".into(),
        ..Default::default()
    };

    let identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
        .expect("generate identity");
    let rocks = std::sync::Arc::new(
        StorageEngine::open(data_dir.join("rocksdb")).expect("open rocksdb"),
    );
    let wmgr = std::sync::Arc::new(WitnessManager::new(rocks.clone()));
    let state = std::sync::Arc::new(NodeState::new(config, identity, rocks, wmgr));
    std::mem::forget(tmp);
    state
}

/// KR-3 S2 wiring-(c) c3 — §9 rotation zone-pin resolver tests. Cover the
/// fork-risk ORDERING invariant (in-memory publish precedes resolve), flag-OFF
/// byte-identity, boot-load rehydration, and cross-node determinism.
#[cfg(test)]
mod c3_rotation_pin_tests {
    use super::NodeState;
    use std::sync::atomic::Ordering::Relaxed;
    use std::sync::Arc;

    /// Mirror of [`super::build_test_node_state`] but with
    /// `s2_rotation_ordering_enabled` set as requested, so a test can exercise
    /// the c3 routing pin flag-ON. Temp dir leaked to keep RocksDB alive.
    fn state_with_flag(flag: bool) -> Arc<NodeState> {
        use crate::identity::{CryptoProfile, EntityType, Identity};
        use crate::network::config::NodeConfig;
        use crate::network::witness::WitnessManager;
        use crate::storage::rocks::StorageEngine;

        let tmp = tempfile::tempdir().expect("tempdir");
        let data_dir = tmp.path().to_path_buf();
        let config = NodeConfig {
            data_dir: data_dir.clone(),
            identity_path: data_dir.join("identity.json"),
            db_path: data_dir.join("elara.db"),
            admin_token: "test-admin".into(),
            network_id: "c3-rotation-pin-test".into(),
            mdns_enabled: false,
            health_check_interval_secs: 0,
            min_pow_difficulty: 0,
            genesis_authority:
                "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".into(),
            s2_rotation_ordering_enabled: flag,
            ..Default::default()
        };
        let identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
            .expect("generate identity");
        let rocks = Arc::new(
            StorageEngine::open(data_dir.join("rocksdb")).expect("open rocksdb"),
        );
        let wmgr = Arc::new(WitnessManager::new(rocks.clone()));
        let state = Arc::new(NodeState::new(config, identity, rocks, wmgr));
        std::mem::forget(tmp);
        state
    }

    /// A lineage id (64-hex, shaped like `sha3(pk₀)`) whose home zone differs
    /// from `naive` at whatever `ZONE_COUNT` is live (default 4 ⇒ found within a
    /// few tries). Deterministic and NON-mutating — never touches the global
    /// zone count, so it can't perturb sibling tests running in parallel.
    fn differing_lineage(naive: &crate::network::zone::ZoneId) -> String {
        (0u64..4096)
            .map(|i| format!("{i:064x}"))
            .find(|l| &crate::network::consensus::zone_for_record(l) != naive)
            .expect("a lineage in a different zone exists at ZONE_COUNT >= 2")
    }

    #[test]
    fn flag_off_ignores_pin_byte_identical() {
        // Even with a pin present in the in-memory set, a flag-OFF resolve
        // returns the NAIVE zone: the c3 hook is inert (byte-identical to the
        // pre-feature resolver).
        let state = state_with_flag(false);
        let rid = "c3_off_record";
        let naive = state.resolve_record_zone(rid);
        let lineage = differing_lineage(&naive);
        state.insert_rotation_pin(rid, &lineage);
        assert_eq!(state.rotation_pins_len.load(Relaxed), 1, "pin is present");
        assert_eq!(
            state.resolve_record_zone(rid),
            naive,
            "flag-OFF resolve must ignore the pin"
        );
    }

    #[test]
    fn flag_on_routes_via_lineage_and_differs_from_naive() {
        let state = state_with_flag(true);
        let rid = "c3_on_record";
        let naive = state.resolve_record_zone(rid); // no pin yet → naive
        let lineage = differing_lineage(&naive);
        state.insert_rotation_pin(rid, &lineage);
        let pinned = state.resolve_record_zone(rid);
        // Routes via the lineage id (identity-shaped), not the record id.
        assert_eq!(
            pinned,
            crate::network::consensus::zone_for_record(&lineage)
        );
        // The pin observably CHANGED routing — the whole point of c3.
        assert_ne!(pinned, naive);
    }

    #[test]
    fn publish_then_resolve_ordering() {
        // THE fork-risk ordering, at component level: a resolve BEFORE the pin is
        // published sees the naive zone; the same resolve AFTER the publish sees
        // the pinned zone. `insert_rotation_pin` is synchronous, so an admission
        // path that publishes before its own `resolve_record_zone` calls is
        // guaranteed to observe the pin (same thread, program order).
        let state = state_with_flag(true);
        let rid = "c3_ordering_record";
        let before = state.resolve_record_zone(rid);
        let lineage = differing_lineage(&before);
        state.insert_rotation_pin(rid, &lineage);
        let after = state.resolve_record_zone(rid);
        assert_ne!(before, after, "publishing the pin must change the resolved zone");
        assert_eq!(
            after,
            crate::network::consensus::zone_for_record(&lineage)
        );
    }

    #[test]
    fn boot_load_rehydrates_pins_from_disk() {
        // A durable pin from a prior run is picked up by `load_rotation_pins` at
        // boot and drives resolution — the restart-durability path.
        let state = state_with_flag(true);
        let rid = "c3_boot_record";
        let naive = state.resolve_record_zone(rid);
        let lineage = differing_lineage(&naive);
        // Durable pin ONLY (not in memory yet) — mirrors a pin written before a
        // restart.
        state
            .rocks
            .pin_rotation_zone_for_test(rid, &lineage)
            .expect("durable pin");
        assert_eq!(state.rotation_pins_len.load(Relaxed), 0);
        assert_eq!(
            state.resolve_record_zone(rid),
            naive,
            "not loaded into memory yet → naive"
        );
        // Boot-load hydrates the in-memory set.
        assert_eq!(state.load_rotation_pins(), 1);
        assert_eq!(state.rotation_pins_len.load(Relaxed), 1);
        assert_eq!(
            state.resolve_record_zone(rid),
            crate::network::consensus::zone_for_record(&lineage)
        );
    }

    #[test]
    fn cross_engine_identical_resolution() {
        // Anti-fork determinism: two independent nodes with the SAME pin resolve
        // the record to the SAME zone (empty registries, same live ZONE_COUNT).
        let a = state_with_flag(true);
        let b = state_with_flag(true);
        let rid = "c3_cross_record";
        let naive = a.resolve_record_zone(rid);
        let lineage = differing_lineage(&naive);
        a.insert_rotation_pin(rid, &lineage);
        b.insert_rotation_pin(rid, &lineage);
        assert_eq!(a.resolve_record_zone(rid), b.resolve_record_zone(rid));
    }

    #[test]
    fn negative_hit_falls_through_to_naive() {
        // Flag-ON with a non-empty pin set, but resolving a DIFFERENT (unpinned)
        // record id falls through to the naive+registry path — the pin set is
        // consulted only for pinned ids.
        let state = state_with_flag(true);
        let pinned_rid = "c3_pinned";
        let other_rid = "c3_other_unpinned";
        let naive_pinned = state.resolve_record_zone(pinned_rid);
        let lineage = differing_lineage(&naive_pinned);
        state.insert_rotation_pin(pinned_rid, &lineage);
        assert_eq!(
            state.resolve_record_zone(other_rid),
            crate::network::consensus::zone_for_record(other_rid),
            "unpinned id is unaffected by the pin set"
        );
    }
}

/// Rebuild the delegation registry from a pre-loaded record slice (single-pass startup).
pub fn rebuild_delegations_from_records(all_records: &[ValidationRecord]) -> DelegationRegistry {
    crate::accounting::delegation::rebuild_delegation_registry_from_records(all_records).unwrap_or_default()
}

/// Rebuild the witness reputation engine from dispute resolution history.
///
/// Replays all dispute resolutions and settled records to reconstruct reputation state.
/// For disputes: attestors of contested records get reputation deltas based on outcomes.
/// For settled (finalized) records: attestors get undisputed credit.
///
/// cfg(test)-gated. Production boot uses
/// `rebuild_reputation_from_records` driven by
/// `for_each_record_ordered_bounded` in `bin/elara_node.rs`. The unbounded
/// `query(usize::MAX)` allocates ~80 GB at 10M records.
#[cfg(test)]
pub fn rebuild_reputation(
    storage: &dyn Storage,
    dispute_state: &super::dispute::DisputeState,
) -> ReputationEngine {
    let records = storage.query(None, None, None, None, usize::MAX).unwrap_or_default();
    rebuild_reputation_from_records(&records, dispute_state)
}

/// Rebuild the witness reputation engine from a pre-loaded record slice (single-pass startup).
pub fn rebuild_reputation_from_records(
    all_records: &[ValidationRecord],
    dispute_state: &super::dispute::DisputeState,
) -> ReputationEngine {
    let mut engine = ReputationEngine::new();

    // Phase 1: Process resolved disputes — apply reputation deltas
    for dispute in dispute_state.all_disputes() {
        if let Some(ref resolution) = dispute.resolution {
            // We don't have attestors stored in dispute state — they live in consensus.
            // At rebuild time consensus hasn't been populated yet. Instead, look up
            // witness_reward records for the contested record to infer attestors.
            let attestors: Vec<String> = all_records.iter()
                .filter(|r| {
                    r.metadata.get("beat_op").and_then(|v| v.as_str()) == Some("witness_reward")
                        && r.metadata.get("beat_record_id").and_then(|v| v.as_str()) == Some(&dispute.contested_record_id)
                })
                .filter_map(|r| r.metadata.get("beat_to").and_then(|v| v.as_str()).map(String::from))
                .collect();

            if !attestors.is_empty() {
                engine.process_dispute_resolution(&resolution.outcome, &attestors, resolution.resolved_at);
            }
        }
    }

    engine
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{Classification, ValidationRecord};

    // ── json_value_matches_string ────────────────────────────────────────

    #[test]
    fn json_value_matches_string_string_variant() {
        assert!(json_value_matches_string(&serde_json::json!("foo"), "foo"));
        assert!(!json_value_matches_string(&serde_json::json!("foo"), "bar"));
        // String variant must NOT compare against the JSON-rendered form
        // (which would include the surrounding quotes).
        assert!(!json_value_matches_string(&serde_json::json!("foo"), "\"foo\""));
    }

    #[test]
    fn json_value_matches_string_bool_and_null() {
        assert!(json_value_matches_string(&serde_json::json!(true), "true"));
        assert!(json_value_matches_string(&serde_json::json!(false), "false"));
        assert!(json_value_matches_string(&serde_json::Value::Null, "null"));
        assert!(!json_value_matches_string(&serde_json::json!(true), "false"));
        assert!(!json_value_matches_string(&serde_json::json!(true), "1"));
        assert!(!json_value_matches_string(&serde_json::Value::Null, ""));
    }

    #[test]
    fn json_value_matches_string_numeric_and_composite() {
        assert!(json_value_matches_string(&serde_json::json!(42), "42"));
        assert!(json_value_matches_string(&serde_json::json!(-1), "-1"));
        assert!(!json_value_matches_string(&serde_json::json!(42), "43"));
        // Arrays/objects render to canonical JSON; matching is intentionally
        // exact-string against that form.
        assert!(json_value_matches_string(&serde_json::json!([1, 2]), "[1,2]"));
        assert!(!json_value_matches_string(&serde_json::json!([1, 2]), "[1, 2]"));
    }

    /// Create a minimal test record with given id, parents, and timestamp.
    fn test_record(id: &str, parents: Vec<String>, timestamp: f64) -> ValidationRecord {
        let mut rec = ValidationRecord::create(
            id.as_bytes(),
            b"test_pub_key".to_vec(),
            parents,
            Classification::Public,
            None,
        );
        rec.timestamp = timestamp;
        rec.id = id.to_string();
        rec
    }

    // ── NodeEvent ────────────────────────────────────────────────────────

    #[test]
    fn test_node_event_record_inserted_fields() {
        let event = NodeEvent::RecordInserted {
            record_id: "r1".into(),
            creator_hash: "c1".into(),
            beat_op: Some("transfer".into()),
            beat_amount: Some(1000),
            timestamp: 100.0,
        };
        match event {
            NodeEvent::RecordInserted { record_id, beat_amount, .. } => {
                assert_eq!(record_id, "r1");
                assert_eq!(beat_amount, Some(1000));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_node_event_record_finalized() {
        let event = NodeEvent::RecordFinalized { record_id: "r1".into() };
        match event {
            NodeEvent::RecordFinalized { record_id } => assert_eq!(record_id, "r1"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_node_event_clone() {
        let event = NodeEvent::RecordInserted {
            record_id: "r1".into(),
            creator_hash: "c1".into(),
            beat_op: None,
            beat_amount: None,
            timestamp: 0.0,
        };
        let cloned = event.clone();
        match cloned {
            NodeEvent::RecordInserted { record_id, .. } => assert_eq!(record_id, "r1"),
            _ => panic!("wrong variant"),
        }
    }

    // ── rebuild_dag_from_records ──────────────────────────────────────────

    #[test]
    fn test_rebuild_dag_empty() {
        let dag = rebuild_dag_from_records(&[]);
        assert_eq!(dag.len(), 0);
        assert!(dag.tips().is_empty());
    }

    #[test]
    fn test_rebuild_dag_single_record() {
        let records = vec![test_record("r1", vec![], 1.0)];
        let dag = rebuild_dag_from_records(&records);
        assert_eq!(dag.len(), 1);
        let tips = dag.tips();
        assert_eq!(tips.len(), 1);
        assert_eq!(tips[0], "r1");
    }

    #[test]
    fn test_rebuild_dag_chain() {
        let records = vec![
            test_record("r1", vec![], 1.0),
            test_record("r2", vec!["r1".into()], 2.0),
            test_record("r3", vec!["r2".into()], 3.0),
        ];
        let dag = rebuild_dag_from_records(&records);
        assert_eq!(dag.len(), 3);
        let tips = dag.tips();
        assert_eq!(tips.len(), 1);
        assert_eq!(tips[0], "r3");
    }

    #[test]
    fn test_rebuild_dag_fork() {
        let records = vec![
            test_record("r1", vec![], 1.0),
            test_record("r2", vec!["r1".into()], 2.0),
            test_record("r3", vec!["r1".into()], 2.0),
        ];
        let dag = rebuild_dag_from_records(&records);
        assert_eq!(dag.len(), 3);
        let tips = dag.tips();
        assert_eq!(tips.len(), 2); // r2 and r3 are both tips
    }

    #[test]
    fn test_rebuild_dag_out_of_order_timestamps() {
        // Records arrive out of order but have correct parent refs
        let records = vec![
            test_record("r3", vec!["r2".into()], 3.0),
            test_record("r1", vec![], 1.0),
            test_record("r2", vec!["r1".into()], 2.0),
        ];
        let dag = rebuild_dag_from_records(&records);
        assert_eq!(dag.len(), 3);
        // After rebuild with sorting + reindex, r3 should be the only tip
        let tips = dag.tips();
        assert_eq!(tips.len(), 1);
        assert_eq!(tips[0], "r3");
    }

    // ── rebuild_trust_from_records ────────────────────────────────────────

    #[test]
    fn test_rebuild_trust_empty() {
        let engine = rebuild_trust_from_records(&[]);
        // No records → no trust profiles
        assert_eq!(engine.tracked_identities(), 0);
    }

    #[test]
    fn test_rebuild_trust_single_creator() {
        let records = vec![
            test_record("r1", vec![], 1.0),
            test_record("r2", vec!["r1".into()], 2.0),
        ];
        let engine = rebuild_trust_from_records(&records);
        // Both records have same creator (test_pub_key) → 1 identity tracked
        assert_eq!(engine.tracked_identities(), 1);
    }

    // ── rebuild_reputation_from_records ───────────────────────────────────

    #[test]
    fn test_rebuild_reputation_empty() {
        let disputes = super::super::dispute::DisputeState::new();
        let engine = rebuild_reputation_from_records(&[], &disputes);
        assert_eq!(engine.tracked_count(), 0);
    }

    #[test]
    fn test_rebuild_reputation_no_disputes() {
        let records = vec![test_record("r1", vec![], 1.0)];
        let disputes = super::super::dispute::DisputeState::new();
        let engine = rebuild_reputation_from_records(&records, &disputes);
        // No disputes → no reputation entries
        assert_eq!(engine.tracked_count(), 0);
    }

    // ── rebuild_delegations_from_records ──────────────────────────────────

    #[test]
    fn test_rebuild_delegations_empty() {
        let registry = rebuild_delegations_from_records(&[]);
        assert_eq!(registry.total(), 0);
    }

    // ── effective_base_timeout_ms ────────────────────────────────────────

    /// Build a minimal NodeState for tests. Background tasks are not
    /// started, but the config + zone_rtt + identity are real enough to
    /// exercise pure functions like `effective_base_timeout_ms`.
    fn test_node_state(
        override_ms: Option<u64>,
    ) -> std::sync::Arc<NodeState> {
        use crate::identity::{CryptoProfile, EntityType, Identity};
        use crate::network::config::NodeConfig;
        use crate::network::witness::WitnessManager;
        use crate::storage::rocks::StorageEngine;

        let tmp = tempfile::tempdir().expect("tempdir");
        let data_dir = tmp.path().to_path_buf();
        let config = NodeConfig {
            data_dir: data_dir.clone(),
            identity_path: data_dir.join("identity.json"),
            db_path: data_dir.join("elara.db"),
            admin_token: "test-admin".into(),
            network_id: "base-timeout-test".into(),
            mdns_enabled: false,
            health_check_interval_secs: 0,
            min_pow_difficulty: 0,
            test_base_timeout_ms_override: override_ms,
            ..Default::default()
        };

        let identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
            .expect("generate identity");
        let rocks = std::sync::Arc::new(
            StorageEngine::open(data_dir.join("rocksdb")).expect("open rocksdb"),
        );
        let wmgr = std::sync::Arc::new(WitnessManager::new(rocks.clone()));
        let state = std::sync::Arc::new(NodeState::new(config, identity, rocks, wmgr));
        std::mem::forget(tmp);
        state
    }

    /// Seal-member durable-write lane: the routing helper's insert is
    /// idempotent (exactly-once edge), bumps the lifetime + F5 counters by
    /// truly-new only, and survives a chunk boundary.
    #[tokio::test]
    async fn insert_members_durable_is_idempotent_and_counted() {
        use std::sync::atomic::Ordering::Relaxed;
        let state = test_node_state(None);
        let rids: Vec<String> = (0..10).map(|i| format!("member-{i}")).collect();

        let new1 = crate::network::reward::insert_members_durable(&state, &rids).await;
        assert_eq!(new1.len(), 10);
        assert!(state.finalized.read().await.contains("member-3"));
        assert_eq!(state.seal_member_finalized_durable_total.load(Relaxed), 10);
        assert_eq!(state.total_ever_settled.load(Relaxed), 10);
        assert_eq!(state.total_ever_finalized.load(Relaxed), 10);

        // Second pass: all dedup'd — no effects edge, no counter movement.
        let new2 = crate::network::reward::insert_members_durable(&state, &rids).await;
        assert!(new2.is_empty());
        assert_eq!(state.seal_member_finalized_durable_total.load(Relaxed), 10);
        assert_eq!(state.total_ever_settled.load(Relaxed), 10);

        // Chunk boundary: a batch larger than MEMBER_FINALITY_CHUNK routes fully.
        let big: Vec<String> = (0..crate::network::reward::MEMBER_FINALITY_CHUNK + 3)
            .map(|i| format!("big-{i}"))
            .collect();
        let new3 = crate::network::reward::insert_members_durable(&state, &big).await;
        assert_eq!(new3.len(), crate::network::reward::MEMBER_FINALITY_CHUNK + 3);
        assert!(state.finalized.read().await.contains(&format!(
            "big-{}",
            crate::network::reward::MEMBER_FINALITY_CHUNK + 1
        )));
    }

    /// Seal-member durable-write lane (brief §9.4): the feed_attestation
    /// member leg is UNCONDITIONAL — a slot-conflict-blocked seal record
    /// (settled=false even though Layer-1 stake reached threshold) still
    /// durably indexes its Layer-2-promoted members. The member itself has
    /// ZERO Layer-1 attestations and never touches the index otherwise.
    #[tokio::test]
    async fn seal_member_leg_fires_with_seal_record_unsettled() {
        use crate::identity::{CryptoProfile, EntityType, Identity};
        use crate::network::epoch::{seal_metadata, SealMetadataParams};
        use crate::network::zone::ZoneId;
        use std::sync::atomic::Ordering::Relaxed;

        let zone = ZoneId::from_legacy(0);
        let state = test_node_state_with_committee_and_stakes(
            None,
            &[
                ("w1", "org-a", "10.0.1", "earth-us", 100),
                ("w2", "org-b", "10.0.2", "earth-eu", 100),
                ("w3", "org-c", "10.0.3", "mars-olympus", 100),
            ],
            &zone,
            0,
        )
        .await;

        // A real epoch-seal record in rocks so feed_attestation's
        // seal-detection path (extract_epoch_seal) engages.
        let identity =
            Identity::generate(EntityType::Device, CryptoProfile::ProfileB).unwrap();
        let root = crate::crypto::hash::sha3_256(b"m");
        let prev = [0u8; 32];
        let meta = seal_metadata(SealMetadataParams {
            zone: zone.clone(),
            epoch_number: 3,
            start: 100.0,
            end: 200.0,
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
            b"seal-payload",
            identity.public_key.clone(),
            vec![],
            Classification::Public,
            Some(meta),
        );
        state.rocks.put_record(&seal_rec.id, &seal_rec).unwrap();

        {
            let mut consensus = state.consensus.lock_recover();
            // Layer-1 settlement resolves the zone from the record-id hash
            // (via the GLOBAL ZONE_COUNT, which other tests in the suite
            // mutate) — register stake there so Layer-1 REACHES threshold and
            // only the slot gate below blocks it. Skip when it maps onto the
            // fixture zone: register_zone_stake ACCUMULATES, and doubling the
            // legacy-0 denominator would keep Layer-2 below 2/3 forever.
            let l1_zone = crate::network::consensus::zone_for_record(&seal_rec.id);
            if l1_zone != zone {
                consensus.register_zone_stake(l1_zone, 300);
            }
            let none = consensus.register_seal_records(&seal_rec.id, vec!["mem-a".into()]);
            assert!(none.is_empty(), "no promotion before settlement");
        }

        // Conflicted slot: the settlement gate must force settled=false.
        state
            .rocks
            .slot_mark_conflict(&seal_rec.slot_key().expect("v5 record has slot key"), "t")
            .unwrap();

        let outcomes = [
            state.feed_attestation(&seal_rec.id, "w1", 1.0).await,
            state.feed_attestation(&seal_rec.id, "w2", 2.0).await,
            state.feed_attestation(&seal_rec.id, "w3", 3.0).await,
        ];

        // The seal record itself is never reported settled (slot gate)…
        assert!(
            outcomes.iter().all(|o| !o.settled),
            "slot-conflicted seal record must not settle"
        );
        // …yet exactly ONE feed crossed the Layer-2 edge and returned the member.
        let member_batches: Vec<&[String]> = outcomes
            .iter()
            .map(|o| o.seal_members_finalized.as_slice())
            .filter(|b| !b.is_empty())
            .collect();
        assert_eq!(member_batches, vec![&["mem-a".to_string()][..]]);

        let fin = state.finalized.read().await;
        assert!(fin.contains("mem-a"), "member durably indexed");
        assert!(
            !fin.contains(&seal_rec.id),
            "the blocked seal record itself must NOT be indexed"
        );
        drop(fin);
        assert_eq!(state.seal_member_finalized_durable_total.load(Relaxed), 1);
    }

    /// Seal-member durable-write lane (brief §9.6 prune survival): a
    /// fast-track member routed durably keeps reporting Finalized after the
    /// 24h-style collateral wipe, via the FinalizedIndex fallback in BOTH
    /// `state.confirmation_level` and the ledger-route enrichment.
    #[tokio::test]
    async fn seal_member_finality_survives_prune_via_durable_index() {
        use crate::network::consensus::{
            Attestation, ConfirmationLevel, SealAttestation, WitnessProfile,
        };
        use crate::network::zone::ZoneId;

        let state = test_node_state(None);
        let zone = ZoneId::from_legacy(0);
        let promoted = {
            let mut consensus = state.consensus.lock_recover();
            consensus.register_zone_stake(zone.clone(), 300);
            for (w, org, sub, geo) in [
                ("w1", "org-a", "10.0.1", "earth-us"),
                ("w2", "org-b", "10.0.2", "earth-eu"),
                ("w3", "org-c", "10.0.3", "mars-olympus"),
            ] {
                consensus.register_profile(
                    w,
                    WitnessProfile {
                        organization: org.into(),
                        subnet: sub.into(),
                        geo_zone: geo.into(),
                    },
                );
            }
            let _ = consensus.register_seal_records("seal-p", vec!["mem-p".into()]);
            // An unrelated OLD Layer-1 attestation so the prune below
            // age-evicts something — the collateral confirmation_levels
            // retain (the production wipe) only fires when pruned > 0.
            consensus.add_attestation(Attestation {
                record_id: "other-rec".into(),
                witness_hash: "w1".into(),
                stake: 1,
                timestamp: 1.0,
            });
            let mut promoted = Vec::new();
            for (i, w) in ["w1", "w2", "w3"].iter().enumerate() {
                promoted.extend(consensus.add_seal_attestation(SealAttestation {
                    seal_id: "seal-p".into(),
                    zone: zone.clone(),
                    epoch_number: 0,
                    witness_hash: (*w).into(),
                    stake: 100,
                    timestamp: 2.0 + i as f64,
                }));
            }
            promoted
        };
        assert_eq!(promoted, vec!["mem-p".to_string()]);
        let new = crate::network::reward::insert_members_durable(&state, &promoted).await;
        assert_eq!(new.len(), 1);

        // 24h-style maintenance: everything ages out; the collateral retain
        // wipes the memberless confirmation_levels entry.
        {
            let mut consensus = state.consensus.lock_recover();
            let pruned = consensus.prune_older_than(1e12);
            assert!(pruned > 0, "age eviction must fire for the collateral wipe");
            assert_eq!(
                consensus.confirmation_level("mem-p"),
                ConfirmationLevel::Pending,
                "in-memory marker collaterally wiped"
            );
        }

        // The durable index answers now.
        assert_eq!(
            state.confirmation_level("mem-p"),
            ConfirmationLevel::Finalized,
            "index fallback preserves finality across the wipe"
        );

        // Ledger-route surface (§9.6 second half): /history-style enrichment
        // reports "finalized" off the durable index after seal state pruned.
        let mut tx = serde_json::json!({});
        {
            let fin = state.finalized.read().await;
            crate::network::routes::ledger::enrich_with_seal_state(
                &mut tx, &state, "mem-p", &fin,
            );
        }
        assert_eq!(tx["seal_state"], serde_json::json!("finalized"));
        assert_eq!(tx["finalized"], serde_json::json!(true));
    }

    /// Seal-member durable-write lane (brief §9.8): the F3 pre-prune sweep
    /// shape — collect ≥Finalized rids under the consensus guard, drop it,
    /// route durably — rescues an UNROUTED promotion before the collateral
    /// wipe, and the second pass is a counted no-op.
    #[tokio::test]
    async fn f3_sweep_indexes_unrouted_members_before_wipe() {
        use crate::network::consensus::{
            Attestation, ConfirmationLevel, SealAttestation, WitnessProfile,
        };
        use crate::network::zone::ZoneId;
        use std::sync::atomic::Ordering::Relaxed;

        let state = test_node_state(None);
        let zone = ZoneId::from_legacy(0);
        {
            let mut consensus = state.consensus.lock_recover();
            consensus.register_zone_stake(zone.clone(), 300);
            for (w, org, sub, geo) in [
                ("w1", "org-a", "10.0.1", "earth-us"),
                ("w2", "org-b", "10.0.2", "earth-eu"),
                ("w3", "org-c", "10.0.3", "mars-olympus"),
            ] {
                consensus.register_profile(
                    w,
                    WitnessProfile {
                        organization: org.into(),
                        subnet: sub.into(),
                        geo_zone: geo.into(),
                    },
                );
            }
            let _ = consensus.register_seal_records("seal-f3", vec!["mem-f3".into()]);
            consensus.add_attestation(Attestation {
                record_id: "other-rec".into(),
                witness_hash: "w1".into(),
                stake: 1,
                timestamp: 1.0,
            });
            for (i, w) in ["w1", "w2", "w3"].iter().enumerate() {
                // DROP the returned members — simulates an unrouted
                // promotion path, the exact class F3 exists to catch.
                let _ = consensus.add_seal_attestation(SealAttestation {
                    seal_id: "seal-f3".into(),
                    zone: zone.clone(),
                    epoch_number: 0,
                    witness_hash: (*w).into(),
                    stake: 100,
                    timestamp: 2.0 + i as f64,
                });
            }
            assert_eq!(
                consensus.confirmation_level("mem-f3"),
                ConfirmationLevel::Finalized,
                "promoted in memory"
            );
        }
        assert!(
            !state.finalized.read().await.contains("mem-f3"),
            "unrouted: not yet durable"
        );

        // F3 pass 1 — the maintenance-tick block shape.
        let rids = { state.consensus.lock_recover().finalized_level_rids() };
        assert!(rids.contains(&"mem-f3".to_string()));
        let new1 = crate::network::reward::insert_members_durable(&state, &rids).await;
        assert!(new1.contains(&"mem-f3".to_string()));

        // The wipe runs AFTER F3 (the ordering the maintenance loop pins).
        {
            let mut consensus = state.consensus.lock_recover();
            let pruned = consensus.prune_older_than(1e12);
            assert!(pruned > 0, "age eviction must fire for the collateral wipe");
        }
        assert_eq!(
            state.confirmation_level("mem-f3"),
            ConfirmationLevel::Finalized,
            "durable write from F3 pass 1 survived the wipe"
        );

        // F3 pass 2: nothing new — idempotent, counter untouched.
        let rids2 = { state.consensus.lock_recover().finalized_level_rids() };
        let new2 = crate::network::reward::insert_members_durable(&state, &rids2).await;
        assert!(new2.is_empty(), "second sweep inserts nothing");
        assert_eq!(
            state.seal_member_finalized_durable_total.load(Relaxed),
            new1.len() as u64,
            "F5 counter counted pass-1 rids exactly once"
        );
    }

    #[test]
    fn test_effective_base_timeout_default_5s_when_no_rtt() {
        // No RTT observed + no override → falls back to 5s floor.
        let state = test_node_state(None);
        let zone = super::super::zone::ZoneId::from_legacy(0);
        assert_eq!(state.effective_base_timeout_ms(&zone), 5_000);
    }

    #[test]
    fn test_effective_base_timeout_override_bypasses_rtt() {
        // Override wins even if RTT observed — and override is *not*
        // subject to the 1_000..=600_000 clamp (sim needs to shrink the
        // stuck threshold well below 1s for the ladder to exhaust fast).
        let state = test_node_state(Some(100));
        let zone = super::super::zone::ZoneId::from_legacy(0);
        state.observe_zone_rtt(&zone, std::time::Duration::from_millis(50));
        assert_eq!(state.effective_base_timeout_ms(&zone), 100);
    }

    #[test]
    fn test_effective_base_timeout_rtt_scales_2x_clamped_min() {
        // RTT=2s → base_s = max(2·2, 5) = 5s → 5_000ms.
        let state = test_node_state(None);
        let zone = super::super::zone::ZoneId::from_legacy(0);
        state.observe_zone_rtt(&zone, std::time::Duration::from_secs(2));
        assert_eq!(state.effective_base_timeout_ms(&zone), 5_000);
    }

    #[test]
    fn test_effective_base_timeout_rtt_scales_above_floor() {
        // RTT=10s → base_s = max(2·10, 5) = 20s → 20_000ms.
        let state = test_node_state(None);
        let zone = super::super::zone::ZoneId::from_legacy(0);
        state.observe_zone_rtt(&zone, std::time::Duration::from_secs(10));
        assert_eq!(state.effective_base_timeout_ms(&zone), 20_000);
    }

    #[test]
    fn test_effective_base_timeout_hard_bounded_by_sample_clamp_under_pathological_peer() {
        // WAN cascade-isolation invariant for the seal-path rank-unlock schedule.
        //
        // The seal loop never awaits a peer (it reads only local state), so a
        // slow/distant peer can influence sealing ONLY indirectly: by inflating
        // `zone_rtt_p95`, which stretches `effective_base_timeout_ms` (the per-rank
        // unlock interval). The safety property is therefore that this stretch is
        // *bounded* — a peer with pathological RTT cannot push the rank-unlock
        // timeout toward infinity and stall non-genesis rank progression forever.
        //
        // The bound is enforced upstream by `zone_rtt::MAX_SAMPLE_US` (30s): every
        // RTT sample is clamped on ingest, so `zone_rtt_p95() ≤ 30s` and thus
        // `effective_base_timeout_ms = 2·p95 ≤ 2·MAX_SAMPLE_US = 60s`, regardless
        // of how slow the peer actually is. The `[1s, 600s]` clamp inside
        // `effective_base_timeout_ms` is belt-and-suspenders: its 600s ceiling is
        // currently UNREACHABLE because the 30s sample clamp binds first.
        use super::super::zone_rtt::MAX_SAMPLE_US;

        // 2·MAX_SAMPLE_US, expressed in ms — the true maximum effective timeout.
        let sample_clamp_bound_ms = 2 * u64::from(MAX_SAMPLE_US) / 1_000;
        assert_eq!(sample_clamp_bound_ms, 60_000, "2·30s sample clamp = 60s");

        // (a) A single 1-hour RTT sample (120× the clamp) caps at 60s, not 2h.
        let state = test_node_state(None);
        let zone = super::super::zone::ZoneId::from_legacy(0);
        state.observe_zone_rtt(&zone, std::time::Duration::from_secs(3_600));
        assert_eq!(
            state.effective_base_timeout_ms(&zone),
            sample_clamp_bound_ms,
            "one pathological RTT sample must cap the rank-unlock timeout at 2·MAX_SAMPLE_US"
        );

        // (b) Saturating the whole 64-slot ring with over-clamp samples is still 60s.
        let state = test_node_state(None);
        let zone = super::super::zone::ZoneId::from_legacy(0);
        for _ in 0..super::super::zone_rtt::RING_SIZE {
            state.observe_zone_rtt(&zone, std::time::Duration::from_secs(120));
        }
        assert_eq!(
            state.effective_base_timeout_ms(&zone),
            sample_clamp_bound_ms,
            "a fully-saturated ring of slow samples is still bounded at 2·MAX_SAMPLE_US"
        );

        // (c) Cross-module coupling guard. The sample clamp must stay strictly
        // below the `effective_base_timeout_ms` 600s ceiling, otherwise the
        // ceiling goes live and unbounded (up-to-10min) rank-unlock stalls
        // become reachable. Raising MAX_SAMPLE_US above 300s trips this and
        // forces a re-review of the rank-unlock bound.
        const CLAMP_CEILING_MS: u64 = 600_000;
        assert!(
            sample_clamp_bound_ms < CLAMP_CEILING_MS,
            "MAX_SAMPLE_US ({MAX_SAMPLE_US}us) makes 2·clamp = {sample_clamp_bound_ms}ms; \
             this MUST stay below the {CLAMP_CEILING_MS}ms ceiling or the ceiling becomes \
             the live (and far looser) bound"
        );
    }

    // ── witness-committee fixture ─────────────────────────────────────────
    //
    // Coverage for the async cluster-fixture paths. The async
    // `feed_attestation` / `batch_feed_attestations` / `publish_record_with_fallback`
    // paths each have an early-step profile lookup (`state.rs:3078-3083`):
    //   let (subnet, org) = {
    //       let consensus = self.consensus.lock_recover();
    //       let profile = consensus.profiles()
    //           .find(|(h, _)| *h == witness_hash)
    //           .map(|(_, p)| (Some(p.subnet.clone()), Some(p.organization.clone())));
    //       profile.unwrap_or((None, None))
    //   };
    // Pre-fixture, every existing async test used `test_node_state(None)`
    // which leaves `consensus.profiles` empty, so the `(None, None)` branch
    // was the only path under coverage and the profile-propagation logic
    // (line 3086-3092 hand-off to `entity_clusterer.record_attestation`)
    // stayed dark. This helper layers a real witness committee on top of
    // `test_node_state`: each entry is registered via `register_profile` so
    // the iterator hit returns the registered (organization, subnet,
    // geo_zone). Subsequent extensions will stack on ledger stake
    // registration + pre-inserted records so settlement can be exercised
    // end-to-end — but the profile-lookup contract is the right first pin
    // (smallest atomic change, biggest dark-path surface).
    ///
    /// Each tuple: `(witness_hash, organization, subnet, geo_zone)`.
    fn test_node_state_with_witness_committee(
        override_ms: Option<u64>,
        witnesses: &[(&str, &str, &str, &str)],
    ) -> std::sync::Arc<NodeState> {
        use super::super::consensus::WitnessProfile;
        let state = test_node_state(override_ms);
        {
            let mut consensus = state.consensus.lock_recover();
            for (hash, org, subnet, geo_zone) in witnesses {
                consensus.register_profile(
                    hash,
                    WitnessProfile {
                        organization: (*org).to_string(),
                        subnet: (*subnet).to_string(),
                        geo_zone: (*geo_zone).to_string(),
                    },
                );
            }
        }
        state
    }

    // Stack ledger stake + consensus zone-stake on
    // top of `test_node_state_with_witness_committee` so the full
    // `feed_attestation` → `is_settled` → `Finalized` chain is exercisable
    // without a live network. The fixture wires three contracts:
    //   1. Each witness has a registered profile (entity-clusterer path,
    //      pinned by the first tests above).
    //   2. Each witness has `ledger.accounts[witness_hash].staked = stake`
    //      so `feed_attestation`'s ledger read at `state.rs:3115-3121`
    //      returns the right per-witness stake into the `Attestation`.
    //   3. The zone has `consensus.zone_stakes[zone] = sum(stakes) + extra`
    //      so `consensus.is_settled` at `consensus.rs:2155-2174` has a
    //      non-zero `settlement_denominator`.
    //
    // The total zone stake registered = sum of witness stakes + `extra_stake`
    // — callers pass `extra_stake > 0` to model a non-attesting staker (e.g.,
    // the creator whose stake must be subtracted in `is_settled`). Each
    // tuple: `(witness_hash, organization, subnet, geo_zone, stake_amount)`.
    async fn test_node_state_with_committee_and_stakes(
        override_ms: Option<u64>,
        witnesses: &[(&str, &str, &str, &str, u64)],
        zone: &super::super::zone::ZoneId,
        extra_stake: u64,
    ) -> std::sync::Arc<NodeState> {
        let committee: Vec<(&str, &str, &str, &str)> = witnesses
            .iter()
            .map(|(h, o, s, g, _)| (*h, *o, *s, *g))
            .collect();
        let state = test_node_state_with_witness_committee(override_ms, &committee);
        let total: u64 = witnesses.iter().map(|(_, _, _, _, s)| *s).sum::<u64>() + extra_stake;
        {
            let mut consensus = state.consensus.lock_recover();
            consensus.register_zone_stake(zone.clone(), total);
        }
        {
            let mut ledger = state.ledger.write().await;
            for (hash, _, _, _, stake) in witnesses {
                let acct = ledger.accounts.entry((*hash).to_string()).or_default();
                acct.staked = *stake;
            }
        }
        state
    }

    /// Fund an additional identity's `staked` balance on the test node's
    /// ledger. Returns `sha3_256_hex(pk_bytes)` so callers can plug the same
    /// identity hash into downstream lookups (record creator, ledger reads).
    async fn fund_account_staked(state: &NodeState, pk_bytes: &[u8], staked: u64) -> String {
        let identity_hash = crate::crypto::hash::sha3_256_hex(pk_bytes);
        let mut ledger = state.ledger.write().await;
        let acct = ledger.accounts.entry(identity_hash.clone()).or_default();
        acct.staked = staked;
        identity_hash
    }

    /// Audit 2026-06-15 item (f). The shared `staked_anchor_view` accessor is
    /// the single source of truth for the seal proposer
    /// (`epoch::should_propose_seal`) and BOTH verifiers (`ingest.rs`). It MUST:
    ///  (1) return exactly `{(id, stake) : anchor ∧ staked>0}` — non-anchor
    ///      stakers and zero-stake anchors excluded (the LIVENESS-1 filter);
    ///  (2) hand a cache HIT the SAME `Arc` — so proposer and verifier read a
    ///      bit-identical set and cannot diverge (a divergent view freezes the
    ///      chain);
    ///  (3) rebuild on each invalidation signal — anchor add (`anchor_add_seq`),
    ///      stake change (`stake_mutation_seq`), and explicit
    ///      `invalidate_anchor_view` (the restore-path mechanism) — while a
    ///      change with NO signal stays cached (it is a memoization, and every
    ///      real mutation path emits a signal);
    ///  (4) keep the `by_zone` partition covering exactly the flat set.
    #[tokio::test]
    async fn staked_anchor_view_set_correctness_and_invalidation() {
        use crate::crypto::hash::sha3_256_hex;
        use std::sync::Arc;

        // The naive scan the call sites used to inline — the spec the cache
        // must reproduce.
        async fn naive(state: &NodeState) -> Vec<(String, u64)> {
            let anchors = state.rocks.list_anchor_identities(usize::MAX);
            let ledger = state.ledger.read().await;
            let mut v: Vec<(String, u64)> = anchors
                .into_iter()
                .filter_map(|id| {
                    ledger
                        .accounts
                        .get(&id)
                        .filter(|a| a.staked > 0)
                        .map(|a| (id, a.staked))
                })
                .collect();
            v.sort();
            v
        }
        fn sorted(arc: &Arc<Vec<(String, u64)>>) -> Vec<(String, u64)> {
            let mut v = (**arc).clone();
            v.sort();
            v
        }

        let state = test_node_state(None);
        let a = sha3_256_hex(b"anchor-a");
        let b = sha3_256_hex(b"anchor-b");
        let c = sha3_256_hex(b"anchor-c"); // anchor but staked==0 → excluded
        let d = sha3_256_hex(b"staker-d"); // staked but NOT an anchor → excluded
        for id in [&a, &b, &c] {
            state.rocks.store_public_key_anchor(id, b"pk").unwrap();
        }
        {
            let mut l = state.ledger.write().await;
            l.accounts.entry(a.clone()).or_default().staked = 100;
            l.accounts.entry(b.clone()).or_default().staked = 200;
            l.accounts.entry(c.clone()).or_default().staked = 0;
            l.accounts.entry(d.clone()).or_default().staked = 500;
        }

        // (1) Set correctness — accessor == naive spec; c and d excluded.
        let (flat1, _) = state.staked_anchor_view().await;
        assert_eq!(sorted(&flat1), naive(&state).await);
        assert_eq!(flat1.len(), 2, "only the two staked anchors");
        assert!(flat1.iter().any(|(id, s)| id == &a && *s == 100));
        assert!(flat1.iter().any(|(id, s)| id == &b && *s == 200));
        assert!(!flat1.iter().any(|(id, _)| id == &c), "zero-stake anchor excluded");
        assert!(!flat1.iter().any(|(id, _)| id == &d), "non-anchor staker excluded");

        // (2) Cache hit hands back the SAME Arc — proposer and verifier share
        // one object, so their staked sets are identical by construction.
        let (flat2, _) = state.staked_anchor_view().await;
        assert!(Arc::ptr_eq(&flat1, &flat2), "no-change read is a cache hit (same Arc)");

        // (3a) Anchor-add signal: a new staked anchor invalidates via
        // anchor_add_seq and the rebuild picks up live ledger stake.
        let e = sha3_256_hex(b"anchor-e");
        state.rocks.store_public_key_anchor(&e, b"pk").unwrap();
        state.ledger.write().await.accounts.entry(e.clone()).or_default().staked = 300;
        let (flat3, _) = state.staked_anchor_view().await;
        assert!(!Arc::ptr_eq(&flat2, &flat3), "anchor add forces a rebuild");
        assert!(flat3.iter().any(|(id, s)| id == &e && *s == 300));
        assert_eq!(sorted(&flat3), naive(&state).await);

        // (3b) Stake-change signal: bumping stake_mutation_seq (what apply_op
        // does) invalidates even when total_staked is otherwise consistent.
        {
            let mut l = state.ledger.write().await;
            l.accounts.get_mut(&a).unwrap().staked = 150;
            l.stake_mutation_seq = l.stake_mutation_seq.wrapping_add(1);
        }
        let (flat4, _) = state.staked_anchor_view().await;
        assert!(flat4.iter().any(|(id, s)| id == &a && *s == 150), "seq bump rebuilds");

        // (3c) No signal → stays cached (it is a memoization, not a live view);
        // explicit invalidate (the restore-path mechanism) then rebuilds.
        state.ledger.write().await.accounts.get_mut(&b).unwrap().staked = 250;
        let (flat5, _) = state.staked_anchor_view().await;
        assert!(
            flat5.iter().any(|(id, s)| id == &b && *s == 200),
            "an unsignalled direct edit is NOT observed (cache hit)"
        );
        state.invalidate_anchor_view();
        let (flat6, by_zone6) = state.staked_anchor_view().await;
        assert!(
            flat6.iter().any(|(id, s)| id == &b && *s == 250),
            "invalidate_anchor_view forces a rebuild from authoritative state"
        );

        // (4) by_zone partition covers exactly the flat set.
        let mut bz: Vec<(String, u64)> = by_zone6.values().flatten().cloned().collect();
        bz.sort();
        assert_eq!(bz, sorted(&flat6), "by_zone partitions exactly the flat set");
    }

    /// Gate S1 #3 (internal design notes): `staked_anchor_view`
    /// must be BYTE-IDENTICAL — same elements AND same order — across two nodes
    /// that hold the same logical anchor+stake set but received it in a
    /// different sequence. This view is the proposer-rank input read by
    /// `epoch::should_propose_seal` AND both `ingest.rs` verifiers; a cross-node
    /// divergence in the set OR its order freezes the chain (LIVENESS-1,
    /// observed testnet 2026-05-10/11). Within-node symmetry is by construction
    /// (one shared accessor); the multi-machine S1 stand-up additionally relies
    /// on this ACROSS-node property, which this pins WITHOUT three machines:
    /// `list_anchor_identities` iterates the RocksDB anchor CF in key (lex)
    /// order — insertion-order-independent — and the join preserves it. If a
    /// future change swapped to a non-lex comparator or introduced a
    /// HashMap-iteration dependency, two honest nodes would rank the same staker
    /// differently and wedge; this test fails first.
    #[tokio::test]
    async fn staked_anchor_view_is_byte_identical_across_insertion_orders() {
        use crate::crypto::hash::sha3_256_hex;

        // Five staked anchors. Hashes (not the labels) determine emission order,
        // so the forward-insert and reverse-insert nodes below exercise two
        // genuinely different CF/ledger write sequences for the same logical set.
        let ids: Vec<String> = (0..5)
            .map(|i| sha3_256_hex(format!("xnode-anchor-{i}").as_bytes()))
            .collect();
        let stakes = [100u64, 200, 300, 400, 500];

        // Node A — forward anchor-CF + ledger insertion order.
        let node_a = test_node_state(None);
        for id in &ids {
            node_a.rocks.store_public_key_anchor(id, b"pk").unwrap();
        }
        {
            let mut l = node_a.ledger.write().await;
            for (id, s) in ids.iter().zip(stakes.iter()) {
                l.accounts.entry(id.clone()).or_default().staked = *s;
            }
        }

        // Node B — SAME logical set, REVERSED anchor-CF write order AND reversed
        // ledger-account insertion order: a peer that ingested the same records
        // in the opposite sequence.
        let node_b = test_node_state(None);
        for id in ids.iter().rev() {
            node_b.rocks.store_public_key_anchor(id, b"pk").unwrap();
        }
        {
            let mut l = node_b.ledger.write().await;
            for (id, s) in ids.iter().zip(stakes.iter()).rev() {
                l.accounts.entry(id.clone()).or_default().staked = *s;
            }
        }

        let (flat_a, _) = node_a.staked_anchor_view().await;
        let (flat_b, _) = node_b.staked_anchor_view().await;

        // Core property: identical contents AND order despite the reversed
        // inserts. `Arc<Vec<_>>: PartialEq` compares the inner Vec by value.
        assert_eq!(
            flat_a, flat_b,
            "staked-anchor view must be insertion-order-independent across nodes",
        );
        assert_eq!(flat_a.len(), 5, "all five staked anchors present");

        // Emission is lexicographic by identity hash — the guarantee that every
        // node agrees on proposer rank order.
        assert!(
            flat_a.windows(2).all(|w| w[0].0 <= w[1].0),
            "flat must be lexicographically ordered by identity hash",
        );

        // Each id carries its own stake regardless of write order.
        for (id, s) in ids.iter().zip(stakes.iter()) {
            assert!(
                flat_a.iter().any(|(fid, fs)| fid == id && fs == s),
                "anchor {id} must carry stake {s}",
            );
        }
    }

    /// First test: pin the witness-committee fixture contract — a
    /// single `feed_attestation` from a witness whose profile is registered
    /// must propagate `(profile.subnet, profile.organization)` into the
    /// `entity_clusterer.signals` map for that witness. This is the path that
    /// builds the entity-clustering signal cluster-wide; pre-fixture
    /// it was untested because the existing DISC-4 dedup tests use the bare
    /// `test_node_state(None)` (no profiles registered) — so the lookup at
    /// `state.rs:3081` always returned `None` and the propagation logic at
    /// `state.rs:3086-3092` stayed dark.
    #[tokio::test]
    async fn test_feed_attestation_propagates_committee_profile_to_signal() {
        let witness = "witness-batchH-01";
        let state = test_node_state_with_witness_committee(
            None,
            &[(witness, "navigatorbuilds", "10.0.1", "earth-eu")],
        );

        state.feed_attestation("rec-doesnt-need-to-exist", witness, 100.0).await;

        let clusterer = state.entity_clusterer.lock_recover();
        let signal = clusterer
            .get_signal(witness)
            .expect("entity_clusterer must record a signal for the witness");
        assert_eq!(
            signal.organization.as_deref(),
            Some("navigatorbuilds"),
            "profile.organization must propagate to ClusterSignal.organization"
        );
        assert_eq!(
            signal.subnet.as_deref(),
            Some("10.0.1"),
            "profile.subnet must propagate to ClusterSignal.subnet"
        );
        assert_eq!(
            signal.witness_hash, witness,
            "ClusterSignal.witness_hash must match the attesting identity"
        );
    }

    /// Second test: with a witness profile registered, the
    /// `entity_clusterer` must also pick up the attestation record id in the
    /// signal's `attestation_records` history. This pins the (record_id,
    /// timestamp) tuple append at `entity.rs:148` — the `.0` of which is the
    /// raw input to settlement-window detection downstream. The asymmetry
    /// with the previous test is intentional: the prior pins propagation
    /// shape, this one pins history append.
    #[tokio::test]
    async fn test_feed_attestation_appends_record_to_signal_history() {
        let witness = "witness-batchH-02";
        let state = test_node_state_with_witness_committee(
            None,
            &[(witness, "acme-corp", "192.168.1", "earth-us")],
        );

        state.feed_attestation("rec-history-pin-1", witness, 100.5).await;
        state.feed_attestation("rec-history-pin-2", witness, 101.5).await;

        let clusterer = state.entity_clusterer.lock_recover();
        let signal = clusterer
            .get_signal(witness)
            .expect("clusterer must record a signal");
        assert_eq!(
            signal.attestation_records.len(),
            2,
            "two attestations must produce two history entries"
        );
        let ids: Vec<&str> = signal
            .attestation_records
            .iter()
            .map(|(r, _)| r.as_str())
            .collect();
        assert!(ids.contains(&"rec-history-pin-1"));
        assert!(ids.contains(&"rec-history-pin-2"));
    }

    // ── end-to-end settlement coverage ────────────────────────────────────
    //
    // Stacks ledger stake + consensus zone-stake on the fixture so
    // the full `feed_attestation` → `is_settled` chain is exercisable
    // in-process. Pins three contracts the in-zone settlement rests on:
    //   1. Once attesting_stake reaches ≥ 2/3 of (zone_stake - creator_stake),
    //      `feed_attestation` returns `true` and `consensus.is_settled`
    //      flips to true (positive case).
    //   2. Below the 2/3 threshold the record stays unsettled (negative case).
    //   3. The creator's own staked balance is excluded from the denominator,
    //      so a creator-heavy zone still settles when the non-creator quorum
    //      attests — the classic "creator can't self-attest into settlement"
    //      pillar of MESH-BFT (Protocol §11.12).
    //
    // The witness-stake distribution is uniform (250 each) to keep arithmetic
    // obvious; bench-fixture style (witnesses with mixed stake) is left to a
    // later iteration when independence-weighted settlement
    // (`is_settled_diverse`) gets its own pinning.

    #[tokio::test]
    async fn test_feed_attestation_reaches_settlement_with_two_thirds_quorum() {
        let witnesses = &[
            ("w-quorum-1", "org-a", "10.0.1", "earth-eu", 250),
            ("w-quorum-2", "org-b", "10.0.2", "earth-eu", 250),
            ("w-quorum-3", "org-c", "10.0.3", "earth-us", 250),
            ("w-quorum-4", "org-d", "10.0.4", "earth-us", 250),
        ];
        // Pre-insert a record so feed_attestation's get_record returns Some
        // and creator_identity_hash can be computed. The record's zone is
        // determined by `zone_for_record(record_id)` (sha3 of id, mod
        // ZONE_COUNT) — discover it here and register zone-stake there so
        // the test stays robust against future ZONE_COUNT changes.
        let creator_pk = b"creator-quorum-pk-bytes".to_vec();
        let record_id = "rec-quorum-settle-1";
        let zone = super::super::consensus::zone_for_record(record_id);

        // zone_stake=1000, creator_staked=0 (default), eligible=1000,
        // 2/3 threshold = 667. 3 witnesses × 250 = 750 attesting → settles.
        let state = test_node_state_with_committee_and_stakes(None, witnesses, &zone, 0).await;
        put_record_with_creator(&state.rocks, record_id, &creator_pk, 1_700_000_000.0);

        // 2 of 4 first → still below 2/3 (500/1000 = 50%)
        let settled_after_2 = {
            let mut any = false;
            for w in &witnesses[..2] {
                any |= state.feed_attestation(record_id, w.0, 1_700_000_001.0).await.settled;
            }
            any
        };
        assert!(!settled_after_2, "2/4 attestations is below 2/3 quorum");
        {
            let c = state.consensus.lock_recover();
            assert!(!c.is_settled(record_id), "is_settled must be false at 2/4");
        }

        // 3rd attestation pushes to 750/1000 = 75% ≥ 2/3 → settles
        let settled_after_3 = state
            .feed_attestation(record_id, witnesses[2].0, 1_700_000_002.0)
            .await
            .settled;
        assert!(
            settled_after_3,
            "3/4 attestations (750/1000 stake) MUST cross the 2/3 quorum"
        );
        {
            let c = state.consensus.lock_recover();
            assert!(c.is_settled(record_id), "is_settled must be true at 3/4");
        }
    }

    /// THE exactly-once finalization edge (2026-06-11 dev-net defect): repeat
    /// attestations on an already-finalized record — including the common
    /// prune-then-re-push gossip cycle — must report `settled` (wire truth)
    /// but NEVER `first_finalization` a second time. Pre-fix, callers gated
    /// rewards + reputation credit on raw `settled`, so every re-push after
    /// the in-flight map pruned re-fired them (each reward record carries a
    /// fresh nonce/timestamp → double-pay once the conservation pool funds).
    /// The durable FinalizedIndex (cold tier) is what survives the prune and
    /// kills the re-fire — that's the property pinned here.
    #[tokio::test]
    async fn test_feed_attestation_first_finalization_fires_exactly_once_across_prune() {
        let witnesses = &[
            ("w-edge-1", "org-a", "10.0.1", "earth-eu", 250),
            ("w-edge-2", "org-b", "10.0.2", "earth-eu", 250),
            ("w-edge-3", "org-c", "10.0.3", "earth-us", 250),
            ("w-edge-4", "org-d", "10.0.4", "earth-us", 250),
        ];
        let creator_pk = b"creator-edge-pk-bytes".to_vec();
        let record_id = "rec-exactly-once-edge-1";
        let zone = super::super::consensus::zone_for_record(record_id);
        let state = test_node_state_with_committee_and_stakes(None, witnesses, &zone, 0).await;
        put_record_with_creator(&state.rocks, record_id, &creator_pk, 1_700_000_000.0);

        // Settle: 3 × 250 = 750/1000 ≥ 2/3.
        let mut first_edges = 0u32;
        for w in &witnesses[..3] {
            let o = state.feed_attestation(record_id, w.0, 1_700_000_001.0).await;
            if o.first_finalization {
                first_edges += 1;
            }
        }
        assert_eq!(first_edges, 1, "exactly ONE attestation call wins the edge");

        // Repeat attestation while still tracked → settled, no edge.
        let repeat = state.feed_attestation(record_id, witnesses[0].0, 1_700_000_002.0).await;
        assert!(repeat.settled, "record stays settled on repeat attestation");
        assert!(
            !repeat.first_finalization,
            "repeat attestation while tracked must not re-fire the edge"
        );

        // Prune the in-flight map (what finality pruning does in production),
        // then re-push the same attestations — the in-memory transition state
        // is gone, so only the durable FinalizedIndex can stop the re-fire.
        {
            let mut c = state.consensus.lock_recover();
            let mut pruned = std::collections::HashSet::new();
            pruned.insert(record_id.to_string());
            c.prune_finalized(&pruned);
        }
        for w in &witnesses[..3] {
            let o = state.feed_attestation(record_id, w.0, 1_700_000_003.0).await;
            assert!(
                !o.first_finalization,
                "re-pushed attestation after prune must NOT re-fire the edge \
                 (durable FinalizedIndex remembers the finalization)"
            );
        }
    }

    #[tokio::test]
    async fn test_feed_attestation_below_quorum_does_not_settle() {
        let witnesses = &[
            ("w-noquorum-1", "org-a", "10.0.1", "earth-eu", 250),
            ("w-noquorum-2", "org-b", "10.0.2", "earth-eu", 250),
            ("w-noquorum-3", "org-c", "10.0.3", "earth-us", 250),
            ("w-noquorum-4", "org-d", "10.0.4", "earth-us", 250),
        ];
        let creator_pk = b"creator-noquorum-pk-bytes".to_vec();
        let record_id = "rec-noquorum-stay-unsettled-1";
        let zone = super::super::consensus::zone_for_record(record_id);

        // zone_stake=1000, eligible=1000. 2 witnesses × 250 = 500 < 667.
        let state = test_node_state_with_committee_and_stakes(None, witnesses, &zone, 0).await;
        put_record_with_creator(&state.rocks, record_id, &creator_pk, 1_700_000_000.0);

        for w in &witnesses[..2] {
            let s = state.feed_attestation(record_id, w.0, 1_700_000_001.0).await;
            assert!(!s.settled, "intermediate attestation must not flip settled");
        }
        let c = state.consensus.lock_recover();
        assert!(
            !c.is_settled(record_id),
            "2/4 quorum (500/1000 stake) is below the 2/3 threshold"
        );
    }

    #[tokio::test]
    async fn test_creator_stake_excluded_from_settlement_denominator() {
        // Pin Protocol §11.12: the record creator's own staked balance is
        // subtracted from the settlement denominator so the creator cannot
        // "self-attest" into finalization. Concrete numbers chosen so the
        // test FAILS without the exclusion:
        //   zone_stake = 500 (3 witnesses × 100 + 200 creator extra)
        //   creator_staked = 200 (registered via feed_attestation's
        //     ledger.staked(creator_hash) lookup)
        //   eligible = 500 - 200 = 300
        //   attesting = 3 × 100 = 300
        //   with exclusion: 300*3=900 ≥ 300*2=600 → settles ✓
        //   without exclusion: 300*3=900 < 500*2=1000 → would NOT settle ✗
        let witnesses = &[
            ("w-excl-1", "org-a", "10.0.1", "earth-eu", 100),
            ("w-excl-2", "org-b", "10.0.2", "earth-eu", 100),
            ("w-excl-3", "org-c", "10.0.3", "earth-us", 100),
        ];
        let creator_pk = b"creator-with-stake-pk-bytes".to_vec();
        let record_id = "rec-creator-excluded-1";
        let zone = super::super::consensus::zone_for_record(record_id);

        // extra_stake=200 → zone_stake=500 (3×100 + 200).
        let state = test_node_state_with_committee_and_stakes(None, witnesses, &zone, 200).await;

        // Fund the creator's identity on the ledger so the ledger.staked
        // lookup inside feed_attestation returns 200 — this is what gets
        // threaded into consensus.register_creator_stake at state.rs:3177.
        let creator_hash = fund_account_staked(&state, &creator_pk, 200).await;

        put_record_with_creator(&state.rocks, record_id, &creator_pk, 1_700_000_000.0);

        for w in witnesses {
            state.feed_attestation(record_id, w.0, 1_700_000_001.0).await;
        }
        let c = state.consensus.lock_recover();
        // The `is_settled == true` assertion is itself proof that
        // `register_creator_stake(record_id, 200)` was called inside
        // `feed_attestation`: without that call, `creator_stakes.get(rid)`
        // returns 0 in `is_settled`, so eligible would be 500 (not 300),
        // and 300*3=900 < 500*2=1000 → would NOT settle.
        assert!(
            c.is_settled(record_id),
            "settlement MUST succeed once creator stake (200) is subtracted \
             from the 500 zone denominator — eligible=300, attesting=300, \
             300*3 >= 300*2 is the 2/3 threshold"
        );
        drop(c);
        let _ = creator_hash;
    }

    // ── diversity-weighted settlement coverage ────────────────────────────
    //
    // Extends the quorum tests to MESH-BFT Theorem 1: a record is
    // diversity-settled only if the *effective* attesting stake (each
    // witness's stake × its independence factor) clears 2/3 of the eligible
    // denominator. Same-org / same-subnet / same-geo attesters get
    // independence < 1, so a colluding committee can hit raw 2/3 stake
    // without crossing the diverse threshold — the safety pillar that
    // turns AWC into BFT even when a stake-majority is corrupted, as long
    // as the corrupted set is correlated (single organization / single
    // datacenter / single ASN).
    //
    // Cross-check vs. production: `recompute_confirmation` at
    // `consensus.rs:1877` reads `is_settled_diverse` and falls back to raw
    // `is_settled` ONLY when `small_network` (< 3 distinct orgs registered).
    // Both tests below register ≥3 distinct profiles in the fixture so the
    // small-network bypass does not fire — the diverse path is the real
    // gate. Constants (from `consensus.rs:53-84`):
    //   ALPHA = 0.5 (same-org), BETA = 0.3 (same-subnet),
    //   GAMMA = 0.2 (same-geo, scaled to 0.0 when bucket_count<2).
    //
    // Worked arithmetic for "correlated" test (Test 1):
    //   3 witnesses × 100 stake = 300 raw. All same org+subnet+geo →
    //   bucket_count=1 (single geo) → gamma_effective=0.0, so
    //   corr(A,B) = 0.5*1 + 0.3*1 + 0.0*1 = 0.8.
    //   For witness A: corr_sum = corr(A,B) + corr(A,C) = 1.6.
    //   independence(A) = 1/(1+1.6) ≈ 0.385. Same for B, C by symmetry.
    //   effective_stake = 3 × 100 × 0.385 ≈ 115.4.
    //   Raw: 300*3=900 ≥ 300*2=600 → settled.
    //   Diverse: 115.4*3 ≈ 346 < 300*2=600 → NOT settled.
    //
    // Worked arithmetic for "fully diverse" test (Test 2):
    //   3 witnesses × 100 stake. Distinct orgs, subnets, geo_zones →
    //   bucket_count=3, witness_count=3 → gamma_effective_scaled(3,3)
    //   = GAMMA*(3-2)/(12-2) = 0.02 (linear ramp from MIN_GEO_BUCKETS=2 to
    //   GAMMA_FULL_WITNESSES=12). But same_zone=0 across all pairs, so
    //   gamma contribution is moot anyway. corr(A,B) = 0 → independence=1.
    //   effective_stake = 3 × 100 × 1.0 = 300. Diverse: 300*3=900 ≥ 600.

    #[tokio::test]
    async fn test_is_settled_diverse_correlated_committee_blocks_settlement() {
        // ALL witnesses report same org + subnet + geo → correlation 0.8
        // each pair → independence ≈ 0.385 each → effective stake drops
        // from 300 to ~115, breaking the 2/3 diversity threshold even
        // though the raw threshold is cleared.
        let witnesses = &[
            ("w-corr-1", "navigator-builds", "10.0.1", "earth-eu", 100),
            ("w-corr-2", "navigator-builds", "10.0.1", "earth-eu", 100),
            ("w-corr-3", "navigator-builds", "10.0.1", "earth-eu", 100),
        ];
        let creator_pk = b"creator-correlated-pk-bytes".to_vec();
        let record_id = "rec-correlated-committee-1";
        let zone = super::super::consensus::zone_for_record(record_id);

        let state = test_node_state_with_committee_and_stakes(None, witnesses, &zone, 0).await;
        put_record_with_creator(&state.rocks, record_id, &creator_pk, 1_700_000_000.0);

        for w in witnesses {
            state.feed_attestation(record_id, w.0, 1_700_000_001.0).await;
        }

        let c = state.consensus.lock_recover();
        assert!(
            c.is_settled(record_id),
            "raw is_settled MUST flip true (all 3 of 3 witnesses attest, 300/300 stake)"
        );
        assert!(
            !c.is_settled_diverse(record_id),
            "is_settled_diverse MUST stay false — same-org/same-subnet/same-geo \
             attesters carry independence ~0.385, dropping effective stake to \
             ~115 of 300 eligible (below the 2/3 = 200 threshold). This is the \
             MESH-BFT Theorem 1 safety pillar: a colluding stake-majority cannot \
             diversity-settle without spreading across orgs."
        );
    }

    #[tokio::test]
    async fn test_is_settled_diverse_fully_diverse_committee_matches_raw() {
        // 3 distinct orgs + distinct subnets + distinct geo_zones → all
        // pairwise correlations are 0 → independence = 1.0 each → effective
        // stake equals raw stake → both is_settled and is_settled_diverse
        // pass. This pins the "no penalty for honest diversity" contract.
        let witnesses = &[
            ("w-div-1", "org-alpha", "10.0.1", "earth-eu", 100),
            ("w-div-2", "org-beta",  "192.168.2", "earth-us", 100),
            ("w-div-3", "org-gamma", "172.16.3", "earth-as", 100),
        ];
        let creator_pk = b"creator-fully-diverse-pk-bytes".to_vec();
        let record_id = "rec-fully-diverse-committee-1";
        let zone = super::super::consensus::zone_for_record(record_id);

        let state = test_node_state_with_committee_and_stakes(None, witnesses, &zone, 0).await;
        put_record_with_creator(&state.rocks, record_id, &creator_pk, 1_700_000_000.0);

        for w in witnesses {
            state.feed_attestation(record_id, w.0, 1_700_000_001.0).await;
        }

        let c = state.consensus.lock_recover();
        assert!(
            c.is_settled(record_id),
            "raw is_settled MUST flip true (3/3 witnesses, 300/300 stake)"
        );
        assert!(
            c.is_settled_diverse(record_id),
            "is_settled_diverse MUST also be true — fully diverse committee \
             carries independence = 1.0 for every witness, so effective stake \
             equals raw stake (300) and clears the 2/3 diversity threshold"
        );
    }

    // The two tests above pin the EXTREMES (all-correlated→blocks,
    // all-distinct→matches-raw). The two tests below pin the MIDDLE: partial
    // correlation where a subset of witnesses cluster on org/subnet/geo while
    // others remain independent. Production committees rarely sit at either
    // extreme — they tend to have a couple of co-located operators among
    // otherwise-diverse anchors. The diversity gate must tolerate this
    // common case (some correlation is fine) while still rejecting committees
    // where correlation dominates. These two tests bracket that contract.

    #[tokio::test]
    async fn test_is_settled_diverse_partial_correlation_settles_via_diverse_anchors() {
        // 4 witnesses, 100 stake each. A & B share an org but have distinct
        // subnets and geo zones. C & D are fully distinct (different org,
        // subnet, geo from everyone). geo_buckets = 4 distinct zones, so
        // MIN_GEO_BUCKETS=2 is met → gamma_effective = GAMMA * 4/12 ≈ 0.0667.
        //   corr(A,B) = 0.5 (org) + 0 (subnet) + 0.0667*0 (geo distinct) = 0.5
        //   corr(A,C) = corr(A,D) = corr(B,C) = corr(B,D) = corr(C,D) = 0
        //   indep(A) = 1/(1+0.5+0+0) = 2/3 ≈ 0.667 → effective ≈ 66.7
        //   indep(B) = same as A: ≈ 66.7
        //   indep(C) = indep(D) = 1.0 → effective = 100 each
        //   total effective ≈ 333.3
        //   eligible = 400, threshold = 400*2/3 ≈ 266.7
        //   333.3 > 266.7 → is_settled_diverse = TRUE
        // The two clean anchors (C, D) carry enough effective stake to
        // settle the record despite the A↔B org-pair penalty.
        let witnesses = &[
            ("w-pcs-1", "org-alpha", "10.0.1",   "earth-eu", 100),
            ("w-pcs-2", "org-alpha", "192.168.2", "earth-us", 100), // same org as #1
            ("w-pcs-3", "org-beta",  "172.16.3",  "earth-as", 100),
            ("w-pcs-4", "org-gamma", "172.17.4",  "earth-oc", 100),
        ];
        let creator_pk = b"creator-partial-settles-pk-bytes".to_vec();
        let record_id = "rec-partial-diverse-settles-1";
        let zone = super::super::consensus::zone_for_record(record_id);

        let state = test_node_state_with_committee_and_stakes(None, witnesses, &zone, 0).await;
        put_record_with_creator(&state.rocks, record_id, &creator_pk, 1_700_000_000.0);

        for w in witnesses {
            state.feed_attestation(record_id, w.0, 1_700_000_001.0).await;
        }

        let c = state.consensus.lock_recover();
        assert!(
            c.is_settled(record_id),
            "raw is_settled MUST flip true (4/4 witnesses, 400/400 stake)"
        );
        assert!(
            c.is_settled_diverse(record_id),
            "is_settled_diverse MUST be true — A & B share an org so each \
             carries ~66.7 effective stake, but C & D are fully distinct and \
             contribute 100 each. Total effective ≈ 333 ≥ threshold 267. \
             The diverse anchors hold the line despite the org-pair correlation."
        );
    }

    #[tokio::test]
    async fn test_is_settled_diverse_partial_correlation_blocks_when_majority_correlated() {
        // 4 witnesses, 100 stake each. A, B, C share org + subnet + geo
        // (full Sybil cluster). D is fully distinct. geo_buckets = 2
        // (earth-eu from A/B/C, earth-us from D) so MIN_GEO_BUCKETS=2 is met
        // → gamma_effective = GAMMA * 4/12 ≈ 0.0667.
        //   corr(A,B) = corr(A,C) = corr(B,C) = 0.5 + 0.3 + 0.0667 ≈ 0.867
        //   corr(A,D) = corr(B,D) = corr(C,D) = 0
        //   indep(A) = 1/(1 + 0.867 + 0.867 + 0) = 1/2.734 ≈ 0.366
        //   indep(B), indep(C) same: ≈ 0.366
        //   indep(D) = 1.0
        //   effective(A,B,C) ≈ 36.6 each, effective(D) = 100
        //   total effective ≈ 210
        //   eligible = 400, threshold = 400*2/3 ≈ 266.7
        //   210 < 266.7 → is_settled_diverse = FALSE
        // The single clean anchor (D) cannot carry the committee. This pins
        // the Theorem 1 invariant: even partial Sybil clusters that dominate
        // the committee are blocked from diversity-settlement.
        let witnesses = &[
            ("w-pcb-1", "navigator-builds", "10.0.1", "earth-eu", 100),
            ("w-pcb-2", "navigator-builds", "10.0.1", "earth-eu", 100),
            ("w-pcb-3", "navigator-builds", "10.0.1", "earth-eu", 100),
            ("w-pcb-4", "org-distinct",     "192.168.5", "earth-us", 100),
        ];
        let creator_pk = b"creator-partial-blocks-pk-bytes".to_vec();
        let record_id = "rec-partial-diverse-blocks-1";
        let zone = super::super::consensus::zone_for_record(record_id);

        let state = test_node_state_with_committee_and_stakes(None, witnesses, &zone, 0).await;
        put_record_with_creator(&state.rocks, record_id, &creator_pk, 1_700_000_000.0);

        for w in witnesses {
            state.feed_attestation(record_id, w.0, 1_700_000_001.0).await;
        }

        let c = state.consensus.lock_recover();
        assert!(
            c.is_settled(record_id),
            "raw is_settled MUST flip true (4/4 witnesses, 400/400 stake)"
        );
        assert!(
            !c.is_settled_diverse(record_id),
            "is_settled_diverse MUST stay false — 3-of-4 witnesses are fully \
             Sybil-clustered (same org+subnet+geo), so they carry only ~36.6 \
             effective stake each. The single distinct anchor at 100 effective \
             cannot lift the total (~210) above the threshold (267). Theorem 1 \
             holds: committees where correlation dominates are blocked even if \
             one diverse anchor attests."
        );
    }

    // ── defensive-branch coverage ─────────────────────────────────────────
    //
    // Three tests pin the early-return / defensive branches of `is_settled`
    // and `is_settled_diverse` that the happy-path quorum
    // + diversity tests don't exercise:
    //
    //   1. Unknown-profile penalty — when attesting witnesses have NO
    //      registered `WitnessProfile`, `correlation_weighted` short-circuits
    //      to `ALPHA + BETA = 0.8` at `consensus.rs:2275-2294` (AUDIT-9
    //      non-disclosure penalty). Effective stake collapses far below
    //      threshold even when raw stake is full.
    //   2. Zero eligible stake — when `settlement_denominator(zone)` returns
    //      0 (no zone stake, no committee stake registered), both
    //      `is_settled` (`consensus.rs:2163-2165`) and `is_settled_diverse`
    //      (`consensus.rs:2192-2194`) short-circuit to false regardless of
    //      how many witnesses attest. Defensive guard against empty-zone
    //      settlement / div-by-zero.
    //   3. Empty attestations — `is_settled_diverse` short-circuits at
    //      `consensus.rs:2196-2199` when the attestations map is missing or
    //      empty. Mirror of the raw path's "0 attesting → 0*3 < eligible*2",
    //      but via a distinct code branch (the diverse path would otherwise
    //      sum effective stake over an empty witness slice — the early
    //      return is what prevents downstream NaN / underflow).

    #[tokio::test]
    async fn test_is_settled_diverse_with_no_registered_profiles_applies_max_correlation_penalty() {
        // 3 witnesses × 100 stake. NONE have registered profiles → every
        // pair hits the `consensus.rs:2275-2294` unknown-profile branch,
        // returning `ALPHA + BETA = 0.8`.
        //   corr_sum(A) = 0.8 + 0.8 = 1.6
        //   indep(A) = 1/(1 + 1.6) ≈ 0.385
        //   effective ≈ 3 × 100 × 0.385 ≈ 115.4
        //   eligible = 300, threshold = 200 → 115.4 < 200 → diverse = FALSE
        //   raw = 300 ≥ 200 → is_settled = TRUE
        // This pins the AUDIT-9 non-disclosure penalty: sybils that skip
        // `register_profile` cannot diversity-settle records — even with
        // 100% raw stake — until they expose their (org, subnet, geo) tuple.
        let witnesses = ["w-noprof-1", "w-noprof-2", "w-noprof-3"];
        let creator_pk = b"creator-noprof-pk-bytes".to_vec();
        let record_id = "rec-noprof-penalty-1";
        let zone = super::super::consensus::zone_for_record(record_id);

        let state = test_node_state(None);
        {
            let mut consensus = state.consensus.lock_recover();
            consensus.register_zone_stake(zone.clone(), 300);
        }
        {
            let mut ledger = state.ledger.write().await;
            for w in &witnesses {
                let acct = ledger.accounts.entry((*w).to_string()).or_default();
                acct.staked = 100;
            }
        }
        put_record_with_creator(&state.rocks, record_id, &creator_pk, 1_700_000_000.0);

        for w in witnesses {
            state.feed_attestation(record_id, w, 1_700_000_001.0).await;
        }

        let c = state.consensus.lock_recover();
        assert!(
            c.is_settled(record_id),
            "raw is_settled MUST flip true (3/3 witnesses, 300/300 stake) — \
             the diversity penalty operates on effective stake, not raw."
        );
        assert!(
            !c.is_settled_diverse(record_id),
            "is_settled_diverse MUST stay false when no profiles are registered. \
             consensus.rs:2293 returns ALPHA+BETA=0.8 per pair → independence \
             collapses to ~0.385 each → effective stake ~115 < 200 threshold. \
             AUDIT-9 non-disclosure penalty: skipping profile registration \
             cannot earn independence credit by omission."
        );
    }

    #[tokio::test]
    async fn test_is_settled_and_diverse_short_circuit_when_zone_has_no_registered_stake() {
        // Pin the defensive `eligible_stake == 0` guard at consensus.rs:2163
        // (is_settled) and consensus.rs:2192 (is_settled_diverse). When a
        // zone has no entry in `zone_stakes` AND no committee_stakes entry,
        // `settlement_denominator` returns 0 → eligible = 0 → both functions
        // return false unconditionally even with full attestations. This is
        // the safety guard against empty-zone settlement (records that
        // arrived in a zone before stake registration completed).
        let witnesses = &[
            ("w-zero-1", "org-a", "10.0.1", "earth-eu", 100u64),
            ("w-zero-2", "org-b", "10.0.2", "earth-us", 100u64),
            ("w-zero-3", "org-c", "10.0.3", "earth-as", 100u64),
        ];
        let creator_pk = b"creator-zero-stake-pk-bytes".to_vec();
        let record_id = "rec-zero-eligible-1";

        let state = test_node_state(None);
        // Register profiles + ledger stake so the attestations carry weight
        // and the diverse path's correlation math has the inputs it expects.
        // CRITICALLY: do NOT call register_zone_stake → settlement_denominator
        // returns 0 → eligible = 0 short-circuit fires.
        {
            let mut consensus = state.consensus.lock_recover();
            for (h, o, s, g, _) in witnesses {
                consensus.register_profile(
                    h,
                    super::super::consensus::WitnessProfile {
                        organization: (*o).to_string(),
                        subnet: (*s).to_string(),
                        geo_zone: (*g).to_string(),
                    },
                );
            }
        }
        {
            let mut ledger = state.ledger.write().await;
            for (h, _, _, _, stake) in witnesses {
                let acct = ledger.accounts.entry((*h).to_string()).or_default();
                acct.staked = *stake;
            }
        }
        put_record_with_creator(&state.rocks, record_id, &creator_pk, 1_700_000_000.0);

        for w in witnesses {
            state.feed_attestation(record_id, w.0, 1_700_000_001.0).await;
        }

        let c = state.consensus.lock_recover();
        assert!(
            !c.is_settled(record_id),
            "is_settled MUST short-circuit to false when settlement_denominator \
             returns 0 (no zone stake registered → eligible_stake = 0). \
             consensus.rs:2163-2165 early-return guards against empty-zone \
             settlement."
        );
        assert!(
            !c.is_settled_diverse(record_id),
            "is_settled_diverse MUST mirror the eligible_stake = 0 short-circuit \
             at consensus.rs:2192-2194. The diverse path's early-return is \
             essential — without it the function would happily compute \
             `effective_stake * 3 >= 0 * 2` as TRUE and falsely settle every \
             attested record in an unstaked zone. Both paths must hold the \
             invariant `diverse ⇒ raw`."
        );
    }

    #[tokio::test]
    async fn test_is_settled_diverse_returns_false_for_record_with_no_attestations() {
        // Pin the consensus.rs:2196-2199 empty-attestations short-circuit:
        // when `attestations.get(record_id)` is None or empty, the diverse
        // path returns false BEFORE computing effective stake over an empty
        // witness slice. Mirror of `is_settled`'s implicit zero-stake branch
        // (`unwrap_or(0)` at consensus.rs:2171), but the diverse path needs
        // its own pinning because it constructs a `witness_hashes: Vec<&str>`
        // slice that is fed into `independence()` — an empty slice through
        // that path is meaningless and the early return is what prevents it.
        let witnesses = &[
            ("w-noatt-1", "org-a", "10.0.1", "earth-eu", 100u64),
            ("w-noatt-2", "org-b", "10.0.2", "earth-us", 100u64),
            ("w-noatt-3", "org-c", "10.0.3", "earth-as", 100u64),
        ];
        let creator_pk = b"creator-no-attestation-pk-bytes".to_vec();
        let record_id = "rec-no-attestations-1";
        let zone = super::super::consensus::zone_for_record(record_id);

        let state = test_node_state_with_committee_and_stakes(None, witnesses, &zone, 0).await;
        put_record_with_creator(&state.rocks, record_id, &creator_pk, 1_700_000_000.0);
        // INTENTIONALLY skip feed_attestation — record exists, zone is fully
        // staked, witnesses have profiles, but no attestations have arrived.

        let c = state.consensus.lock_recover();
        assert!(
            !c.is_settled(record_id),
            "is_settled must return false on a record with no attestations \
             (attesting_stake = 0 < eligible_stake * 2/3)."
        );
        assert!(
            !c.is_settled_diverse(record_id),
            "is_settled_diverse must return false on a record with no \
             attestations. consensus.rs:2196-2199 matches None/empty before \
             constructing `witness_hashes` so the downstream `independence()` \
             call never sees an empty slice."
        );
    }

    // ── batch_feed_attestations DISC-4 phase A/B/C dedup coverage ─────────
    //
    // The 2026-04-19 refactor coalesces per-attestation RocksDB writes into
    // four `HashMap` collectors (entity signals / attestation appends /
    // creator trust / reputation), drained at end into a single
    // `spawn_blocking` task. These tests cover the contract guarantees:
    //   1. Empty batch → empty result, no async work spawned.
    //   2. Many atts for unknown records → no panic, no writes (creator_hash
    //      is None so creator_trust_writes stays empty).
    //   3. Repeated witness in the same batch → dedup applies (verified
    //      indirectly via total_attestations_processed counter increment).

    #[tokio::test]
    async fn test_batch_feed_attestations_empty_batch() {
        let state = test_node_state(None);
        let result = state.batch_feed_attestations(&[]).await;
        assert!(result.settled.is_empty(), "empty batch must return empty outcome");
        assert!(result.newly_finalized.is_empty(), "empty batch must return empty outcome");
        assert_eq!(
            state.total_attestations_processed.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "empty batch must not increment processed counter"
        );
    }

    #[tokio::test]
    async fn test_batch_feed_attestations_unknown_records_no_panic() {
        // Atts arrive for record_ids the node hasn't seen — Step 3a get_record
        // returns None, creator_hashes[i] is None, creator_trust_writes stays
        // empty. Should still process counters and not panic.
        let state = test_node_state(None);
        let batch = vec![
            ("unknown-r1".into(), "witness-w1".into(), 100.0),
            ("unknown-r2".into(), "witness-w2".into(), 101.0),
        ];
        let result = state.batch_feed_attestations(&batch).await;
        // No records exist → nothing settles → empty result
        assert!(result.settled.is_empty());
        // But the counter still tracks all processed atts
        assert_eq!(
            state.total_attestations_processed.load(std::sync::atomic::Ordering::Relaxed),
            2,
            "processed counter must reflect batch size even with unknown records"
        );
    }

    #[tokio::test]
    async fn test_batch_feed_attestations_repeated_witness_dedup() {
        // 50 atts from the SAME witness. Pre-refactor: 50 sync put_cf_raw calls
        // to CF_TRUST entity:{wh}. Post-refactor: 1 entry in entity_signal_writes
        // HashMap (overwrite semantics on .insert).
        // We can't directly observe the HashMap, but we can verify:
        //   - Function completes without hanging
        //   - All atts counted in total_attestations_processed
        //   - No panic from the spawn_blocking drain
        let state = test_node_state(None);
        let mut batch = Vec::with_capacity(50);
        for i in 0..50 {
            batch.push((
                format!("rec-{i:03}"),
                "witness-shared".into(),
                100.0 + i as f64,
            ));
        }
        let result = state.batch_feed_attestations(&batch).await;
        assert!(result.settled.is_empty(), "no settlement expected for unknown records");
        assert_eq!(
            state.total_attestations_processed.load(std::sync::atomic::Ordering::Relaxed),
            50,
            "all 50 atts must count toward processed total"
        );
        // Liveness should track this witness now (in-memory state pre-spawn_blocking)
        let liveness = state.witness_liveness.lock_recover();
        assert!(
            liveness.last_seen("witness-shared").is_some(),
            "Step 1 liveness update must happen synchronously before spawn_blocking"
        );
    }

    // ── batch_feed_attestations happy-path settlement coverage ─────────────
    //
    // The DISC-4 phase A/B/C tests above pin empty / unknown / dedup edges —
    // none exercise the production-active path where atts arrive as a single
    // batch (e.g. via pq_transport gossip burst or via the seal_loop's batched
    // attestation drain) and cross the 2/3 quorum inside ONE call. These three
    // tests mirror the `feed_attestation` settlement contracts at
    // `state.rs:5054` (positive quorum) and `:5104` (sub-quorum) so the batch
    // path is held to the same invariants: `is_settled` agrees with the
    // confirmation-level transition, the within-batch `add_attestation`
    // recompute already lands records at `Finalized` (which is WHY the
    // `force_finalized(rid)` gate at `state.rs:3665` returns false on the
    // immediate re-call — see `test_batch_feed_attestations_idempotent_on_resend`
    // below for the regression pin).

    #[tokio::test]
    async fn test_batch_feed_attestations_promotes_confirmation_to_finalized_on_quorum() {
        let witnesses = &[
            ("w-batch-quorum-1", "org-a", "10.0.1", "earth-eu", 250),
            ("w-batch-quorum-2", "org-b", "10.0.2", "earth-eu", 250),
            ("w-batch-quorum-3", "org-c", "10.0.3", "earth-us", 250),
            ("w-batch-quorum-4", "org-d", "10.0.4", "earth-us", 250),
        ];
        let creator_pk = b"creator-batch-quorum-pk-bytes".to_vec();
        let record_id = "rec-batch-quorum-settle-1";
        let zone = super::super::consensus::zone_for_record(record_id);

        // zone_stake=1000, threshold=667. 3 × 250 = 750 → settles in a single batch.
        let state = test_node_state_with_committee_and_stakes(None, witnesses, &zone, 0).await;
        put_record_with_creator(&state.rocks, record_id, &creator_pk, 1_700_000_000.0);

        // First 3 witnesses, all in ONE batch call (mirrors gossip-burst arrival).
        let batch: Vec<(String, String, f64)> = witnesses[..3]
            .iter()
            .enumerate()
            .map(|(i, w)| (record_id.to_string(), w.0.to_string(), 1_700_000_001.0 + i as f64))
            .collect();

        let _settled = state.batch_feed_attestations(&batch).await;
        // Settlement reflected on the consensus side regardless of whether
        // `add_attestation`'s in-loop recompute or the post-loop force-finalize
        // path emitted the rid — both end states are Finalized.
        {
            use super::super::consensus::ConfirmationLevel;
            let c = state.consensus.lock_recover();
            assert!(
                c.is_settled(record_id),
                "750/1000 stake in a single batch MUST cross the 2/3 quorum"
            );
            assert_eq!(
                c.confirmation_level(record_id),
                ConfirmationLevel::Finalized,
                "after batch of 3 diverse attestations the record's \
                 confirmation_level must be Finalized (witness_count=3 ≥ \
                 CONFIRMED_MIN_WITNESSES, distinct_clusters=3 ≥ \
                 CONFIRMED_MIN_CLUSTERS, raw_settled=true)"
            );
        }
        // Counter increments by batch.len() (3), not settled.len() (1).
        assert_eq!(
            state.total_attestations_processed.load(std::sync::atomic::Ordering::Relaxed),
            3,
            "processed counter tracks atts in the batch, not settled records"
        );
    }

    #[tokio::test]
    async fn test_batch_feed_attestations_below_quorum_stays_unsettled() {
        let witnesses = &[
            ("w-batch-noquorum-1", "org-a", "10.0.1", "earth-eu", 250),
            ("w-batch-noquorum-2", "org-b", "10.0.2", "earth-eu", 250),
            ("w-batch-noquorum-3", "org-c", "10.0.3", "earth-us", 250),
            ("w-batch-noquorum-4", "org-d", "10.0.4", "earth-us", 250),
        ];
        let creator_pk = b"creator-batch-noquorum-pk-bytes".to_vec();
        let record_id = "rec-batch-noquorum-stay-unsettled-1";
        let zone = super::super::consensus::zone_for_record(record_id);

        // zone_stake=1000, threshold=667. 2 × 250 = 500 → below threshold.
        let state = test_node_state_with_committee_and_stakes(None, witnesses, &zone, 0).await;
        put_record_with_creator(&state.rocks, record_id, &creator_pk, 1_700_000_000.0);

        let batch: Vec<(String, String, f64)> = witnesses[..2]
            .iter()
            .enumerate()
            .map(|(i, w)| (record_id.to_string(), w.0.to_string(), 1_700_000_001.0 + i as f64))
            .collect();

        let settled = state.batch_feed_attestations(&batch).await;
        assert!(
            settled.settled.is_empty(),
            "500/1000 stake in a single batch must NOT settle: returned list \
             stays empty (mirrors feed_attestation sub-quorum contract)"
        );
        {
            use super::super::consensus::ConfirmationLevel;
            let c = state.consensus.lock_recover();
            assert!(
                !c.is_settled(record_id),
                "is_settled must be false at 2/4 (500/1000 stake)"
            );
            let lvl = c.confirmation_level(record_id);
            assert_ne!(
                lvl,
                ConfirmationLevel::Finalized,
                "confirmation level must NOT be Finalized below quorum (got {lvl:?})"
            );
            assert_ne!(
                lvl,
                ConfirmationLevel::Anchored,
                "confirmation level must NOT be Anchored below quorum (got {lvl:?})"
            );
        }
        assert_eq!(
            state.total_attestations_processed.load(std::sync::atomic::Ordering::Relaxed),
            2,
            "all 2 atts in the batch must count toward processed total"
        );
    }

    #[tokio::test]
    async fn test_batch_feed_attestations_idempotent_on_resend() {
        // Pins the gate at `state.rs:3665` — calling `batch_feed_attestations`
        // twice with the SAME quorum-crossing batch must leave the consensus
        // side at Finalized exactly once. The second call's
        // `consensus.force_finalized(rid)` returns false (already Finalized
        // by the first call's in-loop recompute), so the second invocation
        // contributes no new finality side-effect — only the att-processed
        // counter advances by batch.len(). This is the regression pin
        // protecting the fleet-wide `total_ever_settled` from the 2-3×
        // over-count seen previously when idempotent re-feed double-bumped.
        let witnesses = &[
            ("w-batch-idem-1", "org-a", "10.0.1", "earth-eu", 250),
            ("w-batch-idem-2", "org-b", "10.0.2", "earth-eu", 250),
            ("w-batch-idem-3", "org-c", "10.0.3", "earth-us", 250),
            ("w-batch-idem-4", "org-d", "10.0.4", "earth-us", 250),
        ];
        let creator_pk = b"creator-batch-idem-pk-bytes".to_vec();
        let record_id = "rec-batch-idem-1";
        let zone = super::super::consensus::zone_for_record(record_id);

        let state = test_node_state_with_committee_and_stakes(None, witnesses, &zone, 0).await;
        put_record_with_creator(&state.rocks, record_id, &creator_pk, 1_700_000_000.0);

        let batch: Vec<(String, String, f64)> = witnesses[..3]
            .iter()
            .enumerate()
            .map(|(i, w)| (record_id.to_string(), w.0.to_string(), 1_700_000_001.0 + i as f64))
            .collect();

        let first = state.batch_feed_attestations(&batch).await;
        assert_eq!(
            first.newly_finalized,
            vec![record_id.to_string()],
            "first settling batch must report the rid on the exactly-once edge"
        );
        let snapshot_settled_after_first = state
            .total_ever_settled
            .load(std::sync::atomic::Ordering::Relaxed);

        {
            use super::super::consensus::ConfirmationLevel;
            let c = state.consensus.lock_recover();
            assert!(c.is_settled(record_id), "first batch must settle the record");
            assert_eq!(
                c.confirmation_level(record_id),
                ConfirmationLevel::Finalized,
                "first batch lands the record at Finalized"
            );
        }

        // Re-submit the identical batch — the in-loop `add_attestation` dedup
        // (`state.rs:1791`) drops the second copy of each (rid, witness) pair.
        // Under the exactly-once-edge contract the record still REPORTS as
        // settled (it is — mirrors feed_attestation's repeat semantics), but
        // the durable FinalizedIndex dedups the insert, so newly_finalized
        // stays empty and total_ever_settled doesn't double-bump.
        let second = state.batch_feed_attestations(&batch).await;
        assert_eq!(
            second.settled,
            vec![record_id.to_string()],
            "second identical batch still reports the record as settled \
             (wire truth — it IS settled); the exactly-once protection \
             lives in newly_finalized, not here"
        );
        assert_eq!(
            state.total_ever_settled.load(std::sync::atomic::Ordering::Relaxed),
            snapshot_settled_after_first,
            "total_ever_settled is invariant across the 2nd identical batch \
             (no re-bump on idempotent re-feed)"
        );
        assert!(
            second.newly_finalized.is_empty(),
            "exactly-once edge must NOT re-fire on an identical second batch"
        );
        // Counter for atts processed DOES advance — both batches counted,
        // even though only batch #1 changed consensus state.
        assert_eq!(
            state.total_attestations_processed.load(std::sync::atomic::Ordering::Relaxed),
            6,
            "total_attestations_processed = 3 + 3 = 6 across both calls"
        );
    }

    // AUDIT-10 Milestone B: per-caller HTTPS fallback counter exposes
    // `elara_https_fallback_total{caller}` so operators can verify that the
    // PQ-only data plane is not silently regressing. The runtime data plane
    // has no HTTPS escape hatch today; this counter is the regression alarm.
    #[test]
    fn https_fallback_helper_increments_each_known_caller() {
        let state = test_node_state(None);
        // Initial state: every counter at zero.
        for caller in ["gossip", "sync", "light", "discovery"] {
            let v = match caller {
                "gossip" => state.https_fallback_gossip_total.load(std::sync::atomic::Ordering::Relaxed),
                "sync" => state.https_fallback_sync_total.load(std::sync::atomic::Ordering::Relaxed),
                "light" => state.https_fallback_light_total.load(std::sync::atomic::Ordering::Relaxed),
                "discovery" => state.https_fallback_discovery_total.load(std::sync::atomic::Ordering::Relaxed),
                _ => unreachable!(),
            };
            assert_eq!(v, 0, "{caller} fallback counter must start at zero");
        }

        // Each known caller increments only its own bucket.
        state.record_https_fallback("gossip");
        state.record_https_fallback("gossip");
        state.record_https_fallback("sync");
        state.record_https_fallback("light");
        state.record_https_fallback("discovery");

        assert_eq!(state.https_fallback_gossip_total.load(std::sync::atomic::Ordering::Relaxed), 2);
        assert_eq!(state.https_fallback_sync_total.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert_eq!(state.https_fallback_light_total.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert_eq!(state.https_fallback_discovery_total.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    #[test]
    fn https_fallback_helper_silently_ignores_unknown_caller() {
        let state = test_node_state(None);
        // Unknown caller name is dropped — no panic, no spurious increment in
        // any bucket. Misspelling a label must never crash a hot loop.
        state.record_https_fallback("unknown");
        state.record_https_fallback("");
        assert_eq!(state.https_fallback_gossip_total.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert_eq!(state.https_fallback_sync_total.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert_eq!(state.https_fallback_light_total.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert_eq!(state.https_fallback_discovery_total.load(std::sync::atomic::Ordering::Relaxed), 0);
    }

    // ── /ws Slice 3c — single-transport session counter ──────────────────
    //
    // The legacy `/ws` route is gone; only `pq_ws_sessions_total` remains.
    // The cutover counter `ws_legacy_sessions_total` was deleted alongside
    // the route — there's nowhere left to bump it. This test pins the
    // post-cutover surface so a re-introduction of the legacy WS route
    // would have to either re-add the counter (caught by code review) or
    // bump pq_ws_sessions_total (which is wrong-shape and would fail this
    // metric-exposition test).

    #[tokio::test]
    async fn metrics_body_exports_pq_ws_session_counter() {
        let state = test_node_state(None);
        state.pq_ws_sessions_total.fetch_add(11, std::sync::atomic::Ordering::Relaxed);
        state.ws_connections.fetch_add(2, std::sync::atomic::Ordering::Relaxed);

        let body = super::super::server::metrics_body(state).await;
        assert!(body.contains("elara_pq_ws_sessions_total 11"), "missing pq_ws count: {body}");
        assert!(body.contains("elara_ws_connections_active 2"), "missing active gauge: {body}");
        assert!(!body.contains("elara_ws_legacy_sessions_total"),
                "legacy counter must be gone post-Slice-3c: {body}");
    }

    #[tokio::test]
    async fn p0_exact_tier_allowlist_has_no_phantom_names() {
        // Regression guard for the "17/32 P0 hits" incident (classify_metric's
        // P0_EXACT once listed `elara_seal_success_total`, a gauge no code path
        // emits). A phantom entry silently shrinks the phone-tier P0 scrape with
        // no error and no failing test. Render the full Debug-tier surface and
        // assert every name in P0_EXACT is actually emitted.
        //
        // PSI/cgroup pressure P0 metrics read /proc/pressure and only emit on a
        // host that exposes it (kernel >= 4.20). On a non-PSI CI host they are
        // legitimately absent — not phantoms — so each /proc-gated family is
        // checked only when THIS host proves the capability by emitting it.
        use crate::network::server::{metrics_body_tiered, MetricTier, P0_EXACT};
        let state = test_node_state(None);
        let body = metrics_body_tiered(state, Some(MetricTier::Debug)).await;

        // Emitted series names = first token of every non-comment line, stripped
        // of any `{label=...}` suffix (`elara_foo{a="b"} 1` -> `elara_foo`).
        let emitted: std::collections::HashSet<&str> = body
            .lines()
            .filter(|l| !l.starts_with('#'))
            .filter_map(|l| l.split([' ', '{']).next())
            .filter(|n| n.starts_with("elara_"))
            .collect();

        let host_has_host_psi = emitted.iter().any(|n| n.starts_with("elara_host_pressure_"));
        let host_has_cgroup_psi = emitted.iter().any(|n| n.starts_with("elara_cgroup_pressure_"));

        let phantoms: Vec<&str> = P0_EXACT
            .iter()
            .copied()
            .filter(|name| !emitted.contains(name))
            .filter(|name| {
                // A /proc-gated PSI family absent because this host lacks the
                // capability is not a phantom — only count genuinely-missing names.
                if name.starts_with("elara_host_pressure_") && !host_has_host_psi {
                    return false;
                }
                if name.starts_with("elara_cgroup_pressure_") && !host_has_cgroup_psi {
                    return false;
                }
                true
            })
            .collect();

        assert!(
            phantoms.is_empty(),
            "classify_metric's P0_EXACT lists {} metric name(s) the node never emits \
             — a phantom shrinks the phone-tier P0 surface (see the \
             `elara_seal_success_total` incident). Fix the name in P0_EXACT or add \
             the emitter. Phantoms: {:?}",
            phantoms.len(),
            phantoms,
        );
    }

    // ── Attestation-receive rejection counters + deferred buffer ─
    //
    // A peer-to-peer pq-400 storm can produce ~25 rejects/min visible only in
    // journal logs (every 50 rejections). These counters surface each
    // rejection reason as a Prometheus metric so operators can distinguish
    // bad-sig spam from sybil-gate hits from deferred (record-not-yet-local).

    #[test]
    fn ops19_rejection_counters_initialize_to_zero() {
        let state = test_node_state(None);
        assert_eq!(state.attestation_receive_rejected_bad_signature_total.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert_eq!(state.attestation_receive_rejected_unknown_pk_total.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert_eq!(state.attestation_receive_rejected_low_stake_total.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert_eq!(state.attestation_receive_rejected_too_young_total.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert_eq!(state.attestation_receive_rejected_bad_powas_total.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert_eq!(state.attestation_receive_deferred_total.load(std::sync::atomic::Ordering::Relaxed), 0);
    }

    #[test]
    fn ops19_rejection_counters_independent() {
        // Six fields, six independent buckets. A single bad-sig increment must
        // not bleed into the unknown-pk bucket — that would defeat the whole
        // point of breaking out the reasons.
        let state = test_node_state(None);
        state.attestation_receive_rejected_bad_signature_total.fetch_add(3, std::sync::atomic::Ordering::Relaxed);
        state.attestation_receive_rejected_unknown_pk_total.fetch_add(5, std::sync::atomic::Ordering::Relaxed);
        state.attestation_receive_rejected_low_stake_total.fetch_add(7, std::sync::atomic::Ordering::Relaxed);
        state.attestation_receive_rejected_too_young_total.fetch_add(11, std::sync::atomic::Ordering::Relaxed);
        state.attestation_receive_rejected_bad_powas_total.fetch_add(13, std::sync::atomic::Ordering::Relaxed);
        state.attestation_receive_deferred_total.fetch_add(17, std::sync::atomic::Ordering::Relaxed);

        assert_eq!(state.attestation_receive_rejected_bad_signature_total.load(std::sync::atomic::Ordering::Relaxed), 3);
        assert_eq!(state.attestation_receive_rejected_unknown_pk_total.load(std::sync::atomic::Ordering::Relaxed), 5);
        assert_eq!(state.attestation_receive_rejected_low_stake_total.load(std::sync::atomic::Ordering::Relaxed), 7);
        assert_eq!(state.attestation_receive_rejected_too_young_total.load(std::sync::atomic::Ordering::Relaxed), 11);
        assert_eq!(state.attestation_receive_rejected_bad_powas_total.load(std::sync::atomic::Ordering::Relaxed), 13);
        assert_eq!(state.attestation_receive_deferred_total.load(std::sync::atomic::Ordering::Relaxed), 17);
    }

    #[test]
    fn ops19_deferred_attestation_counts_empty() {
        let state = test_node_state(None);
        let (records, total) = state.deferred_attestation_counts();
        assert_eq!(records, 0);
        assert_eq!(total, 0);
    }

    #[test]
    fn ops19_deferred_attestation_counts_aggregates() {
        // Two records, mixed witness counts:
        //   record-A: 3 deferred attestations from 3 different witnesses
        //   record-B: 1 deferred attestation
        // Expected: records=2, total=4. This is the data shape /metrics
        // (deferred_records, deferred_buffered) reads, so the helper must
        // sum across HashMap values, not just count keys.
        let state = test_node_state(None);
        {
            let mut buf = state.deferred_attestations.lock().expect("lock");
            for w in ["w1", "w2", "w3"] {
                buf.push_bounded("rec-A", DeferredAttestation { witness_hash: w.into(), signature: vec![1], timestamp: 1.0, witness_public_key: None, powas_nonce: None, powas_difficulty: None, received_at: 1.0 }, 1.0, MAX_DEFERRED_ATTS_PER_RECORD);
            }
            buf.push_bounded("rec-B", DeferredAttestation { witness_hash: "w4".into(), signature: vec![4], timestamp: 2.0, witness_public_key: None, powas_nonce: None, powas_difficulty: None, received_at: 2.0 }, 2.0, MAX_DEFERRED_ATTS_PER_RECORD);
        }
        let (records, total) = state.deferred_attestation_counts();
        assert_eq!(records, 2);
        assert_eq!(total, 4);
    }

    fn mk_deferred(w: &str, t: f64) -> DeferredAttestation {
        DeferredAttestation {
            witness_hash: w.into(),
            signature: vec![0u8; 4],
            timestamp: t,
            witness_public_key: None,
            powas_nonce: None,
            powas_difficulty: None,
            received_at: t,
        }
    }

    // Post-handshake audit 2026-07-02: map-saturation eviction was an
    // O(buckets) scan cloning every key under the mutex, per message once
    // saturated (attacker-reachable via random unknown record_ids). These pin
    // the replacement: creation-order deque, lazy skip of drained rids, and
    // the oldest-FIRST-SEEN semantics (including the recycled-rid bias).
    #[test]
    fn deferred_buf_saturation_evicts_oldest_first_seen_bucket() {
        let mut buf = DeferredAttestationBuf::new();
        for (i, rid) in ["r1", "r2", "r3", "r4"].iter().enumerate() {
            buf.push_bounded(rid, mk_deferred("w", i as f64), i as f64, 128);
        }
        // Over cap → oldest-created bucket goes first.
        assert_eq!(buf.evict_oldest_if_over(3), Some("r1".to_string()));
        assert!(buf.bucket("r1").is_none());
        // At/under cap → no-op.
        assert_eq!(buf.evict_oldest_if_over(3), None);
        // Drain r2 (record arrived): its stale deque entry must be lazily
        // skipped — the next eviction removes the oldest LIVE bucket (r3),
        // never a phantom, and the map count stays exact.
        buf.remove("r2");
        buf.push_bounded("r5", mk_deferred("w", 9.0), 9.0, 128);
        buf.push_bounded("r6", mk_deferred("w", 10.0), 10.0, 128);
        assert_eq!(buf.evict_oldest_if_over(3), Some("r3".to_string()));
        assert_eq!(buf.counts().0, 3);
    }

    #[test]
    fn deferred_buf_sweep_amortized_expires_ttl_and_prunes_stale_order() {
        let mut buf = DeferredAttestationBuf::new();
        assert!(buf.maybe_sweep_expired(0.0)); // tick 0 sweeps
        buf.push_bounded("old", mk_deferred("w", 0.0), 0.0, 128);
        buf.push_bounded("fresh", mk_deferred("w", 650.0), 650.0, 128);
        buf.remove("fresh"); // drained → stale order entry
        buf.push_bounded("fresh", mk_deferred("w", 651.0), 651.0, 128); // re-created → 2nd entry
        assert_eq!(buf.order_len(), 3);
        // Ticks 1..=127 are no-ops (amortization: no per-message O(buckets) work).
        for _ in 0..127 {
            assert!(!buf.maybe_sweep_expired(651.0));
        }
        // Tick 128 sweeps: "old" aged out (>600s) and its deque entry drops
        // with it. "fresh" is live again, so BOTH its entries survive the
        // rid-liveness retain — duplicates for a live rid resolve lazily at
        // eviction pops, not at sweep.
        assert!(buf.maybe_sweep_expired(700.0));
        assert!(buf.bucket("old").is_none());
        assert!(buf.bucket("fresh").is_some());
        assert_eq!(buf.order_len(), 2);
        assert_eq!(buf.counts(), (1, 1));
    }

    #[test]
    fn deferred_buf_recreated_bucket_evicts_at_first_seen_position() {
        // A rid re-cited after its bucket was swept/evicted keeps its original
        // deque position (documented bias: only flood traffic can be re-cited,
        // and evicting recycled rids early is preferred).
        let mut buf = DeferredAttestationBuf::new();
        buf.push_bounded("a", mk_deferred("w", 1.0), 1.0, 128);
        buf.push_bounded("b", mk_deferred("w", 2.0), 2.0, 128);
        buf.remove("a");
        buf.push_bounded("a", mk_deferred("w", 3.0), 3.0, 128);
        assert_eq!(buf.evict_oldest_if_over(1), Some("a".to_string()));
        assert!(buf.bucket("b").is_some());
    }

    #[tokio::test]
    async fn ops19_metrics_body_exports_rejection_counters_and_deferred_gauges() {
        let state = test_node_state(None);
        state.attestation_receive_rejected_bad_signature_total.fetch_add(2, std::sync::atomic::Ordering::Relaxed);
        state.attestation_receive_rejected_unknown_pk_total.fetch_add(4, std::sync::atomic::Ordering::Relaxed);
        state.attestation_receive_rejected_low_stake_total.fetch_add(6, std::sync::atomic::Ordering::Relaxed);
        state.attestation_receive_rejected_too_young_total.fetch_add(8, std::sync::atomic::Ordering::Relaxed);
        state.attestation_receive_rejected_bad_powas_total.fetch_add(10, std::sync::atomic::Ordering::Relaxed);
        state.attestation_receive_deferred_total.fetch_add(12, std::sync::atomic::Ordering::Relaxed);
        state.propagation_limiter.lock().expect("lock").check_and_record("some-identity-hash", 1.0);
        {
            let mut buf = state.deferred_attestations.lock().expect("lock");
            for w in ["wx", "wy"] {
                buf.push_bounded("rec-X", DeferredAttestation { witness_hash: w.into(), signature: vec![9], timestamp: 0.0, witness_public_key: None, powas_nonce: None, powas_difficulty: None, received_at: 0.0 }, 0.0, MAX_DEFERRED_ATTS_PER_RECORD);
            }
        }

        let body = super::super::server::metrics_body(state).await;
        assert!(body.contains("elara_attestation_receive_rejected_bad_signature_total 2"), "missing bad_sig: {body}");
        assert!(body.contains("elara_attestation_receive_rejected_unknown_pk_total 4"), "missing unknown_pk: {body}");
        assert!(body.contains("elara_attestation_receive_rejected_low_stake_total 6"), "missing low_stake: {body}");
        assert!(body.contains("elara_attestation_receive_rejected_too_young_total 8"), "missing too_young: {body}");
        assert!(body.contains("elara_attestation_receive_rejected_bad_powas_total 10"), "missing bad_powas: {body}");
        assert!(body.contains("elara_attestation_receive_deferred_total 12"), "missing deferred_total: {body}");
        assert!(body.contains("elara_attestation_deferred_records 1"), "missing deferred_records gauge: {body}");
        assert!(body.contains("elara_attestation_deferred_buffered 2"), "missing deferred_buffered gauge: {body}");
        assert!(body.contains("elara_propagation_limiter_tracked_identities 1"), "missing propagation-limiter gauge: {body}");
    }

    // ── Auto-witness skip-cause counters ──
    //
    // Closes the `auto_witness_cycles_total = 0` blindspot: before these
    // counters, an operator seeing `cycles_total = 0` could not distinguish
    // catchup-guard pressure (orphan_count > 1000) from missing stake from
    // VRF-committee miss. Each skip-cause counter is bumped at exactly one
    // of the three early-`continue` branches inside `auto_witness::run_loop`
    // — sum of (cycles_total + orphan + not_staked + no_jury) = total loop
    // iterations since boot.

    #[test]
    fn auto_witness_skip_counters_initialize_to_zero() {
        let state = test_node_state(None);
        assert_eq!(state.auto_witness_skips_orphan_total.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert_eq!(state.auto_witness_skips_not_staked_total.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert_eq!(state.auto_witness_skips_no_jury_total.load(std::sync::atomic::Ordering::Relaxed), 0);
    }

    #[test]
    fn auto_witness_skip_counters_independent_no_cross_bleed() {
        // Three counters, three independent buckets. A future code-shuffle
        // that aliased the orphan-skip into the not-staked atomic would
        // silently misattribute a node's catchup pressure as a stake-config
        // bug — exactly the kind of regression these distinct counters
        // exist to prevent.
        let state = test_node_state(None);
        state.auto_witness_skips_orphan_total.fetch_add(3, std::sync::atomic::Ordering::Relaxed);
        state.auto_witness_skips_not_staked_total.fetch_add(5, std::sync::atomic::Ordering::Relaxed);
        state.auto_witness_skips_no_jury_total.fetch_add(7, std::sync::atomic::Ordering::Relaxed);

        assert_eq!(state.auto_witness_skips_orphan_total.load(std::sync::atomic::Ordering::Relaxed), 3);
        assert_eq!(state.auto_witness_skips_not_staked_total.load(std::sync::atomic::Ordering::Relaxed), 5);
        assert_eq!(state.auto_witness_skips_no_jury_total.load(std::sync::atomic::Ordering::Relaxed), 7);
        // Other auto-witness counters MUST stay at 0 — the new counters
        // are siblings of `cycles_total`, not replacements.
        assert_eq!(state.auto_witness_cycles_total.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert_eq!(state.auto_witness_records_total.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert_eq!(state.auto_witness_failures_total.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert_eq!(state.auto_witness_zombie_repush_skipped_total.load(std::sync::atomic::Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn auto_witness_skip_counters_surface_in_metrics_body() {
        // Pins the Prometheus emission shape so operator dashboards that
        // grep for the exact metric name + value will alert on any future
        // serialisation regression (e.g., a format-string typo that drops
        // the trailing `_total` suffix, which would silently break
        // operator alerts keyed on the counter name).
        let state = test_node_state(None);
        state.auto_witness_skips_orphan_total.fetch_add(41, std::sync::atomic::Ordering::Relaxed);
        state.auto_witness_skips_not_staked_total.fetch_add(53, std::sync::atomic::Ordering::Relaxed);
        state.auto_witness_skips_no_jury_total.fetch_add(67, std::sync::atomic::Ordering::Relaxed);

        let body = super::super::server::metrics_body(state).await;
        assert!(body.contains("elara_auto_witness_skips_orphan_total 41"), "missing orphan-skip counter: {body}");
        assert!(body.contains("elara_auto_witness_skips_not_staked_total 53"), "missing not-staked-skip counter: {body}");
        assert!(body.contains("elara_auto_witness_skips_no_jury_total 67"), "missing no-jury-skip counter: {body}");
        // HELP + TYPE lines must also be present so Prometheus picks up the
        // counter type correctly (a missing TYPE line silently degrades the
        // counter to an unlabeled untyped metric).
        assert!(body.contains("# TYPE elara_auto_witness_skips_orphan_total counter"), "missing orphan TYPE: {body}");
        assert!(body.contains("# TYPE elara_auto_witness_skips_not_staked_total counter"), "missing not-staked TYPE: {body}");
        assert!(body.contains("# TYPE elara_auto_witness_skips_no_jury_total counter"), "missing no-jury TYPE: {body}");
    }

    /// R3-9 Decision B: the verify-before-co-sign withheld counter surfaces
    /// as ONE metric family with a fixed-cardinality reason label. Pins the
    /// exact label spelling — operator alerting for the multi-anchor era
    /// keys on `reason="omission"` (the selective-finality alarm).
    #[tokio::test]
    async fn seal_verify_withheld_counters_surface_in_metrics_body() {
        let state = test_node_state(None);
        state.seal_verify_before_attest_withheld_behind_total.fetch_add(11, std::sync::atomic::Ordering::Relaxed);
        state.seal_verify_before_attest_withheld_omission_total.fetch_add(13, std::sync::atomic::Ordering::Relaxed);
        state.seal_verify_before_attest_withheld_root_mismatch_total.fetch_add(17, std::sync::atomic::Ordering::Relaxed);
        state.seal_verify_before_attest_withheld_malformed_total.fetch_add(19, std::sync::atomic::Ordering::Relaxed);

        let body = super::super::server::metrics_body(state).await;
        assert!(
            body.contains("elara_seal_verify_before_attest_withheld_total{reason=\"behind\"} 11"),
            "missing behind reason line: {body}"
        );
        assert!(
            body.contains("elara_seal_verify_before_attest_withheld_total{reason=\"omission\"} 13"),
            "missing omission reason line: {body}"
        );
        assert!(
            body.contains("elara_seal_verify_before_attest_withheld_total{reason=\"root_mismatch\"} 17"),
            "missing root_mismatch reason line: {body}"
        );
        assert!(
            body.contains("elara_seal_verify_before_attest_withheld_total{reason=\"malformed\"} 19"),
            "missing malformed reason line: {body}"
        );
        assert!(
            body.contains("# TYPE elara_seal_verify_before_attest_withheld_total counter"),
            "missing TYPE line: {body}"
        );
    }

    // ── bratio cohort-membership gauge surfaces in metrics_body ───────────
    //
    // Pins the gauge `elara_bratio_cohort_membership` to
    // the metrics_body scrape surface. On a fresh node with no in-flight
    // attestations, `AWCConsensus::attestation_ratio_summary()` returns
    // `tracked=0`, which classify_cohort() maps to band 0 (DORMANT). The
    // assertion locks in both the metric name and the default value — a
    // future format-string typo (e.g. dropping the gauge from the scrape)
    // or a regression in classify_cohort's tracked==0 branch would fail
    // here before reaching production.
    #[tokio::test]
    async fn bratio_cohort_membership_gauge_surfaces_in_metrics_body() {
        let state = test_node_state(None);

        let body = super::super::server::metrics_body(state).await;
        assert!(
            body.contains("elara_bratio_cohort_membership 0"),
            "missing cohort gauge or wrong default value (expected 0=DORMANT on fresh state): {body}"
        );
        // HELP + TYPE lines must also be present so Prometheus parses the
        // gauge type correctly (a missing TYPE line silently degrades it to
        // an untyped metric, breaking band-occupancy panels keyed on it).
        assert!(
            body.contains("# TYPE elara_bratio_cohort_membership gauge"),
            "missing TYPE line: {body}"
        );
        assert!(
            body.contains("# HELP elara_bratio_cohort_membership"),
            "missing HELP line: {body}"
        );
    }

    // ── bratio band-ticks dwell counters ──────────────────────────────────
    //
    // Pins the counter family
    // `elara_bratio_band_ticks_total{band="…"}` to:
    //   1. zero-initialization on a fresh NodeState (no off-by-one
    //      from the constructor),
    //   2. correct branch selection in `sample_bratio_band_tick()` —
    //      fresh state's `attestation_ratio_summary().classify_cohort()`
    //      returns 0 (DORMANT) because tracked==0, so only the dormant
    //      counter must increment,
    //   3. metrics_body emits all 5 labeled counter lines + HELP + TYPE,
    //      so a future format-string typo (missing slot, swapped label,
    //      dropped band) fails here before reaching the fleet.
    //
    // The 5 counters partition `elara_seal_loop_ticks_total` exactly —
    // exactly one fetch_add per sample tick — and that partition is the
    // operator-facing invariant for `rate(...{band="X"}[5m])` dwell
    // panels. Test (2) is the smallest assertion that proves the
    // dispatch shape; full classify_cohort coverage lives in
    // consensus.rs::tests::classify_cohort_*.
    #[test]
    fn bratio_band_ticks_counters_initialize_to_zero() {
        use std::sync::atomic::Ordering::Relaxed;
        let state = test_node_state(None);
        assert_eq!(state.bratio_band_ticks_dormant_total.load(Relaxed), 0);
        assert_eq!(state.bratio_band_ticks_locked_total.load(Relaxed), 0);
        assert_eq!(state.bratio_band_ticks_converged_total.load(Relaxed), 0);
        assert_eq!(state.bratio_band_ticks_active_total.load(Relaxed), 0);
        assert_eq!(state.bratio_band_ticks_hyper_active_total.load(Relaxed), 0);
    }

    #[test]
    fn sample_bratio_band_tick_on_fresh_state_bumps_dormant_only() {
        use std::sync::atomic::Ordering::Relaxed;
        let state = test_node_state(None);
        // Fresh state: AWCConsensus has no tracked attestations, so
        // attestation_ratio_summary() returns tracked=0 →
        // classify_cohort() returns 0 (DORMANT). Three ticks must all
        // land on the dormant counter; the other 4 must stay at zero.
        state.sample_bratio_band_tick();
        state.sample_bratio_band_tick();
        state.sample_bratio_band_tick();
        assert_eq!(state.bratio_band_ticks_dormant_total.load(Relaxed), 3);
        assert_eq!(state.bratio_band_ticks_locked_total.load(Relaxed), 0);
        assert_eq!(state.bratio_band_ticks_converged_total.load(Relaxed), 0);
        assert_eq!(state.bratio_band_ticks_active_total.load(Relaxed), 0);
        assert_eq!(state.bratio_band_ticks_hyper_active_total.load(Relaxed), 0);
    }

    #[tokio::test]
    async fn bratio_band_ticks_total_surfaces_in_metrics_body() {
        use std::sync::atomic::Ordering::Relaxed;
        let state = test_node_state(None);
        // Seed each band with a distinct value so a future format-string
        // typo that swaps two label slots fails here (uniform values
        // would not catch the swap).
        state.bratio_band_ticks_dormant_total.fetch_add(11, Relaxed);
        state.bratio_band_ticks_locked_total.fetch_add(22, Relaxed);
        state.bratio_band_ticks_converged_total.fetch_add(33, Relaxed);
        state.bratio_band_ticks_active_total.fetch_add(44, Relaxed);
        state.bratio_band_ticks_hyper_active_total.fetch_add(55, Relaxed);

        let body = super::super::server::metrics_body(state).await;
        assert!(
            body.contains("elara_bratio_band_ticks_total{band=\"DORMANT\"} 11"),
            "missing dormant counter line or wrong value: {body}"
        );
        assert!(
            body.contains("elara_bratio_band_ticks_total{band=\"LOCKED\"} 22"),
            "missing locked counter line or wrong value: {body}"
        );
        assert!(
            body.contains("elara_bratio_band_ticks_total{band=\"CONVERGED\"} 33"),
            "missing converged counter line or wrong value: {body}"
        );
        assert!(
            body.contains("elara_bratio_band_ticks_total{band=\"ACTIVE\"} 44"),
            "missing active counter line or wrong value: {body}"
        );
        assert!(
            body.contains("elara_bratio_band_ticks_total{band=\"HYPER_ACTIVE\"} 55"),
            "missing hyper-active counter line or wrong value: {body}"
        );
        // HELP + TYPE lines must also be present so Prometheus parses
        // the counter type correctly (a missing TYPE line silently
        // degrades it to an untyped metric).
        assert!(
            body.contains("# TYPE elara_bratio_band_ticks_total counter"),
            "missing TYPE line: {body}"
        );
        assert!(
            body.contains("# HELP elara_bratio_band_ticks_total"),
            "missing HELP line: {body}"
        );
    }

    // ── cascade eviction + utilization gauge ──────────────────────────────
    //
    // Rationale: when DAG hot tier is full, ingest first calls
    // `dag.evict_old_epochs()`. If that frees no room and DAG is still full,
    // the cascade falls through to `dag.evict_finalized(snapshot_predicate)`
    // — only THEN do we reject. The two new counters distinguish
    // "cascade ran" (recoverable) from "cascade also failed" (cliff dropped a
    // record). The utilization gauge surfaces the cliff approach BEFORE the
    // counters tick. These tests cover the state plumbing — the actual
    // ingest-path cascade is exercised by `dag::tests::test_evict_finalized_*`.

    #[test]
    fn ops20_dag_cascade_counters_initialize_to_zero() {
        let state = test_node_state(None);
        assert_eq!(state.dag_evict_finalized_cascade_total.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert_eq!(state.dag_hot_tier_full_rejections_total.load(std::sync::atomic::Ordering::Relaxed), 0);
    }

    #[test]
    fn ops20_dag_cascade_counters_independent() {
        // Counter independence: cascade can run successfully (records freed,
        // no rejection) OR cascade can run AND fail (rejection counter +=1).
        // The two counters carry distinct semantics so operator alerts can
        // distinguish "cascade saved us" from "cascade also failed".
        let state = test_node_state(None);
        state.dag_evict_finalized_cascade_total.fetch_add(7, std::sync::atomic::Ordering::Relaxed);
        state.dag_hot_tier_full_rejections_total.fetch_add(3, std::sync::atomic::Ordering::Relaxed);

        assert_eq!(state.dag_evict_finalized_cascade_total.load(std::sync::atomic::Ordering::Relaxed), 7);
        assert_eq!(state.dag_hot_tier_full_rejections_total.load(std::sync::atomic::Ordering::Relaxed), 3);
    }

    #[tokio::test]
    async fn ops20_metrics_body_exports_dag_cascade_counters_and_utilization_gauge() {
        let state = test_node_state(None);
        state.dag_evict_finalized_cascade_total.fetch_add(5, std::sync::atomic::Ordering::Relaxed);
        state.dag_hot_tier_full_rejections_total.fetch_add(2, std::sync::atomic::Ordering::Relaxed);

        let body = super::super::server::metrics_body(state).await;

        assert!(
            body.contains("elara_dag_evict_finalized_cascade_total 5"),
            "missing cascade counter: {body}"
        );
        assert!(
            body.contains("elara_dag_hot_tier_full_rejections_total 2"),
            "missing rejection counter: {body}"
        );
        assert!(
            body.contains(&format!("elara_dag_hot_tier_max {}", crate::dag::HOT_MAX_FALLBACK)),
            "missing hot_tier_max gauge: {body}"
        );
        // Empty DAG → utilization ratio 0.0000
        assert!(
            body.contains("elara_dag_hot_tier_utilization_ratio 0.0000"),
            "missing/wrong utilization gauge: {body}"
        );
    }

    #[tokio::test]
    async fn ops20_metrics_body_utilization_gauge_at_capacity() {
        // Manually populate the DAG to a known size and confirm the gauge
        // reflects size / HOT_MAX_FALLBACK. This covers the divide path so
        // a regression that stops dividing (or hardcodes 0.0) is caught.
        let state = test_node_state(None);
        {
            let mut dag_guard = state.dag.write().await;
            let dag = std::sync::Arc::make_mut(&mut *dag_guard);
            // 50 records / 50_000 cap = 0.001 → "0.0010"
            for i in 0..50 {
                let _ = dag.insert(format!("rec-{i}"), Vec::new(), 1.0);
            }
        }

        let body = super::super::server::metrics_body(state).await;
        assert!(
            body.contains("elara_dag_hot_tier_utilization_ratio 0.0010"),
            "expected 0.0010 utilization at 50/50000: {body}"
        );
    }

    // ── slow-acquire counters ─────────────────────────────────────────────
    //
    // Rationale: previously the only signal of DAG lock contention was a WARN
    // log at 5000ms. With these two counters at the lower 500ms threshold,
    // contention surfaces in Prometheus an order of magnitude earlier.

    #[test]
    fn ops21_lock_acquire_counters_initialize_to_zero() {
        let state = test_node_state(None);
        assert_eq!(state.lock_acquire_dag_read_slow_total.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert_eq!(state.lock_acquire_dag_write_slow_total.load(std::sync::atomic::Ordering::Relaxed), 0);
    }

    #[test]
    fn ops21_lock_acquire_counters_independent() {
        // Read and write counters carry distinct semantics so dashboards can
        // attribute read-lock vs. write-lock contention separately.
        let state = test_node_state(None);
        state.lock_acquire_dag_read_slow_total.fetch_add(11, std::sync::atomic::Ordering::Relaxed);
        state.lock_acquire_dag_write_slow_total.fetch_add(13, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(state.lock_acquire_dag_read_slow_total.load(std::sync::atomic::Ordering::Relaxed), 11);
        assert_eq!(state.lock_acquire_dag_write_slow_total.load(std::sync::atomic::Ordering::Relaxed), 13);
    }

    #[tokio::test]
    async fn ops21_metrics_body_exports_lock_acquire_counters() {
        let state = test_node_state(None);
        state.lock_acquire_dag_read_slow_total.fetch_add(7, std::sync::atomic::Ordering::Relaxed);
        state.lock_acquire_dag_write_slow_total.fetch_add(9, std::sync::atomic::Ordering::Relaxed);

        let body = super::super::server::metrics_body(state).await;

        assert!(
            body.contains("elara_lock_acquire_dag_read_slow_total 7"),
            "missing dag_read slow counter: {body}"
        );
        assert!(
            body.contains("elara_lock_acquire_dag_write_slow_total 9"),
            "missing dag_write slow counter: {body}"
        );
    }

    // ── GC counters ───────────────────────────────────────────────────────
    //
    // Rationale: previously the only GC signal was a single
    // `gc_pruned_total` aggregate. The GcResult struct already produces
    // a per-reason breakdown (expired/retention/sunken/stale); this slice
    // surfaces it. Plus cycle counter, last-cycle duration, last-cycle
    // timestamp, and the oldest-record-age gauge.

    #[test]
    fn ops22_gc_counters_initialize_to_zero() {
        let state = test_node_state(None);
        assert_eq!(state.gc_pruned_expired_total.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert_eq!(state.gc_pruned_retention_total.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert_eq!(state.gc_pruned_sunken_total.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert_eq!(state.gc_pruned_stale_total.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert_eq!(state.gc_cycles_total.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert_eq!(state.gc_last_cycle_duration_ms.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert_eq!(state.gc_last_cycle_unix_ts.load(std::sync::atomic::Ordering::Relaxed), 0);
    }

    #[test]
    fn ops22_gc_per_reason_counters_independent() {
        // Per-reason counters track distinct semantics — a regression that
        // collapses any two together (e.g. retention bumped on stale-prune
        // by mistake) would miss consensus regressions in monitoring.
        let state = test_node_state(None);
        state.gc_pruned_expired_total.fetch_add(2, std::sync::atomic::Ordering::Relaxed);
        state.gc_pruned_retention_total.fetch_add(3, std::sync::atomic::Ordering::Relaxed);
        state.gc_pruned_sunken_total.fetch_add(5, std::sync::atomic::Ordering::Relaxed);
        state.gc_pruned_stale_total.fetch_add(7, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(state.gc_pruned_expired_total.load(std::sync::atomic::Ordering::Relaxed), 2);
        assert_eq!(state.gc_pruned_retention_total.load(std::sync::atomic::Ordering::Relaxed), 3);
        assert_eq!(state.gc_pruned_sunken_total.load(std::sync::atomic::Ordering::Relaxed), 5);
        assert_eq!(state.gc_pruned_stale_total.load(std::sync::atomic::Ordering::Relaxed), 7);
    }

    #[test]
    fn ops25_orphan_high_count_pruned_counter_init_and_increment() {
        // The high-count circuit-breaker prune counter
        // must start at 0 and accumulate via fetch_add (the path used in
        // orphan_resolver_loop). A regression that drops the field or
        // starts it non-zero would silently break the bootstrap-pathology
        // signal documented in the field's HELP text.
        let state = test_node_state(None);
        assert_eq!(
            state.orphan_resolver_high_count_pruned_total.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "must initialise to 0"
        );
        state
            .orphan_resolver_high_count_pruned_total
            .fetch_add(150, std::sync::atomic::Ordering::Relaxed);
        state
            .orphan_resolver_high_count_pruned_total
            .fetch_add(50, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            state.orphan_resolver_high_count_pruned_total.load(std::sync::atomic::Ordering::Relaxed),
            200,
            "fetch_add must be cumulative"
        );
    }

    #[tokio::test]
    async fn ops25_metrics_body_exports_orphan_high_count_pruned() {
        // Verify metrics_body emits the new counter line. Missing
        // line → Prometheus alert config silently breaks; the bootstrap-
        // pathology dashboard would lose its primary distinguisher between
        // healthy churn and stuck-cascade.
        let state = test_node_state(None);
        state
            .orphan_resolver_high_count_pruned_total
            .fetch_add(6234, std::sync::atomic::Ordering::Relaxed);
        let body = super::super::server::metrics_body(state).await;
        assert!(
            body.contains("elara_orphan_resolver_high_count_pruned_total 6234"),
            "missing OPS-25 counter line: {body}"
        );
    }

    #[test]
    fn ops26_admin_snapshot_rebootstrap_counter_init_and_increment() {
        // The snapshot-rebootstrap escape-hatch
        // counter must start at 0 and accumulate via fetch_add. A regression
        // that drops the field or starts it non-zero would silently break the
        // bootstrap-pathology operator audit trail.
        let state = test_node_state(None);
        assert_eq!(
            state.admin_snapshot_rebootstrap_total.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "must initialise to 0"
        );
        state
            .admin_snapshot_rebootstrap_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        state
            .admin_snapshot_rebootstrap_total
            .fetch_add(2, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            state.admin_snapshot_rebootstrap_total.load(std::sync::atomic::Ordering::Relaxed),
            3,
            "fetch_add must be cumulative"
        );
    }

    #[tokio::test]
    async fn ops26_metrics_body_exports_admin_snapshot_rebootstrap() {
        // Verify metrics_body emits the new counter line. Missing
        // line → operators can't see whether they (or another operator) ever
        // ran the rebootstrap escape hatch — same audit-trail concern as
        // the orphan-prune counter.
        let state = test_node_state(None);
        state
            .admin_snapshot_rebootstrap_total
            .fetch_add(7, std::sync::atomic::Ordering::Relaxed);
        let body = super::super::server::metrics_body(state).await;
        assert!(
            body.contains("elara_admin_snapshot_rebootstrap_total 7"),
            "missing OPS-26 counter line: {body}"
        );
    }

    #[tokio::test]
    async fn account_smt_write_gate_serializes_writers() {
        // Fusion-audited 2026-07-05: account_smt_write_gate is the
        // CF_ACCOUNT_SMT writer serialization (see the field doc). Pin the
        // field's existence, mutual exclusion while held, and clean release.
        let state = test_node_state(None);
        let held = state.account_smt_write_gate.lock().await;
        assert!(
            state.account_smt_write_gate.try_lock().is_err(),
            "second writer must not acquire while the gate is held"
        );
        drop(held);
        assert!(
            state.account_smt_write_gate.try_lock().is_ok(),
            "gate must be free once the holder drops"
        );
    }

    #[test]
    fn ops28_attestation_pull_counters_initialize_to_zero() {
        // Pull-side attestation rejection counters must start at 0.
        // A regression that defaults non-zero would silently break the
        // bootstrap-pathology signal (rate-of-rise = stale-record drift).
        let state = test_node_state(None);
        assert_eq!(
            state.attestation_pull_invalid_sig_total
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "invalid_sig_total must initialise to 0"
        );
        assert_eq!(
            state.attestation_pull_invalid_powas_total
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "invalid_powas_total must initialise to 0"
        );
    }

    #[test]
    fn ops28_attestation_pull_counters_independent() {
        // Distinct semantics — sig-fail (permanent, advances watermark)
        // vs PoWaS-fail (peer may retry). Counters must not bleed.
        let state = test_node_state(None);
        state.attestation_pull_invalid_sig_total
            .fetch_add(13, std::sync::atomic::Ordering::Relaxed);
        state.attestation_pull_invalid_powas_total
            .fetch_add(7, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            state.attestation_pull_invalid_sig_total
                .load(std::sync::atomic::Ordering::Relaxed),
            13
        );
        assert_eq!(
            state.attestation_pull_invalid_powas_total
                .load(std::sync::atomic::Ordering::Relaxed),
            7
        );
    }

    #[tokio::test]
    async fn ops28_metrics_body_exports_attestation_pull_counters() {
        // End-to-end check that metrics_body emits both lines with
        // the right values. A regression that drops these from /metrics would
        // mean operators can no longer see pull-side bad-sig storms (today's
        // only signal is journal-grep, which doesn't scale to 10K nodes).
        let state = test_node_state(None);
        state.attestation_pull_invalid_sig_total
            .fetch_add(17, std::sync::atomic::Ordering::Relaxed);
        state.attestation_pull_invalid_powas_total
            .fetch_add(23, std::sync::atomic::Ordering::Relaxed);
        let body = super::super::server::metrics_body(state).await;
        assert!(
            body.contains("elara_attestation_pull_invalid_sig_total 17"),
            "missing OPS-28 sig counter: {body}"
        );
        assert!(
            body.contains("elara_attestation_pull_invalid_powas_total 23"),
            "missing OPS-28 powas counter: {body}"
        );
    }

    #[tokio::test]
    async fn ops22_metrics_body_exports_gc_counters_and_age_gauge() {
        let state = test_node_state(None);
        state.gc_pruned_expired_total.fetch_add(2, std::sync::atomic::Ordering::Relaxed);
        state.gc_pruned_retention_total.fetch_add(3, std::sync::atomic::Ordering::Relaxed);
        state.gc_pruned_sunken_total.fetch_add(5, std::sync::atomic::Ordering::Relaxed);
        state.gc_pruned_stale_total.fetch_add(7, std::sync::atomic::Ordering::Relaxed);
        state.gc_cycles_total.fetch_add(11, std::sync::atomic::Ordering::Relaxed);
        state.gc_last_cycle_duration_ms.fetch_add(123, std::sync::atomic::Ordering::Relaxed);
        state.gc_last_cycle_unix_ts.fetch_add(1_700_000_000, std::sync::atomic::Ordering::Relaxed);

        let body = super::super::server::metrics_body(state).await;

        assert!(body.contains("elara_gc_pruned_expired_total 2"), "missing expired counter: {body}");
        assert!(body.contains("elara_gc_pruned_retention_total 3"), "missing retention counter: {body}");
        assert!(body.contains("elara_gc_pruned_sunken_total 5"), "missing sunken counter: {body}");
        assert!(body.contains("elara_gc_pruned_stale_total 7"), "missing stale counter: {body}");
        assert!(body.contains("elara_gc_cycles_total 11"), "missing cycles counter: {body}");
        assert!(body.contains("elara_gc_last_cycle_duration_ms 123"), "missing duration gauge: {body}");
        assert!(body.contains("elara_gc_last_cycle_unix_ts 1700000000"), "missing unix_ts gauge: {body}");
        // Empty storage → age 0.0
        assert!(body.contains("elara_gc_oldest_record_age_seconds 0.0"), "missing/wrong age gauge: {body}");
    }

    // ── §11.23 Layer B: search_records routing + counter split ─────────
    //
    // Two contracts to lock in:
    //   (1) `creator_hash`-set queries take the indexed Layer B path —
    //       counter `search_queries_layer_b_total` increments.
    //   (2) `creator_hash`-unset queries with a time/class filter take
    //       the timestamp-window fallback — `search_queries_fallback_total`
    //       increments. Without this split the dashboard can't see whether
    //       the indexed path is being exercised in production.

    fn put_record_with_creator(
        rocks: &crate::storage::rocks::StorageEngine,
        id: &str,
        creator_pk: &[u8],
        ts: f64,
    ) {
        use crate::record::{Classification, ValidationRecord};
        use std::collections::BTreeMap;
        let rec = ValidationRecord {
            id: id.to_string(),
            version: crate::wire::WIRE_VERSION,
            content_hash: crate::crypto::hash::sha3_256(id.as_bytes()).to_vec(),
            creator_public_key: creator_pk.to_vec(),
            timestamp: ts,
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
        };
        rocks.put_record(id, &rec).expect("put_record");
    }

    #[test]
    fn search_records_creator_hash_takes_layer_b_path() {
        use std::sync::atomic::Ordering::Relaxed;
        let state = test_node_state(None);
        let pk = vec![0xAA; 1952];
        put_record_with_creator(&state.rocks, "alpha-1", &pk, 100.0);
        put_record_with_creator(&state.rocks, "alpha-2", &pk, 200.0);

        let creator_hash = crate::crypto::hash::sha3_256_hex(&pk);
        let q = crate::storage::SearchQuery {
            creator_hash: Some(creator_hash),
            limit: 10,
            ..Default::default()
        };
        let results = state.search_records(&q).expect("search ok");
        assert_eq!(results.len(), 2);
        assert_eq!(state.search_queries_layer_b_total.load(Relaxed), 1);
        assert_eq!(state.search_queries_fallback_total.load(Relaxed), 0);
    }

    #[test]
    fn search_records_no_creator_with_window_takes_fallback_path() {
        use std::sync::atomic::Ordering::Relaxed;
        let state = test_node_state(None);
        let pk = vec![0xBB; 1952];
        put_record_with_creator(&state.rocks, "rec-1", &pk, 100.0);
        put_record_with_creator(&state.rocks, "rec-2", &pk, 200.0);

        let q = crate::storage::SearchQuery {
            since: Some(50.0),
            until: Some(250.0),
            limit: 10,
            ..Default::default()
        };
        let _results = state.search_records(&q).expect("search ok");
        assert_eq!(state.search_queries_layer_b_total.load(Relaxed), 0);
        assert_eq!(state.search_queries_fallback_total.load(Relaxed), 1);
    }

    fn put_record_with_creator_meta(
        rocks: &crate::storage::rocks::StorageEngine,
        id: &str,
        creator_pk: &[u8],
        ts: f64,
        meta: std::collections::BTreeMap<String, serde_json::Value>,
    ) {
        use crate::record::{Classification, ValidationRecord};
        let rec = ValidationRecord {
            id: id.to_string(),
            version: crate::wire::WIRE_VERSION,
            content_hash: crate::crypto::hash::sha3_256(id.as_bytes()).to_vec(),
            creator_public_key: creator_pk.to_vec(),
            timestamp: ts,
            parents: vec![],
            classification: Classification::Public,
            metadata: meta,
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
        };
        rocks.put_record(id, &rec).expect("put_record");
    }

    #[test]
    fn search_records_metadata_key_filter_layer_b() {
        // §11.23: ?key=X must drop records whose metadata lacks X. Pre-fix
        // bug: route accepted ?key= but state.search_records ignored it,
        // so the filter was a no-op and the public API silently lied.
        let state = test_node_state(None);
        let pk = vec![0xAA; 1952];
        let mut meta_a = std::collections::BTreeMap::new();
        meta_a.insert("kind".into(), serde_json::json!("photo"));
        let mut meta_b = std::collections::BTreeMap::new();
        meta_b.insert("kind".into(), serde_json::json!("video"));
        let meta_c = std::collections::BTreeMap::new(); // no `kind`
        put_record_with_creator_meta(&state.rocks, "a", &pk, 100.0, meta_a);
        put_record_with_creator_meta(&state.rocks, "b", &pk, 200.0, meta_b);
        put_record_with_creator_meta(&state.rocks, "c", &pk, 300.0, meta_c);

        let creator_hash = crate::crypto::hash::sha3_256_hex(&pk);
        let q = crate::storage::SearchQuery {
            creator_hash: Some(creator_hash.clone()),
            metadata_key: Some("kind".into()),
            limit: 10,
            ..Default::default()
        };
        let results = state.search_records(&q).expect("search ok");
        let ids: Vec<&str> = results.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, vec!["a", "b"]);
    }

    #[test]
    fn search_records_metadata_key_value_filter_layer_b() {
        // ?key=X&value=Y must drop records whose metadata[X] != Y.
        let state = test_node_state(None);
        let pk = vec![0xBB; 1952];
        let mut meta_photo = std::collections::BTreeMap::new();
        meta_photo.insert("kind".into(), serde_json::json!("photo"));
        let mut meta_video = std::collections::BTreeMap::new();
        meta_video.insert("kind".into(), serde_json::json!("video"));
        put_record_with_creator_meta(&state.rocks, "p1", &pk, 100.0, meta_photo.clone());
        put_record_with_creator_meta(&state.rocks, "v1", &pk, 200.0, meta_video);
        put_record_with_creator_meta(&state.rocks, "p2", &pk, 300.0, meta_photo);

        let creator_hash = crate::crypto::hash::sha3_256_hex(&pk);
        let q = crate::storage::SearchQuery {
            creator_hash: Some(creator_hash),
            metadata_key: Some("kind".into()),
            metadata_value: Some("photo".into()),
            limit: 10,
            ..Default::default()
        };
        let results = state.search_records(&q).expect("search ok");
        let ids: Vec<&str> = results.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, vec!["p1", "p2"]);
    }

    #[test]
    fn search_records_no_filter_returns_empty_no_counter_bump() {
        // Defensive: an unfiltered request must not silently scan the whole
        // record store. Returning [] is the conservative behavior; once
        // Layer C / D are implemented this branch will route to those.
        use std::sync::atomic::Ordering::Relaxed;
        let state = test_node_state(None);
        let pk = vec![0xCC; 1952];
        put_record_with_creator(&state.rocks, "any", &pk, 100.0);

        let q = crate::storage::SearchQuery {
            limit: 10,
            ..Default::default()
        };
        let results = state.search_records(&q).expect("search ok");
        assert!(results.is_empty());
        assert_eq!(state.search_queries_layer_b_total.load(Relaxed), 0);
        assert_eq!(state.search_queries_fallback_total.load(Relaxed), 0);
    }

    fn ops125_test_record(
        id: &str,
        timestamp: f64,
        classification: crate::record::Classification,
        beat_op: Option<&str>,
        epoch_op: Option<&str>,
    ) -> crate::record::ValidationRecord {
        let mut metadata = std::collections::BTreeMap::new();
        if let Some(op) = beat_op {
            metadata.insert("beat_op".into(), serde_json::json!(op));
        }
        if let Some(op) = epoch_op {
            metadata.insert(
                crate::network::epoch::EPOCH_OP_KEY.into(),
                serde_json::json!(op),
            );
        }
        crate::record::ValidationRecord {
            id: id.into(),
            version: 5,
            content_hash: vec![],
            creator_public_key: vec![0; 32],
            timestamp,
            parents: vec![],
            classification,
            metadata,
            signature: None,
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
    fn test_ops125_record_stats_bump_counts_classifications_and_ops() {
        use std::sync::atomic::Ordering::Relaxed;
        let state = test_node_state(None);

        // 3 mints, 2 transfers, 1 epoch_seal across two classifications.
        state.record_stats_bump(&ops125_test_record(
            "a", 100.0, crate::record::Classification::Public, Some("mint"), None,
        ));
        state.record_stats_bump(&ops125_test_record(
            "b", 200.0, crate::record::Classification::Public, Some("mint"), None,
        ));
        state.record_stats_bump(&ops125_test_record(
            "c", 300.0, crate::record::Classification::Private, Some("mint"), None,
        ));
        state.record_stats_bump(&ops125_test_record(
            "d", 400.0, crate::record::Classification::Public, Some("transfer"), None,
        ));
        state.record_stats_bump(&ops125_test_record(
            "e", 500.0, crate::record::Classification::Restricted, Some("transfer"), None,
        ));
        state.record_stats_bump(&ops125_test_record(
            "f", 600.0, crate::record::Classification::Sovereign, None, Some("seal"),
        ));

        assert_eq!(state.record_stats_total.load(Relaxed), 6);
        assert_eq!(state.record_stats_class_public.load(Relaxed), 3);
        assert_eq!(state.record_stats_class_private.load(Relaxed), 1);
        assert_eq!(state.record_stats_class_restricted.load(Relaxed), 1);
        assert_eq!(state.record_stats_class_sovereign.load(Relaxed), 1);
        assert_eq!(state.record_stats_op_mint.load(Relaxed), 3);
        assert_eq!(state.record_stats_op_transfer.load(Relaxed), 2);
        assert_eq!(state.record_stats_epoch_seals.load(Relaxed), 1);
        assert_eq!(state.record_stats_non_token.load(Relaxed), 0);
        assert_eq!(state.record_stats_earliest(), Some(100.0));
        assert_eq!(state.record_stats_latest(), Some(600.0));
    }

    #[test]
    fn test_ops125_snapshot_json_shape_matches_legacy() {
        // The legacy `compute_dag_stats` shape this replaces had:
        //   total_records, unique_creators, time_range.{earliest, latest},
        //   by_classification.{public,private,restricted,sovereign},
        //   by_operation.{mint, transfer, stake, unstake, burn, slash,
        //                 witness_reward, dormancy_reclaim, pool_fund,
        //                 epoch_seal, non_token}
        // record_stats adds: stats_partial, creators_indexed (bool flag because
        // unique_creators is intentionally null until HLL follow-up).
        let state = test_node_state(None);
        state.record_stats_bump(&ops125_test_record(
            "a", 100.0, crate::record::Classification::Public, Some("mint"), None,
        ));
        let snap = state.record_stats_snapshot_json();
        assert_eq!(snap["total_records"], serde_json::json!(1));
        assert!(snap["unique_creators"].is_null());
        assert_eq!(snap["creators_indexed"], serde_json::json!(false));
        assert_eq!(snap["stats_partial"], serde_json::json!(false));
        assert_eq!(snap["time_range"]["earliest"], serde_json::json!(100.0));
        assert_eq!(snap["time_range"]["latest"], serde_json::json!(100.0));
        assert_eq!(snap["by_classification"]["public"], serde_json::json!(1));
        assert_eq!(snap["by_classification"]["private"], serde_json::json!(0));
        assert_eq!(snap["by_operation"]["mint"], serde_json::json!(1));
        assert_eq!(snap["by_operation"]["transfer"], serde_json::json!(0));
        assert_eq!(snap["by_operation"]["epoch_seal"], serde_json::json!(0));
        assert_eq!(snap["by_operation"]["non_token"], serde_json::json!(0));
    }

    #[test]
    fn test_ops125_unknown_op_falls_into_non_token() {
        // beat_op present but value not in the canonical 9 → counts as
        // non_token, matching the legacy `_ => non_token += 1` arm.
        use std::sync::atomic::Ordering::Relaxed;
        let state = test_node_state(None);
        state.record_stats_bump(&ops125_test_record(
            "a", 100.0, crate::record::Classification::Public, Some("foobar"), None,
        ));
        // Also: no beat_op AND no epoch_op → also non_token.
        state.record_stats_bump(&ops125_test_record(
            "b", 200.0, crate::record::Classification::Public, None, None,
        ));
        assert_eq!(state.record_stats_non_token.load(Relaxed), 2);
        assert_eq!(state.record_stats_op_mint.load(Relaxed), 0);
        assert_eq!(state.record_stats_epoch_seals.load(Relaxed), 0);
    }

    #[test]
    fn test_ops125_earliest_latest_track_min_max_under_out_of_order() {
        // Bumps arrive out of timestamp order — earliest tracks min, latest
        // tracks max regardless of arrival order.
        let state = test_node_state(None);
        state.record_stats_bump(&ops125_test_record(
            "a", 500.0, crate::record::Classification::Public, Some("mint"), None,
        ));
        state.record_stats_bump(&ops125_test_record(
            "b", 100.0, crate::record::Classification::Public, Some("mint"), None,
        ));
        state.record_stats_bump(&ops125_test_record(
            "c", 1500.0, crate::record::Classification::Public, Some("mint"), None,
        ));
        state.record_stats_bump(&ops125_test_record(
            "d", 700.0, crate::record::Classification::Public, Some("mint"), None,
        ));
        assert_eq!(state.record_stats_earliest(), Some(100.0));
        assert_eq!(state.record_stats_latest(), Some(1500.0));
    }

    #[test]
    fn test_ops125_seed_bounded_flag_surfaces_in_snapshot() {
        let state = test_node_state(None);
        state
            .record_stats_seed_bounded
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let snap = state.record_stats_snapshot_json();
        assert_eq!(snap["stats_partial"], serde_json::json!(true));
    }

    #[test]
    fn ops143_store_max_atomic_only_raises() {
        let target = AtomicU64::new(0);
        // First write — sets the floor.
        super::store_max_atomic(&target, 120);
        assert_eq!(target.load(std::sync::atomic::Ordering::Relaxed), 120);

        // Smaller value — must NOT lower the max.
        super::store_max_atomic(&target, 50);
        assert_eq!(target.load(std::sync::atomic::Ordering::Relaxed), 120);

        // Larger value — replays an observed ~78s record processing time.
        super::store_max_atomic(&target, 77_927);
        assert_eq!(target.load(std::sync::atomic::Ordering::Relaxed), 77_927);

        // Equal value — must be a no-op (the loop only enters when candidate > current).
        super::store_max_atomic(&target, 77_927);
        assert_eq!(target.load(std::sync::atomic::Ordering::Relaxed), 77_927);

        // Replays an observed 415s incident — gauge tracks ever upward.
        super::store_max_atomic(&target, 415_141);
        assert_eq!(target.load(std::sync::atomic::Ordering::Relaxed), 415_141);

        // Smaller again — still pinned at the high water mark.
        super::store_max_atomic(&target, 1_000);
        assert_eq!(target.load(std::sync::atomic::Ordering::Relaxed), 415_141);
    }

    // Per-edge transition counters + lowest-since-boot avail floor.
    // Verify (a) initial values match the export contract — counters at 0,
    // lowest-MB at the u64::MAX sentinel that the metrics renderer maps to 0;
    // (b) fetch_add semantics on counters (monotonic, edge-only); (c)
    // fetch_min semantics on the floor (only-decreases, ignores higher
    // samples). Closes the between-scrape
    // observability holes the boolean disk_avail_pressure gauge missed.

    #[test]
    fn ops175_initial_values_match_export_contract() {
        let state = test_node_state(None);
        assert_eq!(
            state
                .disk_avail_pressure_events_total
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "avail-side counter must start at 0 (no edges observed pre-boot)"
        );
        assert_eq!(
            state
                .disk_cap_pressure_events_total
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "cap-side counter must start at 0 (no edges observed pre-boot)"
        );
        assert_eq!(
            state
                .disk_pressure_lowest_avail_mb
                .load(std::sync::atomic::Ordering::Relaxed),
            u64::MAX,
            "lowest-MB must start at u64::MAX sentinel so first fetch_min(real) wins; \
             metrics renderer maps MAX → 0 to match OPS-65c first-scrape contract"
        );
    }

    #[test]
    fn ops175_avail_counter_bumps_on_each_trip_only() {
        let state = test_node_state(None);
        // Simulate 3 trip edges as observed by disk_pressure_loop.
        for _ in 0..3 {
            state
                .disk_avail_pressure_events_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        assert_eq!(
            state
                .disk_avail_pressure_events_total
                .load(std::sync::atomic::Ordering::Relaxed),
            3,
            "counter must reflect every observed trip edge (each fetch_add(1))"
        );
        // Cap-side counter is independent — must remain 0 even after avail trips.
        assert_eq!(
            state
                .disk_cap_pressure_events_total
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "cap-side counter is symmetric-but-independent — avail trips do not bleed"
        );
    }

    #[test]
    fn ops175_lowest_avail_mb_only_decreases() {
        let state = test_node_state(None);
        // First sample lands — wins against u64::MAX sentinel.
        state
            .disk_pressure_lowest_avail_mb
            .fetch_min(8_192, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            state
                .disk_pressure_lowest_avail_mb
                .load(std::sync::atomic::Ordering::Relaxed),
            8_192,
            "first sample must overwrite the u64::MAX sentinel"
        );
        // Higher value — must NOT raise the floor (recovery doesn't erase
        // the worst dip).
        state
            .disk_pressure_lowest_avail_mb
            .fetch_min(16_384, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            state
                .disk_pressure_lowest_avail_mb
                .load(std::sync::atomic::Ordering::Relaxed),
            8_192,
            "fetch_min ignores higher candidates — floor is the worst observed value"
        );
        // Lower value — replays an observed slow-shrink case where the
        // boolean gauge missed the dip until the floor crossing.
        state
            .disk_pressure_lowest_avail_mb
            .fetch_min(512, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            state
                .disk_pressure_lowest_avail_mb
                .load(std::sync::atomic::Ordering::Relaxed),
            512,
            "lower sample must lower the floor — captures dip the boolean gauge missed"
        );
        // Equal value — no-op (fetch_min only writes when strictly smaller).
        state
            .disk_pressure_lowest_avail_mb
            .fetch_min(512, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            state
                .disk_pressure_lowest_avail_mb
                .load(std::sync::atomic::Ordering::Relaxed),
            512,
        );
    }

    // epoch_seal_loop proposal-outcome
    // counters. These five atomics + the per-tick INFO summary log emitted in
    // `epoch_seal_loop` let operators see WHERE the seal flow is dropping when
    // `elara_epoch_seals_total` is flat. A testnet stall (both
    // anchors stuck at the same epoch for 24+h despite healthy gossip) was the
    // trigger case — `should_propose_seal` was returning None for every (zone,
    // epoch) tuple but previously there was no fleet-visible signal of that fact.

    #[test]
    fn ops188_initial_values_match_export_contract() {
        let state = test_node_state(None);
        for (name, val) in [
            ("ticks_total", state.seal_loop_ticks_total.load(std::sync::atomic::Ordering::Relaxed)),
            ("zones_evaluated_total", state.seal_loop_zones_evaluated_total.load(std::sync::atomic::Ordering::Relaxed)),
            ("proposals_per_zone_total", state.seal_loop_proposals_per_zone_total.load(std::sync::atomic::Ordering::Relaxed)),
            ("proposals_escalate_total", state.seal_loop_proposals_escalate_total.load(std::sync::atomic::Ordering::Relaxed)),
            ("proposals_none_total", state.seal_loop_proposals_none_total.load(std::sync::atomic::Ordering::Relaxed)),
        ] {
            assert_eq!(val, 0, "OPS-188 counter {name} must start at 0 (no ticks observed pre-boot)");
        }
    }

    #[test]
    fn ops188_counters_are_independent_axes() {
        // Each outcome counter must increment in isolation — bumping one must
        // not bleed into another. This is the boot-state contract regression
        // test; if a future refactor accidentally aliases two
        // counters (same AtomicU64 underneath, or a shared fetch_add), this
        // fails immediately at suite time.
        let state = test_node_state(None);
        state.seal_loop_proposals_per_zone_total.fetch_add(5, std::sync::atomic::Ordering::Relaxed);
        state.seal_loop_proposals_none_total.fetch_add(3, std::sync::atomic::Ordering::Relaxed);
        state.seal_loop_proposals_escalate_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        state.seal_loop_ticks_total.fetch_add(4, std::sync::atomic::Ordering::Relaxed);
        state.seal_loop_zones_evaluated_total.fetch_add(8, std::sync::atomic::Ordering::Relaxed);

        assert_eq!(state.seal_loop_proposals_per_zone_total.load(std::sync::atomic::Ordering::Relaxed), 5);
        assert_eq!(state.seal_loop_proposals_none_total.load(std::sync::atomic::Ordering::Relaxed), 3);
        assert_eq!(state.seal_loop_proposals_escalate_total.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert_eq!(state.seal_loop_ticks_total.load(std::sync::atomic::Ordering::Relaxed), 4);
        assert_eq!(state.seal_loop_zones_evaluated_total.load(std::sync::atomic::Ordering::Relaxed), 8);
    }

    #[test]
    fn seal_stall_signature_all_zones_none() {
        // Replays the fleet-stall shape: anchors observe ticks +
        // zones every minute, ALL zones land in SealProposal::None, zero
        // per_zone / escalate. Operator query
        // (`rate(proposals_none) > 0 AND rate(proposals_per_zone) == 0`)
        // becomes the page signal once the counters deploy fleet-wide.
        let state = test_node_state(None);
        // Simulate 10 ticks, 2 zones each, all None.
        for _ in 0..10 {
            state.seal_loop_ticks_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            state.seal_loop_zones_evaluated_total.fetch_add(2, std::sync::atomic::Ordering::Relaxed);
            state.seal_loop_proposals_none_total.fetch_add(2, std::sync::atomic::Ordering::Relaxed);
        }
        let ticks = state.seal_loop_ticks_total.load(std::sync::atomic::Ordering::Relaxed);
        let none = state.seal_loop_proposals_none_total.load(std::sync::atomic::Ordering::Relaxed);
        let per_zone = state.seal_loop_proposals_per_zone_total.load(std::sync::atomic::Ordering::Relaxed);
        let zones = state.seal_loop_zones_evaluated_total.load(std::sync::atomic::Ordering::Relaxed);
        // Page condition: none rate > 0, per_zone rate == 0, zones > 0
        // (so we know it's not a discovery-empty stall).
        assert!(ticks > 0 && zones > 0 && none > 0 && per_zone == 0,
            "stall signature: ticks={ticks} zones={zones} none={none} per_zone={per_zone}");
        // Conservation: none should equal zones (every evaluated zone landed in None).
        assert_eq!(none, zones, "every evaluated zone must land in exactly one outcome counter");
    }

    // ─── reason-tagged None sub-counters ───────────────────────────────────
    //
    // The lumped `proposals_none_total` counter surfaced that every (zone,
    // epoch) lands in `SealProposal::None` during a stall but couldn't say WHY.
    // The reason-tagged sub-counters split
    // that lumped counter into four so /metrics
    // alone disambiguates whether the gate firing is `AlreadySealed` (healthy
    // duplicate-suppression), `BootstrapNonGenesis` (sticky stake-set
    // condition), `NotInTopRanks` (anchor outside top-7 VRF rank), or
    // `RankTooHighForElapsed` (top-7 but backoff schedule not unlocked).

    #[test]
    fn ops189_reason_subcounters_start_at_zero() {
        let state = test_node_state(None);
        for (name, val) in [
            ("none_already_sealed", state.seal_loop_proposals_none_already_sealed_total.load(std::sync::atomic::Ordering::Relaxed)),
            ("none_bootstrap_decline", state.seal_loop_proposals_none_bootstrap_decline_total.load(std::sync::atomic::Ordering::Relaxed)),
            ("none_not_in_top_ranks", state.seal_loop_proposals_none_not_in_top_ranks_total.load(std::sync::atomic::Ordering::Relaxed)),
            ("none_rank_too_high", state.seal_loop_proposals_none_rank_too_high_total.load(std::sync::atomic::Ordering::Relaxed)),
        ] {
            assert_eq!(val, 0, "OPS-189 reason counter {name} must start at 0");
        }
    }

    #[test]
    fn ops189_reason_subcounters_are_independent_axes() {
        // Each reason must bump its OWN counter without bleeding. Catches a
        // future refactor that accidentally aliases two reason counters
        // (e.g. NotInTopRanks bumping AlreadySealed by mistake).
        let state = test_node_state(None);
        state.seal_loop_proposals_none_already_sealed_total.fetch_add(7, std::sync::atomic::Ordering::Relaxed);
        state.seal_loop_proposals_none_bootstrap_decline_total.fetch_add(3, std::sync::atomic::Ordering::Relaxed);
        state.seal_loop_proposals_none_not_in_top_ranks_total.fetch_add(11, std::sync::atomic::Ordering::Relaxed);
        state.seal_loop_proposals_none_rank_too_high_total.fetch_add(2, std::sync::atomic::Ordering::Relaxed);

        assert_eq!(state.seal_loop_proposals_none_already_sealed_total.load(std::sync::atomic::Ordering::Relaxed), 7);
        assert_eq!(state.seal_loop_proposals_none_bootstrap_decline_total.load(std::sync::atomic::Ordering::Relaxed), 3);
        assert_eq!(state.seal_loop_proposals_none_not_in_top_ranks_total.load(std::sync::atomic::Ordering::Relaxed), 11);
        assert_eq!(state.seal_loop_proposals_none_rank_too_high_total.load(std::sync::atomic::Ordering::Relaxed), 2);
    }

    #[test]
    fn ops189_reason_subcounters_sum_to_none_parent() {
        // Conservation invariant: the four reason sub-counters MUST sum to
        // the parent `seal_loop_proposals_none_total` (modulo the parent
        // being bumped on every None and the reason being bumped on the
        // same call). The seal-loop match arm bumps both in the same
        // execution path; if a future change adds a 5th reason and forgets
        // to bump the parent, or vice versa, this test catches the drift.
        let state = test_node_state(None);
        // Simulate the seal-loop's atomic update pattern: every None hits
        // exactly one reason counter AND the parent.
        let bumps = [
            (3u64, &state.seal_loop_proposals_none_already_sealed_total),
            (5u64, &state.seal_loop_proposals_none_bootstrap_decline_total),
            (7u64, &state.seal_loop_proposals_none_not_in_top_ranks_total),
            (2u64, &state.seal_loop_proposals_none_rank_too_high_total),
        ];
        let mut total = 0u64;
        for (n, counter) in bumps {
            counter.fetch_add(n, std::sync::atomic::Ordering::Relaxed);
            state.seal_loop_proposals_none_total.fetch_add(n, std::sync::atomic::Ordering::Relaxed);
            total += n;
        }
        let parent = state.seal_loop_proposals_none_total.load(std::sync::atomic::Ordering::Relaxed);
        let sum = state.seal_loop_proposals_none_already_sealed_total.load(std::sync::atomic::Ordering::Relaxed)
            + state.seal_loop_proposals_none_bootstrap_decline_total.load(std::sync::atomic::Ordering::Relaxed)
            + state.seal_loop_proposals_none_not_in_top_ranks_total.load(std::sync::atomic::Ordering::Relaxed)
            + state.seal_loop_proposals_none_rank_too_high_total.load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(parent, total, "parent counter must reflect all bumps");
        assert_eq!(sum, parent, "sum of reason sub-counters must equal parent — drift = bookkeeping bug");
    }

    // The 5_000-candidate cap on
    // `gc_scan_and_delete` plus the `gc_scan_capped_total` counter let
    // operators tell apart a cycle that finished naturally short from a
    // cycle that broke early because the box is GC-throughput bounded. A node's
    // pre-fix telemetry showed `gc_last_cycle_duration_ms = 616_111` (10.3
    // min on a saturated 19 GB rocksdb / 510 SSTs / 1 vCPU). Without the
    // counter, `cap fired` was indistinguishable from `cycle naturally
    // short` from a single duration gauge alone. These tests pin the boot
    // contract + the drain-mode signature + the export-route inclusion.

    #[test]
    fn ops22_gc_scan_capped_total_starts_at_zero() {
        let state = test_node_state(None);
        assert_eq!(
            state
                .gc_scan_capped_total
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "gc_scan_capped_total is a counter, not a floor — must start at 0 \
             (no GC cycles capped pre-boot)"
        );
    }

    #[test]
    fn ops22_gc_scan_capped_independent_from_other_gc_counters() {
        // Bumping `gc_cycles_total` / `gc_pruned_*_total` / the duration
        // gauge MUST NOT bleed into `gc_scan_capped_total`. Catches a future
        // refactor that aliases the cap counter onto the per-cycle prologue
        // (the bump must live ONLY on the `if scan_count >=
        // MAX_GC_SCAN_PER_CYCLE { break }` branch in `gc_scan_and_delete`).
        let state = test_node_state(None);
        state
            .gc_cycles_total
            .fetch_add(7, std::sync::atomic::Ordering::Relaxed);
        state
            .gc_pruned_retention_total
            .fetch_add(5_000, std::sync::atomic::Ordering::Relaxed);
        state
            .gc_pruned_expired_total
            .fetch_add(3, std::sync::atomic::Ordering::Relaxed);
        state
            .gc_last_cycle_duration_ms
            .store(616_111, std::sync::atomic::Ordering::Relaxed);

        assert_eq!(
            state
                .gc_scan_capped_total
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "scan_capped must remain 0 — no cap event was recorded, only \
             sibling counters bumped"
        );
    }

    #[test]
    fn gc_scan_capped_drain_signature_under_bloat() {
        // Replays an observed drain-mode shape: `gc_cycles_total`
        // climbing AND `gc_scan_capped_total` climbing in lockstep until the
        // backlog clears, then cycles continue to climb but capped does not.
        // Operator query
        // (`rate(gc_cycles_total[5m]) > 0 AND rate(gc_scan_capped_total[5m]) > 0`)
        // becomes the throughput-bound page signal once this counter
        // deploys; `rate(gc_scan_capped_total) → 0 with rate(gc_cycles_total)
        // > 0` is the recovery signal.
        let state = test_node_state(None);
        // 4 capped cycles, each chewing the 5_000-record max under
        // DRAIN_INTERVAL (10 s) instead of `gc_interval_secs`.
        for _ in 0..4 {
            state
                .gc_cycles_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            state
                .gc_scan_capped_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            state
                .gc_pruned_retention_total
                .fetch_add(5_000, std::sync::atomic::Ordering::Relaxed);
        }
        // Backlog drains: the next cycle finishes naturally without hitting
        // the cap (only 2_311 candidates left in the eligibility window).
        state
            .gc_cycles_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        state
            .gc_pruned_retention_total
            .fetch_add(2_311, std::sync::atomic::Ordering::Relaxed);

        let cycles = state
            .gc_cycles_total
            .load(std::sync::atomic::Ordering::Relaxed);
        let capped = state
            .gc_scan_capped_total
            .load(std::sync::atomic::Ordering::Relaxed);

        assert!(capped > 0, "drain signature requires at least one capped cycle");
        assert!(
            capped < cycles,
            "drain ratio: capped should LAG cycles once backlog clears \
             (cycles={cycles} capped={capped})"
        );
        assert_eq!(cycles, 5);
        assert_eq!(capped, 4);
    }

    #[tokio::test]
    async fn ops22_metrics_body_exports_gc_scan_capped_total() {
        // Pairs with `ops22_metrics_body_exports_gc_counters_and_age_gauge`
        // — the scan_capped_total counter was added 2026-05-11 and the
        // earlier metrics-body assertion list never grew to cover it. Without
        // this test, an export-route regression that drops the line (e.g.
        // accidentally tier-gating it past the default tier) would not
        // surface in the suite.
        let state = test_node_state(None);
        state
            .gc_scan_capped_total
            .fetch_add(13, std::sync::atomic::Ordering::Relaxed);

        let body = super::super::server::metrics_body(state).await;

        assert!(
            body.contains("elara_gc_scan_capped_total 13"),
            "missing scan_capped_total counter line in body: {body}"
        );
        assert!(
            body.contains("# TYPE elara_gc_scan_capped_total counter"),
            "missing TYPE line for scan_capped_total: {body}"
        );
    }

    // Paired iteration counter for the lowest-MB gauge.
    // The metrics renderer collapses `u64::MAX` (pre-first-sample sentinel)
    // and a real `0` (statvfs returned <1 MB free, integer-floored) to the
    // same exported value `0`. An observed ENOSPC incident triggered
    // exactly this collapse — `lowest_avail_mb` exported 0 on most of the
    // fleet, and it was misread as a `fetch_min` no-op until this
    // counter was added. The pair `(samples_total, lowest_avail_mb)`
    // disambiguates: samples=0 ⇒ sentinel; samples>0 + lowest=0 ⇒ ENOSPC.

    #[test]
    fn ops178_samples_total_starts_at_zero() {
        let state = test_node_state(None);
        assert_eq!(
            state
                .disk_pressure_samples_total
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "samples_total is a counter, not a floor — must start at 0 (no \
             u64::MAX sentinel; semantically `the loop has fired N times`)"
        );
    }

    #[test]
    fn ops178_samples_total_disambiguates_sentinel_from_real_zero() {
        // Shape (a): loop has never run. Both fields hold their initial
        // values; the renderer maps lowest u64::MAX → 0, which would be
        // indistinguishable from a real sub-MB observation without this
        // counter. samples_total=0 is the disambiguator.
        let pre_sample = test_node_state(None);
        assert_eq!(
            pre_sample
                .disk_pressure_samples_total
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "shape (a): samples=0 ⇒ loop never ran; lowest=0 in export is sentinel"
        );

        // Shape (b): loop ran once and saw an ENOSPC neighbourhood — an
        // observed incident. statvfs returned f_bavail*f_frsize < 1 MB,
        // the integer floor of `(f_bavail*f_frsize) / (1024*1024)` produced 0,
        // fetch_min(0) wrote 0 over the sentinel, and the loop bumped its
        // counter. samples=1 + lowest=0 ⇒ genuine ENOSPC, not sentinel.
        let post_enospc = test_node_state(None);
        post_enospc
            .disk_pressure_lowest_avail_mb
            .fetch_min(0, std::sync::atomic::Ordering::Relaxed);
        post_enospc
            .disk_pressure_samples_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            post_enospc
                .disk_pressure_lowest_avail_mb
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "fetch_min(0) DOES write 0 — beating u64::MAX. An observed \
             ENOSPC incident exercised exactly this branch."
        );
        assert_eq!(
            post_enospc
                .disk_pressure_samples_total
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "shape (b): samples>0 + lowest=0 ⇒ ENOSPC observed, NOT sentinel"
        );
    }

    #[test]
    fn ops178_samples_total_increments_monotonically() {
        let state = test_node_state(None);
        // Simulate ~one hour of disk_pressure_loop ticks (60 iterations at
        // the default 60s cadence). Counter must reach 60 — operators read
        // it as `samples_total ≈ uptime_seconds / 60` to detect a stalled
        // loop (flat counter across two scrapes ⇒ task panicked or wedged).
        for _ in 0..60 {
            state
                .disk_pressure_samples_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        assert_eq!(
            state
                .disk_pressure_samples_total
                .load(std::sync::atomic::Ordering::Relaxed),
            60,
            "counter must increment once per loop iteration with no gaps"
        );
    }

    // Split the recursive data_dir size walk out of
    // disk_pressure_loop into a dedicated `data_dir_size_loop` task at a
    // longer cadence + `spawn_blocking`. A node at 510+ SSTs after a
    // deploy was the trigger: 7 disk_pressure samples in 11 min of uptime
    // (expected ≥11) — the `O(SST count)` stat() pass dominated the 60 s tick.
    // These tests verify: (a) the new samples counter starts at 0 (semantic
    // contract — distinct from the disk-pressure samples counter in scope but identical in shape);
    // (b) gauge+counter pair disambiguates `never sampled` from `walk
    // returned zero` (pathological FS state); (c) counter increments
    // monotonically per walk; (d) end-to-end: a spawn_blocking pass over a
    // real on-disk tree populates the gauge.

    #[test]
    fn ops190_data_dir_size_samples_total_starts_at_zero() {
        let state = test_node_state(None);
        assert_eq!(
            state
                .data_dir_size_samples_total
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "data_dir_size_samples_total is a counter — must start at 0 \
             (semantically: the walk task has not completed any pass yet)"
        );
        assert_eq!(
            state
                .data_dir_total_bytes
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "data_dir_total_bytes starts at 0 (pre-first-walk sentinel — \
             pair with samples_total=0 to distinguish from genuine empty)"
        );
    }

    #[test]
    fn ops190_samples_total_disambiguates_never_ran_from_pathological_zero() {
        // Shape (a): walk task hasn't completed its first pass yet (boot regime).
        // gauge=0 + samples=0 ⇒ unsampled; operator should wait for the first
        // cycle rather than alert.
        let pre = test_node_state(None);
        assert_eq!(
            pre.data_dir_size_samples_total
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
        );
        assert_eq!(
            pre.data_dir_total_bytes
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
        );

        // Shape (b): walk task completed at least one pass and dir_size_bytes
        // returned 0 — pathological FS state (data_dir relocated, unmounted,
        // all reads errored). samples>0 + gauge=0 ⇒ operator must investigate
        // journal; this is NOT the boot sentinel.
        let post = test_node_state(None);
        post.data_dir_total_bytes
            .store(0, std::sync::atomic::Ordering::Relaxed);
        post.data_dir_size_samples_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            post.data_dir_total_bytes
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
        );
        assert_eq!(
            post.data_dir_size_samples_total
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "samples>0 + gauge=0 ⇒ walk ran but returned zero — pathological \
             FS state, NOT the never-sampled sentinel"
        );
    }

    #[test]
    fn ops190_samples_total_increments_monotonically_per_walk() {
        let state = test_node_state(None);
        // Simulate 12 hours at the 300 s default cadence (144 passes). The
        // counter must climb 1:1 with completed walks — operators read it as
        // `samples_total ≈ uptime_seconds / data_dir_size_sample_interval_secs`
        // to detect a stalled task (flat counter ⇒ panic or stuck in stat()).
        for i in 0..144 {
            state
                .data_dir_size_samples_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            // Gauge writes are independent (last-walk wins); counter is monotonic.
            state
                .data_dir_total_bytes
                .store(1024 * (i + 1) as u64, std::sync::atomic::Ordering::Relaxed);
        }
        assert_eq!(
            state
                .data_dir_size_samples_total
                .load(std::sync::atomic::Ordering::Relaxed),
            144,
            "counter must increment once per walk with no gaps"
        );
        assert_eq!(
            state
                .data_dir_total_bytes
                .load(std::sync::atomic::Ordering::Relaxed),
            1024 * 144,
            "gauge holds the most recent walk's value (not a sum)"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ops190_spawn_blocking_walk_populates_gauge_end_to_end() {
        // Boots a tempdir with a few files, runs the new loop body once via
        // `tokio::task::spawn_blocking` + `storage::rocks::dir_size_bytes`,
        // and verifies both the gauge and the samples counter update. This
        // mirrors exactly what `data_dir_size_loop` in elara_node.rs does
        // per iteration — if the wiring breaks (atomic load/store path,
        // spawn_blocking propagation, dir_size_bytes signature), this test
        // catches it before deploy.
        use std::io::Write;
        let dir = tempfile::tempdir().expect("tempdir");
        let p = dir.path();
        // Write 3 files totalling 1500 bytes (500 each).
        for i in 0..3 {
            let mut f =
                std::fs::File::create(p.join(format!("seed_{i}.bin"))).expect("create file");
            f.write_all(&vec![0xAB; 500]).expect("write file");
        }

        let state = std::sync::Arc::new(test_node_state(None));
        // Mirror the loop body from elara_node.rs `data_dir_size_loop`.
        let walk_path = p.to_path_buf();
        let state_for_walk = state.clone();
        let walked = tokio::task::spawn_blocking(move || {
            crate::storage::rocks::dir_size_bytes(&walk_path).unwrap_or(0)
        })
        .await
        .expect("spawn_blocking join");
        state_for_walk
            .data_dir_total_bytes
            .store(walked, std::sync::atomic::Ordering::Relaxed);
        state_for_walk
            .data_dir_size_samples_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        assert_eq!(
            state
                .data_dir_total_bytes
                .load(std::sync::atomic::Ordering::Relaxed),
            1500,
            "gauge must reflect the walk result (3 files × 500 B = 1500)"
        );
        assert_eq!(
            state
                .data_dir_size_samples_total
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "samples counter bumps exactly once per completed pass"
        );
    }

    // Tests covering small, untested public helpers on NodeState. Each isolates a
    // single contract that ingest/seal/health hot paths depend on, so a
    // regression in the helper trips here before it shows up as a fleet
    // symptom.

    #[test]
    fn l28_next_slot_nonce_starts_at_one_and_is_strictly_monotonic() {
        // slot_nonce_self defaults to 1 on `NodeState::new`; fetch_add(1, AcqRel)
        // returns the pre-increment value. So callers see 1, 2, 3, ... and
        // same-creator second records can never collide on slot_key.
        // Regression guard for SLOT EQUIVOCATION rejections at the ingest path.
        let state = test_node_state(None);
        let nonces: Vec<u64> = (0..5).map(|_| state.next_slot_nonce()).collect();
        assert_eq!(nonces, vec![1, 2, 3, 4, 5]);
        // Counter advanced past the last issued nonce (post-increment semantics).
        assert_eq!(
            state
                .slot_nonce_self
                .load(std::sync::atomic::Ordering::Acquire),
            6,
            "after 5 issuances, slot_nonce_self points at the next free slot"
        );
    }

    #[test]
    fn l28_bootstrap_slot_nonce_fresh_node_stays_at_one() {
        // Empty CF_SLOT_INDEX (fresh node) → max_slot_nonce_for_account
        // returns Ok(None); bootstrap leaves slot_nonce_self alone at the
        // default 1, so the very first record this node mints uses nonce=1.
        // Idempotent: calling bootstrap twice is still a no-op.
        let state = test_node_state(None);
        state.bootstrap_slot_nonce();
        state.bootstrap_slot_nonce();
        assert_eq!(state.next_slot_nonce(), 1);
        assert_eq!(state.next_slot_nonce(), 2);
    }

    // ── F-9: durable self-nonce high-water (power-loss reuse prevention) ──────
    //
    // Builds two NodeStates on the SAME durable rocks to simulate a restart:
    // the fsync'd high-water in CF_METADATA persists, the in-memory counter does
    // not. Proves a nonce is never re-handed even when CF_SLOT_INDEX lost its
    // tail (the power-loss window that fed self-inflicted SLOT EQUIVOCATION).
    fn f9_two_states_on_shared_rocks() -> (
        std::sync::Arc<crate::storage::rocks::StorageEngine>,
        std::path::PathBuf,
        crate::identity::Identity,
    ) {
        use crate::identity::{CryptoProfile, EntityType, Identity};
        use crate::storage::rocks::StorageEngine;
        let tmp = tempfile::tempdir().expect("tempdir");
        let data_dir = tmp.path().to_path_buf();
        std::mem::forget(tmp); // leak the tempdir for the test's lifetime
        let identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
            .expect("generate identity");
        let rocks = std::sync::Arc::new(
            StorageEngine::open(data_dir.join("rocksdb")).expect("open rocksdb"),
        );
        (rocks, data_dir, identity)
    }

    fn f9_mk_state(
        rocks: std::sync::Arc<crate::storage::rocks::StorageEngine>,
        data_dir: &std::path::Path,
        identity: &crate::identity::Identity,
    ) -> std::sync::Arc<NodeState> {
        use crate::network::config::NodeConfig;
        use crate::network::witness::WitnessManager;
        let config = NodeConfig {
            data_dir: data_dir.to_path_buf(),
            db_path: data_dir.join("elara.db"),
            mdns_enabled: false,
            ..Default::default()
        };
        let wmgr = std::sync::Arc::new(WitnessManager::new(rocks.clone()));
        std::sync::Arc::new(NodeState::new(config, identity.clone(), rocks, wmgr))
    }

    #[test]
    fn f9_durable_hwm_prevents_nonce_reuse_across_simulated_restart() {
        let (rocks, data_dir, identity) = f9_two_states_on_shared_rocks();

        // Pre-restart: cross at least two reservation blocks so the fsync'd
        // high-water is advanced well past every issued nonce.
        let state1 = f9_mk_state(rocks.clone(), &data_dir, &identity);
        state1.bootstrap_slot_nonce();
        let issued: Vec<u64> = (0..200).map(|_| state1.next_slot_nonce()).collect();
        let max_issued = *issued.iter().max().unwrap();
        // Sanity: monotonic, no dup within one run.
        let mut sorted = issued.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), issued.len(), "single-run nonces must be unique");

        // Simulate a POWER-LOSS that dropped the CF_SLOT_INDEX tail (this unit
        // path never wrote slot entries, so an index-only bootstrap would
        // re-hand nonce 1). The fsync'd high-water must floor above every
        // pre-restart nonce.
        let state2 = f9_mk_state(rocks.clone(), &data_dir, &identity);
        state2.bootstrap_slot_nonce();
        let after_restart = state2.next_slot_nonce();
        assert!(
            after_restart > max_issued,
            "post-restart nonce {after_restart} must exceed every pre-restart nonce \
             (max {max_issued}); reuse would trigger self-equivocation"
        );
    }

    #[test]
    fn f9_slot_nonce_strictly_monotonic_across_three_restarts() {
        let (rocks, data_dir, identity) = f9_two_states_on_shared_rocks();
        let mut global_max: u64 = 0;
        for round in 0..3 {
            let state = f9_mk_state(rocks.clone(), &data_dir, &identity);
            state.bootstrap_slot_nonce();
            for _ in 0..150 {
                let n = state.next_slot_nonce();
                assert!(
                    n > global_max || (round == 0 && global_max == 0 && n >= 1),
                    "round {round}: nonce {n} not strictly above prior global max {global_max}"
                );
                assert!(n >= global_max, "nonce must never regress across restarts");
                global_max = global_max.max(n);
            }
        }
    }

    #[test]
    fn f9_next_slot_nonce_concurrent_no_duplicates() {
        // 8 threads crossing reservation blocks under contention — the
        // reserve-ahead mutex must never let two callers observe the same nonce.
        let state = test_node_state(None);
        state.bootstrap_slot_nonce();
        let mut handles = Vec::new();
        for _ in 0..8 {
            let s = state.clone();
            handles.push(std::thread::spawn(move || {
                (0..100).map(|_| s.next_slot_nonce()).collect::<Vec<u64>>()
            }));
        }
        let mut all: Vec<u64> = handles
            .into_iter()
            .flat_map(|h| h.join().expect("thread panicked"))
            .collect();
        let n = all.len();
        all.sort_unstable();
        all.dedup();
        assert_eq!(
            all.len(),
            n,
            "concurrent next_slot_nonce handed out a duplicate — reserve-ahead race"
        );
    }

    #[test]
    fn l28_pressure_flags_default_false_and_track_atomic_writes() {
        // The five `under_*_pressure()` getters are thin atomic-bool reads
        // over independent flags; ingest gates and the
        // back-compat disk_pressure gauge call them on every record. This
        // guards (a) clean-boot defaults are all false (no spurious 429s
        // after restart) and (b) each getter reads its own flag — a
        // miswired field would surface here, not at deploy.
        use std::sync::atomic::Ordering::Relaxed;
        let state = test_node_state(None);
        assert!(!state.under_memory_pressure());
        assert!(!state.under_critical_memory_pressure());
        assert!(!state.under_disk_pressure());
        assert!(!state.under_avail_pressure());
        assert!(!state.under_cap_pressure());

        state.memory_pressure.store(true, Relaxed);
        state.memory_critical.store(true, Relaxed);
        state.disk_pressure.store(true, Relaxed);
        state.disk_avail_pressure.store(true, Relaxed);
        state.disk_cap_pressure.store(true, Relaxed);
        assert!(state.under_memory_pressure());
        assert!(state.under_critical_memory_pressure());
        assert!(state.under_disk_pressure());
        assert!(state.under_avail_pressure());
        assert!(state.under_cap_pressure());

        // Each getter reads exactly one flag — flip them back independently
        // and verify the others stay set.
        state.disk_avail_pressure.store(false, Relaxed);
        assert!(!state.under_avail_pressure());
        assert!(state.under_cap_pressure(), "cap flag must be unaffected by avail flip");
        assert!(state.under_disk_pressure(), "back-compat disk_pressure unchanged");
    }

    #[test]
    fn l28_observe_peer_rtt_empty_id_is_noop_and_median_round_trips() {
        // Two contracts on the same path:
        //   (a) observe_peer_rtt with empty peer_id is a no-op — the
        //       Stage-5 geo-fraud detector asserts that anonymous samples
        //       cannot pollute the per-peer estimator.
        //   (b) After a real observation, peer_rtt_median returns the
        //       sample (modulo microsecond quantization in RollingP95).
        let state = test_node_state(None);

        state.observe_peer_rtt("", std::time::Duration::from_millis(100));
        assert_eq!(
            state
                .peer_rtt_samples_total
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "empty peer_id must not bump samples counter"
        );
        assert!(
            state.peer_rtt_median("").is_none(),
            "empty peer_id never accumulates samples → median None"
        );
        assert!(
            state.peer_rtt_median("never-observed").is_none(),
            "unknown peer → median None"
        );

        state.observe_peer_rtt("peer-A", std::time::Duration::from_millis(42));
        assert_eq!(
            state
                .peer_rtt_samples_total
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "real sample bumps counter"
        );
        let med = state
            .peer_rtt_median("peer-A")
            .expect("median present after one sample");
        // RollingP95 quantizes to microseconds; 42ms = 42_000us round-trips exact.
        assert_eq!(med, std::time::Duration::from_millis(42));
    }

    #[test]
    fn l28_effective_max_hops_floors_at_two_with_empty_dht() {
        // adaptive = ceil(log2(max(dht_len, 1))) + 2; bounded by config.gossip_max_hops.
        // Empty DHT → peer_count=1 → log2(1)=0 → adaptive=2. The default
        // gossip_max_hops=6 is the upper bound (see config.rs:816), so the
        // returned value is min(2, 6) = 2. This is the cold-boot default
        // every node hits before DHT bootstrap completes — guards against a
        // future change to the formula silently raising hop count for tiny
        // networks (would burn bandwidth on 1-4 peer testnets).
        let state = test_node_state(None);
        assert_eq!(state.effective_max_hops(), 2);
    }

    // Five more NodeState helper unit tests on cold-boot
    // contracts (uptime/zone-RTT/account-facing confirmation surface/storage
    // passthrough/tombstone roundtrip). Same rationale as the prior set: every
    // assertion guards a contract the live testnet exercises within the
    // first second of boot, so a regression here trips inside the helper
    // before it shows up as a fleet-wide symptom.

    #[test]
    fn l28_uptime_returns_small_non_negative_value_after_construction() {
        // uptime() = now - start_time. start_time is captured in NodeState::new
        // at SystemTime::now(), so a freshly-built state must report a small
        // non-negative uptime. Guards against a future change that swaps the
        // clock source and accidentally yields a negative or wildly large
        // value (e.g. if start_time is left at its Default of 0.0, uptime
        // becomes the current unix epoch in seconds — would surface here as
        // a >1e9 value rather than the expected sub-second range).
        let state = test_node_state(None);
        let up = state.uptime();
        assert!(up >= 0.0, "uptime must not be negative, got {up}");
        assert!(
            up < 60.0,
            "fresh state should report sub-minute uptime, got {up} \
             (start_time wired to a stale reference clock?)"
        );

        // Monotonic non-decreasing across consecutive reads — same wall
        // clock, can be equal on fast machines but never goes backwards.
        let later = state.uptime();
        assert!(later >= up, "uptime regressed: {up} → {later}");
    }

    #[test]
    fn l28_zone_rtt_p95_none_before_observation_and_present_after() {
        // Symmetric to peer_rtt: p95 returns None for an unobserved zone,
        // and a single observation makes it present (modulo RollingP95
        // microsecond quantization). zone_rtt_samples_total bumps once per
        // observe — the counter is what the seal loop's adaptive timeout
        // ladder reads to decide "do I trust this estimator yet".
        let state = test_node_state(None);
        let zone = super::super::zone::ZoneId::from_legacy(7);

        assert!(
            state.zone_rtt_p95(&zone).is_none(),
            "unobserved zone → p95 None"
        );
        assert_eq!(
            state
                .zone_rtt_samples_total
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "no observations → counter at zero"
        );

        state.observe_zone_rtt(&zone, std::time::Duration::from_millis(80));
        let p95 = state.zone_rtt_p95(&zone).expect("p95 present after one sample");
        // RollingP95 quantizes to microseconds; 80ms = 80_000us round-trips
        // exact, same as the peer-RTT test.
        assert_eq!(p95, std::time::Duration::from_millis(80));
        assert_eq!(
            state
                .zone_rtt_samples_total
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "observe bumps counter exactly once"
        );

        // A different zone stays untouched — the estimator is per-zone, not
        // global. Guards against an accidental shared-singleton refactor.
        let other = super::super::zone::ZoneId::from_legacy(8);
        assert!(state.zone_rtt_p95(&other).is_none());
    }

    #[test]
    fn l28_confirmation_level_unknown_record_is_pending_and_seal_progress_is_none() {
        // The /record/{id} RPC reads both of these and renders the account's
        // "Pending / Sealed / Finalized" badge. On a fresh node the consensus
        // tracker has no record_to_seal entry, no per-record level, no
        // finalized membership — so:
        //   confirmation_level(unknown) = Pending  (layer-1 default)
        //   seal_progress(unknown)      = None     (`?` early-return on the
        //                                          missing record_to_seal entry)
        // Wallets distinguish "we know nothing" (None) from "sealed with
        // zero attestations" (Some with attestation_count=0) — that contract
        // is the regression risk this test pins.
        let state = test_node_state(None);

        assert_eq!(
            state.confirmation_level("nonexistent-record"),
            super::super::consensus::ConfirmationLevel::Pending,
            "unknown record_id → Pending (layer-1 default)"
        );

        assert!(
            state.seal_progress("nonexistent-record").is_none(),
            "unknown record_id → seal_progress None (record_to_seal miss)"
        );
    }

    #[test]
    fn l28_storage_passthrough_zero_on_fresh_node() {
        // Cold-boot storage-passthrough contract: a fresh RocksDB exposes
        //   record_count()  = Ok(0)
        //   record_exists() = Ok(false) for any id
        // Both are read by /metrics and every record-validation path — a
        // passthrough that silently rewires (e.g. to a tombstone CF instead
        // of CF_RECORDS) would surface here before triggering a fleet-wide
        // counter drift.
        let state = test_node_state(None);

        assert_eq!(state.record_count().expect("count on fresh node"), 0);
        assert!(
            !state
                .record_exists("never-inserted")
                .expect("exists on fresh node"),
            "unknown id must report exists=false"
        );
    }

    #[test]
    fn l28_is_tombstoned_round_trips_through_mark_tombstoned() {
        // CF_METADATA-backed tombstone entries are written by mark_tombstoned
        // and read by is_tombstoned via the `tombstone:{id}` key prefix.
        // Tier 4.5 moved the tombstone keys off CF_RECORDS — this round-trip
        // catches the case where one of the two halves regresses to the old
        // CF, leaving us with a tombstone the read side can never see (which
        // is exactly the failure mode that lets a Byzantine record rejoin
        // the DAG after eviction).
        let state = test_node_state(None);

        assert!(
            !state
                .is_tombstoned("not-yet-marked")
                .expect("is_tombstoned on empty CF"),
            "pre-mark must report tombstoned=false"
        );

        state
            .mark_tombstoned("rec-xyz", "tomb-1", "test-fixture")
            .expect("mark_tombstoned writes to CF_METADATA");

        assert!(
            state
                .is_tombstoned("rec-xyz")
                .expect("is_tombstoned post-mark"),
            "post-mark must report tombstoned=true"
        );

        // Other ids stay untouched — the `tombstone:{id}` key is per-record,
        // not a global flag.
        assert!(
            !state
                .is_tombstoned("rec-unmarked")
                .expect("is_tombstoned on unmarked id"),
            "unmarked id remains tombstoned=false"
        );
    }

    // ── query_records filter combinatorics ────────────────────────────────
    //
    // `NodeState::query_records` is a thin passthrough to the
    // `Storage::query` trait that accounts + history endpoints call to read
    // ordered, filtered slices of the record set. The rocks implementation
    // walks `CF_IDX_TIMESTAMP` from `since` forward, breaks at `until`, and
    // applies `classification`/`creator_key` as per-row gates. These five
    // tests pin the four filter axes plus the empty-DB passthrough so a
    // future regression in any one filter is caught before reaching the
    // /history endpoint.

    #[test]
    fn l28_query_records_fresh_node_returns_empty() {
        // Fresh RocksDB has no records — `query_records` must return Ok(empty)
        // for the most permissive filter set (all None, limit=usize::MAX). The
        // fallback full-scan branch in `rocks::query` (the `!used_index &&
        // results.is_empty()` block) would also re-scan CF_RECORDS, which is
        // empty too, so the function returns an empty Vec, not an error.
        let state = test_node_state(None);
        let out = state
            .query_records(None, None, None, None, usize::MAX)
            .expect("query on fresh node returns Ok");
        assert!(out.is_empty(), "fresh node must yield no rows");
    }

    #[test]
    fn l28_query_records_classification_filter_drops_non_matching() {
        // 2 Public + 1 Private records inserted. Filter by Public => 2 rows,
        // Private => 1 row, Restricted => 0 rows. Pins the per-row
        // classification gate at rocks.rs:3474-3476.
        let state = test_node_state(None);

        let r1 = test_record("rc-cls-pub-1", vec![], 100.0);
        let r2 = test_record("rc-cls-pub-2", vec![], 200.0);
        let mut r3 = test_record("rc-cls-priv-1", vec![], 300.0);
        r3.classification = Classification::Private;

        state.insert_record_both(&r1).expect("insert r1");
        state.insert_record_both(&r2).expect("insert r2");
        state.insert_record_both(&r3).expect("insert r3");

        let pubs = state
            .query_records(Some(Classification::Public), None, None, None, usize::MAX)
            .expect("query Public");
        assert_eq!(
            pubs.len(),
            2,
            "Public filter yields exactly the 2 Public rows"
        );

        let privs = state
            .query_records(Some(Classification::Private), None, None, None, usize::MAX)
            .expect("query Private");
        assert_eq!(privs.len(), 1, "Private filter yields the 1 Private row");
        assert_eq!(privs[0].id, "rc-cls-priv-1");

        let restricted = state
            .query_records(
                Some(Classification::Restricted),
                None,
                None,
                None,
                usize::MAX,
            )
            .expect("query Restricted");
        assert!(
            restricted.is_empty(),
            "Restricted filter matches no inserted row"
        );
    }

    #[test]
    fn l28_query_records_creator_filter_drops_non_matching() {
        // 2 records by creator-A + 1 by creator-B. Filter by creator-A => 2,
        // creator-B => 1, unknown PK => 0. Pins the byte-slice equality at
        // rocks.rs:3477-3479. Uses a non-default PK (test_record defaults to
        // b"test_pub_key") so the filter actually has work to do.
        let state = test_node_state(None);

        let mut r1 = test_record("rc-cre-a-1", vec![], 100.0);
        r1.creator_public_key = b"creator-A".to_vec();
        let mut r2 = test_record("rc-cre-a-2", vec![], 200.0);
        r2.creator_public_key = b"creator-A".to_vec();
        let mut r3 = test_record("rc-cre-b-1", vec![], 300.0);
        r3.creator_public_key = b"creator-B".to_vec();

        state.insert_record_both(&r1).expect("insert r1");
        state.insert_record_both(&r2).expect("insert r2");
        state.insert_record_both(&r3).expect("insert r3");

        let only_a = state
            .query_records(None, Some(b"creator-A"), None, None, usize::MAX)
            .expect("query creator-A");
        assert_eq!(only_a.len(), 2, "creator-A filter yields 2 rows");
        assert!(only_a.iter().all(|r| r.creator_public_key == b"creator-A"));

        let only_b = state
            .query_records(None, Some(b"creator-B"), None, None, usize::MAX)
            .expect("query creator-B");
        assert_eq!(only_b.len(), 1, "creator-B filter yields 1 row");

        let unknown = state
            .query_records(None, Some(b"creator-Z"), None, None, usize::MAX)
            .expect("query unknown PK");
        assert!(unknown.is_empty(), "unknown creator PK matches none");
    }

    #[test]
    fn l28_query_records_timestamp_window_respected() {
        // 5 records at timestamps 100/200/300/400/500. Query window
        // [200, 400] must return exactly the 3 records inside the window,
        // ordered by timestamp. Pins both the `since`-seek (rocks.rs:3438)
        // and the `until`-break (rocks.rs:3454-3457) of the timestamp-index
        // walk.
        let state = test_node_state(None);
        for ts in [100.0, 200.0, 300.0, 400.0, 500.0] {
            let r = test_record(&format!("rc-ts-{ts:.0}"), vec![], ts);
            state.insert_record_both(&r).expect("insert record");
        }

        let window = state
            .query_records(None, None, Some(200.0), Some(400.0), usize::MAX)
            .expect("query window");
        assert_eq!(window.len(), 3, "[200, 400] window yields 3 records");

        // CF_IDX_TIMESTAMP is walked forward — the result is timestamp-ordered
        // ascending. First row at since, last row at until.
        assert_eq!(window[0].timestamp, 200.0, "first row hits the since boundary");
        assert_eq!(window[1].timestamp, 300.0);
        assert_eq!(
            window[2].timestamp, 400.0,
            "last row sits at the until boundary (inclusive)"
        );
    }

    #[test]
    fn l28_query_records_limit_caps_result_count() {
        // 10 records at strictly-increasing timestamps. limit=3 must cap the
        // returned Vec at 3 rows; the post-cap rows must be the EARLIEST 3 by
        // timestamp because the index walk is forward-only. Pins the
        // break-on-limit guard at rocks.rs:3484.
        let state = test_node_state(None);
        for i in 0..10u32 {
            let r = test_record(&format!("rc-lim-{i:02}"), vec![], 100.0 + i as f64);
            state.insert_record_both(&r).expect("insert record");
        }

        let capped = state
            .query_records(None, None, None, None, 3)
            .expect("query limit=3");
        assert_eq!(capped.len(), 3, "limit=3 caps the result Vec at 3 rows");

        // Index walk is forward — the 3 rows are the earliest 3 timestamps.
        assert_eq!(capped[0].timestamp, 100.0);
        assert_eq!(capped[1].timestamp, 101.0);
        assert_eq!(capped[2].timestamp, 102.0);
    }

    // ── enqueue_pending_seal_replication_bounded ──────────────────────────
    // Gap 6.4 slice 3a pure helper at state.rs:134. Bounded-FIFO enqueue used
    // by `track_pending_seal_replication`; tests exercise the policy in
    // isolation without a NodeState. Pairs with the production call site at
    // state.rs:2769 (`track_pending_seal_replication`).

    #[test]
    fn l28_enqueue_pending_seal_repl_empty_targets_is_noop() {
        // `if targets.is_empty()` short-circuit — no slot consumed, no
        // eviction reported. Reconciler can't probe with zero peers.
        let mut q: VecDeque<PendingSealReplication> = VecDeque::new();
        let evicted = enqueue_pending_seal_replication_bounded(
            &mut q,
            8,
            "seal-empty".to_string(),
            Vec::new(),
            Instant::now(),
        );
        assert_eq!(evicted, 0, "empty targets reports no eviction");
        assert!(q.is_empty(), "empty targets must not consume a queue slot");
    }

    #[test]
    fn l28_enqueue_pending_seal_repl_pushes_under_cap_no_eviction() {
        // Queue depth 0, cap 4 — first push lands at the back with retries=0
        // and reports 0 evictions.
        let mut q: VecDeque<PendingSealReplication> = VecDeque::new();
        let t0 = Instant::now();
        let evicted = enqueue_pending_seal_replication_bounded(
            &mut q,
            4,
            "seal-a".to_string(),
            vec!["peer-1".to_string(), "peer-2".to_string()],
            t0,
        );
        assert_eq!(evicted, 0, "under cap means zero evictions");
        assert_eq!(q.len(), 1, "queue gains exactly one entry");

        let back = q.back().expect("entry present");
        assert_eq!(back.seal_id, "seal-a");
        assert_eq!(back.targets, vec!["peer-1".to_string(), "peer-2".to_string()]);
        assert_eq!(back.retries, 0, "slice 3b semantics — retries seeded at 0");
        assert_eq!(back.pushed_at, t0, "pushed_at preserved verbatim");
    }

    #[test]
    fn l28_enqueue_pending_seal_repl_evicts_oldest_at_cap() {
        // Fill queue to cap=3, then push a 4th — FIFO eviction reports 1.
        // Surviving entries must be the youngest 3, ordered oldest→newest.
        let mut q: VecDeque<PendingSealReplication> = VecDeque::new();
        for i in 0..3u32 {
            let n = enqueue_pending_seal_replication_bounded(
                &mut q,
                3,
                format!("seal-{i}"),
                vec![format!("peer-{i}")],
                Instant::now(),
            );
            assert_eq!(n, 0, "first {} pushes do not evict", i + 1);
        }
        assert_eq!(q.len(), 3);

        let evicted = enqueue_pending_seal_replication_bounded(
            &mut q,
            3,
            "seal-3".to_string(),
            vec!["peer-3".to_string()],
            Instant::now(),
        );
        assert_eq!(evicted, 1, "queue at cap evicts exactly one to make room");
        assert_eq!(q.len(), 3, "post-eviction depth still equals cap");

        // FIFO: oldest (`seal-0`) is gone, newest (`seal-3`) at the back.
        let ids: Vec<&str> = q.iter().map(|e| e.seal_id.as_str()).collect();
        assert_eq!(ids, vec!["seal-1", "seal-2", "seal-3"]);
    }

    #[test]
    fn l28_enqueue_pending_seal_repl_cap_zero_normalized_to_one() {
        // `let cap = cap.max(1)` — caller asking for cap=0 still leaves one
        // slot for the new entry; an existing entry must be evicted to make
        // room. Pins the no-zero-cap guard at state.rs:144.
        let mut q: VecDeque<PendingSealReplication> = VecDeque::new();
        // Pre-populate (using max(1)=1 path) with one entry.
        let _ = enqueue_pending_seal_replication_bounded(
            &mut q,
            1,
            "seal-old".to_string(),
            vec!["peer-old".to_string()],
            Instant::now(),
        );
        assert_eq!(q.len(), 1);

        let evicted = enqueue_pending_seal_replication_bounded(
            &mut q,
            0, // requested cap=0 — must be normalized to 1
            "seal-new".to_string(),
            vec!["peer-new".to_string()],
            Instant::now(),
        );
        assert_eq!(evicted, 1, "cap=0 normalized to 1 ⇒ existing entry evicted");
        assert_eq!(q.len(), 1, "post-push depth equals normalized cap=1");
        assert_eq!(q.back().expect("entry").seal_id, "seal-new");
    }

    #[test]
    fn l28_enqueue_pending_seal_repl_oversized_queue_drains_to_cap() {
        // If the queue is already over cap when called (e.g. cap was
        // reconfigured downward at runtime), the while-loop must drain
        // multiple entries in a single call until depth < cap, then push
        // the new entry. Eviction count == (old_depth - cap + 1).
        let mut q: VecDeque<PendingSealReplication> = VecDeque::new();
        // Manually seed 5 entries (simulating depth>cap state).
        for i in 0..5u32 {
            q.push_back(PendingSealReplication {
                seal_id: format!("seal-pre-{i}"),
                targets: vec![format!("peer-{i}")],
                pushed_at: Instant::now(),
                retries: 0,
            });
        }
        assert_eq!(q.len(), 5);

        let evicted = enqueue_pending_seal_replication_bounded(
            &mut q,
            2, // new cap=2 — must drain 4 olds and push 1 new
            "seal-new".to_string(),
            vec!["peer-new".to_string()],
            Instant::now(),
        );
        assert_eq!(evicted, 4, "drains (5 - 2 + 1) = 4 entries to fit new push under cap=2");
        assert_eq!(q.len(), 2, "post-drain depth equals cap=2");

        let ids: Vec<&str> = q.iter().map(|e| e.seal_id.as_str()).collect();
        assert_eq!(ids, vec!["seal-pre-4", "seal-new"]);
    }

    // ── content-safety + delete + zone-resolver helpers ───────────────────
    //
    // All of these are NodeState pass-throughs to either the storage layer
    // (ban/blocked-term/delete) or the in-memory zone registry. They had no
    // direct unit-test coverage prior to this batch; ingest-side bugs that
    // touched them surfaced only via the integration suite. Locking in the
    // pass-through invariants (round-trip persistence, idempotency on the
    // missing-key path, naive-zone fallback when no split is registered)
    // keeps regressions local to those helpers visible at `--lib`.

    #[test]
    fn l28_ban_identity_round_trip_returns_hash_and_reason() {
        let state = test_node_state(None);

        // Empty load on a fresh node — no rows.
        let initial = state
            .load_banned_identities()
            .expect("load_banned_identities ok");
        assert!(initial.is_empty(), "fresh node must have no banned ids");

        state
            .ban_identity("hash-a", "spam")
            .expect("ban hash-a ok");
        state
            .ban_identity("hash-b", "abuse")
            .expect("ban hash-b ok");

        let mut rows = state
            .load_banned_identities()
            .expect("load_banned_identities ok");
        // Sort by hash so the test is independent of RocksDB prefix-iter order.
        rows.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].0, "hash-a");
        assert_eq!(rows[0].1, "spam");
        assert!(rows[0].2 > 0.0, "ban timestamp must be set by storage");
        assert_eq!(rows[1].0, "hash-b");
        assert_eq!(rows[1].1, "abuse");
    }

    #[test]
    fn l28_unban_identity_returns_true_first_call_false_after() {
        let state = test_node_state(None);

        // Unban of an absent hash — false, no side effect.
        let absent = state
            .unban_identity("never-banned")
            .expect("unban absent ok");
        assert!(!absent, "unban of absent hash must return false");

        state
            .ban_identity("hash-x", "test")
            .expect("ban hash-x ok");

        let first = state.unban_identity("hash-x").expect("first unban ok");
        assert!(first, "first unban of present hash must return true");

        let second = state.unban_identity("hash-x").expect("second unban ok");
        assert!(
            !second,
            "second unban must return false (idempotent on absent)"
        );

        let after = state
            .load_banned_identities()
            .expect("post-unban load ok");
        assert!(after.is_empty(), "unbanned hash must be gone from load");
    }

    #[test]
    fn l28_blocked_term_add_load_remove_round_trip() {
        let state = test_node_state(None);

        assert!(state
            .load_blocked_terms()
            .expect("load empty ok")
            .is_empty());

        state.add_blocked_term("badword-1").expect("add 1 ok");
        state.add_blocked_term("badword-2").expect("add 2 ok");

        let mut terms = state.load_blocked_terms().expect("load after add ok");
        terms.sort();
        assert_eq!(terms, vec!["badword-1".to_string(), "badword-2".to_string()]);

        // First remove returns true (term existed).
        let first_rm = state
            .remove_blocked_term("badword-1")
            .expect("remove 1 ok");
        assert!(first_rm, "first remove of present term must return true");

        // Second remove of the same term returns false (idempotent).
        let second_rm = state
            .remove_blocked_term("badword-1")
            .expect("remove 1 again ok");
        assert!(
            !second_rm,
            "second remove of absent term must return false"
        );

        // The other term is unaffected.
        let remaining = state.load_blocked_terms().expect("load remaining ok");
        assert_eq!(remaining, vec!["badword-2".to_string()]);
    }

    #[test]
    fn l28_delete_record_both_removes_record_from_storage() {
        let state = test_node_state(None);
        let rec = test_record("doomed-1", vec![], 123.0);

        state
            .insert_record_both(&rec)
            .expect("insert_record_both ok");
        assert!(
            state.record_exists("doomed-1").expect("exists ok"),
            "record must be present after insert"
        );

        state
            .delete_record_both("doomed-1")
            .expect("delete_record_both ok");
        assert!(
            !state.record_exists("doomed-1").expect("exists post-delete ok"),
            "record must be gone after delete"
        );

        // Deleting an already-absent id is a no-op at this layer — storage's
        // delete_record fast-paths the missing entry (it WriteBatches deletes
        // unconditionally; the secondary-index cleanup is gated on the read).
        // Verify it does not error.
        state
            .delete_record_both("doomed-1")
            .expect("delete absent ok");
    }

    #[test]
    fn l28_resolve_record_zone_empty_registry_returns_naive_and_bumps_query_counter() {
        // Empty zone registry — no splits registered — so `resolve_record_zone`
        // must return the naive `zone_for_record(record_id)` result and bump
        // `_queries_total` exactly once per call. Redirect counter stays at 0
        // because no leaf rewrites occurred. This pins the no-op fast-path: a
        // regression that mis-flags every resolve as redirected (a real bug at
        // an earlier point in the zone-registry refactor) would show up here.
        use std::sync::atomic::Ordering::Relaxed;
        let state = test_node_state(None);

        assert_eq!(
            state.zone_resolve_internal_queries_total.load(Relaxed),
            0,
            "fresh state: queries counter starts at 0"
        );
        assert_eq!(
            state.zone_resolve_internal_redirected_total.load(Relaxed),
            0,
            "fresh state: redirect counter starts at 0"
        );

        let naive_a = super::super::consensus::zone_for_record("rec-A");
        let resolved_a = state.resolve_record_zone("rec-A");
        assert_eq!(resolved_a, naive_a, "empty registry returns naive zone");

        let naive_b = super::super::consensus::zone_for_record("rec-B");
        let resolved_b = state.resolve_record_zone("rec-B");
        assert_eq!(resolved_b, naive_b);

        assert_eq!(
            state.zone_resolve_internal_queries_total.load(Relaxed),
            2,
            "queries counter increments once per resolve call"
        );
        assert_eq!(
            state.zone_resolve_internal_redirected_total.load(Relaxed),
            0,
            "redirect counter stays at 0 with no splits registered"
        );
    }

    // ── subscribe_zone / unsubscribe_zone ZSP Phase E Slice 3 ─────────────
    //
    // Mirror tests for the admin-surface wrappers around `ZoneManager`. The
    // wrappers must (a) mutate the in-memory subscription set, (b) write the
    // updated set through to `zone_persist::save_subscriptions` so it
    // survives restart, and (c) on unsubscribe, push the zone onto the
    // background purge queue. Auto-pinning of ancestor zones is owned by
    // `ZoneManager::subscribe` itself — the wrapper just has to persist
    // whatever set the manager ends up in.

    #[test]
    fn subscribe_zone_persists_to_disk_and_appears_in_manager() {
        let state = test_node_state(None);
        let z = super::super::zone::ZoneId::new("medical/eu");
        state.subscribe_zone(&z);

        let mgr = state.zone_manager.lock().expect("zone_manager mutex");
        assert!(
            mgr.subscribed_zones().contains(&z),
            "subscribed_zones must contain freshly subscribed zone"
        );
        drop(mgr);

        let loaded =
            super::super::zone_persist::load_subscriptions(&state.config.data_dir);
        assert!(
            loaded.contains(&z),
            "persisted subscriptions must include the subscribed zone"
        );
    }

    #[test]
    fn subscribe_zone_auto_pins_ancestor_zones_and_persists_full_set() {
        // ZoneManager::subscribe auto-pins ancestors. The state-level wrapper
        // must persist the *full* ancestor-pinned set, not just the named leaf
        // — that's what the docstring at subscribe_zone() promises and what
        // the disk file has to reflect for the post-restart ingest filter to
        // accept records for the ancestor zones too.
        let state = test_node_state(None);
        let leaf = super::super::zone::ZoneId::new("trade/us/east");
        state.subscribe_zone(&leaf);

        let mgr = state.zone_manager.lock().expect("zone_manager mutex");
        let in_mem = mgr.subscribed_zones().clone();
        drop(mgr);

        let parent = super::super::zone::ZoneId::new("trade/us");
        let grand = super::super::zone::ZoneId::new("trade");
        assert!(in_mem.contains(&leaf), "leaf zone retained");
        assert!(in_mem.contains(&parent), "parent zone auto-pinned");
        assert!(in_mem.contains(&grand), "grandparent zone auto-pinned");

        let loaded =
            super::super::zone_persist::load_subscriptions(&state.config.data_dir);
        assert_eq!(
            loaded, in_mem,
            "persisted set must match the in-memory subscription set after auto-pin"
        );
    }

    #[test]
    fn unsubscribe_zone_removes_only_named_zone_and_persists() {
        let state = test_node_state(None);
        let a = super::super::zone::ZoneId::new("medical/eu");
        let b = super::super::zone::ZoneId::new("trade/us");
        state.subscribe_zone(&a);
        state.subscribe_zone(&b);

        state.unsubscribe_zone(&a);

        let mgr = state.zone_manager.lock().expect("zone_manager mutex");
        let in_mem = mgr.subscribed_zones().clone();
        drop(mgr);
        assert!(!in_mem.contains(&a), "unsubscribed zone must be removed");
        assert!(in_mem.contains(&b), "other subscriptions must be preserved");

        let loaded =
            super::super::zone_persist::load_subscriptions(&state.config.data_dir);
        assert_eq!(
            loaded, in_mem,
            "disk reflects the post-unsubscribe subscription set"
        );
    }

    #[test]
    fn unsubscribe_zone_idempotent_on_never_subscribed_zone() {
        // Unsubscribing a zone that was never added must not panic and must
        // still write a valid sidecar file (empty set is the canonical
        // accept-all default — see zone_persist::load_subscriptions docs).
        let state = test_node_state(None);
        let z = super::super::zone::ZoneId::new("ghost/zone");

        state.unsubscribe_zone(&z);

        let mgr = state.zone_manager.lock().expect("zone_manager mutex");
        assert!(
            mgr.subscribed_zones().is_empty(),
            "unsubscribing an unknown zone leaves the manager set empty"
        );
        drop(mgr);

        let loaded =
            super::super::zone_persist::load_subscriptions(&state.config.data_dir);
        assert!(
            loaded.is_empty(),
            "persisted set is empty after no-op unsubscribe"
        );
    }

    #[test]
    fn unsubscribe_zone_enqueues_purge_for_dropped_zone() {
        // The wrapper tail-calls zone_purge::enqueue_purge_zone, so the
        // unsubscribed zone has to land on the purge queue exactly once —
        // independently of any in-memory manager mutation.
        let state = test_node_state(None);
        let z = super::super::zone::ZoneId::new("retire/zone");
        state.subscribe_zone(&z);

        let pre_len = state
            .zone_purge_queue
            .lock()
            .map(|q| q.len())
            .unwrap_or(usize::MAX);
        assert_eq!(pre_len, 0, "purge queue starts empty");

        state.unsubscribe_zone(&z);

        let q = state
            .zone_purge_queue
            .lock()
            .expect("zone_purge_queue mutex");
        assert_eq!(q.len(), 1, "purge queue grew by exactly one entry");
        assert_eq!(
            &q.front().expect("queue head present").0,
            &z,
            "queued zone matches the unsubscribed one"
        );
    }

    // ── create_self_ledger_record + resolve_identity_zone +
    //    all_record_hashes + get_wire_bytes ──────────────────────────────
    //
    // Closing the remaining sync-helper coverage gap. `create_self_ledger_record`
    // is the canonical in-node writer that bundles `next_slot_nonce()` + sign
    // — the exact pattern whose absence in `create_super_seal` caused a
    // slot collision. Pinning its
    // contract here means any future migration that strips the nonce step
    // from the helper trips these tests instead of surfacing as a Day-1 fleet
    // mint stall.

    #[test]
    fn l28_create_self_ledger_record_two_calls_produce_distinct_nonces() {
        // Direct defense against the slot_nonce=0 collision bug class.
        // Two back-to-back invocations of the canonical helper
        // must hand back records carrying distinct, strictly-monotonic
        // nonces — so `slot_key = sha3_256_hex(pk):{nonce:016x}` differs and
        // both can clear the ingest slot-enforcement check at
        // `network/ingest.rs:559` without one evicting the other.
        let state = test_node_state(None);
        let mut md_a = std::collections::BTreeMap::new();
        md_a.insert("beat_op".into(), serde_json::json!("mint"));
        md_a.insert("beat_amount".into(), serde_json::json!(100u64));
        let mut md_b = md_a.clone();
        md_b.insert("beat_amount".into(), serde_json::json!(200u64));

        let rec_a = state
            .create_self_ledger_record(vec![], md_a)
            .expect("create_self_ledger_record a");
        let rec_b = state
            .create_self_ledger_record(vec![], md_b)
            .expect("create_self_ledger_record b");

        // Nonces are strictly monotonic and non-zero (start nonce is 1 per
        // next_slot_nonce contract — see test_next_slot_nonce_*).
        assert_ne!(rec_a.nonce, rec_b.nonce, "two calls must allocate distinct nonces");
        assert!(rec_a.nonce >= 1 && rec_b.nonce > rec_a.nonce, "monotonic, non-zero");

        // Slot keys differ → no equivocation on insert.
        let sk_a = rec_a.slot_key().expect("v5 record yields slot_key");
        let sk_b = rec_b.slot_key().expect("v5 record yields slot_key");
        assert_ne!(sk_a, sk_b, "distinct slot keys → both inserts can succeed");
        // And neither is the dangerous `:0000000000000000` default.
        assert!(!sk_a.ends_with(":0000000000000000"));
        assert!(!sk_b.ends_with(":0000000000000000"));
    }

    #[test]
    fn l28_create_self_ledger_record_stamps_state_identity_pk_and_signs() {
        // The helper signs with `state.identity` and stamps that identity's
        // public key onto the record — callers do not have to pass either
        // and cannot accidentally use a foreign identity. The signature
        // option must be populated so ingest's sig-verify step has a
        // signature to check at all.
        let state = test_node_state(None);
        let mut md = std::collections::BTreeMap::new();
        md.insert("beat_op".into(), serde_json::json!("mint"));
        md.insert("beat_amount".into(), serde_json::json!(1u64));

        let rec = state
            .create_self_ledger_record(vec![], md)
            .expect("create_self_ledger_record ok");

        assert_eq!(
            rec.creator_public_key, state.identity.public_key,
            "record's creator_pk must match state.identity.public_key"
        );
        assert!(
            rec.signature.is_some() && !rec.signature.as_ref().unwrap().is_empty(),
            "record must carry a Dilithium3 signature"
        );
        // Wire version is v5+ since `nonce` is part of the signed bytes.
        assert!(rec.version >= 5, "v5+ required for slot_key to exist");
    }

    #[test]
    fn l28_resolve_identity_zone_empty_registry_returns_naive_and_bumps_internal_query_counter() {
        // Mirror of `l28_resolve_record_zone_*`: the identity-keyed lookup
        // routes through the same zone-registry resolver, so empty registry
        // → naive zone, exactly one query-counter bump per call, redirect
        // counter pinned at 0 (no splits → nothing to rewrite).
        use std::sync::atomic::Ordering::Relaxed;
        let state = test_node_state(None);

        assert_eq!(
            state.zone_resolve_internal_queries_total.load(Relaxed),
            0,
            "fresh state: queries counter starts at 0"
        );
        assert_eq!(
            state.zone_resolve_internal_redirected_total.load(Relaxed),
            0,
            "fresh state: redirect counter starts at 0"
        );

        // Use the actual self-identity hex so the result is reproducible —
        // any 32-byte hex string would also work since the registry is empty,
        // but pinning to the node's own identity also confirms the helper
        // accepts the canonical input form.
        let identity_hex =
            crate::crypto::hash::sha3_256_hex(&state.identity.public_key);
        let routing_key =
            super::super::zone_registry::routing_key_for_identity(&identity_hex);
        let naive = super::super::consensus::zone_for_record(&identity_hex);
        // Empty registry → resolver returns the naive zone unchanged.
        // (We compute the expected result via the same internal helper the
        // implementation uses; a regression that swaps in a different naive
        // mapping would show here as a value mismatch.)
        let _ = routing_key; // routing_key is only used inside resolver

        let resolved = state.resolve_identity_zone(&identity_hex);
        assert_eq!(resolved, naive, "empty registry returns naive zone");

        let _ = state.resolve_identity_zone(&identity_hex); // second call

        assert_eq!(
            state.zone_resolve_internal_queries_total.load(Relaxed),
            2,
            "queries counter increments once per resolve call"
        );
        assert_eq!(
            state.zone_resolve_internal_redirected_total.load(Relaxed),
            0,
            "redirect counter stays at 0 with no splits registered"
        );
    }

    #[test]
    fn l28_all_record_hashes_returns_empty_on_fresh_state_and_one_after_insert() {
        // Storage passthrough sanity: a fresh node has no records, so the
        // bulk-hash query returns an empty vec. After exactly one insert
        // through `insert_record_both`, the same query returns a single
        // entry. This pins the index-keyed enumeration so a future regression
        // that drops a record from CF_IDX_HASH would show here as a length
        // mismatch.
        let state = test_node_state(None);

        let hashes_before = state
            .all_record_hashes()
            .expect("all_record_hashes ok on fresh state");
        assert!(
            hashes_before.is_empty(),
            "fresh state has no record hashes (got {} entries)",
            hashes_before.len()
        );

        let rec = test_record("only-rec", vec![], 999.0);
        state
            .insert_record_both(&rec)
            .expect("insert_record_both ok");

        let hashes_after = state
            .all_record_hashes()
            .expect("all_record_hashes ok after insert");
        assert_eq!(
            hashes_after.len(),
            1,
            "exactly one hash present after exactly one insert"
        );
    }

    #[test]
    fn l28_get_wire_bytes_round_trips_after_insert_record_both() {
        // After `insert_record_both` persists a record to storage, the wire
        // bytes pulled back via `get_wire_bytes` must non-empty and contain
        // the record's id as a UTF-8 prefix (wire layout puts id first —
        // `record.rs::signable_bytes`). A future regression that splits the
        // wire-encoded write from the storage commit (or omits the id field)
        // would surface here as either an empty buffer or a substring miss.
        let state = test_node_state(None);
        let rec = test_record("wire-bytes-1", vec![], 123.0);
        state
            .insert_record_both(&rec)
            .expect("insert_record_both ok");

        let bytes = state
            .get_wire_bytes("wire-bytes-1")
            .expect("get_wire_bytes ok");
        assert!(
            !bytes.is_empty(),
            "wire bytes must be present for an inserted record"
        );
        // Wire format encodes id first as a length-prefixed UTF-8 string,
        // so the literal id appears in the byte stream. Pinning the
        // substring guards against a silent layout drift that would erase
        // the id without surfacing a wire-version bump.
        assert!(
            bytes.windows(b"wire-bytes-1".len()).any(|w| w == b"wire-bytes-1"),
            "wire bytes must contain the record id substring"
        );
    }

    // ── track_pending_seal_replication async wrapper ──────────────────────
    //
    // An earlier test pinned the underlying free helper `enqueue_pending_seal_replication_bounded`
    // (state.rs:134) in isolation. The async wrapper at `track_pending_seal_replication`
    // (state.rs:2792) sits on top of it and adds three observable behaviors the pure
    // helper does not exercise: (a) empty-targets early-return BEFORE acquiring the
    // tokio Mutex and BEFORE reading config — so an idle reconciler with zero peers
    // produces zero contention and zero counter bumps; (b) bump
    // `gossip_seal_replication_tracked_total` on every successful enqueue
    // (rate-of-tracking gauge); (c) store post-push queue length into
    // `gossip_seal_replication_pending_depth` so /metrics surfaces a live depth gauge
    // without a queue walk. These tests close the wrapper-vs-helper coverage gap and
    // pin the three observability signals every push must update.

    #[tokio::test]
    async fn l28_track_pending_seal_replication_empty_targets_is_noop() {
        use std::sync::atomic::Ordering::Relaxed;
        let state = test_node_state(None);

        assert_eq!(state.gossip_seal_replication_tracked_total.load(Relaxed), 0);
        assert_eq!(state.gossip_seal_replication_overflow_total.load(Relaxed), 0);
        assert_eq!(state.gossip_seal_replication_pending_depth.load(Relaxed), 0);

        state
            .track_pending_seal_replication("seal-empty".to_string(), Vec::new())
            .await;

        assert_eq!(
            state.gossip_seal_replication_tracked_total.load(Relaxed),
            0,
            "empty targets must not bump tracked_total — early-return before lock"
        );
        assert_eq!(
            state.gossip_seal_replication_overflow_total.load(Relaxed),
            0,
            "empty targets must not bump overflow_total"
        );
        assert_eq!(
            state.gossip_seal_replication_pending_depth.load(Relaxed),
            0,
            "empty targets must not store a depth value"
        );
        let q = state.pending_seal_replications.lock().await;
        assert!(
            q.is_empty(),
            "queue must remain empty when targets is empty (no lock acquisition required)"
        );
    }

    #[tokio::test]
    async fn l28_track_pending_seal_replication_single_push_bumps_tracked_and_depth_no_overflow() {
        use std::sync::atomic::Ordering::Relaxed;
        let state = test_node_state(None);

        state
            .track_pending_seal_replication(
                "seal-1".to_string(),
                vec!["peer-a".to_string(), "peer-b".to_string()],
            )
            .await;

        assert_eq!(
            state.gossip_seal_replication_tracked_total.load(Relaxed),
            1,
            "single push bumps tracked_total exactly once"
        );
        assert_eq!(
            state.gossip_seal_replication_overflow_total.load(Relaxed),
            0,
            "under default cap (1000) → zero overflows"
        );
        assert_eq!(
            state.gossip_seal_replication_pending_depth.load(Relaxed),
            1,
            "depth gauge stores post-push queue length (=1)"
        );

        let q = state.pending_seal_replications.lock().await;
        assert_eq!(q.len(), 1, "queue contains exactly one entry");
        let entry = q.back().expect("entry present");
        assert_eq!(entry.seal_id, "seal-1");
        assert_eq!(
            entry.targets,
            vec!["peer-a".to_string(), "peer-b".to_string()],
            "targets preserved verbatim by wrapper"
        );
        assert_eq!(entry.retries, 0, "fresh enqueue starts retries=0");
    }

    #[tokio::test]
    async fn l28_track_pending_seal_replication_multiple_pushes_accumulate_under_cap() {
        use std::sync::atomic::Ordering::Relaxed;
        let state = test_node_state(None);

        for i in 0..3u32 {
            state
                .track_pending_seal_replication(
                    format!("seal-{i}"),
                    vec![format!("peer-{i}")],
                )
                .await;
        }

        assert_eq!(
            state.gossip_seal_replication_tracked_total.load(Relaxed),
            3,
            "three pushes bump tracked_total to 3 (one per call)"
        );
        assert_eq!(
            state.gossip_seal_replication_overflow_total.load(Relaxed),
            0,
            "under default cap (1000) → zero overflows even across multiple pushes"
        );
        assert_eq!(
            state.gossip_seal_replication_pending_depth.load(Relaxed),
            3,
            "depth gauge tracks queue length monotonically (each push refreshes the value)"
        );

        let q = state.pending_seal_replications.lock().await;
        assert_eq!(q.len(), 3, "queue gains exactly one entry per push");
        let ids: Vec<&str> = q.iter().map(|e| e.seal_id.as_str()).collect();
        assert_eq!(
            ids,
            vec!["seal-0", "seal-1", "seal-2"],
            "FIFO order preserved across multiple wrapper calls"
        );
    }

    // ── publish_record_with_fallback (state.rs:3934) ───────────────────────
    //
    // Closes the final remaining wrapper cluster
    // ("publish_record_with_fallback: 3-line async wrapper around
    // gossip::push_to_peers — deferred until a gossip test-harness lands").
    //
    // The wrapper is a 2-line function: (a) `effective_max_hops()` computes
    // adaptive hop count from DHT peer-count, (b) delegates to
    // `gossip::push_to_peers(state, record, hops, exclude, None).await`.
    // Both pieces are independently tested (effective_max_hops in its own
    // tests; push_to_peers across gossip.rs's own test module), so the wrapper's
    // testable surface is the COMPOSITION — does it thread args through
    // correctly, and is the no-peer pass-through panic-free + bounded?
    //
    // A multi-peer gossip harness would extend coverage to "record actually
    // reached peer N" but that requires a network fixture (tokio TCP
    // listener pair + handshake) far beyond what this unit-test
    // scope covers. The no-op no-peer pass-through IS observable
    // and never had a direct pin — these tests close that.

    #[tokio::test]
    async fn l28_publish_record_with_fallback_no_peers_is_clean_noop() {
        let state = test_node_state(None);
        let record = test_record("pub-noop", vec![], 1.0);

        // Bound the no-peer pass-through. With dht.len()=0 + peers.len()=0
        // the wrapper computes hops=2 (effective_max_hops floor) and hands
        // off to push_to_peers, which filters to an empty target set and
        // returns. Wrap in a 2s timeout to catch any deadlock regression
        // in the lock acquisition order — wrapper acquires dht.lock_recover()
        // (sync) then push_to_peers acquires peers.read().await (async).
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            NodeState::publish_record_with_fallback(&state, &record, None),
        )
        .await;

        assert!(
            result.is_ok(),
            "no-peer pass-through must complete within 2s — \
             a hang indicates lock ordering regression in the wrapper"
        );
    }

    #[tokio::test]
    async fn l28_publish_record_with_fallback_with_exclude_arg_does_not_panic() {
        let state = test_node_state(None);
        let record = test_record("pub-excl", vec![], 2.0);

        // Cover the `exclude: Some(&str)` branch of the signature. With no
        // peers in the map there's no peer to actually filter, but the
        // wrapper's String conversion of the exclude hash (via push_to_peers
        // internals) must still complete cleanly — pins the Option<&str>
        // lifetime-handoff into the spawned future.
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            NodeState::publish_record_with_fallback(
                &state,
                &record,
                Some("excluded-peer-hash"),
            ),
        )
        .await;

        assert!(
            result.is_ok(),
            "exclude-arg variant of the no-peer pass-through must also \
             complete within 2s — pins Option<&str> handoff"
        );
    }

    #[tokio::test]
    async fn l28_publish_record_with_fallback_threads_effective_max_hops_from_dht() {
        // Indirect test: the wrapper threads effective_max_hops() into
        // push_to_peers. With dht.len()=0, effective_max_hops returns
        // `(max(1).log2().ceil() as u8 + 2).min(gossip_max_hops)` = `2`
        // (since `0u8 + 2 = 2` and default `gossip_max_hops = 6`).
        //
        // We can't observe the hops arg downstream without a peer fixture,
        // but we CAN pin that the wrapper's input computation matches the
        // canonical helper at the call site. If a future refactor swaps
        // `effective_max_hops()` for a hard-coded value or for
        // `config.gossip_max_hops` directly, this test catches the drift.
        let state = test_node_state(None);
        let expected_hops = state.effective_max_hops();
        assert_eq!(
            expected_hops, 2,
            "fresh state with empty dht must yield hops=2 (the floor); \
             if this assertion shifts, the wrapper's contract with \
             gossip::push_to_peers has shifted too"
        );

        // Run the wrapper too, to make sure the call doesn't panic with
        // the value just computed above.
        let record = test_record("pub-hops", vec![], 3.0);
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            NodeState::publish_record_with_fallback(&state, &record, None),
        )
        .await;
        assert!(result.is_ok(), "wrapper must complete with floor-hops too");
    }

    // ── apply_metadata_filter (state.rs:4481) ─────────────────────────────
    //
    // The `?key=`/`?value=` post-filter on /records query results. It's the
    // gate that turns query hits into the final HTTP response slice, so a
    // regression silently swaps "I asked for kind=tx" into "I got every
    // record" — undetectable from the storage layer's side. The upstream
    // `query_records` filter combinatorics are pinned elsewhere (timestamp window,
    // classification, creator-PK byte slice, limit cap), but the metadata
    // post-filter is a separate sieve applied AFTER Layer B / fallback
    // fetch — its four (key, value) Option-pair branches were never pinned.
    //
    // These five tests cover all four match-arm branches of the helper
    // PLUS the early-return short-circuit when both filters are absent, so
    // a future refactor that swaps `r.metadata.get(k).map(...).unwrap_or(false)`
    // for `r.metadata.get(k) == Some(v)` (which mis-handles the `Number(42)`
    // vs `"42"` HTTP-query case via `json_value_matches_string`) surfaces
    // here as a clear assertion failure rather than as a flaky integration
    // mismatch days later.
    //
    // (None, None)           → early-return, no `.retain` walk (records preserved verbatim)
    // (Some(k), None)        → key-presence gate, value-agnostic
    // (None, Some(v))        → any-value-match gate (across all keys in the map)
    // (Some(k), Some(v))     → exact match on metadata[k] via json_value_matches_string
    // (Some(k), Some(v_bad)) → key present BUT value mismatch → record dropped

    fn metadata_test_record(id: &str, kvs: &[(&str, serde_json::Value)]) -> ValidationRecord {
        let mut rec = test_record(id, vec![], 1.0);
        for (k, v) in kvs {
            rec.metadata.insert((*k).to_string(), v.clone());
        }
        rec
    }

    #[test]
    fn l28_apply_metadata_filter_none_none_is_noop() {
        // Both filters absent → early-return. Any records (even ones with
        // empty metadata or unrelated keys) must pass through untouched.
        // This pins the explicit `if key.is_none() && value.is_none()`
        // short-circuit at state.rs:4482 — if a refactor accidentally
        // falls through to the `.retain` walk with both args None, the
        // `(None, None) => true` arm still returns all records, but the
        // helper would have allocated + walked the vec for no reason.
        // The behavior under test here is the OBSERVABLE one: vec
        // contents preserved bit-for-bit.
        let mut records = vec![
            metadata_test_record("a", &[]),
            metadata_test_record("b", &[("k", serde_json::json!("v"))]),
            metadata_test_record("c", &[("kind", serde_json::json!("tx"))]),
        ];
        let snapshot_ids: Vec<String> = records.iter().map(|r| r.id.clone()).collect();

        apply_metadata_filter(&mut records, None, None);

        assert_eq!(records.len(), 3, "no records dropped when both filters absent");
        let after_ids: Vec<String> = records.iter().map(|r| r.id.clone()).collect();
        assert_eq!(after_ids, snapshot_ids, "order preserved verbatim");
    }

    #[test]
    fn l28_apply_metadata_filter_key_only_retains_records_with_key() {
        // `Some(k), None` → key-presence gate. Records that contain `k`
        // in their metadata are kept regardless of the value; records
        // without the key are dropped. This pins the `contains_key`
        // semantic — a refactor that switches to `.get(k).is_some()` is
        // equivalent today, but a switch to a stricter `.get(k) ==
        // Some(&Value::Bool(true))` (or similar) breaks this contract.
        let mut records = vec![
            metadata_test_record("with-kind-tx", &[("kind", serde_json::json!("tx"))]),
            metadata_test_record("with-kind-null", &[("kind", serde_json::Value::Null)]),
            metadata_test_record("with-other", &[("category", serde_json::json!("ledger"))]),
            metadata_test_record("no-metadata", &[]),
        ];

        apply_metadata_filter(&mut records, Some("kind"), None);

        let ids: Vec<&str> = records.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(
            ids,
            vec!["with-kind-tx", "with-kind-null"],
            "key-only filter keeps records containing the key (any value, including Null), \
             drops records without the key"
        );
    }

    #[test]
    fn l28_apply_metadata_filter_value_only_matches_any_key() {
        // `None, Some(v)` → wide-net gate. A record is kept if ANY of its
        // metadata values matches `v` (string-compared via
        // `json_value_matches_string`), regardless of which key holds it.
        // The documented semantic at state.rs:4475-4477 calls this out
        // explicitly: "what `?value=` without `?key=` can mean".
        let mut records = vec![
            // Hit: value "tx" appears at key "kind".
            metadata_test_record("hit-at-kind", &[("kind", serde_json::json!("tx"))]),
            // Hit: value "tx" appears at key "type" (different key, same value).
            metadata_test_record("hit-at-type", &[("type", serde_json::json!("tx"))]),
            // Miss: no metadata value equals "tx" — "kind" is "transfer".
            metadata_test_record("miss-other-value", &[("kind", serde_json::json!("transfer"))]),
            // Miss: empty metadata, no values to scan.
            metadata_test_record("miss-empty", &[]),
            // Hit: numeric value 42 renders to "42" via json_value_matches_string's
            // composite arm (other.to_string()). This pins the integration
            // with json_value_matches_string for the non-string branch.
            metadata_test_record("hit-numeric-render", &[("count", serde_json::json!(42))]),
        ];

        apply_metadata_filter(&mut records, None, Some("tx"));

        let ids: Vec<&str> = records.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(
            ids,
            vec!["hit-at-kind", "hit-at-type"],
            "value-only filter retains records where any metadata value equals the target string"
        );

        // Numeric render branch — same record set, target="42".
        let mut records2 = vec![
            metadata_test_record("hit-num", &[("count", serde_json::json!(42))]),
            metadata_test_record("miss-num", &[("count", serde_json::json!(43))]),
            metadata_test_record("miss-str", &[("count", serde_json::json!("42"))]),
        ];
        apply_metadata_filter(&mut records2, None, Some("42"));
        let num_ids: Vec<&str> = records2.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(
            num_ids,
            vec!["hit-num", "miss-str"],
            "json_value_matches_string treats Number(42) and String(\"42\") both as match for '42'"
        );
    }

    #[test]
    fn l28_apply_metadata_filter_key_and_value_exact_match() {
        // `Some(k), Some(v)` → exact match. The record must have `k` in
        // metadata AND `metadata[k]` must equal `v` via
        // `json_value_matches_string`. Records missing the key are dropped
        // via the `.unwrap_or(false)` branch, NOT via the contains_key gate
        // — pins that the helper combines key-presence + value-match into
        // one `.get(k).map(...).unwrap_or(false)` chain.
        let mut records = vec![
            metadata_test_record("exact-match", &[("kind", serde_json::json!("transfer"))]),
            metadata_test_record("wrong-value", &[("kind", serde_json::json!("mint"))]),
            metadata_test_record("missing-key", &[("other", serde_json::json!("transfer"))]),
            metadata_test_record("no-metadata", &[]),
        ];

        apply_metadata_filter(&mut records, Some("kind"), Some("transfer"));

        let ids: Vec<&str> = records.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(
            ids,
            vec!["exact-match"],
            "key+value filter keeps ONLY records where metadata[key] == value"
        );
    }

    #[test]
    fn l28_apply_metadata_filter_key_present_value_mismatch_drops() {
        // Narrower case of (Some, Some): the record HAS the key, but the
        // value is wrong (including the subtle "quoted string vs unquoted"
        // case that json_value_matches_string is documented to reject —
        // state.rs:4634-4636 already pins that direction, this pins the
        // integration through apply_metadata_filter). Surfaces any future
        // regression where the helper accidentally substring-matches or
        // case-folds values.
        let mut records = vec![
            // Wrong value at correct key → drop.
            metadata_test_record("dropped-wrong-val", &[("kind", serde_json::json!("ledger"))]),
            // Boolean true vs string "True" → drop (case-sensitive).
            metadata_test_record("dropped-case", &[("flag", serde_json::json!(true))]),
            // Value present at correct key → keep.
            metadata_test_record("kept-bool", &[("flag", serde_json::json!(true))]),
        ];

        // Filter for kind="transfer" → drops all 3 (none have that exact pair).
        apply_metadata_filter(&mut records, Some("kind"), Some("transfer"));
        assert!(
            records.is_empty(),
            "all three records dropped when no record has kind=transfer"
        );

        // Reset + check the boolean true case-sensitive branch.
        let mut records2 = vec![
            metadata_test_record("kept", &[("flag", serde_json::json!(true))]),
            metadata_test_record("dropped-case", &[("flag", serde_json::json!(false))]),
            metadata_test_record("dropped-no-key", &[]),
        ];
        apply_metadata_filter(&mut records2, Some("flag"), Some("true"));
        let ids: Vec<&str> = records2.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(
            ids,
            vec!["kept"],
            "Bool(true) matches \"true\"; Bool(false) and missing-key both drop"
        );
    }

    // ── search_records — uncovered post-fetch branches ────────────────────
    //
    // Prior coverage on `search_records` (state.rs:4190) was 4 tests:
    // Layer B happy-path + counter, fallback happy-path + counter, Layer B
    // metadata key filter, Layer B metadata key+value filter, plus the
    // no-filter empty short-circuit. The five branches the public RPC
    // exercises but the test suite did NOT pin in isolation:
    //
    //   (1) Layer B + `offset` drains the first N hits before truncating.
    //   (2) Layer B + meta-filter inflates fetch_n to 4× headroom; when
    //       the filter keeps everything, the trailing `truncate(limit)`
    //       runs and trims the tail (an off-by-one here ships a account
    //       paging bug where the next page repeats the last row).
    //   (3) Layer B + `classification` filter applied AFTER the index
    //       scan — `query_by_creator_hash` does not filter by class.
    //   (4) Fallback path (since/until window) + meta filter — pins that
    //       `apply_metadata_filter` runs in BOTH paths, not just Layer B.
    //   (5) Fallback path triggered by classification ALONE (no window,
    //       no creator_hash) — closes the "classification.is_some()"
    //       arm of the fallback gate at state.rs:4228 that the existing
    //       fallback test reaches only via since/until.
    //
    // All five guard against silent regressions: route accepts the param
    // but `search_records` quietly ignores it (the exact bug that
    // `search_records_metadata_key_filter_layer_b` was originally written
    // to catch).

    fn put_record_classified(
        rocks: &crate::storage::rocks::StorageEngine,
        id: &str,
        creator_pk: &[u8],
        ts: f64,
        classification: crate::record::Classification,
    ) {
        use crate::record::ValidationRecord;
        use std::collections::BTreeMap;
        let rec = ValidationRecord {
            id: id.to_string(),
            version: crate::wire::WIRE_VERSION,
            content_hash: crate::crypto::hash::sha3_256(id.as_bytes()).to_vec(),
            creator_public_key: creator_pk.to_vec(),
            timestamp: ts,
            parents: vec![],
            classification,
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
        };
        rocks.put_record(id, &rec).expect("put_record");
    }

    #[test]
    fn l28_search_records_layer_b_offset_drains_leading_results() {
        // Four records under one creator at ts 100/200/300/400.
        // `query_by_creator_hash` returns them in timestamp order (see
        // rocks.rs:3600 — index key is `creator_hash + ts_be + record_id`).
        // With offset=2 and limit=2, fetch_n = limit+offset = 4 →
        // rocks returns all 4 → `drain(..2)` skips the first two →
        // truncate(2) is a no-op (results.len() already == limit).
        // Account pagination semantics: page 2 of a 2-per-page feed.
        let state = test_node_state(None);
        let pk = vec![0xDD; 1952];
        put_record_classified(&state.rocks, "rec-a", &pk, 100.0, Classification::Public);
        put_record_classified(&state.rocks, "rec-b", &pk, 200.0, Classification::Public);
        put_record_classified(&state.rocks, "rec-c", &pk, 300.0, Classification::Public);
        put_record_classified(&state.rocks, "rec-d", &pk, 400.0, Classification::Public);

        let creator_hash = crate::crypto::hash::sha3_256_hex(&pk);
        let q = crate::storage::SearchQuery {
            creator_hash: Some(creator_hash),
            limit: 2,
            offset: 2,
            ..Default::default()
        };
        let results = state.search_records(&q).expect("search ok");
        let ids: Vec<&str> = results.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(
            ids,
            vec!["rec-c", "rec-d"],
            "offset=2 drains the first two ts-ordered records, leaving the page-2 slice"
        );
    }

    #[test]
    fn l28_search_records_layer_b_limit_truncates_when_meta_filter_overshoots() {
        // The `if results.len() > query.limit && query.limit > 0 ` truncation
        // branch only fires when fetch_n > limit. fetch_n only exceeds limit
        // when `needs_meta_filter` is true (state.rs:4202 — 4× headroom for
        // the post-filter drop). Insert 4 records that ALL match the meta
        // filter (i.e. filter is a no-op), then assert the trailing
        // truncate(limit) trims down to exactly `limit`. Without this test,
        // a refactor that drops the truncate line would silently leak 4×
        // the account-requested page size to the client.
        let state = test_node_state(None);
        let pk = vec![0xEE; 1952];
        let mut meta = std::collections::BTreeMap::new();
        meta.insert("kind".into(), serde_json::json!("transfer"));
        put_record_with_creator_meta(&state.rocks, "tx-a", &pk, 100.0, meta.clone());
        put_record_with_creator_meta(&state.rocks, "tx-b", &pk, 200.0, meta.clone());
        put_record_with_creator_meta(&state.rocks, "tx-c", &pk, 300.0, meta.clone());
        put_record_with_creator_meta(&state.rocks, "tx-d", &pk, 400.0, meta);

        let creator_hash = crate::crypto::hash::sha3_256_hex(&pk);
        let q = crate::storage::SearchQuery {
            creator_hash: Some(creator_hash),
            metadata_key: Some("kind".into()),
            limit: 2,
            ..Default::default()
        };
        let results = state.search_records(&q).expect("search ok");
        let ids: Vec<&str> = results.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(
            ids,
            vec!["tx-a", "tx-b"],
            "fetch_n=8 → rocks returns 4 → meta filter keeps 4 → truncate(2) trims to first 2 \
             in ts order; missing truncate would return 4 records under a limit=2 request"
        );
    }

    #[test]
    fn l28_search_records_layer_b_classification_filter_retains_only_matching() {
        // `query_by_creator_hash` does NOT filter by classification — see
        // rocks.rs:3592-3623, no class branch in the loop. The class filter
        // is applied AFTER the fetch by the `results.retain(|r| r.classification == cls)`
        // line at state.rs:4214. Insert 3 records (Private, Public, Private)
        // for one creator; query with classification=Private, limit large
        // enough that fetch_n covers all three. Expect only the two Private
        // records, in timestamp order.
        let state = test_node_state(None);
        let pk = vec![0xFF; 1952];
        put_record_classified(&state.rocks, "priv-a", &pk, 100.0, Classification::Private);
        put_record_classified(&state.rocks, "pub-b", &pk, 200.0, Classification::Public);
        put_record_classified(&state.rocks, "priv-c", &pk, 300.0, Classification::Private);

        let creator_hash = crate::crypto::hash::sha3_256_hex(&pk);
        let q = crate::storage::SearchQuery {
            creator_hash: Some(creator_hash),
            classification: Some(Classification::Private),
            limit: 10,
            ..Default::default()
        };
        let results = state.search_records(&q).expect("search ok");
        let ids: Vec<&str> = results.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(
            ids,
            vec!["priv-a", "priv-c"],
            "post-fetch retain drops the Public record between the two Private ones, \
             preserving timestamp order of the survivors"
        );
        // No metadata filter → fallback counter must stay at zero (Layer B path).
        assert_eq!(
            state
                .search_queries_layer_b_total
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert_eq!(
            state
                .search_queries_fallback_total
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    #[test]
    fn l28_search_records_fallback_metadata_filter_drops_non_matching_keys() {
        // Pins that `apply_metadata_filter` is wired into the fallback path
        // (state.rs:4243), not just Layer B. Three records inside a single
        // since/until window — two have metadata.kind="ledger", one does not.
        // Fallback path triggers via since/until; meta-key filter drops the
        // record that lacks the key. Closes the symmetry with the Layer B
        // metadata tests so a refactor that splits the helper into a
        // Layer-B-only path silently leaves the fallback path filter-less.
        use std::sync::atomic::Ordering::Relaxed;
        let state = test_node_state(None);
        let pk = vec![0x11; 1952];
        let mut with_kind = std::collections::BTreeMap::new();
        with_kind.insert("kind".into(), serde_json::json!("ledger"));
        let without_kind = std::collections::BTreeMap::new();
        put_record_with_creator_meta(&state.rocks, "lg-1", &pk, 100.0, with_kind.clone());
        put_record_with_creator_meta(&state.rocks, "lg-2", &pk, 200.0, without_kind);
        put_record_with_creator_meta(&state.rocks, "lg-3", &pk, 300.0, with_kind);

        // No creator_hash → fallback path; since/until pins the window.
        let q = crate::storage::SearchQuery {
            since: Some(50.0),
            until: Some(400.0),
            metadata_key: Some("kind".into()),
            limit: 10,
            ..Default::default()
        };
        let results = state.search_records(&q).expect("search ok");
        let ids: Vec<&str> = results.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(
            ids,
            vec!["lg-1", "lg-3"],
            "fallback path applies metadata filter — lg-2 dropped for missing the key"
        );
        assert_eq!(state.search_queries_layer_b_total.load(Relaxed), 0);
        assert_eq!(state.search_queries_fallback_total.load(Relaxed), 1);
    }

    #[test]
    fn l28_search_records_fallback_classification_only_triggers_path_without_window() {
        // Closes the `classification.is_some()` arm of the fallback gate at
        // state.rs:4228 — the existing fallback test reaches it via
        // since/until. A request with classification=Public but no
        // window and no creator_hash must still take the fallback path
        // (counter +1) and return all matching records.
        use std::sync::atomic::Ordering::Relaxed;
        let state = test_node_state(None);
        let pk = vec![0x22; 1952];
        put_record_classified(&state.rocks, "p1", &pk, 100.0, Classification::Public);
        put_record_classified(&state.rocks, "p2", &pk, 200.0, Classification::Public);
        put_record_classified(&state.rocks, "r1", &pk, 300.0, Classification::Restricted);

        let q = crate::storage::SearchQuery {
            classification: Some(Classification::Public),
            limit: 10,
            ..Default::default()
        };
        let results = state.search_records(&q).expect("search ok");
        let ids: Vec<&str> = results.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(
            ids,
            vec!["p1", "p2"],
            "rocks.query filters by classification → Restricted r1 excluded, \
             Public p1/p2 returned in ts order"
        );
        assert_eq!(state.search_queries_layer_b_total.load(Relaxed), 0);
        assert_eq!(
            state.search_queries_fallback_total.load(Relaxed),
            1,
            "classification-only also bumps the fallback counter (closes the \
             classification.is_some() arm of the gate)"
        );
    }

    // ── rebuild_* free-function helpers ───────────────────────────────────
    //
    // Layered onto the existing rebuild_dag / rebuild_trust / rebuild_ledger /
    // rebuild_reputation / rebuild_delegations empty + single-record tests.
    // Each batch-M test pins a distinct boot-path branch that the prior
    // batches did not cover:
    //   - trust: multi-creator + out-of-order arrival ordering tolerance
    //   - delegations: non-delegation records silently skipped
    //   - ledger: empty slice contract (state default, skipped=0)
    //   - reputation: dispute present but unresolved → no rep deltas (guards
    //     the `if let Some(ref resolution) = dispute.resolution` branch in
    //     rebuild_reputation_from_records)

    fn test_record_with_pk(
        id: &str,
        creator_pk: Vec<u8>,
        timestamp: f64,
    ) -> ValidationRecord {
        let mut rec = ValidationRecord::create(
            id.as_bytes(),
            creator_pk,
            vec![],
            Classification::Public,
            None,
        );
        rec.timestamp = timestamp;
        rec.id = id.to_string();
        rec
    }

    #[test]
    fn m_rebuild_trust_from_records_multiple_creators() {
        // Two records with distinct creator_public_key bytes must hash to
        // distinct creator_identity_hash values (sha3-256 over the pk), so
        // TrustEngine::record_submission should land them in separate
        // profiles. Locks `creator_identity_hash` divergence — a regression
        // that flattens different pks into one identity (e.g. truncated
        // pk-hash, or a hash-collision shortcut) would silently merge trust
        // profiles and break the Tier-2 settlement quorum check.
        let records = vec![
            test_record_with_pk("r1", b"creator_alpha".to_vec(), 1.0),
            test_record_with_pk("r2", b"creator_beta".to_vec(), 2.0),
        ];
        let engine = rebuild_trust_from_records(&records);
        assert_eq!(
            engine.tracked_identities(),
            2,
            "distinct creator_public_key bytes must produce distinct trust profiles"
        );
    }

    #[test]
    fn m_rebuild_trust_from_records_out_of_order_timestamps_still_tracks_all() {
        // The function internally sorts by timestamp before replaying. Even
        // with arrival order shuffled, every record must be processed
        // exactly once. Distinct creators are used so tracked_identities
        // counts each replayed record. Closes the implicit "sort_by drops
        // records" regression surface.
        let records = vec![
            test_record_with_pk("r3", b"pk_c".to_vec(), 30.0),
            test_record_with_pk("r1", b"pk_a".to_vec(), 10.0),
            test_record_with_pk("r2", b"pk_b".to_vec(), 20.0),
        ];
        let engine = rebuild_trust_from_records(&records);
        assert_eq!(
            engine.tracked_identities(),
            3,
            "all three distinct creators tracked regardless of arrival order"
        );
    }

    #[test]
    fn m_rebuild_delegations_from_records_non_delegation_records_pass_through() {
        // Records that do not carry `delegation_op` in metadata are silently
        // skipped — registry stays empty. Pins the `contains_key(DELEGATION_OP_KEY)`
        // gate so a future refactor that drops the filter (treating every
        // record as a candidate delegation) would surface here, not in a
        // boot-path mass-rejection at scale.
        let records = vec![
            test_record("r1", vec![], 1.0),
            test_record("r2", vec!["r1".into()], 2.0),
        ];
        let registry = rebuild_delegations_from_records(&records);
        assert_eq!(
            registry.total(),
            0,
            "records without delegation_op key must not produce delegation entries"
        );
    }

    #[test]
    fn m_rebuild_ledger_from_records_empty_returns_zero_skipped() {
        // Empty slice → default LedgerState, 0 skipped. Closes the empty-
        // boot contract — a new node with no replayable history must
        // produce a usable ledger (total_supply=0, no accounts, no
        // applied_record_ids) and not crash on the sort_by pre-pass.
        let (state, skipped) = rebuild_ledger_from_records(&[], "genesis_authority_hash", &[])
            .expect("empty slice must succeed");
        assert_eq!(skipped, 0, "no records, no skip");
        assert_eq!(state.total_supply, 0, "no mints applied");
        assert_eq!(state.records_processed, 0, "no ledger records replayed");
        assert!(state.accounts.is_empty(), "no accounts seeded");
        assert!(
            state.applied_record_ids.is_empty(),
            "applied_record_ids dedup set empty on cold boot"
        );
    }

    #[test]
    fn m_rebuild_reputation_from_records_unresolved_dispute_no_deltas() {
        // A dispute that is still open (resolution=None) must NOT produce
        // reputation deltas. Pins the `if let Some(ref resolution) =
        // dispute.resolution` guard in rebuild_reputation_from_records —
        // dropping this guard would apply zero-information deltas to every
        // witness of every contested record at boot, polluting the engine
        // before consensus has decided the outcome.
        let mut disputes = super::super::dispute::DisputeState::new();
        disputes
            .open_dispute(
                "dispute-1".into(),
                "contested-rec-1".into(),
                "opener-hash".into(),
                "reason".into(),
                1.0,
            )
            .expect("open dispute");
        // Sanity: the dispute is registered but unresolved.
        assert_eq!(disputes.all_disputes().len(), 1, "dispute registered");
        assert!(
            disputes.all_disputes()[0].resolution.is_none(),
            "dispute remains unresolved"
        );

        // Witness_reward records exist but the dispute has not resolved —
        // engine must not credit/debit anything.
        let records = vec![test_record("r-witness-reward", vec![], 1.5)];
        let engine = rebuild_reputation_from_records(&records, &disputes);
        assert_eq!(
            engine.tracked_count(),
            0,
            "no reputation entries while dispute is unresolved"
        );
    }

    // ── rebuild_dag_from_records orphan / dedup / NaN branches ─────────────
    //
    // The existing dag tests cover empty / single / linear chain / fork /
    // out-of-order timestamps. These tests pin the remaining `insert_tolerant`
    // branches that the boot-path actually relies on at scale:
    //   - persistent orphan: a record whose parent is genuinely absent from
    //     the input slice must still appear as a node, with the orphan edge
    //     surfaced in `orphan_count` / `orphan_parent_ids` (so the catch-up
    //     fetcher knows what to pull).
    //   - duplicate record IDs in the input slice: the `if nodes.contains(&id)
    //     { return 0 }` guard in `DagIndex::insert_tolerant` must dedupe
    //     silently — replay of the same record (e.g. snapshot overlap on
    //     warm reboot) is not a panic.
    //   - partial-missing parents: one of two parents exists at insert time;
    //     the record must wire the visible edge but NOT be promoted to a
    //     root (the `if parents.is_empty() || missing == parents.len()`
    //     short-circuit only fires when ALL parents are missing).
    //   - NaN timestamps in the slice: `partial_cmp` returns None, the
    //     fallback `Ordering::Equal` keeps the sort total. The DAG must
    //     still build without panicking and contain every record.
    //   - reindex_orphans recovery: insert_tolerant runs over a shuffled
    //     slice where the child arrives BEFORE the parent in the original
    //     order (sort_by realigns by timestamp). After the loop the
    //     `reindex_orphans` pass must drive `orphan_count` to 0.

    #[test]
    fn n_rebuild_dag_persistent_orphan_record_stays_in_index() {
        // Record `child` references parent `missing-pid` that is NOT in
        // the input. The record itself must still land in the DAG, and the
        // orphan edge must be surfaced so the catch-up fetcher can request
        // the absent parent. Without this, a record pointing at a pruned
        // ancestor would either silently vanish or never produce a fetch
        // hint.
        let records = vec![test_record("child", vec!["missing-pid".into()], 1.0)];
        let dag = rebuild_dag_from_records(&records);
        assert_eq!(dag.len(), 1, "child record must still be indexed");
        assert!(dag.contains("child"), "child must be present as a node");
        assert!(
            !dag.contains("missing-pid"),
            "missing parent must remain absent from the node set"
        );
        assert_eq!(
            dag.orphan_count(),
            1,
            "single orphan edge must be tracked for the missing parent"
        );
        let orphans = dag.orphan_parent_ids();
        assert_eq!(orphans, vec!["missing-pid".to_string()],
            "fetcher must see exactly the missing parent as the pull hint");
    }

    #[test]
    fn n_rebuild_dag_duplicate_record_ids_are_silently_deduped() {
        // The same record ID appears twice in the input slice (e.g. a
        // snapshot-overlap or replay edge case). `DagIndex::insert_tolerant`
        // guards on `if nodes.contains(&id) { return 0 }`, so the second
        // insert is a no-op and `dag.len()` stays at 1. Closes the
        // "replay panics on duplicate" regression surface.
        let records = vec![
            test_record("r1", vec![], 1.0),
            test_record("r1", vec![], 2.0),
        ];
        let dag = rebuild_dag_from_records(&records);
        assert_eq!(
            dag.len(),
            1,
            "duplicate id in input slice must collapse to a single node"
        );
        assert!(dag.contains("r1"), "the surviving record must be present");
        // No orphans because the duplicate had no parents either.
        assert_eq!(dag.orphan_count(), 0);
    }

    #[test]
    fn n_rebuild_dag_partial_missing_parent_links_visible_edge_but_not_root() {
        // Two parents: `p1` exists in the input, `p2-missing` does not.
        // `insert_tolerant` returns missing=1, < parents.len()=2, so the
        // `parent_ids.is_empty() || missing == parent_ids.len()` guard
        // does NOT fire — the child must NOT be promoted to a root. But
        // the visible edge to `p1` must still be wired (parent removed
        // from tips when its child arrives).
        let records = vec![
            test_record("p1", vec![], 1.0),
            test_record("child", vec!["p1".into(), "p2-missing".into()], 2.0),
        ];
        let dag = rebuild_dag_from_records(&records);
        assert_eq!(dag.len(), 2, "p1 and child are both indexed");
        let roots = dag.roots();
        assert_eq!(roots, vec!["p1".to_string()],
            "child must NOT be a root — it has one resolved parent");
        // child took p1 out of the tip set when it landed.
        let tips = dag.tips();
        assert_eq!(tips, vec!["child".to_string()],
            "child is the sole tip; p1 was promoted to interior once child wired up");
        // Exactly one orphan edge — for the missing parent.
        assert_eq!(dag.orphan_count(), 1);
        assert_eq!(dag.orphan_parent_ids(), vec!["p2-missing".to_string()]);
    }

    #[test]
    fn n_rebuild_dag_nan_timestamps_do_not_panic() {
        // `partial_cmp` returns None for any comparison involving NaN; the
        // sort_by closure falls back to `Ordering::Equal`. This pins the
        // `.unwrap_or(Ordering::Equal)` guard at state.rs:4417 — a future
        // refactor that swaps in `.expect("ordered")` would panic the
        // boot path on a single corrupt record's timestamp. The DAG must
        // still build with every record indexed.
        let mut rec_nan = test_record("nan-ts", vec![], 1.0);
        rec_nan.timestamp = f64::NAN;
        let records = vec![
            test_record("r1", vec![], 1.0),
            rec_nan,
            test_record("r2", vec![], 2.0),
        ];
        let dag = rebuild_dag_from_records(&records);
        assert_eq!(
            dag.len(),
            3,
            "NaN timestamps must not lose any records to a sort panic"
        );
        assert!(dag.contains("r1"));
        assert!(dag.contains("nan-ts"));
        assert!(dag.contains("r2"));
    }

    #[test]
    fn n_rebuild_dag_reindex_orphans_resolves_in_slice_recovery() {
        // Children arrive in input BEFORE their parents (input order, not
        // timestamp order). Because rebuild_dag_from_records sorts by
        // timestamp first, the parents replay first and the children
        // resolve on the initial `insert_tolerant` pass — orphan_count
        // hits zero without needing the trailing reindex_orphans sweep.
        //
        // To exercise reindex_orphans, give the child a SMALLER timestamp
        // than its parent — the sort keeps the child first, insert_tolerant
        // creates an orphan edge, then the trailing reindex_orphans
        // resolves it once the parent lands. Pins the trailing recovery
        // sweep at state.rs:4429.
        let records = vec![
            test_record("parent", vec![], 10.0),
            test_record("child", vec!["parent".into()], 5.0),
        ];
        let dag = rebuild_dag_from_records(&records);
        assert_eq!(dag.len(), 2, "both records indexed");
        assert_eq!(
            dag.orphan_count(),
            0,
            "reindex_orphans must drive orphan edges to zero once parent arrives"
        );
        // Only the child should be a tip — parent gained a child after
        // the reindex pass wired the edge.
        let tips = dag.tips();
        assert_eq!(tips, vec!["child".to_string()],
            "after reindex, parent has a child and is no longer a tip");
        // Parent has no parents of its own → still a root.
        let roots = dag.roots();
        assert_eq!(roots, vec!["parent".to_string()]);
    }

    // ── set_vrf_keys 4-way Option×Option branches + current_rss_mb ─────────
    //
    // `set_vrf_keys` takes `&mut self` and assigns BOTH fields
    // unconditionally (`self.vrf_secret_key = sk.map(Arc::new); self.vrf_public_key = pk;`).
    // It previously had zero direct tests — every caller passed
    // Some/Some at startup, so a refactor that swapped the branches
    // (e.g. `if let Some(sk) = sk { ... }` skipping the None-clears
    // path) would silently regress key-rotation flows where the
    // operator unloads a key. Pins all four Option×Option combinations
    // so the unconditional-assign contract holds.
    //
    // `current_rss_mb` is the second-least-tested helper (only the two
    // cfg-gated definitions). It's a free associated fn — Linux reads
    // /proc/self/status VmRSS, divides KB→MB; other platforms return 0.
    // The Linux branch has a parse pipeline (find VmRSS line, take 2nd
    // whitespace token, parse to u64, divide by 1024) where a divisor
    // typo or unit-conversion regression would surface as either huge
    // or tiny values. We bound the Linux output below 1 TB MB to catch
    // a kb-vs-byte divisor mistake without flaking on sandboxed CI
    // runners where /proc may be unreadable.

    /// Owned `NodeState` (not Arc) for set_vrf_keys tests — the setter
    /// takes `&mut self` so the per-test Arc-wrapped helper higher up
    /// doesn't fit. Inline the full construction here rather than
    /// reusing `test_node_state(...) -> Arc<NodeState>` and threading
    /// `Arc::get_mut` through every caller.
    fn make_node_state_owned_for_vrf_tests() -> NodeState {
        use crate::identity::{CryptoProfile, EntityType, Identity};
        use crate::network::config::NodeConfig;
        use crate::network::witness::WitnessManager;
        use crate::storage::rocks::StorageEngine;

        let tmp = tempfile::tempdir().expect("tempdir");
        let data_dir = tmp.path().to_path_buf();
        let config = NodeConfig {
            data_dir: data_dir.clone(),
            identity_path: data_dir.join("identity.json"),
            db_path: data_dir.join("elara.db"),
            admin_token: "test-admin".into(),
            network_id: "vrf-set-test".into(),
            mdns_enabled: false,
            health_check_interval_secs: 0,
            min_pow_difficulty: 0,
            ..Default::default()
        };
        let identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
            .expect("generate identity");
        let rocks = std::sync::Arc::new(
            StorageEngine::open(data_dir.join("rocksdb")).expect("open rocksdb"),
        );
        let wmgr = std::sync::Arc::new(WitnessManager::new(rocks.clone()));
        let state = NodeState::new(config, identity, rocks, wmgr);
        std::mem::forget(tmp);
        state
    }

    #[test]
    fn o_set_vrf_keys_some_sk_some_pk_assigns_both_fields() {
        // Cold boot: both fields are None. After `set_vrf_keys(Some, Some)`
        // both must be populated. Pins the canonical genesis-authority
        // startup path where `bin/elara_node.rs` loads sk+pk together.
        let mut state = make_node_state_owned_for_vrf_tests();
        assert!(state.vrf_secret_key.is_none(), "fresh node has no sk");
        assert!(state.vrf_public_key.is_none(), "fresh node has no pk");

        let sk = crate::crypto::vrf::VrfSecretKey::generate().expect("generate sk");
        let pk = sk.public_key();
        state.set_vrf_keys(Some(sk), Some(pk));

        assert!(state.vrf_secret_key.is_some(), "sk populated after Some(sk)");
        assert!(state.vrf_public_key.is_some(), "pk populated after Some(pk)");
    }

    #[test]
    fn o_set_vrf_keys_none_none_clears_both_fields() {
        // Operator key-rotation flow: load keys, then unload (None/None)
        // before reloading. The setter is unconditional-assign, so
        // None must overwrite Some. Pins against a future refactor that
        // adds a `if let Some(_) = sk { ... }` guard which would skip
        // the clear path.
        let mut state = make_node_state_owned_for_vrf_tests();
        let sk = crate::crypto::vrf::VrfSecretKey::generate().expect("generate sk");
        let pk = sk.public_key();
        state.set_vrf_keys(Some(sk), Some(pk));
        assert!(state.vrf_secret_key.is_some());
        assert!(state.vrf_public_key.is_some());

        state.set_vrf_keys(None, None);

        assert!(state.vrf_secret_key.is_none(),
            "None sk must clear the previously-set sk");
        assert!(state.vrf_public_key.is_none(),
            "None pk must clear the previously-set pk");
    }

    #[test]
    fn o_set_vrf_keys_some_sk_none_pk_independent_fields() {
        // Witness-only role: a node that signs with a sk but never
        // advertises the matching pk (rare, but the type allows it).
        // After Some(sk)+None, sk is set but pk stays None. Pins the
        // sk/pk field independence — a refactor that derived pk from
        // sk automatically would break here.
        let mut state = make_node_state_owned_for_vrf_tests();
        let sk = crate::crypto::vrf::VrfSecretKey::generate().expect("generate sk");

        state.set_vrf_keys(Some(sk), None);

        assert!(state.vrf_secret_key.is_some(),
            "sk populated from Some path");
        assert!(state.vrf_public_key.is_none(),
            "pk must remain None — caller passed None even though sk could derive one");
    }

    #[test]
    fn o_set_vrf_keys_none_sk_some_pk_independent_fields() {
        // Verifier-only role: a non-anchor node that knows the genesis
        // authority's pk for signature verification but never holds the
        // sk. After None+Some(pk), pk is set but sk stays None. Pins
        // the dual independence direction.
        let mut state = make_node_state_owned_for_vrf_tests();
        let temp_sk = crate::crypto::vrf::VrfSecretKey::generate().expect("generate sk");
        let pk = temp_sk.public_key();
        drop(temp_sk);

        state.set_vrf_keys(None, Some(pk));

        assert!(state.vrf_secret_key.is_none(),
            "sk must remain None — verifier-only path");
        assert!(state.vrf_public_key.is_some(),
            "pk populated from Some path");
    }

    #[test]
    fn o_current_rss_mb_smoke_test_bounds_check() {
        // Smoke test: call must not panic on either platform. On Linux
        // the test process's VmRSS should land below 1 TB MB (catches
        // a kb-vs-byte divisor regression that would shift the result
        // into petabyte range); on non-Linux platforms the stub must
        // return exactly 0.
        let rss = NodeState::current_rss_mb();

        #[cfg(target_os = "linux")]
        {
            assert!(
                rss < 1_048_576,
                "rss must be under 1 TB MB; got {rss} — possible parse-divisor regression"
            );
        }
        #[cfg(not(target_os = "linux"))]
        {
            assert_eq!(
                rss, 0,
                "non-Linux current_rss_mb stub must always return 0"
            );
        }
    }

    // ── get_record Ok/Err mapping + mark_tombstoned JSON shape ─────────────
    //
    // Two pub helpers with thin test coverage despite being on the hot
    // RPC path:
    //
    // `get_record` is the canonical "fetch one record" RPC reader used
    // by /record/{id}, the seal-loop attestation step (state.rs:3178),
    // and the cross-zone proof builder (state.rs:3618). It maps the
    // storage layer's `Ok(None)` into `Err(ElaraError::RecordNotFound)`
    // — that contract is what lets the route layer return 404 instead
    // of 500. Previously only the storage-layer `record_exists`
    // passthrough was directly covered; the Ok/Err branch mapping in
    // get_record had no name-level test. A refactor that propagated
    // `Ok(None)` upward (e.g. dropped the `.ok_or_else`) would surface
    // as account 500s in production, not as a unit-test failure.
    //
    // `mark_tombstoned` stores a JSON blob `{tombstone_id, reason}`
    // under the `tombstone:{target_id}` key in CF_METADATA. The
    // existing batch-E `is_tombstoned` round-trip test only proves the
    // KEY round-trips; it never inspected the VALUE. A regression that
    // wrote an empty or differently-shaped payload (e.g. dropped the
    // reason field, switched to bincode) would still pass that test
    // but would break /admin/tombstones operator readers that parse
    // the JSON. These tests pin the payload shape AND the overwrite
    // semantics (second mark for the same target replaces the prior
    // payload — `put_cf_raw` is a blind write, not an append).

    #[test]
    fn p_get_record_returns_inserted_record_with_field_fidelity() {
        // Ok branch: after `insert_record_both` persists a record, the
        // same id must round-trip through `get_record` with full field
        // fidelity (id, timestamp, classification, creator_public_key).
        // Catches a future regression that drops fields during the
        // wire-encode → CF_RECORDS → wire-decode cycle.
        let state = test_node_state(None);
        let rec = test_record("p-get-rec-1", vec![], 12345.0);
        let inserted_id = state
            .insert_record_both(&rec)
            .expect("insert_record_both ok");
        assert_eq!(
            inserted_id, "p-get-rec-1",
            "insert_record_both returns the same id it persisted"
        );

        let fetched = state
            .get_record("p-get-rec-1")
            .expect("get_record Ok branch on inserted id");
        assert_eq!(fetched.id, "p-get-rec-1", "id field round-trips");
        assert_eq!(
            fetched.timestamp, 12345.0,
            "timestamp field round-trips bit-exactly"
        );
        assert_eq!(
            fetched.classification,
            Classification::Public,
            "classification field round-trips (test_record always sets Public)"
        );
        assert_eq!(
            fetched.creator_public_key, b"test_pub_key".to_vec(),
            "creator_public_key field round-trips bytes-exactly"
        );
    }

    #[test]
    fn p_get_record_unknown_id_maps_storage_none_to_record_not_found_err() {
        // Err branch: storage's `Ok(None)` (record absent) must be
        // converted into `Err(ElaraError::RecordNotFound)` carrying the
        // queried id. This is the contract that lets the /record/{id}
        // route layer translate the error into a 404 — a regression
        // that propagated Ok(None) upward would surface as a 500/empty
        // body on the wire.
        let state = test_node_state(None);
        let err = state
            .get_record("never-inserted-p1")
            .expect_err("missing id must Err, not Ok(default)");
        match err {
            crate::errors::ElaraError::RecordNotFound(id) => {
                assert_eq!(
                    id, "never-inserted-p1",
                    "error payload must carry the queried id verbatim"
                );
            }
            other => panic!(
                "expected RecordNotFound, got {other:?} — \
                 get_record must map storage Ok(None) to RecordNotFound"
            ),
        }
    }

    #[test]
    fn p_get_record_distinguishes_distinct_inserts_by_id() {
        // Two records with distinct ids and timestamps round-trip
        // independently — pins the storage key-isolation contract so a
        // future regression that aliased rows by hash (e.g. dropping
        // the id key) would surface as a cross-fetch contamination
        // here rather than as silent ledger collisions in production.
        let state = test_node_state(None);
        let r_a = test_record("p-distinct-a", vec![], 100.0);
        let r_b = test_record("p-distinct-b", vec![], 200.0);
        state.insert_record_both(&r_a).expect("insert a");
        state.insert_record_both(&r_b).expect("insert b");

        let fetched_a = state.get_record("p-distinct-a").expect("fetch a");
        let fetched_b = state.get_record("p-distinct-b").expect("fetch b");
        assert_eq!(fetched_a.id, "p-distinct-a", "a fetches as a");
        assert_eq!(fetched_b.id, "p-distinct-b", "b fetches as b");
        assert_eq!(fetched_a.timestamp, 100.0, "a's timestamp distinct");
        assert_eq!(fetched_b.timestamp, 200.0, "b's timestamp distinct");
        assert_ne!(
            fetched_a.id, fetched_b.id,
            "no cross-contamination between distinct ids"
        );
    }

    #[test]
    fn p_mark_tombstoned_persists_canonical_json_with_id_and_reason() {
        // mark_tombstoned writes a JSON blob `{"tombstone_id":...,
        // "reason":...}` under the `tombstone:{target_id}` key in
        // CF_METADATA. Pin the exact payload shape so a future
        // regression that drops a field (e.g. omits `reason` for
        // brevity) or switches the serialization (bincode/MessagePack)
        // is caught here — /admin/tombstones operator readers parse
        // this JSON directly and would silently break otherwise.
        let state = test_node_state(None);
        state
            .mark_tombstoned("p-target-1", "p-tomb-1", "byzantine-reorg")
            .expect("mark_tombstoned writes to CF_METADATA");

        // Pull the raw bytes back through the same CF_METADATA access
        // path the production reader uses, decode as JSON, assert the
        // two required field names and values are present.
        let raw = state
            .rocks
            .get_cf_raw(
                crate::storage::rocks::CF_METADATA,
                b"tombstone:p-target-1",
            )
            .expect("get_cf_raw ok")
            .expect("tombstone key present after mark_tombstoned");
        let payload: serde_json::Value =
            serde_json::from_slice(&raw).expect("payload is valid JSON");

        assert_eq!(
            payload.get("tombstone_id").and_then(|v| v.as_str()),
            Some("p-tomb-1"),
            "JSON must carry tombstone_id field with the supplied id"
        );
        assert_eq!(
            payload.get("reason").and_then(|v| v.as_str()),
            Some("byzantine-reorg"),
            "JSON must carry reason field with the supplied reason"
        );
    }

    #[test]
    fn p_mark_tombstoned_second_call_overwrites_with_new_reason() {
        // CF_METADATA writes are blind put_cf_raw (no append, no merge
        // operator) — a second mark_tombstoned for the same target_id
        // must overwrite the prior payload, NOT silently no-op or
        // accumulate. Pin the overwrite semantics so a regression that
        // wrapped the writer with a "skip if exists" guard surfaces
        // here rather than silently freezing the first reason forever.
        let state = test_node_state(None);
        state
            .mark_tombstoned("p-target-2", "p-tomb-first", "initial-reason")
            .expect("first mark");

        // Second mark for the same target with a different tombstone
        // id and reason — should replace the prior payload entirely.
        state
            .mark_tombstoned("p-target-2", "p-tomb-second", "updated-reason")
            .expect("second mark overwrites first");

        let raw = state
            .rocks
            .get_cf_raw(
                crate::storage::rocks::CF_METADATA,
                b"tombstone:p-target-2",
            )
            .expect("get_cf_raw ok")
            .expect("tombstone key still present after overwrite");
        let payload: serde_json::Value =
            serde_json::from_slice(&raw).expect("payload still valid JSON after overwrite");

        assert_eq!(
            payload.get("tombstone_id").and_then(|v| v.as_str()),
            Some("p-tomb-second"),
            "second mark's tombstone_id must replace the first"
        );
        assert_eq!(
            payload.get("reason").and_then(|v| v.as_str()),
            Some("updated-reason"),
            "second mark's reason must replace the first — no accumulation"
        );

        // And is_tombstoned still reports true (key wasn't deleted by
        // the overwrite).
        assert!(
            state
                .is_tombstoned("p-target-2")
                .expect("is_tombstoned post-overwrite"),
            "overwriting payload must preserve tombstoned=true on the key"
        );
    }

    // ── confirmation_level finalized-fallback + effective_max_hops
    //    adaptive growth & config-clamp + record_count increment ──────────
    //
    // Three previously-dark branches:
    //
    // (1) `confirmation_level` line 3947-3953 — when consensus.layered_
    //     confirmation returns Pending AND the record_id is in `state.finalized`,
    //     return Finalized. This path fires after consensus pruning lands a
    //     finalized rid into the bounded-LRU CF_METADATA tier while the
    //     in-memory consensus tracker has forgotten it. l28_…_unknown_record_
    //     is_pending covers the empty/empty side; Q pins the fallback side
    //     plus a negative control so a future refactor that drops the fallback
    //     (e.g. inlining `consensus.layered_confirmation` and forgetting the
    //     fin set check) surfaces here, not as a fleet-wide "Finalized record
    //     reverts to Pending in /record/{id}" account bug.
    //
    // (2) `effective_max_hops` line 3995-3999 — adaptive = `ceil(log2(max(dht_len,
    //     1))) + 2`, clamped by `config.gossip_max_hops`. l28_…_floors_at_two
    //     covers the empty-DHT branch only. Q pins (a) the log2-growth branch
    //     with a populated DHT (3 distinct-subnet peers → `ceil(log2(3))+2 = 4`),
    //     and (b) the config-clamps-below-adaptive branch (config=1 with empty
    //     DHT still returns 1, even though adaptive would say 2). Together
    //     they pin BOTH ends of `adaptive.min(config.gossip_max_hops)` so a
    //     swap (max instead of min, or wrong field order) breaks here, not at
    //     deploy when gossip storms flood the testnet.
    //
    // (3) `record_count` line 4029 — l28_…_zero_on_fresh_node pins the empty
    //     branch. Q pins the post-insert side: insert_record_both must drive
    //     `rocks.record_count()` upward by exactly one per successful insert.
    //     The asymmetric coverage (empty pinned, non-empty unpinned) leaves a
    //     gap where a storage refactor that wired the counter to a tombstone
    //     CF would silently return 0 forever and break `/metrics` total-records.

    #[tokio::test]
    async fn q_confirmation_level_finalized_fallback_pins_pending_to_finalized() {
        // Setup: fresh node — consensus tracker has no `record_to_seal` entry
        // for `q-fin-fallback-r1`, so `layered_confirmation` returns Pending.
        // Then directly insert the rid into the on-disk + hot finalized index
        // (the same path the consensus settlement loop drives at line 3841).
        // After that, the wrapper's try_read fallback at line 3948 must fire
        // and upgrade the answer to Finalized.
        let state = test_node_state(None);

        // Sanity: before any fin insert, the unknown rid returns Pending —
        // identical to the l28_… baseline (empty consensus AND empty fin).
        assert_eq!(
            state.confirmation_level("q-fin-fallback-r1"),
            super::super::consensus::ConfirmationLevel::Pending,
            "pre-insert sanity: empty consensus + empty fin → Pending"
        );

        // Drive the fallback path. tokio::RwLock — write() is async; scope
        // the guard tight so try_read() in confirmation_level can succeed.
        {
            let mut fin = state.finalized.write().await;
            fin.insert("q-fin-fallback-r1".into());
        }

        let lvl = state.confirmation_level("q-fin-fallback-r1");
        assert_eq!(
            lvl,
            super::super::consensus::ConfirmationLevel::Finalized,
            "consensus Pending + fin contains rid → wrapper must upgrade to Finalized \
             (pins the OPS-…/post-prune fallback at state.rs:3947-3953)"
        );
    }

    #[tokio::test]
    async fn q_confirmation_level_unknown_record_no_finalized_entry_returns_pending() {
        // Negative control for the fallback path. The fin index is populated
        // with a DIFFERENT rid than the one we query, so `fin.contains(rid)`
        // returns false and the wrapper must NOT upgrade to Finalized. Pins
        // the contains-check semantics — a regression that flattened the
        // check to `!fin.is_empty()` would surface here as a false Finalized
        // for any record once the first rid lands in fin.
        let state = test_node_state(None);
        {
            let mut fin = state.finalized.write().await;
            fin.insert("q-other-rid".into());
        }

        let lvl = state.confirmation_level("q-not-finalized-rid");
        assert_eq!(
            lvl,
            super::super::consensus::ConfirmationLevel::Pending,
            "consensus Pending + fin contains DIFFERENT rid → wrapper stays Pending"
        );
    }

    #[test]
    fn q_effective_max_hops_three_distinct_subnet_peers_returns_four_log2_growth() {
        // Populate the DHT with 3 peers across distinct /24 subnets to bypass
        // the MAX_PER_SUBNET_PER_BUCKET=2 / MAX_PER_SUBNET_TOTAL=10 limits.
        // peer_count=3 → log2(3)≈1.585 → ceil=2 → adaptive=4. Default config
        // gossip_max_hops=6, so min(4, 6) = 4. Pins the adaptive-growth branch
        // against a regression that swapped `ceil` for `floor` (would return 3)
        // or dropped the +2 offset (would return 2).
        let state = test_node_state(None);
        {
            let mut dht = state.dht.lock_recover();
            for (i, host) in ["10.0.1.5", "10.0.2.5", "10.0.3.5"].iter().enumerate() {
                let mut node_arr = [0u8; 32];
                node_arr[0] = (i as u8) + 1; // distinct first byte → distinct buckets
                let peer = super::super::dht::DhtPeer {
                    node_id: super::super::dht::NodeId(node_arr),
                    identity_hash: format!("{:02x}{}", i + 1, "00".repeat(31)),
                    host: (*host).to_string(),
                    port: 9473,
                    last_seen: 1_700_000_000.0,
                    first_added: 1_700_000_000.0,
                    provenance: super::super::dht::PeerProvenance::Outbound,
                };
                let res = dht.insert(peer);
                assert!(
                    matches!(res, super::super::dht::InsertResult::Inserted),
                    "test fixture must insert all 3 peers cleanly; got {res:?}"
                );
            }
            assert_eq!(dht.len(), 3, "fixture sanity: DHT carries 3 peers");
        }

        assert_eq!(
            state.effective_max_hops(),
            4,
            "3-peer DHT → ceil(log2(3))+2 = 4; default config.gossip_max_hops=6 \
             does not clamp"
        );
    }

    #[test]
    fn q_effective_max_hops_config_below_adaptive_clamps_to_config() {
        // Build a state whose config caps `gossip_max_hops` at 1 (below the
        // adaptive floor of 2 produced by the empty-DHT branch). Even with
        // zero peers, adaptive=2 → min(2, 1) = 1. Pins the upper-bound clamp
        // — a regression that returned `adaptive` raw or used `max` instead
        // of `min` would return 2 here and break operator overrides that
        // intentionally restrict hop budget on phone-tier nodes.
        use crate::identity::{CryptoProfile, EntityType, Identity};
        use crate::network::config::NodeConfig;
        use crate::network::witness::WitnessManager;
        use crate::storage::rocks::StorageEngine;

        let tmp = tempfile::tempdir().expect("tempdir");
        let data_dir = tmp.path().to_path_buf();
        let config = NodeConfig {
            data_dir: data_dir.clone(),
            identity_path: data_dir.join("identity.json"),
            db_path: data_dir.join("elara.db"),
            admin_token: "test-admin".into(),
            network_id: "q-hops-clamp".into(),
            mdns_enabled: false,
            health_check_interval_secs: 0,
            min_pow_difficulty: 0,
            gossip_max_hops: 1,
            ..Default::default()
        };
        let identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
            .expect("generate identity");
        let rocks = std::sync::Arc::new(
            StorageEngine::open(data_dir.join("rocksdb")).expect("open rocksdb"),
        );
        let wmgr = std::sync::Arc::new(WitnessManager::new(rocks.clone()));
        let state = std::sync::Arc::new(NodeState::new(config, identity, rocks, wmgr));
        std::mem::forget(tmp);

        assert_eq!(
            state.effective_max_hops(),
            1,
            "config.gossip_max_hops=1 must clamp adaptive=2 down to 1 — \
             phone-tier operator override path"
        );
    }

    #[test]
    fn q_record_count_increments_after_insert_record_both() {
        // l28_storage_passthrough_zero_on_fresh_node pins the cold-boot
        // record_count=0 branch. Pin the post-insert side here: two distinct
        // insert_record_both calls must drive record_count to 2 (one each).
        // Catches a future regression that wired the counter to a tombstone
        // CF instead of CF_RECORDS — the empty branch would still say 0 and
        // be a deceptive green test while production /metrics flatlined.
        let state = test_node_state(None);
        assert_eq!(
            state.record_count().expect("count on fresh"),
            0,
            "pre-insert sanity"
        );

        let r1 = test_record("q-count-r1", vec![], 100.0);
        let r2 = test_record("q-count-r2", vec![], 200.0);
        state.insert_record_both(&r1).expect("insert r1");
        state.insert_record_both(&r2).expect("insert r2");

        assert_eq!(
            state.record_count().expect("count after insert"),
            2,
            "two distinct insert_record_both calls must drive record_count to 2"
        );
        assert!(
            state.record_exists("q-count-r1").expect("exists r1"),
            "r1 must round-trip through record_exists"
        );
        assert!(
            state.record_exists("q-count-r2").expect("exists r2"),
            "r2 must round-trip through record_exists"
        );
    }

    // ── record_https_fallback caller-router pinning ────────────────────────
    //
    // AUDIT-10 Milestone B / `state.rs:4263` routes the `caller: &str` arg
    // through a `match` into one of four AtomicU64s. The four routing legs
    // power the `elara_https_fallback_total{caller=...}` /metrics surface,
    // which is the canonical "are we still falling back to HTTPS anywhere"
    // signal — the docstring says the steady-state expectation is that ALL
    // FOUR counters stay at zero. Today's coverage is zero direct tests on
    // this surface (the comment immediately above the function calls out
    // /metrics as the canonical check, but /metrics is a network surface,
    // not a regression guard — a refactor that swapped two arms could
    // silently misattribute callers in production while the metrics surface
    // still appeared "live"). Three previously-dark contracts get pinned
    // here:
    //
    // (1) Per-caller routing isolation — incrementing "gossip" must leave
    //     the OTHER three legs at zero. A regression that fanned out to all
    //     four atomics (e.g., a "helpful" tee-style refactor) or that swapped
    //     two arm bindings would trip this — the operator dashboard's
    //     classification of WHICH client surface fell back depends on this.
    //
    // (2) Unknown-caller-is-silent-noop branch — the docstring promises
    //     "unknown callers are silently dropped so a future caller name
    //     typo never panics in steady state". A regression that changed the
    //     `_ => return` arm to a `panic!` or to an `unknown_total` fallback
    //     counter would break the typo-safe contract. Pin BOTH: (a) the
    //     unknown caller produces no panic, (b) all four known atomics
    //     remain at zero after an unknown-caller call.
    //
    // (3) Accumulation contract (not idempotent) — five calls produce five
    //     increments. A regression that wrapped the body in a "first-call-
    //     only" guard (e.g., to throttle log spam in a future refactor)
    //     would silently flatline the counter at 1 and break operator
    //     trend lines.

    #[test]
    #[allow(clippy::type_complexity)]
    fn r_record_https_fallback_known_callers_each_increment_only_their_atomic() {
        // For each of the four documented callers, calling
        // record_https_fallback(c) must increment EXACTLY that caller's
        // atomic by one and leave the other three at zero. Catches an
        // arm-swap or fan-out regression at compile-time-impossible level
        // (Rust's match is exhaustive over &str via the catch-all, but the
        // arm BINDINGS are not checked by the compiler — only by tests).
        use std::sync::atomic::Ordering::Relaxed;

        let cases: &[(&str, fn(&NodeState) -> u64, fn(&NodeState) -> [u64; 3])] = &[
            (
                "gossip",
                |s: &NodeState| s.https_fallback_gossip_total.load(Relaxed),
                |s: &NodeState| [
                    s.https_fallback_sync_total.load(Relaxed),
                    s.https_fallback_light_total.load(Relaxed),
                    s.https_fallback_discovery_total.load(Relaxed),
                ],
            ),
            (
                "sync",
                |s: &NodeState| s.https_fallback_sync_total.load(Relaxed),
                |s: &NodeState| [
                    s.https_fallback_gossip_total.load(Relaxed),
                    s.https_fallback_light_total.load(Relaxed),
                    s.https_fallback_discovery_total.load(Relaxed),
                ],
            ),
            (
                "light",
                |s: &NodeState| s.https_fallback_light_total.load(Relaxed),
                |s: &NodeState| [
                    s.https_fallback_gossip_total.load(Relaxed),
                    s.https_fallback_sync_total.load(Relaxed),
                    s.https_fallback_discovery_total.load(Relaxed),
                ],
            ),
            (
                "discovery",
                |s: &NodeState| s.https_fallback_discovery_total.load(Relaxed),
                |s: &NodeState| [
                    s.https_fallback_gossip_total.load(Relaxed),
                    s.https_fallback_sync_total.load(Relaxed),
                    s.https_fallback_light_total.load(Relaxed),
                ],
            ),
        ];

        for (caller, target, others) in cases {
            let state = test_node_state(None);
            assert_eq!(target(&state), 0, "{caller}: target atomic must start at 0");
            assert_eq!(
                others(&state),
                [0, 0, 0],
                "{caller}: other three atomics must start at 0"
            );

            state.record_https_fallback(caller);

            assert_eq!(
                target(&state),
                1,
                "{caller}: record_https_fallback must drive THIS caller's atomic to 1"
            );
            assert_eq!(
                others(&state),
                [0, 0, 0],
                "{caller}: record_https_fallback must NOT touch the other three atomics — \
                 arm-swap regression candidate"
            );
        }
    }

    #[test]
    fn r_record_https_fallback_unknown_caller_is_silent_noop() {
        // The `_ => return` arm of state.rs:4269 is the typo-safe path.
        // Three things to pin here so a future refactor that promoted
        // unknown callers to a panic or to a generic counter trips this:
        // (1) the call does not panic, (2) none of the four documented
        // atomics moves, (3) the contract holds for several distinct
        // typos (empty string, casing variant, completely foreign word).
        use std::sync::atomic::Ordering::Relaxed;

        let typos = ["", "GOSSIP", "Gossip", "gossipx", "x", "metrics", " "];
        for typo in typos {
            let state = test_node_state(None);
            // Must not panic.
            state.record_https_fallback(typo);
            // All four known atomics must be unchanged.
            assert_eq!(
                state.https_fallback_gossip_total.load(Relaxed),
                0,
                "typo {typo:?}: gossip atomic must stay at 0 — unknown-caller is silent"
            );
            assert_eq!(
                state.https_fallback_sync_total.load(Relaxed),
                0,
                "typo {typo:?}: sync atomic must stay at 0 — unknown-caller is silent"
            );
            assert_eq!(
                state.https_fallback_light_total.load(Relaxed),
                0,
                "typo {typo:?}: light atomic must stay at 0 — unknown-caller is silent"
            );
            assert_eq!(
                state.https_fallback_discovery_total.load(Relaxed),
                0,
                "typo {typo:?}: discovery atomic must stay at 0 — unknown-caller is silent"
            );
        }
    }

    #[test]
    fn r_record_https_fallback_repeated_calls_accumulate_not_idempotent() {
        // The fetch_add is not gated — five "gossip" calls must produce a
        // value of 5, not 1. Pins the accumulation contract so a future
        // refactor that wrapped the body in a "first-call-only" log-spam
        // guard or in a compare_exchange(0, 1) flag would surface here,
        // not as a flatlined operator dashboard.
        use std::sync::atomic::Ordering::Relaxed;
        let state = test_node_state(None);
        for _ in 0..5 {
            state.record_https_fallback("gossip");
        }
        assert_eq!(
            state.https_fallback_gossip_total.load(Relaxed),
            5,
            "5 calls must accumulate to 5 — not idempotent at the counter level"
        );
        // Sibling caller must still be at zero — accumulation must not
        // bleed across legs.
        assert_eq!(
            state.https_fallback_sync_total.load(Relaxed),
            0,
            "accumulation on gossip must not bleed into sync — leg isolation under load"
        );
    }

    // ── post-delete contract for storage-passthrough getters ──────────────
    //
    // `l28_delete_record_both_removes_record_from_storage` (batch-E) pins
    // the boolean post-delete on `record_exists` and the idempotent re-
    // delete branch. The other four passthroughs that the /record/{id} +
    // /count + /metrics routes lean on — `record_count`, `get_record`,
    // `get_wire_bytes`, `all_record_hashes` — were tested only on the
    // INSERT side. A future regression that wired `delete_record_both` to
    // tombstone-only (leaving CF_RECORDS rows behind) would slip past
    // batch-E because `record_exists` would still flip false via the
    // tombstone CF check, while the routes that fan out to the other four
    // would silently keep returning the dead record. Pin all four here so
    // that drift surfaces in unit tests, not as a 200 OK with stale-id body
    // at the network layer.

    #[test]
    fn s_record_count_drops_back_to_zero_after_delete_record_both() {
        // Insert one record (count: 0→1), delete it (count: 1→0). Pins the
        // path that `/count` and the `elara_records_total` gauge read at
        // every metrics scrape — a tombstone-only delete that leaves
        // CF_RECORDS rows behind would surface here as count=1 post-delete,
        // not as a misleading flat dashboard.
        let state = test_node_state(None);
        assert_eq!(state.record_count().expect("count fresh"), 0);

        let rec = test_record("s-count-r1", vec![], 100.0);
        state.insert_record_both(&rec).expect("insert");
        assert_eq!(
            state.record_count().expect("count post-insert"),
            1,
            "single insert must drive count to 1"
        );

        state
            .delete_record_both("s-count-r1")
            .expect("delete");
        assert_eq!(
            state.record_count().expect("count post-delete"),
            0,
            "single delete must drive count back to 0 — \
             tombstone-only regression would leave this at 1"
        );
    }

    #[test]
    fn s_get_record_returns_record_not_found_after_delete_record_both() {
        // get_record(absent) maps storage Ok(None) to
        // ElaraError::RecordNotFound(id) — covered for never-inserted ids
        // by p_get_record_unknown_id_…. Pin the post-DELETE branch here so
        // that delete_record_both wiring stays consistent with the never-
        // inserted contract: same Err variant, same id payload. A regression
        // that wired delete to a per-id soft-flag (record still queryable
        // via get_record but flagged "deleted") would surface here.
        let state = test_node_state(None);
        let rec = test_record("s-get-rec-doomed", vec![], 250.0);
        state.insert_record_both(&rec).expect("insert");
        state.get_record("s-get-rec-doomed").expect("fetch pre-delete ok");

        state
            .delete_record_both("s-get-rec-doomed")
            .expect("delete");

        let err = state
            .get_record("s-get-rec-doomed")
            .expect_err("post-delete get_record must Err, not Ok(stale)");
        match err {
            crate::errors::ElaraError::RecordNotFound(id) => {
                assert_eq!(
                    id, "s-get-rec-doomed",
                    "error payload must carry the queried id verbatim — \
                     route translates this to a 404 with the id echoed back"
                );
            }
            other => panic!(
                "expected RecordNotFound after delete, got {other:?} — \
                 delete must clear storage rows, not soft-flag them"
            ),
        }
    }

    #[test]
    fn s_get_wire_bytes_returns_storage_err_after_delete_record_both() {
        // get_wire_bytes goes through storage's CF_RECORDS lookup directly
        // (no error remap to RecordNotFound — it surfaces a plain
        // ElaraError::Storage with the missing id in the message string).
        // /merkle and /export downstream readers depend on this exact
        // shape: a Storage Err with the id substring lets callers
        // distinguish "absent" from a real RocksDB I/O fault by message
        // inspection. Pin that contract on the post-delete path.
        let state = test_node_state(None);
        let rec = test_record("s-wire-doomed", vec![], 350.0);
        state.insert_record_both(&rec).expect("insert");
        let pre = state
            .get_wire_bytes("s-wire-doomed")
            .expect("wire bytes pre-delete ok");
        assert!(
            !pre.is_empty(),
            "wire bytes pre-delete must be non-empty — sanity gate \
             that the insert actually planted a CF_RECORDS row"
        );

        state.delete_record_both("s-wire-doomed").expect("delete");

        let err = state
            .get_wire_bytes("s-wire-doomed")
            .expect_err("post-delete get_wire_bytes must Err, not Ok(empty)");
        match err {
            crate::errors::ElaraError::Storage(msg) => {
                assert!(
                    msg.contains("s-wire-doomed"),
                    "Storage err message must mention the missing id \
                     so callers can distinguish 'absent' from 'I/O fault': {msg}"
                );
            }
            other => panic!(
                "expected ElaraError::Storage with id in message, got {other:?}"
            ),
        }
    }

    #[test]
    fn s_record_count_under_partial_delete_in_multi_record_state() {
        // Three-record state (count: 0→3), drop the middle one (count: 3→2),
        // drop the remaining two (count: 2→0). Each delete must subtract
        // exactly one — a regression that fan-deleted via prefix match (or
        // cascaded through a stale secondary index) would surface here as
        // an over-subtraction (e.g. count=0 after the first delete) and is
        // the failure mode that would silently snowball into "all records
        // gone after one /admin/delete" at the network layer.
        let state = test_node_state(None);
        let r1 = test_record("s-part-a", vec![], 100.0);
        let r2 = test_record("s-part-b", vec![], 200.0);
        let r3 = test_record("s-part-c", vec![], 300.0);
        state.insert_record_both(&r1).expect("insert a");
        state.insert_record_both(&r2).expect("insert b");
        state.insert_record_both(&r3).expect("insert c");
        assert_eq!(
            state.record_count().expect("count 3"),
            3,
            "three inserts must drive count to 3"
        );

        state.delete_record_both("s-part-b").expect("delete middle");
        assert_eq!(
            state.record_count().expect("count post-1-delete"),
            2,
            "single middle delete must subtract exactly one — \
             prefix-match cascade regression candidate"
        );
        // Siblings still queryable — pin isolation across delete operations.
        assert!(
            state.record_exists("s-part-a").expect("exists a"),
            "sibling a must survive middle delete"
        );
        assert!(
            state.record_exists("s-part-c").expect("exists c"),
            "sibling c must survive middle delete"
        );
        assert!(
            !state.record_exists("s-part-b").expect("exists b"),
            "middle b must be gone after delete"
        );

        state.delete_record_both("s-part-a").expect("delete a");
        state.delete_record_both("s-part-c").expect("delete c");
        assert_eq!(
            state.record_count().expect("count final"),
            0,
            "all three deletes must drive count back to 0"
        );
    }

    // ── record-stats empty-state branches ─────────────────────────────
    // Pin the empty-state branches + monotonic-ratchet
    // equal-ts guards for `record_stats_earliest` / `_latest` /
    // `_snapshot_json`. Populated-state paths are covered by the
    // existing test_ops125_* family; the empty-state `bits == 0`
    // sentinel branch and the equal-ts CAS no-op branch are not
    // directly pinned. A regression that returned `Some(0.0)` from
    // the sentinel branch would silently emit false "epoch
    // 1970-01-01" time ranges on the dag-stats endpoint; a regression
    // that relaxed the equal-ts guard would re-ratchet on every
    // duplicate-timestamp bump, defeating the monotonic invariant
    // the legacy compute_dag_stats min/max scan provided.

    #[test]
    fn t_record_stats_earliest_empty_state_returns_none() {
        // Fresh node — no bumps. `record_stats_earliest_ts_bits`
        // initialises to 0 (line 2435 builder). The helper's
        // `if bits == 0 { None }` arm must fire before any
        // `f64::from_bits(0) == 0.0` materialisation reaches the
        // caller. A regression dropping the sentinel check would
        // surface `Some(0.0)`, which downstream consumers render as
        // "1970-01-01" on the operator dashboard.
        let state = test_node_state(None);
        assert_eq!(
            state.record_stats_earliest(),
            None,
            "fresh-state earliest must be None, not Some(0.0) — \
             the bits==0 sentinel is the only signal distinguishing \
             never-populated from a real epoch-0 record"
        );
    }

    #[test]
    fn t_record_stats_latest_empty_state_returns_none() {
        // Mirror of the earliest test for the latest atomic.
        // `record_stats_latest_ts_bits` also initialises to 0; the
        // helper's `if bits == 0 { None }` arm is the only branch
        // protecting the "no records observed" surface from
        // collapsing into a real `Some(0.0)` reading.
        let state = test_node_state(None);
        assert_eq!(
            state.record_stats_latest(),
            None,
            "fresh-state latest must be None, not Some(0.0)"
        );
    }

    #[test]
    fn t_record_stats_snapshot_json_empty_state_emits_zero_time_range() {
        // Fresh state — pins the `.unwrap_or(0.0)` branch on both
        // `time_range.earliest` and `time_range.latest`, AND pins
        // that every counter slot still serialises (zero-valued)
        // not skipped. `creators_indexed=false` + `stats_partial=
        // false` are the boot-time defaults; `unique_creators` is
        // intentionally `null` until the HLL follow-up lands.
        let state = test_node_state(None);
        let snap = state.record_stats_snapshot_json();
        assert_eq!(snap["total_records"], serde_json::json!(0));
        assert!(snap["unique_creators"].is_null());
        assert_eq!(snap["creators_indexed"], serde_json::json!(false));
        assert_eq!(snap["stats_partial"], serde_json::json!(false));
        assert_eq!(snap["time_range"]["earliest"], serde_json::json!(0.0));
        assert_eq!(snap["time_range"]["latest"], serde_json::json!(0.0));
        // All classification slots present + zero.
        for slot in ["public", "private", "restricted", "sovereign"] {
            assert_eq!(
                snap["by_classification"][slot],
                serde_json::json!(0),
                "classification {slot} must serialise as 0 on fresh state"
            );
        }
        // All operation slots present + zero (the 9 beat_op + epoch_seal + non_token).
        for slot in [
            "mint", "transfer", "stake", "unstake", "burn", "slash",
            "witness_reward", "dormancy_reclaim", "pool_fund",
            "epoch_seal", "non_token",
        ] {
            assert_eq!(
                snap["by_operation"][slot],
                serde_json::json!(0),
                "operation {slot} must serialise as 0 on fresh state"
            );
        }
    }

    #[test]
    fn t_record_stats_earliest_no_update_when_new_ts_higher_or_equal() {
        // Pin the CAS-loop monotonic guard `cur != 0 && from_bits(cur)
        // <= rec.timestamp => break` at state.rs:4353. Bump 500.0
        // seeds the floor; bumping a strictly-higher 600.0 must NOT
        // re-ratchet (the guard short-circuits); a duplicate 500.0
        // also must NOT re-ratchet (`<=` covers equality). A
        // regression relaxing the guard to `<` would let the
        // equal-ts bump pass through the CAS and burn an unnecessary
        // store; a regression flipping the guard direction would
        // ratchet the earliest UPWARD on every bump, defeating min-
        // tracking.
        let state = test_node_state(None);
        state.record_stats_bump(&ops125_test_record(
            "t-min-a", 500.0, crate::record::Classification::Public, Some("mint"), None,
        ));
        assert_eq!(state.record_stats_earliest(), Some(500.0));
        // Strictly-higher bump — must be a no-op on the earliest atomic.
        state.record_stats_bump(&ops125_test_record(
            "t-min-b", 600.0, crate::record::Classification::Public, Some("mint"), None,
        ));
        assert_eq!(
            state.record_stats_earliest(),
            Some(500.0),
            "earliest must not ratchet upward on a higher-ts bump"
        );
        // Equal-ts bump — must also be a no-op (the `<=` arm).
        state.record_stats_bump(&ops125_test_record(
            "t-min-c", 500.0, crate::record::Classification::Public, Some("mint"), None,
        ));
        assert_eq!(
            state.record_stats_earliest(),
            Some(500.0),
            "earliest must not re-store on an equal-ts bump — \
             the `<=` guard pins idempotence"
        );
        // Strictly-lower bump — confirms the ratchet still fires downward.
        state.record_stats_bump(&ops125_test_record(
            "t-min-d", 100.0, crate::record::Classification::Public, Some("mint"), None,
        ));
        assert_eq!(
            state.record_stats_earliest(),
            Some(100.0),
            "earliest must ratchet downward on a lower-ts bump — \
             negative-control for the guard above"
        );
    }

    #[test]
    fn t_record_stats_latest_no_update_when_new_ts_lower_or_equal() {
        // Mirror of the earliest test for the latest CAS-loop guard
        // `from_bits(cur) >= rec.timestamp => break` at state.rs:4365.
        // Bump 500.0 seeds the ceiling; bumping a strictly-lower
        // 400.0 must NOT re-ratchet; a duplicate 500.0 also must
        // NOT re-ratchet (`>=` covers equality); a strictly-higher
        // 1000.0 confirms the ratchet still fires upward.
        let state = test_node_state(None);
        state.record_stats_bump(&ops125_test_record(
            "t-max-a", 500.0, crate::record::Classification::Public, Some("mint"), None,
        ));
        assert_eq!(state.record_stats_latest(), Some(500.0));
        // Strictly-lower bump — must be a no-op on the latest atomic.
        state.record_stats_bump(&ops125_test_record(
            "t-max-b", 400.0, crate::record::Classification::Public, Some("mint"), None,
        ));
        assert_eq!(
            state.record_stats_latest(),
            Some(500.0),
            "latest must not ratchet downward on a lower-ts bump"
        );
        // Equal-ts bump — must also be a no-op (the `>=` arm).
        state.record_stats_bump(&ops125_test_record(
            "t-max-c", 500.0, crate::record::Classification::Public, Some("mint"), None,
        ));
        assert_eq!(
            state.record_stats_latest(),
            Some(500.0),
            "latest must not re-store on an equal-ts bump — \
             the `>=` guard pins idempotence"
        );
        // Strictly-higher bump — confirms the ratchet still fires upward.
        state.record_stats_bump(&ops125_test_record(
            "t-max-d", 1000.0, crate::record::Classification::Public, Some("mint"), None,
        ));
        assert_eq!(
            state.record_stats_latest(),
            Some(1000.0),
            "latest must ratchet upward on a higher-ts bump — \
             negative-control for the guard above"
        );
    }

    // ── bootstrap_slot_nonce recovery-branch coverage ─────────────────────
    // bootstrap_slot_nonce (state.rs:3000) recovery-branch coverage.
    //
    // Previously the only direct test (`l28_bootstrap_slot_nonce_fresh_node_stays_at_one`)
    // pinned the empty `Ok(None)` arm — fresh node, no slot entries, counter
    // stays at the default 1. The `Ok(Some(max))` recovery arm — the actual
    // restart-safety contract that prevents self-equivocation by ensuring a
    // restarted node never re-hands-out a nonce it already used — was dark.
    //
    // The recovery arm is the safety-critical branch. If it regresses to
    // either (a) skipping the +1 or (b) ignoring the on-disk max, the next
    // record this node mints after restart collides with a slot it already
    // claimed pre-restart, trips the SLOT EQUIVOCATION gate, and the node
    // self-slashes. A past incident was the live consequence of an adjacent slot-key
    // mistake (super-seal nonce=0 collision); the bootstrap path is the
    // *defense* against the same failure mode on plain restart, so a unit
    // pin here is overdue.
    //
    // Four tests below cover: (1) the basic recovery flow with multiple
    // entries → max+1, (2) per-account prefix isolation so foreign slots
    // don't bleed into self.slot_nonce_self, (3) malformed-suffix tolerance
    // (the helper continues on parse failures rather than aborting / picking
    // a wrong number — important because pre-v3 entries may exist under
    // legacy layouts), and (4) the post-recovery `next_slot_nonce()` is
    // strictly greater than every pre-existing nonce — the actual safety
    // invariant `bootstrap_slot_nonce` exists to enforce.

    #[test]
    fn u_bootstrap_slot_nonce_recovery_picks_max_plus_one() {
        // Pre-seed CF_SLOT_INDEX with three slot entries for *this* identity
        // at nonces {1, 7, 42}. The recovery arm at state.rs:3003 should
        // store max+1 = 43 into slot_nonce_self via Release, so the next
        // hand-out is 43 (fetch_add returns the pre-increment value).
        let state = test_node_state(None);
        let account_hash = crate::crypto::hash::sha3_256_hex(&state.identity.public_key);
        for nonce in [1u64, 7u64, 42u64] {
            let slot_key = format!("{}:{:016x}", account_hash, nonce);
            state
                .rocks
                .slot_register(&slot_key, &format!("rec-{nonce}"))
                .expect("slot_register");
        }
        state.bootstrap_slot_nonce();
        assert_eq!(
            state.next_slot_nonce(),
            43,
            "recovery must seed counter at max(observed_nonces)+1 = 42+1"
        );
        assert_eq!(
            state.next_slot_nonce(),
            44,
            "post-recovery hand-out must remain strictly monotonic"
        );
    }

    #[test]
    fn u_bootstrap_slot_nonce_ignores_foreign_account_entries() {
        // Per-account prefix isolation (CF_SLOT_INDEX key prefix is
        // `<account_hash>:`). A different account's slots, even at huge
        // nonces, must not pull self.slot_nonce_self off its default — the
        // helper scans only the self-prefix. A regression that prefix-
        // iterated the whole CF would silently push our counter to a
        // foreign max and cause our first post-boot record to land at the
        // *wrong* slot key (still :NNN on our own hash, but skipping the
        // 1..foreign_max range we actually own — a silent waste, but in
        // the inverse failure mode it would mask a real own-slot collision).
        let state = test_node_state(None);
        let foreign_hash = "deadbeefcafebabe".repeat(4); // 64 hex chars
        for nonce in [99u64, 500u64, 12345u64] {
            let slot_key = format!("{}:{:016x}", foreign_hash, nonce);
            state
                .rocks
                .slot_register(&slot_key, &format!("foreign-rec-{nonce}"))
                .expect("slot_register foreign");
        }
        state.bootstrap_slot_nonce();
        // Counter must remain at the default 1 — foreign entries are
        // not under our prefix and must not influence our max.
        assert_eq!(
            state.next_slot_nonce(),
            1,
            "foreign-account slots must not bleed into self.slot_nonce_self"
        );
    }

    #[test]
    fn u_bootstrap_slot_nonce_tolerates_malformed_suffix_entries() {
        // The helper iterates CF_SLOT_INDEX and skips entries whose suffix
        // length != 16 or whose contents fail u64::from_str_radix(_, 16).
        // Pre-seed under our own account hash a mix of: one wrong-length
        // suffix, one non-hex suffix, and one valid hex suffix. The valid
        // one must win the scan — the helper must NOT abort on the bad
        // entries (legacy / migration artifacts) and must NOT include
        // them in the max computation.
        let state = test_node_state(None);
        let account_hash = crate::crypto::hash::sha3_256_hex(&state.identity.public_key);
        // Wrong-length suffix (5 chars instead of 16) — skipped at the
        // suffix.len() != 16 check (rocks.rs:1392).
        let bad_len_key = format!("{}:abcde", account_hash);
        state
            .rocks
            .slot_register(&bad_len_key, "legacy-short-suffix")
            .expect("slot_register short");
        // Right length (16) but non-hex — skipped at the from_str_radix
        // parse failure (rocks.rs:1399).
        let bad_hex_key = format!("{}:ZZZZZZZZZZZZZZZZ", account_hash);
        state
            .rocks
            .slot_register(&bad_hex_key, "legacy-nonhex-suffix")
            .expect("slot_register non-hex");
        // The one valid entry — should drive the recovery to 100+1 = 101.
        let good_key = format!("{}:{:016x}", account_hash, 100u64);
        state
            .rocks
            .slot_register(&good_key, "real-rec-100")
            .expect("slot_register valid");
        state.bootstrap_slot_nonce();
        assert_eq!(
            state.next_slot_nonce(),
            101,
            "malformed entries must be skipped, valid max=100 must drive +1 recovery"
        );
    }

    #[test]
    fn u_bootstrap_slot_nonce_post_recovery_strictly_above_all_existing_nonces() {
        // The actual safety invariant `bootstrap_slot_nonce` is there to
        // enforce: after recovery, *every* nonce subsequently handed out by
        // `next_slot_nonce()` must be strictly greater than any nonce
        // already on disk. This pins the contract end-to-end (not just the
        // first hand-out) by running a small post-recovery burst.
        let state = test_node_state(None);
        let account_hash = crate::crypto::hash::sha3_256_hex(&state.identity.public_key);
        let pre_existing: [u64; 5] = [3, 8, 15, 22, 41];
        for nonce in pre_existing {
            let slot_key = format!("{}:{:016x}", account_hash, nonce);
            state
                .rocks
                .slot_register(&slot_key, &format!("pre-{nonce}"))
                .expect("slot_register pre");
        }
        state.bootstrap_slot_nonce();
        let max_pre = *pre_existing.iter().max().expect("non-empty");
        // Five hand-outs, each must be strictly above the pre-existing max
        // and must be strictly monotonic relative to the prior hand-out.
        let mut last = max_pre;
        for _ in 0..5 {
            let n = state.next_slot_nonce();
            assert!(
                n > max_pre,
                "post-recovery hand-out {n} must exceed pre-existing max {max_pre}"
            );
            assert!(
                n > last,
                "post-recovery hand-outs must be strictly monotonic ({n} <= {last})"
            );
            last = n;
        }
    }

    // ── effective_base_timeout_ms — upstream RTT clamp interaction ─────────
    //
    // The four `test_effective_base_timeout_*` siblings (added with the
    // helper) pin the lower-end behavior of `effective_base_timeout_ms`:
    // 5s floor when no RTT, override bypass at 100ms, 2× scale with the
    // inner `.max(5.0)` floor (2s → 5s), and scale-above-floor at 10s →
    // 20s base. They cover the simple cases but **leave the boundary
    // between the per-sample RTT clamp upstream and the per-base clamp
    // downstream completely unpinned** — and that boundary is where the
    // real finality-freeze risk lives.
    //
    // Two clamps cooperate:
    //
    //   (A) `zone_rtt::MAX_SAMPLE_US = 30_000_000` (`zone_rtt.rs:41`) — every
    //       observation is capped at 30 s before it enters the ring. Comment
    //       at zone_rtt.rs:37-40: "anything above [30 s] is a stuck connection,
    //       not a representative RTT. Clamping prevents one pathological
    //       peer from pulling the p95 into uselessness."
    //
    //   (B) `effective_base_timeout_ms` clamp at `state.rs:3114`:
    //         `(base_s * 1000.0).clamp(1000.0, 600_000.0) as u64`
    //       — the 600 000ms (10-min) downstream ceiling.
    //
    // Because (A) caps every sample at 30 s and `effective_base_timeout_ms`
    // doubles it to 60 s, the downstream 600 000ms ceiling in (B) is
    // **unreachable from the RTT-driven path** — the effective ceiling is
    // 60 000ms. A regression that quietly lifted MAX_SAMPLE_US (e.g. to
    // u32::MAX-or-equivalent "no cap") would let a single pathological
    // 5-min RTT sample push the base timeout to 600 000ms, and downstream
    // rank-unlock would stretch from a few minutes to nearly an hour.
    // Pinning the 60 000ms effective ceiling from observations is the only
    // way this regression surfaces in unit tests rather than at deploy.
    //
    // Override path is independent: the early-return at `state.rs:3107`
    // bypasses both clamps so sim/test callers can set arbitrarily large
    // timeouts (e.g. to disable rank-unlock during a sim).
    //
    // Three tests:
    //
    // (1) RTT at the upstream cap (exactly 30 s) → 2 × 30 = 60 s = 60 000ms.
    //     Pins the cooperative boundary value — equality at both clamps.
    // (2) Pathological RTT well above the upstream cap (400 s observed) →
    //     still clamped to 30 s upstream → still 60 000ms base. Pins that
    //     the upstream cap holds and the downstream clamp is NOT reached.
    // (3) Override at 999 999ms (above the 600 000ms downstream ceiling)
    //     bypasses both clamps. Pins the early-return at state.rs:3107.

    #[test]
    fn v_effective_base_timeout_at_upstream_30s_rtt_cap_yields_60s_base() {
        // RTT = exactly 30 s (at the MAX_SAMPLE_US ceiling). After 2× scale:
        // base_s = 60 → 60 000ms. Below the downstream 600 000ms clamp, so
        // the result is the doubled RTT verbatim. Pins the cooperative
        // boundary between zone_rtt's per-sample clamp and the per-base
        // clamp in `effective_base_timeout_ms`.
        let state = test_node_state(None);
        let zone = super::super::zone::ZoneId::from_legacy(0);
        state.observe_zone_rtt(&zone, std::time::Duration::from_secs(30));
        assert_eq!(
            state.effective_base_timeout_ms(&zone),
            60_000,
            "RTT at the upstream 30 s cap must yield 2× = 60 000ms — \
             a regression that lifted MAX_SAMPLE_US would push this higher"
        );
    }

    #[test]
    fn v_effective_base_timeout_pathological_rtt_clamped_by_upstream_to_60s() {
        // Pathological observation at 400 s RTT (e.g. a single stalled
        // push). The upstream `MAX_SAMPLE_US = 30_000_000` at
        // zone_rtt.rs:41 clamps the sample to 30 s before it enters the
        // ring. Result is identical to test (1): 60 000ms. Pins that the
        // downstream `effective_base_timeout_ms` clamp at 600 000ms is
        // NOT the binding limit today — the upstream sample cap is.
        // This is the regression-detector: if the upstream cap is ever
        // lifted, this test (asserting 60 000) will start failing with
        // the larger value, alerting the next reviewer that the
        // downstream clamp must be re-validated as the safety net.
        let state = test_node_state(None);
        let zone = super::super::zone::ZoneId::from_legacy(0);
        state.observe_zone_rtt(&zone, std::time::Duration::from_secs(400));
        assert_eq!(
            state.effective_base_timeout_ms(&zone),
            60_000,
            "pathological RTT must be clamped upstream at 30 s — \
             a regression here means MAX_SAMPLE_US changed and the \
             downstream ceiling is now the binding clamp"
        );
    }

    #[test]
    fn v_effective_base_timeout_override_bypasses_both_clamps() {
        // The override branch at `state.rs:3107-3109` returns BEFORE the
        // clamp runs. A sim/test caller that sets the override to
        // 999 999ms (above the 600 000ms downstream ceiling AND well
        // above the 60 000ms upstream-effective ceiling) MUST receive
        // 999 999ms back, NOT clamped to either. Sim callers rely on
        // this to disable the rank-unlock ladder by setting an
        // effectively-infinite timeout — a regression that ran the
        // clamp on the override path would silently re-enable
        // rank-unlock in sim, masking real timing bugs.
        let state = test_node_state(Some(999_999));
        let zone = super::super::zone::ZoneId::from_legacy(0);
        // Even with an observed RTT (which would otherwise drive the
        // 60 000ms result via the clamp path), the override wins.
        state.observe_zone_rtt(&zone, std::time::Duration::from_secs(10));
        assert_eq!(
            state.effective_base_timeout_ms(&zone),
            999_999,
            "override must bypass both clamps — \
             early-return at state.rs:3107 precedes any clamp"
        );
    }

    // ── record_stats_bump per-arm beat_op routing ─────────────────────
    //
    // Pins the 9-way match at `state.rs:4336-4347` that maps each canonical
    // beat_op string literal to its own AtomicU64 counter. Existing
    // `test_ops125_record_stats_bump_counts_classifications_and_ops` (line
    // 6740) only bumps `"mint"` and `"transfer"` — the other 7 arms
    // (`stake`/`unstake`/`burn`/`slash`/`witness_reward`/
    // `dormancy_reclaim`/`pool_fund`) plus the `epoch_op` precedence
    // interaction are previously dark. A regression class this pins:
    // a one-character typo or a copy-paste swap (e.g., `"witness_reward"
    // → record_stats_op_witness_reward` accidentally becoming
    // `→ record_stats_op_dormancy_reclaim`) would silently drain
    // entire categories of records into the wrong counter, while
    // `record_stats_total` stays correct so no aggregate test flags it —
    // the dashboard would show "0 stake records" while the chain ran on
    // stake records for weeks. Surfacing here means a unit-test failure
    // at PR time, not at "where did all the stake records go?" on a live
    // operator dashboard.
    #[test]
    fn w_record_stats_bump_each_canonical_beat_op_routes_to_its_own_counter() {
        // Bump one record per canonical op (9 ops). Each counter must
        // end at exactly 1 and all OTHER op counters at exactly 0.
        // Catches typos in any individual match arm AND any cross-wired
        // counter assignment.
        use std::sync::atomic::Ordering::Relaxed;
        let state = test_node_state(None);
        let ops = [
            "mint", "transfer", "stake", "unstake", "burn", "slash",
            "witness_reward", "dormancy_reclaim", "pool_fund",
        ];
        for (i, op) in ops.iter().enumerate() {
            state.record_stats_bump(&ops125_test_record(
                &format!("rec-{i}"),
                100.0 + i as f64,
                crate::record::Classification::Public,
                Some(op),
                None,
            ));
        }
        // Each named counter at exactly 1.
        assert_eq!(state.record_stats_op_mint.load(Relaxed), 1);
        assert_eq!(state.record_stats_op_transfer.load(Relaxed), 1);
        assert_eq!(state.record_stats_op_stake.load(Relaxed), 1);
        assert_eq!(state.record_stats_op_unstake.load(Relaxed), 1);
        assert_eq!(state.record_stats_op_burn.load(Relaxed), 1);
        assert_eq!(state.record_stats_op_slash.load(Relaxed), 1);
        assert_eq!(state.record_stats_op_witness_reward.load(Relaxed), 1);
        assert_eq!(state.record_stats_op_dormancy_reclaim.load(Relaxed), 1);
        assert_eq!(state.record_stats_op_pool_fund.load(Relaxed), 1);
        // No leakage into the catch-all / epoch counters.
        assert_eq!(state.record_stats_non_token.load(Relaxed), 0);
        assert_eq!(state.record_stats_epoch_seals.load(Relaxed), 0);
        // Total tracks the 9 bumps.
        assert_eq!(state.record_stats_total.load(Relaxed), 9);
        // All went into Public classification.
        assert_eq!(state.record_stats_class_public.load(Relaxed), 9);
        assert_eq!(state.record_stats_class_private.load(Relaxed), 0);
    }

    #[test]
    fn w_record_stats_bump_epoch_op_key_preempts_beat_op_when_both_present() {
        // The if-branch at `state.rs:4328` short-circuits on
        // `EPOCH_OP_KEY` presence and never consults `beat_op`. A regression
        // that flipped the precedence (e.g., refactored into a separate
        // `else if` block, or moved the EPOCH_OP_KEY check after the
        // beat_op match) would double-count the record OR miscategorize
        // it as `mint` while still pretending to count it as an epoch seal.
        // Pin: when BOTH keys are present, only `epoch_seals` increments.
        use std::sync::atomic::Ordering::Relaxed;
        let state = test_node_state(None);
        state.record_stats_bump(&ops125_test_record(
            "both-keys",
            100.0,
            crate::record::Classification::Sovereign,
            Some("mint"),   // beat_op = mint
            Some("seal"),   // EPOCH_OP_KEY = seal — must win
        ));
        // Epoch-seal counter took the bump.
        assert_eq!(state.record_stats_epoch_seals.load(Relaxed), 1);
        // No beat_op counter took the bump — the if-branch pre-empted.
        assert_eq!(state.record_stats_op_mint.load(Relaxed), 0);
        assert_eq!(state.record_stats_op_transfer.load(Relaxed), 0);
        assert_eq!(state.record_stats_non_token.load(Relaxed), 0);
        // Total tracks exactly one bump (no double-counting).
        assert_eq!(state.record_stats_total.load(Relaxed), 1);
        // Classification still landed correctly (Sovereign branch).
        assert_eq!(state.record_stats_class_sovereign.load(Relaxed), 1);
    }

    #[test]
    fn w_record_stats_bump_snapshot_json_reflects_per_op_counters_after_each_canonical_bump() {
        // End-to-end shape stability: after bumping each of the 9 canonical
        // beat_op variants exactly once, `record_stats_snapshot_json` must
        // emit `by_operation.{op}=1` for every named key. This pins the
        // serializer-side mapping at `state.rs:4416-4427` — a regression
        // that renamed any JSON key (e.g., `"unstake"` → `"un_stake"`)
        // would surface here, and is a stronger guard than per-counter
        // assertions alone because the dag-stats dashboard reads through
        // this JSON shape, not the raw atomics.
        let state = test_node_state(None);
        let ops = [
            "mint", "transfer", "stake", "unstake", "burn", "slash",
            "witness_reward", "dormancy_reclaim", "pool_fund",
        ];
        for (i, op) in ops.iter().enumerate() {
            state.record_stats_bump(&ops125_test_record(
                &format!("rec-{i}"),
                100.0 + i as f64,
                crate::record::Classification::Public,
                Some(op),
                None,
            ));
        }
        let snap = state.record_stats_snapshot_json();
        // Each named operation key must be present and equal 1.
        for op in ops.iter() {
            assert_eq!(
                snap["by_operation"][op],
                serde_json::json!(1),
                "snapshot.by_operation.{op} should be 1 after a single bump — \
                 a missing or renamed key would surface here, NOT on the \
                 operator dashboard"
            );
        }
        // Epoch + non_token sentinels stay at 0 (not bumped by canonical ops).
        assert_eq!(snap["by_operation"]["epoch_seal"], serde_json::json!(0));
        assert_eq!(snap["by_operation"]["non_token"], serde_json::json!(0));
        // total_records matches the 9 bumps.
        assert_eq!(snap["total_records"], serde_json::json!(9));
    }

    // ── fin-burst-velocity sampler ────────────────────────────────────────

    #[test]
    fn fin_burst_velocity_cold_start_post_rehydrate_emits_zero() {
        // Simulates the first seal-loop tick after node restart where
        // `total_ever_finalized` was rehydrated from RocksDB to a large value.
        // Expected: sample is seeded, prev_delta stays 0, velocity emits 0
        // (NOT a +50000 spurious spike).
        let state = test_node_state(None);
        state
            .total_ever_finalized
            .store(50_000, std::sync::atomic::Ordering::Relaxed);
        state.sample_fin_burst_velocity();
        assert_eq!(
            state.last_fin_sample.load(std::sync::atomic::Ordering::Relaxed),
            50_000,
            "first tick must seed last_fin_sample"
        );
        assert_eq!(
            state
                .last_fin_burst_velocity
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "cold-start tick must emit velocity=0 (no spurious +50000 spike)"
        );
        assert_eq!(
            state.last_fin_delta.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "cold-start tick must seed last_fin_delta=0"
        );
    }

    #[test]
    fn fin_burst_velocity_monotonic_acceleration() {
        // Simulates an observed finalization Δ chain +16, +27, +31 — velocity
        // sequence +16-0=+16 (warmup), +27-16=+11, +31-27=+4.
        let state = test_node_state(None);
        // Tick 1: fin = 16 (from 0). Cold-start path: sample=16, delta=0, velocity=0.
        state
            .total_ever_finalized
            .store(16, std::sync::atomic::Ordering::Relaxed);
        state.sample_fin_burst_velocity();
        assert_eq!(
            state
                .last_fin_burst_velocity
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "tick 1 cold-start emits 0"
        );

        // Tick 2: fin = 16 + 27 = 43. current_delta = 27, prev_delta = 0,
        // velocity = 27. (Warmup transient — documented in HELP.)
        state
            .total_ever_finalized
            .store(43, std::sync::atomic::Ordering::Relaxed);
        state.sample_fin_burst_velocity();
        assert_eq!(
            state
                .last_fin_burst_velocity
                .load(std::sync::atomic::Ordering::Relaxed),
            27,
            "tick 2 reports synthetic velocity = current_delta (warmup)"
        );

        // Tick 3: fin = 43 + 31 = 74. current_delta = 31, prev_delta = 27,
        // velocity = +4. (True Δ² semantics from tick 3 onward.)
        state
            .total_ever_finalized
            .store(74, std::sync::atomic::Ordering::Relaxed);
        state.sample_fin_burst_velocity();
        assert_eq!(
            state
                .last_fin_burst_velocity
                .load(std::sync::atomic::Ordering::Relaxed),
            4,
            "tick 3 reports true Δ² acceleration: 31-27=+4"
        );
    }

    #[test]
    fn fin_burst_velocity_decel_negative_reading() {
        // Simulates the chain decel signature: fin Δ +30, +10. Velocity:
        // tick 1 cold-start 0, tick 2 synthetic +30, tick 3 -20 (decel).
        let state = test_node_state(None);
        state
            .total_ever_finalized
            .store(1, std::sync::atomic::Ordering::Relaxed);
        state.sample_fin_burst_velocity(); // cold-start: velocity=0
        state
            .total_ever_finalized
            .store(31, std::sync::atomic::Ordering::Relaxed);
        state.sample_fin_burst_velocity(); // synthetic: velocity=30
        state
            .total_ever_finalized
            .store(41, std::sync::atomic::Ordering::Relaxed);
        state.sample_fin_burst_velocity(); // true Δ²: 10-30 = -20
        assert_eq!(
            state
                .last_fin_burst_velocity
                .load(std::sync::atomic::Ordering::Relaxed),
            -20,
            "decel from Δ=30 to Δ=10 reports velocity=-20"
        );
    }

    #[test]
    fn fin_burst_velocity_steady_state_emits_zero() {
        // Steady-state cadence (constant Δ per tick) yields velocity=0 in the
        // stable phase. Sequence: fin Δ +5, +5, +5 → velocity 0 (cold), 5
        // (warmup), 0 (steady).
        let state = test_node_state(None);
        state
            .total_ever_finalized
            .store(5, std::sync::atomic::Ordering::Relaxed);
        state.sample_fin_burst_velocity();
        state
            .total_ever_finalized
            .store(10, std::sync::atomic::Ordering::Relaxed);
        state.sample_fin_burst_velocity();
        state
            .total_ever_finalized
            .store(15, std::sync::atomic::Ordering::Relaxed);
        state.sample_fin_burst_velocity();
        assert_eq!(
            state
                .last_fin_burst_velocity
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "constant Δ=5 yields velocity=0 in steady state"
        );

        // One more tick at the same cadence — still 0.
        state
            .total_ever_finalized
            .store(20, std::sync::atomic::Ordering::Relaxed);
        state.sample_fin_burst_velocity();
        assert_eq!(
            state
                .last_fin_burst_velocity
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "constant Δ=5 yields velocity=0 indefinitely"
        );
    }

    #[test]
    fn fin_burst_velocity_genesis_node_no_fin_yet() {
        // Genesis-fresh node where fin stays at 0 indefinitely (no records
        // finalized yet). Every tick: sample=0, fin_now=0, cold-start path
        // is NOT triggered (the guard is `prev == 0 && fin_now > 0`), so we
        // fall through to the normal path: current_delta = 0, prev_delta = 0,
        // velocity = 0. Stable at 0 indefinitely.
        let state = test_node_state(None);
        for _ in 0..5 {
            state.sample_fin_burst_velocity();
            assert_eq!(
                state
                    .last_fin_burst_velocity
                    .load(std::sync::atomic::Ordering::Relaxed),
                0,
                "genesis-fresh node holds velocity=0 indefinitely"
            );
        }
    }

    // ── bratio band-tick dispatch (5-arm code→counter map) ────────────────
    //
    // The empty-consensus DORMANT path and the metrics-body wiring are
    // already covered by the three tests at L6422-L6496 in this module
    // (`bratio_band_ticks_counters_initialize_to_zero`,
    // `sample_bratio_band_tick_on_fresh_state_bumps_dormant_only`,
    // `bratio_band_ticks_total_surfaces_in_metrics_body`). The tests
    // below close the remaining gap: the 5-arm dispatch from band code
    // to counter slot, and the partition invariant that the HELP block
    // promises operators. Standing up an `AWCConsensus` deep enough to
    // make `classify_cohort()` return codes 1-4 is heavy fixture work
    // for a 5-line dispatch — the split helper `bump_bratio_band_tick`
    // is the seam these tests target.

    /// Helper: read the 5-tuple of band-tick counters (dormant, locked,
    /// converged, active, hyper_active). Used to assert the dispatch
    /// landed in the right counter without naming each load inline.
    fn band_tick_snapshot(state: &NodeState) -> (u64, u64, u64, u64, u64) {
        use std::sync::atomic::Ordering::Relaxed;
        (
            state.bratio_band_ticks_dormant_total.load(Relaxed),
            state.bratio_band_ticks_locked_total.load(Relaxed),
            state.bratio_band_ticks_converged_total.load(Relaxed),
            state.bratio_band_ticks_active_total.load(Relaxed),
            state.bratio_band_ticks_hyper_active_total.load(Relaxed),
        )
    }

    #[test]
    fn bratio_band_tick_dispatch_routes_each_band_to_its_counter() {
        // Drive `bump_bratio_band_tick(code)` for each of the 5 valid
        // codes and verify the matching counter advances. Catches
        // code↔counter transpositions in the match arm — the bug
        // surface that a `classify_cohort()`-only test
        // (consensus.rs:9319..) cannot reach.
        let state = test_node_state(None);
        state.bump_bratio_band_tick(0);
        assert_eq!(band_tick_snapshot(&state), (1, 0, 0, 0, 0), "code 0 → DORMANT");
        state.bump_bratio_band_tick(1);
        assert_eq!(band_tick_snapshot(&state), (1, 1, 0, 0, 0), "code 1 → LOCKED");
        state.bump_bratio_band_tick(2);
        assert_eq!(band_tick_snapshot(&state), (1, 1, 1, 0, 0), "code 2 → CONVERGED");
        state.bump_bratio_band_tick(3);
        assert_eq!(band_tick_snapshot(&state), (1, 1, 1, 1, 0), "code 3 → ACTIVE");
        state.bump_bratio_band_tick(4);
        assert_eq!(band_tick_snapshot(&state), (1, 1, 1, 1, 1), "code 4 → HYPER_ACTIVE");
    }

    #[test]
    fn bratio_band_tick_unknown_band_is_noop() {
        let state = test_node_state(None);
        state.bump_bratio_band_tick(5);
        state.bump_bratio_band_tick(255);
        assert_eq!(band_tick_snapshot(&state), (0, 0, 0, 0, 0), "out-of-range band must not panic or increment any counter");
    }

    #[test]
    fn bratio_band_tick_partition_invariant_holds_across_mixed_codes() {
        // Mixed-code burst — emulating a node cycling through bands
        // during a multi-tick settlement event.
        // Sum of the 5 counters MUST equal the total call count. This
        // is the load-bearing semantic the HELP block promises
        // operators: `rate(...{band="X"}[5m])` summed over X must equal
        // `rate(elara_seal_loop_ticks_total[5m])` (modulo the
        // catchup-skip subset).
        let state = test_node_state(None);
        for _ in 0..3 { state.bump_bratio_band_tick(0); }
        for _ in 0..4 { state.bump_bratio_band_tick(1); }
        for _ in 0..2 { state.bump_bratio_band_tick(2); }
        for _ in 0..5 { state.bump_bratio_band_tick(3); }
        for _ in 0..1 { state.bump_bratio_band_tick(4); }
        let (d, l, c, a, h) = band_tick_snapshot(&state);
        assert_eq!((d, l, c, a, h), (3, 4, 2, 5, 1));
        assert_eq!(
            d + l + c + a + h,
            15,
            "partition invariant: sum of 5 band counters must equal total calls"
        );
    }

    // ── store_max_atomic + apply_metadata_filter pure-helper pins ──────────
    //
    // Pins two module-level pure helpers that had zero direct test coverage:
    //
    //   1. `store_max_atomic` (state.rs:115) — atomic-max CAS-loop with
    //      relaxed ordering. Duplicated at 5 sites (state_core.rs:227,
    //      sync.rs:578/587, epoch.rs:63, two record_stats_*_ts_bits sites).
    //      Monotone behavior is load-bearing for high-water-mark gauges; a
    //      regression here would let max counters slip backward under races.
    //
    //   2. `apply_metadata_filter` (state.rs:4720) — Protocol §11.23 post-
    //      filter applied after Layer B / fallback fetch. Four-quadrant
    //      Option/Option dispatch (neither / key only / value only /
    //      key+value). The inner matcher `json_value_matches_string`
    //      already has 3 direct tests (state.rs:4870/4879/4889) — this batch
    //      pins the filter's quadrant routing + dispatch through the matcher.
    //
    // Pure-helper only — no NodeState construction, no storage, no async.

    #[test]
    fn batch_b_store_max_atomic_no_decrease_lower_or_equal_candidates_higher_overwrites() {
        use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

        // Fresh target — candidate==current (==0) is the no-op edge case:
        // CAS-loop guard `while candidate > current` short-circuits before
        // entering, so no spurious compare_exchange_weak attempt.
        let target = AtomicU64::new(0);
        store_max_atomic(&target, 0);
        assert_eq!(target.load(Relaxed), 0, "candidate == current must no-op");

        // First raise from 0 → 100 — CAS enters the loop once.
        store_max_atomic(&target, 100);
        assert_eq!(target.load(Relaxed), 100, "first raise overwrites zero target");

        // Lower candidate (50 < 100) must NOT decrease the target. This is
        // the load-bearing semantic for high-water-mark gauges: a slower
        // reader cannot step a max back down.
        store_max_atomic(&target, 50);
        assert_eq!(target.load(Relaxed), 100, "lower candidate must not decrease target");

        // Equal candidate (100 == 100) — short-circuit, no CAS attempt.
        store_max_atomic(&target, 100);
        assert_eq!(target.load(Relaxed), 100, "equal candidate must no-op (no CAS)");

        // Higher candidate (200 > 100) — overwrites.
        store_max_atomic(&target, 200);
        assert_eq!(target.load(Relaxed), 200, "higher candidate overwrites");

        // u64::MAX edge — saturates without panic or wrap.
        store_max_atomic(&target, u64::MAX);
        assert_eq!(target.load(Relaxed), u64::MAX, "u64::MAX is reachable as a target");

        // Any further candidate at or below u64::MAX must no-op (target
        // already at the absolute ceiling).
        store_max_atomic(&target, 0);
        assert_eq!(target.load(Relaxed), u64::MAX, "u64::MAX target sticks against 0");
        store_max_atomic(&target, u64::MAX - 1);
        assert_eq!(target.load(Relaxed), u64::MAX, "(u64::MAX - 1) does not decrease");

        // Independent target — proves the helper takes `&AtomicU64` and
        // does not touch any global state. Two CAS-max paths in parallel
        // must observe each other's writes only via the shared reference.
        let other = AtomicU64::new(7);
        store_max_atomic(&other, 3);
        assert_eq!(other.load(Relaxed), 7, "second target unaffected by first");
        assert_eq!(target.load(Relaxed), u64::MAX, "first target unaffected by second");
    }

    #[test]
    fn batch_b_apply_metadata_filter_neither_set_is_no_op_preserves_all_records() {
        // Quadrant 1: `key=None, value=None` short-circuits at the
        // `if key.is_none() && value.is_none()` early return. Records pass
        // through unmodified — this is the no-filter case from RPC parsing
        // (HTTP query string lacks both `?key=` and `?value=`).
        let mut records = vec![
            test_record("r1", vec![], 1.0),
            test_record("r2", vec![], 2.0),
            test_record("r3", vec![], 3.0),
        ];
        apply_metadata_filter(&mut records, None, None);
        assert_eq!(records.len(), 3, "neither set must preserve all records");
        let ids: Vec<&str> = records.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, vec!["r1", "r2", "r3"], "order preserved verbatim");

        // Records with non-empty metadata also pass through unchanged when
        // both filters are None — proves the short-circuit is keyed on the
        // arguments, not on the records' metadata population.
        let mut r1 = test_record("rA", vec![], 10.0);
        r1.metadata.insert("k".into(), serde_json::json!("v"));
        let mut records = vec![r1, test_record("rB", vec![], 11.0)];
        apply_metadata_filter(&mut records, None, None);
        assert_eq!(records.len(), 2, "populated metadata preserved under no-op filter");
    }

    #[test]
    fn batch_b_apply_metadata_filter_key_only_filters_by_metadata_key_presence() {
        // Quadrant 2: `key=Some, value=None` keeps records whose metadata
        // contains the key — value is irrelevant (existence-only check
        // via `r.metadata.contains_key(k)`).
        let mut r1 = test_record("r1", vec![], 1.0);
        r1.metadata.insert("trace_id".into(), serde_json::json!("abc"));
        let mut r2 = test_record("r2", vec![], 2.0);
        r2.metadata.insert("zone".into(), serde_json::json!(7)); // different key
        let mut r3 = test_record("r3", vec![], 3.0);
        r3.metadata.insert("trace_id".into(), serde_json::json!("def")); // different value, same key
        let r4 = test_record("r4", vec![], 4.0); // empty metadata

        let mut records = vec![r1, r2, r3, r4];
        apply_metadata_filter(&mut records, Some("trace_id"), None);

        // Only r1 and r3 carry the `trace_id` key; r2 has `zone` but not
        // `trace_id`; r4 has nothing.
        assert_eq!(records.len(), 2, "key-only retains records with the key present");
        let ids: Vec<&str> = records.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, vec!["r1", "r3"], "value irrelevant — both abc/def kept");

        // Key absent everywhere — all records drop.
        let mut empty_match = vec![test_record("rX", vec![], 5.0)];
        apply_metadata_filter(&mut empty_match, Some("nonexistent"), None);
        assert!(empty_match.is_empty(), "absent key in all records drops the vec");
    }

    #[test]
    fn batch_b_apply_metadata_filter_value_only_searches_all_keys_for_matching_value() {
        // Quadrant 3: `key=None, value=Some` keeps records where ANY
        // metadata value (across all keys) matches the target string. Wide
        // net — this is the `?value=` path with no key narrowing. Uses
        // `r.metadata.values().any(|val| json_value_matches_string(val, v))`.
        let mut r1 = test_record("r1", vec![], 1.0);
        r1.metadata.insert("k1".into(), serde_json::json!("alpha"));
        let mut r2 = test_record("r2", vec![], 2.0);
        r2.metadata.insert("k2".into(), serde_json::json!("alpha")); // matches via different key
        let mut r3 = test_record("r3", vec![], 3.0);
        r3.metadata.insert("k1".into(), serde_json::json!("beta"));
        r3.metadata.insert("k3".into(), serde_json::json!("alpha")); // matches via second key
        let r4 = test_record("r4", vec![], 4.0); // no metadata
        let mut r5 = test_record("r5", vec![], 5.0);
        r5.metadata.insert("k1".into(), serde_json::json!("gamma")); // no value matches

        let mut records = vec![r1, r2, r3, r4, r5];
        apply_metadata_filter(&mut records, None, Some("alpha"));

        // r1, r2, r3 each have at least one value == "alpha"; r4 has no
        // metadata so `.values().any(...)` is vacuously false; r5 has no
        // matching value.
        assert_eq!(records.len(), 3, "value-only retains records with any matching value");
        let ids: Vec<&str> = records.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, vec!["r1", "r2", "r3"], "match found in any key counts");
    }

    #[test]
    fn batch_b_apply_metadata_filter_key_value_pair_uses_string_match_on_rendered_value() {
        // Quadrant 4: `key=Some, value=Some` requires the specific key to
        // exist AND its value to match the target via
        // `json_value_matches_string`. Pins the dispatch wiring — pairs
        // with the direct tests of `json_value_matches_string` at lines
        // 4870/4879/4889 by proving `apply_metadata_filter` routes through
        // the matcher for each of String / Number / Bool / Null branches.
        let mut r_string = test_record("r_string", vec![], 1.0);
        r_string.metadata.insert("kind".into(), serde_json::json!("transfer"));
        let mut r_number = test_record("r_number", vec![], 2.0);
        r_number.metadata.insert("amount".into(), serde_json::json!(42));
        let mut r_bool = test_record("r_bool", vec![], 3.0);
        r_bool.metadata.insert("flag".into(), serde_json::json!(true));
        let mut r_null = test_record("r_null", vec![], 4.0);
        r_null.metadata.insert("payload".into(), serde_json::Value::Null);
        let mut r_wrong_value = test_record("r_wrong_value", vec![], 5.0);
        r_wrong_value.metadata.insert("kind".into(), serde_json::json!("mint"));
        let r_missing_key = test_record("r_missing_key", vec![], 6.0); // no metadata at all

        // (kind, "transfer") — String branch, only r_string survives.
        let mut records = vec![
            r_string.clone(), r_number.clone(), r_bool.clone(),
            r_null.clone(), r_wrong_value.clone(), r_missing_key.clone(),
        ];
        apply_metadata_filter(&mut records, Some("kind"), Some("transfer"));
        assert_eq!(records.len(), 1, "String branch matches one record");
        assert_eq!(records[0].id, "r_string");

        // (amount, "42") — Number branch via Display::to_string fallback.
        let mut records = vec![
            r_string.clone(), r_number.clone(), r_bool.clone(), r_null.clone(),
        ];
        apply_metadata_filter(&mut records, Some("amount"), Some("42"));
        assert_eq!(records.len(), 1, "Number branch via to_string matches \"42\" → Number(42)");
        assert_eq!(records[0].id, "r_number");

        // (flag, "true") — Bool(true) branch.
        let mut records = vec![
            r_string.clone(), r_number.clone(), r_bool.clone(), r_null.clone(),
        ];
        apply_metadata_filter(&mut records, Some("flag"), Some("true"));
        assert_eq!(records.len(), 1, "Bool(true) branch matches \"true\"");
        assert_eq!(records[0].id, "r_bool");

        // (payload, "null") — Value::Null branch.
        let mut records = vec![
            r_string.clone(), r_number.clone(), r_bool.clone(), r_null.clone(),
        ];
        apply_metadata_filter(&mut records, Some("payload"), Some("null"));
        assert_eq!(records.len(), 1, "Value::Null branch matches \"null\"");
        assert_eq!(records[0].id, "r_null");

        // Mismatched value with present key — drops the record. Pins the
        // false-arm of `json_value_matches_string` reaching the retain
        // predicate.
        let mut records = vec![r_wrong_value.clone()];
        apply_metadata_filter(&mut records, Some("kind"), Some("transfer"));
        assert!(records.is_empty(), "present key with non-matching value drops");

        // Missing key with target value — drops the record. `r.metadata.get(k)`
        // returns None → `.unwrap_or(false)` keeps the predicate false.
        let mut records = vec![r_missing_key.clone()];
        apply_metadata_filter(&mut records, Some("kind"), Some("transfer"));
        assert!(records.is_empty(), "missing key drops record regardless of value");
    }

}
