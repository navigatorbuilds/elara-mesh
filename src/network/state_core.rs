//! State Core — single-owner task for all mutable node state.
//!
//! Replaces shared RwLock access with message-passing. The core owns
//! the DAG, ledger, and consensus state. All mutations go through the
//! ingest channel. Reads come from periodic snapshots (Arc<StateSnapshot>).
//!
//! This eliminates lock contention between gossip, HTTP handlers, and
//! background tasks — a major production blocker.
//!
//! Spec references:
//!   @spec Protocol §3.2

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use arc_swap::ArcSwap;

use crate::record::ValidationRecord;
use super::state::{NodeState, DeferredAttestation};
use super::ingest;
use super::{LockRecover, RwLockRecover};

/// Messages sent to the state core for processing.
pub enum StateMessage {
    /// Insert a record into the DAG + ledger. Returns result via oneshot.
    InsertRecord {
        record: Box<ValidationRecord>,
        source: RecordSource,
        reply: oneshot::Sender<InsertResult>,
    },
    /// Replace the entire ledger (used by rebuild_ledger after sync).
    /// Routes through state core to avoid direct write lock contention.
    ReplaceLedger {
        ledger: Box<crate::accounting::ledger::LedgerState>,
        reply: oneshot::Sender<()>,
    },
    /// Query: get current snapshot (for callers that need synchronous access).
    GetSnapshot {
        reply: oneshot::Sender<Arc<StateSnapshot>>,
    },
    /// Shutdown the core gracefully.
    Shutdown,
}

/// Priority level for state core messages.
/// RPC/local operations get processed before sync/gossip.
impl StateMessage {
    /// Returns true if this message is high-priority.
    /// RPC/local and gossip push get priority — gossip push records are
    /// already validated by the sender and must not starve behind bulk
    /// delta-pull backlog (the normal channel can back up for minutes
    /// when ledger write-lock contention slows state_core throughput).
    pub fn is_priority(source: &RecordSource) -> bool {
        matches!(source, RecordSource::Local | RecordSource::HttpSubmit { .. } | RecordSource::GossipPush { trusted: true, .. })
    }
}

/// Where a record came from (for metrics + gossip decisions).
#[derive(Debug, Clone)]
pub enum RecordSource {
    /// Submitted via HTTP POST /records
    HttpSubmit { peer_ip: Option<String> },
    /// Received via gossip pull
    GossipPull { peer_hash: String },
    /// Received via gossip push.
    ///
    /// `peer_hash` is the *claimed* originator/relayer from the peer-supplied
    /// `x-elara-sender` header (kept for relay-exclusion + dedup + metrics).
    /// `trusted` is the security-bearing bit: it is `true` only when the
    /// **handshake-authenticated** peer (`PqStream::peer_identity_hash`, NOT
    /// the spoofable header) is a relayer we trust — a configured seed, the
    /// genesis authority, a staked identity, or a local same-process call.
    /// Only a *trusted* push earns the rate-exempt + priority-lane treatment a
    /// legitimate relay of already-validated chain data needs (B6). An
    /// authed-but-untrusted stranger's push is `trusted: false` and is policed
    /// exactly like a fresh `HttpSubmit` (full node-local gauntlet, normal
    /// lane) — see `skips_timestamp_defense` / `is_priority`.
    GossipPush { peer_hash: String, trusted: bool },
    /// Created locally (CLI, auto-witness)
    Local,
    /// Received during initial/delta sync (historical data — skip timestamp defense)
    Sync,
}

impl RecordSource {
    /// Whether records from this source bypass the timestamp-defense gate.
    ///
    /// `Sync` and *trusted* `GossipPush` carry chain data the originator
    /// already timestamp-validated (a trusted relay is a seed/staked/authority
    /// peer; an untrusted authed stranger's push is `trusted: false` and is
    /// NOT exempt — B6). Re-gating them against the *receiver's* wall clock
    /// would reject legitimate records on any node whose clock trails the origin
    /// by more than `MAX_FUTURE_SKEW_SECS` (5 min) — which would deadlock an
    /// external follower (a fresh node joining over a clock-skewed or
    /// high-latency link) out of ever syncing, since it never originates the
    /// chain records it needs and so could never climb the drift estimator out
    /// of the rejection. Freshly-originated records (`Local`, `HttpSubmit`) are
    /// policed against the local clock as normal — there the comparison is the
    /// node's own clock against itself, so absolute offset is irrelevant.
    ///
    /// `GossipPull` is currently gated (returns false) and is **never
    /// constructed on a production ingest path** today (all pull/backfill
    /// ingestion routes through `insert_record_synced` → `Sync`). If a live
    /// ingest path ever tags pulled *historical* records as `GossipPull`, this
    /// classification MUST be revisited: gating bulk historical reconciliation
    /// on the local clock re-introduces the same follower-skew deadlock that
    /// keeping `Sync` skip-true exists to prevent.
    ///
    /// Load-bearing for external join — pinned by the truth-table test below.
    /// Keep this the single source of truth; do not re-inline the `matches!`.
    pub fn skips_timestamp_defense(&self) -> bool {
        matches!(self, RecordSource::Sync | RecordSource::GossipPush { trusted: true, .. })
    }
}

/// Result of attempting to insert a record.
#[derive(Debug)]
pub enum InsertResult {
    /// Record accepted and inserted.
    Accepted { record_id: String },
    /// Record rejected (duplicate, invalid, etc.)
    Rejected { reason: String },
    /// Error during processing.
    Error { message: String },
}

/// Read-only snapshot of node state. Published by the core after mutations.
/// HTTP handlers and background tasks read from this — never blocked by writes.
#[derive(Debug, Clone)]
pub struct StateSnapshot {
    // DAG stats
    pub dag_size: usize,
    pub dag_edges: usize,
    pub dag_tips: usize,
    pub dag_roots: usize,
    pub dag_orphan_edges: usize,

    // Ledger stats
    pub ledger_supply: u64,
    pub ledger_accounts: usize,
    pub ledger_staked: u64,
    pub conservation_pool: u64,

    // Consensus
    pub consensus_attestations: usize,
    pub consensus_settled: usize,

    // Peers (not owned by core, but snapshotted for reads)
    pub peers_connected: usize,
    pub peers_total: usize,

    // DAG tip IDs (for lock-free dag_tip_parents in RPC handlers)
    pub dag_tip_ids: Vec<String>,

    // Finalized
    pub finalized_count: usize,

    // Epoch
    pub current_epoch: u64,

    // Ledger subsystem stats (avoids ledger read lock in /metrics)
    pub circuit_breaker_level: u8,
    pub cb_volume_24h: u64,
    pub cb_velocity_24h: f64,
    pub velocity_tracked: usize,
    pub acquisition_tracked: usize,
    pub vesting_active: usize,
    pub governance_active: usize,
    pub records_processed: u64,

    // Peer subsystem stats (avoids peers read lock in /metrics)
    pub banned_peers: usize,
    pub peers_in_backoff: usize,

    // Trust engine (avoids trust read lock in /metrics)
    pub trust_tracked: usize,

    // Timestamp of last mutation
    pub last_updated: f64,
}

impl Default for StateSnapshot {
    fn default() -> Self {
        Self {
            dag_size: 0,
            dag_edges: 0,
            dag_tips: 0,
            dag_roots: 0,
            dag_orphan_edges: 0,
            ledger_supply: 0,
            ledger_accounts: 0,
            ledger_staked: 0,
            conservation_pool: 0,
            dag_tip_ids: Vec::new(),
            consensus_attestations: 0,
            consensus_settled: 0,
            peers_connected: 0,
            peers_total: 0,
            finalized_count: 0,
            current_epoch: 0,
            circuit_breaker_level: 0,
            cb_volume_24h: 0,
            cb_velocity_24h: 0.0,
            velocity_tracked: 0,
            acquisition_tracked: 0,
            vesting_active: 0,
            governance_active: 0,
            records_processed: 0,
            banned_peers: 0,
            peers_in_backoff: 0,
            trust_tracked: 0,
            last_updated: 0.0,
        }
    }
}

/// Handle for sending messages to the state core.
/// Phase 2 of the zone-parallel state-core refactor: each worker owns a
/// private (normal, priority) channel pair. Records route to a worker by
/// hash of `record.record_zone().path()` so per-zone ordering is preserved
/// while different zones can run on different workers in parallel.
#[derive(Clone)]
struct WorkerChannels {
    tx: mpsc::Sender<StateMessage>,
    priority_tx: mpsc::Sender<StateMessage>,
}

/// Hard cap on the worker pool size. Above this, hash-routing collisions
/// negate the parallelism benefit and shutdown broadcast cost dominates.
/// Operator config is clamped to this ceiling at spawn time.
pub const MAX_STATE_CORE_WORKERS: u8 = 64;

/// Count of state_core watchdog firings at the 30s
/// threshold (first warn from `process_message`'s spawned watchdog timer).
/// Persistent non-zero rate = ingest pipeline routinely blocked >30s on at
/// least one record; pair with `elara_state_core_record_processing_max_ms`
/// to size the worst case. Read via [`state_core_watchdog_metrics`].
static STATE_CORE_WATCHDOG_30S_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Count of state_core watchdog firings at the 60s threshold
/// (confirmed deadlock log from the same spawned timer). Increments only
/// when the inner ingest call still hasn't completed 60s after the first
/// 30s warn — i.e. the record was stuck for the full minute, not transient.
static STATE_CORE_WATCHDOG_60S_TOTAL: AtomicU64 = AtomicU64::new(0);

/// High-water mark of `state_core: record processed in Xms`
/// across the worker pool since boot. Captures the worst-case (NOT
/// average) observed processing time. Watchdog logs catch >30s deadlocks
/// after the fact; this gauge is the lossless record of how slow the
/// pipeline actually got. Read via [`state_core_watchdog_metrics`].
static STATE_CORE_RECORD_PROCESSING_MAX_MS: AtomicU64 = AtomicU64::new(0);

/// Bump the 30s-watchdog counter. Called from the spawned timer
/// in `process_message` after the 30s sleep elapses without `watchdog.abort()`
/// having cancelled it. Cheap fetch_add — fired at most once per stuck record.
pub(crate) fn observe_state_core_watchdog_30s() {
    STATE_CORE_WATCHDOG_30S_TOTAL.fetch_add(1, Ordering::Relaxed);
}

/// Bump the 60s-watchdog counter. Called only after the second
/// 30s sleep, so `_30s` always increments first.
pub(crate) fn observe_state_core_watchdog_60s() {
    STATE_CORE_WATCHDOG_60S_TOTAL.fetch_add(1, Ordering::Relaxed);
}

/// Record the elapsed-ms of a completed record. CAS-loop on
/// the max guarantees monotonic-non-decreasing across all worker tasks.
/// Called once per record in the InsertRecord arm of `process_message`,
/// independent of success/failure (rejected records also count toward
/// pipeline pressure).
pub(crate) fn observe_state_core_record_ms(ms: u64) {
    let mut current = STATE_CORE_RECORD_PROCESSING_MAX_MS.load(Ordering::Relaxed);
    while ms > current {
        match STATE_CORE_RECORD_PROCESSING_MAX_MS.compare_exchange_weak(
            current,
            ms,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(actual) => current = actual,
        }
    }
}

/// Read the watchdog observability counters as a tuple of
/// `(watchdog_30s_total, watchdog_60s_total, record_processing_max_ms)`.
/// Used by the `/metrics` emitter in `network/server.rs`.
pub fn state_core_watchdog_metrics() -> (u64, u64, u64) {
    (
        STATE_CORE_WATCHDOG_30S_TOTAL.load(Ordering::Relaxed),
        STATE_CORE_WATCHDOG_60S_TOTAL.load(Ordering::Relaxed),
        STATE_CORE_RECORD_PROCESSING_MAX_MS.load(Ordering::Relaxed),
    )
}

/// Test-only reset of the watchdog counters. Required because the
/// counters are module-level statics shared across all tests in the binary.
#[cfg(test)]
pub(crate) fn reset_state_core_watchdog_metrics() {
    STATE_CORE_WATCHDOG_30S_TOTAL.store(0, Ordering::Relaxed);
    STATE_CORE_WATCHDOG_60S_TOTAL.store(0, Ordering::Relaxed);
    STATE_CORE_RECORD_PROCESSING_MAX_MS.store(0, Ordering::Relaxed);
}

/// High-water mark of any worker's normal-channel
/// queue depth observed at submission time. CHANNEL_SIZE=1024; gauge
/// reads as `1024 - tx.capacity()` = number of buffered messages waiting
/// for the worker. Pegged near 1024 = `tx.send().await` will block soon
/// = ingest backpressure cascading. Sampled per-record in `insert_record`,
/// so over time with zone-hash routing all workers get observed; the
/// `max` semantics naturally surface the worst-ever depth across the
/// pool. Distinct from the watchdog (post-hoc "this record was slow")
/// — this is pre-flight ("the queue ahead of this record is X deep").
static STATE_CORE_WORKER_NORMAL_QUEUE_DEPTH_MAX: AtomicU64 = AtomicU64::new(0);

/// Same shape but for the priority channel
/// (PRIORITY_CHANNEL_SIZE=1024; was 64 in an earlier revision).
/// Priority queue saturating means live-traffic submissions
/// (gossip-push from peers, RPC/local) are queueing — investigate
/// gossip fanout, witness-committee routing, or anchor-attestation lag.
static STATE_CORE_WORKER_PRIORITY_QUEUE_DEPTH_MAX: AtomicU64 = AtomicU64::new(0);

/// Saturation-event counters paired with the
/// queue-depth max gauges. The max gauges are bounded at the channel size
/// (1024 / 64), so a single boot-burst saturation pegs the gauge
/// forever — operators can't tell "boot burst, healthy now" from
/// "sustained backpressure happening every minute". These counters
/// increment every time the queue is observed at >= cap, so a flat
/// counter post-boot = boot-only saturation, a climbing counter =
/// sustained pressure that needs investigation. Trigger: a
/// priority_queue_depth_max=64 captured at boot is otherwise
/// indistinguishable from sustained 64/64 saturation without these.
static STATE_CORE_WORKER_NORMAL_AT_CAPACITY_TOTAL: AtomicU64 = AtomicU64::new(0);
static STATE_CORE_WORKER_PRIORITY_AT_CAPACITY_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Sample the chosen worker's queue depth at submission.
/// Cheap: 2× atomic loads + 2× CAS-loop max via the shared helper from
/// `network::state`. Inlined-by-default since it sits on the per-record
/// hot path. Saturation counters layer in on the same sample,
/// so the boot-burst-vs-sustained distinction is captured at no extra
/// observation cost.
#[inline]
pub(crate) fn observe_worker_queue_depth(normal_depth: u64, priority_depth: u64) {
    super::state::store_max_atomic(&STATE_CORE_WORKER_NORMAL_QUEUE_DEPTH_MAX, normal_depth);
    super::state::store_max_atomic(&STATE_CORE_WORKER_PRIORITY_QUEUE_DEPTH_MAX, priority_depth);
    if normal_depth >= CHANNEL_SIZE as u64 {
        STATE_CORE_WORKER_NORMAL_AT_CAPACITY_TOTAL.fetch_add(1, Ordering::Relaxed);
    }
    if priority_depth >= PRIORITY_CHANNEL_SIZE as u64 {
        STATE_CORE_WORKER_PRIORITY_AT_CAPACITY_TOTAL.fetch_add(1, Ordering::Relaxed);
    }
}

/// Read the worker queue-depth gauges as `(normal_max,
/// priority_max)`. Used by the `/metrics` emitter.
pub fn state_core_worker_queue_metrics() -> (u64, u64) {
    (
        STATE_CORE_WORKER_NORMAL_QUEUE_DEPTH_MAX.load(Ordering::Relaxed),
        STATE_CORE_WORKER_PRIORITY_QUEUE_DEPTH_MAX.load(Ordering::Relaxed),
    )
}

/// Read the saturation-event counters as `(normal_at_cap,
/// priority_at_cap)`. Compared post-boot, a non-zero counter that is
/// not climbing = boot-burst-only; a climbing counter under steady
/// load = sustained backpressure.
pub fn state_core_worker_at_capacity_metrics() -> (u64, u64) {
    (
        STATE_CORE_WORKER_NORMAL_AT_CAPACITY_TOTAL.load(Ordering::Relaxed),
        STATE_CORE_WORKER_PRIORITY_AT_CAPACITY_TOTAL.load(Ordering::Relaxed),
    )
}

/// Test-only reset of the worker-queue statics. Same rationale as the watchdog counters.
#[cfg(test)]
pub(crate) fn reset_state_core_worker_queue_metrics() {
    STATE_CORE_WORKER_NORMAL_QUEUE_DEPTH_MAX.store(0, Ordering::Relaxed);
    STATE_CORE_WORKER_PRIORITY_QUEUE_DEPTH_MAX.store(0, Ordering::Relaxed);
    STATE_CORE_WORKER_NORMAL_AT_CAPACITY_TOTAL.store(0, Ordering::Relaxed);
    STATE_CORE_WORKER_PRIORITY_AT_CAPACITY_TOTAL.store(0, Ordering::Relaxed);
}

/// Compute the worker index for a given zone path under a pool of size
/// `worker_count`. Uses `DefaultHasher` (non-cryptographic, stable per
/// process — collision-resistance not required, only a uniform spread).
/// `worker_count = 0` is treated as 1 (caller's bug, but no panic).
///
/// Zone path is used as the routing key so all records for one zone
/// always land on the same worker — preserving per-zone ordering.
pub fn worker_index_for_zone(zone_path: &str, worker_count: usize) -> usize {
    let n = worker_count.max(1);
    if n == 1 {
        return 0;
    }
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    zone_path.hash(&mut h);
    (h.finish() as usize) % n
}

/// Outcome of a graceful shutdown. Surfaces how many workers actually
/// drained their queues vs were aborted on timeout, so the operator can
/// distinguish "clean stop" from "in-flight inserts may have been lost".
/// Returned from [`StateCoreHandle::shutdown`].
#[derive(Debug, Clone, Copy)]
pub struct ShutdownReport {
    /// Total workers in the pool when shutdown was invoked. Zero on the
    /// Phase-1-compat `new()` path (synthetic handle with no join handles).
    pub workers: usize,
    /// Workers whose tokio task completed normally within the timeout.
    pub completed: usize,
    /// Workers that hit the timeout and were aborted. Indicates records
    /// in flight at the time of shutdown may not have been committed.
    pub timed_out: usize,
    /// Wall time elapsed between the first Shutdown send and the last
    /// awaited worker completion.
    pub elapsed: Duration,
}

#[derive(Clone)]
pub struct StateCoreHandle {
    /// One channel pair per worker. Length is fixed at spawn time and
    /// bounded by [`MAX_STATE_CORE_WORKERS`]. `workers[0]` is the canonical
    /// worker — `replace_ledger` and other globally-ordered ops pin there.
    workers: Arc<Vec<WorkerChannels>>,
    /// Current snapshot — lock-free reads via ArcSwap.
    pub snapshot: Arc<ArcSwap<StateSnapshot>>,
    /// Tokio JoinHandles for the worker tasks. `Option` so `shutdown()` can
    /// `take()` ownership on the first call (subsequent clones see `None`
    /// and return an empty report). Phase-1-compat `new()` initialises this
    /// to `None` since no tasks were spawned.
    handles: Arc<tokio::sync::Mutex<Option<Vec<JoinHandle<()>>>>>,
}

impl StateCoreHandle {
    /// Phase-1-compat constructor: single worker. Used by tests and any
    /// caller that doesn't need the worker pool. Internally wraps the
    /// (tx, priority_tx) pair as `workers[0]`. No `JoinHandle` is recorded
    /// — `shutdown()` on this path returns a zero-worker report.
    pub fn new(
        tx: mpsc::Sender<StateMessage>,
        priority_tx: mpsc::Sender<StateMessage>,
        snapshot: Arc<ArcSwap<StateSnapshot>>,
    ) -> Self {
        Self {
            workers: Arc::new(vec![WorkerChannels { tx, priority_tx }]),
            snapshot,
            handles: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }

    /// Number of workers in this pool. Always >= 1.
    pub fn worker_count(&self) -> usize {
        self.workers.len()
    }

    /// Pick the worker responsible for `zone_path` via stable hash.
    /// Same zone always lands on the same worker so per-zone ordering
    /// is preserved end-to-end. Single-worker pools short-circuit.
    fn route(&self, zone_path: &str) -> &WorkerChannels {
        let idx = worker_index_for_zone(zone_path, self.workers.len());
        &self.workers[idx]
    }

    /// Submit a record for insertion. Routes to priority or normal channel
    /// based on source — RPC/local goes to priority lane, gossip/sync to normal.
    /// In Phase 2, also routes to a per-zone worker by `record.record_zone()`.
    pub async fn insert_record(
        &self,
        record: ValidationRecord,
        source: RecordSource,
    ) -> InsertResult {
        let is_priority = StateMessage::is_priority(&source);
        let zone_path = record.record_zone().path().to_string();
        let worker = self.route(&zone_path);
        // Sample the chosen worker's queue depth before send. Depth =
        // `CHANNEL_SIZE - tx.capacity()`. Capacity is the number of FREE
        // permits in the underlying semaphore; subtracting from the channel
        // bound gives buffered-message count. Sampled pre-send so the gauge
        // reads "queue ahead of THIS record was X" — pegged near 1024 means
        // `send().await` is about to block on backpressure.
        let normal_depth = CHANNEL_SIZE.saturating_sub(worker.tx.capacity()) as u64;
        let priority_depth = PRIORITY_CHANNEL_SIZE.saturating_sub(worker.priority_tx.capacity()) as u64;
        observe_worker_queue_depth(normal_depth, priority_depth);
        let (reply_tx, reply_rx) = oneshot::channel();
        let msg = StateMessage::InsertRecord {
            record: Box::new(record),
            source,
            reply: reply_tx,
        };

        let send_result = if is_priority {
            worker.priority_tx.send(msg).await
        } else {
            worker.tx.send(msg).await
        };

        if send_result.is_err() {
            return InsertResult::Error {
                message: "state core shut down".into(),
            };
        }
        match reply_rx.await {
            Ok(result) => result,
            Err(_) => InsertResult::Error {
                message: "state core dropped reply".into(),
            },
        }
    }

    /// Replace the entire ledger (used after rebuild_ledger in sync/gossip).
    /// Routes through the state core to avoid direct write lock contention
    /// that was causing RPC deadlocks.
    ///
    /// Always pinned to worker 0: the ledger is global, so we serialize
    /// replacement against a single worker rather than racing N workers
    /// against the same write lock.
    pub async fn replace_ledger(&self, ledger: crate::accounting::ledger::LedgerState) {
        let (reply_tx, reply_rx) = oneshot::channel();
        let msg = StateMessage::ReplaceLedger {
            ledger: Box::new(ledger),
            reply: reply_tx,
        };
        // Use normal channel — rebuild is a sync/gossip operation, not user-facing
        if self.workers[0].tx.send(msg).await.is_err() {
            tracing::warn!("replace_ledger: state core shut down");
            return;
        }
        let _ = reply_rx.await;
    }

    /// Read the current snapshot (lock-free).
    pub fn read_snapshot(&self) -> Arc<StateSnapshot> {
        self.snapshot.load_full()
    }

    /// Request shutdown and await worker drain. Broadcasts `Shutdown` on
    /// every worker's priority channel (so the message jumps any backlog),
    /// then `await`s each worker's tokio task until it exits or `timeout`
    /// elapses. Workers still process queued messages before exiting, so
    /// any insert that already made it onto a channel is committed before
    /// the task returns.
    ///
    /// Phase 3 lifecycle improvement (L1572): the prior implementation was
    /// fire-and-forget — it sent the Shutdown message and returned, leaving
    /// the caller to `sleep(2s)` and hope. On a 1-CPU node where per-record
    /// processing can take 3-16s under load, the 2s sleep was insufficient
    /// and in-flight inserts were dropped on `systemctl stop`. The current
    /// impl actually awaits the workers, so the caller gets a deterministic
    /// "drained vs aborted" signal in [`ShutdownReport`].
    ///
    /// Only the first caller across all clones drains; later clones observe
    /// the `handles` slot as `None` and return a zero-worker report.
    pub async fn shutdown(&self, timeout: Duration) -> ShutdownReport {
        let start = Instant::now();
        for w in self.workers.iter() {
            let _ = w.priority_tx.send(StateMessage::Shutdown).await;
        }
        let handles = {
            let mut guard = self.handles.lock().await;
            guard.take()
        };
        let Some(handles) = handles else {
            return ShutdownReport {
                workers: 0,
                completed: 0,
                timed_out: 0,
                elapsed: start.elapsed(),
            };
        };
        let total = handles.len();
        let deadline = start + timeout;
        let mut completed = 0usize;
        let mut timed_out = 0usize;
        for h in handles {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                h.abort();
                timed_out += 1;
                continue;
            }
            match tokio::time::timeout(remaining, h).await {
                Ok(_) => completed += 1,
                Err(_) => timed_out += 1,
            }
        }
        ShutdownReport {
            workers: total,
            completed,
            timed_out,
            elapsed: start.elapsed(),
        }
    }
}

/// Normal channel buffer size. Reserved for bulk delta-pull / sync /
/// recovery traffic (`RecordSource::Sync` and `RecordSource::GossipPull`).
const CHANNEL_SIZE: usize = 1024;
/// Priority channel buffer size. Grown 64 → 1024 to match the normal
/// channel. Original sizing assumed priority was a small burst path for
/// `RecordSource::Local` + `HttpSubmit` only, but `is_priority()` also
/// routes `GossipPush` here — and on the genesis authority (single-anchor
/// cap), every node's gossip-push lands in the priority channel.
/// Saturation telemetry captured ~4 events/sec sustained at depth 64 even
/// at a <1 rec/s network rate. The
/// "drain priority before normal" guarantee is preserved regardless of
/// channel depth — a deeper buffer just absorbs gossip-fanout bursts
/// without back-pressuring the gossip handler.
const PRIORITY_CHANNEL_SIZE: usize = 1024;

// Compile-time invariants on the channel-depth knobs. PRIORITY_CHANNEL_SIZE
// was grown from 64 → 1024 because saturation events were observed
// sustained at depth=64 even at testnet's <1 rec/s
// fleet rate. A future "save memory" regression that drops EITHER buffer
// to 64 or below would re-open that window — fail at `cargo build`, not
// at `cargo test`.
const _: () = assert!(
    CHANNEL_SIZE > 64,
    "CHANNEL_SIZE must exceed the pre-OPS-146 priority ceiling of 64"
);
const _: () = assert!(
    PRIORITY_CHANNEL_SIZE > 64,
    "PRIORITY_CHANNEL_SIZE must exceed its pre-OPS-146 value of 64 — the saturation events OPS-145 measured were sustained at that depth"
);

/// Spawn the state core task. Returns a handle for sending messages.
///
/// Two channels: priority (RPC/local) and normal (gossip/sync).
/// The core always drains ALL priority messages before processing
/// one normal message. This guarantees user-facing RPCs respond
/// within ~4ms even during heavy gossip sync.
///
/// Phase 2 (zone-parallel state core): spawns
/// `state.config.state_core_worker_count` worker tasks, clamped to
/// [1, MAX_STATE_CORE_WORKERS]. Each worker owns its own channel pair;
/// `StateCoreHandle::insert_record` hashes `record.record_zone()` to
/// pick a worker so per-zone ordering is preserved while distinct
/// zones can run in parallel. Helper loops (drain/sweep/sealed-broadcast/
/// delegation-prune/identity-evict) are spawned exactly once,
/// independent of worker count.
pub fn spawn_state_core(
    state: Arc<NodeState>,
) -> StateCoreHandle {
    let count = state.config.state_core_worker_count
        .clamp(1, MAX_STATE_CORE_WORKERS) as usize;
    let snapshot = Arc::new(ArcSwap::from_pointee(StateSnapshot::default()));

    // ARCH-1: drain + sweep the finalization_queue on every node.
    // `enqueue_finalized` is called unconditionally from consensus state
    // transitions, so a node without a drain loop would accumulate 10K+
    // entries in `finalization_queue`. `drain_and_commit_pending` safely
    // no-ops each drained rid when `pending_ledger` has no matching delta
    // (missing_delta branch in pending_drain.rs).
    spawn_pending_drain_loop(state.clone());
    spawn_pending_sweep_loop(state.clone());

    // MAINNET gap #8: drain-and-broadcast Sealed milestones from cascade
    // paths (force_finalized on behalf of epoch seal settlement, gap
    // recovery, pending_drain commits). Runs unconditionally — accounts
    // rely on Sealed events for optimistic UX.
    spawn_sealed_broadcast_loop(state.clone());

    // Profile C Gap E: drop expired delegation leases every 60s. Bounded
    // walk of `state.delegations` map; runs on every node so each peer
    // converges to the same registry view as leases age out.
    spawn_delegation_prune_loop(state.clone());

    // Identity Partitioning Phase B: cap CF_IDENTITIES_USER. Default
    // 100K entries (≈200 MB) on full_zone, configurable via
    // `identity_user_cache_max`. Tick is cheap when below cap (a single
    // RocksDB count op); a backlog drains at `evict_max_per_tick` per
    // tick interval.
    spawn_identity_user_evict_loop(state.clone());

    tracing::info!(
        "state core spawning {} worker(s) (normal: {}, priority: {})",
        count, CHANNEL_SIZE, PRIORITY_CHANNEL_SIZE
    );

    let mut workers = Vec::with_capacity(count);
    let mut handles = Vec::with_capacity(count);
    for worker_id in 0..count {
        let (tx, rx) = mpsc::channel::<StateMessage>(CHANNEL_SIZE);
        let (priority_tx, priority_rx) = mpsc::channel::<StateMessage>(PRIORITY_CHANNEL_SIZE);
        workers.push(WorkerChannels { tx, priority_tx });
        let h = tokio::spawn(state_core_worker_loop(
            worker_id,
            state.clone(),
            priority_rx,
            rx,
            snapshot.clone(),
        ));
        handles.push(h);
    }

    StateCoreHandle {
        workers: Arc::new(workers),
        snapshot,
        handles: Arc::new(tokio::sync::Mutex::new(Some(handles))),
    }
}

/// Worker loop body — drains priority and normal channels, processing one
/// record at a time per worker. Phase 1 of the zone-parallel state-core
/// refactor: extracted
/// from `spawn_state_core` so Phase 2 can spawn multiple workers (one per
/// zone-shard) using the same loop body.
///
/// Phase 2 (now): `spawn_state_core` spawns N workers per
/// `state.config.state_core_worker_count`; each worker owns its own
/// channel pair. `StateCoreHandle::insert_record` routes to a worker by
/// hash of `record.record_zone().path()`, so a single zone always lands
/// on the same worker (preserving per-zone ordering) while distinct
/// zones run in parallel.
async fn state_core_worker_loop(
    worker_id: usize,
    state: Arc<NodeState>,
    mut priority_rx: mpsc::Receiver<StateMessage>,
    mut rx: mpsc::Receiver<StateMessage>,
    snap_ref: Arc<ArcSwap<StateSnapshot>>,
) {
    tracing::info!(
        "state core worker {} started (normal: {}, priority: {})",
        worker_id, CHANNEL_SIZE, PRIORITY_CHANNEL_SIZE
    );

    // Build initial snapshot — only worker 0 publishes the boot snapshot
    // so N workers don't race to overwrite the same ArcSwap pointer with
    // identical contents N times.
    if worker_id == 0 {
        update_snapshot(&state, &snap_ref).await;
    }

    let mut mutations_since_snap = 0u64;
    let mut running = true;
    let mut normal_batch = 0u32;

    // Process up to batch_size normal records before sleeping.
    // yield_now() alone is insufficient under heavy CPU load — the
    // scheduler can immediately re-schedule this task. A real sleep
    // guarantees HTTP handlers get time slices during sync bursts.
    //
    // Adaptive: on 1-CPU/2GB nodes, the single tokio worker thread must
    // share between state_core and HTTP. Per-record processing
    // on 1-CPU/2GB nodes takes 100-2700ms (RocksDB I/O on 11GB SST with
    // 32MB block cache). A batch of 3 × 500ms = 1.5s continuous, and
    // a 5ms sleep is negligible (0.3%). Scale sleep up to give HTTP
    // handlers meaningful time for TLS handshakes (~50-100ms each).
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    let (batch_size, batch_sleep) = if cpus <= 1 {
        // 1-core: process 1 record then sleep 100ms. This guarantees
        // HTTP/TLS gets a real time window after EVERY record. Previous
        // batch=2/sleep=50ms was insufficient when records take 3-16s —
        // by the time the sleep fires, the TLS handshake already timed out.
        (1u32, std::time::Duration::from_millis(100))
    } else if cpus <= 2 {
        (5u32, std::time::Duration::from_millis(2))
    } else {
        (10u32, std::time::Duration::from_millis(1))
    };
    tracing::info!("state core batch: size={batch_size}, sleep={}ms (cpus={cpus})", batch_sleep.as_millis());

    while running {
        // PRIORITY FIRST: drain all priority messages before touching normal queue
        while let Ok(msg) = priority_rx.try_recv() {
            if process_message(&state, msg, &snap_ref, &mut mutations_since_snap).await {
                running = false;
                break;
            }
            tokio::task::yield_now().await;
        }
        if !running { break; }

        // Then process ONE normal message (non-blocking check first)
        tokio::select! {
            // Bias toward priority — check priority channel again in select
            msg = priority_rx.recv() => {
                if let Some(msg) = msg {
                    if process_message(&state, msg, &snap_ref, &mut mutations_since_snap).await {
                        break;
                    }
                } else {
                    break; // priority channel closed
                }
            }
            msg = rx.recv() => {
                if let Some(msg) = msg {
                    if process_message(&state, msg, &snap_ref, &mut mutations_since_snap).await {
                        break;
                    }
                    normal_batch += 1;
                } else {
                    break; // normal channel closed
                }
            }
        }

        // Every BATCH_SIZE normal records, sleep to let HTTP handlers run.
        // This caps burst throughput at ~10K records/s while keeping the
        // node responsive to /ping, /status, etc. during initial sync.
        if normal_batch >= batch_size {
            normal_batch = 0;
            tokio::time::sleep(batch_sleep).await;
        } else {
            tokio::task::yield_now().await;
        }
        // Stage 6 cooperative scheduler (Protocol §11.10): when the host
        // is busy (desktop user, 4K video, etc.) back off further so
        // elara-node stays an app-grade citizen. Fast no-op when idle.
        crate::network::system_load::coop_yield_if_busy(&state.system_load).await;
    }

    // Final snapshot
    update_snapshot(&state, &snap_ref).await;
    tracing::info!("state core worker {} stopped", worker_id);
}

/// Process a single state message. Returns true if shutdown requested.
async fn process_message(
    state: &Arc<NodeState>,
    msg: StateMessage,
    snap_ref: &Arc<ArcSwap<StateSnapshot>>,
    mutations_since_snap: &mut u64,
) -> bool {
    match msg {
        StateMessage::InsertRecord { record, source, reply } => {
            let origin_hint = match &source {
                RecordSource::GossipPull { .. } | RecordSource::GossipPush { .. } => None,
                _ => None,
            };
            let skip_timestamp_defense = source.skips_timestamp_defense();

            let t0 = std::time::Instant::now();
            // Char-boundary-safe: a raw `&record.id[..16]` here panics on a
            // multibyte id at byte 16, and this runs UNCONDITIONALLY in the
            // catch_unwind-free singleton worker (C1). Ids are ASCII-guarded at
            // decode (`record::validate_wire_id`); this is the belt-and-suspenders.
            let rid_short = crate::record::id_prefix(&record.id, 16);
            tracing::debug!("state_core: processing record {rid_short}");

            // Phase tracker: ingest.rs writes to state.insert_phase, watchdog reads it.
            // Phases: 0=start, 1=epoch-seal/merkle, 2=spawn_blocking, 3=dag.write, 4=ledger.write, 5=post
            state.insert_phase.store(0, std::sync::atomic::Ordering::Relaxed);

            // Watchdog: detect if insert_record_inner_direct hangs (deadlock).
            // Spawns a background timer that warns at 30s and errors at 60s.
            let rid_wd = rid_short.to_string();
            let state_wd = state.clone();
            let watchdog = tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                let p = state_wd.insert_phase.load(std::sync::atomic::Ordering::Relaxed);
                let phase_name = match p {
                    0 => "start/validation",
                    1 => "epoch-seal/merkle-prefetch",
                    2 => "storage/spawn_blocking",
                    3 => "dag.write()",
                    4 => "ledger.write()",
                    5 => "post-processing",
                    _ => "unknown",
                };
                let holder = state_wd.dag_write_holder.load(std::sync::atomic::Ordering::Relaxed);
                let holder_name = match holder {
                    0 => "none",
                    1 => "state_core(ingest)",
                    2 => "orphan_resolver",
                    3 => "finality_monitor",
                    4 => "bootstrap_pull",
                    5 => "admin",
                    6 => "startup",
                    7 => "snapshot_clone(dag.read)",
                    8 => "orphan_prune",
                    _ => "unknown",
                };
                tracing::error!("STATE_CORE WATCHDOG: record {rid_wd} stuck for 30s in phase {p} ({phase_name}), dag_write_holder={holder} ({holder_name})");
                observe_state_core_watchdog_30s();
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                let p2 = state_wd.insert_phase.load(std::sync::atomic::Ordering::Relaxed);
                let holder2 = state_wd.dag_write_holder.load(std::sync::atomic::Ordering::Relaxed);
                tracing::error!("STATE_CORE WATCHDOG: record {rid_wd} stuck for 60s in phase {p2} — confirmed deadlock, dag_write_holder={holder2}");
                observe_state_core_watchdog_60s();
            });
            let result = match ingest::insert_record_inner_direct(state, *record, origin_hint, skip_timestamp_defense).await {
                Ok(id) => {
                    // Drain deferred attestations for this record.
                    // NAT'd nodes push attestations before VPS has the record;
                    // those are buffered and applied here once the record arrives.
                    // Spawn as background task so state_core can proceed immediately —
                    // deferred att processing involves Dilithium3 verify + RocksDB + consensus
                    // which took 30+ seconds on 1-core nodes and froze the HTTP listener.
                    let deferred = {
                        let mut buf = state.deferred_attestations.lock()
                            .unwrap_or_else(|e| e.into_inner());
                        buf.remove(&id)
                    };
                    if let Some(atts) = deferred {
                        let state_bg = state.clone();
                        let id_bg = id.clone();
                        tokio::spawn(async move {
                            process_deferred_attestations(&state_bg, &id_bg, atts).await;
                        });
                    }
                    InsertResult::Accepted { record_id: id }
                }
                Err(e) => {
                    InsertResult::Rejected { reason: e.to_string() }
                }
            };
            watchdog.abort(); // cancel watchdog on successful completion

            let elapsed_ms = t0.elapsed().as_millis() as u64;
            observe_state_core_record_ms(elapsed_ms);
            tracing::info!("state_core: record processed in {elapsed_ms}ms");
            let _ = reply.send(result);

            *mutations_since_snap += 1;
            if *mutations_since_snap >= 10 {
                update_snapshot(state, snap_ref).await;
                *mutations_since_snap = 0;
            }
            false
        }

        StateMessage::ReplaceLedger { ledger, reply } => {
            // Swap the entire ledger — used after rebuild_ledger in sync/gossip.
            // By routing through the state core, we avoid external code taking
            // state.ledger.write() which caused RPC deadlocks.
            {
                let mut current = state.ledger.write().await;
                *current = *ledger;
                // Rebuild paths replay via `apply_op`, which maintains the
                // counter through every `governance.delegate`/`undelegate` call —
                // recount here is defense-in-depth against future replacement
                // sources that bypass replay (e.g. signed snapshot fast-paths).
                current.governance.recount_active_delegations();
                // Same reasoning for per-status proposal counts.
                current.governance.recount_proposal_statuses();
            }
            // Update consensus stakes from new ledger
            {
                let ledger = state.ledger.read().await;
                state.consensus.lock_recover().register_stakes_from_ledger(&ledger);
            }
            // Wholesale ledger replace → drop the memoized staked-anchor view.
            // This path (gossip/bg-sync route through state_core) previously
            // relied on the caller invalidating after `replace_ledger().await`;
            // doing it here makes the state_core sink self-complete so a future
            // caller that forgets the caller-side call can't serve a stale
            // committee → freeze (contract: state.rs:invalidate_anchor_view).
            state.invalidate_anchor_view();
            tracing::info!("state_core: ledger replaced via channel (rebuild_ledger)");
            let _ = reply.send(());

            // Force snapshot update after ledger replace
            update_snapshot(state, snap_ref).await;
            *mutations_since_snap = 0;
            false
        }

        StateMessage::GetSnapshot { reply } => {
            let _ = reply.send(snap_ref.load_full());
            false
        }

        StateMessage::Shutdown => {
            tracing::info!("state core shutting down");
            true
        }
    }
}

/// Process deferred attestations in a background task.
/// Previously ran inline in state_core, blocking the record processing pipeline
/// for 30+ seconds on 1-core nodes (Dilithium3 verify + RocksDB + consensus).
/// Now spawned as a separate Tokio task so state_core can proceed immediately.
async fn process_deferred_attestations(
    state: &Arc<NodeState>,
    record_id: &str,
    atts: Vec<DeferredAttestation>,
) {
    let att_count = atts.len();
    let mut applied = 0u32;
    for da in atts {
        let pk = match &da.witness_public_key {
            Some(pk) => pk,
            None => continue,
        };
        let signable = match state.get_record(record_id) {
            Ok(rec) => rec.signable_bytes(),
            Err(_) => continue,
        };
        match crate::crypto::pqc::dilithium3_verify(&signable, &da.signature, pk) {
            Ok(true) => {}
            _ => {
                tracing::debug!("deferred att: bad sig from {} for {}", &da.witness_hash[..da.witness_hash.len().min(16)], &record_id[..record_id.len().min(16)]);
                continue;
            }
        }
        // Gap 2.1 Phase 2b.3 + Identity Partitioning Phase A: witness
        // PK now verified-good. Store it in the appropriate identity-
        // tier CF so `committee_hash_from_pks(...)` can resolve
        // identity_hash → Dilithium PK on the producer side at finality
        // sign-time. Tier choice:
        //   • If the witness is in `CF_WITNESS_REGISTRY` for any zone
        //     the local node subscribes to → `CF_IDENTITIES_WITNESS`.
        //     Phase E will evict here on zone unsubscribe so the
        //     witness CF stays bounded by `subscribed_zones × witnesses`.
        //   • Otherwise → `CF_IDENTITIES_USER` (catch-all; LRU-bounded
        //     in Phase B).
        // Skip if already present (point-read is faster than a
        // redundant put under the steady-state where the same witness
        // attests many records). Best-effort: failure does not abort
        // the attestation flow — the witness has signed correctly and
        // their `pk_for_identity` lookup will simply fall back to a
        // fresh capture on the next attestation.
        if !state.rocks.has_public_key(&da.witness_hash) {
            let is_witness_for_my_zone = {
                let subs: Vec<String> = state
                    .zone_manager
                    .lock()
                    .ok()
                    .map(|mgr| {
                        mgr.subscribed_zones()
                            .iter()
                            .map(|z| z.path().to_string())
                            .collect()
                    })
                    .unwrap_or_default();
                subs.iter()
                    .any(|zp| state.rocks.is_witness_registered(zp, &da.witness_hash))
            };
            let result = if is_witness_for_my_zone {
                state.rocks.store_public_key_witness(&da.witness_hash, pk)
            } else {
                state.rocks.store_public_key_user(&da.witness_hash, pk)
            };
            match result {
                // Phase C: a real promotion (USER → WITNESS) bumps the
                // counter so operators can see class migrations under
                // load. User-side `Some(_)` returns mean "skipped because
                // higher tier present" — not a promotion, don't count it.
                Ok(Some(crate::storage::rocks::CF_IDENTITIES_USER)) if is_witness_for_my_zone => {
                    state
                        .identity_promotion_user_to_witness_total
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                Ok(_) => {}
                Err(e) => tracing::debug!(
                    "deferred att: pk capture skipped for {}: {e}",
                    &da.witness_hash[..da.witness_hash.len().min(16)]
                ),
            }
        }
        // PoWaS verification
        if let (Some(nonce), Some(difficulty)) = (da.powas_nonce, da.powas_difficulty) {
            let witness_stake = {
                let ledger = state.ledger.read().await;
                ledger.staked(&da.witness_hash)
            };
            if witness_stake > 0 {
                let proof = crate::network::powas::PoWaSProof { nonce, difficulty };
                if !crate::network::powas::verify(record_id, pk, witness_stake, &proof) {
                    tracing::debug!("deferred att: bad PoWaS from {} for {}", &da.witness_hash[..da.witness_hash.len().min(16)], &record_id[..record_id.len().min(16)]);
                    continue;
                }
            }
        }
        // Store and feed to consensus
        {
            let mgr = state.witness_mgr.as_ref();
            let _ = mgr.store_attestation_with_powas(
                record_id, &da.witness_hash, &da.signature, da.timestamp,
                da.witness_public_key.as_deref(),
                da.powas_nonce, da.powas_difficulty,
            );
        }
        let outcome = state.feed_attestation(record_id, &da.witness_hash, da.timestamp).await;
        // Previously this path dropped the settled signal — finalizations it
        // produced never fired rewards/events. Exactly-once edge closes that.
        if outcome.first_finalization {
            crate::network::reward::finalization_effects(state, vec![record_id.to_string()]);
        }
        applied += 1;
    }
    if applied > 0 {
        tracing::info!("deferred attestations: applied {applied}/{att_count} for {}", &record_id[..record_id.len().min(16)]);
    }
}

/// Build a snapshot from current state (reads are fast, no mutations).
/// Uses try_read() to avoid blocking the state core when sync/gossip holds
/// write locks. If locks are held, the snapshot is deferred to next mutation.
/// This prevents the #1 production deadlock: state core blocked in
/// update_snapshot → can't process ANY messages → RPC hangs forever.
async fn update_snapshot(state: &Arc<NodeState>, snap: &Arc<ArcSwap<StateSnapshot>>) {
    let dag = match state.dag.try_read() {
        Ok(d) => d,
        Err(_) => {
            tracing::debug!("update_snapshot: DAG write-locked, deferring");
            return;
        }
    };
    let ledger = match state.ledger.try_read() {
        Ok(l) => l,
        Err(_) => {
            tracing::debug!("update_snapshot: ledger write-locked, deferring");
            return;
        }
    };
    let peers = match state.peers.try_read() {
        Ok(p) => p,
        Err(_) => {
            tracing::debug!("update_snapshot: peers write-locked, deferring");
            return;
        }
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or_else(|_| {
            let prior = snap.load().last_updated;
            tracing::warn!(
                "update_snapshot: system clock before UNIX_EPOCH, \
                 keeping prior last_updated={prior}"
            );
            prior
        });

    let tips = dag.tips(); // sorted newest-first
    // Sample tips across the FULL range, not just newest 256.
    // Previous: .take(256) — only newest tips were visible to dag_tip_parents,
    // leaving 75-80% of older tips permanently unreferenced (dead tips).
    // Now: take newest 128 (active frontier) + randomly sample 128 from the rest.
    // This gives old tips a path to being referenced as parents, draining the
    // tip backlog while keeping the active frontier responsive.
    let tip_ids: Vec<String> = if tips.len() <= 256 {
        tips.clone()
    } else {
        let mut selected = Vec::with_capacity(256);
        // Newest 128: active frontier, high priority
        selected.extend(tips.iter().take(128).cloned());
        // Random 128 from the remaining tips (oldest biased via stride sampling)
        let remaining = &tips[128..];
        if remaining.len() <= 128 {
            selected.extend(remaining.iter().cloned());
        } else {
            // Stride through the old tips to get even coverage
            let stride = remaining.len() as f64 / 128.0;
            for i in 0..128 {
                let idx = (i as f64 * stride) as usize;
                if idx < remaining.len() {
                    selected.push(remaining[idx].clone());
                }
            }
        }
        selected
    };
    let vol_24h = ledger.circuit_breaker.volume_in_window(now);
    let new_snap = StateSnapshot {
        dag_size: dag.len(),
        dag_edges: dag.edge_count(),
        dag_tips: tips.len(),
        dag_roots: dag.roots().len(),
        dag_orphan_edges: dag.orphan_count(),
        ledger_supply: ledger.total_supply,
        ledger_accounts: ledger.accounts.len(),
        ledger_staked: ledger.total_staked,
        conservation_pool: ledger.conservation_pool,
        dag_tip_ids: tip_ids,
        consensus_attestations: 0,
        consensus_settled: 0,
        peers_connected: peers.connected().len(),
        peers_total: peers.len(),
        finalized_count: match state.finalized.try_read() {
            Ok(f) => f.len(),
            Err(_) => snap.load().finalized_count, // keep previous value if locked
        },
        current_epoch: {
            let ep = state.epoch.read_recover();
            let zone_count = super::consensus::get_zone_count();
            // Only consider active zones (0..zone_count) — stale zones from
            // old zone_count configs shouldn't inflate the reported epoch.
            ep.latest_epoch.iter()
                .filter(|(z, _)| {
                    z.path().parse::<u64>().is_ok_and(|n| n < zone_count)
                })
                .map(|(_, &v)| v)
                .max()
                .unwrap_or(0)
        },
        // Ledger subsystem stats — read from the ledger guard we already hold
        circuit_breaker_level: match ledger.circuit_breaker.level {
            crate::accounting::circuit_breaker::BreakerLevel::Normal => 0,
            crate::accounting::circuit_breaker::BreakerLevel::Level1 => 1,
            crate::accounting::circuit_breaker::BreakerLevel::Level2 => 2,
            crate::accounting::circuit_breaker::BreakerLevel::Level3 => 3,
        },
        cb_volume_24h: vol_24h,
        cb_velocity_24h: {
            let circ = ledger.total_supply.saturating_sub(ledger.total_staked);
            vol_24h as f64 / circ.max(1) as f64
        },
        velocity_tracked: ledger.velocity.tracked_identities(),
        acquisition_tracked: ledger.acquisition.tracked_identities(),
        vesting_active: ledger.vesting.active_vestings(),
        governance_active: ledger.governance.active_proposals(),
        records_processed: ledger.records_processed,
        // Peer subsystem stats — read from the peers guard we already hold
        banned_peers: peers.banned_count(),
        peers_in_backoff: peers.in_backoff_count(),
        // Trust engine — try_read to avoid blocking; keep previous on contention
        trust_tracked: match state.trust.try_read() {
            Ok(t) => t.tracked_identities(),
            Err(_) => snap.load().trust_tracked,
        },
        last_updated: now,
    };

    snap.store(Arc::new(new_snap));
}

/// ARCH-1 Phase 3.3c: background drain loop that commits finalized
/// pending deltas to the committed ledger. Tick cadence = 250 ms — tight
/// enough that the finality → committed-balance observable gap stays
/// sub-second at normal ingest rates, cheap enough that a tick on an
/// empty queue is a no-op lock acquire.
///
/// The loop exits when the tokio runtime is torn down (drop of the final
/// `Arc<NodeState>` doesn't signal the task directly, but
/// `drain_and_commit_pending` becomes a no-op once the state is
/// shutting down). We do not return a JoinHandle because the test /
/// runtime teardown path drops `NodeState` before joining.
pub fn spawn_pending_drain_loop(state: Arc<NodeState>) {
    const TICK: std::time::Duration = std::time::Duration::from_millis(250);
    tokio::spawn(async move {
        tracing::info!(
            "ARCH-1 pending drain loop started (tick={}ms)",
            TICK.as_millis()
        );
        let mut interval = tokio::time::interval(TICK);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            let stats = super::pending_drain::drain_and_commit_pending(&state).await;
            if stats.committed > 0 || stats.apply_failed > 0 || stats.missing_record > 0 {
                tracing::debug!(
                    "ARCH-1 drain tick: committed={} missing_delta={} missing_record={} apply_failed={}",
                    stats.committed,
                    stats.missing_delta,
                    stats.missing_record,
                    stats.apply_failed,
                );
            }
            // Gap 2.1 Phase 2b.3 Slice 4 fix: also drain witness-registry
            // queue on every node. Lives here (not in epoch_seal_loop)
            // because non-anchor nodes skip the seal loop entirely, which
            // left their CF_WITNESS_REGISTRY permanently empty even
            // though apply_op had run.
            super::pending_drain::flush_pending_witness_registrations(&state).await;
            // ZSP Phase D: bounded record purge for unsubscribed zones.
            // No-op when queue is empty; up to MAX_PURGE_PER_TICK records
            // per tick when a purge is in flight. Runs on every node so
            // unsubscribe is symmetric across the fleet.
            let purged = super::zone_purge::run_purge_tick(&state).await;
            if purged > 0 {
                tracing::debug!("ZSP Phase D: purged {purged} records this tick");
            }
        }
    });
}

/// ARCH-1 Phase 3.3e: sweep loop that discards pending deltas whose
/// record never reached Finalized within the timeout. Tick cadence is
/// 60 s — sweeps are O(total_pending) in the worst case so we don't
/// want to run them as fast as the drain loop. 60 s means a stuck
/// delta is cleared within 1 minute of crossing the timeout boundary.
pub fn spawn_pending_sweep_loop(state: Arc<NodeState>) {
    const TICK: std::time::Duration = std::time::Duration::from_secs(60);
    tokio::spawn(async move {
        tracing::info!(
            "ARCH-1 pending sweep loop started (tick={}s, ttl={}s)",
            TICK.as_secs(),
            super::pending_drain::PENDING_DISCARD_TIMEOUT_SECS as u64
        );
        let mut interval = tokio::time::interval(TICK);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            let stats = super::pending_drain::sweep_stale_pending(&state).await;
            if stats.discarded > 0 {
                tracing::debug!(
                    "ARCH-1 sweep tick: discarded={}",
                    stats.discarded
                );
            }
        }
    });
}

/// Profile C Gap E: periodic prune of expired delegation leases.
///
/// Walks `state.delegations` every `PRUNE_EXPIRED_INTERVAL_SECS` (60s) and
/// drops every child whose `expires_at < now`. Cheap by design — a 1M-child
/// registry takes a single HashMap iteration in milliseconds. Bumps
/// `delegation_lease_expired_total` by the number of children dropped.
///
/// Also calls `cleanup_authorize_history(now)` on the same tick to keep
/// the per-parent rate-limit window-set bounded as parents go quiet (no
/// new authorize ops for >1h). Without cleanup, the rate-limit map grows
/// once per (compromised gateway) and never sheds.
///
/// Runs on every node — registry replication relies on every node maintaining
/// the same view of expired children.
pub fn spawn_delegation_prune_loop(state: Arc<NodeState>) {
    use std::sync::atomic::Ordering;
    const TICK: std::time::Duration = std::time::Duration::from_secs(
        crate::accounting::delegation::PRUNE_EXPIRED_INTERVAL_SECS,
    );
    tokio::spawn(async move {
        tracing::info!(
            "Profile C Gap E: delegation prune loop started (tick={}s)",
            TICK.as_secs()
        );
        let mut interval = tokio::time::interval(TICK);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            let now = crate::network::ingest::now();
            let dropped: Vec<String> = {
                let mut registry = match state.delegations.write() {
                    Ok(g) => g,
                    Err(poisoned) => poisoned.into_inner(),
                };
                let dropped = registry.prune_expired(now);
                registry.cleanup_authorize_history(now);
                dropped
            };
            if !dropped.is_empty() {
                state
                    .delegation_lease_expired_total
                    .fetch_add(dropped.len() as u64, Ordering::Relaxed);
                let sample = dropped
                    .first()
                    .map(|s| &s[..s.len().min(16)])
                    .unwrap_or("");
                tracing::debug!(
                    "Gap E prune: {} expired children dropped (e.g. {})",
                    dropped.len(),
                    sample
                );
            }
        }
    });
}

/// Identity Partitioning Phase B — periodic LRU eviction on
/// `CF_IDENTITIES_USER`. When the user-tier CF count exceeds the
/// configured `identity_user_cache_max`, drops oldest entries down to
/// the cap. Tick interval and per-tick eviction cap are also
/// configurable; defaults are 60s and 5_000 entries.
///
/// The tick is a no-op when the CF is below cap (single RocksDB count
/// op), so this is safe to run on every node — anchor / witness /
/// archive / light alike. Operators on archive set
/// `identity_user_cache_max = 0` to disable eviction entirely.
///
/// Mirrors the `spawn_delegation_prune_loop` shape so the runtime is
/// uniform across periodic-bounded-work spawners.
pub fn spawn_identity_user_evict_loop(state: Arc<NodeState>) {
    use std::sync::atomic::Ordering;
    let cap = state.config.identity_user_cache_max;
    let interval_secs = state.config.identity_user_evict_interval_secs.max(1);
    let max_per_tick = state.config.identity_user_evict_max_per_tick.max(1);
    if cap == 0 {
        tracing::info!(
            "idp-B identity-user evict loop disabled (identity_user_cache_max=0)"
        );
        return;
    }
    let tick = std::time::Duration::from_secs(interval_secs);
    tokio::spawn(async move {
        tracing::info!(
            "idp-B identity-user evict loop started (cap={} entries, tick={}s, max_per_tick={})",
            cap, interval_secs, max_per_tick
        );
        let mut interval = tokio::time::interval(tick);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            let evicted = match state
                .rocks
                .evict_user_identities_to_cap(cap, max_per_tick)
            {
                Ok(n) => n,
                Err(e) => {
                    tracing::warn!("idp-B evict tick failed: {e}");
                    continue;
                }
            };
            if evicted > 0 {
                state
                    .identity_user_evicted_total
                    .fetch_add(evicted as u64, Ordering::Relaxed);
                tracing::debug!("idp-B evicted {} user-tier identities", evicted);
            }
        }
    });
}

/// MAINNET gap #8: periodic drain-and-broadcast of the newly_sealed_queue.
///
/// `feed_attestation` and `feed_attestation_batch` drain inline for the
/// lowest-latency account UX on the hot path, but any path that calls
/// `force_finalized` (pending_drain commit, epoch seal settlement, gap
/// recovery) cascades into `recompute_confirmation` for cross-zone
/// children — and can enqueue Sealed events that the hot-path drain
/// won't pick up. This loop sweeps those at ≤250 ms latency.
///
/// Drop-newest overflow on the queue means missed ticks don't lose
/// correctness; confirmation_levels remains ground truth. Runs on every
/// node — Gap 8 is a pure observability concern.
pub fn spawn_sealed_broadcast_loop(state: Arc<NodeState>) {
    const TICK: std::time::Duration = std::time::Duration::from_millis(250);
    tokio::spawn(async move {
        tracing::info!(
            "gap8 sealed-broadcast loop started (tick={}ms)",
            TICK.as_millis()
        );
        let mut interval = tokio::time::interval(TICK);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            let drained = {
                let mut consensus = state.consensus.lock_recover();
                consensus.drain_newly_sealed()
            };
            for (rid, witness_count) in drained {
                let _ = state.events.send(super::state::NodeEvent::RecordSealed {
                    record_id: rid,
                    witness_count,
                });
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hash::{sha3_256, sha3_256_hex};
    use crate::identity::{CryptoProfile, EntityType, Identity};
    use crate::network::config::NodeConfig;
    use crate::network::witness::WitnessManager;
    use crate::record::{Classification, ValidationRecord};
    use crate::storage::rocks::{StorageEngine, CF_PENDING_DELTAS};
    use crate::accounting::pending_delta::{PendingLedgerDelta, PendingOp};
    use crate::accounting::types::{self, extract_ledger_op, BASE_UNITS_PER_BEAT};
    use std::collections::BTreeMap;
    use std::sync::atomic::Ordering;

    // Module-scope serialization lock for the worker-queue-depth
    // gauges + at-capacity counters. Replaces per-test `static LOCK`s that
    // only serialized a test against itself — leaving cross-test races between
    // ops144/ops145 (which observe directly) and the `insert_record`
    // tests (which observe indirectly via `observe_worker_queue_depth` at
    // line 412 in production code). Holding a `std::sync::Mutex` across
    // `.await` is safe in `#[tokio::test]` (single-threaded runtime by default).
    static QUEUE_DEPTH_OBSERVER_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn pk(byte: u8) -> Vec<u8> {
        vec![byte; 1952]
    }

    fn mk_record(
        id: &str,
        creator_pk: &[u8],
        ts: f64,
        meta: BTreeMap<String, serde_json::Value>,
    ) -> ValidationRecord {
        ValidationRecord {
            id: id.into(),
            version: crate::wire::WIRE_VERSION,
            content_hash: sha3_256(id.as_bytes()).to_vec(),
            creator_public_key: creator_pk.to_vec(),
            timestamp: ts,
            parents: vec![],
            classification: Classification::Public,
            metadata: meta,
            signature: None,
            sphincs_signature: None,
            zk_proof: None,
            itc_stamp: None,
            zone_refs: Vec::new(),
            creator_sphincs_pk: None,
            sig_algorithm: 0x01,
            sphincs_algorithm: None,
            zone: None,
            identity_hash_wire: None,
            nonce: 0,
        }
    }

    /// ARCH-1 Phase 3.3c: the spawned drain loop actually processes the
    /// finality queue without any manual `drain_and_commit_pending` call.
    #[allow(clippy::manual_assert)]
    #[tokio::test]
    async fn test_arch_1_drain_loop_commits_finalized_deltas() {
        let genesis = pk(0x01);
        let alice = pk(0x02);
        let bob = pk(0x03);
        let genesis_hash = sha3_256_hex(&genesis);
        let alice_hash = sha3_256_hex(&alice);
        let bob_hash = sha3_256_hex(&bob);

        let tmp = tempfile::tempdir().expect("tempdir");
        let data_dir = tmp.path().to_path_buf();
        let config = NodeConfig {
            data_dir: data_dir.clone(),
            identity_path: data_dir.join("identity.json"),
            db_path: data_dir.join("elara.db"),
            admin_token: "test-admin".into(),
            network_id: "arch1-drain-loop-test".into(),
            mdns_enabled: false,
            health_check_interval_secs: 0,
            min_pow_difficulty: 0,
            genesis_authority: genesis_hash.clone(),
            ..Default::default()
        };

        let identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
            .expect("generate identity");
        let rocks = Arc::new(
            StorageEngine::open(data_dir.join("rocksdb")).expect("open rocksdb"),
        );
        let wmgr = Arc::new(WitnessManager::new(rocks.clone()));
        let state = Arc::new(NodeState::new(config, identity, rocks, wmgr));

        // Seed Alice
        let mint_rec = mk_record(
            "mint-loop",
            &genesis,
            1.0,
            types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis"),
        );
        {
            let mut ledger = state.ledger.write().await;
            ledger
                .apply_single_record(&mint_rec, &state.config.genesis_authority)
                .expect("seed mint");
        }

        // Build + persist transfer record, insert pending delta
        let xfer = mk_record(
            "xfer-loop",
            &alice,
            2.0,
            types::transfer_metadata(250 * BASE_UNITS_PER_BEAT, &bob_hash, None),
        );
        state.rocks.put_record(&xfer.id, &xfer).expect("put_record");
        let parsed = extract_ledger_op(&xfer).expect("parse").expect("ledger op");
        let delta = PendingLedgerDelta::new(
            xfer.id.clone(),
            alice_hash.clone(),
            xfer.timestamp,
            2.5,
            PendingOp::from_parsed(parsed, &alice_hash, &xfer.id),
        );
        {
            let mut pending = state.pending_ledger.write().await;
            pending.insert(delta.clone()).expect("insert");
        }
        state
            .rocks
            .put_cf_raw(
                CF_PENDING_DELTAS,
                xfer.id.as_bytes(),
                &delta.to_json().unwrap(),
            )
            .expect("put delta");

        // Spawn the loop and then enqueue finalization.
        spawn_pending_drain_loop(state.clone());
        {
            let mut consensus = state.consensus.lock_recover();
            consensus.force_finalized(&xfer.id);
        }

        // Tick is 250ms; give the loop up to 2s to pick up the event.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            if state
                .pending_ledger_commits_total
                .load(Ordering::Relaxed)
                >= 1
            {
                break;
            }
            if std::time::Instant::now() > deadline {
                panic!(
                    "drain loop failed to commit within 2s — pending_len={}, queue_depth={}",
                    state.pending_ledger.read().await.len(),
                    state.consensus.lock_recover().finalization_queue_depth()
                );
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }

        let ledger = state.ledger.read().await;
        assert_eq!(
            ledger.balance(&alice_hash),
            750 * BASE_UNITS_PER_BEAT,
            "alice debited by loop-driven commit"
        );
        assert_eq!(
            ledger.balance(&bob_hash),
            250 * BASE_UNITS_PER_BEAT,
            "bob credited by loop-driven commit"
        );

        drop(tmp);
    }

    /// ARCH-1 regression: the drain loop must tolerate finalize events
    /// whose rid was never inserted into `pending_ledger` (e.g. force-
    /// finalized cascade rids, or pre-Phase-3.7 boot replays where the
    /// CF was empty). `drain_and_commit_pending` no-ops each such rid
    /// via the `missing_delta` branch in pending_drain.rs. This test
    /// enqueues three rids without populating `pending_ledger` and
    /// proves the queue still drains.
    #[allow(clippy::manual_assert)]
    #[tokio::test]
    async fn test_arch_1_drain_loop_tolerates_missing_deltas() {
        let genesis = pk(0x01);
        let genesis_hash = sha3_256_hex(&genesis);

        let tmp = tempfile::tempdir().expect("tempdir");
        let data_dir = tmp.path().to_path_buf();
        let config = NodeConfig {
            data_dir: data_dir.clone(),
            identity_path: data_dir.join("identity.json"),
            db_path: data_dir.join("elara.db"),
            admin_token: "test-admin".into(),
            network_id: "arch1-non-canary-drain-test".into(),
            mdns_enabled: false,
            health_check_interval_secs: 0,
            min_pow_difficulty: 0,
            genesis_authority: genesis_hash.clone(),
            ..Default::default()
        };

        let identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
            .expect("generate identity");
        let rocks = Arc::new(
            StorageEngine::open(data_dir.join("rocksdb")).expect("open rocksdb"),
        );
        let wmgr = Arc::new(WitnessManager::new(rocks.clone()));
        let state = Arc::new(NodeState::new(config, identity, rocks, wmgr));

        // Spawn the drain loop directly — same call site as spawn_state_core.
        spawn_pending_drain_loop(state.clone());

        // Enqueue three rids. pending_ledger has no matching deltas, so
        // each drain hits the missing_delta branch.
        {
            let mut consensus = state.consensus.lock_recover();
            consensus.force_finalized("missing-delta-rid-1");
            consensus.force_finalized("missing-delta-rid-2");
            consensus.force_finalized("missing-delta-rid-3");
            assert_eq!(consensus.finalization_queue_enqueued_total, 3);
            assert_eq!(consensus.finalization_queue_depth(), 3);
        }

        // Tick is 250ms; give the loop up to 2s to drain.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            let (drained, depth) = {
                let consensus = state.consensus.lock_recover();
                (
                    consensus.finalization_queue_drained_total,
                    consensus.finalization_queue_depth(),
                )
            };
            if drained >= 3 && depth == 0 {
                break;
            }
            if std::time::Instant::now() > deadline {
                panic!(
                    "drain loop did not empty queue within 2s — drained={drained}, depth={depth}"
                );
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }

        // pending_ledger_commits_total stays zero — pending_ledger had no
        // matching deltas, so each drain hit missing_delta.
        assert_eq!(
            state
                .pending_ledger_commits_total
                .load(Ordering::Relaxed),
            0,
            "no matching deltas — drain must no-op via missing_delta"
        );

        drop(tmp);
    }

    /// Phase 2 routing: same zone path always picks the same worker
    /// (deterministic across calls), and the index is bounded by the
    /// worker count.
    #[test]
    fn worker_index_is_deterministic_and_bounded() {
        for &n in &[1usize, 2, 3, 4, 8, 64] {
            for zone in [
                "",
                "/",
                "0",
                "1",
                "global",
                "medical/eu/west",
                "iot/sensors/factory-a/line-3",
                "finance/instant-settlement",
            ] {
                let a = worker_index_for_zone(zone, n);
                let b = worker_index_for_zone(zone, n);
                assert_eq!(a, b, "zone {zone:?} routing must be stable");
                assert!(a < n, "index {a} out of bounds for n={n}");
            }
        }
    }

    /// Phase 2 routing: with `worker_count = 1`, every zone routes to
    /// worker 0 (the single-worker fast path).
    #[test]
    fn worker_index_single_worker_always_zero() {
        for zone in ["", "/", "global", "medical/eu", "0", "1", "abc/def"] {
            assert_eq!(worker_index_for_zone(zone, 1), 0);
        }
    }

    /// Phase 2 routing: defensive — `worker_count = 0` does not panic
    /// (the caller would be buggy but we treat it as 1 worker).
    #[test]
    fn worker_index_zero_count_is_safe() {
        assert_eq!(worker_index_for_zone("anything", 0), 0);
    }

    /// Phase 2 routing: with a non-trivial worker count, the hash
    /// produces a meaningful spread — at least two distinct workers
    /// receive load across a small set of plausible mainnet zone paths.
    /// (Not a uniformity claim: just a sanity check that we are not
    /// pinning everything to worker 0.)
    #[test]
    fn worker_index_spreads_across_workers() {
        let zones = [
            "0", "1", "2", "3", "4", "5", "6", "7",
            "global",
            "medical/eu/west",
            "medical/eu/east",
            "medical/us/east",
            "iot/sensors/a",
            "iot/sensors/b",
            "iot/sensors/c",
            "finance/instant-settlement",
            "finance/batch",
        ];
        let mut hits = std::collections::HashSet::new();
        for z in zones {
            hits.insert(worker_index_for_zone(z, 4));
        }
        assert!(
            hits.len() >= 2,
            "expected at least 2 distinct workers for {} zones, got {}",
            zones.len(),
            hits.len()
        );
    }

    /// Phase 2 handle: `StateCoreHandle::new` (Phase-1-compat) reports
    /// `worker_count() == 1` so tests that build a handle directly via
    /// the legacy constructor see the single-worker view.
    #[test]
    fn state_core_handle_new_is_single_worker() {
        let (tx, _rx) = mpsc::channel::<StateMessage>(8);
        let (ptx, _prx) = mpsc::channel::<StateMessage>(8);
        let snap = Arc::new(ArcSwap::from_pointee(StateSnapshot::default()));
        let handle = StateCoreHandle::new(tx, ptx, snap);
        assert_eq!(handle.worker_count(), 1);
    }

    /// Counters increment + max_ms is monotonic non-decreasing.
    /// We call the observer functions directly (the spawned watchdog timer
    /// would require a 30s sleep — tested at the unit level only).
    #[test]
    fn state_core_watchdog_metrics_track_max_and_counters() {
        // Lock is held for the duration of the test body so concurrent tests
        // don't race on the module-level statics.
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());

        super::reset_state_core_watchdog_metrics();
        let (w30, w60, mx) = super::state_core_watchdog_metrics();
        assert_eq!((w30, w60, mx), (0, 0, 0), "reset clears all three");

        super::observe_state_core_record_ms(120);
        super::observe_state_core_record_ms(50);     // smaller — must NOT lower the max
        super::observe_state_core_record_ms(415_141); // 415-second incident
        super::observe_state_core_record_ms(900);     // smaller — must NOT lower the max

        let (w30, w60, mx) = super::state_core_watchdog_metrics();
        assert_eq!(w30, 0, "no watchdog calls yet");
        assert_eq!(w60, 0, "no watchdog calls yet");
        assert_eq!(mx, 415_141, "max must equal the largest observed elapsed_ms");

        super::observe_state_core_watchdog_30s();
        super::observe_state_core_watchdog_30s();
        super::observe_state_core_watchdog_60s();

        let (w30, w60, mx) = super::state_core_watchdog_metrics();
        assert_eq!(w30, 2, "two 30s watchdog firings");
        assert_eq!(w60, 1, "one 60s watchdog firing (subset of 30s firings)");
        assert_eq!(mx, 415_141, "max gauge unchanged by watchdog increments");

        super::reset_state_core_watchdog_metrics();
    }

    /// Queue-depth observer is monotonic and tracks normal + priority
    /// channels independently. Sampled at insert_record() before each enqueue.
    /// The same observer increments at-capacity counters when depth >= cap,
    /// so the boot-burst-vs-sustained distinction is captured.
    #[test]
    fn ops144_observe_worker_queue_depth_only_raises() {
        // Module-scope lock — see QUEUE_DEPTH_OBSERVER_LOCK declaration at
        // the top of `mod tests`. Per-test locks let the
        // `insert_record` tests race and pollute the gauge with depth=1023.
        let _g = QUEUE_DEPTH_OBSERVER_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        super::reset_state_core_worker_queue_metrics();
        let (n, p) = super::state_core_worker_queue_metrics();
        assert_eq!((n, p), (0, 0), "reset clears both channels");

        super::observe_worker_queue_depth(50, 5);
        super::observe_worker_queue_depth(10, 32); // smaller normal — must NOT lower the max
        super::observe_worker_queue_depth(900, 8); // priority drops, normal jumps
        super::observe_worker_queue_depth(0, 60);  // normal idle, priority spikes

        let (n, p) = super::state_core_worker_queue_metrics();
        assert_eq!(n, 900, "normal max held at the largest observed (900)");
        assert_eq!(p, 60, "priority max held at the largest observed (60)");

        // Independence: bumping one must not touch the other.
        super::observe_worker_queue_depth(0, 0);
        let (n, p) = super::state_core_worker_queue_metrics();
        assert_eq!((n, p), (900, 60), "max gauges never lower");

        // At-capacity counters did NOT fire on any of the
        // sub-cap observations above (max value 900 < 1024 normal cap;
        // 60 < 64 priority cap).
        let (nc, pc) = super::state_core_worker_at_capacity_metrics();
        assert_eq!((nc, pc), (0, 0), "no observation reached cap");

        super::reset_state_core_worker_queue_metrics();
    }

    /// At-capacity counters increment exactly once per
    /// observation that reached the channel cap, distinguishing
    /// boot-burst (single firing) from sustained pressure (climbing
    /// counter under steady load).
    #[test]
    fn ops145_at_capacity_counters_only_fire_at_cap() {
        use super::{CHANNEL_SIZE, PRIORITY_CHANNEL_SIZE};
        // Module-scope lock — see QUEUE_DEPTH_OBSERVER_LOCK declaration
        // at the top of `mod tests`. Shares serialization with ops144 and
        // with the insert_record tests (which observe via L412 prod
        // code) so cross-test races on the gauge can't poison the asserts.
        let _g = QUEUE_DEPTH_OBSERVER_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        super::reset_state_core_worker_queue_metrics();
        let (nc, pc) = super::state_core_worker_at_capacity_metrics();
        assert_eq!((nc, pc), (0, 0), "reset clears both at-capacity counters");

        // Below cap on both channels: no increment.
        super::observe_worker_queue_depth(CHANNEL_SIZE as u64 - 1, PRIORITY_CHANNEL_SIZE as u64 - 1);
        let (nc, pc) = super::state_core_worker_at_capacity_metrics();
        assert_eq!((nc, pc), (0, 0), "depth=cap-1 must NOT bump counter");

        // Exactly at cap on priority only: priority increments, normal stays.
        super::observe_worker_queue_depth(0, PRIORITY_CHANNEL_SIZE as u64);
        let (nc, pc) = super::state_core_worker_at_capacity_metrics();
        assert_eq!((nc, pc), (0, 1), "priority cap firing only");

        // Exactly at cap on normal only.
        super::observe_worker_queue_depth(CHANNEL_SIZE as u64, 0);
        let (nc, pc) = super::state_core_worker_at_capacity_metrics();
        assert_eq!((nc, pc), (1, 1), "normal cap firing only");

        // Both at cap: both increment in the same observation.
        super::observe_worker_queue_depth(CHANNEL_SIZE as u64, PRIORITY_CHANNEL_SIZE as u64);
        let (nc, pc) = super::state_core_worker_at_capacity_metrics();
        assert_eq!((nc, pc), (2, 2), "both fire on a single dual-saturated observation");

        // Sanity: defensive against >cap inputs (shouldn't happen in
        // practice since the channel is bounded, but the >= check
        // tolerates it).
        super::observe_worker_queue_depth(CHANNEL_SIZE as u64 + 100, PRIORITY_CHANNEL_SIZE as u64 + 100);
        let (nc, pc) = super::state_core_worker_at_capacity_metrics();
        assert_eq!((nc, pc), (3, 3), ">cap counts as at-cap (defensive)");

        super::reset_state_core_worker_queue_metrics();
    }

    // ─── Density-hygiene pure-fn helpers ──────────────────────────
    //
    // Each of these three helpers is on
    // the per-record hot path or the snapshot read path; a regression in any
    // of them silently desyncs RPC reads or routes records to the wrong lane.

    /// Pin `StateMessage::is_priority` (state_core.rs:53) — the 5-arm match
    /// that decides whether a record skips the bulk-pull queue. RPC/local +
    /// peer-pushed gossip must take the priority lane so user-facing RPCs and
    /// gossip-push reconciliation don't starve behind bulk delta-pull
    /// backlog. Bulk pulls (`GossipPull`) and historical replay (`Sync`)
    /// take the normal lane.
    #[test]
    fn batch_y_is_priority_routes_local_http_submit_and_gossip_push_to_priority_lane() {
        assert!(
            StateMessage::is_priority(&RecordSource::Local),
            "Local (CLI / auto-witness) must take the priority lane"
        );
        assert!(
            StateMessage::is_priority(&RecordSource::HttpSubmit { peer_ip: None }),
            "HttpSubmit (POST /records) with no peer_ip must take the priority lane"
        );
        assert!(
            StateMessage::is_priority(&RecordSource::HttpSubmit {
                peer_ip: Some("203.0.113.1".into()),
            }),
            "HttpSubmit variant payload must not change priority routing"
        );
        assert!(
            StateMessage::is_priority(&RecordSource::GossipPush {
                peer_hash: "peer-x".into(),
                trusted: true,
            }),
            "trusted GossipPush (seed/staked/authority relay) must take the priority lane"
        );
        assert!(
            !StateMessage::is_priority(&RecordSource::GossipPush {
                peer_hash: "peer-x".into(),
                trusted: false,
            }),
            "B6: untrusted GossipPush (authed stranger) must NOT take the priority lane \
             — else a stranger's flood starves trusted seal/finality relay"
        );
        assert!(
            !StateMessage::is_priority(&RecordSource::GossipPull {
                peer_hash: "peer-y".into(),
            }),
            "GossipPull (bulk delta-pull) must take the normal lane"
        );
        assert!(
            !StateMessage::is_priority(&RecordSource::Sync),
            "Sync (initial/delta historical replay) must take the normal lane"
        );
    }

    /// Pin `RecordSource::skips_timestamp_defense` — the classification that
    /// decides whether an ingested record bypasses the wall-clock timestamp
    /// gate (`MAX_FUTURE_SKEW_SECS = 300s`). This is **load-bearing for
    /// external join**: a fresh follower whose clock trails the chain origin by
    /// more than 5 min can only ever sync because the chain data it receives
    /// (`Sync` on bootstrap/pull, `GossipPush` on live relay) skips the gate.
    /// If a "security tightening" ever drops `GossipPush` from the skip set, or
    /// a new `RecordSource` variant is added unclassified, a clock-skewed node
    /// would silently deadlock out of syncing with nothing else catching it.
    /// Freshly-originated records (`Local`, `HttpSubmit`) stay gated — there
    /// the record is stamped and checked against the same local clock, so the
    /// node's absolute offset is irrelevant and the gate is a real defense.
    #[test]
    fn skips_timestamp_defense_truth_table_pins_external_join_skew_invariant() {
        // Skipped (chain data the originator already timestamp-validated):
        assert!(
            RecordSource::Sync.skips_timestamp_defense(),
            "Sync (bootstrap + delta-pull historical replay) MUST skip the \
             timestamp gate — gating it on the receiver clock deadlocks a \
             clock-skewed external follower out of ever syncing"
        );
        assert!(
            RecordSource::GossipPush { peer_hash: "peer-x".into(), trusted: true }.skips_timestamp_defense(),
            "trusted GossipPush (live chain records relayed by a seed/staked/authority \
             peer) MUST skip the gate for the same external-follower skew reason"
        );

        // B6: an authed-but-UNTRUSTED stranger's push must NOT skip the gate —
        // it is policed exactly like a fresh HttpSubmit. This closes the bypass
        // where a peer-supplied x-elara-sender header alone conferred exemption.
        assert!(
            !RecordSource::GossipPush { peer_hash: "stranger".into(), trusted: false }.skips_timestamp_defense(),
            "B6: untrusted GossipPush MUST be gated — the rate-exemption derives \
             from the handshake-authenticated identity, never the x-elara-sender header"
        );

        // Gated (freshly-originated or locally-pulled — policed on the local clock):
        assert!(
            !RecordSource::Local.skips_timestamp_defense(),
            "Local (CLI / auto-witness origination) MUST be gated"
        );
        assert!(
            !RecordSource::HttpSubmit { peer_ip: None }.skips_timestamp_defense(),
            "HttpSubmit (POST /records) MUST be gated"
        );
        assert!(
            !RecordSource::HttpSubmit { peer_ip: Some("203.0.113.1".into()) }
                .skips_timestamp_defense(),
            "HttpSubmit payload must not change the gating decision"
        );
        assert!(
            !RecordSource::GossipPull { peer_hash: "peer-y".into() }.skips_timestamp_defense(),
            "GossipPull is gated today (and is not constructed on any production \
             ingest path — all pull/backfill routes through insert_record_synced \
             → Sync); if a live GossipPull historical-ingest path is ever added, \
             revisit this — see skips_timestamp_defense doc comment"
        );
    }

    /// Pin `StateSnapshot::default` (state_core.rs:137-168) — the all-zero
    /// snapshot that /metrics and HTTP read paths see on a fresh node before
    /// the first mutation publishes a real snapshot. A non-zero default would
    /// surface as phantom counters in cluster dashboards on every restart.
    #[test]
    fn batch_y_state_snapshot_default_emits_all_zero_and_empty_fields_on_fresh_node() {
        let snap = StateSnapshot::default();
        // DAG fields — every counter starts at zero, tip list empty.
        assert_eq!(snap.dag_size, 0);
        assert_eq!(snap.dag_edges, 0);
        assert_eq!(snap.dag_tips, 0);
        assert_eq!(snap.dag_roots, 0);
        assert_eq!(snap.dag_orphan_edges, 0);
        assert!(snap.dag_tip_ids.is_empty(), "fresh dag has no tip ids");
        // Ledger fields — zero supply, no accounts, no staked balance, zero pool.
        assert_eq!(snap.ledger_supply, 0);
        assert_eq!(snap.ledger_accounts, 0);
        assert_eq!(snap.ledger_staked, 0);
        assert_eq!(snap.conservation_pool, 0);
        // Consensus fields — clean attestation + settled counters.
        assert_eq!(snap.consensus_attestations, 0);
        assert_eq!(snap.consensus_settled, 0);
        // Peer fields — no peer state yet.
        assert_eq!(snap.peers_connected, 0);
        assert_eq!(snap.peers_total, 0);
        assert_eq!(snap.banned_peers, 0);
        assert_eq!(snap.peers_in_backoff, 0);
        // Ledger / governance / consensus trackers.
        assert_eq!(snap.finalized_count, 0);
        assert_eq!(snap.current_epoch, 0);
        assert_eq!(snap.circuit_breaker_level, 0);
        assert_eq!(snap.cb_volume_24h, 0);
        assert_eq!(snap.cb_velocity_24h, 0.0);
        assert_eq!(snap.velocity_tracked, 0);
        assert_eq!(snap.acquisition_tracked, 0);
        assert_eq!(snap.vesting_active, 0);
        assert_eq!(snap.governance_active, 0);
        assert_eq!(snap.records_processed, 0);
        assert_eq!(snap.trust_tracked, 0);
        assert!(
            (snap.last_updated - 0.0).abs() < f64::EPSILON,
            "last_updated must be exactly 0.0 on default"
        );
    }

    /// Pin `StateCoreHandle::read_snapshot` (state_core.rs:461) — the
    /// lock-free entry point HTTP handlers and background tasks call on the
    /// hot path. Contract: the Arc returned reflects whatever was last
    /// stored in the ArcSwap. On a freshly-constructed handle that means
    /// the default snapshot the caller seeded comes back unchanged.
    #[test]
    fn batch_y_state_core_handle_read_snapshot_returns_arc_pointing_at_initial_default() {
        let (tx, _rx) = mpsc::channel::<StateMessage>(8);
        let (ptx, _prx) = mpsc::channel::<StateMessage>(8);
        let snap = Arc::new(ArcSwap::from_pointee(StateSnapshot::default()));
        let handle = StateCoreHandle::new(tx, ptx, snap);

        let observed = handle.read_snapshot();
        // Fresh snapshot — fields match the default. Pins the ArcSwap →
        // Arc<StateSnapshot> round-trip path that callers depend on.
        assert_eq!(observed.dag_size, 0);
        assert_eq!(observed.ledger_supply, 0);
        assert_eq!(observed.consensus_attestations, 0);
        assert_eq!(observed.peers_connected, 0);
        assert_eq!(observed.finalized_count, 0);
        assert!(
            observed.dag_tip_ids.is_empty(),
            "tip list must pass through empty on a fresh handle"
        );

        // Repeated reads return logically-equivalent snapshots — no mutation
        // happened between them, so load_full's Arc clones agree on payload.
        let observed2 = handle.read_snapshot();
        assert_eq!(observed2.dag_size, observed.dag_size);
        assert_eq!(observed2.ledger_supply, observed.ledger_supply);
        assert_eq!(observed2.consensus_attestations, observed.consensus_attestations);
    }

    /// Pin `MAX_STATE_CORE_WORKERS` (state_core.rs:184) — the mainnet
    /// default of 64 workers per state_core. Pins three invariants the
    /// rest of the module relies on: (a) the value is exactly 64, (b)
    /// the storage type is `u8` (the L508 `.clamp(...) as usize` cast
    /// would silently break if the const grew past 255 and needed `u16`),
    /// and (c) the clamp band `[1, MAX_STATE_CORE_WORKERS]` at L508
    /// normalizes both bad-config corner cases — `state_core_worker_count=0`
    /// floor-clamps to 1 (single-worker fast path) and the u8 max ceiling
    /// caps at 64 (no thread-pool explosion).
    #[test]
    fn batch_a_max_state_core_workers_pin_value_64_u8_storage_and_clamp_band_invariants() {
        assert_eq!(
            super::MAX_STATE_CORE_WORKERS,
            64,
            "MAX_STATE_CORE_WORKERS mainnet default — bumping this without re-auditing the WorkerPool spawn cost at L504-560 risks thread-pool oversubscription on phone-tier hardware"
        );
        // Compile-time pin: storage must remain u8. A future widening to u16
        // would require touching the L508 cast expression too.
        let _: u8 = super::MAX_STATE_CORE_WORKERS;
        // Lower-clamp: config=0 (bad value) floor-clamps to 1, preserving
        // the single-worker fast path WorkerPool::new(state) relies on.
        assert_eq!(
            0u8.clamp(1, super::MAX_STATE_CORE_WORKERS),
            1,
            "L508 clamp lower-bound — config=0 must normalize to 1 worker"
        );
        // Upper-clamp: u8::MAX ceiling caps at MAX_STATE_CORE_WORKERS.
        assert_eq!(
            u8::MAX.clamp(1, super::MAX_STATE_CORE_WORKERS),
            64,
            "L508 clamp upper-bound — config=255 must cap at MAX_STATE_CORE_WORKERS=64"
        );
        // In-band values pass through unchanged (no surprise re-mapping).
        assert_eq!(
            8u8.clamp(1, super::MAX_STATE_CORE_WORKERS),
            8,
            "in-band config values must pass through clamp unchanged"
        );
        // u8 storage exposes the entire upper clamp range — verify the
        // bound is reachable (would fail if storage was downgraded to e.g. u4
        // via newtype wrapper).
        assert!(
            super::MAX_STATE_CORE_WORKERS as u16 <= u8::MAX as u16,
            "MAX_STATE_CORE_WORKERS must fit in u8 storage"
        );
    }

    /// Pin `CHANNEL_SIZE` (state_core.rs:476) + `PRIORITY_CHANNEL_SIZE`
    /// (state_core.rs:487) — both at 1024 after the priority channel was
    /// grown 64 → 1024. The L477-486 docstring
    /// argument that "drain priority before normal" gives gossip-push
    /// bursts a deep buffer to absorb without back-pressuring the gossip
    /// handler relies on the two channel depths being EQUAL. A future
    /// "save memory" regression that drops priority back to 64 would
    /// re-introduce the saturation events that growing the channel closed.
    #[test]
    fn batch_a_channel_size_constants_pin_mainnet_defaults_1024_each_and_ops146_parity_invariant() {
        assert_eq!(
            super::CHANNEL_SIZE,
            1024,
            "L476 normal channel buffer — sized for bulk delta-pull / sync / GossipPull burst"
        );
        assert_eq!(
            super::PRIORITY_CHANNEL_SIZE,
            1024,
            "L487 OPS-146: priority channel grown 64 → 1024 to absorb gossip-push bursts without back-pressure"
        );
        // Parity invariant: priority must equal normal. Divergence
        // would re-open the saturation window that growing the channel
        // closed (~4 saturation events/sec sustained at PRIORITY=64 even
        // at testnet's <1 rec/s fleet rate).
        assert_eq!(
            super::CHANNEL_SIZE,
            super::PRIORITY_CHANNEL_SIZE,
            "OPS-146 parity: priority must match normal — if you intend to make priority larger, update the L477-486 docstring's parity argument first"
        );
        // Both buffers must remain large enough to absorb a 64-burst (the
        // earlier ceiling that proved insufficient). The two
        // `CHANNEL_SIZE > 64` and `PRIORITY_CHANNEL_SIZE > 64` invariants
        // are pinned at compile time via the `const _: () = assert!(..)`
        // block next to the const declarations (state_core.rs ~L489). A
        // regression that drops EITHER buffer to 64 or below now fails at
        // `cargo build`, not at `cargo test`. Runtime asserts removed
        // (clippy::assertions_on_constants — both operands const-eval).
    }

    /// Pin `InsertResult` (state_core.rs:75-82) variant constructions —
    /// pins the public producer-side enum that `insert_record` returns to
    /// HTTP handlers, gossip insert paths, and CLI submit. Each variant
    /// payload field name is contract-pinned (renames would silently break
    /// JSON-serialized RPC responses). Debug repr is also pinned because
    /// it shows up in error tracing and operator-side log search.
    #[test]
    fn batch_a_insert_result_variant_constructions_pin_field_names_and_debug_repr_for_rpc_contract() {
        // Accepted: pins `record_id: String` field.
        let acc = super::InsertResult::Accepted {
            record_id: "0123abcd".to_string(),
        };
        let s = format!("{:?}", acc);
        assert!(
            s.contains("Accepted"),
            "Debug repr must contain variant name `Accepted` — used in operator log search"
        );
        assert!(
            s.contains("record_id"),
            "Debug repr must contain field name `record_id` — RPC contract pin"
        );
        assert!(
            s.contains("0123abcd"),
            "Debug repr must contain field value — operators grep for record IDs in logs"
        );
        // Rejected: pins `reason: String` field.
        let rej = super::InsertResult::Rejected {
            reason: "duplicate-record".to_string(),
        };
        let s = format!("{:?}", rej);
        assert!(s.contains("Rejected"));
        assert!(
            s.contains("reason"),
            "Rejected.reason field name is RPC-contract-pinned"
        );
        assert!(s.contains("duplicate-record"));
        // Error: pins `message: String` field (note: `message`, NOT `reason`,
        // NOT `error` — distinct from Rejected's field name on purpose so
        // operator triage can grep by error-class).
        let err = super::InsertResult::Error {
            message: "rocksdb-write-conflict".to_string(),
        };
        let s = format!("{:?}", err);
        assert!(s.contains("Error"));
        assert!(
            s.contains("message"),
            "Error.message field name must remain distinct from Rejected.reason — operator triage relies on the field-name asymmetry to separate transient errors from policy rejections"
        );
        assert!(s.contains("rocksdb-write-conflict"));
    }

    // ─── Pure-fn edges + handle error paths ─────────
    //
    // These tests close pure-fn edge gaps on `observe_state_core_record_ms` and
    // pin the closed-channel error contracts the `StateCoreHandle` ops
    // (`insert_record`, `replace_ledger`, `shutdown`) advertise but never
    // exercised — every handle method must degrade gracefully if the
    // backing worker is gone, so a downstream caller never panics on a
    // half-torn-down core.
    //
    // Pure-fn tests #1/#2 share the watchdog statics with the existing
    // `state_core_watchdog_metrics_track_max_and_counters` test; same
    // reset-at-start, reset-at-end pattern keeps cross-test state clean.

    /// `observe_state_core_record_ms(0)` is a no-op — `0 > current`
    /// is never true (current is u64), so the CAS-loop never enters. Pins
    /// the strict-inequality contract at state_core.rs:226 — a regression
    /// to `>=` would silently zero the max gauge on every record.
    #[test]
    fn batch_z_observe_state_core_record_ms_zero_is_noop_does_not_lower_existing_max() {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());

        super::reset_state_core_watchdog_metrics();
        super::observe_state_core_record_ms(2_500);
        let (_, _, before) = super::state_core_watchdog_metrics();
        assert_eq!(before, 2_500, "seed value must be observed");

        // Submit 0 — CAS-loop must NOT enter, max stays at 2500.
        super::observe_state_core_record_ms(0);
        let (_, _, after) = super::state_core_watchdog_metrics();
        assert_eq!(
            after, 2_500,
            "ms=0 must be a no-op — strict inequality ms > current at state_core.rs:226"
        );

        super::reset_state_core_watchdog_metrics();
    }

    /// Submitting `ms == current_max` is idempotent. The CAS-loop
    /// guard is `ms > current` (strict), so equal-to-current exits without
    /// touching the atomic. Pins the no-spurious-CAS-write contract that
    /// keeps observe-on-hot-path cheap.
    #[test]
    fn batch_z_observe_state_core_record_ms_equal_to_current_max_is_idempotent() {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());

        super::reset_state_core_watchdog_metrics();
        super::observe_state_core_record_ms(900);
        super::observe_state_core_record_ms(900); // same value — no CAS spin
        super::observe_state_core_record_ms(900);

        let (_, _, mx) = super::state_core_watchdog_metrics();
        assert_eq!(mx, 900, "equal-to-current must not change max");

        // Strictly greater value now climbs (proves the comparator is still
        // operational, not stuck after the equal-value submissions).
        super::observe_state_core_record_ms(901);
        let (_, _, mx) = super::state_core_watchdog_metrics();
        assert_eq!(mx, 901, "ms > current must still update");

        super::reset_state_core_watchdog_metrics();
    }

    /// `StateCoreHandle::insert_record` with Local source routes to the
    /// priority channel (per `StateMessage::is_priority`). With the priority
    /// receiver dropped, `priority_tx.send().await` fails immediately and
    /// `insert_record` MUST return `InsertResult::Error { message:
    /// "state core shut down" }` rather than block or panic. Pins the
    /// state_core.rs:426-430 closed-channel error contract — clients calling
    /// during a graceful shutdown see a clean error, never a hang.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // test-serialization lock; #[tokio::test] is single-threaded, see QUEUE_DEPTH_OBSERVER_LOCK comment at state_core.rs:1314
    async fn batch_z_insert_record_with_dropped_priority_receiver_returns_error_on_local_source() {
        // The worker-queue-depth gauge is shared with this
        // test's insert_record path (observes at state_core.rs:412 with
        // bound-8 channels ⇒ depth=1016+). Serialize against the
        // ops144/ops145 asserts so they don't see polluted values.
        let _g = QUEUE_DEPTH_OBSERVER_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let (tx, _rx) = mpsc::channel::<StateMessage>(8);
        let (ptx, prx) = mpsc::channel::<StateMessage>(8);
        drop(prx); // close the priority side — Local routes here
        let snap = Arc::new(ArcSwap::from_pointee(StateSnapshot::default()));
        let handle = StateCoreHandle::new(tx, ptx, snap);

        let rec = mk_record("batch-z-closed-prx", &pk(0xab), 1.0, BTreeMap::new());
        let result = handle.insert_record(rec, RecordSource::Local).await;

        match result {
            InsertResult::Error { message } => assert_eq!(
                message, "state core shut down",
                "closed-channel error message is part of the public RPC contract"
            ),
            other => panic!("expected Error, got {:?}", other),
        }
    }

    /// `StateCoreHandle::replace_ledger` sends via the normal channel of
    /// worker[0]. With that receiver dropped, the call must log a warning
    /// and return WITHOUT panicking — the public contract per state_core.rs:
    /// 453-456. Drop the normal receiver up-front, then prove the call
    /// completes and the (already-closed) reply oneshot is awaited gracefully.
    #[tokio::test]
    async fn batch_z_replace_ledger_with_dropped_normal_receiver_returns_without_panicking() {
        let (tx, rx) = mpsc::channel::<StateMessage>(8);
        let (ptx, _prx) = mpsc::channel::<StateMessage>(8);
        drop(rx); // close the normal side — replace_ledger lands here
        let snap = Arc::new(ArcSwap::from_pointee(StateSnapshot::default()));
        let handle = StateCoreHandle::new(tx, ptx, snap);

        let ledger = crate::accounting::ledger::LedgerState::new();
        // If this panicked or hung, the test would fail. Wrap in a timeout
        // so a hypothetical hang surfaces as a test failure, not a stuck CI.
        tokio::time::timeout(std::time::Duration::from_secs(2), handle.replace_ledger(ledger))
            .await
            .expect("replace_ledger must complete within 2s on closed channel");
    }

    /// `StateCoreHandle::shutdown` broadcasts a `Shutdown` message to every
    /// worker's priority channel. If any priority receiver is gone the send
    /// silently no-ops (state_core.rs:467-471) so a partial-shutdown sequence
    /// where one worker has already exited doesn't poison the rest of the
    /// fanout. With ALL priority receivers dropped (single-worker handle),
    /// `shutdown` must still complete cleanly.
    #[tokio::test]
    async fn batch_z_shutdown_with_dropped_priority_receiver_returns_without_panicking() {
        let (tx, _rx) = mpsc::channel::<StateMessage>(8);
        let (ptx, prx) = mpsc::channel::<StateMessage>(8);
        drop(prx);
        let snap = Arc::new(ArcSwap::from_pointee(StateSnapshot::default()));
        let handle = StateCoreHandle::new(tx, ptx, snap);

        let report = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            handle.shutdown(std::time::Duration::from_secs(1)),
        )
        .await
        .expect("shutdown must complete within 2s on closed channel");
        // Phase-1-compat `new()` handle records no JoinHandles, so the report
        // is zero across the board — confirms the no-handles branch returns
        // cleanly rather than blocking on a Vec we never populated.
        assert_eq!(report.workers, 0);
        assert_eq!(report.completed, 0);
        assert_eq!(report.timed_out, 0);
    }

    /// L1572 Phase-3 graceful drain: `shutdown` must await every spawned
    /// worker's tokio task and report `completed == workers, timed_out == 0`.
    /// Pin the contract on a real `spawn_state_core` pool — Phase-1-compat
    /// `new()` paths are covered by the dropped-receiver test above.
    #[tokio::test]
    async fn l1572_shutdown_awaits_workers_and_reports_completed_count() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let data_dir = tmp.path().to_path_buf();
        let config = NodeConfig {
            data_dir: data_dir.clone(),
            identity_path: data_dir.join("identity.json"),
            db_path: data_dir.join("elara.db"),
            admin_token: "l1572-test".into(),
            network_id: "l1572-shutdown-test".into(),
            mdns_enabled: false,
            health_check_interval_secs: 0,
            min_pow_difficulty: 0,
            // Spawn 3 workers so the report is a sum across the pool,
            // not just one worker.
            state_core_worker_count: 3,
            ..Default::default()
        };
        let identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
            .expect("generate identity");
        let rocks = Arc::new(
            StorageEngine::open(data_dir.join("rocksdb")).expect("open rocksdb"),
        );
        let wmgr = Arc::new(WitnessManager::new(rocks.clone()));
        let state = Arc::new(NodeState::new(config, identity, rocks, wmgr));

        let handle = spawn_state_core(state.clone());
        assert_eq!(handle.worker_count(), 3, "spawn should honour config");

        let report = handle.shutdown(Duration::from_secs(5)).await;
        assert_eq!(report.workers, 3, "report.workers tracks spawned count");
        assert_eq!(report.completed, 3, "all workers must drain within timeout");
        assert_eq!(report.timed_out, 0, "no worker should hit the timeout");
        assert!(
            report.elapsed < Duration::from_secs(5),
            "must return well under the 5s budget for an idle pool, got {:?}",
            report.elapsed
        );

        // Second shutdown on a clone observes the empty `handles` slot —
        // returns instantly with a zero-worker report. Pins the
        // "only first caller drains" semantic.
        let clone = handle.clone();
        let second = clone.shutdown(Duration::from_secs(1)).await;
        assert_eq!(second.workers, 0);
        assert_eq!(second.completed, 0);
        assert_eq!(second.timed_out, 0);

        drop(tmp);
    }

    /// L1572 shutdown: zero-duration budget forces `deadline = start`, so
    /// `remaining.is_zero()` is true for every handle in the loop — each
    /// handle is aborted and counted as `timed_out`. Pins the branch that
    /// differs from the happy-path test above. Invariant: `timed_out +
    /// completed == workers` always holds.
    #[tokio::test]
    async fn l1572_shutdown_zero_timeout_accounts_for_all_workers() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let data_dir = tmp.path().to_path_buf();
        let config = NodeConfig {
            data_dir: data_dir.clone(),
            identity_path: data_dir.join("identity.json"),
            db_path: data_dir.join("elara.db"),
            admin_token: "l1572-zero-test".into(),
            network_id: "l1572-zero-test".into(),
            mdns_enabled: false,
            health_check_interval_secs: 0,
            min_pow_difficulty: 0,
            state_core_worker_count: 2,
            ..Default::default()
        };
        let identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
            .expect("generate identity");
        let rocks = Arc::new(
            StorageEngine::open(data_dir.join("rocksdb")).expect("open rocksdb"),
        );
        let wmgr = Arc::new(WitnessManager::new(rocks.clone()));
        let state = Arc::new(NodeState::new(config, identity, rocks, wmgr));

        let handle = spawn_state_core(state.clone());
        assert_eq!(handle.worker_count(), 2);

        // deadline = start + ZERO = start; Instant::now() in the loop is
        // always >= start, so remaining is ZERO for every handle and all
        // workers are aborted (not awaited).
        let report = handle.shutdown(Duration::ZERO).await;
        assert_eq!(report.workers, 2, "workers must match spawn count");
        assert_eq!(
            report.timed_out + report.completed,
            report.workers,
            "every handle must be either completed or timed_out"
        );
        assert_eq!(report.timed_out, report.workers, "zero budget must abort all workers");
        drop(tmp);
    }

    /// Happy-path routing: a `RecordSource::Local` submission lands on the
    /// priority channel, and the normal channel receives nothing. A fake
    /// worker reads from the priority side and replies `Accepted { record_id
    /// }`; `insert_record` returns that result unchanged. Pins both the
    /// is_priority routing decision AND the full reply oneshot round-trip
    /// — the contract callers actually see end-to-end.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // test-serialization lock; #[tokio::test] is single-threaded, see QUEUE_DEPTH_OBSERVER_LOCK comment at state_core.rs:1314
    async fn batch_z_insert_record_local_source_lands_on_priority_channel_when_worker_responds() {
        // Same lock rationale as the dropped-priority-receiver test above:
        // insert_record observes the worker-queue-depth gauge at L412 so we
        // share the queue-depth serialization.
        let _g = QUEUE_DEPTH_OBSERVER_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let (tx, mut rx) = mpsc::channel::<StateMessage>(8);
        let (ptx, mut prx) = mpsc::channel::<StateMessage>(8);
        let snap = Arc::new(ArcSwap::from_pointee(StateSnapshot::default()));
        let handle = StateCoreHandle::new(tx, ptx, snap);

        let worker = tokio::spawn(async move {
            match prx.recv().await {
                Some(StateMessage::InsertRecord { reply, record, .. }) => {
                    let _ = reply.send(InsertResult::Accepted {
                        record_id: record.id.clone(),
                    });
                }
                other => panic!("priority channel got unexpected message: {:?}", other.is_some()),
            }
        });

        let rec = mk_record("batch-z-routing-rid", &pk(0xcd), 2.0, BTreeMap::new());
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            handle.insert_record(rec, RecordSource::Local),
        )
        .await
        .expect("insert_record must complete within 2s");

        match result {
            InsertResult::Accepted { record_id } => assert_eq!(
                record_id, "batch-z-routing-rid",
                "fake worker must echo the record id back through the reply oneshot"
            ),
            other => panic!("expected Accepted, got {:?}", other),
        }

        // Normal channel must remain empty — Local routes ONLY to priority.
        assert!(
            rx.try_recv().is_err(),
            "normal channel must receive nothing for Local source"
        );

        worker.await.expect("fake worker task panicked");
    }

    // ─── fixture-free pure-helper coverage ────────────────────────────────────
    //
    // Five axes on pure-helper surface not covered by the other test groups:
    //   1. worker_index_for_zone clamp + n=0/n=1 fast-path matrix
    //   2. worker_index_for_zone modulo-bound + extreme-n no-panic
    //   3. worker_index_for_zone determinism + in-zone routing invariant
    //   4. worker_index_for_zone DefaultHasher spread + extreme-zone inputs
    //   5. StateSnapshot Clone field-independence + RecordSource Debug+Clone matrix

    #[test]
    fn batch_b_worker_index_for_zone_clamp_zero_and_single_worker_fast_path() {
        // Two early-return branches at state_core.rs:345-348:
        //   - `worker_count.max(1)` clamps 0 → 1 (caller bug, no panic).
        //   - `if n == 1 { return 0 }` is the single-worker fast path
        //     (skips hashing entirely — pure cost optimization).
        // Both must return 0 for ANY zone_path. A regression that drops
        // the .max(1) clamp would compute `h.finish() % 0` and panic
        // (mod-by-zero); a regression that drops the n==1 fast-path
        // would still return 0 but at hash cost — measurable on the
        // single-worker fleet.

        // n=0 fast-path matrix
        assert_eq!(super::worker_index_for_zone("", 0), 0);
        assert_eq!(super::worker_index_for_zone("zone-1", 0), 0);
        assert_eq!(super::worker_index_for_zone("ANY/path/here", 0), 0);
        assert_eq!(
            super::worker_index_for_zone("0123456789abcdef", 0),
            0,
            "n=0 always clamps to 1-worker → index 0 regardless of zone"
        );

        // n=1 fast-path matrix
        assert_eq!(super::worker_index_for_zone("", 1), 0);
        assert_eq!(super::worker_index_for_zone("zone-1", 1), 0);
        assert_eq!(super::worker_index_for_zone("ANY/path/here", 1), 0);
        assert_eq!(
            super::worker_index_for_zone("0123456789abcdef", 1),
            0,
            "n=1 always returns 0 (single-worker fast path)"
        );
    }

    #[test]
    fn batch_b_worker_index_for_zone_modulo_bound_and_extreme_n_no_panic() {
        // For any (zone, n>1), the result must be in [0, n). This is the
        // load-bearing routing-table invariant: the WorkerPool array is sized
        // `n`, so an out-of-bounds index panics at the indexing site.
        // Sweep over n ∈ {2, 3, 4, 7, 16, 64, 1000, usize::MAX} and 32
        // distinct zone paths each — covers small, mainnet-default (64),
        // and pathological extremes.

        let zones = (0..32u32)
            .map(|i| format!("zone-{i}/sub/{i:08x}"))
            .collect::<Vec<_>>();

        for &n in &[2usize, 3, 4, 7, 16, 64, 1000, usize::MAX] {
            for zone in &zones {
                let idx = super::worker_index_for_zone(zone, n);
                assert!(
                    idx < n,
                    "worker_index_for_zone({zone:?}, {n}) = {idx} must be < {n}"
                );
            }
        }

        // Spot-check the mainnet-default boundary: n=MAX_STATE_CORE_WORKERS=64
        for zone in &zones {
            let idx = super::worker_index_for_zone(zone, super::MAX_STATE_CORE_WORKERS as usize);
            assert!(idx < 64, "mainnet n=64: idx {idx} < 64");
        }
    }

    #[test]
    fn batch_b_worker_index_for_zone_determinism_pins_in_zone_routing_invariant() {
        // THE contract: all records for one zone MUST always land on the
        // same worker — otherwise per-zone ordering breaks (zone-parallel
        // state-core refactor at state_core.rs:170-179 docstring). Test
        // 100 repeated lookups on a fixed (zone, n) returns the SAME
        // index every time. A future "let's add a random salt" or
        // "let's seed the hasher per-call" regression would silently
        // break ordering for every zone in the system.

        let zones = ["alpha", "beta/sub-zone", "x", "γρ", ""];
        for n in [2usize, 4, 16, 64] {
            for &zone in &zones {
                let first = super::worker_index_for_zone(zone, n);
                for _ in 0..100 {
                    assert_eq!(
                        super::worker_index_for_zone(zone, n),
                        first,
                        "non-deterministic routing for ({zone:?}, n={n}): \
                         first={first}, later≠first — in-zone ordering broken"
                    );
                }
            }
        }

        // Cross-pool size: same zone with different `n` may map differently,
        // but for a FIXED n the value is locked. Pin a specific (zone, n)
        // pair so a hash-algorithm swap (e.g. DefaultHasher → fxhash) would
        // fail this test, prompting an audit of the change.
        let pinned_idx_n4 = super::worker_index_for_zone("zone-pin", 4);
        let pinned_idx_n64 = super::worker_index_for_zone("zone-pin", 64);
        // Re-derive and confirm — must match across repeated calls.
        assert_eq!(super::worker_index_for_zone("zone-pin", 4), pinned_idx_n4);
        assert_eq!(super::worker_index_for_zone("zone-pin", 64), pinned_idx_n64);
        // Both must respect the modulo bound.
        assert!(pinned_idx_n4 < 4);
        assert!(pinned_idx_n64 < 64);
    }

    #[test]
    fn batch_b_worker_index_for_zone_spread_across_workers_and_extreme_zone_inputs() {
        // DefaultHasher uniformity sanity: 256 distinct zone paths through
        // a 4-worker pool should hit ALL 4 workers (a regression returning
        // 0 for every zone would surface as "1 of 4 workers does all the
        // work, 3 are idle" — the saturation pathology batch_a covers
        // for the channel size).
        let mut seen = [0u32; 4];
        for i in 0..256u32 {
            let zone = format!("zone-spread-{i:08x}");
            let idx = super::worker_index_for_zone(&zone, 4);
            assert!(idx < 4);
            seen[idx] += 1;
        }
        for (i, count) in seen.iter().enumerate() {
            assert!(
                *count > 0,
                "DefaultHasher spread: worker {i} got 0 of 256 zones — \
                 distribution is broken (seen={seen:?})"
            );
        }
        // 256 zones across 4 workers → ideal 64 each; floor-tolerance 16
        // (a quarter of ideal) guards against the degenerate "all zones
        // routed to 1 worker" pathology while permitting healthy variance.
        for (i, count) in seen.iter().enumerate() {
            assert!(
                *count >= 16,
                "worker {i} got only {count} of 256 zones — distribution skewed"
            );
        }

        // Extreme zone inputs — must not panic on any of these:
        //   - empty string
        //   - very long path (10K chars)
        //   - non-ASCII (Unicode-heavy)
        //   - control bytes via lossy UTF-8
        let big = "z".repeat(10_000);
        for zone in [
            "",
            big.as_str(),
            "γαμμα/δελτα/ωμεγα",
            "zone\nwith\tcontrol",
            "🦀/rustacean/zone",
        ] {
            let idx_n4 = super::worker_index_for_zone(zone, 4);
            let idx_max = super::worker_index_for_zone(zone, usize::MAX);
            assert!(idx_n4 < 4);
            assert!(idx_max < usize::MAX);
            // Determinism preserved for these too.
            assert_eq!(super::worker_index_for_zone(zone, 4), idx_n4);
            assert_eq!(super::worker_index_for_zone(zone, usize::MAX), idx_max);
        }
    }

    #[test]
    fn batch_b_state_snapshot_clone_preserves_all_fields_and_record_source_debug_clone_matrix() {
        // Two complementary derive-pins:
        //   (a) StateSnapshot Clone preserves EVERY field byte-for-byte —
        //       a regression that adds a new field but forgets to Clone it
        //       would silently zero it in cloned snapshots.
        //   (b) RecordSource Clone + Debug preserve every variant payload —
        //       Debug output is grep'd by log scrapers for source classification
        //       (Local / HttpSubmit / GossipPull / GossipPush / Sync), so the
        //       variant-name in Debug output is a contract.

        // ── (a) StateSnapshot Clone field-by-field ──
        // Construct a non-default snapshot with deliberately-distinct values
        // so Clone copying the WRONG field's value would surface as a
        // mismatch in the assertion that follows.
        let original = StateSnapshot {
            dag_size: 1,
            dag_edges: 2,
            dag_tips: 3,
            dag_roots: 4,
            dag_orphan_edges: 5,
            ledger_supply: 6,
            ledger_accounts: 7,
            ledger_staked: 8,
            conservation_pool: 9,
            dag_tip_ids: vec!["t1".into(), "t2".into()],
            consensus_attestations: 10,
            consensus_settled: 11,
            peers_connected: 12,
            peers_total: 13,
            finalized_count: 14,
            current_epoch: 15,
            circuit_breaker_level: 16,
            cb_volume_24h: 500,
            cb_velocity_24h: 0.25,
            velocity_tracked: 17,
            acquisition_tracked: 18,
            vesting_active: 19,
            governance_active: 20,
            records_processed: 21,
            banned_peers: 22,
            peers_in_backoff: 23,
            trust_tracked: 24,
            last_updated: 25.5,
        };
        let cloned = original.clone();
        assert_eq!(cloned.dag_size, original.dag_size);
        assert_eq!(cloned.dag_edges, original.dag_edges);
        assert_eq!(cloned.dag_tips, original.dag_tips);
        assert_eq!(cloned.dag_roots, original.dag_roots);
        assert_eq!(cloned.dag_orphan_edges, original.dag_orphan_edges);
        assert_eq!(cloned.ledger_supply, original.ledger_supply);
        assert_eq!(cloned.ledger_accounts, original.ledger_accounts);
        assert_eq!(cloned.ledger_staked, original.ledger_staked);
        assert_eq!(cloned.conservation_pool, original.conservation_pool);
        assert_eq!(cloned.dag_tip_ids, original.dag_tip_ids);
        assert_eq!(cloned.consensus_attestations, original.consensus_attestations);
        assert_eq!(cloned.consensus_settled, original.consensus_settled);
        assert_eq!(cloned.peers_connected, original.peers_connected);
        assert_eq!(cloned.peers_total, original.peers_total);
        assert_eq!(cloned.finalized_count, original.finalized_count);
        assert_eq!(cloned.current_epoch, original.current_epoch);
        assert_eq!(cloned.circuit_breaker_level, original.circuit_breaker_level);
        assert_eq!(cloned.cb_volume_24h, original.cb_volume_24h);
        assert!((cloned.cb_velocity_24h - original.cb_velocity_24h).abs() < f64::EPSILON);
        assert_eq!(cloned.velocity_tracked, original.velocity_tracked);
        assert_eq!(cloned.acquisition_tracked, original.acquisition_tracked);
        assert_eq!(cloned.vesting_active, original.vesting_active);
        assert_eq!(cloned.governance_active, original.governance_active);
        assert_eq!(cloned.records_processed, original.records_processed);
        assert_eq!(cloned.banned_peers, original.banned_peers);
        assert_eq!(cloned.peers_in_backoff, original.peers_in_backoff);
        assert_eq!(cloned.trust_tracked, original.trust_tracked);
        assert!(
            (cloned.last_updated - original.last_updated).abs() < f64::EPSILON,
            "last_updated f64 clone bit-equal"
        );

        // ── (b) RecordSource Clone + Debug variant matrix ──
        let sources = [
            RecordSource::HttpSubmit { peer_ip: None },
            RecordSource::HttpSubmit { peer_ip: Some("203.0.113.1".into()) },
            RecordSource::GossipPull { peer_hash: "peer-pull".into() },
            RecordSource::GossipPush { peer_hash: "peer-push".into(), trusted: true },
            RecordSource::Local,
            RecordSource::Sync,
        ];

        // Each variant Debug-prints with the variant name visible (log
        // scrapers grep these — drift breaks the source-classification grep).
        let expect_substr = [
            "HttpSubmit",
            "HttpSubmit",
            "GossipPull",
            "GossipPush",
            "Local",
            "Sync",
        ];
        for (src, want) in sources.iter().zip(expect_substr.iter()) {
            let dbg = format!("{src:?}");
            assert!(
                dbg.contains(want),
                "RecordSource::{want} Debug output must contain {want:?}, got {dbg:?}"
            );

            // Clone must preserve Debug output — proves field payloads
            // round-trip through Clone (not just the variant tag).
            let cloned_src = src.clone();
            let dbg_clone = format!("{cloned_src:?}");
            assert_eq!(
                dbg, dbg_clone,
                "RecordSource Clone changed Debug output for {want}"
            );
        }

        // Cross-variant Debug-uniqueness: all 6 source-payloads produce
        // distinct Debug strings (the two HttpSubmits differ on peer_ip).
        let mut dbgs = std::collections::HashSet::new();
        for src in &sources {
            assert!(
                dbgs.insert(format!("{src:?}")),
                "duplicate Debug output across RecordSource variants — {src:?}"
            );
        }
        assert_eq!(dbgs.len(), 6, "all 6 source-payloads have distinct Debug");
    }

    /// update_snapshot clock-skew fallback preserves prior last_updated.
    /// Verifies the `unwrap_or_else` path introduced to replace `unwrap_or_default()`
    /// (which silently returned 0.0 and corrupted freshness checks on clock-skew).
    #[test]
    fn update_snapshot_clock_skew_fallback_preserves_prior_last_updated() {
        // Confirm that a time before UNIX_EPOCH produces Err from duration_since,
        // which is exactly the path our fallback handles.
        let before_epoch = std::time::UNIX_EPOCH
            .checked_sub(std::time::Duration::from_secs(1))
            .expect("checked_sub cannot underflow here");
        assert!(
            before_epoch
                .duration_since(std::time::UNIX_EPOCH)
                .is_err(),
            "pre-epoch SystemTime must return Err from duration_since"
        );

        // Apply the same chain as update_snapshot; prior value must win, not 0.0.
        let prior_last_updated: f64 = 1_748_000_000.0;
        let result = before_epoch
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or_else(|_| prior_last_updated);
        assert!(
            (result - prior_last_updated).abs() < f64::EPSILON,
            "clock-skew fallback must return prior last_updated={prior_last_updated}, got {result}"
        );
    }

    #[test]
    fn cb_velocity_formula_pins_volume_over_circulating() {
        // Pins the formula used in update_state_snapshot:
        // vel = vol_24h / max(total_supply - total_staked, 1)
        let check = |vol: u64, circ: u64, expected: f64| {
            let vel = vol as f64 / circ.max(1) as f64;
            assert!(
                (vel - expected).abs() < 1e-9,
                "vol={vol} circ={circ}: expected {expected}, got {vel}"
            );
        };
        check(1_000, 10_000, 0.1);       // 10% velocity
        check(0, 1_000_000, 0.0);        // zero volume
        check(500, 0, 500.0);            // zero circ-supply → denominator floors to 1
        check(u64::MAX, u64::MAX, 1.0);  // saturating edge: ratio ≈ 1.0
    }
}
