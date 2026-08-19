//! Disk-backed finalized record index with bounded LRU cache.
//!
//! Replaces the unbounded `HashSet<String>` that previously held every
//! finalized record ID in RAM forever.
//!
//! Architecture:
//!   - Hot set: bounded `HashSet` (last N insertions) for O(1) lookups
//!   - Cold store: RocksDB `finalized:{record_id}` keys in CF_METADATA
//!     (Tier 4.5; previously CF_RECORDS, migrated by `migrate_4_to_5`).
//!   - `contains()` checks hot set first, falls back to RocksDB point lookup
//!   - `insert()` writes to both hot set and RocksDB, evicting oldest from RAM
//!   - `len()` tracked by atomic counter (avoids expensive prefix scans)
//!
//! Spec references:
//!   @spec Protocol §12.2

use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::storage::rocks::{StorageEngine, CF_METADATA};

/// Default capacity for the in-memory hot set (FullZone profile / legacy default).
const DEFAULT_CAPACITY: usize = 10_000;

/// Hot-tier capacity for `Light` profile nodes. Phone-tier hardware floor:
/// ~150 KB resident-set at 1k entries (HashSet<String> + VecDeque<String>),
/// fits comfortably below the Light profile's 72h record-retention budget.
/// Light nodes serve recent queries and verify proofs; they do not keep deep
/// finality history in RAM.
pub const LIGHT_PROFILE_CAPACITY: usize = 1_000;

/// Hot-tier capacity for `FullZone` profile nodes (operator default). 10k
/// entries ≈ 1.5 MB resident — matches the observed
/// `elara_finalized_hot_size = 10000` saturation
/// across all nodes. Kept identical to `DEFAULT_CAPACITY` so
/// existing operators see no behavior change post-upgrade.
pub const FULL_ZONE_PROFILE_CAPACITY: usize = 10_000;

/// Hot-tier capacity for `Archive` profile nodes. Archives intentionally hold
/// a large finalized hot set so `is_finalized()` answers from RAM at scale.
/// 1M entries ≈ 150 MB resident — bounded so archives can't OOM from
/// unbounded LRU growth, but large enough that single archives serving a
/// 10T records/day fleet still answer the bulk of finality queries from
/// hot path. Mainnet target operators with >4 GB RAM can raise via TOML
/// override (see `NodeConfig.finalized_hot_capacity`).
pub const ARCHIVE_PROFILE_CAPACITY: usize = 1_000_000;

// Strictly-increasing profile-capacity invariant: Light < FullZone < Archive.
// Compile-time static assertion — protects against a future edit accidentally
// lowering Archive below FullZone or FullZone below Light without noticing.
// Replaces the runtime `with_profile_caps_strictly_increase_by_role` test that
// clippy flagged as `assertions_on_constants` (the asserts were tautological
// at runtime since both sides are compile-time constants).
const _: () = assert!(LIGHT_PROFILE_CAPACITY < FULL_ZONE_PROFILE_CAPACITY);
const _: () = assert!(FULL_ZONE_PROFILE_CAPACITY < ARCHIVE_PROFILE_CAPACITY);

/// Prefix for the durable finalization-effects outbox marker in CF_METADATA.
///
/// A `pending_effects:{rid}` key means the exactly-once finalization
/// side-effects (witness rewards §11.1 + reputation credit §11.2) for `rid`
/// have NOT yet completed. It is written in the SAME RocksDB `WriteBatch` as
/// `finalized:{rid}` for every truly-new finalization (`insert_batch_returning_new`
/// / `insert_marked`), so it is impossible for `finalized:` to become durable
/// without the marker (design C durable outbox, verdict 2026-07-19).
/// `reward::process_finalization_effect` clears it once effects complete; the
/// boot/tick `reward::reconcile_pending_effects` sweep re-fires any marker left
/// behind by a detached effects task that panicked (`panic="unwind"` kills the
/// task silently — recovery cannot be boot-only). Value = 1 byte; bit `0x01`
/// set = reputation already credited (idempotency gate for the non-idempotent
/// `credit_undisputed`). Adjacent to `finalized:` in CF_METADATA — no new CF,
/// no migration; the prefix scan seeks directly into the range, so recovery is
/// O(pending), never O(all-finalized).
pub const PENDING_EFFECTS_PREFIX: &str = "pending_effects:";

/// Byte written for a fresh (reputation-not-yet-credited) effects marker.
pub const PENDING_EFFECTS_FRESH: u8 = 0x00;

/// Marker bit: the reputation credit for this rid has been durably applied.
pub const PENDING_EFFECTS_REPUTATION_CREDITED: u8 = 0x01;

/// Build the CF_METADATA key for a record's finalization-effects marker.
pub fn pending_effects_key(record_id: &str) -> String {
    format!("{PENDING_EFFECTS_PREFIX}{record_id}")
}

/// Disk-backed finalized index. NOT thread-safe on its own — wrap in `RwLock`.
pub struct FinalizedIndex {
    /// Recent finalized IDs kept in RAM for fast lookups.
    hot: HashSet<String>,
    /// Insertion order for eviction (front = oldest).
    order: VecDeque<String>,
    /// Maximum number of entries in the hot set.
    capacity: usize,
    /// Total count of all finalized records (hot + cold).
    total_count: usize,
    /// RocksDB handle for cold storage lookups and persistence.
    rocks: Arc<StorageEngine>,
    /// Cumulative count of `contains()` calls answered from the
    /// in-memory hot set without touching RocksDB. Pair with
    /// `cold_lookups_total` to compute the miss rate.
    pub hot_hits_total: AtomicU64,
    /// Cumulative count of `contains()` calls that fell through
    /// the hot set and probed RocksDB (regardless of whether the cold
    /// tier had the record). Sustained climb at high rate AND
    /// `_size == _capacity` = working set exceeds hot cap, every miss
    /// pays a CF_METADATA point read (~100ns–1µs with bloom filter).
    pub cold_lookups_total: AtomicU64,
    /// Cumulative count of `contains()` cold-path probes that
    /// **found** the record on disk. Cold-hit rate
    /// (`cold_hits / cold_lookups`) tells operators whether the misses
    /// represent real finalized records (rate near 1.0 → hot tier
    /// undersized, increase capacity) or speculative is_finalized
    /// queries for never-finalized rids (rate near 0.0 → cold tier
    /// being used for negative-existence checks, no cap change needed).
    pub cold_hits_total: AtomicU64,
}

impl FinalizedIndex {
    /// Create an empty index backed by the given storage engine.
    pub fn new(rocks: Arc<StorageEngine>, capacity: usize) -> Self {
        Self {
            hot: HashSet::with_capacity(capacity),
            order: VecDeque::with_capacity(capacity),
            capacity,
            total_count: 0,
            rocks,
            hot_hits_total: AtomicU64::new(0),
            cold_lookups_total: AtomicU64::new(0),
            cold_hits_total: AtomicU64::new(0),
        }
    }

    /// Create with default capacity (10,000 entries — FullZone-equivalent).
    /// Kept for legacy callers and tests. New production sites should use
    /// `with_profile` so the cap right-sizes per node role.
    pub fn with_defaults(rocks: Arc<StorageEngine>) -> Self {
        Self::new(rocks, DEFAULT_CAPACITY)
    }

    /// Create with profile-aware capacity.
    /// Phone-tier `Light` nodes get a 1k-entry hot set so they don't blow
    /// past the ~150 KB resident budget; operator `FullZone` nodes keep
    /// the 10k legacy cap; `Archive` nodes get a 1M cap so they answer the
    /// bulk of `is_finalized()` queries from RAM at mainnet scale.
    ///
    /// Operator override path: `NodeConfig.finalized_hot_capacity` (when
    /// non-zero) wins over the profile default. Kept simple — the profile
    /// caps are mainnet-correct for the named tiers; the override exists
    /// for unusual deployments (e.g. 16 GB archives, ultra-constrained
    /// embedded full-zones) without forcing a rebuild.
    pub fn with_profile(
        rocks: Arc<StorageEngine>,
        profile: super::node_profile::NodeProfile,
        override_capacity: usize,
    ) -> Self {
        let cap = if override_capacity > 0 {
            override_capacity
        } else {
            match profile {
                super::node_profile::NodeProfile::Light => LIGHT_PROFILE_CAPACITY,
                super::node_profile::NodeProfile::FullZone => FULL_ZONE_PROFILE_CAPACITY,
                super::node_profile::NodeProfile::Archive => ARCHIVE_PROFILE_CAPACITY,
            }
        };
        Self::new(rocks, cap)
    }

    /// Restore from a snapshot's finalized set. Persists any new ids from the
    /// snapshot into RocksDB (idempotent), then re-derives `total_count` and
    /// the hot LRU from RocksDB — the on-disk store is the authority.
    ///
    /// Why not just trust `all_ids.len()`: the live `/snapshot` and PQ
    /// `snapshot` paths intentionally ship `finalized: HashSet::new()`
    /// (routes/sync.rs:528, pq_transport/router.rs:827) because at 10M+
    /// records, copying the full finalized history into every snapshot
    /// response is too expensive. Treating that empty set as authoritative
    /// would wipe `total_count` to 0 on every snapshot rebootstrap and
    /// corrupt the `elara_finalized_count` metric, even though the on-disk
    /// `finalized:` keys are intact.
    pub fn restore_from_snapshot(&mut self, all_ids: &HashSet<String>) {
        for id in all_ids {
            let key = format!("finalized:{id}");
            let _ = self.rocks.put_cf_raw(CF_METADATA, key.as_bytes(), b"1");
        }

        self.load_count_from_rocks();
        self.load_hot_from_rocks();
    }

    /// Load the count of finalized records from RocksDB on startup.
    /// Scans the `finalized:` prefix to get an accurate count.
    pub fn load_count_from_rocks(&mut self) {
        let mut count = 0usize;
        let _ = self.rocks.prefix_scan(CF_METADATA, b"finalized:", |_, _| {
            count += 1;
            Ok(())
        });
        self.total_count = count;
    }

    /// Load recent finalized IDs from RocksDB into the hot set (startup path).
    /// Takes up to `capacity` entries. Since RocksDB prefix iteration is
    /// lexicographic (not temporal), this loads an arbitrary subset — but
    /// the hot set will naturally fill with truly recent IDs as the node runs.
    pub fn load_hot_from_rocks(&mut self) {
        self.hot.clear();
        self.order.clear();
        let mut loaded = 0usize;
        let cap = self.capacity;
        let _ = self.rocks.prefix_scan(CF_METADATA, b"finalized:", |key, _| {
            if loaded >= cap {
                return Ok(());
            }
            // Key format: "finalized:{record_id}"
            let key_str = std::str::from_utf8(key).unwrap_or("");
            if let Some(record_id) = key_str.strip_prefix("finalized:") {
                self.hot.insert(record_id.to_string());
                self.order.push_back(record_id.to_string());
                loaded += 1;
            }
            Ok(())
        });
    }

    /// Check if a record is finalized.
    /// Hot path: O(1) HashSet lookup. Cold path: single RocksDB point read.
    /// Bumps counters: `hot_hits_total` on RAM hit; on miss it
    /// always bumps `cold_lookups_total`, and bumps `cold_hits_total`
    /// only when the record is found on disk.
    pub fn contains(&self, record_id: &str) -> bool {
        // Fast path: check RAM
        if self.hot.contains(record_id) {
            self.hot_hits_total.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        // Slow path: check RocksDB
        self.cold_lookups_total.fetch_add(1, Ordering::Relaxed);
        let key = format!("finalized:{record_id}");
        let found = self
            .rocks
            .get_cf_raw(CF_METADATA, key.as_bytes())
            .ok()
            .flatten()
            .is_some();
        if found {
            self.cold_hits_total.fetch_add(1, Ordering::Relaxed);
        }
        found
    }

    /// Mark a record as finalized. Writes to both RAM and RocksDB.
    /// Returns true if the rid was *truly new* (not already on disk), i.e.
    /// caller should count it toward total_ever_settled. RocksDB write fires
    /// either way (idempotent in the durable layer too).
    ///
    /// We MUST check RocksDB cold tier before bumping `total_count`. The hot
    /// set is bounded (DEFAULT_CAPACITY = 10K) but the on-disk index grows
    /// without bound — so for any node with more finalized records than
    /// capacity, evicted-from-hot rids re-arriving (gossip refeed,
    /// finality_monitor batch, snapshot replay) would over-count if we only
    /// checked the hot set. Discovered 2026-04-30 via fleet drift: every VPS
    /// node showed `elara_finalized_count` 100-170 records above
    /// `total_ever_settled`. CF_METADATA bloom filter (Tier 4.5) makes the
    /// per-key get_cf_raw cheap (~100ns–1µs).
    pub fn insert(&mut self, record_id: String) -> bool {
        let key = format!("finalized:{record_id}");

        // Check cold tier BEFORE the write so we can distinguish truly-new
        // rids from re-finalizations of rids already on disk.
        let already_in_cold = self
            .rocks
            .get_cf_raw(CF_METADATA, key.as_bytes())
            .ok()
            .flatten()
            .is_some();

        // Persist (idempotent — write either way; RocksDB just overwrites).
        let _ = self.rocks.put_cf_raw(CF_METADATA, key.as_bytes(), b"1");

        self.insert_hot(record_id, already_in_cold)
    }

    /// Same as [`insert`], but for the SINGULAR effects-firing seam
    /// (`feed_attestation`, state.rs): atomically writes the durable
    /// `pending_effects:{rid}` marker alongside `finalized:{rid}` in one
    /// WriteBatch when the rid is truly new. The caller fires
    /// `reward::finalization_effects` on the returned `true`; the marker makes
    /// those effects recoverable if the detached effects task panics
    /// (`panic="unwind"` → silent task death).
    ///
    /// This is NOT a drop-in for the plain [`insert`]: the final-verify found
    /// `insert()` is polymorphic — its non-effects callers (`rotation_sweep`,
    /// `pending_drain` rotation + the xfer record) must NOT get a marker, or a
    /// blanket hook would emit unintended witness rewards for the xfer record.
    /// Only the two effects seams (`insert_batch_returning_new` and this) mark.
    pub fn insert_marked(&mut self, record_id: String) -> bool {
        let key = format!("finalized:{record_id}");

        // Check cold tier BEFORE the write so we can distinguish truly-new
        // rids from re-finalizations of rids already on disk.
        let already_in_cold = self
            .rocks
            .get_cf_raw(CF_METADATA, key.as_bytes())
            .ok()
            .flatten()
            .is_some();

        // Atomic: finalized: + (truly-new only) pending_effects: in one batch.
        if let Some(cf) = self.rocks.cf_handle(CF_METADATA) {
            let mut batch = self.rocks.new_batch();
            batch.put_cf(&cf, key.as_bytes(), b"1");
            if !already_in_cold {
                batch.put_cf(
                    &cf,
                    pending_effects_key(&record_id).as_bytes(),
                    [PENDING_EFFECTS_FRESH],
                );
            }
            let _ = self.rocks.write_batch(batch);
        } else {
            // CF handle unavailable (should never happen once the DB is open):
            // fall back to the plain finalized: put so finality stays durable.
            // RESIDUAL: this one branch writes finalized: WITHOUT the marker, so
            // its effects would not be recovered by the sweep. Accepted — it is
            // strictly no worse than insert_batch_returning_new's own
            // CF-handle-missing branch (which skips the finalized: write
            // entirely), and both require an already-catastrophic DB state.
            let _ = self.rocks.put_cf_raw(CF_METADATA, key.as_bytes(), b"1");
        }

        self.insert_hot(record_id, already_in_cold)
    }

    /// Insert into hot set only (no RocksDB write). Used by insert and
    /// insert_batch after the caller has already checked the cold tier.
    /// Returns true ONLY if the rid was truly new (not already in cold tier);
    /// rids that were on disk but evicted from hot get re-added to hot but
    /// don't bump `total_count`.
    fn insert_hot(&mut self, record_id: String, already_in_cold: bool) -> bool {
        // Already in hot? Nothing to do — duplicate insert in same epoch.
        if self.hot.contains(&record_id) {
            return false;
        }

        // Evict oldest if at capacity.
        if self.hot.len() >= self.capacity {
            if let Some(old) = self.order.pop_front() {
                self.hot.remove(&old);
            }
        }

        self.hot.insert(record_id.clone());
        self.order.push_back(record_id);

        // Only bump total_count when the rid is truly new — otherwise we're
        // just refreshing the hot tier with a rid that was already on disk.
        if already_in_cold {
            false
        } else {
            self.total_count += 1;
            true
        }
    }

    /// Mark multiple records as finalized in a single RocksDB WriteBatch.
    /// Much faster than calling insert() in a loop: 1 WAL sync instead of N.
    /// Returns the count of records that were *truly new* (not already on
    /// disk). Callers that bump `total_ever_settled` should use this return
    /// value, not `record_ids.len()` — otherwise rids already finalized by
    /// another path (e.g. finality_monitor) cause the counter to over-count.
    pub fn insert_batch(&mut self, record_ids: &[String]) -> usize {
        self.insert_batch_returning_new(record_ids).len()
    }

    /// Same as [`insert_batch`] but returns the rids that were *truly new*
    /// (not already in the cold tier). This is the exactly-once finalization
    /// edge: side-effects that must fire once per record lifetime (witness
    /// rewards, reputation credit, RecordFinalized events) key off this
    /// return value, so whichever path wins the insert (feed_attestation,
    /// batch feed, gossip refeed, finality monitor) fires them and every
    /// later path sees the rid as already-finalized.
    pub fn insert_batch_returning_new(&mut self, record_ids: &[String]) -> Vec<String> {
        if record_ids.is_empty() {
            return Vec::new();
        }

        // Probe cold tier for each rid BEFORE the batch write, so we can
        // distinguish truly-new rids from re-finalizations. The CF_METADATA
        // bloom filter shortcuts misses to ~100ns–1µs per probe; for typical
        // 10–100-rid batches this adds < 100µs vs the prior code path.
        let mut already_in_cold: Vec<bool> = Vec::with_capacity(record_ids.len());
        for rid in record_ids {
            let key = format!("finalized:{rid}");
            let in_cold = self
                .rocks
                .get_cf_raw(CF_METADATA, key.as_bytes())
                .ok()
                .flatten()
                .is_some();
            already_in_cold.push(in_cold);
        }

        // Single atomic RocksDB write for all records.
        // Scope the CF handle borrow so it's dropped before we mutate self.
        // Each TRULY-NEW rid (`!already_in_cold`) also gets its durable
        // finalization-effects marker in the SAME batch — so a finalized record
        // can never be durable without its exactly-once effects outbox entry
        // (design C). Re-finalizations of already-cold rids fire NO effects, so
        // they intentionally get no marker.
        if let Some(cf) = self.rocks.cf_handle(CF_METADATA) {
            let mut batch = self.rocks.new_batch();
            for (rid, in_cold) in record_ids.iter().zip(already_in_cold.iter()) {
                let key = format!("finalized:{rid}");
                batch.put_cf(&cf, key.as_bytes(), b"1");
                if !*in_cold {
                    batch.put_cf(
                        &cf,
                        pending_effects_key(rid).as_bytes(),
                        [PENDING_EFFECTS_FRESH],
                    );
                }
            }
            let _ = self.rocks.write_batch(batch);
        }

        // Update hot set (now safe to borrow self mutably) — collect truly-new rids.
        let mut new_rids = Vec::new();
        for (rid, in_cold) in record_ids.iter().zip(already_in_cold.iter()) {
            if self.insert_hot(rid.clone(), *in_cold) {
                new_rids.push(rid.clone());
            }
        }
        new_rids
    }

    /// Total number of finalized records (hot + cold).
    pub fn len(&self) -> usize {
        self.total_count
    }

    /// True if no records have been finalized.
    pub fn is_empty(&self) -> bool {
        self.total_count == 0
    }

    /// Collect all finalized IDs from RocksDB into a HashSet.
    /// Used for snapshot saving and compatibility with `prune_finalized()`.
    /// Expensive — scans all `finalized:*` keys. Use sparingly, and NEVER
    /// while holding the `finalized` RwLock on a hot path: the scan is the
    /// whole cold tier, so a guard held across it stalls every finalization
    /// writer for the walk. Callers that only need the rocks handle should
    /// use the lock-free module fn [`collect_finalized_ids`] directly.
    pub fn to_hashset(&self) -> HashSet<String> {
        collect_finalized_ids(&self.rocks)
    }

    /// Get the hot set size (for metrics/debugging).
    pub fn hot_size(&self) -> usize {
        self.hot.len()
    }

    /// Get the capacity.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Clone the in-memory hot set for use as a predicate snapshot.
    /// Used by the DAG cascade-eviction path in `network::ingest`: we snapshot
    /// the finalized hot set BEFORE taking the DAG write lock, then pass the
    /// snapshot as the `is_finalized` predicate to `dag.evict_finalized()`.
    /// This keeps the predicate a pure O(1) HashSet lookup — no RocksDB I/O
    /// while the DAG write lock is held. Bounded by `capacity` (10K) so the
    /// clone is cheap. The snapshot is necessarily NOT exhaustive (older
    /// finalized records live only in CF_METADATA), but for the cascade path
    /// this is by design — records older than `HOT_EPOCH_WINDOW` should
    /// already have been caught by `evict_old_epochs()`; this fallback only
    /// needs to catch records finalized externally but never `mark_finalized`'d
    /// in the DAG (legacy snapshot, restart, missed wiring), which are by
    /// definition recent if the node is up-to-date.
    pub fn hot_set_clone(&self) -> HashSet<String> {
        self.hot.clone()
    }
}

// ─── Lock-free cold-tier accessors ──────────────────────────────────────────
//
// The cold tier (CF_METADATA `finalized:{record_id}` keys) is the durable
// truth: `insert()` persists to RocksDB BEFORE updating the hot set, so disk
// is never behind RAM (modulo an ignored disk-write error, where the locked
// `to_hashset()` path would miss the rid identically). These fns exist so
// O(n) sweeps (GC, admin snapshot) can probe or enumerate finalization
// WITHOUT holding the `NodeState::finalized` RwLock — holding it across a
// full prefix walk stalls every finalization writer (state_core, gossip,
// sync, pending_drain) for the duration.

/// Lock-free single-record finalized check straight against the cold tier.
/// One bloom-filtered CF_METADATA point read (~100ns–1µs). Truth-equivalent
/// to the snapshot a `to_hashset()` caller would consult, but always fresher:
/// finalization is monotonic (records never un-finalize), so a live read can
/// only ADD protection relative to a stale snapshot.
pub fn contains_in_rocks(rocks: &StorageEngine, record_id: &str) -> bool {
    let key = format!("finalized:{record_id}");
    rocks
        .get_cf_raw(CF_METADATA, key.as_bytes())
        .ok()
        .flatten()
        .is_some()
}

/// Lock-free full enumeration of the cold tier — same output as
/// [`FinalizedIndex::to_hashset`] without needing the index (or its lock).
/// Still O(total finalized history); run it on the blocking pool.
pub fn collect_finalized_ids(rocks: &StorageEngine) -> HashSet<String> {
    let mut set = HashSet::new();
    let _ = rocks.prefix_scan(CF_METADATA, b"finalized:", |key, _| {
        let key_str = std::str::from_utf8(key).unwrap_or("");
        if let Some(record_id) = key_str.strip_prefix("finalized:") {
            set.insert(record_id.to_string());
        }
        Ok(())
    });
    set
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_engine() -> (Arc<StorageEngine>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let engine = Arc::new(StorageEngine::open(dir.path()).unwrap());
        (engine, dir)
    }

    #[test]
    fn test_insert_and_contains() {
        let (rocks, _dir) = test_engine();
        let mut idx = FinalizedIndex::new(rocks, 100);

        assert!(!idx.contains("rec-1"));
        idx.insert("rec-1".to_string());
        assert!(idx.contains("rec-1"));
        assert_eq!(idx.len(), 1);
    }

    /// `insert_batch_returning_new` is the exactly-once finalization edge —
    /// it must return ONLY rids genuinely new to the durable cold tier:
    /// not hot-set duplicates, not cold-tier re-finalizations (even after
    /// hot eviction), and the rids it does return must preserve input order.
    #[test]
    fn test_insert_batch_returning_new_is_the_exactly_once_edge() {
        let (rocks, _dir) = test_engine();
        let mut idx = FinalizedIndex::new(rocks, 2); // tiny: force hot eviction

        // First batch: all new.
        let batch1: Vec<String> = vec!["r-a".into(), "r-b".into(), "r-c".into()];
        let new1 = idx.insert_batch_returning_new(&batch1);
        assert_eq!(new1, batch1, "first insert: every rid is new, order kept");

        // r-a evicted from hot (capacity 2) but durable in cold tier.
        assert!(!idx.hot.contains("r-a"), "r-a must be hot-evicted at cap 2");

        // Second batch: one repeat-in-hot (r-c), one repeat-in-cold-only
        // (r-a — the prune-then-re-push shape), one genuinely new (r-d).
        let batch2: Vec<String> = vec!["r-c".into(), "r-a".into(), "r-d".into()];
        let new2 = idx.insert_batch_returning_new(&batch2);
        assert_eq!(
            new2,
            vec!["r-d".to_string()],
            "only the genuinely-new rid fires the edge; cold-tier re-finalization must not"
        );

        // Counters stay aligned: 4 unique finalizations total.
        assert_eq!(idx.len(), 4);

        // insert_batch (count wrapper) keeps the same semantics.
        assert_eq!(idx.insert_batch(&batch2), 0, "full repeat batch → 0 new");
    }

    #[test]
    fn test_eviction_falls_back_to_rocks() {
        let (rocks, _dir) = test_engine();
        let mut idx = FinalizedIndex::new(rocks, 3); // tiny capacity

        idx.insert("rec-1".to_string());
        idx.insert("rec-2".to_string());
        idx.insert("rec-3".to_string());
        assert_eq!(idx.hot_size(), 3);

        // Insert 4th — should evict rec-1 from hot set
        idx.insert("rec-4".to_string());
        assert_eq!(idx.hot_size(), 3);
        assert_eq!(idx.len(), 4);

        // rec-1 is evicted from RAM but still in RocksDB
        assert!(!idx.hot.contains("rec-1"));
        assert!(idx.contains("rec-1")); // falls back to RocksDB
    }

    #[test]
    fn test_to_hashset_returns_all() {
        let (rocks, _dir) = test_engine();
        let mut idx = FinalizedIndex::new(rocks, 2);

        idx.insert("a".to_string());
        idx.insert("b".to_string());
        idx.insert("c".to_string());

        let all = idx.to_hashset();
        assert_eq!(all.len(), 3);
        assert!(all.contains("a"));
        assert!(all.contains("b"));
        assert!(all.contains("c"));
    }

    // ── design C: durable finalization-effects outbox marker ─────────────────

    fn read_marker(rocks: &StorageEngine, rid: &str) -> Option<Vec<u8>> {
        rocks
            .get_cf_raw(CF_METADATA, pending_effects_key(rid).as_bytes())
            .ok()
            .flatten()
    }

    #[test]
    fn batch_writes_pending_effects_marker_atomically_for_new_rids_only() {
        let (rocks, _dir) = test_engine();
        let mut idx = FinalizedIndex::new(rocks.clone(), 100);

        let new = idx.insert_batch_returning_new(&["a".to_string(), "b".to_string()]);
        assert_eq!(new.len(), 2, "both truly new");

        // Every truly-new rid carries BOTH finalized: and a fresh marker.
        for rid in ["a", "b"] {
            assert!(idx.contains(rid), "{rid} finalized");
            assert_eq!(
                read_marker(&rocks, rid),
                Some(vec![PENDING_EFFECTS_FRESH]),
                "{rid} must carry a fresh (uncredited) effects marker"
            );
        }

        // Re-finalizing an already-cold rid fires NO effects → writes NO new
        // marker. Simulate completed effects by clearing "a" first, then
        // re-insert and confirm the marker is not re-armed.
        let _ = rocks.delete_cf_raw(CF_METADATA, pending_effects_key("a").as_bytes());
        let new2 = idx.insert_batch_returning_new(&["a".to_string()]);
        assert!(new2.is_empty(), "already-cold → not new");
        assert_eq!(
            read_marker(&rocks, "a"),
            None,
            "no marker re-created for a re-finalization"
        );
    }

    #[test]
    fn plain_insert_writes_no_marker_but_insert_marked_does() {
        // Final-verify correction: insert() is polymorphic (rotation / xfer
        // callers) and MUST NOT mark, or the xfer record would emit unintended
        // witness rewards. Only insert_marked (the feed_attestation seam) marks.
        let (rocks, _dir) = test_engine();
        let mut idx = FinalizedIndex::new(rocks.clone(), 100);

        assert!(idx.insert("plain".to_string()), "plain new");
        assert!(idx.contains("plain"));
        assert_eq!(
            read_marker(&rocks, "plain"),
            None,
            "plain insert() must NOT write an effects marker"
        );

        assert!(idx.insert_marked("marked".to_string()), "marked new");
        assert!(idx.contains("marked"));
        assert_eq!(
            read_marker(&rocks, "marked"),
            Some(vec![PENDING_EFFECTS_FRESH]),
            "insert_marked must write a fresh marker"
        );
    }

    #[test]
    fn insert_marked_on_already_cold_rid_writes_no_marker() {
        let (rocks, _dir) = test_engine();
        let mut idx = FinalizedIndex::new(rocks.clone(), 100);

        assert!(idx.insert_marked("x".to_string()), "first is new");
        // Clear the marker to represent completed effects.
        let _ = rocks.delete_cf_raw(CF_METADATA, pending_effects_key("x").as_bytes());

        // Re-finalization of the same rid → false, and must NOT re-arm the
        // marker (effects already fired once).
        assert!(!idx.insert_marked("x".to_string()), "already cold → not new");
        assert_eq!(
            read_marker(&rocks, "x"),
            None,
            "no marker on re-finalization"
        );
    }

    /// The lock-free cold-tier accessors (GC's and admin-snapshot's truth
    /// source since the O(n)-under-lock DoS batch) must agree with the
    /// locked index views: `contains_in_rocks` with `contains()` even after
    /// hot eviction, `collect_finalized_ids` with `to_hashset()`.
    #[test]
    fn test_lock_free_cold_tier_accessors_match_index_views() {
        let (rocks, _dir) = test_engine();
        let mut idx = FinalizedIndex::new(rocks.clone(), 2); // tiny: force eviction

        idx.insert("r-1".to_string());
        idx.insert("r-2".to_string());
        idx.insert("r-3".to_string()); // evicts r-1 from hot

        // Hot-evicted, hot-resident, and absent rids all answer identically
        // to the locked path.
        assert!(!idx.hot.contains("r-1"), "r-1 must be hot-evicted at cap 2");
        for rid in ["r-1", "r-2", "r-3"] {
            assert!(
                contains_in_rocks(&rocks, rid),
                "{rid}: lock-free check must see the durable finalization"
            );
            assert_eq!(contains_in_rocks(&rocks, rid), idx.contains(rid));
        }
        assert!(!contains_in_rocks(&rocks, "r-never"));

        assert_eq!(
            collect_finalized_ids(&rocks),
            idx.to_hashset(),
            "free enumeration must equal the index's own hashset view"
        );
    }

    #[test]
    fn test_duplicate_insert_no_double_count() {
        let (rocks, _dir) = test_engine();
        let mut idx = FinalizedIndex::new(rocks, 100);

        idx.insert("rec-1".to_string());
        idx.insert("rec-1".to_string());
        assert_eq!(idx.len(), 1);
        assert_eq!(idx.hot_size(), 1);
    }

    #[test]
    fn test_restore_from_snapshot() {
        let (rocks, _dir) = test_engine();
        let mut idx = FinalizedIndex::new(rocks, 3);

        let mut snapshot_ids = HashSet::new();
        for i in 0..5 {
            snapshot_ids.insert(format!("rec-{i}"));
        }

        idx.restore_from_snapshot(&snapshot_ids);
        assert_eq!(idx.len(), 5);
        assert_eq!(idx.hot_size(), 3); // only 3 loaded into RAM

        // All 5 should be findable via RocksDB fallback
        for i in 0..5 {
            assert!(idx.contains(&format!("rec-{i}")));
        }
    }

    #[test]
    fn test_load_count_from_rocks() {
        let (rocks, _dir) = test_engine();

        // Pre-populate RocksDB directly
        for i in 0..7 {
            let key = format!("finalized:rec-{i}");
            rocks.put_cf_raw(CF_METADATA, key.as_bytes(), b"1").unwrap();
        }

        let mut idx = FinalizedIndex::new(rocks, 100);
        assert_eq!(idx.len(), 0); // not loaded yet

        idx.load_count_from_rocks();
        assert_eq!(idx.len(), 7);
    }

    #[test]
    fn test_insert_batch() {
        let (rocks, _dir) = test_engine();
        let mut idx = FinalizedIndex::new(rocks, 100);

        let ids: Vec<String> = (0..50).map(|i| format!("batch-{i}")).collect();
        idx.insert_batch(&ids);

        assert_eq!(idx.len(), 50);
        assert_eq!(idx.hot_size(), 50);
        for id in &ids {
            assert!(idx.contains(id));
        }
    }

    #[test]
    fn test_insert_batch_with_eviction() {
        let (rocks, _dir) = test_engine();
        let mut idx = FinalizedIndex::new(rocks, 5); // tiny capacity

        let ids: Vec<String> = (0..10).map(|i| format!("batch-{i}")).collect();
        idx.insert_batch(&ids);

        assert_eq!(idx.len(), 10);
        assert_eq!(idx.hot_size(), 5); // only 5 in hot set

        // All 10 should be findable (hot or RocksDB fallback)
        for id in &ids {
            assert!(idx.contains(id), "missing {id}");
        }
    }

    #[test]
    fn test_load_hot_from_rocks() {
        let (rocks, _dir) = test_engine();

        // Pre-populate RocksDB
        for i in 0..5 {
            let key = format!("finalized:rec-{i}");
            rocks.put_cf_raw(CF_METADATA, key.as_bytes(), b"1").unwrap();
        }

        let mut idx = FinalizedIndex::new(rocks, 3);
        idx.load_count_from_rocks();
        idx.load_hot_from_rocks();

        assert_eq!(idx.len(), 5);
        assert_eq!(idx.hot_size(), 3); // limited by capacity
    }

    /// Regression: an empty snapshot must NOT wipe a node's pre-existing
    /// finalized count. Live snapshots (routes/sync.rs:528, pq router:827)
    /// ship `finalized: HashSet::new()` because copying the full history is
    /// too expensive at 10M+ records — but the receiver's RocksDB already
    /// holds the truth. Reproduced by running snapshot rebootstrap
    /// against a node: total_count went from 42811 to 0, breaking the
    /// elara_finalized_count metric while the on-disk index was intact.
    #[test]
    fn ops34_restore_from_empty_snapshot_preserves_local_state() {
        let (rocks, _dir) = test_engine();

        for i in 0..7 {
            let key = format!("finalized:rec-{i}");
            rocks.put_cf_raw(CF_METADATA, key.as_bytes(), b"1").unwrap();
        }

        let mut idx = FinalizedIndex::new(rocks, 3);
        idx.load_count_from_rocks();
        idx.load_hot_from_rocks();
        assert_eq!(idx.len(), 7);

        idx.restore_from_snapshot(&HashSet::new());

        assert_eq!(idx.len(), 7, "empty snapshot must not clobber local count");
        assert_eq!(idx.hot_size(), 3, "hot set must stay at capacity");
        for i in 0..7 {
            assert!(idx.contains(&format!("rec-{i}")));
        }
    }

    /// Regression: re-inserting a rid that was evicted from the hot set but
    /// still lives in RocksDB cold tier must NOT increment `total_count` again.
    ///
    /// Discovered 2026-04-30 via fleet drift: every VPS node showed
    /// `elara_finalized_count` (= total_count) drifting 100-170 records above
    /// `total_ever_settled`. Root cause: hot set capacity (10K) is much
    /// smaller than finalized history (350K-400K), so rids constantly evict
    /// from hot. Subsequent re-inserts (gossip refeed, finality_monitor
    /// batch, snapshot replay) saw `hot.contains == false`, passed the
    /// duplicate check, and bumped `total_count` even though the rid was
    /// already on disk. The caller-side `is_new_insert` gate then under-bumped
    /// `total_ever_settled` (correctly), creating the divergence.
    #[test]
    fn regression_reinsert_after_hot_eviction_no_double_count() {
        let (rocks, _dir) = test_engine();
        let mut idx = FinalizedIndex::new(rocks, 3); // small capacity to force eviction

        // Insert 4 rids → rec-1 evicts from hot but stays in cold tier.
        idx.insert("rec-1".to_string());
        idx.insert("rec-2".to_string());
        idx.insert("rec-3".to_string());
        idx.insert("rec-4".to_string());
        assert_eq!(idx.len(), 4);
        assert!(!idx.hot.contains("rec-1"), "rec-1 should be evicted from hot");
        assert!(idx.contains("rec-1"), "rec-1 should still be in cold tier");

        // Re-insert rec-1. It's in cold but evicted from hot.
        let was_new = idx.insert("rec-1".to_string());

        // total_count must NOT increase — rec-1 was already finalized.
        assert_eq!(
            idx.len(),
            4,
            "re-insert of cold-tier rid must not bump total_count"
        );
        assert!(!was_new, "re-insert of cold-tier rid must return false (not new)");
        // rec-1 should now be back in hot set (refreshed).
        assert!(idx.hot.contains("rec-1"), "rec-1 should be re-added to hot");
    }

    /// Regression: insert_batch must count only truly-new rids — re-finalizing
    /// rids that were evicted from hot but live in cold tier must not bump
    /// the new-insert count. Same root cause as
    /// `regression_reinsert_after_hot_eviction_no_double_count`, but exercises
    /// the batch path used by gossip refeed and finality_monitor.
    #[test]
    fn regression_insert_batch_skips_cold_tier_dupes() {
        let (rocks, _dir) = test_engine();
        let mut idx = FinalizedIndex::new(rocks, 3);

        // Pre-finalize 5 rids; rec-1 and rec-2 evict from hot (but stay in cold).
        for i in 1..=5 {
            idx.insert(format!("rec-{i}"));
        }
        assert_eq!(idx.len(), 5);
        assert!(!idx.hot.contains("rec-1"));
        assert!(!idx.hot.contains("rec-2"));

        // Batch with mix: rec-1 (cold dupe), rec-2 (cold dupe), rec-6 (new), rec-7 (new).
        let batch = vec![
            "rec-1".to_string(),
            "rec-2".to_string(),
            "rec-6".to_string(),
            "rec-7".to_string(),
        ];
        let new_inserts = idx.insert_batch(&batch);

        assert_eq!(new_inserts, 2, "batch must count only truly-new rids");
        assert_eq!(
            idx.len(),
            7,
            "total_count = 5 (existing) + 2 (rec-6, rec-7); rec-1/rec-2 are dupes"
        );
        // All 7 still findable.
        for i in 1..=7 {
            assert!(idx.contains(&format!("rec-{i}")));
        }
    }

    /// Regression: same rid inserted twice in a single call must not double-count.
    /// (This was already correct via the hot.contains() guard, but the new
    /// cold-tier check shouldn't break it.)
    #[test]
    fn regression_repeated_insert_same_rid_no_double_count() {
        let (rocks, _dir) = test_engine();
        let mut idx = FinalizedIndex::new(rocks, 100);

        let first = idx.insert("rec-A".to_string());
        let second = idx.insert("rec-A".to_string());
        let third = idx.insert("rec-A".to_string());

        assert!(first, "first insert is new");
        assert!(!second, "second insert is duplicate");
        assert!(!third, "third insert is duplicate");
        assert_eq!(idx.len(), 1);
    }

    /// Restore must merge snapshot ids into RocksDB and re-derive total_count
    /// from the on-disk scan — never just `all_ids.len()`. With prior local
    /// state, the post-restore count is the union (hard count from RocksDB).
    #[test]
    fn ops34_restore_from_snapshot_merges_with_existing_state() {
        let (rocks, _dir) = test_engine();

        for i in 0..5 {
            let key = format!("finalized:local-{i}");
            rocks.put_cf_raw(CF_METADATA, key.as_bytes(), b"1").unwrap();
        }

        let mut idx = FinalizedIndex::new(rocks, 100);
        idx.load_count_from_rocks();
        assert_eq!(idx.len(), 5);

        let mut snapshot_ids = HashSet::new();
        for i in 0..3 {
            snapshot_ids.insert(format!("snap-{i}"));
        }

        idx.restore_from_snapshot(&snapshot_ids);

        assert_eq!(idx.len(), 8, "merged set: 5 local + 3 from snapshot");
        for i in 0..5 {
            assert!(idx.contains(&format!("local-{i}")));
        }
        for i in 0..3 {
            assert!(idx.contains(&format!("snap-{i}")));
        }
    }

    /// Pin the LRU hot-tier semantics for the
    /// `elara_finalized_hot_size` and `elara_finalized_hot_capacity`
    /// /metrics gauges. The pair gives operators an LRU-pressure signal:
    /// `hot_size / capacity ≈ 1.0` = LRU saturated, every fresh
    /// `is_finalized()` miss falls through to a RocksDB CF lookup.
    /// Without this gauge, operators see "the cluster slowed down at
    /// 5pm" without the diagnosis that the finalized hot tier had hit
    /// its cap and started thrashing.
    #[test]
    fn ops_52_hot_size_and_capacity_pin_lru_pressure_for_gauges() {
        let (rocks, _dir) = test_engine();
        let cap = 5usize;
        let mut idx = FinalizedIndex::new(rocks, cap);

        // I1: fresh index → hot_size=0, capacity reflects config.
        assert_eq!(idx.hot_size(), 0);
        assert_eq!(idx.capacity(), cap);

        // I2: insertions below capacity climb hot_size linearly until full.
        for i in 0..cap {
            idx.insert(format!("rec-{i}"));
            assert_eq!(
                idx.hot_size(),
                i + 1,
                "hot_size advances by exactly 1 per fresh insert below cap"
            );
            assert_eq!(idx.capacity(), cap, "capacity is static config — never drifts");
        }

        // I3: at saturation, hot_size = capacity (the alarm condition).
        assert_eq!(idx.hot_size(), cap, "saturated LRU");
        assert_eq!(
            idx.hot_size(),
            idx.capacity(),
            "ratio hot_size/capacity = 1.0 — operators alert here"
        );

        // I4: insertion past capacity does NOT inflate hot_size — LRU
        // evicts oldest. Gauge stays pinned at capacity even as more
        // inserts flow through. Critical: this is the OPERATOR-CONFUSING
        // case we test for. Without this invariant, an alert based on
        // "is hot_size growing?" would silently miss saturated thrash
        // because the gauge plateaus.
        for i in cap..(cap + 10) {
            idx.insert(format!("rec-{i}"));
            assert_eq!(
                idx.hot_size(),
                cap,
                "post-saturation inserts evict oldest; hot_size pinned at cap"
            );
        }

        // I5: capacity is immutable across all inserts (static config).
        assert_eq!(idx.capacity(), cap);

        // I6: duplicate inserts are no-ops and do NOT inflate hot_size
        // (gauge MUST count distinct resident IDs, not insert events).
        let before = idx.hot_size();
        for _ in 0..3 {
            // Use one of the records still resident after eviction. With
            // capacity=5 and 15 inserts above, the most-recent residents
            // are rec-10..rec-14.
            idx.insert("rec-14".to_string());
        }
        assert_eq!(
            idx.hot_size(),
            before,
            "duplicate insert of resident ID is no-op — gauge unchanged"
        );
    }

    // ── profile-aware capacity ─────────────────────

    #[test]
    fn with_profile_light_uses_phone_tier_cap() {
        // Phone-tier nodes get a 1k hot set so they don't blow past
        // ~150 KB resident — fits below the Light profile's 72h
        // record-retention budget.
        let (rocks, _dir) = test_engine();
        let idx = FinalizedIndex::with_profile(
            rocks,
            crate::network::node_profile::NodeProfile::Light,
            0,
        );
        assert_eq!(idx.capacity(), LIGHT_PROFILE_CAPACITY);
        assert_eq!(idx.capacity(), 1_000);
    }

    #[test]
    fn with_profile_full_zone_matches_legacy_default() {
        // Operator default — must match the pre-audit DEFAULT_CAPACITY
        // bit-for-bit so existing fleets see no behavior change post-upgrade.
        let (rocks, _dir) = test_engine();
        let idx = FinalizedIndex::with_profile(
            rocks,
            crate::network::node_profile::NodeProfile::FullZone,
            0,
        );
        assert_eq!(idx.capacity(), FULL_ZONE_PROFILE_CAPACITY);
        assert_eq!(idx.capacity(), DEFAULT_CAPACITY);
    }

    #[test]
    fn with_profile_archive_holds_million_entry_hot_set() {
        // Archives keep a large hot set so `is_finalized()` answers
        // from RAM at mainnet scale (10T records/day across 1M zones).
        let (rocks, _dir) = test_engine();
        let idx = FinalizedIndex::with_profile(
            rocks,
            crate::network::node_profile::NodeProfile::Archive,
            0,
        );
        assert_eq!(idx.capacity(), ARCHIVE_PROFILE_CAPACITY);
        assert_eq!(idx.capacity(), 1_000_000);
    }

    #[test]
    fn with_profile_override_wins_when_nonzero() {
        // Operator override path — TOML `finalized_hot_capacity = N`
        // beats the profile default. Lets a 16 GB archive set 4M, or
        // a constrained full-zone drop to 5K, without touching code.
        let (rocks, _dir) = test_engine();
        let idx = FinalizedIndex::with_profile(
            rocks,
            crate::network::node_profile::NodeProfile::Light,
            42_000,
        );
        assert_eq!(idx.capacity(), 42_000);
    }

    // Strictly-increasing profile-capacity invariant
    // (Light < FullZone < Archive) is now a compile-time static assertion
    // at module scope above the consts — see `const _: () = assert!(..)`.
    // The former `with_profile_caps_strictly_increase_by_role` runtime test
    // was clippy::assertions_on_constants tautological.

    #[test]
    fn ops61_hot_hit_increments_only_hot_counter() {
        // A contains() call answered from the in-memory hot set
        // must bump hot_hits_total and leave the cold counters untouched.
        let (rocks, _dir) = test_engine();
        let mut idx = FinalizedIndex::new(rocks, 100);
        idx.insert("rec-hot".to_string());

        assert_eq!(idx.hot_hits_total.load(Ordering::Relaxed), 0);
        assert_eq!(idx.cold_lookups_total.load(Ordering::Relaxed), 0);
        assert_eq!(idx.cold_hits_total.load(Ordering::Relaxed), 0);

        assert!(idx.contains("rec-hot"));

        assert_eq!(idx.hot_hits_total.load(Ordering::Relaxed), 1);
        assert_eq!(idx.cold_lookups_total.load(Ordering::Relaxed), 0);
        assert_eq!(idx.cold_hits_total.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn ops61_cold_miss_not_found_bumps_only_lookup() {
        // A contains() probe for an rid that is NOT in the hot
        // set AND NOT on disk must bump cold_lookups_total once and
        // leave cold_hits_total at 0. This is the speculative-query
        // shape — operators reading the metric should see lookups
        // climb without hits to identify negative-existence checks.
        let (rocks, _dir) = test_engine();
        let idx = FinalizedIndex::new(rocks, 100);

        assert!(!idx.contains("never-finalized"));

        assert_eq!(idx.hot_hits_total.load(Ordering::Relaxed), 0);
        assert_eq!(idx.cold_lookups_total.load(Ordering::Relaxed), 1);
        assert_eq!(idx.cold_hits_total.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn ops61_cold_hit_after_eviction_bumps_both() {
        // When an rid was finalized, evicted from the hot LRU,
        // and is then queried again, contains() must hit RocksDB and
        // bump BOTH cold_lookups_total and cold_hits_total. This is
        // the working-set-too-big shape — the hot tier is undersized
        // for the query mix and operators should bump capacity.
        let (rocks, _dir) = test_engine();
        let mut idx = FinalizedIndex::new(rocks, 2);

        idx.insert("rec-1".to_string());
        idx.insert("rec-2".to_string());
        idx.insert("rec-3".to_string()); // evicts rec-1 from hot

        assert!(!idx.hot.contains("rec-1"));

        // Reset baselines (insert() does not touch contains() counters).
        assert_eq!(idx.hot_hits_total.load(Ordering::Relaxed), 0);
        assert_eq!(idx.cold_lookups_total.load(Ordering::Relaxed), 0);
        assert_eq!(idx.cold_hits_total.load(Ordering::Relaxed), 0);

        assert!(idx.contains("rec-1"));

        assert_eq!(idx.hot_hits_total.load(Ordering::Relaxed), 0);
        assert_eq!(idx.cold_lookups_total.load(Ordering::Relaxed), 1);
        assert_eq!(idx.cold_hits_total.load(Ordering::Relaxed), 1);
    }

    // ── +5 fixture-free pins on legacy ctor / is_empty /
    //    hot_set_clone snapshot / profile triplet / counter monotonicity ──

    /// Pin `with_defaults` legacy ctor to DEFAULT_CAPACITY and
    /// cross-equiv with `FULL_ZONE_PROFILE_CAPACITY`. A future bump of
    /// `DEFAULT_CAPACITY` without also lifting `FULL_ZONE_PROFILE_CAPACITY`
    /// (or vice versa) would silently desync the legacy ctor from the
    /// operator-default profile and break the guarantee
    /// that existing fleets see no behavior change post-upgrade.
    #[test]
    fn batch_b_with_defaults_legacy_ctor_uses_default_capacity_10k() {
        let (rocks, _dir) = test_engine();
        let idx = FinalizedIndex::with_defaults(rocks);

        // Axis 1: DEFAULT_CAPACITY exact byte pin.
        assert_eq!(DEFAULT_CAPACITY, 10_000);
        // Axis 2: with_defaults exposes that value via capacity().
        assert_eq!(idx.capacity(), 10_000);
        assert_eq!(idx.capacity(), DEFAULT_CAPACITY);
        // Axis 3: FullZone profile and legacy ctor are bit-for-bit equal.
        assert_eq!(DEFAULT_CAPACITY, FULL_ZONE_PROFILE_CAPACITY);
        assert_eq!(idx.capacity(), FULL_ZONE_PROFILE_CAPACITY);
        // Axis 4: fresh index from legacy ctor is empty.
        assert_eq!(idx.len(), 0);
        assert!(idx.is_empty());
        assert_eq!(idx.hot_size(), 0);
    }

    /// Pin `is_empty()` to `total_count == 0`, NOT to the hot set.
    /// After hot eviction, the hot set can shrink/cycle but the cold tier
    /// still holds finalized records — `is_empty()` MUST track the durable
    /// total count, not the volatile in-memory window. A future edit
    /// switching `is_empty` to `self.hot.is_empty()` would silently report
    /// an empty index after long-running nodes finalize past `capacity` and
    /// then evict everything that hasn't been re-touched.
    #[test]
    fn batch_b_is_empty_tracks_total_count_not_hot_set() {
        let (rocks, _dir) = test_engine();
        let mut idx = FinalizedIndex::new(rocks, 2);

        // Axis 1: fresh index — both total and hot are empty.
        assert!(idx.is_empty());
        assert_eq!(idx.len(), 0);
        assert_eq!(idx.hot_size(), 0);

        // Axis 2: one insert flips is_empty false; len = 1.
        idx.insert("rec-a".to_string());
        assert!(!idx.is_empty());
        assert_eq!(idx.len(), 1);

        // Axis 3: duplicate-rid insert preserves len and is_empty.
        idx.insert("rec-a".to_string());
        assert!(!idx.is_empty());
        assert_eq!(idx.len(), 1);

        // Axis 4: post-eviction the hot set is at capacity (=2) but is_empty
        // stays false — the index is NOT empty even though `rec-a` was evicted.
        idx.insert("rec-b".to_string());
        idx.insert("rec-c".to_string()); // evicts rec-a from hot
        assert_eq!(idx.hot_size(), 2);
        assert!(!idx.hot.contains("rec-a"), "rec-a must be evicted from hot");
        assert!(idx.contains("rec-a"), "rec-a survives in cold tier");
        assert!(!idx.is_empty(), "is_empty must consult total_count, not hot");
        assert_eq!(idx.len(), 3);

        // Axis 5: batch insert of all-duplicates leaves is_empty/len untouched.
        let new_inserts = idx.insert_batch(&[
            "rec-a".to_string(),
            "rec-b".to_string(),
            "rec-c".to_string(),
        ]);
        assert_eq!(new_inserts, 0, "all rids were cold-tier dupes");
        assert!(!idx.is_empty());
        assert_eq!(idx.len(), 3);
    }

    /// Pin `hot_set_clone()` snapshot semantics. Used by the
    /// DAG cascade-eviction predicate: the caller takes a clone, releases
    /// the index, then passes it to `dag.evict_finalized()` under the DAG
    /// write lock. Any future edit that returns a reference instead of an
    /// owned clone (or that returns `Cow<HashSet>`) would silently couple
    /// the DAG write lock to the index read lock and re-introduce the
    /// prior hold-time regression.
    #[test]
    fn batch_b_hot_set_clone_snapshot_semantics() {
        let (rocks, _dir) = test_engine();
        let mut idx = FinalizedIndex::new(rocks, 3);

        // Axis 1: fresh index → clone is empty + len() == 0.
        let snap0 = idx.hot_set_clone();
        assert!(snap0.is_empty());
        assert_eq!(snap0.len(), idx.hot_size());

        // Axis 2: post-insert, clone len == hot_size, and is a subset
        // of the inserted rids (NOT all 5 inserted — only the resident 3).
        for i in 0..5 {
            idx.insert(format!("rec-{i}"));
        }
        let snap1 = idx.hot_set_clone();
        assert_eq!(snap1.len(), idx.hot_size());
        assert_eq!(snap1.len(), 3, "bounded by capacity");
        for rid in &snap1 {
            // Every snapshot member was inserted (snapshot ⊆ inserts).
            assert!(rid.starts_with("rec-"));
        }

        // Axis 3: cold-only records are NOT in the clone — the snapshot
        // is recent-only by design.
        assert!(idx.contains("rec-0"), "rec-0 lives in cold tier");
        // After 5 inserts at cap=3, rec-0..rec-1 are evicted from hot.
        let evicted_seen_in_snap = snap1.contains("rec-0") || snap1.contains("rec-1");
        assert!(
            !evicted_seen_in_snap,
            "evicted rids must not be in hot snapshot"
        );

        // Axis 4: mutating the returned clone does NOT mutate the index.
        let mut mutable_snap = idx.hot_set_clone();
        mutable_snap.clear();
        mutable_snap.insert("intruder".to_string());
        assert_eq!(idx.hot_size(), 3, "index unaffected by clone mutation");
        assert!(!idx.contains("intruder"), "intruder must not bleed into index");

        // Axis 5: subsequent snapshots are independent of prior ones —
        // a fresh call returns a new HashSet, not a shared handle.
        let snap_a = idx.hot_set_clone();
        let mut snap_b = idx.hot_set_clone();
        snap_b.insert("only-in-b".to_string());
        assert!(!snap_a.contains("only-in-b"), "snap_a must be unaffected");
    }

    /// Pin profile-capacity triplet to exact bytes + strict
    /// ordering + integer ratios. Defends the
    /// resident-budget assumptions per profile (~150 KB phone-tier /
    /// ~1.5 MB operator / ~150 MB mainnet archive). A silent re-tune
    /// of any of the three would change the operator alerting threshold
    /// for `hot_size/capacity ≈ 1.0` (LRU-pressure signal).
    /// Note: strict ordering also enforced at compile time via
    /// `const _: () = assert!(..)` at module scope.
    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_profile_capacity_triplet_exact_bytes_and_ratios() {
        // Axis 1: exact byte pins per profile.
        assert_eq!(LIGHT_PROFILE_CAPACITY, 1_000);
        assert_eq!(FULL_ZONE_PROFILE_CAPACITY, 10_000);
        assert_eq!(ARCHIVE_PROFILE_CAPACITY, 1_000_000);

        // Axis 2: strict ordering Light < FullZone < Archive (also
        // enforced compile-time, but a runtime echo guards against a
        // refactor that moves the consts to a non-static-asserted module).
        assert!(LIGHT_PROFILE_CAPACITY < FULL_ZONE_PROFILE_CAPACITY);
        assert!(FULL_ZONE_PROFILE_CAPACITY < ARCHIVE_PROFILE_CAPACITY);

        // Axis 3: integer-ratio invariants.
        assert_eq!(
            FULL_ZONE_PROFILE_CAPACITY / LIGHT_PROFILE_CAPACITY,
            10,
            "FullZone is 10× phone-tier"
        );
        assert_eq!(
            ARCHIVE_PROFILE_CAPACITY / FULL_ZONE_PROFILE_CAPACITY,
            100,
            "Archive is 100× operator default"
        );
        assert_eq!(
            ARCHIVE_PROFILE_CAPACITY / LIGHT_PROFILE_CAPACITY,
            1_000,
            "Archive is 1000× phone-tier"
        );

        // Axis 4: legacy DEFAULT_CAPACITY is bit-for-bit FullZone (so
        // existing fleets see zero post-upgrade drift).
        assert_eq!(DEFAULT_CAPACITY, FULL_ZONE_PROFILE_CAPACITY);

        // Axis 5: nonzero invariant — none of the three can be 0 (a 0
        // capacity would make `insert_hot` evict-then-insert on every
        // call and break the LRU invariant + freeze hot_size at 0).
        assert!(LIGHT_PROFILE_CAPACITY > 0);
        assert!(FULL_ZONE_PROFILE_CAPACITY > 0);
        assert!(ARCHIVE_PROFILE_CAPACITY > 0);
    }

    /// Pin counter monotonicity contract — counters are
    /// per-call, never deduped, and write-path (`insert`/`insert_batch`)
    /// never touches read-path (`contains`) counters. A future edit that
    /// e.g. coalesces back-to-back same-rid lookups, or that bumps a
    /// cold-lookup counter from inside `insert` for the cold-tier probe,
    /// would silently break the operator dashboard (hot-hit rate
    /// `hot_hits / (hot_hits + cold_lookups)` would no longer reflect
    /// real query mix).
    #[test]
    fn batch_b_ops61_counter_monotonicity_per_call_not_dedup() {
        let (rocks, _dir) = test_engine();
        let mut idx = FinalizedIndex::new(rocks, 100);
        idx.insert("rec-hot".to_string());

        // Axis 1: insert() must NOT touch any of the 3 read-path counters,
        // even though it performs a cold-tier probe internally. Write-path
        // and read-path counters are disjoint by design.
        assert_eq!(idx.hot_hits_total.load(Ordering::Relaxed), 0);
        assert_eq!(idx.cold_lookups_total.load(Ordering::Relaxed), 0);
        assert_eq!(idx.cold_hits_total.load(Ordering::Relaxed), 0);

        // Axis 2: 5 contains() calls of the same hot rid bump hot_hits to
        // exactly 5 — counters are per-call, NOT deduped.
        for _ in 0..5 {
            assert!(idx.contains("rec-hot"));
        }
        assert_eq!(idx.hot_hits_total.load(Ordering::Relaxed), 5);
        assert_eq!(idx.cold_lookups_total.load(Ordering::Relaxed), 0);
        assert_eq!(idx.cold_hits_total.load(Ordering::Relaxed), 0);

        // Axis 3: 5 contains() calls of the same cold-MISS rid bump
        // cold_lookups to exactly 5 — each call is a fresh CF_METADATA
        // probe (no negative-lookup cache).
        for _ in 0..5 {
            assert!(!idx.contains("never-finalized"));
        }
        assert_eq!(idx.hot_hits_total.load(Ordering::Relaxed), 5);
        assert_eq!(idx.cold_lookups_total.load(Ordering::Relaxed), 5);
        assert_eq!(idx.cold_hits_total.load(Ordering::Relaxed), 0);

        // Axis 4: insert_batch of a NEW rid must also leave read-path
        // counters untouched, even though insert_batch probes cold tier
        // for every rid. The dashboard query-mix signal depends
        // on `cold_lookups` reflecting `contains()` calls ONLY.
        let pre_lookups = idx.cold_lookups_total.load(Ordering::Relaxed);
        let pre_hits = idx.cold_hits_total.load(Ordering::Relaxed);
        idx.insert_batch(&["batch-rid-1".to_string(), "batch-rid-2".to_string()]);
        assert_eq!(idx.cold_lookups_total.load(Ordering::Relaxed), pre_lookups);
        assert_eq!(idx.cold_hits_total.load(Ordering::Relaxed), pre_hits);

        // Axis 5: counters are strictly monotonic across operations
        // (Relaxed AtomicU64, fetch_add only — never decrement).
        let final_hot = idx.hot_hits_total.load(Ordering::Relaxed);
        let final_lookups = idx.cold_lookups_total.load(Ordering::Relaxed);
        // Trigger one more hot hit + one more cold miss.
        assert!(idx.contains("rec-hot"));
        assert!(!idx.contains("still-never-finalized"));
        assert!(idx.hot_hits_total.load(Ordering::Relaxed) > final_hot);
        assert!(idx.cold_lookups_total.load(Ordering::Relaxed) > final_lookups);
    }
}
