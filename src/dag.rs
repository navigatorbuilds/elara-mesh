//! In-memory DAG index — fast graph traversal over record IDs.
//!
//! Stores only IDs and edges in memory, not full records.
//! Full records are fetched from the storage backend on demand.

//!
//! Spec references:
//!   @spec Protocol §3.3.3
//!   @spec Protocol §3.3.4

use std::collections::{HashMap, HashSet, VecDeque};

use crate::ZoneId;
use crate::errors::{ElaraError, Result};

/// Hard cap on hot tier. Only reached if epoch sealing stalls.
pub const HOT_MAX_FALLBACK: usize = 50_000;
/// Number of sealed epochs to keep in the hot tier.
pub const HOT_EPOCH_WINDOW: u64 = 3;

/// In-memory DAG index (hot tier) — holds unfinalized records + last N epochs.
/// Finalized records older than the epoch window are evicted from memory.
/// Full graph edges remain in RocksDB (cold tier) for historical queries.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DagIndex {
    /// parent_id -> set of child_ids
    children: HashMap<String, HashSet<String>>,
    /// child_id -> set of parent_ids
    parents: HashMap<String, HashSet<String>>,
    /// All known record IDs in the hot tier
    nodes: HashSet<String>,
    /// Record timestamps for ordering
    pub(crate) timestamps: HashMap<String, f64>,
    /// Orphan edges: parent_id (not yet indexed) -> child_ids waiting for it
    orphan_edges: HashMap<String, HashSet<String>>,
    /// Epoch number when each record was finalized (None = unfinalized)
    #[serde(default)]
    finalized_epoch: HashMap<String, u64>,
    /// Current epoch high-water mark (from latest seal)
    #[serde(default)]
    current_epoch: u64,
    /// Maintained index: records with no parents (genesis records)
    #[serde(default)]
    roots_idx: HashSet<String>,
    /// Maintained index: records with no children (frontier)
    #[serde(default)]
    tips_idx: HashSet<String>,
    /// DAM-3D Phase B: record_id → ZoneId mapping. Populated lazily by
    /// `insert_with_zone` / `insert_tolerant_with_zone` / `set_node_zone`.
    /// Records inserted via the legacy zone-agnostic insert paths have no
    /// entry here and are therefore absent from `tips_per_zone` until the
    /// caller registers them. Hot-tier-bounded; never grows past
    /// `HOT_MAX_FALLBACK = 50_000` regardless of how many zones exist
    /// across the wider mesh, so the storage cost stays O(hot_records),
    /// not O(global_zones).
    #[serde(default)]
    node_zone: HashMap<String, ZoneId>,
    /// DAM-3D Phase B: per-zone tip frontier shadow of `tips_idx`. Each
    /// entry mirrors the subset of `tips_idx` belonging to one zone, so
    /// `tips_for_zone(z)` is O(zone_tips) instead of O(global_tips). Only
    /// populated for records whose zone is known via `node_zone` — empty
    /// entries pruned eagerly to keep the map bounded by the number of
    /// distinct zones currently in the hot tier.
    #[serde(default)]
    tips_per_zone: HashMap<ZoneId, HashSet<String>>,
}

impl DagIndex {
    pub fn new() -> Self {
        Self {
            children: HashMap::new(),
            parents: HashMap::new(),
            nodes: HashSet::new(),
            timestamps: HashMap::new(),
            orphan_edges: HashMap::new(),
            finalized_epoch: HashMap::new(),
            current_epoch: 0,
            roots_idx: HashSet::new(),
            tips_idx: HashSet::new(),
            node_zone: HashMap::new(),
            tips_per_zone: HashMap::new(),
        }
    }

    /// DAM-3D Phase B: insert a tip into the per-zone shadow when the
    /// record's zone is known. No-op when the record has no recorded
    /// zone (legacy zone-agnostic insert path).
    fn tips_per_zone_insert(&mut self, id: &str) {
        if let Some(zone) = self.node_zone.get(id).cloned() {
            self.tips_per_zone
                .entry(zone)
                .or_default()
                .insert(id.to_string());
        }
    }

    /// DAM-3D Phase B: remove a tip from the per-zone shadow. Empties get
    /// pruned to keep `tips_per_zone` bounded by the number of distinct
    /// zones currently in the hot tier.
    fn tips_per_zone_remove(&mut self, id: &str) {
        let zone = match self.node_zone.get(id).cloned() {
            Some(z) => z,
            None => return,
        };
        if let Some(tips) = self.tips_per_zone.get_mut(&zone) {
            tips.remove(id);
            if tips.is_empty() {
                self.tips_per_zone.remove(&zone);
            }
        }
    }

    /// Rebuild roots/tips indices from the graph (for DAGs loaded from pre-v4 snapshots).
    pub fn rebuild_indices(&mut self) {
        self.roots_idx.clear();
        self.tips_idx.clear();
        // DAM-3D Phase B: rebuild the per-zone shadow alongside `tips_idx`
        // so the two indices never drift after a snapshot reload.
        self.tips_per_zone.clear();
        let ids: Vec<String> = self.nodes.iter().cloned().collect();
        for id in &ids {
            if self.parents.get(id).is_none_or(|p| p.is_empty()) {
                self.roots_idx.insert(id.clone());
            }
            if self.children.get(id).is_none_or(|c| c.is_empty()) {
                self.tips_idx.insert(id.clone());
                self.tips_per_zone_insert(id);
            }
        }
    }

    /// Mark a record as finalized in a given epoch.
    pub fn mark_finalized(&mut self, id: &str, epoch: u64) {
        if self.nodes.contains(id) {
            self.finalized_epoch.insert(id.to_string(), epoch);
        }
    }

    /// Whether a record is marked finalized in the hot tier. O(1).
    /// False for unknown ids — callers filtering candidates treat
    /// "not in hot tier" the same as "not finalized here".
    pub fn is_finalized(&self, id: &str) -> bool {
        self.finalized_epoch.contains_key(id)
    }

    /// Update the current epoch high-water mark.
    pub fn set_current_epoch(&mut self, epoch: u64) {
        if epoch > self.current_epoch {
            self.current_epoch = epoch;
        }
    }

    /// Get the current epoch high-water mark.
    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    /// Evict records finalized in epochs older than the window.
    /// Returns the number of evicted records.
    pub fn evict_old_epochs(&mut self) -> usize {
        if self.current_epoch <= HOT_EPOCH_WINDOW {
            return 0;
        }
        let cutoff = self.current_epoch - HOT_EPOCH_WINDOW;
        let to_evict: Vec<String> = self.finalized_epoch
            .iter()
            .filter(|(_, &epoch)| epoch < cutoff)
            .map(|(id, _)| id.clone())
            .collect();
        let count = to_evict.len();
        for id in to_evict {
            self.remove(&id);
            self.finalized_epoch.remove(&id);
        }
        count
    }

    /// Evict ALL records that are known to be finalized (via external predicate).
    /// Records finalized in the last `grace_epochs` epochs are kept.
    /// Returns the number of evicted records.
    ///
    /// This reconciles the DAG with the FinalizedIndex: records that are finalized
    /// but were never `mark_finalized()` (e.g. loaded from a pre-eviction snapshot)
    /// are discovered and evicted here.
    pub fn evict_finalized(&mut self, is_finalized: impl Fn(&str) -> bool) -> usize {
        // Grace period: keep records finalized in recent epochs
        let grace_cutoff = self.current_epoch.saturating_sub(HOT_EPOCH_WINDOW);

        // Find records to evict: finalized externally AND either
        // (a) not in finalized_epoch (never marked — legacy), or
        // (b) marked at an epoch below the grace cutoff
        let to_evict: Vec<String> = self.nodes.iter()
            .filter(|id| {
                if !is_finalized(id) {
                    return false;
                }
                match self.finalized_epoch.get(*id) {
                    Some(&epoch) => epoch < grace_cutoff,
                    None => true, // never marked — evict immediately
                }
            })
            .cloned()
            .collect();

        let count = to_evict.len();
        for id in &to_evict {
            self.remove(id);
            self.finalized_epoch.remove(id);
        }
        count
    }

    /// Evict records older than `max_age_secs` from the in-memory DAG.
    /// Records are NOT deleted — they remain in RocksDB for historical queries.
    /// This is the primary mechanism for keeping memory bounded.
    /// Only evicts records that have been finalized — unfinalized records must
    /// stay in DAG for witnessing and settlement even if their creation timestamp
    /// is old (e.g., records synced via full_pull from days ago).
    /// Returns evicted count.
    pub fn evict_older_than(&mut self, max_age_secs: f64) -> usize {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        let cutoff = now - max_age_secs;

        let to_evict: Vec<String> = self.nodes.iter()
            .filter(|id| {
                let old_enough = self.timestamps.get(*id).copied().unwrap_or(0.0) < cutoff;
                let is_finalized = self.finalized_epoch.contains_key(*id);
                old_enough && is_finalized
            })
            .cloned()
            .collect();

        let count = to_evict.len();
        for id in &to_evict {
            self.remove(id);
            self.finalized_epoch.remove(id);
        }
        count
    }

    /// Evict oldest records until DAG size is at or below `max_records`.
    /// Returns the number of evicted records.
    pub fn evict_to_cap(&mut self, max_records: usize) -> usize {
        if self.nodes.len() <= max_records {
            return 0;
        }
        let excess = self.nodes.len() - max_records;
        let mut by_time: Vec<(String, f64)> = self.timestamps.iter()
            .map(|(id, &ts)| (id.clone(), ts))
            .collect();
        by_time.sort_by(|a, b| a.1.total_cmp(&b.1));
        let mut evicted = 0;
        for (id, _) in by_time.into_iter().take(excess) {
            self.remove(&id);
            self.finalized_epoch.remove(&id);
            evicted += 1;
        }
        evicted
    }

    /// Number of records currently marked as finalized in the hot tier.
    pub fn finalized_count(&self) -> usize {
        self.finalized_epoch.len()
    }

    /// Add a record to the index.
    pub fn insert(&mut self, id: String, parent_ids: Vec<String>, timestamp: f64) -> Result<()> {
        if self.nodes.contains(&id) {
            return Err(ElaraError::DuplicateRecord(id));
        }

        // Check parents exist
        for pid in &parent_ids {
            if !self.nodes.contains(pid) {
                return Err(ElaraError::MissingParent(pid.clone()));
            }
        }

        // Add edges
        for pid in &parent_ids {
            self.children
                .entry(pid.clone())
                .or_default()
                .insert(id.clone());
            self.parents
                .entry(id.clone())
                .or_default()
                .insert(pid.clone());
            // Parent now has a child — remove from tips
            self.tips_idx.remove(pid);
            self.tips_per_zone_remove(pid);
        }

        self.nodes.insert(id.clone());
        self.timestamps.insert(id.clone(), timestamp);

        // New node: it's a tip (no children yet)
        self.tips_idx.insert(id.clone());
        self.tips_per_zone_insert(&id);
        // If no parents, it's a root
        if parent_ids.is_empty() {
            self.roots_idx.insert(id);
        }
        Ok(())
    }

    /// DAM-3D Phase B: insert a record AND register its zone in one
    /// atomic step so the per-zone tips shadow stays consistent. Use
    /// this from the ingest hot path; the legacy `insert` is preserved
    /// for callers that don't have a zone in scope (snapshot reload,
    /// host-arch tests).
    pub fn insert_with_zone(
        &mut self,
        id: String,
        parent_ids: Vec<String>,
        timestamp: f64,
        zone: ZoneId,
    ) -> Result<()> {
        // Pre-validate before mutating `node_zone` so a DuplicateRecord /
        // MissingParent error doesn't leave the per-zone map pointing at
        // a record that never joined the DAG.
        if self.nodes.contains(&id) {
            return Err(ElaraError::DuplicateRecord(id));
        }
        for pid in &parent_ids {
            if !self.nodes.contains(pid) {
                return Err(ElaraError::MissingParent(pid.clone()));
            }
        }
        // Register the zone BEFORE inserting so the tip-set update inside
        // `insert` sees the right zone for the per-zone shadow.
        self.node_zone.insert(id.clone(), zone);
        self.insert(id, parent_ids, timestamp)
    }

    /// DAM-3D Phase B: tolerant insert with zone registration. Mirrors
    /// `insert_with_zone` for the ingest hot path. Tolerant variant
    /// never returns Err (orphans are queued), so no rollback path is
    /// needed.
    pub fn insert_tolerant_with_zone(
        &mut self,
        id: String,
        parent_ids: Vec<String>,
        timestamp: f64,
        zone: ZoneId,
    ) -> usize {
        if self.nodes.contains(&id) {
            return 0; // already indexed; do not overwrite zone
        }
        self.node_zone.insert(id.clone(), zone);
        self.insert_tolerant(id, parent_ids, timestamp)
    }

    /// DAM-3D Phase B: register a zone for an already-inserted record
    /// (e.g. snapshot reload that ran through `insert` before zones were
    /// available). Idempotent: safe to call multiple times with the same
    /// (id, zone). If `id` is already in the tip frontier, the per-zone
    /// shadow is reconciled immediately so callers can backfill in any
    /// order.
    pub fn set_node_zone(&mut self, id: &str, zone: ZoneId) {
        if !self.nodes.contains(id) {
            return;
        }
        // Drop any previous tip-shadow entry under the old zone so we
        // never leak across re-zoning (registry overrides at runtime).
        self.tips_per_zone_remove(id);
        self.node_zone.insert(id.to_string(), zone);
        if self.tips_idx.contains(id) {
            self.tips_per_zone_insert(id);
        }
    }

    /// Insert a record tolerantly — if parents are missing, still add the node
    /// but track it as an orphan for later re-linking.
    /// Returns the number of missing parents (0 = fully linked).
    pub fn insert_tolerant(&mut self, id: String, parent_ids: Vec<String>, timestamp: f64) -> usize {
        if self.nodes.contains(&id) {
            return 0; // already indexed, skip
        }

        let mut missing = 0;
        for pid in &parent_ids {
            if self.nodes.contains(pid) {
                // Parent exists — wire the edge
                self.children.entry(pid.clone()).or_default().insert(id.clone());
                self.parents.entry(id.clone()).or_default().insert(pid.clone());
                // Parent now has a child — remove from tips
                self.tips_idx.remove(pid);
                self.tips_per_zone_remove(pid);
            } else {
                // Parent not yet indexed — record as orphan edge for later
                self.orphan_edges.entry(pid.clone()).or_default().insert(id.clone());
                missing += 1;
            }
        }

        self.nodes.insert(id.clone());
        self.timestamps.insert(id.clone(), timestamp);

        // New node: it's a tip (no children yet)
        self.tips_idx.insert(id.clone());
        self.tips_per_zone_insert(&id);
        // If no parents (or all parents are missing), it's a root for now
        if parent_ids.is_empty() || missing == parent_ids.len() {
            self.roots_idx.insert(id);
        }
        missing
    }

    /// Wire a structural edge to a parent that exists in storage but not in the
    /// in-memory DAG (evicted/finalized). This preserves mesh connectivity in
    /// `edge_count()` and prevents the child from being counted as a root, without
    /// requiring the parent to be tracked as a node. Removes the orphan edge since
    /// the parent is known to exist (no fetch needed).
    pub fn link_external_parent(&mut self, child_id: &str, parent_id: &str) {
        // Wire the edge in the parents map (child → parent)
        self.parents.entry(child_id.to_string()).or_default().insert(parent_id.to_string());
        // Child has at least one parent now — not a root
        self.roots_idx.remove(child_id);
        // Remove from orphan tracking — parent is known, no fetch needed
        if let Some(children) = self.orphan_edges.get_mut(parent_id) {
            children.remove(child_id);
            if children.is_empty() {
                self.orphan_edges.remove(parent_id);
            }
        }
    }

    /// Get the children waiting for a specific orphan parent.
    pub fn orphan_children_of(&self, parent_id: &str) -> Vec<String> {
        self.orphan_edges.get(parent_id).map(|s| s.iter().cloned().collect()).unwrap_or_default()
    }

    /// Re-link orphan edges for a single parent ID that just arrived.
    /// O(children_of_parent) instead of O(all_orphan_edges).
    /// Use this in the per-record insert path for efficiency.
    pub fn relink_single_parent(&mut self, parent_id: &str) -> usize {
        if let Some(children) = self.orphan_edges.remove(parent_id) {
            let mut linked = 0;
            for cid in children {
                if self.nodes.contains(&cid) {
                    self.children.entry(parent_id.to_string()).or_default().insert(cid.clone());
                    self.parents.entry(cid.clone()).or_default().insert(parent_id.to_string());
                    self.tips_idx.remove(parent_id);
                    self.tips_per_zone_remove(parent_id);
                    self.roots_idx.remove(&cid);
                    linked += 1;
                }
            }
            linked
        } else {
            0
        }
    }

    /// Try to re-link orphan edges whose parents have since been indexed.
    /// Returns the number of edges successfully linked.
    pub fn reindex_orphans(&mut self) -> usize {
        let mut linked = 0;
        let known_orphan_parents: Vec<String> = self.orphan_edges.keys()
            .filter(|pid| self.nodes.contains(pid.as_str()))
            .cloned()
            .collect();

        for pid in known_orphan_parents {
            if let Some(children) = self.orphan_edges.remove(&pid) {
                for cid in children {
                    if self.nodes.contains(&cid) {
                        self.children.entry(pid.clone()).or_default().insert(cid.clone());
                        self.parents.entry(cid.clone()).or_default().insert(pid.clone());
                        // Parent now has child — remove from tips
                        self.tips_idx.remove(&pid);
                        self.tips_per_zone_remove(&pid);
                        // Child now has parent — might no longer be a root
                        self.roots_idx.remove(&cid);
                        linked += 1;
                    }
                }
            }
        }
        linked
    }

    /// Number of orphan edges waiting to be linked.
    pub fn orphan_count(&self) -> usize {
        self.orphan_edges.values().map(|s| s.len()).sum()
    }

    /// Parent IDs that are referenced by orphan edges but not yet in the DAG.
    /// These are the records we need to fetch from peers.
    pub fn orphan_parent_ids(&self) -> Vec<String> {
        self.orphan_edges.keys()
            .filter(|pid| !self.nodes.contains(pid.as_str()))
            .cloned()
            .collect()
    }

    /// Number of distinct parent keys in orphan_edges (for diagnostics).
    pub fn orphan_parent_key_count(&self) -> usize {
        self.orphan_edges.len()
    }

    /// Count orphan edge parents that ARE in self.nodes (should be 0 after reindex).
    pub fn orphan_parents_in_nodes(&self) -> usize {
        self.orphan_edges.keys()
            .filter(|pid| self.nodes.contains(pid.as_str()))
            .count()
    }

    /// Remove all orphan edges for a specific parent ID.
    /// Returns the number of edges removed.
    pub fn remove_orphan_parent(&mut self, parent_id: &str) -> usize {
        if let Some(children) = self.orphan_edges.remove(parent_id) {
            children.len()
        } else {
            0
        }
    }

    /// Remove orphan edges older than `max_entries` total. Evicts largest
    /// parent groups first. Prevents unbounded memory growth when parents
    /// never arrive (e.g., from pruned/GC'd records).
    pub fn prune_orphan_edges(&mut self, max_entries: usize) -> usize {
        let current = self.orphan_count();
        if current <= max_entries {
            return 0;
        }
        // Sort parents by child count (descending) — evict biggest groups first
        let mut parents: Vec<(String, usize)> = self
            .orphan_edges
            .iter()
            .map(|(k, v)| (k.clone(), v.len()))
            .collect();
        parents.sort_by_key(|b| std::cmp::Reverse(b.1));

        let mut removed = 0;
        let target = current - max_entries;
        for (pid, count) in parents {
            if removed >= target {
                break;
            }
            self.orphan_edges.remove(&pid);
            removed += count;
        }
        removed
    }

    /// Number of tips (frontier size). O(1).
    pub fn tip_count(&self) -> usize {
        self.tips_idx.len()
    }

    /// Records with no children (frontier). O(k log k) where k = tip count.
    pub fn tips(&self) -> Vec<String> {
        let mut tips: Vec<_> = self.tips_idx.iter().cloned().collect();
        tips.sort_by(|a, b| {
            let ta = self.timestamps.get(a).copied().unwrap_or(0.0);
            let tb = self.timestamps.get(b).copied().unwrap_or(0.0);
            tb.total_cmp(&ta)
        });
        tips
    }

    /// DAM-3D Phase B: tips restricted to a single zone (newest first).
    /// O(k log k) where k = number of tips in the zone — never scans the
    /// global tips frontier. Returns an empty vec if the zone has no
    /// tips in the hot tier.
    pub fn tips_for_zone(&self, zone: &ZoneId) -> Vec<String> {
        let mut tips: Vec<String> = match self.tips_per_zone.get(zone) {
            Some(set) => set.iter().cloned().collect(),
            None => return Vec::new(),
        };
        tips.sort_by(|a, b| {
            let ta = self.timestamps.get(a).copied().unwrap_or(0.0);
            let tb = self.timestamps.get(b).copied().unwrap_or(0.0);
            tb.total_cmp(&ta)
        });
        tips
    }

    /// DAM-3D Phase B: count of tips for a given zone. O(1).
    pub fn tip_count_for_zone(&self, zone: &ZoneId) -> usize {
        self.tips_per_zone.get(zone).map(|s| s.len()).unwrap_or(0)
    }

    /// DAM-3D Phase B: number of distinct zones currently represented in
    /// the per-zone tip frontier. Bounded by hot-tier size, NOT by global
    /// zone count (cold zones with no hot tips contribute nothing).
    pub fn zones_with_tips(&self) -> usize {
        self.tips_per_zone.len()
    }

    /// DAM-3D Phase B: read-only snapshot of (zone, tip-count) pairs for
    /// metrics emission. Caller decides labelling.
    pub fn tips_per_zone_iter(&self) -> impl Iterator<Item = (&ZoneId, usize)> + '_ {
        self.tips_per_zone.iter().map(|(z, s)| (z, s.len()))
    }

    /// Records with no parents (genesis). O(k log k) where k = root count.
    pub fn roots(&self) -> Vec<String> {
        let mut roots: Vec<_> = self.roots_idx.iter().cloned().collect();
        roots.sort_by(|a, b| {
            let ta = self.timestamps.get(a).copied().unwrap_or(0.0);
            let tb = self.timestamps.get(b).copied().unwrap_or(0.0);
            ta.total_cmp(&tb)
        });
        roots
    }

    /// Latest timestamp across all indexed records. Returns 0.0 if empty.
    /// Used for incremental DAG patch on stale-snapshot restart.
    pub fn latest_timestamp(&self) -> f64 {
        self.timestamps.values().cloned().fold(0.0f64, f64::max)
    }

    /// Direct parents of a record.
    pub fn parents(&self, id: &str) -> Vec<String> {
        self.parents
            .get(id)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Direct children of a record.
    pub fn children(&self, id: &str) -> Vec<String> {
        self.children
            .get(id)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// All ancestor IDs (transitive parents), BFS with depth limit.
    pub fn ancestors(&self, id: &str, max_depth: usize) -> HashSet<String> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back((id.to_string(), 0usize));

        while let Some((current, depth)) = queue.pop_front() {
            if depth >= max_depth {
                continue;
            }
            if let Some(parent_set) = self.parents.get(&current) {
                for pid in parent_set {
                    if visited.insert(pid.clone()) {
                        queue.push_back((pid.clone(), depth + 1));
                    }
                }
            }
        }

        visited
    }

    /// All descendant IDs (transitive children), BFS with depth limit.
    pub fn descendants(&self, id: &str, max_depth: usize) -> HashSet<String> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back((id.to_string(), 0usize));

        while let Some((current, depth)) = queue.pop_front() {
            if depth >= max_depth {
                continue;
            }
            if let Some(child_set) = self.children.get(&current) {
                for cid in child_set {
                    if visited.insert(cid.clone()) {
                        queue.push_back((cid.clone(), depth + 1));
                    }
                }
            }
        }

        visited
    }

    /// Bounded ancestor walk for public / diagnostic endpoints.
    ///
    /// Identical traversal to [`ancestors`](Self::ancestors) but with a SECOND
    /// cap on the number of visited nodes. Returns `(visited, truncated)`:
    /// `truncated == true` means `max_nodes` was reached before the walk
    /// completed, so `visited` is a bounded prefix of the true ancestor set.
    ///
    /// The unbounded [`ancestors`](Self::ancestors) stays for consensus callers
    /// (e.g. `operations.rs`) that need the complete set. This variant exists so
    /// a small unauthenticated request cannot make a public node clone
    /// O(hot-tier) record-id strings into a `HashSet` while holding the DAG read
    /// lock — at mainnet hot-tier sizes a depth-only cap is not a bound, since a
    /// wide mesh reaches most of the tier within `max_depth` hops.
    pub fn ancestors_capped(
        &self,
        id: &str,
        max_depth: usize,
        max_nodes: usize,
    ) -> (HashSet<String>, bool) {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back((id.to_string(), 0usize));

        while let Some((current, depth)) = queue.pop_front() {
            if depth >= max_depth {
                continue;
            }
            if let Some(parent_set) = self.parents.get(&current) {
                for pid in parent_set {
                    if visited.len() >= max_nodes {
                        return (visited, true);
                    }
                    if visited.insert(pid.clone()) {
                        queue.push_back((pid.clone(), depth + 1));
                    }
                }
            }
        }

        (visited, false)
    }

    /// Bounded descendant walk for public / diagnostic endpoints. See
    /// [`ancestors_capped`](Self::ancestors_capped) for the rationale; this is
    /// the children-direction twin.
    pub fn descendants_capped(
        &self,
        id: &str,
        max_depth: usize,
        max_nodes: usize,
    ) -> (HashSet<String>, bool) {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back((id.to_string(), 0usize));

        while let Some((current, depth)) = queue.pop_front() {
            if depth >= max_depth {
                continue;
            }
            if let Some(child_set) = self.children.get(&current) {
                for cid in child_set {
                    if visited.len() >= max_nodes {
                        return (visited, true);
                    }
                    if visited.insert(cid.clone()) {
                        queue.push_back((cid.clone(), depth + 1));
                    }
                }
            }
        }

        (visited, false)
    }

    /// Check if a record exists in the index.
    /// Iterator over all record IDs in the DAG.
    /// Returns references to avoid cloning all IDs upfront.
    pub fn record_ids(&self) -> impl Iterator<Item = &String> {
        self.nodes.iter()
    }

    pub fn contains(&self, id: &str) -> bool {
        self.nodes.contains(id)
    }

    /// Total number of records.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Check if the DAG hot tier has reached its fallback cap.
    /// Callers should try evict_old_epochs() first before rejecting records.
    pub fn is_full(&self) -> bool {
        self.nodes.len() >= HOT_MAX_FALLBACK
    }

    /// Total number of edges.
    pub fn edge_count(&self) -> usize {
        self.parents.values().map(|s| s.len()).sum()
    }

    /// Remove a record from the DAG index. Cleans up all parent/child edges.
    pub fn remove(&mut self, id: &str) {
        // Always clean up orphan edges referencing this ID as a parent,
        // even if it was never in nodes (orphan edge keys are specifically
        // IDs NOT in the node set). Prevents unbounded orphan edge
        // accumulation when eviction removes records that children reference.
        self.orphan_edges.remove(id);

        if !self.nodes.remove(id) {
            return;
        }
        self.timestamps.remove(id);
        self.roots_idx.remove(id);
        self.tips_idx.remove(id);
        self.tips_per_zone_remove(id);
        // Drop the zone registration AFTER pruning the per-zone shadow so
        // the shadow lookup still resolves to the right zone.
        self.node_zone.remove(id);

        // Remove from parent→child edges
        if let Some(parent_ids) = self.parents.remove(id) {
            for pid in &parent_ids {
                if let Some(children) = self.children.get_mut(pid) {
                    children.remove(id);
                    // If parent now has no children, it becomes a tip again
                    if children.is_empty() && self.nodes.contains(pid) {
                        self.tips_idx.insert(pid.clone());
                        self.tips_per_zone_insert(pid);
                    }
                }
            }
        }

        // Remove from child→parent edges
        if let Some(child_ids) = self.children.remove(id) {
            for cid in &child_ids {
                if let Some(parents) = self.parents.get_mut(cid) {
                    parents.remove(id);
                    // If child now has no parents, it becomes a root
                    if parents.is_empty() && self.nodes.contains(cid) {
                        self.roots_idx.insert(cid.clone());
                    }
                }
            }
        }
    }
}

impl Default for DagIndex {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_dag() {
        let dag = DagIndex::new();
        assert!(dag.is_empty());
        assert_eq!(dag.len(), 0);
        assert_eq!(dag.edge_count(), 0);
        assert!(dag.tips().is_empty());
        assert!(dag.roots().is_empty());
    }

    #[test]
    fn test_is_finalized_hot_tier_semantics() {
        let mut dag = DagIndex::new();
        // Unknown id: false (auto-witness phase 2b treats "not in hot tier"
        // as "not finalized here" and lets downstream filters decide).
        assert!(!dag.is_finalized("ghost"));

        dag.insert("root_a".to_string(), vec![], 1.0).unwrap();
        assert!(!dag.is_finalized("root_a"));

        // mark_finalized on an id not in the hot tier is a no-op.
        dag.mark_finalized("ghost", 5);
        assert!(!dag.is_finalized("ghost"));

        dag.mark_finalized("root_a", 5);
        assert!(dag.is_finalized("root_a"));

        // Phase 2b candidate filter: finalized roots drop out of the sweep.
        dag.insert("root_b".to_string(), vec![], 2.0).unwrap();
        let unfinalized: Vec<String> = dag
            .roots()
            .into_iter()
            .filter(|r| !dag.is_finalized(r))
            .collect();
        assert_eq!(unfinalized, vec!["root_b".to_string()]);
    }

    #[test]
    fn test_single_root() {
        let mut dag = DagIndex::new();
        dag.insert("r1".into(), vec![], 1.0).unwrap();
        assert_eq!(dag.len(), 1);
        assert_eq!(dag.roots(), vec!["r1"]);
        assert_eq!(dag.tips(), vec!["r1"]);
    }

    #[test]
    fn test_chain() {
        let mut dag = DagIndex::new();
        dag.insert("r1".into(), vec![], 1.0).unwrap();
        dag.insert("r2".into(), vec!["r1".into()], 2.0).unwrap();
        dag.insert("r3".into(), vec!["r2".into()], 3.0).unwrap();

        assert_eq!(dag.roots(), vec!["r1"]);
        assert_eq!(dag.tips(), vec!["r3"]);
        assert_eq!(dag.edge_count(), 2);
        assert_eq!(dag.parents("r3"), vec!["r2"]);
        assert_eq!(dag.children("r1"), vec!["r2"]);
    }

    #[test]
    fn test_branch_and_merge() {
        let mut dag = DagIndex::new();
        dag.insert("root".into(), vec![], 1.0).unwrap();
        dag.insert("left".into(), vec!["root".into()], 2.0).unwrap();
        dag.insert("right".into(), vec!["root".into()], 2.5).unwrap();
        dag.insert("merge".into(), vec!["left".into(), "right".into()], 3.0)
            .unwrap();

        assert_eq!(dag.roots(), vec!["root"]);
        assert_eq!(dag.tips(), vec!["merge"]);
        assert_eq!(dag.edge_count(), 4); // root->left, root->right, left->merge, right->merge

        let merge_parents: HashSet<String> = dag.parents("merge").into_iter().collect();
        assert!(merge_parents.contains("left"));
        assert!(merge_parents.contains("right"));
    }

    #[test]
    fn test_ancestors() {
        let mut dag = DagIndex::new();
        for i in 0..10 {
            let id = format!("r{i}");
            let parents = if i == 0 { vec![] } else { vec![format!("r{}", i - 1)] };
            dag.insert(id, parents, i as f64).unwrap();
        }

        let ancestors = dag.ancestors("r9", 100);
        assert_eq!(ancestors.len(), 9);
        assert!(ancestors.contains("r0"));
        assert!(ancestors.contains("r8"));
        assert!(!ancestors.contains("r9"));
    }

    #[test]
    fn test_ancestors_depth_limit() {
        let mut dag = DagIndex::new();
        for i in 0..10 {
            let id = format!("r{i}");
            let parents = if i == 0 { vec![] } else { vec![format!("r{}", i - 1)] };
            dag.insert(id, parents, i as f64).unwrap();
        }

        let ancestors = dag.ancestors("r9", 3);
        assert_eq!(ancestors.len(), 3); // r8, r7, r6
    }

    #[test]
    fn test_descendants() {
        let mut dag = DagIndex::new();
        dag.insert("a".into(), vec![], 1.0).unwrap();
        dag.insert("b".into(), vec!["a".into()], 2.0).unwrap();
        dag.insert("c".into(), vec!["b".into()], 3.0).unwrap();

        let desc = dag.descendants("a", 100);
        assert_eq!(desc.len(), 2);
        assert!(desc.contains("b"));
        assert!(desc.contains("c"));
    }

    #[test]
    fn ancestors_capped_truncates_at_node_cap() {
        // 10-node chain r0<-..<-r9; r9 has 9 ancestors.
        let mut dag = DagIndex::new();
        for i in 0..10 {
            let id = format!("r{i}");
            let parents = if i == 0 { vec![] } else { vec![format!("r{}", i - 1)] };
            dag.insert(id, parents, i as f64).unwrap();
        }

        // Node cap below the true ancestor count → bounded prefix + truncated.
        let (anc, truncated) = dag.ancestors_capped("r9", 100, 3);
        assert!(truncated, "hitting the node cap MUST set truncated=true");
        assert_eq!(anc.len(), 3, "visited set MUST be bounded to max_nodes");
        assert!(!anc.contains("r9"), "start node is never in its own ancestor set");

        // Cap above the true count → complete walk, not truncated, and
        // byte-for-byte the same set the unbounded walk returns.
        let (anc_full, truncated_full) = dag.ancestors_capped("r9", 100, 10_000);
        assert!(!truncated_full);
        assert_eq!(anc_full, dag.ancestors("r9", 100));
        assert_eq!(anc_full.len(), 9);
    }

    #[test]
    fn descendants_capped_truncates_at_node_cap() {
        let mut dag = DagIndex::new();
        dag.insert("a".into(), vec![], 1.0).unwrap();
        dag.insert("b".into(), vec!["a".into()], 2.0).unwrap();
        dag.insert("c".into(), vec!["b".into()], 3.0).unwrap();

        let (desc, truncated) = dag.descendants_capped("a", 100, 1);
        assert!(truncated);
        assert_eq!(desc.len(), 1);

        let (desc_full, truncated_full) = dag.descendants_capped("a", 100, 10_000);
        assert!(!truncated_full);
        assert_eq!(desc_full, dag.descendants("a", 100));
        assert_eq!(desc_full.len(), 2);
    }

    #[test]
    fn test_duplicate_rejected() {
        let mut dag = DagIndex::new();
        dag.insert("r1".into(), vec![], 1.0).unwrap();
        assert!(dag.insert("r1".into(), vec![], 2.0).is_err());
    }

    #[test]
    fn test_missing_parent() {
        let mut dag = DagIndex::new();
        assert!(dag.insert("r1".into(), vec!["nonexistent".into()], 1.0).is_err());
    }

    #[test]
    fn test_large_dag() {
        let mut dag = DagIndex::new();
        // Build a 10K node chain
        for i in 0..10_000 {
            let id = format!("n{i:05}");
            let parents = if i == 0 { vec![] } else { vec![format!("n{:05}", i - 1)] };
            dag.insert(id, parents, i as f64).unwrap();
        }
        assert_eq!(dag.len(), 10_000);
        assert_eq!(dag.edge_count(), 9_999);
        assert!(!dag.is_full()); // 10K < 100K limit
    }

    // ─── DAG edges referencing tips ─────────────────────

    #[test]
    fn test_new_record_references_all_tips() {
        let mut dag = DagIndex::new();
        dag.insert("genesis".into(), vec![], 1.0).unwrap();
        dag.insert("a".into(), vec!["genesis".into()], 2.0).unwrap();
        dag.insert("b".into(), vec!["genesis".into()], 3.0).unwrap();

        // a and b are current tips (no children)
        let tips: HashSet<String> = dag.tips().into_iter().collect();
        assert!(tips.contains("a") && tips.contains("b"));
        assert!(!tips.contains("genesis"));

        // New record references both tips — merges the frontier
        let tip_vec: Vec<String> = tips.into_iter().collect();
        dag.insert("merge".into(), tip_vec, 4.0).unwrap();

        assert_eq!(dag.tips(), vec!["merge"]);
        assert_eq!(dag.edge_count(), 4); // genesis→a, genesis→b, a→merge, b→merge
    }

    #[test]
    fn test_tips_update_after_sequential_appends() {
        let mut dag = DagIndex::new();
        dag.insert("r0".into(), vec![], 1.0).unwrap();
        assert_eq!(dag.tips(), vec!["r0"]);

        // Each append should advance the tip
        for i in 1..=5u32 {
            let prev = format!("r{}", i - 1);
            let curr = format!("r{i}");
            dag.insert(curr.clone(), vec![prev], i as f64 + 1.0).unwrap();
            assert_eq!(dag.tips(), vec![curr]);
        }
        assert_eq!(dag.edge_count(), 5);
    }

    #[test]
    fn test_insert_tolerant_out_of_order() {
        let mut dag = DagIndex::new();
        // Insert child BEFORE parent — out-of-order arrival
        let missing = dag.insert_tolerant("child".into(), vec!["parent".into()], 2.0);
        assert_eq!(missing, 1);
        assert!(dag.contains("child"));
        assert!(!dag.contains("parent"));
        assert_eq!(dag.orphan_count(), 1);
        // No edge wired yet
        assert_eq!(dag.edge_count(), 0);

        // Now insert the parent
        let missing = dag.insert_tolerant("parent".into(), vec![], 1.0);
        assert_eq!(missing, 0);

        // Reindex orphans — should wire parent→child edge
        let linked = dag.reindex_orphans();
        assert_eq!(linked, 1);
        assert_eq!(dag.orphan_count(), 0);
        assert_eq!(dag.edge_count(), 1);
        assert_eq!(dag.children("parent"), vec!["child"]);
        assert_eq!(dag.parents("child"), vec!["parent"]);
    }

    #[test]
    fn test_insert_tolerant_chain_reverse() {
        let mut dag = DagIndex::new();
        // Insert chain in reverse: r3 → r2 → r1 → r0
        dag.insert_tolerant("r3".into(), vec!["r2".into()], 4.0);
        dag.insert_tolerant("r2".into(), vec!["r1".into()], 3.0);
        dag.insert_tolerant("r1".into(), vec!["r0".into()], 2.0);
        dag.insert_tolerant("r0".into(), vec![], 1.0);

        assert_eq!(dag.len(), 4);
        assert_eq!(dag.orphan_count(), 3); // r3→r2, r2→r1, r1→r0

        let linked = dag.reindex_orphans();
        assert_eq!(linked, 3);
        assert_eq!(dag.orphan_count(), 0);
        assert_eq!(dag.edge_count(), 3);
        assert_eq!(dag.roots(), vec!["r0"]);
        assert_eq!(dag.tips(), vec!["r3"]);
    }

    #[test]
    fn test_orphan_parent_ids() {
        let mut dag = DagIndex::new();
        // Insert children before parents
        dag.insert_tolerant("c1".into(), vec!["p1".into(), "p2".into()], 3.0);
        dag.insert_tolerant("c2".into(), vec!["p2".into(), "p3".into()], 4.0);

        let mut ids = dag.orphan_parent_ids();
        ids.sort();
        assert_eq!(ids, vec!["p1", "p2", "p3"]);

        // Insert p2 — it should no longer be in orphan_parent_ids after reindex
        dag.insert_tolerant("p2".into(), vec![], 1.0);
        dag.reindex_orphans();

        let mut ids = dag.orphan_parent_ids();
        ids.sort();
        assert_eq!(ids, vec!["p1", "p3"]); // p2 resolved
    }

    #[test]
    fn test_is_full() {
        let mut dag = DagIndex::new();
        assert!(!dag.is_full());

        // Manually insert nodes to simulate near-capacity
        for i in 0..HOT_MAX_FALLBACK {
            let id = format!("n{i}");
            dag.nodes.insert(id);
        }
        assert!(dag.is_full());
    }

    /// Memory ceiling test: insert 100K records across 100 epochs,
    /// finalize and evict as we go. Proves hot tier stays bounded
    /// even as total record count grows.
    #[test]
    fn test_memory_ceiling_100k_with_eviction() {
        let mut dag = DagIndex::new();
        let records_per_epoch = 1_000;
        let total_epochs = 100u64;
        let mut prev_id = String::new();

        for epoch in 0..total_epochs {
            // Insert records for this epoch
            for i in 0..records_per_epoch {
                let id = format!("e{epoch:03}_r{i:04}");
                let parents = if prev_id.is_empty() {
                    vec![]
                } else {
                    vec![prev_id.clone()]
                };
                dag.insert(id.clone(), parents, (epoch * records_per_epoch + i) as f64).unwrap();
                prev_id = id;
            }

            // Finalize all records in this epoch
            for i in 0..records_per_epoch {
                let id = format!("e{epoch:03}_r{i:04}");
                dag.mark_finalized(&id, epoch);
            }

            // Advance epoch and evict old records
            dag.set_current_epoch(epoch);
            dag.evict_old_epochs();
        }

        // Total inserted: 100K records
        // But hot tier should only hold ~HOT_EPOCH_WINDOW epochs worth
        // (3 epochs × 1000 records = ~3000, plus some overhead)
        let hot_size = dag.len();
        let max_expected = (HOT_EPOCH_WINDOW as usize + 2) * records_per_epoch as usize;

        assert!(
            hot_size <= max_expected,
            "hot tier should be bounded: got {hot_size} records, expected <= {max_expected} \
             (100K total inserted, {HOT_EPOCH_WINDOW} epoch window × {records_per_epoch}/epoch)"
        );

        // Verify it's roughly the right size (3 epochs ≈ 3000 records)
        assert!(
            hot_size >= records_per_epoch as usize,
            "hot tier should have at least 1 epoch: got {hot_size}"
        );

        // Memory estimate: each record ID ~15 bytes + HashMap overhead ~80 bytes
        // 3000 records × 7 HashMaps × ~95 bytes ≈ 2MB. Well within bounds.
        let estimated_bytes = hot_size * 7 * 95;
        assert!(
            estimated_bytes < 50 * 1024 * 1024, // 50MB ceiling
            "estimated hot tier memory {estimated_bytes} bytes exceeds 50MB ceiling"
        );
    }

    /// Test evict_finalized: records matching predicate are removed from DAG.
    #[test]
    fn test_evict_finalized_removes_matching_records() {
        let mut dag = DagIndex::new();

        let mut prev = String::new();
        for i in 0..100 {
            let id = format!("r{i:03}");
            let parents = if prev.is_empty() { vec![] } else { vec![prev.clone()] };
            dag.insert(id.clone(), parents, i as f64).unwrap();
            prev = id;
        }
        assert_eq!(dag.len(), 100);
        dag.set_current_epoch(50);

        let finalized_set: HashSet<String> = (0..80).map(|i| format!("r{i:03}")).collect();
        let evicted = dag.evict_finalized(|id| finalized_set.contains(id));

        assert_eq!(evicted, 80);
        assert_eq!(dag.len(), 20);
        assert!(dag.contains("r080"));
        assert!(!dag.contains("r000"));
    }

    /// Test evict_older_than: records with old timestamps are evicted.
    #[test]
    fn test_evict_older_than() {
        let mut dag = DagIndex::new();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();

        // Insert records: some old, some recent
        for i in 0..50 {
            let id = format!("old_{i}");
            dag.insert(id.clone(), vec![], now - 10000.0 + i as f64).unwrap(); // ~2.7 hours ago
            dag.mark_finalized(&id, 1); // finalized so age-based eviction applies
        }
        for i in 0..50 {
            let id = format!("new_{i}");
            let parents = if i == 0 { vec!["old_49".into()] } else { vec![format!("new_{}", i - 1)] };
            dag.insert(id, parents, now - 100.0 + i as f64).unwrap(); // ~100 seconds ago
        }
        assert_eq!(dag.len(), 100);

        let evicted = dag.evict_older_than(3600.0); // 1 hour
        assert_eq!(evicted, 50); // all old records evicted
        assert_eq!(dag.len(), 50); // only new records remain
        assert!(dag.contains("new_0"));
        assert!(!dag.contains("old_0"));
    }

    /// Test that evict_older_than stabilizes DAG size regardless of total history.
    #[test]
    fn test_evict_older_than_stabilizes_dag_size() {
        let mut dag = DagIndex::new();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();

        // Insert 5000 records spanning 10 hours
        let mut prev = String::new();
        for i in 0..5000 {
            let id = format!("r{i:05}");
            let parents = if prev.is_empty() { vec![] } else { vec![prev.clone()] };
            let ts = now - 36000.0 + (i as f64 * 7.2); // spread across 10 hours
            dag.insert(id.clone(), parents, ts).unwrap();
            dag.mark_finalized(&id, 1); // finalized so age-based eviction applies
            prev = id;
        }
        assert_eq!(dag.len(), 5000);

        // Evict records older than 2 hours
        let evicted = dag.evict_older_than(7200.0);
        assert!(evicted > 4000, "should evict most old records: evicted {evicted}");

        // Remaining should be only records from last 2 hours
        let remaining = dag.len();
        assert!(
            remaining < 1500,
            "DAG should be bounded: got {remaining} records after eviction"
        );
    }

    #[test]
    fn test_remove_cleans_orphan_edges() {
        let mut dag = DagIndex::new();
        dag.insert("root".into(), vec![], 1.0).unwrap();
        // r2 references root + "missing_parent" (not in DAG → orphan edge)
        let missing = dag.insert_tolerant("r2".into(), vec!["root".into(), "missing_parent".into()], 2.0);
        assert_eq!(missing, 1, "should have 1 missing parent");
        assert_eq!(dag.orphan_count(), 1, "should have 1 orphan edge for missing_parent");

        // Evict missing_parent reference by removing it (simulates eviction cleanup)
        // Even though missing_parent was never inserted as a node, orphan_edges
        // stores it as a key. remove() should clean it up.
        dag.remove("missing_parent");
        assert_eq!(dag.orphan_count(), 0, "orphan edges should be cleaned on remove");
    }

    #[test]
    fn test_eviction_cleans_orphan_edges() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();

        let mut dag = DagIndex::new();
        // Old parent record (will be evicted — must be finalized for age eviction)
        dag.insert("old_parent".into(), vec![], now - 7200.0).unwrap();
        dag.mark_finalized("old_parent", 1);
        // Recent child references old_parent + "ghost" (never arrives)
        let missing = dag.insert_tolerant("child".into(), vec!["old_parent".into(), "ghost".into()], now);
        assert_eq!(missing, 1, "ghost is missing");
        assert_eq!(dag.orphan_count(), 1, "orphan edge for ghost");

        // Evict old records (>1 hour)
        let evicted = dag.evict_older_than(3600.0);
        assert_eq!(evicted, 1, "old_parent should be evicted");
        // child remains (recent), but ghost orphan edge should be preserved
        // (ghost was never a node, so remove() doesn't touch it — that's correct,
        //  ghost might still arrive from a peer)
        assert!(dag.contains("child"));
        assert!(!dag.contains("old_parent"));
    }

    // ─── DAM-3D Phase B: per-zone tips index ─────────────────────────

    /// Helper: build ZoneId from a slash-joined path for terse test code.
    fn z(path: &[&str]) -> ZoneId {
        // `.as_str()` (not `&...`) is load-bearing: under `node`/`node-core`
        // ZoneId::new takes `&str` (the borrow is required), while the default
        // mobile stub takes `impl AsRef<str>` (where `&String` is a needless
        // borrow). An explicit &str satisfies both without a clippy allow.
        ZoneId::new(path.join("/").as_str())
    }

    #[test]
    fn dam3d_b_tips_per_zone_empty_when_no_zones() {
        let mut dag = DagIndex::new();
        dag.insert("legacy".into(), vec![], 1.0).unwrap();
        // legacy insert leaves node_zone empty → per-zone shadow is empty
        assert_eq!(dag.zones_with_tips(), 0);
        assert_eq!(dag.tip_count_for_zone(&z(&["medical"])), 0);
        // Global tips still works.
        assert_eq!(dag.tips(), vec!["legacy"]);
    }

    #[test]
    fn dam3d_b_insert_with_zone_populates_shadow() {
        let mut dag = DagIndex::new();
        let med = z(&["medical"]);
        dag.insert_with_zone("r1".into(), vec![], 1.0, med.clone()).unwrap();
        assert_eq!(dag.tip_count_for_zone(&med), 1);
        assert_eq!(dag.zones_with_tips(), 1);
        assert_eq!(dag.tips_for_zone(&med), vec!["r1"]);
    }

    #[test]
    fn dam3d_b_chain_advances_tip_zone() {
        let mut dag = DagIndex::new();
        let med = z(&["medical"]);
        dag.insert_with_zone("r1".into(), vec![], 1.0, med.clone()).unwrap();
        dag.insert_with_zone("r2".into(), vec!["r1".into()], 2.0, med.clone()).unwrap();
        // r1 is no longer a tip — only r2 remains.
        assert_eq!(dag.tip_count_for_zone(&med), 1);
        assert_eq!(dag.tips_for_zone(&med), vec!["r2"]);
    }

    #[test]
    fn dam3d_b_per_zone_tips_sum_to_global() {
        // 100-record DAG split across 4 zones; per-zone sum == global tips.
        let mut dag = DagIndex::new();
        let zones = [
            z(&["medical", "eu"]),
            z(&["medical", "us"]),
            z(&["finance"]),
            z(&["energy"]),
        ];
        // 25 isolated roots per zone — each is its own tip.
        for (zi, zone) in zones.iter().enumerate() {
            for j in 0..25 {
                let id = format!("z{zi}_r{j:02}");
                dag.insert_with_zone(id, vec![], (zi as f64) * 100.0 + j as f64, zone.clone()).unwrap();
            }
        }

        let global_tips = dag.tip_count();
        let per_zone_total: usize = zones.iter().map(|z| dag.tip_count_for_zone(z)).sum();
        assert_eq!(global_tips, 100);
        assert_eq!(per_zone_total, global_tips, "per-zone tips must sum to global tips");
        assert_eq!(dag.zones_with_tips(), 4);
    }

    #[test]
    fn dam3d_b_remove_updates_both_indices() {
        let mut dag = DagIndex::new();
        let med = z(&["medical"]);
        dag.insert_with_zone("r1".into(), vec![], 1.0, med.clone()).unwrap();
        dag.insert_with_zone("r2".into(), vec!["r1".into()], 2.0, med.clone()).unwrap();
        // r2 is the tip. Remove it: r1 regains tip status in BOTH indices.
        dag.remove("r2");
        assert_eq!(dag.tips(), vec!["r1"]);
        assert_eq!(dag.tips_for_zone(&med), vec!["r1"]);
        assert_eq!(dag.tip_count_for_zone(&med), 1);
        // Remove the remaining record: shadow goes empty + zone is pruned.
        dag.remove("r1");
        assert_eq!(dag.zones_with_tips(), 0, "empty zones must be pruned");
        assert_eq!(dag.tip_count_for_zone(&med), 0);
    }

    #[test]
    fn dam3d_b_set_node_zone_backfills_shadow() {
        let mut dag = DagIndex::new();
        let fin = z(&["finance"]);
        // Legacy insert (snapshot reload simulation): no zone registered.
        dag.insert("r1".into(), vec![], 1.0).unwrap();
        assert_eq!(dag.zones_with_tips(), 0);
        // Backfill the zone — r1 is still a tip → shadow updates.
        dag.set_node_zone("r1", fin.clone());
        assert_eq!(dag.tip_count_for_zone(&fin), 1);
        assert_eq!(dag.tips_for_zone(&fin), vec!["r1"]);
    }

    #[test]
    fn dam3d_b_set_node_zone_idempotent_and_reassigns() {
        let mut dag = DagIndex::new();
        let med = z(&["medical"]);
        let fin = z(&["finance"]);
        dag.insert_with_zone("r1".into(), vec![], 1.0, med.clone()).unwrap();
        // Idempotent: re-set same zone.
        dag.set_node_zone("r1", med.clone());
        assert_eq!(dag.tip_count_for_zone(&med), 1);
        // Re-zoning: move r1 from medical → finance, no leak.
        dag.set_node_zone("r1", fin.clone());
        assert_eq!(dag.tip_count_for_zone(&med), 0, "old zone must drop the tip");
        assert_eq!(dag.tip_count_for_zone(&fin), 1);
        assert_eq!(dag.zones_with_tips(), 1);
    }

    #[test]
    fn dam3d_b_insert_tolerant_with_zone_orphans_then_relinks() {
        let mut dag = DagIndex::new();
        let med = z(&["medical"]);
        // Insert child first with a missing parent — child is a tip in the zone.
        let missing = dag.insert_tolerant_with_zone("r_child".into(), vec!["r_parent".into()], 2.0, med.clone());
        assert_eq!(missing, 1);
        assert_eq!(dag.tips_for_zone(&med), vec!["r_child"]);
        // Now the parent arrives with the same zone.
        dag.insert_tolerant_with_zone("r_parent".into(), vec![], 1.0, med.clone());
        // Re-link orphans: parent loses tip status, child stays the tip.
        let linked = dag.relink_single_parent("r_parent");
        assert_eq!(linked, 1);
        assert_eq!(dag.tip_count_for_zone(&med), 1);
        assert_eq!(dag.tips_for_zone(&med), vec!["r_child"]);
    }

    #[test]
    fn dam3d_b_rebuild_indices_repopulates_shadow() {
        let mut dag = DagIndex::new();
        let med = z(&["medical"]);
        let fin = z(&["finance"]);
        dag.insert_with_zone("a".into(), vec![], 1.0, med.clone()).unwrap();
        dag.insert_with_zone("b".into(), vec![], 2.0, fin.clone()).unwrap();
        // Simulate a snapshot reload that drops only the indices.
        dag.tips_idx.clear();
        dag.tips_per_zone.clear();
        dag.roots_idx.clear();
        dag.rebuild_indices();
        assert_eq!(dag.tip_count_for_zone(&med), 1);
        assert_eq!(dag.tip_count_for_zone(&fin), 1);
        assert_eq!(dag.zones_with_tips(), 2);
    }

    #[test]
    fn dam3d_b_per_zone_size_bounded_by_hot_tier() {
        // The shadow's worst case is bounded by hot-tier size (HOT_MAX_FALLBACK),
        // not by global zone count. This test exercises the upper invariant
        // with a mid-sized population: every record is its own zone.
        let mut dag = DagIndex::new();
        for i in 0..1_000usize {
            let zone = z(&[&format!("z{i:04}")]);
            let id = format!("r{i:04}");
            dag.insert_with_zone(id, vec![], i as f64, zone).unwrap();
        }
        assert_eq!(dag.tip_count(), 1_000);
        assert_eq!(dag.zones_with_tips(), 1_000);
        // Sum of per-zone tip counts equals global.
        let total: usize = dag.tips_per_zone_iter().map(|(_, n)| n).sum();
        assert_eq!(total, 1_000);
    }

    // ─── epoch / hot-tier watermark invariant tests ─────────────────────────────

    /// Pins `set_current_epoch` as a monotonic max-only update. Lower/equal
    /// values are no-ops; higher values advance. Read-back via `current_epoch()`.
    /// Guards against accidental "set to absolute" semantics that would let
    /// a stale seal roll back the hot-tier eviction watermark.
    #[test]
    fn batch_b_set_current_epoch_is_max_only_never_decreases() {
        let mut d = DagIndex::new();
        assert_eq!(d.current_epoch(), 0, "fresh DAG starts at epoch 0");

        d.set_current_epoch(10);
        assert_eq!(d.current_epoch(), 10);

        // Lower value: no decrease
        d.set_current_epoch(5);
        assert_eq!(d.current_epoch(), 10, "set_current_epoch must NOT roll back");

        // Equal value: stays put
        d.set_current_epoch(10);
        assert_eq!(d.current_epoch(), 10);

        // Higher value: advances
        d.set_current_epoch(42);
        assert_eq!(d.current_epoch(), 42);

        // Zero: no-op (0 < 42)
        d.set_current_epoch(0);
        assert_eq!(d.current_epoch(), 42);
    }

    /// Pins `mark_finalized` as a no-op for absent IDs and as an idempotent
    /// counter for present IDs. Re-marking with a different epoch updates the
    /// stored value without growing the count. Closes a gap where `mark_finalized`
    /// is called via `FinalizedIndex` reconciliation against records that may
    /// have been evicted between snapshot read and DAG insert.
    #[test]
    fn batch_b_mark_finalized_no_op_for_absent_id_advances_count_on_present() {
        let mut d = DagIndex::new();
        assert_eq!(d.finalized_count(), 0);

        // Absent ID: no-op, count stays 0
        d.mark_finalized("nonexistent_rec", 5);
        assert_eq!(
            d.finalized_count(),
            0,
            "mark_finalized on absent id must NOT register"
        );

        // Insert a record, then mark — count goes to 1
        d.insert("A".to_string(), vec![], 1.0).unwrap();
        d.mark_finalized("A", 7);
        assert_eq!(d.finalized_count(), 1);

        // Re-mark same ID with different epoch — count stays 1 (idempotent)
        d.mark_finalized("A", 99);
        assert_eq!(d.finalized_count(), 1);

        // Add second record + mark — count advances
        d.insert("B".to_string(), vec![], 2.0).unwrap();
        d.mark_finalized("B", 10);
        assert_eq!(d.finalized_count(), 2);

        // Mark absent ID again — still no-op even with other records present
        d.mark_finalized("phantom_id", 999);
        assert_eq!(d.finalized_count(), 2);
    }

    /// Pins `link_external_parent` three-way state change: orphan_edges entry
    /// is cleared, child is demoted from roots_idx, parents map gains the
    /// external parent — without the parent appearing in `nodes`. Closes the
    /// gap where a record's parent is finalized + evicted to cold storage
    /// before the child's insert path runs.
    #[test]
    fn batch_b_link_external_parent_clears_orphan_entry_and_demotes_root() {
        let mut d = DagIndex::new();

        // Insert child as orphan — parent EXTERNAL_PARENT is not in the DAG
        let missing = d.insert_tolerant(
            "CHILD".to_string(),
            vec!["EXTERNAL_PARENT".to_string()],
            1.0,
        );
        assert_eq!(missing, 1, "exactly 1 missing parent");
        assert_eq!(d.orphan_count(), 1, "1 orphan edge waiting");
        assert!(
            d.roots().contains(&"CHILD".to_string()),
            "child with no live parent is provisionally a root"
        );
        assert_eq!(d.parents("CHILD"), Vec::<String>::new(),
            "no parent wired yet (still orphan)");

        // Link to the external parent
        d.link_external_parent("CHILD", "EXTERNAL_PARENT");

        // Orphan edge gone
        assert_eq!(d.orphan_count(), 0, "orphan edge cleared");
        assert_eq!(
            d.orphan_parent_key_count(),
            0,
            "no orphan parent keys remain"
        );

        // Child demoted from roots
        assert!(
            !d.roots().contains(&"CHILD".to_string()),
            "child with external parent is no longer a root"
        );

        // External parent wired in but NOT a node in the DAG
        let parents = d.parents("CHILD");
        assert!(
            parents.contains(&"EXTERNAL_PARENT".to_string()),
            "external parent wired into parents map: {parents:?}"
        );
        assert!(
            !d.contains("EXTERNAL_PARENT"),
            "external parent stays absent from nodes (it's evicted/cold)"
        );
    }

    /// Pins bidirectional restoration in `remove`: removing a tip restores
    /// its parent to the tips frontier (no children left); removing a root
    /// restores its child to roots (no parents left). Hot-tier eviction
    /// depends on this — without it, the tips/roots indices drift after
    /// every eviction tick.
    #[test]
    fn batch_b_remove_restores_parent_to_tip_and_child_to_root() {
        // Case 1: A → B chain; removing tip B restores A as a tip.
        let mut d = DagIndex::new();
        d.insert("A".to_string(), vec![], 1.0).unwrap();
        d.insert("B".to_string(), vec!["A".to_string()], 2.0).unwrap();
        assert_eq!(d.tip_count(), 1, "only B is a tip initially");
        assert!(d.tips().contains(&"B".to_string()));
        assert!(!d.tips().contains(&"A".to_string()),
            "A has child B, not a tip");

        d.remove("B");
        assert_eq!(d.tip_count(), 1);
        assert!(
            d.tips().contains(&"A".to_string()),
            "after removing B, A becomes a tip again"
        );

        // Case 2: X → Y chain; removing root X restores Y as a root.
        let mut d2 = DagIndex::new();
        d2.insert("X".to_string(), vec![], 1.0).unwrap();
        d2.insert("Y".to_string(), vec!["X".to_string()], 2.0).unwrap();
        assert!(d2.roots().contains(&"X".to_string()));
        assert!(
            !d2.roots().contains(&"Y".to_string()),
            "Y has parent X, not a root"
        );

        d2.remove("X");
        assert!(
            d2.roots().contains(&"Y".to_string()),
            "after removing X, Y becomes a root"
        );
        assert!(!d2.contains("X"), "X gone from nodes");
        assert_eq!(d2.parents("Y"), Vec::<String>::new(),
            "Y's parent edges fully cleaned");
    }

    /// Pins `prune_orphan_edges` largest-group-first eviction order: with
    /// three orphan parent groups of size 3/2/1 (total=6), pruning to max=3
    /// evicts ONLY the size-3 group (returning 3), leaving the size-2 and
    /// size-1 groups intact. Confirms the docstring claim. Also pins the
    /// under-cap no-op return value of 0.
    #[test]
    fn batch_b_prune_orphan_edges_evicts_largest_groups_first() {
        let mut d = DagIndex::new();

        // P_BIG: 3 orphan children
        for cid in ["c1", "c2", "c3"] {
            d.insert_tolerant(cid.to_string(), vec!["P_BIG".to_string()], 1.0);
        }
        // P_MID: 2 orphan children
        for cid in ["c4", "c5"] {
            d.insert_tolerant(cid.to_string(), vec!["P_MID".to_string()], 2.0);
        }
        // P_SMALL: 1 orphan child
        d.insert_tolerant("c6".to_string(), vec!["P_SMALL".to_string()], 3.0);

        assert_eq!(d.orphan_count(), 6, "6 total orphan edges");
        assert_eq!(d.orphan_parent_key_count(), 3, "3 distinct orphan parents");

        // Prune to max=3 — must evict P_BIG (size 3) only
        let removed = d.prune_orphan_edges(3);
        assert_eq!(removed, 3, "evicted exactly P_BIG's 3 children");
        assert_eq!(d.orphan_count(), 3, "P_MID(2) + P_SMALL(1) remain");

        let remaining = d.orphan_parent_ids();
        assert!(
            !remaining.contains(&"P_BIG".to_string()),
            "P_BIG (largest) evicted first: remaining={remaining:?}"
        );
        assert!(remaining.contains(&"P_MID".to_string()), "P_MID survives");
        assert!(remaining.contains(&"P_SMALL".to_string()), "P_SMALL survives");

        // Under-cap no-op: a fresh DAG with 1 orphan edge, prune to max=10
        let mut d2 = DagIndex::new();
        d2.insert_tolerant("k".to_string(), vec!["pp".to_string()], 1.0);
        assert_eq!(d2.orphan_count(), 1);
        assert_eq!(
            d2.prune_orphan_edges(10),
            0,
            "under-cap prune must return 0 and not mutate"
        );
        assert_eq!(d2.orphan_count(), 1, "still 1 orphan after no-op prune");
    }

    #[test]
    fn tips_and_roots_do_not_panic_on_nan_timestamp() {
        let mut d = DagIndex::new();
        d.insert("nan-root".into(), vec![], f64::NAN).unwrap();
        d.insert("nan-tip".into(), vec!["nan-root".into()], f64::NAN).unwrap();
        // Must not panic even with NaN timestamps in both sort paths.
        let _ = d.tips();
        let _ = d.roots();
    }
}
