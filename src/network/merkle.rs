//! Sparse binary Merkle tree — persistent zone state verification.
//!
//! Used for light client proofs, cross-zone verification, and epoch seals.
//! Each zone maintains its own Merkle tree of record hashes, persisted in
//! the RocksDB `merkle` column family.
//!
//! Design:
//!   - Binary tree with max depth 64 (supports 2^64 leaves)
//!   - SHA3-256 hash function (same as record hashing)
//!   - Sparse — only populated subtrees are stored
//!   - Incremental — inserting/removing one leaf updates O(depth) nodes
//!   - Persistent — tree nodes stored in RocksDB, survives restart
//!   - Content-hash sorted — leaf position determined by hash value

//!
//! Spec references:
//!   @spec Protocol §11.3
//!   @spec Protocol §11.12

use std::collections::HashMap;

use crate::crypto::hash::sha3_256;
use crate::errors::{ElaraError, Result};
use crate::storage::rocks::{StorageEngine, CF_MERKLE};
use crate::ZoneId;

// ─── Constants ─────────────────────────────────────────────────────────────

/// Maximum tree depth. With 64 bits we can address 2^64 leaves.
/// Canonical definition lives in the node-free `verify_core` (the offline
/// verifier caps hostile proof paths with the same bound and must not
/// reference node-gated modules); re-exported here so tree code keeps its
/// natural `merkle::MAX_DEPTH` path.
pub use crate::verify_core::ZONE_MERKLE_MAX_DEPTH as MAX_DEPTH;

/// Empty node sentinel — SHA3-256 of the empty string.
/// Any subtree with no leaves has this hash.
const EMPTY_HASH: [u8; 32] = [
    0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66,
    0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62,
    0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa,
    0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a,
];

// ─── Key encoding ──────────────────────────────────────────────────────────

/// Node key in RocksDB: zone_id (8 bytes BE) + depth (1 byte) + path_prefix (8 bytes BE).
///
/// `path_prefix` encodes the left/right decisions from root to this node.
/// Bit i (from MSB) = 0 means left, 1 means right at depth i.
/// For a node at depth d, only the top d bits of path_prefix matter.
fn node_key(zone: &ZoneId, depth: u8, path_prefix: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(17);
    key.extend_from_slice(&zone.to_key_bytes());
    key.push(depth);
    key.extend_from_slice(&path_prefix.to_be_bytes());
    key
}

/// Key for leaf metadata: "leaf:" + zone (8B) + leaf_hash (32B).
/// Value: 1 byte (0x01 = present). Used to enumerate leaves per zone.
fn leaf_key(zone: &ZoneId, leaf_hash: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(5 + 8 + 32);
    key.extend_from_slice(b"leaf:");
    key.extend_from_slice(&zone.to_key_bytes());
    key.extend_from_slice(leaf_hash);
    key
}

/// Key for the leaf count per zone: "count:" + zone (8B).
fn count_key(zone: &ZoneId) -> Vec<u8> {
    let mut key = Vec::with_capacity(14);
    key.extend_from_slice(b"count:");
    key.extend_from_slice(&zone.to_key_bytes());
    key
}

// ─── Path computation ──────────────────────────────────────────────────────

/// Convert a 32-byte leaf hash to a 64-bit path by taking the first 8 bytes.
/// This determines where in the tree the leaf lives.
fn leaf_to_path(leaf_hash: &[u8; 32]) -> u64 {
    u64::from_be_bytes([
        leaf_hash[0], leaf_hash[1], leaf_hash[2], leaf_hash[3],
        leaf_hash[4], leaf_hash[5], leaf_hash[6], leaf_hash[7],
    ])
}

/// Get the bit at a given depth (0 = root, 63 = deepest).
/// Returns true if the bit is 1 (go right), false if 0 (go left).
fn path_bit(path: u64, depth: u8) -> bool {
    (path >> (63 - depth)) & 1 == 1
}

/// Mask a path to only keep the top `depth` bits.
fn path_mask(path: u64, depth: u8) -> u64 {
    if depth >= 64 {
        return path;
    }
    if depth == 0 {
        return 0;
    }
    let mask = !((1u64 << (64 - depth)) - 1);
    path & mask
}

// ─── Merkle Proof ──────────────────────────────────────────────────────────

/// Inclusion/exclusion proof for a leaf in the sparse Merkle tree.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SparseMerkleProof {
    /// The leaf hash being proven.
    pub leaf: [u8; 32],
    /// Root hash this proof verifies against.
    pub root: [u8; 32],
    /// Sibling hashes along the path from leaf to root (bottom-up).
    /// Length = tree depth traversed.
    pub siblings: Vec<SparseMerkleProofNode>,
    /// Zone this proof belongs to.
    pub zone: ZoneId,
}

/// A sibling in the proof path.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SparseMerkleProofNode {
    /// Hash of the sibling node.
    pub hash: [u8; 32],
    /// True if this sibling is on the right side.
    pub is_right: bool,
}

/// Verify a sparse Merkle proof statically (no tree needed).
pub fn verify_proof(proof: &SparseMerkleProof) -> bool {
    let mut current = proof.leaf;

    for node in &proof.siblings {
        let mut combined = [0u8; 64];
        if node.is_right {
            // Sibling is on the right, we're on the left
            combined[..32].copy_from_slice(&current);
            combined[32..].copy_from_slice(&node.hash);
        } else {
            // Sibling is on the left, we're on the right
            combined[..32].copy_from_slice(&node.hash);
            combined[32..].copy_from_slice(&current);
        }
        current = sha3_256(&combined);
    }

    current == proof.root
}

// ─── Cross-Zone Merkle Proofs (Protocol §11.22.1) ─────────────────────────

/// A proof that a record exists in a specific zone's epoch seal merkle tree.
///
/// Used for cross-zone dispute evidence: proves record R (native to zone A)
/// was included in zone B's epoch N merkle root.
///
/// @spec Protocol §11.22.1
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CrossZoneProof {
    /// Record being proven.
    pub record_id: String,
    /// Content hash of the record.
    pub record_hash: [u8; 32],
    /// Zone where the record is native.
    pub source_zone: ZoneId,
    /// Zone whose merkle tree contains proof of the record.
    pub target_zone: ZoneId,
    /// Epoch number in target zone.
    pub target_epoch: u64,
    /// The sparse merkle proof against the target zone's tree.
    pub merkle_proof: SparseMerkleProof,
    /// The epoch seal's merkle root (must match proof.root).
    pub seal_merkle_root: [u8; 32],
    /// Record ID of the epoch seal (for independent verification).
    pub seal_record_id: String,
}

/// Verification result for a cross-zone proof.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CrossZoneVerification {
    /// Whether the merkle proof is mathematically valid.
    pub proof_valid: bool,
    /// Whether the proof root matches the epoch seal's merkle root.
    pub root_matches_seal: bool,
    /// Whether the proof zone matches the target zone.
    pub zone_matches: bool,
    /// Whether the leaf matches the record hash.
    pub leaf_matches: bool,
    /// Overall verdict.
    pub verified: bool,
}

/// Verify a cross-zone merkle proof statically.
///
/// Checks:
/// 1. Merkle proof is mathematically valid (sibling hashes reconstruct root)
/// 2. Proof root matches the epoch seal's merkle root
/// 3. Proof zone matches target zone
/// 4. Leaf hash matches record hash
pub fn verify_cross_zone_proof(proof: &CrossZoneProof) -> CrossZoneVerification {
    let proof_valid = verify_proof(&proof.merkle_proof);
    let root_matches_seal = proof.merkle_proof.root == proof.seal_merkle_root;
    let zone_matches = proof.merkle_proof.zone == proof.target_zone;
    let leaf_matches = proof.merkle_proof.leaf == proof.record_hash;
    CrossZoneVerification {
        proof_valid,
        root_matches_seal,
        zone_matches,
        leaf_matches,
        verified: proof_valid && root_matches_seal && zone_matches && leaf_matches,
    }
}

/// Generate a cross-zone proof for a record in a specific zone.
///
/// Looks up the record's content hash, finds its sparse merkle proof in the
/// target zone's tree, and matches it against the latest epoch seal for that zone.
///
/// Gap 4 Phase C2: `zone_registry` resolves the record's SOURCE zone against
/// the active ZoneRegistry when `Some`, so proofs report the correct post-split
/// leaf instead of the naive flat-modulo zone. Pass `None` to preserve legacy
/// behavior (tests + pre-split callers).
pub fn generate_cross_zone_proof(
    rocks: &StorageEngine,
    record_id: &str,
    target_zone: &ZoneId,
    zone_registry: Option<&super::zone_registry::ZoneRegistry>,
) -> Result<Option<CrossZoneProof>> {
    // Get the record
    let rec = match rocks.get_record(record_id)? {
        Some(r) => r,
        None => return Ok(None),
    };

    let mut record_hash = [0u8; 32];
    if rec.content_hash.len() == 32 {
        record_hash.copy_from_slice(&rec.content_hash);
    } else {
        return Ok(None); // Invalid content hash length
    }
    // KR-3 S2 (c3-ii-2b): route a rotation-hop's source zone by its lineage pin
    // (its SMT leaf lives in the lineage zone). LOCAL, non-consensus — flag-OFF
    // there are no pin rows, so `route_id == record_id` ⇒ byte-identical.
    let route_id = rocks
        .get_rotation_zone_pin(record_id)
        .unwrap_or_else(|| record_id.to_string());
    let source_zone = {
        let naive = crate::network::consensus::zone_for_record(&route_id);
        if let Some(reg) = zone_registry {
            let rk = super::zone_registry::routing_key_for_record(&route_id);
            super::zone_registry::resolve_current_leaf(reg, &naive, &rk).resolved_zone
        } else {
            naive
        }
    };

    // Get sparse merkle proof from target zone's tree
    let tree = SparseMerkleTree::new(rocks, target_zone.clone());
    let merkle_proof = match tree.proof(&record_hash)? {
        Some(p) => p,
        None => return Ok(None), // Record not in this zone's tree
    };

    // Find the latest epoch seal for target zone to get the merkle root
    // Scan recent epoch seals from RocksDB
    let seal_info = find_latest_seal_for_zone(rocks, target_zone)?;
    let (seal_record_id, seal_merkle_root, target_epoch) = match seal_info {
        Some(info) => info,
        None => return Ok(None), // No seal found for this zone
    };

    Ok(Some(CrossZoneProof {
        record_id: record_id.to_string(),
        record_hash,
        source_zone,
        target_zone: target_zone.clone(),
        target_epoch,
        merkle_proof,
        seal_merkle_root,
        seal_record_id,
    }))
}

/// Find the latest epoch seal for a zone. Returns (seal_record_id, merkle_root, epoch_number).
///
/// Exposed `pub(crate)` so Gap 4 orchestration (building a `ZoneSnapshot`
/// for a transition seal's parent) can reuse the same bounded-scan path
/// as cross-zone proof construction.
pub(crate) fn find_latest_seal_for_zone(
    rocks: &StorageEngine,
    zone: &ZoneId,
) -> Result<Option<(String, [u8; 32], u64)>> {
    use crate::network::epoch::{EPOCH_OP_KEY, extract_epoch_seal};

    // Use timestamp index to scan recent records efficiently (newest first)
    // Scan recent records (last 7 days) to find epoch seals
    let since = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
        - 7.0 * 86400.0;
    let recent_ids = rocks.recent_record_ids(since, 2000)?;

    let mut best: Option<(String, [u8; 32], u64)> = None;

    for rid in recent_ids {
        let rec = match rocks.get_record(&rid)? {
            Some(r) => r,
            None => continue,
        };

        // Check if this is an epoch seal
        if !rec.metadata.contains_key(EPOCH_OP_KEY) {
            continue;
        }

        if let Ok(Some(parsed)) = extract_epoch_seal(&rec) {
            if &parsed.zone == zone {
                let is_newer = best.as_ref()
                    .is_none_or(|(_, _, epoch)| parsed.epoch_number > *epoch);
                if is_newer {
                    best = Some((rid, parsed.merkle_root, parsed.epoch_number));
                }
            }
        }
    }

    Ok(best)
}

// ─── Sparse Merkle Tree ───────────────────────────────────────────────────

/// Sparse binary Merkle tree backed by RocksDB.
///
/// Each zone has its own independent tree. Nodes are addressed by
/// (zone, depth, path_prefix) and stored in the `merkle` column family.
///
/// The tree is "sparse" — empty subtrees are represented by EMPTY_HASH
/// and never stored. Only paths with actual leaves are materialized.
pub struct SparseMerkleTree<'a> {
    /// RocksDB storage engine.
    storage: &'a StorageEngine,
    /// Zone ID this tree belongs to.
    zone: ZoneId,
    /// In-memory write cache — batched to RocksDB on commit.
    /// Key: (depth, path_prefix), Value: hash.
    cache: HashMap<(u8, u64), [u8; 32]>,
    /// Nodes to delete from RocksDB on commit.
    deletes: Vec<(u8, u64)>,
    /// Pending leaf-existence writes, flushed on commit.
    /// Key: leaf_hash, Value: true (put) / false (delete).
    /// Coalesces aux writes into the same WriteBatch as `cache`/`deletes`,
    /// reducing per-ingest WAL syncs from 3 → 1 for merkle (DISC-4).
    pending_leaves: HashMap<[u8; 32], bool>,
    /// Pending leaf-count write, flushed on commit. `None` = read storage.
    pending_count: Option<u64>,
}

impl<'a> SparseMerkleTree<'a> {
    /// Open or create a sparse Merkle tree for a zone.
    pub fn new(storage: &'a StorageEngine, zone: ZoneId) -> Self {
        Self {
            storage,
            zone,
            cache: HashMap::new(),
            deletes: Vec::new(),
            pending_leaves: HashMap::new(),
            pending_count: None,
        }
    }

    /// Get the root hash. Returns EMPTY_HASH for an empty tree.
    pub fn root(&self) -> Result<[u8; 32]> {
        self.get_node(0, 0)
    }

    /// Get a node hash at (depth, path_prefix). Returns EMPTY_HASH if not found.
    fn get_node(&self, depth: u8, path_prefix: u64) -> Result<[u8; 32]> {
        let masked = path_mask(path_prefix, depth);

        // Check write cache first
        if let Some(hash) = self.cache.get(&(depth, masked)) {
            return Ok(*hash);
        }

        // Check if it's in the delete set
        if self.deletes.iter().any(|&(d, p)| d == depth && p == masked) {
            return Ok(EMPTY_HASH);
        }

        // Read from RocksDB
        let key = node_key(&self.zone, depth, masked);
        match self.storage.get_cf_raw(CF_MERKLE, &key)? {
            Some(bytes) if bytes.len() == 32 => {
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&bytes);
                Ok(hash)
            }
            _ => Ok(EMPTY_HASH),
        }
    }

    /// Set a node hash in the write cache.
    fn set_node(&mut self, depth: u8, path_prefix: u64, hash: [u8; 32]) {
        let masked = path_mask(path_prefix, depth);
        self.deletes.retain(|&(d, p)| !(d == depth && p == masked));
        self.cache.insert((depth, masked), hash);
    }

    /// Mark a node for deletion.
    fn delete_node(&mut self, depth: u8, path_prefix: u64) {
        let masked = path_mask(path_prefix, depth);
        self.cache.remove(&(depth, masked));
        self.deletes.push((depth, masked));
    }

    /// Insert a leaf hash into the tree.
    ///
    /// Updates the path from leaf to root (O(depth) operations).
    /// Call `commit()` after all inserts to persist to RocksDB.
    pub fn insert(&mut self, leaf_hash: &[u8; 32]) -> Result<()> {
        let path = leaf_to_path(leaf_hash);

        // Store the leaf at max depth
        self.set_node(MAX_DEPTH, path, *leaf_hash);

        // Track leaf existence (pending — flushed in commit)
        // If this leaf was already present (in storage or pending), count stays unchanged.
        let was_present = self.contains_internal(leaf_hash)?;
        self.pending_leaves.insert(*leaf_hash, true);

        // Update leaf count (pending — flushed in commit)
        if !was_present {
            let count = self.leaf_count()? + 1;
            self.pending_count = Some(count);
        }

        // Recompute path from leaf to root
        self.recompute_path(path)?;

        Ok(())
    }

    /// Remove a leaf hash from the tree.
    ///
    /// Sets the leaf to EMPTY_HASH and recomputes the path to root.
    pub fn remove(&mut self, leaf_hash: &[u8; 32]) -> Result<bool> {
        let path = leaf_to_path(leaf_hash);

        // Check if leaf exists
        let current = self.get_node(MAX_DEPTH, path)?;
        if current == EMPTY_HASH || current != *leaf_hash {
            return Ok(false); // Not in tree
        }

        // Remove the leaf
        self.delete_node(MAX_DEPTH, path);

        // Mark leaf tracking for deletion (pending — flushed in commit)
        self.pending_leaves.insert(*leaf_hash, false);

        // Update leaf count (pending — flushed in commit)
        let count = self.leaf_count()?;
        if count > 0 {
            self.pending_count = Some(count - 1);
        }

        // Recompute path from leaf to root
        self.recompute_path(path)?;

        Ok(true)
    }

    /// Recompute nodes from leaf (MAX_DEPTH) up to root (depth 0).
    ///
    /// Short-circuits when the newly computed parent hash matches the current
    /// value (from cache or RocksDB) — everything above is unchanged.
    /// For a sparse tree with N leaves, this reduces work from O(64) to
    /// O(log N) RocksDB reads per insert.
    fn recompute_path(&mut self, path: u64) -> Result<()> {
        let mut depth = MAX_DEPTH;

        while depth > 0 {
            let parent_depth = depth - 1;
            let parent_path = path_mask(path, parent_depth);

            // Get left and right children
            let left_path = parent_path; // bit at parent_depth is 0
            let right_path = parent_path | (1u64 << (63 - parent_depth)); // bit at parent_depth is 1

            let left_hash = self.get_node(depth, left_path)?;
            let right_hash = self.get_node(depth, right_path)?;

            // Compute parent hash
            let parent_hash = if left_hash == EMPTY_HASH && right_hash == EMPTY_HASH {
                EMPTY_HASH
            } else {
                let mut combined = [0u8; 64];
                combined[..32].copy_from_slice(&left_hash);
                combined[32..].copy_from_slice(&right_hash);
                sha3_256(&combined)
            };

            // Short-circuit: if the new parent hash matches what's currently stored
            // (checking cache first, then RocksDB), nothing above changes.
            let current_hash = self.get_node(parent_depth, parent_path)?;
            if parent_hash == current_hash {
                break;
            }

            if parent_hash == EMPTY_HASH {
                self.delete_node(parent_depth, parent_path);
            } else {
                self.set_node(parent_depth, parent_path, parent_hash);
            }

            depth -= 1;
        }

        Ok(())
    }

    /// Generate an inclusion proof for a leaf.
    ///
    /// Returns None if the leaf is not in the tree.
    pub fn proof(&self, leaf_hash: &[u8; 32]) -> Result<Option<SparseMerkleProof>> {
        let path = leaf_to_path(leaf_hash);

        // Check leaf exists
        let stored = self.get_node(MAX_DEPTH, path)?;
        if stored == EMPTY_HASH || stored != *leaf_hash {
            return Ok(None);
        }

        let root = self.root()?;

        // Collect siblings from leaf (bottom) to root (top).
        // depth MAX_DEPTH-1 is the first parent level above the leaf,
        // depth 0 is the root level. We iterate bottom-up.
        let mut siblings = Vec::with_capacity(MAX_DEPTH as usize);
        for depth in (0..MAX_DEPTH).rev() {
            let parent_path = path_mask(path, depth);
            let child_depth = depth + 1;

            let is_right_child = path_bit(path, depth);

            let sibling_hash = if is_right_child {
                // We're on the right, sibling is left
                let left_path = parent_path; // bit at `depth` is 0
                self.get_node(child_depth, left_path)?
            } else {
                // We're on the left, sibling is right
                let right_path = parent_path | (1u64 << (63 - depth));
                self.get_node(child_depth, right_path)?
            };

            siblings.push(SparseMerkleProofNode {
                hash: sibling_hash,
                is_right: !is_right_child, // sibling is on the opposite side
            });
        }

        Ok(Some(SparseMerkleProof {
            leaf: *leaf_hash,
            root,
            siblings,
            zone: self.zone.clone(),
        }))
    }

    /// Commit all cached writes to RocksDB atomically.
    pub fn commit(&mut self) -> Result<()> {
        let mut batch = self.storage.new_batch();
        let cf = self.storage.cf_handle(CF_MERKLE)
            .ok_or_else(|| ElaraError::Storage("CF_MERKLE not registered".into()))?;

        // Write cached nodes
        for (&(depth, path_prefix), hash) in &self.cache {
            let key = node_key(&self.zone, depth, path_prefix);
            batch.put_cf(&cf, &key, hash);
        }

        // Delete removed nodes
        for &(depth, path_prefix) in &self.deletes {
            let key = node_key(&self.zone, depth, path_prefix);
            batch.delete_cf(&cf, &key);
        }

        // Flush pending leaf-existence writes into the same batch.
        for (leaf_hash, present) in &self.pending_leaves {
            let lk = leaf_key(&self.zone, leaf_hash);
            if *present {
                batch.put_cf(&cf, &lk, [0x01]);
            } else {
                batch.delete_cf(&cf, &lk);
            }
        }

        // Flush pending leaf count into the same batch.
        if let Some(count) = self.pending_count {
            let ck = count_key(&self.zone);
            batch.put_cf(&cf, &ck, count.to_be_bytes());
        }

        self.storage.write_batch(batch)?;

        self.cache.clear();
        self.deletes.clear();
        self.pending_leaves.clear();
        self.pending_count = None;

        Ok(())
    }

    /// Get the number of leaves in this zone's tree.
    pub fn leaf_count(&self) -> Result<u64> {
        // Pending count takes precedence over on-disk value.
        if let Some(c) = self.pending_count {
            return Ok(c);
        }
        let ck = count_key(&self.zone);
        match self.storage.get_cf_raw(CF_MERKLE, &ck)? {
            Some(bytes) if bytes.len() == 8 => {
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&bytes);
                Ok(u64::from_be_bytes(arr))
            }
            _ => Ok(0),
        }
    }

    /// Check if a leaf exists in the tree (post-commit view).
    pub fn contains(&self, leaf_hash: &[u8; 32]) -> Result<bool> {
        self.contains_internal(leaf_hash)
    }

    /// Internal helper — checks pending writes first, then storage.
    /// Used by `insert` to detect no-op reinserts and keep `leaf_count` accurate.
    fn contains_internal(&self, leaf_hash: &[u8; 32]) -> Result<bool> {
        if let Some(&present) = self.pending_leaves.get(leaf_hash) {
            return Ok(present);
        }
        let lk = leaf_key(&self.zone, leaf_hash);
        Ok(self.storage.get_cf_raw(CF_MERKLE, &lk)?.is_some())
    }

    /// Get all leaf hashes for this zone (sorted).
    pub fn all_leaves(&self) -> Result<Vec<[u8; 32]>> {
        let mut prefix = Vec::with_capacity(13);
        prefix.extend_from_slice(b"leaf:");
        prefix.extend_from_slice(&self.zone.to_key_bytes());

        let entries = self.storage.prefix_collect(CF_MERKLE, &prefix)?;
        // Merge with pending writes so callers see a consistent post-insert view
        // without waiting for commit. Pending `true` adds leaves; pending `false`
        // removes them (overrides any on-disk entry).
        let mut set: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
        for (key, _) in entries {
            // Key format: "leaf:" (5) + zone (8) + hash (32) = 45 bytes
            if key.len() == 45 {
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&key[13..45]);
                set.insert(hash);
            }
        }
        for (leaf_hash, present) in &self.pending_leaves {
            if *present {
                set.insert(*leaf_hash);
            } else {
                set.remove(leaf_hash);
            }
        }

        let mut leaves: Vec<[u8; 32]> = set.into_iter().collect();
        leaves.sort();
        Ok(leaves)
    }
}

// ─── Convenience functions ─────────────────────────────────────────────────

/// Compute the Merkle root for a zone from its stored tree.
pub fn zone_root(storage: &StorageEngine, zone: ZoneId) -> Result<[u8; 32]> {
    let tree = SparseMerkleTree::new(storage, zone);
    tree.root()
}

/// Generate a Merkle proof for a specific leaf hash in a zone.
pub fn zone_proof(
    storage: &StorageEngine,
    zone: ZoneId,
    leaf_hash: &[u8; 32],
) -> Result<Option<SparseMerkleProof>> {
    let tree = SparseMerkleTree::new(storage, zone);
    tree.proof(leaf_hash)
}

/// Get the empty hash sentinel value.
pub fn empty_hash() -> [u8; 32] {
    EMPTY_HASH
}

/// Capacity hint (bytes) for the global-root accumulator.
///
/// `zone_count` is consensus-set but has no hard ceiling (`set_zone_count` only
/// floors at 1), so a raw `zone_count as usize * 32` would (a) overflow `usize`
/// on 32-bit / phone-tier targets — a debug-build panic — and (b) at large
/// zone-count targets eagerly reserve gigabytes off a single counter. Saturate
/// the multiply and cap the up-front reserve. This is a HINT only: the loop's
/// `extend_from_slice` grows the Vec to the true size, and the hashed bytes (so
/// the computed root) are identical regardless of capacity — therefore this is
/// allocation-only and has NO consensus effect (every node still produces the
/// same root for the same `zone_count`). Bounding `zone_count` itself would be a
/// consensus-rule change (peers must agree on the `0..zone_count` iteration), so
/// it is deliberately NOT done here.
fn global_root_prealloc(zone_count: u64) -> usize {
    const MAX_PREALLOC_BYTES: usize = 1 << 20; // ~32K zones; grows beyond if needed
    (zone_count as usize).saturating_mul(32).min(MAX_PREALLOC_BYTES)
}

/// Compute a global Merkle root across all zones.
///
/// Reads each zone's sparse tree root (O(1) per zone) and hashes them together.
/// Total cost: O(zone_count) RocksDB reads — microseconds in practice (2-4 zones).
///
/// This replaces the old `all_record_hashes() + MerkleTree::root()` pattern
/// which was O(all_records) — 320MB at 10M records.
pub fn global_merkle_root(storage: &StorageEngine) -> [u8; 32] {
    let zone_count = crate::network::consensus::get_zone_count();
    if zone_count == 0 {
        return EMPTY_HASH;
    }
    let mut combined = Vec::with_capacity(global_root_prealloc(zone_count));
    for i in 0..zone_count {
        let zone = ZoneId::from_legacy(i);
        let root = zone_root(storage, zone).unwrap_or(EMPTY_HASH);
        combined.extend_from_slice(&root);
    }
    sha3_256(&combined)
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hash::sha3_256;
    use crate::storage::rocks::StorageEngine;

    fn test_storage() -> (StorageEngine, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let engine = StorageEngine::open(dir.path()).unwrap();
        (engine, dir)
    }

    fn leaf(data: &[u8]) -> [u8; 32] {
        sha3_256(data)
    }

    #[test]
    fn global_root_prealloc_is_bounded_and_never_overflows() {
        // Small zone counts: exact 32-bytes-per-zone hint.
        assert_eq!(global_root_prealloc(0), 0);
        assert_eq!(global_root_prealloc(4), 128);
        assert_eq!(global_root_prealloc(1000), 32_000);
        // Unbounded / overflowing zone_count must NOT panic and must stay capped
        // (the raw `zone_count as usize * 32` would overflow usize here). Assert
        // the invariant rather than an exact value so it holds on 32- and 64-bit.
        assert!(global_root_prealloc(u64::MAX) <= (1 << 20));
        assert!(global_root_prealloc(u64::MAX / 16) <= (1 << 20));
        assert!(global_root_prealloc(1 << 40) <= (1 << 20));
    }

    // ── Basic operations ───────────────────────────────────────────────────

    #[test]
    fn test_empty_tree_root() {
        let (storage, _dir) = test_storage();
        let tree = SparseMerkleTree::new(&storage, ZoneId::from_legacy(0));
        let root = tree.root().unwrap();
        assert_eq!(root, EMPTY_HASH, "empty tree should have the empty sentinel hash");
    }

    #[test]
    fn test_insert_changes_root() {
        let (storage, _dir) = test_storage();
        let mut tree = SparseMerkleTree::new(&storage, ZoneId::from_legacy(0));

        let root_before = tree.root().unwrap();
        tree.insert(&leaf(b"record_1")).unwrap();
        let root_after = tree.root().unwrap();

        assert_ne!(root_before, root_after, "root should change after insert");
        assert_ne!(root_after, EMPTY_HASH, "root should not be empty after insert");
    }

    #[test]
    fn test_insert_multiple_changes_root() {
        let (storage, _dir) = test_storage();
        let mut tree = SparseMerkleTree::new(&storage, ZoneId::from_legacy(0));

        tree.insert(&leaf(b"record_1")).unwrap();
        let root1 = tree.root().unwrap();

        tree.insert(&leaf(b"record_2")).unwrap();
        let root2 = tree.root().unwrap();

        tree.insert(&leaf(b"record_3")).unwrap();
        let root3 = tree.root().unwrap();

        assert_ne!(root1, root2, "root should change with each insert");
        assert_ne!(root2, root3, "root should change with each insert");
        assert_ne!(root1, root3);
    }

    #[test]
    fn test_deterministic_root() {
        let (storage1, _dir1) = test_storage();
        let (storage2, _dir2) = test_storage();

        let leaves: Vec<[u8; 32]> = (0..5u8).map(|i| leaf(&[i])).collect();

        // Insert same leaves in same order
        let mut tree1 = SparseMerkleTree::new(&storage1, ZoneId::from_legacy(0));
        let mut tree2 = SparseMerkleTree::new(&storage2, ZoneId::from_legacy(0));
        for l in &leaves {
            tree1.insert(l).unwrap();
            tree2.insert(l).unwrap();
        }

        assert_eq!(tree1.root().unwrap(), tree2.root().unwrap(),
            "same inserts should produce same root");
    }

    #[test]
    fn test_insert_order_matters() {
        // Unlike a sorted Merkle tree, a sparse tree with path-based addressing
        // gives the same root regardless of insertion order, because each leaf
        // has a fixed position determined by its hash.
        let (storage1, _dir1) = test_storage();
        let (storage2, _dir2) = test_storage();

        let l1 = leaf(b"aaa");
        let l2 = leaf(b"bbb");
        let l3 = leaf(b"ccc");

        let mut tree1 = SparseMerkleTree::new(&storage1, ZoneId::from_legacy(0));
        tree1.insert(&l1).unwrap();
        tree1.insert(&l2).unwrap();
        tree1.insert(&l3).unwrap();

        let mut tree2 = SparseMerkleTree::new(&storage2, ZoneId::from_legacy(0));
        tree2.insert(&l3).unwrap();
        tree2.insert(&l1).unwrap();
        tree2.insert(&l2).unwrap();

        assert_eq!(tree1.root().unwrap(), tree2.root().unwrap(),
            "insertion order should not affect root");
    }

    // ── Proof generation and verification ──────────────────────────────────

    #[test]
    fn test_proof_verify_single_leaf() {
        let (storage, _dir) = test_storage();
        let mut tree = SparseMerkleTree::new(&storage, ZoneId::from_legacy(0));

        let l = leaf(b"only_leaf");
        tree.insert(&l).unwrap();
        tree.commit().unwrap();

        let tree = SparseMerkleTree::new(&storage, ZoneId::from_legacy(0));
        let proof = tree.proof(&l).unwrap().expect("proof should exist");
        assert_eq!(proof.leaf, l);
        assert_eq!(proof.root, tree.root().unwrap());
        assert!(verify_proof(&proof), "valid proof should verify");
    }

    #[test]
    fn test_proof_verify_multiple_leaves() {
        let (storage, _dir) = test_storage();
        let mut tree = SparseMerkleTree::new(&storage, ZoneId::from_legacy(0));

        let leaves: Vec<[u8; 32]> = (0..10u8).map(|i| leaf(&[i])).collect();
        for l in &leaves {
            tree.insert(l).unwrap();
        }
        tree.commit().unwrap();

        // Re-open tree from storage to verify persistence
        let tree = SparseMerkleTree::new(&storage, ZoneId::from_legacy(0));
        let root = tree.root().unwrap();

        for l in &leaves {
            let proof = tree.proof(l).unwrap()
                .expect("proof should exist for inserted leaf");
            assert_eq!(proof.leaf, *l);
            assert_eq!(proof.root, root);
            assert!(verify_proof(&proof), "proof for leaf {} should verify", hex::encode(l));
        }
    }

    #[test]
    fn test_proof_missing_leaf() {
        let (storage, _dir) = test_storage();
        let mut tree = SparseMerkleTree::new(&storage, ZoneId::from_legacy(0));
        tree.insert(&leaf(b"exists")).unwrap();
        tree.commit().unwrap();

        let tree = SparseMerkleTree::new(&storage, ZoneId::from_legacy(0));
        let proof = tree.proof(&leaf(b"does_not_exist")).unwrap();
        assert!(proof.is_none(), "proof for missing leaf should be None");
    }

    #[test]
    fn test_proof_tampered_fails() {
        let (storage, _dir) = test_storage();
        let mut tree = SparseMerkleTree::new(&storage, ZoneId::from_legacy(0));

        let leaves: Vec<[u8; 32]> = (0..4u8).map(|i| leaf(&[i])).collect();
        for l in &leaves {
            tree.insert(l).unwrap();
        }
        tree.commit().unwrap();

        let tree = SparseMerkleTree::new(&storage, ZoneId::from_legacy(0));
        let mut proof = tree.proof(&leaves[0]).unwrap().unwrap();

        // Tamper with a sibling
        if let Some(node) = proof.siblings.first_mut() {
            node.hash[0] ^= 0xFF;
        }
        assert!(!verify_proof(&proof), "tampered proof should fail verification");
    }

    #[test]
    fn test_proof_wrong_root_fails() {
        let (storage, _dir) = test_storage();
        let mut tree = SparseMerkleTree::new(&storage, ZoneId::from_legacy(0));

        tree.insert(&leaf(b"leaf_a")).unwrap();
        tree.commit().unwrap();

        let tree = SparseMerkleTree::new(&storage, ZoneId::from_legacy(0));
        let mut proof = tree.proof(&leaf(b"leaf_a")).unwrap().unwrap();
        proof.root = [0xFFu8; 32]; // Wrong root
        assert!(!verify_proof(&proof), "proof with wrong root should fail");
    }

    // ── Remove ─────────────────────────────────────────────────────────────

    #[test]
    fn test_remove_leaf() {
        let (storage, _dir) = test_storage();
        let mut tree = SparseMerkleTree::new(&storage, ZoneId::from_legacy(0));

        let l1 = leaf(b"keep");
        let l2 = leaf(b"remove");

        tree.insert(&l1).unwrap();
        tree.insert(&l2).unwrap();
        let root_with_both = tree.root().unwrap();

        tree.remove(&l2).unwrap();
        let root_after_remove = tree.root().unwrap();

        assert_ne!(root_with_both, root_after_remove, "root should change after remove");
    }

    #[test]
    fn test_remove_all_leaves_returns_empty() {
        let (storage, _dir) = test_storage();
        let mut tree = SparseMerkleTree::new(&storage, ZoneId::from_legacy(0));

        let l = leaf(b"solo");
        tree.insert(&l).unwrap();
        assert_ne!(tree.root().unwrap(), EMPTY_HASH);

        tree.remove(&l).unwrap();
        assert_eq!(tree.root().unwrap(), EMPTY_HASH, "removing all leaves should yield empty root");
    }

    #[test]
    fn test_remove_nonexistent_returns_false() {
        let (storage, _dir) = test_storage();
        let mut tree = SparseMerkleTree::new(&storage, ZoneId::from_legacy(0));
        let removed = tree.remove(&leaf(b"never_inserted")).unwrap();
        assert!(!removed, "removing non-existent leaf should return false");
    }

    // ── Persistence ────────────────────────────────────────────────────────

    #[test]
    fn test_commit_persists_across_instances() {
        let (storage, _dir) = test_storage();

        let l1 = leaf(b"persistent_1");
        let l2 = leaf(b"persistent_2");

        // Insert and commit
        {
            let mut tree = SparseMerkleTree::new(&storage, ZoneId::from_legacy(0));
            tree.insert(&l1).unwrap();
            tree.insert(&l2).unwrap();
            tree.commit().unwrap();
        }

        // New tree instance should see the same root
        {
            let tree = SparseMerkleTree::new(&storage, ZoneId::from_legacy(0));
            let root = tree.root().unwrap();
            assert_ne!(root, EMPTY_HASH);

            // Proofs should still work
            let proof = tree.proof(&l1).unwrap().unwrap();
            assert!(verify_proof(&proof));
        }
    }

    #[test]
    fn test_persistence_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let l = leaf(b"survive_reopen");
        let root_before;

        // Write and commit
        {
            let storage = StorageEngine::open(dir.path()).unwrap();
            let mut tree = SparseMerkleTree::new(&storage, ZoneId::from_legacy(0));
            tree.insert(&l).unwrap();
            tree.commit().unwrap();
            root_before = tree.root().unwrap();
        }

        // Reopen and verify
        {
            let storage = StorageEngine::open(dir.path()).unwrap();
            let tree = SparseMerkleTree::new(&storage, ZoneId::from_legacy(0));
            assert_eq!(tree.root().unwrap(), root_before);
            let proof = tree.proof(&l).unwrap().unwrap();
            assert!(verify_proof(&proof));
        }
    }

    // ── Leaf tracking ──────────────────────────────────────────────────────

    #[test]
    fn test_leaf_count() {
        let (storage, _dir) = test_storage();
        let mut tree = SparseMerkleTree::new(&storage, ZoneId::from_legacy(0));

        assert_eq!(tree.leaf_count().unwrap(), 0);

        tree.insert(&leaf(b"a")).unwrap();
        assert_eq!(tree.leaf_count().unwrap(), 1);

        tree.insert(&leaf(b"b")).unwrap();
        assert_eq!(tree.leaf_count().unwrap(), 2);

        tree.remove(&leaf(b"a")).unwrap();
        assert_eq!(tree.leaf_count().unwrap(), 1);
    }

    #[test]
    fn test_leaf_count_malformed_bytes_returns_zero() {
        // Corrupt the count key with wrong-length bytes; leaf_count must return
        // Ok(0) rather than panicking (the old .expect() path).
        let (storage, _dir) = test_storage();
        let zone = ZoneId::from_legacy(0);
        let mut tree = SparseMerkleTree::new(&storage, zone.clone());
        tree.insert(&leaf(b"x")).unwrap();
        tree.commit().unwrap();
        assert_eq!(tree.leaf_count().unwrap(), 1);

        let ck = count_key(&zone);
        storage.put_cf_raw(CF_MERKLE, &ck, &[0x01, 0x02, 0x03]).unwrap(); // 3 bytes, not 8
        let tree2 = SparseMerkleTree::new(&storage, zone);
        assert_eq!(tree2.leaf_count().unwrap(), 0, "malformed count falls back to 0");
    }

    #[test]
    fn test_contains() {
        let (storage, _dir) = test_storage();
        let mut tree = SparseMerkleTree::new(&storage, ZoneId::from_legacy(0));

        let l = leaf(b"check_contains");
        assert!(!tree.contains(&l).unwrap());

        tree.insert(&l).unwrap();
        assert!(tree.contains(&l).unwrap());

        tree.remove(&l).unwrap();
        assert!(!tree.contains(&l).unwrap());
    }

    #[test]
    fn test_all_leaves() {
        let (storage, _dir) = test_storage();
        let mut tree = SparseMerkleTree::new(&storage, ZoneId::from_legacy(0));

        let leaves: Vec<[u8; 32]> = (0..5u8).map(|i| leaf(&[i])).collect();
        for l in &leaves {
            tree.insert(l).unwrap();
        }

        let mut all = tree.all_leaves().unwrap();
        all.sort();
        let mut expected = leaves.clone();
        expected.sort();
        assert_eq!(all, expected);
    }

    // ── Multi-zone ─────────────────────────────────────────────────────────

    #[test]
    fn test_separate_zones() {
        let (storage, _dir) = test_storage();

        let l1 = leaf(b"zone0_leaf");
        let l2 = leaf(b"zone1_leaf");

        let mut tree0 = SparseMerkleTree::new(&storage, ZoneId::from_legacy(0));
        tree0.insert(&l1).unwrap();
        tree0.commit().unwrap();

        let mut tree1 = SparseMerkleTree::new(&storage, ZoneId::from_legacy(1));
        tree1.insert(&l2).unwrap();
        tree1.commit().unwrap();

        // Roots should be different
        let tree0 = SparseMerkleTree::new(&storage, ZoneId::from_legacy(0));
        let tree1 = SparseMerkleTree::new(&storage, ZoneId::from_legacy(1));
        assert_ne!(tree0.root().unwrap(), tree1.root().unwrap());

        // Each zone only has its own leaf
        assert!(tree0.contains(&l1).unwrap());
        assert!(!tree0.contains(&l2).unwrap());
        assert!(!tree1.contains(&l1).unwrap());
        assert!(tree1.contains(&l2).unwrap());
    }

    // ── Performance ────────────────────────────────────────────────────────

    #[test]
    fn test_large_tree_10k_leaves() {
        let (storage, _dir) = test_storage();
        let mut tree = SparseMerkleTree::new(&storage, ZoneId::from_legacy(0));

        let leaves: Vec<[u8; 32]> = (0..10_000u32)
            .map(|i| sha3_256(&i.to_be_bytes()))
            .collect();

        // Insert all leaves
        for l in &leaves {
            tree.insert(l).unwrap();
        }
        tree.commit().unwrap();

        let root = tree.root().unwrap();
        assert_ne!(root, EMPTY_HASH);
        assert_eq!(tree.leaf_count().unwrap(), 10_000);

        // Verify proofs for a sample of leaves
        let tree = SparseMerkleTree::new(&storage, ZoneId::from_legacy(0));
        for l in leaves.iter().take(100) {
            let proof = tree.proof(l).unwrap()
                .expect("proof should exist for inserted leaf");
            assert!(verify_proof(&proof), "proof should verify");
        }
    }

    // ── Edge cases ─────────────────────────────────────────────────────────

    #[test]
    fn test_duplicate_insert() {
        let (storage, _dir) = test_storage();
        let mut tree = SparseMerkleTree::new(&storage, ZoneId::from_legacy(0));

        let l = leaf(b"dup");
        tree.insert(&l).unwrap();
        let root1 = tree.root().unwrap();

        // Inserting the same leaf again shouldn't change the root
        // (path overwrites with same value)
        tree.insert(&l).unwrap();
        let root2 = tree.root().unwrap();
        assert_eq!(root1, root2, "duplicate insert should not change root");
    }

    #[test]
    fn test_empty_hash_is_sha3_of_empty() {
        // Verify our constant matches
        assert_eq!(EMPTY_HASH, sha3_256(b""));
    }

    #[test]
    fn test_cross_zone_proof_verification() {
        let (engine, _dir) = test_storage();
        let zone_a = ZoneId::from_legacy(0);
        let zone_b = ZoneId::from_legacy(1);

        let mut tree_b = SparseMerkleTree::new(&engine, zone_b.clone());
        let leaf_hash = leaf(b"record-abc");
        tree_b.insert(&leaf_hash).unwrap();
        let root = tree_b.root().unwrap();
        let merkle_proof = tree_b.proof(&leaf_hash).unwrap().unwrap();

        // Valid cross-zone proof
        let proof = CrossZoneProof {
            record_id: "record-abc".to_string(),
            record_hash: leaf_hash,
            source_zone: zone_a.clone(),
            target_zone: zone_b.clone(),
            target_epoch: 42,
            merkle_proof: merkle_proof.clone(),
            seal_merkle_root: root,
            seal_record_id: "seal-42".to_string(),
        };
        let result = verify_cross_zone_proof(&proof);
        assert!(result.proof_valid);
        assert!(result.root_matches_seal);
        assert!(result.zone_matches);
        assert!(result.leaf_matches);
        assert!(result.verified);

        // Tampered root → fails root_matches_seal
        let mut bad_proof = proof.clone();
        bad_proof.seal_merkle_root = [0u8; 32];
        let result = verify_cross_zone_proof(&bad_proof);
        assert!(result.proof_valid); // proof itself still valid
        assert!(!result.root_matches_seal);
        assert!(!result.verified);

        // Wrong record hash → fails leaf_matches
        let mut bad_leaf = proof.clone();
        bad_leaf.record_hash = [1u8; 32];
        let result = verify_cross_zone_proof(&bad_leaf);
        assert!(!result.leaf_matches);
        assert!(!result.verified);
    }

    // ============================================================
    // fixture-free, pure helpers
    // ============================================================

    #[test]
    fn batch_b_max_depth_strict_pin_with_u64_path_alignment_and_2_pow_64_leaf_invariant() {
        // MAX_DEPTH=64 is load-bearing — it equals the bit-width of the u64
        // path encoded by leaf_to_path. Drift to e.g. 32 or 65 would either
        // truncate the leaf address space (collisions become possible) or
        // exceed the path-bit operations' valid range.
        assert_eq!(MAX_DEPTH, 64);
        // Type pin: MAX_DEPTH is u8 — 1-byte field in node_key encoding.
        let _t: u8 = MAX_DEPTH;
        // Alignment: bits-of-u64 == MAX_DEPTH (path arithmetic depends on this).
        assert_eq!(u64::BITS, MAX_DEPTH as u32);
        // Max leaf count notation: 2^MAX_DEPTH = address space size.
        // u128 fits 2^64 without overflow.
        let max_leaves: u128 = 1u128 << MAX_DEPTH as u32;
        assert_eq!(max_leaves, 1u128 << 64);
        assert_eq!(max_leaves, u64::MAX as u128 + 1);
        // path_mask boundary alignment: path_mask(_, MAX_DEPTH) == identity.
        assert_eq!(path_mask(0x1234_5678_9ABC_DEF0, MAX_DEPTH), 0x1234_5678_9ABC_DEF0);
        assert_eq!(path_mask(u64::MAX, MAX_DEPTH), u64::MAX);
    }

    #[test]
    fn batch_b_path_helpers_bit_manipulation_exhaustive_pin() {
        // ── leaf_to_path: first 8 bytes BE, remaining 24 ignored ────────
        let mut leaf32 = [0u8; 32];
        leaf32[..8].copy_from_slice(&[0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0]);
        assert_eq!(leaf_to_path(&leaf32), 0x1234_5678_9ABC_DEF0u64);
        // Bytes 8..32 must not affect the path — flip them all and verify
        // path is unchanged.
        let mut leaf_noisy = leaf32;
        leaf_noisy[8..].fill(0xFF);
        assert_eq!(leaf_to_path(&leaf_noisy), leaf_to_path(&leaf32));
        // All-zero leaf → path = 0.
        assert_eq!(leaf_to_path(&[0u8; 32]), 0);
        // All-0xFF leaf → path = u64::MAX.
        assert_eq!(leaf_to_path(&[0xFFu8; 32]), u64::MAX);

        // ── path_bit: depth 0 = MSB, depth 63 = LSB ────────────────────
        // Depth 0 reads the top bit.
        assert!(path_bit(0x8000_0000_0000_0000, 0));
        assert!(!path_bit(0x7FFF_FFFF_FFFF_FFFF, 0));
        // Depth 63 reads the bottom bit.
        assert!(path_bit(0x0000_0000_0000_0001, 63));
        assert!(!path_bit(0xFFFF_FFFF_FFFF_FFFE, 63));
        // All-zero path: every bit is 0.
        for d in 0u8..64 {
            assert!(!path_bit(0, d), "depth {d} of zero path");
        }
        // All-one path: every bit is 1.
        for d in 0u8..64 {
            assert!(path_bit(u64::MAX, d), "depth {d} of all-ones path");
        }

        // ── path_mask: keeps top N bits, zeros the rest ────────────────
        // Boundary: depth 0 → zero out everything.
        assert_eq!(path_mask(u64::MAX, 0), 0);
        assert_eq!(path_mask(0x1234_5678_9ABC_DEF0, 0), 0);
        // Boundary: depth 1 → keep only MSB.
        assert_eq!(path_mask(u64::MAX, 1), 0x8000_0000_0000_0000);
        // Depth 2 → keep top 2 bits.
        assert_eq!(path_mask(u64::MAX, 2), 0xC000_0000_0000_0000);
        // Depth 4 → keep top nibble.
        assert_eq!(path_mask(u64::MAX, 4), 0xF000_0000_0000_0000);
        // Depth 8 → keep top byte.
        assert_eq!(path_mask(u64::MAX, 8), 0xFF00_0000_0000_0000);
        // Depth >= 64 saturates to identity (overflow-safe).
        assert_eq!(path_mask(u64::MAX, 64), u64::MAX);
        assert_eq!(path_mask(u64::MAX, 100), u64::MAX);
        // Composition pin: path_mask is idempotent within range.
        let p = 0xABCD_1234_5678_9ABCu64;
        assert_eq!(path_mask(path_mask(p, 16), 16), path_mask(p, 16));
        // path_mask preserves the path_bit result at every kept depth.
        for d in 1u8..=16 {
            let masked = path_mask(p, d);
            for kept in 0..d {
                assert_eq!(
                    path_bit(masked, kept),
                    path_bit(p, kept),
                    "kept bit {kept} after mask at depth {d}"
                );
            }
            // Bits beyond depth must be zero in the mask.
            if d < 63 {
                assert!(!path_bit(masked, d), "bit at depth {d} (one past mask) must be 0");
            }
        }
    }

    #[test]
    fn batch_b_node_key_leaf_key_count_key_byte_layout_and_length_disjointness_pin() {
        let zone = ZoneId::from_legacy(0xABCD);
        let zone_bytes = zone.to_key_bytes();
        assert_eq!(zone_bytes.len(), 8, "ZoneId key encoding is 8 bytes");

        // node_key: 8 (zone) + 1 (depth) + 8 (path BE) = 17 bytes.
        let nk = node_key(&zone, 7, 0x1234_5678_9ABC_DEF0);
        assert_eq!(nk.len(), 17);
        assert_eq!(&nk[..8], &zone_bytes[..]);
        assert_eq!(nk[8], 7);
        assert_eq!(&nk[9..17], &0x1234_5678_9ABC_DEF0u64.to_be_bytes());

        // leaf_key: 5 (b"leaf:") + 8 (zone) + 32 (leaf_hash) = 45 bytes.
        let leaf_hash = [0x5Au8; 32];
        let lk = leaf_key(&zone, &leaf_hash);
        assert_eq!(lk.len(), 45);
        assert_eq!(&lk[..5], b"leaf:");
        assert_eq!(&lk[5..13], &zone_bytes[..]);
        assert_eq!(&lk[13..45], &leaf_hash[..]);

        // count_key: 6 (b"count:") + 8 (zone) = 14 bytes.
        let ck = count_key(&zone);
        assert_eq!(ck.len(), 14);
        assert_eq!(&ck[..6], b"count:");
        assert_eq!(&ck[6..14], &zone_bytes[..]);

        // LENGTH disjointness — same-zone keys CANNOT collide regardless
        // of content because their byte lengths are pairwise distinct:
        //   node_key=17, leaf_key=45, count_key=14.
        // This is the load-bearing keyspace-partitioning invariant for the
        // single CF_MERKLE column family.
        assert_ne!(nk.len(), lk.len());
        assert_ne!(nk.len(), ck.len());
        assert_ne!(lk.len(), ck.len());

        // Prefix-tag disjointness: leaf_key and count_key use ASCII-prefixed
        // namespaces; the prefix first-bytes are distinct so a prefix scan
        // for one type cannot match the other.
        assert_ne!(b"leaf:"[0], b"count:"[0]);
        assert!(!b"count:".starts_with(b"leaf:"));
        assert!(!b"leaf:".starts_with(b"count:"));
    }

    #[test]
    fn batch_b_verify_proof_zero_depth_and_single_sibling_is_right_semantics_with_tamper_sweep() {
        // ── Zero-depth proof: empty siblings → reconstructed root == leaf ─
        // verify_proof must return true iff proof.leaf == proof.root.
        let leaf_bytes = [0xAAu8; 32];
        let proof_id = SparseMerkleProof {
            leaf: leaf_bytes,
            root: leaf_bytes,
            siblings: vec![],
            zone: ZoneId::from_legacy(0),
        };
        assert!(verify_proof(&proof_id));
        // Same proof with mismatched root → false.
        let proof_bad = SparseMerkleProof {
            leaf: leaf_bytes,
            root: [0xBBu8; 32],
            siblings: vec![],
            zone: ZoneId::from_legacy(0),
        };
        assert!(!verify_proof(&proof_bad));

        // ── Single-sibling: is_right semantics ──────────────────────────
        // is_right=true: combined = current(32) ++ sibling(32)
        // is_right=false: combined = sibling(32) ++ current(32)
        // Two orderings produce DIFFERENT intermediate hashes whenever
        // current != sibling — the commutativity break is what gives the
        // proof its position-binding power.
        let sibling = [0xCCu8; 32];
        let mut right_buf = [0u8; 64];
        right_buf[..32].copy_from_slice(&leaf_bytes);
        right_buf[32..].copy_from_slice(&sibling);
        let expected_right = sha3_256(&right_buf);

        let mut left_buf = [0u8; 64];
        left_buf[..32].copy_from_slice(&sibling);
        left_buf[32..].copy_from_slice(&leaf_bytes);
        let expected_left = sha3_256(&left_buf);

        assert_ne!(expected_right, expected_left, "is_right flip must change hash");

        // Build a proof where verify uses is_right=true.
        let p_right = SparseMerkleProof {
            leaf: leaf_bytes,
            root: expected_right,
            siblings: vec![SparseMerkleProofNode { hash: sibling, is_right: true }],
            zone: ZoneId::from_legacy(0),
        };
        assert!(verify_proof(&p_right));
        // Same hashes but flip is_right → must fail (root mismatch).
        let p_right_flipped = SparseMerkleProof {
            leaf: leaf_bytes,
            root: expected_right, // root still expects right-ordering
            siblings: vec![SparseMerkleProofNode { hash: sibling, is_right: false }],
            zone: ZoneId::from_legacy(0),
        };
        assert!(!verify_proof(&p_right_flipped));

        // ── Tamper sweep: flipping any single byte in the sibling breaks ─
        for byte_idx in [0usize, 7, 15, 23, 31] {
            let mut tampered = sibling;
            tampered[byte_idx] ^= 0x01;
            let p_tampered = SparseMerkleProof {
                leaf: leaf_bytes,
                root: expected_right,
                siblings: vec![SparseMerkleProofNode { hash: tampered, is_right: true }],
                zone: ZoneId::from_legacy(0),
            };
            assert!(
                !verify_proof(&p_tampered),
                "tampered byte {byte_idx} must invalidate the proof"
            );
        }
    }

    #[test]
    fn batch_b_cross_zone_verification_four_flag_conjunction_with_each_flag_independent_flip() {
        // Build a synthetic but mathematically valid base proof: empty
        // siblings means reconstructed root == leaf, so verify_proof
        // passes iff proof.leaf == proof.root.
        let h = [0xAAu8; 32];
        let zone_b = ZoneId::from_legacy(7);
        let base_smp = SparseMerkleProof {
            leaf: h,
            root: h,
            siblings: vec![],
            zone: zone_b.clone(),
        };
        let base = CrossZoneProof {
            record_id: "rid".into(),
            record_hash: h,
            source_zone: ZoneId::from_legacy(0),
            target_zone: zone_b.clone(),
            target_epoch: 1,
            merkle_proof: base_smp.clone(),
            seal_merkle_root: h,
            seal_record_id: "seal".into(),
        };
        let v = verify_cross_zone_proof(&base);
        assert!(v.proof_valid && v.root_matches_seal && v.zone_matches && v.leaf_matches);
        assert!(v.verified, "all 4 flags true → verified true");

        // CrossZoneVerification struct shape: 5 boolean fields, serde
        // round-trips with exactly those keys.
        let json = serde_json::to_value(&v).expect("serialize verification");
        let obj = json.as_object().expect("verification serializes to object");
        let mut keys: Vec<&str> = obj.keys().map(|s| s.as_str()).collect();
        keys.sort();
        assert_eq!(
            keys,
            vec![
                "leaf_matches",
                "proof_valid",
                "root_matches_seal",
                "verified",
                "zone_matches"
            ]
        );
        for k in &keys {
            assert!(obj[*k].is_boolean(), "{k} must serialize as bool");
        }

        // ── Each input flag independently flips verified to false ──────

        // (a) Break proof_valid: set root != leaf with empty siblings.
        let mut bad = base.clone();
        bad.merkle_proof = SparseMerkleProof {
            leaf: h,
            root: [0xBBu8; 32], // != leaf → reconstructed root != root
            siblings: vec![],
            zone: zone_b.clone(),
        };
        bad.seal_merkle_root = [0xBBu8; 32]; // keep root_matches_seal true
        let v = verify_cross_zone_proof(&bad);
        assert!(!v.proof_valid);
        assert!(v.root_matches_seal);
        assert!(v.zone_matches);
        assert!(v.leaf_matches);
        assert!(!v.verified, "proof_valid=false flips verified");

        // (b) Break root_matches_seal: seal_merkle_root != merkle_proof.root.
        let mut bad = base.clone();
        bad.seal_merkle_root = [0xCCu8; 32];
        let v = verify_cross_zone_proof(&bad);
        assert!(v.proof_valid);
        assert!(!v.root_matches_seal);
        assert!(v.zone_matches);
        assert!(v.leaf_matches);
        assert!(!v.verified, "root_matches_seal=false flips verified");

        // (c) Break zone_matches: target_zone != merkle_proof.zone.
        let mut bad = base.clone();
        bad.target_zone = ZoneId::from_legacy(99);
        let v = verify_cross_zone_proof(&bad);
        assert!(v.proof_valid);
        assert!(v.root_matches_seal);
        assert!(!v.zone_matches);
        assert!(v.leaf_matches);
        assert!(!v.verified, "zone_matches=false flips verified");

        // (d) Break leaf_matches: record_hash != merkle_proof.leaf.
        let mut bad = base.clone();
        bad.record_hash = [0xDDu8; 32];
        let v = verify_cross_zone_proof(&bad);
        assert!(v.proof_valid);
        assert!(v.root_matches_seal);
        assert!(v.zone_matches);
        assert!(!v.leaf_matches);
        assert!(!v.verified, "leaf_matches=false flips verified");
    }

    #[test]
    fn leaf_to_path_boundary() {
        // all-zeros → path 0
        assert_eq!(leaf_to_path(&[0u8; 32]), 0u64);
        // all-ones → path u64::MAX
        assert_eq!(leaf_to_path(&[0xFFu8; 32]), u64::MAX);
        // first 8 bytes determine path; remaining bytes are ignored
        let mut h = [0u8; 32];
        h[0] = 0x01;
        assert_eq!(leaf_to_path(&h), 0x0100_0000_0000_0000u64);
        h[7] = 0xFF;
        assert_eq!(leaf_to_path(&h), 0x0100_0000_0000_00FFu64);
    }
}
