//! Key-addressed **sparse Merkle tree** (SMT) in safe Rust — compact,
//! collision-safe state proofs over a 256-bit key space, generic over the
//! backing store.
//!
//! A leaf's position is the **full** `SHA3-256(key)` (256 bits), *not* a
//! truncation, so two distinct keys share a position only on a true SHA3-256
//! collision (≈2¹²⁸ work) — there is no birthday-bound "silent overwrite" of
//! one honest account by another, even at billions of keys. The leaf hash
//! **binds the key** (`SHA3-256(LEAF_TAG ‖ key ‖ value)`) and interior nodes are
//! domain-separated (`SHA3-256(NODE_TAG ‖ left ‖ right)`), so a proof for key A
//! can never be reinterpreted as a proof for key B and a leaf can never be
//! confused with an interior node (second-preimage hardening).
//!
//! Empty subtrees collapse to a single sentinel ([`EMPTY_HASH`] = `SHA3-256("")`),
//! so a tree over billions of sparsely-populated keys stores only `O(N·log N)`
//! interior nodes. Proofs are **empty-subtree-compressed**: instead of a fixed
//! `MAX_DEPTH` siblings, a proof carries a 256-bit presence bitmap plus only the
//! non-empty siblings — `≈ log₂(N)` hashes regardless of depth. At 1B keys a
//! proof is ~30 siblings (~1 KB), *smaller* than a fixed 64-deep proof, which
//! keeps the light-client SDK viable on phone / WASM / `no_std` clients.
//!
//! A light client verifies "key K maps to value V" ([`verify_proof`]) or "key K
//! is absent" ([`verify_exclusion_proof`]) by folding the compressed siblings
//! back to a root and comparing to a root it already trusts (e.g. one signed into
//! a checkpoint). Both verifiers are stateless and storage-free.
//!
//! # Pluggable storage
//!
//! The tree is generic over [`SmtStore`] — any key→`[u8; 32]` store. An
//! in-memory [`MemorySmtStore`] ships for tests and embedding; a database-backed
//! store is a dozen lines (`get` + a batched `write_batch`). Pending writes are
//! buffered in-memory and flushed atomically by [`SparseMerkleTree::commit`].
//!
//! ```
//! use elara_smt::{SparseMerkleTree, MemorySmtStore, verify_proof};
//!
//! let mut tree = SparseMerkleTree::new(MemorySmtStore::new());
//! let key = [7u8; 32];
//! let value = [9u8; 32];                       // e.g. SHA3-256 of some state
//! tree.update(&key, &value).unwrap();
//! tree.commit().unwrap();
//!
//! let proof = tree.proof(&key).unwrap().expect("key present");
//! assert!(verify_proof(&proof));               // folds compressed siblings to root
//! assert_eq!(proof.root, tree.root().unwrap());
//! ```
//!
//! Extracted from the [Elara Protocol](https://github.com/navigatorbuilds/elara-mesh)
//! node, where it authenticates global account state; the algebra here carries no
//! protocol dependencies.

#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

/// Deserialize a proof's sibling list, bounding it to [`MAX_DEPTH`] (256)
/// *during* decode. A genuine compressed proof carries at most one sibling per
/// tree level, so a longer list is malformed. Without this gate a hostile blob
/// (`siblings: [ …10M entries… ]`) would allocate hundreds of MB before
/// [`verify_proof`] ever runs — a deserialize-time amplification on a verifier
/// that, by design, decodes proof bytes received from untrusted peers. The
/// visitor caps the pre-allocation and stops at element 257, so the work stays
/// bounded regardless of the attacker's claimed length.
fn deserialize_bounded_siblings<'de, D>(d: D) -> Result<Vec<[u8; 32]>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct BoundedSiblings;
    impl<'de> serde::de::Visitor<'de> for BoundedSiblings {
        type Value = Vec<[u8; 32]>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "at most {MAX_DEPTH} 32-byte siblings")
        }
        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let cap = seq.size_hint().unwrap_or(0).min(MAX_DEPTH as usize);
            let mut out = Vec::with_capacity(cap);
            while let Some(elem) = seq.next_element::<[u8; 32]>()? {
                if out.len() >= MAX_DEPTH as usize {
                    return Err(serde::de::Error::custom(format!(
                        "sibling list exceeds MAX_DEPTH ({MAX_DEPTH})"
                    )));
                }
                out.push(elem);
            }
            Ok(out)
        }
    }
    d.deserialize_seq(BoundedSiblings)
}

// ─── Hashing ──────────────────────────────────────────────────────────────────

/// SHA3-256 of `data`. The single hash primitive used for leaves, interior
/// nodes, and the empty sentinel.
fn sha3_256(data: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

// ─── Constants ─────────────────────────────────────────────────────────────────

/// Maximum tree depth — the path is the full 256-bit `SHA3-256(key)`, so the
/// tree is 256 levels deep. Proofs are compressed (see [`SmtProof`]), so the
/// sibling *count* is `≈ log₂(N)`, not `MAX_DEPTH`. `u16` because 256 > `u8::MAX`.
pub const MAX_DEPTH: u16 = 256;

/// Domain-separation tag prefixed to a **leaf** preimage:
/// `leaf = SHA3-256([LEAF_TAG] ‖ key ‖ value)`. Distinct from `NODE_TAG` so a
/// leaf hash can never collide with an interior-node hash.
const LEAF_TAG: u8 = 0x00;

/// Domain-separation tag prefixed to an **interior-node** preimage:
/// `node = SHA3-256([NODE_TAG] ‖ left ‖ right)`.
const NODE_TAG: u8 = 0x01;

/// Empty-subtree sentinel — `SHA3-256("")`. A subtree with no populated leaves
/// hashes to this value at every level, which is what makes the tree "sparse".
pub const EMPTY_HASH: [u8; 32] = [
    0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66,
    0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62,
    0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa,
    0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a,
];

/// The empty-tree root (== [`EMPTY_HASH`]).
pub fn empty_hash() -> [u8; 32] {
    EMPTY_HASH
}

// ─── Node hashing (domain-separated) ─────────────────────────────────────────

/// Leaf hash: binds the key and value under `LEAF_TAG`. Two accounts with the
/// same `value` (e.g. both at default/zero state) still produce **distinct**
/// leaves because the key is bound in — so a proof for one can never verify as
/// the other.
pub fn leaf_hash(key: &[u8; 32], value: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 1 + 32 + 32];
    buf[0] = LEAF_TAG;
    buf[1..33].copy_from_slice(key);
    buf[33..65].copy_from_slice(value);
    sha3_256(&buf)
}

/// Interior-node hash: combines two child hashes under `NODE_TAG`.
pub fn interior_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 1 + 32 + 32];
    buf[0] = NODE_TAG;
    buf[1..33].copy_from_slice(left);
    buf[33..65].copy_from_slice(right);
    sha3_256(&buf)
}

// ─── Key encoding ──────────────────────────────────────────────────────────────

/// Interior/leaf node store-key: `"n:"` + depth (2B BE) + path_prefix (32B) = 36 bytes.
fn node_key(depth: u16, path_prefix: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(2 + 2 + 32);
    key.extend_from_slice(b"n:");
    key.extend_from_slice(&depth.to_be_bytes());
    key.extend_from_slice(path_prefix);
    key
}

/// Leaf-value store-key: `"v:"` + key (32B) = 34 bytes. Records the current
/// value for a key so a later update knows the prior leaf without walking.
fn value_key(account_id: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(2 + 32);
    key.extend_from_slice(b"v:");
    key.extend_from_slice(account_id);
    key
}

// ─── Path computation (256-bit, MSB-first) ──────────────────────────────────────

/// The 256-bit tree path of a key: the **full** `SHA3-256(key)`. A position
/// collision therefore requires a true SHA3-256 collision (≈2¹²⁸ work), not a
/// 64-bit birthday collision (≈2³²).
pub fn account_path(account_id: &[u8; 32]) -> [u8; 32] {
    sha3_256(account_id)
}

/// The bit at position `index` of a 256-bit value, MSB-first: index 0 is the
/// most-significant bit of byte 0; index 255 is the least-significant bit of
/// byte 31. Used for both paths and presence bitmaps. `index` must be `< 256`.
fn bit_get(bytes: &[u8; 32], index: u16) -> bool {
    let byte = (index / 8) as usize;
    let shift = 7 - (index % 8) as u8;
    (bytes[byte] >> shift) & 1 == 1
}

/// Set the MSB-first bit at position `index` (`< 256`).
fn bit_set(bytes: &mut [u8; 32], index: u16) {
    let byte = (index / 8) as usize;
    let mask = 0x80u8 >> (index % 8) as u8;
    bytes[byte] |= mask;
}

/// `path` keeping only the top `depth` bits (positions `0..depth`) and zeroing
/// the rest — the canonical prefix shared by every key routed through the node
/// at `(depth, _)`. `depth` ranges `0..=256`.
fn path_mask(path: &[u8; 32], depth: u16) -> [u8; 32] {
    let mut out = [0u8; 32];
    let full_bytes = (depth / 8) as usize;
    if full_bytes >= 32 {
        return *path; // depth >= 256: identity
    }
    out[..full_bytes].copy_from_slice(&path[..full_bytes]);
    let rem_bits = (depth % 8) as u8;
    if rem_bits > 0 {
        let mask = 0xFFu8 << (8 - rem_bits); // keep the top `rem_bits` of this byte
        out[full_bytes] = path[full_bytes] & mask;
    }
    out
}

// ─── Proof types ───────────────────────────────────────────────────────────────

/// Compressed **inclusion** proof: "key `account_id` maps to leaf value
/// `state_hash` in a tree rooted at `root`". Field names retain the node's
/// account-state flavour (`account_id` = the SMT key, `state_hash` = the leaf
/// *value*, pre-leaf-hash).
///
/// `present` is a 256-bit bitmap (MSB-first by parent depth): bit `d` set means
/// the sibling at parent-depth `d` is non-empty and appears in `siblings`; bit
/// clear means the sibling is [`EMPTY_HASH`] and is omitted. `siblings` lists
/// only the non-empty siblings, ordered from the leaf's parent (depth 255) up to
/// the root (depth 0) — i.e. by descending parent depth.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtProof {
    /// The 32-byte key being proven.
    pub account_id: [u8; 32],
    /// The leaf *value* at that key (the verifier rebuilds the leaf hash as
    /// `leaf_hash(account_id, state_hash)`).
    pub state_hash: [u8; 32],
    /// Root this proof folds to.
    pub root: [u8; 32],
    /// 256-bit presence bitmap (MSB-first by parent depth).
    pub present: [u8; 32],
    /// Non-empty siblings only, leaf-parent → root order.
    #[serde(deserialize_with = "deserialize_bounded_siblings")]
    pub siblings: Vec<[u8; 32]>,
}

/// Compressed **exclusion** (non-membership) proof: "key `account_id` is absent
/// from the tree rooted at `root`". The leaf position `SHA3-256(account_id)` is
/// empty; folding [`EMPTY_HASH`] at that position up the compressed siblings
/// reproduces `root`. Because the path is the full 256-bit hash, an absent key's
/// slot is genuinely empty (no collision can occupy it), so this is a sound
/// cryptographic non-membership proof — not a trust-the-server assertion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtExclusionProof {
    /// The 32-byte key being proven absent.
    pub account_id: [u8; 32],
    /// Root this proof folds to.
    pub root: [u8; 32],
    /// 256-bit presence bitmap (MSB-first by parent depth).
    pub present: [u8; 32],
    /// Non-empty siblings only, leaf-parent → root order.
    #[serde(deserialize_with = "deserialize_bounded_siblings")]
    pub siblings: Vec<[u8; 32]>,
}

/// Fold a compressed sibling set from a starting `leaf` hash at position
/// `path` up to a root. Returns the reconstructed root, or `None` if the
/// `present`/`siblings` shape is inconsistent (too few siblings, or leftover
/// siblings after the fold).
fn fold(
    path: &[u8; 32],
    leaf: [u8; 32],
    present: &[u8; 32],
    siblings: &[[u8; 32]],
) -> Option<[u8; 32]> {
    let mut current = leaf;
    let mut idx = 0usize;
    // parent_depth from 255 down to 0 (matches proof-generation order).
    let mut parent_depth = MAX_DEPTH; // 256
    while parent_depth > 0 {
        parent_depth -= 1; // 255 .. 0
        let sibling = if bit_get(present, parent_depth) {
            let s = *siblings.get(idx)?;
            idx += 1;
            s
        } else {
            EMPTY_HASH
        };
        let we_are_right = bit_get(path, parent_depth);
        let (left, right) = if we_are_right {
            (sibling, current)
        } else {
            (current, sibling)
        };
        // Mirror the tree's empty-subtree collapse exactly: both children empty
        // → EMPTY_HASH (not interior_hash(EMPTY, EMPTY)). Essential for exclusion
        // proofs, whose leaf starts EMPTY and passes through empty regions.
        current = if left == EMPTY_HASH && right == EMPTY_HASH {
            EMPTY_HASH
        } else {
            interior_hash(&left, &right)
        };
    }
    if idx != siblings.len() {
        return None; // extra siblings not consumed → malformed
    }
    Some(current)
}

/// Stateless **inclusion** verification. Returns `true` iff the compressed
/// siblings reconstruct `proof.root` from `leaf_hash(account_id, state_hash)`
/// along the path `SHA3-256(account_id)`.
pub fn verify_proof(proof: &SmtProof) -> bool {
    let path = account_path(&proof.account_id);
    let leaf = leaf_hash(&proof.account_id, &proof.state_hash);
    match fold(&path, leaf, &proof.present, &proof.siblings) {
        Some(root) => root == proof.root,
        None => false,
    }
}

/// Stateless **exclusion** (non-membership) verification. Returns `true` iff the
/// compressed siblings reconstruct `proof.root` from an empty leaf at position
/// `SHA3-256(account_id)`.
pub fn verify_exclusion_proof(proof: &SmtExclusionProof) -> bool {
    let path = account_path(&proof.account_id);
    match fold(&path, EMPTY_HASH, &proof.present, &proof.siblings) {
        Some(root) => root == proof.root,
        None => false,
    }
}

// ─── Store abstraction ───────────────────────────────────────────────────────

/// Backing key-value store for the tree. Keys are opaque byte strings the tree
/// derives internally; values are always 32-byte hashes.
///
/// Reads happen during `root`/`get`/`proof`/`update`; writes are buffered in the
/// tree and flushed in one atomic batch by [`SparseMerkleTree::commit`]. An
/// implementation that fails to apply a batch atomically can corrupt the tree.
pub trait SmtStore {
    /// Error surfaced by the backing store.
    type Error;

    /// Fetch the 32-byte value at `key`, or `None` if absent. A stored value of
    /// the wrong length must be reported as `None` (treated as an empty node).
    fn get(&self, key: &[u8]) -> Result<Option<[u8; 32]>, Self::Error>;

    /// Atomically apply all `puts` then `deletes`. `puts` and `deletes` never
    /// touch the same key within one call, so apply order is immaterial.
    fn write_batch(
        &mut self,
        puts: &[(Vec<u8>, [u8; 32])],
        deletes: &[Vec<u8>],
    ) -> Result<(), Self::Error>;
}

/// Convenience error for store implementations that don't have their own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmtError {
    /// Backing-store failure; the string describes the fault.
    Store(String),
}

impl std::fmt::Display for SmtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SmtError::Store(s) => write!(f, "SMT store error: {s}"),
        }
    }
}

impl std::error::Error for SmtError {}

/// In-memory [`SmtStore`] backed by a `HashMap`. Useful for tests, embedding,
/// and verifying proofs without a database. Never returns an error.
#[derive(Debug, Default, Clone)]
pub struct MemorySmtStore {
    map: HashMap<Vec<u8>, [u8; 32]>,
}

impl MemorySmtStore {
    /// A fresh, empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of stored entries (interior nodes + leaf values).
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// True if nothing is stored.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

impl SmtStore for MemorySmtStore {
    type Error = SmtError;

    fn get(&self, key: &[u8]) -> Result<Option<[u8; 32]>, Self::Error> {
        Ok(self.map.get(key).copied())
    }

    fn write_batch(
        &mut self,
        puts: &[(Vec<u8>, [u8; 32])],
        deletes: &[Vec<u8>],
    ) -> Result<(), Self::Error> {
        for (k, v) in puts {
            self.map.insert(k.clone(), *v);
        }
        for k in deletes {
            self.map.remove(k);
        }
        Ok(())
    }
}

// ─── Tree ──────────────────────────────────────────────────────────────────────

/// A 256-level key-addressed sparse Merkle tree over an [`SmtStore`].
///
/// Updates buffer in an in-memory write-through cache; [`commit`](Self::commit)
/// flushes them to the store atomically. [`root`](Self::root),
/// [`get`](Self::get), [`proof`](Self::proof), and
/// [`exclusion_proof`](Self::exclusion_proof) read through the cache, so an
/// uncommitted tree answers consistently with what will be persisted.
pub struct SparseMerkleTree<S: SmtStore> {
    store: S,
    /// In-memory write-through cache of interior/leaf node hashes, keyed by
    /// `(depth, masked-path)`.
    cache: HashMap<(u16, [u8; 32]), [u8; 32]>,
    /// Pending deletions (interior **and leaf** nodes that collapsed back to
    /// empty). A set, not a Vec: `get_node`/`set_node` test and remove membership
    /// on every node touched during `recompute_path`, so a Vec makes a
    /// deletion-heavy flush O(D^2). Batch-apply order is irrelevant (distinct key
    /// removals commute, and `cache`/`pending_values` already iterate in HashMap
    /// order).
    deletes: HashSet<(u16, [u8; 32])>,
    /// Pending value-key writes (key -> new leaf *value*).
    pending_values: HashMap<[u8; 32], [u8; 32]>,
    /// Pending value-key *removals* (keys whose `v:` record must be deleted on
    /// commit, set by [`delete`](Self::delete)). Distinct from `deletes`, which
    /// tracks `n:` tree-node keys; this tracks the `v:` value lookups that back
    /// `get`/`proof`. Kept mutually exclusive with `pending_values`
    /// (`update` clears membership here; `delete` clears it there) so a key is
    /// never simultaneously put and deleted in one `write_batch`.
    pending_value_deletes: HashSet<[u8; 32]>,
}

/// Compressed sibling set along a path: a 256-bit presence bitmap plus the
/// non-empty siblings in leaf-parent → root order.
type CompressedSiblings = ([u8; 32], Vec<[u8; 32]>);

impl<S: SmtStore> SparseMerkleTree<S> {
    /// Wrap a store. No I/O happens until the first read or [`commit`](Self::commit).
    pub fn new(store: S) -> Self {
        Self {
            store,
            cache: HashMap::new(),
            deletes: HashSet::new(),
            pending_values: HashMap::new(),
            pending_value_deletes: HashSet::new(),
        }
    }

    /// Borrow the backing store.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Consume the tree and return the backing store.
    pub fn into_store(self) -> S {
        self.store
    }

    /// Current root hash. [`EMPTY_HASH`] for a fresh tree.
    pub fn root(&self) -> Result<[u8; 32], S::Error> {
        self.get_node(0, &[0u8; 32])
    }

    /// Current value recorded for `account_id`, or `None` if absent. A buffered
    /// [`delete`](Self::delete) wins over any previously-committed value, so a
    /// deleted-but-uncommitted key reads `None` (and thus yields an exclusion
    /// proof, not a stale inclusion proof).
    pub fn get(&self, account_id: &[u8; 32]) -> Result<Option<[u8; 32]>, S::Error> {
        if self.pending_value_deletes.contains(account_id) {
            return Ok(None);
        }
        if let Some(h) = self.pending_values.get(account_id) {
            return Ok(Some(*h));
        }
        self.store.get(&value_key(account_id))
    }

    /// Upsert `account_id -> state_hash`. Touches `O(MAX_DEPTH)` interior nodes.
    /// The stored leaf is `leaf_hash(account_id, state_hash)` (identity-bound);
    /// the raw `state_hash` value is recorded separately for `get`/`proof`.
    pub fn update(&mut self, account_id: &[u8; 32], state_hash: &[u8; 32]) -> Result<(), S::Error> {
        let path = account_path(account_id);
        let leaf = leaf_hash(account_id, state_hash);
        self.set_node(MAX_DEPTH, &path, leaf);
        self.pending_value_deletes.remove(account_id);
        self.pending_values.insert(*account_id, *state_hash);
        self.recompute_path(&path)?;
        Ok(())
    }

    /// Remove `account_id` from the tree: collapse its leaf to [`EMPTY_HASH`] and
    /// fold the now-empty subtree back up, exactly as if the key had never been
    /// inserted. Idempotent — deleting an absent key is a no-op that leaves the
    /// root unchanged.
    ///
    /// This is the tombstone primitive a node needs when an account is *removed*
    /// from the ledger (e.g. the chain-divergence repair path): without it the
    /// only mutation is [`update`](Self::update), which always writes a non-empty
    /// `leaf_hash` — so a removed account flushed as `hash(AccountState::default())`
    /// becomes a permanent **ghost leaf** that diverges the persisted
    /// `account_smt_root` from the canonical root and silently corrupts the slot's
    /// light-client exclusion proof. `delete` collapses the slot to genuinely
    /// empty, so after commit `get` returns `None` and the key yields a valid
    /// [`exclusion_proof`](Self::exclusion_proof).
    ///
    /// The root after deleting key `A` from `{A, B, …}` is **byte-identical** to a
    /// fresh tree built from `{B, …}` — the leaf position is the full
    /// `SHA3-256(account_id)` and the empty-subtree collapse is the same fold used
    /// for interior nodes, so removal is a pure inverse of insertion. Touches
    /// `O(MAX_DEPTH)` nodes, like `update`.
    pub fn delete(&mut self, account_id: &[u8; 32]) -> Result<(), S::Error> {
        let path = account_path(account_id);
        // Collapse the leaf node (depth 256) to empty, mirroring how
        // `recompute_path` retires an emptied interior node: drop any buffered
        // leaf and record the node-key deletion so `get_node` reads EMPTY_HASH.
        let masked = path_mask(&path, MAX_DEPTH); // depth 256 → identity (== path)
        self.cache.remove(&(MAX_DEPTH, masked));
        self.deletes.insert((MAX_DEPTH, masked));
        // Drop the buffered value and schedule the `v:` value-key removal so the
        // committed lookup no longer answers `get`/`proof` for this key.
        self.pending_values.remove(account_id);
        self.pending_value_deletes.insert(*account_id);
        // Fold the empty leaf up to the root, collapsing every interior node that
        // is now empty along this key's no-longer-shared path.
        self.recompute_path(&path)?;
        Ok(())
    }

    /// Collect the compressed sibling set along `path`: a 256-bit presence
    /// bitmap plus the non-empty siblings (leaf-parent → root order).
    fn collect_siblings(&self, path: &[u8; 32]) -> Result<CompressedSiblings, S::Error> {
        let mut present = [0u8; 32];
        let mut siblings = Vec::new();
        let mut parent_depth = MAX_DEPTH; // 256
        while parent_depth > 0 {
            parent_depth -= 1; // 255 .. 0
            let child_depth = parent_depth + 1;
            let parent_path = path_mask(path, parent_depth);
            let we_are_right = bit_get(path, parent_depth);
            // The sibling is the *other* child at child_depth.
            let sib_path = if we_are_right {
                parent_path // left child: bit at parent_depth is 0
            } else {
                let mut p = parent_path; // right child: set bit at parent_depth
                bit_set(&mut p, parent_depth);
                p
            };
            let sib = self.get_node(child_depth, &sib_path)?;
            if sib != EMPTY_HASH {
                bit_set(&mut present, parent_depth);
                siblings.push(sib);
            }
        }
        Ok((present, siblings))
    }

    /// Produce a compressed **inclusion** proof for `account_id`. `None` if absent.
    pub fn proof(&self, account_id: &[u8; 32]) -> Result<Option<SmtProof>, S::Error> {
        let state_hash = match self.get(account_id)? {
            Some(h) => h,
            None => return Ok(None),
        };
        let path = account_path(account_id);
        let root = self.root()?;
        let (present, siblings) = self.collect_siblings(&path)?;
        Ok(Some(SmtProof {
            account_id: *account_id,
            state_hash,
            root,
            present,
            siblings,
        }))
    }

    /// Produce a compressed **exclusion** (non-membership) proof for
    /// `account_id`. `None` if the account *is* present (an inclusion proof is
    /// the right artifact then).
    pub fn exclusion_proof(
        &self,
        account_id: &[u8; 32],
    ) -> Result<Option<SmtExclusionProof>, S::Error> {
        if self.get(account_id)?.is_some() {
            return Ok(None); // present → not an exclusion case
        }
        let path = account_path(account_id);
        let root = self.root()?;
        let (present, siblings) = self.collect_siblings(&path)?;
        Ok(Some(SmtExclusionProof {
            account_id: *account_id,
            root,
            present,
            siblings,
        }))
    }

    /// Flush all buffered writes to the store in one atomic batch.
    pub fn commit(&mut self) -> Result<(), S::Error> {
        let mut puts: Vec<(Vec<u8>, [u8; 32])> =
            Vec::with_capacity(self.cache.len() + self.pending_values.len());
        for (&(depth, ref path_prefix), hash) in &self.cache {
            puts.push((node_key(depth, path_prefix), *hash));
        }
        for (acc, hash) in &self.pending_values {
            puts.push((value_key(acc), *hash));
        }
        let mut deletes: Vec<Vec<u8>> = self
            .deletes
            .iter()
            .map(|(depth, path_prefix)| node_key(*depth, path_prefix))
            .collect();
        // Value-key (`v:`) removals from `delete`. Disjoint from `puts`: a key is
        // mutually exclusive between `pending_values` and `pending_value_deletes`,
        // and `v:`/`n:` are separate namespaces, so the `write_batch` "puts and
        // deletes never touch the same key" contract holds.
        for acc in &self.pending_value_deletes {
            deletes.push(value_key(acc));
        }

        self.store.write_batch(&puts, &deletes)?;
        self.cache.clear();
        self.deletes.clear();
        self.pending_values.clear();
        self.pending_value_deletes.clear();
        Ok(())
    }

    // ─── Internals ─────────────────────────────────────────────────────────────

    fn get_node(&self, depth: u16, path_prefix: &[u8; 32]) -> Result<[u8; 32], S::Error> {
        let masked = path_mask(path_prefix, depth);
        if let Some(h) = self.cache.get(&(depth, masked)) {
            return Ok(*h);
        }
        if self.deletes.contains(&(depth, masked)) {
            return Ok(EMPTY_HASH);
        }
        Ok(self.store.get(&node_key(depth, &masked))?.unwrap_or(EMPTY_HASH))
    }

    fn set_node(&mut self, depth: u16, path_prefix: &[u8; 32], hash: [u8; 32]) {
        let masked = path_mask(path_prefix, depth);
        self.deletes.remove(&(depth, masked));
        self.cache.insert((depth, masked), hash);
    }

    fn recompute_path(&mut self, path: &[u8; 32]) -> Result<(), S::Error> {
        let mut depth = MAX_DEPTH;
        while depth > 0 {
            let parent_depth = depth - 1;
            let parent_path = path_mask(path, parent_depth);

            let left_path = parent_path;
            let mut right_path = parent_path;
            bit_set(&mut right_path, parent_depth);

            let left_hash = self.get_node(depth, &left_path)?;
            let right_hash = self.get_node(depth, &right_path)?;

            let parent_hash = if left_hash == EMPTY_HASH && right_hash == EMPTY_HASH {
                EMPTY_HASH
            } else {
                interior_hash(&left_hash, &right_hash)
            };

            let current = self.get_node(parent_depth, &parent_path)?;
            if parent_hash == current {
                break;
            }
            if parent_hash == EMPTY_HASH {
                self.deletes.insert((parent_depth, parent_path));
                self.cache.remove(&(parent_depth, parent_path));
            } else {
                self.set_node(parent_depth, &parent_path, parent_hash);
            }
            depth -= 1;
        }
        Ok(())
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn tree() -> SparseMerkleTree<MemorySmtStore> {
        SparseMerkleTree::new(MemorySmtStore::new())
    }

    fn acc(id: &[u8]) -> [u8; 32] {
        sha3_256(id)
    }

    // --- Roots & proofs ---

    #[test]
    fn empty_tree_root_is_sentinel() {
        assert_eq!(tree().root().unwrap(), EMPTY_HASH);
    }

    #[test]
    fn empty_hash_equals_sha3_of_empty() {
        assert_eq!(EMPTY_HASH, sha3_256(b""));
        assert_eq!(empty_hash(), sha3_256(b""));
    }

    #[test]
    fn single_update_changes_root() {
        let mut t = tree();
        let before = t.root().unwrap();
        t.update(&acc(b"alice"), &sha3_256(b"balance=100")).unwrap();
        let after = t.root().unwrap();
        assert_ne!(before, after);
        assert_ne!(after, EMPTY_HASH);
    }

    #[test]
    fn update_is_key_addressed_not_value_addressed() {
        let mut t = tree();
        let a = acc(b"alice");
        t.update(&a, &sha3_256(b"state_v1")).unwrap();
        let root_v1 = t.root().unwrap();
        t.update(&a, &sha3_256(b"state_v2")).unwrap();
        let root_v2 = t.root().unwrap();
        assert_ne!(root_v1, root_v2);
        assert_eq!(t.get(&a).unwrap(), Some(sha3_256(b"state_v2")));
        // Revert — root returns to v1 because the path is identity-derived.
        t.update(&a, &sha3_256(b"state_v1")).unwrap();
        assert_eq!(t.root().unwrap(), root_v1);
    }

    #[test]
    fn proof_roundtrip_single_account() {
        let mut t = tree();
        let a = acc(b"solo");
        t.update(&a, &sha3_256(b"s")).unwrap();
        t.commit().unwrap();
        let proof = t.proof(&a).unwrap().expect("present");
        assert_eq!(proof.account_id, a);
        assert_eq!(proof.state_hash, sha3_256(b"s"));
        assert_eq!(proof.root, t.root().unwrap());
        // A single-account tree has no non-empty siblings (every sibling is empty).
        assert!(proof.siblings.is_empty());
        assert_eq!(proof.present, [0u8; 32]);
        assert!(verify_proof(&proof));
    }

    #[test]
    fn proof_roundtrip_many_accounts() {
        let mut t = tree();
        let accounts: Vec<[u8; 32]> = (0..50u32).map(|i| acc(&i.to_be_bytes())).collect();
        for (i, a) in accounts.iter().enumerate() {
            t.update(a, &sha3_256(&(i as u64).to_be_bytes())).unwrap();
        }
        t.commit().unwrap();
        let root = t.root().unwrap();
        assert_ne!(root, EMPTY_HASH);
        for (i, a) in accounts.iter().enumerate() {
            let proof = t.proof(a).unwrap().unwrap();
            assert_eq!(proof.root, root);
            assert_eq!(proof.state_hash, sha3_256(&(i as u64).to_be_bytes()));
            assert!(verify_proof(&proof), "proof #{i} should verify");
        }
    }

    #[test]
    fn compressed_proof_is_logarithmic_not_max_depth() {
        // With N accounts the proof carries ≈ log2(N) siblings, NOT MAX_DEPTH.
        let mut t = tree();
        for i in 0..1000u32 {
            t.update(&acc(&i.to_be_bytes()), &sha3_256(&i.to_be_bytes())).unwrap();
        }
        t.commit().unwrap();
        let p = t.proof(&acc(&7u32.to_be_bytes())).unwrap().unwrap();
        // log2(1000) ≈ 10; allow generous slack but assert far below 256.
        assert!(
            p.siblings.len() < 40,
            "expected ~log2(N) siblings, got {}",
            p.siblings.len()
        );
        // Bitmap popcount must equal the sibling count.
        let popcount: u32 = p.present.iter().map(|b| b.count_ones()).sum();
        assert_eq!(popcount as usize, p.siblings.len());
        assert!(verify_proof(&p));
    }

    #[test]
    fn proof_for_missing_account_is_none() {
        let mut t = tree();
        t.update(&acc(b"present"), &sha3_256(b"x")).unwrap();
        t.commit().unwrap();
        assert!(t.proof(&acc(b"absent")).unwrap().is_none());
    }

    #[test]
    fn exclusion_proof_roundtrip() {
        let mut t = tree();
        for i in 0..32u8 {
            t.update(&acc(&[i]), &sha3_256(&[i, i])).unwrap();
        }
        t.commit().unwrap();
        let root = t.root().unwrap();
        // Absent key → exclusion proof verifies against the same signed root.
        let xp = t.exclusion_proof(&acc(b"definitely-absent")).unwrap().unwrap();
        assert_eq!(xp.root, root);
        assert!(verify_exclusion_proof(&xp));
        // A present key has no exclusion proof.
        assert!(t.exclusion_proof(&acc(&[0u8])).unwrap().is_none());
    }

    #[test]
    fn exclusion_proof_cannot_be_forged_for_present_account() {
        // Build an exclusion proof for an ABSENT key, then swap in a PRESENT
        // key's id: the fold from EMPTY no longer reaches the root → rejected.
        let mut t = tree();
        let present = acc(b"i-exist");
        t.update(&present, &sha3_256(b"v")).unwrap();
        t.update(&acc(b"other"), &sha3_256(b"w")).unwrap();
        t.commit().unwrap();
        let mut xp = t.exclusion_proof(&acc(b"absent")).unwrap().unwrap();
        xp.account_id = present; // forge: claim the present account is absent
        assert!(
            !verify_exclusion_proof(&xp),
            "exclusion proof for a present account must be rejected"
        );
    }

    #[test]
    fn tampered_proof_fails() {
        let mut t = tree();
        for i in 0..8u8 {
            t.update(&acc(&[i]), &sha3_256(&[i, i])).unwrap();
        }
        t.commit().unwrap();
        // Tamper a sibling.
        let mut p = t.proof(&acc(&[0])).unwrap().unwrap();
        if !p.siblings.is_empty() {
            p.siblings[0][0] ^= 0x01;
            assert!(!verify_proof(&p));
        }
        // Tamper the value.
        let mut q = t.proof(&acc(&[0])).unwrap().unwrap();
        q.state_hash[0] ^= 0x01;
        assert!(!verify_proof(&q));
        // Tamper the root.
        let mut r = t.proof(&acc(&[0])).unwrap().unwrap();
        r.root = [0xFFu8; 32];
        assert!(!verify_proof(&r));
    }

    #[test]
    fn wrong_identity_proof_rejects() {
        // A proof minted for A must not verify when its account_id is swapped to
        // B — identity is bound into the leaf AND derives the path.
        let mut t = tree();
        let a = acc(b"account-A");
        let b = acc(b"account-B");
        t.update(&a, &sha3_256(b"sA")).unwrap();
        t.update(&b, &sha3_256(b"sB")).unwrap();
        t.commit().unwrap();
        let mut p = t.proof(&a).unwrap().unwrap();
        p.account_id = b; // forge identity, keep A's state + siblings
        assert!(!verify_proof(&p), "identity-swapped proof must reject");
    }

    #[test]
    fn collision_is_now_sha3_strength() {
        // Two ids whose top-64-bit (and top-128-bit) hash prefixes are forced
        // equal would have collided in the old 64-bit tree. Here they get
        // DISTINCT full-256-bit paths and DISTINCT leaves and BOTH prove.
        // We can't cheaply grind a real 64-bit prefix collision in a unit test,
        // so we assert the structural property directly: distinct ids → distinct
        // paths, and co-resident proofs both verify.
        let mut t = tree();
        let a = acc(b"twin-a");
        let b = acc(b"twin-b");
        assert_ne!(account_path(&a), account_path(&b));
        t.update(&a, &sha3_256(b"same")).unwrap();
        t.update(&b, &sha3_256(b"same")).unwrap(); // identical VALUE
        t.commit().unwrap();
        let pa = t.proof(&a).unwrap().unwrap();
        let pb = t.proof(&b).unwrap().unwrap();
        // Identical value but distinct leaves (identity-bound).
        assert_ne!(
            leaf_hash(&a, &sha3_256(b"same")),
            leaf_hash(&b, &sha3_256(b"same"))
        );
        assert!(verify_proof(&pa));
        assert!(verify_proof(&pb));
        assert_eq!(pa.root, pb.root);
    }

    #[test]
    fn leaf_and_interior_are_domain_separated() {
        // A leaf preimage and an interior preimage of the same 64 bytes must not
        // collide: leaf uses LEAF_TAG, interior uses NODE_TAG.
        let x = [0x11u8; 32];
        let y = [0x22u8; 32];
        assert_ne!(leaf_hash(&x, &y), interior_hash(&x, &y));
    }

    #[test]
    fn verify_proof_rejects_malformed_sibling_count() {
        let aid = [0xCAu8; 32];
        let state_hash = sha3_256(b"some-state");
        let root = sha3_256(b"some-root");
        // present claims one sibling but none provided → fold returns None.
        let mut present = [0u8; 32];
        bit_set(&mut present, 255);
        let p = SmtProof {
            account_id: aid,
            state_hash,
            root,
            present,
            siblings: vec![],
        };
        assert!(!verify_proof(&p), "present-bit without sibling must reject");
        // siblings present but bitmap empty → leftover sibling → reject.
        let q = SmtProof {
            account_id: aid,
            state_hash,
            root,
            present: [0u8; 32],
            siblings: vec![[7u8; 32]],
        };
        assert!(!verify_proof(&q), "extra sibling must reject");
    }

    #[test]
    fn commit_persists_then_reads_back() {
        let mut t = tree();
        let a = acc(b"persist");
        t.update(&a, &sha3_256(b"v")).unwrap();
        let root_before = t.root().unwrap();
        t.commit().unwrap();
        let store = t.into_store();
        let t2 = SparseMerkleTree::new(store);
        assert_eq!(t2.root().unwrap(), root_before);
        assert_eq!(t2.get(&a).unwrap(), Some(sha3_256(b"v")));
    }

    // --- Exact-hex root pins (cross-checked byte-for-byte against the node's
    //     RocksDB-backed tree in account_merkle.rs::smt_root_and_proof_exact_hex_pins).
    //     A store is just a KV map, so memory and rocks MUST agree. These pins
    //     freeze the 256-bit / identity-bound / domain-separated construction —
    //     re-baked 2026-06-16 for the consensus-root change (intentional
    //     divergence from the old 64-bit roots). ---

    #[test]
    fn root_hex_pins_match_node() {
        let mut t = tree();
        assert_eq!(
            hex_lower(&t.root().unwrap()),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
        );
        t.update(&acc(b"alice"), &sha3_256(b"balance=100")).unwrap();
        let r1 = hex_lower(&t.root().unwrap());
        t.update(&acc(b"bob"), &sha3_256(b"balance=200")).unwrap();
        t.update(&acc(b"carol"), &sha3_256(b"balance=300")).unwrap();
        let r3 = hex_lower(&t.root().unwrap());
        // Pins frozen from this construction; assert stability + distinctness.
        assert_eq!(r1, PIN_ALICE);
        assert_eq!(r3, PIN_ABC);
        assert_ne!(r1, r3);
        let p = t.proof(&acc(b"bob")).unwrap().unwrap();
        assert!(verify_proof(&p));
        // bob co-resident with alice/carol → at least one non-empty sibling.
        assert!(!p.siblings.is_empty());
    }

    // Frozen construction pins (256-bit identity-bound domain-separated tree).
    const PIN_ALICE: &str = "95329e81b5c68a435cd984e67b3e5d4129c085bd41cb63b2315138b8eb9bfb16";
    const PIN_ABC: &str = "4f1752605c5bd5585bce352f1a16d4d98060f6ab74fe6e0cc96e43e1d3b82aba";

    // Local hex encoder so the crate stays dependency-free of `hex`.
    fn hex_lower(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
            s.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
        }
        s
    }

    // --- Pure-math pins (lock the byte layout) ---

    #[test]
    fn max_depth_is_256_u16() {
        assert_eq!(MAX_DEPTH, 256);
        let _t: u16 = MAX_DEPTH; // type pin
    }

    #[test]
    fn path_mask_boundaries() {
        let ones = [0xFFu8; 32];
        // depth 0 → all zero.
        assert_eq!(path_mask(&ones, 0), [0u8; 32]);
        // depth 256 → identity.
        assert_eq!(path_mask(&ones, 256), ones);
        // depth 8 → first byte kept, rest zero.
        let mut want = [0u8; 32];
        want[0] = 0xFF;
        assert_eq!(path_mask(&ones, 8), want);
        // depth 4 → top nibble of first byte.
        let mut want4 = [0u8; 32];
        want4[0] = 0xF0;
        assert_eq!(path_mask(&ones, 4), want4);
        // depth 255 → all but the very last bit.
        let mut want255 = [0xFFu8; 32];
        want255[31] = 0xFE;
        assert_eq!(path_mask(&ones, 255), want255);
    }

    #[test]
    fn bit_get_set_msb_first() {
        let mut b = [0u8; 32];
        bit_set(&mut b, 0);
        assert_eq!(b[0], 0x80);
        assert!(bit_get(&b, 0));
        assert!(!bit_get(&b, 1));
        let mut c = [0u8; 32];
        bit_set(&mut c, 255);
        assert_eq!(c[31], 0x01);
        assert!(bit_get(&c, 255));
        let mut d = [0u8; 32];
        bit_set(&mut d, 8);
        assert_eq!(d[1], 0x80);
        assert!(bit_get(&d, 8));
    }

    #[test]
    fn node_key_value_key_byte_format_and_disjointness() {
        // node_key: "n:" (2B) + depth (2B BE) + path_prefix (32B) = 36B
        let zero = [0u8; 32];
        let nk = node_key(0, &zero);
        assert_eq!(nk.len(), 36);
        assert_eq!(&nk[0..2], b"n:");
        assert_eq!(&nk[2..4], &0u16.to_be_bytes());
        assert_eq!(&nk[4..36], &zero[..]);
        let nk_be = node_key(0x0142, &[0xABu8; 32]);
        assert_eq!(&nk_be[2..4], &0x0142u16.to_be_bytes());
        assert_eq!(node_key(63, &zero), node_key(63, &zero));
        assert_ne!(node_key(0, &zero), node_key(1, &zero));
        assert_ne!(node_key(256, &zero), node_key(0, &zero));

        // value_key: "v:" (2B) + key (32B) = 34B, key verbatim (no hashing)
        let aid = [0xCDu8; 32];
        let vk = value_key(&aid);
        assert_eq!(vk.len(), 34);
        assert_eq!(&vk[0..2], b"v:");
        assert_eq!(&vk[2..34], &aid[..]);

        // Namespaces can't collide: node keys start 'n', value keys start 'v'.
        assert_ne!(nk[0], vk[0]);
    }

    #[test]
    fn account_path_is_full_sha3_and_deterministic() {
        let id = acc(b"id1");
        assert_eq!(account_path(&id), account_path(&id));
        assert_eq!(account_path(&id), sha3_256(&id));
        // Distinct inputs → distinct paths across a sweep.
        let mut seen = std::collections::HashSet::new();
        for i in 0..1000u32 {
            assert!(seen.insert(account_path(&acc(&i.to_be_bytes()))));
        }
    }

    #[test]
    fn account_path_boundary_inputs_no_panic() {
        let _ = account_path(&[0x00; 32]);
        let _ = account_path(&[0xff; 32]);
        let _ = account_path(&[0x55; 32]);
    }

    #[test]
    fn proof_serde_roundtrip() {
        let mut t = tree();
        t.update(&acc(b"x"), &sha3_256(b"v")).unwrap();
        t.update(&acc(b"y"), &sha3_256(b"w")).unwrap();
        t.commit().unwrap();
        let p = t.proof(&acc(b"x")).unwrap().unwrap();
        let json = serde_json::to_string(&p).expect("serialize");
        let back: SmtProof = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.account_id, p.account_id);
        assert_eq!(back.state_hash, p.state_hash);
        assert_eq!(back.root, p.root);
        assert_eq!(back.present, p.present);
        assert_eq!(back.siblings, p.siblings);
        assert!(verify_proof(&back));
    }

    #[test]
    fn exclusion_serde_roundtrip() {
        let mut t = tree();
        t.update(&acc(b"x"), &sha3_256(b"v")).unwrap();
        t.commit().unwrap();
        let xp = t.exclusion_proof(&acc(b"absent")).unwrap().unwrap();
        let json = serde_json::to_string(&xp).expect("serialize");
        let back: SmtExclusionProof = serde_json::from_str(&json).expect("deserialize");
        assert!(verify_exclusion_proof(&back));
    }

    #[test]
    fn deterministic_root_across_independent_stores() {
        let mut t1 = tree();
        let mut t2 = tree();
        // Same set, different insertion order → same root (key-addressed).
        t1.update(&acc(b"a"), &sha3_256(b"1")).unwrap();
        t1.update(&acc(b"b"), &sha3_256(b"2")).unwrap();
        t2.update(&acc(b"b"), &sha3_256(b"2")).unwrap();
        t2.update(&acc(b"a"), &sha3_256(b"1")).unwrap();
        assert_eq!(t1.root().unwrap(), t2.root().unwrap());
        assert_ne!(t1.root().unwrap(), EMPTY_HASH);
    }

    #[test]
    fn proof_siblings_over_max_depth_rejected_on_deserialize() {
        // A genuine compressed proof has at most one sibling per tree level, so
        // a sibling list longer than MAX_DEPTH (256) is malformed. An attacker
        // can still craft such bytes; the bounded deserializer must reject them
        // rather than allocate the whole list. Construct directly (the tree
        // never produces this), serialize, then confirm deserialize rejects it.
        let proof = SmtProof {
            account_id: [0u8; 32],
            state_hash: [0u8; 32],
            root: [0u8; 32],
            present: [0u8; 32],
            siblings: vec![[0u8; 32]; MAX_DEPTH as usize + 1],
        };
        let json = serde_json::to_string(&proof).unwrap();
        assert!(
            serde_json::from_str::<SmtProof>(&json).is_err(),
            "proof with > MAX_DEPTH siblings must be rejected on deserialize"
        );
        // Exactly MAX_DEPTH still round-trips.
        let ok = SmtProof {
            siblings: vec![[0u8; 32]; MAX_DEPTH as usize],
            ..proof.clone()
        };
        let json_ok = serde_json::to_string(&ok).unwrap();
        assert!(serde_json::from_str::<SmtProof>(&json_ok).is_ok());
    }

    // --- Deletion (tombstone) primitive ---
    // The audit-mandated gate for the F-5 V2 ghost-leaf fix: deletion must be the
    // exact inverse of insertion so a removed account collapses to a genuinely
    // empty slot (valid exclusion proof), never a `hash(default)` ghost leaf.

    #[test]
    fn delete_is_exact_inverse_of_insert() {
        // insert A; capture root_a; insert B; delete B; root must return to root_a.
        let mut t = tree();
        let a = acc(b"alice");
        let b = acc(b"bob");
        t.update(&a, &sha3_256(b"sA")).unwrap();
        let root_a = t.root().unwrap();
        t.update(&b, &sha3_256(b"sB")).unwrap();
        assert_ne!(t.root().unwrap(), root_a);
        t.delete(&b).unwrap();
        assert_eq!(t.root().unwrap(), root_a, "delete must invert insert");
        assert_eq!(t.get(&b).unwrap(), None, "deleted key must read None");
        assert_eq!(t.get(&a).unwrap(), Some(sha3_256(b"sA")));
    }

    #[test]
    fn delete_root_matches_fresh_tree_over_survivors() {
        // The audit's core property: insert {A,B}; delete A; root == fresh{B}.
        let a = acc(b"account-A");
        let b = acc(b"account-B");
        let sb = sha3_256(b"state_B");

        let mut t = tree();
        t.update(&a, &sha3_256(b"state_A")).unwrap();
        t.update(&b, &sb).unwrap();
        t.delete(&a).unwrap();
        t.commit().unwrap();

        let mut fresh = tree();
        fresh.update(&b, &sb).unwrap();
        fresh.commit().unwrap();

        assert_eq!(
            t.root().unwrap(),
            fresh.root().unwrap(),
            "delete A must equal a fresh tree over the survivor set"
        );
        assert_eq!(t.get(&a).unwrap(), None);
        assert_eq!(t.get(&b).unwrap(), Some(sb));
    }

    #[test]
    fn delete_one_of_many_matches_fresh_over_survivors() {
        // Stronger: 50 accounts, delete the 7th, compare to a fresh tree built
        // from the other 49. Exercises partial subtree collapse across shared
        // prefixes, not just a 2-leaf tree.
        let accounts: Vec<[u8; 32]> = (0..50u32).map(|i| acc(&i.to_be_bytes())).collect();
        let val = |i: usize| sha3_256(&(i as u64).to_be_bytes());
        let victim = 7usize;

        let mut t = tree();
        for (i, a) in accounts.iter().enumerate() {
            t.update(a, &val(i)).unwrap();
        }
        t.delete(&accounts[victim]).unwrap();
        t.commit().unwrap();

        let mut fresh = tree();
        for (i, a) in accounts.iter().enumerate() {
            if i != victim {
                fresh.update(a, &val(i)).unwrap();
            }
        }
        fresh.commit().unwrap();

        assert_eq!(t.root().unwrap(), fresh.root().unwrap());
        assert_eq!(t.get(&accounts[victim]).unwrap(), None);
        // Every survivor still proves against the post-delete root.
        for (i, a) in accounts.iter().enumerate() {
            if i != victim {
                let p = t.proof(a).unwrap().unwrap();
                assert!(verify_proof(&p), "survivor #{i} must still prove");
            }
        }
    }

    #[test]
    fn delete_only_account_returns_empty_root() {
        let mut t = tree();
        let a = acc(b"solo");
        t.update(&a, &sha3_256(b"s")).unwrap();
        assert_ne!(t.root().unwrap(), EMPTY_HASH);
        t.delete(&a).unwrap();
        assert_eq!(t.root().unwrap(), EMPTY_HASH, "empty tree → sentinel root");
        // And it persists: a fresh tree over the committed store is empty.
        t.commit().unwrap();
        let store = t.into_store();
        let t2 = SparseMerkleTree::new(store);
        assert_eq!(t2.root().unwrap(), EMPTY_HASH);
        assert_eq!(t2.get(&a).unwrap(), None);
    }

    #[test]
    fn deleted_slot_yields_valid_exclusion_proof() {
        // Audit-mandated proof-level test: after deletion the slot must produce a
        // sound non-membership proof against the new root — not a stale inclusion.
        let mut t = tree();
        let a = acc(b"to-remove");
        for i in 0..16u8 {
            t.update(&acc(&[i]), &sha3_256(&[i, i])).unwrap();
        }
        t.update(&a, &sha3_256(b"present")).unwrap();
        t.commit().unwrap();
        assert!(t.proof(&a).unwrap().is_some(), "present before delete");

        t.delete(&a).unwrap();
        t.commit().unwrap();
        let root = t.root().unwrap();

        // No inclusion proof; a verifying exclusion proof instead.
        assert!(t.proof(&a).unwrap().is_none(), "no inclusion proof after delete");
        let xp = t.exclusion_proof(&a).unwrap().expect("exclusion proof for deleted key");
        assert_eq!(xp.root, root);
        assert!(verify_exclusion_proof(&xp), "deleted slot must verify as absent");
    }

    #[test]
    fn delete_is_idempotent_and_absent_key_is_noop() {
        let mut t = tree();
        let a = acc(b"a");
        let b = acc(b"b");
        t.update(&a, &sha3_256(b"x")).unwrap();
        t.update(&b, &sha3_256(b"y")).unwrap();
        let root = t.root().unwrap();
        // Deleting a never-inserted key changes nothing.
        t.delete(&acc(b"never-here")).unwrap();
        assert_eq!(t.root().unwrap(), root);
        // Deleting the same key twice == once.
        t.delete(&a).unwrap();
        let once = t.root().unwrap();
        t.delete(&a).unwrap();
        assert_eq!(t.root().unwrap(), once);
        assert_eq!(t.get(&a).unwrap(), None);
    }

    #[test]
    fn delete_then_reupdate_restores_presence() {
        // delete then re-update (across and within a commit) must leave the key
        // present — `pending_value_deletes` is cleared by `update`.
        let mut t = tree();
        let a = acc(b"churn");
        t.update(&a, &sha3_256(b"v1")).unwrap();
        t.commit().unwrap();
        t.delete(&a).unwrap();
        assert_eq!(t.get(&a).unwrap(), None);
        t.update(&a, &sha3_256(b"v2")).unwrap();
        assert_eq!(t.get(&a).unwrap(), Some(sha3_256(b"v2")));
        t.commit().unwrap();
        let p = t.proof(&a).unwrap().unwrap();
        assert_eq!(p.state_hash, sha3_256(b"v2"));
        assert!(verify_proof(&p));
    }

    #[test]
    fn delete_removes_value_key_from_store_no_orphan() {
        // After a committed delete the `v:` value record must be gone from the
        // store (a fresh tree can't see it), so `get` can't resurrect a ghost.
        let mut t = tree();
        let a = acc(b"ghosthunt");
        let b = acc(b"keep");
        t.update(&a, &sha3_256(b"va")).unwrap();
        t.update(&b, &sha3_256(b"vb")).unwrap();
        t.commit().unwrap();
        t.delete(&a).unwrap();
        t.commit().unwrap();
        let store = t.into_store();
        let t2 = SparseMerkleTree::new(store);
        assert_eq!(t2.get(&a).unwrap(), None, "value-key must not survive delete");
        assert_eq!(t2.get(&b).unwrap(), Some(sha3_256(b"vb")));
        let mut fresh = tree();
        fresh.update(&b, &sha3_256(b"vb")).unwrap();
        fresh.commit().unwrap();
        assert_eq!(t2.root().unwrap(), fresh.root().unwrap());
    }

    #[test]
    fn delete_differs_from_update_to_default_the_ghost_leaf_bug() {
        // Demonstrates the F-5 V2 defect at the algebra layer: flushing a removed
        // account as `update(hash(default))` (the `unwrap_or_default` path) leaves
        // a non-empty ghost leaf with a DIFFERENT root than a clean delete. The
        // node's repair path must call `delete`, not update-to-default.
        let a = acc(b"removed-account");
        let b = acc(b"survivor");
        let default_leaf = sha3_256(b"AccountState::default()-stand-in");

        // Ghost path: update A to a "default" value (what unwrap_or_default does).
        let mut ghost = tree();
        ghost.update(&b, &sha3_256(b"vb")).unwrap();
        ghost.update(&a, &default_leaf).unwrap();
        ghost.commit().unwrap();

        // Clean path: A was flushed-as-default, then properly deleted.
        let mut clean = tree();
        clean.update(&b, &sha3_256(b"vb")).unwrap();
        clean.update(&a, &default_leaf).unwrap();
        clean.delete(&a).unwrap();
        clean.commit().unwrap();

        // Truth: a tree that only ever held B.
        let mut truth = tree();
        truth.update(&b, &sha3_256(b"vb")).unwrap();
        truth.commit().unwrap();

        assert_ne!(
            ghost.root().unwrap(),
            truth.root().unwrap(),
            "update-to-default must leave a divergent ghost leaf (the bug)"
        );
        assert_eq!(
            clean.root().unwrap(),
            truth.root().unwrap(),
            "delete must match the truth root (the fix)"
        );
        assert_eq!(clean.get(&a).unwrap(), None);
        assert!(ghost.get(&a).unwrap().is_some(), "ghost leaf is still present");
    }
}
