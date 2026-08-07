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
//! Empty subtrees collapse to a single sentinel ([`EMPTY_HASH`] = `SHA3-256("")`).
//! Storage is **format-versioned**: a v2 store (the default for any store this
//! crate initializes) does not materialize unary tails — a key stores its leaf,
//! its exclusive-subtree top, and the shared "crown" rows above divergence, so
//! storage is `O(N·log N)` rows and a mutation touches `O(log N)` store keys
//! (the ~256 tail hashes are computed in a register loop, never stored). A
//! legacy (pre-v2) store — recognized by data present without the format key —
//! keeps the original full-path walk (`O(256)` rows per key) byte-for-byte;
//! roots and proofs are **bit-identical across formats** (design + conditions:
//! internal design notes). Proofs are
//! **empty-subtree-compressed**: instead of a fixed
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
use std::sync::atomic::{AtomicU8, Ordering};

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

// ─── v2 compact-store format ─────────────────────────────────────────────────
//
// A v2 store holds, per resident key: its leaf row (depth 256), one
// exclusive-top row at the key's divergence depth `d*` (= 1 + the deepest
// branch on its path), a `p:` row at that same position recording the
// resident's FULL 256-bit path, and the shared "crown" rows at every depth
// `0..=d*` along its path (crown rows are shared between keys, so total
// storage is O(N·log N) rows). The unary tail strictly between `d*` and 256
// is NOT materialized — its hashes are recomputed in a register loop.
//
// The `p:` row is what lets a point-`get` store answer "which single key
// lives under this unary top?" — without it, an insert diving below an
// exclusive top could not locate the resident's divergence bit and would
// silently compute a wrong root (the audit's #1 risk class). It is primary
// structural data written in the same atomic `write_batch` as everything
// else — not an advisory index.
//
// Format detection: the `f:format` row carries [`FORMAT_V2_TAG`]. Data present
// without it = a legacy full-tail store; the tree then runs the original
// O(256) walk byte-for-byte (fail-safe-slow, never fail-safe-wrong). A store
// carrying an UNRECOGNIZED tag is also walked as legacy — a future format
// must ship in a new crate major so old code never opens it.
//
// Byte order note: `f:` < `n:` < `p:` < `v:`, so scans that seek to `b"v:"`
// (the node's orphan-leaf reconciliation) are unaffected by the new rows.

/// Store-key of the format-version row.
const FORMAT_KEY: &[u8] = b"f:format";

/// Value of the format-version row for a v2 (compact) store:
/// `SHA3-256("elara-smt-store-format-v2")` (pinned by test).
pub const FORMAT_V2_TAG: [u8; 32] = [
    0x8e, 0x0b, 0x03, 0x65, 0x22, 0x8a, 0xba, 0xcd,
    0x1a, 0x3c, 0x38, 0xcb, 0xf3, 0xdc, 0x83, 0x65,
    0xd9, 0x56, 0xec, 0x19, 0x78, 0xe2, 0xcc, 0x10,
    0xd3, 0x7d, 0xc7, 0x79, 0xd2, 0x50, 0xfa, 0x01,
];

/// Exclusive-top path row: `"p:"` + depth (2B BE) + masked path (32B) = 36
/// bytes → value = the resident key's full 256-bit path. Present exactly at
/// exclusive-top positions in a v2 store.
fn p_key(depth: u16, path_prefix: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(2 + 2 + 32);
    key.extend_from_slice(b"p:");
    key.extend_from_slice(&depth.to_be_bytes());
    key.extend_from_slice(path_prefix);
    key
}

/// Format-resolution states for [`SparseMerkleTree::format`].
const FMT_UNRESOLVED: u8 = 0;
const FMT_LEGACY: u8 = 1;
const FMT_V2: u8 = 2;
/// v2 resolved on a virgin store — the `f:format` row still needs writing at
/// the next [`SparseMerkleTree::commit`].
const FMT_V2_FLAG_PENDING: u8 = 3;

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

/// Toggle the MSB-first bit at position `index` (`< 256`). Used to derive a
/// sibling position from an on-path position.
fn bit_toggle(bytes: &mut [u8; 32], index: u16) {
    let byte = (index / 8) as usize;
    let mask = 0x80u8 >> (index % 8) as u8;
    bytes[byte] ^= mask;
}

/// First bit position (MSB-first) at which two 256-bit paths differ, or 256 if
/// they are equal. Equivalently: the number of leading bits they share.
fn first_diff_bit(a: &[u8; 32], b: &[u8; 32]) -> u16 {
    for i in 0..32 {
        let x = a[i] ^ b[i];
        if x != 0 {
            return (i as u16) * 8 + x.leading_zeros() as u16;
        }
    }
    MAX_DEPTH
}

/// Fold a non-empty subtree hash at `(from_depth, path)` up to `to_depth`
/// through EMPTY siblings only — the register-loop tail hash of a unary
/// region. `h` must not be [`EMPTY_HASH`] (an empty subtree folds by the
/// both-empty collapse, not by this chain).
fn fold_tail(mut h: [u8; 32], path: &[u8; 32], from_depth: u16, to_depth: u16) -> [u8; 32] {
    debug_assert!(h != EMPTY_HASH, "fold_tail is for non-empty subtrees only");
    debug_assert!(from_depth >= to_depth);
    let mut d = from_depth;
    while d > to_depth {
        let parent = d - 1;
        h = if bit_get(path, parent) {
            interior_hash(&EMPTY_HASH, &h)
        } else {
            interior_hash(&h, &EMPTY_HASH)
        };
        d = parent;
    }
    h
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
    /// Pending `p:` (exclusive-top path) writes, keyed like `cache`. Mutually
    /// exclusive with `p_deletes` (v2 stores only).
    p_cache: HashMap<(u16, [u8; 32]), [u8; 32]>,
    /// Pending `p:` removals (v2 stores only).
    p_deletes: HashSet<(u16, [u8; 32])>,
    /// Memoized store-format verdict ([`FMT_UNRESOLVED`] until first probed).
    /// Atomic so `&self` readers (root/proof) can resolve it without breaking
    /// the tree's `Sync` auto-trait; a benign double-resolve is idempotent.
    format_state: AtomicU8,
}

/// Compressed sibling set along a path: a 256-bit presence bitmap plus the
/// non-empty siblings in leaf-parent → root order.
type CompressedSiblings = ([u8; 32], Vec<[u8; 32]>);

/// Where a path lands in a v2 compact store, resolved through the full
/// cache → deletes → store layering (never the committed store alone — the
/// audit's #1 correctness risk is an oracle blind to in-batch state).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum V2Site {
    /// The tree is empty (root row absent in the layered view).
    EmptyTree,
    /// The key is resident; its exclusive top sits at `top_depth`
    /// (`top_depth == 256` ⇒ the leaf itself is the top: a leaf-adjacent
    /// branch at depth 255).
    Resident { top_depth: u16 },
    /// The key is absent and its path dives below the exclusive top of a
    /// single resident whose full path is `neighbor_path` (read from the
    /// `p:` row at `(top_depth, ·)`).
    DivesIntoUnary { top_depth: u16, neighbor_path: [u8; 32] },
    /// The key is absent and its path leaves the populated tree at a crown
    /// node: the deepest stored node on the path is at `boundary_depth` and
    /// the path-side child below it is empty. (Covers both "child of a real
    /// branch" and "adjacent to a chain node".)
    BranchAdjacent { boundary_depth: u16 },
}

/// One batch entry for the sharded flush: `(path, account_id, op)` where
/// `Some(state_hash)` upserts and `None` deletes. The path is carried
/// explicitly so shard assignment and the walk agree on it byte-for-byte.
pub type ShardEntry = ([u8; 32], [u8; 32], Option<[u8; 32]>);

/// The owned per-shard result of [`SparseMerkleTree::compute_shard_delta`] —
/// the "owned delta per shard" of the R38 parallel-flush shape
/// (internal design notes §3 Stage 3). Buffers hold only
/// rows at depths `>= shard_bits` (the shard's own subtree); crown rows above
/// the boundary are the serial merge's property and are recomputed there.
/// Entries whose structure crosses the boundary are carried in `refused` and
/// replayed through the ordinary serial walk by
/// [`SparseMerkleTree::apply_shard_deltas`].
#[derive(Debug, Default)]
pub struct ShardDelta {
    shard_bits: u8,
    /// A full path from this shard (any accepted entry) — the serial crown
    /// recompute walks it from `shard_bits` up to the root.
    rep_path: Option<[u8; 32]>,
    nodes: HashMap<(u16, [u8; 32]), [u8; 32]>,
    node_deletes: HashSet<(u16, [u8; 32])>,
    p_nodes: HashMap<(u16, [u8; 32]), [u8; 32]>,
    p_node_deletes: HashSet<(u16, [u8; 32])>,
    values: HashMap<[u8; 32], [u8; 32]>,
    value_deletes: HashSet<[u8; 32]>,
    refused: Vec<ShardEntry>,
}

impl ShardDelta {
    /// Entries this shard could not settle locally (structure crossed the
    /// shard boundary) — replayed serially by `apply_shard_deltas`.
    pub fn refused_len(&self) -> usize {
        self.refused.len()
    }
}

/// Read-only layered store view for per-entry shard walks: the accumulated
/// shard delta first, then the base store. Raw store keys are parsed back to
/// the typed row spaces this crate encodes (`n:`/`p:`/`v:`; everything else —
/// notably `f:format` — passes through to the base). Never written to: the
/// per-entry view trees buffer in memory and are drained, never committed.
struct ShardView<'a, S: SmtStore> {
    delta: &'a ShardDelta,
    base: &'a S,
}

impl<'a, S: SmtStore> SmtStore for ShardView<'a, S> {
    type Error = S::Error;

    fn get(&self, key: &[u8]) -> Result<Option<[u8; 32]>, S::Error> {
        fn typed_32(key: &[u8]) -> Option<(u16, [u8; 32])> {
            if key.len() != 36 {
                return None;
            }
            let depth = u16::from_be_bytes([key[2], key[3]]);
            let mut mask = [0u8; 32];
            mask.copy_from_slice(&key[4..36]);
            Some((depth, mask))
        }
        if key.starts_with(b"n:") {
            if let Some(t) = typed_32(key) {
                if let Some(h) = self.delta.nodes.get(&t) {
                    return Ok(Some(*h));
                }
                if self.delta.node_deletes.contains(&t) {
                    return Ok(None);
                }
            }
        } else if key.starts_with(b"p:") {
            if let Some(t) = typed_32(key) {
                if let Some(p) = self.delta.p_nodes.get(&t) {
                    return Ok(Some(*p));
                }
                if self.delta.p_node_deletes.contains(&t) {
                    return Ok(None);
                }
            }
        } else if key.starts_with(b"v:") && key.len() == 34 {
            let mut acc = [0u8; 32];
            acc.copy_from_slice(&key[2..34]);
            if let Some(v) = self.delta.values.get(&acc) {
                return Ok(Some(*v));
            }
            if self.delta.value_deletes.contains(&acc) {
                return Ok(None);
            }
        }
        self.base.get(key)
    }

    fn write_batch(
        &mut self,
        _puts: &[(Vec<u8>, [u8; 32])],
        _deletes: &[Vec<u8>],
    ) -> Result<(), S::Error> {
        debug_assert!(false, "ShardView is read-only; view trees never commit");
        Ok(())
    }
}

/// Outcome of [`SparseMerkleTree::migrate_legacy_to_v2`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrateOutcome {
    /// The store was legacy and is now v2; `keys` leaves were re-anchored.
    /// Root verified byte-identical before the batch was written.
    Migrated { keys: usize },
    /// The store already carries the v2 format tag (or is virgin, which is
    /// born-v2) — nothing to do.
    AlreadyV2,
    /// The v2 rebuild over the supplied leaves did NOT reproduce the store's
    /// committed root — the store was left byte-for-byte untouched. Either
    /// the supplied leaf set is incomplete or the legacy store is internally
    /// inconsistent; both need operator eyes, not a silent migration.
    RootMismatch {
        /// The committed legacy root.
        expected: [u8; 32],
        /// The root the v2 rebuild produced.
        rebuilt: [u8; 32],
    },
}

impl<S: SmtStore> SparseMerkleTree<S> {
    /// Wrap a store. No I/O happens until the first read or [`commit`](Self::commit).
    pub fn new(store: S) -> Self {
        Self {
            store,
            cache: HashMap::new(),
            deletes: HashSet::new(),
            pending_values: HashMap::new(),
            pending_value_deletes: HashSet::new(),
            p_cache: HashMap::new(),
            p_deletes: HashSet::new(),
            format_state: AtomicU8::new(FMT_UNRESOLVED),
        }
    }

    /// Wrap a store and force the LEGACY (full-tail) walk regardless of store
    /// content. Test/differential harness only — a legacy tree on a virgin
    /// store reproduces the exact pre-v2 write pattern.
    #[doc(hidden)]
    pub fn new_legacy_unchecked(store: S) -> Self {
        let t = Self::new(store);
        t.format_state.store(FMT_LEGACY, Ordering::Release);
        t
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

    /// Upsert `account_id -> state_hash`. On a v2 store this touches
    /// `O(log N)` store rows (tail hashes fold in registers); on a legacy
    /// store it keeps the original `O(MAX_DEPTH)` walk. The stored leaf is
    /// `leaf_hash(account_id, state_hash)` (identity-bound); the raw
    /// `state_hash` value is recorded separately for `get`/`proof`.
    pub fn update(&mut self, account_id: &[u8; 32], state_hash: &[u8; 32]) -> Result<(), S::Error> {
        let path = account_path(account_id);
        self.update_at(&path, account_id, state_hash)
    }

    /// [`update`](Self::update) with an explicit tree path. Test harnesses use
    /// this to construct adversarially deep shared prefixes that real
    /// `SHA3-256` paths never produce; production callers must let `update`
    /// derive the path.
    #[doc(hidden)]
    pub fn update_at(
        &mut self,
        path: &[u8; 32],
        account_id: &[u8; 32],
        state_hash: &[u8; 32],
    ) -> Result<(), S::Error> {
        let leaf = leaf_hash(account_id, state_hash);
        // R36 (audit stage 1): a byte-identical re-write is a no-op — detect
        // it ONCE here instead of letting the walk discover it via a
        // per-level `current` pre-read at all 256 levels. The leaf binds
        // identity + state, so equal leaf ⇒ equal value; a buffered `delete`
        // forces this read to EMPTY_HASH, so delete-then-reinsert can never
        // take this exit. The `get` guard keeps the pathological
        // node-present-but-value-missing store on the full healing path.
        if self.get_node(MAX_DEPTH, path)? == leaf
            && self.get(account_id)?.map(|h| h == *state_hash).unwrap_or(false)
        {
            return Ok(());
        }
        let resume = if self.is_v2()? {
            self.v2_place_leaf(path, leaf)?
        } else {
            self.set_node(MAX_DEPTH, path, leaf);
            MAX_DEPTH
        };
        self.pending_value_deletes.remove(account_id);
        self.pending_values.insert(*account_id, *state_hash);
        self.recompute_path_from(path, resume)?;
        Ok(())
    }

    /// v2 write-side structure walk: place `leaf` at `path`, write the
    /// affected leaf/top/chain/`p:` rows, and return the depth the shared
    /// per-level recompute should resume from (every row at or below the
    /// returned depth is already finalized in the buffers).
    fn v2_place_leaf(&mut self, path: &[u8; 32], leaf: [u8; 32]) -> Result<u16, S::Error> {
        let site = self.v2_resolve(path)?;
        self.set_node(MAX_DEPTH, path, leaf);
        Ok(match site {
            V2Site::EmptyTree => {
                // First key: its exclusive region is the whole tree — the top
                // IS the root row.
                let top = fold_tail(leaf, path, MAX_DEPTH, 0);
                self.set_node(0, path, top);
                self.set_p(0, path, *path);
                0
            }
            V2Site::Resident { top_depth } => {
                // Value change only — the shape is untouched. (top_depth ==
                // 256 means the leaf IS the top; the leaf write above already
                // did the job and the crown recompute runs the full path,
                // which for a leaf-adjacent branch is exactly the crown.)
                if top_depth < MAX_DEPTH {
                    let top = fold_tail(leaf, path, MAX_DEPTH, top_depth);
                    self.set_node(top_depth, path, top);
                }
                top_depth
            }
            V2Site::DivesIntoUnary {
                top_depth,
                neighbor_path,
            } => {
                // The path shares more bits with a lone resident than that
                // resident's materialized top: split at the true divergence
                // bit `s`, re-anchor both keys at depth s+1, and rewrite the
                // old top position as a chain row.
                let s = first_diff_bit(path, &neighbor_path);
                debug_assert!(s >= top_depth && s < MAX_DEPTH);
                let q_leaf = self.get_node(MAX_DEPTH, &neighbor_path)?;
                debug_assert!(q_leaf != EMPTY_HASH, "unary top without a leaf row");
                let k_top = fold_tail(leaf, path, MAX_DEPTH, s + 1);
                let q_top = fold_tail(q_leaf, &neighbor_path, MAX_DEPTH, s + 1);
                self.set_node(s + 1, path, k_top);
                self.set_p(s + 1, path, *path);
                self.set_node(s + 1, &neighbor_path, q_top);
                self.set_p(s + 1, &neighbor_path, neighbor_path);
                // Branch at s (the two children differ exactly at bit s).
                let branch = if bit_get(path, s) {
                    interior_hash(&q_top, &k_top)
                } else {
                    interior_hash(&k_top, &q_top)
                };
                self.set_node(s, path, branch);
                // Chain rows from just above the branch back up to the old
                // top position (which stops being a top: p: retired, n: row
                // rewritten as a chain hash — both trails now cover it).
                let mut h = branch;
                let mut d = s;
                while d > top_depth {
                    d -= 1;
                    h = if bit_get(path, d) {
                        interior_hash(&EMPTY_HASH, &h)
                    } else {
                        interior_hash(&h, &EMPTY_HASH)
                    };
                    self.set_node(d, path, h);
                }
                self.del_p(top_depth, path);
                top_depth
            }
            V2Site::BranchAdjacent { boundary_depth } => {
                // The path leaves the populated tree just below the boundary
                // node: anchor a fresh exclusive top one level under it.
                let top = fold_tail(leaf, path, MAX_DEPTH, boundary_depth + 1);
                self.set_node(boundary_depth + 1, path, top);
                self.set_p(boundary_depth + 1, path, *path);
                boundary_depth + 1
            }
        })
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
        self.delete_at(&path, account_id)
    }

    /// [`delete`](Self::delete) with an explicit tree path — test-harness
    /// counterpart of [`update_at`](Self::update_at).
    #[doc(hidden)]
    pub fn delete_at(&mut self, path: &[u8; 32], account_id: &[u8; 32]) -> Result<(), S::Error> {
        // R36 (audit stage 1): deleting an absent key is a no-op — detect it
        // once up front (previously discovered at the walk's first iteration,
        // after buffering spurious tombstones for a key that was never
        // there). Guarded on BOTH the node and the value being absent so a
        // pathological half-present store still takes the full healing path
        // below.
        if self.get_node(MAX_DEPTH, path)? == EMPTY_HASH && self.get(account_id)?.is_none() {
            return Ok(());
        }
        let resume = if self.is_v2()? {
            match self.v2_remove_leaf(path)? {
                Some(depth) => depth,
                None => {
                    // Tree emptied (or nothing structural to do): still drop
                    // the value row below.
                    self.pending_values.remove(account_id);
                    self.pending_value_deletes.insert(*account_id);
                    return Ok(());
                }
            }
        } else {
            // Collapse the leaf node (depth 256) to empty, mirroring how the
            // walk retires an emptied interior node: drop any buffered leaf
            // and record the node-key deletion so `get_node` reads EMPTY_HASH.
            self.tombstone_node(MAX_DEPTH, path);
            MAX_DEPTH
        };
        // Drop the buffered value and schedule the `v:` value-key removal so the
        // committed lookup no longer answers `get`/`proof` for this key.
        self.pending_values.remove(account_id);
        self.pending_value_deletes.insert(*account_id);
        // Fold the change up to the root, collapsing every interior node that
        // is now empty along this key's no-longer-shared path.
        self.recompute_path_from(path, resume)?;
        Ok(())
    }

    /// v2 delete-side structure walk: tombstone the leaf/top/`p:` rows of the
    /// key at `path`, re-anchor a lone neighbor whose exclusive region grew,
    /// and return `Some(resume_depth)` for the shared per-level recompute —
    /// or `None` when the structural work is already complete (tree emptied,
    /// or the key had no structural footprint).
    fn v2_remove_leaf(&mut self, path: &[u8; 32]) -> Result<Option<u16>, S::Error> {
        let site = self.v2_resolve(path)?;
        let top_depth = match site {
            V2Site::Resident { top_depth } => top_depth,
            // Absent shapes: the R36 guard already returned for genuinely
            // absent keys; a half-present store (value row without a leaf
            // row) has no tree structure to remove.
            _ => return Ok(None),
        };
        // The key's own rows: leaf, top (when distinct from the leaf), p:.
        self.tombstone_node(MAX_DEPTH, path);
        if top_depth < MAX_DEPTH {
            self.tombstone_node(top_depth, path);
        }
        self.del_p(top_depth, path);
        if top_depth == 0 {
            // Sole key — the tree is now empty; its top was the root row,
            // already tombstoned above.
            return Ok(None);
        }
        // The deepest branch on this path sits exactly one level above the
        // exclusive top; its other child is the sibling subtree's top.
        let branch_depth = top_depth - 1;
        let mut sib = path_mask(path, top_depth);
        bit_toggle(&mut sib, branch_depth);
        match self.get_p(top_depth, &sib)? {
            Some(q) => {
                // Lone neighbor: with this key gone the branch dissolves and
                // the neighbor's exclusive region extends up to one level
                // below the NEXT branch above (or to the root if none).
                let mut next_branch: Option<u16> = None;
                for d in (0..branch_depth).rev() {
                    let mut m = path_mask(path, d + 1);
                    bit_toggle(&mut m, d);
                    if self.get_node(d + 1, &m)? != EMPTY_HASH {
                        next_branch = Some(d);
                        break;
                    }
                }
                let new_top_depth = match next_branch {
                    Some(d) => d + 1,
                    None => 0,
                };
                let old_top_hash = self.get_node(top_depth, &sib)?;
                debug_assert!(old_top_hash != EMPTY_HASH, "p: row at an empty position");
                // Rows that covered only this pair's shared run are gone:
                // the chain strictly between the new top and the dissolved
                // branch, the branch row itself, and the neighbor's old top
                // (unless that top is its leaf, which always stays).
                for d in new_top_depth + 1..=branch_depth {
                    self.tombstone_node(d, path);
                }
                if top_depth < MAX_DEPTH {
                    self.tombstone_node(top_depth, &sib);
                }
                self.del_p(top_depth, &sib);
                let new_top = fold_tail(old_top_hash, &q, top_depth, new_top_depth);
                self.set_node(new_top_depth, &q, new_top);
                self.set_p(new_top_depth, &q, q);
                if new_top_depth == 0 {
                    // Neighbor is now the sole key; its top IS the root row.
                    return Ok(None);
                }
                Ok(Some(new_top_depth))
            }
            None => {
                // Branchy neighbor: its top stays anchored; the dissolved
                // branch becomes a chain row, recomputed by the shared walk.
                Ok(Some(top_depth))
            }
        }
    }

    /// Collect the compressed sibling set along `path`: a 256-bit presence
    /// bitmap plus the non-empty siblings (leaf-parent → root order).
    ///
    /// On a legacy store every level is probed (the original walk); on a v2
    /// store the structure oracle bounds the probing to the crown, and the
    /// single below-crown sibling a diving path can have is recomputed from
    /// the lone neighbor's leaf (tail hashes are not materialized in v2).
    /// Both arms produce byte-identical proofs.
    fn collect_siblings(&self, path: &[u8; 32]) -> Result<CompressedSiblings, S::Error> {
        let mut present = [0u8; 32];
        let mut siblings = Vec::new();
        if !self.is_v2()? {
            self.probe_siblings_below(path, MAX_DEPTH, &mut present, &mut siblings)?;
            return Ok((present, siblings));
        }
        match self.v2_resolve(path)? {
            V2Site::EmptyTree => {}
            V2Site::Resident { top_depth } => {
                // Below the exclusive top every sibling is empty.
                self.probe_siblings_below(path, top_depth, &mut present, &mut siblings)?;
            }
            V2Site::DivesIntoUnary {
                top_depth,
                neighbor_path,
            } => {
                // One non-empty sibling below the crown: the lone neighbor's
                // (unmaterialized) tail node at the divergence level.
                let s = first_diff_bit(path, &neighbor_path);
                debug_assert!(s >= top_depth && s < MAX_DEPTH);
                let q_leaf = self.get_node(MAX_DEPTH, &neighbor_path)?;
                debug_assert!(q_leaf != EMPTY_HASH, "unary top without a leaf row");
                let q_tail = fold_tail(q_leaf, &neighbor_path, MAX_DEPTH, s + 1);
                bit_set(&mut present, s);
                siblings.push(q_tail);
                self.probe_siblings_below(path, top_depth, &mut present, &mut siblings)?;
            }
            V2Site::BranchAdjacent { boundary_depth } => {
                // The first possibly-non-empty sibling is the boundary node's
                // populated child at `boundary_depth + 1`; from there upward
                // it is ordinary crown probing.
                self.probe_siblings_below(path, boundary_depth + 1, &mut present, &mut siblings)?;
            }
        }
        Ok((present, siblings))
    }

    /// Probe the siblings of `path` at parent depths `below_depth-1 ..= 0`
    /// (descending — leaf-parent → root order), appending the non-empty ones
    /// to `siblings` and setting their bits in `present`. `below_depth ==
    /// MAX_DEPTH` is the full legacy probe.
    fn probe_siblings_below(
        &self,
        path: &[u8; 32],
        below_depth: u16,
        present: &mut [u8; 32],
        siblings: &mut Vec<[u8; 32]>,
    ) -> Result<(), S::Error> {
        for parent_depth in (0..below_depth).rev() {
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
                bit_set(present, parent_depth);
                siblings.push(sib);
            }
        }
        Ok(())
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

    /// Flush all buffered writes to the store in one atomic batch. On a
    /// virgin (born-v2) store the first commit also persists the `f:format`
    /// tag row.
    pub fn commit(&mut self) -> Result<(), S::Error> {
        let format = self.format()?;
        let mut puts: Vec<(Vec<u8>, [u8; 32])> = Vec::with_capacity(
            self.cache.len() + self.p_cache.len() + self.pending_values.len() + 1,
        );
        for (&(depth, ref path_prefix), hash) in &self.cache {
            puts.push((node_key(depth, path_prefix), *hash));
        }
        for (&(depth, ref path_prefix), resident) in &self.p_cache {
            puts.push((p_key(depth, path_prefix), *resident));
        }
        for (acc, hash) in &self.pending_values {
            puts.push((value_key(acc), *hash));
        }
        if format == FMT_V2_FLAG_PENDING {
            puts.push((FORMAT_KEY.to_vec(), FORMAT_V2_TAG));
        }
        let mut deletes: Vec<Vec<u8>> = self
            .deletes
            .iter()
            .map(|(depth, path_prefix)| node_key(*depth, path_prefix))
            .collect();
        for (depth, path_prefix) in &self.p_deletes {
            deletes.push(p_key(*depth, path_prefix));
        }
        // Value-key (`v:`) removals from `delete`. Disjoint from `puts`: a key is
        // mutually exclusive between `pending_values` and `pending_value_deletes`
        // (and likewise `cache`/`deletes`, `p_cache`/`p_deletes`), and the
        // `f:`/`n:`/`p:`/`v:` namespaces are disjoint by their first byte, so the
        // `write_batch` "puts and deletes never touch the same key" contract holds.
        for acc in &self.pending_value_deletes {
            deletes.push(value_key(acc));
        }

        self.store.write_batch(&puts, &deletes)?;
        self.cache.clear();
        self.deletes.clear();
        self.p_cache.clear();
        self.p_deletes.clear();
        self.pending_values.clear();
        self.pending_value_deletes.clear();
        if format == FMT_V2_FLAG_PENDING {
            self.format_state.store(FMT_V2, Ordering::Release);
        }
        Ok(())
    }

    /// One-shot in-place migration of a LEGACY (full-tail) store to the v2
    /// compact format, from the complete `(key, value)` leaf set the caller
    /// enumerated out of the store's own `v:` rows (NOT from any external
    /// account list — orphan leaves must survive so the root is preserved).
    ///
    /// The v2 row set is rebuilt in memory first and its root compared to the
    /// committed legacy root; on any mismatch the store is left byte-for-byte
    /// untouched ([`MigrateOutcome::RootMismatch`]). On match, one atomic
    /// `write_batch` replaces the legacy node rows with the v2 rows and the
    /// format tag — there is no observable half-migrated state.
    ///
    /// Call on a freshly-opened tree (no buffered mutations); buffered state
    /// would be discarded by design here, so it is debug-asserted empty.
    pub fn migrate_legacy_to_v2(
        &mut self,
        leaves: &[([u8; 32], [u8; 32])],
    ) -> Result<MigrateOutcome, S::Error> {
        debug_assert!(
            self.cache.is_empty()
                && self.deletes.is_empty()
                && self.p_cache.is_empty()
                && self.p_deletes.is_empty()
                && self.pending_values.is_empty()
                && self.pending_value_deletes.is_empty(),
            "migrate_legacy_to_v2 must run on a freshly-opened tree"
        );
        if self.is_v2()? {
            return Ok(MigrateOutcome::AlreadyV2);
        }
        let expected = self.root()?;
        // Rebuild the exact leaf set through the v2 walk on a scratch store.
        // `MemorySmtStore` is infallible, so the swallowed Results below can
        // never actually be errors — and even a hypothetical silent skip is
        // caught by the committed-root anchor gate before anything is written.
        let mut scratch = SparseMerkleTree::new(MemorySmtStore::new());
        for (account_id, state_hash) in leaves {
            let _ = scratch.update(account_id, state_hash);
        }
        let _ = scratch.commit();
        let store = scratch.into_store();
        // Anchor gate: the COMMITTED scratch rows must reproduce the legacy
        // root exactly, or the store stays untouched. This also guards the
        // "supplied leaf set incomplete" and "legacy store internally
        // inconsistent" cases.
        let rebuilt = store
            .map
            .get(&node_key(0, &[0u8; 32]))
            .copied()
            .unwrap_or(EMPTY_HASH);
        if rebuilt != expected {
            return Ok(MigrateOutcome::RootMismatch { expected, rebuilt });
        }
        let mut puts: Vec<(Vec<u8>, [u8; 32])> = store
            .map
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        // Deterministic batch order (HashMap iteration is not) — helps store
        // implementations that log or diff batches; not required for
        // correctness since keys are unique.
        puts.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        let put_keys: HashSet<&[u8]> = puts.iter().map(|(k, _)| k.as_slice()).collect();
        // Every node row a legacy store can hold for these keys, minus the
        // rows the v2 set re-writes (write_batch forbids put+delete overlap).
        let mut deletes: Vec<Vec<u8>> = Vec::new();
        let mut seen: HashSet<Vec<u8>> = HashSet::new();
        for (account_id, _) in leaves {
            let path = account_path(account_id);
            for depth in 0..=MAX_DEPTH {
                let key = node_key(depth, &path_mask(&path, depth));
                if !put_keys.contains(key.as_slice()) && seen.insert(key.clone()) {
                    deletes.push(key);
                }
            }
        }
        self.store.write_batch(&puts, &deletes)?;
        self.format_state.store(FMT_V2, Ordering::Release);
        Ok(MigrateOutcome::Migrated { keys: leaves.len() })
    }

    // ─── R38: sharded batch flush (owned delta per shard, serial top merge) ──

    /// Compute one shard's owned delta for a batch flush, read-only. All
    /// `entries` must share the same top-`shard_bits` path prefix (their
    /// shard). Each entry is walked by the ordinary audited v2 walk on a
    /// private view tree layered delta-so-far → committed store; the
    /// resulting rows at depths `>= shard_bits` accumulate into the delta.
    /// Crown rows (depths `< shard_bits`) are discarded — the serial merge
    /// recomputes them from actual children, so per-shard crown opinions can
    /// never race. An entry is REFUSED into `delta.refused` (for the serial
    /// walk in [`apply_shard_deltas`](Self::apply_shard_deltas)) when its
    /// structure crosses the boundary:
    /// - the shard-root row is empty in the layered view (region empty or its
    ///   resident's top sits above the boundary — resolution would need crown
    ///   structure), or
    /// - the walk wrote/retired a `p:` row above the boundary (tops always
    ///   carry `p:`, so this signal is exact — e.g. a delete re-anchoring a
    ///   lone neighbor into the crown), or
    /// - the store is not v2 (legacy stores take the serial full walk).
    ///
    /// Distinct shards touch disjoint row keyspaces at depths `>= shard_bits`
    /// (every such mask embeds the shard prefix), so deltas from concurrent
    /// `compute_shard_delta` calls (this method is `&self`) merge without
    /// conflicts. Determinism does not depend on thread schedule.
    ///
    /// Must run on a tree with EMPTY buffers (flush batches commit per call);
    /// buffered state is invisible to the view and would make results stale.
    pub fn compute_shard_delta(
        &self,
        shard_bits: u8,
        entries: &[ShardEntry],
    ) -> Result<ShardDelta, S::Error> {
        debug_assert!(
            self.cache.is_empty() && self.deletes.is_empty() && self.p_cache.is_empty(),
            "compute_shard_delta requires empty tree buffers"
        );
        debug_assert!(shard_bits as u16 <= MAX_DEPTH);
        let mut delta = ShardDelta {
            shard_bits,
            ..ShardDelta::default()
        };
        if !self.is_v2()? {
            delta.refused = entries.to_vec();
            return Ok(delta);
        }
        for entry in entries {
            let (path, account_id, op) = entry;
            debug_assert!(
                delta
                    .rep_path
                    .is_none_or(|rp| path_mask(&rp, shard_bits as u16)
                        == path_mask(path, shard_bits as u16)),
                "entry outside this shard's prefix"
            );
            // Boundary pre-check through the LAYERED view (delta + store):
            // an empty shard-root means resolution needs crown structure.
            let shard_root_key = node_key(shard_bits as u16, &path_mask(path, shard_bits as u16));
            let shard_root_present = {
                let view = ShardView {
                    delta: &delta,
                    base: &self.store,
                };
                view.get(&shard_root_key)?.is_some()
            };
            if !shard_root_present {
                delta.refused.push(*entry);
                continue;
            }
            let mut tree = SparseMerkleTree::new(ShardView {
                delta: &delta,
                base: &self.store,
            });
            // The base carries the v2 tag (checked above), so the view
            // resolves v2; skip re-probing.
            tree.format_state.store(FMT_V2, Ordering::Relaxed);
            match op {
                Some(state_hash) => tree.update_at(path, account_id, state_hash)?,
                None => tree.delete_at(path, account_id)?,
            }
            // Exact boundary-crossing signal: p: activity above the shard
            // depth means top structure moved into the crown; p: activity AT
            // the shard depth means the walk consulted crown-adjacent state
            // (a delete re-anchoring at, or removing a top from, the
            // boundary reads the sibling REGION'S root — another shard's
            // property, stale in this view). Both go to the serial walk.
            let crosses = tree
                .p_cache
                .keys()
                .chain(tree.p_deletes.iter())
                .any(|(d, _)| *d <= shard_bits as u16);
            // Take ownership of the view tree's buffers; `store: _` drops the
            // ShardView here, releasing its borrow of `delta`.
            let SparseMerkleTree {
                store: _,
                cache: t_cache,
                deletes: t_deletes,
                p_cache: t_p_cache,
                p_deletes: t_p_deletes,
                pending_values: t_values,
                pending_value_deletes: t_value_deletes,
                format_state: _,
            } = tree;
            if crosses {
                delta.refused.push(*entry);
                continue;
            }
            // Drain the view's buffers into the shard delta, keeping the
            // set/tombstone exclusivity per row and dropping crown n-rows
            // (depths < shard_bits) — the serial merge recomputes those.
            for ((d, m), h) in t_cache {
                if d >= shard_bits as u16 {
                    delta.node_deletes.remove(&(d, m));
                    delta.nodes.insert((d, m), h);
                }
            }
            for (d, m) in t_deletes {
                if d >= shard_bits as u16 {
                    delta.nodes.remove(&(d, m));
                    delta.node_deletes.insert((d, m));
                }
            }
            for ((d, m), p) in t_p_cache {
                delta.p_node_deletes.remove(&(d, m));
                delta.p_nodes.insert((d, m), p);
            }
            for (d, m) in t_p_deletes {
                delta.p_nodes.remove(&(d, m));
                delta.p_node_deletes.insert((d, m));
            }
            for (acc, v) in t_values {
                delta.value_deletes.remove(&acc);
                delta.values.insert(acc, v);
            }
            for acc in t_value_deletes {
                delta.values.remove(&acc);
                delta.value_deletes.insert(acc);
            }
            delta.rep_path.get_or_insert(*path);
        }
        Ok(delta)
    }

    /// Serial merge phase of the R38 sharded flush: install every shard's
    /// owned delta into this tree's buffers, replay the refused entries
    /// through the ordinary serial walk, then recompute the crown (depths
    /// `< shard_bits`) once per dirty shard from actual children. Call
    /// [`commit`](Self::commit) afterwards as usual. The result is
    /// byte-identical to walking every entry serially: the tree is a pure
    /// function of the final key→value map, deltas touch disjoint rows, and
    /// the merge order below is data-independent.
    pub fn apply_shard_deltas(&mut self, deltas: Vec<ShardDelta>) -> Result<(), S::Error> {
        let mut crown_reps: Vec<(u8, [u8; 32])> = Vec::new();
        let mut refused: Vec<ShardEntry> = Vec::new();
        for delta in deltas {
            for ((d, m), h) in delta.nodes {
                self.deletes.remove(&(d, m));
                self.cache.insert((d, m), h);
            }
            for (d, m) in delta.node_deletes {
                self.cache.remove(&(d, m));
                self.deletes.insert((d, m));
            }
            for ((d, m), p) in delta.p_nodes {
                self.p_deletes.remove(&(d, m));
                self.p_cache.insert((d, m), p);
            }
            for (d, m) in delta.p_node_deletes {
                self.p_cache.remove(&(d, m));
                self.p_deletes.insert((d, m));
            }
            for (acc, v) in delta.values {
                self.pending_value_deletes.remove(&acc);
                self.pending_values.insert(acc, v);
            }
            for acc in delta.value_deletes {
                self.pending_values.remove(&acc);
                self.pending_value_deletes.insert(acc);
            }
            if let Some(rep) = delta.rep_path {
                crown_reps.push((delta.shard_bits, rep));
            }
            refused.extend(delta.refused);
        }
        // Crown recompute FIRST, one representative path per dirty shard —
        // this both refreshes crown VALUES and fixes crown EXISTENCE
        // (empties collapse, chains re-anchor) from the delta-fresh children
        // at the shard depth. It must precede the refused replays: their
        // resolution reads crown rows, and shard deltas deliberately discard
        // crown writes/tombstones, so without this pass a replay would
        // resolve against stale pre-batch crown structure (measured: a top
        // anchored one level too deep). Shared parents get recomputed more
        // than once with identical inputs — idempotent; cost bounded by
        // 2^shard_bits × shard_bits.
        for (bits, rep) in crown_reps {
            self.recompute_path_from(&rep, bits as u16)?;
        }
        // Refused entries then take the ordinary serial walk against the
        // merged, crown-fresh layered state; each replay maintains full v2
        // structure (including crown tops), and the tree is a pure function
        // of the final key→value map, so replay position after the parallel
        // phase cannot change the result.
        for (path, account_id, op) in refused {
            match op {
                Some(state_hash) => self.update_at(&path, &account_id, &state_hash)?,
                None => self.delete_at(&path, &account_id)?,
            }
        }
        Ok(())
    }

    // ─── Internals ─────────────────────────────────────────────────────────────

    /// Resolve (and memoize) the store format. `f:format` row present with the
    /// v2 tag → v2; present with an unknown tag, or absent while data exists →
    /// legacy (fail-safe-slow full walk); absent on a virgin store → v2, with
    /// the tag row written at the next commit.
    fn format(&self) -> Result<u8, S::Error> {
        let s = self.format_state.load(Ordering::Acquire);
        if s != FMT_UNRESOLVED {
            return Ok(s);
        }
        let resolved = match self.store.get(FORMAT_KEY)? {
            Some(tag) if tag == FORMAT_V2_TAG => FMT_V2,
            Some(_) => FMT_LEGACY,
            None => {
                // Raw presence probe (NOT get_node — we must distinguish
                // "row exists" from "empty node" here).
                if self.store.get(&node_key(0, &[0u8; 32]))?.is_some() {
                    FMT_LEGACY
                } else {
                    FMT_V2_FLAG_PENDING
                }
            }
        };
        self.format_state.store(resolved, Ordering::Release);
        Ok(resolved)
    }

    /// `true` iff the store runs the v2 compact walk.
    fn is_v2(&self) -> Result<bool, S::Error> {
        Ok(matches!(self.format()?, FMT_V2 | FMT_V2_FLAG_PENDING))
    }

    /// The store format currently in effect, for diagnostics: `2` = v2
    /// compact, `1` = legacy full-tail.
    #[doc(hidden)]
    pub fn detected_format(&self) -> Result<u8, S::Error> {
        Ok(if self.is_v2()? { 2 } else { 1 })
    }

    /// Layered read of a `p:` (exclusive-top path) row: pending writes, then
    /// pending deletes, then the committed store.
    fn get_p(&self, depth: u16, path_prefix: &[u8; 32]) -> Result<Option<[u8; 32]>, S::Error> {
        let masked = path_mask(path_prefix, depth);
        if let Some(p) = self.p_cache.get(&(depth, masked)) {
            return Ok(Some(*p));
        }
        if self.p_deletes.contains(&(depth, masked)) {
            return Ok(None);
        }
        self.store.get(&p_key(depth, &masked))
    }

    fn set_p(&mut self, depth: u16, path_prefix: &[u8; 32], resident_path: [u8; 32]) {
        let masked = path_mask(path_prefix, depth);
        self.p_deletes.remove(&(depth, masked));
        self.p_cache.insert((depth, masked), resident_path);
    }

    fn del_p(&mut self, depth: u16, path_prefix: &[u8; 32]) {
        let masked = path_mask(path_prefix, depth);
        self.p_cache.remove(&(depth, masked));
        self.p_deletes.insert((depth, masked));
    }

    /// Buffer the removal of an `n:` node row (cache and store views both).
    fn tombstone_node(&mut self, depth: u16, path_prefix: &[u8; 32]) {
        let masked = path_mask(path_prefix, depth);
        self.cache.remove(&(depth, masked));
        self.deletes.insert((depth, masked));
    }

    /// v2 structure oracle. Binary-searches the deepest stored node on `path`
    /// over depths `0..=255` — stored crown/top rows are depth-contiguous from
    /// the root by the v2 trail invariant, so existence is monotone and ≤8
    /// layered probes suffice — then classifies the boundary via the leaf row
    /// and the `p:` row. Every probe goes through `get_node`/`get_p`
    /// (cache → deletes → store), so in-batch mutations are visible.
    fn v2_resolve(&self, path: &[u8; 32]) -> Result<V2Site, S::Error> {
        if self.get_node(0, &[0u8; 32])? == EMPTY_HASH {
            return Ok(V2Site::EmptyTree);
        }
        // Largest depth in 0..=255 whose on-path node is non-empty.
        let (mut lo, mut hi) = (0u16, MAX_DEPTH - 1);
        while lo < hi {
            let mid = lo + (hi - lo).div_ceil(2);
            if self.get_node(mid, path)? != EMPTY_HASH {
                lo = mid;
            } else {
                hi = mid - 1;
            }
        }
        let b = lo;
        let leaf_present = self.get_node(MAX_DEPTH, path)? != EMPTY_HASH;
        if leaf_present {
            // b == d*(key), except when the deepest branch is leaf-adjacent
            // (d* == 256): then (255, ·) is a branch row, recognizable by its
            // missing `p:` marker.
            return Ok(match self.get_p(b, path)? {
                Some(p) if p == *path => V2Site::Resident { top_depth: b },
                _ => V2Site::Resident { top_depth: MAX_DEPTH },
            });
        }
        match self.get_p(b, path)? {
            Some(q) if q != *path => Ok(V2Site::DivesIntoUnary {
                top_depth: b,
                neighbor_path: q,
            }),
            Some(_) => {
                // p: row claims THIS path is resident but its leaf row is
                // absent — unreachable via the tree's own operations. Classify
                // deterministically as boundary-adjacent (fail-safe shape).
                debug_assert!(false, "p: row for a leafless path — corrupt store");
                Ok(V2Site::BranchAdjacent { boundary_depth: b })
            }
            None => Ok(V2Site::BranchAdjacent { boundary_depth: b }),
        }
    }

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

    /// Per-level bottom-up recompute of the nodes on `path`, from the parent
    /// of `start_depth` to the root. The on-path child at each level is read
    /// from the buffers (seeded by the caller); the sibling is a layered
    /// lookup. Legacy walks resume from `MAX_DEPTH` (the full original walk);
    /// v2 walks resume from the anchor depth their structural pre-pass
    /// finalized, so only crown rows are visited.
    fn recompute_path_from(&mut self, path: &[u8; 32], start_depth: u16) -> Result<(), S::Error> {
        let mut depth = start_depth;
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

            // R36: the per-level `current` pre-read + `parent_hash == current`
            // early-exit is gone. It could only ever fire on the FIRST
            // iteration (a genuine leaf change forces a changed parent at
            // every level, absent a SHA3 collision), and the two no-op shapes
            // that reached it — same-value update, absent-key delete — now
            // return at the `update`/`delete` entry instead. Dropping the
            // read removes ~256 of the ~512 real store lookups per mutation.
            if parent_hash == EMPTY_HASH {
                self.tombstone_node(parent_depth, &parent_path);
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

    // ─── R36 (audit stage 1): up-front no-op detection ──────────────────────

    /// A byte-identical re-update and an absent-key delete must not buffer ANY
    /// work: cache, deletes, and both pending-value maps stay empty. This pins
    /// the R36 early-return as an invariant (the pre-R36 code buffered
    /// redundant same-byte writes and spurious tombstones, which commit()
    /// then pushed into the store as a no-op-shaped write batch).
    #[test]
    fn noop_update_and_absent_delete_buffer_no_work() {
        let mut t = SparseMerkleTree::new(MemorySmtStore::default());
        let a = *b"noop_target_account_id_32_bytes!";
        let v = sha3_256(b"state-v1");
        t.update(&a, &v).unwrap();
        t.commit().unwrap();
        let root_before = t.root().unwrap();

        // Same-value update after commit: early return, nothing buffered.
        t.update(&a, &v).unwrap();
        assert!(t.cache.is_empty(), "no-op update must not populate cache");
        assert!(t.deletes.is_empty(), "no-op update must not tombstone");
        assert!(t.pending_values.is_empty(), "no-op update must not re-buffer value");
        assert!(t.pending_value_deletes.is_empty());

        // Absent-key delete: early return, nothing buffered.
        let absent = *b"never_inserted_account_id_32byte";
        t.delete(&absent).unwrap();
        assert!(t.cache.is_empty(), "absent delete must not populate cache");
        assert!(t.deletes.is_empty(), "absent delete must not tombstone");
        assert!(t.pending_value_deletes.is_empty());

        t.commit().unwrap();
        assert_eq!(t.root().unwrap(), root_before, "root must be untouched");
        // Changed-value update must still take the full path.
        let v2 = sha3_256(b"state-v2");
        t.update(&a, &v2).unwrap();
        assert!(!t.cache.is_empty(), "genuine update must buffer the walk");
        t.commit().unwrap();
        assert_ne!(t.root().unwrap(), root_before);
    }

    /// Randomized op soup — updates (with deliberate same-value repeats),
    /// deletes (with deliberate absent-key repeats), interleaved commits —
    /// must land on a root byte-identical to a fresh tree built from only the
    /// final survivor state, and every survivor must produce a verifying
    /// inclusion proof. Deterministic splitmix64 PRNG; guards the R36
    /// early-return against every interleaving class it could plausibly skew.
    #[test]
    fn randomized_ops_with_noops_match_fresh_tree_over_final_state() {
        fn splitmix(state: &mut u64) -> u64 {
            *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = *state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
        let mut seed = 0x00E1_A2A0_2026_0727u64;
        let mut t = SparseMerkleTree::new(MemorySmtStore::default());
        let mut truth: std::collections::BTreeMap<[u8; 32], [u8; 32]> =
            std::collections::BTreeMap::new();

        const KEYS: u64 = 64;
        const OPS: u64 = 600;
        for op in 0..OPS {
            let k_idx = splitmix(&mut seed) % KEYS;
            let key = sha3_256(&k_idx.to_be_bytes());
            match splitmix(&mut seed) % 10 {
                // 0-4: update to a fresh value
                0..=4 => {
                    let v = sha3_256(&splitmix(&mut seed).to_be_bytes());
                    t.update(&key, &v).unwrap();
                    truth.insert(key, v);
                }
                // 5-6: repeat the CURRENT value if present (no-op shape),
                // else insert a fresh one
                5 | 6 => {
                    let v = truth
                        .get(&key)
                        .copied()
                        .unwrap_or_else(|| sha3_256(&splitmix(&mut seed).to_be_bytes()));
                    t.update(&key, &v).unwrap();
                    truth.insert(key, v);
                }
                // 7-8: delete (often absent — the no-op shape)
                7 | 8 => {
                    t.delete(&key).unwrap();
                    truth.remove(&key);
                }
                // 9: delete-then-reinsert same value in one buffered batch
                _ => {
                    t.delete(&key).unwrap();
                    let v = truth
                        .get(&key)
                        .copied()
                        .unwrap_or_else(|| sha3_256(&splitmix(&mut seed).to_be_bytes()));
                    t.update(&key, &v).unwrap();
                    truth.insert(key, v);
                }
            }
            if op % 37 == 0 {
                t.commit().unwrap();
            }
        }
        t.commit().unwrap();

        // Fresh tree over only the survivors must reproduce the root.
        let mut fresh = SparseMerkleTree::new(MemorySmtStore::default());
        for (k, v) in &truth {
            fresh.update(k, v).unwrap();
        }
        fresh.commit().unwrap();
        assert_eq!(
            t.root().unwrap(),
            fresh.root().unwrap(),
            "op-soup root must equal fresh-build over final state"
        );

        // Every survivor proves; every deleted key excludes.
        let root = t.root().unwrap();
        for (k, v) in &truth {
            let p = t.proof(k).unwrap().expect("survivor must have a proof");
            assert!(verify_proof(&p), "survivor proof must verify");
            assert_eq!(p.root, root);
            assert_eq!(p.state_hash, *v);
        }
        for k_idx in 0..KEYS {
            let key = sha3_256(&k_idx.to_be_bytes());
            if !truth.contains_key(&key) {
                let e = t
                    .exclusion_proof(&key)
                    .unwrap()
                    .expect("absent key must have an exclusion proof");
                assert!(verify_exclusion_proof(&e), "exclusion proof must verify");
            }
        }
    }

    // ─── R37 (audit stage 2): compact store + divergence-aware walk ─────────
    // The battery mandated by internal design notes §3
    // Stage 2, gates (i)–(viii). The write path is fail-silent (C2), so these
    // tests are the only guard on root bit-identicality.

    /// The format tag is pinned to its preimage so no edit can silently move
    /// the format key out from under deployed stores.
    #[test]
    fn format_v2_tag_matches_preimage() {
        assert_eq!(FORMAT_V2_TAG, sha3_256(b"elara-smt-store-format-v2"));
    }

    /// A virgin store is born v2: the first commit persists the `f:format`
    /// row, and a reopened tree detects v2.
    #[test]
    fn virgin_store_gets_format_tag_on_first_commit() {
        let mut t = tree();
        t.update(&acc(b"first"), &sha3_256(b"v")).unwrap();
        t.commit().unwrap();
        let store = t.into_store();
        assert_eq!(
            store.map.get(FORMAT_KEY),
            Some(&FORMAT_V2_TAG),
            "first commit must persist the format tag"
        );
        let reopened = SparseMerkleTree::new(store);
        assert_eq!(reopened.detected_format().unwrap(), 2);
    }

    /// Deterministic splitmix64 op stream applied to BOTH arms — the v2
    /// compact walk and the forced-legacy full walk — asserting root equality
    /// after EVERY single op (battery (i)) plus byte-equal inclusion AND
    /// exclusion proofs at the end (battery (iii), (vi)).
    #[test]
    fn dual_arm_randomized_roots_equal_after_every_op() {
        fn splitmix(state: &mut u64) -> u64 {
            *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = *state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
        let mut seed = 0x00E1_A2A0_2026_0728u64;
        let mut v2 = tree();
        let mut legacy = SparseMerkleTree::new_legacy_unchecked(MemorySmtStore::new());
        assert_eq!(v2.detected_format().unwrap(), 2);
        assert_eq!(legacy.detected_format().unwrap(), 1);

        const KEYS: u64 = 48;
        const OPS: u64 = 500;
        let mut live: std::collections::BTreeMap<[u8; 32], [u8; 32]> =
            std::collections::BTreeMap::new();
        for op in 0..OPS {
            let key = sha3_256(&(splitmix(&mut seed) % KEYS).to_be_bytes());
            match splitmix(&mut seed) % 8 {
                0..=4 => {
                    let v = sha3_256(&splitmix(&mut seed).to_be_bytes());
                    v2.update(&key, &v).unwrap();
                    legacy.update(&key, &v).unwrap();
                    live.insert(key, v);
                }
                5 | 6 => {
                    v2.delete(&key).unwrap();
                    legacy.delete(&key).unwrap();
                    live.remove(&key);
                }
                _ => {
                    // Same-value rewrite (no-op shape) where possible.
                    let v = live
                        .get(&key)
                        .copied()
                        .unwrap_or_else(|| sha3_256(&splitmix(&mut seed).to_be_bytes()));
                    v2.update(&key, &v).unwrap();
                    legacy.update(&key, &v).unwrap();
                    live.insert(key, v);
                }
            }
            assert_eq!(
                v2.root().unwrap(),
                legacy.root().unwrap(),
                "arms diverged at op #{op}"
            );
            if op % 41 == 0 {
                v2.commit().unwrap();
                legacy.commit().unwrap();
            }
        }
        v2.commit().unwrap();
        legacy.commit().unwrap();
        assert_eq!(v2.root().unwrap(), legacy.root().unwrap());

        // Byte-equal proofs across arms: every live key's inclusion proof and
        // every dead key's exclusion proof.
        for k_idx in 0..KEYS {
            let key = sha3_256(&k_idx.to_be_bytes());
            if live.contains_key(&key) {
                let a = v2.proof(&key).unwrap().unwrap();
                let b = legacy.proof(&key).unwrap().unwrap();
                assert_eq!(a.state_hash, b.state_hash);
                assert_eq!(a.root, b.root);
                assert_eq!(a.present, b.present, "inclusion bitmap diverged");
                assert_eq!(a.siblings, b.siblings, "inclusion siblings diverged");
                assert!(verify_proof(&a));
            } else {
                let a = v2.exclusion_proof(&key).unwrap().unwrap();
                let b = legacy.exclusion_proof(&key).unwrap().unwrap();
                assert_eq!(a.root, b.root);
                assert_eq!(a.present, b.present, "exclusion bitmap diverged");
                assert_eq!(a.siblings, b.siblings, "exclusion siblings diverged");
                assert!(verify_exclusion_proof(&a));
            }
        }
    }

    /// Battery (ii): after an op soup, the COMMITTED v2 store must be
    /// byte-for-byte identical (every row: `n:`, `p:`, `v:`, `f:`) to a fresh
    /// v2 build over only the survivors — the strongest guard against delete
    /// re-anchoring leaving orphan rows or missing trail rows.
    #[test]
    fn store_content_equals_fresh_build_over_survivors() {
        fn splitmix(state: &mut u64) -> u64 {
            *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = *state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
        let mut seed = 0x51_0E37_2026_0728u64;
        let mut t = tree();
        let mut live: std::collections::BTreeMap<[u8; 32], [u8; 32]> =
            std::collections::BTreeMap::new();
        for op in 0..700u64 {
            let key = sha3_256(&(splitmix(&mut seed) % 40).to_be_bytes());
            if splitmix(&mut seed).is_multiple_of(3) {
                t.delete(&key).unwrap();
                live.remove(&key);
            } else {
                let v = sha3_256(&splitmix(&mut seed).to_be_bytes());
                t.update(&key, &v).unwrap();
                live.insert(key, v);
            }
            if op % 53 == 0 {
                t.commit().unwrap();
            }
        }
        t.commit().unwrap();

        let mut fresh = tree();
        for (k, v) in &live {
            fresh.update(k, v).unwrap();
        }
        fresh.commit().unwrap();

        let got = t.into_store().map;
        let want = fresh.into_store().map;
        // Diff row-by-row for a readable failure before the blanket compare.
        for (k, v) in &want {
            assert_eq!(
                got.get(k),
                Some(v),
                "missing/mismatched row {:02x?}",
                &k[..4.min(k.len())]
            );
        }
        assert_eq!(got.len(), want.len(), "orphan rows survived the op soup");
    }

    // Raw-path helpers for adversarial shapes real SHA3 paths never hit:
    // depth-`d` shared prefixes with `d` up to 255. Each raw key gets a
    // distinct id; only roots/store-content/get are asserted (proof() derives
    // its path from the id, which raw placement deliberately bypasses).
    fn raw_path(byte: u8, tail: u8) -> [u8; 32] {
        let mut p = [byte; 32];
        p[31] = tail;
        p
    }

    fn diverging_at(base: &[u8; 32], bit: u16) -> [u8; 32] {
        let mut p = *base;
        bit_toggle(&mut p, bit);
        p
    }

    /// Battery (iv): synthetic deep divergences — keys parting at bits 200,
    /// 250, 254, and 255 (the leaf-adjacent branch, `d* == 256`) — pushed
    /// through insert / value-update / delete on BOTH arms, with root
    /// equality after every op and full store equality vs a fresh v2 build
    /// at the end.
    #[test]
    fn deep_divergence_raw_paths_dual_arm() {
        let base = raw_path(0xAB, 0x00);
        let shapes: Vec<([u8; 32], [u8; 32])> = [256u16, 200, 250, 254, 255]
            .iter()
            .enumerate()
            .map(|(i, &bit)| {
                let path = if bit == 256 {
                    base
                } else {
                    diverging_at(&base, bit)
                };
                (path, acc(&[i as u8, 0xEE]))
            })
            .collect();

        let mut v2 = tree();
        let mut legacy = SparseMerkleTree::new_legacy_unchecked(MemorySmtStore::new());
        let val = |n: u8| sha3_256(&[n, n, n]);

        // Insert all, deepest-sharing last and first interleaved.
        for (i, (path, id)) in shapes.iter().enumerate() {
            v2.update_at(path, id, &val(i as u8)).unwrap();
            legacy.update_at(path, id, &val(i as u8)).unwrap();
            assert_eq!(v2.root().unwrap(), legacy.root().unwrap(), "insert #{i}");
        }
        // Value-churn every key (Resident arm at depths 201/251/255/256).
        for (i, (path, id)) in shapes.iter().enumerate() {
            v2.update_at(path, id, &val(0x40 + i as u8)).unwrap();
            legacy.update_at(path, id, &val(0x40 + i as u8)).unwrap();
            assert_eq!(v2.root().unwrap(), legacy.root().unwrap(), "churn #{i}");
        }
        v2.commit().unwrap();
        legacy.commit().unwrap();

        // Delete the leaf-adjacent pair member (d*=256 removal + neighbor
        // re-anchor), then the deepest remaining, asserting equality each time.
        for (i, (path, id)) in shapes.iter().enumerate().rev() {
            v2.delete_at(path, id).unwrap();
            legacy.delete_at(path, id).unwrap();
            assert_eq!(v2.root().unwrap(), legacy.root().unwrap(), "delete #{i}");
            v2.commit().unwrap();
            legacy.commit().unwrap();
        }
        assert_eq!(v2.root().unwrap(), EMPTY_HASH);

        // Rebuild a partial set and compare the committed store to a fresh
        // build over the same survivors (delete re-anchoring shape check).
        let mut t = tree();
        for (i, (path, id)) in shapes.iter().enumerate() {
            t.update_at(path, id, &val(i as u8)).unwrap();
        }
        t.delete_at(&shapes[3].0, &shapes[3].1).unwrap(); // bit-254 member
        t.delete_at(&shapes[1].0, &shapes[1].1).unwrap(); // bit-200 member
        t.commit().unwrap();
        let mut fresh = tree();
        for (i, (path, id)) in shapes.iter().enumerate() {
            if i != 3 && i != 1 {
                fresh.update_at(path, id, &val(i as u8)).unwrap();
            }
        }
        fresh.commit().unwrap();
        assert_eq!(t.root().unwrap(), fresh.root().unwrap());
        assert_eq!(t.into_store().map, fresh.into_store().map);
    }

    /// Battery (v): production-shaped multi-key batches — clustered-prefix
    /// keys mutated in ONE uncommitted batch, so every structure-oracle probe
    /// must read through cache/deletes (an oracle consulting the committed
    /// store alone computes a too-shallow divergence — the audit's #1 risk).
    /// Includes delete-then-reinsert and same-key-twice in-batch.
    #[test]
    fn in_batch_clustered_prefix_oracle_reads_through_buffers() {
        let base = raw_path(0x5C, 0x0F);
        let k1 = (base, acc(b"cluster-1"));
        let k2 = (diverging_at(&base, 250), acc(b"cluster-2"));
        let k3 = (diverging_at(&base, 255), acc(b"cluster-3"));
        let k4 = (diverging_at(&base, 240), acc(b"cluster-4"));
        let val = |n: u8| sha3_256(&[n, 0xBB]);

        // Everything below happens in ONE buffered batch (no commit): the
        // committed store stays EMPTY the whole time, so any oracle blind to
        // the buffers would see an empty tree and mis-anchor every key.
        let mut t = tree();
        let mut legacy = SparseMerkleTree::new_legacy_unchecked(MemorySmtStore::new());
        for (i, (p, id)) in [&k1, &k2, &k3, &k4].iter().enumerate() {
            t.update_at(p, id, &val(i as u8)).unwrap();
            legacy.update_at(p, id, &val(i as u8)).unwrap();
            assert_eq!(t.root().unwrap(), legacy.root().unwrap(), "in-batch #{i}");
        }
        // Same key twice (second write wins), then delete-then-reinsert.
        t.update_at(&k3.0, &k3.1, &val(0x33)).unwrap();
        legacy.update_at(&k3.0, &k3.1, &val(0x33)).unwrap();
        t.delete_at(&k2.0, &k2.1).unwrap();
        legacy.delete_at(&k2.0, &k2.1).unwrap();
        t.update_at(&k2.0, &k2.1, &val(0x22)).unwrap();
        legacy.update_at(&k2.0, &k2.1, &val(0x22)).unwrap();
        // Delete the deepest pair member while still uncommitted.
        t.delete_at(&k3.0, &k3.1).unwrap();
        legacy.delete_at(&k3.0, &k3.1).unwrap();
        assert_eq!(t.root().unwrap(), legacy.root().unwrap());

        t.commit().unwrap();
        legacy.commit().unwrap();
        assert_eq!(t.root().unwrap(), legacy.root().unwrap());

        // Committed shape equals a fresh build over the survivors.
        let mut fresh = tree();
        fresh.update_at(&k1.0, &k1.1, &val(0)).unwrap();
        fresh.update_at(&k2.0, &k2.1, &val(0x22)).unwrap();
        fresh.update_at(&k4.0, &k4.1, &val(3)).unwrap();
        fresh.commit().unwrap();
        assert_eq!(t.root().unwrap(), fresh.root().unwrap());
        assert_eq!(t.into_store().map, fresh.into_store().map);
    }

    /// Battery (vii): a legacy store is recognized and REFUSES the fast path
    /// — the tree keeps the full-tail walk, writes no `p:`/`f:` rows, and
    /// stays root-correct.
    #[test]
    fn legacy_store_detected_and_walked_full_tail() {
        // Build committed legacy content.
        let mut writer = SparseMerkleTree::new_legacy_unchecked(MemorySmtStore::new());
        writer.update(&acc(b"alice"), &sha3_256(b"balance=100")).unwrap();
        writer.commit().unwrap();
        let store = writer.into_store();
        let legacy_rows = store.map.len();
        assert!(
            legacy_rows > 200,
            "legacy write pattern must materialize the tail (got {legacy_rows} rows)"
        );

        // Reopen WITHOUT forcing: data-without-tag must classify as legacy.
        let mut t = SparseMerkleTree::new(store);
        assert_eq!(t.detected_format().unwrap(), 1);
        assert_eq!(
            hex_lower(&t.root().unwrap()),
            PIN_ALICE,
            "legacy root must still match the construction pin"
        );
        // Further mutations stay legacy-shaped: no p:/f: rows, tail present.
        t.update(&acc(b"bob"), &sha3_256(b"balance=200")).unwrap();
        t.update(&acc(b"carol"), &sha3_256(b"balance=300")).unwrap();
        assert_eq!(hex_lower(&t.root().unwrap()), PIN_ABC);
        t.commit().unwrap();
        let map = t.into_store().map;
        assert!(
            !map.contains_key(FORMAT_KEY),
            "legacy store must never gain the v2 tag implicitly"
        );
        assert!(
            !map.keys().any(|k| k.starts_with(b"p:")),
            "legacy store must never gain p: rows"
        );
        assert!(map.len() > 600, "3-key legacy store must keep full tails");
    }

    /// C4: migration is one-shot and root-gated. A migrated store must be
    /// byte-identical to a fresh v2 build over the same leaves (plus nothing
    /// else), preserve the root, and include leaves the ledger never heard of
    /// (orphans) because the leaf set comes from the store itself.
    #[test]
    fn migration_preserves_root_and_equals_fresh_v2_store() {
        let mut writer = SparseMerkleTree::new_legacy_unchecked(MemorySmtStore::new());
        let mut leaves: Vec<([u8; 32], [u8; 32])> = Vec::new();
        for i in 0..12u8 {
            let id = acc(&[i, 0x77]);
            let v = sha3_256(&[i, 0x99]);
            writer.update(&id, &v).unwrap();
            leaves.push((id, v));
        }
        // An "orphan" leaf (no ledger account would list it) — must survive.
        let orphan = (acc(b"orphan-leaf"), sha3_256(b"ghost"));
        writer.update(&orphan.0, &orphan.1).unwrap();
        leaves.push(orphan);
        writer.commit().unwrap();
        let legacy_root = writer.root().unwrap();
        let store = writer.into_store();

        let mut t = SparseMerkleTree::new(store);
        assert_eq!(t.detected_format().unwrap(), 1);
        let outcome = t.migrate_legacy_to_v2(&leaves).unwrap();
        assert_eq!(outcome, MigrateOutcome::Migrated { keys: leaves.len() });
        assert_eq!(t.detected_format().unwrap(), 2);
        assert_eq!(t.root().unwrap(), legacy_root, "migration must preserve the root");
        assert_eq!(t.get(&orphan.0).unwrap(), Some(orphan.1));

        // Store now byte-identical to a fresh v2 build.
        let mut fresh = tree();
        for (id, v) in &leaves {
            fresh.update(id, v).unwrap();
        }
        fresh.commit().unwrap();
        assert_eq!(t.into_store().map, fresh.into_store().map);
    }

    /// C4's abort arm: an incomplete leaf enumeration must be REFUSED with
    /// the store left byte-for-byte untouched — a half-migrated store is a
    /// silent-corruption vector.
    #[test]
    fn migration_refuses_incomplete_leaf_set_untouched() {
        let mut writer = SparseMerkleTree::new_legacy_unchecked(MemorySmtStore::new());
        let mut leaves: Vec<([u8; 32], [u8; 32])> = Vec::new();
        for i in 0..6u8 {
            let id = acc(&[i, 0x13]);
            let v = sha3_256(&[i, 0x14]);
            writer.update(&id, &v).unwrap();
            leaves.push((id, v));
        }
        writer.commit().unwrap();
        let legacy_root = writer.root().unwrap();
        let before = writer.store().map.clone();
        let mut t = SparseMerkleTree::new(writer.into_store());

        let partial = &leaves[..5]; // one leaf withheld
        match t.migrate_legacy_to_v2(partial).unwrap() {
            MigrateOutcome::RootMismatch { expected, rebuilt } => {
                assert_eq!(expected, legacy_root);
                assert_ne!(rebuilt, legacy_root);
            }
            other => panic!("expected RootMismatch, got {other:?}"),
        }
        assert_eq!(t.detected_format().unwrap(), 1, "must stay legacy after refusal");
        assert_eq!(t.into_store().map, before, "refused migration must not write");
    }

    /// Migrating an already-v2 store is a recognized no-op.
    #[test]
    fn migration_on_v2_store_is_noop() {
        let mut t = tree();
        t.update(&acc(b"x"), &sha3_256(b"v")).unwrap();
        t.commit().unwrap();
        let mut reopened = SparseMerkleTree::new(t.into_store());
        assert_eq!(
            reopened.migrate_legacy_to_v2(&[]).unwrap(),
            MigrateOutcome::AlreadyV2
        );
    }

    // ─── R38 (audit stage 3): sharded batch flush ───────────────────────────

    /// Build a committed v2 base store with `n` sha3-pathed keys.
    fn seeded_base(n: u32) -> MemorySmtStore {
        let mut t = tree();
        for i in 0..n {
            t.update(&acc(&i.to_be_bytes()), &sha3_256(&[1, 2, i as u8])).unwrap();
        }
        t.commit().unwrap();
        t.into_store()
    }

    /// Run `batch` through the sharded path on `base` at `shard_bits`.
    fn sharded_apply(
        base: MemorySmtStore,
        batch: &[ShardEntry],
        shard_bits: u8,
    ) -> MemorySmtStore {
        let mut t = SparseMerkleTree::new(base);
        // Partition by top bits of the path (byte 0 shifted) — same rule the
        // runtime uses.
        let mut groups: std::collections::BTreeMap<u8, Vec<ShardEntry>> =
            std::collections::BTreeMap::new();
        for e in batch {
            let idx = if shard_bits == 0 { 0 } else { e.0[0] >> (8 - shard_bits) };
            groups.entry(idx).or_default().push(*e);
        }
        let deltas: Vec<ShardDelta> = groups
            .values()
            .map(|entries| t.compute_shard_delta(shard_bits, entries).unwrap())
            .collect();
        t.apply_shard_deltas(deltas).unwrap();
        t.commit().unwrap();
        t.into_store()
    }

    /// Store equality with a readable symmetric-difference report: prints
    /// each differing row as namespace/depth/mask-prefix instead of a raw
    /// 300-row map dump.
    fn assert_store_eq(got: &MemorySmtStore, want: &MemorySmtStore, label: &str) {
        if got.map == want.map {
            return;
        }
        let describe = |k: &Vec<u8>| -> String {
            if k.len() >= 4 && (k.starts_with(b"n:") || k.starts_with(b"p:")) {
                let d = u16::from_be_bytes([k[2], k[3]]);
                format!(
                    "{}: depth={d} mask={}",
                    k[0] as char,
                    hex_lower(&k[4..k.len().min(10)])
                )
            } else if k.starts_with(b"v:") {
                format!("v: acc={}", hex_lower(&k[2..k.len().min(8)]))
            } else {
                format!("{:02x?}", k)
            }
        };
        for (k, v) in &got.map {
            match want.map.get(k) {
                None => eprintln!("[{label}] EXTRA in sharded: {}", describe(k)),
                Some(w) if w != v => eprintln!(
                    "[{label}] VALUE differs: {} ({} vs {})",
                    describe(k),
                    hex_lower(&v[..4]),
                    hex_lower(&w[..4])
                ),
                _ => {}
            }
        }
        for k in want.map.keys() {
            if !got.map.contains_key(k) {
                eprintln!("[{label}] MISSING in sharded: {}", describe(k));
            }
        }
        panic!("{label}: store content diverged from serial (diff above)");
    }

    /// Run the same batch through the plain serial walk.
    fn serial_apply(base: MemorySmtStore, batch: &[ShardEntry]) -> MemorySmtStore {
        let mut t = SparseMerkleTree::new(base);
        for (path, id, op) in batch {
            match op {
                Some(v) => t.update_at(path, id, v).unwrap(),
                None => t.delete_at(path, id).unwrap(),
            }
        }
        t.commit().unwrap();
        t.into_store()
    }

    /// R38 gate: the sharded flush must be byte-identical (root AND full
    /// store content) to the serial walk at every shard width, and repeat
    /// runs must be byte-identical (the acceptance's thread-count invariance
    /// is a corollary: shards are data-partitioned, so schedule cannot reach
    /// the result — width and repetition are the levers that could).
    #[test]
    fn sharded_flush_matches_serial_across_widths_and_repeats() {
        fn splitmix(state: &mut u64) -> u64 {
            *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = *state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
        let mut seed = 0x0038_2026_0728u64;
        // Mixed batch over a 300-key base: updates, inserts, deletes.
        let mut batch: Vec<ShardEntry> = Vec::new();
        for i in 0..120u32 {
            let id = acc(&(i * 2).to_be_bytes()); // even ids exist in base(300)
            let path = account_path(&id);
            let op = match splitmix(&mut seed) % 4 {
                0 => None,                                        // delete existing
                _ => Some(sha3_256(&splitmix(&mut seed).to_be_bytes())), // update
            };
            batch.push((path, id, op));
        }
        for i in 0..60u32 {
            let id = acc(&[0xFE, i as u8, (i >> 8) as u8]); // fresh inserts
            batch.push((account_path(&id), id, Some(sha3_256(&[i as u8, 7]))));
        }

        let want = serial_apply(seeded_base(300), &batch);
        for bits in [0u8, 2, 4, 8] {
            let got = sharded_apply(seeded_base(300), &batch, bits);
            assert_store_eq(&got, &want, &format!("sharded flush at {bits} bits"));
        }
        // Repeat-run invariance at the production-shaped width.
        let a = sharded_apply(seeded_base(300), &batch, 4);
        let b = sharded_apply(seeded_base(300), &batch, 4);
        let c = sharded_apply(seeded_base(300), &batch, 4);
        assert_eq!(a.map, b.map);
        assert_eq!(b.map, c.map);
    }

    /// Boundary-crossing shapes must be REFUSED to the serial walk and still
    /// land byte-identical: empty-tree start (everything refuses), a region
    /// emptied by deletes, a delete that re-anchors a lone neighbor into the
    /// crown, and clustered in-shard prefixes that depend on each other's
    /// in-batch structure.
    #[test]
    fn sharded_flush_refusals_cover_boundary_structure() {
        // (a) Empty base: every entry must refuse (shard-root absent) and the
        // result must equal a fresh serial build.
        let inserts: Vec<ShardEntry> = (0..40u32)
            .map(|i| {
                let id = acc(&[0xAA, i as u8]);
                (account_path(&id), id, Some(sha3_256(&[i as u8])))
            })
            .collect();
        let probe = SparseMerkleTree::new(MemorySmtStore::new());
        let d = probe.compute_shard_delta(4, &inserts[..8]).unwrap();
        assert_eq!(d.refused_len(), 8, "empty tree must refuse every entry");
        let got = sharded_apply(MemorySmtStore::new(), &inserts, 4);
        let want = serial_apply(MemorySmtStore::new(), &inserts);
        assert_eq!(got.map, want.map);

        // (b) The exact p:-signal shape: K1/K2 share the shard prefix and
        // diverge at bit 6 (tops at 7, shard-local at 4 bits — the shard-root
        // row EXISTS, so the pre-check passes); K3 diverges at bit 1 (crown
        // branch). Deleting K2 re-anchors lone-neighbor K1's top to depth 2 —
        // INTO the crown — which only the p:-write signal can catch.
        let k1 = raw_path(0x00, 0x01);
        let k2 = diverging_at(&k1, 6);
        let k3 = diverging_at(&k1, 1);
        let (id1, id2, id3) = (acc(b"sig-1"), acc(b"sig-2"), acc(b"sig-3"));
        let mut t = tree();
        t.update_at(&k1, &id1, &sha3_256(b"v1")).unwrap();
        t.update_at(&k2, &id2, &sha3_256(b"v2")).unwrap();
        t.update_at(&k3, &id3, &sha3_256(b"v3")).unwrap();
        t.commit().unwrap();
        let base = t.into_store();

        let probe2 = SparseMerkleTree::new(base.clone());
        let batch: Vec<ShardEntry> = vec![(k2, id2, None)];
        let d2 = probe2.compute_shard_delta(4, &batch).unwrap();
        assert_eq!(
            d2.refused_len(),
            1,
            "crown re-anchor must be refused via the p: signal"
        );
        drop(probe2);
        let got = sharded_apply(base.clone(), &batch, 4);
        let want = serial_apply(base, &batch);
        assert_eq!(got.map, want.map);

        // (c) In-shard clustered dependency: two fresh keys sharing 250 bits
        // inserted in the same shard batch — the second's walk must see the
        // first through the delta layering.
        let seeded = seeded_base(64);
        let anchor = {
            // Use an existing base key's path region: derive a path inside a
            // populated shard by reusing a real path's prefix.
            let id0 = acc(&0u32.to_be_bytes());
            account_path(&id0)
        };
        let deep1 = diverging_at(&anchor, 250);
        let deep2 = diverging_at(&anchor, 253);
        let batch2: Vec<ShardEntry> = vec![
            (deep1, acc(b"deep-1"), Some(sha3_256(b"d1"))),
            (deep2, acc(b"deep-2"), Some(sha3_256(b"d2"))),
        ];
        let got2 = sharded_apply(seeded.clone(), &batch2, 4);
        let want2 = serial_apply(seeded, &batch2);
        assert_eq!(got2.map, want2.map);
    }

    /// A legacy store refuses the whole batch to the serial (full-tail) walk
    /// — the sharded entry point never writes v2 rows into a legacy store.
    #[test]
    fn sharded_flush_on_legacy_store_falls_back_serial() {
        let mut w = SparseMerkleTree::new_legacy_unchecked(MemorySmtStore::new());
        w.update(&acc(b"l1"), &sha3_256(b"x")).unwrap();
        w.commit().unwrap();
        let base = w.into_store();

        let batch: Vec<ShardEntry> = (0..10u32)
            .map(|i| {
                let id = acc(&[0xBB, i as u8]);
                (account_path(&id), id, Some(sha3_256(&[i as u8, 3])))
            })
            .collect();
        let t = SparseMerkleTree::new(base.clone());
        let d = t.compute_shard_delta(4, &batch[..3]).unwrap();
        assert_eq!(d.refused_len(), 3, "legacy store must refuse everything");
        drop(t);
        let got = sharded_apply(base.clone(), &batch, 4);
        let want = serial_apply(base, &batch);
        assert_eq!(got.map, want.map);
        assert!(!got.map.contains_key(FORMAT_KEY));
    }

    /// v2 storage really is compact: a 200-key store must hold rows within
    /// the O(N·log N) crown budget — an order of magnitude under the legacy
    /// O(N·256) shape — while every key still proves.
    #[test]
    fn v2_store_row_count_is_crown_bounded() {
        let mut t = tree();
        for i in 0..200u32 {
            t.update(&acc(&i.to_be_bytes()), &sha3_256(&i.to_be_bytes())).unwrap();
        }
        t.commit().unwrap();
        let root = t.root().unwrap();
        for i in 0..200u32 {
            let p = t.proof(&acc(&i.to_be_bytes())).unwrap().unwrap();
            assert_eq!(p.root, root);
            assert!(verify_proof(&p));
        }
        let rows = t.into_store().map.len();
        // Legacy shape would exceed 200 × ~240 ≈ 48,000 rows; the crown shape
        // is ~(2·branches + tops + p + leaves + values + tag) ≈ 6–8 rows/key.
        assert!(
            rows < 2_500,
            "v2 store must be compact: got {rows} rows for 200 keys"
        );
    }
}
