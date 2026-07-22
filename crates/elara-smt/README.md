# elara-smt

A **key-addressed sparse Merkle tree** in safe Rust — compact state proofs over a
256-bit key space, generic over the backing store.

A leaf's position is `SHA3-256(key)`, *not* its value, so a given key always
occupies the same **256-bit path** and its leaf hash changes as the value changes.
The tree is 256 levels deep; empty subtrees collapse to one sentinel
(`SHA3-256("")`) at every level, so a tree over billions of sparsely-populated keys
materializes only the interior nodes on populated paths.

Proofs are **empty-subtree-compressed**: instead of a fixed 256 siblings, a proof
carries a 256-bit *presence bitmap* plus only the **non-empty** siblings —
`≈ log₂(N)` hashes, independent of the 256-level depth. At 1 billion keys a proof
is ~30 siblings (~1 KB). The same compression powers sound **non-membership**
proofs ("this key is absent"): because the path is the full 256-bit hash, an absent
key's slot is genuinely empty (no collision can occupy it), so exclusion is a
cryptographic proof, not a trust-the-server assertion.

Extracted from the [Elara Protocol](https://github.com/navigatorbuilds/elara-mesh)
node, where it authenticates global account state so a light client can verify a
balance against a root signed into a checkpoint. The tree algebra here carries no
protocol dependencies — only `sha3` and `serde`.

## What you get

| Item | Purpose |
|------|---------|
| `SparseMerkleTree<S>` | the tree, generic over an `SmtStore` |
| `SmtStore` | trait: `get(key)` + atomic `write_batch(puts, deletes)` |
| `MemorySmtStore` | a `HashMap`-backed store for tests / embedding |
| `SmtProof` | a compressed **inclusion** proof: `account_id` + `state_hash` + `root` + `present` bitmap + non-empty `siblings` (derives `serde`) |
| `SmtExclusionProof` | a compressed **non-membership** proof (same shape, empty leaf) |
| `verify_proof` / `verify_exclusion_proof` | stateless, storage-free proof checks |
| `account_path`, `leaf_hash`, `interior_hash`, `empty_hash`, `MAX_DEPTH` (256), `EMPTY_HASH` | path + hashing helpers |

## Usage

```rust
use elara_smt::{SparseMerkleTree, MemorySmtStore, verify_proof};

let mut tree = SparseMerkleTree::new(MemorySmtStore::new());

let key = [7u8; 32];
let value = [9u8; 32];          // e.g. SHA3-256 of some serialized state
tree.update(&key, &value).unwrap();
tree.commit().unwrap();         // flush buffered writes atomically

// Prove "key → value" and verify it without touching storage.
let proof = tree.proof(&key).unwrap().expect("key present");
assert_eq!(proof.root, tree.root().unwrap());
assert!(verify_proof(&proof));  // folds the compressed siblings back to the root
```

A light client only needs `verify_proof` / `verify_exclusion_proof` plus the proof
types above and a root it already trusts — no store, no tree.

### Proving a key is *absent*

`exclusion_proof` returns `None` for a key that *is* present (an inclusion proof is
the right artifact then) and `Some(proof)` for a genuinely absent one:

```rust
use elara_smt::{SparseMerkleTree, MemorySmtStore, verify_exclusion_proof};

let mut tree = SparseMerkleTree::new(MemorySmtStore::new());
tree.update(&[1u8; 32], &[2u8; 32]).unwrap();
tree.commit().unwrap();

let missing = [42u8; 32];
let proof = tree.exclusion_proof(&missing).unwrap().expect("key is absent");
assert_eq!(proof.root, tree.root().unwrap());
assert!(verify_exclusion_proof(&proof));   // the slot at SHA3-256(key) is empty
```

## Bring your own store

Implement `SmtStore` for any database. Reads happen during
`root`/`get`/`proof`/`update`; writes are buffered in the tree and applied in one
atomic batch on `commit`. Keys are opaque byte strings the tree derives; values
are always 32-byte hashes.

```rust,ignore
use elara_smt::{SmtStore, SmtError};

struct MyStore { /* db handle */ }

impl SmtStore for MyStore {
    type Error = SmtError;

    fn get(&self, key: &[u8]) -> Result<Option<[u8; 32]>, Self::Error> {
        // return the 32-byte value at `key`, or None (also None on wrong length)
    }

    fn write_batch(
        &mut self,
        puts: &[(Vec<u8>, [u8; 32])],
        deletes: &[Vec<u8>],
    ) -> Result<(), Self::Error> {
        // apply all puts, then all deletes, atomically
    }
}
```

The atomicity of `write_batch` is the one correctness requirement: a partially
applied batch can corrupt the tree.

## Hashing & proof layout

- Nodes and leaves hash with **SHA3-256**: a leaf is `leaf_hash(key, value)`, an
  interior node is `SHA3-256(left ‖ right)`, and an empty subtree is
  `EMPTY_HASH = SHA3-256("")` at every level.
- A proof's `present` is a 256-bit bitmap (MSB-first by parent depth): bit `d` set
  means the sibling at parent-depth `d` is non-empty and is listed in `siblings`;
  a clear bit means that sibling is `EMPTY_HASH` and is omitted. `siblings` carries
  only the non-empty ones, ordered from the leaf's parent (depth 255) up to the
  root (depth 0). `verify_proof` rebuilds the leaf as `leaf_hash(account_id,
  state_hash)`, folds the siblings back per the bitmap, and compares to `proof.root`.
- Deserialization is bounded to `MAX_DEPTH` (256) siblings, so a hostile proof
  cannot force an unbounded allocation before verification.

These are fixed wire/consensus details in the upstream node, so the crate pins them
with exact-hex root vectors in its test suite.

## License

MIT OR Apache-2.0.
