## Merkle Forest (one tree per zone)

Each zone maintains its own Merkle tree, updated incrementally:

```
Hash function: SHA3-256 (consistent with all protocol hashing)
Tree type: sparse binary Merkle tree
Leaf ordering: content-hash sorted (deterministic across all nodes)
Persistence: RocksDB merkle CF (zone:level:index → hash)
Max depth: 64 levels (supports 2^64 records per zone)
```

```
Insert record → O(log n) path update from leaf to root
Generate proof → O(log n) sibling hashes
Verify proof  → O(log n) hash computations, NO STATE NEEDED
```

Light clients (phones, browsers) need ONLY:
- Their own records (local storage)
- The zone's Merkle root (from latest epoch seal)
- A proof for any record they want to verify (requested from any full node)

Phone asks full node: "prove record X exists in zone Y."
Full node returns ~30 hashes for a billion-record zone (~960 bytes).
Phone verifies locally. Zero trust needed.

**ZK proof interaction:** ZK proofs are stored alongside their records in the records CF. The Merkle tree covers the full record including its ZK proof. A Merkle proof thus proves both the record's existence AND that it had a valid ZK proof at seal time. Verification of the ZK proof itself is separate from Merkle verification.

---

