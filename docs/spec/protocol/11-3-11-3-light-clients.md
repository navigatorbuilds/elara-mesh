### 11.3 Light Clients

**The problem:** A $30 phone cannot store the full DAM. A Mars colony with limited bandwidth cannot download Earth's complete history. How do lightweight nodes verify claims without the full dataset?

**Solution: Merkle Proof Verification**

The DAM maintains a Merkle tree over all validation records. A light client can verify any specific record with:

1. The validation record itself (~4-5 KB)
2. A Merkle proof path (~log2(N) × 32 bytes — for a billion records, this is ~960 bytes)
3. The Merkle root (32 bytes, published by anchor nodes)

Total verification payload for a single record: **under 6 KB**, regardless of how large the DAM grows.

**Trust headers:**

Anchor nodes publish periodic **trust headers** — compact summaries containing:

```
TrustHeader {
    zone:           zone identifier
    timestamp:      vector clock position
    merkle_root:    root hash of all records in this zone
    record_count:   total validation records
    witness_summary: aggregated trust statistics
    anchor_signatures: [signed by multiple anchor nodes]
}
```

A light client that trusts at least one anchor node can verify any claim against the trust header without downloading the full DAM. This is analogous to Simplified Payment Verification (SPV) in proof-of-work systems, extended for the DAM's multi-zone structure.

**Progressive download:**

Light clients can optionally download DAM data incrementally:

- **Level 0:** Trust headers only (~1 KB/day) — sufficient for basic verification
- **Level 1:** Headers + own records + records they've queried (~100 KB–10 MB)
- **Level 2:** Headers + local zone history (~10 MB–1 GB)
- **Level 3:** Full DAM replica (anchor/archive nodes only)

A budget smartphone operates at Level 0 or 1. It validates locally, syncs its own records, and verifies others via Merkle proofs. It never needs the full DAM.

