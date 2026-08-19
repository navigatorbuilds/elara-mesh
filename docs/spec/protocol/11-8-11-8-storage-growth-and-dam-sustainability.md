### 11.8 Storage Growth and DAM Sustainability

**The problem:** "Nothing is ever deleted" combined with IoT-scale validation creates unbounded storage growth. A single factory with 10,000 sensors producing readings every second generates ~864 million records per day. At ~4.5 KB per validation record (dominated by the PQC signature), that is **~3.9 TB per day from one deployment.** At planetary scale, the DAM would grow by petabytes daily.

No single node can store this. The protocol must handle it.

**Solution: Hierarchical Storage with Validation Summarization**

**Tier 1: Leaf and relay nodes — store only what they need**

Leaf nodes (sensors, phones) maintain a circular buffer of their own records. Once synced to the network, old records can be evicted from local storage. The node retains its keypair and a pointer to its last synced position — not the full history.

**Tier 2: Zone-level summarization**

The protocol introduces **epoch summaries** — periodic Merkle tree snapshots that compress historical records into compact proofs:

```
EpochSummary {
    zone:           zone identifier
    epoch:          sequential epoch number
    time_range:     [start_vector_clock, end_vector_clock]
    record_count:   number of records in this epoch
    merkle_root:    root hash of all records in epoch
    creator_roots:  per-creator Merkle subtrees
    summary_hash:   hash of this summary (self-referential)
    signatures:     [anchor node signatures]
}
```

After an epoch is summarized and signed by multiple anchor nodes, individual validation records within that epoch can be pruned from standard nodes. The Merkle root preserves the ability to verify any individual record if the full record is retrieved from an archive node.

**Tier 3: Archive nodes — store everything**

Archive nodes (Seed Vault Tiers 2-4) maintain the full, uncompressed DAM. These are purpose-built for storage — high-capacity, redundant, geographically distributed. They serve the same role as the Internet Archive: not every node needs the full history, but the full history must exist somewhere.

**Tier 4: IoT-specific compression**

For high-frequency sensor data, the protocol supports **batch validation** — aggregating multiple readings into a single validation record:

```
BatchValidation {
    device:         device public key
    readings:       [reading_1, reading_2, ..., reading_n]
    batch_hash:     Merkle root of all readings
    individual_hashes: [hash_1, hash_2, ..., hash_n]  // required for individual verifiability
    time_range:     [first_reading_time, last_reading_time]
    signature:      device signature over batch_hash
}
```

A sensor producing 1 reading/second can batch 3,600 readings into one hourly validation record. Storage reduction: **3,600x** with no loss of verifiability (individual readings can still be proved via the batch Merkle tree).

**Storage projections with batching:**

| Scale                   | Raw (unbatched) | With hourly batching      | With epoch summarization  |
|-------------------------|-----------------|---------------------------|---------------------------|
| 1 factory (10K sensors) | ~3.9 TB/day     | ~1.1 GB/day               | ~100 MB/day (after epoch) |
| 1M personal devices     | ~450 GB/day     | ~450 GB/day (no batching) | ~45 GB/day                |
| Global IoT (1B devices) | ~390 PB/day     | ~108 TB/day               | ~11 TB/day                |

At ~11 TB/day after optimization, the full global DAM grows at ~4 PB/year — large but within the capacity of distributed archive infrastructure. For comparison, YouTube ingests ~720,000 hours of video daily (~1.5 PB). The DAM's storage challenge is significant but solvable with existing technology, and no single node bears the full load.

