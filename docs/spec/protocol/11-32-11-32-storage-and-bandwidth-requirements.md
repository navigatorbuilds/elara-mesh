### 11.32 Storage and Bandwidth Requirements

**The question:** How much data does the Elara Protocol produce, and what are the storage requirements for different node types?

This section provides concrete estimates based on the cryptographic primitives specified in this paper, enabling infrastructure planning and economic modeling.

**Per-Record Sizes**

| Record Type                               | Approximate Size | Breakdown                                                                                |
|-------------------------------------------|------------------|------------------------------------------------------------------------------------------|
| PUBLIC validation record                  | ~4-5 KB          | Content hash (32 B) + Dilithium3 signature (~3.3 KB) + metadata/causal anchors (~500 B)  |
| PRIVATE validation (Phase 1: SHA3 commitment) | ~4-5 KB      | SHA3-256 commitment proof + PQC signature (~3.3 KB) + commitment (32 B) + metadata (~500 B). The Groth16 zk-SNARK (288 B proof) is the design-stage target (§5.3). |
| PRIVATE validation (Phase 2, hybrid ZKP)  | ~55 KB           | Hybrid lattice+classical proof (~50 KB) + PQC signature (~3.3 KB) + metadata (~500 B)    |
| SOVEREIGN validation (target: zk-STARK)   | ~100-200 KB      | STARK proof (variable, typically 50-200 KB) + PQC signature (~3.3 KB) + metadata. Planned; current runtime ships SHA3-256 commitments (`src/crypto/commitment.rs`) in this slot. |
| Witness attestation                       | ~3.5 KB          | Record reference (32 B) + Dilithium3 signature (~3.3 KB) + timestamp + node identity     |
| Trust header                              | ~15-20 KB        | Epoch reference + multiple anchor node signatures + zone metadata                        |
| Epoch summary                             | ~50-100 KB       | Merkle root + multi-anchor signatures + record count + zone state                        |
| DeviceAuthorization record                | ~5 KB            | Root identity + device key + permissions + PQC signature                                 |
| VersionRecord                             | ~4-5 KB          | Previous version reference + content hash + PQC signature + metadata                     |

Each validation record requires 3-5 witness attestations to reach meaningful trust scores (Section 11.12). The effective network cost of one validation is therefore approximately 4-5x the base record size.

**Daily Data Volume by Network Scale**

| Scale          | Users   | IoT Devices  | Records/Day | Raw Data/Day | With Witnesses | Annual  |
|----------------|---------|--------------|-------------|--------------|----------------|---------|
| Early network  | 10,000  | —            | ~100K       | ~500 MB      | ~2 GB          | ~730 GB |
| Growth phase   | 100,000 | 1M sensors   | ~2M         | ~10 GB       | ~35 GB         | ~12 TB  |
| Mature network | 10M     | 100M sensors | ~200M       | ~1 TB        | ~4 TB          | ~1.4 PB |
| Full vision    | 100M+   | 1B+ sensors  | ~1B+        | ~5 TB        | ~20 TB         | ~7 PB   |

**IoT is the dominant data source.** A single autonomous vehicle fleet (1,000 vehicles at 100 decisions/second) generates ~8.6 billion raw events per day. The protocol's tiered approach addresses this: most IoT validations remain on Layer 1 (local only, never reaching the network), with periodic summaries propagated to Layer 2 via incremental validation (Section 11.7) and batched witness requests.

**Per-Node Storage Requirements**

Not every node stores the full DAM. The zone architecture (Section 7) and node type hierarchy distribute storage across the network:

| Node Type               | Stores                | Typical Storage | Growth Rate        |
|-------------------------|-----------------------|-----------------|--------------------|
| Leaf node (phone, IoT)  | Own records only      | 10 MB – 1 GB    | ~1-10 MB/day       |
| Relay node              | Zone records (recent) | 10 GB – 100 GB  | ~100 MB – 1 GB/day |
| Anchor node             | Full zone history     | 1 TB – 50 TB    | ~1-10 GB/day       |
| Archive node (Tier 3)   | Complete DAM history  | 100 TB+         | ~5-20 GB/day       |
| Off-world node (Tier 4) | Zone-scoped snapshot  | 1 TB – 10 TB    | Sync-dependent     |

**Bandwidth Requirements**

| Node Type   | Upload              | Download            | Notes                         |
|-------------|---------------------|---------------------|-------------------------------|
| Leaf node   | ~10 KB/validation   | ~50 KB/validation   | Mostly witness responses      |
| Relay node  | ~1-10 MB/hour       | ~1-10 MB/hour       | Zone gossip protocol          |
| Anchor node | ~100 MB – 1 GB/hour | ~100 MB – 1 GB/hour | Trust headers + epoch sealing |

**Comparison to existing systems:** At early network scale (~2 GB/day), the Elara Protocol produces data comparable to major proof-of-work networks (~500 MB/day) or proof-of-stake platforms (~2-3 GB/day). At full IoT scale (~20 TB/day aggregate), the protocol approaches the data volume of major cloud platforms — but no single node bears the full load, and the zone architecture ensures geographic locality of most traffic.

**Storage economics:** The beat staking model (Section 9) incentivizes relay and anchor node operators to provide storage capacity. The free tier (Layer 1) produces negligible network storage costs because local-only validations do not propagate. Storage costs scale with network utility, not with network existence.

