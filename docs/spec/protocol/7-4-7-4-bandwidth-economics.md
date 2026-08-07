### 7.4 Bandwidth Economics

Interplanetary communication is expensive. The Deep Space Network allocates bandwidth in kilobits per second. The Elara Protocol optimizes for minimal bandwidth:

**Merkle roots** — a single 32-byte hash summarizes millions of validation records. Zones exchange Merkle roots to detect divergence, then synchronize only the differences.

**Delta sync** — only new records since last synchronization are transmitted. A zone with 1 million records that has added 100 since last sync transmits only 100 records plus the updated Merkle root.

**Priority sync** — records are prioritized for transmission based on:
- Classification level (SOVEREIGN records sync first)
- Witness count (more-attested records are higher priority)
- Age (recent records are more likely to be queried)
- Creator priority (configurable per zone)

**Bloom filters** — probabilistic data structures (~10 bytes per element) that answer "does this record exist in your zone?" with a small false-positive rate. Bloom filter exchange enables efficient detection of missing records before full synchronization begins.

**Compression** — validation records use a compact binary encoding (not JSON or XML) with protocol-buffer-style varint encoding. A typical PUBLIC validation record is approximately 4–5 KB, dominated by the Dilithium3 signature (~3.3 KB).

