# elara-dht

A lightweight, dependency-light Kademlia routing table for peer discovery and
content routing — **no key-value storage layer**, just the XOR-metric k-bucket
structure and the lookup primitives built on top of it.

Extracted as a standalone crate from the [Elara Protocol](https://github.com/navigatorbuilds/elara-mesh)
node, where it backs structured gossip at scale. It has no dependency on the
rest of the node (only `serde`, `serde_json`, `hex`, and `sha3`), so it drops
into any Rust peer-to-peer project.

## What it does

- **`NodeId`** — a 256-bit identifier with XOR `distance`, `bucket_index`, and
  `from_record_id` (SHA3-256 of a content key → a point in the node-id space,
  so every node agrees on which peers are responsible for a record).
- **`RoutingTable`** — 256 k-buckets with least-recently-seen eviction:
  - `insert` / `evict_and_insert` / `touch` / `remove`
  - `closest(target, k)` and `closest_to_record(record_id, k)` for content routing
  - `closest_prefer_outbound` to bias toward peers you dialed (eclipse resistance)
  - `rotate_stale_peers`, `provenance_counts`, `bucket_distribution` for health
  - `save` / `load` for on-disk persistence (JSON)
- **`ALPHA`** (lookup parallelism) and **`DISJOINT_PATHS`** (independent lookup
  paths for resilience) as the Kademlia tuning constants.

## What it is not

It does not store or replicate values, open sockets, or speak a wire protocol.
It is the *routing-table half* of a DHT — you bring the transport and decide
what "closest peers to a key" means for your application.

## Example

```rust
use elara_dht::{NodeId, RoutingTable, DhtPeer, PeerProvenance};

let local = NodeId::from_hex(&"ab".repeat(32)).unwrap();
let mut table = RoutingTable::new(local);

// ... insert peers ...

// Who should hold this record?
let replicas = table.closest_to_record("record-id-here", 8);
```

## License

Licensed under either of [MIT](LICENSE-MIT) or
[Apache-2.0](LICENSE-APACHE) at your option. (The Elara node itself is
AGPL-3.0; this extracted library is permissively licensed for reuse.)
