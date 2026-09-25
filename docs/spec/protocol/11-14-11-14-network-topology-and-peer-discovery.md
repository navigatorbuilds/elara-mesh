### 11.14 Network Topology and Peer Discovery

**The gap:** The paper describes what happens when nodes communicate but never specifies how nodes find each other. Without a peer discovery mechanism, the network cannot form.

**Solution: Hybrid Discovery with Kademlia DHT**

The Elara Protocol uses a three-layer peer discovery system:

**Layer A: Bootstrap Nodes**

Every Elara client ships with a configurable bootstrap-node list — the seed peers a new node dials to be introduced to the network. In the current public release this list is **empty by default** (`TESTNET_SEED_PEERS = []`): there are no foundation-run public endpoints, and operators set their own seeds (`seed_peers` / `ELARA_SEEDS`; see `docs/JOIN-DEVNET.md`). Seed nodes serve one purpose — introducing new nodes — and are not privileged in any other way.

```
Bootstrap list (example):
  seed-1.example.org:9473
  seed-2.example.org:9473
  seed-3.example.org:9473
```

Operators change the bootstrap list in their node configuration; it is not a governance parameter. If all bootstrap nodes go offline simultaneously, nodes that already know peers continue operating — bootstrap is only needed for first contact.

**Layer B: Kademlia DHT (Distributed Hash Table)**

Once connected to at least one peer, nodes join a Kademlia-based DHT (a widely deployed algorithm in peer-to-peer networks). Kademlia provides:

- O(log n) lookup for any node in the network
- Self-healing: the routing table automatically repairs when nodes leave
- Resistance to targeted attacks: no single node is critical for routing
- NAT handling: at startup a node with no configured advertise address uses STUN to learn its NAT type and external address and asks the router for a UPnP port mapping. It advertises an address only when that address is publicly reachable (a public IP, a UPnP mapping to a public IP, or a full-cone NAT); otherwise it takes part by dialing out and pulls twice as often. Hole-punching and relay fallback are planned, not implemented.

Each node keeps at most 8 peers per k-bucket, about 8 × log2(N) entries in practice. For a million-node network this is about 160 entries, and the table is capped at 2,048 — negligible memory.

**Layer C: Local Discovery**

For devices on the same local network (IoT deployments, mesh networks), the protocol uses mDNS/DNS-SD (multicast DNS / Service Discovery) for zero-configuration local peer discovery. A sensor and its gateway find each other without any internet connectivity.

For Bluetooth-capable devices, BLE advertisements would enable peer discovery within ~100 meters, for the mesh-networking scenarios described in the Emergency Protocols (Section 12.3). BLE discovery is planned and not implemented; mDNS discovery is implemented and on by default.

**Gossip Protocol for Record Propagation:**

Once peers are discovered, validation records propagate via an epidemic gossip protocol:

1. Node creates or receives a new record
2. Node selects peers: every eligible peer when there are fewer than 10, otherwise √n of them chosen pseudo-randomly per record (n = eligible peers); at 100 or more eligible peers, the k peers closest to the record ID instead (content routing, below)
3. Node pushes the full record to the selected peers
4. Separately, after each pull a node announces its own recent records to that peer in compact form (record ID, content hash, creator hash, classification, zone, timestamp, size; a few hundred bytes each), and the peer requests only the records it lacks (pull-on-demand)

With √n fan-out, theoretical propagation completes in ~2-3 rounds. Duplicate messages, network latency and partial peer overlap are expected to raise this to ~6-10 gossip rounds for 1 million nodes — projected under 15 seconds on Earth-zone networks (an estimate; untested at this scale).

**Zone-Scoped Gossip Filtering (v0.7.3):**

Records are only relayed to peers subscribed to the record's zone. This prevents bandwidth waste — a node subscribed to `medical/eu/west` does not receive or relay `iot/manufacturing/automotive` records. Three kinds of record bypass zone filtering: epoch seals, beat (ledger) operations and governance operations are relayed globally, as they affect cross-zone state (zone registry, supply conservation, network parameters). Nodes with empty zone subscriptions accept all records (backward compatibility with pre-zone nodes).

**Content-Routed DHT above 100 peers (v0.7.7):**

Flood-gossip with `√n` fan-out works well for small networks but becomes wasteful above 100 peers: every record reaches every subscribed node regardless of whether that node stores or serves it. At 10K+ nodes per zone, the protocol uses a **content-routed overlay** layered on the same Kademlia DHT that handles peer discovery.

Each record is routed to a deterministic responsibility set by XOR distance in the DHT keyspace, keyed on SHA3-256 of its `record_id` (usually a UUIDv7 chosen by the creator):

```
responsible_nodes(record_id) = k-closest Kademlia peers to SHA3-256(record_id)
                               where k = content_routing_k (default 5)
```

A record is gossiped once to its `k` responsible nodes instead of flood-forwarded. If fewer than 3 of the closest peers are eligible, the node falls back to √n flood. Retrieval by a Kademlia lookup against `record_id` is planned and not implemented; nodes currently obtain records they lack through pull sync with their peers. Responsibility rotates naturally as peers join and leave — Kademlia's self-healing property applies unchanged.

**Fallback rule.** Below 100 peers in a zone, flood-gossip remains active (the overhead of content routing exceeds its savings at small scale). At 100+ peers, the overlay activates automatically. The threshold is not a governance parameter — it is a per-node heuristic so partitioned or bootstrapping nodes gracefully degrade.

**Safety.** Content routing changes only the propagation topology, not the consensus model. Epoch seal attestation, slot mutex (§11.12 v0.7.6), and cross-zone proofs (§11.22.1) all operate identically. A record that arrives via content-routed DHT is indistinguishable from one that arrived via flood-gossip — ingest validation is invariant.

**Testnet status:** Content-routed placement above 100 peers is implemented in the Elara Runtime (public `v0.2.0` release; content-routing threshold default 100 in `config.rs`). The testnet runs under the threshold, so flood-gossip is the active path; overlay testing is pending testnet expansion.

**Peer Liveness Probes (v0.7.3):**

Nodes periodically probe peers via `POST /probe` — a three-in-one protocol that combines liveness checking, record exchange, and trust scoring in a single round-trip. The probe interval scales with network size:

```
interval = 300s × √(peers / 5), clamped to [60s, 3600s]
```

At 5 peers: 300s. At 20 peers: 600s. At 500 peers: ~3000s. This keeps the network alive with zero user traffic while avoiding probe storms in large peer sets. A failed probe carries no penalty. Separately, a peer whose connections fail three times in a row is marked stale and backed off exponentially, which drops it from gossip fan-out once a node knows 10 or more peers.

