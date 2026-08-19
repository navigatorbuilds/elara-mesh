### 11.14 Network Topology and Peer Discovery

**The gap:** The paper describes what happens when nodes communicate but never specifies how nodes find each other. Without a peer discovery mechanism, the network cannot form.

**Solution: Hybrid Discovery with Kademlia DHT**

The Elara Protocol uses a three-layer peer discovery system:

**Layer A: Bootstrap Nodes**

At installation, every Elara client ships with a hardcoded list of bootstrap nodes — geographically distributed servers operated by the foundation and early community members. These serve one purpose: introducing new nodes to the network. They are not privileged in any other way.

```
Bootstrap list (example):
  bootstrap-eu.elara.network:4001
  bootstrap-us.elara.network:4001
  bootstrap-asia.elara.network:4001
  bootstrap-africa.elara.network:4001
```

The bootstrap list is updatable through protocol governance. If all bootstrap nodes go offline simultaneously, nodes that already know peers continue operating — bootstrap is only needed for first contact.

All bootstrap traffic uses the ElaraPQ transport defined in §4.7 — including the very first packet from a freshly-installed client. The hybrid Curve25519 + ML-KEM-768 handshake is the *only* node-to-node wire protocol on mainnet; bootstrap is not a special case. The bootstrap list itself is signed by the foundation reserve multisig and embedded in the binary tarball, so a client can verify peer authenticity before sending its first frame.

**Layer B: Kademlia DHT (Distributed Hash Table)**

Once connected to at least one peer, nodes join a Kademlia-based DHT (a widely deployed algorithm in peer-to-peer networks). Kademlia provides:

- O(log n) lookup for any node in the network
- Self-healing: the routing table automatically repairs when nodes leave
- Resistance to targeted attacks: no single node is critical for routing
- NAT traversal via hole-punching, where every UDP datagram carries an ElaraPQ-encrypted payload (§4.7); plain unencrypted UDP is forbidden on mainnet

Each node maintains a routing table of ~20 × log2(N) entries. For a million-node network, this is ~400 entries — negligible memory.

**Layer C: Local Discovery**

For devices on the same local network (IoT deployments, mesh networks), the protocol uses mDNS/DNS-SD (multicast DNS / Service Discovery) for zero-configuration local peer discovery. A sensor and its gateway find each other without any internet connectivity.

For Bluetooth-capable devices, BLE advertisements enable peer discovery within ~100 meters. This enables the mesh-networking scenarios described in the Emergency Protocols (Section 12.3).

**Gossip Protocol for Record Propagation:**

Once peers are discovered, validation records propagate via an epidemic gossip protocol:

1. Node creates or receives a new record
2. Node selects √n random peers from its routing table (where n = number of known peers)
3. Node forwards the record to selected peers
4. Recipients repeat the process for records they haven't seen

With √n fan-out, theoretical propagation completes in ~2-3 rounds. In practice, duplicate messages, network latency, and partial peer overlap increase this to ~6-10 gossip rounds for 1 million nodes — projected under 15 seconds on Earth-zone networks (modelled from epidemic-gossip theory; untested at this scale).

