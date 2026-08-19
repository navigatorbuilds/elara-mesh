## What Elara Already Has

- Kademlia DHT (256 k-buckets, K=8, alpha=3) — `network/dht.rs`
- PoW on identity (min_pow_difficulty=16) — equivalent to S/Kademlia static puzzle
- PeerTable with ban/backoff, PoW verification, reputation — `network/peer.rs`
- Seed peer bootstrap + DHT lookup + PEX + seed reconnect — `network/discovery.rs`
- DHT persistence (JSON snapshots across restarts)
- Dilithium3 signed identities (post-quantum)
- Genesis authority hash as trust anchor
- 6 node types (Leaf/Relay/Witness/Archive/Anchor/Gateway)

---

