## Cross-Zone Discovery

**The Problem:** How does a node in Zone A discover Zone B exists? How does an outsider
verify it's the REAL network?

**Existing approaches:**
- Ethereum: attestation subnet bitfields in ENR records, discv5 topic advertisement
- Polkadot: relay chain assigns validators to parachains, authority discovery via DHT
- Cosmos: manually configured relayers + centralized chain-registry (NOT decentralized)
- Harmony: Kademlia-routed cross-shard, shard IDs in Kademlia address space

**Proposed for Elara:**
- Zone IDs map to Kademlia address space regions
- Nodes advertise zone membership alongside identity
- Cross-zone lookup = standard Kademlia lookup for target zone ID
- Epoch seals carry zone registry (active zones + anchor nodes)
- New node verification: genesis_authority hash + minimum expected DAG size

**Trust model for outsiders:**
- Must know genesis_authority hash (pre-shared, in the binary)
- Syncs DAG, verifies genesis authority signed initial records
- Enhancement: include genesis block hash + minimum DAG size in config to detect fake genesis

---

