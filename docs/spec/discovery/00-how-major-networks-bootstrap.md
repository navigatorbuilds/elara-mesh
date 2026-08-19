## How Major Networks Bootstrap

| Network | Primary | Fallback | Attack History |
|---------|---------|----------|----------------|
| Bitcoin | 9 DNS seeds (different operators) | Hardcoded IPs, peers.dat, addr gossip | Eclipse via table filling (2015), BGP partition (ETH Zurich) |
| Ethereum | EIP-1459 signed DNS Merkle trees | discv5 Kademlia DHT, hardcoded bootnodes | Eclipse with 2 IPs (2018, fixed), post-Merge eclipse (2026) |
| Polkadot | Hardcoded bootstrap + mDNS | Kademlia random walks | — |
| Cosmos | Seed nodes + persistent peers | PEX reactor (vetted/unvetted buckets) | Manual cross-chain (not decentralized) |
| Solana | Entrypoints + IP echo | Gossip push/pull (stake-weighted) | — |
| IPFS | Amino DHT bootstrappers | Kademlia DHT + mDNS | Sybil with 1 desktop in 1.5h (2024) |
| Tor | 9 directory authorities (hardcoded keys) | — | Centralized by design |

**Key insight:** Every network requires at least ONE piece of pre-shared knowledge
(genesis hash, authority key, CID). Without it, you cannot distinguish the real network
from an attacker's simulation.

---

