## Attack Vectors & Defenses

| Attack | Demonstrated | Defense |
|--------|-------------|---------|
| Eclipse (fill routing table) | Bitcoin 2015, Ethereum 2018 (2 IPs!) | IP diversity limits, test-before-evict, outbound preference |
| DNS poisoning | Theoretical for Bitcoin | EIP-1459 hash-authenticated Merkle trees |
| BGP hijacking | Bitcoin (ETH Zurich), KlaySwap 2022 ($2.2B KRW) | SABRE relay, RPKI, multi-source bootstrap |
| Sybil DHT flooding | IPFS 2024 (1 desktop, 1.5h) | S/Kademlia PoW puzzles, disjoint paths |
| MITM bootstrap | All networks at first contact | Signed peer lists, genesis hash verification |
| Post-Merge eclipse | Ethereum Jan 2026 (multi-stage) | DHT rate limits, DNS crawler hardening |

---

