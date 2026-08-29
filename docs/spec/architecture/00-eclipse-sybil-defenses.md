### Eclipse/Sybil defenses
- IP diversity limits in k-buckets (max 2 per /24 per bucket)
- Test-before-evict (ping before replacing)
- S/Kademlia disjoint parallel lookups (d=4 → 99% success with 20% adversaries)
- Outbound peer preference
- PoW on identity (existing)
- ML-DSA-65 (FIPS 204, "Dilithium3") signed peer records (post-quantum — unique to Elara)

