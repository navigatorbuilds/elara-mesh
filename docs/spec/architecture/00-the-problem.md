## The Problem

The current node treats every node as a full node holding everything in memory.
22K records = ~500MB RAM. At 1M records = 20+ GB. At quintillions = impossible.

The protocol whitepapers describe zones, epoch seals, hardware tiers, Merkle proofs.
The implementation ignored all of it. This document is the bridge from testnet to production.

---

