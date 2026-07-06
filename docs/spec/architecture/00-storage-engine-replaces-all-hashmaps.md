## Storage Engine (replaces ALL HashMaps)

```
StorageEngine
├── RocksDB (disk, unbounded)
│   ├── records          CF → record_id : ValidationRecord
│   ├── dag              CF → record_id : parents + children
│   ├── ledger           CF → identity  : AccountState (available, staked, vested, delegated, last_active, peak_balance_30d)
│   ├── trust            CF → identity  : TrustScore + entropy signals
│   ├── attestations     CF → epoch:zone : Vec<WitnessAttestation>  (pruned after finalization)
│   ├── reputation       CF → witness   : reputation scores
│   ├── merkle           CF → zone:level:index : hash
│   ├── epochs           CF → zone:epoch_num : EpochSeal
│   ├── peers            CF → peer_id   : PeerInfo + zones
│   ├── disputes         CF → dispute_id : DisputeState (only open disputes in LRU)
│   ├── pending_xzone    CF → transfer_lock_id : PendingCrossZoneTransfer (pruned on claim/timeout)
│   ├── identities       CF → identity_hash : IdentityRecord (creation, rotations, delegations, succession)
│   ├── governance       CF → proposal_id : GovernanceProposal + votes
│   ├── velocity         CF → identity : VelocityState (peak_balance_30d, daily_volume)
│   └── vrf_keys         CF → node_id : VRFKeyPair
│
└── LRU Caches (RAM, bounded by ram_budget)
    ├── hot_records         → current epoch records only
    ├── hot_accounts        → recently active accounts
    ├── hot_trust           → recently queried identities
    ├── hot_reputation      → recently queried witnesses
    └── pending_epoch_seals → ONLY unsettled seals (pruned every epoch)
```

**Why RocksDB over SQLite:** SQLite is single-file, can't handle petabytes, has write
contention with concurrent access. RocksDB is an LSM tree — what Ethereum and Cosmos use.
Column families give logical separation without separate databases. Rust crate: `rust-rocksdb`.

**Additional CFs (ledger operations):** ledger CF now includes staking/velocity/dormancy data. New CFs: disputes, pending_xzone (cross-zone transfers), identities, governance, velocity, vrf_keys.

**Anti-spam data location:** Entropy scores and trust tiers are in the trust CF. Rate limit counters are in-memory (current epoch only, bounded). Behavioral entropy signals stored per-identity in trust CF.

The 7 previously-unbounded in-memory HashMaps ALL disappear into RocksDB:
1. AWCConsensus.attestations → attestations CF (epoch-scoped, pruned after finalization)
2. AWCConsensus.confirmation_levels → replaced by layered consensus (see below)
3. NodeState.finalized → `is_finalized` flag in records CF
4. TrustEngine → trust CF + LRU cache
5. EntityClusterer.signals → trust CF (merged with trust data)
6. ReputationEngine.entries → reputation CF + LRU cache
7. DisputeState → disputes CF (only open disputes in LRU)

---

