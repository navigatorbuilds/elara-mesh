## Zone Registry

**NOT full registry in every seal.** Epoch seals carry:

```
zone_registry_root: Hash,              // Merkle root of ALL known zones
zone_registry_delta: Vec<ZoneChange>,  // only changes since last seal
```

At 1M zones with ~100 changes per epoch: delta is ~10KB. Merkle root is 32 bytes.
Full registry stored in RocksDB. Any node can request proof of zone existence.

Zone changes include: new zone created, zone split, zone deactivated, anchor rotation.

---

