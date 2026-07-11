### Layer 2: Epoch Finalization (per-batch, anchor-proposed)

**Epoch boundary rule:** The anchor node proposes epoch contents. Not timestamp-based — proposal-based. The anchor collects pending records for the epoch duration, then proposes:

```
EpochSeal {
    epoch_number,           // per-zone counter (no cross-zone conflicts)
    zone_path,              // which zone
    merkle_root,            // SHA3-256 Merkle root over all records in this epoch
    record_count,           // how many records
    record_hashes,          // list of record hashes (for witness verification)
    zone_balance_total,     // sum of all account balances in this zone (for conservation)
    previous_seal_hash,     // chain of seals (for genesis verification)
    zone_registry_root,     // Merkle root of known zones (NOT full list)
    zone_registry_delta,    // only zone changes since last seal
    vrf_output + proof,     // unpredictable seal (existing VRF)
    anchor_dilithium3_sig   // post-quantum signed by proposing anchor
}
```

Witnesses verify:
1. "Do I have all these records?" (request missing ones if needed)
2. "Do they all pass Layer 1 validation?"
3. "Does my Merkle root match?"
4. "Does the zone_balance_total match my computation?"

If yes → witness signs attestation to the seal. If no → abstain or reject.

**VRF selects which anchor proposes each epoch** (existing behavior, per-zone). Multiple anchors per zone prevent single-point-of-failure.

