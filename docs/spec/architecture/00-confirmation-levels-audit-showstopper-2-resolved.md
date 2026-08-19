### Confirmation Levels

The four-level confirmation model, adapted for layered consensus:

| Level | Testnet Equivalent | Production Definition |
|-------|-------------------|----------------------|
| **Pending** | Unconfirmed | Received, Layer 1 validated, not yet in an epoch seal |
| **Sealed** | Attested | Included in anchor's proposed epoch seal |
| **Finalized** | Confirmed | Epoch seal has >67% stake-weighted diverse attestations |
| **Anchored** | Anchored | Finalized + no open challenges after challenge window (e.g., 24h) |

**Diversity scoring per epoch seal:** The diversity function d(n, W) applies to the SET of witnesses who attested to an epoch seal. same_org, same_subnet discounts still apply. same_zone discount does NOT apply (all witnesses are in the same zone by definition — this discount was designed for cross-zone per-record attestation and doesn't apply to zone-scoped epoch consensus). Cross-zone diversity is achieved by the zone registry mechanism and cross-zone Merkle proofs, not by within-zone attestation diversity.

---

