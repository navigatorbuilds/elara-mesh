### Normal operation — the trust chain

A phone from Montenegro (zone medical/eu/south/montenegro) enters a hospital
in Brazil (zone medical/sa/brazil). Zones have never communicated directly.

The phone carries:
- Its identity (Dilithium3 signed + PoW proof)
- Its records
- Merkle proof for each record (from home zone's epoch seal)
- The epoch seal itself (signed by home zone witnesses)

The hospital verifies:
1. Epoch seal signature → valid Dilithium3 signature
2. Merkle proof → record is under that seal's Merkle root (math, no network)
3. Witness legitimacy → witnesses have staked beats (verifiable via global ledger or cross-zone proof)
4. Genesis chain → epoch seal `previous_seal_hash` chain traces back to genesis_authority

