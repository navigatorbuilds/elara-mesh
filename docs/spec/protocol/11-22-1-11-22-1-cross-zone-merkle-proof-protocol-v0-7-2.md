#### 11.22.1 Cross-Zone Merkle Proof Protocol (v0.7.2)

**The problem:** With zone-scoped storage, a node in Zone A does not hold Zone B's records. How does it verify a record from Zone B without trusting Zone B's nodes?

**Solution: Self-Verifiable Records with Merkle Proofs**

A record is self-verifiable when it carries:
1. The record itself (signed with Dilithium3/SPHINCS+)
2. A Merkle proof: the sibling hashes from the record's leaf to the zone's Merkle root
3. The epoch seal containing the Merkle root (signed by the zone's anchor, attested by witnesses)
4. The epoch seal chain: `previous_seal_hash` links back to genesis

**Verification without holding any Zone B data:**

```
1. Verify record signature (Dilithium3) → authentic
2. Compute Merkle path from record hash using proof hashes → get root
3. Compare computed root with epoch seal's merkle_root → matches
4. Verify epoch seal's anchor signature (Dilithium3) → authentic
5. Verify epoch seal attestations → ≥⌈2N/3⌉ committee witnesses signed (mandatory finality quorum, see below)
6. Verify witness identities → staked, PoW, age requirements met
7. Verify epoch seal chain → previous_seal_hash chain to genesis_authority
```

Steps 1-3 are pure math (no network). Steps 4-7 require the epoch seal and witness identity data, which can be cached or requested via DHT.

**Step 5 finality requirement (mandatory):** the cross-zone proof must carry a `SealFinalityWitness` bundle — distinct Dilithium3 signatures from at least ⌈2N/3⌉ members of the source zone's committee at `seal_epoch`, each over the canonical `(zone_path ‖ seal_epoch ‖ merkle_root ‖ committee_hash)` bytes, plus a Merkle inclusion proof against the pinned `committee_hash`. Inclusion in a tentative (sub-quorum) seal is **not** sufficient — orphaned tentative seals violate the cross-zone conservation invariant. The verifier rejects with `committee_size must be > 0 to enforce quorum` when no committee is supplied, preventing legacy inclusion-only proofs from advancing.

**Cross-zone proof request protocol:**

```
1. Node A wants to verify record R from Zone B
2. DHT lookup: sha256("elara-zone:" || zone_B_path) → find Zone B peers
3. Request from Zone B peer: GET /zone/B/proof/{record_hash}
4. Response: { record, merkle_proof, epoch_seal, witness_attestations }
5. Node A verifies everything locally (steps 1-7 above)
6. Cache the epoch seal for future Zone B verifications
```

**Proof size:** For a zone with N records, Merkle proof is log2(N) × 32 bytes. For 1 billion records: 30 × 32 = 960 bytes. Negligible bandwidth.

**Cross-zone transfers use this mechanism.** A transfer-lock record in Zone A is presented to Zone B with its Merkle proof and the source-zone finality-witness bundle (≥⌈2N/3⌉ committee signatures over the source seal). Zone B verifies without contacting Zone A. The finality bundle is what makes the conservation invariant survive an orphaned source seal.

