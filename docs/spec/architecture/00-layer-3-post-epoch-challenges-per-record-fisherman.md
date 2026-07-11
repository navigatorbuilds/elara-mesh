### Layer 3: Post-Epoch Challenges (per-record, fisherman)

**Fisherman under batch consensus:**

Fisherman can challenge INDIVIDUAL records within a sealed epoch:

```
Challenge {
    epoch_number,
    zone_path,
    challenged_record_hash,
    evidence,              // "invalid signature" | "double spend" | "format violation"
    merkle_proof,          // proves the record is in the challenged epoch
    challenger_identity,
    challenger_dilithium3_sig
}
```

**Differentiated penalties:**
- **Anchor node (epoch proposer):** FULL slash. They built the Merkle tree including the bad record. Primary responsibility.
- **Attesting witnesses:** REDUCED slash (10-20% of normal). They attested to the batch. Incentivized to spot-check but not required to verify every record at extreme throughput.
- **Non-attesting witnesses:** No penalty. Choosing not to attest is safe.

**Nash equilibrium:** Anchors carefully validate (full slash risk). Witnesses spot-check (reduced slash + reputation damage). Fishermen monitor for bad records (challenger reward). Three layers of defense.

