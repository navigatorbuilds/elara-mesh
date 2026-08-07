#### 5.3.5 Gossip Verification

ZK proof verification dispatches on the first byte of `zk_proof`. In the Phase-1 runtime: SHA3-256 commitment proofs (version `0x03`, and legacy `0x01`) are verified by hash recomputation (`src/crypto/commitment.rs`, `src/crypto/zk.rs`); Groth16-format bytes (version `0x02`) are **rejected fail-closed** at ingest, since no Groth16 verifier exists. (In the design-stage Groth16 construction, `0x02` proofs would be verified against the CRS loaded at node startup.) WASM browser nodes relay proofs without verifying — native witness nodes verify before consensus acceptance.

(Note: the BN254 curve in the design-stage construction provides ~100-bit security against classical attacks and is NOT post-quantum. See Section 14.3 for the migration timeline to post-quantum ZKP constructions.)

For SOVEREIGN classification, the protocol specifies zk-STARKs (Scalable Transparent Arguments of Knowledge) as a future extension — larger proofs (~100 KB) but no trusted setup required.

