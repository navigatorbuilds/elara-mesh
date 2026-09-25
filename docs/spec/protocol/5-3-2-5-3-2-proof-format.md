#### 5.3.2 Proof Format

> **Implementation status — DESIGN-STAGE.** The Phase-1 runtime emits
> **SHA3-256 commitment proofs** (`src/crypto/commitment.rs`); the Groth16
> format below is reserved (version byte `0x02`) but is neither produced nor
> verified.

**Phase-1 (IMPLEMENTED):** SHA3-256 commitment proofs. The wire format carries a
version/type discriminator, the 32-byte commitment, the public inputs, and the
commitment proof data; `src/crypto/commitment.rs` is the byte-level source of
truth (version byte `0x03`). The proof data is the commitment's opening (the
committed value and its blinding factor), so these proofs reveal what they
commit to. Groth16-format bytes (version `0x02`) are **rejected
fail-closed** at ingest, since no Groth16 verifier exists.

**Specified Groth16 format (DESIGN-STAGE, not implemented):** 2 G1 points + 1 G2
point = 128 bytes compressed on BN254 (256 uncompressed), verifiable in a few milliseconds on commodity hardware
once a prover lands. Version byte `0x02` is reserved for this future format.

