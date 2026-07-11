### 5.3 ZKP Construction

> **Implementation status — DESIGN-STAGE (not in the Phase-1 runtime).**
> The Phase-1 runtime implements **SHA3-256 commitment proofs**
> (`src/crypto/commitment.rs`, whose own doc-comment notes they are "not
> zero-knowledge, not post-quantum in the ZK sense"): the three proof types
> below are implemented as hash commitments, **not** as zk-SNARK circuits. The
> Groth16-on-BN254 construction this section specifies is the **migration
> target** — there is no Groth16 prover, verifier, trusted setup, or Cargo
> feature in the tree. See whitepaper §14.3 for the honest gap assessment. The
> status legend used throughout §5.3 and §4.2: **IMPLEMENTED** (code exists,
> tested), **DESIGN-STAGE** (specified, not built), **PLANNED** (intended).

The Elara Protocol **specifies** Groth16 zk-SNARKs (Zero-Knowledge Succinct Non-Interactive Arguments of Knowledge) on the BN254 curve for PRIVATE and RESTRICTED classifications. Three proof types are specified below — and implemented in Phase-1 as SHA3-256 commitments:

