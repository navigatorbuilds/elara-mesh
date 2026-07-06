#### 5.3.3 PQC + ZK Orthogonal Composition

ZK proofs and post-quantum signatures serve orthogonal purposes and compose naturally:

- **ZK proof = privacy** — hides content while proving properties about it
- **PQC signature = authenticity** — proves the record was created by a specific identity

Dilithium3 signature verification inside R1CS is infeasible: lattice operations produce millions of constraints, making proof generation take minutes and CRS generation hours. The pragmatic split keeps both properties without combining them inside a single circuit. A PRIVATE record carries both: a privacy proof (Phase 1: a SHA3-256 commitment; design-stage: a ZK proof — verifiable without learning the content) and a PQC signature (anyone can verify who created it).

