## 5. Zero-Knowledge Validation

*Implementation-status note: throughout Section 5, "zero-knowledge proof" / "ZKP" describes the specified design. Phase 1 attaches SHA3-256 commitments to PRIVATE and RESTRICTED records; they are not zero-knowledge proofs and do not yet hide anything: each proof carries its opening, the proof is not bound to its record, and every record carries its plain content hash. The Groth16/BN254 and zk-STARK constructions are design-stage and rejected on the wire until a prover/verifier lands. Section 5.3 gives the full status; Section 11.26 describes the migration path and Section 14.3 its open risks.*

