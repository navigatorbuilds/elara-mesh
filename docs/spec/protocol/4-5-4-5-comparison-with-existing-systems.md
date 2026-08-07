### 4.5 Comparison with Existing Systems

| System Type              | Typical Signature Algorithm                     | Quantum-Safe | Migration Status |
|--------------------------|-------------------------------------------------|--------------|------------------|
| PoW blockchains          | ECDSA (secp256k1)                               | No           | Not started      |
| Smart contract platforms | ECDSA (secp256k1)                               | No           | Research phase   |
| High-throughput ledgers  | Ed25519                                         | No           | Not started      |
| DAG-based systems        | Ed25519 / hash-based OTS                        | Partial      | In progress      |
| Elara Protocol           | Dilithium (all profiles) + SPHINCS+ (Profile A) | **Yes**      | **Native**       |

The Elara Protocol's signature layer is post-quantum from genesis — there is no legacy migration burden. However, algorithm agility (Section 4.4) ensures the protocol can adopt future PQC standards as the field evolves; "quantum-safe at launch" is not the same as "cryptographically final." (The ZKP layer uses classical elliptic curves in Phase 1 — see Section 11.26 for the quantum migration path.)

