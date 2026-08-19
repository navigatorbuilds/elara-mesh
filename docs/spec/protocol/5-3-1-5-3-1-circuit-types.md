#### 5.3.1 Circuit Types

| Type | Public Inputs | Private Witness | Proves |
|------|--------------|-----------------|--------|
| **BalanceRange** | threshold | balance, excess | "I have ≥ threshold beats" without revealing exact balance |
| **MetadataProperty** | key_hash, commitment | value_hash, salt | "Metadata key has a specific value" without revealing it |
| **ContentCommitment** | commitment | content_hash_fr, blinding_factor | "I know content behind this commitment" |

The proof *semantics* above are implemented in Phase-1 as SHA3-256 commitments
(`src/crypto/commitment.rs`). The R1CS circuit specifications that follow are the
**DESIGN-STAGE** Groth16 target — no R1CS, Poseidon, or BN254 code exists in the
tree.

**BalanceRange circuit** (R1CS, design-stage): Would prove `balance ≥ threshold` by decomposing `excess = balance - threshold` into 64 bits, constraining all higher bits to zero. This implicitly constrains excess to `[0, 2^64)`.

**MetadataProperty circuit** (R1CS, design-stage): Algebraic commitment `commitment = key_hash + value_hash × salt`. Demonstrates the R1CS structure for property commitments.

**ContentCommitment circuit** (R1CS with Poseidon hash, design-stage): The primary ZK-friendly circuit in the target design. Would use Poseidon hash inside R1CS constraints:

```
Public inputs:  commitment
Private witness: content_hash_fr, blinding_factor
Constraint:     commitment == Poseidon(content_hash_fr, blinding_factor)
```

Poseidon parameters for BN254: rate=2, capacity=1, alpha=17, 8 full rounds + 57 partial rounds (standard security parameters from the Poseidon specification).

