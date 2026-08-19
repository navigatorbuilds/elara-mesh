### 11.0 Threat Model

Before analyzing specific attacks, we define the adversary model:

**Adversary capabilities (ordered by strength):**

| Level | Adversary         | Capabilities                                                     |
|-------|-------------------|------------------------------------------------------------------|
| 1     | Individual        | Controls one or a few nodes, limited resources                   |
| 2     | Organization      | Controls hundreds of nodes, significant capital, legal standing  |
| 3     | Nation-state      | Controls network infrastructure, can compel ISPs, legal coercion |
| 4     | Quantum adversary | Access to cryptographically relevant quantum computer (future)   |

**Assumptions:**

- **Honest majority:** At least 2/3 of staked weight in any zone is held by honest nodes (standard BFT assumption)
- **Cryptographic hardness:** NIST PQC primitives (Dilithium, Kyber, SPHINCS+) remain computationally infeasible to break for the claimed security levels
- **Network model:** Asynchronous with eventual delivery — messages may be delayed arbitrarily but are eventually delivered to honest nodes
- **No trusted hardware:** The protocol does not assume TEEs, secure enclaves, or tamper-proof devices. Security derives from cryptography and economics, not hardware trust.
- **Rational actors:** Witness nodes are economically rational — they will not spend resources on actions that reduce their expected returns

**What the protocol does NOT defend against:**

- Compromise of a creator's private key combined with physical theft of unreleased content (this is a physical security problem, not a protocol problem)
- A quantum adversary that breaks both lattice-based AND hash-based cryptography simultaneously (no known path to this)
- Social engineering that induces a user to sign content they did not create (the protocol validates signatures, not intent)

