### 11.11 zk-SNARK Trusted Setup

> **Implementation status — DESIGN-STAGE.** This chapter analyses the trusted setup for the *specified* Groth16 zk-SNARK construction (§5.3), which is not built. The Phase-1 runtime uses SHA3-256 commitments, which need **no trusted setup**. The ceremony design below applies to a future Groth16 deployment.

**The problem:** the specified zk-SNARKs (for PRIVATE and RESTRICTED classifications — design-stage, §5.3) would require a trusted setup ceremony — a one-time generation of cryptographic parameters (Common Reference String). If the setup is compromised, an attacker can forge proofs. Who performs this ceremony, and how is it decentralized?

**Solution: Multi-Party Computation Ceremony + Migration Path**

**Phase 1: Initial ceremony (pre-mainnet)**

The trusted setup uses a **multi-party computation (MPC) ceremony** where multiple independent participants each contribute randomness. The security guarantee: as long as at least ONE participant destroys their random input, the setup is secure.

The Elara Protocol's ceremony will:

1. Include a minimum of 100 independent participants across 20+ countries
2. Accept contributions from anyone (public participation, open-source verification tools)
3. Publish all contributions and verification proofs on the DAM itself
4. Use the Zcash Powers of Tau ceremony model [26] (battle-tested, well-understood)

**Phase 2: Progressive migration to zk-STARKs**

zk-STARKs (the specified SOVEREIGN path — design-stage, §5.3) require NO trusted setup. They are transparent — all parameters are derived from public randomness. The tradeoff is larger proof sizes (~100 KB vs ~288 bytes for SNARKs).

As hardware improves and STARK proof compression advances, the protocol will migrate PRIVATE and RESTRICTED classifications from SNARKs to STARKs:

- **Year 0-3:** SNARKs for PRIVATE/RESTRICTED (compact proofs, trusted setup)
- **Year 3-5:** Dual support (SNARKs and STARKs accepted)
- **Year 5+:** STARKs only (no trusted setup dependency)

The algorithm agility mechanism (Section 4.4) makes this migration seamless — old SNARK-based proofs remain valid; new proofs use STARKs.

**Phase 3: Long-term (post-quantum ZKPs)**

Research into post-quantum zero-knowledge proofs is active. The protocol's algorithm agility ensures it can adopt new ZKP systems (lattice-based ZKPs, hash-based ZKPs) as they mature, maintaining both quantum safety and zero-knowledge properties.

