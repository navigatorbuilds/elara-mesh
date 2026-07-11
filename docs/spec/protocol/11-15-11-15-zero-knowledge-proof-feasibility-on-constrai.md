### 11.15 Zero-Knowledge Proof Feasibility on Constrained Devices

> **Implementation status — DESIGN-STAGE.** The proving-cost figures below are projections for the *specified* zk-SNARK construction (§5.3), not measurements of running code. The Phase-1 SHA3-256 commitment scheme generates proofs in microseconds on every device class; this analysis governs a future zk-SNARK deployment.

**The problem:** generating a zk-SNARK proof (in the specified construction) requires significant computation:

| Device                     | zk-SNARK Generation (projected) | RAM Required     |
|----------------------------|---------------------|------------------|
| Modern laptop              | 1–5 seconds         | 1–4 GB           |
| Flagship smartphone (2026) | 3–10 seconds        | 500 MB–2 GB      |
| Budget smartphone ($30)    | 15–60 seconds       | 200 MB–1 GB      |
| Raspberry Pi 4             | 10–30 seconds       | 500 MB–2 GB      |
| ESP32                      | **Infeasible**      | 520 KB total RAM |

The Kenya teenager's $30 phone can generate a proof, but it takes up to a minute and drains the battery. An ESP32 cannot generate a proof at all. This limits PRIVATE classification to devices with meaningful compute.

**Solution: Layered Privacy by Device Capability**

**Capable devices (phones, laptops, servers):**
Generate privacy proofs locally (Phase 1: SHA3-256 commitments; the zk-SNARK path is design-stage per the banner above). PRIVATE, RESTRICTED, and SOVEREIGN classifications supported.

**Constrained devices (IoT, ESP32):**
Three options for privacy-preserving validation:

1. **Gateway-delegated proof generation** — the constrained device sends content to a trusted gateway over a secure local channel. The gateway generates the ZK proof. Trust boundary: the gateway sees the content (acceptable within a single deployment, e.g., factory sensors reporting to a factory server).

2. **Deferred proof generation** — the device validates as PUBLIC initially (just the hash), then a more capable device generates a ZK proof later, converting the record to PRIVATE. The record's DAM position is preserved — it does not lose its timestamp.

3. **Symmetric encryption fallback** — for IoT deployments where even the gateway should not see individual readings, the device encrypts the reading with a pre-shared key before hashing. The hash is of encrypted content. Decryption requires the key. This is not zero-knowledge in the cryptographic sense, but it provides practical privacy for the constrained device use case.

**Budget smartphones — optimization path:**

ZK proof generation on smartphones is an active area of research and optimization. Specific measures for the Elara Protocol:

- Use Groth16 (most compact and fastest zk-SNARK) for the standard proof circuit
- Pre-compute the proving key once and cache it (~50 MB)
- Offload to GPU/NPU on devices that support it (most 2025+ smartphones have ML accelerators that can be repurposed)
- As STARK compression advances, migrate to STARKs which have simpler prover algorithms

The protocol's algorithm agility ensures that as ZKP technology improves, constrained devices gain privacy capabilities without protocol changes.

