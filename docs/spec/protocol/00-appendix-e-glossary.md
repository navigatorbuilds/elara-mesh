## Appendix E: Glossary

| Term                              | Definition                                                                                                                   |
|-----------------------------------|------------------------------------------------------------------------------------------------------------------------------|
| **DAM**                           | Directed Acyclic Mesh — the protocol's zone-partitioned data structure with self-healing topology and two operational layers |
| **AWC**                           | Adaptive Witness Consensus — the protocol's continuous trust consensus mechanism                                             |
| **PQC**                           | Post-Quantum Cryptography — cryptographic algorithms resistant to quantum computing                                          |
| **ZKP**                           | Zero-Knowledge Proof — a proof that a statement is true without revealing the underlying data                                |
| **PoWaS**                         | Proof of Work-at-Stake — hybrid Sybil resistance combining staking and lightweight computation                               |
| **ITC**                           | Interval Tree Clocks — scalable logical clocks used for intra-zone causal ordering                                           |
| **TYOS**                          | Historical internal code name for the utility unit, since renamed the **beat** throughout the codebase. Not required for private deployments (Section 10.6) |
| **Zone**                          | An autonomous region of the DAM (geographic or planetary)                                                                    |
| **Epoch**                         | A time-bounded segment of the DAM, sealed with a Merkle root by anchor nodes                                                 |
| **Leaf node**                     | A device that creates and validates locally but does not relay or witness                                                    |
| **Anchor node**                   | A high-availability, high-trust node that publishes trust headers and signs epoch summaries                                  |
| **Trust score**                   | A continuous value in [0, 1] representing network confidence in a validation record                                          |
| **Causal anchor**                 | A DAG reference that cryptographically binds a record to a specific point in the DAM's history                               |
| **Identity constellation**        | A set of device keys linked to a root identity for multi-device key management                                               |
| **Continuity score**              | A trust component measuring how long an identity has maintained unbroken network presence                                    |
| **Reincarnation detection**       | Behavioral fingerprinting that identifies likely identity resets from the same physical device                               |
| **Organizational identity chain** | A hierarchy linking device fleet identities to an organizational root for accountability persistence                         |
| **Hardware attestation level**    | Classification of identity binding strength: NONE, SOFTWARE, SECURE_BOOT, HARDWARE_KEY, or PUF                               |
| **Cognitive Continuity Chain**    | A hash-chained sequence of dual-signed cognitive state snapshots that provides cryptographic proof of unbroken AI experience  |
| **CognitiveDigest**               | A structured summary of a node's cognitive state (mood, memory counts, goals, allostatic load) captured in each checkpoint    |
| **Module Tier**                   | A 4-level capability classification (VALIDATE/REMEMBER/THINK/CONNECT) that controls what cognitive features a node activates  |
| **Cognitive Checkpoint**          | A ValidationRecord of type `cognitive_checkpoint` containing a CognitiveDigest, chained to previous checkpoints via DAG refs  |

---

**Document Hash (SHA-256, v0.6.1):** *computed after final edit*
**Hash verification:** To verify, replace the hash on the line above with the literal string `HASH_PLACEHOLDER` and compute SHA-256 of the file.
**Previous Hash (v0.5.3):** *see ELARA-PROTOCOL-WHITEPAPER.v0.5.3.md.ots*
**Previous Hash (v0.5.2):** *see ELARA-PROTOCOL-WHITEPAPER.v0.5.2.md.ots*
**Previous Hash (v0.5.1):** *see ELARA-PROTOCOL-WHITEPAPER.v0.5.1.md.ots*
**Previous Hash (v0.5.0):** *see ELARA-PROTOCOL-WHITEPAPER.v0.5.0.md.ots*
**Previous Hash (v0.2.9):** `5db16af282aded38d34802f4b0f8a15ef0f65f4c945d53a513b59d6e99ee4339`
**Previous Hash (v0.2.8):** `b5ccc415492d63275bbe80acb1deafd1ad7a64388d940f425fd29e497a5ccdf4`
**Previous Hash (v0.2.7):** `b9a249c93ae082b20269aa3bbd338d8e2740b15339ce473304f02c0ed81d166f`
**Previous Hash (v0.2.6):** `ec1c676b447c9082a4ecd3079f4b74057f64d7f41bdd282e77af31e84d667e26`
**Previous Hash (v0.2.5):** `25dfbe17d91208ad28feb1263105b818a367680539a9d506ac6191d80c5b4c12`
**Previous Hash (v0.2.3):** `b7220126fc907685ee946ea0226f49688a6fc3e585c1055811368d0c223a6336`
**OpenTimestamps Proof:** `ELARA-PROTOCOL-WHITEPAPER.v0.6.1.md.ots`
**Genesis Document:** `ELARA-PROTOCOL-GENESIS.md` (2026-02-09, OpenTimestamps verified on Bitcoin blocks 935812, 935817, 935820, 935861)

---

