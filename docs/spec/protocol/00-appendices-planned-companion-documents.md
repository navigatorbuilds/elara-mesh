## Appendices (Planned Companion Documents)

The following companion documents will be published separately during Phase 1 development (2026–2027):

- **Appendix A: Protocol Wire Format** — Complete binary encoding, message formats, handshake sequences, and network protocol specification for interoperable implementations. *Published in part as `docs/PROTOCOL-SPEC.md` in the runtime source repository: record encoding, signature preimage, record verification, account proofs and zone routing are normative there, with test vectors; epoch seals (apart from the normative Merkle fold recipe) and the post-quantum transport handshake are described as reference material. Where that document and the code disagree, the code is authoritative.*
- **Appendix B: Cryptographic Parameter Selection** — Security level rationale, performance benchmarks on target hardware (ESP32, Raspberry Pi, smartphone, server), and comparison with alternative parameter sets. *Not yet produced; the Q3 2026 target was missed. Desktop-class measurements are in the runtime's `benches/bench_crypto.rs` (Section 4.2); ESP32, Raspberry Pi and smartphone have not been measured.*
- **Appendix C: Economic Model Simulation** — Agent-based simulation of the beat economy modeling validator behavior, staking dynamics, free-tier sustainability, and attack economics. *Target: Q1 2027, requires testnet data from Phase 1 launch.*
- **Appendix D: TLA+ Consensus Specification** — the models and TLC configurations ship as `spec/tla/` in the runtime source (Section 11.31). A written companion document collecting the model-checking results has not been produced, and record-preserving zone merge is not among the checked properties.

