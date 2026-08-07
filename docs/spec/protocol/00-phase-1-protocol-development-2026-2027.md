### Phase 1: Protocol Development (2026–2027)

- Reference implementation of Layer 1 (local validation, PQC keypair, DAG) — **shipped**
- Reference implementation of Layer 1.5 (Rust DAM VM, 9 ops, PyO3 bindings) — **shipped**
- Reference implementation of Layer 2 (HTTP server, record exchange, witness attestation) — **shipped** (v0.11.0: server, client, discovery, witness manager, trust scoring — 985 lines across 8 files)
- Layer 2 testnet hardening (signature verification, peer rate limiting, attestation back-propagation, heartbeat protocol, weighted trust with temporal decay + diversity bonus, role enforcement) — **shipped** (v0.12.0)
- Layer 1↔Layer 3 bridge (cognitive outputs signed as DAM records, hardened with validation guards, dedup, rate limiting) — **shipped** (v0.10.8, hardened v0.11.0)
- Cortical Execution Model (5-layer concurrent architecture for non-blocking tool dispatch) + long-range temporal memory — **shipped** (v0.13.0)
- Tier system (4-level hardware capability gating: VALIDATE/REMEMBER/THINK/CONNECT) — **shipped** (v0.15.0)
- Cognitive Continuity Chain (hash-chained, dual-signed cognitive state snapshots in DAG — cryptographic proof of unbroken AI experience) — **shipped** (v0.15.0)
- Security audit by independent cryptography firm — **not yet done** (no third-party security audit has been performed as of 2026)
- Developer SDK (Python, Rust, C/embedded) — **partial** (Rust + PQ/light-client SDK crates shipped; packaged Python/C bindings planned)

