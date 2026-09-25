### Phase 1: Protocol Development (2026–2027)

- Reference implementation of Layer 1 (local validation, PQC keypair, DAG) — **shipped** (Rust, public source repository; releases v0.2.0–v0.3.0)
- Layer 1.5 runtime features (DAM VM with its 9 operations; PyO3 bindings for signing, verification, hashing and record encoding) — **shipped**
- Reference implementation of Layer 2 (HTTP server, record exchange, witness attestation, MESH-BFT epoch seals and settlement) — **shipped** (Rust, public source repository)
- Layer 2 hardening (signature verification on ingest, peer rate limiting, witness reputation with a 180-day half-life and a zone-diversity bonus, peer heartbeat and liveness probes, bounded post-quantum verification under load) — **shipped**
- Layer 3 prototype (Elara Core, private and frozen; not part of the open-source release): Layer 1↔Layer 3 bridge, Cortical Execution Model, tier system, Cognitive Continuity Chain — built in the prototype. Earlier editions of this paper tagged these with the prototype's internal version numbers (v0.10.8–v0.15.0); those were never public releases.
- Security audit by independent cryptography firm — **not yet done**
- Developer SDK (Python, Rust, C/embedded) — partly shipped: Rust crates on crates.io (`elara-record`, `elara-verify` and others), Python and TypeScript SDKs in the source repository; C/embedded not started

