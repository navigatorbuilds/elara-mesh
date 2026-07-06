# Contributing to Elara Runtime

Thank you for your interest in the Elara Protocol. This guide covers how to contribute.

## Getting Started

```bash
# Clone and build
git clone https://github.com/navigatorbuilds/elara-mesh.git
cd elara-mesh
cargo build --features node

# Run tests
cargo test --features node --lib

# Run integration tests (in tests/; some bind localhost ports — run sequentially)
cargo test --features node --test record_relay_v1 --test relay_by_hash \
  --test slot_conflict_injection --test spec_compliance -- --test-threads=1
```

## Project Structure

```
src/
├── crypto/           # Post-quantum cryptography (Dilithium3, SPHINCS+, ML-KEM-768)
├── accounting/       # beat ledger — custodial accounting (24 modules)
├── network/          # Node daemon (HTTP, WebSocket, gossip, consensus)
├── content_safety.rs # 6-layer content safety
├── identity.rs       # Identity management + PoW
├── record.rs         # Validation records + wire format
├── dag.rs            # Directed Acyclic Mesh
└── storage/          # RocksDB backend (column families, FTS)

crates/               # Extracted standalone crates (PQ transport, light-client, SMT, …) — MIT/Apache
scripts/              # Build, testing, verification
tests/                # Integration tests (multi-node)
```

## Development Guidelines

- **Run tests before committing:** `cargo test --features node --lib` — all 5,700+ lib tests must pass with 0 failures
- **No unsafe code** — the entire codebase is safe Rust
- **Clippy clean:** `cargo clippy --features node` should produce minimal warnings
- **Security first:** read `SECURITY.md` and `docs/CONTENT-POSTURE.md` before touching security-related code
- **Scale rule:** every change must be designed for the target scale (1M zones, 10T records/day, 10K+ nodes — design targets, not current demonstrated capacity). No O(all_records) scans, no full rebuilds in hot paths, no loading all data into memory.
- **Historical references:** comments citing "internal design notes §N" or dated internal audits point at the project's private engineering ledger, kept for provenance — those documents are not part of this repository.

## What to Work On

Check the [GitHub Issues](https://github.com/navigatorbuilds/elara-mesh/issues) for open items. Good areas:

- **Tests** — integration tests for untested endpoints, property-based tests, fuzzing
- **Documentation** — API examples, architecture diagrams, tutorials
- **Light clients & SDKs** — WASM/embedded verification, Python/light-client SDK ergonomics
- **Performance** — benchmarks, optimization of gossip/consensus paths

## Pull Request Process

1. Fork the repo
2. Create a feature branch
3. Write tests for your changes
4. Ensure all tests pass
5. Submit a PR with a clear description

## Code of Conduct

Be respectful. Focus on the work. No spam, no self-promotion in issues.

## License

Split model (see [LICENSING.md](LICENSING.md)): the node / network / protocol
code (`elara-runtime` crate) is **AGPL-3.0-only**; the client SDKs under
`sdks/` and extracted crates are **MIT OR Apache-2.0**. Contributions are
accepted under the license of the component they modify (inbound = outbound) —
no contributor license agreement required.

## Questions?

- Email: nenadvasic@protonmail.com
- GitHub Issues: preferred for technical discussions
