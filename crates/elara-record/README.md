# elara-record

The **data layer** of the [Elara Protocol](https://github.com/navigatorbuilds/elara-mesh):
`ValidationRecord`, the byte-exact post-quantum wire codec, receipt types, the hierarchical
`ZoneId`, `uuid7`, and the verify-side crypto primitives (Dilithium3 / SPHINCS+ *verify*, SHA3).

It is the **single source of truth** shared by the AGPL Elara node and the permissive
`elara-verify` receipt verifier (its sibling crate, extraction in progress) — so a receipt
produced by the node and a receipt checked by a third-party verifier can never disagree
about the wire format.

- **Pure-Rust, `wasm32`-portable** — no storage, network, async, or node coupling.
- **Verify-only crypto** — this crate carries signature *verification* and hashing; it does
  **not** carry key generation or signing (those stay in the node).
- **Licensed `MIT OR Apache-2.0`** so it embeds anywhere: CLI, browser-WASM, third-party apps.

Extracted from the Elara Protocol node as part of its standalone-crates lane; the node
re-exports these types, so in-node and standalone use stay byte-identical.

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.
