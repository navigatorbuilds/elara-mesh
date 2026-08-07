# elara-record

The **data layer** of the [Elara Protocol](https://github.com/navigatorbuilds/elara-mesh):
`ValidationRecord`, the byte-exact post-quantum wire codec, receipt types, the hierarchical
`ZoneId`, `uuid7`, and the verify-side crypto primitives (Dilithium3 / SPHINCS+ *verify*, SHA3).

It is the **single source of truth** shared by the AGPL Elara node and the permissive
`elara-verify` receipt verifier (its sibling crate) — so a receipt
produced by the node and a receipt checked by a third-party verifier can never disagree
about the wire format.

- **Pure-Rust, `wasm32`-portable** — no storage, network, async, or node coupling.
- **Verify-only crypto** — this crate carries signature *verification* and hashing; it does
  **not** carry key generation or signing (those stay in the node).
- **Licensed `MIT OR Apache-2.0`** so it embeds anywhere: CLI, browser-WASM, third-party apps.

Extracted from the Elara Protocol node as part of its standalone-crates lane; the node
re-exports these types, so in-node and standalone use stay byte-identical.

## Usage

Decode a record from its wire bytes and read its byte-exact identity — the same
32-byte hash the node and any third-party verifier independently compute:

```rust
use elara_record::record::ValidationRecord;

// Wire bytes of a record — from a node, a file, or an `elara-verify` receipt.
let wire: &[u8] = /* the record's bytes */ b"";
match ValidationRecord::from_bytes(wire) {
    Ok(rec) => {
        let hash: [u8; 32] = rec.record_hash();
        println!("record id={} v{} hash[0..2]={:02x}{:02x}", rec.id, rec.version, hash[0], hash[1]);
    }
    Err(e) => println!("not a valid elara record: {e:?}"),
}
```

Pair it with [`elara-verify`](https://crates.io/crates/elara-verify) to check a
record/receipt against a pinned anchor, fully offline.

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.
