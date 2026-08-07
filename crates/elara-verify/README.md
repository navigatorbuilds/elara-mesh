# elara-verify

The **complete offline verifier** of the [Elara Protocol](https://github.com/navigatorbuilds/elara-mesh):
record/receipt structural checks, the account-SMT walk binding (via
[`elara-smt`](https://crates.io/crates/elara-smt)), anchor-pinned seal
verification, the drand BLS +
OpenTimestamps→Bitcoin anchor legs with receipt grading (feature
`verify-anchor`), the agent-mandate evaluator and its offline bundle verdict
(`mandate` / `mandate_bundle`), the anchor-proof record codec, the
`elara-verify` CLI (feature `cli`), and the browser wasm exports (feature
`wasm`). The CLI binary, the wasm demo artifact, and the node all call this
one library, so no verdict surface can drift from another.

It is **signing-incapable by design**: key generation and signing stay in the
AGPL node; this crate (MIT/Apache) can only *check*. A verifier built on it
cannot forge what it verifies.

Pure Rust, `wasm32-unknown-unknown`-portable under default features — no tokio,
no `std::process`, no filesystem access in the core functions: they take
already-read bytes (or parsed values) and return `Result<_, String>` with the
human reason a malformed input is rejected. File IO and argv parsing live only
behind the `cli` feature; JsValue conversion only behind `wasm`.

## Usage

Verify an epoch seal offline — against a Dilithium3 anchor you pin, with no
network, no node, and no private keys:

```rust
use elara_verify::{verify_seal_record_against_anchor, SealRecordVerifyError};

// Inputs you already hold offline: a seal record's wire bytes (pulled from any
// node or read from a file), the record hash you are checking it against, and
// your pinned anchor public-key set.
let seal_wire: &[u8] = /* bytes of the epoch-seal record */ b"";
let expected_record_hash: [u8; 32] = [0u8; 32];
let trusted_anchor_pubkeys: Vec<Vec<u8>> = vec![/* pinned Dilithium3 pubkey bytes */];

match verify_seal_record_against_anchor(seal_wire, expected_record_hash, &trusted_anchor_pubkeys) {
    Ok(()) => println!("verified: decodes, hash-binds, and is signed by a trusted anchor"),
    Err(SealRecordVerifyError::RecordHashMismatch { .. }) => println!("rejected: not the record you asked for"),
    Err(e) => println!("rejected: {e}"),
}
```

`Ok(())` means all three legs held: the bytes decoded as a `ValidationRecord`,
its `record_hash()` matched `expected_record_hash`, and the seal carried a valid
Dilithium3 signature from one of `trusted_anchor_pubkeys`. For the full offline
chain (drand BLS + OpenTimestamps→Bitcoin receipt grading, account-SMT
inclusion/absence, the agent-mandate verdict) see the `elara-verify` CLI and the
worked examples in [`examples/verify/`](https://github.com/navigatorbuilds/elara-mesh/tree/master/examples/verify).

## Features

- *(default)* — record/receipt structural checks, SMT walk binding,
  `verify_seal_record_against_anchor` (decode → hash-bind → pinned-anchor-set
  membership → Dilithium3), mandate + bundle evaluation, anchor-proof codec.
- `verify-anchor` — the drand BLS (BLS12-381) and OTS anchor legs plus receipt
  grading; pulls `sha2` + `drand-verify`, both pure-Rust and wasm32-clean.
- `cli` — the `elara-verify` binary (clap + file IO + prose/JSON rendering
  around the library checks); implies `verify-anchor`.
- `wasm` — the browser exports (`verify_record_offline`,
  `verify_receipt_offline`, `evaluate_mandate_bundle`) behind `wasm-bindgen`;
  implies `verify-anchor`.

## License

MIT OR Apache-2.0 (the node that *produces* records is AGPL-3.0-only; the
verify stack is permissive so anyone can check receipts anywhere).
