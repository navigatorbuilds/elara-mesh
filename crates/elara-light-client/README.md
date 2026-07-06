# elara-light-client

Stateless, **wasm-portable light-client verification** for the
[Elara Protocol](https://github.com/navigatorbuilds/elara-mesh). A light client
never replays the chain: it pins a small amount of trusted data out of band — a
witness-signed epoch seal, or an anchor pubkey set — and checks individual
proofs against it with pure functions that do no I/O, allocate almost nothing,
and run unchanged in a `wasm32` browser build.

This crate is the **deterministic core** of that flow.

## What it does

```rust
use elara_light_client::{LiteAccountStateProof, LiteEpochHeader,
    verify_account_proof_against_header};

// A proof from `/proof/account/{id}` and a header from `/epochs/headers`
// deserialize straight from the endpoints' JSON (32-byte fields as hex).
let proof: LiteAccountStateProof = serde_json::from_str(proof_json)?;
let header: LiteEpochHeader = serde_json::from_str(header_json)?;

// True only if the proof folds to the `account_smt_root` the header signs —
// connecting "this is the account's state" to "the network sealed this state".
if verify_account_proof_against_header(&proof, &header) {
    // trust proof.state_hash as the account's state-as-of-seal
}
# Ok::<(), serde_json::Error>(())
```

* [`verify_proof`] folds a 64-level account-SMT inclusion proof back to a root.
  A leaf's position is `SHA3-256(account_id)`, so a proof is a fixed 64 siblings
  regardless of how many accounts exist.
* [`verify_account_proof_against_header`] binds that proof to the
  `account_smt_root` a trusted epoch header signs.
* [`verify_state_delta_seal_binding`] checks that a fetched state-delta is bound
  to the exact seal (epoch + root) the caller already trusts, so a server cannot
  serve a delta from a different chain head.

The wire types ([`LiteAccountStateProof`], [`LiteEpochHeader`],
[`LiteStateDeltaBinding`]) deserialize from either the REST JSON shape
(`[u8; 32]` as 64-char hex) or the in-process Rust→JSON shape (byte arrays), so
a caller can feed a raw endpoint payload straight in.

## Scope

This crate covers the storage-free, **signature-free** half of the trust chain —
the part a phone or browser must run locally. Verifying a fetched seal record's
Dilithium3 signature against an anchor set stays in the Elara Protocol node,
which owns the `ValidationRecord` wire type. The hashing is pinned to SHA3-256 at
the same `sha3` minor the node resolves, so a proof the node produces folds
byte-identically here. `#![forbid(unsafe_code)]`.

## License

Licensed under either of [MIT](LICENSE-MIT) or
[Apache-2.0](LICENSE-APACHE) at your option.
