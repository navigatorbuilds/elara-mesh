# ap2-evidence-reader

An independent, fail-closed reader for **`ap2-evidence-pack/1.0`** — the AP2 mandate
evidence-pack format specified in
[`SPEC_AP2_EVIDENCE.md`](vectors/SPEC_AP2_EVIDENCE.md) (v1.0, 2026-09-05, Roberto Locatelli,
Apache-2.0; discussed on
[google-agentic-commerce/AP2 #338](https://github.com/google-agentic-commerce/AP2/issues/338)).

**Independence.** This reader was written from the spec text and the six published conformance
vectors only. The reference implementation (`ap2_evidence.py`, `run_ap2_conformance.py`,
`make_vectors.py`) was deliberately never opened, so that agreement between the two readers means
"the spec is implementable as written", not "the port matches".

**Result (2026-09-06):** all six upstream vectors reproduce every one of the eleven normative
verdict fields (66/66), with exactly one ACCEPT (`valid_signed`). `cargo test` re-checks this.

## Build and run

```sh
cd tools/ap2-evidence-reader          # stand-alone crate: its own lockfile + target dir
cargo build --release
cargo test

# Verify one pack (exit 0 = valid, 1 = invalid, 2 = usage/parse error). Policy flags and the
# pinned trust set can come from an upstream `*.expected.json` or from the CLI.
target/release/ap2-evidence-reader verify vectors/valid_signed.json --policy vectors/valid_signed.expected.json
target/release/ap2-evidence-reader verify pack.json --pins pins.json --require-producer --require-pq

# Reproduce the upstream conformance table (markdown on stdout; exit 0 only if every field matches).
target/release/ap2-evidence-reader conformance vectors

# Check an RFC 3161 token against a digest, with or without a TSA trust anchor.
target/release/ap2-evidence-reader rfc3161 tests/fixtures/freetsa-epoch-107599-zone-0.tsr \
    59065cf1cf6615a40c5edde97740bc683fafb94626171f88d92e74f6fa971a90 --tsa-root tests/fixtures/freetsa-cacert.pem
```

Output of `verify` is one canonical JSON object `{"diagnostics": …, "normative": …}`; the
`normative` block is exactly the eleven tri-state fields of spec §6 (`valid`, `digest_ok`,
`bindings_ok`, `policy_ok`, `pq_protected`, `producer_present`, `producer_ok`,
`producer_trusted`, `rfc3161_claimed`, `rfc3161_verified`, `self_asserted_only`).

## What it checks (spec section → module)

| Spec | Check | Where |
|---|---|---|
| §1 | strict RFC 8259 JSON, **duplicate keys rejected at any depth**, required top-level fields and types, `created_utc` shape, non-empty `artifacts` | `json.rs`, `pack.rs` |
| §3 | digest = SHA-256 of the Python-compatible canonical form (sorted keys, `,`/`:`, `ensure_ascii`) of the top-level object minus the three excluded keys | `json::canonical`, `pack.rs` |
| §2, §6.2 | per artifact: ES256 issuer signature under the **snapshotted** `key.jwk` (not the header copy), fail-closed SD-JWT disclosure resolution (unmatched / duplicate / malformed / colliding / reserved-name → reject), canonical resolved claims == recorded `resolved_claims`, KB-JWT re-verified under `cnf.jwk` when present | `sdjwt.rs` |
| §4 | bindings recomputed from top-level string claims (`hex(sha256(other.sd_jwt_compact))`) and compared to the recorded set | `pack::compute_bindings` |
| §5 | producer block: `ed25519` (strict), `ecdsa-p256` (raw r‖s, SHA-256), `ml-dsa-65` (FIPS 204 final, pure, empty context — via `elara_record::pqc::dilithium3_verify`, the same function every Elara record signature uses, ACVP-pinned in `crates/elara-record/tests/acvp_mldsa65.rs`); each signature over the ASCII lowercase hex of the **recomputed** digest; any invalid signature fails the block; unknown `sig_alg` = gap; pinning per §5 | `producer.rs` |
| §6.4 | RFC 3161: DER parse, status granted, `messageImprint` (SHA-256) == recomputed digest, signed `messageDigest`/`contentType` attributes, CMS signature under the embedded signer certificate (RSA PKCS#1 v1.5 / RSASSA-PSS / ECDSA P-256 / P-384), `id-kp-timeStamping` EKU, chain to a supplied trust anchor (`--tsa-root`) with validity at `genTime` | `rfc3161.rs`, `der.rs` |
| §6.6–6.8 | policy flags, `self_asserted_only`, the `valid` conjunction | `pack.rs` |

The RFC 3161 path is exercised by a **real** freetsa.org token over an Elara epoch seal
(`tests/fixtures/freetsa-epoch-107599-zone-0.tsr`, from `examples/verify/`): with the freetsa root
supplied it verifies; without one it is *null* (never true); a wrong imprint, a flipped signature
byte, or garbage (the `anchor_invalid` vector) is *false*.

## What it does not do

- It does not fetch anything: no JWKS lookups, no TSA queries, no CA bundles. Trust roots for
  RFC 3161 come only from `--tsa-root`.
- It does not evaluate AP2 mandate *semantics* (amounts, scopes, expiry) — only the evidence
  container, its signatures and its internal commitments.
- `x5c_header` / `supplied` / `jwks_fetched` provenance classes are recorded, not validated; the
  spec says the pack carries a snapshot and this reader verifies against that snapshot.
- KB-JWT `aud` / `nonce` / `iat` are not policy-checked (the spec does not ask for it).

## Spec observations (things the text leaves open, and what this reader does)

Filed so the two implementations can converge. Marked **[spec]** where the spec would need a
sentence, **[choice]** where the reader picked one of several defensible readings.

1. **[spec] Bindings over nested claims.** §4 says "some string claim in A's resolved claims"; this
   reader only scans **top-level** string claims. A binding sitting inside a nested object or array
   would be missed by this reader and (depending on the reference) possibly found by the other.
2. **[spec] `post_quantum` flag vs algorithm.** §5 never says what happens when `post_quantum`
   disagrees with `sig_alg`. This reader treats `post_quantum: true` on a classical algorithm (or
   `false` on ML-DSA-65) as an invalid signature entry → block fails.
3. **[spec] Pins supplied but no producer block.** `producer_trusted` is `null` (block absent);
   `valid` is then governed only by `require_producer`. The spec's "valid-but-unpinned MUST reject"
   sentence does not reach an absent block.
4. **[spec] Unknown `sig_alg` counts as a gap.** A gap makes `producer_ok` **false** here (the spec
   says "never ok"; it does not say whether that is `false` or `null`).
5. **[spec] Hybrid composition is not enforced.** `scheme: "hybrid"` with only classical signatures
   (or only ML-DSA-65) passes §5 as written; the reader does not add a composition rule.
6. **[spec] RFC 3161 trust root.** `anchor_invalid.expected.json` requires `openssl`, i.e.
   `openssl ts -verify`, which needs a `-CAfile` the spec never names. Without a root a structurally
   valid token can only ever be `null` here; it is never promoted to `true` on internal consistency
   alone. `rfc3161_verified: true` therefore always means "chained to the anchor the verifier chose".
7. **[choice] Container MUST violations** (wrong `evidence_format`, missing `honest_scope`, bad
   `created_utc`, …) fold into `valid: false` via a diagnostic `container_ok`; the spec has no
   normative field for them.
8. **[choice] `header` is informative.** A mismatch between the recorded `header` copy and the
   actual protected header is reported as a diagnostic, never a failure; the signature is checked
   under `key.jwk` only.
9. **[choice] Recorded `kb_jwt` block** is not compared against the computed KB-JWT status (the
   spec marks it as a record). A KB-JWT that is present without `cnf.jwk` stays `null` and never
   fails the artifact by itself, as §6.2 says; one that verifies false does.
10. **[choice] JSON strictness beyond RFC 8259.** Lone surrogates (`"\ud800"`) and the
    `NaN`/`Infinity` literals are rejected even though Python's `json` accepts them; big integers
    are kept as decimal text; floats re-serialise with Python's `repr` rules (the vectors contain
    no floats, so this path is covered by unit tests only).
11. **[choice] `verify_strict` for ed25519** (rejects non-canonical points/scalars) — stricter than
    RFC 8032 basic verification.
12. **[choice] Exactly one SignerInfo** is accepted in a timestamp token (RFC 3161 §2.4.2 requires
    it); `signedAttrs` are mandatory.

No vector exercises KB-JWT / `cnf.jwk`, `x5c_header`, `ecdsa-p256` producer signatures, nested
bindings, or a *valid* RFC 3161 anchor; those paths are covered by unit tests or not at all and are
the natural next vectors.

## Layout

```
Cargo.toml         stand-alone crate ([workspace] table → not a member of the elara-runtime workspace)
src/json.rs        strict parser + Python-compatible canonical serializer
src/der.rs         minimal DER walker
src/sdjwt.rs       SD-JWT (ES256) artifact verification
src/producer.rs    §5 producer signatures (ed25519 / ecdsa-p256 / ml-dsa-65)
src/rfc3161.rs     RFC 3161 TimeStampResp verification
src/pack.rs        container, digest, bindings, policy, verdict
src/main.rs        CLI (verify / conformance / rfc3161)
vectors/           upstream spec + vectors, verbatim (see vectors/README.md)
tests/fixtures/    real freetsa token over an Elara epoch seal + the freetsa root certificate
```

Licence: MIT OR Apache-2.0 (same as `elara-record`). The vectors and spec under `vectors/` are
Apache-2.0, © Roberto Locatelli.
