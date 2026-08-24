# What exactly is signed — the rule beside the vectors

2026-08-22. An independent implementer verifying these bundles with their own
code had to recover the signing rule from source comments. That is a
documentation defect: the rule belongs next to the artifacts it governs. This
file is that fix. If anything here disagrees with the code, the code is
normative and this file has a bug — tell us on the SCITT list or open an issue.

## The one rule

> **Correction 2026-08-23.** The first published version of this page
> (2026-08-22) said every signature in a bundle is ML-DSA-65. That omitted the
> record's **SLH-DSA co-signature** — records are dual-signed (Profile A), and
> our own verifier prints so on every run. The preimage rule below was and is
> correct; the signature count was not. Same page, fixed the next day, stated
> here rather than silently.

A published record carries **two** signatures from its creator — an
**ML-DSA-65** (Dilithium3, FIPS 204) signature and an **SLH-DSA-SHA2-192f**
(SPHINCS+, FIPS 205) co-signature — and **both cover the identical preimage**:
`ValidationRecord::signable_bytes()` — crate
[`elara-record`](https://crates.io/crates/elara-record) (0.3.x),
`src/record.rs`. The verifier requires the ML-DSA-65 signature and grades the
SLH-DSA leg as the dual-signature profile check ("Profile A"). The preimage is
domain-separated (a constant tag leads it from record version 6 on, followed by
the length-prefixed network id), every variable-length field is
length-prefixed, every integer fixed-width big-endian. The byte layout is
pinned by frozen known-answer tests (`tests/kat_frozen_preimages.rs` in the
same crate) — those KATs, not any prose, are the compatibility contract.

For a mandate bundle specifically: the mandate JSON rides **inside** that
preimage, as part of the record's canonical-JSON metadata
(`json.dumps(metadata, sort_keys=True, separators=(",", ":"))` shape). The
carrier's signature covers it. There is no separate signature over the mandate
object itself.

## The trap, named so you do not repeat it

`MandateRecord::canonical_signing_bytes` (crate
[`elara-verify`](https://crates.io/crates/elara-verify), `src/mandate.rs`) is an
**id-derivation** preimage: `mandate_id` is SHA3-256 of those bytes, and that is
the only thing they are used for. Despite the name, nothing anywhere verifies a
signature over them. Its same-named neighbour `RealmCert::canonical_signing_bytes`
IS genuinely signed and verified — so anyone who greps the method name finds a
real sign/verify pair first and assumes it applies to mandates. It does not.
The in-source correction is dated 2026-07-29 (`elara-verify/src/mandate.rs`,
doc comment on the method); on 2026-08-22 it caught an independent implementer
mid-mistake, which is why this paragraph now also lives here.

## How the principal binds, if not by signing the mandate preimage

An ingest-time equality rule, re-checked by the verifier:
`sha3_256(carrier record's creator_public_key) == mandate.principal_identity_hash`
(`elara-verify/src/mandate.rs`, chain-of-authority path). A mandate is
unforgeable by a third party because only the principal's key can create the
carrier record that the mandate must arrive in — not because the mandate
preimage carries its own signature.

## Key and signature encoding (independent-toolchain note)

Published key material is raw bytes, two legs per record: ML-DSA-65
(1,952-byte public key, 3,309-byte signature) and SLH-DSA-SHA2-192f
(48-byte public key, 35,664-byte signature — 86% of a typical record's wire
bytes; the hash-based leg is the size story).
Wrapping the raw public key in a bare SPKI structure parses as `ml-dsa-65`
under OpenSSL 3.5.6 (e.g. Node v24.16); under OpenSSL 3.5.1 the identical wrap
yields a key object with no algorithm name. If you report interop results,
name your toolchain versions. (Established by Emek Can Dogru, Conarium,
2026-08-22, verifying these bundles with non-Elara code — the first independent
toolchain to do so.)

## What a CONSISTENT verdict does not say (scope_deferred)

A CONSISTENT verdict on a mandate bundle proves the chain of authority and its
validity at the act's signed time. It does **not** check the act against the
scope string the principal wrote; that field ships marked `scope_deferred`, and
no released verifier enforces it. Do not represent scope as enforced policy.
As of elara-verify 0.3.0 the offline bundle verdict says this itself, per
bundle: a `scope_deferred` field (`true` = a recorded restriction v0 did not
check, `false` = wildcard — nothing to enforce, which is NOT evidence of a
check, `null` = no mandate resolved) plus a "scope" row in `checks[]`, pinned
by the committed vector pair `mandate-bundle-scope-deferred.json` (positive)
and `mandate-bundle-valid.json` (negative).

---

Verify offline: `cargo install elara-verify`, then
`elara-verify --receipt <record_id>.receipt.json` against any **receipt
envelope** in this directory (that path checks the record + seal legs; its
verdict vocabulary is VERIFIED / PARTIAL / FAILED). The CONSISTENT verdict
discussed above comes from the mandate-**bundle** verifier, which has no CLI
mode: run it in your browser at
<https://navigatorbuilds.github.io/elara-mesh/verify/> (the same crate
compiled to WASM — "Scoped mandate" sample included), or feed the committed
bundle vectors (`examples/verify/mandate-bundle-*.json`) to
`elara_verify::mandate_bundle::evaluate_mandate_bundle` from Rust.
