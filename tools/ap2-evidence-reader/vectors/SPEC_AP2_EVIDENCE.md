<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Roberto Locatelli -->

# ap2-evidence-pack — normative format v1.0 (2026-09-05)

Status: **candidate standard**, defined by the conformance vectors in
`spec/vectors/ap2/` (each `<name>.json` pack + `<name>.expected.json`
policy/verdict). An independent verifier claims conformance by reproducing every
vector's `normative` block from this text alone — see §7. Reference
implementation: `ap2_evidence.py` (informative, not normative).

Scope (what a valid pack proves): these exact SD-JWT artifacts, with the
snapshotted key material, verified when the pack was built; the pack was not
altered afterwards; and — only when an RFC 3161 token verifies — all of it
existed by the TSA's time. It does NOT prove the issuer authorised a key beyond
the declared provenance class, and never proves the truth of the recorded
transaction.

## 1. Container

One UTF-8 JSON object. A strict parser MUST reject duplicate object keys
(top-level or nested). Top-level fields:

| Field | Req | Meaning |
|---|---|---|
| `evidence_format` | MUST | `"ap2-evidence-pack/1.0"` |
| `subject` | MUST | free-text description |
| `created_utc` | MUST | ISO-8601 UTC, `YYYY-MM-DDTHH:MM:SSZ` |
| `artifacts` | MUST | array of artifact entries (§2), ≥ 1 — an empty pack is never `valid` |
| `bindings` | MUST | array of discovered hash bindings (§4) |
| `honest_scope` | MUST | the scope statement, part of the sealed content |
| `evidence_digest_sha256` | MUST | hex SHA-256 over the canonical content (§3) |
| `rfc3161_timestamp` | MUST | `{"anchored": false, ...}` or `{"anchored": true, "tsr_b64": <b64 DER TimeStampResp>, ...}` |
| `producer_signatures` | MAY | hybrid producer-signature block (§5) |

## 2. Artifact entry

| Field | Meaning |
|---|---|
| `name` | unique within the pack (duplicate names MUST reject at build) |
| `sd_jwt_compact` | the EXACT compact serialization `issuer-JWT~disclosure*~[kb-jwt]` |
| `header` | the decoded protected header (informative copy) |
| `key` | `{"jwk": <P-256 JWK>, "provenance_class": <class>, ...}` — the snapshotted verification key |
| `resolved_claims` | payload with every `_sd` digest resolved to its disclosed claim |
| `kb_jwt` | KB-JWT verification record (§6, `kb_verified`) |
| `verified_at_build` | build-time attestation (informative) |

`provenance_class` is a DECLARED dimension, one of `x5c_header`, `jwk_header`,
`supplied`, `jwks_fetched` — the format records how the key was captured instead
of pretending all captures are equal. `jwk_header` is self-asserted.

## 3. Canonicalisation and digest (NORMATIVE)

`evidence_digest_sha256 = HEX(SHA-256(canonical_bytes))` where `canonical_bytes`
is the JSON serialisation of the top-level object **excluding** the keys
`evidence_digest_sha256`, `rfc3161_timestamp`, `producer_signatures`, with:

- keys sorted lexicographically, recursively;
- separators `(",", ":")` — no insignificant whitespace;
- ASCII-escaped output (`ensure_ascii`): every non-ASCII character as `\uXXXX`.

(The file's own indentation/escaping on disk is NOT significant — the digest
is over the canonical form, not the file bytes.) The RFC 3161 token and the
producer signatures are outside the digest so they can be attached after
sealing without changing what they attest.

## 4. Bindings (NORMATIVE)

A binding records that one artifact commits to another **by value**: artifact
`A` binds `B` iff some string claim in `A`'s resolved claims equals
`HEX(SHA-256(B.sd_jwt_compact))` — the hash of the exact compact serialization
(the primary quantity, not a proxy field). A verifier MUST recompute the full
binding set and compare it to the recorded `bindings`; a mismatch fails the pack.

## 5. Producer signatures (NORMATIVE when present)

```json
{"scheme": "hybrid" | "classical-only",
 "over": "evidence_digest_sha256",
 "signatures": [{"sig_alg": "ed25519" | "ecdsa-p256" | "ml-dsa-65",
                 "public_key_b64": "<base64 raw key>",
                 "signature_b64": "<base64 signature>",
                 "post_quantum": bool}]}
```

Each signature is over the **ASCII bytes of the lowercase hex**
`evidence_digest_sha256` as **recomputed** by the verifier (never the declared
value — recompute-from-content is the rule). Key/signature encodings: `ed25519`
raw 32-byte key / 64-byte signature; `ecdsa-p256` X9.62 uncompressed point
(65 bytes, leading `0x04`) / raw `r||s` (64 bytes), SHA-256; `ml-dsa-65`
FIPS 204 **final** ML-DSA-65, external/pure interface, **empty context** —
raw 1952-byte key / ≈3309-byte signature. (The ML-DSA-65 path is checked
against the NIST ACVP sigVer subset in `pqcrypto/vectors/`, the same vectors
elara-mesh runs — one oracle, both stacks.)

Verification is fail-closed: any present-but-invalid signature makes the block
(and the pack) invalid; an unknown `sig_alg` or a missing PQ backend is a
verification GAP (skip), and a block with any gap or zero passing signatures is
never `ok`. **Pinning:** an embedded key proves internal consistency, never
authenticity. When the relying party supplies a pinned trust set
(`{sig_alg: [public_key_b64, ...]}`), `producer_trusted` is `true` only if every
present signature's key is pinned; a valid-but-unpinned signature MUST reject
the pack even with no policy flags set. Without a pinned set `producer_trusted`
is `null` and the pack MUST NOT be treated as authentic. `pq_protected` is true
only on a valid ML-DSA-65 signature whose key is pinned (or no pin set given).

## 6. Verification algorithm and verdict (NORMATIVE)

Inputs: the pack file, an optional pinned producer trust set, and three policy
flags: `require_producer`, `require_pq`, `require_anchor`.

1. Parse (duplicate keys reject). Recompute the digest (§3) → `digest_ok`.
2. For EVERY artifact: parse `sd_jwt_compact`; verify the ES256 signature with
   the snapshotted JWK over the JWS signing input; resolve disclosures
   fail-closed (unmatched, duplicate, or malformed disclosure → reject); the
   canonical form of the resolved claims MUST equal the recorded
   `resolved_claims`; re-verify the KB-JWT when the issuer payload carries
   `cnf.jwk` (ES256 over `issuer-JWT~disclosure*~`; without `cnf.jwk` a present
   KB-JWT is recorded as unverifiable, never treated as verified-green, and
   never fails the pack by itself — but a KB-JWT that verifies FALSE does).
3. Recompute bindings (§4), compare → `bindings_ok`.
4. If `rfc3161_timestamp.anchored`: cryptographically verify the token — status
   granted AND message imprint == the **recomputed** digest → `rfc3161_verified`
   true/false; a claimed token that cannot be checked (no tooling) is `null`
   ("recorded but NOT verified"), never true. A claimed-but-failing token fails
   the pack (tamper, not a warning).
5. Verify the producer block per §5 → `producer_ok`, `producer_trusted`,
   `pq_protected`.
6. Policy: `policy_ok` is false if `require_producer` and no valid producer
   block; if `require_pq` and not (`pq_protected` and `producer_trusted` true);
   if `require_anchor` and `rfc3161_verified` is not true (missing, unverifiable
   and failing all reject — "claimed" never upgrades to "proven").
7. `self_asserted_only` = every artifact's provenance class is `jwk_header`
   (flag, not a failure: the verdict names the weakness instead of hiding it).
8. `valid` = artifacts non-empty AND `digest_ok` AND every artifact verifies
   AND `bindings_ok` AND `rfc3161_verified` is not false AND producer block ok
   (when present) and trusted (when pinned) AND `policy_ok`.

The eleven **normative verdict fields** a conformant verifier must reproduce:
`valid`, `digest_ok`, `bindings_ok`, `policy_ok`, `pq_protected`,
`producer_present`, `producer_ok`, `producer_trusted`, `rfc3161_claimed`,
`rfc3161_verified`, `self_asserted_only` (tri-state fields use
true/false/null).

## 7. Conformance (normative)

Run every `spec/vectors/ap2/<name>.json` under the policy in
`<name>.expected.json` and reproduce the `normative` block exactly
(`run_ap2_conformance.py` does this for the reference; exit 0 = conformant).
The set contains exactly one ACCEPT (`valid_signed`) — positive control — and
five REJECTs (stripped-signature downgrade, valid-but-unpinned producer, digest
mismatch, anchor required-but-missing, anchor claimed-but-invalid). A vector
whose `requires` tooling is absent is reported SKIP, honestly unverified.
Independent implementations: open a PR to be listed in the README conformance table.
