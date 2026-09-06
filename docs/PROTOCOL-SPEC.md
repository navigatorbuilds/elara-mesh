# Elara Protocol Specification

**Status:** Normative for the layers marked *Stable* in §11; informative for layers marked *Design-stage*.
**Reference implementation:** `elara-runtime` (this repository), `master@HEAD`.
**Audience:** anyone implementing an independent Elara verifier, light client, relay, or node in **any language**.

This document is the single language-agnostic entry point for re-implementing
Elara from scratch. It does **not** restate every byte layout in full — instead
it specifies the cryptographic primitives, the verification algorithms, and the
conformance requirements, and names the **authoritative source** for each layer.

> **Authority rule.** Where this document and the reference code disagree, **the
> code is authoritative and this document is the bug.** Every normative claim
> below names the source module that defines it. The byte layout of a
> `ValidationRecord` is additionally guarded by the round-trip test
> `test_wire_format_spec_locked` in `crates/elara-record/src/record.rs`.

> **Honest-claims rule.** Scale figures ("designed for N zones / records-per-day")
> are *design targets that shaped the architecture*, never measured throughput.
> Measured behaviour lives in `benches/` and the test suite. This spec
> distinguishes *Stable* (shipped, tested, wire-frozen) from *Design-stage*
> (specified, not yet enforced in consensus) in §11. Do not implement a
> Design-stage layer as if it were binding.

## Conformance conventions

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are
to be interpreted as in RFC 2119 / RFC 8174.

An implementation that satisfies the §12 checklist is a **conforming verifier**.
A conforming verifier can independently check that a record is authentic and that
an account balance is included under a sealed root, **without trusting any Elara
node and without network access** (given the record/proof bytes and the trusted
anchor key set).

All multi-byte integers are **big-endian** unless explicitly noted.

---

## 1. Overview

### 1.1 What Elara is

Elara is a post-quantum **validation mesh**: a network that produces
**offline-verifiable proofs** of *who recorded what, when, and — for the agent
layer — on whose authority*. Each `ValidationRecord` is dual-signed with two
independent post-quantum signature schemes and content-addressed. Records are
sharded into **zones**, ordered per-account by a slot **nonce**, and periodically
**sealed**: a zone's account state is committed to a 256-level Sparse Merkle Tree
whose root is signed by the zone's witness committee. A light client that pins the
genesis **anchor** key(s) can verify any account's state against a sealed root
with `O(log N)` proof data.

### 1.2 Layered architecture

| Layer | Purpose | This spec | Authoritative source |
|-------|---------|-----------|----------------------|
| L0 Crypto primitives | Hash + 2 PQ signatures | §2 (normative) | `src/crypto/` |
| L1 Identity | Key → identity binding | §3 (normative) | `crates/elara-record/src/record.rs`, `crates/elara-verify/src/lib.rs` |
| L2 Record | The signed unit of data | §4 (normative) | `crates/elara-record/src/record.rs`, `crates/elara-record/src/wire.rs` |
| L3 Record verification | Authenticity check | §5 (normative) | `crates/elara-verify/src/lib.rs`, `src/light_verify.rs` |
| L4 Account SMT | State commitment + proofs | §6 (normative) | `crates/elara-smt`, `src/network/account_merkle.rs` |
| L5 Seals & finality | Consensus output a client trusts | §7 (reference) | `src/network/epoch.rs`, `src/light_verify.rs` |
| L6 Zones & routing | Sharding | §8 (normative) | `src/network/zone.rs`, `src/network/consensus.rs` |
| L7 Beat conservation | Supply invariant | §9 (reference) | `docs/PROTOCOL-ECONOMICS.md` |
| L8 PQ transport | Encrypted peer sessions | §10 (reference) | `crates/elara-pq-transport` |

### 1.3 Implementation profiles

- **Offline verifier** (minimum): L0–L3. Checks record authenticity. This is what
  the shipped `elara-verify` CLI and the in-browser WASM widget do.
- **Light client**: + L4–L5. Verifies account inclusion against a sealed,
  anchor-signed root. No full ledger, no gossip.
- **Full node**: all layers + consensus participation. Out of scope for a *spec*
  conformance target; the reference implementation is `elara-runtime`.

### 1.4 Authoritative-source rule

Because this spec deliberately points at code rather than duplicating frozen byte
layouts (two normative documents that can drift apart is worse than one), a
conforming implementer SHOULD treat the named module as ground truth and use this
document as the map. Appendix B is the module index.

---

## 2. Cryptographic primitives

Elara uses exactly one hash function and two signature schemes. All are NIST
post-quantum standards (or, for SHA3, the standard hash underpinning them). No
other primitive participates in record authenticity.

### 2.1 Hash — SHA3-256 (FIPS 202)

Every hash in the authenticity path is **SHA3-256** (NIST FIPS 202), **not**
Keccak-256 and **not** SHA-2/BLAKE. Output is 32 bytes. Source: `crates/elara-record/src/hash.rs`.

Known-answer test (a conforming implementation MUST reproduce it):

```
SHA3-256("abc") = 3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532
```

### 2.2 Primary signature — ML-DSA-65 (FIPS 204, "Dilithium3")

| Parameter | Value |
|-----------|-------|
| Algorithm ID (`sig_algorithm`) | `0x01` |
| Public key length | **1952** bytes |
| Signature length | **3309** bytes (fixed) |
| Secret key length | 4032 bytes |

A conforming verifier MUST reject any primary signature whose length ≠ 3309 bytes
*before* attempting verification (`src/crypto/pqc.rs`). The 3309-byte gate also
rejects legacy 3293-byte OQS signatures from the pre-FIPS era.

### 2.3 Secondary signature — SLH-DSA-SHA2-192f (FIPS 205, "SPHINCS+")

| Parameter | Value |
|-----------|-------|
| Algorithm ID (`sphincs_algorithm`) | `0x02` |
| Public key length | **48** bytes |
| Signature length | **35664** bytes (fixed) |

Source: `src/crypto/pqc.rs`. Present only on **Profile A** records (§2.4).

### 2.4 Signature profiles

- **Profile A (dual-signed):** both ML-DSA-65 and SLH-DSA-SHA2-192f signatures are
  present. The canonical, defence-in-depth profile (two independent PQ hardness
  assumptions — lattice + hash-based). The shipped sample record is Profile A.
- **Profile B (Dilithium-only):** only the ML-DSA-65 signature is present.

**Wire consistency invariant (MUST):** the three SPHINCS+ fields
(`sphincs_signature`, `creator_sphincs_pk`, `sphincs_algorithm`) are
all-present-or-all-absent. A record with some-but-not-all MUST be rejected at
decode (`crates/elara-record/src/record.rs`). When `sphincs_signature` is present,
`sphincs_algorithm` MUST be `0x02`.

### 2.5 Domain separation

**v6+ (current emission): the signing preimage LEADS with an explicit domain
tag** — the ASCII constant `ELARA_RECORD_V1`, then a u16-BE-length-prefixed
`network_id`, then the §4.4 body (T63, flag day 2026-08-19). This makes a record
preimage structurally disjoint from every other signed context (witness
attestations carry their own leading tag; snapshot/seal checksums bind a
`sig_domain` selector). **v≤5 (historical records)**: no tag — the signed message
is exactly the §4.4 body, whose structure (id, version, nonce, content_hash,
key, …) is the scoping; those preimages are frozen forever by known-answer
tests. Domain separation also appears in the SMT (§6, tags `0x00`/`0x01`) and
in the transport layer (§10), which have their own preimages.

---

## 3. Identity

### 3.1 Derivation

An actor's identity is the SHA3-256 of its **primary** (ML-DSA-65) public key:

```
identity_hash = SHA3-256(creator_public_key)        // 32 bytes
identity_hex  = lowercase_hex(identity_hash)         // 64 chars, for display/API
```

Source: `crates/elara-record/src/record.rs`, `crates/elara-verify/src/lib.rs`, `crates/elara-record/src/hash.rs`. There is no
domain tag — the input is exactly the raw 1952-byte public key. The SPHINCS+ key
does **not** participate in identity derivation.

### 3.2 Binding

Because `creator_public_key` is part of `signable_bytes()` (§4.4), the identity is
transitively bound by the signature: a verifier that checks the signature has
also checked that this key signed this record, and the identity is just the hash
of that key.

`identity_hash_wire` is a **bandwidth optimization** for transports that can
supply the 32-byte hash out of band instead of the 1952-byte key: the receiver
resolves the full key from a local identity store. It is **not carried by the
binary wire codec** — the encoder never writes it and the decoder never reads it
(§4.3.1), so a from-the-bytes implementation will not encounter it. Wherever it
*is* supplied, a verifier MUST confirm
`SHA3-256(creator_public_key) == identity_hash_wire` once the key is resolved
(`crates/elara-verify/src/lib.rs`).

---

## 4. The ValidationRecord

### 4.1 Logical fields

| Field | Type | Notes |
|-------|------|-------|
| `id` | string | UUID v7 (time-ordered), 36 ASCII chars |
| `version` | u16 | Wire version, 1..=5 (current 5) |
| `content_hash` | 32 bytes | SHA3-256 of the payload the record attests to |
| `creator_public_key` | bytes | ML-DSA-65 PK (1952 bytes) |
| `timestamp` | f64 | Unix seconds, fractional |
| `parents` | string[] | DAG parent ids (≤ 256) |
| `classification` | u8 | §4.2 |
| `metadata` | map | UTF-8 key → JSON value, key-sorted |
| `signature` | bytes? | ML-DSA-65 signature (3309 bytes) |
| `sphincs_signature` | bytes? | SLH-DSA signature (35664 bytes, Profile A) |
| `creator_sphincs_pk` | bytes? | SLH-DSA PK (48 bytes, Profile A) |
| `sig_algorithm` | u8 | `0x01` |
| `sphincs_algorithm` | u8? | `0x02` (Profile A) |
| `zone` | string? | Explicit zone path (v3+) |
| `zone_refs` | bytes[] | Inter-zone causal refs, 24-byte opaque (≤ 256) |
| `itc_stamp` | bytes? | Interval Tree Clock (v2+) |
| `nonce` | u64 | Slot nonce (v5+), see §4.4 |
| `zk_proof` | bytes? | Required for PRIVATE classification |

### 4.2 Classification (u8)

| Value | Name | Status |
|-------|------|--------|
| `0` | PUBLIC | Stable — full content visible (minus ZK fields) |
| `1` | PRIVATE | Stable — commitment-only; `zk_proof` required at ingest |
| `2` | RESTRICTED | **Reserved** — byte allocated, enforcement not shipped |
| `3` | SOVEREIGN | **Reserved** — byte allocated, enforcement not shipped |

### 4.3 Wire encoding

The on-wire byte layout (8-byte header `"ELRA" + version + rec_type + reserved`,
then the field sequence, with `u8`/`u16`/`u32`-prefixed variable fields and
version-gated extensions) is fully specified by the reference codecs:

- **Authoritative:** `crates/elara-record/src/record.rs` (`to_bytes` / `from_bytes`) and `crates/elara-record/src/wire.rs`
  (length-prefix helpers + the v4+ binary metadata TLV).
- **Guard:** `test_wire_format_spec_locked` in `crates/elara-record/src/record.rs`.

A decoder MUST reject magic ≠ `"ELRA"`, any `version` outside the closed range
**[`WIRE_VERSION_MIN`, `WIRE_VERSION`] = [4, 7]**, unknown `rec_type` (≠ `0x01`),
and any length prefix that exceeds the §4.5 bounds. The range check is one
statement — `read_header` in `crates/elara-record/src/wire.rs` — and both ends
move only on a named flag day.

- **Floor = 4** (raised 1→4 on 2026-08-18). v1–v3 are **no longer decodable**:
  those versions carried metadata as a sorted compact-JSON blob that the
  encoder could no longer re-emit, so the read path and the JSON branch were
  deleted together in one commit rather than left as a silent round-trip
  corruption. No stored or frozen artifact is below v4.
- **Ceiling = 7.** Metadata is a binary TLV at v4+.

**v7 is the emission version as of the 2026-08-23 flag day**: fresh records
stamp `CURRENT_SIGNING_VERSION` (7). The two constants are deliberately split —
the fleet becomes decode-capable at a version everywhere before any node emits
it, so the ceiling is always raised in an earlier commit than the emission
version, never the same one.

Two flag days are folded into that range, and they are **not** alike:

- **v6 (emission 2026-08-19)** changed bytes. The wire extension appends a
  `u16`-prefixed ASCII `network_id` (≤64 bytes) after the v5 nonce, and the
  signing preimage prepends `ELARA_RECORD_V1` ‖ `u16`-BE length ‖ `network_id`
  before the §4.4 body (see §4.4). The committed v6 sample
  `examples/verify/sample-record-v6.wire` and the `record-hash-v6` /
  `signable-prefix-v6` conformance vectors pin both byte layouts.
- **v7 (emission 2026-08-23)** changed **no record bytes at all** — v7 wire
  bytes are shape-identical to v6, which is why the v6 sample still pins the
  layout and no separate v7 sample exists. The version is a *dispatch signal
  carried by the record*: it selects the Merkle fold recipe used for seals
  (§7.1). An implementation that decodes v6 correctly already decodes v7
  correctly; what it must additionally get right is the fold, not the parse.

#### 4.3.1 Field order (NORMATIVE)

Fields are emitted in exactly this order with no padding and no alignment.
`u8-len`/`u16-len`/`u32-len` mean a big-endian length prefix of that width
followed by that many bytes; all multi-byte integers are **big-endian**.

| # | Field | Encoding | Notes |
|---|-------|----------|-------|
| — | `magic` | 4 raw bytes | `"ELRA"` (0x45 0x4C 0x52 0x41) |
| — | `version` | `u16` | the record's own version, never the writer's ceiling |
| — | `rec_type` | `u8` | `0x01`; any other value MUST be rejected |
| — | `reserved` | `u8` | `0x00` |
| 1 | `id` | `u8-len` + UTF-8 | UUID v7 in text form (36 bytes) |
| 2 | `content_hash` | 32 raw bytes | **no** length prefix |
| 3 | `creator_public_key` | `u16-len` + bytes | ML-DSA-65 public key, 1952 bytes |
| 4 | `timestamp` | `f64` BE (8 bytes) | IEEE-754 binary64, Unix seconds |
| 5 | `parents` | `u16` count, then per parent: `u8-len` + UTF-8 | |
| 6 | `classification` | `u8` | §4.2 |
| 7 | `metadata` | binary TLV — see §4.3.2 | |
| 8 | `zk_proof` | `u32-len` + bytes | |
| 9 | `signature` | `u16-len` + bytes | ML-DSA-65 |
| 10 | `sphincs_signature` | `u16-len` + bytes | SLH-DSA |
| **v2+** | | | present in every decodable record (floor = 4) |
| 11 | `itc_stamp` | `u16-len` + bytes | |
| 12 | `zone_refs` | `u16` count, then per ref: **24 raw bytes** | zone `u64` ‖ sequence `u64` ‖ epoch `u64`, each BE |
| 13 | `creator_sphincs_pk` | `u16-len` + bytes | 48 bytes for Profile A |
| 14 | `sig_algorithm` | `u8` | §2.4 |
| 15 | `sphincs_algorithm` | `u8` | `0` when absent |
| **v3+** | | | |
| 16 | `zone_present` | `u8` | `0` or `1` |
| 17 | `zone` | present only if the flag is `1`: `u16-len` + UTF-8 path | |
| **v5+** | | | |
| 18 | `nonce` | `u64` BE (8 bytes) | slot mutual exclusion |
| **v6+** | | | |
| 19 | `network_id` | `u16-len` + ASCII | ≤64 bytes; the same value the §4.4 preimage commits to |

**Absent vs empty.** Every optional byte-string field above writes a zero length
prefix when absent, so a zero-length field and an absent field are the *same
bytes*. An implementation MUST treat length 0 as "absent" and MUST NOT invent a
distinction the wire cannot carry.

**`identity_hash_wire` is not a wire field.** §3.2 describes it as a bandwidth
optimization; in this codec it is never written by the encoder and never read by
the decoder (the struct field exists for the JSON representation only). The full
`creator_public_key` is always on the wire. A transport that supplies the hash
out of band still owes the §3.2 equality check.

#### 4.3.2 Metadata TLV (v4+)

`u16` entry count, then per entry a `u8-len` UTF-8 key followed by one value:

| Tag | Type | Value bytes |
|-----|------|-------------|
| `0` | null | *(none)* |
| `1` | bool | `u8` — `0` or `1` |
| `2` | int | `i64` BE |
| `3` | float | `f64` BE |
| `4` | string | `u16-len` + UTF-8 |
| `5` | array | `u16` count, then that many values (recursive) |
| `6` | object | `u16` count, then that many `u8-len` key + value pairs (recursive) |

A JSON number that fits `i64` MUST encode as tag `2`; otherwise as tag `3`.
Object keys — top-level and nested alike — are emitted in **ascending byte
order**, so two conforming encoders produce identical bytes for identical
content. Depth and count limits are in §4.5; a decoder MUST enforce them before
allocating.

### 4.4 `signable_bytes` — the signature preimage (NORMATIVE)

The bytes signed by **both** signature schemes are **not** the wire serialization.
They are the canonical subset produced by `signable_bytes()` (`crates/elara-record/src/record.rs`):

```
domain_tag          "ELARA_RECORD_V1"  (only if version >= 6 — LEADS the preimage)
network_id_len      u16 BE             (only if version >= 6)
network_id          ASCII bytes        (only if version >= 6; may be empty)
id                  UTF-8 bytes        (NO length prefix)
version             u16 BE
nonce               u64 BE             (only if version >= 5)
content_hash        32 bytes           (NO length prefix)
creator_public_key  raw bytes          (NO length prefix)
timestamp           f64 BE             (8 bytes)
num_parents         u16 BE
parents             UTF-8 bytes        (sorted lexicographically; NO per-parent prefix)
classification      u8
metadata_len        u32 BE
metadata_json       compact JSON       (sort_keys=true, separators=(",",":"))
zk_proof_len        u32 BE             (0 if absent)
zk_proof_bytes      payload            (if present)
```

**Critical invariants (MUST):**

1. The metadata in `signable_bytes` is always the **compact-JSON** form, even for
   v4+ records that carry binary-TLV metadata on the wire. Signatures are
   format-stable across the v3→v4 metadata migration.
2. `parents` are **sorted** for signing but preserved in creator order on the
   wire. A relay re-sorting parents on the wire does NOT invalidate the signature.
3. `itc_stamp`, `zone_refs`, `zone`, the SPHINCS+ fields, `sig_algorithm`,
   `sphincs_algorithm`, `identity_hash_wire`, and `signature` itself are **never**
   in `signable_bytes`. Nodes may attach or rewrite them without breaking the
   creator's signature.
4. v4→v5: a v4 record has `nonce == 0` and is signed **without** the nonce field;
   a v5 record always includes the nonce in `signable_bytes` regardless of value.
5. v6 domain separation (T63/T65, defined 2026-08-18): for `version >= 6` the
   preimage is PREFIXED with the constant tag `ELARA_RECORD_V1` + the
   length-prefixed `network_id`, making record signatures a distinct domain
   from every other Elara signing context (witness attestations, snapshot /
   seal / veto checksums) and binding the emitting network into the signed
   payload (MESH-BFT A8). v≤5 preimages are byte-identical to the previous
   revision of this spec — pinned by frozen KAT vectors
   (`crates/elara-record/tests/kat/`).

The record's content-address (`record_hash`) is `SHA3-256(signable_bytes())`.

### 4.5 Size bounds

| Bound | Value | Source |
|-------|-------|--------|
| `MAX_RECORD_BYTES` | 65,536 (64 KiB) | `src/network/ingest.rs` |
| Max parents | 256 | `crates/elara-record/src/record.rs` |
| Max zone_refs | 256 | `crates/elara-record/src/record.rs` |
| Max metadata entries | 64 admitted at ingest / 256 wire-decode bound | `src/network/ingest.rs` (64) · `crates/elara-record/src/wire.rs` (256) |
| Max metadata nesting depth | 8 | `crates/elara-record/src/wire.rs` |
| Max metadata JSON (v1–v3) | 102,400 (100 KiB) | `crates/elara-record/src/wire.rs` |

A conforming decoder MUST enforce these *before* allocating from a length prefix
(length-gate-before-alloc), so a malformed frame cannot drive an unbounded
allocation.

---

## 5. Record verification (NORMATIVE)

A conforming offline verifier performs the following ordered steps
(`crates/elara-verify/src/lib.rs`, `src/light_verify.rs`). Any failure ⇒ the record is
**not verified**.

1. **Decode** the wire bytes (§4.3). Reject on bad magic, unsupported version,
   unknown `rec_type`, or any bound violation.
2. **Profile consistency** (§2.4): the three SPHINCS+ fields are
   all-present-or-all-absent; if a primary `signature` is present,
   `sig_algorithm == 0x01`; if `sphincs_signature` is present,
   `sphincs_algorithm == 0x02`.
3. **Identity binding** (§3.2): if the record carries `identity_hash_wire`, resolve
   the full `creator_public_key` and confirm `SHA3-256(creator_public_key) ==
   identity_hash_wire`. (v1–v3 records carry the full key inline; no check needed.)
4. **Reconstruct `signable_bytes`** (§4.4) from the decoded fields — same field
   order, same sorting, same compact-JSON metadata.
5. **Primary signature (MUST):** verify the 3309-byte ML-DSA-65 `signature` over
   `signable_bytes` with `creator_public_key`. Absent or invalid ⇒ fail.
6. **Secondary signature (Profile A, MUST):** if `sphincs_signature` and
   `creator_sphincs_pk` are present, verify the 35664-byte SLH-DSA signature over
   the *same* `signable_bytes` with `creator_sphincs_pk`. Invalid ⇒ fail. (Both
   absent ⇒ Profile B, acceptable.)
7. **Content binding (optional):** if the original payload bytes are supplied,
   confirm `SHA3-256(payload) == content_hash`.

Steps 5 and 6 both sign the identical preimage; an implementation MUST NOT sign
`content_hash` or `record_hash` directly.

This algorithm establishes **authenticity** (this key signed this record) and
**integrity** (the content matches), but NOT inclusion, finality, or anchor trust
— those require §6–§7.

---

## 6. Account state & the Sparse Merkle Tree (NORMATIVE)

Each zone commits its account state to a **256-level key-addressed Sparse Merkle
Tree**. Sources: `crates/elara-smt` (the pure engine, a standalone MIT/Apache
crate) and `src/network/account_merkle.rs` (the protocol binding).

### 6.1 Structure

- The tree is **256 levels** deep. A key's leaf **position** is the full
  `SHA3-256(key)` (256 bits, MSB-first by depth). Using the full digest as the
  path (rather than a truncation) prevents an attacker from manufacturing a
  position collision to substitute one honest account's leaf for another.
- Single hash primitive throughout: **SHA3-256**.

### 6.2 Node hashing (domain-separated)

```
leaf hash     = SHA3-256( 0x00 ‖ key ‖ value )      // LEAF_TAG = 0x00
interior hash = SHA3-256( 0x01 ‖ left ‖ right )      // NODE_TAG = 0x01
empty subtree = SHA3-256("")                          // EMPTY_HASH sentinel
```

The distinct `0x00`/`0x01` tags mean a leaf preimage can never be reinterpreted as
an interior-node preimage (second-preimage hardening). An empty subtree (no
populated leaves beneath it) collapses to the single `EMPTY_HASH` sentinel.

### 6.3 Account leaf binding

For the account SMT:

```
key   = account_id                                   // the account's identity bytes
value = hash_account_state(account)                  // SHA3-256 over every balance field
```

`hash_account_state` (`src/network/account_merkle.rs`) is sensitive to **every**
field of the account (available balance, staked, tx_count, last_active, …) — a
test (`hash_account_state_is_sensitive_to_every_field`) pins this so a refactor
cannot silently drop a field and let two distinct states share a leaf.

### 6.4 Compressed inclusion proof + verification

A proof for "key K maps to value V under root R" carries:

- a **256-bit presence bitmap** (`present`, MSB-first by parent depth): bit `d`
  set ⇒ the sibling at depth `d` is non-empty and **present in the sibling list**;
  bit `d` clear ⇒ the sibling is `EMPTY_HASH` and is **omitted**;
- the **sibling list**: only the non-empty siblings, ordered **from the leaf's
  parent (depth 255) up to the root (depth 0)** — **deepest-first (fold
  order)**, i.e. by *descending* parent depth, the order the fold consumes them in (≈ `log₂(N)` entries, never more
  than 256). This is the one place an independent implementation is most likely
  to diverge: a root-first list folds to a different root and every proof fails.

Verification (`verify_proof` in `crates/elara-smt`):

1. Compute the leaf hash from `K` and `V` (§6.2).
2. Derive the 256-bit path from `SHA3-256(K)`.
3. Fold from depth 255 up to the root: at each depth, the sibling is the next
   entry from the list if `present` bit is set, else `EMPTY_HASH`; order the two
   children by the path bit (path bit set ⇒ the running value is the *right*
   child) and combine with the interior-node rule (§6.2) — **except** when both
   children are `EMPTY_HASH`, in which case the parent is `EMPTY_HASH` itself,
   **not** `interior_hash(EMPTY_HASH, EMPTY_HASH)`. This exception is the
   §6.2 empty-subtree collapse expressed as a folding rule; it is normative, and
   it is what makes a proof whose path crosses an empty region verify at all.
4. Every entry of the sibling list MUST have been consumed exactly once. A proof
   that folds to the right root while leaving siblings unread MUST be rejected —
   otherwise a valid proof can be padded with arbitrary trailing entries and
   stays valid, which is proof malleability.
5. The folded result MUST equal the claimed root `R`.

A conforming light client MUST bound the deserialized sibling list to 256 entries
*before* folding, to prevent a deserialize-time amplification from a malformed
proof. Vectors `smt-proof/bob-in-abc` and `smt-proof-reject/bob-tampered-sibling`
in `examples/verify/conformance-vectors.json` pin the accept and the reject.

### 6.5 Exclusion (non-membership) proofs

The same compressed shape proves a key is **absent**. An exclusion proof carries
the key, the root, the presence bitmap and the sibling list, but no value; the
verifier folds `EMPTY_HASH` at the leaf position instead of a leaf hash and
requires the result to equal `R` (`verify_exclusion_proof` in `crates/elara-smt`;
the fold, including the empty-collapse rule of §6.4 step 3, is bit-for-bit the
same routine as inclusion).

This is a **cryptographic** non-membership proof, not a trust-the-server
assertion: the path is the full 256-bit `SHA3-256(K)`, so an absent key's slot is
genuinely empty and no other key can occupy it. A verifier that can prove absence
can answer "this record does not exist" without trusting the responder — which is
the property a light client needs to detect withholding.

---

## 7. Epoch seals & finality (reference)

> **Status: Stable in code; specified here at reference level.** The exact seal
> byte layout is authoritative in `src/network/epoch.rs` / `src/light_verify.rs`;
> a future revision of this spec will inline it. The trust *model* below is
> binding for a light client.

A **seal** finalizes a zone's state for an epoch. It binds (among other fields)
the zone, the epoch number, and the zone's **`account_smt_root`** (§6), and is
signed by the zone's witness committee. The genesis **anchor** key(s) form the
root of trust a light client pins.

### 7.1 Merkle fold recipe is versioned per seal (NORMATIVE)

A seal's record tree is folded with one of two recipes, selected by **that
seal's own signed wire version** — never by the verifier's build, and never by a
global switch:

| Seal version | Recipe | Interior preimage |
|--------------|--------|-------------------|
| ≤ 6 | v1 (bare) | untagged concatenation, as originally shipped |
| ≥ 7 | v2 (tagged) | domain-tagged: `ELARA_SEAL_MERKLE_NODE_V1` for the zone record tree, `ELARA_SUPER_SEAL_MERKLE_NODE_V1` for the super-seal tree, and a distinct committee interior tag |

The threshold is the constant `FOLD_V2_MIN_WIRE_VERSION` (= 7) in
`crates/elara-record/src/wire.rs`; every fold site — producer, committee hasher,
proof builder, parse gate — derives it from that one constant so the ungated and
the consensus paths cannot disagree.

Two consequences bind an implementer:

1. **Pre-flip seals never migrate.** A seal stamped ≤6 folds bare v1 *forever*,
   including when it is re-verified years later by a v7-only client. Dispatch is
   per seal, so a client MUST keep both recipes.
2. **The mismatch fails closed.** A v1 proof presented against a v2 root, or the
   reverse, does not verify — it is rejected, not silently accepted. Vectors
   `seal-merkle-fold-v2/tagged-roots`, `seal-merkle-inclusion-v2/proof-walk`,
   `seal-merkle-inclusion-v2-reject/v1-proof-vs-v2-root` and
   `seal-merkle-inclusion-v2-reject/v2-proof-vs-v1-root` pin all four corners.

**Light-client trust chain** (the property a conforming light client establishes):

1. Pin the trusted anchor public key(s) out of band (genesis material).
2. Obtain a seal for the target zone+epoch; verify its signature chains to a
   trusted anchor (directly, or via a checkpoint / super-seal whose coverage is
   re-verified against per-epoch `seal_record_hash`).
3. Verify the account inclusion proof (§6.4) against the **`account_smt_root`
   carried in that verified seal** — not against a root reported by an untrusted
   RPC.

Optimistic **"Sealed"** state (one anchor signature, surfaced in a few seconds) is
distinct from **"Finalized"** (≥ 2/3 committee attestation). A client that needs
full finality MUST wait for the attestation threshold, not the first signature.
See `docs/MESH-BFT-MERGE-SEMANTICS.md` for partition/merge semantics.

The shipped `elara-verify` tool implements anchor / seal / inclusion /
account-inclusion verification modes; see `docs/ELARA-VERIFY.md`.

---

## 8. Zones & routing (NORMATIVE)

Records are sharded into zones. The default routing is deterministic and
content-addressed:

```
zone_index = SHA3-256(record_id) mod zone_count
```

Source: `src/network/zone.rs`, `src/network/consensus.rs`. `zone_count` is
**consensus-critical topology**: every node MUST agree on it, because it changes
which zone (and thus which committee + seal) a record belongs to. It is mutated
only by **signed `ZoneTransition` records** anchored by the genesis authority at a
future `target_epoch` (a dispute-free migration window), never by local config
divergence. v3+ records MAY also carry an explicit hierarchical `zone` path; when
absent, the zone is derived by the formula above.

---

## 9. Beat conservation (reference)

Elara's internal accounting unit (the *beat*; 1 beat = 10⁹ base units) obeys a
fixed-supply conservation invariant:

```
Σ balances + Σ staked + Σ cross_zone_locked + conservation_pool = total_supply
```

Supply is minted once at genesis (no ongoing emission). The invariant is enforced
on every state transition. Full economic model, genesis allocation, and the
cross-zone locked-value accounting: **`docs/PROTOCOL-ECONOMICS.md`** (mirror) and
`docs/EARN-IN-ECONOMY.md`. Cross-zone settlement is async-optimistic (not 2PC);
see `src/accounting/cross_zone.rs`.

---

## 10. PQ transport (reference)

Peer sessions run over an authenticated, post-quantum, encrypted channel. The
frame format and handshake are specified by the standalone
**`crates/elara-pq-transport`** crate (no protocol dependencies):

- Frame header: 9 bytes — magic `"ELPQ"` + version + type + 3-byte length.
- Handshake: Noise-XX-style mutual auth with a hybrid suite — ML-DSA-65 (identity
  auth) + ML-KEM-768 + X25519 (key agreement).
- Session: HKDF-SHA256 key schedule, ChaCha20-Poly1305 AEAD with per-direction
  keys, transcript-bound.

Record authenticity (§5) does **not** depend on the transport: a record verifies
identically whether fetched over PQ transport, plain HTTP, or read from disk. The
transport protects the *channel*; the signatures protect the *record*. Browser
clients tunnel ELPQ frames over a `/pq-ws` WebSocket.

---

## 11. Layer status — Stable vs Design-stage

| Layer | Status | Notes |
|-------|--------|-------|
| L0 crypto, L1 identity | **Stable** | FIPS-pinned; const-pinned by tests |
| L2 record / L3 verification | **Stable** | Wire v4–v5 frozen + v6 defined (decode-required, emission flag-day-gated); v1–v3 decode retired 2026-08-18 (`WIRE_VERSION_MIN`=4); round-trip guarded |
| L4 account SMT + proofs | **Stable** | 256-level; standalone crate; tested |
| L5 seals / finality | **Stable (code)** | Trust model binding; byte layout = code |
| L6 zones / routing | **Stable** | Signed transitions; consensus-critical |
| L7 conservation | **Stable** | Invariant enforced each transition |
| L8 PQ transport | **Stable** | Standalone crate, KAT-tested |
| Agent mandates (v0) | **Observational** | Flag computed, NOT consensus-weighted (`docs/AGENT-DELEGATION.md`) |
| Agent mandates (v1 enforcement) | **Design-stage** | Multi-validator-gated; op/zone scope-taxonomy not yet ratified |
| Protocol upgrade enforcement | **Design-stage** | Tally + state machine exist (`src/network/protocol_upgrade.rs`); not wired to consensus |
| RESTRICTED / SOVEREIGN class | **Reserved** | Bytes allocated; no enforcement |
| Realms / self-assembly | **Design-stage** | `docs/REALMS-SELF-ASSEMBLY.md` |

A conforming implementation MUST NOT treat a Design-stage / Reserved layer as
binding consensus behaviour.

---

## 12. Conformance checklist

A **conforming offline verifier** MUST:

1. Reproduce the SHA3-256 KAT (§2.1).
2. Decode v4–v6 records (`WIRE_VERSION_MIN`=4 .. `WIRE_VERSION`=6) and reject
   bad magic / out-of-range version / `rec_type` / bound violations,
   length-gating before allocation (§4.3, §4.5).
3. Enforce the SPHINCS+ all-or-nothing profile invariant (§2.4).
4. Reconstruct `signable_bytes` exactly per §4.4 (BE integers, sorted parents,
   compact-JSON metadata even at v4+, v5 nonce placement, v6 domain-tag +
   `network_id` prefix).
5. Verify the 3309-byte ML-DSA-65 signature over `signable_bytes`, after a
   strict length gate (§2.2, §5).
6. Verify the 35664-byte SLH-DSA signature over the same preimage when present
   (Profile A), and accept Profile B when both SPHINCS+ fields are absent (§2.3,
   §5).
7. Check `identity_hash_wire` against `SHA3-256(creator_public_key)` when present
   (§3.2).

A **conforming light client** MUST additionally:

8. Verify SMT inclusion proofs by folding compressed siblings with the
   domain-separated leaf/interior/empty rules (§6), bounding the sibling list to
   256 before folding.
9. Verify account inclusion against the `account_smt_root` carried in an
   **anchor-trusted seal**, never a root reported by an untrusted RPC (§7).
10. Distinguish optimistic *Sealed* from *Finalized* (≥ 2/3 attestation) (§7).

A conforming implementation SHOULD emit at the latest wire version, preserve
`parents` order on relay, and treat `zone_refs` entries as opaque 24-byte blobs.

---

## Appendix A — Test vectors

These let an independent implementation self-check without a running node.

**A.0 Machine-readable conformance set** —
[`examples/verify/conformance-vectors.json`](../examples/verify/conformance-vectors.json)
is a single language-agnostic file of `{input → expected}` vectors covering every
deterministic primitive below: SHA3-256, the account-SMT empty/leaf/interior
hashing and the full 256-level inclusion-proof fold (§6.2), identity derivation
(§4.3), record-hash binding (§4.4), and the *second*, domain-tag-free zone
record-membership Merkle proof (`merkle-inclusion` and its must-reject twin,
A.4.1) — plus an ML-DSA-65 (FIPS 204) signature
verification KAT (`mldsa65-sig` and its must-reject twin, A.6), the
light-client account-proof → signed-header binding (`account-binding` and its
must-reject twin, A.7), and the epoch-seal anchor-signature trust root
(`seal-anchor-sig` and its must-reject twin, A.8) — a real anchor-signed seal
verified against a caller-pinned anchor key. Every
value is **derived from the reference implementation** (Appendix B), not
hand-written, and is pinned against the code by unit tests
(`conformance::tests::committed_conformance_vectors_match_authoritative_derivation`,
`mldsa65_signature_vector_verifies_and_reject_is_rejected`,
`account_binding_reject_vector_rejects_valid_proof_against_wrong_root`, and
`seal_anchor_sig_vector_verifies_and_reject_is_rejected`)
that fail CI if a recipe ever changes without regenerating the file — so
the vectors cannot silently drift from the spec. An implementation in any language
can iterate the array and self-check the hash primitives with no Rust, no node, and
no network; the four ML-DSA-65 signature vectors (A.6, A.8) additionally require a
FIPS 204 verifier. The pure-stdlib `verify_conformance.py` size-pins those four;
`verify_pq.py` (`verify.sh` leg 0c) then verifies them for real against **liboqs**
(the Open Quantum Safe reference C library — a second FIPS 204 implementation,
independent of the Rust generator), accepting each valid signature and rejecting
each must-reject twin, and skipping transparently when no PQ library is present.
Regenerate with `cargo run --example gen_conformance_vectors`.

A **separate, verdict-level vector family** covers the offline mandate-bundle
judge: `examples/verify/mandate-bundle-{valid,post-revocation,agent-mismatch,
act-tampered,scope-deferred}.json` — five frozen, real-chain-harvested signed
bundles whose expected verdicts (including the `scope_deferred` positive/negative
pair) are pinned by
`mandate_bundle_tests::committed_mandate_bundle_vectors_pin_their_verdicts`.
These are not byte-primitive KATs (that is this appendix's A.0 set); they pin the
`evaluate_mandate_bundle` verdict surface end-to-end. The prose vectors
A.1–A.8 below are the same primitives in human-readable form.

**A.1 SHA3-256 KAT**

```
SHA3-256("abc") = 3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532
SHA3-256("")    = EMPTY_HASH sentinel (the account-SMT empty-subtree value, §6.2)
```

**A.2 `signable_bytes` field order** — §4.4 is itself the canonical recipe; an
implementation that produces a different byte string for the same logical record
will fail signature verification.

**A.3 Sample record (Profile A, dual-signed)** —
`examples/verify/sample-record.json`. A real harvested record with both ML-DSA-65
and SLH-DSA signatures. Running the verification algorithm (§5) over it MUST yield
**verified**; flipping a single byte of `content_hash` MUST yield **failed** at
the primary-signature step (this is exactly what the in-browser
`browser-node/verify-demo/` widget demonstrates).

**A.4 Sample sealed account proof** — `examples/verify/account-proof.json` and the
binary seal `examples/verify/epoch-41340-zone-0.seal.wire` exercise the §6–§7 light
-client path. The machine set's self-contained `smt-proof` vector folds a
compressed inclusion proof to its root with no binary artifacts — the §6.2
256-level traversal (path = SHA3-256(key), MSB-first, empty-subtree collapse) in
isolation, the single step a light-client implementer is most likely to get wrong.
Its `smt-proof-reject` twin is the same proof with one sibling byte flipped: a
conforming fold MUST NOT reconstruct the sealed root, so the set certifies
*fail-closed* rejection cross-language — not just happy-path acceptance — and an
implementation that still accepts it admits a forged account-state proof.

**A.4.1 Record-inclusion Merkle proof (the second tree)** — the machine set's
`merkle-inclusion` vector folds a record-membership inclusion proof in the *zone
record-membership* Merkle tree (`network::merkle`, §11.22.1) — the cross-zone
settlement-evidence path, and exactly the proof `elara-verify --inclusion`
checks against a sealed root. This is a **distinct** tree from the account-SMT of
A.4, and the difference is the trap: it carries **no domain tags**. The leaf is
the record hash verbatim (the A.3 / `record-hash` value, so the vectors chain),
and an interior node is `SHA3-256(left ‖ right)` — *not* the account-SMT's
`SHA3-256(0x00 ‖ …)` / `SHA3-256(0x01 ‖ …)`. Sibling order is explicit per node
(`is_right`), not derived from a key path. Fold bottom-up: `current =
SHA3-256(current ‖ sibling)` when the sibling is on the right, else
`SHA3-256(sibling ‖ current)`; the final value MUST equal the sealed root. Its
`merkle-inclusion-reject` twin flips one sibling byte — a conforming fold MUST
NOT reconstruct the sealed root, certifying *fail-closed* rejection of forged
cross-zone inclusion evidence cross-language. An implementer who (wrongly) reuses
the account-SMT's tagged recipe here gets a different root: that is the mistake
this vector exists to catch.
(Scope note, wire v7: "no domain tags" is a property of *this* tree — the zone
record-membership tree — and stays true by design; its vectors are frozen.
From wire v7 the *epoch-seal* record tree, the super-seal tree, and the
committee tree fold with interior domain tags (`ELARA_SEAL_MERKLE_NODE_V1`,
`ELARA_SUPER_SEAL_MERKLE_NODE_V1`, `ELARA/COMMITTEE_NODE/v1`), dispatched
per-seal by the seal record's own signed wire version — pre-v7 seals fold
bare v1 forever. See the `seal-merkle-fold-v2` vector family. Do not read
this section as "Elara inclusion proofs carry no tags in general.")

**A.5 Identity derivation** — `identity_hash = SHA3-256(creator_public_key)`;
take the `creator_public_key` from A.3, hash it, and compare to the record's
derived identity.

**A.6 ML-DSA-65 (FIPS 204) signature verification** — the machine set's
`mldsa65-sig` vector is a post-quantum signature KAT for the anchor-signature
primitive. The keypair is derived deterministically from a pinned 32-byte seed
(`0x00..0x1f`), so `public_key` is reproducible; feed `(public_key,
message_ascii, signature)` to a FIPS 204 ML-DSA-65 `Verify` with an **empty
context string** and it MUST return accept. Its `mldsa65-sig-reject` twin is the
same key and message with one signature byte flipped — `Verify` MUST reject it;
an implementation that accepts it is fail-open (it would admit a forged anchor
signature). Because ML-DSA-65 signing is randomized (FIPS 204 hedged), the vector
pins **one** valid signature and the conformance surface is *verification*, not
signature reproduction — a conforming signer produces a different but equally
valid signature for the same key and message. Unlike A.1–A.5 this vector needs a
PQ verifier: the pure-stdlib `verify_conformance.py` size-pins it (public key
1952 bytes, signature 3309 bytes) and defers the cryptographic check, while
`verify_pq.py` (`verify.sh` leg 0c) runs it against liboqs ML-DSA-65 — a second,
non-Rust FIPS 204 implementation that must accept the valid signature and reject
the byte-flipped twin.

**A.7 Account-proof → signed-header binding** — the light-client *keystone* the
per-tree fold vectors (A.4, A.4.1) leave un-pinned. `smt-proof` certifies a proof
folds to *its own* claimed root; but a sound light client must **also** bind that
folded root to the `account_smt_root` the trusted, anchor-signed epoch header
commits to (§11.22). The machine set's `account-binding` vector pins exactly this
two-level check: fold the proof to a root, **then** accept iff that root equals
`header_account_smt_root`. `expected` is the boolean verify result (`"true"`), not
a hash. Its `account-binding-reject` twin is the same **perfectly valid** proof
(it still folds cleanly to its own root) bound to a header signing a *different*
root — `Verify` MUST return `"false"`. This is the fail-open class the per-tree
`*-reject` folds cannot catch: there the fold is broken; here the fold is valid
and only the context (which header signs the root) is wrong. An implementation
that trusts `proof.root` without binding it to the signed header admits a forged
account balance from a Byzantine server. Derived from the authoritative
`elara_light_client::verify_account_proof_against_header`, so the published
boolean cannot drift from the verifier real SDK clients call. Being a pure
equality-and-fold check, it is fully reproducible in any language with no PQ
library (the stdlib `verify_conformance.py` recomputes both the accept and the
reject decision).

**A.8 Epoch-seal anchor-signature — the trust ROOT** — the keystone everything
above stands on. A.4 / A.4.1 / A.7 prove a proof folds to the `account_smt_root`
(or zone root) a header commits to — but *why* trust that header's root? Because
an anchor signed the epoch seal that carries it. The machine set's
`seal-anchor-sig` vector pins exactly that closure over a **real** anchor-signed
seal — `examples/verify/epoch-41340-zone-0.seal.wire`, the very epoch the A.7
binding consumes: decode it per §4, confirm `record_hash == seal_record_hash`,
require `creator_public_key == trusted_anchor_public_key` (the committed
`examples/verify/zone-0-anchor-pubkey.hex`), rebuild the §4.4 `signable_bytes`,
and run FIPS 204 ML-DSA-65 `Verify` over them with an **empty context string** —
accept iff all hold (`expected = "true"`). Unlike A.6 the signed message is not an
arbitrary string but the seal's *own* §4.4 preimage, so this is the one vector
binding the post-quantum signature primitive to the actual seal whose
`account_smt_root` the A.7 vector trusts — record decode, PQ verify and
anchor-pinning composed into a single trust-anchor check. Its
`seal-anchor-sig-reject` twin is the same **perfectly valid** seal pinned to a
*different* anchor key: `Verify` must return `"false"` at the anchor-membership
check, because the seal is signed by a key the caller never pinned. Unlike A.6's
reject twin (a tampered signature) the signature here is valid — only the trusted
context is wrong; an implementation that accepts it is fail-open, trusting a seal
from an unpinned key (the catastrophic trust-root break). Derived from the
authoritative `light_verify::verify_seal_record_against_anchor` — the Gap-1
light-client trust closure real SDK clients call. It needs a FIPS 204 verifier, so
`verify_conformance.py` size-pins the anchor key (1952 bytes) and the seal wire
hash and defers the cryptographic check; two independent verifiers then run it end
to end — the Rust test `seal_anchor_sig_vector_verifies_and_reject_is_rejected`,
and the non-Rust `verify_pq.py` (`verify.sh` leg 0c), which rebuilds the seal's
§4.4 preimage via `decode_record.py`, applies the anchor-trust gate, and verifies
the signature against liboqs ML-DSA-65 — accepting the valid seal and rejecting
the wrong-anchor twin.

## Appendix B — Authoritative source map

| Module | Defines |
|--------|---------|
| `crates/elara-record/src/hash.rs` | SHA3-256 |
| `src/crypto/pqc.rs` | ML-DSA-65 + SLH-DSA-SHA2-192f params + verify |
| `crates/elara-record/src/record.rs` | `ValidationRecord`, `to_bytes`/`from_bytes`, `signable_bytes`, `record_hash` |
| `crates/elara-record/src/wire.rs` | length-prefix codecs, v4+ binary metadata TLV |
| `crates/elara-verify/src/lib.rs` | record verification algorithm (`verify_record`) |
| `src/light_verify.rs` | seal-against-anchor + inclusion verification |
| `crates/elara-smt` | 256-level Sparse Merkle Tree engine + `verify_proof` |
| `crates/elara-light-client` | pure wasm-portable light-client core: `verify_proof`, `verify_account_proof_against_header` (the A.7 binding), state-delta seal binding |
| `src/network/account_merkle.rs` | account leaf binding, `hash_account_state` |
| `src/network/merkle.rs` | zone record-membership Merkle tree (no domain tags) + cross-zone proof `verify_proof` |
| `src/network/epoch.rs` | epoch seal construction |
| `src/network/zone.rs`, `consensus.rs` | zone routing, `zone_count` authority |
| `crates/elara-pq-transport` | ELPQ frame + hybrid handshake |

## Appendix D — Independent implementations

An implementation written from this document *alone* is the only real test of
whether the document says what the code does. Results are recorded here as they
arrive.

- **2026-09-06 — `elara_reader.py`**, an independent reader of the Appendix A
  vector set by **Noûs**, an AI agent operating for
  [@robertolocatelli81-dev](https://github.com/robertolocatelli81-dev), written
  from this spec's text with the reference implementations unopened
  ([reader](https://github.com/robertolocatelli81-dev/ap2-evidence-pack/blob/master/interop/elara_reader.py),
  [report](https://github.com/google-agentic-commerce/AP2/issues/338#issuecomment-5560133862)).
  **21 of 25 vectors byte-agreed**, including both ML-DSA-65 vectors verified
  against a third FIPS 204 implementation, and the v7 tagged seal fold deduced
  from the A.4.1 scope note alone. The 4 remaining vectors were the ones needing
  the wire layout, which §4.3 then deferred to code — that gap is closed by
  §4.3.1, and the §6.4 sibling-order ambiguity they isolated (one reading out of
  96 enumerated) is fixed in that section. Both findings were theirs.

## Appendix C — References

In-repository (also in the public mirror): `docs/ELARA-VERIFY.md`,
`docs/api.md`, `docs/PROTOCOL-ECONOMICS.md`, `docs/AGENT-DELEGATION.md`,
`docs/MESH-BFT-MERGE-SEMANTICS.md`.

Standards: FIPS 202 (SHA3), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), RFC 2119 /
RFC 8174 (conformance keywords), RFC 9562 (UUID v7).
