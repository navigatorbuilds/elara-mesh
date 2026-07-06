# Offline verification sample — check us, don't trust us

These are **real artifacts from the Elara testnet**. You can verify them on a
laptop with **no node, no network, and no trust in the people who run Elara**.
This directory is the "show, don't tell" — clone the repo, build one small
binary, and confirm two things for yourself:

1. **A record was authentically signed** (post-quantum, dual signature), and
2. **An epoch seal sits in a trustless time bracket** — a drand not-before
   (BLS-verified) below, a Bitcoin existed-by above.

Nothing here phones home. The anchor check makes **zero network syscalls** — it
reads an archived Bitcoin block header shipped right next to the proof.

## Build the verifier

`elara-verify` is a standalone binary; it pulls in none of the node stack — and
builds with **only a Rust toolchain**: no C compiler, no `cmake`, no `liboqs`.
Every primitive it needs is pure Rust (ML-DSA-65 verify, SLH-DSA verify, and the
drand BLS12-381 check), so a fresh `rustup` install is the only prerequisite.

```bash
cargo build --release --features verify-cli --bin elara-verify
V=target/release/elara-verify
```

Or just run `./examples/verify/verify.sh` from the repo root, which builds it
for you and runs every check below.

## Optional — make the independent second-language legs run too

`verify.sh` opens with legs **0–0e**: the same facts re-checked in a *second
language* (Python), so you are not trusting the Rust reference implementation
either. Leg **0** (the deterministic primitives) and leg **0b** (the wire
decoder) are pure-stdlib and **always run**. The three *cryptographic* legs need
a library the Python stdlib does not ship, so out of the box they **skip
transparently** (never a fake green) and you only see the Rust legs prove those
bounds:

| Leg | Proves, with no Rust | Needs |
|-----|----------------------|-------|
| 0c  | ML-DSA-65 (FIPS 204) signatures — accepts the valid, rejects the forged | `liboqs-python` |
| 0d  | the **Bitcoin existed-by** upper bound of the time bracket | `opentimestamps` |
| 0e  | the **drand not-before** lower bound of the time bracket | `py_ecc` |

To make them *run* — i.e. reproduce **both ends of the trustless time bracket and
the post-quantum signatures in a toolchain with zero Elara code** — install those
libraries. Modern distros (PEP 668) refuse `pip install` into the system Python,
so use a throwaway venv right here; `verify.sh` auto-detects it and routes the
Python legs through it:

```bash
python3 -m venv examples/verify/.venv

# legs 0d + 0e — both bracket ends, pure-Python, installs in seconds:
examples/verify/.venv/bin/pip install opentimestamps py_ecc

# leg 0c — independent PQ verification. The first import builds/fetches the
# native liboqs C library, so this one also needs cmake + a C compiler:
examples/verify/.venv/bin/pip install liboqs-python

./examples/verify/verify.sh        # now runs all five independent legs
```

The venv is local only — `.gitignore`d and excluded from the published mirror.
Install just the light tier and leg 0c still skips honestly; install nothing and
the Rust legs below remain the reference. No combination ever fakes a pass.

## 1. The record — *who signed this?*

```bash
$V examples/verify/sample-record.wire --wire
```

`sample-record.wire` is one record in its canonical wire form, exactly as the
mesh stores it. The verifier confirms the embedded public key hashes to the
identity it claims, the **Dilithium3 (ML-DSA-65)** signature is valid over the
canonical bytes, and — this record being Profile A — the second **SPHINCS+
(SLH-DSA)** signature too. Expected verdict: `VERIFIED`.

The record's own timestamp is only the creator's *claim*. For trustless time,
use the anchor.

## 2. The anchor — *when did it provably exist?*

```bash
$V --anchor examples/verify/epoch-3217-zone-0.json
```

`epoch-3217-zone-0.json` is an epoch-anchor artifact. It carries the drand
beacon round **and the beacon's BLS signature**, so the not-before is verifiable,
not just cited. Beside it are the proofs it needs, all offline:

| File | What it proves |
|------|----------------|
| `epoch-3217-zone-0.json.ots`    | OpenTimestamps: a SHA-256 path committing the seal into a **Bitcoin block's** merkle root |
| `btc-header-953657.txt`         | the archived 80-byte header of that block — so the existed-by check needs no Bitcoin node and no calendar server |
| `epoch-3217-zone-0.json.tsr`    | an RFC-3161 timestamp token — an *independent* TSA witness, **not checked by `elara-verify`** (verify separately with `openssl ts -verify`) |
| `epoch-3217-zone-0.json.qtsr`   | an **eIDAS-qualified** timestamp token — a statutory-grade witness, **not checked by `elara-verify`** (verify with an eIDAS validator) |

Only the first two files back the bracket `elara-verify` proves; the timestamp
tokens are extra independent witnesses you can check with their own tools.

Expected verdict: a time bracket, **both ends trustless** —

```
TIME BRACKET (seal c2bc324c…):
  2026-06-14 16:20:00 UTC  ≤  the anchored seal existed  ≤  2026-06-14 16:43:25 UTC
  lower = drand round publication (BLS-verified — trustless); upper = Bitcoin block 953657 (archived header — pin-authenticated, trustless).
```

The bracket is the existence window of the **seal** the anchor commits to.

The lower bound is a drand beacon round, and its randomness is unknowable before
publication. The anchor carries the beacon's BLS signature; the verifier checks
it against the **pinned League-of-Entropy public key**, so the round provably
could not have been minted early — you take that on the beacon's math, not on
Elara's word. The upper bound is the timestamp of the Bitcoin block the proof
commits into — anyone holding Bitcoin's history can re-check it forever, trusting
nobody. Both ends are verified offline against a key and a header shipped right
here. That is the point.

> This sample is **fully confirmed** (Bitcoin block 953657 is archived beside
> it), so it verifies to exit 0. A freshly-sealed anchor whose Bitcoin
> timestamp is still pending — or whose block header you have not archived
> locally — verifies as **PARTIAL** (exit 3): the not-before holds, but the
> existed-by upper bound is honestly marked unproven (`⚠`), never a false green.
>
> `verify.sh` **leg 4 demonstrates this live**: it re-runs this very anchor with
> the `.ots` proof withheld and confirms the verifier keeps the trustless drand
> not-before (`✓`) yet marks the Bitcoin bound `⚠` PARTIAL — the fail-closed
> behaviour is *shown*, not just asserted, and the leg fails the demo if a future
> change ever lets a withheld proof pass as VERIFIED.

## Run both at once

```bash
$V examples/verify/sample-record.wire --wire \
   --anchor examples/verify/epoch-3217-zone-0.json
$V ... --json      # machine-readable verdict for any combination
```

These are checked as **two independent proofs** — the record is signed, *and* the
anchor's seal is Bitcoin-bracketed. The run does **not** assert the record is
inside that seal (the verifier prints a NOTE saying exactly that); binding the
record into the seal is the `--inclusion` + `--seal` chain below.

Exit codes: `0` = VERIFIED (every bound proven), `1` = FAILED (a check found
forgery/tampering), `2` = ERROR (could not read/parse), `3` = PARTIAL (nothing
forged, but a claimed bound is UNPROVEN — e.g. a pending or un-archived Bitcoin
existed-by, or a reference-only drand round without a verified BLS signature).
Each check prints `✓` proven, `⚠` unproven, or `✗` failed.

## 3. The full chain — *this account is in that sealed root* (legs 5–6)

The record above is proven *signed*, and the anchor's seal is proven
*Bitcoin-bracketed* — but as two **independent** facts. Binding a specific thing
*into* a sealed root is the chain. `verify.sh` does it offline with the account
SMT, the always-sealed tree:

```bash
elara-verify --account-inclusion account-proof.json \
  --seal epoch-8219-zone-0.seal.wire \
  --trusted-anchor "$(cat zone-0-anchor-pubkey.hex)" \
  --expected-hash d0742b057c228305f1ae36e60230dd68fdbbef65ac339eea2963ca44ad3e6f04
```

Three links make it **one** object, not three valid-but-unrelated ones: the
account walk (the identity's *sealed* state is a leaf), `account-root↔seal` (that
root is one the seal cryptographically committed to), and the seal is signed by
the validator key you pinned. Verdict: `VERIFIED`. **leg 6** then feeds the *same*
valid proof a root it does **not** climb to and confirms the verifier returns
`FAILED` (exit 1) — the false-chain guard, shown, not asserted.

This proves the **sealed account-state snapshot**, not the live balance and not
any record. Why the account SMT and not the record SMT? On an idle node recent
epochs hold no records, so the per-zone record tree is empty and a record
inclusion proof has nothing to harvest — but **every account is sealed every
epoch**, so this chain reproduces against any live node. Add the epoch's
`--anchor` to extend it to a Bitcoin time bracket. Full recipes (record *and*
account chains):
[`docs/ELARA-VERIFY.md`](../../docs/ELARA-VERIFY.md).

## 4. The receipt — *the whole run in one file*

The flags above hand the verifier each piece of evidence separately. A
`.elara-receipt` (v1, JSON) bundles them — signed wire objects hex-encoded,
proof JSONs verbatim — so "check this yourself" is one file plus the verifier.
`sample-receipt.json` here carries the same record and epoch-8219 seal as the
legs above:

```bash
elara-verify --receipt sample-receipt.json \
  --trusted-anchor "$(cat zone-0-anchor-pubkey.hex)" \
  --expected-hash d0742b057c228305f1ae36e60230dd68fdbbef65ac339eea2963ca44ad3e6f04
```

Verdict: `VERIFIED` (exit 0) — and the headline says exactly what was and was
not established (this receipt has no inclusion leg, so no record→seal chain is
claimed). **Trust never rides in the receipt**: drop the two pin flags and the
seal leg downgrades to an honest `⚠ PARTIAL` (exit 3) instead of trusting the
receipt's own contents — a receipt cannot vouch for its own trust root. `.ots`
Bitcoin proofs do not ride in receipts (their sidecar files stay CLI legs, §2).
The same envelope verifies **in a browser** at the hosted verify page
(`verify_receipt_offline`, the identical shared core compiled to wasm) — paste
the file, paste the pins.

## Reproduce the primitives in any language

The proofs above run through the Rust `elara-verify` binary. The protocol's
deterministic primitives are *also* published as language-agnostic **conformance
vectors**, so you can confirm a from-scratch implementation in **your** language
is byte-compatible — with no Rust at all.

```bash
python3 examples/verify/verify_conformance.py
```

`conformance-vectors.json` carries fully-specified inputs and expected outputs
for SHA3-256, the account-SMT empty/leaf/interior hashing, the full 256-level
account-SMT **inclusion-proof fold** (the light-client account-proof check — where
a from-scratch implementation is most likely to slip: MSB-first bit order, the
sibling-consumption order, the empty-subtree collapse), and identity derivation
(`docs/PROTOCOL-SPEC.md` §6.2 / Appendix A/B). It also carries a **must-reject**
vector — the same inclusion proof with one sibling byte flipped — so a second
implementation can prove it is *fail-closed*, not merely correct on the happy
path: a sound fold does **not** reconstruct the sealed root from a tampered proof,
and the check fails loudly if it does (a verifier that still accepted it would
admit a forged account-state proof — the catastrophic light-client break).
`verify_conformance.py` is a
small, pure-`hashlib` reimplementation that recomputes every one of them from the
documented byte layouts and fails loudly on any mismatch — it imports **no Elara
code**, so it is a genuinely independent check, not the reference implementation
re-deriving itself. The Rust tests in `src/conformance.rs` pin the same vectors
from the implementation side; the two together bracket the bytes from opposite
directions. `verify.sh` runs the Python leg automatically (leg 0) when `python3`
is on the PATH, and skips it cleanly otherwise.

The set carries a **second** inclusion-proof tree — and this is the subtlety an
implementer is most likely to miss. Alongside the domain-tagged account-SMT above,
the `merkle-inclusion` vector folds a proof in the **zone record-membership** tree
(`network::merkle`, §11.22.1) — the cross-zone settlement evidence the
`elara-verify verify-inclusion` command checks against a sealed root. It is a
*different* recipe: **no domain tags**. The leaf is the record hash verbatim (the
`record-hash` vector's output, so the two chain) and an interior node is
`SHA3-256(left ‖ right)` — not the account-SMT's `0x00`/`0x01`-tagged form — with
the sibling side given explicitly per node (`is_right`), not derived from a key
path. Its must-reject twin flips one sibling byte, so a second implementation
proves it is fail-closed here too. Reuse the account-SMT's tagged hashing for this
tree and you get a wrong root — exactly the mistake the vector exists to catch.

The set also carries an **ML-DSA-65 (FIPS 204) signature verification KAT** —
`mldsa65-sig` plus its must-reject twin. This is the one vector that needs a
post-quantum verifier rather than just a hash: feed `(public_key, message_ascii,
signature)` to your own FIPS 204 ML-DSA-65 `Verify` with an **empty context
string** — it must accept the valid signature and reject the byte-flipped twin
(accepting the twin is fail-open: a forged anchor signature admitted). Because
ML-DSA-65 signing is randomized, the conformance surface is *verification*, not
signature reproduction — your signer emits a different but equally-valid signature
for the same key and message. `verify_conformance.py` is pure-stdlib and has no PQ
library, so it size-pins these vectors (public key 1952 bytes, signature 3309
bytes) and leaves the cryptographic check to your implementation. Two independent
verifiers then actually run it: the Rust test
`mldsa65_signature_vector_verifies_and_reject_is_rejected`, and — outside Rust
entirely — `verify_pq.py` (leg 0c below), which feeds the vector to **liboqs** (the
Open Quantum Safe reference C library via `python-oqs`), a second FIPS 204
implementation that must accept the valid signature and reject the byte-flipped
twin. So the accept/reject is proven by a non-Rust verifier too, not merely
size-pinned.

Finally the set pins the light-client **keystone** the per-tree fold vectors leave
open — `account-binding` plus its must-reject twin (§11.22 / Appendix A.7). A fold
vector proves a proof reconstructs *its own* claimed root; but a sound light client
must **also** bind that root to the `account_smt_root` the trusted, anchor-signed
header commits to. `account-binding` is that two-level check: fold to a root, then
accept *iff* it equals `header_account_smt_root` (`expected` is the boolean
`"true"`). Its reject twin is the subtle one — a **perfectly valid** proof (it
still folds cleanly) bound to a header signing a *different* root: `Verify` must
return `"false"`. This is the fail-open class the per-tree `*-reject` vectors can't
catch — there the fold is *broken*; here the fold is *valid* and only the header
context is wrong. Skip the bind and a Byzantine server feeds you a proof folding to
a root it chose (one no anchor signed) and a forged balance sails through. It needs
no PQ library — `verify_conformance.py` recomputes both the accept and the reject
decision from scratch — and is derived from the same
`verify_account_proof_against_header` real SDK clients call.

And the **trust root** the whole chain rests on — `seal-anchor-sig` plus its
must-reject twin (§11.3 / Appendix A.8). Every vector above trusts a header's
`account_smt_root`; this one proves *why* you can. It takes a **real**
anchor-signed epoch seal (`epoch-8219-zone-0.seal.wire` — the same epoch
`account-binding` uses), decodes it, rebuilds its §4.4 preimage, and verifies the
anchor's ML-DSA-65 signature against the key you pinned
(`zone-0-anchor-pubkey.hex`). Unlike `mldsa65-sig` the signed message is the
seal's *own* canonical preimage, not an arbitrary string — so reproducing it
proves your record decode, your PQ verify, and your anchor-pinning all compose
into one trust-anchor check. Its reject twin is the same valid seal pinned to a
*different* anchor: a sound verifier returns `"false"` because the seal is signed
by a key you never pinned — accept it and you trust a seal from an unpinned key,
the trust-root fail-open (the signature is fine here; only the pinned context is
wrong). Like the PQ KAT it needs a FIPS 204 verifier, so the pure-stdlib
`verify_conformance.py` size-pins the anchor key (1952 bytes) and the seal wire
hash and leaves the cryptographic check to you. Both the Rust test
`seal_anchor_sig_vector_verifies_and_reject_is_rejected` and the non-Rust
`verify_pq.py` (leg 0c) then run the full check end to end: `verify_pq.py` reuses
`decode_record.py` to rebuild the seal's §4.4 preimage and surface the anchor
signature from the wire, applies the trust gate (`creator == pinned anchor`), and
feeds the preimage to liboqs ML-DSA-65 — accepting the valid seal and rejecting
the wrong-anchor twin in a second language, no Rust.

The hash primitives are the easy part; the **record wire format** (§4.3) and its
signature preimage (§4.4 `signable_bytes`) are where a second implementation earns
its keep. `decode_record.py` does exactly that — a pure-stdlib decoder that reads
`sample-record.wire`, rebuilds the §4.4 preimage, and recomputes `record_hash`:

```bash
python3 examples/verify/decode_record.py
```

It prints the decoded record (id, version, nonce, metadata, …) and confirms the
recomputed `record_hash` equals the `record-hash` vector — so the byte layout in
`docs/PROTOCOL-SPEC.md` §4.3/§4.4 is proven **implementable**, not just documented.
A single wrong byte (field order, the compact-JSON metadata, the v5 nonce) changes
the hash and fails the check. `verify.sh` runs it as **leg 0b**. It decodes the
*signed* subset and surfaces the primary ML-DSA signature from the wire (itself
pure-stdlib, no signature math) for the PQ leg below.

```bash
python3 examples/verify/verify_pq.py
```

`verify_pq.py` is **leg 0c** — the independent post-quantum check. The pure-stdlib
legs above can only size-pin the four ML-DSA-65 vectors; this one feeds them to
**liboqs** (the Open Quantum Safe reference C library via `python-oqs`), a second
FIPS 204 implementation independent of the Rust `fips204` crate that generated the
vectors, and proves a conformant verifier **accepts** each valid signature and
**rejects** each must-reject twin — including the `seal-anchor-sig` trust root over
the real epoch-8219 seal. It needs a PQ library, so without `python-oqs`/liboqs it
**skips transparently** (exit 3) and the leg-0 size-pins still stand — never a fake
green. So PQ signature verification is now demonstrated *twice* over, in two
independent languages: the Rust `elara-verify` binary (legs 1–6) and this liboqs
leg, no Rust.

And the **trustless time bracket** — the most distinctive claim here — gets the
same second-toolchain treatment for its *upper* bound:

```bash
python3 examples/verify/verify_btc.py
```

`verify_btc.py` is **leg 0d** — the independent **Bitcoin existed-by** check. The
anchor's time bracket (a BLS-verified drand not-before below, a Bitcoin existed-by
above) is proven by the Rust `elara-verify` binary in legs 1–4; this leg re-derives
the Bitcoin upper bound with **no Rust**, using the
[`opentimestamps`](https://pypi.org/project/opentimestamps/) reference Python
library (independent of the hand-rolled OTS walker in `src/bin/elara_verify.rs`)
plus stdlib SHA-256. It checks the whole chain, offline: (1) `SHA-256` of the
anchor artifact equals the digest the `.ots` proof commits to — the proof is for
*this* seal, not another file; (2) the `opentimestamps` library walks the proof to
a Bitcoin block-header attestation — block height and the committed merkle root;
(3) the archived 80-byte header double-SHA-256s to a block hash **pinned in the
script** — the *same* pin the Rust binary compiles in, never a hash read from the
bundle, and **this is what makes the bound trustless**; (4) the header's own
merkle-root field equals the OTS-committed root, so the proof genuinely lands in
that pinned block; (5) the block's header timestamp is the existed-by upper bound.
It is **fail-closed** — a tampered header, a proof bound to the wrong artifact, or
an OTS root absent from the pinned block all return exit 1, demonstrated by the
adversarial cases — and **skips transparently** (exit 3) when the `opentimestamps`
library is absent, leaving the Rust legs 1–4 as the reference. So the Bitcoin
existed-by bound, too, now stands in two independent toolchains.

The bracket's *other* end gets the same treatment:

```bash
python3 examples/verify/verify_drand.py
```

`verify_drand.py` is **leg 0e** — the independent **drand not-before** check, the
companion to leg 0d. The not-before is verified by the Rust binary (legs 1–4, via
the `drand-verify` crate); this leg re-derives it with **no Rust**, using
[`py_ecc.bls`](https://github.com/ethereum/py_ecc) — the Ethereum Foundation's
pure-Python BLS12-381 reference, a different implementation from the Rust backend.
It verifies the League-of-Entropy beacon signature over the chained-beacon message
`SHA-256(previous_signature ‖ round)` against the LoE group key **pinned in the
script** (never the artifact's own — a forged `(key, signature)` pair cannot pass,
and the round→time mapping uses pinned chain params, so the whole bound is
trustless), then maps the round to its scheduled publication time as the lower
bound. It is **fail-closed**: a one-byte-tampered signature must verify `False` on
every run (an inline self-check proves it is not fake-accepting), and a substituted
key, corrupted signature, or wrong chain each return exit 1 — demonstrated by the
adversarial cases. It **skips transparently** (exit 3) when no BLS library is
installed (`pip install py_ecc` enables it; BLS is common in the drand / Ethereum /
Filecoin ecosystems). With 0d and 0e, **both ends of the trustless time bracket —
the drand not-before below and the Bitcoin existed-by above — are now reproduced in
a second, non-Rust toolchain**, not just by the `elara-verify` binary.

## Provenance of these samples

Harvested from the Elara testnet, all fixed snapshots that stay valid offline
indefinitely: the record is `019ec215-…` (creator `ada8575c…`, harvested
2026-06-13); the anchor is epoch 3217, zone 0, whose seal `c2bc324c…` was
published against drand round 6200766 (2026-06-14 16:20:00 UTC) and timestamped
into Bitcoin block 953657. The account-chain bundle (`account-proof.json`,
`epoch-8219-zone-0.seal.wire`, `zone-0-anchor-pubkey.hex`) is identity
`ada8575c…`'s sealed account-state and the zone-0 epoch-8219 seal that committed
it, signed by the zone-0 validator key — re-harvested 2026-06-17 under the
256-bit identity-bound compressed account-SMT. That account seal is
validator-signed (PQ trust chain), not Bitcoin-anchored; legs 1–4 carry the
Bitcoin bracket.
