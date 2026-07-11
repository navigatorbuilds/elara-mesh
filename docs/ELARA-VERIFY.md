# elara-verify — offline verification, no trust in us

`elara-verify` is a single standalone binary that answers, **offline**, with no
node, no network, and no trust in the people who run Elara:

> *Was this record authentically signed, and when did it provably exist?*

It pulls in no node stack. Build it on its own:

```bash
cargo build --release --features verify-cli --bin elara-verify
```

There are four verification modes. Each prints a plain-language verdict and exits
`0` (VERIFIED — every bound proven), `1` (FAILED — a check found forgery or
tampering), `2` (ERROR — could not read/parse the input), or `3` (PARTIAL —
nothing is forged, but a claimed bound is *unproven*: a pending or un-archived
Bitcoin existed-by, or a reference-only drand round whose BLS signature was not
verified). Per-check glyphs are `✓` proven, `⚠` unproven, `✗` failed — `⚠`/PARTIAL
exists so a legitimately-fresh anchor is never rejected as forged, yet a missing
or pending bound is never overstated as VERIFIED. Any modes may be combined; the
overall verdict is the worst across all checks (FAILED ≻ PARTIAL ≻ VERIFIED).

## 1. Record — *who signed this, and over what content*

```bash
elara-verify <record.json>                 # JSON record (default)
elara-verify <record.wire> --wire          # canonical wire bytes
elara-verify <record.json> --content file  # also bind an artifact to the record
```

Checks: the record parses; the embedded public key hashes (SHA3-256) to the
identity it claims; the **Dilithium3** signature is valid over the canonical
bytes; for Profile A, the **SPHINCS+** second signature too; and (with
`--content`) that your artifact hashes to exactly the record's content hash.

The record's own timestamp is only the creator's *claim*. For trustless time,
use the anchor mode.

## 2. Anchor — *the Bitcoin-anchored time bracket*

```bash
elara-verify --anchor epoch-N-zone-Z.json
```

An epoch-anchor artifact brackets when a seal existed — a Bitcoin upper bound
(trustless when its block header is pin-authenticated, otherwise a reference),
plus a drand lower bound (trustless when the artifact carries the beacon
signature, otherwise a reference) — fully offline:

- **not-before** — the artifact cites a drand round whose publication time is
  `genesis + (round-1)·period`, indicating the seal was created no earlier. When
  the artifact carries the beacon's BLS signature, `elara-verify` verifies it
  against the **pinned** League-of-Entropy public key (never the artifact's own
  claimed key — that is what makes a pass trustless), so the lower bound is then
  trustless, fully offline. Legacy artifacts that stored only the round remain a
  *reference* (the randomness is a one-way hash of the signature, so it cannot
  stand in), and the verdict says which. A present-but-invalid signature FAILS.
- **existed-by** — the `.ots` proof beside the artifact is a SHA-256 path into a
  Bitcoin block's merkle root; `elara-verify` walks it and matches it against the
  80-byte block header self-archived next to the artifact (`btc-header-*.txt`).
  The block's timestamp is then the upper bound — **trustless** when that header's
  double-SHA256 matches a block hash pinned in the verifier (an auditable mainnet
  block hash compiled into the binary), and a **reference** bound otherwise: an
  offline tool cannot prove an arbitrary header is on Bitcoin's canonical chain
  (no PoW chain to a checkpoint), so an unpinned header is only as strong as its
  own authenticity, which you check out-of-band. No calendar server, no Bitcoin
  node, no `ots` CLI either way.

```
TIME BRACKET (seal 826306639200879b…):
  2026-07-10 23:25:00 UTC  ≤  the anchored seal existed  ≤  2026-07-10 23:34:41 UTC
  lower = drand round publication (BLS-verified — trustless)
  upper = Bitcoin block 957487 (archived header — pin-authenticated, trustless, offline)
```

The bracket is the existence window of the **seal** the anchor commits to — not,
on its own, of any record. Pairing a `<record>` with `--anchor` verifies both as
independent facts; binding the record *into* that seal needs `--inclusion` +
`--seal` (see "The full chain"). The verifier prints a NOTE saying so when a
record and an anchor are checked together without that binding.

(A signature-less legacy artifact shows `lower = … (reference)` instead, and the
verdict names which — the bound is never claimed stronger than what was checked.)

A still-pending or un-archived proof says exactly that, rather than implying a
bound it cannot show.

## 3. Seal — *signed by a validator you pinned*

```bash
elara-verify --seal seal.wire \
  --trusted-anchor <anchor-pubkey-hex> \
  [--expected-hash <record-hash-hex>]
```

Verifies a fetched epoch-seal record is authentically signed by a **caller-pinned**
anchor key (anchor membership + Dilithium3). `--expected-hash`, taken from a
header you already trust, also pins the seal's identity → a proven `✓`. **Omit it
and the leg is `⚠` PARTIAL, not a green `✓`**: a trusted anchor signed *some*
seal, but nothing pins *which* one (an attacker could swap in a different
anchor-signed seal for another epoch), so the verdict honestly stays below
VERIFIED until you supply the pin.

## 4. Inclusion — *this record is in that sealed root*

```bash
elara-verify --inclusion proof.json [--expect-root <sealed-root-hex>]
```

`proof.json` is the `/zone/{zone}/proof/{record_hash}` payload. `elara-verify`
walks the record's hash up the sparse-Merkle siblings (SHA3-256) to the zone's
root. The proof's root is **self-declared by the proof itself** — so `--expect-root`
binds it to a sealed root you already trust. **Without `--expect-root` the
sealed-root bind is `⚠` PARTIAL** (the walk is internally consistent, but it
climbs to a root the proof author chose, which proves nothing about a real seal);
supply `--expect-root` to make it a proven `✓`. A zero-sibling proof (or one whose
`is_right` flags are not JSON booleans) is rejected outright.

## 5. Account inclusion — *reproducible on any live node*

```bash
elara-verify --account-inclusion proof.json \
  [--seal seal.wire --trusted-anchor <K>] [--expect-root <root-hex>] \
  [--expect-identity <identity-hex>]
```

`proof.json` is the `/proof/account/{identity}` payload. This is the inclusion
mode you can always reproduce: the **account SMT is populated and sealed every
epoch**, whereas the per-zone *record* SMT (`/zone/{zone}/proof/...`, §4) is empty
on a node with no recent records — so on an idle testnet there is nothing to build
a record proof from, but every account still has a proof.

`elara-verify` walks the identity's **sealed** account state up the 256-bit
account SMT (the path is the full identity SHA3-256, and the leaf binds the
identity) to the proof's root, via a compressed sibling set. It
verifies the leaf — `state_hash`, the *at-last-seal* snapshot — **verbatim**; it
never re-hashes the live `account_state` field (that is the current ledger view,
which is unauthenticated and may be ahead of the seal). With `--seal` present the
account root is matched automatically to the seal's committed `epoch_account_smt_root`
(the `account-root↔seal` link); else pin it with `--expect-root`. **Without either,
the bind is `⚠` PARTIAL** (the root is self-declared). `--expect-identity` guards
against a valid proof for a *different* identity than you asked about.

What this proves is the identity's **sealed account-state snapshot** at that epoch
— **not** the live balance, and **not** that any particular record exists. A
non-existence response (`exists:false`) is routed to `--account-exclusion` (§6);
a not-yet-sealed account is reported as such, never as a green. To extend the
chain to Bitcoin, add the epoch's `--anchor` (§2), exactly as for the record
chain below.

## 6. Account absence — *provably NOT there*

```bash
elara-verify --account-exclusion proof.json \
  [--seal seal.wire --trusted-anchor <K>] [--expect-root <root-hex>] \
  [--expect-identity <identity-hex>]
```

`proof.json` is the same `/proof/account/{identity}` payload when the account is
**absent**: the server answers `exists:false` plus a compressed **exclusion
witness**. `elara-verify` folds the **empty** leaf up the identity's 256-bit
key-addressed path and requires it to reconstruct the witness's root — sound
non-membership, the same engine as §5, so a server can no longer assert absence
by bare claim; it must produce a fold, which is impossible for an account that
actually has a leaf.

Scope discipline: this proves the identity is absent **at the witness's root**
— and once that root is bound to a real seal, absent *as of that seal* — never
"currently absent" (it may gain a leaf at any later seal) and never absent
forever. The root binding carries all the weight: *any* witness folds to *some*
root (an empty tree "proves" anything absent), so **without
`--seal`/`--expect-root` the run is `⚠` PARTIAL** and the CAUTION line says why. `--expect-identity` matters even more here than in §5 —
a valid witness for a *different* identity silently inverts the meaning of the
answer you think you got. Payloads that assert presence (`state_hash`,
`pending_first_seal`, `exists:true`) and witness-less legacy bare-root responses
are input errors (exit 2), each routed with guidance — never graded as absence.

## 7. Receipts — *the whole chain in one file*

```bash
elara-verify --receipt receipt.bin \
  [--trusted-anchor <K>] [--expected-hash <H>] [--expect-root <R>] [--expect-identity <I>]
```

`--receipt` takes a `.elara-receipt` **v1 envelope** — one JSON file bundling
the evidence legs of §§1–6 — or, as a degenerate receipt, a bare record
(canonical wire bytes from `/record/<id>/wire`, or a raw record JSON), which
grades exactly like `elara-verify <record>`.

The envelope: `{"receipt_version": 1, "producer": {…}, "legs": {…}}`. Known
legs: `record` and `seal` as **hex-encoded canonical wire bytes**; `anchor`,
`inclusion`, `account_inclusion`, `account_exclusion` as the same JSON payloads
the flags read, verbatim; `lineage` is reserved. Every leg runs through the
**identical verifier** its flag uses, and the cross-leg bindings are re-derived
cryptographically — no envelope field can assert a binding.

What a receipt can never do is vouch for itself: **trust pins stay on your
side of the command line.** `--trusted-anchor`, `--expected-hash`,
`--expect-root`, `--expect-identity` compose with `--receipt` exactly as with
flags, and their absence grades `⚠` PARTIAL, exactly as with flags (a receipt
carrying a seal but given no `--trusted-anchor` reports the seal as UNGRADED —
honestly, never silently). `producer` is displayed but never trusted. Legs this
verifier does not recognize are disclosed and **cap the verdict at PARTIAL** —
never VERIFIED-with-skips. A `receipt_version` this build does not speak is
refused outright (exit 2): a newer envelope may carry security-bearing fields
an old verifier cannot check, so it must under-claim, never under-check.
`--receipt` is mutually exclusive with the per-leg evidence flags.

The same envelope verifies **in a browser**: the hosted verify page's
`verify_receipt_offline` export runs the identical shared
`verify_core::grade` sequence compiled to wasm (paste the receipt, paste the
pins), so the browser verdict cannot drift from the CLI's. `.ots` existed-by
sidecars remain CLI-only and surface there as an honest `⚠`. Both surfaces
lead with the same gates-driven one-line **headline** (also in `--json` as
`headline`) that states exactly what was — and was not — established.

## The full chain

Combine the modes and you have an end-to-end statement, trustless on the Bitcoin
and signature legs — *this record existed by this Bitcoin-anchored time, signed
by this key*:

1. `--inclusion proof.json` — the record is a leaf under the proof's root. With
   `--seal` present that root is matched automatically to a root the seal signed
   (below); without a seal, pin it to a root you trust with `--expect-root <R>`.
2. `--seal seal.wire --trusted-anchor <K>` — the seal is signed by pinned
   validator `K` and carries the committed root(s) the proof is bound against.
3. `--anchor epoch.json` — that seal's epoch is bracketed
   `drand ≤ … ≤ Bitcoin block`.

When you supply several legs together, `elara-verify` **cross-binds** them so the
chain is one object, not several unrelated valid ones. It checks three links:
the inclusion proof's leaf is the `<record>`'s own hash (`record↔proof`); the
proof's root is one of the roots the `--seal` cryptographically committed to —
each lives in the seal's signed bytes, so the anchor signature vouches for it
(`inclusion↔seal`); and the `--anchor` commits to the `--seal` you supplied
(`seal↔anchor`). A mismatch at any link — a proof for a *different* record, a
proof whose root no seal signed, or an anchor for a *different* seal — is a hard
`✗` FAILED, not a quietly-ignored pass. Only when all three links pass (alongside
the per-leg checks) does the verdict say *this record's seal* existed within the
bracket; otherwise the bracket is the seal's own window and a NOTE states the
legs were verified independently. This closes the gap where individually-valid
but unrelated inputs could otherwise read as one VERIFIED chain.

Every step is checkable on a laptop with no network; the existed-by, seal, and
inclusion checks need no trust in Elara's operators — and the drand lower bound
joins them when the artifact carries the beacon signature (signature-less legacy
artifacts stay a reference). `--json` emits a machine-readable verdict for any combination.
