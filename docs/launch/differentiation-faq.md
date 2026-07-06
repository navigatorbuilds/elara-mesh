# "How is this not just X?" — launch-day differentiation FAQ

*(Every comparative claim below was fact-checked against the other systems'
primary docs/specs — we'd rather concede a point than overstate one.)*

## The headline question: "Why not just OpenTimestamps + a post-quantum signature?"

Compose *just* those two primitives and you get exactly: **"this key signed
these bytes, and the bytes existed by this Bitcoin block."** That is *when*
something happened and *which key* touched it. Neither primitive — alone or
composed — carries any notion of **delegation, scope, or revocation**, so the
pair structurally cannot express the one thing that matters when an autonomous
agent acts:

> *agent A was mandated by principal P to do X, the mandate was valid at the
> act's signing time, and it was later revoked.*

Expressing that needs a **third layer**: an authority/accountability record.
Elara is that layer, native — post-quantum, offline-recomputable, and queryable
as a time-aware ledger of *acts under authority* rather than a credential you
bolt on. `cargo run --example mandate_demo` shows it in ~60 seconds with no node
and no network.

**The honest scope of "structurally cannot":** it is true of the OTS+signature
*strawman* — those two primitives and nothing else. It is **not** a claim that
no system can express a mandate (see Verifiable Credentials below). Anyone who
adds the missing authority layer has built something that does what Elara does;
our claim is that we ship it as one integrated, post-quantum, offline-verifiable
mesh, not that the idea is ours alone.

**OpenTimestamps, precisely.** OTS proves a single hash existed by a given
Bitcoin block — and nothing about who produced it, under whose authority, or
whether that authority was valid. Its own docs are explicit that it does *not*
prove authorship. Calendar servers are queryable, but only to *upgrade one
commitment's Bitcoin proof* — there is no queryable, time-aware history of
*acts* or *authority*. We *use* OTS as one leg of our anchor braid.

**A bare signature (post-quantum or classical), precisely.** A Dilithium3 /
ML-DSA signature answers `Verify(pk, msg, σ) → {0,1}` — "the holder of key K
signed these bytes." Nothing in any signature standard introduces an issuer
chain, a scope, a validity window, or revocation. That is the entire reason
credential layers exist on top of raw signatures.

## "But W3C Verifiable Credentials / X.509 attribute certificates already do delegated, scoped, revocable authority."

**True — and we don't claim otherwise.** W3C Verifiable Credentials 2.0 (a
Recommendation since 2025) with a Bitstring Status List express a scoped,
time-bounded, revocable grant; X.509 attribute certificates (RFC 5755) have
encoded delegated privilege for years. If you only need to *express* a mandate,
those are real options.

The honest distinction is **what kind of thing each is**:

- A VC or attribute certificate is a **credential format** — a statement you
  *present*, that answers *"is this credential valid right now?"* You issue it,
  you host its revocation/status service, and you bolt it onto your system.
- Elara records the **act** — a witnessed, content-addressed, time-anchored
  ledger entry that *references* its mandate and answers a harder question:
  *"was the authority valid at the exact, sealed moment this act was signed —
  given that revocation may have happened afterward?"* The authority record and
  the act live on the **same** witnessed ledger; revocation is read-time and
  front-run-proof (keyed to the principal, so a non-principal's revocation is
  never even consulted). And the signing layer is **post-quantum today** — W3C
  post-quantum cryptosuites are still marked experimental.

So: VCs answer *"were you allowed?"*; Elara's mandate layer records *"you acted,
here, at this time, and here is whether the authority held — permanently, on a
witnessed ledger."* Different problem, different shape.

## "Just sigstore?"

sigstore is excellent for OSS supply chains — and we're careful about what it
does today:

- It **can** verify offline: cosign bundles carry the Rekor inclusion proof and
  a signed timestamp, and `cosign verify --offline` is shipped. (An earlier
  draft of this FAQ said "no offline story" — that was wrong; corrected.)
- Its public instance is **not yet post-quantum** as of 2026, though
  experimental ML-DSA support is landing in the client/bundle tooling.

What sigstore has no concept of is **authority-to-act**: a Fulcio certificate
binds a signing identity (an OIDC token, a CI workflow) to a key, and Rekor logs
the signing event — but neither says *"principal P authorized agent A, within
scope S, revocably."* gitsign/attestations record *who signed an artifact*, not
*who was authorized to*. sigstore is built for public transparency logs and
internet OIDC, not a long-running private validation mesh. That authority gap —
not offline-ness or PQ alone — is the difference.

## "Just C2PA / Content Credentials?"

C2PA is media-provenance metadata under a consortium PKI. Precisely:

- Plain manifests are easily stripped (save-as, format conversion, most social
  platforms). C2PA 2.1+ answers this with **Durable Content Credentials**
  (invisible watermark + perceptual fingerprint + a **cloud manifest lookup**),
  designed to survive stripping — at the cost of reintroducing a hosted
  database and network dependency, and the watermark is not invulnerable to
  adversarial editing. (An earlier draft called manifests simply "strippable"
  with no caveat — corrected.)
- C2PA manifests **do** carry a time authority: the spec uses RFC 3161 TSA
  timestamps. (An earlier draft said "no time authority" — that was wrong;
  corrected. It is a *trusted-authority* timestamp, not a trustless anchor.)

What C2PA is *not*: a consensus network, a validator quorum, or a queryable
ledger of authorized acts. It attests *who made this media and how it was
edited* — not *who was authorized to perform an action, under what mandate*. The
two compose fine: a C2PA manifest hash is a perfectly good thing to record on
Elara.

## "Just Certificate Transparency?"

CT (RFC 6962 / 9162) is the closest structural cousin — an append-only Merkle
log with public monitors — so it's worth naming. But CT logs *certificate
issuance*: it proves a CA issued a certificate, by design **not** that the key
was *authorized to perform an act*, with what scope, still valid at a later
moment. CT is issuance transparency for the web PKI (and classical-crypto);
Elara is an append-only, post-quantum record of *acts under delegated
authority*, with validity-at-signing and revocation as first-class, offline-
recomputable ledger semantics. Orthogonal problems.

## "Just a blockchain?"

No global chain, no blocks to fight over, no fees, no tradeable coin (the
internal unit is a non-tradeable **beat**; you earn standing by verifying, you
cannot buy in). The mesh is an offline-first DAG: partitions keep writing and
*merge* on reconnection — designed for interplanetary delays, which is why a
factory basement or an air-gapped agency works the same way.

## "Just a timestamping SaaS?"

Those ask you to trust the vendor's key custody and database. Elara's
**trustless path** is offline against media nobody controls — the Bitcoin hash
chain (an existed-by upper bound, via OpenTimestamps, authenticated against a
Bitcoin block hash pinned in the verifier — live on every anchored seal) and
drand public randomness (a not-before lower bound, verified offline against the
pinned League-of-Entropy key — fully supported by the verifier and the sample
bundles; the node-side fetcher is shipped but opt-in — default off — so live
seals carry pulses once enabled) —
and the verifier in this repo checks both in front of
you, zero network. We *also* carry an EU-qualified RFC-3161 timestamp as a
conventional trusted-authority cross-check — but for that one you trust the
authority, so it is **not** part of the trustless offline path and the verifier
doesn't check it. (We name it explicitly so the trustless claim is scoped
honestly: the trustless guarantee is the Bitcoin+drand path, not the whole
stack.)

---

## The one-sentence version

> **OpenTimestamps proves *when* a hash existed and a post-quantum signature
> proves *which key* signed it — but neither, alone or composed, expresses
> whether that key was *authorized* to act; Elara adds a post-quantum,
> queryable ledger that records each act's reference to a revocable,
> time-bounded mandate from a named principal and deterministically flags —
> offline, re-runnable years later — whether that authority held at the act's
> signing time, on the same witnessed ledger as the act itself.**

## What ships today vs. what's next (honest-claims rule)

The mandate layer is an **observational v0**, and we say so everywhere:

- **Enforced in v0:** the *who* (agent-identity binding), the *when* (validity
  window), **revocation** (read-time, front-run-proof, keyed to the principal),
  and the **sub-delegation chain-walk** (leaf→root genealogy + per-hop scope
  *narrowing* + depth cap) with **lineage attribution** surfaced only on a
  clean `Valid` verdict (anti-libel). Out-of-mandate acts are **recorded and
  flagged** with a typed taxonomy (`NO_CHAIN` / `AGENT_MISMATCH` / `LAPSED` /
  `NOT_YET_VALID` / `POST_REVOCATION` / `UNVERIFIED_CHAIN` / `SCOPE_BROADENED` /
  …) and carry **zero trust/consensus weight** — a truth ledger records
  violations rather than silently dropping them.
- **Not yet in v0:** **op/zone/amount scope is recorded but not yet enforced
  against an act for non-wildcard mandates** (a sound, node-invariant op/zone
  derivation needs a signed canonical taxonomy — `OVER_SCOPE` fires today only
  for wildcard mandates); and **consensus-weight enforcement** (a flag gating
  stake / committee standing) is **deferred to a multi-validator network**
  (≥2 staked attesters + that signed scope taxonomy — see
  `docs/AGENT-DELEGATION.md`). We never claim a scope check the code doesn't
  perform.

Run it yourself: `cargo run --example mandate_demo` (no node, no network, no
features) reproduces every verdict above from the same pure function the live
node's `GET /mandate/status/{record_id}` endpoint calls. Or check an
authorization chain **offline in your browser** — the verify demo's mandate
verifier (`evaluate_mandate_bundle`, the same `mandate_bundle` core compiled to
WASM) takes a signed bundle and returns `CONSISTENT` / `NOT AUTHORIZED` with the
honest-scope caveats (offline it proves the chain *given the bundle*, never that
records are on-chain or that a revocation wasn't withheld — that is the node's
answer).
