# Multi-Validator Emitter Authorization — Design & Sequencing (2026-06-17)

Status: **apply-path seam landing now (provable no-op); M-of-N deferred to S3 with this design.**

This document is the output of a high-stakes independent adversarial design review
(2026-06-17) of the last open item from the apply-path float-determinism sweep (internal design notes):
*"Multi-validator emitter-auth for protocol mutations (slash/idle_decay/reward) — the
single-authority gate is exact today; the generalisation is a separate cross-cutting design."*

## TL;DR verdict

- **Build now:** generalize the *apply-path* authorization from string-equality
  (`actor != genesis_authority`) to set-membership (`!authority.is_authorized(actor)`),
  with the set hard-wired to `{genesis_authority}`. Bit-identical today, provable by
  the fresh-clone replay-root match. ~23 consensus comparison sites.
- **Do NOT build now:** M-of-N verification, a typed `AuthorityProof`, a new record
  wire field, a new config field, or per-op policy objects. All over-fit an undefined
  S3 topology in consensus-replicated code — the dangerous kind of premature.
- **Defer to S3 (the multi-validator stage, hard-gated, last):** everything in §4–§6.

## 1. Current model (ground truth)

A single identity string `config.genesis_authority` is THE authority. Two distinct
gate classes use it, and only one is consensus-critical:

| Class | Where | Runs on | Fork-critical? |
|-------|-------|---------|----------------|
| **Gate A — apply/validate** | `accounting/validate.rs` (~11) + `accounting/ledger.rs` (~12): `if actor != genesis_authority { reject }` for mint / witness_reward / slash / dormancy_reclaim / burn / idle_decay | **Every node, incl. any follower replaying the chain** | **YES** — the accept/reject is consensus-replicated; a divergence silently forks two honest nodes |
| **Gate B — emission** | `network/{slashing,reward,health,epoch}.rs`: `if self.identity != genesis_authority { don't emit }` | **Only the authority node** (followers never run it) | No — node-local "is it my job to author this record" |

The asymmetry is the whole design. **Gate A is the seam that is expensive and
dangerous to retrofit later; Gate B is local policy with zero consensus exposure.**

## 2. The seam landing now (apply-path Gate A only)

The seam **centralizes the authorization decision** behind one named predicate, keeping
the existing `&str` boundary. No signatures change, no new type, no allocation:

```rust
// accounting/authority.rs
/// THE authorization decision for privileged protocol mutations (mint / witness_reward /
/// slash / dormancy_reclaim / burn / idle_decay). Every consensus apply/validate gate
/// (`accounting/validate.rs`, `accounting/ledger.rs`) routes its accept/reject through here, so the
/// rule lives in ONE place when S3 generalizes it to M-of-N.
///
/// DETERMINISM INVARIANT (verbatim, see §5): authorization is a pure function of
/// (the actor identity, the genesis-pinned authority). It reads no balance, no live
/// stake, no finality state, no wall-clock. `genesis_authority` is byte-identical on
/// every node and immutable-since-genesis until S3 defines epoch-scoped rotation.
pub fn is_privileged_emitter(actor: &str, genesis_authority: &str) -> bool {
    actor == genesis_authority
}
```

Each Gate A site `if actor != genesis_authority { reject }` becomes
`if !authority::is_privileged_emitter(actor, genesis_authority) { reject }`. The body is
literally `actor == genesis_authority`, so every gate returns the identical bool. A unit
test asserts `is_privileged_emitter(x, g) == (x == g)` for arbitrary `x`; the integration
proof is that a fresh-clone replay converges to the **same account-state SMT root**
(a fresh-clone virgin-join replay is the oracle).

**Why a free predicate, not a typed `EmitterAuthority` set threaded through signatures:**
the value of the seam is centralizing the *decision* so S3 changes the logic in one place —
the predicate achieves that fully. Pre-threading a richer authority *type* through ~23
function signatures now buys only mechanical work saved at S3; it does **not** reduce fork
risk (the type change is compile-time and replay-verified whether done now or at S3 — only
the *logic* change str-equality→M-of-N is fork-bearing, and that lands at S3 regardless).
Under effort-is-scarce + release-is-the-near-term-priority, the predicate is the minimal,
no-dead-code seam. Promoting it to a typed set is the first S3 step (§4).

**Deliberately NOT in the seam:**
- No `EmitterAuthority` struct / `BTreeSet` yet — with a singleton authority it is dead,
  speculative surface (exactly what the panel warned against). It is the §4 S3 artifact.
- No new config field (`authorized_emitters: Vec<…>`). A multi-element source now creates a
  divergence surface (two operators, two configs → fork) with **no consumer**. Defer it to the
  change that defines S3.
- No change to Gate B emission sites. Node-local; touching consensus-adjacent code for no
  behavioral reason is pure risk.
- The authority stays **immutable-since-genesis**. The predicate is correct *only* while the
  authority never changes mid-chain (see §5 epoch-scoping caveat).

Precedent for the S3 set form (not a new abstraction): `trust_set = trusted_snapshot_signers ∪
{genesis}` with `.contains()` at `sync.rs:756/919` → `snapshot.rs:544`, and
`genesis_validators: Vec<…>` — "deterministic membership over a genesis-pinned trusted set"
already ships.

## 3. Why now, not pure-defer and not full-build

- **Pure-defer is the wrong default:** it leaves string-equality smeared across ~23 consensus
  sites to be re-threaded later, for the first time, *while a live follower fleet exists* —
  when any mistake is a silent fork. The refactor's risk is **lowest now** (singleton set,
  provable no-op) and rises monotonically.
- **Full-build is the dangerous default:** no second-validator topology is defined (M-of-N?
  per-zone committees? rotating? stake-weighted?). Guessing it in consensus-replicated code is
  worse than no code. The settlement/apply-path float-determinism sweeps are the recent proof
  that premature generalization in this layer produces design regret.
- **Readability:** a documented `EmitterAuthority` with the determinism invariant reads better
  to external reviewers than string-equality across 23 sites — minor, not deciding.

## 4. Deferred M-of-N verification design (build at S3, not before)

**First S3 step:** promote the §2 predicate to a typed, genesis-pinned set —
`EmitterAuthority { authorized: BTreeSet<String> }` with `is_authorized(&self, id) ->
self.authorized.contains(id)` — and thread `&EmitterAuthority` through the apply/validate
signatures (replay-verified, no fork risk: it is a compile-time type change proven by the
SMT-root oracle). `BTreeSet` for canonical iteration if it is ever serialized; today's set
is the singleton `{genesis_authority}`.

Then generalize `EmitterAuthority` to require ≥M authorizing signatures. The PQ-safe,
deterministic design:

- **Inline detached signatures, not a quorum-certificate record.** The privileged record
  carries `Vec<(signer_identity, dilithium3_sig[, sphincs_sig])>`. Verify each over the
  *same canonical payload bytes*; accept iff **≥M distinct members of the consensus-pinned
  set** signed. (BLS aggregation is unavailable — Dilithium3/SPHINCS+ don't aggregate; N
  individual verifications are required, acceptable because privileged ops are low-frequency.)
  - *Rejected: quorum-certificate-as-separate-record* — it puts an "is the cert finalized?"
    read into the privileged-op apply path. That is a node-local **mutable finality-state**
    read: a since-genesis node and a snapshot-bootstrapped node can disagree whether an old
    cert finalized → silent fork. It also breaks light-client self-containment (Gap 1 SDK).
- **Canonical serialization:** signatures stored lex-sorted by signer identity (or
  registration index) so the record bytes/hash are canonical. The **accept/reject decision is
  order-independent** (a distinct-member count), so ordering affects only serialization, not
  the gate — the strongest determinism posture.
- **Coordinator-assembled, exactly-M:** one coordinator assembles the canonical signature set
  and publishes ONE record. Nodes reject privileged records whose signer set isn't exactly the
  threshold (an "at least M" rule admits multiple valid-but-different-hash variants of the same
  mutation → two honest nodes finalize different variants → fork).

## 5. The determinism invariant (write this verbatim into the gate)

> **Privileged-op authorization is a pure function of (record bytes, genesis-pinned
> authority set). It reads no balance, no live stake, no finality state, no wall-clock.
> The authority set is byte-identical on every node and immutable-since-genesis until
> S3 defines epoch-scoped rotation.**

- **#1 silent-fork vector (all panelists):** the gate reads node-local *mutable* state —
  "is this signer *currently staked* / *in the committee* / *above reputation*?" — and two
  honest nodes answer differently (one bootstrapped, one replayed since genesis). This is
  exactly the `#[serde(skip)]` consensus-tracker bug class fixed 2026-06-17. Precluded by
  making the set a **consensus parameter, not derived state**.
- **Epoch-scoping caveat (mandatory if the set ever becomes mutable):** the moment the
  authorized set can change mid-chain (adding the 2nd validator, rotation), replay must use
  "the set **as sealed at the epoch this record was applied**," not the current-tip set. A
  naive current-config read for a historical record forks instantly. Mutability is **out of
  scope** for the seam; it requires epoch-versioning the set (the same epoch-scoping the rest
  of the protocol uses for seal state).

## 6. The real S3 blocker (harder than authorization — scope it, don't mistake it for done)

The privileged ops are **auto-emitted on a schedule by the authority node**, not
user-submitted. So multi-validator's hard problem is *emission*, not *authorization*:

- **Leader-election / double-emission / liveness:** which validator emits the reward batch
  (or idle_decay, or dormancy-reclaim) for epoch E? Two emitting → conservation breaks. None
  emitting → liveness stall. This is a coordination/leader-election protocol, **undesigned**,
  and it is the actual S3 work item — the authorization seam is necessary but far from
  sufficient. **Do not let "emitter-auth" read as handled.**
- **Shrink the surface first:** `witness_reward` and `idle_decay` are deterministic
  epoch-formulas — candidates to become *computed identically on every node with no emitter
  at all* (no auth, no leader-election needed). Evaluate making them emitter-free before
  building auth for them; that likely reduces the S3 privileged set toward `{mint, slash,
  dormancy_reclaim}` or fewer.
- **Proposer vs. authorizer vs. record-creator are three distinct roles.** Who *creates*
  (signs/publishes) a privileged record (`creator_public_key` — authenticity) can differ from
  who *authorizes* it (the M-of-N quorum — authorization). If only the genesis key may publish,
  a quorum-authorized model is only partially decentralized. Keep these separate in the S3 design.
- **Proposal/assembly gossip** (a `PrivilegedOpProposal` record type + signing coordination)
  is an undesigned protocol surface, also S3.

## 7. Per-op intent (for the S3 design, not built now)

| Op | Likely S3 model |
|----|-----------------|
| `mint` | Highest-threshold M-of-N of founding validators; very rare |
| `slash` | Stake-weighted validator quorum + evidence submission (not bare identity-set membership) |
| `witness_reward` | Candidate to become **deterministic/emitter-free** (epoch attestation formula) |
| `idle_decay` | Candidate to become **deterministic/emitter-free** (epoch-triggered fixed formula) |
| `dormancy_reclaim` | Formula-based (time + inactivity); could become permissionless |
| `burn` | M-of-N or remain authority-only |

---

**Review provenance:** independent adversarial design-review panel (2 Sonnet + 1 Opus), Opus-judged,
2026-06-17. Ground truth verified against source: Gate A ≈ 23 comparison sites
(`validate.rs` + `ledger.rs`), Gate B emission sites (`slashing.rs`×4, `reward.rs`×2,
`health.rs`), `trust_set` precedent (`sync.rs:756/919`). Supersedes the one-line "still open"
note in the apply-path float-determinism sweep.
