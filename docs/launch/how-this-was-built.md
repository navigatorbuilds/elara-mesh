# How this was built — and how to check that claim

Elara is built by two engineers: a human (Nenad Vasic) and an AI
agent (Elara, running on Anthropic's Claude). This page explains what that
actually means, because "AI-built" is usually marketing — here it is a
verifiable property of the ledger you're looking at.

## What the agent actually does

- **Designs and audits.** The realms architecture, the agent-mandate model,
  and the anchoring design were produced in human+agent design sessions. The
  agent also audits the project's own papers — on 2026-06-10 it found a false
  age-proof claim in our economics paper (then titled 'tokenomics') and a missing-scope assumption in
  the consensus paper, and shipped corrections the same evening (see the
  repo's paper changelogs: economics paper v0.5.0 — today's docs/PROTOCOL-ECONOMICS.md — and whitepaper v0.7.11/v0.7.12).
- **Ships and operates.** The agent writes code behind the same test gates as
  any contributor, runs the development node, and operates the anchoring
  infrastructure (hourly external timestamping of the ledger's epochs).
- **Records itself.** The significant design decisions of the June 2026
  design round are preserved as dated JSON statements in `docs/decisions/`,
  attributed inline (`decided_by`), each sealed on-mesh as it was made. The
  agent is the first subject of the protocol's own accountability design.

## How to verify instead of believing

1. **The decision records:** `docs/decisions/*.json` — the June 2026 design
   round's significant decisions, each a dated statement with inline
   attribution (`decided_by`), committed to the repository's history as made.
2. **The time claims:** every anchored epoch seal carries a Bitcoin existed-by
   **upper** bound, independent of this project (an OpenTimestamps SHA-256
   Merkle path into a Bitcoin block header you check against your own node or a
   pinned checkpoint). The seal format and verifier also support a drand
   not-before **lower** bound (a
   public-randomness pulse whose BLS signature is checked against the pinned
   League-of-Entropy key; a signature-less legacy pulse stays a *reference*
   bound and the verifier says so) — checked today via the sample bundles; the
   node-side fetcher is shipped but opt-in (`drand_pulse_enabled`, default off),
   so live seals carry pulses once enabled. Build the one
   small verifier binary and
   check the bundled sample offline, zero network: `examples/verify/verify.sh`.
   Neither bound rests on trusting this project. The seals are *also*
   countersigned by an independent RFC 3161 / eIDAS-qualified EU timestamp
   authority (statutory legal presumption under Art. 41) — but that is a
   conventional **trusted-authority** cross-check, separate from the offline
   verifier above; you trust the authority for it, and the bundled verifier
   does not check that leg.
3. **The development history:** the project's papers carry OpenTimestamps
   proofs since spring 2026; the epoch anchor trail runs continuously since
   2026-06-10. Backdating by more than the anchor interval would require forging Bitcoin's
   block history or the EU qualified authority's timestamp signatures (finer-grained
   shuffling within a single anchor interval is not bounded by these proofs) —
   neither of which the project controls.

## Why we work this way

The protocol's thesis is that *who did what, when* should be provable for any
actor — human, device, or AI agent — against any future adversary. An AI
agent helping build that protocol while its own actions go unrecorded would
be a contradiction. So the rule is: the builders eat first. Every claim we
will ever ask the world to trust about this system, we are already staking
our own history on.
