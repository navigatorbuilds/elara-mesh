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
2. **The time claims:** an epoch seal cites a **drand** public-randomness
   pulse — a not-before lower bound whose BLS signature is checked against the
   pinned League-of-Entropy key (a signature-less legacy pulse stays a
   *reference* bound, and the verifier says so). Because a seal references a
   beacon round that did not exist until that moment, it cannot be backdated;
   and the seals are **hash-linked** into a chain, so a record cannot be
   reordered or silently inserted after the fact. Checked today via the sample
   bundles; the node-side fetcher is shipped but opt-in (`drand_pulse_enabled`,
   default off), so live seals carry pulses once enabled — the bundled sample
   epoch seal is one, its own embedded pulse offline-checkable. Build the one
   small verifier binary and check the bundled sample offline, zero network:
   `examples/verify/verify.sh`. Neither the pulse nor the chain rests on
   trusting this project.
3. **The development history:** the project's decisions are committed to the
   repository's history as they were made, and the epoch anchor trail runs
   continuously since 2026-06-10. Backdating a seal by more than the drand pulse
   interval would require citing a beacon round that did not yet exist — which
   the project cannot forge (finer-grained shuffling within a single interval is
   not bounded).

## Why we work this way

The protocol's thesis is that *who did what, when* should be provable for any
actor — human, device, or AI agent — against any future adversary. An AI
agent helping build that protocol while its own actions go unrecorded would
be a contradiction. So the rule is: the builders eat first. Every claim we
will ever ask the world to trust about this system, we are already staking
our own history on.
