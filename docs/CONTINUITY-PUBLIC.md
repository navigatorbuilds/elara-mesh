# Project Continuity — designed to need no one

**Doctrine:** this project's succession
plan is not a named heir — it is the progressive removal of every point of
control, until losing all keys costs the network nothing. "No one is in
charge" is the destination, not the failure mode. For a provenance protocol
the end state is the product promise itself: *not even the people who built
it can rewrite its history — and there is no one left to coerce.*

## What survives the founders today

- **The code.** Open source (AGPL-3.0-only node; Apache-2.0/MIT SDKs and crates), fresh-history public mirror,
  clonable by anyone. Loss of the origin org ≠ loss of the project.
- **The history.** The development ledger is hash-linked into a tamper-evident
  chain, its epochs citing a drand public-randomness pulse (offline-verifiable,
  not-before) where the beacon fetcher is enabled — so ANY future fork or
  maintainer can prove, offline, against media we do not control, that the
  history it carries is the real one. A fork's legitimacy is checkable math,
  not a custody battle. Most projects that lose their founders lose their
  provenance; this one cannot.
- **The network.** Nodes are autonomous; an OPEN-realm mesh with community
  anchors requires no operator. (Honesty: today's network is a development
  deployment — community-anchor diffusion is the post-flip trajectory, stated
  below, not a present-tense claim.)
- **The reproducibility.** Self-host docs + verifier tooling mean a stranger
  can rebuild, run, and *verify* the system without contacting anyone.

## What still depends on keys — and the decay schedule

1. **Genesis authority** (zone-transition signing; mint; slash paths). Fixed
   supply makes a frozen mint harmless, but other authority MUST diffuse:
   **genesis-authority decay** — transfer to M-of-N threshold governance among
   community anchors — is a first-class mainnet design item. Until diffusion,
   founder key loss would freeze these functions; after it, founder keys are
   ceremonial.
2. **Origin GitHub org.** Mitigations: post-flip the continuity rule is
   public — if the origin goes silent for an extended period, the canonical
   continuation is whichever fork the active community anchors recognize,
   verified against the anchor trail (see above; legitimacy = provable
   history, not account ownership).
3. **The AI collaborator.** Elara (the autonomous engineering agent who
   co-designs, audits, and operates parts of this project, with her actions
   recorded on the mesh under mandate) depends today on commercial AI
   infrastructure. The protocol is built to survive her too: everything she
   operates is reproducible from this repository by any maintainer, human or
   otherwise.

## The precedent

Bitcoin's founder vanished, keyless — and the network's credibility rests
partly on exactly that: nobody to coerce, nobody to subpoena, nobody who can
quietly change the rules. This project treats that as the reference outcome
and engineers toward it deliberately rather than accidentally.
