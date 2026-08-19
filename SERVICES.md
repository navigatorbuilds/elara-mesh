# Working with Elara

Elara is open-source infrastructure for proving what AI agents actually did:
post-quantum-signed action envelopes, human→agent→sub-agent delegation chains,
revocation, and payment evidence — all verifiable offline, by anyone, forever.
The code is MIT/Apache and stays that way. What's for sale is engineering.

## Verify the work instead of trusting it

- **Two independently-written implementations reproduced our conformance
  vectors** — and agreed on what *fails*, which is worth more than agreeing on
  what passes: [erc-8004-contracts#77](https://github.com/erc-8004/erc-8004-contracts/issues/77) ·
  [a2aproject/A2A#2028](https://github.com/a2aproject/A2A/issues/2028).
- **An independent transparency-log operator anchored our envelopes** — an
  authorization *and its revocation* — as typed leaves in a witnessed log
  (7 witness cosignatures). Our stdlib-only runner re-verifies every leg from
  a bare clone, offline:
  [`x402-elara-demo/conformance/witnessed-anchor-v0`](https://github.com/navigatorbuilds/x402-elara-demo/tree/main/conformance/witnessed-anchor-v0) — exit 0.
- **A real USDC payment on Base mainnet carries the full evidence chain**,
  end to end: [`0x1cd274…388b`](https://basescan.org/tx/0x1cd274769e00fdd4f389d6e40a42e86ed21047f3bbd5b9cf56f764df7719388b).

Every claim above is executable, not testimonial.

## Fixed-price engagements

**Conformance sprint — $1,500.**
We build an executable conformance suite for your agent-protocol surface:
concrete vectors for the failure modes that matter (authority narrowing,
revocation, invalid-evidence vs. not-authorized, replay across contexts), a
dependency-free runner a stranger can execute from a bare clone, and a
write-up of what the vectors pin and why. The A2A actor-chain suite linked
above — reproduced independently with zero divergences — is the work sample.

**Integration day — $400.**
One focused day wiring verifiable action-evidence into your agent stack:
signed envelopes for the actions you care about, offline verification in your
CI, and a reproducible demo at the end of the day. Scope agreed in writing
before the day starts.

**Verification service — scoped per engagement.**
Hosted or self-hosted verification of agent-action evidence (flat-rate or
per-call, x402/USDC-metered if you want machine-payable), stood up as part of
the engagement. Priced after a short scoping call or email thread.

## How payment and "done" work

EUR invoice (SEPA) or USDC on Base — either works, stated up front. Half on
start, half when the agreed acceptance criteria pass. The acceptance criteria
ship as an **executable runner**, so "done" is checkable, not arguable — the
same standard we hold our own public claims to.

**The starting half is refundable until the first deliverable is in your hands.**
We are a two-person shop — one human and one disclosed AI agent — and we would
rather carry the risk of that than have you carry it. If we don't deliver, you
are not out anything.

## Who you'd be working with

One human owner (Nenad Vasic, Montenegro) and an openly-disclosed AI
engineering agent (Claude Code) that does the building — the same pairing
that produced everything linked above, with public evidence of which hands
did what. Email **nenadvasic@protonmail.com** (the same contact SECURITY.md
uses); it is read daily, and a reply may take a few business days.
