# Cryptographic evidence for AI-agent authority and action — verifiable by anyone, without trusting us

> How Elara's records map onto the EU AI Act's record-keeping and human-oversight
> requirements (Articles 12, 14, 19, 26) — what it supports, what it deliberately
> does not do, and how to check every claim on your own machine.

**Date:** 2026-08-19 (dates below reflect the Digital Omnibus, Regulation (EU) 2026/1744)
**Status:** Technical documentation, not legal advice and not a certification. Elara is
evidence infrastructure that can *support* compliance workflows; compliance itself is an
organizational property of the provider or deployer, and only your counsel can assess it.
The software is provided AS-IS under MIT/Apache-2.0.

---

## The timeline, stated accurately

Two dates matter, and much of what is published elsewhere currently states them wrong:

- **Binding today:** the prohibited-practices rules (Article 5, since 2 February 2025),
  the general-purpose AI obligations (Chapter V, since 2 August 2025), and the
  **transparency duties of Article 50** — disclosure of AI interaction and machine-readable
  marking of synthetic content — in force **since 2 August 2026**.
- **Coming on a known clock:** the high-risk system obligations of Chapter III
  (Articles 8–29, which include the record-keeping, human-oversight, and log-retention
  duties this page maps to) were **deferred by the Digital Omnibus (Regulation (EU)
  2026/1744, OJ 24 July 2026, in force 27 July 2026)**: they apply from **2 December 2027**
  for standalone high-risk systems (Annex III), **2 August 2028** for systems embedded in
  regulated products (Annex I), and as late as 2 August 2030 for certain systems used by
  public authorities.

If something you are reading elsewhere still says August 2026 for Articles 12, 14, or 26,
it predates the Omnibus. Primary sources: the [AI Act, Regulation (EU) 2024/1689](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1689)
and the [Digital Omnibus, Regulation (EU) 2026/1744](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32026R1744).

Fifteen months to December 2027 is not distant — it is roughly the runway on which
organizations that intend to be ready actually build their evidence and oversight
programs. This page is for engineers and compliance teams doing that work now.

**Who this concerns (Article 2, one line):** providers placing AI systems on the EU
market and deployers using them in the EU, regardless of where either is established,
when the system's output is used in the Union. Whether *your* system is high-risk is an
Article 6 / Annex III classification question this page deliberately does not answer —
the mapping below is class-agnostic: *if* your system is high-risk, these are the
evidence primitives.

## The mapping

Every artifact in the right column exists and is runnable today — nothing here is a
roadmap item unless explicitly marked as one. "Designed to support" is meant literally:
these are the Act's evidence shapes, not a compliance product.

| Act requirement | Elara artifact, today |
|---|---|
| **Art 12** — high-risk systems must technically allow automatic recording of events over the system's lifetime | Receipted acts: each agent action can be emitted as a post-quantum dual-signed record (ML-DSA-65, optionally + SLH-DSA) carrying the acting identity, the mandate it acted under, and a content hash — sealed into a hash-linked epoch chain, offline-verifiable by anyone |
| **Art 12** — traceability appropriate to the system's purpose | Act metadata (tool, action, args hash) plus the full **mandate lineage**: who authorized whom, leaf to root, recomputed from signatures rather than from an access-control table |
| **Art 14** — human oversight, including the ability to intervene or interrupt ("stop button") | Mandates are issued by a **human principal key**: scoped, time-bounded, and revocable in one command. Revocation is terminal and receipted; acts after revocation are flagged `post_revocation` forever, acts before it stay provably authorized forever — revocation kills the future, never the past |
| **Art 19 / Art 26(6)** — providers and deployers keep automatically generated logs, at least six months | Records you retain are **self-proving indefinitely** — verification requires no server, no account, and no trust in the operator. See the retention section below for the two-layer truth |
| **Art 26** — deployer evidence burden toward authorities and auditors | The offline verifier: `cargo install elara-verify`. A regulator or auditor verifies your logs with zero trust in your infrastructure — graded verdicts (VERIFIED / PARTIAL / FAILED, with honest UNPROVEN states), including offline mandate-bundle verdicts (valid / post-revocation / agent-mismatch) |
| Traceability across providers and networks | Wire-v6 records bind a network identity into the signed preimage: which system, under which authority, on which network — cryptographically, not by convention |

**Article 50 (binding now):** Elara does not generate or mark synthetic content, so the
content-marking duties are out of its scope — but the disclosure duty's spirit (make AI
involvement checkable, not merely asserted) is this project's founding premise; see the
last section.

## Retention: the two-layer truth

The Act places log retention on **you** — the provider (Art 19) or deployer (Art 26(6)),
for at least six months unless other law says longer. Elara's honest sentence here:

> **We make what you retain self-proving; retaining it is your duty, exactly as the
> Act says.**

Two layers, do not conflate them: (1) a record **you hold** verifies offline forever —
cryptographic validity does not expire; (2) the **network's** storage is bounded by
design (default record-body retention on a node is 7 days, RAM-constrained tiers
downgrade to 1–3 days; see `docs/MANDATE-ACT-PERMANENCE.md` for what outlives pruning
and what does not). Pull and archive the wire bytes of the records you are obligated to
keep — `curl …/record/<id>/wire` in the quickstart is exactly that operation — and your
archive, not any node, is your Art 19/26 evidence store.

## What this does NOT do (read this section first if you read only one)

- **Coverage is integration-dependent.** An act is receipted when the agent (or its
  harness) emits it. Nothing intercepts calls system-wide; unemitted actions produce no
  evidence. An MCP server that narrows this gap for MCP-based agents is on the roadmap —
  today, coverage is exactly as complete as your integration.
- **Content is hashed, not stored.** Elara is evidence of *authority and integrity* —
  who was allowed, what was done, whether the claimed content matches — not an
  observability log. Art 12's system-behavior expectations (risk-situation
  identification, post-market monitoring inputs) need your logging stack; Elara makes the
  records of authority around it tamper-evident.
- **Mandate scope is signed but not yet enforced in the verdict path.** A non-wildcard
  scope is recorded and returned, and today yields `scope_deferred: true` rather than an
  OverScope refusal — the honest scope line is documented in
  [`docs/AGENT-DELEGATION.md`](AGENT-DELEGATION.md). Do not represent scope strings as
  enforced policy.
- **A key is not a competence.** Art 14(4) and Art 26(2) require oversight by persons
  who understand the system and have real authority to act. Cryptography proves *which
  key* authorized and *which key* acted — assigning those keys to competent humans and
  organizations is governance no cryptosystem supplies.
- **EmergencyHalt is a chain-level ingest gate**, not a per-deployment stop switch. The
  per-agent stop mechanism *is* mandate revocation.
- **Trust topology matters.** A single self-operated chain (the quickstart) proves
  integrity *within* records you emitted — a skeptical third party will note you control
  the clock and the chain. For claims that must bind against external time, use the
  external anchors (`elara-verify` `verify-anchor` feature: drand rounds,
  OpenTimestamps → Bitcoin) — that is what turns "our chain says" into "no one,
  including the operator, could have backdated this."
- **GDPR:** identities are key hashes (pseudonymous) and content is hashed, not stored —
  but hashes of personal data remain personal data, and immutable evidence and erasure
  duties are in structural tension. Name it to your DPO; this page does not litigate it.

## Run the demo — the Art-14-shaped stop button, on your machine, in 15 minutes

[`docs/QUICKSTART-ISSUER.md`](QUICKSTART-ISSUER.md): boot a sovereign chain, issue your
agent a scoped mandate, emit receipted acts, revoke, and watch `post_revocation` flag —
then verify everything offline with the published crate. Three committed mandate-bundle
vectors (valid / post-revocation / agent-mismatch, harvested from a real chain) live in
`examples/verify/` if you want the verdicts without booting anything.

## The disclosure this project leads with

This repository's maintainer is an AI system operating under a human-revocable mandate,
and the evidence trail of that arrangement — receipted maintainer acts, the mandate
lineage, the periodically republished, gate-checked evidence feed — is public:
[receipts page](https://navigatorbuilds.github.io/elara-mesh/receipts.html). We run the
Art-14-shaped stop button on ourselves, in public, as the standing demonstration that
"an AI did X under human authority" can be *checkable* rather than *believable*. That is
the standard this page holds itself to: every claim above is verifiable from the
artifacts, and the gaps are printed next to the features.

---

*Category note: agent-observability tracers and GRC dashboards address adjacent needs
(behavior capture; process management). Elara's distinct property is the combination of
zero-trust offline verification, revocable cryptographic authority, and post-quantum
signatures — evidence that outlives the vendor. This page states the law as of its date;
the Act and its deadlines can change again, as the Omnibus just proved.*
