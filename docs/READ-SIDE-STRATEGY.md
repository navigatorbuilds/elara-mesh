# Read-Side Strategy — what's behind the corner

**A strategic read of where the value lands.** Thesis: the project has invested
almost entirely in the WRITING side of the ledger (records, seals, anchors,
mandates). Value will be judged
on the READING side — and the readers arrive on a regulatory/insurance
schedule that is FASTER than our network-effect schedule.

## 1. The verifier is the product

Single-file, offline, boring: record + delegation chain + anchor proofs in →
plain-language verdict out ("not-before <date> per drand round N (BLS-verified);
signed under valid mandate from <principal>, scope <s>; flags: none").
No node, no network, no trust in us. CLI first (builds on `light_verify.rs`
+ `light_sdk.rs`), WASM page second (same core, drag-and-drop). Until this
exists our evidence is expert-only — which recreates the middleman we claim
to remove. Grant-deliverable shaped; adoption wedge; the demo that makes
everything else legible.

## 2. Compliance buyers arrive before believers

- **EU AI Act** high-risk provisions phase in 2026–27; **Article 12**
  (record-keeping): automatic logs + lifecycle traceability for high-risk AI
  systems. Mandates + flags + anchor trails ARE the provable version of this.
  Position as compliance artifact ("Article 12 logging, cryptographically
  verifiable"), not as crypto-adjacent infrastructure.
- **Agent liability insurance** is the second forcing function: insurers will
  demand provable mandate-compliance to price agent risk. Delegation chains =
  the seatbelt standard.
- **eIDAS unlock (cheap, huge):** qualified timestamps carry legal presumption
  by statute in the EU. Add ONE eIDAS-qualified TSA as a braid leg (even one
  stamp/day over the running root). Records then enter EU proceedings with
  statutory weight. Action: identify a qualified TSA with API access +
  per-stamp pricing; add as leg 4 of the anchor braid.

## 3. Agents are the first mass customer (not just the subject)

Operators of agents need to prove what their agents did: billing (verified
work), liability, enterprise procurement. Distribution channel: **`elara-mcp`**
— an MCP server exposing "sign this action into the mesh" / "fetch my
provenance" tools to any MCP-speaking agent framework. Small Rust crate;
rides Lane 3. The accountability layer sells as the agent-economy's receipt
system.

## 4. We are the first Validation IPO — deliberate dogfood

Our own ops already form a long-running private provenance network: OTS-
stamped papers (since spring), anchored epochs (since 2026-06-10), full
commit/audit history. Run it as the reference deployment; pitch with "verify
our own history yourself" instead of hypothetical factories. The first mandated
agent under AGENT-DELEGATION is the project's own build agent (commits signed
under a scoped mandate from the maintainer) — dogfood + unforgeable origin story.

## 5. Guardrail at flip time

The OPEN mesh starts at ~2 nodes and is trivially sybil-able; SAY SO. Frame:
our federated network progressively opening, anchored from day one,
decentralization earned not claimed (honest-claims rule applies to network
maturity, not just throughput numbers).

## Sequencing notes

Pre-Aug-1 candidates (bounded): verifier CLI thin slice; eIDAS TSA scouting
(research only, no spend yet); `elara-mcp` design sketch. Post-flip: WASM verifier, MCP crate publish, AI-Act positioning page.
