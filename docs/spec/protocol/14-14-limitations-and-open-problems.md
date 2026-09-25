## 14. Limitations and Open Problems

This section acknowledges known limitations and unsolved problems. An honest protocol is a credible protocol.

**14.1 No Proof of Creation**

The protocol proves possession and timing, not creation. A thief who hashes stolen content before the creator validates it will have temporal priority. Incremental validation (Section 11.7) and composite attribution (Section 6.3) mitigate but do not eliminate this fundamental limitation. No cryptographic system can prove that a key holder is the original author of content.

**14.2 Cold Start Economics (Public Network Only)**

The public network's beat economy requires network effects to be self-sustaining. During the cold start phase (0–1,000 nodes), beat utility is low, making it difficult to attract validators. The elevated early rewards (Section 11.4) address this, but the actual incentive sufficiency is unproven and will require testnet data to validate. Private network deployments (Section 10.6) do not experience cold start problems — they operate with organizational trust from deployment day one.

**14.3 Post-Quantum ZKP Immaturity**

Lattice-based and hash-based zero-knowledge proof systems are active research areas without production-grade implementations. The Phase 2–3 quantum migration path (Section 11.26) depends on these constructions maturing on the projected timeline. If they do not, the PRIVATE and RESTRICTED classifications retain a quantum vulnerability window longer than planned.

**14.4 Governance Capture (Public Network Only)**

Beat-weighted governance on the public network is vulnerable to plutocratic capture — entities with large beat holdings can dominate voting. The conviction voting mechanism and voting caps (Section 10.3) mitigate this, but concentrated beat accumulation over decades could shift governance power. Long-term governance resilience remains an open research question for all decentralized protocols. Private network deployments use organizational governance structures and are not subject to this limitation.

**14.5 Storage Sustainability at Full Scale (Public Network Only)**

At full IoT scale (~7 PB/year), the public network's archive node infrastructure requires significant and growing investment. The economic model assumes that storage costs continue declining and that beat incentives sufficiently compensate archive operators. If storage economics shift unfavorably, the protocol may need to introduce more aggressive pruning than currently specified. Private network deployments manage storage through organizational budgets and infrastructure, without beat-dependent storage incentives.

**14.6 Formal Verification Completeness**

The TLA+ consensus specification (Section 11.31) is TLC-model-checked at bounded scale — a 36-model gate covering safety (no conflicting finalization, diversity-penalty soundness, cross-zone sealed-abort exclusion), supply conservation, and liveness (cross-zone settlement, in-zone epoch-seal, and cross-epoch seal recurrence), with each Byzantine-threshold and guard-necessity bound shown tight in the bounded models (`spec/tla/`). The post-quantum transport and realm-admission layer is symbolically verified in ProVerif (`spec/proverif/`). What remains open: the checks are at bounded scale, not an unbounded proof; the liveness models use uniform stake, set the record creator's stake to zero and let Byzantine proposers only withhold, so they miss that seal settlement is not live and that the rank is not split-neutral, and their passing configurations assume the unsteerable beacon that the shipped code does not yet provide (Section 11.12.3 of the whitepaper); the refinement mapping from each TLA+ action to its Rust function is an English-plus-code-grep argument, not a mechanized (TLAPS or Coq) proof of the implementation; and the companion paper has not yet been circulated to external reviewers. The consensus mechanism should therefore be considered model-checked at bounded scale with a written refinement argument, not mechanically proven at the implementation level.

**14.7 Regulatory Uncertainty**

Securities classification of the beat remains jurisdiction-dependent and ultimately determined by regulators, not protocol design. The utility-first approach — the beat is earned through verification work and is never sold, listed, or traded (Sections 9 and 11.17) — represents best-effort mitigation, not a guarantee.

**14.8 Zone Split/Merge Is Partially Implemented — Account Rehoming Is Not**

The zone lifecycle mechanism of Section 7.5.3 is now partially in the runtime: the `TRANSITION_SPLIT`/`TRANSITION_MERGE` seal types, their structural validation, canonical signing encoding, and multi-anchor signature verification ship (`zone_transition_seal.rs`); the auto-scaler constructs transition proposals from live per-zone activity; and every node runs the scaling calculator — with *emission* authority-gated: only the genesis authority emits the `zone_transition` record that actually moves the network. What does **not** ship: account→zone rehoming (redistribution proofs, balance-partition execution) — a transition changes zone routing, but no account state migrates yet. Because a record's signed bytes carry no zone binding (wire format v6 added a network binding, not a zone binding), full permissionless activation remains gated behind a wire-version transition that adds that binding (a constraint of the same kind as the one that led to the Network Publication reframing in §10.6.3–10.6.4). The safety claims of §7.5.3 (e.g., witnesses rejecting a bogus split) remain design analysis, not tested multi-node behavior.

**14.9 The drand Not-Before Bound Is Opt-In, Not Yet Network-Default**

Each epoch seal's time bracket has two legs. The Bitcoin *existed-by* upper bound (OpenTimestamps) is live on every anchored seal and offline-verifiable today. The drand *not-before* lower bound is now supported end-to-end: the seal format and the offline verifier (BLS verification against the pinned League-of-Entropy key) are exercised by the published sample bundles, and the node-side beacon fetcher has landed — a seal-producing node that enables it embeds League-of-Entropy pulses in its seals, and pulse-bearing seals produced this way verify offline. The fetcher is deliberately opt-in (`drand_pulse_enabled` defaults to false, so a producer never emits new seal metadata by surprise). Until it is the network default, the not-before guarantee applies only to seals that carry an embedded pulse, and the verifier reports the distinction rather than overstating it.

**14.10 Network Publication Is Not Live (Disabled in Code)**

The NETWORK_PUBLISH / Validation-IPO transition (Sections 10.6.3–10.6.4) — importing a private network's historical records *into* public consensus where they gain retroactive native standing — is **disabled at compile time** (`NETWORK_PUBLISH_ENABLED = false`, `src/network/publish.rs`). It was found unsound: when it was disabled, a record's signed bytes carried no realm/network binding, so an imported record was consensus-indistinguishable from a native one, and MESH-BFT's single-network safety theorem does not cover adopting a foreign network's records as native settlement parents (Assumption A8, `docs/MESH-BFT-MERGE-SEMANTICS.md`). Since wire format v6 each new record signs its network identifier and a node rejects a record that names a different network; records at v4 and v5, which nodes still accept, and records that name no network, carry no binding. The mechanism is being reframed to **inert-import** — public consensus attests only that a publication *bundle* existed at an anchored time, conferring zero native standing — pending a proven multi-root merge theorem. Sections 10.6.3–10.6.4 describe the original (disabled) design and are bannered accordingly.

---

