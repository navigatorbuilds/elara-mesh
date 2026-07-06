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

The TLA+ consensus specification (Section 11.31) is now implemented and TLC-model-checked at bounded scale — a 36-model gate covering safety (no conflicting finalization, diversity-penalty soundness, cross-zone sealed-abort exclusion), supply conservation, and liveness (cross-zone settlement, in-zone epoch-seal, and cross-epoch seal recurrence), with each Byzantine-threshold and guard-necessity bound proved tight by a reproduced counterexample (`spec/tla/`). The post-quantum transport and realm-admission layer is symbolically verified in ProVerif (handshake secrecy and mutual authentication, KCI and UKS resistance, forward secrecy, the record layer, full handshake-record composition, and membership-cert admission — `spec/proverif/`). What remains open is the *completeness* of that evidence, not its absence: the model checks are at bounded scale (small witness, zone, and epoch counts — sound for the stake-fraction safety arguments, but not an unbounded proof); the refinement mapping from each TLA+ action to its Rust function is an English-plus-code-grep argument, not a mechanized (TLAPS or Coq) proof of the implementation; and the companion paper has not yet been circulated to external reviewers. The consensus mechanism should therefore be considered *model-checked at bounded scale with a written refinement argument* — the bar Tendermint, HotStuff, and Diem shipped — not *mechanically proven at the implementation level*.

**14.7 Regulatory Posture**

Validation beats are an internal protocol mechanism — never offered, sold, listed, or traded — so the protocol carries no tradeable asset for a regulator to classify as a security. This is a design choice, not a legal opinion. Operators running private or sovereign realms remain responsible for any law applicable to the data they validate.

**14.8 Network Publication Is Not Live (Disabled in Code)**

The NETWORK_PUBLISH / Validation-IPO transition (Section 10.6.3–10.6.4) — importing a private network's historical records *into* public consensus where they gain retroactive native standing — is **disabled at compile time** (`NETWORK_PUBLISH_ENABLED = false`, `src/network/publish.rs`). It was found unsound: a record's signed bytes carry no realm/network binding, so an imported record is consensus-indistinguishable from a native one, and MESH-BFT's single-network safety theorem does not cover adopting a foreign network's records as native settlement parents (Assumption A8, `docs/MESH-BFT-MERGE-SEMANTICS.md`). The mechanism is being reframed to **inert-import** — public consensus attests only that a publication *bundle* existed at an anchored time, conferring zero native standing — pending a proven multi-root merge theorem. Sections 10.6.3–10.6.4 describe the original (disabled) design and are bannered accordingly.

---

