#### 7.5.3 Zone Lifecycle: Activity-Driven Split and Merge (v0.7.7)

> **PARTIALLY IMPLEMENTED — authority-gated, not autonomous.** The
> `TRANSITION_SPLIT`/`TRANSITION_MERGE` seal types, their structural
> validation, canonical signing encoding, and multi-anchor signature
> verification ship in the runtime (`zone_transition_seal.rs`); what is not yet
> live is autonomous account-rehoming across the split (see §14.8). Signed records carry no
> zone binding in their signed bytes (wire format v6 added a network binding, not a
> zone binding), so activating this mechanism safely
> requires a wire-version transition that adds that binding first — a decided
> one-way door, gated before any federation (see the MESH-BFT merge-semantics
> design notes in the runtime repository). What *is* shipped is the zone
> auto-scaling **decision engine** (activity tracking with hysteresis, split/merge
> recommendations, and dynamic zone-count routing — the `elara-zone-autoscaler`
> crate); the per-zone transition-seal protocol below is the design it will
> eventually drive. See also the limitation in §14.8.

**The problem:** Semantic zones are static in §7.5.1 — an operator picks `medical/eu/west` at creation time and the zone carries its full traffic forever. At 1M-zone scale, some zones will become hot (thousands of records per second) while others go cold (weeks between records). A single zone cannot scale past a single anchor's capacity; a cold zone wastes witness attention. The protocol needs a dispute-free mechanism to split hot zones and merge cold ones without interrupting finality.

**Solution: Anchor-attested transition seals.**

Each zone tracks its own activity: records-per-second over a rolling 1-hour window, average epoch inclusion count, and ledger account cardinality. Two configurable thresholds define the lifecycle:

- **Split threshold** (shipped default: average zone rate above **40 rec/sec** — 2× the 20 rec/sec per-zone target rate — held for 4 consecutive scaler ticks) — zone forks into two child zones.
- **Merge threshold** (shipped default: average zone rate below **2 rec/sec** — 0.1× the per-zone target — held for 4 consecutive scaler ticks; the design adds an account-cardinality floor not yet enforced) — sibling cold zones coalesce with their parent.

**Split protocol:**

1. The anchor observes its zone is above the split threshold. It computes a deterministic split key by SHA3-256 hashing the account_id of each account in the zone; accounts with `key[0] < 0x80` go to child A, the rest to child B. Account-hash redistribution is verifiable by anyone holding the zone's SMT (§ Stage 2, MESH-BFT).
2. The anchor proposes a **transition seal** — an epoch seal with the special `TRANSITION_SPLIT` flag, containing: parent zone path, child A path, child B path, account→zone assignment Merkle root, parent ledger state at split epoch, child A opening balance_total, child B opening balance_total.
3. The transition seal is attested by at least 2/3 of the parent zone's stake-weighted witnesses (standard epoch settlement rules). Once zone-settled, both child zones begin sealing epochs independently from the next epoch number.
4. Clients rebuild their account→zone routing by walking the transition seal chain. Pending cross-zone transfers (whitepaper §11.22.2) targeting the parent zone are redirected to the correct child by account hash.

**Merge protocol:**

Symmetric to split. Two sibling zones under the merge threshold for 24 hours jointly propose a `TRANSITION_MERGE` seal signed by both anchors. The merge seal combines both ledger states; conservation is preserved because `merged.balance_total = sibling_A.balance_total + sibling_B.balance_total`.

**Dispute-free property.** Transition seals are epoch seals — they inherit the safety properties of §11.12. There is no separate voting mechanism, no new attack surface. A Byzantine anchor proposing a bogus split produces a seal that witnesses will reject (the account→zone Merkle root will not match their independent computation).

**Implementation status:** The activity-tracking and decision layer is shipped in the Elara Runtime (the `elara-zone-autoscaler` crate, re-exported through `auto_scale.rs`: hysteresis-gated split/merge recommendations and anchor-signed zone-count transition records with hash-based re-routing). The transition-seal protocol above — per-zone forking with account→zone assignment Merkle roots and balance-partition seals — is partially implemented: the runtime constructs, signs, and verifies `TRANSITION_SPLIT`/`TRANSITION_MERGE` seals (`zone_transition_seal.rs`, proposed via `POST /transitions/propose` and applied on the health tick), but the seals are authority-gated and autonomous account-rehoming across the split is not yet live (§14.8). A shipped seal is accepted on a fixed count of distinct, valid anchor signatures (four for a split, seven for a merge), not on the stake-weighted witness attestation of step 3. Existing tests cover the decision engine and seal validation, not end-to-end seal-based migration.

---

