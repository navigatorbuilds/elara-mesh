### 11.4 Network Bootstrap

**The problem:** The first node has no witnesses. The second node has only one possible witness. How does a trust network start from zero?

**Phase 1: Genesis Anchor (nodes 1–10)**

The founding team operates the first anchor nodes. These nodes are explicitly identified in the protocol's genesis block as **genesis anchors** — trusted not by accumulated attestation, but by their role in creating the network. This is centralization, and it is acknowledged openly.

Every decentralized network starts centralized. Early proof-of-work networks had one miner. Smart contract platforms launched with foundations. The difference is the exit plan.

**Phase 2: Early Growth (nodes 10–1,000)**

Genesis anchors actively attest to new nodes' identity registrations. Early participants earn elevated trust through:

- Direct attestation by genesis anchors (bootstrapping trust)
- Participation in testnet validation (proving reliability)
- Contribution to the codebase, documentation, or tooling (proof of commitment)

Beat incentives during this phase are elevated — early validators earn disproportionate rewards to compensate for the network's low utility. The distribution schedule and bootstrap economics are specified separately.

**Phase 3: Decentralization Threshold (nodes 1,000–10,000)**

At 1,000 active witness nodes across at least 10 geographic regions, the protocol reaches its **decentralization threshold.** At this point:

- Genesis anchors' special trust status expires (they become regular anchor nodes)
- Governance transitions from founding team to beat-weighted voting
- The protocol is self-sustaining — no single entity can disrupt consensus

**Phase 4: Critical Mass (10,000+ nodes)**

The network effects take over. Developers build on the protocol because users are there. Users join because developers have built tools. Institutions adopt because the network is too large to ignore.

The bootstrap problem is real, but it is a solved problem in practice. The challenge is not technical — it is social. The protocol must be useful enough that the first 1,000 people choose to run nodes. Section 3.5 (Minimum Viable Validation) is the answer: the protocol is useful to a single person with a single device before anyone else joins.

#### 11.4.1 Epoch-Indexed State Snapshots (v0.7.9+)

Once a network accumulates 10M+ records across its zones, replaying the DAG from genesis to derive ledger state becomes cost-prohibitive for new joiners and for any node recovering from a storage wipe. The protocol solves this with **epoch-indexed snapshots**: archive-profile nodes emit signed snapshots at epoch boundaries (default: every 10 epochs, retention 20), published at deterministic paths of the form `/snapshot/epoch/{N}` and listed via `/snapshot/epochs`.

A snapshot is authoritative state, not a replay hint. It includes:

- The complete ledger (`total_supply`, per-account balances, active stakes, staked totals, trust scores, continuity scores) as of the snapshot boundary.
- The set of record IDs whose beat ops have already been applied to that ledger (`applied_record_ids`). This set is what lets a bootstrapping node seed its `CF_APPLIED` dedup column family, so any pre-snapshot record re-delivered via delta sync or gossip is recognized as already-accounted-for and skipped at the ledger-apply gate — no double-apply, regardless of gossip redelivery order.
- The finalized-record set, last-seal metadata per zone, genesis state, and bootstrap phase.
- A snapshot timestamp (`snapshot_timestamp`), which is the cursor the subsequent delta-sync loop resumes from.
- A Dilithium3 signature over the canonical serialization, signed by the emitting archive node's identity key. The signer's public key is embedded so verifiers need no out-of-band trust.

**Bootstrap algorithm.** A joining node:

1. Queries `/snapshot/epochs` from its seed peers and selects the highest-numbered epoch that is available on at least two independent peers.
2. Downloads the full snapshot from the primary peer via `/snapshot/epoch/{N}`.
3. Cross-verifies the snapshot's Merkle checksum against up to three other peers' `/snapshot/epoch/{N}/checksum` endpoints. Any mismatch (primary says root `R` but another peer says `R' ≠ R`) aborts the bootstrap. Silence (peer has no snapshot for `N`) is not a disagreement.
4. Verifies the Dilithium3 signature against the embedded public key and checks the signer satisfies the local trust policy (anchor, archive, or allow-listed peer).
5. Applies the snapshot as authoritative state: the ledger replaces any partial local ledger; `CF_APPLIED` is bulk-seeded with the snapshot's `applied_record_ids`; the finalized set, genesis state, and bootstrap phase are restored; and the `pull_catchup_cursor` is advanced to `snapshot_timestamp`.
6. From that cursor, delta sync fetches only records newer than the snapshot — the ~9.99M pre-snapshot records on a 10M-record chain are never downloaded.

**Profile-scoped behavior.** The cursor-advance in step 6 is conditional on node profile. `Light` and `FullZone` profiles seed the cursor and skip pre-snapshot record fetches entirely — the snapshot is authoritative for all state they need; retention policy would prune old records anyway. `Archive` profiles — the historical source of truth — do **not** seed the cursor, so delta sync backfills pre-snapshot records from timestamp zero for DAG completeness. CF_APPLIED dedup still prevents any ledger double-apply; Archive just additionally retains the record bytes and DAG edges.

**Why signed and cross-verified, not just signed.** A single archive node's signature vouches that _it_ computed this state at that epoch — not that the state is correct. A colluding peer could serve a forged snapshot signed with its own legitimate key. Cross-peer Merkle-root verification protects against that class of attack: an honest peer that emitted its own snapshot at the same epoch will have a different root if the primary's snapshot is forged. Silence is allowed because not every peer is configured as an archive emitter; disagreement is not. This matches the pattern used for super-seal verification in §11.12.

**Retention and liveness.** Archive nodes hold the last `retention` snapshots (default 20) and prune older ones lazily to bound disk growth at `20 × snapshot_size`. Snapshots are emitted every `every_n_epochs` (default 10) — at a 60-second P50 epoch, that's a new bootstrap anchor every ten minutes, with a ~200-minute window of historical bootstrapping options.

#### 11.4.2 Storage Tiers and Snapshot Pricing

See §12.2 for how snapshot emission interacts with the Light / FullZone / Archive retention profiles, and how the delegated-storage market in §12.2 prices snapshot serving alongside cold-tier record serving.

