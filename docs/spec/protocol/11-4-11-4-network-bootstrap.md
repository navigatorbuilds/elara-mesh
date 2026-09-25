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

Beat incentives during this phase are elevated — early validators earn disproportionate rewards to compensate for the network's low utility. The bootstrap distribution (participation faucet) is described in Section 9.5 of the whitepaper.

**Phase 3: Decentralization Threshold (nodes 1,000–10,000)**

At 1,000 active witness nodes across at least 10 geographic regions, the protocol reaches its **decentralization threshold.** At this point:

- Genesis anchors' special trust status expires (they become regular anchor nodes)
- Governance transitions from founding team to beat-weighted voting
- The protocol is self-sustaining — no single entity can disrupt consensus

**Phase 4: Critical Mass (10,000+ nodes)**

The network effects take over. Developers build on the protocol because users are there. Users join because developers have built tools. Institutions adopt because the network is too large to ignore.

*Status: Phases 3 and 4 describe the plan. In the current implementation the genesis authority's privileged powers have no expiry and no decentralization threshold is detected (Section 11.12.3 of the whitepaper).*

The bootstrap problem is real, but it is a solved problem in practice. The challenge is not technical — it is social. The protocol must be useful enough that the first 1,000 people choose to run nodes. Section 3.5 (Minimum Viable Validation) is the answer: the protocol is useful to a single person with a single device before anyone else joins.

**Fast Snapshot Sync for Onboarding (v0.7.7)**

Once a zone has sealed its first few hundred epochs, genesis replay becomes impractical for new full nodes. A 10M-record zone with 100K epoch seals takes hours to reconstruct from scratch. The protocol addresses this with **epoch-indexed state snapshots** served by archive nodes:

1. Archive nodes (node_profile = Archive, §11.3) emit a signed state snapshot every `archive_snapshot_every_n_epochs` (default 10). Each snapshot is a JSON artifact at `epoch-{N:012}.json` — zero-padded for lexicographic ordering equals numeric ordering — containing: epoch number, SHA3-256 checksum of the contained state, full ledger snapshot, per-zone epoch cursors, zone registry root, Merkle tree roots, and the archive node's signature over the checksum (ML-DSA-65, FIPS 204, named "Dilithium3" in the code, always; a second SPHINCS+ leg is added when the archive runs signing Profile A — the SPHINCS+ fields are absent otherwise).
2. Retention is bounded: archives keep the last `archive_snapshot_retention` snapshots (default 20) and prune older files. At the default cadence of 10 epochs per snapshot (10 min at the default 60 s epoch interval), 20 retained snapshots cover about 3.3 hours of state history. The adaptive 5–60 s interval (Section 11.12; its sealing gate is off by default) would shorten this to as little as about 17 minutes under sustained load.
3. A new node onboards by: (a) fetching the snapshot index from a peer via `GET /snapshot/epochs` (returns sorted epoch list); (b) downloading the latest snapshot via `GET /snapshot/epoch/{N}`; (c) verifying the signatures and the checksum, and accepting the snapshot only if its signer is the genesis authority or an operator-configured trusted signer (by default the genesis authority alone); (d) comparing its checksum with the same epoch's snapshot from up to three other connected peers that offer it, aborting on any mismatch; (e) applying the snapshot to its local state; (f) fetching only records produced *after* epoch N via the standard delta sync path (§11.22.1 Merkle proofs + gossip). Onboarding time collapses from hours to minutes.
4. Snapshot emission resumes from the highest on-disk epoch on archive restart — the archive does not re-emit snapshots it has already written. Snapshot *emission* is archival-only — full-zone and light nodes never produce snapshots; *consumption* is open to any onboarding node (step 3 above), after which non-archive nodes pull records directly.

**Safety under compromised archive:** A signature proves who produced a snapshot, not that its state is correct, so a joining node accepts snapshots only from the genesis authority or from signers its operator has configured — by default the genesis authority alone. It also compares the snapshot's checksum with the same epoch's snapshot from up to three other connected peers that offer it and aborts on any mismatch; a peer that does not offer the epoch is not a disagreement, so a network with a single archive is accepted on the signature alone. Snapshots never replace the attested epoch seal chain; they are an acceleration mechanism for consensus-identical state.

**Scale limit:** a snapshot carries the set of already-applied record ids only while the serving chain has at most one million applied records; above that the set is sent empty, and the joining node's protection against re-applying a pre-snapshot record is best-effort (a bounded watermark that removes this limit is designed but not yet built).

**Testnet status:** Epoch-indexed snapshots are implemented in the Elara Runtime (public `v0.2.0` release, `archive_snapshot_loop`); an archival anchor node has been observed emitting epoch-indexed snapshots (e.g. `epoch-000000004004.json`) under the default 10-epoch cadence.

