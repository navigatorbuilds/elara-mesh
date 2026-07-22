# Realms + Self-Assembly — design seed

A two-part architectural idea: (1) nodes find each other online and
self-assemble into the mesh — and after destruction or partition, surviving
parts re-find each other and re-home (the "liquid Terminator" image: the parts
just find their way back); (2) membership is tiered by privilege:
ordinary nodes self-assemble into the open mesh, while high-trust deployments
(government / military / special agencies) never auto-join anything — they run
their own network, minding their own business.

**Verdict: plausible — roughly 60% already built.** The remaining 40% is
well-understood engineering (no research risk), and the idea strengthens the
provenance positioning rather than fighting it.

## The load-bearing reframe: realm = exposure policy, NOT power

"High tier" must never mean "more say." It means **more isolation, chosen by
the operator**. Consensus weight stays exactly what it is today: per-zone
stake + diversity-weighted committees. A sovereign node gets *fewer*
connections, not more authority. This inverts the usual hierarchy and is the
anti-centralization invariant — the standing concern that a mesh could
eventually centralise around specific high-value nodes.

Three realms (discovery profiles):

| Realm | Who | Discovery behavior |
|-------|-----|--------------------|
| **OPEN** | public mesh, anyone | full self-assembly: mDNS + seeds + DHT + PEX |
| **FEDERATED** | consortiums (companies, hospitals, registries) | self-assembly *within* a credentialed membership; admission = Dilithium3-signed membership cert chained to the federation root key |
| **SOVEREIGN** | gov / military / agencies | never dials out, never beacons, denies unknown peers (inbound-rejection is design-stage — see *To build*); own root of trust, own genesis; optional one-way public anchoring (below) |

## Already built (the Terminator half)

- **LAN self-discovery:** `src/network/mdns.rs` — zero-infrastructure peer
  finding on the local network, feeds discovered peers into the DHT
  (`discovery.rs:625` wrapper).
- **PEX (peer exchange):** `pq_list_peers` in `discovery.rs` — peers learn
  peers from peers, over Dilithium3-TOFU-authenticated PQ transport (no HTTPS
  fallback since AUDIT-10).
- **Peer memory across death:** DHT routing table persists to disk
  (`dht.rs:454`) — a rebooted node redials its last-known world.
- **Seed bootstrap + reconnect heartbeat:** `discovery.rs` loop.
- **NAT traversal:** `crates/elara-nat/` (extracted standalone crate).
- **State rebirth:** archive snapshots + `/snapshot/state-delta` +
  divergence-repair — a destroyed-and-reborn node catches up without genesis
  replay. The node's *identity* is its Dilithium3 keypair: as long as the key
  survives, the reborn node IS the same part coming home.
- **Partition tolerance is native:** the DAM is a DAG, not a single chain —
  fragments keep writing locally and **merge** on re-contact (cross-zone merge
  is in the whitepaper §3.3.4 diagram; designed for interplanetary link gaps).
  Healing after fragmentation is the same machinery as normal operation.

## To build (the privilege half + hardening)

- **P1 — Realm admission (small slice, ships first):** `NetworkRealm` enum in
  `NodeConfig` (`Open` / `Federated{root_pk}` / `Sovereign`); one gate in the
  PQ handshake checking `network_id` + realm credential; Sovereign profile
  disables mDNS beaconing, seed dialing, and outbound PEX, and rejects
  unknown identities inbound. Mostly config + one handshake gate + tests.
- **P2 — Reassembly hardening:** signed peer records inside PEX
  (poison-resistance); boot-time redial-last-known with backoff; eclipse
  resistance via peer-selection diversity (ASN/geo — `asn_lookup.rs` already
  exists); a fragment-merge simulation test (split the sim net into islands,
  heal, assert DAG/zone merge converges — `elara-simulate` bin exists).
- **P3 — Sovereign one-way anchor bridge (the gem):** operator-triggered
  notarization of a sovereign network's state root into the public mesh.
  Private operation, public undeniability: an agency proves *that* its records
  existed at time T without revealing *what* they are. This is the provenance
  story at its strongest and a natural grant milestone.
- **P4 — Federation gateways (later):** explicit, policy-gated bridges
  between realms.

## Admission model — who decides a node's tier?

**Nobody — and that's the design holding, not a gap.** Realm is self-declared,
and self-declaration is harmless because realm confers zero authority:

- Declaring `Sovereign` = self-exile. You leave the public mesh; you affect
  nobody. A government's sovereign net is special only because the government
  controls its membership credentials — not because the protocol blessed it.
- Joining an existing `Federated` realm requires a membership cert **signed by
  that federation's root key** — the handshake gate rejects you otherwise.
  "Who decides" = the federation operator, for their own door only. Founding
  your own federation is permissionless (and gets you an empty club).
- **No global tier registry exists.** Boundaries are enforced from the inside:
  each member node locally verifies signatures against its own realm root.
  No central decision point, no extraction point.
- This is safe ONLY because tier grants no public-mesh advantage (no extra
  consensus weight / trust). If it ever does, everyone fakes it and a
  gatekeeper becomes necessary — never cross that line.
- Residual risk is social impersonation ("I'm the official Ministry node") —
  answered by the provenance machinery itself: institutions publish/anchor
  their root public keys; claims either verify against the known key or fail.
- PKI mechanics for P1: membership certs are Dilithium3-signed with expiry;
  federations publish internal revocation lists; federation root may be an
  M-of-N threshold quorum so no single admin is a single point of failure.

## Network lifecycle — the "IPO" event

The three ideas are ONE idea — the lifecycle of a network: born self-assembled
(sovereign/federated), lives private for years or decades, optionally goes
public. The "IPO" = a realm transition (SOVEREIGN/FEDERATED → OPEN, full or
SELECTIVE), and the protocol object for it ALREADY EXISTS ON PAPER:
**NETWORK_PUBLISH §10.6.3** (record 0x0E: scope, redaction policy,
SNAPSHOT/STREAMING/GRADUAL modes, completeness_proof) plus the mega-publisher
attack analysis (five failure modes, ingestion-cap formula). The record
plumbing exists in code but ships hard-disabled (`NETWORK_PUBLISH_ENABLED =
false`) pending the inert-import reframe.

**Design laws (non-negotiable for credibility):**
1. **Anchor-density law.** Without periodic external anchoring during the
   private years, post-hoc publication is cryptographically worthless theater:
   a sovereign operator owns every key and every clock in its realm and can
   fabricate a decade of internally-consistent history. Internal consistency
   proves nothing about WHEN. Backdating window = interval between anchors.
   "Your history is only as credible as your anchor trail" must be stated in
   the protocol and the whitepaper. (completeness_proof stops selective
   omission; it does NOT stop backdating — that gap is real.)
2. **Zero-standing rule.** Imported history confers NO public-mesh standing —
   no stake, no witness eligibility, no trust score. You arrive as a newcomer
   with a verifiable past, never as a veteran.
3. **Attestation semantics.** Public consensus attests ONLY: existence
   (anchors), identity continuity (key-rotation chain), and the publication
   event itself. It NEVER attests the internal truth of imported records.
   Publication ≠ endorsement — same honest-claims discipline as everything.
4. **Mandatory ingestion caps.** Whitepaper already proposes them; keep them
   protocol-level, not publisher-voluntary.

**Status:** design seed — not yet implemented. Realm admission is the
prerequisite first slice. The publication mechanism — "verifiable disclosure
of long-running private provenance networks" — is the flagship architecture
item of this design line.

## Open formal problem — multi-root settlement semantics

MESH-BFT's safety theorems are stated for a single network with one global
stake universe. Realms instantiate one MESH-BFT instance per realm, which is
sound in practice, but the cross-realm case is not yet formalized: merging
two independently-finalized DAGs across a publication boundary has no defined
conflict-resolution rule, and pre-merge finality across that boundary is
unproven. Until the multi-root theorem is stated, the interim rule is
conservative — imported history is attested as a sealed bundle (existence +
identity continuity + the publication event), and public consensus is never
extended over the internal conflicts of imported records. Stating the
multi-root + merge semantics formally is open work.

## Bootstrap of truth — concrete evidence from day one

A digital truth ledger cannot start from assumptions — it needs concrete
evidence from the beginning. How does it get that at genesis? The answer:
**truth bootstraps by leaning on older truth.** A young mesh is exactly as
self-attested as any private operator, so from genesis it inherits witnessing
from the strongest public evidence systems that already exist, and over time
becomes such a system itself (the anchor medium private realms use).

Two-sided time bracket per epoch:
- **Outbound / existed-by:** epoch seal root stamped into Bitcoin via
  OpenTimestamps (free; quantum-durable — rests on SHA-256 hash chains, not
  signatures). Proves the seal existed by block time T2.
- **Inbound / not-before:** a public randomness pulse (drand round) embedded
  in the sealed content — unknowable in advance, so the seal cannot predate
  the pulse (T1). Newspaper-photo principle.
- Every record is then bracketed [T1, T2], minutes-to-hours wide, verifiable
  by anyone forever, trusting nobody — least of all us. Evidence strength
  multiplies across independent media; an adversary must corrupt all of them
  retroactively.

**Implemented (sidecar):** an hourly job takes the latest seal anchor from the
node's status endpoint, wraps it with the latest drand pulse, and OTS-stamps
it; proofs are stored locally and replicated off-site. NOTE the honest limit:
the sidecar's drand pulse brackets the *artifact*, not the seal's creation —
the strong not-before leg needs the pulse INSIDE the sealed content (the P1.5
in-protocol work below; the seal-embedding half of it has since landed).

**P1.5 (in-protocol, after realm-admission P1):** beacon pulse field in epoch
seal headers (true not-before for the seal itself — **landed** as slices
a2/a3: seal-metadata format + the opt-in `drand_pulse_enabled` fetcher, and a
production pulse-carrying seal ships in `examples/verify/`; network-default
remains open) + anchor proofs as
first-class records (so light clients can verify the bracket) + genesis rule:
any real mainnet genesis embeds latest drand pulse + latest Bitcoin block hash
and is OTS-stamped before announcement.

### The anchor braid — answering "BTC is not PQ, wrong foundation"

Precision first: quantum breaks Bitcoin's SIGNATURES (Shor → ECDSA → its
economy), not its HASHES (Grover → SHA-256 keeps ~2^128). An OTS anchor is a
pure SHA-256 Merkle path into a block header — it survives the collapse of
Bitcoin's signature economy. And anchors only carry the TIME bracket; record
integrity/authorship is Dilithium3 inside our own DAM — no Bitcoin failure
can compromise records, worst case age-evidence degrades to structural trust.

The legitimate residue: "which historical chain is canonical" is a social
fact, and ANY single witness is a wrong foundation. Hence the braid
(whitepaper, "Anchor-media requirements"):
1. **Multiple independent media** per anchor: OTS/Bitcoin (hash-based, strong
   leg) + RFC3161 TSA token (freetsa; signature-based — diversifier only,
   must be re-wrapped by hash media over time) + drand pulse. All three are
   produced per anchor (the TSA token is openssl-verifiable).
   **+ Leg 4 — eIDAS-QUALIFIED timestamp** —
   Sectigo (Europe) SL anonymous public endpoint
   (`timestamp.sectigo.com/qualified`, Spanish trusted list, policy
   0.4.0.2023.1.1, qcStatements present). eIDAS Art. 41(2): statutory
   presumption of date accuracy + integrity in ALL EU member states; the
   requester's jurisdiction does not affect the presumption (it attaches
   to the QTSP). Zero cost, zero signup. A qualified-QTSP paid fallback is
   identified for when this leg becomes load-bearing, but is not yet enabled.
2. **We archive the headers ourselves**: a daily job upgrades pending OTS
   proofs to Bitcoin attestations and stores
   the attesting 80-byte headers from two independent sources (blockstream +
   mempool.space, disagreement-flagged). Our proofs never depend on anyone
   else remembering the chain.
3. **Continuous re-anchoring = migration path**: each hourly anchor of the
   running root re-witnesses ALL history beneath it under every current
   medium; as stronger/PQ-native media appear (including our own mesh), the
   braid absorbs them and the bootstrap medium can be dropped without losing
   the past. Bitcoin is the ladder, not the building.
4. **O(1) external-stamp scaling (what if the mesh is mass-adopted
   worldwide?).** Stamp count is independent of adoption: the state
   root commits to everything beneath it, so ONE stamp per interval covers
   the entire mesh at any size (17K records or 10T, 1 zone or 1M). Private/
   sovereign realms never touch external TSAs — they anchor INTO the public
   mesh as ordinary records (normal traffic), and the mesh exports a single
   combined root per interval to the external witnesses. Worldwide adoption
   = same one-hash-per-hour external footprint. Anchor-density law is
   time-bounded, never volume-bounded; the notary bill is O(1) forever.

## Notes

- **Sybil:** OPEN-realm self-assembly is exactly why beat stake stays
  load-bearing (internal beats, post-pivot — mechanism, not product).
- **Sequencing:** sequenced behind the current hardening work. P1 is a strong
  NLnet milestone candidate ("permissioned/air-gapped deployment profiles").
- Whitepaper already gestures at this ("private networks", private deployments
  as primary model) — this doc makes it concrete.
