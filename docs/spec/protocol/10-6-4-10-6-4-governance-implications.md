#### 10.6.4 Governance Implications

> **Status (2026-06-22): DISABLED in code** — these governance events follow from the NETWORK_PUBLISH transition of §10.6.3, which is compile-time disabled (`NETWORK_PUBLISH_ENABLED = false`) pending the inert-import reframe. The retroactive-witnessing and IPO-style "public trust bootstrapping" described below do not occur on the live protocol. Retained for reference. See §10.6.3 and `docs/MESH-BFT-MERGE-SEMANTICS.md`.

Private-to-public transitions create governance events:

**Zone registration.** A large private network publishing as a new zone follows the zone creation process (Section 10.2, cross-zone decision). The zone's internal governance may differ from the public network's governance model.

**Trust bootstrapping.** Published historical records carry internal trust (accumulated from private witnesses) but zero public trust. Public trust accumulates through retroactive witnessing. A 10-year-old published record may reach high public trust within weeks if many public nodes verify and witness it.

**Representation.** Once published, the organization's nodes become public network participants with governance weight proportional to their staked beats and accumulated conviction (Section 10.3). A large organization entering the public network could represent significant governance weight — the square-root dampening and 5% cap per identity (Section 10.4) limit this concentration.

**The analogy to traditional markets is deliberate:** a private network choosing to publish is structurally similar to a company filing an IPO — historical records are disclosed, public trust is established based on track record, and the entity gains access to the broader ecosystem's resources (public witnessing, storage delegation, cross-network attestation) in exchange for transparency.

Detailed analysis of the economic dynamics of this transition — including beat demand modeling, anti-gaming mechanisms, and the long-term implications of dual-direction network growth — is specified separately.

---

