#### 10.6.4 Governance Implications

> **Implementation-status note: DISABLED in the current runtime.** The governance events below follow from the NETWORK_PUBLISH transition of §10.6.3, which is compile-time disabled (`NETWORK_PUBLISH_ENABLED = false`) pending the inert-import reframe. The retroactive trust-bootstrapping and IPO-style governance weight described here do not occur on the live protocol; retained for reference. See §10.6.3.

Private-to-public transitions create governance events:

**Zone registration.** A large private network publishing as a new zone follows the zone creation process (Section 10.2, cross-zone decision). The zone's internal governance may differ from the public network's governance model.

**Trust bootstrapping.** Published historical records carry internal trust (accumulated from private witnesses) but zero public trust. Public trust accumulates through retroactive witnessing. A 10-year-old published record may reach high public trust within weeks if many public nodes verify and witness it.

**Representation.** Once published, the organization's nodes become public network participants with governance weight proportional to their staked beats and accumulated conviction (Section 10.3). A large organization entering the public network could represent significant governance weight — the square-root dampening (Section 10.4) limits this concentration. Earlier versions of this paper also named a "5% cap per identity" here; no such cap is specified anywhere in this document, and the phrase is withdrawn.

**The analogy to traditional markets is deliberate:** a private network choosing to publish is structurally similar to a company filing an IPO — historical records are disclosed, public trust is established based on track record, and the entity gains access to the broader ecosystem's resources (public witnessing, storage delegation, cross-network attestation) in exchange for transparency.

Section 11.34 analyzes the economic dynamics and failure modes of this transition, including ingestion rate-limiting as an anti-gaming mechanism.

---

