#### 11.25.14 Honest Position

Earlier versions of this document stated: "A protocol that can censor harmful content can censor any content." This remains true. The eight defense layers described above give node operators the technical capability to reject records — and that capability can be misused.

The protocol's defense against misuse is structural:

- **Structural constraints (Layers 1–3, 6) cannot be weaponized.** A 256-byte memo limit does not censor political speech. A metadata key allowlist does not suppress dissent. URL rejection does not block ideas. These are engineering constraints that limit the protocol's capacity to carry content — any content, harmful or benign.
- **Operator tools (Layers 4, 7, 8) are decentralized.** Each node operator controls their own tombstones, bans, and blocklist. There is no central authority that can order all nodes to suppress a record. A record rejected by one node may be accepted by another. The global DAM is the union of all nodes' records — suppression on one node does not suppress on the network.
- **No default terms are shipped.** The protocol does not decide what is harmful. Operators do, according to their jurisdiction.

The infrastructure does judge certain properties of the payload — its size, its key structure, the presence of URL patterns in text fields. It does not judge the meaning. This is the same architectural boundary observed by SMTP (which rejects messages over a size limit but does not read them) and DNS (which enforces label length limits but does not evaluate domain semantics).

The Elara Protocol chooses structural hostility to content distribution over either extreme: it does not preserve everything blindly (which creates criminal liability for operators), nor does it build meaning-level content moderation into the protocol layer (which creates censorship infrastructure). The structural approach makes the network unsuitable for content distribution without making it capable of content-level censorship.

