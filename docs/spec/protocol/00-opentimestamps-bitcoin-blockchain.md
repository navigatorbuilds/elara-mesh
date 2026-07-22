### Document integrity

Each released version of this whitepaper is identified by the **SHA3-256 hash** of its exact bytes and preserved in public **git history**. Under the protocol it describes (next section), the document can also carry its own on-mesh validation record — its existence provable by the very mechanism it specifies, rather than resting on any single external anchor.

External time anchors — a drand *not-before* pulse, an RFC-3161 timestamp authority, and (optionally) an OpenTimestamps/Bitcoin proof — are pluggable, removable strands of that record, never its trust root.
