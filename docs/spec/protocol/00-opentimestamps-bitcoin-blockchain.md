### Document integrity

Each released version of the whitepaper is published as a PDF whose **SHA-256** hash is timestamped on the Bitcoin blockchain via **OpenTimestamps** (the `.ots` proof ships beside the PDF), and preserved in public **git history**. Under the protocol it describes (next section), the document can also carry its own on-mesh validation record — its existence provable by the very mechanism it specifies, rather than resting on any single external anchor.

External time anchors — a drand *not-before* pulse and an OpenTimestamps/Bitcoin *existed-by* proof (an RFC-3161 timestamp-authority slot is reserved in the record format, but no verifier for it exists yet) — are pluggable, removable strands of that record, never its trust root.

