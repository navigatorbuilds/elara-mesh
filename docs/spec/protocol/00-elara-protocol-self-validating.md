### Validation under the protocol it describes

The protocol described in this whitepaper is designed to give any file its own provable record. A creator signs a **Dilithium3** (ML-DSA-65, FIPS 204) validation record that binds:

- a **SHA3-256 hash** of the content — a post-quantum fingerprint of the exact bytes;
- the creator's **public-key identity** — the Dilithium3 key that produced the signature;
- a **timestamp** — when the record was created; and
- the record's **position in the creator's validation chain** — linking it to their prior records.

You can try this validate-locally model in your browser — identity generated on your device, no account, no server, nothing leaving your machine — at [elara-validate.pages.dev](https://elara-validate.pages.dev).

**Prior art and priority.** A US provisional patent application (No. 63/983,064, filed February 14, 2026) documented this protocol's design during early development. The project has since committed fully to open publication: the public source repository, this whitepaper, and the mesh's own timestamped records serve as the prior-art record. The provisional is being allowed to lapse; no patent will be pursued.

---

*The Elara Protocol — because every creation deserves proof.*
