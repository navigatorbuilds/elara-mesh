# Elara Design Specification

This directory is the protocol's **design documentation** — the working corpus
the implementation is built against. It is published for transparency and
review, with one honest-claims rule applied throughout the project:

> **Designed-for is not tested-at.** Scale figures in these documents
> (records/day, zone counts, node counts) are *design targets* that shaped the
> architecture, not measured benchmarks. Measured behaviour lives in the
> benchmarks (`benches/`) and the test suite.

> **The whitepaper is authoritative.** The `protocol/` shards are an earlier
> working split of the protocol whitepaper and have since diverged from it
> (for example, they frame the DAM as two structural axes where the whitepaper
> uses three dimensions). Where they differ, the published whitepaper,
> [`../whitepaper/ELARA-PROTOCOL-WHITEPAPER.pdf`](../whitepaper/ELARA-PROTOCOL-WHITEPAPER.pdf),
> is the statement of what is implemented and what is design-stage.
> `output/protocol.pdf` is assembled from these shards, not from the whitepaper.

Layout:

| Directory | Contents |
|-----------|----------|
| `protocol/` | Earlier working split of the protocol whitepaper (records, zones, epochs, seals, settlement); the published whitepaper wins where they differ |
| `architecture/` | Architecture notes and design resolutions |
| `discovery/` | Peer discovery, DHT, attack/defense analysis |
| `output/` | Documents assembled from these shards (the published whitepaper is in [`../whitepaper/`](../whitepaper/)) |

Some shards reference design discussions and numbering from internal sessions;
they are kept verbatim rather than rewritten, so the design history stays
honest.
