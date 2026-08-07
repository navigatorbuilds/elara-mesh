# Elara Design Specification

This directory is the protocol's **design documentation** — the working corpus
the implementation is built against. It is published for transparency and
review, with one honest-claims rule applied throughout the project:

> **Designed-for is not tested-at.** Scale figures in these documents
> (records/day, zone counts, node counts) are *design targets* that shaped the
> architecture, not measured benchmarks. Measured behaviour lives in the
> benchmarks (`benches/`) and the test suite.

Layout:

| Directory | Contents |
|-----------|----------|
| `protocol/` | Protocol whitepaper source shards (records, zones, epochs, seals, settlement) |
| `architecture/` | Architecture notes and design resolutions |
| `discovery/` | Peer discovery, DHT, attack/defense analysis |
| `output/` | Compiled documents (see also [`../whitepaper/`](../whitepaper/)) |

Some shards reference design discussions and numbering from internal sessions;
they are kept verbatim rather than rewritten, so the design history stays
honest.
