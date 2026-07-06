# Roadmap

A condensed, repo-level view. The full technical roadmap lives in the
[protocol whitepaper](README.md#documentation) §13; operational limits and
their planned fixes live in [docs/KNOWN-LIMITATIONS.md](docs/KNOWN-LIMITATIONS.md).

## Maintainership

Elara is currently a **single-maintainer project** (see the Author section in
the README) built in an extended human+AI collaboration — the process is
documented honestly in [docs/launch/how-this-was-built.md](docs/launch/how-this-was-built.md).
There is no SLA; security reports get priority handling per
[SECURITY.md](SECURITY.md). Widening the bus factor is an explicit goal of the
funding work below: the first grant milestones include extracting the
standalone crates (PQ transport, sparse-Merkle tree, light client) so they can
live independently of the node and of any single maintainer.

## Near term (weeks)

- **v0.2.x releases** — tagged binaries for Linux/Windows/macOS-arm64 with
  SBOM and build provenance (pipeline already in `release.yml`).
- **Public dev-net soak** — external machines joining over the public
  internet against a residential seed (first successful external-machine
  join: 2026-07-02).
- **Live drand time-bounds** — nodes fetching randomness-beacon pulses so
  every seal carries a verifiable *not-before* bound (the offline verifier
  already validates them; production is the missing half).

## Medium term (months)

- **DAG history completeness hardening** — closing the paging and >24h-gap
  recovery items tracked in KNOWN-LIMITATIONS §1.
- **Standalone crate releases** — `elara-pq-transport`, `elara-smt`,
  `elara-light-client` and friends published to crates.io under
  MIT/Apache-2.0.
- **Third-party security review** — grant-funded external audit of the PQ
  transport and consensus core.

## Long term

- **Realm federation** — independently-operated validation networks with
  explicit trust topology (design-stage; see MESH-BFT merge-semantics notes).
- **Zone scaling toward the whitepaper targets** — the §11.12 design numbers
  are targets, not claims; scaling work is sequenced behind real-world load.

Dates are intentionally absent: this roadmap orders work, it does not promise
delivery weeks. Items move up when someone depends on them.
