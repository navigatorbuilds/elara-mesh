# Elara Runtime

[![CI](https://github.com/navigatorbuilds/elara-mesh/actions/workflows/ci.yml/badge.svg)](https://github.com/navigatorbuilds/elara-mesh/actions/workflows/ci.yml)

**The black box for AI agents** — post-quantum, offline-verifiable proof of *who
(or what) did what, on whose authority, and when*. Don't trust us: check it
yourself — one command, no server, no network, and it never fakes a green.

**The proof you can run today.** As autonomous software acts across more of the
world, every action raises the same question: *who — or what — did this, on whose
authority, in what form, and when — and can that be proven later, by anyone?*
Elara answers with proof a stranger can check alone. A standalone verifier
(`elara-verify`, one small binary) confirms a post-quantum dual signature, a
time bracket (a drand "not-before" lower bound, BLS-verified · a Bitcoin
"existed-by" upper bound from a pin-authenticated block header), and sealed-state
inclusion — fully offline, trusting only the math. When a proof is missing it says
**⚠ UNPROVEN**; when a chain doesn't link, **✗ FAILED**. It refuses to lie even for
itself — and that honesty is the point.

**What it's for, and what's underneath.** The differentiator is an accountability
layer for autonomous agents: an OpenTimestamps proof says *when* a hash existed and
a signature says *which key* signed it — but neither, alone or composed, says
whether that key was *authorized* to act, by whom, or whether that authority still
held at signing. Elara records each act's reference to a revocable, time-bounded
mandate from a named principal and deterministically flags — offline, re-runnable
years later — whether the authority held at the act's signing time. (`cargo run
--example mandate_demo` shows it in ~60s, no node, no network. v0 enforces the
*who* (agent identity), the *when* (validity window) and *revocation*, and
**records-and-flags** out-of-mandate acts rather than consensus-enforcing them;
op/zone scope is recorded but deferred to v1 — full head-to-head vs. OTS / sigstore
/ C2PA / Verifiable Credentials in the [differentiation FAQ](docs/launch/differentiation-faq.md).)
It rides on the substrate that makes the claim
credible — an open-source, post-quantum, zone-partitioned **validation mesh**,
written in Rust. Records work fully offline at creation; when connectivity exists,
a peer-to-peer DAG weaves them into shared, witness-attested history.

~350,000 lines of Rust · 5,700+ tests · post-quantum signatures (Dilithium3 + SPHINCS+) in the consensus hot path · offline-first by design.

## Project status — read this first

This project distinguishes **designed-for** from **tested-at**, everywhere:

| | |
|---|---|
| **Tested at** | small private testnets — historically up to 6 rented VPS nodes across Europe and North America (that fleet was retired 2026-06-09); the current fleet is 3 local machines (one desktop + two laptops), weeks of continuous soak; ~17K-record DAGs; first external-machine join over the public internet completed July 2026; full test suite (5,700+ tests) green |
| **Designed for** | 1M zones × 10T records/day × 10K+ nodes — these are *design targets that shaped the architecture*, *not demonstrated capacity* |
| **Hardening status** | explicit-panic phase done — **0** `unwrap()`/`expect()`/`panic!` across the node and published protocol crates (`src/` + `crates/*/src/`, `#[cfg(test)]` excluded), CI-gated and re-runnable yourself: `python3 scripts/scan-prod-panics.py --check`. Active lane: hot-path bounds/arithmetic hardening against attacker-controlled bytes (a Byzantine peer must never be able to crash a node). |
| **Public network** | none yet — this is a runtime you can build and run yourself today |
| **Beats** | the internal unit (the **beat**) is **protocol plumbing** (staking, sybil resistance, resource accounting). It is **not a cryptocurrency offering**: there is no token sale, no exchange listing, no airdrop, and none is planned. |

This codebase was built by a solo developer (Nenad Vasic) working with [Claude](https://claude.com) as an engineering collaborator — the AI helps write and adversarially audit the code under human direction.

## What it does

- **Post-quantum cryptography** — Dilithium3 + SPHINCS+-SHA2-192f + ML-KEM-768 (key encapsulation; FIPS 203, formerly Kyber)
- **Directed Acyclic Mesh** — zone-partitioned DAG with BFS traversal, tips, roots, ancestors, fork detection
- **Interval Tree Clocks** — causal ordering without timestamps, zone-aware clock management
- **Binary wire format** — compact ELRA encode/decode with LEB128 varints
- **Internal resource model** — fixed-supply conservation ledger (staking, witness rewards, storage delegation) — see beats note above
- **Attestation-Weighted Consensus** — confirmation levels, epoch seals, Merkle proofs
- **Network daemon** — gossip, peer discovery, post-quantum ElaraPQ transport (ML-KEM-768 + X25519 + Dilithium3, see whitepaper §4.7), rate limiting, content-routed structured gossip
- **Full node REST API** — verification, explorer, governance, admin, DAG inspection
- **Hash-commitment privacy (SHA3)** — 3 commitment proof types (BalanceRange, MetadataProperty, ContentCommitment) with a fail-closed verifier. These are SHA3-256 commitments, **not** zero-knowledge proofs; Groth16 zk-SNARK circuits remain design-stage scaffolding (see whitepaper §5, §14.3 for the honest gap assessment).
- **Python** — 26 native PyO3 sign/verify bindings (`pyo3` feature) + a zero-dependency pure-stdlib HTTP SDK (`sdks/python/`)
- **Light clients** — header-only sync with SMT account proofs; checkpoint skip-sync (no genesis replay)
- **Agent-mandate accountability (observational v0)** — `MandateRecord` / `RevocationRecord` wire types, storage (CF_MANDATE / CF_REVOCATION / CF_MANDATE_ACT), and front-run-proof read-time revocation for *"agent A was authorized by principal P to do X, revocable over time"*, with public `/mandate/{id}` + `/mandate/status/{record_id}` queries and a runnable demo (`cargo run --example mandate_demo`). v0 verifies the *who* + *when* + *revocation* and **records-and-flags** out-of-mandate acts (zero trust/consensus weight); consensus-weight enforcement and op/zone scope are deferred to v1.

## Verify it yourself — offline, no node, no trust in us

"Don't trust us — check us" is the whole point, so verification is a standalone
binary that needs **no running node and no network**. Build it and check any
record, seal, external anchor, or inclusion proof against the cryptography
directly:

```bash
cargo build --release --features verify-cli --bin elara-verify

# Check that a record's hash is sealed under a zone's Merkle root. The proof
# JSON comes from any node's /zone/{zone}/proof/{record_hash}; the walk is pure
# SHA3-256, done locally — the node is never trusted, only the math.
target/release/elara-verify --inclusion proof.json --expect-root <sealed-root-hex>
#   ✓ record inclusion  … is a leaf under Merkle root … (64 siblings)
#   ✓ sealed-root bind  proof root matches the sealed root you supplied
#   VERDICT: VERIFIED
```

Four modes, combinable: **record** (structure + identity-binding +
Dilithium3/SPHINCS+ signature + content hash), **anchor** (the Bitcoin
"existed-by" upper bound via OpenTimestamps, plus a drand "not-before" lower
bound), **seal** (signed by an anchor key you pin), and **inclusion** (record →
sealed Merkle root). A tampered input
returns `VERDICT: FAILED` and a non-zero exit code. Full guide:
[`docs/ELARA-VERIFY.md`](docs/ELARA-VERIFY.md).

**Or check a record in your browser — zero setup.** The record check (structure,
identity binding, and the post-quantum signature) also runs **entirely
client-side** at **https://navigatorbuilds.github.io/elara-mesh/verify/** — no install,
no server, no account. It is the same `verify_core` logic `elara-verify` runs,
compiled to WebAssembly with no wallet, keys, or network code linked in, so the
in-browser verdict can't drift from the CLI's. It covers the record only, not
inclusion/seal/anchor — that full chain is the CLI above. Build and serve it
yourself from [`browser-node/verify-demo/`](browser-node/verify-demo/):
`wasm-pack build --target web -d ../browser-node/verify-demo/pkg verify-wasm`.

**Or verify an account on a *live* node — without trusting it.** The checks above
need no node; this one needs a running node but still trusts only the math.
`cargo run --features node-core --example light_client_live` points the read-only
light-client SDK at a node, pulls its `/proof/account` Merkle proof, and re-derives
the account-SMT root locally — so a node that lies about a balance is caught by
arithmetic, not reputation. The example proves it end-to-end: inflating the claimed
balance fails with `LeafHashMismatch`, corrupting one Merkle sibling fails with
`ProofInvalid`, and pinning a seal root you obtained out-of-band rejects a
one-byte-different root. Read-only — the SDK holds no key and cannot move funds.
Source: [`examples/light_client_live.rs`](examples/light_client_live.rs).

## Why now — the verification gap

Intelligence is becoming abundant; verification is not. As fluent AI output
approaches free, the scarce input is verification — knowing which outputs hold,
which agent did what, on whose authority, and whether it is still the same agent.
Elara is open infrastructure for that half of the problem: not reputation or
alignment, but a post-quantum, offline-checkable record of *who did what, on whose
authority, and when*.

That gap is turning concrete in EU law. Five regulations enacted in 2023–2024 lean
on the same missing piece — durable, tamper-evident, verifiable records of what
agents, machines, and products did — without specifying who provides it:

- **AI Act** ((EU) 2024/1689, Art. 12) — automatic event logging for **high-risk**
  AI systems (obligations phase in on the Act's staged timeline through 2027).
- **Cyber Resilience Act** ((EU) 2024/2847) — products with digital elements must
  declare conformity with essential cybersecurity requirements and handle
  vulnerabilities across their lifecycle.
- **Battery Regulation** ((EU) 2023/1542) — a per-battery digital product passport
  is mandatory from **18 Feb 2027**; this is the first instance of the broader
  Ecodesign for Sustainable Products DPP framework ((EU) 2024/1781), which extends
  to other product categories by delegated act.
- **eIDAS 2.0** ((EU) 2024/1183) — identity wallets for people and companies, but
  machines and AI agents are left unanswered.
- **Machinery Regulation** ((EU) 2023/1230) — verifiable records of safety-software
  versions and interventions for autonomous machinery (from 20 Jan 2027).

None of them specify the record infrastructure, and the default answer will be
closed, per-vendor silos. Elara is **designed to support** the record-keeping these
regulations require — as an open, post-quantum commons, not a compliance product.
(We enable these workflows; we do not certify compliance, and "AI Act compliant" is
a claim we never make.)

## Where this is going (design stage — see docs)

External time anchoring (the first item) is **live in the development mesh today**,
and the agent-mandate layer ships an **observational v0** (verdict core, query
endpoints, and a runnable demo — see "What it does" above; consensus-weight
enforcement is the design-stage next slice). Realms remain a **design document
under active development**, not a shipped feature (honest-claims rule applies —
see Project status above):

- **External time anchoring — live today.** The development mesh's epoch
  seals are anchored into Bitcoin (via OpenTimestamps) — an existed-by bound
  anyone can verify offline against the public chain — and countersigned by an
  independent RFC 3161 / eIDAS-qualified timestamp authority. Each artifact
  also embeds a drand public-randomness pulse as a not-before bound; `elara-verify`
  checks that pulse's BLS signature against the pinned League-of-Entropy key —
  offline, when the artifact carries the signature — so the lower bound rests
  only on the League-of-Entropy threshold group (not on us), verifiable offline. Embedding the pulse *inside* every per-seal record (vs. the
  external anchor artifact) is the remaining design step. The project's own papers
  and design decisions are timestamped the same way. [`docs/REALMS-SELF-ASSEMBLY.md`](docs/REALMS-SELF-ASSEMBLY.md)
- **Realms.** Three membership modes — open self-assembling mesh, federated
  consortium networks, fully sovereign isolated deployments — where a realm
  is an *exposure policy*, never a privilege: no tier confers any advantage
  on the open mesh. Includes the "Validation IPO": a private network that ran
  for years can later publish its history with verifiable age (credibility
  proportional to its external anchor trail). [`docs/REALMS-SELF-ASSEMBLY.md`](docs/REALMS-SELF-ASSEMBLY.md)
- **Agent mandates — observational v0 shipped, enforcement next.** A principal
  issues a scoped, revocable, signed mandate to an agent key; every agent action
  then proves not just *which key* signed, but *under whose authority, within what
  mandate*. Shipped today (v0): identity binding, validity window, front-run-proof
  revocation, and the recorded-and-flagged taxonomy for out-of-mandate acts (zero
  weight, never silently dropped — a truth ledger records what happened). Next
  (v1): op/zone scope enforcement, consensus-weight gating, and sub-delegation
  chain-walk. [`docs/AGENT-DELEGATION.md`](docs/AGENT-DELEGATION.md)

## Architecture

> **On `accounting/`:** the internal unit (the **beat**) is accounting plumbing — it meters
> staking, Sybil-resistance, and resource use inside the protocol. It is not a tradeable asset
> (no token sale, exchange listing, or airdrop, and none planned). The modules are protocol
> mechanics: `custodial.rs` classifies custodial entities for accounting, `governance.rs` is
> parameter voting, `idle_decay.rs` is idle-state decay. More:
> [`docs/launch/differentiation-faq.md`](docs/launch/differentiation-faq.md).

```
src/
├── crypto/                     # Post-quantum primitives (8 modules)
│   ├── pqc.rs                  # Dilithium3 + SPHINCS+ keygen/sign/verify
│   ├── hash.rs                 # SHA3-256
│   ├── batch.rs                # Parallel batch sign/verify (rayon)
│   ├── kem.rs                  # ML-KEM-768 (FIPS 203) post-quantum key encapsulation
│   ├── commitment.rs           # SHA3-based deterministic commitment proofs
│   ├── vrf.rs                  # Dilithium3-signed sortition draw (SHA3-based; not a full RFC-9381 VRF)
│   └── zk.rs                   # Hash-commitment privacy (SHA3; Groth16 zk-SNARK = design-stage)
│
├── accounting/                 # internal resource accounting (staking, Sybil-resistance, metering)
│   ├── types.rs                # operation types + fixed-supply constants (9-decimal base unit)
│   ├── ledger.rs               # In-memory ledger, conservation pool
│   ├── validate.rs             # beat operation validation
│   ├── genesis.rs              # Genesis allocation (6 pools, vesting)
│   ├── bootstrap.rs            # Phased bootstrap (4 phases, reward scaling)
│   ├── governance.rs           # Conviction voting, proposals, committees
│   ├── velocity.rs             # 5-tier beat-flow velocity throttling
│   ├── circuit_breaker.rs      # 4-level emergency circuit breaker
│   ├── trust.rs                # 6-signal Sybil resistance scoring
│   ├── acquisition.rs          # Anti-accumulation rate limiting
│   ├── cross_zone.rs           # Async-optimistic cross-zone settlement
│   ├── idle_decay.rs           # Idle-state decay (keeps accounting honest)
│   ├── dormancy.rs             # 3-phase dormancy lifecycle (7-year)
│   ├── entity.rs               # Entity classification (individual/org)
│   ├── custodial.rs            # Custodial-entity classification
│   ├── storage_market.rs       # Storage delegation metering
│   ├── delegation.rs           # Stake delegation
│   ├── batch.rs                # Batch record validation + Merkle
│   └── limits.rs               # Hard protocol limits (non-governable)
│
├── network/                    # P2P network daemon (68 modules)
│   ├── pq_server.rs            # ELPQ-bound RPC server (post-quantum-authenticated methods)
│   ├── pq_client.rs            # PQ peer client (Dilithium3-authenticated)
│   ├── gossip.rs               # Push/pull gossip, 22-step insert pipeline
│   ├── state.rs                # Shared node state
│   ├── config.rs               # TOML config + env var overrides
│   ├── consensus.rs            # AWC finality, confirmation levels, zones
│   ├── epoch.rs                # Epoch sealing with Merkle roots
│   ├── sync.rs                 # Merkle tree + bloom filter delta sync
│   ├── discovery.rs            # Bootstrap + mDNS peer discovery
│   ├── zone.rs                 # Zone routing + auto-scaling (Gap 4)
│   ├── pq_transport/           # ElaraPQ post-quantum transport (handshake/frame/stream/router)
│   ├── witness.rs              # Attestation storage + WitnessManager
│   ├── auto_witness.rs         # Automatic attestation scheduling
│   ├── reward.rs               # Witness reward distribution
│   ├── reputation.rs           # Witness reputation tracking
│   ├── dispute.rs              # 3-tier dispute resolution
│   ├── light.rs                # Light client (header-only sync)
│   ├── fisherman.rs            # Fisherman slashing protocol
│   ├── slashing.rs             # Slash execution + distribution
│   ├── zone_committee.rs       # Per-zone sortition witness committees (Gap 5)
│   ├── publish.rs              # Publication + mega-publication limits
│   ├── key_rotation.rs         # Key rotation + revocation registry
│   ├── liveness.rs             # Witness liveness heartbeats
│   ├── health.rs               # Node health scoring
│   ├── peer.rs                 # Peer state tracking
│   ├── fork.rs                 # Fork detection + healing
│   ├── gc.rs                   # Record garbage collection
│   ├── powas.rs                # Proof-of-Work-as-Stake
│   ├── ingest.rs               # Record ingest validation + disk-pressure gate
│   ├── timestamp_defense.rs    # Timestamp manipulation defense
│   ├── sunset.rs               # Algorithm sunset scheduling
│   └── snapshot.rs             # State snapshot + recovery
│
├── storage/                    # Persistent storage (RocksDB-only)
│   └── rocks.rs                # RocksDB backend — column families, timestamp index, FTS
│
├── record.rs                   # ValidationRecord, wire format v5
├── dag.rs                      # In-memory DAG index
├── itc.rs                      # Interval Tree Clocks (causal ordering)
├── identity.rs                 # PQC identity management
├── light_verify.rs             # Offline seal-against-anchor verification (Gap 1)
├── operations.rs               # DamVm with 9 DAM operations
├── versioning.rs               # Content version chains + fork detection
├── uuid7.rs                    # UUID v7 generation
├── wire.rs                     # ELRA binary wire format
├── errors.rs                   # Error types
├── lib.rs                      # Library crate root + PyO3 bindings (Python SDK)
│
├── bin/
│   ├── elara_node.rs           # Node daemon binary
│   └── elara_cli.rs            # CLI client binary
│
crates/                         # Standalone publishable crates (MIT/Apache-2.0)
├── elara-pq-transport          # PQ transport (ML-KEM-768 + Dilithium3 handshake)
├── elara-light-client          # Light-client SDK (header sync + SMT proofs)
├── elara-smt                   # Sparse Merkle tree
├── elara-dht                   # Kademlia routing table
├── elara-itc                   # Interval Tree Clocks
├── elara-nat                   # NAT traversal (STUN/UPnP)
├── elara-zone-autoscaler       # Zone split/merge decision engine
└── elara-active-inference      # Active-inference engine

tests/                          # Integration tests (in-process multi-node)
├── spec_compliance.rs          # Protocol spec conformance
├── record_relay_v1.rs          # Record relay
├── relay_by_hash.rs            # Relay-by-hash routing
├── slot_conflict_injection.rs  # Slot-conflict handling
├── disk_full.rs                # Disk-pressure ingest gate
├── memory_ceiling.rs           # Memory-ceiling behavior
└── wallet_pq_regression.rs     # PQ wallet regression

benches/
├── bench_crypto.rs             # PQC + hashing benchmarks
├── bench_wire.rs               # Wire format benchmarks
├── bench_dag.rs                # DAG traversal benchmarks
└── bench_tps.rs                # Transaction throughput benchmarks
```

## Installation

**You do not need Rust or a compiler to run Elara.** Pick one path:

### Fastest — download a prebuilt binary (no Rust, no build)

After the first tagged release, the [Releases page](https://github.com/navigatorbuilds/elara-mesh/releases)
ships ready-to-run binaries — nothing to compile:

| Your machine | Download |
|---|---|
| Linux desktop (Intel/AMD) | the `…-linux-x86_64` archive, or the **AppImage** (double-click) |
| Linux on ARM / Raspberry Pi | the `…-linux-aarch64` archive |
| Mac — Apple Silicon (M1–M4) | the `…-macos-aarch64` archive |
| Mac — Intel (pre-2020) | the `…-macos-x86_64` archive |
| Windows | the `…-windows-x86_64.zip`, or the installer |

Each archive contains `elara-node`, `elara-cli` (Linux/Mac), and `elara-verify` —
the offline verifier — so "don't trust us, check it yourself" needs no Rust and
no compile either.

Every artifact carries a SHA-256 checksum and a GitHub SLSA build-provenance
attestation — verify your download before running it ([`VERIFY.md`](VERIFY.md)).
macOS: clear the quarantine flag once — `xattr -d com.apple.quarantine ./elara-node`.

### Build from source

Needs **Rust 1.87+** (a fresh `rustup` gives ≥1.93 — a stale distro `apt` rustc
will fail with cryptic errors) plus a C/C++ toolchain (`cmake` + `clang`) for the
bundled post-quantum crypto (`liboqs`) and storage (`rocksdb`):

```bash
# Debian/Ubuntu — install the toolchain first
sudo apt install -y build-essential pkg-config libssl-dev cmake clang libclang-dev git
# macOS:   xcode-select --install && brew install cmake
# Windows: choco install cmake llvm     (or build inside WSL2 — smoother)

git clone https://github.com/navigatorbuilds/elara-mesh.git && cd elara-mesh

# Easiest: this wrapper checks your toolchain, auto-applies the gcc-13+ RocksDB
# fix, and caps parallelism on low-RAM boxes — so the FIRST build doesn't fail.
scripts/build.sh                 # add --verify to also build the offline verifier

# …or the raw commands it wraps:
cargo test  --features node --lib                                   # 5,700+ tests
cargo build --features node --release --bin elara-node --bin elara-cli
```

**Build failed?** Almost every first-build error is one of a handful of known
toolchain issues, each with a copy-paste fix →
[`docs/INSTALL-TROUBLESHOOTING.md`](docs/INSTALL-TROUBLESHOOTING.md). (A first
build is 10–30 min — RocksDB + liboqs are large C libraries; it is not hung.)

**Optional Python SDK:** A pure-stdlib HTTP client (zero third-party
dependencies) for reading balances, fetching state proofs, and submitting
pre-signed records. Requires Python 3.9+.

```bash
pip install -e sdks/python
```

See [`sdks/python/README.md`](sdks/python/README.md) for the three-line `Agent`
quickstart and the endpoints it wraps.

## Node Daemon

```bash
# Generate a post-quantum identity (prints your identity hash — copy it)
./target/release/elara-node --data-dir ./mynode --generate-identity

# Start a genesis node. ELARA_DATA_PLANE_LISTEN= (empty) serves the full API on
# the single --listen port — simplest for local use; see "Two listeners" below.
ELARA_GENESIS=<your-identity-hash> ELARA_NODE_TYPE=witness ELARA_AUTO_WITNESS=true \
ELARA_DATA_PLANE_LISTEN= \
    ./target/release/elara-node --data-dir ./mynode --listen 127.0.0.1:9473

# Join an existing network
ELARA_GENESIS=<genesis-hash> ELARA_SEEDS=seed-host:9473 ELARA_DATA_PLANE_LISTEN= \
    ./target/release/elara-node --data-dir ./mynode2 --listen 127.0.0.1:9474
# (9474 above only avoids colliding with the first node on the SAME box —
#  on its own machine, omit --listen and it binds the default 9473)
```

**Joining a live network for the first time? Use the guided path.** The command
above is the raw mechanism; **[`docs/JOIN-DEVNET.md`](docs/JOIN-DEVNET.md)** wraps it
with two guard-rail scripts — `scripts/init-join.sh` proves both the HTTP **and** the
post-quantum data port are reachable and writes a correct config *before* you build,
and `scripts/check-my-join.sh` gives a plain-language "are you synced?" verdict. This
catches the most common silent first-join failure: the PQ data port being firewalled,
which otherwise strands a new node at `peers=0` with no error.

### Two listeners: public surface vs. data plane

By default a node runs **two HTTP listeners**, so a bare node never exposes its
full API to the internet:

- **Public surface** — on `--listen` (e.g. `127.0.0.1:9473`). The endpoints
  reachable from another host are an explicit read-only allowlist: liveness/meta
  (`/health` `/metrics` `/ping` `/status` `/alive` `/version`), the light-client /
  wallet reads (`/proof/account/{id}`, `/headers/from/{epoch}`, `/snapshot/state-delta`,
  `/seal/progress/{id}`, `/records/by-hash/{hash}`, `/mandate`, `/governance/upgrade_outcomes`),
  the read-only block explorer (`/explorer` plus `/epochs` `/consensus/status`
  `/dag/stats` `/dag/tips` `/transactions/recent` `/record/{id}` `/account/{identity}`),
  and the `/pq-ws` post-quantum WebSocket. This listener serves **only** that
  allowlist — every other path 404s here regardless of caller, and topology/deanon
  endpoints (`/peers`, bulk `/balances`, `/witness/profiles`) stay data-plane-only
  by design (the full API is on the data-plane listener below). In single-listener
  mode (next paragraph) the same restriction is enforced by a path gate that 404s
  non-loopback callers.
- **Data plane** — the full query/submit/admin API (everything in the API table
  below, including `POST /records`). Bound to `127.0.0.1:9472` (**loopback only**)
  by default, set via `ELARA_DATA_PLANE_LISTEN` / `data_plane_listen_addr`. For a
  public node, front it with a reverse proxy (Caddy/nginx, terminating TLS) and
  expose only the paths you choose — the node itself speaks plain HTTP.

**Local development:** set **`ELARA_DATA_PLANE_LISTEN=`** (empty) as shown above to
collapse both onto the single `--listen` port. Then every endpoint, `curl`, CLI
and SDK example below works against one address. (Bound to `127.0.0.1`, this stays
on your machine; the path gate still protects you if you bind a public interface.)

## Run with Docker

The quickest way to watch a multi-node network run without a local Rust
toolchain — spins up a 3-node testnet (1 genesis + 2 witnesses) with identities
and genesis authority auto-resolved, zero manual steps:

```bash
docker compose up --build
```

Nodes listen on `localhost:9473` (genesis), `9474`, and `9475`. The compose file
runs single-listener mode (`ELARA_DATA_PLANE_LISTEN=`), so the **full** API and
the `curl`/SDK examples below work against those ports. The first build compiles
the release binary from source inside the image, so it takes a few minutes; later
starts are instant. Tear down with `docker compose down -v`.

## API Overview

Key endpoints by category — verification, node operation, consensus, governance.
Only the **public surface** is served on the `--listen` port to off-host
callers; **everything else here is on the data plane** (loopback `127.0.0.1:9472`
by default, or the single `--listen` port in single-listener mode — see
[Two listeners](#two-listeners-public-surface-vs-data-plane) above). The public
surface is an explicit read-only allowlist (`PUBLIC_ROUTE_PREFIXES` in
`src/network/server/mod.rs`):

- **Liveness / meta** — `/ping` `/status` `/health` `/alive` `/metrics` `/version`
- **Light-client / wallet reads** — `/proof/account` `/headers` `/snapshot/state-delta`
  `/seal/progress` `/records/by-hash` `/mandate` `/governance/upgrade_outcomes`
- **Read-only block explorer** — the browser page `/explorer` plus the JSON it reads:
  `/epochs` `/consensus/status` `/dag/stats` `/dag/tips` `/transactions/recent`
  `/record/{id}` `/account/{identity}`

Each is read-only, idempotent, and carries the same disclosure profile as a public
ledger. Endpoints that would leak node topology or deanonymize participants —
`/peers`, bulk `/balances`, and `/witness/profiles` (which exposes a witness `/24`
subnet) — stay **data-plane-only** by design; on a public node the corresponding
explorer panels degrade to empty rather than leak.

| Category | Key Endpoints |
|----------|---------------|
| **Core** (public) | `/ping` `/status` `/health` `/metrics` `/version` |
| **Explorer** (public, read-only) | `/explorer` (browser UI) `/epochs` `/consensus/status` `/dag/stats` `/dag/tips` `/transactions/recent` |
| **Records** | `/records` `/records/search` `/records/stream` `/record/{id}` `/validate` |
| **Governance** | `/governance/proposals` `/governance/summary` `/governance/params` `/governance/delegations/{id}` |
| **Consensus** | `/consensus/status` `/consensus/record/{id}` `/epochs` `/epochs/headers` `/zones` `/network` |
| **Witness** | `/witness` `/witness/profiles` `/witness/reputation` `/witness/correlation` `/attestations` |
| **Disputes** | `/disputes` `/disputes/{id}` `/challenges` `/challenges/{id}` `/proofs/{record_id}` |
| **DAG** | `/dag/stats` `/dag/tips` `/dag/lifecycle` `/dag/record/{id}/graph` `/dag/search` |
| **P2P** | `/peers` `/peers/reputation` `/merkle_root` `/delta_sync` `/gossip` `/dht/find_node` |
| **Admin** | `/admin/snapshot` `/admin/export` `/admin/gc` `/admin/fork_check` `/admin/ban_ip` `/admin/revocations` |

Full API documentation: [`docs/api.md`](docs/api.md)

## CLI Client

The CLI talks to a node over the **post-quantum transport**, not the REST API: it
derives the PQ port from `--node` as the HTTP base **+ 100** (so `:9473` → `:9573`).
It therefore works the same in either listener mode, as long as the node's PQ port
is reachable.

```bash
CLI="./target/release/elara-cli --node http://localhost:9473"

$CLI status                    # Node status + finality metrics
$CLI peers                     # Connected peers
$CLI summary                   # Ledger summary
$CLI mint --to <hash> --amount 1000 --identity id.json
$CLI transfer --to <hash> --amount 50 --identity id.json
$CLI balance <hash>            # Account balance
$CLI stake --amount 200 --purpose witness --identity id.json
$CLI unstake --stake-record-id <id> --identity id.json
```

## Benchmarks

Measured on Xeon E5 / 64GB RDIMM — single-machine microbenchmarks, not production SLAs. Run with `cargo bench`.

| Operation | Time |
|-----------|------|
| Dilithium3 keygen | 57 µs |
| Dilithium3 sign | 159 µs |
| Dilithium3 verify | 55 µs |
| SPHINCS+ sign | 28 ms |
| SHA3-256 (4 KB) | 16 µs |
| Batch verify 100 sigs | 1.7 ms |
| Wire serialize | 292 ns |
| Wire deserialize | 780 ns |
| DAG insert 10K records | 16 ms |

## Configuration

Copy `elara-node.toml.example` and customize. Every field has an `ELARA_*` env var override.

| Field | Env Var | Default |
|-------|---------|---------|
| `listen_addr` | `ELARA_LISTEN` | `0.0.0.0:9473` (public surface) |
| `data_plane_listen_addr` | `ELARA_DATA_PLANE_LISTEN` | `127.0.0.1:9472` (empty ⇒ single-listener) |
| `genesis_authority` | `ELARA_GENESIS` | (required) |
| `node_type` | `ELARA_NODE_TYPE` | `witness` |
| `zone_count` | `ELARA_ZONE_COUNT` | `0` (auto; pin to `1` for the single-zone dev-net) |
| `seed_peers` | `ELARA_SEEDS` | `[]` |
| `gossip_pull_interval_secs` | `ELARA_GOSSIP_INTERVAL` | `30` |
| `auto_witness` | `ELARA_AUTO_WITNESS` | `true` |
| `admin_token` | `ELARA_ADMIN_TOKEN` | (empty = auto-generated at boot; applies to proxied `/rpc/*` only — `/admin/*` needs the PQ-signed `X-PQ-Admin` header) |
| `dns_seeds` | `ELARA_DNS_SEEDS` | (empty — no public DNS seed; comma-separated hostnames if you run your own) |

> TLS is terminated by your reverse proxy, not the node — the node speaks plain
> HTTP. Front the data-plane port with Caddy/nginx to expose it over HTTPS.

## Documentation

| Document | Description |
|----------|-------------|
| [Protocol Whitepaper](docs/whitepaper/ELARA-PROTOCOL-WHITEPAPER.pdf) | The Elara Protocol — post-quantum universal validation layer (v0.7.30) |
| [MESH-BFT Paper](docs/whitepaper/MESH-BFT-PAPER.pdf) | Consensus: diversity-weighted Byzantine fault tolerance |
| [Protocol Economics](docs/PROTOCOL-ECONOMICS.md) | Validation-beat mechanics as implemented — fixed supply, conservation invariant, staking, slashing; with a "rejected alternatives" appendix |
| [Design Specification](docs/spec/) | Full protocol / architecture / hardware design corpus |
| [Differentiation FAQ](docs/launch/differentiation-faq.md) | "How is this not just X?" — how Elara differs from C2PA, sigstore, OpenTimestamps, blockchains, and timestamping SaaS |

## Support & expectations

This is a small, independent project, maintained on a best-effort basis — there
is no support SLA. Issues and pull requests are welcome and read, but reviews
and responses may be slow. Please report **security vulnerabilities privately**
via [SECURITY.md](SECURITY.md), not in public issues. If you rely on Elara for
anything that matters, run and verify your own node — the protocol is designed
so you trust the math, not us.

## License

Elara uses a split license model — strong copyleft on the node, permissive on
the client SDKs. See [LICENSING.md](LICENSING.md) for the full breakdown.

- **Node, network daemon, and protocol code** (the `elara-runtime` crate / the
  `elara-node` binary) — **AGPL-3.0-only** ([LICENSE](LICENSE)). Running a
  *modified* node as a network service obliges you to publish your changes
  (AGPL §13); running it unmodified does not. This keeps the network substrate
  open (the Grafana / MinIO / Mastodon pattern).
- **Client SDKs** under [`sdks/`](sdks/) and crates extracted from this tree —
  **MIT OR Apache-2.0** ([LICENSE-MIT](LICENSE-MIT) / [LICENSE-APACHE](LICENSE-APACHE)),
  at your option. Permissive on purpose: frictionless integration grows the
  network the node operates.

### Contribution

Contributions are accepted under the license of the component they modify
(inbound = outbound): changes to the AGPL node under AGPL-3.0, changes to a
permissively-licensed SDK or crate under MIT OR Apache-2.0. No contributor
license agreement is required.

## Author

**Nenad Vasic** — Solo developer, Montenegro
- Email: nenadvasic@protonmail.com
- GitHub: [@navigatorbuilds](https://github.com/navigatorbuilds)

---

*The same math for the teenager in Kenya and the colonist on Mars.*
