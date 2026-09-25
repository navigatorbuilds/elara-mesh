# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest on `main` | Yes |
| Older releases | Best effort |

## Reporting a Vulnerability

If you discover a security vulnerability in Elara Runtime, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

### How to report

1. **Email:** Send details to **nenadvasic@protonmail.com** with subject line `[SECURITY] elara-runtime: <brief description>`
2. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to expect

- **Acknowledgment** within 48 hours
- **Assessment** within 7 days
- **Fix timeline** depends on severity:
  - Critical (key compromise, auth bypass): patch within 72 hours
  - High (data exposure, privilege escalation): patch within 2 weeks
  - Medium/Low: addressed in next release

### Scope

The following are in scope:

- Authentication and authorization bypass
- Cryptographic weaknesses (PQC implementations, key handling)
- Beat-ledger exploits (double-spend, conservation violation)
- Network protocol attacks (gossip poisoning, consensus manipulation)
- Denial of service against node daemon
- Identity key exposure or theft
- Admin endpoint security

### Out of scope

- Social engineering
- Attacks requiring physical access to the server
- Issues in dependencies (report upstream, but do let us know)
- Theoretical attacks without a proof of concept

## Recognition for Security Researchers

Elara has no bug-bounty fund and validation beats are an internal protocol
mechanism — not a currency, not transferable, not for sale — so we do not pay
monetary bounties. What we offer instead:

- **Credit in the release notes** for the fix (or anonymity, if you prefer).
- **On-mesh provenance**: your finding (with your name or handle, your call)
  is recorded and anchored as a permanent, externally-verifiable record of
  who found what, when — which is rather on-brand.

### Severity classes (for triage)

| Severity | Impact |
|----------|--------|
| **Critical** | Conservation violation (beat creation/destruction), consensus bypass, key compromise |
| **High** | Double-spend, identity theft, admin bypass, Sybil attack that defeats the sortition-based witness jury |
| **Medium** | DoS that crashes nodes, gossip poisoning, data corruption, attestation manipulation |
| **Low** | Information disclosure, timing attacks, edge-case panics |

### Rules

1. **One bug, one report.** Don't chain multiple issues into one submission.
2. **Test locally only.** Use the `elara-simulate` binary on your own machine; never test against other people's nodes.
3. **No DoS testing on production.** Use the `elara-simulate` binary for adversarial testing locally.
4. **Provide a PoC.** Theoretical attacks without reproduction steps are out of scope.
5. **First reporter wins.** Duplicate reports receive acknowledgment but no reward.
6. **Responsible disclosure.** Give us 90 days before public disclosure.

### Where to Test

There are currently no public testnet endpoints. Test locally — the
simulator runs a full multi-node network on your machine:

### How to Test Locally

```bash
cargo build --release --features node
cargo run --features node --bin elara-simulate -- basic    # 4-node local sim
cargo run --features node --bin elara-fuzz                 # 1000 adversarial test cases
```

## Content & Abuse Reports

The mesh stores **commitments, not content** — records carry hashes and
bounded metadata; payloads live off-mesh with whoever hosts them (full
doctrine: `docs/CONTENT-POSTURE.md`). That shapes what an abuse report can
achieve:

- **Abuse contact:** **nenadvasic@protonmail.com**, subject line
  `[ABUSE] elara: <brief description>`. Same 48-hour acknowledgment
  commitment as vulnerability reports.
- **Hosted content** (the bytes a record points at): we never host it.
  Reports about the content itself go to the off-mesh host or provider —
  we can tell you which record attested it and when, which is often useful
  evidence for exactly that report.
- **Metadata abuse** (abusive bytes smuggled into record metadata): on
  nodes we operate we unpin the record, drop it from local retention, and
  flag it. Other operators apply their own jurisdiction's law to what they
  store. The protocol guarantees attested history cannot be silently
  rewritten — it does not guarantee universal hosting of every byte.
- **Every action is documented.** Responses to abuse are themselves
  recorded — we are a provenance project, and the response trail is part
  of the posture.
- **Legal process:** requests from law enforcement or counsel go to the
  same contact and are escalated to the operator. What we never do, by
  design: protocol-level content deletion, silent removals, or any
  authority that can rewrite attested history.

## Security model & current maturity

**Read this before relying on anything below.** Elara distinguishes, deliberately and throughout its documentation, what is *designed* from what is *tested*.

**Adversary model (designed).** The full adversary model and a 34-vector attack analysis live in the specification under `docs/spec/protocol/` (§11, "Threat model" and "Adversarial resilience"). In summary, adversaries are tiered from an individual (a few nodes), through an organization (hundreds of nodes, capital) and a nation-state (network-level control, legal coercion), to a future quantum adversary. Safety assumes the standard BFT condition — at least two-thirds of staked weight in any zone is held by honest nodes — plus the computational hardness of the NIST PQC primitives. The spec also states plainly what the protocol does **not** defend against (a signing key compromised together with physical theft of unreleased content; social engineering that induces a victim to sign). One more item belongs on that list today: an adversary that breaks ML-DSA alone. The hash-based second signature is not yet bound to identities, so it does not stop that adversary (see `docs/KNOWN-LIMITATIONS.md`).

**Designed vs. deployed (the honest gap).** The implementation is substantial (~410k lines of Rust with a large automated test suite) but it is **not** a battle-tested network. At the time of writing it runs as a single authority node plus a small number of followers; it has **not** run a public multi-node testnet, has **no** external users, and has had **no** third-party security audit. Consequently the Byzantine-fault-tolerance, Sybil-resistance, and per-zone witness-committee properties are **designed and unit-tested, not demonstrated under multi-node adversarial conditions**. "MESH-BFT" is a custom BFT-family consensus design, not a formally verified or externally peer-reviewed protocol. Every scale figure in the documentation (e.g. millions of zones, trillions of records per day) is a **design target, never measured at scale**. An independent security audit and a public testnet are the explicit next steps before these properties should be relied upon.

**What you can verify today, without trusting any node.** The one security property that is *demonstrable right now*, by anyone, offline, is verification. A fresh user can check a record's post-quantum signature (ML-DSA-65, plus the SPHINCS+ signature on Profile A records, with the limits below) and — given the proofs — its inclusion in a validator-signed epoch seal and a time bracket on that seal, as pure local math, trusting no node (`examples/verify/`). The trust boundaries are stated honestly rather than rounded up to "trustless":

- The Bitcoin **existed-by** upper bound is verified **only** when the archived block header is authenticated against a block hash pinned in the verifier (the `examples/verify/` sample's block is pinned). Even then the bound is the block's header time, which the miner sets: Bitcoin lets it trail the real mining time, typically by at most about an hour. An OpenTimestamps proof against an *unpinned* header is a **reference** bound: the proof cryptographically commits the artifact into a Bitcoin merkle root, but an offline tool cannot prove that header sits on the canonical chain (no PoW chain to a checkpoint), so its strength rests on the operator-supplied header's authenticity, which you establish out-of-band (any Bitcoin explorer). The verifier marks the two cases distinctly and never grades an unauthenticated header as verified.
- The drand **not-before** lower bound is verified **only** when the beacon's BLS signature is verified against the pinned League-of-Entropy public key and pinned chain genesis/period constants. It then assumes that fewer than drand's threshold of League-of-Entropy operators collude.
- A record → seal → anchor chain is *bound* only when all of its links (record↔proof, proof↔seal inclusion, seal↔anchor) are present and checked; with any link withheld the verifier returns **PARTIAL** or **FAILED**, never a false **VERIFIED** — behaviour covered by the verifier's own honest-failure and false-chain-rejection test legs.

## Security Design

- **Post-quantum cryptography:** ML-DSA-65 (FIPS 204, "Dilithium3") signs every record; there is no classical-signature mode. Profile A identities add a second signature, SPHINCS+-SHA2-192f; Profile B is ML-DSA-65 only. Two limits apply to that second signature today. Its backend hashes with SHA-256 throughout, where FIPS 205 requires SHA-512 at this security category, so it is not FIPS 205 SLH-DSA and does not interoperate with it (`crates/elara-record/tests/acvp_slhdsa192f.rs` pins this against NIST's vectors). And its public key travels inside the record and is bound neither to the creator's identity nor to the ML-DSA-signed bytes, so it adds no protection against an ML-DSA break until that binding is built. ML-KEM-768 (FIPS 203) key encapsulation, from the CRYSTALS-Kyber family (the FIPS parameter sets are not wire-compatible with the round-3 submissions)
- **Admin authentication:** post-quantum-signed `X-PQ-Admin` header (Dilithium3, bound to the exact method + path) on all admin endpoints — bearer-token auth was removed in PQ-R7; the legacy `admin_token` survives only on the proxied `/rpc/*` path, compared constant-time
- **Admin brute-force protection:** IPs locked out after 5 failed attempts in 5 minutes
- **Rate limiting:** per-IP token bucket with deny list
- **Transport security:** inter-node consensus traffic uses the post-quantum transport (Dilithium3-authenticated handshake, hybrid X25519 + ML-KEM-768 key exchange). Peer keys are trust-on-first-use: a node dialling a peer accepts the Dilithium3 key it presents on first contact and pins it for later dials (`PeerExpectation::Tofu` in `crates/elara-pq-transport/src/handshake.rs`). The ProVerif proofs in `spec/proverif/` authenticate a peer the initiator has already pinned, so a man-in-the-middle at first contact is outside them. Seed peers are configured as plain addresses, so a node's first contact with them is trust-on-first-use too. An operator can close that gap by writing a peer's identity hash into `<data_dir>/pq-peer-pins.json` before first contact, with the node stopped (the store is `PeerIdentityStore` in `src/network/pq_transport/peer_store.rs`), but nothing does it by default. The classical HTTP API is served plaintext — terminate public HTTPS at a reverse proxy (e.g. Caddy or nginx).
- **Key files:** identity files, and the VRF key file that sealing nodes keep, are created with 0600 permissions (owner read/write only) and replaced atomically, so the keys are never readable by others, even briefly, and a crash cannot leave a half-written key file in place. Identity files are plaintext JSON unless `ELARA_IDENTITY_PASSPHRASE` is set (Argon2id + AES-256-GCM); set `ELARA_REQUIRE_ENCRYPTED_IDENTITY=1` to make the node refuse a plaintext file. The VRF key file is always plaintext. Encrypting an existing plaintext file rewrites it, but cannot erase the old plaintext from the disk underneath.
- **Admin surface:** fails closed — requests without a valid `X-PQ-Admin` signature are rejected, and the `/rpc/*` token path is rejected by default when not configured

## Cryptographic dependencies

Elara does not implement its post-quantum signature or key-exchange algorithms itself. What it relies on, and what those projects say about themselves:

- **ML-DSA-65:** `dilithium-rs` 0.2.0, pure Rust. Its own `SECURITY.md` lists only 0.1.x as a supported version. Under "What this crate does NOT provide" it lists a "Certified FIPS 204 module" ("has not been submitted for CMVP validation"), "Side-channel hardened signing" ("the signing path uses rejection sampling with data-dependent branches"), and "Formal verification".
- **SPHINCS+-SHA2-192f:** `lattice-slh-dsa` 0.3.3, pure Rust. Its README says it is FIPS 205 compliant; for the parameter set we use it is not (see the Profile A limits above).
- **ML-KEM-768:** `oqs` 0.11 over liboqs 0.13.0, used only for the ML-KEM half of the hybrid transport key exchange. The liboqs README says: "WE DO NOT CURRENTLY RECOMMEND RELYING ON THIS LIBRARY IN A PRODUCTION ENVIRONMENT OR TO PROTECT ANY SENSITIVE DATA." Session secrecy does not rest on ML-KEM alone: the X25519 half carries it if ML-KEM fails (`spec/proverif/`, scenario `mlkem_broken`).

Whatever review these libraries have had, Elara's own code, including how it uses them, has had no third-party security audit.

## License

See LICENSE files in the repository root.
