### 4.2 Cryptographic Primitives

The Elara Protocol uses NIST-standardized post-quantum algorithms across **all** cryptographic surfaces — signatures, key exchange, randomness, zero-knowledge, hashes, AEAD, and key-derivation. The protocol is PQ-uniform: there is no classical-public-key primitive on any path that touches mainnet records, attestations, seals, transport, or proofs.

#### Signatures

**CRYSTALS-Dilithium** (ML-DSA, FIPS 204) — Digital signatures
- Used for: signing validation records, authenticating node identity
- Security basis: Module Lattice-Based Digital Signature (ML-DSA-65, NIST Security Level 3)
- Signature size: ~3.3 KB (3,293 bytes in liboqs Round 3 implementation; FIPS 204 final specifies 3,309 bytes for ML-DSA-65 — the 16-byte difference reflects standardization changes, migration planned)
- Signing speed: ~0.3 ms on modern hardware
- Selected for: balance of security, performance, and signature size

**SPHINCS+** (FIPS 205, SLH-DSA) — Hash-based signatures
- Used for: long-term anchor signatures, seed vault attestation, root of trust, optional dual-sig under §4.3
- Security basis: stateless hash-based signatures (SLH-DSA, no algebraic structure)
- Signature size: ~35 KB (SPHINCS+-SHA2-192f / SLH-DSA-SHA2-192f)
- Signing speed: slower than Dilithium (~10 ms)
- Selected for: conservative security assumptions — if lattice-based cryptography fails, hash-based signatures remain secure under minimal hash assumptions

#### Key encapsulation

**CRYSTALS-Kyber** (ML-KEM, FIPS 203) — Key encapsulation
- Used for: establishing encrypted channels between nodes, session-key exchange in PQ transport (`src/network/pq_transport/`)
- Security basis: Module Learning With Errors (ML-KEM-768, NIST Security Level 3)
- Ciphertext size: ~1.1 KB (Kyber768)
- Selected for: efficiency in key exchange, well-studied security proofs

#### Verifiable randomness

**Dilithium3-VRF (alg = `0x11`)** — a post-quantum verifiable, unique, unforgeable selection function (sortition). This is **not a full RFC-9381 VRF**: it provides verifiability, uniqueness, and unforgeability, but **not output secrecy** (see security properties below).
- Used for: epoch-seal entropy, per-zone witness committee selection (Efraimidis-Spirakis stake-weighted draw), fisherman jury selection
- Construction: `output = SHA3-256("elara-vrf-v1" || pk || alpha)` — a deterministic public function of the public key and input; `proof = Dilithium3 signature over output`. Verification recomputes the output from `(pk, alpha)` and checks the signature against `pk`. ML-DSA signing is randomized (FIPS 204), so the output is deliberately **not** derived from the signature — the signature serves only as the unforgeable authorization proof.
- Algorithm tag: `0x11` in the proof wire format (single-byte prefix)
- Security properties: **uniqueness** (exactly one valid output per `(pk, alpha)`, from the deterministic hash), **verifiability** (anyone checks with `pk`), **unforgeability** (no valid proof without `sk`, under ML-DSA hardness). **Not provided: output secrecy** — the output is publicly computable from `(pk, alpha)`, so a draw is unpredictable only insofar as `alpha` carries entropy not known in advance (e.g. a prior epoch seal). The primitive is not relied on for output pseudorandomness against a holder of `pk`.
- Proof size: ~3.3 KB (a Dilithium3 signature)
- Legacy compatibility: algorithm tag `0x10` (EC-VRF/RFC 9381 over Ed25519) was retired 2026-03-31. The legacy EC-VRF verifier has been removed, so `0x10` proofs are detected, increment the `elara_legacy_vrf_proof_total` Prometheus counter (expected count = 0 on mainnet post-genesis), and are rejected — no feature flag re-enables them

#### Zero-knowledge

> **Implementation status — DESIGN-STAGE.** The Phase-1 runtime implements
> **SHA3-256 commitment proofs** (`src/crypto/commitment.rs`), not zk-SNARKs or
> STARKs. The Groth16 and STARK constructions below are the **specified
> migration target** — there is no Groth16/STARK prover, verifier, or Cargo
> feature in the tree. See §5.3 and whitepaper §14.3.

**SHA3-256 commitment proofs (IMPLEMENTED)** — the Phase-1 privacy layer
- Used for: balance-range proofs (PRIVATE classification), metadata-property proofs, content-commitment proofs
- Construction: deterministic SHA3-256 commitments that prove a property of hidden data (e.g. balance ≥ threshold) without revealing the value. As `commitment.rs` states plainly, these are commitments — "not zero-knowledge, not post-quantum in the ZK sense" — a pragmatic Phase-1 stand-in for the circuits specified in §5.3
- Verifier: fail-closed (`src/crypto/zk.rs`, `src/crypto/commitment.rs`); malformed proofs are rejected

**STARKs (FRI-based) — DESIGN-STAGE** — the post-quantum ZK target *(transition path: see §4.4 algorithm agility)*
- Would be used for: the same three proof properties, with genuine zero-knowledge + post-quantum security
- Security basis: FRI (Fast Reed-Solomon Interactive Oracle Proofs), built solely on collision-resistant hashes — no trusted setup
- Proof size: ~50–200 KB depending on circuit (larger than Groth16, but post-quantum)
- Migration path: Groth16 (BN254 pairings, classical) is the intermediate design target; STARKs are the post-quantum endpoint. Neither a Groth16 nor a STARK prover/verifier exists in the tree today; the proof envelope reserves version bytes (`0x02` Groth16, rejected fail-closed) so a future prover can be slotted in without a wire-format break

#### Hashes

**SHA3-256** (Keccak-f[1600] permutation, FIPS 202)
- Used for: record IDs, content-hash commitments, Merkle trees (account state SMT, attestation index, Merkle-root chunk manifests in tiered storage), Dilithium3-VRF input compression, key derivation under HKDF
- Security basis: 128-bit effective Grover-quantum strength; collision-resistant under standard assumptions
- Selected for: hash-based primitives are the most conservative PQ surface — Grover at most square-roots brute-force attacks, no algebraic shortcut

**Poseidon** (over BN254 base field) — ZK-friendly hash *(DESIGN-STAGE — not in the tree)*
- Would be used for: content commitments inside the design-stage Groth16 circuits (§5.3.1); SMT path hashing within those circuits
- Security note: Poseidon's BN254 instantiation is itself classical (BN254 base field). It is **not present in the runtime** — the Phase-1 commitment scheme and all live hashing use SHA3-256. In the specified Groth16 design, Poseidon's classical reach would match Groth16's and retire together under §4.4; the STARK endpoint uses SHA3-based hashing throughout.

#### Authenticated encryption

**ChaCha20-Poly1305** (RFC 8439, IETF AEAD)
- Used for: PQ transport AEAD layer (`crates/elara-pq-transport/src/frame.rs`), session-key envelope after Kyber768 KEM
- Security basis: 256-bit symmetric key, 128-bit Poly1305 tag; effective 128-bit quantum strength under Grover (NIST PQ guidance — symmetric primitives at ≥ 256-bit keys remain quantum-acceptable)

**AES-256-GCM** — Symmetric AEAD (alternate)
- Used for: identity-at-rest encryption (private-key file encryption with passphrase-derived KEK)
- Security basis: 256-bit AES key, 128-bit GCM tag; 128-bit effective quantum strength under Grover

#### Key derivation

**HKDF-SHA256** (RFC 5869) — Extract-then-expand KDF
- Used for: deriving session keys from Kyber768 shared secrets; per-channel subkey derivation in PQ transport
- Security basis: pseudorandomness from underlying SHA-256 (or SHA3-256 in Elara's instantiation); 128-bit effective quantum strength

**Argon2id** (RFC 9106) — Memory-hard passphrase KDF
- Used for: deriving identity-encryption KEK from operator passphrase, seed-vault unlock
- Security basis: memory-hard hash; not a public-key primitive — quantum exposure equivalent to its hash core (acceptable under NIST PQ guidance for symmetric KDFs)

#### NOT USED — classical primitives explicitly excluded from the runtime path

Every primitive below was considered and rejected for the mainnet node path. There is no Groth16/BN254/pairing implementation in the node (no such crate, module, or Cargo feature); a `grep -rn "ed25519|secp256k1|p256|ecdsa|bn254|bls12|pairing" src/` returns only comment strings documenting the rationale below and reserved version-byte constants — not live classical public-key code. (The optional `verify-cli` tool is the one exception: it pulls `drand-verify` for BLS12-381 beacon checks, outside the node graph — see the BLS row.)

| Primitive | Rationale for exclusion |
|---|---|
| **Ed25519 / Ed448** (EdDSA) | Curve-based discrete-log, CRQC-breakable under Shor in polynomial time. Used historically only in `vrf_legacy.rs` (alg=0x10), retired 2026-03-31. No new records, attestations, seals, or proofs emit Ed25519. |
| **ECDSA secp256k1** (Bitcoin/Ethereum signature curve) | Same Shor exposure as Ed25519. Never used in Elara runtime. Mentioned in OpenTimestamps anchoring (§ companion docs) for whitepaper prior-art only — not a runtime dependency. |
| **ECDSA P-256 / NIST curves** | Same Shor exposure. Excluded from PQ transport, signature, and KEM paths. |
| **RSA** (any modulus size) | Shor breaks RSA in polynomial time on a sufficiently capable CRQC. No Elara path uses RSA; PQ transport uses Kyber768 KEM, signatures use Dilithium3/SPHINCS+. |
| **BN254 / BLS12-381 pairings** | Pairing-based curves are CRQC-breakable, so they are excluded from the node consensus, transport, and signature paths. BN254 appears only in the design-stage Groth16 construction (§5.3) — **no BN254/pairing code is in the tree**. BLS12-381 is used **only** by the optional `verify-cli` offline tool (`drand-verify`, to check drand randomness-beacon signatures on anchors), never by the node. |
| **BLS threshold signatures** | Pairing-based threshold cryptography is CRQC-breakable. Phase 5.1 (cryptographically-blind mempool) is locked to lattice-based or hash-based threshold schemes — see §4F.3 decision 2026-04-19. No BLS threshold on the mainnet path, ever. |
| **ECDH (any curve)** | Replaced by Kyber768 KEM for key agreement. PQ transport never falls back to ECDH. |
| **NaCl / standalone X25519** | Not used as a *standalone* classical key-exchange and never for signatures. `x25519-dalek` **is** a dependency — but only as the classical half of the **hybrid ML-KEM-768 + X25519** transport key-exchange (defence-in-depth: the session key stays secret unless *both* the PQ and classical halves break). It is never a classical fallback. |

#### Coverage summary

| Cryptographic surface | Primitive | Standard | Quantum status |
|---|---|---|---|
| Record signatures | Dilithium3 | ML-DSA, FIPS 204 | PQ |
| Anchor / dual-sig | SPHINCS+ | SLH-DSA, FIPS 205 | PQ |
| Session-key exchange | Kyber768 | ML-KEM, FIPS 203 | PQ |
| Verifiable randomness | Dilithium3-VRF | derived from FIPS 204 | PQ |
| Zero-knowledge proofs | SHA3-256 commitments (Phase-1); STARKs are the design-stage target (§5.3) | SHA3 commitments / FRI (design-stage) | Hash-based (PQ-acceptable); genuine ZK is design-stage |
| Hashes & Merkle | SHA3-256 | FIPS 202 | PQ-acceptable (128-bit Grover) |
| AEAD (transport) | ChaCha20-Poly1305 | RFC 8439 | PQ-acceptable (128-bit Grover, 256-bit key) |
| AEAD (at-rest) | AES-256-GCM | NIST | PQ-acceptable (128-bit Grover) |
| KDF (session) | HKDF-SHA256 | RFC 5869 | PQ-acceptable |
| KDF (passphrase) | Argon2id | RFC 9106 | PQ-acceptable (hash-based) |

The protocol is PQ across signatures, KEM, VRF, hashes, AEAD, and KDFs. The session-key exchange is a **hybrid** ML-KEM-768 + X25519 construction — the classical half is defence-in-depth (the session key stays secret unless *both* halves break), never a classical fallback or opt-out. The one designed-but-not-yet-PQ-ZK surface is the privacy layer: Phase-1 uses SHA3-256 commitments (hash-based, PQ-acceptable), with genuine post-quantum STARKs as the specified target (§5.3, §14.3). The only legacy surface is the rejection of pre-2026-03-31 EC-VRF (`0x10`) proofs.

