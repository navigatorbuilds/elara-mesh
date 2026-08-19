### 4.7 Post-Quantum Transport Layer

The Elara Protocol's transport between nodes is **post-quantum by default and post-quantum only on mainnet.** Classical TLS is not an alternate path, a fallback, or a deployment option — it is absent from the wire protocol on mainnet. Every byte that crosses the wire between two Elara nodes (gossip pushes, sync pulls, RPC calls, admin API, WebSocket streams) rides the ElaraPQ transport described below.

This section is normative. Implementations that ship classical TLS (rustls, OpenSSL, BoringSSL, native_tls) on a mainnet node-to-node interface are non-conformant.

#### 4.7.1 The Hybrid Handshake

ElaraPQ uses a three-message hybrid handshake combining classical Curve25519 with the NIST-standardized ML-KEM-768 (FIPS 203). The handshake is:

```
msg1: initiator → responder
  ELPQ_MAGIC(4) | WIRE_VERSION(1) | timestamp(8) |
  initiator_dilithium3_pk(1952) | initiator_x25519_pk(32) |
  initiator_kyber768_ct(1088) | initiator_dilithium3_sig_over_transcript(3309)
  = 6394 bytes

msg2: responder → initiator
  responder_x25519_pk(32) | responder_kyber768_ct(1088) |
  responder_dilithium3_sig_over_transcript(3309) | aead_tag(16)
  = 4445 bytes

msg3: initiator → responder
  aead_handshake_finished(48)
  = 48 bytes
```

The session key is derived as:

```
shared_x25519     = X25519(initiator_x25519_sk, responder_x25519_pk)
shared_kyber768   = ML-KEM-768.Decapsulate(responder_kyber768_ct, sk)
session_key       = HKDF-SHA256(salt = transcript_hash,
                                ikm  = shared_x25519 || shared_kyber768,
                                info = "elara-pq-session-v1",
                                len  = 32)
```

The session key feeds ChaCha20-Poly1305 AEAD for all subsequent frames. The transcript signature binds both peers to the full handshake under their long-term Dilithium3 identity keys, preventing transcript-substitution attacks. The hybrid construction means a successful attack must break both X25519 (classical, trivially broken by Shor's algorithm) **and** ML-KEM-768 (post-quantum, lattice-based, currently no known attack) — the protocol fails open only if both substrates fall.

Constants are normative:

| Constant | Value | Source |
|----------|-------|--------|
| `ELPQ_MAGIC` | `b"ELPQ"` | `crates/elara-pq-transport/src/frame.rs:23` |
| `WIRE_VERSION` | `0x01` | `crates/elara-pq-transport/src/frame.rs:27` |
| `MAX_HANDSHAKE_SKEW_SECS` | `30` | `crates/elara-pq-transport/src/handshake.rs:45` |
| `DEFAULT_HANDSHAKE_TIMEOUT` | `10s` | `src/network/pq_transport/stream.rs:80` |
| `MAX_FRAME` | 4 MiB after AEAD | `frame.rs` |

#### 4.7.2 ML-KEM-768 as a Transport-Layer Requirement

ML-KEM-768 (FIPS 203, NIST Security Level 3) is **not optional**. It is a wire-protocol-level requirement, on the same footing as Dilithium3 for record signatures. A node that does not implement ML-KEM-768 cannot speak the ElaraPQ transport and therefore cannot peer with any mainnet node.

This is stricter than §4.2's framing of cryptographic primitives, because §4.2 lists *what algorithms the protocol uses* whereas this section lists *what algorithms a conformant implementation must provide.* The two lists overlap fully today, but as the protocol absorbs new primitives via the algorithm-agility mechanism (§4.4) the transport layer's requirements may evolve faster than the broader primitive set — for example, if a future ML-KEM-1024 variant becomes mandatory for transport while ML-KEM-768 remains accepted for at-rest record keying.

#### 4.7.3 No Classical Transport Fallback

The protocol does not define a "classical-only" transport mode. Implementations are forbidden from offering one on mainnet. Specifically:

- HTTPS over TLS 1.3 with classical KEM (X25519, P-256, RSA) — forbidden as a node-to-node transport on mainnet.
- HTTPS over TLS 1.3 with hybrid KEM (X25519+ML-KEM-768) negotiated by IETF draft-ietf-tls-hybrid-design — forbidden, because the draft is not yet a standard and Elara does not pin to any in-flight standardization process.
- QUIC with the same primitives — forbidden on the same grounds.
- Plaintext UDP (any form) — forbidden.

The protocol does permit a *bootstrap* exception (§11.14): light clients on first install retrieve a foundation-signed seed-peer list from a single foundation-operated HTTPS origin, used exactly once. After first contact, all subsequent traffic uses ElaraPQ.

Implementations that wish to integrate with non-Elara IoT or web infrastructure (MQTT bridges, CoAP gateways, HTTP REST APIs documented in §8.3) may use classical transports for that integration boundary. Those classical transports terminate at the gateway; the gateway then signs validation records with the device's PQ identity (Profile C, §4.6) and pushes them onto the DAM via ElaraPQ. The classical surface is a non-protocol boundary — outside the scope of this section.

#### 4.7.4 Pluggable Transports for Censored Networks

For deployments in jurisdictions that block direct ElaraPQ traffic, the protocol supports tunneling ElaraPQ frames inside other transports (Tor pluggable transports, WireGuard, Tailscale, SSH port-forwarding). The ElaraPQ handshake and AEAD remain unchanged; the outer wrapper is opaque to the protocol.

What the protocol does **not** do: define a "domain-fronting mode" that masquerades as classical HTTPS to fool deep-packet-inspection middleboxes. Earlier drafts of this section described domain fronting as a censorship-resistance feature; that language is retired. Domain-fronting compromises the cryptographic transcript by accepting classical TLS framing on the outer layer, which leaks per-connection metadata (TLS ClientHello fingerprints, SNI when not encrypted via ECH, certificate chain timing) that defeat the transport's post-quantum forward-secrecy goal. Operators who need DPI-bypass should use Tor, Snowflake, or obfuscated VPNs as the carrier — not bake classical TLS into the protocol.

#### 4.7.5 Compliance Verification

A mainnet node operator can verify their deployment matches §4.7 by:

1. `ss -tlnp` shows only the ElaraPQ port bound on public interfaces (no port 443 / 9473 HTTPS listener).
2. `tcpdump -i any -w pcap` followed by `elara-capture-audit pcap` returns ≥99.9% sampled-payload `ELPQ_MAGIC` and zero `0x16 0x03 0x0[1234]` (TLS ClientHello) bytes on public interfaces.
3. `grep -rn "rustls\|TlsAcceptor\|tokio-rustls" src/` returns zero hits in the deployed binary's source.
4. The compiled binary's dependency graph (`cargo tree --features node`) lists no `rustls`, `tokio-rustls`, `rustls-pemfile`, `rustls-pki-types`, `rcgen`, `hyper`, or `hyper-util` as direct or transitive dependencies on the mainnet build profile.

These four checks are the operator-facing acceptance gates for §4.7 compliance.

