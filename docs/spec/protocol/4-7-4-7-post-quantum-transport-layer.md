### 4.7 Post-Quantum Transport Layer

The Elara Protocol's transport between nodes is **post-quantum by default and post-quantum only on mainnet.** Classical TLS is not an alternate path, a fallback, or a deployment option — it is absent from the wire protocol on mainnet. Every byte that crosses the wire between two Elara nodes (gossip pushes, sync pulls, RPC calls, admin API, WebSocket streams) rides the ElaraPQ transport described below.

This section is normative. Implementations that ship classical TLS (rustls, OpenSSL, BoringSSL, native_tls) on a mainnet node-to-node interface are non-conformant.

#### 4.7.1 The Hybrid Handshake

ElaraPQ uses a three-message hybrid handshake in the Noise XX style. Key agreement combines classical X25519 with the NIST-standardized ML-KEM-768 (FIPS 203); both peers authenticate with their long-term ML-DSA-65 (FIPS 204, "Dilithium3") identity keys. Each message travels in a frame with a 9-byte header: `ELPQ_MAGIC` (4 bytes), `WIRE_VERSION` (1), frame type (1) and a 3-byte big-endian payload length. The payloads are:

```
msg1 (Hello): initiator → responder
  timestamp(8) | ephemeral_x25519_pk(32) | ephemeral_mlkem768_pk(1184)
  = 1224 bytes

msg2 (Challenge): responder → initiator
  ephemeral_x25519_pk(32) | mlkem768_ct(1088) |
  AEAD(responder_mldsa65_pk(1952) | responder_sig_over_transcript(3309)) + tag(16)
  = 6397 bytes

msg3 (Auth): initiator → responder
  AEAD(initiator_mldsa65_pk(1952) | initiator_sig_over_transcript(3309)) + tag(16)
  = 5277 bytes
```

The responder rejects a msg1 whose timestamp is more than `MAX_HANDSHAKE_SKEW_SECS` from its own clock. The session keys are derived as:

```
transcript_hash  = running SHA3-256 hash of the handshake, seeded with WIRE_VERSION
x25519_ss        = X25519(own ephemeral secret, peer's ephemeral public key)
mlkem768_ss      = ML-KEM-768 shared secret (the responder encapsulates to the
                   initiator's ephemeral key; the initiator decapsulates)
k_send, k_recv   = HKDF-SHA256(salt = transcript_hash,
                               ikm  = x25519_ss || mlkem768_ss),
                   expanded with the labels "ELPQ session v1 k_send" and
                   "ELPQ session v1 k_recv", 32 bytes each
```

The two keys feed ChaCha20-Poly1305 AEAD, one key per direction; they encrypt the identity blocks of msg2 and msg3 and every later frame. Each peer signs the running transcript hash with its ML-DSA-65 identity key, so impersonating a peer requires forging ML-DSA-65, and the identities never cross the wire in the clear. A dialing node that does not already know the peer's key pins the key presented on first contact (trust on first use). The hybrid key agreement means a passive attacker must break both X25519 (breakable by Shor's algorithm on a large quantum computer) **and** ML-KEM-768 (lattice-based, no known practical attack) to read the traffic.

Constants are normative:

| Constant | Value | Source |
|----------|-------|--------|
| `ELPQ_MAGIC` | `b"ELPQ"` | `crates/elara-pq-transport/src/frame.rs` |
| `WIRE_VERSION` | `0x02` | `crates/elara-pq-transport/src/frame.rs` |
| `MAX_HANDSHAKE_SKEW_SECS` | `30` | `crates/elara-pq-transport/src/handshake.rs` |
| `DEFAULT_HANDSHAKE_TIMEOUT` | `10s` | `src/network/pq_transport/stream.rs` |
| `MAX_PAYLOAD` | 2^24 − 1 bytes (16 MiB − 1), the most the 3-byte length field can express | `crates/elara-pq-transport/src/frame.rs` |

The Source column names the file, not a line: the constant's own name in column 1
is the anchor. Three of the four line numbers here were stale by 2026-09-06, and
`WIRE_VERSION` additionally read `0x01` while the shipped constant — and every
running node's `/version` — reported `0x02`. Do not confuse this transport-layer
`WIRE_VERSION` with the record-format `WIRE_VERSION` in `crates/elara-record/src/wire.rs`;
they are different constants on different version lines.

#### 4.7.2 ML-KEM-768 as a Transport-Layer Requirement

ML-KEM-768 (FIPS 203, NIST Security Level 3) is **not optional**. It is a wire-protocol-level requirement, on the same footing as Dilithium3 for record signatures. A node that does not implement ML-KEM-768 cannot speak the ElaraPQ transport and therefore cannot peer with any mainnet node.

This is stricter than §4.2's framing of cryptographic primitives, because §4.2 lists *what algorithms the protocol uses* whereas this section lists *what algorithms a conformant implementation must provide.* The two lists overlap fully today, but as the protocol absorbs new primitives via the algorithm-agility mechanism (§4.4) the transport layer's requirements may evolve faster than the broader primitive set — for example, if a future ML-KEM-1024 variant becomes mandatory for transport while ML-KEM-768 remains accepted for at-rest record keying.

#### 4.7.3 No Classical Transport Fallback

The protocol does not define a "classical-only" transport mode. Implementations are forbidden from offering one on mainnet. Specifically:

- HTTPS over TLS 1.3 with classical KEM (X25519, P-256, RSA) — forbidden as a node-to-node transport on mainnet.
- HTTPS over TLS 1.3 with hybrid KEM (X25519+ML-KEM-768) negotiated by IETF draft-ietf-tls-hybrid-design — forbidden, because the draft is not yet a standard and Elara does not pin to any in-flight standardization process.
- QUIC with the same primitives — forbidden on the same grounds.
- Plaintext UDP (any form) — forbidden as a node-to-node transport. Local discovery and NAT detection (mDNS, STUN and UPnP) do send plaintext UDP datagrams; they carry at most a node's identity hash, node type, software version and address, never records, attestations or seals.

The protocol permits a *bootstrap* exception (§11.14) in its design: a light client on first install would fetch a signed seed-peer list from a single HTTPS origin, once, and use ElaraPQ for all later traffic. This is not implemented. Today a node takes its seed peers from its operator's configuration, and the light-client SDK talks to a configured seed over HTTP(S) on the public listener that testnet nodes keep open (`allow_public_https`, default true; a node configured with `network_id = "mainnet"` refuses to start with it on).

Implementations that wish to integrate with non-Elara IoT or web infrastructure (MQTT bridges, CoAP gateways, HTTP REST APIs documented in §8.3) may use classical transports for that integration boundary. Those classical transports terminate at the gateway; the gateway then signs validation records with the device's PQ identity (Profile C, §4.6) and pushes them onto the DAM via ElaraPQ. The classical surface is a non-protocol boundary — outside the scope of this section.

#### 4.7.4 Pluggable Transports for Censored Networks

For deployments in jurisdictions that block direct ElaraPQ traffic, an operator can carry ElaraPQ frames inside an external tunnel (WireGuard, Tailscale, SSH port-forwarding, or Tor), since the transport runs over ordinary TCP; no pluggable transport is built into the node (Section 11.16). The ElaraPQ handshake and AEAD remain unchanged; the outer wrapper is opaque to the protocol.

What the protocol does **not** do: define a "domain-fronting mode" that masquerades as classical HTTPS to fool deep-packet-inspection middleboxes. Earlier drafts of this section described domain fronting as a censorship-resistance feature; that language is retired. Domain-fronting compromises the cryptographic transcript by accepting classical TLS framing on the outer layer, which leaks per-connection metadata (TLS ClientHello fingerprints, SNI when not encrypted via ECH, certificate chain timing) that defeat the transport's post-quantum forward-secrecy goal. Operators who need DPI-bypass should use Tor, Snowflake, or obfuscated VPNs as the carrier — not bake classical TLS into the protocol.

#### 4.7.5 Compliance Verification

A mainnet node operator can verify their deployment matches §4.7 by:

1. `ss -tlnp` shows only the ElaraPQ port bound on public interfaces (no port 443 / 9473 HTTPS listener).
2. `tcpdump -i any -w pcap` followed by `elara-capture-audit pcap` returns ≥99.9% sampled-payload `ELPQ_MAGIC` and zero `0x16 0x03 0x0[1234]` (TLS ClientHello) bytes on public interfaces.
3. `grep -rn "rustls\|TlsAcceptor\|tokio-rustls" src/` returns zero hits in the deployed binary's source.
4. The compiled binary's dependency graph (`cargo tree --features node`) lists no `rustls`, `tokio-rustls`, `rustls-pemfile`, `rustls-pki-types`, `rcgen`, `hyper`, or `hyper-util` as direct or transitive dependencies on the mainnet build profile.

These four checks are the operator-facing acceptance gates for §4.7 compliance.

**Status:** these gates describe the mainnet target, and three of them cannot pass today. No mainnet build profile exists: the node build depends on `hyper` and `hyper-util` directly and on `rustls`, `tokio-rustls` and `rustls-pki-types` through `reqwest`, so check 4 fails. The `elara-capture-audit` tool named in check 2 has not been written. The grep in check 3 matches four source comments. Check 1 depends on `allow_public_https` being off, which testnet nodes do not do by default.

