# elara-pq-transport

A **post-quantum network transport** in safe Rust: a deliberately minimal,
downgrade-proof wire frame, the session key schedule and bulk cipher that ride
on top of it, and a hand-rolled hybrid handshake that binds a session to a
long-term post-quantum identity.

## Wire frame

A deliberately minimal, downgrade-proof frame format.

```text
| magic "ELPQ" (4B) | version 0x02 (1B) | type (1B) | len (3B BE) | payload |
```

The current wire version is `0x02` (`frame.rs::WIRE_VERSION`); any other
version byte — including the retired `0x01` — is rejected at decode
(test-pinned: `decode_rejects_wrong_version`).

A fixed **9-byte header** and nothing else: no cipher-suite negotiation, no
extensions, no optional fields. There is nothing to downgrade because there is
nothing to negotiate. Anything that does not begin with `ELPQ\x02` is rejected
before a single payload byte is parsed — the transport never tries to recognise
a TLS `ClientHello` or an HTTP request from a probing adversary, so it offers no
polyglot-parsing surface.

The 3-byte big-endian length field caps a frame at `2^24 − 1` bytes (16 MiB − 1).
Frame type discriminants (`Hello`, `Challenge`, `Auth`, `Data`, `Rekey`, `Close`,
`StreamChunk`, `Admission`) are part of the wire format and are pinned by tests —
they are only ever appended to, never renumbered.

```rust
use elara_pq_transport::{Frame, FrameType};

let f = Frame::new(FrameType::Data, b"hello".to_vec()).unwrap();
let wire = f.encode();
let (decoded, consumed) = Frame::decode(&wire).unwrap();
assert_eq!(decoded, f);
assert_eq!(consumed, wire.len());
```

## Session crypto

After a handshake establishes two 32-byte shared secrets (one from X25519, one
from ML-KEM-768) and a SHA3-256 transcript hash, the session keys are derived as:

```text
prk    = HKDF-SHA256-Extract(salt = transcript_hash, ikm = x25519_ss || ml_kem_ss)
k_send = HKDF-Expand(prk, "ELPQ session v1 k_send", 32)
k_recv = HKDF-Expand(prk, "ELPQ session v1 k_recv", 32)
```

`k_send ≠ k_recv` by construction (distinct HKDF labels), so a frame can never
decrypt under the reverse-direction key — cross-direction replay is structurally
impossible. Bulk traffic is ChaCha20-Poly1305 with a 96-bit nonce built from a
per-direction monotonic counter (4 zero bytes + 8 big-endian counter bytes).
A `TranscriptHash` folds every handshake byte for the signature to bind. The
exact key-schedule and AEAD outputs are pinned by a known-answer test so the
wire format is reproducible by any independent implementation.

## Handshake

A hand-rolled **Noise-XX-style 3-message hybrid handshake** establishes the two
shared secrets above and binds the session to each peer's long-term identity:

```text
msg1  init → resp:  timestamp(8) || e_x25519_pk(32) || e_mlkem_pk(1184)
msg2  resp → init:  e_x25519_pk(32) || e_mlkem_ct(1088) || AEAD(pk_dil || sig_dil)
msg3  init → resp:                                         AEAD(pk_dil || sig_dil)
```

Each party signs the running transcript hash with **Dilithium3 / ML-DSA-65**
(FIPS 204), encrypted under the freshly derived session key. That signature is
the MITM killer **even if ML-KEM is broken**: an attacker cannot forge ML-DSA-65
over a transcript it did not participate in. The responder either pins the
peer's `SHA3-256(pk_dil)` against an expected hash or accepts it TOFU on first
contact. A 30-second timestamp window is the fast-abort path; the signed
transcript is the real check.

```rust
use elara_pq_transport::{PqHandshake, PeerExpectation};

// Each side drives the synchronous state machine; the caller moves bytes.
let (mut initiator, msg1) =
    PqHandshake::new_initiator(my_pk, my_sk, PeerExpectation::Tofu, now_unix_secs)?;
let mut responder = PqHandshake::new_responder(peer_pk, peer_sk, now_unix_secs)?;
let msg2 = responder.responder_process_msg1(&msg1)?;
let msg3 = initiator.initiator_process_msg2(&msg2)?;
responder.responder_process_msg3(&msg3)?;
let session = initiator.into_completed()?.session; // k_send / k_recv for bulk data
```

## Scope

This crate is the **framing + session-crypto + handshake core** of the Elara
Protocol's hybrid **ML-KEM-768 + X25519** key agreement with **Dilithium3**
identity binding. The async stream/RPC wrappers remain in the
[Elara Protocol](https://github.com/navigatorbuilds/elara-mesh) node for now;
the layers here carry no protocol dependencies.

## Platform support

This is a **native** node↔node transport — ML-KEM-768 is liboqs (C). The
`kem`, `sig`, and `handshake` layers compile for non-`wasm32` targets only.
On `wasm32` the crate degrades to the pure-Rust [`frame`] + [`crypto`] layers
(only `thiserror`/`hkdf`/`sha2`/`sha3`/`chacha20poly1305`/`zeroize`/`hex`), so it
can sit in a wasm consumer's dependency graph without pulling liboqs or forcing a
`getrandom` backend. The `oqs` feature (ML-KEM + handshake) is on by default;
disable it for a pure-Rust frame+crypto+sig build.

## License

Licensed under either of [MIT](LICENSE-MIT) or
[Apache-2.0](LICENSE-APACHE) at your option.
