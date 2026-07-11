//! PQ-transport wire frame.
//!
//! ```text
//! | magic "ELPQ" (4B) | version 0x02 (1B) | type (1B) | len (3B BE) | payload |
//! ```
//!
//! - Fixed 9-byte header. No negotiation, no extensions, no cipher-suite
//!   selection — there is nothing to downgrade.
//! - Length field is 3 bytes big-endian → max payload = 16 MiB. Handshake
//!   messages cap well under that; data frames respect the session rekey
//!   threshold (2^30 bytes total) which is far above any single frame.
//! - Anything that fails to parse as a valid frame immediately drops the
//!   connection. We never attempt to recognise TLS ClientHello or HTTP
//!   requests from a probing adversary.

use std::io;

/// Wire magic: the ASCII bytes `E L P Q`.
///
/// Every PQ-transport frame starts with these four bytes. A peer that
/// speaks TLS, HTTP, or anything else will not send this prefix, and we
/// drop the connection without parsing further.
pub const ELPQ_MAGIC: [u8; 4] = *b"ELPQ";

/// Current wire version. Bump on ANY change observable on the wire — not
/// just the frame header layout, but ALSO the post-handshake AEAD
/// associated-data construction (see `PqStream::decrypt_frame`) and the
/// HKDF session-key schedule (`crypto::derive_session_keys`). The handshake
/// seeds its transcript with this byte (`handshake::PqHandshake::new_*`), so
/// two peers on different `WIRE_VERSION` values derive divergent session
/// keys and fail the handshake AEAD CLEANLY (counted as a handshake
/// failure), instead of silently failing every post-handshake frame.
///
/// 0x01 → 0x02 (2026-06-30): commit 483569ea changed the frame AEAD AD from
/// empty to `[frame_type]` WITHOUT bumping this byte, silently desyncing
/// every stale peer post-handshake — the exact failure mode this versioning
/// now closes. Never bump for optional, wire-invisible features.
pub const WIRE_VERSION: u8 = 0x02;

/// Fixed header length (magic 4 + version 1 + type 1 + length 3).
pub const HEADER_LEN: usize = 9;

/// Maximum payload size = 2^24 - 1 bytes (16 MiB - 1). Enforced by the
/// 3-byte length field.
pub const MAX_PAYLOAD: usize = (1 << 24) - 1;

/// Frame types. Numeric values are part of the wire format — never
/// renumber, only append.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    /// Initiator → Responder: handshake message 1 (ephemeral public keys).
    Hello = 1,
    /// Responder → Initiator: handshake message 2 (KEM ciphertext + auth).
    Challenge = 2,
    /// Initiator → Responder: handshake message 3 (identity + signature).
    Auth = 3,
    /// Post-handshake application payload, AEAD-protected.
    Data = 4,
    /// Explicit session key rotation (rekey with fresh HKDF info label).
    Rekey = 5,
    /// Graceful shutdown.
    Close = 6,
    /// Server-sent event chunk in a streaming response (4E.3).
    /// One request (carried in a [`FrameType::Data`] frame) is answered by
    /// a sequence of `StreamChunk` frames, the last of which carries the
    /// `FINAL` flag in its envelope. Callers that don't use streaming
    /// responses never see this type.
    StreamChunk = 7,
    /// REALMS P1 slice (b): post-handshake realm-admission exchange,
    /// AEAD-protected like Data. Emitted ONLY by responders whose
    /// configured realm is not `Open` — public-mesh nodes never send or
    /// receive it, and pre-realm peers decode it as `UnknownType(8)` and
    /// drop, which is the correct outcome (a legacy node cannot join a
    /// federated realm).
    Admission = 8,
}

impl FrameType {
    fn from_byte(b: u8) -> Result<Self, FrameError> {
        match b {
            1 => Ok(FrameType::Hello),
            2 => Ok(FrameType::Challenge),
            3 => Ok(FrameType::Auth),
            4 => Ok(FrameType::Data),
            5 => Ok(FrameType::Rekey),
            6 => Ok(FrameType::Close),
            7 => Ok(FrameType::StreamChunk),
            8 => Ok(FrameType::Admission),
            other => Err(FrameError::UnknownType(other)),
        }
    }
}

/// A parsed, validated PQ-transport frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub frame_type: FrameType,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn new(frame_type: FrameType, payload: Vec<u8>) -> Result<Self, FrameError> {
        if payload.len() > MAX_PAYLOAD {
            return Err(FrameError::PayloadTooLarge(payload.len()));
        }
        Ok(Self { frame_type, payload })
    }

    /// Serialize to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.payload.len());
        out.extend_from_slice(&ELPQ_MAGIC);
        out.push(WIRE_VERSION);
        out.push(self.frame_type as u8);
        let len = self.payload.len() as u32;
        // 3-byte big-endian length. Guaranteed to fit by the MAX_PAYLOAD check.
        out.push(((len >> 16) & 0xFF) as u8);
        out.push(((len >> 8) & 0xFF) as u8);
        out.push((len & 0xFF) as u8);
        out.extend_from_slice(&self.payload);
        out
    }

    /// Parse a frame from a byte slice. Returns the frame plus the number
    /// of bytes consumed (so callers can decode stream-framed input).
    ///
    /// No partial-recovery behaviour: the first parse error drops.
    pub fn decode(input: &[u8]) -> Result<(Self, usize), FrameError> {
        if input.len() < HEADER_LEN {
            return Err(FrameError::Incomplete);
        }
        if input[0..4] != ELPQ_MAGIC {
            return Err(FrameError::BadMagic);
        }
        if input[4] != WIRE_VERSION {
            return Err(FrameError::UnsupportedVersion(input[4]));
        }
        let frame_type = FrameType::from_byte(input[5])?;
        let len = ((input[6] as u32) << 16) | ((input[7] as u32) << 8) | (input[8] as u32);
        let len = len as usize;
        let total = HEADER_LEN + len;
        if input.len() < total {
            return Err(FrameError::Incomplete);
        }
        let payload = input[HEADER_LEN..total].to_vec();
        Ok((Frame { frame_type, payload }, total))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("frame incomplete: need more bytes")]
    Incomplete,
    #[error("bad magic: expected ELPQ")]
    BadMagic,
    #[error("unsupported wire version: {0:#x}")]
    UnsupportedVersion(u8),
    #[error("unknown frame type: {0}")]
    UnknownType(u8),
    #[error("payload too large: {0} bytes (max {MAX_PAYLOAD})")]
    PayloadTooLarge(usize),
    #[error("io error: {0}")]
    Io(#[from] io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_each_frame_type() {
        for ft in [
            FrameType::Hello,
            FrameType::Challenge,
            FrameType::Auth,
            FrameType::Data,
            FrameType::Rekey,
            FrameType::Close,
            FrameType::StreamChunk,
            FrameType::Admission,
        ] {
            let original = Frame::new(ft, vec![0xAB; 128]).unwrap();
            let wire = original.encode();
            let (decoded, used) = Frame::decode(&wire).unwrap();
            assert_eq!(decoded, original);
            assert_eq!(used, wire.len());
        }
    }

    /// Empirical fail-closed fuzz: `Frame::decode` must never panic/hang/OOM on
    /// any input. Zero-dep seeded splitmix64 (reproducible). Three input classes:
    /// pure-random; valid-header-with-arbitrary-claimed-length (the 3-byte len-prefix
    /// DoS — a huge claimed length with a too-short payload MUST return `Incomplete`,
    /// never allocate up to 16 MiB); and valid-frame-then-mutated.
    #[test]
    fn fuzz_decode_is_fail_closed() {
        struct R(u64);
        impl R {
            fn next_u64(&mut self) -> u64 {
                self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
                let mut z = self.0;
                z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
                z ^ (z >> 31)
            }
            fn below(&mut self, m: usize) -> usize {
                if m == 0 { 0 } else { (self.next_u64() % m as u64) as usize }
            }
        }
        let types = [
            FrameType::Hello,
            FrameType::Challenge,
            FrameType::Auth,
            FrameType::Data,
            FrameType::Rekey,
            FrameType::Close,
            FrameType::StreamChunk,
            FrameType::Admission,
        ];
        let mut r = R(0xF8A3_0001);
        for _ in 0..40_000 {
            let input: Vec<u8> = match r.below(3) {
                0 => (0..r.below(48)).map(|_| (r.next_u64() & 0xff) as u8).collect(),
                1 => {
                    let mut v = ELPQ_MAGIC.to_vec();
                    v.push(WIRE_VERSION);
                    v.push(r.below(12) as u8); // valid (1..=8) + unknown type bytes
                    let claimed = r.next_u64() & 0x00FF_FFFF; // up to MAX_PAYLOAD
                    v.push(((claimed >> 16) & 0xff) as u8);
                    v.push(((claimed >> 8) & 0xff) as u8);
                    v.push((claimed & 0xff) as u8);
                    for _ in 0..r.below(24) {
                        v.push((r.next_u64() & 0xff) as u8); // far short of `claimed`
                    }
                    v
                }
                _ => {
                    let ft = types[r.below(types.len())];
                    let payload: Vec<u8> =
                        (0..r.below(40)).map(|_| (r.next_u64() & 0xff) as u8).collect();
                    let mut v = Frame::new(ft, payload).unwrap().encode();
                    if !v.is_empty() {
                        match r.below(3) {
                            0 => {
                                let i = r.below(v.len());
                                v[i] ^= 1u8 << r.below(8);
                            }
                            1 => v.truncate(r.below(v.len())),
                            _ => {
                                for _ in 0..r.below(6) {
                                    v.push((r.next_u64() & 0xff) as u8);
                                }
                            }
                        }
                    }
                    v
                }
            };
            let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = Frame::decode(&input);
            }));
            assert!(
                res.is_ok(),
                "Frame::decode PANICKED — not fail-closed. len={} input={:02x?}",
                input.len(),
                input,
            );
        }
    }

    #[test]
    fn empty_payload_roundtrips() {
        let f = Frame::new(FrameType::Close, Vec::new()).unwrap();
        let wire = f.encode();
        assert_eq!(wire.len(), HEADER_LEN);
        let (decoded, _) = Frame::decode(&wire).unwrap();
        assert_eq!(decoded, f);
    }

    #[test]
    fn decode_rejects_wrong_magic() {
        let mut wire = Frame::new(FrameType::Hello, vec![1, 2, 3]).unwrap().encode();
        wire[0] = b'T'; // "TLPQ" — probing TLS? Drop.
        let err = Frame::decode(&wire).unwrap_err();
        assert!(matches!(err, FrameError::BadMagic));
    }

    #[test]
    fn decode_rejects_wrong_version() {
        // Any version byte != WIRE_VERSION is rejected. Future-proof against the
        // next bump by deriving the "wrong" byte from the live constant.
        let wrong = WIRE_VERSION.wrapping_add(1);
        let mut wire = Frame::new(FrameType::Hello, vec![1, 2, 3]).unwrap().encode();
        wire[4] = wrong;
        let err = Frame::decode(&wire).unwrap_err();
        assert!(matches!(err, FrameError::UnsupportedVersion(v) if v == wrong));

        // The previous wire version (0x01) MUST now be rejected — this is the
        // stale-peer guard the 0x01→0x02 bump installs: a peer built against the
        // un-versioned AEAD-AD wire (pre-483569ea) sends 0x01 frames and is
        // dropped here at decode, before any handshake crypto runs.
        let mut old = Frame::new(FrameType::Hello, vec![1, 2, 3]).unwrap().encode();
        old[4] = 0x01;
        assert!(matches!(
            Frame::decode(&old).unwrap_err(),
            FrameError::UnsupportedVersion(0x01)
        ));
    }

    #[test]
    fn decode_rejects_unknown_type() {
        let mut wire = Frame::new(FrameType::Hello, vec![1, 2, 3]).unwrap().encode();
        wire[5] = 0xFF;
        let err = Frame::decode(&wire).unwrap_err();
        assert!(matches!(err, FrameError::UnknownType(0xFF)));
    }

    #[test]
    fn stream_chunk_frame_type_byte_is_seven() {
        // Wire format: StreamChunk MUST be numeric 7 forever — downstream
        // peers pin on it. Catch accidental renumbering in tests.
        let wire = Frame::new(FrameType::StreamChunk, vec![0xAA]).unwrap().encode();
        assert_eq!(wire[5], 7);
    }

    #[test]
    fn stream_chunk_unknown_to_pre_43_peers() {
        // Before 4E.3 landed, peers only parsed types 1..=6. Confirm that
        // a StreamChunk frame decodes as UnknownType(7) when parsed by
        // the pre-4E.3 match arm — documents the backward-compat story.
        let wire = Frame::new(FrameType::StreamChunk, vec![0x01]).unwrap().encode();
        // Simulate the pre-4E.3 matcher directly:
        let t = wire[5];
        let legacy = match t {
            1..=6 => Ok(t),
            other => Err(other),
        };
        assert_eq!(legacy, Err(7));
    }

    #[test]
    fn admission_frame_type_byte_is_eight_and_unknown_to_pre_realm_peers() {
        // Wire format: Admission MUST be numeric 8 forever.
        let wire = Frame::new(FrameType::Admission, vec![0xAA]).unwrap().encode();
        assert_eq!(wire[5], 8);
        // Pre-realm peers parsed types 1..=7 — an Admission frame decodes
        // as UnknownType(8) there and the connection drops. Correct
        // outcome: a legacy node cannot join a federated realm.
        let legacy = match wire[5] {
            1..=7 => Ok(wire[5]),
            other => Err(other),
        };
        assert_eq!(legacy, Err(8));
    }

    #[test]
    fn decode_returns_incomplete_on_short_input() {
        let wire = Frame::new(FrameType::Hello, vec![0; 100]).unwrap().encode();
        // Truncate mid-payload.
        let err = Frame::decode(&wire[..50]).unwrap_err();
        assert!(matches!(err, FrameError::Incomplete));
    }

    #[test]
    fn decode_consumes_exact_bytes_with_trailer() {
        let f = Frame::new(FrameType::Data, vec![0x42; 32]).unwrap();
        let mut wire = f.encode();
        let frame_end = wire.len();
        wire.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // next frame / trailer
        let (decoded, used) = Frame::decode(&wire).unwrap();
        assert_eq!(decoded, f);
        assert_eq!(used, frame_end);
    }

    #[test]
    fn payload_too_large_rejected_at_construction() {
        let huge = vec![0u8; MAX_PAYLOAD + 1];
        let err = Frame::new(FrameType::Data, huge).unwrap_err();
        assert!(matches!(err, FrameError::PayloadTooLarge(_)));
    }

    #[test]
    fn header_length_is_nine() {
        assert_eq!(HEADER_LEN, 9);
    }

    #[test]
    fn magic_is_elpq_ascii() {
        assert_eq!(&ELPQ_MAGIC, b"ELPQ");
    }

    #[test]
    fn no_tls_polyglot() {
        // TLS ClientHello starts with 0x16 0x03 (handshake, TLS 1.x). Must be rejected.
        let tls_bytes = [0x16, 0x03, 0x03, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00];
        let err = Frame::decode(&tls_bytes).unwrap_err();
        assert!(matches!(err, FrameError::BadMagic));
    }

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_wire_constants_strict_pin_matrix_and_max_payload_byte_capacity() {
        // Magic byte-by-byte pin: ASCII E L P Q.
        assert_eq!(ELPQ_MAGIC[0], 0x45);
        assert_eq!(ELPQ_MAGIC[1], 0x4C);
        assert_eq!(ELPQ_MAGIC[2], 0x50);
        assert_eq!(ELPQ_MAGIC[3], 0x51);
        assert_eq!(ELPQ_MAGIC.len(), 4);
        // Version byte pin — bumped only on a wire-observable change (framing,
        // post-handshake AEAD AD, or key schedule). 0x01→0x02 on 2026-06-30.
        assert_eq!(WIRE_VERSION, 0x02);
        // Header geometry pin: magic(4) + version(1) + type(1) + length(3) = 9.
        assert_eq!(HEADER_LEN, 9);
        assert_eq!(HEADER_LEN, 4 + 1 + 1 + 3);
        // Max payload = 2^24 - 1 = 16_777_215 (the largest value a 3-byte
        // BE length field can express).
        assert_eq!(MAX_PAYLOAD, 16_777_215);
        assert_eq!(MAX_PAYLOAD, (1usize << 24) - 1);
        // MAX_PAYLOAD must fit in 24 bits (3 bytes) — pin the upper limit
        // so a careless widening to 4 bytes never silently lands.
        assert!(MAX_PAYLOAD < (1usize << 24));
        assert!(MAX_PAYLOAD >= (1usize << 23)); // > 8 MiB
        // 3-byte BE encoding of MAX_PAYLOAD is [0xFF, 0xFF, 0xFF].
        let len = MAX_PAYLOAD as u32;
        assert_eq!(((len >> 16) & 0xFF) as u8, 0xFF);
        assert_eq!(((len >> 8) & 0xFF) as u8, 0xFF);
        assert_eq!((len & 0xFF) as u8, 0xFF);
    }

    #[test]
    fn batch_b_frame_type_discriminant_strict_pin_all_seven_variants_and_pairwise_distinct() {
        // Wire-format discriminants are part of the protocol — never
        // renumber. Pin each variant byte explicitly.
        assert_eq!(FrameType::Hello as u8, 1);
        assert_eq!(FrameType::Challenge as u8, 2);
        assert_eq!(FrameType::Auth as u8, 3);
        assert_eq!(FrameType::Data as u8, 4);
        assert_eq!(FrameType::Rekey as u8, 5);
        assert_eq!(FrameType::Close as u8, 6);
        assert_eq!(FrameType::StreamChunk as u8, 7);
        assert_eq!(FrameType::Admission as u8, 8);
        // Pairwise distinctness: C(8,2) = 28 ordered comparisons.
        let all = [
            FrameType::Hello as u8,
            FrameType::Challenge as u8,
            FrameType::Auth as u8,
            FrameType::Data as u8,
            FrameType::Rekey as u8,
            FrameType::Close as u8,
            FrameType::StreamChunk as u8,
            FrameType::Admission as u8,
        ];
        let mut pairs_checked = 0usize;
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(all[i], all[j], "FrameType discriminants collide at {i},{j}");
                pairs_checked += 1;
            }
        }
        assert_eq!(pairs_checked, 28);
        // from_byte must reject 0 and any byte > 8 (sweep representative
        // out-of-range values, including the gap-adjacent 9 + boundary 255).
        for bad in [0u8, 9, 10, 100, 200, 255] {
            let mut wire = Frame::new(FrameType::Hello, vec![]).unwrap().encode();
            wire[5] = bad;
            let err = Frame::decode(&wire).unwrap_err();
            match err {
                FrameError::UnknownType(byte) => assert_eq!(byte, bad),
                other => panic!("expected UnknownType({bad}), got {other:?}"),
            }
        }
    }

    #[test]
    fn batch_b_encode_decode_byte_shape_roundtrip_across_payload_length_boundary() {
        // Payload length sweep exercises both the small (single-byte BE
        // tail) and large (all three BE bytes) paths, including the exact
        // 256 / 65536 carry boundaries.
        for size in [0usize, 1, 254, 255, 256, 257, 65_535, 65_536, 65_537] {
            let payload = vec![0xA5u8; size];
            let f = Frame::new(FrameType::Data, payload.clone()).unwrap();
            let wire = f.encode();
            // Wire length is exactly header + payload — no padding, no
            // alignment slack.
            assert_eq!(wire.len(), HEADER_LEN + size);
            // First 4 bytes are the magic; byte 4 is version; byte 5 is type.
            assert_eq!(&wire[0..4], &ELPQ_MAGIC);
            assert_eq!(wire[4], WIRE_VERSION);
            assert_eq!(wire[5], FrameType::Data as u8);
            // Payload region is bit-identical to the input.
            assert_eq!(&wire[HEADER_LEN..], &payload[..]);
            // Decode returns the same frame and consumes all bytes.
            let (decoded, used) = Frame::decode(&wire).unwrap();
            assert_eq!(decoded.frame_type, FrameType::Data);
            assert_eq!(decoded.payload, payload);
            assert_eq!(used, wire.len());
        }
    }

    #[test]
    fn batch_b_length_field_three_byte_big_endian_encoding_strict_pin_at_byte_offsets_6_7_8() {
        // For each test size, pin the exact bytes at offsets 6 (high), 7
        // (mid), 8 (low) so a swap to LE or a byte-order regression is
        // caught immediately.
        struct Case {
            size: usize,
            high: u8,
            mid: u8,
            low: u8,
        }
        let cases = [
            Case { size: 0, high: 0x00, mid: 0x00, low: 0x00 },
            Case { size: 1, high: 0x00, mid: 0x00, low: 0x01 },
            Case { size: 255, high: 0x00, mid: 0x00, low: 0xFF },
            Case { size: 256, high: 0x00, mid: 0x01, low: 0x00 },
            Case { size: 65_535, high: 0x00, mid: 0xFF, low: 0xFF },
            Case { size: 65_536, high: 0x01, mid: 0x00, low: 0x00 },
            Case { size: 0x123456, high: 0x12, mid: 0x34, low: 0x56 },
            Case { size: MAX_PAYLOAD, high: 0xFF, mid: 0xFF, low: 0xFF },
        ];
        for c in cases {
            let f = Frame::new(FrameType::Data, vec![0u8; c.size]).unwrap();
            let wire = f.encode();
            assert_eq!(wire[6], c.high, "size={}: high byte", c.size);
            assert_eq!(wire[7], c.mid, "size={}: mid byte", c.size);
            assert_eq!(wire[8], c.low, "size={}: low byte", c.size);
            // Decode reads the same BE length back.
            let (decoded, used) = Frame::decode(&wire).unwrap();
            assert_eq!(decoded.payload.len(), c.size);
            assert_eq!(used, HEADER_LEN + c.size);
        }
    }

    #[test]
    fn batch_b_frame_error_display_format_strings_pin_for_operator_log_stability() {
        // Operator dashboards grep on these strings — pin them so a
        // thiserror message tweak can't silently break log analysis.
        let s_incomplete = format!("{}", FrameError::Incomplete);
        assert_eq!(s_incomplete, "frame incomplete: need more bytes");
        let s_bad_magic = format!("{}", FrameError::BadMagic);
        assert_eq!(s_bad_magic, "bad magic: expected ELPQ");
        let s_ver = format!("{}", FrameError::UnsupportedVersion(0x02));
        assert_eq!(s_ver, "unsupported wire version: 0x2");
        let s_unknown = format!("{}", FrameError::UnknownType(0xFF));
        assert_eq!(s_unknown, "unknown frame type: 255");
        let s_too_large = format!("{}", FrameError::PayloadTooLarge(99));
        assert_eq!(s_too_large, "payload too large: 99 bytes (max 16777215)");
        // Io variant carries through the inner error's Display verbatim.
        let inner = io::Error::new(io::ErrorKind::UnexpectedEof, "short read");
        let s_io = format!("{}", FrameError::Io(inner));
        assert_eq!(s_io, "io error: short read");
    }
}
