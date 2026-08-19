// Copyright (c) 2026 Elara Protocol contributors
// Licensed under MIT OR Apache-2.0

//! The ELPQ wire frame, end to end: encode a frame, read it back, and watch the
//! decoder reject anything that isn't an ELPQ v1 frame *before* it reads a
//! single payload byte. That early rejection is the "no-downgrade" invariant —
//! a peer can't be talked down to a weaker or legacy framing.
//!
//! Run it:
//!
//! ```text
//! cargo run -p elara-pq-transport --example frame_roundtrip
//! ```

use elara_pq_transport::frame::{
    Frame, FrameError, FrameType, ELPQ_MAGIC, HEADER_LEN, WIRE_VERSION,
};

fn main() {
    // 1. ENCODE — a Data frame carrying an application payload. The 9-byte header
    //    is `magic "ELPQ" | version | type | 3-byte big-endian length`, then the
    //    payload verbatim. No negotiation, no options, no polyglot parser.
    let original = Frame::new(FrameType::Data, b"hello, post-quantum mesh".to_vec()).unwrap();
    let wire = original.encode();
    println!(
        "encoded {} bytes — header[{HEADER_LEN}] = {:02x?}  (ELPQ | v{:#04x} | type {} | len {})",
        wire.len(),
        &wire[..HEADER_LEN],
        WIRE_VERSION,
        FrameType::Data as u8,
        original.payload.len(),
    );
    assert_eq!(&wire[..4], &ELPQ_MAGIC, "frame opens with the ELPQ magic");

    // 2. DECODE — read it back. `decode` returns the frame plus how many bytes it
    //    consumed, so a stream of frames can be parsed one after another.
    let (parsed, consumed) = Frame::decode(&wire).unwrap();
    assert_eq!(parsed, original, "round-trip is lossless");
    assert_eq!(consumed, wire.len(), "consumed exactly one frame");
    println!(
        "✓ round-trip — decoded type {:?}, {} payload byte(s), {consumed} byte(s) consumed",
        parsed.frame_type,
        parsed.payload.len(),
    );

    // 3. NO DOWNGRADE — flip the first magic byte. The decoder rejects it on the
    //    magic check, before the version, type, or any payload byte is read.
    let mut not_elpq = wire.clone();
    not_elpq[0] ^= 0xFF;
    assert!(
        matches!(Frame::decode(&not_elpq), Err(FrameError::BadMagic)),
        "non-ELPQ bytes are rejected at the magic"
    );
    println!("✓ no-downgrade — bytes that don't start with ELPQ are rejected (BadMagic)");

    // 4. VERSION PINNING — a frame claiming an unsupported wire version is
    //    refused by version, not silently parsed under v1 rules.
    let mut wrong_version = wire.clone();
    wrong_version[4] = 0x02;
    assert!(
        matches!(Frame::decode(&wrong_version), Err(FrameError::UnsupportedVersion(0x02))),
        "an unknown wire version is rejected"
    );
    println!("✓ version-pinning — an unsupported wire version is rejected (UnsupportedVersion)");

    // 5. NO PARTIAL READS — a header that promises more payload than is present
    //    yields `Incomplete`, never a truncated frame.
    assert!(
        matches!(Frame::decode(&wire[..wire.len() - 1]), Err(FrameError::Incomplete)),
        "a short buffer is Incomplete, not a partial frame"
    );
    println!("✓ no partial reads — a truncated buffer is Incomplete, never half-parsed");

    println!("\nall checks passed — the frame round-trips and refuses everything that isn't ELPQ v1.");
}
