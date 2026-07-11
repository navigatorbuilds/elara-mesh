//! SHA3-256 hashing.

//!
//! Spec references:
//!   @spec Protocol §4.2

use sha3::{Digest, Sha3_256};

/// Compute SHA3-256 hash of data, returns 32 bytes.
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Compute SHA3-256 hash and return hex string.
pub fn sha3_256_hex(data: &[u8]) -> String {
    hex::encode(sha3_256(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha3_256_empty() {
        let hash = sha3_256(b"");
        assert_eq!(hash.len(), 32);
        // Known SHA3-256 of empty string
        assert_eq!(
            sha3_256_hex(b""),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
    }

    #[test]
    fn test_sha3_256_deterministic() {
        let data = b"elara protocol";
        assert_eq!(sha3_256(data), sha3_256(data));
    }

    #[test]
    fn test_sha3_256_different_inputs() {
        assert_ne!(sha3_256(b"hello"), sha3_256(b"world"));
    }

    // ─── hash correctness invariants ───────────────

    /// NIST FIPS 202 canonical test vector: SHA3-256("abc"). Pinning the
    /// canonical NIST output catches any silent algorithm-swap regression
    /// (e.g. a future refactor that switches to Keccak-256 — which produces
    /// a *different* hash for the same input despite identical 32-byte
    /// output shape).
    #[test]
    fn batch_b_sha3_256_matches_nist_fips202_canonical_abc_test_vector() {
        assert_eq!(
            sha3_256_hex(b"abc"),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
            "SHA3-256(\"abc\") drifted from NIST FIPS 202 canonical — algorithm swap?",
        );
    }

    /// Avalanche / diffusion: flipping a single input bit must change a
    /// substantial fraction of output bits. The cryptographic ideal is ~128
    /// of 256 bits (50% flip rate). Pin a very conservative floor at 96 of
    /// 256 (~37.5%) — even a badly weakened hash beats this; falling below
    /// it signals a serious diffusion regression.
    #[test]
    fn batch_b_sha3_256_avalanche_single_bit_flip_diffuses_most_of_output() {
        let msg_a = b"elara avalanche probe message".to_vec();
        let mut msg_b = msg_a.clone();
        msg_b[0] ^= 0x01; // flip lowest bit of first byte
        let h_a = sha3_256(&msg_a);
        let h_b = sha3_256(&msg_b);
        let differing_bits: u32 = h_a.iter().zip(h_b.iter()).map(|(a, b)| (a ^ b).count_ones()).sum();
        assert!(
            differing_bits >= 96,
            "single-bit input flip diffused to only {} of 256 output bits — diffusion regression",
            differing_bits,
        );
    }

    /// `sha3_256_hex` wrapper contract: output is always exactly 64
    /// lowercase hex characters (no `0x` prefix, no uppercase, no spacing).
    /// Pin so a future "let's add a 0x prefix for readability" refactor
    /// breaks here, not in downstream callers that parse the hex string
    /// fixed-width.
    #[test]
    fn batch_b_sha3_256_hex_output_is_exactly_64_lowercase_hex_chars() {
        let probes: &[&[u8]] = &[b"", b"a", b"elara", b"the quick brown fox", &[0u8; 1024]];
        for p in probes {
            let h = sha3_256_hex(p);
            assert_eq!(h.len(), 64, "sha3_256_hex output not 64 chars: {h:?}");
            for c in h.chars() {
                assert!(
                    c.is_ascii_hexdigit() && (c.is_ascii_digit() || c.is_ascii_lowercase()),
                    "sha3_256_hex emitted non-lowercase-hex char {c:?} in {h:?}",
                );
            }
        }
    }

    /// Round-trip identity: `hex::decode(sha3_256_hex(x))` must equal
    /// `sha3_256(x).to_vec()`. Pins the wrapper as a pure encoding —
    /// catches a future regression where `sha3_256_hex` ever differs
    /// from `hex::encode(sha3_256(_))` (e.g. truncated, base64'd, padded).
    #[test]
    fn batch_b_sha3_256_hex_round_trips_to_raw_bytes_under_hex_decode() {
        let probes: &[&[u8]] = &[b"", b"x", b"elara protocol", &[0x42u8; 4096]];
        for p in probes {
            let raw = sha3_256(p);
            let hex_s = sha3_256_hex(p);
            let decoded = hex::decode(&hex_s).expect("hex decode of sha3_256_hex output");
            assert_eq!(decoded, raw.to_vec(), "round-trip mismatch for input len={}", p.len());
        }
    }

    /// Large-input length invariance: hashing a 1 MiB payload still
    /// produces a 32-byte output and 64-char hex string. Pin against a
    /// future regression that adds a "small input only" length guard or
    /// silently truncates large payloads.
    #[test]
    fn batch_b_sha3_256_handles_one_mebibyte_input_with_fixed_output_size() {
        let big: Vec<u8> = (0..1_048_576u32).map(|i| (i & 0xFF) as u8).collect();
        let h = sha3_256(&big);
        assert_eq!(h.len(), 32, "1 MiB input must still yield 32-byte hash");
        let h_hex = sha3_256_hex(&big);
        assert_eq!(h_hex.len(), 64, "1 MiB input must still yield 64-char hex");
        // Determinism on large input — same input twice → same hash
        assert_eq!(sha3_256(&big), h, "1 MiB hash must be deterministic on repeat");
    }
}
