//! PoWaS — Proof of Work-at-Stake.
//!
//! Protocol v0.6.1 Section 11.1: Hybrid Sybil resistance combining staking
//! and lightweight computation. Witnesses must solve a proof-of-work puzzle
//! before attesting to a record.
//!
//! **Puzzle construction:**
//! ```text
//! puzzle_input  = SHA3-256(record_id || witness_pubkey || nonce)
//! difficulty    = BASE_DIFFICULTY × (1 / sqrt(stake_amount))
//! target        = 2^256 / difficulty
//! valid_if      = puzzle_input < target
//! ```
//!
//! Difficulty is inversely proportional to the square root of stake.
//! A witness staking 1,000 beat solves a puzzle ~32x easier than one staking 1 beat.
//! Bounded by MIN/MAX difficulty so large stakers still compute and small stakers
//! aren't excluded.
//!
//! Target attestation cost: ~0.1 seconds CPU per attestation.

//!
//! Spec references:
//!   @spec economics §9.1

use crate::crypto::hash::sha3_256;

/// Base difficulty for PoWaS puzzles. Expected solve work ≈ `difficulty` SHA3
/// hashes (`meets_target` passes with prob ≈ 1/difficulty), so MIN_DIFFICULTY
/// (5_000) ≈ a few ms and the ~0.1 s target sits near 50_000 hashes.
///
/// `effective_difficulty = clamp(BASE_DIFFICULTY * 1000 / sqrt(stake_base_units),
/// MIN, MAX)`. With stake in base units (10^9/beat) the unclamped band spans
/// ~1e4..1e8 base units (1e-5..0.1 beat); every witness at or above the
/// MIN_STAKE floor (100 beat = 1e11 base units) therefore clamps to
/// MIN_DIFFICULTY. The inverse-sqrt curve differentiates only sub-floor stakes,
/// so all currently-admitted witnesses do the same MIN_DIFFICULTY work. (This
/// flat-at-floor behavior predates the 10^9 unit migration — it is a standing
/// calibration property of the curve, not a regression from it.)
pub const BASE_DIFFICULTY: u64 = 50_000;

/// Minimum difficulty: BASE / 10. Even the largest stakers do meaningful work.
pub const MIN_DIFFICULTY: u64 = BASE_DIFFICULTY / 10; // 5,000

/// Maximum difficulty: BASE × 10. Small stakers aren't excluded.
pub const MAX_DIFFICULTY: u64 = BASE_DIFFICULTY * 10; // 500,000

/// Maximum nonce iterations before giving up (prevents infinite loops on
/// misconfigured difficulty). ~2 seconds worst case.
pub const MAX_NONCE_ATTEMPTS: u64 = 10_000_000;

/// A solved PoWaS puzzle proof.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PoWaSProof {
    /// The nonce that solves the puzzle.
    pub nonce: u64,
    /// The effective difficulty used.
    pub difficulty: u64,
}

/// Calculate effective difficulty for a given stake amount (in base units, 10^9/beat).
///
/// `difficulty = clamp(BASE_DIFFICULTY * 1000 / sqrt(stake_base_units), MIN, MAX)`
pub fn effective_difficulty(stake_base_units: u64) -> u64 {
    if stake_base_units == 0 {
        return MAX_DIFFICULTY;
    }

    let sqrt_stake = (stake_base_units as f64).sqrt();
    let raw = (BASE_DIFFICULTY as f64 / sqrt_stake * 1000.0) as u64;

    raw.clamp(MIN_DIFFICULTY, MAX_DIFFICULTY)
}

/// Compute the puzzle hash for a given record, witness key, and nonce.
///
/// `SHA3-256(record_id || witness_pubkey || nonce_bytes)`
fn puzzle_hash(record_id: &str, witness_pubkey: &[u8], nonce: u64) -> [u8; 32] {
    let mut input = Vec::with_capacity(record_id.len() + witness_pubkey.len() + 8);
    input.extend_from_slice(record_id.as_bytes());
    input.extend_from_slice(witness_pubkey);
    input.extend_from_slice(&nonce.to_le_bytes());
    sha3_256(&input)
}

/// Check if a hash meets the difficulty target.
///
/// `valid_if = hash < 2^256 / difficulty`
///
/// We check by counting leading zero bits. For difficulty D:
/// - target = 2^256 / D
/// - leading_zeros >= log2(D) means hash < target
///
/// More precisely: interpret hash as big-endian u256, check hash < target.
fn meets_target(hash: &[u8; 32], difficulty: u64) -> bool {
    // For small difficulties (< 256), count leading zero bits
    // target = 2^256 / difficulty
    // hash < target iff hash * difficulty < 2^256
    //
    // Fast path: check leading zero bytes first
    let required_zero_bits = (difficulty as f64).log2().floor() as u32;
    let leading_zeros = count_leading_zero_bits(hash);

    if leading_zeros > required_zero_bits + 1 {
        return true; // Definitely below target
    }
    if leading_zeros < required_zero_bits.saturating_sub(1) {
        return false; // Definitely above target
    }

    // Precise check: interpret first 8 bytes as big-endian u64
    // target_prefix = 2^64 / (difficulty / 2^(256-64)) ≈ 2^64 * 2^192 / difficulty
    // Simplified: hash_prefix < u64::MAX / difficulty
    let hash_prefix = u64::from_be_bytes([
        hash[0], hash[1], hash[2], hash[3],
        hash[4], hash[5], hash[6], hash[7],
    ]);

    // target_prefix = 2^64 / difficulty (approximately)
    if difficulty <= 1 {
        return true; // difficulty ≤ 1 means target ≥ 2^256, all hashes pass
    }
    let target_prefix = u64::MAX / difficulty;
    hash_prefix < target_prefix
}

/// Count leading zero bits in a byte array.
fn count_leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut count = 0u32;
    for &b in bytes {
        if b == 0 {
            count += 8;
        } else {
            count += b.leading_zeros();
            break;
        }
    }
    count
}

/// Solve a PoWaS puzzle: find a nonce such that the puzzle hash meets the target.
///
/// Returns `Some(PoWaSProof)` if solved, `None` if MAX_NONCE_ATTEMPTS exceeded.
pub fn solve(
    record_id: &str,
    witness_pubkey: &[u8],
    stake_base_units: u64,
) -> Option<PoWaSProof> {
    let difficulty = effective_difficulty(stake_base_units);

    for nonce in 0..MAX_NONCE_ATTEMPTS {
        let hash = puzzle_hash(record_id, witness_pubkey, nonce);
        if meets_target(&hash, difficulty) {
            return Some(PoWaSProof { nonce, difficulty });
        }
    }

    None // Puzzle too hard (shouldn't happen with proper difficulty bounds)
}

/// Verify a PoWaS proof: check that the nonce produces a valid hash.
///
/// Re-derives the difficulty from stake to ensure consistency.
pub fn verify(
    record_id: &str,
    witness_pubkey: &[u8],
    stake_base_units: u64,
    proof: &PoWaSProof,
) -> bool {
    let expected_difficulty = effective_difficulty(stake_base_units);

    // Proof must use the correct difficulty
    if proof.difficulty != expected_difficulty {
        return false;
    }

    let hash = puzzle_hash(record_id, witness_pubkey, proof.nonce);
    meets_target(&hash, proof.difficulty)
}

/// Serialize a PoWaS proof to metadata values for inclusion in attestation records.
pub fn proof_to_metadata(proof: &PoWaSProof) -> (String, String) {
    (
        proof.nonce.to_string(),
        proof.difficulty.to_string(),
    )
}

/// Parse a PoWaS proof from attestation metadata.
pub fn proof_from_metadata(nonce_str: &str, difficulty_str: &str) -> Option<PoWaSProof> {
    let nonce = nonce_str.parse().ok()?;
    let difficulty = difficulty_str.parse().ok()?;
    Some(PoWaSProof { nonce, difficulty })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_effective_difficulty_zero_stake() {
        assert_eq!(effective_difficulty(0), MAX_DIFFICULTY);
    }

    #[test]
    fn test_effective_difficulty_min_stake() {
        // MIN_STAKE = 100 beat = 100 * BASE_UNITS_PER_BEAT base units (10^9/beat).
        // The bare 100_000_000 literal here was a pre-10^9-migration leftover
        // (0.1 beat), so the test no longer exercised the real minimum stake.
        let d = effective_difficulty(crate::accounting::types::MIN_STAKE);
        assert!(d >= MIN_DIFFICULTY);
        assert!(d <= MAX_DIFFICULTY);
    }

    #[test]
    fn test_effective_difficulty_large_stake() {
        // 1,000,000 beat = very large staker
        let d = effective_difficulty(1_000_000 * crate::accounting::types::BASE_UNITS_PER_BEAT);
        assert_eq!(d, MIN_DIFFICULTY); // Clamped to min
    }

    #[test]
    fn test_effective_difficulty_tiny_stake() {
        // 1 base unit (10^-9 beat, far below any real stake) — math hits the MAX clamp
        let d = effective_difficulty(1);
        assert_eq!(d, MAX_DIFFICULTY); // Clamped to max
    }

    #[test]
    fn test_difficulty_inversely_proportional() {
        // Sub-floor stakes chosen to land in the unclamped band (at/above the
        // 100-beat floor all stakes clamp to MIN_DIFFICULTY, so the inverse-sqrt
        // curve is only observable here).
        let d_small = effective_difficulty(1_000_000); // 0.001 beat
        let d_large = effective_difficulty(100_000_000); // 0.1 beat
        // Larger stake → lower difficulty (easier puzzle)
        assert!(d_large < d_small, "d_large={d_large} should be < d_small={d_small}");
    }

    #[test]
    fn test_solve_and_verify() {
        let record_id = "test_record_123";
        let witness_pubkey = b"witness_pub_key_bytes";
        let stake = crate::accounting::types::MIN_STAKE; // 100 beat (MIN_STAKE), base units

        let proof = solve(record_id, witness_pubkey, stake)
            .expect("should solve within MAX_NONCE_ATTEMPTS");

        assert!(verify(record_id, witness_pubkey, stake, &proof));
    }

    #[test]
    fn test_verify_wrong_record() {
        let witness_pubkey = b"witness_pub_key_bytes";
        let stake = 100_000_000u64;

        let proof = solve("record_a", witness_pubkey, stake).unwrap();
        // Proof for record_a doesn't verify against record_b
        assert!(!verify("record_b", witness_pubkey, stake, &proof));
    }

    #[test]
    fn test_verify_wrong_witness() {
        let stake = 100_000_000u64;

        let proof = solve("record_a", b"witness_a", stake).unwrap();
        // Proof for witness_a doesn't verify against witness_b
        assert!(!verify("record_a", b"witness_b", stake, &proof));
    }

    #[test]
    fn test_verify_wrong_difficulty() {
        let record_id = "test_record";
        let witness_pubkey = b"witness_pub";
        let stake = 100_000_000u64;

        let mut proof = solve(record_id, witness_pubkey, stake).unwrap();
        proof.difficulty = 999; // Tampered difficulty
        assert!(!verify(record_id, witness_pubkey, stake, &proof));
    }

    #[test]
    fn test_count_leading_zero_bits() {
        // 0x01 = 0b00000001 → 7 leading zeros per byte
        assert_eq!(count_leading_zero_bits(&[0, 0, 0, 1]), 31); // 24 + 7
        assert_eq!(count_leading_zero_bits(&[0, 0, 1, 0]), 23); // 16 + 7
        assert_eq!(count_leading_zero_bits(&[0x0F, 0, 0, 0]), 4);
        assert_eq!(count_leading_zero_bits(&[0xFF, 0, 0, 0]), 0);
        assert_eq!(count_leading_zero_bits(&[0, 0, 0, 0]), 32);
    }

    #[test]
    fn test_meets_target_easy() {
        // Difficulty 1 → target = 2^64, everything passes
        let hash = [0xFF; 32];
        assert!(meets_target(&hash, 1));
    }

    #[test]
    fn test_meets_target_hard() {
        // Very high difficulty → only hashes with many leading zeros pass
        let mut hash = [0xFF; 32];
        assert!(!meets_target(&hash, 1_000_000));

        hash = [0; 32]; // All zeros always passes
        assert!(meets_target(&hash, 1_000_000));
    }

    #[test]
    fn test_proof_metadata_roundtrip() {
        let proof = PoWaSProof { nonce: 42, difficulty: 5000 };
        let (n, d) = proof_to_metadata(&proof);
        let recovered = proof_from_metadata(&n, &d).unwrap();
        assert_eq!(recovered.nonce, 42);
        assert_eq!(recovered.difficulty, 5000);
    }

    #[test]
    fn test_solve_performance() {
        // Ensure solving completes in reasonable time for MIN_STAKE.
        // Under isolation this is sub-100ms on modern hardware; the 5s
        // ceiling tolerates ~50× CPU contention from parallel cargo
        // build/test runs without false-flaking, while still catching
        // an algorithmic regression that turned solve into O(N²) or
        // similar (which would push wall-time well past 5s).
        let start = std::time::Instant::now();
        let proof = solve("perf_test", b"witness_key", 100_000_000).unwrap();
        let elapsed = start.elapsed();

        assert!(elapsed.as_secs_f64() < 5.0, "took {elapsed:?}, nonce={}", proof.nonce);
    }

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_constants_strict_pin_and_cross_relation_ratios() {
        // PoWaS calibration is load-bearing for Sybil resistance — drift in
        // any constant changes the puzzle cost/stake curve. Pin each one
        // strictly so an accidental refactor (e.g. typo
        // BASE_DIFFICULTY = 5_000 instead of 50_000) surfaces here.
        assert_eq!(BASE_DIFFICULTY, 50_000u64,
            "BASE_DIFFICULTY drift breaks the ~0.1s/attestation target");
        assert_eq!(MIN_DIFFICULTY, 5_000u64,
            "MIN_DIFFICULTY drift removes the work floor for large stakers");
        assert_eq!(MAX_DIFFICULTY, 500_000u64,
            "MAX_DIFFICULTY drift excludes small stakers from witnessing");
        assert_eq!(MAX_NONCE_ATTEMPTS, 10_000_000u64,
            "MAX_NONCE_ATTEMPTS drift changes solve() upper-bound wall-time");

        // Cross-relation: MIN = BASE / 10, MAX = BASE * 10, MAX/MIN = 100.
        assert_eq!(MIN_DIFFICULTY, BASE_DIFFICULTY / 10);
        assert_eq!(MAX_DIFFICULTY, BASE_DIFFICULTY * 10);
        assert_eq!(MAX_DIFFICULTY / MIN_DIFFICULTY, 100,
            "MAX:MIN difficulty ratio must be exactly 100:1");

        // Total range is symmetric in log space around BASE.
        let log_min = (MIN_DIFFICULTY as f64).log2();
        let log_base = (BASE_DIFFICULTY as f64).log2();
        let log_max = (MAX_DIFFICULTY as f64).log2();
        let to_base = log_base - log_min;
        let from_base = log_max - log_base;
        // Both gaps are log2(10) ≈ 3.3219 — symmetric in log space.
        assert!((to_base - from_base).abs() < 0.001,
            "log-space difficulty range must be symmetric around BASE: log_min→base={to_base}, base→max={from_base}");

        // All constants are non-zero positive u64.
        assert!(BASE_DIFFICULTY > 0);
        assert!(MIN_DIFFICULTY > 0);
        assert!(MAX_DIFFICULTY > 0);
        assert!(MAX_NONCE_ATTEMPTS > 0);
    }

    #[test]
    fn batch_b_count_leading_zero_bits_exhaustive_byte_boundary_matrix() {
        // Sweep across single-byte leading patterns at every bit position
        // (0x80 = 0 zeros, 0x40 = 1 zero, ..., 0x01 = 7 zeros, 0x00 = 8 zeros
        // continued to next byte). Existing test_count_leading_zero_bits
        // covers 5 cases; this axis covers all 9 single-byte states
        // plus multi-byte chain boundaries.
        let single_byte_cases: [(&[u8], u32); 9] = [
            (&[0x80], 0),  // MSB set
            (&[0x40], 1),
            (&[0x20], 2),
            (&[0x10], 3),
            (&[0x08], 4),
            (&[0x04], 5),
            (&[0x02], 6),
            (&[0x01], 7),
            (&[0x00], 8),  // all zero in single byte
        ];
        for (bytes, expected) in single_byte_cases {
            let got = count_leading_zero_bits(bytes);
            assert_eq!(got, expected,
                "single-byte {bytes:02X?}: expected {expected} leading zeros, got {got}");
        }

        // Multi-byte chain — the function counts zero BYTES then the
        // partial-bit count of the first non-zero byte.
        assert_eq!(count_leading_zero_bits(&[0x00, 0x80]), 8,
            "0x00 0x80 → 8 zeros (full byte) + 0 partial = 8");
        assert_eq!(count_leading_zero_bits(&[0x00, 0x00, 0x80]), 16,
            "0x00 0x00 0x80 → 16 + 0 = 16");
        assert_eq!(count_leading_zero_bits(&[0x00, 0x00, 0x00, 0x40]), 25,
            "0x00 0x00 0x00 0x40 → 24 + 1 = 25");

        // Empty input → zero count (no bytes to scan).
        assert_eq!(count_leading_zero_bits(&[]), 0,
            "empty input must return 0 leading-zero-bit count");

        // Full 32-byte zero array — 256 bits all zero.
        let all_zero = [0u8; 32];
        assert_eq!(count_leading_zero_bits(&all_zero), 256,
            "32 zero bytes must yield 32*8=256 leading zero bits");
    }

    #[test]
    fn batch_b_puzzle_hash_determinism_and_three_input_distinctness_sweep() {
        // puzzle_hash = SHA3-256(record_id || witness_pubkey || nonce_le_bytes).
        // Determinism: same inputs → same hash (across multiple calls).
        let r = "rec-abc";
        let w = b"witness-key-bytes";
        let n = 12345u64;
        let h1 = puzzle_hash(r, w, n);
        let h2 = puzzle_hash(r, w, n);
        let h3 = puzzle_hash(r, w, n);
        assert_eq!(h1, h2);
        assert_eq!(h2, h3);
        assert_eq!(h1.len(), 32, "SHA3-256 output is always 32 bytes");

        // Independent-input distinctness: changing ANY of the 3 inputs
        // must produce a distinct hash (otherwise verify() would accept
        // a stolen proof from a different record/witness/nonce).
        let base = puzzle_hash("rec-A", b"witness-A", 100);
        let diff_record = puzzle_hash("rec-B", b"witness-A", 100);
        let diff_witness = puzzle_hash("rec-A", b"witness-B", 100);
        let diff_nonce = puzzle_hash("rec-A", b"witness-A", 101);
        assert_ne!(base, diff_record, "different record_id must yield different hash");
        assert_ne!(base, diff_witness, "different witness_pubkey must yield different hash");
        assert_ne!(base, diff_nonce, "different nonce must yield different hash");
        assert_ne!(diff_record, diff_witness, "permutation across record/witness must differ");
        assert_ne!(diff_witness, diff_nonce, "permutation across witness/nonce must differ");
        assert_ne!(diff_record, diff_nonce, "permutation across record/nonce must differ");

        // Nonce-bytes are little-endian — sweep across u64 byte-position
        // sensitivity (nonce=1 vs nonce=256 must differ since they hit
        // different bytes of the LE representation).
        let n1 = puzzle_hash("R", b"W", 1);
        let n256 = puzzle_hash("R", b"W", 256);
        let n65536 = puzzle_hash("R", b"W", 65536);
        let n_max = puzzle_hash("R", b"W", u64::MAX);
        assert_ne!(n1, n256);
        assert_ne!(n1, n65536);
        assert_ne!(n1, n_max);
        assert_ne!(n256, n65536);
        assert_ne!(n65536, n_max);

        // Empty record_id / empty witness_pubkey — must still produce
        // a valid 32-byte hash (no panic, no length variation).
        let h_empty_r = puzzle_hash("", b"witness", 0);
        let h_empty_w = puzzle_hash("rec", b"", 0);
        let h_empty_both = puzzle_hash("", b"", 0);
        assert_eq!(h_empty_r.len(), 32);
        assert_eq!(h_empty_w.len(), 32);
        assert_eq!(h_empty_both.len(), 32);
        assert_ne!(h_empty_r, h_empty_w, "empty-record vs empty-witness must differ");
        assert_ne!(h_empty_r, h_empty_both);
    }

    #[test]
    fn batch_b_powas_proof_derive_clone_debug_and_serde_roundtrip() {
        // PoWaSProof is a tiny POD struct (nonce + difficulty) but is
        // wire-critical — it travels in attestation metadata. A regression
        // in derive(Clone) or derive(Serialize) would silently break the
        // pull/push gossip path's attestation forwarding.

        // Clone preserves both fields independently.
        let orig = PoWaSProof { nonce: 0xDEADBEEF, difficulty: 7777 };
        let cloned = orig.clone();
        assert_eq!(cloned.nonce, 0xDEADBEEF);
        assert_eq!(cloned.difficulty, 7777);

        // Mutating one field on a second clone must not affect the first.
        let mut mut_clone = orig.clone();
        mut_clone.nonce = 0;
        mut_clone.difficulty = 0;
        // Confirm mutation actually applied — otherwise the independence
        // assertion below is vacuously true.
        assert_eq!(mut_clone.nonce, 0, "mutation must apply");
        assert_eq!(mut_clone.difficulty, 0, "mutation must apply");
        assert_eq!(cloned.nonce, 0xDEADBEEF, "first clone unaffected by second mutation");
        assert_eq!(cloned.difficulty, 7777);

        // Debug format contains the struct name and both field names.
        let dbg = format!("{:?}", orig);
        assert!(dbg.contains("PoWaSProof"));
        assert!(dbg.contains("nonce"));
        assert!(dbg.contains("difficulty"));

        // serde JSON roundtrip — wire interop with attestation metadata.
        let json = serde_json::to_string(&orig).unwrap();
        assert!(json.contains("\"nonce\""));
        assert!(json.contains("\"difficulty\""));
        let back: PoWaSProof = serde_json::from_str(&json).unwrap();
        assert_eq!(back.nonce, orig.nonce);
        assert_eq!(back.difficulty, orig.difficulty);

        // Boundary values (zero, u64::MAX) roundtrip without overflow.
        let edge = PoWaSProof { nonce: u64::MAX, difficulty: u64::MAX };
        let edge_json = serde_json::to_string(&edge).unwrap();
        let edge_back: PoWaSProof = serde_json::from_str(&edge_json).unwrap();
        assert_eq!(edge_back.nonce, u64::MAX);
        assert_eq!(edge_back.difficulty, u64::MAX);

        // proof_to_metadata + proof_from_metadata roundtrip at boundary.
        let (n_str, d_str) = proof_to_metadata(&edge);
        let recovered = proof_from_metadata(&n_str, &d_str).unwrap();
        assert_eq!(recovered.nonce, u64::MAX);
        assert_eq!(recovered.difficulty, u64::MAX);

        // Malformed metadata → None (no panic).
        assert!(proof_from_metadata("not-a-number", "5000").is_none());
        assert!(proof_from_metadata("5000", "not-a-number").is_none());
        assert!(proof_from_metadata("", "").is_none());
    }

    #[test]
    fn batch_b_effective_difficulty_monotonic_decrease_across_stake_sweep_with_clamp_bounds() {
        // Difficulty is INVERSELY proportional to sqrt(stake), clamped to
        // [MIN_DIFFICULTY, MAX_DIFFICULTY]. Existing tests only check 2-point
        // monotonicity (1M vs 100M). Sweep 9 stake levels across 12 orders
        // of magnitude and pin the monotonic-decrease property + the
        // clamp boundaries.
        let stakes: [u64; 9] = [
            0,                  // zero stake → MAX_DIFFICULTY
            1,                  // 1 base unit (10^-9 beat) → MAX (clamped)
            1_000,              // 1e-6 beat
            1_000_000,          // 0.001 beat
            100_000_000,        // 0.1 beat
            1_000_000_000,      // 1 beat
            100_000_000_000,    // 100 beat (MIN_STAKE)
            1_000_000_000_000,  // 1000 beat (large staker)
            u64::MAX,           // u64::MAX → MIN (clamped)
        ];
        let difficulties: Vec<u64> = stakes.iter().map(|&s| effective_difficulty(s)).collect();

        // Boundary: zero stake = MAX_DIFFICULTY (the special-case at L62-64).
        assert_eq!(difficulties[0], MAX_DIFFICULTY,
            "stake=0 must return MAX_DIFFICULTY (special-case in effective_difficulty)");
        // Boundary: u64::MAX stake = MIN_DIFFICULTY (clamped from very small raw).
        assert_eq!(difficulties[8], MIN_DIFFICULTY,
            "stake=u64::MAX must clamp to MIN_DIFFICULTY (sqrt(huge) makes raw small)");
        // Boundary: stake=1 raw = BASE/sqrt(1)*1000 = 50_000_000 → clamps to MAX.
        assert_eq!(difficulties[1], MAX_DIFFICULTY,
            "stake=1 base unit must clamp to MAX_DIFFICULTY");

        // Monotonic non-increase across the sweep (allows clamp ties).
        for i in 0..difficulties.len() - 1 {
            assert!(difficulties[i] >= difficulties[i + 1],
                "non-monotonic at stake[{i}]={} → diff={} vs stake[{}]={} → diff={}: difficulty must decrease as stake increases",
                stakes[i], difficulties[i], i + 1, stakes[i + 1], difficulties[i + 1]);
        }

        // Strict decrease somewhere in the middle (not all clamped — at
        // least one stake level produces a difficulty strictly between
        // MIN and MAX). This guards against a regression where the
        // clamp range collapsed to a single value.
        let in_range_count = difficulties.iter()
            .filter(|&&d| d > MIN_DIFFICULTY && d < MAX_DIFFICULTY)
            .count();
        assert!(in_range_count >= 1,
            "expected at least one stake level to produce an in-range difficulty (not at clamp); got: {difficulties:?}");

        // Range bounds: every result is in [MIN, MAX].
        for (stake, diff) in stakes.iter().zip(difficulties.iter()) {
            assert!(*diff >= MIN_DIFFICULTY,
                "stake={stake}: difficulty {diff} < MIN_DIFFICULTY={MIN_DIFFICULTY}");
            assert!(*diff <= MAX_DIFFICULTY,
                "stake={stake}: difficulty {diff} > MAX_DIFFICULTY={MAX_DIFFICULTY}");
        }
    }
}
