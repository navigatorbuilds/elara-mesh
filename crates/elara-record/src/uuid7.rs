//! UUID v7 generation — time-ordered, random.

//!
//! Spec references:
//!   @spec Protocol §3.3.4

use uuid::Uuid;

/// Generate a new UUID v7 string.
pub fn uuid7() -> String {
    Uuid::now_v7().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uuid7_format() {
        let id = uuid7();
        // Standard UUID format: 8-4-4-4-12
        assert_eq!(id.len(), 36);
        assert_eq!(&id[8..9], "-");
        assert_eq!(&id[13..14], "-");
        // Version 7: char at position 14 should be '7'
        assert_eq!(&id[14..15], "7");
    }

    #[test]
    fn test_uuid7_uniqueness() {
        let ids: Vec<String> = (0..100).map(|_| uuid7()).collect();
        let mut deduped = ids.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(ids.len(), deduped.len());
    }

    #[test]
    fn test_uuid7_ordering() {
        // UUIDs generated sequentially should be lexicographically ordered
        let id1 = uuid7();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let id2 = uuid7();
        assert!(id1 < id2, "UUID v7 should be time-ordered: {} < {}", id1, id2);
    }

    // ─── UUID v7 format + monotonicity invariants ──

    /// All four hyphen separators (positions 8, 13, 18, 23) must be present.
    /// The existing format test only pins positions 8 and 13. A bug that
    /// dropped the third or fourth hyphen would produce a "valid-looking"
    /// 36-char string with the wrong byte structure — pin so it breaks
    /// loudly. The 8-4-4-4-12 grouping is RFC 9562 §4.
    #[allow(clippy::range_plus_one)]
    #[test]
    fn batch_b_uuid7_all_four_hyphen_separators_at_canonical_positions() {
        let id = uuid7();
        assert_eq!(id.len(), 36);
        for pos in [8usize, 13, 18, 23] {
            assert_eq!(
                &id[pos..pos + 1],
                "-",
                "UUID v7 separator missing at position {pos} in {id}",
            );
        }
    }

    /// All non-separator characters MUST be lowercase hex. The existing
    /// format test only checks one position (14). A future refactor that
    /// switches to UUID::to_string_hyphenated_ref().to_ascii_uppercase()
    /// or interpolates non-hex chars must break here. Cover every position
    /// outside the four hyphen slots.
    #[test]
    fn batch_b_uuid7_all_non_separator_chars_are_lowercase_hex() {
        let id = uuid7();
        let hyphen_positions = [8usize, 13, 18, 23];
        for (i, c) in id.chars().enumerate() {
            if hyphen_positions.contains(&i) {
                continue;
            }
            assert!(
                c.is_ascii_hexdigit() && (c.is_ascii_digit() || c.is_ascii_lowercase()),
                "non-lowercase-hex char {c:?} at position {i} in {id}",
            );
        }
    }

    /// RFC 9562 §4 variant: position 19 (the first char of the 4th group)
    /// encodes variant bits `10xx`, which in hex means one of {8, 9, a, b}.
    /// Pin so a future "let's emit variant 0 to save bits" or "variant c
    /// for our custom flag" regression breaks here. Sample many UUIDs since
    /// only 4 of 16 hex values are valid (random sampling needs depth).
    #[test]
    fn batch_b_uuid7_variant_byte_at_position_19_is_rfc9562_compliant() {
        let allowed = ['8', '9', 'a', 'b'];
        for _ in 0..256 {
            let id = uuid7();
            let variant = id.chars().nth(19).expect("position 19 exists in 36-char UUID");
            assert!(
                allowed.contains(&variant),
                "UUID v7 variant char at pos 19 = {variant:?} (must be one of {{8,9,a,b}}) in {id}",
            );
        }
    }

    /// Scale uniqueness: 10× the existing test's 100-batch. A regression
    /// in the random-tail entropy (e.g. seeded RNG, low-entropy time tick)
    /// might pass at 100 samples but collide at 1000. Pin the harder bound
    /// without depending on `std::thread::sleep` (would slow CI).
    #[test]
    fn batch_b_uuid7_one_thousand_sequential_ids_have_zero_collisions() {
        use std::collections::HashSet;
        let mut seen: HashSet<String> = HashSet::with_capacity(1000);
        for _ in 0..1000 {
            let id = uuid7();
            assert!(seen.insert(id.clone()), "collision on {id} at batch size 1000");
        }
        assert_eq!(seen.len(), 1000, "expected 1000 unique UUIDs");
    }

    /// Monotonicity across 10 sequential calls with millisecond-scale gaps.
    /// Existing ordering test is one pair only — a regression where the
    /// random tail occasionally beats the timestamp prefix (sub-millisecond
    /// reordering inside the same tick) could pass on a single pair but
    /// fail on a chain. Pin a 10-id strictly-increasing sequence with 2 ms
    /// gaps so the time prefix is unambiguously different per step.
    #[test]
    fn batch_b_uuid7_ten_id_sequence_with_millisecond_gaps_strictly_increasing() {
        let mut ids: Vec<String> = Vec::with_capacity(10);
        for _ in 0..10 {
            ids.push(uuid7());
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        for w in ids.windows(2) {
            assert!(
                w[0] < w[1],
                "UUID v7 sequence not strictly increasing: {} >= {}",
                w[0],
                w[1],
            );
        }
    }
}
