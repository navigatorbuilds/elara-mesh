//! Build-level invariants asserted as tests in the standing
//! `cargo test --features node --lib` gate.
//!
//! These guard properties of the *build configuration* (not runtime logic) that
//! no other test can see — a `cfg!(panic = ...)` check, for instance, only
//! observes the test profile, never `[profile.release]`. So they assert against
//! the workspace manifest source directly.

/// Return the 1-based line numbers in a TOML manifest that set
/// `panic = "abort"` (either quote style). Strips `#` line comments and
/// collapses whitespace so `panic = "abort"` and `panic="abort"` both match. A
/// `#` inside a string can only truncate AFTER a value, never hide a standalone
/// `panic = "abort"` key line — so no false negatives for the real threat.
/// Shared by the live guard and its self-test so the matcher can't rot into a
/// vacuous pass (same philosophy as scan-prod-panics / scan-ledger-replace).
#[cfg(test)]
fn lines_setting_panic_abort(manifest_text: &str) -> Vec<usize> {
    manifest_text
        .lines()
        .enumerate()
        .filter(|(_, line)| {
            let code: String = line
                .split('#')
                .next()
                .unwrap_or("")
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            code.contains("panic=\"abort\"") || code.contains("panic='abort'")
        })
        .map(|(i, _)| i + 1)
        .collect()
}

/// True iff the manifest sets `overflow-checks = true` inside `[profile.release]`
/// (any quote/spacing). Scans line-by-line: tracks the current `[section]` and
/// only accepts the key within the release profile, so the same key set in
/// `[profile.bench]` or an unrelated table does not satisfy it. Strips `#`
/// comments and whitespace, same as the panic matcher. Shared by the live guard
/// and its self-test so the matcher can't rot into a vacuous pass.
#[cfg(test)]
fn release_profile_sets_overflow_checks(manifest_text: &str) -> bool {
    let mut in_release = false;
    for line in manifest_text.lines() {
        let code: String = line
            .split('#')
            .next()
            .unwrap_or("")
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        if code.starts_with('[') {
            in_release = code == "[profile.release]";
            continue;
        }
        if in_release && code == "overflow-checks=true" {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::{lines_setting_panic_abort, release_profile_sets_overflow_checks};

    /// Self-test: the matcher must catch `panic = "abort"` (both quote styles,
    /// spaced or tight) and must NOT trip on `panic = "unwind"` or a commented
    /// line. Guards against a future "simplification" silently breaking detection.
    #[test]
    fn matcher_catches_abort_and_clears_safe_lines() {
        assert_eq!(lines_setting_panic_abort("panic = \"abort\"\n"), vec![1]);
        assert_eq!(lines_setting_panic_abort("panic=\"abort\"\n"), vec![1]);
        assert_eq!(lines_setting_panic_abort("panic = 'abort'\n"), vec![1]);
        assert_eq!(
            lines_setting_panic_abort("[profile.release]\npanic = \"abort\" # bad\n"),
            vec![2]
        );
        assert!(lines_setting_panic_abort("panic = \"unwind\"\n").is_empty());
        assert!(lines_setting_panic_abort("# panic = \"abort\" (a doc note)\n").is_empty());
        assert!(lines_setting_panic_abort("[profile.release]\npanic = \"unwind\"\n").is_empty());
    }

    /// S2 hostile-input safety gate (internal design notes):
    /// a stranger's malformed handshake/gossip/sync bytes must unwind the
    /// per-connection tokio task, NEVER abort the node process. `panic = "abort"`
    /// in any build profile would turn a single decoder panic into a fleet-wide
    /// node crash — the exact "the first stranger who crashes your node writes
    /// the HN comment" failure the gate guards against.
    ///
    /// Rust's default is `unwind`; `[profile.release]` pins it explicitly. This
    /// test fails the build if a future binary-size/perf tweak ever sets
    /// `panic = "abort"` (either quote style) anywhere in the workspace manifest.
    /// `cfg!(panic = "abort")` can't be used here — a test binary is built under
    /// the test profile (always unwind), so it would be vacuously green even if
    /// the release profile flipped. Hence the manifest-source scan.
    #[test]
    fn release_profile_must_not_panic_abort_for_per_connection_isolation() {
        let manifest = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");
        let text = std::fs::read_to_string(manifest)
            .unwrap_or_else(|e| panic!("read workspace manifest {manifest}: {e}"));

        let offending = lines_setting_panic_abort(&text);

        assert!(
            offending.is_empty(),
            "Cargo.toml sets panic=\"abort\" (line(s) {offending:?}). A malformed \
             packet from a stranger would crash the whole node instead of one \
             connection (S2 hostile-input gate). Use panic=\"unwind\" so decoder \
             panics stay per-connection."
        );
    }

    /// Self-test: the overflow-checks matcher must detect the key inside
    /// `[profile.release]` (both spacings), must reject it when absent, when set
    /// in a different profile, or when explicitly false. Guards against a future
    /// "simplification" silently making the live guard vacuous.
    #[test]
    fn overflow_checks_matcher_detects_only_release_profile_true() {
        assert!(release_profile_sets_overflow_checks(
            "[profile.release]\noverflow-checks = true\n"
        ));
        assert!(release_profile_sets_overflow_checks(
            "[profile.release]\noverflow-checks=true\n"
        ));
        assert!(release_profile_sets_overflow_checks(
            "[profile.release]\npanic = \"unwind\"\noverflow-checks = true # money safety\n"
        ));
        // Absent => false (the silent-wrap bug).
        assert!(!release_profile_sets_overflow_checks(
            "[profile.release]\npanic = \"unwind\"\n"
        ));
        // Set in the WRONG profile => false.
        assert!(!release_profile_sets_overflow_checks(
            "[profile.bench]\noverflow-checks = true\n"
        ));
        // Explicitly false => false.
        assert!(!release_profile_sets_overflow_checks(
            "[profile.release]\noverflow-checks = false\n"
        ));
    }

    /// Monetary-safety gate: release must enable overflow-checks. Without it,
    /// release builds silently WRAP integer overflow (Rust's release default) —
    /// a wrapping monetary add could bypass a cap check or corrupt a balance / SMT
    /// leaf, a silent consensus fork. Monetary accumulators are `saturating_add`
    /// and intentional wraps are `wrapping_*`, so the flag never panics a normal
    /// path; it is the regression net that turns any FUTURE raw overflow into a
    /// contained (panic=unwind, per-connection) failure. `cfg!(overflow_checks)`
    /// can't be used here — the test binary is built under the test profile (which
    /// already has checks on), so it would pass vacuously even if the release
    /// profile lacked the flag. Hence the manifest-source scan.
    #[test]
    fn release_profile_must_enable_overflow_checks_for_monetary_safety() {
        let manifest = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");
        let text = std::fs::read_to_string(manifest)
            .unwrap_or_else(|e| panic!("read workspace manifest {manifest}: {e}"));

        assert!(
            release_profile_sets_overflow_checks(&text),
            "[profile.release] must set overflow-checks = true. Without it, release \
             silently wraps integer overflow — a wrapping monetary add could bypass a \
             cap check or corrupt a balance/SMT leaf (a silent consensus fork). \
             Accumulators use saturating_add and intentional wraps use wrapping_*, so \
             the flag never panics a normal path."
        );
    }
}
