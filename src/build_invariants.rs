//! Build-level and doc-level invariants asserted as tests in the standing
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

// ─── Refinement-map guard: TLA+ ↔ Rust citations must track the source ──────
//
// internal design notes §6 tabulates which Rust function realises
// each TLA+ action, and the modules under `spec/tla/` carry the same map as
// header comments (`correlation_weighted_q  consensus.rs:3020`, …). Nothing
// checked those citations for four months: every table row drifted by 120 to
// 1,000 lines and one row named a struct the function never lived on. This
// guard is the `make refinement-check` the doc promised (no Makefile ever
// existed): every function the table names must be DEFINED in the file it
// cites, within the doc's own ±5-line drift budget (§10.4); and every
// `file.rs:N` citation in a spec module must have one of the identifiers on
// that comment line mentioned within ±5 lines of N. A citation with no
// identifier on its line is listed, not failed — nothing mechanical to check.
//
// The public mirror holds the doc back but ships `spec/tla/` and `src/` with
// line numbers intact (its pointer rewrite is in-line), so the doc half skips
// only when the tree is provably the mirror (no `scripts/build-public-mirror.sh`)
// and never silently in the private tree. Parsers are shared with a self-test
// so the guard can't rot into a vacuous pass.
#[cfg(test)]
mod refinement_map {
    use std::collections::{BTreeMap, HashMap};
    use std::path::{Path, PathBuf};

    /// The doc's contract (§10.4): "allow ±5 line drift before failing".
    pub const LINE_DRIFT: usize = 5;

    /// One `path.rs:N[-M]` (or file-only) citation.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Citation {
        /// Path as written: `consensus.rs`, `network/witness.rs`, `src/accounting/ledger.rs`.
        pub path: String,
        /// 1-based inclusive line range; `None` = file-only citation.
        pub lines: Option<(usize, usize)>,
    }

    fn is_word(c: u8) -> bool {
        c.is_ascii_alphanumeric() || c == b'_'
    }

    fn is_path_char(c: u8) -> bool {
        is_word(c) || c == b'/' || c == b'.' || c == b'-'
    }

    fn read_num(b: &[u8], mut i: usize) -> (Option<usize>, usize) {
        let start = i;
        let mut n: usize = 0;
        while i < b.len() && b[i].is_ascii_digit() {
            n = n.saturating_mul(10).saturating_add((b[i] - b'0') as usize);
            i += 1;
        }
        if i == start {
            (None, start)
        } else {
            (Some(n), i)
        }
    }

    /// Every `path.rs:N`, `path.rs:N-M`, `path.rs:N/M` and short-form `(:N)`
    /// citation on one line, left to right. A short form inherits the most
    /// recent explicit path (`last_path`, carried across lines by the caller).
    /// `path.rs::tests` (a Rust path, not a citation) is ignored.
    pub fn parse_citations(line: &str, last_path: &mut Option<String>) -> Vec<Citation> {
        let b = line.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < b.len() {
            if b[i] != b':' {
                // A `path.rs` that pins no line still names a file, and the
                // line's identifiers say which symbol. The scan was `:`-anchored
                // until 2026-09-06, so these were invisible rather than checked:
                // `Liveness.tla:13` cited `aggregator.rs:` with the number
                // wrapped onto the next comment line and went unverified for
                // months while pointing 16 lines off `proposer_rank`.
                if b[i] == b'.' && line[i..].starts_with(".rs") {
                    let after = i + 3;
                    // A `.` right after `.rs` ends a sentence unless a word char
                    // follows it: `consensus.rs.` is a citation, `foo.rs.bak` is a
                    // filename. Without this the trailing period made `.` a path
                    // char and the whole citation vanished silently.
                    let sentence_dot = b.get(after) == Some(&b'.')
                        && !matches!(b.get(after + 1), Some(&c) if is_word(c));
                    if after >= b.len()
                        || (!is_path_char(b[after]) && b[after] != b':')
                        || sentence_dot
                    {
                        let mut s = i;
                        while s > 0 && is_path_char(b[s - 1]) {
                            s -= 1;
                        }
                        let path = &line[s..after];
                        if path.len() > 3 {
                            *last_path = Some(path.to_string());
                            out.push(Citation {
                                path: path.to_string(),
                                lines: None,
                            });
                        }
                        i = after;
                        continue;
                    }
                }
                i += 1;
                continue;
            }
            let mut s = i;
            while s > 0 && is_path_char(b[s - 1]) {
                s -= 1;
            }
            let path = &line[s..i];
            let explicit = path.len() > 3 && path.ends_with(".rs");
            let short = !explicit && s == i && i > 0 && b[i - 1] == b'(';
            if !explicit && !short {
                i += 1;
                continue;
            }
            let (n1, j) = read_num(b, i + 1);
            let Some(n1) = n1 else {
                // `path.rs::tests` is a Rust path, not a citation. A `path.rs:`
                // whose number wrapped to the next comment line still names the
                // file, so it is checked as a file-only citation.
                if explicit && b.get(i + 1) != Some(&b':') {
                    *last_path = Some(path.to_string());
                    out.push(Citation {
                        path: path.to_string(),
                        lines: None,
                    });
                }
                i += 1;
                continue;
            };
            let owned = if explicit {
                *last_path = Some(path.to_string());
                path.to_string()
            } else if let Some(p) = last_path.clone() {
                p
            } else {
                i = j;
                continue;
            };
            let mut end = n1;
            let mut k = j;
            if k < b.len() && b[k] == b'-' {
                if let (Some(n2), k2) = read_num(b, k + 1) {
                    end = n2;
                    k = k2;
                }
            }
            out.push(Citation {
                path: owned.clone(),
                lines: Some((n1, end)),
            });
            while k < b.len() && b[k] == b'/' {
                match read_num(b, k + 1) {
                    (Some(n3), k3) => {
                        out.push(Citation {
                            path: owned.clone(),
                            lines: Some((n3, n3)),
                        });
                        k = k3;
                    }
                    _ => break,
                }
            }
            i = k;
        }
        out
    }

    /// Identifier-looking tokens on a comment line: maximal `[A-Za-z0-9_]`
    /// runs that contain an underscore and don't start with a digit
    /// (`is_zone_stuck`, `REAP_HORIZON_SECS`, `pending_xzone_locked`). Plain
    /// English and TLA+ names (`CorrQ`, `attest`) never qualify.
    pub fn code_tokens(line: &str) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for run in line.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
            let ok = run.contains('_')
                && run.len() >= 3
                && !run.as_bytes()[0].is_ascii_digit()
                && run.bytes().any(|c| c.is_ascii_alphabetic());
            if ok && !out.iter().any(|t| t == run) {
                out.push(run.to_string());
            }
        }
        out
    }

    /// Whole-word occurrence of `word` in `text`.
    pub fn has_word(text: &str, word: &str) -> bool {
        let b = text.as_bytes();
        let mut from = 0;
        while let Some(off) = text[from..].find(word) {
            let s = from + off;
            let e = s + word.len();
            let before = s == 0 || !is_word(b[s - 1]);
            let after = e >= b.len() || !is_word(b[e]);
            if before && after {
                return true;
            }
            from = s + 1;
        }
        false
    }

    /// 1-based lines in `lo..=hi` (clamped to the file) that mention `word`.
    pub fn mentions_in(lines: &[&str], word: &str, lo: usize, hi: usize) -> Vec<usize> {
        let lo = lo.max(1);
        let hi = hi.min(lines.len());
        (lo..=hi).filter(|&n| has_word(lines[n - 1], word)).collect()
    }

    /// 1-based lines that mention `word` as CODE — comment and bare-`use`
    /// lines excluded. This is what a citation points at: the symbol's
    /// mechanism, not a prose reference to it.
    pub fn code_mentions_in(lines: &[&str], word: &str) -> Vec<usize> {
        mentions_in(lines, word, 1, lines.len())
            .into_iter()
            .filter(|&m| is_code_mention(lines[m - 1]))
            .collect()
    }

    /// 1-based lines that DEFINE `fn name(` / `fn name<` (comment lines skipped).
    pub fn fn_def_lines(lines: &[&str], name: &str) -> Vec<usize> {
        let needle = format!("fn {name}");
        lines
            .iter()
            .enumerate()
            .filter(|(_, l)| {
                let t = l.trim_start();
                if t.starts_with("//") {
                    return false;
                }
                let b = l.as_bytes();
                let mut from = 0;
                while let Some(off) = l[from..].find(&needle) {
                    let s = from + off;
                    let e = s + needle.len();
                    let before = s == 0 || !is_word(b[s - 1]);
                    let mut k = e;
                    while k < b.len() && (b[k] == b' ' || b[k] == b'\t') {
                        k += 1;
                    }
                    let after = k < b.len() && (b[k] == b'(' || b[k] == b'<');
                    if before && after {
                        return true;
                    }
                    from = s + 1;
                }
                false
            })
            .map(|(i, _)| i + 1)
            .collect()
    }

    /// Is this line CODE, for diagnostic purposes — i.e. not a comment and not a
    /// bare `use` import? Both mention a symbol without being the mechanism a
    /// citation points at.
    fn is_code_mention(line: &str) -> bool {
        let t = line.trim_start();
        !(t.starts_with("//")
            || t.starts_with("/*")
            || t.starts_with('*')
            || t.starts_with("use "))
    }

    /// Nearest mention of `word` to `cited`, PREFERRING code lines.
    ///
    /// Returns `(line, was_code)`. The drift diagnostic used to report the plain
    /// nearest mention, which twice on 2026-09-06 named the wrong line for
    /// `try_sign_xzone_abort`: a `use` import 17 lines from the citation won over
    /// the actual call site 38 lines away, and on the earlier hit a comment won.
    /// Following the hint verbatim re-breaks the test, so the hint must point at
    /// code whenever code exists. Verification semantics are untouched — this
    /// only changes what the failure message names.
    pub fn nearest_mention_preferring_code(
        lines: &[&str],
        word: &str,
        cited: usize,
    ) -> Option<(usize, bool)> {
        let all = mentions_in(lines, word, 1, lines.len());
        let code: Vec<usize> = all
            .iter()
            .copied()
            .filter(|&m| is_code_mention(lines[m - 1]))
            .collect();
        let was_code = !code.is_empty();
        let pool = if was_code { &code } else { &all };
        pool.iter()
            .min_by_key(|&&m| m.abs_diff(cited))
            .map(|&m| (m, was_code))
    }

    /// Drop `( … )` groups (nesting-aware): the doc's "(was `:1635`, +144)" notes.
    pub fn strip_parens(s: &str) -> String {
        let mut depth = 0usize;
        let mut out = String::new();
        for c in s.chars() {
            match c {
                '(' => depth += 1,
                ')' => depth = depth.saturating_sub(1),
                _ if depth == 0 => out.push(c),
                _ => {}
            }
        }
        out
    }

    /// Substrings between backtick pairs, in order.
    pub fn backticked(s: &str) -> Vec<String> {
        s.split('`')
            .enumerate()
            .filter(|(i, _)| i % 2 == 1)
            .map(|(_, t)| t.trim().to_string())
            .filter(|t| !t.is_empty())
            .collect()
    }

    /// One row of the §6 table: TLA+ action, Rust fn names (last `::` segment),
    /// citations from the File:line cell (history notes in parentheses ignored).
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct DocRow {
        pub action: String,
        pub fns: Vec<String>,
        pub citations: Vec<Citation>,
    }

    /// Rows of the first markdown table whose header cell is `TLA+ action`.
    pub fn doc_table_rows(doc: &str) -> Vec<DocRow> {
        let mut rows = Vec::new();
        let mut in_table = false;
        for line in doc.lines() {
            let t = line.trim();
            if !in_table {
                if t.starts_with('|') && t.contains("TLA+ action") {
                    in_table = true;
                }
                continue;
            }
            if !t.starts_with('|') {
                break;
            }
            let cells: Vec<&str> = t.trim_matches('|').split('|').map(str::trim).collect();
            if cells.len() < 3 || cells[0].chars().all(|c| c == '-' || c == ':') {
                continue;
            }
            let fns = backticked(&strip_parens(cells[1]))
                .into_iter()
                .map(|f| f.rsplit("::").next().unwrap_or("").to_string())
                .filter(|f| !f.is_empty() && f.bytes().all(is_word))
                .collect();
            let mut citations = Vec::new();
            for tok in backticked(&strip_parens(cells[2])) {
                let mut last = None;
                let parsed = parse_citations(&tok, &mut last);
                if !parsed.is_empty() {
                    citations.extend(parsed);
                } else if tok.ends_with(".rs") {
                    citations.push(Citation {
                        path: tok,
                        lines: None,
                    });
                }
            }
            rows.push(DocRow {
                action: cells[0].to_string(),
                fns,
                citations,
            });
        }
        rows
    }

    /// Every `*.rs` under `<root>/src` **and** `<root>/crates/*/src`, as
    /// `/`-joined paths relative to `root`.
    ///
    /// The `crates/` half was added by D10 (2026-09-06). Lane 3 extracted whole
    /// subsystems out of `src/` — the record type, the DHT, the PQ transport, the
    /// verifier — and an index that stops at `src/` cannot see any of them, so a
    /// citation naming `crates/elara-record/src/record.rs` failed with "no file
    /// under src/ matches" even though both the file and the symbol were correct.
    /// That is a guard blind spot, not a doc defect: the fix a "fix the FILE, not
    /// the guard" reflex would produce is DELETION OF A TRUE CITATION, which is
    /// the wrong direction. Verified safe before widening: only four basenames
    /// (`anchor_proof.rs`, `kem.rs`, `lib.rs`, `pqc.rs`) exist in both trees, and
    /// no citation that resolves today resolves to a different file afterwards —
    /// a newly-ambiguous bare basename was already failing as unmatched.
    pub fn src_index(root: &Path) -> Vec<String> {
        fn walk(dir: &Path, root: &Path, out: &mut Vec<String>) {
            let Ok(rd) = std::fs::read_dir(dir) else { return };
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(&p, root, out);
                } else if p.extension().is_some_and(|x| x == "rs") {
                    if let Ok(rel) = p.strip_prefix(root) {
                        out.push(rel.to_string_lossy().replace('\\', "/"));
                    }
                }
            }
        }
        let mut out = Vec::new();
        walk(&root.join("src"), root, &mut out);
        if let Ok(rd) = std::fs::read_dir(root.join("crates")) {
            let mut crate_dirs: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
            crate_dirs.sort();
            for c in crate_dirs {
                walk(&c.join("src"), root, &mut out);
            }
        }
        out.sort();
        out
    }

    /// Resolve a cited path against the index: exact relative path, or a
    /// unique suffix match (`consensus.rs`, `network/witness.rs`). A bare
    /// basename shared by several files (`ledger.rs`) resolves only through a
    /// `hint` recorded from an earlier directory-qualified citation of the
    /// same basename in the same document — otherwise it is an error, so the
    /// author has to disambiguate rather than the guard guessing.
    pub fn resolve(
        cited: &str,
        index: &[String],
        hints: &mut HashMap<String, String>,
    ) -> Result<String, String> {
        let cited = cited.trim_start_matches("./");
        let suffix = format!("/{cited}");
        let cands: Vec<&String> = index
            .iter()
            .filter(|p| p.as_str() == cited || p.ends_with(&suffix))
            .collect();
        let base = cited.rsplit('/').next().unwrap_or(cited).to_string();
        match cands.len() {
            1 => {
                let hit = cands[0].clone();
                if cited.contains('/') {
                    hints.insert(base, hit.clone());
                }
                Ok(hit)
            }
            0 => Err(format!("`{cited}`: no file under src/ or crates/*/src/ matches")),
            _ => hints.get(&base).cloned().ok_or_else(|| {
                format!(
                    "`{cited}`: ambiguous ({}) — cite it with a directory prefix",
                    cands.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
                )
            }),
        }
    }

    /// Outcome of one guard half: hard failures, informational notes, and the
    /// number of citations actually verified (a vacuity floor for the tests).
    #[derive(Debug, Default)]
    pub struct Report {
        pub failures: Vec<String>,
        pub notes: Vec<String>,
        pub verified: usize,
    }

    /// Read-and-split cache so a 12k-line file is read once per run.
    pub struct Sources<'a> {
        root: &'a Path,
        cache: BTreeMap<String, Vec<String>>,
    }

    impl<'a> Sources<'a> {
        pub fn new(root: &'a Path) -> Self {
            Self {
                root,
                cache: BTreeMap::new(),
            }
        }

        /// Pre-seed a file (self-tests inject in-memory sources here).
        pub fn seed(&mut self, rel: &str, text: &str) {
            self.cache
                .insert(rel.to_string(), text.lines().map(str::to_string).collect());
        }

        pub fn lines(&mut self, rel: &str) -> Result<&Vec<String>, String> {
            if !self.cache.contains_key(rel) {
                let text = std::fs::read_to_string(self.root.join(rel))
                    .map_err(|e| format!("read {rel}: {e}"))?;
                self.cache
                    .insert(rel.to_string(), text.lines().map(str::to_string).collect());
            }
            Ok(&self.cache[rel])
        }
    }

    /// Doc half: each named fn must be defined in a cited file, inside the
    /// cited range ± `LINE_DRIFT` when a range is given.
    pub fn check_doc_rows(rows: &[DocRow], index: &[String], src: &mut Sources<'_>) -> Report {
        let mut rep = Report::default();
        let mut hints = HashMap::new();
        for row in rows {
            if row.fns.is_empty() {
                rep.notes
                    .push(format!("row {}: no backticked Rust function named", row.action));
                continue;
            }
            if row.citations.is_empty() {
                rep.failures
                    .push(format!("row {}: names {:?} but cites no file", row.action, row.fns));
                continue;
            }
            for f in &row.fns {
                let mut ok = false;
                let mut any_resolved = false;
                let mut found: Vec<String> = Vec::new();
                for c in &row.citations {
                    let rel = match resolve(&c.path, index, &mut hints) {
                        Ok(r) => r,
                        Err(e) => {
                            rep.failures.push(format!("row {}: {e}", row.action));
                            continue;
                        }
                    };
                    any_resolved = true;
                    let lines = match src.lines(&rel) {
                        Ok(l) => l,
                        Err(e) => {
                            rep.failures.push(format!("row {}: {e}", row.action));
                            continue;
                        }
                    };
                    let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
                    let defs = fn_def_lines(&refs, f);
                    for d in &defs {
                        found.push(format!("{rel}:{d}"));
                    }
                    let hit = match c.lines {
                        None => !defs.is_empty(),
                        Some((lo, hi)) => defs
                            .iter()
                            .any(|&d| d + LINE_DRIFT >= lo && d <= hi + LINE_DRIFT),
                    };
                    if hit {
                        ok = true;
                        break;
                    }
                }
                if ok {
                    rep.verified += 1;
                } else if any_resolved {
                    let cited: Vec<String> = row
                        .citations
                        .iter()
                        .map(|c| match c.lines {
                            Some((a, b)) if a == b => format!("{}:{a}", c.path),
                            Some((a, b)) => format!("{}:{a}-{b}", c.path),
                            None => c.path.clone(),
                        })
                        .collect();
                    let where_ = if found.is_empty() {
                        let mut elsewhere = Vec::new();
                        for rel in index {
                            if let Ok(lines) = src.lines(rel) {
                                let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
                                for d in fn_def_lines(&refs, f) {
                                    elsewhere.push(format!("{rel}:{d}"));
                                }
                            }
                        }
                        if elsewhere.is_empty() {
                            "not defined anywhere under src/ or crates/*/src/ (renamed or removed?)".to_string()
                        } else {
                            format!("defined elsewhere: {}", elsewhere.join(", "))
                        }
                    } else {
                        format!("defined at {} (> ±{LINE_DRIFT} lines away)", found.join(", "))
                    };
                    rep.failures.push(format!(
                        "row {}: `{f}` cited {} — {where_}",
                        row.action,
                        cited.join(" + ")
                    ));
                }
            }
        }
        rep
    }

    /// Spec half: every citation in a module comment names a FILE and a SYMBOL,
    /// and one of the line's identifiers must occur as CODE somewhere in that file.
    /// A citation carrying `:N` is REJECTED outright (D5, 2026-09-06) — there is no
    /// tolerance window any more, because a tolerance is what let pins accumulate.
    pub fn check_spec_text(
        module: &str,
        text: &str,
        index: &[String],
        src: &mut Sources<'_>,
    ) -> Report {
        let mut rep = Report::default();
        let mut hints = HashMap::new();
        let mut last_path = None;
        for (i, line) in text.lines().enumerate() {
            let n = i + 1;
            let cits = parse_citations(line, &mut last_path);
            if cits.is_empty() {
                continue;
            }
            // Tokenise with the cited paths blanked out: `cross_zone.rs` must not
            // supply `cross_zone` as evidence for its own citation.
            let mut scrubbed = line.to_string();
            for c in &cits {
                scrubbed = scrubbed.replace(&c.path, " ");
            }
            let tokens = code_tokens(&scrubbed);
            for c in &cits {
                let rel = match resolve(&c.path, index, &mut hints) {
                    Ok(r) => r,
                    Err(e) => {
                        rep.failures.push(format!("{module}:{n}: {e}"));
                        continue;
                    }
                };
                let lines = match src.lines(&rel) {
                    Ok(l) => l,
                    Err(e) => {
                        rep.failures.push(format!("{module}:{n}: {e}"));
                        continue;
                    }
                };
                let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
                // D5 ENFORCEMENT (2026-09-06): a citation that names a LINE is a
                // FAILURE. The old shape ACCEPTED `foo.rs:123` and validated it
                // against a +/-LINE_DRIFT window — permissive, not prohibitive, so
                // nothing stopped the next contributor reintroducing the pins that
                // cost 22 repairs across 10 commits in a single day. The convention
                // is prohibitive, so the guard prohibits. Checked BEFORE the
                // `tokens.is_empty()` note, or a pin on an identifier-free line
                // would slip through as a note instead of failing.
                // The old `lo > refs.len()` bounds check died here: after this
                // branch it had no reachable caller, and a branch that cannot run
                // is worse than no branch.
                if let Some((lo, _)) = c.lines {
                    rep.failures.push(format!(
                        "{module}:{n}: cites {rel}:{lo} — citations name a FILE and a SYMBOL, never a line. \
                         Drop the `:{lo}` and keep the symbol on this same line (the guard resolves a \
                         citation against the identifiers on its own line, so splitting them silently \
                         unverifies it)."
                    ));
                    continue;
                }
                if tokens.is_empty() {
                    rep.notes.push(format!(
                        "{module}:{n}: {rel} — no identifier on the line, unverifiable"
                    ));
                    continue;
                }
                {
                    // The only remaining shape: some identifier on the line must occur
                    // as CODE somewhere in the file. Skipping these silently (the
                    // shape before 2026-09-06) meant a citation that carried no
                    // line number was verified by nothing while the guard still
                    // printed `ok` — the failure mode a line-free convention
                    // would otherwise have walked straight into.
                    if tokens.iter().any(|t| !code_mentions_in(&refs, t).is_empty()) {
                        rep.verified += 1;
                        continue;
                    }
                    let mut prose: Vec<String> = Vec::new();
                    for t in &tokens {
                        if let Some(&first) = mentions_in(&refs, t, 1, refs.len()).first() {
                            prose.push(format!(
                                "{t} appears only in comments/imports, first {rel}:{first}"
                            ));
                        }
                    }
                    let hint = if prose.is_empty() {
                        format!("none of {tokens:?} appears anywhere in {rel}")
                    } else {
                        prose.join("; ")
                    };
                    rep.failures.push(format!(
                        "{module}:{n}: {rel} has no CODE mention of {tokens:?} — {hint}"
                    ));
                }
            }
        }
        rep
    }

    /// The private tree ships the mirror builder; the public mirror never does.
    pub fn is_private_tree(root: &Path) -> bool {
        root.join("scripts/build-public-mirror.sh").is_file()
    }

    pub fn root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// The drift hint must name a CODE line. Reproduces the exact shape that
        /// misled twice on 2026-09-06: a `use` import sits CLOSER to the stale
        /// citation than the real call site, so plain nearest-mention picked the
        /// import — and copying that line into the spec re-breaks the test.
        #[test]
        fn nearest_mention_prefers_code_over_imports_and_comments() {
            let lines = vec![
                "use crate::x::{try_sign_xzone_abort, TransferStatus};", // 1 — import
                "fn unrelated() {}",                                     // 2
                "    // try_sign_xzone_abort refuses unless its proof holds",  // 3 — comment
                "fn other() {}",                                         // 4
                "                try_sign_xzone_abort(&state, &t).await;", // 5 — the CALL
            ];
            let refs: Vec<&str> = lines.clone();

            // Cited line 2: the import (1) is 1 away, the call (5) is 3 away.
            // Plain nearest would say 1; we must say 5.
            let (line, was_code) =
                nearest_mention_preferring_code(&refs, "try_sign_xzone_abort", 2)
                    .expect("token appears in the fixture");
            assert_eq!(line, 5, "must name the call site, not the closer `use` import");
            assert!(was_code);

            // Pin the DIVERGENCE, so this test cannot pass under the old logic:
            // plain nearest-mention answers 1 (the import) for the same input.
            let plain = mentions_in(&refs, "try_sign_xzone_abort", 1, refs.len());
            assert_eq!(plain, vec![1, 3, 5], "fixture shape");
            assert_eq!(
                plain.iter().min_by_key(|&&m| m.abs_diff(2)).copied(),
                Some(1),
                "the superseded logic picked the import — that is the bug this fixes"
            );

            // A token that exists ONLY in a comment is reported as such, not
            // dressed up as a code site.
            let only_comment = vec!["    // mentions ghost_symbol here", "fn a() {}"];
            let refs2: Vec<&str> = only_comment.clone();
            let (l2, was_code2) = nearest_mention_preferring_code(&refs2, "ghost_symbol", 2)
                .expect("token appears in a comment");
            assert_eq!(l2, 1);
            assert!(!was_code2, "comment-only must be flagged, not silently reported");
        }

        #[test]
        fn refinement_map_parsers_self_test() {
            // Explicit, range, slash-continuation, short form, non-citation.
            let mut last = None;
            let c = parse_citations(
                "x consensus.rs:2829 y src/accounting/ledger.rs:206-210, cross_zone.rs:903/936 (:44) consensus.rs::tests",
                &mut last,
            );
            let want = |p: &str, a: usize, b: usize| Citation {
                path: p.to_string(),
                lines: Some((a, b)),
            };
            assert_eq!(
                c,
                vec![
                    want("consensus.rs", 2829, 2829),
                    want("src/accounting/ledger.rs", 206, 210),
                    want("cross_zone.rs", 903, 903),
                    want("cross_zone.rs", 936, 936),
                    want("cross_zone.rs", 44, 44),
                ]
            );
            assert_eq!(last.as_deref(), Some("cross_zone.rs"));
            // A short form with no prior explicit path is dropped, not guessed.
            let mut none = None;
            assert!(parse_citations("(:12) alone", &mut none).is_empty());

            // A `path.rs` pinning no line is a file-only citation, and so is a
            // `path.rs:` whose number wrapped onto the next comment line.
            let mut bare = None;
            let file_only = |p: &str| Citation {
                path: p.to_string(),
                lines: None,
            };
            assert_eq!(
                parse_citations(
                    "map (src/accounting/cross_zone.rs + epoch.rs): proposer_rank (aggregator.rs:",
                    &mut bare
                ),
                vec![
                    file_only("src/accounting/cross_zone.rs"),
                    file_only("epoch.rs"),
                    file_only("aggregator.rs"),
                ]
            );
            assert_eq!(bare.as_deref(), Some("aggregator.rs"));

            // Sentence-final `.` used to make the citation vanish: `.` is a path
            // char, so `b[after]` failed the test and no branch ever matched.
            let mut b2 = None;
            assert_eq!(
                parse_citations("the gate lives in consensus.rs.", &mut b2),
                vec![file_only("consensus.rs")]
            );
            // ...but a real extension is still part of the filename.
            let mut b3 = None;
            assert_eq!(parse_citations("see consensus.rs.bak now", &mut b3), vec![]);

            assert_eq!(
                code_tokens("is_zone_stuck (aggregator.rs:224) CorrQ attest REAP_HORIZON_SECS d_q 12_3"),
                vec!["is_zone_stuck", "REAP_HORIZON_SECS", "d_q"]
            );
            assert!(has_word("pub fn is_settled(&self)", "is_settled"));
            assert!(!has_word("pub fn is_settled_diverse(&self)", "is_settled"));

            let src = ["// fn foo(", "  pub fn foo(&self) {}", "fn foo<T>() {}", "fn foobar() {}", "fn foo () {}"];
            assert_eq!(fn_def_lines(&src, "foo"), vec![2, 3, 5]);

            assert_eq!(strip_parens("a (b (c) d) e"), "a  e");
            assert_eq!(backticked("x `a::b` (was `c`) + `d`"), vec!["a::b", "c", "d"]);

            let doc = "\
intro
| TLA+ action | Rust function | File:line |
|---|---|---|
| `Attest(w, r)` | `S::add_attestation` (was `record_attestation`) | `consensus.rs:1779` (was `:1635`, +144) |
| `EffectiveStake` | inline in `is_settled` + `effective_attesting_stake` | `consensus.rs:2706` + `consensus.rs:2805` |
| `ProfileUpdate(w, p)` | `WitnessManager::register_profile` | `network/witness.rs` |
after";
            let rows = doc_table_rows(doc);
            assert_eq!(rows.len(), 3);
            assert_eq!(rows[0].fns, vec!["add_attestation"]);
            assert_eq!(
                rows[0].citations,
                vec![Citation {
                    path: "consensus.rs".into(),
                    lines: Some((1779, 1779))
                }]
            );
            assert_eq!(rows[1].fns, vec!["is_settled", "effective_attesting_stake"]);
            assert_eq!(rows[1].citations.len(), 2);
            assert_eq!(
                rows[2].citations,
                vec![Citation {
                    path: "network/witness.rs".into(),
                    lines: None
                }]
            );
        }

        /// End-to-end on in-memory sources: the checks must FAIL on a wrong
        /// name, a stale line beyond ±5, an ambiguous bare basename, and a
        /// citation past EOF — and PASS inside the drift budget.
        #[test]
        fn refinement_map_checks_reject_pins_and_verify_symbol_only() {
            let root = root();
            let index = vec![
                "src/a/consensus.rs".to_string(),
                "src/a/cross_zone.rs".to_string(),
                "src/a/ledger.rs".to_string(),
                "src/b/ledger.rs".to_string(),
                "src/a/park_lane.rs".to_string(),
            ];
            let mut src = Sources::new(&root);
            let mut body = String::new();
            for i in 1..=40 {
                body.push_str(&format!("// line {i}\n"));
            }
            body.push_str("    pub fn add_attestation(&mut self) {}\n"); // line 41
            body.push_str("    pub fn is_settled(&self) -> bool { true }\n"); // 42
            body.push_str("    const REAP_HORIZON_SECS: u64 = 1; // \"metric_name_total\"\n"); // 43
            src.seed("src/a/consensus.rs", &body);
            src.seed("src/a/ledger.rs", "fn x() {}\n");
            src.seed("src/b/ledger.rs", "fn x() {}\n");
            src.seed("src/a/cross_zone.rs", "// cross_zone module\nfn y() {}\n");
            src.seed("src/a/park_lane.rs", "// only_in_comment is named here\nfn z() {}\n");

            let doc = "\
| TLA+ action | Rust function | File:line |
|---|---|---|
| `Ok1` | `S::add_attestation` | `consensus.rs:38` |
| `Ok2` | `S::is_settled` | `consensus.rs:40-45` |
| `Ok3` | `S::is_settled` | `a/consensus.rs` |
| `Stale` | `S::add_attestation` | `consensus.rs:30` |
| `Renamed` | `S::record_attestation` | `consensus.rs:41` |
| `Ambiguous` | `x` | `ledger.rs:1` |
";
            let rep = check_doc_rows(&doc_table_rows(doc), &index, &mut src);
            assert_eq!(rep.verified, 3, "{rep:?}");
            assert_eq!(rep.failures.len(), 3, "{rep:?}");
            assert!(rep.failures[0].contains("row `Stale`") && rep.failures[0].contains(":41"));
            assert!(rep.failures[1].contains("row `Renamed`") && rep.failures[1].contains("not defined anywhere"));
            assert!(rep.failures[2].contains("ambiguous"));

            let spec = "\
(* add_attestation consensus.rs:40 ok within drift *)
(* REAP_HORIZON_SECS (:39) ok; metric_name_total (:43) ok *)
(* is_settled consensus.rs:10 STALE *)
(* consensus.rs:12 no identifier here *)
(* add_attestation consensus.rs:999 past eof *)
(* src/a/ledger.rs:1 qualifies the hint, then ledger.rs:1 resolves *)
(* cross_zone.rs:1 — the path stem alone is not evidence *)
(* add_attestation a/consensus.rs symbol-only, no line *)
(* only_in_comment a/park_lane.rs is never code *)
(* absent_symbol_here a/park_lane.rs is nowhere at all *)
";
            let rep = check_spec_text("Spec.tla", spec, &index, &mut src);
            // D5 (2026-09-06): this fixture deliberately still carries the nine
            // line-pinned shapes the OLD window rule graded — "ok within drift",
            // "STALE", "past eof", "no identifier here". Under the prohibitive
            // rule every one of them is a REJECTION, so the counts invert: what
            // used to be verified=4 / notes=4 / failures=4 is now
            // verified=1 / notes=0 / failures=11. The lines are kept rather than
            // deleted so the fixture proves the pins are refused, not merely absent.
            //
            // notes went 4 -> 0 ON PURPOSE: the pin check runs BEFORE the
            // `tokens.is_empty()` note, so `consensus.rs:12 no identifier here`
            // now FAILS instead of being filed as unverifiable. A pin on an
            // identifier-free line must not be able to launder itself into a note.
            assert_eq!(rep.verified, 1, "{rep:?}");
            assert_eq!(rep.notes.len(), 0, "{rep:?}");
            assert_eq!(rep.failures.len(), 11, "{rep:?}");
            // Every pinned line is refused, and the message names the offending
            // number so the author can delete exactly it.
            for (i, line_no) in [(0usize, "40"), (1, "39"), (2, "43"), (3, "10"), (4, "12"), (5, "999")] {
                assert!(
                    rep.failures[i].contains("never a line") && rep.failures[i].contains(line_no),
                    "failure {i} must refuse the pin :{line_no} — {rep:?}"
                );
            }
            // The only VERIFIED line is the symbol-only one: `add_attestation
            // a/consensus.rs` with no `:N`. That is the whole convention in one case.
            assert!(
                rep.failures.iter().all(|f| !f.contains("Spec.tla:8")),
                "the symbol-only citation must verify, not fail — {rep:?}"
            );
            // A file-only citation is verified by a CODE mention — a symbol that
            // only ever appears in a comment does NOT satisfy it, and one that
            // appears nowhere says so distinctly.
            assert!(
                rep.failures[9].contains("Spec.tla:9")
                    && rep.failures[9].contains("no CODE mention")
                    && rep.failures[9].contains("only in comments/imports, first src/a/park_lane.rs:1"),
                "{rep:?}"
            );
            assert!(
                rep.failures[10].contains("Spec.tla:10")
                    && rep.failures[10].contains("appears anywhere in src/a/park_lane.rs"),
                "{rep:?}"
            );

            // A bare ambiguous basename with nothing qualifying it above resolves
            // to no file at all. The hint that lets `ledger.rs` work downstream is
            // seeded by the FIRST citation in the module, so editing that one line
            // breaks every citation below it — the guard must say which file to
            // name rather than guess one. Hit for real 2026-09-06: dropping the
            // directory prefix from Conservation.tla's opening citation failed 13
            // rows at once, all of them correct until that seed went away.
            let unseeded = "(* add_attestation ledger.rs, nothing qualifies it above *)\n";
            let rep = check_spec_text("Unseeded.tla", unseeded, &index, &mut src);
            assert_eq!(rep.verified, 0, "{rep:?}");
            assert_eq!(rep.failures.len(), 1, "{rep:?}");
            assert!(
                rep.failures[0].contains("ambiguous")
                    && rep.failures[0].contains("directory prefix"),
                "{rep:?}"
            );
        }

        /// internal design notes §6 table vs the live source.
        #[test]
        fn refinement_map_doc_table_tracks_source() {
            let root = root();
            let doc_path = root.join("internal design notes");
            let doc = match std::fs::read_to_string(&doc_path) {
                Ok(d) => d,
                Err(e) if !is_private_tree(&root) => {
                    eprintln!("refinement_map: {} absent ({e}); public mirror holds it back — doc half skipped", doc_path.display());
                    return;
                }
                Err(e) => panic!("private tree but {} unreadable: {e}", doc_path.display()),
            };
            let rows = doc_table_rows(&doc);
            assert!(rows.len() >= 8, "refinement table not found or truncated ({} rows parsed)", rows.len());
            let index = src_index(&root);
            let mut src = Sources::new(&root);
            let rep = check_doc_rows(&rows, &index, &mut src);
            for n in &rep.notes {
                eprintln!("refinement_map note: {n}");
            }
            assert!(
                rep.failures.is_empty(),
                "internal design notes §6 refinement table does not match src/ (fix the table; cite file+symbol — check_doc_rows still tolerates a legacy ±{LINE_DRIFT} range, but the shipped table carries no pins):\n  {}",
                rep.failures.join("\n  ")
            );
            assert!(rep.verified >= 9, "vacuity floor: only {} functions verified", rep.verified);
        }

        /// D5 ENFORCEMENT: a citation that names a LINE must FAIL, not be
        /// validated against a tolerance window. Permissive-but-validating is
        /// what let the pins exist in the first place; after 22 line repairs in
        /// one day the convention is prohibitive, so the guard must prohibit.
        #[test]
        fn spec_citation_carrying_a_line_number_is_rejected() {
            let root = root();
            let index = src_index(&root);
            let mut src = Sources::new(&root);
            // A pin that is CORRECT under the old window rule — VERIFIED, not
            // assumed: `CLAIM_TIMEOUT_SECS` really is at cross_zone.rs:29, so the
            // old code counted this as `verified` and produced zero failures. That
            // is what makes this test discriminating: it must go from 0 failures
            // (old, permissive) to exactly 1 (new, prohibitive). A pin that was
            // merely WRONG would fail under both rules and prove nothing — the
            // first draft of this fixture made exactly that mistake.
            let text = "(* CLAIM_TIMEOUT_SECS src/accounting/cross_zone.rs:29 *)\n";
            let rep = check_spec_text("probe.tla", text, &index, &mut src);
            assert_eq!(
                rep.failures.len(),
                1,
                "a line-carrying citation must produce exactly one failure; got {:?} (verified={}, notes={:?})",
                rep.failures,
                rep.verified,
                rep.notes
            );
            assert!(
                rep.failures[0].contains("29"),
                "the failure must name the offending line so the author can delete it: {:?}",
                rep.failures[0]
            );
            assert_eq!(rep.verified, 0, "a rejected citation must not count as verified");
        }

        /// `spec/tla/*.tla` refinement-map comments vs the live source.
        #[test]
        fn refinement_map_spec_module_citations_track_source() {
            let root = root();
            let dir = root.join("spec/tla");
            let mut modules: Vec<PathBuf> = match std::fs::read_dir(&dir) {
                Ok(rd) => rd
                    .flatten()
                    .map(|e| e.path())
                    // README.md is INCLUDED deliberately (D5-ENFORCE commit 2). The
                    // `extension == "tla"` filter meant spec/tla/README.md was checked
                    // by NOTHING, which is exactly why its 20 pins had gone stale
                    // unnoticed — `consensus.rs:2829` for correlation_weighted_q, and
                    // an `aggregator.rs:290` for a proposer_rank living at 306. A guard
                    // that skips a file by extension is a guard that file does not have.
                    // check_spec_text is generic over text — it parses per line and does
                    // not care about TLA+ syntax — so no parser work is needed.
                    .filter(|p| {
                        p.extension().is_some_and(|x| x == "tla")
                            || p.file_name().is_some_and(|f| f == "README.md")
                    })
                    .collect(),
                Err(e) if !is_private_tree(&root) => {
                    eprintln!("refinement_map: {} absent ({e}) — spec half skipped", dir.display());
                    return;
                }
                Err(e) => panic!("private tree but {} unreadable: {e}", dir.display()),
            };
            modules.sort();
            assert!(!modules.is_empty(), "no .tla modules under {}", dir.display());
            let index = src_index(&root);
            let mut src = Sources::new(&root);
            let mut failures = Vec::new();
            let mut verified = 0;
            let mut readme_verified = 0usize;
            for m in &modules {
                let name = m.file_name().unwrap_or_default().to_string_lossy().to_string();
                let text = std::fs::read_to_string(m).unwrap_or_else(|e| panic!("read {name}: {e}"));
                let rep = check_spec_text(&name, &text, &index, &mut src);
                for n in &rep.notes {
                    eprintln!("refinement_map note: {n}");
                }
                if name == "README.md" {
                    readme_verified = rep.verified;
                }
                verified += rep.verified;
                failures.extend(rep.failures);
            }
            assert!(
                failures.is_empty(),
                "spec/tla refinement-map citations do not match src/ (fix the comment; a citation names a FILE and a SYMBOL, never a line):\n  {}",
                failures.join("\n  ")
            );
            // Print the tally unconditionally. The floor below only reports on
            // the way down, so without this the one number that says whether a
            // citation-convention change kept its coverage is invisible unless
            // it already broke — and "did the flip lose citations?" has to be
            // answerable before the floor trips, not after.
            // README.md gets its OWN vacuity floor, not just a share of the
            // aggregate: it was checked by NOTHING until D5-ENFORCE commit 2 (the
            // `extension == "tla"` filter skipped it), which is precisely how its
            // 20 pins went stale unnoticed. A floor only on the 32-module total
            // would let the README silently fall back to zero verified citations
            // while the .tla files carried the number — the same invisibility,
            // re-created one layer up.
            // DERIVATION: measured 16 verified of 23 citations today (the other 7
            // are identifier-free lines, correctly NOTES). Floor set to 12 — room
            // for four citations to be deleted or reworded before it trips, the
            // same four-to-five-deletion slack the aggregate floor of 45 uses
            // against its own measured count. Raise it if the README grows; never
            // lower it to make a red run green.
            eprintln!("refinement_map: README.md alone verified {readme_verified} (floor 12)");
            assert!(
                readme_verified >= 12,
                "README.md vacuity floor: only {readme_verified} citations verified — the file was \
                 unchecked entirely before D5-ENFORCE; do not let it drift back to unverified"
            );
            eprintln!(
                "refinement_map: {verified} spec citations verified across {} modules",
                modules.len()
            );
            // Measured 50 on 2026-09-06 after the spec half moved to file+symbol
            // citations (48 while `.tla` still carried line pins; 45 before
            // file-only citations became visible at all). Dropping the pins did
            // not cost coverage: it consolidated six line numbers for one symbol
            // in one file into the one citation they always were, and naming a
            // symbol on lines that had only a number added more than that back.
            // 45 leaves room for five deletions before the floor trips and still
            // trips if any single module loses all of its citations.
            // MODULE-COUNT floor — the same hole closed next door in
            // `public_doc_citations_track_source`, found by asking whether that
            // fix had a sibling. `!modules.is_empty()` above passes with ONE
            // module of 32, and the citation floor only catches a loss big
            // enough to cross its slack (measured 50 verified against a floor of
            // 45), so a small `.tla` being renamed or deleted takes its module
            // out of the guard SILENTLY.
            //
            // DELIBERATELY `>=`, NOT the `==` used for the shipped-doc list, and
            // the asymmetry is the point rather than an oversight: that list is
            // curated, so ADDING to it must force the floor re-derivation the
            // D10 membership rule requires, and `==` is what forces it. Here the
            // set is a glob over a spec directory another lane actively grows —
            // failing someone's build for adding a module would be friction with
            // no safety in it. A minimum closes the silent-loss hole, which is
            // the whole defect, and leaves growth alone.
            assert!(
                modules.len() >= 32,
                "spec-module floor: {} modules checked, expected at least 32 — a .tla file was \
                 renamed or deleted and its citations left the guard silently",
                modules.len()
            );
            assert!(verified >= 45, "vacuity floor: only {verified} citations verified");
        }

        /// The docs we SHIP publicly, checked exactly like the spec modules (D10).
        ///
        /// The D5 arc closed the guard over `spec/tla/*` and internal design notes and stopped
        /// there. A census of everything else found 9,009 line pins across 309 files
        /// — and most of those are FOSSILS: in `docs/AUDIT-REPORTS/*` or a dated
        /// `*-VERDICT-*.md`, a pin records where the code stood on that date, so
        /// rewriting it would fabricate history. The set that is not a fossil is the
        /// intersection with `packaging/public-mirror-allowlist.txt` — a rotten line
        /// number in a doc we PUBLISH is a defect a stranger can hit, and
        /// `src/network/publish.rs`'s own doc-comment points readers at the first
        /// file in this list, so the path is public code → public doc → dead
        /// citation. Every pin sampled there was wrong: `src/record.rs`,
        /// `token/ledger.rs` and `dht.rs` had not existed for months;
        /// `is_settled_diverse` pointed at a blank line; `insert_record_inner` was
        /// 847 lines off and `ParsedEpochSeal` 853.
        ///
        /// The list is EXPLICIT, not a glob over `docs/`: membership here is the
        /// judgement "this doc is read as current truth", which is exactly the
        /// judgement a glob would erase by sweeping the fossils back in.
        #[test]
        fn public_doc_citations_track_source() {
            let root = root();
            const DOCS: [&str; 5] = [
                "docs/MESH-BFT-MERGE-SEMANTICS.md",
                "docs/MULTI-VALIDATOR-EMITTER-AUTH.md",
                "docs/REALMS-SELF-ASSEMBLY.md",
                "spec/proverif/README.md",
                // Not mirror-allowlisted, so not a public-surface defect — but it
                // is a LIVE design doc that governs current behaviour, and the
                // 2026-09-06 D7 audit cited its §3.2 as the invariant the code
                // violated. Its own pins were 17, 506 and 679 lines out at the
                // time. "Read as current truth" is the membership test here, not
                // "published".
                "internal design notes",
            ];
            let index = src_index(&root);
            let mut src = Sources::new(&root);
            let mut failures = Vec::new();
            let mut verified = 0usize;
            let mut checked = 0usize;
            let mut per_file: Vec<(&str, usize)> = Vec::new();
            for rel in DOCS {
                let text = match std::fs::read_to_string(root.join(rel)) {
                    Ok(t) => t,
                    Err(e) if !is_private_tree(&root) => {
                        eprintln!("public_doc_citations: {rel} absent ({e}) — skipped");
                        continue;
                    }
                    Err(e) => panic!("private tree but {rel} unreadable: {e}"),
                };
                checked += 1;
                let rep = check_spec_text(rel, &text, &index, &mut src);
                for n in &rep.notes {
                    eprintln!("public_doc_citations note: {n}");
                }
                eprintln!("public_doc_citations: {rel} verified {}", rep.verified);
                per_file.push((rel, rep.verified));
                verified += rep.verified;
                failures.extend(rep.failures);
            }
            assert!(
                failures.is_empty(),
                "shipped-doc citations do not match src/ (fix the DOC; a citation names a FILE and a SYMBOL, never a line):\n  {}",
                failures.join("\n  ")
            );
            eprintln!("public_doc_citations: {verified} verified across {checked} shipped docs");
            // TWO floors, because one aggregate number cannot express both failures.
            //
            // PER-FILE (>= 1): measured 2026-09-06 as 14 / 5 / 3 / 4. An aggregate
            // floor alone cannot catch a SMALL file going silently empty — drop all
            // 3 of REALMS' citations and a 26-measured aggregate still sits well
            // above any sane threshold, so the file quietly reverts to the
            // unverifiable prose this guard exists to prevent, and the total covers
            // for it. Tightening the aggregate until it caught that (24 of 26) would
            // leave two deletions of slack and trip on ordinary editing. So the
            // "every file still carries at least one verified citation" property is
            // asserted directly rather than approximated by a bigger number.
            //
            // AGGREGATE (>= 33): from the measured 41 — 14 / 5 / 3 / 4 / 15 on
            // 2026-09-06 — eight deletions of slack, the same proportional slack
            // the spec floors keep against their own counts. RAISED from 20 when
            // internal design notes joined the list: a floor derived from a
            // 26-citation corpus does not floor a 41-citation one, so leaving it
            // would have quietly stopped covering the file just added.
            for (rel, n) in &per_file {
                assert!(
                    *n >= 1,
                    "{rel} has no verified citation left — it has drifted back to unverifiable \
                     prose, which is exactly the state D10 found these files in"
                );
            }
            // THIRD floor: the LIST itself. The two above protect citations
            // inside the files that are listed — neither notices a file being
            // dropped from `DOCS` entirely, and then it is simply unguarded.
            // Measured 2026-09-06: at 44 verified (17/5/3/4/15) against an
            // aggregate floor of 33, deleting `MESH-BFT` (−17) or
            // `IDENTITY-PARTITIONING` (−15) trips it, but deleting `MVEA` (−5),
            // `proverif` (−4) or `REALMS` (−3) leaves 39/40/41 and passes
            // SILENTLY. That is the same "an aggregate cannot catch a small
            // loss" argument that justified the per-file floor, one layer up,
            // and I missed it there.
            //
            // Asserted on `checked` rather than `DOCS.len()` so it also catches
            // a listed file disappearing from disk, and gated on the private
            // tree because the public mirror legitimately skips absent files
            // (the `Err(e) if !is_private_tree` arm above).
            //
            // ADDING a doc is meant to fail here too: the D10 membership rule
            // says a new entry must re-derive the aggregate floor from the new
            // measured total, and being forced to touch this number is what
            // makes that happen instead of being forgotten.
            if is_private_tree(&root) {
                assert_eq!(
                    checked, 5,
                    "shipped-doc guard covers {checked} files, expected 5 — a doc was dropped from \
                     DOCS (or deleted); the aggregate floor cannot see a small file leave. If this \
                     is a deliberate add/remove, update this count AND re-derive the floor below."
                );
            }
            assert!(
                verified >= 33,
                "shipped-doc vacuity floor: only {verified} citations verified — these files were \
                 unchecked entirely before D10; do not let them drift back to unverified"
            );
        }
    }
}

/// R1 (2026-09-02): `network::epoch::KNOWN_EPOCH_OPS` must EQUAL the set of
/// `epoch_op` values the PRODUCTION sources write — derived from the tree,
/// never restated. A writer inserting a value missing from the list would
/// produce records that lose the global lane at ingest and the GC exemption,
/// silently; a listed value with no writer is dead allowlist surface.
///
/// Test code is excluded with a Rust-aware mini-lexer (the same approach as
/// `scripts/scan-prod-panics.py`): comments and string/char literals are
/// classified byte-by-byte, so a `#[cfg(test)]` inline module is blanked
/// from its attribute to its MATCHING closing brace (and scanning resumes
/// after it), `#[cfg(test)] mod x;` resolves to a separate file that is
/// skipped entirely, and a doc comment quoting `"epoch_op":"junk"` can't
/// register as a writer. The Opus diff-read of the first version caught the
/// naive "text before the first `#[cfg(test)]`" cut (95% of server/mod.rs
/// invisible, separate-file test modules scanned as production) — this is
/// the corrected guard, with lexer self-tests on known shapes.
///
/// Gated on `node-core` because it resolves `crate::network::epoch` (the
/// ungated first version broke default-feature `cargo check --all-targets`).
#[cfg(all(test, feature = "node-core"))]
mod epoch_ops {
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::{Path, PathBuf};

    use crate::network::epoch::{is_known_epoch_op, is_known_epoch_op_record, KNOWN_EPOCH_OPS};

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Kind {
        Code,
        Comment,
        Lit,
    }

    /// Classify every byte as code, comment, or the body of a string/char
    /// literal. Carries line and (nested) block comments, `"…"`, `b"…"`,
    /// `r#"…"#`, `br"…"` and char literals (told apart from lifetimes)
    /// across lines.
    fn classify(src: &[u8]) -> Vec<Kind> {
        let n = src.len();
        let mut kind = vec![Kind::Code; n];
        let at = |i: usize| if i < n { src[i] } else { 0 };
        let mut i = 0;
        while i < n {
            let c = src[i];
            let next = at(i + 1);
            if c == b'/' && next == b'/' {
                let mut j = i;
                while j < n && src[j] != b'\n' {
                    kind[j] = Kind::Comment;
                    j += 1;
                }
                i = j;
                continue;
            }
            if c == b'/' && next == b'*' {
                let mut depth = 0usize;
                let mut j = i;
                while j < n {
                    if src[j] == b'/' && at(j + 1) == b'*' {
                        depth += 1;
                        kind[j] = Kind::Comment;
                        kind[j + 1] = Kind::Comment;
                        j += 2;
                        continue;
                    }
                    if src[j] == b'*' && at(j + 1) == b'/' {
                        depth -= 1;
                        kind[j] = Kind::Comment;
                        kind[j + 1] = Kind::Comment;
                        j += 2;
                        if depth == 0 {
                            break;
                        }
                        continue;
                    }
                    kind[j] = Kind::Comment;
                    j += 1;
                }
                i = j;
                continue;
            }
            // raw strings: r"…", r#"…"#, br"…", br#"…"#
            let prev_ident = i > 0 && (src[i - 1].is_ascii_alphanumeric() || src[i - 1] == b'_');
            let raw_start = if c == b'r' && !prev_ident && (next == b'"' || next == b'#') {
                Some(i + 1)
            } else if c == b'b'
                && !prev_ident
                && next == b'r'
                && (at(i + 2) == b'"' || at(i + 2) == b'#')
            {
                Some(i + 2)
            } else {
                None
            };
            if let Some(start) = raw_start {
                let mut hashes = 0usize;
                let mut j = start;
                while j < n && src[j] == b'#' {
                    hashes += 1;
                    j += 1;
                }
                if at(j) == b'"' {
                    j += 1;
                    while j < n {
                        if src[j] == b'"' {
                            let mut k = 0;
                            while k < hashes && at(j + 1 + k) == b'#' {
                                k += 1;
                            }
                            if k == hashes {
                                j += 1 + hashes;
                                break;
                            }
                        }
                        kind[j] = Kind::Lit;
                        j += 1;
                    }
                    i = j;
                    continue;
                }
            }
            if c == b'"' {
                let mut j = i + 1;
                while j < n {
                    if src[j] == b'\\' {
                        kind[j] = Kind::Lit;
                        if j + 1 < n {
                            kind[j + 1] = Kind::Lit;
                        }
                        j += 2;
                        continue;
                    }
                    if src[j] == b'"' {
                        break;
                    }
                    kind[j] = Kind::Lit;
                    j += 1;
                }
                i = j + 1;
                continue;
            }
            if c == b'\'' {
                if next == b'\\' {
                    // '\', the escaped char, then scan to the closing quote
                    let mut j = i + 3;
                    kind[i + 1] = Kind::Lit;
                    if i + 2 < n {
                        kind[i + 2] = Kind::Lit;
                    }
                    while j < n && src[j] != b'\'' {
                        kind[j] = Kind::Lit;
                        j += 1;
                    }
                    i = j + 1;
                    continue;
                }
                if next != b'\'' && at(i + 2) == b'\'' {
                    kind[i + 1] = Kind::Lit;
                    i += 3;
                    continue;
                }
                let width = if next >= 0xF0 {
                    4
                } else if next >= 0xE0 {
                    3
                } else if next >= 0xC0 {
                    2
                } else {
                    0
                };
                if width > 0 && at(i + 1 + width) == b'\'' {
                    kind[i + 1..i + 1 + width].fill(Kind::Lit);
                    i += width + 2;
                    continue;
                }
                i += 1; // lifetime
                continue;
            }
            i += 1;
        }
        kind
    }

    /// `cfg(test)` or `cfg(all(…, test, …))` (whitespace already removed).
    /// `any(test, …)` / `not(test)` compile in production → NOT test-only.
    fn is_test_only_cfg(attr: &str) -> bool {
        if attr == "cfg(test)" {
            return true;
        }
        let Some(inner) = attr
            .strip_prefix("cfg(all(")
            .and_then(|s| s.strip_suffix("))"))
        else {
            return false;
        };
        let mut depth = 0i32;
        let mut start = 0;
        let mut elems = Vec::new();
        for (idx, ch) in inner.char_indices() {
            match ch {
                '(' => depth += 1,
                ')' => depth -= 1,
                ',' if depth == 0 => {
                    elems.push(&inner[start..idx]);
                    start = idx + 1;
                }
                _ => {}
            }
        }
        elems.push(&inner[start..]);
        elems.contains(&"test")
    }

    /// Where `mod name;` declared in `path` lives on disk (both layouts).
    fn module_file_candidates(path: &Path, name: &str) -> Vec<PathBuf> {
        let file = path.file_name().and_then(|f| f.to_str()).unwrap_or("");
        let dir = path.parent().unwrap_or(Path::new("."));
        let base = if matches!(file, "mod.rs" | "lib.rs" | "main.rs") {
            dir.to_path_buf()
        } else {
            dir.join(path.file_stem().and_then(|s| s.to_str()).unwrap_or(""))
        };
        vec![
            base.join(format!("{name}.rs")),
            base.join(name).join("mod.rs"),
        ]
    }

    /// Blank (space-fill, newline-preserving) comments and every test-only
    /// item — `#[cfg(test)] mod tests { … }` to its matching brace, test-only
    /// fns/uses/impls to their `;` or block end — and return the separate
    /// files that `#[cfg(test)] mod x;` declarations resolve to.
    fn production_text(path: &Path, src: &str) -> (String, Vec<PathBuf>) {
        let bytes = src.as_bytes();
        let n = bytes.len();
        let kind = classify(bytes);
        let mut out = bytes.to_vec();
        for (i, k) in kind.iter().enumerate() {
            if *k == Kind::Comment && bytes[i] != b'\n' {
                out[i] = b' ';
            }
        }
        let attr_end = |from: usize| -> usize {
            // `from` points at '#'; returns the index just past the matching ']'
            let mut depth = 0i32;
            let mut j = from + 1;
            while j < n {
                if kind[j] == Kind::Code {
                    match bytes[j] {
                        b'[' | b'(' => depth += 1,
                        b']' | b')' => {
                            depth -= 1;
                            if depth == 0 {
                                return j + 1;
                            }
                        }
                        _ => {}
                    }
                }
                j += 1;
            }
            n
        };
        let mut excluded = Vec::new();
        let mut i = 0;
        while i < n {
            if !(kind[i] == Kind::Code && bytes[i] == b'#' && i + 1 < n && bytes[i + 1] == b'[') {
                i += 1;
                continue;
            }
            let a_start = i;
            let a_end = attr_end(i);
            let attr: String = src[a_start + 2..a_end.saturating_sub(1)]
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            if !is_test_only_cfg(&attr) {
                i = a_end;
                continue;
            }
            // skip whitespace, blanked comments and further attributes
            let mut k = a_end;
            loop {
                while k < n && out[k].is_ascii_whitespace() {
                    k += 1;
                }
                if k + 1 < n && bytes[k] == b'#' && bytes[k + 1] == b'[' {
                    k = attr_end(k);
                    continue;
                }
                break;
            }
            // item extent: first `;` at depth 0, or the end of the first `{…}` block
            let item_start = k;
            let mut depth = 0i32;
            let mut m = k;
            let mut end = n;
            while m < n {
                if kind[m] == Kind::Code {
                    match bytes[m] {
                        b'{' => depth += 1,
                        b'}' => {
                            depth -= 1;
                            if depth == 0 {
                                end = m + 1;
                                break;
                            }
                        }
                        b';' if depth == 0 => {
                            end = m + 1;
                            break;
                        }
                        _ => {}
                    }
                }
                m += 1;
            }
            let head = String::from_utf8_lossy(&out[item_start..end])
                .trim()
                .to_string();
            if let Some(decl) = head.strip_suffix(';') {
                let words: Vec<&str> = decl.split_whitespace().collect();
                if let Some(pos) = words.iter().position(|w| *w == "mod") {
                    if let Some(name) = words.get(pos + 1) {
                        excluded.extend(module_file_candidates(path, name));
                    }
                }
            }
            for b in out[a_start..end].iter_mut() {
                if *b != b'\n' {
                    *b = b' ';
                }
            }
            i = end;
        }
        (
            String::from_utf8(out).expect("blanking keeps UTF-8 valid"),
            excluded,
        )
    }

    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in rd.flatten() {
            let p = entry.path();
            if p.is_dir() {
                if p.file_name().and_then(|f| f.to_str()) != Some("target") {
                    walk(&p, out);
                }
            } else if p.extension().and_then(|e| e.to_str()) == Some("rs") {
                out.push(p);
            }
        }
    }

    /// `const EPOCH_OP_*: &str = "…";` declarations in production text.
    fn collect_consts(prod: &str, into: &mut BTreeMap<String, String>) {
        let mut from = 0;
        while let Some(p) = prod[from..].find("const EPOCH_OP_") {
            let start = from + p + "const ".len();
            let name_end = prod[start..]
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .map(|e| start + e)
                .unwrap_or(prod.len());
            let name = prod[start..name_end].to_string();
            let stmt_end = prod[name_end..]
                .find(';')
                .map(|e| name_end + e)
                .unwrap_or(prod.len());
            let stmt = &prod[name_end..stmt_end];
            if let Some(q) = stmt.find('"') {
                if let Some(q2) = stmt[q + 1..].find('"') {
                    into.insert(name, stmt[q + 1..q + 1 + q2].to_string());
                }
            }
            from = stmt_end;
        }
    }

    struct Producer {
        line: usize,
        token: String,
        value: Option<String>,
    }

    /// Every production `epoch_op` WRITER: `insert(<key>, …)` (map form) or
    /// `<key>: …` (object-literal form). Readers (`get(EPOCH_OP_KEY)`,
    /// `contains_key(…)`, protected-key lists) are not writers.
    fn producers_in(prod: &str, consts: &BTreeMap<String, String>) -> Vec<Producer> {
        let b = prod.as_bytes();
        let is_ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
        let mut out = Vec::new();
        let mut from = 0;
        loop {
            let a = prod[from..]
                .find("EPOCH_OP_KEY")
                .map(|p| (from + p, "EPOCH_OP_KEY".len(), true));
            let s = prod[from..]
                .find("\"epoch_op\"")
                .map(|p| (from + p, "\"epoch_op\"".len(), false));
            let (pos, len, ident) = match (a, s) {
                (Some(x), Some(y)) => {
                    if x.0 <= y.0 {
                        x
                    } else {
                        y
                    }
                }
                (Some(x), None) => x,
                (None, Some(y)) => y,
                (None, None) => break,
            };
            from = pos + len;
            if ident {
                let prev_ok = pos == 0 || !is_ident(b[pos - 1]);
                let next_ok = pos + len >= b.len() || !is_ident(b[pos + len]);
                if !prev_ok || !next_ok {
                    continue;
                }
            }
            let mut bs = pos.saturating_sub(64);
            while !prod.is_char_boundary(bs) {
                bs += 1;
            }
            let before = &prod[bs..pos];
            let decl = before.trim_end();
            if decl.ends_with("const") || decl.ends_with("static") || decl.ends_with("let") {
                continue; // the key's own declaration, not a writer
            }
            let mut rest = prod[pos + len..].trim_start();
            for w in [".to_string()", ".into()", ".to_owned()"] {
                if let Some(r) = rest.strip_prefix(w) {
                    rest = r.trim_start();
                }
            }
            let object_form = rest.starts_with(':') && !rest.starts_with("::");
            let insert_form = before.contains("insert(") && rest.starts_with(',');
            if !object_form && !insert_form {
                continue;
            }
            rest = rest[1..].trim_start();
            loop {
                let mut stripped = false;
                for w in [
                    "serde_json::",
                    "json!",
                    "Value::String",
                    "String::from",
                    "(",
                    "&",
                ] {
                    if let Some(r) = rest.strip_prefix(w) {
                        rest = r.trim_start();
                        stripped = true;
                    }
                }
                if !stripped {
                    break;
                }
            }
            let line = prod[..pos].matches('\n').count() + 1;
            if let Some(lit) = rest.strip_prefix('"') {
                let v = lit.split('"').next().unwrap_or("").to_string();
                out.push(Producer {
                    line,
                    token: format!("{v:?}"),
                    value: Some(v),
                });
                continue;
            }
            let tok_end = rest
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == ':'))
                .unwrap_or(rest.len());
            let token = rest[..tok_end].to_string();
            let last = token.rsplit("::").next().unwrap_or("").to_string();
            let value = consts.get(&last).cloned();
            out.push(Producer { line, token, value });
        }
        out
    }

    fn production_tree() -> (Vec<(PathBuf, String)>, BTreeSet<PathBuf>) {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files = Vec::new();
        walk(&root.join("src"), &mut files);
        if let Ok(rd) = std::fs::read_dir(root.join("crates")) {
            for entry in rd.flatten() {
                walk(&entry.path().join("src"), &mut files);
            }
        }
        files.sort();
        let mut texts = Vec::new();
        let mut excluded = BTreeSet::new();
        for f in files {
            let src = std::fs::read_to_string(&f).unwrap_or_default();
            let (prod, ex) = production_text(&f, &src);
            excluded.extend(ex);
            texts.push((f, prod));
        }
        (texts, excluded)
    }

    #[test]
    fn lexer_self_test_on_known_shapes() {
        let (texts, excluded) = production_tree();
        assert!(
            excluded
                .iter()
                .any(|p| p.ends_with("network/routes/explorer/tests.rs")),
            "separate-file `#[cfg(test)] mod tests;` resolution broke: {excluded:?}"
        );
        fn text<'a>(texts: &'a [(PathBuf, String)], suffix: &str) -> &'a str {
            &texts
                .iter()
                .find(|(p, _)| p.ends_with(suffix))
                .unwrap_or_else(|| panic!("{suffix} not walked"))
                .1
        }
        let gc = text(&texts, "network/gc.rs");
        assert!(
            gc.contains("seal_pruning_floor"),
            "production body of gc.rs was blanked"
        );
        assert!(
            !gc.contains("fn gc_unknown_epoch_op_value_is_not_immortal"),
            "inline `#[cfg(test)] mod` body NOT blanked"
        );
        let server = text(&texts, "network/server/mod.rs");
        assert!(
            server.contains("elara_gc_seal_floor_lag_epochs_max"),
            "scanning stopped at the first inline test module (must resume after it)"
        );
        let epoch = text(&texts, "network/epoch.rs");
        assert!(
            epoch.contains("pub const KNOWN_EPOCH_OPS"),
            "epoch.rs production text lost"
        );
        let raw_epoch = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("src/network/epoch.rs"),
        )
        .expect("epoch.rs readable");
        assert!(
            raw_epoch.contains("Network note (Opus diff-read S3"),
            "self-test anchor comment moved"
        );
        assert!(
            !epoch.contains("Network note (Opus diff-read S3"),
            "doc comments were not blanked"
        );
        assert!(is_test_only_cfg("cfg(test)"));
        assert!(is_test_only_cfg("cfg(all(test,feature=\"node\"))"));
        assert!(!is_test_only_cfg("cfg(any(test,feature=\"x\"))"));
        assert!(!is_test_only_cfg("cfg(not(test))"));
        assert!(!is_test_only_cfg("cfg(feature=\"node-core\")"));
        // char-literal vs lifetime vs string: braces inside literals must not count
        let sample = "fn a<'x>() { let _ = '{'; let _ = \"}\"; let _ = r#\"{\"#; }\n#[cfg(test)]\nmod t { fn w() { m.insert(EPOCH_OP_KEY.into(), json!(\"epoch_seal\")); } }\nfn z() {}\n";
        let (prod, _) = production_text(Path::new("x/y.rs"), sample);
        assert!(
            prod.contains("fn z() {}"),
            "scan did not resume after the test module: {prod:?}"
        );
        assert!(
            !prod.contains("epoch_seal"),
            "test module body leaked: {prod:?}"
        );
    }

    #[test]
    fn known_epoch_ops_equal_the_production_writer_set() {
        let (texts, excluded) = production_tree();
        let mut consts = BTreeMap::new();
        for (p, prod) in &texts {
            if !excluded.contains(p) {
                collect_consts(prod, &mut consts);
            }
        }
        assert!(
            consts.get("EPOCH_OP_SEAL").map(String::as_str) == Some("seal"),
            "const resolution broke: {consts:?}"
        );
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut found: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut dynamic = Vec::new();
        for (p, prod) in &texts {
            if excluded.contains(p) {
                continue;
            }
            let rel = p.strip_prefix(root).unwrap_or(p).display().to_string();
            for pr in producers_in(prod, &consts) {
                match pr.value {
                    Some(v) => found
                        .entry(v)
                        .or_default()
                        .push(format!("{rel}:{}", pr.line)),
                    None => dynamic.push(format!("{rel}:{} ({})", pr.line, pr.token)),
                }
            }
        }
        assert!(
            dynamic.is_empty(),
            "epoch_op written from a non-literal in PRODUCTION code — the allowlist cannot be derived: {dynamic:?}"
        );
        let known: BTreeSet<&str> = KNOWN_EPOCH_OPS.iter().copied().collect();
        let writers: BTreeSet<&str> = found.keys().map(String::as_str).collect();
        assert_eq!(
            writers, known,
            "KNOWN_EPOCH_OPS must equal the production writer set (left = writers found, right = allowlist). Writers: {found:#?}"
        );
    }

    #[test]
    fn unknown_epoch_op_values_are_not_known() {
        for v in ["junk", "epoch_seal", "anchor", "SEAL", "", "seal "] {
            assert!(!is_known_epoch_op(v), "{v:?} must be unknown");
        }
        assert!(is_known_epoch_op("seal"));
        let mut rec = crate::record::ValidationRecord::create(
            b"r1",
            vec![0u8; 32],
            vec![],
            crate::record::Classification::Public,
            None,
        );
        assert!(
            !is_known_epoch_op_record(&rec),
            "missing key must be unknown"
        );
        rec.metadata.insert("epoch_op".into(), serde_json::json!(7));
        assert!(
            !is_known_epoch_op_record(&rec),
            "non-string value must be unknown"
        );
        rec.metadata
            .insert("epoch_op".into(), serde_json::json!("junk"));
        assert!(
            !is_known_epoch_op_record(&rec),
            "unknown value must be unknown"
        );
        rec.metadata
            .insert("epoch_op".into(), serde_json::json!("seal"));
        assert!(is_known_epoch_op_record(&rec));
    }
}
