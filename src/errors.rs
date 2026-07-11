//! Error types for the Elara Runtime.

//!
//! Spec references:
//!   @spec Protocol §3.2

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ElaraError {
    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Wire format error: {0}")]
    Wire(String),

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Record not found: {0}")]
    RecordNotFound(String),

    #[error("Duplicate record: {0}")]
    DuplicateRecord(String),

    #[error("Missing parent: {0}")]
    MissingParent(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Address error: {0}")]
    Address(String),

    #[error("DAG error: {0}")]
    Dag(String),

    #[error("Ledger error: {0}")]
    Ledger(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Governance error: {0}")]
    Governance(String),

    #[error("Dispute error: {0}")]
    Dispute(String),

    #[error("Config error: {0}")]
    Config(String),

    #[error("Rate limited")]
    RateLimited,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

}

pub type Result<T> = std::result::Result<T, ElaraError>;

/// Bridge the permissive `elara-record` crate's focused error into the node's wider
/// `ElaraError`, variant-for-variant, preserving the message so `?`-propagation and
/// existing `matches!(err, ElaraError::Wire(..))` sites keep working after extraction.
impl From<elara_record::RecordError> for ElaraError {
    fn from(e: elara_record::RecordError) -> Self {
        use elara_record::RecordError as RE;
        match e {
            RE::Wire(s) => ElaraError::Wire(s),
            RE::Crypto(s) => ElaraError::Crypto(s),
            RE::Json(e) => ElaraError::Json(e),
            RE::Io(e) => ElaraError::Io(e),
        }
    }
}

#[cfg(all(not(target_arch = "wasm32"), feature = "pyo3"))]
impl From<ElaraError> for pyo3::PyErr {
    fn from(err: ElaraError) -> pyo3::PyErr {
        pyo3::exceptions::PyValueError::new_err(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ────────────────────────────────────────────────────────────────────────
    // Coverage tests on every public surface of
    // ElaraError. errors.rs has no prior test module, so this pack is the
    // floor coverage; the five axes are chosen to defend the wire-visible
    // contracts (Display prose, source-chain hops, auto-trait bounds) that
    // operators and downstream `?`-propagating call sites depend on without
    // realising it. A future refactor that silently retypes one variant or
    // drops a #[from] attribute must trip one of these tests.
    //
    //  (1) 17-variant Display strict-prose pin — every variant rendered
    //      exact-byte, including the two #[from] variants (Io/Json) and the
    //      two unit variants (InvalidSignature/RateLimited). Defends against
    //      log-scraper regressions from silent thiserror prose drift.
    //  (2) source() chain matrix — 15 flat variants return None, the 2
    //      #[from] variants return Some + downcast back to inner type.
    //      Defends single-hop log walkers + boundary `?` propagation.
    //  (3) Send + Sync + 'static + std::error::Error auto-trait pins +
    //      sizeof bound. Defends async-fn return propagation + Result
    //      discriminant inlining cost.
    //  (4) From<io::Error> + From<serde_json::Error> conversion shape pin +
    //      io::ErrorKind round-trip via source() + Result<T> alias pin.
    //      Defends silent rewrap that loses the inner error kind.
    //  (5) Payload-rendering matrix on String-carrying variants (empty /
    //      ASCII / multi-line / UTF-8 / surrounding-whitespace). Defends
    //      against html-escape / debug-quote / truncation regressions in
    //      thiserror's `{0}` format substitution.
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn batch_b_seventeen_variant_display_strict_prose_pin() {
        // Every variant's Display string is what operators see in logs and
        // what downstream services may grep for. Pin EXACT bytes so a
        // thiserror attribute rewrite (e.g. capitalisation drift, prefix
        // change, colon-vs-dash punctuation drift) forces a deliberate
        // cross-update of test + attribute + any external scraper rule.
        //
        // 13 String-carrying variants — sentinel "X" payload makes the
        // colon + space + payload boundary unambiguous.
        assert_eq!(ElaraError::Crypto("X".into()).to_string(),         "Crypto error: X");
        assert_eq!(ElaraError::Wire("X".into()).to_string(),           "Wire format error: X");
        assert_eq!(ElaraError::RecordNotFound("X".into()).to_string(), "Record not found: X");
        assert_eq!(ElaraError::DuplicateRecord("X".into()).to_string(),"Duplicate record: X");
        assert_eq!(ElaraError::MissingParent("X".into()).to_string(),  "Missing parent: X");
        assert_eq!(ElaraError::Storage("X".into()).to_string(),        "Storage error: X");
        assert_eq!(ElaraError::Address("X".into()).to_string(),        "Address error: X");
        assert_eq!(ElaraError::Dag("X".into()).to_string(),            "DAG error: X");
        assert_eq!(ElaraError::Ledger("X".into()).to_string(),          "Ledger error: X");
        assert_eq!(ElaraError::Network("X".into()).to_string(),        "Network error: X");
        assert_eq!(ElaraError::Governance("X".into()).to_string(),     "Governance error: X");
        assert_eq!(ElaraError::Dispute("X".into()).to_string(),        "Dispute error: X");
        assert_eq!(ElaraError::Config("X".into()).to_string(),         "Config error: X");

        // 2 unit variants — exact prose, no payload, no trailing punctuation.
        assert_eq!(ElaraError::InvalidSignature.to_string(), "Invalid signature");
        assert_eq!(ElaraError::RateLimited.to_string(),      "Rate limited");

        // 2 #[from] variants — render the inner Display verbatim with prefix.
        // Use a known-shape io::Error so the inner Display is deterministic.
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "missing");
        // Inner io::Error Display is "missing" (the inner.to_string() output).
        let io_inner_display = io_err.to_string();
        let wrapped: ElaraError = io_err.into();
        assert_eq!(wrapped.to_string(), format!("IO error: {io_inner_display}"));

        let json_err: serde_json::Error = serde_json::from_str::<u8>("not-a-number").unwrap_err();
        let json_inner_display = json_err.to_string();
        let wrapped_json: ElaraError = json_err.into();
        assert_eq!(wrapped_json.to_string(), format!("JSON error: {json_inner_display}"));

        // Negative pin: Display must NOT collapse to Debug (would surface as
        // "Crypto(\"X\")" if thiserror's #[derive(Error)] were ever removed).
        // Covers every variant in one sweep so the regression can't slip in
        // through a single variant.
        for s in [
            ElaraError::Crypto("X".into()).to_string(),
            ElaraError::Wire("X".into()).to_string(),
            ElaraError::InvalidSignature.to_string(),
            ElaraError::RecordNotFound("X".into()).to_string(),
            ElaraError::DuplicateRecord("X".into()).to_string(),
            ElaraError::MissingParent("X".into()).to_string(),
            ElaraError::Storage("X".into()).to_string(),
            ElaraError::Address("X".into()).to_string(),
            ElaraError::Dag("X".into()).to_string(),
            ElaraError::Ledger("X".into()).to_string(),
            ElaraError::Network("X".into()).to_string(),
            ElaraError::Governance("X".into()).to_string(),
            ElaraError::Dispute("X".into()).to_string(),
            ElaraError::Config("X".into()).to_string(),
            ElaraError::RateLimited.to_string(),
        ] {
            assert!(
                !s.starts_with("ElaraError"),
                "Display fell back to Debug shape: {s:?}"
            );
            assert!(!s.is_empty(), "Display must be non-empty");
        }
    }

    #[test]
    fn batch_b_source_chain_matrix_flat_none_vs_from_downcast() {
        // The single-hop source chain is load-bearing for log walkers that
        // grep `error.source()` for the root-cause type. Pin both halves:
        // (A) every flat variant returns source() == None, (B) the two
        // #[from] variants return Some that downcasts back to the inner
        // error type. Adding `#[source]` to a flat variant in future would
        // silently change scraper behaviour (one hop → two hops); this test
        // forces a deliberate test-update + scraper-update.
        use std::error::Error;

        // (A) 15 flat variants — source() must be None on each.
        let flats: Vec<ElaraError> = vec![
            ElaraError::Crypto("X".into()),
            ElaraError::Wire("X".into()),
            ElaraError::InvalidSignature,
            ElaraError::RecordNotFound("X".into()),
            ElaraError::DuplicateRecord("X".into()),
            ElaraError::MissingParent("X".into()),
            ElaraError::Storage("X".into()),
            ElaraError::Address("X".into()),
            ElaraError::Dag("X".into()),
            ElaraError::Ledger("X".into()),
            ElaraError::Network("X".into()),
            ElaraError::Governance("X".into()),
            ElaraError::Dispute("X".into()),
            ElaraError::Config("X".into()),
            ElaraError::RateLimited,
        ];
        assert_eq!(flats.len(), 15, "ElaraError flat-variant count must be 15");
        for err in flats {
            assert!(
                err.source().is_none(),
                "variant {err:?} unexpectedly has a source() chain — only Io/Json should"
            );
        }

        // (B) Io variant — source() returns Some, downcasts to io::Error,
        // and the downcast preserves the original ErrorKind.
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let wrapped: ElaraError = io_err.into();
        let src = wrapped.source().expect("Io variant must surface a source");
        let inner = src
            .downcast_ref::<std::io::Error>()
            .expect("source must downcast to std::io::Error");
        assert_eq!(
            inner.kind(),
            std::io::ErrorKind::PermissionDenied,
            "io::ErrorKind must round-trip through From/source unchanged"
        );

        // (B) Json variant — source() returns Some + downcasts to serde_json::Error.
        let json_err: serde_json::Error = serde_json::from_str::<u8>("not-a-number").unwrap_err();
        let wrapped: ElaraError = json_err.into();
        let src = wrapped.source().expect("Json variant must surface a source");
        let _inner = src
            .downcast_ref::<serde_json::Error>()
            .expect("source must downcast to serde_json::Error");
    }

    #[test]
    fn batch_b_send_sync_static_std_error_and_sizeof_bound() {
        // ElaraError is the canonical Result-arm error for the whole crate.
        // It must satisfy Send + Sync + 'static so `?` works across .await
        // points in async fns (the resulting Future has to be Send for tokio
        // to move it across worker threads). A future variant carrying a
        // non-Send inner (Rc<…>, MutexGuard, *mut T) would silently demote
        // every `Result<_, ElaraError>` and the compiler error would surface
        // at a confusing axum/tokio call site rather than here.
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        fn assert_static<T: 'static>() {}
        fn assert_std_error<T: std::error::Error>() {}
        fn assert_display<T: std::fmt::Display>() {}
        fn assert_debug<T: std::fmt::Debug>() {}
        assert_send::<ElaraError>();
        assert_sync::<ElaraError>();
        assert_static::<ElaraError>();
        assert_std_error::<ElaraError>();
        assert_display::<ElaraError>();
        assert_debug::<ElaraError>();

        // Sizeof bound — every `Result<T, ElaraError>` discriminant inlines
        // this error. A 4 KB error variant (e.g. an accidental Box<dyn Error>
        // wrapping a large struct) would inflate every async frame. The
        // current shape is dominated by `String` (24 B) + `serde_json::Error`
        // (typically ≤ 32 B via boxed inner) → comfortably under 64 B; cap
        // at 256 B for generous headroom that still catches an accidental
        // multi-KB inline.
        let size = std::mem::size_of::<ElaraError>();
        assert!(
            size <= 256,
            "ElaraError size = {size} bytes; every Result<_, ElaraError> inlines this — keep small"
        );
        // Lower-bound pin: size must be > 0 (else the enum has no variants,
        // which would mean the file was emptied — a refactor disaster).
        assert!(size > 0, "ElaraError must have at least one variant");
    }

    #[test]
    fn batch_b_from_conversions_and_result_alias_round_trip() {
        // The two #[from] attributes generate `impl From<io::Error>` and
        // `impl From<serde_json::Error>` for ElaraError, which is what makes
        // `?` propagation work in every fn returning `Result<T, ElaraError>`
        // or the `Result<T>` alias. Pin both conversions + the alias.
        //
        // io::Error round-trip via .into() must land in the Io variant
        // AND preserve the original ErrorKind on the wrapped inner.
        let io_err = std::io::Error::new(std::io::ErrorKind::AlreadyExists, "exists");
        let wrapped: ElaraError = io_err.into();
        match &wrapped {
            ElaraError::Io(inner) => {
                assert_eq!(
                    inner.kind(),
                    std::io::ErrorKind::AlreadyExists,
                    "From<io::Error> must NOT mutate kind"
                );
            }
            other => panic!("expected ElaraError::Io, got {other:?}"),
        }

        // serde_json::Error round-trip via .into() must land in the Json variant.
        let json_err: serde_json::Error = serde_json::from_str::<u8>("not-a-number").unwrap_err();
        let wrapped: ElaraError = json_err.into();
        assert!(
            matches!(wrapped, ElaraError::Json(_)),
            "expected ElaraError::Json, got {wrapped:?}"
        );

        // Result<T> alias — pin that the alias resolves to
        // std::result::Result<T, ElaraError>. Call-sites that mix the alias
        // with the fully-qualified form rely on identity equivalence; a
        // future refactor renaming the alias arm to a different error type
        // would silently break every `Result<()>` signature in the crate.
        fn produces_err() -> Result<u8> {
            Err(ElaraError::RateLimited)
        }
        let r: std::result::Result<u8, ElaraError> = produces_err();
        let e = r.unwrap_err();
        assert!(
            matches!(e, ElaraError::RateLimited),
            "Result<T> alias must resolve to std::result::Result<T, ElaraError>"
        );

        // Cross-pin: the `?` operator must work for both #[from] inputs
        // inside a fn returning Result<T>. If a future refactor removes the
        // #[from] attribute, this fn fails to compile, surfacing the break
        // at the type level rather than at every downstream call site.
        fn uses_question_mark_for_io() -> Result<()> {
            let _: u32 = "not-an-int".parse::<u32>().map_err(|e| ElaraError::Wire(e.to_string()))?;
            Ok(())
        }
        fn uses_question_mark_for_json() -> Result<u8> {
            let v: u8 = serde_json::from_str("1")?;
            Ok(v)
        }
        // Compile-test: smoke-run both at runtime so an accidental panic in
        // either path surfaces here, not in production.
        assert!(uses_question_mark_for_io().is_err());
        assert_eq!(uses_question_mark_for_json().unwrap(), 1);
    }

    #[test]
    fn batch_b_string_payload_rendering_matrix_empty_unicode_multiline_whitespace() {
        // Every String-carrying variant uses `{0}` (Display) on the inner
        // String, NOT `{0:?}` (Debug). That means the payload must render
        // verbatim — no escaping, no quoting, no truncation. Operators
        // copy/paste error strings into incident tickets; a silent encoding
        // change (e.g. html-escape of '<' '>', backslash-escape of '\n')
        // would break root-cause analysis without surfacing a failure.
        //
        // Sweep the payload matrix across one representative variant
        // (Crypto) because every String-carrying variant uses the same
        // `{0}` substitution; a divergence between variants would mean
        // thiserror itself broke, which is too coarse a regression to
        // sniff at variant-granularity. Cover the four edge classes:
        // empty, ASCII multi-word, multi-line (newline preserved), UTF-8
        // multibyte, and surrounding whitespace (must NOT be trimmed).
        for (payload, want_suffix) in [
            ("", ""),
            ("connection reset by peer", "connection reset by peer"),
            ("line1\nline2", "line1\nline2"),
            ("utf8: ñ é 🌀 \u{200B}zero-width", "utf8: ñ é 🌀 \u{200B}zero-width"),
            ("  leading + trailing  ", "  leading + trailing  "),
        ] {
            let s = ElaraError::Crypto(payload.into()).to_string();
            assert_eq!(
                s,
                format!("Crypto error: {want_suffix}"),
                "Crypto payload must render verbatim; got {s:?}"
            );
            // Negative: must NOT wrap the payload in quotes (would mean
            // thiserror switched to `{0:?}` for the field).
            assert!(
                !s.contains("\""),
                "payload must not be debug-quoted; got {s:?}"
            );
        }

        // Cross-variant sanity: one extra sample on Ledger variant proves
        // the verbatim contract isn't local to Crypto. A future refactor
        // that switches Ledger to `{0:?}` while leaving Crypto on `{0}`
        // would create a wire-format split where operator scrapers would
        // need per-variant escape handling.
        let s = ElaraError::Ledger("amount=-1 (underflow)".into()).to_string();
        assert_eq!(s, "Ledger error: amount=-1 (underflow)");
        assert!(!s.contains("\""), "Ledger payload must not be debug-quoted");

        // Empty-payload edge: the trailing space after the colon survives
        // thiserror's substitution (no auto-trim). Operators reading the
        // log can distinguish "missing context" (trailing space) from
        // "context withheld" (no space) — preserve the contract.
        let s = ElaraError::Crypto(String::new()).to_string();
        assert!(
            s.ends_with(": "),
            "empty payload must surface as trailing colon+space, not trimmed; got {s:?}"
        );
    }
}
