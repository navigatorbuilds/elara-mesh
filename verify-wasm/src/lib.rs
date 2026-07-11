//! Elara — the HEADLINE offline record verifier, compiled to WASM as a
//! **verify-only** module.
//!
//! Paste a `ValidationRecord` JSON into a web page and get the SAME tri-state
//! verdict the `elara-verify` CLI produces — structure, identity binding, and
//! the Dilithium3 (ML-DSA-65) signature over the canonical record bytes — with
//! **zero network and zero trust in any server**.
//!
//! Since extraction Step 4c this crate is a thin cdylib wrapper: every export
//! (`verify_record_offline`, `verify_receipt_offline`,
//! `evaluate_mandate_bundle`) is defined in [`elara_verify::wasm_api`] — the
//! permissively-licensed verifier crate — and re-exported here verbatim, so
//! the artifact wasm-pack ships is that code with no wrapper logic on top and
//! the browser verdict can never drift from the CLI verdict (both call the
//! same library).
//!
//! ## Why a separate crate (not the `browser-node` wallet build)
//! `browser-node` is the full web wallet: it links secret-key handling,
//! `sign_transfer`/`sign_stake`/…, the PQ-handshake transport, and a QR codec.
//! A public "verify it yourself" widget should carry the **minimum** trusted
//! surface. This crate's dependency graph contains no wallet, no signing, no
//! secret-key type, no network transport — and since Step 4c no AGPL node
//! code at all: it links only `elara-verify` + `elara-record` (MIT/Apache).
//! Those code paths are not merely feature-gated off, they are *absent*. The
//! result is a small wasm whose only capability is producing an honest verdict.
//!
//! ## Honest-claims contract (mirrors `elara_verify::Status`)
//! `✓` is printed ONLY for a cryptographically proven Pass; an absent/pending
//! bound is `⚠ PARTIAL`, never a false green; a forged/tampered/inconsistent
//! record is `✗ FAILED`. It refuses to lie even for itself.

pub use elara_verify::wasm_api::*;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    //! Native-target tests exercise the inner verify paths directly (the
    //! wasm-bindgen JsValue wiring is validated when the crate compiles to
    //! wasm32). A garbage input must FAIL CLOSED, never read as a green.
    //! Fixtures sign live records with node-side `Identity` — that's why
    //! `elara-runtime` is a DEV-dependency only: it never links into the
    //! shipped wasm artifact.
    use super::verify_receipt_inner;
    use elara_runtime::crypto::pqc::dilithium3_sign_with_pk;
    use elara_runtime::identity::{CryptoProfile, EntityType, Identity};
    use elara_runtime::record::{Classification, ValidationRecord};
    use elara_runtime::verify_core::{verify_record, Status, Verdict};

    #[test]
    fn empty_json_object_fails_to_parse_as_record() {
        // A bare `{}` is not a ValidationRecord — the wrapper's parse arm must
        // reject it (the export then returns verdict FAILED).
        let parsed: Result<ValidationRecord, _> = serde_json::from_str("{}");
        assert!(parsed.is_err());
    }

    #[test]
    fn empty_check_set_fails_closed() {
        // The load-bearing invariant: an empty check set is FAILED, never a
        // false green. (Full signed-record round-trips live in the runtime's
        // verify_core / elara_verify tests — the shared, drift-proof logic.)
        let checks: Vec<elara_runtime::verify_core::Check> = Vec::new();
        assert_eq!(Verdict::of(&checks), Verdict::Failed);
        let _ = (Status::Pass, verify_record); // keep imports referenced
    }

    // ── `.elara-receipt` v1 through the wasm shell (CLI-parity) ─────────────

    fn signed_record(content: &[u8]) -> (ValidationRecord, Identity) {
        let id = Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
            .expect("generate identity");
        let mut rec = ValidationRecord::create(
            content,
            id.public_key.clone(),
            vec![],
            Classification::Public,
            None,
        );
        rec.signature = Some(
            dilithium3_sign_with_pk(&rec.signable_bytes(), &id.secret_key_bytes(), &id.public_key)
                .expect("sign"),
        );
        (rec, id)
    }

    /// A signed seal-shaped record; returns (wire, anchor pubkey hex, own
    /// record-hash hex) — the pins a caller supplies from a trusted source.
    fn seal_fixture() -> (Vec<u8>, String, String) {
        let (seal, id) = signed_record(b"epoch seal");
        let hash_hex = hex::encode(seal.record_hash());
        (seal.to_bytes(), hex::encode(&id.public_key), hash_hex)
    }

    #[test]
    fn receipt_v1_record_plus_seal_grades_with_pins() {
        let (rec, _) = signed_record(b"receipt evidence");
        let (seal_wire, anchor_hex, seal_hash_hex) = seal_fixture();
        let envelope = serde_json::json!({
            "receipt_version": elara_runtime::receipt::RECEIPT_VERSION,
            "producer": { "node": "wasm-test-fixture" },
            "legs": {
                "record": hex::encode(rec.to_bytes()),
                "seal": hex::encode(&seal_wire),
            },
        })
        .to_string();
        let pins = serde_json::json!({
            "trusted_anchor": [anchor_hex],
            "expected_hash": seal_hash_hex,
        })
        .to_string();
        let r = verify_receipt_inner(&envelope, &pins);
        assert_eq!(r.reason, "ok");
        // Record legs and seal legs all graded through the shared core.
        assert!(r.checks.iter().any(|c| c.name == "signature" && c.status == "pass"));
        assert!(r.checks.iter().any(|c| c.name.contains("seal") && c.status == "pass"));
        // Producer is surfaced (display-only, never graded).
        assert!(r.producer.is_some());
    }

    #[test]
    fn receipt_v1_seal_without_pin_caps_partial_never_green() {
        // Trust-root inversion (audit invariant #1): a receipt can never vouch
        // for its own trust root — a pin-less seal grades PARTIAL, not green.
        let (seal_wire, _, _) = seal_fixture();
        let envelope = serde_json::json!({
            "receipt_version": elara_runtime::receipt::RECEIPT_VERSION,
            "legs": { "seal": hex::encode(&seal_wire) },
        })
        .to_string();
        let r = verify_receipt_inner(&envelope, "");
        assert_eq!(r.reason, "ok");
        assert_eq!(r.verdict, "PARTIAL");
        assert!(r
            .checks
            .iter()
            .any(|c| c.name == "seal anchor" && c.status == "partial"));
        // The gates-driven headline leads with the honest-gap framing.
        assert!(r.headline.starts_with("⚠ PARTIAL"), "got: {}", r.headline);
    }

    #[test]
    fn unknown_pin_key_refuses_strictly() {
        // Pins are trust-affecting: a typo'd key must refuse, never no-op.
        let r = verify_receipt_inner("{}", r#"{"trusted_anchors": ["ab"]}"#);
        assert_eq!(r.verdict, "FAILED");
        assert!(r.reason.contains("pins_json"), "got: {}", r.reason);
        assert!(r.checks.is_empty());
    }

    #[test]
    fn garbage_receipt_fails_closed() {
        let r = verify_receipt_inner("not a receipt at all", "");
        assert_eq!(r.verdict, "FAILED");
        assert_ne!(r.reason, "ok");
        assert!(r.checks.is_empty());
    }

    #[test]
    fn bare_record_json_degenerate_grades_like_record_export() {
        // The pre-v1 published convention: a bare record JSON is accepted as a
        // degenerate receipt, exactly like the CLI's --receipt arm.
        let (rec, _) = signed_record(b"bare record");
        let r = verify_receipt_inner(&serde_json::to_string(&rec).expect("json"), "");
        assert_eq!(r.reason, "ok");
        assert_eq!(r.verdict, "VERIFIED");
        assert!(r.checks.iter().any(|c| c.name == "signature" && c.status == "pass"));
        // Record-only headline claims record-integrity scope, never a chain.
        assert!(
            r.headline.contains("record's own integrity"),
            "got: {}",
            r.headline
        );
        assert!(!r.headline.contains("FULL chain"), "got: {}", r.headline);
    }

    #[test]
    fn unknown_leg_kind_disclosed_and_caps_partial() {
        // Open-legs posture: unknown leg kinds don't hard-fail the parse, but
        // the verdict is CAPPED at PARTIAL with disclosure — never
        // VERIFIED-with-skips (EV-1).
        let (rec, _) = signed_record(b"receipt evidence");
        let envelope = serde_json::json!({
            "receipt_version": elara_runtime::receipt::RECEIPT_VERSION,
            "legs": {
                "record": hex::encode(rec.to_bytes()),
                "frobnicate": { "x": 1 },
            },
        })
        .to_string();
        let r = verify_receipt_inner(&envelope, "");
        assert_eq!(r.reason, "ok");
        assert_eq!(r.verdict, "PARTIAL");
        assert_eq!(r.not_evaluated, vec!["frobnicate".to_string()]);
        assert!(r
            .checks
            .iter()
            .any(|c| c.name == "receipt coverage" && c.status == "partial"));
    }
}
