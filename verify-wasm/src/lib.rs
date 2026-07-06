//! Elara — the HEADLINE offline record verifier, compiled to WASM as a
//! **verify-only** module.
//!
//! Paste a `ValidationRecord` JSON into a web page and get the SAME tri-state
//! verdict the `elara-verify` CLI produces — structure, identity binding, and
//! the Dilithium3 (ML-DSA-65) signature over the canonical record bytes — with
//! **zero network and zero trust in any server**. The verification LOGIC is the
//! shared, node-free `elara_runtime::verify_core` (the exact code path the CLI
//! binary calls), so the browser verdict can never drift from the CLI verdict.
//!
//! ## Why a separate crate (not the `browser-node` wallet build)
//! `browser-node` is the full web wallet: it links secret-key handling,
//! `sign_transfer`/`sign_stake`/…, the PQ-handshake transport, and a QR codec.
//! A public "verify it yourself" widget should carry the **minimum** trusted
//! surface. This crate's dependency graph contains no wallet, no signing, no
//! secret-key type, and no network transport — those code paths are not merely
//! feature-gated off, they are *absent*. The result is a much smaller wasm whose
//! only capability is producing an honest verdict over a pasted record.
//!
//! ## Honest-claims contract (mirrors `verify_core::Status`)
//! `✓` is printed ONLY for a cryptographically proven Pass; an absent/pending
//! bound is `⚠ PARTIAL`, never a false green; a forged/tampered/inconsistent
//! record is `✗ FAILED`. It refuses to lie even for itself.
//!
//! ## Scope — full-chain parity via receipts (flagship audit 2026-07-06 step 4)
//! [`verify_record_offline`] grades a record's own integrity.
//! [`verify_receipt_offline`] grades a `.elara-receipt` v1 envelope — record,
//! epoch-seal, inclusion proof, account inclusion/exclusion, epoch-anchor with
//! the drand-BLS not-before leg — through the SAME
//! `verify_core::grade::{grade_receipt_v1, bind_outcomes}` sequence the
//! `elara-verify --receipt` CLI runs, so the browser verdict and the CLI
//! verdict cannot drift. Trust pins stay CALLER-side (a receipt can never
//! vouch for itself); the OTS existed-by leg stays an honest PARTIAL in a
//! receipt (`.ots` sidecars don't ride in envelopes — the CLI grades those).

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use elara_runtime::receipt::{parse_receipt_input, ReceiptInput};
use elara_runtime::record::ValidationRecord;
use elara_runtime::verify_core::grade::{
    bind_outcomes, grade_receipt_v1, record_leg, LegOutcomes, TrustPins,
};
use elara_runtime::verify_core::{verdict_headline, Check, Verdict};

#[derive(Serialize)]
struct CheckJs {
    /// Stable check name (e.g. "structure", "identity binding", "signature").
    name: &'static str,
    /// Machine-readable outcome — branch on this, not on `detail`.
    /// `"pass"` | `"partial"` | `"fail"`.
    status: &'static str,
    /// UI glyph — `✓` | `⚠` | `✗`. Never `✓` for anything short of a proven pass.
    glyph: &'static str,
    /// Human-readable detail line.
    detail: String,
}

#[derive(Serialize)]
struct VerifyRecordResult {
    /// `"VERIFIED"` | `"PARTIAL"` | `"FAILED"`. FAIL dominates PARTIAL dominates
    /// VERIFIED (a tampered bound is never softened by a proven one); an empty
    /// check set fails closed.
    verdict: &'static str,
    /// Overall glyph for the verdict.
    glyph: &'static str,
    /// The gates-driven one-line headline (`verify_core::verdict_headline`) —
    /// the SAME sentence the CLI leads with; never stronger than the gates.
    headline: String,
    /// Per-check breakdown, in the order `verify_core` produced them.
    checks: Vec<CheckJs>,
    /// `"ok"` on parse success; otherwise the parse-error reason (with `verdict`
    /// = `"FAILED"` and `checks` empty). The verifier never throws.
    reason: String,
}

fn to_js<T: Serialize>(v: &T) -> JsValue {
    serde_wasm_bindgen::to_value(v).unwrap_or(JsValue::NULL)
}

fn verdict_glyph(v: Verdict) -> &'static str {
    match v {
        Verdict::Verified => "✓",
        Verdict::Partial => "⚠",
        Verdict::Failed => "✗",
    }
}

/// Verify a pasted `ValidationRecord` JSON entirely offline.
///
/// Mirrors the record leg of `elara-verify <record.json>`: structure parse,
/// identity binding (the embedded public key must SHA3-256 to the claimed
/// identity), and the Dilithium3 (ML-DSA-65) signature over the record's
/// canonical `signable_bytes()`.
///
/// Returns a JS object
/// `{verdict, glyph, checks: [{name, status, glyph, detail}], reason}`.
/// Never throws — a malformed input surfaces as `verdict: "FAILED"` with the
/// parse reason, not an exception. (Identical export name + shape to the one in
/// `browser-node`; both are thin shells over the shared `verify_core`, so the
/// demo can switch between them without a UI change.)
#[wasm_bindgen]
pub fn verify_record_offline(record_json: &str) -> JsValue {
    let record: ValidationRecord = match serde_json::from_str(record_json) {
        Ok(r) => r,
        Err(e) => {
            return to_js(&VerifyRecordResult {
                verdict: "FAILED",
                glyph: "✗",
                headline: "✗ FAILED — nothing was verifiable in the supplied input.".to_string(),
                checks: Vec::new(),
                reason: format!("record_json: parse error: {e}"),
            });
        }
    };

    let mut checks: Vec<Check> = Vec::new();
    // The SAME shared record leg the CLI runs (checks + summary in one call).
    let (summary, _record_hash) = record_leg(&record, None, &mut checks);
    let verdict = Verdict::of(&checks);

    let checks_js: Vec<CheckJs> = checks
        .iter()
        .map(|c| CheckJs {
            name: c.name,
            status: c.status.as_str(),
            glyph: c.status.glyph(),
            detail: c.detail.clone(),
        })
        .collect();

    // Record-only run: no anchor/account/absence facts exist on this path, so
    // the headline's strongest possible claim is the record-integrity scope.
    let headline = verdict_headline(verdict, &checks, Some(&summary), None, None, None);
    to_js(&VerifyRecordResult {
        verdict: verdict.label(),
        glyph: verdict_glyph(verdict),
        headline,
        checks: checks_js,
        reason: "ok".to_string(),
    })
}

/// Verifier-side trust pins for [`verify_receipt_offline`] — the browser
/// equivalent of the CLI's `--trusted-anchor`/`--expected-hash`/`--expect-root`/
/// `--expect-identity` flags. STRICT parse (`deny_unknown_fields`): a typo'd
/// pin key must refuse, never silently no-op — pins are trust-affecting.
/// All fields optional; their absence grades PARTIAL exactly as in the CLI.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
struct PinsJs {
    /// Anchor pubkey-hex list the seal must verify against (from a source YOU
    /// trust — never from the receipt).
    trusted_anchor: Vec<String>,
    /// The seal's own record-hash, from a source you trust.
    expected_hash: Option<String>,
    /// A sealed root (record-Merkle or account-SMT) pin.
    expect_root: Option<String>,
    /// The identity an account proof must be about.
    expect_identity: Option<String>,
}

#[derive(Serialize)]
struct VerifyReceiptResult {
    /// `"VERIFIED"` | `"PARTIAL"` | `"FAILED"` — FAIL dominates PARTIAL
    /// dominates VERIFIED; an empty check set fails closed.
    verdict: &'static str,
    glyph: &'static str,
    /// The gates-driven one-line headline (`verify_core::verdict_headline`) —
    /// the SAME sentence the CLI leads with; never stronger than the gates.
    headline: String,
    checks: Vec<CheckJs>,
    /// `"ok"` on a graded run; otherwise the input-error reason (with
    /// `verdict: "FAILED"` and `checks` empty — the CLI's exit-2 analog).
    /// The verifier never throws.
    reason: String,
    /// Self-declared by whoever wrote the receipt — display with a provenance
    /// caveat; NOT verified by any check, never graded, never trusted.
    producer: Option<serde_json::Value>,
    /// Leg kinds this verifier disclosed-but-skipped (already reflected as a
    /// PARTIAL cap by the `receipt coverage` check).
    not_evaluated: Vec<String>,
}

fn receipt_input_error(reason: String) -> VerifyReceiptResult {
    VerifyReceiptResult {
        verdict: "FAILED",
        glyph: "✗",
        headline: "✗ FAILED — nothing was verifiable in the supplied input.".to_string(),
        checks: Vec::new(),
        reason,
        producer: None,
        not_evaluated: Vec::new(),
    }
}

/// The full receipt run behind [`verify_receipt_offline`], kept off
/// `wasm_bindgen` so native-target tests can exercise it end-to-end (JsValue
/// only exists on wasm32). EXACTLY the CLI `--receipt` sequence: envelope
/// parse (caps before crypto) → `grade_receipt_v1` → `bind_outcomes` →
/// `Verdict::of` — all shared `verify_core::grade` code, zero drift.
fn verify_receipt_inner(receipt_json: &str, pins_json: &str) -> VerifyReceiptResult {
    let pins_js: PinsJs = if pins_json.trim().is_empty() {
        PinsJs::default()
    } else {
        match serde_json::from_str(pins_json) {
            Ok(p) => p,
            Err(e) => return receipt_input_error(format!("pins_json: parse error: {e}")),
        }
    };

    let mut checks: Vec<Check> = Vec::new();
    let mut producer: Option<serde_json::Value> = None;
    let mut not_evaluated: Vec<String> = Vec::new();

    let out: LegOutcomes = match parse_receipt_input(receipt_json.as_bytes()) {
        Err(reason) => return receipt_input_error(reason),
        // The pre-v1 published convention — a bare record (wire bytes or
        // record JSON) grades exactly like `elara-verify <record>`, same as
        // the CLI's --receipt degenerate arm.
        Ok(ReceiptInput::BareRecord(raw)) => {
            let record: ValidationRecord = if raw.starts_with(b"ELRA") {
                match ValidationRecord::from_bytes(&raw) {
                    Ok(r) => r,
                    Err(e) => {
                        return receipt_input_error(format!(
                            "receipt is neither a v1 envelope nor a valid wire record: {e}"
                        ))
                    }
                }
            } else {
                match serde_json::from_slice(&raw) {
                    Ok(r) => r,
                    Err(e) => {
                        return receipt_input_error(format!(
                            "receipt is neither a v1 envelope nor a valid record JSON: {e}"
                        ))
                    }
                }
            };
            let mut out = LegOutcomes::default();
            let (summary, hash) = record_leg(&record, None, &mut checks);
            out.record_summary = Some(summary);
            out.record_hash = Some(hash);
            out
        }
        Ok(ReceiptInput::V1(legs)) => {
            let pins = TrustPins {
                trusted_anchor: &pins_js.trusted_anchor,
                expected_hash: pins_js.expected_hash.as_deref(),
                expect_root: pins_js.expect_root.as_deref(),
                expect_identity: pins_js.expect_identity.as_deref(),
                // No --content twin in the browser shell: without the original
                // artifact bytes the record's content check simply doesn't run,
                // exactly like the CLI without --content.
                content: None,
            };
            producer = legs.producer.clone();
            not_evaluated = legs.not_evaluated.clone();
            match grade_receipt_v1(&legs, &pins, &mut checks) {
                Ok(out) => out,
                Err(reason) => return receipt_input_error(reason),
            }
        }
    };

    if let Err(reason) = bind_outcomes(&mut checks, &out, pins_js.expect_root.as_deref()) {
        return receipt_input_error(reason);
    }

    let verdict = Verdict::of(&checks);
    let headline = verdict_headline(
        verdict,
        &checks,
        out.record_summary.as_ref(),
        out.anchor_summary.as_ref(),
        out.account_facts.as_ref(),
        out.absence_facts.as_ref(),
    );
    VerifyReceiptResult {
        verdict: verdict.label(),
        glyph: verdict_glyph(verdict),
        headline,
        checks: checks
            .iter()
            .map(|c| CheckJs {
                name: c.name,
                status: c.status.as_str(),
                glyph: c.status.glyph(),
                detail: c.detail.clone(),
            })
            .collect(),
        reason: "ok".to_string(),
        producer,
        not_evaluated,
    }
}

/// Verify a `.elara-receipt` v1 envelope entirely offline — the FULL chain
/// (record → inclusion proof → epoch seal → anchor, plus account
/// inclusion/exclusion legs) in one pasted file, graded through the SAME
/// shared `verify_core::grade` sequence as `elara-verify --receipt`, so the
/// browser verdict can never drift from the CLI verdict.
///
/// `receipt_json` is the envelope text (a bare record is accepted as the
/// degenerate case, exactly like the CLI). `pins_json` carries the
/// verifier-side trust pins `{"trusted_anchor": ["<pubkey-hex>", …],
/// "expected_hash": "…", "expect_root": "…", "expect_identity": "…"}` — all
/// optional (pass `""` or `"{}"` for none), STRICTLY parsed (an unknown key
/// refuses — pins are trust-affecting), and NEVER read from the receipt
/// itself: a receipt cannot vouch for its own trust root, so pin-less runs
/// grade PARTIAL, never a false green.
///
/// Returns `{verdict, glyph, checks[], reason, producer, not_evaluated[]}`.
/// Never throws — malformed input surfaces as `verdict: "FAILED"` with the
/// reason (the CLI's exit-2 analog). `producer` is self-declared metadata:
/// display it with a provenance caveat; no check vouches for it.
#[wasm_bindgen]
pub fn verify_receipt_offline(receipt_json: &str, pins_json: &str) -> JsValue {
    to_js(&verify_receipt_inner(receipt_json, pins_json))
}

/// Verify a mandate **bundle** entirely offline — the accountability/authority-
/// to-act differentiator (who/which-AI-agent was *authorized* to do what, by
/// whom, valid at signing — or revoked) that OpenTimestamps and a bare PQ
/// signature structurally cannot express.
///
/// Input is a JSON envelope `{bundle_version, act, mandates[], revocations[]}`
/// of SIGNED carrier records (see `examples/verify/sample-mandate-bundles.json`).
/// This is a thin shell over the shared, drift-proof
/// [`elara_runtime::mandate_bundle::evaluate_mandate_bundle`] — the SAME pure
/// verdict core the live node's `GET /mandate/status` calls — so the browser
/// verdict can never diverge from the node verdict.
///
/// Returns a JS object (see `BundleVerdict`): `{verdict, glyph, flag,
/// authorized, attributes_to_principal, network, signer, principal,
/// act_timestamp_ms, explanation, lineage[], scope_note, soundness_caveats[],
/// checks[], reason}`. Never throws — malformed input is `verdict: "FAILED"`.
///
/// HONEST SCOPE: a `✓ CONSISTENT` verdict proves signatures + that authority
/// held at the act's signed time GIVEN THE RECORDS IN THIS BUNDLE. It does NOT
/// prove the records are on-chain / sealed / time-anchored, and cannot detect a
/// revocation the bundle author withheld — hence the verdict is `CONSISTENT`,
/// never the node-only `AUTHORIZED`, and `soundness_caveats` always ship.
#[wasm_bindgen]
pub fn evaluate_mandate_bundle(bundle_json: &str) -> JsValue {
    to_js(&elara_runtime::mandate_bundle::evaluate_mandate_bundle(bundle_json))
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    //! Native-target tests exercise the inner verify paths directly (the
    //! wasm-bindgen JsValue wiring is validated when the crate compiles to
    //! wasm32). A garbage input must FAIL CLOSED, never read as a green.
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
