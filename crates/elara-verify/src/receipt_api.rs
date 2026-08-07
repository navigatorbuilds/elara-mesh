//! The native receipt-verdict entry point — `verify_receipt_inner` and its
//! result shapes, ALWAYS compiled (no `wasm` feature required).
//!
//! Moved out of `wasm_api` (T59, 2026-07-29): the function is wasm-free by
//! construction (it exists precisely so native-target tests can exercise the
//! full receipt sequence — JsValue only exists on wasm32), yet it sat behind
//! `#[cfg(feature = "wasm")]`, making the native entry point unreachable
//! without pulling wasm-bindgen. Pure move, zero logic change; `wasm_api`
//! re-exports everything here so every pre-T59 import path still works.

use serde::{Deserialize, Serialize};

use elara_record::receipt::{parse_receipt_input, ReceiptInput};
use elara_record::record::ValidationRecord;

use crate::grade::{bind_outcomes, grade_receipt_v1, record_leg, LegOutcomes, TrustPins};
use crate::{verdict_headline, Check, Verdict};

/// One check row of a verify result — the JS-facing mirror of [`crate::Check`].
#[derive(Serialize)]
pub struct CheckJs {
    /// Stable check name (e.g. "structure", "identity binding", "signature").
    pub name: &'static str,
    /// Machine-readable outcome — branch on this, not on `detail`.
    /// `"pass"` | `"partial"` | `"fail"`.
    pub status: &'static str,
    /// UI glyph — `✓` | `⚠` | `✗`. Never `✓` for anything short of a proven pass.
    pub glyph: &'static str,
    /// Human-readable detail line.
    pub detail: String,
}

pub(crate) fn verdict_glyph(v: Verdict) -> &'static str {
    match v {
        Verdict::Verified => "✓",
        Verdict::Partial => "⚠",
        Verdict::Failed => "✗",
    }
}

/// Verifier-side trust pins for the receipt run — the browser/native
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

/// Result shape of `verify_receipt_offline` / [`verify_receipt_inner`].
#[derive(Serialize)]
pub struct VerifyReceiptResult {
    /// `"VERIFIED"` | `"PARTIAL"` | `"FAILED"` — FAIL dominates PARTIAL
    /// dominates VERIFIED; an empty check set fails closed.
    pub verdict: &'static str,
    pub glyph: &'static str,
    /// The gates-driven one-line headline ([`crate::verdict_headline`]) —
    /// the SAME sentence the CLI leads with; never stronger than the gates.
    pub headline: String,
    pub checks: Vec<CheckJs>,
    /// `"ok"` on a graded run; otherwise the input-error reason (with
    /// `verdict: "FAILED"` and `checks` empty — the CLI's exit-2 analog).
    /// The verifier never throws.
    pub reason: String,
    /// Self-declared by whoever wrote the receipt — display with a provenance
    /// caveat; NOT verified by any check, never graded, never trusted.
    pub producer: Option<serde_json::Value>,
    /// Leg kinds this verifier disclosed-but-skipped (already reflected as a
    /// PARTIAL cap by the `receipt coverage` check).
    pub not_evaluated: Vec<String>,
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

/// The full receipt run behind `verify_receipt_offline`, kept off
/// `wasm_bindgen` so native-target tests (in the `verify-wasm` wrapper crate,
/// which signs fixtures with node-side keys) can exercise it end-to-end
/// (JsValue only exists on wasm32). EXACTLY the CLI `--receipt` sequence:
/// envelope parse (caps before crypto) → `grade_receipt_v1` → `bind_outcomes`
/// → `Verdict::of` — all shared [`crate::grade`] code, zero drift.
pub fn verify_receipt_inner(receipt_json: &str, pins_json: &str) -> VerifyReceiptResult {
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
