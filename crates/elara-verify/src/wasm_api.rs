//! The browser/wasm verify entry points — the `#[wasm_bindgen]` exports behind
//! the public "verify it yourself" demo page, moved here (extraction Step 4c)
//! so the wasm verifier is built from this permissively-licensed crate alone.
//!
//! The `verify-wasm` cdylib crate in the node repo is a thin re-export of this
//! module (`pub use elara_verify::wasm_api::*;`) — wasm-bindgen's export glue
//! is generated here and links through to the final `.wasm`, so the artifact
//! wasm-pack ships is THIS code with no wrapper logic on top.
//!
//! ## Honest-claims contract (mirrors [`crate::Status`])
//! `✓` is printed ONLY for a cryptographically proven Pass; an absent/pending
//! bound is `⚠ PARTIAL`, never a false green; a forged/tampered/inconsistent
//! record is `✗ FAILED`. It refuses to lie even for itself.
//!
//! ## Scope — full-chain parity via receipts (flagship audit 2026-07-06 step 4)
//! [`verify_record_offline`] grades a record's own integrity.
//! [`verify_receipt_offline`] grades a `.elara-receipt` v1 envelope — record,
//! epoch-seal, inclusion proof, account inclusion/exclusion, epoch-anchor with
//! the drand-BLS not-before leg — through the SAME
//! [`crate::grade::grade_receipt_v1`] + [`crate::grade::bind_outcomes`]
//! sequence the `elara-verify --receipt` CLI runs, so the browser verdict and
//! the CLI verdict cannot drift. Trust pins stay CALLER-side (a receipt can
//! never vouch for itself); the OTS existed-by leg stays an honest PARTIAL in
//! a receipt (`.ots` sidecars don't ride in envelopes — the CLI grades those).
//!
//! [`evaluate_mandate_bundle`] is the offline authority-to-act verdict over a
//! bundle of SIGNED carrier records — a thin shell over
//! [`crate::mandate_bundle::evaluate_mandate_bundle`], the same pure core the
//! live node's `GET /mandate/status` calls.

use serde::Serialize;
use wasm_bindgen::prelude::*;

use elara_record::record::ValidationRecord;

use crate::grade::record_leg;
use crate::{verdict_headline, Check, Verdict};

// The receipt entry point + shared result shapes moved to the ALWAYS-compiled
// `receipt_api` module (T59) — re-exported here verbatim so every pre-T59
// `wasm_api::…` import path keeps working.
pub use crate::receipt_api::{verify_receipt_inner, CheckJs, VerifyReceiptResult};

use crate::receipt_api::verdict_glyph;

/// Result shape of [`verify_record_offline`].
#[derive(Serialize)]
pub struct VerifyRecordResult {
    /// `"VERIFIED"` | `"PARTIAL"` | `"FAILED"`. FAIL dominates PARTIAL dominates
    /// VERIFIED (a tampered bound is never softened by a proven one); an empty
    /// check set fails closed.
    pub verdict: &'static str,
    /// Overall glyph for the verdict.
    pub glyph: &'static str,
    /// The gates-driven one-line headline ([`crate::verdict_headline`]) —
    /// the SAME sentence the CLI leads with; never stronger than the gates.
    pub headline: String,
    /// Per-check breakdown, in the order the library produced them.
    pub checks: Vec<CheckJs>,
    /// `"ok"` on parse success; otherwise the parse-error reason (with `verdict`
    /// = `"FAILED"` and `checks` empty). The verifier never throws.
    pub reason: String,
}

fn to_js<T: Serialize>(v: &T) -> JsValue {
    serde_wasm_bindgen::to_value(v).unwrap_or(JsValue::NULL)
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
/// parse reason, not an exception. (Same export NAME as the legacy copy in
/// `browser-node/src/verify_record.rs`, but the result shapes have DRIFTED —
/// this one adds `headline`. The demo pages build against THIS crate (ci.yml
/// verify-wasm job); do not switch bundles without re-checking the consuming
/// JS. 2026-07-12 sweep A8.)
#[wasm_bindgen]
pub fn verify_record_offline(record_json: &str) -> JsValue {
    let record: ValidationRecord = match serde_json::from_str(record_json) {
        Ok(r) => r,
        Err(e) => {
            return to_js(&VerifyRecordResult {
                // Through the enum authorities, never hand literals — the
                // reason-enum-in-more-than-one-place drift class (SCITT list,
                // vaara.io field report 2026-08-19): three individually-
                // reasonable hand assemblies is where their defect lived.
                verdict: crate::Verdict::Failed.label(),
                glyph: crate::Status::Fail.glyph(),
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

/// Verify a `.elara-receipt` v1 envelope entirely offline — the FULL chain
/// (record → inclusion proof → epoch seal → anchor, plus account
/// inclusion/exclusion legs) in one pasted file, graded through the SAME
/// shared [`crate::grade`] sequence as `elara-verify --receipt`, so the
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
/// [`crate::mandate_bundle::evaluate_mandate_bundle`] — the SAME pure
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
    to_js(&crate::mandate_bundle::evaluate_mandate_bundle(bundle_json))
}
