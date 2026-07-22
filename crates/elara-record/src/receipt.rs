//! `.elara-receipt` v1 — the single-file evidence envelope for `elara-verify`.
//!
//! A receipt bundles the EVIDENCE for one verification run — the signed wire
//! objects and proof JSONs a server (or a script like
//! `scripts/harvest-verify-bundle.sh`) hands out — so "check this yourself"
//! is one file plus the verifier, not a five-flag scavenger hunt.
//!
//! ## Trust posture (audit-locked, verifier-flagship-fusion-an internal audit)
//!
//! - **Evidence only — trust roots are NEVER receipt-sourced.** The trust
//!   flags (`--trusted-anchor`, `--expected-hash`, `--expect-root`,
//!   `--expect-identity`) stay verifier-side; their absence grades PARTIAL
//!   exactly as in flag mode. A receipt cannot vouch for itself: every
//!   cross-leg link is re-derived cryptographically by the same
//!   `verify_core::bind_chain` path — no envelope field asserts a binding.
//! - **Version fail-closed:** missing `receipt_version` defaults to 0 and is
//!   refused; anything != `RECEIPT_VERSION` is refused (an old verifier
//!   facing a future security-bearing envelope must under-claim, never
//!   under-check). Mirrors `mandate_bundle::MANDATE_BUNDLE_VERSION`.
//! - **Open legs map, PARTIAL cap:** unknown leg KINDS do not hard-fail the
//!   parse (the ACER metadata-freeze lesson, internal design notes) —
//!   they are surfaced in `ReceiptLegs::not_evaluated` and the CLI caps the
//!   verdict at PARTIAL with explicit disclosure. Never VERIFIED-with-skips.
//!   Unknown fields at the ENVELOPE level (outside `legs`) are rejected —
//!   the interpreted structure is strict (`deny_unknown_fields`).
//! - **Signed objects ride as canonical wire bytes, hex-encoded** (`record`,
//!   `seal` — decodable by `ValidationRecord::from_bytes`); proof/anchor JSON
//!   sub-objects ride verbatim. Hex, not base64, for consistency with every
//!   shipped wire helper. This dodges the measured 8.5× numeric-array serde
//!   blowup of record JSON.
//! - **DoS caps before crypto:** the envelope byte size, each wire leg's hex
//!   length, and each JSON leg's serialized size are bounded here, before any
//!   hex decode or signature work. The legs' own internal caps (64 zone
//!   siblings, 256 SMT siblings, seal decode bounds) still apply downstream.
//!
//! The module is intentionally node-free and feature-ungated (like
//! `verify_core` / `mandate_bundle`) so the wasm build can grow receipt
//! support without drift.

use serde::Deserialize;
use serde_json::Value;

/// Current receipt envelope version. Bump on ANY change to the envelope's
/// interpreted structure or leg semantics (the schema-fingerprint test below
/// forces this at CI time).
pub const RECEIPT_VERSION: u8 = 1;

/// Whole-envelope byte cap, enforced before JSON parsing. Generous: the
/// largest real leg is a seal wire (bounded by the node's 64 KiB record cap →
/// 128 KiB hex) plus proof JSONs in the tens of KiB.
pub const RECEIPT_MAX_BYTES: usize = 2 * 1024 * 1024;

/// Per-wire-leg cap in HEX CHARACTERS (192 KiB hex = 96 KiB wire — headroom
/// over the node's 64 KiB record-size cap), enforced before hex::decode.
pub const RECEIPT_WIRE_LEG_MAX_HEX: usize = 192 * 1024;

/// Per-JSON-leg cap on the sub-object's serialized size, enforced before the
/// leg is handed to its verifier.
pub const RECEIPT_JSON_LEG_MAX_BYTES: usize = 512 * 1024;

/// The known v1 leg keys, in grading order. `lineage` is a RESERVED slot
/// (audit KR-3): parses, carries no semantics, and — when non-null — is
/// surfaced as not-evaluated (PARTIAL cap) rather than silently dropped.
pub const RECEIPT_V1_LEGS: [&str; 7] = [
    "record",
    "seal",
    "anchor",
    "inclusion",
    "account_inclusion",
    "account_exclusion",
    "lineage",
];

/// The envelope's strict interpreted structure. Top-level unknown fields are
/// REJECTED (`deny_unknown_fields` — an envelope field we don't understand
/// could be security-bearing); unknown keys INSIDE `legs` are tolerated and
/// disclosed instead (see module docs).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptEnvelope {
    /// Defaults to 0 when absent so an unversioned blob fails the version
    /// gate (closed) rather than being trusted.
    #[serde(default)]
    receipt_version: u8,
    /// Self-declared producer info (node identity, software version, URL…).
    /// ADVISORY ONLY — displayed with a provenance caveat, never graded,
    /// never trusted.
    #[serde(default)]
    producer: Option<Value>,
    /// The evidence map. Known keys: [`RECEIPT_V1_LEGS`].
    legs: serde_json::Map<String, Value>,
}

/// What a v1 receipt carried, decoded and size-capped — ready for the same
/// per-leg verifiers the CLI flags feed.
#[derive(Debug, Default)]
pub struct ReceiptLegs {
    /// Canonical `ValidationRecord` wire bytes (the record being verified).
    pub record_wire: Option<Vec<u8>>,
    /// Canonical epoch-seal record wire bytes.
    pub seal_wire: Option<Vec<u8>>,
    /// Epoch-anchor artifact JSON, verbatim.
    pub anchor: Option<Value>,
    /// Record-inclusion proof JSON, verbatim.
    pub inclusion: Option<Value>,
    /// Account-inclusion proof JSON, verbatim.
    pub account_inclusion: Option<Value>,
    /// Account-exclusion (absence) witness JSON, verbatim.
    pub account_exclusion: Option<Value>,
    /// Self-declared producer info (advisory, never trusted).
    pub producer: Option<Value>,
    /// Leg keys present in the envelope that THIS verifier did not evaluate:
    /// unknown kinds plus a non-null reserved `lineage` slot. Non-empty MUST
    /// cap the verdict at PARTIAL with explicit disclosure (EV-1: never
    /// VERIFIED-with-skips).
    pub not_evaluated: Vec<String>,
}

/// How `--receipt` input was classified.
#[derive(Debug)]
pub enum ReceiptInput {
    /// A v1 envelope, decoded and capped.
    V1(Box<ReceiptLegs>),
    /// Not an envelope at all — the published pre-v1 convention
    /// (`site/receipts.html`: `curl …/record/<id> > receipt.json`) or raw
    /// record wire bytes. The caller routes these through the SAME
    /// record-loading path the positional `<record>` argument uses, so the
    /// degenerate receipt grades exactly like `elara-verify <record>`.
    BareRecord(Vec<u8>),
}

/// Classify and decode `--receipt` bytes. Fail-closed: every rejection is a
/// reason string (CLI exit 2 — input error, nothing gradeable).
///
/// Envelope detection is by MARKER, not by parse success: a JSON object
/// carrying `receipt_version` or `legs` is committed to the envelope path —
/// a malformed envelope must never silently degrade into "try it as a bare
/// record" (that would grade DIFFERENT evidence than the producer intended).
pub fn parse_receipt_input(bytes: &[u8]) -> Result<ReceiptInput, String> {
    if bytes.len() > RECEIPT_MAX_BYTES {
        return Err(format!(
            "receipt is {} bytes — exceeds the {} byte envelope cap",
            bytes.len(),
            RECEIPT_MAX_BYTES
        ));
    }

    // Non-JSON input (e.g. raw ELRA wire bytes) → degenerate bare record.
    let Ok(v) = serde_json::from_slice::<Value>(bytes) else {
        return Ok(ReceiptInput::BareRecord(bytes.to_vec()));
    };
    let is_envelope =
        v.as_object().is_some_and(|o| o.contains_key("receipt_version") || o.contains_key("legs"));
    if !is_envelope {
        // JSON, but not an envelope: the bare-record convention.
        return Ok(ReceiptInput::BareRecord(bytes.to_vec()));
    }

    // Committed to the envelope path from here on — strict.
    let env: ReceiptEnvelope = serde_json::from_value(v)
        .map_err(|e| format!("not a valid .elara-receipt envelope: {e}"))?;
    if env.receipt_version != RECEIPT_VERSION {
        return Err(format!(
            "unsupported receipt_version {} (this verifier speaks v{}) — refusing to verify \
             (a newer envelope may carry security-bearing fields this build cannot check)",
            env.receipt_version, RECEIPT_VERSION
        ));
    }

    let mut legs = ReceiptLegs { producer: env.producer, ..Default::default() };

    for (key, val) in &env.legs {
        // A null leg is "slot present, evidence absent" — ignored (this is
        // how a producer templates optional legs without tripping the
        // unknown-leg disclosure).
        if val.is_null() {
            continue;
        }
        match key.as_str() {
            "record" => legs.record_wire = Some(wire_leg(key, val)?),
            "seal" => legs.seal_wire = Some(wire_leg(key, val)?),
            "anchor" => legs.anchor = Some(json_leg(key, val)?),
            "inclusion" => legs.inclusion = Some(json_leg(key, val)?),
            "account_inclusion" => legs.account_inclusion = Some(json_leg(key, val)?),
            "account_exclusion" => legs.account_exclusion = Some(json_leg(key, val)?),
            // Reserved slot: no semantics in v1. Non-null content is honestly
            // not-evaluated (never silently dropped, never guessed at).
            "lineage" => legs.not_evaluated.push(key.clone()),
            _ => legs.not_evaluated.push(key.clone()),
        }
    }

    if legs.record_wire.is_none()
        && legs.seal_wire.is_none()
        && legs.anchor.is_none()
        && legs.inclusion.is_none()
        && legs.account_inclusion.is_none()
        && legs.account_exclusion.is_none()
        && legs.not_evaluated.is_empty()
    {
        return Err("receipt envelope carries no evidence legs (all absent/null)".into());
    }

    Ok(ReceiptInput::V1(Box::new(legs)))
}

/// Decode a hex-encoded wire leg, caps first.
fn wire_leg(key: &str, val: &Value) -> Result<Vec<u8>, String> {
    let s = val
        .as_str()
        .ok_or_else(|| format!("receipt leg '{key}' must be a hex string of canonical wire bytes"))?;
    if s.len() > RECEIPT_WIRE_LEG_MAX_HEX {
        return Err(format!(
            "receipt leg '{key}' is {} hex chars — exceeds the {} char cap",
            s.len(),
            RECEIPT_WIRE_LEG_MAX_HEX
        ));
    }
    hex::decode(s.trim()).map_err(|e| format!("receipt leg '{key}' is not valid hex: {e}"))
}

/// Bound a JSON sub-object leg, verbatim passthrough.
fn json_leg(key: &str, val: &Value) -> Result<Value, String> {
    if !val.is_object() {
        return Err(format!("receipt leg '{key}' must be a JSON object (rides verbatim)"));
    }
    // Serialized size as the cap metric — cheap, and what downstream parsers see.
    let size = val.to_string().len();
    if size > RECEIPT_JSON_LEG_MAX_BYTES {
        return Err(format!(
            "receipt leg '{key}' serializes to {size} bytes — exceeds the {RECEIPT_JSON_LEG_MAX_BYTES} byte cap"
        ));
    }
    Ok(val.clone())
}

/// The v1 schema descriptor the drift-guard test fingerprints. ANY change to
/// the envelope's interpreted structure, leg set, caps, or version MUST alter
/// this string — and the pinned fingerprint below — forcing a conscious
/// `RECEIPT_VERSION` bump (precedent:
/// `elara-pq-transport::wire_fingerprint_ledger_forces_version_bump`).
pub fn schema_descriptor() -> String {
    format!(
        "elara-receipt|version:{RECEIPT_VERSION}|envelope:{{receipt_version:u8:default0,producer:Value?,legs:map}}|deny_unknown_fields:envelope|open:legs|legs:{}|wire_hex_legs:record,seal|json_legs:anchor,inclusion,account_inclusion,account_exclusion|reserved:lineage|caps:{{envelope:{RECEIPT_MAX_BYTES},wire_hex:{RECEIPT_WIRE_LEG_MAX_HEX},json_leg:{RECEIPT_JSON_LEG_MAX_BYTES}}}",
        RECEIPT_V1_LEGS.join(",")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope(version: Value, legs: Value) -> Vec<u8> {
        serde_json::json!({ "receipt_version": version, "legs": legs }).to_string().into_bytes()
    }

    #[test]
    fn unknown_receipt_version_fails_closed() {
        // Future version → refuse.
        let e = parse_receipt_input(&envelope(99.into(), serde_json::json!({}))).unwrap_err();
        assert!(e.contains("receipt_version 99"), "{e}");
        // Absent version (defaults 0) with the `legs` marker → refuse, NOT
        // bare-record fallthrough.
        let raw = serde_json::json!({ "legs": { "record": "00" } }).to_string();
        let e = parse_receipt_input(raw.as_bytes()).unwrap_err();
        assert!(e.contains("receipt_version 0"), "{e}");
    }

    #[test]
    fn envelope_unknown_top_level_field_rejected() {
        let raw = serde_json::json!({
            "receipt_version": RECEIPT_VERSION,
            "legs": {},
            "trusted_anchor": "attacker-supplied",
        })
        .to_string();
        let e = parse_receipt_input(raw.as_bytes()).unwrap_err();
        assert!(e.contains("not a valid .elara-receipt envelope"), "{e}");
    }

    #[test]
    fn unknown_and_reserved_legs_disclosed_not_dropped() {
        let raw = envelope(
            RECEIPT_VERSION.into(),
            serde_json::json!({
                "record": "abcd",
                "quantum_notary": { "x": 1 },
                "lineage": { "hops": [] },
            }),
        );
        let ReceiptInput::V1(legs) = parse_receipt_input(&raw).unwrap() else {
            panic!("expected V1 envelope");
        };
        assert_eq!(legs.record_wire.as_deref(), Some(&[0xab, 0xcd][..]));
        let mut ne = legs.not_evaluated.clone();
        ne.sort();
        assert_eq!(ne, vec!["lineage".to_string(), "quantum_notary".to_string()]);
        // Null legs are templating, not evidence — no disclosure.
        let raw = envelope(
            RECEIPT_VERSION.into(),
            serde_json::json!({ "record": "abcd", "lineage": null }),
        );
        let ReceiptInput::V1(legs) = parse_receipt_input(&raw).unwrap() else {
            panic!("expected V1 envelope");
        };
        assert!(legs.not_evaluated.is_empty());
    }

    #[test]
    fn caps_enforced_before_decode() {
        // Envelope cap.
        let big = vec![b' '; RECEIPT_MAX_BYTES + 1];
        assert!(parse_receipt_input(&big).unwrap_err().contains("envelope cap"));
        // Wire-leg hex cap — construct WITHOUT allocating a decoded copy.
        let hex_blob = "ab".repeat(RECEIPT_WIRE_LEG_MAX_HEX / 2 + 1);
        let raw = envelope(RECEIPT_VERSION.into(), serde_json::json!({ "seal": hex_blob }));
        assert!(parse_receipt_input(&raw).unwrap_err().contains("char cap"));
        // JSON-leg cap.
        let fat = serde_json::json!({ "pad": "x".repeat(RECEIPT_JSON_LEG_MAX_BYTES) });
        let raw = envelope(RECEIPT_VERSION.into(), serde_json::json!({ "anchor": fat }));
        assert!(parse_receipt_input(&raw).unwrap_err().contains("byte cap"));
    }

    #[test]
    fn wire_legs_must_be_hex_strings() {
        let raw = envelope(RECEIPT_VERSION.into(), serde_json::json!({ "record": [1, 2, 3] }));
        assert!(parse_receipt_input(&raw).unwrap_err().contains("hex string"));
        let raw = envelope(RECEIPT_VERSION.into(), serde_json::json!({ "record": "zz-not-hex" }));
        assert!(parse_receipt_input(&raw).unwrap_err().contains("not valid hex"));
        let raw = envelope(RECEIPT_VERSION.into(), serde_json::json!({ "anchor": "not-an-object" }));
        assert!(parse_receipt_input(&raw).unwrap_err().contains("JSON object"));
    }

    #[test]
    fn empty_envelope_rejected() {
        let raw = envelope(RECEIPT_VERSION.into(), serde_json::json!({}));
        assert!(parse_receipt_input(&raw).unwrap_err().contains("no evidence legs"));
        let raw = envelope(RECEIPT_VERSION.into(), serde_json::json!({ "record": null }));
        assert!(parse_receipt_input(&raw).unwrap_err().contains("no evidence legs"));
    }

    #[test]
    fn bare_record_convention_falls_through() {
        // The receipts.html convention: a /record/<id> JSON body (no envelope
        // markers) routes to the degenerate path.
        let record_json = serde_json::json!({
            "record_id": "0198…", "zone": "0", "metadata": {}
        })
        .to_string();
        let ReceiptInput::BareRecord(b) = parse_receipt_input(record_json.as_bytes()).unwrap()
        else {
            panic!("expected BareRecord for plain record JSON");
        };
        assert_eq!(b, record_json.as_bytes());
        // Raw wire bytes (not JSON at all) also fall through.
        let wire = b"ELRA\x02garbage-but-not-json";
        let ReceiptInput::BareRecord(b) = parse_receipt_input(wire).unwrap() else {
            panic!("expected BareRecord for non-JSON bytes");
        };
        assert_eq!(b, wire);
    }

    #[test]
    fn receipt_v1_schema_fingerprint_forces_version_bump() {
        // Fingerprint of `schema_descriptor()`. If this assertion fires you
        // changed the receipt envelope's interpreted structure: bump
        // RECEIPT_VERSION, update the pin, and add a migration note to
        // docs/ELARA-VERIFY.md — old receipts in the wild must keep verifying
        // under the version they were produced for (fail-closed, never
        // silently reinterpreted).
        use sha3::{Digest, Sha3_256};
        let fp = hex::encode(Sha3_256::digest(schema_descriptor().as_bytes()));
        assert_eq!(
            fp, "e28e33a45cd00d24097a99fec93965620f7ed010d9e900d73721235df1d20595",
            "receipt v1 schema descriptor changed — bump RECEIPT_VERSION and re-pin"
        );
    }
}
