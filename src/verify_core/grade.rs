//! Receipt grading + the cross-leg binding pass — the ONE sequence that turns
//! evidence (a `.elara-receipt` v1 envelope, or per-flag legs) plus
//! verifier-side trust pins into a graded check list, shared VERBATIM by the
//! `elara-verify` CLI and the wasm verifier so a browser receipt verdict can
//! never drift from the CLI verdict (verifier-flagship fusion audit
//! 2026-07-06, step 4: full-chain parity).
//!
//! Trust posture (audit-locked): EVIDENCE rides in the receipt; TRUST stays
//! caller-side in [`TrustPins`] — a receipt embedding its own trust root would
//! be self-vouching. Every cross-leg link is re-derived cryptographically by
//! [`bind_outcomes`] (`bind_chain` / `bind_account_chain` /
//! `bind_sealed_account_root`); no envelope field may assert a binding.
//!
//! Gated on `verify-anchor` (the receipt's anchor/seal-drand legs need the
//! drand BLS path); `verify-cli` and the wasm verifier both enable it.

use serde_json::Value;

use super::anchor::{seal_drand_leg, verify_anchor_obj};
use super::{
    AccountExclusionFacts, AccountInclusionFacts, AnchorSummary, Check, InclusionFacts,
    RecordSummary, Status,
};
use crate::crypto::hash::sha3_256;
use crate::receipt::ReceiptLegs;
use crate::record::ValidationRecord;

/// The `--content` artifact as the RESOLVED caller supplies it — bytes, or the
/// reason they could not be read. Transport-free: the CLI resolves a file path
/// (a read failure becomes [`ContentArtifact::Unreadable`], so the record's
/// structure/identity/signature checks still run and the `content` check then
/// FAILS with that reason — never a silent skip); a browser caller passes the
/// bytes it already holds.
pub enum ContentArtifact<'a> {
    /// Artifact bytes + a display label for the check detail (the CLI uses the
    /// file path; a browser caller a field name).
    Bytes(&'a [u8], &'a str),
    /// The caller failed to read the artifact — carries the human reason.
    Unreadable(String),
}

/// The verifier-side trust pins the evidence legs compose with. EVIDENCE rides
/// in the receipt (or flag files); TRUST stays here — a receipt embedding its
/// own trust root would be self-vouching (audit rule, receipt v1).
pub struct TrustPins<'a> {
    /// `--trusted-anchor` pubkey-hex list the seal must verify against.
    pub trusted_anchor: &'a [String],
    /// `--expected-hash`: the seal's own record-hash, from a source you trust.
    pub expected_hash: Option<&'a str>,
    /// `--expect-root`: a sealed root (record-Merkle or account-SMT) pin.
    pub expect_root: Option<&'a str>,
    /// `--expect-identity`: the identity an account proof must be about.
    pub expect_identity: Option<&'a str>,
    /// `--content`: the original artifact the record's content_hash must match.
    /// Borrowed so one resolved artifact serves whichever transport runs.
    pub content: Option<&'a ContentArtifact<'a>>,
}

/// Everything the evidence legs learned, threaded into the ONE cross-leg
/// binding pass ([`bind_outcomes`]) — the receipt path and the CLI's per-flag
/// path populate the same facts, so the downstream binding is IDENTICAL for
/// both transports (and for the wasm verifier).
#[derive(Default)]
pub struct LegOutcomes {
    pub record_summary: Option<RecordSummary>,
    pub record_hash: Option<[u8; 32]>,
    pub anchor_summary: Option<AnchorSummary>,
    pub seal_hash: Option<[u8; 32]>,
    /// Roots the seal cryptographically committed to (anchor-signed); used to
    /// bind the inclusion proof's root into THIS seal in `bind_chain`.
    pub seal_roots: Vec<[u8; 32]>,
    /// The seal's TYPED account-SMT root — the account legs bind against THIS
    /// alone, never the union above (see `bind_sealed_account_root`: the union
    /// carries an empty-record-zone root equal to an empty-account exclusion
    /// witness's fold, a cross-type false-absence vector).
    pub seal_account_root: Option<[u8; 32]>,
    pub inclusion_facts: Option<InclusionFacts>,
    pub account_facts: Option<AccountInclusionFacts>,
    pub absence_facts: Option<AccountExclusionFacts>,
}

/// The record leg over a DECODED record — shared by the CLI's positional
/// `<record>` path, the `--receipt` paths, and the wasm verifier so they can
/// never drift. Runs the four record checks (structure / identity binding /
/// signature / content) and returns the summary + canonical record hash.
pub fn record_leg(
    record: &ValidationRecord,
    content: Option<&ContentArtifact>,
    checks: &mut Vec<Check>,
) -> (RecordSummary, [u8; 32]) {
    let pk_hash = sha3_256(&record.creator_public_key);
    match content {
        None => super::verify_record(record, None, "", checks),
        Some(ContentArtifact::Bytes(artifact, label)) => {
            super::verify_record(record, Some(artifact), label, checks);
        }
        Some(ContentArtifact::Unreadable(reason)) => {
            // Run the non-content checks exactly as before (the inlined leg
            // pushed structure/identity/signature/profile BEFORE attempting
            // the content read), then reproduce the content Fail verbatim.
            super::verify_record(record, None, "", checks);
            checks.push(Check {
                name: "content",
                status: Status::Fail,
                detail: reason.clone(),
            });
        }
    }
    (
        RecordSummary {
            id: record.id.clone(),
            creator_hex: hex::encode(pk_hash),
            timestamp: record.timestamp,
        },
        record.record_hash(),
    )
}

/// Grade every leg a v1 receipt carries, through the SAME verifiers the CLI
/// flags feed (the envelope only changes how evidence arrives, never what is
/// proven). An `Err` is an input error (CLI exit 2) — malformed leg content,
/// or an envelope-level claim conflict.
pub fn grade_receipt_v1(
    legs: &ReceiptLegs,
    pins: &TrustPins,
    checks: &mut Vec<Check>,
) -> Result<LegOutcomes, String> {
    let mut out = LegOutcomes::default();

    // One account CLAIM per run — the same rule the flag guard in the CLI's
    // `main` enforces, applied to the envelope's legs.
    if legs.account_inclusion.is_some() && legs.account_exclusion.is_some() {
        return Err("receipt carries BOTH account_inclusion and account_exclusion legs — one account claim per receipt (produce two receipts for two claims)".into());
    }

    if let Some(wire) = &legs.record_wire {
        let record = ValidationRecord::from_bytes(wire)
            .map_err(|e| format!("receipt 'record' leg is not a valid Elara wire record: {e}"))?;
        let (summary, hash) = record_leg(&record, pins.content, checks);
        out.record_summary = Some(summary);
        out.record_hash = Some(hash);
    }

    if let Some(obj) = &legs.anchor {
        let summary = verify_anchor_obj(obj, checks)
            .map_err(|reason| format!("{reason} (receipt 'anchor' leg)"))?;
        // .ots proofs do not ride in receipt v1 — push the same explicit
        // PARTIAL the file path pushes for a missing sidecar (never silently
        // drop the leg).
        checks.push(Check {
            name: "existed-by",
            status: Status::Partial,
            detail: "OTS proofs do not ride in a receipt — the Bitcoin existed-by upper bound \
                     is UNPROVEN here (absent, not forged); run --anchor <artifact.json> with \
                     its .ots sidecar to grade it"
                .into(),
        });
        out.anchor_summary = Some(summary);
    }

    if let Some(wire) = &legs.seal_wire {
        if pins.trusted_anchor.is_empty() {
            // Flag mode hard-errors (--seal without --trusted-anchor is a
            // usage error), but a receipt arrives as a sealed unit: grade what
            // is gradeable, stay honest about the rest. PARTIAL, never a skip.
            checks.push(Check {
                name: "seal anchor",
                status: Status::Partial,
                detail: "receipt carries a seal, but no --trusted-anchor was supplied — the \
                         seal is UNGRADED (a receipt can never vouch for its own trust root); \
                         pass --trusted-anchor <pubkey-hex> from a source you trust"
                    .into(),
            });
        } else {
            let facts = super::verify_seal(wire, pins.trusted_anchor, pins.expected_hash, checks)?;
            out.seal_hash = Some(facts.own_hash);
            out.seal_roots = facts.committed_roots;
            out.seal_account_root = facts.committed_account_root;
            seal_drand_leg(wire, checks);
        }
    }

    if let Some(obj) = &legs.inclusion {
        out.inclusion_facts = Some(super::verify_inclusion(
            obj.to_string().as_bytes(),
            pins.expect_root,
            checks,
        )?);
    }
    if let Some(obj) = &legs.account_inclusion {
        out.account_facts = super::verify_account_inclusion(
            obj.to_string().as_bytes(),
            pins.expect_identity,
            checks,
        )?;
    }
    if let Some(obj) = &legs.account_exclusion {
        out.absence_facts = Some(super::verify_account_exclusion(
            obj.to_string().as_bytes(),
            pins.expect_identity,
            checks,
        )?);
    }

    // Legs this verifier did not evaluate (unknown kinds + the reserved
    // lineage slot): disclosed, and the Partial status caps the verdict —
    // never VERIFIED-with-skips (EV-1).
    if !legs.not_evaluated.is_empty() {
        checks.push(Check {
            name: "receipt coverage",
            status: Status::Partial,
            detail: format!(
                "receipt carries {} leg(s) this verifier does not evaluate ({}) — verdict \
                 capped at PARTIAL; upgrade elara-verify to grade them",
                legs.not_evaluated.len(),
                legs.not_evaluated.join(", "),
            ),
        });
    }

    Ok(out)
}

/// The cross-leg binding pass — prove the supplied objects are the SAME chain.
/// The ONE sequence both the CLI's `main` and the wasm verifier run after the
/// evidence legs, so the binding semantics cannot drift between them:
///
///   1. `bind_chain` — record → proof.root → seal → anchor (+ the EV-1
///      record↔anchor unlinked disclosure);
///   2. `bind_account_chain` — the account-INCLUSION chain, with its own
///      non-record leg names so a record run can never borrow an account leg;
///   3. `bind_sealed_account_root` for an absence witness — the exclusion
///      root binds through the SAME sealed-root ladder (seal commitment /
///      `--expect-root` pin / honest PARTIAL).
///
/// An `Err` is an input error (malformed `--expect-root`) — CLI exit 2.
pub fn bind_outcomes(
    checks: &mut Vec<Check>,
    out: &LegOutcomes,
    expect_root: Option<&str>,
) -> Result<(), String> {
    super::bind_chain(
        checks,
        out.record_hash,
        out.inclusion_facts.as_ref(),
        out.seal_hash,
        &out.seal_roots,
        out.anchor_summary.as_ref(),
    );
    // Account chain binds separately (its own non-record leg names) so a record
    // run missing its real record-inclusion proof can never have `chain_is_bound`
    // satisfied by an account leg — that would be a new false-"this record's seal".
    super::bind_account_chain(checks, out.account_facts.as_ref(), expect_root, out.seal_account_root)?;
    // The absence witness's root is self-declared exactly like the inclusion
    // proof's — bind it through the SAME sealed-root ladder (seal commitment /
    // --expect-root pin / honest PARTIAL). Only one of the two account legs can
    // have run (guard at entry), so the shared check names stay unambiguous.
    if let Some(x) = out.absence_facts.as_ref() {
        super::bind_sealed_account_root(checks, x.root, expect_root, out.seal_account_root)?;
    }
    Ok(())
}

/// Advisory receipt metadata for renderers. `producer` is self-declared by
/// whoever wrote the receipt — displayed with a provenance caveat, never
/// graded, never trusted. `not_evaluated` lists leg kinds this verifier
/// disclosed-but-skipped (already reflected as a PARTIAL cap by the grader).
pub struct ReceiptDisplay {
    pub producer: Option<Value>,
    pub not_evaluated: Vec<String>,
}
