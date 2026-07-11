//! elara-verify — the pure, node-free, wasm-portable verification LOGIC behind
//! the `elara-verify` CLI (still `src/bin/elara_verify.rs` in the node until
//! extraction Step 4) and the browser wasm verifier.
//!
//! This crate exists so every consumer calls the IDENTICAL verify logic with no
//! drift: the binary is a thin shell that reads files, parses CLI flags, and
//! renders prose/JSON, but every cryptographic/structural CHECK lives here. It
//! deliberately references only pure-Rust deps (`elara_record` for the wire
//! type, hash, and PQ verify primitives; `elara_smt`; `serde_json`; `hex`) —
//! NOT `std::process`, `clap`, `std::fs`, or any node-gated symbol — so it
//! compiles for `wasm32-unknown-unknown` under default features. It is
//! signing-incapable by design (keygen/sign stay node-side): a verifier cannot
//! forge what it checks.
//!
//! The fallible/IO legs are split: the core functions here take already-read
//! bytes (or parsed values) and return `Result<_, String>` (the `String` is the
//! human reason a malformed input is rejected). The binary keeps thin wrappers
//! that read the file(s) and map `Err(String)` → `eprintln!` + the original exit
//! code, preserving the CLI's exact behavior.

#![forbid(unsafe_code)]

// Anchor-leg verification (drand BLS + OTS→Bitcoin) — gated on `verify-anchor`
// (pulls sha2 + drand-verify, both pure-Rust and wasm32-clean) so the node
// build doesn't pay for BLS12-381. `verify-cli` and the wasm verifier enable it.
#[cfg(feature = "verify-anchor")]
pub mod anchor;
// Receipt grading + the ONE cross-leg binding sequence, shared verbatim by the
// CLI and the wasm verifier (full-chain parity). Needs the anchor legs.
#[cfg(feature = "verify-anchor")]
pub mod grade;
// Anchor-pinned seal-record verification (decode + hash-bind + anchor-set
// membership + Dilithium3). Ungated: the node's `light_verify` shim re-exports
// it on every build profile.
pub mod seal_record;
pub use seal_record::{verify_seal_record_against_anchor, SealRecordVerifyError};
// Agent-mandate evaluation (authority-to-act) + the offline bundle verifier on
// top of it — pure serde/sha3 logic, ungated (wasm/default-safe): the browser
// demo's `evaluate_mandate_bundle` export is this exact code, so the offline
// verdict can never drift from the node's `GET /mandate/status`. Signing-
// dependent fixtures stayed node-side (src/mandate_bundle_tests.rs) — this
// crate remains signing-incapable.
pub mod mandate;
pub mod mandate_bundle;
// Anchor-proof record codec (P1.5(b)) — consts + build/parse of the metadata
// envelope the CLI's --anchor-record leg verifies. Ungated (serde_json + base64
// + hex only); the node's `anchor_proof` shim maps String errors to ElaraError.
pub mod anchor_proof;
// The `elara-verify` CLI driver (argv parsing, file reads, prose/JSON render) —
// gated on `cli` (pulls clap + the verify-anchor legs) so library consumers and
// the wasm build never pay for it. Both the crate's own bin and the node repo's
// root delegate bin call `cli::run()`; the signing-dependent CLI fixtures stay
// in the node's bin (this crate remains signing-incapable).
#[cfg(feature = "cli")]
pub mod cli;
// The browser/wasm exports (`verify_record_offline`, `verify_receipt_offline`,
// `evaluate_mandate_bundle`) — gated on `wasm` (pulls wasm-bindgen + the anchor
// legs). The `verify-wasm` cdylib in the node repo is a thin `pub use` of this
// module; the demo page's artifact is built from this crate alone.
#[cfg(feature = "wasm")]
pub mod wasm_api;

use serde_json::Value;

use elara_record::hash::{sha3_256, sha3_256_hex};
use elara_record::pqc::{dilithium3_verify, sphincs_verify};
use elara_record::record::ValidationRecord;
// The account-SMT walk is DELEGATED to the network-agreed, cross-engine-pinned
// `elara_smt` crate (a plain top-level dep, no node stack) — NOT re-implemented
// here. Its walk is key-addressed (path from the identity) and treats each
// sibling's `is_right` as a consistency check, the opposite of the record walk;
// copying the record walk for account proofs would be a forgeable binding.
use elara_smt::{
    verify_exclusion_proof as smt_verify_exclusion_proof, verify_proof as smt_verify_proof,
    SmtExclusionProof, SmtProof,
};

/// Zone-Merkle tree depth cap — 64 levels address 2^64 leaves. This is the
/// CANONICAL definition: `network::merkle::MAX_DEPTH` re-exports it, so the
/// node's tree and this node-free verifier can never disagree on the bound
/// (this module must stay free of node-gated symbols — see module doc).
pub const ZONE_MERKLE_MAX_DEPTH: u8 = 64;

/// Outcome of one verification check. Tri-state so the verifier can FAIL
/// CLOSED (forged/tampered/inconsistent) yet still express a legitimately
/// *unproven* bound (a pending Bitcoin timestamp, an un-archived header, a
/// reference-only drand round) without overstating it as proven.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Status {
    /// Cryptographically/structurally PROVEN. Contributes to VERIFIED (exit 0).
    Pass,
    /// Not proven, but NOT forged — absent or pending evidence. Contributes to
    /// PARTIAL (exit 3): an honest "I cannot confirm this", never a false green.
    Partial,
    /// Forged, tampered, or self-inconsistent. Contributes to FAILED (exit 1).
    Fail,
}

impl Status {
    /// Prose glyph — never print ✓ for anything short of a proven Pass.
    pub fn glyph(self) -> &'static str {
        match self {
            Status::Pass => "✓",
            Status::Partial => "⚠",
            Status::Fail => "✗",
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Pass => "pass",
            Status::Partial => "partial",
            Status::Fail => "fail",
        }
    }
}

/// Binary checks (record signature, identity binding, inclusion) have no
/// partial state: a thing is proven or it is forged.
pub fn st(proven: bool) -> Status {
    if proven {
        Status::Pass
    } else {
        Status::Fail
    }
}

/// Overall verdict. FAIL dominates PARTIAL dominates VERIFIED — a tampered
/// bound is never softened by a proven one (this ordering is the structural
/// defense against the strip-the-.ots downgrade vector).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Verdict {
    Verified,
    Partial,
    Failed,
}

impl Verdict {
    pub fn of(checks: &[Check]) -> Verdict {
        // Fail CLOSED on an empty check set: a verifier that proved NOTHING must
        // never read as a green. Unreachable through today's CLI (every leg
        // pushes ≥1 check and `main` rejects the no-leg case), but the
        // "no checks ⇒ Verified" else-branch is one refactor away from a
        // catastrophic fail-open, so the invariant is enforced, not incidental.
        if checks.is_empty() {
            return Verdict::Failed;
        }
        if checks.iter().any(|c| c.status == Status::Fail) {
            Verdict::Failed
        } else if checks.iter().any(|c| c.status == Status::Partial) {
            Verdict::Partial
        } else {
            Verdict::Verified
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Verdict::Verified => "VERIFIED",
            Verdict::Partial => "PARTIAL",
            Verdict::Failed => "FAILED",
        }
    }
}

/// One verification check: name, outcome, human detail.
pub struct Check {
    pub name: &'static str,
    pub status: Status,
    pub detail: String,
}

/// What we learned about a verified record (for the final verdict + JSON).
pub struct RecordSummary {
    pub id: String,
    pub creator_hex: String,
    pub timestamp: f64,
}

/// What we learned about a verified anchor's not-before leg.
pub struct AnchorSummary {
    pub epoch: u64,
    pub seal_hash: String,
    /// The drand-derived lower bound (unix seconds), when a usable drand round is
    /// present. Reference-only UNLESS `not_before_trustless` is true: the round→time
    /// formula is applied to the cited round, and when the artifact carries the
    /// beacon signature it is verified against the pinned LoE key (see below).
    pub not_before_unix: Option<u64>,
    /// True when the beacon's BLS signature was VERIFIED against the pinned
    /// League-of-Entropy key — the not-before is then trustless, not a reference.
    /// False for legacy/signature-less artifacts or unknown chains (reference only).
    pub not_before_trustless: bool,
    /// Which beacon's parameters were used, and whether they were the
    /// artifact's own (self-describing) or the LoE-default fallback.
    pub beacon_label: String,
    pub assumed_default_beacon: bool,
    pub has_ots_sidecar: bool,
    /// The EXISTED-BY upper bound (unix seconds) — the timestamp of the Bitcoin
    /// block the OTS proof commits into, confirmed against an archived header.
    /// `None` = pending / no archived header / no proof. This bound is TRUSTLESS
    /// only when `existed_by_trustless` is true (the header was authenticated
    /// against a pin compiled into the verifier); otherwise it is a REFERENCE
    /// bound whose strength rests on the (operator-supplied) header's authenticity.
    pub existed_by_unix: Option<u64>,
    pub existed_by_height: Option<u64>,
    /// True only when the archived Bitcoin header was authenticated — its
    /// double-SHA256 matched a block hash PINNED in the verifier binary (never a
    /// hash read from the bundle). False = the header is internally consistent
    /// with the OTS proof but unauthenticated → the upper bound is reference-only.
    pub existed_by_trustless: bool,
}

/// Cross-leg binding. Each leg above verifies ONE object in isolation; this
/// proves the supplied objects are the SAME chain. Without it, a
/// `record + --inclusion + --seal + --anchor` run can read VERIFIED while the
/// four inputs are individually-valid but UNRELATED (a proof for a different
/// record, a seal for a different epoch). Three links span the chain
/// record → proof.root → seal → anchor: `record↔proof` (the proof's leaf is
/// THIS record's hash), `inclusion↔seal` (the proof's root is a root THIS seal
/// committed to), and `seal↔anchor` (the anchor commits to THIS seal's hash).
/// Each link is checked only when both of its ends were supplied; a missing
/// link is not invented (the prose then says the legs are not chained). A
/// mismatch is a hard Fail.
pub fn bind_chain(
    checks: &mut Vec<Check>,
    record_hash: Option<[u8; 32]>,
    inclusion: Option<&InclusionFacts>,
    seal_hash: Option<[u8; 32]>,
    seal_roots: &[[u8; 32]],
    anchor: Option<&AnchorSummary>,
) {
    // record ↔ inclusion proof: the proof's leaf must be THIS record's hash.
    if let (Some(rh), Some(incl)) = (record_hash, inclusion) {
        let bound = rh == incl.leaf;
        checks.push(Check {
            name: "record↔proof",
            status: st(bound),
            detail: if bound {
                format!("the inclusion proof's leaf is THIS record's hash ({}…)", &hex::encode(rh)[..16])
            } else {
                format!(
                    "the inclusion proof is for leaf {}…, but the record under audit hashes to {}… — the proof is for a DIFFERENT record",
                    &hex::encode(incl.leaf)[..16],
                    &hex::encode(rh)[..16],
                )
            },
        });
    }
    // inclusion ↔ seal: the proof's proven root must be one of the roots THIS
    // seal cryptographically committed to (each lives in the seal record's
    // signable_bytes, so the anchor signature vouches for it). This is the
    // middle link that joins the {record, proof} half to the {seal, anchor}
    // half — without it a valid proof climbing to some root and an
    // individually-valid but UNRELATED seal (committing to a different root)
    // would be reported as one chain. Checked only when an inclusion proof and a
    // seal carrying ≥1 committed root were both supplied; a legacy seal with no
    // root metadata yields no link, leaving the chain honestly unproven.
    if let Some(incl) = inclusion {
        if !seal_roots.is_empty() {
            let bound = seal_roots.contains(&incl.root);
            checks.push(Check {
                name: "inclusion↔seal",
                status: st(bound),
                detail: if bound {
                    format!(
                        "the inclusion proof climbs to root {}…, a root THIS seal committed to (anchor-signed)",
                        &hex::encode(incl.root)[..16],
                    )
                } else {
                    format!(
                        "the inclusion proof climbs to root {}…, which is NOT among the roots this seal signed — the proof and the seal are for DIFFERENT epochs/trees",
                        &hex::encode(incl.root)[..16],
                    )
                },
            });
        }
    }
    // seal ↔ anchor: the anchor must commit to THIS seal's hash.
    if let (Some(sh), Some(a)) = (seal_hash, anchor) {
        let sh_hex = hex::encode(sh);
        let bound = sh_hex.eq_ignore_ascii_case(a.seal_hash.trim());
        checks.push(Check {
            name: "seal↔anchor",
            status: st(bound),
            detail: if bound {
                format!("the anchor commits to THIS seal ({}…)", &sh_hex[..16])
            } else {
                format!(
                    "the --seal record hashes to {}…, but the --anchor commits to seal {}… — they are NOT the same seal",
                    &sh_hex[..16],
                    &short(&a.seal_hash),
                )
            },
        });
    }
    // EV-1 (2026-07-03 audit): a record and an anchor supplied TOGETHER but with
    // no --seal/--inclusion to bridge them share NO cryptographic link — the
    // anchor proves some seal existed at a time, the record is independently
    // valid, but nothing ties THIS record to THAT anchor. With no bridging
    // objects the three link checks above never fire, so the verdict stayed at
    // VERIFIED (all-Pass) — an over-claim. Record the record↔anchor chain as
    // honestly unproven (Partial) so the top-line verdict is PARTIAL, not green.
    if record_hash.is_some() && anchor.is_some() {
        let bridged = inclusion.is_some() && seal_hash.is_some() && !seal_roots.is_empty();
        if !bridged {
            checks.push(Check {
                name: "record↔anchor",
                status: Status::Partial,
                detail: "a record and an anchor were supplied but are NOT cryptographically linked — pass --seal and --inclusion to bind THIS record to THIS anchor; without them the anchor's time bracket does not apply to this record".to_string(),
            });
        }
    }
}

/// True only when the FULL record → proof.root → seal → anchor chain is
/// cryptographically linked: the record is the proof's leaf (`record↔proof`),
/// the leaf climbs to the proof's root (`record inclusion`), that root is one
/// the seal committed to (`inclusion↔seal`), and the anchor commits to that
/// seal (`seal↔anchor`). Drives whether the prose may say "this record's seal"
/// and suppress the independent-verification NOTE. Requiring all four — not just
/// the two end-links — is what stops a valid proof + an UNRELATED valid seal
/// from reading as one chain (the false-chain class).
pub fn chain_is_bound(checks: &[Check]) -> bool {
    let leg = |name: &str| checks.iter().any(|c| c.name == name && c.status == Status::Pass);
    leg("record↔proof") && leg("record inclusion") && leg("inclusion↔seal") && leg("seal↔anchor")
}

/// Cross-leg binding for the ACCOUNT chain: account-proof → account_smt_root →
/// seal → anchor. Kept separate from `bind_chain` (the record chain) with its
/// own leg names so the record-named `chain_is_bound` can never be satisfied by
/// an account leg. The account root is self-declared by the proof, so it is
/// bound to a seal the caller trusts EXACTLY one of three ways: against a
/// `--seal`'s committed roots (`account-root↔seal`); against a `--expect-root`
/// the caller pins; or — neither given — honestly PARTIAL (a self-declared root
/// proves nothing). The `seal↔anchor` link is the SAME one `bind_chain` emits,
/// so it is not duplicated here. Returns Err only on a malformed `--expect-root`.
pub fn bind_account_chain(
    checks: &mut Vec<Check>,
    account: Option<&AccountInclusionFacts>,
    expect_root_hex: Option<&str>,
    seal_account_root: Option<[u8; 32]>,
) -> Result<(), String> {
    let Some(acct) = account else { return Ok(()) };
    bind_sealed_account_root(checks, acct.root, expect_root_hex, seal_account_root)
}

/// The account-SMT-root binding SHARED by the inclusion and exclusion legs: an
/// account proof's root is self-declared either way, so it means nothing until
/// bound to a seal the caller trusts. Same three-way ladder for both — seal
/// commitment, `--expect-root` pin, or honest PARTIAL. Emitting identical check
/// names keeps the chain predicates uniform (only ONE account leg runs per
/// invocation — the CLI rejects `--account-inclusion` + `--account-exclusion`
/// together, so the names never collide).
///
/// `seal_account_root` is the seal's TYPED `epoch_account_smt_root`
/// (`seal_committed_account_root`), NOT the untyped four-root union. This is
/// load-bearing for the exclusion leg: an empty-account-tree exclusion witness
/// folds to `elara_smt::EMPTY_HASH`, which also equals an empty RECORD zone's
/// `epoch_sparse_merkle_root`; binding against the union would let a real
/// anchor-signed empty-record-zone seal certify a fabricated absence for ANY
/// identity. Comparing only against the account root means an empty witness
/// binds solely to a genuinely-empty account tree (where universal absence is
/// TRUE), never to a non-empty one via a sibling tree's empty sentinel.
pub fn bind_sealed_account_root(
    checks: &mut Vec<Check>,
    root: [u8; 32],
    expect_root_hex: Option<&str>,
    seal_account_root: Option<[u8; 32]>,
) -> Result<(), String> {
    if let Some(committed) = seal_account_root {
        // A --seal was supplied AND committed an account root: bind the proof's
        // root against THAT root specifically. It lives in the seal's
        // signable_bytes, so the anchor signature (checked in verify_seal)
        // vouches for it.
        let bound = root == committed;
        checks.push(Check {
            name: "account-root↔seal",
            status: st(bound),
            detail: if bound {
                format!(
                    "the account-SMT root {}… is the account root THIS seal committed to (anchor-signed)",
                    &hex::encode(root)[..16],
                )
            } else {
                format!(
                    "the account-SMT root {}… is NOT the account root this seal signed ({}…) — the proof and the seal are for DIFFERENT epochs",
                    &hex::encode(root)[..16],
                    &hex::encode(committed)[..16],
                )
            },
        });
    } else if let Some(expect_hex) = expect_root_hex {
        let expect = match hash32_from_hex(expect_hex) {
            Some(e) => e,
            None => {
                return Err("--expect-root must be 32-byte hex".into());
            }
        };
        let bound = root == expect;
        checks.push(Check {
            name: "sealed account-root bind",
            status: st(bound),
            detail: if bound {
                format!(
                    "account-SMT root matches the sealed root you supplied ({}…)",
                    &hex::encode(expect)[..16],
                )
            } else {
                format!(
                    "account-SMT root {}… ≠ supplied sealed root {}… — account is NOT under that seal",
                    &hex::encode(root)[..16],
                    &hex::encode(expect)[..16],
                )
            },
        });
    } else {
        checks.push(Check {
            name: "sealed account-root bind",
            status: Status::Partial,
            detail: format!(
                "account-SMT root {}… is self-declared by the proof, NOT bound to a sealed root you trust — add --seal <wire> (+ --anchor) or --expect-root <sealed-root-hex> from a seal you verified",
                &hex::encode(root)[..16],
            ),
        });
    }
    Ok(())
}

/// True only when the FULL account chain is cryptographically linked: the
/// identity's sealed state is a leaf under the proof's root (`account inclusion`),
/// that root is one the seal committed to (`account-root↔seal`), and the anchor
/// commits to that seal (`seal↔anchor`). Drives whether the prose may say the
/// account's sealed state sits inside the Bitcoin-bracketed seal. There is NO
/// `record↔proof` link — an account chain proves a sealed account-state, not a
/// record.
pub fn chain_is_account_bound(checks: &[Check]) -> bool {
    let leg = |name: &str| checks.iter().any(|c| c.name == name && c.status == Status::Pass);
    leg("account inclusion") && leg("account-root↔seal") && leg("seal↔anchor")
}

/// True only when an account chain is BOTH linked into an anchor-named seal
/// (`chain_is_account_bound`) AND that anchor actually proved a TRUSTLESS time
/// bound — a BLS-verified drand not-before or a PIN-authenticated Bitcoin
/// existed-by. `seal↔anchor` alone proves the anchor commits to the seal's hash,
/// NOT that its time legs hold; an existed-by computed from an unauthenticated
/// (reference) header is NOT a trustless bracket. Gating the "Bitcoin-bracketed
/// / trustless time window" prose and the JSON `bound_to_bitcoin` on a genuinely
/// trustless leg is what stops the verifier from claiming a bracket it did not
/// prove.
pub fn account_chain_time_bracketed(checks: &[Check], anchor: Option<&AnchorSummary>) -> bool {
    chain_is_account_bound(checks)
        && anchor.is_some_and(|a| a.not_before_trustless || a.existed_by_trustless)
}

/// True only when the FULL account-ABSENCE chain is cryptographically linked:
/// the identity provably has NO leaf under the witness's root (`account
/// exclusion`), that root is one the seal committed to (`account-root↔seal`),
/// and the anchor commits to that seal (`seal↔anchor`). Kept separate from
/// `chain_is_account_bound` so an absence leg can never satisfy the presence
/// predicate or vice versa — reading one as the other inverts the claim.
pub fn chain_is_account_absence_bound(checks: &[Check]) -> bool {
    let leg = |name: &str| checks.iter().any(|c| c.name == name && c.status == Status::Pass);
    leg("account exclusion") && leg("account-root↔seal") && leg("seal↔anchor")
}

/// The absence twin of `account_chain_time_bracketed`: the absence chain is
/// linked into an anchor-named seal AND that anchor proved a trustless time
/// bound. Only then may the verdict place the absence inside a proven time
/// window ("provably absent at the sealed root of THAT bracketed epoch") —
/// chain linkage alone is not a bracket.
pub fn account_absence_time_bracketed(checks: &[Check], anchor: Option<&AnchorSummary>) -> bool {
    chain_is_account_absence_bound(checks)
        && anchor.is_some_and(|a| a.not_before_trustless || a.existed_by_trustless)
}

/// The one-line human verdict HEADLINE, synthesized ENTIRELY from the graded
/// checks and the chain-binding gates above — never free text, never a claim a
/// gate did not prove (verifier-flagship audit 2026-07-06, step 5: a flat
/// "chain verified" sentence would regress EV-1 `4f33b49f`). Shared by the CLI
/// (`emit_prose` first line, `--json` `headline` field) and the wasm verifier
/// so the strongest sentence each surface prints is the SAME sentence.
///
/// Claim ladder (strongest proven claim wins):
/// - FAILED   → says what failed, nothing else.
/// - PARTIAL  → proven/total arithmetic + which legs are honest gaps.
/// - VERIFIED → absence chain ("PROVABLY ABSENT … as of that sealed epoch" —
///   never "currently absent"), account chain, full record chain, record-only
///   scope, or independently-verified-objects — each phrased no stronger than
///   its gate (`chain_is_*`, `*_time_bracketed`).
pub fn verdict_headline(
    verdict: Verdict,
    checks: &[Check],
    record: Option<&RecordSummary>,
    anchor: Option<&AnchorSummary>,
    account: Option<&AccountInclusionFacts>,
    absence: Option<&AccountExclusionFacts>,
) -> String {
    // Up-to-3 check names for a status, for compact FAILED/PARTIAL headlines.
    let names_with = |status: Status| -> String {
        let names: Vec<&str> = checks
            .iter()
            .filter(|c| c.status == status)
            .map(|c| c.name)
            .collect();
        let shown = names.iter().take(3).cloned().collect::<Vec<_>>().join(", ");
        if names.len() > 3 {
            format!("{shown}, +{} more", names.len() - 3)
        } else {
            shown
        }
    };
    let total = checks.len();
    let proven = checks.iter().filter(|c| c.status == Status::Pass).count();

    match verdict {
        Verdict::Failed if total == 0 => {
            "✗ FAILED — nothing was verifiable in the supplied input.".to_string()
        }
        Verdict::Failed => {
            let failed = checks.iter().filter(|c| c.status == Status::Fail).count();
            format!(
                "✗ FAILED — {failed} of {total} checks failed ({}); the evidence is forged, \
                 tampered, or inconsistent — do not rely on it.",
                names_with(Status::Fail),
            )
        }
        Verdict::Partial => format!(
            "⚠ PARTIAL — {proven} of {total} checks proven; unproven: {} — honest gaps, not \
             failures. What passed holds; the rest needs more evidence or a trust pin.",
            names_with(Status::Partial),
        ),
        Verdict::Verified => {
            // Strongest proven claim first. Each arm's wording is bounded by
            // its gate — the absence arm never says "currently", the unbound
            // arm never says "chain".
            if let Some(x) = absence {
                let id8 = &hex::encode(x.identity)[..16];
                let seal_bound = checks
                    .iter()
                    .any(|c| c.name == "account-root↔seal" && c.status == Status::Pass);
                if chain_is_account_absence_bound(checks) {
                    let epoch_note = anchor
                        .map(|a| format!(" of epoch {}", a.epoch))
                        .unwrap_or_default();
                    let bracket = if account_absence_time_bracketed(checks, anchor) {
                        " inside a trustlessly time-bracketed seal"
                    } else {
                        ""
                    };
                    format!(
                        "✓ VERIFIED — identity {id8}… is PROVABLY ABSENT from the sealed \
                         account tree{epoch_note}{bracket}: a claim about THAT sealed instant, \
                         never about now."
                    )
                } else if seal_bound {
                    format!(
                        "✓ VERIFIED — identity {id8}… is PROVABLY ABSENT at the account root \
                         the verified seal committed to: a claim about that sealed instant, \
                         never about now."
                    )
                } else {
                    format!(
                        "✓ VERIFIED — identity {id8}… is provably absent under the account \
                         root you pinned: a claim about the seal that root came from, never \
                         about now."
                    )
                }
            } else if account.is_some() && chain_is_account_bound(checks) {
                let id8 = account.map(|a| hex::encode(a.identity)).unwrap_or_default();
                let epoch_note = anchor
                    .map(|a| format!(" of epoch {}", a.epoch))
                    .unwrap_or_default();
                let bracket = if account_chain_time_bracketed(checks, anchor) {
                    " inside a trustlessly time-bracketed seal"
                } else {
                    ""
                };
                format!(
                    "✓ VERIFIED — identity {}…'s sealed account state is cryptographically \
                     bound into the anchored seal{epoch_note}{bracket}; every link verified \
                     independently, offline.",
                    &id8[..16.min(id8.len())],
                )
            } else if account.is_some()
                && checks
                    .iter()
                    .any(|c| c.name == "account-root↔seal" && c.status == Status::Pass)
            {
                let id8 = account.map(|a| hex::encode(a.identity)).unwrap_or_default();
                format!(
                    "✓ VERIFIED — identity {}…'s sealed account state is bound to the account \
                     root the verified seal committed to (no anchor supplied, so no independent \
                     time claim is made).",
                    &id8[..16.min(id8.len())],
                )
            } else if record.is_some() && chain_is_bound(checks) {
                "✓ VERIFIED — the FULL chain holds: record → inclusion proof → sealed epoch \
                 root → anchor, every link re-derived and verified independently, offline."
                    .to_string()
            } else if record.is_some()
                && anchor.is_none()
                && account.is_none()
                && !checks.iter().any(|c| c.name.starts_with("seal"))
                && !checks.iter().any(|c| c.name == "record inclusion")
            {
                "✓ VERIFIED — this record's structure, identity binding, and post-quantum \
                 signature all verify. Scope: the record's own integrity — no seal or anchor \
                 chain was supplied, so no chain claim is made."
                    .to_string()
            } else {
                // Everything supplied proved, possibly including SOME binding
                // legs — but not the full record→…→anchor chain (that arm is
                // above) and not an account chain. Claim exactly the checks,
                // deny the full chain, promise nothing more.
                format!(
                    "✓ VERIFIED — all {total} checks pass; the proven claims are exactly the \
                     ✓ lines above (the full record → inclusion → seal → anchor chain was \
                     not established)."
                )
            }
        }
    }
}

/// The four record checks (structure / identity binding / signature / content),
/// pushed onto `checks`. Structure parsing already succeeded by the time we
/// are called.
///
/// `content` is the already-read artifact bytes (when `--content` was given) and
/// `content_label` is the display string for that artifact path, used only in
/// the content-check detail so the messages stay byte-identical to the CLI.
pub fn verify_record(
    record: &ValidationRecord,
    content: Option<&[u8]>,
    content_label: &str,
    checks: &mut Vec<Check>,
) {
    // 1. Structure — parsing succeeded to get here.
    checks.push(Check {
        name: "structure",
        status: Status::Pass,
        detail: format!(
            "ValidationRecord v{} id={} ({} parent{})",
            record.version,
            record.id,
            record.parents.len(),
            if record.parents.len() == 1 { "" } else { "s" },
        ),
    });

    // 2. Identity binding — pk must hash to the claimed identity when the
    // record carries one (wire v4+). JSON records without the field skip
    // the check honestly rather than inventing a pass.
    let pk_hash = sha3_256(&record.creator_public_key);
    match &record.identity_hash_wire {
        Some(claimed) if claimed.len() == 32 => {
            let pass = claimed.as_slice() == pk_hash.as_slice();
            checks.push(Check {
                name: "identity binding",
                status: st(pass),
                detail: if pass {
                    format!(
                        "creator = {} (SHA3-256 of embedded public key)",
                        &hex::encode(pk_hash)[..16]
                    )
                } else {
                    format!(
                        "record claims identity {} but the embedded public key hashes to {}",
                        &hex::encode(claimed)[..16.min(claimed.len() * 2)],
                        &hex::encode(pk_hash)[..16],
                    )
                },
            });
        }
        Some(claimed) => {
            // Present but NOT 32 bytes — a structurally malformed identity claim.
            // `identity_hash_wire` is outside `signable_bytes` (not authenticated
            // by the signature), so an attacker can graft a garbage-length claim
            // onto a validly-signed record; silently treating it as "no claim"
            // (the old `_` arm) reported a green ✓ for a broken record. Fail.
            checks.push(Check {
                name: "identity binding",
                status: Status::Fail,
                detail: format!(
                    "record carries a malformed identity claim: {} byte(s), expected 32 — rejected",
                    claimed.len(),
                ),
            });
        }
        None => {
            // No separate identity claim. The creator identity IS sha3-256 of the
            // embedded (and signature-bound) public key, so deriving it is a
            // proven fact, not an unverified one — Pass is honest here.
            checks.push(Check {
                name: "identity binding",
                status: Status::Pass,
                detail: format!(
                    "creator identity derived from embedded key: {} (record carries no separate identity claim to cross-check)",
                    &hex::encode(pk_hash)[..16],
                ),
            });
        }
    }

    // 3. Signature(s).
    let signable = record.signable_bytes();
    match &record.signature {
        None => checks.push(Check {
            name: "signature",
            status: Status::Fail,
            detail: "record is UNSIGNED".into(),
        }),
        Some(sig) => {
            let pass =
                dilithium3_verify(&signable, sig, &record.creator_public_key).unwrap_or(false);
            checks.push(Check {
                name: "signature",
                status: st(pass),
                detail: if pass {
                    "Dilithium3 (ML-DSA-65) valid over canonical record bytes".into()
                } else {
                    "Dilithium3 signature DOES NOT VERIFY over the record's canonical bytes".into()
                },
            });
        }
    }
    match (&record.sphincs_signature, &record.creator_sphincs_pk) {
        (None, None) => checks.push(Check {
            name: "profile",
            status: Status::Pass,
            detail: "Profile B (single signature)".into(),
        }),
        (Some(ssig), Some(spk)) => {
            let pass = sphincs_verify(&signable, ssig, spk).unwrap_or(false);
            checks.push(Check {
                name: "profile",
                status: st(pass),
                detail: if pass {
                    "Profile A (dual signature) — SPHINCS+ (SLH-DSA) also valid".into()
                } else {
                    "Profile A claimed but the SPHINCS+ signature DOES NOT VERIFY".into()
                },
            });
        }
        _ => checks.push(Check {
            name: "profile",
            status: Status::Fail,
            detail: "inconsistent Profile A fields (SPHINCS+ key/signature must both be present or both absent)".into(),
        }),
    }

    // 4. Content binding (optional).
    if let Some(artifact) = content {
        let h = sha3_256(artifact);
        let pass = h.as_slice() == record.content_hash.as_slice();
        checks.push(Check {
            name: "content",
            status: st(pass),
            detail: if pass {
                format!(
                    "{} ({} bytes) hashes to exactly the record's content hash",
                    content_label,
                    artifact.len(),
                )
            } else {
                format!(
                    "{} hashes to {} but the record binds {}",
                    content_label,
                    &sha3_256_hex(artifact)[..16],
                    &hex::encode(&record.content_hash)
                        [..16.min(record.content_hash.len() * 2)],
                )
            },
        });
    }
}

/// What `verify_seal` learned, for the cross-leg binding in `main`. The roots
/// are EMPTY/None unless the seal's anchor signature verified — a forged seal's
/// self-declared roots must never drive an inclusion↔seal bind.
pub struct SealFacts {
    /// The seal record's own hash (a `--seal` + `--anchor` run must check the
    /// anchor commits to THIS seal).
    pub own_hash: [u8; 32],
    /// Every Merkle/SMT root the seal committed (the untyped union) — the
    /// RECORD-inclusion bind searches these.
    pub committed_roots: Vec<[u8; 32]>,
    /// The seal's TYPED `epoch_account_smt_root` — the only root the ACCOUNT
    /// legs may bind against (see `bind_sealed_account_root` for why the union
    /// is a false-absence vector).
    pub committed_account_root: Option<[u8; 32]>,
}

/// Verify a fetched epoch-seal record (canonical wire bytes) is authentically
/// signed by a caller-pinned anchor key, via the audited light-client closure
/// `light_verify::verify_seal_record_against_anchor`. With `--expected-hash`
/// the seal's `record_hash` is also pinned to a header the caller trusts;
/// without it that single cross-check is skipped and the verdict says so.
pub fn verify_seal(
    seal_bytes: &[u8],
    trusted_anchors_hex: &[String],
    expected_hash_hex: Option<&str>,
    checks: &mut Vec<Check>,
) -> Result<SealFacts, String> {
    let wire = seal_bytes;
    if trusted_anchors_hex.is_empty() {
        return Err("--seal requires at least one --trusted-anchor <pubkey-hex>".into());
    }
    let mut anchors: Vec<Vec<u8>> = Vec::with_capacity(trusted_anchors_hex.len());
    for h in trusted_anchors_hex {
        match hex::decode(h.trim()) {
            Ok(b) => anchors.push(b),
            Err(e) => {
                return Err(format!("bad --trusted-anchor hex '{h}': {e}"));
            }
        }
    }

    // Decode once to recover the record's own hash (for the no-pin path + display)
    // and the Merkle/SMT roots this seal cryptographically committed to. Those
    // roots live in the seal record's metadata, which is inside `signable_bytes()`
    // (record.rs) — so the anchor signature verified below vouches for every one.
    // `bind_chain` uses them for the `inclusion↔seal` link.
    let (own_hash, committed_roots, committed_account_root) = match ValidationRecord::from_bytes(wire) {
        Ok(r) => (
            r.record_hash(),
            seal_committed_roots(&r),
            seal_committed_account_root(&r),
        ),
        Err(e) => {
            return Err(format!("not a valid Elara wire seal record: {e}"));
        }
    };

    let (expected, pinned) = match expected_hash_hex {
        Some(h) => match hex::decode(h.trim()) {
            Ok(b) if b.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                (arr, true)
            }
            _ => {
                return Err("--expected-hash must be 32-byte hex".into());
            }
        },
        // No external header to pin against: pass the record's own hash so the
        // identity check is a tautology, leaving anchor-membership + signature
        // as the meaningful checks. Flagged honestly in the detail below.
        None => (own_hash, false),
    };

    let seal_result = verify_seal_record_against_anchor(wire, expected, &anchors);
    match &seal_result {
        // Signed by a pinned anchor AND pinned to an external header you trust →
        // the seal's identity is proven. Pass.
        Ok(()) if pinned => checks.push(Check {
            name: "seal anchor",
            status: Status::Pass,
            detail: format!(
                "seal {}… is signed by a pinned anchor (Dilithium3 valid); record_hash matches the header you pinned",
                &hex::encode(own_hash)[..16],
            ),
        }),
        // Signed by a pinned anchor, but NO --expected-hash: the record_hash
        // check was a tautology (seal hash vs itself), so the seal's identity is
        // bound to nothing you trust — an attacker can swap in a DIFFERENT
        // anchor-signed seal for a different epoch and this still passes. Honest
        // status is PARTIAL, not a green ✓ (same discipline the --anchor leg uses
        // for an unproven bound — previously applied only there).
        Ok(()) => checks.push(Check {
            name: "seal anchor",
            status: Status::Partial,
            detail: format!(
                "seal {}… UNPROVEN identity: the Dilithium3 signature is valid for a pinned anchor, \
                 but that alone proves only that SOME anchor signed SOME seal — not which epoch/seal \
                 this is. Without --expected-hash an attacker could substitute a different \
                 anchor-signed seal and this check would still pass. Supply --expected-hash to bind \
                 it to a header you trust.",
                &hex::encode(own_hash)[..16],
            ),
        }),
        Err(e) => checks.push(Check {
            name: "seal anchor",
            status: Status::Fail,
            detail: format!("seal verification FAILED: {e}"),
        }),
    }
    // Only surface the seal's committed roots when its anchor signature actually
    // verified. On a signature failure the roots are from an unsigned/forged
    // record and must never drive the record/account inclusion↔seal bind — even
    // though the Fail status already dominates the verdict, a future caller that
    // reads the returned roots without re-checking the leg would trust them.
    let trusted_roots = if seal_result.is_ok() { committed_roots } else { Vec::new() };
    // The account leg binds against the TYPED account root ONLY (never the
    // untyped `trusted_roots` union) — see `bind_sealed_account_root`. Gated on
    // the same signature check, for the same reason.
    let trusted_account_root = if seal_result.is_ok() { committed_account_root } else { None };
    Ok(SealFacts {
        own_hash,
        committed_roots: trusted_roots,
        committed_account_root: trusted_account_root,
    })
}

/// The single account-SMT root an epoch-seal record committed (`epoch_account_smt_root`).
/// Split out from `seal_committed_roots` because an account inclusion/exclusion
/// proof must bind against the account tree's root SPECIFICALLY, never the
/// untyped union of all four seal roots: the record sparse-tree root, the zone
/// registry root and the account root are DIFFERENT trees, and for an empty
/// zone the record sparse root equals `elara_smt::EMPTY_HASH` — the exact value
/// an empty-account-tree exclusion witness folds to. Binding an account claim
/// against the union would let a real (anchor-signed) empty-record-zone seal
/// certify a fabricated `EMPTY_HASH`-rooted absence witness for ANY identity,
/// including a present one. Binding against the typed account root closes that:
/// an empty witness (root = EMPTY_HASH) only matches a genuinely-empty account
/// tree, where universal absence is TRUE. `None` for a legacy seal without the
/// key → the account claim stays honestly unbound (PARTIAL).
pub fn seal_committed_account_root(rec: &ValidationRecord) -> Option<[u8; 32]> {
    rec.metadata
        .get("epoch_account_smt_root")
        .and_then(|v| v.as_str())
        .and_then(hash32_from_hex)
}

/// The Merkle/SMT roots an epoch-seal record cryptographically committed to.
/// Each is stored in the seal's metadata, which is part of `signable_bytes()`,
/// so the anchor's Dilithium3 signature (checked in `verify_seal`) vouches for
/// every one. A record-inclusion proof is genuinely bound to THIS seal iff its
/// proven root is one of these — see `bind_chain`'s `inclusion↔seal` link. The
/// keys mirror `network::epoch`'s seal-metadata writers; a legacy seal missing
/// all of them yields an empty set, so the chain is left honestly unproven
/// rather than falsely bound.
pub fn seal_committed_roots(rec: &ValidationRecord) -> Vec<[u8; 32]> {
    const ROOT_KEYS: [&str; 4] = [
        "epoch_merkle_root",
        "epoch_sparse_merkle_root",
        "epoch_account_smt_root",
        "epoch_zone_registry_root",
    ];
    let mut roots = Vec::with_capacity(ROOT_KEYS.len());
    for k in ROOT_KEYS {
        // Absent key → normal: a legacy seal predates this root. Stay silent.
        let Some(v) = rec.metadata.get(k) else { continue };
        match v.as_str().and_then(hash32_from_hex) {
            Some(h) => roots.push(h),
            // Present but unparseable. In a seal whose anchor signature verified
            // this means the producer signed a malformed root into its metadata —
            // never admitted to the accepted set (so any inclusion↔seal bind that
            // needs it stays honestly UNPROVEN), but no longer a SILENT drop: name
            // the unreadable root so the operator knows why the chain won't bind.
            None => {
                let shown = v
                    .as_str()
                    .map(|s| s.chars().take(16).collect::<String>())
                    .unwrap_or_else(|| "<non-string>".into());
                eprintln!(
                    "warning: seal metadata '{k}' is present but not a 32-byte hex root \
                     ('{shown}'…) — dropped; any inclusion↔seal bind needing it stays UNPROVEN"
                );
            }
        }
    }
    roots
}

/// Decode a 32-byte hash from a trimmed hex string.
pub fn hash32_from_hex(s: &str) -> Option<[u8; 32]> {
    let b = hex::decode(s.trim()).ok()?;
    if b.len() != 32 {
        return None;
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&b);
    Some(a)
}

/// Decode a 32-byte hash from a JSON value expected to hold a hex string.
pub fn hash32_from_json(v: Option<&Value>) -> Option<[u8; 32]> {
    hash32_from_hex(v?.as_str()?)
}

/// The leaf/root an inclusion proof asserted — returned so `main` can cross-bind
/// the leaf to the record under audit (`record.record_hash() == leaf`).
pub struct InclusionFacts {
    pub leaf: [u8; 32],
    pub root: [u8; 32],
}

/// What the `--account-inclusion` leg learned, for `bind_account_chain`. `root`
/// is the account-SMT root the proof reconstructs to; `identity` and
/// `state_hash` are echoed in the verdict so a misattributed proof (a valid
/// proof for the wrong identity) is visible to the reader.
#[derive(Debug)]
pub struct AccountInclusionFacts {
    pub identity: [u8; 32],
    pub state_hash: [u8; 32],
    pub root: [u8; 32],
}

/// What the `--account-exclusion` leg learned, for the sealed-root binding.
/// `root` is the account-SMT root the EMPTY leaf reconstructs to; `identity` is
/// echoed in the verdict so a misattributed witness (a valid absence proof for
/// an identity you did not ask about) is visible to the reader. There is no
/// `state_hash` — absence has no leaf.
#[derive(Debug)]
pub struct AccountExclusionFacts {
    pub identity: [u8; 32],
    pub root: [u8; 32],
}

/// Verify a record-inclusion proof (the JSON returned by
/// `/zone/{zone}/proof/{record_hash}`): the record's hash is a leaf under a
/// zone's sparse-Merkle root, fully offline. The walk replicates
/// `network::merkle::verify_proof` exactly (sha3-256; sibling-on-the-right ⇒
/// `current‖sibling`, else `sibling‖current`). With `--expect-root <hex>` the
/// proven root is also checked against a sealed root the caller already trusts,
/// binding the record to that seal.
pub fn verify_inclusion(
    proof_bytes: &[u8],
    expect_root_hex: Option<&str>,
    checks: &mut Vec<Check>,
) -> Result<InclusionFacts, String> {
    let obj: Value = match serde_json::from_slice(proof_bytes) {
        Ok(v) => v,
        Err(e) => {
            return Err(format!("not a valid inclusion-proof JSON: {e}"));
        }
    };
    let leaf = match hash32_from_json(obj.get("leaf")) {
        Some(h) => h,
        None => {
            return Err("inclusion proof has no valid 'leaf' (need 32-byte hex)".into());
        }
    };
    let root = match hash32_from_json(obj.get("root")) {
        Some(h) => h,
        None => {
            return Err("inclusion proof has no valid 'root' (need 32-byte hex)".into());
        }
    };
    let mut siblings: Vec<([u8; 32], bool)> = Vec::new();
    if let Some(arr) = obj.get("siblings").and_then(|v| v.as_array()) {
        for s in arr {
            let h = match hash32_from_json(s.get("hash")) {
                Some(h) => h,
                None => {
                    return Err("inclusion proof sibling has no valid 'hash'".into());
                }
            };
            // `is_right` selects the combine order and so determines the root —
            // it must be an explicit JSON boolean. A missing field or a
            // non-bool (e.g. integer 1, string "true") previously defaulted to
            // `false` via `unwrap_or(false)`, silently flipping the path; reject it.
            let is_right = match s.get("is_right") {
                Some(v) => match v.as_bool() {
                    Some(b) => b,
                    None => {
                        return Err(
                            "inclusion proof sibling 'is_right' must be a JSON boolean".into(),
                        );
                    }
                },
                None => {
                    return Err("inclusion proof sibling is missing 'is_right'".into());
                }
            };
            siblings.push((h, is_right));
        }
    }

    // The record/zone sparse-Merkle tree is `ZONE_MERKLE_MAX_DEPTH = 64` levels
    // (addresses 2^64 leaves), so a real path carries at most 64 siblings — one
    // per level traversed. Cap it before the hashing walk: an attacker handing
    // an offline verifier a proof JSON with millions of siblings would otherwise
    // force unbounded SHA3-256 work (`> 64` cannot verify against a 64-deep tree
    // anyway). Mirrors the 256-level cap on the account-inclusion path below.
    if siblings.len() > ZONE_MERKLE_MAX_DEPTH as usize {
        return Err(format!(
            "record-inclusion proof carries {} siblings — exceeds the {}-level zone-Merkle depth",
            siblings.len(),
            ZONE_MERKLE_MAX_DEPTH
        ));
    }

    // A real record proof in the sparse-Merkle tree always carries a fixed-depth
    // path of siblings. ZERO siblings makes the walk a no-op and `path_ok`
    // collapses to `leaf == root` — an attacker who sets leaf == root in the
    // proof JSON would pass a "membership" check that walked nothing. Reject it
    // as a structural non-proof rather than letting the tautology through.
    if siblings.is_empty() {
        checks.push(Check {
            name: "record inclusion",
            status: Status::Fail,
            detail: "inclusion proof carries no Merkle path (0 siblings) — a record cannot equal a sealed zone root; nothing is proven".into(),
        });
        return Ok(InclusionFacts { leaf, root });
    }

    // Walk leaf → root — verbatim network::merkle::verify_proof (sha3-256).
    let mut current = leaf;
    for (hash, is_right) in &siblings {
        let mut combined = [0u8; 64];
        if *is_right {
            combined[..32].copy_from_slice(&current);
            combined[32..].copy_from_slice(hash);
        } else {
            combined[..32].copy_from_slice(hash);
            combined[32..].copy_from_slice(&current);
        }
        current = sha3_256(&combined);
    }
    let path_ok = current == root;

    checks.push(Check {
        name: "record inclusion",
        status: st(path_ok),
        detail: if path_ok {
            format!(
                "record {}… is a leaf under Merkle root {}… ({} sibling{})",
                &hex::encode(leaf)[..16],
                &hex::encode(root)[..16],
                siblings.len(),
                if siblings.len() == 1 { "" } else { "s" },
            )
        } else {
            format!(
                "record {}… does NOT hash up to the claimed root {}… — proof invalid",
                &hex::encode(leaf)[..16],
                &hex::encode(root)[..16],
            )
        },
    });

    // The proof's `root` is taken from the proof JSON itself — i.e. it is
    // attacker-chosen unless bound to a root the caller already trusts. So the
    // sealed-root bind is ALWAYS emitted: with --expect-root it is Pass/Fail;
    // WITHOUT it the bind is PARTIAL ("the path is internally consistent, but the
    // root it climbs to is self-declared, not a sealed root you trust"). Omitting
    // the check entirely (the old behaviour) let a green "record inclusion ✓"
    // overstate inclusion in a trusted seal — the same fail-open class fixed for
    // the --anchor leg, which had been left in place here.
    match expect_root_hex {
        Some(expect_hex) => match hash32_from_hex(expect_hex) {
            Some(expect) => {
                let bound = root == expect;
                checks.push(Check {
                    name: "sealed-root bind",
                    status: st(bound),
                    detail: if bound {
                        format!(
                            "proof root matches the sealed root you supplied ({}…)",
                            &hex::encode(expect)[..16],
                        )
                    } else {
                        format!(
                            "proof root {}… ≠ supplied sealed root {}… — record is NOT under that seal",
                            &hex::encode(root)[..16],
                            &hex::encode(expect)[..16],
                        )
                    },
                });
            }
            None => {
                return Err("--expect-root must be 32-byte hex".into());
            }
        },
        None => checks.push(Check {
            name: "sealed-root bind",
            status: Status::Partial,
            detail: format!(
                "proof root {}… is self-declared by the proof, NOT bound to a sealed root you trust — supply --expect-root <sealed-root-hex> from a seal you verified to make this meaningful",
                &hex::encode(root)[..16],
            ),
        }),
    }
    Ok(InclusionFacts { leaf, root })
}

/// Verify a `/proof/account/{identity}` account-inclusion proof: the identity's
/// SEALED account-state (`state_hash`) is a leaf in the account SMT under the
/// proof's `root`. The walk is DELEGATED to `elara_smt::verify_proof` — the
/// network-agreed, cross-engine-pinned engine — NOT re-implemented from the
/// record walk. Key facts that keep this fail-closed:
///   - The path is the full 256-bit `SHA3-256(account_id)`; the compressed proof
///     carries a `present` bitmap + only non-empty siblings, and orientation is
///     derived from the path (no per-sibling `is_right` to trust).
///   - The leaf binds the identity: `leaf = SHA3-256(LEAF_TAG ‖ account_id ‖
///     state_hash)`, so a proof for one identity cannot be replayed as another.
///   - `account_id` is the identity bytes VERBATIM; `verify_proof` hashes them
///     once internally to derive the path — pre-hashing here is the double-hash trap.
///   - The leaf value is `state_hash` VERBATIM. The live `account_state` field is NEVER
///     re-hashed: it is unauthenticated and `hash_account_state` covers a
///     different field set than this opaque sealed leaf, so re-hashing would
///     false-mismatch even on a sealed-matching account.
///
/// Returns `Ok(Some(facts))` for a real proof (a Pass/Fail `account inclusion`
/// check is pushed), `Ok(None)` for an account that exists but is not yet sealed
/// (an honest PARTIAL check is pushed), or `Err(String)` for a malformed input /
/// wrong proof type / non-existence response (absence is graded by
/// `verify_account_exclusion`, not here).
pub fn verify_account_inclusion(
    proof_bytes: &[u8],
    expect_identity_hex: Option<&str>,
    checks: &mut Vec<Check>,
) -> Result<Option<AccountInclusionFacts>, String> {
    let obj: Value = match serde_json::from_slice(proof_bytes) {
        Ok(v) => v,
        Err(e) => {
            return Err(format!("not a valid account-inclusion-proof JSON: {e}"));
        }
    };

    // Wrong proof TYPE: a record-inclusion proof carries `leaf` and no
    // `state_hash`. Routing it here would cross the leaf domains the two trees
    // keep separate — reject it to the right flag instead.
    if obj.get("leaf").is_some() && obj.get("state_hash").is_none() {
        return Err("this looks like a record-inclusion proof (has 'leaf'); use --inclusion, not --account-inclusion".into());
    }

    // Non-existence response: it parses, but there is nothing to prove INCLUSION
    // of — absence is the OTHER leg's claim, graded by its exclusion witness.
    if obj.get("exists").and_then(|v| v.as_bool()) == Some(false) {
        return Err("account-inclusion proof reports exists:false — a non-existence response, not an inclusion proof; use --account-exclusion to verify the absence witness it carries".into());
    }

    // The identity the proof's path is derived from. The canonical payload emits
    // `identity` (a 32-byte hex); there is no server-supplied `account_id` to trust.
    let identity = match obj.get("identity").and_then(|v| v.as_str()).and_then(hash32_from_hex) {
        Some(h) => h,
        None => {
            return Err("account-inclusion proof has no valid 'identity' (need 32-byte hex)".into());
        }
    };

    // Distinguish "no proof body yet" (pending first seal — honest PARTIAL) from
    // "half a proof body" (malformed — hard input error). Conflating them would
    // describe a malformed/tampered payload to the user as the reassuring "exists
    // but not yet sealed", a different and misleading claim.
    let has_state = obj.get("state_hash").is_some();
    let has_sibs = obj.get("siblings").is_some();
    if !has_state && !has_sibs {
        // Account seen but not yet committed to a sealed SMT root (the server
        // short-circuits without a proof body). There is no sealed root to bind.
        checks.push(Check {
            name: "account inclusion",
            status: Status::Partial,
            detail: format!(
                "identity {}… exists in the ledger but is not yet committed to a sealed account-SMT root (no proof body) — re-query after the next seal",
                &hex::encode(identity)[..16],
            ),
        });
        return Ok(None);
    }
    if has_state != has_sibs {
        return Err(format!(
            "account-inclusion proof is malformed: it has {} but not {} — a real account proof carries both",
            if has_state { "'state_hash'" } else { "'siblings'" },
            if has_state { "'siblings'" } else { "'state_hash'" },
        ));
    }

    let state_hash = match hash32_from_json(obj.get("state_hash")) {
        Some(h) => h,
        None => {
            return Err("account-inclusion proof has no valid 'state_hash' (need 32-byte hex)".into());
        }
    };
    let root = match hash32_from_json(obj.get("root")) {
        Some(h) => h,
        None => {
            return Err("account-inclusion proof has no valid 'root' (need 32-byte hex)".into());
        }
    };

    // Compressed account-SMT proof: a 256-bit `present` bitmap plus only the
    // non-empty siblings (each a 32-byte hex hash). Orientation and empty
    // siblings are recovered from `present` + the identity path during the fold.
    let present = match hash32_from_json(obj.get("present")) {
        Some(p) => p,
        None => {
            return Err("account-inclusion proof has no valid 'present' bitmap (need 32-byte hex)".into());
        }
    };
    let mut siblings: Vec<[u8; 32]> = Vec::new();
    if let Some(arr) = obj.get("siblings").and_then(|v| v.as_array()) {
        for s in arr {
            let hash = match hash32_from_json(Some(s)) {
                Some(h) => h,
                None => {
                    return Err("account-inclusion proof sibling is not valid 32-byte hex".into());
                }
            };
            siblings.push(hash);
        }
    }
    // Compressed proofs are ≈ log2(N) siblings, never more than the 256-level
    // depth. A wrong-length list is a structural input error.
    if siblings.len() > elara_smt::MAX_DEPTH as usize {
        return Err(format!(
            "account-inclusion proof carries {} siblings — exceeds the {}-level account-SMT depth",
            siblings.len(),
            elara_smt::MAX_DEPTH
        ));
    }

    // Optional identity pin: a valid proof for a DIFFERENT identity is still
    // cryptographically sound but answers a question you did not ask.
    if let Some(want_hex) = expect_identity_hex {
        let want = match hash32_from_hex(want_hex) {
            Some(h) => h,
            None => {
                return Err("--expect-identity must be 32-byte hex".into());
            }
        };
        let ok = identity == want;
        checks.push(Check {
            name: "account identity",
            status: st(ok),
            detail: if ok {
                format!("proof is for the identity you asked about ({}…)", &hex::encode(want)[..16])
            } else {
                format!(
                    "proof is for identity {}…, NOT the {}… you asked about",
                    &hex::encode(identity)[..16],
                    &hex::encode(want)[..16],
                )
            },
        });
    }

    let smt_proof = SmtProof { account_id: identity, state_hash, root, present, siblings };
    let path_ok = smt_verify_proof(&smt_proof);
    checks.push(Check {
        name: "account inclusion",
        status: st(path_ok),
        detail: if path_ok {
            format!(
                "identity {}… holds SEALED account-state {}… as a leaf under account-SMT root {}… (256-level identity-bound key-addressed path)",
                &hex::encode(identity)[..16],
                &hex::encode(state_hash)[..16],
                &hex::encode(root)[..16],
            )
        } else {
            format!(
                "identity {}… with sealed state {}… does NOT reconstruct the claimed account-SMT root {}… — proof invalid",
                &hex::encode(identity)[..16],
                &hex::encode(state_hash)[..16],
                &hex::encode(root)[..16],
            )
        },
    });

    Ok(Some(AccountInclusionFacts { identity, state_hash, root }))
}

/// Verify a `/proof/account/{identity}` NON-EXISTENCE response: the identity
/// has NO leaf in the account SMT under the witness's `root`. The fold is
/// DELEGATED to `elara_smt::verify_exclusion_proof` — the same network-agreed
/// engine as the inclusion leg — starting from the EMPTY leaf at the identity's
/// 256-bit key-addressed path (the port of the node SDK's absence check,
/// `pq_client_sdk/light.rs`: bind identity → bind root → fold). Fail-closed
/// facts:
///   - What this PROVES is non-membership AT THE WITNESS'S ROOT — absence as of
///     the seal that committed that root, never "currently absent" and never
///     "absent for all time". The root is self-declared until bound via
///     `bind_sealed_account_root` (a `--seal`'s committed roots or
///     `--expect-root`), so an unbound run grades PARTIAL overall.
///   - A trivial all-empty witness (empty tree) folds to the EMPTY root and
///     "verifies" — but that root can never equal a real sealed root, so the
///     binding step is what keeps the trick meaningless. Absence claims are
///     only as strong as their root binding.
///   - `exists:true` payloads (inclusion or `pending_first_seal`) are ROUTING
///     errors, not verdicts: the payload asserts presence, which this leg has
///     no mandate to grade. `pending_first_seal` in particular proves neither
///     membership nor non-membership — the account is in the ledger but not
///     yet under any sealed root.
///   - The legacy bare-root shape (`{root, exists:false}`, pre-witness servers)
///     carries NO cryptographic witness and is rejected as an input error —
///     grading it would be trust-the-server, the exact class this tool exists
///     to kill.
///
/// Returns `Ok(facts)` when a real witness was graded (a Pass/Fail `account
/// exclusion` check is pushed), or `Err(String)` for malformed/mis-routed input
/// (nothing gradeable — CLI exit 2).
pub fn verify_account_exclusion(
    proof_bytes: &[u8],
    expect_identity_hex: Option<&str>,
    checks: &mut Vec<Check>,
) -> Result<AccountExclusionFacts, String> {
    let obj: Value = match serde_json::from_slice(proof_bytes) {
        Ok(v) => v,
        Err(e) => {
            return Err(format!("not a valid account-exclusion-proof JSON: {e}"));
        }
    };

    // Wrong proof TYPE: route each mis-fed shape to the flag that grades it.
    if obj.get("leaf").is_some() && obj.get("state_hash").is_none() {
        return Err("this looks like a record-inclusion proof (has 'leaf'); use --inclusion, not --account-exclusion".into());
    }
    if obj.get("state_hash").is_some() {
        // A payload that asserts absence while carrying an inclusion body is
        // self-contradictory — bouncing it to --account-inclusion (whose
        // exists:false guard bounces it straight back) would loop the user
        // between flags. Name the contradiction instead.
        if obj.get("exists").and_then(|v| v.as_bool()) == Some(false) {
            return Err("self-contradictory payload: it reports exists:false but carries an inclusion body ('state_hash') — malformed or tampered; trust neither claim".into());
        }
        return Err("this is an account-INCLUSION payload (has 'state_hash') — the server asserts the account EXISTS; use --account-inclusion to verify that instead".into());
    }
    if obj.get("pending_first_seal").and_then(|v| v.as_bool()) == Some(true) {
        return Err("the payload reports the account EXISTS but is pending its first seal — neither absence nor inclusion is provable against a sealed root yet; re-query after the next seal".into());
    }
    if obj.get("exists").and_then(|v| v.as_bool()) == Some(true) {
        return Err("the payload reports exists:true — it asserts presence, not absence; use --account-inclusion".into());
    }

    // The identity whose absence is claimed. The REST payload emits both
    // `identity` and `account_id` (same value); accept either, but if BOTH are
    // present they must agree — a payload that names two different identities
    // is self-inconsistent, and silently picking one would let a server show
    // one identity to the reader while proving absence of another.
    let id_rest = obj.get("identity").and_then(|v| v.as_str()).and_then(hash32_from_hex);
    let id_store = obj.get("account_id").and_then(|v| v.as_str()).and_then(hash32_from_hex);
    let identity = match (id_rest, id_store) {
        (Some(a), Some(b)) if a != b => {
            return Err("account-exclusion proof is self-inconsistent: 'identity' and 'account_id' name DIFFERENT identities".into());
        }
        (Some(a), _) => a,
        (None, Some(b)) => b,
        (None, None) => {
            return Err("account-exclusion proof has no valid 'identity'/'account_id' (need 32-byte hex)".into());
        }
    };

    // Distinguish "no witness at all" (legacy bare-root response — nothing
    // cryptographic to grade) from "half a witness" (malformed). Both are input
    // errors, but the reader deserves to know which server class they hit.
    let has_present = obj.get("present").is_some();
    let has_sibs = obj.get("siblings").is_some();
    if !has_present && !has_sibs {
        return Err("this non-existence response carries NO exclusion witness (no 'present'/'siblings') — a bare-root absence claim is trust-the-server, nothing to verify; re-query a current node (post-2026-06-16 servers serve the witness)".into());
    }
    if has_present != has_sibs {
        return Err(format!(
            "account-exclusion proof is malformed: it has {} but not {} — a real exclusion witness carries both",
            if has_present { "'present'" } else { "'siblings'" },
            if has_present { "'siblings'" } else { "'present'" },
        ));
    }

    let root = match hash32_from_json(obj.get("root")) {
        Some(h) => h,
        None => {
            return Err("account-exclusion proof has no valid 'root' (need 32-byte hex)".into());
        }
    };
    let present = match hash32_from_json(obj.get("present")) {
        Some(p) => p,
        None => {
            return Err("account-exclusion proof has no valid 'present' bitmap (need 32-byte hex)".into());
        }
    };

    // Sibling cap BEFORE the parse loop: the array length is attacker-supplied,
    // so reject oversize witnesses before allocating for them (a compressed
    // proof never exceeds the 256-level depth).
    let arr = match obj.get("siblings").and_then(|v| v.as_array()) {
        Some(a) => a,
        None => {
            return Err("account-exclusion proof 'siblings' is not an array".into());
        }
    };
    if arr.len() > elara_smt::MAX_DEPTH as usize {
        return Err(format!(
            "account-exclusion proof carries {} siblings — exceeds the {}-level account-SMT depth",
            arr.len(),
            elara_smt::MAX_DEPTH
        ));
    }
    let mut siblings: Vec<[u8; 32]> = Vec::with_capacity(arr.len());
    for s in arr {
        let hash = match hash32_from_json(Some(s)) {
            Some(h) => h,
            None => {
                return Err("account-exclusion proof sibling is not valid 32-byte hex".into());
            }
        };
        siblings.push(hash);
    }

    // Optional identity pin — same semantics as the inclusion leg: a valid
    // absence witness for a DIFFERENT identity is cryptographically sound but
    // answers a question you did not ask, and for absence a misread identity
    // INVERTS the claim's meaning.
    if let Some(want_hex) = expect_identity_hex {
        let want = match hash32_from_hex(want_hex) {
            Some(h) => h,
            None => {
                return Err("--expect-identity must be 32-byte hex".into());
            }
        };
        let ok = identity == want;
        checks.push(Check {
            name: "account identity",
            status: st(ok),
            detail: if ok {
                format!("absence witness is for the identity you asked about ({}…)", &hex::encode(want)[..16])
            } else {
                format!(
                    "absence witness is for identity {}…, NOT the {}… you asked about — a different account's absence proves nothing about yours",
                    &hex::encode(identity)[..16],
                    &hex::encode(want)[..16],
                )
            },
        });
    }

    let xproof = SmtExclusionProof { account_id: identity, root, present, siblings };
    let absent = smt_verify_exclusion_proof(&xproof);
    checks.push(Check {
        name: "account exclusion",
        status: st(absent),
        detail: if absent {
            format!(
                "identity {}… has NO leaf under account-SMT root {}… — the EMPTY leaf at its 256-level key-addressed path reconstructs that root (sound non-membership AT that root; whether a real seal committed it is graded separately below)",
                &hex::encode(identity)[..16],
                &hex::encode(root)[..16],
            )
        } else {
            format!(
                "exclusion witness for identity {}… does NOT reconstruct the claimed account-SMT root {}… — witness invalid (the identity may exist under that root, or the witness is corrupted)",
                &hex::encode(identity)[..16],
                &hex::encode(root)[..16],
            )
        },
    });

    Ok(AccountExclusionFacts { identity, root })
}

/// First 16 hex chars (or the whole string if shorter), for compact display.
fn short(hex: &str) -> String {
    hex.chars().take(16).collect()
}

#[cfg(test)]
mod headline_tests {
    //! `verdict_headline` is gates-driven prose — these tests pin the claim
    //! ladder to the gates with synthetic checks (no crypto needed): the
    //! headline must never say more than its gate proved, and the absence
    //! framing must never read as a claim about the present.
    use super::*;

    fn pass(name: &'static str) -> Check {
        Check { name, status: Status::Pass, detail: String::new() }
    }
    fn partial(name: &'static str) -> Check {
        Check { name, status: Status::Partial, detail: String::new() }
    }
    fn fail(name: &'static str) -> Check {
        Check { name, status: Status::Fail, detail: String::new() }
    }
    fn rec() -> RecordSummary {
        RecordSummary { id: "r".into(), creator_hex: "aa".repeat(32), timestamp: 0.0 }
    }
    fn anchor(trustless: bool) -> AnchorSummary {
        AnchorSummary {
            epoch: 42,
            seal_hash: "cc".repeat(32),
            not_before_unix: Some(1_700_000_000),
            not_before_trustless: trustless,
            beacon_label: "drand".into(),
            assumed_default_beacon: false,
            has_ots_sidecar: false,
            existed_by_unix: None,
            existed_by_height: None,
            existed_by_trustless: false,
        }
    }

    #[test]
    fn failed_headline_names_the_failures_and_nothing_else() {
        let checks = vec![pass("structure"), fail("signature")];
        let h = verdict_headline(Verdict::Failed, &checks, Some(&rec()), None, None, None);
        assert!(h.starts_with("✗ FAILED"), "got: {h}");
        assert!(h.contains("signature"), "got: {h}");
        assert!(!h.contains("VERIFIED"), "got: {h}");
    }

    #[test]
    fn empty_checks_failed_headline_is_the_nothing_verifiable_line() {
        let h = verdict_headline(Verdict::Failed, &[], None, None, None, None);
        assert!(h.contains("nothing was verifiable"), "got: {h}");
    }

    #[test]
    fn partial_headline_counts_and_names_gaps() {
        let checks = vec![pass("structure"), pass("signature"), partial("existed-by")];
        let h = verdict_headline(Verdict::Partial, &checks, Some(&rec()), None, None, None);
        assert!(h.starts_with("⚠ PARTIAL — 2 of 3"), "got: {h}");
        assert!(h.contains("existed-by"), "got: {h}");
    }

    #[test]
    fn record_only_verified_claims_integrity_scope_never_a_chain() {
        let checks = vec![pass("structure"), pass("identity binding"), pass("signature")];
        let h = verdict_headline(Verdict::Verified, &checks, Some(&rec()), None, None, None);
        assert!(h.contains("record's own integrity"), "got: {h}");
        assert!(!h.contains("FULL chain"), "got: {h}");
    }

    #[test]
    fn fully_bound_record_chain_headline_claims_the_full_chain() {
        let checks = vec![
            pass("structure"),
            pass("signature"),
            pass("record↔proof"),
            pass("record inclusion"),
            pass("inclusion↔seal"),
            pass("seal↔anchor"),
        ];
        assert!(chain_is_bound(&checks));
        let h = verdict_headline(
            Verdict::Verified,
            &checks,
            Some(&rec()),
            Some(&anchor(true)),
            None,
            None,
        );
        assert!(h.contains("FULL chain"), "got: {h}");
    }

    #[test]
    fn unbound_multi_object_verified_denies_the_full_chain() {
        // record + seal, each proven, zero binding legs — the headline must
        // not imply a chain (this is the EV-1 regression the audit warned on).
        let checks = vec![
            pass("structure"),
            pass("signature"),
            pass("seal signature"),
            pass("seal anchor"),
        ];
        assert!(!chain_is_bound(&checks));
        let h = verdict_headline(Verdict::Verified, &checks, Some(&rec()), None, None, None);
        assert!(h.contains("was\u{a0}not established") || h.contains("was not established"), "got: {h}");
        assert!(!h.contains("FULL chain holds"), "got: {h}");
    }

    #[test]
    fn absence_headline_is_about_the_sealed_instant_never_now() {
        let x = AccountExclusionFacts { identity: [7u8; 32], root: [9u8; 32] };
        // Tier 1: full absence chain (exclusion + root↔seal + seal↔anchor).
        let bound = vec![
            pass("account exclusion"),
            pass("account-root↔seal"),
            pass("seal↔anchor"),
        ];
        let h = verdict_headline(
            Verdict::Verified,
            &bound,
            None,
            Some(&anchor(true)),
            None,
            Some(&x),
        );
        assert!(h.contains("PROVABLY ABSENT"), "got: {h}");
        assert!(h.contains("epoch 42"), "got: {h}");
        assert!(h.contains("never about now"), "got: {h}");
        assert!(!h.to_lowercase().contains("currently"), "got: {h}");

        // Tier 2: seal-bound, no anchor — still an instant claim, never "now".
        let seal_only = vec![pass("account exclusion"), pass("account-root↔seal")];
        let h2 = verdict_headline(Verdict::Verified, &seal_only, None, None, None, Some(&x));
        assert!(h2.contains("seal committed to"), "got: {h2}");
        assert!(h2.contains("never about now"), "got: {h2}");

        // Tier 3: pinned root only.
        let pinned = vec![pass("account exclusion"), pass("sealed account-root bind")];
        let h3 = verdict_headline(Verdict::Verified, &pinned, None, None, None, Some(&x));
        assert!(h3.contains("root you pinned"), "got: {h3}");
        assert!(!h3.to_lowercase().contains("currently"), "got: {h3}");
    }
}
