//! elara-verify — offline Elara record + anchor verifier (READ-SIDE-STRATEGY
//! §1, thin slice).
//!
//! Single file in, plain-language verdict out. No node, no network, no
//! trust in us.
//!
//! **Record mode** (`<record>`) verifies, in order:
//!   1. **structure** — parses as a `ValidationRecord` (JSON, or wire with `--wire`)
//!   2. **binding** — the creator public key hashes (SHA3-256) to the claimed identity
//!   3. **signature** — Dilithium3 (ML-DSA-65), plus SPHINCS+ (SLH-DSA) for Profile A
//!   4. **content** — with `--content <file>`, SHA3-256 of your artifact == content hash
//!
//! **Anchor mode** (`--anchor <epoch-anchor.json>`) verifies the Bitcoin-anchored
//! time bracket around the seal, both legs, fully offline (each leg is trustless
//! only when it is cryptographically anchored — see below; otherwise a reference):
//!   - **NOT-BEFORE** — the artifact references a drand round whose publication
//!     time is fixed by the beacon's `genesis + period`, indicating the seal was
//!     created no earlier (lower bound). When the artifact carries the beacon's
//!     BLS signature it is verified against the PINNED League-of-Entropy key and
//!     the bound is trustless; signature-less (legacy) artifacts stay a reference.
//!   - **EXISTED-BY** — the `.ots` proof is a SHA-256 path from the artifact's
//!     hash into a Bitcoin block's merkle root; we walk it and confirm it lands
//!     on the merkle root of a block header archived next to the artifact. That
//!     header is the upper bound's trust root, so it must itself be authenticated:
//!     when its double-SHA256 matches a block hash PINNED in this verifier the
//!     bound is trustless; otherwise (no pin for that height) it is a REFERENCE
//!     bound whose strength rests on the operator-supplied header's authenticity —
//!     this offline tool cannot validate an arbitrary Bitcoin header (no PoW chain
//!     to a checkpoint), so it says so rather than implying a bound it cannot show.
//!     A still-pending or un-archived proof likewise says exactly that.
//!
//! **Seal mode** (`--seal <wire> --trusted-anchor <pubkey-hex>`) verifies a
//! fetched epoch-seal record is authentically signed by a caller-pinned anchor
//! key (the audited `light_verify::verify_seal_record_against_anchor` closure):
//! anchor membership + Dilithium3, plus an optional `--expected-hash` to pin
//! the seal's identity to a header you already trust.
//!
//! **Inclusion mode** (`--inclusion <proof.json>`) verifies a record-inclusion
//! proof (the `/zone/{zone}/proof/{record_hash}` payload): the record's hash is
//! a leaf under a zone's sparse-Merkle root, walked offline with sha3-256. With
//! `--expect-root <hex>` the proven root is bound to a sealed root you trust —
//! chaining record → seal → (via --seal + --anchor) a Bitcoin-anchored window.
//!
//! At least one of `<record>` / `--anchor` / `--seal` / `--inclusion` is
//! required; any may be combined.
//!
//! Exit codes: 0 = VERIFIED, 1 = verification FAILED, 2 = cannot read or
//! parse an input at all.
//!
//! Spec references:
//!   @spec docs/READ-SIDE-STRATEGY.md §1
//!   The drand round→time formula mirrors `src/network/time_bracket.rs`
//!   (§1045, `DrandPulse::not_before_unix`); it is reproduced here so the
//!   verifier stays standalone — the `network` module is `node-core`-gated and
//!   the whole point of this binary is "no node stack."

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;
use serde_json::Value;
use sha2::{Digest, Sha256};

// The verify LOGIC (every cryptographic/structural CHECK) lives at this
// crate's root so the WASM/browser build calls the IDENTICAL code with no
// drift. This module is the thin shell: it reads files, parses CLI flags, and
// renders prose/JSON. The anchor/OTS/drand-BLS legs live in `crate::anchor`
// (feature `verify-anchor`, required by `cli`) — shared with the wasm
// verifier since the 2026-07-06 flagship-audit step-4 move. The fallible legs
// below are thin wrappers that read the file(s) and map `Err(String)` →
// eprintln! + exit code.
// Still needed by the driver itself: `run` parses the record/seal wire/JSON, and
// the thin `verify_seal`/`verify_record` wrappers pass it through to the root.
use elara_record::receipt;
use elara_record::record::ValidationRecord;
// Every CHECK lives at the crate root. The driver calls the five fallible legs
// by the historical `verify_core::…` path (aliased to this crate below — the
// name every consumer knows from the node era) inside thin file-reading
// wrappers, and imports the shared types + the binding/summary predicates it
// renders.
use crate::{
    self as verify_core, account_absence_time_bracketed, account_chain_time_bracketed,
    chain_is_account_absence_bound, chain_is_account_bound, chain_is_bound, st,
    AccountExclusionFacts, AccountInclusionFacts, AnchorSummary, Check, InclusionFacts,
    RecordSummary, Status, Verdict,
};
// The anchor/OTS/drand legs, moved to `crate::anchor` (flagship-audit step 4)
// so the wasm verifier shares them. The driver keeps only the transport shims:
// file reads, the `.ots` sidecar probe, and the archived `btc-header-<h>.txt`
// lookup closure.
use crate::anchor::{
    drand_not_before_leg, existed_by_leg_from_bytes, flexible_u64, format_utc, seal_drand_leg,
    verify_anchor_obj, HeaderLoad,
};
// Receipt grading + the ONE cross-leg binding sequence (`bind_outcomes`),
// shared verbatim with the wasm verifier — the envelope only changes how
// evidence arrives, never what is proven.
use crate::grade::{
    bind_outcomes, grade_receipt_v1, record_leg, ContentArtifact, LegOutcomes, ReceiptDisplay,
    TrustPins,
};

#[derive(Parser)]
#[command(
    name = "elara-verify",
    version,
    about = "Offline Elara record + anchor + seal + inclusion verifier — no node, no network, no trust in us"
)]
pub struct Cli {
    /// Record file (JSON by default; pass --wire for canonical wire bytes).
    record: Option<PathBuf>,
    /// Treat the record file as canonical wire bytes instead of JSON.
    #[arg(long)]
    wire: bool,
    /// Artifact file to check against the record's content hash.
    #[arg(long)]
    content: Option<PathBuf>,
    /// Epoch-anchor artifact (the sidecar's epoch-N-zone-Z.json) — verify the
    /// Bitcoin existed-by / drand not-before time bracket.
    #[arg(long)]
    anchor: Option<PathBuf>,
    /// Anchor-proof MESH RECORD (canonical wire bytes, kind=anchor_proof) —
    /// the P1.5(b) record form of --anchor. Verifies the record signature,
    /// the artifact↔record content bind (sha3), the metadata↔artifact binding
    /// tuple (a record cannot lie about what it anchors), then the same
    /// drand not-before + Bitcoin existed-by legs as --anchor. BTC header
    /// files (btc-header-<height>.txt) are read from the record file's
    /// directory. Chain to a real seal with --seal + --trusted-anchor.
    #[arg(long = "anchor-record")]
    anchor_record: Option<PathBuf>,
    /// Epoch-seal record (canonical WIRE bytes) — verify it is signed by a
    /// pinned anchor key. Requires at least one --trusted-anchor.
    #[arg(long)]
    seal: Option<PathBuf>,
    /// Anchor public key (hex) the --seal record must be signed by. Repeatable;
    /// the seal's creator key must match one of them.
    #[arg(long = "trusted-anchor")]
    trusted_anchor: Vec<String>,
    /// Optional expected record hash (hex) for --seal, taken from a header you
    /// already trust; pins the seal's identity. Omitted → that one cross-check
    /// is skipped (and the verdict says so).
    #[arg(long)]
    expected_hash: Option<String>,
    /// Record-inclusion proof JSON (the `/zone/{zone}/proof/{record_hash}`
    /// payload) — verify the record's hash is in a zone's sealed Merkle root.
    #[arg(long)]
    inclusion: Option<PathBuf>,
    /// Optional sealed Merkle root (hex) the --inclusion / --account-inclusion
    /// proof's root must equal — binds it to a seal whose root you already trust.
    #[arg(long)]
    expect_root: Option<String>,
    /// Account-inclusion proof JSON (the `/proof/account/{identity}` payload) —
    /// verify an identity's SEALED account-state is committed in a sealed
    /// account-SMT root. This is the always-populated tree (the per-zone record
    /// SMT is empty on idle nodes), so the full chain is reproducible against any
    /// live node. Proves the at-last-seal snapshot, NOT the live balance, and NOT
    /// that any particular record exists. Bind to Bitcoin with --seal + --anchor.
    #[arg(long = "account-inclusion")]
    account_inclusion: Option<PathBuf>,
    /// Account NON-EXISTENCE proof JSON (the `/proof/account/{identity}` payload
    /// for an absent account) — verify the identity has NO leaf under the
    /// witness's account-SMT root (sound non-membership; same compressed
    /// 256-level SMT engine as --account-inclusion, folded from the EMPTY leaf).
    /// Proves absence AT THE WITNESS'S ROOT — as of the seal that committed it,
    /// once the root is bound — NOT "currently absent" and NOT absent forever.
    /// Pin the identity you queried with
    /// --expect-identity; bind the root with --seal (+ --anchor) or --expect-root.
    /// Mutually exclusive with --account-inclusion (one account claim per run).
    #[arg(long = "account-exclusion")]
    account_exclusion: Option<PathBuf>,
    /// Optional expected identity (hex) the --account-inclusion /
    /// --account-exclusion proof must be FOR. A valid proof for a DIFFERENT
    /// identity is still cryptographically sound but misattributed; this pins
    /// which identity you asked about (for absence, a misread identity INVERTS
    /// the claim — pin it).
    #[arg(long = "expect-identity")]
    expect_identity: Option<String>,
    /// Emit a machine-readable JSON verdict instead of prose.
    #[arg(long)]
    json: bool,
    /// `.elara-receipt` v1 evidence envelope (one file bundling record / seal /
    /// anchor / proof legs), or a bare `/record/<id>` JSON as a degenerate
    /// receipt. EVIDENCE ONLY: trust roots never ride in the receipt — compose
    /// with --trusted-anchor / --expected-hash / --expect-root /
    /// --expect-identity exactly as in flag mode (their absence grades PARTIAL).
    /// Mutually exclusive with the per-leg evidence flags.
    #[arg(long)]
    receipt: Option<PathBuf>,
}

// `Status`, `Verdict`, `Check`, `RecordSummary`, `AnchorSummary`, `st` and the
// `Verdict::of`/`label` logic now live in `elara_runtime::verify_core` (imported
// above) so the wasm/browser build shares the IDENTICAL types + verdict
// precedence. The one piece that CANNOT move is the exit-code mapping
// (`std::process::ExitCode` must stay out of the wasm-portable lib): it is
// reproduced here as a free function with the same Verified→0 / Partial→3 /
// Failed→1 mapping `Verdict::exit` had.
pub fn verdict_exit(v: Verdict) -> ExitCode {
    match v {
        Verdict::Verified => ExitCode::SUCCESS,
        Verdict::Partial => ExitCode::from(3),
        Verdict::Failed => ExitCode::from(1),
    }
}

/// The CLI driver — `main` of both the crate’s `elara-verify` bin and the
/// node repo’s root delegate bin. Parses argv, dispatches the verify legs,
/// renders prose/JSON, returns the process exit code.
pub fn run() -> ExitCode {
    let cli = Cli::parse();

    if cli.record.is_none()
        && cli.anchor.is_none()
        && cli.anchor_record.is_none()
        && cli.seal.is_none()
        && cli.inclusion.is_none()
        && cli.account_inclusion.is_none()
        && cli.account_exclusion.is_none()
        && cli.receipt.is_none()
    {
        eprintln!(
            "nothing to verify: pass a <record> file, --receipt, --anchor, --anchor-record, --seal, --inclusion, --account-inclusion, and/or --account-exclusion"
        );
        return ExitCode::from(2);
    }
    // Evidence comes from the receipt OR from per-leg flags, never both: a
    // receipt leg and a flag leg of the same kind would silently compete for
    // the same verdict slot, and the reader could not tell WHICH evidence the
    // verdict graded. Trust flags (--trusted-anchor / --expected-hash /
    // --expect-root / --expect-identity / --content) compose — they are pins,
    // not evidence.
    if cli.receipt.is_some()
        && (cli.record.is_some()
            || cli.anchor.is_some()
            || cli.anchor_record.is_some()
            || cli.seal.is_some()
            || cli.inclusion.is_some()
            || cli.account_inclusion.is_some()
            || cli.account_exclusion.is_some())
    {
        eprintln!("--receipt is mutually exclusive with the per-leg evidence flags (<record>, --anchor, --anchor-record, --seal, --inclusion, --account-inclusion, --account-exclusion) — evidence comes from the receipt OR from flags, never both");
        return ExitCode::from(2);
    }
    // Both fill the same anchor slot of the verdict; two competing anchor
    // sources would make the cross-leg binding ambiguous. One at a time.
    if cli.anchor.is_some() && cli.anchor_record.is_some() {
        eprintln!("pass ONE of --anchor / --anchor-record, not both");
        return ExitCode::from(2);
    }
    // One account CLAIM per run: presence and absence bind through the same
    // check names (`account-root↔seal` / `sealed account-root bind`) and share
    // --expect-identity, so running both at once would make the binding checks
    // and the verdict prose ambiguous about WHICH claim they grade. Two
    // identities' proofs (one present, one absent) = two invocations.
    if cli.account_inclusion.is_some() && cli.account_exclusion.is_some() {
        eprintln!("pass ONE of --account-inclusion / --account-exclusion, not both — one account claim per run (run twice for two identities)");
        return ExitCode::from(2);
    }

    let mut checks: Vec<Check> = Vec::new();
    // Facts every evidence leg learned — the receipt legs and the per-flag legs
    // fill the SAME struct, so the cross-leg binding pass (`grade::bind_outcomes`,
    // shared verbatim with the wasm verifier) is IDENTICAL for both transports.
    let mut out = LegOutcomes::default();
    // Advisory receipt metadata for the emitters (producer is displayed with a
    // provenance caveat, never graded).
    let mut receipt_display: Option<ReceiptDisplay> = None;
    // Resolve --content ONCE (whichever transport's record leg runs consumes
    // it): the artifact bytes, or the read-failure reason the record's content
    // check will FAIL with (never a silent skip).
    let content_label = cli
        .content
        .as_deref()
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    let content_bytes: Option<Result<Vec<u8>, String>> = cli.content.as_deref().map(|p| {
        std::fs::read(p).map_err(|e| format!("cannot read artifact {}: {e}", p.display()))
    });
    let content: Option<ContentArtifact> = match &content_bytes {
        None => None,
        Some(Ok(b)) => Some(ContentArtifact::Bytes(b, &content_label)),
        Some(Err(msg)) => Some(ContentArtifact::Unreadable(msg.clone())),
    };

    // ── Receipt: one-file evidence envelope (or bare-record degenerate) ──
    // Same legs, same verifiers, same binding pass as the flags below — the
    // envelope only changes how evidence ARRIVES, never what is proven. Trust
    // pins still come from the CLI (a receipt can never vouch for itself).
    if let Some(receipt_path) = &cli.receipt {
        let bytes = match read_bounded(receipt_path, receipt::RECEIPT_MAX_BYTES) {
            Ok(b) => b,
            Err(msg) => {
                eprintln!("{msg}");
                return ExitCode::from(2);
            }
        };
        match receipt::parse_receipt_input(&bytes) {
            Err(reason) => {
                eprintln!("{reason}");
                return ExitCode::from(2);
            }
            // The pre-v1 published convention (site/receipts.html:
            // `curl …/record/<id> > receipt.json`) or raw wire bytes — grades
            // exactly like `elara-verify <record>` (sniffed by the ELRA magic,
            // so no --wire flag is needed).
            Ok(receipt::ReceiptInput::BareRecord(raw)) => {
                let record: ValidationRecord = if raw.starts_with(b"ELRA") {
                    match ValidationRecord::from_bytes(&raw) {
                        Ok(r) => r,
                        Err(e) => {
                            eprintln!("receipt is neither a v1 envelope nor a valid wire record: {e}");
                            return ExitCode::from(2);
                        }
                    }
                } else {
                    match serde_json::from_slice(&raw) {
                        Ok(r) => r,
                        Err(e) => {
                            eprintln!("receipt is neither a v1 envelope nor a valid record JSON: {e}");
                            return ExitCode::from(2);
                        }
                    }
                };
                let (summary, hash) = record_leg(&record, content.as_ref(), &mut checks);
                out.record_summary = Some(summary);
                out.record_hash = Some(hash);
            }
            Ok(receipt::ReceiptInput::V1(legs)) => {
                let pins = TrustPins {
                    trusted_anchor: &cli.trusted_anchor,
                    expected_hash: cli.expected_hash.as_deref(),
                    expect_root: cli.expect_root.as_deref(),
                    expect_identity: cli.expect_identity.as_deref(),
                    content: content.as_ref(),
                };
                out = match grade_receipt_v1(&legs, &pins, &mut checks) {
                    Ok(out) => out,
                    Err(reason) => {
                        eprintln!("{reason}");
                        return ExitCode::from(2);
                    }
                };
                receipt_display = Some(ReceiptDisplay {
                    producer: legs.producer.clone(),
                    not_evaluated: legs.not_evaluated.clone(),
                });
            }
        }
    }

    // ── Record verification ─────────────────────────────────────────────
    if let Some(rec_path) = &cli.record {
        let bytes = match std::fs::read(rec_path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("cannot read {}: {e}", rec_path.display());
                return ExitCode::from(2);
            }
        };

        let record: ValidationRecord = if cli.wire {
            match ValidationRecord::from_bytes(&bytes) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("not a valid Elara wire record: {e}");
                    return ExitCode::from(2);
                }
            }
        } else {
            match serde_json::from_slice(&bytes) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!(
                        "not a valid Elara record JSON ({e}); if this is wire bytes, pass --wire"
                    );
                    return ExitCode::from(2);
                }
            }
        };

        let (summary, hash) = record_leg(&record, content.as_ref(), &mut checks);
        out.record_summary = Some(summary);
        out.record_hash = Some(hash);
    }

    // ── Anchor verification (Bitcoin existed-by / drand not-before legs) ─
    if let Some(anchor_path) = &cli.anchor {
        match verify_anchor(anchor_path, &mut checks) {
            Ok(summary) => out.anchor_summary = Some(summary),
            Err(code) => return code,
        }
    }

    // ── Anchor-proof RECORD verification (P1.5(b)) — fills the same anchor
    //    slot, so --seal chaining and the emit paths work identically. ─────
    if let Some(path) = &cli.anchor_record {
        match verify_anchor_record(path, &mut checks) {
            Ok(summary) => out.anchor_summary = Some(summary),
            Err(code) => return code,
        }
    }

    // ── Seal-record verification (signed by a pinned anchor) ────────────
    if let Some(seal_path) = &cli.seal {
        match verify_seal(
            seal_path,
            &cli.trusted_anchor,
            cli.expected_hash.as_deref(),
            &mut checks,
        ) {
            Ok(facts) => {
                out.seal_hash = Some(facts.own_hash);
                out.seal_roots = facts.committed_roots;
                out.seal_account_root = facts.committed_account_root;
            }
            Err(code) => return code,
        }
    }

    // ── Record-inclusion proof (record's hash is in a sealed Merkle root) ─
    if let Some(inclusion_path) = &cli.inclusion {
        match verify_inclusion(inclusion_path, cli.expect_root.as_deref(), &mut checks) {
            Ok(facts) => out.inclusion_facts = Some(facts),
            Err(code) => return code,
        }
    }

    // ── Account-inclusion proof (an identity's SEALED account-state is in a
    //    sealed account-SMT root). Distinct from the record path: the account
    //    SMT is the always-populated, always-sealed tree, so the full chain is
    //    reproducible on idle nodes where the record SMT is empty. ───────────
    if let Some(account_path) = &cli.account_inclusion {
        match verify_account_inclusion(account_path, cli.expect_identity.as_deref(), &mut checks) {
            Ok(facts) => out.account_facts = facts,
            Err(code) => return code,
        }
    }

    // ── Account-exclusion witness (an identity provably has NO leaf under a
    //    sealed account-SMT root — non-membership as of that seal). The absence
    //    twin of the block above; mutually exclusive with it (guard at entry). ──
    if let Some(path) = &cli.account_exclusion {
        match verify_account_exclusion(path, cli.expect_identity.as_deref(), &mut checks) {
            Ok(facts) => out.absence_facts = Some(facts),
            Err(code) => return code,
        }
    }

    // ── Cross-leg binding: prove the supplied objects are the SAME chain ─
    // The ONE sequence shared verbatim with the wasm verifier
    // (`verify_core::grade::bind_outcomes`) — record chain, account chain,
    // absence sealed-root ladder. An Err is a malformed --expect-root (exit 2).
    if let Err(reason) = bind_outcomes(&mut checks, &out, cli.expect_root.as_deref()) {
        eprintln!("{reason}");
        return ExitCode::from(2);
    }

    let verdict = Verdict::of(&checks);

    if cli.json {
        emit_json(
            &checks,
            &out.record_summary,
            &out.anchor_summary,
            out.account_facts.as_ref(),
            out.absence_facts.as_ref(),
            receipt_display.as_ref(),
            verdict,
        );
    } else {
        emit_prose(
            &checks,
            &out.record_summary,
            &out.anchor_summary,
            out.account_facts.as_ref(),
            out.absence_facts.as_ref(),
            receipt_display.as_ref(),
            verdict,
        );
    }

    verdict_exit(verdict)
}

// ── Thin file-reading wrappers around the verify_core legs ──────────────────
//
// `bind_chain`, `chain_is_bound`, `chain_is_account_bound`,
// `account_chain_time_bracketed`, `seal_committed_roots`, `hash32_from_hex`,
// `hash32_from_json`, and the `InclusionFacts` / `AccountInclusionFacts` types
// are PURE and now live in `elara_runtime::verify_core` (imported above) — the
// browser/wasm build shares the IDENTICAL logic. What stays here are the five
// fallible/IO legs as thin wrappers that keep the binary's ORIGINAL signatures:
// they read the file(s) and map the core's `Err(String)` → `eprintln!` + the
// SAME exit code today's CLI returns.

/// Verify a fetched epoch-seal record (canonical wire bytes) is authentically
/// signed by a caller-pinned anchor key. Thin wrapper: reads the seal file and
/// delegates to `verify_core::verify_seal`, mapping a malformed/unreadable input
/// to exit 2 (the original behavior).
pub fn verify_seal(
    seal_path: &Path,
    trusted_anchors_hex: &[String],
    expected_hash_hex: Option<&str>,
    checks: &mut Vec<Check>,
) -> Result<verify_core::SealFacts, ExitCode> {
    let wire = match std::fs::read(seal_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("cannot read seal {}: {e}", seal_path.display());
            return Err(ExitCode::from(2));
        }
    };
    match verify_core::verify_seal(&wire, trusted_anchors_hex, expected_hash_hex, checks) {
        Ok(out) => {
            seal_drand_leg(&wire, checks);
            Ok(out)
        }
        Err(reason) => {
            eprintln!("{reason}");
            Err(ExitCode::from(2))
        }
    }
}

/// Read at most `cap` bytes from `path`, rejecting (not truncating) larger
/// files — the same read-bounded-before-allocate discipline as the OTS
/// sidecar read (`take(cap+1)`: a file over the cap lands at cap+1 and is
/// refused rather than truncate-and-lie).
pub fn read_bounded(path: &Path, cap: usize) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let f = std::fs::File::open(path)
        .map_err(|e| format!("cannot read receipt {}: {e}", path.display()))?;
    let mut buf = Vec::new();
    f.take(cap as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("cannot read receipt {}: {e}", path.display()))?;
    if buf.len() > cap {
        return Err(format!(
            "receipt {} exceeds the {cap} byte envelope cap",
            path.display()
        ));
    }
    Ok(buf)
}

/// Verify a record-inclusion proof. Thin wrapper: reads the proof file and
/// delegates to `verify_core::verify_inclusion`, mapping a malformed/unreadable
/// input to exit 2.
pub fn verify_inclusion(
    proof_path: &Path,
    expect_root_hex: Option<&str>,
    checks: &mut Vec<Check>,
) -> Result<InclusionFacts, ExitCode> {
    let bytes = match std::fs::read(proof_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("cannot read inclusion proof {}: {e}", proof_path.display());
            return Err(ExitCode::from(2));
        }
    };
    match verify_core::verify_inclusion(&bytes, expect_root_hex, checks) {
        Ok(facts) => Ok(facts),
        Err(reason) => {
            eprintln!("{reason}");
            Err(ExitCode::from(2))
        }
    }
}

/// Verify a `/proof/account/{identity}` account-inclusion proof. Thin wrapper:
/// reads the proof file and delegates to `verify_core::verify_account_inclusion`,
/// mapping a malformed/unreadable input (or a non-inclusion payload) to exit 2.
pub fn verify_account_inclusion(
    proof_path: &Path,
    expect_identity_hex: Option<&str>,
    checks: &mut Vec<Check>,
) -> Result<Option<AccountInclusionFacts>, ExitCode> {
    let bytes = match std::fs::read(proof_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("cannot read account-inclusion proof {}: {e}", proof_path.display());
            return Err(ExitCode::from(2));
        }
    };
    match verify_core::verify_account_inclusion(&bytes, expect_identity_hex, checks) {
        Ok(facts) => Ok(facts),
        Err(reason) => {
            eprintln!("{reason}");
            Err(ExitCode::from(2))
        }
    }
}

/// Verify a `/proof/account/{identity}` NON-EXISTENCE witness. Thin wrapper:
/// reads the witness file and delegates to `verify_core::verify_account_exclusion`,
/// mapping a malformed/mis-routed input (an inclusion payload, a pending-first-seal
/// response, a witness-less bare-root claim) to exit 2.
pub fn verify_account_exclusion(
    proof_path: &Path,
    expect_identity_hex: Option<&str>,
    checks: &mut Vec<Check>,
) -> Result<AccountExclusionFacts, ExitCode> {
    let bytes = match std::fs::read(proof_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("cannot read account-exclusion proof {}: {e}", proof_path.display());
            return Err(ExitCode::from(2));
        }
    };
    match verify_core::verify_account_exclusion(&bytes, expect_identity_hex, checks) {
        Ok(facts) => Ok(facts),
        Err(reason) => {
            eprintln!("{reason}");
            Err(ExitCode::from(2))
        }
    }
}

/// Parse an archived `btc-header-<height>.txt`: returns (merkle_root, block unix
/// time) from its 80-byte `blockstream_header` (or `mempool_header`) line. The
/// merkle root is bytes 36..68 in the header's stored (internal) byte order —
/// returned RAW, which is exactly what an OTS proof's SHA-256 path arrives at
/// (Bitcoin hashes the root in this order; only display reverses it).
pub fn load_btc_header(dir: &Path, height: u64) -> HeaderLoad {
    let path = dir.join(format!("btc-header-{height}.txt"));
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        // A genuinely missing file is ABSENT (→ PARTIAL); any other read error
        // (e.g. invalid UTF-8 in a present file) is BROKEN (→ FAIL).
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return HeaderLoad::Absent,
        Err(e) => return HeaderLoad::Broken(format!("cannot read header file: {e}")),
    };
    let hexhdr = match text
        .lines()
        .find_map(|l| l.strip_prefix("blockstream_header:").map(str::trim))
        .or_else(|| {
            text.lines()
                .find_map(|l| l.strip_prefix("mempool_header:").map(str::trim))
        }) {
        Some(h) => h,
        None => {
            return HeaderLoad::Broken("no blockstream_header:/mempool_header: line".into())
        }
    };
    let raw = match hex::decode(hexhdr) {
        Ok(r) => r,
        Err(e) => return HeaderLoad::Broken(format!("header is not valid hex: {e}")),
    };
    if raw.len() != 80 {
        return HeaderLoad::Broken(format!("header is {} bytes, expected 80", raw.len()));
    }
    let mut mr = [0u8; 32];
    mr.copy_from_slice(&raw[36..68]);
    let ts = u32::from_le_bytes([raw[68], raw[69], raw[70], raw[71]]);
    // double-SHA256 of the 80-byte header (internal byte order) is the Bitcoin
    // block hash — used to authenticate the header against a compiled-in pin.
    let mut block_hash = [0u8; 32];
    block_hash.copy_from_slice(&Sha256::digest(Sha256::digest(&raw)));
    HeaderLoad::Found(mr, ts, block_hash)
}

/// Verify an epoch-anchor artifact's Bitcoin existed-by + drand not-before legs. Returns
/// the summary on success, or an `ExitCode` to terminate with when the file
/// can't be read or isn't an anchor artifact at all (exit 2).
pub fn verify_anchor(path: &Path, checks: &mut Vec<Check>) -> Result<AnchorSummary, ExitCode> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("cannot read anchor {}: {e}", path.display());
            return Err(ExitCode::from(2));
        }
    };
    let obj: Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("not a valid anchor JSON: {e}");
            return Err(ExitCode::from(2));
        }
    };

    let mut summary = match verify_anchor_obj(&obj, checks) {
        Ok(s) => s,
        Err(reason) => {
            eprintln!("{reason} ({})", path.display());
            return Err(ExitCode::from(2));
        }
    };
    // The existed-by leg is evidence-transport-specific (an .ots SIDECAR FILE
    // next to the artifact), so it stays here with the file path — the receipt
    // path pushes its own honest PARTIAL instead.
    summary.has_ots_sidecar = ots_path(path).exists();
    dispatch_existed_by_leg(&mut summary, path, &bytes, checks);
    Ok(summary)
}

/// Verify an anchor-proof MESH RECORD (P1.5(b)) — the record form of
/// `--anchor`. The binding chain, in order (each its own check):
///
///   1. wire parse + creator signature + identity binding  (verify_core)
///   2. sha3(artifact bytes) == record.content_hash        (verify_core, content leg)
///   3. metadata binding tuple == artifact fields           ("anchor binding")
///   4. drand not-before leg over the artifact              (shared with --anchor)
///   5. OTS existed-by leg over the EXACT artifact bytes    (shared with --anchor)
///
/// Steps 3–5 are what stop a record carrying a REAL OTS proof for different
/// bytes from claiming to bracket a seal it never touched. BTC headers are
/// read from the record file's directory (same convention as --anchor).
pub fn verify_anchor_record(path: &Path, checks: &mut Vec<Check>) -> Result<AnchorSummary, ExitCode> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("cannot read anchor record {}: {e}", path.display());
            return Err(ExitCode::from(2));
        }
    };
    let record = match ValidationRecord::from_bytes(&bytes) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("not a valid Elara wire record: {e}");
            return Err(ExitCode::from(2));
        }
    };
    let fields = match crate::anchor_proof::parse_anchor_proof_metadata(&record.metadata) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("not an anchor_proof record: {e}");
            return Err(ExitCode::from(2));
        }
    };

    // Steps 1–2: structure, identity, signature(s), and the content leg —
    // the artifact decoded from metadata must hash (sha3) to content_hash,
    // binding the verbatim artifact bytes to this producer-signed record.
    verify_core::verify_record(
        &record,
        Some(&fields.artifact_bytes),
        "anchor artifact (anchor_artifact_b64)",
        checks,
    );

    // Step 3: the metadata binding tuple must MATCH the artifact the OTS
    // proof commits to. The tuple is producer-asserted; the artifact is
    // what Bitcoin actually vouches for. Any mismatch = the record lies.
    let obj: Value = match serde_json::from_slice(&fields.artifact_bytes) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("anchor_artifact_b64 does not decode to JSON: {e}");
            return Err(ExitCode::from(2));
        }
    };
    let art_epoch = flexible_u64(obj.get("epoch"));
    let art_seal = obj.get("seal_hash").and_then(|v| v.as_str()).unwrap_or("");
    let art_zone = obj.get("zone").and_then(|v| v.as_str()).unwrap_or("");
    let (epoch, seal_hash) = match (art_epoch, art_seal) {
        (Some(e), s) if !s.is_empty() => (e, s.to_string()),
        _ => {
            eprintln!(
                "embedded artifact is not an Elara epoch-anchor (needs epoch + seal_hash)"
            );
            return Err(ExitCode::from(2));
        }
    };
    let tuple_ok = fields.anchor_digest.eq_ignore_ascii_case(&seal_hash)
        && fields.anchor_epoch == epoch
        && fields.anchor_zone == art_zone;
    checks.push(Check {
        name: "anchor binding",
        status: st(tuple_ok),
        detail: if tuple_ok {
            format!(
                "record's anchor_(digest,epoch,zone) == embedded artifact ({}, {epoch}, {art_zone})",
                short(&seal_hash),
            )
        } else {
            format!(
                "record CLAIMS (digest {}, epoch {}, zone {}) but the OTS-committed artifact \
                 says (seal {}, epoch {epoch}, zone {art_zone}) — the record lies about what \
                 it anchors",
                short(&fields.anchor_digest),
                fields.anchor_epoch,
                fields.anchor_zone,
                short(&seal_hash),
            )
        },
    });

    // Steps 4–5: identical legs to --anchor, sourced from record fields.
    // Summary facts come from the ARTIFACT (what Bitcoin vouches for),
    // never from the record's self-asserted tuple.
    let leg = drand_not_before_leg(&obj, checks);
    let mut summary = AnchorSummary {
        epoch,
        seal_hash,
        not_before_unix: leg.not_before_unix,
        not_before_trustless: leg.not_before_trustless,
        beacon_label: leg.beacon_label,
        assumed_default_beacon: leg.assumed_default,
        has_ots_sidecar: true, // the proof rides IN the record (anchor_ots_b64)
        existed_by_unix: None,
        existed_by_height: None,
        existed_by_trustless: false,
    };
    let header_dir = path.parent().unwrap_or_else(|| Path::new("."));
    existed_by_leg_from_bytes(
        &mut summary,
        &fields.artifact_bytes,
        Some(&fields.ots_bytes),
        &mut |height| load_btc_header(header_dir, height),
        checks,
    );
    Ok(summary)
}

/// The existed-by (OTS → Bitcoin / TSA) leg of `verify_anchor`, split out
/// when the drand leg was extracted so both stay independently readable.
/// Mutates `summary`'s existed-by fields and pushes its checks.
pub fn dispatch_existed_by_leg(
    summary: &mut AnchorSummary,
    path: &Path,
    bytes: &[u8],
    checks: &mut Vec<Check>,
) {
    let ots_bytes = if summary.has_ots_sidecar {
        // Bound the sidecar read. An honest OTS proof is a few KB; the ops
        // budget (OTS_MAX_OPS) caps computation but only AFTER the bytes are in
        // memory, so read a bounded prefix first — otherwise a multi-GB sidecar
        // file would try to allocate its full size and abort the process on
        // out-of-memory instead of exiting cleanly. 4 MiB is far above any real
        // proof and still trivially allocatable on a phone-tier node.
        const MAX_OTS_SIDECAR_BYTES: u64 = 4 * 1024 * 1024;
        use std::io::Read;
        Some(match std::fs::File::open(ots_path(path)) {
            Ok(f) => {
                let mut buf = Vec::new();
                // take(CAP+1): if the file exceeds the cap, `buf.len()`
                // lands at CAP+1 and we reject rather than truncate-and-lie.
                if f.take(MAX_OTS_SIDECAR_BYTES + 1).read_to_end(&mut buf).is_ok()
                    && buf.len() as u64 > MAX_OTS_SIDECAR_BYTES
                {
                    Vec::new() // treated as unreadable below → clean Fail, never OOM
                } else {
                    buf
                }
            }
            Err(_) => Vec::new(),
        })
    } else {
        None
    };
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    existed_by_leg_from_bytes(
        summary,
        bytes,
        ots_bytes.as_deref(),
        &mut |height| load_btc_header(dir, height),
        checks,
    );
}

/// `<path>.ots` — the OpenTimestamps sidecar proof for an anchor artifact.
pub fn ots_path(anchor: &Path) -> PathBuf {
    let mut s = anchor.as_os_str().to_owned();
    s.push(".ots");
    PathBuf::from(s)
}

/// First 16 hex chars (or the whole string if shorter), for compact display.
pub fn short(hex: &str) -> String {
    hex.chars().take(16).collect()
}

pub fn emit_json(
    checks: &[Check],
    record: &Option<RecordSummary>,
    anchor: &Option<AnchorSummary>,
    account: Option<&AccountInclusionFacts>,
    absence: Option<&AccountExclusionFacts>,
    receipt: Option<&ReceiptDisplay>,
    verdict: Verdict,
) {
    let mut out = serde_json::json!({
        "checks": checks.iter().map(|c| serde_json::json!({
            // `status` is the authoritative tri-state; `pass` is kept as a bool
            // alias (true ONLY for a proven Pass) for backward-compatible consumers.
            "name": c.name, "status": c.status.as_str(), "pass": c.status == Status::Pass, "detail": c.detail,
        })).collect::<Vec<_>>(),
        "verdict": verdict.label(),
        // The same gates-driven one-liner the prose emitter leads with — never
        // free text, never stronger than the chain-binding gates proved.
        "headline": verify_core::verdict_headline(
            verdict, checks, record.as_ref(), anchor.as_ref(), account, absence,
        ),
        "exit": match verdict { Verdict::Verified => 0, Verdict::Partial => 3, Verdict::Failed => 1 },
    });
    if let Some(r) = record {
        out["record_id"] = Value::from(r.id.clone());
        out["creator"] = Value::from(r.creator_hex.clone());
        out["timestamp_claimed"] = Value::from(r.timestamp);
        out["time_note"] = Value::from(
            "the record's own timestamp is the creator's claim; any --anchor time bracket is the ANCHORED SEAL's existence window, which binds this record only if the full chain is proven — the record↔proof, record inclusion, inclusion↔seal and seal↔anchor checks all present and Pass",
        );
    }
    if let Some(a) = anchor {
        out["anchor"] = serde_json::json!({
            "epoch": a.epoch,
            "seal_hash": a.seal_hash,
            "not_before_unix": a.not_before_unix,
            "not_before_utc": a.not_before_unix.map(|t| format_utc(t as f64)),
            "not_before_trustless": a.not_before_trustless,
            "not_before_note": if a.not_before_trustless {
                "trustless lower bound: the beacon's BLS signature verified against the pinned League-of-Entropy key"
            } else {
                "reference lower bound: round->time only; the beacon BLS signature was not verified (legacy/signature-less artifact or unknown chain)"
            },
            "beacon": a.beacon_label,
            "assumed_default_beacon": a.assumed_default_beacon,
            "existed_by_unix": a.existed_by_unix,
            "existed_by_utc": a.existed_by_unix.map(|t| format_utc(t as f64)),
            "existed_by_btc_block": a.existed_by_height,
            "existed_by_note": if a.existed_by_trustless {
                "trustless upper bound: the OTS proof commits into the named Bitcoin block, and the archived header is authenticated against a block hash pinned in the verifier"
            } else if a.existed_by_unix.is_some() {
                "reference upper bound: the OTS proof commits into the named Bitcoin block and the archived header is internally consistent, but the header is NOT pin-authenticated — its strength rests on the (operator-supplied) header's authenticity, which you must establish independently (e.g. check the block on any Bitcoin explorer)"
            } else if a.has_ots_sidecar {
                "an .ots proof is present but no confirmed+archived Bitcoin block yet (pending, or its header is not archived locally)"
            } else {
                "no .ots proof alongside this artifact; the existed-by (Bitcoin) upper bound is unverified"
            },
        });
    }
    if let Some(acct) = account {
        // `chain_linked` = the account root is bound into an anchor-named seal.
        // `bound_to_bitcoin` ADDITIONALLY requires the anchor to have proven a
        // trustless time bound — chain linkage alone is NOT a Bitcoin bracket, and
        // a machine consumer must not read one as the other.
        out["account"] = serde_json::json!({
            "identity": hex::encode(acct.identity),
            "sealed_state_hash": hex::encode(acct.state_hash),
            "account_smt_root": hex::encode(acct.root),
            "chain_linked": chain_is_account_bound(checks),
            "bound_to_bitcoin": account_chain_time_bracketed(checks, anchor.as_ref()),
            "note": "proves the SEALED account-state snapshot at the last seal, NOT the live balance and NOT any record; bound_to_bitcoin requires a proven anchor time bracket, not just chain linkage",
        });
    }
    if let Some(x) = absence {
        // Absence is a claim ABOUT a specific sealed root, never about "now" —
        // a machine consumer must scope it to that root/seal or it will read a
        // historical absence as a live one (the account may exist by the time
        // this JSON is parsed).
        out["account_absence"] = serde_json::json!({
            "identity": hex::encode(x.identity),
            "account_smt_root": hex::encode(x.root),
            "chain_linked": chain_is_account_absence_bound(checks),
            "bound_to_bitcoin": account_absence_time_bracketed(checks, anchor.as_ref()),
            "note": "proves NON-membership at the named sealed account-SMT root — absence AS OF that seal, NOT 'currently absent' and NOT absent forever; meaningless until the root is bound to a seal you trust (see the sealed-root bind check)",
        });
    }
    if let Some(r) = receipt {
        // Producer is whoever WROTE the receipt file — a machine consumer must
        // never treat it as verified fact (it is outside every signature).
        out["receipt"] = serde_json::json!({
            "producer": r.producer.clone().unwrap_or(serde_json::Value::Null),
            "legs_not_evaluated": r.not_evaluated,
            "note": "producer is self-declared by the receipt file — advisory, never graded; legs_not_evaluated non-empty caps the verdict at PARTIAL",
        });
    }
    println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
}

pub fn emit_prose(
    checks: &[Check],
    record: &Option<RecordSummary>,
    anchor: &Option<AnchorSummary>,
    account: Option<&AccountInclusionFacts>,
    absence: Option<&AccountExclusionFacts>,
    receipt: Option<&ReceiptDisplay>,
    verdict: Verdict,
) {
    // The one-line gates-driven headline (verify_core::verdict_headline) leads;
    // the per-check narrative and VERDICT block below remain the substance.
    println!(
        "{}",
        verify_core::verdict_headline(
            verdict,
            checks,
            record.as_ref(),
            anchor.as_ref(),
            account,
            absence,
        )
    );
    println!();
    for c in checks {
        println!("  {} {:<17} {}", c.status.glyph(), c.name, c.detail);
    }
    println!();

    match verdict {
        Verdict::Failed => {
            println!("VERDICT: FAILED — do not rely on this input.");
            return;
        }
        Verdict::Partial => println!(
            "VERDICT: PARTIAL — nothing is forged, but at least one bound is UNPROVEN \
             (see the ⚠ check(s) above). Treat only the ✓ bounds as established."
        ),
        Verdict::Verified => println!("VERDICT: VERIFIED"),
    }
    if let Some(r) = record {
        println!(
            "         this exact content was signed by {}…,",
            &r.creator_hex[..16],
        );
        println!(
            "         who claims it existed at {} (UTC, the creator's own claim).",
            format_utc(r.timestamp),
        );
    }
    if let Some(a) = anchor {
        // Is the record proven to be INSIDE this anchor's seal? Only when EVERY
        // link of the chain record → proof.root → seal → anchor is green (see
        // `chain_is_bound`). Otherwise the bracket below is the SEAL's existence
        // window, and the record is a separate, independently-verified object —
        // the bracket says nothing about the record. (This juxtaposition — "this
        // content was signed" directly above "≤ sealed content ≤" — was the
        // misleading prose that implied an unproven chain.)
        let chain_bound = chain_is_bound(checks);
        let nb = a.not_before_unix.map(|t| format_utc(t as f64));
        let eb = a.existed_by_unix.map(|t| format_utc(t as f64));
        let bracketed = if chain_bound { "this record's seal" } else { "the anchored seal" };
        match (nb, eb) {
            (Some(nb), Some(eb)) => {
                println!("         TIME BRACKET (seal {}…):", &short(&a.seal_hash));
                println!("           {nb} UTC  ≤  {bracketed} existed  ≤  {eb} UTC");
                println!(
                    "           lower = drand round publication ({}); upper = Bitcoin block {} (archived header — {}).",
                    if a.not_before_trustless {
                        "BLS-verified — trustless"
                    } else {
                        "reference"
                    },
                    a.existed_by_height.unwrap_or(0),
                    if a.existed_by_trustless {
                        "pin-authenticated, trustless"
                    } else {
                        "reference — not pin-authenticated"
                    },
                );
            }
            (Some(nb), None) => {
                println!(
                    "         TIME BRACKET — not-before {nb} UTC ({}, {}).",
                    if a.not_before_trustless {
                        "drand BLS-verified — trustless"
                    } else {
                        "drand reference — BLS not verified"
                    },
                    a.beacon_label,
                );
                if a.has_ots_sidecar {
                    println!(
                        "         Existed-by (Bitcoin) upper bound: not confirmed offline — see the existed-by check above."
                    );
                } else {
                    println!(
                        "         Existed-by (Bitcoin) upper bound: no .ots proof alongside — unverified."
                    );
                }
            }
            _ => {}
        }
        if record.is_some() && !chain_bound {
            println!(
                "         NOTE: the record and the anchor were verified INDEPENDENTLY — this run does NOT prove the record is inside the bracketed seal. Add --inclusion <proof> + --seal <wire>: the proof's root is then matched to a root the seal cryptographically committed to, binding the chain record→seal→anchor."
            );
        }
    } else if record.is_some() {
        println!(
            "         Trustless time bracketing requires an --anchor proof — not given here."
        );
    }
    if let Some(acct) = account {
        // What an account proof attests is categorically NOT what a record proof
        // attests — say so plainly so a reader never reads "balance" or "record"
        // into a sealed-state membership proof.
        println!(
            "         ACCOUNT: identity {}… held SEALED state-hash {}… — the at-last-seal snapshot, NOT the live balance, and NOT any record.",
            short(&hex::encode(acct.identity)),
            short(&hex::encode(acct.state_hash)),
        );
        let root_bound = checks.iter().any(|c| {
            (c.name == "account-root↔seal" || c.name == "sealed account-root bind")
                && c.status == Status::Pass
        });
        // `chain_is_account_bound` means the account root is bound into an
        // anchor-NAMED seal — but `seal↔anchor` only proves the anchor commits to
        // this seal's hash, NOT that the anchor's time legs were proven. Claiming
        // a "Bitcoin-bracketed / trustless time window" additionally requires the
        // anchor to have actually proven a bound (a BLS-verified drand not-before
        // or an archived-block existed-by). Without that the bracket is UNPROVEN
        // and saying otherwise would be exactly the overstatement this tool forbids.
        if account_chain_time_bracketed(checks, anchor.as_ref()) {
            println!(
                "         This sealed account-state is committed in the Bitcoin-bracketed seal above — bound trustlessly to that time window."
            );
        } else if chain_is_account_bound(checks) {
            println!(
                "         Committed in the anchor-named seal above, but that seal's Bitcoin/drand time bracket is UNPROVEN here (see the ⚠ checks) — the binding holds, the time window does not."
            );
        } else if root_bound {
            println!(
                "         Bound to a sealed account-SMT root you trust; add --seal + --anchor (with a proven Bitcoin/drand bracket) to place it in a trustless time window."
            );
        } else {
            println!(
                "         The account-SMT root is self-declared — add --seal <wire> (+ --anchor) or --expect-root <sealed-root-hex> to bind it to a root you trust."
            );
        }
    }
    if let Some(x) = absence {
        // Absence framing discipline: the claim is scoped to ONE sealed root —
        // "provably absent AT root R, as of its seal". Never "currently absent"
        // (the account may exist by the time this line is read) and never
        // "absent forever" (any later seal may add it).
        println!(
            "         ACCOUNT ABSENCE: identity {}… has NO leaf under account-SMT root {}… — provably absent AT that sealed root (as of its seal), NOT 'currently absent' and NOT absent forever.",
            short(&hex::encode(x.identity)),
            short(&hex::encode(x.root)),
        );
        let root_bound = checks.iter().any(|c| {
            (c.name == "account-root↔seal" || c.name == "sealed account-root bind")
                && c.status == Status::Pass
        });
        if account_absence_time_bracketed(checks, anchor.as_ref()) {
            println!(
                "         That root belongs to the Bitcoin-bracketed seal above — the absence is pinned trustlessly to that epoch's time window."
            );
        } else if chain_is_account_absence_bound(checks) {
            println!(
                "         The root belongs to the anchor-named seal above, but that seal's Bitcoin/drand time bracket is UNPROVEN here (see the ⚠ checks) — the absence binds to the seal, not to a proven time window."
            );
        } else if root_bound {
            println!(
                "         Bound to a sealed account-SMT root you trust; add --seal + --anchor (with a proven Bitcoin/drand bracket) to place the absence in a trustless time window."
            );
        } else {
            println!(
                "         CAUTION: the root is self-declared by the witness — an absence claim is only as strong as its root binding (any witness folds to SOME root; an empty tree 'proves' anything absent). Add --seal <wire> (+ --anchor) or --expect-root <sealed-root-hex> from a seal you verified."
            );
        }
        if checks.iter().all(|c| c.name != "account identity") {
            println!(
                "         (Tip: add --expect-identity <hex> to pin WHICH identity's absence you asked about — a valid witness for a different identity proves nothing about yours.)"
            );
        }
        // Parity with the record leg's independence NOTE: when an anchor's time
        // bracket printed above but the absence is not itself proven into that
        // bracket, say so — never let juxtaposition imply the link (EV-1).
        if anchor.is_some() && !account_absence_time_bracketed(checks, anchor.as_ref()) {
            println!(
                "         (Any time bracket above is the anchored seal's existence window — it does NOT apply to this absence unless every absence-chain link is ✓.)"
            );
        }
    }
    if let Some(r) = receipt {
        if let Some(p) = &r.producer {
            // Single line, compact — and explicitly outside the proof surface:
            // the producer field is written by whoever made the receipt file.
            println!(
                "         (Receipt producer, self-declared — NOT verified by any check above: {})",
                serde_json::to_string(p).unwrap_or_default(),
            );
        }
    }
}

