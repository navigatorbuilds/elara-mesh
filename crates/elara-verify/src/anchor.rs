//! Anchor-leg verification — drand not-before (BLS against the pinned
//! League-of-Entropy key) and OTS→Bitcoin existed-by — moved out of the
//! `elara-verify` binary so the wasm verifier reaches full-chain parity
//! (verifier-flagship fusion audit 2026-07-06, step 4: "extend, not spike").
//!
//! Gated behind the `verify-anchor` feature (pulls `sha2` + `drand-verify`,
//! both pure Rust and wasm32-proven: bls12_381/pairing carry no C, no rng, no
//! fs). The node build does not pay for BLS12-381 unless it opts in; the
//! `verify-cli` feature includes this, and `verify-wasm` enables it directly.
//!
//! Everything here is path-free: functions take already-read bytes / parsed
//! JSON. The ONE transport hook is `existed_by_leg_from_bytes`'s
//! `lookup_header` closure — the CLI resolves archived `btc-header-<h>.txt`
//! files next to the artifact; a browser caller returns [`HeaderLoad::Absent`]
//! (honest PARTIAL) until it grows a header-supply UI. Trust pins
//! (`PINNED_BTC_HEADER_HASHES`, `LOE_DEFAULT_PUBKEY_HEX`) are compiled in —
//! never read from the (attacker-supplied) evidence.

use serde_json::Value;
use sha2::{Digest, Sha256};

use drand_verify::{derive_randomness, G1Pubkey, Pubkey};

/// Re-exported so callers (CLI tests, wasm shims) can derive drand randomness
/// = sha256(signature) without importing `drand-verify` themselves.
pub use drand_verify::derive_randomness as drand_derive_randomness;

use super::{short, AnchorSummary, Check, Status};
use elara_record::record::ValidationRecord;

/// League-of-Entropy default chained beacon — the chain `api.drand.sh` serves
/// at `/public/latest` (no chain hash in the path). Used as the fallback for
/// legacy anchor artifacts written before the sidecar emitted self-describing
/// `drand_genesis_unix` / `drand_period_secs` fields, AND as the pinned trust
/// root for BLS verification (see `LOE_DEFAULT_PUBKEY_HEX`). These are public,
/// well-known constants — the same role the Bitcoin genesis hash plays in an
/// OTS verifier. Values authoritative as of `curl https://api.drand.sh/info`.
pub const LOE_DEFAULT_GENESIS_UNIX: u64 = 1_595_431_050;
pub const LOE_DEFAULT_PERIOD_SECS: u64 = 30;
pub const LOE_DEFAULT_CHAIN_HASH: &str =
    "8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce";

/// Pinned group public key (48-byte G1, hex) of the League-of-Entropy default
/// `pedersen-bls-chained` beacon. This is the trust root that makes the drand
/// not-before TRUSTLESS: an artifact's own `drand_public_key` is NOT trusted —
/// the signature is verified against THIS pinned key, so a forged artifact that
/// supplies its own (key, signature) pair cannot pass. Identical to the value
/// in `drand-verify`'s `G1Pubkey` doctest and the live beacon `/info`.
pub const LOE_DEFAULT_PUBKEY_HEX: &str =
    "868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31";

/// drand round → publication time (unix seconds). Round 1 is emitted at
/// `genesis_unix`; each subsequent round adds one `period`. Round 0 clamps to
/// round 1 (drand rounds are 1-indexed). Saturating throughout — a hostile
/// artifact cannot overflow us into a wrong (small) bound.
///
/// Canonical source: `src/network/time_bracket.rs::DrandPulse::not_before_unix`
/// (§1045, verified against the drand spec + Sui/Filecoin). Reproduced here
/// because that module is `node-core`-gated and this module must stay node-free.
pub fn drand_not_before(round: u64, genesis_unix: u64, period_secs: u64) -> u64 {
    let rounds_after_genesis = round.saturating_sub(1);
    genesis_unix.saturating_add(rounds_after_genesis.saturating_mul(period_secs))
}

/// Outcome of attempting to verify the drand beacon's BLS signature — the check
/// that upgrades the not-before from a reference bound to a trustless one.
#[derive(Debug, PartialEq, Eq)]
pub enum DrandBls {
    /// Signature verified against the PINNED LoE key — the not-before is trustless.
    Verified,
    /// Cannot verify offline (no signature stored, unknown chain, …). The
    /// not-before stands as a reference bound. Carries the human reason.
    Reference(String),
    /// A signature WAS present but did not verify — forged or corrupt artifact.
    Failed(String),
}

/// Verify the drand beacon signature an anchor artifact carries, against the
/// PINNED League-of-Entropy public key — NOT the artifact's own claimed key, so
/// a passing result is trustless (a forged artifact cannot substitute its own
/// beacon). Fully offline. For the default `pedersen-bls-chained` beacon the
/// signed message is `H(previous_signature || round)`, so the chained
/// `previous_signature` must be present. drand randomness is `sha256(signature)`,
/// cross-checked here as a belt-and-suspenders bind.
pub fn verify_drand_bls(
    obj: &Value,
    round: u64,
    chain_hash: Option<&str>,
    assumed_default: bool,
) -> DrandBls {
    let sig_hex = obj
        .get("drand_signature")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if sig_hex.is_empty() {
        return DrandBls::Reference(
            "the beacon's BLS signature is not in this artifact — legacy anchors stored only \
             round + randomness, and randomness is a one-way hash of the signature"
                .into(),
        );
    }
    // Trustless verification needs a pinned key for a KNOWN chain. Only the LoE
    // default chain is pinned here; any other chain stays a reference bound.
    let is_default = assumed_default
        || chain_hash
            .map(|h| h.eq_ignore_ascii_case(LOE_DEFAULT_CHAIN_HASH))
            .unwrap_or(false);
    if !is_default {
        return DrandBls::Reference(format!(
            "no pinned public key for {} — cannot verify its signature offline",
            chain_hash.map(short).unwrap_or_else(|| "this chain".into()),
        ));
    }
    // If the artifact ships its own pubkey it MUST equal the pinned one; a
    // mismatch means it is trying to substitute a forged beacon key.
    if let Some(pk) = obj.get("drand_public_key").and_then(|v| v.as_str()) {
        if !pk.is_empty() && !pk.eq_ignore_ascii_case(LOE_DEFAULT_PUBKEY_HEX) {
            return DrandBls::Failed(
                "artifact's drand_public_key does not match the pinned League-of-Entropy key"
                    .into(),
            );
        }
    }
    let sig = match hex::decode(sig_hex) {
        Ok(b) => b,
        Err(_) => return DrandBls::Failed("signature is not valid hex".into()),
    };
    let prev_hex = obj
        .get("drand_previous_signature")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if prev_hex.is_empty() {
        return DrandBls::Reference(
            "chained beacon: previous_signature absent, so the signed message cannot be \
             reconstructed offline"
                .into(),
        );
    }
    let prev = match hex::decode(prev_hex) {
        Ok(b) => b,
        Err(_) => return DrandBls::Failed("previous_signature is not valid hex".into()),
    };
    let pk_bytes: [u8; 48] = match hex::decode(LOE_DEFAULT_PUBKEY_HEX)
        .ok()
        .and_then(|v| v.try_into().ok())
    {
        Some(b) => b,
        None => return DrandBls::Failed("pinned LoE public key is malformed (build bug)".into()),
    };
    let pk = match G1Pubkey::from_fixed(pk_bytes) {
        Ok(p) => p,
        Err(e) => return DrandBls::Failed(format!("pinned key rejected: {e:?}")),
    };
    match pk.verify(round, &prev, &sig) {
        Ok(true) => {
            // drand randomness == sha256(signature); if the artifact carries it,
            // it must agree with the signature we just verified.
            if let Some(rnd) = obj.get("drand_randomness").and_then(|v| v.as_str()) {
                if !rnd.is_empty() && !hex::encode(derive_randomness(&sig)).eq_ignore_ascii_case(rnd)
                {
                    return DrandBls::Failed("randomness does not equal sha256(signature)".into());
                }
            }
            DrandBls::Verified
        }
        Ok(false) => DrandBls::Failed("BLS pairing check failed".into()),
        Err(e) => DrandBls::Failed(format!("{e:?}")),
    }
}

/// Extract a u64 from a JSON value that may be a number OR a quoted string —
/// the sidecar historically wrote `"drand_round": "6192366"` (string).
pub fn flexible_u64(v: Option<&Value>) -> Option<u64> {
    match v? {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.trim().parse::<u64>().ok(),
        _ => None,
    }
}

/// Outcome of the drand not-before leg, consumed by `AnchorSummary` on the
/// anchor path and reported check-only on the --seal path.
pub struct DrandLegOutcome {
    pub not_before_unix: Option<u64>,
    pub not_before_trustless: bool,
    pub beacon_label: String,
    pub assumed_default: bool,
}

/// The drand not-before leg, shared by epoch-anchor artifacts and seal
/// records — both carry the same `drand_*` key contract (the seal keys are
/// written by `time_bracket.rs::write_metadata`, the artifact ones by
/// `scripts/elara-epoch-anchor.sh`). Grades Verified→Pass /
/// Reference→Partial / Failed→Fail, and never upgrades a bound whose
/// genesis/period the BLS signature cannot vouch for (the
/// `loe_param_conflict` fail-closed gate).
pub fn drand_not_before_leg(obj: &Value, checks: &mut Vec<Check>) -> DrandLegOutcome {
    let round = flexible_u64(obj.get("drand_round"));
    let self_genesis = flexible_u64(obj.get("drand_genesis_unix"));
    let self_period = flexible_u64(obj.get("drand_period_secs"));
    let self_chain = obj
        .get("drand_chain_hash")
        .and_then(|v| v.as_str())
        .map(String::from);

    // SECURITY — drand parameter authentication (fail-closed). The beacon BLS
    // signature binds only (round, previous_signature); it does NOT cover the
    // chain's genesis/period. For the pinned League-of-Entropy chain those two
    // are well-known CONSTANTS, so an artifact that explicitly claims the LoE
    // chain (its hash matches the pinned constant — the same gate that lets its
    // signature verify against the pinned key and earn a TRUSTLESS bound) yet
    // supplies genesis/period differing from the constants is forged or corrupt:
    // it is replaying a real beacon round while mapping it to an attacker-chosen
    // instant under the trustless badge. Refuse it below. Non-LoE chains keep
    // their own self-declared parameters — their bound is reference-only anyway
    // (no pinned key), so it can never be stamped trustless.
    let loe_param_conflict = self_chain
        .as_deref()
        .map(|h| h.eq_ignore_ascii_case(LOE_DEFAULT_CHAIN_HASH))
        .unwrap_or(false)
        && ((self_genesis.is_some() && self_genesis != Some(LOE_DEFAULT_GENESIS_UNIX))
            || (self_period.is_some() && self_period != Some(LOE_DEFAULT_PERIOD_SECS)));

    let (genesis_unix, period_secs, chain_hash, assumed_default) =
        match (self_genesis, self_period) {
            (Some(g), Some(p)) if p > 0 => (g, p, self_chain, false),
            _ => (
                LOE_DEFAULT_GENESIS_UNIX,
                LOE_DEFAULT_PERIOD_SECS,
                Some(LOE_DEFAULT_CHAIN_HASH.to_string()),
                true,
            ),
        };

    let beacon_label = match &chain_hash {
        Some(h) => format!("drand chain {}", &short(h)),
        None => "drand (unidentified chain)".to_string(),
    };

    let mut outcome = DrandLegOutcome {
        not_before_unix: None,
        not_before_trustless: false,
        beacon_label: beacon_label.clone(),
        assumed_default,
    };

    match round {
        // Forged LoE timing: the artifact claims the pinned chain (so its real
        // beacon signature would verify against the pinned key and earn a
        // trustless bound) but supplies genesis/period the signature cannot
        // vouch for. Fail closed before any trustless upgrade — see
        // `loe_param_conflict` above. Ordered before the `r > 0` arm so a
        // conflicting artifact never reaches the BLS path.
        Some(_) if loe_param_conflict => {
            checks.push(Check {
                name: "drand not-before",
                status: Status::Fail,
                detail: format!(
                    "artifact claims the League-of-Entropy chain but its \
                     drand_genesis_unix/drand_period_secs differ from the pinned \
                     constants ({LOE_DEFAULT_GENESIS_UNIX}/{LOE_DEFAULT_PERIOD_SECS}s); \
                     the beacon BLS signature does not cover those fields, so a \
                     not-before derived from them is forgeable — refusing to treat \
                     it as trustless"
                ),
            });
        }
        Some(r) if r > 0 => {
            let nb = drand_not_before(r, genesis_unix, period_secs);
            outcome.not_before_unix = Some(nb);
            let default_note = if assumed_default {
                " (assuming the League-of-Entropy default beacon — this artifact \
                 predates self-describing drand fields)"
            } else {
                ""
            };
            // Try to UPGRADE the reference bound to a trustless one by verifying
            // the beacon's BLS signature against the PINNED LoE key (never the
            // artifact's own claimed key — that is what makes a pass trustless).
            let bls = verify_drand_bls(obj, r, chain_hash.as_deref(), assumed_default);
            outcome.not_before_trustless = matches!(bls, DrandBls::Verified);
            let (status, detail) = match bls {
                DrandBls::Verified => (
                    Status::Pass,
                    format!(
                        "seal cites {beacon_label} round {r}, published {} UTC — TRUSTLESS \
                         not-before: the beacon's BLS signature VERIFIES against the pinned \
                         League-of-Entropy key{default_note}",
                        format_utc(nb as f64),
                    ),
                ),
                // Reference-only: the round→time arithmetic is sound but the
                // beacon BLS signature was NOT verified (legacy/signature-less
                // artifact or unknown chain). This is the symmetric "unproven
                // lower bound" of an unconfirmed upper bound — PARTIAL, never a
                // green Pass, so a stripped-signature anchor cannot earn exit 0.
                DrandBls::Reference(why) => (
                    Status::Partial,
                    format!(
                        "seal cites {beacon_label} round {r}, mapped to {} UTC by round→time \
                         arithmetic — REFERENCE ONLY, not trustless: the beacon BLS signature \
                         was NOT verified ({why}){default_note}",
                        format_utc(nb as f64),
                    ),
                ),
                DrandBls::Failed(why) => (
                    Status::Fail,
                    format!(
                        "seal cites {beacon_label} round {r} but its drand BLS signature DOES \
                         NOT VERIFY ({why}) — the not-before is forged or corrupt"
                    ),
                ),
            };
            checks.push(Check {
                name: "drand not-before",
                status,
                detail,
            });
        }
        _ => {
            // No usable round at all: the lower bound is ABSENT, not forged —
            // PARTIAL (an honest "no not-before could be established"). Only
            // reachable on the anchor path — the --seal caller gates the leg
            // on `drand_round` presence, so a pulse-less seal never lands here.
            checks.push(Check {
                name: "drand not-before",
                status: Status::Partial,
                detail: "artifact carries no usable drand round — no \
                         not-before lower bound can be established"
                    .into(),
            });
        }
    }

    outcome
}

/// Seal-drand leg (REALMS P1.5 a3), shared by `--seal` and the receipt's seal
/// leg: a seal whose metadata carries a drand pulse gets the same not-before
/// grading as an anchor artifact — the anchor signature (already verified by
/// `verify_seal`) covers metadata (it lives inside `signable_bytes()`), so the
/// pulse is producer-signed. A pulse-less seal skips the leg entirely: the
/// pulse is OPTIONAL and absence must not downgrade a valid seal's exit code.
/// A pulse WITHOUT its BLS signature grades Partial (reference bound),
/// matching the anchor semantics.
pub fn seal_drand_leg(wire: &[u8], checks: &mut Vec<Check>) {
    if let Ok(rec) = ValidationRecord::from_bytes(wire) {
        if rec.metadata.contains_key("drand_round") {
            let drand_obj = Value::Object(
                rec.metadata
                    .iter()
                    .filter(|(k, _)| k.starts_with("drand_"))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect(),
            );
            drand_not_before_leg(&drand_obj, checks);
        }
    }
}

/// The path-free legs of an epoch-anchor artifact — structure + drand
/// not-before — shared by `--anchor` (file), the receipt's embedded `anchor`
/// leg, and the wasm verifier so they can never drift. The Bitcoin existed-by
/// leg is NOT here: it needs the `.ots` sidecar, which is transport-specific
/// (`has_ots_sidecar` starts false; the file path overrides it).
pub fn verify_anchor_obj(obj: &Value, checks: &mut Vec<Check>) -> Result<AnchorSummary, String> {
    // Must look like an Elara epoch-anchor artifact: epoch + seal_hash.
    let epoch = flexible_u64(obj.get("epoch"));
    let seal_hash = obj.get("seal_hash").and_then(|v| v.as_str()).map(String::from);
    let (epoch, seal_hash) = match (epoch, seal_hash) {
        (Some(e), Some(s)) if !s.is_empty() => (e, s),
        _ => {
            return Err(
                "not an Elara epoch-anchor artifact (needs epoch + seal_hash)".to_string()
            );
        }
    };

    checks.push(Check {
        name: "anchor structure",
        status: Status::Pass,
        detail: format!("epoch-anchor for epoch {epoch} (seal {})", &short(&seal_hash)),
    });

    // drand not-before leg — shared with the --seal path (a seal record's
    // pulse writes the identical `drand_*` keys, so both artifact kinds grade
    // through one implementation).
    let leg = drand_not_before_leg(obj, checks);

    Ok(AnchorSummary {
        epoch,
        seal_hash,
        not_before_unix: leg.not_before_unix,
        not_before_trustless: leg.not_before_trustless,
        beacon_label: leg.beacon_label,
        assumed_default_beacon: leg.assumed_default,
        has_ots_sidecar: false,
        existed_by_unix: None,
        existed_by_height: None,
        existed_by_trustless: false,
    })
}

// ── OpenTimestamps EXISTED-BY leg (OTS → Bitcoin, fully offline) ─────────────
//
// An `.ots` proof is a SHA-256 commitment path from the artifact's digest into a
// Bitcoin block's merkle root. We walk it OFFLINE and confirm the path lands
// exactly on the merkle root of a block header archived next to the artifact —
// then that block's timestamp is an UPPER bound on when the sealed content
// existed. The bound is TRUSTLESS only when the archived header is authenticated
// against a block hash PINNED in this verifier; an unpinned header yields a
// REFERENCE bound (its strength rests on the operator-supplied header being a
// genuine Bitcoin block). No calendar server, no Bitcoin node, no `ots` CLI.
//
// Wire format (python-opentimestamps DetachedTimestampFile):
//   magic b"\x00OpenTimestamps\x00\x00Proof\x00" + 8 magic bytes + version varint
//   file op (0x08 = sha256) + 32-byte digest         ← must equal sha256(artifact)
//   a recursive timestamp tree of:
//     0x08 sha256 (unary)  |  0xf0 append <varbytes>  |  0xf1 prepend <varbytes>
//     0xff  → another branch of the tree follows (repeats before the last branch)
//     0x00 <8-byte attestation tag> <varbytes payload>   (Bitcoin tag → block height)

/// python-opentimestamps `BitcoinBlockHeaderAttestation.TAG`.
pub const OTS_BITCOIN_TAG: [u8; 8] = [0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01];
/// Bound total ops walked — a hostile proof cannot fan us out into unbounded
/// work or deep recursion (real proofs are ~100 ops; this is far above that).
pub const OTS_MAX_OPS: usize = 4096;

#[derive(Clone)]
pub struct BitcoinAttestation {
    pub height: u64,
    /// The committed digest at the attestation point. Bitcoin hashes the merkle
    /// root in its internal (little-endian) byte order, so this equals the block
    /// header's merkle-root field (bytes 36..68) DIRECTLY. (`ots info` displays
    /// it byte-reversed per Bitcoin's big-endian display convention — the raw
    /// committed bytes are what we compare.)
    pub merkle_root: [u8; 32],
}

/// Read an OTS base-128 varint (LEB128, little-endian groups, high bit = more).
/// `pub` for the decoder fuzz gate — hostile-byte fail-closed sweeps call it raw.
pub fn read_varint(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    loop {
        let b = *buf.get(*pos)?;
        *pos += 1;
        result |= ((b & 0x7f) as u64).checked_shl(shift)?;
        if b & 0x80 == 0 {
            return Some(result);
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
}

/// Read a length-prefixed byte string (varint length, then that many bytes).
/// `pub` for the decoder fuzz gate.
pub fn read_varbytes<'a>(buf: &'a [u8], pos: &mut usize) -> Option<&'a [u8]> {
    let len = read_varint(buf, pos)? as usize;
    let start = *pos;
    let end = start.checked_add(len)?;
    let slice = buf.get(start..end)?;
    *pos = end;
    Some(slice)
}

/// Parse a `.ots` proof, verify it commits to `expected_file_sha256`, and return
/// every Bitcoin attestation found (height + the committed merkle root). `Err`
/// on a malformed proof or a file-hash mismatch (the proof is for another file).
pub fn ots_bitcoin_attestations(
    ots: &[u8],
    expected_file_sha256: &[u8; 32],
) -> Result<Vec<BitcoinAttestation>, String> {
    const MAGIC: &[u8] = b"\x00OpenTimestamps\x00\x00Proof\x00";
    const VER_MAGIC: [u8; 8] = [0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94];

    if !ots.starts_with(MAGIC) {
        return Err("not an OpenTimestamps proof (bad magic)".into());
    }
    let mut pos = MAGIC.len();
    if ots.get(pos..pos + 8) != Some(&VER_MAGIC[..]) {
        return Err("unrecognized OTS version magic".into());
    }
    pos += 8;
    let _version = read_varint(ots, &mut pos).ok_or("truncated OTS version")?;

    // File-hash op: sha256 (0x08) + 32-byte digest.
    match ots.get(pos) {
        Some(0x08) => pos += 1,
        _ => return Err("OTS file op is not sha256 (unsupported)".into()),
    }
    let file_digest = ots.get(pos..pos + 32).ok_or("truncated OTS file digest")?;
    pos += 32;
    if file_digest != expected_file_sha256 {
        return Err(format!(
            "proof is for a different file (commits to {}…, artifact hashes to {}…)",
            &hex::encode(file_digest)[..16],
            &hex::encode(expected_file_sha256)[..16],
        ));
    }

    let mut out = Vec::new();
    let mut budget = OTS_MAX_OPS;
    ots_walk(ots, &mut pos, file_digest, &mut out, &mut budget)?;
    Ok(out)
}

/// Walk the timestamp tree from message `msg` (the current digest), collecting
/// Bitcoin attestations. Mirrors python-opentimestamps `Timestamp.deserialize`:
/// a run of `0xff`-separated branches, then a last one.
///
/// ITERATIVE by construction — an earlier mutually-recursive version (walk ⇄
/// do-tag, one level per chained op) let a hostile ~4 KB proof of `OTS_MAX_OPS`
/// chained sha256 ops overflow the call stack (caught by
/// `ots_recursion_depth_probe_returns_err_not_stack_overflow`, 2026-07-02; a
/// stack overflow ABORTS — it cannot be caught, so it must be unreachable).
/// Suspended parent walks live on an explicit heap stack whose depth is bounded
/// by the same `budget` that bounds total ops.
fn ots_walk(
    buf: &[u8],
    pos: &mut usize,
    msg: &[u8],
    out: &mut Vec<BitcoinAttestation>,
    budget: &mut usize,
) -> Result<(), String> {
    // Parent digests suspended mid-branch-run, awaiting their child walk.
    let mut stack: Vec<Vec<u8>> = Vec::new();
    let mut msg = msg.to_vec();
    // A fresh walk entry pays budget; a parent resumed off the stack already
    // paid on ITS entry. Mirrors the recursive version: one unit per walk.
    let mut fresh = true;
    'walk: loop {
        if fresh {
            if *budget == 0 {
                return Err("OTS proof exceeds operation budget (possible DoS)".into());
            }
            *budget -= 1;
            fresh = false;
        }
        let mut tag = *buf.get(*pos).ok_or("truncated OTS (expected tag)")?;
        *pos += 1;
        while tag == 0xff {
            let branch_tag = *buf.get(*pos).ok_or("truncated OTS (branch tag)")?;
            *pos += 1;
            if branch_tag == 0x00 {
                // Attestation leaf — stay in this walk's branch run.
                ots_attestation(buf, pos, &msg, out)?;
            } else {
                // Op opens a child walk; suspend this walk until it finishes.
                let child = ots_apply_op(buf, pos, branch_tag, &msg)?;
                stack.push(msg);
                msg = child;
                fresh = true;
                continue 'walk;
            }
            tag = *buf.get(*pos).ok_or("truncated OTS (tag after branch)")?;
            *pos += 1;
        }
        // Final (non-branch) tag of this walk.
        if tag == 0x00 {
            ots_attestation(buf, pos, &msg, out)?;
            // This walk is complete — resume the suspended parent, or done.
            match stack.pop() {
                Some(parent) => msg = parent,
                None => return Ok(()),
            }
        } else {
            // Tail-position op: the child walk replaces this one (no suspend).
            msg = ots_apply_op(buf, pos, tag, &msg)?;
            fresh = true;
        }
    }
}

/// Parse one attestation (`0x00` tag already consumed): 8-byte type tag +
/// varbytes payload. Bitcoin attestations record (height, committed digest);
/// pending / unknown attestations are not a trustless bound — ignored.
fn ots_attestation(
    buf: &[u8],
    pos: &mut usize,
    msg: &[u8],
    out: &mut Vec<BitcoinAttestation>,
) -> Result<(), String> {
    let att_tag = buf
        .get(*pos..*pos + 8)
        .ok_or("truncated OTS attestation tag")?;
    let is_bitcoin = att_tag == OTS_BITCOIN_TAG;
    *pos += 8;
    let payload = read_varbytes(buf, pos).ok_or("truncated OTS attestation payload")?;
    if is_bitcoin {
        // payload = varint(block height); msg = the committed merkle root.
        let mut pp = 0usize;
        let height =
            read_varint(payload, &mut pp).ok_or("malformed Bitcoin attestation height")?;
        if msg.len() != 32 {
            return Err("Bitcoin attestation over a non-32-byte digest".into());
        }
        let mut root = [0u8; 32];
        root.copy_from_slice(msg);
        out.push(BitcoinAttestation { height, merkle_root: root });
    }
    Ok(())
}

/// Apply one OTS operation to `msg`, returning the new digest/message. Only the
/// ops Bitcoin calendar proofs use (sha256 / append / prepend) are supported.
fn ots_apply_op(buf: &[u8], pos: &mut usize, tag: u8, msg: &[u8]) -> Result<Vec<u8>, String> {
    match tag {
        0x08 => Ok(Sha256::digest(msg).to_vec()),
        0xf0 => {
            let operand = read_varbytes(buf, pos).ok_or("truncated append operand")?;
            let mut v = Vec::with_capacity(msg.len() + operand.len());
            v.extend_from_slice(msg);
            v.extend_from_slice(operand);
            Ok(v)
        }
        0xf1 => {
            let operand = read_varbytes(buf, pos).ok_or("truncated prepend operand")?;
            let mut v = Vec::with_capacity(operand.len() + msg.len());
            v.extend_from_slice(operand);
            v.extend_from_slice(msg);
            Ok(v)
        }
        other => Err(format!(
            "unsupported OTS op 0x{other:02x} (Bitcoin proofs need sha256/append/prepend only)"
        )),
    }
}

/// Pinned Bitcoin block hashes (double-SHA256 of the 80-byte header, in INTERNAL
/// byte order) for the blocks this project's own anchors commit into. This is the
/// trust anchor that makes the existed-by leg TRUSTLESS: an archived header is
/// authenticated ONLY when its double-SHA256 equals the pin compiled into THIS
/// binary — never a hash read from the (operator-supplied) bundle. Each pin is a
/// real mainnet block hash, independently auditable against any Bitcoin explorer
/// (the conventional display hash is the byte-reverse of the stored value).
///
/// Heights ABSENT from this table cannot be authenticated offline (full SPV would
/// need a header chain to a checkpoint) → their existed-by leg is a REFERENCE
/// bound (PARTIAL), never a trustless Pass. Extend this table as new epochs anchor.
const PINNED_BTC_HEADER_HASHES: &[(u64, [u8; 32])] = &[
    // block 953657 — display 00000000000000000000d2d19c330bfca44c19de152b6c1e7edc2a05271a9d44
    // (the pre-re-genesis demo anchor, epoch 3217 — superseded in examples/verify/
    // but timelessly valid; the pin stays so archived bundles keep verifying).
    (
        953657,
        [
            0x44, 0x9d, 0x1a, 0x27, 0x05, 0x2a, 0xdc, 0x7e, 0x1e, 0x6c, 0x2b, 0x15, 0xde, 0x19,
            0x4c, 0xa4, 0xfc, 0x0b, 0x33, 0x9c, 0xd1, 0xd2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ],
    ),
    // block 957487 — display 000000000000000000016be5b78cad8d66b755feea252ee460e22e42a6288319
    // (the examples/verify/ demo seal's Bitcoin anchor: epoch 41340, zone 0 —
    // the same live-chain seal the account-chain legs bind into).
    (
        957487,
        [
            0x19, 0x83, 0x28, 0xa6, 0x42, 0x2e, 0xe2, 0x60, 0xe4, 0x2e, 0x25, 0xea, 0xfe, 0x55,
            0xb7, 0x66, 0x8d, 0xad, 0x8c, 0xb7, 0xe5, 0x6b, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ],
    ),
];

/// The pinned double-SHA256 block hash for `height`, if the verifier ships one.
pub fn pinned_btc_hash(height: u64) -> Option<[u8; 32]> {
    PINNED_BTC_HEADER_HASHES
        .iter()
        .find(|(h, _)| *h == height)
        .map(|(_, hash)| *hash)
}

/// Outcome of loading an archived Bitcoin block header. Distinguishes a
/// genuinely ABSENT header (operator hasn't archived it — honest gap, PARTIAL)
/// from a PRESENT-but-unparseable one (corrupt/tampered evidence — FAIL).
pub enum HeaderLoad {
    /// (merkle_root [bytes 36..68], block unix time, double-SHA256 block hash)
    Found([u8; 32], u32, [u8; 32]),
    Absent,
    Broken(String),
}

/// The existed-by leg over in-memory bytes — shared by the CLI's file path
/// (`--anchor`, OTS from the `.ots` sidecar next to the artifact), the record
/// path (`--anchor-record`, OTS decoded from `anchor_ots_b64`), and any
/// browser caller. `lookup_header` resolves a Bitcoin block height to an
/// archived header — the ONE transport-specific hook (the CLI reads
/// `btc-header-<height>.txt` next to the artifact; a caller with no header
/// source returns [`HeaderLoad::Absent`], which grades an honest PARTIAL).
pub fn existed_by_leg_from_bytes(
    summary: &mut AnchorSummary,
    artifact_bytes: &[u8],
    ots_bytes: Option<&[u8]>,
    lookup_header: &mut dyn FnMut(u64) -> HeaderLoad,
    checks: &mut Vec<Check>,
) {
    // ── EXISTED-BY leg: OTS proof → Bitcoin, offline against archived headers ──
    // The upper bound is LOAD-BEARING. Absent .ots / pending OTS / un-archived
    // header → PARTIAL (honestly unproven, exit 3). A PRESENT-but-broken header
    // or a root mismatch → FAIL (tampered/inconsistent evidence, exit 1). The
    // leg is never silently dropped and never a false green Pass.
    if let Some(ots_bytes) = ots_bytes {
        let mut file_sha = [0u8; 32];
        file_sha.copy_from_slice(&Sha256::digest(artifact_bytes));
        match ots_bitcoin_attestations(ots_bytes, &file_sha) {
            Ok(attestations) if attestations.is_empty() => {
                // Proof is well-formed and for this file, but not yet anchored.
                checks.push(Check {
                    name: "existed-by",
                    status: Status::Partial,
                    detail: ".ots proof is PENDING calendar aggregation — no Bitcoin \
                             attestation yet (normal for anchors < ~a day old); the \
                             existed-by upper bound is NOT YET provable offline"
                        .into(),
                });
            }
            Ok(attestations) => {
                // confirmed_pinned: the archived header's double-SHA256 matched a
                // block hash PINNED in this binary → genuinely trustless. The pin
                // is the trust anchor an offline tool cannot otherwise establish
                // (full SPV would need a header chain to a checkpoint).
                // confirmed_reference: the header's merkle root matched the OTS
                // proof, but the header is NOT pin-authenticated — its strength
                // rests entirely on the (operator-supplied) header being a genuine
                // Bitcoin block, which this tool did not verify → reference-only.
                let mut confirmed_pinned: Vec<(u64, u32)> = Vec::new();
                let mut confirmed_reference: Vec<(u64, u32)> = Vec::new();
                let mut mismatched = 0usize;
                let mut pin_mismatch: Vec<u64> = Vec::new();
                let mut broken: Vec<(u64, String)> = Vec::new();
                let mut unarchived: Vec<u64> = Vec::new();
                for att in &attestations {
                    match lookup_header(att.height) {
                        HeaderLoad::Found(hdr_root, blocktime, block_hash)
                            if hdr_root == att.merkle_root =>
                        {
                            match pinned_btc_hash(att.height) {
                                Some(pin) if pin == block_hash => {
                                    confirmed_pinned.push((att.height, blocktime));
                                }
                                // Header for a pinned height but the wrong block
                                // hash → substituted/forged header (the exact
                                // operator-bundle tampering the pin exists to catch).
                                Some(_) => pin_mismatch.push(att.height),
                                None => confirmed_reference.push((att.height, blocktime)),
                            }
                        }
                        HeaderLoad::Found(..) => mismatched += 1, // present but root disagrees
                        HeaderLoad::Broken(why) => broken.push((att.height, why)),
                        HeaderLoad::Absent => unarchived.push(att.height),
                    }
                }
                if mismatched > 0 {
                    checks.push(Check {
                        name: "existed-by",
                        status: Status::Fail,
                        detail: format!(
                            "{mismatched} Bitcoin attestation(s) commit to a merkle root that \
                             does NOT match the archived block header — proof is inconsistent"
                        ),
                    });
                } else if let Some(height) = pin_mismatch.first() {
                    checks.push(Check {
                        name: "existed-by",
                        status: Status::Fail,
                        detail: format!(
                            "archived header for Bitcoin block {height} does NOT match the block \
                             hash PINNED in this verifier — the header is forged or substituted"
                        ),
                    });
                } else if let Some((height, why)) = broken.first() {
                    // A header file is PRESENT but won't parse — corrupt evidence,
                    // not innocent absence. Fail closed (distinct from unarchived).
                    checks.push(Check {
                        name: "existed-by",
                        status: Status::Fail,
                        detail: format!(
                            "archived header for Bitcoin block {height} is PRESENT but \
                             structurally invalid ({why}) — possible tampering"
                        ),
                    });
                } else if let Some(&(height, blocktime)) =
                    confirmed_pinned.iter().min_by_key(|(_, t)| *t)
                {
                    // Pin-authenticated → genuinely trustless upper bound.
                    summary.existed_by_unix = Some(blocktime as u64);
                    summary.existed_by_height = Some(height);
                    summary.existed_by_trustless = true;
                    checks.push(Check {
                        name: "existed-by",
                        status: Status::Pass,
                        detail: format!(
                            "OTS proof commits the seal into Bitcoin block {height}; the archived \
                             header is authenticated against the block hash PINNED in this verifier \
                             — TRUSTLESS, existed by {} UTC",
                            format_utc(blocktime as f64),
                        ),
                    });
                } else if let Some(&(height, blocktime)) =
                    confirmed_reference.iter().min_by_key(|(_, t)| *t)
                {
                    // Root matches the OTS proof but the header is not pinned: the
                    // bound is REFERENCE-only, NOT trustless. The header is from the
                    // (operator-supplied) bundle and is unauthenticated by this
                    // offline tool — honest PARTIAL, never a trustless Pass.
                    summary.existed_by_unix = Some(blocktime as u64);
                    summary.existed_by_height = Some(height);
                    checks.push(Check {
                        name: "existed-by",
                        status: Status::Partial,
                        detail: format!(
                            "OTS proof commits the seal into Bitcoin block {height} and the archived \
                             header is internally consistent with it (existed by {} UTC) — but the \
                             header is NOT pin-authenticated, so this is a REFERENCE bound, not \
                             trustless: it is only as strong as the header's authenticity, which you \
                             must establish (check block {height} on any Bitcoin explorer, or add \
                             its hash to the verifier's pin set)",
                            format_utc(blocktime as f64),
                        ),
                    });
                } else {
                    let heights = unarchived
                        .iter()
                        .map(|h| h.to_string())
                        .collect::<Vec<_>>()
                        .join(",");
                    checks.push(Check {
                        name: "existed-by",
                        status: Status::Partial,
                        detail: format!(
                            "OTS proof carries Bitcoin attestation(s) (block {heights}) but their \
                             headers are not archived next to this artifact — fetch them to bound \
                             existed-by offline (upper bound UNPROVEN here)"
                        ),
                    });
                }
            }
            Err(e) => {
                checks.push(Check {
                    name: "existed-by",
                    status: Status::Fail,
                    detail: format!("OTS proof malformed or not for this artifact: {e}"),
                });
            }
        }
    } else {
        // No .ots sidecar at all: the upper bound is ABSENT. Push an explicit
        // PARTIAL check — never silently drop the leg (an omitted check is
        // indistinguishable from one that passed).
        checks.push(Check {
            name: "existed-by",
            status: Status::Partial,
            detail: "no .ots sidecar alongside this artifact — the Bitcoin \
                     existed-by upper bound is UNPROVEN (absent, not forged)"
                .into(),
        });
    }
}

/// Render a unix-seconds float as a UTC string without pulling in chrono —
/// civil-date math from days-since-epoch (Howard Hinnant's algorithm).
pub fn format_utc(ts: f64) -> String {
    if !ts.is_finite() || ts < 0.0 {
        return format!("{ts} (unparseable)");
    }
    let secs = ts as u64;
    let (days, rem) = (secs / 86_400, secs % 86_400);
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{m:02}:{s:02}")
}
