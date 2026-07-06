//! Offline mandate-chain **bundle** verifier — the reason-to-exist
//! differentiator (authority-to-act), made verifiable with **zero trust in any
//! server** the same way [`crate::verify_core`] makes a single record verifiable
//! offline.
//!
//! A *bundle* is a small JSON envelope carrying the SIGNED carrier records that
//! together answer "was this agent authorized?": the agent's act record, the
//! mandate(s) it chains through, and any revocations. This module re-runs the
//! EXACT pure verdict core the live node's `GET /mandate/status` calls
//! ([`crate::mandate::evaluate_mandate_v0_with_lineage`]) against an in-memory
//! resolver rebuilt from the bundle — so the browser verdict can never drift
//! from the node verdict. It is the bundle analogue of `verify_record_offline`.
//!
//! ## Honest-scope contract (this is load-bearing — read it)
//! An offline bundle proves a strictly WEAKER thing than the node endpoint, and
//! the output says so without hedging. A `✓ CONSISTENT` result proves only:
//!   * every carrier signature is valid (Dilithium3 / ML-DSA-65), and
//!   * the authority held at the act's *signed* time **given the records in this
//!     bundle**.
//!
//! It does **NOT** prove the records exist on any ledger / are sealed / are
//! time-anchored, and it **cannot** detect a revocation the bundle author
//! withheld, nor confirm either identity has ever touched a node. That is why
//! the green verdict is labelled `CONSISTENT`, never the unqualified
//! `AUTHORIZED` the node answer earns — and why the withheld-revocation and
//! not-on-ledger caveats ride in every response ([`BundleVerdict::soundness_caveats`]).
//! This mirrors the record verifier's discipline (a `⚠`/scoped claim for an
//! unproven bound, never a false green). The honest core gap audit (3 Sonnet +
//! 1 Opus panel → synthesis → Opus final-verify, 2026-06-28) fenced exactly
//! these overclaims before this code was written.
//!
//! ## Soundness invariants enforced here (audited)
//! * **Content-addressing.** Every mandate is indexed under its RECOMPUTED
//!   [`MandateRecord::mandate_id`], never an id supplied by the bundle — so a
//!   forged mandate cannot occupy the leaf id the act references.
//! * **Principal binding.** A mandate carrier counts only if
//!   `sha3(carrier.creator_public_key) == mandate.principal_identity_hash`.
//! * **Network from the SIGNED mandate.** `ValidationRecord` carries no network
//!   field, so the judged network is taken from the resolved leaf mandate's own
//!   signed `network_id` (and displayed), never from an attacker-settable
//!   envelope field; cross-network revocations are dropped.
//! * **Read-time revocation authorization.** Revocations are keyed by
//!   `(mandate_id, sha3(carrier_pk))`; the evaluator only ever consults the
//!   mandate's `principal_identity_hash`, so a non-principal revocation is inert
//!   by key-miss (cannot forge a `PostRevocation`, cannot front-run the real one).
//! * **Bounded work.** Array + payload + scope + chain-depth caps mirror the
//!   node ingest path so a hostile bundle cannot hang a browser tab.
//! * **Anti-libel.** Lineage is non-empty only on `Valid` (enforced in the pure
//!   function); the principal is named only when the flag attributes to them.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::crypto::hash::sha3_256_hex;
use crate::mandate::{
    evaluate_mandate_v0_with_lineage, secs_f64_to_ms_saturating, MandateClaim, MandateFlag,
    MandateRecord, MandateResolver, RevocationRecord, MANDATE_OP_KEY, MANDATE_REF_METADATA_KEY,
    MANDATE_REVOCATION_OP_KEY,
};
use crate::record::ValidationRecord;
use crate::verify_core::{verify_record, Verdict};

/// Current bundle envelope version. A missing/unknown version fails CLOSED
/// (never a green) — mirroring `MANDATE_FORMAT_VERSION`'s "unrecognized ⇒
/// Malformed, never Valid" discipline, so an old verifier facing a future
/// security-bearing envelope field refuses rather than under-checks.
pub const MANDATE_BUNDLE_VERSION: u8 = 1;

// Bounds mirrored from the node ingest path (`network::mandate_node`) so the
// offline verifier enforces the same limits the node does. Defined locally
// (not imported) because that module is node-feature-gated and this core must
// compile under default features for the WASM build.
const BUNDLE_MAX_MANDATES: usize = 64; // >> MANDATE_MAX_CHAIN_DEPTH (16)
const BUNDLE_MAX_REVOCATIONS: usize = 256;
const MANDATE_PAYLOAD_MAX_BYTES: usize = 2048; // == mandate_node::MANDATE_MAX_PAYLOAD_BYTES
const SCOPE_ENTRIES_MAX: usize = 64; // == mandate_node::MANDATE_MAX_SCOPE_ENTRIES

/// The input envelope. SIGNED carrier records, not bare structs — authenticity
/// comes from each carrier's signature exactly as on the chain.
#[derive(Debug, Clone, Deserialize)]
pub struct MandateBundle {
    /// Envelope format version. Defaults to 0 when absent so an unversioned
    /// blob fails the version gate (closed) rather than being trusted.
    #[serde(default)]
    pub bundle_version: u8,
    /// The agent-signed act record being judged (its `metadata.mandate_ref`
    /// names the leaf mandate).
    pub act: ValidationRecord,
    /// Mandate carrier records (each `metadata.mandate_op` = a `MandateRecord`).
    #[serde(default)]
    pub mandates: Vec<ValidationRecord>,
    /// Revocation carrier records (each `metadata.revocation_op` = a
    /// `RevocationRecord`), signed by the revoker.
    #[serde(default)]
    pub revocations: Vec<ValidationRecord>,
}

/// One verified leaf→root hop, surfaced ONLY on a `Valid` verdict (anti-libel).
#[derive(Debug, Clone, Serialize)]
pub struct LineageHop {
    pub mandate_id: String,
    pub principal: String,
    pub agent: String,
}

/// One line of the transparent audit trail (what the offline check proved).
#[derive(Debug, Clone, Serialize)]
pub struct BundleCheck {
    pub name: String,
    /// `"pass"` | `"fail"` | `"info"`.
    pub status: &'static str,
    pub detail: String,
}

/// The offline bundle verdict. `verdict` is the human headline
/// (`"CONSISTENT"` | `"NOT AUTHORIZED"` | `"FAILED"`); `authorized` is the
/// machine boolean and is `true` ONLY for `Valid` — and ONLY *given this
/// bundle* (see [`Self::soundness_caveats`]).
#[derive(Debug, Clone, Serialize)]
pub struct BundleVerdict {
    pub verdict: &'static str,
    pub glyph: &'static str,
    /// `MandateFlag::as_str()` of the underlying verdict (or `"input_error"`).
    pub flag: String,
    /// `true` only when the flag is `Valid`. Honest name: "consistent &
    /// authorizing GIVEN THIS BUNDLE", not "authorized on-chain".
    pub authorized: bool,
    /// Whether the flag legitimately attributes to the principal. The UI must
    /// gate any principal display on this (an `AgentMismatch` EXONERATES them).
    pub attributes_to_principal: bool,
    /// The network the verdict was judged on — taken from the resolved leaf
    /// mandate's own signed `network_id`, surfaced so a wrong-network bundle is
    /// visible rather than silently attributed to "the" network.
    pub network: String,
    /// `sha3` of the act signer's public key (the agent), hex.
    pub signer: String,
    /// The principal — present ONLY when `attributes_to_principal` is true.
    pub principal: Option<String>,
    /// The act's own signed timestamp (ms). Surfaced because offline there is
    /// no anchor proving it; the reviewer sees the self-asserted value.
    pub act_timestamp_ms: u64,
    /// Plain-language explanation of the flag (never names a principal the flag
    /// does not attribute to).
    pub explanation: String,
    /// Verified leaf→root chain — empty unless `Valid`.
    pub lineage: Vec<LineageHop>,
    /// What v0 enforces vs. defers (who+when+revocation enforced; op/zone/amount
    /// recorded, not checked).
    pub scope_note: String,
    /// The non-dismissible honest-scope caveats — what an offline bundle
    /// structurally CANNOT prove. Always present.
    pub soundness_caveats: Vec<String>,
    /// Per-step audit trail.
    pub checks: Vec<BundleCheck>,
    /// `"ok"` or the input/parse error reason.
    pub reason: String,
}

/// In-memory resolver rebuilt from the bundle. The two maps ARE the offline
/// ledger view: the bundle author's chosen contents (hence the soundness
/// caveats). Revocation keying matches the node CF (`(mandate_id, revoker)`).
struct BundleResolver {
    mandates: HashMap<String, MandateRecord>,
    revocations: HashMap<(String, String), u64>,
}

impl MandateResolver for BundleResolver {
    fn mandate(&self, mandate_id: &str) -> Option<MandateRecord> {
        self.mandates.get(mandate_id).cloned()
    }
    fn revocation(&self, mandate_id: &str, principal_identity_hash: &str) -> Option<u64> {
        self.revocations
            .get(&(mandate_id.to_string(), principal_identity_hash.to_string()))
            .copied()
    }
}

/// The three honest-scope caveats every response carries verbatim. These are
/// the exact overclaims the 2026-06-28 audit fenced; they are not optional UI
/// chrome — a consumer that drops them is lying for us.
fn soundness_caveats() -> Vec<String> {
    vec![
        "A ✓ CONSISTENT verdict proves the carrier signatures are valid and the authority held at the act's signed time — GIVEN ONLY the records in this bundle.".to_string(),
        "It does NOT prove these records exist on the Elara ledger, are sealed, or are time-anchored. For that, query a node's /mandate/status or run `elara-verify --seal --anchor`.".to_string(),
        "The bundle's author chooses what it contains: this verifier CANNOT detect a revocation that was withheld, nor confirm either identity has ever submitted records to any node. Cross-check the principal against a node before relying on the attribution.".to_string(),
    ]
}

fn scope_note() -> String {
    "v0 enforces agent identity + validity window + revocation (the WHO and the WHEN). A mandate's op/zone/amount scope is recorded but not checked offline in v0 — sound, node-invariant scope enforcement is a later slice.".to_string()
}

fn explain(flag: MandateFlag) -> String {
    match flag {
        MandateFlag::Valid => {
            "this agent WAS authorized by the principal at the act's signed time — given the records in this bundle"
        }
        MandateFlag::AgentMismatch => {
            "the signer is NOT the mandated agent — the named principal is exonerated"
        }
        MandateFlag::NoChain => {
            "no such mandate is present in this bundle — the act binds its signer only"
        }
        MandateFlag::PostRevocation => {
            "the principal had REVOKED this mandate before the act was signed"
        }
        MandateFlag::Lapsed => "the mandate's validity window had closed before the act",
        MandateFlag::NotYetValid => "the mandate's validity window had not yet opened",
        MandateFlag::Malformed => {
            "the referenced mandate is malformed or bound to a different network"
        }
        MandateFlag::UnverifiedChain => {
            "a sub-delegation ancestor is missing or unverifiable — include every mandate from the leaf to the root"
        }
        MandateFlag::DepthExceeded => "the sub-delegation chain is deeper than the protocol allows",
        MandateFlag::ScopeBroadened => {
            "a sub-delegation hop tried to grant MORE than its parent — rejected"
        }
        MandateFlag::OverScope => "the act exceeds the mandate's recorded scope",
        MandateFlag::UnauthorizedRevocation => {
            "a revocation was signed by someone other than the principal — inert"
        }
    }
    .to_string()
}

/// Does a carrier record's signature verify? Reuses the shared `verify_core`
/// path (structure + identity binding + Dilithium3/SPHINCS+ over canonical
/// bytes), so the bundle's notion of "validly signed" is byte-identical to the
/// single-record verifier's. A plain signed record (no anchor leg) yields
/// `Verified` iff every signature/binding check passes.
fn carrier_verifies(record: &ValidationRecord) -> bool {
    let mut checks = Vec::new();
    verify_record(record, None, "", &mut checks);
    // Fail-safe: a hypothetical future `Partial` (no `content` leg can produce
    // one today) is `!= Verified` ⇒ the carrier is rejected, never trusted.
    Verdict::of(&checks) == Verdict::Verified
}

/// Build a fail-closed `FAILED` verdict for structural / input errors (parse,
/// version, oversize, unsigned act, no mandate_ref). Never green.
fn failed(reason: impl Into<String>, checks: Vec<BundleCheck>) -> BundleVerdict {
    BundleVerdict {
        verdict: "FAILED",
        glyph: "✗",
        flag: "input_error".to_string(),
        authorized: false,
        attributes_to_principal: false,
        network: String::new(),
        signer: String::new(),
        principal: None,
        act_timestamp_ms: 0,
        explanation: String::new(),
        lineage: Vec::new(),
        scope_note: scope_note(),
        soundness_caveats: soundness_caveats(),
        checks,
        reason: reason.into(),
    }
}

/// Verify a mandate bundle entirely offline. Never panics — every malformed
/// input surfaces as a `FAILED`/`NOT AUTHORIZED` verdict with a reason, the
/// same fail-closed posture as `verify_record_offline`.
pub fn evaluate_mandate_bundle(bundle_json: &str) -> BundleVerdict {
    // 1. Parse the envelope. A parse failure is fail-closed.
    let bundle: MandateBundle = match serde_json::from_str(bundle_json) {
        Ok(b) => b,
        Err(e) => return failed(format!("bundle parse error: {e}"), Vec::new()),
    };

    // 2. Version gate — unknown/missing fails CLOSED, never green.
    if bundle.bundle_version != MANDATE_BUNDLE_VERSION {
        return failed(
            format!(
                "unsupported bundle_version {} (this verifier speaks v{}) — refusing to verify",
                bundle.bundle_version, MANDATE_BUNDLE_VERSION
            ),
            Vec::new(),
        );
    }

    // 3. Bound the work before touching crypto.
    if bundle.mandates.len() > BUNDLE_MAX_MANDATES {
        return failed(
            format!(
                "bundle carries {} mandates (max {})",
                bundle.mandates.len(),
                BUNDLE_MAX_MANDATES
            ),
            Vec::new(),
        );
    }
    if bundle.revocations.len() > BUNDLE_MAX_REVOCATIONS {
        return failed(
            format!(
                "bundle carries {} revocations (max {})",
                bundle.revocations.len(),
                BUNDLE_MAX_REVOCATIONS
            ),
            Vec::new(),
        );
    }

    let mut checks: Vec<BundleCheck> = Vec::new();

    // 4. The act carrier signature MUST verify (fail-closed).
    if !carrier_verifies(&bundle.act) {
        checks.push(BundleCheck {
            name: "act signature".to_string(),
            status: "fail",
            detail: "the act record's signature/identity does not verify".to_string(),
        });
        return failed(
            "act record signature does not verify over its canonical bytes".to_string(),
            checks,
        );
    }
    checks.push(BundleCheck {
        name: "act signature".to_string(),
        status: "pass",
        detail: "Dilithium3 valid over the act's canonical bytes".to_string(),
    });

    // 5. The act must reference a mandate. "No ref" is an input error, distinct
    //    from "ref resolves to nothing" (NoChain) — don't conflate them.
    let mandate_ref = bundle
        .act
        .metadata
        .get(MANDATE_REF_METADATA_KEY)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if mandate_ref.is_empty() {
        return failed(
            "act record carries no mandate_ref — it references no mandate".to_string(),
            checks,
        );
    }

    // 6. Index mandates, content-addressed + principal-bound.
    let mut mandates: HashMap<String, MandateRecord> = HashMap::new();
    for (i, carrier) in bundle.mandates.iter().enumerate() {
        if !carrier_verifies(carrier) {
            checks.push(BundleCheck {
                name: format!("mandate[{i}] signature"),
                status: "fail",
                detail: "carrier signature does not verify — skipped".to_string(),
            });
            continue;
        }
        let Some(raw) = carrier.metadata.get(MANDATE_OP_KEY) else {
            checks.push(BundleCheck {
                name: format!("mandate[{i}]"),
                status: "info",
                detail: "carrier has no mandate_op payload — skipped".to_string(),
            });
            continue;
        };
        if raw.to_string().len() > MANDATE_PAYLOAD_MAX_BYTES {
            checks.push(BundleCheck {
                name: format!("mandate[{i}]"),
                status: "fail",
                detail: "mandate payload exceeds size cap — skipped".to_string(),
            });
            continue;
        }
        let m: MandateRecord = match serde_json::from_value(raw.clone()) {
            Ok(m) => m,
            Err(_) => {
                checks.push(BundleCheck {
                    name: format!("mandate[{i}]"),
                    status: "fail",
                    detail: "mandate_op payload is not a MandateRecord — skipped".to_string(),
                });
                continue;
            }
        };
        if m.scope.allowed_ops.len() > SCOPE_ENTRIES_MAX
            || m.scope.allowed_zones.len() > SCOPE_ENTRIES_MAX
        {
            checks.push(BundleCheck {
                name: format!("mandate[{i}]"),
                status: "fail",
                detail: "mandate scope exceeds entry cap — skipped".to_string(),
            });
            continue;
        }
        // Principal binding: the carrier signature IS the principal's signature.
        let carrier_principal = sha3_256_hex(&carrier.creator_public_key);
        if !carrier_principal.eq_ignore_ascii_case(&m.principal_identity_hash) {
            checks.push(BundleCheck {
                name: format!("mandate[{i}] principal binding"),
                status: "fail",
                detail: "carrier signer is not the mandate's principal — skipped".to_string(),
            });
            continue;
        }
        // Content-address: index under the RECOMPUTED id, never a bundle field.
        let id = m.mandate_id();
        checks.push(BundleCheck {
            name: format!("mandate[{i}]"),
            status: "pass",
            detail: format!(
                "verified + principal-bound; indexed under content id {}…",
                &id[..id.len().min(12)]
            ),
        });
        mandates.insert(id, m);
    }

    // 7. Resolve the leaf to get the AUTHORITATIVE (signed) network. Absent leaf
    //    is NoChain — honest "the referenced mandate is not in this bundle".
    let Some(leaf) = mandates.get(&mandate_ref).cloned() else {
        return not_authorized(
            MandateFlag::NoChain,
            &bundle,
            String::new(),
            None,
            Vec::new(),
            checks,
        );
    };
    let network = leaf.network_id.clone();

    // 8. Index revocations, keyed by (mandate_id, sha3(carrier_pk)); drop
    //    cross-network. A non-principal revoker lands under a key the evaluator
    //    never consults → inert (cannot forge PostRevocation).
    let mut revocations: HashMap<(String, String), u64> = HashMap::new();
    for (i, carrier) in bundle.revocations.iter().enumerate() {
        if !carrier_verifies(carrier) {
            checks.push(BundleCheck {
                name: format!("revocation[{i}] signature"),
                status: "fail",
                detail: "carrier signature does not verify — skipped".to_string(),
            });
            continue;
        }
        let Some(raw) = carrier.metadata.get(MANDATE_REVOCATION_OP_KEY) else {
            continue;
        };
        if raw.to_string().len() > MANDATE_PAYLOAD_MAX_BYTES {
            continue;
        }
        let rev: RevocationRecord = match serde_json::from_value(raw.clone()) {
            Ok(r) => r,
            Err(_) => continue,
        };
        if !rev.network_id.eq_ignore_ascii_case(&network) {
            checks.push(BundleCheck {
                name: format!("revocation[{i}]"),
                status: "info",
                detail: "cross-network revocation — not applicable to this bundle, skipped"
                    .to_string(),
            });
            continue;
        }
        let revoker = sha3_256_hex(&carrier.creator_public_key);
        let revoked_at = secs_f64_to_ms_saturating(carrier.timestamp);
        let key = (rev.mandate_id.clone(), revoker);
        revocations
            .entry(key)
            .and_modify(|t| {
                if revoked_at < *t {
                    *t = revoked_at;
                }
            })
            .or_insert(revoked_at);
        checks.push(BundleCheck {
            name: format!("revocation[{i}]"),
            status: "pass",
            detail: "verified; indexed by (mandate_id, revoker)".to_string(),
        });
    }

    // 9. Build the claim (op/zone empty: v0 defers scope) + run the SAME pure
    //    verdict core the node endpoint uses.
    let signer = sha3_256_hex(&bundle.act.creator_public_key);
    let act_timestamp_ms = secs_f64_to_ms_saturating(bundle.act.timestamp);
    let resolver = BundleResolver { mandates, revocations };
    let claim = MandateClaim {
        signer_identity_hash: &signer,
        act_timestamp_ms,
        mandate_ref: &mandate_ref,
        op: "",
        zone: "",
        amount: None,
        network_id: &network,
    };
    let (flag, lineage) = evaluate_mandate_v0_with_lineage(&claim, &resolver);

    let lineage_hops: Vec<LineageHop> = lineage
        .iter()
        .map(|(id, m)| LineageHop {
            mandate_id: id.clone(),
            principal: m.principal_identity_hash.clone(),
            agent: m.agent_identity_hash.clone(),
        })
        .collect();

    // The principal is named ONLY when the flag attributes to them (anti-libel).
    let principal = if flag.attributes_to_principal() {
        Some(leaf.principal_identity_hash.clone())
    } else {
        None
    };

    if flag == MandateFlag::Valid {
        BundleVerdict {
            verdict: "CONSISTENT",
            glyph: "✓",
            flag: flag.as_str().to_string(),
            authorized: true,
            attributes_to_principal: true,
            network,
            signer,
            principal,
            act_timestamp_ms,
            explanation: explain(flag),
            lineage: lineage_hops,
            scope_note: scope_note(),
            soundness_caveats: soundness_caveats(),
            checks,
            reason: "ok".to_string(),
        }
    } else {
        not_authorized(flag, &bundle, network, principal, lineage_hops, checks)
    }
}

/// Build a `NOT AUTHORIZED` verdict for any non-`Valid`, non-input-error flag.
/// `lineage` is always empty here (the pure function guarantees it for every
/// non-`Valid` flag); the parameter exists only so the one caller can pass the
/// already-built value without a second walk.
fn not_authorized(
    flag: MandateFlag,
    bundle: &MandateBundle,
    network: String,
    principal: Option<String>,
    lineage: Vec<LineageHop>,
    checks: Vec<BundleCheck>,
) -> BundleVerdict {
    let signer = sha3_256_hex(&bundle.act.creator_public_key);
    let act_timestamp_ms = secs_f64_to_ms_saturating(bundle.act.timestamp);
    BundleVerdict {
        verdict: "NOT AUTHORIZED",
        glyph: "✗",
        flag: flag.as_str().to_string(),
        authorized: false,
        attributes_to_principal: flag.attributes_to_principal(),
        network,
        signer,
        principal,
        act_timestamp_ms,
        explanation: explain(flag),
        lineage, // empty for every non-Valid flag
        scope_note: scope_note(),
        soundness_caveats: soundness_caveats(),
        checks,
        reason: "ok".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{CryptoProfile, EntityType, Identity};
    use crate::mandate::{MandateScope, RevocationRecord};
    use crate::record::Classification;
    use std::collections::BTreeMap;

    const NETWORK: &str = "testnet";
    const WINDOW_OPEN_MS: u64 = 1_700_000_000_000;
    const WINDOW_CLOSE_MS: u64 = 1_700_100_000_000;
    const T_ACT: f64 = 1_700_000_500.0;
    const T_REVOKE: f64 = 1_700_050_000.0;
    const T_ACT_AFTER_REVOKE: f64 = 1_700_060_000.0;

    fn signed_record(
        signer: &Identity,
        meta: BTreeMap<String, serde_json::Value>,
        ts_secs: f64,
    ) -> ValidationRecord {
        let mut rec = ValidationRecord::create(
            b"mandate-bundle-test",
            signer.public_key.clone(),
            vec![],
            Classification::Public,
            Some(meta),
        );
        rec.timestamp = ts_secs;
        signer.sign_record(&mut rec).expect("sign");
        rec
    }

    fn mandate_carrier(principal: &Identity, m: &MandateRecord, ts: f64) -> ValidationRecord {
        let mut meta = BTreeMap::new();
        meta.insert(MANDATE_OP_KEY.to_string(), serde_json::to_value(m).unwrap());
        signed_record(principal, meta, ts)
    }

    fn revocation_carrier(
        signer: &Identity,
        rev: &RevocationRecord,
        ts: f64,
    ) -> ValidationRecord {
        let mut meta = BTreeMap::new();
        meta.insert(
            MANDATE_REVOCATION_OP_KEY.to_string(),
            serde_json::to_value(rev).unwrap(),
        );
        signed_record(signer, meta, ts)
    }

    fn act_record(agent: &Identity, mandate_id: &str, ts: f64) -> ValidationRecord {
        let mut meta = BTreeMap::new();
        meta.insert(
            MANDATE_REF_METADATA_KEY.to_string(),
            serde_json::Value::String(mandate_id.to_string()),
        );
        signed_record(agent, meta, ts)
    }

    fn root_mandate(principal: &Identity, agent: &Identity) -> MandateRecord {
        let scope = MandateScope {
            allowed_ops: vec!["*".to_string()],
            allowed_zones: vec!["*".to_string()],
            max_amount: None,
        };
        MandateRecord::new_root(
            NETWORK,
            &principal.identity_hash,
            &agent.identity_hash,
            scope,
            WINDOW_OPEN_MS,
            WINDOW_CLOSE_MS,
            0,
            "bundle-test-0001",
        )
    }

    fn cast() -> (Identity, Identity, Identity) {
        (
            Identity::generate(EntityType::Human, CryptoProfile::ProfileB).unwrap(),
            Identity::generate(EntityType::Ai, CryptoProfile::ProfileB).unwrap(),
            Identity::generate(EntityType::Ai, CryptoProfile::ProfileB).unwrap(),
        )
    }

    /// Serialize a bundle the way the example tool / browser does.
    fn bundle_json(
        act: &ValidationRecord,
        mandates: &[ValidationRecord],
        revocations: &[ValidationRecord],
    ) -> String {
        serde_json::json!({
            "bundle_version": MANDATE_BUNDLE_VERSION,
            "act": act,
            "mandates": mandates,
            "revocations": revocations,
        })
        .to_string()
    }

    #[test]
    fn pristine_valid_bundle_is_consistent_and_names_principal() {
        let (principal, agent, _) = cast();
        let m = root_mandate(&principal, &agent);
        let id = m.mandate_id();
        let carrier = mandate_carrier(&principal, &m, 1_700_000_000.0);
        let act = act_record(&agent, &id, T_ACT);
        let v = evaluate_mandate_bundle(&bundle_json(&act, &[carrier], &[]));
        assert_eq!(v.verdict, "CONSISTENT", "{:?}", v);
        assert_eq!(v.glyph, "✓");
        assert_eq!(v.flag, "valid");
        assert!(v.authorized);
        assert!(v.attributes_to_principal);
        assert_eq!(v.principal.as_deref(), Some(principal.identity_hash.as_str()));
        assert_eq!(v.network, NETWORK);
        assert_eq!(v.lineage.len(), 1, "root chain = one hop");
        // The honest-scope caveats are always present.
        assert_eq!(v.soundness_caveats.len(), 3);
        assert!(v
            .soundness_caveats
            .iter()
            .any(|c| c.contains("withheld")));
    }

    #[test]
    fn impostor_using_the_agents_mandate_exonerates_the_principal() {
        let (principal, agent, impostor) = cast();
        let m = root_mandate(&principal, &agent);
        let id = m.mandate_id();
        let carrier = mandate_carrier(&principal, &m, 1_700_000_000.0);
        // The impostor (not the agent) signs the act referencing the mandate.
        let act = act_record(&impostor, &id, T_ACT);
        let v = evaluate_mandate_bundle(&bundle_json(&act, &[carrier], &[]));
        assert_eq!(v.verdict, "NOT AUTHORIZED", "{:?}", v);
        assert_eq!(v.flag, "agent_mismatch");
        assert!(!v.authorized);
        assert!(!v.attributes_to_principal, "principal must be exonerated");
        assert_eq!(v.principal, None, "must NOT name the principal");
        assert!(v.lineage.is_empty());
    }

    #[test]
    fn act_after_revocation_is_not_authorized() {
        let (principal, agent, _) = cast();
        let m = root_mandate(&principal, &agent);
        let id = m.mandate_id();
        let carrier = mandate_carrier(&principal, &m, 1_700_000_000.0);
        let rev = RevocationRecord::new(NETWORK, id.clone(), "key compromise");
        let rev_carrier = revocation_carrier(&principal, &rev, T_REVOKE);
        let act = act_record(&agent, &id, T_ACT_AFTER_REVOKE);
        let v = evaluate_mandate_bundle(&bundle_json(&act, &[carrier], &[rev_carrier]));
        assert_eq!(v.verdict, "NOT AUTHORIZED", "{:?}", v);
        assert_eq!(v.flag, "post_revocation");
        assert!(!v.authorized);
        // PostRevocation legitimately attributes to the principal (they revoked).
        assert!(v.attributes_to_principal);
        assert_eq!(v.principal.as_deref(), Some(principal.identity_hash.as_str()));
    }

    #[test]
    fn pre_revocation_act_stays_consistent_revocation_not_retroactive() {
        let (principal, agent, _) = cast();
        let m = root_mandate(&principal, &agent);
        let id = m.mandate_id();
        let carrier = mandate_carrier(&principal, &m, 1_700_000_000.0);
        let rev = RevocationRecord::new(NETWORK, id.clone(), "later compromise");
        let rev_carrier = revocation_carrier(&principal, &rev, T_REVOKE);
        // Act signed BEFORE the revocation — authority is not retroactive.
        let act = act_record(&agent, &id, T_ACT);
        let v = evaluate_mandate_bundle(&bundle_json(&act, &[carrier], &[rev_carrier]));
        assert_eq!(v.verdict, "CONSISTENT", "{:?}", v);
        assert_eq!(v.flag, "valid");
    }

    #[test]
    fn tampered_act_signature_fails_closed() {
        let (principal, agent, _) = cast();
        let m = root_mandate(&principal, &agent);
        let id = m.mandate_id();
        let carrier = mandate_carrier(&principal, &m, 1_700_000_000.0);
        let mut act = act_record(&agent, &id, T_ACT);
        // Flip a signature byte.
        if let Some(sig) = act.signature.as_mut() {
            sig[0] ^= 0xFF;
        }
        let v = evaluate_mandate_bundle(&bundle_json(&act, &[carrier], &[]));
        assert_eq!(v.verdict, "FAILED", "{:?}", v);
        assert!(!v.authorized);
    }

    #[test]
    fn tampered_mandate_breaks_content_address_no_false_valid() {
        // The HIGH-2 audit regression: a mutated mandate must NOT resolve under
        // the leaf id the act references → NoChain, never a forged Valid.
        let (principal, agent, _) = cast();
        let m = root_mandate(&principal, &agent);
        let id = m.mandate_id();
        // Build a carrier whose embedded mandate has been broadened AFTER the
        // act pinned `id`. The principal re-signs the carrier (so the carrier
        // sig + principal-binding still hold), but the content now hashes to a
        // DIFFERENT id, so it indexes elsewhere and the leaf id is unresolved.
        let mut m2 = m.clone();
        m2.not_after_ms += 1; // any content change moves the content address
        let carrier = mandate_carrier(&principal, &m2, 1_700_000_000.0);
        let act = act_record(&agent, &id, T_ACT);
        let v = evaluate_mandate_bundle(&bundle_json(&act, &[carrier], &[]));
        assert_eq!(v.verdict, "NOT AUTHORIZED", "{:?}", v);
        assert_eq!(v.flag, "no_chain", "tampered mandate must not back-resolve");
        assert!(!v.authorized);
    }

    #[test]
    fn non_principal_revocation_is_inert() {
        // The revocation-key-construction audit (FINDING-1): a revocation signed
        // by the AGENT (not the principal) must not forge a PostRevocation.
        let (principal, agent, _) = cast();
        let m = root_mandate(&principal, &agent);
        let id = m.mandate_id();
        let carrier = mandate_carrier(&principal, &m, 1_700_000_000.0);
        // Agent signs the revocation — wrong revoker.
        let rev = RevocationRecord::new(NETWORK, id.clone(), "spoofed by agent");
        let rev_carrier = revocation_carrier(&agent, &rev, T_REVOKE);
        let act = act_record(&agent, &id, T_ACT_AFTER_REVOKE);
        let v = evaluate_mandate_bundle(&bundle_json(&act, &[carrier], &[rev_carrier]));
        assert_eq!(v.verdict, "CONSISTENT", "spoofed revocation must be inert: {:?}", v);
        assert_eq!(v.flag, "valid");
    }

    #[test]
    fn cross_network_revocation_is_skipped() {
        let (principal, agent, _) = cast();
        let m = root_mandate(&principal, &agent);
        let id = m.mandate_id();
        let carrier = mandate_carrier(&principal, &m, 1_700_000_000.0);
        // Revocation on a DIFFERENT network — must not apply.
        let rev = RevocationRecord::new("mainnet", id.clone(), "wrong network");
        let rev_carrier = revocation_carrier(&principal, &rev, T_REVOKE);
        let act = act_record(&agent, &id, T_ACT_AFTER_REVOKE);
        let v = evaluate_mandate_bundle(&bundle_json(&act, &[carrier], &[rev_carrier]));
        assert_eq!(v.verdict, "CONSISTENT", "cross-network rev must be skipped: {:?}", v);
        assert_eq!(v.flag, "valid");
    }

    #[test]
    fn withheld_revocation_yields_consistent_but_caveat_is_present() {
        // Honest-scope: a withheld revocation is undetectable offline — the
        // verdict is CONSISTENT, and the response MUST carry the caveat so the
        // demo never silently overclaims.
        let (principal, agent, _) = cast();
        let m = root_mandate(&principal, &agent);
        let id = m.mandate_id();
        let carrier = mandate_carrier(&principal, &m, 1_700_000_000.0);
        let act = act_record(&agent, &id, T_ACT_AFTER_REVOKE);
        // Note: the real revocation exists on-chain but is simply NOT in the bundle.
        let v = evaluate_mandate_bundle(&bundle_json(&act, &[carrier], &[]));
        assert_eq!(v.verdict, "CONSISTENT");
        assert!(v
            .soundness_caveats
            .iter()
            .any(|c| c.contains("withheld")));
    }

    #[test]
    fn unknown_bundle_version_fails_closed() {
        let (principal, agent, _) = cast();
        let m = root_mandate(&principal, &agent);
        let id = m.mandate_id();
        let carrier = mandate_carrier(&principal, &m, 1_700_000_000.0);
        let act = act_record(&agent, &id, T_ACT);
        let json = serde_json::json!({
            "bundle_version": 99,
            "act": act,
            "mandates": [carrier],
            "revocations": [],
        })
        .to_string();
        let v = evaluate_mandate_bundle(&json);
        assert_eq!(v.verdict, "FAILED");
        assert!(v.reason.contains("bundle_version"));
    }

    #[test]
    fn act_without_mandate_ref_is_input_error_not_nochain() {
        let (_, agent, _) = cast();
        // Act with empty metadata — no mandate_ref at all.
        let act = signed_record(&agent, BTreeMap::new(), T_ACT);
        let v = evaluate_mandate_bundle(&bundle_json(&act, &[], &[]));
        assert_eq!(v.verdict, "FAILED");
        assert!(v.reason.contains("no mandate_ref"));
    }

    #[test]
    fn ref_with_no_mandate_in_bundle_is_no_chain() {
        let (_, agent, _) = cast();
        let act = act_record(&agent, &"ff".repeat(32), T_ACT);
        let v = evaluate_mandate_bundle(&bundle_json(&act, &[], &[]));
        assert_eq!(v.verdict, "NOT AUTHORIZED");
        assert_eq!(v.flag, "no_chain");
    }

    #[test]
    fn garbage_input_fails_closed_never_throws() {
        for s in ["", "{}", "not json", "[]", "{\"bundle_version\":1}"] {
            let v = evaluate_mandate_bundle(s);
            assert_eq!(v.verdict, "FAILED", "input {s:?} must fail closed");
            assert!(!v.authorized);
        }
    }
}
