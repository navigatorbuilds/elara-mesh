//! Pack-level verification: container, digest, bindings, anchor, producer, policy, verdict
//! (SPEC_AP2_EVIDENCE.md §1, §3, §4, §6).

use crate::json::{self, Value};
use crate::producer;
use crate::rfc3161;
use crate::sdjwt::{self, ArtifactResult};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Default)]
pub struct Policy {
    pub require_producer: bool,
    pub require_pq: bool,
    pub require_anchor: bool,
    /// Pinned trust set `{sig_alg: [raw key bytes, ...]}`; None = no pin set supplied.
    pub pins: Option<Vec<(String, Vec<Vec<u8>>)>>,
}

impl Policy {
    /// From an `.expected.json` `policy` block (or any object of the same shape).
    pub fn from_expected(policy: &Value) -> Result<Policy, String> {
        let flag = |k: &str| policy.get(k).and_then(Value::as_bool).unwrap_or(false);
        let pins = match policy.get("trusted_producer_keys") {
            None | Some(Value::Null) => None,
            Some(v) => Some(parse_pins(v)?),
        };
        Ok(Policy {
            require_producer: flag("require_producer"),
            require_pq: flag("require_pq"),
            require_anchor: flag("require_anchor"),
            pins,
        })
    }
    pub fn pinned(&self, alg: &str, pk: &[u8]) -> Option<bool> {
        self.pins
            .as_ref()
            .map(|p| p.iter().any(|(a, keys)| a == alg && keys.iter().any(|k| k == pk)))
    }
}

pub fn parse_pins(v: &Value) -> Result<Vec<(String, Vec<Vec<u8>>)>, String> {
    let obj = v.as_obj().ok_or("trusted_producer_keys must be an object")?;
    let mut out = Vec::new();
    for (alg, keys) in obj {
        let arr = keys.as_arr().ok_or("pinned keys must be arrays")?;
        let mut decoded = Vec::new();
        for k in arr {
            let s = k.as_str().ok_or("pinned key must be a base64 string")?;
            decoded.push(STANDARD.decode(s).map_err(|e| format!("pinned key base64: {e}"))?);
        }
        out.push((alg.clone(), decoded));
    }
    Ok(out)
}

#[derive(Debug)]
pub struct Verdict {
    pub valid: bool,
    pub digest_ok: bool,
    pub bindings_ok: bool,
    pub policy_ok: bool,
    pub pq_protected: bool,
    pub producer_present: bool,
    pub producer_ok: Option<bool>,
    pub producer_trusted: Option<bool>,
    pub rfc3161_claimed: bool,
    pub rfc3161_verified: Option<bool>,
    pub self_asserted_only: bool,
    // diagnostics
    pub container_ok: bool,
    pub artifacts_ok: bool,
    pub recomputed_digest: String,
    pub declared_digest: Option<String>,
    pub artifacts: Vec<ArtifactResult>,
    pub recomputed_bindings: Vec<Value>,
    pub reasons: Vec<String>,
}

pub const NORMATIVE_FIELDS: [&str; 11] = [
    "bindings_ok",
    "digest_ok",
    "policy_ok",
    "pq_protected",
    "producer_ok",
    "producer_present",
    "producer_trusted",
    "rfc3161_claimed",
    "rfc3161_verified",
    "self_asserted_only",
    "valid",
];

fn tri(v: Option<bool>) -> Value {
    v.map(Value::Bool).unwrap_or(Value::Null)
}

impl Verdict {
    pub fn normative(&self) -> Value {
        Value::obj(vec![
            ("bindings_ok", Value::Bool(self.bindings_ok)),
            ("digest_ok", Value::Bool(self.digest_ok)),
            ("policy_ok", Value::Bool(self.policy_ok)),
            ("pq_protected", Value::Bool(self.pq_protected)),
            ("producer_ok", tri(self.producer_ok)),
            ("producer_present", Value::Bool(self.producer_present)),
            ("producer_trusted", tri(self.producer_trusted)),
            ("rfc3161_claimed", Value::Bool(self.rfc3161_claimed)),
            ("rfc3161_verified", tri(self.rfc3161_verified)),
            ("self_asserted_only", Value::Bool(self.self_asserted_only)),
            ("valid", Value::Bool(self.valid)),
        ])
    }

    pub fn diagnostics(&self) -> Value {
        Value::obj(vec![
            ("container_ok", Value::Bool(self.container_ok)),
            ("artifacts_ok", Value::Bool(self.artifacts_ok)),
            ("recomputed_digest", Value::str(&self.recomputed_digest)),
            (
                "declared_digest",
                self.declared_digest.as_deref().map(Value::str).unwrap_or(Value::Null),
            ),
            (
                "artifacts",
                Value::Arr(
                    self.artifacts
                        .iter()
                        .map(|a| {
                            Value::obj(vec![
                                ("name", Value::str(&a.name)),
                                ("signature_ok", Value::Bool(a.signature_ok)),
                                ("disclosures_ok", Value::Bool(a.disclosures_ok)),
                                ("claims_match", Value::Bool(a.claims_match)),
                                ("kb_present", Value::Bool(a.kb_present)),
                                ("kb_verified", tri(a.kb_verified)),
                                ("verified", Value::Bool(a.verified)),
                                ("sha256_of_compact", Value::str(&a.compact_sha256_hex)),
                                ("reasons", Value::Arr(a.reasons.iter().map(|r| Value::str(r)).collect())),
                            ])
                        })
                        .collect(),
                ),
            ),
            ("recomputed_bindings", Value::Arr(self.recomputed_bindings.clone())),
            ("reasons", Value::Arr(self.reasons.iter().map(|r| Value::str(r)).collect())),
        ])
    }
}

fn is_created_utc(s: &str) -> bool {
    // YYYY-MM-DDTHH:MM:SSZ
    let b = s.as_bytes();
    if b.len() != 20 {
        return false;
    }
    for (i, &c) in b.iter().enumerate() {
        let ok = match i {
            4 | 7 => c == b'-',
            10 => c == b'T',
            13 | 16 => c == b':',
            19 => c == b'Z',
            _ => c.is_ascii_digit(),
        };
        if !ok {
            return false;
        }
    }
    true
}

pub fn verify_pack(text: &str, policy: &Policy, tsa_root: Option<&[u8]>) -> Result<Verdict, String> {
    let pack = json::parse(text).map_err(|e| format!("pack is not strict JSON: {e}"))?;
    let obj = pack.as_obj().ok_or("pack is not a JSON object")?;
    let mut reasons: Vec<String> = Vec::new();
    let mut container_ok = true;
    let mut fail = |msg: &str, reasons: &mut Vec<String>| {
        container_ok = false;
        reasons.push(format!("container: {msg}"));
    };

    if pack.get("evidence_format").and_then(Value::as_str) != Some("ap2-evidence-pack/1.0") {
        fail("evidence_format is not \"ap2-evidence-pack/1.0\"", &mut reasons);
    }
    if pack.get("subject").and_then(Value::as_str).is_none() {
        fail("subject missing or not a string", &mut reasons);
    }
    match pack.get("created_utc").and_then(Value::as_str) {
        Some(s) if is_created_utc(s) => {}
        _ => fail("created_utc missing or not YYYY-MM-DDTHH:MM:SSZ", &mut reasons),
    }
    let arts: &[Value] = match pack.get("artifacts").and_then(Value::as_arr) {
        Some(a) if !a.is_empty() => a,
        _ => {
            fail("artifacts missing or empty (an empty pack is never valid)", &mut reasons);
            &[]
        }
    };
    if pack.get("bindings").and_then(Value::as_arr).is_none() {
        fail("bindings missing or not an array", &mut reasons);
    }
    if pack.get("honest_scope").and_then(Value::as_str).is_none() {
        fail("honest_scope missing or not a string", &mut reasons);
    }
    let declared_digest = pack.get("evidence_digest_sha256").and_then(Value::as_str).map(String::from);
    match &declared_digest {
        Some(d) if d.len() == 64 && d.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) => {}
        _ => fail("evidence_digest_sha256 missing or not 64 lowercase hex chars", &mut reasons),
    }
    let ts = pack.get("rfc3161_timestamp");
    let anchored = ts.and_then(|t| t.get("anchored")).and_then(Value::as_bool);
    if ts.and_then(Value::as_obj).is_none() || anchored.is_none() {
        fail("rfc3161_timestamp missing or lacks a boolean 'anchored'", &mut reasons);
    }

    // §3 digest over the canonical top-level object minus the three excluded keys.
    let content: Vec<(String, Value)> = obj
        .iter()
        .filter(|(k, _)| !matches!(k.as_str(), "evidence_digest_sha256" | "rfc3161_timestamp" | "producer_signatures"))
        .cloned()
        .collect();
    let canonical = json::canonical(&Value::Obj(content));
    let digest_bytes = Sha256::digest(canonical.as_bytes());
    let recomputed_digest = hex::encode(digest_bytes);
    let digest_ok = declared_digest.as_deref() == Some(recomputed_digest.as_str());
    if !digest_ok {
        reasons.push(format!(
            "digest: recomputed {recomputed_digest} != declared {}",
            declared_digest.as_deref().unwrap_or("<missing>")
        ));
    }

    // §6 step 2: every artifact.
    let artifacts: Vec<ArtifactResult> = arts.iter().map(sdjwt::verify_artifact).collect();
    let mut artifacts_ok = !artifacts.is_empty() && artifacts.iter().all(|a| a.verified);
    for a in &artifacts {
        for r in &a.reasons {
            reasons.push(format!("artifact {:?}: {r}", a.name));
        }
    }
    let mut names: Vec<&str> = artifacts.iter().map(|a| a.name.as_str()).collect();
    names.sort_unstable();
    if names.windows(2).any(|w| w[0] == w[1]) {
        artifacts_ok = false;
        reasons.push("artifact names are not unique".into());
    }
    if arts.iter().any(|a| a.as_obj().is_none()) {
        artifacts_ok = false;
        reasons.push("an artifact entry is not an object".into());
    }

    // §4 bindings.
    let (recomputed_bindings, bindings_ok) = compute_bindings(&artifacts, pack.get("bindings"), &mut reasons);

    // §6 step 4: anchor.
    let rfc3161_claimed = anchored == Some(true);
    let rfc3161_verified = if rfc3161_claimed {
        match ts.and_then(|t| t.get("tsr_b64")).and_then(Value::as_str) {
            None => {
                reasons.push("anchor: anchored=true but tsr_b64 missing".into());
                Some(false)
            }
            Some(b64) => match STANDARD.decode(b64) {
                Err(e) => {
                    reasons.push(format!("anchor: tsr_b64 is not base64: {e}"));
                    Some(false)
                }
                Ok(der) => match rfc3161::verify_token(&der, &digest_bytes, tsa_root) {
                    rfc3161::Outcome::Verified => Some(true),
                    rfc3161::Outcome::Failed(why) => {
                        reasons.push(format!("anchor: RFC 3161 token FAILED: {why}"));
                        Some(false)
                    }
                    rfc3161::Outcome::Unverifiable(why) => {
                        reasons.push(format!("anchor: RFC 3161 token recorded but NOT verified: {why}"));
                        None
                    }
                },
            },
        }
    } else {
        None
    };

    // §5 producer.
    let prod = producer::verify(pack.get("producer_signatures"), recomputed_digest.as_bytes(), policy, &mut reasons);

    // §6 step 6: policy.
    let mut policy_ok = true;
    if policy.require_producer && !(prod.present && prod.ok == Some(true)) {
        policy_ok = false;
        reasons.push("policy: require_producer but no valid producer block".into());
    }
    if policy.require_pq && !(prod.pq_protected && prod.trusted == Some(true)) {
        policy_ok = false;
        reasons.push("policy: require_pq but not (pq_protected and producer_trusted)".into());
    }
    if policy.require_anchor && rfc3161_verified != Some(true) {
        policy_ok = false;
        reasons.push("policy: require_anchor but rfc3161_verified is not true".into());
    }

    // §6 step 7.
    let self_asserted_only =
        !artifacts.is_empty() && artifacts.iter().all(|a| a.provenance_class.as_deref() == Some("jwk_header"));

    // §6 step 8.
    let producer_term = if prod.present {
        prod.ok == Some(true) && (policy.pins.is_none() || prod.trusted == Some(true))
    } else {
        true
    };
    let valid = container_ok
        && !artifacts.is_empty()
        && digest_ok
        && artifacts_ok
        && bindings_ok
        && rfc3161_verified != Some(false)
        && producer_term
        && policy_ok;

    Ok(Verdict {
        valid,
        digest_ok,
        bindings_ok,
        policy_ok,
        pq_protected: prod.pq_protected,
        producer_present: prod.present,
        producer_ok: prod.ok,
        producer_trusted: prod.trusted,
        rfc3161_claimed,
        rfc3161_verified,
        self_asserted_only,
        container_ok,
        artifacts_ok,
        recomputed_digest,
        declared_digest,
        artifacts,
        recomputed_bindings,
        reasons,
    })
}

/// §4: A binds B iff some TOP-LEVEL string claim of A's resolved claims equals
/// HEX(SHA-256(B.sd_jwt_compact)). Compared to the recorded list as sorted canonical sets.
fn compute_bindings(artifacts: &[ArtifactResult], recorded: Option<&Value>, reasons: &mut Vec<String>) -> (Vec<Value>, bool) {
    let mut found: Vec<Value> = Vec::new();
    for a in artifacts {
        let Some(claims) = a.resolved.as_ref().and_then(Value::as_obj) else { continue };
        for b in artifacts {
            if std::ptr::eq(a, b) {
                continue;
            }
            for (claim, v) in claims {
                if let Value::Str(s) = v {
                    if *s == b.compact_sha256_hex {
                        found.push(Value::obj(vec![
                            ("claim", Value::str(claim)),
                            ("commits_to", Value::str(&b.name)),
                            ("encoding", Value::str("hex")),
                            ("in", Value::str(&a.name)),
                        ]));
                    }
                }
            }
        }
    }
    let mut mine: Vec<String> = found.iter().map(json::canonical).collect();
    mine.sort();
    let theirs: Option<Vec<String>> = recorded.and_then(Value::as_arr).map(|arr| {
        let mut v: Vec<String> = arr.iter().map(json::canonical).collect();
        v.sort();
        v
    });
    let ok = theirs.as_ref() == Some(&mine);
    if !ok {
        reasons.push(format!(
            "bindings: recomputed {} binding(s) != recorded {}",
            mine.len(),
            theirs.map(|t| t.len().to_string()).unwrap_or_else(|| "<missing>".into())
        ));
    }
    (found, ok)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn vectors_dir() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors")
    }

    /// §7: reproduce every `normative` block of the upstream conformance vectors, field by field.
    #[test]
    fn upstream_vectors_reproduce_all_eleven_normative_fields() {
        let dir = vectors_dir();
        let mut names: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok()?.file_name().into_string().ok())
            .filter_map(|f| f.strip_suffix(".expected.json").map(String::from))
            .collect();
        names.sort();
        assert_eq!(names.len(), 6, "expected the six upstream vectors");
        let mut accepts = 0;
        for name in &names {
            let exp = json::parse(&std::fs::read_to_string(dir.join(format!("{name}.expected.json"))).unwrap()).unwrap();
            let policy = Policy::from_expected(exp.get("policy").unwrap()).unwrap();
            let text = std::fs::read_to_string(dir.join(format!("{name}.json"))).unwrap();
            let ours = verify_pack(&text, &policy, None).unwrap().normative();
            let expected = exp.get("normative").unwrap();
            for f in NORMATIVE_FIELDS {
                assert_eq!(expected.get(f), ours.get(f), "vector {name}: field {f}");
            }
            if ours.get("valid") == Some(&Value::Bool(true)) {
                accepts += 1;
            }
        }
        assert_eq!(accepts, 1, "exactly one vector (valid_signed) is ACCEPT");
    }

    #[test]
    fn duplicate_top_level_key_is_rejected_before_any_verification() {
        let text = std::fs::read_to_string(vectors_dir().join("valid_signed.json")).unwrap();
        // Append a second `subject` key inside the top-level object.
        let dup = text.trim_end().trim_end_matches('}').to_string() + ", \"subject\": \"again\"}";
        let err = verify_pack(&dup, &Policy::default(), None).err().expect("duplicate key must be a hard error");
        assert!(err.contains("duplicate"), "{err}");
    }

    #[test]
    fn stripping_one_disclosure_fails_the_artifact_and_the_pack() {
        let text = std::fs::read_to_string(vectors_dir().join("valid_signed.json")).unwrap();
        let pack = json::parse(&text).unwrap();
        let compact = pack.get("artifacts").unwrap().as_arr().unwrap()[0]
            .get("sd_jwt_compact")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();
        // Drop the last disclosure (the resolved claims then differ from the recorded ones).
        let mut parts: Vec<&str> = compact.split('~').collect();
        assert!(parts.len() >= 3);
        parts.remove(parts.len() - 2);
        let stripped = parts.join("~");
        let tampered = text.replace(&compact, &stripped);
        assert_ne!(tampered, text);
        let v = verify_pack(&tampered, &Policy::default(), None).unwrap();
        assert!(!v.artifacts[0].verified);
        assert!(!v.artifacts[0].claims_match);
        assert!(v.artifacts[0].signature_ok, "the issuer signature itself is untouched");
        assert!(!v.digest_ok, "the compact is inside the digested content");
        assert!(!v.valid);
    }

    #[test]
    fn empty_artifacts_is_never_valid() {
        let text = r#"{"evidence_format":"ap2-evidence-pack/1.0","subject":"x","created_utc":"2026-09-06T00:00:00Z","artifacts":[],"bindings":[],"honest_scope":"none","evidence_digest_sha256":"0000000000000000000000000000000000000000000000000000000000000000","rfc3161_timestamp":{"anchored":false}}"#;
        let v = verify_pack(text, &Policy::default(), None).unwrap();
        assert!(!v.valid);
        assert!(!v.container_ok);
        assert!(!v.self_asserted_only);
    }
}
