//! Producer signature block (SPEC_AP2_EVIDENCE.md §5), fail-closed.

use crate::json::Value;
use crate::pack::Policy;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use p256::ecdsa::signature::Verifier as _;

pub struct ProducerOutcome {
    pub present: bool,
    pub ok: Option<bool>,
    pub trusted: Option<bool>,
    pub pq_protected: bool,
}

enum Outcome {
    Pass,
    Fail(String),
    Gap(String),
}

pub const ML_DSA_65_PK_LEN: usize = 1952;
pub const ML_DSA_65_SIG_LEN: usize = 3309;

/// `msg` = ASCII bytes of the lowercase-hex RECOMPUTED digest (§5).
pub fn verify(block: Option<&Value>, msg: &[u8], policy: &Policy, reasons: &mut Vec<String>) -> ProducerOutcome {
    let Some(block) = block else {
        return ProducerOutcome { present: false, ok: None, trusted: None, pq_protected: false };
    };
    let mut out = ProducerOutcome {
        present: true,
        ok: Some(false),
        trusted: policy.pins.as_ref().map(|_| false),
        pq_protected: false,
    };
    if block.as_obj().is_none() {
        reasons.push("producer_signatures is not an object".into());
        return out;
    }
    match block.get("scheme").and_then(Value::as_str) {
        Some("hybrid") | Some("classical-only") => {}
        other => {
            reasons.push(format!("producer scheme {other:?} is not hybrid|classical-only"));
            return out;
        }
    }
    if block.get("over").and_then(Value::as_str) != Some("evidence_digest_sha256") {
        reasons.push("producer 'over' is not evidence_digest_sha256".into());
        return out;
    }
    let Some(sigs) = block.get("signatures").and_then(Value::as_arr) else {
        reasons.push("producer signatures is not an array".into());
        return out;
    };
    let (mut pass, mut fail, mut gap) = (0usize, 0usize, 0usize);
    let mut all_pinned = true;
    let mut pq = false;
    for (i, s) in sigs.iter().enumerate() {
        let alg = s.get("sig_alg").and_then(Value::as_str);
        let pk = s.get("public_key_b64").and_then(Value::as_str).and_then(|b| STANDARD.decode(b).ok());
        let sig = s.get("signature_b64").and_then(Value::as_str).and_then(|b| STANDARD.decode(b).ok());
        let pq_flag = s.get("post_quantum").and_then(Value::as_bool);
        let (Some(alg), Some(pk), Some(sig), Some(pq_flag)) = (alg, pk, sig, pq_flag) else {
            fail += 1;
            all_pinned = false;
            reasons.push(format!("producer signature #{i}: malformed entry"));
            continue;
        };
        let pinned = policy.pinned(alg, &pk);
        if pinned == Some(false) {
            all_pinned = false;
        }
        let outcome = match alg {
            "ed25519" => verify_ed25519(&pk, &sig, msg),
            "ecdsa-p256" => verify_p256(&pk, &sig, msg),
            "ml-dsa-65" => verify_mldsa65(&pk, &sig, msg),
            other => Outcome::Gap(format!("unknown sig_alg {other:?}")),
        };
        let expects_pq = alg == "ml-dsa-65";
        match outcome {
            Outcome::Pass => {
                if pq_flag != expects_pq {
                    fail += 1;
                    reasons.push(format!(
                        "producer signature #{i} ({alg}): post_quantum={pq_flag} contradicts the algorithm"
                    ));
                } else {
                    pass += 1;
                    if expects_pq && pinned != Some(false) {
                        pq = true;
                    }
                }
            }
            Outcome::Fail(why) => {
                fail += 1;
                reasons.push(format!("producer signature #{i} ({alg}) INVALID: {why}"));
            }
            Outcome::Gap(why) => {
                gap += 1;
                reasons.push(format!("producer signature #{i}: verification GAP: {why}"));
            }
        }
    }
    out.ok = Some(fail == 0 && gap == 0 && pass >= 1);
    out.trusted = policy.pins.as_ref().map(|_| all_pinned && !sigs.is_empty());
    out.pq_protected = pq;
    out
}

fn verify_ed25519(pk: &[u8], sig: &[u8], msg: &[u8]) -> Outcome {
    let Ok(pk): Result<[u8; 32], _> = pk.try_into() else {
        return Outcome::Fail(format!("ed25519 key must be 32 bytes, got {}", pk.len()));
    };
    let key = match ed25519_dalek::VerifyingKey::from_bytes(&pk) {
        Ok(k) => k,
        Err(e) => return Outcome::Fail(format!("ed25519 key: {e}")),
    };
    let Ok(sig): Result<[u8; 64], _> = sig.try_into() else {
        return Outcome::Fail(format!("ed25519 signature must be 64 bytes, got {}", sig.len()));
    };
    let sig = ed25519_dalek::Signature::from_bytes(&sig);
    if key.verify_strict(msg, &sig).is_ok() {
        Outcome::Pass
    } else {
        Outcome::Fail("signature does not verify".into())
    }
}

fn verify_p256(pk: &[u8], sig: &[u8], msg: &[u8]) -> Outcome {
    if pk.len() != 65 || pk[0] != 0x04 {
        return Outcome::Fail(format!("ecdsa-p256 key must be a 65-byte uncompressed point, got {} bytes", pk.len()));
    }
    let key = match p256::ecdsa::VerifyingKey::from_sec1_bytes(pk) {
        Ok(k) => k,
        Err(e) => return Outcome::Fail(format!("ecdsa-p256 key: {e}")),
    };
    if sig.len() != 64 {
        return Outcome::Fail(format!("ecdsa-p256 signature must be raw r||s (64 bytes), got {}", sig.len()));
    }
    let sig = match p256::ecdsa::Signature::from_slice(sig) {
        Ok(s) => s,
        Err(e) => return Outcome::Fail(format!("ecdsa-p256 signature: {e}")),
    };
    if key.verify(msg, &sig).is_ok() {
        Outcome::Pass
    } else {
        Outcome::Fail("signature does not verify".into())
    }
}

fn verify_mldsa65(pk: &[u8], sig: &[u8], msg: &[u8]) -> Outcome {
    if pk.len() != ML_DSA_65_PK_LEN {
        return Outcome::Fail(format!("ml-dsa-65 key must be {ML_DSA_65_PK_LEN} bytes, got {}", pk.len()));
    }
    if sig.len() != ML_DSA_65_SIG_LEN {
        return Outcome::Fail(format!("ml-dsa-65 signature must be {ML_DSA_65_SIG_LEN} bytes, got {}", sig.len()));
    }
    // FIPS 204 final, pure/external interface, empty context — the exact function Elara records use.
    match elara_record::pqc::dilithium3_verify(msg, sig, pk) {
        Ok(true) => Outcome::Pass,
        Ok(false) => Outcome::Fail("signature does not verify".into()),
        Err(e) => Outcome::Fail(format!("{e}")),
    }
}
