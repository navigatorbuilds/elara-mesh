//! SD-JWT artifact verification (SPEC_AP2_EVIDENCE.md §2 + §6 step 2), fail-closed.

use crate::json::{self, Value};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct ArtifactResult {
    pub name: String,
    pub provenance_class: Option<String>,
    pub signature_ok: bool,
    pub disclosures_ok: bool,
    pub claims_match: bool,
    pub kb_present: bool,
    /// Some(true/false) = KB-JWT checked against cnf.jwk; None = absent or unverifiable.
    pub kb_verified: Option<bool>,
    pub verified: bool,
    pub resolved: Option<Value>,
    pub compact_sha256_hex: String,
    pub reasons: Vec<String>,
}

pub fn b64url(s: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD.decode(s).map_err(|e| format!("base64url: {e}"))
}

fn utf8(b: Vec<u8>) -> Result<String, String> {
    String::from_utf8(b).map_err(|e| format!("utf-8: {e}"))
}

pub fn p256_key_from_jwk(jwk: &Value) -> Result<VerifyingKey, String> {
    if jwk.get("kty").and_then(Value::as_str) != Some("EC") {
        return Err("jwk.kty != EC".into());
    }
    if jwk.get("crv").and_then(Value::as_str) != Some("P-256") {
        return Err("jwk.crv != P-256".into());
    }
    let x = b64url(jwk.get("x").and_then(Value::as_str).ok_or("jwk.x missing")?)?;
    let y = b64url(jwk.get("y").and_then(Value::as_str).ok_or("jwk.y missing")?)?;
    if x.len() != 32 || y.len() != 32 {
        return Err("jwk coordinates must be 32 bytes".into());
    }
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    VerifyingKey::from_sec1_bytes(&sec1).map_err(|e| format!("invalid P-256 point: {e}"))
}

fn verify_es256(key: &VerifyingKey, signing_input: &[u8], sig_b64: &str) -> Result<bool, String> {
    let sig = b64url(sig_b64)?;
    if sig.len() != 64 {
        return Err(format!("ES256 signature must be 64 bytes, got {}", sig.len()));
    }
    let sig = Signature::from_slice(&sig).map_err(|e| format!("ES256 signature: {e}"))?;
    Ok(key.verify(signing_input, &sig).is_ok())
}

struct Jws<'a> {
    signing_input: &'a str,
    header: Value,
    payload: Value,
    sig_b64: &'a str,
}

fn parse_jws(compact: &str) -> Result<Jws<'_>, String> {
    let parts: Vec<&str> = compact.split('.').collect();
    if parts.len() != 3 || parts.iter().any(|p| p.is_empty()) {
        return Err("JWS must have three non-empty parts".into());
    }
    let header = json::parse(&utf8(b64url(parts[0])?)?)?;
    let payload = json::parse(&utf8(b64url(parts[1])?)?)?;
    if header.as_obj().is_none() || payload.as_obj().is_none() {
        return Err("JWS header/payload must be objects".into());
    }
    Ok(Jws {
        signing_input: &compact[..parts[0].len() + 1 + parts[1].len()],
        header,
        payload,
        sig_b64: parts[2],
    })
}

struct Disclosure {
    digest: String,
    /// Some(name) for an object-property disclosure, None for an array element.
    name: Option<String>,
    value: Value,
    used: bool,
}

fn parse_disclosures(parts: &[&str]) -> Result<Vec<Disclosure>, String> {
    let mut out: Vec<Disclosure> = Vec::new();
    for d in parts {
        if d.is_empty() {
            return Err("empty disclosure".into());
        }
        let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(d.as_bytes()));
        if out.iter().any(|x| x.digest == digest) {
            return Err("duplicate disclosure".into());
        }
        let v = json::parse(&utf8(b64url(d)?)?)?;
        let arr = v.as_arr().ok_or("disclosure is not an array")?;
        let (name, value) = match arr {
            [Value::Str(_salt), Value::Str(name), value] => {
                if name == "_sd" || name == "..." {
                    return Err(format!("reserved claim name {name:?} in disclosure"));
                }
                (Some(name.clone()), value.clone())
            }
            [Value::Str(_salt), value] => (None, value.clone()),
            _ => return Err("malformed disclosure (expected [salt, name, value] or [salt, value])".into()),
        };
        out.push(Disclosure { digest, name, value, used: false });
    }
    Ok(out)
}

/// Resolve `_sd` / `...` references in place. Unmatched disclosures are detected by the caller.
fn resolve(v: &mut Value, ds: &mut [Disclosure]) -> Result<(), String> {
    match v {
        Value::Obj(entries) => {
            let mut sd_digests: Vec<String> = Vec::new();
            if let Some(pos) = entries.iter().position(|(k, _)| k == "_sd") {
                let (_, sd) = entries.remove(pos);
                let arr = sd.as_arr().ok_or("_sd is not an array")?;
                for d in arr {
                    sd_digests.push(d.as_str().ok_or("_sd digest is not a string")?.to_string());
                }
            }
            if let Some(pos) = entries.iter().position(|(k, _)| k == "_sd_alg") {
                let (_, alg) = entries.remove(pos);
                if alg.as_str() != Some("sha-256") {
                    return Err("unsupported _sd_alg (only sha-256)".into());
                }
            }
            let mut seen = std::collections::HashSet::new();
            for dg in &sd_digests {
                if !seen.insert(dg.clone()) {
                    return Err("digest listed twice in one _sd".into());
                }
                if let Some(i) = ds.iter().position(|d| d.digest == *dg) {
                    if ds[i].used {
                        return Err("disclosure referenced twice".into());
                    }
                    ds[i].used = true;
                    let name = ds[i]
                        .name
                        .clone()
                        .ok_or("array-element disclosure referenced from an _sd array")?;
                    if entries.iter().any(|(k, _)| *k == name) {
                        return Err(format!("disclosed claim {name:?} collides with an existing claim"));
                    }
                    entries.push((name, ds[i].value.clone()));
                }
                // An unreferenced digest is a decoy or a withheld claim: allowed.
            }
            for (_, child) in entries.iter_mut() {
                resolve(child, ds)?;
            }
        }
        Value::Arr(items) => {
            let mut out: Vec<Value> = Vec::with_capacity(items.len());
            for mut item in items.drain(..) {
                if let Some(obj) = item.as_obj() {
                    if obj.len() == 1 && obj[0].0 == "..." {
                        let dg = obj[0].1.as_str().ok_or("'...' digest is not a string")?.to_string();
                        if let Some(i) = ds.iter().position(|d| d.digest == dg) {
                            if ds[i].used {
                                return Err("disclosure referenced twice".into());
                            }
                            if ds[i].name.is_some() {
                                return Err("object-property disclosure referenced from an array element".into());
                            }
                            ds[i].used = true;
                            let mut val = ds[i].value.clone();
                            resolve(&mut val, ds)?;
                            out.push(val);
                        }
                        // Withheld array element: dropped.
                        continue;
                    }
                    if obj.iter().any(|(k, _)| k == "...") {
                        return Err("object mixes '...' with other keys".into());
                    }
                }
                resolve(&mut item, ds)?;
                out.push(item);
            }
            *items = out;
        }
        _ => {}
    }
    Ok(())
}

pub fn verify_artifact(art: &Value) -> ArtifactResult {
    let mut r = ArtifactResult {
        name: art.get("name").and_then(Value::as_str).unwrap_or("<unnamed>").to_string(),
        provenance_class: art
            .get("key")
            .and_then(|k| k.get("provenance_class"))
            .and_then(Value::as_str)
            .map(String::from),
        signature_ok: false,
        disclosures_ok: false,
        claims_match: false,
        kb_present: false,
        kb_verified: None,
        verified: false,
        resolved: None,
        compact_sha256_hex: String::new(),
        reasons: Vec::new(),
    };
    if art.get("name").and_then(Value::as_str).is_none() {
        r.reasons.push("artifact name missing".into());
        return r;
    }
    let compact = match art.get("sd_jwt_compact").and_then(Value::as_str) {
        Some(c) => c,
        None => {
            r.reasons.push("sd_jwt_compact missing".into());
            return r;
        }
    };
    r.compact_sha256_hex = hex::encode(Sha256::digest(compact.as_bytes()));
    let key = match art
        .get("key")
        .and_then(|k| k.get("jwk"))
        .ok_or_else(|| "key.jwk missing".to_string())
        .and_then(p256_key_from_jwk)
    {
        Ok(k) => k,
        Err(e) => {
            r.reasons.push(format!("snapshotted key: {e}"));
            return r;
        }
    };
    let parts: Vec<&str> = compact.split('~').collect();
    if parts.len() < 2 {
        r.reasons.push("SD-JWT compact lacks the '~' separator".into());
        return r;
    }
    let jwt = parts[0];
    let kb = parts[parts.len() - 1];
    let disc_parts = &parts[1..parts.len() - 1];
    let jws = match parse_jws(jwt) {
        Ok(j) => j,
        Err(e) => {
            r.reasons.push(format!("issuer JWT: {e}"));
            return r;
        }
    };
    if jws.header.get("alg").and_then(Value::as_str) != Some("ES256") {
        r.reasons.push("issuer JWT alg is not ES256".into());
        return r;
    }
    if jws.header.get("crit").is_some() {
        r.reasons.push("issuer JWT carries 'crit' (unsupported, fail-closed)".into());
        return r;
    }
    match verify_es256(&key, jws.signing_input.as_bytes(), jws.sig_b64) {
        Ok(ok) => {
            r.signature_ok = ok;
            if !ok {
                r.reasons.push("issuer JWT ES256 signature INVALID under the snapshotted key".into());
            }
        }
        Err(e) => r.reasons.push(format!("issuer JWT signature: {e}")),
    }
    let mut resolved = jws.payload.clone();
    let outcome = parse_disclosures(disc_parts).and_then(|mut ds| {
        resolve(&mut resolved, &mut ds)?;
        if let Some(u) = ds.iter().find(|d| !d.used) {
            return Err(format!("unmatched disclosure (digest {})", u.digest));
        }
        Ok(())
    });
    match outcome {
        Ok(()) => r.disclosures_ok = true,
        Err(e) => r.reasons.push(format!("disclosures: {e}")),
    }
    if r.disclosures_ok {
        match art.get("resolved_claims") {
            Some(rec) => {
                r.claims_match = json::canonical(rec) == json::canonical(&resolved);
                if !r.claims_match {
                    r.reasons.push("resolved claims differ from the recorded resolved_claims".into());
                }
            }
            None => r.reasons.push("resolved_claims missing".into()),
        }
        r.resolved = Some(resolved);
    }
    if !kb.is_empty() {
        r.kb_present = true;
        match jws.payload.get("cnf").and_then(|c| c.get("jwk")) {
            None => r
                .reasons
                .push("KB-JWT present but the issuer payload has no cnf.jwk: recorded, unverifiable".into()),
            Some(jwk) => {
                let presented = &compact[..compact.len() - kb.len()];
                r.kb_verified = Some(verify_kb(jwk, kb, presented, &mut r.reasons));
            }
        }
    }
    let rec_present = art.get("kb_jwt").and_then(|k| k.get("present")).and_then(Value::as_bool);
    if rec_present != Some(r.kb_present) {
        r.reasons.push(format!(
            "diagnostic: kb_jwt.present recorded as {rec_present:?}, actual {}",
            r.kb_present
        ));
    }
    r.verified = r.signature_ok && r.disclosures_ok && r.claims_match && r.kb_verified != Some(false);
    r
}

fn verify_kb(jwk: &Value, kb: &str, presented: &str, reasons: &mut Vec<String>) -> bool {
    let key = match p256_key_from_jwk(jwk) {
        Ok(k) => k,
        Err(e) => {
            reasons.push(format!("cnf.jwk: {e}"));
            return false;
        }
    };
    let jws = match parse_jws(kb) {
        Ok(j) => j,
        Err(e) => {
            reasons.push(format!("KB-JWT: {e}"));
            return false;
        }
    };
    if jws.header.get("typ").and_then(Value::as_str) != Some("kb+jwt") {
        reasons.push("KB-JWT typ is not kb+jwt".into());
        return false;
    }
    if jws.header.get("alg").and_then(Value::as_str) != Some("ES256") {
        reasons.push("KB-JWT alg is not ES256".into());
        return false;
    }
    match verify_es256(&key, jws.signing_input.as_bytes(), jws.sig_b64) {
        Ok(true) => {}
        Ok(false) => {
            reasons.push("KB-JWT ES256 signature INVALID under cnf.jwk".into());
            return false;
        }
        Err(e) => {
            reasons.push(format!("KB-JWT signature: {e}"));
            return false;
        }
    }
    let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(presented.as_bytes()));
    if jws.payload.get("sd_hash").and_then(Value::as_str) != Some(expected.as_str()) {
        reasons.push("KB-JWT sd_hash does not commit to issuer-JWT~disclosure*~".into());
        return false;
    }
    true
}
