//! RFC 3161 TimeStampResp verification (SPEC_AP2_EVIDENCE.md §6 step 4).
//!
//! Outcome semantics (fail-closed):
//!   Failed       — status not granted, malformed DER, imprint ≠ recomputed digest,
//!                  messageDigest attribute mismatch, CMS signature invalid, EKU missing,
//!                  no path to the supplied trust anchor, or genTime outside validity;
//!   Unverifiable — internally consistent but something could not be checked here
//!                  (unsupported algorithm, signer certificate not embedded, or no
//!                  `--tsa-root` supplied — the spec names no trust root);
//!   Verified     — everything above passes AND the signer chains to the supplied root.

use crate::der::{self, Tlv};
use p256::ecdsa::signature::hazmat::PrehashVerifier as _;
use rsa::{BigUint, Pkcs1v15Sign, Pss, RsaPublicKey};
use sha2::{Digest, Sha256, Sha384, Sha512};

pub enum Outcome {
    Verified,
    Failed(String),
    Unverifiable(String),
}

const OID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
const OID_TST_INFO: &str = "1.2.840.113549.1.9.16.1.4";
const OID_SHA256: &str = "2.16.840.1.101.3.4.2.1";
const OID_SHA384: &str = "2.16.840.1.101.3.4.2.2";
const OID_SHA512: &str = "2.16.840.1.101.3.4.2.3";
const OID_MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
const OID_CONTENT_TYPE: &str = "1.2.840.113549.1.9.3";
const OID_RSA: &str = "1.2.840.113549.1.1.1";
const OID_MGF1: &str = "1.2.840.113549.1.1.8";
const OID_RSA_PSS: &str = "1.2.840.113549.1.1.10";
const OID_SHA256_RSA: &str = "1.2.840.113549.1.1.11";
const OID_SHA384_RSA: &str = "1.2.840.113549.1.1.12";
const OID_SHA512_RSA: &str = "1.2.840.113549.1.1.13";
const OID_EC_PUBKEY: &str = "1.2.840.10045.2.1";
const OID_P256: &str = "1.2.840.10045.3.1.7";
const OID_P384: &str = "1.3.132.0.34";
const OID_ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
const OID_ECDSA_SHA384: &str = "1.2.840.10045.4.3.3";
const OID_ECDSA_SHA512: &str = "1.2.840.10045.4.3.4";
const OID_SKI: &str = "2.5.29.14";
const OID_EKU: &str = "2.5.29.37";
const OID_KP_TIMESTAMPING: &str = "1.3.6.1.5.5.7.3.8";

#[derive(Clone)]
enum Spki {
    Rsa { n: Vec<u8>, e: Vec<u8> },
    P256(Vec<u8>),
    P384(Vec<u8>),
    Other(String),
}

#[derive(Clone)]
struct Cert {
    raw: Vec<u8>,
    tbs_raw: Vec<u8>,
    serial: Vec<u8>,
    issuer_raw: Vec<u8>,
    subject_raw: Vec<u8>,
    not_before: String,
    not_after: String,
    spki: Spki,
    sig_alg: String,
    sig_params: Option<Vec<u8>>,
    signature: Vec<u8>,
    ski: Option<Vec<u8>>,
    eku: Vec<String>,
}

enum SigCheck {
    Good,
    Bad,
    Unsupported(String),
}

pub fn verify_token(resp_der: &[u8], digest: &[u8], root: Option<&[u8]>) -> Outcome {
    match verify_inner(resp_der, digest, root) {
        Ok(o) => o,
        Err(e) => Outcome::Failed(e),
    }
}

fn verify_inner(resp: &[u8], digest: &[u8], root: Option<&[u8]>) -> Result<Outcome, String> {
    let (top, rest) = der::read(resp)?;
    if !rest.is_empty() {
        return Err("trailing bytes after TimeStampResp".into());
    }
    let items = der::seq(Some(&top), "TimeStampResp")?;
    let status_items = der::seq(items.first(), "PKIStatusInfo")?;
    let status = der::int_u32(status_items.first())?;
    if status != 0 && status != 1 {
        return Err(format!("PKIStatus {status} is not granted"));
    }
    let token = items.get(1).ok_or("status granted but no timeStampToken")?;
    let ci = der::seq(Some(token), "ContentInfo")?;
    if der::oid(ci.first())? != OID_SIGNED_DATA {
        return Err("timeStampToken contentType is not id-signedData".into());
    }
    let sd_wrapper = der::expect(ci.get(1), 0xA0, "ContentInfo.content")?;
    let (sd_tlv, _) = der::read(sd_wrapper)?;
    let sd = der::seq(Some(&sd_tlv), "SignedData")?;
    let eci = der::seq(sd.get(2), "EncapsulatedContentInfo")?;
    if der::oid(eci.first())? != OID_TST_INFO {
        return Err("eContentType is not id-ct-TSTInfo".into());
    }
    let econtent = der::expect(eci.get(1), 0xA0, "eContent")?;
    let (octets, _) = der::read(econtent)?;
    let tst_bytes = der::expect(Some(&octets), 0x04, "eContent OCTET STRING")?;

    // TSTInfo: version, policy, messageImprint, serialNumber, genTime, ...
    let (tst_tlv, _) = der::read(tst_bytes)?;
    let tst = der::seq(Some(&tst_tlv), "TSTInfo")?;
    let mi = der::seq(tst.get(2), "MessageImprint")?;
    let mi_alg = der::seq(mi.first(), "MessageImprint.hashAlgorithm")?;
    if der::oid(mi_alg.first())? != OID_SHA256 {
        return Err("messageImprint hash algorithm is not sha256".into());
    }
    let hashed = der::expect(mi.get(1), 0x04, "hashedMessage")?;
    if hashed != digest {
        return Err(format!(
            "messageImprint {} != recomputed evidence digest {}",
            hex::encode(hashed),
            hex::encode(digest)
        ));
    }
    let gen_time = der::time(tst.get(4))?;

    // certificates [0] IMPLICIT, crls [1], signerInfos SET
    let mut certs: Vec<Cert> = Vec::new();
    let mut signer_infos: Option<Tlv> = None;
    for it in sd.iter().skip(3) {
        match it.tag {
            0xA0 => {
                for c in der::items(it.content)? {
                    if c.tag == 0x30 {
                        certs.push(parse_cert(&c)?);
                    }
                }
            }
            0x31 => signer_infos = Some(*it),
            _ => {}
        }
    }
    let sis = der::items(signer_infos.ok_or("signerInfos missing")?.content)?;
    if sis.len() != 1 {
        return Err(format!("RFC 3161 requires exactly one SignerInfo, found {}", sis.len()));
    }
    let si = der::seq(sis.first(), "SignerInfo")?;
    let sid = si.get(1).ok_or("SignerIdentifier missing")?;
    let dalg = der::oid(der::seq(si.get(2), "digestAlgorithm")?.first())?;
    let mut idx = 3;
    let signed_attrs = match si.get(idx) {
        Some(t) if t.tag == 0xA0 => {
            idx += 1;
            *t
        }
        _ => return Err("signedAttrs missing (RFC 3161 requires them)".into()),
    };
    let sig_alg_seq = der::seq(si.get(idx), "signatureAlgorithm")?;
    let sig_alg = der::oid(sig_alg_seq.first())?;
    let sig_params: Option<Vec<u8>> = sig_alg_seq.get(1).map(|p| p.raw.to_vec());
    let signature = der::expect(si.get(idx + 1), 0x04, "signature")?;

    let mut msg_digest: Option<&[u8]> = None;
    let mut content_type: Option<String> = None;
    for a in der::items(signed_attrs.content)? {
        let a = der::seq(Some(&a), "Attribute")?;
        let t = der::oid(a.first())?;
        let vals = der::items(der::expect(a.get(1), 0x31, "attrValues")?)?;
        if t == OID_MESSAGE_DIGEST {
            msg_digest = Some(der::expect(vals.first(), 0x04, "messageDigest")?);
        } else if t == OID_CONTENT_TYPE {
            content_type = Some(der::oid(vals.first())?);
        }
    }
    if content_type.as_deref() != Some(OID_TST_INFO) {
        return Err("signed contentType attribute is not id-ct-TSTInfo".into());
    }
    let Some(hash) = hash_fn(&dalg) else {
        return Ok(Outcome::Unverifiable(format!("SignerInfo digest algorithm {dalg} unsupported here")));
    };
    if msg_digest != Some(hash(tst_bytes).as_slice()) {
        return Err("signed messageDigest attribute != hash(TSTInfo)".into());
    }
    let Some(signer) = find_signer(&certs, sid)? else {
        return Ok(Outcome::Unverifiable("signer certificate is not embedded in the token".into()));
    };
    // The signature covers DER(SET OF Attribute): re-tag the [0] IMPLICIT wrapper as SET.
    let mut set_der = signed_attrs.raw.to_vec();
    set_der[0] = 0x31;
    match verify_sig(&signer.spki, &sig_alg, sig_params.as_deref(), Some(&dalg), &set_der, signature)? {
        SigCheck::Good => {}
        SigCheck::Bad => return Err("CMS signature INVALID under the embedded signer certificate".into()),
        SigCheck::Unsupported(w) => return Ok(Outcome::Unverifiable(w)),
    }
    if !signer.eku.iter().any(|e| e == OID_KP_TIMESTAMPING) {
        return Err("signer certificate lacks the id-kp-timeStamping extended key usage".into());
    }
    let Some(root) = root else {
        return Ok(Outcome::Unverifiable(
            "token is internally consistent and signed by its embedded certificate, but no TSA trust anchor was supplied (--tsa-root); the spec names no trust root".into(),
        ));
    };
    let root_der = pem_or_der(root)?;
    let (root_tlv, _) = der::read(&root_der)?;
    let root = parse_cert(&root_tlv)?;
    chain(signer, &certs, &root, &gen_time)
}

fn chain(signer: &Cert, certs: &[Cert], root: &Cert, gen_time: &str) -> Result<Outcome, String> {
    let mut cur = signer.clone();
    for _ in 0..4 {
        if gen_time < cur.not_before.as_str() || gen_time > cur.not_after.as_str() {
            return Err(format!(
                "certificate not valid at genTime {gen_time} (validity {}..{})",
                cur.not_before, cur.not_after
            ));
        }
        if cur.raw == root.raw {
            return Ok(Outcome::Verified);
        }
        if cur.issuer_raw == root.subject_raw {
            return match verify_sig(&root.spki, &cur.sig_alg, cur.sig_params.as_deref(), None, &cur.tbs_raw, &cur.signature)? {
                SigCheck::Good => Ok(Outcome::Verified),
                SigCheck::Bad => Err("certificate signature does not verify under the supplied TSA root".into()),
                SigCheck::Unsupported(w) => Ok(Outcome::Unverifiable(w)),
            };
        }
        let mut next: Option<Cert> = None;
        for c in certs {
            if c.raw == cur.raw || c.subject_raw != cur.issuer_raw {
                continue;
            }
            if let SigCheck::Good =
                verify_sig(&c.spki, &cur.sig_alg, cur.sig_params.as_deref(), None, &cur.tbs_raw, &cur.signature)?
            {
                next = Some(c.clone());
                break;
            }
        }
        cur = next.ok_or("no certificate path from the signer to the supplied TSA root")?;
    }
    Err("certificate path too long".into())
}

fn hash_fn(oid: &str) -> Option<fn(&[u8]) -> Vec<u8>> {
    match oid {
        OID_SHA256 => Some(|d| Sha256::digest(d).to_vec()),
        OID_SHA384 => Some(|d| Sha384::digest(d).to_vec()),
        OID_SHA512 => Some(|d| Sha512::digest(d).to_vec()),
        _ => None,
    }
}

fn verify_sig(
    spki: &Spki,
    alg: &str,
    params: Option<&[u8]>,
    cms_digest: Option<&str>,
    data: &[u8],
    sig: &[u8],
) -> Result<SigCheck, String> {
    match (spki, alg) {
        (Spki::Rsa { n, e }, OID_RSA | OID_SHA256_RSA | OID_SHA384_RSA | OID_SHA512_RSA) => {
            let digest_oid = match alg {
                OID_RSA => cms_digest.ok_or("rsaEncryption needs a CMS digest algorithm")?,
                OID_SHA256_RSA => OID_SHA256,
                OID_SHA384_RSA => OID_SHA384,
                _ => OID_SHA512,
            };
            let key = rsa_key(n, e)?;
            let ok = match digest_oid {
                OID_SHA256 => key.verify(Pkcs1v15Sign::new::<Sha256>(), &Sha256::digest(data), sig).is_ok(),
                OID_SHA384 => key.verify(Pkcs1v15Sign::new::<Sha384>(), &Sha384::digest(data), sig).is_ok(),
                OID_SHA512 => key.verify(Pkcs1v15Sign::new::<Sha512>(), &Sha512::digest(data), sig).is_ok(),
                other => return Ok(SigCheck::Unsupported(format!("RSA digest {other} unsupported"))),
            };
            Ok(if ok { SigCheck::Good } else { SigCheck::Bad })
        }
        (Spki::Rsa { n, e }, OID_RSA_PSS) => {
            let hash = pss_hash(params)?;
            let key = rsa_key(n, e)?;
            let ok = match hash.as_str() {
                OID_SHA256 => key.verify(Pss::new::<Sha256>(), &Sha256::digest(data), sig).is_ok(),
                OID_SHA384 => key.verify(Pss::new::<Sha384>(), &Sha384::digest(data), sig).is_ok(),
                OID_SHA512 => key.verify(Pss::new::<Sha512>(), &Sha512::digest(data), sig).is_ok(),
                other => return Ok(SigCheck::Unsupported(format!("RSA-PSS hash {other} unsupported"))),
            };
            Ok(if ok { SigCheck::Good } else { SigCheck::Bad })
        }
        (Spki::P256(_) | Spki::P384(_), OID_ECDSA_SHA256 | OID_ECDSA_SHA384 | OID_ECDSA_SHA512 | OID_EC_PUBKEY) => {
            // ECDSA over the named digest; a bare id-ecPublicKey signatureAlgorithm (RFC 5753 §2.1.1
            // permits it in CMS) takes the digest from the SignerInfo digestAlgorithm.
            let digest_oid = match alg {
                OID_ECDSA_SHA256 => OID_SHA256,
                OID_ECDSA_SHA384 => OID_SHA384,
                OID_ECDSA_SHA512 => OID_SHA512,
                _ => cms_digest.ok_or("id-ecPublicKey signatureAlgorithm needs a CMS digest algorithm")?,
            };
            let Some(hash) = hash_fn(digest_oid) else {
                return Ok(SigCheck::Unsupported(format!("ECDSA digest {digest_oid} unsupported")));
            };
            let prehash = hash(data);
            let ok = match spki {
                Spki::P256(point) => {
                    let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(point).map_err(|e| format!("EC key: {e}"))?;
                    match p256::ecdsa::Signature::from_der(sig) {
                        Ok(s) => key.verify_prehash(&prehash, &s).is_ok(),
                        Err(_) => false,
                    }
                }
                Spki::P384(point) => {
                    let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(point).map_err(|e| format!("EC key: {e}"))?;
                    match p384::ecdsa::Signature::from_der(sig) {
                        Ok(s) => key.verify_prehash(&prehash, &s).is_ok(),
                        Err(_) => false,
                    }
                }
                _ => unreachable!(),
            };
            Ok(if ok { SigCheck::Good } else { SigCheck::Bad })
        }
        (Spki::Other(o), _) => Ok(SigCheck::Unsupported(format!("public key algorithm {o} unsupported"))),
        (_, other) => Ok(SigCheck::Unsupported(format!("signature algorithm {other} unsupported"))),
    }
}

fn rsa_key(n: &[u8], e: &[u8]) -> Result<RsaPublicKey, String> {
    RsaPublicKey::new_with_max_size(BigUint::from_bytes_be(n), BigUint::from_bytes_be(e), 16384)
        .map_err(|e| format!("RSA key: {e}"))
}

/// RSASSA-PSS-params: hashAlgorithm [0] (default sha1), maskGenAlgorithm [1] (default mgf1-sha1).
fn pss_hash(params: Option<&[u8]>) -> Result<String, String> {
    let Some(p) = params else { return Ok("sha1".into()) };
    let (tlv, _) = der::read(p)?;
    let items = der::seq(Some(&tlv), "RSASSA-PSS-params")?;
    let mut hash = "sha1".to_string();
    let mut mgf_hash: Option<String> = None;
    for it in &items {
        match it.tag {
            0xA0 => {
                let (alg, _) = der::read(it.content)?;
                hash = der::oid(der::seq(Some(&alg), "hashAlgorithm")?.first())?;
            }
            0xA1 => {
                let (mgf, _) = der::read(it.content)?;
                let m = der::seq(Some(&mgf), "maskGenAlgorithm")?;
                if der::oid(m.first())? != OID_MGF1 {
                    return Ok("non-mgf1".into());
                }
                let h = m.get(1).ok_or("mgf1 hashAlgorithm missing")?;
                mgf_hash = Some(der::oid(der::seq(Some(h), "mgf1 hashAlgorithm")?.first())?);
            }
            _ => {}
        }
    }
    if let Some(m) = mgf_hash {
        if m != hash {
            return Ok("mgf1-hash-mismatch".into());
        }
    }
    Ok(hash)
}

fn find_signer<'a>(certs: &'a [Cert], sid: &Tlv) -> Result<Option<&'a Cert>, String> {
    match sid.tag {
        0x30 => {
            let s = der::seq(Some(sid), "IssuerAndSerialNumber")?;
            let issuer = s.first().ok_or("issuer missing")?.raw;
            let serial = der::expect(s.get(1), 0x02, "serialNumber")?;
            Ok(certs.iter().find(|c| c.issuer_raw == issuer && c.serial == serial))
        }
        0x80 => Ok(certs.iter().find(|c| c.ski.as_deref() == Some(sid.content))),
        other => Err(format!("unknown SignerIdentifier tag 0x{other:02x}")),
    }
}

fn parse_cert(tlv: &Tlv) -> Result<Cert, String> {
    let c = der::seq(Some(tlv), "Certificate")?;
    let tbs = c.first().ok_or("tbsCertificate missing")?;
    let t = der::seq(Some(tbs), "TBSCertificate")?;
    let mut i = 0;
    if matches!(t.first(), Some(v) if v.tag == 0xA0) {
        i += 1;
    }
    let serial = der::expect(t.get(i), 0x02, "serialNumber")?.to_vec();
    i += 2; // serial, signature AlgorithmIdentifier
    let issuer_raw = t.get(i).ok_or("issuer missing")?.raw.to_vec();
    i += 1;
    let validity = der::seq(t.get(i), "Validity")?;
    i += 1;
    let not_before = der::time(validity.first())?;
    let not_after = der::time(validity.get(1))?;
    let subject_raw = t.get(i).ok_or("subject missing")?.raw.to_vec();
    i += 1;
    let spki = parse_spki(t.get(i))?;
    i += 1;
    let mut ski = None;
    let mut eku = Vec::new();
    for rest in &t[i..] {
        if rest.tag != 0xA3 {
            continue;
        }
        let (exts, _) = der::read(rest.content)?;
        for ext in der::items(exts.content)? {
            let e = der::seq(Some(&ext), "Extension")?;
            let oid = der::oid(e.first())?;
            let val = der::expect(e.last(), 0x04, "extnValue")?;
            if oid == OID_SKI {
                let (inner, _) = der::read(val)?;
                ski = Some(der::expect(Some(&inner), 0x04, "SubjectKeyIdentifier")?.to_vec());
            } else if oid == OID_EKU {
                let (inner, _) = der::read(val)?;
                for o in der::items(inner.content)? {
                    eku.push(der::oid(Some(&o))?);
                }
            }
        }
    }
    let sa = der::seq(c.get(1), "signatureAlgorithm")?;
    let sig_alg = der::oid(sa.first())?;
    let sig_params = sa.get(1).map(|p| p.raw.to_vec());
    let bits = der::expect(c.get(2), 0x03, "signatureValue")?;
    if bits.is_empty() || bits[0] != 0 {
        return Err("signatureValue BIT STRING with unused bits unsupported".into());
    }
    Ok(Cert {
        raw: tlv.raw.to_vec(),
        tbs_raw: tbs.raw.to_vec(),
        serial,
        issuer_raw,
        subject_raw,
        not_before,
        not_after,
        spki,
        sig_alg,
        sig_params,
        signature: bits[1..].to_vec(),
        ski,
        eku,
    })
}

fn parse_spki(t: Option<&Tlv>) -> Result<Spki, String> {
    let s = der::seq(t, "SubjectPublicKeyInfo")?;
    let alg = der::seq(s.first(), "AlgorithmIdentifier")?;
    let oid = der::oid(alg.first())?;
    let bits = der::expect(s.get(1), 0x03, "subjectPublicKey")?;
    if bits.is_empty() || bits[0] != 0 {
        return Err("subjectPublicKey BIT STRING with unused bits unsupported".into());
    }
    let key = &bits[1..];
    Ok(match oid.as_str() {
        OID_RSA => {
            let (rk, _) = der::read(key)?;
            let r = der::seq(Some(&rk), "RSAPublicKey")?;
            let strip = |b: &[u8]| -> Vec<u8> {
                let mut i = 0;
                while i + 1 < b.len() && b[i] == 0 {
                    i += 1;
                }
                b[i..].to_vec()
            };
            Spki::Rsa {
                n: strip(der::expect(r.first(), 0x02, "modulus")?),
                e: strip(der::expect(r.get(1), 0x02, "publicExponent")?),
            }
        }
        OID_EC_PUBKEY => {
            let curve = alg.get(1).and_then(|c| der::oid(Some(c)).ok());
            match curve.as_deref() {
                Some(OID_P256) => Spki::P256(key.to_vec()),
                Some(OID_P384) => Spki::P384(key.to_vec()),
                _ => Spki::Other(format!("EC curve {curve:?}")),
            }
        }
        other => Spki::Other(other.to_string()),
    })
}

fn pem_or_der(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let text = String::from_utf8_lossy(bytes);
    if let Some(start) = text.find("-----BEGIN CERTIFICATE-----") {
        let body = &text[start + "-----BEGIN CERTIFICATE-----".len()..];
        let end = body.find("-----END CERTIFICATE-----").ok_or("PEM: END marker missing")?;
        let b64: String = body[..end].chars().filter(|c| !c.is_whitespace()).collect();
        use base64::Engine as _;
        return base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| format!("PEM base64: {e}"));
    }
    Ok(bytes.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST_HEX: &str = "59065cf1cf6615a40c5edde97740bc683fafb94626171f88d92e74f6fa971a90";

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)).unwrap()
    }

    /// A real freetsa.org token over an Elara epoch seal (examples/verify/epoch-107599-zone-0.json.tsr).
    #[test]
    fn freetsa_token_verifies_against_its_root_and_is_null_without_one() {
        let token = fixture("freetsa-epoch-107599-zone-0.tsr");
        let digest = hex::decode(DIGEST_HEX).unwrap();
        let root = fixture("freetsa-cacert.pem");
        assert!(matches!(verify_token(&token, &digest, Some(&root)), Outcome::Verified));
        assert!(matches!(verify_token(&token, &digest, None), Outcome::Unverifiable(_)));
    }

    #[test]
    fn imprint_mismatch_fails_closed() {
        let token = fixture("freetsa-epoch-107599-zone-0.tsr");
        let root = fixture("freetsa-cacert.pem");
        let wrong = [0u8; 32];
        assert!(matches!(verify_token(&token, &wrong, Some(&root)), Outcome::Failed(_)));
    }

    #[test]
    fn corrupted_signature_byte_fails_closed() {
        let mut token = fixture("freetsa-epoch-107599-zone-0.tsr");
        let digest = hex::decode(DIGEST_HEX).unwrap();
        let root = fixture("freetsa-cacert.pem");
        // The CMS signature sits at the very end of the SignerInfo, i.e. the end of the token.
        let n = token.len();
        token[n - 5] ^= 0x01;
        assert!(matches!(verify_token(&token, &digest, Some(&root)), Outcome::Failed(_)));
    }

    #[test]
    fn wrong_root_fails_closed() {
        let token = fixture("freetsa-epoch-107599-zone-0.tsr");
        let digest = hex::decode(DIGEST_HEX).unwrap();
        // A trust anchor is trusted by identity (subject + key), never by its own signature, so
        // corrupting an extension byte must NOT matter; corrupting the KEY must fail the chain.
        let root_der = pem_or_der(&fixture("freetsa-cacert.pem")).unwrap();
        let (tlv, _) = der::read(&root_der).unwrap();
        let root = parse_cert(&tlv).unwrap();
        let Spki::Rsa { n, .. } = &root.spki else { panic!("freetsa root is RSA") };
        let pos = root_der.windows(n.len()).position(|w| w == n.as_slice()).expect("modulus bytes present verbatim");
        let mut wrong_key = root_der.clone();
        wrong_key[pos + n.len() / 2] ^= 0x40;
        match verify_token(&token, &digest, Some(&wrong_key)) {
            Outcome::Failed(why) => assert!(why.contains("does not verify under the supplied TSA root"), "{why}"),
            _ => panic!("a root with a different key must fail the chain"),
        }
    }

    #[test]
    fn garbage_is_failed_not_null() {
        assert!(matches!(verify_token(b"not an RFC 3161 token", &[0u8; 32], None), Outcome::Failed(_)));
    }
}
