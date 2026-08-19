//! REALMS P1 slice (b1) — federated-realm membership certificates and the
//! post-handshake admission exchange messages.
//!
//! Spec: docs/REALMS-SELF-ASSEMBLY.md §"Admission model". A `Federated`
//! realm admits a peer only when it presents a membership cert signed by
//! the federation root key. Certs are Dilithium3-signed with an explicit
//! validity window; revocation lists and M-of-N threshold roots are
//! documented follow-ups, not part of P1.
//!
//! Trust shape: the cert does NOT need to ride inside the handshake
//! transcript. The PQ handshake already proves the peer possesses the
//! secret key behind `peer_identity_hash`; the cert binds that identity to
//! the realm root. A stolen cert fails the identity match, and a forged
//! cert fails root-signature verification — each check covers the other's
//! gap. The admission exchange therefore runs AFTER the handshake, inside
//! the established AEAD session (certs are encrypted in transit; member
//! lists stay private to the federation).

use serde::{Deserialize, Serialize};

use crate::crypto::pqc::{
    dilithium3_sign_with_pk, dilithium3_verify, DILITHIUM3_PUBLIC_KEY_LEN,
};

/// Domain-separation tag for cert signing bytes. Versioned: a future cert
/// format change mints `..._V2` rather than mutating this layout.
pub const REALM_MEMBERSHIP_DOMAIN_TAG: &[u8] = b"ELARA_REALM_MEMBER_V1";

/// Admission message protocol version carried in challenge/response.
pub const ADMISSION_PROTOCOL_V: u8 = 1;

/// Clock-skew allowance (seconds) on cert validity-window checks. Wider
/// than the handshake's 30s msg1 skew bound: cert windows span days, so
/// minutes of operator clock drift must not flap admission.
pub const CERT_CLOCK_SKEW_SECS: u64 = 300;

/// Typed admission failures. Variants are wire-stable reasons — the
/// responder reports the variant name to the rejected peer (no internal
/// detail), and metrics label on it.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RealmAdmissionError {
    #[error("cert realm root does not match this node's configured realm root")]
    RootMismatch,
    #[error("cert member identity does not match the handshake-proven peer identity")]
    MemberMismatch,
    #[error("cert not yet valid (issued_at in the future beyond skew)")]
    NotYetValid,
    #[error("cert expired")]
    Expired,
    #[error("cert validity window inverted (expires_at <= issued_at)")]
    InvertedWindow,
    #[error("cert signature did not verify against the realm root key")]
    BadSignature,
    #[error("realm root public key is not a valid Dilithium3 key: {0}")]
    MalformedRootKey(String),
    #[error("network_id mismatch: peer '{peer}', ours '{ours}'")]
    NetworkMismatch { peer: String, ours: String },
    #[error("peer presented no membership cert but this realm requires one")]
    CertMissing,
}

/// A federated-realm membership certificate: the federation root vouches
/// that `member_identity_hash` belongs to the realm until `expires_at`.
///
/// Issued offline by the federation operator (root key never travels);
/// the member node loads its cert at boot and presents it during the
/// admission exchange when dialing or being dialed by realm members.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealmMembershipCert {
    /// Hex SHA3-256 of the member's Dilithium3 public key — the same
    /// identity hash the PQ handshake proves possession of.
    pub member_identity_hash: String,
    /// Hex Dilithium3 public key of the federation root that signed this
    /// cert. Binds the cert to ONE realm: a cert for federation A never
    /// verifies on a node configured with federation B's root.
    pub realm_root_pk: String,
    /// Validity window start (unix seconds).
    pub issued_at: u64,
    /// Validity window end (unix seconds). Spec: certs carry expiry.
    pub expires_at: u64,
    /// Dilithium3 signature by the realm root over
    /// [`RealmMembershipCert::canonical_signing_bytes`].
    pub signature: Vec<u8>,
}

impl RealmMembershipCert {
    /// Deterministic signing payload. NUL separators between the variable-
    /// length hex fields remove any concatenation ambiguity; integers are
    /// fixed-width big-endian.
    pub fn canonical_signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            REALM_MEMBERSHIP_DOMAIN_TAG.len()
                + self.member_identity_hash.len()
                + self.realm_root_pk.len()
                + 2 // separators
                + 16, // two u64
        );
        out.extend_from_slice(REALM_MEMBERSHIP_DOMAIN_TAG);
        out.extend_from_slice(self.member_identity_hash.as_bytes());
        out.push(0);
        out.extend_from_slice(self.realm_root_pk.as_bytes());
        out.push(0);
        out.extend_from_slice(&self.issued_at.to_be_bytes());
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out
    }

    /// Issue a cert for `member_identity_hash`, signing with the federation
    /// root keypair. Hex fields are normalized to lowercase at issue time.
    pub fn issue(
        member_identity_hash: &str,
        root_public_key: &[u8],
        root_secret_key: &[u8],
        issued_at: u64,
        expires_at: u64,
    ) -> crate::errors::Result<Self> {
        if expires_at <= issued_at {
            return Err(crate::errors::ElaraError::Crypto(format!(
                "realm cert window inverted: expires_at {expires_at} <= issued_at {issued_at}"
            )));
        }
        let mut cert = RealmMembershipCert {
            member_identity_hash: member_identity_hash.to_ascii_lowercase(),
            realm_root_pk: hex::encode(root_public_key),
            issued_at,
            expires_at,
            signature: Vec::new(),
        };
        cert.signature =
            dilithium3_sign_with_pk(&cert.canonical_signing_bytes(), root_secret_key, root_public_key)?;
        Ok(cert)
    }

    /// Load a cert from a JSON file (the format `issue()` + serde produce).
    /// Used at node boot for `NodeConfig::realm_membership_cert_path`.
    pub fn load(path: &std::path::Path) -> crate::errors::Result<Self> {
        let bytes = std::fs::read(path).map_err(|e| {
            crate::errors::ElaraError::Config(format!(
                "failed to read realm membership cert {}: {e}",
                path.display()
            ))
        })?;
        serde_json::from_slice(&bytes).map_err(|e| {
            crate::errors::ElaraError::Config(format!(
                "failed to parse realm membership cert {}: {e}",
                path.display()
            ))
        })
    }

    /// Verify this cert against the verifying node's configured realm root,
    /// the handshake-proven peer identity, and the local clock.
    ///
    /// Check order is cheapest-first and every arm is a typed reason — the
    /// admission gate maps these straight onto reject responses + metrics.
    pub fn verify(
        &self,
        expected_root_pk_hex: &str,
        peer_identity_hash_hex: &str,
        now_unix: u64,
    ) -> std::result::Result<(), RealmAdmissionError> {
        if !self.realm_root_pk.eq_ignore_ascii_case(expected_root_pk_hex) {
            return Err(RealmAdmissionError::RootMismatch);
        }
        if !self
            .member_identity_hash
            .eq_ignore_ascii_case(peer_identity_hash_hex)
        {
            return Err(RealmAdmissionError::MemberMismatch);
        }
        if self.expires_at <= self.issued_at {
            return Err(RealmAdmissionError::InvertedWindow);
        }
        if now_unix.saturating_add(CERT_CLOCK_SKEW_SECS) < self.issued_at {
            return Err(RealmAdmissionError::NotYetValid);
        }
        if now_unix > self.expires_at.saturating_add(CERT_CLOCK_SKEW_SECS) {
            return Err(RealmAdmissionError::Expired);
        }
        let root_pk = hex::decode(&self.realm_root_pk)
            .map_err(|e| RealmAdmissionError::MalformedRootKey(e.to_string()))?;
        if root_pk.len() != DILITHIUM3_PUBLIC_KEY_LEN {
            return Err(RealmAdmissionError::MalformedRootKey(format!(
                "{} bytes, expected {DILITHIUM3_PUBLIC_KEY_LEN}",
                root_pk.len()
            )));
        }
        match dilithium3_verify(&self.canonical_signing_bytes(), &self.signature, &root_pk) {
            Ok(true) => Ok(()),
            Ok(false) => Err(RealmAdmissionError::BadSignature),
            Err(_) => Err(RealmAdmissionError::BadSignature),
        }
    }
}

/// Admission-exchange wire messages, carried in AEAD-encrypted
/// `FrameType::Admission` frames after the PQ handshake. JSON with a
/// `kind` tag — one parse point, no untagged ambiguity.
///
/// Sequence (responder realm != Open only; Open responders never emit
/// any of these, keeping the public-mesh byte stream bit-identical to
/// pre-realm builds):
///   responder → `Challenge` → initiator → `Response` → responder →
///   `Verdict` (then Close on rejection).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AdmissionMsg {
    /// Responder → initiator, immediately after the handshake. Carries the
    /// responder's network_id so the initiator hard-fails locally on
    /// mismatch instead of sending its cert to a foreign network.
    Challenge {
        /// [`ADMISSION_PROTOCOL_V`].
        v: u8,
        network_id: String,
        /// Responder realm label ("federated" / "sovereign") — diagnostic.
        realm: String,
        /// Whether a membership cert must be present in the response.
        cert_required: bool,
    },
    /// Initiator → responder, answering a `Challenge`. `cert: None` with
    /// `cert_required` ⇒ [`RealmAdmissionError::CertMissing`].
    Response {
        v: u8,
        network_id: String,
        cert: Option<RealmMembershipCert>,
    },
    /// Responder → initiator verdict closing the exchange. `reason` is the
    /// stable [`RealmAdmissionError::wire_reason`] label on rejection,
    /// empty when admitted.
    Verdict {
        v: u8,
        admitted: bool,
        #[serde(default)]
        reason: String,
    },
}

impl RealmAdmissionError {
    /// Stable snake_case wire label for verdicts + metrics. Never leaks
    /// internal detail strings — variant identity only.
    pub fn wire_reason(&self) -> &'static str {
        match self {
            RealmAdmissionError::RootMismatch => "root_mismatch",
            RealmAdmissionError::MemberMismatch => "member_mismatch",
            RealmAdmissionError::NotYetValid => "not_yet_valid",
            RealmAdmissionError::Expired => "expired",
            RealmAdmissionError::InvertedWindow => "inverted_window",
            RealmAdmissionError::BadSignature => "bad_signature",
            RealmAdmissionError::MalformedRootKey(_) => "malformed_root_key",
            RealmAdmissionError::NetworkMismatch { .. } => "network_mismatch",
            RealmAdmissionError::CertMissing => "cert_missing",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hash::sha3_256;
    use crate::crypto::pqc::dilithium3_keygen;

    /// One root + one member keypair, generated once — Dilithium keygen is
    /// not free and every test in this module needs the same shape.
    fn fixtures() -> (
        crate::crypto::pqc::DilithiumKeypair,
        crate::crypto::pqc::DilithiumKeypair,
        String,
    ) {
        let root = dilithium3_keygen().expect("root keygen");
        let member = dilithium3_keygen().expect("member keygen");
        let member_hash = hex::encode(sha3_256(&member.public_key));
        (root, member, member_hash)
    }

    #[test]
    fn issue_then_verify_happy_path() {
        let (root, _member, member_hash) = fixtures();
        let cert = RealmMembershipCert::issue(&member_hash, &root.public_key, &root.secret_key, 1_000, 2_000)
            .expect("issue");
        let root_hex = hex::encode(&root.public_key);
        assert_eq!(cert.verify(&root_hex, &member_hash, 1_500), Ok(()));
        // Case-insensitive hex comparison on both bindings.
        assert_eq!(
            cert.verify(&root_hex.to_ascii_uppercase(), &member_hash.to_ascii_uppercase(), 1_500),
            Ok(()),
        );
    }

    #[test]
    fn verify_rejects_each_failure_mode() {
        let (root, _member, member_hash) = fixtures();
        let cert = RealmMembershipCert::issue(&member_hash, &root.public_key, &root.secret_key, 1_000, 2_000)
            .expect("issue");
        let root_hex = hex::encode(&root.public_key);

        // Wrong realm root (different federation).
        let other_root = dilithium3_keygen().expect("other root");
        assert_eq!(
            cert.verify(&hex::encode(&other_root.public_key), &member_hash, 1_500),
            Err(RealmAdmissionError::RootMismatch),
        );
        // Stolen cert: presented by a different handshake identity.
        assert_eq!(
            cert.verify(&root_hex, &"ab".repeat(32), 1_500),
            Err(RealmAdmissionError::MemberMismatch),
        );
        // Outside the window (beyond skew on both edges).
        assert_eq!(
            cert.verify(&root_hex, &member_hash, 1_000 - CERT_CLOCK_SKEW_SECS - 1),
            Err(RealmAdmissionError::NotYetValid),
        );
        assert_eq!(
            cert.verify(&root_hex, &member_hash, 2_000 + CERT_CLOCK_SKEW_SECS + 1),
            Err(RealmAdmissionError::Expired),
        );
        // Within skew on both edges: admitted.
        assert_eq!(cert.verify(&root_hex, &member_hash, 1_000 - CERT_CLOCK_SKEW_SECS), Ok(()));
        assert_eq!(cert.verify(&root_hex, &member_hash, 2_000 + CERT_CLOCK_SKEW_SECS), Ok(()));
    }

    #[test]
    fn tampered_fields_break_the_signature() {
        let (root, _member, member_hash) = fixtures();
        let root_hex = hex::encode(&root.public_key);
        let cert = RealmMembershipCert::issue(&member_hash, &root.public_key, &root.secret_key, 1_000, 2_000)
            .expect("issue");

        // Extend expiry without re-signing → BadSignature, not Expired-dodge.
        let mut extended = cert.clone();
        extended.expires_at = 9_000;
        assert_eq!(
            extended.verify(&root_hex, &member_hash, 8_000),
            Err(RealmAdmissionError::BadSignature),
        );
        // Flip a signature byte.
        let mut flipped = cert.clone();
        flipped.signature[0] ^= 0x01;
        assert_eq!(
            flipped.verify(&root_hex, &member_hash, 1_500),
            Err(RealmAdmissionError::BadSignature),
        );
    }

    #[test]
    fn issue_rejects_inverted_window_and_verify_double_checks() {
        let (root, _member, member_hash) = fixtures();
        assert!(
            RealmMembershipCert::issue(&member_hash, &root.public_key, &root.secret_key, 2_000, 2_000).is_err(),
            "issue must reject expires_at <= issued_at",
        );
        // Hand-built inverted cert (hostile input path) is caught by verify
        // before any window math can misbehave.
        let cert = RealmMembershipCert {
            member_identity_hash: member_hash.clone(),
            realm_root_pk: hex::encode(&root.public_key),
            issued_at: 2_000,
            expires_at: 1_000,
            signature: vec![0; 3309],
        };
        assert_eq!(
            cert.verify(&hex::encode(&root.public_key), &member_hash, 1_500),
            Err(RealmAdmissionError::InvertedWindow),
        );
    }

    #[test]
    fn malformed_root_key_is_typed_not_panicked() {
        let (_root, _member, member_hash) = fixtures();
        // Root pk that isn't hex, and one that's hex but wrong length —
        // both must come back as MalformedRootKey (Byzantine peer can put
        // anything in a cert it fabricates).
        let mut cert = RealmMembershipCert {
            member_identity_hash: member_hash.clone(),
            realm_root_pk: "zz-not-hex".into(),
            issued_at: 1_000,
            expires_at: 2_000,
            signature: vec![0; 3309],
        };
        assert!(matches!(
            cert.verify("zz-not-hex", &member_hash, 1_500),
            Err(RealmAdmissionError::MalformedRootKey(_)),
        ));
        cert.realm_root_pk = "abcd".into();
        assert!(matches!(
            cert.verify("abcd", &member_hash, 1_500),
            Err(RealmAdmissionError::MalformedRootKey(_)),
        ));
    }

    #[test]
    fn cert_load_roundtrips_from_disk_and_errors_are_typed() {
        let (root, _member, member_hash) = fixtures();
        let cert = RealmMembershipCert::issue(
            &member_hash,
            &root.public_key,
            &root.secret_key,
            1_000,
            2_000,
        )
        .expect("issue");

        let path = std::env::temp_dir()
            .join(format!("elara-realm-cert-test-{}.json", std::process::id()));
        std::fs::write(&path, serde_json::to_vec(&cert).expect("serialize")).expect("write");
        let loaded = RealmMembershipCert::load(&path).expect("load");
        assert_eq!(loaded, cert);
        std::fs::remove_file(&path).ok();

        // Missing file and non-JSON content are typed Config errors —
        // boot-time cert problems must never panic the node.
        assert!(RealmMembershipCert::load(std::path::Path::new(
            "/nonexistent/elara-realm-cert.json"
        ))
        .is_err());
        let bad = std::env::temp_dir()
            .join(format!("elara-realm-cert-bad-{}.json", std::process::id()));
        std::fs::write(&bad, b"not-json").expect("write");
        assert!(RealmMembershipCert::load(&bad).is_err());
        std::fs::remove_file(&bad).ok();
    }

    #[test]
    fn admission_messages_roundtrip_json() {
        let challenge = AdmissionMsg::Challenge {
            v: ADMISSION_PROTOCOL_V,
            network_id: "testnet".into(),
            realm: "federated".into(),
            cert_required: true,
        };
        let json = serde_json::to_string(&challenge).expect("serialize");
        assert!(json.contains(r#""kind":"challenge""#), "tagged wire form: {json}");
        let back: AdmissionMsg = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, challenge);

        let response = AdmissionMsg::Response {
            v: ADMISSION_PROTOCOL_V,
            network_id: "testnet".into(),
            cert: None,
        };
        let json = serde_json::to_string(&response).expect("serialize");
        let back: AdmissionMsg = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, response);

        // Verdict with missing `reason` field (older peer) defaults empty.
        let verdict: AdmissionMsg =
            serde_json::from_str(r#"{"kind":"verdict","v":1,"admitted":true}"#)
                .expect("deserialize");
        assert_eq!(
            verdict,
            AdmissionMsg::Verdict { v: 1, admitted: true, reason: String::new() },
        );
    }

    /// Rejection verdict (`admitted: false`) must round-trip with its reason
    /// string intact.  This is the wire path a peer sees when the admission
    /// gate rejects it — the `reason` field is the stable wire label the peer
    /// uses to distinguish "wrong network" from "cert expired" etc.
    #[test]
    fn rejection_verdict_carries_reason_through_json() {
        for reason in &["cert_missing", "root_mismatch", "expired", "network_mismatch"] {
            let verdict = AdmissionMsg::Verdict {
                v: ADMISSION_PROTOCOL_V,
                admitted: false,
                reason: reason.to_string(),
            };
            let json = serde_json::to_string(&verdict).expect("serialize");
            assert!(json.contains(r#""admitted":false"#), "admitted=false must be on the wire: {json}");
            assert!(json.contains(reason), "reason label must survive: {json}");
            let back: AdmissionMsg = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(back, verdict, "round-trip must preserve reason={reason}");
        }
    }

    /// Response carrying an actual membership cert must round-trip through JSON
    /// without data loss.  This covers the wire path where an initiator sends
    /// its cert to the responder's admission gate.
    #[test]
    fn response_with_cert_roundtrips_json() {
        let (root, _member, member_hash) = fixtures();
        let cert = RealmMembershipCert::issue(
            &member_hash,
            &root.public_key,
            &root.secret_key,
            1_000,
            2_000,
        )
        .expect("issue");

        let response = AdmissionMsg::Response {
            v: ADMISSION_PROTOCOL_V,
            network_id: "testnet-1".into(),
            cert: Some(cert.clone()),
        };
        let json = serde_json::to_string(&response).expect("serialize");
        let back: AdmissionMsg = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, response, "cert-carrying Response must round-trip");

        // Sanity: the cert embedded in the round-tripped message still verifies.
        if let AdmissionMsg::Response { cert: Some(c), .. } = back {
            let root_hex = hex::encode(&root.public_key);
            assert_eq!(c.verify(&root_hex, &member_hash, 1_500), Ok(()));
        } else {
            panic!("cert must survive deserialization");
        }
    }

    #[test]
    fn wire_reasons_are_stable_snake_case() {
        // Metrics + verdict consumers pin on these labels.
        assert_eq!(RealmAdmissionError::RootMismatch.wire_reason(), "root_mismatch");
        assert_eq!(RealmAdmissionError::CertMissing.wire_reason(), "cert_missing");
        assert_eq!(
            RealmAdmissionError::NetworkMismatch { peer: "a".into(), ours: "b".into() }.wire_reason(),
            "network_mismatch",
        );
        assert_eq!(
            RealmAdmissionError::MalformedRootKey("x".into()).wire_reason(),
            "malformed_root_key",
        );
    }

    #[test]
    fn canonical_bytes_are_domain_tagged_and_field_separated() {
        let cert = RealmMembershipCert {
            member_identity_hash: "aa".into(),
            realm_root_pk: "bb".into(),
            issued_at: 1,
            expires_at: 2,
            signature: Vec::new(),
        };
        let bytes = cert.canonical_signing_bytes();
        assert!(bytes.starts_with(REALM_MEMBERSHIP_DOMAIN_TAG));
        // tag || "aa" || 0 || "bb" || 0 || u64 || u64
        let expected_len = REALM_MEMBERSHIP_DOMAIN_TAG.len() + 2 + 1 + 2 + 1 + 8 + 8;
        assert_eq!(bytes.len(), expected_len);
        // Moving a char across the separator changes the bytes (no
        // concatenation ambiguity between the two hex fields).
        let shifted = RealmMembershipCert {
            member_identity_hash: "aab".into(),
            realm_root_pk: "b".into(),
            ..cert.clone()
        };
        assert_ne!(bytes, shifted.canonical_signing_bytes());
    }
}
