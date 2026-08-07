//! Signing-dependent tests for [`crate::mandate_bundle`] (parked node-side in
//! extraction Step 4a — elara-verify is signing-incapable by design, and these
//! fixtures sign live carriers via node-side `Identity`; the pure logic tests
//! moved with the module). Runs against the re-exported shim path, so
//! node↔crate drift here is a compile error.

#[cfg(test)]
mod tests {
    use crate::mandate_bundle::*;
    use crate::identity::{CryptoProfile, EntityType, Identity};
    use crate::mandate::{
        MandateRecord, MandateScope, RevocationRecord, MANDATE_OP_KEY, MANDATE_REF_METADATA_KEY,
        MANDATE_REVOCATION_OP_KEY,
    };
    use crate::record::{Classification, ValidationRecord};
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
