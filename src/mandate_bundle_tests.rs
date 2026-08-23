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
        // No leaf resolved → scope_deferred must be None (never a silent
        // false), and no "scope" check row may exist.
        assert_eq!(v.scope_deferred, None);
        assert!(v.checks.iter().all(|c| c.name != "scope"));
    }

    #[test]
    fn garbage_input_fails_closed_never_throws() {
        for s in ["", "{}", "not json", "[]", "{\"bundle_version\":1}"] {
            let v = evaluate_mandate_bundle(s);
            assert_eq!(v.verdict, "FAILED", "input {s:?} must fail closed");
            assert!(!v.authorized);
            assert_eq!(v.scope_deferred, None, "input {s:?}: no leaf → None");
            // R4: input errors judge nothing — no scope prose, no caveats
            // about what a CONSISTENT verdict proves.
            assert!(v.scope_note.is_empty(), "input {s:?}: scope_note empty");
            assert!(v.soundness_caveats.is_empty(), "input {s:?}: caveats empty");
        }
    }

    /// scope_deferred is a PER-BUNDLE fact off the resolved leaf: Some(true)
    /// for a materially restricted scope v0 recorded but did not check,
    /// Some(false) for wildcard (nothing to enforce — NOT evidence of a
    /// check), and the paired "scope" info row carries the matching wording
    /// on both branches so `false` can never read as "checked".
    #[test]
    fn scope_deferred_field_and_row_track_the_leaf_scope() {
        let (principal, agent, _) = cast();

        // Wildcard leaf → Some(false) + the nothing-to-enforce wording.
        let m = root_mandate(&principal, &agent);
        let id = m.mandate_id();
        let act = act_record(&agent, &id, T_ACT);
        let v = evaluate_mandate_bundle(&bundle_json(
            &act,
            &[mandate_carrier(&principal, &m, T_ACT - 1.0)],
            &[],
        ));
        assert_eq!(v.verdict, "CONSISTENT");
        assert_eq!(v.scope_deferred, Some(false));
        let row = v.checks.iter().find(|c| c.name == "scope").expect("scope row");
        assert_eq!(row.status, "info");
        assert!(row.detail.contains("NOT evidence that scope was checked"));

        // Non-wildcard leaf → Some(true) + the deferred wording, still
        // CONSISTENT (v0 records scope, never checks it — the exact
        // non-obvious state the field exists to make legible).
        let narrow = MandateRecord::new_root(
            NETWORK,
            &principal.identity_hash,
            &agent.identity_hash,
            MandateScope {
                allowed_ops: vec!["commit".to_string()],
                allowed_zones: vec!["*".to_string()],
                max_amount: None,
            },
            WINDOW_OPEN_MS,
            WINDOW_CLOSE_MS,
            0,
            "bundle-test-scoped-0001",
        );
        let nid = narrow.mandate_id();
        let act2 = act_record(&agent, &nid, T_ACT);
        let v2 = evaluate_mandate_bundle(&bundle_json(
            &act2,
            &[mandate_carrier(&principal, &narrow, T_ACT - 1.0)],
            &[],
        ));
        assert_eq!(v2.verdict, "CONSISTENT", "reason: {}", v2.reason);
        assert_eq!(v2.scope_deferred, Some(true));
        let row2 = v2.checks.iter().find(|c| c.name == "scope").expect("scope row");
        assert!(row2.detail.contains("scope_deferred"));
        assert!(row2.detail.contains("does NOT enforce"));
    }

    /// T-vaara pre-work — one-shot generator for the PUBLIC mandate-bundle
    /// vectors (`examples/verify/mandate-bundle-*.json`): three committed,
    /// offline-judgeable cases harvested from a REAL single-node chain
    /// (the issuer-quickstart world, network "my-agent-chain", 2026-08-19):
    ///   valid           — agent act under a live mandate; the bundle ALSO
    ///                     carries the (later) revocation, proving verdicts
    ///                     are act-timestamp-aware, not bundle-order-aware.
    ///   post-revocation — same mandate, act after the revocation.
    ///   agent-mismatch  — act signed by a DIFFERENT key than the mandate's
    ///                     agent (exonerates the principal — anti-libel path).
    /// Freeze rule (same as the KATs): NEVER regenerate over committed
    /// vectors; the generator asserts every expected verdict at freeze time.
    ///   cargo test --lib mandate_bundle_vector_generator -- --ignored --nocapture
    #[test]
    #[ignore]
    fn mandate_bundle_vector_generator() {
        use crate::record::ValidationRecord;
        use std::path::Path;
        // Harvest dir comes from the environment — never a literal path in
        // source (the mirror's Stage-4 home-path scan is a HARD gate, and it
        // fired on the first version of this line after it had already been
        // pushed: the one time the push wasn't gated on the scan's exit code).
        let world_env = std::env::var("ELARA_BUNDLE_WORLD")
            .expect("set ELARA_BUNDLE_WORLD=<harvest dir with {mandate,revocation,act1,act2,act3}.wire>");
        let world = Path::new(&world_env);
        let out_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/verify");
        let load = |n: &str| -> serde_json::Value {
            let wire = std::fs::read(world.join(format!("{n}.wire"))).expect("wire");
            let rec = ValidationRecord::from_bytes(&wire).expect("decode");
            serde_json::to_value(&rec).expect("serde")
        };
        let (mandate, revocation) = (load("mandate"), load("revocation"));
        let cases = [
            ("valid", "act1", true, "valid"),
            ("post-revocation", "act2", false, "post_revocation"),
            ("agent-mismatch", "act3", false, "agent_mismatch"),
        ];
        for (name, act_file, want_auth, want_flag) in cases {
            let bundle = serde_json::json!({
                "bundle_version": 1,
                "act": load(act_file),
                "mandates": [mandate],
                "revocations": [revocation],
            });
            let out = out_dir.join(format!("mandate-bundle-{name}.json"));
            assert!(!out.exists(), "{name}: frozen vector exists — never regenerate");
            let js = serde_json::to_string_pretty(&bundle).unwrap();
            let v = elara_verify::mandate_bundle::evaluate_mandate_bundle(&js);
            assert_eq!(v.authorized, want_auth, "{name}: authorized");
            assert_eq!(v.flag, want_flag, "{name}: flag (got {}, detail: {:?})", v.flag,
                v.checks.iter().map(|c| format!("{}={}", c.name, c.status)).collect::<Vec<_>>());
            std::fs::write(&out, format!("{js}\n")).unwrap();
            println!("froze {name}: authorized={want_auth} flag={want_flag} -> {}", out.display());
        }
    }


    /// One-shot freeze generator for the scope_deferred POSITIVE vector
    /// (`examples/verify/mandate-bundle-scope-deferred.json`): a real-chain
    /// harvested bundle whose leaf mandate carries a NON-wildcard scope
    /// (`allowed_ops:["commit"]`) and whose act is CONSISTENT/valid anyway —
    /// proving a green verdict does NOT mean the act was within scope
    /// (v0 records scope, never checks it). Same freeze rule + harvest flow
    /// as `mandate_bundle_vector_generator` (issuer-quickstart world; set
    /// ELARA_BUNDLE_WORLD=<dir with {mandate,act1}.wire>).
    ///   cargo test --lib mandate_bundle_scope_deferred_vector_generator -- --ignored --nocapture
    #[test]
    #[ignore]
    fn mandate_bundle_scope_deferred_vector_generator() {
        use crate::record::ValidationRecord;
        use std::path::Path;
        let world_env = std::env::var("ELARA_BUNDLE_WORLD")
            .expect("set ELARA_BUNDLE_WORLD=<harvest dir with {mandate,act1}.wire>");
        let world = Path::new(&world_env);
        let out_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/verify");
        let load = |n: &str| -> serde_json::Value {
            let wire = std::fs::read(world.join(format!("{n}.wire"))).expect("wire");
            let rec = ValidationRecord::from_bytes(&wire).expect("decode");
            serde_json::to_value(&rec).expect("serde")
        };
        let bundle = serde_json::json!({
            "bundle_version": 1,
            "act": load("act1"),
            "mandates": [load("mandate")],
            "revocations": [],
        });
        let out = out_dir.join("mandate-bundle-scope-deferred.json");
        assert!(!out.exists(), "frozen vector exists — never regenerate");
        let js = serde_json::to_string_pretty(&bundle).unwrap();
        let v = elara_verify::mandate_bundle::evaluate_mandate_bundle(&js);
        assert!(v.authorized, "authorized");
        assert_eq!(v.flag, "valid", "flag");
        assert_eq!(v.scope_deferred, Some(true), "scope_deferred must be true");
        std::fs::write(&out, format!("{js}\n")).unwrap();
        println!("froze scope-deferred: CONSISTENT + scope_deferred=Some(true) -> {}", out.display());
    }

    /// The committed public mandate-bundle vectors verdict-pin (KAT-style:
    /// a mismatch is an ALARM, never a regenerate). Guards the offline
    /// bundle judge against drift on every committed outcome, including the
    /// scope_deferred pair: the wildcard `valid` vector is the NEGATIVE
    /// (Some(false) — a real computation, not a constant) and
    /// `scope-deferred` is the POSITIVE (Some(true) on a CONSISTENT verdict).
    /// `act-tampered` (previously pinned by nothing) fails closed at the act
    /// signature gate → input_error, no leaf → scope_deferred None.
    #[test]
    fn committed_mandate_bundle_vectors_pin_their_verdicts() {
        for (name, want_auth, want_flag, want_scope) in [
            ("valid", true, "valid", Some(false)),
            ("post-revocation", false, "post_revocation", Some(false)),
            ("agent-mismatch", false, "agent_mismatch", Some(false)),
            ("act-tampered", false, "input_error", None),
            ("scope-deferred", true, "valid", Some(true)),
        ] {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join(format!("examples/verify/mandate-bundle-{name}.json"));
            let js = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("{name}: committed vector must exist: {e}"));
            let v = elara_verify::mandate_bundle::evaluate_mandate_bundle(&js);
            assert_eq!(v.authorized, want_auth, "{name}: authorized drifted");
            assert_eq!(v.flag, want_flag, "{name}: flag drifted");
            assert_eq!(v.scope_deferred, want_scope, "{name}: scope_deferred drifted");
        }
    }

}
