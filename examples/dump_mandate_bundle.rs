//! Emit real, signed sample **mandate bundles** for the offline browser
//! verifier (`verify-wasm`'s `evaluate_mandate_bundle`) and the verify demo.
//!
//! ```text
//! cargo run --example dump_mandate_bundle > browser-node/verify-demo/sample-mandate-bundles.json
//! ```
//!
//! Builds three scenarios from ONE cast of real Dilithium3 identities so the
//! demo can flip between them coherently:
//!   * `valid`     — the mandated agent acts inside the window  → CONSISTENT
//!   * `impostor`  — a different AI presents the agent's mandate → NOT AUTHORIZED
//!     (agent_mismatch; the named principal is exonerated)
//!   * `revoked`   — the agent acts AFTER the principal revoked  → NOT AUTHORIZED
//!     (post_revocation)
//!
//! Every carrier record is really signed; the tool re-runs each bundle through
//! the exact offline verdict core (`mandate_bundle::evaluate_mandate_bundle`)
//! and panics if any scenario does not produce its documented verdict — so a
//! committed sample can never silently drift from the code.

use std::collections::BTreeMap;

use elara_runtime::identity::{CryptoProfile, EntityType, Identity};
use elara_runtime::mandate::{
    MandateRecord, MandateScope, RevocationRecord, MANDATE_OP_KEY, MANDATE_REF_METADATA_KEY,
    MANDATE_REVOCATION_OP_KEY,
};
use elara_runtime::mandate_bundle::{evaluate_mandate_bundle, MANDATE_BUNDLE_VERSION};
use elara_runtime::record::{Classification, ValidationRecord};
use serde_json::{json, Value};

const NETWORK: &str = "testnet";
const WINDOW_OPEN_MS: u64 = 1_700_000_000_000;
const WINDOW_CLOSE_MS: u64 = 1_700_100_000_000;
const T_ISSUE: f64 = 1_700_000_000.0;
const T_ACT: f64 = 1_700_000_500.0;
const T_REVOKE: f64 = 1_700_050_000.0;
const T_ACT_AFTER_REVOKE: f64 = 1_700_060_000.0;

fn signed_record(
    signer: &Identity,
    meta: BTreeMap<String, Value>,
    ts_secs: f64,
) -> ValidationRecord {
    let mut rec = ValidationRecord::create(
        b"agent-mandate-demo",
        signer.public_key.clone(),
        vec![],
        Classification::Public,
        Some(meta),
    );
    rec.timestamp = ts_secs;
    signer.sign_record(&mut rec).expect("sign carrier record");
    rec
}

fn bundle(
    act: &ValidationRecord,
    mandates: &[ValidationRecord],
    revocations: &[ValidationRecord],
) -> Value {
    json!({
        "bundle_version": MANDATE_BUNDLE_VERSION,
        "act": act,
        "mandates": mandates,
        "revocations": revocations,
    })
}

fn main() {
    let principal =
        Identity::generate(EntityType::Human, CryptoProfile::ProfileB).expect("keygen principal");
    let agent = Identity::generate(EntityType::Ai, CryptoProfile::ProfileB).expect("keygen agent");
    let impostor =
        Identity::generate(EntityType::Ai, CryptoProfile::ProfileB).expect("keygen impostor");

    // The principal issues a (wildcard-scope) mandate to the agent.
    let scope = MandateScope {
        allowed_ops: vec!["*".to_string()],
        allowed_zones: vec!["*".to_string()],
        max_amount: None,
    };
    let m = MandateRecord::new_root(
        NETWORK,
        &principal.identity_hash,
        &agent.identity_hash,
        scope,
        WINDOW_OPEN_MS,
        WINDOW_CLOSE_MS,
        0,
        "demo-bundle-0001",
    );
    let mandate_id = m.mandate_id();

    let mut issue_meta = BTreeMap::new();
    issue_meta.insert(MANDATE_OP_KEY.to_string(), serde_json::to_value(&m).unwrap());
    let mandate_carrier = signed_record(&principal, issue_meta, T_ISSUE);

    // Act helper.
    let act_for = |signer: &Identity, ts: f64| {
        let mut meta = BTreeMap::new();
        meta.insert(
            MANDATE_REF_METADATA_KEY.to_string(),
            Value::String(mandate_id.clone()),
        );
        signed_record(signer, meta, ts)
    };

    // valid
    let valid_act = act_for(&agent, T_ACT);
    let valid = bundle(&valid_act, std::slice::from_ref(&mandate_carrier), &[]);

    // impostor
    let impostor_act = act_for(&impostor, T_ACT);
    let impostor_bundle = bundle(&impostor_act, std::slice::from_ref(&mandate_carrier), &[]);

    // revoked
    let rev = RevocationRecord::new(NETWORK, mandate_id.clone(), "agent key suspected compromised");
    let mut rev_meta = BTreeMap::new();
    rev_meta.insert(
        MANDATE_REVOCATION_OP_KEY.to_string(),
        serde_json::to_value(&rev).unwrap(),
    );
    let rev_carrier = signed_record(&principal, rev_meta, T_REVOKE);
    let revoked_act = act_for(&agent, T_ACT_AFTER_REVOKE);
    let revoked = bundle(
        &revoked_act,
        std::slice::from_ref(&mandate_carrier),
        std::slice::from_ref(&rev_carrier),
    );

    // Self-verify: the committed sample must match the documented verdicts.
    let check = |label: &str, b: &Value, want_verdict: &str, want_flag: &str| {
        let v = evaluate_mandate_bundle(&b.to_string());
        assert_eq!(v.verdict, want_verdict, "{label}: verdict {:?}", v);
        assert_eq!(v.flag, want_flag, "{label}: flag {:?}", v);
    };
    check("valid", &valid, "CONSISTENT", "valid");
    check("impostor", &impostor_bundle, "NOT AUTHORIZED", "agent_mismatch");
    check("revoked", &revoked, "NOT AUTHORIZED", "post_revocation");

    let out = json!({
        "_comment": "Real Dilithium3-signed sample mandate bundles for the offline verifier. \
                     Generated by `cargo run --example dump_mandate_bundle`. Each bundle is \
                     self-verified against mandate_bundle::evaluate_mandate_bundle before emit.",
        "valid": valid,
        "impostor": impostor_bundle,
        "revoked": revoked,
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
