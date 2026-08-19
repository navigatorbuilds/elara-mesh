//! T63 frozen-preimage KATs — the byte-identity gate for `signable_bytes()`.
//!
//! Vectors were frozen 2026-08-18 from the PRE-v6-change binary (generator:
//! `kat_freeze_generator_t63` in the node's `src/crypto/pqc.rs`), covering
//! synthetic v4 (single-sig) + v5 (dual-sig, nonce=7) records and three REAL
//! v5 chain records (two maintainer acts + one epoch seal) lifted as raw wire
//! bytes from the public receipt envelopes.
//!
//! What a failure here MEANS: a v≤5 `signable_bytes()` / `record_hash()` /
//! wire-codec byte moved — i.e. every existing signature on the chain would
//! stop verifying. That is the alarm working. NEVER "fix" a mismatch by
//! regenerating the fixture (that silently refreezes the broken formula);
//! fix the code so the frozen bytes verify again. See the generator rustdoc
//! and internal design notes.
//!
//! Unlike the round-trip tests elsewhere in this crate, these vectors do NOT
//! move with the code — that is their entire value (T65 verdict :269-271:
//! "byte-identical v4/v5 signable_bytes vectors" is a pre-bump MUST).

use elara_record::pqc::{dilithium3_verify, sphincs_verify};
use elara_record::record::ValidationRecord;

const FIXTURES: &str = include_str!("kat/frozen_preimages_t63.json");

#[test]
fn frozen_v4_v5_preimages_are_byte_identical() {
    let doc: serde_json::Value = serde_json::from_str(FIXTURES).expect("fixture JSON parses");
    let vectors = doc["vectors"].as_array().expect("vectors array");
    assert!(
        vectors.len() >= 5,
        "fixture floor: expected >=5 frozen vectors, got {} — an emptied fixture must fail loudly",
        vectors.len()
    );

    for v in vectors {
        let name = v["name"].as_str().expect("name");
        let wire = hex::decode(v["wire_hex"].as_str().expect("wire_hex")).expect("wire hex");
        let rec = ValidationRecord::from_bytes(&wire)
            .unwrap_or_else(|e| panic!("{name}: frozen wire must decode: {e}"));

        // The three frozen byte identities.
        assert_eq!(
            hex::encode(rec.signable_bytes()),
            v["signable_hex"].as_str().expect("signable_hex"),
            "{name}: signable_bytes moved for a v{} record — every existing signature breaks",
            rec.version
        );
        assert_eq!(
            hex::encode(rec.record_hash()),
            v["record_hash_hex"].as_str().expect("record_hash_hex"),
            "{name}: record_hash moved for a v{} record",
            rec.version
        );
        if v["assert_reencode"].as_bool().unwrap_or(false) {
            assert_eq!(
                hex::encode(rec.to_bytes()),
                v["wire_hex"].as_str().unwrap(),
                "{name}: decode→re-encode no longer reproduces the frozen wire bytes"
            );
        }

        // Signatures must still VERIFY over the recomputed preimage — pinning
        // bytes alone would miss a formula change that happened to collide.
        if v["expect_dilithium"].as_bool().unwrap_or(false) {
            let sig = rec.signature.as_ref().expect("dilithium sig present");
            assert!(
                dilithium3_verify(&rec.signable_bytes(), sig, &rec.creator_public_key).unwrap(),
                "{name}: frozen Dilithium3 signature no longer verifies"
            );
        }
        if v["expect_sphincs"].as_bool().unwrap_or(false) {
            let sig = rec.sphincs_signature.as_ref().expect("sphincs sig present");
            let pk = rec.creator_sphincs_pk.as_ref().expect("sphincs pk present");
            assert!(
                sphincs_verify(&rec.signable_bytes(), sig, pk).unwrap(),
                "{name}: frozen SPHINCS+ signature no longer verifies"
            );
        }
    }
}

/// Cross-type non-replay guard (verdict KAT plan, last leg): a signature over
/// one frozen record's preimage must NOT verify over any other's. With v6
/// domain tags this becomes the tag's job; pinning it now proves the property
/// holds for the frozen v≤5 corpus and gives v6 a differential baseline.
#[test]
fn frozen_signatures_do_not_cross_verify() {
    let doc: serde_json::Value = serde_json::from_str(FIXTURES).expect("fixture JSON parses");
    let vectors = doc["vectors"].as_array().expect("vectors array");
    let recs: Vec<(String, ValidationRecord)> = vectors
        .iter()
        .map(|v| {
            let wire = hex::decode(v["wire_hex"].as_str().unwrap()).unwrap();
            (
                v["name"].as_str().unwrap().to_string(),
                ValidationRecord::from_bytes(&wire).unwrap(),
            )
        })
        .collect();

    for (i, (name_a, a)) in recs.iter().enumerate() {
        let sig_a = a.signature.as_ref().expect("signed");
        for (j, (name_b, b)) in recs.iter().enumerate() {
            if i == j {
                continue;
            }
            assert!(
                !dilithium3_verify(&b.signable_bytes(), sig_a, &a.creator_public_key).unwrap(),
                "{name_a}'s signature must not verify over {name_b}'s preimage"
            );
        }
    }
}
