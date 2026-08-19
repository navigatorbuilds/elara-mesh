use std::collections::BTreeMap;

use criterion::{criterion_group, criterion_main, Criterion};
use elara_runtime::crypto::hash::sha3_256;
use elara_runtime::record::{Classification, ValidationRecord};
use elara_runtime::wire::WIRE_VERSION;

fn make_record() -> ValidationRecord {
    let mut metadata = BTreeMap::new();
    metadata.insert("key".into(), serde_json::Value::String("value".into()));
    metadata.insert("type".into(), serde_json::Value::String("benchmark".into()));

    {
        let mut __r = ValidationRecord::fixture_shell();
        __r.id = "019506e0-1234-7000-8000-000000000001".to_string();
        __r.version = WIRE_VERSION;
        __r.content_hash = sha3_256(b"benchmark content").to_vec();
        __r.creator_public_key = vec![0xAA; 1952];
        __r.timestamp = 1739712345.123456;
        __r.parents = vec![
            "019506e0-1234-7000-8000-000000000000".to_string(),
            "019506e0-1234-7000-8000-ffffffffffff".to_string(),
        ];
        __r.classification = Classification::Public;
        __r.metadata = metadata;
        __r.signature = Some(vec![0xBB; 3293]);
        __r.sphincs_signature = None;
        __r.zk_proof = None;
        __r.itc_stamp = None;
        __r.zone_refs = Vec::new();
        __r.creator_sphincs_pk = None;
        __r.sig_algorithm = elara_runtime::crypto::ALG_DILITHIUM3;
        __r.sphincs_algorithm = None;
        __r.zone = None;
        __r.identity_hash_wire = None;
        __r.nonce = 0;
        __r.network_id = String::new();
        __r
    }
}

fn bench_to_bytes(c: &mut Criterion) {
    let rec = make_record();
    c.bench_function("record_to_bytes", |b| b.iter(|| rec.to_bytes()));
}

fn bench_from_bytes(c: &mut Criterion) {
    let rec = make_record();
    let wire = rec.to_bytes();
    c.bench_function("record_from_bytes", |b| {
        b.iter(|| ValidationRecord::from_bytes(&wire).unwrap());
    });
}

fn bench_signable_bytes(c: &mut Criterion) {
    let rec = make_record();
    c.bench_function("signable_bytes", |b| b.iter(|| rec.signable_bytes()));
}

fn bench_record_hash(c: &mut Criterion) {
    let rec = make_record();
    c.bench_function("record_hash", |b| b.iter(|| rec.record_hash()));
}

criterion_group!(
    benches,
    bench_to_bytes,
    bench_from_bytes,
    bench_signable_bytes,
    bench_record_hash
);
criterion_main!(benches);
