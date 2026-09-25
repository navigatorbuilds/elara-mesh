use criterion::{criterion_group, criterion_main, Criterion, SamplingMode};
use elara_runtime::crypto::batch::{batch_verify, VerifyJob};
use elara_runtime::crypto::hash::sha3_256;
use elara_runtime::crypto::pqc::{
    dilithium3_keygen, dilithium3_sign_with_pk, dilithium3_verify, sphincs_keygen, sphincs_sign_with_pk,
    sphincs_verify,
};

fn bench_dilithium3_keygen(c: &mut Criterion) {
    c.bench_function("dilithium3_keygen", |b| {
        b.iter(|| dilithium3_keygen().unwrap());
    });
}

fn bench_dilithium3_sign(c: &mut Criterion) {
    let kp = dilithium3_keygen().unwrap();
    let msg = b"benchmark message for signing";
    c.bench_function("dilithium3_sign", |b| {
        b.iter(|| dilithium3_sign_with_pk(msg, &kp.secret_key, &kp.public_key).unwrap());
    });
}

fn bench_dilithium3_verify(c: &mut Criterion) {
    let kp = dilithium3_keygen().unwrap();
    let msg = b"benchmark message for verification";
    let sig = dilithium3_sign_with_pk(msg, &kp.secret_key, &kp.public_key).unwrap();
    c.bench_function("dilithium3_verify", |b| {
        b.iter(|| dilithium3_verify(msg, &sig, &kp.public_key).unwrap());
    });
}

// SPHINCS+-SHA2-192f signs in tens of milliseconds or more, so criterion's default of
// 100 linearly growing samples would run for minutes: use 10 flat samples instead.
fn bench_sphincs(c: &mut Criterion) {
    let kp = sphincs_keygen().unwrap();
    let msg = b"benchmark message for signing";
    let sig = sphincs_sign_with_pk(msg, &kp.secret_key, &kp.public_key).unwrap();
    let mut group = c.benchmark_group("sphincs_sha2_192f");
    group.sampling_mode(SamplingMode::Flat);
    group.sample_size(10);
    group.bench_function("sign", |b| {
        b.iter(|| sphincs_sign_with_pk(msg, &kp.secret_key, &kp.public_key).unwrap());
    });
    group.bench_function("verify", |b| {
        b.iter(|| sphincs_verify(msg, &sig, &kp.public_key).unwrap());
    });
    group.finish();
}

fn bench_sha3_256(c: &mut Criterion) {
    let data = vec![0xABu8; 4096];
    c.bench_function("sha3_256_4kb", |b| b.iter(|| sha3_256(&data)));
}

fn bench_batch_verify(c: &mut Criterion) {
    let kp = dilithium3_keygen().unwrap();
    let messages: Vec<Vec<u8>> = (0..100).map(|i| format!("bench-{i}").into_bytes()).collect();
    let sigs: Vec<Vec<u8>> = messages
        .iter()
        .map(|m| dilithium3_sign_with_pk(m, &kp.secret_key, &kp.public_key).unwrap())
        .collect();

    let jobs: Vec<VerifyJob> = messages
        .iter()
        .zip(sigs.iter())
        .map(|(m, s)| VerifyJob {
            message: m,
            signature: s,
            public_key: &kp.public_key,
        })
        .collect();

    c.bench_function("batch_verify_100", |b| b.iter(|| batch_verify(&jobs)));
}

criterion_group!(
    benches,
    bench_dilithium3_keygen,
    bench_dilithium3_sign,
    bench_dilithium3_verify,
    bench_sphincs,
    bench_sha3_256,
    bench_batch_verify
);
criterion_main!(benches);
