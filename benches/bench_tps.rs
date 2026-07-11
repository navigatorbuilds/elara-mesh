//! TPS Benchmark — measures real throughput of the full record pipeline.
//!
//! Tests each bottleneck independently, then the full end-to-end flow:
//! 1. Record creation + signing (Dilithium3)
//! 2. Signature verification
//! 3. SQLite insert
//! 4. Ledger operation (transfer) through full pipeline
//! 5. Ledger derivation from N records
//! 6. Batch signature verification (parallel via Rayon)

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

use elara_runtime::crypto::batch::{batch_verify, VerifyJob};
use elara_runtime::crypto::hash::sha3_256_hex;
use elara_runtime::crypto::pqc::{dilithium3_keygen, dilithium3_sign_with_pk};
use elara_runtime::identity::{CryptoProfile, EntityType, Identity};
use elara_runtime::record::{Classification, ValidationRecord};
use elara_runtime::storage::rocks::StorageEngine;
use elara_runtime::storage::Storage;
use elara_runtime::accounting::ledger;
use elara_runtime::accounting::types::*;

/// Create a signed record (simulates record submission).
fn create_signed_record(identity: &Identity, parents: Vec<String>) -> ValidationRecord {
    let mut record = ValidationRecord::create(
        b"benchmark content payload",
        identity.public_key.clone(),
        parents,
        Classification::Public,
        None,
    );
    let signable = record.signable_bytes();
    let sig = identity.sign(&signable).unwrap();
    record.signature = Some(sig);
    record
}

/// Create a signed beat transfer record.
fn create_transfer_record(
    identity: &Identity,
    to: &str,
    amount: u64,
    parents: Vec<String>,
) -> ValidationRecord {
    let meta = transfer_metadata(amount, to, None);
    let mut record = ValidationRecord::create(
        format!("beat:transfer:{amount}").as_bytes(),
        identity.public_key.clone(),
        parents,
        Classification::Public,
        Some(meta),
    );
    let signable = record.signable_bytes();
    let sig = identity.sign(&signable).unwrap();
    record.signature = Some(sig);
    record
}

// ─── Individual bottleneck benchmarks ────────────────────────────────────────

fn bench_record_create_and_sign(c: &mut Criterion) {
    let identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB).unwrap();

    c.bench_function("record_create_sign", |b| {
        b.iter(|| create_signed_record(&identity, vec![]));
    });
}

fn bench_record_verify(c: &mut Criterion) {
    let identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB).unwrap();
    let record = create_signed_record(&identity, vec![]);
    let signable = record.signable_bytes();
    let sig = record.signature.as_ref().unwrap();
    let pk = &record.creator_public_key;

    c.bench_function("record_verify_sig", |b| {
        b.iter(|| Identity::verify(&signable, sig, pk).unwrap());
    });
}

fn bench_rocksdb_insert(c: &mut Criterion) {
    let identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB).unwrap();

    c.bench_function("rocksdb_insert_record", |b| {
        b.iter_custom(|iters| {
            let dir = tempfile::tempdir().unwrap();
            let mut db = StorageEngine::open(dir.path()).unwrap();
            let start = std::time::Instant::now();
            for i in 0..iters {
                let mut record = create_signed_record(&identity, vec![]);
                record.id = format!("bench-{i:010}");
                let _ = db.insert(&record);
            }
            start.elapsed()
        });
    });
}

fn bench_wire_encode_decode(c: &mut Criterion) {
    let identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB).unwrap();
    let record = create_signed_record(&identity, vec![]);

    c.bench_function("wire_encode", |b| {
        b.iter(|| record.to_bytes());
    });

    let wire = record.to_bytes();
    c.bench_function("wire_decode", |b| {
        b.iter(|| ValidationRecord::from_bytes(&wire).unwrap());
    });
}

// ─── Full pipeline benchmark ─────────────────────────────────────────────────

fn bench_full_pipeline(c: &mut Criterion) {
    let identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB).unwrap();

    c.bench_function("full_pipeline_create_verify_insert", |b| {
        b.iter_custom(|iters| {
            let dir = tempfile::tempdir().unwrap();
            let mut db = StorageEngine::open(dir.path()).unwrap();
            let start = std::time::Instant::now();
            for i in 0..iters {
                // 1. Create and sign
                let mut record = create_signed_record(&identity, vec![]);
                record.id = format!("pipe-{i:010}");

                // 2. Verify signature
                let signable = record.signable_bytes();
                let _valid = Identity::verify(
                    &signable,
                    record.signature.as_ref().unwrap(),
                    &record.creator_public_key,
                )
                .unwrap();

                // 3. Insert into storage
                let _ = db.insert(&record);
            }
            start.elapsed()
        });
    });
}

// ─── Ledger-specific benchmarks ───────────────────────────────────────────────

fn bench_token_transfer_pipeline(c: &mut Criterion) {
    let genesis = Identity::generate(EntityType::Device, CryptoProfile::ProfileB).unwrap();
    let alice = Identity::generate(EntityType::Device, CryptoProfile::ProfileB).unwrap();
    let bob = Identity::generate(EntityType::Device, CryptoProfile::ProfileB).unwrap();

    let alice_hash = sha3_256_hex(&alice.public_key);
    let bob_hash = sha3_256_hex(&bob.public_key);

    c.bench_function("token_transfer_pipeline", |b| {
        b.iter_custom(|iters| {
            let dir = tempfile::tempdir().unwrap();
            let mut db = StorageEngine::open(dir.path()).unwrap();

            // Seed: mint to Alice
            let mint_meta = mint_metadata(iters * BASE_UNITS_PER_BEAT * 100, &alice_hash, "bench");
            let mut mint_rec = ValidationRecord::create(
                b"beat:mint:seed",
                genesis.public_key.clone(),
                vec![],
                Classification::Public,
                Some(mint_meta),
            );
            mint_rec.id = "mint-seed".to_string();
            let signable = mint_rec.signable_bytes();
            mint_rec.signature = Some(genesis.sign(&signable).unwrap());
            db.insert(&mint_rec).unwrap();

            let start = std::time::Instant::now();
            for i in 0..iters {
                // Create transfer record
                let mut record = create_transfer_record(
                    &alice,
                    &bob_hash,
                    BASE_UNITS_PER_BEAT, // 1 beat each
                    vec![],
                );
                record.id = format!("xfer-{i:010}");

                // Verify signature
                let signable = record.signable_bytes();
                let _valid = Identity::verify(
                    &signable,
                    record.signature.as_ref().unwrap(),
                    &record.creator_public_key,
                )
                .unwrap();

                // Insert
                let _ = db.insert(&record);
            }
            start.elapsed()
        });
    });
}

fn bench_ledger_derivation(c: &mut Criterion) {
    let genesis = Identity::generate(EntityType::Device, CryptoProfile::ProfileB).unwrap();
    let alice = Identity::generate(EntityType::Device, CryptoProfile::ProfileB).unwrap();
    let bob = Identity::generate(EntityType::Device, CryptoProfile::ProfileB).unwrap();

    let genesis_hash = sha3_256_hex(&genesis.public_key);
    let alice_hash = sha3_256_hex(&alice.public_key);
    let bob_hash = sha3_256_hex(&bob.public_key);

    for &count in &[100, 1000, 10000] {
        // Pre-build ledger records
        let mut records: Vec<(ValidationRecord, ParsedLedgerOp)> = Vec::with_capacity(count + 1);

        // Genesis mint
        let mint_meta = mint_metadata(count as u64 * BASE_UNITS_PER_BEAT * 10, &alice_hash, "bench");
        let mint_rec = ValidationRecord {
            id: "mint-0".into(),
            version: 1,
            content_hash: vec![0; 32],
            creator_public_key: genesis.public_key.clone(),
            timestamp: 0.0,
            parents: vec![],
            classification: Classification::Public,
            metadata: mint_meta.clone(),
            signature: None,
            sphincs_signature: None,
            zk_proof: None,
            itc_stamp: None,
            zone_refs: Vec::new(),
            creator_sphincs_pk: None,
            sig_algorithm: elara_runtime::crypto::ALG_DILITHIUM3,
            sphincs_algorithm: None,
            zone: None,
            identity_hash_wire: None,
            nonce: 0,
        };
        let mint_op = extract_ledger_op(&mint_rec).unwrap().unwrap();
        records.push((mint_rec, mint_op));

        // Transfers
        for i in 0..count {
            let meta = transfer_metadata(BASE_UNITS_PER_BEAT, &bob_hash, None);
            let rec = ValidationRecord {
                id: format!("xfer-{i}"),
                version: 1,
                content_hash: vec![0; 32],
                creator_public_key: alice.public_key.clone(),
                timestamp: (i + 1) as f64,
                parents: vec![],
                classification: Classification::Public,
                metadata: meta,
                signature: None,
                sphincs_signature: None,
                zk_proof: None,
                itc_stamp: None,
                zone_refs: Vec::new(),
                creator_sphincs_pk: None,
                sig_algorithm: elara_runtime::crypto::ALG_DILITHIUM3,
                sphincs_algorithm: None,
                zone: None,
                identity_hash_wire: None,
                nonce: 0,
            };
            let op = extract_ledger_op(&rec).unwrap().unwrap();
            records.push((rec, op));
        }

        c.bench_with_input(
            BenchmarkId::new("ledger_derive", count),
            &records,
            |b, records| {
                b.iter(|| ledger::derive_ledger(records, &genesis_hash).unwrap());
            },
        );
    }
}

fn bench_batch_verify_tps(c: &mut Criterion) {
    let kp = dilithium3_keygen().unwrap();

    for &count in &[10, 100, 1000] {
        let messages: Vec<Vec<u8>> = (0..count)
            .map(|i| format!("batch-msg-{i}").into_bytes())
            .collect();
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

        c.bench_with_input(
            BenchmarkId::new("batch_verify_parallel", count),
            &jobs,
            |b, jobs| b.iter(|| batch_verify(jobs)),
        );
    }
}

criterion_group!(
    benches,
    bench_record_create_and_sign,
    bench_record_verify,
    bench_rocksdb_insert,
    bench_wire_encode_decode,
    bench_full_pipeline,
    bench_token_transfer_pipeline,
    bench_ledger_derivation,
    bench_batch_verify_tps,
);
criterion_main!(benches);
