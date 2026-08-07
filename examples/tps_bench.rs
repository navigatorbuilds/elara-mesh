//! Standalone TPS benchmark — run on any device to get real throughput numbers.
//! No criterion dependency, just raw timing.
//!
//! Usage: cargo run --release --example tps_bench
//! Or cross-compile and copy the binary to a Raspberry Pi.

use std::time::Instant;

use elara_runtime::crypto::batch::{batch_verify, VerifyJob};
use elara_runtime::crypto::hash::sha3_256_hex;
use elara_runtime::crypto::pqc::{dilithium3_keygen, dilithium3_sign_with_pk, dilithium3_verify};
use elara_runtime::identity::{CryptoProfile, EntityType, Identity};
use elara_runtime::record::{Classification, ValidationRecord};
use elara_runtime::storage::rocks::StorageEngine;
use elara_runtime::storage::Storage;
use elara_runtime::accounting::ledger;
use elara_runtime::accounting::types::*;

fn main() {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║         beat Network — TPS Benchmark                       ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║ Platform: {:<50}║", std::env::consts::ARCH);

    // CPU info
    #[cfg(target_os = "linux")]
    {
        if let Ok(cpuinfo) = std::fs::read_to_string("/proc/cpuinfo") {
            for line in cpuinfo.lines() {
                if line.starts_with("model name") || line.starts_with("Model") {
                    let name = line.split(':').nth(1).unwrap_or("unknown").trim();
                    println!("║ CPU: {:<55}║", &name[..name.len().min(55)]);
                    break;
                }
            }
        }
    }
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    let n = 1000; // iterations per test

    // ─── 1. Dilithium3 keygen ───────────────────────────────────────────
    print_bench("Dilithium3 keygen", n, || {
        dilithium3_keygen().unwrap();
    });

    // ─── 2. Dilithium3 sign ─────────────────────────────────────────────
    let kp = dilithium3_keygen().unwrap();
    let msg = b"benchmark message for signing performance test";
    print_bench("Dilithium3 sign", n, || {
        dilithium3_sign_with_pk(msg, &kp.secret_key, &kp.public_key).unwrap();
    });

    // ─── 3. Dilithium3 verify ───────────────────────────────────────────
    let sig = dilithium3_sign_with_pk(msg, &kp.secret_key, &kp.public_key).unwrap();
    print_bench("Dilithium3 verify", n, || {
        dilithium3_verify(msg, &sig, &kp.public_key).unwrap();
    });

    // ─── 4. Record create + sign ────────────────────────────────────────
    let identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB).unwrap();
    print_bench("Record create+sign", n, || {
        let mut record = ValidationRecord::create(
            b"benchmark content",
            identity.public_key.clone(),
            vec![],
            Classification::Public,
            None,
        );
        let signable = record.signable_bytes();
        record.signature = Some(identity.sign(&signable).unwrap());
    });

    // ─── 5. Wire encode ─────────────────────────────────────────────────
    let record = {
        let mut r = ValidationRecord::create(
            b"wire bench",
            identity.public_key.clone(),
            vec![],
            Classification::Public,
            None,
        );
        let signable = r.signable_bytes();
        r.signature = Some(identity.sign(&signable).unwrap());
        r
    };
    let n_wire = 10_000;
    print_bench("Wire encode", n_wire, || {
        let _ = record.to_bytes();
    });

    // ─── 6. Wire decode ─────────────────────────────────────────────────
    let wire = record.to_bytes();
    print_bench("Wire decode", n_wire, || {
        ValidationRecord::from_bytes(&wire).unwrap();
    });

    // ─── 7. SQLite insert ───────────────────────────────────────────────
    {
        let dir = tempfile::tempdir().unwrap();
        let mut db = StorageEngine::open(dir.path()).unwrap();
        let start = Instant::now();
        for i in 0..n {
            let mut rec = ValidationRecord::create(
                format!("sql-{i}").as_bytes(),
                identity.public_key.clone(),
                vec![],
                Classification::Public,
                None,
            );
            rec.id = format!("sql-{i:06}");
            let signable = rec.signable_bytes();
            rec.signature = Some(identity.sign(&signable).unwrap());
            let _ = db.insert(&rec);
        }
        let elapsed = start.elapsed();
        print_result("SQLite insert (incl sign)", n as u64, elapsed);
    }

    // ─── 8. Full pipeline: create + verify + insert ─────────────────────
    {
        let dir = tempfile::tempdir().unwrap();
        let mut db = StorageEngine::open(dir.path()).unwrap();
        let start = Instant::now();
        for i in 0..n {
            let mut rec = ValidationRecord::create(
                format!("pipe-{i}").as_bytes(),
                identity.public_key.clone(),
                vec![],
                Classification::Public,
                None,
            );
            rec.id = format!("pipe-{i:06}");
            let signable = rec.signable_bytes();
            rec.signature = Some(identity.sign(&signable).unwrap());

            // Verify
            let _v = Identity::verify(
                &signable,
                rec.signature.as_ref().unwrap(),
                &rec.creator_public_key,
            )
            .unwrap();

            // Insert
            let _ = db.insert(&rec);
        }
        let elapsed = start.elapsed();
        print_result("FULL PIPELINE (create+verify+insert)", n as u64, elapsed);
    }

    // ─── 9. Beat transfer pipeline ─────────────────────────────────────
    {
        let genesis = Identity::generate(EntityType::Device, CryptoProfile::ProfileB).unwrap();
        let alice = Identity::generate(EntityType::Device, CryptoProfile::ProfileB).unwrap();
        let bob = Identity::generate(EntityType::Device, CryptoProfile::ProfileB).unwrap();
        let alice_hash = sha3_256_hex(&alice.public_key);
        let bob_hash = sha3_256_hex(&bob.public_key);

        let dir = tempfile::tempdir().unwrap();
        let mut db = StorageEngine::open(dir.path()).unwrap();

        // Seed mint
        let mint_meta = mint_metadata(n as u64 * BASE_UNITS_PER_BEAT * 100, &alice_hash, "bench");
        let mut mint_rec = ValidationRecord::create(
            b"beat:mint:seed",
            genesis.public_key.clone(),
            vec![],
            Classification::Public,
            Some(mint_meta),
        );
        mint_rec.id = "mint-seed".into();
        let signable = mint_rec.signable_bytes();
        mint_rec.signature = Some(genesis.sign(&signable).unwrap());
        db.insert(&mint_rec).unwrap();

        let start = Instant::now();
        for i in 0..n {
            let meta = transfer_metadata(BASE_UNITS_PER_BEAT, &bob_hash, None);
            let mut rec = ValidationRecord::create(
                format!("beat:transfer:{}", BASE_UNITS_PER_BEAT).as_bytes(),
                alice.public_key.clone(),
                vec![],
                Classification::Public,
                Some(meta),
            );
            rec.id = format!("xfer-{i:06}");
            let signable = rec.signable_bytes();
            rec.signature = Some(alice.sign(&signable).unwrap());

            let _v = Identity::verify(
                &signable,
                rec.signature.as_ref().unwrap(),
                &rec.creator_public_key,
            )
            .unwrap();

            let _ = db.insert(&rec);
        }
        let elapsed = start.elapsed();
        print_result("BEAT TRANSFER PIPELINE", n as u64, elapsed);
    }

    // ─── 10. Batch verify (parallel) ────────────────────────────────────
    for &batch_size in &[10, 100, 1000] {
        let messages: Vec<Vec<u8>> = (0..batch_size)
            .map(|i| format!("batch-{i}").into_bytes())
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

        let runs = (1000 / batch_size).max(10);
        let start = Instant::now();
        for _ in 0..runs {
            batch_verify(&jobs);
        }
        let elapsed = start.elapsed();
        let total_verifies = (runs * batch_size) as u64;
        print_result(
            &format!("Batch verify ({}×{})", runs, batch_size),
            total_verifies,
            elapsed,
        );
    }

    // ─── 11. Ledger derivation ──────────────────────────────────────────
    {
        let genesis = Identity::generate(EntityType::Device, CryptoProfile::ProfileB).unwrap();
        let alice = Identity::generate(EntityType::Device, CryptoProfile::ProfileB).unwrap();
        let bob = Identity::generate(EntityType::Device, CryptoProfile::ProfileB).unwrap();
        let genesis_hash = sha3_256_hex(&genesis.public_key);
        let alice_hash = sha3_256_hex(&alice.public_key);
        let bob_hash = sha3_256_hex(&bob.public_key);

        for &count in &[100, 1000, 10000] {
            let mut records = Vec::with_capacity(count + 1);

            let mint_meta =
                mint_metadata(count as u64 * BASE_UNITS_PER_BEAT * 10, &alice_hash, "bench");
            let mint_rec = ValidationRecord {
                id: "mint-0".into(),
                version: 1,
                content_hash: vec![0; 32],
                creator_public_key: genesis.public_key.clone(),
                timestamp: 0.0,
                parents: vec![],
                classification: Classification::Public,
                metadata: mint_meta,
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

            let runs = (10000 / count).max(5);
            let start = Instant::now();
            for _ in 0..runs {
                ledger::derive_ledger(&records, &genesis_hash).unwrap();
            }
            let elapsed = start.elapsed();
            let total = (runs * (count + 1)) as u64;
            print_result(
                &format!("Ledger derive ({} records × {})", count, runs),
                total,
                elapsed,
            );
        }
    }

    println!();
    println!("Done.");
}

fn print_bench<F: FnMut()>(name: &str, iterations: usize, mut f: F) {
    let start = Instant::now();
    for _ in 0..iterations {
        f();
    }
    let elapsed = start.elapsed();
    print_result(name, iterations as u64, elapsed);
}

fn print_result(name: &str, count: u64, elapsed: std::time::Duration) {
    let secs = elapsed.as_secs_f64();
    let per_op = secs / count as f64;
    let ops_per_sec = count as f64 / secs;

    if per_op < 0.001 {
        println!(
            "  {:<42} {:>8.1} µs/op    {:>10.0} ops/sec",
            name,
            per_op * 1_000_000.0,
            ops_per_sec
        );
    } else {
        println!(
            "  {:<42} {:>8.2} ms/op    {:>10.0} ops/sec",
            name,
            per_op * 1_000.0,
            ops_per_sec
        );
    }
}
