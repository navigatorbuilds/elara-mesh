//! Gap 3 super-seal scale benchmark — closes the "test + benchmark + deploy"
//! rule for super-seal aggregation / checkpoint consolidation
//! (internal design notes §MAINNET MANDATE Gap 3). Correctness was already covered by
//! the integrity + coverage tests in `src/network/light.rs`; this supplies
//! the cluster-wide-rate evidence behind the design.
//!
//! ## What this measures
//!
//! Three call surfaces dominate the super-seal hot path:
//!
//! 1. **`create_super_seal`** — runs on the seal-loop of every anchor on
//!    every zone every `SUPER_SEAL_INTERVAL=64` epochs
//!    (`src/network/epoch.rs:4782`). Cost = Merkle root over N seal hashes
//!    plus one Dilithium3 sign. At Protocol §11.12 target of 1M zones ×
//!    60 s in-zone target, that's `1M / (64 × 60s) ≈ 260 super-seals/sec`
//!    cluster-wide create rate.
//!
//! 2. **`verify_super_seal_record_integrity`** — runs on every ingest path
//!    when a super-seal record arrives via gossip
//!    (`src/network/light.rs:1016`). Cost = SHA3-256 record hash +
//!    Dilithium3 verify. Every node that holds the zone in its peer set
//!    verifies once; at 64-witness committees, cluster-wide verify rate ≈
//!    create rate × 64.
//!
//! 3. **`verify_super_seal_full`** — runs on every light-client
//!    checkpoint sync (`src/network/light.rs:1075`). Cost = integrity
//!    verify + Merkle coverage rebuild over N seal hashes. A light client
//!    bootstrapping from genesis to current must walk one super-seal per
//!    interval — at 1M-zone mainnet running 1 year, that's
//!    `365 × 24 × 60 / (64 × 1 min) ≈ 8200 super-seals` per zone of
//!    interest.
//!
//! ## Why this matters
//!
//! Without super-seals, light clients must replay every seal from
//! genesis (Protocol §12 hard rule). At 720 seals/day/zone × 1M zones ×
//! 1 year = 263B seal records — uncatchable on phone-tier hardware.
//! Super-seals compress 64 seals into one signed Merkle root, dropping
//! the light-client trust set by 64× per checkpoint hop and bounding the
//! sync cost at `O(supersealsfromcheckpoint_to_now)` rather than
//! `O(allseals_since_genesis)`.
//!
//! ## Scenarios
//!
//! - `N=64`  — default `SUPER_SEAL_INTERVAL` cadence on mainnet.
//! - `N=256` — exercises a 4× larger window (would happen if the
//!   interval is bumped after a finality cadence change).
//! - `N=1024` — far past the realistic interval; surfaces Merkle/coverage
//!   cost as N grows so that any future tuning sees the trend.

use criterion::{
    criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput,
};

use elara_runtime::identity::{CryptoProfile, EntityType, Identity};
use elara_runtime::network::epoch::{create_super_seal, SuperSealParams};
use elara_runtime::network::light::{
    verify_super_seal_full, verify_super_seal_record_integrity,
};
use elara_runtime::ZoneId;

/// Build a deterministic set of `n` seal hashes. Pattern matches
/// `light.rs::build_real_super_seal` so bench coverage parallels test
/// coverage and any future Merkle layout change here doesn't drift
/// silently away from the test fixtures.
fn make_seal_hashes(n: u64) -> Vec<[u8; 32]> {
    (0..n)
        .map(|i| {
            let mut h = [0u8; 32];
            h[0..8].copy_from_slice(&i.to_le_bytes());
            h[8] = 0x01;
            h
        })
        .collect()
}

/// One-shot identity reused across iterations. Dilithium3 keygen is
/// expensive (single-digit ms) — generating per-iter would dominate.
/// Real seal-loops also reuse the anchor identity for its lifetime, so
/// pinning the identity here matches production behaviour.
fn fixture_identity() -> Identity {
    Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
        .expect("Dilithium3 keygen must succeed for bench fixture")
}

/// Helper: build a signed super-seal and return its wire bytes + record_hash.
fn build_signed_super_seal(
    identity: &Identity,
    n: u64,
) -> (Vec<u8>, [u8; 32], Vec<[u8; 32]>) {
    let hashes = make_seal_hashes(n);
    let (rec, _parsed) = create_super_seal(SuperSealParams {
        identity,
        zone: ZoneId::from_legacy(0),
        start_epoch: 0,
        end_epoch: n.saturating_sub(1),
        seal_hashes: &hashes,
        previous_super_seal_hash: [0u8; 32],
        committee_hash: [0u8; 32],
        timestamp: 0.0,
        slot_nonce: 1,
    })
    .expect("create_super_seal must succeed");
    let wire = rec.to_bytes();
    let record_hash = rec.record_hash();
    (wire, record_hash, hashes)
}

/// `create_super_seal` cost: Merkle root over N hashes + Dilithium3 sign.
/// The Dilithium3 sign should dominate for any reasonable N; if Merkle
/// shows up in the profile at large N, that's a flag to revisit the
/// `sort + MerkleTree::root` step.
fn bench_create(c: &mut Criterion) {
    let mut group = c.benchmark_group("super_seal_create");

    for &n in &[64u64, 256, 1024] {
        let identity = fixture_identity();
        let hashes = make_seal_hashes(n);

        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::new("seals", n), &n, |b, &n| {
            b.iter_batched(
                || (identity.clone(), hashes.clone()),
                |(id, hh)| {
                    let (rec, _) = create_super_seal(SuperSealParams {
                        identity: &id,
                        zone: ZoneId::from_legacy(0),
                        start_epoch: 0,
                        end_epoch: n.saturating_sub(1),
                        seal_hashes: &hh,
                        previous_super_seal_hash: [0u8; 32],
                        committee_hash: [0u8; 32],
                        timestamp: 0.0,
                        slot_nonce: 1,
                    })
                    .unwrap();
                    std::hint::black_box(rec);
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

/// Per-ingest cost: SHA3-256 record hash + Dilithium3 verify. This is
/// what every node pays for every super-seal it gossips, so cluster-wide
/// CPU = create_rate × committee_size × verify_cost.
fn bench_verify_integrity(c: &mut Criterion) {
    let mut group = c.benchmark_group("super_seal_verify_integrity");
    let identity = fixture_identity();
    let (wire, record_hash, _) = build_signed_super_seal(&identity, 64);

    group.throughput(Throughput::Elements(1));
    group.bench_function("seals_64", |b| {
        b.iter(|| {
            verify_super_seal_record_integrity(record_hash, &wire).unwrap();
        });
    });
    group.finish();
}

/// Light-client checkpoint sync cost: integrity verify + coverage
/// Merkle rebuild over N hashes. Per-super-seal cost during sync; total
/// sync = (super-seals from checkpoint to head) × this.
fn bench_verify_full(c: &mut Criterion) {
    let mut group = c.benchmark_group("super_seal_verify_full");
    let identity = fixture_identity();

    for &n in &[64u64, 256, 1024] {
        let (wire, record_hash, hashes) = build_signed_super_seal(&identity, n);

        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::new("seals", n), &n, |b, _| {
            b.iter(|| {
                verify_super_seal_full(record_hash, &wire, &hashes).unwrap();
            });
        });
    }
    group.finish();
}

fn print_projection(_c: &mut Criterion) {
    eprintln!();
    eprintln!("[super_seal_scale_projection]");
    eprintln!("  Protocol §11.12 target: 1M zones, 60 s in-zone finality,");
    eprintln!("  SUPER_SEAL_INTERVAL = 64.");
    eprintln!();
    eprintln!("  Per-zone create rate: 1 super-seal per (64 × 60 s) = 3840 s");
    eprintln!("                      = 22.5 super-seals/day per zone");
    eprintln!("  Cluster create rate: 1M zones × 22.5/day = 22.5M/day");
    eprintln!("                     ≈ 260 super-seals/sec cluster-wide");
    eprintln!();
    eprintln!("  Per-witness ingest verify rate: create rate × committee_size");
    eprintln!("                                  At C=64: 260 × 64 ≈ 16.6k/s");
    eprintln!("  CPU bound check: verify_integrity_secs × 16600 must be < 1 s/core");
    eprintln!();
    eprintln!("  Light-client genesis-to-now sync:");
    eprintln!("    1 year × 22.5 super-seals/day = ~8200 super-seals per zone");
    eprintln!("    Sync CPU = verify_full(64) × 8200");
    eprintln!("    Target: < 30 s on phone-tier hardware (single zone of interest).");
    eprintln!();
    eprintln!("  Compare against the criterion rows above to see where the");
    eprintln!("  scale ceiling binds.");
    eprintln!();
}

criterion_group!(
    benches,
    bench_create,
    bench_verify_integrity,
    bench_verify_full,
    print_projection,
);
criterion_main!(benches);
