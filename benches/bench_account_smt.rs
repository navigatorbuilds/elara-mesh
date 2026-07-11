//! Account-SMT benchmarks — MESH-BFT Phase 3 Stage 2E.
//!
//! Measures the hot path introduced by Stage 2A/2B: the key-addressed sparse
//! Merkle tree over `AccountState` and the `flush_dirty` pipeline.
//!
//! What we guard against:
//!   - Per-update latency regressing above O(log N) sha3 + rocksdb cost.
//!   - Batched flush throughput dropping below the 10K rec/s target
//!     (≈20K account touches/sec assuming ~2 accounts per transfer).
//!   - Proof generation cost creeping up (it's the read path light nodes hit).
//!
//! For the soak-style 4GB / 10K rec/s / <300 MB RSS test, see the `#[ignore]`
//! integration test in `src/network/account_merkle.rs` (runnable via
//! `cargo test --features node --lib -- --ignored smt_soak`).

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use elara_runtime::crypto::hash::sha3_256;
use elara_runtime::network::account_merkle::{
    flush_dirty, hash_account_state, verify_proof, AccountStateSMT,
};
use elara_runtime::storage::rocks::StorageEngine;
use elara_runtime::accounting::ledger::{AccountState, LedgerState};

fn acc(seed: u64) -> [u8; 32] {
    sha3_256(&seed.to_be_bytes())
}

fn state_with_balance(available: u64, tx_count: u64) -> AccountState {
    AccountState {
        available,
        tx_count,
        ..Default::default()
    }
}

// ─── Core SMT ops ───────────────────────────────────────────────────────────

/// Single `update()` — measures O(log N) sha3 + cache hits on a cold tree.
fn bench_smt_update_cold(c: &mut Criterion) {
    c.bench_function("smt_update_cold", |b| {
        b.iter_custom(|iters| {
            let dir = tempfile::tempdir().unwrap();
            let storage = StorageEngine::open(dir.path()).unwrap();
            let mut tree = AccountStateSMT::new(&storage);
            let start = std::time::Instant::now();
            for i in 0..iters {
                tree.update(&acc(i), &sha3_256(&i.to_be_bytes())).unwrap();
            }
            start.elapsed()
        });
    });
}

/// `update` + `commit` per account — the expensive per-tx path we want to
/// *avoid* in production. Baseline for comparing against batched flush.
fn bench_smt_update_and_commit(c: &mut Criterion) {
    c.bench_function("smt_update_commit_per_account", |b| {
        b.iter_custom(|iters| {
            let dir = tempfile::tempdir().unwrap();
            let storage = StorageEngine::open(dir.path()).unwrap();
            let start = std::time::Instant::now();
            for i in 0..iters {
                let mut tree = AccountStateSMT::new(&storage);
                tree.update(&acc(i), &sha3_256(&i.to_be_bytes())).unwrap();
                tree.commit().unwrap();
            }
            start.elapsed()
        });
    });
}

/// Batched flush: N dirty accounts committed in a single WriteBatch.
/// This is the epoch-boundary hot path. Throughput here is the real
/// production number — `10000` should finish well under 1 second.
fn bench_smt_flush_batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("smt_flush_batch");
    for &n in &[100u64, 1_000, 10_000] {
        group.throughput(Throughput::Elements(n));
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter_custom(|iters| {
                // Pre-populate a ledger with n accounts, mark all dirty.
                // We rebuild on every iter so the tree starts empty and the
                // flush measures the full insert path, not in-place updates.
                let mut total = std::time::Duration::ZERO;
                for _ in 0..iters {
                    let dir = tempfile::tempdir().unwrap();
                    let storage = StorageEngine::open(dir.path()).unwrap();
                    let mut ledger = LedgerState::new();
                    for i in 0..n {
                        let hex_id = hex::encode(acc(i));
                        ledger.accounts.insert(hex_id.clone(), state_with_balance(i, 1));
                        ledger.smt_dirty.insert(hex_id);
                    }
                    let start = std::time::Instant::now();
                    let (flushed, _root) = flush_dirty(&storage, &mut ledger).unwrap();
                    total += start.elapsed();
                    assert_eq!(flushed as u64, n);
                }
                total
            });
        });
    }
    group.finish();
}

/// In-place re-flush: tree is already populated with N accounts; dirty all of
/// them again with new state. Represents steady-state ledger operation.
fn bench_smt_flush_reflow(c: &mut Criterion) {
    let mut group = c.benchmark_group("smt_flush_reflow");
    for &n in &[1_000u64, 10_000] {
        group.throughput(Throughput::Elements(n));
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter_custom(|iters| {
                // Build once, time only the second flush (everything already
                // committed to rocksdb, cache cold, tree populated).
                let dir = tempfile::tempdir().unwrap();
                let storage = StorageEngine::open(dir.path()).unwrap();
                let mut ledger = LedgerState::new();
                for i in 0..n {
                    let hex_id = hex::encode(acc(i));
                    ledger.accounts.insert(hex_id.clone(), state_with_balance(i, 1));
                    ledger.smt_dirty.insert(hex_id);
                }
                flush_dirty(&storage, &mut ledger).unwrap();

                let mut total = std::time::Duration::ZERO;
                for iter in 0..iters {
                    // Mutate every account, re-dirty, time the flush.
                    for i in 0..n {
                        let hex_id = hex::encode(acc(i));
                        let acct = ledger.accounts.get_mut(&hex_id).unwrap();
                        acct.available = acct.available.wrapping_add(iter + 1);
                        ledger.smt_dirty.insert(hex_id);
                    }
                    let start = std::time::Instant::now();
                    flush_dirty(&storage, &mut ledger).unwrap();
                    total += start.elapsed();
                }
                total
            });
        });
    }
    group.finish();
}

// ─── Proofs ────────────────────────────────────────────────────────────────

/// Proof generation at various populations. Sibling fetch is the cost driver.
fn bench_smt_proof_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("smt_proof_generate");
    for &n in &[100u64, 10_000, 100_000] {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            let dir = tempfile::tempdir().unwrap();
            let storage = StorageEngine::open(dir.path()).unwrap();
            let mut tree = AccountStateSMT::new(&storage);
            for i in 0..n {
                tree.update(&acc(i), &hash_account_state(&state_with_balance(i, 1)))
                    .unwrap();
            }
            tree.commit().unwrap();

            let target = acc(n / 2);
            let tree = AccountStateSMT::new(&storage);
            b.iter(|| tree.proof(&target).unwrap().unwrap());
        });
    }
    group.finish();
}

/// Stateless verification — what the light client pays per proof.
fn bench_smt_proof_verify(c: &mut Criterion) {
    let dir = tempfile::tempdir().unwrap();
    let storage = StorageEngine::open(dir.path()).unwrap();
    let mut tree = AccountStateSMT::new(&storage);
    for i in 0..1_000u64 {
        tree.update(&acc(i), &hash_account_state(&state_with_balance(i, 1)))
            .unwrap();
    }
    tree.commit().unwrap();
    let tree = AccountStateSMT::new(&storage);
    let proof = tree.proof(&acc(500)).unwrap().unwrap();

    c.bench_function("smt_proof_verify", |b| {
        b.iter(|| assert!(verify_proof(&proof)));
    });
}

// ─── Helpers ───────────────────────────────────────────────────────────────

fn bench_hash_account_state(c: &mut Criterion) {
    let state = AccountState {
        available: 12_345_678,
        staked: 9_876,
        total_received: 100_000,
        total_sent: 50_000,
        tx_count: 42,
        last_active: 1_700_000_000.0,
        vested_locked: 1_000_000,
        uptime_secs: 86_400,
        inactive_days: 3,
        witness_bonded: 0,
    };
    c.bench_function("hash_account_state", |b| {
        b.iter(|| hash_account_state(&state));
    });
}

criterion_group!(
    benches,
    bench_smt_update_cold,
    bench_smt_update_and_commit,
    bench_smt_flush_batch,
    bench_smt_flush_reflow,
    bench_smt_proof_generation,
    bench_smt_proof_verify,
    bench_hash_account_state,
);
criterion_main!(benches);
