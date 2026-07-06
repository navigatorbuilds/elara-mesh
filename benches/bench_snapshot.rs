//! Snapshot wire-path benchmark — Gap 7 onboard-speed (an internal audit).
//!
//! Closes the audit's unmeasured-claim hole: "10M-record chains onboard in
//! minutes" was structurally true (snapshot serialize → transfer → apply
//! exists) but never benchmarked. Fresh nodes today pay this cost on every
//! cold start; without numbers, scale-targets in Protocol §11.12 are
//! aspiration, not budget.
//!
//! ## What this measures
//!
//!   * `snapshot_serialize_to_json` — `serde_json::to_vec(NodeSnapshot)` at
//!     N = 1k, 10k, 100k accounts. Linear in account count; the JSON-write
//!     path is the dominant single-thread cost on the emitter side.
//!   * `snapshot_deserialize_from_json` — `serde_json::from_slice` of the
//!     same payload. The receiver pays this once before any verification or
//!     ledger-apply step starts.
//!   * `state_delta_serialize` — same thing for the incremental
//!     `StateDelta` path landed in `9b52d03`. Delta size scales with
//!     `changed_accounts.len()`, not total ledger size — this bench
//!     quantifies the win for steady-state light-client sync vs. cold-start.
//!
//! Wire size and per-account cost is extrapolatable to 10M from these
//! points: serde_json on `AccountState` is bounded per row, so
//! `bytes(N) ≈ N · bytes(1)`.
//!
//! ## What this deliberately does NOT measure
//!
//!   * Network transfer time. That's link-bandwidth × wire-size and the
//!     audit's "100 Mbps" is a deployment assumption, not a code path.
//!   * Dual-sig verification (Dilithium3 + SPHINCS+). Constant-time per
//!     snapshot regardless of N — covered by `bench_crypto`.
//!   * Full apply path (`load_snapshot` + ledger merge + SMT rebuild).
//!     Apply speed is ledger-state mutation cost, which is RocksDB-bound
//!     and orthogonal to the wire-format bottleneck.
//!
//! ## How to read results
//!
//! Throughput is reported as `accounts/sec`. To project to 10M:
//!
//!   serialize_seconds_at_10M ≈ 10_000_000 / accounts_per_sec_at_100k
//!
//! Audit claim ("minutes" at 10M) holds iff the projection stays under
//! ~600 s end-to-end (serialize + parse + apply). This bench covers the
//! first two; the third needs a soak test.
//!
//! Run subset:
//!     cargo bench --bench bench_snapshot
//!     cargo bench --bench bench_snapshot snapshot_serialize_to_json/100000
//!
//! @spec Protocol §11.12 (cold-start onboarding budget)

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::collections::{BTreeMap, HashSet};

use elara_runtime::network::epoch::EpochState;
use elara_runtime::network::snapshot::{NodeSnapshot, StateDelta};
use elara_runtime::accounting::ledger::{AccountState, LedgerState};

/// Build a synthetic ledger with `n` accounts. Each account has a small
/// random-looking but deterministic balance distribution so JSON serialize
/// hits a realistic field-population path (not all-zeros short-circuit).
fn synth_ledger(n: usize) -> LedgerState {
    let mut ledger = LedgerState::new();
    for i in 0..n {
        let id = format!("{:064x}", i as u128);
        let bal = 1_000_000 + (i as u64).wrapping_mul(7919);
        let st = AccountState {
            available: bal,
            staked: bal / 4,
            total_received: bal,
            total_sent: bal / 8,
            tx_count: ((i % 1024) + 1) as u64,
            last_active: 1_700_000_000.0 + (i as f64),
            vested_locked: bal / 16,
            uptime_secs: (i % 86_400) as u64,
            inactive_days: (i % 7) as u32,
            witness_bonded: if i % 50 == 0 { bal / 2 } else { 0 },
        };
        ledger.accounts.insert(id, st);
    }
    ledger.total_supply = ledger
        .accounts
        .values()
        .map(|s| s.available + s.staked)
        .sum();
    ledger.total_staked = ledger.accounts.values().map(|s| s.staked).sum();
    ledger
}

fn synth_snapshot(n: usize) -> NodeSnapshot {
    let ledger = synth_ledger(n);
    let finalized: HashSet<String> = HashSet::new();
    let epoch = EpochState::default();
    NodeSnapshot::new(ledger, finalized, epoch)
}

fn synth_state_delta(changed: usize) -> StateDelta {
    let mut changed_accounts = BTreeMap::new();
    for i in 0..changed {
        let id = format!("{:064x}", i as u128);
        let bal = 1_000_000 + (i as u64).wrapping_mul(7919);
        let st = AccountState {
            available: bal,
            staked: bal / 4,
            total_received: bal,
            total_sent: bal / 8,
            tx_count: ((i % 1024) + 1) as u64,
            last_active: 1_700_000_000.0 + (i as f64),
            vested_locked: bal / 16,
            uptime_secs: (i % 86_400) as u64,
            inactive_days: (i % 7) as u32,
            witness_bonded: 0,
        };
        changed_accounts.insert(id, st);
    }
    StateDelta {
        since_epoch: 100,
        current_epoch: 200,
        baseline_available: true,
        account_state_root: format!("{:064x}", 0u128),
        merkle_root: format!("{:064x}", 0u128),
        latest_super_seal_epoch: Some(192),
        latest_super_seal_record_hash: Some(format!("{:064x}", 0u128)),
        latest_sealed_account_epoch: Some(108),
        latest_sealed_account_smt_root: Some(format!("{:064x}", 0u128)),
        changed_accounts,
        removed_accounts: Vec::new(),
        total_accounts: changed as u64,
        total_supply: 0,
        total_staked: 0,
        snapshot_timestamp: 1_700_000_000.0,
        signer_identity: format!("{:064x}", 0u128),
        signer_public_key: "00".repeat(1952),
        signer_sphincs_public_key: None,
        checksum: format!("{:064x}", 0u128),
        signature: "00".repeat(3293),
        sphincs_signature: None,
        protocol_version: 1,
    }
}

// ─── Snapshot serialize ─────────────────────────────────────────────────────

fn bench_snapshot_serialize(c: &mut Criterion) {
    let mut group = c.benchmark_group("snapshot_serialize_to_json");
    for &n in &[1_000usize, 10_000, 100_000] {
        let snap = synth_snapshot(n);
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &snap, |b, snap| {
            b.iter(|| {
                let bytes = serde_json::to_vec(snap).expect("serialize");
                std::hint::black_box(bytes.len())
            });
        });
    }
    group.finish();
}

// ─── Snapshot deserialize ───────────────────────────────────────────────────

fn bench_snapshot_deserialize(c: &mut Criterion) {
    let mut group = c.benchmark_group("snapshot_deserialize_from_json");
    for &n in &[1_000usize, 10_000, 100_000] {
        let snap = synth_snapshot(n);
        let bytes = serde_json::to_vec(&snap).expect("serialize");
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &bytes, |b, bytes| {
            b.iter(|| {
                let parsed: NodeSnapshot =
                    serde_json::from_slice(bytes).expect("deserialize");
                std::hint::black_box(parsed.ledger.accounts.len())
            });
        });
    }
    group.finish();
}

// ─── State-delta serialize ──────────────────────────────────────────────────

fn bench_state_delta_serialize(c: &mut Criterion) {
    let mut group = c.benchmark_group("state_delta_serialize");
    for &n in &[100usize, 1_000, 10_000, 100_000] {
        let delta = synth_state_delta(n);
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &delta, |b, delta| {
            b.iter(|| {
                let bytes = serde_json::to_vec(delta).expect("serialize");
                std::hint::black_box(bytes.len())
            });
        });
    }
    group.finish();
}

// ─── Wire-size sanity print (one-shot, not a perf measurement) ─────────────
//
// Runs once at bench startup so operators see absolute byte counts in the
// criterion log. Not measured by criterion itself; the per-account cost
// from this print is what gets multiplied to project 10M.

fn print_wire_sizes(_c: &mut Criterion) {
    let mut sizes_for_log = Vec::new();
    for &n in &[1_000usize, 10_000, 100_000] {
        let snap = synth_snapshot(n);
        let raw = serde_json::to_vec(&snap).expect("serialize");
        sizes_for_log.push((n, raw.len()));
    }
    eprintln!("\n[snapshot_wire_size]");
    for (n, bytes) in &sizes_for_log {
        let per_account = *bytes as f64 / *n as f64;
        let proj_10m = (per_account * 10_000_000.0) / (1024.0 * 1024.0);
        eprintln!(
            "  N={n:>7}  raw={bytes:>10} bytes  per_account={per_account:6.0} B  10M_projection={proj_10m:8.0} MB"
        );
    }
    eprintln!();
}

// ─── Audit-2026-05-02 §7 follow-up — direct 1M / 10M measurement ───────────
//
// The standard criterion benches above stop at 100k accounts because each
// data-point runs for ~100 iterations and 100k × 100 = ~10M total elements
// is already a 60-second bench. Closing the audit's §7 hole ("did not
// exercise snapshot path at 10M record scale") needs ONE pass at the audit's
// claimed scale, not a hot-loop measurement.
//
// Default-off because the 10M run peaks at ~2.5 GB heap and ~70 s wall time
// on i9-class hardware. 1M is the sweet spot for routine validation: 10×
// past the criterion top scale, ~250 MB peak, ~7 s wall — enough to
// re-validate that serde_json's per-account cost stays linear.
//
// Opt-in:
//   BENCH_SNAPSHOT_LARGE=1   run at N=1_000_000  (linear-extrapolation check)
//   BENCH_SNAPSHOT_HUGE=1    also run at N=10_000_000  (audit-claim direct measurement)
fn bench_snapshot_large_oneshot(_c: &mut Criterion) {
    let mut sizes: Vec<usize> = Vec::new();
    if std::env::var("BENCH_SNAPSHOT_LARGE").is_ok() {
        sizes.push(1_000_000);
    }
    if std::env::var("BENCH_SNAPSHOT_HUGE").is_ok() {
        sizes.push(10_000_000);
    }
    if sizes.is_empty() {
        return;
    }

    eprintln!("\n[snapshot_large_oneshot] (an internal audit follow-up)");
    for n in sizes {
        let t_build = std::time::Instant::now();
        let snap = synth_snapshot(n);
        let build_ms = t_build.elapsed().as_secs_f64() * 1000.0;

        let t_ser = std::time::Instant::now();
        let bytes = serde_json::to_vec(&snap).expect("serialize");
        let ser_ms = t_ser.elapsed().as_secs_f64() * 1000.0;
        let len = bytes.len();

        let t_deser = std::time::Instant::now();
        let parsed: NodeSnapshot =
            serde_json::from_slice(&bytes).expect("deserialize");
        let deser_ms = t_deser.elapsed().as_secs_f64() * 1000.0;
        let parsed_len = parsed.ledger.accounts.len();
        assert_eq!(parsed_len, n, "round-trip account count mismatch at N={n}");

        let per_account = len as f64 / n as f64;
        let ser_us_per_acct = (ser_ms * 1000.0) / n as f64;
        let deser_us_per_acct = (deser_ms * 1000.0) / n as f64;
        eprintln!(
            "  N={n:>10}  build={build_ms:>7.0}ms  ser={ser_ms:>7.0}ms  \
             deser={deser_ms:>7.0}ms  bytes={len:>11}  per_acct={per_account:>5.0}B  \
             ser_us/acct={ser_us_per_acct:>4.2}  deser_us/acct={deser_us_per_acct:>4.2}"
        );
        if n < 10_000_000 {
            eprintln!(
                "  ──── linear projection to 10M:  ser={:.1}s  deser={:.1}s  bytes={:.0}MB",
                (ser_ms / n as f64) * 10_000_000.0 / 1000.0,
                (deser_ms / n as f64) * 10_000_000.0 / 1000.0,
                (len as f64 / n as f64) * 10_000_000.0 / (1024.0 * 1024.0),
            );
        }
        // Drop the parsed copy explicitly so the next iteration doesn't
        // double-peak heap (matters at 10M where each copy is ~2 GB).
        drop(parsed);
        drop(bytes);
        drop(snap);
    }
    eprintln!();
}

criterion_group!(
    benches,
    bench_snapshot_serialize,
    bench_snapshot_deserialize,
    bench_state_delta_serialize,
    print_wire_sizes,
    bench_snapshot_large_oneshot,
);
criterion_main!(benches);
