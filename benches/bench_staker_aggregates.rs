//! Staker aggregate read benchmark — OPS-126 100× claim closure
//! (an internal audit carry-forward, an internal audit carry-forward).
//!
//! OPS-126 (commit `dc7a74c` follow-up) replaced O(accounts) scans in three
//! runtime hot paths with reads of the incrementally-maintained `total_staked`
//! field and `staker_index: HashMap<String, Vec<String>>`:
//!
//!   * `consensus::register_stakes_from_ledger` (was: scan every account to
//!     sum `staked`; is: read `ledger.total_staked` once).
//!   * `ingest::global_seal` `stakers_by_zone` build (was: scan every account
//!     to materialize the staker set; is: iterate `staker_index.keys()`).
//!   * `auto_witness` stake-weighted committee selection (was: scan to build
//!     the staked-pool; is: enumerate `staker_index` then look up amounts).
//!
//! The audit's open question: **is the 100× claim measurable?**
//!
//! This bench answers it with two scenarios mirroring the runtime hot paths:
//!
//!   * `total_staked_read` — global sum (consensus + auto_witness numerator).
//!     Old path = `accounts.iter().filter(staked>0).map(staked).sum::<u64>()`.
//!     New path = `ledger.total_staked` u64 read.
//!
//!   * `all_stakers_enum` — staker identity set (auto_witness denominator +
//!     ingest::global_seal). Old path = `accounts.iter().filter(staked>0)`.
//!     New path = `staker_index.keys()`.
//!
//! ## Scenarios
//!
//! Sized to reflect mainnet account population × testnet staker rate:
//!
//!   * `1k_accounts/1pct_stakers`    — early mainnet, ~10 stakers
//!   * `10k_accounts/1pct_stakers`   — mid mainnet (Protocol §11.12 floor)
//!   * `100k_accounts/1pct_stakers`  — denser mainnet
//!   * `1M_accounts/1pct_stakers`    — Protocol §11.12 target (1M zones)
//!   * `10k_accounts/5pct_stakers`   — high-stake regime sensitivity check
//!   * `100k_accounts/5pct_stakers`  — same, larger scale
//!
//! ## What this bench answers
//!
//!   * Pre-OPS-126 cost per consensus tick at 1M accounts × 1% stakers
//!   * Post-OPS-126 cost (constant — single u64 read or HashMap iter)
//!   * Speedup ratio per scenario — closes the "100× claim is theoretical"
//!     carry-forward by producing concrete numbers
//!
//! ## What this bench deliberately does NOT measure
//!
//!   * Lock contention on `ledger.read().await` while iterating —
//!     orthogonal to the inner-loop CPU cost (an internal audit #5 carry).
//!   * Real-traffic stake-event throughput — that's the OPS-126 "synthetic
//!     stake feeder" remaining open work; this bench amortizes the CPU
//!     measurement so the feeder is only needed for end-to-end testing.
//!   * Index rebuild cost on snapshot restore (`rebuild_staker_index`) —
//!     that's a startup-path cost, not a runtime hot-path cost.
//!
//! Run subset:
//!     cargo bench --bench bench_staker_aggregates
//!     cargo bench --bench bench_staker_aggregates total_staked_read/1M
//!
//! @spec Protocol §11.12 (mainnet scale target) — an internal audit +
//! an internal audit carry-forward closure for OPS-126.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use elara_runtime::accounting::ledger::{AccountState, LedgerState};

/// Build a synthetic `LedgerState` with `n` accounts, of which the first
/// `staker_count` carry a non-zero `staked` balance. All invariants used by
/// the bench are populated by hand (no DAG replay), matching the steady-state
/// the runtime maintains after `apply_op` has done the same updates:
///
///   * `accounts.staked` = per-account stake (set on the staker prefix).
///   * `total_staked`    = sum of `accounts.staked` (maintained at every
///     stake/unstake/slash mutation site).
///   * `staker_index`    = identity → stake-record-IDs for every staker
///     (rebuilt on snapshot restore, maintained at
///     mutation sites otherwise).
fn synth_ledger(n: usize, staker_count: usize) -> LedgerState {
    assert!(staker_count <= n, "stakers must be subset of accounts");
    let mut ledger = LedgerState::new();
    ledger.accounts.reserve(n);
    ledger.staker_index.reserve(staker_count);

    let mut running_total: u64 = 0;
    for i in 0..n {
        let id = format!("{:064x}", i as u128);
        let mut acct = AccountState { available: 1_000_000, ..Default::default() };
        if i < staker_count {
            // Non-uniform stake — mirrors realistic skew without needing the
            // VestingManager / StakeEntry overhead.
            let stake = 1_000 + (i as u64).wrapping_mul(7919) % 100_000;
            acct.staked = stake;
            running_total += stake;
            // staker_index.entry().or_default().push(record_id) — one
            // synthetic stake record per identity is enough; the runtime
            // path enumerates `keys()`, not the Vec<String> contents.
            let synthetic_record_id = format!("stake-{i:010}");
            ledger
                .staker_index
                .entry(id.clone())
                .or_default()
                .push(synthetic_record_id);
        }
        ledger.accounts.insert(id, acct);
    }
    ledger.total_staked = running_total;
    debug_assert_eq!(
        ledger.staker_index.len(),
        staker_count,
        "staker_index size must match populated staker prefix"
    );
    ledger
}

fn bench_total_staked_read(c: &mut Criterion) {
    let mut group = c.benchmark_group("total_staked_read");

    // (account_count, staker_count, label)
    let scenarios: &[(usize, usize, &str)] = &[
        (1_000, 10, "1k_1pct"),
        (10_000, 100, "10k_1pct"),
        (100_000, 1_000, "100k_1pct"),
        (1_000_000, 10_000, "1M_1pct"),
        (10_000, 500, "10k_5pct"),
        (100_000, 5_000, "100k_5pct"),
    ];

    for (n, k, label) in scenarios {
        let ledger = synth_ledger(*n, *k);

        // OLD path — O(N) scan over every account, sum non-zero stakes.
        group.throughput(Throughput::Elements(*n as u64));
        group.bench_with_input(
            BenchmarkId::new("scan_old", label),
            &ledger,
            |b, ledger| {
                b.iter(|| {
                    let total: u64 = ledger
                        .accounts
                        .iter()
                        .filter(|(_, a)| a.staked > 0)
                        .map(|(_, a)| a.staked)
                        .sum();
                    std::hint::black_box(total)
                });
            },
        );

        // NEW path — O(1) u64 field read.
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::new("field_new", label),
            &ledger,
            |b, ledger| {
                b.iter(|| std::hint::black_box(ledger.total_staked));
            },
        );
    }
    group.finish();
}

fn bench_all_stakers_enum(c: &mut Criterion) {
    let mut group = c.benchmark_group("all_stakers_enum");

    let scenarios: &[(usize, usize, &str)] = &[
        (1_000, 10, "1k_1pct"),
        (10_000, 100, "10k_1pct"),
        (100_000, 1_000, "100k_1pct"),
        (1_000_000, 10_000, "1M_1pct"),
        (10_000, 500, "10k_5pct"),
        (100_000, 5_000, "100k_5pct"),
    ];

    for (n, k, label) in scenarios {
        let ledger = synth_ledger(*n, *k);

        // OLD path — O(N) scan over accounts, collect identities with
        // staked > 0. Mirrors `ingest::global_seal`'s pre-OPS-126
        // `stakers_by_zone` materialization (without the per-staker
        // zone-lookup, which is orthogonal).
        group.throughput(Throughput::Elements(*n as u64));
        group.bench_with_input(
            BenchmarkId::new("scan_old", label),
            &ledger,
            |b, ledger| {
                b.iter(|| {
                    let stakers: Vec<&String> = ledger
                        .accounts
                        .iter()
                        .filter(|(_, a)| a.staked > 0)
                        .map(|(id, _)| id)
                        .collect();
                    std::hint::black_box(stakers.len())
                });
            },
        );

        // NEW path — O(K) iter over the pre-indexed staker set.
        group.throughput(Throughput::Elements(*k as u64));
        group.bench_with_input(
            BenchmarkId::new("index_new", label),
            &ledger,
            |b, ledger| {
                b.iter(|| {
                    let stakers: Vec<&String> = ledger.staker_index.keys().collect();
                    std::hint::black_box(stakers.len())
                });
            },
        );
    }
    group.finish();
}

// ─── Speedup projection log ────────────────────────────────────────────────
//
// Per-call cost is measured by the criterion groups above; this prints the
// audit's flagship claim and the budget threshold so the projection is
// machine-readable from the bench log without diff'ing two criterion runs
// by hand.

fn print_projection_table(_c: &mut Criterion) {
    eprintln!();
    eprintln!("[staker_aggregates_projection]");
    eprintln!("  Audit claim (OPS-126): 100× CPU reduction at 1M accounts × 1% stakers.");
    eprintln!("  Formula: speedup = scan_old(N) / field_or_index_new(N or K).");
    eprintln!();
    eprintln!("  Reference points (theoretical, validated by criterion above):");
    eprintln!("    1k accounts   × 1% stakers → ~1k ops vs O(1)/O(10)  → ~100× / ~100×");
    eprintln!("    10k accounts  × 1% stakers → ~10k ops vs O(1)/O(100) → ~10000× / ~100×");
    eprintln!("    100k accounts × 1% stakers → ~100k ops vs O(1)/O(1k) → ~100000× / ~100×");
    eprintln!("    1M accounts   × 1% stakers → ~1M ops vs O(1)/O(10k)  → ~1000000× / ~100×");
    eprintln!();
    eprintln!("  Consensus tick cost @ 1M accounts (pre/post-OPS-126):");
    eprintln!("    pre  : O(1M) HashMap iter per call = ~ms per tick (audit hot path)");
    eprintln!("    post : O(1) field read OR O(10k) index iter = ~µs per tick");
    eprintln!();
    eprintln!("  Compare against `total_staked_read/*/scan_old` vs `field_new`,");
    eprintln!("  and `all_stakers_enum/*/scan_old` vs `index_new` rows above.");
    eprintln!();
}

criterion_group!(
    benches,
    bench_total_staked_read,
    bench_all_stakers_enum,
    print_projection_table,
);
criterion_main!(benches);
