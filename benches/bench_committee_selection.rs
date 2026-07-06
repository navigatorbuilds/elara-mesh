//! VRF committee selection scale benchmark — Gap 5 unmeasured-claim closure
//! (an internal audit).
//!
//! `select_epoch_committee_scoped` runs once per zone per epoch on the
//! consensus tick (`epoch.rs:3367`). At the Protocol §11.12 target of 1M
//! zones, this loop dominates epoch CPU cost. The audit asserted "O(zone_count
//! × subscribers_per_zone), not quadratic — no scale-blocker identified" but
//! never measured the constant. This bench supplies the number so the assert
//! is a budget, not a wish.
//!
//! ## Per-zone cost model (consensus.rs:488)
//!
//! 1. **Filter**: `staked_weighted.iter().filter(|id| subs.contains(id))`
//!    → O(|staked|) HashSet lookups. Always paid.
//! 2. **Pool selection**: if eligible < `MIN_SCOPED_ELIGIBLE` (3) →
//!    fall back to full staked slice; else use eligible.
//! 3. **Small-network short-circuit**: if pool ≤ `COMMITTEE_SMALL_NETWORK`
//!    (10) → return whole pool, skip sortition. This is the common-case
//!    path at mainnet targets (5 subs/zone).
//! 4. **Sortition** (only when pool > 10): for each pool member, one
//!    SHA3-256 over (vrf || zone || identity) → O(|pool|) hashing +
//!    O(|pool| log |pool|) priority sort.
//!
//! ## Scenarios
//!
//! Names are `<stakers>/<subscribers_per_zone>`:
//!
//!   * `6/6`        — retired 6-node dev fleet (2026-06), kept as a historical shape
//!   * `100/5`      — early mainnet, sparse zones
//!   * `1k/5`       — mid mainnet target, sparse zones
//!   * `10k/5`      — Protocol §11.12 target (10K nodes × 5 subs/zone)
//!   * `100k/5`     — interplanetary headroom
//!   * `10k/50`     — denser subscription (fits the per-zone cap; still
//!     on the small-network path)
//!   * `10k/2`      — bootstrap fallback: subs < `MIN_SCOPED_ELIGIBLE` so
//!     we score the entire 10K stake set per zone (worst-
//!     case sortition path)
//!   * `10k/100`    — sortition path stress (pool=100 > small-network)
//!
//! ## Projecting to 1M zones
//!
//!   per_epoch_cpu_secs ≈ zone_count × per_call_secs
//!
//! For example, if `10k/5` runs in 200 µs, then 1M zones · 200 µs = 200 s
//! of single-thread CPU per epoch. With a 120 s epoch the consensus tick
//! must finish inside the window, so anything > 60 s/epoch single-thread
//! is a parallelism requirement (rayon, already a dependency) or a
//! call-site refactor (per-zone subscriber index instead of global filter).
//!
//! ## What this deliberately does NOT measure
//!
//!   * Per-epoch full sweep across all zones. That's the projection
//!     formula above; benching it would just be 1M times the per-zone
//!     number. The cost model is linear by construction (no shared state
//!     across calls), so per-call × zone_count is exact.
//!   * VRF generation (`epoch::vrf_output`). Already covered by epoch
//!     tests; the input here is a pre-computed 32-byte VRF.
//!   * Subscription-set lookup (`zone_subscriptions::subscribers`). That's
//!     a HashMap lookup once per zone — orthogonal to selection.
//!
//! Run subset:
//!     cargo bench --bench bench_committee_selection
//!     cargo bench --bench bench_committee_selection committee_selection/10k_5
//!
//! @spec Protocol §11.12 (mainnet scale target) — an internal audit Gap 5

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::collections::HashSet;

use elara_runtime::network::consensus::{
    select_epoch_committee_scoped, select_epoch_committee_scoped_indexed,
    CommitteeSelectionIndex, MAINNET_COMMITTEE_SIZE, MIN_SCOPED_ELIGIBLE,
};
use elara_runtime::network::zone_committee::select_committee_v2;
use elara_runtime::ZoneId;

/// Build a deterministic synthetic stake set of `n` accounts. Stakes are
/// non-uniform so the priority sort isn't a degenerate equal-weight case.
fn synth_stakers(n: usize) -> Vec<(String, u64)> {
    (0..n)
        .map(|i| {
            let id = format!("{:064x}", i as u128);
            // Power-law-ish distribution: most accounts small, a few large.
            // Mirrors realistic stake skew without needing real ledger data.
            let stake = 1_000 + (i as u64).wrapping_mul(7919) % 100_000;
            (id, stake)
        })
        .collect()
}

/// Pick `m` subscribers from a staker pool of size `n` deterministically.
/// Uses a stride to avoid clustering at the front of the identity space.
fn synth_subscribers(stakers: &[(String, u64)], m: usize) -> HashSet<String> {
    let n = stakers.len();
    if m >= n {
        return stakers.iter().map(|(id, _)| id.clone()).collect();
    }
    let stride = (n / m).max(1);
    (0..m).map(|i| stakers[i * stride].0.clone()).collect()
}

/// Synthesize a 32-byte VRF output. Real VRFs are random per-zone-per-epoch;
/// the bench just needs a non-empty buffer to exercise the SHA3 path.
fn synth_vrf() -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(31).wrapping_add(7);
    }
    out
}

fn bench_committee_selection(c: &mut Criterion) {
    let mut group = c.benchmark_group("committee_selection");

    // (stakers, subscribers_per_zone, label)
    let scenarios: &[(usize, usize, &str)] = &[
        (6, 6, "6_6_testnet"),
        (100, 5, "100_5"),
        (1_000, 5, "1k_5"),
        (10_000, 5, "10k_5_mainnet"),
        (100_000, 5, "100k_5_interplanetary"),
        (10_000, 50, "10k_50"),
        (10_000, 2, "10k_2_bootstrap_fallback"),
        (10_000, 100, "10k_100_sortition"),
    ];

    let vrf = synth_vrf();
    let zone = ZoneId::from_legacy(42);

    for (stakers_n, subs_m, label) in scenarios {
        let stakers = synth_stakers(*stakers_n);
        let subs = synth_subscribers(&stakers, *subs_m);

        // Throughput as "calls/sec" — directly comparable to required
        // 1M zones / epoch_secs to see if the budget closes.
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::from_parameter(label),
            &(stakers, subs),
            |b, (stakers, subs)| {
                b.iter(|| {
                    let committee = select_epoch_committee_scoped(
                        &vrf,
                        stakers.as_slice(),
                        &zone,
                        subs,
                    );
                    std::hint::black_box(committee.len())
                });
            },
        );
    }
    group.finish();

    // Indexed variant — `CommitteeSelectionIndex` built once, per-zone
    // selection is O(|subs|) instead of O(|staked|). Demonstrates the
    // 100k interplanetary tier closure: the dense-pool 100k/5 case
    // drops from a 3.4 ms scan to a handful of µs.
    let mut idx_group = c.benchmark_group("committee_selection_indexed");
    for (stakers_n, subs_m, label) in scenarios {
        let stakers = synth_stakers(*stakers_n);
        let subs = synth_subscribers(&stakers, *subs_m);
        let index = CommitteeSelectionIndex::build(&stakers);

        idx_group.throughput(Throughput::Elements(1));
        idx_group.bench_with_input(
            BenchmarkId::from_parameter(label),
            &(index, subs),
            |b, (index, subs)| {
                b.iter(|| {
                    let committee = select_epoch_committee_scoped_indexed(
                        &vrf,
                        index,
                        &zone,
                        subs,
                    );
                    std::hint::black_box(committee.len())
                });
            },
        );
    }
    idx_group.finish();

    // Gap 5 Phase 6b second slice (an internal audit) — v2 bench
    // arm. Mirrors `committee_selection_indexed` but routes through
    // `select_committee_v2`, the unified algorithm that will replace
    // the v1 indexed path once `use_committee_v2` flips on. The
    // per-call cost shape matters: v2 does its own filter+materialize
    // of `(id, stake)` from the candidate vec (no shared
    // CommitteeSelectionIndex reuse), so the caller-side allocation
    // shows up here, not amortized.
    //
    // At the call site (`epoch.rs:4332`) the v2 branch materializes a
    // `Vec<(String, u64)>` eligible pool by intersecting subs ∩
    // staked_index, applies the MIN_SCOPED_ELIGIBLE bootstrap
    // fallback, and passes the pool down. We replicate the same
    // shape here so the bench number is comparable to the indexed
    // arm above.
    let mut v2_group = c.benchmark_group("committee_selection_v2");
    for (stakers_n, subs_m, label) in scenarios {
        let stakers = synth_stakers(*stakers_n);
        let subs = synth_subscribers(&stakers, *subs_m);
        let index = CommitteeSelectionIndex::build(&stakers);
        let zone_path = zone.to_string();

        v2_group.throughput(Throughput::Elements(1));
        v2_group.bench_with_input(
            BenchmarkId::from_parameter(label),
            &(index, subs, zone_path),
            |b, (index, subs, zone_path)| {
                b.iter(|| {
                    // Replicate the call-site shape from epoch.rs:4332:
                    // build the eligible pool from the index, apply
                    // bootstrap fallback, then run v2.
                    let eligible: Vec<(String, u64)> = subs
                        .iter()
                        .filter_map(|id| {
                            index
                                .staked_index
                                .get(id)
                                .map(|stake| (id.clone(), *stake))
                        })
                        .collect();
                    let pool: Vec<(String, u64)> = if eligible.len() < MIN_SCOPED_ELIGIBLE {
                        index.bootstrap_pool.clone()
                    } else {
                        eligible
                    };
                    let committee = select_committee_v2(
                        &vrf,
                        zone_path,
                        &pool,
                        MAINNET_COMMITTEE_SIZE,
                    );
                    std::hint::black_box(committee.len())
                });
            },
        );
    }
    v2_group.finish();
}

// ─── Per-epoch projection log (one-shot, not a perf measurement) ───────────
//
// Runs once at startup so operators see the zone_count × per_call number
// in the bench log. Per-call cost is filled in by the criterion group
// above; here we just print the projection formula and the budget
// threshold at the audit's 120 s epoch SLA.

fn print_projection_table(_c: &mut Criterion) {
    eprintln!();
    eprintln!("[committee_selection_projection]");
    eprintln!(
        "  Formula: per_epoch_cpu_secs = zone_count × per_call_secs"
    );
    eprintln!(
        "  Budget @ 120 s epoch (single-thread): per_call_secs ≤ 120 / zone_count"
    );
    eprintln!("  Reference points:");
    eprintln!("    1k zones    → per_call ≤ 120 ms      (trivially met)");
    eprintln!("    10k zones   → per_call ≤ 12 ms       (still very loose)");
    eprintln!("    100k zones  → per_call ≤ 1.2 ms");
    eprintln!("    1M zones    → per_call ≤ 120 µs       ← Protocol §11.12 target");
    eprintln!("    1M zones, 4-thread parallel → per_call ≤ 480 µs");
    eprintln!("    1M zones, 16-thread parallel → per_call ≤ 1.92 ms");
    eprintln!();
    eprintln!("  Compare against the criterion `committee_selection/*`");
    eprintln!("  rows above to see where the parallelism bar kicks in.");
    eprintln!();
}

criterion_group!(
    benches,
    bench_committee_selection,
    print_projection_table,
);
criterion_main!(benches);
