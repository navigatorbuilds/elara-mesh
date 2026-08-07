//! Gap 4 auto-scaling scale benchmark — closes the "test + benchmark + deploy"
//! rule for the zone auto-scaler hot path (internal design notes §MAINNET MANDATE Gap 4).
//! Correctness was already covered by 8 unit tests in `src/network/auto_scale.rs`;
//! this supplies the per-tick CPU evidence behind the design at scale.
//!
//! ## What this measures
//!
//! Three pure-function call surfaces drive the auto-scale tick loop:
//!
//! 1. **`recommend_zone_count`** — O(zones) HashMap iteration + average.
//!    Runs on every health-tick on every node (`health.rs:589` inside
//!    `run_auto_scale_tick` via `scaler.observe`). At the §11.12 1M-zone
//!    target the activity map is at most 1M entries; in practice it tracks
//!    only zones that produced records during the sample window, but the
//!    worst case must fit one health-tick budget.
//!
//! 2. **`pick_transition_target`** — translates a `Split`/`Merge` decision
//!    into a concrete parent zone (Split → O(zones) `max`) or parent pair
//!    (Merge → O(zones log zones) sort). Runs on the genesis authority only
//!    when hysteresis fires (`health.rs:716`).
//!
//! 3. **`AutoScaler::observe`** — wrapper that bumps hysteresis counters
//!    and gates the underlying `recommend_zone_count`. Same per-tick cost
//!    as `recommend_zone_count` plus a few branch ops; benched separately
//!    so any future change to the wrapper (e.g. logging/telemetry hook)
//!    doesn't drift silently from the pure function.
//!
//! ## Why this matters
//!
//! At 1M zones × 10K nodes the auto-scaler tick fires on every node every
//! health-tick (~2 min by default). If `recommend_zone_count` at N=1M
//! costs >1 s the tick eats more than 1 % of a core per node — at fleet
//! scale that's an idle-network CPU floor of ~100 cores cluster-wide,
//! spent on a decision that's almost always "no change."
//!
//! The picker is rarer (fires only when hysteresis converges on Split or
//! Merge) and only on the genesis authority — but at 1M parent candidates
//! the sort is the binding cost. If it takes seconds, the orchestrator
//! tick blocks behind it.
//!
//! ## Scenarios
//!
//! - `N=10`     — single-VPS testnet today.
//! - `N=1000`   — early-mainnet (operator onramp in flight).
//! - `N=10000`  — 1 % of §11.12 target.
//! - `N=1000000` — full §11.12 1M-zone target. Worst case the hot path must
//!   survive.

use std::collections::HashMap;

use criterion::{
    criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput,
};

use elara_runtime::network::auto_scale::{
    pick_transition_target, recommend_zone_count, AutoScaler, ScalingDecision, TARGET_ZONE_RATE,
    SPLIT_RATE_MULTIPLIER,
};
use elara_runtime::network::zone::ZoneId;

/// Per-zone activity map populated with `n` entries. The `rate_func` callable
/// picks a per-entry rate so callers can shape the distribution (uniform hot,
/// uniform cold, balanced, mixed) without rewriting the loop.
fn build_activity<F: Fn(u64) -> f64>(n: u64, rate_func: F) -> HashMap<ZoneId, f64> {
    let mut map = HashMap::with_capacity(n as usize);
    for i in 0..n {
        map.insert(ZoneId::from_legacy(i), rate_func(i));
    }
    map
}

/// Uniform hot — every zone above the split threshold. Drives the
/// `recommend_zone_count` fast path that exits with `Split`.
fn hot_uniform(_: u64) -> f64 {
    TARGET_ZONE_RATE * SPLIT_RATE_MULTIPLIER * 4.0
}

/// Uniform balanced — every zone right at target rate. The healthy band.
/// `recommend_zone_count` returns `NoChange{Balanced}`.
fn balanced_uniform(_: u64) -> f64 {
    TARGET_ZONE_RATE
}

/// Uniform cold — every zone below the merge threshold. Drives the
/// `Merge` path.
fn cold_uniform(_: u64) -> f64 {
    0.0001
}

/// Mixed pattern — half hot, half cold. Stresses `pick_transition_target`'s
/// sort: the picker must scan all entries to find the extremes regardless
/// of skew.
fn mixed_distribution(i: u64) -> f64 {
    if i.is_multiple_of(2) {
        TARGET_ZONE_RATE * SPLIT_RATE_MULTIPLIER * 4.0
    } else {
        0.0001
    }
}

/// `recommend_zone_count` cost: HashMap iteration + arithmetic average.
/// Should be ~linear in `n`; if Criterion shows super-linear growth, the
/// f64 sum is hitting cache limits and we'd want to pre-aggregate the
/// average in `zone_activity_rate` (incremental counter pattern).
fn bench_recommend_balanced(c: &mut Criterion) {
    let mut group = c.benchmark_group("auto_scale_recommend_balanced");
    for &n in &[10u64, 1_000, 10_000, 1_000_000] {
        let activity = build_activity(n, balanced_uniform);
        group.throughput(Throughput::Elements(n));
        group.bench_with_input(BenchmarkId::new("zones", n), &n, |b, &_n| {
            b.iter(|| {
                let dec = recommend_zone_count(&activity, n / 2, 1_000_000);
                std::hint::black_box(dec);
            });
        });
    }
    group.finish();
}

/// Hot uniform: average is above split threshold. The decision path is
/// identical to balanced in cost terms (still O(n) sum); benched
/// separately to catch any future early-exit optimisation that might
/// short-circuit one but not the other.
fn bench_recommend_hot(c: &mut Criterion) {
    let mut group = c.benchmark_group("auto_scale_recommend_hot");
    for &n in &[10u64, 1_000, 10_000, 1_000_000] {
        let activity = build_activity(n, hot_uniform);
        group.throughput(Throughput::Elements(n));
        group.bench_with_input(BenchmarkId::new("zones", n), &n, |b, &_n| {
            b.iter(|| {
                let dec = recommend_zone_count(&activity, n / 2, 1_000_000);
                std::hint::black_box(dec);
            });
        });
    }
    group.finish();
}

/// `pick_transition_target` Split path: O(n) max-scan with deterministic
/// tie-break. The picker only runs on the genesis authority when
/// hysteresis converges on Split — rare in steady state but binding at
/// the moment of a real split.
fn bench_pick_split(c: &mut Criterion) {
    let mut group = c.benchmark_group("auto_scale_pick_split");
    for &n in &[10u64, 1_000, 10_000, 1_000_000] {
        let activity = build_activity(n, mixed_distribution);
        let decision = ScalingDecision::Split {
            new_count: n.saturating_mul(2).min(1_000_000),
            avg_rate: TARGET_ZONE_RATE * SPLIT_RATE_MULTIPLIER * 4.0,
        };
        group.throughput(Throughput::Elements(n));
        group.bench_with_input(BenchmarkId::new("zones", n), &n, |b, &_n| {
            b.iter(|| {
                let t = pick_transition_target(&decision, &activity);
                std::hint::black_box(t);
            });
        });
    }
    group.finish();
}

/// `pick_transition_target` Merge path: O(n log n) sort. This is the
/// binding cost of the picker at scale — the Vec::sort dominates the
/// per-element work, so if 1M shows up on the wrong side of the
/// per-tick budget the operator surface is the place to revisit
/// (e.g. partial-sort: only need the two smallest).
fn bench_pick_merge(c: &mut Criterion) {
    let mut group = c.benchmark_group("auto_scale_pick_merge");
    for &n in &[10u64, 1_000, 10_000, 1_000_000] {
        // Need ≥2 entries for Merge; n=10 already covers it.
        let activity = build_activity(n, cold_uniform);
        let decision = ScalingDecision::Merge {
            new_count: (n / 2).max(1),
            avg_rate: 0.0001,
        };
        group.throughput(Throughput::Elements(n));
        group.bench_with_input(BenchmarkId::new("zones", n), &n, |b, &_n| {
            b.iter_batched(
                || activity.clone(),
                |a| {
                    let t = pick_transition_target(&decision, &a);
                    std::hint::black_box(t);
                },
                BatchSize::LargeInput,
            );
        });
    }
    group.finish();
}

/// `AutoScaler::observe` cost — same as `recommend_zone_count` plus
/// hysteresis-counter branch ops. Benched at the cadence the loop
/// actually drives it (one observe per health-tick, no fire) so any
/// future log/metric hook lands here.
fn bench_observe(c: &mut Criterion) {
    let mut group = c.benchmark_group("auto_scale_observe_no_fire");
    for &n in &[10u64, 1_000, 10_000, 1_000_000] {
        let activity = build_activity(n, balanced_uniform);
        group.throughput(Throughput::Elements(n));
        group.bench_with_input(BenchmarkId::new("zones", n), &n, |b, &_n| {
            b.iter_batched(
                || AutoScaler::new(4, 1_000_000),
                |mut scaler| {
                    let dec = scaler.observe(&activity, n / 2);
                    std::hint::black_box(dec);
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

fn print_projection(_c: &mut Criterion) {
    eprintln!();
    eprintln!("[auto_scale_scale_projection]");
    eprintln!("  Protocol §11.12 target: 1M zones, 10K+ nodes.");
    eprintln!("  Auto-scale tick cadence: per health-tick (~2 min default).");
    eprintln!();
    eprintln!("  Per-tick per-node cost: recommend_zone_count(N=1M) × 1");
    eprintln!("  Compare against the auto_scale_recommend_* rows.");
    eprintln!("  Target ceiling: <100 ms (0.08% of one core at 120 s tick).");
    eprintln!();
    eprintln!("  Picker cost (Split/Merge fire, genesis only):");
    eprintln!("  Compare auto_scale_pick_split/merge at N=1M against the");
    eprintln!("  health-tick budget (~120 s). Even 100 ms is <0.1% of tick.");
    eprintln!();
    eprintln!("  Cluster-wide steady-state CPU:");
    eprintln!("  recommend_zone_count(N=1M) × 10K nodes × 1 tick / 120 s");
    eprintln!("  If recommend@1M is 50 ms, cluster CPU = 4.2 cores sustained.");
    eprintln!("  If 500 ms, cluster CPU = 42 cores — operator-visible.");
    eprintln!();
    eprintln!("  Mitigation if the bench shows >100 ms at 1M:");
    eprintln!("  - Maintain an incremental avg_rate counter in EpochState");
    eprintln!("    so the per-tick cost becomes O(1) (SCALE RULE: never");
    eprintln!("    rebuild what you can update).");
    eprintln!("  - Cap the activity map size and sample the long tail.");
    eprintln!();
}

criterion_group!(
    benches,
    bench_recommend_balanced,
    bench_recommend_hot,
    bench_pick_split,
    bench_pick_merge,
    bench_observe,
    print_projection,
);
criterion_main!(benches);
