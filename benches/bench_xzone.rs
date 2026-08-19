//! Gap 2 cross-zone settlement scale benchmark — closes the "test +
//! benchmark + deploy" closure rule for Cross-Zone Atomic Settlement
//! (internal design notes). Unit tests covered correctness; this
//! supplies the scale number behind the operator surface so the asserts
//! become budgets, not wishes.
//!
//! ## What this measures
//!
//! Three call surfaces dominate the cross-zone hot path:
//!
//! 1. **Operator-surface gauges** (`/metrics` scrape):
//!    `oldest_locked_age_secs`, `locked_past_expiry_count`,
//!    `sealed_locked_past_expiry_count`, `pending_abort_candidates`. All
//!    iterate `CrossZoneState::pending.values()` — cost is
//!    O(|active_pending|). Scrape interval is typically 15 s; at the 1M-zone
//!    Protocol §11.12 target, a large in-flight pending set (e.g. during a
//!    zone-B partition) makes every scrape pay this scan four times.
//!
//! 2. **Active recovery hot-path** (`epoch.rs:4478` "Gap 2 sealed-abort P-3d
//!    producer-side abort-witness emitter"): `pending_abort_candidates`
//!    runs on every epoch tick on every B-committee witness — at 120 s
//!    adaptive epoch the scan must stay well under epoch budget.
//!
//! 3. **Passive recovery hot-path** (`accounting::ledger::apply_op`):
//!    `process_expired` runs every epoch tick on the source-zone apply path
//!    and walks every pending transfer — must scale to large pending sets
//!    without dominating epoch CPU.
//!
//! ## Per-op cost (sanity floor)
//!
//! Per-op `lock_transfer` / `set_proof` / `abort_transfer` are O(1) HashMap
//! mutations and should land sub-µs at any pending size. Drift on these
//! would signal a regression in the hot path (e.g. accidental linear scan
//! added to `lock_transfer`).
//!
//! ## Scenarios
//!
//! Pending sizes: `1k`, `10k`, `100k`, `1M`. The mid-incident shape is "50%
//! sealed / 50% past-expiry" — the realistic worst case for the alarm gauge
//! `sealed_locked_past_expiry_count` (OPS-56). Process-expired uses the
//! pure "100% unsealed + 100% expired" shape for its own worst case (every
//! pending entry is a refund candidate).
//!
//! ## Projecting to 1M zones
//!
//! At 1M zones with N pending xzone transfers cluster-wide and per-scrape
//! cost C, scrape CPU budget = `4 × C`. Target: < 100 ms per scrape on a
//! single core. Compare against the criterion rows below.

use criterion::{
    criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput,
};

use elara_runtime::crypto::hash::sha3_256;
use elara_runtime::accounting::cross_zone::{
    CrossZoneState, ProofSibling, CLAIM_TIMEOUT_SECS,
};
use elara_runtime::ZoneId;

/// Build a CrossZoneState pre-populated with `n` Locked transfers.
///
/// `sealed_frac` of them are sealed (`set_proof` + `set_finality_witnesses`
/// with epoch=1, committee_size=1, empty signer vec — the gauge scans only
/// check `merkle_proof.is_empty()` / `source_seal_epoch == 0`, not the
/// signatures themselves).
///
/// `expired_frac` of them have a lock timestamp older than
/// `CLAIM_TIMEOUT_SECS` so they show up in past-expiry gauges and the
/// abort-candidate scan.
fn build_state(n: usize, sealed_frac: f64, expired_frac: f64) -> CrossZoneState {
    let mut state = CrossZoneState::new();
    let now = 1_000_000.0_f64;
    let expired_lock_ts = now - CLAIM_TIMEOUT_SECS - 100.0;
    let active_lock_ts = now - 10.0;

    let source_zone = ZoneId::new("bench/source");
    let dest_zone = ZoneId::new("bench/dest");

    let sealed_cutoff = ((n as f64) * sealed_frac) as usize;
    let expired_cutoff = ((n as f64) * expired_frac) as usize;

    for i in 0..n {
        let id = format!("bench-tx-{:08}", i);
        let sender = format!("alice-{}", i % 100);
        let recipient = format!("bob-{}", i % 100);
        let leaf = sha3_256(id.as_bytes());
        let lock_ts = if i < expired_cutoff { expired_lock_ts } else { active_lock_ts };

        state
            .lock_transfer(
                id.clone(),
                sender,
                recipient,
                100,
                source_zone.clone(),
                dest_zone.clone(),
                lock_ts,
                leaf,
            )
            .unwrap();

        if i < sealed_cutoff {
            // Flip "sealed" without a real Merkle root — the gauge scans only
            // check emptiness of `merkle_proof` and `source_seal_epoch > 0`,
            // not proof validity. claim_transfer would reject this (bad
            // proof + missing sigs) but abort_transfer / gauges accept it.
            let root = sha3_256(b"bench-root");
            let proof = vec![ProofSibling { hash: [0u8; 32], is_right: true }];
            state.set_proof(&id, proof, root).unwrap();
            state.set_finality_witnesses(&id, vec![], [0u8; 32], 1, 1).unwrap();
        }
    }
    state
}

/// Operator-surface gauges — every Prometheus scrape pays each of these
/// linearly in the active pending count.
fn bench_xzone_gauges(c: &mut Criterion) {
    let mut group = c.benchmark_group("xzone_gauges");
    let now = 1_000_000.0_f64;
    let dest_zone = ZoneId::new("bench/dest");

    // 50% sealed + 50% expired: realistic mid-incident shape. The first
    // 50% of indices are expired (so they overlap with the first 50%
    // sealed) — that produces ~50% sealed-and-expired, the exact subset
    // `sealed_locked_past_expiry_count` (OPS-56) and
    // `pending_abort_candidates` both scan.
    for &n in &[1_000usize, 10_000, 100_000, 1_000_000] {
        let state = build_state(n, 0.5, 0.5);

        group.throughput(Throughput::Elements(n as u64));

        group.bench_with_input(
            BenchmarkId::new("oldest_locked_age_secs", n),
            &state,
            |b, state| {
                b.iter(|| std::hint::black_box(state.oldest_locked_age_secs(now)));
            },
        );
        group.bench_with_input(
            BenchmarkId::new("locked_past_expiry_count", n),
            &state,
            |b, state| {
                b.iter(|| std::hint::black_box(state.locked_past_expiry_count(now)));
            },
        );
        group.bench_with_input(
            BenchmarkId::new("sealed_locked_past_expiry_count_OPS56", n),
            &state,
            |b, state| {
                b.iter(|| {
                    std::hint::black_box(state.sealed_locked_past_expiry_count(now))
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("pending_abort_candidates", n),
            &state,
            |b, state| {
                b.iter(|| {
                    std::hint::black_box(
                        state.pending_abort_candidates(&dest_zone, now).len(),
                    )
                });
            },
        );
    }
    group.finish();
}

/// Per-op cost — should stay sub-µs and flat across pending size. A
/// regression here means a linear scan slipped into a HashMap operation.
fn bench_xzone_per_op(c: &mut Criterion) {
    let mut group = c.benchmark_group("xzone_per_op");

    // Run at two pending sizes: 1k (fits in L1 + a HashMap that's still
    // tight) and 100k (HashMap that won't fit cache — confirms ops are
    // genuinely O(1) and not "fast because everything is hot").
    for &n in &[1_000usize, 100_000] {
        // ── lock_transfer: insert into HashMap ────────────────────────
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::new("lock_transfer", n),
            &n,
            |b, &n| {
                let source = ZoneId::new("bench/source");
                let dest = ZoneId::new("bench/dest");
                b.iter_batched(
                    || (build_state(n, 0.0, 0.0), 0usize),
                    |(mut state, mut counter)| {
                        let id = format!("bench-new-{:08}", n + counter);
                        let leaf = sha3_256(id.as_bytes());
                        state
                            .lock_transfer(
                                id,
                                "alice".into(),
                                "bob".into(),
                                100,
                                source.clone(),
                                dest.clone(),
                                1_000_000.0,
                                leaf,
                            )
                            .unwrap();
                        counter += 1;
                        std::hint::black_box((state, counter));
                    },
                    BatchSize::SmallInput,
                );
            },
        );

        // ── set_proof: HashMap lookup + field-write ───────────────────
        group.bench_with_input(
            BenchmarkId::new("set_proof", n),
            &n,
            |b, &n| {
                b.iter_batched(
                    || {
                        let state = build_state(n, 0.0, 0.0);
                        let target_id = format!("bench-tx-{:08}", n / 2);
                        (state, target_id)
                    },
                    |(mut state, target_id)| {
                        let root = sha3_256(b"bench-root");
                        let proof =
                            vec![ProofSibling { hash: [0u8; 32], is_right: true }];
                        state.set_proof(&target_id, proof, root).unwrap();
                        std::hint::black_box(state);
                    },
                    BatchSize::SmallInput,
                );
            },
        );

        // ── abort_transfer: HashMap lookup + status mutation ──────────
        group.bench_with_input(
            BenchmarkId::new("abort_transfer", n),
            &n,
            |b, &n| {
                b.iter_batched(
                    || {
                        // Pre-seal every entry so abort can fire on any id.
                        let state = build_state(n, 1.0, 0.0);
                        let target_id = format!("bench-tx-{:08}", n / 2);
                        (state, target_id)
                    },
                    |(mut state, target_id)| {
                        let _ = state.abort_transfer(&target_id).unwrap();
                        std::hint::black_box(state);
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

/// `process_expired` walks every pending transfer once per epoch tick —
/// pure O(|active_pending|). Worst case shape: 100% unsealed (so every
/// past-expiry transfer is refunded, exercising the full inner branch),
/// 100% expired.
fn bench_xzone_process_expired(c: &mut Criterion) {
    let mut group = c.benchmark_group("xzone_process_expired");
    let now = 1_000_000.0_f64;

    for &n in &[1_000usize, 10_000, 100_000] {
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(
            BenchmarkId::new("all_unsealed_expired", n),
            &n,
            |b, &n| {
                b.iter_batched(
                    || build_state(n, 0.0, 1.0),
                    |mut state| {
                        let refunds = state.process_expired(now);
                        std::hint::black_box(refunds.len());
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

fn print_projection(_c: &mut Criterion) {
    eprintln!();
    eprintln!("[xzone_scale_projection]");
    eprintln!(
        "  Operator surface gauges run on every Prometheus scrape interval"
    );
    eprintln!("  (default 15 s). Four gauges scan `pending.values()` linearly:");
    eprintln!("    oldest_locked_age_secs");
    eprintln!("    locked_past_expiry_count");
    eprintln!("    sealed_locked_past_expiry_count  (OPS-56 pager input)");
    eprintln!("    pending_abort_candidates         (epoch-tick scan too)");
    eprintln!();
    eprintln!("  Per-scrape budget: 4 × per_call_secs must be << 15 s");
    eprintln!("    Target: < 100 ms total scrape CPU on a single core.");
    eprintln!("  Per-epoch-tick budget (B-committee abort-emitter loop at");
    eprintln!(
        "    `epoch.rs:4478`): pending_abort_candidates_secs × n_witnesses"
    );
    eprintln!("    must be << adaptive_epoch_secs (~120 s default).");
    eprintln!();
    eprintln!("  Reference: at N pending and per-iter cost X ns:");
    eprintln!("    N=1k     → per_call ≈ 1000 × X ns         (trivial)");
    eprintln!("    N=10k    → per_call ≈ 10⁴ × X ns          (still loose)");
    eprintln!("    N=100k   → per_call ≈ 10⁵ × X ns");
    eprintln!("    N=1M     → per_call ≈ 10⁶ × X ns   ← scale-test boundary");
    eprintln!();
    eprintln!(
        "  Compare against the criterion `xzone_gauges/*` rows above to see"
    );
    eprintln!("  where the scrape budget starts to bind.");
    eprintln!();
}

criterion_group!(
    benches,
    bench_xzone_per_op,
    bench_xzone_gauges,
    bench_xzone_process_expired,
    print_projection,
);
criterion_main!(benches);
