// Native PoW timing harness — measures elara_runtime's Identity::generate_with_pow
// at a given difficulty. WASM is typically 1.5-3× slower than native for hash-heavy
// loops, so this is a lower-bound estimate of the account's user-facing latency.
//
// Usage:
//   cargo run --release --example pow_timing -- [samples=10] [difficulty=16]
//
// Backs the 60-second identity-generation UX budget. The browser-node account
// calls generate_identity(16); prior to MIN_POW_DIFFICULTY=16 in
// browser-node/src/signing.rs the WASM clamped the request up to 20 bits,
// blowing the 60-second budget by 16×.

use elara_runtime::identity::{CryptoProfile, EntityType, Identity};
use std::time::Instant;

fn main() {
    let n: usize = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(10);
    let diff: u8 = std::env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(16);
    let mut samples = Vec::with_capacity(n);

    eprintln!(
        "Sampling {} identity generations at difficulty={} (native, single-thread) ...",
        n, diff
    );
    for i in 0..n {
        let t0 = Instant::now();
        let id =
            Identity::generate_with_pow(EntityType::Human, CryptoProfile::ProfileB, diff)
                .expect("generate failed");
        let dt = t0.elapsed();
        samples.push(dt);
        eprintln!(
            "  sample {:2}: {:7.3} ms  nonce={:>10}",
            i + 1,
            dt.as_secs_f64() * 1000.0,
            id.pow_nonce
        );
    }
    samples.sort();
    let p50 = samples[n / 2].as_secs_f64() * 1000.0;
    let p95 = samples[(n * 95 / 100).min(n - 1)].as_secs_f64() * 1000.0;
    let max = samples[n - 1].as_secs_f64() * 1000.0;
    let avg: f64 = samples.iter().map(|d| d.as_secs_f64()).sum::<f64>() / n as f64 * 1000.0;
    println!(
        "difficulty={} samples={} p50={:.1}ms p95={:.1}ms max={:.1}ms avg={:.1}ms",
        diff, n, p50, p95, max, avg
    );
}
