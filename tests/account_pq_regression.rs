//! L1999 — Account PQ regression test.
//!
//! Exercises the post-quantum account path end-to-end against a live
//! elara-node listener. Measures cold-handshake and warm-pooled-stream
//! latency for every read-only verb in the account SDK and asserts a
//! sane production envelope. Used as the empirical verification gate
//! for AUDIT-10 Milestone C — proves the PQ transport's account surface
//! is fast enough for interactive use.
//!
//! Default target: `127.0.0.1:9574` (local PQ TCP listener). Override
//! with `ELARA_TEST_PQ_PEER` (e.g. `<peer-host>:9573`).
//!
//! The test is `#[ignore]` because it depends on a running node — CI
//! has no live testnet fixture. Run manually when you want a fresh
//! latency report:
//!
//! ```text
//! cargo test --features node --test wallet_pq_regression \
//!     -- --ignored --nocapture
//! ```
//!
//! Acceptance envelope (mainnet floor — phone-tier hardware):
//!   - cold p100 (handshake + verb)  ≤  2_000 ms
//!   - warm p50   (pooled verb)      ≤    150 ms
//!   - warm p95                       ≤    500 ms
//!
//! Looser than the developer-LAN actuals (warm p50 ~10–30 ms) so this
//! gate stays meaningful for slower foundation-testnet boxes too.

#![cfg(feature = "node")]

use std::sync::Arc;
use std::time::{Duration, Instant};

use elara_runtime::pq_client_sdk::{dilithium3_keypair, raw_client, PinStore, AccountClient};

const DEFAULT_PEER: &str = "127.0.0.1:9574";
const WARMUP_CALLS: usize = 3;
const SAMPLE_CALLS: usize = 30;

const MAX_COLD_MS: u128 = 2_000;
const MAX_WARM_P50_MS: u128 = 150;
const MAX_WARM_P95_MS: u128 = 500;

fn target_peer() -> String {
    std::env::var("ELARA_TEST_PQ_PEER").unwrap_or_else(|_| DEFAULT_PEER.to_string())
}

fn percentile(samples: &[Duration], pct: f64) -> Duration {
    debug_assert!(!samples.is_empty(), "no samples for percentile");
    let mut sorted: Vec<Duration> = samples.to_vec();
    sorted.sort();
    let rank = ((pct / 100.0) * (sorted.len() as f64 - 1.0)).round() as usize;
    sorted[rank.min(sorted.len() - 1)]
}

struct LatencyReport {
    verb: &'static str,
    cold: Duration,
    warm: Vec<Duration>,
}

impl LatencyReport {
    fn p50(&self) -> Duration {
        percentile(&self.warm, 50.0)
    }
    fn p95(&self) -> Duration {
        percentile(&self.warm, 95.0)
    }
    fn print(&self) {
        let cold_ms = self.cold.as_millis();
        let p50_ms = self.p50().as_millis();
        let p95_ms = self.p95().as_millis();
        let p99_ms = percentile(&self.warm, 99.0).as_millis();
        let min_ms = self
            .warm
            .iter()
            .min()
            .copied()
            .unwrap_or_default()
            .as_millis();
        let max_ms = self
            .warm
            .iter()
            .max()
            .copied()
            .unwrap_or_default()
            .as_millis();
        println!(
            "[{:<14}] cold={:>5}ms  warm n={}  p50={:>4}ms  p95={:>4}ms  p99={:>4}ms  min={:>4}ms  max={:>4}ms",
            self.verb, cold_ms, self.warm.len(), p50_ms, p95_ms, p99_ms, min_ms, max_ms,
        );
    }
}

#[tokio::test]
#[ignore = "requires a live elara-node PQ listener; run with --ignored"]
async fn wallet_pq_latency_envelope() {
    let peer = target_peer();
    println!("\n=== L1999 account PQ regression ===");
    println!("peer:  {peer}");
    println!("warmup calls:  {WARMUP_CALLS}");
    println!("sample calls:  {SAMPLE_CALLS}");
    println!();

    let account = AccountClient::ephemeral().expect("mint ephemeral account");
    let identity_hex =
        "ada8575c57e1da94000000000000000000000000000000000000000000000000".to_string();
    let bogus_record_id = "00000000-0000-0000-0000-000000000000".to_string();

    let cold_start = Instant::now();
    let _ = account
        .account_proof(&peer, &identity_hex)
        .await
        .expect("first account_proof — handshake should succeed against live node");
    let cold = cold_start.elapsed();

    for _ in 0..WARMUP_CALLS {
        let _ = account.account_proof(&peer, &identity_hex).await;
    }

    let mut reports: Vec<LatencyReport> = Vec::new();

    let mut samples = Vec::with_capacity(SAMPLE_CALLS);
    for _ in 0..SAMPLE_CALLS {
        let t = Instant::now();
        let _ = account
            .account_proof(&peer, &identity_hex)
            .await
            .expect("account_proof should keep succeeding under warm pool");
        samples.push(t.elapsed());
    }
    reports.push(LatencyReport {
        verb: "account_proof",
        cold,
        warm: samples,
    });

    let mut samples = Vec::with_capacity(SAMPLE_CALLS);
    for _ in 0..SAMPLE_CALLS {
        let t = Instant::now();
        let _ = account
            .activity(&peer, &identity_hex)
            .await
            .expect("activity should succeed");
        samples.push(t.elapsed());
    }
    reports.push(LatencyReport {
        verb: "activity",
        cold: Duration::ZERO,
        warm: samples,
    });

    let mut samples = Vec::with_capacity(SAMPLE_CALLS);
    for _ in 0..SAMPLE_CALLS {
        let t = Instant::now();
        let _ = account.seal_progress(&peer, &bogus_record_id).await;
        samples.push(t.elapsed());
    }
    reports.push(LatencyReport {
        verb: "seal_progress",
        cold: Duration::ZERO,
        warm: samples,
    });

    let (status_pk, status_sk) = dilithium3_keypair().expect("mint identity for raw client");
    let raw = raw_client(status_pk, status_sk, Arc::new(PinStore::in_memory()));
    let _ = raw
        .get_status(&peer)
        .await
        .expect("first get_status should succeed");
    let mut samples = Vec::with_capacity(SAMPLE_CALLS);
    for _ in 0..SAMPLE_CALLS {
        let t = Instant::now();
        let _ = raw
            .get_status(&peer)
            .await
            .expect("get_status should keep succeeding");
        samples.push(t.elapsed());
    }
    reports.push(LatencyReport {
        verb: "status",
        cold: Duration::ZERO,
        warm: samples,
    });

    println!();
    for r in &reports {
        r.print();
    }
    println!();

    let primary = &reports[0];
    assert!(
        primary.cold.as_millis() <= MAX_COLD_MS,
        "cold latency {} ms exceeds {} ms — handshake regressed",
        primary.cold.as_millis(),
        MAX_COLD_MS,
    );

    for r in &reports {
        let p50_ms = r.p50().as_millis();
        let p95_ms = r.p95().as_millis();
        assert!(
            p50_ms <= MAX_WARM_P50_MS,
            "{} warm p50 {} ms exceeds {} ms — pooled verb regressed",
            r.verb,
            p50_ms,
            MAX_WARM_P50_MS,
        );
        assert!(
            p95_ms <= MAX_WARM_P95_MS,
            "{} warm p95 {} ms exceeds {} ms — tail regressed",
            r.verb,
            p95_ms,
            MAX_WARM_P95_MS,
        );
    }

    println!("L1999 acceptance envelope MET on {peer}");
}
