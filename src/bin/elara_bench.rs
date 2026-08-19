//! elara-bench — Performance benchmark for elara-node
//!
//! Measures TPS (transfers/sec) and finality latency (P50/P95/P99) against
//! a running node. Also verifies conservation invariant across fleet.
//!
//! Usage:
//!   cargo run --features node --bin elara-bench
//!   cargo run --features node --bin elara-bench -- --transfers 200 --target http://127.0.0.1:9474
//!   cargo run --features node --bin elara-bench -- --mode finality --poll-secs 300

use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::Parser;
use tokio::sync::Mutex as AsyncMutex;

#[derive(Parser)]
#[command(name = "elara-bench", version, about = "Elara network performance benchmark")]
struct Cli {
    /// Target node URL.
    #[arg(long, default_value = "http://127.0.0.1:9474")]
    target: String,

    /// Admin token for RPC auth (set to your node's configured token).
    #[arg(long, default_value = "changeme")]
    admin_token: String,

    /// Recipient identity hash (transfers go here). If empty, uses genesis authority from /status.
    #[arg(long, default_value = "")]
    to: String,

    /// Number of transfers to send.
    #[arg(long, default_value = "100")]
    transfers: usize,

    /// Amount per transfer in nano-beat (default 1 = 0.000000001 beat).
    #[arg(long, default_value = "1")]
    amount: u64,

    /// Max seconds to poll for finality after all transfers sent.
    #[arg(long, default_value = "600")]
    poll_secs: u64,

    /// Poll interval in seconds when tracking finality.
    #[arg(long, default_value = "5")]
    poll_interval: u64,

    /// Benchmark mode: "tps" (transfers only), "finality" (transfers + track settlement),
    /// "conservation" (check invariant across nodes), "full" (all),
    /// "microscope" (Gap 8 — fine-grained /seal/progress timeline for a single transfer),
    /// "sustained" (paced-RPS soak — runs for --duration-secs, samples health/latency
    /// every --sample-secs, optional --csv, breaks on --break-on-error-rate).
    #[arg(long, default_value = "full")]
    mode: String,

    /// Microscope-mode poll interval in milliseconds. 100ms by default so a
    /// 5s-floor epoch produces ≥50 samples in the send→Sealed window.
    #[arg(long, default_value = "100")]
    micro_poll_ms: u64,

    /// Microscope-mode timeout in seconds (per transfer).
    #[arg(long, default_value = "180")]
    micro_timeout_secs: u64,

    /// PQ listen address (`host:port`) for 4E.3 streaming microscope. When set
    /// AND mode=microscope, the bench subscribes to `seal_progress_stream`
    /// over the PQ transport (port 9475 / 9573 depending on the node) instead
    /// of polling HTTPS `/seal/progress/{id}`. Leave empty to keep HTTPS poll.
    #[arg(long, default_value = "")]
    pq_target: String,

    /// Comma-separated node URLs for conservation check.
    #[arg(long, default_value = "https://127.0.0.1:9474")]
    nodes: String,

    /// Concurrency: number of parallel transfer requests.
    #[arg(long, default_value = "1")]
    concurrency: usize,

    /// Sustained-mode target rate in transfers/second (float). Sender paces
    /// every 1/rate seconds; if send latency exceeds the interval the error
    /// rate climbs — that's the breaking-point signal.
    #[arg(long, default_value = "1.0")]
    rate: f64,

    /// Sustained-mode total duration in seconds. Default 3600 = 1 hour.
    /// Multi-hour soak: pass `--duration-secs 14400` for 4h.
    #[arg(long, default_value = "3600")]
    duration_secs: u64,

    /// Sustained-mode health sample interval in seconds. Every tick prints a
    /// rolling P50/P95/P99 + error rate + /status snapshot (rss_mb, peers,
    /// settled_count, finalized_count).
    #[arg(long, default_value = "30")]
    sample_secs: u64,

    /// Sustained-mode optional CSV output path. One header line + one line per
    /// sample tick. Empty = no CSV (prints to stdout only).
    #[arg(long, default_value = "")]
    csv: String,

    /// Sustained-mode abort threshold: stop early if rolling error rate
    /// (computed per sample window) exceeds this fraction. 0 = never abort.
    #[arg(long, default_value = "0.25")]
    break_on_error_rate: f64,
}

#[derive(Debug, Clone)]
struct TransferResult {
    record_id: String,
    send_time: Instant,
    send_latency: Duration,
    settled_at: Option<Instant>,
    finalized_at: Option<Instant>,
    confirmation: String,
}

fn main() {
    let cli = Cli::parse();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| {
            eprintln!("fatal: cannot build async runtime: {e}");
            std::process::exit(1);
        });
    rt.block_on(run(cli));
}

async fn run(cli: Cli) {
    println!("=== elara-bench ===");
    println!("target: {}", cli.target);
    println!("mode:   {}", cli.mode);
    println!();

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .danger_accept_invalid_certs(true) // testnet self-signed certs
        .build()
        .unwrap_or_else(|e| {
            eprintln!("fatal: cannot build HTTP client: {e}");
            std::process::exit(1);
        });

    // Resolve recipient
    let to = if cli.to.is_empty() {
        let status = fetch_status(&client, &cli.target).await;
        let genesis = status["genesis_authority"].as_str().unwrap_or("").to_string();
        if genesis.is_empty() {
            eprintln!("ERROR: could not get genesis_authority from /status");
            std::process::exit(1);
        }
        // Don't send to self — get identity and pick the other
        let self_id = status["identity_hash"].as_str().unwrap_or("");
        if self_id == genesis {
            // We ARE genesis, pick first seed peer identity or a known one
            eprintln!("WARNING: target node IS genesis authority — transfers will be self-sends (still valid for TPS measurement)");
        }
        genesis
    } else {
        cli.to.clone()
    };

    println!("recipient: {}...{}", &to[..8], &to[to.len()-8..]);

    let do_microscope = cli.mode == "microscope";
    let do_sustained = cli.mode == "sustained";
    let do_tps = !do_microscope && !do_sustained && (cli.mode == "tps" || cli.mode == "full");
    let do_finality = !do_microscope && !do_sustained && (cli.mode == "finality" || cli.mode == "full");
    let do_conservation = !do_microscope && !do_sustained && (cli.mode == "conservation" || cli.mode == "full");

    // ── Microscope: Gap 8 send→Sealed→Finalized sub-second timeline ──────
    if do_microscope {
        if !cli.pq_target.is_empty() {
            run_microscope_pq(&client, &cli, &to).await;
        } else {
            run_microscope(&client, &cli, &to).await;
        }
        println!("\n=== done ===");
        return;
    }

    // ── Sustained: paced-RPS multi-hour soak ──
    if do_sustained {
        run_sustained(&client, &cli, &to).await;
        println!("\n=== done ===");
        return;
    }

    let mut results: Vec<TransferResult> = Vec::new();

    // ── Phase 1: TPS — send transfers as fast as possible ────────────────
    if do_tps || do_finality {
        println!("\n--- Phase 1: TPS ({} transfers, concurrency={}) ---", cli.transfers, cli.concurrency);

        let start = Instant::now();

        if cli.concurrency <= 1 {
            // Sequential
            for i in 0..cli.transfers {
                let send_start = Instant::now();
                match send_transfer(&client, &cli.target, &cli.admin_token, &to, cli.amount).await {
                    Ok(record_id) => {
                        let latency = send_start.elapsed();
                        if (i + 1) % 10 == 0 || i == 0 {
                            println!("  [{}/{}] {} ({:.0}ms)", i + 1, cli.transfers, &record_id[..16], latency.as_millis());
                        }
                        results.push(TransferResult {
                            record_id,
                            send_time: send_start,
                            send_latency: latency,
                            settled_at: None,
                            finalized_at: None,
                            confirmation: "Pending".to_string(),
                        });
                    }
                    Err(e) => {
                        eprintln!("  [{}/{}] FAILED: {}", i + 1, cli.transfers, e);
                    }
                }
            }
        } else {
            // Parallel batches
            let mut sent = 0usize;
            while sent < cli.transfers {
                let batch_size = std::cmp::min(cli.concurrency, cli.transfers - sent);
                let mut handles = Vec::new();
                for _ in 0..batch_size {
                    let c = client.clone();
                    let target = cli.target.clone();
                    let token = cli.admin_token.clone();
                    let to_clone = to.clone();
                    let amount = cli.amount;
                    handles.push(tokio::spawn(async move {
                        let t = Instant::now();
                        let r = send_transfer(&c, &target, &token, &to_clone, amount).await;
                        (t, t.elapsed(), r)
                    }));
                }
                for h in handles {
                    if let Ok((send_time, latency, result)) = h.await {
                        sent += 1;
                        match result {
                            Ok(record_id) => {
                                if sent.is_multiple_of(10) || sent == 1 {
                                    println!("  [{}/{}] {} ({:.0}ms)", sent, cli.transfers, &record_id[..16], latency.as_millis());
                                }
                                results.push(TransferResult {
                                    record_id,
                                    send_time,
                                    send_latency: latency,
                                    settled_at: None,
                                    finalized_at: None,
                                    confirmation: "Pending".to_string(),
                                });
                            }
                            Err(e) => {
                                eprintln!("  [{}/{}] FAILED: {}", sent, cli.transfers, e);
                            }
                        }
                    }
                }
            }
        }

        let elapsed = start.elapsed();
        let succeeded = results.len();
        let tps = if elapsed.as_secs_f64() > 0.0 {
            succeeded as f64 / elapsed.as_secs_f64()
        } else {
            0.0
        };

        println!("\n  Sent: {}/{} succeeded in {:.1}s", succeeded, cli.transfers, elapsed.as_secs_f64());
        println!("  TPS (insertion): {:.2}", tps);

        // Send latency stats
        if !results.is_empty() {
            let mut latencies: Vec<f64> = results.iter().map(|r| r.send_latency.as_secs_f64() * 1000.0).collect();
            latencies.sort_by(|a, b| a.total_cmp(b));
            let p50 = percentile(&latencies, 50.0);
            let p95 = percentile(&latencies, 95.0);
            let p99 = percentile(&latencies, 99.0);
            println!("  Send latency: P50={:.0}ms P95={:.0}ms P99={:.0}ms", p50, p95, p99);
        }
    }

    // ── Phase 2: Finality — poll until records settle ────────────────────
    if do_finality && !results.is_empty() {
        println!("\n--- Phase 2: Finality tracking ({} records, timeout={}s) ---", results.len(), cli.poll_secs);
        println!("  Polling source + fleet nodes for confirmation status");

        let poll_start = Instant::now();
        let poll_interval = Duration::from_secs(cli.poll_interval);
        let timeout = Duration::from_secs(cli.poll_secs);

        // Poll the target only. The hardcoded VPS poll set died with the
        // 2026-06-09 fleet decommission; finality confirmation across other
        // nodes needs explicit targets, not baked-in dead endpoints.
        let poll_nodes: Vec<String> = vec![cli.target.clone()];

        loop {
            if poll_start.elapsed() > timeout {
                println!("  TIMEOUT after {}s", cli.poll_secs);
                break;
            }

            let pending: Vec<usize> = results.iter().enumerate()
                .filter(|(_, r)| r.settled_at.is_none())
                .map(|(i, _)| i)
                .collect();

            if pending.is_empty() {
                println!("  All {} records settled!", results.len());
                break;
            }

            // Poll a batch of pending records across all reachable nodes
            let batch: Vec<(usize, String)> = pending.iter().take(20)
                .map(|&i| (i, results[i].record_id.clone()))
                .collect();
            let mut settled_this_round = 0usize;
            let mut finalized_this_round = 0usize;
            let mut max_att_count = 0usize;

            for (idx, rid) in &batch {
                let idx = *idx;
                // Check all nodes — take the best confirmation level found
                for node_url in &poll_nodes {
                    if let Ok(info) = fetch_record(&client, node_url, rid).await {
                        let att = info["attestation_count"].as_u64().unwrap_or(0) as usize;
                        if att > max_att_count { max_att_count = att; }

                        let level = info["confirmation_level"].as_str().unwrap_or("pending");
                        let is_finalized = info["finalized"].as_bool().unwrap_or(false);

                        let is_settled = level == "settled" || level == "Settled"
                            || level == "finalized" || level == "Finalized"
                            || level == "anchored" || level == "Anchored"
                            || is_finalized;

                        if is_settled && results[idx].settled_at.is_none() {
                            results[idx].settled_at = Some(Instant::now());
                            results[idx].confirmation = level.to_string();
                            settled_this_round += 1;
                        }
                        if is_finalized && results[idx].finalized_at.is_none() {
                            results[idx].finalized_at = Some(Instant::now());
                            finalized_this_round += 1;
                        }
                        // Once settled, no need to check more nodes
                        if results[idx].settled_at.is_some() {
                            break;
                        }
                    }
                }
            }

            let total_settled = results.iter().filter(|r| r.settled_at.is_some()).count();
            let total_finalized = results.iter().filter(|r| r.finalized_at.is_some()).count();
            let elapsed = poll_start.elapsed().as_secs();

            println!("  [{}s] settled={}/{} finalized={}/{} (+{}/+{} this round, max_att={})",
                elapsed, total_settled, results.len(), total_finalized, results.len(),
                settled_this_round, finalized_this_round, max_att_count);

            if total_settled == results.len() {
                break;
            }

            tokio::time::sleep(poll_interval).await;
        }

        // Finality latency stats (time from send to settlement detection)
        let settlement_latencies: Vec<f64> = results.iter()
            .filter_map(|r| r.settled_at.map(|s| s.duration_since(r.send_time).as_secs_f64()))
            .collect();

        if !settlement_latencies.is_empty() {
            let mut lats = settlement_latencies.clone();
            lats.sort_by(|a, b| a.total_cmp(b));
            println!("\n  Finality latency (send → settlement detection):");
            println!("    P50:  {:.1}s", percentile(&lats, 50.0));
            println!("    P95:  {:.1}s", percentile(&lats, 95.0));
            println!("    P99:  {:.1}s", percentile(&lats, 99.0));
            println!("    min:  {:.1}s", lats.first().copied().unwrap_or(0.0));
            println!("    max:  {:.1}s", lats.last().copied().unwrap_or(0.0));
            println!("    settled: {}/{}", settlement_latencies.len(), results.len());
        } else {
            println!("\n  No records reached settlement within timeout.");
        }

        let finalization_latencies: Vec<f64> = results.iter()
            .filter_map(|r| r.finalized_at.map(|f| f.duration_since(r.send_time).as_secs_f64()))
            .collect();
        if !finalization_latencies.is_empty() {
            let mut lats = finalization_latencies.clone();
            lats.sort_by(|a, b| a.total_cmp(b));
            println!("\n  Finalization latency (send → finalized index):");
            println!("    P50:  {:.1}s", percentile(&lats, 50.0));
            println!("    P95:  {:.1}s", percentile(&lats, 95.0));
            println!("    P99:  {:.1}s", percentile(&lats, 99.0));
            println!("    finalized: {}/{}", finalization_latencies.len(), results.len());
        }
    }

    // ── Phase 3: Conservation check across fleet ─────────────────────────
    if do_conservation {
        println!("\n--- Phase 3: Conservation check ---");
        let node_urls: Vec<&str> = cli.nodes.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();

        let mut supplies: Vec<(String, String)> = Vec::new();
        for url in &node_urls {
            match fetch_ledger_summary(&client, url).await {
                Ok(summary) => {
                    let supply = summary["total_supply_beat_precise"]
                        .as_str()
                        .unwrap_or("?")
                        .to_string();
                    let name = url.split("//").nth(1).unwrap_or(url);
                    println!("  {} — supply: {} beat", name, supply);
                    supplies.push((name.to_string(), supply));
                }
                Err(e) => {
                    let name = url.split("//").nth(1).unwrap_or(url);
                    println!("  {} — UNREACHABLE: {}", name, e);
                }
            }
        }

        if supplies.len() >= 2 {
            let first = &supplies[0].1;
            let all_match = supplies.iter().all(|(_, s)| s == first);
            if all_match {
                println!("\n  CONSERVATION: PASS — all {} nodes report {} beat", supplies.len(), first);
            } else {
                println!("\n  CONSERVATION: FAIL — supply divergence detected!");
                for (name, supply) in &supplies {
                    println!("    {} = {}", name, supply);
                }
            }
        }
    }

    // ── Summary ──────────────────────────────────────────────────────────
    if !results.is_empty() {
        println!("\n=== Summary ===");
        let succeeded = results.len();
        let settled = results.iter().filter(|r| r.settled_at.is_some()).count();
        let finalized = results.iter().filter(|r| r.finalized_at.is_some()).count();
        println!("  transfers:  {}/{} succeeded", succeeded, cli.transfers);
        println!("  settled:    {}/{}", settled, succeeded);
        println!("  finalized:  {}/{}", finalized, succeeded);

        // Confirmation level distribution
        let mut levels: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
        for r in &results {
            *levels.entry(r.confirmation.clone()).or_default() += 1;
        }
        println!("  levels: {:?}", levels);
    }

    println!("\n=== done ===");
}

async fn send_transfer(
    client: &reqwest::Client,
    target: &str,
    admin_token: &str,
    to: &str,
    amount: u64,
) -> Result<String, String> {
    let url = format!("{}/rpc/transfer", target);
    let body = serde_json::json!({
        "to": to,
        "amount": amount,
    });

    let resp = client
        .post(&url)
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", admin_token))
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("HTTP error: {}", e))?;

    let status = resp.status();
    let text = resp.text().await.map_err(|e| format!("read error: {}", e))?;

    if !status.is_success() {
        return Err(format!("HTTP {}: {}", status, text));
    }

    let json: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| format!("JSON parse error: {}", e))?;

    json["record_id"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| format!("no record_id in response: {}", text))
}

async fn fetch_status(client: &reqwest::Client, target: &str) -> serde_json::Value {
    let url = format!("{}/status", target);
    match client.get(&url).send().await {
        Ok(resp) => resp.json().await.unwrap_or(serde_json::Value::Null),
        Err(_) => serde_json::Value::Null,
    }
}

async fn fetch_record(
    client: &reqwest::Client,
    target: &str,
    record_id: &str,
) -> Result<serde_json::Value, String> {
    let url = format!("{}/record/{}", target, record_id);
    let resp = client
        .get(&url)
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .map_err(|e| format!("HTTP error: {}", e))?;
    resp.json()
        .await
        .map_err(|e| format!("JSON error: {}", e))
}

async fn fetch_ledger_summary(
    client: &reqwest::Client,
    target: &str,
) -> Result<serde_json::Value, String> {
    let url = format!("{}/ledger/summary", target);
    let resp = client
        .get(&url)
        .timeout(Duration::from_secs(60))
        .send()
        .await
        .map_err(|e| format!("{}", e))?;
    resp.json()
        .await
        .map_err(|e| format!("{}", e))
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = (p / 100.0 * (sorted.len() - 1) as f64).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

// ─── Sustained (multi-hour soak) ─────────────────────────────────────────
//
// Paced sender at `--rate` transfers/sec for `--duration-secs`. Every
// `--sample-secs` the sampler prints — and optionally writes to `--csv` —
// the rolling send error-rate, send-latency P50/P95/P99, and a /status
// snapshot (rss_mb, connected peers, settled/finalized counts, epoch). If
// the rolling error rate in a sample window exceeds `--break-on-error-rate`
// the soak aborts early — that's the breaking-point signal the mainnet
// load test is designed to catch.
//
// Design notes:
//   - Interval-driven sender: tokio::time::interval ticks every 1/rate s;
//     each tick spawns a detached `send_transfer`. Send latency exceeding
//     the interval does NOT back-pressure the ticker — the next tick still
//     fires — so if the node stalls, errors pile up and the breaker kicks.
//   - All shared state is AtomicU64 (counts) + AsyncMutex<Vec<f64>> (latencies).
//     The latency vec is drained on each sample tick so memory stays bounded
//     at ~sample_secs × rate entries.
//   - `/status` is best-effort; if it fails we still print the rolling stats.

struct SustainedState {
    sent_ok: AtomicU64,
    sent_err: AtomicU64,
    // Only per-window slices (drained per sample). Cumulative counts live in the atomics.
    latencies_ms: AsyncMutex<Vec<f64>>,
}

async fn run_sustained(client: &reqwest::Client, cli: &Cli, to: &str) {
    if cli.rate <= 0.0 {
        eprintln!("ERROR: --rate must be > 0");
        return;
    }
    if cli.duration_secs == 0 {
        eprintln!("ERROR: --duration-secs must be > 0");
        return;
    }
    let interval_ms = ((1000.0 / cli.rate).max(1.0)).round() as u64;

    println!(
        "\n--- Sustained soak: rate={:.2}/s duration={}s sample_every={}s csv={} break_err_rate={:.2} ---",
        cli.rate,
        cli.duration_secs,
        cli.sample_secs,
        if cli.csv.is_empty() { "(none)" } else { cli.csv.as_str() },
        cli.break_on_error_rate,
    );
    println!(
        "  pacing every {}ms ({} planned sends over {}s)",
        interval_ms,
        (cli.rate * cli.duration_secs as f64).round() as u64,
        cli.duration_secs
    );

    let state = Arc::new(SustainedState {
        sent_ok: AtomicU64::new(0),
        sent_err: AtomicU64::new(0),
        latencies_ms: AsyncMutex::new(Vec::with_capacity(1024)),
    });

    // Open CSV writer if requested.
    let mut csv_writer: Option<std::fs::File> = if cli.csv.is_empty() {
        None
    } else {
        match std::fs::File::create(&cli.csv) {
            Ok(mut f) => {
                let _ = writeln!(
                    f,
                    "elapsed_s,window_ok,window_err,window_err_rate,p50_ms,p95_ms,p99_ms,cum_ok,cum_err,rss_mb,peers,settled,finalized,epoch"
                );
                Some(f)
            }
            Err(e) => {
                eprintln!("WARNING: could not open CSV {}: {}", cli.csv, e);
                None
            }
        }
    };

    let start = Instant::now();
    let deadline = start + Duration::from_secs(cli.duration_secs);
    let sample_dur = Duration::from_secs(cli.sample_secs.max(1));
    let abort = Arc::new(std::sync::atomic::AtomicBool::new(false));

    // ── Sender task ──────────────────────────────────────────────────────
    let sender_state = Arc::clone(&state);
    let sender_abort = Arc::clone(&abort);
    let sender_client = client.clone();
    let sender_target = cli.target.clone();
    let sender_token = cli.admin_token.clone();
    let sender_to = to.to_string();
    let sender_amount = cli.amount;
    let sender = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_millis(interval_ms));
        // Skip missed ticks rather than bursting to catch up — we want rate control, not catch-up.
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            if sender_abort.load(Ordering::Relaxed) || Instant::now() >= deadline {
                break;
            }
            let st = Arc::clone(&sender_state);
            let c = sender_client.clone();
            let target = sender_target.clone();
            let token = sender_token.clone();
            let to_clone = sender_to.clone();
            tokio::spawn(async move {
                let t = Instant::now();
                let r = send_transfer(&c, &target, &token, &to_clone, sender_amount).await;
                let ms = t.elapsed().as_secs_f64() * 1000.0;
                match r {
                    Ok(_) => {
                        st.sent_ok.fetch_add(1, Ordering::Relaxed);
                        let mut v = st.latencies_ms.lock().await;
                        v.push(ms);
                    }
                    Err(_) => {
                        st.sent_err.fetch_add(1, Ordering::Relaxed);
                    }
                }
            });
        }
    });

    // ── Sampler loop (main task) ─────────────────────────────────────────
    let mut prev_ok: u64 = 0;
    let mut prev_err: u64 = 0;
    let mut ticks: u64 = 0;
    loop {
        tokio::time::sleep(sample_dur).await;
        ticks += 1;
        let elapsed = start.elapsed().as_secs_f64();

        let cum_ok = state.sent_ok.load(Ordering::Relaxed);
        let cum_err = state.sent_err.load(Ordering::Relaxed);
        let win_ok = cum_ok - prev_ok;
        let win_err = cum_err - prev_err;
        let win_total = win_ok + win_err;
        let win_err_rate = if win_total == 0 {
            0.0
        } else {
            win_err as f64 / win_total as f64
        };
        prev_ok = cum_ok;
        prev_err = cum_err;

        let mut lats: Vec<f64> = {
            let mut v = state.latencies_ms.lock().await;
            std::mem::take(&mut *v)
        };
        lats.sort_by(|a, b| a.total_cmp(b));
        let p50 = percentile(&lats, 50.0);
        let p95 = percentile(&lats, 95.0);
        let p99 = percentile(&lats, 99.0);

        // Best-effort /status snapshot.
        let status = fetch_status(client, &cli.target).await;
        let rss_mb = status["rss_mb"].as_u64().unwrap_or(0);
        let peers = status["connected_peers"].as_u64()
            .or_else(|| status["active_peers"].as_u64())
            .unwrap_or(0);
        let settled = status["consensus_settled"].as_u64()
            .or_else(|| status["settled"].as_u64())
            .unwrap_or(0);
        let finalized = status["finalized_count"].as_u64()
            .or_else(|| status["finalized"].as_u64())
            .unwrap_or(0);
        let epoch = status["current_epoch"].as_u64()
            .or_else(|| status["epoch"].as_u64())
            .unwrap_or(0);

        println!(
            "  [{:>5.0}s] win: ok={} err={} err_rate={:.1}% | P50={:.0}ms P95={:.0}ms P99={:.0}ms | rss={}MB peers={} settled={} finalized={} epoch={}",
            elapsed, win_ok, win_err, win_err_rate * 100.0,
            p50, p95, p99, rss_mb, peers, settled, finalized, epoch
        );

        if let Some(f) = csv_writer.as_mut() {
            let _ = writeln!(
                f,
                "{:.1},{},{},{:.4},{:.0},{:.0},{:.0},{},{},{},{},{},{},{}",
                elapsed, win_ok, win_err, win_err_rate, p50, p95, p99,
                cum_ok, cum_err, rss_mb, peers, settled, finalized, epoch
            );
            let _ = f.flush();
        }

        // Breaker — give it one warmup window before arming.
        if cli.break_on_error_rate > 0.0
            && ticks >= 2
            && win_total >= 10
            && win_err_rate > cli.break_on_error_rate
        {
            println!(
                "\n  BREAKER TRIPPED: window error rate {:.1}% > threshold {:.1}% — aborting soak",
                win_err_rate * 100.0,
                cli.break_on_error_rate * 100.0
            );
            abort.store(true, Ordering::Relaxed);
            break;
        }

        if Instant::now() >= deadline {
            break;
        }
    }

    abort.store(true, Ordering::Relaxed);
    let _ = sender.await;

    let cum_ok = state.sent_ok.load(Ordering::Relaxed);
    let cum_err = state.sent_err.load(Ordering::Relaxed);
    let total = cum_ok + cum_err;
    let dur = start.elapsed().as_secs_f64();
    let effective_rate = if dur > 0.0 { cum_ok as f64 / dur } else { 0.0 };
    let final_err_rate = if total == 0 { 0.0 } else { cum_err as f64 / total as f64 };
    println!("\n  === Sustained summary ===");
    println!("    duration:       {:.1}s", dur);
    println!("    target rate:    {:.2}/s", cli.rate);
    println!("    effective rate: {:.2}/s (ok only)", effective_rate);
    println!("    sent ok:        {}", cum_ok);
    println!("    sent err:       {} ({:.1}%)", cum_err, final_err_rate * 100.0);
}

// ─── Microscope (Gap 8) ──────────────────────────────────────────────────
//
// Drives N single transfers serially, polling `/seal/progress/{id}` at
// sub-second resolution to produce a per-record timeline:
//
//   t=0ms        send
//   t=Ams        first attestation observed (progress_pct > 0)
//   t=Sms        ConfirmationLevel::Sealed  (level flips sealed|finalized|anchored)
//   t=Tms        2/3 threshold crossed      (progress_pct ≥ 100 / settled==true)
//   t=Fms        Finalized                  (confirmation_level=finalized)
//
// This is the instrument that validates the Gap 8 "optimistic Sealed at 3-5s"
// claim. MIN_ADAPTIVE_EPOCH_SECS was lowered to 5s on 2026-04-22. Use this
// bench to measure P50/P95 seal latency and decide whether sub-5s is safe.

#[derive(Debug, Default, Clone)]
struct MicroSample {
    first_attestation_ms: Option<u128>,
    sealed_ms: Option<u128>,
    threshold_ms: Option<u128>,
    finalized_ms: Option<u128>,
    final_level: String,
    peak_attestations: usize,
    peak_progress_pct: f64,
    samples: usize,
}

async fn run_microscope(client: &reqwest::Client, cli: &Cli, to: &str) {
    let n = cli.transfers.max(1);
    let poll = Duration::from_millis(cli.micro_poll_ms);
    let timeout = Duration::from_secs(cli.micro_timeout_secs);

    println!("\n--- Microscope (Gap 8): {} transfer(s), poll={}ms, timeout={}s ---",
        n, cli.micro_poll_ms, cli.micro_timeout_secs);
    println!("  endpoint: {}/seal/progress/{{id}}", cli.target);

    let mut samples: Vec<MicroSample> = Vec::with_capacity(n);

    for i in 0..n {
        let t0 = Instant::now();
        let record_id = match send_transfer(client, &cli.target, &cli.admin_token, to, cli.amount).await {
            Ok(id) => id,
            Err(e) => {
                eprintln!("  [{}/{}] send FAILED: {}", i + 1, n, e);
                continue;
            }
        };
        let send_ms = t0.elapsed().as_millis();

        let mut s = MicroSample::default();
        let deadline = Instant::now() + timeout;
        let mut last_att = 0usize;
        let mut last_level = String::new();

        loop {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            let elapsed_ms = t0.elapsed().as_millis();
            s.samples += 1;

            match fetch_seal_progress(client, &cli.target, &record_id).await {
                Ok(v) => {
                    let level = v["confirmation_level"].as_str().unwrap_or("pending").to_string();
                    let sp = &v["seal_progress"];
                    let att = sp["attestation_count"].as_u64().unwrap_or(0) as usize;
                    let progress = sp["progress_pct"].as_f64().unwrap_or(0.0);
                    let settled = sp["settled"].as_bool().unwrap_or(false);
                    let finalized_at = !sp["finalized_at"].is_null();

                    if att > s.peak_attestations { s.peak_attestations = att; }
                    if progress > s.peak_progress_pct { s.peak_progress_pct = progress; }

                    if s.first_attestation_ms.is_none() && att > 0 {
                        s.first_attestation_ms = Some(elapsed_ms);
                    }
                    if s.sealed_ms.is_none()
                        && (level == "sealed" || level == "finalized" || level == "anchored")
                    {
                        s.sealed_ms = Some(elapsed_ms);
                    }
                    if s.threshold_ms.is_none() && (settled || progress >= 100.0) {
                        s.threshold_ms = Some(elapsed_ms);
                    }
                    if s.finalized_ms.is_none()
                        && (level == "finalized" || level == "anchored" || finalized_at)
                    {
                        s.finalized_ms = Some(elapsed_ms);
                    }

                    if level != last_level || att != last_att {
                        last_level = level.clone();
                        last_att = att;
                    }
                    s.final_level = level;

                    if s.finalized_ms.is_some() {
                        break;
                    }
                }
                Err(_) => {
                    // transient — keep polling
                }
            }

            tokio::time::sleep(poll).await;
        }

        let fmt = |o: Option<u128>| o.map(|m| format!("{}ms", m)).unwrap_or_else(|| "—".to_string());
        println!(
            "  [{}/{}] {}  send={}ms  first_att={}  sealed={}  thresh={}  finalized={}  peak_att={}  peak={:.0}%  level={}",
            i + 1, n, &record_id[..16.min(record_id.len())],
            send_ms,
            fmt(s.first_attestation_ms),
            fmt(s.sealed_ms),
            fmt(s.threshold_ms),
            fmt(s.finalized_ms),
            s.peak_attestations,
            s.peak_progress_pct,
            s.final_level,
        );

        samples.push(s);
    }

    // Aggregate
    if samples.is_empty() {
        println!("\n  no samples collected");
        return;
    }

    let collect = |pick: fn(&MicroSample) -> Option<u128>| -> Vec<f64> {
        let mut v: Vec<f64> = samples.iter().filter_map(pick).map(|m| m as f64).collect();
        v.sort_by(|a, b| a.total_cmp(b));
        v
    };
    let first_att = collect(|s| s.first_attestation_ms);
    let sealed = collect(|s| s.sealed_ms);
    let thresh = collect(|s| s.threshold_ms);
    let final_ = collect(|s| s.finalized_ms);

    let dump = |label: &str, lats: &[f64], total: usize| {
        if lats.is_empty() {
            println!("    {}: —  (0/{} reached this state)", label, total);
            return;
        }
        println!(
            "    {}: P50={:.0}ms P95={:.0}ms P99={:.0}ms  min={:.0}ms max={:.0}ms  ({}/{})",
            label,
            percentile(lats, 50.0),
            percentile(lats, 95.0),
            percentile(lats, 99.0),
            lats.first().copied().unwrap_or(0.0),
            lats.last().copied().unwrap_or(0.0),
            lats.len(),
            total,
        );
    };

    println!("\n  Transition latencies (send → state):");
    dump("first_attestation", &first_att, samples.len());
    dump("sealed           ", &sealed, samples.len());
    dump("threshold_crossed", &thresh, samples.len());
    dump("finalized        ", &final_, samples.len());
}

async fn fetch_seal_progress(
    client: &reqwest::Client,
    target: &str,
    record_id: &str,
) -> Result<serde_json::Value, String> {
    let url = format!("{}/seal/progress/{}", target, record_id);
    let resp = client
        .get(&url)
        .timeout(Duration::from_secs(3))
        .send()
        .await
        .map_err(|e| format!("HTTP error: {}", e))?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    resp.json()
        .await
        .map_err(|e| format!("JSON error: {}", e))
}

// ─── PQ microscope (4E.3 Part C) ─────────────────────────────────────────
//
// Subscribes to `seal_progress_stream` on the target node's PQ listener and
// replays the cadence-driven server pushes through the same MicroSample
// aggregator that the HTTPS poll path fills. This is the first end-to-end
// consumer of the 4E.3 Part B wire and validates that the stream closes on
// the terminal FINAL chunk (finalized | anchored | settled | pruned_settled).
//
// Transfers are still sent over the existing HTTPS admin RPC — tokens for
// that path are out of scope for 4E.3; the PQ win here is on the *polling*
// side, which for a 5s-floor epoch fires at 100ms and dominates the
// per-transfer call volume.

async fn run_microscope_pq(client: &reqwest::Client, cli: &Cli, to: &str) {
    use elara_runtime::network::pq_client::{PqNodeClient, StreamProgressMessage};
    use elara_runtime::network::pq_transport::PeerIdentityStore;
    use std::sync::Arc;

    let n = cli.transfers.max(1);
    let timeout = Duration::from_secs(cli.micro_timeout_secs);

    // Ephemeral Dilithium3 identity for the bench process. Pins are
    // in-memory and TOFU — the bench is not a long-running node, so there
    // is nothing to persist. One keypair serves all N transfers.
    let kp = match elara_runtime::crypto::pqc::dilithium3_keygen() {
        Ok(kp) => kp,
        Err(e) => {
            eprintln!("bench: dilithium3_keygen failed: {e}");
            return;
        }
    };
    let (my_pk, my_sk) = kp.into_parts();
    let pins = Arc::new(PeerIdentityStore::in_memory());
    let pq = PqNodeClient::new(my_pk, my_sk, pins);

    println!(
        "\n--- Microscope (Gap 8, PQ stream): {} transfer(s), timeout={}s ---",
        n, cli.micro_timeout_secs
    );
    println!("  send endpoint:   {}/rpc (HTTPS admin RPC)", cli.target);
    println!("  stream endpoint: {} (PQ seal_progress_stream)", cli.pq_target);

    let mut samples: Vec<MicroSample> = Vec::with_capacity(n);

    for i in 0..n {
        let t0 = Instant::now();
        let record_id = match send_transfer(client, &cli.target, &cli.admin_token, to, cli.amount).await {
            Ok(id) => id,
            Err(e) => {
                eprintln!("  [{}/{}] send FAILED: {}", i + 1, n, e);
                continue;
            }
        };
        let send_ms = t0.elapsed().as_millis();

        let mut s = MicroSample::default();

        // Open the stream AFTER send so the subscription starts from first
        // seal attempt. stream_seal_progress itself handshakes + pins.
        let rx = match pq.stream_seal_progress(&cli.pq_target, &record_id).await {
            Ok(rx) => rx,
            Err(e) => {
                eprintln!("  [{}/{}] stream FAILED: {}", i + 1, n, e);
                continue;
            }
        };

        // Apply a whole-transfer deadline on the subscription. If the node
        // never emits a FINAL chunk (unlikely — router enforces a 300s
        // server-side deadline) we don't want to block the bench forever.
        let consumed = tokio::time::timeout(timeout, async {
            let mut rx = rx;
            while let Some(msg) = rx.recv().await {
                match msg {
                    StreamProgressMessage::Progress(v) => {
                        let elapsed_ms = t0.elapsed().as_millis();
                        s.samples += 1;

                        let level = v["confirmation_level"]
                            .as_str()
                            .unwrap_or("pending")
                            .to_string();
                        let sp = &v["seal_progress"];
                        let att = sp["attestation_count"].as_u64().unwrap_or(0) as usize;
                        let progress = sp["progress_pct"].as_f64().unwrap_or(0.0);
                        let settled = sp["settled"].as_bool().unwrap_or(false);
                        let finalized_at = !sp["finalized_at"].is_null();

                        if att > s.peak_attestations {
                            s.peak_attestations = att;
                        }
                        if progress > s.peak_progress_pct {
                            s.peak_progress_pct = progress;
                        }
                        if s.first_attestation_ms.is_none() && att > 0 {
                            s.first_attestation_ms = Some(elapsed_ms);
                        }
                        if s.sealed_ms.is_none()
                            && (level == "sealed" || level == "finalized" || level == "anchored")
                        {
                            s.sealed_ms = Some(elapsed_ms);
                        }
                        if s.threshold_ms.is_none() && (settled || progress >= 100.0) {
                            s.threshold_ms = Some(elapsed_ms);
                        }
                        if s.finalized_ms.is_none()
                            && (level == "finalized" || level == "anchored" || finalized_at)
                        {
                            s.finalized_ms = Some(elapsed_ms);
                        }
                        s.final_level = level;
                    }
                    StreamProgressMessage::Error(e) => {
                        eprintln!("  [{}/{}] stream error: {}", i + 1, n, e);
                        break;
                    }
                }
            }
        })
        .await;

        if consumed.is_err() {
            eprintln!("  [{}/{}] stream deadline reached before FINAL", i + 1, n);
        }

        let fmt = |o: Option<u128>| {
            o.map(|m| format!("{}ms", m))
                .unwrap_or_else(|| "—".to_string())
        };
        println!(
            "  [{}/{}] {}  send={}ms  first_att={}  sealed={}  thresh={}  finalized={}  peak_att={}  peak={:.0}%  level={}",
            i + 1, n, &record_id[..16.min(record_id.len())],
            send_ms,
            fmt(s.first_attestation_ms),
            fmt(s.sealed_ms),
            fmt(s.threshold_ms),
            fmt(s.finalized_ms),
            s.peak_attestations,
            s.peak_progress_pct,
            s.final_level,
        );

        samples.push(s);
    }

    if samples.is_empty() {
        println!("\n  no samples collected");
        return;
    }

    let collect = |pick: fn(&MicroSample) -> Option<u128>| -> Vec<f64> {
        let mut v: Vec<f64> = samples.iter().filter_map(pick).map(|m| m as f64).collect();
        v.sort_by(|a, b| a.total_cmp(b));
        v
    };
    let first_att = collect(|s| s.first_attestation_ms);
    let sealed = collect(|s| s.sealed_ms);
    let thresh = collect(|s| s.threshold_ms);
    let final_ = collect(|s| s.finalized_ms);

    let dump = |label: &str, lats: &[f64], total: usize| {
        if lats.is_empty() {
            println!("    {}: —  (0/{} reached this state)", label, total);
            return;
        }
        println!(
            "    {}: P50={:.0}ms P95={:.0}ms P99={:.0}ms  min={:.0}ms max={:.0}ms  ({}/{})",
            label,
            percentile(lats, 50.0),
            percentile(lats, 95.0),
            percentile(lats, 99.0),
            lats.first().copied().unwrap_or(0.0),
            lats.last().copied().unwrap_or(0.0),
            lats.len(),
            total,
        );
    };

    println!("\n  Transition latencies (send → state):");
    dump("first_attestation", &first_att, samples.len());
    dump("sealed           ", &sealed, samples.len());
    dump("threshold_crossed", &thresh, samples.len());
    dump("finalized        ", &final_, samples.len());
}

// ─────────────────────────────────────────────────────────────────────────
// tests
// ─────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::percentile;

    #[test]
    fn percentile_empty_slice_returns_zero() {
        let empty: [f64; 0] = [];
        assert_eq!(percentile(&empty, 50.0), 0.0);
        assert_eq!(percentile(&empty, 99.0), 0.0);
    }

    #[test]
    fn percentile_single_element() {
        let one = [42.0];
        assert_eq!(percentile(&one, 0.0), 42.0);
        assert_eq!(percentile(&one, 50.0), 42.0);
        assert_eq!(percentile(&one, 100.0), 42.0);
    }

    #[test]
    fn percentile_basic_values_on_10_element_sorted_slice() {
        // 10 elements [1.0..10.0], indices 0..=9
        // Rust f64::round() is round-half-away-from-zero:
        //   p0   → idx = round(0)    = 0 → 1.0
        //   p50  → idx = round(4.5)  = 5 → 6.0
        //   p95  → idx = round(8.55) = 9 → 10.0
        //   p99  → idx = round(8.91) = 9 → 10.0
        //   p100 → idx = round(9)    = 9 → 10.0
        let v: Vec<f64> = (1..=10).map(|n| n as f64).collect();
        assert_eq!(percentile(&v, 0.0), 1.0);
        assert_eq!(percentile(&v, 100.0), 10.0);
        assert_eq!(percentile(&v, 50.0), 6.0);
        assert_eq!(percentile(&v, 95.0), 10.0);
        assert_eq!(percentile(&v, 99.0), 10.0);
    }

    #[test]
    fn percentile_clamps_overshoot_to_last_index() {
        // p > 100% is bounded by .min(len-1) — never panics
        let v = [1.0, 2.0, 3.0];
        assert_eq!(percentile(&v, 150.0), 3.0);
        assert_eq!(percentile(&v, 1000.0), 3.0);
    }

    #[test]
    fn percentile_handles_two_element_slice() {
        let v = [10.0, 20.0];
        assert_eq!(percentile(&v, 0.0), 10.0);
        assert_eq!(percentile(&v, 100.0), 20.0);
        // p50 → idx = round(0.5) = 1 (round-half-away-from-zero)
        assert_eq!(percentile(&v, 50.0), 20.0);
    }

    #[test]
    fn percentile_does_not_panic_on_unsorted_input() {
        // Function claims `sorted` in the signature but does not enforce it.
        // Pin that we don't panic on unsorted input (caller's responsibility
        // to sort first — bench code calls sort_by before percentile).
        let v = [3.0, 1.0, 2.0];
        let _ = percentile(&v, 50.0);
    }

    // ─── percentile-function invariant tests ─────

    #[test]
    fn batch_b_percentile_monotonic_non_decreasing_in_p_across_sorted_input() {
        // For a sorted slice, the percentile function MUST be monotonic
        // non-decreasing in p: larger p → larger-or-equal value. If a
        // future refactor breaks the index arithmetic (e.g., `len()` vs
        // `len() - 1` off-by-one mid-slice), this test catches it.
        let v: Vec<f64> = (1..=100).map(|n| n as f64).collect();
        let mut prev = f64::NEG_INFINITY;
        for p_int in 0..=100 {
            let p = p_int as f64;
            let cur = percentile(&v, p);
            assert!(
                cur >= prev,
                "monotonicity violated at p={p}: {cur} < previous {prev}"
            );
            prev = cur;
        }
    }

    #[test]
    fn batch_b_percentile_p0_returns_first_and_p100_returns_last_across_shapes() {
        // For every non-empty input shape, p=0 must return v[0] and
        // p=100 must return v[len-1]. Pin across 6 shapes covering
        // varying lengths and value ranges.
        let shapes: Vec<Vec<f64>> = vec![
            vec![0.0],
            vec![-1.0, 1.0],
            vec![0.0, 0.5, 1.0],
            (0..50).map(|n| n as f64 * 2.0).collect(),
            (0..1000).map(|n| n as f64 / 7.0).collect(),
            vec![f64::MIN, 0.0, f64::MAX],
        ];
        for v in &shapes {
            assert_eq!(
                percentile(v, 0.0),
                v[0],
                "p=0 must return first element for {v:?}",
            );
            assert_eq!(
                percentile(v, 100.0),
                v[v.len() - 1],
                "p=100 must return last element for {v:?}",
            );
        }
    }

    #[test]
    fn batch_b_percentile_negative_p_saturates_to_first_element() {
        // Rust 1.45+ `as usize` cast from negative f64 saturates to 0
        // (NOT undefined behavior). So `percentile(v, -50.0)` returns v[0]
        // rather than panicking. Pin this so the contract is explicit.
        let v = [10.0, 20.0, 30.0];
        assert_eq!(percentile(&v, -50.0), 10.0);
        assert_eq!(percentile(&v, -100.0), 10.0);
        assert_eq!(percentile(&v, f64::NEG_INFINITY), 10.0);
    }

    #[test]
    fn batch_b_percentile_nan_p_does_not_panic_and_returns_finite() {
        // NaN propagation: NaN/100 = NaN, NaN * x = NaN, NaN.round() = NaN,
        // NaN as usize = 0 (saturating cast since Rust 1.45). Returned
        // value is a real element of the slice (NOT NaN itself).
        let v = [10.0, 20.0, 30.0];
        let got = percentile(&v, f64::NAN);
        assert!(got.is_finite(), "result must be finite, got {got}");
        assert!(
            v.contains(&got),
            "result {got} must be one of the input values"
        );
    }

    #[test]
    fn batch_b_percentile_index_arithmetic_correct_at_round_boundaries() {
        // f64::round() is round-half-away-from-zero. Pin the boundary
        // index calculation across an even-count slice where p hits exact
        // half-integer indices.
        // 4-element slice: indices 0,1,2,3. (sorted.len() - 1) = 3.
        // p=50 → 0.5 * 3 = 1.5 → round = 2 (half-away-from-zero)
        // p=25 → 0.25 * 3 = 0.75 → round = 1
        // p=75 → 0.75 * 3 = 2.25 → round = 2
        // p=33.333 → 0.333.. * 3 = 1.0 → round = 1
        // p=66.666 → 0.666.. * 3 = 2.0 → round = 2
        let v = [10.0, 20.0, 30.0, 40.0];
        assert_eq!(percentile(&v, 25.0), 20.0); // idx 1
        assert_eq!(percentile(&v, 50.0), 30.0); // idx 2 (half rounds up)
        assert_eq!(percentile(&v, 75.0), 30.0); // idx 2
        assert_eq!(percentile(&v, 100.0 / 3.0), 20.0); // idx 1
        assert_eq!(percentile(&v, 200.0 / 3.0), 30.0); // idx 2
        // Returned value must always be one of the inputs (NOT interpolated).
        for p_int in 0..=100 {
            let r = percentile(&v, p_int as f64);
            assert!(v.contains(&r), "p={p_int}: {r} must be a v-element");
        }
    }

    #[test]
    fn dilithium3_keygen_succeeds_for_bench_microscope() {
        // Guards the expect->Result conversion: keygen must return Ok so the
        // run_microscope_pq early-return path is never hit in practice.
        let result = elara_runtime::crypto::pqc::dilithium3_keygen();
        assert!(result.is_ok(), "dilithium3_keygen must succeed: {:?}", result.err());
    }

    #[test]
    fn tokio_runtime_builder_is_ok() {
        // Pin: Builder::build() succeeds under the default bench configuration.
        // Guards against future changes where this path would silently panic.
        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build();
        assert!(rt.is_ok(), "tokio runtime builder must not fail: {:?}", rt.err());
    }

    #[test]
    fn reqwest_bench_client_builder_is_ok() {
        // Pin: ClientBuilder::build() with danger_accept_invalid_certs always returns Ok.
        // Ensures the unwrap_or_else exit path in run() is never hit on valid config.
        let result = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .danger_accept_invalid_certs(true)
            .build();
        assert!(result.is_ok(), "reqwest client builder must not fail: {:?}", result.err());
    }

    #[test]
    fn min_max_copied_unwrap_or_never_panics() {
        // Guards the first/last unwrap->unwrap_or hardening in print_report /
        // dump closures. Empty slice must return 0.0; non-empty must return
        // the actual boundary values.
        let empty: Vec<f64> = Vec::new();
        assert_eq!(empty.first().copied().unwrap_or(0.0), 0.0);
        assert_eq!(empty.last().copied().unwrap_or(0.0), 0.0);

        let sorted = [1.5_f64, 3.0, 7.2];
        assert_eq!(sorted.first().copied().unwrap_or(0.0), 1.5);
        assert_eq!(sorted.last().copied().unwrap_or(0.0), 7.2);
    }
}
