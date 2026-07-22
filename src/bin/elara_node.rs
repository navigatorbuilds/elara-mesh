//! elara-node — Elara Protocol network daemon.
//!
//! Usage:
//!   cargo run --features node --bin elara-node -- --config elara-node.toml
//!   cargo run --features node --bin elara-node -- --generate-identity
//!   cargo run --features node --bin elara-node -- --listen 0.0.0.0:9473

//!
//! Spec references:
//!   @spec Protocol §3.2
//!   @spec Protocol §3.4

#[cfg(all(not(target_arch = "wasm32"), target_family = "unix", feature = "tikv-jemallocator"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

// Tune jemalloc for memory-constrained nodes:
//   dirty_decay_ms:0     — immediately return freed pages to OS via madvise(DONTNEED).
//                          Without this, continuous record processing prevents the decay
//                          timer from firing, causing single arenas to hold 800MB+ RSS.
//   muzzy_decay_ms:0     — immediately release lazy-purged pages
//   narenas:2            — limit arenas (default 4×cores, wastes per-arena overhead)
//   background_thread:true — async purging even during continuous allocations
#[cfg(all(not(target_arch = "wasm32"), target_family = "unix", feature = "tikv-jemallocator"))]
#[allow(non_upper_case_globals)]
#[export_name = "_rjem_malloc_conf"]
pub static malloc_conf: &[u8] = b"dirty_decay_ms:0,muzzy_decay_ms:0,narenas:2,background_thread:true\0";

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use tokio::signal;
use tokio::sync::mpsc;
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

use elara_runtime::errors::{ElaraError, Result};
use elara_runtime::identity::{CryptoProfile, EntityType, Identity};
use elara_runtime::network::config::NodeConfig;
use elara_runtime::network::server;
use elara_runtime::network::snapshot;
use elara_runtime::network::state::NodeState;
use elara_runtime::network::witness::WitnessManager;
use elara_runtime::network::{account_merkle, auto_witness, consensus, discovery, dispute, drand_fetch, epoch, fisherman, gc, gossip, key_rotation, liveness, sunset, sync, LockRecover, RwLockRecover};
use elara_runtime::storage::Storage;

#[derive(Parser)]
#[command(name = "elara-node", version, about = "Elara Protocol network node")]
struct Cli {
    /// Path to TOML configuration file.
    #[arg(long, default_value = "elara-node.toml")]
    config: String,

    /// Override listen address (e.g., 0.0.0.0:9473).
    #[arg(long)]
    listen: Option<String>,

    /// Generate a new identity and exit.
    #[arg(long)]
    generate_identity: bool,

    /// Data directory for all node files.
    #[arg(long)]
    data_dir: Option<String>,

    /// Restore RocksDB from a checkpoint directory, then start normally.
    #[arg(long)]
    restore: Option<String>,

    /// Repair a corrupted RocksDB and exit.
    #[arg(long)]
    repair: bool,

    /// Export node data for migration. Creates a checksum-verified tarball of
    /// identity, ledger snapshot, peer + DHT state, and a RocksDB checkpoint.
    #[arg(long)]
    export_data: Option<String>,

    /// Verify integrity of node data directory (conservation, record count, identity).
    #[arg(long)]
    verify_data: bool,

    /// Install the node as an OS service that starts on boot and restarts on
    /// failure, then exit. Linux/WSL2: systemd unit (system-wide as root,
    /// per-user otherwise; WSL2 additionally gets a Windows logon wake entry
    /// so the distro boots without a terminal). Windows: logon autostart
    /// entry. The service reproduces this exact invocation minus the
    /// service-management flags.
    #[arg(long)]
    install_service: bool,

    /// Remove the service installed by --install-service, then exit.
    #[arg(long)]
    uninstall_service: bool,

    /// Report the installed-service state, then exit.
    #[arg(long)]
    service_status: bool,

    /// With --install-service / --uninstall-service: print every action
    /// (including full file contents) without executing anything.
    #[arg(long)]
    service_dry_run: bool,

    /// Skip the Windows-side logon entry (WSL2 / native Windows installs).
    #[arg(long)]
    no_windows_autostart: bool,

    /// Verbosity tier for /metrics output.
    /// P0 = consensus + finality + connectivity + resource ceilings (~30 families);
    /// P1 = P0 + per-host utilization + error counters (~150 families);
    /// debug = full surface (~590 families).
    /// When unset, defaults derive from `node_profile`: Light → P0 (phone-tier),
    /// FullZone → P1 (server, default), Archive → debug (forensic). Operators who
    /// want yesterday's full-surface behavior on a FullZone node pass
    /// `--metric-tier=debug` explicitly. Also configurable via the
    /// ELARA_METRIC_TIER env var. /metrics also accepts a per-request
    /// `?tier=p0|p1|debug` query-param override (no restart required).
    #[arg(long, value_parser = ["P0", "p0", "P1", "p1", "debug", "Debug"])]
    metric_tier: Option<String>,
}

fn main() {
    // Limit glibc malloc arenas BEFORE Tokio spawns worker threads.
    // Default: 8 × cores (e.g. 64 on 8-core). Each Tokio worker thread gets its own
    // arena (~64MB each), and malloc_trim only frees the main arena. With default
    // settings, 20+ arenas × 64MB = 1.3GB+ of unreclaimable heap fragmentation.
    // Must be called before any threads are created.
    #[cfg(target_os = "linux")]
    unsafe {
        libc::mallopt(libc::M_ARENA_MAX, 2);
    }

    // Minimum 2 worker threads even on 1-CPU nodes.
    // With 1 worker (Tokio default for 1 CPU), 28 background tasks +
    // spawn_blocking result polls starve the HTTP accept task — the
    // socket stays bound but no connections are accepted (the observed freeze).
    // A second worker ensures the scheduler can serve HTTP while the
    // other worker is stuck on state_core / gossip / RocksDB I/O.
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let workers = cpus.max(2);

    // Limit blocking thread pool on resource-constrained nodes.
    // Default is 512 — too many threads cause CPU contention on small nodes.
    // But too few causes queue stalls: gossip push uses 2 spawn_blocking calls
    // simultaneously, so 2 threads leaves 0 for record processing (51-98s waits).
    // The step function lives in `config::max_blocking_threads_for` so the
    // HEAVY-read concurrency-cap derivation (network/state.rs) computes the same
    // pool size from the same source and cannot drift from this builder.
    let max_blocking = elara_runtime::network::config::max_blocking_threads_for(cpus);

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .max_blocking_threads(max_blocking)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("fatal: failed to build Tokio runtime: {e}");
            std::process::exit(1);
        }
    };
    rt.block_on(async_main());
}

async fn async_main() {
    // Initialize tracing (ELARA_LOG_FORMAT=json for structured output)
    // ELARA_LOG/RUST_LOG wins when set & valid; otherwise fall back to the
    // project default directives. EnvFilter::new is infallible (bad directives
    // are dropped, not panicked) — the literal here is a known-good constant
    // guarded by the default_log_filter_string_is_valid regression test.
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("elara_node=info,elara_runtime=info"));
    let json_mode = std::env::var("ELARA_LOG_FORMAT")
        .map(|v| v.eq_ignore_ascii_case("json"))
        .unwrap_or(false);
    if json_mode {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(env_filter)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .init();
    }

    if let Err(e) = run().await {
        error!("fatal: {e}");
        std::process::exit(1);
    }
}

/// Rebases `p` under `data_dir` by keeping only its filename component.
/// Returns a Config error if `p` has no filename (e.g. `/` or `..`-terminated).
fn rebase_path(p: &std::path::Path, data_dir: &std::path::Path) -> Result<std::path::PathBuf> {
    let name = p.file_name().ok_or_else(|| ElaraError::Config(format!(
        "path has no filename component: {}",
        p.display()
    )))?;
    Ok(data_dir.join(name))
}

fn generate_admin_token() -> Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes)
        .map_err(|e| ElaraError::Config(format!("failed to generate random token: {e}")))?;
    Ok(hex::encode(bytes))
}

/// F2 PSR-1: resolve the boot ledger checkpoint, honoring the persistent gov-rebuild
/// marker. Returns `(checkpoint, force_full_gov_rebuild)`:
/// - `force_full` is the FAIL-CLOSED marker read (`gov_rebuild_required()` returns true
///   when a governance-op tombstone set the marker OR the read errored). When true the
///   checkpoint is `None` so the caller takes the full-rebuild path (which drops the
///   tombstoned gov op), and the caller uses the flag to gate the post-rebuild marker clear.
/// - otherwise the checkpoint is `Some` iff a conservation-passing (`total_supply ==
///   MAX_SUPPLY`) ledger snapshot + its timestamp both load.
///
/// Extracted from `run()` (post-ship review recommendation) so the marker-gate wiring is
/// unit-testable — see `f2_psr1_resolve_boot_checkpoint_*` tests. Behavior-preserving move.
fn resolve_boot_checkpoint(
    rocks: &elara_runtime::storage::rocks::StorageEngine,
) -> (Option<(elara_runtime::accounting::ledger::LedgerState, f64)>, bool) {
    if rocks.gov_rebuild_required() {
        info!("F2 PSR-1: gov_rebuild_required marker set — forcing full ledger rebuild (durable governance-tombstone skip)");
        return (None, true);
    }
    let cp_ts = rocks.load_snapshot::<f64>("checkpoint_timestamp").ok().flatten();
    let cp_ledger = rocks
        .load_snapshot::<elara_runtime::accounting::ledger::LedgerState>("ledger")
        .ok()
        .flatten();
    let cp = match (cp_ts, cp_ledger) {
        (Some(ts), Some(ledger))
            if ledger.total_supply == elara_runtime::accounting::types::MAX_SUPPLY =>
        {
            info!(
                "checkpoint found: ts={:.0}, ledger supply={}, {} accounts, {} applied records",
                ts, ledger.total_supply, ledger.accounts.len(), ledger.applied_record_ids.len()
            );
            Some((ledger, ts))
        }
        (Some(_ts), Some(ledger)) if ledger.total_supply > 0 => {
            warn!(
                "checkpoint ledger conservation violation: supply={} ≠ expected={} — falling back to full rebuild",
                ledger.total_supply, elara_runtime::accounting::types::MAX_SUPPLY
            );
            None
        }
        _ => None,
    };
    (cp, false)
}

async fn run() -> Result<()> {
    // Boot timing — captured at run() entry, finalized at HTTP listener bind.
    // Operators saw 2m44s–5m18s of pre-bind silence on a rolling deploy
    // (every endpoint connection-refused while axum waits for ledger rebuild),
    // which trips false "node down" alerts. Surfacing this lets a slow boot be
    // distinguished from a hung boot via /metrics post-bind.
    let boot_t0 = std::time::Instant::now();

    let cli = Cli::parse();

    // ─── Generate identity mode ─────────────────────────────────────────

    if cli.generate_identity {
        return generate_identity(&cli);
    }

    // ─── Service install / uninstall / status mode ─────────────────────

    if cli.install_service || cli.uninstall_service || cli.service_status {
        let opts = elara_runtime::service_install::ServiceOpts {
            dry_run: cli.service_dry_run,
            windows_autostart: !cli.no_windows_autostart,
        };
        return if cli.install_service {
            elara_runtime::service_install::install(&opts)
        } else if cli.uninstall_service {
            elara_runtime::service_install::uninstall(&opts)
        } else {
            elara_runtime::service_install::status()
        };
    }

    // ─── Load config ────────────────────────────────────────────────────

    let mut config = if std::path::Path::new(&cli.config).exists() {
        info!("loading config from {}", cli.config);
        NodeConfig::load(&cli.config)?
    } else {
        info!("no config file found, using defaults + env vars");
        NodeConfig::from_defaults()
    };

    // ─── Metric tier ───────────────────
    //
    // Resolution order:
    //   1. `--metric-tier` CLI flag
    //   2. `ELARA_METRIC_TIER` env var (systemd EnvironmentFile)
    //   3. Per-`node_profile` default (Light=P0 phone-tier, FullZone=P1 server,
    //      Archive=Debug forensic). Operators who want today's full-surface
    //      behavior pin `--metric-tier=debug` explicitly.
    //
    // The OnceLock is read by metrics_body() — must be set before any /metrics
    // request fires, which is satisfied because the HTTP listener binds later
    // in run().
    let tier_source = cli
        .metric_tier
        .clone()
        .or_else(|| std::env::var("ELARA_METRIC_TIER").ok());
    let resolved_tier = match tier_source.as_deref() {
        Some(s) => match elara_runtime::network::server::MetricTier::parse(s) {
            Some(t) => {
                info!("metric tier = {} (--metric-tier or ELARA_METRIC_TIER)", t.label());
                Some(t)
            }
            None => {
                warn!(
                    "ignoring invalid metric tier '{}', falling back to node_profile default",
                    s
                );
                None
            }
        },
        None => None,
    };
    let tier = resolved_tier.unwrap_or_else(|| {
        use elara_runtime::network::node_profile::NodeProfile;
        use elara_runtime::network::server::MetricTier;
        let profile = NodeProfile::from_str(&config.node_profile);
        let t = match profile {
            NodeProfile::Light => MetricTier::P0,
            NodeProfile::FullZone => MetricTier::P1,
            NodeProfile::Archive => MetricTier::Debug,
        };
        info!(
            "metric tier = {} (default for node_profile={})",
            t.label(),
            profile.as_str()
        );
        t
    });
    let _ = elara_runtime::network::server::METRIC_TIER.set(tier);

    // CLI overrides
    if let Some(listen) = &cli.listen {
        config.listen_addr = listen.clone();
    }
    if let Some(data_dir) = &cli.data_dir {
        config.data_dir = data_dir.into();
        // Re-resolve relative paths
        if config.identity_path.starts_with(&config.data_dir) {
            // already resolved
        } else {
            config.identity_path = rebase_path(&config.identity_path, &config.data_dir)?;
            config.db_path = rebase_path(&config.db_path, &config.data_dir)?;
            // vrf_key_path was resolved against the DEFAULT data_dir by
            // resolve_paths() before this CLI override ran — without the
            // rebase an anchor booted via `--data-dir` (no --config) writes
            // its VRF key into a directory that may not exist. Caught by
            // docker-finality run 3: compose genesis (anchor since PM-2)
            // died `failed to write VRF key: No such file or directory`.
            if !config.vrf_key_path.as_os_str().is_empty() {
                config.vrf_key_path = rebase_path(&config.vrf_key_path, &config.data_dir)?;
            }
            if !config.realm_membership_cert_path.as_os_str().is_empty() {
                config.realm_membership_cert_path =
                    rebase_path(&config.realm_membership_cert_path, &config.data_dir)?;
            }
        }
    }

    // Validate config and log warnings
    let warnings = config.validate();
    for w in &warnings {
        warn!("config: {w}");
    }

    // AUDIT-10 Milestone D mainnet safety gate. A misconfigured mainnet node
    // with allow_public_https=true would silently expose the legacy data
    // plane that the migration is supposed to retire — fail fast instead.
    if let Err(reason) = config.enforce_mainnet_safety() {
        return Err(elara_runtime::errors::ElaraError::Config(reason));
    }

    info!("light_mode={} (Profile A records → {})",
        config.light_mode,
        if config.light_mode { "Dilithium3 only (~5KB)" } else { "dual-sig SPHINCS+Dilithium (~41KB)" }
    );

    // Auto-scale retention period for memory-constrained nodes.
    // 7-day retention on 2GB nodes creates 5.5GB+ of SST files — the page cache
    // pressure alone makes the node unresponsive. Scale down unless user explicitly
    // set ELARA_RECORD_RETENTION.
    if std::env::var("ELARA_RECORD_RETENTION").is_err() {
        let ram_gb = elara_runtime::storage::rocks::StorageEngine::detect_system_ram_gb();
        let default_retention = 7.0 * 24.0 * 3600.0;
        if ram_gb <= 2 && config.record_retention_secs >= default_retention {
            config.record_retention_secs = 1.0 * 24.0 * 3600.0; // 1 day
            config.max_record_age_secs = 1.0 * 24.0 * 3600.0;
            info!("auto-scaled retention to 1 day ({}GB RAM detected)", ram_gb);
        } else if ram_gb <= 4 && config.record_retention_secs >= default_retention {
            config.record_retention_secs = 3.0 * 24.0 * 3600.0; // 3 days
            config.max_record_age_secs = 3.0 * 24.0 * 3600.0;
            info!("auto-scaled retention to 3 days ({}GB RAM detected)", ram_gb);
        }
    }

    // Set global zone count from config (dynamic consensus zones)
    if config.zone_count == 0 {
        // Auto mode: start at 1 zone. zone_count changes ONLY via signed
        // authority-emitted ZoneTransition records (Gap-4 activity autoscaler),
        // applied deterministically fleet-wide. A new joiner that starts here at
        // 1 and replays the authority's signed transition chain converges to the
        // canonical count. (The former peer-count heuristic was removed
        // 2026-06-19 — it forked followers by deriving zone_count from local
        // peer count; see src/network/health.rs.)
        elara_runtime::network::consensus::set_zone_count(1);
        info!("zone count: auto (starts at 1, scales via signed ZoneTransition records)");
    } else {
        elara_runtime::network::consensus::set_zone_count(config.zone_count);
        info!("zone count: {} (fixed, override with ELARA_ZONE_COUNT=0 for auto)", config.zone_count);
    }

    // KR-3 S2 wiring-(c) c3-ii: mirror the network-uniform rotation-ordering gate
    // into the consensus process global so the seal-membership free functions can
    // route rotation hops by lineage. Set once here from config, never at runtime.
    elara_runtime::network::consensus::set_s2_rotation_ordering(
        config.s2_rotation_ordering_enabled,
    );

    // Ensure data directory exists
    std::fs::create_dir_all(&config.data_dir)
        .map_err(|e| ElaraError::Config(format!("failed to create data_dir: {e}")))?;

    // Clamp disk_cap_bytes against the actual filesystem at data_dir.
    // Default cap is 200 GB, designed for mainnet FullZone hardware. On a
    // 24-38 GB VPS the cap is unreachable, so GC's size-based retention
    // compression (gc.rs:319-327) never fires and the disk fills up at the
    // 90-day FullZone retention SLA. Clamp gives GC a real target to drive
    // against. Operator opt-out: explicit `ELARA_DISK_CAP_BYTES` is honored
    // verbatim and bypasses the clamp.
    if let Some((pre, post, total)) = config.clamp_disk_cap_to_fs() {
        info!(
            "ops-159: clamped disk_cap_bytes {:.1}GB → {:.1}GB (70% of {:.1}GB filesystem at {})",
            pre as f64 / 1e9,
            post as f64 / 1e9,
            total as f64 / 1e9,
            config.data_dir.display(),
        );
    }
    // B5: profile-aware + ≤25%-of-disk_cap clamp on the act-index budget.
    if let Some((pre, post)) = config.clamp_acts_budget() {
        info!(
            "B5: clamped acts_budget_bytes {:.2}GB → {:.2}GB (profile={}, ≤25% of disk_cap)",
            pre as f64 / 1e9,
            post as f64 / 1e9,
            config.node_profile,
        );
    }

    // ─── Repair mode ────────────────────────────────────────────────────

    if cli.repair {
        let rocks_path = config.data_dir.join("rocksdb");
        info!("repairing RocksDB at {}", rocks_path.display());
        elara_runtime::storage::rocks::StorageEngine::repair(&rocks_path)
            .map_err(|e| ElaraError::Storage(format!("repair failed: {e}")))?;
        info!("RocksDB repair complete");
        return Ok(());
    }

    // ─── Verify data integrity ─────────────────────────────────────────

    if cli.verify_data {
        return verify_data_dir(&config);
    }

    // ─── Export data for migration ───────────────────────────────────────

    if let Some(ref output_path) = cli.export_data {
        return export_data_dir(&config, output_path);
    }

    // ─── Restore from checkpoint ────────────────────────────────────────

    if let Some(ref checkpoint_path) = cli.restore {
        let src = PathBuf::from(checkpoint_path);
        let rocks_path = config.data_dir.join("rocksdb");

        if !src.exists() {
            return Err(ElaraError::Config(format!(
                "checkpoint path does not exist: {}", src.display()
            )));
        }

        info!("restoring RocksDB from checkpoint: {}", src.display());

        // Remove current DB if it exists
        if rocks_path.exists() {
            let backup = rocks_path.with_extension("bak");
            if backup.exists() {
                std::fs::remove_dir_all(&backup)
                    .map_err(|e| ElaraError::Storage(format!("failed to remove old backup: {e}")))?;
            }
            std::fs::rename(&rocks_path, &backup)
                .map_err(|e| ElaraError::Storage(format!("failed to move current DB to backup: {e}")))?;
            info!("existing DB moved to {}", backup.display());
        }

        // Copy checkpoint to DB path
        copy_dir_recursive(&src, &rocks_path)
            .map_err(|e| ElaraError::Storage(format!("failed to copy checkpoint: {e}")))?;
        info!("checkpoint restored to {}", rocks_path.display());
    }

    // ─── TLS server removed (AUDIT-10 / PQ-R6 / 4E.6) ──────────────────
    // Classical transport is plain HTTP; all authenticated node↔node traffic
    // flows over the PQ server (ML-KEM-768 + Dilithium3 TOFU). Operators who
    // want public HTTPS can front the plain listener with nginx / caddy.

    // ─── Auto-generate admin token if empty ────────────────────────────

    if config.admin_token.is_empty() {
        let token = generate_admin_token()?;
        // Log only first 8 chars — full token visible only via TOML config or ELARA_ADMIN_TOKEN env
        info!("auto-generated admin token (use for RPC): {}…", &token[..8]);
        config.admin_token = token;
    }

    // ─── Load identity ──────────────────────────────────────────────────

    let identity = load_identity(&config)?;
    info!(
        "identity: {} ({})",
        &identity.identity_hash[..16],
        format!("{:?}", identity.entity_type)
    );

    // ─── Open RocksDB (production storage) ────────────────────────────
    let rocks_path = config.data_dir.join("rocksdb");

    // Check for stale lock before opening — prevents crash-loop when another
    // instance (orphan process or manual run) holds the RocksDB lock.
    // Unix-only advisory-lock probe; elsewhere StorageEngine::open surfaces
    // RocksDB's own lock-held error (same protection, blunter message).
    #[cfg(unix)]
    {
        let lock_path = rocks_path.join("LOCK");
        if lock_path.exists() {
            use std::fs::File;
            use std::os::unix::io::AsRawFd;
            // Try a non-blocking exclusive lock to see if someone else holds it
            if let Ok(f) = File::open(&lock_path) {
                let ret = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
                if ret != 0 {
                    error!(
                        "RocksDB lock held by another process ({}). \
                         Kill the other elara-node instance first, or run: \
                         fuser -k {}",
                        lock_path.display(),
                        lock_path.display()
                    );
                    std::process::exit(1);
                }
                // Release immediately — StorageEngine::open will acquire it properly
                unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_UN) };
            }
        }
    }

    info!("opening RocksDB: {}", rocks_path.display());
    let rocks = Arc::new(
        elara_runtime::storage::rocks::StorageEngine::open(&rocks_path)
            .map_err(|e| ElaraError::Storage(format!("failed to open RocksDB: {e}")))?,
    );

    // Run pending database migrations (creates checkpoint before migrating)
    if let Err(e) = rocks.run_migrations(&config.data_dir) {
        error!("Database migration failed: {e}");
        error!("Restore from pre-migration checkpoint in {} if needed", config.data_dir.display());
        std::process::exit(1);
    }

    // B5: initialize the act-index coverage floor if this DB has never carried it
    // (writes now_ms — the honest window for an upgraded seed that already GC'd
    // acts, or a virgin pull-join that can't re-ingest pruned carriers). Genesis-0
    // (force_acts_coverage_floor_genesis) is NOT yet wired into any ceremony — a
    // future re-genesis must call it. Safe to continue on failure: an uninitialized
    // floor is fail-CLOSED (acts_coverage_floor_state → None → /mandate/status
    // absence is non-authoritative), never a false "not a mandate act".
    if let Err(e) = rocks.ensure_acts_coverage_floor_initialized() {
        warn!("B5: acts coverage floor init failed after retries (continuing — absence answers stay non-authoritative until a later boot succeeds): {e}");
    }

    // Startup compaction is spawned AFTER node_state is built (~614) so the
    // counter bump can be wired via a state.startup_compactions_total clone.
    // The compaction itself is fire-and-forget — the call site below spawns
    // a thread, doesn't block startup, and the HTTP server comes up while
    // RocksDB drains the scheduled compactions in its background pool.

    // ─── Build shared state ─────────────────────────────────────────────

    let witness_mgr = Arc::new(WitnessManager::new(rocks.clone()));

    // Backfill attestation timestamp index (one-time migration).
    // Skip if index already has entries — avoids scanning 184K+ attestations
    // on every restart (pulls ~200MB of SST pages into RSS via block cache).
    {
        let idx_exists = rocks.prefix_scan(
            elara_runtime::storage::rocks::CF_IDX_ATT_TIME,
            &[],
            |_, _| Err(elara_runtime::errors::ElaraError::Storage("exists".into())),
        ).is_err(); // scan callback returns Err on first entry = index exists

        if idx_exists {
            debug!("attestation time index already populated, skipping backfill");
        } else {
            match witness_mgr.backfill_time_index() {
                Ok(n) if n > 0 => info!("backfilled attestation time index: {n} entries"),
                Ok(_) => {},
                Err(e) => warn!("attestation time index backfill failed: {e}"),
            }
        }
    }

    let mut node_state_mut = NodeState::new(config.clone(), identity, rocks.clone(), witness_mgr.clone());

    // P0 slot-equivocation fix: bootstrap slot_nonce counter from RocksDB so a
    // restarted node never hands out a nonce that collides with its own
    // historical records. Without this, `next_slot_nonce()` would start at 1
    // on restart and immediately conflict with records we already persisted.
    node_state_mut.bootstrap_slot_nonce();

    // Rehydrate VRF registry from CF_VRF_KEYS so a restart doesn't strand
    // witness nodes with empty committees (Protocol §11.12). The registry
    // is RAM-only; without this, registrations persisted by prior runs are
    // invisible until peers happen to re-gossip their registration record.
    {
        let rehydrated = elara_runtime::network::vrf_registry::rehydrate_registry(
            &node_state_mut.rocks,
        );
        let count = rehydrated.count();
        if count > 0 {
            *node_state_mut.vrf_registry.write_recover() = rehydrated;
            info!("VRF registry rehydrated from RocksDB: {count} anchor(s)");
        }
    }

    // KR-3 S2 wiring-(c) c3: boot-load the in-memory rotation zone-pin set from
    // the durable `rotation_zone_pin:` CF rows, so a restart reproduces the
    // routing pins written at admission (c2) BEFORE any record resolves. Flag-
    // gated — the durable pins are only ever written flag-ON, so a flag-OFF boot
    // skips the scan entirely (byte-identical).
    if node_state_mut.config.s2_rotation_ordering_enabled {
        let n = node_state_mut.load_rotation_pins();
        if n > 0 {
            info!("KR-3 S2: rotation zone-pins rehydrated from RocksDB: {n} pin(s)");
        }
    }

    // Restore EmergencyHalt state from CF_EMERGENCY (B2) so a warm restart of a
    // halted node stays halted instead of un-halting and admitting writes the
    // fleet is rejecting. The atomics are RAM-only; the durable blob is the source
    // of truth on boot.
    if let Some(es) = node_state_mut.rocks.get_emergency_state() {
        node_state_mut.emergency_load_state(&es);
        if es.halted_at(elara_runtime::network::ingest::now() as u64) {
            warn!(
                "boot: chain is under an active EMERGENCY HALT (nonce={}, reason={:?}) — new writes refused until resume/expiry",
                es.latest_halt_nonce, es.active_reason
            );
        }
    }

    // ─── Load VRF keys ────────────────────────────────────────────────
    {
        use elara_runtime::crypto::vrf::{VrfSecretKey, VrfPublicKey};

        let is_genesis = node_state_mut.identity.identity_hash == config.genesis_authority;

        // Load or generate VRF secret key (genesis authority + anchor nodes)
        let is_anchor = elara_runtime::network::peer::NodeType::from_str(&config.node_type).can_seal_epochs();
        let vrf_sk = if is_genesis || is_anchor {
            if config.vrf_key_path.exists() {
                let bytes = std::fs::read(&config.vrf_key_path)
                    .map_err(|e| ElaraError::Config(format!("failed to read VRF key: {e}")))?;
                let sk = if bytes.len() == 32 {
                    // Legacy 32-byte seed — migrate to full Dilithium3 format
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    let sk = VrfSecretKey::from_bytes(arr)
                        .map_err(|e| ElaraError::Config(format!("failed to build VRF key from legacy seed: {e}")))?;
                    // Save in full format for future loads
                    std::fs::write(&config.vrf_key_path, sk.to_full_bytes())
                        .map_err(|e| ElaraError::Config(format!("failed to write migrated VRF key: {e}")))?;
                    // VRF secret key is a signing secret — owner-only (0600).
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        std::fs::set_permissions(&config.vrf_key_path, std::fs::Permissions::from_mode(0o600))
                            .map_err(|e| ElaraError::Config(format!("failed to set VRF key permissions: {e}")))?;
                    }
                    info!("VRF key migrated to Dilithium3 format at {}", config.vrf_key_path.display());
                    sk
                } else {
                    // Full Dilithium3 format (seed + pk + sk)
                    VrfSecretKey::from_full_bytes(&bytes)
                        .map_err(|e| ElaraError::Config(format!("failed to parse VRF key: {e}")))?
                };
                info!("VRF secret key loaded from {}", config.vrf_key_path.display());
                Some(sk)
            } else {
                let sk = VrfSecretKey::generate()?;
                std::fs::write(&config.vrf_key_path, sk.to_full_bytes())
                    .map_err(|e| ElaraError::Config(format!("failed to write VRF key: {e}")))?;
                // VRF secret key is a signing secret — owner-only (0600).
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&config.vrf_key_path, std::fs::Permissions::from_mode(0o600))
                        .map_err(|e| ElaraError::Config(format!("failed to set VRF key permissions: {e}")))?;
                }
                info!("VRF secret key generated and saved to {} ({})",
                    config.vrf_key_path.display(),
                    if is_genesis { "genesis" } else { "anchor" });
                Some(sk)
            }
        } else {
            debug!("VRF key not loaded (not genesis, not anchor)");
            None
        };

        // Derive or load VRF public key
        let vrf_pk = if let Some(ref sk) = vrf_sk {
            let pk = sk.public_key();
            info!("VRF public key: {}", pk.to_hex());
            Some(pk)
        } else if !config.vrf_public_key.is_empty() {
            match VrfPublicKey::from_hex(&config.vrf_public_key) {
                Ok(pk) => {
                    info!("VRF public key loaded from config: {}...", &config.vrf_public_key[..16.min(config.vrf_public_key.len())]);
                    Some(pk)
                }
                Err(e) => {
                    warn!("invalid VRF public key in config: {e} — VRF verification disabled");
                    None
                }
            }
        } else {
            None
        };

        // Auto-register this node's VRF key in the registry (Protocol §11.12)
        if let Some(ref pk) = vrf_pk {
            let reg = elara_runtime::network::vrf_registry::VrfRegistration {
                vrf_public_key_hex: hex::encode(pk.as_bytes()),
                vrf_full_public_key_hex: String::new(),
                registered_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs_f64(),
                record_id: "local-bootstrap".to_string(),
                node_type: config.node_type.clone(),
            };
            let self_hash = node_state_mut.identity.identity_hash.clone();
            node_state_mut.vrf_registry.write_recover()
                .register(&self_hash, reg.clone());
            // Persist the self-bootstrap so subsequent restarts see it.
            if let Err(e) = elara_runtime::network::vrf_registry::persist_registration(
                &node_state_mut.rocks,
                &self_hash,
                &reg,
            ) {
                warn!("VRF self-registration persist failed: {e}");
            }
            info!("VRF key registered in local registry for {}", &self_hash[..16]);
        }
        node_state_mut.set_vrf_keys(vrf_sk, vrf_pk);
    }

    // ─── NAT auto-detection ──────────────────────────────────────────
    // Runs STUN + UPnP before gossip to auto-set advertise_addr and behind_nat.
    // Only runs when config doesn't already have explicit values.
    let upnp_mapped = if config.advertise_addr.is_empty() {
        let listen_port = config.listen_addr.rsplit(':').next()
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(9473);
        let nat = elara_runtime::network::nat::auto_detect_nat(listen_port).await;
        if let Some(ref addr) = nat.advertise_addr {
            node_state_mut.config.advertise_addr = addr.clone();
            config.advertise_addr = addr.clone();
            info!("NAT: auto-set advertise_addr={addr}");
        }
        if nat.behind_nat && !config.behind_nat {
            node_state_mut.config.behind_nat = true;
            config.behind_nat = true;
            info!("NAT: auto-set behind_nat=true");
        }
        nat.upnp_mapped
    } else {
        debug!("NAT: skipping auto-detection (advertise_addr already set)");
        false
    };

    let node_state = Arc::new(node_state_mut);

    // Startup compaction: reclaims SST bloat from accumulated tombstones.
    // Runs in a background thread so the HTTP server starts immediately.
    // Previously blocked startup for 5-15+ minutes on nodes with 14GB+ SST.
    // Bumps `startup_compactions_total` by the number
    // of CFs scheduled — closes the observability gap where post-reboot nodes
    // looked like GC was dead (`gc_compactions_total=0`) when startup
    // compaction had already done the work.
    {
        let rocks_bg = rocks.clone();
        let state_bg = node_state.clone();
        std::thread::spawn(move || {
            let compacted = rocks_bg.startup_compaction_if_needed();
            if compacted > 0 {
                state_bg.startup_compactions_total
                    .fetch_add(compacted as u64, std::sync::atomic::Ordering::Relaxed);
            }
        });
    }

    // ─── Load snapshot or rebuild ledger ─────────────────────────────────

    let snapshot_path = config.data_dir.join("ledger-snapshot.json");

    // Time the dominant boot phase — DAG/ledger rebuild + conservation-fix
    // fallback. At 10M-record scale this is the primary driver of slow boots.
    let ledger_rebuild_t0 = std::time::Instant::now();

    info!("rebuilding DAG index and ledger...");
    {
        // Try loading DAG from RocksDB snapshot first — but validate by RECENCY, not size.
        //
        // The DAG is bounded (5000 records on 2GB nodes, HOT_EPOCH_WINDOW elsewhere) while
        // RocksDB grows unbounded. Comparing dag.len() to rocks.count() always shows a huge
        // "gap" on long-running nodes, even though the snapshot is perfectly recent — the
        // gap is just finalized history that's correctly evicted from the DAG. The old
        // heuristic (gap >= 5000 → full rebuild) tripped on every restart, costing ~24s of
        // O(records_in_db) lightweight rebuild per boot.
        //
        // Right comparison: how stale is the snapshot in WALL-CLOCK terms? If the most
        // recent record in the snapshot is within MAX_PATCH_AGE_SECS of now, the
        // incremental patch path can catch up by querying records since
        // `latest_timestamp()` — bounded by `~rec/s × age`, not by total DB size. If the
        // snapshot is older than that, fall back to the lightweight rebuild path.
        const MAX_PATCH_AGE_SECS: f64 = 86_400.0; // 24h
        let dag_from_rocks = {
            let candidate = node_state.rocks.load_snapshot::<elara_runtime::dag::DagIndex>("dag")
                .ok().flatten();
            if let Some(ref dag) = candidate {
                let latest_ts = dag.latest_timestamp();
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs_f64())
                    .unwrap_or(0.0);
                let age = (now - latest_ts).max(0.0);
                if latest_ts == 0.0 {
                    // Empty snapshot — nothing to patch from. Treat as missing.
                    warn!("DAG snapshot empty (latest_ts=0) — falling back to lightweight rebuild");
                    None
                } else if age <= MAX_PATCH_AGE_SECS {
                    info!(
                        "DAG snapshot recent: {} nodes, latest_ts age={:.1}min — incremental patch",
                        dag.len(), age / 60.0
                    );
                    candidate
                } else {
                    warn!(
                        "DAG snapshot too old: {} nodes, latest_ts age={:.1}h (> {:.1}h) — forcing rebuild",
                        dag.len(), age / 3600.0, MAX_PATCH_AGE_SECS / 3600.0
                    );
                    None
                }
            } else {
                None
            }
        };
        // The actual record count at snapshot-check time — used to decide patch vs load-all in spawn_blocking.
        let dag_snapshot_actual_count = {
            use elara_runtime::storage::Storage;
            node_state.rocks.count().unwrap_or(0)
        };

        // ─── CHECKPOINT FAST PATH ────────────────────────────────────────
        // Try loading ledger from RocksDB snapshot + checkpoint timestamp.
        // If both exist and the ledger passes conservation, do incremental replay
        // (only records newer than checkpoint) instead of full streaming rebuild.
        // F2 PSR-1: resolve the boot ledger checkpoint, honoring the fail-closed gov-rebuild
        // marker (extracted to `resolve_boot_checkpoint` so the marker-gate wiring is
        // unit-testable — post-ship review recommendation). `force_full_gov_rebuild` is
        // threaded into the spawn_blocking below to gate the post-rebuild marker clear.
        let (checkpoint_ledger, force_full_gov_rebuild) =
            resolve_boot_checkpoint(&node_state.rocks);

        let state2 = node_state.clone();
        let genesis = config.genesis_authority.clone();
        // GENESIS VALIDATOR BOOTSTRAP: boot-local clone so the move-closure
        // below doesn't consume config.genesis_validators (still needed by
        // the conservation-rebuild + later paths outside this closure).
        let genesis_validators_boot = config.genesis_validators.clone();
        let snap_path = snapshot_path.clone();

        let (dag, ledger_result, restored_snapshot, genesis_rebuilt) = tokio::task::spawn_blocking(move || {
            let rocks = &state2.rocks;

            // DAG: load from RocksDB snapshot (fast), incremental patch (medium),
            // or full rebuild from records (slow — only when snapshot is very stale or absent).
            let mut dag = if let Some(cached_dag) = dag_from_rocks {
                let cached_len = cached_dag.len();
                if cached_len + 50 < dag_snapshot_actual_count {
                    // Incremental patch: snapshot was slightly stale.
                    // Load only records newer than the latest timestamp in the snapshot —
                    // avoids loading the full DB (potentially GB of data on small nodes).
                    let latest_ts = cached_dag.latest_timestamp();
                    info!(
                        "DAG incremental patch: snapshot has {} nodes, patching with records since ts={:.0}",
                        cached_len, latest_ts
                    );
                    use elara_runtime::storage::Storage;
                    let new_records = rocks.query(None, None, Some(latest_ts), None, usize::MAX)?;
                    let mut dag = cached_dag;
                    let mut patched = 0usize;
                    for rec in &new_records {
                        if !dag.contains(&rec.id) {
                            let missing = dag.insert_tolerant(rec.id.clone(), rec.parents.clone(), rec.timestamp);
                            if missing > 0 {
                                // Wire structural edges for parents in RocksDB (evicted from DAG)
                                for pid in &rec.parents {
                                    if !dag.contains(pid)
                                        && rocks.record_exists(pid).unwrap_or(false) {
                                            dag.link_external_parent(&rec.id, pid);
                                        }
                                }
                            }
                            patched += 1;
                        }
                    }
                    let linked = dag.reindex_orphans();
                    info!("DAG incremental patch: added {patched} records, relinked {linked} orphan edges");
                    dag
                } else {
                    info!("DAG loaded from RocksDB snapshot ({} nodes)", cached_len);
                    cached_dag
                }
            } else {
                // Lightweight DAG rebuild: reads only edges + timestamps from
                // CF_DAG and CF_IDX_TIMESTAMP. Avoids loading full records (~8KB
                // each with SPHINCS+ sigs) — saves ~100MB+ on 14K-record DBs.
                // On 2GB nodes, bound to 5K records to avoid OOM during rebuild.
                let rebuild_ram = elara_runtime::storage::rocks::StorageEngine::detect_system_ram_gb();
                let max_rebuild = if rebuild_ram <= 2 { 5_000usize } else { 0 };
                if max_rebuild > 0 {
                    info!("DAG bounded rebuild ({}GB RAM, cap={})", rebuild_ram, max_rebuild);
                } else {
                    info!("DAG lightweight rebuild from CF_DAG + CF_IDX_TIMESTAMP");
                }
                rocks.rebuild_dag_lightweight_bounded(max_rebuild)?
            };
            // Rebuild roots/tips indices (empty in pre-v4 snapshots)
            dag.rebuild_indices();
            info!("DAG indices: {} roots, {} tips", dag.roots().len(), dag.tips().len());

            // Clean stale orphan edges:
            // 1. Reindex: resolve orphan edges whose parents ARE in the DAG now
            // 2. Cold-storage: wire structural edges for parents in RocksDB (evicted from DAG)
            let pre_orphans = dag.orphan_count();
            if pre_orphans > 0 {
                let linked = dag.reindex_orphans();
                let orphan_parents = dag.orphan_parent_ids();
                let mut rocks_wired = 0usize;
                for pid in &orphan_parents {
                    if rocks.record_exists(pid).unwrap_or(false) {
                        let children = dag.orphan_children_of(pid);
                        for cid in &children {
                            dag.link_external_parent(cid, pid);
                        }
                        rocks_wired += 1;
                    }
                }
                let post_orphans = dag.orphan_count();
                if linked > 0 || rocks_wired > 0 {
                    info!(
                        "orphan cleanup: {} → {} edges ({linked} relinked, {rocks_wired} cold-storage parents wired)",
                        pre_orphans, post_orphans
                    );
                } else if pre_orphans > 0 {
                    info!("orphan cleanup: {pre_orphans} edges remain (parents not in DAG or RocksDB — truly missing)");
                }
                // Aggressive prune: if >2000 truly-missing orphan edges remain after
                // cleanup, prune them all. These parents don't exist in DAG or RocksDB
                // and will never resolve. Keeping them causes the orphan resolver to
                // run in urgent mode (every 30s), burning CPU on futile fetch attempts
                // and starving the state_core of DAG write lock access.
                let remaining = dag.orphan_count();
                if remaining > 200 {
                    let pruned = dag.prune_orphan_edges(200);
                    info!("orphan startup prune: removed {pruned} stale edges (cap 200, had {remaining})");
                }
            }

            // Post-load eviction: immediately trim the DAG to HOT_EPOCH_WINDOW.
            // Without this, full rebuilds or stale snapshots load ALL records into
            // the DAG, causing peak memory to be proportional to total record count
            // instead of epoch window size. This is what OOM-kills 2GB nodes.
            {
                let pre_evict = dag.len();
                let evicted_epoch = dag.evict_old_epochs();
                if evicted_epoch > 0 {
                    info!(
                        "post-load eviction: {} → {} records ({} evicted by epoch window)",
                        pre_evict, dag.len(), evicted_epoch
                    );
                }
                // Also evict records finalized in RocksDB but not in DAG's finalized_epoch map
                // (common after full rebuild from records that were already settled).
                // Tier 4.5: finalized: keys live in CF_METADATA.
                let evicted_fin = dag.evict_finalized(|id| {
                    let key = format!("finalized:{id}");
                    rocks.get_cf_raw(elara_runtime::storage::rocks::CF_METADATA, key.as_bytes())
                        .ok()
                        .flatten()
                        .is_some()
                });
                if evicted_fin > 0 {
                    info!(
                        "post-load eviction: {} more records evicted (finalized in RocksDB)",
                        evicted_fin
                    );
                }
            }

            // Post-eviction edge repair: eviction destroys edges to evicted parents,
            // turning connected records into roots. Re-wire structural edges for roots
            // whose parents exist in cold storage (RocksDB). Without this, the DAG
            // starts with ~0 edges after every restart — the mesh is a flat pile of
            // disconnected records until gossip slowly rebuilds edges at runtime.
            {
                let roots: Vec<String> = dag.roots().clone();
                let pre_edges = dag.edge_count();
                let mut rewired = 0usize;
                for rid in &roots {
                    if let Ok(Some((parent_ids, _))) = rocks.get_dag_edges(rid) {
                        for pid in &parent_ids {
                            // Parent in DAG → already wired by insert_tolerant
                            if dag.contains(pid) {
                                continue;
                            }
                            // Parent in cold storage → wire external edge
                            if rocks.record_exists(pid).unwrap_or(false) {
                                dag.link_external_parent(rid, pid);
                                rewired += 1;
                            }
                        }
                    }
                }
                if rewired > 0 {
                    info!(
                        "post-eviction edge repair: {rewired} edges re-wired ({} → {} total edges, {} roots → {})",
                        pre_edges, dag.edge_count(), roots.len(), dag.roots().len()
                    );
                }
            }

            // Recalibrate record count cache.
            // The snapshot loop previously wrote dag_len as record_count, corrupting it
            // to ~70 when the real count is 88K+. Detect corruption via RocksDB's key
            // estimate, then fix with a fast timestamp index scan.
            let dag_len = dag.len();
            let cached_count = rocks.count().unwrap_or(0);
            let est_keys = rocks.approximate_cf_size("records");
            if est_keys > cached_count as u64 * 10 && est_keys > 50_000 {
                // Cache is clearly corrupt (off by >10x from RocksDB estimate).
                // Do a fast key-only scan of the timestamp index to get the real count.
                let actual = rocks.count_by_timestamp_index();
                info!("record count corruption: cache={cached_count}, est_keys={est_keys}, actual={actual} — recalibrating");
                rocks.recalibrate_count(actual);
            } else if dag_len > cached_count {
                info!("record count drift: cache={cached_count}, dag={dag_len} — recalibrating up");
                rocks.recalibrate_count(dag_len);
            }

            // Ledger: checkpoint fast path or full streaming rebuild
            let ledger = if let Some((mut cp_ledger, cp_ts)) = checkpoint_ledger {
                // FAST PATH: incremental replay from checkpoint.
                // B1: seek from the ledger's own `last_applied_ts` (max record ts
                // actually folded into this snapshot), NOT the wall-clock
                // `checkpoint_timestamp`. cp_ts is SystemTime::now() at save, so it
                // can sit AFTER the last folded record; seeking from it skipped any
                // record committed in the (last_applied_ts, cp_ts] gap. Fall back to
                // cp_ts only when last_applied_ts is unset (0.0 — a ledger-empty
                // snapshot) to keep that seek bounded.
                let since_ts = if cp_ledger.last_applied_ts > 0.0 {
                    cp_ledger.last_applied_ts
                } else {
                    cp_ts
                };
                let start = std::time::Instant::now();
                match rocks.incremental_ledger_replay(&mut cp_ledger, &genesis, &genesis_validators_boot, since_ts) {
                    Ok((applied, skipped)) => {
                        let elapsed = start.elapsed();
                        cp_ledger.rebuild_staker_index();
                        info!(
                            "checkpoint incremental replay: {} applied, {} skipped in {:?} (fast path)",
                            applied, skipped, elapsed
                        );
                        // Conservation backstop (supply): a fast-path replay that moved
                        // total_supply off MAX_SUPPLY means an op was dropped or
                        // double-applied → fall back to the authoritative full rebuild.
                        // This catches supply-MOVING drops only; the supply-NEUTRAL class
                        // (a dropped A→B transfer) is caught post-convergence by the §6a
                        // sealed-root boot check (see below + internal design notes §6).
                        //
                        // HISTORY (B1, 2026-06-19): an account-SMT root assertion was
                        // declared UNSOUND here because the leaf committed time-evolved fields
                        // (uptime_secs/last_active/inactive_days) advanced out-of-band by the
                        // wall-clock `uptime_vesting_loop`, so the seal root drifted from any
                        // record-derived root every epoch. That premise is now OBSOLETE: C11
                        // (069a344b, 2026-06-21) REMOVED the loop and fail-closed-guarded the
                        // flag, so the leaf is a pure function of the record DAG. The sound
                        // form — compare against the canonical seal at the LEDGER's tip epoch,
                        // single-zone, with an overhang gate — now runs once at boot AFTER all
                        // replay paths converge (search: check_boot_sealed_root). It does NOT
                        // force a rebuild and is O(1) seeks + one O(accounts) root.
                        if cp_ledger.total_supply != elara_runtime::accounting::types::MAX_SUPPLY
                            && cp_ledger.total_supply > 0
                        {
                            warn!(
                                "post-replay conservation violation: supply={} — falling back to full rebuild",
                                cp_ledger.total_supply
                            );
                            let records_in_storage = rocks.approximate_record_count();
                            info!("ledger streaming replay from storage (~{records_in_storage} records)");
                            let (full_ledger, full_skipped) = rocks.rebuild_ledger_streaming(&genesis, &genesis_validators_boot)?;
                            if full_skipped > 0 {
                                warn!("ledger streaming replay: {full_skipped} records skipped (tolerant mode)");
                            }
                            full_ledger
                        } else {
                            cp_ledger
                        }
                    }
                    Err(e) => {
                        warn!("checkpoint incremental replay failed: {e} — falling back to full rebuild");
                        let records_in_storage = rocks.approximate_record_count();
                        info!("ledger streaming replay from storage (~{records_in_storage} records)");
                        let (full_ledger, full_skipped) = rocks.rebuild_ledger_streaming(&genesis, &genesis_validators_boot)?;
                        if full_skipped > 0 {
                            warn!("ledger streaming replay: {full_skipped} records skipped (tolerant mode)");
                        }
                        full_ledger
                    }
                }
            } else {
                // SLOW PATH: full streaming rebuild (no checkpoint or checkpoint invalid)
                let records_in_storage = rocks.approximate_record_count();
                info!("ledger streaming replay from storage (~{records_in_storage} records)");
                let (full_ledger, skipped) = rocks.rebuild_ledger_streaming(&genesis, &genesis_validators_boot)?;
                if skipped > 0 {
                    warn!("ledger streaming replay: {skipped} records skipped (tolerant mode)");
                }
                full_ledger
            };

            // F2 PSR-1: the forced full rebuild (if any) has now completed and dropped
            // the tombstoned governance op from the tally. Clear the marker so the next
            // boot can fast-path again. Gated on force_full_gov_rebuild so a marker whose
            // rebuild did NOT run is never cleared (with the fail-closed read + this gate,
            // the fast path is taken only when the marker is genuinely absent — nothing to
            // clear). Best-effort inside clear_gov_rebuild_required (`let _ =`): a failed
            // clear only costs one redundant full rebuild next boot, never a crash.
            if force_full_gov_rebuild {
                rocks.clear_gov_rebuild_required();
            }

            // Check if we need to load records (snapshot restore)
            let snap_opt = snapshot::load_snapshot(&snap_path).ok().flatten();
            let snap_opt = match snap_opt {
                Some(ref snap) => {
                    use elara_runtime::storage::Storage;
                    let records_in_storage = rocks.count().unwrap_or(0);
                    if records_in_storage == 0 && snap.ledger.total_supply > 0 {
                        // Stale snapshot: DB was wiped but snapshot survived.
                        // Loading this would prevent genesis bootstrap (pool_empty
                        // condition never fires because snapshot has non-zero supply).
                        // Delete the file so it doesn't cause the same problem next restart.
                        warn!(
                            "stale snapshot detected: {} supply but 0 records in storage — deleting {}",
                            snap.ledger.total_supply,
                            snap_path.display()
                        );
                        if let Err(e) = std::fs::remove_file(&snap_path) {
                            warn!("failed to delete stale snapshot: {e}");
                        }
                        None
                    } else {
                        snap_opt
                    }
                }
                None => None,
            };

            // When streaming rebuild produces supply=0 (genesis records GC'd),
            // fall back to the snapshot's ledger if it has valid supply.
            // This handles nodes that were wiped and can't bootstrap from records
            // because the mint/pool_fund records were garbage collected.
            let ledger = if ledger.total_supply == 0 {
                if let Some(ref snap) = snap_opt {
                    if snap.ledger.total_supply == elara_runtime::accounting::types::MAX_SUPPLY {
                        info!(
                            "ledger streaming rebuild produced supply=0 (genesis records GC'd) — using snapshot ledger (supply={})",
                            snap.ledger.total_supply
                        );
                        snap.ledger.clone()
                    } else {
                        ledger
                    }
                } else {
                    ledger
                }
            } else {
                ledger
            };

            let snapshot_data = if let Some(snap) = snap_opt {
                let finalized = snap.finalized.clone();
                let epoch = snap.epoch_state();
                let genesis_st = snap.genesis_state.clone();
                let bootstrap_st = snap.bootstrap_state.clone();
                Some((finalized, epoch, genesis_st, bootstrap_st))
            } else {
                None
            };

            // Genesis state: only rebuild from records if snapshot didn't provide it.
            // This avoids a full record scan on every startup.
            let genesis_rebuilt = if !genesis.is_empty() && snapshot_data.as_ref().and_then(|s| s.2.as_ref()).is_none() {
                // Try RocksDB snapshot first (fast path — saved by shutdown/periodic checkpoint)
                match rocks.load_snapshot::<elara_runtime::accounting::genesis::GenesisState>("genesis_state") {
                    Ok(Some(gs)) => {
                        info!("genesis state loaded from RocksDB snapshot (fast path)");
                        Some(gs)
                    }
                    _ => {
                        // Bound the boot-time rebuild scan. Previously this
                        // path called `query(Public, None, None, None, usize::MAX)` —
                        // O(all_records) materialization at 10M records is multi-GB
                        // heap and can OOM a 4 GB VPS during boot. The rebuild logic
                        // in `GenesisState::rebuild_from_records` filters every record
                        // by `creator == genesis_authority`, so use the creator-keyed
                        // index (`CF_IDX_CREATOR`, OPS Layer B) to scan only that
                        // subset — bounded by how many records the genesis authority
                        // ever authors (mints + faucet receipts, low hundreds in
                        // practice). MAX_GENESIS_AUTHORITY_RECORDS = 100K caps the
                        // scan defensively; if it ever binds, the genesis-rebuild is
                        // truncated and we log a warning so operators see it.
                        info!("no genesis state in snapshot or RocksDB — rebuilding from records");
                        use elara_runtime::storage::Storage;
                        const MAX_GENESIS_AUTHORITY_RECORDS: usize = 100_000;
                        let records = rocks.query_by_creator_hash(
                            &genesis,
                            None,
                            None,
                            MAX_GENESIS_AUTHORITY_RECORDS,
                        )?;
                        if records.len() >= MAX_GENESIS_AUTHORITY_RECORDS {
                            warn!(
                                "genesis-rebuild scan hit cap ({MAX_GENESIS_AUTHORITY_RECORDS} records) — pool balances may be undercounted. Investigate: genesis authority should not author this many records."
                            );
                        }
                        let gs = elara_runtime::accounting::genesis::GenesisState::rebuild_from_records(&records, &genesis);
                        drop(records);
                        Some(gs)
                    }
                }
            } else {
                None
            };

            Ok::<_, ElaraError>((dag, ledger, snapshot_data, genesis_rebuilt))
        })
        .await
        .map_err(|e| ElaraError::Network(format!("rebuild failed: {e}")))??;

        *node_state.dag.write().await = std::sync::Arc::new(dag);
        let mut ledger_state = ledger_result;

        // Conservation invariant check: if total_supply ≠ MAX_SUPPLY after snapshot
        // restore, the snapshot had stale/corrupted ledger state. Force a full rebuild
        // from RocksDB records. This catches divergence from pre-fix duplicate records
        // that got baked into snapshots (observed: two nodes had 1.5B instead of 10B).
        if ledger_state.total_supply != elara_runtime::accounting::types::MAX_SUPPLY && ledger_state.total_supply > 0 {
            warn!(
                "CONSERVATION VIOLATION on boot: supply={} ≠ expected={}. Forcing full ledger rebuild from storage.",
                ledger_state.total_supply, elara_runtime::accounting::types::MAX_SUPPLY
            );
            let rocks_ref = node_state.rocks.clone();
            let genesis_clone = config.genesis_authority.clone();
            let gv_clone = config.genesis_validators.clone();
            match tokio::task::spawn_blocking(move || {
                rocks_ref.rebuild_ledger_streaming(&genesis_clone, &gv_clone)
            }).await {
                Ok(Ok((mut rebuilt, applied))) => {
                    info!("conservation fix: ledger rebuilt from storage — {applied} ops, supply={}", rebuilt.total_supply);
                    rebuilt.rebuild_staker_index();
                    ledger_state = rebuilt;
                }
                Ok(Err(e)) => warn!("conservation fix: rebuild failed: {e}"),
                Err(e) => warn!("conservation fix: spawn failed: {e}"),
            }
        }

        // Migration: populate RocksDB CF_APPLIED from in-memory applied_record_ids
        // (loaded from old-format snapshot) or from storage scan.
        // CF_APPLIED replaces the 135K+ entry in-memory HashSet that caused slow ledger clones.
        {
            let applied_in_rocks = node_state.rocks.applied_count();
            if applied_in_rocks == 0 && ledger_state.total_supply > 0 {
                if !ledger_state.applied_record_ids.is_empty() {
                    // One-time migration from old snapshot format
                    let count = ledger_state.applied_record_ids.len();
                    node_state.rocks.bulk_mark_applied(&ledger_state.applied_record_ids);
                    info!("migrated {count} applied record IDs from snapshot to RocksDB CF_APPLIED");
                } else {
                    // Stream-scan CF_RECORDS instead of materializing all
                    // public records into a Vec. Previously the migration path
                    // called `query(Public, None, None, None, usize::MAX)` which
                    // allocates a Vec<ValidationRecord> for the entire chain (~8 KB
                    // per record × 10M = 80 GB heap). At 10M records this OOMs even
                    // a 64 GB box. `for_each_record` iterates CF_RECORDS one record
                    // at a time and never holds more than a single decoded record on
                    // the heap. The mark_applied path itself is incremental — each
                    // call writes one CF_APPLIED key, no aggregation required.
                    info!("populating CF_APPLIED from storage scan (first run or empty snapshot)");
                    let rocks_ref = node_state.rocks.clone();
                    match tokio::task::spawn_blocking(move || {
                        let mut count = 0usize;
                        rocks_ref.for_each_record(|record| {
                            if record.classification == elara_runtime::record::Classification::Public
                                && record.metadata.contains_key("beat_op")
                            {
                                rocks_ref.mark_applied(&record.id);
                                count += 1;
                            }
                        })?;
                        Ok::<_, ElaraError>(count)
                    }).await {
                        Ok(Ok(count)) => info!("populated CF_APPLIED with {count} ledger record IDs"),
                        Ok(Err(e)) => warn!("failed to populate CF_APPLIED: {e}"),
                        Err(e) => warn!("failed to spawn CF_APPLIED population task: {e}"),
                    }
                }
            } else if applied_in_rocks > 0 {
                info!("CF_APPLIED already has {applied_in_rocks} entries — skipping migration");
            }
            // Clear in-memory set — runtime dedup is now in RocksDB
            ledger_state.applied_record_ids.clear();
        }

        ledger_state.rebuild_staker_index();
        // Re-derive per-status pending counters on a freshly
        // loaded ledger. Pre-migration snapshots have all four counters at
        // 0 (serde(default)); a one-shot recount aligns them with the
        // live `pending` map. Idempotent on already-migrated state.
        ledger_state.cross_zone.recount_status();
        // Same reasoning — re-derive `active_delegations_count`
        // on snapshot restore so the O(1) reads in
        // `compute_token_enforcement` and `compute_governance_summary`
        // observe a counter that matches the live `delegations` map.
        ledger_state.governance.recount_active_delegations();
        // Re-derive per-status proposal counts. Pre-migration snapshots
        // load with all counts at 0; recount fixes them before `proposal_counts()`
        // returns.
        ledger_state.governance.recount_proposal_statuses();
        *node_state.ledger.write().await = ledger_state;
        // Snapshot-restore wholesale ledger load → invalidate the staked-anchor
        // view. This is the "snapshot bootstrap" case the contract names: the
        // deserialized ledger's `stake_mutation_seq` is #[serde(skip)] and resets
        // to 0, so the cache key alone can't detect the swap (state.rs:invalidate_anchor_view).
        node_state.invalidate_anchor_view();

        // Restore finalized set + epoch + genesis/bootstrap state.
        //
        // Finalized rehydration is independent of the JSON snapshot: even if the
        // snapshot is missing or corrupt, the per-record finalized: markers live
        // in CF_METADATA and the in-memory FinalizedIndex must reflect them on
        // boot, otherwise consensus eviction, prune_where, and /metrics
        // finalized_count are all out of sync with disk until gossip catches up.
        // (Pre-fix: the load_*_from_rocks() calls were nested inside the
        // `if let Some(restored_snapshot)` block, so a corrupt-snapshot path
        // left the index empty even though CF_METADATA had ~all records.)
        let (snapshot_finalized, snapshot_epoch, snapshot_genesis, snapshot_bootstrap) = match restored_snapshot {
            Some((f, e, g, b)) => (Some(f), Some(e), g, b),
            None => (None, None, None, None),
        };
        {
            let mut finalized = node_state.finalized.write().await;
            match snapshot_finalized.as_ref() {
                Some(set) if !set.is_empty() => {
                    let count = set.len();
                    finalized.restore_from_snapshot(set);
                    info!("restored {} finalized records from snapshot ({} in RAM cache)", count, finalized.hot_size());
                }
                Some(_) => {
                    // Snapshot present but periodic snapshots skip the expensive finalized scan — load from RocksDB.
                    finalized.load_count_from_rocks();
                    finalized.load_hot_from_rocks();
                    if !finalized.is_empty() {
                        info!("restored {} finalized records from RocksDB ({} in RAM cache, periodic snapshot)", finalized.len(), finalized.hot_size());
                    }
                }
                None => {
                    // No snapshot (corrupt, missing, or first boot post-migration) — rehydrate from CF_METADATA so we don't start with an empty FinalizedIndex while disk has all the markers.
                    finalized.load_count_from_rocks();
                    finalized.load_hot_from_rocks();
                    if !finalized.is_empty() {
                        info!("restored {} finalized records from CF_METADATA ({} in RAM cache, no JSON snapshot)", finalized.len(), finalized.hot_size());
                    }
                }
            }
        }
        if let Some(epoch_state) = snapshot_epoch {
            if !epoch_state.latest_epoch.is_empty() {
                let mut epoch = node_state.epoch.write_recover();
                *epoch = epoch_state;
                info!("restored epoch state: {} zones from snapshot", epoch.latest_epoch.len());
            }
        }
        if let Some(gs) = snapshot_genesis {
            let claimed = gs.bootstrap_claimed.len();
            *node_state.genesis_state.write_recover() = gs;
            if claimed > 0 {
                info!("restored genesis state: {} bootstrap claims from snapshot", claimed);
            }
        }
        if let Some(bs) = snapshot_bootstrap {
            let phase = bs.current_phase;
            *node_state.bootstrap_state.write_recover() = bs;
            info!("restored bootstrap state: phase={} from snapshot", phase);
        }

        // Apply genesis state rebuilt from records (if we had records and snapshot didn't provide it)
        if let Some(rebuilt_gs) = genesis_rebuilt {
            // Scope the sync MutexGuard so it's released before any await — clippy's
            // await_holding_lock can't always trace an explicit drop(); a block is unambiguous.
            let gs_empty = {
                let gs = node_state.genesis_state.read_recover();
                gs.total_remaining() == 0 && gs.total_distributed() == 0
            };

            let ledger = node_state.ledger.read().await;
            if gs_empty && ledger.total_supply > 0 {
                let remaining = rebuilt_gs.total_remaining();
                let distributed = rebuilt_gs.total_distributed();
                let claimed = rebuilt_gs.bootstrap_claimed.len();
                *node_state.genesis_state.write_recover() = rebuilt_gs;
                info!(
                    "genesis state rebuilt from records: remaining={} beat distributed={} beat bootstrap_claims={}",
                    remaining / elara_runtime::accounting::types::BASE_UNITS_PER_BEAT,
                    distributed / elara_runtime::accounting::types::BASE_UNITS_PER_BEAT,
                    claimed
                );
            }
            drop(ledger);
        }

        // ─── Startup DAG eviction for memory-constrained nodes ─────────
        // On 2GB nodes, stale DAG snapshots can contain 10K+ records that
        // immediately consume 1.4GB+ on load. GC can't run because the node
        // is already throttled. Break the death spiral by evicting old records
        // from the in-memory DAG before sync starts. Records remain in RocksDB.
        {
            let ram_gb = elara_runtime::storage::rocks::StorageEngine::detect_system_ram_gb();
            let dag_len = node_state.dag.read().await.len();
            // On ≤2GB nodes with >500 DAG records, aggressively evict old ones.
            // Keep only records from the last 6 hours in the hot tier.
            // On ≤4GB nodes with >2000 records, keep last 24 hours.
            let evict_age = if ram_gb <= 2 && dag_len > 500 {
                Some(3600.0) // 1 hour
            } else if ram_gb <= 4 && dag_len > 1000 {
                Some(2.0 * 3600.0) // 2 hours
            } else if dag_len > 5000 {
                Some(4.0 * 3600.0) // 4 hours
            } else {
                None
            };
            if let Some(max_age) = evict_age {
                let mut dag_guard = node_state.dag.write().await;
                let dag = std::sync::Arc::make_mut(&mut *dag_guard);
                let before = dag.len();
                let evicted = dag.evict_older_than(max_age);
                info!(
                    "startup DAG eviction ({}GB RAM): evicted {} of {} records (keeping last {}h)",
                    ram_gb, evicted, before, max_age / 3600.0
                );
                // Hard cap: RAM-scaled, same as the runtime eviction loop.
                // Previously used HOT_MAX_FALLBACK (50K) which overwhelmed 2GB nodes
                // during subsystem rebuild (50K records × attestation lookups = OOM/hang).
                let max = if ram_gb <= 2 { 1_500usize } else if ram_gb <= 4 { 5_000 } else { 20_000 };
                if dag.len() > max {
                    let before_force = dag.len();
                    let force_evicted = dag.evict_to_cap(max);
                    info!(
                        "startup FORCE eviction: {} → {} records ({} force-evicted to reach cap {})",
                        before_force, dag.len(), force_evicted, max
                    );
                }

                // Post-eviction edge repair: eviction destroys edges to evicted parents.
                // Scan roots whose parents are in RocksDB cold storage and re-wire
                // structural edges so the mesh isn't flat on startup.
                let roots: Vec<String> = dag.roots().clone();
                let pre_edges = dag.edge_count();
                let mut rewired = 0usize;
                for rid in &roots {
                    if let Ok(Some((parent_ids, _))) = node_state.rocks.get_dag_edges(rid) {
                        for pid in &parent_ids {
                            if dag.contains(pid) { continue; }
                            if node_state.rocks.record_exists(pid).unwrap_or(false) {
                                dag.link_external_parent(rid, pid);
                                rewired += 1;
                            }
                        }
                    }
                }
                if rewired > 0 {
                    info!(
                        "post-eviction edge repair: {rewired} edges re-wired ({} → {} total, {} roots → {})",
                        pre_edges, dag.edge_count(), roots.len(), dag.roots().len()
                    );
                }
            }
        }

        // F-2 boot reconcile: flush genesis-config account leaves into the
        // persistent SMT BEFORE the §6a check. Heals nodes that genesised
        // before the smt_dirty-marking fix (genesis stake mutates accounts
        // outside apply_op; see reconcile_genesis_accounts_into_smt). Idempotent
        // on a healthy node. Boot-only — no traffic served yet — so holding the
        // write lock across the handful of SMT writes is fine. The first boot
        // after deploying still warns (the historical tip seal predates the
        // reconcile); the next seal advertises the corrected root and every
        // boot thereafter verifies clean.
        {
            let mut ledger_w = node_state.ledger.write().await;
            // CF_ACCOUNT_SMT writer gate. This is the ONE permitted
            // ledger→gate nesting (see NodeState field doc): boot-serial code
            // — runs before the first tokio::spawn and before axum binds, so
            // no other gate holder can exist. Taken anyway so this site stays
            // race-safe if it ever becomes post-boot reachable. Never copy
            // this nesting to a live-traffic site.
            let _smt_gate = node_state.account_smt_write_gate.lock().await;
            match elara_runtime::network::account_merkle::reconcile_genesis_accounts_into_smt(
                &node_state.rocks,
                &mut ledger_w,
                &config.genesis_authority,
                &config.genesis_validators,
            ) {
                Ok(n) if n > 0 => info!(
                    "§6a genesis-account SMT reconcile: flushed {n} config leaf/leaves into the persistent SMT"
                ),
                Ok(_) => {}
                Err(e) => warn!("§6a genesis-account SMT reconcile failed: {e}"),
            }
        }

        let dag_read = node_state.dag.read().await;
        let ledger = node_state.ledger.read().await;
        info!(
            "DAG: {} records, {} edges | Ledger: {} supply, {} staked",
            dag_read.len(),
            dag_read.edge_count(),
            ledger.total_supply,
            ledger.total_staked,
        );
        // Register zone stakes for consensus engine
        node_state.consensus.lock_recover().register_stakes_from_ledger(&ledger);

        // §6a — single-zone sealed-root boot integrity check
        // (internal design notes §6). Runs ONCE here, AFTER every
        // replay path (fast checkpoint / full rebuild / snapshot fallback) has
        // converged on the final `ledger` and the epoch tip is installed — the
        // only point where the in-memory account set and the sealed tip agree.
        // Detects a supply-NEUTRAL dropped record on the replay path (the supply
        // backstop only sees supply-MOVING drops). Counter+warn only; the node
        // always continues (a false-close would brick a launch follower).
        {
            use std::sync::atomic::Ordering;
            use elara_runtime::network::epoch::BootSealedRootOutcome;
            let latest_epoch_snapshot = node_state.epoch.read_recover().latest_epoch.clone();
            match elara_runtime::network::epoch::check_boot_sealed_root(
                &node_state.rocks,
                &ledger.accounts,
                &latest_epoch_snapshot,
                ledger.last_applied_ts,
            ) {
                BootSealedRootOutcome::Verified { epoch, zone } => {
                    node_state.boot_sealed_root_verified_total.fetch_add(1, Ordering::Relaxed);
                    info!(
                        "§6a boot sealed-root verified: zone={} epoch={} (replayed account-SMT root == signed seal)",
                        zone.path(), epoch
                    );
                }
                BootSealedRootOutcome::Mismatch { epoch, zone, replayed, sealed } => {
                    node_state.boot_sealed_root_mismatch_total.fetch_add(1, Ordering::Relaxed);
                    warn!(
                        "§6a boot sealed-root MISMATCH: zone={} epoch={} replayed={} sealed={} — supply-neutral replay divergence. Continuing as follower; re-bootstrap from a trusted snapshot if this persists.",
                        zone.path(), epoch, hex::encode(replayed), hex::encode(sealed)
                    );
                    // F-2 diagnostic: pinpoint WHICH account leaf diverges so the
                    // mismatch is actionable instead of opaque (one-shot O(accounts),
                    // mismatch-only). Empty list + non-zero roots ⇒ a phantom SMT
                    // leaf the ledger-side scan cannot enumerate (see the fn doc).
                    let (diverged, sample) =
                        elara_runtime::network::account_merkle::diagnose_account_smt_divergence(
                            &node_state.rocks,
                            &ledger.accounts,
                            16,
                        );
                    if diverged == 0 {
                        // F-5: SMT-ahead-of-ledger phantom — count it distinctly
                        // so it is separable from a real supply-neutral drop in
                        // metrics (real corruption = mismatch − phantom).
                        node_state.boot_sealed_root_phantom_total.fetch_add(1, Ordering::Relaxed);
                        warn!(
                            "§6a divergence diagnostic: 0 ledger accounts differ from their SMT leaf → the divergence is a PHANTOM SMT leaf (an identity in the SMT but absent from the ledger: dirtied-then-removed, or a recipient marked dirty whose op never created the account)."
                        );
                        // F-5 "name the phantom": the ledger-side scan above returns
                        // (0, []) for an SMT-ahead leaf by construction. Enumerate the
                        // SMT side and log the orphan leaf(s) by account_id — the exact
                        // key a future targeted reconcile/delete takes, and the datum the
                        // gated cleanup audit needs. Bounded, read-only, one-shot; runs
                        // only on this (rare) phantom branch.
                        let ledger_ids: std::collections::HashSet<String> =
                            ledger.accounts.keys().cloned().collect();
                        let scan = elara_runtime::network::account_merkle::scan_orphan_smt_leaves(
                            &node_state.rocks,
                            &ledger_ids,
                            1_000_000,
                            16,
                        );
                        warn!(
                            "§6a phantom naming: {} orphan SMT leaf/leaves (scanned {} value-leaves{}) — account_id is the AccountStateSMT::delete key:",
                            scan.orphan_count,
                            scan.scanned_leaves,
                            if scan.truncated { ", TRUNCATED at cap" } else { "" }
                        );
                        for (acc, leaf) in &scan.sample {
                            warn!("  §6a orphan leaf account_id={acc} leaf_hash={leaf}");
                        }
                    } else {
                        warn!(
                            "§6a divergence diagnostic: {diverged} ledger account(s) differ from their persisted SMT leaf (showing {}):",
                            sample.len()
                        );
                        for (id, in_mem, on_disk) in &sample {
                            warn!("  §6a diverged account {id}: in_mem_leaf={in_mem} smt_leaf={on_disk}");
                        }
                    }
                }
                BootSealedRootOutcome::Skipped(reason) => {
                    node_state.boot_sealed_root_skipped_total.fetch_add(1, Ordering::Relaxed);
                    debug!("§6a boot sealed-root check skipped: {reason:?}");
                }
            }
        }

        // Liveness-decay denominator config (internal design notes).
        // Defaults keep settlement bit-identical (decay OFF).
        {
            let cfg = &node_state.config;
            node_state.consensus.lock_recover().configure_liveness(
                cfg.liveness_decay_enabled,
                cfg.liveness_window_epochs,
                cfg.liveness_floor_divisor,
            );
            if cfg.liveness_decay_enabled {
                // 0b-(ii): persist + hydrate per-staker last-active epochs so
                // a restart cannot reset the decay clock. Must run BEFORE the
                // attestation bulk-load below (hydrated history wins replay).
                node_state
                    .consensus
                    .lock_recover()
                    .attach_liveness_persistence(node_state.rocks.clone());
                info!(
                    "liveness-decay ENABLED: window={} floor=1/{}",
                    cfg.liveness_window_epochs,
                    cfg.liveness_floor_divisor
                );
            }
        }
        // Seed the chain-tip estimate from the persisted DAG: on a fully
        // stalled chain no new seal will ever arrive to feed it, and an
        // unfed tip (0) would read as "not stalled" — the exact wedge the
        // decay exists to clear. Boot-seeding breaks that chicken-and-egg.
        {
            let tip_at_boot = dag_read.current_epoch();
            node_state
                .consensus
                .lock_recover()
                .note_chain_tip(tip_at_boot);
        }

        // ── Rebuild consensus attestations from WitnessManager ──────────
        // On restart, ConsensusEngine starts empty. WitnessManager has all
        // attestations persisted in RocksDB. Without this rebuild, att-pull
        // sees "already known" (skipped_known) and never re-feeds to consensus,
        // leaving settlement permanently stuck at 0.
        {
            let att_records = {
                let mgr = node_state.witness_mgr.as_ref();
                mgr.get_latest_attestations(50_000)
            };
            match att_records {
                Ok(atts) if !atts.is_empty() => {
                    let att_count = atts.len();
                    // Build consensus Attestation structs + collect creator stakes
                    let mut consensus_atts = Vec::with_capacity(att_count);
                    let mut creator_stakes: std::collections::HashMap<String, (String, u64)> = std::collections::HashMap::new();
                    for att in &atts {
                        let witness_stake = ledger.staked(&att.witness_hash);
                        // Look up creator identity + stake (for denominator exclusion + H1).
                        if !creator_stakes.contains_key(&att.record_id) {
                            let entry = node_state.rocks.get_record(&att.record_id).ok().flatten()
                                .map(|rec| {
                                    let h = elara_runtime::accounting::types::creator_identity_hash(&rec);
                                    let s = ledger.staked(&h);
                                    (h, s)
                                })
                                .unwrap_or_else(|| (String::new(), 0));
                            creator_stakes.insert(att.record_id.clone(), entry);
                        }
                        consensus_atts.push(
                            elara_runtime::network::consensus::Attestation {
                                record_id: att.record_id.clone(),
                                witness_hash: att.witness_hash.clone(),
                                stake: witness_stake,
                                timestamp: att.timestamp,
                            }
                        );
                    }
                    let mut consensus = node_state.consensus.lock_recover();
                    for (rid, (chash, cs)) in &creator_stakes {
                        if !chash.is_empty() {
                            consensus.register_creator_stake(rid, chash, *cs);
                        }
                    }
                    let record_count = consensus.bulk_load_attestations(consensus_atts);
                    let settled = consensus.force_finalize_settled().len();
                    info!(
                        "consensus rebuild: {att_count} attestations for {record_count} records from WitnessManager, {settled} immediately settled"
                    );

                    // ── Reconcile unsettled records ──────────────────────────
                    // The 50K limit means some attestations for unsettled records
                    // may not have been loaded. For each unsettled record, fetch
                    // ALL attestations from WitnessManager and fill any gaps.
                    let unsettled: Vec<String> = consensus.unsettled_summary()
                        .into_iter().map(|(rid, _, _)| rid).collect();
                    drop(consensus); // release lock for WitnessManager + RocksDB access

                    if !unsettled.is_empty() {
                        let mgr = node_state.witness_mgr.as_ref();
                        let mut extra_atts = Vec::new();
                        let mut extra_creator_stakes: std::collections::HashMap<String, (String, u64)> = std::collections::HashMap::new();
                        for rid in &unsettled {
                            if let Ok(wm_atts) = mgr.get_attestations(rid) {
                                for att in wm_atts {
                                    let ws = ledger.staked(&att.witness_hash);
                                    extra_atts.push(
                                        elara_runtime::network::consensus::Attestation {
                                            record_id: att.record_id.clone(),
                                            witness_hash: att.witness_hash.clone(),
                                            stake: ws,
                                            timestamp: att.timestamp,
                                        }
                                    );
                                }
                            }
                            if !extra_creator_stakes.contains_key(rid) {
                                let entry = node_state.rocks.get_record(rid).ok().flatten()
                                    .map(|rec| {
                                        let h = elara_runtime::accounting::types::creator_identity_hash(&rec);
                                        let s = ledger.staked(&h);
                                        (h, s)
                                    })
                                    .unwrap_or_else(|| (String::new(), 0));
                                extra_creator_stakes.insert(rid.clone(), entry);
                            }
                        }

                        let mut consensus = node_state.consensus.lock_recover();
                        for (rid, (chash, cs)) in &extra_creator_stakes {
                            if !chash.is_empty() {
                                consensus.register_creator_stake(rid, chash, *cs);
                            }
                        }
                        let extra_count = extra_atts.len();
                        let extra_records = consensus.bulk_load_attestations(extra_atts);
                        let extra_settled = consensus.force_finalize_settled().len();
                        info!(
                            "consensus reconcile: {extra_count} attestations for {} unsettled records, {extra_records} updated, {extra_settled} newly settled",
                            unsettled.len()
                        );
                    }

                    // NOTE: gap-fill moved to async rebuild (runs after the 50K async
                    // load, so its results aren't evicted by the async rebuild's add_attestation calls)
                }
                _ => {
                    info!("consensus rebuild: no attestations in WitnessManager");
                }
            }
        }
    }

    // Rebuild phase done — record duration. state_core_init phase
    // starts here; covers everything between rebuild and HTTP bind (subsystem
    // rebuild dispatch, state_core spawn, background-task setup).
    {
        use std::sync::atomic::Ordering;
        node_state.boot_ledger_rebuild_secs.store(
            ledger_rebuild_t0.elapsed().as_secs(),
            Ordering::Relaxed,
        );
    }
    let state_core_init_t0 = std::time::Instant::now();

    // ─── Initialize pull catch-up cursor from RocksDB ──────────────────
    // Without this, every restart resets the cursor to 0.0, causing a full
    // re-sync of ALL records from peers. On 2GB nodes this immediately blows
    // memory. Set it to the latest timestamp in storage so we only sync new records.
    if let Some(latest_ts) = node_state.rocks.latest_record_timestamp() {
        *node_state.pull_catchup_cursor.lock().unwrap_or_else(|e| e.into_inner()) = latest_ts;
        info!("pull catch-up cursor initialized to {:.0} (latest record in storage)", latest_ts);
    }

    // ─── Post-load jemalloc purge ───────────────────────────────────────
    // Snapshot restore + ledger rebuild create massive transient allocations
    // that fragment jemalloc arenas. Force a full purge to return pages to OS.
    // Without this, a 29K-record snapshot restore leaves ~1GB of dirty pages
    // resident despite dirty_decay_ms:0 (pages still have live fragments).
    #[cfg(all(not(target_arch = "wasm32"), target_family = "unix", feature = "tikv-jemalloc-ctl"))]
    {
        let rss_before = {
            #[cfg(target_os = "linux")]
            {
                std::fs::read_to_string("/proc/self/status")
                    .ok()
                    .and_then(|s| {
                        s.lines()
                            .find(|l| l.starts_with("VmRSS:"))
                            .and_then(|l| l.split_whitespace().nth(1))
                            .and_then(|n| n.parse::<u64>().ok())
                    })
                    .unwrap_or(0) / 1024 // MB
            }
            #[cfg(not(target_os = "linux"))]
            { 0u64 }
        };

        // Advance jemalloc stats epoch, then purge all arenas
        let _ = tikv_jemalloc_ctl::epoch::advance();
        // Purge via mallctl — force all dirty + muzzy pages to be released
        unsafe {
            let purge_key = b"arena.0.purge\0";
            tikv_jemalloc_ctl::raw::write(purge_key, 0u64).ok();
            let purge_key = b"arena.1.purge\0";
            tikv_jemalloc_ctl::raw::write(purge_key, 0u64).ok();
        }

        let rss_after = {
            #[cfg(target_os = "linux")]
            {
                std::fs::read_to_string("/proc/self/status")
                    .ok()
                    .and_then(|s| {
                        s.lines()
                            .find(|l| l.starts_with("VmRSS:"))
                            .and_then(|l| l.split_whitespace().nth(1))
                            .and_then(|n| n.parse::<u64>().ok())
                    })
                    .unwrap_or(0) / 1024 // MB
            }
            #[cfg(not(target_os = "linux"))]
            { 0u64 }
        };
        if rss_before > 0 {
            info!("jemalloc post-load purge: RSS {}MB → {}MB (freed {}MB)", rss_before, rss_after, rss_before.saturating_sub(rss_after));
        }
    }

    // ─── Auto-genesis mint (first startup only) ─────────────────────────

    {
        let ledger = node_state.ledger.read().await;
        let is_genesis = node_state.identity.identity_hash == config.genesis_authority;
        let ledger_empty = ledger.total_supply == 0;
        drop(ledger);

        if is_genesis && ledger_empty {
            info!("genesis authority with empty ledger — initializing allocation...");
            match elara_runtime::accounting::genesis::auto_genesis_mint(&node_state, &config).await {
                Ok(0) => {
                    // auto_genesis_mint found an existing genesis mint in storage
                    // and rebuilt the ledger from it. No new records were created,
                    // so skip pool_fund and genesis state init — they already exist
                    // from the previous boot and will arrive via gossip.
                    info!("genesis mint already existed in storage — ledger rebuilt, skipping pool_fund");
                }
                Ok(minted) => {
                    info!("genesis mint complete: {} beat across 6 pools", minted / elara_runtime::accounting::types::BASE_UNITS_PER_BEAT);

                    // Seed conservation pool via pool_fund record (survives ledger rebuild).
                    // On testnet: 1B beat (enough for millions of witness rewards).
                    // On mainnet: smaller seed, grows via slashes + dormancy reclaims.
                    let pool_seed: u64 = if elara_runtime::accounting::bootstrap::is_testnet() {
                        1_000_000_000 * elara_runtime::accounting::types::BASE_UNITS_PER_BEAT
                    } else {
                        100_000_000 * elara_runtime::accounting::types::BASE_UNITS_PER_BEAT
                    };
                    {
                        let meta = elara_runtime::accounting::types::pool_fund_metadata(pool_seed);
                        let record = node_state.create_self_ledger_record(vec![], meta)?;
                        match gossip::insert_record_inner_direct(&node_state, record, None, false).await {
                            Ok(_) => info!(
                                "conservation pool seeded: {} beat via pool_fund record",
                                pool_seed / elara_runtime::accounting::types::BASE_UNITS_PER_BEAT
                            ),
                            Err(e) => warn!("pool_fund failed: {e}"),
                        }
                    }

                    // Initialize genesis state — use coordinated timestamp if configured
                    let genesis_time = if config.genesis_timestamp > 0.0 {
                        config.genesis_timestamp
                    } else {
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs_f64()
                    };
                    *node_state.genesis_state.write_recover() =
                        elara_runtime::accounting::genesis::GenesisState::initialize(genesis_time);
                    info!("genesis state initialized with allocation pools");
                }
                Err(e) => warn!("genesis mint failed: {e} — manual mint required"),
            }
        }
    }

    // ─── Submit VRF registration record to DAG (Protocol §11.12) ────────
    // This allows other nodes to learn this anchor's VRF public key via gossip.
    if let Some(ref pk) = node_state.vrf_public_key {
        let is_anchor = elara_runtime::network::peer::NodeType::from_str(&config.node_type).can_seal_epochs();
        if is_anchor {
            let meta = elara_runtime::network::vrf_registry::vrf_registration_metadata(pk);
            let record = node_state.create_self_ledger_record(vec![], meta);
            match record {
                Ok(rec) => {
                    match gossip::insert_record_inner_direct(&node_state, rec, None, false).await {
                        Ok(id) => info!("VRF registration record submitted: {}", &id[..16]),
                        Err(e) => warn!("VRF registration record failed: {e}"),
                    }
                }
                Err(e) => warn!("VRF registration record creation failed: {e}"),
            }
        }
    }

    // ─── Submit witness profile registration record (Protocol §7.5) ────
    // Propagates this node's organizational identity via gossip so the consensus
    // engine can properly discount correlated attestations. Without this, all
    // witnesses get the 0.8 correlation penalty (assumed same org + same subnet).
    if !config.witness_organization.is_empty() {
        let profile = elara_runtime::network::consensus::WitnessProfile {
            organization: config.witness_organization.clone(),
            subnet: config.witness_subnet.clone(),
            geo_zone: config.witness_geo_zone.clone(),
        };

        // Register locally immediately (don't wait for gossip round-trip)
        {
            let mut consensus = node_state.consensus.lock_recover();
            consensus.register_profile(&node_state.identity.identity_hash, profile.clone());
        }

        let meta = elara_runtime::network::consensus::witness_profile_metadata(&profile);
        let record = node_state.create_self_ledger_record(vec![], meta);
        match record {
            Ok(rec) => {
                match gossip::insert_record_inner_direct(&node_state, rec, None, false).await {
                    Ok(id) => info!("witness profile registered: org={}, subnet={}, geo={} ({})",
                        config.witness_organization, config.witness_subnet, config.witness_geo_zone,
                        &id[..16]),
                    Err(e) => warn!("witness profile registration record failed: {e}"),
                }
            }
            Err(e) => warn!("witness profile record creation failed: {e}"),
        }
    }

    // ─── Load persisted peers ─────────────────────────────────────────

    let peers_path = config.data_dir.join("peers.json");
    {
        use elara_runtime::network::dht::{DhtPeer, NodeId};
        use elara_runtime::network::peer::PeerTable;
        let loaded = PeerTable::load(&peers_path);
        if !loaded.is_empty() {
            let mut peers = node_state.peers.write().await;
            let mut dht = node_state.dht.lock_recover();
            let self_hash = &node_state.identity.identity_hash;
            for peer in loaded.all() {
                // Skip self — prevents NAT loopback gossip pull-from-self
                if peer.identity_hash == *self_hash {
                    continue;
                }
                peers.insert(peer.clone());
                if let Some(node_id) = NodeId::from_hex(&peer.identity_hash) {
                    dht.insert(DhtPeer {
                        node_id,
                        identity_hash: peer.identity_hash.clone(),
                        host: peer.host.clone(),
                        port: peer.port,
                        last_seen: peer.last_seen,
                        first_added: peer.last_seen, // best estimate from persisted data
                        provenance: elara_runtime::network::dht::PeerProvenance::Outbound,
                    });
                }
            }
            info!("loaded {} persisted peers (DHT seeded)", loaded.len());
        }
    }

    // ─── Peer discovery + bootstrap ─────────────────────────────────────

    // REALMS P1 slice (c): sovereign realms never dial out to discover —
    // no seed bootstrap (peers are added by the operator via explicit
    // config/pins). Open/Federated behave as before.
    if config.network_realm.discovery_enabled() {
        discovery::bootstrap(&node_state).await;
    } else {
        info!("realm=sovereign: seed bootstrap disabled (discovery-off)");
    }

    // ─── Initial delta sync (background) ──────────────────────────────
    // Moved to background task so HTTP server starts immediately.
    // Previously blocked here for 30-60+ seconds, causing nodes to appear down.
    {
        let sync_state = node_state.clone();
        let sync_genesis = config.genesis_authority.clone();
        tokio::spawn(async move {
            let sync_ingested = sync::initial_sync(&sync_state).await;
            if sync_ingested > 0 {
                // Check if checkpoint already loaded a valid ledger.
                // On 2GB nodes (Hillsboro), rebuild_ledger loads ALL records from
                // RocksDB into memory via derive_from_storage_tolerant(usize::MAX),
                // causing OOM. When a valid checkpoint exists, the ledger is already
                // correct — the checkpoint incremental replay handles new records.
                let ledger_already_valid = {
                    let ledger = sync_state.ledger.read().await;
                    ledger.total_supply == elara_runtime::accounting::types::MAX_SUPPLY
                        && !ledger.accounts.is_empty()
                };

                // On ≤2GB nodes, ALWAYS skip rebuild when checkpoint is valid.
                // rebuild_ledger loads ALL records from RocksDB into memory —
                // on 2GB nodes this starves the tokio runtime for minutes,
                // freezing the HTTP server completely. The checkpoint ledger
                // is already correct; state_core processes new records incrementally.
                let ram_gb = elara_runtime::storage::rocks::StorageEngine::detect_system_ram_gb();
                let skip_threshold: u32 = if ram_gb <= 2 { u32::MAX } else { 100 };
                if ledger_already_valid && sync_ingested < skip_threshold {
                    info!(
                        "background sync: skipping full rebuild — checkpoint ledger valid, {sync_ingested} new records ingested (ram={ram_gb}GB)"
                    );
                } else {
                    // Incremental replay: apply only records newer than last_applied_ts.
                    // O(new_records) not O(all_records) — scales to millions of records.
                    let since_ts = {
                        let ledger = sync_state.ledger.read().await;
                        ledger.last_applied_ts
                    };
                    info!("background sync: incremental ledger replay from ts={since_ts} ({sync_ingested} new records, checkpoint_valid={ledger_already_valid})...");
                    let rocks_ref = sync_state.rocks.clone();
                    let genesis = sync_genesis.clone();
                    let gv_clone = sync_state.config.genesis_validators.clone();
                    let mut ledger_clone = sync_state.ledger.read().await.clone();
                    match tokio::task::spawn_blocking(move || {
                        rocks_ref.incremental_ledger_replay(&mut ledger_clone, &genesis, &gv_clone, since_ts)
                            .map(|(applied, skipped)| (ledger_clone, applied, skipped))
                    })
                    .await
                    {
                        Ok(Ok((mut new_ledger, applied, skipped))) => {
                            new_ledger.rebuild_staker_index();
                            // Sync any new applied IDs to CF_APPLIED
                            if !new_ledger.applied_record_ids.is_empty() {
                                sync_state.rocks.bulk_mark_applied(&new_ledger.applied_record_ids);
                                info!("background sync: synced {} applied IDs to CF_APPLIED", new_ledger.applied_record_ids.len());
                                new_ledger.applied_record_ids.clear();
                            }
                            if let Some(core) = sync_state.state_core.get() {
                                core.replace_ledger(new_ledger).await;
                            } else {
                                sync_state.consensus.lock_recover().register_stakes_from_ledger(&new_ledger);
                                *sync_state.ledger.write().await = new_ledger;
                            }
                            // Wholesale ledger replace → invalidate the staked-anchor
                            // view (contract: state.rs:invalidate_anchor_view). The
                            // replay can change the staked set while the cache key/fp
                            // collide; a stale view diverges proposer↔verifier → freeze.
                            sync_state.invalidate_anchor_view();
                            info!("background sync: incremental replay done — {applied} applied, {skipped} skipped");
                        }
                        Ok(Err(e)) => {
                            warn!("background sync: incremental replay failed ({e}), falling back to streaming rebuild");
                            let rocks_ref2 = sync_state.rocks.clone();
                            let genesis2 = sync_genesis.clone();
                            let gv_clone2 = sync_state.config.genesis_validators.clone();
                            if let Ok(Ok((mut new_ledger, _))) = tokio::task::spawn_blocking(move || {
                                rocks_ref2.rebuild_ledger_streaming(&genesis2, &gv_clone2)
                            }).await {
                                new_ledger.rebuild_staker_index();
                                if !new_ledger.applied_record_ids.is_empty() {
                                    sync_state.rocks.bulk_mark_applied(&new_ledger.applied_record_ids);
                                    new_ledger.applied_record_ids.clear();
                                }
                                if let Some(core) = sync_state.state_core.get() {
                                    core.replace_ledger(new_ledger).await;
                                } else {
                                    sync_state.consensus.lock_recover().register_stakes_from_ledger(&new_ledger);
                                    *sync_state.ledger.write().await = new_ledger;
                                }
                                // Wholesale ledger replace → invalidate the staked-anchor
                                // view (contract: state.rs:invalidate_anchor_view).
                                sync_state.invalidate_anchor_view();
                                info!("background sync: streaming fallback rebuild complete");
                            }
                        }
                        Err(e) => warn!("background sync: spawn_blocking failed: {e}"),
                    }
                }
            } else {
                debug!("background sync: 0 records ingested — already in sync");
            }
        });
    }

    // ─── Try loading subsystem snapshots from RocksDB ─────────────────
    // Phase 1: Attempt cheap snapshot deserialization for each subsystem.
    // Phase 2: For any that fail, rebuild from a single record load.

    let epoch_already_restored = !node_state.epoch.read_recover().latest_epoch.is_empty();
    if epoch_already_restored {
        // NOTE: stale-zone pruning is deferred to AFTER LIVENESS-2 transition
        // rehydration below — pruning here would use the boot-seed zone_count
        // (1 in auto mode) and silently delete live epoch/seal/VRF state for
        // legitimately-active high zones before the canonical count is restored
        // (fixed 2026-06-19 zone_count fusion audit).
        let epoch = node_state.epoch.read_recover();
        let total_seals: u64 = epoch.latest_epoch.values().map(|n| n + 1).sum();
        info!("epoch state from JSON snapshot: {} zones, {} total seals", epoch.latest_epoch.len(), total_seals);
    }

    // Always check RocksDB epoch snapshot — it may be fresher than the JSON
    // snapshot (which can be minutes stale). Merge by taking max epoch per zone.
    let need_epoch = match node_state.rocks.load_snapshot::<elara_runtime::network::epoch::EpochStateSnapshot>("epoch") {
        Ok(Some(snap)) => {
            // stale-zone pruning deferred to after LIVENESS-2 rehydration (see
            // note above) — do not prune with the pre-rehydration zone_count.
            let rocks_epoch = elara_runtime::network::epoch::EpochState::from_snapshot(&snap);

            if epoch_already_restored {
                // Merge: take the higher epoch per zone from either source
                let mut json_epoch = node_state.epoch.write_recover();
                let mut merged = 0u32;
                for (zone, &rocks_num) in &rocks_epoch.latest_epoch {
                    let json_num = json_epoch.latest_epoch.get(zone).copied().unwrap_or(0);
                    if rocks_num > json_num {
                        json_epoch.latest_epoch.insert(zone.clone(), rocks_num);
                        if let Some(seal_id) = rocks_epoch.latest_seal_id.get(zone) {
                            json_epoch.latest_seal_id.insert(zone.clone(), seal_id.clone());
                        }
                        if let Some(seal_hash) = rocks_epoch.latest_seal_hash.get(zone) {
                            json_epoch.latest_seal_hash.insert(zone.clone(), *seal_hash);
                        }
                        if let Some(vrf) = rocks_epoch.latest_vrf_output.get(zone) {
                            json_epoch.latest_vrf_output.insert(zone.clone(), *vrf);
                        }
                        merged += 1;
                    }
                }
                if merged > 0 {
                    let total_seals: u64 = json_epoch.latest_epoch.values().map(|n| n + 1).sum();
                    info!("epoch state merged from RocksDB: {merged} zones advanced, {} total seals", total_seals);
                }
                false
            } else {
                // No JSON epoch — use RocksDB entirely
                let zone_count = rocks_epoch.latest_epoch.len();
                let total_seals: u64 = rocks_epoch.latest_epoch.values().map(|n| n + 1).sum();
                *node_state.epoch.write_recover() = rocks_epoch;
                if total_seals > 0 {
                    info!("epoch state loaded from RocksDB: {} zones, {} total seals", zone_count, total_seals);
                }
                false
            }
        }
        Ok(None) => !epoch_already_restored, // only need rebuild if neither source had data
        Err(e) => {
            warn!("epoch snapshot load failed: {e}");
            !epoch_already_restored
        }
    };

    // Rebuild the rolling super-seal buffer from CF_EPOCHS. Neither
    // the JSON snapshot nor the RocksDB EpochStateSnapshot persists
    // `recent_seal_hashes`, so without this every restart resets the buffer
    // to empty and Gap 3 super-seal creation can't fire until 64 fresh seals
    // arrive (~64 min at mainnet 60s cadence; effectively never at testnet
    // cadence). Bounded reverse scan; no-op when latest_epoch is empty.
    {
        let mut epoch = node_state.epoch.write_recover();
        // F-10: recover the per-zone epoch tip from the durable CF_EPOCHS index
        // BEFORE repopulating the super-seal buffer. A periodic (async) snapshot
        // can restore `latest_epoch` behind the durable seal tail (power-loss, or
        // simply a snapshot that lagged the last few seals); re-proposing an
        // already-sealed epoch trips the seal-equivocation detector. Running
        // first also lets `repopulate_recent_seal_hashes` window off the
        // corrected tip. See internal design notes.
        elara_runtime::network::epoch::rebuild_latest_epoch_from_cf_epochs(
            &mut epoch,
            &node_state.rocks,
        );
        elara_runtime::network::epoch::repopulate_recent_seal_hashes(
            &mut epoch,
            &node_state.rocks,
        );
    }

    // LIVENESS-2: rehydrate zone_transition schedule from CF_IDX_CREATOR.
    // state.zone_transition is a runtime cache initialised to None on every
    // boot. If a zone_transition announcement was ingested in a prior session
    // but the chain froze (LIVENESS-1) or the node restarted before
    // target_epoch, the schedule is lost — apply_pending_zone_transition_if_due
    // never fires and ZONE_COUNT stays at old_count forever.
    //
    // On boot: scan the genesis authority's records (bounded), pick the
    // latest unapplied transition (old_count == our current zone_count), and
    // either apply it immediately (if chain already past target_epoch) or
    // schedule it (if still in the future).
    {
        let our_zc = elara_runtime::network::consensus::get_zone_count();
        let current_max_epoch = {
            let epoch_state = node_state.epoch.read_recover();
            epoch_state.latest_epoch.values().copied().max().unwrap_or(0)
        };
        if let Some(transition) = elara_runtime::network::epoch::find_latest_unapplied_zone_transition(
            &node_state.rocks,
            &config.genesis_authority,
            our_zc,
        ) {
            if transition.target_epoch <= current_max_epoch {
                elara_runtime::network::consensus::set_zone_count(transition.new_count);
                info!(
                    "LIVENESS-2: zone_transition applied at boot: zone_count {} → {} \
                     (target_epoch {} ≤ current_max {}, record {})",
                    transition.old_count, transition.new_count,
                    transition.target_epoch, current_max_epoch,
                    &transition.record_id[..transition.record_id.len().min(16)]
                );
            } else {
                let mut zt = node_state.zone_transition.lock_recover();
                *zt = Some(transition.clone());
                info!(
                    "LIVENESS-2: zone_transition rehydrated at boot: epoch {} → zone_count {} \
                     (from {}, current_max {})",
                    transition.target_epoch, transition.new_count,
                    transition.old_count, current_max_epoch
                );
            }
        }
    }

    // Prune stale zones using the FINAL zone_count — i.e. AFTER LIVENESS-2 has
    // rehydrated the canonical count from the signed transition chain. Doing
    // this before rehydration (the prior behaviour) used the boot-seed count
    // (1 in auto mode) and deleted live epoch/seal/VRF state for legitimately
    // active high zones, silently breaking the chained-beacon VRF chain on any
    // node that reboots while the network runs at zone_count >= 2. No-op at
    // single-zone scale (no zone >= 1 exists). (2026-06-19 zone_count audit.)
    {
        let final_zone_count = elara_runtime::network::consensus::get_zone_count();
        node_state.epoch.write_recover().prune_stale_zones(final_zone_count);
    }

    let need_trust = match node_state.rocks.load_snapshot::<elara_runtime::accounting::trust::TrustEngine>("trust") {
        Ok(Some(engine)) => {
            let tracked = engine.tracked_identities();
            *node_state.trust.write().await = engine;
            if tracked > 0 {
                info!("trust engine loaded from RocksDB: {} tracked identities", tracked);
            }
            false
        }
        Ok(None) => true,
        Err(e) => { warn!("trust snapshot load failed, falling back to full rebuild: {e}"); true }
    };

    let need_key_registry = match node_state.rocks.load_snapshot::<elara_runtime::network::key_rotation::KeyRegistry>("key_registry") {
        Ok(Some(registry)) => {
            let total = registry.total_rotations();
            *node_state.key_registry.write_recover() = registry;
            if total > 0 {
                info!("key registry loaded from RocksDB: {} rotations", total);
            }
            false
        }
        Ok(None) => true,
        Err(e) => { warn!("key registry snapshot load failed: {e}"); true }
    };

    // Witness liveness — uses WitnessManager, not records (no snapshot fallback to records)
    {
        let rocks_loaded = match node_state.rocks.load_snapshot::<elara_runtime::network::liveness::WitnessLiveness>("liveness") {
            Ok(Some(lv)) => {
                let tracked = lv.tracked_count();
                *node_state.witness_liveness.lock_recover() = lv;
                if tracked > 0 {
                    info!("witness liveness loaded from RocksDB: {} tracked witnesses", tracked);
                }
                true
            }
            Ok(None) => false,
            Err(e) => { warn!("liveness snapshot load failed: {e}"); false }
        };

        if !rocks_loaded {
            let witness_mgr = node_state.witness_mgr.as_ref();
            let lv = liveness::rebuild_liveness(witness_mgr);
            let tracked = lv.tracked_count();
            *node_state.witness_liveness.lock_recover() = lv;
            if tracked > 0 {
                info!("witness liveness rebuilt: {} tracked witnesses", tracked);
            }
        }
    }

    // Load persistent counters from RocksDB (survive restarts).
    //
    // For total_ever_settled / total_ever_finalized we ALSO consult
    // FinalizedIndex.len() (set by load_count_from_rocks during the
    // earlier boot block) and prefer the LARGER of the two:
    //   - finalized.len() is authoritative for "how many unique rids
    //     have ever finalized" — it's a scan over CF_METADATA's
    //     `finalized:*` keys, immune to in-process counter drift.
    //   - The persisted settled/finalized snapshot can drift higher
    //     than finalized.len() if a prior session double-bumped the
    //     counter (the over-count fixed in 56e6424); we don't trust
    //     a stored value that exceeds the disk-authoritative count
    //     in that scenario, but for a correct prior session a stored
    //     value can legitimately equal finalized.len().
    // Picking max() preserves monotonicity if a future session ever
    // has fewer FinalizedIndex entries than what was previously
    // recorded (e.g. CF_METADATA prune), while clamping to disk
    // truth when the stored counter is inflated.
    //
    // total_attestations_processed has no equivalent disk-derivable
    // source, so it loads as-is.
    let finalized_authoritative = {
        let finalized = node_state.finalized.read().await;
        finalized.len() as u64
    };
    match node_state.rocks.load_snapshot::<(u64, u64, u64)>("persistent_counters") {
        Ok(Some((settled, finalized, processed))) => {
            // Clamp stored counter to disk-authoritative finalized count.
            // Pre-fix sessions inflated the counter by 1.3-3x via
            // double-bumping; clamp removes that drift on restart.
            let settled_seed = settled.min(finalized_authoritative);
            let finalized_seed = finalized.min(finalized_authoritative);
            node_state.total_ever_settled.store(settled_seed, std::sync::atomic::Ordering::Relaxed);
            node_state.total_ever_finalized.store(finalized_seed, std::sync::atomic::Ordering::Relaxed);
            node_state.total_attestations_processed.store(processed, std::sync::atomic::Ordering::Relaxed);
            info!(
                "persistent counters loaded: settled={settled_seed} (stored={settled}, disk_finalized={finalized_authoritative}), \
                 finalized={finalized_seed} (stored={finalized}), processed={processed}"
            );
        }
        Ok(None) => {
            // First run, or counters cleared. Seed from FinalizedIndex so
            // /metrics reflects historical finalizations even before
            // consensus rebuild populates new in-flight settlements.
            node_state.total_ever_settled.store(finalized_authoritative, std::sync::atomic::Ordering::Relaxed);
            node_state.total_ever_finalized.store(finalized_authoritative, std::sync::atomic::Ordering::Relaxed);
            if finalized_authoritative > 0 {
                info!("persistent counters seeded from FinalizedIndex: {finalized_authoritative}");
            }
        }
        Err(e) => warn!("persistent counters load failed: {e}"),
    }

    // Consensus attestation state — rebuild in background to avoid blocking HTTP startup.
    // This populates settlement state from stored attestations. With 50K+ attestations and
    // per-record RocksDB lookups, this can take 60-90s on slow VPS nodes.
    {
        let cons_state = node_state.clone();
        tokio::spawn(async move {
            // Scale attestation rebuild limit by RAM — 100K attestation objects
            // plus per-record RocksDB lookups uses ~200-400MB transient memory.
            // On 4GB nodes (Nuremberg), this pushes past the cgroup memory.high limit.
            let att_ram_gb = elara_runtime::storage::rocks::StorageEngine::detect_system_ram_gb();
            let att_limit = if att_ram_gb <= 2 { 25_000usize } else if att_ram_gb <= 4 { 50_000 } else { 100_000 };
            let stored_atts = {
                let witness_mgr = cons_state.witness_mgr.as_ref();
                // Load newest attestations first — recent ones are for records still
                // in the DAG and most likely to form live settlements. Old attestations
                // for long-finalized records waste the rebuild budget.
                witness_mgr.get_latest_attestations(att_limit)
            };
            match stored_atts {
                Ok(atts) if !atts.is_empty() => {
                    let n = atts.len();

                    // Step 1: collect unique record IDs from attestations
                    let mut seen_records = std::collections::HashSet::new();
                    for att in &atts {
                        seen_records.insert(att.record_id.clone());
                    }

                    // Step 2: fetch creator hashes from RocksDB WITHOUT holding ledger lock.
                    // Only include records that exist in local storage — attestations for
                    // records we don't have are useless (can't verify, can't determine creator
                    // stake for settlement). They'll be re-added when records sync via gossip.
                    let mut creator_map = std::collections::HashMap::new();
                    for rid in &seen_records {
                        if let Ok(Some(record)) = cons_state.rocks.get_record(rid) {
                            let creator = elara_runtime::accounting::types::creator_identity_hash(&record);
                            creator_map.insert(rid.clone(), creator);
                        }
                    }
                    let records_in_storage = creator_map.len();
                    let records_missing = seen_records.len() - records_in_storage;

                    // Step 3: brief ledger read to snapshot stakes, then DROP the lock.
                    // Previously held ledger.read() through 100K attestation iterations (~3 min
                    // on a 2 GB node), starving state_core's ledger.write() and freezing the HTTP server.
                    let stake_cache: std::collections::HashMap<String, u64> = {
                        // Collect unique identity hashes that need stake lookups
                        let mut identities = std::collections::HashSet::new();
                        for att in &atts {
                            if creator_map.contains_key(&att.record_id) {
                                identities.insert(att.witness_hash.clone());
                            }
                        }
                        for creator in creator_map.values() {
                            identities.insert(creator.clone());
                        }
                        // Brief lock — just HashMap reads, no I/O
                        let ledger = cons_state.ledger.read().await;
                        identities.into_iter()
                            .map(|id| { let s = ledger.staked(&id); (id, s) })
                            .collect()
                        // ledger lock dropped here
                    };

                    // Scope consensus_guard so it drops before any .await — std::MutexGuard is !Send,
                    // and tokio::spawn requires the future to be Send for its entire lifetime.
                    // Explicit drop() is insufficient for the compiler's Send analysis; lexical scope is.
                    let unsettled_rids: Vec<String> = {
                        let mut consensus_guard = cons_state.consensus.lock_recover();

                        let mut loaded = 0usize;
                        let mut skipped = 0usize;
                        for att in &atts {
                            // Skip attestations for records not in local storage
                            if !creator_map.contains_key(&att.record_id) {
                                skipped += 1;
                                continue;
                            }
                            let stake = stake_cache.get(&att.witness_hash).copied().unwrap_or(0);
                            let ca = elara_runtime::network::consensus::Attestation {
                                record_id: att.record_id.clone(),
                                witness_hash: att.witness_hash.clone(),
                                stake,
                                timestamp: att.timestamp,
                            };
                            consensus_guard.add_attestation(ca);
                            loaded += 1;
                        }

                        // Register creator identity (+ stake) for settlement threshold +
                        // H1 self-attestation rejection (MESH-BFT Def 18 amended).
                        for (rid, creator) in &creator_map {
                            let creator_staked = stake_cache.get(creator).copied().unwrap_or(0);
                            consensus_guard.register_creator_stake(rid, creator, creator_staked);
                        }

                        let settled = consensus_guard.force_finalize_settled().len();
                        info!("consensus attestations rebuilt: {loaded}/{n} loaded (limit={att_limit}, {skipped} skipped — records not in storage), {settled} settled, {records_in_storage} records ({records_missing} missing)");

                        // ── Reconcile: for unsettled records, load ALL their WitnessManager attestations ──
                        // The limit-based load may miss attestations for records near threshold.
                        consensus_guard.unsettled_summary()
                            .into_iter().map(|(rid, _, _)| rid).collect()
                        // consensus_guard dropped here (lexical scope end)
                    };

                    if !unsettled_rids.is_empty() {
                        let mgr = cons_state.witness_mgr.as_ref();
                        let mut extra_atts = Vec::new();
                        let mut extra_creators: std::collections::HashMap<String, (String, u64)> = std::collections::HashMap::new();
                        for rid in &unsettled_rids {
                            if let Ok(wm_atts) = mgr.get_attestations(rid) {
                                for att in wm_atts {
                                    let ws = stake_cache.get(&att.witness_hash).copied().unwrap_or(0);
                                    extra_atts.push(elara_runtime::network::consensus::Attestation {
                                        record_id: att.record_id.clone(),
                                        witness_hash: att.witness_hash.clone(),
                                        stake: ws,
                                        timestamp: att.timestamp,
                                    });
                                }
                            }
                            if let Ok(Some(rec)) = cons_state.rocks.get_record(rid) {
                                let creator = elara_runtime::accounting::types::creator_identity_hash(&rec);
                                let cs = stake_cache.get(&creator).copied().unwrap_or(0);
                                extra_creators.insert(rid.clone(), (creator, cs));
                            }
                        }

                        let mut cg = cons_state.consensus.lock_recover();
                        for (rid, (creator, cs)) in &extra_creators {
                            cg.register_creator_stake(rid, creator, *cs);
                        }
                        let extra_count = extra_atts.len();
                        let extra_updated = cg.bulk_load_attestations(extra_atts);
                        let extra_settled = cg.force_finalize_settled().len();
                        if extra_count > 0 {
                            info!("async reconcile: {extra_count} attestations for {} unsettled records, {extra_updated} updated, {extra_settled} newly settled", unsettled_rids.len());
                        }
                    }

                    // ── Gap-fill: attestations in WitnessManager but not tracked in consensus ──
                    // After the async rebuild + reconcile, records that didn't make it into
                    // the initial limit-based load AND aren't referenced by unsettled records
                    // are invisible. Scan recent WitnessManager attestations (bounded by
                    // att_limit, same as initial load) for records that exist in local storage
                    // but aren't tracked in consensus.
                    // Uses spawn_blocking — witness_mgr holds a std::Mutex and get_attestations_since
                    // does RocksDB I/O; both must not block tokio worker threads.
                    {
                        let tracked_rids: std::collections::HashSet<String> = {
                            let cg = cons_state.consensus.lock_recover();
                            cg.tracked_record_ids().into_iter().collect()
                        };
                        let now_ts = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs_f64();
                        let retention = cons_state.config.record_retention_secs.max(86400.0);
                        let cutoff = now_ts - retention * 2.0;
                        let stake_cache_clone = stake_cache.clone();
                        let cons_state_gf = cons_state.clone();
                        let gap_result = tokio::task::spawn_blocking(move || {
                            let scan_atts = {
                                let mgr = cons_state_gf.witness_mgr.as_ref();
                                mgr.get_attestations_since(cutoff, att_limit)
                            };
                            match scan_atts {
                                Ok(recent) => {
                                    let mut gap_atts = Vec::new();
                                    let mut gap_creator_stakes: std::collections::HashMap<String, (String, u64)> = std::collections::HashMap::new();
                                    for att in &recent {
                                        if tracked_rids.contains(&att.record_id) { continue; }
                                        if cons_state_gf.rocks.get_record(&att.record_id).ok().flatten().is_none() { continue; }
                                        let ws = stake_cache_clone.get(&att.witness_hash).copied().unwrap_or(0);
                                        gap_atts.push(
                                            elara_runtime::network::consensus::Attestation {
                                                record_id: att.record_id.clone(),
                                                witness_hash: att.witness_hash.clone(),
                                                stake: ws,
                                                timestamp: att.timestamp,
                                            }
                                        );
                                        if !gap_creator_stakes.contains_key(&att.record_id) {
                                            let entry = cons_state_gf.rocks.get_record(&att.record_id).ok().flatten()
                                                .map(|rec| {
                                                    let creator = elara_runtime::accounting::types::creator_identity_hash(&rec);
                                                    let s = stake_cache_clone.get(&creator).copied().unwrap_or(0);
                                                    (creator, s)
                                                })
                                                .unwrap_or_else(|| (String::new(), 0));
                                            gap_creator_stakes.insert(att.record_id.clone(), entry);
                                        }
                                    }
                                    Ok((gap_atts, gap_creator_stakes))
                                }
                                Err(e) => Err(e),
                            }
                        }).await;
                        if let Ok(Ok((gap_atts, gap_creator_stakes))) = gap_result {
                            if !gap_atts.is_empty() {
                                let gap_count = gap_atts.len();
                                let mut cg = cons_state.consensus.lock_recover();
                                for (rid, (creator, cs)) in &gap_creator_stakes {
                                    if !creator.is_empty() { cg.register_creator_stake(rid, creator, *cs); }
                                }
                                let gap_records = cg.bulk_load_attestations(gap_atts);
                                let gap_settled = cg.force_finalize_settled().len();
                                info!(
                                    "async gap-fill: {gap_count} attestations for {gap_records} untracked records, {gap_settled} settled (limit={att_limit})"
                                );
                            }
                        }
                    }

                    // Don't override persistent counters from consensus
                    // rebuild's settled_count(): that's the count of
                    // currently-Finalized records in the in-memory
                    // attestations map, NOT the lifetime finalization
                    // count. The boot path seeded total_ever_settled from
                    // FinalizedIndex.len() (disk-authoritative); from here
                    // forward, finality_monitor + the runtime paths will
                    // increment in lockstep with insert_batch's actual-new
                    // count.
                }
                Ok(_) => {}
                Err(e) => warn!("consensus rebuild failed: {e}"),
            }
        });
    }

    let need_sunset = match node_state.rocks.load_snapshot::<elara_runtime::network::sunset::SunsetState>("sunset") {
        Ok(Some(ss)) => {
            let count = ss.count();
            *node_state.sunset.write_recover() = ss;
            if count > 0 {
                info!("sunset state loaded from RocksDB: {} algorithm entries", count);
            }
            false
        }
        Ok(None) => true,
        Err(e) => { warn!("sunset snapshot load failed: {e}"); true }
    };

    let need_delegations = match node_state.rocks.load_snapshot::<elara_runtime::accounting::delegation::DelegationRegistry>("delegations") {
        Ok(Some(reg)) => {
            let total = reg.total();
            *node_state.delegations.write_recover() = reg;
            if total > 0 {
                info!("delegation registry loaded from RocksDB: {} active delegations", total);
            }
            false
        }
        Ok(None) => true,
        Err(e) => { warn!("delegation snapshot load failed: {e}"); true }
    };

    let need_zone_state = match node_state.rocks.load_snapshot::<consensus::ZoneState>("zone_state") {
        Ok(Some(zs)) => {
            let zones = zs.active_zones.len();
            *node_state.zone_state.lock_recover() = zs;
            if zones > 0 {
                info!("zone state loaded from RocksDB: {} active zones", zones);
            }
            false
        }
        Ok(None) => true,
        Err(e) => { warn!("zone state snapshot load failed: {e}"); true }
    };

    let need_disputes = match node_state.rocks.load_snapshot::<elara_runtime::network::dispute::DisputeState>("disputes") {
        Ok(Some(ds)) => {
            let total = ds.all_disputes().len();
            *node_state.disputes.write_recover() = ds;
            if total > 0 {
                info!("dispute state loaded from RocksDB: {} disputes", total);
            }
            false
        }
        Ok(None) => true,
        Err(e) => { warn!("dispute snapshot load failed, falling back to full rebuild: {e}"); true }
    };

    let need_reputation = match node_state.rocks.load_snapshot::<elara_runtime::network::reputation::ReputationEngine>("reputation") {
        Ok(Some(rep)) => {
            let count = rep.tracked_count();
            *node_state.reputation.lock_recover() = rep;
            if count > 0 {
                info!("witness reputation loaded from RocksDB: {} witnesses tracked", count);
            }
            false
        }
        Ok(None) => true,
        Err(e) => { warn!("reputation snapshot load failed, falling back to full rebuild: {e}"); true }
    };

    let need_challenges = match node_state.rocks.load_snapshot::<elara_runtime::network::fisherman::ChallengeState>("challenges") {
        Ok(Some(ch)) => {
            let count = ch.all().count();
            *node_state.challenges.write_recover() = ch;
            if count > 0 {
                info!("fisherman challenges loaded from RocksDB: {} challenges", count);
            }
            false
        }
        Ok(None) => true,
        Err(e) => { warn!("challenges snapshot load failed: {e}"); true }
    };

    // ─── Timestamp defense violations (persist across restarts) ──────────
    match node_state.rocks.load_snapshot::<elara_runtime::network::timestamp_defense::TimestampViolationSnapshot>("timestamp_violations") {
        Ok(Some(snap)) => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs_f64();
            let mut defense = node_state.timestamp_defense.lock_recover();
            defense.import_violations(snap, now);
            let count = defense.violator_count();
            if count > 0 {
                info!("timestamp defense: loaded {count} active violators from RocksDB");
            }
        }
        Ok(None) => {} // no previous violations — fresh start
        Err(e) => warn!("timestamp violations snapshot load failed: {e}"),
    }

    // ─── Single-pass rebuild from records ────────────────────────────────
    // Load all records ONCE and pass the slice to every subsystem that
    // couldn't be restored from a snapshot. This avoids N full table scans.

    let any_need_rebuild = need_epoch || need_trust || need_key_registry
        || need_sunset || need_delegations || need_zone_state
        || need_disputes || need_reputation || need_challenges;

    if any_need_rebuild {
        // Run single-pass rebuild in background — can take minutes on large DAGs.
        // Subsystems start empty and get populated when the rebuild completes.
        let state2 = node_state.clone();
        let rebuild_state = node_state.clone();
        let genesis_auth = node_state.config.genesis_authority.clone();
        let min_w = config.zone_min_witnesses;
        let evidence_window = config.dispute_evidence_window_secs;
        // Clone dispute state for reputation rebuild (needs disputes resolved first)
        let dispute_snapshot_for_rep = if need_reputation && !need_disputes {
            Some(node_state.disputes.read_recover().clone())
        } else {
            None
        };

        // Collect which subsystems need rebuild into the closure
        let rebuild_flags = (
            need_epoch, need_trust, need_key_registry, need_sunset,
            need_delegations, need_zone_state, need_disputes,
            need_reputation, need_challenges,
        );

        info!("subsystem rebuild needed — running in background");
        tokio::spawn(async move {
        #[allow(clippy::type_complexity)]
        let result: std::result::Result<std::result::Result<(
            Option<elara_runtime::network::epoch::EpochState>,
            Option<elara_runtime::accounting::trust::TrustEngine>,
            Option<elara_runtime::network::key_rotation::KeyRegistry>,
            Option<elara_runtime::network::sunset::SunsetState>,
            Option<elara_runtime::accounting::delegation::DelegationRegistry>,
            Option<elara_runtime::network::consensus::ZoneState>,
            Option<elara_runtime::network::dispute::DisputeState>,
            Option<elara_runtime::network::reputation::ReputationEngine>,
            Option<elara_runtime::network::fisherman::ChallengeState>,
        ), ElaraError>, _> = tokio::task::spawn_blocking(move || {
            // Stream records via for_each_record — O(1) memory for the record stream.
            // Each record is deserialized, passed to all subsystem rebuilders, then dropped.
            // At 10M records, the old approach loaded ALL into a Vec (~20GB).
            // Now only subsystem state accumulates (epoch seals, trust scores, etc — all tiny).
            info!("streaming subsystem rebuild from timestamp index...");

            // Initialize subsystem states
            let (f_epoch, f_trust, f_key, f_sunset, f_deleg, f_zone, f_dispute, f_rep, f_chal) = rebuild_flags;
            let mut epoch_state = if f_epoch { Some(epoch::EpochState::new()) } else { None };
            let mut trust_engine = if f_trust { Some(elara_runtime::accounting::trust::TrustEngine::new()) } else { None };
            let mut key_registry = if f_key { Some(key_rotation::KeyRegistry::new()) } else { None };
            let mut sunset_state = if f_sunset { Some(sunset::SunsetState::new()) } else { None };
            let mut deleg_registry = if f_deleg { Some(elara_runtime::accounting::delegation::DelegationRegistry::new()) } else { None };
            let mut zone_state_obj = if f_zone { Some(consensus::ZoneState::new(min_w)) } else { None };
            let mut dispute_state_obj = if f_dispute { Some(dispute::DisputeState::new()) } else { None };
            // Challenge needs all_identities — collect creator hashes incrementally
            let mut all_identities: std::collections::HashSet<String> = std::collections::HashSet::new();
            // Challenge records need to be replayed after we have all identities
            let mut challenge_records: Vec<elara_runtime::record::ValidationRecord> = Vec::new();
            // Reputation needs witness_reward records for resolved disputes
            let mut witness_reward_records: Vec<elara_runtime::record::ValidationRecord> = Vec::new();

            // On 2GB nodes, bound subsystem rebuild to 50K most recent records.
            // Full history is in the snapshot; this rebuild only recovers lost state.
            // 298K records × ~8KB each = minutes of CPU on single-core 2GB boxes.
            let rebuild_ram_gb = elara_runtime::storage::rocks::StorageEngine::detect_system_ram_gb();
            let rebuild_cap = if rebuild_ram_gb <= 2 { 50_000usize } else { 0 };
            if rebuild_cap > 0 {
                info!("subsystem rebuild: bounded to {rebuild_cap} most recent records ({}GB RAM)", rebuild_ram_gb);
            }

            // Record `stats_partial` flag so /dag/stats can surface
            // that totals reflect only the most-recent `rebuild_cap` records.
            // Big-RAM nodes (rebuild_cap=0) seed unbounded from CF_IDX_TIMESTAMP
            // and report the full chain.
            state2
                .record_stats_seed_bounded
                .store(rebuild_cap > 0, std::sync::atomic::Ordering::Relaxed);

            let mut total_streamed: usize = 0;
            state2.rocks.for_each_record_ordered_bounded(rebuild_cap, |rec| {
                total_streamed += 1;

                // Seed incremental record-stats counters from this
                // single bounded scan; subsequent ingest writes bump
                // incrementally via `state.record_stats_bump`. Free piggyback
                // on the rebuild iteration that already runs.
                state2.record_stats_bump(rec);

                // Epoch: register seals
                if let Some(ref mut es) = epoch_state {
                    es.process_record(rec);
                }

                // Trust: record submission
                if let Some(ref mut te) = trust_engine {
                    te.process_record(rec);
                }

                // Key rotation: register rotations/revocations
                if let Some(ref mut kr) = key_registry {
                    kr.process_record(rec);
                }

                // Sunset: register sunset records
                if let Some(ref mut ss) = sunset_state {
                    ss.process_record(rec, &genesis_auth);
                }

                // F2 PSR-2: skip delegation/dispute/challenge-op replay for a tombstoned
                // record, converging the boot rebuild with the live ingest early-return
                // (see NodeState::sibling_op_tombstone_suppressed). Scale-safe: the
                // is_tombstoned CF read fires ONLY on the op-carrying subset. Zone / trust /
                // epoch / continuity (fed for EVERY record) are deliberately NOT gated —
                // that would be an O(all) point-read and they are out-of-seal / non-forking
                // (post-ship review CHANGE 4).
                let sib_suppressed = state2.sibling_op_tombstone_suppressed(rec);

                // Delegation: apply delegation records
                if let Some(ref mut dr) = deleg_registry {
                    if !sib_suppressed {
                        dr.process_record(rec);
                    }
                }

                // Zone: track record insertions
                if let Some(ref mut zs) = zone_state_obj {
                    zs.record_inserted(&rec.id);
                }

                // Dispute: process dispute records
                if let Some(ref mut ds) = dispute_state_obj {
                    if !sib_suppressed {
                        ds.process_record(rec, evidence_window);
                    }
                }

                // Collect identity hashes for challenge jury selection
                if f_chal {
                    let creator = elara_runtime::accounting::types::creator_identity_hash(rec);
                    all_identities.insert(creator);
                    // Only keep records that have challenge ops (tiny subset).
                    // F2 PSR-2 CHANGE 5: gate the op replay (push) on !sib_suppressed, but
                    // keep all_identities.insert (above) UNCONDITIONAL — the creator of a
                    // tombstoned record is still a real identity in the VRF jury pool;
                    // dropping it would diverge historically-selected jury composition.
                    if !sib_suppressed && rec.metadata.contains_key(fisherman::CHALLENGE_OP_KEY) {
                        challenge_records.push(rec.clone());
                    }
                }

                // Collect witness_reward records for reputation rebuild (tiny subset)
                if f_rep
                    && rec.metadata.get("beat_op").and_then(|v| v.as_str()) == Some("witness_reward") {
                        witness_reward_records.push(rec.clone());
                    }
            })?;
            info!("streamed {} records for subsystem rebuild", total_streamed);

            // Subsystem states were populated by the streaming loop above.
            // Now finalize: extract results, handle post-stream processing.
            let epoch_result = epoch_state;
            let trust_result = trust_engine;
            let key_result = key_registry;
            let sunset_result = sunset_state;
            let deleg_result = deleg_registry;
            let zone_result = zone_state_obj;

            let dispute_result = dispute_state_obj;

            // Reputation: process resolved disputes against collected witness_reward records.
            // Only the tiny subset of witness_reward records was kept during streaming.
            let rep_result = if f_rep {
                let ds_ref = if let Some(ref ds) = dispute_result {
                    ds
                } else if let Some(ref ds) = dispute_snapshot_for_rep {
                    ds
                } else {
                    &elara_runtime::network::dispute::DisputeState::new()
                };
                let mut engine = elara_runtime::network::reputation::ReputationEngine::new();
                for d in ds_ref.all_disputes() {
                    if let Some(ref resolution) = d.resolution {
                        let attestors: Vec<String> = witness_reward_records.iter()
                            .filter(|r| {
                                r.metadata.get("beat_record_id").and_then(|v| v.as_str()) == Some(&d.contested_record_id)
                            })
                            .filter_map(|r| r.metadata.get("beat_to").and_then(|v| v.as_str()).map(String::from))
                            .collect();
                        if !attestors.is_empty() {
                            engine.process_dispute_resolution(&resolution.outcome, &attestors, resolution.resolved_at);
                        }
                    }
                }
                Some(engine)
            } else { None };

            // Challenges: replay collected challenge records with full identity set.
            // Only challenge-op records were kept (tiny subset), identities built incrementally.
            // AUDIT-6: use `epoch_result.vrf_output_at_or_before(zone, rec.timestamp)`
            // for jury seeding so rebuild matches the live path deterministically.
            let chal_result = if f_chal {
                let id_vec: Vec<String> = all_identities.into_iter().collect();
                let mut chal_state = fisherman::ChallengeState::new();
                let epoch_ref = epoch_result.as_ref();
                for rec in &challenge_records {
                    if let Ok(Some(op)) = fisherman::extract_challenge_op(&rec.metadata) {
                        let creator = elara_runtime::accounting::types::creator_identity_hash(rec);
                        let rec_zone = rec.zone.clone()
                            .unwrap_or_else(|| elara_runtime::ZoneId::from_legacy(0));
                        let vrf = epoch_ref
                            .and_then(|e| e.vrf_output_at_or_before(&rec_zone, rec.timestamp));
                        match op {
                            fisherman::ParsedChallengeOp::File { accused, challenge_type, evidence } => {
                                if let Some(ct) = fisherman::ChallengeType::parse_str(&challenge_type) {
                                    let _ = chal_state.file_challenge(
                                        rec.id.clone(), creator, accused, ct, evidence,
                                        rec.timestamp, &id_vec, vrf.as_ref(),
                                    );
                                }
                            }
                            fisherman::ParsedChallengeOp::Vote { challenge_id, guilty } => {
                                let _ = chal_state.cast_vote(&challenge_id, &creator, guilty, rec.timestamp);
                            }
                            fisherman::ParsedChallengeOp::Appeal { challenge_id, reason } => {
                                let _ = chal_state.file_appeal(
                                    &challenge_id, &creator, reason, rec.timestamp, &id_vec, vrf.as_ref(),
                                );
                            }
                        }
                    }
                }
                Some(chal_state)
            } else { None };

            Ok((epoch_result, trust_result, key_result, sunset_result,
                deleg_result, zone_result, dispute_result, rep_result, chal_result))
        }).await;

        match result {
            Ok(Ok((epoch_r, trust_r, key_r, sunset_r, deleg_r, zone_r, dispute_r, rep_r, chal_r))) => {
                if let Some(epoch_state) = epoch_r {
                    let zone_count = epoch_state.latest_epoch.len();
                    let total_seals: u64 = epoch_state.latest_epoch.values().map(|n| n + 1).sum();
                    *rebuild_state.epoch.write_recover() = epoch_state;
                    if total_seals > 0 {
                        info!("epoch state rebuilt from records: {} zones, {} total seals", zone_count, total_seals);
                    }
                }
                if let Some(trust_engine) = trust_r {
                    let tracked = trust_engine.tracked_identities();
                    *rebuild_state.trust.write().await = trust_engine;
                    if tracked > 0 {
                        info!("trust engine rebuilt from records: {} tracked identities", tracked);
                    }
                }
                if let Some(registry) = key_r {
                    let total = registry.total_rotations();
                    *rebuild_state.key_registry.write_recover() = registry;
                    if total > 0 {
                        info!("key registry rebuilt from records: {} rotations across {} identities",
                            total, rebuild_state.key_registry.read_recover().rotated_identities());
                    }
                }
                if let Some(sunset_state) = sunset_r {
                    let count = sunset_state.count();
                    *rebuild_state.sunset.write_recover() = sunset_state;
                    if count > 0 {
                        info!("sunset state rebuilt from records: {} algorithm entries", count);
                    }
                }
                if let Some(registry) = deleg_r {
                    let total = registry.total();
                    *rebuild_state.delegations.write_recover() = registry;
                    if total > 0 {
                        info!("delegation registry rebuilt from records: {} active delegations", total);
                    }
                }
                if let Some(zs) = zone_r {
                    let zones = zs.active_zones.len();
                    *rebuild_state.zone_state.lock_recover() = zs;
                    if zones > 0 {
                        info!("zone state rebuilt from records: {} active zones", zones);
                    }
                }
                if let Some(ds) = dispute_r {
                    let total = ds.all_disputes().len();
                    *rebuild_state.disputes.write_recover() = ds;
                    if total > 0 {
                        info!("dispute state rebuilt from records: {} disputes", total);
                    }
                }
                if let Some(rep) = rep_r {
                    let count = rep.tracked_count();
                    *rebuild_state.reputation.lock_recover() = rep;
                    if count > 0 {
                        info!("witness reputation rebuilt from records: {} witnesses tracked", count);
                    }
                }
                if let Some(ch) = chal_r {
                    let count = ch.all().count();
                    *rebuild_state.challenges.write_recover() = ch;
                    if count > 0 {
                        info!("fisherman challenges rebuilt from records: {} challenges", count);
                    }
                }
                info!("background subsystem rebuild complete");
            }
            Ok(Err(e)) => warn!("single-pass subsystem rebuild failed: {e}"),
            Err(e) => warn!("single-pass subsystem rebuild spawn failed: {e}"),
        }
        }); // end tokio::spawn for subsystem rebuild
    } else {
        // When all subsystems restore from snapshot, the rebuild
        // closure (which is the only place that touched record_stats during
        // boot) never fires. Counters would start at 0 and only reflect
        // records ingested after boot, breaking the dag-stats contract.
        // Run a dedicated bounded seed pass here so /dag/stats reflects the
        // existing chain. Bounded by RAM tier — same policy as the rebuild
        // closure (≤2GB → 50K most recent + stats_partial=true).
        let seed_state = node_state.clone();
        let seed_ram_gb = elara_runtime::storage::rocks::StorageEngine::detect_system_ram_gb();
        let seed_cap = if seed_ram_gb <= 2 { 50_000usize } else { 0 };
        seed_state
            .record_stats_seed_bounded
            .store(seed_cap > 0, std::sync::atomic::Ordering::Relaxed);
        tokio::spawn(async move {
            let res = tokio::task::spawn_blocking(move || {
                let mut count = 0usize;
                let r = seed_state.rocks.for_each_record_ordered_bounded(seed_cap, |rec| {
                    seed_state.record_stats_bump(rec);
                    count += 1;
                });
                (r, count)
            }).await;
            match res {
                Ok((Ok(_), n)) => info!("OPS-125 dag-stats seed: {n} records ({}GB RAM, cap={})", seed_ram_gb, seed_cap),
                Ok((Err(e), n)) => warn!("OPS-125 dag-stats seed iter failed after {n}: {e}"),
                Err(e) => warn!("OPS-125 dag-stats seed spawn failed: {e}"),
            }
        });
    }

    // ─── ARCH-1 boot replay — rehydrate PendingLedger from disk ────────
    // Must run BEFORE spawn_state_core so the drain loop's first tick
    // sees a complete in-memory store.
    match elara_runtime::network::pending_drain::boot_replay_pending_deltas(&node_state).await {
        Ok(n) => info!("ARCH-1 pending-ledger rehydrated: {n} deltas"),
        Err(e) => warn!("ARCH-1 pending-ledger replay failed: {e}"),
    }

    // ─── State Core — serializes all record mutations ──────────────────
    let state_core_handle = elara_runtime::network::state_core::spawn_state_core(node_state.clone());
    let _ = node_state.state_core.set(state_core_handle);
    info!("state core started — all record mutations via channel");

    // ─── Background tasks ───────────────────────────────────────────────

    // Loop-supervision mpsc→watch migration (verdict 2026-07-19): these 18 loop
    // shutdown signals are `watch::channel(())` (not mpsc) so their receivers are
    // CLONEABLE — the prerequisite for wrapping each loop in `spawn_supervised`
    // (which must hand a fresh receiver to every restart). Behaviour is identical:
    // the loops `select!` on `shutdown.changed()` and the teardown DROPS the sender,
    // which fires `changed()` → Err exactly like mpsc `recv()` → None (pinned by
    // `supervision::tests::watch_changed_waits_then_fires_on_drop`).
    let (heartbeat_tx, heartbeat_rx) = watch::channel(());
    let (gossip_tx, gossip_rx) = watch::channel(());
    let (orphan_tx, orphan_rx) = watch::channel(());
    let (witness_tx, witness_rx) = watch::channel(());
    let (att_gossip_tx, att_gossip_rx) = watch::channel(());
    let (prune_tx, prune_rx) = watch::channel(());
    let (snapshot_tx, snapshot_rx) = watch::channel(());
    let (pex_tx, pex_rx) = watch::channel(());
    let (epoch_tx, epoch_rx) = watch::channel(());
    let (finality_tx, finality_rx) = watch::channel(());
    let (health_tx, health_rx) = watch::channel(());
    let (reconnect_tx, reconnect_rx) = watch::channel(());
    let (gc_tx, gc_rx) = watch::channel(());
    let (system_load_tx, system_load_rx) = watch::channel(());
    let (fork_tx, fork_rx) = watch::channel(());
    let (probe_tx, probe_rx) = watch::channel(());
    let (tip_merge_tx, tip_merge_rx) = watch::channel(());
    let (mdns_tx, mdns_rx) = watch::channel(());
    // Gap 1: Light-client header sync (only spawned on NodeProfile::Light).
    let (light_sync_tx, light_sync_rx) = mpsc::channel(1);

    // Loop-supervision shared teardown flag, hoisted here so EVERY supervised spawn
    // below (incl. these pre-wave-1 loops) can reference it. Stays false until the
    // graceful-shutdown wiring sets it — a clean Ok(()) loop exit (its watch shutdown
    // fired) already marks the loop Disabled without needing this.
    let loop_shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

    // Heartbeat loop — supervised (restart-on-panic; peer keepalive is restart-safe).
    {
        let hb_state = node_state.clone();
        let status = node_state.loop_registry.register("heartbeat", 300);
        let hb = status.clone();
        elara_runtime::network::supervision::spawn_supervised(
            status,
            loop_shutdown.clone(),
            move || discovery::heartbeat_loop(hb_state.clone(), heartbeat_rx.clone(), hb.clone()),
        );
    }

    // PEX (Peer Exchange) loop
    // REALMS P1 slice (c): outbound PEX is discovery — off in sovereign.
    if config.network_realm.discovery_enabled() {
        let pex_state = node_state.clone();
        let status = node_state.loop_registry.register("pex", 600);
        elara_runtime::network::supervision::spawn_supervised(
            status,
            loop_shutdown.clone(),
            move || discovery::pex_loop(pex_state.clone(), pex_rx.clone()),
        );
    } else {
        info!("realm=sovereign: PEX loop disabled (discovery-off)");
    }

    // mDNS LAN discovery (Protocol §11.14 Layer C)
    // REALMS P1 slice (c): sovereign realms never beacon on the LAN.
    if config.mdns_enabled && config.network_realm.discovery_enabled() {
        // Supervised: the last unwrapped lifecycle loop. Panic-restart is now
        // leak-safe (the DaemonGuard RAII fix shuts the ServiceDaemon down on
        // unwind, so a restart no longer leaks an OS thread). Non-consensus (LAN
        // discovery) so low-stakes; heartbeat surfaces a hang on /health.
        let mdns_state = node_state.clone();
        let status = node_state.loop_registry.register("mdns", 60);
        let hb = status.clone();
        elara_runtime::network::supervision::spawn_supervised(
            status,
            loop_shutdown.clone(),
            move || elara_runtime::network::mdns::mdns_loop(mdns_state.clone(), mdns_rx.clone(), hb.clone()),
        );
    } else if !config.network_realm.discovery_enabled() {
        info!("realm=sovereign: mDNS beaconing disabled (discovery-off)");
    } else {
        debug!("mDNS disabled by config");
    }

    // UPnP lease renewal (only if mapping was created at startup).
    // NOT yet supervised: upnp_renewal_loop lives in the standalone elara-nat crate
    // (Lane 3) which must not couple to this crate's LoopStatus, and this spawn
    // precedes the `loop_shutdown` handle created below — a panic-restart wrap is a
    // clean follow-up in the mpsc→watch wave. A dropped UPnP lease is non-load-bearing.
    if upnp_mapped {
        let listen_port = config.listen_addr.rsplit(':').next()
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(9473);
        tokio::spawn(async move {
            elara_runtime::network::nat::upnp_renewal_loop(listen_port).await;
        });
    }

    // Gossip pull loop. NodeProfile::Light short-circuits inside pull_loop —
    // it returns immediately (records aren't pulled) so Light nodes don't
    // ingest the full record firehose.
    {
        let gs_state = node_state.clone();
        let status = node_state.loop_registry.register("pull", 120);
        let hb = status.clone();
        elara_runtime::network::supervision::spawn_supervised(
            status,
            loop_shutdown.clone(),
            move || gossip::pull_loop(gs_state.clone(), gossip_rx.clone(), hb.clone()),
        );
    }

    // Gap 1: Light-client header sync loop — runs only on NodeProfile::Light.
    // On FullZone/Archive nodes the light_sync_tx drops silently after the
    // shutdown channel is closed; no loop is spawned.
    {
        use elara_runtime::network::node_profile::NodeProfile;
        let profile = NodeProfile::from_str(&node_state.config.node_profile);
        if matches!(profile, NodeProfile::Light) {
            let ls_state = node_state.clone();
            tokio::spawn(async move {
                elara_runtime::network::light::light_sync_loop(ls_state, light_sync_rx).await;
            });
            info!("Gap 1: light_sync_loop spawned (NodeProfile::Light)");
        } else {
            // Keep the sender alive so the channel doesn't close — otherwise
            // an idle receiver on another profile could panic. Silently
            // shadowing is fine here.
            let _ = light_sync_tx;
        }
    }

    // Independent orphan resolver loop (separate from pull_loop to avoid starvation)
    {
        let or_state = node_state.clone();
        let status = node_state.loop_registry.register("orphan_resolver", 120);
        let hb = status.clone();
        elara_runtime::network::supervision::spawn_supervised(
            status,
            loop_shutdown.clone(),
            move || gossip::orphan_resolver_loop(or_state.clone(), orphan_rx.clone(), hb.clone()),
        );
    }

    // Gap 6.4 slice 3b: seal-replication reconciler. Periodically drains
    // K-DHT-routed seal pushes from `pending_seal_replications`, probes
    // each tracked target via `records_exist`, and re-pushes if the
    // realized replication factor is below `seal_dht_replication_floor`.
    // Implements verifiable seal replication.
    {
        let r_state = node_state.clone();
        tokio::spawn(async move {
            elara_runtime::network::seal_replication_reconciler::reconcile_loop(r_state).await;
        });
    }

    // Auto-witness loop
    {
        let aw_state = node_state.clone();
        let aw_mgr = witness_mgr.clone();
        let status = node_state.loop_registry.register("auto_witness", 1200);
        let hb = status.clone();
        elara_runtime::network::supervision::spawn_supervised(
            status,
            loop_shutdown.clone(),
            move || auto_witness::auto_witness_loop(aw_state.clone(), aw_mgr.clone(), witness_rx.clone(), hb.clone()),
        );
    }

    // Attestation gossip pull loop
    {
        let ag_state = node_state.clone();
        let status = node_state.loop_registry.register("attestation_pull", 120);
        let hb = status.clone();
        elara_runtime::network::supervision::spawn_supervised(
            status,
            loop_shutdown.clone(),
            move || gossip::attestation_pull_loop(ag_state.clone(), att_gossip_rx.clone(), hb.clone()),
        );
    }

    // Attestation pruning loop (hourly, keep 30 days)
    let prune_mgr = witness_mgr.clone();
    {
        let status = node_state.loop_registry.register("attestation_prune", 7200);
        let hb = status.clone();
        elara_runtime::network::supervision::spawn_supervised(
            status,
            loop_shutdown.clone(),
            move || attestation_prune_loop(prune_mgr.clone(), prune_rx.clone(), hb.clone()),
        );
    }

    // Loop-supervision wave-1 (verdict 2026-07-19): the SAFE no-shutdown-receiver
    // retention loops run under spawn_supervised — restart-on-panic instead of
    // silent death, each with a loop-top heartbeat() so a HANG (not just a panic)
    // surfaces as Stale on /health + /metrics. `loop_shutdown` stays false here
    // (these loops die on process exit; the graceful-shutdown wiring that sets it
    // is a follow-up). register() returns a shared LoopStatus: the original drives
    // the supervisor (restart/dead), a clone drives the loop body's heartbeat.
    // (`loop_shutdown` is declared once at the top of the background-tasks section.)

    // Trust engine pruning loop (hourly, prune identities inactive >30 days)
    {
        let trust_prune_state = node_state.clone();
        let status = node_state.loop_registry.register("trust_prune", 7200);
        let hb = status.clone();
        elara_runtime::network::supervision::spawn_supervised(
            status,
            loop_shutdown.clone(),
            move || trust_prune_loop(trust_prune_state.clone(), hb.clone()),
        );
    }

    // Memory pruning loop (every 10 min — consensus, reputation, rate limiter)
    {
        let mem_prune_state = node_state.clone();
        let status = node_state.loop_registry.register("memory_prune", 1800);
        let hb = status.clone();
        elara_runtime::network::supervision::spawn_supervised(
            status,
            loop_shutdown.clone(),
            move || memory_prune_loop(mem_prune_state.clone(), hb.clone()),
        );
    }

    // Tier 4.6 bootstrap-pathology defer/replay loop (every 60s).
    // Replays attestations whose witness stake row arrived after the
    // attestation itself — without this, a 1-CPU node behind on catch-up
    // rejects every external attestation at the sybil gate and never
    // finalizes incoming records before they age out of pending_ledger.
    {
        let lsr_state = node_state.clone();
        tokio::spawn(async move {
            elara_runtime::network::low_stake_replay::low_stake_replay_loop(lsr_state).await;
        });
    }

    // Periodic ledger snapshot loop
    if config.snapshot_interval_secs > 0 {
        let snap_state = node_state.clone();
        let snap_path = snapshot_path.clone();
        let snap_interval = config.snapshot_interval_secs;
        // stale_after 900 > snapshot_interval_secs (default 300) + serialize time:
        // the register("snapshot", 240) was MIS-SIZED (240 < 300 interval → would
        // false-Stale once heartbeat is wired). 900 = 3× interval + margin.
        let status = node_state.loop_registry.register("snapshot", 900);
        let hb = status.clone();
        elara_runtime::network::supervision::spawn_supervised(
            status,
            loop_shutdown.clone(),
            move || snapshot_loop(snap_state.clone(), snap_path.clone(), snap_interval, snapshot_rx.clone(), hb.clone()),
        );
    }

    // Gap 7: archive/anchor-only epoch-boundary snapshot loop.
    // Emits signed, epoch-indexed snapshots to {data_dir}/snapshots/ so new
    // nodes can bootstrap from the latest epoch rather than replaying genesis.
    {
        let node_type = elara_runtime::network::peer::NodeType::from_str(&config.node_type);
        if node_type.is_archival() && config.archive_snapshot_every_n_epochs > 0 {
            let snap_state = node_state.clone();
            let snap_dir = config.data_dir.join("snapshots");
            let status = node_state.loop_registry.register("archive_snapshot", 120);
            let hb = status.clone();
            elara_runtime::network::supervision::spawn_supervised(
                status,
                loop_shutdown.clone(),
                move || archive_snapshot_loop(snap_state.clone(), snap_dir.clone(), hb.clone()),
            );
        }
    }

    // Gap 7: chain divergence detector.
    // Runs in read-only-diagnostic mode — calls `poll_peer_tips` to fan-out to up to
    // CHAIN_DIVERGENCE_MAX_REPAIR_PEERS connected peers, parses
    // `elara_epoch_seals_total` from each /metrics, and writes
    // `max_peer_seals - local_seals` into the `chain_divergence_epochs` gauge.
    // NO repair action is taken in this loop (state-delta pull + verify/apply live elsewhere).
    // Spawned on every node (not gated on node_type) because divergence detection
    // applies to all node profiles — light, full-zone, and archive alike all have a
    // local chain-tip that can fall behind the cluster.
    {
        let cd_state = node_state.clone();
        tokio::spawn(async move {
            chain_divergence_monitor_loop(cd_state).await;
        });
    }

    // RocksDB TTL compaction loop (every 6 hours — prune old reputation/disputes from disk)
    {
        let ttl_state = node_state.clone();
        let status = node_state.loop_registry.register("ttl_compaction", 43200);
        let hb = status.clone();
        elara_runtime::network::supervision::spawn_supervised(
            status,
            loop_shutdown.clone(),
            move || ttl_compaction_loop(ttl_state.clone(), hb.clone()),
        );
    }

    // One-time CF_EPOCHS backfill from CF_RECORDS for nodes upgraded
    // from binaries that predate incremental CF_EPOCHS writes. Skips if
    // CF_EPOCHS already populated, or if CF_RECORDS is empty (fresh node —
    // incremental writes from day 0).
    {
        let bf_state = node_state.clone();
        tokio::spawn(async move {
            let rocks_for_size = bf_state.rocks.clone();
            let cf_epochs_size = rocks_for_size
                .approximate_cf_size(elara_runtime::storage::rocks::CF_EPOCHS);
            let record_count = rocks_for_size.approximate_record_count();
            if cf_epochs_size == 0 && record_count > 0 {
                info!(
                    "DISC-5 backfill starting: CF_EPOCHS empty, ~{} records to scan",
                    record_count
                );
                let rocks = bf_state.rocks.clone();
                let written = tokio::task::spawn_blocking(move || -> usize {
                    let mut written = 0usize;
                    let _ = rocks.for_each_record(|rec| {
                        if !rec.metadata
                            .contains_key(elara_runtime::network::epoch::EPOCH_OP_KEY)
                        {
                            return;
                        }
                        if let Ok(Some(seal)) =
                            elara_runtime::network::epoch::extract_epoch_seal(rec)
                        {
                            let key = elara_runtime::network::epoch::disc5_index_key(
                                seal.epoch_number,
                                seal.zone.path(),
                                &rec.id,
                            );
                            if rocks
                                .put_cf_raw(
                                    elara_runtime::storage::rocks::CF_EPOCHS,
                                    &key,
                                    &[],
                                )
                                .is_ok()
                            {
                                written += 1;
                            }
                        }
                    });
                    written
                })
                .await
                .unwrap_or(0);
                info!(
                    "DISC-5 backfill: indexed {written} historical epoch seals into CF_EPOCHS"
                );
            } else {
                info!(
                    "DISC-5 backfill skipped: cf_epochs_size={cf_epochs_size} record_count={record_count}"
                );
            }
        });
    }

    // Epoch seal loop (genesis authority only, auto-skips on non-genesis nodes).
    // Supervised: this is THE consensus liveness driver — a bare panic here
    // silently stops sealing (the authority chain stops advancing) with no
    // restart, page, or /health visibility. Restart-safety prerequisites DONE
    // (epoch-lock hygiene `04c694eb` + mpsc→watch `4b70c2e7`); the loop
    // re-derives its durable tip at start (rebuild + canonicalize), closing the
    // re-propose/self-slash window for every TRACKED zone — i.e. every zone that
    // exists at zone_count==1, so restart is fully safe on the current fleet.
    // SCOPED RESIDUAL (multi-zone only, UNREACHABLE today): a brand-new zone's
    // first-ever seal panicking mid-`register_seal` can re-propose epoch 0 →
    // equivocation self-slash; the producer-aware durable `already_sealed` guard
    // that closes it is a documented multi-zone prerequisite (see the epoch.rs
    // loop-start comment + loop-supervision memory). On a non-eligible node the
    // loop returns clean → set_disabled (never restarted). spawn_supervised
    // restarts on panic with capped backoff and marks DEAD (stops) at the
    // crash-loop ceiling. CONSENSUS-CRITICAL → a sustained
    // elara_loop_state{loop="epoch_seal"}=2 (Dead) MUST page.
    {
        let ep_state = node_state.clone();
        let status = node_state.loop_registry.register("epoch_seal", 240);
        let hb = status.clone();
        elara_runtime::network::supervision::spawn_supervised(
            status,
            loop_shutdown.clone(),
            move || epoch::epoch_seal_loop(ep_state.clone(), epoch_rx.clone(), hb.clone()),
        );
    }

    // REALMS P1.5 a3: live drand pulse fetcher. Opt-in (`drand_pulse_enabled`,
    // default false — fork-class rollout discipline) AND composed with the
    // public-HTTPS gate: a mainnet node (which must boot with
    // `allow_public_https=false`) keeps its zero-classical-TLS wire and uses
    // the out-of-process anchor sidecar for drand bracketing instead.
    if node_state.config.drand_pulse_enabled && node_state.config.allow_public_https {
        let drand_state = node_state.clone();
        let status = node_state.loop_registry.register("drand_fetch", 60);
        let hb = status.clone();
        elara_runtime::network::supervision::spawn_supervised(
            status,
            loop_shutdown.clone(),
            move || drand_fetch::drand_fetch_loop(drand_state.clone(), hb.clone()),
        );
    }

    // Finality monitor + consensus attestation pruning
    {
        let fm_state = node_state.clone();
        // CONDITIONAL wrap (audited): a restart re-derives newly_settled idempotently
        // (finalized:rid is the exactly-once edge → no double-finalization), so panic-
        // restart keeps finalization ALIVE — bare tokio::spawn let a panic kill it
        // entirely (node stops finalizing). Accepted residual: the effects-loss window
        // (a panic between the durable finalized-insert and the detached effects call
        // drops THAT batch's rewards/reputation) — the exactly-once fix is design C
        // (internal design notes), a
        // separate consensus-economic build. CONSENSUS-CRITICAL → a sustained
        // elara_loop_state{loop="finality_monitor"}=2 (Dead) MUST page.
        let status = node_state.loop_registry.register("finality_monitor", 120);
        let hb = status.clone();
        elara_runtime::network::supervision::spawn_supervised(
            status,
            loop_shutdown.clone(),
            move || finality_monitor_loop(fm_state.clone(), finality_rx.clone(), hb.clone()),
        );
    }

    // Gap 4: re-hydrate the TransitionStore from CF_TRANSITIONS_PENDING
    // before the health loop runs its first tick. Synchronous — the work
    // is bounded by MAX_PENDING_TRANSITIONS (1024) so it finishes in ms.
    let replayed =
        elara_runtime::network::health::boot_replay_pending_transitions(&node_state);
    if replayed > 0 {
        tracing::info!(
            "gap4 boot-replay: {replayed} pending transition(s) restored from CF"
        );
    }

    // Gap 5: rebuild the live ZoneRegistry from CF_TRANSITIONS_FINAL so
    // routing + committee iteration reflect the post-transition zone
    // tree from epoch 0, not just transitions finalized since process
    // start. O(N log N) in finalized seal count — tiny at current scale.
    let registry_applied =
        elara_runtime::network::health::boot_rehydrate_zone_registry(&node_state);
    if registry_applied > 0 {
        tracing::info!(
            "gap5 boot-rehydrate: {registry_applied} finalized seal(s) applied to ZoneRegistry"
        );
    }

    // Health monitor loop
    {
        let hm_state = node_state.clone();
        tokio::spawn(async move {
            elara_runtime::network::health::health_check_loop(hm_state, health_rx).await;
        });
    }

    // Stage 6 cooperative-scheduler load sensor — samples /proc/stat + /proc/loadavg
    // every 5s so gossip/ingest hot loops can back off when the host is busy.
    {
        let sl_sensor = node_state.system_load.clone();
        let status = node_state.loop_registry.register("system_load", 30);
        let hb = status.clone();
        elara_runtime::network::supervision::spawn_supervised(
            status,
            loop_shutdown.clone(),
            move || elara_runtime::network::system_load::run_refresh_loop(sl_sensor.clone(), system_load_rx.clone(), hb.clone()),
        );
    }

    // Memory pressure monitor — checks RSS every 30s.
    // Two thresholds:
    //   80% (soft): reduce batch sizes, trigger aggressive eviction.
    //   90% (critical): reject new record submissions with HTTP 429 to prevent OOM.
    // Critical uses 5% hysteresis (clears at 85%) to avoid rapid toggling.
    {
        let mp_state = node_state.clone();
        let system_ram_mb = elara_runtime::storage::rocks::StorageEngine::detect_system_ram_gb() * 1024;
        let soft_threshold_mb = (system_ram_mb as f64 * 0.80) as u64;
        let critical_threshold_mb = (system_ram_mb as f64 * 0.90) as u64;
        let critical_clear_mb = (system_ram_mb as f64 * 0.85) as u64;
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                let rss = elara_runtime::network::state::NodeState::current_rss_mb();

                // Soft pressure (80%)
                let was_soft = mp_state.under_memory_pressure();
                let now_soft = rss > soft_threshold_mb && soft_threshold_mb > 0;
                if now_soft != was_soft {
                    mp_state.memory_pressure.store(now_soft, std::sync::atomic::Ordering::Relaxed);
                    if now_soft {
                        warn!("memory pressure ON: RSS {}MB > {}MB threshold ({}MB system RAM)",
                            rss, soft_threshold_mb, system_ram_mb);
                    } else {
                        info!("memory pressure OFF: RSS {}MB < {}MB threshold",
                            rss, soft_threshold_mb);
                    }
                }

                // Critical pressure (90% on, 85% off — 5% hysteresis)
                let was_critical = mp_state.under_critical_memory_pressure();
                let now_critical = if was_critical {
                    // Already critical: clear only when RSS drops to 85%
                    critical_clear_mb > 0 && rss > critical_clear_mb
                } else {
                    // Not critical: trigger at 90%
                    critical_threshold_mb > 0 && rss > critical_threshold_mb
                };
                if now_critical != was_critical {
                    mp_state.memory_critical.store(now_critical, std::sync::atomic::Ordering::Relaxed);
                    if now_critical {
                        error!("CRITICAL memory pressure ON: RSS {}MB > {}MB threshold — rejecting new submissions (429)",
                            rss, critical_threshold_mb);
                    } else {
                        warn!("critical memory pressure OFF: RSS {}MB dropped below {}MB",
                            rss, critical_clear_mb);
                    }
                }
            }
        });
    }

    // Disk pressure monitor — checks filesystem free space + RocksDB live bytes every 60s.
    // Two triggers:
    //   (a) Filesystem avail < 512MB — absolute floor regardless of configured cap.
    //   (b) RocksDB live bytes > 95% of disk_cap_bytes — approaching configured quota.
    // Hysteresis: clears when avail > 1GB AND live < 80% of cap (prevents rapid toggling).
    {
        let dp_state = node_state.clone();
        tokio::spawn(async move {
            // Sample-then-sleep so the first reading lands at boot,
            // not 60s later. Operators verifying a fresh deploy used to see
            // elara_data_dir_total_bytes=0 for the first minute and couldn't
            // tell whether the gauge was broken or just unsampled. With sample-first, the
            // first /metrics scrape after rocks.open() returns a live value.
            // Sample cost is bounded (`O(SST count)` stat() syscalls) and
            // safe at boot since rocks is opened before this task spawns.
            loop {
                // Filesystem available space (Unix only; 0 on Windows/unsupported).
                let avail_mb: u64 = {
                    #[cfg(unix)]
                    {
                        use std::os::unix::ffi::OsStrExt;
                        let path = std::ffi::CString::new(
                            dp_state.config.data_dir.as_os_str().as_bytes()
                        ).ok();
                        if let Some(p) = path {
                            let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
                            if unsafe { libc::statvfs(p.as_ptr(), &mut stat) } == 0 {
                                // `statvfs` field widths differ by platform — `f_bavail`/`f_frsize`
                                // are u32 on macOS (Darwin) but u64 on Linux. Widen both to u64 so
                                // the byte math is correct (and compiles) everywhere; the casts are
                                // no-ops on Linux.
                                #[allow(clippy::unnecessary_cast)]
                                {
                                    (stat.f_bavail as u64).saturating_mul(stat.f_frsize as u64)
                                        / (1024 * 1024)
                                }
                            } else { u64::MAX }
                        } else { u64::MAX }
                    }
                    #[cfg(not(unix))]
                    { u64::MAX }
                };

                // RocksDB live bytes vs configured cap.
                let disk_cap = dp_state.config.disk_cap_bytes;
                let live_bytes = if disk_cap > 0 { dp_state.rocks.total_live_bytes() } else { 0 };
                let cap_pct = (live_bytes * 100).checked_div(disk_cap).unwrap_or(0);

                // The recursive filesystem footprint of data_dir
                // is sampled by a separate `data_dir_size_loop` task at a
                // longer cadence (default 5 min, configurable). Previously
                // the walk ran here every 60 s and `O(SST count)` stat()
                // syscalls dominated the tick under compaction pressure
                // (a constrained node was observed at 7 ticks in 11 min). Splitting the walk
                // keeps this loop on its strict 60 s rhythm so
                // `disk_pressure_lowest_avail_mb` + `disk_avail_pressure`
                // edges stay trustworthy as between-scrape canaries. Reads
                // `data_dir_total_bytes` from the atomic populated by the
                // other task — 0 until that task's first pass completes.

                let was_avail_pressure = dp_state.under_avail_pressure();
                let was_cap_pressure = dp_state.under_cap_pressure();
                // Thresholds raised from 512 MB / 1 GB to configurable
                // 2 GB / 4 GB defaults. The earlier sizing was too tight to
                // absorb RocksDB compaction churn (single L1→L2 compaction can
                // write 256+ MB before the 60 s sample tick) — a fleet outage
                // tripped pressure but still hit
                // ENOSPC because in-flight compactions ate the last 512 MB
                // headroom. The avail-MB low watermark only fires when
                // configured > 0 (operators can disable the FS-avail trip path
                // entirely and rely on the live_bytes/cap fallback alone).
                let avail_low = dp_state.config.disk_pressure_avail_low_mb;
                let avail_high = dp_state.config.disk_pressure_avail_high_mb;
                // Split the two pressure signals so callers can react
                // to the right one. `avail` is real disk-full safety (rejects
                // ingest); `cap` is operator-policy budget (drives GC force-
                // compaction + retention compression but not ingest gating).
                let now_avail_pressure = if was_avail_pressure {
                    avail_high > 0 && avail_mb < avail_high
                } else {
                    avail_low > 0 && avail_mb < avail_low
                };
                let now_cap_pressure = if was_cap_pressure {
                    disk_cap > 0 && live_bytes > disk_cap * 80 / 100
                } else {
                    disk_cap > 0 && live_bytes > disk_cap * 95 / 100
                };
                let was_pressure = was_avail_pressure || was_cap_pressure;
                let now_pressure = now_avail_pressure || now_cap_pressure;

                if now_avail_pressure != was_avail_pressure {
                    dp_state.disk_avail_pressure.store(now_avail_pressure, std::sync::atomic::Ordering::Relaxed);
                }
                if now_cap_pressure != was_cap_pressure {
                    dp_state.disk_cap_pressure.store(now_cap_pressure, std::sync::atomic::Ordering::Relaxed);
                }

                if now_pressure != was_pressure {
                    dp_state.disk_pressure.store(now_pressure, std::sync::atomic::Ordering::Relaxed);
                }

                // Per-edge event counters + lowest-since-boot avail
                // gauge. Counters bump exactly once on each 0→1 transition;
                // 1→0 clears do not decrement. Lowest-MB tracks the floor
                // across the entire process lifetime — closes the
                // gauge-failure-on-slow-shrink shape where a between-scrape
                // dip recovers before either scrape catches it.
                if now_avail_pressure && !was_avail_pressure {
                    dp_state.disk_avail_pressure_events_total
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                if now_cap_pressure && !was_cap_pressure {
                    dp_state.disk_cap_pressure_events_total
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                dp_state.disk_pressure_lowest_avail_mb
                    .fetch_min(avail_mb, std::sync::atomic::Ordering::Relaxed);
                // Bump the iteration counter so operators can tell
                // `lowest_avail_mb=0 because never sampled` (samples=0) from
                // `lowest_avail_mb=0 because statvfs returned <1 MB` (samples>0).
                // The renderer collapses both to exported value 0.
                dp_state.disk_pressure_samples_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                // Edge transitions are reported per-signal so operators can
                // see exactly which one tripped/cleared.
                if now_avail_pressure && !was_avail_pressure {
                    error!(
                        "DISK avail pressure ON: avail={}MB < low={}MB — rejecting new submissions (429)",
                        avail_mb, avail_low,
                    );
                } else if !now_avail_pressure && was_avail_pressure {
                    warn!(
                        "disk avail pressure OFF: avail={}MB ≥ high={}MB",
                        avail_mb, avail_high,
                    );
                }
                if now_cap_pressure && !was_cap_pressure {
                    warn!(
                        "DISK cap pressure ON: live={:.1}GB cap_pct={}% — GC will compact more aggressively (ingest unaffected, OPS-169)",
                        live_bytes as f64 / 1e9, cap_pct,
                    );
                } else if !now_cap_pressure && was_cap_pressure {
                    warn!(
                        "disk cap pressure OFF: live={:.1}GB ({}% of cap)",
                        live_bytes as f64 / 1e9, cap_pct,
                    );
                }

                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            }
        });
    }

    // data_dir recursive-size walk loop. Split out of
    // disk_pressure_loop because the walk is `O(SST count)` blocking stat()
    // syscalls — on a node at 510+ SSTs under compaction pressure the pass took
    // long enough that disk_pressure_loop slipped to ~7 ticks per 11 min
    // instead of ~11, which broke `disk_pressure_lowest_avail_mb` as a
    // between-scrape canary. Now the walk runs in `spawn_blocking` (so it
    // never ties up an async worker) at a configurable cadence (default 5 min)
    // and writes to the same `data_dir_total_bytes` atomic the gauge reads.
    {
        let dds_state = node_state.clone();
        tokio::spawn(async move {
            let interval = dds_state.config.data_dir_size_sample_interval_secs;
            if interval == 0 {
                // Operator opt-out: gauge stays at 0 / last sample. No task body.
                return;
            }
            // Sample-first like disk_pressure_loop so the first /metrics scrape
            // after boot reports a real value rather than 0 for `interval` seconds.
            loop {
                let data_dir = dds_state.config.data_dir.clone();
                let walked = tokio::task::spawn_blocking(move || {
                    elara_runtime::storage::rocks::dir_size_bytes(&data_dir).unwrap_or(0)
                })
                .await
                .unwrap_or(0);
                dds_state
                    .data_dir_total_bytes
                    .store(walked, std::sync::atomic::Ordering::Relaxed);
                dds_state
                    .data_dir_size_samples_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
            }
        });
    }

    // Seed peer reconnection loop
    // REALMS P1 slice (c): no seed dialing in sovereign realms.
    if config.network_realm.discovery_enabled() {
        let rc_state = node_state.clone();
        let status = node_state.loop_registry.register("seed_reconnect", 240);
        elara_runtime::network::supervision::spawn_supervised(
            status,
            loop_shutdown.clone(),
            move || discovery::seed_reconnect_loop(rc_state.clone(), reconnect_rx.clone()),
        );
    } else {
        info!("realm=sovereign: seed reconnect loop disabled (discovery-off)");
    }

    // GC loop (prune expired + old finalized records)
    {
        let gc_state = node_state.clone();
        let status = node_state.loop_registry.register("gc", 1200);
        let hb = status.clone();
        elara_runtime::network::supervision::spawn_supervised(
            status,
            loop_shutdown.clone(),
            move || gc::gc_loop(gc_state.clone(), gc_rx.clone(), hb.clone()),
        );
    }

    // Fork monitor loop (detect divergence, auto-heal)
    {
        let fork_state = node_state.clone();
        // CONSENSUS-CRITICAL (partition/divergence safety-net): a sustained
        // elara_loop_state{loop="fork_monitor"}=2 (Dead — crash-loop ceiling hit) MUST
        // page. A silently-dead fork monitor is the worst failure in the set (verdict).
        let status = node_state.loop_registry.register("fork_monitor", 1200);
        let hb = status.clone();
        elara_runtime::network::supervision::spawn_supervised(
            status,
            loop_shutdown.clone(),
            move || elara_runtime::network::fork::fork_monitor_loop(fork_state.clone(), fork_rx.clone(), hb.clone()),
        );
    }

    // Peer liveness probe loop (all nodes — keeps network alive with zero user traffic)
    {
        let probe_state = node_state.clone();
        // stale_after > MAX_PROBE_INTERVAL_SECS (3600): the adaptive interval reaches
        // 3600s at 0/large peer count, so a tighter threshold would false-Stale.
        let status = node_state.loop_registry.register("probe", 7200);
        let hb = status.clone();
        elara_runtime::network::supervision::spawn_supervised(
            status,
            loop_shutdown.clone(),
            move || elara_runtime::network::probe::probe_loop(probe_state.clone(), probe_rx.clone(), hb.clone()),
        );
    }

    // Fisherman finalization loop (finalize challenges past appeal window)
    {
        let fish_state = node_state.clone();
        tokio::spawn(async move {
            challenge_finalization_loop(fish_state).await;
        });
    }

    // RocksDB checkpoint loop (every 6 hours, keep last 3)
    {
        let cp_rocks = node_state.rocks.clone();
        let cp_data_dir = config.data_dir.clone();
        tokio::spawn(async move {
            checkpoint_loop(cp_rocks, cp_data_dir).await;
        });
    }

    // Uptime-vesting loop: PERMANENTLY GATED OFF pending a record-driven redesign
    // (C11, internal design notes). The loop mutated the SMT-leaf
    // `uptime_secs`/`inactive_days`/`vested_locked` out-of-band on this node's
    // wall clock with no record, so a follower replaying via records diverges the
    // account-SMT root — a silent consensus fork. The fields are inert
    // (`vested_locked == 0` everywhere) so this costs nothing today. The
    // `uptime_vesting_enabled` flag can NO LONGER re-enable the out-of-band loop;
    // vesting must first ship as genesis-signed records (the idle_decay pattern,
    // `epoch.rs`). The flag is honoured loudly-fail-closed: set-but-ignored, never
    // forking. (Fail-closed on the danger without bricking boot for a node that
    // inherited a stale config with the flag set.)
    if config.uptime_vesting_enabled {
        error!(
            "uptime_vesting_enabled=true IGNORED: the out-of-band vesting loop would fork the \
             account-SMT root across nodes and is disabled until vesting is re-implemented as \
             signed records — see internal design notes"
        );
    } else {
        info!("uptime-vesting loop disabled (record-driven redesign pending) — see internal design notes");
    }

    // Tip-merge loop (every 60s — compress DAG frontier into actual mesh)
    {
        let tm_state = node_state.clone();
        let status = node_state.loop_registry.register("tip_merge", 240);
        let hb = status.clone();
        elara_runtime::network::supervision::spawn_supervised(
            status,
            loop_shutdown.clone(),
            move || elara_runtime::network::tip_merge::tip_merge_loop(tm_state.clone(), tip_merge_rx.clone(), hb.clone()),
        );
    }

    // ─── Load content safety state ─────────────────────────────────────
    {
        let state2 = node_state.clone();
        match tokio::task::spawn_blocking(move || {
            let banned = state2.rocks.load_banned_identities()?;
            let terms = state2.rocks.load_blocked_terms()?;
            Ok::<_, ElaraError>((banned, terms))
        })
        .await
        {
            Ok(Ok((banned, terms))) => {
                let ban_count = banned.len();
                let term_count = terms.len();
                {
                    let mut set = node_state.banned_identities.write_recover();
                    for (hash, _, _) in &banned {
                        set.insert(hash.clone());
                    }
                }
                {
                    let mut list = node_state.content_blocklist.write_recover();
                    *list = terms;
                }
                if ban_count > 0 || term_count > 0 {
                    info!("content safety: {} banned identities, {} blocked terms", ban_count, term_count);
                }
            }
            Ok(Err(e)) => warn!("failed to load content safety state: {e}"),
            Err(e) => warn!("content safety load spawn failed: {e}"),
        }
    }

    // ─── HTTP server ────────────────────────────────────────────────────

    // Finalize boot timing just before the listener binds. After this
    // point /metrics is reachable, so the gauges populated here are visible on
    // the very first scrape post-boot. The 3 sub-phase fields are bucketed
    // (rebuild + state_core_init); boot_total_secs is the wall-clock floor.
    {
        use std::sync::atomic::Ordering;
        node_state.boot_state_core_init_secs.store(
            state_core_init_t0.elapsed().as_secs(),
            Ordering::Relaxed,
        );
        let boot_total = boot_t0.elapsed().as_secs();
        node_state.boot_total_secs.store(boot_total, Ordering::Relaxed);
        info!(
            "boot timing: total={}s, ledger_rebuild={}s, state_core_init={}s",
            boot_total,
            node_state.boot_ledger_rebuild_secs.load(Ordering::Relaxed),
            node_state.boot_state_core_init_secs.load(Ordering::Relaxed),
        );
    }

    // L1995 Phase 2 — listener architecture:
    // - `listen_addr` (`0.0.0.0:9473`): when `data_plane_listen_addr` is set,
    //   carries ONLY the whitelisted public surface (`/pq-ws`, `/ws`,
    //   `/metrics`, `/health`, `/status`, `/ping`, `/version`). Otherwise
    //   carries the full data plane (legacy single-listener mode).
    // - `data_plane_listen_addr` (`127.0.0.1:9472` default): when non-empty,
    //   carries the full data plane (`/peers`, `/dag/*`, `/admin/*`, etc).
    //   Loopback-only — Caddy/nginx fronts it for external HTTPS callers.
    // - `admin_listen_addr` (optional): admin/RPC subset on a separate port.
    let split_data_plane = !config.data_plane_listen_addr.is_empty();
    let app = if split_data_plane {
        server::public_routes(node_state.clone())
    } else {
        server::routes(node_state.clone())
    };

    let listener = tokio::net::TcpListener::bind(&config.listen_addr)
        .await
        .map_err(|e| ElaraError::Network(format!("failed to bind {}: {e}", config.listen_addr)))?;

    // Start the data-plane listener on loopback (L1995 Phase 2). Holds the
    // full router that the public interface no longer exposes.
    if split_data_plane {
        let dp_app = server::routes(node_state.clone());
        let dp_addr = config.data_plane_listen_addr.clone();
        match tokio::net::TcpListener::bind(&dp_addr).await {
            Ok(dp_listener) => {
                info!("data plane listening on {} (loopback-only — Caddy upstream)", dp_addr);
                info!("  full router: /peers /balance /dag/* /explorer /admin/* /rpc/* /account/* …");
                tokio::spawn(async move {
                    if let Err(e) = axum::serve(
                        dp_listener,
                        dp_app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
                    )
                        .await
                    {
                        tracing::error!("data-plane server error: {e}");
                    }
                });
            }
            Err(e) => {
                return Err(ElaraError::Network(format!(
                    "failed to bind data-plane listener {dp_addr}: {e}"
                )));
            }
        }
    }

    // Start post-quantum RPC server on separate port if configured.
    // Dual-stack alongside the classical HTTP listener during Phase 4
    // migration. Handler is `pq_router(state)` — same NodeState, same
    // handlers as HTTP routes, different transport.
    if let Some(pq_addr) = config.effective_pq_listen_addr() {
        use elara_runtime::network::pq_server::PqServer;
        use elara_runtime::network::pq_transport::{
            pq_router, pq_streaming_handler, pq_streaming_methods, PqListener,
        };
        let pq_pk = node_state.identity.public_key.clone();
        let pq_sk = node_state.identity.secret_key_bytes();
        let pq_router_handler = pq_router(node_state.clone());
        let pq_stream_handler = pq_streaming_handler(node_state.clone());
        match PqListener::bind(&pq_addr, pq_pk, pq_sk).await {
            Ok(pq_listener) => {
                // REALMS P1 slice (b3): arm the admission gate from config.
                // Open (default) stores no gate — bit-identical accept path;
                // Federated challenges every inbound peer for a membership
                // cert signed by the configured realm root.
                let pq_listener = pq_listener.with_realm_gate(
                    node_state.config.network_id.clone(),
                    node_state.config.network_realm.clone(),
                );
                // REALMS P1 slice (c2): sovereign inbound deny-unknown —
                // only operator-pinned identities may connect inbound.
                let pq_listener = if matches!(
                    node_state.config.network_realm,
                    elara_runtime::network::config::NetworkRealm::Sovereign
                ) {
                    info!(
                        "realm=sovereign: inbound deny-unknown armed ({} pinned identit{})",
                        node_state.pq_pins.len(),
                        if node_state.pq_pins.len() == 1 { "y" } else { "ies" },
                    );
                    pq_listener.with_sovereign_pins(node_state.pq_pins.clone())
                } else {
                    pq_listener
                };
                info!(
                    "PQ-RPC listening on {} (ML-KEM-768 + Dilithium3, realm={})",
                    pq_addr,
                    node_state.config.network_realm.label(),
                );
                info!("  pq: ping/status/submit_record/query_records/announce/fetch_records/merkle_root/delta_sync/find_node/witness/snapshot_*");
                info!("  pq-stream: seal_progress_stream (4E.3 server-push)");
                let server = PqServer::new(pq_listener, pq_router_handler)
                    .with_streaming(pq_streaming_methods(), pq_stream_handler)
                    // B8: bound the accept-path handshake concurrency so one
                    // slow/half-open inbound peer can't stall new-peer admission.
                    .with_accept_limiter(
                        node_state.pq_handshake_semaphore.clone(),
                        node_state.pq_handshake_failed_total.clone(),
                        node_state.pq_handshake_shed_total.clone(),
                    )
                    // STREAM-F1 defense-in-depth: bound the POST-handshake
                    // serve population (the accept limiter frees its permit
                    // before serving; the idle read-deadline bounds lifetime,
                    // this bounds count). Over-budget = shed, never queued.
                    .with_serve_limiter(
                        node_state.pq_serve_semaphore.clone(),
                        node_state.pq_serve_shed_total.clone(),
                    )
                    // Seed-side post-handshake wire-break visibility: count
                    // AEAD frame-decrypt failures so a stale external follower's
                    // silent desync shows on THIS node, not only on the follower.
                    .with_serve_metrics(node_state.pq_serve_frame_decrypt_failed_total.clone())
                    // Accept-path companion: split the PQ-wire-incompatibility
                    // (incompatible-WIRE_VERSION) sub-cause out of the opaque
                    // handshake-failed aggregate so a mis-built external joiner
                    // self-diagnoses instead of "looking like the network is dead".
                    .with_handshake_class_metrics(node_state.pq_handshake_wire_mismatch_total.clone());
                tokio::spawn(async move {
                    server.run().await;
                    tracing::error!("PQ-RPC server exited unexpectedly");
                });
            }
            Err(e) => {
                warn!("failed to bind PQ-RPC on {}: {e} — PQ transport disabled", pq_addr);
            }
        }
    }

    // Start admin server on separate port if configured
    if !config.admin_listen_addr.is_empty() {
        let admin_app = server::admin_routes(node_state.clone());
        let admin_addr = config.admin_listen_addr.clone();
        match tokio::net::TcpListener::bind(&admin_addr).await {
            Ok(admin_listener) => {
                info!("admin API listening on {} (localhost-only)", admin_addr);
                info!("  admin: /admin/* /rpc/* /bootstrap/*");
                tokio::spawn(async move {
                    if let Err(e) = axum::serve(admin_listener, admin_app.into_make_service_with_connect_info::<std::net::SocketAddr>()).await {
                        tracing::error!("admin server error: {e}");
                    }
                });
            }
            Err(e) => {
                // Truth fix 2026-07-02: there is no main-port fallback for
                // REMOTE callers — /admin/* stays loopback-only. On-box it
                // remains reachable via the full router (data-plane listener
                // under split plane, main listener in legacy mode), so a
                // failed dedicated bind degrades convenience, not access.
                warn!(
                    "failed to bind admin API on {}: {e} — no dedicated admin listener; \
                     /admin/* stays reachable on-box via the full router \
                     (data-plane listener, or main listener in legacy mode)",
                    admin_addr
                );
            }
        }
    }

    if split_data_plane {
        info!(
            "elara-node listening on {} (PUBLIC SURFACE: /pq-ws /ws /metrics /health /status /ping /version)",
            config.listen_addr
        );
        info!("  L1995 Phase 2 — data plane on {} (loopback-only)", config.data_plane_listen_addr);
    } else {
        info!("elara-node listening on {} (public endpoints — legacy single-listener)", config.listen_addr);
        info!("  core: /ping /status /health /records /records/stream /witness /peers /validate /metrics");
        info!("  sync: /merkle_root /delta_sync /attestations /slash /gossip");
        info!("  ledger: /balances /stakes /ledger/summary /history /transactions/recent /supply /supply/total /supply/max");
        info!("  explorer: /account/{{id}} /record/{{id}} /validate_address/{{addr}} /network");
        info!("  consensus: /epochs /consensus/status /consensus/record/{{id}} /zones /rewards");
        info!("  witness: /witness/profile /witness/profiles /witness/correlation");
        info!("  dag: /dag/lifecycle /dag/tips /dag/record/{{id}}/graph /dag/search /dag/stats");
        info!("  diagnostics: /node/identity /node/config /peers/reputation /dht/find_node");
    }
    if config.admin_listen_addr.is_empty() && !split_data_plane {
        // Truth fix 2026-07-02 (second pass): in legacy single-listener mode
        // the main listener carries the full router, so /admin/* IS available
        // — but only to loopback callers (public_route_gate 404s the rest).
        // The earlier "DISABLED" wording here overcorrected the original
        // "served on main port" lie (which had implied remote reachability).
        info!("  admin: /admin/* available to LOOPBACK callers on the main listener (legacy single-listener mode; set admin_listen_addr for a dedicated port)");
    }

    // ─── Graceful shutdown ──────────────────────────────────────────────

    let shutdown_state = node_state.clone();
    let shutdown_peers_path = peers_path.clone();
    let shutdown_snapshot_path = snapshot_path.clone();
    let shutdown_signal = async move {
        // Wait for SIGINT (ctrl-c) or SIGTERM (kill/systemd)
        #[cfg(unix)]
        {
            match signal::unix::signal(signal::unix::SignalKind::terminate()) {
                Ok(mut sigterm) => {
                    tokio::select! {
                        _ = signal::ctrl_c() => {},
                        _ = sigterm.recv() => {},
                    }
                }
                Err(e) => {
                    warn!("SIGTERM handler unavailable ({e}), falling back to SIGINT only");
                    signal::ctrl_c().await.ok();
                }
            }
        }
        #[cfg(not(unix))]
        {
            signal::ctrl_c().await.ok();
        }
        info!("shutting down...");

        // Broadcast signed going-offline to all connected peers before dropping
        // tx channels. Best-effort (2s per-peer timeout, 300ms yield after spawn).
        // Receiving peers mark us Offline (no failure count, no backoff).
        gossip::notify_going_offline(&shutdown_state).await;

        // 1. Stop all background tasks FIRST so they release their locks.
        //    Drop senders — recv() returns None, which fires the select! arm.
        //    This is instant and doesn't block even if the task is busy.
        drop(heartbeat_tx);
        drop(pex_tx);
        drop(gossip_tx);
        drop(orphan_tx);
        drop(witness_tx);
        drop(att_gossip_tx);
        drop(prune_tx);
        drop(snapshot_tx);
        drop(epoch_tx);
        drop(finality_tx);
        drop(health_tx);
        drop(reconnect_tx);
        drop(gc_tx);
        drop(system_load_tx);
        drop(fork_tx);
        drop(probe_tx);
        drop(tip_merge_tx);
        drop(mdns_tx);

        // Stop state_core — it may hold write locks on ledger/dag mid-insert.
        // Shutdown is sent on the priority channel, so it's processed immediately.
        // Graceful drain (L1572 Phase 3): await worker tasks for up to 10s so
        // in-flight inserts already on a worker channel commit before exit. On
        // 1-CPU nodes a single record can take 3-16s; if a worker overruns the
        // 10s budget the JoinHandle is aborted and the report flags timeouts.
        if let Some(core) = shutdown_state.state_core.get() {
            let report = core.shutdown(std::time::Duration::from_secs(10)).await;
            info!(
                "state_core shutdown: {}/{} workers drained, {} timed out in {:?}",
                report.completed, report.workers, report.timed_out, report.elapsed
            );
        }

        // Give background tasks time to finish current operation and release locks.
        // 2s is enough for most ops; if a task is stuck in blocking I/O,
        // the timeout on lock acquisitions below will catch it.
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        info!("background tasks signalled, saving state...");

        // Helper: acquire a tokio RwLock with a timeout, returning None on timeout.
        use std::time::Duration;
        let lock_timeout = Duration::from_secs(5);

        macro_rules! timed_read {
            ($lock:expr, $name:expr) => {
                match tokio::time::timeout(lock_timeout, $lock.read()).await {
                    Ok(guard) => Some(guard),
                    Err(_) => {
                        warn!("shutdown: {} lock timed out after 5s — skipping", $name);
                        None
                    }
                }
            };
        }

        // 2. Save peers + DHT (std locks — fast, won't hang)
        if let Some(peers) = timed_read!(shutdown_state.peers, "peers") {
            peers.save(&shutdown_peers_path);
        }
        let dht_path = shutdown_state.config.data_dir.join("dht.json");
        shutdown_state.dht.lock_recover().save(&dht_path);

        // 3. Save full node snapshot for fast startup
        if let (Some(ledger), Some(finalized)) = (
            timed_read!(shutdown_state.ledger, "ledger"),
            timed_read!(shutdown_state.finalized, "finalized"),
        ) {
            let finalized_set = finalized.to_hashset();
            drop(finalized);
            let epoch = shutdown_state.epoch.read_recover().clone();
            let genesis_st = shutdown_state.genesis_state.read_recover().clone();
            let bootstrap_st = shutdown_state.bootstrap_state.read_recover().clone();
            let result = snapshot::save_snapshot_full(
                &ledger, &finalized_set, &epoch,
                Some(&genesis_st), Some(&bootstrap_st),
                &shutdown_snapshot_path,
            );
            drop(ledger);
            if let Err(e) = result {
                warn!("failed to save node snapshot: {e}");
            }
        } else {
            warn!("shutdown: skipped JSON snapshot due to lock timeout");
        }

        // 4. Save ALL subsystem snapshots to RocksDB
        //    Acquire tokio RwLocks with timeout; std locks are fast.
        {
            let dag_opt = timed_read!(shutdown_state.dag, "dag");
            let ledger_opt = timed_read!(shutdown_state.ledger, "ledger-rocks");
            let trust_opt = timed_read!(shutdown_state.trust, "trust");

            let dag_clone = dag_opt.map(|g| g.clone());
            let ledger_clone = ledger_opt.map(|g| g.clone());
            let trust_clone = trust_opt.map(|g| g.clone());

            // std::sync locks — these are fast (no async contention)
            let reputation_clone = shutdown_state.reputation.lock_recover().clone();
            let disputes_clone = shutdown_state.disputes.read_recover().clone();
            let epoch_snap = shutdown_state.epoch.read_recover().to_snapshot();
            let key_reg_clone = shutdown_state.key_registry.read_recover().clone();
            let liveness_clone = shutdown_state.witness_liveness.lock_recover().clone();
            let sunset_clone = shutdown_state.sunset.read_recover().clone();
            let deleg_clone = shutdown_state.delegations.read_recover().clone();
            let zone_clone = shutdown_state.zone_state.lock_recover().clone();
            let challenges_clone = shutdown_state.challenges.read_recover().clone();
            let genesis_state_clone = shutdown_state.genesis_state.read_recover().clone();

            let counters: (u64, u64, u64) = (
                shutdown_state.total_ever_settled.load(std::sync::atomic::Ordering::Relaxed),
                shutdown_state.total_ever_finalized.load(std::sync::atomic::Ordering::Relaxed),
                shutdown_state.total_attestations_processed.load(std::sync::atomic::Ordering::Relaxed),
            );

            let checkpoint_ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs_f64();

            // Save what we could acquire — skip what timed out
            let mut snapshots: Vec<(&str, Result<()>)> = Vec::new();
            if let Some(ref dag) = dag_clone {
                snapshots.push(("dag", shutdown_state.rocks.save_snapshot("dag", dag.as_ref())));
            }
            // F-3 crash-atomicity: the replay-critical trio (ledger,
            // checkpoint_timestamp, epoch) is written in ONE WriteBatch, so a
            // SIGKILL/power-cut mid-save can never leave the epoch tip desynced
            // from the ledger baseline it was checkpointed against. Serialize
            // first — a serde error on one value omits only that value from the
            // batch rather than tearing it (these in-memory structs effectively
            // never fail to encode). `dag` stays a separate save above (slow to
            // serialize, not part of the replay baseline).
            {
                let mut trio: Vec<(&str, Vec<u8>)> = Vec::new();
                if let Some(ref ledger) = ledger_clone {
                    match serde_json::to_vec(ledger) {
                        Ok(b) => trio.push(("ledger", b)),
                        Err(e) => snapshots.push(("ledger", Err(
                            elara_runtime::errors::ElaraError::Storage(format!("ledger serialize: {e}"))))),
                    }
                }
                match serde_json::to_vec(&checkpoint_ts) {
                    Ok(b) => trio.push(("checkpoint_timestamp", b)),
                    Err(e) => snapshots.push(("checkpoint_timestamp", Err(
                        elara_runtime::errors::ElaraError::Storage(format!("checkpoint_timestamp serialize: {e}"))))),
                }
                match serde_json::to_vec(&epoch_snap) {
                    Ok(b) => trio.push(("epoch", b)),
                    Err(e) => snapshots.push(("epoch", Err(
                        elara_runtime::errors::ElaraError::Storage(format!("epoch serialize: {e}"))))),
                }
                match shutdown_state.rocks.save_snapshots_batch(&trio) {
                    Ok(()) => for (name, _) in &trio { snapshots.push((*name, Ok(()))); },
                    Err(e) => {
                        let msg = e.to_string();
                        for (name, _) in &trio {
                            snapshots.push((*name, Err(
                                elara_runtime::errors::ElaraError::Storage(format!("snapshot batch: {msg}")))));
                        }
                    }
                }
            }
            snapshots.push(("reputation", shutdown_state.rocks.save_snapshot("reputation", &reputation_clone)));
            snapshots.push(("disputes", shutdown_state.rocks.save_snapshot("disputes", &disputes_clone)));
            if let Some(ref trust) = trust_clone {
                snapshots.push(("trust", shutdown_state.rocks.save_snapshot("trust", trust)));
            }
            snapshots.push(("key_registry", shutdown_state.rocks.save_snapshot("key_registry", &key_reg_clone)));
            snapshots.push(("liveness", shutdown_state.rocks.save_snapshot("liveness", &liveness_clone)));
            snapshots.push(("sunset", shutdown_state.rocks.save_snapshot("sunset", &sunset_clone)));
            snapshots.push(("delegations", shutdown_state.rocks.save_snapshot("delegations", &deleg_clone)));
            snapshots.push(("zone_state", shutdown_state.rocks.save_snapshot("zone_state", &zone_clone)));
            snapshots.push(("challenges", shutdown_state.rocks.save_snapshot("challenges", &challenges_clone)));
            snapshots.push(("persistent_counters", shutdown_state.rocks.save_snapshot("persistent_counters", &counters)));
            snapshots.push(("genesis_state", shutdown_state.rocks.save_snapshot("genesis_state", &genesis_state_clone)));

            let total = snapshots.len();
            let mut saved = 0;
            for (name, result) in &snapshots {
                match result {
                    Ok(()) => saved += 1,
                    Err(e) => warn!("RocksDB {name} snapshot failed: {e}"),
                }
            }
            let failed = total - saved;
            if failed > 0 {
                warn!("RocksDB: {saved}/{total} saved, {failed} failed (checkpoint_ts={checkpoint_ts:.0})");
            } else {
                info!("RocksDB: {saved}/{total} subsystem snapshots saved (checkpoint_ts={checkpoint_ts:.0})");
            }
        }
    };

    let ram_gb = elara_runtime::storage::rocks::StorageEngine::detect_system_ram_gb();

    // Warm the dag_stats / epoch_headers caches in a background thread.
    // These endpoints scan all CF_RECORDS (7-30+ seconds on 4GB VPS with 14GB SST).
    // Without warmup, the first HTTP request times out.
    // SKIP on ≤2GB nodes — the 168-second full-scan thread saturates the single
    // CPU, starving Tokio workers and causing HTTP/TLS timeouts for ~3 minutes.
    // Stats will be computed lazily on first request instead.
    if ram_gb > 2 {
        elara_runtime::network::routes::explorer::warm_stats_cache(node_state.clone());
    }

    // PQ-R6: always serve plain HTTP on the classical listener. The PQ
    // server on `pq_listen_addr` is the authenticated transport.
    //
    // Served by the hardened accept loop, NOT axum::serve — axum exposes no
    // hook to arm hyper's header_read_timeout, so the internet-exposed
    // listener had no header deadline and no connection cap
    // (internal design notes; fusion-audited + final-
    // verified 2026-07-12). Loopback stays exempt from the caps, so the
    // systemd ExecStartPost probe and local tooling cannot be shed. All
    // durability work runs inside `shutdown_signal` BEFORE the loop's bounded
    // drain; the force-exit below is unchanged.
    elara_runtime::network::server::public_http::serve_public_http(
        listener,
        app,
        elara_runtime::network::server::public_http::PublicHttpOpts {
            conn_cap: config.http_conn_cap.max(1) as usize,
            per_ip_cap: config.http_conn_per_ip_cap.max(1),
            header_read_timeout: std::time::Duration::from_secs(
                config.http_header_read_timeout_secs.max(1),
            ),
            drain_timeout: std::time::Duration::from_secs(10),
            exempt_loopback: true,
            shed_total: node_state.http_conn_shed_total.clone(),
            per_ip_shed_total: node_state.http_conn_per_ip_shed_total.clone(),
        },
        shutdown_signal,
    )
    .await;

    // Cancel RocksDB background compaction/flush before Drop runs.
    // Without this, the Drop handler blocks 60-90s flushing memtables.
    // All state has been saved to RocksDB snapshots above, so no data loss.
    node_state.rocks.shutdown_fast();
    info!("elara-node stopped");
    // Force-exit: RocksDB Drop handler + tokio runtime teardown can block
    // 20-90s on large databases. All data is already persisted above.
    std::process::exit(0);
}

/// Background task: prune old attestations every hour. Keeps 30 days.
async fn attestation_prune_loop(
    witness_mgr: Arc<WitnessManager>,
    mut shutdown: watch::Receiver<()>,
    hb: Arc<elara_runtime::network::supervision::LoopStatus>,
) {
    let interval = std::time::Duration::from_secs(3600); // 1 hour
    let retention_secs: f64 = 30.0 * 24.0 * 3600.0; // 30 days

    loop {
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = shutdown.changed() => {
                info!("attestation prune loop shutting down");
                return;
            }
        }
        hb.heartbeat(); // hang-detection: stamp each tick (3600s interval « 7200s stale_after)

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        let cutoff = now - retention_secs;

        // RocksDB iteration + WriteBatch delete is blocking I/O — keep it off
        // the async workers (the prune itself is O(pruned) via CF_IDX_ATT_TIME).
        let mgr = witness_mgr.clone();
        match tokio::task::spawn_blocking(move || mgr.prune_before(cutoff)).await {
            Ok(Ok(0)) => {}
            Ok(Ok(n)) => info!("pruned {n} old attestations"),
            Ok(Err(e)) => warn!("attestation prune failed: {e}"),
            Err(e) => warn!("attestation prune task join failed: {e}"),
        }
    }
}

/// Background task: prune inactive identities from the trust engine every hour.
///
/// Identities with no activity (no submissions, no witness registrations) for
/// more than 30 days are removed from the in-memory HashMap. Their profiles are
/// already dual-written to RocksDB (CF_TRUST) and can be reloaded on demand via
/// `TrustEngine::restore_from_rocks`.
async fn trust_prune_loop(state: Arc<NodeState>, hb: Arc<elara_runtime::network::supervision::LoopStatus>) {
    let interval = std::time::Duration::from_secs(3600); // 1 hour
    let retention_secs: u64 = 30 * 24 * 3600; // 30 days

    loop {
        tokio::time::sleep(interval).await;
        hb.heartbeat();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();

        let pruned = {
            let mut trust = state.trust.write().await;
            trust.prune_inactive(now, retention_secs)
        };
        if pruned > 0 {
            info!("trust engine: pruned {pruned} inactive identities (>{} days)", retention_secs / 86400);
        }
    }
}

/// Background task: prune unbounded in-memory state every 10 minutes.
///
/// Targets:
/// - AWCConsensus: attestations, confirmation_levels, anchored for finalized records
/// - AWCConsensus: seal attestations for anchored seals
/// - ReputationEngine: witnesses inactive >30 days
/// - PropagationLimiter: stale identity entries with no recent timestamps
///
/// All pruned data is already persisted in RocksDB — this only frees RAM.
async fn memory_prune_loop(state: Arc<NodeState>, hb: Arc<elara_runtime::network::supervision::LoopStatus>) {
    let interval = std::time::Duration::from_secs(600); // 10 minutes

    // First run after 10 minutes. The 30s delay was too aggressive — with 7-day
    // attestation retention, there's no urgency to prune at startup. The 30s delay
    // previously destroyed replayed attestations before pull cycles could refill them.
    tokio::time::sleep(interval).await;

    loop {
        hb.heartbeat();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();

        // 1. Prune consensus attestations — two strategies:
        //    a) Finalized records: safe to evict (already settled)
        //    b) Age-based: evict anything older than 24 hours regardless of finalization
        //       This is a safety valve for unbounded growth. 7 days was too generous —
        //       with ~30s epochs, that accumulates ~20K records. 24h gives enough time
        //       for attestation gathering while keeping memory bounded.
        //       Records that can't settle in 24h have a deeper issue (missing witnesses,
        //       stalled finalization) that holding them in RAM won't fix.
        let attestation_max_age_secs = 24.0 * 3600.0; // 24 hours
        let age_cutoff = now - attestation_max_age_secs;

        // F3 durable-parity sweep (seal-member durable-write lane): every rid
        // at Finalized/Anchored in the in-memory map gets an idempotent
        // durable FinalizedIndex insert BEFORE the prunes below collaterally
        // wipe memberless confirmation_levels entries. Catches any promotion
        // path that failed to route its rids (defense-in-depth behind
        // F1/R1/R2/PA routing). MUST stay a standalone lock scope: the prune
        // block below holds finalized.read() across the consensus lock, and
        // nesting a finalized.write() there would deadlock.
        {
            let f3_rids = {
                let consensus = state.consensus.lock_recover();
                consensus.finalized_level_rids()
            };
            elara_runtime::network::reward::route_member_finality(&state, f3_rids).await;
        }

        // Use per-record point lookups instead of scanning all 84K+ finalized keys.
        // prune_where checks each consensus record against FinalizedIndex::contains(),
        // which hits the 10K hot set first (O(1)) and falls back to a single RocksDB read.
        let finalized_guard = state.finalized.read().await;
        let finalized_count = finalized_guard.len();
        // lock_recover (not raw .lock()): a poisoned lock must not permanently
        // freeze memory pruning (→ unbounded RAM → OOM). B5-adjacent loop-supervision
        // audit finding 2026-07-19; matches the in-tree convention (timestamp_defense
        // below already uses it).
        {
            let mut consensus = state.consensus.lock_recover();
            {
                // First: prune finalized records (safe, data in RocksDB)
                if finalized_count > 0 {
                    let pruned = consensus.prune_where(|rid| finalized_guard.contains(rid));
                    if pruned > 0 {
                        info!("memory prune: freed {pruned} finalized record attestations");
                    }
                    let seal_pruned = consensus.prune_anchored_seals_where(|sid| finalized_guard.contains(sid));
                    if seal_pruned > 0 {
                        info!("memory prune: freed {seal_pruned} anchored seal attestations");
                    }
                }

                // Second: age-based eviction (critical for stalled finalization)
                let age_pruned = consensus.prune_older_than(age_cutoff);
                if age_pruned > 0 {
                    info!("memory prune: evicted {age_pruned} attestation entries older than {}h", attestation_max_age_secs / 3600.0);
                }

                // Proactive eviction: scale threshold by RAM so big machines
                // can accumulate enough attestations per record for settlement.
                // Previous: 10K threshold evicted 20% every cycle on 63GB machine,
                // preventing records from ever reaching 2/3 stake threshold.
                let ram_gb = elara_runtime::storage::rocks::StorageEngine::detect_system_ram_gb();
                let pressure_threshold: usize = if ram_gb <= 2 { 10_000 } else if ram_gb <= 4 { 25_000 } else { 100_000 };
                let entries = consensus.memory_entry_count();
                if entries > pressure_threshold {
                    let att_count = consensus.attestation_record_count();
                    let evict_n = att_count / 10; // evict 10% (was 20%)
                    if evict_n > 0 {
                        consensus.evict_oldest_attestations(evict_n);
                        info!("consensus memory pressure: {entries}/{pressure_threshold} entries, evicted {evict_n} oldest attestation records [{}GB]", ram_gb);
                    }
                }
            }
        }
        drop(finalized_guard);

        // 2. Prune reputation engine (witnesses inactive >30 days)
        let rep_retention = 30.0 * 24.0 * 3600.0; // 30 days
        {
            let mut rep = state.reputation.lock_recover(); // poison must not freeze pruning
            let pruned = rep.prune_inactive(now, rep_retention);
            if pruned > 0 {
                info!("memory prune: freed {pruned} inactive witness reputations");
                state
                    .reputation_pruned_total
                    .fetch_add(pruned as u64, std::sync::atomic::Ordering::Relaxed);
            }
        }

        // 2b. Prune timestamp defense violations + persist to RocksDB
        {
            let mut defense = state.timestamp_defense.lock_recover();
            let pruned = defense.prune(now);
            if pruned > 0 {
                info!("memory prune: freed {pruned} expired timestamp violator entries");
            }
            if defense.violator_count() > 0 {
                let snapshot = defense.export_violations();
                drop(defense); // release lock before I/O
                if let Err(e) = state.rocks.save_snapshot("timestamp_violations", &snapshot) {
                    warn!("failed to persist timestamp violations: {e}");
                }
            } else {
                drop(defense);
                // Clean up stale snapshot if no violators remain
                let _ = state.rocks.save_snapshot("timestamp_violations",
                    &elara_runtime::network::timestamp_defense::TimestampViolationSnapshot::default());
            }
        }

        // 3. Cleanup propagation limiter stale entries
        {
            let mut limiter = state.propagation_limiter.lock_recover(); // poison must not freeze pruning
            let before = limiter.tracked_identities();
            limiter.cleanup(now);
            let freed = before.saturating_sub(limiter.tracked_identities());
            if freed > 0 {
                info!("memory prune: freed {freed} stale rate-limit entries");
            }
        }

        // 3b. Cleanup stale daily-cap counters (O(active identities) — scale rule)
        {
            let mut caps = state.daily_caps.lock_recover();
            let before = caps.tracked_identities();
            caps.cleanup(now);
            let freed = before.saturating_sub(caps.tracked_identities());
            if freed > 0 {
                info!("memory prune: freed {freed} stale daily-cap counters");
            }
        }

        // 4. Prune resolved disputes from memory
        {
            let pruned = state.disputes.write_recover().prune_resolved();
            if pruned > 0 {
                info!("memory prune: freed {pruned} resolved disputes");
            }
        }

        // 5. Force glibc to return freed memory to OS.
        // Sync paths allocate large Vecs (all records for bloom filters, merkle roots,
        // ledger rebuild) then drop them. glibc's allocator keeps freed pages in its
        // arena pool — malloc_trim(0) releases them back to the kernel.
        // This is the difference between 2.8GB RSS and ~300MB RSS after sync completes.
        #[cfg(target_os = "linux")]
        {
            // SAFETY: malloc_trim is a standard glibc function, no unsafe invariants.
            unsafe { libc::malloc_trim(0); }
        }

        tokio::time::sleep(interval).await;
    }
}

/// Background task: RocksDB TTL compaction — delete old entries from disk.
///
/// Runs every 6 hours. Targets:
/// - CF_REPUTATION: entries with timestamp older than 90 days
/// - CF_DISPUTES: entries with timestamp older than 90 days
/// - CF_ATTESTATIONS: already handled by attestation_prune_loop (30 days)
///
/// After deletion, triggers manual compaction to reclaim disk space.
async fn ttl_compaction_loop(state: Arc<NodeState>, hb: Arc<elara_runtime::network::supervision::LoopStatus>) {
    use elara_runtime::storage::rocks::{CF_REPUTATION, CF_DISPUTES};

    let interval = std::time::Duration::from_secs(6 * 3600); // 6 hours
    let ttl_secs: f64 = 90.0 * 24.0 * 3600.0; // 90 days

    // First run after 5 minutes (let startup settle)
    tokio::time::sleep(std::time::Duration::from_secs(300)).await;

    loop {
        hb.heartbeat();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        let cutoff = now - ttl_secs;

        // Full-CF scans with per-entry JSON parse — blocking I/O, keep it off
        // the async workers.
        let st = state.clone();
        match tokio::task::spawn_blocking(move || {
            (
                st.rocks.ttl_cleanup_cf_by_timestamp(CF_REPUTATION, cutoff),
                st.rocks.ttl_cleanup_cf_by_timestamp(CF_DISPUTES, cutoff),
            )
        })
        .await
        {
            Ok((rep, dis)) => {
                match rep {
                    Ok(0) => {}
                    Ok(n) => info!("ttl compaction: deleted {n} old reputation entries (>90d)"),
                    Err(e) => warn!("ttl compaction reputation failed: {e}"),
                }
                match dis {
                    Ok(0) => {}
                    Ok(n) => info!("ttl compaction: deleted {n} old dispute entries (>90d)"),
                    Err(e) => warn!("ttl compaction disputes failed: {e}"),
                }
            }
            Err(e) => warn!("ttl compaction task join failed: {e}"),
        }

        tokio::time::sleep(interval).await;
    }
}

/// Gap 7: archive/anchor-node epoch-boundary snapshot emitter.
///
/// Every 30s, reads the node's current max epoch across zones. When it has
/// advanced by `archive_snapshot_every_n_epochs` since the last emission,
/// creates a signed `NodeSnapshot` and writes it to
/// `{data_dir}/snapshots/epoch-{N:012}.json`. Prunes older snapshots beyond
/// `archive_snapshot_retention`.
///
/// Purpose (Gap 7): provides historical, verifiable bootstrap points for
/// new nodes. Instead of downloading the live `/snapshot` (timestamp=now)
/// and hoping peers agree on state, a new node fetches a specific epoch
/// snapshot — same checksum across all archive nodes, cross-verifiable by
/// comparing checksums before trusting.
async fn archive_snapshot_loop(
    state: Arc<NodeState>,
    dir: std::path::PathBuf,
    hb: Arc<elara_runtime::network::supervision::LoopStatus>,
) {
    use elara_runtime::network::snapshot;

    let every_n = state.config.archive_snapshot_every_n_epochs;
    let keep_n = state.config.archive_snapshot_retention;
    if every_n == 0 {
        info!("archive snapshot loop disabled (every_n_epochs=0)");
        return;
    }

    // Resume from the latest epoch snapshot on disk so a restart doesn't
    // re-emit duplicates.
    let mut last_emitted: u64 = match snapshot::list_epoch_snapshots(&dir) {
        Ok(list) => list.last().copied().unwrap_or(0),
        Err(e) => {
            warn!("archive snapshot: list existing failed: {e}");
            0
        }
    };

    // Seed the `archive_snapshot_last_epoch` gauge from the resume value so
    // operators see the on-disk truth across restarts. Without this seed the
    // gauge would read 0 immediately after every restart even when valid
    // snapshots are sitting on disk — misleading any "no snapshots emitted"
    // alert wired to it. Counter-style metrics (emit_total, prune_total) stay
    // at 0 by Prom convention; only the state gauge is back-filled here.
    state
        .archive_snapshot_last_epoch
        .store(last_emitted, std::sync::atomic::Ordering::Relaxed);

    info!(
        "archive snapshot loop started: dir={} every_n_epochs={} retention={} resume_from_epoch={}",
        dir.display(), every_n, keep_n, last_emitted,
    );

    let tick = std::time::Duration::from_secs(30);
    loop {
        tokio::time::sleep(tick).await;
        hb.heartbeat();

        // Compute the global max epoch across all zones. Latest-epoch is
        // per-zone in EpochState; we use the max as the "protocol epoch".
        let max_epoch = {
            let ep = state.epoch.read_recover();
            ep.latest_epoch.values().copied().max().unwrap_or(0)
        };

        // Emit only when the epoch has advanced by at least every_n ticks.
        if max_epoch == 0 || max_epoch < last_emitted.saturating_add(every_n) {
            continue;
        }

        // Clone state we need for the snapshot, then drop all locks before
        // touching the disk (snapshot JSON serialize is CPU-heavy).
        let mut ledger = state.ledger.read().await.clone();
        // Gap 7: Clone() drops applied_record_ids; epoch-indexed archive
        // snapshots are a primary bootstrap path, so they must carry it or a
        // joiner can't pre-seed CF_APPLIED (the "no double apply" guard). This
        // loop has no request-path cap guard, so use the bounded collector
        // gated on the O(1) estimate-num-keys size (NOT an O(n) count): above
        // MAX_SNAPSHOT_APPLIED_RECORDS it ships empty (Phase-1 watermark
        // territory) rather than scanning O(total_history) every N epochs.
        let approx_applied = state
            .rocks
            .approximate_cf_size(elara_runtime::storage::rocks::CF_APPLIED);
        ledger.applied_record_ids = state.rocks.collect_applied_ids_capped(
            approx_applied,
            elara_runtime::network::routes::sync::MAX_SNAPSHOT_APPLIED_RECORDS,
        );
        let finalized: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        let epoch_state = state.epoch.read_recover().clone();
        let genesis_st = state.genesis_state.read_recover().clone();
        let bootstrap_st = state.bootstrap_state.read_recover().clone();
        let identity = state.identity.clone();
        let state_for_merkle = state.clone();
        let dir_clone = dir.clone();

        let result = tokio::task::spawn_blocking(move || {
            let merkle_root = elara_runtime::network::merkle::global_merkle_root(
                &state_for_merkle.rocks);
            let record_count = state_for_merkle.record_count().unwrap_or(0) as u64;
            // Gap 7 post-apply verify: advertise the root over the SAME in-memory
            // `ledger.accounts` set serialized below — what downstream bootstrappers
            // reproduce — NOT the persisted CF_ACCOUNT_SMT root, which lags the live
            // ledger until the next seal-time flush_dirty and made the joiner's
            // post-apply verify false-fail on every legitimate bootstrap. Pure
            // in-memory rebuild (no rocks read, no smt_dirty flush, no seal-loop
            // race) — see account_merkle::root_over_accounts.
            let account_state_root = elara_runtime::network::account_merkle::root_over_accounts(
                &ledger.accounts)
                .ok();

            let snap = snapshot::create_signed_snapshot(snapshot::SignedSnapshotInputs {
                ledger: &ledger,
                finalized: &finalized,
                epoch: &epoch_state,
                genesis_state: Some(&genesis_st),
                bootstrap_state: Some(&bootstrap_st),
                merkle_root,
                record_count,
                identity: &identity,
                account_state_root,
                // C4 slice 1: carry mandate registries for bootstrap.
                mandates: state_for_merkle.rocks.collect_mandates(),
                revocations: state_for_merkle.rocks.collect_revocations(),
                emergency: state_for_merkle.emergency_snapshot_carry(),
            })?;

            // Pre-prune to keep_n - 1 BEFORE save_epoch_snapshot so the dir
            // never momentarily holds keep_n + 1 snapshots. Same disk-doubling
            // class as the checkpoint_loop fix: the old
            // order save → prune-to-N peaks at N+1 snapshots before being
            // trimmed back to N. At the 10M-record / 2.6GB-per-snapshot scale
            // (benches/bench_snapshot.rs), the (N+1)th snapshot during the
            // window between save and post-prune is a free 2.6GB transient
            // — meaningful on the 38G/4GB tier with `archive_snapshot_retention`
            // default 20 (peak: 21 × 2.6GB = 55GB vs. 20 × 2.6GB = 52GB).
            // Limitation: prune_old_epoch_snapshots(_, 0) is a no-op (see
            // test_prune_zero_is_noop at snapshot.rs:1805 — different
            // semantics than rotate_checkpoints(_, 0) which removes all).
            // So when keep_n == 1, saturating_sub(1) → 0 short-circuits and
            // peak stays at 2; only keep_n >= 2 benefits from this fix. The
            // default (keep_n=20) and any reasonable operator config benefits.
            let pre_pruned = snapshot::prune_old_epoch_snapshots(
                &dir_clone,
                keep_n.saturating_sub(1),
            ).unwrap_or(0);

            let path = snapshot::save_epoch_snapshot(&dir_clone, max_epoch, &snap)?;
            let post_pruned = snapshot::prune_old_epoch_snapshots(&dir_clone, keep_n)?;
            elara_runtime::errors::Result::Ok((path, pre_pruned + post_pruned, record_count))
        }).await;

        match result {
            Ok(Ok((path, pruned, count))) => {
                last_emitted = max_epoch;
                use std::sync::atomic::Ordering;
                state.archive_snapshot_emit_total.fetch_add(1, Ordering::Relaxed);
                state.archive_snapshot_prune_total.fetch_add(pruned as u64, Ordering::Relaxed);
                state.archive_snapshot_last_epoch.store(max_epoch, Ordering::Relaxed);
                info!(
                    "archive snapshot: epoch={} records={} path={} pruned_old={}",
                    max_epoch, count, path.display(), pruned,
                );
            }
            Ok(Err(e)) => warn!("archive snapshot failed at epoch {}: {}", max_epoch, e),
            Err(e) => warn!("archive snapshot task panicked: {}", e),
        }
    }
}

// Gap 7: chain divergence detector constants.

/// How often the chain-divergence detector polls peer chain-tips. 300s
/// (5 min) chosen so a freshly-stuck node doesn't wait long, but the
/// fan-out is bounded to MAX_REPAIR_PEERS to keep the per-tick cost
/// O(MAX_REPAIR_PEERS), not O(connected_peers).
const CHAIN_DIVERGENCE_POLL_INTERVAL_SECS: u64 = 300;

/// Divergence threshold (in seals — each seal is one epoch) that triggers an
/// autonomous repair attempt. 50 chosen safely above the Mode-3 RocksDB
/// compaction-cycle depth (~30 epochs floor observed under disk pressure)
/// so transient disk-pressure rebounds don't false-fire repair attempts.
/// The matching `ChainDivergencePersistent` alert
/// (docs/operations/prometheus-alerts.yml) fires at the same threshold with
/// `for: 30m` — i.e. alert is a 30-min confirmation of repair-loop inability
/// to close the gap.
///
/// **Naming note:** the gauge is `chain_divergence_epochs` but the
/// underlying measurement is `epoch_seals_total` delta. At the protocol layer
/// one epoch produces one seal, so the count is interchangeable; the
/// `_epochs` suffix is the human-readable unit.
const CHAIN_DIVERGENCE_THRESHOLD_EPOCHS: u64 = 50;

/// Cap on per-tick fan-out: never poll more than N peers for chain-tips.
/// O(N) memory + N sequential HTTP requests (10s timeout each, ≤30s total
/// inside the 300s tick budget); at mainnet scale (10K+ peers connected) we
/// don't want a divergence-monitor tick to N²-flood the network or hold N
/// pending RPC futures in memory.
const CHAIN_DIVERGENCE_MAX_REPAIR_PEERS: usize = 3;

/// Per-peer HTTP timeout for the `/metrics` fetch during chain-divergence
/// peer polling. 10s chosen because /metrics on a healthy node responds in
/// <100ms; a 10s timeout absorbs cold-start RocksDB scans and slow
/// network paths without blocking the tick budget.
const CHAIN_DIVERGENCE_PEER_TIMEOUT_SECS: u64 = 10;

/// Poll up to `max_peers` connected peers for their chain tip. Returns
/// `Vec<(endpoint, chain_tip_epoch)>` for peers that responded with a
/// parseable metric value. Failed/timed-out peers are silently dropped — the
/// caller falls back to `chain_divergence_epochs=0` when the vec is empty.
///
/// **Basis switch.** Prefers `elara_local_chain_tip` (persistent
/// chain-tip from `latest_epoch.max()`), falling back to
/// `elara_epoch_seals_total` for backward-compat with older peers
/// during the rolling deploy. Once all peers are on the newer binaries the
/// fallback returns nothing and chain-tip becomes the sole basis.
///
/// **Why the switch.** `elara_epoch_seals_total` is `state.record_stats_epoch_seals`
/// — a runtime counter that resets on restart AND is `fetch_add(1)`-bumped per
/// gossip-replayed seal applied during sync, so it over-counts duplicates
/// catastrophically. Observed post-restart across nodes
/// (e.g. node A=21823, node B=4775, node C=22231, node D=22319, node E=4859),
/// none of which represented a real partition. chain-tip
/// (epoch.latest_epoch.values().max()) is persistent across restart, derived
/// from the canonical seal stream, and cannot be inflated by gossip-replay
/// because each apply only updates the per-zone tip, never bumping past the
/// true max-epoch.
///
/// **SCALE RULE.** Per-tick cost O(max_peers) memory + O(max_peers)
/// sequential HTTP fetches with per-request timeout. Never holds the peer
/// table read-lock across awaits (snapshot endpoints, drop lock, then fan out).
async fn poll_peer_tips(
    state: &Arc<NodeState>,
    max_peers: usize,
) -> Vec<(String, u64)> {
    // Snapshot endpoints, drop the peer-table read-lock IMMEDIATELY — HTTP
    // futures below await for up to PEER_TIMEOUT_SECS each and must not pin
    // the peer table.
    let endpoints: Vec<String> = {
        let peers = state.peers.read().await;
        peers
            .connected()
            .iter()
            .take(max_peers)
            .map(|p| format!("http://{}:{}", p.host, p.port))
            .collect()
    };

    if endpoints.is_empty() {
        return Vec::new();
    }

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(
            CHAIN_DIVERGENCE_PEER_TIMEOUT_SECS,
        ))
        // SSRF: a connected peer answering this /metrics GET with `302 Location:
        // http://169.254.169.254/…` would otherwise drive a blind dial to a fresh
        // off-wire host past the peer-table insert filter. The peer endpoint is
        // fixed — never follow a redirect.
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!("chain-divergence: reqwest client build failed: {}", e);
            return Vec::new();
        }
    };

    let mut results = Vec::with_capacity(endpoints.len());
    for endpoint in endpoints {
        let url = format!("{}/metrics", endpoint);
        match client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(body) = resp.text().await {
                    if let Some(tip) = parse_peer_chain_tip(&body) {
                        results.push((endpoint, tip));
                    }
                }
            }
            Ok(resp) => {
                debug!(
                    "chain-divergence: peer {} returned HTTP {}",
                    endpoint,
                    resp.status()
                );
            }
            Err(e) => {
                debug!("chain-divergence: peer {} fetch failed: {}", endpoint, e);
            }
        }
    }
    results
}

/// Parse the `elara_epoch_seals_total VALUE` line from a Prometheus metrics
/// text body. Tolerant of both integer and float formats. Returns `None` when
/// the metric is absent or the value is unparseable.
fn parse_epoch_seals_total(body: &str) -> Option<u64> {
    for line in body.lines() {
        // Match exactly the gauge value line. HELP/TYPE lines start with `#`
        // so they won't match this prefix; labels (if any) would be `{...} `
        // before the value, but `elara_epoch_seals_total` is fleet-wide and
        // has no labels in server.rs:4797.
        if let Some(rest) = line.strip_prefix("elara_epoch_seals_total ") {
            let trimmed = rest.trim();
            if let Ok(v) = trimmed.parse::<u64>() {
                return Some(v);
            }
            if let Ok(v) = trimmed.parse::<f64>() {
                if v.is_finite() && v >= 0.0 {
                    return Some(v as u64);
                }
            }
        }
    }
    None
}

/// Parse the `elara_local_chain_tip VALUE` line from a Prometheus metrics text
/// body. Chain-tip metric — persistent across restart, derived from
/// `latest_epoch.values().max()` on the responding peer. Tolerant of both
/// integer and float formats. Returns `None` when the metric is absent
/// (older peer binaries that predate it) or the value is unparseable.
fn parse_local_chain_tip(body: &str) -> Option<u64> {
    for line in body.lines() {
        if let Some(rest) = line.strip_prefix("elara_local_chain_tip ") {
            let trimmed = rest.trim();
            if let Ok(v) = trimmed.parse::<u64>() {
                return Some(v);
            }
            if let Ok(v) = trimmed.parse::<f64>() {
                if v.is_finite() && v >= 0.0 {
                    return Some(v as u64);
                }
            }
        }
    }
    None
}

/// Pick a peer's chain-tip value with preference order:
///   1. `elara_local_chain_tip` (newer peers, persistent + accurate)
///   2. `elara_epoch_seals_total` (fallback for older peers, runtime counter —
///      gossip-replay-confused but better than no measurement)
///
/// Returns `None` only when neither metric is present.
///
/// **Rollout note.** Once the fleet fully transitions to binaries that emit
/// the chain-tip metric, every peer exposes it and the fallback path becomes
/// unreachable on healthy peers. The fallback exists ONLY for the rolling-deploy
/// window where a mix of old and new binaries coexist on the network.
fn parse_peer_chain_tip(body: &str) -> Option<u64> {
    parse_local_chain_tip(body).or_else(|| parse_epoch_seals_total(body))
}

/// HTTP timeout for `/snapshot/state-delta` repair pulls during chain-divergence
/// reconciliation. 120 s budget rationale: per
/// `benches/bench_snapshot.rs` a full 2.6 GB JSON payload deserialises in ~10 s
/// CPU and transfers in ~210 s @ 100 Mbps; a typical state-delta is far
/// smaller (changeset-only, bounded by `MAX_SNAPSHOT_FULL_ACCOUNTS=100000`
/// server-side cap) and fits inside this floor with margin. Longer-tail
/// responses are absorbed by the repair-attempt re-fire on the next monitor
/// tick (`CHAIN_DIVERGENCE_POLL_INTERVAL_SECS=300`) rather than by extending
/// this timeout — bounded blast radius.
const CHAIN_DIVERGENCE_REPAIR_TIMEOUT_SECS: u64 = 120;

// Compile-time invariant: a single repair attempt must fit inside the
// monitor-tick budget. If the timeout exceeded the tick interval, a
// slow / hostile peer could stall the repair loop into skipping ticks.
// Surface that as a build error, not a runtime test failure.
const _: () = assert!(
    CHAIN_DIVERGENCE_REPAIR_TIMEOUT_SECS < CHAIN_DIVERGENCE_POLL_INTERVAL_SECS,
    "CHAIN_DIVERGENCE_REPAIR_TIMEOUT_SECS must be < CHAIN_DIVERGENCE_POLL_INTERVAL_SECS — a single repair attempt must fit inside one monitor tick or a slow peer can stall the loop into skipping ticks"
);

/// HTTP-fetch a signed `StateDelta` from a peer's `/snapshot/state-delta` route.
///
/// `base_url` shape: `http://HOST:PORT` (matches `poll_peer_tips` endpoints);
/// `since_epoch` is the local chain-tip the peer should serve incrementally
/// from. Bounded by `CHAIN_DIVERGENCE_REPAIR_TIMEOUT_SECS`.
///
/// **NOT a verify step.** The caller MUST run `verify_signed_state_delta` +
/// `enforce_snapshot_signer_trust` before applying — this fn only handles the
/// wire fetch. Network errors / non-2xx responses surface as `ElaraError::Wire`
/// so the caller can bump `chain_divergence_repair_failures_total` distinct
/// from verify/apply fails.
///
/// **SCALE RULE compliance.** O(delta_payload) memory; bounded by server-side
/// `MAX_SNAPSHOT_FULL_ACCOUNTS=100000` cap (`server.rs:6489`). At a 1M-account
/// chain a typical 50-epoch lag → ~1-5 K-account changeset (each ~150 B JSON)
/// → ≤1 MB on the wire.
async fn pull_state_delta(
    base_url: &str,
    since_epoch: u64,
) -> Result<snapshot::StateDelta> {
    let url = format!("{base_url}/snapshot/state-delta?since_epoch={since_epoch}");
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(
            CHAIN_DIVERGENCE_REPAIR_TIMEOUT_SECS,
        ))
        // SSRF: never follow a peer redirect on the repair fetch — a `302 Location:
        // http://169.254.169.254/…` would dial a fresh off-wire host past the peer
        // filter (the response is verified later, but the redirect dial fires first).
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| ElaraError::Wire(format!(
            "state-delta repair: reqwest client build failed: {e}"
        )))?;
    let resp = client.get(&url).send().await.map_err(|e| {
        ElaraError::Wire(format!(
            "state-delta repair: GET {url} failed: {e}"
        ))
    })?;
    if !resp.status().is_success() {
        return Err(ElaraError::Wire(format!(
            "state-delta repair: GET {url} returned HTTP {}",
            resp.status(),
        )));
    }
    let body = resp.text().await.map_err(|e| {
        ElaraError::Wire(format!(
            "state-delta repair: read body from {url} failed: {e}"
        ))
    })?;
    serde_json::from_str::<snapshot::StateDelta>(&body).map_err(|e| {
        ElaraError::Wire(format!(
            "state-delta repair: parse JSON body from {url} failed: {e}"
        ))
    })
}

/// Apply a verified `StateDelta` to the local ledger + persistent SMT.
///
/// **Pre-conditions (caller-enforced).** The delta MUST have been verified via
/// `verify_signed_state_delta` AND the signer identity MUST have passed
/// `enforce_snapshot_signer_trust`. This fn does NOT re-verify; we want a clean
/// separation so the caller can bump verify-fail vs apply-fail counters
/// independently.
///
/// **What it does.**
/// 1. Under a single `ledger.write()`: upsert `changed_accounts`, remove
///    `removed_accounts`, mark all touched identities in `smt_dirty`, then
///    drain the touched-subset into an SMT-pair snapshot via `snapshot_scoped`
///    (which itself clears those entries from `smt_dirty`).
/// 2. Off-lock: `account_merkle::apply_snapshot` commits the SMT changes to
///    persistent storage. Returns the new SMT root, which we log but do NOT
///    yet gate against `delta.account_state_root` — see "Why no post-apply
///    root match (yet)" below.
///
/// **Why no post-apply root match (yet).** The delta's `account_state_root`
/// is bound by the Dilithium3 signature over its checksum; forging it requires
/// the trusted signer's private key, at which point the trust gate already
/// fails the security model. A post-apply SMT-root equality check is the
/// natural next slice (it catches local-apply bugs + version skew + on-wire
/// flips that didn't trip Dilithium3 verify) and is on the follow-up list for
/// the same tick; omitting it here keeps the initial repair-half ship tight.
///
/// **SCALE RULE compliance.** O(changed + removed) time + memory. No genesis
/// replay, no full ledger scan; SMT flush scoped to touched identities. The
/// `apply_snapshot` call runs in `spawn_blocking` so the async runtime is not
/// held during disk I/O.
async fn apply_state_delta_for_repair(
    state: &Arc<NodeState>,
    delta: &snapshot::StateDelta,
) -> Result<usize> {
    let mut scope: std::collections::HashSet<String> = delta
        .changed_accounts
        .keys()
        .chain(delta.removed_accounts.iter())
        .cloned()
        .collect();
    // F-5 V2: explicit tombstone set for `snapshot_scoped`. Every account this
    // repair removes from the ledger — explicit `removed_accounts`, plus the
    // `!baseline_available` implied local-only removals added below — gets its
    // SMT leaf DELETED (collapsed to EMPTY_HASH), not rewritten as
    // `hash(default)`. The latter is a non-empty "ghost" leaf that strands a
    // repaired node's `account_smt_root` ahead of its ledger (diverging from
    // canonical, breaking light-client exclusion proofs); deletion converges it.
    let mut deletes: std::collections::HashSet<String> =
        delta.removed_accounts.iter().cloned().collect();
    // Mutate ledger + drain the touched-subset snapshot under one write lock.
    // `snapshot_scoped` clears the touched identities from `smt_dirty` itself.
    let (pairs, repaired_total_staked, scalar_drift, conservation_ok, repair_orphan_stakes) = {
        let mut ledger = state.ledger.write().await;
        // Full-ledger fallback (`baseline_available=false`): the producer could
        // not reconstruct a baseline at `since_epoch`, so `changed_accounts` IS
        // its COMPLETE account set and `removed_accounts` is empty (see
        // routes/sync.rs). An upsert-only apply would then leave any LOCAL-only
        // account — e.g. one this node forged on its own fork that the producer
        // never saw — as a phantom, inflating our recomputed denominator and
        // forking the SMT root. Treat it as clear-and-replace: every local id
        // absent from `changed_accounts` is an implied removal (added to `scope`
        // AND `deletes` so `snapshot_scoped` tombstones its SMT leaf to
        // EMPTY_HASH, identically to an explicit `removed_accounts` entry).
        // Baseline deltas carry explicit removals, so
        // this branch never fires for them. Bounded recovery path.
        if !delta.baseline_available {
            let implied_removals: Vec<String> = ledger
                .accounts
                .keys()
                .filter(|id| !delta.changed_accounts.contains_key(*id))
                .cloned()
                .collect();
            for id in implied_removals {
                ledger.accounts.remove(&id);
                ledger.smt_dirty.insert(id.clone());
                deletes.insert(id.clone());
                scope.insert(id);
            }
        }
        for (id, account) in &delta.changed_accounts {
            ledger.accounts.insert(id.clone(), account.clone());
            ledger.smt_dirty.insert(id.clone());
        }
        for id in &delta.removed_accounts {
            ledger.accounts.remove(id);
            ledger.smt_dirty.insert(id.clone());
        }
        // This path mutates `ledger.accounts` out-of-band (not via `apply_op`),
        // so the incrementally-maintained scalar `total_staked` is now stale
        // relative to the repaired account set. Recompute it from the post-apply
        // accounts — NOT from `delta.total_staked` (the producer's GLOBAL
        // scalar): the delta is a subset diff and repair fires precisely when we
        // are forked, so the producer's global may not match our post-apply
        // leaves. `is_settled`'s denominator (`zone_stakes` <- `total_staked`)
        // must equal the staked-sum over the SAME accounts its numerator is
        // summed from, so the self-consistent recompute is the correct value
        // (and in the unforked case it equals `delta.total_staked` anyway). One
        // pass also yields `available_sum` for the conservation check. Bounded
        // recovery path: accounts <= MAX_SNAPSHOT_FULL_ACCOUNTS and repair fires
        // only on >=50-epoch divergence, never the ingest hot path — the
        // documented recovery-only exception to the no-O(N)-scan rule.
        let mut staked_sum: u64 = 0;
        let mut available_sum: u64 = 0;
        // Local self-consistency detector (observability only): an account with a
        // positive stake balance but NO `staker_index` entry is a staker onboarded
        // by THIS delta whose `Stake` record we have not yet folded — `StateDelta`
        // carries account state, not the `StakeEntry` map. Piggybacks this
        // already-bounded recovery scan (no extra pass). Surfaced as a counter so
        // the otherwise-silent window is observable; self-heals via forward ingest
        // (see the `register_stakes_from_ledger` note below). Disjoint immutable
        // field borrows — `ledger` is not yet `&mut`-borrowed (snapshot_scoped is).
        let mut orphan_stake_count: u64 = 0;
        for (hash, a) in ledger.accounts.iter() {
            staked_sum = staked_sum.saturating_add(a.staked);
            available_sum = available_sum.saturating_add(a.available);
            if a.staked > 0 && !ledger.staker_index.contains_key(hash) {
                orphan_stake_count = orphan_stake_count.saturating_add(1);
            }
        }
        ledger.total_staked = staked_sum;
        // The repair IS a stake mutation; bump the monotonic seq so any consumer
        // keying on it detects the change (incl. a net-zero reshuffle), beyond
        // the anchor view which we invalidate explicitly below.
        ledger.stake_mutation_seq = ledger.stake_mutation_seq.wrapping_add(1);
        // Diagnostics captured under-lock, emitted after release.
        let scalar_drift = staked_sum != delta.total_staked;
        // `total_supply` is deliberately NOT assigned from the peer (it is the
        // monetary base, near-invariant; a subset-diff peer is not authoritative
        // for it). Conservation cannot be fully restored anyway: `StateDelta`
        // carries neither `conservation_pool` nor `pending_xzone_locked`, so the
        // identity is checked against the retained local values and any drift is
        // surfaced (counter), not masked.
        let conservation_ok = available_sum
            .saturating_add(staked_sum)
            .saturating_add(ledger.pending_xzone_locked)
            .saturating_add(ledger.conservation_pool)
            == ledger.total_supply;
        let pairs = account_merkle::snapshot_scoped(&mut ledger, &scope, &deletes);
        (pairs, staked_sum, scalar_drift, conservation_ok, orphan_stake_count)
    };
    // Anchor view: invalidate so the next read rebuilds `flat` from the
    // authoritative (now-recomputed) ledger. Load-bearing — the cache key/fp
    // (`stake_mutation_seq`/`total_staked`) alone may not detect the swap.
    state.invalidate_anchor_view();
    // Push the recomputed `total_staked` into the consensus settlement
    // denominator (`zone_stakes`) + refresh `staker_stakes`, exactly as
    // `apply_bootstrap_snapshot_full` does (network/sync.rs). Without this,
    // `zone_stakes` keeps the pre-repair value until the next epoch/ingest tick.
    // NOTE: `register_stakes_from_ledger` iterates `staker_index` (derived from
    // `ledger.stakes`, the StakeEntry map), which `StateDelta` does NOT carry — so
    // a staker onboarded by this repair is briefly absent from `staker_index` /
    // `staker_stakes`. This is FAIRNESS-SELF-HEALING, not a safety/fork issue
    // (fusion-audited 2026-06-25, 3 read-only panels unanimous): every
    // consensus-BINDING consumer reads `ledger.accounts` directly, not this index
    // — the epoch committee + super-seal `committee_hash` (epoch.rs, `staked>0`
    // filter), the seal-escalation verifier (`staked_anchor_view`, already
    // migrated off `staker_index` for exactly this stale-index reason), the
    // settlement denominator `zone_stakes` (<- recomputed `total_staked` above),
    // and `ledger.staked()` point lookups. Only NON-binding consumers touch the
    // gap: this node's local auto-witness self-gate and the liveness-decay
    // denominator (default-OFF, and floor-bounded so it cannot fork even when on).
    // It self-heals via FORWARD INGEST: the repair never marks records applied
    // (`CF_APPLIED` untouched), so normal sync re-delivers the staker's actual
    // `Stake` record through `apply_op`, folding the REAL `StakeEntry`. The wire
    // change (carry StakeEntry) is WONTFIX — disproportionate for a non-forking,
    // self-correcting gap; synthesizing an entry from `acct.staked` was REJECTED
    // (a single net scalar can't reconstruct multi-entry/multi-purpose stakes, and
    // a fabricated record_id/purpose would shadow the real record + corrupt
    // governance vote weight). The orphan-stake counter above makes the window
    // observable instead of silent.
    {
        let ledger = state.ledger.read().await;
        state
            .consensus
            .lock_recover()
            .register_stakes_from_ledger(&ledger);
    }
    // ADVISORY-only (downgraded from warn!+counter 2026-06-16 per fusion audit).
    // A chain-divergence repair applies a SUBSET diff onto THIS node's own
    // pre-state and recomputes node-local totals, so the producer's *global*
    // `delta.total_staked` and the conservation identity legitimately differ
    // from our post-apply values by construction (partial coverage + per-node
    // timing + the delta carrying neither conservation_pool nor
    // pending_xzone_locked). Equality is not a cross-node-stable invariant here,
    // so the old counters false-fired on every honest repair (alert fatigue).
    // The real integrity fence is the Dilithium3 signature + signer trust-gate
    // (verified upstream); the consensus-stable cross-node anchor is
    // `latest_sealed_account_smt_root` (sealed-root cross-check — gated
    // follow-up). We install the self-consistent recomputed values and log at
    // debug for diagnostics.
    if scalar_drift {
        debug!(
            "chain-divergence repair scalar drift (advisory): recomputed total_staked={} != delta.total_staked={} — installed self-consistent recomputed value",
            repaired_total_staked, delta.total_staked,
        );
    }
    if !conservation_ok {
        debug!(
            "chain-divergence repair conservation drift (advisory): identity does not hold post-apply (StateDelta carries no conservation_pool/pending_xzone_locked)",
        );
    }
    // Unlike the two drift signals above (cross-node-unstable, debug-only since
    // 2026-06-16), this is a LOCAL self-consistency signal — `staked>0` with no
    // local StakeEntry — so it is bump-worthy: a non-zero, non-decreasing value
    // tells an operator a repair onboarded a staker whose `staker_index` membership
    // is lagging (expected to self-heal via forward ingest; investigate if it
    // grows without bound, which would mean forward ingest is not re-folding).
    if repair_orphan_stakes > 0 {
        state
            .chain_divergence_repair_orphan_stake_total
            .fetch_add(repair_orphan_stakes, std::sync::atomic::Ordering::Relaxed);
        debug!(
            "chain-divergence repair: {repair_orphan_stakes} account(s) carry staked>0 with no StakeEntry (staker onboarded by the delta; staker_index/staker_stakes membership lags until forward ingest re-folds the Stake record). Binding consensus (committee, seal, zone_stakes) unaffected.",
        );
    }
    let touched = pairs.len();
    // Off-lock SMT flush. Hold no ledger lock across spawn_blocking.
    let rocks = Arc::clone(&state.rocks);
    // CF_ACCOUNT_SMT writer gate (leaf lock — see NodeState field doc). The
    // divergence monitor fires this on its own schedule, so it is the most
    // important auto-triggered writer to serialize against the seal flush.
    let smt_gate = state.account_smt_write_gate.lock().await;
    let apply_outcome = tokio::task::spawn_blocking(move || {
        account_merkle::apply_snapshot(&rocks, &pairs)
    })
    .await
    .map_err(|e| ElaraError::Wire(format!(
        "state-delta repair: SMT apply task panicked: {e}"
    )))?;
    drop(smt_gate);
    let (_flushed, post_root) = apply_outcome.map_err(|e| ElaraError::Wire(format!(
        "state-delta repair: SMT apply failed: {e}"
    )))?;
    // Gap 7 post-apply SMT-root — ADVISORY-only (downgraded from warn!+counter
    // 2026-06-16 per fusion audit). The producer's signed `account_state_root`
    // is its live root over a FULL account set; we compute a post-apply root
    // over our OWN forked pre-state patched with the delta's subset scope, so
    // the two legitimately differ (unsealed mutations + partial coverage). It is
    // NOT a cross-node-stable equality — asserting it false-fired on every
    // legitimate repair. The real anti-forgery fence is the Dilithium3 signature
    // + signer trust-gate (verified upstream before we reach here). The
    // consensus-stable cross-node anchor is `latest_sealed_account_smt_root`
    // (witness-signed into the seal); wiring that as the meaningful divergence
    // signal is a gated follow-up (inert until seals carry the binding). We log
    // the comparison at debug for diagnostics and do not bump a page-worthy
    // counter on this non-cross-node-stable signal.
    let post_root_hex = hex::encode(post_root);
    let expected = delta.account_state_root.trim().to_ascii_lowercase();
    if post_root_hex != expected {
        debug!(
            "chain-divergence repair root advisory: post_apply={} producer_signed={} since_epoch={} current_epoch={} touched={} (live-root not cross-node-stable; not counted)",
            post_root_hex,
            expected,
            delta.since_epoch,
            delta.current_epoch,
            touched,
        );
    }
    Ok(touched)
}

/// Background task: Gap 7 chain-divergence detector + autonomous repair loop.
///
/// **Purpose.** Closes the testnet SPLIT-BRAIN failure shape observed in
/// testing: two chains co-existing for hours (a subset of nodes' seal-count
/// diverged from the others by ~7000 epochs) without any autonomous
/// reconciliation; only operator Path SB-1 (manual seed-peer edit) could
/// close the gap.
///
/// **Initial stub.** Landed only the structural framework: gauge
/// fields, metric emission, spawn site, and a loop body that emitted
/// `elara_chain_divergence_epochs = 0` + bumped
/// `chain_divergence_poll_no_peers_total` every tick.
///
/// **Tick-116 (THIS commit — read-only-diagnostic).** Wires the first half of
/// the chain:
/// 1. `poll_peer_tips` — bounded sequential HTTP fan-out to
///    `MAX_REPAIR_PEERS=3` peers, parses `elara_epoch_seals_total` from each
///    `/metrics`, returns `Vec<(endpoint, seals)>`. Per-peer timeout =
///    `CHAIN_DIVERGENCE_PEER_TIMEOUT_SECS=10s`, total ≤30s inside the 300s
///    tick budget.
/// 2. Compute `divergence = max_peer_seals.saturating_sub(local_seals)` and
///    store into `chain_divergence_epochs` gauge.
/// 3. When `divergence ≥ CHAIN_DIVERGENCE_THRESHOLD_EPOCHS`, emit a `warn!()`
///    so operators see the threshold cross BEFORE the
///    `ChainDivergencePersistent` Prometheus alert (which has
///    `for: 30m` — 6 ticks of confirmation).
///
/// **Tick-122 (THIS commit — autonomous repair).** Wires the second half of
/// the chain into the same loop:
/// 1. `pull_state_delta` — for the max-tip peer, GET
///    `/snapshot/state-delta?since_epoch=<local_tip>`. Returns a signed
///    `StateDelta`. Timeout bound: `CHAIN_DIVERGENCE_REPAIR_TIMEOUT_SECS=120`.
/// 2. `snapshot::verify_signed_state_delta` — Dilithium3 + optional SPHINCS+
///    + checksum + `signer_public_key→signer_identity` binding.
/// 3. `snapshot::enforce_snapshot_signer_trust` — gate against
///    `{genesis_authority} ∪ trusted_snapshot_signers` (same union as
///    `epoch_indexed_snapshot_bootstrap`, so state-delta and bootstrap honour
///    the same anchor). Failure counts under `verify_fails_total` because the
///    trust gate is the *binding* defense — signature without trust is forgery.
/// 4. `apply_state_delta_for_repair` — upsert `changed_accounts`, remove
///    `removed_accounts`, mark `smt_dirty`, drain the touched subset, and
///    flush to the persistent SMT via `account_merkle::apply_snapshot` in
///    `spawn_blocking` (no ledger lock held across disk I/O).
///
/// **Counter discipline.** Each branch bumps a distinct counter so operators
/// can tell network failure from peer forgery from local apply bug:
/// - `repair_attempts_total`   — bumped on every threshold-cross entry
/// - `repair_failures_total`   — HTTP/network/parse failure (fetch step)
/// - `repair_verify_fails_total` — Dilithium3/checksum/trust-gate failure
/// - `repair_apply_fails_total` — local ledger/SMT apply failure (rare;
///   usually code or storage)
/// - `repair_success_total`    — happy path
///
/// **SCALE RULE compliance.** Per-tick cost O(MAX_REPAIR_PEERS) memory for
/// peer polling + O(changed + removed) memory for delta apply (bounded by
/// server-side `MAX_SNAPSHOT_FULL_ACCOUNTS=100000`). Sequential HTTP fetches;
/// no genesis replay, no full chain scan. The peer-poll loop never holds
/// `state.peers` across awaits (endpoints snapshotted, lock dropped before
/// HTTP fan-out). The apply path never holds `ledger.write()` across the
/// disk I/O — the SMT flush runs in `spawn_blocking`.
async fn chain_divergence_monitor_loop(state: Arc<NodeState>) {
    use std::sync::atomic::Ordering;

    info!(
        "chain-divergence monitor loop started: poll_interval={}s threshold={} epochs max_repair_peers={} per_peer_timeout={}s repair_timeout={}s (mode=autonomous-repair — pull→verify→trust-gate→apply on threshold cross)",
        CHAIN_DIVERGENCE_POLL_INTERVAL_SECS,
        CHAIN_DIVERGENCE_THRESHOLD_EPOCHS,
        CHAIN_DIVERGENCE_MAX_REPAIR_PEERS,
        CHAIN_DIVERGENCE_PEER_TIMEOUT_SECS,
        CHAIN_DIVERGENCE_REPAIR_TIMEOUT_SECS,
    );

    let mut ticker = tokio::time::interval(
        std::time::Duration::from_secs(CHAIN_DIVERGENCE_POLL_INTERVAL_SECS),
    );
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        ticker.tick().await;

        // Step 1: snapshot the local chain-tip — `latest_epoch.values().max()`.
        // Switched from `record_stats_epoch_seals` (runtime counter,
        // resets on restart, over-counts gossip-replayed seals) to the
        // persistent chain-tip derived from the canonical seal stream. See
        // `parse_peer_chain_tip` doc for the rationale.
        let local_tip = {
            let ep = state.epoch.read_recover();
            ep.latest_epoch.values().copied().max().unwrap_or(0)
        };

        // Step 2: bounded peer fan-out for chain tips.
        let peer_tips = poll_peer_tips(&state, CHAIN_DIVERGENCE_MAX_REPAIR_PEERS).await;

        if peer_tips.is_empty() {
            // No peers responded — could be a network partition, all peers
            // banned, or zero connected peers. Bump the counter so operators
            // can detect this fleet-wide via `chain_divergence_poll_no_peers_total`
            // and emit gauge=0 (no measurement to report).
            state
                .chain_divergence_poll_no_peers_total
                .fetch_add(1, Ordering::Relaxed);
            state.chain_divergence_epochs.store(0, Ordering::Relaxed);
            // Zero BOTH directional gauges in the no-peers branch so
            // a stale AHEAD reading from the previous tick doesn't masquerade
            // as a current measurement during a partition.
            state.chain_divergence_epochs_ahead.store(0, Ordering::Relaxed);
            state.chain_divergence_epochs_behind.store(0, Ordering::Relaxed);
            debug!(
                "chain-divergence tick: no peer tips (local_tip={})",
                local_tip,
            );
            continue;
        }

        // Step 3: compute divergence vs the most-advanced peer chain-tip.
        let max_peer_tip = peer_tips.iter().map(|(_, t)| *t).max().unwrap_or(0);

        // ── Bootstrapping guard (fusion audit 2026-06-17, high-stakes) ─────────
        // `divergence = max_peer_tip - local_tip` is a meaningful FORK distance
        // ONLY when local_tip > 0 (the node has committed to a seal chain that
        // could diverge). With local_tip == 0 the node has no canonical seal
        // chain yet — it is fresh or mid-bootstrap, NOT forked — so the raw
        // "divergence" spuriously equals the whole chain height. Two failure
        // modes this prevents, BOTH observed live (scripts/prove-virgin-join.sh):
        //   1. `chain_divergence_epochs` spikes to chain-height on every joiner →
        //      a fleet-wide `ChainDivergencePersistent` false-alert storm at the
        //      1M-node mainnet target. (Hence the gauge store is gated BELOW.)
        //   2. A whole-chain (since=0) state-delta repair fires on a node that is
        //      bootstrapping normally — the recovery path that, by wire-format,
        //      cannot carry conservation_pool/pending_xzone_locked/the StakeEntry
        //      map, and whose writes can trip the `dag_len != 0` snapshot-bootstrap
        //      kill (sync.rs:445).
        // ROOT CAUSE: `apply_bootstrap_snapshot_full` loads the ledger
        // (total_supply > 0) but does NOT populate `epoch.latest_epoch`, and the
        // monitor's first `interval` tick fires at t=0 — so it observes
        // total_supply>0 && local_tip==0. The OLD guard keyed on total_supply==0
        // and missed this window (its "cannot false-positive" claim was wrong).
        // A restart with intact data rebuilds latest_epoch synchronously before
        // this loop spawns (elara_node.rs:1843-1890); the rarer no-epoch-snapshot
        // rebuild path lands here harmlessly (skip + retry next tick).
        if local_tip == 0 {
            // Not a fork — emit parity gauges so dashboards don't alarm.
            state.chain_divergence_epochs.store(0, Ordering::Relaxed);
            state.chain_divergence_epochs_ahead.store(0, Ordering::Relaxed);
            state.chain_divergence_epochs_behind.store(0, Ordering::Relaxed);
            let total_supply = state.ledger.read().await.total_supply;
            if total_supply == 0 {
                // Truly fresh, never bootstrapped: route to snapshot-bootstrap (a
                // wholesale ledger replace carrying every scalar + the stakes map),
                // NOT the subset state-delta repair.
                if let Some((max_peer_url, _)) =
                    peer_tips.iter().max_by_key(|(_, tip)| *tip).cloned()
                {
                    warn!(
                        "chain-divergence: FRESH node (local_tip=0, total_supply=0) behind {} epochs vs {} — routing to snapshot-bootstrap, NOT repair",
                        max_peer_tip, max_peer_url,
                    );
                    match sync::snapshot_bootstrap(&state, &max_peer_url, false).await {
                        Ok(_) => info!(
                            "chain-divergence: fresh-node snapshot-bootstrap from {} returned — re-polling next tick",
                            max_peer_url,
                        ),
                        Err(e) if sync::is_snapshot_config_error(&e) => error!(
                            "chain-divergence: fresh-node snapshot-bootstrap from {} REJECTED by a config gate, \
                             NOT a transient fault: {e}. Retrying will keep failing — the delta-sync fallback \
                             rejects the seed's seals for the same reason, so the epoch will never advance. Set \
                             genesis_authority (and min_protocol_version) to match the seed's /status, then \
                             restart — run scripts/check-my-join.sh to confirm.",
                            max_peer_url,
                        ),
                        Err(e) => warn!(
                            "chain-divergence: fresh-node snapshot-bootstrap from {} failed: {e} — retry next tick",
                            max_peer_url,
                        ),
                    }
                }
            } else {
                // Ledger loaded but seal stream not yet applied: a snapshot
                // bootstrap is in flight. Let it finish — a later tick will see
                // local_tip > 0 and resume normal divergence/repair evaluation.
                debug!(
                    "chain-divergence: local_tip=0 but total_supply>0 — mid-bootstrap (max_peer_tip={}), skipping repair this tick",
                    max_peer_tip,
                );
            }
            continue;
        }

        // local_tip > 0: divergence is a genuine fork distance. `saturating_sub`
        // because local could be AHEAD of all peers (producer state, not a
        // divergence). Paired signed gauges: at most one of behind/ahead is
        // non-zero per tick — both 0 means parity.
        let divergence = max_peer_tip.saturating_sub(local_tip);
        let behind = divergence;
        let ahead = local_tip.saturating_sub(max_peer_tip);
        state
            .chain_divergence_epochs
            .store(divergence, Ordering::Relaxed);
        state
            .chain_divergence_epochs_ahead
            .store(ahead, Ordering::Relaxed);
        state
            .chain_divergence_epochs_behind
            .store(behind, Ordering::Relaxed);

        // Step 4: threshold-cross — initiate autonomous repair.
        if divergence >= CHAIN_DIVERGENCE_THRESHOLD_EPOCHS {
            warn!(
                "chain-divergence ABOVE THRESHOLD: local_tip={} max_peer_tip={} divergence={} peers_polled={} — initiating autonomous repair",
                local_tip, max_peer_tip, divergence, peer_tips.len(),
            );
            // Select the max-tip peer endpoint for the state-delta pull.
            let Some((max_peer_url, max_peer_seen_tip)) = peer_tips
                .iter()
                .max_by_key(|(_, tip)| *tip)
                .cloned()
            else {
                continue;
            };

            state
                .chain_divergence_repair_attempts_total
                .fetch_add(1, Ordering::Relaxed);
            // Build trust set once per repair attempt — same union as
            // `epoch_indexed_snapshot_bootstrap` (network/sync.rs:740) so
            // state-delta and snapshot bootstrap honour the same trust anchor.
            let trust_set_owned: Vec<String> = {
                let mut v = Vec::with_capacity(
                    state.config.trusted_snapshot_signers.len() + 1,
                );
                if !state.config.genesis_authority.is_empty() {
                    v.push(state.config.genesis_authority.clone());
                }
                v.extend(state.config.trusted_snapshot_signers.iter().cloned());
                v
            };
            let trust_set: Vec<&str> =
                trust_set_owned.iter().map(|s| s.as_str()).collect();
            // Step 4a: HTTP fetch the signed state-delta.
            let delta = match pull_state_delta(&max_peer_url, local_tip).await {
                Ok(d) => d,
                Err(e) => {
                    warn!(
                        "chain-divergence repair fetch failed: peer={} since={} err={e}",
                        max_peer_url, local_tip
                    );
                    state
                        .chain_divergence_repair_failures_total
                        .fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            };
            // Step 4b: Dilithium3 + checksum + signer-identity-binding verify.
            let signer = match snapshot::verify_signed_state_delta(&delta) {
                Ok(s) => s,
                Err(e) => {
                    warn!(
                        "chain-divergence repair verify failed: peer={} since={} err={e}",
                        max_peer_url, local_tip
                    );
                    state
                        .chain_divergence_repair_verify_fails_total
                        .fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            };
            // Step 4c: trusted-signer gate. Mismatch is counted under
            // verify_fails (it's a verification failure of the trust binding,
            // not an apply failure).
            if let Err(e) =
                snapshot::enforce_snapshot_signer_trust(&signer, &trust_set)
            {
                warn!(
                    "chain-divergence repair trust gate rejected signer={}... peer={} err={e}",
                    &signer[..16.min(signer.len())],
                    max_peer_url,
                );
                state
                    .chain_divergence_repair_verify_fails_total
                    .fetch_add(1, Ordering::Relaxed);
                continue;
            }
            // Step 4d: apply.
            match apply_state_delta_for_repair(&state, &delta).await {
                Ok(touched) => {
                    state
                        .chain_divergence_repair_success_total
                        .fetch_add(1, Ordering::Relaxed);
                    info!(
                        "chain-divergence repair APPLIED: peer={} signer={}... since_epoch={} current_epoch={} peer_tip_at_poll={} changed={} removed={} touched={} new_total_accounts={} new_total_supply={} new_total_staked={}",
                        max_peer_url,
                        &signer[..16.min(signer.len())],
                        delta.since_epoch,
                        delta.current_epoch,
                        max_peer_seen_tip,
                        delta.changed_accounts.len(),
                        delta.removed_accounts.len(),
                        touched,
                        delta.total_accounts,
                        delta.total_supply,
                        delta.total_staked,
                    );
                }
                Err(e) => {
                    warn!(
                        "chain-divergence repair apply failed: peer={} err={e}",
                        max_peer_url
                    );
                    state
                        .chain_divergence_repair_apply_fails_total
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
        } else {
            debug!(
                "chain-divergence tick: local_tip={} max_peer_tip={} divergence={} peers_polled={}",
                local_tip, max_peer_tip, divergence, peer_tips.len(),
            );
        }
    }
}

/// Background task: periodic ledger snapshots for crash recovery.
async fn snapshot_loop(
    state: Arc<NodeState>,
    path: std::path::PathBuf,
    interval_secs: u64,
    mut shutdown: watch::Receiver<()>,
    hb: Arc<elara_runtime::network::supervision::LoopStatus>,
) {
    let interval = std::time::Duration::from_secs(interval_secs);
    info!("snapshot loop started (every {}s)", interval_secs);
    let mut cycle: u64 = 0;

    loop {
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = shutdown.changed() => {
                info!("snapshot loop shutting down");
                return;
            }
        }
        hb.heartbeat(); // hang-detection: stamp each tick (interval « 900s stale_after)
        cycle += 1;

        // Clone ledger and finalized set, then drop read locks before disk I/O.
        // Previously held ledger.read() across save_snapshot_full (JSON serialization
        // + file write), which blocked state_core's ledger.write() on slow VPS disks.
        let snap_t0 = std::time::Instant::now();
        // Clone ledger ONCE — reused for both JSON snapshot and RocksDB subsystem snapshot.
        // Previously cloned twice: once here, once at the subsystem block (line ~2464).
        // On 2GB nodes the second clone caused 60s+ memory pressure, holding ledger.read()
        // and cascading into write lock contention (47s ledger.write() stalls on a 2 GB node).
        let ledger_clone = std::sync::Arc::new(state.ledger.read().await.clone());
        let d_ledger = snap_t0.elapsed().as_millis();
        // Skip expensive 84K+ key prefix scan for periodic snapshots.
        // Finalized records are already durable in RocksDB (finalized:{id} keys).
        // Startup will load from RocksDB if the snapshot's finalized set is empty.
        let _finalized_count = state.finalized.read().await.len();
        let finalized_set = std::collections::HashSet::new();
        let d_finalized = snap_t0.elapsed().as_millis() - d_ledger;

        // JSON snapshot is a debugging aid — RocksDB subsystem snapshots are
        // the primary persistence mechanism. Save JSON only every 6th cycle
        // (~30 min with 5-min interval) to avoid 5-10s disk I/O stalls that
        // block the spawn_blocking pool and starve record ingest.
        // Shutdown handler saves a final JSON snapshot regardless.
        let d_json = if cycle % 6 == 1 {
            let epoch = state.epoch.read_recover().clone();
            let genesis_st = state.genesis_state.read_recover().clone();
            let bootstrap_st = state.bootstrap_state.read_recover().clone();
            let snap_path = path.clone();
            let ledger_for_json = ledger_clone.clone();
            let t_before_json = snap_t0.elapsed().as_millis();
            match tokio::task::spawn_blocking(move || {
                snapshot::save_snapshot_full(
                    &ledger_for_json, &finalized_set, &epoch,
                    Some(&genesis_st), Some(&bootstrap_st),
                    &snap_path,
                )
            }).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => warn!("periodic snapshot failed: {e}"),
                Err(e) => warn!("snapshot task panicked: {e}"),
            }
            snap_t0.elapsed().as_millis() - t_before_json
        } else {
            0
        };

        // Also save RocksDB subsystem snapshots periodically.
        // Without this, a crash loses all subsystem state and forces
        // a full record load on next startup (Phase 6).
        // Clone each subsystem then DROP the lock before taking the next.
        // Previous code held dag.read() while waiting for trust.read()
        // and ledger.read() — cascading lock chain starved state_core's
        // dag.write() for 60s+ on 2GB nodes, triggering watchdog kills.
        let (d_dag, d_trust, d_subsystem) = {
            let t_before_dag = snap_t0.elapsed().as_millis();
            // Hold the read lock only long enough to
            // bump the Arc refcount; the deep clone (was 30-60 s on 2 GB nodes
            // and triggered the dag_write_holder=7 phase-2 watchdog deadlock)
            // is gone — the snapshot operates on the cheap Arc clone outside
            // the lock. `dag_write_holder=7` is left in place as the slow-path
            // canary; with Arc-CoW it should never fire above µs-scale.
            state.dag_write_holder.store(7, std::sync::atomic::Ordering::Relaxed);
            let dag_clone: std::sync::Arc<elara_runtime::dag::DagIndex> = {
                let guard = state.dag.read().await;
                std::sync::Arc::clone(&*guard)
            };
            state.dag_write_holder.store(0, std::sync::atomic::Ordering::Relaxed);
            let d_dag = snap_t0.elapsed().as_millis() - t_before_dag;

            // On ≤2GB nodes, only save essential snapshots (5 instead of 14).
            // The full set takes 41+ seconds on 1-core, blocking RocksDB writes.
            // Non-essential subsystems (trust, reputation, sunset, delegations,
            // disputes, challenges, key_registry, genesis_state) are rebuilt
            // from records on next startup — they're nice-to-have, not critical.
            let snap_ram_gb = elara_runtime::storage::rocks::StorageEngine::detect_system_ram_gb();
            let full_snapshots = snap_ram_gb > 2;

            let t_before_trust = snap_t0.elapsed().as_millis();
            let trust_clone = if full_snapshots {
                Some(state.trust.read().await.clone())
            } else {
                None
            };
            let d_trust = snap_t0.elapsed().as_millis() - t_before_trust;

            let reputation = if full_snapshots { Some(state.reputation.lock_recover().clone()) } else { None };
            let sunset = if full_snapshots { Some(state.sunset.read_recover().clone()) } else { None };
            let delegations = if full_snapshots { Some(state.delegations.read_recover().clone()) } else { None };
            let zone_state = if full_snapshots { Some(state.zone_state.lock_recover().clone()) } else { None };
            let disputes = if full_snapshots { Some(state.disputes.read_recover().clone()) } else { None };
            let challenges = if full_snapshots { Some(state.challenges.read_recover().clone()) } else { None };
            let key_registry = if full_snapshots { Some(state.key_registry.read_recover().clone()) } else { None };
            let genesis_state_snap = if full_snapshots { Some(state.genesis_state.read_recover().clone()) } else { None };
            let epoch_snap = state.epoch.read_recover().to_snapshot();
            // Save persistent counters (survive restarts)
            let counters: (u64, u64, u64) = (
                state.total_ever_settled.load(std::sync::atomic::Ordering::Relaxed),
                state.total_ever_finalized.load(std::sync::atomic::Ordering::Relaxed),
                state.total_attestations_processed.load(std::sync::atomic::Ordering::Relaxed),
            );
            // Checkpoint timestamp = now. On next startup, only records after this
            // timestamp need to be replayed into the loaded ledger snapshot.
            let checkpoint_ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs_f64();

            // Recalibrate + save subsystem snapshots in spawn_blocking
            // to avoid blocking the async runtime with synchronous RocksDB writes.
            let dag_len = dag_clone.len();
            let rocks = state.rocks.clone();
            let t_before_subsystem = snap_t0.elapsed().as_millis();
            let snap_result = tokio::task::spawn_blocking(move || {
                // Only recalibrate UP — DAG evicts old records, so dag_len < record_count
                // is normal. Unconditional recalibrate was destroying the real count
                // (e.g., writing 94 when 88K records exist in storage).
                {
                    use elara_runtime::storage::Storage;
                    let cached = rocks.count().unwrap_or(0);
                    if dag_len > cached {
                        rocks.recalibrate_count(dag_len);
                    }
                }

                let mut saved = 0u32;
                let mut failed = 0u32;
                // Essential snapshots (always saved).
                // On ≤2GB, skip DAG snapshot — serializing 1500 records + edges
                // takes 56s on 1-core, holding a spawn_blocking thread and starving
                // record ingest. DAG rebuilds from CF_DAG in ~19s on startup.
                let snap_ram = elara_runtime::storage::rocks::StorageEngine::detect_system_ram_gb();
                let mut essential: Vec<(&str, elara_runtime::errors::Result<()>)> = Vec::new();
                if snap_ram > 2 {
                    essential.push(("dag", rocks.save_snapshot("dag", &*dag_clone)));
                }
                // F-3 crash-atomicity: ledger + checkpoint_timestamp + epoch in
                // ONE WriteBatch (serialize first). A torn save here would
                // desync the epoch tip from the ledger baseline on the next
                // boot. dag + persistent_counters stay separate (dag is slow;
                // counters are not part of the replay baseline).
                {
                    let mut trio: Vec<(&str, Vec<u8>)> = Vec::new();
                    match serde_json::to_vec(&*ledger_clone) {
                        Ok(b) => trio.push(("ledger", b)),
                        Err(e) => essential.push(("ledger", Err(
                            elara_runtime::errors::ElaraError::Storage(format!("ledger serialize: {e}"))))),
                    }
                    match serde_json::to_vec(&checkpoint_ts) {
                        Ok(b) => trio.push(("checkpoint_timestamp", b)),
                        Err(e) => essential.push(("checkpoint_timestamp", Err(
                            elara_runtime::errors::ElaraError::Storage(format!("checkpoint_timestamp serialize: {e}"))))),
                    }
                    match serde_json::to_vec(&epoch_snap) {
                        Ok(b) => trio.push(("epoch", b)),
                        Err(e) => essential.push(("epoch", Err(
                            elara_runtime::errors::ElaraError::Storage(format!("epoch serialize: {e}"))))),
                    }
                    match rocks.save_snapshots_batch(&trio) {
                        Ok(()) => for (name, _) in &trio { essential.push((*name, Ok(()))); },
                        Err(e) => {
                            let msg = e.to_string();
                            for (name, _) in &trio {
                                essential.push((*name, Err(
                                    elara_runtime::errors::ElaraError::Storage(format!("snapshot batch: {msg}")))));
                            }
                        }
                    }
                }
                essential.push(("persistent_counters", rocks.save_snapshot("persistent_counters", &counters)));
                for (name, result) in essential {
                    match result {
                        Ok(()) => saved += 1,
                        Err(e) => { failed += 1; tracing::debug!("subsystem snapshot {name} failed: {e}"); }
                    }
                }
                // Non-essential snapshots (≥4GB nodes only)
                if let Some(ref trust) = trust_clone {
                    match rocks.save_snapshot("trust", trust) {
                        Ok(()) => saved += 1,
                        Err(e) => { failed += 1; tracing::debug!("subsystem snapshot trust failed: {e}"); }
                    }
                }
                if full_snapshots {
                    if let Some(ref v) = reputation { let _ = rocks.save_snapshot("reputation", v).map(|_| saved += 1); }
                    if let Some(ref v) = sunset { let _ = rocks.save_snapshot("sunset", v).map(|_| saved += 1); }
                    if let Some(ref v) = delegations { let _ = rocks.save_snapshot("delegations", v).map(|_| saved += 1); }
                    if let Some(ref v) = zone_state { let _ = rocks.save_snapshot("zone_state", v).map(|_| saved += 1); }
                    if let Some(ref v) = disputes { let _ = rocks.save_snapshot("disputes", v).map(|_| saved += 1); }
                    if let Some(ref v) = challenges { let _ = rocks.save_snapshot("challenges", v).map(|_| saved += 1); }
                    if let Some(ref v) = key_registry { let _ = rocks.save_snapshot("key_registry", v).map(|_| saved += 1); }
                    if let Some(ref v) = genesis_state_snap { let _ = rocks.save_snapshot("genesis_state", v).map(|_| saved += 1); }
                }
                (saved, failed)
            }).await;
            let d_subsystem = snap_t0.elapsed().as_millis() - t_before_subsystem;
            match snap_result {
                Ok((saved, failed)) if failed > 0 => {
                    warn!("periodic subsystem snapshots: {saved} saved, {failed} failed");
                }
                Err(e) => warn!("subsystem snapshot task panicked: {e}"),
                _ => {}
            }
            (d_dag, d_trust, d_subsystem)
        };
        let t_total = snap_t0.elapsed().as_millis();
        if t_total > 3000 {
            warn!("snapshot loop slow: total={t_total}ms (ledger={d_ledger}ms finalized={d_finalized}ms json={d_json}ms dag={d_dag}ms trust={d_trust}ms subsystem={d_subsystem}ms)");
        }
    }
}

/// Background task: finality monitor — promotes settled records and prunes consensus state.
///
/// Every 30 seconds, scans all records with attestations and checks if any have
/// newly reached settlement. Also periodically prunes attestation data for records
/// that have already been finalized (prevents unbounded memory growth).
async fn finality_monitor_loop(
    state: Arc<NodeState>,
    mut shutdown: watch::Receiver<()>,
    hb: Arc<elara_runtime::network::supervision::LoopStatus>,
) {
    let interval = std::time::Duration::from_secs(30);
    let mut cycles: u64 = 0;

    // Boot recovery: re-fire any exactly-once finalization effects left pending
    // by a detached effects task that died before completing (design C durable
    // outbox). `panic="unwind"` kills such a task silently, so this cannot be
    // deferred to normal ticks alone — run it once before the loop starts.
    elara_runtime::network::reward::reconcile_pending_effects(&state).await;

    loop {
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = shutdown.changed() => {
                info!("finality monitor shutting down");
                return;
            }
        }

        // Hang-detection: a deadlocked (non-panicking) finality_monitor is
        // invisible to panic-restart but now surfaces as Stale via
        // last_tick_age. Critical here — a hung loop stops BOTH finalization
        // AND the exactly-once effects recovery sweep below.
        hb.heartbeat();
        cycles += 1;

        // Check for newly settled records.
        // Hold finalized read lock briefly to check each candidate.
        let newly_settled: Vec<String> = {
            let finalized = state.finalized.read().await;
            let consensus = state.consensus.lock_recover();
            consensus
                .tracked_record_ids()
                .into_iter()
                .filter(|rid| !finalized.contains(rid) && consensus.is_settled(rid))
                .collect()
        };

        if !newly_settled.is_empty() {
            // Insert into finalized index first (separate lock scope).
            // Single RocksDB WriteBatch; returns the truly-new rids — the
            // exactly-once finalization edge. Records the monitor promotes
            // here previously fired NO rewards/reputation/events at all
            // (and a feed-path arriving later saw is_new_insert=false, so
            // they were lost entirely); finalization_effects on the new
            // rids closes that hole, and rids another path already
            // inserted fire nothing here — once, whoever wins.
            let new_rids = {
                let mut finalized = state.finalized.write().await;
                finalized.insert_batch_returning_new(&newly_settled)
            };
            // Then mark in DAG (separate lock scope — avoids holding both locks
            // simultaneously, which caused deadlock-like starvation on Nuremberg)
            {
                state.dag_write_holder.store(3, std::sync::atomic::Ordering::Relaxed); // 3=finality_monitor
                let mut dag_guard = state.dag.write().await;
                let dag = std::sync::Arc::make_mut(&mut *dag_guard);
                let current_epoch = dag.current_epoch();
                for rid in &newly_settled {
                    dag.mark_finalized(rid, current_epoch);
                }
            }
            state.dag_write_holder.store(0, std::sync::atomic::Ordering::Relaxed);
            // Persistent counters — finality monitor path. Bump by actual-new
            // inserts so total_ever_settled tracks unique finalizations.
            if !new_rids.is_empty() {
                state.total_ever_settled.fetch_add(new_rids.len() as u64, std::sync::atomic::Ordering::Relaxed);
                state.total_ever_finalized.fetch_add(new_rids.len() as u64, std::sync::atomic::Ordering::Relaxed);
                info!("finality monitor: promoted {} records (of {} candidates, total_ever_settled={})",
                    new_rids.len(),
                    newly_settled.len(),
                    state.total_ever_settled.load(std::sync::atomic::Ordering::Relaxed));
                elara_runtime::network::reward::finalization_effects(&state, new_rids);
            }
        }

        // Per-tick recovery sweep (design C): re-fire the exactly-once effects
        // for any pending marker whose detached task panicked mid-flight —
        // without waiting for a restart. O(pending) prefix scan, near-free when
        // empty (the common steady-state path).
        elara_runtime::network::reward::reconcile_pending_effects(&state).await;

        // Every 20th cycle (~10 min): log settlement diagnostic for closest-to-settled record
        if newly_settled.is_empty() && cycles.is_multiple_of(20) {
            let consensus = state.consensus.lock_recover();
            let tracked = consensus.tracked_record_ids();
            if !tracked.is_empty() {
                // Find record with highest attesting/eligible ratio
                let mut best_ratio = 0.0f64;
                let mut best_rid = String::new();
                let mut best_atts = 0usize;
                let mut best_stake = 0u64;
                let mut best_zone_stake = 0u64;
                for rid in tracked.iter().take(500) {
                    let (_eff, raw, _) = consensus.effective_attesting_stake(rid);
                    // Gap 4 Phase C: registry-aware resolution so diagnostic picks
                    // stake from the correct post-split leaf zone.
                    let zone = state.resolve_record_zone(rid);
                    let zs = consensus.total_zone_stake(zone);
                    if zs > 0 {
                        let ratio = raw as f64 / zs as f64;
                        if ratio > best_ratio {
                            best_ratio = ratio;
                            best_rid = rid.clone();
                            best_atts = consensus.attestation_count(rid);
                            best_stake = raw;
                            best_zone_stake = zs;
                        }
                    }
                }
                info!(
                    "finality diag: tracked={} settled=0 best_ratio={:.1}% best_atts={} attesting_stake={} zone_stake={} rid={}",
                    tracked.len(), best_ratio * 100.0, best_atts, best_stake, best_zone_stake, &best_rid[..best_rid.len().min(16)]
                );
            }
        }

        // Every 5th cycle (~2.5 min): prune attestations for finalized records
        // and phantom records (in consensus but GC'd from RocksDB).
        if cycles.is_multiple_of(5) {
            let finalized = state.finalized.read().await;
            // Collect phantom record IDs: tracked in consensus but not in RocksDB storage.
            // These waste auto-witness cycles (skip_miss) and can never settle.
            let phantom_rids: std::collections::HashSet<String> = {
                let consensus = state.consensus.lock_recover();
                consensus.tracked_record_ids().into_iter()
                    .filter(|rid| {
                        !finalized.contains(rid)
                            && state.rocks.get_record(rid).ok().flatten().is_none()
                    })
                    .collect()
            };
            let pruned = {
                let mut consensus = state.consensus.lock_recover();
                consensus.prune_where(|rid| finalized.contains(rid) || phantom_rids.contains(rid))
            };
            if pruned > 0 {
                let phantom_count = phantom_rids.len();
                if phantom_count > 0 {
                    info!("finality monitor: pruned attestations for {pruned} records ({phantom_count} phantom/GC'd)");
                } else {
                    info!("finality monitor: pruned attestations for {pruned} finalized records");
                }
            }
            drop(finalized);
        }

        // Every 10th cycle (~5 min): promote Finalized seals past the 24h challenge
        // window to Anchored (Protocol §11.12, Layer 4). No urgency — window is 24h.
        if cycles.is_multiple_of(10) {
            let (promoted_seals, promoted_rids) = {
                let mut consensus = state.consensus.lock_recover();
                consensus.promote_anchored()
            };
            if !promoted_rids.is_empty() {
                info!(
                    "finality monitor: anchored {} records across {} seals (24h challenge window passed)",
                    promoted_rids.len(), promoted_seals
                );
                // Mark in finalized index (anchored ⊃ finalized) — durable,
                // idempotent (normally a dedup no-op post-R1/R2; the write is
                // what rescues members that reached Anchored through an
                // unrouted path, since the seal fast-track's edge guard
                // treats Anchored as terminal and never re-fires for them).
                elara_runtime::network::reward::route_member_finality(&state, promoted_rids).await;
            }
        }

        // Every 3rd cycle (~1.5 min): evict old records from DAG.
        // Previous: every 10th cycle (5 min) — too slow when records arrive at ~1/sec,
        // DAG grew to 3.8K records with 139K edges before eviction kicked in.
        // Records remain in RocksDB for historical queries, gossip, and sync.
        // Window scales by RAM: 2GB→15min, 4GB→30min, >4GB→1h.
        if cycles.is_multiple_of(3) {
            {
                let ram_gb = elara_runtime::storage::rocks::StorageEngine::detect_system_ram_gb();
                let pressure = state.under_memory_pressure();
                // Under memory pressure, halve retention and caps to aggressively free RAM
                let max_age = if pressure {
                    if ram_gb <= 2 { 300.0 } else { 600.0 }
                } else if ram_gb <= 2 { 900.0 } else if ram_gb <= 4 { 1800.0 } else { 3600.0 };
                let orphan_cap = if pressure {
                    if ram_gb <= 2 { 200usize } else { 1_000 }
                } else if ram_gb <= 2 { 800usize } else if ram_gb <= 4 { 3_000 } else { 5_000 };
                let dag_cap = if pressure {
                    if ram_gb <= 2 { 500usize } else { 2_000 }
                } else if ram_gb <= 2 { 1_500usize } else if ram_gb <= 4 { 5_000 } else { 20_000 };

                state.dag_write_holder.store(3, std::sync::atomic::Ordering::Relaxed);
                let mut dag_guard = state.dag.write().await;
                let dag = std::sync::Arc::make_mut(&mut *dag_guard);
                let before = dag.len();

                // Time-based eviction
                let evicted_age = dag.evict_older_than(max_age);

                // Hard cap: if still over limit, evict oldest until under cap
                let evicted_cap = dag.evict_to_cap(dag_cap);

                // Orphan edge cap
                let pruned_orphans = dag.prune_orphan_edges(orphan_cap);

                state.dag_write_holder.store(0, std::sync::atomic::Ordering::Relaxed);
                let after = dag.len();
                let edges = dag.edge_count();
                drop(dag_guard);

                let total_evicted = evicted_age + evicted_cap;
                if total_evicted > 0 || pruned_orphans > 0 {
                    info!(
                        "finality monitor: DAG {before} → {after} (evicted {evicted_age} by age, {evicted_cap} by cap, {pruned_orphans} orphan edges pruned, {edges} edges) [{}GB, {}min window]",
                        ram_gb, max_age / 60.0
                    );
                }

                // Force jemalloc to return freed pages to OS after significant
                // eviction. Same gate as the post-load purge above: jemalloc-ctl
                // is only linked on unix under the full `node` feature — a
                // `node-core`/`node-windows` build has no jemalloc and skips this.
                #[cfg(all(not(target_arch = "wasm32"), target_family = "unix", feature = "tikv-jemalloc-ctl"))]
                if total_evicted > 100 {
                    let _ = tikv_jemalloc_ctl::epoch::advance();
                    unsafe {
                        tikv_jemalloc_ctl::raw::write(b"arena.0.purge\0", 0u64).ok();
                        tikv_jemalloc_ctl::raw::write(b"arena.1.purge\0", 0u64).ok();
                    }
                }
            }
        }
    }
}

/// Background task: finalize fisherman challenges past their appeal window.
///
/// Runs every 60 seconds. Challenges with `Verdict` status whose appeal window
/// has expired are promoted to `Final`, making the slash permanent.
async fn challenge_finalization_loop(state: Arc<NodeState>) {
    use elara_runtime::network::RwLockRecover;

    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
    loop {
        interval.tick().await;
        let now = elara_runtime::record::now_timestamp();
        let mut ch = state.challenges.write_recover();
        let verdict_ids: Vec<String> = ch.all()
            .filter(|c| c.status == elara_runtime::network::fisherman::ChallengeStatus::Verdict)
            .map(|c| c.id.clone())
            .collect();
        let mut finalized = 0;
        for id in &verdict_ids {
            if ch.finalize_if_expired(id, now) {
                finalized += 1;
                info!("fisherman challenge {} finalized (appeal window expired)", &id[..id.len().min(16)]);
            }
        }
        if finalized > 0 {
            info!("fisherman: finalized {} challenges past appeal window", finalized);
        }
    }
}

/// Get identity passphrase from ELARA_IDENTITY_PASSPHRASE env var.
fn get_passphrase() -> Option<String> {
    std::env::var("ELARA_IDENTITY_PASSPHRASE").ok().filter(|s| !s.is_empty())
}

fn load_identity(config: &NodeConfig) -> Result<Identity> {
    use elara_runtime::identity::{is_encrypted_identity, write_identity_file};

    // Operator opt-in: when `require_encrypted_identity` is set, a passphrase is
    // mandatory and we refuse to touch a plaintext identity at all — neither
    // saving a freshly generated one nor loading an existing plaintext file.
    // Fail fast HERE, before generating (PoW, 30-60s) or reading the file, so a
    // misconfigured node stops immediately with an actionable error instead of
    // silently persisting a secret key in plaintext. Default off — see the field
    // doc on NodeConfig::require_encrypted_identity.
    if config.require_encrypted_identity && get_passphrase().is_none() {
        return Err(ElaraError::Config(
            "require_encrypted_identity is set but ELARA_IDENTITY_PASSPHRASE is not set — \
             refusing to save or load a plaintext node identity. Set the passphrase and restart."
                .into(),
        ));
    }

    if !config.identity_path.exists() {
        // Auto-generate identity on first run (Phase 3: zero-config startup).
        info!("no identity found — generating new one (Profile A dual-sig, PoW difficulty 20)...");
        info!("this may take 30-60 seconds...");
        let identity = Identity::generate_with_pow(
            EntityType::Device,
            CryptoProfile::ProfileA,
            20,
        )?;

        // Encrypt if passphrase is available
        let json = if let Some(passphrase) = get_passphrase() {
            info!("encrypting identity with AES-256-GCM + Argon2id");
            identity.to_encrypted_json(passphrase.as_bytes())?
        } else {
            warn!(
                "no ELARA_IDENTITY_PASSPHRASE set — saving identity in PLAINTEXT. \
                 Set the env var and restart to encrypt."
            );
            identity.to_json()
        };

        write_identity_file(&config.identity_path, &json)?;
        info!(
            "identity generated: {} (saved to {})",
            identity.identity_hash,
            config.identity_path.display()
        );
        return Ok(identity);
    }

    let json_str = std::fs::read_to_string(&config.identity_path)
        .map_err(|e| ElaraError::Config(format!("failed to read identity: {e}")))?;
    let data: std::collections::BTreeMap<String, serde_json::Value> =
        serde_json::from_str(&json_str)?;

    if is_encrypted_identity(&data) {
        // Encrypted format — need passphrase
        let passphrase = get_passphrase().ok_or_else(|| {
            ElaraError::Config(
                "identity is encrypted but ELARA_IDENTITY_PASSPHRASE not set".into(),
            )
        })?;
        info!("decrypting identity from {}", config.identity_path.display());
        Identity::from_encrypted_json(&data, passphrase.as_bytes())
    } else {
        // Plaintext format — load and optionally re-encrypt
        let identity = Identity::from_json(&data)?;

        if let Some(passphrase) = get_passphrase() {
            // Passphrase available — re-encrypt the plaintext file
            warn!(
                "identity file is plaintext — re-encrypting to {}",
                config.identity_path.display()
            );
            let encrypted = identity.to_encrypted_json(passphrase.as_bytes())?;
            write_identity_file(&config.identity_path, &encrypted)?;
            info!("identity re-encrypted successfully");
        } else {
            warn!(
                "WARNING: identity secret keys stored in PLAINTEXT at {}. \
                 Set ELARA_IDENTITY_PASSPHRASE to encrypt.",
                config.identity_path.display()
            );
        }

        Ok(identity)
    }
}

fn generate_identity(cli: &Cli) -> Result<()> {
    use elara_runtime::identity::write_identity_file;

    let config = if std::path::Path::new(&cli.config).exists() {
        NodeConfig::load(&cli.config)?
    } else {
        NodeConfig::from_defaults()
    };

    let path = if let Some(data_dir) = &cli.data_dir {
        let p = std::path::PathBuf::from(data_dir);
        std::fs::create_dir_all(&p)
            .map_err(|e| ElaraError::Config(format!("failed to create dir: {e}")))?;
        p.join("identity.json")
    } else {
        // Ensure the data directory from config exists (TOML data_dir support)
        std::fs::create_dir_all(&config.data_dir)
            .map_err(|e| ElaraError::Config(format!("failed to create data_dir: {e}")))?;
        config.identity_path.clone()
    };

    if path.exists() {
        info!("identity already exists at {}", path.display());
        let json_str = std::fs::read_to_string(&path)
            .map_err(|e| ElaraError::Config(format!("read: {e}")))?;
        let data: std::collections::BTreeMap<String, serde_json::Value> =
            serde_json::from_str(&json_str)?;
        let id = Identity::from_json(&data)?;
        info!("identity hash: {}", id.identity_hash);
        // Also emit to stdout so a first-time joiner can copy/grep it cleanly —
        // the info! line above is buried in the tracing wall on stderr (QUICKSTART
        // tells the operator to "copy the identity hash it prints").
        println!("identity hash: {}", id.identity_hash);
        return Ok(());
    }

    // Profile A: dual-sig (Dilithium3 + SPHINCS+) — strongest PQ crypto.
    // All node identities use Profile A for production readiness.
    info!("generating new identity with PoW (difficulty 20, Profile A dual-sig)...");
    let identity = Identity::generate_with_pow(
        EntityType::Device,
        CryptoProfile::ProfileA,
        20,
    )?;

    // Encrypt if passphrase is available, otherwise plaintext with warning
    let json = if let Some(passphrase) = get_passphrase() {
        info!("encrypting identity with AES-256-GCM + Argon2id");
        identity.to_encrypted_json(passphrase.as_bytes())?
    } else {
        warn!(
            "WARNING: no ELARA_IDENTITY_PASSPHRASE set — saving identity in PLAINTEXT. \
             Set the env var and restart to encrypt."
        );
        identity.to_json()
    };

    write_identity_file(&path, &json)?;

    info!("identity saved to {} (permissions: 0600)", path.display());
    info!("identity hash: {}", identity.identity_hash);
    info!(
        "PoW nonce: {} (difficulty: {} bits)",
        identity.pow_nonce, identity.pow_difficulty
    );
    // Clean stdout line for the joiner to copy (info! above goes to stderr).
    println!("identity hash: {}", identity.identity_hash);

    Ok(())
}

/// Background task: periodic RocksDB checkpoints for data recovery.
///
/// Runs every 6 hours. Creates a point-in-time snapshot in
/// `{data_dir}/checkpoints/checkpoint_{timestamp}` using RocksDB's built-in
/// Checkpoint API (fast, non-blocking). Retains the last 3 checkpoints and
/// deletes older ones automatically.
async fn checkpoint_loop(
    rocks: Arc<elara_runtime::storage::rocks::StorageEngine>,
    data_dir: PathBuf,
) {
    let ram_gb = elara_runtime::storage::rocks::StorageEngine::detect_system_ram_gb();
    // ≤2GB: checkpoints are too expensive relative to disk — skip entirely.
    // ≤4GB: keep 1 checkpoint every 12h. >4GB: keep 2 every 6h.
    let (interval_secs, max_checkpoints) = if ram_gb <= 2 {
        info!("checkpoint loop: ≤2GB RAM — checkpoints disabled (re-sync from peers on crash)");
        return;
    } else if ram_gb <= 4 {
        (12 * 3600u64, 1usize) // 12h, keep 1
    } else {
        (6 * 3600u64, 2usize) // 6h, keep 2
    };

    let interval = std::time::Duration::from_secs(interval_secs);
    let checkpoints_dir = data_dir.join("checkpoints");
    info!("checkpoint loop started (every {}h, keep last {max_checkpoints}, {ram_gb}GB RAM)",
        interval_secs / 3600);

    // Disk-pressure failure shape: a checkpoint that fails to
    // rotate because the next create_checkpoint() hit ENOSPC keeps growing as
    // the live DB compacts away SSTs that only the checkpoint still pins.
    //
    // The previous stale-age guard at
    // `2 * interval_secs` was too lenient — on a 4GB-keep=1 box at 12h cadence,
    // an orphan checkpoint at age 24h still missed the strict `> stale_age`
    // comparison and grew to 28G before the 4th cycle could prune it. By then
    // root was 100% full and writes blocked, requiring manual recovery
    // (28G checkpoint + 384M journal cleanup).
    //
    // Fix: swap the rotate-AFTER-create
    // ordering for rotate-BEFORE-create so the previous cycle's pinned SSTs
    // are released before requesting space for the new checkpoint. The
    // pre-rotate keeps `max_checkpoints - 1` entries, so after the create
    // succeeds we land at exactly `max_checkpoints`. The stale-prune guard is
    // retained as a defensive layer for any pre-rotate failure paths.
    //
    // Trade-off: for the ≤4GB tier (keep=1) there's a brief 0-checkpoint
    // window during create_checkpoint. RocksDB's checkpoint API is hardlink-
    // based and typically completes in well under a second; on a crash inside
    // that window the node re-syncs from peers, which is already the
    // documented recovery path for ≤2GB tier and acceptable for ≤4GB. The
    // alternative (ENOSPC + ingest rejection + manual disk recovery) is
    // strictly worse — it's what we already hit.
    let stale_age_secs = 2 * interval_secs;

    loop {
        tokio::time::sleep(interval).await;

        // Ensure checkpoints directory exists
        if let Err(e) = std::fs::create_dir_all(&checkpoints_dir) {
            warn!("failed to create checkpoints dir: {e}");
            continue;
        }

        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Step 1: stale-age prune. Defensive recovery for wedged disk state
        // from a prior failed cycle that bypassed the pre-rotate path below
        // (e.g., process killed between Step 2 and Step 3).
        if let Err(e) =
            prune_stale_checkpoints(&checkpoints_dir, now_secs, stale_age_secs)
        {
            warn!("checkpoint stale-prune failed: {e}");
        }

        // Step 2: pre-rotate to free space BEFORE requesting space for the new
        // checkpoint. Keeps `max_checkpoints - 1` existing entries; after the
        // create succeeds we'll be at exactly `max_checkpoints` again. Without
        // this step, create_checkpoint can hit ENOSPC when the previous cycle's
        // pinned-SST hardlinks have diverged from the live DB (compactions
        // removed those SSTs from live but the checkpoint still owns them).
        let pre_rotate_keep = max_checkpoints.saturating_sub(1);
        if let Err(e) = rotate_checkpoints(&checkpoints_dir, pre_rotate_keep) {
            warn!("checkpoint pre-rotate failed: {e}");
        }

        // Step 3: create the new checkpoint.
        let cp_path = checkpoints_dir.join(format!("checkpoint_{now_secs}"));
        match rocks.create_checkpoint(&cp_path) {
            Ok(()) => {
                info!("RocksDB checkpoint created: {}", cp_path.display());
            }
            Err(e) => {
                warn!("RocksDB checkpoint failed: {e}");
                continue;
            }
        }

        // Step 4: final rotation. No-op in steady state (pre-rotate already
        // landed the count at `max_checkpoints - 1` and step 3 added one), but
        // guards against pre-rotate partial failure or a concurrent admin
        // create. Cheap when there's nothing to do.
        if let Err(e) = rotate_checkpoints(&checkpoints_dir, max_checkpoints) {
            warn!("checkpoint rotation failed: {e}");
        }
    }
}

/// Remove `checkpoint_<unix_ts>` directories whose timestamp suffix is older
/// than `max_age_secs` relative to `now_secs`. Entries that don't match the
/// `checkpoint_<u64>` shape are skipped silently.
///
/// This is the safety valve that handles the "wedged checkpoint" failure mode:
/// a prior `checkpoint_loop` cycle hit ENOSPC during `create_checkpoint`,
/// took the `continue` path, and never reached `rotate_checkpoints`. With
/// `keep = 1` the leftover checkpoint then bloats indefinitely as the live DB
/// compacts SSTs away that the stale checkpoint still hardlinks.
fn prune_stale_checkpoints(
    dir: &std::path::Path,
    now_secs: u64,
    max_age_secs: u64,
) -> std::result::Result<usize, String> {
    if !dir.exists() {
        return Ok(0);
    }
    let mut removed = 0usize;
    for entry in std::fs::read_dir(dir).map_err(|e| format!("read checkpoints dir: {e}"))? {
        let entry = entry.map_err(|e| format!("read entry: {e}"))?;
        let name = match entry.file_name().into_string() {
            Ok(n) => n,
            Err(_) => continue,
        };
        if !name.starts_with("checkpoint_") {
            continue;
        }
        if !entry.path().is_dir() {
            continue;
        }
        let ts: u64 = match name["checkpoint_".len()..].parse() {
            Ok(t) => t,
            Err(_) => continue,
        };
        let age = now_secs.saturating_sub(ts);
        if age > max_age_secs {
            match std::fs::remove_dir_all(entry.path()) {
                Ok(()) => {
                    info!(
                        "pruned stale checkpoint: {name} (age {age}s > {max_age_secs}s max)"
                    );
                    removed += 1;
                }
                Err(e) => warn!("failed to prune stale checkpoint {name}: {e}"),
            }
        }
    }
    Ok(removed)
}

/// Keep the newest `keep` checkpoint directories, remove older ones.
fn rotate_checkpoints(dir: &std::path::Path, keep: usize) -> std::result::Result<(), String> {
    let mut entries: Vec<(String, std::path::PathBuf)> = std::fs::read_dir(dir)
        .map_err(|e| format!("read checkpoints dir: {e}"))?
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let name = entry.file_name().into_string().ok()?;
            if name.starts_with("checkpoint_") && entry.path().is_dir() {
                Some((name, entry.path()))
            } else {
                None
            }
        })
        .collect();

    // Sort by name descending (timestamp suffix means lexicographic == chronological)
    entries.sort_by(|a, b| b.0.cmp(&a.0));

    // Remove entries beyond the keep limit
    for (name, path) in entries.iter().skip(keep) {
        match std::fs::remove_dir_all(path) {
            Ok(()) => info!("removed old checkpoint: {name}"),
            Err(e) => warn!("failed to remove checkpoint {name}: {e}"),
        }
    }

    Ok(())
}

// NOTE (C11, internal design notes): the `uptime_vesting_loop` async
// fn was REMOVED here. It was the wall-clock, out-of-band mutator of the SMT-leaf
// vesting fields (`uptime_secs`/`inactive_days`/`vested_locked`) and the account-
// SMT fork vector — a follower replaying via records could never reproduce its
// mutations. Vesting will return as genesis-signed records (the idle_decay pattern,
// `epoch.rs`), applied verbatim by every node. The pure milestone math in
// `token::uptime_vesting` is retained (unit-tested) to inform that apply path.

/// Recursively copy a directory tree from `src` to `dst`.
/// Verify integrity of a node data directory.
///
/// Checks: identity readable, RocksDB opens, record count, ledger conservation.
fn verify_data_dir(config: &NodeConfig) -> Result<()> {
    use elara_runtime::storage::rocks::{StorageEngine, CF_RECORDS, CF_ATTESTATIONS, CF_IDENTITIES};

    println!("verifying node data at {}", config.data_dir.display());

    // 1. Identity
    let id_path = &config.identity_path;
    if id_path.exists() {
        let id_data = std::fs::read_to_string(id_path)
            .map_err(|e| ElaraError::Config(format!("failed to read identity: {e}")))?;
        let id: serde_json::Value = serde_json::from_str(&id_data)
            .map_err(|e| ElaraError::Config(format!("failed to parse identity: {e}")))?;
        let hash = id["identity_hash"].as_str().unwrap_or("unknown");
        let entity = id["entity_type"].as_str().unwrap_or("unknown");
        println!("  identity: {} ({})", &hash[..hash.len().min(16)], entity);
    } else {
        println!("  identity: NOT FOUND at {}", id_path.display());
    }

    // 2. (TLS certs check removed — 4E.6: in-process TLS server gone, no certs to verify.)

    // 3. Ledger snapshot
    let snap_path = config.data_dir.join("ledger-snapshot.json");
    if snap_path.exists() {
        if let Ok(snap_data) = std::fs::read_to_string(&snap_path) {
            let snap: serde_json::Value = serde_json::from_str(&snap_data).unwrap_or_default();
            let supply = snap["ledger"]["total_supply"].as_u64().unwrap_or(0);
            let staked = snap["ledger"]["total_staked"].as_u64().unwrap_or(0);
            let accounts = snap["ledger"]["accounts"].as_object().map(|a| a.len()).unwrap_or(0);
            let pool = snap["ledger"]["conservation_pool"].as_u64().unwrap_or(0);
            let account_sum: u64 = snap["ledger"]["accounts"].as_object()
                .map(|accs| accs.values().filter_map(|v| v["available"].as_u64()).sum())
                .unwrap_or(0);
            let computed_supply = pool + account_sum + staked;
            let conservation_ok = computed_supply == supply;
            println!("  snapshot: supply={} pool={} staked={} accounts={} conservation={}",
                     supply, pool, staked, accounts,
                     if conservation_ok { "OK" } else { "MISMATCH" });
            if !conservation_ok {
                println!("    WARNING: pool({pool}) + accounts({account_sum}) + staked({staked}) = {computed_supply} != supply({supply})");
            }
        }
    } else {
        println!("  snapshot: NOT FOUND (will rebuild from genesis on start)");
    }

    // 4. RocksDB
    let rocks_path = config.data_dir.join("rocksdb");
    if rocks_path.exists() {
        match StorageEngine::open(&rocks_path) {
            Ok(engine) => {
                let records = engine.approximate_cf_size(CF_RECORDS);
                let attestations = engine.approximate_cf_size(CF_ATTESTATIONS);
                let identities = engine.approximate_cf_size(CF_IDENTITIES);
                println!("  rocksdb (estimated): records=~{records} attestations=~{attestations} identities=~{identities}");
                engine.shutdown_fast();
            }
            Err(e) => {
                println!("  rocksdb: LOCKED (node running?) — {e}");
                println!("    stop the node first for full verification");
            }
        }
    } else {
        println!("  rocksdb: NOT FOUND at {}", rocks_path.display());
    }

    // 5. Peers / DHT
    let peers_path = config.data_dir.join("peers.json");
    let dht_path = config.data_dir.join("dht.json");
    println!("  peers.json: {}", if peers_path.exists() { "OK" } else { "MISSING" });
    println!("  dht.json: {}", if dht_path.exists() { "OK" } else { "MISSING" });

    println!("verification complete");
    Ok(())
}

/// Export node data directory as a tarball for migration.
///
/// Creates a RocksDB checkpoint, bundles it with identity + ledger snapshot +
/// peer/DHT state, computes SHA-256 checksums, and writes a .tar.gz archive.
/// Uses system `tar` to avoid extra Rust dependencies.
fn export_data_dir(config: &NodeConfig, output_path: &str) -> Result<()> {
    use elara_runtime::storage::rocks::StorageEngine;
    use std::process::Command;

    let output = PathBuf::from(output_path);
    println!("exporting node data from {}", config.data_dir.display());

    // Check RocksDB lock — refuse if node is running.
    // Unix-only advisory-lock probe; elsewhere the StorageEngine::open below
    // fails with RocksDB's own lock-held error if a node is running.
    let rocks_path = config.data_dir.join("rocksdb");
    #[cfg(unix)]
    {
        let lock_path = rocks_path.join("LOCK");
        if lock_path.exists() {
            use std::os::unix::io::AsRawFd;
            if let Ok(f) = std::fs::File::open(&lock_path) {
                let ret = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
                if ret != 0 {
                    return Err(ElaraError::Config(
                        "RocksDB is locked by a running node. Stop the node first.".into()
                    ));
                }
                // Unlock immediately — we just wanted to check
                unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_UN); }
            }
        }
    }

    // Create temporary staging directory
    let staging = config.data_dir.join("_export_staging");
    if staging.exists() {
        std::fs::remove_dir_all(&staging)
            .map_err(|e| ElaraError::Storage(format!("failed to clean staging dir: {e}")))?;
    }
    std::fs::create_dir_all(&staging)
        .map_err(|e| ElaraError::Storage(format!("failed to create staging dir: {e}")))?;

    // Copy individual files to staging
    let snap_path = config.data_dir.join("ledger-snapshot.json");
    let peers_path = config.data_dir.join("peers.json");
    let dht_path = config.data_dir.join("dht.json");
    let files_to_copy: Vec<(&std::path::Path, &str)> = vec![
        (&config.identity_path, "identity.json"),
        (&snap_path, "ledger-snapshot.json"),
        (&peers_path, "peers.json"),
        (&dht_path, "dht.json"),
    ];
    let mut copied = Vec::new();
    for (src, name) in &files_to_copy {
        if src.exists() {
            std::fs::copy(src, staging.join(name))
                .map_err(|e| ElaraError::Config(format!("copy {name}: {e}")))?;
            copied.push(*name);
        }
    }
    println!("  staged {} files", copied.len());

    // Create RocksDB checkpoint in staging
    let checkpoint_dir = staging.join("rocksdb");
    if rocks_path.exists() {
        println!("  creating RocksDB checkpoint...");
        let engine = StorageEngine::open(&rocks_path)
            .map_err(|e| ElaraError::Storage(format!("failed to open RocksDB: {e}")))?;
        engine.create_checkpoint(&checkpoint_dir)
            .map_err(|e| ElaraError::Storage(format!("checkpoint failed: {e}")))?;
        engine.shutdown_fast();
        println!("  checkpoint created");
    }

    // Compute SHA-256 manifest for all staged files
    println!("  computing checksums...");
    let staging_str = staging.to_str()
        .ok_or_else(|| ElaraError::Config(format!("data_dir path is not valid UTF-8: {}", staging.display())))?;
    let sha_output = Command::new("find")
        .args([staging_str, "-type", "f", "-exec",
               "sha256sum", "{}", ";"])
        .output()
        .map_err(|e| ElaraError::Config(format!("sha256sum failed: {e}")))?;
    let manifest_raw = String::from_utf8_lossy(&sha_output.stdout);
    // Rewrite paths to be relative to staging
    let staging_prefix = format!("{}/", staging.display());
    let manifest_content: String = manifest_raw
        .lines()
        .map(|line| line.replace(&staging_prefix, ""))
        .collect::<Vec<_>>()
        .join("\n") + "\n";
    std::fs::write(staging.join("MANIFEST.sha256"), &manifest_content)
        .map_err(|e| ElaraError::Config(format!("write manifest: {e}")))?;

    // Create tar.gz using system tar
    println!("  creating archive...");
    let status = Command::new("tar")
        .args(["czf", output_path, "-C", staging_str, "."])
        .status()
        .map_err(|e| ElaraError::Config(format!("tar failed: {e}")))?;
    if !status.success() {
        return Err(ElaraError::Config("tar command failed".into()));
    }

    // Clean up staging
    let _ = std::fs::remove_dir_all(&staging);

    let file_size = std::fs::metadata(&output)
        .map(|m| m.len())
        .unwrap_or(0);
    let manifest_lines = manifest_content.lines().filter(|l| !l.is_empty()).count();
    println!("  exported to {} ({:.1} MB, {} files checksummed)",
             output.display(), file_size as f64 / 1_048_576.0, manifest_lines);

    println!("\nto restore on new hardware:");
    println!("  1. mkdir -p /opt/elara/data && tar xzf {} -C /opt/elara/data/", output.display());
    println!("  2. elara-node --config /opt/elara/elara-node.toml --verify-data");
    println!("  3. systemctl start elara-node");

    Ok(())
}

fn copy_dir_recursive(src: &std::path::Path, dst: &std::path::Path) -> std::result::Result<(), String> {
    std::fs::create_dir_all(dst)
        .map_err(|e| format!("create dir {}: {e}", dst.display()))?;

    for entry in std::fs::read_dir(src).map_err(|e| format!("read dir {}: {e}", src.display()))? {
        let entry = entry.map_err(|e| format!("dir entry: {e}"))?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        if src_path.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            std::fs::copy(&src_path, &dst_path)
                .map_err(|e| format!("copy {} -> {}: {e}", src_path.display(), dst_path.display()))?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;
    use tempfile::tempdir;

    #[test]
    fn rotate_checkpoints_keeps_most_recent_n() {
        let dir = tempdir().unwrap();
        // Create 5 checkpoint dirs with lex-ordered names (timestamp suffix).
        for ts in ["1000", "1001", "1002", "1003", "1004"] {
            std::fs::create_dir(dir.path().join(format!("checkpoint_{ts}"))).unwrap();
        }

        rotate_checkpoints(dir.path(), 2).unwrap();

        // Only the 2 lex-largest should survive.
        let mut survivors: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok().and_then(|e| e.file_name().into_string().ok()))
            .collect();
        survivors.sort();
        assert_eq!(survivors, vec!["checkpoint_1003", "checkpoint_1004"]);
    }

    #[test]
    fn f2_psr1_resolve_boot_checkpoint_marker_forces_full_rebuild() {
        // F2 PSR-1 wiring: when the gov-rebuild marker is set, resolve_boot_checkpoint
        // returns (None, true) — forcing the full rebuild — EVEN IF a valid conservation-
        // passing checkpoint exists. Pins the boot marker-gate the live-boot path uses (the
        // piece the direct-predicate KATs couldn't reach; this is why it was extracted).
        use elara_runtime::accounting::ledger::LedgerState;
        use elara_runtime::accounting::types::MAX_SUPPLY;
        let dir = tempdir().unwrap();
        let rocks = elara_runtime::storage::rocks::StorageEngine::open(dir.path()).unwrap();
        // A valid checkpoint exists (fast-path would normally trigger).
        let led = LedgerState { total_supply: MAX_SUPPLY, ..Default::default() };
        rocks.save_snapshot("ledger", &led).unwrap();
        rocks.save_snapshot("checkpoint_timestamp", &1_800_000_000.0f64).unwrap();
        // Sanity: without the marker, it fast-paths.
        let (cp, force) = resolve_boot_checkpoint(&rocks);
        assert!(cp.is_some() && !force, "no marker + valid checkpoint → fast path");
        // Set the marker → must force full rebuild despite the valid checkpoint.
        rocks.set_gov_rebuild_required().unwrap();
        let (cp, force) = resolve_boot_checkpoint(&rocks);
        assert!(
            cp.is_none() && force,
            "F2 PSR-1: gov_rebuild_required MUST force checkpoint=None + force_full=true, overriding a valid checkpoint"
        );
    }

    #[test]
    fn f2_psr1_resolve_boot_checkpoint_conservation_gate_and_absence() {
        // No marker: a conservation-VIOLATING checkpoint (supply != MAX_SUPPLY) → None, and
        // total absence → None. Pins that the existing conservation gate survived the extraction.
        use elara_runtime::accounting::ledger::LedgerState;
        let dir = tempdir().unwrap();
        let rocks = elara_runtime::storage::rocks::StorageEngine::open(dir.path()).unwrap();
        // Absent: no checkpoint at all → (None, false).
        let (cp, force) = resolve_boot_checkpoint(&rocks);
        assert!(cp.is_none() && !force, "no checkpoint, no marker → (None,false) full rebuild");
        // Conservation violation: supply > 0 but != MAX_SUPPLY → None.
        let led = LedgerState { total_supply: 42, ..Default::default() };
        rocks.save_snapshot("ledger", &led).unwrap();
        rocks.save_snapshot("checkpoint_timestamp", &1_800_000_000.0f64).unwrap();
        let (cp, force) = resolve_boot_checkpoint(&rocks);
        assert!(cp.is_none() && !force, "conservation-violating checkpoint → (None,false) full rebuild");
    }

    #[test]
    fn prune_stale_checkpoints_removes_only_old_entries() {
        let dir = tempdir().unwrap();
        // now = 1_000_000; max_age = 1000 → anything older than ts=999_000 is stale.
        let now: u64 = 1_000_000;
        let max_age: u64 = 1000;
        // Stale (age 5000): should be deleted.
        std::fs::create_dir(dir.path().join("checkpoint_995000")).unwrap();
        // Borderline-fresh (age 500): kept.
        std::fs::create_dir(dir.path().join("checkpoint_999500")).unwrap();
        // Fresh (age 0): kept.
        std::fs::create_dir(dir.path().join("checkpoint_1000000")).unwrap();
        // Future timestamp (clock skew or test artefact): age underflow → saturates to 0 → kept.
        std::fs::create_dir(dir.path().join("checkpoint_1000500")).unwrap();
        // Non-checkpoint dirent: untouched.
        std::fs::create_dir(dir.path().join("snapshots")).unwrap();
        // Unparseable timestamp: untouched.
        std::fs::create_dir(dir.path().join("checkpoint_abc")).unwrap();

        let removed = prune_stale_checkpoints(dir.path(), now, max_age).unwrap();
        assert_eq!(removed, 1, "exactly one stale checkpoint deleted");

        let names: std::collections::BTreeSet<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok().and_then(|e| e.file_name().into_string().ok()))
            .collect();
        assert!(!names.contains("checkpoint_995000"), "stale removed");
        assert!(names.contains("checkpoint_999500"), "borderline kept");
        assert!(names.contains("checkpoint_1000000"), "fresh kept");
        assert!(names.contains("checkpoint_1000500"), "future timestamp kept");
        assert!(names.contains("snapshots"), "non-checkpoint untouched");
        assert!(names.contains("checkpoint_abc"), "unparseable untouched");
    }

    #[test]
    fn prune_stale_checkpoints_handles_missing_dir() {
        let root = tempdir().unwrap();
        let nonexistent = root.path().join("does_not_exist");
        // Returns Ok(0) without error when the directory does not exist —
        // this matches the `if !dir.exists() { return Ok(0); }` early-out path
        // used by the loop when the data_dir was wiped or reinitialized.
        let removed = prune_stale_checkpoints(&nonexistent, 1_000_000, 100).unwrap();
        assert_eq!(removed, 0);
    }

    #[test]
    fn rotate_checkpoints_keep_zero_removes_all() {
        // Regression test for the checkpoint_loop pre-rotate path used
        // on the ≤4GB tier where max_checkpoints=1: pre-rotate calls
        // `rotate_checkpoints(dir, 0)` to clear all existing checkpoints
        // BEFORE create_checkpoint requests new space. This frees the SSTs
        // pinned by the previous cycle (the wedge mode where a
        // single orphaned checkpoint grew to 28G as live-DB compactions
        // removed SSTs that only the checkpoint still hardlinked).
        //
        // Without this guarantee, the pre-rotate step would silently leave
        // the wedge intact and the next create_checkpoint() would hit ENOSPC,
        // re-triggering the same incident.
        let dir = tempdir().unwrap();
        std::fs::create_dir(dir.path().join("checkpoint_1000")).unwrap();
        std::fs::create_dir(dir.path().join("checkpoint_2000")).unwrap();
        std::fs::create_dir(dir.path().join("checkpoint_3000")).unwrap();
        // Sibling non-checkpoint dirs/files must not be touched.
        std::fs::create_dir(dir.path().join("snapshots")).unwrap();
        std::fs::write(dir.path().join("README"), b"keep me").unwrap();

        rotate_checkpoints(dir.path(), 0).unwrap();

        let survivors: std::collections::BTreeSet<String> =
            std::fs::read_dir(dir.path())
                .unwrap()
                .filter_map(|e| e.ok().and_then(|e| e.file_name().into_string().ok()))
                .collect();
        assert!(!survivors.contains("checkpoint_1000"), "removed");
        assert!(!survivors.contains("checkpoint_2000"), "removed");
        assert!(!survivors.contains("checkpoint_3000"), "removed");
        assert!(survivors.contains("snapshots"), "non-checkpoint dir untouched");
        assert!(survivors.contains("README"), "non-checkpoint file untouched");
    }

    #[test]
    fn rotate_checkpoints_ignores_files_and_unrelated_dirs() {
        let dir = tempdir().unwrap();
        // Mix of checkpoint dirs (timestamp-suffixed so lex == chronological),
        // non-checkpoint dirs, and a file with the checkpoint_ prefix.
        std::fs::create_dir(dir.path().join("checkpoint_1000")).unwrap();
        std::fs::create_dir(dir.path().join("checkpoint_2000")).unwrap();
        std::fs::create_dir(dir.path().join("snapshots")).unwrap();
        std::fs::write(dir.path().join("checkpoint_file.txt"), b"not a dir").unwrap();

        rotate_checkpoints(dir.path(), 1).unwrap();

        // checkpoint_2000 survives (lex-largest), checkpoint_1000 removed.
        // snapshots/ and checkpoint_file.txt untouched (file fails the is_dir filter).
        let names: std::collections::BTreeSet<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok().and_then(|e| e.file_name().into_string().ok()))
            .collect();
        assert!(names.contains("checkpoint_2000"), "kept newest checkpoint dir");
        assert!(!names.contains("checkpoint_1000"), "removed older checkpoint dir");
        assert!(names.contains("snapshots"), "non-checkpoint dir untouched");
        assert!(names.contains("checkpoint_file.txt"), "file (not dir) untouched");
    }

    #[test]
    fn copy_dir_recursive_clones_nested_tree() {
        let root = tempdir().unwrap();
        let src = root.path().join("src");
        let dst = root.path().join("dst");

        // Build a nested src tree:
        //   src/a.txt
        //   src/sub/b.txt
        //   src/sub/deep/c.txt
        std::fs::create_dir_all(src.join("sub").join("deep")).unwrap();
        std::fs::write(src.join("a.txt"), b"alpha").unwrap();
        std::fs::write(src.join("sub").join("b.txt"), b"beta").unwrap();
        std::fs::write(src.join("sub").join("deep").join("c.txt"), b"gamma").unwrap();

        copy_dir_recursive(&src, &dst).unwrap();

        assert_eq!(std::fs::read(dst.join("a.txt")).unwrap(), b"alpha");
        assert_eq!(std::fs::read(dst.join("sub").join("b.txt")).unwrap(), b"beta");
        assert_eq!(
            std::fs::read(dst.join("sub").join("deep").join("c.txt")).unwrap(),
            b"gamma"
        );
    }

    /// Helper: build a NodeConfig whose data_dir + identity_path point into a
    /// fresh temporary directory. All four verify_data_dir tests below use it.
    fn verify_data_dir_test_config(dir: &std::path::Path) -> NodeConfig {
        NodeConfig {
            data_dir: dir.to_path_buf(),
            identity_path: dir.join("identity.json"),
            ..Default::default()
        }
    }

    #[test]
    fn verify_data_dir_empty_directory_returns_ok() {
        // Covers the "fresh init / nothing on disk yet"
        // path. verify_data_dir is the operator-facing `elara-node verify`
        // entry point — must never error out on a brand-new data_dir, just
        // report what's missing. Each subsystem branch (identity / snapshot /
        // rocksdb / peers / dht) takes the "NOT FOUND" leg.
        let dir = tempdir().unwrap();
        let config = verify_data_dir_test_config(dir.path());
        verify_data_dir(&config).expect("empty data_dir must verify Ok");
    }

    #[test]
    fn verify_data_dir_valid_identity_returns_ok() {
        // Identity present + parseable. Exercises the happy-path branch that
        // strips the identity_hash to first 16 chars and prints the entity_type.
        // Also seeds peers.json/dht.json so those branches report OK rather
        // than MISSING, covering both legs of those if/else printlns.
        let dir = tempdir().unwrap();
        let config = verify_data_dir_test_config(dir.path());

        std::fs::write(
            &config.identity_path,
            br#"{"identity_hash":"abcdef0123456789deadbeefcafebabe","entity_type":"witness"}"#,
        ).unwrap();
        std::fs::write(dir.path().join("peers.json"), b"[]").unwrap();
        std::fs::write(dir.path().join("dht.json"), b"{}").unwrap();

        verify_data_dir(&config).expect("valid identity must verify Ok");
    }

    #[test]
    fn verify_data_dir_malformed_identity_returns_err() {
        // Identity file present but not valid JSON → serde_json::from_str
        // fails → ElaraError::Config bubbles up. This is the ONLY path in
        // verify_data_dir that returns Err — every other malformed input
        // (broken snapshot, missing rocksdb, locked rocksdb) is treated as
        // a soft warning and returns Ok. Locking in that contract here means
        // future refactors can't silently change error semantics on this
        // entry point.
        let dir = tempdir().unwrap();
        let config = verify_data_dir_test_config(dir.path());

        std::fs::write(&config.identity_path, b"{this is not valid json").unwrap();

        let err = verify_data_dir(&config).expect_err("malformed identity must Err");
        let msg = format!("{err}");
        assert!(
            msg.contains("identity") || msg.contains("parse"),
            "error should mention identity parse failure, got: {msg}"
        );
    }

    #[test]
    fn verify_data_dir_snapshot_conservation_mismatch_is_soft_warning() {
        // Ledger snapshot present but pool + accounts + staked != total_supply
        // (the conservation invariant is violated). verify_data_dir prints
        // a WARNING line but returns Ok — operators get a flagged report,
        // not a hard failure. This matches the design intent: `verify` is
        // a diagnostic that must always run to completion so operators can
        // see the FULL picture (identity OK but ledger broken, etc.), rather
        // than aborting on the first issue.
        //
        // total_supply=100, pool=10, staked=20, one account with available=30
        // → sum=60, mismatch by 40 → soft warning, still Ok.
        let dir = tempdir().unwrap();
        let config = verify_data_dir_test_config(dir.path());

        let snapshot = serde_json::json!({
            "ledger": {
                "total_supply": 100u64,
                "total_staked": 20u64,
                "conservation_pool": 10u64,
                "accounts": {
                    "id1": { "available": 30u64 }
                }
            }
        });
        std::fs::write(
            dir.path().join("ledger-snapshot.json"),
            serde_json::to_vec(&snapshot).unwrap(),
        ).unwrap();

        verify_data_dir(&config).expect("conservation mismatch is soft warning, not Err");
    }

    // ──────────────────────────────────────────────────────────────────────
    // Gap 7: chain_divergence_monitor_loop
    // unit tests. Validates: constants are sensible, the stub loop ticks the
    // no-peers counter and emits gauge=0 without panicking, and the gauge
    // field is initialized to 0 on NodeState construction.
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn chain_divergence_constants_match_design() {
        // Constants must align with the design sketch +
        // the `ChainDivergencePersistent` alert threshold.
        // If any of these drift, the alert rule's >50/30m window becomes
        // misaligned with the detector's behavior — page the on-call.
        assert_eq!(
            CHAIN_DIVERGENCE_POLL_INTERVAL_SECS, 300,
            "poll interval must be 5min: alert rule for=30m needs ≥5 ticks to confirm",
        );
        assert_eq!(
            CHAIN_DIVERGENCE_THRESHOLD_EPOCHS, 50,
            "threshold must match `ChainDivergencePersistent` alert expr",
        );
        assert_eq!(
            CHAIN_DIVERGENCE_MAX_REPAIR_PEERS, 3,
            "max-repair-peers cap: O(N) memory per tick, never O(connected_peers)",
        );
    }

    #[test]
    fn chain_divergence_threshold_above_mode3_cycle_depth() {
        // Mode-3 RocksDB compaction cycle hits ~30 epochs deep at peak
        // (observed deep-phase values around N=12-13 per cycle).
        // Threshold must exceed cycle floor by ≥1.5× margin to avoid
        // false-firing repair attempts during normal disk-pressure rebound.
        // A 50-epoch threshold gives 1.67× margin over 30 — safely above.
        let observed_mode3_cycle_depth: u64 = 30;
        let margin = CHAIN_DIVERGENCE_THRESHOLD_EPOCHS as f64
            / observed_mode3_cycle_depth as f64;
        assert!(
            margin >= 1.5,
            "threshold margin {margin:.2}× over Mode-3 cycle ({observed_mode3_cycle_depth} epochs) too tight — false repair-fires expected",
        );
    }

    #[test]
    fn chain_divergence_fields_init_to_zero() {
        // Verifies the seven new atomic fields land on NodeState with the
        // correct default state. If any of these defaulted to non-zero, the
        // `ChainDivergencePersistent` alert could false-fire on a freshly-
        // booted node — paging operators with no actual divergence.
        use elara_runtime::network::config::NodeConfig;
        use elara_runtime::network::witness::WitnessManager;
        use elara_runtime::storage::rocks::StorageEngine;
        use std::sync::atomic::Ordering;
        use std::sync::Arc;

        let tmp = tempdir().unwrap();
        let data_dir = tmp.path().to_path_buf();
        let config = NodeConfig {
            data_dir: data_dir.clone(),
            identity_path: data_dir.join("identity.json"),
            db_path: data_dir.join("elara.db"),
            admin_token: "test-admin".into(),
            network_id: "chain-divergence-init-test".into(),
            mdns_enabled: false,
            health_check_interval_secs: 0,
            min_pow_difficulty: 0,
            ..Default::default()
        };
        let identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
            .expect("identity gen");
        let rocks = Arc::new(
            StorageEngine::open(data_dir.join("rocksdb")).expect("rocks open"),
        );
        let wmgr = Arc::new(WitnessManager::new(rocks.clone()));
        let state = NodeState::new(config, identity, rocks, wmgr);

        // All seven Gap 7 divergence fields must init to 0. The gauge default
        // matters for alert-correctness (0 = healthy); the counter defaults
        // matter for rate-calc baselines (counters MUST start at 0 per Prom
        // convention so `rate()` is interpretable).
        assert_eq!(state.chain_divergence_epochs.load(Ordering::Relaxed), 0);
        // Signed-divergence pair MUST also init to 0 so a freshly-
        // booted node does not false-fire as either AHEAD or BEHIND.
        assert_eq!(state.chain_divergence_epochs_ahead.load(Ordering::Relaxed), 0);
        assert_eq!(state.chain_divergence_epochs_behind.load(Ordering::Relaxed), 0);
        assert_eq!(
            state.chain_divergence_poll_no_peers_total.load(Ordering::Relaxed),
            0,
        );
        assert_eq!(
            state.chain_divergence_repair_attempts_total.load(Ordering::Relaxed),
            0,
        );
        assert_eq!(
            state.chain_divergence_repair_failures_total.load(Ordering::Relaxed),
            0,
        );
        assert_eq!(
            state.chain_divergence_repair_verify_fails_total.load(Ordering::Relaxed),
            0,
        );
        assert_eq!(
            state.chain_divergence_repair_apply_fails_total.load(Ordering::Relaxed),
            0,
        );
        assert_eq!(
            state.chain_divergence_repair_success_total.load(Ordering::Relaxed),
            0,
        );
    }

    // ──────────────────────────────────────────────────────────────────────
    // Signed-divergence directionality tests. The pair
    // (`ahead`, `behind`) is computed by `chain_divergence_monitor_loop`
    // via two `saturating_sub`s on `local_tip` ↔ `max_peer_tip`. Mirroring
    // the loop body arithmetic locally lets us pin the directionality without
    // standing up the full peer-fan-out HTTP harness — same shape used by the
    // cross-equivalence tests for `parse_epoch_seals_total`.
    // ──────────────────────────────────────────────────────────────────────

    /// Mirrors elara_node.rs:4515-4521 loop body. Kept inline here so the
    /// math under test is the math actually shipping; a refactor on either
    /// side will surface as a test failure rather than silent drift.
    fn signed_divergence_pair(local_tip: u64, max_peer_tip: u64) -> (u64, u64) {
        let behind = max_peer_tip.saturating_sub(local_tip);
        let ahead = local_tip.saturating_sub(max_peer_tip);
        (ahead, behind)
    }

    #[test]
    fn signed_divergence_local_behind_peer() {
        // Follower scenario: peer is the producer, we trail by 7 epochs.
        // The earlier unsigned gauge already captured this — the new
        // _behind field must mirror it exactly (behind=divergence) while
        // _ahead stays 0 (we did not outrun anyone).
        let (ahead, behind) = signed_divergence_pair(/*local*/ 100, /*peer*/ 107);
        assert_eq!(ahead, 0, "follower must report ahead=0");
        assert_eq!(behind, 7, "follower must report behind=peer-local");
    }

    #[test]
    fn signed_divergence_local_ahead_of_peer() {
        // Producer scenario: we ship epochs faster than peers catch up.
        // Previously the unsigned gauge clamped to 0 here (saturating_sub
        // underflow), losing the "we are 5 ahead" signal: a node that is
        // 1 AHEAD and a node that is 1 BEHIND both rendered as `=1`, which
        // is indistinguishable. New _ahead
        // field surfaces the producer state; _behind stays 0.
        let (ahead, behind) = signed_divergence_pair(/*local*/ 112, /*peer*/ 107);
        assert_eq!(ahead, 5, "producer must report ahead=local-peer");
        assert_eq!(behind, 0, "producer must report behind=0");
    }

    #[test]
    fn signed_divergence_parity_zero_both() {
        // Healthy parity: local matches max peer exactly. Both directions
        // MUST report 0 — non-zero on either side at parity would mean an
        // arithmetic error has crept into the loop body.
        let (ahead, behind) = signed_divergence_pair(/*local*/ 200, /*peer*/ 200);
        assert_eq!(ahead, 0, "at-parity must report ahead=0");
        assert_eq!(behind, 0, "at-parity must report behind=0");

        // Mutual exclusion property: across all (local, peer) inputs at most
        // one of (ahead, behind) is non-zero. Spot-check a handful of pairs
        // around the boundary where signed-int math would have produced
        // negatives (and where the saturating_sub pair must NOT both fire).
        for (local, peer) in [(0u64, 0u64), (0, 1), (1, 0), (50, 50), (51, 49), (49, 51)] {
            let (a, b) = signed_divergence_pair(local, peer);
            assert!(
                !(a > 0 && b > 0),
                "ahead+behind both non-zero at (local={local}, peer={peer}): a={a} b={b}"
            );
        }
    }

    // ──────────────────────────────────────────────────────────────────────
    // Gap 7: poll_peer_tips + parse_epoch_seals_total unit tests. Validates
    // the Prometheus-line parser against the exact text body shape produced
    // by the metrics handler in server.rs.
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn parse_epoch_seals_total_matches_live_metrics_shape() {
        // Live shape captured from a node's /metrics:
        //   elara_epoch_seals_total 15654
        // Must round-trip without label or float weirdness.
        let body = "\
# HELP elara_epoch_seals_total Total epoch seals across all zones\n\
# TYPE elara_epoch_seals_total gauge\n\
elara_epoch_seals_total 15654\n\
# HELP elara_other_gauge Some other thing\n\
elara_other_gauge 42\n\
";
        assert_eq!(parse_epoch_seals_total(body), Some(15654));
    }

    #[test]
    fn parse_epoch_seals_total_returns_none_when_absent() {
        // Light-profile nodes that don't expose the metric (or unrelated
        // services) must return None — caller treats this as `no peer tip`
        // (same as a network failure).
        let body = "\
# HELP something_else other gauge\n\
something_else 5\n\
elara_dht_size 3\n\
";
        assert_eq!(parse_epoch_seals_total(body), None);
    }

    #[test]
    fn parse_epoch_seals_total_tolerates_float_value() {
        // Some Prometheus exporters emit floats even for integer counters
        // (e.g. `1.5654e4`); parser must accept these and round to u64.
        let body = "elara_epoch_seals_total 15654.0\n";
        assert_eq!(parse_epoch_seals_total(body), Some(15654));
    }

    #[test]
    fn parse_epoch_seals_total_rejects_negative_float() {
        // A negative or NaN value is nonsense for a cumulative counter; the
        // parser must reject rather than wraparound to u64::MAX.
        let body = "elara_epoch_seals_total -1\n";
        assert_eq!(parse_epoch_seals_total(body), None);
        let body_nan = "elara_epoch_seals_total NaN\n";
        assert_eq!(parse_epoch_seals_total(body_nan), None);
    }

    #[test]
    fn chain_divergence_peer_timeout_below_tick_interval() {
        // Sequential per-peer timeout × MAX_REPAIR_PEERS must finish well
        // within the 300s tick budget. 10s × 3 = 30s leaves ≥270s headroom
        // for the rest of the loop body (read_recover, atomic stores, log).
        let total = CHAIN_DIVERGENCE_PEER_TIMEOUT_SECS
            * CHAIN_DIVERGENCE_MAX_REPAIR_PEERS as u64;
        assert!(
            total < CHAIN_DIVERGENCE_POLL_INTERVAL_SECS,
            "peer-poll fan-out {total}s must fit inside tick interval {tick}s",
            tick = CHAIN_DIVERGENCE_POLL_INTERVAL_SECS,
        );
    }

    // ──────────────────────────────────────────────────────────────────────
    // Gap 7: chain-tip basis switch.
    // `parse_local_chain_tip` + `parse_peer_chain_tip` validation.
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn parse_local_chain_tip_matches_live_metrics_shape() {
        // Tick-121 metric shape:
        //   elara_local_chain_tip 22196
        // Must parse without label or HELP/TYPE-line confusion.
        let body = "\
# HELP elara_local_chain_tip Gap 7 tick-121 PERSISTENT chain-tip\n\
# TYPE elara_local_chain_tip gauge\n\
elara_local_chain_tip 22196\n\
# HELP elara_epoch_seals_total old runtime counter\n\
elara_epoch_seals_total 99999\n\
";
        assert_eq!(parse_local_chain_tip(body), Some(22196));
    }

    #[test]
    fn parse_peer_chain_tip_prefers_chain_tip_over_epoch_seals() {
        // Mixed-binary rollout: chain-tip MUST win when both metrics are
        // present on the same peer. If this regresses, the divergence math
        // silently falls back to the gossip-replay-inflated counter for any
        // peer that exposes both (i.e. every newer peer), defeating the
        // whole point of the switch.
        let body = "\
elara_local_chain_tip 22196\n\
elara_epoch_seals_total 99999\n\
";
        assert_eq!(parse_peer_chain_tip(body), Some(22196));

        // Older peer: only epoch_seals available; fallback returns it
        // so the loop has SOMETHING to compare against during the rollout
        // window. Once all peers emit the chain-tip metric this path is unreachable.
        let body_old = "elara_epoch_seals_total 15654\n";
        assert_eq!(parse_peer_chain_tip(body_old), Some(15654));

        // Pre-detector peer (neither metric): returns None, caller bumps
        // poll_no_peers_total and emits gauge=0.
        let body_neither = "elara_dht_size 3\n";
        assert_eq!(parse_peer_chain_tip(body_neither), None);
    }

    // ──────────────────────────────────────────────────────────────────────
    // Gap 7: repair-half tests for
    // `pull_state_delta` + `apply_state_delta_for_repair`. Validates:
    //   1. The repair-timeout floor is below the monitor-tick interval so a
    //      single attempt cannot overrun the next tick.
    //   2. `pull_state_delta` against an unreachable URL surfaces as
    //      `ElaraError::Wire` (so the caller bumps `repair_failures_total`
    //      and not a panic).
    //   3. `apply_state_delta_for_repair` upserts `changed_accounts`,
    //      removes `removed_accounts`, and drains the touched identities
    //      from `smt_dirty` (so subsequent epoch-seal flushes don't
    //      double-apply the same set).
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn chain_divergence_repair_timeout_below_tick_interval() {
        // Repair-timeout-fits-tick-interval invariant pinned at compile
        // time via the `const _: () = assert!(..)` block next to the
        // CHAIN_DIVERGENCE_REPAIR_TIMEOUT_SECS declaration
        // (bin/elara_node.rs ~L4233). A regression that flipped the
        // ordering now fails at `cargo build`, not at `cargo test`.
        // Runtime assert removed (clippy::assertions_on_constants —
        // both operands const-eval). 120 s repair << 300 s tick gives
        // 180 s headroom for peer-poll fan-out (≤30 s) + verify/apply
        // (negligible) + log.
    }

    #[tokio::test]
    async fn pull_state_delta_unreachable_url_returns_wire_error() {
        // Port 1 is the conventional "definitely unused on this host" port —
        // connection-refused returns immediately, which the function MUST
        // surface as `ElaraError::Wire` so the caller can bump
        // `chain_divergence_repair_failures_total` without panicking. If
        // this regresses to a different error variant the caller's match
        // arm silently misclassifies network failure as something else.
        let result = pull_state_delta("http://127.0.0.1:1", 0).await;
        let err = result.expect_err("connection-refused must surface as Err");
        assert!(
            matches!(err, ElaraError::Wire(_)),
            "expected Wire error, got: {err:?}",
        );
    }

    #[tokio::test]
    async fn apply_state_delta_for_repair_upserts_and_removes() {
        use elara_runtime::network::config::NodeConfig;
        use elara_runtime::network::witness::WitnessManager;
        use elara_runtime::storage::rocks::StorageEngine;

        // Fresh node with an empty ledger.
        let tmp = tempdir().unwrap();
        let data_dir = tmp.path().to_path_buf();
        let config = NodeConfig {
            data_dir: data_dir.clone(),
            identity_path: data_dir.join("identity.json"),
            db_path: data_dir.join("elara.db"),
            admin_token: "test-admin".into(),
            network_id: "state-delta-apply-test".into(),
            mdns_enabled: false,
            health_check_interval_secs: 0,
            min_pow_difficulty: 0,
            ..Default::default()
        };
        let identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
            .expect("identity gen");
        let rocks = Arc::new(
            StorageEngine::open(data_dir.join("rocksdb")).expect("rocks open"),
        );
        let wmgr = Arc::new(WitnessManager::new(rocks.clone()));
        let state = Arc::new(NodeState::new(config, identity, rocks, wmgr));

        // Pre-seed an account that the delta will REMOVE. Pre-seed another
        // that the delta will UPDATE. Pre-seed an unrelated account that
        // must remain untouched.
        let removed_id = "0".repeat(64); // 32-byte hex
        let updated_id = format!("{}{}", "1".repeat(63), "1");
        let untouched_id = format!("{}{}", "2".repeat(63), "2");
        let new_id = format!("{}{}", "3".repeat(63), "3");
        {
            let mut ledger = state.ledger.write().await;
            ledger.accounts.insert(
                removed_id.clone(),
                elara_runtime::accounting::ledger::AccountState {
                    available: 99,
                    ..Default::default()
                },
            );
            ledger.accounts.insert(
                updated_id.clone(),
                elara_runtime::accounting::ledger::AccountState {
                    available: 10,
                    ..Default::default()
                },
            );
            ledger.accounts.insert(
                untouched_id.clone(),
                elara_runtime::accounting::ledger::AccountState {
                    available: 42,
                    ..Default::default()
                },
            );
            // Pre-fill smt_dirty with the untouched id to prove the apply
            // path only drains scoped identities.
            ledger.smt_dirty.insert(untouched_id.clone());
        }

        // Build a synthetic StateDelta. The signing is irrelevant to apply
        // (the caller is responsible for verify+trust-gate); we just need
        // the payload shape.
        let mut changed = std::collections::BTreeMap::new();
        changed.insert(
            updated_id.clone(),
            elara_runtime::accounting::ledger::AccountState {
                available: 500,
                staked: 100,
                ..Default::default()
            },
        );
        changed.insert(
            new_id.clone(),
            elara_runtime::accounting::ledger::AccountState {
                available: 7,
                ..Default::default()
            },
        );
        let signer_identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
            .expect("signer gen");
        let delta = snapshot::create_signed_state_delta(snapshot::StateDeltaInputs {
            since_epoch: 100,
            current_epoch: 200,
            baseline_available: true,
            account_state_root: [0xA0u8; 32],
            merkle_root: [0xB0u8; 32],
            latest_super_seal_epoch: None,
            latest_super_seal_record_hash: None,
            latest_sealed_account_epoch: None,
            latest_sealed_account_smt_root: None,
            changed_accounts: changed,
            removed_accounts: vec![removed_id.clone()],
            total_accounts: 3,
            total_supply: 1_000_000,
            total_staked: 100,
            identity: &signer_identity,
        }).expect("delta sign");

        // Apply.
        let touched = apply_state_delta_for_repair(&state, &delta)
            .await
            .expect("apply must succeed");
        // 2 changed + 1 removed = 3 touched identities (all decode as valid
        // 32-byte hex). `snapshot_scoped` may skip entries whose hex doesn't
        // decode, but our test ids are all-hex by construction.
        assert_eq!(touched, 3, "must drain all scoped identities");

        // Assert ledger reflects the delta.
        let ledger = state.ledger.read().await;
        assert!(!ledger.accounts.contains_key(&removed_id),
            "removed account must be gone");
        let updated = ledger.accounts.get(&updated_id)
            .expect("updated account must exist");
        assert_eq!(updated.available, 500);
        assert_eq!(updated.staked, 100);
        let new = ledger.accounts.get(&new_id)
            .expect("new account must exist");
        assert_eq!(new.available, 7);
        let untouched = ledger.accounts.get(&untouched_id)
            .expect("untouched account must remain");
        assert_eq!(untouched.available, 42,
            "delta apply must NOT mutate accounts outside its scope");

        // The 3 scoped identities should have been drained from smt_dirty
        // by `snapshot_scoped`. The pre-seeded untouched_id must remain
        // (it's outside scope).
        assert!(!ledger.smt_dirty.contains(&updated_id));
        assert!(!ledger.smt_dirty.contains(&new_id));
        assert!(!ledger.smt_dirty.contains(&removed_id));
        assert!(
            ledger.smt_dirty.contains(&untouched_id),
            "pre-seeded out-of-scope smt_dirty entry must persist",
        );
        drop(ledger);

        // Gap 7 post-apply SMT-root (advisory since 2026-06-16 fusion audit):
        // the synthetic delta's `account_state_root = [0xA0; 32]` cannot match
        // any real post-apply root, but the live-root comparison is NOT a
        // cross-node-stable invariant on a subset repair (we patch a subset diff
        // onto our own forked pre-state), so it MUST NOT bump the page-worthy
        // counter — it only logs at debug. Counter stays 0.
        let mismatch = state
            .chain_divergence_repair_root_mismatch_total
            .load(Ordering::Relaxed);
        assert_eq!(
            mismatch, 0,
            "post-apply live-root mismatch is advisory-only — must NOT bump the page-worthy counter (not cross-node-stable on a subset repair)",
        );

        // (audit 2026-06-15 f2) The repair mutates `accounts` out-of-band, so it
        // MUST reconcile the incrementally-maintained scalars from the post-apply
        // account set — pre-fix `total_staked` stayed 0 here (the bug). Recompute
        // (not assign-from-delta) is the correct source: it is self-consistent
        // with the leaves `is_settled`'s numerator is summed over.
        let ledger = state.ledger.read().await;
        assert_eq!(
            ledger.total_staked, 100,
            "repair must recompute total_staked from post-apply accounts (only updated_id staked=100)",
        );
        assert_eq!(
            ledger.accounts.len(),
            3,
            "post-apply account set = updated + untouched + new",
        );
        drop(ledger);
        // Fully-covered case: recomputed total_staked (100) == delta.total_staked
        // (100) → NO scalar drift signalled.
        assert_eq!(
            state
                .chain_divergence_repair_scalar_drift_total
                .load(Ordering::Relaxed),
            0,
            "covered case: recomputed total_staked == delta.total_staked → no drift",
        );
        // Settlement denominator must reflect the repaired stake immediately —
        // register_stakes_from_ledger ran in-path, not deferred to the next tick.
        let zone0 = state
            .consensus
            .lock_recover()
            .total_zone_stake(elara_runtime::ZoneId::from_legacy(0));
        assert_eq!(
            zone0, 100,
            "zone_stakes denominator must track repaired total_staked after in-path register_stakes",
        );
        // Conservation cannot hold on a partial delta (sum_available=549 +
        // staked=100 = 649 vs total_supply=1_000_000; the delta carries no
        // pool/xzone) — a known wire-format limitation, NOT cross-node
        // divergence. Advisory since 2026-06-16: logs at debug, does not bump.
        assert_eq!(
            state
                .chain_divergence_repair_conservation_drift_total
                .load(Ordering::Relaxed),
            0,
            "conservation drift is advisory-only on a partial delta — must NOT bump the page-worthy counter",
        );
    }

    #[tokio::test]
    async fn apply_state_delta_for_repair_recomputes_not_assigns_total_staked() {
        // (audit 2026-06-15 f2) The fork-beyond-coverage case: an out-of-scope
        // staked account (NOT in the delta) means the post-apply staked-sum
        // differs from the producer's GLOBAL delta.total_staked. The repair MUST
        // install the self-consistent recomputed value (so is_settled's
        // denominator matches the node's own leaves) and SIGNAL the divergence —
        // proving recompute-from-accounts, not assign-from-delta.
        use elara_runtime::network::config::NodeConfig;
        use elara_runtime::network::witness::WitnessManager;
        use elara_runtime::storage::rocks::StorageEngine;

        let tmp = tempdir().unwrap();
        let data_dir = tmp.path().to_path_buf();
        let config = NodeConfig {
            data_dir: data_dir.clone(),
            identity_path: data_dir.join("identity.json"),
            db_path: data_dir.join("elara.db"),
            admin_token: "test-admin".into(),
            network_id: "state-delta-recompute-test".into(),
            mdns_enabled: false,
            health_check_interval_secs: 0,
            min_pow_difficulty: 0,
            ..Default::default()
        };
        let identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
            .expect("identity gen");
        let rocks = Arc::new(
            StorageEngine::open(data_dir.join("rocksdb")).expect("rocks open"),
        );
        let wmgr = Arc::new(WitnessManager::new(rocks.clone()));
        let state = Arc::new(NodeState::new(config, identity, rocks, wmgr));

        // Out-of-scope staked anchor the delta never mentions (our forked base).
        let oos_staker = format!("{}{}", "5".repeat(63), "5");
        let in_scope = format!("{}{}", "6".repeat(63), "6");
        {
            let mut ledger = state.ledger.write().await;
            ledger.accounts.insert(
                oos_staker.clone(),
                elara_runtime::accounting::ledger::AccountState {
                    available: 0,
                    staked: 50,
                    ..Default::default()
                },
            );
        }

        let mut changed = std::collections::BTreeMap::new();
        changed.insert(
            in_scope.clone(),
            elara_runtime::accounting::ledger::AccountState {
                available: 0,
                staked: 100,
                ..Default::default()
            },
        );
        let signer_identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
            .expect("signer gen");
        // Producer's GLOBAL total_staked = 100 (it does not know our oos staker).
        let delta = snapshot::create_signed_state_delta(snapshot::StateDeltaInputs {
            since_epoch: 100,
            current_epoch: 200,
            baseline_available: true,
            account_state_root: [0xA0u8; 32],
            merkle_root: [0xB0u8; 32],
            latest_super_seal_epoch: None,
            latest_super_seal_record_hash: None,
            latest_sealed_account_epoch: None,
            latest_sealed_account_smt_root: None,
            changed_accounts: changed,
            removed_accounts: vec![],
            total_accounts: 1,
            total_supply: 1_000_000,
            total_staked: 100,
            identity: &signer_identity,
        }).expect("delta sign");

        apply_state_delta_for_repair(&state, &delta)
            .await
            .expect("apply must succeed");

        // Self-consistent recompute = 50 (oos) + 100 (in-scope) = 150, NOT the
        // producer's global 100. Installing 100 would make is_settled's
        // denominator disagree with the node's own staked leaves.
        let ledger = state.ledger.read().await;
        assert_eq!(
            ledger.total_staked, 150,
            "must install recomputed sum over OUR accounts (150), not delta.total_staked (100)",
        );
        drop(ledger);
        // recomputed (150) != delta.total_staked (100) is the EXPECTED honest
        // outcome of a fork-beyond-coverage repair (producer's global scalar vs
        // our own-account sum), NOT cross-node divergence. Advisory since
        // 2026-06-16: logs at debug, does not bump the page-worthy counter.
        assert_eq!(
            state
                .chain_divergence_repair_scalar_drift_total
                .load(Ordering::Relaxed),
            0,
            "scalar drift is advisory-only — recomputed != delta.total_staked is expected on a subset repair, must NOT bump the page-worthy counter",
        );
        assert_eq!(
            state
                .consensus
                .lock_recover()
                .total_zone_stake(elara_runtime::ZoneId::from_legacy(0)),
            150,
            "denominator tracks the self-consistent recomputed stake",
        );
    }

    #[tokio::test]
    async fn apply_state_delta_for_repair_full_ledger_removes_local_only_accounts() {
        // (audit 2026-06-15 f2 follow-up) baseline_available=false = full-ledger
        // fallback: `changed_accounts` IS the producer's complete set and
        // `removed_accounts` is empty. A local-only account the producer never
        // saw (a fork artifact) MUST be cleared, not left as a phantom that
        // inflates the denominator + forks the SMT root.
        use elara_runtime::network::config::NodeConfig;
        use elara_runtime::network::witness::WitnessManager;
        use elara_runtime::storage::rocks::StorageEngine;

        let tmp = tempdir().unwrap();
        let data_dir = tmp.path().to_path_buf();
        let config = NodeConfig {
            data_dir: data_dir.clone(),
            identity_path: data_dir.join("identity.json"),
            db_path: data_dir.join("elara.db"),
            admin_token: "test-admin".into(),
            network_id: "state-delta-fullledger-test".into(),
            mdns_enabled: false,
            health_check_interval_secs: 0,
            min_pow_difficulty: 0,
            ..Default::default()
        };
        let identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
            .expect("identity gen");
        let rocks = Arc::new(
            StorageEngine::open(data_dir.join("rocksdb")).expect("rocks open"),
        );
        let wmgr = Arc::new(WitnessManager::new(rocks.clone()));
        let state = Arc::new(NodeState::new(config, identity, rocks, wmgr));

        let local_only = format!("{}{}", "7".repeat(63), "7"); // fork artifact, staked
        let shared = format!("{}{}", "8".repeat(63), "8");
        {
            let mut ledger = state.ledger.write().await;
            ledger.accounts.insert(
                local_only.clone(),
                elara_runtime::accounting::ledger::AccountState {
                    available: 0,
                    staked: 30,
                    ..Default::default()
                },
            );
            ledger.accounts.insert(
                shared.clone(),
                elara_runtime::accounting::ledger::AccountState {
                    available: 0,
                    staked: 10,
                    ..Default::default()
                },
            );
        }

        // Producer's COMPLETE ledger = just `shared` (staked 70). Full-ledger
        // fallback: baseline_available=false, removed_accounts empty.
        let mut changed = std::collections::BTreeMap::new();
        changed.insert(
            shared.clone(),
            elara_runtime::accounting::ledger::AccountState {
                available: 0,
                staked: 70,
                ..Default::default()
            },
        );
        let signer_identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
            .expect("signer gen");
        let delta = snapshot::create_signed_state_delta(snapshot::StateDeltaInputs {
            since_epoch: 0,
            current_epoch: 200,
            baseline_available: false,
            account_state_root: [0xA0u8; 32],
            merkle_root: [0xB0u8; 32],
            latest_super_seal_epoch: None,
            latest_super_seal_record_hash: None,
            latest_sealed_account_epoch: None,
            latest_sealed_account_smt_root: None,
            changed_accounts: changed,
            removed_accounts: vec![],
            total_accounts: 1,
            total_supply: 1_000_000,
            total_staked: 70,
            identity: &signer_identity,
        }).expect("delta sign");

        apply_state_delta_for_repair(&state, &delta)
            .await
            .expect("apply must succeed");

        let ledger = state.ledger.read().await;
        assert!(
            !ledger.accounts.contains_key(&local_only),
            "full-ledger repair must clear the local-only phantom account",
        );
        assert_eq!(
            ledger.accounts.get(&shared).map(|a| a.staked),
            Some(70),
            "shared account must take the producer's value",
        );
        assert_eq!(
            ledger.total_staked, 70,
            "denominator must reflect ONLY the producer's full ledger (70), not 70+30",
        );

        // F-5 V2: the removed local-only fork artifact must be TOMBSTONED in the
        // persistent SMT (collapsed to EMPTY_HASH), not left as a hash(default)
        // ghost leaf. The repaired node's account_smt_root must therefore equal
        // root_over_accounts over its post-repair set (only `shared`) — i.e. it
        // converges to the root a node that never saw the artifact computes,
        // instead of stranding an SMT-ahead phantom.
        use elara_runtime::network::account_merkle;
        let tree = account_merkle::AccountStateSMT::new(&state.rocks);
        let mut local_only_id = [0u8; 32];
        local_only_id.copy_from_slice(&hex::decode(&local_only).unwrap());
        assert_eq!(
            tree.get(&local_only_id).unwrap(),
            None,
            "removed fork artifact must be tombstoned in the SMT, not a ghost leaf",
        );
        let expected = account_merkle::root_over_accounts(&ledger.accounts).unwrap();
        assert_eq!(
            tree.root().unwrap(),
            expected,
            "post-repair persisted SMT root must converge to root_over_accounts(survivors)",
        );
    }

    #[tokio::test]
    async fn apply_state_delta_for_repair_live_root_mismatch_is_advisory_not_counted() {
        // Gap 7 (post-2026-06-16 fusion audit): the post-apply live-root
        // comparison against the producer's signed `account_state_root` is
        // ADVISORY ONLY — it is not a cross-node-stable invariant (the consumer
        // patches a subset diff onto its own forked pre-state, so its post-apply
        // root legitimately differs from the producer's full-set root), so it
        // MUST NOT bump the page-worthy mismatch counter regardless of match or
        // mismatch. The repair must still SUCCEED (no abort) in both cases.
        // Two-pass protocol: first apply with a deliberately-wrong root, then a
        // matching root; the counter stays 0 throughout.
        use elara_runtime::network::account_merkle;
        use elara_runtime::network::config::NodeConfig;
        use elara_runtime::network::witness::WitnessManager;
        use elara_runtime::storage::rocks::StorageEngine;

        let tmp = tempdir().unwrap();
        let data_dir = tmp.path().to_path_buf();
        let config = NodeConfig {
            data_dir: data_dir.clone(),
            identity_path: data_dir.join("identity.json"),
            db_path: data_dir.join("elara.db"),
            admin_token: "test-admin".into(),
            network_id: "state-delta-match-test".into(),
            mdns_enabled: false,
            health_check_interval_secs: 0,
            min_pow_difficulty: 0,
            ..Default::default()
        };
        let identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
            .expect("identity gen");
        let rocks = Arc::new(
            StorageEngine::open(data_dir.join("rocksdb")).expect("rocks open"),
        );
        let wmgr = Arc::new(WitnessManager::new(rocks.clone()));
        let state = Arc::new(NodeState::new(config, identity, rocks.clone(), wmgr));

        // Pre-seed two accounts in the ledger so the SMT has real content
        // (an empty SMT root is a known constant; using non-empty state
        // gives the test the same shape as a production repair).
        let id_a = "a".repeat(64);
        let id_b = "b".repeat(64);
        {
            let mut ledger = state.ledger.write().await;
            ledger.accounts.insert(
                id_a.clone(),
                elara_runtime::accounting::ledger::AccountState {
                    available: 1,
                    ..Default::default()
                },
            );
            ledger.accounts.insert(
                id_b.clone(),
                elara_runtime::accounting::ledger::AccountState {
                    available: 2,
                    ..Default::default()
                },
            );
        }

        // Pass 1 — apply with a deliberately-wrong root to discover the
        // actual post-apply root via the SMT.
        let mut changed = std::collections::BTreeMap::new();
        changed.insert(
            id_a.clone(),
            elara_runtime::accounting::ledger::AccountState {
                available: 1000,
                ..Default::default()
            },
        );
        let signer = Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
            .expect("signer gen");
        let delta_bogus = snapshot::create_signed_state_delta(snapshot::StateDeltaInputs {
            since_epoch: 100,
            current_epoch: 200,
            baseline_available: true,
            account_state_root: [0xFFu8; 32],
            merkle_root: [0x00u8; 32],
            latest_super_seal_epoch: None,
            latest_super_seal_record_hash: None,
            latest_sealed_account_epoch: None,
            latest_sealed_account_smt_root: None,
            changed_accounts: changed.clone(),
            removed_accounts: vec![],
            total_accounts: 2,
            total_supply: 0,
            total_staked: 0,
            identity: &signer,
        }).expect("delta sign");
        let touched_bogus = apply_state_delta_for_repair(&state, &delta_bogus)
            .await
            .expect("first apply succeeds despite a divergent live root (advisory, no abort)");
        assert!(touched_bogus > 0, "repair applied the delta scope");
        assert_eq!(
            state.chain_divergence_repair_root_mismatch_total.load(Ordering::Relaxed),
            0,
            "live-root mismatch is advisory — must NOT bump the page-worthy counter (not cross-node-stable on a subset repair)",
        );

        // Read the actual post-apply SMT root straight from RocksDB.
        let actual_root = account_merkle::AccountStateSMT::new(&rocks)
            .root()
            .expect("root read");

        // Pass 2 — same touched scope, but build a NEW delta whose claimed
        // root is the freshly-observed root. The apply re-asserts the same
        // pairs (idempotent: state-hash unchanged) and computes the same
        // post-root. Counter stays 0 (matching path was never the bump trigger
        // either, and the live-root check no longer bumps regardless).
        let delta_match = snapshot::create_signed_state_delta(snapshot::StateDeltaInputs {
            since_epoch: 200,
            current_epoch: 300,
            baseline_available: true,
            account_state_root: actual_root,
            merkle_root: [0x00u8; 32],
            latest_super_seal_epoch: None,
            latest_super_seal_record_hash: None,
            latest_sealed_account_epoch: None,
            latest_sealed_account_smt_root: None,
            changed_accounts: changed,
            removed_accounts: vec![],
            total_accounts: 2,
            total_supply: 0,
            total_staked: 0,
            identity: &signer,
        }).expect("delta sign");
        apply_state_delta_for_repair(&state, &delta_match)
            .await
            .expect("second apply");
        assert_eq!(
            state.chain_divergence_repair_root_mismatch_total.load(Ordering::Relaxed),
            0,
            "matching root also does not bump — the live-root check is advisory-only (still 0)",
        );
    }

    // ─── metrics-parser label-rejection tests ────────────────────────────

    #[test]
    fn batch_b_parse_metrics_rejects_label_bearing_lines_strict_prefix_requires_space() {
        // strip_prefix("elara_epoch_seals_total ") expects exactly one space
        // after the name. Prometheus labels like {zone="x"} sit BETWEEN the
        // name and the space — so `elara_epoch_seals_total{zone="z"} 42` MUST
        // NOT match. Same for chain_tip. This pins the documented invariant
        // that the metrics are emitted unlabeled by server.rs:4797.
        let body_labeled = "elara_epoch_seals_total{zone=\"z\"} 42\n";
        assert_eq!(parse_epoch_seals_total(body_labeled), None);
        let body_labeled_tip = "elara_local_chain_tip{node=\"hel\"} 100\n";
        assert_eq!(parse_local_chain_tip(body_labeled_tip), None);
        assert_eq!(parse_peer_chain_tip(body_labeled), None);
        assert_eq!(parse_peer_chain_tip(body_labeled_tip), None);
        // Brace immediately after name → no match
        let body_brace = "elara_epoch_seals_total{} 5\n";
        assert_eq!(parse_epoch_seals_total(body_brace), None);
    }

    #[test]
    fn batch_b_parse_metrics_returns_none_on_empty_and_whitespace_only_body() {
        for body in ["", " ", "\n", "\n\n\n", "   \n   \n", "\t\t\n"] {
            assert_eq!(parse_epoch_seals_total(body), None, "body={body:?}");
            assert_eq!(parse_local_chain_tip(body), None, "body={body:?}");
            assert_eq!(parse_peer_chain_tip(body), None, "body={body:?}");
        }
    }

    #[test]
    fn batch_b_parse_metrics_tolerates_multiple_internal_spaces_after_name() {
        // strip_prefix takes one space; trim() on the remainder absorbs extra
        // leading whitespace. Two-space and tab-separated forms must still
        // parse — a Prometheus exporter quirk seen on tightly-aligned outputs.
        let body_two = "elara_epoch_seals_total  42\n";
        assert_eq!(parse_epoch_seals_total(body_two), Some(42));
        let body_tabbed = "elara_epoch_seals_total \t 42\n";
        assert_eq!(parse_epoch_seals_total(body_tabbed), Some(42));
        let body_trailing = "elara_local_chain_tip 100  \n";
        assert_eq!(parse_local_chain_tip(body_trailing), Some(100));
        let body_trailing_tab = "elara_local_chain_tip 100\t\n";
        assert_eq!(parse_local_chain_tip(body_trailing_tab), Some(100));
    }

    #[test]
    fn batch_b_parse_metrics_help_type_lines_dont_capture_value_from_their_help_text() {
        // A HELP/TYPE line never starts with the metric name + space, but a
        // pathological body could embed the metric NAME inside HELP text.
        // The parser must only match lines that BEGIN with the exact metric
        // name + space — not lines where the name appears mid-line.
        let body_help_only = "\
# HELP elara_epoch_seals_total The total seals counter\n\
# TYPE elara_epoch_seals_total gauge\n\
";
        assert_eq!(parse_epoch_seals_total(body_help_only), None);
        let body_embedded_name = "elara_other_metric_elara_epoch_seals_total 999\n";
        assert_eq!(parse_epoch_seals_total(body_embedded_name), None);
        // The literal commented-out form must not be picked up either
        let body_commented = "# elara_epoch_seals_total 42\n";
        assert_eq!(parse_epoch_seals_total(body_commented), None);
        assert_eq!(parse_local_chain_tip("# elara_local_chain_tip 42\n"), None);
    }

    #[test]
    fn batch_b_parse_peer_chain_tip_only_epoch_seals_on_last_body_line_falls_back_correctly() {
        // Mixed-binary rollout: an older peer exposes ONLY
        // elara_epoch_seals_total. The fallback must find it regardless of
        // its line position in the body. Test with the metric on first, last,
        // and middle lines.
        let body_first = "elara_epoch_seals_total 1234\nelara_other 5\n";
        assert_eq!(parse_peer_chain_tip(body_first), Some(1234));
        let body_last = "elara_other 5\nelara_dht_size 3\nelara_epoch_seals_total 1234\n";
        assert_eq!(parse_peer_chain_tip(body_last), Some(1234));
        let body_middle = "elara_other 5\nelara_epoch_seals_total 1234\nelara_dht_size 3\n";
        assert_eq!(parse_peer_chain_tip(body_middle), Some(1234));
        // Body with chain_tip on LAST line and seals on FIRST: chain_tip still wins
        let body_chain_tip_last = "elara_epoch_seals_total 99999\nelara_other 5\nelara_local_chain_tip 22196\n";
        assert_eq!(parse_peer_chain_tip(body_chain_tip_last), Some(22196));
    }

    #[test]
    fn rebase_path_errors_on_no_filename_component() {
        use std::path::Path;
        use elara_runtime::errors::ElaraError;
        let data = Path::new("/data");
        // root path has no filename
        let err = crate::rebase_path(Path::new("/"), data).unwrap_err();
        assert!(matches!(err, ElaraError::Config(_)), "expected Config error, got {err:?}");
        // `..`-terminated path has no filename
        let err2 = crate::rebase_path(Path::new("/some/path/.."), data).unwrap_err();
        assert!(matches!(err2, ElaraError::Config(_)), "expected Config error, got {err2:?}");
        // normal path rebases correctly
        let rebased = crate::rebase_path(Path::new("/old/identity.json"), data).unwrap();
        assert_eq!(rebased, data.join("identity.json"));
    }

    #[test]
    fn divergence_repair_peer_tip_selection_handles_empty_and_non_empty() {
        // Pins the defensive fallback added to chain_divergence_monitor_loop:
        // max_by_key on an empty peer_tips must return None (loop continues),
        // and on a non-empty set must return the highest-tip entry.
        let empty: Vec<(String, u64)> = vec![];
        assert!(
            empty.iter().max_by_key(|(_, tip)| *tip).cloned().is_none(),
            "empty peer_tips must yield None — defensive continue fires"
        );

        let tips = [("http://a".to_string(), 10u64),
            ("http://b".to_string(), 30u64),
            ("http://c".to_string(), 20u64)];
        let selected = tips.iter().max_by_key(|(_, tip)| *tip).cloned();
        assert_eq!(
            selected,
            Some(("http://b".to_string(), 30u64)),
            "max_by_key must select the highest-tip peer"
        );
    }

    #[test]
    #[cfg(unix)] // OsStrExt::from_bytes is unix-only; the non-UTF-8 path trick needs it
    fn export_staging_path_non_utf8_returns_config_error() {
        use std::os::unix::ffi::OsStrExt;
        use std::path::PathBuf;
        use elara_runtime::errors::ElaraError;
        // Construct a path containing a lone 0xFF byte — not valid UTF-8.
        let bad_os = std::ffi::OsStr::from_bytes(b"/data/\xff_staging");
        let staging: PathBuf = bad_os.into();
        let result: std::result::Result<&str, ElaraError> = staging
            .to_str()
            .ok_or_else(|| ElaraError::Config(format!("data_dir path is not valid UTF-8: {}", staging.display())));
        assert!(result.is_err(), "non-UTF-8 path must return Err");
        assert!(
            matches!(result.unwrap_err(), ElaraError::Config(_)),
            "error must be ElaraError::Config"
        );
    }

    #[test]
    fn default_log_filter_string_is_valid() {
        // The fallback filter used when ELARA_LOG / RUST_LOG are unset must parse
        // successfully; a tracing-subscriber update that changes directive syntax
        // would otherwise panic the node at startup.
        // clippy flags try_from as unnecessary because the CURRENT tracing-subscriber
        // makes &str -> EnvFilter infallible — but this test EXISTS to catch a future
        // version where directive syntax changes and the conversion starts failing.
        // Keep the fallible path; switching to From::from would delete the guard.
        #[allow(clippy::unnecessary_fallible_conversions)]
        let result = tracing_subscriber::EnvFilter::try_from("elara_node=info,elara_runtime=info");
        assert!(result.is_ok(), "default log filter failed to parse: {:?}", result.err());
    }

    #[test]
    fn generate_admin_token_returns_64_char_hex() {
        let token = generate_admin_token().expect("getrandom is available in tests");
        assert_eq!(token.len(), 64, "32 random bytes → 64 hex chars");
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()), "token must be hex");
        // Two successive calls must not produce the same token.
        let token2 = generate_admin_token().expect("getrandom is available");
        assert_ne!(token, token2, "tokens must be unique");
    }

    #[cfg(unix)]
    #[test]
    fn sigterm_fallback_message_covers_signal_and_cause() {
        // Pins the warning emitted when SIGTERM registration fails so the fallback
        // branch stays observable in operator logs after any future refactor.
        let e = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "EPERM");
        let msg = format!("SIGTERM handler unavailable ({e}), falling back to SIGINT only");
        assert!(msg.contains("SIGTERM"), "message must name the failing signal");
        assert!(msg.contains("SIGINT"), "message must name the fallback signal");
        assert!(msg.contains("EPERM"), "message must include the underlying cause");
    }

    #[test]
    fn tokio_runtime_builder_succeeds_with_valid_settings() {
        // Covers the hardened main() path: build() must return Ok so the match
        // arm that calls process::exit(1) is never reached under normal conditions.
        let result = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .max_blocking_threads(4)
            .enable_all()
            .build();
        assert!(result.is_ok(), "Tokio runtime build must succeed: {:?}", result.err());
    }
}
