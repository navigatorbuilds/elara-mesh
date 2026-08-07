//! System load sensor — Stage 6 cooperative scheduler foundation.
//!
//! Samples kernel load signals on a 5-second cadence and exposes cheap
//! atomic reads for hot-path consumers. The node then uses `is_busy()` to
//! decide when to yield / back off so elara-node stays an "app-grade
//! citizen" on user hardware (Protocol §11.10 — runs alongside a
//! desktop workload without dropping frames).
//!
//! # Signals
//! - **CPU %** — delta of `/proc/stat` `cpu` counters across two samples.
//!   0.0 = idle, 1.0 = single core saturated, N = N cores saturated.
//! - **Load average (1-minute)** — `/proc/loadavg` first column. Normalized
//!   by core count so thresholds are portable across a 2-core VPS and
//!   a 16-core laptop.
//! - **Memory pressure** — already carried by [`NodeState::memory_pressure`];
//!   this module only covers CPU.
//!
//! # Scale / cost
//! - One blocking read of `/proc/stat` every 5s. Negligible on any host.
//! - Hot-path read is a single `AtomicU64::load` (bit-cast f64). Lock-free.
//! - No per-peer or per-zone state — global signal.
//!
//! Platforms other than Linux read as "idle" (0.0). Production testnet
//! is Linux-only (Hetzner / DO / Tailscale Ubuntu); the fallback is only
//! to keep `cargo test` green on macOS dev machines.
//!
//! # Spec
//! @spec Protocol §11.10 (cooperative resource usage, user-hardware mandate)

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Sampling cadence for the background refresh task. 5 seconds is the
/// same cadence the memory-pressure monitor uses — aligns refresh cycles.
pub const SAMPLE_INTERVAL: Duration = Duration::from_secs(5);

/// Default normalized-load threshold above which the node is "busy".
///
/// Normalization divides the raw 1-minute load by CPU core count, so
/// `NORMALIZED_BUSY_LOAD = 0.8` means "the kernel runqueue averaged at
/// least 80 % of a core per CPU for the last minute". On a 4-core box,
/// that's raw load ≥ 3.2. On a 1-core box, raw load ≥ 0.8.
///
/// The value matches Linux's own convention for when a box is
/// "under sustained load" (above 1.0 per core is pageable).
pub const NORMALIZED_BUSY_LOAD: f64 = 0.8;

/// Default CPU% threshold — node is "busy" if the 5s sample shows
/// more than this fraction of one CPU-core-equivalent used by this host
/// across all processes. 0.75 = 75% of one core. This catches short
/// bursts that the 1-minute load average would smooth away.
pub const CPU_BUSY_FRACTION: f64 = 0.75;

/// Lock-free system-load snapshot. Every field is an `AtomicU64`
/// carrying the bit pattern of an `f64`, so readers see a torn-free
/// sample without taking a lock. Writers are serialized by the single
/// background refresh task.
pub struct SystemLoadSensor {
    /// Raw 1-minute load average from `/proc/loadavg`. NaN-free.
    load_1m_bits: AtomicU64,
    /// 1-minute load normalized by core count (load_1m / cores).
    normalized_load_bits: AtomicU64,
    /// Fraction of one CPU-core equivalent used across the whole host
    /// over the last sample interval. 0.0–N where N = core count.
    cpu_fraction_bits: AtomicU64,
    /// Core count, read once at startup. Public for metrics.
    cores: u32,
    /// Monotonic sample counter (Prometheus counter).
    samples_total: AtomicU64,
}

impl Default for SystemLoadSensor {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemLoadSensor {
    pub fn new() -> Self {
        let cores = num_cpus_on_host();
        Self {
            load_1m_bits: AtomicU64::new(0),
            normalized_load_bits: AtomicU64::new(0),
            cpu_fraction_bits: AtomicU64::new(0),
            cores,
            samples_total: AtomicU64::new(0),
        }
    }

    /// Core count observed at startup. Minimum 1 so consumers can
    /// divide safely without a zero-check.
    pub fn cores(&self) -> u32 {
        self.cores
    }

    /// 1-minute load average (raw, not normalized).
    pub fn load_1m(&self) -> f64 {
        f64::from_bits(self.load_1m_bits.load(Ordering::Relaxed))
    }

    /// 1-minute load average divided by core count. A value ≥ 1.0 means
    /// every core was fully subscribed on average over the last minute.
    pub fn normalized_load(&self) -> f64 {
        f64::from_bits(self.normalized_load_bits.load(Ordering::Relaxed))
    }

    /// CPU usage from the most recent 5-second delta sample. 0.0–N cores.
    pub fn cpu_fraction(&self) -> f64 {
        f64::from_bits(self.cpu_fraction_bits.load(Ordering::Relaxed))
    }

    /// Total number of samples observed since startup (Prometheus counter).
    pub fn samples_total(&self) -> u64 {
        self.samples_total.load(Ordering::Relaxed)
    }

    /// Is the host under sustained or bursty CPU load? Used by hot-path
    /// callers to decide whether to cooperatively yield.
    ///
    /// Returns true if **either**:
    /// - the 1-minute normalized load exceeds [`NORMALIZED_BUSY_LOAD`]
    ///   (sustained pressure), or
    /// - the 5-second CPU fraction exceeds [`CPU_BUSY_FRACTION`] × cores
    ///   (bursty pressure — e.g. user just launched a browser).
    pub fn is_busy(&self) -> bool {
        let normalized = self.normalized_load();
        let cpu = self.cpu_fraction();
        let cpu_budget = CPU_BUSY_FRACTION * f64::from(self.cores);
        normalized > NORMALIZED_BUSY_LOAD || cpu > cpu_budget
    }

    /// Is the host severely saturated — beyond what cooperative yielding
    /// can rescue? Used by *background resolvers* (orphan resolver, prune
    /// sweeps) to skip an entire tick rather than pile heavy work on a
    /// runtime that's already pegged.
    ///
    /// Returns true when **both** signals trip together:
    /// - 1-minute normalized load > 1.5 (1.5× cores subscribed sustained), AND
    /// - aggregate CPU fraction > total core count (every core fully busy).
    ///
    /// Requiring both prevents a single spiky CPU sample from blocking the
    /// resolver indefinitely while the box is otherwise idle.
    ///
    /// Empirical origin: a 2-vCPU node under soak load.
    /// After a service restart the orphan resolver's MAX_FETCH=50 batch
    /// kept all tokio runtime threads at ~100% for ~14 minutes, starving
    /// the HTTP handler. The existing [`coop_yield_if_busy`] yields at
    /// loop top but cannot help mid-batch — skipping the cycle entirely
    /// lets `/version` + `/metrics` keep serving while orphans wait for
    /// the next 60s tick.
    pub fn is_saturated(&self) -> bool {
        let normalized = self.normalized_load();
        let cpu = self.cpu_fraction();
        normalized > 1.5 && cpu > f64::from(self.cores)
    }

    /// Install a fresh sample. Called by the background refresh task.
    /// Values that fail to read are left unchanged — we never overwrite
    /// a good sample with a broken one.
    fn install(&self, load_1m: f64, cpu_fraction: f64) {
        let normalized = load_1m / f64::from(self.cores);
        self.load_1m_bits.store(load_1m.to_bits(), Ordering::Relaxed);
        self.normalized_load_bits
            .store(normalized.to_bits(), Ordering::Relaxed);
        self.cpu_fraction_bits
            .store(cpu_fraction.to_bits(), Ordering::Relaxed);
        self.samples_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Test helper: install a synthetic reading without sampling /proc.
    /// Private so production code can't accidentally forge a load value.
    #[cfg(test)]
    fn install_for_test(&self, load_1m: f64, cpu_fraction: f64) {
        self.install(load_1m, cpu_fraction);
    }
}

/// Run the sensor's refresh loop until the shutdown channel fires.
/// Each iteration samples `/proc/stat` delta CPU and `/proc/loadavg`,
/// then installs the reading on the shared sensor.
///
/// Matches the `mpsc::Receiver<()>` shutdown convention used by
/// `health::health_check_loop`, `gc::gc_loop`, etc. Spawn once at node
/// boot and forget.
pub async fn run_refresh_loop(
    sensor: std::sync::Arc<SystemLoadSensor>,
    mut shutdown: tokio::sync::watch::Receiver<()>,
    hb: std::sync::Arc<super::supervision::LoopStatus>,
) {
    let mut prior = CpuTotals::read();
    // First sample with an artificial 100ms delta so the fraction is
    // meaningful immediately instead of waiting 5s at boot.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let initial = CpuTotals::read();
    if let (Some(a), Some(b)) = (prior, initial) {
        sensor.install(read_load_1m(), cpu_fraction(a, b));
    }
    prior = initial;

    loop {
        tokio::select! {
            _ = tokio::time::sleep(SAMPLE_INTERVAL) => {}
            _ = shutdown.changed() => { return; }
        }
        hb.heartbeat(); // hang-detection: stamp each 5s sample (« 30s stale_after)

        let now = CpuTotals::read();
        let cpu = match (prior, now) {
            (Some(a), Some(b)) => cpu_fraction(a, b),
            _ => sensor.cpu_fraction(), // keep prior sample on read failure
        };
        let load = read_load_1m();
        sensor.install(load, cpu);
        prior = now;
    }
}

/// Cooperatively yield if the host is busy. Called from hot loops
/// (gossip push/pull, ingest). Yields the current tokio task and, if
/// the box is *very* busy (CPU > 1.5× the busy budget), sleeps briefly
/// to let the user's foreground workload breathe.
///
/// Cheap fast-path: if not busy, the function returns after a single
/// atomic load and does NOT yield. This keeps the overhead at ~5ns on
/// an idle testnet node.
pub async fn coop_yield_if_busy(sensor: &SystemLoadSensor) {
    if !sensor.is_busy() {
        return;
    }
    let cpu = sensor.cpu_fraction();
    let hard_budget = 1.5 * CPU_BUSY_FRACTION * f64::from(sensor.cores);
    if cpu > hard_budget {
        // Heavy pressure — briefly sleep to actually release the core.
        // 50ms matches the existing gossip.rs stall-sleep value so we
        // don't introduce a third latency regime.
        tokio::time::sleep(Duration::from_millis(50)).await;
    } else {
        // Normal busy — just yield. Restores the tokio runtime's
        // fairness without adding fixed latency.
        tokio::task::yield_now().await;
    }
}

// ─── /proc sampling helpers (Linux) ─────────────────────────────────────

#[derive(Copy, Clone, Debug)]
struct CpuTotals {
    total: u64,
    idle: u64,
}

impl CpuTotals {
    #[cfg(target_os = "linux")]
    fn read() -> Option<Self> {
        let s = std::fs::read_to_string("/proc/stat").ok()?;
        // First line is aggregate: "cpu  user nice system idle iowait irq softirq steal guest guest_nice"
        let line = s.lines().next()?;
        let mut it = line.split_whitespace();
        if it.next()? != "cpu" {
            return None;
        }
        let vals: Vec<u64> = it.filter_map(|v| v.parse::<u64>().ok()).collect();
        // Need at least user, nice, system, idle.
        if vals.len() < 4 {
            return None;
        }
        let idle = vals[3] + vals.get(4).copied().unwrap_or(0); // idle + iowait
        let total: u64 = vals.iter().sum();
        Some(Self { total, idle })
    }

    #[cfg(not(target_os = "linux"))]
    fn read() -> Option<Self> {
        // Non-Linux dev machines get a constant "idle" signal. Testnet is
        // Linux-only so this fallback never ships to production.
        Some(Self { total: 1, idle: 1 })
    }
}

fn cpu_fraction(prev: CpuTotals, now: CpuTotals) -> f64 {
    let total_d = now.total.saturating_sub(prev.total);
    let idle_d = now.idle.saturating_sub(prev.idle);
    if total_d == 0 {
        return 0.0;
    }
    let busy_d = total_d.saturating_sub(idle_d);
    // Express as fraction of ONE core, not aggregate fraction. Callers
    // know the core count separately (sensor.cores()).
    (busy_d as f64 / total_d as f64) * f64::from(num_cpus_on_host())
}

#[cfg(target_os = "linux")]
fn read_load_1m() -> f64 {
    std::fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|s| s.split_whitespace().next().and_then(|v| v.parse().ok()))
        .unwrap_or(0.0)
}

#[cfg(not(target_os = "linux"))]
fn read_load_1m() -> f64 {
    0.0
}

fn num_cpus_on_host() -> u32 {
    // std::thread::available_parallelism is stable since 1.59. Falls
    // back to 1 if it fails (degenerate but safe — means "every load
    // is normalized by 1", same as raw).
    std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn new_sensor_reports_zero_load_until_sampled() {
        let s = SystemLoadSensor::new();
        assert_eq!(s.load_1m(), 0.0);
        assert_eq!(s.normalized_load(), 0.0);
        assert_eq!(s.cpu_fraction(), 0.0);
        assert_eq!(s.samples_total(), 0);
        assert!(!s.is_busy());
    }

    #[test]
    fn cores_is_at_least_one() {
        let s = SystemLoadSensor::new();
        assert!(s.cores() >= 1, "cores() must be >= 1 even on exotic hosts");
    }

    #[test]
    fn install_updates_all_three_fields_and_counter() {
        let s = SystemLoadSensor::new();
        s.install_for_test(1.5, 0.4);
        assert_eq!(s.load_1m(), 1.5);
        assert_eq!(s.cpu_fraction(), 0.4);
        assert!((s.normalized_load() - 1.5 / f64::from(s.cores())).abs() < 1e-9);
        assert_eq!(s.samples_total(), 1);
    }

    #[test]
    fn is_busy_fires_on_high_normalized_load() {
        let s = SystemLoadSensor::new();
        // Normalized load 0.9 > NORMALIZED_BUSY_LOAD (0.8).
        s.install_for_test(0.9 * f64::from(s.cores()), 0.0);
        assert!(s.is_busy());
    }

    #[test]
    fn is_busy_fires_on_bursty_cpu_even_with_low_load() {
        let s = SystemLoadSensor::new();
        // CPU fraction > busy budget even if load average is near zero.
        let busy_cpu = CPU_BUSY_FRACTION * f64::from(s.cores()) + 0.1;
        s.install_for_test(0.0, busy_cpu);
        assert!(s.is_busy());
    }

    #[test]
    fn is_busy_false_when_under_both_thresholds() {
        let s = SystemLoadSensor::new();
        s.install_for_test(0.1, 0.1);
        assert!(!s.is_busy());
    }

    #[test]
    fn cpu_fraction_returns_zero_when_total_delta_is_zero() {
        let a = CpuTotals { total: 100, idle: 40 };
        // Same totals → no time passed → 0.
        assert_eq!(cpu_fraction(a, a), 0.0);
    }

    #[test]
    fn cpu_fraction_scales_with_cores() {
        // 60% busy (60 of 100 ticks), converted to per-core fraction
        // equals 0.6 × cores. We don't assert absolute value because
        // num_cpus differs per host; just sign-check.
        let prev = CpuTotals { total: 100, idle: 60 };
        let now = CpuTotals { total: 200, idle: 100 };
        // 100 total delta, 40 idle delta → 60 busy → 0.6 of aggregate
        // × cores. Must be > 0 on any host with cores >= 1.
        let frac = cpu_fraction(prev, now);
        assert!(frac > 0.0);
    }

    #[test]
    fn coop_yield_fast_path_does_not_block_when_idle() {
        // Idle sensor → coop_yield_if_busy must return ~instantly.
        let s = Arc::new(SystemLoadSensor::new());
        // Pretend-idle: no install calls.
        // Build the runtime first so we don't measure Runtime::new() startup
        // cost (can be several ms on a cold/loaded machine).
        let rt = tokio::runtime::Runtime::new().unwrap();
        let start = std::time::Instant::now();
        rt.block_on(async {
            coop_yield_if_busy(&s).await;
        });
        // Bound at 5ms — far below the 50ms heavy-load sleep, proves we
        // took the fast path. We start the clock after runtime init to
        // avoid flakiness from tokio scheduler cold-start overhead.
        assert!(
            start.elapsed() < Duration::from_millis(5),
            "idle fast-path should be near-instant, took {:?}",
            start.elapsed(),
        );
    }

    #[test]
    fn coop_yield_on_heavy_load_actually_sleeps() {
        // Force CPU > 1.5× busy budget → sleep path.
        let s = Arc::new(SystemLoadSensor::new());
        let heavy = 2.0 * CPU_BUSY_FRACTION * f64::from(s.cores());
        s.install_for_test(0.0, heavy);
        let start = std::time::Instant::now();
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            coop_yield_if_busy(&s).await;
        });
        // Sleep path is 50ms; allow a wide margin for CI jitter.
        assert!(
            start.elapsed() >= Duration::from_millis(40),
            "heavy-load branch should sleep ~50ms, took {:?}",
            start.elapsed(),
        );
    }

    #[test]
    fn is_saturated_false_when_idle() {
        let s = SystemLoadSensor::new();
        s.install_for_test(0.05, 0.05);
        assert!(!s.is_saturated());
    }

    #[test]
    fn is_saturated_false_when_only_load_high() {
        // Both gates must trip — load alone (e.g. iowait pile-up) is not
        // sufficient. Prevents skipping when CPU is actually idle.
        let s = SystemLoadSensor::new();
        let load = 2.0 * f64::from(s.cores()); // normalized 2.0
        s.install_for_test(load, 0.1);
        assert!(s.normalized_load() > 1.5);
        assert!(!s.is_saturated());
    }

    #[test]
    fn is_saturated_false_when_only_cpu_high() {
        // CPU spike alone (single 5s sample) without sustained load
        // shouldn't block the resolver indefinitely.
        let s = SystemLoadSensor::new();
        let cpu = f64::from(s.cores()) + 0.5; // > cores
        s.install_for_test(0.0, cpu);
        assert!(s.cpu_fraction() > f64::from(s.cores()));
        assert!(!s.is_saturated());
    }

    #[test]
    fn is_saturated_true_when_both_signals_trip() {
        // Post-restart catch-up pattern on a 2-vCPU node: load 2.5+
        // (normalized 1.25+) PLUS aggregate CPU > cores.
        let s = SystemLoadSensor::new();
        let load = 2.0 * f64::from(s.cores()); // normalized 2.0
        let cpu = f64::from(s.cores()) + 0.5;
        s.install_for_test(load, cpu);
        assert!(s.is_saturated());
    }

    // ─── constants + sensor/is_busy/is_saturated/cpu_fraction tests ───────
    // Pins surface invariants not covered by the legacy tests above:
    //  (1) 3 module constants strict-pin + cross-relations
    //  (2) Sensor field initial state + Default==new + samples_total monotonic + AtomicU64 f64-bits round-trip
    //  (3) is_busy() strict > boundary matrix on BOTH OR-gates
    //  (4) is_saturated() AND semantics + strict > at 1.5/cores boundaries
    //  (5) cpu_fraction() arithmetic surface (zero delta / saturating_sub / fraction math)

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_system_load_constants_strict_pin_and_cross_relations() {
        // Three module constants. Changing any one moves the
        // cooperative-yield threshold on every node — operator-tunable
        // surface so it must be pinned to catch silent drift.
        assert_eq!(SAMPLE_INTERVAL, Duration::from_secs(5),
            "SAMPLE_INTERVAL=5s — aligned with memory-pressure refresh");
        assert_eq!(SAMPLE_INTERVAL.as_secs(), 5,
            "SAMPLE_INTERVAL secs-form == 5");
        assert_eq!(SAMPLE_INTERVAL.as_millis(), 5000,
            "SAMPLE_INTERVAL millis-form == 5000");
        assert_eq!(NORMALIZED_BUSY_LOAD, 0.8,
            "NORMALIZED_BUSY_LOAD=0.8 — Linux convention for 'under sustained load'");
        assert_eq!(CPU_BUSY_FRACTION, 0.75,
            "CPU_BUSY_FRACTION=0.75 — 75% of one core triggers bursty-busy");

        // Cross-relations:
        // Both thresholds in (0, 1) — fraction-of-one-core semantic guard.
        assert!(NORMALIZED_BUSY_LOAD > 0.0 && NORMALIZED_BUSY_LOAD < 1.0,
            "0 < NORMALIZED_BUSY_LOAD < 1.0");
        assert!(CPU_BUSY_FRACTION > 0.0 && CPU_BUSY_FRACTION < 1.0,
            "0 < CPU_BUSY_FRACTION < 1.0");

        // CPU_BUSY_FRACTION < NORMALIZED_BUSY_LOAD — bursty signal is
        // intentionally MORE sensitive than the sustained signal so a
        // sudden foreground spike yields faster than a 1-minute average.
        assert!(CPU_BUSY_FRACTION < NORMALIZED_BUSY_LOAD,
            "bursty threshold (0.75) < sustained threshold (0.8)");

        // is_saturated hard-codes 1.5 normalized — assert it stays
        // BELOW physical headroom but ABOVE NORMALIZED_BUSY_LOAD so
        // saturation is strictly worse than busy.
        const SATURATED_NORMALIZED: f64 = 1.5;
        assert!(SATURATED_NORMALIZED > NORMALIZED_BUSY_LOAD,
            "saturated threshold (1.5) > busy threshold (0.8) — saturated is strictly worse than busy");
        // Saturated threshold is hard-coded in is_saturated; pin its
        // distance from NORMALIZED_BUSY_LOAD as a regression guard.
        // (Difference = 0.7 ≈ near doubling of the busy threshold.)
        assert!((SATURATED_NORMALIZED - NORMALIZED_BUSY_LOAD - 0.7).abs() < 1e-9,
            "saturated - busy == 0.7 exact");

        // The coop_yield heavy-path uses 1.5 * CPU_BUSY_FRACTION:
        let hard_budget_per_core = 1.5 * CPU_BUSY_FRACTION;
        assert!((hard_budget_per_core - 1.125).abs() < 1e-9,
            "1.5 * CPU_BUSY_FRACTION = 1.125 exact (coop_yield_if_busy heavy-path budget)");

        // Type pin: SAMPLE_INTERVAL is Duration (not u64/Instant).
        let _dur: Duration = SAMPLE_INTERVAL;
        // Type pin: thresholds are f64 (not f32 — load values from /proc
        // are parsed as f64 and would lose precision through f32).
        let _f64_a: f64 = NORMALIZED_BUSY_LOAD;
        let _f64_b: f64 = CPU_BUSY_FRACTION;
    }

    #[test]
    fn batch_b_sensor_initial_state_default_eq_new_and_samples_monotonic_and_f64_roundtrip() {
        // SystemLoadSensor::new() initial state — all f64 fields read
        // as 0.0 before any sample.
        let s = SystemLoadSensor::new();
        assert_eq!(s.load_1m(), 0.0,
            "new sensor load_1m == 0.0 (no sample yet)");
        assert_eq!(s.normalized_load(), 0.0);
        assert_eq!(s.cpu_fraction(), 0.0);
        assert_eq!(s.samples_total(), 0,
            "samples_total counter starts at 0");
        assert!(s.cores() >= 1,
            "cores() >= 1 on any host (fallback path returns 1)");
        assert!(!s.is_busy(),
            "new sensor is not busy (all thresholds quiescent)");
        assert!(!s.is_saturated(),
            "new sensor is not saturated");

        // Default::default() must match new(). install_for_test sees
        // exactly the same initial state.
        let d = SystemLoadSensor::default();
        assert_eq!(d.load_1m(), s.load_1m());
        assert_eq!(d.normalized_load(), s.normalized_load());
        assert_eq!(d.cpu_fraction(), s.cpu_fraction());
        assert_eq!(d.samples_total(), s.samples_total());
        assert_eq!(d.cores(), s.cores(),
            "Default::default() == new(): same observable state");

        // samples_total is a strict monotonic counter — N installs → N.
        // Catches a refactor that swaps fetch_add for a `store` (which
        // would clamp samples_total to 1 forever).
        let s = SystemLoadSensor::new();
        const N: u64 = 100;
        for _ in 0..N {
            s.install_for_test(0.5, 0.5);
        }
        assert_eq!(s.samples_total(), N,
            "samples_total monotonic +1 per install — N installs -> N");

        // f64 bit-cast round-trip through AtomicU64 (lossless for
        // non-NaN values per IEEE 754). Pins that install stores the
        // EXACT bit pattern (no quantization, no f32 down-cast).
        let s = SystemLoadSensor::new();
        let tricky_values: [f64; 6] = [
            0.0,
            -0.0,
            1.0,
            f64::MIN_POSITIVE,
            f64::MAX,
            std::f64::consts::PI,
        ];
        for v in tricky_values {
            let cores = f64::from(s.cores());
            s.install_for_test(v, v);
            // load_1m reads back exact bit pattern (no NaN involved).
            assert_eq!(s.load_1m().to_bits(), v.to_bits(),
                "load_1m: f64 bit-cast round-trip lossless for {v}");
            assert_eq!(s.cpu_fraction().to_bits(), v.to_bits(),
                "cpu_fraction: f64 bit-cast round-trip lossless for {v}");
            // normalized = load_1m / cores formula pin.
            let expected_norm = v / cores;
            assert_eq!(s.normalized_load().to_bits(), expected_norm.to_bits(),
                "normalized_load == load_1m / cores exact for v={v}");
        }
    }

    #[test]
    fn batch_b_is_busy_strict_gt_boundary_matrix_on_both_or_gates() {
        // is_busy() is `normalized > NORMALIZED_BUSY_LOAD OR cpu > budget`
        // where budget = CPU_BUSY_FRACTION * cores. Both comparisons are
        // STRICT >. Pinning the boundary matrix catches a > vs >= drift.
        let s = SystemLoadSensor::new();
        let cores = f64::from(s.cores());

        // GATE 1: normalized = load_1m / cores. Boundary at NORMALIZED_BUSY_LOAD.
        // Load that makes normalized == NORMALIZED_BUSY_LOAD exact (NOT busy).
        let boundary_load = NORMALIZED_BUSY_LOAD * cores;
        s.install_for_test(boundary_load, 0.0);
        assert!((s.normalized_load() - NORMALIZED_BUSY_LOAD).abs() < 1e-12,
            "test premise: normalized == NORMALIZED_BUSY_LOAD exact");
        assert!(!s.is_busy(),
            "at exact normalized boundary (== 0.8) — NOT busy (strict > check)");

        // Just above boundary — IS busy.
        let just_above = (NORMALIZED_BUSY_LOAD + 1e-9) * cores;
        s.install_for_test(just_above, 0.0);
        assert!(s.is_busy(),
            "just above normalized boundary (0.8 + eps) — IS busy");

        // GATE 2: cpu > CPU_BUSY_FRACTION * cores. Boundary at budget exact.
        let cpu_budget = CPU_BUSY_FRACTION * cores;
        s.install_for_test(0.0, cpu_budget);
        assert!(!s.is_busy(),
            "at exact CPU budget boundary — NOT busy (strict > check)");

        // Just above CPU budget — IS busy.
        s.install_for_test(0.0, cpu_budget + 1e-9);
        assert!(s.is_busy(),
            "just above CPU budget (budget + eps) — IS busy");

        // OR semantics: either gate alone trips the predicate.
        // Already proved with single-axis tests above. Now joint trip.
        s.install_for_test(just_above, cpu_budget + 1e-9);
        assert!(s.is_busy(),
            "both gates above — IS busy (OR)");

        // Zero install — NOT busy.
        s.install_for_test(0.0, 0.0);
        assert!(!s.is_busy(),
            "all zeros — NOT busy");

        // CPU budget scales with cores. Test premise: doubling load
        // input doubles the normalized value (formula = load_1m / cores).
        // If we install load such that load_1m / cores > NORMALIZED_BUSY_LOAD,
        // is_busy fires regardless of cores count.
        s.install_for_test(2.0 * cores, 0.0); // normalized = 2.0
        assert!(s.is_busy());
    }

    #[test]
    fn batch_b_is_saturated_and_semantics_strict_gt_at_1_5_and_cores_boundaries() {
        // is_saturated() is `normalized > 1.5 AND cpu > cores` — both
        // strict >. The hard-coded 1.5 (not via NORMALIZED_BUSY_LOAD)
        // and the hard-coded cores-comparison are load-bearing.
        let s = SystemLoadSensor::new();
        let cores = f64::from(s.cores());

        // BOTH BELOW: NOT saturated.
        s.install_for_test(0.0, 0.0);
        assert!(!s.is_saturated());

        // LOAD ABOVE, CPU AT or below cores: NOT saturated (cpu gate fails).
        let high_load = 2.0 * cores; // normalized 2.0 > 1.5
        s.install_for_test(high_load, cores); // cpu == cores (NOT > cores)
        assert!(s.normalized_load() > 1.5,
            "test premise: normalized > 1.5");
        assert_eq!(s.cpu_fraction(), cores,
            "test premise: cpu == cores exactly");
        assert!(!s.is_saturated(),
            "cpu at exact cores boundary (not > cores) — NOT saturated");

        // LOAD AT 1.5 boundary, CPU above cores: NOT saturated (load gate fails strict).
        let boundary_load = 1.5 * cores; // normalized == 1.5 exact
        let high_cpu = cores + 0.5;
        s.install_for_test(boundary_load, high_cpu);
        assert!((s.normalized_load() - 1.5).abs() < 1e-12,
            "test premise: normalized == 1.5 exact");
        assert!(s.cpu_fraction() > cores,
            "test premise: cpu > cores");
        assert!(!s.is_saturated(),
            "normalized at exact 1.5 boundary (not > 1.5) — NOT saturated");

        // BOTH JUST ABOVE: saturated.
        let just_above_load = (1.5 + 1e-9) * cores;
        let just_above_cpu = cores + 1e-9;
        s.install_for_test(just_above_load, just_above_cpu);
        assert!(s.is_saturated(),
            "both gates just above thresholds — saturated");

        // BOTH WELL ABOVE: saturated (2-vCPU catch-up pattern).
        s.install_for_test(3.0 * cores, cores + 1.0);
        assert!(s.is_saturated());

        // is_saturated implies is_busy (saturation is strictly worse).
        s.install_for_test(3.0 * cores, cores + 1.0);
        assert!(s.is_saturated());
        assert!(s.is_busy(),
            "saturated implies busy (1.5 > NORMALIZED_BUSY_LOAD=0.8, so load gate trips)");

        // is_busy does NOT imply is_saturated (busy at normalized=0.9 is NOT saturated).
        s.install_for_test(0.9 * cores, 0.0);
        assert!(s.is_busy());
        assert!(!s.is_saturated(),
            "busy at 0.9 normalized is NOT saturated (< 1.5)");
    }

    #[test]
    fn batch_b_cpu_fraction_arithmetic_surface_zero_delta_saturating_sub_and_scaling() {
        // cpu_fraction(prev, now) is pure arithmetic:
        //   total_d = now.total.saturating_sub(prev.total)
        //   idle_d  = now.idle.saturating_sub(prev.idle)
        //   if total_d == 0 -> 0.0 (divide-by-zero guard)
        //   busy_d = total_d.saturating_sub(idle_d)
        //   (busy_d / total_d) * num_cpus_on_host()
        //
        // Pins: zero-delta returns 0, saturating_sub never panics on
        // counter wraparound, busy/total ratio scales with cores.

        let cores = f64::from(num_cpus_on_host());

        // Zero-delta (prev == now) — total_d=0 → 0.0.
        let p = CpuTotals { total: 1000, idle: 400 };
        assert_eq!(cpu_fraction(p, p), 0.0,
            "prev == now -> zero delta -> 0.0 (divide-by-zero guard)");

        // total_d=0 specifically (idle changed but total didn't — impossible
        // physically but the function must not panic): same totals -> 0.
        let p = CpuTotals { total: 100, idle: 50 };
        let n = CpuTotals { total: 100, idle: 60 };
        assert_eq!(cpu_fraction(p, n), 0.0,
            "total_d=0 -> 0.0 regardless of idle delta");

        // Counter-wrap: now.total < prev.total (counter reset/wrap).
        // saturating_sub clamps to 0 -> total_d=0 -> 0.0. No panic.
        let p = CpuTotals { total: 2000, idle: 800 };
        let n = CpuTotals { total: 1000, idle: 500 }; // backwards
        assert_eq!(cpu_fraction(p, n), 0.0,
            "now.total < prev.total (counter wrap) -> 0.0, no panic");

        // 0% busy: idle_d == total_d (all delta was idle).
        let p = CpuTotals { total: 0, idle: 0 };
        let n = CpuTotals { total: 100, idle: 100 };
        assert_eq!(cpu_fraction(p, n), 0.0,
            "100% idle delta -> 0.0 fraction");

        // 100% busy: idle_d == 0 (no idle delta).
        let p = CpuTotals { total: 0, idle: 0 };
        let n = CpuTotals { total: 100, idle: 0 };
        let frac = cpu_fraction(p, n);
        // (100 - 0) / 100 * cores = 1.0 * cores
        assert!((frac - 1.0 * cores).abs() < 1e-9,
            "100% busy delta -> 1.0 * cores = {cores}, got {frac}");

        // 50% busy: idle_d = total_d / 2.
        let p = CpuTotals { total: 0, idle: 0 };
        let n = CpuTotals { total: 100, idle: 50 };
        let frac = cpu_fraction(p, n);
        assert!((frac - 0.5 * cores).abs() < 1e-9,
            "50% busy delta -> 0.5 * cores = {}, got {frac}", 0.5 * cores);

        // 75% busy: 75/100 total, 25/100 idle.
        let p = CpuTotals { total: 0, idle: 0 };
        let n = CpuTotals { total: 100, idle: 25 };
        let frac = cpu_fraction(p, n);
        assert!((frac - 0.75 * cores).abs() < 1e-9,
            "75% busy delta -> 0.75 * cores");

        // Scaling pin: doubling cores doubles output for same fraction.
        // Already implicit but make explicit — sign-check the formula
        // (busy_d / total_d) * cores is multiplicative on cores.
        let frac1 = cpu_fraction(
            CpuTotals { total: 0, idle: 0 },
            CpuTotals { total: 200, idle: 100 },
        );
        let frac2 = cpu_fraction(
            CpuTotals { total: 0, idle: 0 },
            CpuTotals { total: 400, idle: 200 },
        );
        // Both 50% busy — should produce identical output regardless of
        // absolute counter magnitude (busy/total ratio is invariant).
        assert!((frac1 - frac2).abs() < 1e-12,
            "cpu_fraction depends on ratio, not absolute counts");

        // Idle saturating_sub: if now.idle < prev.idle (idle counter
        // appears to go backwards while total advances), idle_d=0 and
        // busy_d = total_d -> 100% busy output (cores * 1.0).
        let p = CpuTotals { total: 100, idle: 50 };
        let n = CpuTotals { total: 200, idle: 30 }; // idle went DOWN
        let frac = cpu_fraction(p, n);
        // total_d=100, idle_d=saturating_sub(30, 50)=0, busy_d=100.
        // Output = (100/100) * cores = cores.
        assert!((frac - cores).abs() < 1e-9,
            "now.idle < prev.idle -> idle_d=0 via saturating_sub -> 100% busy = cores");

        // CpuTotals Copy semantics — function takes them by value.
        let p = CpuTotals { total: 1000, idle: 400 };
        let _f1 = cpu_fraction(p, p);
        let _f2 = cpu_fraction(p, p); // p still usable -> Copy derived
        let _ = p.total; // still readable
    }
}
