//! Lifecycle-loop supervision (verdict internal design notes).
//!
//! The node spawns ~20+ long-lived lifecycle loops as detached tokio tasks; a
//! panic in any one silently kills that subsystem while `/health` stays green.
//! This module is the audited fix (design A+C):
//!
//! - [`spawn_supervised`] — restart a loop on PANIC ONLY (`JoinError::is_panic`),
//!   with capped exponential backoff (mirrors `seed_reconnect_loop`: 1→2→4→8→15min)
//!   and a crash-loop ceiling after which the loop is marked [`LoopState::Dead`]
//!   and NOT restarted (page). A CLEAN exit (`Ok(())`) is NEVER auto-restarted —
//!   many loops legitimately return by design (config/role-disabled, or shutdown).
//!   Shutdown-aware: an `Arc<AtomicBool>` shutting-down flag, checked before every
//!   restart, so an intentional teardown never triggers a restart.
//! - [`LoopRegistry`]/[`LoopStatus`] — a per-loop liveness registry (last-tick +
//!   state) so `/health` catches both PANIC (via the supervisor) and HANG (a
//!   deadlocked task never resolves its JoinHandle, so `is_panic` supervision
//!   alone is blind to it — the staleness check is the only thing that sees it).
//!
//! WIRING IS A SEPARATE STEP: this module is self-contained + unit-tested; the
//! boot-path wiring (wave-1 = the SAFE no-channel prune loops), the 11-loop
//! `mpsc::Receiver` → `tokio::sync::watch` migration, and the `epoch_seal_loop`
//! raw-lock fix all land in follow-up PRs per the verdict. `epoch_seal_loop` must
//! NOT be blind-supervised (a restart double-proposes a seal → 25% auto-slash).

use std::future::Future;
use std::sync::atomic::{AtomicU64, AtomicU8, AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::network::state::mono_secs;

/// Crash-loop ceiling: after this many CONSECUTIVE panics (with no intervening
/// stable run), stop restarting and mark [`LoopState::Dead`].
pub const CRASH_LOOP_CEILING: u64 = 8;

/// A supervised loop that runs stably for at least this long before panicking has
/// its consecutive-panic counter reset — an occasional panic (once a day) must
/// never accumulate into a false crash-loop DEAD.
pub const STABLE_RUN_RESET_SECS: u64 = 300;

/// Backoff (seconds) before restart attempt `n` (1-based): 60·2^(n-1) capped at
/// 900s (15min) — the same shape as `seed_reconnect_loop` (discovery.rs:1175).
pub fn backoff_secs(consecutive_panics: u64) -> u64 {
    let n = consecutive_panics.saturating_sub(1).min(4); // cap the shift at 2^4=16 → 960→cap
    (60u64.saturating_mul(1u64 << n)).min(900)
}

/// Per-loop liveness state, surfaced on `/health` and as a metric gauge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LoopState {
    /// Ticking within its expected interval.
    Running = 0,
    /// Alive but no heartbeat within the staleness threshold — hung or wedged.
    Stale = 1,
    /// Crash-loop ceiling hit; the supervisor stopped restarting. PAGE.
    Dead = 2,
    /// Cleanly exited by design (config/role-disabled) — never a fault.
    Disabled = 3,
}

impl LoopState {
    fn from_u8(v: u8) -> Self {
        match v {
            1 => LoopState::Stale,
            2 => LoopState::Dead,
            3 => LoopState::Disabled,
            _ => LoopState::Running,
        }
    }

    /// Stable wire label for `/health` JSON + Prometheus.
    pub fn as_str(&self) -> &'static str {
        match self {
            LoopState::Running => "running",
            LoopState::Stale => "stale",
            LoopState::Dead => "dead",
            LoopState::Disabled => "disabled",
        }
    }
}

/// One supervised loop's live status. Shared (`Arc`) between the supervisor and
/// the loop body (which calls [`Self::heartbeat`] at the top of each iteration).
pub struct LoopStatus {
    pub name: &'static str,
    /// `mono_secs()` at the last heartbeat; 0 = never ticked.
    last_tick_mono: AtomicU64,
    /// Total panic-restarts over the process lifetime.
    restarts: AtomicU64,
    /// Current [`LoopState`] as a u8.
    state: AtomicU8,
    /// Staleness threshold (seconds). A loop whose last heartbeat is older than
    /// this reads [`LoopState::Stale`]. Should be ~3-4× the loop's own interval.
    stale_after_secs: u64,
}

impl LoopStatus {
    fn new(name: &'static str, stale_after_secs: u64) -> Self {
        Self {
            name,
            last_tick_mono: AtomicU64::new(0),
            restarts: AtomicU64::new(0),
            state: AtomicU8::new(LoopState::Running as u8),
            stale_after_secs,
        }
    }

    /// Called by the supervised loop at the TOP of each iteration — right after
    /// its `select!`/`interval.tick()` wakes and BEFORE any `continue`-guard — so
    /// an idle loop (a quiet-testnet `epoch_seal_loop` that does no work this tick)
    /// still stamps liveness and never reads as dead.
    pub fn heartbeat(&self) {
        // Store mono_secs()+1 (the in-tree convention, cf. last_inbound_sync_mono):
        // mono_secs() can legitimately be 0 in the first second of process life, so
        // 0 must mean "never ticked", not "ticked at t=0".
        self.last_tick_mono.store(mono_secs() + 1, Ordering::Relaxed);
        // A heartbeat means the loop is alive; clear any prior Stale/Disabled.
        self.state.store(LoopState::Running as u8, Ordering::Relaxed);
    }

    /// Mark the loop cleanly self-disqualified (config/role-disabled clean exit).
    fn set_disabled(&self) {
        self.state.store(LoopState::Disabled as u8, Ordering::Relaxed);
    }

    fn set_dead(&self) {
        self.state.store(LoopState::Dead as u8, Ordering::Relaxed);
    }

    fn record_restart(&self) {
        self.restarts.fetch_add(1, Ordering::Relaxed);
    }

    pub fn restart_count(&self) -> u64 {
        self.restarts.load(Ordering::Relaxed)
    }

    /// The loop's live state, folding in staleness: a `Running` loop whose last
    /// heartbeat is older than `stale_after_secs` is reported `Stale` (catches
    /// HANGS the panic-supervisor can't see). `Dead`/`Disabled` are sticky.
    pub fn state(&self) -> LoopState {
        let base = LoopState::from_u8(self.state.load(Ordering::Relaxed));
        if base != LoopState::Running {
            return base; // Dead/Disabled/Stale-already are terminal-ish; don't override
        }
        let last = self.last_tick_mono.load(Ordering::Relaxed);
        if last == 0 {
            return LoopState::Running; // just spawned, hasn't ticked yet — not stale
        }
        // `last` is mono_secs()+1, so age = (now+1) - last (see heartbeat()).
        if (mono_secs() + 1).saturating_sub(last) > self.stale_after_secs {
            LoopState::Stale
        } else {
            LoopState::Running
        }
    }

    /// Seconds since the last heartbeat (`None` if never ticked).
    pub fn last_tick_age_secs(&self) -> Option<u64> {
        let last = self.last_tick_mono.load(Ordering::Relaxed);
        if last == 0 {
            None
        } else {
            Some((mono_secs() + 1).saturating_sub(last))
        }
    }
}

/// Registry of all supervised loops. Held in an `Arc` on `NodeState`; queried by
/// `/health` and the `/metrics` surface. Registration happens once at boot.
#[derive(Default)]
pub struct LoopRegistry {
    loops: Mutex<Vec<Arc<LoopStatus>>>,
}

impl LoopRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a loop; returns its shared [`LoopStatus`] (hand one clone to
    /// [`spawn_supervised`], keep another for the loop body's `heartbeat()`).
    pub fn register(&self, name: &'static str, stale_after_secs: u64) -> Arc<LoopStatus> {
        let status = Arc::new(LoopStatus::new(name, stale_after_secs));
        self.loops
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(status.clone());
        status
    }

    /// Snapshot for `/health` / `/metrics`: `(name, state, last_tick_age, restarts)`.
    pub fn snapshot(&self) -> Vec<(&'static str, LoopState, Option<u64>, u64)> {
        self.loops
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|s| (s.name, s.state(), s.last_tick_age_secs(), s.restart_count()))
            .collect()
    }

    /// True iff any registered loop is `Dead` or `Stale` (the `/health` degraded
    /// signal — a subsystem silently died or hung).
    pub fn any_degraded(&self) -> bool {
        self.loops
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .any(|s| matches!(s.state(), LoopState::Dead | LoopState::Stale))
    }

    /// Compact JSON for the `/health` `supervised_loops` field: one object per
    /// loop with `{name, state, last_tick_age_secs, restarts}`. The wave-1 wiring
    /// folds `any_degraded()` into the overall readiness level.
    pub fn render_health_json(&self) -> serde_json::Value {
        let rows: Vec<serde_json::Value> = self
            .snapshot()
            .into_iter()
            .map(|(name, state, age, restarts)| {
                serde_json::json!({
                    "name": name,
                    "state": state.as_str(),
                    "last_tick_age_secs": age,
                    "restarts": restarts,
                })
            })
            .collect();
        serde_json::json!(rows)
    }

    /// Prometheus text for the loop-supervision metrics. `elara_loop_state`
    /// (0=running/1=stale/2=dead/3=disabled — a sustained 2 pages),
    /// `elara_loop_restarts_total` (panic-restarts), and
    /// `elara_loop_last_tick_age_seconds` (staleness — catches hangs). The loop
    /// name is a bounded, code-fixed label (the ~20 lifecycle loops), so no
    /// cardinality blowup. Empty until the wave-1 wiring registers loops.
    pub fn render_prometheus(&self) -> String {
        let snap = self.snapshot();
        let mut out = String::with_capacity(64 + snap.len() * 200);
        out.push_str(
            "# HELP elara_loop_state Supervised lifecycle-loop state (0=running,1=stale,2=dead,3=disabled). Sustained 2 = a subsystem silently died — page.\n\
             # TYPE elara_loop_state gauge\n",
        );
        for (name, state, _age, _restarts) in &snap {
            out.push_str(&format!(
                "elara_loop_state{{loop=\"{name}\"}} {}\n",
                *state as u8
            ));
        }
        out.push_str(
            "# HELP elara_loop_restarts_total Panic-restarts of a supervised lifecycle loop.\n\
             # TYPE elara_loop_restarts_total counter\n",
        );
        for (name, _state, _age, restarts) in &snap {
            out.push_str(&format!(
                "elara_loop_restarts_total{{loop=\"{name}\"}} {restarts}\n"
            ));
        }
        out.push_str(
            "# HELP elara_loop_last_tick_age_seconds Seconds since a supervised loop last stamped a heartbeat (catches HANGS the panic path can't see). -1 = never ticked yet.\n\
             # TYPE elara_loop_last_tick_age_seconds gauge\n",
        );
        for (name, _state, age, _restarts) in &snap {
            let v = age.map(|a| a as i64).unwrap_or(-1);
            out.push_str(&format!(
                "elara_loop_last_tick_age_seconds{{loop=\"{name}\"}} {v}\n"
            ));
        }
        out
    }
}

/// Spawn a lifecycle loop under supervision. `fut_factory` re-creates the loop
/// future on each restart (so it MUST close over only re-mintable state — clone
/// `Arc<NodeState>` etc.; a loop taking a single-use `mpsc::Receiver` cannot be
/// supervised until migrated to a cloneable signal — verdict prerequisite).
///
/// Restart policy: PANIC only, capped backoff, crash-loop ceiling → `Dead`. A
/// clean `Ok(())` exit is `Disabled`, never restarted. `shutting_down` short-
/// circuits every restart so teardown never resurrects a loop.
pub fn spawn_supervised<F, Fut>(
    status: Arc<LoopStatus>,
    shutting_down: Arc<AtomicBool>,
    fut_factory: F,
) -> tokio::task::JoinHandle<()>
where
    F: Fn() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        let mut consecutive_panics: u64 = 0;
        loop {
            if shutting_down.load(Ordering::Relaxed) {
                return;
            }
            let started = mono_secs();
            // Run the loop as a child task so its panic is observable via the
            // JoinHandle (tokio wraps every task poll in catch_unwind → is_panic).
            let child = tokio::spawn(fut_factory());
            match child.await {
                Ok(()) => {
                    // Clean exit — the loop returned by design. NEVER restart.
                    if !shutting_down.load(Ordering::Relaxed) {
                        status.set_disabled();
                        tracing::info!(
                            "supervised loop '{}' exited cleanly (config/role-disabled or shutdown) — not restarting",
                            status.name
                        );
                    }
                    return;
                }
                Err(e) if e.is_panic() => {
                    if shutting_down.load(Ordering::Relaxed) {
                        return;
                    }
                    // A stable run before the panic resets the crash-loop counter —
                    // an occasional panic must not accumulate into a false DEAD.
                    if mono_secs().saturating_sub(started) >= STABLE_RUN_RESET_SECS {
                        consecutive_panics = 0;
                    }
                    consecutive_panics += 1;
                    status.record_restart();
                    if consecutive_panics >= CRASH_LOOP_CEILING {
                        status.set_dead();
                        tracing::error!(
                            "supervised loop '{}' PANICKED {} consecutive times — crash-loop ceiling hit, marking DEAD (page); NOT restarting",
                            status.name,
                            consecutive_panics
                        );
                        return;
                    }
                    let backoff = backoff_secs(consecutive_panics);
                    tracing::error!(
                        "supervised loop '{}' panicked (attempt {}/{}) — restarting in {}s",
                        status.name,
                        consecutive_panics,
                        CRASH_LOOP_CEILING,
                        backoff
                    );
                    tokio::time::sleep(Duration::from_secs(backoff)).await;
                }
                Err(_cancelled) => {
                    // Task aborted (shutdown teardown) — do not restart.
                    return;
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pins the two watch-shutdown properties the mpsc→watch loop migration relies
    // on: (1) a fresh receiver's `changed()` WAITS for a signal (does NOT fire on the
    // initial value — else every migrated loop would exit on its first select! poll),
    // and (2) dropping the last sender fires `changed()` with Err (the teardown-drop
    // path that replaces mpsc `recv()`→None). Verify-not-assume before the sweep.
    #[tokio::test(start_paused = true)]
    async fn watch_changed_waits_then_fires_on_drop() {
        let (tx, mut rx) = tokio::sync::watch::channel(());
        // (1) must NOT fire immediately:
        tokio::select! {
            _ = rx.changed() => panic!("watch changed() fired on the initial value — would kill every loop at boot"),
            _ = tokio::time::sleep(Duration::from_secs(1)) => {} // expected path
        }
        // (2) dropping the sole sender fires changed() → Err (shutdown signalled):
        drop(tx);
        assert!(rx.changed().await.is_err(), "changed() after sender drop must return Err");
    }

    #[test]
    fn backoff_matches_seed_reconnect_shape() {
        // 1min → 2min → 4min → 8min → 15min cap.
        assert_eq!(backoff_secs(1), 60);
        assert_eq!(backoff_secs(2), 120);
        assert_eq!(backoff_secs(3), 240);
        assert_eq!(backoff_secs(4), 480);
        assert_eq!(backoff_secs(5), 900); // 960 capped to 900
        assert_eq!(backoff_secs(50), 900); // stays capped
    }

    #[test]
    fn state_folds_in_staleness_and_stickiness() {
        let s = LoopStatus::new("t", 2);
        assert_eq!(s.state(), LoopState::Running); // never ticked, just spawned
        s.heartbeat();
        assert_eq!(s.state(), LoopState::Running);
        assert!(s.last_tick_age_secs().is_some());
        // Dead is sticky (doesn't get overridden by a fresh-looking tick check).
        s.set_dead();
        assert_eq!(s.state(), LoopState::Dead);
        // A heartbeat clears it back to Running (a re-registered/recovered loop).
        s.heartbeat();
        assert_eq!(s.state(), LoopState::Running);
    }

    #[test]
    fn registry_registers_and_snapshots() {
        let reg = LoopRegistry::new();
        let a = reg.register("alpha", 60);
        let _b = reg.register("beta", 60);
        a.heartbeat();
        let snap = reg.snapshot();
        assert_eq!(snap.len(), 2);
        assert!(snap.iter().any(|(n, st, _, _)| *n == "alpha" && *st == LoopState::Running));
        assert!(!reg.any_degraded());
        a.set_dead();
        assert!(reg.any_degraded());
    }

    #[test]
    fn renderers_produce_health_json_and_prometheus() {
        let reg = LoopRegistry::new();
        let a = reg.register("prune_a", 60);
        let b = reg.register("prune_b", 60);
        a.heartbeat(); // running + ticked
        b.set_dead(); // dead (never ticked)

        // /health JSON: one row per loop, correct state labels.
        let j = reg.render_health_json();
        let rows = j.as_array().expect("array");
        assert_eq!(rows.len(), 2);
        let ra = rows.iter().find(|r| r["name"] == "prune_a").unwrap();
        assert_eq!(ra["state"], serde_json::json!("running"));
        assert!(ra["last_tick_age_secs"].is_number());
        let rb = rows.iter().find(|r| r["name"] == "prune_b").unwrap();
        assert_eq!(rb["state"], serde_json::json!("dead"));
        assert_eq!(rb["last_tick_age_secs"], serde_json::Value::Null); // never ticked

        // Prometheus: the three metric families + correct state values + never=-1.
        let p = reg.render_prometheus();
        assert!(p.contains("elara_loop_state{loop=\"prune_a\"} 0")); // running
        assert!(p.contains("elara_loop_state{loop=\"prune_b\"} 2")); // dead
        assert!(p.contains("elara_loop_restarts_total{loop=\"prune_a\"} 0"));
        assert!(p.contains("elara_loop_last_tick_age_seconds{loop=\"prune_b\"} -1"));
        assert!(p.contains("# TYPE elara_loop_state gauge"));
    }

    #[tokio::test(start_paused = true)]
    async fn panics_are_restarted_then_stable() {
        // A loop that panics its first 2 iterations, then runs (sleeps) forever.
        let counter = Arc::new(AtomicU64::new(0));
        let status = Arc::new(LoopStatus::new("flaky", 3600));
        let shutting = Arc::new(AtomicBool::new(false));
        let c2 = counter.clone();
        let sup = spawn_supervised(status.clone(), shutting.clone(), move || {
            let c = c2.clone();
            async move {
                let n = c.fetch_add(1, Ordering::SeqCst);
                assert!(n >= 2, "flaky panic #{n}");
                // stable: run forever (until aborted)
                loop {
                    tokio::time::sleep(Duration::from_secs(3600)).await;
                }
            }
        });
        // Let the supervisor cycle through the 2 panics + their backoff sleeps.
        for _ in 0..6 {
            tokio::time::advance(Duration::from_secs(300)).await;
            tokio::task::yield_now().await;
        }
        assert_eq!(status.restart_count(), 2, "should have restarted exactly twice");
        assert!(counter.load(Ordering::SeqCst) >= 3, "third invocation (stable) ran");
        assert_ne!(status.state(), LoopState::Dead, "a recovered loop is not DEAD");
        // Teardown: signal shutdown + abort the supervisor.
        shutting.store(true, Ordering::Relaxed);
        sup.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn crash_loop_ceiling_marks_dead() {
        // A loop that panics forever hits the ceiling and stops restarting.
        let status = Arc::new(LoopStatus::new("doomed", 3600));
        let shutting = Arc::new(AtomicBool::new(false));
        let sup = spawn_supervised(status.clone(), shutting.clone(), || async {
            panic!("always");
        });
        for _ in 0..(CRASH_LOOP_CEILING + 4) {
            tokio::time::advance(Duration::from_secs(1000)).await; // > any backoff
            tokio::task::yield_now().await;
        }
        assert_eq!(status.state(), LoopState::Dead);
        // restart_count is bounded by the ceiling (no infinite spin).
        assert!(status.restart_count() <= CRASH_LOOP_CEILING);
        sup.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn clean_exit_is_not_restarted() {
        // A loop that returns Ok(()) immediately (config-disabled) → Disabled, once.
        let counter = Arc::new(AtomicU64::new(0));
        let status = Arc::new(LoopStatus::new("disabled", 3600));
        let shutting = Arc::new(AtomicBool::new(false));
        let c2 = counter.clone();
        let sup = spawn_supervised(status.clone(), shutting.clone(), move || {
            let c = c2.clone();
            async move {
                c.fetch_add(1, Ordering::SeqCst);
                // returns immediately — a legitimate config/role-disabled exit
            }
        });
        for _ in 0..4 {
            tokio::time::advance(Duration::from_secs(100)).await;
            tokio::task::yield_now().await;
        }
        assert_eq!(counter.load(Ordering::SeqCst), 1, "clean exit must NOT be restarted");
        assert_eq!(status.state(), LoopState::Disabled);
        assert_eq!(status.restart_count(), 0);
        sup.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_suppresses_restart() {
        // shutting_down set before a panic is observed → no restart.
        let status = Arc::new(LoopStatus::new("s", 3600));
        let shutting = Arc::new(AtomicBool::new(true)); // already shutting down
        let sup = spawn_supervised(status.clone(), shutting.clone(), || async {
            panic!("should not be restarted under shutdown");
        });
        for _ in 0..3 {
            tokio::time::advance(Duration::from_secs(100)).await;
            tokio::task::yield_now().await;
        }
        // The supervisor sees shutting_down first and returns without restarting.
        assert_eq!(status.restart_count(), 0);
        assert_ne!(status.state(), LoopState::Dead);
        sup.abort();
    }
}
