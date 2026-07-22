//! HTTP server — axum routes for the node API.

//!
//! Spec references:
//!   @spec Protocol §11.19
//!   @spec Protocol §3.2
//!
//! Handler functions are organized into route modules under `super::routes::`.
//! This file contains the router composition, shared types, middleware,
//! and helper functions used across route modules.

pub mod public_http;

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Instant;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::middleware;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::Router;
use tower_http::cors::{Any, CorsLayer};
use tracing::warn;

use crate::errors::ElaraError;
use crate::accounting::types::ParsedLedgerOp;

use super::gossip;
use super::state::NodeState;
use super::{LockRecover, RwLockRecover};

// ─── Error wrapper for axum ─────────────────────────────────────────────────

pub struct AppError(pub ElaraError);

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let status = match &self.0 {
            ElaraError::DuplicateRecord(_) => StatusCode::CONFLICT,
            ElaraError::RecordNotFound(_) => StatusCode::NOT_FOUND,
            ElaraError::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            ElaraError::Wire(_) => StatusCode::BAD_REQUEST,
            ElaraError::InvalidSignature => StatusCode::BAD_REQUEST,
            ElaraError::Ledger(_) => StatusCode::UNPROCESSABLE_ENTITY,
            ElaraError::Crypto(_) => StatusCode::BAD_REQUEST,
            ElaraError::MissingParent(_) => StatusCode::BAD_REQUEST,
            ElaraError::Address(_) => StatusCode::BAD_REQUEST,
            ElaraError::Dag(_) => StatusCode::BAD_REQUEST,
            ElaraError::Config(_) => StatusCode::BAD_REQUEST,
            ElaraError::Dispute(msg) if msg.contains("not found") => StatusCode::NOT_FOUND,
            ElaraError::Dispute(_) => StatusCode::BAD_REQUEST,
            ElaraError::Governance(msg) if msg.contains("not found") => StatusCode::NOT_FOUND,
            ElaraError::Governance(_) => StatusCode::BAD_REQUEST,
            // Storage errors that contain "Ledger error" are ledger validation failures, not crashes
            ElaraError::Storage(msg) if msg.contains("Ledger error") => StatusCode::UNPROCESSABLE_ENTITY,
            ElaraError::Storage(msg) if msg.contains("not found") => StatusCode::NOT_FOUND,
            // A transient decline (a not-yet-present durable dependency) is retryable,
            // not a client-malformed (400) or server-fault (500) condition: answer 503
            // so the submitter re-tries once the dependency lands (KR-3 S2 v4 slice-0).
            ElaraError::TransientReject(_) => StatusCode::SERVICE_UNAVAILABLE,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        // 4xx client errors describe the caller's own bad input (bad hex, unknown
        // id, bad signature) — echoing the Display detail is safe and useful. 5xx
        // are internal faults whose Display can carry RocksDB CF names, file paths,
        // or tokio internals; never echo those on a public surface — log the detail
        // server-side and return a generic body. `into_response` has no peer IP
        // here, so this is unconditional (not loopback-gated): an operator
        // debugging a 500 reads the node log, not the HTTP body.
        let body = if status.is_server_error() {
            warn!(error = %self.0, status = status.as_u16(), "internal server error (detail withheld from client body)");
            "internal server error".to_string()
        } else {
            self.0.to_string()
        };
        (status, body).into_response()
    }
}

impl From<ElaraError> for AppError {
    fn from(e: ElaraError) -> Self {
        Self(e)
    }
}

impl From<elara_record::RecordError> for AppError {
    fn from(e: elara_record::RecordError) -> Self {
        Self(e.into())
    }
}

// ─── Admin auth ─────────────────────────────────────────────────────────────

/// Tracks failed admin auth attempts per IP for brute-force protection.
/// After `MAX_ADMIN_FAILURES` failures within `ADMIN_LOCKOUT_WINDOW_SECS`,
/// the IP is blocked from admin endpoints for the remainder of the window.
struct AdminAuthTracker {
    /// Map of IP -> (failure_count, first_failure_time)
    failures: std::sync::Mutex<HashMap<IpAddr, (u32, Instant)>>,
}

/// Maximum failed admin auth attempts before an IP is locked out.
const MAX_ADMIN_FAILURES: u32 = 5;
/// Window in seconds for tracking failed admin auth attempts (5 minutes).
const ADMIN_LOCKOUT_WINDOW_SECS: u64 = 300;

/// Build-identity gauge. Compile-time constant string fed by `build.rs` env
/// vars (BUILD_GIT_SHA / BUILD_GIT_REF / BUILD_GIT_DIRTY / BUILD_TS_SECS).
/// Appended to the raw `/metrics` body, then tier-filtered: classified Debug in
/// `classify_metric` (loopback-only), so it reaches a local operator but is
/// dropped for non-loopback callers (P1 ceiling). git_sha is the PRIVATE-repo
/// HEAD — kept off the public plane to match the /version + /status build-
/// identity gates. Operator use (loopback; `?tier=debug` on a P0/P1 node):
/// compare `git_sha` across nodes to confirm uniform fleet version; flag
/// `git_dirty="1"` in prod; date a regression via `build_ts`.
const BUILD_INFO_METRIC: &str = concat!(
    "# HELP elara_build_info Build-identity gauge (always = 1). Labels: \
git_sha (full HEAD sha at build time), git_ref (branch/tag), \
git_dirty (0|1 — uncommitted changes in worktree at build time), \
build_ts (unix-seconds UTC of the cargo build). Operator use: confirm \
two nodes ran the same binary by comparing git_sha; flag a dev-binary \
in production via git_dirty=\"1\"; date a regression via build_ts.\n",
    "# TYPE elara_build_info gauge\n",
    "elara_build_info{git_sha=\"", env!("BUILD_GIT_SHA"),
    "\",git_ref=\"", env!("BUILD_GIT_REF"),
    "\",git_dirty=\"", env!("BUILD_GIT_DIRTY"),
    "\",build_ts=\"", env!("BUILD_TS_SECS"),
    "\"} 1\n",
);

impl AdminAuthTracker {
    fn new() -> Self {
        Self {
            failures: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Check if an IP is currently locked out. Returns true if blocked.
    fn is_locked_out(&self, ip: IpAddr) -> bool {
        let failures = self.failures.lock_recover();
        if let Some((count, first_failure)) = failures.get(&ip) {
            if first_failure.elapsed().as_secs() < ADMIN_LOCKOUT_WINDOW_SECS {
                return *count >= MAX_ADMIN_FAILURES;
            }
        }
        false
    }

    /// Record a failed admin auth attempt. Returns true if the IP is now locked out.
    fn record_failure(&self, ip: IpAddr) -> bool {
        let mut failures = self.failures.lock_recover();
        let now = Instant::now();

        // Periodic cleanup: evict stale entries before any borrow via entry()
        if failures.len() > 256 {
            failures.retain(|_, (_, first)| first.elapsed().as_secs() < ADMIN_LOCKOUT_WINDOW_SECS);
        }

        let (count, first_seen) = failures.entry(ip).or_insert((0, now));

        // Reset window if expired
        if first_seen.elapsed().as_secs() >= ADMIN_LOCKOUT_WINDOW_SECS {
            *count = 0;
            *first_seen = now;
        }

        *count += 1;
        *count >= MAX_ADMIN_FAILURES
    }

    /// Clear failures for an IP on successful auth so partial failures don't
    /// accumulate across legitimate operator sessions.
    fn clear(&self, ip: IpAddr) {
        self.failures.lock_recover().remove(&ip);
    }
}

/// Global admin auth failure tracker (lazy-initialized).
static ADMIN_AUTH_TRACKER: std::sync::OnceLock<AdminAuthTracker> = std::sync::OnceLock::new();

fn admin_auth_tracker() -> &'static AdminAuthTracker {
    ADMIN_AUTH_TRACKER.get_or_init(AdminAuthTracker::new)
}

/// Stage 4E.4: lazily-loaded Dilithium3 admin pubkey allowlist.
///
/// Sourced from `ELARA_ADMIN_PUBKEYS` env var (comma-separated hex pubkeys,
/// 1952 bytes each). Loaded once at first admin request and cached. An empty
/// allowlist means admin endpoints are locked — operators MUST provision at
/// least one pubkey (AUDIT-10 / PQ-R7: bearer fallback removed).
static ADMIN_PQ_ALLOWLIST: std::sync::OnceLock<Vec<Vec<u8>>> = std::sync::OnceLock::new();

/// Stage 4E.4: process-global nonce cache for PQ admin replay protection.
/// Bounded by [`crate::network::admin_pq_auth::NONCE_WINDOW_SECS`].
static ADMIN_PQ_NONCE_CACHE: std::sync::OnceLock<crate::network::admin_pq_auth::NonceCache> =
    std::sync::OnceLock::new();

fn admin_pq_allowlist() -> &'static Vec<Vec<u8>> {
    ADMIN_PQ_ALLOWLIST
        .get_or_init(crate::network::admin_pq_auth::load_allowlist_from_env)
}

fn admin_pq_nonce_cache() -> &'static crate::network::admin_pq_auth::NonceCache {
    ADMIN_PQ_NONCE_CACHE.get_or_init(crate::network::admin_pq_auth::NonceCache::new)
}

/// Verify admin endpoint access — **PQ-only** (AUDIT-10 / PQ-R7, 2026-04-24).
///
/// Client MUST send an `X-PQ-Admin` header carrying a Dilithium3 signature
/// over `(method, path, ts, nonce)`. Pubkey must be in `ELARA_ADMIN_PUBKEYS`
/// allowlist. Replay-protected by nonce cache. See `network::admin_pq_auth`
/// for the full wire spec.
///
/// Bearer fallback (`Authorization: Bearer`) was removed in PQ-R7: a shared
/// secret crossing the wire is harvest-now-decrypt-later fodder and conflicts
/// with the PQ-primary mandate. There is no downgrade path.
///
/// Also enforces: genesis-authority-only (unless `require_genesis=false`),
/// brute-force lockout after 5 failed attempts in 5 min, TLS warning.
pub(crate) fn verify_admin_auth_pq(
    state: &NodeState,
    method: &str,
    uri: &Uri,
    headers: &HeaderMap,
) -> Result<(), AppError> {
    verify_admin_auth_inner(state, method, uri, headers, true)
}

/// PQ-R7 variant for admin endpoints that are not genesis-authority-gated
/// (e.g. `/admin/memory` — must work on every node). Same PQ requirement,
/// same allowlist, same nonce protection — only the genesis check is skipped.
pub(crate) fn verify_admin_auth_pq_any_node(
    state: &NodeState,
    method: &str,
    uri: &Uri,
    headers: &HeaderMap,
) -> Result<(), AppError> {
    verify_admin_auth_inner(state, method, uri, headers, false)
}

fn verify_admin_auth_inner(
    state: &NodeState,
    method: &str,
    uri: &Uri,
    headers: &HeaderMap,
    require_genesis: bool,
) -> Result<(), AppError> {
    // V2: bind the full origin-form request target (path + `?query`), not the
    // bare path — so an on-path attacker cannot race a captured header with a
    // substituted query string. Derived once here from the exact received URI;
    // `uri.query()` returns the raw wire bytes (no decode/reorder).
    let request_target =
        crate::network::admin_pq_auth::request_target_from_parts(uri.path(), uri.query());
    // Extract client IP for rate limiting.
    let client_ip = if !state.config.trusted_proxy_ips.is_empty() {
        headers
            .get("x-real-ip")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse::<IpAddr>().ok())
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)))
    } else {
        IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0))
    };

    // Check if IP is locked out from too many failed attempts
    if admin_auth_tracker().is_locked_out(client_ip) {
        warn!(ip = %client_ip, "admin auth: IP locked out after {} failed attempts in {}s",
              MAX_ADMIN_FAILURES, ADMIN_LOCKOUT_WINDOW_SECS);
        return Err(ElaraError::Ledger(
            "admin endpoint: too many failed authentication attempts — try again later".into(),
        ).into());
    }

    // TLS is irrelevant for PQ admin auth — the Dilithium3 signature binds the
    // header contents so plaintext transport cannot be replayed or forged. Kept
    // warning removed (bearer removal in PQ-R7 closed the credential-in-cleartext
    // concern that motivated the warning).

    // Genesis authority gate — skipped for endpoints like /admin/memory that
    // must work on every node.
    if require_genesis && state.identity.identity_hash != state.config.genesis_authority {
        return Err(ElaraError::Ledger("admin endpoint: genesis authority only".into()).into());
    }

    // ─── PQ admin auth (mandatory, PQ-R7) ──────────────────────────────────
    //
    // There is NO bearer fallback. Every admin request MUST carry a valid
    // X-PQ-Admin Dilithium3 header bound to this exact (method, path).

    let allowlist = admin_pq_allowlist();
    if allowlist.is_empty() {
        // No allowlist configured = admin surface is locked. Operators must
        // provision at least one pubkey via `ELARA_ADMIN_PUBKEYS`.
        return Err(ElaraError::Ledger(
            "admin endpoint: ELARA_ADMIN_PUBKEYS is not configured on this node — admin surface is locked".into(),
        ).into());
    }

    let pq_hdr_val = headers
        .get(crate::network::admin_pq_auth::HEADER_NAME)
        .ok_or_else(|| {
            admin_auth_tracker().record_failure(client_ip);
            ElaraError::Ledger(
                "admin endpoint: X-PQ-Admin header required (bearer auth removed in PQ-R7)".into(),
            )
        })?;

    let header_str = pq_hdr_val.to_str().map_err(|_| {
        admin_auth_tracker().record_failure(client_ip);
        ElaraError::Ledger("admin endpoint: X-PQ-Admin header not utf-8".into())
    })?;

    match crate::network::admin_pq_auth::verify_admin_request(
        header_str,
        method,
        &request_target,
        allowlist,
        admin_pq_nonce_cache(),
        crate::network::admin_pq_auth::now_unix_secs(),
    ) {
        Ok(pubkey_hex) => {
            admin_auth_tracker().clear(client_ip);
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs_f64())
                .unwrap_or(0.0);
            let pk_prefix = if pubkey_hex.len() >= 16 {
                format!("pq:{}...", &pubkey_hex[..16])
            } else {
                "pq:***".to_string()
            };
            if let Ok(mut log) = state.admin_audit_log.lock() {
                log.push((now, client_ip.to_string(), "admin_auth_pq".to_string(), pk_prefix));
                let len = log.len();
                if len > 10_000 {
                    log.drain(..len - 5_000);
                }
            }
            Ok(())
        }
        Err(e) => {
            let locked = admin_auth_tracker().record_failure(client_ip);
            if locked {
                warn!(ip = %client_ip, "admin auth (PQ): IP now locked out after {} failed attempts", MAX_ADMIN_FAILURES);
            }
            Err(ElaraError::Ledger(format!("admin endpoint: PQ auth failed: {e}")).into())
        }
    }
}

/// Maximum request body size in bytes (2 MB).
///
/// Records: ~4KB metadata + content hash + signature ≈ 10KB max typical.
/// Delta sync: Bloom filter can be larger for big DAGs.
/// 2MB is generous while preventing abuse (multipart uploads, oversized payloads).
const MAX_REQUEST_BODY_BYTES: usize = 2 * 1024 * 1024;

/// Tighter body cap for the small account-command POST routes (`/rpc/*` and the
/// genesis faucet `/bootstrap/claim`).
///
/// Those handlers deserialize an untyped `serde_json::Value` from the request
/// body, and in axum the body extractor runs *before* the handler — so the
/// `Value` is fully materialized **before** `verify_rpc_auth` (or the faucet's
/// genesis-authority check) executes. `serde_json::Value` is the worst-case
/// decode amplifier (~10×: every JSON token becomes a ~24-byte enum node), so a
/// 2 MiB body of `[1,1,…]` balloons into ~20 MiB transient heap on a fully
/// **unauthenticated** request — a memory-pressure vector on a phone-tier node.
///
/// A legitimate account command is a handful of scalar fields (`{"to","amount",
/// "memo"}` ≈ a few hundred bytes, well under 4 KiB even with a long memo), so
/// 64 KiB leaves >16× headroom while denying the amplifier. This mirrors the
/// `pq_transport` peer-ingress caps (`MAX_LIST_REQUEST_BODY` / `MAX_EVENT_SUB_FILTER_BODY`)
/// — the HTTP twin of the same threat, treated consistently (network-first).
const MAX_RPC_BODY_BYTES: usize = 64 * 1024;

/// Body cap for `POST /transitions/propose`, sized to the largest *legitimate*
/// proposal rather than the 64 KiB [`MAX_RPC_BODY_BYTES`] tight cap.
///
/// Unlike the single-sig `/transitions/{id}/sig` and `/veto` routes, a proposal
/// carries `proposer_sigs: Vec<AnchorSig>` — up to `MAX_PROPOSER_SIGS` (32)
/// Dilithium3 signatures may be bundled upfront. Each `AnchorSig` serializes via
/// serde_json as a *number-array* (`dilithium3_sig: Vec<u8>` has no hex/base64
/// attr), so a single 3309-byte ML-DSA-65 sig is ~13 KiB of JSON worst-case; 32
/// of them plus the seal envelope is ~423 KiB. 512 KiB clears that with headroom
/// while staying 4× under the 2 MiB global [`MAX_REQUEST_BODY_BYTES`] — bounding
/// the pre-handler `Json<TransitionSeal>` parse, which materializes the full Vec
/// *before* `validate_structure` rejects `len > MAX_PROPOSER_SIGS`.
const MAX_TRANSITION_PROPOSE_BODY_BYTES: usize = 512 * 1024;

/// Body cap for `POST /slot-conflicts`, sized to the largest *legitimate*
/// `ConflictProof` rather than the 64 KiB [`MAX_RPC_BODY_BYTES`] tight cap.
///
/// `receive_conflict_proof` decodes `Json<ConflictProof>` pre-verification, and a
/// `ConflictProof` embeds **two** full `ValidationRecord`s (`record_a`,
/// `record_b`). Each record is bounded at [`crate::network::ingest::MAX_RECORD_BYTES`]
/// (64 KiB) *on the binary wire* — but that bound is enforced at `/records`
/// ingest, never re-checked on this path, so the cap must cover two max records.
/// A record's bulk fields (`signature`, `sphincs_signature` ≈ 17–30 KiB,
/// `creator_public_key`, `content_hash`, `zk_proof`) are `Vec<u8>` with no
/// hex/base64 serde attr, so they serialize as JSON *number-arrays* — a ~4×
/// worst-case expansion. Two 64 KiB-binary records → ~512 KiB of JSON plus the
/// envelope. 1 MiB doubles that legit worst-case while still halving the 2 MiB
/// global [`MAX_REQUEST_BODY_BYTES`] an unauthenticated peer could otherwise force
/// the `Json<ConflictProof>` parse to materialize before `verify()` runs.
const MAX_CONFLICT_PROOF_BODY_BYTES: usize = 1024 * 1024;

/// Per-path request-body ceiling for the early Content-Length reject in
/// [`rate_limit_middleware`]. Returns the tight [`MAX_RPC_BODY_BYTES`] for the
/// explicitly-enumerated small-command POST routes, else the global
/// [`MAX_REQUEST_BODY_BYTES`].
///
/// **Explicit allowlist, not a `/rpc/` prefix, on purpose:** the cap is opt-in
/// per route known to carry a tiny body. A future `/rpc/*` route that legitimately
/// needs a large body must NOT silently inherit the tight cap and start 413-ing
/// valid traffic — adding it here is a deliberate decision. Genuinely large-body
/// routes (delta-sync, snapshot pulls) keep the 2 MiB global cap here. (`/records`
/// & the other single-record ingest routes carry their own tight 64 KiB extractor
/// cap via `record_body_cap`; this Content-Length fast-path leaves them at the
/// global cap on purpose — the extractor is the load-bearing enforcement.)
fn small_command_body_cap(path: &str) -> usize {
    const SMALL_VALUE_POST_ROUTES: &[&str] = &[
        "/rpc/transfer",
        "/rpc/xzone_lock",
        "/rpc/xzone_claim",
        "/rpc/xzone_abort",
        "/rpc/stake",
        "/rpc/pool_fund",
        "/rpc/unstake",
        "/rpc/stamp",
        "/rpc/stamp-private",
        "/bootstrap/claim",
    ];
    if SMALL_VALUE_POST_ROUTES.contains(&path) {
        MAX_RPC_BODY_BYTES
    } else {
        MAX_REQUEST_BODY_BYTES
    }
}

// ─── Prometheus histogram ────────────────────────────────────────────────────

/// Lock-free Prometheus histogram with fixed buckets.
///
/// Uses atomic operations for concurrent recording without locks.
/// Bucket boundaries follow Prometheus conventions for HTTP latency.
pub struct Histogram {
    /// (upper_bound_seconds, cumulative_count)
    buckets: Vec<(f64, AtomicU64)>,
    /// Sum of all observations in microseconds (avoid f64 atomics).
    sum_micros: AtomicU64,
    /// Total number of observations.
    count: AtomicU64,
}

/// Standard Prometheus HTTP request duration buckets.
pub const LATENCY_BUCKETS: &[f64] = &[
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

impl Histogram {
    pub fn new(bucket_bounds: &[f64]) -> Self {
        let buckets = bucket_bounds
            .iter()
            .map(|&b| (b, AtomicU64::new(0)))
            .collect();
        Self {
            buckets,
            sum_micros: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    /// Record an observation (in seconds).
    pub fn observe(&self, value_secs: f64) {
        let micros = (value_secs * 1_000_000.0) as u64;
        self.sum_micros.fetch_add(micros, std::sync::atomic::Ordering::Relaxed);
        self.count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        for (bound, count) in &self.buckets {
            if value_secs <= *bound {
                count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }

    /// Format as Prometheus exposition text.
    pub fn to_prometheus(&self, name: &str, help: &str) -> String {
        let mut out = format!(
            "# HELP {name} {help}\n# TYPE {name} histogram\n"
        );
        for (bound, count) in &self.buckets {
            let c = count.load(std::sync::atomic::Ordering::Relaxed);
            out.push_str(&format!("{name}_bucket{{le=\"{bound}\"}} {c}\n"));
        }
        let total = self.count.load(std::sync::atomic::Ordering::Relaxed);
        out.push_str(&format!("{name}_bucket{{le=\"+Inf\"}} {total}\n"));
        let sum = self.sum_micros.load(std::sync::atomic::Ordering::Relaxed) as f64 / 1_000_000.0;
        out.push_str(&format!("{name}_sum {sum:.6}\n"));
        out.push_str(&format!("{name}_count {total}\n"));
        out
    }

    /// Format buckets/sum/count as Prometheus text with a custom label string
    /// (e.g. `route="/headers/from/{epoch}"`). Caller is responsible for
    /// emitting `# HELP` and `# TYPE` lines once per metric name.
    /// Used by `LabeledHistogram` to fold many per-label histograms under one
    /// metric name with cardinality bounded by registered axum routes.
    pub fn to_prometheus_with_labels(&self, name: &str, labels: &str) -> String {
        let mut out = String::new();
        for (bound, count) in &self.buckets {
            let c = count.load(std::sync::atomic::Ordering::Relaxed);
            out.push_str(&format!("{name}_bucket{{{labels},le=\"{bound}\"}} {c}\n"));
        }
        let total = self.count.load(std::sync::atomic::Ordering::Relaxed);
        out.push_str(&format!("{name}_bucket{{{labels},le=\"+Inf\"}} {total}\n"));
        let sum = self.sum_micros.load(std::sync::atomic::Ordering::Relaxed) as f64 / 1_000_000.0;
        out.push_str(&format!("{name}_sum{{{labels}}} {sum:.6}\n"));
        out.push_str(&format!("{name}_count{{{labels}}} {total}\n"));
        out
    }
}

// ─── Labeled histogram (per-route HTTP latency) ──────────────────────────────

/// Maximum distinct labels (routes) tracked by a `LabeledHistogram`.
///
/// Bounded for SCALE: a malformed or hostile client can never blow up
/// cardinality. Axum's `MatchedPath` returns the registered route pattern
/// (e.g. `/headers/from/{epoch}`) — not the instantiated URL — so the live
/// cardinality is bounded by the number of registered routes (~50 today).
/// `LABELED_HISTOGRAM_CAP` is set well above that ceiling. If exceeded
/// (e.g. via a future router refactor), overflow rolls into the `<overflow>`
/// label so observability degrades gracefully instead of blowing up memory.
pub const LABELED_HISTOGRAM_CAP: usize = 256;

/// Per-label Prometheus histogram. One inner `Histogram` per distinct label
/// value, lazily instantiated on first observation. Bounded by
/// `LABELED_HISTOGRAM_CAP`.
pub struct LabeledHistogram {
    by_label: std::sync::RwLock<HashMap<String, Histogram>>,
    bucket_bounds: &'static [f64],
    cap: usize,
}

impl LabeledHistogram {
    pub fn new(bucket_bounds: &'static [f64], cap: usize) -> Self {
        Self {
            by_label: std::sync::RwLock::new(HashMap::new()),
            bucket_bounds,
            cap,
        }
    }

    /// Record an observation under the given label.
    /// Fast path: read-lock + map lookup. Slow path: insert under write-lock
    /// (only the first time each label is seen).
    pub fn observe(&self, label: &str, value_secs: f64) {
        {
            let map = self.by_label.read_recover();
            if let Some(hist) = map.get(label) {
                hist.observe(value_secs);
                return;
            }
        }
        let mut map = self.by_label.write_recover();
        if let Some(hist) = map.get(label) {
            hist.observe(value_secs);
            return;
        }
        if map.len() >= self.cap {
            map.entry("<overflow>".to_string())
                .or_insert_with(|| Histogram::new(self.bucket_bounds))
                .observe(value_secs);
        } else {
            map.entry(label.to_string())
                .or_insert_with(|| Histogram::new(self.bucket_bounds))
                .observe(value_secs);
        }
    }

    /// Format all per-label histograms as Prometheus exposition text under one
    /// metric name. The `# HELP`/`# TYPE` preamble is emitted once at the top.
    pub fn to_prometheus(&self, name: &str, help: &str) -> String {
        let map = self.by_label.read_recover();
        let mut out = format!("# HELP {name} {help}\n# TYPE {name} histogram\n");
        for (label, hist) in map.iter() {
            // Prometheus label values need quote/backslash/newline escaped.
            let escaped = label
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('\n', "\\n");
            let labels = format!("route=\"{escaped}\"");
            out.push_str(&hist.to_prometheus_with_labels(name, &labels));
        }
        out
    }

    /// Number of distinct labels currently tracked. Surfaced via `/metrics`
    /// so operators can detect cardinality saturation before the overflow
    /// label kicks in.
    pub fn label_count(&self) -> usize {
        self.by_label.read_recover().len()
    }
}

// ─── Labeled counter (per-route × status-class) ──────────────────────────────

/// Per-`(route, status_class)` Prometheus counter. Companion to
/// `LabeledHistogram` — gives operators per-route success/error visibility.
/// Cardinality: bounded by `routes × 4 status_classes` (≤ 256 × 4 = 1024) and
/// further capped by `LABELED_HISTOGRAM_CAP`.
pub struct LabeledCounter {
    by_label: std::sync::RwLock<HashMap<String, AtomicU64>>,
    cap: usize,
}

impl LabeledCounter {
    pub fn new(cap: usize) -> Self {
        Self {
            by_label: std::sync::RwLock::new(HashMap::new()),
            cap,
        }
    }

    /// Bump counter for `(route, status_class)`. Status classes are the four
    /// HTTP families: `"2xx"`, `"3xx"`, `"4xx"`, `"5xx"`.
    pub fn inc(&self, route: &str, status_class: &'static str) {
        let key = format!("{route}|{status_class}");
        {
            let map = self.by_label.read_recover();
            if let Some(c) = map.get(&key) {
                c.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return;
            }
        }
        let mut map = self.by_label.write_recover();
        if let Some(c) = map.get(&key) {
            c.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return;
        }
        if map.len() >= self.cap {
            map.entry(format!("<overflow>|{status_class}"))
                .or_insert_with(|| AtomicU64::new(0))
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        } else {
            map.entry(key)
                .or_insert_with(|| AtomicU64::new(0))
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    pub fn to_prometheus(&self, name: &str, help: &str) -> String {
        let map = self.by_label.read_recover();
        let mut out = format!("# HELP {name} {help}\n# TYPE {name} counter\n");
        for (key, counter) in map.iter() {
            let (route, status_class) = key.split_once('|').unwrap_or((key.as_str(), "unknown"));
            let escaped_route = route
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('\n', "\\n");
            let val = counter.load(std::sync::atomic::Ordering::Relaxed);
            out.push_str(&format!(
                "{name}{{route=\"{escaped_route}\",status_class=\"{status_class}\"}} {val}\n"
            ));
        }
        out
    }

    pub fn label_count(&self) -> usize {
        self.by_label.read_recover().len()
    }
}

/// Map an HTTP status code into one of the four standard Prometheus status
/// classes. Centralized so middleware and tests stay consistent.
pub(crate) fn status_class_for(status: u16) -> &'static str {
    match status / 100 {
        2 => "2xx",
        3 => "3xx",
        4 => "4xx",
        5 => "5xx",
        _ => "other",
    }
}

// ─── Rate limiter ───────────────────────────────────────────────────────────

/// Per-IP token-bucket rate limiter with 1-minute windows and deny list.
pub struct RateLimiter {
    buckets: std::sync::Mutex<HashMap<IpAddr, (u32, Instant)>>,
    write_limit: u32,
    read_limit: u32,
    /// Total requests rejected with 429.
    pub rejected_total: AtomicU64,
    /// Denied IPs — immediately rejected with 403.
    denied: std::sync::Mutex<std::collections::HashSet<IpAddr>>,
    /// Total requests blocked by deny list.
    pub denied_total: AtomicU64,
    /// Total check() calls — used for periodic eviction cycle.
    total: AtomicU64,
}

impl RateLimiter {
    pub fn new(write_limit: u32, read_limit: u32) -> Self {
        Self {
            buckets: std::sync::Mutex::new(HashMap::new()),
            write_limit,
            read_limit,
            rejected_total: AtomicU64::new(0),
            denied: std::sync::Mutex::new(std::collections::HashSet::new()),
            denied_total: AtomicU64::new(0),
            total: AtomicU64::new(0),
        }
    }

    /// Add an IP to the deny list.
    pub fn deny_ip(&self, ip: IpAddr) {
        self.denied.lock_recover().insert(ip);
    }

    /// Remove an IP from the deny list.
    pub fn allow_ip(&self, ip: IpAddr) -> bool {
        self.denied.lock_recover().remove(&ip)
    }

    /// List all denied IPs.
    pub fn denied_ips(&self) -> Vec<IpAddr> {
        self.denied.lock_recover().iter().copied().collect()
    }

    /// Check if request is allowed. Returns true if within limit.
    pub fn check(&self, ip: IpAddr, is_write: bool) -> bool {
        // Check deny list first
        if self.denied.lock_recover().contains(&ip) {
            self.denied_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return false;
        }

        let limit = if is_write { self.write_limit } else { self.read_limit };
        if limit == 0 {
            return true;
        }
        let mut buckets = self.buckets.lock_recover();
        let now = Instant::now();

        let evict_cycle = self.total.fetch_add(1, std::sync::atomic::Ordering::Relaxed).is_multiple_of(64);
        if evict_cycle || buckets.len() > 1024 {
            let before = buckets.len();
            buckets.retain(|_, (_, window_start)| {
                now.duration_since(*window_start).as_secs() < 120
            });
            if buckets.len() > 10_000 {
                let excess = buckets.len() - 5_000;
                let keys: Vec<IpAddr> = buckets.keys().take(excess).copied().collect();
                for k in keys {
                    buckets.remove(&k);
                }
            }
            let evicted = before.saturating_sub(buckets.len());
            if evicted > 0 {
                tracing::debug!("rate limiter: evicted {evicted} stale entries ({} remaining)", buckets.len());
            }
        }

        let entry = buckets.entry(ip).or_insert((0, now));

        // Refill if window elapsed (60s)
        if now.duration_since(entry.1).as_secs() >= 60 {
            entry.0 = 0;
            entry.1 = now;
        }

        if entry.0 >= limit {
            return false;
        }
        entry.0 += 1;
        true
    }
}

/// Public-route gate (L1995 Phase 1).
///
/// The axum HTTPS listener on `listen_addr` is bound publicly so Caddy can
/// reverse-proxy `/pq-ws` from your public hostname (e.g. `testnet.example.com`). Caddy is
/// co-located on the same box, so its requests arrive over loopback.
/// Everything else on the data plane should be reachable ONLY from loopback
/// (Caddy, the local node operator, localhost CLI tools).
///
/// External (non-loopback) clients are restricted to the whitelist below:
/// the PQ gateway, and a small read-only diagnostic surface
/// (metrics / health / status / ping / version). All other paths return 404
/// to non-loopback peers, hiding the legacy HTTPS data plane from the
/// public internet without requiring a Caddy upstream-port reconfiguration.
///
/// Phase 2 of L1995 will physically split the listener (data plane on a
/// localhost-only port) so `ss -tlnp` reports only the PQ ports on the
/// public interface. This middleware closes the practical security gap
/// today.
const PUBLIC_ROUTE_PREFIXES: &[&str] = &[
    "/pq-ws",
    // /ws Slice 3c: "/ws" prefix removed alongside the route deletion.
    "/metrics",
    "/health",
    "/alive",
    "/status",
    "/ping",
    "/version",
    // Gap 1 light-client surface — both endpoints are signed, read-only,
    // idempotent and serve the same data already on the WS data plane:
    //   /proof/account/{identity}  Merkle proof + AccountState bound to seal
    //   /headers/from/{epoch}      epoch headers (timestamp, anchor sig)
    // Without these, an external account using LightClient cannot verify a
    // balance — it would call /proof/account, hit the public-route gate,
    // and get 404. Loopback-only would be the right posture for endpoints
    // that mutate or expose private state; these expose neither.
    "/proof/account",
    "/headers",
    // C4 slice 1: agent-mandate query surface — read-only, idempotent, no
    // secrets (a public ledger's mandates/acts are public by design; same
    // disclosure profile as /proof/account). The prefix covers both
    // /mandate/{id} and /mandate/status/{record_id}. The reverse agent-history
    // endpoint is deliberately NOT here (it stays loopback-only until its
    // enumeration-graph exposure is explicitly decided).
    "/mandate",
    // §11.23 Layer A slice 0: by-hash lookup is read-only, signed by the
    // record's creator, and idempotent — same disclosure profile as the
    // existing `/record/{id}` route, but addressed by the content hash
    // accounts already compute.
    "/records/by-hash",
    // Audit-3: /snapshot/state-delta is the light-client incremental sync
    // surface. Returns a SignedStateDelta (changed accounts since baseline
    // epoch + state root + Dilithium3 sig). Read-only, idempotent, signed —
    // same disclosure profile as `/proof/account` and `/headers`. Bigger
    // archive paths (/snapshot, /snapshot/fast, /snapshot/epoch/*) stay
    // loopback-only to keep heavy bootstrap traffic on PQ-WS.
    "/snapshot/state-delta",
    // Gap 8: /seal/progress/{id} surfaces the Sealed-vs-Finalized state for a
    // record so phone-tier accounts can show "Sealed (3s)" before the 2/3-of-
    // attestation finalization completes. Read-only, idempotent — same shape
    // as the other light-client endpoints. Without this on the public surface,
    // off-host accounts calling the new sealed/finalized fields hit the public-
    // route gate and get 404.
    "/seal/progress",
    // Protocol §11.18 Slice 4 — the route was added to
    // `public_routes()` at `9717f585` but the gate allowlist was missed,
    // so the deployed binary 404'd at the middleware before reaching the
    // handler. This completes the slice-4 promotion by listing the prefix
    // here. Read-only, idempotent, O(1) RocksDB point lookup, no auth
    // needed. Prefix covers both `/governance/upgrade_outcomes` (list)
    // and `/governance/upgrade_outcomes/{proposal_id}` (detail) per the
    // `is_public_route` `path == prefix || starts_with("{prefix}/")` rule.
    "/governance/upgrade_outcomes",
    // Public block-explorer (static/explorer.html) read-only data surface —
    // fusion-audited 2026-06-23 (3 Sonnet + 1 Opus panel + Opus verify against
    // source). Each is read-only, idempotent, bounded, same disclosure profile
    // as a public ledger. DELIBERATELY EXCLUDED (stay loopback/auth-only):
    //   • /peers            — node IP:port topology + per-peer bad-sig diagnostics
    //   • bare /balances    — bulk all-account+balance enumeration / deanon surface
    //   • /witness/profiles — leaks witness IP /24 via `subnet` (config.rs:471
    //                         documents it as an IP prefix; identity.rs:104
    //                         uses it as the network identity for Sybil difficulty)
    // Those three explorer panels degrade to empty — acceptable; a node-IP /
    // topology leak is not. Prefixes are SPECIFIC, not bare parents: `/dag/stats`
    // + `/dag/tips` (NOT `/dag` → would expose `/dag/search`, `/dag/record/{id}/graph`);
    // `/consensus/status` (NOT `/consensus` → would expose `/consensus/record/{id}`).
    "/epochs",            // also /epochs/headers — header-class, same as public /headers
    "/consensus/status",  // exact: excludes /consensus/record/{id}
    "/dag/stats",         // exact: not /dag
    "/dag/tips",          // exact: not /dag (frontier sample bounded — limit default 1000 / max 10000)
    "/transactions/recent",
    "/record",            // /record/{id} (+ /causal-proof); .starts_with("/record/") does NOT match /records/by-hash
    "/account",           // /account/{identity} — same profile as public /proof/account
];

/// Exact-path public allowlist — like PUBLIC_ROUTE_PREFIXES but NEVER matches
/// children. Used for serving a single HTML/asset path publicly without
/// implicitly exposing future siblings under the same parent. Keeps the
/// granular defense around `/exchange/*` data routes intact even while
/// `/exchange` (the page) becomes browser-reachable.
const PUBLIC_EXACT_ROUTES: &[&str] = &[
    // Block-explorer HTML page (fusion-audited 2026-06-23). EXACT match, NOT a
    // prefix, so no future `/explorer/*` sibling is implicitly exposed — exactly
    // the use case this mechanism documents. The page's client-side fetches hit
    // the read-only data prefixes above; its peers/balances/witness panels
    // degrade to empty (those endpoints stay gated — see the note above).
    "/explorer",
    // (`/exchange`, the orderbook viewer, was removed in the not-a-coin pivot
    // 2026-06-09; executed 2026-06-14.)
];

fn is_public_route(path: &str) -> bool {
    if PUBLIC_EXACT_ROUTES.contains(&path) {
        return true;
    }
    PUBLIC_ROUTE_PREFIXES.iter().any(|p| {
        path == *p || path.starts_with(&format!("{p}/"))
    })
}

pub(crate) static PUBLIC_ROUTE_BLOCKED_TOTAL: AtomicU64 = AtomicU64::new(0);

async fn public_route_gate(
    req: axum::extract::Request,
    next: middleware::Next,
) -> axum::response::Response {
    let path = req.uri().path().to_string();
    let is_loopback = req
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ip_is_loopback_canonical(ci.0.ip()))
        .unwrap_or(false);

    if !is_loopback && !is_public_route(&path) {
        PUBLIC_ROUTE_BLOCKED_TOTAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return (StatusCode::NOT_FOUND, "").into_response();
    }
    next.run(req).await
}

async fn rate_limit_middleware(
    State(node_state): State<Arc<NodeState>>,
    req: axum::extract::Request,
    next: middleware::Next,
) -> Result<axum::response::Response, StatusCode> {
    // Early rejection of oversized payloads via Content-Length header.
    // This avoids hyper's connection reset when body exceeds DefaultBodyLimit —
    // we reject BEFORE reading any body bytes, so the client gets a clean 413.
    // Small account-command routes (`/rpc/*`, `/bootstrap/claim`) get a tighter
    // cap: they untyped-`Value`-decode the body pre-auth, so an oversized body is
    // an unauthenticated decode-amplifier (see `small_command_body_cap`).
    //
    // This header check is a FAST-PATH ONLY — it is bypassed by a request that
    // omits Content-Length (`Transfer-Encoding: chunked` / streaming body). The
    // load-bearing enforcement is the body extractor's `DefaultBodyLimit`,
    // which counts ACTUAL streamed bytes: 2 MiB globally, and the tight
    // `MAX_RPC_BODY_BYTES` per-route on the command surface (see `rpc_body_cap`).
    // So a chunked oversized `/rpc/*` body still 413s at the extractor.
    let body_cap = small_command_body_cap(req.uri().path());
    if let Some(cl) = req.headers().get(axum::http::header::CONTENT_LENGTH) {
        if let Ok(len) = cl.to_str().unwrap_or("0").parse::<usize>() {
            if len > body_cap {
                return Err(StatusCode::PAYLOAD_TOO_LARGE);
            }
        }
    }

    // Rate limiting
    if let Some(limiter) = node_state.rate_limiter.get() {
        let ip = req.extensions()
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            .map(|ci| ci.0.ip())
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)));

        // Exempt known peers from rate limiting — they're the network, not abuse.
        // The rate limiter protects against external DoS, not peer-to-peer gossip.
        let is_peer = {
            let peers = node_state.peers.read().await;
            peers.has_peer_ip(ip)
        };

        if !is_peer {
            let is_write = req.method() == axum::http::Method::POST;

            if !limiter.check(ip, is_write) {
                limiter.rejected_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return Err(StatusCode::TOO_MANY_REQUESTS);
            }
        }
    }

    // Request latency tracking — record under both the legacy unlabeled
    // histogram (preserved for dashboard compatibility) and the per-route
    // labeled histogram (lets operators isolate slow routes — light-client
    // `/headers/from/{epoch}` and `/proof/account/*`, gossip `/peers/*`,
    // etc. — without grepping logs).
    let route_label = req
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(|mp| mp.as_str().to_string())
        .unwrap_or_else(|| "<unmatched>".to_string());
    let start = Instant::now();
    let resp = next.run(req).await;
    let elapsed = start.elapsed().as_secs_f64();
    node_state.request_latency.observe(elapsed);
    node_state.request_latency_by_route.observe(&route_label, elapsed);
    node_state
        .request_status_by_route
        .inc(&route_label, status_class_for(resp.status().as_u16()));
    Ok(resp)
}

// ─── Shared helpers (used by route modules) ──────────────────────────────────

/// Loopback test that is correct on dual-stack sockets. `Ipv6Addr::is_loopback()`
/// only matches `::1`, so an IPv4 loopback connection surfaced as the IPv4-mapped
/// form `::ffff:127.0.0.1` (which a dual-stack listener can present) would NOT be
/// recognized as loopback. Map it back to IPv4 first. Without this, a future
/// dual-stack bind would reject genuine on-box clients.
pub(crate) fn ip_is_loopback_canonical(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback()),
    }
}

/// Pure RPC authorization policy, separated from header/peer extraction so the
/// security decision is unit-testable without a full `NodeState`. Returns true
/// iff the request is authorized. Two independent grants:
/// 1. A valid admin token (constant-time Bearer compare) — the transport-
///    independent credential, and the ONLY path for proxy-fronted callers.
/// 2. A genuine loopback TCP peer (`peer_ip`) with no reverse-proxy headers —
///    i.e. direct on-box tooling.
///
/// The grant is derived from the REAL peer, never from `X-Real-IP`: trusting that
/// client-controllable header for auth is a spoofable bypass (an external client
/// behind a reverse proxy could send `X-Real-IP: 127.0.0.1`). `request_is_proxied`
/// being true excludes the loopback grant, which also closes the "same-host Caddy
/// on loopback" laundering path — a forwarded external request carries proxy
/// headers, so it cannot pass as direct-local and must use the Bearer token.
fn rpc_auth_authorized(
    admin_token: &str,
    provided_bearer: &str,
    peer_ip: IpAddr,
    request_is_proxied: bool,
) -> bool {
    if !provided_bearer.is_empty() && !admin_token.is_empty() {
        let expected = admin_token.as_bytes();
        let provided = provided_bearer.as_bytes();
        let mut diff = expected.len() ^ provided.len();
        for (a, b) in expected.iter().zip(provided.iter()) {
            diff |= (*a ^ *b) as usize;
        }
        if diff == 0 {
            return true;
        }
    }
    ip_is_loopback_canonical(peer_ip) && !request_is_proxied
}

/// Verify RPC authentication. RPC endpoints sign with the node's private key, so
/// a caller must either present a valid admin Bearer token or be direct on-box
/// tooling (genuine loopback peer, no reverse-proxy headers). "Local" comes from
/// the real TCP peer (`ConnectInfo`, passed in as `peer_ip`), never from a header
/// — see `rpc_auth_authorized`. This honors the documented `trusted_proxy_ips`
/// contract (config.rs): `X-Real-IP` is never trusted for authorization.
pub(crate) fn verify_rpc_auth(
    state: &NodeState,
    peer_ip: IpAddr,
    headers: &HeaderMap,
) -> Result<(), AppError> {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let token = auth.strip_prefix("Bearer ").or_else(|| auth.strip_prefix("bearer ")).unwrap_or("");
    let request_is_proxied =
        headers.contains_key("x-forwarded-for") || headers.contains_key("x-real-ip");

    if rpc_auth_authorized(&state.config.admin_token, token, peer_ip, request_is_proxied) {
        if state.config.admin_token.is_empty() {
            warn!("RPC endpoint accessed without auth token — allowing because admin_token is not configured (peer is loopback). Set ELARA_ADMIN_TOKEN for production.");
        }
        return Ok(());
    }

    Err(ElaraError::Ledger(
        "RPC endpoint requires authentication: set Authorization: Bearer <admin_token> header, or configure ELARA_ADMIN_TOKEN".into()
    ).into())
}

#[cfg(test)]
mod rpc_auth_tests {
    use super::{ip_is_loopback_canonical, rpc_auth_authorized};
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn loopback_canonical_covers_v4_v6_and_ipv4_mapped() {
        // Genuine loopback in every representation a socket can surface.
        assert!(ip_is_loopback_canonical(ip("127.0.0.1")));
        assert!(ip_is_loopback_canonical(ip("127.0.0.53"))); // whole 127/8
        assert!(ip_is_loopback_canonical(ip("::1")));
        // IPv4-mapped loopback — a dual-stack listener can present this; std's
        // Ipv6Addr::is_loopback() returns false for it, so the canonicalization
        // is load-bearing to avoid rejecting genuine on-box clients.
        assert!(ip_is_loopback_canonical(ip("::ffff:127.0.0.1")));
        // Non-loopback must stay false in every representation.
        assert!(!ip_is_loopback_canonical(ip("10.0.0.5")));
        assert!(!ip_is_loopback_canonical(ip("192.168.1.1")));
        assert!(!ip_is_loopback_canonical(ip("0.0.0.0")));
        assert!(!ip_is_loopback_canonical(ip("::ffff:10.0.0.5")));
        assert!(!ip_is_loopback_canonical(ip("2001:db8::1")));
    }

    #[test]
    fn xrealip_spoof_from_remote_peer_is_rejected() {
        // The core fix: a remote attacker who sets X-Real-IP: 127.0.0.1 (which
        // makes request_is_proxied=true) over a non-loopback peer is NOT local.
        assert!(!rpc_auth_authorized("secret", "", ip("203.0.113.7"), true));
        // Even with proxy header stripped, a non-loopback peer is still not local.
        assert!(!rpc_auth_authorized("secret", "", ip("203.0.113.7"), false));
    }

    #[test]
    fn direct_loopback_client_is_authorized() {
        // Direct on-box CLI: loopback peer, no token, no proxy headers — allowed
        // whether or not admin_token is configured (improves on the old code,
        // which rejected a tokenless direct-localhost client when admin_token set).
        assert!(rpc_auth_authorized("secret", "", ip("127.0.0.1"), false));
        assert!(rpc_auth_authorized("", "", ip("127.0.0.1"), false));
        // IPv4-mapped loopback resolves correctly end-to-end.
        assert!(rpc_auth_authorized("secret", "", ip("::ffff:127.0.0.1"), false));
    }

    #[test]
    fn loopback_with_proxy_headers_requires_bearer() {
        // Same-host Caddy laundering external traffic: the real peer is loopback
        // but the forwarded request carries proxy headers → not direct-local.
        assert!(!rpc_auth_authorized("secret", "", ip("127.0.0.1"), true));
        // The proxy path works only with a valid Bearer token.
        assert!(rpc_auth_authorized("secret", "secret", ip("127.0.0.1"), true));
    }

    #[test]
    fn bearer_token_paths() {
        // Remote caller with a valid token is authorized.
        assert!(rpc_auth_authorized("secret", "secret", ip("203.0.113.7"), true));
        // Wrong token from a remote peer is rejected.
        assert!(!rpc_auth_authorized("secret", "wrong", ip("203.0.113.7"), true));
        // A token is meaningless when the node has no admin_token configured:
        // the bearer branch is skipped and a non-loopback peer falls through.
        assert!(!rpc_auth_authorized("", "anything", ip("203.0.113.7"), false));
    }

    #[test]
    fn unconfigured_node_does_not_open_rpc_to_non_loopback() {
        // Hardening vs the old `!has_proxy_headers && admin_token.is_empty()`
        // grant: with no admin_token, an accidental non-loopback exposure (no
        // proxy headers) must NOT authorize — only a genuine loopback peer does.
        assert!(!rpc_auth_authorized("", "", ip("203.0.113.7"), false));
        assert!(rpc_auth_authorized("", "", ip("127.0.0.1"), false));
    }
}

/// Get up to `max` current DAG tips as parent references for new records.
/// Uses lock-free snapshot when available — avoids blocking on DAG write lock
/// held by gossip bootstrap or state core inserts.
pub(crate) async fn dag_tip_parents(state: &Arc<NodeState>, max: usize) -> Vec<String> {
    // Hard cap: never reference more than 5 tips as parents.
    // Previous adaptive scaling (up to 64) caused edge explosion —
    // 139K edges on 3.7K records (37 edges/record vs normal 2-3).
    // More parents doesn't improve convergence enough to justify 20x
    // edge overhead and the memory/CPU cost that comes with it.
    let hard_cap = max.min(5);

    // Prefer snapshot tips (lock-free via ArcSwap)
    let mut tips = if let Some(core) = state.state_core.get() {
        let snap = core.read_snapshot();
        if !snap.dag_tip_ids.is_empty() {
            snap.dag_tip_ids.clone()
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    // Fallback: direct DAG read (before state core init or empty snapshot)
    if tips.is_empty() {
        let dag = state.dag.read().await;
        tips = dag.tips();
    }

    if tips.len() <= hard_cap {
        return tips;
    }

    // Random sampling via Fisher-Yates partial shuffle.
    // Without this, the same newest tips get picked every time,
    // leaving 75-80% of tips permanently unreferenced.
    let mut seed = [0u8; 8];
    getrandom::getrandom(&mut seed).unwrap_or_default();
    let mut rng_state = u64::from_le_bytes(seed);
    let mut result = Vec::with_capacity(hard_cap);
    for i in 0..hard_cap {
        // xorshift64 — fast, good enough for tip selection
        rng_state ^= rng_state << 13;
        rng_state ^= rng_state >> 7;
        rng_state ^= rng_state << 17;
        let j = i + (rng_state as usize % (tips.len() - i));
        tips.swap(i, j);
        result.push(tips[i].clone());
    }
    result
}

/// Insert a record AND push it to all peers via gossip.
pub(crate) async fn insert_and_push(state: &Arc<NodeState>, record: crate::record::ValidationRecord) -> Result<String, AppError> {
    let record_clone = record.clone();
    let record_id = gossip::insert_record(state, record).await?;

    let state2 = state.clone();
    tokio::spawn(async move {
        super::state::NodeState::publish_record_with_fallback(&state2, &record_clone, None).await;
    });

    Ok(record_id)
}

/// Insert a record AND push it to all peers — bypasses rate limits.
/// Used for admin-authenticated RPC operations (stake, unstake, governance)
/// where the operator has already proven ownership of the node.
pub(crate) async fn insert_and_push_admin(state: &Arc<NodeState>, record: crate::record::ValidationRecord) -> Result<String, AppError> {
    let record_clone = record.clone();
    let record_id = gossip::insert_record_synced(state, record).await?;

    let state2 = state.clone();
    tokio::spawn(async move {
        super::state::NodeState::publish_record_with_fallback(&state2, &record_clone, None).await;
    });

    Ok(record_id)
}

/// Format a parsed ledger operation as JSON.
pub(crate) fn format_op(op: &ParsedLedgerOp) -> serde_json::Value {
    match op {
        ParsedLedgerOp::Mint { amount, to, reason } => serde_json::json!({
            "op": "mint",
            "amount": amount,
            "to": to,
            "reason": reason,
        }),
        ParsedLedgerOp::Transfer { amount, to, memo } => serde_json::json!({
            "op": "transfer",
            "amount": amount,
            "to": to,
            "memo": memo,
        }),
        ParsedLedgerOp::Stake { amount, purpose } => serde_json::json!({
            "op": "stake",
            "amount": amount,
            "purpose": purpose.as_str(),
        }),
        ParsedLedgerOp::Unstake { stake_record_id } => serde_json::json!({
            "op": "unstake",
            "stake_record_id": stake_record_id,
        }),
        ParsedLedgerOp::WitnessReward { amount, from, to, record_id } => serde_json::json!({
            "op": "witness_reward",
            "amount": amount,
            "from": from,
            "to": to,
            "record_id": record_id,
        }),
        ParsedLedgerOp::Slash { amount, offender, challenger, jury, stake_record_id, reason } => serde_json::json!({
            "op": "slash",
            "amount": amount,
            "offender": offender,
            "challenger": challenger,
            "jury": jury,
            "stake_record_id": stake_record_id,
            "reason": reason,
        }),
        ParsedLedgerOp::DormancyReclaim { amount, dormant_identity, last_activity } => serde_json::json!({
            "op": "dormancy_reclaim",
            "amount": amount,
            "dormant_identity": dormant_identity,
            "last_activity": last_activity,
        }),
        ParsedLedgerOp::Burn { amount, memo } => serde_json::json!({
            "op": "burn",
            "amount": amount,
            "memo": memo,
        }),
        ParsedLedgerOp::PoolFund { amount } => serde_json::json!({
            "op": "pool_fund",
            "amount": amount,
        }),
        ParsedLedgerOp::Predict { amount, zone, target_epoch, claim, predicted_value } => serde_json::json!({
            "op": "predict",
            "amount": amount,
            "zone": zone,
            "target_epoch": target_epoch,
            "claim": claim.as_str(),
            "predicted_value": predicted_value,
        }),
        ParsedLedgerOp::XZoneLock { amount, recipient, source_zone, dest_zone } => serde_json::json!({
            "op": "xzone_lock",
            "amount": amount,
            "recipient": recipient,
            "source_zone": source_zone,
            "dest_zone": dest_zone,
        }),
        ParsedLedgerOp::XZoneClaim { transfer_id, amount, recipient } => serde_json::json!({
            "op": "xzone_claim",
            "transfer_id": transfer_id,
            "amount": amount,
            "recipient": recipient,
        }),
        ParsedLedgerOp::XZoneCancel { transfer_id } => serde_json::json!({
            "op": "xzone_cancel",
            "transfer_id": transfer_id,
        }),
        ParsedLedgerOp::XZoneReject { transfer_id } => serde_json::json!({
            "op": "xzone_reject",
            "transfer_id": transfer_id,
        }),
        ParsedLedgerOp::XZoneAbort { transfer_id, dest_committee_size, signers, .. } => serde_json::json!({
            "op": "xzone_abort",
            "transfer_id": transfer_id,
            "dest_committee_size": dest_committee_size,
            "signer_count": signers.len(),
        }),
        ParsedLedgerOp::DormancyDeclare { target_identity, last_known_active } => serde_json::json!({
            "op": "dormancy_declare",
            "target_identity": target_identity,
            "last_known_active": last_known_active,
        }),
        ParsedLedgerOp::DormancyHeartbeat => serde_json::json!({
            "op": "dormancy_heartbeat",
        }),
        ParsedLedgerOp::DormancyProofOfLife { target_identity, signature } => serde_json::json!({
            "op": "dormancy_proof_of_life",
            "target_identity": target_identity,
            "signature": signature,
        }),
        ParsedLedgerOp::WitnessRegister { zone_path, bond } => serde_json::json!({
            "op": "witness_register",
            "zone_path": zone_path,
            "bond": bond,
        }),
        ParsedLedgerOp::IdleDecay { batch } => serde_json::json!({
            "op": "idle_decay",
            "epoch": batch.epoch,
            "zone": batch.zone,
            "total_debit": batch.total_debit() as u64,
            "pool_credit": batch.pool_credit,
            "exchange_count": batch.debits.len(),
            "staker_count": batch.staker_credits.len(),
        }),
        ParsedLedgerOp::XZoneTimeoutRefund { batch } => serde_json::json!({
            "op": "xzone_timeout_refund",
            "epoch": batch.epoch,
            "zone": batch.zone,
            "total_refund": batch.total_refund() as u64,
            "refund_count": batch.refunds.len(),
        }),
        ParsedLedgerOp::XZoneStaleReap { batch } => serde_json::json!({
            "op": "xzone_stale_reap",
            "epoch": batch.epoch,
            "zone": batch.zone,
            "total_reaped": batch.total_refund() as u64,
            "reap_count": batch.refunds.len(),
        }),
    }
}

/// Parse an IPv4 address string into 4 octets.
pub(crate) fn parse_ipv4_octets(s: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 { return None; }
    Some([
        parts[0].parse().ok()?,
        parts[1].parse().ok()?,
        parts[2].parse().ok()?,
        parts[3].parse().ok()?,
    ])
}

// ─── Metrics handler (kept in server.rs due to size) ─────────────────────────

/// Compute the on-disk SMT root vs latest seal-binding diagnostic for the
/// `elara_account_smt_disk_root_*` gauges. Empirically, only the rotating
/// seal CREATOR holds an on-disk root that matches the `account_smt_root`
/// signed in its seal — witness flush drains a different `smt_dirty` set
/// and lands at a divergent root. The gauge surfaces that asymmetry per
/// node so operators can see the LightClientPool soft-fail surface.
///
/// Returns `(matches, age_seconds, epoch)`:
/// - `matches`: 1 if disk root == sealed root, 0 if diverged. Reports 1
///   when no binding exists (genesis / pre-Gap-1 chain) so dashboards
///   don't alert on a network with nothing to diverge from yet.
/// - `age_seconds`: `now - sealed_at` if matching, `-1` if diverged or
///   no binding. Negative is the "not currently bound" sentinel.
/// - `epoch`: epoch number of the binding, or `-1` if no binding.
fn smt_disk_root_vs_seal(
    storage: &crate::storage::rocks::StorageEngine,
    sealed: Option<(u64, super::zone::ZoneId, String, [u8; 32], f64)>,
    now: f64,
) -> (u64, f64, i64) {
    let on_disk = crate::network::account_merkle::AccountStateSMT::new(storage)
        .root()
        .ok();
    match (on_disk, sealed) {
        (Some(disk), Some((epoch_n, _zone, _seal_id, sealed_root, sealed_at))) => {
            if disk == sealed_root {
                (1, (now - sealed_at).max(0.0), epoch_n as i64)
            } else {
                (0, -1.0, epoch_n as i64)
            }
        }
        (Some(_), None) => (1, -1.0, -1),
        _ => (0, -1.0, -1),
    }
}

/// Open file descriptor count via `/proc/self/fd`.
///
/// Linux-only. Returns 0 on non-Linux hosts or if `/proc/self/fd` is not
/// readable (extremely rare — would mean PID-namespace isolation broke or
/// the procfs mount was lost). Counting `read_dir` entries matches
/// `lsof -p $PID | wc -l` semantics for this process. Cheap: O(open_fds)
/// dirent walk against the kernel's per-process FD table.
fn count_open_fds() -> u64 {
    std::fs::read_dir("/proc/self/fd")
        .map(|it| it.filter(|e| e.is_ok()).count() as u64)
        .unwrap_or(0)
}

/// Soft FD limit via `getrlimit(RLIMIT_NOFILE)`.
///
/// Returns 0 if the syscall fails. The soft limit is what the kernel
/// actually enforces — exceeding it triggers EMFILE on `accept`/`open`,
/// which cascades into "too many open files" errors that look like
/// network outages but are really FD exhaustion.
fn max_open_fds() -> u64 {
    #[cfg(not(unix))]
    {
        // No getrlimit off-unix; 0 = "unavailable", the documented failure value.
        0
    }
    #[cfg(unix)]
    {
    let mut rl = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) };
    if rc == 0 {
        rl.rlim_cur
    } else {
        0
    }
    }
}

/// Process memory pressure beyond RSS — `(VmPeak_kb, VmSwap_kb, threads)`.
///
/// Reads `/proc/self/status` once and pulls three fields:
///
/// - `VmPeak` is the high-water mark of virtual address space ever held by
///   this process. RSS can drop after a transient spike; VmPeak does not.
///   Useful for detecting one-off memory-explosion bugs (a streaming pull
///   that buffered everything, an unbounded queue) post-mortem when RSS
///   has already deflated.
/// - `VmSwap` is the canonical phone-tier death signal. On a 2 GB node with
///   1 GB swap configured, a single large compaction or pull-loop spike can
///   push pages out — and once paged out, every state_core read pays a disk
///   roundtrip until those pages re-fault back in. Sustained `VmSwap > 0` is
///   never benign — pair with `elara_rocksdb_running_compactions` to confirm
///   compactor pressure or with `elara_process_major_faults_total` rate to
///   confirm thrashing.
/// - `threads` is the live thread count. Tokio worker pools spike here when
///   the runtime is forced to spawn extra blocking workers because async
///   tasks blocked on syscalls; sustained climb above the configured
///   `max_blocking_threads` indicates back-pressure escaped from async.
fn process_status_extended() -> (u64, u64, u64) {
    let mut peak = 0u64;
    let mut swap = 0u64;
    let mut threads = 0u64;
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            let extract = |line: &str, prefix: &str| -> Option<u64> {
                line.strip_prefix(prefix)
                    .and_then(|rest| rest.split_whitespace().next())
                    .and_then(|s| s.parse().ok())
            };
            if let Some(v) = extract(line, "VmPeak:") { peak = v; continue; }
            if let Some(v) = extract(line, "VmSwap:") { swap = v; continue; }
            if let Some(v) = extract(line, "Threads:") { threads = v; continue; }
        }
    }
    (peak, swap, threads)
}

/// Process scheduler thrash + RSS high-water — `(VmHWM_kb, voluntary_ctxt, nonvoluntary_ctxt)`.
///
/// Reads `/proc/self/status` and pulls three fields the page-fault helper does not:
///
/// - `VmHWM` is the high-water mark of *resident* memory (RSS) ever held by
///   this process. Distinct from `VmPeak` (high-water of virtual address
///   space): VmHWM tracks what physical memory actually hit, so it is the
///   OOM-relevant peak. Useful when current RSS has deflated post-spike —
///   VmHWM preserves the cliff that the OOM killer almost cut.
/// - `voluntary_ctxt_switches` increments each time the process yields the
///   CPU willingly (blocked on I/O, futex, sleep). Healthy for an I/O-bound
///   async runtime; rate ≈ syscalls/sec at steady state. The "good" half of
///   the pair — worry only when this is flat (process not yielding = hot CPU
///   loop) or when the ratio against nonvoluntary inverts.
/// - `nonvoluntary_ctxt_switches` increments each time the kernel preempts
///   the process before its quantum expires — almost always because another
///   process took the CPU. On shared-VPS nodes (DigitalOcean droplets,
///   Hetzner CX23, phone tier) this is the canonical "noisy neighbor"
///   signal. Rate >> voluntary rate = host is contended and elara-node is
///   being starved.
fn process_scheduler_stats() -> (u64, u64, u64) {
    let mut vmhwm = 0u64;
    let mut voluntary = 0u64;
    let mut nonvoluntary = 0u64;
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            let extract = |line: &str, prefix: &str| -> Option<u64> {
                line.strip_prefix(prefix)
                    .and_then(|rest| rest.split_whitespace().next())
                    .and_then(|s| s.parse().ok())
            };
            if let Some(v) = extract(line, "VmHWM:") { vmhwm = v; continue; }
            if let Some(v) = extract(line, "voluntary_ctxt_switches:") { voluntary = v; continue; }
            if let Some(v) = extract(line, "nonvoluntary_ctxt_switches:") { nonvoluntary = v; continue; }
        }
    }
    (vmhwm, voluntary, nonvoluntary)
}

/// Process RSS composition split — `(RssAnon_kb, RssFile_kb, RssShmem_kb)`.
///
/// Reads `/proc/self/status` and pulls the three fields that decompose RSS
/// into its three sources. RSS = RssAnon + RssFile + RssShmem on every Linux
/// kernel since 4.5 (the kernel that introduced this split). Exposing the
/// split is critical for understanding memory pressure on a phone-tier node:
///
/// - `RssAnon` is the heap that elara-node actually owns — Rust allocations,
///   stacks, COW'd pages. This is the memory the kernel CANNOT take back
///   without swapping; sustained growth here is a real leak or working-set
///   inflation. Compare to the RocksDB block-cache (that lives in
///   RssFile), to jemalloc allocated, and to Threads × stack
///   size (typical 8 MB/thread on x86_64) — RssAnon should align.
/// - `RssFile` is the page cache holding mmap'd files (RocksDB SST blocks,
///   the binary's text+rodata, snapshot tempfiles). High RssFile is HEALTHY:
///   it means hot RocksDB blocks are resident and reads can hit cache. Under
///   memory pressure the kernel reclaims this first, before touching RssAnon.
///   On a 2 GB phone-tier node where RssFile suddenly drops while RssAnon
///   climbs, the kernel is shrinking the page cache to make room for our
///   heap — every subsequent read misses cache and pays disk.
/// - `RssShmem` is shared memory (POSIX shm, tmpfs, sysv shm). For elara-node
///   this is typically near zero — we don't intentionally use shared memory.
///   A non-zero growth here points at: a sidecar daemon sharing a tmpfs we
///   inherited, an mmap'd /dev/shm region, or systemd journal forwarding via
///   shm. Worth alerting on any drift from baseline; the baseline is "0 or
///   small constant".
///
/// This is the 3rd /proc/self/status read per scrape (after the memory and
/// scheduler readers); the file is ~5 kB and parsed line-by-line, so total cost is
/// bounded — but if `/metrics` scrape latency ever becomes a hot path we
/// can merge all three readers into one helper. Today the cost is invisible
/// next to RocksDB stats and disk-I/O reads.
fn process_rss_composition() -> (u64, u64, u64) {
    let raw = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    parse_rss_composition(&raw)
}

fn parse_rss_composition(raw: &str) -> (u64, u64, u64) {
    let mut anon = 0u64;
    let mut file = 0u64;
    let mut shmem = 0u64;
    for line in raw.lines() {
        let extract = |line: &str, prefix: &str| -> Option<u64> {
            line.strip_prefix(prefix)
                .and_then(|rest| rest.split_whitespace().next())
                .and_then(|s| s.parse().ok())
        };
        if let Some(v) = extract(line, "RssAnon:") { anon = v; continue; }
        if let Some(v) = extract(line, "RssFile:") { file = v; continue; }
        if let Some(v) = extract(line, "RssShmem:") { shmem = v; continue; }
    }
    (anon, file, shmem)
}

/// Extended host memory accounting from `/proc/meminfo`.
///
/// Returns `(mem_total_kb, mem_available_kb, mem_free_kb, buffers_kb,
/// slab_kb, sreclaimable_kb, swap_total_kb, swap_free_kb, page_tables_kb)`.
///
/// The OOM-imminence reader already exposes Dirty/Writeback/Cached. This
/// extension closes the gaps for true memory-pressure visibility on phone-tier nodes:
///
/// - `MemTotal`: host RAM as the kernel sees it. The denominator for every
///   memory-pressure ratio. On a VPS this can be subtly different from the
///   plan's nominal RAM (kernel reserves 1-3% for crash dumps, hypervisor
///   ballooning) — surface it so operators can sanity-check what they're
///   actually paying for.
/// - `MemAvailable`: the GOLD-STANDARD "really free" RAM metric. Computed by
///   the kernel as MemFree + reclaimable cache + reclaimable slab, minus
///   watermarks. Better than MemFree because it accounts for what the
///   kernel can actually reclaim under pressure. This is the canonical
///   alert metric: MemAvailable / MemTotal < 0.10 = OOM-kill territory
///   within the next minute on a busy node.
/// - `MemFree`: strictly unallocated pages. Always ≤ MemAvailable. The
///   gap (MemAvailable - MemFree) tells you how much of the "free" memory
///   is actually reclaimable cache that other workloads might compete for.
///   On a healthy steady-state node MemFree is small (most RAM is doing
///   useful work as cache or anonymous mappings); MemFree → MemAvailable
///   means caches got dumped (reclaim event happened recently).
/// - `Buffers`: block-device cache (raw disk reads via /dev/sda style).
///   Distinct from Cached (page cache for file-backed pages). Usually small
///   (~1% of RAM) but can grow under heavy LVM/RAID metadata reads.
/// - `Slab`: kernel slab caches (dentry cache, inode cache, network buffers,
///   socket buffers, etc.). Grows with FD count, mount points, network
///   connection count. Sustained growth without a corresponding workload
///   change = kernel slab leak (rare but documented for older kernel
///   versions). Pair with elara_process_open_fds_count.
/// - `SReclaimable`: subset of Slab that the kernel can reclaim under
///   pressure. The non-reclaimable portion (Slab - SReclaimable) is real
///   kernel overhead we cannot win back; if that grows unboundedly the
///   kernel itself is the leak source.
/// - `SwapTotal`: total swap configured. Zero on phone-tier nodes (we
///   typically run swapless to avoid eMMC wear); non-zero on legacy hosts.
/// - `SwapFree`: unused swap. SwapTotal - SwapFree is "swap used" — any
///   non-zero value on a phone-tier node = the kernel is paging anonymous
///   memory to disk, latency catastrophe imminent.
/// - `PageTables`: kernel memory used for page-table entries. Grows
///   linearly with our mmap region count (RocksDB SST files, the binary's
///   text+rodata, snapshot temp files). Sustained growth past ~100 MB on
///   a 2 GB node = excessive mmap fragmentation; pair with
///   elara_process_rss_file_kb to confirm the cost matches our usage.
///
/// All fields zero on read failure (containers without /proc/meminfo,
/// non-Linux). The file is read once and parsed line-by-line; cost is
/// ~50 µs and the file is a few kB held in a slab buffer.
fn host_meminfo_extras() -> (u64, u64, u64, u64, u64, u64, u64, u64, u64) {
    let raw = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
    parse_meminfo_extras(&raw)
}

fn parse_meminfo_extras(raw: &str) -> (u64, u64, u64, u64, u64, u64, u64, u64, u64) {
    let mut mem_total = 0u64;
    let mut mem_available = 0u64;
    let mut mem_free = 0u64;
    let mut buffers = 0u64;
    let mut slab = 0u64;
    let mut sreclaimable = 0u64;
    let mut swap_total = 0u64;
    let mut swap_free = 0u64;
    let mut page_tables = 0u64;
    for line in raw.lines() {
        let mut parts = line.split_whitespace();
        let key = match parts.next() {
            Some(k) => k,
            None => continue,
        };
        let val: u64 = parts.next().and_then(|v| v.parse().ok()).unwrap_or(0);
        match key {
            "MemTotal:" => mem_total = val,
            "MemAvailable:" => mem_available = val,
            "MemFree:" => mem_free = val,
            "Buffers:" => buffers = val,
            "Slab:" => slab = val,
            "SReclaimable:" => sreclaimable = val,
            "SwapTotal:" => swap_total = val,
            "SwapFree:" => swap_free = val,
            "PageTables:" => page_tables = val,
            _ => {}
        }
    }
    (mem_total, mem_available, mem_free, buffers, slab, sreclaimable, swap_total, swap_free, page_tables)
}

/// Per-process aggregated time blocked on disk I/O (delayacct).
///
/// Returns cumulative seconds the kernel scheduler counted elara-node as
/// blocked-on-block-IO, derived from `/proc/self/stat` field 42
/// (`delayacct_blkio_ticks`) divided by `sysconf(_SC_CLK_TCK)`.
///
/// Distinct from every other I/O signal we already expose:
///
/// - `elara_process_io_read_bytes_total` measures throughput — how
///   many bytes the kernel pulled from the block device. A node can do a lot
///   of bytes per second without ever stalling (sequential, queue depth high).
/// - `elara_psi_io_some_avg10` is HOST-WIDE — every process on the
///   box contributes. A noisy-neighbor compaction in another VM saturates the
///   PSI signal even when elara-node itself was never blocked.
/// - `elara_process_schedstat_*` covers scheduler wait time (waiting
///   for a CPU), which is orthogonal to disk-wait.
///
/// `delayacct_blkio_seconds_total` answers a question none of those answer:
/// "How much wall-clock time did THIS process spend with at least one task
/// blocked on a block-IO request?" That is the canonical phone-tier disk-
/// pressure signal. On a healthy node the rate is near zero. Sustained
/// `rate(elara_process_blkio_wait_seconds_total[5m]) > 0.1` (i.e. >10% of
/// elara-node's wall time spent blocked on disk) = the bottleneck IS the
/// disk, even if PSI looks fine. On RocksDB-heavy workloads this is the
/// fastest leading indicator of compaction backing up.
///
/// `/proc/self/stat` field layout (after the last `)`, 0-indexed): the 42nd
/// 1-indexed field of the canonical man-7-proc record is `delayacct_blkio_
/// ticks`. Counting from the post-`)` tail: state(0) ppid(1) … policy(38)
/// **delayacct_blkio_ticks(39)**.
///
/// Requires `CONFIG_TASK_DELAY_ACCT=y` (set on every mainline distro since
/// 2018 — the kernel option is gated by `delayacct=on` boot param on some
/// distros but the field still exists, just stays at 0). On the rare host
/// without delay accounting we report 0 — that is the correct fallback
/// (looks like a healthy steady-state rather than a missing data point).
fn process_blkio_wait_seconds() -> f64 {
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
    let tail = stat.rsplit(')').next().unwrap_or("");
    let parts: Vec<&str> = tail.split_whitespace().collect();
    let ticks: u64 = parts.get(39).and_then(|s| s.parse().ok()).unwrap_or(0);
    #[cfg(unix)]
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    // No sysconf off-unix; 0 routes to the 100 Hz default (and /proc is absent
    // there anyway, so ticks is already 0).
    #[cfg(not(unix))]
    let hz: i64 = 0;
    let hz = if hz > 0 { hz as f64 } else { 100.0 };
    ticks as f64 / hz
}

/// Per-zone CPU thermal temperature from `/sys/class/thermal`.
///
/// Returns `Vec<(zone_name, type_label, celsius)>` sorted by zone name for
/// stable Prometheus output. Each tuple corresponds to one thermal zone
/// the kernel exposes.
///
/// On hosts without `/sys/class/thermal` (almost all virtualised cloud
/// VPSs — Hetzner CX23, DigitalOcean droplets — because the hypervisor
/// abstracts CPU thermals away from the guest) returns an empty Vec. We
/// emit zero gauge rows in that case rather than fake values; an absent
/// metric family is the correct fallback for "this host can't tell us
/// the temperature".
///
/// On hosts WITH thermal zones (the local mini-PC, the laptop node, future
/// Pi/RPi phone-tier nodes), the kernel typically reports:
///
/// - `x86_pkg_temp` — package-level temperature on Intel CPUs (the
///   single most actionable thermal signal on x86)
/// - `coretemp` — per-core temperatures (some laptops/desktops)
/// - `acpitz` — ACPI thermal zone (legacy, often the chassis sensor)
/// - `cpu-thermal` (ARM) — SoC die temperature on Pi/RPi
///
/// Phone-tier alert: any zone reporting > 80 °C sustained = thermal
/// throttling territory. Linux thermal_throttle scales clock to ~60% at
/// the ACPI passive trip point (typically 85–90 °C for laptop SoCs);
/// elara-node performance silently degrades 30–40% with no other signal
/// in /metrics. Pair with `elara_process_cpu_user_seconds_total` rate:
/// CPU rate FLAT while temp climbs = throttling already active and the
/// runtime is being clock-gated by the kernel.
///
/// Format of `/sys/class/thermal/thermal_zone*/temp`: a single integer in
/// millidegrees Celsius (so `47000` = 47.000 °C). Some zones report
/// negative values when offline; we surface those as-is rather than
/// clipping to zero so debugging unusual hardware states is possible.
fn host_thermal_zones() -> Vec<(String, String, f64)> {
    let mut out: Vec<(String, String, f64)> = Vec::new();
    let dir = match std::fs::read_dir("/sys/class/thermal") {
        Ok(d) => d,
        Err(_) => return out,
    };
    for entry in dir.flatten() {
        let name = entry.file_name();
        let name_str = match name.to_str() {
            Some(s) => s,
            None => continue,
        };
        if !name_str.starts_with("thermal_zone") {
            continue;
        }
        let path = entry.path();
        let temp_path = path.join("temp");
        let type_path = path.join("type");
        let temp_raw = match std::fs::read_to_string(&temp_path) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let temp_milli: i64 = temp_raw.trim().parse().unwrap_or(0);
        let type_label = std::fs::read_to_string(&type_path)
            .ok()
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "unknown".to_string());
        out.push((name_str.to_string(), type_label, temp_milli as f64 / 1000.0));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// Per-chip / per-sensor temperatures from `/sys/class/hwmon`.
///
/// Returns `Vec<(chip, sensor, label, celsius)>` sorted by (chip, sensor)
/// for stable Prometheus output. Complements the `/sys/class/thermal`
/// reader which only covers the kernel's `thermal_zone*` interface. Modern x86
/// laptops route CPU temperatures through hwmon (`coretemp` for Intel,
/// `k10temp`/`zenpower` for AMD) instead of `thermal_zone*`; the laptop node is the
/// canonical example — it has only `cooling_device*` under thermal but
/// has no CPU sensor exposed at all on its current kernel/firmware combo.
///
/// Phone-tier value: hwmon surfaces PER-CORE temperatures (each `temp*`
/// row on a `coretemp` chip is a single core), which lets us detect
/// single-core hot-spots that a package-level zone cannot. Workload
/// pinning a single core sustained at 95 °C while the other cores idle
/// at 50 °C produces full-package throttling that looks identical to
/// uniform load on a single-zone metric. Per-core observability is the
/// difference between "the chip is hot" (tells operators nothing) and
/// "core 1 is pinned" (tells operators which thread to look at).
///
/// Also covers non-CPU sensors:
/// - `nvme` chips report SSD package temperature (Composite, Sensor 1/2)
///   — phone-tier eMMC temp signal when present
/// - `dell_smm` / `acpitz` report chassis/SODIMM temperatures on laptops
/// - VRM and PCIe sensors on enterprise hardware
///
/// The hwmon convention is one chip per `hwmon*` dir, one or more
/// `temp{N}_input` files per chip, optional `temp{N}_label` companion
/// files giving a human-readable name for the sensor (e.g. "Package id
/// 0", "Core 0", "Composite"). Values in `temp{N}_input` are in
/// millidegrees Celsius. Empty label is normal — emit "" rather than
/// fabricate a label, so operators can see the kernel reported nothing.
///
/// Empty Vec on hosts without hwmon (most virtualised cloud VPSs) — same
/// fallback policy as the thermal-zone reader.
fn host_hwmon_temps() -> Vec<(String, String, String, f64)> {
    let mut out: Vec<(String, String, String, f64)> = Vec::new();
    let dir = match std::fs::read_dir("/sys/class/hwmon") {
        Ok(d) => d,
        Err(_) => return out,
    };
    for entry in dir.flatten() {
        let name = entry.file_name();
        let name_str = match name.to_str() {
            Some(s) => s,
            None => continue,
        };
        if !name_str.starts_with("hwmon") {
            continue;
        }
        let path = entry.path();
        let chip = std::fs::read_to_string(path.join("name"))
            .ok()
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let inputs = match std::fs::read_dir(&path) {
            Ok(d) => d,
            Err(_) => continue,
        };
        let mut input_names: Vec<String> = inputs
            .flatten()
            .filter_map(|e| e.file_name().to_str().map(String::from))
            .filter(|n| n.starts_with("temp") && n.ends_with("_input"))
            .collect();
        input_names.sort();
        for input_name in input_names {
            let temp_path = path.join(&input_name);
            let temp_raw = match std::fs::read_to_string(&temp_path) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let temp_milli: i64 = temp_raw.trim().parse().unwrap_or(0);
            let sensor = input_name.trim_end_matches("_input").to_string();
            let label_path = path.join(format!("{}_label", sensor));
            let label = std::fs::read_to_string(&label_path)
                .ok()
                .map(|s| s.trim().to_string())
                .unwrap_or_default();
            out.push((chip.clone(), sensor, label, temp_milli as f64 / 1000.0));
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    out
}

/// Per-CPU current clock frequency from
/// `/sys/devices/system/cpu/cpu*/cpufreq/scaling_cur_freq`.
///
/// Returns `Vec<(cpu_id, hz)>` sorted by cpu_id. Empty Vec when cpufreq
/// is unavailable (most virtualised cloud VPSs
/// have a `cpufreq` directory but no `scaling_cur_freq` file because
/// the hypervisor manages clock and frequency-scaling is opaque to the
/// guest). Live on phone-tier hardware (the local mini-PC, the laptop node, future
/// Pi/RPi) where the cpufreq governor reports the kernel's view of the
/// current clock.
///
/// **Phone-tier value:** this gauge is the *consequence* of thermal
/// throttling. The thermal readers surface temperature; this gauge surfaces
/// what the kernel did about it. Specifically:
///
/// - Temperature climbing past 80 °C while cpufreq drops from 3.5 GHz to
///   2.0 GHz = throttling actively gating the clock right now. The 30-40%
///   silent perf degradation the thermal readers warn about becomes literal:
///   utime grows half as fast as wall-clock.
/// - Cpufreq pinned at scaling_min_freq for sustained periods = something
///   else (PSU rail droop, battery limit, conservative governor) holding
///   the clock down even though thermals are fine.
///
/// Pair with `rate(elara_process_cpu_user_seconds_total[1m])`: at a fixed
/// workload, user-time-rate scales linearly with frequency, so a frequency
/// drop should produce a proportional drop in user-time-rate. If they
/// move out of step, something else is happening (priority changes,
/// scheduler steal, neighboring noisy guest).
///
/// Source: `/sys/devices/system/cpu/cpu*/cpufreq/scaling_cur_freq` is in
/// kHz; we multiply by 1000 to emit Hz per Prometheus naming convention
/// (always SI base unit). At 4 cores × 3.5 GHz that's `3500000000` per
/// row — large numbers but lossless.
fn host_cpu_frequencies() -> Vec<(u32, u64)> {
    let mut out: Vec<(u32, u64)> = Vec::new();
    let dir = match std::fs::read_dir("/sys/devices/system/cpu") {
        Ok(d) => d,
        Err(_) => return out,
    };
    for entry in dir.flatten() {
        let name = entry.file_name();
        let name_str = match name.to_str() {
            Some(s) => s,
            None => continue,
        };
        // Match cpuN where N is digits — skip "cpufreq", "cpuidle", etc.
        let cpu_id: u32 = match name_str.strip_prefix("cpu").and_then(|s| s.parse().ok()) {
            Some(n) => n,
            None => continue,
        };
        let freq_path = entry.path().join("cpufreq").join("scaling_cur_freq");
        let freq_raw = match std::fs::read_to_string(&freq_path) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let khz: u64 = match freq_raw.trim().parse() {
            Ok(n) => n,
            Err(_) => continue,
        };
        out.push((cpu_id, khz.saturating_mul(1000)));
    }
    out.sort_by_key(|t| t.0);
    out
}

/// Process resource limits from `/proc/self/limits`.
///
/// Returns `Vec<(resource_label, soft_limit, hard_limit)>` where
/// `resource_label` is snake_case (e.g. `max_open_files`,
/// `max_address_space`). The kernel reports "unlimited" for ceilings
/// that aren't bounded; we encode that as `u64::MAX` so a single
/// gauge type handles both bounded and unbounded resources without
/// a sentinel value collision (real RLIMIT_NOFILE on Linux is
/// 2^20 — well below u64::MAX).
///
/// Why this is a phone-tier observability gap on the same level
/// as the memory-ceiling and clock-rate-ceiling readers:
/// `RLIMIT_NOFILE` (max_open_files) is the silent strangler at
/// 10K-conn mainnet — when systemd defaults to 1024 fds and the
/// node tries to peer with 8K nodes, the listening socket starts
/// returning EMFILE on accept and the gossip layer goes
/// asymptotically deaf with no other signal. Same shape for
/// `RLIMIT_NPROC` (max_processes — futex contention masquerades
/// as scheduler delay), `RLIMIT_AS` (max_address_space —
/// RocksDB block cache + WAL + memtables push toward ceiling),
/// and `RLIMIT_MEMLOCK` (mmap'd RocksDB SST files). Surfacing
/// these as gauges lets `(used / limit) > 0.8` style alerts fire
/// BEFORE the ceiling is hit, instead of post-hoc forensics from
/// strace.
///
/// `/proc/self/limits` is fixed-width text per the Linux ABI:
/// `[0..26)` = limit name, `[26..47)` = soft, `[47..68)` = hard,
/// `[68..)` = units (sometimes empty for `Max nice priority` /
/// `Max realtime priority`). We don't emit units — the resource
/// name implies the unit and the metric value is the raw integer.
fn process_rlimits() -> Vec<(String, u64, u64)> {
    let raw = std::fs::read_to_string("/proc/self/limits").unwrap_or_default();
    let mut out = Vec::new();
    for (i, line) in raw.lines().enumerate() {
        if i == 0 {
            continue;
        }
        if line.len() < 68 {
            continue;
        }
        let limit_str = line[0..26].trim();
        let soft_str = line[26..47].trim();
        let hard_str = line[47..68].trim();
        if limit_str.is_empty() || soft_str.is_empty() || hard_str.is_empty() {
            continue;
        }
        let label = if let Some(rest) = limit_str.strip_prefix("Max ") {
            format!("max_{}", rest.replace(' ', "_").to_lowercase())
        } else {
            limit_str.replace(' ', "_").to_lowercase()
        };
        let parse_v = |s: &str| -> u64 {
            if s == "unlimited" {
                u64::MAX
            } else {
                s.parse().unwrap_or(0)
            }
        };
        out.push((label, parse_v(soft_str), parse_v(hard_str)));
    }
    out
}

/// Pressure Stall Information from `/proc/pressure/{cpu,memory,io}`.
///
/// Returns 3 `PsiResource` rows, one per resource. Each row has up to two
/// scopes: `some` (≥1 task stalled) and `full` (ALL tasks stalled — only
/// meaningful for memory and io; on cpu the "full" line is absent on
/// kernels <5.13 and zero-by-construction on newer kernels). Each scope
/// carries three exponential-moving averages (10s/60s/300s windows, in
/// percent of wall time, 0.0..100.0) plus a monotonic `total_us` counter.
///
/// PSI is the cleanest "is this node struggling?" signal Linux exposes —
/// 0% across all three resources = headroom; sustained nonzero on memory
/// = swapping or compaction stalls; sustained nonzero on io = disk-bound;
/// sustained nonzero on cpu = scheduler-bound. On phone-tier hardware
/// this is the early-warning system that fires BEFORE the kernel starts
/// killing processes.
///
/// Format from kernel:
///   some avg10=0.41 avg60=0.52 avg300=3.08 total=33996194668
///   full avg10=0.00 avg60=0.00 avg300=0.00 total=0
///
/// Empty vec on kernels <4.20, or in containers with /proc/pressure
/// masked. We emit nothing on those hosts so dashboards just see absent
/// series rather than zeroed-out fake-healthy gauges.
fn host_pressure_stall() -> Vec<PsiResource> {
    let mut out = Vec::with_capacity(3);
    for resource in &["cpu", "memory", "io"] {
        let path = format!("/proc/pressure/{resource}");
        let raw = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let (some, full) = parse_psi_block(&raw);
        if some.is_some() || full.is_some() {
            out.push(PsiResource {
                resource: resource.to_string(),
                some,
                full,
            });
        }
    }
    out
}

#[derive(Debug, Clone)]
struct PsiScope {
    avg10: f64,
    avg60: f64,
    avg300: f64,
    total_us: u64,
}

#[derive(Debug, Clone)]
struct PsiResource {
    resource: String,
    some: Option<PsiScope>,
    full: Option<PsiScope>,
}

fn parse_psi_block(raw: &str) -> (Option<PsiScope>, Option<PsiScope>) {
    let mut some = None;
    let mut full = None;
    for line in raw.lines() {
        let scope = if line.starts_with("some ") {
            "some"
        } else if line.starts_with("full ") {
            "full"
        } else {
            continue;
        };
        let mut avg10 = 0.0_f64;
        let mut avg60 = 0.0_f64;
        let mut avg300 = 0.0_f64;
        let mut total_us: u64 = 0;
        for tok in line.split_whitespace().skip(1) {
            let (k, v) = match tok.split_once('=') {
                Some(p) => p,
                None => continue,
            };
            match k {
                "avg10" => avg10 = v.parse().unwrap_or(0.0),
                "avg60" => avg60 = v.parse().unwrap_or(0.0),
                "avg300" => avg300 = v.parse().unwrap_or(0.0),
                "total" => total_us = v.parse().unwrap_or(0),
                _ => {}
            }
        }
        let entry = PsiScope { avg10, avg60, avg300, total_us };
        match scope {
            "some" => some = Some(entry),
            "full" => full = Some(entry),
            _ => {}
        }
    }
    (some, full)
}

/// Per-cgroup PSI for the elara-node service.
///
/// Auto-discovers the cgroup via `/proc/self/cgroup`, then reads
/// `/sys/fs/cgroup<path>/{cpu,memory,io}.pressure`. Same kernel format as
/// host PSI (the host pressure-stall reader).
///
/// Host PSI shows whole-host stalls; cgroup PSI shows only elara-node's
/// stalls. The cross-table is the diagnostic value:
/// - host high + cgroup high = co-tenant noise AND own work both stalling.
/// - host high + cgroup low  = noisy neighbour, elara-node fine.
/// - host low + cgroup high  = elara-node alone is breaching its cgroup cap
///   (memory.high, cpu.weight, io.weight) — operator must raise the limit.
/// - host low + cgroup low   = healthy.
///
/// Without this, a containerized phone-tier node hitting its `memory.high`
/// cgroup limit looks calm in host PSI (the kernel has free RAM) — and the
/// operator never sees the stall until the OOM-killer fires.
///
/// Empty vec on cgroupv1, on `/proc/self/cgroup` paths we can't parse, or
/// on kernels lacking cgroup PSI (introduced 4.20 same as host PSI).
/// Unconstrained processes in the root cgroup will read identical numbers
/// to host PSI — that's expected behaviour, not a bug.
fn process_cgroup_pressure_stall() -> Vec<PsiResource> {
    let cgroup_raw = match std::fs::read_to_string("/proc/self/cgroup") {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    // cgroupv2: single line `0::/system.slice/elara-node.service`.
    // cgroupv1: multiple lines `N:controller:/path` — abort, no per-cgroup PSI.
    let path = match cgroup_raw.lines().find_map(|l| l.strip_prefix("0::")) {
        Some(p) => p.trim(),
        None => return Vec::new(),
    };
    let base = if path.is_empty() || path == "/" {
        "/sys/fs/cgroup".to_string()
    } else {
        format!("/sys/fs/cgroup{path}")
    };
    let mut out = Vec::with_capacity(3);
    for resource in &["cpu", "memory", "io"] {
        let p = format!("{base}/{resource}.pressure");
        let raw = match std::fs::read_to_string(&p) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let (some, full) = parse_psi_block(&raw);
        if some.is_some() || full.is_some() {
            out.push(PsiResource {
                resource: resource.to_string(),
                some,
                full,
            });
        }
    }
    out
}

/// Sanitize a Prometheus label value: drop newlines and escape backslash and
/// double-quote per `text format` spec (`\\` and `\"`). Used by the thermal-zone
/// reader for the human-readable thermal zone `type` string which may contain spaces or
/// special characters from BIOS/ACPI tables.
fn escape_prom_label(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        match c {
            '\n' => continue,
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            _ => out.push(c),
        }
    }
    out
}

/// Lifetime page-fault counters via `/proc/self/stat`.
///
/// Returns `(minor_faults, major_faults)`. Minor faults resolve via memory
/// reclaim or COW without touching disk and are normal at any rate. Major
/// faults force a synchronous disk read (page swap-in or first-touch of
/// mmap'd file), and a sustained rate above ~100/s = memory thrashing —
/// every record processed is paying for synchronous I/O. On phone-tier
/// nodes the cliff is sharp: rate jumps from 0 to thousands per second
/// once swap pressure starts pulling state_core working set out.
///
/// `/proc/self/stat` field layout: comm is parenthesized and may contain
/// spaces, so we split on the *last* `)` and parse the tail. After the
/// `)`: state ppid pgrp session tty_nr tpgid flags **minflt** cminflt
/// **majflt** ... — minor at index 7 (0-indexed), major at index 9.
fn process_page_faults() -> (u64, u64) {
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
    let tail = stat.rsplit(')').next().unwrap_or("");
    let parts: Vec<&str> = tail.split_whitespace().collect();
    let minflt = parts.get(7).and_then(|s| s.parse().ok()).unwrap_or(0);
    let majflt = parts.get(9).and_then(|s| s.parse().ok()).unwrap_or(0);
    (minflt, majflt)
}

/// Per-process CPU time in seconds — `(user_seconds, system_seconds)`.
///
/// Distinguishes "the box is busy" (covered by `elara_system_load_1m`) from
/// "elara-node itself is busy". Useful when system load looks high but the
/// node looks idle to the operator: rising `elara_process_cpu_user_seconds_total`
/// rate confirms the node IS the load source; a flat counter says the load is
/// some other process and elara-node is fine.
///
/// `/proc/self/stat` field layout (after the last `)`, 0-indexed):
/// state(0) ppid(1) pgrp(2) session(3) tty_nr(4) tpgid(5) flags(6)
/// minflt(7) cminflt(8) majflt(9) cmajflt(10) **utime(11) stime(12)** ...
/// The kernel reports both in clock ticks; convert via sysconf(_SC_CLK_TCK).
/// On every standard Linux kernel SC_CLK_TCK = 100, so the conversion is
/// `ticks / 100` → seconds with 10 ms resolution. We read the actual value
/// via libc rather than hardcoding so PREEMPT_RT or exotic kernel configs
/// where SC_CLK_TCK ≠ 100 still report correct seconds.
fn process_cpu_seconds() -> (f64, f64) {
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
    let tail = stat.rsplit(')').next().unwrap_or("");
    let parts: Vec<&str> = tail.split_whitespace().collect();
    let utime: u64 = parts.get(11).and_then(|s| s.parse().ok()).unwrap_or(0);
    let stime: u64 = parts.get(12).and_then(|s| s.parse().ok()).unwrap_or(0);
    #[cfg(unix)]
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    // No sysconf off-unix; 0 routes to the 100 Hz default (utime/stime are
    // already 0 there — /proc is absent).
    #[cfg(not(unix))]
    let ticks: i64 = 0;
    let hz = if ticks > 0 { ticks as f64 } else { 100.0 };
    (utime as f64 / hz, stime as f64 / hz)
}

/// Per-process I/O bytes from `/proc/self/io` —
/// `(rchar, wchar, read_bytes, write_bytes, syscr, syscw, cancelled_write_bytes)`.
///
/// Lets operators tell apart "lots of cached reads" from "lots of disk
/// reads" — both can look like load, only the second is paying I/O cost.
///
/// The seven counters surfaced from `/proc/self/io`:
/// - `rchar`: bytes read by `read(2)` family (includes hits in the page
///   cache — i.e. fast in-memory reads). Steady growth with low
///   `read_bytes` = warm cache, no disk pressure.
/// - `wchar`: bytes written by `write(2)` family (includes writes that
///   were absorbed by the page cache without yet hitting disk). Steady
///   growth with low `write_bytes` is normal for buffered writes.
/// - `read_bytes`: bytes the kernel actually pulled from the block
///   device for this process. THIS is the disk-read cost. On a phone-tier
///   node, sustained `rate(read_bytes) > 10 MiB/s` while idle = working
///   set has overflowed RAM.
/// - `write_bytes`: bytes the kernel actually flushed to the block
///   device on this process's behalf. Tracks RocksDB WAL append, SST
///   flush, and compaction writes. `rate(write_bytes)` is the canonical
///   "is the disk the bottleneck?" signal — pair with
///   `elara_rocksdb_pending_compaction_bytes` to confirm compactor is
///   keeping up.
/// - `syscr`: count of read(2)-family syscalls. Pair with rchar
///   to compute average bytes/read syscall — RocksDB block reads pull
///   ~64 KB at a time, gossip frame reads ~1 KB; an aggregate average
///   trending toward 1 KB while throughput stays flat = block fetch
///   replaced by per-record header reads (cache miss storm).
/// - `syscw`: count of write(2)-family syscalls. Pair with
///   wchar: low avg bytes/write = chatty fsync rhythm; high avg = RocksDB
///   batched flushes. Sustained syscw rate > 10K/s on phone-tier eMMC =
///   syscall overhead approaching disk-throughput overhead.
/// - `cancelled_write_bytes`: bytes that WERE charged to wchar but never
///   reached the block device, because a truncate(2)/unlink(2) discarded
///   them before the page-cache flush. On a healthy RocksDB node
///   this stays near zero; growth indicates churn from compactor cleanup
///   or temp-file thrash. Subtract from wchar to get a more accurate
///   "writes that actually hit storage" figure.
///
/// `/proc/self/io` is one read per scrape; format is
/// `key: value\n` repeated, easy to parse.
fn process_io_bytes() -> (u64, u64, u64, u64, u64, u64, u64) {
    let raw = std::fs::read_to_string("/proc/self/io").unwrap_or_default();
    parse_proc_self_io(&raw)
}

fn parse_proc_self_io(raw: &str) -> (u64, u64, u64, u64, u64, u64, u64) {
    let mut rchar = 0u64;
    let mut wchar = 0u64;
    let mut read_bytes = 0u64;
    let mut write_bytes = 0u64;
    let mut syscr = 0u64;
    let mut syscw = 0u64;
    let mut cancelled_write_bytes = 0u64;
    for line in raw.lines() {
        let mut parts = line.splitn(2, ':');
        let key = parts.next().unwrap_or("").trim();
        let value: u64 = parts.next().unwrap_or("").trim().parse().unwrap_or(0);
        match key {
            "rchar" => rchar = value,
            "wchar" => wchar = value,
            "read_bytes" => read_bytes = value,
            "write_bytes" => write_bytes = value,
            "syscr" => syscr = value,
            "syscw" => syscw = value,
            "cancelled_write_bytes" => cancelled_write_bytes = value,
            _ => {}
        }
    }
    (rchar, wchar, read_bytes, write_bytes, syscr, syscw, cancelled_write_bytes)
}

/// Aggregate network bytes/drops across non-loopback interfaces, from
/// `/proc/net/dev` — `(rx_bytes, tx_bytes, rx_drops, tx_drops)`.
///
/// Skips `lo` so we surface only real network egress/ingress; tailscale,
/// wireguard, eth, and tun all sum into the totals. The two byte counters
/// give the operator a rate signal (`rate(tx_bytes) > device-budget × 0.5`
/// → outbound-saturation alert before gossip queues build up). The two drop
/// counters are the leading indicator the kernel is dropping packets the
/// process couldn't accept fast enough — `rate(rx_drops) > 0` means we're
/// either pinned on CPU or the qdisc is full, both of which precede gossip
/// loss.
///
/// Format from `/proc/net/dev` (header is 2 lines, then one row per iface):
///   `face: rx_bytes rx_pkts rx_errs rx_drop rx_fifo rx_frame rx_compressed rx_multicast tx_bytes tx_pkts tx_errs tx_drop ...`
///
/// At 10K+ node mainnet scale outbound saturation is THE constraint — phone-
/// tier uplinks (~50–500 KB/s sustained) get hammered by gossip + records
/// long before the node is CPU-bound, and `tx_drop` is the first place the
/// kernel reports it. Pair with `elara_gossip_bytes_out_kind_total` to see
/// *what* is consuming the budget.
fn process_net_bytes() -> (u64, u64, u64, u64) {
    let mut rx_bytes = 0u64;
    let mut tx_bytes = 0u64;
    let mut rx_drops = 0u64;
    let mut tx_drops = 0u64;
    if let Ok(dev) = std::fs::read_to_string("/proc/net/dev") {
        for line in dev.lines().skip(2) {
            let mut split = line.splitn(2, ':');
            let iface = split.next().unwrap_or("").trim();
            if iface.is_empty() || iface == "lo" {
                continue;
            }
            let rest = split.next().unwrap_or("");
            let cols: Vec<&str> = rest.split_whitespace().collect();
            // 0:rx_bytes 1:rx_pkts 2:rx_errs 3:rx_drop ...
            // 8:tx_bytes 9:tx_pkts 10:tx_errs 11:tx_drop
            if cols.len() >= 12 {
                rx_bytes = rx_bytes.saturating_add(cols[0].parse().unwrap_or(0));
                rx_drops = rx_drops.saturating_add(cols[3].parse().unwrap_or(0));
                tx_bytes = tx_bytes.saturating_add(cols[8].parse().unwrap_or(0));
                tx_drops = tx_drops.saturating_add(cols[11].parse().unwrap_or(0));
            }
        }
    }
    (rx_bytes, tx_bytes, rx_drops, tx_drops)
}

/// TCP connection-state inventory across IPv4 + IPv6 sockets, from
/// `/proc/net/tcp` + `/proc/net/tcp6` — `(established, time_wait, close_wait,
/// syn_recv, listen)`.
///
/// Five states out of the eleven Linux exposes — these are the ones that
/// matter on a gossip-heavy node:
/// - `ESTABLISHED` (0x01): currently-active peer connections. The natural
///   ceiling is the peer-count target × (gossip + RPC + WS) channels.
/// - `TIME_WAIT` (0x06): recently-closed sockets in 2×MSL wait. High count
///   = high connection churn — typically a peer aggressively reconnecting
///   or a short-lived RPC client looping. Hits the local port-range ceiling
///   (~28K ephemeral ports) before EMFILE does.
/// - `CLOSE_WAIT` (0x08): peer closed but our app hasn't `close()`d. CLIMBING
///   `CLOSE_WAIT` is a socket leak — the canonical "we're going to run out of
///   FDs" leading indicator. Pair with `elara_process_open_fds` to
///   see the FD pressure landing.
/// - `SYN_RECV` (0x03): half-open during handshake. Climbing = SYN backlog
///   filling, either a SYN flood or a misbehaving peer storm. The kernel
///   will start dropping new SYNs once the listen backlog overflows.
/// - `LISTEN` (0x0A): listener sockets. Should be a small fixed number
///   matching our bound services; non-stationary count = a service is
///   spinning listeners up/down unexpectedly.
///
/// `/proc/net/tcp` line shape: `sl local rem st tx_queue rx_queue tr tm
/// retrnsmt uid timeout inode ...`. Column 3 (`st`) is the state code as a
/// 2-char hex byte. Cost is bounded: O(open sockets); on a 10K-peer node
/// that's ~10K lines and ~50 µs to read both files.
fn process_tcp_states() -> (u64, u64, u64, u64, u64) {
    let mut established = 0u64;
    let mut time_wait = 0u64;
    let mut close_wait = 0u64;
    let mut syn_recv = 0u64;
    let mut listen = 0u64;
    for path in &["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(content) = std::fs::read_to_string(path) {
            for line in content.lines().skip(1) {
                let cols: Vec<&str> = line.split_whitespace().collect();
                if let Some(state) = cols.get(3) {
                    match *state {
                        "01" => established += 1,
                        "03" => syn_recv += 1,
                        "06" => time_wait += 1,
                        "08" => close_wait += 1,
                        "0A" => listen += 1,
                        _ => {}
                    }
                }
            }
        }
    }
    (established, time_wait, close_wait, syn_recv, listen)
}

/// Kernel Pressure Stall Information from
/// `/proc/pressure/{cpu,memory,io}`. Returns the 10-second "some" and
/// "full" avg fractions for cpu, memory, and io (six values). Returns
/// 0.0 on each axis if PSI is unavailable (CONFIG_PSI=n on older kernels;
/// /proc/pressure not exposed in unprivileged containers).
///
/// PSI is THE phone-tier early-warning signal. RSS, page faults, and
/// swap describe the *process* state; PSI measures *kernel back-pressure*
/// — what percentage of the last 10s tasks were stalled waiting on cpu,
/// memory, or io. Kernel reports as percent in [0.0, 100.0] (avg10=0.53
/// = 0.53% of the window stalled). Healthy steady-state is near zero on
/// all six. Sustained `some` > 10 = at least one task stalled ≥10% of
/// the time on that resource; `full` > 5 = ALL runnable tasks stalled
/// ≥5% of the time = system effectively wedged. PSI catches contention
/// well before RSS/CPU saturate — the canonical use is "set an alert on
/// memory.full > 10 to page operator before OOM kicks in".
///
/// /proc/pressure/cpu line shape: `some avg10=0.53 avg60=0.49 avg300=0.57
/// total=30743040510`. Two lines per file (some, full); we extract avg10
/// from each. Cost is bounded: 3× tiny file reads (<1KB each), parse-once
/// per /metrics scrape. Safe in containers — read fails are 0.0, not
/// panic.
fn process_pressure_stats() -> (f64, f64, f64, f64, f64, f64) {
    fn parse_avg10(content: &str) -> (f64, f64) {
        let mut some = 0.0;
        let mut full = 0.0;
        for line in content.lines() {
            let mut parts = line.split_whitespace();
            let label = match parts.next() {
                Some(s) => s,
                None => continue,
            };
            for tok in parts {
                if let Some(rest) = tok.strip_prefix("avg10=") {
                    let v = rest.parse::<f64>().unwrap_or(0.0);
                    match label {
                        "some" => some = v,
                        "full" => full = v,
                        _ => {}
                    }
                }
            }
        }
        (some, full)
    }
    let (mut cpu_some, mut cpu_full) = (0.0, 0.0);
    let (mut mem_some, mut mem_full) = (0.0, 0.0);
    let (mut io_some, mut io_full) = (0.0, 0.0);
    if let Ok(c) = std::fs::read_to_string("/proc/pressure/cpu") {
        let (s, f) = parse_avg10(&c);
        cpu_some = s;
        cpu_full = f;
    }
    if let Ok(c) = std::fs::read_to_string("/proc/pressure/memory") {
        let (s, f) = parse_avg10(&c);
        mem_some = s;
        mem_full = f;
    }
    if let Ok(c) = std::fs::read_to_string("/proc/pressure/io") {
        let (s, f) = parse_avg10(&c);
        io_some = s;
        io_full = f;
    }
    (cpu_some, cpu_full, mem_some, mem_full, io_some, io_full)
}

/// OOM-imminence + page-cache pressure from
/// `/proc/self/oom_score`, `/proc/self/oom_score_adj`, and
/// `/proc/meminfo`. Returns (oom_score, oom_score_adj, dirty_kb,
/// writeback_kb, cached_kb). All zeros on read failure (containers,
/// non-Linux).
///
/// `oom_score` is THE direct OOM-kill imminence signal — the kernel
/// computes it continuously; when memory pressure forces an eviction
/// decision, the process with the highest score is killed. Range is
/// effectively 0..1500 (RSS-percent + adj). Pairs with PSI memory.full:
/// PSI tells you the kernel is *trying* to reclaim, oom_score tells you
/// who is the *target* if reclaim fails. On a phone-tier node with two
/// hot tenants (elara-node + a sidecar) these two metrics together
/// answer "is OOM imminent and is it us being killed".
///
/// `oom_score_adj` is the operator-tunable knob set by the systemd unit
/// (`OOMScoreAdjust=`) or `prlimit`. Surface it so /metrics shows
/// whether the protection the operator *thinks* is in place actually
/// landed — a unit-file typo silently leaves the runtime at default 0.
///
/// `Dirty` + `Writeback` from /proc/meminfo are the canonical
/// page-cache writeback-throttle signals. RocksDB writes go through
/// page cache; if Dirty grows unboundedly the kernel throttles writers
/// (writeback congestion). Sustained high Dirty is the leading
/// indicator that fsync rhythm cannot keep up with submission rate —
/// disk-bound, even if PSI io has not yet spiked.
fn process_oom_state() -> (i32, i32, u64, u64, u64) {
    let oom_score: i32 = std::fs::read_to_string("/proc/self/oom_score")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);
    let oom_score_adj: i32 = std::fs::read_to_string("/proc/self/oom_score_adj")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);
    let mut dirty_kb: u64 = 0;
    let mut writeback_kb: u64 = 0;
    let mut cached_kb: u64 = 0;
    if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
        for line in meminfo.lines() {
            let mut parts = line.split_whitespace();
            let key = match parts.next() {
                Some(k) => k,
                None => continue,
            };
            let val: u64 = parts
                .next()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            match key {
                "Dirty:" => dirty_kb = val,
                "Writeback:" => writeback_kb = val,
                "Cached:" => cached_kb = val,
                _ => {}
            }
        }
    }
    (oom_score, oom_score_adj, dirty_kb, writeback_kb, cached_kb)
}

/// Host TCP/UDP error counters from `/proc/net/snmp`.
/// Returns `(tcp_retrans_segs, tcp_out_segs, tcp_attempt_fails,
/// tcp_curr_estab, tcp_out_rsts, udp_rcvbuf_errors)`.
///
/// `RetransSegs / OutSegs` is the canonical TCP retransmit rate. Healthy
/// nodes < 1% sustained; sustained > 2% = NIC saturation, network-path
/// degradation, or peer-side congestion. Distinct from the per-process
/// bandwidth and socket-inventory readers — those say WHAT we sent;
/// this says how cleanly the kernel + network delivered it.
///
/// `AttemptFails` is the outbound-connectivity failure counter (SYN sent,
/// no SYN+ACK received, connection abandoned). High rate(AttemptFails) /
/// rate(ActiveOpens) = peer addresses are stale, peers crashed, or the
/// outbound NAT is dropping fresh flows.
///
/// `CurrEstab` is the LIVE TCP connection count gauge — distinct from
/// the socket-state inventory which is per-state. Useful as a single
/// scalar for dashboards.
///
/// `OutRsts` is the count of TCP RST packets we sent. RST is the kernel's
/// "this segment doesn't match any open connection" reply; sustained high
/// rate(OutRsts) = stale peer state on the other side, or scanning
/// attempts. Operator playbook: rate(OutRsts) > 5/sec sustained = peer
/// gossip protocol is leaking dead-peer addresses.
///
/// `Udp.RcvbufErrors` counts datagrams DROPPED because the kernel UDP
/// receive buffer overflowed (i.e., we couldn't read fast enough). Direct
/// signal of UDP pipeline saturation. Pair with the per-interface packet-drop
/// counters.
fn host_tcp_udp_state() -> (u64, u64, u64, u64, u64, u64) {
    let snmp = std::fs::read_to_string("/proc/net/snmp").unwrap_or_default();
    let mut tcp_retrans = 0u64;
    let mut tcp_out = 0u64;
    let mut tcp_fails = 0u64;
    let mut tcp_estab = 0u64;
    let mut tcp_rsts = 0u64;
    let mut udp_rcvbuf = 0u64;
    // SNMP format: header line "Tcp: RtoAlgorithm RtoMin ..." followed by
    // a value line "Tcp: 1 200 ...". Same prefix differentiates the two.
    let mut tcp_hdr: Option<Vec<&str>> = None;
    let mut udp_hdr: Option<Vec<&str>> = None;
    for line in snmp.lines() {
        if let Some(rest) = line.strip_prefix("Tcp: ") {
            let parts: Vec<&str> = rest.split_whitespace().collect();
            match tcp_hdr {
                None => tcp_hdr = Some(parts),
                Some(ref hdr) => {
                    for (i, name) in hdr.iter().enumerate() {
                        if let Some(v) = parts.get(i).and_then(|s| s.parse::<u64>().ok()) {
                            match *name {
                                "RetransSegs" => tcp_retrans = v,
                                "OutSegs" => tcp_out = v,
                                "AttemptFails" => tcp_fails = v,
                                "CurrEstab" => tcp_estab = v,
                                "OutRsts" => tcp_rsts = v,
                                _ => {}
                            }
                        }
                    }
                    tcp_hdr = None;
                }
            }
        } else if let Some(rest) = line.strip_prefix("Udp: ") {
            let parts: Vec<&str> = rest.split_whitespace().collect();
            match udp_hdr {
                None => udp_hdr = Some(parts),
                Some(ref hdr) => {
                    for (i, name) in hdr.iter().enumerate() {
                        if *name == "RcvbufErrors" {
                            if let Some(v) = parts.get(i).and_then(|s| s.parse::<u64>().ok()) {
                                udp_rcvbuf = v;
                            }
                        }
                    }
                    udp_hdr = None;
                }
            }
        }
    }
    (tcp_retrans, tcp_out, tcp_fails, tcp_estab, tcp_rsts, udp_rcvbuf)
}

/// Host TCP "deeper" counters from `/proc/net/netstat` `TcpExt:`.
///
/// Returns `(listen_overflows, listen_drops, tcp_timeouts,
/// tcp_memory_pressures, tcp_abort_on_memory)`.
///
/// Selected for highest actionability at 10K-peer mesh scale; the snmp
/// reader already covers `RetransSegs`/`OutSegs`/`AttemptFails`/`CurrEstab`/
/// `OutRsts`/`UdpRcvbufErrors` — those say "is the network path clean."
/// These say "is the LOCAL TCP stack still admitting traffic."
///
/// - `ListenOverflows`: accept-queue full at the moment a SYN+ACK should
///   be moved into ESTABLISHED. Bounded by `min(somaxconn, listen()
///   backlog)`. When this counter moves, peers retry-but-eventually-
///   give-up; on a mesh this looks like "peer count plateaued without
///   us making any code change."
/// - `ListenDrops`: superset of overflows + memory-pressure drops.
///   Divergence from `ListenOverflows` = drops are not queue but
///   resource-pressure (can't allocate sock_alloc).
/// - `TCPTimeouts`: count of RTO firings (retransmission timeout). Each
///   RTO doubles the timer, so the rate is a damped signal — but
///   sustained > 0 means at least one peer's TCP path has degraded
///   beyond what fast-retransmit recovers. Pair with rate(RetransSegs)
///   from the snmp reader: high RetransSegs + low TCPTimeouts = packet loss
///   recovered cleanly; high RetransSegs + high TCPTimeouts = path is
///   collapsing.
/// - `TCPMemoryPressures`: count of times the TCP stack entered the
///   memory-pressure mode (alloc crossed `tcp_mem[1]`, the soft
///   threshold). Each entry triggers buffer shrinking: existing
///   connections silently degrade. Counter moves once per cycle, not
///   per byte — small numbers are still significant.
/// - `TCPAbortOnMemory`: connections aborted because the kernel could
///   not allocate buffer space for them. Direct signal of OOM-class
///   socket failure: the next peer to send a segment had its connection
///   killed.
fn host_tcp_netstat_extras() -> (u64, u64, u64, u64, u64) {
    let raw = std::fs::read_to_string("/proc/net/netstat").unwrap_or_default();
    parse_tcp_netstat_extras(&raw)
}

fn parse_tcp_netstat_extras(raw: &str) -> (u64, u64, u64, u64, u64) {
    let mut listen_overflows = 0u64;
    let mut listen_drops = 0u64;
    let mut tcp_timeouts = 0u64;
    let mut tcp_mem_pressure = 0u64;
    let mut tcp_abort_on_mem = 0u64;
    let mut hdr: Option<Vec<&str>> = None;
    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("TcpExt: ") {
            let parts: Vec<&str> = rest.split_whitespace().collect();
            match hdr {
                None => hdr = Some(parts),
                Some(ref h) => {
                    for (i, name) in h.iter().enumerate() {
                        if let Some(v) = parts.get(i).and_then(|s| s.parse::<u64>().ok()) {
                            match *name {
                                "ListenOverflows" => listen_overflows = v,
                                "ListenDrops" => listen_drops = v,
                                "TCPTimeouts" => tcp_timeouts = v,
                                "TCPMemoryPressures" => tcp_mem_pressure = v,
                                "TCPAbortOnMemory" => tcp_abort_on_mem = v,
                                _ => {}
                            }
                        }
                    }
                    hdr = None;
                }
            }
        }
    }
    (
        listen_overflows,
        listen_drops,
        tcp_timeouts,
        tcp_mem_pressure,
        tcp_abort_on_mem,
    )
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct TcpDropCounters {
    syn_retrans: u64,
    rcv_q_drop: u64,
    backlog_drop: u64,
    pf_memalloc_drop: u64,
    spurious_rtos: u64,
    lost_retransmit: u64,
}

/// Host TCP drop-class counters from
/// `/proc/net/netstat` `TcpExt:`. Distinct from the deeper-counters reader which is the
/// "is the local stack admitting traffic" counter set; these are the
/// "what is silently degrading" counters at 10K-peer mesh fanout.
///
/// - `TCPSynRetrans`: SYN retransmissions during connect(). Each retry
///   doubles the timeout per RFC 6298 (1 → 2 → 4 → 8 …). At 10K-peer
///   target fanout, "I can only reach 7K of 10K peers" looks identical
///   to "I'm fine at 7K and the other 3K are intentionally not connected"
///   without this counter — once it moves, the 3K gap is dial-time loss
///   and a peer-discovery degradation, not policy.
/// - `TCPRcvQDrop`: packets dropped because the per-socket receive queue
///   was full at the time the segment arrived. Direct signal that the
///   userspace consumer (Tokio task pool) is not draining recv buffers
///   fast enough — back-pressure has reached the kernel. Pair with
///   elara_process_threads and PSI cpu to locate
///   the cause: high recvq drops + low cgroup PSI cpu = userspace task
///   blocked on something other than CPU (mutex, fs, IPC).
/// - `TCPBacklogDrop`: segments dropped at the per-socket *backlog* —
///   the kernel-side temporary queue used while the socket lock is held
///   by another path. Distinct from RcvQDrop: backlog drops mean the
///   socket's own producer/consumer are racing under contention, not
///   that the consumer is slow. Almost always indicates a hot socket
///   (one peer flooding) with no local-side back-pressure escape.
/// - `PFMemallocDrop`: kernel dropped a packet because allocating the
///   skb would have required dipping into the PF_MEMALLOC reserve
///   (memory-pressure emergency pool). The hardest signal in this set:
///   the kernel itself was out of memory for socket buffers; even
///   ESTABLISHED connections are starting to fail forward. On phone-
///   tier this typically fires moments before OOM-kill. Treat any
///   nonzero value as page-an-operator territory.
/// - `TCPSpuriousRTOs`: false retransmission-timeout firings — the RTO
///   fired but the original ACK was just delayed (network jitter, not
///   loss). Counter goes up under intercontinental-link variance
///   without any actual packet loss. Correlation:
///   high SpuriousRTOs + low TCPTimeouts = jitter not loss;
///   high SpuriousRTOs + high TCPTimeouts = both, path is bad.
/// - `TCPLostRetransmit`: a retransmitted segment was itself lost. The
///   path is collapsing — fast-retransmit's recovery mechanism has
///   degraded to "send the same packet 3+ times before getting through".
///   At 10K-peer mesh we expect this to be near-zero per peer; non-zero
///   sustained = WAN-link congestion or an adversarial intermediary.
fn host_tcp_drops() -> TcpDropCounters {
    let raw = std::fs::read_to_string("/proc/net/netstat").unwrap_or_default();
    parse_tcp_drops(&raw)
}

fn parse_tcp_drops(raw: &str) -> TcpDropCounters {
    let mut out = TcpDropCounters::default();
    let mut hdr: Option<Vec<&str>> = None;
    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("TcpExt: ") {
            let parts: Vec<&str> = rest.split_whitespace().collect();
            match hdr {
                None => hdr = Some(parts),
                Some(ref h) => {
                    for (i, name) in h.iter().enumerate() {
                        if let Some(v) = parts.get(i).and_then(|s| s.parse::<u64>().ok()) {
                            match *name {
                                "TCPSynRetrans" => out.syn_retrans = v,
                                "TCPRcvQDrop" => out.rcv_q_drop = v,
                                "TCPBacklogDrop" => out.backlog_drop = v,
                                "PFMemallocDrop" => out.pf_memalloc_drop = v,
                                "TCPSpuriousRTOs" => out.spurious_rtos = v,
                                "TCPLostRetransmit" => out.lost_retransmit = v,
                                _ => {}
                            }
                        }
                    }
                    hdr = None;
                }
            }
        }
    }
    out
}

/// TCP loss-recovery + ECN counters from
/// `/proc/net/netstat` `TcpExt:`. Phone-tier wireless networks reorder
/// heavily (cellular handovers, multi-path) and modern carrier paths
/// negotiate AQM (Active Queue Management) which signals congestion via
/// the ECN-CE bit instead of dropping packets. Without these counters
/// we cannot tell "AQM is dropping us" from "the link is collapsing".
///
/// - `TCPDelivered`: bytes delivered to the application (cumulative ACK
///   + SACK accounting). The denominator for the CE rate.
/// - `TCPDeliveredCE`: of those, how many were marked with the
///   Congestion Experienced bit by an in-path AQM. The CE/Delivered
///   ratio is the ECN signal: 0% = no AQM in path, low % = AQM healthy,
///   sustained high % = path is congested and AQM is back-pressuring us.
///   Mobile/cellular paths typically negotiate ECN; wired data centres
///   often don't.
/// - `TCPLossProbes`: TLP (Tail Loss Probe, RFC 8985) probes fired. TLP
///   sends a probe segment to detect tail loss without waiting for the
///   full RTO. Counter rate = how often the kernel suspects tail loss.
/// - `TCPLossProbeRecovery`: TLP probes that successfully recovered the
///   loss. Ratio LossProbeRecovery/LossProbes is TLP effectiveness; low
///   ratio means probes are firing but not finding the gap, network
///   path is producing real loss not jitter.
/// - `TCPSACKReorder`: events where SACK-driven re-ordering detection
///   fired. Distinct from drops: reorder events mean the segments
///   arrived but out-of-order, requiring resequencing before delivery.
///   Wireless paths and Linux SO_REUSEPORT load-balancing both
///   produce reordering; rate spikes indicate either path-quality
///   regression OR a misconfigured ECMP load-balancer in the path.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct TcpRecoveryStats {
    delivered: u64,
    delivered_ce: u64,
    loss_probes: u64,
    loss_probe_recovery: u64,
    sack_reorder: u64,
}
fn host_tcp_recovery() -> TcpRecoveryStats {
    let raw = std::fs::read_to_string("/proc/net/netstat").unwrap_or_default();
    parse_tcp_recovery(&raw)
}
fn parse_tcp_recovery(raw: &str) -> TcpRecoveryStats {
    let mut out = TcpRecoveryStats::default();
    let mut hdr: Option<Vec<&str>> = None;
    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("TcpExt: ") {
            let parts: Vec<&str> = rest.split_whitespace().collect();
            match hdr {
                None => hdr = Some(parts),
                Some(ref h) => {
                    for (i, name) in h.iter().enumerate() {
                        if let Some(v) = parts.get(i).and_then(|s| s.parse::<u64>().ok()) {
                            match *name {
                                "TCPDelivered" => out.delivered = v,
                                "TCPDeliveredCE" => out.delivered_ce = v,
                                "TCPLossProbes" => out.loss_probes = v,
                                "TCPLossProbeRecovery" => out.loss_probe_recovery = v,
                                "TCPSACKReorder" => out.sack_reorder = v,
                                _ => {}
                            }
                        }
                    }
                    hdr = None;
                }
            }
        }
    }
    out
}

/// Host IP-layer packet pipeline counters from
/// `/proc/net/snmp` `Ip:`. Sits below the TCP-layer readers —
/// surfaces packets dropped, header errors, fragmentation/reassembly
/// failures, and out-of-route discards that NEVER reach the TCP counters.
/// At 10K-peer fanout these are tail-latency root causes invisible from
/// above: a saturated upstream pipe drops at the IP layer (InDiscards) and
/// the TCP-layer counters only show "retransmit went up" without the
/// upstream cause; a misconfigured MTU breaks fragmentation reassembly
/// (ReasmFails) and TCP sees inflated RTT without knowing why.
///
/// All ten fields are RFC 1213 / RFC 2011 standard counters, supported
/// since the earliest cgroup-v2 kernels. We pick:
///
/// - `InReceives`: total IP datagrams arriving at this host (denominator).
/// - `InHdrErrors`: IP datagrams discarded due to header errors (bad version,
///   bad checksum, truncated header). Sustained > 0 = link/driver corruption
///   OR an attacker probing with malformed packets.
/// - `InAddrErrors`: discarded due to wrong destination address (we got a
///   packet that wasn't addressed to us, e.g. promiscuous mode picked it
///   up but routing didn't accept). Sustained nonzero = a peer is sending
///   to a stale or misconfigured address.
/// - `InDiscards`: input packets the kernel dropped due to LOCAL resource
///   exhaustion (mostly `dst_alloc` failures, route cache pressure). The
///   IP-layer equivalent of TCP backlog drops. ANY non-zero rate at the
///   10K-peer scale is a SEV2 — the kernel is dropping before we even
///   get to look at the packet.
/// - `InDelivers`: input packets successfully handed to upper layers
///   (TCP/UDP/ICMP). The numerator for delivery efficiency:
///   delivered/received ratio < 99% sustained = something is dropping.
/// - `OutRequests`: locally-generated datagrams given to the IP layer for
///   transmission. Pairs with `OutDiscards` to compute send-side drop rate.
/// - `OutDiscards`: outbound datagrams dropped due to local resource
///   exhaustion (egress queue full, route lookup failure, dst alloc
///   failure). At 10K outbound conns this fires when txqueuelen is too
///   small or the egress NIC is saturated.
/// - `OutNoRoutes`: outbound packets dropped because no route was found.
///   The "you're trying to send to a peer the routing table doesn't know
///   how to reach" counter — gossip-table sync skew, stale peer addresses,
///   network-partition recovery period.
/// - `ReasmFails`: IP fragment reassembly failures (timeout waiting for
///   missing fragment, conflict, table full). UDP-heavy workloads care
///   about this. TCP fragments are rare (PMTUd succeeds usually); if this
///   climbs on a TCP-mostly workload, MTU configuration is wrong upstream.
/// - `FragFails`: locally-generated packets that needed fragmentation but
///   couldn't be fragmented (DF bit set + packet larger than next-hop
///   MTU). Symptom of PMTU discovery breakage.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct HostIpStats {
    in_receives: u64,
    in_hdr_errors: u64,
    in_addr_errors: u64,
    in_discards: u64,
    in_delivers: u64,
    out_requests: u64,
    out_discards: u64,
    out_no_routes: u64,
    reasm_fails: u64,
    frag_fails: u64,
}
fn host_ip_stats() -> HostIpStats {
    let raw = std::fs::read_to_string("/proc/net/snmp").unwrap_or_default();
    parse_host_ip_stats(&raw)
}
fn parse_host_ip_stats(raw: &str) -> HostIpStats {
    let mut out = HostIpStats::default();
    let mut hdr: Option<Vec<&str>> = None;
    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("Ip: ") {
            let parts: Vec<&str> = rest.split_whitespace().collect();
            match hdr {
                None => hdr = Some(parts),
                Some(ref h) => {
                    for (i, name) in h.iter().enumerate() {
                        if let Some(v) = parts.get(i).and_then(|s| s.parse::<u64>().ok()) {
                            match *name {
                                "InReceives" => out.in_receives = v,
                                "InHdrErrors" => out.in_hdr_errors = v,
                                "InAddrErrors" => out.in_addr_errors = v,
                                "InDiscards" => out.in_discards = v,
                                "InDelivers" => out.in_delivers = v,
                                "OutRequests" => out.out_requests = v,
                                "OutDiscards" => out.out_discards = v,
                                "OutNoRoutes" => out.out_no_routes = v,
                                "ReasmFails" => out.reasm_fails = v,
                                "FragFails" => out.frag_fails = v,
                                _ => {}
                            }
                        }
                    }
                    hdr = None;
                }
            }
        }
    }
    out
}

/// Host UDP-layer datagram counters from
/// `/proc/net/snmp` `Udp:`. Complements the snmp reader (which only exposes
/// `RcvbufErrors`) and the `/proc/net/sockstat` UDP socket inventory
/// with the full Layer-4 UDP-pipeline picture.
///
/// UDP is the second-most-important transport surface: gossip protocols,
/// time-sync, DNS, ICMP-as-tunnel — none retry at the transport layer, so
/// a UDP drop is a permanent loss of that record from the upper layer's
/// perspective. Without these counters we cannot tell "the network never
/// delivered the packet" (InDatagrams flat, peer-side issue) from "we
/// dropped it in our own stack" (InErrors moving) from "no listener was
/// bound" (NoPorts moving — peer is sending to a closed port).
///
/// Selected fields:
/// - `InDatagrams`: total UDP packets delivered to applications. Send-side
///   denominator pair: rate(in_datagrams)/rate(in_receives_ip) ratio
///   (with the IP-layer in_receives) gives "what fraction of our IP traffic
///   was UDP" — useful for triaging "TCP-vs-UDP-dominant" load.
/// - `NoPorts`: UDP datagrams arrived for an unbound port. The kernel
///   responds with ICMP Port-Unreachable and increments this counter.
///   Sustained nonzero = a peer is sending to a stale endpoint (port was
///   closed since last gossip refresh) OR a scanner is probing. At 10K-
///   peer fanout this surfaces gossip-table rot — peers learn we used to
///   listen on a port we no longer do.
/// - `InErrors`: UDP datagrams discarded due to bad checksum, truncated
///   header, or malformed length. Distinct from RcvbufErrors (kernel had
///   no buffer space) and NoPorts (no listener) — InErrors means the
///   packet itself was bad. Sustained nonzero = layer-2 corruption OR an
///   attacker probing for parser bugs in our gossip dispatcher. SEV3.
/// - `OutDatagrams`: UDP packets transmitted from this host. Send-side
///   denominator. Pairs with `SndbufErrors` to compute send-failure rate.
/// - `SndbufErrors`: UDP datagrams that could not be sent because the
///   send buffer was full. Distinct from RcvbufErrors (receive side).
///   The 'we tried to gossip but our outbound UDP buffer was full'
///   counter — fires when the application sends UDP faster than the
///   kernel can move it onto the wire (NIC saturated, txqueuelen tight,
///   or PSI io blocking the interrupt path). Sustained > 0 = upgrade
///   `net.core.wmem_max` or shed UDP fanout.
/// - `MemErrors`: UDP datagrams dropped because socket-buffer allocation
///   failed (we crossed `net.ipv4.udp_mem` `pressure`/`high` threshold).
///   The UDP equivalent of TCP `TCPMemoryPressures` +
///   `TCPAbortOnMemory` rolled into one. ANY nonzero rate = SEV2 — the
///   kernel is starving for memory mid-UDP-handling, frames lost.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct HostUdpStats {
    in_datagrams: u64,
    no_ports: u64,
    in_errors: u64,
    out_datagrams: u64,
    sndbuf_errors: u64,
    mem_errors: u64,
}
fn host_udp_stats() -> HostUdpStats {
    let raw = std::fs::read_to_string("/proc/net/snmp").unwrap_or_default();
    parse_host_udp_stats(&raw)
}
fn parse_host_udp_stats(raw: &str) -> HostUdpStats {
    let mut out = HostUdpStats::default();
    let mut hdr: Option<Vec<&str>> = None;
    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("Udp: ") {
            let parts: Vec<&str> = rest.split_whitespace().collect();
            match hdr {
                None => hdr = Some(parts),
                Some(ref h) => {
                    for (i, name) in h.iter().enumerate() {
                        if let Some(v) = parts.get(i).and_then(|s| s.parse::<u64>().ok()) {
                            match *name {
                                "InDatagrams" => out.in_datagrams = v,
                                "NoPorts" => out.no_ports = v,
                                "InErrors" => out.in_errors = v,
                                "OutDatagrams" => out.out_datagrams = v,
                                "SndbufErrors" => out.sndbuf_errors = v,
                                "MemErrors" => out.mem_errors = v,
                                _ => {}
                            }
                        }
                    }
                    hdr = None;
                }
            }
        }
    }
    out
}

/// Host ICMP-layer counters from `/proc/net/snmp` `Icmp:`.
/// Rounds out the L3/L4 telemetry triad (IP / UDP / TCP / ICMP). ICMP is the
/// kernel's out-of-band channel for path errors — `InDestUnreachs` /
/// `InTimeExcds` are the "peers / routers told us they couldn't deliver"
/// signal, distinct from anything visible at the IP or UDP layer because the
/// failure happened *off* this host.
///
/// Selected fields (9 of 29 — we keep the operationally-actionable ones, the
/// rest are echo-request/reply / address-mask probes that have near-zero
/// signal on a server workload):
///
/// - `InMsgs`: total ICMP packets received. Receive-side denominator.
/// - `InErrors`: ICMP messages dropped due to packet-level errors (the ICMP
///   counter equivalent of `Udp:InErrors`). Sustained > 0 = link-layer
///   corruption deep enough to slip past the IP-checksum stage.
/// - `InCsumErrors`: ICMP messages with bad checksum. Subset of InErrors with
///   the specific cause; useful to discriminate "checksum offload bug on the
///   NIC" from "general malformed-packet pattern" (attacker probe).
/// - `InDestUnreachs`: ICMP Destination-Unreachable messages we received.
///   THE canonical "I tried to reach a peer and the network told me no"
///   counter. Each event = a peer/router told us our outbound packet
///   couldn't reach its destination — port closed (peer offline), host
///   unreachable (NAT pinhole closed, peer firewall), or fragmentation
///   needed and DF set (PMTU black hole). At 10K-peer fanout this is the
///   first signal that gossip-table entries have rotted faster than our
///   refresh cadence. Distinct from `Udp:NoPorts` (which fires when a
///   peer probes US for an unbound port) — that triggers an OUTGOING
///   Dest-Unreach on our side; this counter is the inverse direction.
/// - `InTimeExcds`: ICMP Time-Exceeded messages received. TTL hit zero on
///   one of our outbound packets and a router along the path told us. Two
///   common causes: (a) a peer's network has a routing loop (rare in
///   production but real on misconfigured BGP edges), or (b) we're
///   intentionally probing with traceroute-like low TTL. Sustained nonzero
///   on a non-traceroute workload = SEV3, page network ops.
/// - `InRedirects`: ICMP Redirect messages received. A router told us
///   "use a different next-hop for that destination." Modern hardened
///   networks reject these (Linux default since 2009: `accept_redirects=0`
///   on most distros). Sustained > 0 here = the router is *trying* to
///   redirect us; if `accept_redirects=0` is set we're (correctly)
///   ignoring it but the counter still increments. SEV3 anomaly — the
///   default route is mispointing on someone's gateway.
/// - `OutMsgs`: total ICMP packets sent from this host. Send-side
///   denominator.
/// - `OutDestUnreachs`: ICMP Destination-Unreachable messages WE sent.
///   Each event = a peer sent us a packet for an endpoint we don't host
///   (closed UDP port → kernel auto-emits ICMP Port-Unreachable; closed
///   TCP backlog → kernel emits ICMP Host-Unreachable; routing didn't
///   accept the destination address → ICMP Net-Unreachable). Pairs 1:1
///   with `Udp:NoPorts` — every UDP NoPorts event MAY emit one
///   OutDestUnreach, modulo `OutRateLimitHost` (the kernel's per-dest
///   ICMP rate cap). At 10K-peer scale a sustained spike here is gossip
///   misroute (peers learning a stale endpoint of ours).
/// - `OutTimeExcds`: ICMP Time-Exceeded WE sent. The kernel emits these
///   when a packet we forwarded had TTL=0 (we don't forward, so this
///   should stay near zero) OR when reassembly timed out (we held
///   fragments for too long and gave up — pairs with `Ip:ReasmFails`).
///   Sustained nonzero alongside ReasmFails means our reassembly ring
///   is undersized for incoming fragmented load.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct HostIcmpStats {
    in_msgs: u64,
    in_errors: u64,
    in_csum_errors: u64,
    in_dest_unreachs: u64,
    in_time_excds: u64,
    in_redirects: u64,
    out_msgs: u64,
    out_dest_unreachs: u64,
    out_time_excds: u64,
}
fn host_icmp_stats() -> HostIcmpStats {
    let raw = std::fs::read_to_string("/proc/net/snmp").unwrap_or_default();
    parse_host_icmp_stats(&raw)
}
fn parse_host_icmp_stats(raw: &str) -> HostIcmpStats {
    let mut out = HostIcmpStats::default();
    let mut hdr: Option<Vec<&str>> = None;
    for line in raw.lines() {
        // Match exact "Icmp: " prefix — must NOT match "IcmpMsg: " (separate
        // section with a different schema: per-type counters InType3 etc.).
        if let Some(rest) = line.strip_prefix("Icmp: ") {
            let parts: Vec<&str> = rest.split_whitespace().collect();
            match hdr {
                None => hdr = Some(parts),
                Some(ref h) => {
                    for (i, name) in h.iter().enumerate() {
                        if let Some(v) = parts.get(i).and_then(|s| s.parse::<u64>().ok()) {
                            match *name {
                                "InMsgs" => out.in_msgs = v,
                                "InErrors" => out.in_errors = v,
                                "InCsumErrors" => out.in_csum_errors = v,
                                "InDestUnreachs" => out.in_dest_unreachs = v,
                                "InTimeExcds" => out.in_time_excds = v,
                                "InRedirects" => out.in_redirects = v,
                                "OutMsgs" => out.out_msgs = v,
                                "OutDestUnreachs" => out.out_dest_unreachs = v,
                                "OutTimeExcds" => out.out_time_excds = v,
                                _ => {}
                            }
                        }
                    }
                    hdr = None;
                }
            }
        }
    }
    out
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct SoftnetStats {
    processed_total: u64,
    dropped_total: u64,
    time_squeeze_total: u64,
    flow_limit_total: u64,
    dropped_max_per_cpu: u64,
}

/// Per-CPU NAPI/softnet packet pipeline stats from
/// `/proc/net/softnet_stat`. Aggregated across all CPUs (sum) plus
/// `dropped_max_per_cpu` (max) to surface RX-imbalance without paying
/// per-CPU cardinality.
///
/// Each row in the file represents one CPU's NAPI poll loop counters.
/// The columns are hex-encoded u32. Schema (kernel ≥ 3.6):
///
/// | Col | Field             | Meaning |
/// |-----|-------------------|---------|
/// | 0   | packets_processed | Successfully NAPI-polled into the stack |
/// | 1   | packets_dropped   | Input backlog full → kernel dropped at netif_receive_skb |
/// | 2   | time_squeeze      | NAPI ran out of budget mid-poll (backlog forming) |
/// | 8   | flow_limit_count  | RFS per-flow limit drops |
///
/// Why these four (not all 16 columns):
/// - `processed`: provides denominator for drop rate; without it a
///   non-zero `dropped` is uninterpretable.
/// - `dropped`: DIRECT signal that the network stack is shedding load.
///   Distinct from elara_host_netdev_rx_drop_total which is
///   per-NIC (driver-level); softnet_dropped is per-CPU (NAPI-level).
///   On a system where one NIC's RPS pins all interrupts to CPU0,
///   dropped will climb on CPU0 only — invisible to the per-NIC
///   counter, visible here via dropped_max_per_cpu.
/// - `time_squeeze`: NAPI's budget is finite (default 64 packets/poll);
///   when packets arrive faster than the poll loop can drain, the
///   counter increments and kernel reschedules NAPI for another shot.
///   Sustained rate > 100/s on a single CPU = that CPU is the RX
///   bottleneck. Pair with cgroup PSI cpu and softirq net_rx
///   — high time_squeeze + high softirq net_rx + low PSI cpu
///   means RPS is not enabled or is misconfigured (all RX hits one CPU).
/// - `flow_limit`: kernel ≥ 3.6 RFS flow-table per-flow rate limiter.
///   Increments when a single elephant flow saturates a CPU's input
///   queue. Useful for identifying a misbehaving peer flooding one
///   socket — pair with elara_tcp_backlog_drop_total.
///
/// Cardinality budget: 5 lines/host (4 sums + 1 max). The
/// dropped_max_per_cpu is the differentiator that catches RX imbalance
/// without surfacing all N CPUs as labels.
fn host_softnet_stats() -> SoftnetStats {
    let raw = std::fs::read_to_string("/proc/net/softnet_stat").unwrap_or_default();
    parse_softnet_stat(&raw)
}

fn parse_softnet_stat(raw: &str) -> SoftnetStats {
    let mut out = SoftnetStats::default();
    for line in raw.lines() {
        // Each line: 16 hex u32 columns space-separated, one per CPU.
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 9 {
            continue;
        }
        let h = |s: &str| u64::from_str_radix(s, 16).unwrap_or(0);
        let processed = h(cols[0]);
        let dropped = h(cols[1]);
        let squeeze = h(cols[2]);
        let flow_limit = h(cols[8]);
        out.processed_total = out.processed_total.saturating_add(processed);
        out.dropped_total = out.dropped_total.saturating_add(dropped);
        out.time_squeeze_total = out.time_squeeze_total.saturating_add(squeeze);
        out.flow_limit_total = out.flow_limit_total.saturating_add(flow_limit);
        if dropped > out.dropped_max_per_cpu {
            out.dropped_max_per_cpu = dropped;
        }
    }
    out
}

/// Host VM / page-fault counters from `/proc/vmstat`.
///
/// Returns `(pgmajfault, pgsteal_kswapd, oom_kill, pswpin, pswpout)`.
///
/// All five are kernel-maintained monotonic counters (since boot). They
/// answer the single phone-tier question that RSS-based alerting cannot:
/// is the box's working set actively spilling beyond physical RAM?
///
/// - `pgmajfault`: major page faults — accesses that had to read from
///   disk because the page wasn't in any cache. THE canonical signal of
///   RAM pressure on a phone-tier box. Each major fault is typically
///   100-1000× slower than a minor fault (cache miss vs. cache hit).
///   Sustained rate(pgmajfault[1m]) > 50/s on a 4GB node = the working
///   set doesn't fit and every operation is paying disk-read cost.
///   Distinct from minor page faults (`pgfault - pgmajfault`) which are
///   benign first-touch faults during normal allocation.
/// - `pgsteal_kswapd`: pages reclaimed by `kswapd` (the kernel's
///   asynchronous page reclaim daemon). Leading indicator that beats
///   pgmajfault: when memory is getting tight, kswapd starts reclaiming
///   inactive pages BEFORE allocations stall and trigger major faults.
///   rate(pgsteal_kswapd[5m]) climbing while pgmajfault is still flat =
///   you have ~minutes before the cliff. Distinct from `pgsteal_direct`
///   which is reclaim done synchronously by the allocating process —
///   kswapd-only is the asymptomatic leading indicator; direct reclaim
///   means you're already in the cliff.
/// - `oom_kill`: cumulative count of times the kernel OOM-killer has
///   selected a victim. On a healthy phone-tier node this stays at 0
///   indefinitely. ANY increment is a SEV1 incident — there is no
///   "graceful degradation" path through OOM kill: the killed process
///   loses everything in-flight (mid-RocksDB-write = potential SST
///   corruption; mid-attestation = lost vote). Pair with
///   elara_oom_score — score climbs toward 1000 BEFORE oom_kill
///   moves; an alert at oom_score > 700 gives operator runway to
///   intervene before the kernel does.
/// - `pswpin` / `pswpout`: pages swapped IN / OUT. On phone-tier boxes
///   we configure swap = 0 deliberately (latency-sensitive workloads
///   should never swap), so these should stay at exactly the last
///   sample value forever. ANY increase = swap is enabled by accident
///   OR a co-tenant turned it on. Per-second swap I/O is the WORST
///   possible disk traffic (4 KB random scattered all over the
///   pagefile, blocking on block-layer IO with no merge opportunity).
///   On 4-GB nodes these counters are typically 0
///   sample-to-sample — exception: a noisy-neighbor node which
///   inherits swap behavior we already track via
///   CPU steal.
///
/// Pairs with: elara_process_oom_score, elara_process_pressure_*
/// PSI gauges, elara_host_psi_mem_* (host-wide if separate).
/// pgmajfault often moves BEFORE PSI memory because PSI is sampled at
/// 10s coarse granularity; vmstat counters update on every page fault.
fn host_vmstat_pressure() -> (u64, u64, u64, u64, u64) {
    let raw = std::fs::read_to_string("/proc/vmstat").unwrap_or_default();
    parse_vmstat_pressure(&raw)
}

fn parse_vmstat_pressure(raw: &str) -> (u64, u64, u64, u64, u64) {
    let mut pgmajfault = 0u64;
    let mut pgsteal_kswapd = 0u64;
    let mut oom_kill = 0u64;
    let mut pswpin = 0u64;
    let mut pswpout = 0u64;
    for line in raw.lines() {
        let mut it = line.split_whitespace();
        let key = match it.next() { Some(k) => k, None => continue };
        let val: u64 = match it.next().and_then(|v| v.parse().ok()) {
            Some(v) => v,
            None => continue,
        };
        match key {
            "pgmajfault" => pgmajfault = val,
            // Older kernels emit `pgsteal_kswapd_dma`/`_normal` etc as
            // separate per-zone counters; modern kernels (≥5.0) coalesce
            // into a single `pgsteal_kswapd`. Sum any name that starts
            // with that prefix to be robust across both.
            k if k.starts_with("pgsteal_kswapd") => {
                pgsteal_kswapd = pgsteal_kswapd.saturating_add(val);
            }
            "oom_kill" => oom_kill = val,
            "pswpin" => pswpin = val,
            "pswpout" => pswpout = val,
            _ => {}
        }
    }
    (pgmajfault, pgsteal_kswapd, oom_kill, pswpin, pswpout)
}

/// Process scheduler statistics from `/proc/self/schedstat`.
///
/// Returns `(exec_runtime_ns, run_delay_ns, dispatches)`.
///
/// The single line of `/proc/self/schedstat` has three fields per
/// `Documentation/scheduler/sched-stats.rst`:
///
/// 1. `sum_exec_runtime` — cumulative ns this task spent ON the CPU.
/// 2. `run_delay` — cumulative ns this task spent on the runqueue WAITING for
///    CPU. Distinct from "sleeping" (blocked on I/O / a futex / etc) — this
///    is purely "I'm runnable, give me a core," and the scheduler hasn't yet.
/// 3. `pcount` — number of times the task was dispatched onto a CPU.
///
/// The single most useful derived signal is the ratio:
///
/// ```text
/// scheduling_pressure = rate(run_delay)  / rate(exec_runtime + run_delay)
/// ```
///
/// On a healthy box this is < 0.01; sustained > 0.10 means elara-node is
/// being starved by something — kernel RT tasks, a co-tenant CPU pin, a
/// noisy IRQ on the same core. Distinct from PSI cpu which is
/// SYSTEM-wide ("any task is waiting"); this is PROCESS-specific
/// ("elara-node is waiting"). On a 4-vCPU box where 3 cores are busy
/// servicing a noisy NIC IRQ, PSI may stay flat while elara-node's
/// run_delay climbs because elara-node is the one being deferred.
///
/// pcount alone is rarely actionable — it's the dispatcher count, useful
/// only as a sanity divisor (rate(exec_runtime + run_delay) / rate(pcount)
/// = average runqueue residency per dispatch; a rising number = scheduler
/// quanta being shortened = co-tenant pressure).
///
/// Cost: one `read()` syscall, one short string parse. The kernel updates
/// these fields on every schedule event (no stat collection cost beyond
/// the read).
fn process_schedstat() -> (u64, u64, u64) {
    let raw = std::fs::read_to_string("/proc/self/schedstat").unwrap_or_default();
    parse_schedstat(&raw)
}

fn parse_schedstat(raw: &str) -> (u64, u64, u64) {
    let mut it = raw.split_whitespace();
    let exec    = it.next().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
    let delay   = it.next().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
    let pcount  = it.next().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
    (exec, delay, pcount)
}

/// Cumulative PSI stall counters from
/// `/proc/pressure/{cpu,memory,io}` `total=` field. Returns micros stalled
/// for cpu_some, mem_some, mem_full, io_some, io_full (5 monotonic
/// counters). Returns 0 on each axis if PSI is unavailable (CONFIG_PSI=n
/// on older kernels; /proc/pressure not exposed in unprivileged
/// containers).
///
/// The PSI avg10 reader already exposes the instantaneous gauges. This complements
/// them with cumulative counters required for PromQL `rate()` over operator-
/// chosen windows. The two answer different questions: avg10 is
/// "what is happening now"; `rate(_us_total[5m])` is the time-weighted
/// pressure across any window the alert chooses, and is what alert
/// pipelines correlate with rate(http_request_duration_seconds_sum) or
/// other rate-shape metrics. Without a counter, an operator who wants
/// "PSI memory.full > 5% over a 30-minute window" cannot express it from
/// avg10 alone (which decays exponentially over 10s).
///
/// Why no cpu_full: kernel docs (Documentation/accounting/psi.rst) flag
/// CPU `full` as ill-defined; on every kernel ≥5.13 it is hardcoded 0
/// so a counter on it is dead noise. cpu_some captures all the useful
/// CPU pressure signal.
///
/// Microseconds, not seconds: kernel exposes `total=` in microseconds,
/// and we keep the unit explicit (`_us_total`) rather than converting,
/// so operators inspecting raw counters do not have to second-guess the
/// scale. `rate()` math is unit-agnostic anyway — the ratio of `rate(some)`
/// to wall time gives the same fraction whether you divide by 10000 (for
/// us → percent) or 1e7 (for seconds → percent of a 10s window).
fn process_pressure_totals_us() -> (u64, u64, u64, u64, u64) {
    let cpu_raw = std::fs::read_to_string("/proc/pressure/cpu").unwrap_or_default();
    let mem_raw = std::fs::read_to_string("/proc/pressure/memory").unwrap_or_default();
    let io_raw  = std::fs::read_to_string("/proc/pressure/io").unwrap_or_default();
    let (cpu_some, _cpu_full) = parse_psi_total(&cpu_raw);
    let (mem_some, mem_full)  = parse_psi_total(&mem_raw);
    let (io_some,  io_full)   = parse_psi_total(&io_raw);
    (cpu_some, mem_some, mem_full, io_some, io_full)
}

fn parse_psi_total(raw: &str) -> (u64, u64) {
    let mut some = 0u64;
    let mut full = 0u64;
    for line in raw.lines() {
        let mut parts = line.split_whitespace();
        let label = match parts.next() {
            Some(s) => s,
            None => continue,
        };
        for tok in parts {
            if let Some(rest) = tok.strip_prefix("total=") {
                let v = rest.parse::<u64>().unwrap_or(0);
                match label {
                    "some" => some = v,
                    "full" => full = v,
                    _ => {}
                }
            }
        }
    }
    (some, full)
}

/// Cgroup v2 memory accounting from
/// `/sys/fs/cgroup/<own>/memory.{current,max,high,swap.current,events}`.
/// Returns 6 values: (current, max, high, swap_current, oom_kill,
/// high_throttle). Each 0 if cgroup v2 is unavailable, the path cannot be
/// read, or `memory.max`/`memory.high` is the literal "max" (= unlimited).
///
/// Why this is a separate signal from process resident bytes:
/// /proc/self/status `VmRSS` measures pages elara-node has mapped. The
/// cgroup `memory.current` measures every byte the kernel has CHARGED
/// to elara-node's cgroup — that includes page cache, slab/kmem (kernel
/// allocations on behalf of this process), tmpfs pages mounted inside,
/// network buffers attributed to processes in the cgroup, and the
/// transparent-hugepages backing those pages. A node can have RSS=150 MB
/// (its own working set) while `memory.current=1.8 GB` because RocksDB
/// SST reads warmed the page cache and the cgroup limit is 2 GB. From
/// the kernel's perspective those page-cache pages are reclaimable but
/// *attributed* to this cgroup; if another process tries to allocate
/// and the cgroup is at limit, kernel evicts them, paying a latency cost
/// elara-node sees as page faults (vmstat pgmajfault).
///
/// Phone-tier deployment is the canonical setting: a 4-GB phone running
/// elara-node under a systemd MemoryLimit=2G unit will OOM-kill at 2 GB
/// total cgroup charge — invisible to process RSS metrics. Operators need
/// `memory.current / memory.max > 0.80` as the early warning, and
/// `oom_kill > 0` as the SEV1 confirmation that the limit was hit.
///
/// Containers/k8s: same shape, different mount layout, all handled by
/// reading /proc/self/cgroup which is unified to v2 single-controller
/// since kernel 5.x. cgroup v1 systems (RHEL 7/8 with hybrid mode) have
/// a different layout (split memory, cpu, blkio controllers under
/// /sys/fs/cgroup/memory/...); we return zeros and operators get a
/// flat-zero gauge that they can alert on as "cgroup v1, retire box".
///
/// `memory.high` is the soft limit — the kernel throttles writers
/// (busy-loop reclaiming) when current crosses it but does not OOM-kill.
/// Surfacing it lets operators see the throttle band BEFORE the hard
/// cliff. `memory.events:high` counter ticks each time the kernel
/// entered throttle mode for this cgroup; a sudden spike with current
/// near limit = working set just blew past the soft band.
fn cgroup_memory_state() -> (u64, u64, u64, u64, u64, u64, u64, u64, u64, u64) {
    let path = match parse_self_cgroup_path(
        &std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default(),
    ) {
        Some(p) => p,
        None => return (0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    };
    let base = format!("/sys/fs/cgroup{}", path);
    let read_u64 = |name: &str| -> u64 {
        std::fs::read_to_string(format!("{}/{}", base, name))
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(0)
    };
    let read_max = |name: &str| -> u64 {
        parse_cgroup_max_value(
            &std::fs::read_to_string(format!("{}/{}", base, name)).unwrap_or_default(),
        )
    };
    let current = read_u64("memory.current");
    let max     = read_max("memory.max");
    let high    = read_max("memory.high");
    let swap    = read_u64("memory.swap.current");
    let ev = parse_memory_events(
        &std::fs::read_to_string(format!("{}/memory.events", base)).unwrap_or_default(),
    );
    (current, max, high, swap, ev.oom_kill, ev.high, ev.low, ev.max, ev.oom, ev.oom_group_kill)
}

/// Parse `/proc/self/cgroup` to find the cgroup v2 unified-hierarchy path.
/// Returns the path portion (e.g. "/system.slice/elara-node.service")
/// from the line starting `0::`. None if no v2 line is found (cgroup v1
/// hybrid systems where the v2 line is absent).
fn parse_self_cgroup_path(raw: &str) -> Option<String> {
    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("0::") {
            let p = rest.trim();
            if !p.is_empty() {
                return Some(p.to_string());
            }
        }
    }
    None
}

/// Parse `memory.max` / `memory.high`. Kernel writes `max` (literal
/// string) for unlimited or a u64 byte count. We return 0 for unlimited
/// so a single u64 metric can carry both states; operators read 0 as
/// "no limit set" which is what they want to alert on (no observable
/// ceiling = no early-warning possible). Garbage input (parse failure)
/// also returns 0 — the caller then sees an unconfigured-cgroup posture
/// and treats it the same.
fn parse_cgroup_max_value(raw: &str) -> u64 {
    let trimmed = raw.trim();
    if trimmed == "max" || trimmed.is_empty() {
        return 0;
    }
    trimmed.parse::<u64>().unwrap_or(0)
}

/// Parse cgroup v2 `memory.events`. Format is multi-line:
///   low 0
///   high 1234
///   max 0
///   oom 0
///   oom_kill 5
///   oom_group_kill 0
///
/// The base cgroup-memory reader covered `high` + `oom_kill`. This extends to all six kernel
/// keys: `low` (kernel reclaimed despite memory.low protection — soft-min
/// failure), `max` (kernel hit memory.max ceiling — one step before OOM,
/// distinct from `oom_kill` which is the process-kill event), `oom`
/// (kernel detected OOM in this cgroup, not necessarily killed yet),
/// `oom_group_kill` (entire cgroup wiped via memory.oom.group=1).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct MemoryEvents {
    low: u64,
    high: u64,
    max: u64,
    oom: u64,
    oom_kill: u64,
    oom_group_kill: u64,
}
fn parse_memory_events(raw: &str) -> MemoryEvents {
    let mut out = MemoryEvents::default();
    for line in raw.lines() {
        let mut it = line.split_whitespace();
        let key = match it.next() {
            Some(k) => k,
            None => continue,
        };
        let val: u64 = match it.next().and_then(|v| v.parse().ok()) {
            Some(v) => v,
            None => continue,
        };
        match key {
            "low" => out.low = val,
            "high" => out.high = val,
            "max" => out.max = val,
            "oom" => out.oom = val,
            "oom_kill" => out.oom_kill = val,
            "oom_group_kill" => out.oom_group_kill = val,
            _ => {}
        }
    }
    out
}

/// Cgroup v2 `memory.stat` detailed breakdown. The `memory.current`
/// gauge is a single number — useful for "is the cgroup approaching
/// max?" but blind to *what kind* of memory is dominating. The breakdown
/// here distinguishes:
///   - `anon`: process-private mappings (heap, stack, MAP_ANONYMOUS) —
///     unfreeable without paging. The number that matters for OOM headroom.
///   - `file`: page cache for files this cgroup opened — kernel can reclaim
///     under pressure, so high `file` is healthy if it's hot working set,
///     and a leak indicator if it's growing unbounded with cold data.
///   - `kernel`: slab + kmem allocated by the kernel on this cgroup's
///     behalf (sockets, dentries, network buffers). Slab leaks (e.g.
///     dentry cache runaway) hide here, NOT in RSS.
///   - `pgfault`: minor faults — already-resident pages getting mapped
///     into the process. Surge = working set rotating, not necessarily bad.
///   - `pgmajfault`: major faults — disk read required. Surge = thrashing
///     or cold-cache, the proximate signal for "we ran out of cache".
///   - `workingset_refault_file`: file pages evicted from cache then
///     re-faulted in. Non-zero = working set > available cache; THIS is
///     the early-warning for cache pressure, before pgmajfault explodes.
///
/// At 1M zones × phone-tier hardware, distinguishing "anon growing"
/// (real memory leak) from "file growing" (page cache headroom doing
/// its job) is the difference between "evict the box" and "leave it
/// alone" — without this breakdown, the base reader says only "memory.current
/// is up" and operators have no way to triage.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct CgroupMemoryStat {
    anon: u64,
    file: u64,
    kernel: u64,
    pgfault: u64,
    pgmajfault: u64,
    workingset_refault_file: u64,
}
fn parse_cgroup_memory_stat(raw: &str) -> CgroupMemoryStat {
    let mut out = CgroupMemoryStat::default();
    for line in raw.lines() {
        let mut it = line.split_whitespace();
        let key = match it.next() {
            Some(k) => k,
            None => continue,
        };
        let val: u64 = match it.next().and_then(|v| v.parse().ok()) {
            Some(v) => v,
            None => continue,
        };
        match key {
            "anon" => out.anon = val,
            "file" => out.file = val,
            "kernel" => out.kernel = val,
            "pgfault" => out.pgfault = val,
            "pgmajfault" => out.pgmajfault = val,
            "workingset_refault_file" => out.workingset_refault_file = val,
            _ => {}
        }
    }
    out
}

/// Read this cgroup's `memory.stat` and return the breakdown.
/// Kept distinct from `cgroup_memory_state` because that function's
/// tuple is already at 10 fields and the stat file is a separate
/// kernel surface (different docs, different lifecycle: stat counters
/// may exist while events file is still empty during early boot).
fn cgroup_memory_stat_breakdown() -> CgroupMemoryStat {
    let path = match parse_self_cgroup_path(
        &std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default(),
    ) {
        Some(p) => p,
        None => return CgroupMemoryStat::default(),
    };
    let raw = std::fs::read_to_string(format!("/sys/fs/cgroup{}/memory.stat", path))
        .unwrap_or_default();
    parse_cgroup_memory_stat(&raw)
}

/// Cgroup v2 CPU accounting from
/// /sys/fs/cgroup/<own>/cpu.stat + cpu.max. Returns
/// (usage_us, user_us, system_us, throttled_us, nr_throttled,
///  quota_us, period_us). Zeros when v2 is not mounted (RHEL
/// hybrid) or the cgroup files are missing.
fn cgroup_cpu_state() -> (u64, u64, u64, u64, u64, u64, u64) {
    let path = match parse_self_cgroup_path(
        &std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default(),
    ) {
        Some(p) => p,
        None => return (0, 0, 0, 0, 0, 0, 0),
    };
    let base = format!("/sys/fs/cgroup{}", path);
    let stat_raw = std::fs::read_to_string(format!("{}/cpu.stat", base)).unwrap_or_default();
    let (usage, user, system, throttled_us, nr_throttled) = parse_cpu_stat(&stat_raw);
    let max_raw = std::fs::read_to_string(format!("{}/cpu.max", base)).unwrap_or_default();
    let (quota, period) = parse_cpu_max(&max_raw);
    (usage, user, system, throttled_us, nr_throttled, quota, period)
}

/// Parse cgroup v2 `cpu.stat`. Format is multi-line key/value:
///   usage_usec 718565846
///   user_usec 598599316
///   system_usec 119966530
///   nr_periods 0
///   nr_throttled 0
///   throttled_usec 0
///   core_sched.force_idle_usec 0
///   ... (kernel may add fields)
/// Returns (usage_usec, user_usec, system_usec, throttled_usec,
/// nr_throttled). Throttle fields are zero when no quota is set
/// (kernel still emits them but they never increment).
fn parse_cpu_stat(raw: &str) -> (u64, u64, u64, u64, u64) {
    let mut usage = 0u64;
    let mut user = 0u64;
    let mut system = 0u64;
    let mut throttled_us = 0u64;
    let mut nr_throttled = 0u64;
    for line in raw.lines() {
        let mut it = line.split_whitespace();
        let key = match it.next() {
            Some(k) => k,
            None => continue,
        };
        let val: u64 = match it.next().and_then(|v| v.parse().ok()) {
            Some(v) => v,
            None => continue,
        };
        match key {
            "usage_usec" => usage = val,
            "user_usec" => user = val,
            "system_usec" => system = val,
            "throttled_usec" => throttled_us = val,
            "nr_throttled" => nr_throttled = val,
            _ => {}
        }
    }
    (usage, user, system, throttled_us, nr_throttled)
}

/// Parse cgroup v2 `cpu.max`. Format is one line: `<quota> <period>`
/// where quota is the literal `max` (no quota) or u64 microseconds,
/// and period is u64 microseconds (default 100000 = 100 ms). Returns
/// (quota_us, period_us). Quota=0 carries 'no quota' (literal `max`)
/// AND 'file missing' (cgroup v1 hybrid) — both are unobservable from
/// a single u64; operator alerts on quota=0+throttle_total>0 (impossible)
/// or quota>0+(throttle_total-baseline)>threshold.
fn parse_cpu_max(raw: &str) -> (u64, u64) {
    let mut it = raw.split_whitespace();
    let quota_tok = match it.next() {
        Some(t) => t,
        None => return (0, 0),
    };
    let period_tok = match it.next() {
        Some(t) => t,
        None => return (0, 0),
    };
    let quota = if quota_tok == "max" {
        0
    } else {
        quota_tok.parse::<u64>().unwrap_or(0)
    };
    let period = period_tok.parse::<u64>().unwrap_or(0);
    (quota, period)
}

/// Process FD saturation. Returns `(open_fds, max_fds)`.
///
/// `open_fds` counts entries in /proc/self/fd — every open file, socket,
/// pipe, eventfd, and timerfd consumes one. Each TCP peer connection,
/// each RocksDB SST kept open, each PQ-WS stream, each watched file all
/// add to this count.
///
/// `max_fds` reads the soft RLIMIT_NOFILE via `getrlimit(2)`. This is the
/// LIVE cap (not /proc/self/limits which is read-once at exec). Phone-tier
/// systemd default is 1024 — at saturation the kernel rejects accept(),
/// open(), and socket() with EBADF/EMFILE, and elara-node loses the ability
/// to accept new peer connections OR open RocksDB SSTs (silent corruption
/// risk on writes that were mid-flight when the FD ceiling hit).
///
/// Pairs with elara_socket_recv_drops_total and the TCP socket
/// inventory. Open FDs grow with peer count + RocksDB working set;
/// alert at `open_fds / max_fds > 0.80` to leave operator headroom for the
/// systemctl edit + restart cycle before the saturation cliff.
fn process_fd_state() -> (u64, u64) {
    let open_fds = std::fs::read_dir("/proc/self/fd")
        .map(|d| d.filter(|e| e.is_ok()).count() as u64)
        .unwrap_or(0);
    #[cfg(unix)]
    let max_fds = {
        let mut rlim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        unsafe {
            if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) == 0 {
                rlim.rlim_cur
            } else {
                0
            }
        }
    };
    // No getrlimit off-unix; 0 = "unavailable", same as the syscall-failure path.
    #[cfg(not(unix))]
    let max_fds = 0u64;
    (open_fds, max_fds)
}

/// Whole-host CPU jiffy breakdown from `/proc/stat` first line.
/// Returns `(user, system, iowait, softirq, steal, idle)` in seconds via
/// `sysconf(_SC_CLK_TCK)`. Six monotonic counters; rate() across them
/// gives current CPU breakdown.
///
/// Distinct from `process_cpu_seconds()` (`/proc/self/stat` utime/stime),
/// which is elara-node-only. This is the WHOLE host — surfaces three
/// signals that elara-node's own counters cannot see:
///
/// - `iowait` — global I/O-wait time (kernel-tracked synchronous-I/O
///   blocking on any process). Complements PSI io: PSI is the modern
///   kernel-tracked stall metric, iowait is the long-standing /proc/stat
///   metric. Sustained `rate(iowait) > 10%` of one core = global disk
///   queue saturated; pair with `elara_psi_io_full_avg10` for a second
///   opinion.
/// - `softirq` — time spent in software-interrupt context (network RX
///   processing, timer, RCU). On gossip-heavy nodes this rises with
///   inbound packet rate; sustained `rate(softirq) > 30%` of one core
///   = NIC RX is the bottleneck (kernel can't keep up with packet
///   delivery). Pair with `elara_socket_recv_drops_total` to confirm.
/// - `steal` — CPU time stolen by the hypervisor for other VMs on the
///   same physical host. INVISIBLE from `/proc/self/stat`. The canonical
///   "noisy neighbour" signal on shared VPS hardware. Sustained
///   `rate(steal) > 5%` of one core = the hypervisor is preempting
///   elara-node for its neighbours; our scheduling guarantees are
///   degraded and there is nothing we can do about it from inside the
///   VM (operator must contact the VPS provider or migrate). On
///   bare-metal or dedicated hardware this is always 0.
///
/// `user`, `system`, `idle` are emitted as the standard host-CPU baseline
/// for ratio/percentage computations.
/// Whole-host scheduler + interrupt + context-switch counters from
/// `/proc/stat` trailing lines.
///
/// Returns `(procs_running, procs_blocked, ctxt_total, intr_total)`.
///
/// - `procs_running` is the count of currently runnable processes/threads
///   across the whole host. Companion to `elara_host_runnable_tasks` from
///   /proc/loadavg, but sampled fresh — loadavg's runnable count is itself
///   instantaneous, so the two should agree at scrape time. Useful as a
///   sanity cross-check.
/// - `procs_blocked` is the D-state count: tasks in uninterruptible sleep,
///   typically waiting on disk I/O. The classic "stuck in iowait" signal.
///   On phone-tier eMMC nodes this climbs whenever many threads cold-fault
///   into mmap'd RocksDB SSTs at once. Sustained `procs_blocked > 0` =
///   kernel says some task is stuck in I/O wait right now; pair with
///   elara_psi_io_full_avg10.
/// - `ctxt_total` is the host-wide cumulative context-switch counter
///   across ALL processes (not just elara-node). The per-process equivalent
///   is the per-process voluntary+nonvoluntary. Comparing host-rate to elara-node-
///   rate tells you what fraction of the box's scheduler activity is us.
/// - `intr_total` is the host-wide cumulative interrupt count. Useful as a
///   "device activity" baseline — a sharply rising rate without a
///   corresponding traffic increase often indicates NIC IRQ storm or a
///   misbehaving driver pinning a CPU to interrupt servicing.
fn host_proc_stat_extras() -> (u64, u64, u64, u64) {
    let stat = std::fs::read_to_string("/proc/stat").unwrap_or_default();
    let mut procs_running = 0u64;
    let mut procs_blocked = 0u64;
    let mut ctxt = 0u64;
    let mut intr = 0u64;
    for line in stat.lines() {
        let extract_first = |rest: &str| -> u64 {
            rest.split_whitespace().next().and_then(|s| s.parse().ok()).unwrap_or(0)
        };
        if let Some(rest) = line.strip_prefix("ctxt ") { ctxt = extract_first(rest); continue; }
        if let Some(rest) = line.strip_prefix("intr ") { intr = extract_first(rest); continue; }
        if let Some(rest) = line.strip_prefix("procs_running ") { procs_running = extract_first(rest); continue; }
        if let Some(rest) = line.strip_prefix("procs_blocked ") { procs_blocked = extract_first(rest); continue; }
    }
    (procs_running, procs_blocked, ctxt, intr)
}

/// System-wide file-descriptor saturation from `/proc/sys/fs/file-nr`.
///
/// Returns `(allocated, max)`. The kernel's file-nr line has three numbers:
/// allocated, free, max. On modern kernels (≥2.6.something) the "free" pool
/// is always 0 — the kernel allocates and frees on demand without a pool —
/// so we return only the two meaningful values. `allocated/max` ratio is the
/// host-wide FD pressure: at >0.8 the next open(2) anywhere on the host
/// (including elara-node's accept loop) is at material risk of EMFILE.
/// Companion to the process-level `elara_process_open_fds_count` — they
/// answer different questions: process-level FD spike = elara-node leak;
/// host-level FD spike = some OTHER process is leaking and we'll be
/// collateral damage when the kernel's global allocator runs out.
fn host_file_nr() -> (u64, u64) {
    let raw = std::fs::read_to_string("/proc/sys/fs/file-nr").unwrap_or_default();
    let parts: Vec<&str> = raw.split_whitespace().collect();
    let allocated = parts.first().and_then(|s| s.parse().ok()).unwrap_or(0);
    let max = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
    (allocated, max)
}

/// Host-wide TCP/UDP socket inventory from `/proc/net/sockstat`.
///
/// Returns `(sockets_used, tcp_inuse, tcp_orphan, tcp_tw, tcp_alloc,
/// tcp_mem_pages, udp_inuse, udp_mem_pages)`. Layered onto the host FD
/// pressure: FD count tells you "we have N descriptors open" but does not
/// distinguish the *kind*. A sock=O(N) FD spike with retrans steady = peer
/// fanout grew normally. The same FD spike with `tcp_tw` runaway = the box
/// is churning short-lived connections (typical: a peer-discovery loop
/// reconnecting on every gossip tick) and is heading for ephemeral-port
/// exhaustion (default 32K range / `net.ipv4.ip_local_port_range`). `orphan`
/// is the half-closed bucket — peers crashed without proper FIN — and is
/// capped by `net.ipv4.tcp_max_orphans` (typical 4096); past that the kernel
/// silently discards. `mem_pages` is socket-buffer pressure invisible to
/// process RSS: TCP send/recv buffers live in kernel-space, so a fanout
/// climbing from 100 to 10K peers can pin hundreds of MB the process
/// metrics never see.
fn host_sockstat() -> (u64, u64, u64, u64, u64, u64, u64, u64) {
    let raw = std::fs::read_to_string("/proc/net/sockstat").unwrap_or_default();
    parse_sockstat(&raw)
}

fn parse_sockstat(raw: &str) -> (u64, u64, u64, u64, u64, u64, u64, u64) {
    let mut sockets_used = 0u64;
    let mut tcp_inuse = 0u64;
    let mut tcp_orphan = 0u64;
    let mut tcp_tw = 0u64;
    let mut tcp_alloc = 0u64;
    let mut tcp_mem = 0u64;
    let mut udp_inuse = 0u64;
    let mut udp_mem = 0u64;
    let kv = |line: &str, key: &str| -> Option<u64> {
        let mut iter = line.split_whitespace();
        while let Some(tok) = iter.next() {
            if tok == key {
                return iter.next().and_then(|v| v.parse().ok());
            }
        }
        None
    };
    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("sockets:") {
            if let Some(v) = kv(rest, "used") {
                sockets_used = v;
            }
        } else if let Some(rest) = line.strip_prefix("TCP:") {
            if let Some(v) = kv(rest, "inuse") {
                tcp_inuse = v;
            }
            if let Some(v) = kv(rest, "orphan") {
                tcp_orphan = v;
            }
            if let Some(v) = kv(rest, "tw") {
                tcp_tw = v;
            }
            if let Some(v) = kv(rest, "alloc") {
                tcp_alloc = v;
            }
            if let Some(v) = kv(rest, "mem") {
                tcp_mem = v;
            }
        } else if let Some(rest) = line.strip_prefix("UDP:") {
            if let Some(v) = kv(rest, "inuse") {
                udp_inuse = v;
            }
            if let Some(v) = kv(rest, "mem") {
                udp_mem = v;
            }
        }
    }
    (
        sockets_used,
        tcp_inuse,
        tcp_orphan,
        tcp_tw,
        tcp_alloc,
        tcp_mem,
        udp_inuse,
        udp_mem,
    )
}

fn host_cpu_jiffies() -> (f64, f64, f64, f64, f64, f64) {
    let stat = std::fs::read_to_string("/proc/stat").unwrap_or_default();
    let first = stat.lines().next().unwrap_or("");
    let mut parts = first.split_whitespace();
    let _label = parts.next();
    let user: u64 = parts.next().and_then(|v| v.parse().ok()).unwrap_or(0);
    let _nice: u64 = parts.next().and_then(|v| v.parse().ok()).unwrap_or(0);
    let system: u64 = parts.next().and_then(|v| v.parse().ok()).unwrap_or(0);
    let idle: u64 = parts.next().and_then(|v| v.parse().ok()).unwrap_or(0);
    let iowait: u64 = parts.next().and_then(|v| v.parse().ok()).unwrap_or(0);
    let _irq: u64 = parts.next().and_then(|v| v.parse().ok()).unwrap_or(0);
    let softirq: u64 = parts.next().and_then(|v| v.parse().ok()).unwrap_or(0);
    let steal: u64 = parts.next().and_then(|v| v.parse().ok()).unwrap_or(0);
    #[cfg(unix)]
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    // No sysconf off-unix; 0 routes to the 100 Hz default (all jiffy fields are
    // already 0 there — /proc is absent).
    #[cfg(not(unix))]
    let ticks: i64 = 0;
    let hz = if ticks > 0 { ticks as f64 } else { 100.0 };
    (
        user as f64 / hz,
        system as f64 / hz,
        iowait as f64 / hz,
        softirq as f64 / hz,
        steal as f64 / hz,
        idle as f64 / hz,
    )
}

/// Aggregated host disk I/O counters from `/proc/diskstats`.
/// Returns `(reads, writes, read_sectors, write_sectors, read_ms, write_ms,
/// in_flight)` summed across physical block devices.
///
/// Filters to `sd*`, `nvme*`, `vd*`, `xvd*`, `mmcblk*` — drops loop/ram/dm/zd
/// virtual devices to avoid double-counting (dm-* maps to underlying sd*).
///
/// Pairs with host CPU `iowait`: iowait says disk is the global bottleneck,
/// diskstats says HOW saturated and at what latency.
/// - `rate(reads + writes)` = real IOPS the kernel saw
/// - `rate(read_ms) / rate(reads)` = avg per-IO read service time
/// - `in_flight` = current queue depth (gauge from field 12, not a counter)
///   — sustained > device's queue depth = HW saturated, latency tail rising.
///
/// Per-device disk stats. Replaces the aggregated tuple — keeps
/// the same 7 fields, but tags them with the device name so operators can see
/// WHICH disk is saturated (typical Elara nodes have data on a separate NVMe
/// from the OS root). Cardinality is bounded by physical block devices (1-3
/// per host); virtual/composite devices (loop/ram/dm/zd/md) and partitions are
/// filtered out so we don't double-count.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct HostDiskStat {
    device: String,
    reads: u64,
    writes: u64,
    read_sectors: u64,
    write_sectors: u64,
    read_ms: u64,
    write_ms: u64,
    in_flight: u64,
    /// Ms during which the device was actively servicing I/O
    /// (`/proc/diskstats` field 13). rate(io_ms[1m]) / 60000 = utilization
    /// fraction. On phone-tier eMMC the disk caps at ~30-50 IOPS sustained
    /// before queue lock-up; sustained io_ms rate > 0.3 (30% busy) means
    /// RocksDB compactions are about to stall.
    io_ms: u64,
    /// Queue-time-weighted ms (`/proc/diskstats` field 14).
    /// `rate(weighted_io_ms) = avg queue depth over the interval`. Diverges
    /// upward from io_ms when the queue grows faster than the disk drains —
    /// the leading-indicator for IO latency tails BEFORE p99 read_ms or
    /// write_ms move.
    weighted_io_ms: u64,
    /// Count of FLUSH/fua requests completed (`/proc/diskstats`
    /// field 19, present on Linux ≥ 5.5). Each RocksDB WAL fsync becomes a
    /// flush request to the block layer. rate(flushes) ≈ fsyncs/sec.
    flushes: u64,
    /// Ms spent servicing flush requests (`/proc/diskstats` field
    /// 20). avg flush latency = rate(flush_ms) / rate(flushes). On
    /// phone-tier eMMC the per-fsync cost can be 30-150ms; on enterprise
    /// NVMe it's < 1ms. This is the most direct signal of write-amp pain
    /// in RocksDB on a phone-tier device.
    flush_ms: u64,
    /// Discard IOs completed (`/proc/diskstats` field 15, kernel
    /// ≥ 4.18; 0 on older kernels). Each RocksDB SST deletion bottoms
    /// out here when the data-disk is mounted with `discard` (or the
    /// systemd `fstrim.timer` is active). rate(discards) > 0 confirms
    /// the device is being told it can free blocks for wear-leveling.
    /// Sustained 0 with sustained writes = TRIM is being swallowed
    /// somewhere — eMMC/SSD wear-leveling will degrade over weeks.
    discards: u64,
    /// Discard IOs merged (`/proc/diskstats` field 16). Same
    /// merge semantics as reads_merged / writes_merged: kernel coalesces
    /// adjacent discards before issuing them. high merges means the
    /// filesystem is asking for many small adjacent TRIM ranges and the
    /// kernel is being efficient about combining them. Cosmetic on its
    /// own, useful as the merge denominator alongside `discards`.
    discards_merged: u64,
    /// 512-byte sectors discarded (`/proc/diskstats` field 17).
    /// Volume of flash freed: `rate(sectors_discarded) × 512` bytes/sec.
    /// `rate(sectors_discarded) / rate(write_sectors)` = TRIM efficiency
    /// (1.0 = every byte written eventually trimmed; healthy steady-state
    /// for RocksDB-on-discard ≈ 0.5-0.8). Anomalously low ratio = TRIM
    /// is being eaten by an LVM/dm/raid layer that doesn't pass discards.
    sectors_discarded: u64,
    /// Ms spent servicing discard requests (`/proc/diskstats`
    /// field 18). avg per-discard latency = rate(discard_ms) /
    /// rate(discards). On phone-tier eMMC each TRIM can stall the device
    /// for tens of ms; this is the visibility you need to know whether a
    /// `discard` mount option is causing IO tail latency vs leaving it
    /// off and using `fstrim.timer` to batch it.
    discard_ms: u64,
}

/// 5/15-minute load averages + runqueue depth from /proc/loadavg.
///
/// Format of /proc/loadavg: `1m 5m 15m runnable/total last_pid`.
/// SystemLoadSensor (network/system_load.rs) already exposes 1m via the
/// elara_system_load_1m gauge for cooperative-yield logic, but doesn't track
/// 5m/15m or the runnable/total task counts. Operators need 5m and 15m to see
/// trend (load_1m can spike; load_15m says "is this sustained?"), and the
/// runnable count is the most direct scheduler-pressure signal — it's
/// "tasks waiting for a CPU right now" which is what causes the latency
/// tail growth that load_1m only correlates with.
fn host_loadavg_extra() -> (f64, f64, u64, u64) {
    let raw = std::fs::read_to_string("/proc/loadavg").unwrap_or_default();
    let parts: Vec<&str> = raw.split_whitespace().collect();
    if parts.len() < 4 { return (0.0, 0.0, 0, 0); }
    let load_5m  = parts[1].parse::<f64>().unwrap_or(0.0);
    let load_15m = parts[2].parse::<f64>().unwrap_or(0.0);
    // Field 4 is "runnable/total". Both u32-range in practice (kernel cap < 4M).
    let mut runnable = 0u64;
    let mut total    = 0u64;
    if let Some((r, t)) = parts[3].split_once('/') {
        runnable = r.parse::<u64>().unwrap_or(0);
        total    = t.parse::<u64>().unwrap_or(0);
    }
    (load_5m, load_15m, runnable, total)
}

fn host_disk_stats() -> Vec<HostDiskStat> {
    let stats = std::fs::read_to_string("/proc/diskstats").unwrap_or_default();
    parse_host_disk_stats(&stats)
}

/// Shared parser for `/proc/diskstats`-formatted text. Split out
/// from `host_disk_stats()` so the device-filter + field-positional logic
/// gets unit-test coverage without touching `/proc`.
fn parse_host_disk_stats(stats: &str) -> Vec<HostDiskStat> {
    let mut out = Vec::new();
    for line in stats.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 14 { continue; }
        let dev = parts[2];
        if dev.starts_with("loop") || dev.starts_with("ram") || dev.starts_with("dm-")
            || dev.starts_with("zd") || dev.starts_with("md")
        { continue; }
        if dev.starts_with("sd") || dev.starts_with("vd") || dev.starts_with("xvd") {
            if dev.chars().last().is_some_and(|c| c.is_ascii_digit()) { continue; }
        } else if dev.starts_with("nvme") || dev.starts_with("mmcblk") {
            if dev.contains('p') { continue; }
        } else {
            continue;
        }
        out.push(HostDiskStat {
            device: dev.to_string(),
            reads:        parts[3].parse::<u64>().unwrap_or(0),
            read_sectors: parts[5].parse::<u64>().unwrap_or(0),
            read_ms:      parts[6].parse::<u64>().unwrap_or(0),
            writes:       parts[7].parse::<u64>().unwrap_or(0),
            write_sectors: parts[9].parse::<u64>().unwrap_or(0),
            write_ms:     parts[10].parse::<u64>().unwrap_or(0),
            in_flight:    parts[11].parse::<u64>().unwrap_or(0),
            // Fields 12 (io_ms), 13 (weighted_io_ms), 18 (flushes),
            // 19 (flush_ms). Older kernels may emit shorter rows — fall
            // back to 0 rather than skip the device, so the core disk fields
            // remain visible even on a Linux 4.x box.
            io_ms:          parts.get(12).and_then(|s| s.parse().ok()).unwrap_or(0),
            weighted_io_ms: parts.get(13).and_then(|s| s.parse().ok()).unwrap_or(0),
            // Discard fields (kernel ≥ 4.18 emit 14-17; flushes
            // start at 18). On a 4.x box without discard support these
            // four positions are absent and the row is shorter — `.get()`
            // safely yields 0.
            discards:          parts.get(14).and_then(|s| s.parse().ok()).unwrap_or(0),
            discards_merged:   parts.get(15).and_then(|s| s.parse().ok()).unwrap_or(0),
            sectors_discarded: parts.get(16).and_then(|s| s.parse().ok()).unwrap_or(0),
            discard_ms:        parts.get(17).and_then(|s| s.parse().ok()).unwrap_or(0),
            flushes:        parts.get(18).and_then(|s| s.parse().ok()).unwrap_or(0),
            flush_ms:       parts.get(19).and_then(|s| s.parse().ok()).unwrap_or(0),
        });
    }
    out
}

/// Per-network-device error / drop counters from /proc/net/dev.
/// Catches NIC-level packet loss that TCP-layer counters cannot
/// see — drops happening below the IP stack on ring overflow, link-layer
/// errors, or carrier bounces. Particularly important on phone-tier
/// hardware (USB-Ethernet adapters, wifi NICs, cheap eMMC SoC NICs)
/// where the kernel ring is small and bursty TCP can overrun it before
/// the receive path drains.
struct HostNetDevStat {
    device: String,
    /// /proc/net/dev field after `:` index 2 — packets that arrived but
    /// were dropped by the NIC due to checksum / framing / size errors.
    /// Sustained > 0 = bad cable / failing NIC / driver bug.
    rx_errs: u64,
    /// Index 3 — packets dropped by the kernel because the receive ring
    /// was full when they arrived. SUSTAINED > 0 under load = the box
    /// can't drain its NIC ring fast enough; raise net.core.netdev_max_backlog
    /// or move to RPS/RFS. Most actionable network-loss signal.
    rx_drop: u64,
    /// Index 10 — packets the driver couldn't transmit. Should always
    /// be 0 on a healthy NIC; a non-zero value is hardware fault or
    /// driver wedge.
    tx_errs: u64,
    /// Index 11 — packets the kernel queued for transmit but had to drop
    /// (typically because the qdisc was full). Indicates the egress
    /// pipeline can't keep up — relevant on slow uplinks (~10
    /// KB/s sustained outbound during seal storms).
    tx_drop: u64,
    /// Index 14 — count of TX carrier-loss events. Each increment = the
    /// link physically dropped (cable unplugged, switchport flapped,
    /// wifi roam). This catches cloud-VM live-migrations
    /// and any mid-session network pivots that would otherwise look like
    /// peer churn at the application layer.
    tx_carrier: u64,
}

/// Read /proc/net/dev and parse per-physical-device counters.
/// Filters: skip loopback `lo`, Docker / k8s bridges (`docker*`,
/// `br-*`, `veth*`, `virbr*`, `cni*`, `flannel*`, `kube-*`), all of
/// which are virtual interfaces whose drop counters add noise without
/// surfacing real NIC pain. KEEPS `tailscale0` because Tailscale is
/// the deploy backbone for the laptop node and counts as a real path.
fn host_netdev_stats() -> Vec<HostNetDevStat> {
    let raw = std::fs::read_to_string("/proc/net/dev").unwrap_or_default();
    parse_proc_net_dev(&raw)
}

/// Per-type aggregate softirq counters from /proc/softirqs.
/// Returns (net_rx, net_tx, block, sched, timer) summed across CPUs.
/// Imbalanced softirq distribution (one CPU running 90% of NET_RX
/// while others idle) is the canonical phone-tier saturation
/// signal — surfaces as TCP retransmits and elevated p99 latency
/// long before any other counter moves. The aggregate is the
/// first cut; per-CPU labels are a future expansion if cardinality
/// budget allows.
fn host_softirq_totals() -> (u64, u64, u64, u64, u64) {
    let raw = std::fs::read_to_string("/proc/softirqs").unwrap_or_default();
    parse_softirqs(&raw)
}

/// Parse /proc/softirqs. Format:
///     "                    CPU0       CPU1       CPU2 ..."
///     "          HI:          1          2          4 ..."
///     "       TIMER:   16748842   21210153 ..."
///     "      NET_RX:    1357256    1327963 ..."
///     "       SCHED:  281014952  143984324 ..."
/// We sum across CPUs for the five most-actionable types:
/// NET_RX, NET_TX, BLOCK, SCHED, TIMER. Header row has no
/// `:` so it's skipped naturally; unknown labels (HI, IRQ_POLL,
/// TASKLET, HRTIMER, RCU) are ignored.
fn parse_softirqs(raw: &str) -> (u64, u64, u64, u64, u64) {
    let mut net_rx = 0u64;
    let mut net_tx = 0u64;
    let mut block = 0u64;
    let mut sched = 0u64;
    let mut timer = 0u64;
    for line in raw.lines() {
        let trimmed = line.trim_start();
        let (label, rest) = match trimmed.split_once(':') {
            Some(pair) => pair,
            None => continue,
        };
        let label = label.trim();
        let target: Option<&mut u64> = match label {
            "NET_RX" => Some(&mut net_rx),
            "NET_TX" => Some(&mut net_tx),
            "BLOCK"  => Some(&mut block),
            "SCHED"  => Some(&mut sched),
            "TIMER"  => Some(&mut timer),
            _ => None,
        };
        if let Some(t) = target {
            for tok in rest.split_whitespace() {
                if let Ok(v) = tok.parse::<u64>() {
                    *t = t.saturating_add(v);
                }
            }
        }
    }
    (net_rx, net_tx, block, sched, timer)
}

/// Memory fragmentation snapshot from /proc/buddyinfo.
///
/// Returns free-page counts at three allocation orders, summed across
/// all NUMA nodes and memory zones. The kernel maintains free pages
/// as a buddy-allocator bitmap per zone; high-order pages are
/// contiguous physical memory required for hugepage mmaps, RocksDB
/// block reads, and network jumbo frames. When a phone-tier 2 GB box
/// fragments under sustained load, order-8+ counts drain to zero
/// long before memory.current cliffs — high-order allocations start
/// failing first, kernel falls back to compaction (CPU stall) or
/// OOM-kills.
///
/// Order conventions (page size = 4 KB on Linux):
///   - order 0 → 4 KB blocks (smallest, kernel always retains)
///   - order 4 → 64 KB blocks (RocksDB read-ahead block size)
///   - order 8 → 1 MB blocks (hugepage candidate, jumbo frames)
///
/// Three orders chosen for cardinality (3 lines/host) — operators
/// compute fragmentation index = (order8 / order0) on the dashboard
/// without paying per-order label cost.
///
/// 0 if /proc/buddyinfo unreadable (containers with /proc namespace
/// strip, certain hardened kernels). Distinct from "0 free pages of
/// that order" — both return 0 here, dashboards flag flat-zero as
/// "unobservable" only if the order-0 count is also 0.
fn host_buddy_free_pages() -> (u64, u64, u64) {
    let raw = std::fs::read_to_string("/proc/buddyinfo").unwrap_or_default();
    parse_buddyinfo(&raw)
}

/// Parse /proc/buddyinfo. Format (one line per (node, zone)):
///     "Node 0, zone   Normal  42820  14159  13457   9227   5974   3095   1359    401      3      0      0"
/// The first 12 tokens before the counts are the node/zone label
/// (variable-length: "Node N, zone <name>"); free-page counts start
/// at column 4 in the rstrip'd token stream after splitting on
/// whitespace. We locate counts by finding the index after the
/// "zone NAME" pair and sum order indices [0, 4, 8] across all rows.
/// Kernel currently emits 11 orders (0..=10).
fn parse_buddyinfo(raw: &str) -> (u64, u64, u64) {
    let mut order0 = 0u64;
    let mut order4 = 0u64;
    let mut order8 = 0u64;
    for line in raw.lines() {
        let toks: Vec<&str> = line.split_whitespace().collect();
        // Layout: ["Node", "N,", "zone", "<name>", count0, count1, ...]
        // Minimum useful row = prefix + at least order-0 count.
        if toks.len() < 5 { continue; }
        if toks[0] != "Node" { continue; }
        let counts_start = 4;
        // Sum orders 0/4/8 if present; missing column → 0 (no panic).
        if let Some(t) = toks.get(counts_start) {
            if let Ok(v) = t.parse::<u64>() { order0 = order0.saturating_add(v); }
        }
        if let Some(t) = toks.get(counts_start + 4) {
            if let Ok(v) = t.parse::<u64>() { order4 = order4.saturating_add(v); }
        }
        if let Some(t) = toks.get(counts_start + 8) {
            if let Ok(v) = t.parse::<u64>() { order8 = order8.saturating_add(v); }
        }
    }
    (order0, order4, order8)
}

/// Read jemalloc internal stats via mallctl.
/// Returns (allocated, active, resident, metadata, mapped, retained) in bytes.
/// Requires `epoch::advance()` to refresh counters before reading — without
/// this, all values are stale (frozen at jemalloc init). Gated on
/// `feature = "node"` because tikv-jemalloc-ctl is only pulled in there;
/// non-node builds (mobile, wasm, node-windows) return all zeros.
#[cfg(all(feature = "node", target_family = "unix", not(target_arch = "wasm32")))]
fn host_jemalloc_stats() -> (u64, u64, u64, u64, u64, u64) {
    use tikv_jemalloc_ctl::{epoch, stats};
    if epoch::advance().is_err() {
        return (0, 0, 0, 0, 0, 0);
    }
    let allocated = stats::allocated::read().unwrap_or(0) as u64;
    let active    = stats::active::read().unwrap_or(0) as u64;
    let resident  = stats::resident::read().unwrap_or(0) as u64;
    let metadata  = stats::metadata::read().unwrap_or(0) as u64;
    let mapped    = stats::mapped::read().unwrap_or(0) as u64;
    let retained  = stats::retained::read().unwrap_or(0) as u64;
    (allocated, active, resident, metadata, mapped, retained)
}

#[cfg(not(all(feature = "node", target_family = "unix", not(target_arch = "wasm32"))))]
fn host_jemalloc_stats() -> (u64, u64, u64, u64, u64, u64) {
    (0, 0, 0, 0, 0, 0)
}

fn parse_proc_net_dev(raw: &str) -> Vec<HostNetDevStat> {
    let mut out = Vec::new();
    for line in raw.lines() {
        let trimmed = line.trim_start();
        let (dev, rest) = match trimmed.split_once(':') {
            Some(pair) => pair,
            None => continue,
        };
        let dev = dev.trim();
        if dev.is_empty() { continue; }
        if dev == "lo" { continue; }
        if dev.starts_with("docker")
            || dev.starts_with("br-")
            || dev.starts_with("veth")
            || dev.starts_with("virbr")
            || dev.starts_with("cni")
            || dev.starts_with("flannel")
            || dev.starts_with("kube-")
        { continue; }
        let parts: Vec<&str> = rest.split_whitespace().collect();
        if parts.len() < 16 { continue; }
        out.push(HostNetDevStat {
            device:    dev.to_string(),
            rx_errs:   parts[2].parse::<u64>().unwrap_or(0),
            rx_drop:   parts[3].parse::<u64>().unwrap_or(0),
            tx_errs:   parts[10].parse::<u64>().unwrap_or(0),
            tx_drop:   parts[11].parse::<u64>().unwrap_or(0),
            tx_carrier: parts[14].parse::<u64>().unwrap_or(0),
        });
    }
    out
}

// ─── Metric tier classification ─────────────────────
//
// 591 metric families × 6 nodes × 30 s scrape = 118 K samples/min today.
// At mainnet's 10 K-node target the same surface = 17 GB/day of Prometheus
// storage and 8 KB/s upstream PER NODE just for monitoring. A Pi-4 phone-tier
// node serving the full 292 KB body burns ~0.5 % of its CPU on /metrics
// rendering — non-trivial when the budget is "make consensus and finality
// fit in a phone."
//
// The fix: classify each metric family into a tier and let operators pick
// the level of detail they ship. The mapping is intentionally permissive
// (default = P1) so adding a new metric without classifying it shows up at
// P1, not silently disappearing into P0 or Debug.

/// Verbosity tier for /metrics output. Lower = more essential.
///
/// **P0 (~30 families):** consensus + finality + connectivity + resource
///   ceilings. The minimum set to answer "is this node alive and producing
///   blocks?" — what an oncall pager must see.
///
/// **P1 (~150 families, default):** P0 + per-host resource utilization +
///   error counters + queue depths. The set you want for "is this node
///   healthy?" capacity-planning and root-cause forensics.
///
/// **Debug (591 families):** P1 + high-cardinality breakdowns (per-CPU,
///   per-zone, per-resource jiffy/temp/freq/rlimit rows). Useful for deep
///   dives but paid for in scrape cost. Default for local dev nodes.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum MetricTier {
    P0 = 0,
    P1 = 1,
    Debug = 2,
}

impl MetricTier {
    pub fn label(&self) -> &'static str {
        match self {
            MetricTier::P0 => "P0",
            MetricTier::P1 => "P1",
            MetricTier::Debug => "debug",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "p0" => Some(MetricTier::P0),
            "p1" => Some(MetricTier::P1),
            "debug" => Some(MetricTier::Debug),
            _ => None,
        }
    }
}

/// Runtime tier — set once at startup. The binary entry point
/// (`bin/elara_node.rs`) resolves it from `--metric-tier`, then
/// `ELARA_METRIC_TIER`, then a `node_profile`-derived default
/// (Light=P0, FullZone=P1, Archive=Debug). Test callers that
/// don't go through the binary fall through to `Debug`, preserving the
/// full-surface default behavior.
pub static METRIC_TIER: std::sync::OnceLock<MetricTier> = std::sync::OnceLock::new();

/// Resolve the runtime tier. Falls back to `Debug` when nothing has been
/// set yet — this keeps unit tests (which never spin up the full binary)
/// seeing the full /metrics surface they were written against.
pub fn current_metric_tier() -> MetricTier {
    METRIC_TIER.get().copied().unwrap_or(MetricTier::Debug)
}

/// Clamp a per-request `?tier=` override for the `/metrics` handler.
///
/// Loopback callers (an operator on the box, or the loopback admin/data plane)
/// keep the full spot-check override, including `debug`. Non-loopback callers —
/// anyone reaching the public `0.0.0.0` listener — may *downgrade* the scrape
/// surface but are capped at **P1**.
///
/// The Debug tier — per-core CPU frequency, hwmon/thermal temperatures, per-disk
/// IO, per-NIC error counters, process rlimits — is a precise physical-machine
/// fingerprint: a local-operator/forensics surface that is NEVER served off the
/// loopback plane. This cap holds even when the node's configured `ceiling` is
/// Debug (the `NodeProfile::Archive` default, see `current_metric_tier`): a
/// public-facing Archive node must not hand its machine fingerprint to anonymous
/// callers any more than the public `/status` does (parallels the `/status`
/// host-fingerprint gate). Without the P1 cap the tier system is bypassable on
/// exactly those nodes. `MetricTier` is `Ord` (P0 < P1 < Debug), so the cap is a
/// direct comparison; loopback keeps full Debug via `?tier=debug`.
pub(crate) fn clamp_public_metric_tier(
    is_loopback: bool,
    requested: Option<MetricTier>,
    ceiling: MetricTier,
) -> Option<MetricTier> {
    if is_loopback {
        return requested;
    }
    // Debug is loopback-only host fingerprint — cap the public ceiling at P1
    // regardless of the node's configured tier (Archive defaults to Debug).
    let public_ceiling = if ceiling > MetricTier::P1 {
        MetricTier::P1
    } else {
        ceiling
    };
    match requested {
        Some(t) if t <= public_ceiling => Some(t),
        _ => Some(public_ceiling),
    }
}

// ── P0 — exact-match essentials ───────────────────────────────────────
// Names verified against live `/metrics` on running nodes.
// Anything that wasn't in the live surface was dropped — phantom names
// like `elara_seal_success_total` (no such gauge exists; seal-throughput
// shows up as `elara_epoch_seals_total`) were the reason TIER-1 v1
// shipped with 17/32 P0 hits instead of the audit-target ~30.
pub(crate) const P0_EXACT: &[&str] = &[
    // consensus / finality core
    "elara_consensus_settled",
    "elara_finalized_count",
    "elara_records_processed",
    "elara_attestations_processed_total",
    "elara_epoch_seals_total",
    // adaptive epoch interval — seal cadence + headroom signal
    "elara_adaptive_interval_floor_seconds",
    "elara_adaptive_interval_ceil_seconds",
    "elara_adaptive_interval_min_active_seconds",
    "elara_adaptive_interval_max_active_seconds",
    "elara_adaptive_interval_mean_seconds",
    "elara_adaptive_interval_floor_pinned_zones",
    "elara_adaptive_interval_zones_tracked",
    // pending-ledger health (finality-lag visibility)
    "elara_pending_ledger_depth",
    "elara_pending_ledger_oldest_age_seconds",
    "elara_pending_ledger_max_identity_depth",
    "elara_pending_ledger_distinct_identities",
    // attestation / VRF / committee health
    "elara_phase6d_ready",
    "elara_vrf_registry_identities",
    "elara_vrf_registry_quorum_global",
    "elara_committee_skipped_below_k_total",
    "elara_enforce_per_zone_vrf",
    "elara_seal_attestation_rejected_not_in_committee_total",
    // Phase 6D readiness diagnosis — scalar globals (NOT per-zone) feed the
    // `member_observations` predicate in `phase6d_readiness()`. Without them
    // in P0, an operator running a phone-tier node at tier=P0 sees
    // `elara_phase6d_ready=0` with no way to disambiguate the blocker
    // (registry-too-small vs. zero-member-attestations) — the per-zone
    // breakdowns at `elara_committee_attestations_total{zone=...}` stay at
    // Debug because they're high-cardinality. These two are scalar globals.
    "elara_committee_attestations_member_total",
    "elara_committee_attestations_nonmember_total",
    // peer connectivity — without peers nothing else matters
    "elara_peers_connected",
    "elara_peers_total",
    "elara_peers_banned",
    "elara_peers_in_backoff",
    // disk pressure — node death signal
    "elara_disk_pressure",
    // Split signals — avail is the ingest-gating real-disk-full
    // safety bound, cap is the operator-policy budget that drives GC
    // behavior but does not reject ingest.
    "elara_disk_avail_pressure",
    "elara_disk_cap_pressure",
    // Per-edge transition counters + lowest-since-boot avail
    // floor. Counters catch between-scrape flaps; lowest-mb catches
    // slow monotonic shrinks the boolean gauge missed.
    "elara_disk_avail_pressure_events_total",
    "elara_disk_cap_pressure_events_total",
    "elara_disk_pressure_lowest_avail_mb",
    // Paired iteration counter for sentinel-vs-zero disambiguation.
    "elara_disk_pressure_samples_total",
    // RocksDB hard-wedge signal — a background flush/compaction FAILED and
    // writes are halted. Same node-death class as elara_disk_pressure but
    // catches the non-space faults (I/O error, corruption, mid-compaction
    // ENOSPC) the free-space gate is blind to. Any non-zero = operator page.
    "elara_rocksdb_background_errors",
    // Operator-triggered /admin/rocks/compact_cf invocation count.
    "elara_admin_compact_cf_triggered_total",
    "elara_data_dir_total_bytes",
    // Paired iteration counter for the data_dir walk task
    // (lets operators tell never-sampled from genuine-zero footprint).
    "elara_data_dir_size_samples_total",
    // circuit breaker — protocol panic signal
    "elara_circuit_breaker_level",
    // node identity / liveness
    "elara_uptime_seconds",
    // resource ceiling self-saturation indicators
    "elara_node_open_fds",
    "elara_node_max_fds",
    // PSI avg10 — earliest "node is struggling" signal Linux exposes.
    // Only the 10-second window goes P0 (4 series: some/full × cpu+memory+io;
    // cpu only emits 'some'). avg60/300 + total go P1 — useful for capacity
    // planning, not pager-grade.
    "elara_host_pressure_some_avg10",
    "elara_host_pressure_full_avg10",
    // Cgroup-scoped PSI avg10 — pair with host PSI to disambiguate
    // "noisy neighbour" (host high + cgroup low) from "own cgroup is the
    // bottleneck" (host low + cgroup high). Both diagnostic states are
    // pager-grade in containerized phone-tier deployments.
    "elara_cgroup_pressure_some_avg10",
    "elara_cgroup_pressure_full_avg10",
];

/// Classify one metric family by name. Used both at the filter step and
/// from tests to lock in the tier of specific families.
///
/// Strategy: explicit P0 list (consensus + finality + connectivity + the
/// few resource-ceiling gauges that exist), histogram-prefix fall-through
/// for the histogram families that are P0, then a debug-prefix list that
/// catches the high-cardinality families (per-CPU, per-zone, per-resource).
/// Everything else is P1.
pub fn classify_metric(name: &str) -> MetricTier {
    // The self-reporting gauge MUST always survive the filter so operators
    // can see what tier each node is publishing.
    if name == "elara_metric_tier" {
        return MetricTier::P0;
    }
    // Build-identity gauge carries the PRIVATE-repo HEAD git_sha (+ git_ref/
    // git_dirty/build_ts) — the same build fingerprint /version (86d9bc32) and
    // /status (01301319) gate loopback-only. Debug-tier so the non-loopback P1
    // ceiling (clamp_public_metric_tier) drops the whole family off the public
    // plane. Loopback keeps it via `?tier=debug`; git_sha also stays on loopback
    // /version + /status with no param, and the deploy pre-flight reads it from
    // the binary via `strings` — so no consumer needs it on the public tier.
    if name == "elara_build_info" {
        return MetricTier::Debug;
    }

    if P0_EXACT.contains(&name) {
        return MetricTier::P0;
    }

    // ── P0 — histogram families (match base + _bucket / _sum / _count) ────
    // Verified against live histogram families on a running node. There is no
    // `elara_in_zone_finality_seconds` or `elara_finality_seconds` family —
    // finality is a counter (`elara_finalized_count`), not a histogram. The
    // closest latency floor we expose is the seal pipeline.
    const P0_HISTOGRAM_PREFIXES: &[&str] = &[
        "elara_seal_attestation_latency_seconds",
        "elara_seal_propagation_latency_seconds",
        "elara_seal_quorum_latency_seconds",
    ];
    if P0_HISTOGRAM_PREFIXES.iter().any(|p| name.starts_with(p)) {
        return MetricTier::P0;
    }

    // ── Debug — high-cardinality breakdowns ───────────────────────────────
    // The prefixes below catch families whose live byte-cost dominated the
    // P1 body when measured on a running node — without them, P1 stays at
    // 99% of the Debug body and the tier system can't justify itself.
    const DEBUG_PREFIXES: &[&str] = &[
        // Host hardware breakdowns (per-CPU / per-hwmon / per-zone / per-iface / per-device)
        "elara_host_cpu_frequency_hz",        // per-CPU
        "elara_host_cpu_temperature_celsius", // per-hwmon
        "elara_host_hwmon_temp_celsius",      // per-sensor
        "elara_host_thermal_celsius",         // legacy thermal
        "elara_host_netdev_",                 // per-interface NIC stats
        "elara_host_disk_",                   // per-device IO stats
        "elara_thermal_zone_celsius",         // per-zone
        // Per-process per-resource breakdowns
        "elara_process_rlimit_soft",          // per-resource
        "elara_process_rlimit_hard",          // per-resource
        "elara_jiffies_",                     // per-mode
        // Per-zone / per-kind cumulative breakdowns
        "elara_committee_attestations_",      // per-zone
        "elara_zone_eligible_",               // per-zone
        "elara_per_zone_",                    // per-zone (any future)
        "elara_dag_kind_",                    // per-record-kind
        "elara_gossip_bytes_out_kind_",       // per-kind breakdown
        // Per-route HTTP histograms (1 family ~ 4 KB each — biggest single bloat)
        "elara_http_request_route_duration_seconds", // per-route histogram
        "elara_http_request_duration_seconds",       // 15-bucket aggregate histogram
        "elara_http_request_status_",                // per-route status counter
        "elara_request_duration_seconds_by_route",   // legacy per-route name
        "elara_request_status_by_route_total",       // legacy per-route counter
        // Per-rank seal latency histograms (high-cardinality, debug-only)
        "elara_seal_attestor_rank_latency_seconds",
        // Other large debug histograms
        "elara_gossip_push_duration_seconds",
    ];
    if DEBUG_PREFIXES.iter().any(|p| name.starts_with(p)) {
        return MetricTier::Debug;
    }

    MetricTier::P1
}

/// Extract the metric family name from a single line of Prometheus text.
/// Returns `None` for blank lines or comments that aren't `# HELP` /
/// `# TYPE` (so operators' free-form comments are preserved untouched).
fn metric_name_from_line(line: &str) -> Option<&str> {
    if let Some(rest) = line.strip_prefix("# HELP ").or_else(|| line.strip_prefix("# TYPE ")) {
        return rest.split_whitespace().next();
    }
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    // Data line: "metric_name{labels} value [timestamp]" or "metric_name value".
    let end = line.find(['{', ' ', '\t']).unwrap_or(line.len());
    if end == 0 {
        None
    } else {
        Some(&line[..end])
    }
}

/// Filter a fully-rendered Prometheus body so only metric families at the
/// requested tier (or lower) survive. `Debug` is a no-op fast path.
///
/// Lines we don't recognize as metric-bound (blank, free-form comments) are
/// preserved unchanged so any future structured-comment convention keeps
/// working.
pub fn filter_metrics_by_tier(body: &str, tier: MetricTier) -> String {
    if tier == MetricTier::Debug {
        return body.to_string();
    }
    let mut out = String::with_capacity(body.len());
    for line in body.lines() {
        let keep = match metric_name_from_line(line) {
            Some(name) => classify_metric(name) <= tier,
            None => true,
        };
        if keep {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// Axum adapter — wraps [`metrics_body_tiered`] with the Prometheus content-type
/// header. Called from `routes::core::metrics`, which extracts an optional
/// `?tier=...` query param. `None` = use the node-level default set at startup.
/// The PQ `metrics` verb renders via `metrics_body_tiered` with a public-clamped
/// tier (see `pq_transport::router::handle_metrics`) and serves the same bytes with
/// no header layer, so both transports emit byte-identical Prometheus text per tier.
pub(crate) async fn metrics_handler_tiered(
    state: Arc<NodeState>,
    tier_override: Option<MetricTier>,
) -> impl IntoResponse {
    let body = metrics_body_tiered(state, tier_override).await;
    (
        [(axum::http::header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        body,
    )
}

/// Node-default-tier convenience wrapper over `metrics_body_tiered(state, None)`.
/// Test-only: production transports call `metrics_body_tiered` directly (the axum
/// `/metrics` handler with the request tier; the PQ `metrics` verb with a
/// public-clamped tier). `#[cfg(test)]` keeps this wrapper out of the non-test lib
/// target, where its lack of a production caller trips `dead_code` under
/// `-D warnings`. Consumed by the `*_surfaces_in_metrics_body` tests in `state.rs`.
#[cfg(test)]
pub(crate) async fn metrics_body(
    state: Arc<NodeState>,
) -> String {
    metrics_body_tiered(state, None).await
}

/// Render the Prometheus exposition body at a caller-chosen tier (`None` = node-level
/// default, [`current_metric_tier`]). The render cost is identical — every metric
/// is computed regardless — only the final filter changes.
pub(crate) async fn metrics_body_tiered(
    state: Arc<NodeState>,
    tier_override: Option<MetricTier>,
) -> String {
    // Per-block tier guard. The tier override introduced
    // post-render filtering — bytes shrink, /proc reads still run. At
    // tier=P0 the body strips ~16 expensive /proc reader call sites whose
    // output is then discarded; gating those readers up-front skips the
    // syscalls entirely. `collect_p1` runs scalar /proc readers (host_*
    // counters, process_* gauges); `collect_debug` runs per-device readers
    // (host_disk_*, host_netdev_*, host_cpu_frequency_*, hwmon, thermal,
    // rlimit). Stays correct across the existing classify_metric tier
    // assignments — a metric tagged Debug must come from a reader gated at
    // collect_debug; a metric tagged P1 from one gated at collect_p1.
    let target_tier = tier_override.unwrap_or_else(current_metric_tier);
    let collect_p1 = target_tier >= MetricTier::P1;
    let collect_debug = target_tier >= MetricTier::Debug;
    // Use snapshot for ALL stats to avoid lock contention with state_core.
    // Falls back to direct locks only before state core init.
    let (dag_size, dag_tips, dag_edges, ledger_supply, ledger_staked, ledger_accounts,
         connected_peers, total_peers, finalized_len, conservation_pool_val,
         breaker_level, cb_volume_24h, cb_velocity_24h, velocity_tracked, acquisition_tracked,
         vesting_active, governance_active, records_processed, banned_peers, peers_in_backoff,
         trust_tracked) =
        if let Some(core) = state.state_core.get() {
            let snap = core.read_snapshot();
            (snap.dag_size, snap.dag_tips, snap.dag_edges,
             snap.ledger_supply, snap.ledger_staked, snap.ledger_accounts,
             snap.peers_connected, snap.peers_total, snap.finalized_count,
             snap.conservation_pool,
             snap.circuit_breaker_level, snap.cb_volume_24h, snap.cb_velocity_24h,
             snap.velocity_tracked, snap.acquisition_tracked,
             snap.vesting_active, snap.governance_active, snap.records_processed,
             snap.banned_peers, snap.peers_in_backoff, snap.trust_tracked)
        } else {
            let dag = state.dag.read().await;
            let ledger = state.ledger.read().await;
            let peers = state.peers.read().await;
            let finalized = state.finalized.read().await;
            let bl: u8 = match ledger.circuit_breaker.level {
                crate::accounting::circuit_breaker::BreakerLevel::Normal => 0,
                crate::accounting::circuit_breaker::BreakerLevel::Level1 => 1,
                crate::accounting::circuit_breaker::BreakerLevel::Level2 => 2,
                crate::accounting::circuit_breaker::BreakerLevel::Level3 => 3,
            };
            let now_f = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs_f64();
            let vol24 = ledger.circuit_breaker.volume_in_window(now_f);
            let circ = ledger.total_supply.saturating_sub(ledger.total_staked);
            let vel24 = vol24 as f64 / circ.max(1) as f64;
            let tt = match state.trust.try_read() {
                Ok(t) => t.tracked_identities(),
                Err(_) => 0,
            };
            (dag.len(), dag.tips().len(), dag.edge_count(),
             ledger.total_supply, ledger.total_staked, ledger.accounts.len(),
             peers.connected().len(), peers.len(), finalized.len(),
             ledger.conservation_pool,
             bl, vol24, vel24, ledger.velocity.tracked_identities(),
             ledger.acquisition.tracked_identities(),
             ledger.vesting.active_vestings(), ledger.governance.active_proposals(),
             ledger.records_processed,
             peers.banned_count(), peers.in_backoff_count(), tt)
        };
    // These still need direct lock access (not in snapshot)
    let (consensus_attestations, finalized_settled, witness_profiles_count, attestation_diversity,
         pending_anchors, pending_anchor_oldest_split, pending_anchor_retroactive, ratio_summary,
         committee_size, missing_creator_stake) = {
        let c = state.consensus.lock_recover();
        (c.total_attestation_count(), c.settled_count(), c.profiles().count(),
         c.mean_diversity_score(), c.pending_anchor_count(),
         c.seal_pending_anchor_oldest_at_split(),
         c.seal_pending_anchor_retroactive_count(),
         c.attestation_ratio_summary(),
         c.committee_size_summary(),
         c.missing_creator_stake_count())
    };
    // Pending-anchor oldest-age — `now - oldest finalized_at`
    // across seals waiting for an anchor signature. 0 when sub-population
    // empty (Prometheus-friendly; absence of work is age-zero, not unknown).
    // The age is split by retroactive-vs-local so operators can alarm on
    // each failure mode separately:
    //   * local age > anchor-sig timeout = anchor service stalled
    //   * retro age > 24h + slop = `promote_anchored` not draining
    // Combined `_oldest_age_seconds` retained for backward-compat dashboards;
    // it is `max(local_age, retro_age)` since older timestamp ⇒ older age.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    let age_or_zero = |opt_ts: Option<f64>| match opt_ts {
        Some(ts) => (now - ts).max(0.0),
        None => 0.0,
    };
    let (pending_anchor_oldest_local_at, pending_anchor_oldest_retro_at) = pending_anchor_oldest_split;
    let pending_anchor_oldest_age_local_secs = age_or_zero(pending_anchor_oldest_local_at);
    let pending_anchor_oldest_age_retro_secs = age_or_zero(pending_anchor_oldest_retro_at);
    let pending_anchor_oldest_age_secs =
        pending_anchor_oldest_age_local_secs.max(pending_anchor_oldest_age_retro_secs);

    let gossip_push = state.gossip_push_total.load(std::sync::atomic::Ordering::Relaxed);
    let gossip_relay = state.gossip_relay_total.load(std::sync::atomic::Ordering::Relaxed);
    let gossip_pull = state.gossip_pull_total.load(std::sync::atomic::Ordering::Relaxed);
    let gossip_pap_announcements = state
        .gossip_push_after_pull_announcements_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let gossip_pap_at_cap = state
        .gossip_push_after_pull_at_cap_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let gossip_pap_cycles = state
        .gossip_push_after_pull_cycles_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let gossip_pap_max = state
        .gossip_push_after_pull_max
        .load(std::sync::atomic::Ordering::Relaxed);
    let gossip_pap_autotune_raises = state
        .gossip_push_after_pull_autotune_raises_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let gossip_pap_autotune_lowers = state
        .gossip_push_after_pull_autotune_lowers_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let gossip_push_skipped = state.gossip_push_skipped_total.load(std::sync::atomic::Ordering::Relaxed);
    let gossip_seen_dedup = state.gossip_seen_dedup_total.load(std::sync::atomic::Ordering::Relaxed);
    let gossip_push_failed = state.gossip_push_failed_total.load(std::sync::atomic::Ordering::Relaxed);
    let gossip_retry = state.gossip_retry_total.load(std::sync::atomic::Ordering::Relaxed);
    let gossip_retry_success = state.gossip_retry_success_total.load(std::sync::atomic::Ordering::Relaxed);
    let aw_cycles = state.auto_witness_cycles_total.load(std::sync::atomic::Ordering::Relaxed);
    let aw_records = state.auto_witness_records_total.load(std::sync::atomic::Ordering::Relaxed);
    let aw_failures = state.auto_witness_failures_total.load(std::sync::atomic::Ordering::Relaxed);
    let aw_zombie_skipped = state
        .auto_witness_zombie_repush_skipped_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let aw_skips_orphan = state
        .auto_witness_skips_orphan_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let aw_skips_not_staked = state
        .auto_witness_skips_not_staked_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let aw_skips_no_jury = state
        .auto_witness_skips_no_jury_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let sv_withheld_behind = state
        .seal_verify_before_attest_withheld_behind_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let sv_withheld_omission = state
        .seal_verify_before_attest_withheld_omission_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let sv_withheld_root_mismatch = state
        .seal_verify_before_attest_withheld_root_mismatch_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let sv_withheld_malformed = state
        .seal_verify_before_attest_withheld_malformed_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let seal_p5_entered = state
        .seal_ingest_phase5_entered_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let seal_p5_completed = state
        .seal_ingest_phase5_completed_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let seal_extract_err = state
        .seal_ingest_extract_err_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let seal_derive_attempts = state
        .seal_ingest_derive_hook_attempts_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let gossip_seal_reject = state
        .gossip_seal_insert_reject_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let gossip_seal_declined_stale = state
        .gossip_seal_declined_stale_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let seal_reentry = state
        .seal_ingest_reentry_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let gossip_push_rejected_profile = state
        .gossip_push_rejected_profile_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let delegation_op_rejected_role = state
        .delegation_op_rejected_role_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let profile_c_gate_rejected = state
        .profile_c_gate_rejected_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let attestation_gate_rejected = state
        .attestation_gate_rejected_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let revoke_all_voluntary = state
        .revoke_all_voluntary_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let revoke_all_involuntary = state
        .revoke_all_involuntary_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let revoke_all_rejected = state
        .revoke_all_rejected_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let delegation_lease_expired = state
        .delegation_lease_expired_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let delegation_child_cap_rejected = state
        .delegation_child_cap_rejected_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let delegation_rate_cap_rejected = state
        .delegation_rate_cap_rejected_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let delegation_extend = state
        .delegation_extend_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let delegation_extend_rejected = state
        .delegation_extend_rejected_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let identity_user_evicted = state
        .identity_user_evicted_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let idp_promo_user_to_witness = state
        .identity_promotion_user_to_witness_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let idp_promo_user_to_anchor = state
        .identity_promotion_user_to_anchor_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let idp_promo_witness_to_anchor = state
        .identity_promotion_witness_to_anchor_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let idp_witness_purged = state
        .identity_witness_purged_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let idp_pk_fetch_attempts = state
        .identity_pk_fetch_attempts_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let idp_pk_fetch_hits = state
        .identity_pk_fetch_hits_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let idp_pk_fetch_misses = state
        .identity_pk_fetch_misses_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let (idp_anchor_count, idp_witness_count, idp_user_count, idp_legacy_count) =
        state.rocks.identity_tier_counts_estimated();
    let cross_zone_parent_observed = state
        .cross_zone_parent_observed_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let cross_zone_parent_rejected = state
        .cross_zone_parent_rejected_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let zone_ref_observed = state
        .zone_ref_observed_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let zone_ref_anchored = state
        .zone_ref_anchored_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let zone_ref_ghost = state
        .zone_ref_ghost_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let zone_ref_deferred = state
        .zone_ref_deferred_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let att_dedup = state.attestation_dedup_total.load(std::sync::atomic::Ordering::Relaxed);
    let att_push_attempted = state.attestation_push_attempted_total.load(std::sync::atomic::Ordering::Relaxed);
    let att_push_success = state.attestation_push_success_total.load(std::sync::atomic::Ordering::Relaxed);
    let att_push_skip_bw = state.attestation_push_skip_bandwidth_total.load(std::sync::atomic::Ordering::Relaxed);
    let att_bytes_out = state.attestation_bytes_out_total.load(std::sync::atomic::Ordering::Relaxed);
    let att_bytes_in = state.attestation_bytes_in_total.load(std::sync::atomic::Ordering::Relaxed);
    let att_processed_total = state.total_attestations_processed.load(std::sync::atomic::Ordering::Relaxed);
    let att_rej_bad_sig = state.attestation_receive_rejected_bad_signature_total.load(std::sync::atomic::Ordering::Relaxed);
    let att_pull_invalid_sig = state.attestation_pull_invalid_sig_total.load(std::sync::atomic::Ordering::Relaxed);
    let att_pull_invalid_powas = state.attestation_pull_invalid_powas_total.load(std::sync::atomic::Ordering::Relaxed);
    let att_rej_unknown_pk = state.attestation_receive_rejected_unknown_pk_total.load(std::sync::atomic::Ordering::Relaxed);
    let att_rej_low_stake = state.attestation_receive_rejected_low_stake_total.load(std::sync::atomic::Ordering::Relaxed);
    let att_rej_too_young = state.attestation_receive_rejected_too_young_total.load(std::sync::atomic::Ordering::Relaxed);
    let att_rej_bad_powas = state.attestation_receive_rejected_bad_powas_total.load(std::sync::atomic::Ordering::Relaxed);
    let att_deferred_total = state.attestation_receive_deferred_total.load(std::sync::atomic::Ordering::Relaxed);
    let att_deferred_evicted_total = state.attestation_deferred_evicted_total.load(std::sync::atomic::Ordering::Relaxed);
    let (att_deferred_records, att_deferred_buffered) = state.deferred_attestation_counts();
    let propagation_tracked_identities = state.propagation_limiter.lock_recover().tracked_identities();
    let att_low_stake_deferred_total = state.attestation_receive_low_stake_deferred_total.load(std::sync::atomic::Ordering::Relaxed);
    let att_low_stake_drained_total = state.attestation_receive_low_stake_drained_total.load(std::sync::atomic::Ordering::Relaxed);
    let att_low_stake_expired_total = state.attestation_receive_low_stake_expired_total.load(std::sync::atomic::Ordering::Relaxed);
    let att_push_unattributed_total = state.att_push_unattributed_total.load(std::sync::atomic::Ordering::Relaxed);
    // Incremental atomics — was a `low_stake_deferred.lock()` plus
    // `buf.values().flat_map(...).fold(min)` and `buf.values().sum()`, both
    // O(total entries) under the buffer mutex (which the ingest hot path
    // also takes via `buffer_low_stake_attestation`). Counters are
    // maintained at every mutation site in `low_stake_replay`; the scrape
    // path now reads them with three relaxed atomic loads.
    let (att_low_stake_witnesses, att_low_stake_buffered, att_low_stake_oldest_age_secs) = {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        let witnesses = state
            .low_stake_deferred_witnesses
            .load(std::sync::atomic::Ordering::Relaxed);
        let buffered = state
            .low_stake_deferred_total
            .load(std::sync::atomic::Ordering::Relaxed);
        let oldest_bits = state
            .low_stake_deferred_oldest_at_bits
            .load(std::sync::atomic::Ordering::Relaxed);
        let oldest_received_at = f64::from_bits(oldest_bits);
        let oldest_age = if oldest_received_at.is_finite() {
            (now - oldest_received_at).max(0.0)
        } else {
            0.0
        };
        (witnesses, buffered, oldest_age)
    };
    let dag_evict_cascade = state.dag_evict_finalized_cascade_total.load(std::sync::atomic::Ordering::Relaxed);
    let dag_hot_tier_full_rejections = state.dag_hot_tier_full_rejections_total.load(std::sync::atomic::Ordering::Relaxed);
    let lock_acq_dag_read_slow = state.lock_acquire_dag_read_slow_total.load(std::sync::atomic::Ordering::Relaxed);
    let lock_acq_dag_write_slow = state.lock_acquire_dag_write_slow_total.load(std::sync::atomic::Ordering::Relaxed);
    let dag_hot_tier_max = crate::dag::HOT_MAX_FALLBACK;
    let dag_hot_tier_utilization_ratio: f64 = if dag_hot_tier_max == 0 {
        0.0
    } else {
        dag_size as f64 / dag_hot_tier_max as f64
    };
    let auto_rewards = state.auto_rewards_total.load(std::sync::atomic::Ordering::Relaxed);
    let auto_rewards_amount = state.auto_rewards_amount_total.load(std::sync::atomic::Ordering::Relaxed);
    let reconnect_attempts = state.peer_reconnect_attempts_total.load(std::sync::atomic::Ordering::Relaxed);
    let reconnect_success = state.peer_reconnect_success_total.load(std::sync::atomic::Ordering::Relaxed);
    let rate_limit_rejected = state.rate_limiter.get()
        .map(|rl| rl.rejected_total.load(std::sync::atomic::Ordering::Relaxed))
        .unwrap_or(0);
    let auto_banned = state.peer_auto_banned_total.load(std::sync::atomic::Ordering::Relaxed);
    let gc_pruned = state.gc_pruned_total.load(std::sync::atomic::Ordering::Relaxed);
    // Epoch-based pruning observability: per-reason GC
    // counters + cycle + duration + earliest-record-age gauge. `gc_pruned`
    // (above) preserved as the aggregate; the per-reason counters expose
    // the GcResult breakdown. `gc_oldest_record_age_seconds` is computed
    // from CF_IDX_TIMESTAMP via an O(1) seek-to-first — no scan even at
    // 10M+ records.
    let gc_pruned_expired = state.gc_pruned_expired_total.load(std::sync::atomic::Ordering::Relaxed);
    let gc_pruned_retention = state.gc_pruned_retention_total.load(std::sync::atomic::Ordering::Relaxed);
    let gc_pruned_sunken = state.gc_pruned_sunken_total.load(std::sync::atomic::Ordering::Relaxed);
    let gc_pruned_stale = state.gc_pruned_stale_total.load(std::sync::atomic::Ordering::Relaxed);
    let gc_compactions = state.gc_compactions_total.load(std::sync::atomic::Ordering::Relaxed);
    let startup_compactions = state.startup_compactions_total.load(std::sync::atomic::Ordering::Relaxed);
    let gc_pruned_seals = state.gc_pruned_seals_total.load(std::sync::atomic::Ordering::Relaxed);
    let gc_pruned_epoch = state.gc_pruned_epoch_total.load(std::sync::atomic::Ordering::Relaxed);
    let gc_cycles = state.gc_cycles_total.load(std::sync::atomic::Ordering::Relaxed);
    let gc_last_cycle_duration_ms = state.gc_last_cycle_duration_ms.load(std::sync::atomic::Ordering::Relaxed);
    let gc_last_cycle_unix_ts = state.gc_last_cycle_unix_ts.load(std::sync::atomic::Ordering::Relaxed);
    let gc_scan_capped = state.gc_scan_capped_total.load(std::sync::atomic::Ordering::Relaxed);
    let gc_oldest_record_age_seconds: f64 = match state.rocks.earliest_record_timestamp() {
        Some(earliest_ts) => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs_f64())
                .unwrap_or(0.0);
            (now - earliest_ts).max(0.0)
        }
        None => 0.0, // no records on disk
    };
    let fork_heals = state.fork_heals_total.load(std::sync::atomic::Ordering::Relaxed);
    let persistent_divergence = state
        .peer_persistent_divergence_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let persistent_divergence_resolved = state
        .peer_persistent_divergence_resolved_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let divergence_streaks_active = state.peer_divergence_first_seen.lock().await.len();

    let push_fail_rate = if gossip_push > 0 { gossip_push_failed as f64 / gossip_push as f64 } else { 0.0 };
    // Reuse the same peers_check the /health rollup uses so the
    // elara_readiness_level gauge can never drift from the /health JSON.
    let peers_status = super::health::peers_check(
        connected_peers,
        state.config.health_min_peers as usize,
        gossip_push,
        super::health::inbound_sync_age_secs(&state),
    )
    .status;
    let readiness_level = super::health::determine_readiness(
        connected_peers, push_fail_rate, gossip_push, &peers_status,
    );

    // Incremental counter — was `latest_epoch.values().map(|n| n+1).sum()`,
    // O(zones) under the epoch read lock on every scrape. Counter is maintained
    // at every `latest_epoch` mutation site and on snapshot restore.
    let (
        epoch_count,
        za_tracked,
        za_rate_max,
        za_rate_avg,
        za_above_split,
        za_below_merge,
    ): (usize, usize, f64, f64, usize, usize) = {
        let epoch = state.epoch.read_recover();
        let epoch_count = epoch.total_epochs_total as usize;
        // Gap 4 follow-up: cardinality-safe summary of
        // `EpochState.zone_activity_rate` for the autoscaler operator
        // surface. A per-zone variant
        // `elara_zone_activity_rate{zone="…"}` — one gauge per zone —
        // would emit 1M time-series at the §11.12 mainnet
        // scale target and OOM Prometheus. Instead we publish 5
        // bounded gauges that answer the same operator questions:
        // "is there a hot zone? how hot? are any near the split
        // band? are any near the merge band?". Same pattern as
        // `elara_dag_max_tips_in_zone` (DAM-3D Phase B above).
        let split_threshold =
            super::auto_scale::TARGET_ZONE_RATE * super::auto_scale::SPLIT_RATE_MULTIPLIER;
        let merge_threshold =
            super::auto_scale::TARGET_ZONE_RATE * super::auto_scale::MERGE_RATE_MULTIPLIER;
        let mut tracked: usize = 0;
        let mut total: f64 = 0.0;
        let mut rate_max: f64 = 0.0;
        let mut above_split: usize = 0;
        let mut below_merge: usize = 0;
        for rate in epoch.zone_activity_rate.values().copied() {
            if rate <= 0.0 {
                continue;
            }
            tracked += 1;
            total += rate;
            if rate > rate_max {
                rate_max = rate;
            }
            if rate > split_threshold {
                above_split += 1;
            } else if rate < merge_threshold {
                below_merge += 1;
            }
        }
        let rate_avg = if tracked > 0 { total / tracked as f64 } else { 0.0 };
        (
            epoch_count,
            tracked,
            rate_max,
            rate_avg,
            above_split,
            below_merge,
        )
    };
    let dht_size = state.dht.lock_recover().len();
    let effective_hops = state.effective_max_hops();

    let (witnesses_active, witnesses_tracked) = {
        let liveness = state.witness_liveness.lock_recover();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        (
            liveness.active_count(48.0 * 3600.0, now),
            liveness.tracked_count(),
        )
    };

    // DAM-3D Phase B: per-zone tip distribution. Cardinality-safe summary
    // metrics — we never emit one label per zone (worst case 1M zones).
    // Distinct shadow size + max-tips-in-any-zone is enough to flag
    // imbalance and verify the index is being populated.
    let (dag_zones_with_tips, dag_max_tips_in_zone) = {
        let dag = state.dag.read().await;
        let max_tips = dag.tips_per_zone_iter().map(|(_, n)| n).max().unwrap_or(0);
        (dag.zones_with_tips(), max_tips)
    };

    // ZSP Phase B: zone-keyed secondary index size. O(1) RocksDB property
    // queries — no scans even at 1M-zone scale. `entries` matches put_record
    // calls 1:1 once backfill catches up; `bytes` is the on-disk SST size of
    // the index CF (excludes obsolete files).
    let zone_idx_entries = state
        .rocks
        .approximate_cf_size(crate::storage::rocks::CF_RECORD_BY_ZONE);
    let zone_idx_bytes = state
        .rocks
        .cf_live_bytes(crate::storage::rocks::CF_RECORD_BY_ZONE);

    let body = format!(
        "# HELP elara_dag_size Number of records in the DAG\n\
         # TYPE elara_dag_size gauge\n\
         elara_dag_size {}\n\
         # HELP elara_dag_tips Number of DAG tip nodes\n\
         # TYPE elara_dag_tips gauge\n\
         elara_dag_tips {}\n\
         # HELP elara_dag_edges Number of DAG edges\n\
         # TYPE elara_dag_edges gauge\n\
         elara_dag_edges {}\n\
         # HELP elara_dag_hot_tier_max Hot-tier cap, the value of the HOT_MAX_FALLBACK constant. When elara_dag_size approaches this, ingest enters the eviction path and may eventually drop records (elara_dag_hot_tier_full_rejections_total). Surfaced as a gauge — not a config knob — so dashboards can divide elara_dag_size by it without hardcoding the constant.\n\
         # TYPE elara_dag_hot_tier_max gauge\n\
         elara_dag_hot_tier_max {dag_hot_tier_max}\n\
         # HELP elara_dag_hot_tier_utilization_ratio elara_dag_size / elara_dag_hot_tier_max, in [0.0, 1.0]. Above 0.9 = imminent rejection cliff; pair with eviction counters to diagnose. Above 0.95 sustained = settlement is not draining the DAG fast enough (check elara_consensus_settled, elara_pending_ledger_oldest_age_seconds). Mainnet operator alert: gauge >= 0.85 for >5min.\n\
         # TYPE elara_dag_hot_tier_utilization_ratio gauge\n\
         elara_dag_hot_tier_utilization_ratio {dag_hot_tier_utilization_ratio:.4}\n\
         # HELP elara_dag_evict_finalized_cascade_total Cumulative DAG hot-tier cascade evictions triggered. Increments once per ingest call where evict_old_epochs() returned 0 evictions AND DAG was still full, forcing fallback to evict_finalized() against the FinalizedIndex hot snapshot. Sustained non-zero rate = wiring drift between the finality monitor and dag.mark_finalized() (records finalized externally but never marked in dag.finalized_epoch). Should be near-zero in steady state. Pair with elara_dag_hot_tier_full_rejections_total to distinguish 'cascade saved us' from 'cascade also failed'.\n\
         # TYPE elara_dag_evict_finalized_cascade_total counter\n\
         elara_dag_evict_finalized_cascade_total {dag_evict_cascade}\n\
         # HELP elara_dag_hot_tier_full_rejections_total Cumulative records rejected at ingest because BOTH evict_old_epochs() AND the cascade fallback failed to free room. Each increment is one record dropped on the floor. ANY non-zero rate is a production incident. Causes: (a) genuine 50K+ unfinalized backlog (settlement broken), (b) cold-boot race (finalized indices not caught up), (c) mark_finalized() wiring regression. Fleet-wide alert: rate(elara_dag_hot_tier_full_rejections_total[5m]) > 0.\n\
         # TYPE elara_dag_hot_tier_full_rejections_total counter\n\
         elara_dag_hot_tier_full_rejections_total {dag_hot_tier_full_rejections}\n\
         # HELP elara_lock_acquire_dag_read_slow_total Cumulative slow state.dag.read() acquires (>500ms) in the ingest path's eviction-check site (network/ingest.rs ~586). Previously the only signal was the journal-grep WARN at 5000ms; this counter fires an order of magnitude earlier so contention surfaces in Prometheus before it becomes a hard-warn. Sustained non-zero rate = competing writers or eviction-cascade holding the write lock. Cross-correlate with elara_dag_hot_tier_utilization_ratio (DAG-fill triggers eviction which holds write lock for the full evict_old_epochs() + cascade pass).\n\
         # TYPE elara_lock_acquire_dag_read_slow_total counter\n\
         elara_lock_acquire_dag_read_slow_total {lock_acq_dag_read_slow}\n\
         # HELP elara_lock_acquire_dag_write_slow_total Cumulative slow state.dag.write() acquires (>500ms) at the record-insert stage of ingest. Same 500ms threshold as elara_lock_acquire_dag_read_slow_total; this counter surfaces write-lock contention an order of magnitude before it becomes a hard warning. Mainnet operator alert: rate(elara_lock_acquire_dag_write_slow_total[5m]) > 0.5 = ingest serializing on DAG writes (1+ slow every 2s).\n\
         # TYPE elara_lock_acquire_dag_write_slow_total counter\n\
         elara_lock_acquire_dag_write_slow_total {lock_acq_dag_write_slow}\n\
         # HELP elara_dag_zones_with_tips Distinct zones in per-zone tip frontier shadow\n\
         # TYPE elara_dag_zones_with_tips gauge\n\
         elara_dag_zones_with_tips {}\n\
         # HELP elara_dag_max_tips_in_zone Largest per-zone tip count (imbalance signal)\n\
         # TYPE elara_dag_max_tips_in_zone gauge\n\
         elara_dag_max_tips_in_zone {}\n\
         # HELP elara_zone_activity_zones_tracked Count of zones with non-zero EMA rec/s in EpochState.zone_activity_rate. Bounded-cardinality summary of the per-zone activity table — we never emit `{{zone=\"…\"}}` labels (1M-zone mainnet target would OOM Prometheus). Pair with the four `elara_zone_activity_rate_*` siblings for the full autoscaler operator surface.\n\
         # TYPE elara_zone_activity_zones_tracked gauge\n\
         elara_zone_activity_zones_tracked {za_tracked}\n\
         # HELP elara_zone_activity_rate_max Hottest zone's EMA record-rate in rec/s. Above `TARGET_ZONE_RATE × SPLIT_RATE_MULTIPLIER` (40 rec/s at default constants) the autoscaler arms a Split decision. Compare with `elara_zone_activity_rate_avg` for hot-spot detection — single hot zone vs. uniform load.\n\
         # TYPE elara_zone_activity_rate_max gauge\n\
         elara_zone_activity_rate_max {za_rate_max:.4}\n\
         # HELP elara_zone_activity_rate_avg Arithmetic mean of EMA rec/s across zones with non-zero activity. This is the value that feeds `recommend_zone_count` and drives the autoscaler hysteresis counter. Sustained above SPLIT_RATE_MULTIPLIER × TARGET_ZONE_RATE for `HYSTERESIS_TICKS` consecutive ticks triggers a Split.\n\
         # TYPE elara_zone_activity_rate_avg gauge\n\
         elara_zone_activity_rate_avg {za_rate_avg:.4}\n\
         # HELP elara_zone_activity_zones_above_split Count of zones whose EMA rec/s exceeds `TARGET_ZONE_RATE × SPLIT_RATE_MULTIPLIER` (split threshold). The autoscaler decides on the *average*, but this gauge surfaces the count so operators can distinguish 'one runaway zone' (count=1) from 'uniformly hot fleet' (count≈total).\n\
         # TYPE elara_zone_activity_zones_above_split gauge\n\
         elara_zone_activity_zones_above_split {za_above_split}\n\
         # HELP elara_zone_activity_zones_below_merge Count of zones whose EMA rec/s is positive but below `TARGET_ZONE_RATE × MERGE_RATE_MULTIPLIER` (merge threshold = 2 rec/s at default). Sustained non-zero count is the merge candidate signal — pair with `elara_zone_count` and the autoscaler counters in `/admin/zone_autoscale` to verify hysteresis is closing in on a Merge decision.\n\
         # TYPE elara_zone_activity_zones_below_merge gauge\n\
         elara_zone_activity_zones_below_merge {za_below_merge}\n\
         # HELP elara_zone_idx_entries Estimated entries in CF_RECORD_BY_ZONE (O(1) RocksDB property)\n\
         # TYPE elara_zone_idx_entries gauge\n\
         elara_zone_idx_entries {}\n\
         # HELP elara_zone_idx_bytes Live SST bytes for CF_RECORD_BY_ZONE\n\
         # TYPE elara_zone_idx_bytes gauge\n\
         elara_zone_idx_bytes {}\n\
         # HELP elara_ledger_supply_micros Total credit supply in base units (10^9 base units = 1 beat; _micros suffix is a legacy metric name — the unit is base/nano-scale, not micro)\n\
         # TYPE elara_ledger_supply_micros gauge\n\
         elara_ledger_supply_micros {}\n\
         # HELP elara_ledger_staked_micros Total staked in base units (10^9 base units = 1 beat; _micros suffix is a legacy metric name)\n\
         # TYPE elara_ledger_staked_micros gauge\n\
         elara_ledger_staked_micros {}\n\
         # HELP elara_ledger_accounts Number of ledger accounts\n\
         # TYPE elara_ledger_accounts gauge\n\
         elara_ledger_accounts {}\n\
         # HELP elara_peers_connected Number of connected peers\n\
         # TYPE elara_peers_connected gauge\n\
         elara_peers_connected {}\n\
         # HELP elara_peers_total Total known peers\n\
         # TYPE elara_peers_total gauge\n\
         elara_peers_total {}\n\
         # HELP elara_finalized_count Number of finalized records\n\
         # TYPE elara_finalized_count gauge\n\
         elara_finalized_count {}\n\
         # HELP elara_consensus_attestations Attestations currently held in the in-flight attestation map (point-in-time gauge, NOT a lifetime counter). Records evict from this map once finalized via consensus.prune_finalized()/prune_finalized_atomic, so steady-state value tracks ~hot-tier × avg-attestations-per-record, not history. For lifetime attestation throughput see elara_attestations_processed_total. Operator confusion to avoid: this dropping near 0 on a long-running quiet node is correct behavior, not a settlement failure — the records that ever held attestations have all settled and been pruned to elara_total_ever_settled.\n\
         # TYPE elara_consensus_attestations gauge\n\
         elara_consensus_attestations {}\n\
         # HELP elara_consensus_settled Records currently in the in-flight attestation map that pass is_settled (2/3 stake threshold). Point-in-time gauge — drops to ~0 quickly because settled records cascade to Finalized confirmation level and prune out of the attestations map. Sustained 0 on a healthy node is normal; what an operator actually wants is elara_total_ever_settled (lifetime counter), which stays monotonic across pruning. Sustained non-zero IS a signal of settlement-stuck records — pair with elara_pending_ledger_oldest_age_seconds to diagnose.\n\
         # TYPE elara_consensus_settled gauge\n\
         elara_consensus_settled {}\n\
         # HELP elara_consensus_records_tracked Records currently held in the in-flight attestation map (denominator for the ratio gauges below). Same value as elara_consensus_attestations divided by avg-attestations-per-record; surfaced separately so alerts can divide best/mean ratio gauges by tracked-count without cardinality.\n\
         # TYPE elara_consensus_records_tracked gauge\n\
         elara_consensus_records_tracked {}\n\
         # HELP elara_consensus_records_ratiable Subset of tracked records whose zone has registered stake (eligible_stake > 0). Records with eligible_stake == 0 cannot settle by definition and are excluded from the best/mean ratio gauges; tracked minus ratiable is the count waiting on zone stake registration. This count mechanically includes elara_consensus_records_at_threshold (at-threshold records have eligible_stake > 0 by construction), so during a settlement burst the at-threshold count surges and inflates ratiable proportionally, then both drain together on event exit (near mass-conserving). Operator implication: a ratiable collapse immediately following a best-attestation-ratio excursion is the expected revert to steady state, not a settlement failure -- ignore single-tick ratiable drops that are paired with at-threshold drops.\n\
         # TYPE elara_consensus_records_ratiable gauge\n\
         elara_consensus_records_ratiable {}\n\
         # HELP elara_consensus_best_attestation_ratio Highest attesting_stake/eligible_stake ratio across all in-flight records (0.0..1.0): the max over tracked records of sum(attestation stake) / (zone settlement denominator - creator stake). This is the RAW stake sum, not the correlation-discounted effective stake, so the gauge stays comparable across nodes with differing witness-correlation views. It is a per-record maximum, NOT a fleet-wide attendance ratio -- a single record at full-stake attestation pins it to 1.0 regardless of how many other records are tracked. Settlement threshold is 2/3 ~= 0.667. Sustained best_ratio < 0.667 with non-zero tracked records means settlement is stuck, usually a peer-count regression where the node sees only a minority of witnesses so attestations cap below threshold. To tell a structural cap (persistent stake/witness skew) from a transient one (a witness cohort in catchup-skip), compare elara_seal_loop_ticks_total across the fleet: if some nodes report 0 while others are positive the cap is operational and recovers as the zero-tick cohort resumes sealing; if all nodes are positive yet the ratio still caps below 2/3 the cap is structural and needs witness/stake reconfiguration. Note the periodic finality-diag log uses raw_attesting_stake/total_zone_stake (no creator-stake subtraction) and so reads lower than this gauge by roughly (N-1)/N for N witnesses.\n\
         # TYPE elara_consensus_best_attestation_ratio gauge\n\
         elara_consensus_best_attestation_ratio {:.4}\n\
         # HELP elara_consensus_mean_attestation_ratio Mean attesting_stake/eligible_stake ratio across ratiable records (0.0..1.0). Slow drift toward 0 with rising tracked count = pile-up of records that aren't attracting attestations; pair with peer-count and gossip metrics to localise.\n\
         # TYPE elara_consensus_mean_attestation_ratio gauge\n\
         elara_consensus_mean_attestation_ratio {:.4}\n\
         # HELP elara_consensus_records_at_threshold Records currently in the attestation map whose attesting_stake satisfies attesting * 3 >= eligible * 2 (i.e. would settle on next tick). Should be approximately equal to elara_consensus_settled in steady state; large divergence indicates a stuck settlement->finalization path.\n\
         # TYPE elara_consensus_records_at_threshold gauge\n\
         elara_consensus_records_at_threshold {}\n\
         # HELP elara_bratio_cohort_membership Per-node settlement-state code (0-4) classifying this node against the best-attestation-ratio bands. Codes: 0 = DORMANT (tracked == 0, nothing to attest), 1 = LOCKED (tracked > 0 with best_ratio < 0.60 -- covers both the zone-stake-unregistered ratiable==0 sub-state and the anchored-low sub-state; disambiguate via elara_consensus_records_ratiable), 2 = CONVERGED (0.60 <= best_ratio < 0.667, the steady-state attractor), 3 = ACTIVE (0.667 <= best_ratio < 0.999, mid-settlement burst), 4 = HYPER_ACTIVE (best_ratio >= 0.999, full-stake attestation). The code is monotonic in settlement health -- higher means more activity -- and the CONVERGED/ACTIVE boundary at 2/3 ~= 0.6667 is the structural settlement threshold. Apply count_values over this gauge across the fleet to get the cluster cohort histogram; sustained inter-tick band divergence (more than one cohort across 2+ consecutive ticks without collapsing back to a single cohort) is the real cluster-health alarm, whereas single-tick multi-cohort excursions are the normal settlement-event signature and should not page.\n\
         # TYPE elara_bratio_cohort_membership gauge\n\
         elara_bratio_cohort_membership {}\n\
         # HELP elara_bratio_band_ticks_total Per-node dwell counters for the settlement bands -- one labeled counter per band, incremented once per seal-loop tick that survived catchup-skip. The five counters partition elara_seal_loop_ticks_total exactly (their sum equals the tick count). rate(elara_bratio_band_ticks_total{{band=BAND}}[5m]) gives the fraction of recent ticks this node spent in BAND. Sustained rate({{band=LOCKED}}) > 0 on a single node indicates stake-config or witness-committee divergence; uniform rate({{band=CONVERGED}}) ~= 1.0 across the fleet is the resting-state signature; non-zero rate({{band=ACTIVE}}) / rate({{band=HYPER_ACTIVE}}) is that node's settlement-event participation rate. Band labels match elara_bratio_cohort_membership: DORMANT, LOCKED (< 0.60), CONVERGED (0.60-0.667), ACTIVE (0.667-0.999), HYPER_ACTIVE (>= 0.999).\n\
         # TYPE elara_bratio_band_ticks_total counter\n\
         elara_bratio_band_ticks_total{{band=\"DORMANT\"}} {}\n\
         elara_bratio_band_ticks_total{{band=\"LOCKED\"}} {}\n\
         elara_bratio_band_ticks_total{{band=\"CONVERGED\"}} {}\n\
         elara_bratio_band_ticks_total{{band=\"ACTIVE\"}} {}\n\
         elara_bratio_band_ticks_total{{band=\"HYPER_ACTIVE\"}} {}\n\
         # HELP elara_uptime_seconds Node uptime in seconds\n\
         # TYPE elara_uptime_seconds gauge\n\
         elara_uptime_seconds {}\n\
         # HELP elara_records_processed Total ledger records processed\n\
         # TYPE elara_records_processed counter\n\
         elara_records_processed {}\n\
         # HELP elara_gossip_push_total Total originator gossip pushes\n\
         # TYPE elara_gossip_push_total counter\n\
         elara_gossip_push_total {}\n\
         # HELP elara_gossip_relay_total Total relay forwards\n\
         # TYPE elara_gossip_relay_total counter\n\
         elara_gossip_relay_total {}\n\
         # HELP elara_gossip_pull_total Total records received via pull\n\
         # TYPE elara_gossip_pull_total counter\n\
         elara_gossip_pull_total {}\n\
         # HELP elara_gossip_push_after_pull_announcements_total Cumulative announcements sent in push-after-pull cycles\n\
         # TYPE elara_gossip_push_after_pull_announcements_total counter\n\
         elara_gossip_push_after_pull_announcements_total {}\n\
         # HELP elara_gossip_push_after_pull_at_cap_total Push-after-pull cycles that hit MAX_PUSH cap (sustained non-zero = autotune will raise)\n\
         # TYPE elara_gossip_push_after_pull_at_cap_total counter\n\
         elara_gossip_push_after_pull_at_cap_total {}\n\
         # HELP elara_gossip_push_after_pull_cycles_total Push-after-pull cycles that emitted announcements (denominator for cap-hit rate)\n\
         # TYPE elara_gossip_push_after_pull_cycles_total counter\n\
         elara_gossip_push_after_pull_cycles_total {}\n\
         # HELP elara_gossip_push_after_pull_max Current effective push-after-pull MAX_PUSH cap (autotune adjusts in [50, 800])\n\
         # TYPE elara_gossip_push_after_pull_max gauge\n\
         elara_gossip_push_after_pull_max {}\n\
         # HELP elara_gossip_push_after_pull_autotune_raises_total Times autotune doubled the cap (cap-hit rate exceeded raise threshold)\n\
         # TYPE elara_gossip_push_after_pull_autotune_raises_total counter\n\
         elara_gossip_push_after_pull_autotune_raises_total {}\n\
         # HELP elara_gossip_push_after_pull_autotune_lowers_total Times autotune halved the cap (cap-hit rate fell below lower threshold)\n\
         # TYPE elara_gossip_push_after_pull_autotune_lowers_total counter\n\
         elara_gossip_push_after_pull_autotune_lowers_total {}\n\
         # HELP elara_gossip_push_skipped_total Pushes skipped (hops exhausted)\n\
         # TYPE elara_gossip_push_skipped_total counter\n\
         elara_gossip_push_skipped_total {}\n\
         # HELP elara_gossip_seen_dedup_total Duplicate records deduplicated\n\
         # TYPE elara_gossip_seen_dedup_total counter\n\
         elara_gossip_seen_dedup_total {}\n\
         # HELP elara_gossip_push_failed_total Gossip push attempts that failed\n\
         # TYPE elara_gossip_push_failed_total counter\n\
         elara_gossip_push_failed_total {}\n\
         # HELP elara_gossip_retry_total DHT fallback retry attempts\n\
         # TYPE elara_gossip_retry_total counter\n\
         elara_gossip_retry_total {}\n\
         # HELP elara_gossip_retry_success_total Successful DHT fallback retries\n\
         # TYPE elara_gossip_retry_success_total counter\n\
         elara_gossip_retry_success_total {}\n\
         # HELP elara_epoch_seals_total Total epoch seals across all zones\n\
         # TYPE elara_epoch_seals_total gauge\n\
         elara_epoch_seals_total {}\n\
         # HELP elara_dht_size Number of peers in DHT routing table\n\
         # TYPE elara_dht_size gauge\n\
         elara_dht_size {}\n\
         # HELP elara_gossip_effective_hops Adaptive gossip hop limit\n\
         # TYPE elara_gossip_effective_hops gauge\n\
         elara_gossip_effective_hops {}\n\
         # HELP elara_witness_profiles_registered Number of registered witness profiles\n\
         # TYPE elara_witness_profiles_registered gauge\n\
         elara_witness_profiles_registered {}\n\
         # HELP elara_auto_witness_cycles_total Auto-witness cycles completed by this node's auto_witness run loop. Increments only when the local node has been selected into the epoch committee for at least one zone (the per-zone VRF committee gate); nodes outside every committee skip past the counter and stay at 0 indefinitely. This is decoupled from settlement-state attestation -- receiving peer attestations, participating in attestation cascades, or settling records via incoming witness traffic does NOT increment it. So a reading of 0 means 'this node has not been a committee juror recently', NOT 'this node is silent on the network'. Operator implication: do not page on a 0 value during cluster-wide settlement excursions -- 0 on a non-juror node is the expected baseline regardless of fleet activity, and a peer's non-zero value during cluster events does not imply the 0 node is misconfigured or partitioned.\n\
         # TYPE elara_auto_witness_cycles_total counter\n\
         elara_auto_witness_cycles_total {}\n\
         # HELP elara_auto_witness_records_total Records auto-witnessed\n\
         # TYPE elara_auto_witness_records_total counter\n\
         elara_auto_witness_records_total {}\n\
         # HELP elara_auto_witness_failures_total Auto-witness signing failures\n\
         # TYPE elara_auto_witness_failures_total counter\n\
         elara_auto_witness_failures_total {}\n\
         # HELP elara_auto_witness_zombie_repush_skipped_total Auto-witness re-push attempts skipped because the attestation timestamp is past REPUSH_MAX_AGE_SECS=86400 — record is a zombie that will never settle. Sustained non-zero rate confirms a settlement-impossible backlog (record GC'd from peers' active disk).\n\
         # TYPE elara_auto_witness_zombie_repush_skipped_total counter\n\
         elara_auto_witness_zombie_repush_skipped_total {aw_zombie_skipped}\n\
         # HELP elara_auto_witness_skips_orphan_total Auto-witness loop iterations that skipped on the catchup-guard at auto_witness.rs:101 (dag.orphan_count() > 1000). Operator signal: node is in initial sync, ingest backlog, or eviction-window pressure. Closes the cycles_total=0 blindspot - pair with elara_orphan_resolver_high_count_pruned_total to see whether catchup pressure is actually clearing.\n\
         # TYPE elara_auto_witness_skips_orphan_total counter\n\
         elara_auto_witness_skips_orphan_total {aw_skips_orphan}\n\
         # HELP elara_auto_witness_skips_not_staked_total Auto-witness loop iterations that skipped because the local identity has staked_amount==0 (auto_witness.rs:128). Operator signal: node_type=witness but no stake on the local identity. Likely a fresh node that has not yet earned stake, or a slashed/unstaked witness. Pairs with elara_ledger_staked.\n\
         # TYPE elara_auto_witness_skips_not_staked_total counter\n\
         elara_auto_witness_skips_not_staked_total {aw_skips_not_staked}\n\
         # HELP elara_auto_witness_skips_no_jury_total Auto-witness loop iterations that skipped because the per-zone VRF committee selection picked zero zones for the local node (auto_witness.rs:186 — allowed_zones.is_empty()). Operator signal at a staked witness: local stake is too low to win the VRF lottery in any subscribed zone OR the node is subscribed to zero zones. Sustained non-zero alongside elara_ledger_staked > 0 indicates a stake/subscription configuration mismatch, not a wiring fault.\n\
         # TYPE elara_auto_witness_skips_no_jury_total counter\n\
         elara_auto_witness_skips_no_jury_total {aw_skips_no_jury}\n\
         # HELP elara_seal_verify_before_attest_withheld_total Epoch-seal co-signatures WITHHELD by the R3-9 verify-before-co-sign gate (auto_witness): the seal's enumerated (or re-derived) record list disagreed with the local view. reason=behind: seal lists records this node lacks or claims more than the local window holds (witness catching up, retried next cycle). reason=omission: this node holds MORE window records than the seal claims — definite omission; sustained non-zero at multi-anchor is the selective-finality alarm. reason=root_mismatch: equal counts, divergent Merkle root. reason=malformed: unparseable seal candidate. MOOT at single-authority testnet (an anchor cannot disagree with itself); load-bearing the moment staked anchors > 1.\n\
         # TYPE elara_seal_verify_before_attest_withheld_total counter\n\
         elara_seal_verify_before_attest_withheld_total{{reason=\"behind\"}} {sv_withheld_behind}\n\
         elara_seal_verify_before_attest_withheld_total{{reason=\"omission\"}} {sv_withheld_omission}\n\
         elara_seal_verify_before_attest_withheld_total{{reason=\"root_mismatch\"}} {sv_withheld_root_mismatch}\n\
         elara_seal_verify_before_attest_withheld_total{{reason=\"malformed\"}} {sv_withheld_malformed}\n\
         # HELP elara_seal_ingest_phase5_entered_total Phase-5 seal-consumer block entries (successful post-storage seal parse). entered > completed = seals dying mid-block with no other trace (the R3-8 soak silent class).\n\
         # TYPE elara_seal_ingest_phase5_entered_total counter\n\
         elara_seal_ingest_phase5_entered_total {seal_p5_entered}\n\
         # HELP elara_seal_ingest_phase5_completed_total Phase-5 seal-consumer block completions (epoch registered, derive+deficit+witness-flush+finality done).\n\
         # TYPE elara_seal_ingest_phase5_completed_total counter\n\
         elara_seal_ingest_phase5_completed_total {seal_p5_completed}\n\
         # HELP elara_seal_ingest_extract_err_total extract_epoch_seal failures at Phase 5 for records carrying epoch_op — previously a silent skip of ALL seal consumers on this node.\n\
         # TYPE elara_seal_ingest_extract_err_total counter\n\
         elara_seal_ingest_extract_err_total {seal_extract_err}\n\
         # HELP elara_seal_ingest_derive_hook_attempts_total Derive-when-absent hook attempts at seal ingest (empty enumeration, record_count>0). attempts == elara_seal_enum_derived_total + elara_seal_enum_derive_miss_total contributions from this path.\n\
         # TYPE elara_seal_ingest_derive_hook_attempts_total counter\n\
         elara_seal_ingest_derive_hook_attempts_total {seal_derive_attempts}\n\
         # HELP elara_gossip_seal_insert_reject_total SEAL-class records rejected by ingest across gossip pull paths (full_pull/delta_pull/att-pull/orphan-resolver). Since the 8b fix the stale-gap class declines pre-crypto (see elara_gossip_seal_declined_stale_total) and never reaches ingest, so sustained growth here means genuinely-invalid seals from a peer — non-retryable rejects still enter the permanent gossip_rejected embargo.\n\
         # TYPE elara_gossip_seal_insert_reject_total counter\n\
         elara_gossip_seal_insert_reject_total {gossip_seal_reject}\n\
         # HELP elara_gossip_seal_declined_stale_total SEAL records declined PRE-CRYPTO by the stale-gap filter on the pull paths (timestamp/full/delta pull) — routed to declined_seal_ids, never the embargo or the park queue (8b). Expected to burst once per sweep of previously-unswept history, then quiesce as the retention-floored cursor stops the re-fetch; a sustained per-sweep plateau means a peer keeps serving history this node has pruned (benign, cheap) or an old-binary peer without the fix.\n\
         # TYPE elara_gossip_seal_declined_stale_total counter\n\
         elara_gossip_seal_declined_stale_total {gossip_seal_declined_stale}\n\
         # HELP elara_seal_ingest_reentry_total Stored-but-uncanonicalized seal re-entries through the storage-dedup short-circuit (8b design B, successor-re-admission): a stored seal at zone-tip+1 re-flows the full idempotent pipeline instead of dedup-skipping forever. Heals the chain-link-rejected honest successor after a phantom tip corrects; sustained growth WITHOUT the zone tip advancing = the tip it fails to chain to is still phantom.\n\
         # TYPE elara_seal_ingest_reentry_total counter\n\
         elara_seal_ingest_reentry_total {seal_reentry}\n\
         # HELP elara_gossip_push_rejected_profile_total Inbound record pushes rejected because the local node_profile (e.g. light) does not accept gossip pushes. Always 0 on full_zone/archive nodes; on light nodes a steady non-zero rate is the operator signal that peers haven't downgraded their fan-out yet.\n\
         # TYPE elara_gossip_push_rejected_profile_total counter\n\
         elara_gossip_push_rejected_profile_total {gossip_push_rejected_profile}\n\
         # HELP elara_delegation_op_rejected_role_total `delegation_op` records rejected because the creator is neither a Gateway/Anchor (per gossiped peer NodeType) nor stake-gated above MIN_STAKE_TO_DELEGATE (10000 beat). Sustained non-zero is an attempted authorization fraud or a misconfigured operator publishing delegations from a Leaf-typed node.\n\
         # TYPE elara_delegation_op_rejected_role_total counter\n\
         elara_delegation_op_rejected_role_total {delegation_op_rejected_role}\n\
         # HELP elara_profile_c_gate_rejected_total Records rejected at sig-verify because the creator is a registered delegation child (presumed Profile C) and signed with its own key instead of using parent proxy-sign. The IoT/constrained-device path requires the parent to sign on the child's behalf — a child with its own PQ keys defeats the whole delegation premise. Sustained non-zero is either misconfigured device firmware or an adversary trying to gain per-child accountability while inheriting parent stake.\n\
         # TYPE elara_profile_c_gate_rejected_total counter\n\
         elara_profile_c_gate_rejected_total {profile_c_gate_rejected}\n\
         # HELP elara_attestation_gate_rejected_total `delegation_op = authorize` records rejected because the parent's advertised hardware attestation level (max of ledger record + inline metadata) is below the configured MIN_ATTESTATION_FOR_GATEWAY floor. Mainnet floor is SECURE_BOOT (rank 2); testnet operators may set ELARA_MIN_ATTESTATION_FOR_GATEWAY=NONE to disable. Sustained non-zero is either operator misconfiguration (gateway not advertising via attestation_level metadata) or an adversary publishing authorize records from software-only nodes to inflate Gateway influence.\n\
         # TYPE elara_attestation_gate_rejected_total counter\n\
         elara_attestation_gate_rejected_total {attestation_gate_rejected}\n\
         # HELP elara_revoke_all_voluntary_total `delegation_op = revoke_all` ops accepted via the voluntary path: creator IS the parent_to_disarm (self-signed handoff). One tick per gateway voluntarily decommissioning itself.\n\
         # TYPE elara_revoke_all_voluntary_total counter\n\
         elara_revoke_all_voluntary_total {revoke_all_voluntary}\n\
         # HELP elara_revoke_all_involuntary_total `revoke_all` ops accepted via the involuntary (fisherman) path: sum of cosigner ledger stakes met or exceeded total_supply * 2/3. Each cosigner sig must verify against the canonical message via Dilithium3. Sustained non-zero means the fleet is using the slashing path to disarm compromised gateways.\n\
         # TYPE elara_revoke_all_involuntary_total counter\n\
         elara_revoke_all_involuntary_total {revoke_all_involuntary}\n\
         # HELP elara_revoke_all_rejected_total `revoke_all` ops rejected. Reasons: creator not parent AND cosigner stake < 2/3 supply, or malformed metadata, or insufficient valid cosigner signatures. Sustained non-zero is either an adversary attempting unauthorized mass-revocation or a malformed fisherman claim that didn't gather enough valid cosigners.\n\
         # TYPE elara_revoke_all_rejected_total counter\n\
         elara_revoke_all_rejected_total {revoke_all_rejected}\n\
         # HELP elara_delegation_lease_expired_total Children dropped by the periodic prune_expired tick because their lease (`expires_at`) elapsed. One tick per child whose parent failed to extend before the 30d default lease.\n\
         # TYPE elara_delegation_lease_expired_total counter\n\
         elara_delegation_lease_expired_total {delegation_lease_expired}\n\
         # HELP elara_delegation_child_cap_rejected_total `delegation_op = authorize` ops rejected because the parent already has MAX_CHILDREN_PER_PARENT (1M) active children. Hard cap protects every node's in-memory registry from one parent's blast radius.\n\
         # TYPE elara_delegation_child_cap_rejected_total counter\n\
         elara_delegation_child_cap_rejected_total {delegation_child_cap_rejected}\n\
         # HELP elara_delegation_rate_cap_rejected_total Authorize ops rejected because the parent has already authored MAX_AUTHORIZE_PER_PARENT_PER_HOUR (10K) authorize ops in the trailing hour. Sustained non-zero suggests a compromised gateway key being used to spam new child registrations.\n\
         # TYPE elara_delegation_rate_cap_rejected_total counter\n\
         elara_delegation_rate_cap_rejected_total {delegation_rate_cap_rejected}\n\
         # HELP elara_delegation_extend_total Successful `delegation_op = extend` ops. One tick per child whose lease was prolonged without re-issuing the full authorize record.\n\
         # TYPE elara_delegation_extend_total counter\n\
         elara_delegation_extend_total {delegation_extend}\n\
         # HELP elara_delegation_extend_rejected_total Extend ops rejected. Reasons: child not registered, creator not the recorded parent, or missing/malformed expires_at metadata.\n\
         # TYPE elara_delegation_extend_rejected_total counter\n\
         elara_delegation_extend_rejected_total {delegation_extend_rejected}\n\
         # HELP elara_identity_user_evicted_total Cumulative count of USER-tier identity entries dropped by the LRU eviction loop. Climbs steadily once CF_IDENTITIES_USER hits identity_user_cache_max; plateaus when inflow ≈ eviction.\n\
         # TYPE elara_identity_user_evicted_total counter\n\
         elara_identity_user_evicted_total {identity_user_evicted}\n\
         # HELP elara_identity_tier_anchor_count Estimated entry count in CF_IDENTITIES_ANCHOR (VRF-registered anchor PKs, never evicted). RocksDB estimate-num-keys, O(1) per scrape; replaces O(N) full-CF scan that was 4× per /metrics call.\n\
         # TYPE elara_identity_tier_anchor_count gauge\n\
         elara_identity_tier_anchor_count {idp_anchor_count}\n\
         # HELP elara_identity_tier_witness_count Estimated entry count in CF_IDENTITIES_WITNESS (zone-witness PKs, evicted on zone unsubscribe). RocksDB estimate-num-keys, O(1) per scrape.\n\
         # TYPE elara_identity_tier_witness_count gauge\n\
         elara_identity_tier_witness_count {idp_witness_count}\n\
         # HELP elara_identity_tier_user_count Estimated entry count in CF_IDENTITIES_USER (catch-all, LRU-bounded by identity_user_cache_max). RocksDB estimate-num-keys, O(1) per scrape; eviction loop still uses exact count_cf to enforce cap boundary.\n\
         # TYPE elara_identity_tier_user_count gauge\n\
         elara_identity_tier_user_count {idp_user_count}\n\
         # HELP elara_identity_tier_legacy_count Estimated entry count in legacy CF_IDENTITIES (pre-partition data, drained by future migration). RocksDB estimate-num-keys, O(1) per scrape.\n\
         # TYPE elara_identity_tier_legacy_count gauge\n\
         elara_identity_tier_legacy_count {idp_legacy_count}\n\
         # HELP elara_identity_promotion_user_to_witness_total Count of identities that physically migrated USER→WITNESS via class promotion (write to CF_IDENTITIES_WITNESS + tombstone of USER+TS+REV in one atomic batch). Bumps in process_deferred_attestations when a witness write finds a pre-existing user-tier entry.\n\
         # TYPE elara_identity_promotion_user_to_witness_total counter\n\
         elara_identity_promotion_user_to_witness_total {idp_promo_user_to_witness}\n\
         # HELP elara_identity_promotion_user_to_anchor_total Count of identities that physically migrated USER→ANCHOR. Currently only triggered by tests; production anchor writes will route through this counter once the genesis-anchor and VRF flows migrate to store_public_key_anchor.\n\
         # TYPE elara_identity_promotion_user_to_anchor_total counter\n\
         elara_identity_promotion_user_to_anchor_total {idp_promo_user_to_anchor}\n\
         # HELP elara_identity_promotion_witness_to_anchor_total Count of identities that physically migrated WITNESS→ANCHOR (write to CF_IDENTITIES_ANCHOR + tombstone of WITNESS in one atomic batch).\n\
         # TYPE elara_identity_promotion_witness_to_anchor_total counter\n\
         elara_identity_promotion_witness_to_anchor_total {idp_promo_witness_to_anchor}\n\
         # HELP elara_identity_witness_purged_total Cumulative count of witness-tier PKs dropped from CF_IDENTITIES_WITNESS because the unsubscribed zone was their last claim. Climbs when an operator unsubscribes a zone whose witness set was disjoint from every other zone they serve. Anchor-tier PKs are never touched.\n\
         # TYPE elara_identity_witness_purged_total counter\n\
         elara_identity_witness_purged_total {idp_witness_purged}\n\
         # HELP elara_identity_pk_fetch_attempts_total Cumulative count of on-miss peer-fetch attempts (`GET /identity/pk/{{hash}}` over PQ) initiated when a local PK lookup missed. Hits + misses must sum to attempts. A clean fleet on testnet sits at 0 because every PK is captured at ingest; mainnet under heavy onboarding ticks as new nodes verify records signed by previously-unobserved identities.\n\
         # TYPE elara_identity_pk_fetch_attempts_total counter\n\
         elara_identity_pk_fetch_attempts_total {idp_pk_fetch_attempts}\n\
         # HELP elara_identity_pk_fetch_hits_total On-miss fetches that returned a PK (cached locally in CF_IDENTITIES_USER before returning to the caller). hit_rate := hits/attempts is the canonical SLO for the on-miss path — should sit above 0.95 on a healthy mesh.\n\
         # TYPE elara_identity_pk_fetch_hits_total counter\n\
         elara_identity_pk_fetch_hits_total {idp_pk_fetch_hits}\n\
         # HELP elara_identity_pk_fetch_misses_total On-miss fetches that exhausted the candidate list without finding a peer holding the PK. Caller policy on miss is soft-fail (verification result = \"unknown PK\").\n\
         # TYPE elara_identity_pk_fetch_misses_total counter\n\
         elara_identity_pk_fetch_misses_total {idp_pk_fetch_misses}\n\
         # HELP elara_cross_zone_parent_observed_total Records observed at ingest with at least one parent in a zone other than the record's own zone (and not an ancestor). Always bumped, regardless of allow_cross_zone_parents. Sustained non-zero on testnet means legacy hash-derived parents from before the structural-zone gate landed; on mainnet, with allow_cross_zone_parents=false, this counter ticks alongside elara_cross_zone_parent_rejected_total.\n\
         # TYPE elara_cross_zone_parent_observed_total counter\n\
         elara_cross_zone_parent_observed_total {cross_zone_parent_observed}\n\
         # HELP elara_cross_zone_parent_rejected_total Records hard-rejected at ingest because allow_cross_zone_parents=false and at least one parent zone is not the record's zone or an ancestor. Mainnet path. On testnet (default config) this stays at 0 even when elara_cross_zone_parent_observed_total ticks.\n\
         # TYPE elara_cross_zone_parent_rejected_total counter\n\
         elara_cross_zone_parent_rejected_total {cross_zone_parent_rejected}\n\
         # HELP elara_zone_ref_observed_total Cumulative zone_refs entries observed across all ingested records. Each successfully-decoded ref is one tick — a record with three valid refs ticks this counter three times. Strict invariant: _observed == _anchored + _ghost + _deferred. Wire-decoder failures (malformed bytes <24B) skip both observed and classification together, preserving the invariant. Unit-tested at network/zone.rs::dam3d_c_count_zone_refs_*.\n\
         # TYPE elara_zone_ref_observed_total counter\n\
         elara_zone_ref_observed_total {zone_ref_observed}\n\
         # HELP elara_zone_ref_anchored_total zone_refs whose claimed (zone, epoch) resolves to a locally-known seal. Healthy path — node hosts the referenced zone AND CF_EPOCHS has an entry at that epoch. On a clean fleet _anchored + _deferred ≈ _observed and _ghost == 0.\n\
         # TYPE elara_zone_ref_anchored_total counter\n\
         elara_zone_ref_anchored_total {zone_ref_anchored}\n\
         # HELP elara_zone_ref_ghost_total Subscribed-and-no-seal zone_refs claiming a (zone, epoch) we host but for which no seal is on disk. Sustained non-zero is the operator signal that a partition or equivocating witness is seeding refs to fabricated seals. A future slice will hard-reject these.\n\
         # TYPE elara_zone_ref_ghost_total counter\n\
         elara_zone_ref_ghost_total {zone_ref_ghost}\n\
         # HELP elara_zone_ref_deferred_total zone_refs to zones we don't host. Cannot validate locally - provisionally accepted. A future slice will stage these into a pending_xzone_refs map with TTL+cap, graduating on gossip from a subscribing peer.\n\
         # TYPE elara_zone_ref_deferred_total counter\n\
         elara_zone_ref_deferred_total {zone_ref_deferred}\n\
         # HELP elara_attestation_dedup_total Duplicate attestation pushes suppressed\n\
         # TYPE elara_attestation_dedup_total counter\n\
         elara_attestation_dedup_total {}\n\
         # HELP elara_attestation_push_attempted_total Attestation fanout targets selected (before bandwidth filter)\n\
         # TYPE elara_attestation_push_attempted_total counter\n\
         elara_attestation_push_attempted_total {att_push_attempted}\n\
         # HELP elara_attestation_push_success_total Attestation pushes acknowledged by peer (2xx HTTP or PQ)\n\
         # TYPE elara_attestation_push_success_total counter\n\
         elara_attestation_push_success_total {att_push_success}\n\
         # HELP elara_attestation_push_skip_bandwidth_total Attestation targets dropped by per-peer bandwidth token\n\
         # TYPE elara_attestation_push_skip_bandwidth_total counter\n\
         elara_attestation_push_skip_bandwidth_total {att_push_skip_bw}\n\
         # HELP elara_attestation_bytes_out_total Cumulative attestation egress bytes (JSON payload × fan-out, excludes PQ framing). MAINNET mandate #3 floor-push: at finalising scale, attestations are 5-7× per record so they dominate steady-state egress. Sum with elara_gossip_bytes_out_total for total record-path budget when sizing the seal-traffic ceiling for MIN_ADAPTIVE_EPOCH_SECS reductions.\n\
         # TYPE elara_attestation_bytes_out_total counter\n\
         elara_attestation_bytes_out_total {att_bytes_out}\n\
         # HELP elara_attestation_bytes_in_total Cumulative attestation ingress bytes received on the PQ receive_attestation verb (body.len() per request, captured before deserialise so malformed bodies are still counted — they ate wire bandwidth). Mirror of elara_attestation_bytes_out_total: together they bound steady-state attestation-path budget on either side of the wire. Excludes the legacy axum POST /attestations route (Json<T> deserialise loses raw bytes — non-mainnet path post PQ-AUDIT closure).\n\
         # TYPE elara_attestation_bytes_in_total counter\n\
         elara_attestation_bytes_in_total {att_bytes_in}\n\
         # HELP elara_attestations_processed_total Cumulative attestations successfully validated and weighted by feed_attestation (success-side companion to elara_attestation_bytes_in_total which counts every body, even malformed). Operator signal: bytes_in > 0 AND processed > 0 = inbound pipeline functional; bytes_in rising while processed flat = signatures failing or records not yet local (deferred buffer growing). Independent from push_success_total (egress acknowledgement, the OTHER side's bytes_in).\n\
         # TYPE elara_attestations_processed_total counter\n\
         elara_attestations_processed_total {att_processed_total}\n\
         # HELP elara_attestation_receive_rejected_bad_signature_total Cumulative attestation pushes rejected because the Dilithium3 signature failed verify, the signature hex was malformed, or the (record_id, witness_hash) tuple was in the negative-sig cache. Counts both HTTP /attestations and PQ receive_attestation paths. Mainnet operator signal: rising linearly + zero processed_total = upstream is forging or stale-keying; cross-correlate with elara_peer_persistent_divergence_total to pick which neighbour to ban. Distinct from push_failed_total (THIS node sending to a peer) — this is what others sent to US.\n\
         # TYPE elara_attestation_receive_rejected_bad_signature_total counter\n\
         elara_attestation_receive_rejected_bad_signature_total {att_rej_bad_sig}\n\
         # HELP elara_attestation_pull_invalid_sig_total Cumulative attestations rejected by attestation_pull_loop because Dilithium3 sig-verify failed. PULL-path counterpart to elara_attestation_receive_rejected_bad_signature_total (PUSH path). Bootstrap-pathology signature: rises when local records have content_hash drift from the peer's view (forensically evicted + re-emitted under different content) — the witness's sig over (witness_id, record_id, content_hash) verifies with the peer's content but not ours. Sustained non-zero against a single peer = this node has stale records vs. that peer; trigger snapshot rebootstrap.\n\
         # TYPE elara_attestation_pull_invalid_sig_total counter\n\
         elara_attestation_pull_invalid_sig_total {att_pull_invalid_sig}\n\
         # HELP elara_attestation_pull_invalid_powas_total Cumulative attestations rejected by attestation_pull_loop because PoWaS proof-of-work failed. Distinct from sig-fail (which advances the watermark, permanent reject) — PoWaS-fail does NOT advance the watermark since the peer may resend a corrected proof. Sustained non-zero = a peer sending malformed PoWaS, likely an old binary or witness key/stake mismatch.\n\
         # TYPE elara_attestation_pull_invalid_powas_total counter\n\
         elara_attestation_pull_invalid_powas_total {att_pull_invalid_powas}\n\
         # HELP elara_attestation_receive_rejected_unknown_pk_total Cumulative attestation pushes rejected because the witness public key could not be resolved — either the inline pk_hex hash didn't match the witness_hash, the pk_hex was malformed, or no inline pk was supplied AND CF_IDENTITIES had no entry. AUDIT-1 closed the forgery hole here; this counter surfaces it. Persistent non-zero = a peer is pushing attestations for a witness whose identity record this node hasn't yet ingested (stale identity table or wrong genesis).\n\
         # TYPE elara_attestation_receive_rejected_unknown_pk_total counter\n\
         elara_attestation_receive_rejected_unknown_pk_total {att_rej_unknown_pk}\n\
         # HELP elara_attestation_receive_rejected_low_stake_total Cumulative attestation pushes hitting the witness-stake gate (MIN_WITNESS_STAKE = 100 beat, base units). The gate semantics changed from reject (HTTP 400 Wire) to defer (HTTP 200 status=deferred); this counter increments on every defer to preserve the original cold-boot signal. The actual sybil-attack signal is now elara_attestation_receive_low_stake_expired_total - entries that aged out at PENDING_HARD_DISCARD_TIMEOUT_SECS without the witness's stake row catching up. Bootstrap-pathology distinguisher: rises during catch-up, drains visibly via elara_attestation_receive_low_stake_drained_total within the same uptime window.\n\
         # TYPE elara_attestation_receive_rejected_low_stake_total counter\n\
         elara_attestation_receive_rejected_low_stake_total {att_rej_low_stake}\n\
         # HELP elara_attestation_receive_rejected_too_young_total Cumulative attestation pushes rejected because the witness identity is younger than min_age_secs (1h staked, 48h unstaked) on THIS node's clock. Per-node measure: trust.identity_age() resets on restart if the trust snapshot is stale. Persistent non-zero with one specific witness on one specific node = stale trust on that node, NOT a sybil attack — restart or rebuild trust to clear.\n\
         # TYPE elara_attestation_receive_rejected_too_young_total counter\n\
         elara_attestation_receive_rejected_too_young_total {att_rej_too_young}\n\
         # HELP elara_attestation_receive_rejected_bad_powas_total Cumulative attestation pushes rejected because the optional Proof-of-Witness-Stake proof failed to verify against (record_id, witness_pk, witness_stake). Only checked when both nonce + difficulty are present in the body. Non-zero = a peer is sending attestations with stale witness_stake (ledger drift) or forging the PoWaS proof. PoWaS difficulty is computed from CURRENT staked balance, so a witness whose stake just dropped will fail this until they re-mine.\n\
         # TYPE elara_attestation_receive_rejected_bad_powas_total counter\n\
         elara_attestation_receive_rejected_bad_powas_total {att_rej_bad_powas}\n\
         # HELP elara_attestation_receive_deferred_total Cumulative attestations buffered because the record_id was not in local storage at receive-time. NAT'd-node pushes into pull-blind VPS show up here — we cannot pull from them, so without this buffer the attestations would be permanently lost. Increment ≠ failure: deferred attestations re-verify when the record arrives. If this rises but elara_attestation_deferred_records stays low, retry is succeeding; if both rise together the record-arrival channel is broken (gossip stuck or zone-routing wrong).\n\
         # TYPE elara_attestation_receive_deferred_total counter\n\
         elara_attestation_receive_deferred_total {att_deferred_total}\n\
         # HELP elara_attestation_deferred_records Distinct record_ids currently sitting in the deferred-attestation buffer awaiting record arrival. Capped at 5000 (oldest record evicted at insert). Steady-state should be near zero on a synced node - sustained non-zero values indicate inbound attestations whose underlying records aren't reaching this node, which is the symptom of attestation storms when the receiver hasn't ingested the record yet.\n\
         # TYPE elara_attestation_deferred_records gauge\n\
         elara_attestation_deferred_records {att_deferred_records}\n\
         # HELP elara_attestation_deferred_buffered Total individual deferred attestations across all records. Ratio with elara_attestation_deferred_records gives mean attestations-per-deferred-record — high ratio (>3) suggests a small set of records is missing while many witnesses race to attest them; low ratio (≤1) suggests broad record-arrival lag. Bounded by 5000 records × the per-record FIFO cap (state.rs MAX_DEFERRED_ATTS_PER_RECORD = 128, enforced on BOTH the PQ and HTTP receive paths), so the absolute cap is 5000 × 128 — per-record shedding under flood shows up in elara_attestation_deferred_evicted_total.\n\
         # TYPE elara_attestation_deferred_buffered gauge\n\
         elara_attestation_deferred_buffered {att_deferred_buffered}\n\
         # HELP elara_attestation_deferred_evicted_total Cumulative FIFO evictions from a per-record_id deferred-attestation bucket that hit its hard cap (state.rs MAX_DEFERRED_ATTS_PER_RECORD = 128, enforced on BOTH the PQ and HTTP receive paths). Zero in steady state and honest bootstrap — a record's bucket never exceeds its witness committee. Sustained growth = a handshaked peer flooding one/few not-yet-local record_ids with distinct keypairs (the record-not-local defer path buffers before signature verification, gated only by sha3 of pk equalling witness_hash); the cap bounds memory and kills the O(N squared) dedup scan, this counts what was shed.\n\
         # TYPE elara_attestation_deferred_evicted_total counter\n\
         elara_attestation_deferred_evicted_total {att_deferred_evicted_total}\n\
         # HELP elara_propagation_limiter_tracked_identities Distinct creator identities currently tracked by the per-identity propagation rate limiter (sliding 1h windows, keyed by sha3 of the creator public key). Deliberately UNCAPPED: evict-oldest would let a cycled identity re-enter with an empty window (rate-limit bypass) and fail-closed-at-cap would lock out new identities (DoS) — growth is instead admission-bounded by the global 10k/min ingest window, so the worst case is about 600k entries under a sustained cap-saturating sybil flood, self-healing within 1h of the flood stopping (cleanup retains 1h). Relayed/synced records skip the limiter and do not grow this. Healthy steady state: roughly the number of distinct identities that submitted fresh records in the last hour.\n\
         # TYPE elara_propagation_limiter_tracked_identities gauge\n\
         elara_propagation_limiter_tracked_identities {propagation_tracked_identities}\n\
         # HELP elara_attestation_receive_low_stake_deferred_total Bootstrap-pathology counter. Cumulative attestations buffered because the record IS local but the witness's stake row hasn't synced yet. Bootstrap-lag signature: rises sharply during catch-up, drains to zero once stake records propagate (track alongside elara_attestation_receive_low_stake_drained_total). Sybil-attack signature: sustained non-zero in steady state with the same witness_hashes recurring after the buffer TTL - investigate elara_attestation_receive_low_stake_expired_total. Distinct from elara_attestation_receive_deferred_total (record-not-local).\n\
         # TYPE elara_attestation_receive_low_stake_deferred_total counter\n\
         elara_attestation_receive_low_stake_deferred_total {att_low_stake_deferred_total}\n\
         # HELP elara_attestation_receive_low_stake_drained_total Sweep-drain counter. Cumulative attestations successfully replayed by low_stake_replay_loop once the witness stake row caught up. Healthy bootstrap signature: rises in step with the fall in pending_ledger_depth on a behind-fleet node.\n\
         # TYPE elara_attestation_receive_low_stake_drained_total counter\n\
         elara_attestation_receive_low_stake_drained_total {att_low_stake_drained_total}\n\
         # HELP elara_attestation_receive_low_stake_expired_total Sweep-expire counter. Cumulative attestations dropped after exceeding PENDING_HARD_DISCARD_TIMEOUT_SECS (1200s) without the witness stake reaching MIN_WITNESS_STAKE. Sustained non-zero on a long-running node = genuinely-low-stake or sybil witnesses; this is the primary sybil-attack metric (elara_attestation_receive_rejected_low_stake_total also covers the bootstrap-lag false-positive case).\n\
         # TYPE elara_attestation_receive_low_stake_expired_total counter\n\
         elara_attestation_receive_low_stake_expired_total {att_low_stake_expired_total}\n\
         # HELP elara_attestation_low_stake_witnesses Distinct witness_hashes currently in the low-stake-deferred buffer. Capped at 5000.\n\
         # TYPE elara_attestation_low_stake_witnesses gauge\n\
         elara_attestation_low_stake_witnesses {att_low_stake_witnesses}\n\
         # HELP elara_attestation_low_stake_buffered Total individual attestations across all witnesses currently in the low-stake-deferred buffer.\n\
         # TYPE elara_attestation_low_stake_buffered gauge\n\
         elara_attestation_low_stake_buffered {att_low_stake_buffered}\n\
         # HELP elara_attestation_low_stake_oldest_age_seconds Age in seconds of the oldest deferred entry in the low-stake-deferred buffer (now - min(received_at)). 0 when the buffer is empty. Distinguishes healthy bootstrap churn (age stays <60s as the 60s sweep drains entries when stake catches up) from stuck/sybil patterns (age grows toward PENDING_HARD_DISCARD_TIMEOUT_SECS=1200 because the witness stake row never reaches the gate). Pair with elara_attestation_low_stake_buffered: rising buffered + rising age = stake gossip not catching up; rising buffered + flat age = healthy churn; flat buffered + age near 1200 = sybil.\n\
         # TYPE elara_attestation_low_stake_oldest_age_seconds gauge\n\
         elara_attestation_low_stake_oldest_age_seconds {att_low_stake_oldest_age_secs:.1}\n\
         # HELP elara_att_push_unattributed_total Cumulative low-stake-deferred bumps that targeted a peer hash not in the peer table (cold-restart race or chronic gap — peer PQ-handshakes but never gets into the table). Compare against elara_attestation_receive_low_stake_deferred_total to compute the attribution-gap ratio. Healthy: drops to a stable floor as the peer table warms (race side). Unhealthy: ratio stays >10% steady state → check seed_peers config / mDNS coverage / discovery loops. Without this counter, a PQ-handshake-only peer would silently invert the per-peer att_push_low_stake_deferred gauge.\n\
         # TYPE elara_att_push_unattributed_total counter\n\
         elara_att_push_unattributed_total {att_push_unattributed_total}\n\
         # HELP elara_auto_rewards_total Witness reward records created on settlement\n\
         # TYPE elara_auto_rewards_total counter\n\
         elara_auto_rewards_total {}\n\
         # HELP elara_auto_rewards_amount_total Total base units distributed as witness rewards (10^9 base units = 1 beat)\n\
         # TYPE elara_auto_rewards_amount_total counter\n\
         elara_auto_rewards_amount_total {}\n\
         # HELP elara_conservation_pool_micros Conservation pool balance in base units (10^9 base units = 1 beat; _micros suffix is a legacy metric name)\n\
         # TYPE elara_conservation_pool_micros gauge\n\
         elara_conservation_pool_micros {}\n\
         # HELP elara_peer_reconnect_attempts_total Seed peer reconnection attempts\n\
         # TYPE elara_peer_reconnect_attempts_total counter\n\
         elara_peer_reconnect_attempts_total {}\n\
         # HELP elara_peer_reconnect_success_total Successful seed peer reconnections\n\
         # TYPE elara_peer_reconnect_success_total counter\n\
         elara_peer_reconnect_success_total {}\n\
         # HELP elara_rate_limit_rejected_total Requests rejected by rate limiter (429)\n\
         # TYPE elara_rate_limit_rejected_total counter\n\
         elara_rate_limit_rejected_total {}\n\
         # HELP elara_peer_auto_banned_total Peers auto-banned for excessive failures\n\
         # TYPE elara_peer_auto_banned_total counter\n\
         elara_peer_auto_banned_total {}\n\
         # HELP elara_peers_banned Current number of banned peers\n\
         # TYPE elara_peers_banned gauge\n\
         elara_peers_banned {}\n\
         # HELP elara_peers_in_backoff Peers currently in exponential backoff\n\
         # TYPE elara_peers_in_backoff gauge\n\
         elara_peers_in_backoff {}\n\
         # HELP elara_trust_tracked_identities Identities tracked by trust engine\n\
         # TYPE elara_trust_tracked_identities gauge\n\
         elara_trust_tracked_identities {}\n\
         # HELP elara_circuit_breaker_level Circuit breaker level (0=normal, 1-3=elevated)\n\
         # TYPE elara_circuit_breaker_level gauge\n\
         elara_circuit_breaker_level {}\n\
         # HELP elara_token_volume_24h beat transfer volume in last 24 h window (base units)\n\
         # TYPE elara_token_volume_24h gauge\n\
         elara_token_volume_24h {}\n\
         # HELP elara_token_velocity_24h Fraction of circulating beat supply transferred in last 24 h (volume_24h / max(circulating, 1))\n\
         # TYPE elara_token_velocity_24h gauge\n\
         elara_token_velocity_24h {}\n\
         # HELP elara_velocity_tracked_identities Identities tracked by velocity limiter\n\
         # TYPE elara_velocity_tracked_identities gauge\n\
         elara_velocity_tracked_identities {}\n\
         # HELP elara_acquisition_tracked_identities Identities tracked by acquisition limiter\n\
         # TYPE elara_acquisition_tracked_identities gauge\n\
         elara_acquisition_tracked_identities {}\n\
         # HELP elara_vesting_active_schedules Active vesting schedules\n\
         # TYPE elara_vesting_active_schedules gauge\n\
         elara_vesting_active_schedules {}\n\
         # HELP elara_governance_active_proposals Active governance proposals\n\
         # TYPE elara_governance_active_proposals gauge\n\
         elara_governance_active_proposals {}\n\
         # HELP elara_gc_pruned_total Records pruned by garbage collection (aggregate; see per-reason counters below)\n\
         # TYPE elara_gc_pruned_total counter\n\
         elara_gc_pruned_total {}\n\
         # HELP elara_gc_pruned_expired_total Records pruned because their explicit `expires` metadata field passed AND they were finalized. Distinct from retention pruning. Sustained non-zero rate = TTL-tagged records aging out as designed.\n\
         # TYPE elara_gc_pruned_expired_total counter\n\
         elara_gc_pruned_expired_total {gc_pruned_expired}\n\
         # HELP elara_gc_pruned_retention_total Finalized records pruned because they aged past the retention window (Light=72h, FullZone=90d, Archive=never). This is the BASELINE counter - non-zero in steady state on Light/FullZone profiles. Drops to zero only on Archive nodes. Once epoch-based pruning lands, retention pruning can be tightened toward 'epoch_sealed + N epochs' instead of a fixed time window.\n\
         # TYPE elara_gc_pruned_retention_total counter\n\
         elara_gc_pruned_retention_total {gc_pruned_retention}\n\
         # HELP elara_gc_pruned_sunken_total Finalized records pruned EARLY (before retention) because the relevance tracker flagged them as low-utility. Sustained non-zero = relevance heuristic actively shedding low-relevance records. Zero = either no records have collapsed in relevance, or the sunken-pruning code path is disabled.\n\
         # TYPE elara_gc_pruned_sunken_total counter\n\
         elara_gc_pruned_sunken_total {gc_pruned_sunken}\n\
         # HELP elara_gc_pruned_stale_total UNFINALIZED records pruned after 2x retention window (abandoned — never witnessed). Mainnet operator alert: rate(elara_gc_pruned_stale_total[1h]) > 0.01 sustained = consensus health regression (records submitted but never finalized — witness/proposer infrastructure issue, NOT a GC issue).\n\
         # TYPE elara_gc_pruned_stale_total counter\n\
         elara_gc_pruned_stale_total {gc_pruned_stale}\n\
         # HELP elara_gc_compactions_total Count of post-GC compaction triggers fired (periodic every ~1h, burst at 5000+ deletes, OR disk-pressure every cycle). Compacts ALL CFs that delete_record touches - previously only `records`, `attestations`, `dag`, `idx_timestamp` were compacted while tombstones in `idx_creator`, `idx_hash`, `idx_record_hash`, `idx_tips`, `record_by_zone`, `metadata`, `epochs` accumulated for weeks of uptime on constrained nodes. Operator alert: rate(elara_gc_compactions_total[1h]) == 0 on a non-Archive node for >24h while elara_gc_pruned_total > 0 is a regression - fresh tombstones aren't being reclaimed.\n\
         # TYPE elara_gc_compactions_total counter\n\
         elara_gc_compactions_total {gc_compactions}\n\
         # HELP elara_startup_compactions_total Count of CFs that startup_compaction_if_needed scheduled for compaction at boot. Distinct from elara_gc_compactions_total (runtime GC loop) so operators can attribute disk reclamation between startup vs runtime paths. Closes a false-negative observability gap: a freshly-rebooted node could read gc_compactions=0 despite startup compaction having reclaimed disk, making a fix look broken when it was actually working. Bumps once per CF scheduled (heavy-bloat path OR L0-L2 file-count path OR ELARA_FORCE_COMPACT_CF env var). Steady state 0 once a node has been up >0 boot cycles; resets on every restart. Non-zero on first metric scrape after a deploy is expected and healthy.\n\
         # TYPE elara_startup_compactions_total counter\n\
         elara_startup_compactions_total {startup_compactions}\n\
         # HELP elara_gc_pruned_seals_total MAINNET gap #3: per-zone epoch seals pruned because a covering super-seal exists AND the seal's epoch is below the per-zone safety floor (latest_super_seal end_epoch − 2 × SUPER_SEAL_INTERVAL). Super-seals, zone_transitions, and global seals are integrity-critical and never counted here. Sustained non-zero on FullZone profile = super-seal consolidation closing the unbounded-growth gap on the seal stream. Always zero on Archive (∞ retention keeps seals on disk) and Light (no seals stored).\n\
         # TYPE elara_gc_pruned_seals_total counter\n\
         elara_gc_pruned_seals_total {gc_pruned_seals}\n\
         # HELP elara_gc_pruned_epoch_total Finalized non-seal records pruned because their per-zone epoch has already been super-sealed (timestamp below `latest_super_seal end_epoch - 2 x SUPER_SEAL_INTERVAL` boundary). The seal Merkle root preserves verifiability; the body bytes are no longer needed. Distinct from elara_gc_pruned_retention_total (time-based) - this fires as soon as a super-seal covers the record. Sustained non-zero on FullZone = epoch-based GC trimming the body stream against the seal root, the scaling path that lets the chain hold 1M zones x 720 seals/day. Always zero on Archive (auto-disabled) and on nodes with epoch_pruning_enabled=false.\n\
         # TYPE elara_gc_pruned_epoch_total counter\n\
         elara_gc_pruned_epoch_total {gc_pruned_epoch}\n\
         # HELP elara_gc_cycles_total Total successful GC passes since boot. Rate gives operational baseline (e.g. 1/300s = 12/hour at default interval). rate(elara_gc_cycles_total[10m]) == 0 AND staleness > 2*interval = GC genuinely halted.\n\
         # TYPE elara_gc_cycles_total counter\n\
         elara_gc_cycles_total {gc_cycles}\n\
         # HELP elara_gc_last_cycle_duration_ms Wall-clock duration of the most recent GC cycle in milliseconds (scan + delete loop). Mainnet budget: must be < gc_interval_secs * 250 (= 25% of interval, i.e. 75000ms for a 300s interval). Beyond that, the bounded-50K-batch needs raising or scan path needs further optimisation.\n\
         # TYPE elara_gc_last_cycle_duration_ms gauge\n\
         elara_gc_last_cycle_duration_ms {gc_last_cycle_duration_ms}\n\
         # HELP elara_gc_last_cycle_unix_ts Unix timestamp (integer seconds) of the most recent GC cycle completion. 0 at boot before the first cycle. Dashboards compute staleness = `time() - elara_gc_last_cycle_unix_ts`. Mainnet operator alert: staleness > 2 * gc_interval_secs = GC stalled.\n\
         # TYPE elara_gc_last_cycle_unix_ts gauge\n\
         elara_gc_last_cycle_unix_ts {gc_last_cycle_unix_ts}\n\
         # HELP elara_gc_scan_capped_total Cycles where gc_scan_and_delete hit MAX_GC_SCAN_PER_CYCLE=5000 and broke early. The next cycle fires after the 10 s DRAIN_INTERVAL instead of gc_interval_secs to chew through the backlog incrementally. Sustained non-zero rate = the box is bounded by GC throughput rather than schedule cadence; rate returning to zero = backlog drained. Distinct from elara_gc_last_cycle_duration_ms which measures wall time; this metric tells you whether the cycle was cap-limited or naturally short.\n\
         # TYPE elara_gc_scan_capped_total counter\n\
         elara_gc_scan_capped_total {gc_scan_capped}\n\
         # HELP elara_gc_oldest_record_age_seconds Age (in seconds) of the OLDEST record still on disk in CF_IDX_TIMESTAMP. Computed via O(1) seek-to-first - no scan even at 10M+ records. On a Light profile (72h retention), should hover near 72*3600=259200s in steady state. This gauge proxies the saving from epoch-based pruning - if epoch sealing happens every 120s and we keep N epochs of records, the floor would be ~N*120 instead of the 72h/90d retention window. Discrepancy between this gauge and effective_retention_secs reveals GC-batch backlog (50K cap means slow drain at 1M+ daily ingest).\n\
         # TYPE elara_gc_oldest_record_age_seconds gauge\n\
         elara_gc_oldest_record_age_seconds {gc_oldest_record_age_seconds:.1}\n\
         # HELP elara_fork_heals_total Partition heals via Merkle consistency\n\
         # TYPE elara_fork_heals_total counter\n\
         elara_fork_heals_total {}\n\
         # HELP elara_peer_persistent_divergence_total Cumulative count of distinct divergence streaks that crossed the PERSISTENT_DIVERGENCE_ALERT_THRESHOLD_SECS (600s) window. Fork-monitor signal. Seal-anchored: `in_sync` is now computed in `fork::check_single_peer` by comparing both peers' `latest_seal_anchor` (zone, epoch, anchor-signed seal_hash) at a matching `(zone, epoch)` - gossip-window differences NEVER register as divergence; only a real fork at a finalized anchor-signed epoch does. Cold-start nodes (no anchor yet), peers anchored on different zones, peers at different epochs, and peers without `latest_seal_anchor` in /status all resolve to `in_sync = true`. Previously the signal was `global_merkle_root` - a sparse-tree commitment over locally-ingested records - which saturated this counter cluster-wide as a constant false positive. Interpret with `peer_persistent_divergence_resolved_total` (delta = currently-firing alerts) and ledger invariants (ledger_supply / ledger_accounts / ledger_staked).\n\
         # TYPE elara_peer_persistent_divergence_total counter\n\
         elara_peer_persistent_divergence_total {}\n\
         # HELP elara_peer_persistent_divergence_resolved_total Cumulative count of previously-alerted divergence streaks that subsequently resolved (peer rejoined consensus → in_sync==true on the same peer_addr). Only resolutions of streaks that ALREADY crossed the alert threshold tick this counter; sub-threshold churn is filtered. Operator-facing delta: `persistent_divergence_total - persistent_divergence_resolved_total` = streaks currently firing. Mainnet healthy steady state under the seal-anchored signal: delta = 0 unless a peer is genuinely on a forked chain; gossip-lag artifacts no longer alert.\n\
         # TYPE elara_peer_persistent_divergence_resolved_total counter\n\
         elara_peer_persistent_divergence_resolved_total {}\n\
         # HELP elara_peer_divergence_streaks_active Peers currently observed diverged in the fork monitor\n\
         # TYPE elara_peer_divergence_streaks_active gauge\n\
         elara_peer_divergence_streaks_active {}\n\
         # HELP elara_readiness_level Emergency readiness level (0=green, 1=yellow, 2=orange, 3=red)\n\
         # TYPE elara_readiness_level gauge\n\
         elara_readiness_level {}\n\
         # HELP elara_auto_slashes_total Auto-slashes executed for protocol violations\n\
         # TYPE elara_auto_slashes_total counter\n\
         elara_auto_slashes_total {}\n\
         # HELP elara_key_rotations_total Total key rotations registered\n\
         # TYPE elara_key_rotations_total gauge\n\
         elara_key_rotations_total {}\n\
         # HELP elara_rotated_identities Identities with active key rotations\n\
         # TYPE elara_rotated_identities gauge\n\
         elara_rotated_identities {}\n\
         # HELP elara_witnesses_active Active witnesses within liveness threshold\n\
         # TYPE elara_witnesses_active gauge\n\
         elara_witnesses_active {}\n\
         # HELP elara_witnesses_tracked Total tracked witnesses\n\
         # TYPE elara_witnesses_tracked gauge\n\
         elara_witnesses_tracked {}\n\
         # HELP elara_sunset_algorithms Algorithms with sunset entries\n\
         # TYPE elara_sunset_algorithms gauge\n\
         elara_sunset_algorithms {}\n\
         # HELP elara_attestation_diversity_score Mean distinct-cluster count across attested records\n\
         # TYPE elara_attestation_diversity_score gauge\n\
         elara_attestation_diversity_score {:.4}\n\
         # HELP elara_seal_pending_anchor Seals finalized but still waiting for an anchor signature. Drains via prune_anchored_seals (anchor signature arrives) or promote_anchored (challenge window expires). Healthy churn is a stable mid-single-digit value. Samples cluster into three durable bands: a floor (roughly 0-12, drained / steady-state churn between settlement events), a climb band (roughly 27-35, mid-event accumulation), and a spike band (60+, settlement-excursion peak); band transitions are typically one tick. Operator implication: a single sample in the climb band is not by itself an anchor-signature backlog alarm -- it is the normal accumulation phase of a settlement cycle. Sustained values above 60 OUTSIDE a settlement excursion are the legitimate backlog signal (cross-reference the best-attestation-ratio gauge to confirm whether an excursion is in progress). A sustained backlog usually means anchor signing has stalled -- a partitioned or under-quorum committee, or a stuck aggregator.\n\
         # TYPE elara_seal_pending_anchor gauge\n\
         elara_seal_pending_anchor {}\n\
         # HELP elara_seal_pending_anchor_oldest_age_seconds Age in seconds of the oldest seal currently waiting for an anchor signature. 0 when window empty (Prometheus-friendly: absence of work is age-zero, not unknown). Stuck signal: grows unboundedly past CHALLENGE_WINDOW_SECS=86400 (24h) = promote_anchored loop isn't aging the seal out. Same pattern as elara_pending_ledger_oldest_age_seconds.\n\
         # TYPE elara_seal_pending_anchor_oldest_age_seconds gauge\n\
         elara_seal_pending_anchor_oldest_age_seconds {:.3}\n\
         # HELP elara_seal_pending_anchor_retroactive Pending-anchor seals finalized retroactively (peer-attested only, never locally registered). Drains via promote_anchored after 24h challenge window — bounded by 24h × per-zone seal rate. Sustained value at that ceiling under peer-driven catchup is normal. Subtract from elara_seal_pending_anchor to get locally-registered pending-anchor depth — sustained growth there is a real anchor-signature backlog, not retroactive accumulation. Pairs with elara_seal_latency_retroactive_skipped_total (rate of new retroactive entries; this gauge is the resident depth).\n\
         # TYPE elara_seal_pending_anchor_retroactive gauge\n\
         elara_seal_pending_anchor_retroactive {}\n\
         # HELP elara_seal_pending_anchor_oldest_age_seconds_local Oldest-age in seconds restricted to LOCALLY-registered pending-anchor seals (the `register_seal_records` path fired here, then the seal finalized but no anchor signature yet). 0 when no local entries pending. Alarm when this exceeds the anchor-signature SLA (~600s on mainnet) — the anchor service is not signing seals this witness produced. Distinct from elara_seal_pending_anchor_oldest_age_seconds_retroactive (retro entries drain at 24h via promote_anchored — different failure mode). Combined elara_seal_pending_anchor_oldest_age_seconds remains `max(local, retro)` for backward-compat dashboards.\n\
         # TYPE elara_seal_pending_anchor_oldest_age_seconds_local gauge\n\
         elara_seal_pending_anchor_oldest_age_seconds_local {:.3}\n\
         # HELP elara_seal_pending_anchor_oldest_age_seconds_retroactive Oldest-age in seconds restricted to RETROACTIVE pending-anchor seals (peer-attested only, never locally registered — definition shared with elara_seal_pending_anchor_retroactive). 0 when no retro entries pending. Alarm when this exceeds CHALLENGE_WINDOW_SECS=86400 (24h) plus operator-chosen slop — `promote_anchored` is not draining the retroactive window. Distinct from elara_seal_pending_anchor_oldest_age_seconds_local — that side alarms on anchor-sig backlog (~600s SLA), this side alarms on retro-drain stall (~24h SLA).\n\
         # TYPE elara_seal_pending_anchor_oldest_age_seconds_retroactive gauge\n\
         elara_seal_pending_anchor_oldest_age_seconds_retroactive {:.3}\n\
",
        dag_size, dag_tips, dag_edges,
        dag_zones_with_tips, dag_max_tips_in_zone,
        zone_idx_entries, zone_idx_bytes,
        ledger_supply, ledger_staked, ledger_accounts,
        connected_peers, total_peers, finalized_len,
        consensus_attestations, finalized_settled,
        ratio_summary.tracked, ratio_summary.ratiable,
        ratio_summary.best_ratio, ratio_summary.mean_ratio,
        ratio_summary.count_at_threshold,
        ratio_summary.classify_cohort(),
        state.bratio_band_ticks_dormant_total.load(std::sync::atomic::Ordering::Relaxed),
        state.bratio_band_ticks_locked_total.load(std::sync::atomic::Ordering::Relaxed),
        state.bratio_band_ticks_converged_total.load(std::sync::atomic::Ordering::Relaxed),
        state.bratio_band_ticks_active_total.load(std::sync::atomic::Ordering::Relaxed),
        state.bratio_band_ticks_hyper_active_total.load(std::sync::atomic::Ordering::Relaxed),
        state.uptime(),
        records_processed,
        gossip_push, gossip_relay, gossip_pull,
        gossip_pap_announcements, gossip_pap_at_cap,
        gossip_pap_cycles, gossip_pap_max,
        gossip_pap_autotune_raises, gossip_pap_autotune_lowers,
        gossip_push_skipped,
        gossip_seen_dedup, gossip_push_failed, gossip_retry, gossip_retry_success,
        epoch_count, dht_size, effective_hops, witness_profiles_count,
        aw_cycles, aw_records, aw_failures, att_dedup,
        auto_rewards, auto_rewards_amount, conservation_pool_val,
        reconnect_attempts, reconnect_success, rate_limit_rejected,
        auto_banned, banned_peers, peers_in_backoff, trust_tracked,
        breaker_level, cb_volume_24h, cb_velocity_24h, velocity_tracked, acquisition_tracked,
        vesting_active, governance_active, gc_pruned, fork_heals,
        persistent_divergence, persistent_divergence_resolved, divergence_streaks_active,
        readiness_level.level(),
        state.auto_slashes_total.load(std::sync::atomic::Ordering::Relaxed),
        state.key_registry.read_recover().total_rotations(),
        state.key_registry.read_recover().rotated_identities(),
        witnesses_active, witnesses_tracked,
        state.sunset.read_recover().count(),
        attestation_diversity,
        pending_anchors, pending_anchor_oldest_age_secs,
        pending_anchor_retroactive,
        pending_anchor_oldest_age_local_secs,
        pending_anchor_oldest_age_retro_secs,
    );

    // ITC metrics
    let itc_events = state.itc_events_total.load(std::sync::atomic::Ordering::Relaxed);
    let itc_joins = state.itc_joins_total.load(std::sync::atomic::Ordering::Relaxed);
    let itc_zones = { state.zone_clocks.lock_recover().zone_count() };
    let (conf_summary, seal_latency_buckets, seal_latency_count, seal_latency_sum,
         seal_prop_buckets, seal_prop_count, seal_prop_sum,
         seal_quorum_buckets, seal_quorum_count, seal_quorum_sum,
         seal_rank_buckets, seal_rank_count, seal_rank_sum,
         seal_add_total, seal_settled_true_total,
         seal_latency_retroactive_skipped) = {
        let c = state.consensus.lock_recover();
        let (buckets, count, sum) = c.seal_attestation_latency_snapshot();
        let (p_buckets, p_count, p_sum) = c.seal_propagation_latency_snapshot();
        let (q_buckets, q_count, q_sum) = c.seal_quorum_latency_snapshot();
        let (r_buckets, r_count, r_sum) = c.seal_attestor_rank_latency_snapshot();
        (c.confirmation_summary(), buckets, count, sum,
         p_buckets, p_count, p_sum,
         q_buckets, q_count, q_sum,
         r_buckets, r_count, r_sum,
         c.seal_attestation_add_total, c.seal_settled_true_total,
         c.seal_latency_retroactive_skipped_total)
    };
    let conf_unconfirmed = conf_summary.get(&super::consensus::ConfirmationLevel::Pending).copied().unwrap_or(0);
    let conf_attested = conf_summary.get(&super::consensus::ConfirmationLevel::Sealed).copied().unwrap_or(0);
    let conf_confirmed = conf_summary.get(&super::consensus::ConfirmationLevel::Finalized).copied().unwrap_or(0);
    let conf_anchored = conf_summary.get(&super::consensus::ConfirmationLevel::Anchored).copied().unwrap_or(0);

    let total_ever_settled = state.total_ever_settled.load(std::sync::atomic::Ordering::Relaxed);
    let total_ever_finalized = state.total_ever_finalized.load(std::sync::atomic::Ordering::Relaxed);
    let seal_member_finalized_durable = state.seal_member_finalized_durable_total.load(std::sync::atomic::Ordering::Relaxed);
    // #0ba — fin-burst-velocity (signed; can be negative on decel)
    let fin_burst_velocity = state.last_fin_burst_velocity.load(std::sync::atomic::Ordering::Relaxed);
    let zk_proofs = state.zk_proofs_verified_total.load(std::sync::atomic::Ordering::Relaxed);
    let global_rate_limited = state.global_rate_limited_total.load(std::sync::atomic::Ordering::Relaxed);
    // MAINNET gap #8 (floor-push): cumulative gossip byte counters.
    // Wire-body bytes only — HTTP/TLS framing excluded.
    let bytes_out = state.gossip_bytes_out_total.load(std::sync::atomic::Ordering::Relaxed);
    let bytes_in = state.gossip_bytes_in_total.load(std::sync::atomic::Ordering::Relaxed);
    // MAINNET mandate #3 (floor-push): kind-split egress sub-counters.
    // Sum across the four kinds is the originator+relay subset of bytes_out;
    // (bytes_out - sum_kinds) is the unclassified pull-responder remainder.
    let bytes_out_seal = state.gossip_bytes_out_seal_total.load(std::sync::atomic::Ordering::Relaxed);
    let bytes_out_ledger = state.gossip_bytes_out_ledger_total.load(std::sync::atomic::Ordering::Relaxed);
    let bytes_out_governance = state.gossip_bytes_out_governance_total.load(std::sync::atomic::Ordering::Relaxed);
    let bytes_out_other = state.gossip_bytes_out_other_total.load(std::sync::atomic::Ordering::Relaxed);
    let beat_transfers = state.beat_transfers_total.load(std::sync::atomic::Ordering::Relaxed);
    let beat_volume = state.beat_volume_micros_total.load(std::sync::atomic::Ordering::Relaxed);
    let legacy_vrf_total = crate::crypto::vrf::legacy_vrf_proof_total();
    // AUDIT-10 Milestone B: per-caller HTTPS fallback counters. Steady state on
    // the 6-node fleet should be 0 — runtime data plane is PQ-only post-DISC-7d.
    let https_fb_gossip = state.https_fallback_gossip_total.load(std::sync::atomic::Ordering::Relaxed);
    let https_fb_sync = state.https_fallback_sync_total.load(std::sync::atomic::Ordering::Relaxed);
    let https_fb_light = state.https_fallback_light_total.load(std::sync::atomic::Ordering::Relaxed);
    let https_fb_discovery = state.https_fallback_discovery_total.load(std::sync::atomic::Ordering::Relaxed);

    let body = format!("{body}\
         # HELP elara_total_ever_settled Lifetime records that reached settlement\n\
         # TYPE elara_total_ever_settled counter\n\
         elara_total_ever_settled {total_ever_settled}\n\
         # HELP elara_total_ever_finalized Lifetime records that reached finality (monotonic, survives pruning). Operators track the per-tick delta rather than the absolute value -- the per-tick delta is the local node's finality-throughput proxy. Cluster-wide settlement events show up as a symmetric pair of elevated-delta ticks: a first burst on the event-entry tick (best-attestation-ratio jumps from CONVERGED to ACTIVE/HYPER_ACTIVE) and a mirror burst on the event-exit tick when it reverts to CONVERGED. Operator implication: do not declare a settlement event over on the first deceleration below the entry burst -- the second elevated delta on the revert tick is the expected mass-conservation signature, and only the post-revert tick reads steady-state cadence again. A single isolated delta spike without the matched entry/exit bracket usually indicates a non-settlement burst (e.g. catch-up after a peer-sync stall) rather than a quorum-driven attestation cascade.\n\
         # TYPE elara_total_ever_finalized counter\n\
         elara_total_ever_finalized {total_ever_finalized}\n\
         # HELP elara_seal_member_finalized_durable_total Seal members whose durable FinalizedIndex insert happened via the Layer-2 routing lane (seal fast-track / registration settle-check / late-member resolve / promote_anchored / F3 maintenance sweep) rather than a Layer-1 settlement path. Before 2026-07-11 this class was silently dropped: members finalized in-memory only, evaporating from finality reporting at the first prune and never becoming GC-eligible. Steady growth alongside seal traffic is healthy; what operators watch is elara_total_ever_settled staying ~equal to elara_finalized_count (the historical 1.35-3x drift was this bug).\n\
         # TYPE elara_seal_member_finalized_durable_total counter\n\
         elara_seal_member_finalized_durable_total {seal_member_finalized_durable}\n\
         # HELP elara_fin_burst_velocity Second derivative of elara_total_ever_finalized per seal-loop tick: current_delta - prev_delta, where each delta is the per-tick finality count. Sampled at the deterministic per-epoch cadence (paired 1:1 with elara_seal_loop_ticks_total increments), NOT per Prometheus scrape -- scrape frequency is observer-dependent and would alias the second-derivative signal. Operator bands: positive velocity = finality bursts growing tick-on-tick (a chain entering acceleration); near zero = steady cadence; negative = bursts shrinking (normal deceleration or chain exit). Sustained large positive velocity (> +10 for 2+ consecutive ticks) marks a burst-chain acceleration regime. Cold-start guard: the first tick after boot seeds the sampler and emits 0; the second tick reports a synthetic value (current_delta - 0) that should be treated as a warmup transient -- true second-derivative semantics begin at the third tick after boot.\n\
         # TYPE elara_fin_burst_velocity gauge\n\
         elara_fin_burst_velocity {fin_burst_velocity}\n\
         # HELP elara_zk_proofs_verified_total ZK proofs verified\n\
         # TYPE elara_zk_proofs_verified_total counter\n\
         elara_zk_proofs_verified_total {zk_proofs}\n\
         # HELP elara_global_rate_limited_total Records rejected by global rate limit\n\
         # TYPE elara_global_rate_limited_total counter\n\
         elara_global_rate_limited_total {global_rate_limited}\n\
         # HELP elara_itc_events_total Local ITC events (record creation)\n\
         # TYPE elara_itc_events_total counter\n\
         elara_itc_events_total {itc_events}\n\
         # HELP elara_itc_joins_total Remote ITC joins (received stamps)\n\
         # TYPE elara_itc_joins_total counter\n\
         elara_itc_joins_total {itc_joins}\n\
         # HELP elara_itc_zones Active ITC zone count\n\
         # TYPE elara_itc_zones gauge\n\
         elara_itc_zones {itc_zones}\n\
         # HELP elara_gossip_bytes_out_total Cumulative gossip egress bytes (wire body, excludes HTTP/TLS framing)\n\
         # TYPE elara_gossip_bytes_out_total counter\n\
         elara_gossip_bytes_out_total {bytes_out}\n\
         # HELP elara_gossip_bytes_out_kind_total Per-kind breakdown of originator+relay egress (push_to_peers + relay_to_peers paths). Pull-responder bytes are excluded — operator can derive `pull_remainder = bytes_out_total - sum(kinds)`. Use `kind=\"seal\"` rate to size the per-epoch seal-traffic budget when deciding to lower MIN_ADAPTIVE_EPOCH_SECS.\n\
         # TYPE elara_gossip_bytes_out_kind_total counter\n\
         elara_gossip_bytes_out_kind_total{{kind=\"seal\"}} {bytes_out_seal}\n\
         elara_gossip_bytes_out_kind_total{{kind=\"ledger\"}} {bytes_out_ledger}\n\
         elara_gossip_bytes_out_kind_total{{kind=\"governance\"}} {bytes_out_governance}\n\
         elara_gossip_bytes_out_kind_total{{kind=\"other\"}} {bytes_out_other}\n\
         # HELP elara_gossip_bytes_in_total Cumulative wire bytes received from peers across BOTH transports: HTTP POST /records (post network-id + protocol-version gating) AND every PQ-transport request body (pre-gating, dispatched in pq_transport/router.rs). Despite the historical name, this counts ALL PQ traffic — control-plane verbs (status, find_node, ping), gossip pushes (submit_record), AND attestation pushes (receive_attestation). For attestation-only ingress see elara_attestation_bytes_in_total — that subset is included here. For mainnet floor-push budget sizing, total network ingress ≈ this counter; per-path breakdown requires subtracting attestation_bytes_in_total to isolate non-attestation PQ traffic.\n\
         # TYPE elara_gossip_bytes_in_total counter\n\
         elara_gossip_bytes_in_total {bytes_in}\n\
         # HELP elara_beat_transfers_total Total successful beat peer-to-peer transfers\n\
         # TYPE elara_beat_transfers_total counter\n\
         elara_beat_transfers_total {beat_transfers}\n\
         # HELP elara_beat_volume_micros_total Total base units moved by peer-to-peer transfers (10^9 base units = 1 beat)\n\
         # TYPE elara_beat_volume_micros_total counter\n\
         elara_beat_volume_micros_total {beat_volume}\n\
         # HELP elara_legacy_vrf_proof_total EC-VRF (alg=0x10) proofs verified - should be 0 on mainnet post-genesis wipe.\n\
         # TYPE elara_legacy_vrf_proof_total counter\n\
         elara_legacy_vrf_proof_total {legacy_vrf_total}\n\
         # HELP elara_https_fallback_total HTTPS fallback events from PQ-first call sites — target 0 on the 6-node fleet (AUDIT-10 Milestone B)\n\
         # TYPE elara_https_fallback_total counter\n\
         elara_https_fallback_total{{caller=\"gossip\"}} {https_fb_gossip}\n\
         elara_https_fallback_total{{caller=\"sync\"}} {https_fb_sync}\n\
         elara_https_fallback_total{{caller=\"light\"}} {https_fb_light}\n\
         elara_https_fallback_total{{caller=\"discovery\"}} {https_fb_discovery}\n\
         # HELP elara_confirmation_level Records by confirmation level\n\
         # TYPE elara_confirmation_level gauge\n\
         elara_confirmation_level{{level=\"unconfirmed\"}} {conf_unconfirmed}\n\
         elara_confirmation_level{{level=\"attested\"}} {conf_attested}\n\
         elara_confirmation_level{{level=\"confirmed\"}} {conf_confirmed}\n\
         elara_confirmation_level{{level=\"anchored\"}} {conf_anchored}\n\
    ");

    // Gap 8 / MAINNET mandate #3: seal-attestation latency histogram.
    // Observation = (seal first-settlement wall-clock) - (register_seal_records wall-clock).
    // One sample per seal — bounded at 11 buckets × u64 (zero memory growth).
    // Use this to judge whether lowering MIN_ADAPTIVE_EPOCH_SECS below 30s is
    // safe: scrape-rate delta of the `le="30"` bucket vs `_count` reveals how
    // often settlement beats the current floor.
    // Top buckets le=300, le=600: without them
    // testnet idle finality (~100-300s) all piled in +Inf and the histogram
    // was unreadable — operator could not separate "slow but converging" from
    // "stuck > 600s".
    let b = seal_latency_buckets;
    let body = format!("{body}\
         # HELP elara_seal_attestation_latency_seconds Seconds from epoch seal proposal to 2/3-stake attestation (finality latency)\n\
         # TYPE elara_seal_attestation_latency_seconds histogram\n\
         elara_seal_attestation_latency_seconds_bucket{{le=\"1\"}} {}\n\
         elara_seal_attestation_latency_seconds_bucket{{le=\"3\"}} {}\n\
         elara_seal_attestation_latency_seconds_bucket{{le=\"5\"}} {}\n\
         elara_seal_attestation_latency_seconds_bucket{{le=\"10\"}} {}\n\
         elara_seal_attestation_latency_seconds_bucket{{le=\"20\"}} {}\n\
         elara_seal_attestation_latency_seconds_bucket{{le=\"30\"}} {}\n\
         elara_seal_attestation_latency_seconds_bucket{{le=\"60\"}} {}\n\
         elara_seal_attestation_latency_seconds_bucket{{le=\"120\"}} {}\n\
         elara_seal_attestation_latency_seconds_bucket{{le=\"300\"}} {}\n\
         elara_seal_attestation_latency_seconds_bucket{{le=\"600\"}} {}\n\
         elara_seal_attestation_latency_seconds_bucket{{le=\"+Inf\"}} {}\n\
         elara_seal_attestation_latency_seconds_sum {seal_latency_sum}\n\
         elara_seal_attestation_latency_seconds_count {seal_latency_count}\n\
         # HELP elara_seal_attestation_add_total DISC-7c diagnostic: total entries into add_seal_attestation (if 0 while Layer-1 seal attestations exist, call-site wiring is broken)\n\
         # TYPE elara_seal_attestation_add_total counter\n\
         elara_seal_attestation_add_total {seal_add_total}\n\
         # HELP elara_seal_settled_true_total DISC-7c diagnostic: add_seal_attestation calls where is_seal_settled returned true (compare with _latency_seconds_count — divergence means histogram fire-site bypassed)\n\
         # TYPE elara_seal_settled_true_total counter\n\
         elara_seal_settled_true_total {seal_settled_true_total}\n\
         # HELP elara_seal_latency_retroactive_skipped_total seal-attestation+quorum latency observations skipped because the seal was retroactively registered (witness-clock stamp, not local). High rate vs _latency_seconds_count = heavy peer-driven catchup\n\
         # TYPE elara_seal_latency_retroactive_skipped_total counter\n\
         elara_seal_latency_retroactive_skipped_total {seal_latency_retroactive_skipped}\n\
    ", b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10]);

    // DISC-2 per-stage latency: splits end-to-end seal finality into two halves
    // so we can tell whether the binding constraint is witness-propagation delay
    // (attestations slow to arrive) or quorum-convergence delay (enough attestations
    // land but stake threshold lags). Propagation = first attestation - register.
    // Quorum = settle - first attestation. Sum ≈ elara_seal_attestation_latency.
    let p = seal_prop_buckets;
    let q = seal_quorum_buckets;
    let body = format!("{body}\
         # HELP elara_seal_propagation_latency_seconds Seconds from register_seal_records to first-witness-attestation (propagation component of finality)\n\
         # TYPE elara_seal_propagation_latency_seconds histogram\n\
         elara_seal_propagation_latency_seconds_bucket{{le=\"1\"}} {}\n\
         elara_seal_propagation_latency_seconds_bucket{{le=\"3\"}} {}\n\
         elara_seal_propagation_latency_seconds_bucket{{le=\"5\"}} {}\n\
         elara_seal_propagation_latency_seconds_bucket{{le=\"10\"}} {}\n\
         elara_seal_propagation_latency_seconds_bucket{{le=\"20\"}} {}\n\
         elara_seal_propagation_latency_seconds_bucket{{le=\"30\"}} {}\n\
         elara_seal_propagation_latency_seconds_bucket{{le=\"60\"}} {}\n\
         elara_seal_propagation_latency_seconds_bucket{{le=\"120\"}} {}\n\
         elara_seal_propagation_latency_seconds_bucket{{le=\"300\"}} {}\n\
         elara_seal_propagation_latency_seconds_bucket{{le=\"600\"}} {}\n\
         elara_seal_propagation_latency_seconds_bucket{{le=\"+Inf\"}} {}\n\
         elara_seal_propagation_latency_seconds_sum {seal_prop_sum}\n\
         elara_seal_propagation_latency_seconds_count {seal_prop_count}\n\
         # HELP elara_seal_quorum_latency_seconds Seconds from first attestation to 2/3-stake settlement (quorum-convergence component of finality)\n\
         # TYPE elara_seal_quorum_latency_seconds histogram\n\
         elara_seal_quorum_latency_seconds_bucket{{le=\"1\"}} {}\n\
         elara_seal_quorum_latency_seconds_bucket{{le=\"3\"}} {}\n\
         elara_seal_quorum_latency_seconds_bucket{{le=\"5\"}} {}\n\
         elara_seal_quorum_latency_seconds_bucket{{le=\"10\"}} {}\n\
         elara_seal_quorum_latency_seconds_bucket{{le=\"20\"}} {}\n\
         elara_seal_quorum_latency_seconds_bucket{{le=\"30\"}} {}\n\
         elara_seal_quorum_latency_seconds_bucket{{le=\"60\"}} {}\n\
         elara_seal_quorum_latency_seconds_bucket{{le=\"120\"}} {}\n\
         elara_seal_quorum_latency_seconds_bucket{{le=\"300\"}} {}\n\
         elara_seal_quorum_latency_seconds_bucket{{le=\"600\"}} {}\n\
         elara_seal_quorum_latency_seconds_bucket{{le=\"+Inf\"}} {}\n\
         elara_seal_quorum_latency_seconds_sum {seal_quorum_sum}\n\
         elara_seal_quorum_latency_seconds_count {seal_quorum_count}\n\
    ",
        p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9], p[10],
        q[0], q[1], q[2], q[3], q[4], q[5], q[6], q[7], q[8], q[9], q[10]);

    // DISC-2 analytic: per-attestor-rank arrival latency. 5 histograms labelled
    // by rank (1st, 2nd, 3rd, 4th, 5th+). Identifies whether the quorum tail is
    // dominated by one slow witness (rank-4 >> rank-1) or all witnesses drag
    // equally. Source data for the floor-push decision (line 110).
    const RANK_LABELS: [&str; 5] = ["1", "2", "3", "4", "5plus"];
    let mut rank_body = String::from(
        "# HELP elara_seal_attestor_rank_latency_seconds Seconds from register_seal_records to the Nth attestation arrival for a seal, bucketed by rank of arrival\n\
         # TYPE elara_seal_attestor_rank_latency_seconds histogram\n",
    );
    for r in 0..5 {
        let b = seal_rank_buckets[r];
        let label = RANK_LABELS[r];
        let count = seal_rank_count[r];
        let sum = seal_rank_sum[r];
        rank_body.push_str(&format!(
            "elara_seal_attestor_rank_latency_seconds_bucket{{rank=\"{label}\",le=\"1\"}} {}\n\
             elara_seal_attestor_rank_latency_seconds_bucket{{rank=\"{label}\",le=\"3\"}} {}\n\
             elara_seal_attestor_rank_latency_seconds_bucket{{rank=\"{label}\",le=\"5\"}} {}\n\
             elara_seal_attestor_rank_latency_seconds_bucket{{rank=\"{label}\",le=\"10\"}} {}\n\
             elara_seal_attestor_rank_latency_seconds_bucket{{rank=\"{label}\",le=\"20\"}} {}\n\
             elara_seal_attestor_rank_latency_seconds_bucket{{rank=\"{label}\",le=\"30\"}} {}\n\
             elara_seal_attestor_rank_latency_seconds_bucket{{rank=\"{label}\",le=\"60\"}} {}\n\
             elara_seal_attestor_rank_latency_seconds_bucket{{rank=\"{label}\",le=\"120\"}} {}\n\
             elara_seal_attestor_rank_latency_seconds_bucket{{rank=\"{label}\",le=\"300\"}} {}\n\
             elara_seal_attestor_rank_latency_seconds_bucket{{rank=\"{label}\",le=\"600\"}} {}\n\
             elara_seal_attestor_rank_latency_seconds_bucket{{rank=\"{label}\",le=\"+Inf\"}} {}\n\
             elara_seal_attestor_rank_latency_seconds_sum{{rank=\"{label}\"}} {sum}\n\
             elara_seal_attestor_rank_latency_seconds_count{{rank=\"{label}\"}} {count}\n",
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10],
        ));
    }
    let body = format!("{body}{rank_body}");

    // Agent-mandate observability (C4/C16). The flag histogram is incremented
    // at first-apply in mandate_node.rs but was write-only until now; surfacing
    // it is the slice-1 audit's open NICE item and the live-chain proof that the
    // verifier runs. LABEL-FREE BY DISCRIMINANT: the `flag` label is the 12
    // fixed MandateFlag variants only — never an agent/principal/mandate_id
    // label, which would reopen the deliberately-withheld agent->mandate
    // enumeration surface (slice-1 audit). Mandate CONSENSUS enforcement stays
    // DEFERRED (fusion-audited 2026-06-22 -> DEFER-TO-S3, see AGENT-DELEGATION.md);
    // this is observational only, classified P1 (stripped at phone-tier P0).
    let mut mandate_body = String::from(
        "# HELP elara_mandate_flag_total Agent-mandate act verdicts by flag (first-apply sample; the authoritative verdict is always the recomputed query flag). Observational, not consensus-weighted.\n\
         # TYPE elara_mandate_flag_total counter\n",
    );
    for flag in crate::mandate::MandateFlag::ALL {
        let n = crate::network::mandate_node::MANDATE_FLAG_TOTAL[flag as usize]
            .load(std::sync::atomic::Ordering::Relaxed);
        mandate_body.push_str(&format!(
            "elara_mandate_flag_total{{flag=\"{}\"}} {n}\n",
            flag.as_str()
        ));
    }
    mandate_body.push_str(&format!(
        "# HELP elara_mandate_records_total Mandate issuance records applied (first-apply gated)\n\
         # TYPE elara_mandate_records_total counter\n\
         elara_mandate_records_total {}\n\
         # HELP elara_mandate_revocations_total Mandate revocation records applied (first-apply gated)\n\
         # TYPE elara_mandate_revocations_total counter\n\
         elara_mandate_revocations_total {}\n\
         # HELP elara_mandate_acts_total Mandate-referencing act records indexed (first-apply gated)\n\
         # TYPE elara_mandate_acts_total counter\n\
         elara_mandate_acts_total {}\n\
         # HELP elara_mandate_malformed_ref_total Act records carrying a malformed mandate_ref (first-apply gated)\n\
         # TYPE elara_mandate_malformed_ref_total counter\n\
         elara_mandate_malformed_ref_total {}\n\
         # HELP elara_mandate_snapshot_rejected_total Snapshot-carried mandates/revocations rejected at bootstrap by the content-address/well-formed guard (apply_mandates + apply_revocations); non-zero implies a producer bug or a tampered-but-signed snapshot on the virgin-join path\n\
         # TYPE elara_mandate_snapshot_rejected_total counter\n\
         elara_mandate_snapshot_rejected_total {}\n",
        crate::network::mandate_node::MANDATE_RECORDS_TOTAL.load(std::sync::atomic::Ordering::Relaxed),
        crate::network::mandate_node::MANDATE_REVOCATIONS_TOTAL.load(std::sync::atomic::Ordering::Relaxed),
        crate::network::mandate_node::MANDATE_ACTS_TOTAL.load(std::sync::atomic::Ordering::Relaxed),
        crate::network::mandate_node::MANDATE_MALFORMED_REF_TOTAL.load(std::sync::atomic::Ordering::Relaxed),
        crate::mandate::MANDATE_SNAPSHOT_REJECTED_TOTAL.load(std::sync::atomic::Ordering::Relaxed),
    ));
    let body = format!("{body}{mandate_body}");

    // B5 act-permanence (verdict 2026-07-18): coverage-floor + exempt-mass gauges
    // and the by-reason deletion counter. reason=gc|zone_purge MUST stay 0 —
    // retention GC and zone purge PRESERVE the act index; a non-zero reading there
    // is the B5 regression alarm.
    let b5_body = format!(
        "# HELP elara_mandate_acts_coverage_floor_ms B5 act-index coverage floor (ms); 0 = full authoritative coverage. Absence of an act with claimed_ts below this floor is NOT authoritative on this node. Reads 0 when uninitialized too — pair with elara_mandate_acts_coverage_floor_initialized to disambiguate.\n\
         # TYPE elara_mandate_acts_coverage_floor_ms gauge\n\
         elara_mandate_acts_coverage_floor_ms {}\n\
         # HELP elara_mandate_acts_coverage_floor_initialized 1 iff the durable coverage-floor key is present + well-formed; 0 = UNINITIALIZED (boot init never succeeded → absence answers are fail-closed to non-authoritative). Sustained 0 on a live node is an alarm: the one-time init write keeps failing.\n\
         # TYPE elara_mandate_acts_coverage_floor_initialized gauge\n\
         elara_mandate_acts_coverage_floor_initialized {}\n\
         # HELP elara_mandate_exempt_live_bytes B5 GC-exempt mandate mass on disk (act index + registry); subtracted from disk_cap_bytes by the GC size governor so it never compresses record retention chasing bytes it cannot reclaim.\n\
         # TYPE elara_mandate_exempt_live_bytes gauge\n\
         elara_mandate_exempt_live_bytes {}\n\
         # HELP elara_mandate_act_entries_deleted_total B5 act-index entry deletions by reason. reason=gc and reason=zone_purge MUST stay 0 (GC and zone purge preserve the index); non-zero there is the B5 regression alarm. admin_evict and budget_evict are the legitimate removers.\n\
         # TYPE elara_mandate_act_entries_deleted_total counter\n\
         elara_mandate_act_entries_deleted_total{{reason=\"gc\"}} {}\n\
         elara_mandate_act_entries_deleted_total{{reason=\"zone_purge\"}} {}\n\
         elara_mandate_act_entries_deleted_total{{reason=\"admin_evict\"}} {}\n\
         elara_mandate_act_entries_deleted_total{{reason=\"budget_evict\"}} {}\n",
        state.rocks.acts_coverage_floor_ms().unwrap_or(0),
        state.rocks.acts_coverage_floor_state().map(|o| o.is_some() as u8).unwrap_or(0),
        state.rocks.exempt_live_bytes(),
        crate::network::mandate_node::MANDATE_ACT_ENTRIES_DELETED_GC.load(std::sync::atomic::Ordering::Relaxed),
        crate::network::mandate_node::MANDATE_ACT_ENTRIES_DELETED_ZONE_PURGE.load(std::sync::atomic::Ordering::Relaxed),
        crate::network::mandate_node::MANDATE_ACT_ENTRIES_DELETED_ADMIN_EVICT.load(std::sync::atomic::Ordering::Relaxed),
        crate::network::mandate_node::MANDATE_ACT_ENTRIES_DELETED_BUDGET_EVICT.load(std::sync::atomic::Ordering::Relaxed),
    );
    let body = format!("{body}{b5_body}");

    // Loop-supervision (verdict 2026-07-19): elara_loop_state / restarts_total /
    // last_tick_age_seconds per supervised lifecycle loop. Empty string until the
    // boot wiring registers loops; a sustained elara_loop_state=2 (Dead) means a
    // subsystem silently died while /health stayed green — page.
    let body = format!("{body}{}", state.loop_registry.render_prometheus());

    // Gap 4 TransitionSeal counters — mirrors /transitions/stats but in
    // Prometheus format for scrape-based dashboards / alerting.
    let tr_boot_replayed   = state.transitions_boot_replayed_total.load(std::sync::atomic::Ordering::Relaxed);
    let tr_mirror_failures = state.transitions_mirror_write_failures_total.load(std::sync::atomic::Ordering::Relaxed);
    let tr_orch_proposed   = state.transitions_proposed_by_orchestrator_total.load(std::sync::atomic::Ordering::Relaxed);
    let tr_orch_rejected   = state.transitions_orchestrator_insert_rejected_total.load(std::sync::atomic::Ordering::Relaxed);
    let tr_orch_skipped    = state.transitions_orchestrator_skipped_pending_total.load(std::sync::atomic::Ordering::Relaxed);
    let tr_orch_undersized = state.transitions_orchestrator_skipped_undersized_pool_total.load(std::sync::atomic::Ordering::Relaxed);
    let tr_finalized       = state.transitions_finalized_total.load(std::sync::atomic::Ordering::Relaxed);
    let tr_finalized_split = state.transitions_finalized_split_total.load(std::sync::atomic::Ordering::Relaxed);
    let tr_finalized_merge = state.transitions_finalized_merge_total.load(std::sync::atomic::Ordering::Relaxed);
    let tr_expired         = state.transitions_expired_total.load(std::sync::atomic::Ordering::Relaxed);
    let tr_gossip_pushed   = state.transition_gossip_pushed_total.load(std::sync::atomic::Ordering::Relaxed);
    let tr_gossip_dedup    = state.transition_gossip_dedup_total.load(std::sync::atomic::Ordering::Relaxed);
    let tr_sig_pushed      = state.transition_sig_gossip_pushed_total.load(std::sync::atomic::Ordering::Relaxed);
    let tr_sig_dedup       = state.transition_sig_gossip_dedup_total.load(std::sync::atomic::Ordering::Relaxed);
    let tr_cosigns         = state.transition_cosigns_total.load(std::sync::atomic::Ordering::Relaxed);
    let tr_pulled          = state.transition_pulled_total.load(std::sync::atomic::Ordering::Relaxed);
    let tr_pull_errors     = state.transition_pull_errors_total.load(std::sync::atomic::Ordering::Relaxed);
    let tr_stake_rejected  = state.transition_sig_stake_rejected_total.load(std::sync::atomic::Ordering::Relaxed);

    let body = format!("{body}\
         # HELP elara_transitions_boot_replayed_total Pending TransitionSeals replayed from CF_TRANSITIONS_PENDING at boot\n\
         # TYPE elara_transitions_boot_replayed_total counter\n\
         elara_transitions_boot_replayed_total {tr_boot_replayed}\n\
         # HELP elara_transitions_mirror_write_failures_total Failures mirroring pending TransitionSeal entries to RocksDB\n\
         # TYPE elara_transitions_mirror_write_failures_total counter\n\
         elara_transitions_mirror_write_failures_total {tr_mirror_failures}\n\
         # HELP elara_transitions_orchestrator_proposed_total TransitionSeals proposed+inserted by auto-scaler on this node\n\
         # TYPE elara_transitions_orchestrator_proposed_total counter\n\
         elara_transitions_orchestrator_proposed_total {tr_orch_proposed}\n\
         # HELP elara_transitions_orchestrator_insert_rejected_total Orchestrator proposals rejected at store insert (dup/gossip feedback)\n\
         # TYPE elara_transitions_orchestrator_insert_rejected_total counter\n\
         elara_transitions_orchestrator_insert_rejected_total {tr_orch_rejected}\n\
         # HELP elara_transitions_orchestrator_skipped_pending_total Orchestrator ticks where a fresh proposal was skipped because an active one for the same parents is already pending\n\
         # TYPE elara_transitions_orchestrator_skipped_pending_total counter\n\
         elara_transitions_orchestrator_skipped_pending_total {tr_orch_skipped}\n\
         # HELP elara_transitions_orchestrator_skipped_undersized_pool_total Orchestrator ticks skipped because the registered+staked anchor pool is below the kind's M-of-N threshold\n\
         # TYPE elara_transitions_orchestrator_skipped_undersized_pool_total counter\n\
         elara_transitions_orchestrator_skipped_undersized_pool_total {tr_orch_undersized}\n\
         # HELP elara_transitions_finalized_total TransitionSeals this node observed flipping to Finalized\n\
         # TYPE elara_transitions_finalized_total counter\n\
         elara_transitions_finalized_total {tr_finalized}\n\
         # HELP elara_transitions_finalized_split_total Split-kind subset of finalized_total\n\
         # TYPE elara_transitions_finalized_split_total counter\n\
         elara_transitions_finalized_split_total {tr_finalized_split}\n\
         # HELP elara_transitions_finalized_merge_total Merge-kind subset of finalized_total\n\
         # TYPE elara_transitions_finalized_merge_total counter\n\
         elara_transitions_finalized_merge_total {tr_finalized_merge}\n\
         # HELP elara_transitions_expired_total TransitionSeals that expired in AwaitingSigs without threshold\n\
         # TYPE elara_transitions_expired_total counter\n\
         elara_transitions_expired_total {tr_expired}\n\
         # HELP elara_transition_gossip_pushed_total TransitionSeal broadcasts originated from this node\n\
         # TYPE elara_transition_gossip_pushed_total counter\n\
         elara_transition_gossip_pushed_total {tr_gossip_pushed}\n\
         # HELP elara_transition_gossip_dedup_total TransitionSeal gossip attempts skipped by SeenSet\n\
         # TYPE elara_transition_gossip_dedup_total counter\n\
         elara_transition_gossip_dedup_total {tr_gossip_dedup}\n\
         # HELP elara_transition_sig_gossip_pushed_total Per-sig AnchorSig broadcasts forwarded by this node\n\
         # TYPE elara_transition_sig_gossip_pushed_total counter\n\
         elara_transition_sig_gossip_pushed_total {tr_sig_pushed}\n\
         # HELP elara_transition_sig_gossip_dedup_total AnchorSig broadcast attempts skipped by per-(seal,anchor) SeenSet\n\
         # TYPE elara_transition_sig_gossip_dedup_total counter\n\
         elara_transition_sig_gossip_dedup_total {tr_sig_dedup}\n\
         # HELP elara_transition_cosigns_total Gossiped TransitionSeals this anchor auto-cosigned\n\
         # TYPE elara_transition_cosigns_total counter\n\
         elara_transition_cosigns_total {tr_cosigns}\n\
         # HELP elara_transition_pulled_total TransitionSeals recovered via pull backstop (gossip-loss recovery)\n\
         # TYPE elara_transition_pulled_total counter\n\
         elara_transition_pulled_total {tr_pulled}\n\
         # HELP elara_transition_pull_errors_total Pull-backstop fetch/verify failures (malformed or unsigned seals)\n\
         # TYPE elara_transition_pull_errors_total counter\n\
         elara_transition_pull_errors_total {tr_pull_errors}\n\
         # HELP elara_transition_sig_stake_rejected_total AnchorSigs rejected by the Transitions-F1 staked-anchor gate (registered but unstaked signer)\n\
         # TYPE elara_transition_sig_stake_rejected_total counter\n\
         elara_transition_sig_stake_rejected_total {tr_stake_rejected}\n\
    ");

    // Pair the existing _total counters
    // (transitions_finalized_total, _expired_total) with current resident
    // depth gauges from `status_counts()`. Without these, operators can
    // see "proposals are landing and resolving" but cannot tell *where*
    // the queue is stuck — AwaitingSigs (M-of-N anchor cosign hung) vs
    // DisputeWindow (veto window not closing) are very different
    // failure modes. At mainnet 1M-zone scale, this depth ratio is the
    // primary orchestrator-health signal. Also surface the in-store
    // `evictions_total` + `proposals_accepted_total` (already exposed
    // via /transitions/stats JSON) as Prometheus counters so the eviction
    // *rate* (capacity pressure) is visible in dashboards. Bounded reads
    // under a brief read-lock — `status_counts()` is O(pending) and
    // `MAX_PENDING_TRANSITIONS` caps the store, so the scrape cost is
    // bounded regardless of zone count.
    let (
        tr_pending_awaiting_sigs,
        tr_pending_dispute_window,
        tr_pending_vetoed,
        tr_store_evictions_total,
        tr_proposals_accepted_total,
    ) = {
        use super::RwLockRecover;
        let store = state.transitions.read_recover();
        let counts = store.status_counts();
        (
            counts.awaiting_sigs as u64,
            counts.dispute_window as u64,
            counts.vetoed as u64,
            store.evictions_total(),
            store.proposals_accepted_total(),
        )
    };
    let body = format!("{body}\
         # HELP elara_transitions_pending_awaiting_sigs Pending TransitionSeals in AwaitingSigs (orchestrator-fired but M-of-N anchor cosign threshold not yet reached). Sustained non-zero alongside flat _orchestrator_proposed_total = anchor-cosign path stalled (anchor identities offline OR sig gossip not propagating). Spike + drain = healthy proposal-then-cosign churn. Pair with `elara_transitions_orchestrator_skipped_pending_total` (cooldown counter): fresh proposals on the same parents are skipped while AwaitingSigs is non-zero, so a long flat AwaitingSigs gauge is what *causes* `_orchestrator_proposed_total` to plateau.\n\
         # TYPE elara_transitions_pending_awaiting_sigs gauge\n\
         elara_transitions_pending_awaiting_sigs {tr_pending_awaiting_sigs}\n\
         # HELP elara_transitions_pending_dispute_window Pending TransitionSeals in DisputeWindow (M-of-N reached, awaiting effective_epoch + 0..2 ticks for veto path). Sustained non-zero past TRANSITION_DISPUTE_WINDOW_EPOCHS=3 = tick loop has stopped advancing OR `tick()` is not being called from the health module — distinct failure from AwaitingSigs (which means cosigns missing). Healthy churn: brief spikes that flip to Finalized within 3 epochs.\n\
         # TYPE elara_transitions_pending_dispute_window gauge\n\
         elara_transitions_pending_dispute_window {tr_pending_dispute_window}\n\
         # HELP elara_transitions_pending_vetoed Pending TransitionSeals halted by ≥MIN_VETOES_TO_HALT=2 distinct vetoes. These linger until `prune()` reaps them past retention. Sustained non-zero with growing trend = legitimate dissent OR veto-spam attack reaching the halt threshold; cross-check with `elara_transitions_orchestrator_skipped_undersized_pool_total` and `_insert_rejected_total` to triage.\n\
         # TYPE elara_transitions_pending_vetoed gauge\n\
         elara_transitions_pending_vetoed {tr_pending_vetoed}\n\
         # HELP elara_transitions_store_evictions_total Pending TransitionSeals dropped because MAX_PENDING_TRANSITIONS was hit at insert time (capacity-pressure counter — honest proposals may have lost their slot). Steady-state should be 0; non-zero = gossip flood OR pending-store cap is too low for current zone-split rate. Resets only on process restart.\n\
         # TYPE elara_transitions_store_evictions_total counter\n\
         elara_transitions_store_evictions_total {tr_store_evictions_total}\n\
         # HELP elara_transitions_proposals_accepted_total Fresh TransitionSeals accepted into the pending store since process start (re-inserts that only merge sigs do NOT count). Pair with `_store_evictions_total`: ratio `evictions/accepted` is the eviction rate. Resets on process restart.\n\
         # TYPE elara_transitions_proposals_accepted_total counter\n\
         elara_transitions_proposals_accepted_total {tr_proposals_accepted_total}\n\
    ");

    // timestamp_defense violator + verdict counters.
    // Currently `state.timestamp_defense` is wired into the validation hot
    // path (every record goes through `validate()`) but its three exposed
    // helpers — `violator_count()`, `total_validated()`, `total_rejected()`
    // — are not on /metrics anywhere. That makes clock-skew attacks
    // operationally invisible: a sudden flood of `FutureTooFar` /
    // `CausalViolation` / `BeforeEpoch` rejects only shows up in trace
    // logs, never in dashboards or alerts. At interplanetary scale,
    // ZoneTimeConsensus drift adjustment makes per-zone clock attacks the
    // most likely subverter of timestamp ordering. Three new metrics
    // (bounded reads under brief mutex via `LockRecover::lock_recover`):
    //   * `elara_timestamp_defense_violators_active` (gauge,
    //     identities with ≥1 violation in last VIOLATION_DECAY_SECS=600s
    //     window).
    //   * `elara_timestamp_defense_validated_total` (counter, lifetime
    //     records timestamp-checked).
    //   * `elara_timestamp_defense_rejected_total` (counter, subset that
    //     failed any of the 5 verdict gates: BeforeEpoch / FutureTooFar /
    //     CausalViolation / PastTooFar / RateLimited).
    let (td_violators, td_validated, td_rejected) = {
        use super::LockRecover;
        let td = state.timestamp_defense.lock_recover();
        (td.violator_count() as u64, td.total_validated(), td.total_rejected())
    };
    let body = format!("{body}\
         # HELP elara_timestamp_defense_violators_active Distinct identities with ≥1 timestamp violation in the last VIOLATION_DECAY_SECS=600s window. 0 = healthy steady state. Sustained non-zero = clock-skew attack OR upstream node NTP drift; values approaching MAX_VIOLATIONS_PER_IDENTITY=20 per identity = rate-limit gate engaging (subsequent records from that identity get RateLimited verdict). Pair with `_rejected_total/_validated_total` ratio for full picture: high violator count + flat reject rate = old violations decaying, attack ended; high violator count + climbing reject rate = active attack.\n\
         # TYPE elara_timestamp_defense_violators_active gauge\n\
         elara_timestamp_defense_violators_active {td_violators}\n\
         # HELP elara_timestamp_defense_validated_total Lifetime records that ran the timestamp_defense `validate()` gate (every record going through ingest hits this once). Resets on process restart. Pair with `_rejected_total` for a rejection-rate dashboard: ratio rejected/validated should be ~0 in healthy operation; spike = clock attack OR fleet-wide NTP drift.\n\
         # TYPE elara_timestamp_defense_validated_total counter\n\
         elara_timestamp_defense_validated_total {td_validated}\n\
         # HELP elara_timestamp_defense_rejected_total Lifetime records rejected by the timestamp_defense gate (any of: BeforeEpoch (claimed pre-MIN_VALID_TIMESTAMP), FutureTooFar (>MAX_FUTURE_SKEW_SECS=300s ahead of arrival even after zone drift correction), CausalViolation (claims to be before parent), PastTooFar (>MAX_PAST_SKEW_SECS=30d before parent), RateLimited (≥MAX_VIOLATIONS_PER_IDENTITY=20 in last 600s)). Resets on process restart.\n\
         # TYPE elara_timestamp_defense_rejected_total counter\n\
         elara_timestamp_defense_rejected_total {td_rejected}\n\
    ");

    // cross_zone_stats DAM-3D resident-state gauges +
    // boost-event counter. The existing _observed_total / _rejected_total
    // counters track the *rate* of cross-zone parents arriving at ingest,
    // but operators have no signal on (a) how many records currently track
    // cross-zone parents in the live consensus map vs (b) how often the
    // Protocol §7.5 shared-witness bridge actually fires. The bridge is
    // the load-bearing acceleration: when ALL cross-zone parents are
    // finalized in their own zones, this record's cluster requirement
    // relaxes from CONFIRMED_MIN_CLUSTERS to 1 — the canonical example
    // of cross-zone causal certification reducing local witness work.
    // Three new metrics, single O(cross_zone_parents) lock:
    //   * `elara_consensus_cross_zone_records_active` — distinct records
    //     currently tracking ≥1 cross-zone parent in the live map.
    //   * `elara_consensus_cross_zone_parent_refs_active` — total ref
    //     entries summed across those records (fanout indicator —
    //     refs/records is avg cross-zone parents per record).
    //   * `elara_consensus_cross_zone_boost_total` — lifetime count of
    //     finalize() calls that took the §7.5 cluster relaxation
    //     (`min_clusters = 1` instead of CONFIRMED_MIN_CLUSTERS).
    let (cz_records_active, cz_parent_refs_active, cz_boost_total) = {
        let c = state.consensus.lock_recover();
        let (records, refs, boost) = c.cross_zone_stats();
        (records as u64, refs as u64, boost)
    };
    let body = format!("{body}\
         # HELP elara_consensus_cross_zone_records_active Distinct records currently tracking ≥1 cross-zone parent in the live AWCConsensus `cross_zone_parents` map. Distinct from `elara_cross_zone_parent_observed_total` (rate counter, ticks once per ingest event) — this is the resident depth. Sustained climb alongside flat _observed_total = retention sweep is not pruning xzone_parents (memory-budget alarm). Steady-state ≈ active xzone fanout × retention window.\n\
         # TYPE elara_consensus_cross_zone_records_active gauge\n\
         elara_consensus_cross_zone_records_active {cz_records_active}\n\
         # HELP elara_consensus_cross_zone_parent_refs_active Total cross-zone parent refs summed across all records currently tracking xzone parents. Ratio refs/records = average cross-zone fanout per xzone record. Spike in fanout without record-count growth = a few highly-connected records observe many xzone parents (DAM ingestion frontier hitting a partition merge); even fanout growth across both = healthy xzone activity scaling.\n\
         # TYPE elara_consensus_cross_zone_parent_refs_active gauge\n\
         elara_consensus_cross_zone_parent_refs_active {cz_parent_refs_active}\n\
         # HELP elara_consensus_cross_zone_boost_total Lifetime count of finalize() calls where the shared-witness bridge fired — ALL cross-zone parents were already finalized so the cluster requirement relaxed from CONFIRMED_MIN_CLUSTERS to 1. The 2/3 stake threshold is NOT relaxed — only cluster diversity. This is the canonical cross-zone-acceleration counter: ratio _boost_total / _records_finalized_total measures how often cross-zone causal certification reduces local witness work. Resets on process restart.\n\
         # TYPE elara_consensus_cross_zone_boost_total counter\n\
         elara_consensus_cross_zone_boost_total {cz_boost_total}\n\
    ");

    // KeyRegistry::revocation_count resident-set gauge.
    // The fleet already exposes `elara_revocations_rejected_total` (records
    // rejected at ingest because the signing key was revoked), but operators
    // had no signal on the *resident set* of revoked keys — the upstream
    // half of the same problem. The pair gives full propagation visibility:
    //   * `_revocation_count` climbs when revocation records are posted +
    //     applied locally (KeyRegistry tombstones grow).
    //   * `_rejected_total` climbs when a peer is still SIGNING with a
    //     revoked key after revocation propagated — i.e. the revocation
    //     hasn't reached that peer yet, OR an attacker is replaying
    //     pre-revocation captures.
    // Healthy steady state: gauge stable, counter ~0. Gauge climbs while
    // counter spikes simultaneously = revocation propagation lag (alert).
    // Gauge stable while counter climbs = active compromised-key replay.
    let kr_revocation_count = state
        .key_registry
        .read_recover()
        .revocation_count() as u64;
    let body = format!("{body}\
         # HELP elara_key_revocation_count Distinct revoked Dilithium3 keys currently held in the local KeyRegistry tombstone set. HashSet semantics — re-applying the same revocation record is idempotent. Pair with `elara_revocations_rejected_total` for full picture: gauge climbing while counter climbs simultaneously = revocation propagation lag (peers still signing with the just-revoked key); gauge stable while counter climbs = active compromised-key replay attempt; both flat = healthy steady state. Bounded by the number of legitimate compromise/decommission/superseded events ever propagated to this node — never resets except on cold-start state rebuild.\n\
         # TYPE elara_key_revocation_count gauge\n\
         elara_key_revocation_count {kr_revocation_count}\n\
    ");

    // ReputationEngine residency gauge + cumulative
    // prune counter. The reputation engine (economics §11.2 delta-based
    // witness scoring) is wired into the consensus settlement path —
    // every undisputed-finalized record bulk-credits its attestors and
    // every dispute-resolution apply()s reputation deltas — but had zero
    // /metrics surface. Operators couldn't see (a) how many witnesses are
    // currently being scored locally, (b) whether the 30-day prune loop
    // (`elara_node.rs:3366`) is actually running.
    //
    // Two metrics, single brief lock on `state.reputation` for the gauge
    // (atomic counter is lock-free):
    //   * `elara_reputation_witnesses_tracked` (gauge) = `tracked_count()`,
    //     the size of the in-memory `entries` HashMap.
    //   * `elara_reputation_pruned_total` (counter) = lifetime sum of
    //     entries reaped by `prune_inactive()` calls (NodeState atomic,
    //     incremented at elara_node.rs:3366 each prune cycle).
    //
    // Operator dashboard rules (codified in HELP text):
    //   * gauge=0 fresh-boot drains as records arrive — first
    //     attestation that reaches this node adds the attestor to the
    //     reputation map. Steady state on a healthy fleet ≈ peer count.
    //   * gauge climbing past expected peer count without prune counter
    //     advancing = retention-window misconfigured OR prune loop dead.
    //   * counter advancing while gauge stays bounded = healthy churn —
    //     inactive witnesses retiring as fresh ones replace them.
    //   * gauge collapse + matching counter spike = mass-prune event —
    //     check if a peer disconnected the fleet for >retention period.
    let rep_tracked = {
        let rep = state.reputation.lock_recover();
        rep.tracked_count() as u64
    };
    let rep_pruned = state
        .reputation_pruned_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let body = format!("{body}\
         # HELP elara_reputation_witnesses_tracked Distinct witnesses currently scored by the local ReputationEngine (the economics spec delta-based scoring). Bounded by `_pruned_total` cleanup running in `memory_prune_loop` every prune-tick (default 30-day retention). Pair with `elara_reputation_pruned_total` for full residency picture: gauge stable + counter climbing = healthy churn (inactive witnesses retiring as fresh ones replace them); gauge climbing past expected peer count + counter flat = retention window misconfigured OR prune loop dead; gauge collapse + matching counter spike = mass-prune event (peer disconnected the fleet for >retention period). Fresh-boot value = 0; drains in as records arrive (first attestation adds attestor to the map).\n\
         # TYPE elara_reputation_witnesses_tracked gauge\n\
         elara_reputation_witnesses_tracked {rep_tracked}\n\
         # HELP elara_reputation_pruned_total Lifetime cumulative count of inactive-witness reputation entries reaped by `ReputationEngine::prune_inactive` (default 30-day inactivity cutoff). Pair with `elara_reputation_witnesses_tracked` gauge: counter advancing while gauge stays bounded = healthy churn; counter flat while gauge climbs unboundedly = prune loop has stopped firing (memory-budget alarm — investigate `memory_prune_loop` health). Resets on process restart.\n\
         # TYPE elara_reputation_pruned_total counter\n\
         elara_reputation_pruned_total {rep_pruned}\n\
    ");

    // EntityClusterer (economics §6.3 diminishing-
    // returns sybil defense) residency gauges. The clusterer is wired
    // into the reward path — `network/reward.rs:94,120,318,341` consult
    // `effective_reward()` / `reward_multiplier()` for every settled
    // record's witness rewards — but had ZERO /metrics surface. Operators
    // had no signal on (a) how many distinct entities the local node has
    // identified as sybil rings, (b) how many witnesses are clustered
    // into them. At mainnet scale, the entity-vs-witness ratio is the
    // operator-visible signal of sybil concentration:
    //   * `witnesses_clustered / entities_tracked` ≈ 1.0 = no sybil
    //     evidence (every witness is its own entity — healthy fleet).
    //   * ratio rising = clusters consolidating (a few witnesses link
    //     to many entities — possible sybil ring).
    //   * `entities_tracked == 0` while reward path is active = signal
    //     ingest gate is not feeding `record_attestation` (economics
    //     §6.3 diminishing-returns silently disabled).
    //
    // Two gauges, single brief lock on `state.entity_clusterer`:
    //   * `elara_entity_clusterer_entities_tracked` = `entity_count()`
    //     (size of `entity_sizes` HashMap — distinct cluster IDs).
    //   * `elara_entity_clusterer_witnesses_clustered` = `witness_count()`
    //     (size of `signals` HashMap — distinct witness identities).
    let (ec_entities, ec_witnesses) = {
        let ec = state.entity_clusterer.lock_recover();
        (ec.entity_count() as u64, ec.witness_count() as u64)
    };
    let body = format!("{body}\
         # HELP elara_entity_clusterer_entities_tracked Distinct entities currently tracked by EntityClusterer (the economics spec diminishing-returns sybil defense). Each entity is a union-find cluster of witnesses that co-attest enough to be treated as one identity for reward calculation. Pair with `elara_entity_clusterer_witnesses_clustered`: ratio witnesses/entities ≈ 1.0 = no sybil concentration (every witness is its own cluster, healthy); ratio rising = clusters consolidating (a few entity IDs gathering many witnesses — possible sybil ring); entities=0 while witnesses>0 = post-recompute() before clusters re-formed; both 0 while reward path is active = signal-ingest gate not feeding `record_attestation` (diminishing returns silently disabled).\n\
         # TYPE elara_entity_clusterer_entities_tracked gauge\n\
         elara_entity_clusterer_entities_tracked {ec_entities}\n\
         # HELP elara_entity_clusterer_witnesses_clustered Distinct witnesses with cluster signals in EntityClusterer. Bounded by record-attestation rate (each `record_attestation` call inserts/updates a signal entry). Operators should expect this to track the active witness set on a healthy fleet — a value lagging `elara_witnesses_active` by a wide margin signals the cluster signal-ingest gate is dropping events (e.g., reward path bypassed, `prune_stale` over-aggressive). Resets only on process restart since `prune_stale` is not currently wired into `memory_prune_loop`.\n\
         # TYPE elara_entity_clusterer_witnesses_clustered gauge\n\
         elara_entity_clusterer_witnesses_clustered {ec_witnesses}\n\
    ");

    // TransitionStore kind/veto observability gauges.
    // Closes the remaining unwired helpers in transition_store.rs after
    // `status_counts` was wired. Three new signals:
    //   * `kind_counts()` → split / merge distribution. Sustained
    //     Split >> Merge = fleet under traffic growth; sustained
    //     Merge >> Split = under-utilization. At mainnet 1M-zone scale
    //     this ratio is the operator-visible capacity-sizing signal.
    //   * `proposals_with_vetoes_count()` → DISTINCT from
    //     `status_counts.vetoed`: a proposal only flips to Vetoed once
    //     `MIN_VETOES_TO_HALT=2` vetoes accumulate, but a single veto
    //     is already operator-visible signal of contestation. The
    //     difference `with_vetoes − pending_vetoed` is the early-
    //     contestation pool — operators alert on it before it crosses
    //     the halt threshold.
    //   * `veto_reason_counts()` → BadBoundary / UnauthorizedProposer
    //     / CommitteeDiversity / StateRootMismatch / Other distribution.
    //     A wave of any single reason is a distinct fleet-wide
    //     diagnosis: StateRootMismatch wave = state-machine divergence;
    //     CommitteeDiversity wave = per-zone VRF rotation drift;
    //     UnauthorizedProposer wave = orchestrator split-brain or
    //     malicious injection.
    //
    // Single brief read-lock under `RwLockRecover::read_recover` — all
    // three helpers are O(pending) bounded by `MAX_PENDING_TRANSITIONS`,
    // no scrape cost concerns.
    let (
        tr_pending_split,
        tr_pending_merge,
        tr_with_vetoes,
        tr_veto_bad_boundary,
        tr_veto_unauth_proposer,
        tr_veto_committee_diversity,
        tr_veto_state_root_mismatch,
        tr_veto_other,
    ) = {
        use super::RwLockRecover;
        let store = state.transitions.read_recover();
        let kinds = store.kind_counts();
        let with_vetoes = store.proposals_with_vetoes_count();
        let reasons = store.veto_reason_counts();
        (
            kinds.split as u64,
            kinds.merge as u64,
            with_vetoes as u64,
            reasons.bad_boundary as u64,
            reasons.unauthorized_proposer as u64,
            reasons.committee_diversity as u64,
            reasons.state_root_mismatch as u64,
            reasons.other as u64,
        )
    };
    let body = format!("{body}\
         # HELP elara_transitions_pending_split Pending TransitionSeals with kind=Split (zone splitting under traffic load). Pair with `elara_transitions_pending_merge`: ratio split/merge gives orchestrator decision shape — sustained Split>>Merge = fleet under load growth; sustained Merge>>Split = under-utilization (zones consolidating). At mainnet 1M-zone scale, ratio drift signals capacity sizing miscalibration.\n\
         # TYPE elara_transitions_pending_split gauge\n\
         elara_transitions_pending_split {tr_pending_split}\n\
         # HELP elara_transitions_pending_merge Pending TransitionSeals with kind=Merge (zone consolidating). Pair with `elara_transitions_pending_split` for orchestrator decision shape.\n\
         # TYPE elara_transitions_pending_merge gauge\n\
         elara_transitions_pending_merge {tr_pending_merge}\n\
         # HELP elara_transitions_with_vetoes Pending TransitionSeals with ≥1 veto attached (any vetoer, any reason). DISTINCT from `elara_transitions_pending_vetoed` which requires MIN_VETOES_TO_HALT=2 vetoes to flip status. The difference `with_vetoes − pending_vetoed` is the early-contestation pool — proposals contested but not yet halted. Sustained non-zero with `_pending_vetoed=0` = vetoes arriving but not crossing the halt threshold (single-vetoer dissent or threshold misconfigured); sudden equalization with `_pending_vetoed` = waves of multi-vetoer agreement on bad proposals (real dispute fleet-wide).\n\
         # TYPE elara_transitions_with_vetoes gauge\n\
         elara_transitions_with_vetoes {tr_with_vetoes}\n\
         # HELP elara_transitions_vetoes_by_reason_bad_boundary Total veto records (summed across all pending proposals) with reason=BadBoundary — proposer's chosen zone-id boundary disagrees with verifier's local view. A wave signals account-hash range disagreement — typically the proposer is operating on a stale ZoneRegistry view. Compare to `_committee_diversity` and `_state_root_mismatch` to triage which subsystem is drifting.\n\
         # TYPE elara_transitions_vetoes_by_reason_bad_boundary gauge\n\
         elara_transitions_vetoes_by_reason_bad_boundary {tr_veto_bad_boundary}\n\
         # HELP elara_transitions_vetoes_by_reason_unauthorized_proposer Veto reason=UnauthorizedProposer — the proposer is not currently a recognized orchestrator. Sustained non-zero = orchestrator-rotation gossip lagged behind the proposer's perception (split-brain on who's the current orchestrator) OR a malicious node attempting to inject transitions. Pair with `elara_consensus_committee_rotations_total`: a stalled rotation counter alongside this gauge climbing is the canonical orchestrator split-brain signature.\n\
         # TYPE elara_transitions_vetoes_by_reason_unauthorized_proposer gauge\n\
         elara_transitions_vetoes_by_reason_unauthorized_proposer {tr_veto_unauth_proposer}\n\
         # HELP elara_transitions_vetoes_by_reason_committee_diversity Veto reason=CommitteeDiversity — per-zone witness committee composition fails the diversity rule (too few distinct entity clusters or stake-concentration above threshold). Pairs with `elara_entity_clusterer_*`: waves here while EntityClusterer witnesses/entities ratio climbs = sybil concentration penetrating the committee-selection path.\n\
         # TYPE elara_transitions_vetoes_by_reason_committee_diversity gauge\n\
         elara_transitions_vetoes_by_reason_committee_diversity {tr_veto_committee_diversity}\n\
         # HELP elara_transitions_vetoes_by_reason_state_root_mismatch Veto reason=StateRootMismatch — verifier's local state_root for the parent zone differs from proposer's claimed pre-transition root. The most operationally severe veto reason: signals state-machine divergence between proposer and verifiers — typically a missed-record in the proposer's local DAG (gossip miss) OR a genuine state-machine bug. A sustained wave is a fleet-wide alarm.\n\
         # TYPE elara_transitions_vetoes_by_reason_state_root_mismatch gauge\n\
         elara_transitions_vetoes_by_reason_state_root_mismatch {tr_veto_state_root_mismatch}\n\
         # HELP elara_transitions_vetoes_by_reason_other Veto reason=Other (free-form string; per-proposal granular reason matters for triage but at the aggregate level only the count matters). Climbing while the four named reasons stay flat = a new dispute mode operators haven't seen before (warrants log inspection on the specific proposal).\n\
         # TYPE elara_transitions_vetoes_by_reason_other gauge\n\
         elara_transitions_vetoes_by_reason_other {tr_veto_other}\n\
    ");

    // SlashingMonitor BFT-equivocation observability.
    // SlashingMonitor (economics §10 BFT auto-slash) is wired into the
    // epoch-seal validation path — every epoch seal arriving at this node
    // calls `record_seal()` which detects when an anchor produces two
    // different seals for the same (zone, epoch_number) and triggers
    // `mark_slashed()` — but had ZERO /metrics surface. Operators saw
    // `elara_conflict_proof_pushed_total` (proofs THIS node generated) and
    // `elara_revoke_all_involuntary_total` (gateway slashes via fisherman
    // path), but no signal on (a) whether the auto-slash path has fired
    // locally, (b) how many seal entries the local monitor is tracking, or
    // (c) the size of the dedup set preventing repeat slashes for the same
    // equivocation pair.
    //
    // At mainnet 1M-zone × 7-witness × 720-epoch/day scale, a non-trivial
    // fraction of zones will have an anchor produce two seals for the same
    // epoch in the wild (NTP drift, fork resolution churn, malicious
    // attempt) — the equivocation-detection working set IS the operator-
    // visible "BFT safety footprint" gauge.
    //
    // Three new metrics, single brief lock under `LockRecover::lock_recover`:
    //   * `elara_slashing_executed_total` (counter — `slash_count`)
    //     lifetime BFT auto-slashes by THIS node. Resets on process
    //     restart. Steady-state should be 0; non-zero = an anchor is
    //     equivocating in the local view.
    //   * `elara_slashing_tracked_seals` (gauge — `tracked_seals()`)
    //     resident equivocation-detection entries (one per
    //     (creator, zone, epoch) tuple seen). Bounded by per-zone prune
    //     cycle via `prune_before_epoch`; sustained climbing past
    //     pruned-window expectation = retention loop is stalled
    //     (memory-budget alarm).
    //   * `elara_slashing_dedup_pairs` (gauge — `slashed_pair_count()`)
    //     size of the already-slashed (creator, seal_a, seal_b) dedup
    //     set. Pair with `_executed_total`: dedup_pairs grows ≥1 per
    //     fresh equivocation pair, ≤ executed_total (each slash adds
    //     1 to both). Sustained dedup_pairs > executed_total =
    //     impossible (would mean the dedup set was populated without
    //     a slash — would indicate a bug). dedup_pairs < executed_total
    //     is also impossible since `mark_slashed` increments both.
    //     The two should agree.
    let (slash_executed_total, slash_tracked_seals, slash_dedup_pairs) = {
        let s = state.slashing.lock_recover();
        (s.slash_count, s.tracked_seals() as u64, s.slashed_pair_count() as u64)
    };
    let body = format!("{body}\
         # HELP elara_slashing_executed_total Lifetime count of BFT auto-slashes executed by this node (the economics spec — anchor equivocation detected via `record_seal` returning a different content_hash for the same (creator, zone, epoch_number)). Steady-state should be 0; non-zero = an anchor is equivocating in the local view (NTP drift, malicious attempt, or fork-resolution churn). Resets on process restart. Pair with `elara_slashing_dedup_pairs` (always equal in steady state — `mark_slashed` increments both); divergence indicates a bug.\n\
         # TYPE elara_slashing_executed_total counter\n\
         elara_slashing_executed_total {slash_executed_total}\n\
         # HELP elara_slashing_tracked_seals Resident equivocation-detection entries in SlashingMonitor (one per (creator, zone, epoch_number) tuple seen via `record_seal`). Bounded by per-zone prune cycle via `prune_before_epoch` after each tick. Sustained growth past pruned-window expectation = retention loop is stalled (memory-budget alarm — investigate epoch tick health). At mainnet 1M-zone × 720-epoch/day scale this gauge IS the operator-visible BFT safety-footprint signal.\n\
         # TYPE elara_slashing_tracked_seals gauge\n\
         elara_slashing_tracked_seals {slash_tracked_seals}\n\
         # HELP elara_slashing_dedup_pairs Size of the already-slashed (creator, seal_a, seal_b) dedup set in SlashingMonitor. Pair with `elara_slashing_executed_total`: each `mark_slashed` increments both, so the two gauges should agree in steady state. dedup_pairs > executed_total OR dedup_pairs < executed_total = bug in slash bookkeeping. Resets on process restart along with `_executed_total`.\n\
         # TYPE elara_slashing_dedup_pairs gauge\n\
         elara_slashing_dedup_pairs {slash_dedup_pairs}\n\
    ");

    // Resident-set gauges for three admin/eligibility
    // pools that today only emit rejection-event counters. Each pair
    // (gauge resident_size + counter rejections_total) gives operators the
    // full "list size vs rejection rate" picture, mirroring the
    // KeyRegistry::revocation_count + revocations_rejected pattern.
    //
    //   * `elara_vrf_registry_identities` = `vrf_registry.count()`
    //     Identities that have published a VRF registration record and
    //     are therefore eligible for per-zone witness committee selection
    //     (mainnet Gap 5). At 1M zones × 7-witness target, the eligible
    //     pool must climb past `MAINNET_COMMITTEE_SIZE * zones_registered`
    //     for stake-diversity selection to find committees. A flat or
    //     declining pool while `_consensus_committee_zones_below_target`
    //     climbs is the canonical "VRF coverage shortfall"
    //     dashboard signal.
    //   * `elara_banned_identities_count` = `banned_identities.len()`
    //     Pairs with existing `_banned_rejections_total` (rate of records
    //     rejected because their creator is on the ban list). The two
    //     are independent axes: list size grows when admin posts a ban
    //     record (or governance applies one); rejection counter grows
    //     when a peer is still publishing AS the banned identity. List
    //     stable + counter climbing = a banned actor still actively
    //     publishing (either ban hasn't propagated to the source OR
    //     attacker rotating creator IDs — admin actionable).
    //   * `elara_content_blocklist_count` = `content_blocklist.len()`
    //     Pairs with existing `_content_rejections_total`. List size
    //     starts at `default_blocklist().len()` and grows as admin
    //     adds entries; mismatch across the cluster (operator should
    //     graph variance across nodes) signals propagation drift.
    //
    // Three independent brief read-locks under `RwLockRecover::read_recover`.
    // All three are O(1) `len()` reads — no scrape cost regardless of size.
    let vrf_registry_count = {
        use super::RwLockRecover;
        let r = state.vrf_registry.read_recover();
        r.count() as u64
    };
    // Read the live (configurable) Phase 6d threshold instead of
    // the hardcoded DEFAULT_COMMITTEE_SIZE. On mainnet this resolves to 7;
    // on testnets (cluster < 7) operators lower it via toml or
    // ELARA_PHASE6D_MIN_COMMITTEE_SIZE so the quorum signal can actually
    // turn on at small cluster sizes.
    let phase6d_min_k = state.config.phase6d_min_committee_size as u64;
    let vrf_registry_quorum_global: u64 =
        if vrf_registry_count >= phase6d_min_k {
            1
        } else {
            0
        };
    let banned_count = {
        use super::RwLockRecover;
        let r = state.banned_identities.read_recover();
        r.len() as u64
    };
    let blocklist_count = {
        use super::RwLockRecover;
        let r = state.content_blocklist.read_recover();
        r.len() as u64
    };
    let body = format!("{body}\
         # HELP elara_vrf_registry_identities Distinct identities currently registered in the local VRF registry for per-zone witness committees. Each entry is one identity that published a VRF registration record and is therefore eligible for stake-weighted per-zone witness selection. Read this as the GLOBAL eligibility pool size -- necessary but not sufficient for per-zone coverage, and independent of whether per-zone VRF enforcement is actually switched on (the enforce_per_zone_vrf config flag defaults off and is flipped manually by an operator, not automatically by this gauge crossing any threshold). For the live per-zone coverage signal use the trio: elara_vrf_registry_quorum_global (this pool >= elara_phase6d_min_committee_size), elara_committee_skipped_below_k_total (attestations bypassing the gate because a zone is short of committee members), and elara_phase6d_ready (single-bit flip-readiness). A flat or declining pool while committee-skips climb indicates bootstrap-phase instability (re-encourage staking and registration); flat skips alongside a steady or rising pool is healthy steady state. This gauge alone says nothing about whether the gate is enforcing -- read elara_enforce_per_zone_vrf for that.\n\
         # TYPE elara_vrf_registry_identities gauge\n\
         elara_vrf_registry_identities {vrf_registry_count}\n\
         # HELP elara_vrf_registry_quorum_global 0/1 boolean - does the local VrfRegistry hold at least `phase6d_min_committee_size` distinct identities (default 7, configurable; read live via `elara_phase6d_min_committee_size`)? Necessary-but-not-sufficient precondition for the per-zone VRF gate to do real work; without it, every gate call lands in the bootstrap fallback (`elara_committee_skipped_below_k_total` climbs every attestation). The cheap global-pool sufficiency signal - pair with per-zone view (a zone may have <K eligible candidates even when the global pool is >=K). Mainnet operator workflow: gauge must be 1 cluster-wide before flipping `enforce_per_zone_vrf=true` for the first time. Variance across nodes signals VRF-registration record propagation lag.\n\
         # TYPE elara_vrf_registry_quorum_global gauge\n\
         elara_vrf_registry_quorum_global {vrf_registry_quorum_global}\n\
         # HELP elara_banned_identities_count Distinct identities currently on the local ban list. PAIR with `elara_banned_rejections_total` (rate counter of records rejected at ingest because creator is banned). Independent axes: list size grows on admin/governance ban actions; rejection counter grows when banned actors keep publishing. Stable list + climbing rejections = banned actor still publishing AS that identity (ban hasn't propagated to source OR attacker rotating creator IDs — admin actionable). Cluster-wide gauge variance signals ban-propagation drift across nodes.\n\
         # TYPE elara_banned_identities_count gauge\n\
         elara_banned_identities_count {banned_count}\n\
         # HELP elara_content_blocklist_count Distinct entries in the local content_blocklist. PAIR with `elara_content_rejections_total` (rate of records rejected because text-field content matched). Starts at `default_blocklist().len()` on boot; admin ops add or remove entries. Cluster-wide gauge variance is itself a signal: a node missing recent blocklist updates will silently let through content other nodes reject (graph variance to detect propagation lag).\n\
         # TYPE elara_content_blocklist_count gauge\n\
         elara_content_blocklist_count {blocklist_count}\n\
    ");

    // TransitionStore WHEN-axis epoch gauges.
    // Closes the last unwired helpers in `transition_store.rs` after the
    // status_counts (WHAT-axis) and kind/veto distribution (WHAT-
    // axis) gauges. Both are already exposed via `/transitions/stats` JSON (which
    // operators must know exists), but had no /metrics surface. The pair
    // gives operators the WHEN axis — for any pending pile of proposals
    // operators see in the status/kind/veto gauges, these answer "how stale is
    // it" and "when does the soonest deadline land":
    //
    //   * `nearest_effective_epoch()` — soonest `effective_epoch` across
    //     pending entries still in `AwaitingSigs` or `DisputeWindow`.
    //     Terminal statuses (Vetoed/Finalized/Expired) excluded — their
    //     windows no longer represent work operators need to watch.
    //     Operator dashboard rule: `nearest_effective_epoch − current_epoch`
    //     ≤ 1 = window about to close (verifier sweep imminent); diverging
    //     suddenly into the past (negative) means the dispute-tick loop
    //     stopped advancing while proposals piled up — same alarm as
    //     `_pending_dispute_window > TRANSITION_DISPUTE_WINDOW_EPOCHS=3`
    //     but pinpoints the EXACT epoch the loop got stuck.
    //
    //   * `oldest_active_proposed_at_epoch()` — oldest `proposed_at_epoch`
    //     across active-status entries. Operators diff against current
    //     epoch to compute "longest-waiting in-flight proposal" age in
    //     epochs; sustained age past `TRANSITION_DISPUTE_WINDOW_EPOCHS`
    //     = orchestrator stall (anchor cosign hung OR tick loop dead).
    //
    // Encoding: both helpers return `Option<u64>`. Prometheus has no None
    // semantic, so we emit 0 for None — unambiguous because in production
    // proposed_at_epoch is always > 0 (genesis is epoch 0 and no transitions
    // are proposed at genesis). Operators graph the gauge directly and a
    // 0 reading reads as "no active proposals," not "epoch 0 proposal."
    //
    // Single brief read-lock under `RwLockRecover::read_recover` — both
    // helpers are O(N) in store size bounded by `MAX_PENDING_TRANSITIONS`,
    // no scrape cost concerns. Independent of the kind/veto lock above by
    // design — keeps that review scope small and allows these gauges to be
    // reverted independently if needed.
    let (tr_nearest_effective_epoch, tr_oldest_active_proposed_at_epoch) = {
        use super::RwLockRecover;
        let store = state.transitions.read_recover();
        (
            store.nearest_effective_epoch().unwrap_or(0),
            store.oldest_active_proposed_at_epoch().unwrap_or(0),
        )
    };
    let body = format!("{body}\
         # HELP elara_transitions_nearest_effective_epoch Soonest `effective_epoch` across pending TransitionSeals still in active lifecycle (AwaitingSigs or DisputeWindow). Terminal statuses (Vetoed/Finalized/Expired) excluded - their windows no longer represent work. Emits 0 when no active proposals (unambiguous: production never has proposals at epoch 0 since genesis is epoch 0 and no transitions are proposed there). Pairs with transition status_counts and kind/veto distributions to give the WHEN axis: `nearest_effective_epoch - current_epoch <= 1` = next dispute window about to close (verifier sweep imminent); diverging into the past = the dispute-tick loop stopped advancing (the same condition as the _pending_dispute_window > 3 alarm, but it pinpoints the exact stuck epoch).\n\
         # TYPE elara_transitions_nearest_effective_epoch gauge\n\
         elara_transitions_nearest_effective_epoch {tr_nearest_effective_epoch}\n\
         # HELP elara_transitions_oldest_active_proposed_at_epoch Oldest `proposed_at_epoch` across pending TransitionSeals still in active lifecycle (AwaitingSigs or DisputeWindow). Emits 0 when no active proposals. Operators diff against the current epoch to compute longest-waiting in-flight proposal age in epochs: sustained age past `TRANSITION_DISPUTE_WINDOW_EPOCHS=3` = orchestrator stall (anchor cosign hung OR tick loop dead). Pairs with `_nearest_effective_epoch` (deadline side) — together they bound the active proposal window in epoch space.\n\
         # TYPE elara_transitions_oldest_active_proposed_at_epoch gauge\n\
         elara_transitions_oldest_active_proposed_at_epoch {tr_oldest_active_proposed_at_epoch}\n\
    ");

    // Finalized-record LRU hot-tier gauges.
    // The existing `elara_finalized_count` gauge reports the TOTAL finalized
    // record count (hot RAM cache + cold RocksDB tier) — operationally
    // meaningful but it conceals the LRU pressure on the hot tier. The
    // `is_finalized()` predicate hot-path (called by ingest validation,
    // DAG cascade-eviction, attestation processing) does an O(1) hot-tier
    // lookup first; on miss it falls through to a RocksDB CF read. When
    // hot_size approaches `capacity` the LRU thrash kicks in: every miss
    // is a syscall + disk seek + page-cache pressure. The two gauges
    // together let operators detect (a) hot-tier saturation BEFORE the
    // disk fall-through becomes a cluster-wide tail-latency alarm, and
    // (b) sized-too-small misconfigurations on phone-tier nodes (mainnet
    // Gap goal: phone-tier hardware floor).
    //
    // Two new gauges, brief read-lock under tokio RwLock (same pattern as
    // existing `finalized.len()` reader). `hot_size()` is `BTreeSet::len`,
    // O(1); `capacity()` returns the configured constant, O(1). No scrape
    // cost concerns.
    //
    // Operator dashboard rules:
    //   * `_hot_size / _hot_capacity ≈ 1.0` for sustained periods = LRU
    //     saturated; every fresh `is_finalized()` miss falls through to
    //     disk. Pair with `elara_dag_evict_finalized_cascade_total` —
    //     a cascade burst on a saturated cache is the canonical
    //     "ingest validation slowdown" diagnosis.
    //   * `_hot_size << _hot_capacity` for sustained periods on a node
    //     that has been finalizing records for hours = retention loop
    //     pruning hot entries faster than ingest produces them OR
    //     workload genuinely below cache capacity (no action needed).
    //   * `_hot_capacity` is a static-config gauge — useful for cluster-
    //     wide audit (every node should report the same cap unless
    //     intentionally per-profile). Variance signals config drift.
    let (finalized_hot_size, finalized_capacity, finalized_hot_hits, finalized_cold_lookups, finalized_cold_hits) = {
        let f = state.finalized.read().await;
        (
            f.hot_size() as u64,
            f.capacity() as u64,
            f.hot_hits_total.load(std::sync::atomic::Ordering::Relaxed),
            f.cold_lookups_total.load(std::sync::atomic::Ordering::Relaxed),
            f.cold_hits_total.load(std::sync::atomic::Ordering::Relaxed),
        )
    };
    let node_profile_label = state.config.node_profile.clone();
    // Participation-role label exposed alongside the
    // storage-profile label. `node_profile` (Light/FullZone/
    // Archive) and `node_type` (Anchor/Witness/Leaf/Relay/Gateway) are
    // orthogonal axes — operators need both to read the fleet topology.
    // Surfaces which nodes run as `witness`/`leaf` vs `anchor`, which
    // explains a low `elara_vrf_registry_identities` cluster-wide
    // observation (only Anchor-class nodes publish VRF registration
    // records per Protocol §11.12) without requiring SSH-into-each-node
    // config inspection.
    let node_type_label = {
        let raw = state.config.node_type.as_str();
        // Normalise via NodeType::from_str so an unknown string in
        // config (typo, legacy value) collapses to "leaf" and the
        // label cardinality stays bounded at the 6 known kinds.
        super::peer::NodeType::from_str(raw).as_str()
    };
    let body = format!("{body}\
         # HELP elara_finalized_hot_size Count of finalized record IDs currently resident in the LRU hot tier (RAM cache for the `is_finalized()` predicate hot path). Pair with `elara_finalized_hot_capacity`: ratio approaching 1.0 = LRU saturation, every fresh miss in `is_finalized()` falls through to a RocksDB CF lookup. Distinct from `elara_finalized_count` (TOTAL finalized = hot + cold, monotonic over the node's lifetime) — `_hot_size` is the LRU-pressure signal, `_count` is the lifetime-total signal.\n\
         # TYPE elara_finalized_hot_size gauge\n\
         elara_finalized_hot_size {finalized_hot_size}\n\
         # HELP elara_finalized_hot_capacity Configured capacity of the finalized-record LRU hot tier. Profile-aware: Light=1_000, FullZone=10_000, Archive=1_000_000 - the cap CORRECTLY varies across a heterogeneous fleet. Pair with `elara_node_profile_info` to attribute the expected cap; pair with `elara_finalized_hot_size` for the saturation ratio. Operator override: `NodeConfig.finalized_hot_capacity > 0` wins.\n\
         # TYPE elara_finalized_hot_capacity gauge\n\
         elara_finalized_hot_capacity {finalized_capacity}\n\
         # HELP elara_finalized_hot_hits_total Cumulative `is_finalized()` calls answered from the LRU hot tier without touching RocksDB. Pair with `elara_finalized_cold_lookups_total` to derive the miss rate (`cold / (hot + cold)`). Sustained low miss rate = hot tier sized correctly; sustained high miss rate at saturation = working set exceeds cap (raise `finalized_hot_capacity` or upgrade node profile).\n\
         # TYPE elara_finalized_hot_hits_total counter\n\
         elara_finalized_hot_hits_total {finalized_hot_hits}\n\
         # HELP elara_finalized_cold_lookups_total Cumulative `is_finalized()` calls that fell through the hot tier and probed RocksDB CF_METADATA (regardless of whether the record was found). Each cold lookup pays a bloom-filtered point read (~100ns–1µs). Pair with `elara_finalized_cold_hits_total` to compute cold-hit rate (see that metric for interpretation).\n\
         # TYPE elara_finalized_cold_lookups_total counter\n\
         elara_finalized_cold_lookups_total {finalized_cold_lookups}\n\
         # HELP elara_finalized_cold_hits_total Cumulative cold-tier probes that **found** the record on disk. Cold-hit rate `cold_hits_total / cold_lookups_total` distinguishes two distinct operational states. (a) Rate near 1.0: hot tier is undersized — misses represent real finalized records that aged out of RAM. Action: raise `finalized_hot_capacity` or move to Archive profile. (b) Rate near 0.0: hot tier is sized correctly — misses are speculative `is_finalized()` queries against rids that were never finalized. Action: none, this is healthy.\n\
         # TYPE elara_finalized_cold_hits_total counter\n\
         elara_finalized_cold_hits_total {finalized_cold_hits}\n\
         # HELP elara_node_profile_info Node retention profile. Info gauge — value is always 1, the single label `profile` carries the role: `light` (phone-tier, ≤72h record retention), `full_zone` (operator default, 90-day retention), `archive` (full history). Pair with `elara_finalized_hot_capacity`, `elara_identity_user_cache_max`, `elara_records_retention_seconds` to attribute config-aware sizing across mixed fleets. Cardinality bounded at 3 fixed labels — safe at any fleet size.\n\
         # TYPE elara_node_profile_info gauge\n\
         elara_node_profile_info{{profile=\"{node_profile_label}\"}} 1\n\
         # HELP elara_node_type_info Node participation role (see the protocol spec / network/peer.rs::NodeType). Info gauge -- the value is always 1 and the single node_type label carries the role: anchor (publishes VRF registration, seals epochs, archival), witness (attests records, no epoch sealing), archive (storage-only, no attestation), relay (forwards records only), gateway (delegation proxy for IoT), leaf (light client, no relay). Orthogonal to elara_node_profile_info -- profile is storage-retention shape, node_type is consensus participation. Pair with elara_vrf_registry_identities to check the all-anchors-registered invariant: count(elara_node_type_info{{node_type=\"anchor\"}}) == elara_vrf_registry_identities cluster-wide once gossip converges. Pair with elara_vrf_registration_records_accepted_total to attribute per-node emission (anchors emit one VRF registration record at boot; non-anchors emit zero). Cardinality is bounded at 6 fixed labels, safe at any fleet size; unknown or legacy node_type strings collapse to leaf via NodeType::from_str.\n\
         # TYPE elara_node_type_info gauge\n\
         elara_node_type_info{{node_type=\"{node_type_label}\"}} 1\n\
    ");

    // Witness-liveness fleet-pulse gauges.
    // `WitnessLiveness` (Protocol §11.12) is wired into the consensus
    // settlement path: every attestation arriving at the node calls
    // `record_attestation` to update last-seen timestamp per witness
    // identity. Exposed via `/admin/witness_liveness` JSON and the
    // `/health` endpoint already pulls `(active_count, tracked_count)`,
    // but had ZERO /metrics surface. Operators couldn't see the
    // fleet-wide attestation pulse from dashboards —
    // `elara_consensus_witnesses_seen_total` is monotonic-lifetime
    // and conceals drop-off. At mainnet 10K-witness target this is
    // the canonical "is the fleet healthy?" signal.
    //
    // Two new gauges, single brief lock under `LockRecover::lock_recover`:
    // (1) `elara_witness_liveness_tracked` (= `tracked_count()`,
    //     HashMap len — distinct witnesses ever observed via
    //     attestations on this node, O(1)).
    // (2) `elara_witness_liveness_active_48h` (= `active_count(48h, now)`,
    //     subset attesting in the last 2 days; O(N) iter+filter
    //     bounded by tracked witnesses — at 10K mainnet target a
    //     sub-microsecond pass on each scrape).
    //
    // The 48h threshold matches the pre-existing `/health` endpoint
    // convention so dashboards already grepping /health JSON can
    // switch to /metrics without changing the alarm threshold.
    //
    // Operator dashboard rules:
    //   * `_active_48h / _tracked ≈ 1.0` = healthy fleet, every
    //     tracked witness attesting recently.
    //   * `_active_48h / _tracked < 0.5` for sustained periods =
    //     fleet shedding witnesses faster than new ones join — page
    //     someone (mass-idle event or consensus regression).
    //   * `_tracked` climbing alongside `_active_48h` flat = new
    //     witnesses onboarding but not attesting (mis-staked, wrong
    //     key, network partition isolating new joiners).
    //   * `_tracked` flat alongside `_active_48h` collapsing =
    //     mass-idle event; correlate with
    //     `elara_seal_pending_anchor_oldest_age_seconds`.
    //     If seal pipeline ALSO stalled = infra issue, not witness-side.
    //   * economics §11.2 inactivity-leak alarm: ratio dropping is
    //     the canonical signal that gradual-stake-drain conditions
    //     are firing fleet-wide on idle stake.
    let (witness_liveness_tracked, witness_liveness_active_48h) = {
        use super::LockRecover;
        let liveness = state.witness_liveness.lock_recover();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        (
            liveness.tracked_count() as u64,
            liveness.active_count(48.0 * 3600.0, now) as u64,
        )
    };
    let body = format!("{body}\
         # HELP elara_witness_liveness_tracked Count of distinct witnesses ever observed via attestation on this node (HashMap of witness_hash → last-seen timestamp). Monotonic until `WitnessLiveness::remove` is called (post full-unstake). Pair with `elara_witness_liveness_active_48h`: ratio active/tracked is the fleet-pulse signal — close to 1.0 = healthy, dropping = witnesses going silent.\n\
         # TYPE elara_witness_liveness_tracked gauge\n\
         elara_witness_liveness_tracked {witness_liveness_tracked}\n\
         # HELP elara_witness_liveness_active_48h Count of witnesses that attested at least once in the last 48 hours. 48h threshold matches `/health` endpoint convention. Sustained `< 0.5 × _tracked` = fleet shedding witnesses (mass-idle event, consensus regression, or the economics spec inactivity-leak gradual-drain conditions firing across active stake).\n\
         # TYPE elara_witness_liveness_active_48h gauge\n\
         elara_witness_liveness_active_48h {witness_liveness_active_48h}\n\
    ");

    // L1543 follow-up: per-peer outbound bandwidth bucket observability.
    // Gossip pushes that hit an empty token bucket are silently skipped at 7
    // call sites in `gossip.rs` (`peer_bandwidth.try_acquire`); the L1543 50/100
    // node bench showed 88-95% drop rates with no Prometheus signal explaining
    // *which* gossip path was being throttled. Surface the cumulative skip count
    // and the tracked-peers gauge so operators can graph and alert on token-
    // bucket saturation distinct from hops-exhausted (`gossip_push_skipped`) and
    // attestation-bucket drops (`attestation_push_skip_bandwidth`).
    let pb_skipped = state.peer_bandwidth.skipped_total.load(std::sync::atomic::Ordering::Relaxed);
    let pb_tracked = state.peer_bandwidth.tracked_peers();
    let body = format!("{body}\
         # HELP elara_peer_bandwidth_skipped_total Outbound gossip pushes skipped because the per-peer token bucket was empty (distinct from hops-exhausted and attestation-bucket drops)\n\
         # TYPE elara_peer_bandwidth_skipped_total counter\n\
         elara_peer_bandwidth_skipped_total {pb_skipped}\n\
         # HELP elara_peer_bandwidth_tracked_peers Peers with a live token bucket (LRU-bounded by MAX_PEERS=10000)\n\
         # TYPE elara_peer_bandwidth_tracked_peers gauge\n\
         elara_peer_bandwidth_tracked_peers {pb_tracked}\n\
    ");

    // Gap 4 routing close-out + Gap 5 Phase 6b advisory counters.
    let rr_queries     = state.zone_routing_resolve_queries_total.load(std::sync::atomic::Ordering::Relaxed);
    let rr_redirected  = state.zone_routing_resolve_redirected_total.load(std::sync::atomic::Ordering::Relaxed);
    let ri_queries     = state.zone_resolve_internal_queries_total.load(std::sync::atomic::Ordering::Relaxed);
    let ri_redirected  = state.zone_resolve_internal_redirected_total.load(std::sync::atomic::Ordering::Relaxed);
    let cm_member      = state.committee_attestations_member_total.load(std::sync::atomic::Ordering::Relaxed);
    let cm_nonmember   = state.committee_attestations_nonmember_total.load(std::sync::atomic::Ordering::Relaxed);
    let cm_skipped     = state.committee_observations_skipped_no_candidates_total.load(std::sync::atomic::Ordering::Relaxed);

    let body = format!("{body}\
         # HELP elara_zone_routing_resolve_queries_total /routing/resolve queries served\n\
         # TYPE elara_zone_routing_resolve_queries_total counter\n\
         elara_zone_routing_resolve_queries_total {rr_queries}\n\
         # HELP elara_zone_routing_resolve_redirected_total /routing/resolve queries where resolved leaf differed from naive zone\n\
         # TYPE elara_zone_routing_resolve_redirected_total counter\n\
         elara_zone_routing_resolve_redirected_total {rr_redirected}\n\
         # HELP elara_zone_resolve_internal_queries_total Internal resolve_record_zone/resolve_identity_zone calls (migration progress counter)\n\
         # TYPE elara_zone_resolve_internal_queries_total counter\n\
         elara_zone_resolve_internal_queries_total {ri_queries}\n\
         # HELP elara_zone_resolve_internal_redirected_total Internal resolves where the registry walked at least one split/merge hop (zero until splits finalize)\n\
         # TYPE elara_zone_resolve_internal_redirected_total counter\n\
         elara_zone_resolve_internal_redirected_total {ri_redirected}\n\
         # HELP elara_committee_attestations_member_total Layer 2 seal attestations whose witness IS in the VRF-selected committee for (zone, epoch)\n\
         # TYPE elara_committee_attestations_member_total counter\n\
         elara_committee_attestations_member_total {cm_member}\n\
         # HELP elara_committee_attestations_nonmember_total Layer 2 seal attestations whose witness is NOT in the committee (advisory only — still accepted)\n\
         # TYPE elara_committee_attestations_nonmember_total counter\n\
         elara_committee_attestations_nonmember_total {cm_nonmember}\n\
         # HELP elara_committee_observations_skipped_no_candidates_total Seal attestations the observer couldn't judge (empty VRF registry / zero-stake anchors)\n\
         # TYPE elara_committee_observations_skipped_no_candidates_total counter\n\
         elara_committee_observations_skipped_no_candidates_total {cm_skipped}\n\
    ");

    // Gap 5 Phase 6b cached resolver gauges + counters.
    // The `ZoneCommitteeResolver` is the single call site behind both the
    // advisory `/committees/is_member` predicate (today) and the consensus
    // attestation gate (once `enforce_per_zone_vrf` flips). Operators need
    // four signals before the flip is safe:
    //   1. Cache size / capacity (RAM headroom — at 1M-zone mainnet the cap
    //      is the operator-tunable knob from `committee_resolver_cache_size`).
    //   2. Hits / misses (cache effectiveness — high miss rate at low query
    //      rate signals candidates_fingerprint thrashing, which means the
    //      VRF registry or stake set is mutating mid-epoch faster than the
    //      cache can amortize).
    //   3. Evictions (working-set vs cap mismatch — non-zero evictions on a
    //      small fleet is an early signal that the cap is undersized).
    //   4. Enforcement flag (per-fleet audit; if any node reports
    //      `enforce_per_zone_vrf=1` while the rest report 0, that's a
    //      committee-membership divergence at attestation gating).
    //
    // Cache-size + capacity are static gauges (no scrape cost beyond a
    // single std::sync::Mutex hold for `cache.len()` and `max_entries`).
    // Hits/misses/evictions are AtomicU64 counters.
    //
    // Operator dashboard rules:
    //   * `_misses / (_hits + _misses) ≈ 1.0` at low query rate = thrashing.
    //   * Sustained `_evictions_total` growth = `committee_resolver_cache_size`
    //     too small for the working set.
    //   * Cluster-wide `_enforce_per_zone_vrf` axis: must be uniform across
    //     all nodes. A single `1` against a fleet of `0`s = drift; treat
    //     as a config-rollout incident until the rest catch up.
    let ccr_size = state.zone_committee_resolver.cache_size() as u64;
    let ccr_cap = state.zone_committee_resolver.cache_capacity() as u64;
    let ccr_hits = state.zone_committee_resolver.hits_total.load(std::sync::atomic::Ordering::Relaxed);
    let ccr_misses = state.zone_committee_resolver.misses_total.load(std::sync::atomic::Ordering::Relaxed);
    let ccr_evictions = state.zone_committee_resolver.evictions_total.load(std::sync::atomic::Ordering::Relaxed);
    let enforce_per_zone_vrf_flag = if state.config.enforce_per_zone_vrf { 1u8 } else { 0u8 };
    // Gap 5 Phase 6c rejection counter. Number of
    // Layer 2 epoch seal attestations dropped by the per-zone VRF
    // committee gate at the consensus call sites (`feed_attestation`,
    // `batch_feed_attestations`, `process_attestation_pull_batch`). Stays
    // at 0 while `enforce_per_zone_vrf=false` (Phase 6c default — gate
    // is wired but short-circuits). When the flag flips, divergence vs
    // `committee_attestations_nonmember_total` (advisory observer) is the
    // operator signal that the gate disagrees with the observer (cache
    // skew, candidate-fingerprint split, or a bug).
    let phase6c_rejected = state
        .seal_attestation_rejected_not_in_committee_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let phase6c5_below_k = state
        .committee_skipped_below_k_total
        .load(std::sync::atomic::Ordering::Relaxed);
    // VRF registration ingest accept/reject totals.
    // Diagnostic gap surfaced when the testnet showed a low registry
    // count cluster-wide despite multiple anchors running. Today the
    // rejection path emits only a `tracing::debug!` line, so the only
    // fleet-wide signal is the *result* (registry size) — these counters
    // expose the *cause* (records arriving but failing the extract gate)
    // without needing to turn on debug-level logging across all nodes.
    let vrf_reg_accepted = state
        .vrf_registration_records_accepted_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let vrf_reg_rejected = state
        .vrf_registration_records_rejected_total
        .load(std::sync::atomic::Ordering::Relaxed);
    // Single-signal Phase 6d readiness gauge.
    // Encodes the flip-safety rule (registry >= K AND real committee
    // work observed) in code instead of in operator runbooks. Both
    // dashboards and any future auto-flip logic should consume this
    // gauge rather than re-deriving the rule by hand.
    let phase6d = crate::network::zone_committee::phase6d_readiness(&state);
    let phase6d_ready = if phase6d.ready { 1u8 } else { 0u8 };

    let body = format!("{body}\
         # HELP elara_committee_resolver_cache_size Count of `(zone_path, epoch, k, candidates_fingerprint) → committee` entries currently resident in the per-zone VRF resolver. Pair with `_capacity` for headroom; `_evictions_total` if size hits cap and growth stalls.\n\
         # TYPE elara_committee_resolver_cache_size gauge\n\
         elara_committee_resolver_cache_size {ccr_size}\n\
         # HELP elara_committee_resolver_cache_capacity Configured FIFO cap on the resolver cache (`committee_resolver_cache_size` config, default 4096). Static gauge — variance across the fleet signals config drift.\n\
         # TYPE elara_committee_resolver_cache_capacity gauge\n\
         elara_committee_resolver_cache_capacity {ccr_cap}\n\
         # HELP elara_committee_resolver_hits_total Cache-hit count. Hot path returns a clone of the cached committee without re-running the Efraimidis–Spirakis sort.\n\
         # TYPE elara_committee_resolver_hits_total counter\n\
         elara_committee_resolver_hits_total {ccr_hits}\n\
         # HELP elara_committee_resolver_misses_total Cache-miss count. Each miss falls through to `select_zone_committee` and inserts the result. Sustained miss-rate ≈ 1.0 at low query rate signals candidates_fingerprint thrash (VRF registry / stake set mutating faster than the cache can amortize).\n\
         # TYPE elara_committee_resolver_misses_total counter\n\
         elara_committee_resolver_misses_total {ccr_misses}\n\
         # HELP elara_committee_resolver_evictions_total FIFO eviction count. Sustained growth = working set exceeds `committee_resolver_cache_size` cap; raise the cap.\n\
         # TYPE elara_committee_resolver_evictions_total counter\n\
         elara_committee_resolver_evictions_total {ccr_evictions}\n\
         # HELP elara_enforce_per_zone_vrf Per-zone VRF gate kill-switch. 1 = consensus attestation gate consults the per-zone resolver; 0 = global VRF path (bootstrap default). Cluster-wide axis MUST be uniform - a single `1` against `0`s signals a half-rolled config and is a committee-membership divergence at gating.\n\
         # TYPE elara_enforce_per_zone_vrf gauge\n\
         elara_enforce_per_zone_vrf {enforce_per_zone_vrf_flag}\n\
         # HELP elara_seal_attestation_rejected_not_in_committee_total Per-zone VRF gate rejections - seal attestations dropped because `enforce_per_zone_vrf=true` and witness was not in the per-zone VRF committee for (seal.zone, seal.epoch). Stays 0 while flag is off. After flip: rate should track `elara_committee_attestations_nonmember_total` rate; divergence is a gate-vs-observer disagreement (likely cache or candidate-fingerprint skew).\n\
         # TYPE elara_seal_attestation_rejected_not_in_committee_total counter\n\
         elara_seal_attestation_rejected_not_in_committee_total {phase6c_rejected}\n\
         # HELP elara_committee_skipped_below_k_total Per-zone VRF bootstrap fallback counter - seal attestations that bypassed the per-zone VRF gate because the VRF-registered+staked population is below `phase6d_min_committee_size` (default 7; read live via `elara_phase6d_min_committee_size`). Both the consensus gate (per-call) and the advisory observer (per-batch) bump this counter. Sustained growth past the bootstrap window = enforcement is silently inactive at scale; `elara_vrf_registry_identities >= elara_phase6d_min_committee_size` is the necessary-but-not-sufficient condition for this counter to stop climbing (each active zone also needs that many staked anchors). When this counter plateaus AND `elara_committee_attestations_member_total` starts climbing, the per-zone gate is fully active and the flag flip is safe.\n\
         # TYPE elara_committee_skipped_below_k_total counter\n\
         elara_committee_skipped_below_k_total {phase6c5_below_k}\n\
         # HELP elara_vrf_registration_records_accepted_total Count of records carrying VRF_REGISTRATION_KEY metadata that ingested cleanly — `extract_vrf_registration()` returned Some and the local VrfRegistry now holds the entry (idempotent overwrite if already present). Pair with `_rejected_total` for the acceptance rate. Sustained climb on accepted while `elara_vrf_registry_identities` stays flat = same anchors re-publishing (idempotent — fine, but unusual at steady state); flat accepted + low `elara_vrf_registry_identities` = anchors not publishing or records not propagating. Cluster-wide rate variance signals gossip-propagation drift between fleet members.\n\
         # TYPE elara_vrf_registration_records_accepted_total counter\n\
         elara_vrf_registration_records_accepted_total {vrf_reg_accepted}\n\
         # HELP elara_vrf_registration_records_rejected_total Count of records that carried VRF_REGISTRATION_KEY metadata but `extract_vrf_registration()` returned None — record was rejected because (a) `vrf_public_key` field missing or hex-invalid, (b) hex did not decode to exactly 32 bytes, (c) `node_type` does not satisfy `can_seal_epochs()`. Today this gate emits a `tracing::debug!` line per rejection — invisible in production. This counter exposes the rejection rate at /metrics so operators can detect the anchors-publishing-but-being-dropped scenario without enabling debug logs cluster-wide. Healthy = 0 in steady state. Sustained growth = anchor configs out of sync with ingest gate (e.g. node_type misfiled, key format drift).\n\
         # TYPE elara_vrf_registration_records_rejected_total counter\n\
         elara_vrf_registration_records_rejected_total {vrf_reg_rejected}\n\
         # HELP elara_phase6d_ready Per-zone VRF flip readiness. 1 = all pre-flip safety conditions hold, `enforce_per_zone_vrf=true` is safe to roll. 0 = at least one blocker is active. Conditions checked: (a) `vrf_registry_below_committee_size` - local registry has fewer than `phase6d_min_committee_size` (default 7) identities; flipping now would land in the sub-K fallback for every attestation, leaving enforcement silently inactive. (b) `no_observed_committee_members` - `committee_attestations_member_total == 0`; the observer has never seen a real committee draw, so flipping now would prove nothing. The full snapshot also exposes `registry_size`, `min_committee_size`, `gate_currently_enforcing`, `member_observations` via the `phase6d_readiness()` lib helper. Operator workflow: this gauge must be 1 cluster-wide AND stable across a >=24h window before flipping. Cluster axis variance signals stake-drift between nodes.\n\
         # TYPE elara_phase6d_ready gauge\n\
         elara_phase6d_ready {phase6d_ready}\n\
         # HELP elara_phase6d_min_committee_size Per-zone VRF readiness threshold actually in effect on this node - value of `phase6d_min_committee_size` config (default 7 = `DEFAULT_COMMITTEE_SIZE`; can be lowered via toml or `ELARA_PHASE6D_MIN_COMMITTEE_SIZE` env override for small testnets). Cluster-axis variance = config drift; mainnet operators should see a uniform 7 fleet-wide. Pair with `elara_phase6d_ready` to interpret readiness - a node reporting `_ready=1` at threshold=2 with only 2 anchors is NOT mainnet-safe, even though both gauges look healthy.\n\
         # TYPE elara_phase6d_min_committee_size gauge\n\
         elara_phase6d_min_committee_size {phase6d_min_k}\n\
    ");

    // Gap 4 close-out: zone-registry tick-time Dilithium3 signature verify
    // gate. Counts TransitionSeals that reached AwaitingSigs threshold but
    // whose aggregated `proposer_sigs` did not verify against the registered
    // anchor pubkeys (either forgery attempt or pubkey-propagation hole). A
    // healthy fleet reads `count=0`; non-zero should page.
    let zr_sig_fail = state.zone_registry_tick_sig_verify_failures_total.load(std::sync::atomic::Ordering::Relaxed);
    // Gap 5 zone-registry boot+tick coherence counters. Boot path replays
    // CF_TRANSITIONS_FINAL into the in-memory registry on startup; tick path
    // applies finalized seals as they land. boot_applied + tick_applied
    // together must equal transitions_finalized_total in steady state — any
    // gap is a registry inconsistency. decode_failures = on-disk corruption.
    // boot_apply_failures + tick_apply_failures = registry-side rejection
    // (race or bug). All five expected zero on a coherent fleet.
    let zr_boot_applied = state.zone_registry_boot_applied_total.load(std::sync::atomic::Ordering::Relaxed);
    let zr_boot_decode_fail = state.zone_registry_boot_decode_failures_total.load(std::sync::atomic::Ordering::Relaxed);
    let zr_boot_apply_fail = state.zone_registry_boot_apply_failures_total.load(std::sync::atomic::Ordering::Relaxed);
    let zr_tick_applied = state.zone_registry_tick_applied_total.load(std::sync::atomic::Ordering::Relaxed);
    let zr_tick_apply_fail = state.zone_registry_tick_apply_failures_total.load(std::sync::atomic::Ordering::Relaxed);
    // Protocol-level zone-leaf inventory. Bounded read
    // (`active_count` = `BTreeSet::len`, `total_zones` = `HashMap::len`) under a
    // brief read-lock. Pair with `elara_consensus_committee_zones_registered`:
    // if `active_zones > committee_zones_registered` in steady
    // state, the per-epoch rotation is missing zones (committee-coverage
    // drift). `total_zones - active_zones` = ever-closed zones (split parents
    // + merged-into).
    let (zr_active_zones, zr_total_zones) = {
        use super::RwLockRecover;
        let reg = state.zone_registry.read_recover();
        (reg.active_count() as u64, reg.total_zones() as u64)
    };
    let body = format!("{body}\
         # HELP elara_zone_registry_tick_sig_verify_failures_total TransitionSeals rejected at run_transition_tick because anchor-pubkey Dilithium3 verify failed (forgery or missing pubkey registration)\n\
         # TYPE elara_zone_registry_tick_sig_verify_failures_total counter\n\
         elara_zone_registry_tick_sig_verify_failures_total {zr_sig_fail}\n\
         # HELP elara_zone_registry_boot_applied_total TransitionSeals successfully reapplied to the in-memory ZoneRegistry from CF_TRANSITIONS_FINAL on this node's last cold start. Compare with transitions_finalized_total - boot_applied + tick_applied must equal finalized in steady state. A gap indicates registry/disk drift.\n\
         # TYPE elara_zone_registry_boot_applied_total counter\n\
         elara_zone_registry_boot_applied_total {zr_boot_applied}\n\
         # HELP elara_zone_registry_boot_decode_failures_total Finalized seal rows whose stored bytes failed to decode at boot. Non-zero means on-disk corruption - registry came up partial. Operator alert: investigate before this node serves routing traffic.\n\
         # TYPE elara_zone_registry_boot_decode_failures_total counter\n\
         elara_zone_registry_boot_decode_failures_total {zr_boot_decode_fail}\n\
         # HELP elara_zone_registry_boot_apply_failures_total Decoded seals whose apply_transition rejected at boot - registry-side consistency check failed. CF_TRANSITIONS_FINAL only accepts post-cosign seals, so any non-zero count flags a registry bug or upstream concurrent-apply race.\n\
         # TYPE elara_zone_registry_boot_apply_failures_total counter\n\
         elara_zone_registry_boot_apply_failures_total {zr_boot_apply_fail}\n\
         # HELP elara_zone_registry_tick_applied_total Finalized seals applied to ZoneRegistry by run_transition_tick since process start. Pairs with transitions_finalized_total - finalized >= tick_applied; the gap is finalized seals whose apply errored after persistence (logged per-failure).\n\
         # TYPE elara_zone_registry_tick_applied_total counter\n\
         elara_zone_registry_tick_applied_total {zr_tick_applied}\n\
         # HELP elara_zone_registry_tick_apply_failures_total Finalized seals rejected by ZoneRegistry::apply_transition (consistency error) in the live tick. Per-failure error logged; this counter is the fleet-aggregate signal. Expected zero on a coherent fleet.\n\
         # TYPE elara_zone_registry_tick_apply_failures_total counter\n\
         elara_zone_registry_tick_apply_failures_total {zr_tick_apply_fail}\n\
         # HELP elara_zone_registry_active_zones Count of currently-active leaf zones in the protocol-of-record `ZoneRegistry`. This is the truth source for routing (which leaf zone owns an account) and per-epoch committee draws — every active leaf must have a per-zone witness committee. At mainnet target (1M zones) this number is the fleet's primary scaling-state gauge. Pair with `elara_consensus_committee_zones_registered`: if `active_zones > committee_zones_registered` in steady state, the per-epoch rotation is missing some zones (committee-coverage drift). Bounded read on the registry's active-set BTreeSet, no allocation.\n\
         # TYPE elara_zone_registry_active_zones gauge\n\
         elara_zone_registry_active_zones {zr_active_zones}\n\
         # HELP elara_zone_registry_total_zones Count of all zones the registry has ever known — currently active + historically closed (split parents and merged-into intermediates). `total_zones - active_zones` = number of zones that have ever been split, merged, or otherwise closed; sustained growth at constant `active_zones` = healthy split/merge churn. Sustained `total_zones == active_zones` with a non-trivial fleet = registry hasn't seen any auto-scaling activity. Bounded read on the registry's entries HashMap, no allocation.\n\
         # TYPE elara_zone_registry_total_zones gauge\n\
         elara_zone_registry_total_zones {zr_total_zones}\n\
    ");

    // Gap 6 + MAINNET routing visibility: gossip routing-decision counters.
    // - relay_content_routed: fanouts that used SHA3-of-record DHT placement
    //   (Kademlia overlay) instead of sqrt(n) flood. Steady non-zero rate
    //   confirms content-addressed gossip is live; flat = degraded to flood.
    // - push_content_routed: same path on the originator-push side.
    // - relay_committee_routed: attestation pushes that included the active
    //   committee peers as mandatory targets. Confirms committee-aware
    //   routing is firing on mainnet.
    // - rejected_dedup: pushes/relays/pulls dropped by gossip_rejected cache.
    //   High vs gossip_seen_dedup_total ratio means signature failures, not
    //   benign duplicate suppression — investigate.
    let gpc_relay_content = state.gossip_relay_content_routed_total.load(std::sync::atomic::Ordering::Relaxed);
    let gpc_push_content = state.gossip_push_content_routed_total.load(std::sync::atomic::Ordering::Relaxed);
    let gpc_push_floor_fb = state.gossip_push_dht_floor_fallback_total.load(std::sync::atomic::Ordering::Relaxed);
    let gpc_relay_floor_fb = state.gossip_relay_dht_floor_fallback_total.load(std::sync::atomic::Ordering::Relaxed);
    let gpc_repl_factor = state.gossip_push_dht_replication_factor_last.load(std::sync::atomic::Ordering::Relaxed);
    let gpc_seal_repl_tracked = state.gossip_seal_replication_tracked_total.load(std::sync::atomic::Ordering::Relaxed);
    let gpc_seal_repl_overflow = state.gossip_seal_replication_overflow_total.load(std::sync::atomic::Ordering::Relaxed);
    let gpc_seal_repl_pending = state.gossip_seal_replication_pending_depth.load(std::sync::atomic::Ordering::Relaxed);
    let gpc_seal_repl_ticks = state.gossip_seal_replication_reconcile_ticks_total.load(std::sync::atomic::Ordering::Relaxed);
    let gpc_seal_repl_probe_ok = state.gossip_seal_replication_probe_ok_total.load(std::sync::atomic::Ordering::Relaxed);
    let gpc_seal_repl_probe_miss = state.gossip_seal_replication_probe_miss_total.load(std::sync::atomic::Ordering::Relaxed);
    let gpc_seal_repl_probe_fail = state.gossip_seal_replication_probe_fail_total.load(std::sync::atomic::Ordering::Relaxed);
    let gpc_seal_repl_repush = state.gossip_seal_replication_repush_total.load(std::sync::atomic::Ordering::Relaxed);
    let gpc_seal_repl_violation = state.gossip_seal_replication_floor_violation_total.load(std::sync::atomic::Ordering::Relaxed);
    let gpc_relay_committee = state.gossip_relay_committee_routed_total.load(std::sync::atomic::Ordering::Relaxed);
    let gossip_rejected_dedup = state.gossip_rejected_dedup_total.load(std::sync::atomic::Ordering::Relaxed);
    let gpc_select_dht = state.gossip_select_dht_total.load(std::sync::atomic::Ordering::Relaxed);
    let gpc_select_fallback = state.gossip_select_fallback_total.load(std::sync::atomic::Ordering::Relaxed);
    let peer_admit_cap_clipped = state.peer_admission_source_cap_clipped_total.load(std::sync::atomic::Ordering::Relaxed);
    let delta_sync_attempts = state.delta_sync_attempts_total.load(std::sync::atomic::Ordering::Relaxed);
    let unknown_meta_keys_admitted = state.unknown_metadata_keys_admitted_total.load(std::sync::atomic::Ordering::Relaxed);
    let delta_sync_failures_timeout = state.delta_sync_failures_timeout_total.load(std::sync::atomic::Ordering::Relaxed);
    let delta_sync_failures_other = state.delta_sync_failures_other_total.load(std::sync::atomic::Ordering::Relaxed);
    let delta_sync_failures_other_addr = state.delta_sync_failures_other_addr_total.load(std::sync::atomic::Ordering::Relaxed);
    let delta_sync_failures_other_dial = state.delta_sync_failures_other_dial_total.load(std::sync::atomic::Ordering::Relaxed);
    let delta_sync_failures_other_rpc = state.delta_sync_failures_other_rpc_total.load(std::sync::atomic::Ordering::Relaxed);
    let delta_sync_failures_other_decode = state.delta_sync_failures_other_decode_total.load(std::sync::atomic::Ordering::Relaxed);
    let secs_since_last_pull = {
        let last = state.last_successful_pull_unix.load(std::sync::atomic::Ordering::Relaxed);
        if last == 0 {
            0u64
        } else {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
                .saturating_sub(last)
        }
    };
    let delta_sync_lat_lt_2s = state.delta_sync_latency_lt_2s_total.load(std::sync::atomic::Ordering::Relaxed);
    let delta_sync_lat_lt_10s = state.delta_sync_latency_lt_10s_total.load(std::sync::atomic::Ordering::Relaxed);
    let delta_sync_lat_lt_30s = state.delta_sync_latency_lt_30s_total.load(std::sync::atomic::Ordering::Relaxed);
    let delta_sync_to_handshake = state.delta_sync_failures_timeout_handshake_total.load(std::sync::atomic::Ordering::Relaxed);
    let delta_sync_to_rpc = state.delta_sync_failures_timeout_rpc_total.load(std::sync::atomic::Ordering::Relaxed);
    let delta_sync_scan_hit_cap = state.delta_sync_scan_hit_cap_total.load(std::sync::atomic::Ordering::Relaxed);
    let ds_cursor_pages     = state.delta_sync_cursor_pages_total.load(std::sync::atomic::Ordering::Relaxed);
    let ds_cursor_reject    = state.delta_sync_cursor_reject_total.load(std::sync::atomic::Ordering::Relaxed);
    let ds_cursor_guard     = state.delta_sync_cursor_guard_trips_total.load(std::sync::atomic::Ordering::Relaxed);
    let ds_cursor_exhausted = state.delta_sync_cursor_cycle_exhausted_total.load(std::sync::atomic::Ordering::Relaxed);
    let delta_sync_served = state.delta_sync_served_total.load(std::sync::atomic::Ordering::Relaxed);
    let delta_sync_served_records = state.delta_sync_served_records_total.load(std::sync::atomic::Ordering::Relaxed);
    let witness_scope_cap = state.witness_smt_scope_scan_hit_cap_total.load(std::sync::atomic::Ordering::Relaxed);
    let witness_scope_incomplete = state.witness_smt_scope_incomplete_total.load(std::sync::atomic::Ordering::Relaxed);
    let body = format!("{body}\
         # HELP elara_gossip_relay_content_routed_total Relay forwards routed via SHA3-of-record DHT placement (Kademlia overlay) - fanout to the K responsible peers for the record's content hash, NOT sqrt(n) flood. Steady non-zero rate confirms content-addressed gossip is live in production; flat = relay degraded to flood-gossip.\n\
         # TYPE elara_gossip_relay_content_routed_total counter\n\
         elara_gossip_relay_content_routed_total {gpc_relay_content}\n\
         # HELP elara_gossip_push_content_routed_total Originator pushes routed via SHA3-of-record DHT placement. Mirror counter to elara_gossip_relay_content_routed_total for the producer-side path.\n\
         # TYPE elara_gossip_push_content_routed_total counter\n\
         elara_gossip_push_content_routed_total {gpc_push_content}\n\
         # HELP elara_peer_admission_source_cap_clipped_total Times a discovery source's genuinely-new-peer batch was clipped at MAX_NEW_PEERS_PER_SOURCE (anti-flood). Benign and expected at cold-start when a large seed legitimately offers more new peers than the cap; sustained non-zero AFTER the peer table has converged may indicate a source flooding new identities. Not per-source-labelled (would be unbounded-cardinality) - correlate with discovery logs to identify the source.\n\
         # TYPE elara_peer_admission_source_cap_clipped_total counter\n\
         elara_peer_admission_source_cap_clipped_total {peer_admit_cap_clipped}\n\
         # HELP elara_gossip_push_dht_floor_fallback_total Originator pushes that ATTEMPTED the K-DHT path but fell back to flood because fewer than seal_dht_replication_floor distinct DHT-closest peers passed zone/reachability filtering. Sustained non-zero rate on a high-peer-count node means the DHT is sparse, peer filters are too aggressive, or the floor is set too tight for the current cluster size.\n\
         # TYPE elara_gossip_push_dht_floor_fallback_total counter\n\
         elara_gossip_push_dht_floor_fallback_total {gpc_push_floor_fb}\n\
         # HELP elara_gossip_relay_dht_floor_fallback_total Relay forwards that fell back from K-DHT to reputation-weighted DHT walk because fewer than seal_dht_replication_floor distinct peers passed filtering. Tracked separately because the relay's eligible-peer set is typically smaller, so its fallback rate is naturally higher.\n\
         # TYPE elara_gossip_relay_dht_floor_fallback_total counter\n\
         elara_gossip_relay_dht_floor_fallback_total {gpc_relay_floor_fb}\n\
         # HELP elara_gossip_push_dht_replication_factor_last Most recently observed K-DHT replication factor for an originator push. Sticky between pushes so scraping is meaningful at low push rates. Compare against content_routing_k to confirm the configured K is achievable in the current peer topology.\n\
         # TYPE elara_gossip_push_dht_replication_factor_last gauge\n\
         elara_gossip_push_dht_replication_factor_last {gpc_repl_factor}\n\
         # HELP elara_gossip_seal_replication_tracked_total K-DHT-routed seal pushes recorded into the pending-replication queue (post bandwidth filter). Compare against gossip_push_content_routed_total to confirm seals are dominating the content-routed mix. The reconciler probes each tracked target for actual seal persistence and re-pushes if the realized replication factor falls below seal_dht_replication_floor.\n\
         # TYPE elara_gossip_seal_replication_tracked_total counter\n\
         elara_gossip_seal_replication_tracked_total {gpc_seal_repl_tracked}\n\
         # HELP elara_gossip_seal_replication_overflow_total Pending-replication entries dropped (FIFO) because the queue was at seal_dht_replication_pending_max. Sustained non-zero means the seal-replication reconciler isn't keeping pace with seal traffic - operator must lower seal rate, raise the queue cap, or shorten the reconciler interval. Distinct from gossip_push_dht_floor_fallback_total which counts K-DHT bypass at push time.\n\
         # TYPE elara_gossip_seal_replication_overflow_total counter\n\
         elara_gossip_seal_replication_overflow_total {gpc_seal_repl_overflow}\n\
         # HELP elara_gossip_seal_replication_pending_depth Current depth of the pending-replication queue. Bounded above by seal_dht_replication_pending_max. Steady-state depth ~= (push rate x ack timeout) once the reconciler is live; depth pinned at cap = reconciler-starvation alarm.\n\
         # TYPE elara_gossip_seal_replication_pending_depth gauge\n\
         elara_gossip_seal_replication_pending_depth {gpc_seal_repl_pending}\n\
         # HELP elara_gossip_seal_replication_reconcile_ticks_total Count of seal-replication reconciler ticks since process start. Increments every seal_dht_reconcile_interval_secs even when the queue is empty, so a flat counter unambiguously means the loop is dead. Pair with the probe/repush counters to compute average work-per-tick without timeseries math.\n\
         # TYPE elara_gossip_seal_replication_reconcile_ticks_total counter\n\
         elara_gossip_seal_replication_reconcile_ticks_total {gpc_seal_repl_ticks}\n\
         # HELP elara_gossip_seal_replication_probe_ok_total Per-target presence-probe responses where the peer confirmed the seal is persisted. Numerator of the realized replication factor.\n\
         # TYPE elara_gossip_seal_replication_probe_ok_total counter\n\
         elara_gossip_seal_replication_probe_ok_total {gpc_seal_repl_probe_ok}\n\
         # HELP elara_gossip_seal_replication_probe_miss_total Peer was reachable but reported the seal absent. Sustained non-zero rate without matching probe_fail = peers are dropping seals post-receipt; investigate retention/GC, not network reachability.\n\
         # TYPE elara_gossip_seal_replication_probe_miss_total counter\n\
         elara_gossip_seal_replication_probe_miss_total {gpc_seal_repl_probe_miss}\n\
         # HELP elara_gossip_seal_replication_probe_fail_total Probe RPC failed (timeout / unreachable / malformed reply). Distinct from probe_miss so an operator can attribute under-replication to network outage vs. peer-side GC.\n\
         # TYPE elara_gossip_seal_replication_probe_fail_total counter\n\
         elara_gossip_seal_replication_probe_fail_total {gpc_seal_repl_probe_fail}\n\
         # HELP elara_gossip_seal_replication_repush_total Re-push attempts the reconciler issued to fresh K-DHT targets because the realized replication factor was below seal_dht_replication_floor. Sustained high rate alongside healthy probe counters = either floor too tight for topology or peer-side GC.\n\
         # TYPE elara_gossip_seal_replication_repush_total counter\n\
         elara_gossip_seal_replication_repush_total {gpc_seal_repl_repush}\n\
         # HELP elara_gossip_seal_replication_floor_violation_total Pending entries that exhausted seal_dht_max_repush_retries without ever reaching seal_dht_replication_floor. Each increment is a seal the network failed to keep R-replicated despite the reconciler's retry budget - operator escalation needed (DHT partition, peer-side GC, floor mis-tuning).\n\
         # TYPE elara_gossip_seal_replication_floor_violation_total counter\n\
         elara_gossip_seal_replication_floor_violation_total {gpc_seal_repl_violation}\n\
         # HELP elara_gossip_relay_committee_routed_total MAINNET gap #2: attestation pushes that included the zone's active committee peers as mandatory targets. Incremented once per attestation push regardless of how many committee peers were reachable. Confirms committee-aware routing is live on mainnet.\n\
         # TYPE elara_gossip_relay_committee_routed_total counter\n\
         elara_gossip_relay_committee_routed_total {gpc_relay_committee}\n\
         # HELP elara_gossip_rejected_dedup_total Records skipped because they were already in the gossip_rejected cache (signature failure, malformed payload, or stale). Distinct from gossip_seen_dedup_total which dedups already-accepted records. High rejected_dedup vs seen_dedup ratio means peers are re-pushing records that failed verification — investigate misbehaving peer.\n\
         # TYPE elara_gossip_rejected_dedup_total counter\n\
         elara_gossip_rejected_dedup_total {gossip_rejected_dedup}\n\
         # HELP elara_gossip_select_dht_total Pull-side peer-selection took the DHT path. Each increment = one select_gossip_peers call where dht.closest() returned at least one reachable candidate that survived reputation/backoff filtering. Pairs 1:1 with elara_gossip_select_fallback_total — the dominant value tells you whether the DHT is operationally contributing to gossip-target diversity, or whether the node is iterating PeerTable. At cold start fallback dominates; once DHT bootstrap completes the DHT path should dominate within ~5 cycles. fallback >> dht_path on a node with elara_dht_size>0 means stale DHT entries (not bootstrap regression).\n\
         # TYPE elara_gossip_select_dht_total counter\n\
         elara_gossip_select_dht_total {gpc_select_dht}\n\
         # HELP elara_gossip_select_fallback_total Pull-side peer-selection fell through to PeerTable iteration. Two distinct causes both bump this counter: (a) DHT was empty, or (b) DHT had candidates but all of them failed reputation/backoff/reachability filtering. Pair with elara_dht_size to discriminate: high fallback + dht_size=0 = bootstrap regression; high fallback + dht_size>0 = stale-entry regression (DHT holds entries faster than dht_refresh_interval can refresh them).\n\
         # TYPE elara_gossip_select_fallback_total counter\n\
         elara_gossip_select_fallback_total {gpc_select_fallback}\n\
         # HELP elara_delta_sync_attempts_total Cumulative pq_delta_sync(...) invocations across both callers (sync.rs::delta_sync_loop and gossip.rs::pull_loop). Pair with elara_delta_sync_failures_timeout_total + elara_delta_sync_failures_other_total to compute the live delta-sync success ratio. Previously only journalctl warnings surfaced this path; without a counter, operators could not Prometheus-alert on a delta-sync regression.\n\
         # TYPE elara_delta_sync_attempts_total counter\n\
         elara_delta_sync_attempts_total {delta_sync_attempts}\n\
         # HELP elara_unknown_metadata_keys_admitted_total Metadata keys admitted at ingest that are NOT in this binary's ALLOWED_KEYS schema registry (forward-compat admission, 2026-07-02 — unknown non-blocked keys are inert and tolerated so additive schema growth cannot wedge a frozen binary; see internal design notes). Steady growth = peers run a newer schema than this binary: the node stays in sync, but plan an upgrade. Flat 0 on a single-version fleet. NOT a rejection counter — rejected keys (blocked/oversize/bad-charset) never reach it.\n\
         # TYPE elara_unknown_metadata_keys_admitted_total counter\n\
         elara_unknown_metadata_keys_admitted_total {unknown_meta_keys_admitted}\n\
         # HELP elara_delta_sync_failures_timeout_total pq_delta_sync calls that returned an error containing 'timed out' - the dominant operator-visible failure mode. Distinct from _other_total so timeout-vs-everything-else is plottable without label parsing. Steady non-zero rate against a single peer = handshake/transport saturation on that peer; spread across multiple peers = local PQ-client tuning issue (timeouts too tight for current network conditions).\n\
         # TYPE elara_delta_sync_failures_timeout_total counter\n\
         elara_delta_sync_failures_timeout_total {delta_sync_failures_timeout}\n\
         # HELP elara_delta_sync_failures_other_total pq_delta_sync failures whose error did NOT contain 'timed out'. This is the AGGREGATE; the four _other_addr / _other_dial / _other_rpc / _other_decode sub-buckets below discriminate it (they sum to <= this total, remainder uncategorized). High _other with _timeout flat = transport works but something past the timeout axis fails — read the sub-buckets to tell 'cannot reach peer' (addr/dial) from 'incompatible post-handshake wire' (rpc) from 'drifted response shape' (decode) WITHOUT per-follower WARN-log forensics.\n\
         # TYPE elara_delta_sync_failures_other_total counter\n\
         elara_delta_sync_failures_other_total {delta_sync_failures_other}\n\
         # HELP elara_delta_sync_failures_other_addr_total Sub-bucket of _other_total: 'cannot derive PQ peer addr' — the peer base_url could not be mapped to a PQ address. LOCAL config/URL problem (pq_port_offset, malformed seed URL); the pull never left this node.\n\
         # TYPE elara_delta_sync_failures_other_addr_total counter\n\
         elara_delta_sync_failures_other_addr_total {delta_sync_failures_other_addr}\n\
         # HELP elara_delta_sync_failures_other_dial_total Sub-bucket of _other_total: non-timeout failure at the dial+handshake stage (pq_dial). TCP connect refused / host unreachable, OR the PQ handshake was rejected (identity-pin mismatch, bad signature) — cannot reach or authenticate the peer. Non-zero here while the SERVER side shows elara_pq_handshake_failed_total flat = the dial never arrived (connectivity), not a handshake reject; a network-partitioned follower lands here.\n\
         # TYPE elara_delta_sync_failures_other_dial_total counter\n\
         elara_delta_sync_failures_other_dial_total {delta_sync_failures_other_dial}\n\
         # HELP elara_delta_sync_failures_other_rpc_total Sub-bucket of _other_total: non-timeout failure AFTER a completed handshake during RPC transport (rpc stage) — data-frame AEAD verification failure or peer-closed mid-call. THE SILENT-WIRE-BREAK SIGNATURE: handshake succeeds but the encrypted exchange fails because two binaries drifted on the data-frame AEAD-AD / framing without bumping a version field. Non-zero here with _dial flat = peers connect but speak an incompatible post-handshake wire; escalate as a protocol-compat regression.\n\
         # TYPE elara_delta_sync_failures_other_rpc_total counter\n\
         elara_delta_sync_failures_other_rpc_total {delta_sync_failures_other_rpc}\n\
         # HELP elara_delta_sync_failures_other_decode_total Sub-bucket of _other_total: the server answered but the response could not be decoded — 'unexpected delta_sync response format', 'bad hex', a 'parse:' error, or a non-2xx 'returned status'. Wire transport is healthy; the response SHAPE drifted (stale-binary protocol skew) or the server rejected at the application layer.\n\
         # TYPE elara_delta_sync_failures_other_decode_total counter\n\
         elara_delta_sync_failures_other_decode_total {delta_sync_failures_other_decode}\n\
         # HELP elara_seconds_since_last_successful_pull Seconds since this node last completed a SUCCESSFUL pull from any peer (gossip.rs::pull_loop Ok branch; a 0-record 'caught up' pull counts). 0 = never pulled this process — a fresh node before its first pull, OR a pure seed/authority that never pulls (delta_sync_attempts_total stays 0). For a follower this is the live desync detector: it climbs without bound when pulls fail (unreachable seed, wire-incompatible peer) EVEN WHILE record-age looks fine — the silent-desync class elara_delta_sync_failures_other_total only counts. Alert: a follower (attempts>0) with this > ~600s is stuck. Drives the /health 'pull-sync' check.\n\
         # TYPE elara_seconds_since_last_successful_pull gauge\n\
         elara_seconds_since_last_successful_pull {secs_since_last_pull}\n\
         # HELP elara_delta_sync_latency_lt_2s_total pq_delta_sync successes that completed in under 2 seconds — the healthy LAN/regional bucket. Buckets-as-counters give tail-latency visibility without a Histogram framework: sum of the three _lt_*_total buckets equals total successes (_attempts_total minus _failures_*_total). Per-bucket rate is graphable directly; ratios answer 'what fraction of successes are healthy?' (rate(_lt_2s) / rate(success)).\n\
         # TYPE elara_delta_sync_latency_lt_2s_total counter\n\
         elara_delta_sync_latency_lt_2s_total {delta_sync_lat_lt_2s}\n\
         # HELP elara_delta_sync_latency_lt_10s_total pq_delta_sync successes in [2s, 10s) — cross-region or moderately loaded peer; not yet near the 30 s DEFAULT_CALL_TIMEOUT. Sustained climb here while _lt_2s_total flattens = peers are slowing down before they start timing out.\n\
         # TYPE elara_delta_sync_latency_lt_10s_total counter\n\
         elara_delta_sync_latency_lt_10s_total {delta_sync_lat_lt_10s}\n\
         # HELP elara_delta_sync_latency_lt_30s_total pq_delta_sync successes in [10s, 30s) — the 'near-timeout' bucket. Leading-indicator surface that climbs BEFORE _failures_timeout_total starts incrementing. Sustained non-zero rate against a single peer = handshake saturation on that peer; spread across peers = local PqClient timeout (DEFAULT_CALL_TIMEOUT=30s) is too tight for current network conditions.\n\
         # TYPE elara_delta_sync_latency_lt_30s_total counter\n\
         elara_delta_sync_latency_lt_30s_total {delta_sync_lat_lt_30s}\n\
         # HELP elara_delta_sync_failures_timeout_handshake_total Subset of _failures_timeout_total where the timeout fired during the PQ handshake (pq_dial exceeded DEFAULT_CALL_TIMEOUT=30s). Distinguishes 'peer PQ port not responding' from 'peer accepted handshake but RPC stalled'. High handshake-timeout share = peer's :9573 listener saturated, dropped TCP, or PQ accept loop hung — investigate at peer's PQ server, not the verb dispatcher.\n\
         # TYPE elara_delta_sync_failures_timeout_handshake_total counter\n\
         elara_delta_sync_failures_timeout_handshake_total {delta_sync_to_handshake}\n\
         # HELP elara_delta_sync_failures_timeout_rpc_total Subset of _failures_timeout_total where the timeout fired during RPC dispatch (stream.call exceeded DEFAULT_CALL_TIMEOUT=30s) on a session with completed handshake. High RPC-timeout share = handshake works but verb processing on the remote stalls — slow query, lock contention, large delta payload — investigate at the verb handler, not the transport.\n\
         # TYPE elara_delta_sync_failures_timeout_rpc_total counter\n\
         elara_delta_sync_failures_timeout_rpc_total {delta_sync_to_rpc}\n\
         # HELP elara_delta_sync_scan_hit_cap_total Server-side counter - incremented every time handle_delta_sync hits MAX_SCAN=50000 timestamp-index entries. At the cap older records past the cap aren't bloom-tested in this round (safe failure mode: requester re-pulls or falls back to snapshot sync). Sustained non-zero on every dial = the requester's 24h since-floor is too wide for the chain's record-arrival rate; tighten the window or shard the request. Pairs with _failures_timeout_rpc_total - if rpc-timeouts drop AND scan_hit_cap stays low after the bounded scan rollout, the bound is doing its job.\n\
         # TYPE elara_delta_sync_scan_hit_cap_total counter\n\
         elara_delta_sync_scan_hit_cap_total {delta_sync_scan_hit_cap}\n\
         # HELP elara_delta_sync_cursor_pages_total Server-side - delta_sync pages served via the cross-page cursor path (x-delta-cursor present, both transports). Adoption signal for the 2026-07-05 cursor rollout; flat at 0 = no cursor-capable clients yet.\n\
         # TYPE elara_delta_sync_cursor_pages_total counter\n\
         elara_delta_sync_cursor_pages_total {ds_cursor_pages}\n\
         # HELP elara_delta_sync_cursor_reject_total Server-side - malformed x-delta-cursor values rejected fail-closed (400, never a silent fallback to offset paging). Non-zero = a buggy or hostile client.\n\
         # TYPE elara_delta_sync_cursor_reject_total counter\n\
         elara_delta_sync_cursor_reject_total {ds_cursor_reject}\n\
         # HELP elara_delta_sync_cursor_guard_trips_total Client-side - cursor cycles broken by the echo/advance guard (server echoed a different cursor than sent or failed to advance the frontier). Non-zero = a buggy or hostile server on the other end of a pull.\n\
         # TYPE elara_delta_sync_cursor_guard_trips_total counter\n\
         elara_delta_sync_cursor_guard_trips_total {ds_cursor_guard}\n\
         # HELP elara_delta_sync_cursor_cycle_exhausted_total Client-side - cursor cycles that hit MAX_PAGES_PER_CYCLE(64) with the server still reporting has_more=true. The cursor-path analog of scan_hit_cap: sustained growth = this node is persistently deeper behind a peer than one cycle can walk; snapshot sync is the right catch-up path.\n\
         # TYPE elara_delta_sync_cursor_cycle_exhausted_total counter\n\
         elara_delta_sync_cursor_cycle_exhausted_total {ds_cursor_exhausted}\n\
         # HELP elara_delta_sync_served_total Server-side counter - delta_sync requests this node SERVED to pullers, across BOTH the HTTP (routes/sync.rs::delta_sync) and PQ-transport (pq_transport/router.rs::handle_delta_sync) serve paths. Distinct from elara_delta_sync_attempts_total, which is the CLIENT-side count of pulls this node initiates. On a seed/anchor that followers pull from, this is the primary 'am I serving sync?' signal - previously untelemetered server-side (every other delta_sync_* counter is the puller's view). Non-zero and climbing = followers are actively pulling state from this node. Includes the low-RAM skip response (a valid served reply with 0 records).\n\
         # TYPE elara_delta_sync_served_total counter\n\
         elara_delta_sync_served_total {delta_sync_served}\n\
         # HELP elara_delta_sync_served_records_total Server-side counter - total records returned across all served delta_sync requests (sum of each response batch length). Serve-side throughput; divide by elara_delta_sync_served_total for mean records per served request. Flat while _served_total climbs = pullers are caught up (bloom-complete, nothing missing); both climbing = active catch-up traffic from a joining or lagging follower.\n\
         # TYPE elara_delta_sync_served_records_total counter\n\
         elara_delta_sync_served_records_total {delta_sync_served_records}\n\
         # HELP elara_witness_smt_scope_scan_hit_cap_total Witness-side counter - incremented when compute_witness_smt_scope hits MAX_WITNESS_SCOPE_SCAN=100000 zone-window index entries while building a seal's SMT-flush scope. At the cap late-window records are excluded from this round's flush, so the witness on-disk account-SMT root cannot match the seal's signed account_smt_root until a later seal re-covers them (safe: self-heals on the next covering seal). Mainnet signal: a single zone is carrying >100K records/epoch - split the zone or raise the cap. Distinct from _incomplete_total (scan truncated vs result partial); the two co-fire when the cap is what truncated the match.\n\
         # TYPE elara_witness_smt_scope_scan_hit_cap_total counter\n\
         elara_witness_smt_scope_scan_hit_cap_total {witness_scope_cap}\n\
         # HELP elara_witness_smt_scope_incomplete_total Witness-side counter - incremented when a seal's SMT-flush scope build matched fewer records than the seal references (the witness had not yet received every covered record), so the flushed scope is a strict subset and the on-disk root cannot match the sealed root this round. This is the common transient cause of account_smt_disk_root_matches_latest_seal=0 on a non-creator node: gossip propagation lag, not a fault. rate() gives the share of seals a witness flushed from an incomplete scope; pair with _scan_hit_cap_total - non-zero here with the cap counter flat = pure propagation lag (self-heals).\n\
         # TYPE elara_witness_smt_scope_incomplete_total counter\n\
         elara_witness_smt_scope_incomplete_total {witness_scope_incomplete}\n\
    ");

    // Tier-1 DAG-completeness deficit surface (internal design notes
    // §4): sealed epochs provably missing local records, and whether the
    // full_pull escalation is actually closing them.
    let dag_deficit_open = state
        .dag_deficit_open
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .len();
    let dag_deficit_epochs = state
        .dag_deficit_epochs_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let dag_deficit_resolved = state
        .dag_deficit_resolved_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let full_pull_zero_streak = state
        .full_pull_zero_progress_streak
        .load(std::sync::atomic::Ordering::Relaxed);
    let full_pull_zero_total = state
        .full_pull_zero_progress_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let declined_seal_cached = state
        .declined_seal_ids
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .len();
    let body = format!("{body}\
         # HELP elara_dag_deficit_open Open sealed-epoch completeness deficits - epochs whose seal record_hashes (committed on the wire) name records this node still lacks locally. Captured at seal ingest via the point lookups resolve_seal_record_ids already performs (no scan), re-checked one entry per pull cycle, bounded at 512. Non-zero forces full_pull every cycle (escalation) instead of the ~200-cycle backstop. Healthy steady-state = 0; non-zero and FLAT while elara_full_pull_zero_progress_streak climbs = the hole is not healing, see the /health dag_gap recovery recipe.\n\
         # TYPE elara_dag_deficit_open gauge\n\
         elara_dag_deficit_open {dag_deficit_open}\n\
         # HELP elara_dag_deficit_epochs_total Monotonic count of distinct (zone, epoch) completeness deficits ever opened. rate() gives how often this node ingests seals for records it does not hold - sustained growth on a caught-up node means propagation is losing records ahead of sealing.\n\
         # TYPE elara_dag_deficit_epochs_total counter\n\
         elara_dag_deficit_epochs_total {dag_deficit_epochs}\n\
         # HELP elara_dag_deficit_resolved_total Monotonic count of deficits closed by the per-cycle re-check - all named records arrived (pull escalation worked) or the seal itself was pruned below the super-seal floor (records unprovable AND unpullable by design, not a hole). Pair with _epochs_total: resolved tracking opened = self-healing works.\n\
         # TYPE elara_dag_deficit_resolved_total counter\n\
         elara_dag_deficit_resolved_total {dag_deficit_resolved}\n\
         # HELP elara_full_pull_zero_progress_streak Consecutive full_pull sweeps that found zero new records while sealed-epoch deficits stayed open (trend alarm, contract 4.2). Resets to 0 on any sweep that finds records. Climbing = the escalation machinery is running but the peers contacted cannot supply the missing records - the manual recovery recipe is warranted.\n\
         # TYPE elara_full_pull_zero_progress_streak gauge\n\
         elara_full_pull_zero_progress_streak {full_pull_zero_streak}\n\
         # HELP elara_full_pull_zero_progress_total Monotonic twin of elara_full_pull_zero_progress_streak for rate() alerting across streak resets.\n\
         # TYPE elara_full_pull_zero_progress_total counter\n\
         elara_full_pull_zero_progress_total {full_pull_zero_total}\n\
         # HELP elara_declined_seal_cache Stale epoch-seal record ids this node intentionally declined (catch-up pre-filter) now folded into the delta_pull bloom so peers stop re-serving them every pass. Bounded LRU (4096). Populated on catching-up nodes; empty on caught-up ones.\n\
         # TYPE elara_declined_seal_cache gauge\n\
         elara_declined_seal_cache {declined_seal_cached}\n\
    ");

    // Seal-window observability. Earlier work collapsed
    // peak heap on the seal hot path from O(N records) to O(N IDs) — claim
    // is ~962 MB → ~6 MB at 1M-record windows. That collapse is bounded by
    // MAX_SEAL_RECORDS=1M; if a zone exceeds it the seal scan caps and the
    // anchor signs a partial window (still safe, but means the zone needs
    // splitting per Gap 4 zone auto-scaling). These two surfaces let
    // operators see live distance-to-ceiling without an offline bench.
    let (seal_window_max, seal_window_cap_hits) = super::epoch::seal_window_metrics();
    let seal_enum_root_mismatch = super::epoch::seal_enum_root_mismatch_total();
    let (seal_enum_derived, seal_enum_derive_miss) = super::epoch::seal_enum_derive_metrics();
    // Snapshot-serve pressure observability.
    // /snapshot has two OOM-protection caps (accounts and applied
    // records); both fail with RateLimited above the cap. The
    // existing `snapshot_size_rejected_total` counter only fires AFTER
    // a cap is tripped — operators couldn't see distance-to-cap
    // progression. These gauges sample both dimensions BEFORE either
    // cap check so we capture the request that tripped the gate too.
    let (snapshot_accounts_max, snapshot_applied_max) =
        super::routes::sync::snapshot_serve_pressure_metrics();
    let body = format!("{body}\
         # HELP elara_seal_window_records_observed_max High-water mark of records scanned in any seal-create or seal-verify zone-window scan since process start. Trends toward MAX_SEAL_RECORDS=1M as a zone gets hot; pair with elara_seal_window_cap_hits_total to detect ceiling pressure. Use this gauge to size the heap budget (O(IDs), ~6 MB at 1M IDs / 6 bytes each); if the value approaches 750K and stays there, plan zone-split before the cap clamps the seal.\n\
         # TYPE elara_seal_window_records_observed_max gauge\n\
         elara_seal_window_records_observed_max {seal_window_max}\n\
         # HELP elara_seal_window_cap_hits_total Counter — incremented every time a seal-create, seal-verify, or witness-verify zone-window scan returns ids.len() >= MAX_SEAL_RECORDS=1M. At the cap the seal commits to a partial window (deterministic across the fleet because every node uses the same cap), but the anchor's chosen end-timestamp now excludes records beyond the 1M cutoff — those records will appear in the NEXT seal. Sustained non-zero rate = a single zone exceeds 1M records per epoch interval (current default 5s floor → 200 K rec/s sustained), which is past the per-zone scaling envelope. Mitigation: zone-split or shorten the adaptive epoch interval floor.\n\
         # TYPE elara_seal_window_cap_hits_total counter\n\
         elara_seal_window_cap_hits_total {seal_window_cap_hits}\n\
         # HELP elara_seal_enum_root_mismatch_total Counter — seals whose inline epoch_record_hashes enumeration failed the parse-time root gate (recomputed Merkle root != signed epoch_merkle_root) and was dropped to empty (R3-8). The seal itself is still accepted; consumers fall back to their legacy-empty behavior. Non-zero means a producer emitted an enumeration inconsistent with its own signed root — a producer-side bug or a malicious anchor (R3-9). Healthy = 0.\n\
         # TYPE elara_seal_enum_root_mismatch_total counter\n\
         elara_seal_enum_root_mismatch_total {seal_enum_root_mismatch}\n\
         # HELP elara_seal_enum_derived_total Counter — seals whose absent/dropped inline epoch_record_hashes enumeration was re-derived from the local zone+window and matched the signed merkle_root (R3-8 derive-when-absent). At mainnet rates (>SEAL_INLINE_ENUM_MAX=96 rec/epoch) this is the COMMON path for hot zones; at testnet rates it stays 0 unless ELARA_SEAL_INLINE_ENUM_MAX is lowered for a soak.\n\
         # TYPE elara_seal_enum_derived_total counter\n\
         elara_seal_enum_derived_total {seal_enum_derived}\n\
         # HELP elara_seal_enum_derive_miss_total Counter — derive attempts whose recomputed window root did NOT match the signed merkle_root: the local DAG is incomplete for that seal window (propagation lag, catch-up) or the producer diverged. Consumers fall back to legacy-empty and self-heal via full_pull; a sustained climb alongside dag-deficit growth means records are not arriving.\n\
         # TYPE elara_seal_enum_derive_miss_total counter\n\
         elara_seal_enum_derive_miss_total {seal_enum_derive_miss}\n\
         # HELP elara_snapshot_serve_accounts_observed_max High-water mark of `ledger.accounts.len()` sampled at /snapshot calls since process start. Pairs with MAX_SNAPSHOT_FULL_ACCOUNTS=100000. At ~80K accounts plan to switch bootstrappers to /snapshot/state-delta with an archive baseline; once the gauge hits 100K the next /snapshot dial returns RateLimited and the cap counter (`elara_snapshot_size_rejected_total`) climbs. Distance-to-cap signal lets operators migrate before peers see rejections instead of after.\n\
         # TYPE elara_snapshot_serve_accounts_observed_max gauge\n\
         elara_snapshot_serve_accounts_observed_max {snapshot_accounts_max}\n\
         # HELP elara_snapshot_serve_applied_observed_max High-water mark of `approximate_cf_size(CF_APPLIED)` sampled at /snapshot calls since process start. Pairs with MAX_SNAPSHOT_APPLIED_RECORDS=1000000. The applied-records dimension is OOM-driven by collect_applied_ids HashSet (~64 B per id × 1M = ~64 MB), independent of accounts.len() — a chain can sit comfortably under MAX_SNAPSHOT_FULL_ACCOUNTS and still trip this cap. Same migration signal as accounts: when this gauge approaches 800K, plan archive-baselined incremental sync.\n\
         # TYPE elara_snapshot_serve_applied_observed_max gauge\n\
         elara_snapshot_serve_applied_observed_max {snapshot_applied_max}\n\
    ");

    // state_core watchdog observability. The watchdog
    // already logs at 30s/60s thresholds when an inserted record's inner
    // call (storage spawn_blocking, dag.write, ledger.write) blocks past
    // the deadline, but those logs were operator-grep-only — there was no
    // Prometheus signal for stuck-record incidents. A node was observed
    // processing a single record for 415 seconds (~14× the watchdog
    // threshold) with no metric trail. These three surfaces
    // close that gap: two counters track watchdog firings (30s = warned,
    // 60s = confirmed deadlock), and a high-water-mark gauge captures the
    // worst observed elapsed-ms across all records (also catches slow
    // records under the 30s threshold but still pathological at 1M zones
    // × 10T records/day target).
    let (sc_wd30, sc_wd60, sc_max_ms) = super::state_core::state_core_watchdog_metrics();
    let body = format!("{body}\
         # HELP elara_state_core_watchdog_30s_total Counter — incremented when a state_core insert-record call has not completed 30 seconds after the worker started processing it. Each increment corresponds to a `STATE_CORE WATCHDOG: record X stuck for 30s` ERROR log. The 30s threshold is the worker-pool freshness budget — past it, ingest throughput is structurally degraded (one stuck record blocks all records routed to the same worker via zone-hash). Sustained rate > 0 = at least one zone is hitting a storage-write or lock-contention pathology; pair with `elara_ingest_slow_records_*_total` (split by sub-phase) to localize the cause.\n\
         # TYPE elara_state_core_watchdog_30s_total counter\n\
         elara_state_core_watchdog_30s_total {sc_wd30}\n\
         # HELP elara_state_core_watchdog_60s_total Counter — incremented when the same insert-record call still has not completed 30 seconds after the 30s warning fired (total 60s+ stuck). Each increment corresponds to `STATE_CORE WATCHDOG: record X stuck for 60s — confirmed deadlock` ERROR log. _60s_total is always <= _30s_total because the 60s timer is the second sleep in the same spawned task. Non-zero rate = real deadlock or pathological synchronous I/O blocking the worker; this is the primary alerting signal for ingest-pipeline incidents.\n\
         # TYPE elara_state_core_watchdog_60s_total counter\n\
         elara_state_core_watchdog_60s_total {sc_wd60}\n\
         # HELP elara_state_core_record_processing_max_ms High-water mark (milliseconds) of any single record's elapsed time through the state_core InsertRecord arm since boot. Captures BOTH the success and failure paths (rejected records still count toward pipeline pressure). Independent of the watchdog counters — the max gauge tracks the worst observed even when the record completes before 30s. Steady rise without watchdog firings = the pipeline is degrading silently; a single jump to >30000 ms followed by `_watchdog_30s_total` increment = same incident captured both ways. Reset only on process restart.\n\
         # TYPE elara_state_core_record_processing_max_ms gauge\n\
         elara_state_core_record_processing_max_ms {sc_max_ms}\n\
    ");

    // state_core worker queue depth observability.
    // Compounds with the watchdog + per-phase latency gauges — those tell you
    // a record is stuck and which sub-phase owns the time, but neither answers
    // "is the worker queue backing up?" If a single zone-hash routes 100 rec/s
    // into a worker that takes 78s on one record, the channels fill (both
    // bounded at 1024) and clients hit InsertRecord backpressure. Sampled in
    // insert_record() before each enqueue; tracks the high-water mark across
    // all workers. Healthy fleet baseline: 0 (sub-second processing keeps
    // queues empty). >50 = at least one worker is falling behind its zone's
    // record rate.
    let (sc_q_normal, sc_q_priority) = super::state_core::state_core_worker_queue_metrics();
    let (sc_q_normal_atcap, sc_q_priority_atcap) = super::state_core::state_core_worker_at_capacity_metrics();
    let body = format!("{body}\
         # HELP elara_state_core_worker_normal_queue_depth_max High-water mark of pending records in the normal-priority worker mpsc channel since boot. Sampled at every insert_record() enqueue as `CHANNEL_SIZE - tx.capacity()`. Channel is bounded at 1024 (carries Sync + GossipPull bulk traffic); >100 = a worker's zone-hash is falling behind its record rate; >900 = clients within ~10% of InsertRecord backpressure. Pair with `elara_state_core_watchdog_30s_total` - queue depth climbing alongside watchdog firings means the head-of-line record is stuck AND the queue is filling behind it. Reset only on process restart.\n\
         # TYPE elara_state_core_worker_normal_queue_depth_max gauge\n\
         elara_state_core_worker_normal_queue_depth_max {sc_q_normal}\n\
         # HELP elara_state_core_worker_priority_queue_depth_max High-water mark of pending records in the priority worker mpsc channel since boot. Channel is bounded at 1024 (grown from 64 after the channel resize to match normal because GossipPush is routed here, making priority the dominant live-traffic path on genesis-authority nodes). >100 = priority traffic spiking; >900 = priority backpressure imminent; investigate witness-committee routing or gossip-fanout volume.\n\
         # TYPE elara_state_core_worker_priority_queue_depth_max gauge\n\
         elara_state_core_worker_priority_queue_depth_max {sc_q_priority}\n\
         # HELP elara_state_core_worker_normal_at_capacity_total Counter — incremented every time the normal worker channel is observed at >= cap (1024). Distinguishes boot-burst saturation (max gauge pegged at 1024 forever, counter increments once at boot) from sustained backpressure (max pegged AND counter climbing under steady load). A non-zero value with `rate() == 0` post-boot is healthy. A climbing rate is a real bottleneck — either grow CHANNEL_SIZE or shed load.\n\
         # TYPE elara_state_core_worker_normal_at_capacity_total counter\n\
         elara_state_core_worker_normal_at_capacity_total {sc_q_normal_atcap}\n\
         # HELP elara_state_core_worker_priority_at_capacity_total Counter for the priority channel (cap=1024 after the channel resize). Steady non-zero rate post-boot = priority traffic exceeds the channel's drain rate; investigate gossip-fanout volume, witness-committee routing, or per-zone worker-pool throughput.\n\
         # TYPE elara_state_core_worker_priority_at_capacity_total counter\n\
         elara_state_core_worker_priority_at_capacity_total {sc_q_priority_atcap}\n\
    ");

    // Governance + abuse rejection counters. All bump in ingest.rs at the
    // canonical accept/reject gate. Surfaced on JSON /admin and /explorer
    // routes but were missing from /metrics — operators couldn't see abuse
    // pressure or governance activity rate from Prometheus.
    let banned_rejections = state.banned_rejections_total.load(std::sync::atomic::Ordering::Relaxed);
    let content_rejections = state.content_rejections_total.load(std::sync::atomic::Ordering::Relaxed);
    let revocations_rejected = state.revocations_rejected_total.load(std::sync::atomic::Ordering::Relaxed);
    let disputes_opened = state.disputes_opened_total.load(std::sync::atomic::Ordering::Relaxed);
    let challenges_filed = state.challenges_filed_total.load(std::sync::atomic::Ordering::Relaxed);
    // Pair the existing _total counters with current
    // resident depth gauges. Without these, operators can see "disputes
    // opening" / "challenges filed" rates but can't tell whether they are
    // also resolving — flat _active gauges + climbing _total = healthy
    // open/close churn; both climbing together = stuck disputes /
    // jury-stalled challenges. Bounded reads under brief read-locks; both
    // helpers are O(stored) per scrape with no allocation.
    let (disputes_active, fisherman_open, fisherman_open_epoch) = {
        use super::RwLockRecover;
        let d = state.disputes.read_recover();
        let c = state.challenges.read_recover();
        let ec = state.epoch_challenges.read_recover();
        (d.dispute_count() as u64, c.open_count() as u64, ec.open_count() as u64)
    };
    let body = format!("{body}\
         # HELP elara_banned_rejections_total Records rejected at ingest because the creator identity is on the banned list. Sustained non-zero rate means a banned identity is still attempting to publish — peer hasn't propagated the ban OR the attacker is rotating creator IDs. Compare cluster sum against the on-disk ban list to size the per-ban rejection cost.\n\
         # TYPE elara_banned_rejections_total counter\n\
         elara_banned_rejections_total {banned_rejections}\n\
         # HELP elara_content_rejections_total Records rejected at ingest because text-field content matched the local content_blocklist. Operator signal: rate ≈ inbound spam pressure. Each node maintains its own blocklist, so cluster sum can diverge — divergence itself is an operational signal (a node missing recent blocklist updates).\n\
         # TYPE elara_content_rejections_total counter\n\
         elara_content_rejections_total {content_rejections}\n\
         # HELP elara_revocations_rejected_total Records rejected because the signing key has been revoked. Steady non-zero means a revoked key is still in use — either lagging key-revocation propagation across the fleet or an active compromised-key replay attempt.\n\
         # TYPE elara_revocations_rejected_total counter\n\
         elara_revocations_rejected_total {revocations_rejected}\n\
         # HELP elara_disputes_opened_total Disputes opened at ingest. Climbs when a record asserts a conflict with prior state. Rate is the fleet-wide governance activity baseline; sudden spikes pair with conflict_proof_received_total to triangulate equivocation events.\n\
         # TYPE elara_disputes_opened_total counter\n\
         elara_disputes_opened_total {disputes_opened}\n\
         # HELP elara_challenges_filed_total Fisherman challenges filed (the economics spec). One increment per challenge record accepted at ingest. Rate matters more than absolute level — sustained climb indicates active fisherman participation; flat = fisherman role is dormant.\n\
         # TYPE elara_challenges_filed_total counter\n\
         elara_challenges_filed_total {challenges_filed}\n\
         # HELP elara_disputes_active Count of currently-tracked disputes in DisputeState. Pair with elara_disputes_opened_total: flat gauge while opened_total climbs = disputes opening AND closing at equal rate (healthy resolution); both climbing together = disputes accumulating (resolution pipeline stalled — investigate via /disputes endpoint). Bounded by DisputeState's prune policy.\n\
         # TYPE elara_disputes_active gauge\n\
         elara_disputes_active {disputes_active}\n\
         # HELP elara_fisherman_open_challenges Count of fisherman challenges in non-Final/non-Dismissed status (filed → JuryVoting → Verdict → Appeal pipeline; everything before Final or Dismissed terminal states). Pair with elara_challenges_filed_total: flat gauge while filed_total climbs = jury voting + appeal windows are completing on schedule; both climbing together = jury-vote stall (insufficient quorum) OR appeal-window not closing (`finalize_if_expired` not running). Operator alarm on sustained growth.\n\
         # TYPE elara_fisherman_open_challenges gauge\n\
         elara_fisherman_open_challenges {fisherman_open}\n\
         # HELP elara_fisherman_open_epoch_challenges Count of EpochChallenges (internal design notes differentiated-penalty layer) with no verdict yet. Filed-but-unresolved epoch challenges that should drain through jury voting. Sustained non-zero past the jury vote window = juror set unavailable OR verdict-write path broken. Distinct signal from regular fisherman challenges (record-level) — this gauge tracks the epoch-level Merkle-tree challenge layer that slashes anchor + attesting witnesses.\n\
         # TYPE elara_fisherman_open_epoch_challenges gauge\n\
         elara_fisherman_open_epoch_challenges {fisherman_open_epoch}\n\
    ");

    // Gap 6 RTT estimator cadence + search query rate. The RTT counters
    // bump in observe_zone_rtt / observe_peer_rtt (state.rs:1932/1946) every
    // time the gossip stack records a measured push/pull round-trip. They
    // feed the geographic-fraud detector (Protocol §11.12, MESH-BFT §5).
    // Flat counter while gossip is flowing = the RTT observation hook is
    // not firing — geo-fraud detection blind. search_queries bumps in
    // routes/core.rs at the search dispatch site.
    let zone_rtt_samples = state.zone_rtt_samples_total.load(std::sync::atomic::Ordering::Relaxed);
    let peer_rtt_samples = state.peer_rtt_samples_total.load(std::sync::atomic::Ordering::Relaxed);

    // Pair the existing _samples_total counters
    // (gossip RTT events) with the resident-depth gauges (distinct
    // zones / peers currently tracked). Without these, operators see
    // the *rate* of RTT samples but cannot tell whether the working
    // set is stable or churning under LRU pressure. Bounded reads
    // under brief read-locks; both helpers are O(1) (HashMap::len).
    //
    // Operator dashboard rules:
    //   gauge == 0 AND samples_total > 0  =>  LRU eviction wave
    //     wiped the working set (peer/zone churn faster than retention).
    //   gauge climbing toward MAX  =>  estimator near cap; the geo-
    //     fraud detector starts dropping the least-recently-active
    //     peers/zones from its diversity-score input.
    //   gauge stable + samples_total climbing  =>  healthy steady state.
    let (zone_rtt_zones_tracked, peer_rtt_peers_tracked) = {
        use super::RwLockRecover;
        let zr = state.zone_rtt.read_recover();
        let pr = state.peer_rtt.read_recover();
        (zr.zone_count() as u64, pr.peer_count() as u64)
    };
    let search_queries = state.search_queries_total.load(std::sync::atomic::Ordering::Relaxed);
    let search_queries_layer_b = state.search_queries_layer_b_total.load(std::sync::atomic::Ordering::Relaxed);
    let search_queries_fallback = state.search_queries_fallback_total.load(std::sync::atomic::Ordering::Relaxed);
    let by_hash_hits = state.records_by_hash_hits_total.load(std::sync::atomic::Ordering::Relaxed);
    let by_hash_misses = state.records_by_hash_misses_total.load(std::sync::atomic::Ordering::Relaxed);
    let by_hash_relay_attempts = state.records_by_hash_peer_relay_attempts_total.load(std::sync::atomic::Ordering::Relaxed);
    let by_hash_relay_hits = state.records_by_hash_peer_relay_hits_total.load(std::sync::atomic::Ordering::Relaxed);
    let by_hash_relay_misses = state.records_by_hash_peer_relay_misses_total.load(std::sync::atomic::Ordering::Relaxed);
    let seal_rec_resolved = state.seal_record_hashes_resolved_total.load(std::sync::atomic::Ordering::Relaxed);
    let seal_rec_missing = state.seal_record_hashes_missing_total.load(std::sync::atomic::Ordering::Relaxed);
    let body = format!("{body}\
         # HELP elara_zone_rtt_samples_total Per-zone gossip RTT samples observed. One increment per push/pull round-trip recorded against a zone. Bounded estimator: 64 samples/zone × MAX_ZONES=256. Flat counter while gossip is flowing = the RTT observation hook is silent — zone-rtt-based diversity scoring degrades.\n\
         # TYPE elara_zone_rtt_samples_total counter\n\
         elara_zone_rtt_samples_total {zone_rtt_samples}\n\
         # HELP elara_peer_rtt_samples_total Per-peer gossip RTT samples observed. Feeds the Stage-5 geographic-fraud detector — without samples, geo-fraud scan_witness_set has no data. Compare ratio peer_rtt_samples / zone_rtt_samples ≈ active-peer / active-zone fanout; sudden drop indicates push/pull RTT instrumentation broke.\n\
         # TYPE elara_peer_rtt_samples_total counter\n\
         elara_peer_rtt_samples_total {peer_rtt_samples}\n\
         # HELP elara_zone_rtt_zones_tracked Distinct zones currently held in the per-zone RTT estimator (≤ MAX_ZONES=256). Pair with elara_zone_rtt_samples_total: gauge=0 AND samples_total>0 = LRU eviction wave wiped the working set; gauge climbing toward 256 = estimator at cap, diversity-score input drops the least-recently-active zones; stable gauge + climbing samples = healthy steady state.\n\
         # TYPE elara_zone_rtt_zones_tracked gauge\n\
         elara_zone_rtt_zones_tracked {zone_rtt_zones_tracked}\n\
         # HELP elara_peer_rtt_peers_tracked Distinct peers currently held in the per-peer RTT estimator (≤ MAX_PEERS=10000, mainnet 10K-node target). Pair with elara_peer_rtt_samples_total: gauge=0 AND samples_total>0 = LRU eviction wave wiped working set; gauge climbing toward MAX_PEERS = geo-fraud detector starts losing visibility on least-recently-active peers; stable gauge + climbing samples = healthy steady state.\n\
         # TYPE elara_peer_rtt_peers_tracked gauge\n\
         elara_peer_rtt_peers_tracked {peer_rtt_peers_tracked}\n\
         # HELP elara_search_queries_total Search queries served by this node. One increment per /search dispatch. Rate is the search-tier load signal; pair with cache-hit metrics in the search subsystem to size capacity.\n\
         # TYPE elara_search_queries_total counter\n\
         elara_search_queries_total {search_queries}\n\
         # HELP elara_search_queries_layer_b_total Search queries served by the Layer B creator-keyed indexed path. Each /records/search?creator=… request increments here — O(records_for_creator_in_window), independent of fleet size. High ratio vs fallback means callers use the indexed path.\n\
         # TYPE elara_search_queries_layer_b_total counter\n\
         elara_search_queries_layer_b_total {search_queries_layer_b}\n\
         # HELP elara_search_queries_fallback_total Search queries served by the timestamp-window fallback. Hit when no creator filter is supplied — scales worse than Layer B at fleet scale. Sustained high rate vs layer_b is a signal that accounts/clients aren't passing creator hashes.\n\
         # TYPE elara_search_queries_fallback_total counter\n\
         elara_search_queries_fallback_total {search_queries_fallback}\n\
         # HELP elara_records_by_hash_hits_total /records/by-hash/{{content_hash}} resolved from the local CF_IDX_HASH. One increment per hit. O(1) RocksDB point read — independent of fleet size or zone count.\n\
         # TYPE elara_records_by_hash_hits_total counter\n\
         elara_records_by_hash_hits_total {by_hash_hits}\n\
         # HELP elara_records_by_hash_misses_total /records/by-hash/{{content_hash}} returned 404 (no record matches the hash on this node). Sustained high miss rate is the operator signal that peer-relay would actually do useful work.\n\
         # TYPE elara_records_by_hash_misses_total counter\n\
         elara_records_by_hash_misses_total {by_hash_misses}\n\
         # HELP elara_records_by_hash_peer_relay_attempts_total Caller opted into peer-relay (`?relay=1`) after a local miss. Sum with elara_records_by_hash_misses_total to get the relay-tier participation rate. One increment per entry into the fetcher, regardless of outcome.\n\
         # TYPE elara_records_by_hash_peer_relay_attempts_total counter\n\
         elara_records_by_hash_peer_relay_attempts_total {by_hash_relay_attempts}\n\
         # HELP elara_records_by_hash_peer_relay_hits_total Some peer in the fan-out returned the record body. Effective Layer A hit-rate seen by callers = (by_hash_hits_total + by_hash_peer_relay_hits_total) / total-lookups.\n\
         # TYPE elara_records_by_hash_peer_relay_hits_total counter\n\
         elara_records_by_hash_peer_relay_hits_total {by_hash_relay_hits}\n\
         # HELP elara_records_by_hash_peer_relay_misses_total Every queried peer answered \"no\" or was unreachable. Sustained non-zero growth means the record genuinely doesn't exist in the connected mesh — likely an archive-node coverage gap, not an index health problem.\n\
         # TYPE elara_records_by_hash_peer_relay_misses_total counter\n\
         elara_records_by_hash_peer_relay_misses_total {by_hash_relay_misses}\n\
         # HELP elara_seal_record_hashes_resolved_total Seal-record-hash resolutions that hit CF_IDX_HASH on this node. One increment per record_hash inside seal.record_hashes that maps to a local record_id. Pair with missing_total: at fleet scale resolved/(resolved+missing) ≈ 1.0 once the v5→v6 CF_IDX_HASH key-format migration has rebuilt the index. Doubles as the regression alarm for the pre-v6 double-hash key bug — flat resolved counter under live seal traffic = bug returned.\n\
         # TYPE elara_seal_record_hashes_resolved_total counter\n\
         elara_seal_record_hashes_resolved_total {seal_rec_resolved}\n\
         # HELP elara_seal_record_hashes_missing_total Seal-record-hash resolutions that missed CF_IDX_HASH locally. Expected to be near zero post-migration; sustained non-zero rate post-cold-join is normal until gossip backfill catches up. Sustained non-zero rate under steady state means the local node is receiving seals for records that haven't replicated to it yet — orthogonal to consensus correctness, but operators should investigate gossip lag.\n\
         # TYPE elara_seal_record_hashes_missing_total counter\n\
         elara_seal_record_hashes_missing_total {seal_rec_missing}\n\
    ");

    // Stage 6 cooperative scheduler — system_load gauges + sample counter.
    // Surfaced on /core JSON since launch but absent from /metrics, so
    // capacity dashboards couldn't see the cooperative-yield signal that
    // gossip + state_core hot-path callers consult via is_busy(). The 5-sec
    // sample cadence makes these effectively live-read; samples_total is the
    // health proxy — flat counter on a node with elapsed uptime means the
    // background refresh task died and is_busy() is returning stale data.
    let sl_cores = state.system_load.cores();
    let sl_load_1m = state.system_load.load_1m();
    let sl_normalized = state.system_load.normalized_load();
    let sl_cpu_fraction = state.system_load.cpu_fraction();
    let sl_samples_total = state.system_load.samples_total();
    let body = format!("{body}\
         # HELP elara_system_load_cores Host CPU core count observed at startup. Used by consumers to interpret normalized_load and to size cooperative yield thresholds. Static after process start.\n\
         # TYPE elara_system_load_cores gauge\n\
         elara_system_load_cores {sl_cores}\n\
         # HELP elara_system_load_1m Raw 1-minute kernel load average from /proc/loadavg. Not normalized — for that see elara_system_load_normalized. Compare across nodes only after dividing by elara_system_load_cores.\n\
         # TYPE elara_system_load_1m gauge\n\
         elara_system_load_1m {sl_load_1m:.4}\n\
         # HELP elara_system_load_normalized 1-minute load divided by core count. NORMALIZED_BUSY_LOAD=0.8 is the cooperative-yield threshold; sustained >= 0.8 means runqueue averaged 80%+ of a core/CPU and node is yielding hot-path work to stay app-grade. Comparable across hosts of different core counts.\n\
         # TYPE elara_system_load_normalized gauge\n\
         elara_system_load_normalized {sl_normalized:.4}\n\
         # HELP elara_system_load_cpu_fraction Whole-host CPU fraction over the most recent 5-second sample (delta of /proc/stat cpu counters). 0.0 = idle, 1.0 = single core saturated, N = N cores saturated. CPU_BUSY_FRACTION=0.75 is the burst-detect threshold the 1-minute load smooths away.\n\
         # TYPE elara_system_load_cpu_fraction gauge\n\
         elara_system_load_cpu_fraction {sl_cpu_fraction:.4}\n\
         # HELP elara_system_load_samples_total Monotonic count of /proc/stat samples taken since startup at SAMPLE_INTERVAL=5s cadence. Health proxy for the cooperative-scheduler background refresh task — flat counter on a node with non-zero uptime means refresh died and the load signals are stale (is_busy() returns ghost data).\n\
         # TYPE elara_system_load_samples_total counter\n\
         elara_system_load_samples_total {sl_samples_total}\n\
    ");

    // Rate-limiter denied + total checks. `rejected_total` (429) is already
    // exported via the legacy positional formatter; `denied_total` (deny-list
    // 403s) and `total` (all check() calls — proxy for inbound RPC throughput
    // before per-bucket math) were wired but never surfaced. Both are nil on
    // a node without rate limiting configured, so OptionLock unwrap_or(0) is
    // safe. Sustained non-zero `denied_total` means an operator-managed deny
    // entry is actively blocking traffic; `checks_total` lets dashboards
    // distinguish "limiter quiet because no traffic" from "limiter quiet
    // because middleware not wired".
    let (rl_denied, rl_checks) = state.rate_limiter.get()
        .map(|rl| (
            rl.denied_total.load(std::sync::atomic::Ordering::Relaxed),
            rl.total.load(std::sync::atomic::Ordering::Relaxed),
        ))
        .unwrap_or((0, 0));
    let body = format!("{body}\
         # HELP elara_rate_limit_denied_total Requests rejected with HTTP 403 because the source IP is on the rate-limiter deny list. Distinct from elara_rate_limit_rejected_total (429 token-bucket exhaustion). Sustained non-zero confirms an operator-managed ban is actively absorbing traffic — useful when paired with audit logs to size abusive-peer impact.\n\
         # TYPE elara_rate_limit_denied_total counter\n\
         elara_rate_limit_denied_total {rl_denied}\n\
         # HELP elara_rate_limit_checks_total Total RateLimiter::check() invocations since startup. Counts every request that passed through rate_limit_middleware regardless of outcome (allow / 429 / 403). Throughput proxy for the public RPC surface; flat on a node with no inbound HTTP traffic, monotonic otherwise. Difference vs. (rejected + denied) gives allowed-request count.\n\
         # TYPE elara_rate_limit_checks_total counter\n\
         elara_rate_limit_checks_total {rl_checks}\n\
    ");

    // Consensus memory budget gauge — sum of in-flight entries across all
    // consensus maps (attestations + confirmations + anchored + seal_*
    // bookkeeping + creator_stakes + cross_zone_parents + profiles). Used
    // for memory-budget monitoring per consensus.rs:memory_entry_count
    // documentation. Distinct from elara_consensus_records_tracked
    // (attestations only) — this counts every keyed entry in every map,
    // so it grows as seal-attestation history accumulates even when the
    // active record window stays bounded. Sustained climb signals retention
    // sweep hasn't been pruning seal_* maps; pair with /memory or the
    // memory_detail RPC for per-map breakdown.
    let consensus_memory_entries = {
        let c = state.consensus.lock_recover();
        c.memory_entry_count() as u64
    };
    let body = format!("{body}\
         # HELP elara_consensus_memory_entries Total in-memory entries across every consensus bookkeeping map (attestations, confirmations, anchored, seal_attestations, seal_record_ids, record_to_seal, seal_finalized_at, seal_registered_at, seal_first_attested_at, creator_stakes, cross_zone_parents, profiles). Memory-budget gauge — should plateau at O(retention_window × active_zones); sustained climb means retention sweep is not pruning seal_* bookkeeping. Distinct from elara_consensus_records_tracked which counts only the attestation map.\n\
         # TYPE elara_consensus_memory_entries gauge\n\
         elara_consensus_memory_entries {consensus_memory_entries}\n\
    ");

    // Tier 3.4 Slice 1 — Epoch-based pruning shadow metric
    // (NETWORK-HARDENING-ROADMAP §3.4 / Protocol §11.8). Observation only —
    // counts how many already-sealed records are currently far enough behind
    // their zone's latest epoch (>= EPOCH_PRUNE_SHADOW_HORIZON) that they would
    // be reclaimable under epoch-based pruning. Lets operators size the policy
    // before flipping it to actual pruning. Zero on a fresh testnet zone is
    // expected — only fires once a zone has produced > horizon epochs.
    let (epoch_prune_shadow_eligible, seal_epoch_indexed_seals) = {
        let zone_epochs: HashMap<super::zone::ZoneId, u64> = {
            let epoch = state.epoch.read_recover();
            epoch.latest_epoch.clone()
        };
        let c = state.consensus.lock_recover();
        let eligible = c.count_epoch_prune_shadow_eligible(
            crate::network::consensus::AWCConsensus::EPOCH_PRUNE_SHADOW_HORIZON,
            &zone_epochs,
        );
        let indexed = c.seal_epoch_indexed_count() as u64;
        (eligible, indexed)
    };
    let epoch_prune_shadow_horizon = crate::network::consensus::AWCConsensus::EPOCH_PRUNE_SHADOW_HORIZON;
    let body = format!("{body}\
         # HELP elara_epoch_prune_shadow_eligible_records Observation-only count of already-sealed records that would be reclaimable under epoch-based pruning today (seal must be settled AND its zone's current epoch must be at least EPOCH_PRUNE_SHADOW_HORIZON ahead of the seal's epoch). Used to size the eventual prune policy before activating it. Zero is expected on fresh zones - only fires once a zone has produced > horizon epochs.\n\
         # TYPE elara_epoch_prune_shadow_eligible_records gauge\n\
         elara_epoch_prune_shadow_eligible_records {epoch_prune_shadow_eligible}\n\
         # HELP elara_epoch_prune_shadow_horizon Constant — minimum epoch lag (current_zone_epoch - seal_epoch) for a sealed record to be considered shadow-eligible. Pairs with elara_epoch_prune_shadow_eligible_records.\n\
         # TYPE elara_epoch_prune_shadow_horizon gauge\n\
         elara_epoch_prune_shadow_horizon {epoch_prune_shadow_horizon}\n\
         # HELP elara_seal_epoch_indexed_seals Number of seals currently registered in the seal_epoch index (denominator for the shadow metric — gives operators a quick sanity check on how much of the in-memory seal set is sized for this metric).\n\
         # TYPE elara_seal_epoch_indexed_seals gauge\n\
         elara_seal_epoch_indexed_seals {seal_epoch_indexed_seals}\n\
    ");

    // Push-side delivery-failure counters across all four PQ-gossip push
    // paths (attestation, finality-witness, xzone-abort-witness, conflict-
    // proof). Previously these were tracked only in function-scope
    // `static AtomicU64` log-throttle counters inside gossip.rs, so the
    // operator could see the warn lines but had no scrape-able totals to
    // alert on. Each path emits three buckets:
    //   * addr_fail — peer base_url could not be mapped to a PQ address
    //     (peer-table issue, e.g. PQ_PORT_OFFSET mismatch or stale entry).
    //   * peer_reject — PQ peer returned a non-2xx, non-429 status (peer-
    //     side rejection — protocol-version drift, malformed body the peer
    //     rejects, etc).
    //   * net_fail — PQ transport returned `Err` (network failure, serde
    //     error, peer unreachable).
    // Distinct from the existing `*_pushed_total` / `*_attempted_total`
    // (initiation gauges) and the receiver-side `*_received_total` /
    // `*_rejected_total` (PEER PERSPECTIVE). Sustained non-zero on any of
    // these is the operator signal that gossip is draining without
    // landing — not detectable from initiation counters alone.
    let att_push_addr_fail   = state.attestation_push_addr_fail_total.load(std::sync::atomic::Ordering::Relaxed);
    let att_push_peer_reject = state.attestation_push_peer_reject_total.load(std::sync::atomic::Ordering::Relaxed);
    let att_push_net_fail    = state.attestation_push_net_fail_total.load(std::sync::atomic::Ordering::Relaxed);
    let fw_push_addr_fail    = state.finality_witness_push_addr_fail_total.load(std::sync::atomic::Ordering::Relaxed);
    let fw_push_peer_reject  = state.finality_witness_push_peer_reject_total.load(std::sync::atomic::Ordering::Relaxed);
    let fw_push_net_fail     = state.finality_witness_push_net_fail_total.load(std::sync::atomic::Ordering::Relaxed);
    let xa_push_addr_fail    = state.xzone_abort_witness_push_addr_fail_total.load(std::sync::atomic::Ordering::Relaxed);
    let xa_push_peer_reject  = state.xzone_abort_witness_push_peer_reject_total.load(std::sync::atomic::Ordering::Relaxed);
    let xa_push_net_fail     = state.xzone_abort_witness_push_net_fail_total.load(std::sync::atomic::Ordering::Relaxed);
    let cp_push_addr_fail    = state.conflict_proof_push_addr_fail_total.load(std::sync::atomic::Ordering::Relaxed);
    let cp_push_peer_reject  = state.conflict_proof_push_peer_reject_total.load(std::sync::atomic::Ordering::Relaxed);
    let cp_push_net_fail     = state.conflict_proof_push_net_fail_total.load(std::sync::atomic::Ordering::Relaxed);
    let body = format!("{body}\
         # HELP elara_attestation_push_addr_fail_total Total attestation pushes aborted because peer base_url could not be mapped to a PQ address (peer-table issue — stale entry or PQ_PORT_OFFSET mismatch).\n\
         # TYPE elara_attestation_push_addr_fail_total counter\n\
         elara_attestation_push_addr_fail_total {att_push_addr_fail}\n\
         # HELP elara_attestation_push_peer_reject_total Total attestation pushes where the PQ peer returned a non-2xx, non-429 status (peer-side rejection — protocol drift or malformed body).\n\
         # TYPE elara_attestation_push_peer_reject_total counter\n\
         elara_attestation_push_peer_reject_total {att_push_peer_reject}\n\
         # HELP elara_attestation_push_net_fail_total Total attestation pushes where the PQ transport returned Err (network failure, serde error, peer unreachable).\n\
         # TYPE elara_attestation_push_net_fail_total counter\n\
         elara_attestation_push_net_fail_total {att_push_net_fail}\n\
         # HELP elara_finality_witness_push_addr_fail_total Total SealFinalityWitness pushes aborted because peer base_url could not be mapped to a PQ address.\n\
         # TYPE elara_finality_witness_push_addr_fail_total counter\n\
         elara_finality_witness_push_addr_fail_total {fw_push_addr_fail}\n\
         # HELP elara_finality_witness_push_peer_reject_total Total SealFinalityWitness pushes where the PQ peer returned a non-2xx, non-429 status.\n\
         # TYPE elara_finality_witness_push_peer_reject_total counter\n\
         elara_finality_witness_push_peer_reject_total {fw_push_peer_reject}\n\
         # HELP elara_finality_witness_push_net_fail_total Total SealFinalityWitness pushes where the PQ transport returned Err.\n\
         # TYPE elara_finality_witness_push_net_fail_total counter\n\
         elara_finality_witness_push_net_fail_total {fw_push_net_fail}\n\
         # HELP elara_xzone_abort_witness_push_addr_fail_total Total XZoneAbortWitness pushes aborted because peer base_url could not be mapped to a PQ address.\n\
         # TYPE elara_xzone_abort_witness_push_addr_fail_total counter\n\
         elara_xzone_abort_witness_push_addr_fail_total {xa_push_addr_fail}\n\
         # HELP elara_xzone_abort_witness_push_peer_reject_total Total XZoneAbortWitness pushes where the PQ peer returned a non-2xx, non-429 status.\n\
         # TYPE elara_xzone_abort_witness_push_peer_reject_total counter\n\
         elara_xzone_abort_witness_push_peer_reject_total {xa_push_peer_reject}\n\
         # HELP elara_xzone_abort_witness_push_net_fail_total Total XZoneAbortWitness pushes where the PQ transport returned Err.\n\
         # TYPE elara_xzone_abort_witness_push_net_fail_total counter\n\
         elara_xzone_abort_witness_push_net_fail_total {xa_push_net_fail}\n\
         # HELP elara_conflict_proof_push_addr_fail_total Total ConflictProof pushes aborted because peer base_url could not be mapped to a PQ address.\n\
         # TYPE elara_conflict_proof_push_addr_fail_total counter\n\
         elara_conflict_proof_push_addr_fail_total {cp_push_addr_fail}\n\
         # HELP elara_conflict_proof_push_peer_reject_total Total ConflictProof pushes where the PQ peer returned a non-2xx, non-429 status.\n\
         # TYPE elara_conflict_proof_push_peer_reject_total counter\n\
         elara_conflict_proof_push_peer_reject_total {cp_push_peer_reject}\n\
         # HELP elara_conflict_proof_push_net_fail_total Total ConflictProof pushes where the PQ transport returned Err.\n\
         # TYPE elara_conflict_proof_push_net_fail_total counter\n\
         elara_conflict_proof_push_net_fail_total {cp_push_net_fail}\n\
    ");

    // Gap 2: Cross-zone transfer counters + gauges. Counters (locks/claims/
    // refunds) are bumped on ledger apply and at the epoch refund tick.
    // `currently_locked_micros` and `active_transfers` are live-read from the
    // ledger so they reflect authoritative state even if counters are replayed.
    let xz_locks   = state.xzone_locks_total.load(std::sync::atomic::Ordering::Relaxed);
    let xz_claims  = state.xzone_claims_total.load(std::sync::atomic::Ordering::Relaxed);
    let xz_refunds = state.xzone_refunds_total.load(std::sync::atomic::Ordering::Relaxed);
    let xz_aborts  = state.xzone_aborts_total.load(std::sync::atomic::Ordering::Relaxed);
    let xz_cancels = state.xzone_cancels_total.load(std::sync::atomic::Ordering::Relaxed);
    let xz_rejects = state.xzone_rejects_total.load(std::sync::atomic::Ordering::Relaxed);
    let xz_zone_mismatch = state.xzone_lock_declared_zone_mismatch_total.load(std::sync::atomic::Ordering::Relaxed);
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    let (xz_locked_micros, xz_active_transfers, xz_finality_enforced, xz_finality_legacy, xz_oldest_age, xz_past_expiry, xz_sealed_past_expiry) = match state.ledger.try_read() {
        Ok(l) => (
            l.pending_xzone_locked,
            l.cross_zone.locked_count() as u64,
            l.cross_zone.claim_finality_enforced_total,
            l.cross_zone.claim_finality_legacy_total,
            l.cross_zone.oldest_locked_age_secs(now_secs),
            l.cross_zone.locked_past_expiry_count(now_secs),
            l.cross_zone.sealed_locked_past_expiry_count(now_secs),
        ),
        // Lock contended — surface zeros rather than blocking /metrics. The
        // counters above are still authoritative.
        Err(_) => (0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64),
    };
    let xz_attach_lock_contended = state
        .xzone_attach_finality_lock_contended_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let xz_state_digest = state.xzone_state_digest.load(std::sync::atomic::Ordering::Relaxed);
    let xz_state_digest_epoch = state
        .xzone_state_digest_epoch
        .load(std::sync::atomic::Ordering::Relaxed);
    let pending_fx = state
        .pending_finalization_effects
        .load(std::sync::atomic::Ordering::Relaxed);

    let body = format!("{body}\
         # HELP elara_pending_finalization_effects Pending exactly-once finalization-effects markers (witness rewards + reputation credit) observed by the last recovery sweep. A durable pending_effects: marker is written atomically with finalized: and cleared once effects complete; the boot/tick reconcile sweep re-fires any left behind by a detached effects task that panicked (panic=unwind kills it silently). Healthy = 0. A sustained non-zero value means effects tasks are dying mid-flight and the sweep is carrying finalization payouts — correlate with reward-insert warnings. Saturates at the per-sweep cap (512) when the true backlog is larger (a warn! also fires).\n\
         # TYPE elara_pending_finalization_effects gauge\n\
         elara_pending_finalization_effects {pending_fx}\n\
         # HELP elara_xzone_locks_total Cross-zone transfer LOCK records successfully applied (debit side)\n\
         # TYPE elara_xzone_locks_total counter\n\
         elara_xzone_locks_total {xz_locks}\n\
         # HELP elara_xzone_claims_total Cross-zone transfer CLAIM records successfully applied (credit side)\n\
         # TYPE elara_xzone_claims_total counter\n\
         elara_xzone_claims_total {xz_claims}\n\
         # HELP elara_xzone_refunds_total Expired cross-zone transfers refunded to sender at the epoch tick\n\
         # TYPE elara_xzone_refunds_total counter\n\
         elara_xzone_refunds_total {xz_refunds}\n\
         # HELP elara_xzone_aborts_total Sealed cross-zone transfers aborted via destination-zone committee non-inclusion proof\n\
         # TYPE elara_xzone_aborts_total counter\n\
         elara_xzone_aborts_total {xz_aborts}\n\
         # HELP elara_xzone_cancels_total Pre-seal cross-zone transfers cancelled by sender (refund before lock-zone seal commits the LOCK record). Sustained climb signals account UX bugs (timeout-then-cancel) or adversarial lock-then-cancel churn.\n\
         # TYPE elara_xzone_cancels_total counter\n\
         elara_xzone_cancels_total {xz_cancels}\n\
         # HELP elara_xzone_rejects_total Pre-seal cross-zone transfers rejected by recipient (refund without claiming). Sustained climb signals recipient-side account auto-rejection misfiring on legitimate transfers.\n\
         # TYPE elara_xzone_rejects_total counter\n\
         elara_xzone_rejects_total {xz_rejects}\n\
         # HELP elara_xzone_lock_declared_zone_mismatch_total Observability-only: XZoneLock records ingested whose DECLARED `source_zone` did not equal the record's registry-resolved zone. NOT a reject — a wrong source_zone is self-defeating (the claim's finality-quorum check binds the zone path, so the lock cannot be claimed and refunds after 24h). A hard reject was rejected by design audit (would fork ingest across the zone-split migration window for zero security gain). A sustained climb points at a buggy account/SDK computing source_zone with a stale zone count, not an attack. First-ingest only (not replay); never zone-labelled.\n\
         # TYPE elara_xzone_lock_declared_zone_mismatch_total counter\n\
         elara_xzone_lock_declared_zone_mismatch_total {xz_zone_mismatch}\n\
         # HELP elara_xzone_currently_locked_micros Base units currently locked in pending cross-zone transfers (10^9 base units = 1 beat; conservation invariant)\n\
         # TYPE elara_xzone_currently_locked_micros gauge\n\
         elara_xzone_currently_locked_micros {xz_locked_micros}\n\
         # HELP elara_xzone_active_transfers Pending cross-zone transfers still in Locked status\n\
         # TYPE elara_xzone_active_transfers gauge\n\
         elara_xzone_active_transfers {xz_active_transfers}\n\
         # HELP elara_xzone_claim_finality_enforced_total Cross-zone claims accepted with `source_committee_size > 0` AND >=2/3 zone-A finality quorum verified. This is the fully-protected path - claims protected by the cross-zone settlement finality machinery against orphaned-source-seal attacks.\n\
         # TYPE elara_xzone_claim_finality_enforced_total counter\n\
         elara_xzone_claim_finality_enforced_total {xz_finality_enforced}\n\
         # HELP elara_xzone_claim_finality_legacy_total FROZEN counter: cross-zone claims that were accepted via the legacy inclusion-only path (`source_committee_size == 0`) BEFORE that path was deleted (2026-04-28 — claims now unconditionally require a >=2/3 finality quorum and hard-reject committee_size 0). Persists for on-disk serde back-compat; can only carry a pre-deletion historical value and must never increase again. Any post-2026-04 increase = consensus regression, alert immediately.\n\
         # TYPE elara_xzone_claim_finality_legacy_total counter\n\
         elara_xzone_claim_finality_legacy_total {xz_finality_legacy}\n\
         # HELP elara_xzone_oldest_pending_age_seconds Age of the oldest still-Locked cross-zone transfer in seconds. Healthy churn keeps this in the minutes-to-low-hours band as recipients claim. Sustained climb toward 86400 (24h CLAIM_TIMEOUT_SECS) means the recipient zone cannot claim — witness quorum can't form, recipient lost key, or lock-zone seal stuck pre-finality. Idle nodes report 0.\n\
         # TYPE elara_xzone_oldest_pending_age_seconds gauge\n\
         elara_xzone_oldest_pending_age_seconds {xz_oldest_age}\n\
         # HELP elara_xzone_locked_past_expiry_count Pending cross-zone transfers past their 24h CLAIM_TIMEOUT_SECS deadline but still in Locked status. Healthy state is 0 (or briefly 1-2 transient). Unsealed expired transfers are now refunded fleet-wide via the genesis-authority XZoneTimeoutRefund record (Option A), applied identically on every node — this closed the old anchor-only-sweep asymmetry where only seal-eligible nodes ran the passive refund (see internal design notes). Sealed transfers flip to Aborted only via an XZoneAbort record from the dest-zone committee. Sustained non-zero therefore means EITHER the emitter (genesis authority) is not producing refund batches, OR, for sealed transfers, the dest committee is not signing aborts (correlate with elara_xzone_abort_bundles_submitted_total staying flat).\n\
         # TYPE elara_xzone_locked_past_expiry_count gauge\n\
         elara_xzone_locked_past_expiry_count {xz_past_expiry}\n\
         # HELP elara_xzone_sealed_locked_past_expiry_count Cross-zone transfers that are SEALED and past their 24h claim-timeout deadline but still in Locked status. Sealed transfers are deliberately NOT passively refunded: a passive refund could race an in-flight CLAIM record and break global conservation (the source zone flips Locked to Refunded on its local view, then rejects the arriving CLAIM gossip, while the destination zone has already credited the recipient). The only safe refund path for a sealed transfer is an XZoneAbort from the destination zone's committee (a >= 2/3 quorum non-inclusion proof). This gauge is the unsafe-stuck signal: healthy is 0 (abort signing fires within an epoch tick of expiry); a sustained non-zero value (> 10 min) means the destination committee is not gathering quorum -- a destination-zone partition, fewer than 2/3 of the committee online, or a stuck aggregator (correlate with elara_xzone_abort_bundles_submitted_total staying flat). Distinct from elara_xzone_locked_past_expiry_count, which also includes unsealed transfers (those are still refunded passively, which is race-free because no CLAIM can succeed against an unsealed lock).\n\
         # TYPE elara_xzone_sealed_locked_past_expiry_count gauge\n\
         elara_xzone_sealed_locked_past_expiry_count {xz_sealed_past_expiry}\n\
         # HELP elara_xzone_attach_finality_lock_contended_total Seal-apply proof-attach passes that fell back to attaching WITHOUT finality witnesses because the consensus mutex was try_lock-contended at that instant. A pending lock proofed on this fallback path is baked with committee_size 0, and since the 2026-04-28 removal of the inclusion-only claim path that transfer is unclaimable until a later seal re-attaches witnesses (sender recovery otherwise = the 30-day stale-reap refund). Healthy = 0 or static. Growth while cross-zone transfers are in flight = silent minting of unclaimable transfers; correlate elara_xzone_state_digest across the fleet.\n\
         # TYPE elara_xzone_attach_finality_lock_contended_total counter\n\
         elara_xzone_attach_finality_lock_contended_total {xz_attach_lock_contended}\n\
         # HELP elara_xzone_state_digest 53-bit order-independent SHA3 digest of live cross-zone transfer state (transfer_id, status, proof_present, committee_size), refreshed at each applied seal. Fleet divergence detector: two nodes reporting the SAME elara_xzone_state_digest_epoch but persistently DIFFERENT digests have baked divergent cross-zone state — the only detector that works with more than one zone, where the boot sealed-root cross-check is structurally skipped and a dropped claim or lost proof is supply-neutral (invisible to conservation checks). 0 = not computed since boot. Signer sets are deliberately excluded (node-local, gossip-timing dependent).\n\
         # TYPE elara_xzone_state_digest gauge\n\
         elara_xzone_state_digest {xz_state_digest}\n\
         # HELP elara_xzone_state_digest_epoch Epoch number at which elara_xzone_state_digest was last refreshed. Only compare digests between nodes reporting the same value here.\n\
         # TYPE elara_xzone_state_digest_epoch gauge\n\
         elara_xzone_state_digest_epoch {xz_state_digest_epoch}\n\
    ");

    // Gap 7: epoch-indexed archive snapshot observability. Archive nodes emit a
    // signed snapshot every `archive_snapshot_every_n_epochs`; new nodes prefer
    // the deterministic archive path over the live `/snapshot` route.
    let sb_epoch_indexed = state.snapshot_bootstrap_epoch_indexed_total.load(std::sync::atomic::Ordering::Relaxed);
    let sb_live_fallback = state.snapshot_bootstrap_live_fallback_total.load(std::sync::atomic::Ordering::Relaxed);
    let sb_ledger_loaded = state.snapshot_bootstrap_ledger_loaded_total.load(std::sync::atomic::Ordering::Relaxed);
    let sb_root_verified = state.snapshot_bootstrap_root_verified_total.load(std::sync::atomic::Ordering::Relaxed);
    let sb_root_mismatch = state.snapshot_bootstrap_root_mismatch_total.load(std::sync::atomic::Ordering::Relaxed);
    let sb_root_absent = state.snapshot_bootstrap_root_absent_total.load(std::sync::atomic::Ordering::Relaxed);
    let boot_root_verified = state.boot_sealed_root_verified_total.load(std::sync::atomic::Ordering::Relaxed);
    let boot_root_mismatch = state.boot_sealed_root_mismatch_total.load(std::sync::atomic::Ordering::Relaxed);
    let boot_root_phantom = state.boot_sealed_root_phantom_total.load(std::sync::atomic::Ordering::Relaxed);
    let boot_root_skipped = state.boot_sealed_root_skipped_total.load(std::sync::atomic::Ordering::Relaxed);
    let sb_ledger_flag   = state.ledger_loaded_from_snapshot.load(std::sync::atomic::Ordering::Relaxed) as u64;
    let arc_emit    = state.archive_snapshot_emit_total.load(std::sync::atomic::Ordering::Relaxed);
    let arc_prune   = state.archive_snapshot_prune_total.load(std::sync::atomic::Ordering::Relaxed);
    let arc_last_ep = state.archive_snapshot_last_epoch.load(std::sync::atomic::Ordering::Relaxed);

    let body = format!("{body}\
         # HELP elara_snapshot_bootstrap_epoch_indexed_total New-node bootstraps served via the deterministic `/snapshot/epochs` + `/snapshot/epoch/{{N}}` archive path\n\
         # TYPE elara_snapshot_bootstrap_epoch_indexed_total counter\n\
         elara_snapshot_bootstrap_epoch_indexed_total {sb_epoch_indexed}\n\
         # HELP elara_snapshot_bootstrap_live_fallback_total New-node bootstraps that fell back to the live `/snapshot` path (peer had no archive snapshot)\n\
         # TYPE elara_snapshot_bootstrap_live_fallback_total counter\n\
         elara_snapshot_bootstrap_live_fallback_total {sb_live_fallback}\n\
         # HELP elara_archive_snapshot_emit_total Signed epoch snapshots this archive node has persisted to disk\n\
         # TYPE elara_archive_snapshot_emit_total counter\n\
         elara_archive_snapshot_emit_total {arc_emit}\n\
         # HELP elara_archive_snapshot_prune_total Old epoch snapshots deleted under the `archive_snapshot_retention` knob\n\
         # TYPE elara_archive_snapshot_prune_total counter\n\
         elara_archive_snapshot_prune_total {arc_prune}\n\
         # HELP elara_archive_snapshot_last_epoch Epoch number of the most recent archive snapshot this node has on disk (seeded from the latest resume_from on startup, advanced on each emit). 0 = no on-disk snapshots AND none emitted this run.\n\
         # TYPE elara_archive_snapshot_last_epoch gauge\n\
         elara_archive_snapshot_last_epoch {arc_last_ep}\n\
         # HELP elara_snapshot_bootstrap_ledger_loaded_total Bootstraps that loaded peer ledger as authoritative (CF_APPLIED seeded from snapshot.applied_record_ids, no from-genesis replay).\n\
         # TYPE elara_snapshot_bootstrap_ledger_loaded_total counter\n\
         elara_snapshot_bootstrap_ledger_loaded_total {sb_ledger_loaded}\n\
         # HELP elara_snapshot_bootstrap_root_verified_total Bootstraps where the post-apply local SMT root matched the producer's signed account_state_root. Should track 1:1 with `elara_snapshot_bootstrap_ledger_loaded_total` once the producer fleet is fully upgraded.\n\
         # TYPE elara_snapshot_bootstrap_root_verified_total counter\n\
         elara_snapshot_bootstrap_root_verified_total {sb_root_verified}\n\
         # HELP elara_snapshot_bootstrap_root_mismatch_total Bootstraps where the post-apply local SMT root did NOT match the producer's signed account_state_root. Counter-only signal (ledger has already committed). Operator playbook on sustained non-zero: cross-check producer trust gate, inspect `signer_identity`, escalate to Path SB-1 (manual seed-peer reset) if persistent.\n\
         # TYPE elara_snapshot_bootstrap_root_mismatch_total counter\n\
         elara_snapshot_bootstrap_root_mismatch_total {sb_root_mismatch}\n\
         # HELP elara_snapshot_bootstrap_root_absent_total Bootstraps where the producer did NOT populate account_state_root (legacy snapshot or producer running older code). Goes to ~0 once the fleet is fully upgraded; sustained non-zero = stale producer still serving snapshots.\n\
         # TYPE elara_snapshot_bootstrap_root_absent_total counter\n\
         elara_snapshot_bootstrap_root_absent_total {sb_root_absent}\n\
         # HELP elara_boot_sealed_root_verified_total §6a single-zone boot checks where the replayed account-SMT root matched the canonical seal's signed account_smt_root. The supply-neutral-drop detector on the replay path (see internal design notes §6).\n\
         # TYPE elara_boot_sealed_root_verified_total counter\n\
         elara_boot_sealed_root_verified_total {boot_root_verified}\n\
         # HELP elara_boot_sealed_root_mismatch_total §6a boot checks where the replayed root did NOT match the signed seal — a supply-neutral dropped/extra record on replay. Counter-only (node continues as follower). Operator playbook on non-zero: re-bootstrap from a trusted snapshot and cross-check the seal producer's chain.\n\
         # TYPE elara_boot_sealed_root_mismatch_total counter\n\
         elara_boot_sealed_root_mismatch_total {boot_root_mismatch}\n\
         # HELP elara_boot_sealed_root_phantom_total §6a/F-5 PHANTOM subset of mismatch_total: a boot mismatch with ZERO diverging ledger accounts, i.e. the SMT holds leaf(s) the ledger has no account for (SMT-ahead-of-ledger). real_corruption = mismatch − phantom. Benign clean-SIGKILL phantoms self-heal next seal; SUSTAINED non-zero = live F-5 vector (repair-path ghost leaf or prediction-settlement lag).\n\
         # TYPE elara_boot_sealed_root_phantom_total counter\n\
         elara_boot_sealed_root_phantom_total {boot_root_phantom}\n\
         # HELP elara_boot_sealed_root_skipped_total §6a boot checks that could not run soundly (multi-zone, no tip epoch, no Gap-1 seal at tip, or unsealed overhang). Each is a zero-false-positive bail-out, not a pass.\n\
         # TYPE elara_boot_sealed_root_skipped_total counter\n\
         elara_boot_sealed_root_skipped_total {boot_root_skipped}\n\
         # HELP elara_ledger_loaded_from_snapshot 1 if the current in-memory ledger was loaded from a peer snapshot this run; 0 if rebuilt locally\n\
         # TYPE elara_ledger_loaded_from_snapshot gauge\n\
         elara_ledger_loaded_from_snapshot {sb_ledger_flag}\n\
    ");

    // Snapshot rebootstrap escape hatch.
    let admin_snapshot_rebootstrap = state.admin_snapshot_rebootstrap_total.load(std::sync::atomic::Ordering::Relaxed);
    let body = format!("{body}\
         # HELP elara_admin_snapshot_rebootstrap_total Cumulative invocations of `/admin/snapshot_rebootstrap_from`. Operator escape hatch — forces snapshot bootstrap regardless of local DAG state to unstick a node severely behind on FinalizedIndex. Should be 0 in steady state; non-zero indicates an operator manually rebootstrapped a node against bootstrap-pathology that the orphan resolver + tentative-ledger buffers couldn't unstick.\n\
         # TYPE elara_admin_snapshot_rebootstrap_total counter\n\
         elara_admin_snapshot_rebootstrap_total {admin_snapshot_rebootstrap}\n\
    ");

    // Gap 3 super-seal coverage failures.
    // Bumped by light_sync_loop when a fetched super-seal's `merkle_root`
    // doesn't reconstruct from the seal_record_hash values its claimed
    // `[start_epoch, end_epoch]` range. Should be 0 in healthy operation;
    // sustained growth = colluding seeds signing a forged aggregate, page.
    let super_seal_cov_fail = state.super_seal_coverage_failures_total.load(std::sync::atomic::Ordering::Relaxed);
    let body = format!("{body}\
         # HELP elara_super_seal_coverage_failures_total Super-seal coverage verification failures observed by `light_sync_loop`. Each increment = one super-seal whose claimed `merkle_root` failed `verify_super_seal_full` against the seal_record_hash values gathered for `[start_epoch, end_epoch]` headers. Healthy = 0. Non-zero = colluding-seed forge or seed serving a corrupted/stale super-seal — page operator and rotate seeds.\n\
         # TYPE elara_super_seal_coverage_failures_total counter\n\
         elara_super_seal_coverage_failures_total {super_seal_cov_fail}\n\
    ");

    // B7: non-genesis epoch seals deferred on the catch-up fast-forward branch
    // because the proposer's VRF key is not registered locally (so the VRF proof
    // cannot be verified). The seal is parked (retryable), never applied — it
    // cannot fast-forward `latest_epoch` and wedge this node off the canonical
    // chain. Healthy = 0 (genesis is VRF-exempt; today the only live proposer).
    // Sustained growth = a forged-seal probe against a catching-up node OR an
    // honest joiner that has not yet synced a real non-genesis anchor's VRF
    // registration — cross-check `elara_seal_record_hashes_missing_total`
    // (cold-join backfill lag) before paging.
    let b7_ff_deferred = state.epoch_seal_fastforward_vrf_deferred_total.load(std::sync::atomic::Ordering::Relaxed);
    let body = format!("{body}\
         # HELP elara_epoch_seal_fastforward_vrf_deferred_total Non-genesis epoch seals deferred on the catch-up fast-forward branch of `verify_epoch_seal_inner` because the proposer VRF key is not locally registered (proof unverifiable). Parked + retried, never applied — closes the B7 unverified fast-forward wedge. Healthy = 0.\n\
         # TYPE elara_epoch_seal_fastforward_vrf_deferred_total counter\n\
         elara_epoch_seal_fastforward_vrf_deferred_total {b7_ff_deferred}\n\
    ");

    let c2_chain_rejected = state.epoch_seal_chain_link_rejected_total.load(std::sync::atomic::Ordering::Relaxed);
    let body = format!("{body}\
         # HELP elara_epoch_seal_chain_link_rejected_total Strictly-sequential epoch seals (epoch == our tip+1) REJECTED at ingest register-time because their previous_seal_hash did not chain to our canonical tip — the authoritative C2 chain-link guard under the epoch write lock (the verify-time check is advisory). A valid signature proves WHO signed, not which chain; this blocks a key-holding Byzantine anchor from advancing latest_seal_hash onto a fork. Healthy = 0; a sustained climb = a forged-seal fork probe.\n\
         # TYPE elara_epoch_seal_chain_link_rejected_total counter\n\
         elara_epoch_seal_chain_link_rejected_total {c2_chain_rejected}\n\
    ");

    let phantom_tip_suspected = state.epoch_phantom_tip_suspected_total.load(std::sync::atomic::Ordering::Relaxed);
    let body = format!("{body}\
         # HELP elara_epoch_phantom_tip_suspected_total Subset of chain-link rejects where OUR canonical tip carries 0 external attestations — the crash-before-broadcast phantom signature (a durable-but-never-broadcast seal restored as tip on reboot, self-inflicting a freeze against an honest successor), as distinct from a Byzantine forged-successor probe of an attested tip. Runtime-only freeze: it self-heals on the next reboot (the honest successor is durable in CF_EPOCHS) or on gap->=2 catch-up. Non-zero here at multi-sealer scale (first external sealers onward) gates the deferred provisional-self-tip cure. Healthy = 0.\n\
         # TYPE elara_epoch_phantom_tip_suspected_total counter\n\
         elara_epoch_phantom_tip_suspected_total {phantom_tip_suspected}\n\
    ");

    let successor_chainable = state.epoch_successor_chainable_total.load(std::sync::atomic::Ordering::Relaxed);
    let body = format!("{body}\
         # HELP elara_epoch_successor_chainable_total Subset of elara_epoch_phantom_tip_suspected_total where the chain-link-rejected sequential successor's previous_seal_hash matches the record_hash of a seal we hold durably at CF_EPOCHS (zone, tip_epoch) — the honest successor chains off a real-but-non-canonical seal in our store (the phantom won the lex-min tiebreak but the honest E-seal it beat is still durable). This is the subset the deferred provisional-self-tip chain-existence C2 relaxation would heal (vs an unknown/forged predecessor it must not admit). Sustained non-zero at multi-sealer scale (first external sealers onward) is the live trigger to build the full cure. Healthy = 0.\n\
         # TYPE elara_epoch_successor_chainable_total counter\n\
         elara_epoch_successor_chainable_total {successor_chainable}\n\
    ");

    // B8: PQ accept-path handshake limiter observability. The accept loop runs
    // each responder handshake in a detached task bounded by a semaphore, so one
    // slow/half-open inbound peer can no longer stall new-peer admission.
    // `failed` = in-task handshake failures (timeout / malformed / sovereign-
    // denied / admission-rejected) — a low background rate is normal (hostile
    // probes, mid-handshake drops); post-split this counter is the only signal
    // for that class (it no longer reaches the accept-loop match). `shed` = inbound
    // connections dropped because the handshake limiter was at capacity — healthy
    // = 0; sustained growth = a handshake flood OR `pq_handshake_concurrency` set
    // too low for real fan-in.
    let pq_hs_failed = state.pq_handshake_failed_total.load(std::sync::atomic::Ordering::Relaxed);
    let pq_hs_wire_mismatch = state.pq_handshake_wire_mismatch_total.load(std::sync::atomic::Ordering::Relaxed);
    let pq_hs_shed = state.pq_handshake_shed_total.load(std::sync::atomic::Ordering::Relaxed);
    let pq_serve_decrypt_failed = state.pq_serve_frame_decrypt_failed_total.load(std::sync::atomic::Ordering::Relaxed);
    // STREAM-F1 serve-connection cap: in-flight = cap − available permits.
    let pq_serve_cap = state.pq_serve_cap as u64;
    let pq_serve_inflight = pq_serve_cap.saturating_sub(state.pq_serve_semaphore.available_permits() as u64);
    let pq_serve_shed = state.pq_serve_shed_total.load(std::sync::atomic::Ordering::Relaxed);
    let http_conn_shed = state.http_conn_shed_total.load(std::sync::atomic::Ordering::Relaxed);
    let http_conn_per_ip_shed = state.http_conn_per_ip_shed_total.load(std::sync::atomic::Ordering::Relaxed);
    // HEAVY-read global concurrency cap: in-flight = cap − available permits.
    let pq_hr_cap = state.pq_heavy_read_cap as u64;
    let pq_hr_inflight = pq_hr_cap.saturating_sub(state.pq_heavy_read_semaphore.available_permits() as u64);
    let pq_hr_shed = state.pq_heavy_read_shed_total.load(std::sync::atomic::Ordering::Relaxed);
    // HEAVY-VERIFY global concurrency gate (write-side twin of the read cap).
    let pq_vf_cap = state.pq_verify_cap as u64;
    let pq_vf_inflight = pq_vf_cap.saturating_sub(state.pq_verify_semaphore.available_permits() as u64);
    let pq_vf_waited = state.pq_verify_waited_total.load(std::sync::atomic::Ordering::Relaxed);
    let body = format!("{body}\
         # HELP elara_pq_handshake_failed_total PQ responder handshakes that failed in the detached accept-path task (timeout, malformed frame, AEAD failure, sovereign-denied, or admission-rejected). Replaces the pre-B8 accept-loop recoverable-error visibility — post-split these never reach the loop. A low background rate is normal (hostile probes, mid-handshake drops); a spike means a handshake flood or a misconfigured peer. The PQ-wire-incompatibility sub-cause is split out into elara_pq_handshake_wire_mismatch_total.\n\
         # TYPE elara_pq_handshake_failed_total counter\n\
         elara_pq_handshake_failed_total {pq_hs_failed}\n\
         # HELP elara_pq_handshake_wire_mismatch_total The PQ-wire-incompatibility subset of elara_pq_handshake_failed_total (which still counts the aggregate): either an explicit wire-version reject (the peer's first handshake frame carried a different WIRE_VERSION byte, caught at frame decode) or a transcript/AEAD divergence. Both are the signature of a peer on an incompatible PQ wire — a sustained non-zero on a fresh external join means that peer built a different commit; rebuild it to the seed's. Isolates the #1 first-join failure mode (otherwise just 'looks like the network is dead') from the opaque aggregate. A sporadic non-zero can also be in-transit tampering. Healthy = 0.\n\
         # TYPE elara_pq_handshake_wire_mismatch_total counter\n\
         elara_pq_handshake_wire_mismatch_total {pq_hs_wire_mismatch}\n\
         # HELP elara_pq_handshake_shed_total PQ inbound connections shed because the accept-path handshake limiter (Semaphore sized by pq_handshake_concurrency) was at capacity — the connection is dropped in O(1) rather than queued, so a flood cannot pile up parked tasks holding fds. Healthy = 0. Sustained growth = a handshake flood OR pq_handshake_concurrency set too low for real inbound fan-in.\n\
         # TYPE elara_pq_handshake_shed_total counter\n\
         elara_pq_handshake_shed_total {pq_hs_shed}\n\
         # HELP elara_http_conn_shed_total Public-HTTP connections dropped at accept because the global connection cap (http_conn_cap, loopback exempt) was saturated — the accept-path twin of elara_pq_handshake_shed_total, same shed-not-queue rationale (internal design notes). Healthy = 0. Sustained growth = a connection flood OR http_conn_cap set too low for real fan-in.\n\
         # TYPE elara_http_conn_shed_total counter\n\
         elara_http_conn_shed_total {http_conn_shed}\n\
         # HELP elara_http_conn_per_ip_shed_total Public-HTTP connections dropped at accept because ONE remote IP exceeded http_conn_per_ip_cap while the global cap still had room — the single-source-starves-everyone defense (the SSE per-IP bug class, one layer lower). Healthy = 0. Growth while elara_http_conn_shed_total stays quiet = a single-source slowloris being blunted; the per-IP cap is also what keeps fleet health probes admitted during a flood.\n\
         # TYPE elara_http_conn_per_ip_shed_total counter\n\
         elara_http_conn_per_ip_shed_total {http_conn_per_ip_shed}\n\
         # HELP elara_pq_serve_frame_decrypt_failed_total POST-handshake AEAD frame-decrypt failures on the responder/seed serve path (TCP serve_connection + the /pq-ws read surface): a peer that COMPLETED the PQ handshake then sent an application frame this node could not decrypt. The seed-side symmetric of the follower's elara_delta_sync_failures_other_rpc_total — when a stale-binary external follower silently desyncs it shows HERE, on the box an operator watches, not only on the follower. CANNOT fire on a clean close (those resolve to PeerClosed/Io and are not counted), so it is not connection-churn noise. Healthy = 0; non-zero = post-handshake wire/key divergence (stale binary, an AEAD-AD change shipped without a version bump) or in-transit tampering. Pair with elara_pq_handshake_failed_total (the PRE-handshake equivalent) to localise a desync to before vs after the handshake.\n\
         # TYPE elara_pq_serve_frame_decrypt_failed_total counter\n\
         elara_pq_serve_frame_decrypt_failed_total {pq_serve_decrypt_failed}\n\
         # HELP elara_pq_serve_inflight POST-handshake PQ serve connections currently holding a serve-population permit (STREAM-F1 defense-in-depth; cap = pq_serve_concurrency). The idle read-deadline bounds how long an idle connection lives; this cap bounds how many live ones exist at once. Sustained pinning at the cap = follower fan-in above the cap or a handshake-completing connection swarm — pair with elara_pq_serve_shed_total.\n\
         # TYPE elara_pq_serve_inflight gauge\n\
         elara_pq_serve_inflight {pq_serve_inflight}\n\
         # HELP elara_pq_serve_cap Resolved permit count for the STREAM-F1 serve-connection cap (max post-handshake serve connections at once). Reported so operators see headroom = cap − inflight.\n\
         # TYPE elara_pq_serve_cap gauge\n\
         elara_pq_serve_cap {pq_serve_cap}\n\
         # HELP elara_pq_serve_shed_total Connections shed by the STREAM-F1 serve-connection cap: the PQ handshake completed but the serve population was at capacity, so the connection was dropped (fd freed) before request service — shed-not-queue, a queued connection would hold the very fd the cap protects. Healthy = 0. Sustained growth = legitimate fan-in above pq_serve_concurrency (raise it) OR a connection swarm being contained.\n\
         # TYPE elara_pq_serve_shed_total counter\n\
         elara_pq_serve_shed_total {pq_serve_shed}\n\
         # HELP elara_pq_heavy_read_inflight HEAVY PQ reads (chain-scale verbs — whole-ledger clone or O(zone_count) global-root recompute — run in spawn_blocking) currently holding a global concurrency permit. Cap = pq_heavy_read_concurrency, or max_blocking_threads/2 when 0. Sustained pinning at the cap = heavy-read saturation; consensus ingest may be starved of blocking-pool headroom — pair with elara_pq_heavy_read_shed_total.\n\
         # TYPE elara_pq_heavy_read_inflight gauge\n\
         elara_pq_heavy_read_inflight {pq_hr_inflight}\n\
         # HELP elara_pq_heavy_read_cap Resolved permit count for the HEAVY-read global concurrency cap (max heavy PQ reads in flight at once). Reported so operators see headroom = cap − inflight.\n\
         # TYPE elara_pq_heavy_read_cap gauge\n\
         elara_pq_heavy_read_cap {pq_hr_cap}\n\
         # HELP elara_pq_heavy_read_shed_total HEAVY PQ reads shed (429) because the global concurrency cap stayed full past pq_heavy_read_wait_ms. Healthy = 0. Sustained growth = a heavy-read flood (Sybil swarm bypassing the per-peer rate gate in aggregate) OR pq_heavy_read_concurrency set too low for real joiner fan-in.\n\
         # TYPE elara_pq_heavy_read_shed_total counter\n\
         elara_pq_heavy_read_shed_total {pq_hr_shed}\n\
         # HELP elara_pq_verify_inflight Inbound HEAVY-VERIFY verbs (submit_record / witness / receive_attestation — per-message inline PQC, run in spawn_blocking) currently holding a global verify permit. Cap = pq_verify_concurrency, or the half of the blocking pool the read cap leaves free when 0 (≈ CPU count). Sustained pinning at the cap = an inbound verify flood is being throttled (excess dispatches WAIT, they are never shed — a dropped consensus message is permanently lost).\n\
         # TYPE elara_pq_verify_inflight gauge\n\
         elara_pq_verify_inflight {pq_vf_inflight}\n\
         # HELP elara_pq_verify_cap Resolved permit count for the HEAVY-VERIFY global concurrency gate (max gated verify verbs in flight at once). Reported so operators see headroom = cap − inflight.\n\
         # TYPE elara_pq_verify_cap gauge\n\
         elara_pq_verify_cap {pq_vf_cap}\n\
         # HELP elara_pq_verify_waited_total Dispatches of a heavy-verify verb that found the verify gate saturated and WAITED for a permit (backpressure; never shed, unlike the read gate). Healthy ≈ 0. Sustained growth = an inbound verify flood being absorbed, OR pq_verify_concurrency set too low for real consensus fan-in.\n\
         # TYPE elara_pq_verify_waited_total counter\n\
         elara_pq_verify_waited_total {pq_vf_waited}\n\
    ");

    // Gap 3 observability: super-seal mint rate and
    // max end_epoch. Pairs the existing coverage_failures counter with the
    // "is the producer keeping up?" half of the picture — coverage_failures
    // tells you whether the super-seals you receive are valid, these tell
    // you whether super-seals are happening at all. Mint rate near zero on
    // a non-idle cluster = Gap 3 producer pipeline stalled; max_end_epoch
    // not advancing while latest_epoch climbs = the buffer between
    // SUPER_SEAL_INTERVAL boundaries is widening. Reading from the
    // EpochState gauge is O(1) — `super_seal_max_end_epoch` is updated
    // inside `register_super_seal` (no per-scrape O(zones) scan, which
    // would page-fault a 1M-zone archive node).
    let super_seals_minted = state.super_seals_minted_total.load(std::sync::atomic::Ordering::Relaxed);
    let super_seal_max_end = state.epoch.read().map(|e| e.super_seal_max_end_epoch).unwrap_or(0);
    let super_seal_creation_attempts = state.super_seal_creation_attempts_total.load(std::sync::atomic::Ordering::Relaxed);
    let super_seal_creation_failures = state.super_seal_creation_failures_total.load(std::sync::atomic::Ordering::Relaxed);
    let super_seal_sign_failures = state.super_seal_creation_sign_failures_total.load(std::sync::atomic::Ordering::Relaxed);
    let super_seal_insert_failures = state.super_seal_creation_insert_failures_total.load(std::sync::atomic::Ordering::Relaxed);
    let body = format!("{body}\
         # HELP elara_super_seals_minted_total Cumulative super-seals minted by this node. Bumped from `ingest::process_super_seal` only when `register_super_seal` returns true (end_epoch advances the per-zone latest, not a duplicate replay). Compare its rate against `elara_super_seal_max_end_epoch` advance to detect a stalled producer pipeline.\n\
         # TYPE elara_super_seals_minted_total counter\n\
         elara_super_seals_minted_total {super_seals_minted}\n\
         # HELP elara_super_seal_max_end_epoch Running max of `end_epoch` across every zone's latest super-seal. Reading via the O(1) gauge maintained in `EpochState::register_super_seal` — never scans the per-zone map. Stalls (flat while seal-finalized rate climbs) signal SUPER_SEAL_INTERVAL boundaries are not being collapsed by the producer; page on >2×SUPER_SEAL_INTERVAL epoch divergence from `elara_latest_epoch`.\n\
         # TYPE elara_super_seal_max_end_epoch gauge\n\
         elara_super_seal_max_end_epoch {super_seal_max_end}\n\
         # HELP elara_super_seal_creation_attempts_total Producer-side super-seal creation attempts (this node only). Bumped in `epoch_seal_loop` after `should_create_super_seal` returns true — i.e. just before `create_super_seal()` runs. Disambiguates the failure mode when minted_total stays at 0: attempts climbing but minted flat = create/insert errors (failures counter), attempts flat = gate never fires (boundary log lines explain).\n\
         # TYPE elara_super_seal_creation_attempts_total counter\n\
         elara_super_seal_creation_attempts_total {super_seal_creation_attempts}\n\
         # HELP elara_super_seal_creation_failures_total Producer-side super-seal creation failures (rollup). Bumped on Err from `create_super_seal()` (sign step) or `insert_record_synced()` (storage + gossip step). Healthy = 0. For per-step breakdown see `_sign_failures_total` and `_insert_failures_total`.\n\
         # TYPE elara_super_seal_creation_failures_total counter\n\
         elara_super_seal_creation_failures_total {super_seal_creation_failures}\n\
         # HELP elara_super_seal_creation_sign_failures_total Producer-side super-seal SIGN-step failures. Bumped on Err from `create_super_seal()` in `epoch_seal_loop` — Dilithium3 signing / record construction failed before the record reached gossip. Bumps in addition to the rollup. Non-zero with `creation_attempts` climbing = signing path broken (committee-hash empty, identity not initialized, anchor signature format mismatch). Healthy = 0.\n\
         # TYPE elara_super_seal_creation_sign_failures_total counter\n\
         elara_super_seal_creation_sign_failures_total {super_seal_sign_failures}\n\
         # HELP elara_super_seal_creation_insert_failures_total Producer-side super-seal INSERT-step failures. Bumped on Err from `insert_record_synced()` in `epoch_seal_loop` — record was signed OK but storage + gossip rejected it. Bumps in addition to the rollup. Non-zero with `creation_attempts` climbing = storage or gossip path broken (RocksDB disk-pressure rejection, ingest validation failure, peer fan-out broken). Healthy = 0.\n\
         # TYPE elara_super_seal_creation_insert_failures_total counter\n\
         elara_super_seal_creation_insert_failures_total {super_seal_insert_failures}\n\
    ");

    // Gap 7 chain divergence detector metrics surface.
    // Gauge + 6 counters emitted by `chain_divergence_monitor_loop` (bin/elara_node.rs).
    // Chain-tip basis switch — gauge now driven by latest_epoch.max() instead
    // of record_stats_epoch_seals. Adds `elara_local_chain_tip` so peers can compare
    // chain-tips directly (persistent across restart, not gossip-replay-confused).
    let local_chain_tip = {
        let ep = state.epoch.read_recover();
        ep.latest_epoch.values().copied().max().unwrap_or(0)
    };
    let cd_epochs = state.chain_divergence_epochs.load(std::sync::atomic::Ordering::Relaxed);
    let cd_epochs_ahead = state.chain_divergence_epochs_ahead.load(std::sync::atomic::Ordering::Relaxed);
    let cd_epochs_behind = state.chain_divergence_epochs_behind.load(std::sync::atomic::Ordering::Relaxed);
    let cd_poll_no_peers = state.chain_divergence_poll_no_peers_total.load(std::sync::atomic::Ordering::Relaxed);
    let cd_repair_attempts = state.chain_divergence_repair_attempts_total.load(std::sync::atomic::Ordering::Relaxed);
    let cd_repair_failures = state.chain_divergence_repair_failures_total.load(std::sync::atomic::Ordering::Relaxed);
    let cd_repair_verify_fails = state.chain_divergence_repair_verify_fails_total.load(std::sync::atomic::Ordering::Relaxed);
    let cd_repair_apply_fails = state.chain_divergence_repair_apply_fails_total.load(std::sync::atomic::Ordering::Relaxed);
    let cd_repair_success = state.chain_divergence_repair_success_total.load(std::sync::atomic::Ordering::Relaxed);
    let cd_repair_root_mismatch = state.chain_divergence_repair_root_mismatch_total.load(std::sync::atomic::Ordering::Relaxed);
    let cd_repair_scalar_drift = state.chain_divergence_repair_scalar_drift_total.load(std::sync::atomic::Ordering::Relaxed);
    let cd_repair_conservation_drift = state.chain_divergence_repair_conservation_drift_total.load(std::sync::atomic::Ordering::Relaxed);
    let cd_repair_orphan_stake = state.chain_divergence_repair_orphan_stake_total.load(std::sync::atomic::Ordering::Relaxed);
    let body = format!("{body}\
         # HELP elara_local_chain_tip Persistent chain-tip: max(latest_epoch.values()) across all zones tracked locally. Drives the `chain_divergence_monitor_loop` basis (replaces gossip-replay-confused `elara_epoch_seals_total`). Persistent across restart, derived from the canonical seal stream, cannot be inflated by gossip-replay (each apply only updates the per-zone tip). Peers without this metric fall back to `elara_epoch_seals_total` during the rolling deploy window only.\n\
         # TYPE elara_local_chain_tip gauge\n\
         elara_local_chain_tip {local_chain_tip}\n\
         # HELP elara_chain_divergence_epochs Max(peer_chain_tip) - local_chain_tip in epochs. 0 = local at-or-ahead of every polled peer. >50 for 30m triggers `ChainDivergencePersistent` (severity=critical). Emitted by `chain_divergence_monitor_loop` every CHAIN_DIVERGENCE_POLL_INTERVAL_SECS=300. Basis is `latest_epoch.max()` chain-tip (persistent, accurate) instead of the gossip-replay-inflated runtime seal counter. Operator playbook on alert fire: inspect `chain_divergence_repair_failures_total / chain_divergence_repair_verify_fails_total / chain_divergence_repair_apply_fails_total` for the breakage mode.\n\
         # TYPE elara_chain_divergence_epochs gauge\n\
         elara_chain_divergence_epochs {cd_epochs}\n\
         # HELP elara_chain_divergence_epochs_ahead Signed-divergence AHEAD direction: local_chain_tip - max(peer_chain_tip) in epochs. Non-zero means local is the producer / peers are catching up - NOT a split-brain. Paired with `elara_chain_divergence_epochs_behind`; at most one of the two is non-zero per tick. Operators: ahead>0 on the producer is healthy steady state; ahead>0 on a follower means peers fell silent.\n\
         # TYPE elara_chain_divergence_epochs_ahead gauge\n\
         elara_chain_divergence_epochs_ahead {cd_epochs_ahead}\n\
         # HELP elara_chain_divergence_epochs_behind Signed-divergence BEHIND direction: max(peer_chain_tip) - local_chain_tip in epochs. Mirrors the legacy unsigned `elara_chain_divergence_epochs` value (the unsigned gauge IS the behind-only computation). Kept as a distinct field so the paired scrape reads naturally and a future deprecation of the unsigned gauge has a clean rename target. >50 for 30m fires `ChainDivergencePersistent` (same threshold as legacy gauge).\n\
         # TYPE elara_chain_divergence_epochs_behind gauge\n\
         elara_chain_divergence_epochs_behind {cd_epochs_behind}\n\
         # HELP elara_chain_divergence_poll_no_peers_total Cumulative monitor-loop ticks where no peers were eligible for tip comparison (no connected peers, all in backoff, or stub-mode no-op). Bumps every tick in stub mode; in production stays near-zero except during network partitions. Rapid growth + zero `repair_attempts_total` = monitor loop is alive but ineffective — peer connectivity broken.\n\
         # TYPE elara_chain_divergence_poll_no_peers_total counter\n\
         elara_chain_divergence_poll_no_peers_total {cd_poll_no_peers}\n\
         # HELP elara_chain_divergence_repair_attempts_total Cumulative repair attempts initiated. Bumped when local divergence crosses CHAIN_DIVERGENCE_THRESHOLD_EPOCHS=50 and a state-delta pull is issued to the max-tip peer. Zero in stub mode (tick-114). Rate growth in production = autonomous reconciliation actively working.\n\
         # TYPE elara_chain_divergence_repair_attempts_total counter\n\
         elara_chain_divergence_repair_attempts_total {cd_repair_attempts}\n\
         # HELP elara_chain_divergence_repair_failures_total Cumulative repair attempts that failed at the network layer (timeout / connection refused / 5xx response). Bumped BEFORE signature verify. Sustained non-zero with attempts climbing = max-tip peer unreachable; loop will rotate to next-tip peer on next tick.\n\
         # TYPE elara_chain_divergence_repair_failures_total counter\n\
         elara_chain_divergence_repair_failures_total {cd_repair_failures}\n\
         # HELP elara_chain_divergence_repair_verify_fails_total Cumulative repair attempts where signed state-delta arrived but Dilithium3 verification rejected. Possible peer-forge or corrupt transit. Non-zero MUST cross-reference with `peer_persistent_divergence_total` to identify the bad-actor peer and trigger ban/fork-monitor.\n\
         # TYPE elara_chain_divergence_repair_verify_fails_total counter\n\
         elara_chain_divergence_repair_verify_fails_total {cd_repair_verify_fails}\n\
         # HELP elara_chain_divergence_repair_apply_fails_total Cumulative repair attempts where signature verify PASSED but local apply path rejected (state machine error, missing parent, disk-pressure). Distinct failure class from verify_fails: peer was honest, our local apply is the blocker. Inspect logs for apply-side error chain.\n\
         # TYPE elara_chain_divergence_repair_apply_fails_total counter\n\
         elara_chain_divergence_repair_apply_fails_total {cd_repair_apply_fails}\n\
         # HELP elara_chain_divergence_repair_success_total Cumulative successful repairs. Each increment = one autonomous reconciliation closing a >50-epoch split-brain without operator action. Non-zero rate growth = autonomous-mesh success signal; closes the Path SB-1 manual seed-peer-edit class of operator interventions.\n\
         # TYPE elara_chain_divergence_repair_success_total counter\n\
         elara_chain_divergence_repair_success_total {cd_repair_success}\n\
         # HELP elara_chain_divergence_repair_root_mismatch_total DORMANT since 2026-06-16 (downgraded to advisory debug-log per fusion audit). The post-apply comparison of our local SMT root vs the producer's signed `delta.account_state_root` is NOT a cross-node-stable invariant: a repair patches a subset diff onto this node's own forked pre-state, so the post-apply live root legitimately differs from the producer's full-set root, and the old counter false-fired on every legitimate repair. The binding integrity fence is the Dilithium3 signature + signer trust-gate (see `repair_verify_fails_total`). Reserved for the consensus-stable `latest_sealed_account_smt_root` cross-check (gated follow-up); does not currently bump.\n\
         # TYPE elara_chain_divergence_repair_root_mismatch_total counter\n\
         elara_chain_divergence_repair_root_mismatch_total {cd_repair_root_mismatch}\n\
         # HELP elara_chain_divergence_repair_scalar_drift_total DORMANT since 2026-06-16 (downgraded to advisory debug-log per fusion audit). The post-apply recomputed `total_staked` (sum over the node's own account set, the denominator `is_settled` MUST equal) legitimately differs from the producer's global `delta.total_staked` on any subset repair. The repair installs the self-consistent recomputed value, so settlement math stays internally correct. Not a cross-node-stable invariant; does not currently bump.\n\
         # TYPE elara_chain_divergence_repair_scalar_drift_total counter\n\
         elara_chain_divergence_repair_scalar_drift_total {cd_repair_scalar_drift}\n\
         # HELP elara_chain_divergence_repair_conservation_drift_total DORMANT since 2026-06-16 (downgraded to advisory debug-log per fusion audit). The conservation identity (sum_available + total_staked + pending_xzone_locked + conservation_pool == total_supply) cannot hold on a partial `StateDelta`, which carries neither `conservation_pool` nor `pending_xzone_locked` — a known wire-format limitation, not a divergence. Does not currently bump; a sustained-divergence operator would instead trigger a full snapshot bootstrap (carries all four scalars via wholesale ledger replace).\n\
         # TYPE elara_chain_divergence_repair_conservation_drift_total counter\n\
         elara_chain_divergence_repair_conservation_drift_total {cd_repair_conservation_drift}\n\
         # HELP elara_chain_divergence_repair_orphan_stake_total LIVE (bumps, unlike the three DORMANT drift counters above). Accounts seen during a repair carrying staked>0 but with no local StakeEntry in staker_index — a staker onboarded by the StateDelta (which carries account state, not the StakeEntry map) whose Stake record has not yet been folded. FAIRNESS-SELF-HEALING, not a fork (fusion-audited 2026-06-25): binding consensus — epoch committee, super-seal committee_hash, seal-escalation verifier, zone_stakes denominator — reads ledger.accounts, not this index. Self-heals via forward ingest (the repair leaves CF_APPLIED untouched, so normal sync re-delivers the Stake record). Operator response on UNBOUNDED growth: confirm forward ingest is delivering the affected stakers Stake records, else trigger a full snapshot bootstrap. A bounded value that stops growing is expected and benign.\n\
         # TYPE elara_chain_divergence_repair_orphan_stake_total counter\n\
         elara_chain_divergence_repair_orphan_stake_total {cd_repair_orphan_stake}\n\
    ");

    // REALMS P1.5 a3 — live drand pulse fetcher family. All zeros on nodes
    // without the fetcher enabled (the default).
    let drand_fetch_ok = state.drand_fetch_ok_total.load(std::sync::atomic::Ordering::Relaxed);
    let drand_fetch_fail = state.drand_fetch_fail_total.load(std::sync::atomic::Ordering::Relaxed);
    let drand_disagree = state.drand_relay_disagree_total.load(std::sync::atomic::Ordering::Relaxed);
    let drand_regression = state.drand_round_regression_total.load(std::sync::atomic::Ordering::Relaxed);
    let drand_ahead = state.drand_pulse_ahead_of_clock_total.load(std::sync::atomic::Ordering::Relaxed);
    let drand_attached = state.drand_seal_pulse_attached_total.load(std::sync::atomic::Ordering::Relaxed);
    let drand_absent = state.drand_seal_pulse_absent_total.load(std::sync::atomic::Ordering::Relaxed);
    let drand_age: i64 = state
        .drand_pulse_cache
        .age_secs(crate::network::admin_pq_auth::now_unix_secs())
        .map_or(-1, |a| a.min(i64::MAX as u64) as i64);
    let body = format!("{body}\
         # HELP elara_drand_fetch_ok_total Cross-relay-agreed drand pulses stored (cache advanced). Flat while the fetcher is enabled = relays unreachable or disagreeing — read fail/disagree below.\n\
         # TYPE elara_drand_fetch_ok_total counter\n\
         elara_drand_fetch_ok_total {drand_fetch_ok}\n\
         # HELP elara_drand_fetch_fail_total Fetch ticks with no usable agreed pulse (relay outage, no quorum, or garbage material). Transient growth is normal; sustained growth with ok_total flat = both relays down or the pinned chain halted.\n\
         # TYPE elara_drand_fetch_fail_total counter\n\
         elara_drand_fetch_fail_total {drand_fetch_fail}\n\
         # HELP elara_drand_relay_disagree_total Two relays returned different BLS material for the same round — at least one lying or corrupt; the pulse was skipped. Healthy = 0.\n\
         # TYPE elara_drand_relay_disagree_total counter\n\
         elara_drand_relay_disagree_total {drand_disagree}\n\
         # HELP elara_drand_round_regression_total Agreed round was not newer than the cached round; the monotone cache refused it so an embedded not-before can never walk backwards. Occasional = relay lag; sustained = a relay pinned to an old round.\n\
         # TYPE elara_drand_round_regression_total counter\n\
         elara_drand_round_regression_total {drand_regression}\n\
         # HELP elara_drand_pulse_ahead_of_clock_total Pulse not-before was ahead of local now — a genuine beacon round cannot be future, so the LOCAL clock is behind (pulse still embedded; the bound stays true against real time). Sustained growth = fix this node's NTP.\n\
         # TYPE elara_drand_pulse_ahead_of_clock_total counter\n\
         elara_drand_pulse_ahead_of_clock_total {drand_ahead}\n\
         # HELP elara_drand_seal_pulse_attached_total Seal-emit attempts that embedded a fresh drand pulse. With the fetcher healthy this should track seal production 1:1.\n\
         # TYPE elara_drand_seal_pulse_attached_total counter\n\
         elara_drand_seal_pulse_attached_total {drand_attached}\n\
         # HELP elara_drand_seal_pulse_absent_total Seal-emit attempts with no fresh pulse (fetcher off, cold cache, or past the 300s staleness cap). On fetcher-enabled producers this climbing while attached is flat = stuck fetcher.\n\
         # TYPE elara_drand_seal_pulse_absent_total counter\n\
         elara_drand_seal_pulse_absent_total {drand_absent}\n\
         # HELP elara_drand_pulse_age_seconds Seconds since the cached pulse was cross-relay agreed; -1 = never fetched (fetcher off or cold). Embedding stops past 300 (staleness cap), so sustained >300 with the fetcher enabled = stuck fetcher or halted beacon.\n\
         # TYPE elara_drand_pulse_age_seconds gauge\n\
         elara_drand_pulse_age_seconds {drand_age}\n\
    ");

    // Gap 3 upstream-stall diagnosis: epoch_seal_loop proposal-outcome counters.
    // Per-reason breakdown of the `None` outcome so /metrics surfaces WHICH gate fired.
    let seal_loop_ticks = state.seal_loop_ticks_total.load(std::sync::atomic::Ordering::Relaxed);
    let seal_loop_zones_eval = state.seal_loop_zones_evaluated_total.load(std::sync::atomic::Ordering::Relaxed);
    let seal_loop_per_zone = state.seal_loop_proposals_per_zone_total.load(std::sync::atomic::Ordering::Relaxed);
    let seal_loop_escalate = state.seal_loop_proposals_escalate_total.load(std::sync::atomic::Ordering::Relaxed);
    let seal_loop_none = state.seal_loop_proposals_none_total.load(std::sync::atomic::Ordering::Relaxed);
    let seal_loop_none_already = state.seal_loop_proposals_none_already_sealed_total.load(std::sync::atomic::Ordering::Relaxed);
    let seal_loop_none_bootstrap = state.seal_loop_proposals_none_bootstrap_decline_total.load(std::sync::atomic::Ordering::Relaxed);
    let seal_loop_none_not_in_top = state.seal_loop_proposals_none_not_in_top_ranks_total.load(std::sync::atomic::Ordering::Relaxed);
    let seal_loop_none_rank_too_high = state.seal_loop_proposals_none_rank_too_high_total.load(std::sync::atomic::Ordering::Relaxed);
    let body = format!("{body}\
         # HELP elara_seal_loop_ticks_total Cumulative `epoch_seal_loop` ticks that survived the catchup-skip check. At base 60s interval this climbs by ~1/min once boot warmup ends. Pair with the four proposal-outcome counters below to disambiguate stall mode.\n\
         # TYPE elara_seal_loop_ticks_total counter\n\
         elara_seal_loop_ticks_total {seal_loop_ticks}\n\
         # HELP elara_seal_loop_zones_evaluated_total Cumulative zones evaluated across all ticks. Sum of `zones_to_seal.len()` per tick. Zero growth = zone-discovery returns empty AND `latest_epoch` is empty — node has no zones to seal.\n\
         # TYPE elara_seal_loop_zones_evaluated_total counter\n\
         elara_seal_loop_zones_evaluated_total {seal_loop_zones_eval}\n\
         # HELP elara_seal_loop_proposals_per_zone_total Cumulative `SealProposal::PerZone(_)` outcomes. This is the canonical happy-path counter — this anchor IS the rank-elected proposer for some (zone, epoch). Should climb 1:1 with new seals minted by this node (modulo create/insert failures).\n\
         # TYPE elara_seal_loop_proposals_per_zone_total counter\n\
         elara_seal_loop_proposals_per_zone_total {seal_loop_per_zone}\n\
         # HELP elara_seal_loop_proposals_escalate_total Cumulative `SealProposal::GlobalEscalate(_)` outcomes (Stage 3c.1 stuck-zone bailout). Healthy = 0. Sustained non-zero = a zone's rank ladder is fully exhausted; this node is emitting a global quorum seal because no anchor in the natural zone responded.\n\
         # TYPE elara_seal_loop_proposals_escalate_total counter\n\
         elara_seal_loop_proposals_escalate_total {seal_loop_escalate}\n\
         # HELP elara_seal_loop_proposals_none_total Cumulative `SealProposal::None` outcomes (sum of the four reason sub-counters). In a 2-anchor fleet sealing 2 zones, one anchor will None and the other PerZone on any given (zone, epoch), so steady-state climb rate is ~1x per_zone rate. None climbing AND per_zone flat at 0 across ALL anchors = consensus liveness break (no anchor is rank-eligible).\n\
         # TYPE elara_seal_loop_proposals_none_total counter\n\
         elara_seal_loop_proposals_none_total {seal_loop_none}\n\
         # HELP elara_seal_loop_proposals_none_already_sealed_total `NoneReason::AlreadySealed` — `latest_epoch[zone] >= epoch_number`. Healthy duplicate-suppression signal; fires on every anchor that lost the race for a (zone, epoch).\n\
         # TYPE elara_seal_loop_proposals_none_already_sealed_total counter\n\
         elara_seal_loop_proposals_none_already_sealed_total {seal_loop_none_already}\n\
         # HELP elara_seal_loop_proposals_none_bootstrap_decline_total `NoneReason::BootstrapNonGenesis` — `staked.len() < 3` and this node is not the genesis authority. Sticky on non-genesis anchors until the stake set grows past 3; sustained non-zero after a mainnet stake set is established = stake-drain regression.\n\
         # TYPE elara_seal_loop_proposals_none_bootstrap_decline_total counter\n\
         elara_seal_loop_proposals_none_bootstrap_decline_total {seal_loop_none_bootstrap}\n\
         # HELP elara_seal_loop_proposals_none_not_in_top_ranks_total `NoneReason::NotInTopRanks` — `rank_of(beacon, staked, zone, our_identity, MAX_VIEW_DEPTH=7)` returned None, this anchor is outside the top 7 VRF-weighted stakers for the zone+epoch beacon. LIVENESS-CRITICAL if non-zero across ALL anchors for the same zone over multiple ticks: the natural-zone partition has drifted or stake redistributed off the anchors.\n\
         # TYPE elara_seal_loop_proposals_none_not_in_top_ranks_total counter\n\
         elara_seal_loop_proposals_none_not_in_top_ranks_total {seal_loop_none_not_in_top}\n\
         # HELP elara_seal_loop_proposals_none_rank_too_high_total `NoneReason::RankTooHighForElapsed` — top-7 but `our_rank > current_allowed_rank` (exponential backoff has not yet unlocked our slot). Self-clearing as elapsed_ms grows; sustained non-zero across all anchors for the same zone = lower ranks absent/byzantine, schedule parked waiting on them.\n\
         # TYPE elara_seal_loop_proposals_none_rank_too_high_total counter\n\
         elara_seal_loop_proposals_none_rank_too_high_total {seal_loop_none_rank_too_high}\n\
    ");

    // DISC-4 Phase D-2 observability: slow-record classification counters.
    // Each slow record (>10s in insert_record_inner) is bucketed by the
    // dominant sub-phase of its timing. Pattern A (pre) was the pre-D-2
    // cascade caused by a misfiring backpressure sleep — delta should stay
    // at 0 post-deploy. Pattern B (post) is real phase-5 RocksDB write
    // pressure and is the next DISC-4 fix candidate.
    let slow_pre   = state.ingest_slow_records_pre_total.load(std::sync::atomic::Ordering::Relaxed);
    let slow_post  = state.ingest_slow_records_post_total.load(std::sync::atomic::Ordering::Relaxed);
    let slow_sb    = state.ingest_slow_records_sb_total.load(std::sync::atomic::Ordering::Relaxed);
    let slow_other = state.ingest_slow_records_other_total.load(std::sync::atomic::Ordering::Relaxed);
    // Per-phase max-latency gauges paired with the slow_records counters.
    let phase_max_pre   = state.ingest_record_phase_max_ms_pre.load(std::sync::atomic::Ordering::Relaxed);
    let phase_max_post  = state.ingest_record_phase_max_ms_post.load(std::sync::atomic::Ordering::Relaxed);
    let phase_max_sb    = state.ingest_record_phase_max_ms_sb.load(std::sync::atomic::Ordering::Relaxed);
    let phase_max_other = state.ingest_record_phase_max_ms_other.load(std::sync::atomic::Ordering::Relaxed);

    let body = format!("{body}\
         # HELP elara_ingest_slow_records_pre_total Slow records (>10s) dominated by pre-storage (validation/sig/ledger-read) — Pattern A, should stay flat post DISC-4 D-2\n\
         # TYPE elara_ingest_slow_records_pre_total counter\n\
         elara_ingest_slow_records_pre_total {slow_pre}\n\
         # HELP elara_ingest_slow_records_post_total Slow records dominated by phase-5 post-processing (epoch/equivocation/fisherman) — Pattern B, real RocksDB write pressure\n\
         # TYPE elara_ingest_slow_records_post_total counter\n\
         elara_ingest_slow_records_post_total {slow_post}\n\
         # HELP elara_ingest_slow_records_sb_total Slow records dominated by phase-2 spawn_blocking RocksDB put_record + Merkle\n\
         # TYPE elara_ingest_slow_records_sb_total counter\n\
         elara_ingest_slow_records_sb_total {slow_sb}\n\
         # HELP elara_ingest_slow_records_other_total Slow records with no single dominant sub-phase (mixed stall)\n\
         # TYPE elara_ingest_slow_records_other_total counter\n\
         elara_ingest_slow_records_other_total {slow_other}\n\
         # HELP elara_ingest_record_phase_max_ms_pre High-water mark in ms of pre-storage time (validation/sig/ledger-read) across all slow records (>10s total). Bumped on every slow record regardless of which phase dominated, so an 11s record with 6s pre + 5s post bumps both pre and post. Pair with `elara_state_core_record_processing_max_ms` and `elara_ingest_slow_records_pre_total` to localise the cause when the watchdog fires. Triggered when record_processing_max_ms fires with no per-phase breakdown, so operators cannot tell whether a multi-second stall lived in storage, ledger.write, or pre.\n\
         # TYPE elara_ingest_record_phase_max_ms_pre gauge\n\
         elara_ingest_record_phase_max_ms_pre {phase_max_pre}\n\
         # HELP elara_ingest_record_phase_max_ms_post High-water mark in ms of phase-5 post-processing time (epoch seal + equivocation + fisherman + attestation recovery) across all slow records. Sustained climb here = phase-5 sub-phase needs a 'do not materialize' refactor to address RocksDB write pressure under the dag/ledger write lock.\n\
         # TYPE elara_ingest_record_phase_max_ms_post gauge\n\
         elara_ingest_record_phase_max_ms_post {phase_max_post}\n\
         # HELP elara_ingest_record_phase_max_ms_sb High-water mark in ms of phase-2 spawn_blocking time (RocksDB put_record + Merkle inclusion). Sustained values >5s suggest backpressure-sleep is firing. Also inflates under disk-IO contention from compaction.\n\
         # TYPE elara_ingest_record_phase_max_ms_sb gauge\n\
         elara_ingest_record_phase_max_ms_sb {phase_max_sb}\n\
         # HELP elara_ingest_record_phase_max_ms_other High-water mark in ms of total ingest time on slow records where no single phase >50% dominated (mixed stall). Records `total_ingest_ms` only — not a sub-phase split. High value here paired with low pre/post/sb maxes = rolling lock contention spread across phases, not localised to one bottleneck.\n\
         # TYPE elara_ingest_record_phase_max_ms_other gauge\n\
         elara_ingest_record_phase_max_ms_other {phase_max_other}\n\
    ");

    // Disk + memory metrics
    // Also extract f_files / f_ffree (total /
    // available inodes) from the same statvfs call. At mainnet scale
    // (1M zones × ~50 SST files/zone = 50M inodes) phone-tier eMMC
    // formatted with default mkfs.ext4 (~300K inodes/GB) on a 32 GB
    // partition has only ~10M inodes — runs out of inodes long before
    // it runs out of bytes. The bytes-side gauges (disk_total_mb /
    // disk_available_mb) miss this cliff entirely: a "20% disk free"
    // alert can fire AFTER write() already returns ENOSPC because no
    // inode is free.
    let (disk_total_mb, disk_avail_mb, disk_inodes_total, disk_inodes_avail, mem_rss_kb) = {
        // Off-unix the statvfs block below vanishes and these stay at their
        // 0 = "unavailable" defaults, leaving the `mut` unused there.
        #[cfg_attr(not(unix), allow(unused_mut))]
        let mut dt = 0u64;
        #[cfg_attr(not(unix), allow(unused_mut))]
        let mut da = 0u64;
        #[cfg_attr(not(unix), allow(unused_mut))]
        let mut it_total = 0u64;
        #[cfg_attr(not(unix), allow(unused_mut))]
        let mut it_avail = 0u64;
        let mut rss = 0u64;

        #[cfg(unix)]
        {
            // libc::statvfs fields (f_blocks, f_frsize, f_bavail, f_files, f_ffree)
            // are c_ulong: u64 on Linux x86_64/aarch64 but u32 on 32-bit unix targets.
            // The u64::from() promotion is a no-op on 64-bit (clippy flags it as
            // useless) but mandatory on 32-bit so the multiplication can't
            // overflow. Suppress the lint here — correctness on 32-bit wins.
            #[allow(clippy::useless_conversion)]
            {
                use std::os::unix::ffi::OsStrExt;
                let path = std::ffi::CString::new(state.config.data_dir.as_os_str().as_bytes()).ok();
                if let Some(p) = path {
                    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
                    if unsafe { libc::statvfs(p.as_ptr(), &mut stat) } == 0 {
                        dt = (u64::from(stat.f_blocks) * u64::from(stat.f_frsize)) / (1024 * 1024);
                        da = (u64::from(stat.f_bavail) * u64::from(stat.f_frsize)) / (1024 * 1024);
                        it_total = u64::from(stat.f_files);
                        it_avail = u64::from(stat.f_ffree);
                    }
                }
            }
        }

        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if line.starts_with("VmRSS:") {
                    rss = line.split_whitespace()
                        .nth(1)
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0);
                    break;
                }
            }
        }

        (dt, da, it_total, it_avail, rss)
    };
    let mem_pressure = if state.under_memory_pressure() { 1u8 } else { 0u8 };
    let mem_critical = if state.under_critical_memory_pressure() { 1u8 } else { 0u8 };
    let disk_pressure = if state.under_disk_pressure() { 1u8 } else { 0u8 };
    let disk_avail_pressure = if state.under_avail_pressure() { 1u8 } else { 0u8 };
    let disk_cap_pressure = if state.under_cap_pressure() { 1u8 } else { 0u8 };
    let disk_pressure_rejected_ingest_total = state
        .disk_pressure_rejected_ingest_total
        .load(std::sync::atomic::Ordering::Relaxed);
    // EmergencyHalt circuit-breaker — on/off gauge + rejected-ingest counter.
    let emergency_rejected_ingest_total = state
        .emergency_rejected_ingest_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let emergency_halted: u8 =
        if state.emergency_halted_now(crate::network::ingest::now() as u64) { 1 } else { 0 };
    // Per-edge transition counters + lowest-since-boot avail floor.
    // Closes the gauge-failure-on-slow-shrink shape: the 60s scrape cadence
    // can miss a brief trip-and-recover AND can miss a slow
    // monotonic decline. Counters bump exactly once per 0→1
    // transition; the lowest-MB gauge tracks the floor across the entire
    // process lifetime via fetch_min. Sentinel u64::MAX (pre-first-sample)
    // is mapped to 0 in the export so first-scrape-after-boot reads 0 like
    // the sample-then-sleep pattern; once the loop has ticked once
    // the value is the live running minimum.
    let disk_avail_pressure_events_total = state
        .disk_avail_pressure_events_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let disk_cap_pressure_events_total = state
        .disk_cap_pressure_events_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let disk_pressure_lowest_avail_mb = {
        let raw = state
            .disk_pressure_lowest_avail_mb
            .load(std::sync::atomic::Ordering::Relaxed);
        if raw == u64::MAX { 0 } else { raw }
    };
    // Paired iteration counter so operators can disambiguate the
    // sentinel `u64::MAX → 0` rendering of `_lowest_avail_mb` from a real
    // statvfs-saw-<1MB observation. `samples_total = 0` ⇒ never sampled
    // (sentinel); `samples_total > 0` AND `lowest_avail_mb = 0` ⇒ the loop
    // has observed a sub-MB free window (e.g. an ENOSPC window).
    let disk_pressure_samples_total = state
        .disk_pressure_samples_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let admin_compact_cf_triggered_total = state
        .admin_compact_cf_triggered_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let pre_migration_backup_bytes =
        crate::storage::rocks::pre_migration_backup_bytes_cached(&state.config.data_dir);
    // Filesystem footprint of data_dir, sampled by the
    // dedicated `data_dir_size_loop` task at a longer cadence (default 5 min)
    // rather than inline in disk_pressure_loop. Pair with `data_dir_size_samples_total`
    // to tell `unsampled-since-boot` (samples=0) apart from `walk succeeded but
    // saw zero bytes` (samples>0 — pathological filesystem state).
    let data_dir_total_bytes = state
        .data_dir_total_bytes
        .load(std::sync::atomic::Ordering::Relaxed);
    let data_dir_size_samples_total = state
        .data_dir_size_samples_total
        .load(std::sync::atomic::Ordering::Relaxed);
    // Boot timing observability. Set ONCE per process
    // at the moment HTTP listener binds, so the very first /metrics scrape
    // post-boot already carries the values. A sustained zero in steady state
    // means a downstream-side bug — boot can't have taken zero seconds.
    let boot_total_secs = state.boot_total_secs.load(std::sync::atomic::Ordering::Relaxed);
    let boot_ledger_rebuild_secs = state.boot_ledger_rebuild_secs.load(std::sync::atomic::Ordering::Relaxed);
    let boot_state_core_init_secs = state.boot_state_core_init_secs.load(std::sync::atomic::Ordering::Relaxed);
    // File descriptor inventory — open + soft RLIMIT.
    // Sampled at scrape time (no background loop). On a healthy fleet
    // open_fds ≈ peers + RocksDB SST handles + log file + a few sockets,
    // typically <500. Sustained climb without peer growth = FD leak.
    let open_fds = count_open_fds();
    let max_fds = max_open_fds();
    // Process memory + thread + page-fault inventory.
    // Two cheap /proc reads; both consumed by the gauges below.
    // P1-tier — emit family `elara_proc_*` not in P0_EXACT.
    let (proc_vmpeak_kb, proc_vmswap_kb, proc_threads) =
        if collect_p1 { process_status_extended() } else { (0u64, 0u64, 0u64) };
    let (proc_minor_faults, proc_major_faults) =
        if collect_p1 { process_page_faults() } else { (0u64, 0u64) };
    // Scheduler thrash + RSS high-water. Voluntary vs
    // nonvoluntary ctxt switches separate I/O-bound healthy yields from
    // noisy-neighbor preemption; VmHWM preserves the resident-peak cliff
    // that VmPeak (virtual-peak) doesn't capture.
    // P1-tier.
    let (proc_vmhwm_kb, proc_ctxt_voluntary, proc_ctxt_nonvoluntary) =
        if collect_p1 { process_scheduler_stats() } else { (0u64, 0u64, 0u64) };
    // RSS decomposition into anon (true heap) vs file
    // (page cache holding mmap'd RocksDB blocks + binary text) vs shmem.
    // The memory reader exposes total RSS but cannot tell whether 1.5 GB of
    // resident memory is "we own all 1.5 GB" or "kernel is caching 1.4 GB of
    // SST blocks for us". Under memory pressure the file half is reclaimed
    // first; watching RssAnon climb while RssFile drops is the canonical
    // "page cache thrash starting" signal on a 2 GB phone-tier node.
    // P1-tier.
    let (proc_rss_anon_kb, proc_rss_file_kb, proc_rss_shmem_kb) =
        if collect_p1 { process_rss_composition() } else { (0u64, 0u64, 0u64) };
    // Extended host /proc/meminfo coverage. The OOM-imminence reader
    // surfaces Dirty/Writeback/Cached only — operators have no way to compute
    // true free RAM (MemAvailable, kernel-computed: MemFree + reclaimable
    // cache + reclaimable slab) or swap usage from /metrics. On phone-tier
    // 2GB nodes MemAvailable is THE primary OOM-imminence signal; PageTables
    // grows linearly with mmap region count (a hidden cost of RocksDB SST
    // file growth that we cannot see anywhere else); Slab tracks kernel
    // overhead from FD/connection counts. Adds 9 gauges from the same
    // /proc/meminfo file already read by the OOM reader (separate read; cost ~50µs).
    // P1-tier — emits `elara_meminfo_*` (not in P0_EXACT).
    let (
        meminfo_total_kb,
        meminfo_available_kb,
        meminfo_free_kb,
        meminfo_buffers_kb,
        meminfo_slab_kb,
        meminfo_sreclaimable_kb,
        meminfo_swap_total_kb,
        meminfo_swap_free_kb,
        meminfo_page_tables_kb,
    ) = if collect_p1 {
        host_meminfo_extras()
    } else {
        (0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64)
    };
    // Per-process aggregated time blocked on disk I/O.
    // /proc/self/stat field 42 (delayacct_blkio_ticks). Distinct from
    // process_io_*_bytes (throughput, not wait time), distinct from
    // PSI (host-wide, includes other processes), distinct from
    // schedstat wait-time (waiting for CPU, not for disk). Answers: how much
    // wall-clock time did THIS process spend with at least one task blocked
    // on a block-IO request. The cleanest leading indicator of compaction
    // back-pressure on phone-tier RocksDB workloads.
    // P1-tier.
    let proc_blkio_wait_secs = if collect_p1 { process_blkio_wait_seconds() } else { 0.0 };
    // Per-zone CPU thermal temperature. Cloud VPSs
    // typically expose no thermal zones (hypervisor abstraction); phone-tier
    // hardware (the laptop node, the local mini-PC, future Pi/RPi) does. Without this
    // gauge, thermal-throttling-induced performance degradation is silent —
    // the kernel scales clock to ~60% at the ACPI passive trip point
    // (typically 85-90 °C) and elara-node performance drops 30-40% with no
    // other signal in /metrics. Empty gauge family on hosts without thermal
    // zones — that is the correct fallback (don't fake values).
    // Debug-tier — per-zone label routes to DEBUG_PREFIXES.
    let thermal_zones = if collect_debug { host_thermal_zones() } else { Vec::new() };
    let mut thermal_rows = String::new();
    for (zone, type_label, celsius) in &thermal_zones {
        thermal_rows.push_str(&format!(
            "elara_host_thermal_celsius{{zone=\"{}\",type=\"{}\"}} {:.3}\n",
            escape_prom_label(zone),
            escape_prom_label(type_label),
            celsius
        ));
    }
    // Per-chip/per-sensor temperatures from
    // /sys/class/hwmon — covers laptops (coretemp/k10temp), per-core hot
    // spots, NVMe SSD temps, VRM sensors. Complements the thermal-zone reader
    // which only covers the older /sys/class/thermal/thermal_zone* interface.
    // Debug-tier — per-chip/per-sensor label set.
    let hwmon_temps = if collect_debug { host_hwmon_temps() } else { Vec::new() };
    let mut hwmon_rows = String::new();
    for (chip, sensor, label, celsius) in &hwmon_temps {
        hwmon_rows.push_str(&format!(
            "elara_host_hwmon_temp_celsius{{chip=\"{}\",sensor=\"{}\",label=\"{}\"}} {:.3}\n",
            escape_prom_label(chip),
            escape_prom_label(sensor),
            escape_prom_label(label),
            celsius
        ));
    }
    // Per-CPU current clock frequency from
    // /sys/devices/system/cpu/cpu*/cpufreq/scaling_cur_freq. The visible
    // CONSEQUENCE of thermal throttling — pairs with the thermal readers to make
    // throttling alerts actionable: temp climbing past 80 °C + cpufreq
    // dropping = clock gate active. Empty on virtualised cloud VPSs.
    // Debug-tier — per-CPU label set.
    let cpu_freqs = if collect_debug { host_cpu_frequencies() } else { Vec::new() };
    let mut cpu_freq_rows = String::new();
    for (cpu_id, hz) in &cpu_freqs {
        cpu_freq_rows.push_str(&format!(
            "elara_host_cpu_frequency_hz{{cpu=\"{}\"}} {}\n",
            cpu_id, hz
        ));
    }
    // Process resource limits from /proc/self/limits.
    // Surfaces silent-stranglers like RLIMIT_NOFILE that go EMFILE under
    // mainnet 10K-conn load with no other signal until the gossip layer
    // is deaf. Ceiling visibility — pair with elara_process_open_fds for
    // utilisation ratio alerts.
    // Debug-tier — per-resource label set.
    let rlimits = if collect_debug { process_rlimits() } else { Vec::new() };
    let mut rlimit_soft_rows = String::new();
    let mut rlimit_hard_rows = String::new();
    for (resource, soft, hard) in &rlimits {
        rlimit_soft_rows.push_str(&format!(
            "elara_process_rlimit_soft{{resource=\"{}\"}} {}\n",
            resource, soft
        ));
        rlimit_hard_rows.push_str(&format!(
            "elara_process_rlimit_hard{{resource=\"{}\"}} {}\n",
            resource, hard
        ));
    }
    // Pressure Stall Information from /proc/pressure/*.
    // Single cleanest "is this node struggling?" signal Linux exposes —
    // memory.some sustained nonzero = swapping/compaction stalls; io.some
    // = disk-bound; cpu.some = scheduler-bound. Phone-tier early-warning.
    let psi = host_pressure_stall();
    let mut psi_some_avg10 = String::new();
    let mut psi_some_avg60 = String::new();
    let mut psi_some_avg300 = String::new();
    let mut psi_some_total = String::new();
    let mut psi_full_avg10 = String::new();
    let mut psi_full_avg60 = String::new();
    let mut psi_full_avg300 = String::new();
    let mut psi_full_total = String::new();
    for entry in &psi {
        if let Some(s) = &entry.some {
            psi_some_avg10.push_str(&format!(
                "elara_host_pressure_some_avg10{{resource=\"{}\"}} {:.4}\n",
                entry.resource, s.avg10));
            psi_some_avg60.push_str(&format!(
                "elara_host_pressure_some_avg60{{resource=\"{}\"}} {:.4}\n",
                entry.resource, s.avg60));
            psi_some_avg300.push_str(&format!(
                "elara_host_pressure_some_avg300{{resource=\"{}\"}} {:.4}\n",
                entry.resource, s.avg300));
            psi_some_total.push_str(&format!(
                "elara_host_pressure_some_total_us{{resource=\"{}\"}} {}\n",
                entry.resource, s.total_us));
        }
        if let Some(f) = &entry.full {
            psi_full_avg10.push_str(&format!(
                "elara_host_pressure_full_avg10{{resource=\"{}\"}} {:.4}\n",
                entry.resource, f.avg10));
            psi_full_avg60.push_str(&format!(
                "elara_host_pressure_full_avg60{{resource=\"{}\"}} {:.4}\n",
                entry.resource, f.avg60));
            psi_full_avg300.push_str(&format!(
                "elara_host_pressure_full_avg300{{resource=\"{}\"}} {:.4}\n",
                entry.resource, f.avg300));
            psi_full_total.push_str(&format!(
                "elara_host_pressure_full_total_us{{resource=\"{}\"}} {}\n",
                entry.resource, f.total_us));
        }
    }
    // Cgroup-scoped PSI for the elara-node service —
    // distinguishes "host struggling" from "elara-node alone struggling".
    // On a containerized phone-tier node hitting its memory.high limit,
    // host PSI stays calm while cgroup PSI lights up. Read /proc/self/cgroup
    // to auto-discover the path so the same code works whether running
    // unconstrained, as a systemd service, or inside docker/k8s.
    let cgroup_psi = process_cgroup_pressure_stall();
    let mut cgpsi_some_avg10 = String::new();
    let mut cgpsi_some_avg60 = String::new();
    let mut cgpsi_some_avg300 = String::new();
    let mut cgpsi_some_total = String::new();
    let mut cgpsi_full_avg10 = String::new();
    let mut cgpsi_full_avg60 = String::new();
    let mut cgpsi_full_avg300 = String::new();
    let mut cgpsi_full_total = String::new();
    for entry in &cgroup_psi {
        if let Some(s) = &entry.some {
            cgpsi_some_avg10.push_str(&format!(
                "elara_cgroup_pressure_some_avg10{{resource=\"{}\"}} {:.4}\n",
                entry.resource, s.avg10));
            cgpsi_some_avg60.push_str(&format!(
                "elara_cgroup_pressure_some_avg60{{resource=\"{}\"}} {:.4}\n",
                entry.resource, s.avg60));
            cgpsi_some_avg300.push_str(&format!(
                "elara_cgroup_pressure_some_avg300{{resource=\"{}\"}} {:.4}\n",
                entry.resource, s.avg300));
            cgpsi_some_total.push_str(&format!(
                "elara_cgroup_pressure_some_total_us{{resource=\"{}\"}} {}\n",
                entry.resource, s.total_us));
        }
        if let Some(f) = &entry.full {
            cgpsi_full_avg10.push_str(&format!(
                "elara_cgroup_pressure_full_avg10{{resource=\"{}\"}} {:.4}\n",
                entry.resource, f.avg10));
            cgpsi_full_avg60.push_str(&format!(
                "elara_cgroup_pressure_full_avg60{{resource=\"{}\"}} {:.4}\n",
                entry.resource, f.avg60));
            cgpsi_full_avg300.push_str(&format!(
                "elara_cgroup_pressure_full_avg300{{resource=\"{}\"}} {:.4}\n",
                entry.resource, f.avg300));
            cgpsi_full_total.push_str(&format!(
                "elara_cgroup_pressure_full_total_us{{resource=\"{}\"}} {}\n",
                entry.resource, f.total_us));
        }
    }
    // Whole-host scheduler/interrupt/FD baseline.
    // Host-wide counterparts to the per-process gauges, plus D-state
    // count and system-wide FD saturation.
    // P1-tier.
    let (host_procs_running, host_procs_blocked, host_ctxt_total, host_intr_total) =
        if collect_p1 { host_proc_stat_extras() } else { (0u64, 0u64, 0u64, 0u64) };
    let (host_fd_allocated, host_fd_max) =
        if collect_p1 { host_file_nr() } else { (0u64, 0u64) };
    // System-wide TCP/UDP socket inventory. The host FD count
    // tells you the size of the open-file pool but not what's in
    // it; sockstat distinguishes ESTABLISHED TCP, TIME_WAIT churn, orphan
    // half-closes, kernel socket-buffer memory.
    // P1-tier.
    let (
        host_sockets_used,
        host_tcp_inuse,
        host_tcp_orphan,
        host_tcp_tw,
        host_tcp_alloc,
        host_tcp_mem_pages,
        host_udp_inuse,
        host_udp_mem_pages,
    ) = if collect_p1 {
        host_sockstat()
    } else {
        (0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64)
    };
    // Per-process CPU time (utime + stime) in seconds.
    // Distinguishes "elara-node is the load source" from "host is busy with
    // something else" — system_load_1m can't tell them apart.
    // P1-tier.
    let (cpu_user_f, cpu_system_f) =
        if collect_p1 { process_cpu_seconds() } else { (0.0_f64, 0.0_f64) };
    let proc_cpu_user_secs = format!("{:.3}", cpu_user_f);
    let proc_cpu_system_secs = format!("{:.3}", cpu_system_f);
    // Per-process I/O bytes — distinguishes cached
    // reads from cold disk reads, and absorbed writes from flushed writes.
    // syscr/syscw/cancelled_write_bytes from the same
    // /proc/self/io read — surfaces avg-bytes-per-syscall and writeback-cancel
    // efficiency without paying for a second file read.
    // P1-tier.
    let (proc_io_rchar, proc_io_wchar, proc_io_read_bytes, proc_io_write_bytes,
         proc_io_syscr, proc_io_syscw, proc_io_cancelled_write_bytes) =
        if collect_p1 {
            process_io_bytes()
        } else {
            (0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64)
        };
    // Aggregate net bytes/drops across non-loopback
    // ifaces — outbound saturation is THE constraint at 10K+ node mainnet.
    // P1-tier.
    let (proc_net_rx_bytes, proc_net_tx_bytes, proc_net_rx_drops, proc_net_tx_drops) =
        if collect_p1 { process_net_bytes() } else { (0u64, 0u64, 0u64, 0u64) };
    // TCP socket-state inventory — connection-pool
    // exhaustion is a classic gossip outage signal (CLOSE_WAIT leak,
    // TIME_WAIT churn, SYN_RECV flood).
    // P1-tier.
    let (
        tcp_established,
        tcp_time_wait,
        tcp_close_wait,
        tcp_syn_recv,
        tcp_listen,
    ) = if collect_p1 {
        process_tcp_states()
    } else {
        (0u64, 0u64, 0u64, 0u64, 0u64)
    };
    // Kernel Pressure Stall Information — measures
    // task stall fraction on cpu/memory/io, the canonical early-warning
    // signal for phone-tier back-pressure (catches contention before RSS
    // or CPU saturate).
    // P1-tier (process-PSI `elara_psi_*` family is NOT in P0_EXACT;
    // P0 PSI lives under `elara_host_pressure_*` from host_pressure_stall()).
    let (
        psi_cpu_some,
        psi_cpu_full,
        psi_mem_some,
        psi_mem_full,
        psi_io_some,
        psi_io_full,
    ) = if collect_p1 {
        process_pressure_stats()
    } else {
        (0.0_f64, 0.0_f64, 0.0_f64, 0.0_f64, 0.0_f64, 0.0_f64)
    };
    // OOM-imminence + page-cache pressure. oom_score
    // is the kernel's continuously-computed "next victim" rank; oom_score_adj
    // is the operator-tunable knob (systemd OOMScoreAdjust=). Dirty/Writeback
    // from /proc/meminfo are the page-cache writeback-throttle leading
    // indicator — RocksDB submissions backing up before PSI io spikes.
    // P1-tier.
    let (
        oom_score,
        oom_score_adj,
        meminfo_dirty_kb,
        meminfo_writeback_kb,
        meminfo_cached_kb,
    ) = if collect_p1 {
        process_oom_state()
    } else {
        (0i32, 0i32, 0u64, 0u64, 0u64)
    };
    let rocksdb_live_bytes = state.rocks.total_live_bytes();
    let cont_ids = state.continuity.try_lock().map(|c| c.identity_count()).unwrap_or(0);
    let reinc_fps = state.reincarnation.try_lock().map(|r| r.fingerprint_count()).unwrap_or(0);
    let reinc_cands = state.reincarnation.try_lock().map(|r| r.candidate_count()).unwrap_or(0);

    let (rocks_memtable, rocks_cache, rocks_table_readers) = state.rocks.memory_usage();
    let (rocks_pending_compaction, rocks_running_compactions, rocks_immutable_memtables) =
        state.rocks.compaction_pressure();
    let rocks_background_errors = state.rocks.background_errors();
    let (rocks_l0_total, rocks_l0_max_cf, rocks_write_stopped_cfs, rocks_delay_rate_bps_max) =
        state.rocks.write_stall_state();
    // P1-tier — `elara_host_cpu_*_seconds_total` (scalar host totals).
    let (host_cpu_user_secs, host_cpu_system_secs, host_cpu_iowait_secs, host_cpu_softirq_secs, host_cpu_steal_secs, host_cpu_idle_secs) =
        if collect_p1 {
            host_cpu_jiffies()
        } else {
            (0.0_f64, 0.0_f64, 0.0_f64, 0.0_f64, 0.0_f64, 0.0_f64)
        };
    // Debug-tier — per-device disk IO counters (elara_host_disk_*).
    let host_disks = if collect_debug { host_disk_stats() } else { Vec::new() };
    // Per-NIC error / drop / carrier counters
    // from /proc/net/dev. Catches packet loss BELOW the TCP layer
    // (where the TCP counters stop). Phone-tier hardware ring-buffers are
    // small; rx_drop is the leading indicator that the box can't
    // drain its NIC fast enough under burst.
    // Debug-tier — per-NIC counters (elara_host_netdev_*).
    let host_netdevs = if collect_debug { host_netdev_stats() } else { Vec::new() };
    // P1-tier (all three scalar readers below).
    let (host_load_5m, host_load_15m, host_runnable_tasks, host_total_tasks) =
        if collect_p1 { host_loadavg_extra() } else { (0.0_f64, 0.0_f64, 0u64, 0u64) };
    let (process_open_fds, process_max_fds) =
        if collect_p1 { process_fd_state() } else { (0u64, 0u64) };
    let (host_tcp_retrans_segs, host_tcp_out_segs, host_tcp_attempt_fails,
         host_tcp_curr_estab, host_tcp_out_rsts, host_udp_rcvbuf_errors) =
        if collect_p1 {
            host_tcp_udp_state()
        } else {
            (0u64, 0u64, 0u64, 0u64, 0u64, 0u64)
        };
    // TcpExt deeper counters from /proc/net/netstat.
    // The snmp reader tells us "is the network path clean" — these tell us
    // "is the LOCAL TCP stack still admitting traffic at all". Listen-queue
    // overflows = accept() backlog full → the kernel dropped a SYN-ACK that
    // already completed handshake. TCP memory pressure / OOM-aborts =
    // tcp_mem 'pressure' threshold crossed → kernel actively shrinking
    // buffers or killing connections, invisible to RSS, surfaces minutes
    // before the network looks broken.
    // P1-tier.
    let (host_listen_overflows, host_listen_drops, host_tcp_timeouts,
         host_tcp_mem_pressure, host_tcp_abort_on_mem) =
        if collect_p1 {
            host_tcp_netstat_extras()
        } else {
            (0u64, 0u64, 0u64, 0u64, 0u64)
        };
    // TCP drop-class counters from /proc/net/netstat
    // TcpExt:. Distinct from the deeper-counters reader ("is the local stack
    // admitting traffic") — these are the silent-degradation counters at
    // 10K-peer mesh fanout.
    // syn_retrans = dial-time loss; rcv_q_drop = userspace not draining;
    // backlog_drop = hot-socket contention; pf_memalloc_drop = pre-OOM
    // (page-an-operator territory); spurious_rtos = jitter; lost_retransmit
    // = path collapsing. 6 lines/host, all rare-event counters.
    // P1-tier — `elara_host_tcp_*` (no per-CPU label, scalar host total).
    let TcpDropCounters {
        syn_retrans:      host_tcp_syn_retrans,
        rcv_q_drop:       host_tcp_rcv_q_drop,
        backlog_drop:     host_tcp_backlog_drop,
        pf_memalloc_drop: host_tcp_pf_memalloc_drop,
        spurious_rtos:    host_tcp_spurious_rtos,
        lost_retransmit: host_tcp_lost_retransmit,
    } = if collect_p1 { host_tcp_drops() } else { TcpDropCounters::default() };
    // Per-CPU NAPI softnet pipeline stats from
    // /proc/net/softnet_stat, aggregated cluster-style: 4 sums (processed,
    // dropped, time_squeeze, flow_limit) plus dropped_max_per_cpu to
    // surface RX imbalance without per-CPU cardinality. softnet_dropped
    // is the kernel-level packet drop counter that's INVISIBLE to per-NIC
    // metrics — when RPS pins RX to one CPU, drops happen at
    // softnet not at the NIC. dropped_max_per_cpu finds the hot CPU.
    // P1-tier — `elara_host_softnet_*` (host-wide aggregate sums).
    let SoftnetStats {
        processed_total:     host_softnet_processed,
        dropped_total:       host_softnet_dropped,
        time_squeeze_total:  host_softnet_time_squeeze,
        flow_limit_total:    host_softnet_flow_limit,
        dropped_max_per_cpu: host_softnet_dropped_max_per_cpu,
    } = if collect_p1 { host_softnet_stats() } else { SoftnetStats::default() };
    // TCP loss-recovery + ECN counters from
    // /proc/net/netstat TcpExt:. delivered_ce/delivered = AQM congestion-
    // mark rate (ECN signal); loss_probe_recovery/loss_probes = TLP
    // effectiveness; sack_reorder = wireless/cellular reorder pressure.
    // P1-tier.
    let TcpRecoveryStats {
        delivered:           host_tcp_delivered,
        delivered_ce:        host_tcp_delivered_ce,
        loss_probes:         host_tcp_loss_probes,
        loss_probe_recovery: host_tcp_loss_probe_recovery,
        sack_reorder:        host_tcp_sack_reorder,
    } = if collect_p1 { host_tcp_recovery() } else { TcpRecoveryStats::default() };
    // Host IP-layer packet pipeline counters from
    // /proc/net/snmp Ip:. Sits below the TCP-layer readers —
    // surfaces the pipeline-level drops, header errors, fragmentation /
    // reassembly failures, and out-of-route discards that never reach
    // the TCP counters above. At 10K-peer fanout these are tail-latency
    // root causes invisible from the TCP layer alone.
    // P1-tier.
    let HostIpStats {
        in_receives:    host_ip_in_receives,
        in_hdr_errors:  host_ip_in_hdr_errors,
        in_addr_errors: host_ip_in_addr_errors,
        in_discards:    host_ip_in_discards,
        in_delivers:    host_ip_in_delivers,
        out_requests:   host_ip_out_requests,
        out_discards:   host_ip_out_discards,
        out_no_routes:  host_ip_out_no_routes,
        reasm_fails:    host_ip_reasm_fails,
        frag_fails:     host_ip_frag_fails,
    } = if collect_p1 { host_ip_stats() } else { HostIpStats::default() };
    // Host UDP-layer datagram counters from
    // /proc/net/snmp Udp:. UDP doesn't retry — every drop is a permanent
    // loss to the upper layer. NoPorts catches gossip-table-rot (peer
    // sending to a closed port); InErrors/SndbufErrors split kernel-side
    // failure modes; MemErrors is the SEV2 'kernel ran out of memory
    // mid-UDP-handling'. Pairs with snmp RcvbufErrors and
    // /proc/net/sockstat UDP inuse/mem_pages.
    // P1-tier.
    let HostUdpStats {
        in_datagrams:  host_udp_in_datagrams,
        no_ports:      host_udp_no_ports,
        in_errors:     host_udp_in_errors,
        out_datagrams: host_udp_out_datagrams,
        sndbuf_errors: host_udp_sndbuf_errors,
        mem_errors:    host_udp_mem_errors,
    } = if collect_p1 { host_udp_stats() } else { HostUdpStats::default() };
    // Host ICMP-layer counters from /proc/net/snmp
    // Icmp:. Out-of-band path-error visibility: InDestUnreachs / InTimeExcds
    // tell us "the network refused to deliver our outbound packets" — a
    // signal invisible at the IP/UDP layer because the failure happened
    // off this host. OutDestUnreachs pairs 1:1 with Udp:NoPorts (peer
    // sent us a closed port → kernel auto-emits ICMP back).
    // P1-tier.
    let HostIcmpStats {
        in_msgs:           host_icmp_in_msgs,
        in_errors:         host_icmp_in_errors,
        in_csum_errors:    host_icmp_in_csum_errors,
        in_dest_unreachs:  host_icmp_in_dest_unreachs,
        in_time_excds:     host_icmp_in_time_excds,
        in_redirects:      host_icmp_in_redirects,
        out_msgs:          host_icmp_out_msgs,
        out_dest_unreachs: host_icmp_out_dest_unreachs,
        out_time_excds:    host_icmp_out_time_excds,
    } = if collect_p1 { host_icmp_stats() } else { HostIcmpStats::default() };
    // VM / page-fault counters from /proc/vmstat.
    // pgmajfault is the canonical phone-tier RAM-pressure cliff signal;
    // pgsteal_kswapd is its leading indicator (kswapd reclaiming pages
    // before allocations stall). oom_kill increment is a SEV1 — any
    // rise means the kernel killed something with no graceful path.
    // pswpin/pswpout should be 0 on phone-tier (we disable swap); any
    // rise means swap is enabled by accident OR co-tenant noise.
    // P1-tier — `elara_host_vmstat_*` (large /proc/vmstat read).
    let (host_pgmajfault, host_pgsteal_kswapd, host_oom_kill,
         host_pswpin, host_pswpout) =
        if collect_p1 {
            host_vmstat_pressure()
        } else {
            (0u64, 0u64, 0u64, 0u64, 0u64)
        };
    // Per-process scheduler statistics from
    // /proc/self/schedstat. exec_runtime + run_delay tell us "is
    // elara-node specifically getting CPU when ready" — distinct from
    // PSI cpu (system-wide) and host CPU jiffies (also system-wide).
    // The derived ratio rate(run_delay) / rate(exec + run_delay) is
    // the scheduling-pressure signal that catches co-tenant starvation
    // when the box itself looks idle.
    // P1-tier.
    let (proc_sched_exec_ns, proc_sched_delay_ns, proc_sched_pcount) =
        if collect_p1 { process_schedstat() } else { (0u64, 0u64, 0u64) };
    let proc_sched_exec_secs  = format!("{:.3}", proc_sched_exec_ns  as f64 / 1_000_000_000.0);
    let proc_sched_delay_secs = format!("{:.3}", proc_sched_delay_ns as f64 / 1_000_000_000.0);

    // Cumulative PSI stall counters in microseconds
    // from /proc/pressure/{cpu,memory,io} `total=` field. Complements
    // the avg10 gauges with the counter shape needed for PromQL
    // rate() over operator-chosen windows. cpu_full omitted because
    // kernel docs flag it as ill-defined (always 0 on ≥5.13).
    // P1-tier — `elara_host_pressure_*_total_us` is P1 (the avg10
    // family at P0 reads from a separate helper, host_pressure_stall, so
    // gating this one at P1 doesn't strip P0 metrics).
    let (host_psi_cpu_some_us, host_psi_mem_some_us, host_psi_mem_full_us,
         host_psi_io_some_us,  host_psi_io_full_us) =
        if collect_p1 {
            process_pressure_totals_us()
        } else {
            (0u64, 0u64, 0u64, 0u64, 0u64)
        };

    // Cgroup v2 memory accounting from
    // /sys/fs/cgroup/<own>/memory.{current,max,high,swap.current,events}.
    // Phone-tier mainnet runs inside cgroups (systemd MemoryLimit, k8s,
    // mobile container) where memory.max < host memory and OOM-kill
    // fires at the cgroup limit not the host limit. process RSS
    // cannot see this cliff because the cgroup limit is
    // separate. memory.current includes page cache + slab attributed
    // to the cgroup, so a node with RSS=150 MB can hit memory.current
    // 1.8 GB if RocksDB SST reads warmed the cache under a 2 GB cap.
    // The memory.events extension exposes all six
    // memory.events kernel keys. low/max/oom/oom_group_kill are leading
    // indicators distinct from oom_kill (which is the process-kill
    // event). One file read covers all of them.
    // P1-tier — `elara_cgroup_memory_*` (cgroup file reads).
    let (cg_mem_current, cg_mem_max, cg_mem_high,
         cg_mem_swap_current, cg_mem_oom_kill, cg_mem_high_throttle,
         cg_mem_ev_low, cg_mem_ev_max, cg_mem_ev_oom, cg_mem_ev_oom_group_kill) =
        if collect_p1 {
            cgroup_memory_state()
        } else {
            (0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64)
        };

    // Cgroup v2 memory.stat detailed breakdown.
    // memory.current is a single number — useful for "approaching
    // max?" but blind to *what kind* of memory dominates. anon vs file vs
    // kernel split is the difference between "real leak" and "page cache
    // doing its job"; pgfault/pgmajfault/workingset_refault_file give
    // early-warning visibility into cache pressure BEFORE OOM headroom
    // collapses. One file read covers all six metrics.
    // P1-tier.
    let cg_mem_breakdown = if collect_p1 {
        cgroup_memory_stat_breakdown()
    } else {
        CgroupMemoryStat::default()
    };
    let cg_mem_anon = cg_mem_breakdown.anon;
    let cg_mem_file = cg_mem_breakdown.file;
    let cg_mem_kernel = cg_mem_breakdown.kernel;
    let cg_mem_pgfault = cg_mem_breakdown.pgfault;
    let cg_mem_pgmajfault = cg_mem_breakdown.pgmajfault;
    let cg_mem_ws_refault_file = cg_mem_breakdown.workingset_refault_file;

    // Cgroup v2 CPU accounting from
    // /sys/fs/cgroup/<own>/cpu.stat + cpu.max. Pairs with the cgroup
    // memory readers to complete the cgroup-state observability set. usage_us /
    // user_us / system_us let operators detect a co-tenant CPU steal
    // by diffing usage vs (proc_cpu_time_user+system) — if process-
    // level says we ran but cgroup says we didn't, the noisy-neighbor
    // ate our slice. Throttle counters are silent on phone-tier
    // (no quota set) and visible on managed-cluster runs (k8s, ECS,
    // systemd CPUQuota). throttle_us > 0 with quota=0 is impossible;
    // throttle_us climbing under a finite quota means the cgroup
    // is queue-limited and tail latencies will spike.
    // P1-tier.
    let (cg_cpu_usage_us, cg_cpu_user_us, cg_cpu_system_us,
         cg_cpu_throttled_us, cg_cpu_nr_throttled,
         cg_cpu_quota_us, cg_cpu_period_us) =
        if collect_p1 {
            cgroup_cpu_state()
        } else {
            (0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64)
        };

    // Aggregate softirq counters from
    // /proc/softirqs. Sum across CPUs (no per-CPU label) so cardinality
    // stays at 5 lines/host. Per-CPU imbalance still surfaces because
    // a kernel pinning RX softirqs to one CPU shows the AGGREGATE
    // climbing while user-mode CPU time on the other cores stays flat
    // — operators correlate across the cgroup CPU reader + this counter
    // to localize "one CPU is melting under softirq" without paying
    // the per-CPU cardinality tax. NET_RX is the single most-actionable
    // signal: phone-tier RPS (Receive Packet Steering) defaults often
    // pin all NIC interrupts to CPU0; gossip-fanout floods that one core.
    // P1-tier — `elara_host_softirq_*` (large /proc/softirqs read,
    // per-CPU rows summed in helper; cardinality is host-aggregate scalars).
    let (sirq_net_rx, sirq_net_tx, sirq_block, sirq_sched, sirq_timer) =
        if collect_p1 {
            host_softirq_totals()
        } else {
            (0u64, 0u64, 0u64, 0u64, 0u64)
        };

    // Memory fragmentation snapshot from
    // /proc/buddyinfo. Counts free pages at orders 0 (4 KB),
    // 4 (64 KB), 8 (1 MB), summed across all NUMA nodes and
    // memory zones. Phone-tier 2 GB nodes fragment under sustained
    // RocksDB compaction churn — high-order pages drain to 0 and
    // hugepage mmap fallbacks slow down the read path before
    // memory.current OR PSI memory show any sign of trouble.
    // P1-tier.
    let (buddy_order0, buddy_order4, buddy_order8) =
        if collect_p1 { host_buddy_free_pages() } else { (0u64, 0u64, 0u64) };

    // Jemalloc internal accounting via mallctl. Six gauges paint a
    // picture the cgroup memory.current single number can't: allocated
    // (live bytes Rust thinks it owns) vs resident (RSS jemalloc holds, of
    // which much is unused but un-purged) vs retained (mapped-but-unused,
    // available for re-use without syscall). When (resident - allocated)
    // grows steadily on a long-running node, jemalloc is fragmenting and
    // a `mallctl arena.<i>.purge` is the right intervention — this metric
    // makes that visible BEFORE OOM-killer fires. Free on every scrape
    // (one epoch advance + 6 reads, microseconds total).
    // P1-tier — `elara_jemalloc_*` (mallctl reads, very cheap but
    // skipping at P0 still saves a half-dozen syscalls per scrape).
    let (jem_allocated, jem_active, jem_resident, jem_metadata, jem_mapped, jem_retained) =
        if collect_p1 {
            host_jemalloc_stats()
        } else {
            (0u64, 0u64, 0u64, 0u64, 0u64, 0u64)
        };

    // Per-device disk samples. Build one Prometheus line per
    // (metric, device) combo so dashboards can sum() over the device label
    // (replicating the aggregate) OR slice by it (which device is
    // saturated — OS root vs RocksDB data NVMe).
    let (mut disk_reads_lines, mut disk_writes_lines, mut disk_rsec_lines,
         mut disk_wsec_lines, mut disk_rms_lines, mut disk_wms_lines,
         mut disk_inflight_lines) = (
        String::new(), String::new(), String::new(), String::new(),
        String::new(), String::new(), String::new(),
    );
    // Separate accumulators for the four new fields. Same per-device
    // cardinality as the base disk samples (1-3 physical block devices per host),
    // so adding them here keeps the cardinality budget unchanged.
    let (mut disk_io_ms_lines, mut disk_weighted_io_ms_lines,
         mut disk_flushes_lines, mut disk_flush_ms_lines) = (
        String::new(), String::new(), String::new(), String::new(),
    );
    // Per-device discard counters. Same per-device cardinality
    // budget (1-3 physical block devices); no new label dimensions, so
    // the cardinality envelope is unchanged from the other disk families.
    let (mut disk_discards_lines, mut disk_discards_merged_lines,
         mut disk_discard_sectors_lines, mut disk_discard_ms_lines) = (
        String::new(), String::new(), String::new(), String::new(),
    );
    // Per-NIC accumulators. Cardinality is small (1-3 real
    // interfaces per box: 1 wired + 1 Tailscale on testnet VPS);
    // virtual bridges (docker/veth/br-*) are filtered in the
    // helper, so the cardinality budget is bounded by real hardware.
    let (mut netdev_rx_errs_lines, mut netdev_rx_drop_lines,
         mut netdev_tx_errs_lines, mut netdev_tx_drop_lines,
         mut netdev_tx_carrier_lines) = (
        String::new(), String::new(), String::new(),
        String::new(), String::new(),
    );
    for n in &host_netdevs {
        use std::fmt::Write as _;
        let _ = writeln!(netdev_rx_errs_lines,    "elara_host_netdev_rx_errs_total{{device=\"{}\"}} {}",    n.device, n.rx_errs);
        let _ = writeln!(netdev_rx_drop_lines,    "elara_host_netdev_rx_drop_total{{device=\"{}\"}} {}",    n.device, n.rx_drop);
        let _ = writeln!(netdev_tx_errs_lines,    "elara_host_netdev_tx_errs_total{{device=\"{}\"}} {}",    n.device, n.tx_errs);
        let _ = writeln!(netdev_tx_drop_lines,    "elara_host_netdev_tx_drop_total{{device=\"{}\"}} {}",    n.device, n.tx_drop);
        let _ = writeln!(netdev_tx_carrier_lines, "elara_host_netdev_tx_carrier_total{{device=\"{}\"}} {}", n.device, n.tx_carrier);
    }
    for d in &host_disks {
        use std::fmt::Write as _;
        let _ = writeln!(disk_reads_lines,    "elara_host_disk_reads_total{{device=\"{}\"}} {}", d.device, d.reads);
        let _ = writeln!(disk_writes_lines,   "elara_host_disk_writes_total{{device=\"{}\"}} {}", d.device, d.writes);
        let _ = writeln!(disk_rsec_lines,     "elara_host_disk_read_sectors_total{{device=\"{}\"}} {}", d.device, d.read_sectors);
        let _ = writeln!(disk_wsec_lines,     "elara_host_disk_write_sectors_total{{device=\"{}\"}} {}", d.device, d.write_sectors);
        let _ = writeln!(disk_rms_lines,      "elara_host_disk_read_ms_total{{device=\"{}\"}} {}", d.device, d.read_ms);
        let _ = writeln!(disk_wms_lines,      "elara_host_disk_write_ms_total{{device=\"{}\"}} {}", d.device, d.write_ms);
        let _ = writeln!(disk_inflight_lines, "elara_host_disk_in_flight{{device=\"{}\"}} {}", d.device, d.in_flight);
        let _ = writeln!(disk_io_ms_lines,          "elara_host_disk_io_ms_total{{device=\"{}\"}} {}", d.device, d.io_ms);
        let _ = writeln!(disk_weighted_io_ms_lines, "elara_host_disk_weighted_io_ms_total{{device=\"{}\"}} {}", d.device, d.weighted_io_ms);
        let _ = writeln!(disk_flushes_lines,        "elara_host_disk_flushes_total{{device=\"{}\"}} {}", d.device, d.flushes);
        let _ = writeln!(disk_flush_ms_lines,       "elara_host_disk_flush_ms_total{{device=\"{}\"}} {}", d.device, d.flush_ms);
        let _ = writeln!(disk_discards_lines,         "elara_host_disk_discards_total{{device=\"{}\"}} {}",         d.device, d.discards);
        let _ = writeln!(disk_discards_merged_lines,  "elara_host_disk_discards_merged_total{{device=\"{}\"}} {}",  d.device, d.discards_merged);
        let _ = writeln!(disk_discard_sectors_lines,  "elara_host_disk_discard_sectors_total{{device=\"{}\"}} {}",  d.device, d.sectors_discarded);
        let _ = writeln!(disk_discard_ms_lines,       "elara_host_disk_discard_ms_total{{device=\"{}\"}} {}",       d.device, d.discard_ms);
    }

    // Surface the post-clamp disk_cap_bytes so operators can see the
    // value GC actually drives against (vs. the configured/default value,
    // which may have been clamped down at boot to fit the actual filesystem).
    let disk_cap_bytes_effective: u64 = state.config.disk_cap_bytes;

    let body = format!("{body}\
         # HELP elara_disk_total_mb Total disk space in MB on the data_dir filesystem (statvfs f_blocks × f_frsize). Captures the disk volume the node writes RocksDB + WAL + checkpoint backups to. Static unless the volume is resized.\n\
         # TYPE elara_disk_total_mb gauge\n\
         elara_disk_total_mb {disk_total_mb}\n\
         # HELP elara_disk_available_mb Available disk space in MB on the data_dir filesystem (statvfs f_bavail x f_frsize). Operator alert: <2048 MB on a phone-tier or canary node OR <512 MB on any node = page operator. <512 MB or >95% full ALSO trips elara_disk_pressure=1 internally (rejects new submissions). Common growth sources, in order of past-incident frequency: (1) pre-migration backup dirs - old migrations may leave a `pre-migration-v{{N}}-backup` checkpoint; sweep now auto-prunes on every boot (kept: rollback target only). (2) checkpoint dirs `checkpoints/checkpoint_*` retained by hand for recovery - each ~20 GB on a large chain; rotate manually when not under active rollback. (3) WAL/SST tiered growth - bounded by retention windows.\n\
         # TYPE elara_disk_available_mb gauge\n\
         elara_disk_available_mb {disk_avail_mb}\n\
         # HELP elara_disk_inodes_total Total inode count on the data_dir filesystem (statvfs f_files). GAUGE. Static unless filesystem is reformatted. At mainnet scale (1M zones × ~50 SST files/zone = 50M inodes) phone-tier eMMC formatted with default mkfs.ext4 (~300K inodes/GB) on a 32 GB partition has only ~10M inodes — that runs out of inodes BEFORE running out of bytes. The bytes-side gauges (disk_total_mb / disk_available_mb) cannot see this cliff: write() returns ENOSPC because no inode is free, even though `df -h` says the disk has 80% bytes free. Operators read this metric ONCE at boot to verify the partition is sized for the zone count it'll host; sustained alerts come from inodes_available, not this one.\n\
         # TYPE elara_disk_inodes_total gauge\n\
         elara_disk_inodes_total {disk_inodes_total}\n\
         # HELP elara_disk_inodes_available Free inodes on the data_dir filesystem (statvfs f_ffree). GAUGE. Counterpart to disk_available_mb but for inodes — neither one alone is sufficient on phone-tier. RocksDB SST files are MANY (each compaction layer writes thousands of files); WAL adds more; checkpoints multiply by N (each checkpoint hardlinks every SST). At sustained zone growth this gauge drains; alert at `< total/4` (75% inodes used) on phone-tier so operators have one full SST-rotation cycle of headroom before write() starts ENOSPC'ing. 0 means f_ffree was not retrievable (statvfs failed) — distinct from 0 free inodes (which means the FS is full and write() is failing right now).\n\
         # TYPE elara_disk_inodes_available gauge\n\
         elara_disk_inodes_available {disk_inodes_avail}\n\
         # HELP elara_disk_cap_bytes_effective Post-clamp 'disk_cap_bytes' - the value GC actually drives against for size-based retention compression (gc.rs:319). 0 = size-based retention disabled. The default is clamped to 70% of statvfs total at boot so GC has a real target on every host. If this gauge is far above `elara_disk_total_mb * 1024 * 1024 * 0.7` it means the operator set `ELARA_DISK_CAP_BYTES` explicitly (clamp respects operator opt-out). If below, the auto-clamp fired.\n\
         # TYPE elara_disk_cap_bytes_effective gauge\n\
         elara_disk_cap_bytes_effective {disk_cap_bytes_effective}\n\
         # HELP elara_process_rss_kb Process resident set size in KB\n\
         # TYPE elara_process_rss_kb gauge\n\
         elara_process_rss_kb {mem_rss_kb}\n\
         # HELP elara_process_vmpeak_kb High-water mark of virtual memory ever held by this process (kB) via /proc/self/status VmPeak. Monotonically increasing per process — never resets short of restart. RSS deflates when memory is reclaimed, but VmPeak preserves the spike. Use this for post-mortem on transient memory blowups: if RSS is now 600 MB but VmPeak is 4.5 GB, the process briefly tried to allocate 4.5 GB and got reclaimed — typically a streaming pull that buffered everything, an unbounded queue, or an unbounded-iter loop in a hot path. Sustained VmPeak ≈ RSS is the healthy steady-state shape.\n\
         # TYPE elara_process_vmpeak_kb gauge\n\
         elara_process_vmpeak_kb {proc_vmpeak_kb}\n\
         # HELP elara_process_vmswap_kb Bytes paged out to swap (kB) via /proc/self/status VmSwap. Sustained >0 is the canonical phone-tier death signal — once the kernel has paged out state_core working set, every read pays a synchronous disk roundtrip until the page faults back in. On a 2 GB phone-tier node with 1 GB swap configured, a single heavy compaction or pull-spike can flip this from 0 to 100s of MB and cripple latency. Operator alert: ANY non-zero on a hot path; pair with elara_process_major_faults_total rate to confirm thrashing-vs-stable-paged-out.\n\
         # TYPE elara_process_vmswap_kb gauge\n\
         elara_process_vmswap_kb {proc_vmswap_kb}\n\
         # HELP elara_process_threads Live thread count via /proc/self/status Threads. The Tokio runtime worker pool is fixed-size (typically `num_cpus` workers + a separate blocking pool capped at `max_blocking_threads`, default 512); steady-state thread count = workers + a few helpers. A sustained climb above ~16 + (max_blocking_threads / 2) means async tasks are blocking on syscalls and the runtime is forced to spawn extra blocking workers — back-pressure has escaped from the async layer into the OS thread layer. Pair with elara_process_vmswap_kb: blocking on disk I/O while paged-out = double-trouble.\n\
         # TYPE elara_process_threads gauge\n\
         elara_process_threads {proc_threads}\n\
         # HELP elara_process_vmhwm_kb High-water mark of resident memory (RSS) ever held by this process (kB) via /proc/self/status VmHWM. Distinct from elara_process_vmpeak_kb which tracks virtual-address-space peak — VmHWM tracks the physical-memory peak, so it is the OOM-relevant cliff. Use this for OOM post-mortem: if RSS is now 800 MB but VmHWM is 1.9 GB on a 2 GB phone-tier node, the process briefly hit the OOM cliff and lived through reclaim. Sustained VmHWM ≈ RSS = healthy steady state; VmHWM ≫ RSS = transient blowup happened (look back in elara_process_major_faults_total rate around the same time).\n\
         # TYPE elara_process_vmhwm_kb gauge\n\
         elara_process_vmhwm_kb {proc_vmhwm_kb}\n\
         # HELP elara_process_ctxt_switches_voluntary_total Cumulative voluntary context switches via /proc/self/status voluntary_ctxt_switches. Increments every time the process yields the CPU willingly — blocked on I/O, futex, sleep. Healthy for an I/O-bound async runtime: a Tokio worker yields every poll, so rate ≈ poll-loop frequency × active-task count. The 'good' half of the pair: worry only when this is flat (process not yielding = hot CPU loop spinning on the runtime) or when the ratio against nonvoluntary inverts.\n\
         # TYPE elara_process_ctxt_switches_voluntary_total counter\n\
         elara_process_ctxt_switches_voluntary_total {proc_ctxt_voluntary}\n\
         # HELP elara_process_ctxt_switches_nonvoluntary_total Cumulative nonvoluntary context switches via /proc/self/status nonvoluntary_ctxt_switches. Increments every time the kernel preempts the process before its quantum expires - almost always because another process took the CPU. On shared-VPS or phone-tier nodes this is the canonical 'noisy neighbor' signal. rate(nonvoluntary[5m]) >> rate(voluntary[5m]) = host is contended and elara-node is being starved by neighbor workloads. Operator alert: sustained nonvoluntary rate > voluntary rate for 30+ min on a node not under heavy load = consider migrating off the contended host. On a dedicated node nonvoluntary should be a small fraction of voluntary.\n\
         # TYPE elara_process_ctxt_switches_nonvoluntary_total counter\n\
         elara_process_ctxt_switches_nonvoluntary_total {proc_ctxt_nonvoluntary}\n\
         # HELP elara_process_rss_anon_kb Anonymous resident-memory bytes (kB) — the heap elara-node actually owns, from /proc/self/status RssAnon. GAUGE. RSS = RssAnon + RssFile + RssShmem. The anon half is Rust allocations + thread stacks + COW'd anonymous pages; the kernel CANNOT reclaim these without swapping. Steady growth here against a flat workload = a real memory leak or working-set inflation. Compare: RssAnon should align with elara_jemalloc_allocated_bytes modulo allocator-page slack — a divergence means either the allocator is fragmenting (jemalloc retained climbs while RssAnon stays flat) or there's non-jemalloc heap (libc malloc, mmap'd buffers). Phone-tier alert: RssAnon > 70% of total RAM on a 2 GB node = OOM-killer one bad compaction away.\n\
         # TYPE elara_process_rss_anon_kb gauge\n\
         elara_process_rss_anon_kb {proc_rss_anon_kb}\n\
         # HELP elara_process_rss_file_kb File-backed resident-memory bytes (kB) — the page cache holding our mmap'd files, from /proc/self/status RssFile. GAUGE. Mostly RocksDB SST blocks pulled into cache, plus the elara-node binary text+rodata, plus snapshot/wire buffers. HIGH RssFile is HEALTHY: hot RocksDB blocks resident = reads hit cache. Under memory pressure the kernel reclaims this half FIRST, before touching RssAnon. The canonical phone-tier thrash signature on a 2 GB node: RssFile drops from ~800 MB to ~200 MB while RssAnon climbs ~200 MB → kernel shrinking page cache to make room for our heap → every subsequent read misses cache → elara_process_io_read_bytes_total rate spikes. Watching the trio together (RssAnon up, RssFile down, read_bytes rate up) gives the cause-effect chain in three gauges.\n\
         # TYPE elara_process_rss_file_kb gauge\n\
         elara_process_rss_file_kb {proc_rss_file_kb}\n\
         # HELP elara_process_rss_shmem_kb Shared-memory resident bytes (kB) — POSIX shm + tmpfs + sysv shm pages held by elara-node, from /proc/self/status RssShmem. GAUGE. Baseline is 0 or a small constant — elara-node does not intentionally use shared memory. Non-zero growth means: a sidecar daemon mapped a tmpfs we inherited, an mmap of /dev/shm, or systemd-journal-gateway forwarding via shm. Worth alerting on any sustained drift from baseline because it's not in our code path — investigate which inherited fd is holding the shared mapping. RSS = RssAnon + RssFile + RssShmem identity check: if the trio doesn't sum to elara_process_rss_kb (within 1-page rounding), the kernel /proc/self/status format has drifted.\n\
         # TYPE elara_process_rss_shmem_kb gauge\n\
         elara_process_rss_shmem_kb {proc_rss_shmem_kb}\n\
         # HELP elara_meminfo_total_kb Total host RAM (kB) from /proc/meminfo MemTotal. GAUGE. Denominator for every memory-pressure ratio. On a VPS this can be subtly different from the plan's nominal RAM — kernel reserves 1-3% for crashdump / hypervisor balloon — surface it so operators can sanity-check what they're paying for vs what's usable. Effectively constant per-host (only changes on memory hotplug or VPS replan).\n\
         # TYPE elara_meminfo_total_kb gauge\n\
         elara_meminfo_total_kb {meminfo_total_kb}\n\
         # HELP elara_meminfo_available_kb Kernel-computed 'really free' RAM (kB) from /proc/meminfo MemAvailable. GAUGE. THE primary OOM-imminence signal — better than MemFree because it accounts for reclaimable cache + reclaimable slab minus per-zone watermarks. Phone-tier alert: MemAvailable / MemTotal < 0.10 sustained = OOM-kill within minutes on a busy node. Steady-state on a healthy 2 GB node sits around 30-50% of MemTotal. Drops in MemAvailable while RssAnon climbs = page cache being reclaimed under heap pressure (the canonical thrash signature, see elara_process_rss_file_kb).\n\
         # TYPE elara_meminfo_available_kb gauge\n\
         elara_meminfo_available_kb {meminfo_available_kb}\n\
         # HELP elara_meminfo_free_kb Strictly unallocated host RAM (kB) from /proc/meminfo MemFree. GAUGE. Always ≤ MemAvailable. The gap (MemAvailable - MemFree) tells you how much of the 'free' memory is actually reclaimable cache that other workloads might compete for. On a healthy steady-state node MemFree is small — most RAM is doing useful work as cache or anonymous mappings; sustained MemFree → MemAvailable means caches got dumped (recent reclaim event). Sudden jump UP after sustained near-zero = workload just released memory or kernel just reclaimed.\n\
         # TYPE elara_meminfo_free_kb gauge\n\
         elara_meminfo_free_kb {meminfo_free_kb}\n\
         # HELP elara_meminfo_buffers_kb Block-device cache (kB) from /proc/meminfo Buffers. GAUGE. Distinct from Cached (page cache for file-backed pages) — Buffers is raw disk-block cache, populated when something reads /dev/sda directly (LVM scans, RAID metadata, partition table reads). Usually small (~1% of RAM); growth past 100 MB = LVM/RAID metadata churn or a misbehaving daemon doing raw block I/O. Pair with elara_meminfo_cached_kb to see the full kernel-cache picture: Buffers + Cached + (small overhead) is approximately the kernel's reclaimable cache budget.\n\
         # TYPE elara_meminfo_buffers_kb gauge\n\
         elara_meminfo_buffers_kb {meminfo_buffers_kb}\n\
         # HELP elara_meminfo_slab_kb Kernel slab cache total (kB) from /proc/meminfo Slab. GAUGE. The kernel's small-object allocator: dentry cache (path lookups), inode cache, kmalloc-* buckets, network skbuffs, socket buffers, RocksDB-related FD/inode entries. Grows with FD count, mount points, network connection count. Phone-tier 2 GB node steady-state: 50-200 MB. Sustained climb without a corresponding workload change = kernel slab leak (rare but documented in older kernel versions); check 'slabtop' from a privileged shell to find the offending cache. Pair with elara_process_open_fds_count: per-FD cost is ~1 KB of slab.\n\
         # TYPE elara_meminfo_slab_kb gauge\n\
         elara_meminfo_slab_kb {meminfo_slab_kb}\n\
         # HELP elara_meminfo_sreclaimable_kb Reclaimable subset of slab (kB) from /proc/meminfo SReclaimable. GAUGE. The portion of Slab that the kernel CAN free under memory pressure (mostly dentry + inode cache). The non-reclaimable remainder (Slab - SReclaimable) is real kernel overhead we cannot win back. Sustained growth in (Slab - SReclaimable) without workload growth = kernel-side leak source; that residual is included in MemAvailable's denominator and bites hardest on phone-tier where every MB matters.\n\
         # TYPE elara_meminfo_sreclaimable_kb gauge\n\
         elara_meminfo_sreclaimable_kb {meminfo_sreclaimable_kb}\n\
         # HELP elara_meminfo_swap_total_kb Total swap configured on the host (kB) from /proc/meminfo SwapTotal. GAUGE. Effectively constant per-host (changes only on swapon/swapoff). Zero on phone-tier nodes — we run swapless to avoid eMMC/SD wear. Non-zero on legacy hosts; surface so operators can sanity-check that swap is or isn't configured matching their playbook.\n\
         # TYPE elara_meminfo_swap_total_kb gauge\n\
         elara_meminfo_swap_total_kb {meminfo_swap_total_kb}\n\
         # HELP elara_meminfo_swap_free_kb Unused swap space (kB) from /proc/meminfo SwapFree. GAUGE. SwapTotal - SwapFree = swap actually used. Any non-zero swap-used value on a phone-tier node = the kernel is paging anonymous memory to disk, which on eMMC/SD is a latency catastrophe (10-100 ms per page-in vs 100 ns per RAM access). Mainnet alert: rate of SwapFree DECREASING + RssAnon CLIMBING = imminent swap-thrash; pair with elara_psi_mem_full_avg10. On swapless hosts (most phone-tier) this stays equal to SwapTotal forever.\n\
         # TYPE elara_meminfo_swap_free_kb gauge\n\
         elara_meminfo_swap_free_kb {meminfo_swap_free_kb}\n\
         # HELP elara_meminfo_page_tables_kb Kernel memory used for page-table entries (kB) from /proc/meminfo PageTables. GAUGE. Grows linearly with our mmap region count (RocksDB SST files, the binary's text+rodata, snapshot temp files) and process count. On x86_64 the per-page cost is ~8 bytes per 4 KB mapping (0.2% overhead) — for our 1-2 GB resident sets that's typically 4-8 MB of PageTables. Sustained growth past ~100 MB on a 2 GB node = excessive mmap fragmentation (perhaps RocksDB SST count grew unboundedly); pair with elara_process_rss_file_kb to confirm the cost matches our usage. NOT included in RssFile/RssAnon — it's kernel-side overhead the process pays for indirectly.\n\
         # TYPE elara_meminfo_page_tables_kb gauge\n\
         elara_meminfo_page_tables_kb {meminfo_page_tables_kb}\n\
         # HELP elara_process_blkio_wait_seconds_total Per-process aggregated time blocked on disk I/O, in seconds, derived from /proc/self/stat field 42 (delayacct_blkio_ticks) ÷ sysconf(_SC_CLK_TCK). COUNTER. Distinct from every other I/O signal we expose: elara_process_io_*_bytes is throughput not wait time; elara_psi_io_some_avg10 is host-wide and includes neighbor-process compactions; elara_process_schedstat_* is wait time for a CPU not for disk. Answers the precise question 'how much wall-clock time did THIS process spend with at least one task blocked on a block-IO request'. Steady state on a quiet 6-node testnet: rate near zero. Phone-tier alert: rate(elara_process_blkio_wait_seconds_total[5m]) > 0.1 (10% of wall time blocked on disk) = the bottleneck IS the disk and elara-node specifically is paying for it — fastest leading indicator of RocksDB compaction back-pressure even when host-level PSI looks calm. Requires CONFIG_TASK_DELAY_ACCT=y; reports 0 on hosts without delay accounting (kernel option default-on since 2018).\n\
         # TYPE elara_process_blkio_wait_seconds_total counter\n\
         elara_process_blkio_wait_seconds_total {proc_blkio_wait_secs}\n\
         # HELP elara_host_thermal_celsius Per-zone CPU/SoC thermal temperature in degrees Celsius from /sys/class/thermal/thermal_zone*/temp. GAUGE family with two labels - zone (kernel zone name e.g. thermal_zone0) and type (kernel zone type e.g. x86_pkg_temp, coretemp, cpu-thermal, acpitz). Empty on virtualised cloud nodes - the hypervisor abstracts CPU thermals so /sys/class/thermal is missing and we emit zero rows; an absent metric family is the correct fallback for 'this host can't tell us the temperature'. Live on phone-tier hardware (laptops, mini PCs, Pi-class boards). Phone-tier alert: any zone reporting > 80 degC sustained = thermal throttling territory; the kernel scales clock to ~60% at the ACPI passive trip point (typically 85-90 degC) and elara-node performance silently degrades 30-40% with no other signal in /metrics. The clock-gate signature: elara_host_thermal_celsius climbing past 80 + rate(elara_process_cpu_user_seconds_total[1m]) flattening = throttling already active. Source: /sys/class/thermal/thermal_zone*/temp (millidegrees C / 1000).\n\
         # TYPE elara_host_thermal_celsius gauge\n\
         {thermal_rows}\
         # HELP elara_host_hwmon_temp_celsius Per-chip / per-sensor temperatures from /sys/class/hwmon/hwmon*/temp*_input. GAUGE family with three labels — chip (driver name from `name` file: coretemp, k10temp, nvme, dell_smm, acpitz), sensor (temp{{N}} canonical id), label (human-readable from temp{{N}}_label or empty). Complements elara_host_thermal_celsius which only covers the older /sys/class/thermal/thermal_zone* interface — modern x86 laptops route CPU temperatures through hwmon (coretemp for Intel, k10temp for AMD) and have no thermal_zone entries. Phone-tier value: per-core CPU temperatures let us distinguish 'whole package hot' (uniform load) from 'core N pinned' (one workload thread saturating one core), which is the difference between an alert that says nothing and an alert that names the offending thread. Also surfaces NVMe SSD package temps (chip='nvme', label='Composite') — eMMC/NVMe thermal throttle stalls write throughput in a way that's invisible at the host CPU level. Empty on virtualised cloud VPSs. Source: /sys/class/hwmon/hwmon*/temp{{N}}_input (millidegrees C ÷ 1000) + companion temp{{N}}_label.\n\
         # TYPE elara_host_hwmon_temp_celsius gauge\n\
         {hwmon_rows}\
         # HELP elara_host_cpu_frequency_hz Per-CPU current clock frequency in Hz from /sys/devices/system/cpu/cpu*/cpufreq/scaling_cur_freq. GAUGE family with one label - cpu (numeric core id, '0','1','...'). Empty on virtualised cloud nodes where the hypervisor manages clock and the cpufreq directory exists but scaling_cur_freq is absent. Live on phone-tier hardware with cpufreq governor active. The visible CONSEQUENCE of thermal throttling - pairs with thermal metrics to make alerts actionable. Phone-tier diagnostic: temperature climbing past 80 degC while cpu frequency drops from 3.5 GHz to 2.0 GHz = clock gate actively throttling, a 30-40% silent perf degradation. If frequency is pinned at scaling_min_freq for sustained periods without thermal pressure, something else is holding the clock down (PSU rail droop, battery-saver, conservative governor). Pair with rate(elara_process_cpu_user_seconds_total[1m]): at fixed workload, user-time-rate scales linearly with frequency. Source: scaling_cur_freq (kHz) x 1000 = Hz per Prometheus SI-base-unit convention.\n\
         # TYPE elara_host_cpu_frequency_hz gauge\n\
         {cpu_freq_rows}\
         # HELP elara_process_rlimit_soft Process resource ceiling (soft limit) from /proc/self/limits. GAUGE family with one label — resource (snake_case from /proc/self/limits 'Max...' rows: max_open_files, max_processes, max_address_space, max_locked_memory, max_pending_signals, max_msgqueue_size, max_nice_priority, max_realtime_priority, max_realtime_timeout, max_resident_set, max_stack_size, max_core_file_size, max_data_size, max_file_size, max_file_locks, max_cpu_time). 'unlimited' encodes as 18446744073709551615 (u64::MAX) so a single gauge type handles bounded and unbounded ceilings without sentinel collision. Phone-tier value: max_open_files (RLIMIT_NOFILE) is the silent strangler at mainnet 10K-conn — when systemd defaults to 1024 fds and the node tries to peer with 8K nodes, accept() returns EMFILE and the gossip layer goes asymptotically deaf with no other signal in /metrics. Same shape for max_processes (futex contention masquerades as scheduler delay), max_address_space (RocksDB block cache + WAL + memtables), max_locked_memory (mmap'd SST files). Surfacing these as gauges enables (used / limit) > 0.8 alerts BEFORE the ceiling is hit, instead of post-hoc strace forensics. Pair with elara_process_open_fds for the open-fds-vs-RLIMIT_NOFILE saturation alert.\n\
         # TYPE elara_process_rlimit_soft gauge\n\
         {rlimit_soft_rows}\
         # HELP elara_process_rlimit_hard Process resource ceiling (hard limit) from /proc/self/limits — same labels and encoding as elara_process_rlimit_soft. Hard limit is the kernel-imposed ceiling that only privileged processes can raise; soft limit is the current effective ceiling that any process can lower or (up to hard) raise. The two diverge when a service's systemd unit set LimitNOFILE=65536 (raises soft from 1024 default) but the kernel allows further headroom via /etc/security/limits.conf — soft will report 65536 while hard reports the higher kernel ceiling. For elara-node the gap matters because under sustained load the operator may need to bump soft mid-flight via prlimit, which only succeeds up to hard. If soft == hard for a resource you care about (max_open_files at mainnet scale), the only headroom is a kernel-level config change.\n\
         # TYPE elara_process_rlimit_hard gauge\n\
         {rlimit_hard_rows}\
         # HELP elara_host_pressure_some_avg10 PSI 'some' avg10 from /proc/pressure/{{resource}} — fraction of the last 10 seconds that AT LEAST ONE task was stalled waiting on this resource (cpu / memory / io). Range 0.0..100.0 (percent). Single cleanest 'is this node struggling?' signal Linux exposes — orthogonal to LoadAvg (which is unbounded queue length) and CPU% (which can be 100% on healthy work). Phone-tier alert thresholds: memory.some_avg10 > 5 sustained = swap thrash imminent; io.some_avg10 > 10 = disk-bound (RocksDB compaction or page-cache miss storm); cpu.some_avg10 > 20 = scheduler-bound (under-provisioned vCPU). The 'some' scope means ≥1 task stalled — paired with 'full' (all tasks stalled) which is the OOM-imminent / total-stall signal. Empty on kernels <4.20 and on containers with /proc/pressure masked — series simply absent rather than zero so dashboards don't show fake-healthy.\n\
         # TYPE elara_host_pressure_some_avg10 gauge\n\
         {psi_some_avg10}\
         # HELP elara_host_pressure_some_avg60 PSI 'some' avg60 — fraction of the last 60 seconds with ≥1 task stalled. Smoother than avg10, surfaces sustained pressure that a 10s window wouldn't trip (e.g. a 30s memory pressure spike during compaction). Pair with avg10 for hysteresis: avg60 high + avg10 low = recent spike already cleared; both high = ongoing stall.\n\
         # TYPE elara_host_pressure_some_avg60 gauge\n\
         {psi_some_avg60}\
         # HELP elara_host_pressure_some_avg300 PSI 'some' avg300 — 5-minute average. Capacity-planning grade. Sustained nonzero on memory or io = the node is structurally undersized for its workload; sustained zero = headroom available for higher record-rate or more zones. Mainnet phone-tier baseline: should be < 1.0 across all three resources during steady-state seal cadence.\n\
         # TYPE elara_host_pressure_some_avg300 gauge\n\
         {psi_some_avg300}\
         # HELP elara_host_pressure_some_total_us PSI 'some' total_us — monotonic counter of microseconds with ≥1 task stalled, ever. Use rate() in Prometheus to derive any custom averaging window the avg{{10,60,300}} family doesn't already give you (e.g. rate over 1h for SLO computation). Resets on reboot only.\n\
         # TYPE elara_host_pressure_some_total_us counter\n\
         {psi_some_total}\
         # HELP elara_host_pressure_full_avg10 PSI 'full' avg10 — fraction of the last 10 seconds where ALL non-idle tasks were stalled on this resource. Only meaningful on memory and io (cpu cannot have 'full' stall by definition — at least one task is always runnable on a non-idle CPU). When memory.full_avg10 goes nonzero the kernel is one OOM-kill decision away from making the node unresponsive; io.full_avg10 nonzero = synchronous-write storm (fsync queue depth saturated) or filesystem freeze. Treat any nonzero value here as page-an-operator territory.\n\
         # TYPE elara_host_pressure_full_avg10 gauge\n\
         {psi_full_avg10}\
         # HELP elara_host_pressure_full_avg60 PSI 'full' avg60 — same 'all tasks stalled' signal averaged over 60 seconds. Sustained nonzero is the post-mortem evidence of a node freeze; can correlate with elara_circuit_breaker_level transitions and the elara_pending_ledger_oldest_age_seconds spike that the freeze caused.\n\
         # TYPE elara_host_pressure_full_avg60 gauge\n\
         {psi_full_avg60}\
         # HELP elara_host_pressure_full_avg300 PSI 'full' avg300 — 5-minute 'all tasks stalled' baseline. Should be flat zero on a healthy node; sustained nonzero means the node spent significant time fully unresponsive in the last 5 minutes — likely missed seal attestation deadlines.\n\
         # TYPE elara_host_pressure_full_avg300 gauge\n\
         {psi_full_avg300}\
         # HELP elara_host_pressure_full_total_us PSI 'full' total_us — monotonic counter of microseconds with ALL tasks stalled. The rate-derivable absolute floor of node-freeze time. On a 30-day uptime, 'full' total_us should be ≪ 1% of uptime_microseconds.\n\
         # TYPE elara_host_pressure_full_total_us counter\n\
         {psi_full_total}\
         # HELP elara_cgroup_pressure_some_avg10 Cgroup-scoped PSI 'some' avg10 from /sys/fs/cgroup<self>/{{resource}}.pressure — same kernel format as host PSI but limited to the elara-node cgroup. Auto-discovers the cgroup path from /proc/self/cgroup so the same code works for systemd services, docker containers, k8s pods, and unconstrained processes. The cross-table with elara_host_pressure_some_avg10 is the diagnostic value: host high + cgroup high = co-tenant noise AND own work both stalling; host high + cgroup low = noisy neighbour, elara-node fine; host low + cgroup high = elara-node alone breaching its cgroup cap (memory.high, cpu.weight, io.weight) — the operator must raise the limit. Without this, a containerized phone-tier node hitting its cgroup memory.high looks calm in host PSI (kernel has free RAM elsewhere) and the operator sees no warning until OOM-kill fires. Empty on cgroupv1 systems (the per-cgroup PSI file family is cgroupv2-only) and on kernels <4.20.\n\
         # TYPE elara_cgroup_pressure_some_avg10 gauge\n\
         {cgpsi_some_avg10}\
         # HELP elara_cgroup_pressure_some_avg60 Cgroup PSI 'some' avg60 — same 'at least one task stalled' signal as host PSI but scoped to the elara-node cgroup, averaged over 60 s. Use the avg10/avg60 pair the same way as host PSI: avg60 high + avg10 low = recent spike already cleared; both high = ongoing stall.\n\
         # TYPE elara_cgroup_pressure_some_avg60 gauge\n\
         {cgpsi_some_avg60}\
         # HELP elara_cgroup_pressure_some_avg300 Cgroup PSI 'some' avg300 — capacity-planning grade signal for whether the elara-node cgroup is structurally undersized. Sustained nonzero with host PSI low = the cgroup limit is the bottleneck; raise memory.high / io.weight / cpu.weight before adding workload.\n\
         # TYPE elara_cgroup_pressure_some_avg300 gauge\n\
         {cgpsi_some_avg300}\
         # HELP elara_cgroup_pressure_some_total_us Cgroup PSI 'some' total_us — monotonic microseconds-stalled counter scoped to elara-node's cgroup. Resets on reboot or on cgroup recreate (systemd unit restart). Use rate() for custom windows.\n\
         # TYPE elara_cgroup_pressure_some_total_us counter\n\
         {cgpsi_some_total}\
         # HELP elara_cgroup_pressure_full_avg10 Cgroup PSI 'full' avg10 — fraction of the last 10 s where ALL tasks in the elara-node cgroup were stalled on this resource. Page-an-operator threshold same as host PSI 'full', but more precise: a host with multiple cgroups can have a single cgroup fully stalled while host PSI 'full' stays low (the other cgroups' tasks still run). For elara-node specifically this means 'the entire node process is wedged on this resource'.\n\
         # TYPE elara_cgroup_pressure_full_avg10 gauge\n\
         {cgpsi_full_avg10}\
         # HELP elara_cgroup_pressure_full_avg60 Cgroup PSI 'full' avg60 — same 'all tasks in elara-node stalled' signal averaged over 60 s. Post-mortem evidence of a cgroup-bound freeze; correlate with elara_circuit_breaker_level transitions during the same window.\n\
         # TYPE elara_cgroup_pressure_full_avg60 gauge\n\
         {cgpsi_full_avg60}\
         # HELP elara_cgroup_pressure_full_avg300 Cgroup PSI 'full' avg300 — 5-minute 'cgroup fully wedged' baseline. Should be flat zero on a healthy elara-node; sustained nonzero = the cgroup limit is wedging the entire node periodically (likely missed seal attestation deadlines for the duration).\n\
         # TYPE elara_cgroup_pressure_full_avg300 gauge\n\
         {cgpsi_full_avg300}\
         # HELP elara_cgroup_pressure_full_total_us Cgroup PSI 'full' total_us — monotonic absolute floor of how long elara-node was fully wedged inside its cgroup. Distinct from host_pressure_full_total_us when the cgroup is the constraint binding (e.g. memory.high reached but host has free RAM).\n\
         # TYPE elara_cgroup_pressure_full_total_us counter\n\
         {cgpsi_full_total}\
         # HELP elara_process_minor_faults_total Cumulative minor page faults via /proc/self/stat. Minor faults resolve via memory reclaim, COW (copy-on-write), or first-touch of an anonymous mapping — no disk I/O. Steady-state rate scales with allocation rate (Rust drop+alloc cycles, mmap touches), and is informative as a baseline rather than as an alert: rate(minor_faults[5m]) >> previous baseline can indicate an allocator hot-loop. Pair with elara_process_major_faults_total to compute the major:minor ratio — a healthy node sees thousands of minors for every major.\n\
         # TYPE elara_process_minor_faults_total counter\n\
         elara_process_minor_faults_total {proc_minor_faults}\n\
         # HELP elara_process_major_faults_total Cumulative MAJOR page faults via /proc/self/stat. Each major fault is a synchronous disk read — the page wasn't resident and had to be paged in (swap-in or first-touch of a memory-mapped file). The single most actionable phone-tier observability signal: a sustained rate above ~100/s = the working set has overflowed RAM and every record processed is paying for synchronous I/O. On a quiet node the rate should be near zero outside of cold cache warm-up. Mainnet alert: rate(elara_process_major_faults_total[5m]) > 50 sustained = page operator. Pair with elara_process_vmswap_kb to confirm root cause (swap pressure vs cold mmap warm-up).\n\
         # TYPE elara_process_major_faults_total counter\n\
         elara_process_major_faults_total {proc_major_faults}\n\
         # HELP elara_process_cpu_user_seconds_total Cumulative CPU time spent in user mode by elara-node, in seconds, from /proc/self/stat utime ÷ sysconf(_SC_CLK_TCK). Distinguishes elara-node load from whole-host load: if elara_system_load_1m is high but rate(elara_process_cpu_user_seconds_total[1m]) is flat, the load is some other process and elara-node is fine; if both rise together, the node IS the load source. Steady state on a quiet 6-node testnet: rate ≈ 0.05–0.20 cores. Sustained rate ≈ 1.0 (or ≥1.0 cores fully consumed) without a corresponding records/s climb = unintended hot loop, often a sign-verification storm or a runaway gossip-pull cycle.\n\
         # TYPE elara_process_cpu_user_seconds_total counter\n\
         elara_process_cpu_user_seconds_total {proc_cpu_user_secs}\n\
         # HELP elara_process_cpu_system_seconds_total Cumulative CPU time spent in kernel mode on behalf of elara-node, in seconds, from /proc/self/stat stime ÷ sysconf(_SC_CLK_TCK). Healthy ratio: stime ≪ utime — kernel time should be the small fraction (typically 5-20%) spent in syscalls (read/write/socket/futex). A sustained kernel-time ratio approaching or exceeding user-time means the node is paying more for syscalls than it is doing actual work — typically chatty I/O (per-record fsync, tiny socket writes), excessive context switching from a busy futex, or the kernel servicing the major-fault path. Pair with elara_process_major_faults_total: a major-fault storm shows up as sustained stime growth.\n\
         # TYPE elara_process_cpu_system_seconds_total counter\n\
         elara_process_cpu_system_seconds_total {proc_cpu_system_secs}\n\
         # HELP elara_process_io_rchar_bytes_total Cumulative bytes read by elara-node via the read(2) syscall family (read/pread/readv) from /proc/self/io rchar. INCLUDES bytes served from the page cache without touching disk — i.e. this is the syscall-level read volume, not the disk-level cost. Pair with elara_process_io_read_bytes_total to compute cache hit ratio: high rchar with low read_bytes = warm cache (good); rchar ≈ read_bytes = cold reads going to disk every time (bad on phone-tier).\n\
         # TYPE elara_process_io_rchar_bytes_total counter\n\
         elara_process_io_rchar_bytes_total {proc_io_rchar}\n\
         # HELP elara_process_io_wchar_bytes_total Cumulative bytes written by elara-node via the write(2) syscall family (write/pwrite/writev) from /proc/self/io wchar. INCLUDES writes absorbed by the page cache without yet flushing — i.e. this is the syscall-level write volume, not the disk-level cost. Pair with elara_process_io_write_bytes_total: high wchar with low write_bytes = writes still buffered (normal); wchar ≈ write_bytes = forced sync writes (RocksDB WAL fsync rhythm + compaction flushes).\n\
         # TYPE elara_process_io_wchar_bytes_total counter\n\
         elara_process_io_wchar_bytes_total {proc_io_wchar}\n\
         # HELP elara_process_io_read_bytes_total Cumulative bytes the kernel actually pulled from the block device for elara-node, from /proc/self/io read_bytes. THE disk-read cost. On a phone-tier 2 GB node a healthy steady-state rate is near zero outside of cold-start and the periodic `block_cache` re-warm — sustained rate > 10 MiB/s while otherwise idle = working set has overflowed page cache, the kernel is paging-in state_core data on every record. Pair with elara_process_major_faults_total to confirm whether read amplification is from faults or from buffered RocksDB block reads.\n\
         # TYPE elara_process_io_read_bytes_total counter\n\
         elara_process_io_read_bytes_total {proc_io_read_bytes}\n\
         # HELP elara_process_io_write_bytes_total Cumulative bytes the kernel actually flushed to the block device on elara-node behalf, from /proc/self/io write_bytes. Canonical disk-bottleneck signal. RocksDB WAL appends, SST flushes, and compaction rewrites all show up here. Steady-state rate scales with submission rate (each record = WAL append + eventual SST + N× compaction rewrites under leveled compaction). Mainnet alert: rate > device-throughput-budget × 0.5 sustained = compactor will fall behind; pair with elara_rocksdb_pending_compaction_bytes climbing to confirm. On phone-tier eMMC (~50 MB/s sustained writes) sustained > 25 MB/s = compactor squeeze.\n\
         # TYPE elara_process_io_write_bytes_total counter\n\
         elara_process_io_write_bytes_total {proc_io_write_bytes}\n\
         # HELP elara_net_rx_bytes_total Cumulative bytes received across all non-loopback interfaces (eth/wifi/tailscale/wireguard/tun summed) from /proc/net/dev. Skips lo. Combined with elara_net_rx_drops_total this is the inbound-saturation pair. Operator alert pattern: rate(rx_bytes) climbs while rate(rx_drops) > 0 = NIC RX queue overflowing, kernel dropping packets the process couldn't accept fast enough — typically gossip-fanout from a many-peer cluster overwhelming a phone-tier node. Pair with elara_process_cpu_user_seconds_total to disambiguate CPU-pin vs qdisc-fill.\n\
         # TYPE elara_net_rx_bytes_total counter\n\
         elara_net_rx_bytes_total {proc_net_rx_bytes}\n\
         # HELP elara_net_tx_bytes_total Cumulative bytes transmitted across all non-loopback interfaces from /proc/net/dev. THE outbound-bandwidth signal. At 10K+ node mainnet phone-tier nodes (~50-500 KB/s sustained uplink) get hammered by gossip + record propagation long before they hit CPU limits. Operator alert: rate(tx_bytes) > device-throughput-budget × 0.5 sustained = uplink saturating, gossip queues will start to build up. Pair with elara_gossip_bytes_out_kind_total to see what is consuming the budget (records vs seals vs attestations).\n\
         # TYPE elara_net_tx_bytes_total counter\n\
         elara_net_tx_bytes_total {proc_net_tx_bytes}\n\
         # HELP elara_net_rx_drops_total Cumulative packets dropped on RX across all non-loopback interfaces from /proc/net/dev (rx_drop column). Leading indicator the kernel is dropping inbound packets — NIC ring buffer overflowed, qdisc full, or the socket receive buffer overran because the process did not drain it fast enough. Mainnet impact: dropped gossip = missed records = stale state at this node = peers see us as out-of-sync. Healthy steady-state is 0 — any non-zero rate is operator-actionable.\n\
         # TYPE elara_net_rx_drops_total counter\n\
         elara_net_rx_drops_total {proc_net_rx_drops}\n\
         # HELP elara_net_tx_drops_total Cumulative packets dropped on TX across all non-loopback interfaces from /proc/net/dev (tx_drop column). Leading indicator the qdisc is dropping outbound packets — uplink fully saturated, or the socket send buffer filled because the kernel could not flush it to the wire fast enough. Healthy steady-state is 0; any non-zero rate is operator-actionable. Pair with elara_net_tx_bytes_total to confirm we hit the device throughput budget.\n\
         # TYPE elara_net_tx_drops_total counter\n\
         elara_net_tx_drops_total {proc_net_tx_drops}\n\
         # HELP elara_tcp_established Count of TCP sockets currently in ESTABLISHED state across IPv4 + IPv6 (state 0x01 in /proc/net/tcp[6]). Operator natural ceiling is the peer-count target × per-peer channel multiplier (gossip + RPC + WS). Sustained value > expected peer-count × 5 = unexpected connection bloat — typically a misconfigured peer reconnecting in a tight loop or an RPC client without keepalive that's opening a fresh connection per request.\n\
         # TYPE elara_tcp_established gauge\n\
         elara_tcp_established {tcp_established}\n\
         # HELP elara_tcp_time_wait Count of TCP sockets in TIME_WAIT state across IPv4 + IPv6 (state 0x06). High count = high connection churn (short-lived connections, aggressive peer reconnects, RPC client without connection-pooling). The local ephemeral port range is ~28K ports, so TIME_WAIT > ~20K starts running into port exhaustion before file-descriptor exhaustion. Linux defaults: tw_reuse=2, tcp_fin_timeout=60s — so TIME_WAIT clears in ~2 minutes per socket.\n\
         # TYPE elara_tcp_time_wait gauge\n\
         elara_tcp_time_wait {tcp_time_wait}\n\
         # HELP elara_tcp_close_wait Count of TCP sockets in CLOSE_WAIT state across IPv4 + IPv6 (state 0x08). Peer has sent FIN but the local app hasn't called close() yet. Healthy steady-state is near zero. Sustained climbing CLOSE_WAIT is the canonical socket-leak signal — the app is failing to drain a closed connection. Pair with elara_process_open_fds to see the FD pressure landing — a CLOSE_WAIT leak ends in EMFILE.\n\
         # TYPE elara_tcp_close_wait gauge\n\
         elara_tcp_close_wait {tcp_close_wait}\n\
         # HELP elara_tcp_syn_recv Count of TCP sockets in SYN_RECV state across IPv4 + IPv6 (state 0x03). Half-open connection during the 3-way handshake. Healthy steady-state is single-digit. Climbing SYN_RECV indicates either a SYN flood (attacker-initiated, syncookies handle it) or a misbehaving peer storm (many peers retrying handshake without progressing). Once the kernel listen backlog overflows, new SYNs are dropped — the leading indicator that gossip ingress is breaking.\n\
         # TYPE elara_tcp_syn_recv gauge\n\
         elara_tcp_syn_recv {tcp_syn_recv}\n\
         # HELP elara_tcp_listen Count of TCP listener sockets across IPv4 + IPv6 (state 0x0A). Should be a small fixed number matching our bound services (PQ transport, gossip listener, RPC, /metrics). Non-stationary count = a service is spinning listeners up or down unexpectedly — useful as a configuration-drift alert.\n\
         # TYPE elara_tcp_listen gauge\n\
         elara_tcp_listen {tcp_listen}\n\
         # HELP elara_psi_cpu_some_avg10 Kernel Pressure Stall Information — percent of the last 10s during which AT LEAST ONE task was stalled waiting on the CPU, from /proc/pressure/cpu (kernel reports as 0.0–100.0 percent, NOT a 0.0–1.0 fraction). PSI catches contention well before raw CPU% saturates: a node with two CPU-bound tasks on a single-core phone shows 50% CPU but `psi_cpu_some_avg10 ≈ 50` because half the time one task can't run. Healthy steady-state on a 6-node testnet < 5. Sustained > 20 = page operator: the runtime is competing with other host workloads or the work is too dense for the core count.\n\
         # TYPE elara_psi_cpu_some_avg10 gauge\n\
         elara_psi_cpu_some_avg10 {psi_cpu_some:.4}\n\
         # HELP elara_psi_cpu_full_avg10 PSI percent of the last 10s during which ALL runnable tasks were stalled on CPU (from /proc/pressure/cpu `full` row, 0.0–100.0). Note: kernel docs flag CPU-`full` as ill-defined and it is often 0 even under heavy load — `some` is the canonical CPU pressure signal. Surfaced for completeness.\n\
         # TYPE elara_psi_cpu_full_avg10 gauge\n\
         elara_psi_cpu_full_avg10 {psi_cpu_full:.4}\n\
         # HELP elara_psi_memory_some_avg10 PSI percent of the last 10s during which AT LEAST ONE task was stalled on memory reclaim, swap-in, or page fault, from /proc/pressure/memory `some` (0.0–100.0). THE canonical phone-tier OOM-imminence signal. Reads independently of vmswap_kb / major_faults: PSI captures the *latency* cost of the stall (how often work was paused), while major_faults captures the *count* of faults. A node can have low fault count but high PSI if each fault stalls multiple seconds. Operator alert: sustained > 10 = working set has overflowed RAM, swap activity is throttling the runtime.\n\
         # TYPE elara_psi_memory_some_avg10 gauge\n\
         elara_psi_memory_some_avg10 {psi_mem_some:.4}\n\
         # HELP elara_psi_memory_full_avg10 PSI percent of the last 10s during which ALL runnable tasks were stalled on memory, from /proc/pressure/memory `full` (0.0–100.0). Different from `some`: full=10 means EVERY task was paused 10% of the time waiting on memory — the system is effectively wedged for that fraction. Sustained > 5 is the most actionable mainnet alert in this family — page operator immediately, OOM-killer is moments away.\n\
         # TYPE elara_psi_memory_full_avg10 gauge\n\
         elara_psi_memory_full_avg10 {psi_mem_full:.4}\n\
         # HELP elara_psi_io_some_avg10 PSI percent of the last 10s during which AT LEAST ONE task was stalled on I/O wait, from /proc/pressure/io `some` (0.0–100.0). Captures kernel-level disk back-pressure complementary to elara_process_io_read_bytes_total: bytes-rate tells you THROUGHPUT, PSI tells you LATENCY-TAX. RocksDB compaction, WAL fsync, and snapshot writes all show up here. Healthy steady-state on a quiet phone-tier node < 5. Sustained > 20 = I/O is the dominant bottleneck for the runtime.\n\
         # TYPE elara_psi_io_some_avg10 gauge\n\
         elara_psi_io_some_avg10 {psi_io_some:.4}\n\
         # HELP elara_psi_io_full_avg10 PSI percent of the last 10s during which ALL runnable tasks were stalled on I/O, from /proc/pressure/io `full` (0.0–100.0). Mainnet alert: sustained > 10 = compactor is dominating the node, the runtime is deadlocked behind disk waits — typically eMMC/SD-card-class storage or a misconfigured volume on slower-than-spec hardware. Pair with elara_rocksdb_pending_compaction_bytes climbing to confirm compactor as the source.\n\
         # TYPE elara_psi_io_full_avg10 gauge\n\
         elara_psi_io_full_avg10 {psi_io_full:.4}\n\
         # HELP elara_process_oom_score Kernel's continuously-computed OOM-kill rank for elara-node from /proc/self/oom_score. The kernel sums normalized RSS-percent + oom_score_adj to produce this 0..~1500 score; the process with the highest score is the next victim if the OOM-killer fires. Pairs with elara_psi_memory_full_avg10: PSI tells you the kernel is *trying* to reclaim memory; oom_score tells you whether *we* are the target if reclaim fails. On a phone-tier 2 GB node sharing host with a sidecar, oom_score > 800 sustained = page operator: a memory-spike on EITHER tenant will prefer to kill us. Healthy steady-state is below ~500. The gauge re-reads on every /metrics scrape, so transient spikes from short-lived RSS bumps will surface.\n\
         # TYPE elara_process_oom_score gauge\n\
         elara_process_oom_score {oom_score}\n\
         # HELP elara_process_oom_score_adj Operator-set OOM-score adjustment for elara-node from /proc/self/oom_score_adj. Range -1000 (OOM-protected) to +1000 (sacrificial). Default 0 = no protection. Surface this so /metrics shows whether the systemd unit's `OOMScoreAdjust=-500` actually landed - a unit-file typo silently leaves the runtime at 0 with no ops-side warning. On constrained 2 GB nodes, consider lowering so a transient host-OOM preferentially kills background processes, not the consensus node.\n\
         # TYPE elara_process_oom_score_adj gauge\n\
         elara_process_oom_score_adj {oom_score_adj}\n\
         # HELP elara_meminfo_dirty_kb Bytes of dirty page-cache pages awaiting writeback (kB) from /proc/meminfo Dirty. The leading indicator that page-cache writeback cannot keep up with the submission rate: RocksDB writes go through page cache; the kernel asynchronously flushes dirty pages to disk via writeback. If Dirty grows unboundedly, the kernel triggers writeback congestion-throttling (`dirty_ratio` / `dirty_bytes` sysctls) which back-pressures every writer process. On a phone-tier eMMC node sustained Dirty > 100 MB while submission rate is steady = fsync rhythm is falling behind disk throughput, and the runtime will start blocking on write() before PSI io has had a chance to register. Pair with elara_process_io_write_bytes_total: high Dirty + high write_bytes = compactor saturating the disk; high Dirty + low write_bytes = WAL fsync stalling on the device's slow path.\n\
         # TYPE elara_meminfo_dirty_kb gauge\n\
         elara_meminfo_dirty_kb {meminfo_dirty_kb}\n\
         # HELP elara_meminfo_writeback_kb Bytes currently mid-writeback (kB) from /proc/meminfo Writeback. Pages the kernel has handed to the block layer but not yet ack'd. Healthy steady-state is near zero — pages flush in microseconds on a non-saturated device. Sustained Writeback > 1 MB indicates the device is the bottleneck: pages are queued at the block layer faster than the device can drain them. This is independent of Dirty: a node can have Dirty=0 but Writeback non-zero if the kernel has queued the entire dirty backlog onto a slow device. eMMC / SD-card / contended virtualized disk are the typical sources.\n\
         # TYPE elara_meminfo_writeback_kb gauge\n\
         elara_meminfo_writeback_kb {meminfo_writeback_kb}\n\
         # HELP elara_meminfo_cached_kb Bytes of file-backed page cache (kB) from /proc/meminfo Cached. Surfaces RocksDB read-path health: LSM SST reads are served from page cache when warm — Cached close to working-set size = warm cache, low Cached relative to data_dir size = cold reads going to disk on every block fetch. Pair with elara_process_io_read_bytes_total: high read_bytes rate while Cached is small = the kernel keeps re-faulting blocks because there isn't room to cache them, the canonical phone-tier 'working set overflowed RAM' pattern. Cached is reported BEFORE accounting for shared anonymous mappings; on most servers Cached + Buffers + free ≈ MemAvailable.\n\
         # TYPE elara_meminfo_cached_kb gauge\n\
         elara_meminfo_cached_kb {meminfo_cached_kb}\n\
         # HELP elara_memory_pressure Whether the node is under memory pressure (0 or 1)\n\
         # TYPE elara_memory_pressure gauge\n\
         elara_memory_pressure {mem_pressure}\n\
         # HELP elara_memory_critical Whether the node is under critical memory pressure — new submissions rejected with 429 (0 or 1)\n\
         # TYPE elara_memory_critical gauge\n\
         elara_memory_critical {mem_critical}\n\
         # HELP elara_disk_pressure Whether the node is under any disk pressure - `disk_avail_pressure || disk_cap_pressure` (0 or 1). Operators reading this for back-compat - to distinguish the two signals, see `elara_disk_avail_pressure` (real disk-full safety, gates ingest with HTTP 429) and `elara_disk_cap_pressure` (operator-policy budget overrun, drives GC compaction but does NOT gate ingest). Operator playbook on sustained pressure=1: (1) `du -sh <data_dir>/pre-migration-v*-backup` - old migration backups are leaked checkpoints (auto-prune sweep keeps only the rollback target); (2) `du -sh <data_dir>/checkpoints/checkpoint_*` - hand-retained recovery checkpoints, rotate the oldest if not actively rolling back; (3) RocksDB SST growth - tiered compaction is bounded by retention windows but check `cf_size_*` totals if the above are clean.\n\
         # TYPE elara_disk_pressure gauge\n\
         elara_disk_pressure {disk_pressure}\n\
         # HELP elara_disk_avail_pressure Real-disk-full safety signal — set when statvfs avail drops below `disk_pressure_avail_low_mb` (default 2 GB) and not yet recovered above `disk_pressure_avail_high_mb` (default 4 GB). This is the **only** disk-pressure signal that gates ingest (the `/records` POST handler and `insert_record_inner` both 429 when this is 1). When this is 1 and `elara_disk_pressure_rejected_ingest_total` is climbing, peers are still pushing records that the operator's space-clearing budget has to absorb. Independent of `disk_cap_bytes` operator policy.\n\
         # TYPE elara_disk_avail_pressure gauge\n\
         elara_disk_avail_pressure {disk_avail_pressure}\n\
         # HELP elara_disk_cap_pressure Operator-policy budget signal - set when `elara_rocksdb_live_bytes` exceeds 95% of `elara_disk_cap_bytes_effective` and not yet recovered to <= 80%. **Does NOT gate ingest** - hard-rejecting client writes on small volumes whose legitimate working sets exceed the FS clamp causes a fleet trap. Cap-pressure drives force-compaction (fires every cycle when this is 1, via the combined disk_pressure flag). GC's retention-shrink is a SEPARATE independent computation (effective_cap vs live_bytes in gc.rs), correlated in intent but NOT gated by this gauge — the two can diverge when exempt mandate/registry mass is significant. For ingest gating on cap-overrun, set `disk_pressure_avail_low_mb` such that statvfs avail trips before cap, or set `disk_cap_bytes=0` to disable this signal entirely.\n\
         # TYPE elara_disk_cap_pressure gauge\n\
         elara_disk_cap_pressure {disk_cap_pressure}\n\
         # HELP elara_disk_pressure_rejected_ingest_total Cumulative records rejected at the insert_record_inner gate because elara_disk_pressure was 1 at the time. Previously only the /records POST handler checked disk_pressure; gossip pull/push, sync, and direct-route ingest bypassed the gate and continued writing through 100% disk until the daemon hit ENOSPC. Now ALL ingest sources funnel through one gate that fires while pressure is on. Pair with elara_disk_pressure (the on/off signal) — this counter's RATE while the gauge is 1 is the live-blast-radius signal: how many records peers are currently trying to push that the operator's space-clearing budget has to absorb. Counter only advances during pressure windows; in normal operation it is flat. Already-stored records still ack with their existing id (the dedup short-circuit fires before this gate), so re-pushes of known records are not counted here.\n\
         # TYPE elara_disk_pressure_rejected_ingest_total counter\n\
         elara_disk_pressure_rejected_ingest_total {disk_pressure_rejected_ingest_total}\n\
         # HELP elara_emergency_halted Signed EmergencyHalt circuit-breaker state. 1 = a valid authority-signed EmergencyHalt is active (the ingest gate refuses new non-authority writes with 429) and the wall-clock auto-expiry window has not elapsed; 0 = un-halted. Node-local, never folded into consensus/seals. Pair with elara_emergency_rejected_ingest_total.\n\
         # TYPE elara_emergency_halted gauge\n\
         elara_emergency_halted {emergency_halted}\n\
         # HELP elara_emergency_rejected_ingest_total Cumulative records refused at the emergency-halt ingest gate while a halt was active. Authority records, the halt/resume ops themselves, and synced (already-sealed) records are always admitted; this counts only NEW non-authority external writes turned away. Flat in normal operation; its rate while elara_emergency_halted is 1 is how many writes clients are retrying against the paused network.\n\
         # TYPE elara_emergency_rejected_ingest_total counter\n\
         elara_emergency_rejected_ingest_total {emergency_rejected_ingest_total}\n\
         # HELP elara_disk_avail_pressure_events_total Cumulative count of `elara_disk_avail_pressure` 0->1 transitions observed by `disk_pressure_loop`. Bumps exactly once per trip edge; clears (1->0) do NOT decrement. Pairs with the on/off `elara_disk_avail_pressure` gauge to disambiguate two operationally identical scrape shapes: (i) gauge=1 + counter steady => still under pressure since the last trip, no new edge; (ii) gauge=0 + counter advanced since last scrape => at least one transient pressure episode fired AND cleared inside the 60s sample cadence. Operator playbook: monitor `rate(elara_disk_avail_pressure_events_total)` over a 5-min window; non-zero rate while gauge=0 => flap below scrape resolution, lower `disk_pressure_avail_low_mb` or shorten the loop tick to catch it.\n\
         # TYPE elara_disk_avail_pressure_events_total counter\n\
         elara_disk_avail_pressure_events_total {disk_avail_pressure_events_total}\n\
         # HELP elara_disk_cap_pressure_events_total Cumulative count of `elara_disk_cap_pressure` 0→1 transitions observed by `disk_pressure_loop`. Identical semantics to `elara_disk_avail_pressure_events_total` but for the operator-policy budget signal (live_bytes vs disk_cap_bytes_effective). Symmetric pair so operators can attribute a between-scrape flap to the avail-side or cap-side without tail-grepping the journal for the edge log lines. Cap-side flaps without avail-side flaps ⇒ live_bytes oscillating near the 95% / 80% hysteresis band; tighten the band or raise `disk_cap_bytes` if the GC-driven shrink is overshooting.\n\
         # TYPE elara_disk_cap_pressure_events_total counter\n\
         elara_disk_cap_pressure_events_total {disk_cap_pressure_events_total}\n\
         # HELP elara_disk_pressure_lowest_avail_mb Minimum `disk_available_mb` observed since process boot (running fetch_min on every disk_pressure_loop tick). Closes a gauge-failure-on-slow-shrink shape: between two scrapes the live `elara_disk_available_mb` can dip below the low watermark and recover before either scrape catches it. The lowest-mb gauge surfaces the dip-history the boolean cannot. Sentinel u64::MAX (pre-first-sample) renders as 0; pair with `elara_disk_pressure_samples_total` to disambiguate not-yet-sampled (samples=0) from actually-saw-sub-MB-free (samples>0 AND lowest=0). Operator playbook: this gauge minus the rolling-window minimum of `elara_disk_available_mb` => the worst between-scrape dip caught by the inline fetch_min; if that delta is sustained >1 GB the loop tick is too coarse for the IO pattern.\n\
         # TYPE elara_disk_pressure_lowest_avail_mb gauge\n\
         elara_disk_pressure_lowest_avail_mb {disk_pressure_lowest_avail_mb}\n\
         # HELP elara_disk_pressure_samples_total Cumulative count of `disk_pressure_loop` iterations (one increment per 60s tick after the iteration completes its `fetch_min`). Pairs with `elara_disk_pressure_lowest_avail_mb` to disambiguate two operationally-distinct shapes that the renderer's `u64::MAX -> 0` sentinel-collapse otherwise looks identical: (a) `lowest_avail_mb=0` AND `samples_total=0` => the loop has never run, the 0 is the not-yet-sampled sentinel; (b) `lowest_avail_mb=0` AND `samples_total>0` => the loop has observed `statvfs(data_dir).f_bavail*f_frsize < 1 MB` at least once (genuine ENOSPC neighbourhood). Steady-state on a long-running node: `samples_total ~= uptime_seconds / 60`. If samples_total is flat across two scrapes the loop has stalled - investigate `disk_pressure_loop` task health.\n\
         # TYPE elara_disk_pressure_samples_total counter\n\
         elara_disk_pressure_samples_total {disk_pressure_samples_total}\n\
         # HELP elara_admin_compact_cf_triggered_total Cumulative count of operator-triggered RocksDB compactions via POST /admin/rocks/compact_cf. Distinct from auto-triggered compaction inside gc_loop (gc.rs:553 'pressure_due' branch + startup_compaction_if_needed), which does NOT increment this counter. Pair with elara_rocksdb_running_compactions to attribute a compaction window to operator-triggered vs gc-triggered intervention. Steady state 0 on a fleet that never needs operator escalation. Bumps once per successful auth+dispatch - the spawn_blocking that walks the CF list runs in background and may still be running after the counter advanced; check total-sst-files-size before/after to confirm reclaim.\n\
         # TYPE elara_admin_compact_cf_triggered_total counter\n\
         elara_admin_compact_cf_triggered_total {admin_compact_cf_triggered_total}\n\
         # HELP elara_pre_migration_backup_bytes Total bytes occupied by `pre-migration-v{{N}}-backup` directories under data_dir. Created by `run_migrations` as a rollback safety net before each schema migration. The auto-prune sweep keeps only the rollback target (most recent v{{N}}); older backups are deleted on every boot. A single rollback target on a large chain can be tens of GB. Operator action: (a) zero is normal on a fresh node or after the next migration cycle reaps the previous target; (b) sustained non-zero with no upcoming migration is the disk-pressure source — once the operator is confident in v{{CURRENT}}, manually `rm -rf <data_dir>/pre-migration-v{{N}}-backup` to reclaim. Cached 60s to avoid repeated tree walks per /metrics scrape.\n\
         # TYPE elara_pre_migration_backup_bytes gauge\n\
         elara_pre_migration_backup_bytes {pre_migration_backup_bytes}\n\
         # HELP elara_data_dir_total_bytes Total bytes used by the data_dir directory tree, deduplicated by inode (matches `du -sh` semantics, NOT `du -shl`). Hardlinked rocksdb checkpoint SSTs are counted ONCE - the value is what statvfs avail actually decreases against, not the dirent-sum. Sampled by the dedicated `data_dir_size_loop` task at `data_dir_size_sample_interval_secs` cadence (default 300 s) via `tokio::task::spawn_blocking` + `storage::rocks::dir_size_bytes`. Previously the walk ran inside disk_pressure_loop every 60 s and O(SST count) stat() syscalls under compaction pressure stretched the tick - the split keeps the pressure loop on its strict 60 s rhythm. Captures rocksdb SSTs + WAL + checkpoint inodes (deduped) + pre-migration backups + log files. Compare with elara_rocksdb_live_bytes to see how much footprint is held outside the active LSM - hardlinked checkpoints under data_dir/checkpoints can contribute tens of GB without changing live_bytes, visible only via statvfs avail falling toward the floor. Sampled (not live) - first scrape after boot reads 0 until the first walk completes; pair with `elara_data_dir_size_samples_total` to distinguish never-sampled from genuine-zero.\n\
         # TYPE elara_data_dir_total_bytes gauge\n\
         elara_data_dir_total_bytes {data_dir_total_bytes}\n\
         # HELP elara_data_dir_size_samples_total Cumulative count of `data_dir_size_loop` iterations (one increment per completed `dir_size_bytes` walk, default 5 min cadence). Pairs with `elara_data_dir_total_bytes` to disambiguate two operationally distinct shapes the gauge alone cannot distinguish: (a) `data_dir_total_bytes=0` AND `data_dir_size_samples_total=0` ⇒ the walk task has not finished its first pass yet (boot regime — on a stressed I/O subsystem at 10 K+ SSTs the first walk can take minutes); (b) `data_dir_total_bytes=0` AND `data_dir_size_samples_total>0` ⇒ the walk ran but returned zero, which means a pathological filesystem state (data_dir relocated, unmounted, all reads errored — investigate journal). Steady state: `samples_total ≈ uptime_seconds / data_dir_size_sample_interval_secs` (≈ 1 per 5 min by default). Raise the interval if the ratio drifts below ~50 %, which means the walk is dominating its own cadence. Steady at 0 forever ⇒ operator set `ELARA_DATA_DIR_SIZE_SAMPLE_INTERVAL_SECS=0` to disable.\n\
         # TYPE elara_data_dir_size_samples_total counter\n\
         elara_data_dir_size_samples_total {data_dir_size_samples_total}\n\
         # HELP elara_rocksdb_live_bytes Total bytes occupied by live data across all RocksDB column families (sum of cf_live_bytes for every CF). This is the rocksdb-internal view: SSTs that are part of the active LSM tree at the current sequence number, excluding obsolete files awaiting compaction, WAL beyond the memtable, hardlinked checkpoints, and any content under data_dir that isn't part of active DB state. The same value disk_pressure_loop checks against disk_cap_bytes. Pair with elara_data_dir_total_bytes — the diff is bytes held by checkpoints/backups/WAL/logs and is the right signal for capacity-planning a node that runs heavy backup retention.\n\
         # TYPE elara_rocksdb_live_bytes gauge\n\
         elara_rocksdb_live_bytes {rocksdb_live_bytes}\n\
         # HELP elara_node_boot_total_seconds Wall-clock seconds from process run() entry to HTTP listener bind. Set ONCE at boot and held for the rest of the process lifetime - first /metrics scrape post-boot already shows the value. During the boot window itself /metrics is connection-refused (axum hasn't bound), so this gauge being non-zero is also the signal that boot completed. Operator alert: gauge >300 with boot_ledger_rebuild_seconds dominating -> boot is in the storage-replay regime, not stuck. >600 anywhere is expected only on initial bring-up of a large archive node, otherwise investigate. A sustained 0 in steady-state means either a downstream-side bug or a node that hasn't restarted since this gauge was added - check uptime first.\n\
         # TYPE elara_node_boot_total_seconds gauge\n\
         elara_node_boot_total_seconds {boot_total_secs}\n\
         # HELP elara_node_boot_ledger_rebuild_seconds Wall-clock seconds spent in the dominant boot phase: DAG/ledger rebuild from RocksDB snapshot or full streaming replay, plus checkpoint fast-path, plus orphan cleanup, plus the conservation-fix fallback. Scales with record count — at 10M records this is the primary driver of slow boots. Independent from boot_state_core_init: the two roughly sum to boot_total_seconds (the small remainder is config load, identity bring-up, and HTTP setup). Pair with `elara_records_total` to track per-record rebuild cost across versions; if the ratio rises sharply between deploys, the rebuild path regressed. Captured in elara_node.rs run() between the start of the snapshot/rebuild block and just before pull catch-up cursor init.\n\
         # TYPE elara_node_boot_ledger_rebuild_seconds gauge\n\
         elara_node_boot_ledger_rebuild_seconds {boot_ledger_rebuild_secs}\n\
         # HELP elara_node_boot_state_core_init_seconds Wall-clock seconds spent post-rebuild and pre-HTTP: pull-cursor init, jemalloc purge, subsystem rebuild dispatch (tokio::spawn, bg work continues after this gauge is set), state_core spawn, background-task setup. Independent of the rebuild path — every boot pays roughly the same cost here. Typically smaller than ledger_rebuild but grows with per-zone state size and number of background subsystems. A sustained anomaly here points at one of the post-rebuild init blocks (gossip setup, content safety load, etc) regressing — the timing is bracketed exactly there.\n\
         # TYPE elara_node_boot_state_core_init_seconds gauge\n\
         elara_node_boot_state_core_init_seconds {boot_state_core_init_secs}\n\
         # HELP elara_node_open_fds Count of file descriptors currently open by this process, sampled from /proc/self/fd at /metrics scrape time. Linux-only; 0 on non-Linux hosts. On the 6-node testnet steady state is typically <500: peers (~3-5 sockets each direction × few peers) + RocksDB live SST handles + WAL + log file + listening socket + a small constant for stdio/identity files. Sustained climb without proportional peer growth points at an FD leak — common sources past audits surfaced: (a) tokio task that opens a file or socket and never drops the handle, (b) reqwest client created per-request instead of reused, (c) RocksDB iterator held across an await point in a long-lived loop. Pair with elara_node_max_fds — the open/max ratio is the operator-facing utilization signal. Once the ratio crosses ~70% the kernel starts returning EMFILE on accept/open, which cascades into apparent network or RocksDB failures with no other root-cause signal in the logs.\n\
         # TYPE elara_node_open_fds gauge\n\
         elara_node_open_fds {open_fds}\n\
         # HELP elara_node_max_fds Soft RLIMIT_NOFILE for this process - the kernel-enforced FD ceiling. Set by the unit file (`LimitNOFILE=` for systemd nodes), shell `ulimit -n`, or distro default. On a small cloud VPS systemd default is often 524288; on a desktop with an unconfigured unit file the limit is typically 1024. A 1024 ceiling on a heavily-peered node will exhaust under 200-peer load - change the unit file or sysctl, restart needed for new limit to take effect. Hold steady once configured; growing or shrinking values mean the unit file or kernel limits changed mid-run.\n\
         # TYPE elara_node_max_fds gauge\n\
         elara_node_max_fds {max_fds}\n\
         # HELP elara_continuity_identities Number of identities tracked by continuity scoring\n\
         # TYPE elara_continuity_identities gauge\n\
         elara_continuity_identities {cont_ids}\n\
         # HELP elara_reincarnation_fingerprints Number of behavioral fingerprints tracked\n\
         # TYPE elara_reincarnation_fingerprints gauge\n\
         elara_reincarnation_fingerprints {reinc_fps}\n\
         # HELP elara_reincarnation_candidates Number of detected reincarnation candidates\n\
         # TYPE elara_reincarnation_candidates gauge\n\
         elara_reincarnation_candidates {reinc_cands}\n\
         # HELP elara_rocksdb_memtable_bytes RocksDB memtable memory usage\n\
         # TYPE elara_rocksdb_memtable_bytes gauge\n\
         elara_rocksdb_memtable_bytes {rocks_memtable}\n\
         # HELP elara_rocksdb_block_cache_bytes RocksDB block cache usage\n\
         # TYPE elara_rocksdb_block_cache_bytes gauge\n\
         elara_rocksdb_block_cache_bytes {rocks_cache}\n\
         # HELP elara_rocksdb_table_readers_bytes RocksDB table readers (index/filter) memory\n\
         # TYPE elara_rocksdb_table_readers_bytes gauge\n\
         elara_rocksdb_table_readers_bytes {rocks_table_readers}\n\
         # HELP elara_rocksdb_pending_compaction_bytes Estimated bytes still needing compaction across ALL column families (sum of `rocksdb.estimate-pending-compaction-bytes`). This is the LEADING indicator of write-stall risk — it bends up well before write latency does, because RocksDB throttles writes once pending bytes cross `soft_pending_compaction_bytes_limit` (default 64 GB but the throttling ramp starts much earlier). On phone-tier 2 GB nodes the practical alert threshold is much lower than the default soft-limit: a sustained value >2 GB or growing by >100 MB/min while ingest continues = compactor is falling behind ingest. Pair with elara_rocksdb_running_compactions: if `running` is pinned at the configured `max-background-compactions` cap AND `pending_compaction_bytes` is climbing, the node is CPU-saturated on compaction and writes will stall next. If `running` is below the cap but `pending` grows, the level-trigger thresholds have not been crossed yet — compactor is intentionally idle, this is normal LSM behaviour. Sustained 0 = healthy.\n\
         # TYPE elara_rocksdb_pending_compaction_bytes gauge\n\
         elara_rocksdb_pending_compaction_bytes {rocks_pending_compaction}\n\
         # HELP elara_rocksdb_running_compactions Currently active compaction jobs across ALL column families (sum of `rocksdb.num-running-compactions`). Bounded above by RocksDB's configured `max-background-compactions` (default 2 unless overridden). Pinned at the cap with elara_rocksdb_pending_compaction_bytes climbing = saturation; below the cap with pending climbing = level thresholds not crossed yet (intentional idle); sustained 0 with pending=0 = quiet steady state. Per-CF granularity is intentionally not exposed — operators see fleet-wide compactor saturation as one number; per-CF triage happens via `compact_cf` admin RPCs and `total-sst-files-size` per CF in `startup_compaction_if_needed` log lines.\n\
         # TYPE elara_rocksdb_running_compactions gauge\n\
         elara_rocksdb_running_compactions {rocks_running_compactions}\n\
         # HELP elara_rocksdb_immutable_memtables Frozen memtables awaiting flush to L0 across ALL column families (sum of `rocksdb.num-immutable-mem-table`). >0 means the flush thread is behind active writes; if it grows past `max_write_buffer_number - 1`, RocksDB STALLS new writes for that CF until a flush completes. The upstream root cause of any flush stall is almost always disk I/O (slow sync write tail) — this gauge surfaces it as a memory-side signal so operators see the shape of the stall before client-visible latency spikes. Steady state at 0; transient 1-2 during heavy write bursts is normal and clears on the next flush; sustained >2 fleet-wide = disk write tail is the bottleneck (check elara_disk_available_mb for I/O queue depth proxy).\n\
         # TYPE elara_rocksdb_immutable_memtables gauge\n\
         elara_rocksdb_immutable_memtables {rocks_immutable_memtables}\n\
         # HELP elara_rocksdb_background_errors RocksDB accumulated background-error count (`rocksdb.background-errors`, DB-global). The HARD-failure signal — categorically distinct from the recoverable back-pressure gauges above (pending_compaction/running_compactions/immutable_memtables all self-clear when the compactor catches up) and from elara_disk_pressure (proactive free-space headroom, fires BEFORE an error). Non-zero means a background flush or compaction FAILED outright — mid-compaction ENOSPC, an I/O fault, a lost mount / permissions change, or on-disk corruption — after which RocksDB halts writes into a read-only state that does NOT self-clear when free space returns. Any non-zero value is an operator page: the node is silently dropping every write; ingest, sealing, and gossip persistence are all failing even though the process is still up and /metrics still scrapes. Steady state is exactly 0; there is no benign non-zero. Pair with elara_disk_pressure to attribute (space-driven vs a non-space I/O/corruption fault).\n\
         # TYPE elara_rocksdb_background_errors gauge\n\
         elara_rocksdb_background_errors {rocks_background_errors}\n\
         # HELP elara_rocksdb_l0_files_total Total file count across ALL column families at LSM level 0 (sum of `rocksdb.num-files-at-level0`). L0 is the only LSM level whose key ranges overlap, so EVERY read for a CF visits each L0 file via bloom filter until that file gets compacted into L1. Sustained climb = read amplification rising and L0->L1 compactor falling behind ingest. Pair with elara_rocksdb_l0_files_max_cf to find the worst-CF concentration, and with elara_rocksdb_running_compactions to see whether L0->L1 compactions are running yet. Steady state on a healthy node: low single digits (memtable flushes drain to L0 then immediately compact down).\n\
         # TYPE elara_rocksdb_l0_files_total gauge\n\
         elara_rocksdb_l0_files_total {rocks_l0_total}\n\
         # HELP elara_rocksdb_l0_files_max_cf Max L0 file count across ALL column families (worst-CF). RocksDB applies write-throttling per-CF based on its OWN L0 count: `level0_slowdown_writes_trigger` (default 20) starts the soft-throttle ramp, `level0_stop_writes_trigger` (default 36) hard-stops writes for that CF until L0 drains. Operator alert: sustained >20 = soft-throttle is active and ingest is being capped below client demand; sustained >36 = a CF is in hard-stop, every ingest into that CF blocks until compaction catches up. This is the canonical 'writes are stalling RIGHT NOW' gauge. Pair with elara_rocksdb_actual_delayed_write_rate_bps_max to read the throttle ceiling, and elara_rocksdb_write_stopped_cfs to confirm hard-stop.\n\
         # TYPE elara_rocksdb_l0_files_max_cf gauge\n\
         elara_rocksdb_l0_files_max_cf {rocks_l0_max_cf}\n\
         # HELP elara_rocksdb_write_stopped_cfs Count of column families reporting `rocksdb.is-write-stopped`. Non-zero = at least one CF is in HARD-STOP — every PUT into that CF blocks (synchronous) until the L0->L1 compactor drains the CF below `level0_stop_writes_trigger`. Different from compaction throttling (which slows ingest); hard-stop fully blocks. Steady state strictly 0. Any non-zero reading mid-flight = ingest path latency is about to spike to whatever the L0 drain cycle takes (often 10s of seconds on phone-tier eMMC). Operator playbook: confirm via elara_rocksdb_l0_files_max_cf >= 36 (default trigger), check elara_rocksdb_pending_compaction_bytes for backlog size, then either wait it out or escalate via /admin/compact_cf if the CF is under known bloat.\n\
         # TYPE elara_rocksdb_write_stopped_cfs gauge\n\
         elara_rocksdb_write_stopped_cfs {rocks_write_stopped_cfs}\n\
         # HELP elara_rocksdb_actual_delayed_write_rate_bps_max Max `rocksdb.actual-delayed-write-rate` across ALL column families, in bytes/second. When >0, RocksDB has clamped write bandwidth on at least one CF via the leveled-compaction soft-throttle (active before hard-stop). The value is the SUSTAINED bandwidth ceiling RocksDB will accept — ingest above this rate blocks until compaction catches up. Reading the magnitude tells operators HOW MUCH the compactor is slowing ingest: 100 MB/s = barely throttled, 1 MB/s = catastrophically throttled. Steady state 0 (no throttling). Sustained >0 with elara_rocksdb_l0_files_max_cf rising = compactor is losing the race; hardware is at its physical write-throughput floor and ingest must back off or zone must be split.\n\
         # TYPE elara_rocksdb_actual_delayed_write_rate_bps_max gauge\n\
         elara_rocksdb_actual_delayed_write_rate_bps_max {rocks_delay_rate_bps_max}\n\
         # HELP elara_host_cpu_user_seconds_total Cumulative WHOLE-HOST user-mode CPU time in seconds, from /proc/stat first-line `user` jiffies ÷ sysconf(_SC_CLK_TCK). Includes all processes on the host, not just elara-node. Pair with elara_process_cpu_user_seconds_total to compute elara-node share of host CPU: rate(elara_process_cpu_user_seconds_total) / rate(elara_host_cpu_user_seconds_total). Useful on shared-tenant hosts to spot when a co-resident process (logging, monitoring, the operator's own ssh shell) is consuming meaningful CPU and starving elara-node.\n\
         # TYPE elara_host_cpu_user_seconds_total counter\n\
         elara_host_cpu_user_seconds_total {host_cpu_user_secs}\n\
         # HELP elara_host_cpu_system_seconds_total Cumulative WHOLE-HOST kernel-mode CPU time in seconds, from /proc/stat first-line `system` jiffies ÷ sysconf(_SC_CLK_TCK). Healthy ratio: system-time is a small fraction of user-time fleet-wide. Sustained `rate(system) > rate(user)` host-wide = the kernel is paying more for syscalls than userspace is doing work — typically chatty I/O, networking syscalls, or a major-fault storm visiting kernel page-fault paths.\n\
         # TYPE elara_host_cpu_system_seconds_total counter\n\
         elara_host_cpu_system_seconds_total {host_cpu_system_secs}\n\
         # HELP elara_host_cpu_iowait_seconds_total Cumulative WHOLE-HOST CPU time spent idle while at least one runnable task was blocked on disk I/O, from /proc/stat first-line `iowait` jiffies ÷ sysconf(_SC_CLK_TCK). The classic /proc kernel-tracked I/O-pressure metric — predates PSI by many years and remains the simplest 'is the disk saturated' counter. Sustained `rate(iowait) > 0.1 cores` = global disk queue is the bottleneck. Pair with elara_psi_io_full_avg10 (PSI is finer-grained and kernel-tracked-current); they should agree directionally — divergence usually means PSI is more sensitive in the short window. On phone-tier eMMC the practical alert is `rate > 0.05 cores` sustained for 5 min.\n\
         # TYPE elara_host_cpu_iowait_seconds_total counter\n\
         elara_host_cpu_iowait_seconds_total {host_cpu_iowait_secs}\n\
         # HELP elara_host_cpu_softirq_seconds_total Cumulative WHOLE-HOST CPU time spent in software-interrupt context, from /proc/stat first-line `softirq` jiffies ÷ sysconf(_SC_CLK_TCK). Network packet RX (NET_RX softirq), timer wheels (TIMER softirq), RCU callbacks, and block-I/O completion all run here. On gossip-heavy nodes this rises with inbound packet rate — sustained `rate(softirq) > 0.3 cores` = NIC RX is the bottleneck (kernel cannot keep up with packet delivery). Pair with elara_socket_recv_drops_total: high softirq + non-zero drops = packets are being dropped at the kernel boundary before elara-node sees them.\n\
         # TYPE elara_host_cpu_softirq_seconds_total counter\n\
         elara_host_cpu_softirq_seconds_total {host_cpu_softirq_secs}\n\
         # HELP elara_host_cpu_steal_seconds_total Cumulative CPU time STOLEN by the hypervisor from this VM to run other tenants, from /proc/stat first-line `steal` jiffies ÷ sysconf(_SC_CLK_TCK). The canonical 'noisy neighbour' signal on shared VPS hardware — INVISIBLE from /proc/self/stat, only the host kernel sees it. Sustained `rate(steal) > 0.05 cores` on a single-vCPU plan = the hypervisor is preempting elara-node for its co-tenants ~5% of the time; our scheduling guarantees are degraded and there is nothing we can do about it from inside the VM. Operator playbook: rate(steal) > 0.10 cores sustained for 1h = contact the VPS provider, escalate the contention, or migrate workload to a dedicated-CPU plan. On bare-metal or dedicated-CPU plans this counter is always 0.\n\
         # TYPE elara_host_cpu_steal_seconds_total counter\n\
         elara_host_cpu_steal_seconds_total {host_cpu_steal_secs}\n\
         # HELP elara_host_cpu_idle_seconds_total Cumulative WHOLE-HOST idle CPU time in seconds, from /proc/stat first-line `idle` jiffies ÷ sysconf(_SC_CLK_TCK). Baseline for ratio computations: 1 - rate(idle)/cores = host CPU utilisation. Pair with elara_system_load_1m: high load + low idle = CPU-bound; high load + high idle = D-state blocked tasks (typically I/O-bound, confirm via elara_host_cpu_iowait_seconds_total).\n\
         # TYPE elara_host_cpu_idle_seconds_total counter\n\
         elara_host_cpu_idle_seconds_total {host_cpu_idle_secs}\n\
         # HELP elara_host_disk_reads_total Per-device count of disk read I/Os COMPLETED, from /proc/diskstats field 4. COUNTER - use rate() to get IOPS per disk; sum() to recover the host total. Labelled by device name so operators can see WHICH disk is saturated (typical Elara node: OS root on one disk, RocksDB data on a separate NVMe). Filtered to physical block devices (sd*/nvme*/vd*/xvd*/mmcblk*); virtual/composite (loop/ram/dm/zd/md) and partitions excluded so totals don't double-count. Sustained rate(reads) > device queue depth x (1/avg_latency) = HW saturated. Spinning disk ceiling ~150 IOPS; NVMe ~5k. Pairs with elara_host_cpu_iowait_seconds_total: iowait says disk is the global bottleneck, this says which one.\n\
         # TYPE elara_host_disk_reads_total counter\n\
         {disk_reads_lines}\
         # HELP elara_host_disk_writes_total Per-device count of disk write I/Os COMPLETED, from /proc/diskstats field 8. Counter. RocksDB compaction is the dominant write source on the data-disk; OS-root writes are small and bursty (logs, journal). Pair with elara_rocksdb_l0_files_total + elara_compaction_pressure_max_bytes scoped by device: rising rate(writes{{device='nvme0n1'}}) + rising L0 = data-disk compaction backed up; flat writes + rising L0 = back-pressure on the write path.\n\
         # TYPE elara_host_disk_writes_total counter\n\
         {disk_writes_lines}\
         # HELP elara_host_disk_read_sectors_total Per-device 512-byte sectors read, from /proc/diskstats field 6. Counter — rate × 512 = read bandwidth bytes/sec per device. Combines with rate(reads_total) at same device to derive avg request size: rate(read_sectors{{device=X}})/rate(reads{{device=X}}) sectors/IO. Large-sequential reads (snapshot restore, archival sync) → sectors-per-IO climbs; random small reads (point ledger lookups) → stays low.\n\
         # TYPE elara_host_disk_read_sectors_total counter\n\
         {disk_rsec_lines}\
         # HELP elara_host_disk_write_sectors_total Per-device 512-byte sectors written, from /proc/diskstats field 10. Counter — rate × 512 = write bandwidth bytes/sec. Compaction write amplification per device: rate(write_sectors{{device=X}})*512 / rate(record_bytes_in) = WAF. WAF > 30 on the data-disk = compaction-dominated steady state.\n\
         # TYPE elara_host_disk_write_sectors_total counter\n\
         {disk_wsec_lines}\
         # HELP elara_host_disk_read_ms_total Per-device cumulative ms servicing read I/Os, from /proc/diskstats field 7. Counter. avg read service time per device = rate(read_ms{{device=X}}) / rate(reads{{device=X}}) ms/IO. Healthy NVMe <1ms; spinning disk 5-15ms; saturated 50-500ms. Per-device labels make tail-latency attribution unambiguous when one disk in a multi-disk node is the bottleneck.\n\
         # TYPE elara_host_disk_read_ms_total counter\n\
         {disk_rms_lines}\
         # HELP elara_host_disk_write_ms_total Per-device cumulative ms servicing write I/Os, from /proc/diskstats field 11. Counter. avg write service time = rate(write_ms{{device=X}}) / rate(writes{{device=X}}). Compaction-induced write stalls: rate(write_ms{{device='data-disk'}}) climbing while rate(writes) stays flat = kernel queuing against saturation.\n\
         # TYPE elara_host_disk_write_ms_total counter\n\
         {disk_wms_lines}\
         # HELP elara_host_disk_in_flight Per-device instantaneous I/Os in the kernel block-layer queue, from /proc/diskstats field 12. GAUGE. Per-device queue-depth signal: 0-1 idle, 2-8 active healthy, 32+ sustained = saturated. NVMe caps at 1024/device; spinning disk effective ~32. Cleanest leading indicator for tail-latency growth without per-device profiling tools — and per-device labels make attribution direct (which disk is queue-saturated).\n\
         # TYPE elara_host_disk_in_flight gauge\n\
         {disk_inflight_lines}\
         # HELP elara_host_disk_io_ms_total Per-device cumulative ms during which the device was actively servicing I/O, from /proc/diskstats field 13. COUNTER. Single-disk utilization signal: rate(io_ms[1m]) / 60000 = utilization fraction. On phone-tier eMMC or shared-cloud NVMe, sustained > 0.30 means the disk is the bottleneck - RocksDB compactions are about to stall. NVMe in dedicated mode tolerates 0.7-0.8 sustained without latency tail. Distinct from elara_host_disk_in_flight: in_flight = queue depth NOW, io_ms = total busy time integrated over device lifetime.\n\
         # TYPE elara_host_disk_io_ms_total counter\n\
         {disk_io_ms_lines}\
         # HELP elara_host_disk_weighted_io_ms_total Per-device queue-time-weighted busy ms from /proc/diskstats field 14. COUNTER. rate(weighted_io_ms[1m]) = average queue depth integrated over the interval. Diverges UPWARD from rate(io_ms) when the queue grows faster than the disk drains — the leading-indicator for IO latency tails BEFORE elara_host_disk_read_ms_total or write_ms_total p99 move. (avg queue depth) = rate(weighted_io_ms) / rate(io_ms); when this ratio climbs above 1, latency tail is rising even though throughput numbers look flat.\n\
         # TYPE elara_host_disk_weighted_io_ms_total counter\n\
         {disk_weighted_io_ms_lines}\
         # HELP elara_host_disk_flushes_total Per-device count of FLUSH/FUA requests COMPLETED at the block layer, from /proc/diskstats field 19 (Linux ≥ 5.5; 0 on older kernels). COUNTER. Each RocksDB WAL fsync, every checkpoint sync_dir, every state_core flush_data() bottoms out as a kernel flush request. rate(flushes) ≈ fsyncs/sec hitting hardware. Healthy steady state on a write-active node: 5-30/sec; > 200/sec sustained = the WAL fsync loop is the hot path and throughput is fsync-bound, not bandwidth-bound. Distinct from elara_host_disk_writes_total which counts data-write IOs.\n\
         # TYPE elara_host_disk_flushes_total counter\n\
         {disk_flushes_lines}\
         # HELP elara_host_disk_flush_ms_total Per-device cumulative ms spent servicing flush requests from /proc/diskstats field 20 (Linux ≥ 5.5; 0 on older kernels). COUNTER. Average per-flush latency = rate(flush_ms) / rate(flushes). Phone-tier eMMC: 30-150 ms per fsync is normal; > 500 ms sustained = device is GC'ing internally and write tail will spike. Enterprise NVMe with PLP: < 1 ms. The most direct signal of write-amplification pain in RocksDB on a phone-tier device, and it surfaces BEFORE p99 elara_seal_apply_seconds_bucket starts climbing because the cliff is fsync, not data-write.\n\
         # TYPE elara_host_disk_flush_ms_total counter\n\
         {disk_flush_ms_lines}\
         # HELP elara_host_disk_discards_total Per-device count of discard (TRIM/UNMAP) IOs COMPLETED, from /proc/diskstats field 15 (Linux ≥ 4.18; 0 on older kernels). COUNTER. Each RocksDB SST deletion triggers a discard if the data-disk is mounted with `discard` (or fstrim.timer is active and the filesystem batches them). rate(discards) > 0 confirms TRIM is reaching hardware so the SSD/eMMC controller can free flash blocks for wear-leveling. Sustained 0 with sustained writes_total = TRIM is being swallowed in dm/lvm/raid layer or `discard` is not mounted; check `mount | grep discard` on the data-disk. Without TRIM the device's internal free-block pool shrinks and write-amp climbs over weeks (NAND garbage-collection contention).\n\
         # TYPE elara_host_disk_discards_total counter\n\
         {disk_discards_lines}\
         # HELP elara_host_disk_discards_merged_total Per-device discard IOs MERGED by the kernel before issue, from /proc/diskstats field 16 (Linux ≥ 4.18; 0 on older kernels). COUNTER. Same merge semantics as reads_merged / writes_merged: kernel coalesces adjacent discard ranges before sending to hardware. High merge count is HEALTHY — it means the filesystem requested many small adjacent TRIMs and the kernel was efficient. Use as merge denominator alongside discards_total: rate(discards_merged) / rate(discards) = avg merge factor. Cosmetic on its own.\n\
         # TYPE elara_host_disk_discards_merged_total counter\n\
         {disk_discards_merged_lines}\
         # HELP elara_host_disk_discard_sectors_total Per-device 512-byte sectors successfully discarded (TRIM volume), from /proc/diskstats field 17 (Linux ≥ 4.18; 0 on older kernels). COUNTER. rate(discard_sectors) × 512 = bytes/sec freed for wear-leveling. TRIM-efficiency ratio: rate(discard_sectors) / rate(write_sectors). Healthy steady-state for RocksDB on a `discard`-mounted disk ≈ 0.5-0.8 (compactions delete old SSTs after writing new ones). Anomalously low ratio = TRIM passes are being eaten by an LVM/dm/raid layer that doesn't pass discards through to the device. Anomalously high ratio = bursty deletion (compaction storm) and hardware is busy GCing.\n\
         # TYPE elara_host_disk_discard_sectors_total counter\n\
         {disk_discard_sectors_lines}\
         # HELP elara_host_disk_discard_ms_total Per-device cumulative ms spent servicing discard requests, from /proc/diskstats field 18 (Linux ≥ 4.18; 0 on older kernels). COUNTER. avg per-discard latency = rate(discard_ms) / rate(discards). On phone-tier eMMC each TRIM can stall the device for tens of ms — sustained > 50 ms/op is the visibility you need to know whether the `discard` mount option is causing IO tail latency spikes vs leaving it off and using `fstrim.timer` to batch trims off-peak. Enterprise NVMe: typically < 1 ms/op. Pair with elara_host_disk_discard_sectors_total to attribute tail latency: high ms/op + high sectors = device GC contention.\n\
         # TYPE elara_host_disk_discard_ms_total counter\n\
         {disk_discard_ms_lines}\
         # HELP elara_process_open_fds Count of file descriptors currently held by elara-node, from /proc/self/fd. Includes every open file, TCP/Unix socket, pipe, eventfd, timerfd, and RocksDB SST. Each peer connection, each open SST, each PQ-WS stream consumes one slot. Pair with elara_process_max_fds: ratio open_fds/max_fds > 0.80 = page operator BEFORE the saturation cliff (at 100% the kernel rejects accept() with EMFILE and elara-node silently stops accepting peers).\n\
         # TYPE elara_process_open_fds gauge\n\
         elara_process_open_fds {process_open_fds}\n\
         # HELP elara_process_max_fds Soft RLIMIT_NOFILE for elara-node, read live via getrlimit(2). The hard ceiling on open_fds. Phone-tier systemd default is 1024 — at saturation the kernel rejects accept(), open(), and socket() with EMFILE/EBADF, killing new peer connections AND new RocksDB SST opens. Operator playbook: bump LimitNOFILE in the systemd unit BEFORE saturation; mainnet target floor is 65536 to handle 10K+ peer fanout × DAG edge-set RocksDB CFs. Distinct from /proc/self/limits which is the exec-time snapshot — this gauge tracks live `prlimit --nofile=N --pid=PID` changes too.\n\
         # TYPE elara_process_max_fds gauge\n\
         elara_process_max_fds {process_max_fds}\n\
         # HELP elara_host_tcp_retrans_segs_total Cumulative count of TCP segments RETRANSMITTED by the kernel from /proc/net/snmp `Tcp.RetransSegs`. COUNTER. The canonical signal for TCP path quality: rate(retrans_segs)/rate(out_segs) = retransmit fraction. Healthy < 1% sustained, > 2% sustained = NIC saturation, network-path degradation, or peer-side congestion. Pairs with per-process bandwidth which says WHAT we sent - this says how cleanly the network DELIVERED it.\n\
         # TYPE elara_host_tcp_retrans_segs_total counter\n\
         elara_host_tcp_retrans_segs_total {host_tcp_retrans_segs}\n\
         # HELP elara_host_tcp_out_segs_total Cumulative count of TCP segments transmitted from /proc/net/snmp `Tcp.OutSegs`. Counter — denominator for retransmit-fraction calculations: rate(retrans_segs)/rate(out_segs).\n\
         # TYPE elara_host_tcp_out_segs_total counter\n\
         elara_host_tcp_out_segs_total {host_tcp_out_segs}\n\
         # HELP elara_host_tcp_attempt_fails_total Cumulative count of outbound TCP connection attempts that FAILED to establish, from /proc/net/snmp `Tcp.AttemptFails` (SYN sent, no SYN+ACK received within retry budget, kernel abandoned the attempt). Counter. Sustained high rate(attempt_fails)/rate(active_opens) = peer addresses are stale, peers crashed mid-handshake, or the outbound NAT is dropping fresh flows. Distinct from `EstabResets` which is connections that DID establish then died.\n\
         # TYPE elara_host_tcp_attempt_fails_total counter\n\
         elara_host_tcp_attempt_fails_total {host_tcp_attempt_fails}\n\
         # HELP elara_host_tcp_curr_estab Live count of TCP connections in ESTABLISHED state from /proc/net/snmp `Tcp.CurrEstab`. GAUGE - single-scalar dashboard signal. Distinct from per-state socket inventory; this is kernel-side from the connection table.\n\
         # TYPE elara_host_tcp_curr_estab gauge\n\
         elara_host_tcp_curr_estab {host_tcp_curr_estab}\n\
         # HELP elara_host_tcp_out_rsts_total Cumulative count of TCP RST packets we sent, from /proc/net/snmp `Tcp.OutRsts`. Counter. RST is the kernel's 'this segment does not match any open connection' reply. Sustained rate(out_rsts) > 5/sec = stale peer state on the other side (peers dialing dead listeners), gossip protocol leaking dead-peer addresses, or scanning traffic from the open internet.\n\
         # TYPE elara_host_tcp_out_rsts_total counter\n\
         elara_host_tcp_out_rsts_total {host_tcp_out_rsts}\n\
         # HELP elara_host_udp_rcvbuf_errors_total Cumulative count of UDP datagrams DROPPED because the kernel receive buffer overflowed before userspace could read them, from /proc/net/snmp `Udp.RcvbufErrors`. COUNTER. Direct signal of UDP pipeline saturation: we got the packet on the wire but our reader was too slow. Pair with per-interface RX-drop counters; if UDP rcvbuf rising while device-RX is clean = the read loop is the bottleneck (CPU-bound in network handler), not the NIC.\n\
         # TYPE elara_host_udp_rcvbuf_errors_total counter\n\
         elara_host_udp_rcvbuf_errors_total {host_udp_rcvbuf_errors}\n\
         # HELP elara_system_load_5m 5-minute kernel load average from /proc/loadavg field 2. Companion to elara_system_load_1m — operators need 5m and 15m to distinguish a transient 1-minute spike (frame stutter, GC pause, single hot peer) from sustained pressure that warrants intervention. Same caveat as 1m: not normalized — divide by elara_system_load_cores for cross-host comparison. Healthy steady state: load_5m ≈ load_1m. load_5m climbing while load_1m stays flat = pressure drained recently. load_5m below load_1m = pressure just started.\n\
         # TYPE elara_system_load_5m gauge\n\
         elara_system_load_5m {host_load_5m:.4}\n\
         # HELP elara_system_load_15m 15-minute kernel load average from /proc/loadavg field 3. The 'sustained pressure' signal — anything > cores × 1.0 here means the box has been overloaded for a real stretch, not just a transient burst. Use with elara_system_load_normalized: load_15m / cores > 0.8 is the definition of a chronically saturated host that needs more capacity, not a tuning fix.\n\
         # TYPE elara_system_load_15m gauge\n\
         elara_system_load_15m {host_load_15m:.4}\n\
         # HELP elara_host_runnable_tasks Instantaneous count of kernel tasks in RUNNABLE state — waiting for or actively using a CPU — from /proc/loadavg field 4 numerator (`runnable/total`). GAUGE. The most direct scheduler-pressure signal: load_1m is the EWMA of this value over a minute, so when load_1m climbs it's because runnable_tasks is climbing. runnable_tasks > cores sustained = there are MORE tasks ready to run than CPUs to run them, which is exactly what causes async-task wakeup latency to rise. Single-second resolution where load_1m is 60-second smoothed.\n\
         # TYPE elara_host_runnable_tasks gauge\n\
         elara_host_runnable_tasks {host_runnable_tasks}\n\
         # HELP elara_host_total_tasks Total kernel task count (threads + processes) from /proc/loadavg field 4 denominator. GAUGE. Includes elara-node's own threads, every other process on the box, and every kernel thread. Doesn't directly show pressure — runnable_tasks does that — but a fast-climbing total often means a process is leaking threads (typical: a panicking thread pool keeps respawning, or libp2p / tokio worker count is mis-tuned). Static-ish steady state on a phone-tier node: 200-500. Cluster-wide divergence (one node has 5x the others) is a process-leak smoke alarm.\n\
         # TYPE elara_host_total_tasks gauge\n\
         elara_host_total_tasks {host_total_tasks}\n\
         # HELP elara_host_procs_running Instantaneous count of processes/threads in RUNNABLE state via /proc/stat procs_running. GAUGE. Same scheduler-pressure signal as elara_host_runnable_tasks (which comes from /proc/loadavg field 4) but sampled fresh from /proc/stat — the kernel populates both from the same internal counter, so they should agree at scrape time. Cluster-wide divergence between the two on a single node = scrape race or kernel-version quirk worth investigating, not a real signal divergence.\n\
         # TYPE elara_host_procs_running gauge\n\
         elara_host_procs_running {host_procs_running}\n\
         # HELP elara_host_procs_blocked Instantaneous count of processes/threads in D-state (uninterruptible sleep, typically blocked on disk I/O) via /proc/stat procs_blocked. GAUGE. The classic 'stuck in iowait' signal — D-state means the kernel cannot wake the task even with a signal. On phone-tier eMMC nodes this climbs whenever many threads cold-fault into mmap'd RocksDB SSTs at once. Sustained `procs_blocked > 0` = some task is wedged in I/O wait right now; pair with elara_psi_io_full_avg10 (PSI's similar signal computed differently) — divergence indicates short-window vs broader pressure.\n\
         # TYPE elara_host_procs_blocked gauge\n\
         elara_host_procs_blocked {host_procs_blocked}\n\
         # HELP elara_host_ctxt_switches_total Cumulative WHOLE-HOST context switches across ALL processes via /proc/stat ctxt. COUNTER. The host-wide counterpart to elara_process_ctxt_switches_voluntary_total + nonvoluntary - comparing the two rates tells you what fraction of the box's scheduler activity is elara-node. rate(elara_process_ctxt_switches[5m]) / rate(elara_host_ctxt_switches_total[5m]) > 0.5 = elara-node dominates this host's scheduling load (common on dedicated nodes); << 0.1 on a host where elara-node is logically the main workload = something else is generating scheduler pressure.\n\
         # TYPE elara_host_ctxt_switches_total counter\n\
         elara_host_ctxt_switches_total {host_ctxt_total}\n\
         # HELP elara_host_intr_total Cumulative WHOLE-HOST interrupt count via /proc/stat intr (first field — the sum across all IRQ vectors). COUNTER. Useful as a 'device activity' baseline. Sharp climb in rate without a corresponding rate(elara_gossip_bytes_in_total) / rate(elara_host_disk_reads_total) increase often indicates a NIC IRQ storm or misbehaving driver pinning a CPU to interrupt servicing — pair with rate(elara_host_cpu_softirq_seconds_total) which spikes when interrupt handling overflows into softirq.\n\
         # TYPE elara_host_intr_total counter\n\
         elara_host_intr_total {host_intr_total}\n\
         # HELP elara_host_fd_allocated System-wide allocated file descriptors via /proc/sys/fs/file-nr field 1. GAUGE. Companion to elara_process_open_fds_count: process-level FD spike = elara-node leak; host-level FD spike with elara-node's process FD flat = some OTHER process on the host is leaking and we'll be collateral damage when the kernel's global FD allocator runs out. Ratio elara_host_fd_allocated / elara_host_fd_max > 0.8 = the next open(2) anywhere on the host (including elara-node's accept loop) is at material EMFILE risk.\n\
         # TYPE elara_host_fd_allocated gauge\n\
         elara_host_fd_allocated {host_fd_allocated}\n\
         # HELP elara_host_fd_max System-wide file-descriptor limit via /proc/sys/fs/file-nr field 3 (= /proc/sys/fs/file-max). GAUGE. The global ceiling — typically 1M+ on default-tuned kernels but can be much lower on phone-tier or container hosts (32k or 64k). Static unless an operator tunes it. Use as the denominator when computing host-wide FD pressure ratio against elara_host_fd_allocated. If max < 65536 on a node serving tens of peers + tens of pull connections, the node is configured below safe operating range.\n\
         # TYPE elara_host_fd_max gauge\n\
         elara_host_fd_max {host_fd_max}\n\
         # HELP elara_host_sockets_used Total kernel-tracked sockets (all protocols) from /proc/net/sockstat 'sockets: used'. GAUGE. Aggregate of TCP+UDP+UNIX+RAW. Typically tracks elara_process_open_fds_count + sockets owned by other processes; divergence (sockets climbing while process FDs flat) is the same 'noisy neighbor' signal as elara_host_fd_allocated. Useful as a coarse 'how many sockets does the box hold' top-line - drill down with the per-protocol gauges.\n\
         # TYPE elara_host_sockets_used gauge\n\
         elara_host_sockets_used {host_sockets_used}\n\
         # HELP elara_host_tcp_inuse TCP sockets currently in active state from /proc/net/sockstat 'TCP: inuse'. GAUGE. Excludes TIME_WAIT (those are in 'tw'). Roughly the count of live mesh peer connections + RPC clients + outbound pull sockets. At 10K-peer fanout this is the canonical headcount; pair with rate(elara_gossip_bytes_in_total) — high inuse with low bytes-in = lots of idle peers, possibly indicating connection leak in the gossip dial loop. The kernel global ceiling for active TCP sockets is essentially unbounded but ephemeral-port exhaustion bites long before sock-table limits.\n\
         # TYPE elara_host_tcp_inuse gauge\n\
         elara_host_tcp_inuse {host_tcp_inuse}\n\
         # HELP elara_host_tcp_orphan TCP sockets in orphan state from /proc/net/sockstat 'TCP: orphan'. GAUGE. 'Orphan' = the local userspace closed but the connection is still consuming kernel resources (FIN_WAIT_1/FIN_WAIT_2/CLOSING/LAST_ACK awaiting peer ack) and elara-node no longer has an FD for it. Kernel cap is `net.ipv4.tcp_max_orphans` (default 4096 on stock kernels, 1024 on phone-tier). When the cap is hit kernel SILENTLY DISCARDS new orphan candidates with no error to userspace; sustained orphan > 0.5 × cap = peers are crashing without proper close (no FIN), and we are about to start corrupting graceful-shutdown semantics for healthy peers as cap pressure rises.\n\
         # TYPE elara_host_tcp_orphan gauge\n\
         elara_host_tcp_orphan {host_tcp_orphan}\n\
         # HELP elara_host_tcp_tw TCP sockets in TIME_WAIT state from /proc/net/sockstat 'TCP: tw'. GAUGE. TIME_WAIT is the 60-second cooldown after a clean close on the active-close side, holding the (src_ip,src_port,dst_ip,dst_port) 4-tuple to prevent stale-segment confusion. Each TIME_WAIT pins one ephemeral port for ~60s. With default `net.ipv4.ip_local_port_range=32768-60999` (~28K usable ports) and a peer-churn workload generating, say, 500 closes/sec, tw stabilizes at 500*60=30K — i.e., RIGHT at port-exhaustion. Sustained tw > 20K on a phone-tier box = next outbound TCP connect() may fail with EADDRNOTAVAIL. Operator playbook: enable `tcp_tw_reuse` or widen the port range — DON'T enable `tcp_tw_recycle` (removed in modern kernels, was buggy with NAT).\n\
         # TYPE elara_host_tcp_tw gauge\n\
         elara_host_tcp_tw {host_tcp_tw}\n\
         # HELP elara_host_tcp_alloc Total TCP socket structures allocated from /proc/net/sockstat 'TCP: alloc'. GAUGE. Sum of inuse + tw + orphan + others (SYN_SENT/SYN_RECV/etc). A spike here without inuse climbing = connection churn (lots of half-open dials or short-lived flows). Pair with rate(elara_host_tcp_attempt_fails_total) - high alloc with high attempt_fails = SYN flood pattern (we're dialing dead peers); high alloc with clean attempt_fails but high tw = healthy peers but excessive re-connect.\n\
         # TYPE elara_host_tcp_alloc gauge\n\
         elara_host_tcp_alloc {host_tcp_alloc}\n\
         # HELP elara_host_tcp_mem_pages Kernel pages used by TCP socket buffers (send + recv) from /proc/net/sockstat 'TCP: mem'. GAUGE. Each page = 4096 bytes on x86_64. CRITICAL: this memory is NOT counted in elara-node's RSS — kernel socket buffers live in kernel-space, so a fleet at 10K peers can pin hundreds of MB the process metrics never see. Compare against `net.ipv4.tcp_mem` triplet (low/pressure/high — when alloc crosses 'pressure' the kernel begins shrinking buffers, when it crosses 'high' the kernel rejects new sends with ENOBUFS). On phone-tier 4GB nodes the default 'high' is ~80MB worth of pages — a 10K-peer mesh hitting that means seal-broadcast tail latency degrades silently as buffers shrink.\n\
         # TYPE elara_host_tcp_mem_pages gauge\n\
         elara_host_tcp_mem_pages {host_tcp_mem_pages}\n\
         # HELP elara_host_udp_inuse UDP sockets in use from /proc/net/sockstat 'UDP: inuse'. GAUGE. Today elara-node's primary transport is TCP (PQ-handshake over noise), but mDNS, Tailscale userspace, libp2p QUIC fallback, and the host's own DNS resolver all bind UDP sockets. Useful as a baseline + change-detector: a step climb here is usually a co-tenant misconfiguration (a UDP-heavy neighbor) rather than elara-node itself, but it shares the same kernel socket-buffer pool as TCP and can starve TCP's receive path under saturation.\n\
         # TYPE elara_host_udp_inuse gauge\n\
         elara_host_udp_inuse {host_udp_inuse}\n\
         # HELP elara_host_udp_mem_pages Kernel pages used by UDP socket buffers from /proc/net/sockstat 'UDP: mem'. GAUGE. Same units (4096 bytes/page) as TCP mem - pinned in kernel-space, invisible to RSS. Compare against `net.ipv4.udp_mem` triplet for pressure detection. UDP datagrams that arrive when the receive buffer is full are silently dropped (counted in elara_host_udp_rcvbuf_errors_total) - a sustained climb here ahead of the 'pressure' threshold is the leading indicator before that counter starts moving.\n\
         # TYPE elara_host_udp_mem_pages gauge\n\
         elara_host_udp_mem_pages {host_udp_mem_pages}\n\
         # HELP elara_host_listen_overflows_total TCP listen-queue overflows from /proc/net/netstat 'TcpExt: ListenOverflows'. COUNTER. Each event = a connection completed the 3-way handshake but the accept() queue was full, so the kernel dropped the connection. The peer sees a successful TCP open then a silent reset later — looks like a load-balancer flake from the outside. THE definitive signal that the userspace accept() loop is too slow OR the listen backlog (`somaxconn`, default 4096; `tcp_max_syn_backlog`) is undersized for offered load. On phone-tier where somaxconn=128, even a brief gossip burst can overflow. Distinct from elara_host_tcp_attempt_fails_total which counts OUTBOUND failed dials — listen_overflows is INBOUND. Pair with elara_socket_recv_drops_total and elara_process_open_fds_count — overflow with FDs near max = saturation, overflow with FDs healthy = pure CPU starvation in the accept loop.\n\
         # TYPE elara_host_listen_overflows_total counter\n\
         elara_host_listen_overflows_total {host_listen_overflows}\n\
         # HELP elara_host_listen_drops_total TCP listen-state drops from /proc/net/netstat 'TcpExt: ListenDrops'. COUNTER. Strict superset of ListenOverflows — also counts SYN cookies refused, SYN-cookie-disabled half-open exhaustion, and rare path-MTU/icmp-unreachable rejects on the listen socket. listen_drops > listen_overflows = there are non-overflow rejections (bad source ports, bogus SYN-flags, syncookie hits). When listen_drops climbs but listen_overflows is flat, the issue is upstream of the accept queue — usually a SYN-flood (real or synthetic from a misbehaving peer in a tight reconnect loop). When both move together, the accept backlog is the root cause.\n\
         # TYPE elara_host_listen_drops_total counter\n\
         elara_host_listen_drops_total {host_listen_drops}\n\
         # HELP elara_host_tcp_timeouts_total TCP retransmit-exhaustion timeouts from /proc/net/netstat 'TcpExt: TCPTimeouts'. COUNTER. Each event = the local stack gave up on an existing connection because retransmits exhausted (default 15 retries with exponential backoff, ~924 s wall-clock) and the kernel reset the socket. Distinct from elara_host_tcp_retrans_segs_total which counts INDIVIDUAL retransmit packets — timeouts counts the FINAL connection-killing event after all retries failed. Sustained > 1/min = peers are routing-blackholed (bad peer in gossip table, network partition, MTU mismatch). Each timeout costs a connection pool slot for ~15 minutes — fleet-wide tail latency degrades as peer-pool replenishment slows.\n\
         # TYPE elara_host_tcp_timeouts_total counter\n\
         elara_host_tcp_timeouts_total {host_tcp_timeouts}\n\
         # HELP elara_host_tcp_memory_pressures_total TCP memory pressure entries from /proc/net/netstat 'TcpExt: TCPMemoryPressures'. COUNTER. Each event = the kernel crossed the middle (`pressure`) threshold of the `net.ipv4.tcp_mem` triplet (low/pressure/high). Below low = freely allocate; between low and high but moving toward pressure = kernel begins shrinking per-socket send/recv buffers; above high = new sends fail with ENOBUFS. Counter increments once per ENTRY into pressure (not per byte), so small numbers are still significant — each entry corresponds to a measurable degradation event for ALL active sockets on the host. Phone-tier 4GB box `tcp_mem` 'pressure' is ~50MB worth of pages. Pair with elara_host_tcp_mem_pages — pages climbing toward 'pressure' is the LEADING indicator before this counter moves; this counter is the AFTER-THE-FACT confirmation.\n\
         # TYPE elara_host_tcp_memory_pressures_total counter\n\
         elara_host_tcp_memory_pressures_total {host_tcp_mem_pressure}\n\
         # HELP elara_host_tcp_abort_on_memory_total TCP connections aborted due to socket-buffer allocation failure from /proc/net/netstat 'TcpExt: TCPAbortOnMemory'. COUNTER. Each event = an existing connection received a segment that needed buffer space, the kernel couldn't allocate (above 'high' tcp_mem threshold OR per-socket sk_sndbuf cap), so the kernel killed the connection with a RST. The peer that just sent us a record block / seal / attestation now sees a silent reset. CRITICAL signal — the rare events that actually correspond to lost record-flow on a live mainnet. Pair with elara_host_tcp_memory_pressures_total above: pressures = warning, abort_on_memory = damage already done. Operator playbook: raise net.ipv4.tcp_mem `high` ceiling OR reduce per-peer fanout. Phone-tier alert threshold: > 0 sustained = act now.\n\
         # TYPE elara_host_tcp_abort_on_memory_total counter\n\
         elara_host_tcp_abort_on_memory_total {host_tcp_abort_on_mem}\n\
         # HELP elara_tcp_syn_retrans_total TCP SYN retransmissions from /proc/net/netstat 'TcpExt: TCPSynRetrans'. COUNTER. Each event = an outbound connect() retried its SYN because the first attempt timed out (initial RTO ~1s, then exponential backoff per RFC 6298: 1 → 2 → 4 → 8s …). At 10K-peer target fanout, 'I can only reach 7K of 10K peers' looks identical to '3K are intentionally not connected' WITHOUT this counter. Once it moves, the gap is dial-time loss — peer-discovery degradation, not policy. Distinct from elara_host_tcp_attempt_fails_total which counts the FINAL connection-pool dial failure after retransmits exhaust; this counter increments on EVERY SYN retry, so it moves BEFORE attempt_fails and gives operators ~30s of runway. Sustained rate > 5/s = peer-discovery layer is bleeding; investigate firewall, MTU mismatch, or SYN-cookie path on a downstream peer.\n\
         # TYPE elara_tcp_syn_retrans_total counter\n\
         elara_tcp_syn_retrans_total {host_tcp_syn_retrans}\n\
         # HELP elara_tcp_rcv_queue_drop_total Per-socket receive-queue overflow drops from /proc/net/netstat 'TcpExt: TCPRcvQDrop'. COUNTER. Each event = a TCP segment arrived but the per-socket recv queue was already full at the SO_RCVBUF cap, so the kernel dropped the segment and forced the sender into retransmit. Direct signal that the userspace consumer (Tokio task pool) is not draining recv buffers fast enough — back-pressure has reached the kernel. Pair with elara_process_threads and elara_cgroup_pressure_some_avg10 cpu: high recvq drops + low cgroup PSI cpu = userspace task blocked on something other than CPU (mutex, fs, IPC). High recvq drops + high cgroup PSI cpu = literal CPU starvation, scale workers or move off the contended host. Sustained > 0 means peers are seeing slowness; sustained rate > 10/s is record-flow loss territory.\n\
         # TYPE elara_tcp_rcv_queue_drop_total counter\n\
         elara_tcp_rcv_queue_drop_total {host_tcp_rcv_q_drop}\n\
         # HELP elara_tcp_backlog_drop_total Per-socket backlog-queue drops from /proc/net/netstat 'TcpExt: TCPBacklogDrop'. COUNTER. Distinct from rcv_queue_drop: backlog drops occur in the temporary kernel-side queue used WHILE the socket lock is held by another path (typically a sender currently writing). When a hot peer floods one socket, the producer side holds the lock long enough that the receive-side handler gets bumped to backlog; if backlog also fills, the kernel drops. Almost always indicates ONE peer is gossiping disproportionately (committee leader, anchor) with no local-side back-pressure escape valve. Operator playbook: identify the chatty peer via tcpdump, raise net.core.netdev_max_backlog, or add per-peer rate-limiting in the gossip layer. Sustained > 0 on a multi-peer node = a single hot socket is degrading the rest.\n\
         # TYPE elara_tcp_backlog_drop_total counter\n\
         elara_tcp_backlog_drop_total {host_tcp_backlog_drop}\n\
         # HELP elara_tcp_pfmemalloc_drop_total TCP packets dropped during PF_MEMALLOC reserve from /proc/net/netstat 'TcpExt: PFMemallocDrop'. COUNTER. CRITICAL signal. Each event = the kernel dropped an incoming packet because allocating the skb would have required dipping into the PF_MEMALLOC emergency-reserve pool (memory-pressure last-ditch allocator). The kernel itself is out of memory for socket buffers; ESTABLISHED connections are starting to fail forward. On phone-tier 2GB nodes this typically fires moments before OOM-kill. ANY nonzero value is page-an-operator territory — pair with elara_host_oom_kill_total and elara_process_vmswap_kb. Operator playbook: investigate which co-tenant or workload spiked, immediately reduce per-peer fanout via gossip backpressure config, prepare for graceful elara-node shutdown if oom_kill is also climbing.\n\
         # TYPE elara_tcp_pfmemalloc_drop_total counter\n\
         elara_tcp_pfmemalloc_drop_total {host_tcp_pf_memalloc_drop}\n\
         # HELP elara_tcp_spurious_rtos_total False retransmission-timeout firings from /proc/net/netstat 'TcpExt: TCPSpuriousRTOs'. COUNTER. Each event = the local stack fired an RTO and retransmitted, but the original ACK was just delayed (network jitter, not loss) and arrived right after. Counter goes up on high-latency or intercontinental link variance WITHOUT any actual packet loss. Pure-jitter signal. Diagnostic correlation: high SpuriousRTOs + low TCPTimeouts = jitter not loss, the network is slow not broken - operator action is to increase TCP_USER_TIMEOUT on long-haul peer connections. High SpuriousRTOs + high TCPTimeouts = both are happening, the path is genuinely bad (mid-route congestion or bufferbloat). On a healthy LAN this stays at low single digits forever; sustained climb on a single node = check egress quota or upstream BGP routes.\n\
         # TYPE elara_tcp_spurious_rtos_total counter\n\
         elara_tcp_spurious_rtos_total {host_tcp_spurious_rtos}\n\
         # HELP elara_tcp_lost_retransmit_total Retransmitted segments that were themselves lost from /proc/net/netstat 'TcpExt: TCPLostRetransmit'. COUNTER. Each event = the local stack retransmitted (because of fast-retransmit or RTO) and the retransmitted copy was ALSO lost — the path is collapsing. Fast-retransmit's recovery mechanism has degraded to 'send the same packet 3+ times before getting through'. At 10K-peer mesh we expect this to be near-zero per peer; non-zero sustained = WAN-link congestion, asymmetric routing breakage, or an adversarial intermediary dropping retries selectively. Worst-case signal in this set after PFMemallocDrop — on a healthy global mesh, packet-loss-on-retry implies path failure for the duration of the lost-retransmit window. Operator playbook: traceroute the affected peers, check whether one upstream link is at fault, route around if peer churn allows.\n\
         # TYPE elara_tcp_lost_retransmit_total counter\n\
         elara_tcp_lost_retransmit_total {host_tcp_lost_retransmit}\n\
         # HELP elara_host_softnet_processed_total Packets processed by the NAPI poll loop summed across all CPUs from /proc/net/softnet_stat column 0. COUNTER. Throughput denominator for the dropped/squeeze rate signals - alone it is uninteresting, but `rate(softnet_dropped) / rate(softnet_processed)` gives the kernel-level packet loss ratio at the network-stack ingress (distinct from per-NIC driver-level drops and per-socket backlog drops). On a healthy multi-core host with RPS enabled, processed should be roughly equal across CPUs; large spread = RPS misconfigured.\n\
         # TYPE elara_host_softnet_processed_total counter\n\
         elara_host_softnet_processed_total {host_softnet_processed}\n\
         # HELP elara_host_softnet_dropped_total Kernel-level packet drops at the NAPI input backlog summed across CPUs from /proc/net/softnet_stat column 1. COUNTER. Each event = the NAPI poll loop on a CPU couldn't keep up and the per-CPU input queue (`netdev_max_backlog`, default 1000) overflowed. INVISIBLE to per-NIC drop metrics because the drop happens AFTER the NIC's driver delivered the packet. Worst-case signature: one CPU pinned for all RX (RPS off or pinned to CPU0) → that CPU's softnet_dropped climbs while netdev rx_drop stays flat. Pair with elara_host_softnet_dropped_max_per_cpu to localize. Operator playbook: enable RPS (`echo ffff > /sys/class/net/eth0/queues/rx-0/rps_cpus`) OR raise netdev_max_backlog if the CPU already has spare cycles.\n\
         # TYPE elara_host_softnet_dropped_total counter\n\
         elara_host_softnet_dropped_total {host_softnet_dropped}\n\
         # HELP elara_host_softnet_time_squeeze_total NAPI poll-budget exhaustion events summed across CPUs from /proc/net/softnet_stat column 2. COUNTER. NAPI's per-poll budget is `netdev_budget` packets (default 300) and `netdev_budget_usecs` microseconds. When a CPU receives packets faster than the poll loop can drain in one budget unit, time_squeeze increments and the kernel reschedules NAPI to try again. Sustained rate > 100/s on a single CPU = that CPU is the RX bottleneck. Doesn't drop packets directly (just delays them slightly) but tracks proximity to the dropped cliff: time_squeeze climbing without softnet_dropped moving = ~seconds-to-minutes of runway before drops start. Mainnet phone-tier alert: rate > 50/s sustained = raise netdev_budget OR enable RPS.\n\
         # TYPE elara_host_softnet_time_squeeze_total counter\n\
         elara_host_softnet_time_squeeze_total {host_softnet_time_squeeze}\n\
         # HELP elara_host_softnet_flow_limit_total RFS (Receive Flow Steering) per-flow input-queue limit drops summed across CPUs from /proc/net/softnet_stat column 8 (kernel ≥ 3.6). COUNTER. RFS, when enabled, caps the per-CPU input queue allocation that any SINGLE flow (5-tuple hash) can consume — preventing one elephant flow from starving small flows on the same CPU. flow_limit increments when a flow tries to enqueue past its allocation and the kernel forces a drop. ZERO on a system without RFS configured. Non-zero in production means: (a) RFS is on and (b) one peer is sending so much that the kernel is rate-limiting it. Pair with elara_tcp_backlog_drop_total: both move together when one peer dominates a single socket. Operator playbook: identify the chatty peer, raise net.core.flow_limit_table_len, or add per-peer rate-limiting at the gossip layer.\n\
         # TYPE elara_host_softnet_flow_limit_total counter\n\
         elara_host_softnet_flow_limit_total {host_softnet_flow_limit}\n\
         # HELP elara_host_softnet_dropped_max_per_cpu Maximum softnet_dropped value observed across all CPUs from /proc/net/softnet_stat column 1. GAUGE. Surfaces RX imbalance without paying per-CPU cardinality cost. The softnet_dropped_total / N_cpus mean is misleading when one CPU has 99% of the drops: the mean shows '12 drops/cpu' but the max shows '12000 drops on cpu5, 0 elsewhere'. Operator alert: ratio (max_per_cpu / total) > 0.6 sustained = single-CPU bottleneck (likely RPS off or pinned). On a balanced load this approaches total/N_cpus from below; on an unbalanced load it approaches total. This is a CUMULATIVE-since-boot value, so dashboards should track delta() not the raw value.\n\
         # TYPE elara_host_softnet_dropped_max_per_cpu gauge\n\
         elara_host_softnet_dropped_max_per_cpu {host_softnet_dropped_max_per_cpu}\n\
         # HELP elara_host_tcp_delivered_total Bytes delivered to TCP applications since boot from /proc/net/netstat TcpExt `TCPDelivered`. COUNTER. Denominator for the ECN-CE rate: rate(delivered_ce) / rate(delivered) is the fraction of delivered bytes marked Congestion Experienced by an in-path AQM. Without this denominator the CE counter alone is uninterpretable (a 100/s CE rate could be benign if delivered=10M/s, or a path-collapse signal if delivered=1k/s).\n\
         # TYPE elara_host_tcp_delivered_total counter\n\
         elara_host_tcp_delivered_total {host_tcp_delivered}\n\
         # HELP elara_host_tcp_delivered_ce_total Bytes delivered with the ECN Congestion Experienced bit set, from /proc/net/netstat TcpExt `TCPDeliveredCE`. COUNTER. The ECN signal: an in-path Active Queue Management box (FQ_CoDel, PIE, RED) marked these segments as a back-pressure hint instead of dropping them. 0% sustained = no ECN-aware AQM in the path (typical wired DCs); low % under load = AQM healthy and signalling early; high sustained % = path is congested and AQM is asking us to slow down. Mobile / cellular carrier paths typically negotiate ECN. Pairs with delivered_total: alert on rate(delivered_ce) / rate(delivered) > 0.05 sustained = path congestion.\n\
         # TYPE elara_host_tcp_delivered_ce_total counter\n\
         elara_host_tcp_delivered_ce_total {host_tcp_delivered_ce}\n\
         # HELP elara_host_tcp_loss_probes_total TCP Tail Loss Probe (TLP, RFC 8985) probes sent, from /proc/net/netstat TcpExt `TCPLossProbes`. COUNTER. TLP fires a probe segment when the kernel suspects tail loss (last segment of a flight got lost), without waiting for the full RTO. A probe is conceptually 'are you still there?' — getting an ACK lets us recover the loss in 1×RTT instead of 1×RTO. Counter rate = how often the kernel suspects tail loss; pairs with loss_probe_recovery_total to compute effectiveness.\n\
         # TYPE elara_host_tcp_loss_probes_total counter\n\
         elara_host_tcp_loss_probes_total {host_tcp_loss_probes}\n\
         # HELP elara_host_tcp_loss_probe_recovery_total TLP probes that successfully recovered the suspected loss, from /proc/net/netstat TcpExt `TCPLossProbeRecovery`. COUNTER. Ratio rate(loss_probe_recovery) / rate(loss_probes) is TLP effectiveness. High ratio (>0.7) = probes are doing their job, network has tail-loss but it's recoverable. Low ratio (<0.3) = probes fire but loss is real (segments still missing on retry); the network is producing actual loss not jitter, RTO + slow-start incoming. Below the 0.5 threshold sustained → operator should investigate path quality, not TCP-stack tuning.\n\
         # TYPE elara_host_tcp_loss_probe_recovery_total counter\n\
         elara_host_tcp_loss_probe_recovery_total {host_tcp_loss_probe_recovery}\n\
         # HELP elara_host_tcp_sack_reorder_total SACK-driven packet reordering events detected, from /proc/net/netstat TcpExt `TCPSACKReorder`. COUNTER. Distinct from drops (segments arrived, just out of order). Wireless / cellular paths reorder due to handovers and multi-path radio. ECMP (Equal-Cost Multi-Path) load-balancers in datacentre networks reorder when hash-bucket churn pulls flows across links. Healthy wired paths are near-zero; any reorder rate spike on a previously stable wired path is a network-side regression. Mobile/4G/5G paths sit at sustained low rates; sudden spikes there mean handover storms or multi-path fallback. Pairs with TCPDSACKRecv to confirm spurious vs real reorder.\n\
         # TYPE elara_host_tcp_sack_reorder_total counter\n\
         elara_host_tcp_sack_reorder_total {host_tcp_sack_reorder}\n\
         # HELP elara_host_ip_in_receives_total Total IP datagrams arriving at this host, from /proc/net/snmp Ip `InReceives`. COUNTER. Layer-3 receive denominator. Pairs with InDelivers to compute IP-pipeline efficiency: rate(in_delivers) / rate(in_receives) should sit at >0.99 on healthy hosts. The TCP-layer counters only see what the IP layer hands UP — anything dropped before that is INVISIBLE without this counter and InDiscards/InHdrErrors below.\n\
         # TYPE elara_host_ip_in_receives_total counter\n\
         elara_host_ip_in_receives_total {host_ip_in_receives}\n\
         # HELP elara_host_ip_in_hdr_errors_total IP datagrams discarded due to header errors, from /proc/net/snmp Ip `InHdrErrors`. COUNTER. Bad IP version, bad checksum, truncated header, options-field corruption. Sustained > 0 = layer-2 corruption (cabling, NIC ASIC issue, driver bug) OR an attacker probing with malformed packets to find a parser bug. Pair with elara_host_netdev_rx_errs_total — rx_errs counts driver-level errors, in_hdr_errors counts kernel-IP-stack-level. ANY non-zero rate sustained on a wired LAN is a SEV3 — get tcpdump on the bad NIC.\n\
         # TYPE elara_host_ip_in_hdr_errors_total counter\n\
         elara_host_ip_in_hdr_errors_total {host_ip_in_hdr_errors}\n\
         # HELP elara_host_ip_in_addr_errors_total IP datagrams discarded because their destination address was not us, from /proc/net/snmp Ip `InAddrErrors`. COUNTER. Promiscuous mode and bridged virtual interfaces show packets that don't belong to us; this counts how many the kernel rejected. Sustained nonzero on a non-promiscuous host = a peer is sending to a stale address (DHCP lease churn, IPv6 SLAAC reset, container migration). At 10K-peer scale this surfaces gossip-table rot before peers start seeing connection-reset storms.\n\
         # TYPE elara_host_ip_in_addr_errors_total counter\n\
         elara_host_ip_in_addr_errors_total {host_ip_in_addr_errors}\n\
         # HELP elara_host_ip_in_discards_total Input IP datagrams the kernel dropped due to LOCAL resource exhaustion, from /proc/net/snmp Ip `InDiscards`. COUNTER. Mostly dst-cache pressure, route-cache allocation failure, or ipfrag table full. The IP-layer equivalent of TCP backlog drops — but THIS fires BEFORE TCP even sees the segment. Sustained non-zero rate at the 10K-peer scale = the kernel is dropping packets the TCP layer never gets to retransmit (because it doesn't know they were sent). SEV2 the moment rate exceeds 1/s sustained — operator playbook: raise net.ipv4.route.max_size, check ip_conntrack_max, investigate co-tenant memcg pressure stealing slab.\n\
         # TYPE elara_host_ip_in_discards_total counter\n\
         elara_host_ip_in_discards_total {host_ip_in_discards}\n\
         # HELP elara_host_ip_in_delivers_total IP datagrams successfully delivered to upper layers (TCP/UDP/ICMP/etc), from /proc/net/snmp Ip `InDelivers`. COUNTER. Pairs with in_receives to compute pipeline efficiency. The arithmetic identity InReceives = InDelivers + InDiscards + InHdrErrors + InAddrErrors + (forwarded) holds for non-router hosts (forwarding=0). On a healthy elara-node baseline the ratio in_delivers / in_receives sits at exactly 1.0 — any drift below 0.99 is the FIRST place to look when TCP retransmits start climbing without an obvious cause.\n\
         # TYPE elara_host_ip_in_delivers_total counter\n\
         elara_host_ip_in_delivers_total {host_ip_in_delivers}\n\
         # HELP elara_host_ip_out_requests_total Locally-generated IP datagrams handed to the IP layer for transmission, from /proc/net/snmp Ip `OutRequests`. COUNTER. Send-side denominator. Distinct from elara_host_tcp_out_segs_total which is TCP-only — OutRequests includes UDP gossip, DNS lookups, ICMP heartbeats, and any other IP traffic. Pairs with OutDiscards / OutNoRoutes to compute send-side drop fraction.\n\
         # TYPE elara_host_ip_out_requests_total counter\n\
         elara_host_ip_out_requests_total {host_ip_out_requests}\n\
         # HELP elara_host_ip_out_discards_total Outbound IP datagrams dropped by the kernel due to local resource exhaustion, from /proc/net/snmp Ip `OutDiscards`. COUNTER. Egress queue full, route-table allocation failure, dst-cache eviction during alloc. At 10K outbound conns this fires when txqueuelen is too small for offered burst rate, OR the egress NIC is saturating its hardware queue. The send-side mirror of in_discards. Sustained rate > 1/s = upgrade `ip link set txqueuelen` OR shed peer fanout. Pairs with elara_host_netdev_tx_drop_total: tx_drop = NIC driver dropped, out_discards = kernel IP layer dropped before the driver ever saw it.\n\
         # TYPE elara_host_ip_out_discards_total counter\n\
         elara_host_ip_out_discards_total {host_ip_out_discards}\n\
         # HELP elara_host_ip_out_no_routes_total Outbound IP datagrams dropped because no route was found, from /proc/net/snmp Ip `OutNoRoutes`. COUNTER. The 'we tried to send to a peer the routing table doesn't know how to reach' counter. At mainnet scale fires during: (1) gossip-table sync skew where we know a peer address but our forwarding table doesn't have a route to its subnet, (2) stale peer entries surviving past their TTL, (3) IPv6 link-local cache eviction during heavy peer churn, (4) network-partition recovery period when one segment's routes haven't propagated back. Sustained nonzero = peer-discovery layer is producing addresses our networking stack cannot honour — review gossip TTL or peer churn rate.\n\
         # TYPE elara_host_ip_out_no_routes_total counter\n\
         elara_host_ip_out_no_routes_total {host_ip_out_no_routes}\n\
         # HELP elara_host_ip_reasm_fails_total IP fragment reassembly failures, from /proc/net/snmp Ip `ReasmFails`. COUNTER. Increments per FAILED reassembly attempt — timeout waiting for missing fragment, fragment-table overflow, or duplicate-fragment conflict. UDP-heavy gossip workloads care about this directly. TCP fragments are rare on healthy paths (PMTU discovery converges to a non-fragmenting MSS); if this climbs on a TCP-mostly workload, MTU is misconfigured upstream and PMTUd is broken — the path is generating fragments that eventually time out. Each failure = one full upper-layer retransmit. Operator playbook: tcpdump for `ip[6:2] & 0x1fff != 0` to see fragments hitting this host, then trace the source.\n\
         # TYPE elara_host_ip_reasm_fails_total counter\n\
         elara_host_ip_reasm_fails_total {host_ip_reasm_fails}\n\
         # HELP elara_host_ip_frag_fails_total Locally-generated IP packets that needed fragmentation but could not be fragmented, from /proc/net/snmp Ip `FragFails`. COUNTER. Triggers when DF (Don't Fragment) bit is set on a packet larger than the next-hop MTU — the canonical PMTU-discovery breakage signal. The kernel emits an ICMP Frag-Needed back to the sender (us) but if upstream filters drop ICMP, we never learn the right MSS and these accumulate. Sustained nonzero = some peer's path has an MTU smaller than our advertised MSS AND the ICMP-back-channel is being filtered (PMTUd black hole). Operator playbook: temporarily clamp `tcp_mtu_probing=1` and `ip_no_pmtu_disc=0`, check the affected peer's MTU with `tracepath`.\n\
         # TYPE elara_host_ip_frag_fails_total counter\n\
         elara_host_ip_frag_fails_total {host_ip_frag_fails}\n\
         # HELP elara_host_udp_in_datagrams_total Total UDP datagrams successfully delivered to applications, from /proc/net/snmp Udp `InDatagrams`. COUNTER. UDP-layer receive denominator. Pairs with elara_host_ip_in_delivers_total to compute the UDP fraction of upper-layer traffic. The denominator for the UDP loss-rate ratios below: rate(no_ports + in_errors + rcvbuf_errors + mem_errors) / rate(in_datagrams) is the UDP-side receive-failure fraction.\n\
         # TYPE elara_host_udp_in_datagrams_total counter\n\
         elara_host_udp_in_datagrams_total {host_udp_in_datagrams}\n\
         # HELP elara_host_udp_no_ports_total UDP datagrams arriving for an unbound port, from /proc/net/snmp Udp `NoPorts`. COUNTER. Each event = a peer sent a UDP packet to a port that no application is listening on; kernel responded with ICMP Port-Unreachable (which itself increments OutMsgs and contributes to OutRateLimitHost if rate-capped). At 10K-peer fanout sustained nonzero rate means gossip-table rot — peers are caching a stale endpoint of ours from before a config change. Operator action: shorten gossip TTL, OR on a planned port migration, leave the old port bound for `2 × gossip_ttl` to bleed off the cached entries before reusing it.\n\
         # TYPE elara_host_udp_no_ports_total counter\n\
         elara_host_udp_no_ports_total {host_udp_no_ports}\n\
         # HELP elara_host_udp_in_errors_total UDP datagrams discarded due to packet-level errors (bad checksum, truncated header, malformed length), from /proc/net/snmp Udp `InErrors`. COUNTER. Distinct from `RcvbufErrors` (kernel had no buffer space) and `NoPorts` (no listener bound). InErrors means the datagram itself was bad. Sustained nonzero on a wired LAN = layer-2 corruption (cabling, NIC, driver) OR an attacker probing for parser bugs in the gossip dispatcher. Pair with elara_host_ip_in_hdr_errors_total to localize: ip_in_hdr_errors moving but udp_in_errors flat = the IP layer caught it before UDP saw it; both moving = corruption deep enough that even the IP layer accepted some bad headers.\n\
         # TYPE elara_host_udp_in_errors_total counter\n\
         elara_host_udp_in_errors_total {host_udp_in_errors}\n\
         # HELP elara_host_udp_out_datagrams_total Total UDP datagrams sent from this host, from /proc/net/snmp Udp `OutDatagrams`. COUNTER. Send-side denominator - pairs with `SndbufErrors` and `MemErrors` for send-failure ratios. Distinct from elara_host_ip_out_requests_total (which counts ALL outbound IP traffic - TCP + UDP + ICMP); this is UDP-only. The ratio rate(out_datagrams) / rate(out_requests_ip) tells operators 'how much of our send traffic is UDP-gossip vs TCP-records'.\n\
         # TYPE elara_host_udp_out_datagrams_total counter\n\
         elara_host_udp_out_datagrams_total {host_udp_out_datagrams}\n\
         # HELP elara_host_udp_sndbuf_errors_total UDP datagrams that could not be sent because the per-socket send buffer was full, from /proc/net/snmp Udp `SndbufErrors`. COUNTER. The send-side mirror of RcvbufErrors. Triggers when the application sends UDP faster than the kernel can move datagrams onto the wire (NIC saturated, txqueuelen tight, or PSI io blocking the interrupt path). At 10K-peer gossip fanout this fires when a single egress NIC is fielding fanout bursts beyond its hardware queue depth. Sustained > 0 = upgrade `net.core.wmem_max`, raise `txqueuelen`, OR shed UDP fanout. Distinct from elara_host_ip_out_discards_total which catches IP-layer egress drops; sndbuf_errors catches per-socket buffer exhaustion BEFORE it reaches the IP layer.\n\
         # TYPE elara_host_udp_sndbuf_errors_total counter\n\
         elara_host_udp_sndbuf_errors_total {host_udp_sndbuf_errors}\n\
         # HELP elara_host_udp_mem_errors_total UDP datagrams dropped because socket-buffer allocation failed (kernel crossed `net.ipv4.udp_mem` pressure/high threshold), from /proc/net/snmp Udp `MemErrors`. COUNTER. The UDP equivalent of TCP `TCPMemoryPressures` plus `TCPAbortOnMemory` rolled into one. ANY non-zero rate = SEV2: the kernel is starving for memory mid-UDP-handling and frames are being dropped. On phone-tier 2 GB nodes this fires under co-tenant memory pressure or aggressive page-cache competition. Operator playbook: raise `net.ipv4.udp_mem` ceiling, OR identify the memcg consuming pages, OR shed UDP fanout. Pairs tightly with elara_cgroup_memory_high_throttle_count and elara_host_psi_memory_full_us_total.\n\
         # TYPE elara_host_udp_mem_errors_total counter\n\
         elara_host_udp_mem_errors_total {host_udp_mem_errors}\n\
         # HELP elara_host_icmp_in_msgs_total Total ICMP messages received from /proc/net/snmp Icmp `InMsgs`. COUNTER. Receive-side denominator for ICMP signals. Most healthy network paths see 1-10 ICMP/min from peer reachability noise (echo replies to occasional traceroutes, timestamp probes from monitoring boxes). Sustained > 100/s here = either we're being probe-scanned OR a monitoring system on the LAN is emitting heavy ICMP at us. Pair with `in_dest_unreachs` and `in_time_excds` to disambiguate scanner-noise (random types) from real path-error events (Type 3 / Type 11 dominated).\n\
         # TYPE elara_host_icmp_in_msgs_total counter\n\
         elara_host_icmp_in_msgs_total {host_icmp_in_msgs}\n\
         # HELP elara_host_icmp_in_errors_total ICMP messages dropped due to packet-level errors, from /proc/net/snmp Icmp `InErrors`. COUNTER. The ICMP-layer mirror of `Udp:InErrors`. Sustained > 0 = link-layer corruption deep enough to slip past IP-layer header checks (rare on wired LAN, more common on cellular / phone-tier links with weak FEC). Distinct from `in_csum_errors` below — InErrors is the umbrella; InCsumErrors is the subset where the cause was specifically the ICMP checksum.\n\
         # TYPE elara_host_icmp_in_errors_total counter\n\
         elara_host_icmp_in_errors_total {host_icmp_in_errors}\n\
         # HELP elara_host_icmp_in_csum_errors_total ICMP messages with bad checksum, from /proc/net/snmp Icmp `InCsumErrors`. COUNTER. Subset of `in_errors` with the specific cause. Distinguishes 'NIC checksum offload bug' from 'attacker probe'. Sustained nonzero on a single peer pair (cross-tab with `in_msgs` against peers via tcpdump) usually indicates a buggy NIC driver — reload the driver or disable rx-checksum offload (`ethtool -K eth0 rx off`). Distributed sustained nonzero across many peers = layer-2 corruption fleet-wide (cabling, switch backplane, PoE injector glitches).\n\
         # TYPE elara_host_icmp_in_csum_errors_total counter\n\
         elara_host_icmp_in_csum_errors_total {host_icmp_in_csum_errors}\n\
         # HELP elara_host_icmp_in_dest_unreachs_total ICMP Destination-Unreachable messages received, from /proc/net/snmp Icmp `InDestUnreachs`. COUNTER. THE canonical 'network told us our outbound packet could not reach its destination' signal. Each event = a router or peer sent us back ICMP Type 3 (port closed, host unreachable, NAT pinhole closed, fragmentation needed and DF set). At 10K-peer fanout sustained nonzero rate = gossip-table rot — peers are caching stale endpoint addresses for offline / firewalled peers. Pair with `elara_gossip_peer_failures_total` to disambiguate: gossip-failure-rate up + in_dest_unreachs flat = peer dropped TCP connection (peer-side issue); both up together = the network is refusing our packets (NAT / firewall churn or PMTU black hole).\n\
         # TYPE elara_host_icmp_in_dest_unreachs_total counter\n\
         elara_host_icmp_in_dest_unreachs_total {host_icmp_in_dest_unreachs}\n\
         # HELP elara_host_icmp_in_time_excds_total ICMP Time-Exceeded messages received (TTL hit zero on an outbound packet of ours), from /proc/net/snmp Icmp `InTimeExcds`. COUNTER. Two lawful causes: (1) a router along the path has a routing loop (rare on production WANs but real on misconfigured BGP edges), (2) we are intentionally probing with traceroute-like low TTL. On a non-traceroute workload sustained nonzero = SEV3 — page network ops, get a `mtr` to the affected peer to trace the looping hop. Distinct from `out_time_excds` — InTimeExcds is what peers/routers told US, OutTimeExcds is what WE told THEM.\n\
         # TYPE elara_host_icmp_in_time_excds_total counter\n\
         elara_host_icmp_in_time_excds_total {host_icmp_in_time_excds}\n\
         # HELP elara_host_icmp_in_redirects_total ICMP Redirect messages received, from /proc/net/snmp Icmp `InRedirects`. COUNTER. Each event = a router told us 'use a different next-hop for that destination'. Modern hardened Linux defaults to `accept_redirects=0` (rejected as a security risk: a malicious gateway could blackhole specific peers by injecting redirects), so we ignore the message — but the counter still increments. Sustained > 0 here = the upstream gateway is *trying* to redirect us. SEV3 anomaly — the LAN's default route is mispointing on someone's gateway and the kernel is (correctly) ignoring the suggested fix.\n\
         # TYPE elara_host_icmp_in_redirects_total counter\n\
         elara_host_icmp_in_redirects_total {host_icmp_in_redirects}\n\
         # HELP elara_host_icmp_out_msgs_total Total ICMP messages sent from /proc/net/snmp Icmp `OutMsgs`. COUNTER. Send-side denominator. Steady-state nonzero is normal: the kernel autonomously emits ICMP for echo replies (incoming pings), Port-Unreachable for closed UDP, Frag-Needed for outbound packets too large for next-hop MTU. Sustained spike here without a corresponding spike in `out_dest_unreachs` or echo activity = something on this host is generating ICMP fanout — usually a misconfigured TTL on outbound packets or aggressive PMTU probing.\n\
         # TYPE elara_host_icmp_out_msgs_total counter\n\
         elara_host_icmp_out_msgs_total {host_icmp_out_msgs}\n\
         # HELP elara_host_icmp_out_dest_unreachs_total ICMP Destination-Unreachable messages WE sent, from /proc/net/snmp Icmp `OutDestUnreachs`. COUNTER. Each event = a peer sent us a packet for an endpoint we don't host (closed UDP port → kernel auto-emits Port-Unreachable; closed TCP backlog → Host-Unreachable; routing didn't accept → Net-Unreachable). Pairs near-1:1 with `elara_host_udp_no_ports_total` modulo the kernel's per-destination ICMP rate cap (`OutRateLimitHost`). At 10K-peer scale sustained spike here = gossip misroute (peers learning a stale endpoint of ours) — same operator action as for UDP NoPorts: shorten gossip TTL or extend bind-overlap on planned port migrations.\n\
         # TYPE elara_host_icmp_out_dest_unreachs_total counter\n\
         elara_host_icmp_out_dest_unreachs_total {host_icmp_out_dest_unreachs}\n\
         # HELP elara_host_icmp_out_time_excds_total ICMP Time-Exceeded messages WE sent, from /proc/net/snmp Icmp `OutTimeExcds`. COUNTER. Two causes: (1) we forwarded a packet with TTL=0 (we don't IP-forward, so this is normally near zero), (2) IP-fragment reassembly timed out — we held received fragments past `net.ipv4.ipfrag_time` waiting for the missing piece, kernel gave up and emitted Time-Exceeded. Sustained nonzero alongside `elara_host_ip_reasm_fails_total` = our reassembly ring is undersized for incoming fragmented load. Operator playbook: raise `net.ipv4.ipfrag_high_thresh` OR cross-tab the failing fragments by source via `tcpdump -nni any 'ip[6:2] & 0x1fff != 0'` to identify the misbehaving sender.\n\
         # TYPE elara_host_icmp_out_time_excds_total counter\n\
         elara_host_icmp_out_time_excds_total {host_icmp_out_time_excds}\n\
         # HELP elara_host_pgmajfault_total Major page faults since boot from /proc/vmstat 'pgmajfault'. COUNTER. Each event = a memory access that had to read from disk because the page wasn't resident. THE canonical signal of RAM pressure on a phone-tier 4GB box: one major fault is 100-1000x slower than a minor fault (cache miss vs cache hit). Sustained rate(pgmajfault[1m]) > 50/s on a 4GB node = working set doesn't fit and every operation is paying disk-read cost — RocksDB block cache miss rate climbs and seal_apply tail latency degrades silently. Distinct from minor page faults (pgfault - pgmajfault) which are benign first-touch faults during normal allocation. pgmajfault often moves BEFORE PSI memory because PSI is sampled at 10s coarse granularity; vmstat updates on every fault.\n\
         # TYPE elara_host_pgmajfault_total counter\n\
         elara_host_pgmajfault_total {host_pgmajfault}\n\
         # HELP elara_host_pgsteal_kswapd_total Pages reclaimed by kswapd from /proc/vmstat 'pgsteal_kswapd*' (sum across all zones for cross-kernel compatibility). COUNTER. Leading indicator that beats pgmajfault: when memory gets tight, kswapd starts reclaiming inactive pages BEFORE allocations stall and trigger major faults. rate(pgsteal_kswapd[5m]) climbing while pgmajfault is still flat = ~minutes of runway before the cliff. Distinct from pgsteal_direct (synchronous reclaim by the allocating process — kswapd-only is the asymptomatic leading indicator; direct reclaim means you're already in the cliff). Phone-tier alert: rate(pgsteal_kswapd) > 0 sustained for > 5min = approach memory cap; > 1000/s = imminent pressure.\n\
         # TYPE elara_host_pgsteal_kswapd_total counter\n\
         elara_host_pgsteal_kswapd_total {host_pgsteal_kswapd}\n\
         # HELP elara_host_oom_kill_total Cumulative OOM-killer activations from /proc/vmstat 'oom_kill'. COUNTER. ANY increment is a SEV1 incident: the kernel selected a victim and SIGKILL'd it with no graceful shutdown path. If the victim was elara-node, in-flight RocksDB writes may have left half-written SSTs (potential corruption); in-flight attestations were lost (epoch fork risk if we were the swing vote); peer connections RST'd (peer reconnect storm follows). Pair with elara_process_oom_score — score climbs toward 1000 BEFORE oom_kill moves; alert at oom_score > 700 gives operator runway to systemctl edit OOMScoreAdjust= or kill a co-tenant before the kernel intervenes. Healthy phone-tier 4GB node: stays at 0 forever. Even one increment = read kernel ring buffer (`dmesg | grep -i oom`) to identify what was killed.\n\
         # TYPE elara_host_oom_kill_total counter\n\
         elara_host_oom_kill_total {host_oom_kill}\n\
         # HELP elara_host_pswpin_total Pages swapped IN from /proc/vmstat 'pswpin'. COUNTER. On phone-tier 4GB nodes we deliberately disable swap (latency-sensitive workloads should never swap — random 4 KB scattered I/O is the worst possible disk traffic). This counter SHOULD stay at exactly the boot value forever. ANY increase = swap was enabled by accident OR a co-tenant flipped it on. Per-second swap-in correlates 1:1 with seal_apply tail-latency spikes because the application thread blocks for ~10ms (NVMe) to ~100ms (eMMC) on each page-in. Operator playbook on first nonzero rate: `swapoff -a; sysctl vm.swappiness=0; mask the swap.target` and add to the systemd unit's overrides.\n\
         # TYPE elara_host_pswpin_total counter\n\
         elara_host_pswpin_total {host_pswpin}\n\
         # HELP elara_host_pswpout_total Pages swapped OUT from /proc/vmstat 'pswpout'. COUNTER. Should stay at the boot value forever on a swap-disabled phone-tier node. swapout activity is even worse than swapin - it pins write IOPS into the swap device on a critical path (kernel needs to free a page NOW to satisfy an alloc, can't proceed until the dirty page is durable on disk). Sustained pswpout activity on a constrained shared-cloud node has been observed under co-tenant memory pressure.\n\
         # TYPE elara_host_pswpout_total counter\n\
         elara_host_pswpout_total {host_pswpout}\n\
         # HELP elara_process_sched_exec_seconds_total Cumulative seconds elara-node spent ON the CPU since process start, from /proc/self/schedstat field 1 (sum_exec_runtime, ns / 1e9). COUNTER. Distinct from elara_process_cpu_user_seconds_total which counts userspace ticks via /proc/self/stat — schedstat counts wall-clock CPU time at scheduler granularity (more accurate, captures kernel-mode execution within syscalls). Useful as the denominator in the scheduling-pressure ratio: rate(run_delay) / rate(exec + run_delay).\n\
         # TYPE elara_process_sched_exec_seconds_total counter\n\
         elara_process_sched_exec_seconds_total {proc_sched_exec_secs}\n\
         # HELP elara_process_sched_run_delay_seconds_total Cumulative seconds elara-node spent on the runqueue WAITING for CPU, from /proc/self/schedstat field 2 (run_delay, ns / 1e9). COUNTER. The 'process is runnable but scheduler has not given it a core yet' counter. Distinct from blocked-on-I/O time (which does not count) and from PSI cpu which is system-wide ('any task is waiting'). On a 4-vCPU box where 3 cores are busy servicing a noisy NIC IRQ, PSI may stay flat while THIS counter climbs because elara-node is the one being deferred. Derived signal: rate(run_delay) / rate(exec + run_delay) > 0.10 sustained = something is starving us — kernel RT tasks, co-tenant CPU pin, scheduler quanta shortened by bursty competing workloads. < 0.01 = healthy.\n\
         # TYPE elara_process_sched_run_delay_seconds_total counter\n\
         elara_process_sched_run_delay_seconds_total {proc_sched_delay_secs}\n\
         # HELP elara_process_sched_dispatches_total Cumulative number of times elara-node has been dispatched onto a CPU, from /proc/self/schedstat field 3 (pcount). COUNTER. Rarely actionable alone — its value is as a divisor: rate(exec_runtime + run_delay) / rate(pcount) = average runqueue residency per dispatch in seconds; rising = scheduler quanta being shortened (co-tenant pressure preempting more often). Phone-tier 4-vCPU box: typical ~5-50 ms per dispatch; if this drops below 1 ms sustained, the box is doing heavy preemption and elara-node is getting sliced into fragments rather than full quanta.\n\
         # TYPE elara_process_sched_dispatches_total counter\n\
         elara_process_sched_dispatches_total {proc_sched_pcount}\n\
         # HELP elara_host_psi_cpu_some_us_total Cumulative microseconds at least one task was stalled waiting for CPU, from /proc/pressure/cpu `total=` field. COUNTER. Pairs with elara_psi_cpu_some_avg10. The counter shape is what PromQL rate() needs over arbitrary alert windows — `rate(elara_host_psi_cpu_some_us_total[5m]) / 10000` gives percent-stalled over 5min, which avg10 cannot express (decays in 10s). Healthy phone-tier nodes accumulate slowly (low single-digit thousand μs/s); sustained rate > 100000 μs/s = 10% of wall time stalled = page operator. cpu_full omitted because kernel docs flag it as ill-defined and it is hardcoded 0 on ≥5.13.\n\
         # TYPE elara_host_psi_cpu_some_us_total counter\n\
         elara_host_psi_cpu_some_us_total {host_psi_cpu_some_us}\n\
         # HELP elara_host_psi_memory_some_us_total Cumulative microseconds at least one task was stalled on memory reclaim/swap-in/page-fault, from /proc/pressure/memory `some` line `total=`. COUNTER. THE leading-indicator memory-pressure counter — fires before pgmajfault crosses an alert threshold because PSI captures stall *latency* even when fault *count* stays modest. Useful pair: alert on `rate(elara_host_psi_memory_some_us_total[1m]) > 50000` (5% stalled) AND `rate(elara_host_pgmajfault_total[1m]) > 50` simultaneously for the strongest 'working set just overflowed RAM' signal. Either alone is noisy; both together has near-zero false positives in 6-node testnet history.\n\
         # TYPE elara_host_psi_memory_some_us_total counter\n\
         elara_host_psi_memory_some_us_total {host_psi_mem_some_us}\n\
         # HELP elara_host_psi_memory_full_us_total Cumulative microseconds ALL runnable tasks were stalled on memory, from /proc/pressure/memory `full` line `total=`. COUNTER. The most actionable PSI counter on the box. `full` means the entire system was wedged for that fraction — every task paused waiting on memory reclaim simultaneously. Should be 0 on a healthy phone-tier node forever. ANY accumulation in this counter that exceeds boot baseline is a SEV1 — kernel was actively unable to make progress and OOM-killer is the next step. Most-leading signal we have for the OOM cliff: ahead of pgmajfault, ahead of oom_kill, ahead of pswpout. Bind a tight alert.\n\
         # TYPE elara_host_psi_memory_full_us_total counter\n\
         elara_host_psi_memory_full_us_total {host_psi_mem_full_us}\n\
         # HELP elara_host_psi_io_some_us_total Cumulative microseconds at least one task was stalled on block I/O, from /proc/pressure/io `some` line `total=`. COUNTER. Catches storage saturation that pure throughput metrics miss — a disk doing 10 MB/s while every reader is blocked is invisible to elara_disk_read_bytes_total but obvious here. Healthy: rate ~10000 μs/s sustained (background tasks always have some IO wait). Concerning: rate > 100000 μs/s sustained AND rate(elara_disk_io_ms_total[1m]) > 800 = the underlying NVMe is saturating queue depth, not just doing concurrent work — switch to fewer-larger writes or shed load.\n\
         # TYPE elara_host_psi_io_some_us_total counter\n\
         elara_host_psi_io_some_us_total {host_psi_io_some_us}\n\
         # HELP elara_host_psi_io_full_us_total Cumulative microseconds ALL runnable tasks were stalled on block I/O, from /proc/pressure/io `full` line `total=`. COUNTER. Different from CPU full (which is dead noise) and from memory full (which is OOM-imminence): IO full means every task on the box was paused waiting for the block layer to make progress. Common causes: (1) RocksDB compaction stall on the data NVMe, (2) noisy-neighbor on a shared storage backend, (3) WAL fsync bursts on slow storage. Operator threshold: rate > 50000 us/s sustained = 5% of wall time the box wasn't doing ANY work because everything was IO-blocked.\n\
         # TYPE elara_host_psi_io_full_us_total counter\n\
         elara_host_psi_io_full_us_total {host_psi_io_full_us}\n\
         # HELP elara_cgroup_memory_current_bytes Bytes the kernel has CHARGED to elara-node's cgroup v2, from /sys/fs/cgroup/<own>/memory.current. GAUGE. Distinct from process RSS: RSS is what THIS process has mapped, while memory.current includes every byte the kernel attributes to the cgroup — page cache for files this process opened, slab/kmem allocated by the kernel on its behalf, network buffers, tmpfs pages mounted inside, transparent-hugepages backing those. A node with RSS=150 MB and memory.current=1.8 GB under a 2 GB cgroup cap is one RocksDB compaction away from OOM-kill; only THIS metric makes that visible. 0 if cgroup v2 not mounted (RHEL 7/8 hybrid mode) — operators see flat-zero gauge as 'unobservable, retire box'.\n\
         # TYPE elara_cgroup_memory_current_bytes gauge\n\
         elara_cgroup_memory_current_bytes {cg_mem_current}\n\
         # HELP elara_cgroup_memory_max_bytes Hard memory limit for the cgroup, from /sys/fs/cgroup/<own>/memory.max. GAUGE. 0 means 'max' (no limit configured) — kernel writes the literal string 'max' for unlimited cgroups; we coerce to 0 so a single u64 carries both states. Operators alert on `current/max > 0.80` for early warning; on a 0-valued max gauge that ratio is undefined and the alert is correctly silent (no ceiling means no impending cliff). On phone-tier the systemd unit should set MemoryLimit to 80% of host RAM to leave kernel + co-tenants headroom; if this gauge is 0 on a phone-tier node, the unit-file is misconfigured.\n\
         # TYPE elara_cgroup_memory_max_bytes gauge\n\
         elara_cgroup_memory_max_bytes {cg_mem_max}\n\
         # HELP elara_cgroup_memory_high_bytes Soft memory limit (throttle band) for the cgroup, from /sys/fs/cgroup/<own>/memory.high. GAUGE. 0 = no soft limit. When current crosses high, kernel throttles writers (busy-loop reclaiming pages instead of admitting new allocations); does NOT OOM-kill but tail latencies suffer. The soft-then-hard pattern (memory.high < memory.max) gives operators a buffer: cross high = page warning, cross max = OOM. Surfacing this lets ops verify the buffer exists.\n\
         # TYPE elara_cgroup_memory_high_bytes gauge\n\
         elara_cgroup_memory_high_bytes {cg_mem_high}\n\
         # HELP elara_cgroup_memory_swap_current_bytes Bytes of cgroup memory currently swapped out, from /sys/fs/cgroup/<own>/memory.swap.current. GAUGE. Phone-tier nodes should run with swap disabled; this gauge should remain 0. Any non-zero value paired with rising rate(elara_host_pswpout_total) confirms swap is enabled AND active for this cgroup specifically - root-cause for tail-latency spikes that don't appear in PSI memory but DO appear in PSI io. Constrained nodes (2-4 GB RAM, shared cloud) have historically shown swap activity under co-tenant pressure even with operator-set vm.swappiness=0.\n\
         # TYPE elara_cgroup_memory_swap_current_bytes gauge\n\
         elara_cgroup_memory_swap_current_bytes {cg_mem_swap_current}\n\
         # HELP elara_cgroup_memory_oom_kill_total Number of times the kernel killed a process in this cgroup because memory.max was hit, from /sys/fs/cgroup/<own>/memory.events `oom_kill` row. COUNTER. The SEV1 confirmation that the cgroup limit was breached. Should be 0 forever on a healthy phone-tier node — any rise = the runtime was killed (will be a fresh PID), and elara-node's systemd unit's RestartSec window is racing the OOM cliff. If this counter is incrementing AND the service keeps restarting, raise MemoryLimit OR shed load OR investigate a leak — the cgroup is sized too small for the working set.\n\
         # TYPE elara_cgroup_memory_oom_kill_total counter\n\
         elara_cgroup_memory_oom_kill_total {cg_mem_oom_kill}\n\
         # HELP elara_cgroup_memory_high_throttle_total Number of times the kernel entered memory.high throttle for this cgroup, from /sys/fs/cgroup/<own>/memory.events `high` row. COUNTER. Leading-indicator counter for cgroup pressure: high-throttle fires every time the cgroup crosses its soft limit. A rate spike here, BEFORE the oom_kill counter moves, is the operator's window to act — bump MemoryLimit, shed load, or migrate workloads. Healthy steady-state rate ~0; sustained `rate > 1/s` means the cgroup is permanently under reclaim and OOM cliff is one tail-latency burst away.\n\
         # TYPE elara_cgroup_memory_high_throttle_total counter\n\
         elara_cgroup_memory_high_throttle_total {cg_mem_high_throttle}\n\
         # HELP elara_cgroup_memory_low_events_total Number of times the kernel reclaimed memory from this cgroup despite memory.low protection, from /sys/fs/cgroup/<own>/memory.events `low` row. COUNTER. memory.low is a soft-min guarantee — the kernel tries to keep this much memory available before reclaiming, but under extreme pressure it falls through. A rising counter means the soft-min protection failed: either the host is under sustained reclaim pressure (other cgroups starving us out) OR memory.low is set higher than achievable. Phone-tier with no memory.low configured stays flat-zero. If non-zero in shared/multi-tenant deployments, raise memory.low or migrate the noisy co-tenant.\n\
         # TYPE elara_cgroup_memory_low_events_total counter\n\
         elara_cgroup_memory_low_events_total {cg_mem_ev_low}\n\
         # HELP elara_cgroup_memory_max_events_total Number of times the kernel hit the memory.max ceiling for this cgroup, from /sys/fs/cgroup/<own>/memory.events `max` row. COUNTER. Distinct from oom_kill: `max` increments when the kernel had to reclaim aggressively because the cgroup was at the hard cap, but a process was not necessarily killed (kernel may have succeeded in freeing pages). Operationally this is the 'one-step-before-OOM' counter: every `max` event means the cgroup is operating at the cliff. Sustained rate > 0 is a SEV2 (working set exceeds cap, OOM is one allocation away); paired with oom_kill > 0 it confirms cap-driven kills.\n\
         # TYPE elara_cgroup_memory_max_events_total counter\n\
         elara_cgroup_memory_max_events_total {cg_mem_ev_max}\n\
         # HELP elara_cgroup_memory_oom_events_total Number of times the kernel detected OOM in this cgroup (regardless of whether a process was killed), from /sys/fs/cgroup/<own>/memory.events `oom` row. COUNTER. Distinct from oom_kill: `oom` increments when the kernel decides this cgroup is OOM and starts the kill path, but the actual victim selection / kill may be skipped (e.g. memory.oom.group=0 with no killable tasks, or external OOM handler intervened). Triple-pair with max_events_total + oom_kill_total: max event = at cliff, oom event = decided OOM, oom_kill = killed a process. Healthy = all three zero forever.\n\
         # TYPE elara_cgroup_memory_oom_events_total counter\n\
         elara_cgroup_memory_oom_events_total {cg_mem_ev_oom}\n\
         # HELP elara_cgroup_memory_oom_group_kill_total Number of times the entire cgroup was group-killed at once (memory.oom.group=1), from /sys/fs/cgroup/<own>/memory.events `oom_group_kill` row. COUNTER. Most elara-node systemd units run a single process so memory.oom.group is irrelevant and this stays zero forever. Non-zero on a single-process unit is anomalous (someone enabled group-kill) — the nuclear-OOM path. On multi-process containers (k8s pod with sidecars) this fires when the kernel decided the entire pod must die together, distinct from picking a single victim. Pairs with oom_kill: group_kill = mass casualty, oom_kill = single victim count.\n\
         # TYPE elara_cgroup_memory_oom_group_kill_total counter\n\
         elara_cgroup_memory_oom_group_kill_total {cg_mem_ev_oom_group_kill}\n\
         # HELP elara_cgroup_memory_anon_bytes Anonymous (process-private) memory charged to this cgroup, from /sys/fs/cgroup/<own>/memory.stat `anon`. GAUGE. This is the unfreeable component of memory.current — heap, stack, MAP_ANONYMOUS mappings; the kernel cannot reclaim this without paging out. Distinct from RSS which counts what the process has mapped; `anon` here is what the cgroup owns regardless of mapping state. The number that matters for OOM headroom: `anon` approaching memory.max with `file` reclaimable = cliff is real. Phone-tier baseline ~600 MB. Sustained linear growth = real memory leak (heap fragmentation OR forgotten allocations); compare delta(anon) over hours against delta(elara_pending_ledger_size) to attribute leak source.\n\
         # TYPE elara_cgroup_memory_anon_bytes gauge\n\
         elara_cgroup_memory_anon_bytes {cg_mem_anon}\n\
         # HELP elara_cgroup_memory_file_bytes Page-cache memory for files this cgroup opened, from /sys/fs/cgroup/<own>/memory.stat `file`. GAUGE. Reclaimable component of memory.current — kernel can drop these pages under pressure to make room for `anon` allocations. High `file` is HEALTHY when it's hot working set (RocksDB SST blocks, log files); UNHEALTHY when growing unbounded with cold data the kernel can't tell apart from hot. Cross-tab with workingset_refault_file_total: if file is high AND refaults are zero = good (cache is hitting); if file is high AND refaults are climbing = working set > available cache, kernel is churning the same pages in/out. RocksDB on phone-tier should sit at ~200-400 MB file; sustained >1 GB warrants block_cache_limit tuning.\n\
         # TYPE elara_cgroup_memory_file_bytes gauge\n\
         elara_cgroup_memory_file_bytes {cg_mem_file}\n\
         # HELP elara_cgroup_memory_kernel_bytes Kernel-side memory (slab + kmem) allocated on this cgroup's behalf, from /sys/fs/cgroup/<own>/memory.stat `kernel`. GAUGE. Includes socket buffers, dentry/inode cache, network frame buffers, transparent-hugepages metadata — anything the kernel charges back to us via memcg accounting. This is INVISIBLE to RSS — a slab-leaking driver or a dentry-cache runaway (find / piped to nothing) shows here, not in process metrics. Phone-tier baseline ~20-30 MB. >100 MB sustained = something is burning kernel memory; common culprits: too many open sockets (check /proc/net/sockstat), aggressive readahead, container runtime overhead. ANY linear growth here over days = kernel-side leak — `slabtop` on the host to identify the cache.\n\
         # TYPE elara_cgroup_memory_kernel_bytes gauge\n\
         elara_cgroup_memory_kernel_bytes {cg_mem_kernel}\n\
         # HELP elara_cgroup_memory_pgfault_total Cumulative minor page faults charged to this cgroup, from /sys/fs/cgroup/<own>/memory.stat `pgfault`. COUNTER. Minor faults = page already resident in physical memory, just not yet mapped into this process's address space (first-touch on a fresh anon mmap, COW after fork, page reactivation). High rate is NORMAL during boot/startup as the runtime warms up; sustained high rate = working set is rotating through memory faster than the cache can hold it. Pairs with pgmajfault: rate(pgfault) >> rate(pgmajfault) = healthy paging activity; ratio approaching 1:1 = thrash.\n\
         # TYPE elara_cgroup_memory_pgfault_total counter\n\
         elara_cgroup_memory_pgfault_total {cg_mem_pgfault}\n\
         # HELP elara_cgroup_memory_pgmajfault_total Cumulative MAJOR page faults charged to this cgroup, from /sys/fs/cgroup/<own>/memory.stat `pgmajfault`. COUNTER. Major fault = page is NOT resident, kernel must read it from disk (swap or file-backed mmap) — this is the proximate signal for cache thrashing. EVERY major fault is a disk seek tax on tail latency. Healthy phone-tier sits at 0 forever after warmup; sustained rate > 0 means working set has overflowed RAM and the kernel is paying disk-IO for what should be RAM hits. Cross-tab with elara_psi_io_some_total: coincident spike = confirmed memory pressure flushing to disk. Operator action: drop block_cache_limit OR add RAM OR shed load.\n\
         # TYPE elara_cgroup_memory_pgmajfault_total counter\n\
         elara_cgroup_memory_pgmajfault_total {cg_mem_pgmajfault}\n\
         # HELP elara_cgroup_memory_workingset_refault_file_total File pages evicted from cache and then re-faulted in, from /sys/fs/cgroup/<own>/memory.stat `workingset_refault_file`. COUNTER. The EARLY-WARNING for cache pressure — fires BEFORE pgmajfault explodes because re-faults hit the inactive list first. Kernel evicted a file page (decided it was cold), then the same page was needed again (proving it was actually hot) — working set genuinely exceeds cache budget. Healthy = 0 for the lifetime of the process. ANY sustained non-zero rate = the kernel's reclaim heuristic is making wrong decisions about what's hot — block_cache is undersized OR there's competing memory pressure from another cgroup. Predictive: refault counter rises minutes-to-hours before pgmajfault, giving an operator early-warning window to act before tail latencies tank.\n\
         # TYPE elara_cgroup_memory_workingset_refault_file_total counter\n\
         elara_cgroup_memory_workingset_refault_file_total {cg_mem_ws_refault_file}\n\
         # HELP elara_cgroup_cpu_usage_us_total Cumulative CPU time consumed by this cgroup in microseconds, from /sys/fs/cgroup/<own>/cpu.stat `usage_usec`. COUNTER. Diverges from elara_process_cpu_time_total when the cgroup contains multiple processes OR when CPU steal is happening (process accounting reflects wall-clock-on-CPU but cgroup accounting reflects what the scheduler attributed to us). Comparing rate(usage_us_total) vs rate(process_cpu_time_total)*1e6 surfaces co-tenant theft on shared-cloud hosts. Phone-tier nodes typically have 1:1 (single process per cgroup), so divergence is a significant alarm.\n\
         # TYPE elara_cgroup_cpu_usage_us_total counter\n\
         elara_cgroup_cpu_usage_us_total {cg_cpu_usage_us}\n\
         # HELP elara_cgroup_cpu_user_us_total Cumulative user-mode CPU time for the cgroup in microseconds, from /sys/fs/cgroup/<own>/cpu.stat `user_usec`. COUNTER. user_us / (user_us + system_us) gives the user/kernel split for the cgroup. A jump in system_us share (drop in user share) indicates kernel-side pressure - RocksDB syscall storms, gossip frame fragmentation, or fsync stalls on the WAL volume. Healthy phone-tier node sits at 85-95% user; sustained <70% user means the runtime is fighting the kernel.\n\
         # TYPE elara_cgroup_cpu_user_us_total counter\n\
         elara_cgroup_cpu_user_us_total {cg_cpu_user_us}\n\
         # HELP elara_cgroup_cpu_system_us_total Cumulative kernel-mode CPU time for the cgroup in microseconds, from /sys/fs/cgroup/<own>/cpu.stat `system_usec`. COUNTER. Pairs with process system time. Kernel-side time spike indicates: (1) excessive syscalls (small reads/writes, accept() storms, fsync churn), (2) softirq pile-up from network packet floods, (3) page-cache thrash (paired with rate(elara_host_pgmajfault_total)). Operator alert: rate(system_us)/rate(usage_us) > 0.30 sustained = the runtime needs syscall batching.\n\
         # TYPE elara_cgroup_cpu_system_us_total counter\n\
         elara_cgroup_cpu_system_us_total {cg_cpu_system_us}\n\
         # HELP elara_cgroup_cpu_throttled_us_total Cumulative microseconds the cgroup was throttled by hitting cpu.max quota, from /sys/fs/cgroup/<own>/cpu.stat `throttled_usec`. COUNTER. Always 0 when no quota set (phone-tier baseline). Becomes non-zero in managed-cluster runs (k8s CPU limit, systemd CPUQuota, ECS task limit) — every microsecond accumulates the runtime was forcibly paused waiting for the next period to start. ANY non-zero rate here under load = the cgroup is queue-limited and tail latencies are elevated; raise quota OR shed load. Pairs with cpu_quota_us=0 to confirm 'unconfigured' vs 'quota too tight'.\n\
         # TYPE elara_cgroup_cpu_throttled_us_total counter\n\
         elara_cgroup_cpu_throttled_us_total {cg_cpu_throttled_us}\n\
         # HELP elara_cgroup_cpu_throttle_periods_total Number of CFS periods the cgroup was throttled, from /sys/fs/cgroup/<own>/cpu.stat `nr_throttled`. COUNTER. Discrete-event counterpart to throttled_us — increments once per period in which the cgroup hit its quota. Useful for latency budgeting: throttled_us tells you cumulative pain, throttle_periods tells you how many requests took the throttle hit. (throttled_us / throttle_periods) gives mean throttle duration per impacted period; if that ratio approaches the period_us value, the cgroup is essentially shut off for whole periods at a time — an operator MUST raise quota or split workload.\n\
         # TYPE elara_cgroup_cpu_throttle_periods_total counter\n\
         elara_cgroup_cpu_throttle_periods_total {cg_cpu_nr_throttled}\n\
         # HELP elara_cgroup_cpu_quota_us Configured CPU quota for the cgroup in microseconds per period, from /sys/fs/cgroup/<own>/cpu.max first field. GAUGE. 0 means 'max' (no quota — kernel writes the literal string 'max') OR file unreadable (cgroup v1 hybrid). Operator semantics: 0 = baseline phone-tier (no scheduler cap, only NUMA-locality + nice level limits us), >0 = hard cap. quota/period gives effective CPU count: e.g., quota=200000 period=100000 = 2 vCPU equivalent. Useful for capacity planning AND for distinguishing 'unconfigured cgroup' (always 0) from 'misconfigured cgroup' (quota too low, throttle counters rising).\n\
         # TYPE elara_cgroup_cpu_quota_us gauge\n\
         elara_cgroup_cpu_quota_us {cg_cpu_quota_us}\n\
         # HELP elara_cgroup_cpu_period_us CFS period length for the cgroup in microseconds, from /sys/fs/cgroup/<own>/cpu.max second field. GAUGE. Default 100000 (100 ms) on Linux ≥4.18; rare deployments shorten it to 50 ms for tighter latency. Period itself is not actionable on its own (it's a kernel scheduling parameter, not a workload property), but quota / period gives the effective vCPU allocation — operators read both metrics together for capacity planning. 0 = file unreadable (cgroup v1 hybrid OR file missing because no quota set on this kernel).\n\
         # TYPE elara_cgroup_cpu_period_us gauge\n\
         elara_cgroup_cpu_period_us {cg_cpu_period_us}\n\
         # HELP elara_host_netdev_rx_errs_total NIC-reported receive errors per device, from /proc/net/dev field 3 (after the device name). COUNTER. Counts packets the NIC physically received but flagged as bad — checksum mismatch, runt frame, oversize, framing fault. Should be 0 forever on a healthy wired link; non-zero usually means cable / connector / driver fault, OR a co-tenant on a shared NIC virtio queue is corrupting frames. Compare across nodes: a single node with rising rate(rx_errs) on its primary uplink while peers stay flat = SEV2 hardware/cable swap.\n\
         # TYPE elara_host_netdev_rx_errs_total counter\n\
         {netdev_rx_errs_lines}\
         # HELP elara_host_netdev_rx_drop_total Kernel-dropped receive packets per device, from /proc/net/dev field 4. COUNTER. Most actionable network-loss signal on phone-tier: ring-buffer overrun OR socket-buffer pressure. Each drop = a packet the NIC delivered to the host but the kernel had to discard because no slot was free to receive it. Sustained > 0 under load means the box can't drain its NIC fast enough — net.core.netdev_max_backlog is too low, OR softirq processing is starved by another CPU-heavy workload. The TCP-layer counters only see consequences after this counter has fired. Operator threshold: ANY rate > 1/s on a wired link = page; on Tailscale/wifi rate > 10/s = page.\n\
         # TYPE elara_host_netdev_rx_drop_total counter\n\
         {netdev_rx_drop_lines}\
         # HELP elara_host_netdev_tx_errs_total NIC-reported transmit errors per device, from /proc/net/dev field 11. COUNTER. Always 0 on a healthy NIC; non-zero is hardware fault, driver wedge, or a kernel-level descriptor exhaustion. Distinct from tx_drop (which is qdisc-level): tx_errs means the driver tried to hand the packet to the hardware and the hardware refused. SEV1 if it climbs at all.\n\
         # TYPE elara_host_netdev_tx_errs_total counter\n\
         {netdev_tx_errs_lines}\
         # HELP elara_host_netdev_tx_drop_total Kernel-dropped transmit packets per device, from /proc/net/dev field 12. COUNTER. Egress qdisc overflow - kernel queued a packet for transmit but the qdisc was full so the packet was dropped before reaching the driver. Indicates the egress pipeline can't keep up. On constrained or slow uplinks, seal-storm bursts can briefly exceed qdisc capacity; sustained > 0 under steady-state means the egress quota is too tight or the application is bursting harder than the link can absorb.\n\
         # TYPE elara_host_netdev_tx_drop_total counter\n\
         {netdev_tx_drop_lines}\
         # HELP elara_host_netdev_tx_carrier_total Count of TX-side carrier-loss events per device, from /proc/net/dev field 15. COUNTER. Each increment = the link physically dropped (cable unplugged, switchport flapped, wifi roam, hypervisor live-migration). Pairs with elara_peer_disconnects_total to attribute peer churn to physical link bounce vs application-layer disconnect: if carrier_total bumps up at the same wall-clock as a peer-mass-disconnect, the box is the cause not the peer. On Tailscale this counts relay-path bounces - useful for diagnosing NAT-traversal pathology.\n\
         # TYPE elara_host_netdev_tx_carrier_total counter\n\
         {netdev_tx_carrier_lines}\
         # HELP elara_softirq_net_rx_total Cumulative NET_RX softirqs serviced across ALL CPUs, summed from /proc/softirqs row 'NET_RX'. COUNTER. The most actionable network-side phone-tier signal: every received packet the NIC hands to the kernel passes through NET_RX softirq before TCP/UDP delivery. A sustained rate climb here, while elara_net_rx_bytes_total stays flat, means each packet is taking more softirq cycles than before — typically driver-side coalescing is off, or the kernel is fragmenting RX into many small sub-events. Phone-tier alert: rate(NET_RX) > 50K/s sustained on a 1-core box = softirq is the bottleneck and user-mode time will starve. Aggregated across CPUs to keep cardinality at 1 line/host, but a per-CPU imbalance still shows up here: if irqbalance has pinned all NIC IRQs to one core, the AGGREGATE count climbs against a single-CPU's usage_us, exposing the asymmetry without per-CPU labels.\n\
         # TYPE elara_softirq_net_rx_total counter\n\
         elara_softirq_net_rx_total {sirq_net_rx}\n\
         # HELP elara_softirq_net_tx_total Cumulative NET_TX softirqs serviced across ALL CPUs, summed from /proc/softirqs row 'NET_TX'. COUNTER. Counter for outbound packet completions handed back from the NIC. NET_TX rate ≪ NET_RX rate is normal (TX completions are batched harder than RX delivery). A NET_TX rate that climbs in lockstep with NET_RX while disk I/O is flat = uplink is saturated and the kernel is doing extra TX-completion work to drain queued frames; pair with elara_host_netdev_tx_drop_total climbing to confirm qdisc overflow.\n\
         # TYPE elara_softirq_net_tx_total counter\n\
         elara_softirq_net_tx_total {sirq_net_tx}\n\
         # HELP elara_softirq_block_total Cumulative BLOCK softirqs serviced across ALL CPUs, summed from /proc/softirqs row 'BLOCK'. COUNTER. Each disk I/O completion delivers a BLOCK softirq. Healthy ratio: rate(BLOCK) ≈ rate(elara_process_io_read_bytes_total + elara_process_io_write_bytes_total) / typical_block_size. Climbing BLOCK rate WITHOUT corresponding throughput growth = each I/O is smaller than before, typically RocksDB switching from large compactor reads to many tiny WAL fsyncs OR a cache-miss storm. On phone-tier eMMC the kernel may pin block softirq handling to one CPU — combined with a NET_RX-pinned CPU, that creates a single-CPU saturation cliff that this counter exposes.\n\
         # TYPE elara_softirq_block_total counter\n\
         elara_softirq_block_total {sirq_block}\n\
         # HELP elara_softirq_sched_total Cumulative SCHED softirqs serviced across ALL CPUs, summed from /proc/softirqs row 'SCHED'. COUNTER. Increments on every scheduler-driven IPI (inter-processor interrupt) — wakeups, load-balancing migrations, RCU callbacks scheduled cross-CPU. Highest-volume softirq on a busy multi-core box (millions/s normal). Useful as a denominator: when NET_RX or BLOCK approaches SCHED in count, softirq serving has shifted off the scheduler-overhead baseline and onto I/O — a structural regime change. Sudden DROP in SCHED rate with stable workload = scheduler is migrating less, meaning workload has consolidated to one CPU (the same imbalance signal as NET_RX pinning, viewed from the scheduler side).\n\
         # TYPE elara_softirq_sched_total counter\n\
         elara_softirq_sched_total {sirq_sched}\n\
         # HELP elara_softirq_timer_total Cumulative TIMER softirqs serviced across ALL CPUs, summed from /proc/softirqs row 'TIMER'. COUNTER. Steady-state rate ≈ HZ × num_online_cpus (e.g. 1000 Hz × 8 cores = 8K/s baseline). Most stable softirq class — useful as the ground-truth tick reference: if rate(TIMER) drops below baseline, the kernel is suppressing timer interrupts, meaning at least one CPU has gone NOHZ-idle (no work to drive a tick). Sustained TIMER rate exactly = HZ × num_online_cpus = box is fully busy on every core (no CPU is idle long enough to skip a tick) — pair with cgroup CPU usage to distinguish 'busy doing useful work' from 'busy spinning on a hot path'.\n\
         # TYPE elara_softirq_timer_total counter\n\
         elara_softirq_timer_total {sirq_timer}\n\
         # HELP elara_buddy_free_pages_order0 Free 4 KB pages summed across all NUMA nodes and memory zones, from /proc/buddyinfo column 4 (order-0 free list). GAUGE. Smallest allocation unit — the kernel maintains a large reserve here at all times. Useful as the denominator for fragmentation index: (free_pages_order8 / free_pages_order0) on the dashboard. Sustained drop here (paired with order4/order8 staying flat) is rare — it means the kernel is consuming small pages without releasing them, typically a slab cache leak. 0 on systems with /proc/buddyinfo unavailable (hardened containers); distinguish from genuinely-zero by checking elara_host_pgmajfault_total — if the host is paging hard with 0 here, /proc is restricted.\n\
         # TYPE elara_buddy_free_pages_order0 gauge\n\
         elara_buddy_free_pages_order0 {buddy_order0}\n\
         # HELP elara_buddy_free_pages_order4 Free 64 KB contiguous blocks summed across all NUMA nodes and zones, from /proc/buddyinfo column 8 (order-4 free list). GAUGE. RocksDB block reads default to 64 KiB; SST file mmap pages prefer order-4 backings when available. When this drains to <100 fleet-wide, RocksDB falls back to assembling 64 KB blocks from 16× 4 KB pages — page-table overhead climbs, TLB pressure rises, and the read path slows. Phone-tier alert: sustained order4 < 50 with rate(elara_process_io_read_bytes_total) > 5 MB/s = the read path is paying compaction tax on every block fetch.\n\
         # TYPE elara_buddy_free_pages_order4 gauge\n\
         elara_buddy_free_pages_order4 {buddy_order4}\n\
         # HELP elara_buddy_free_pages_order8 Free 1 MB contiguous blocks summed across all NUMA nodes and zones, from /proc/buddyinfo column 12 (order-8 free list). GAUGE. The phone-tier fragmentation cliff: 1 MB allocations are required for hugepage mmaps, network jumbo frames, and certain RocksDB cache promotions. When this hits 0 fleet-wide AND stays there for >5 min, the kernel can't satisfy hugepage requests and falls back to 4 KB pages — TLB miss rate doubles, throughput drops 10-30%. Local box NORMAL-zone order-8 currently = 3 with order-9/10 = 0 — typical for a 7-year-old desktop running heavy workloads, but the SAME number on a phone-tier 2 GB node = SEV2. Operators alert at sustained order8 < 5 across all nodes.\n\
         # TYPE elara_buddy_free_pages_order8 gauge\n\
         elara_buddy_free_pages_order8 {buddy_order8}\n\
         # HELP elara_jemalloc_allocated_bytes Bytes currently allocated to live Rust objects, from jemalloc 'stats.allocated' via mallctl. GAUGE. The closest jemalloc analog to 'how much memory is the application asking for'. Differs from cgroup memory.current: cgroup counts ALL pages (jemalloc heap + slab + page cache + stacks); allocated counts ONLY live heap. The gap (memory.current - allocated) is mostly arena-internal fragmentation + retained pages + non-heap kernel accounting. Steady allocated growth with flat resident = a true heap leak; flat allocated with growing resident = fragmentation, which a periodic 'arena.<i>.purge' fixes. 0 on builds without the 'node' feature (mobile, wasm, node-windows).\n\
         # TYPE elara_jemalloc_allocated_bytes gauge\n\
         elara_jemalloc_allocated_bytes {jem_allocated}\n\
         # HELP elara_jemalloc_active_bytes Bytes in jemalloc 'active' pages — pages currently used to back live allocations PLUS jemalloc's per-thread caches and freelists. GAUGE. Always >= allocated. The (active - allocated) gap measures how much memory jemalloc is sitting on inside its arenas without releasing it to the OS — this is the 'wasted-but-not-leaked' figure. Phone-tier alert: (active - allocated) > 100 MB on a 2 GB node = an arena purge would meaningfully reduce RSS pressure.\n\
         # TYPE elara_jemalloc_active_bytes gauge\n\
         elara_jemalloc_active_bytes {jem_active}\n\
         # HELP elara_jemalloc_resident_bytes Bytes physically resident in RAM that jemalloc has mapped, from 'stats.resident'. GAUGE. The closest jemalloc-side proxy for OS RSS attributable to the heap. Should track cgroup memory.current's heap-share within ~10% in steady-state. When (resident - active) climbs while active stays flat = jemalloc is holding pages that were freed by Rust but not unmapped to the OS — page reclaim subsystem hasn't pulled them yet, but they're available for re-use without a syscall. This is normal; jemalloc rarely returns memory unless purge is forced.\n\
         # TYPE elara_jemalloc_resident_bytes gauge\n\
         elara_jemalloc_resident_bytes {jem_resident}\n\
         # HELP elara_jemalloc_metadata_bytes Bytes used by jemalloc internal metadata structures (arena chunk headers, extent rtrees, prof samples). GAUGE. Typically 1-3% of resident on a healthy node. Climbing past 5% suggests too many small arenas or a misconfigured profiling sample rate. Stable, slow growth — useful as a sanity bound: if metadata > 50 MB on a 2 GB node, the arena layout needs review.\n\
         # TYPE elara_jemalloc_metadata_bytes gauge\n\
         elara_jemalloc_metadata_bytes {jem_metadata}\n\
         # HELP elara_jemalloc_mapped_bytes Total bytes in active extents mapped by jemalloc from the OS, from 'stats.mapped'. GAUGE. Always >= active. The (mapped - active) gap is dirty-but-not-yet-decommitted pages — pages jemalloc has touched but is willing to give back to the OS via madvise(MADV_DONTNEED) on the next purge cycle. A wide (mapped - active) gap with low purge activity = jemalloc could release memory but isn't being asked to.\n\
         # TYPE elara_jemalloc_mapped_bytes gauge\n\
         elara_jemalloc_mapped_bytes {jem_mapped}\n\
         # HELP elara_jemalloc_retained_bytes Bytes that have been munmap()'d FROM jemalloc's perspective but kept in the address space for re-use, from 'stats.retained'. GAUGE. NOT counted against RSS but consumes virtual address space. On a 64-bit box with 256 TB VA this is essentially free; useful only as a tripwire for ULTRA-long-running nodes where retained climbing past 10× allocated indicates a runaway address-space leak (jemalloc keeps mapping new chunks instead of re-using retained ones — an arena bug rather than an app bug).\n\
         # TYPE elara_jemalloc_retained_bytes gauge\n\
         elara_jemalloc_retained_bytes {jem_retained}\n\
         # HELP elara_process_io_syscr_total Count of read(2)-family syscalls (read/pread/readv/preadv) issued by elara-node, from /proc/self/io syscr. COUNTER. Pair with elara_process_io_rchar_bytes_total to compute avg bytes per read syscall — RocksDB block reads pull ~64 KB at a time when warm, ~1 KB per record header when cold. Avg trending toward 1 KB while throughput stays flat = block fetch replaced by per-record header reads (LSM cache miss storm). Sustained syscr rate > 50 K/s on phone-tier 4-core eMMC = syscall overhead alone consuming a non-trivial slice of CPU.\n\
         # TYPE elara_process_io_syscr_total counter\n\
         elara_process_io_syscr_total {proc_io_syscr}\n\
         # HELP elara_process_io_syscw_total Count of write(2)-family syscalls (write/pwrite/writev/pwritev) issued by elara-node, from /proc/self/io syscw. COUNTER. Pair with elara_process_io_wchar_bytes_total: low avg bytes/write = chatty fsync rhythm (RocksDB WAL appending tiny records, gossip frame writes); high avg bytes/write = batched compactor flushes. On a phone-tier eMMC node sustained syscw rate > 10 K/s = syscall overhead approaching the disk-throughput overhead — the kernel context-switch cost is becoming visible. Useful for diagnosing why a node with quiet 'rate(write_bytes)' nonetheless shows high CPU.\n\
         # TYPE elara_process_io_syscw_total counter\n\
         elara_process_io_syscw_total {proc_io_syscw}\n\
         # HELP elara_process_io_cancelled_write_bytes_total Cumulative bytes that were charged to wchar but never reached the block device — discarded by truncate(2)/unlink(2) before the page-cache flush — from /proc/self/io cancelled_write_bytes. COUNTER. On a healthy RocksDB node this stays near zero; non-trivial growth indicates compactor temp-file churn (write SST → cancel via rename), snapshot-purge thrash, or a misbehaving subsystem creating-then-deleting buffered data. Subtract from wchar to get a more accurate 'writes that actually hit storage' figure. Sudden jumps after a deploy = a new code path is creating short-lived files; investigate via 'fatrace' or eBPF.\n\
         # TYPE elara_process_io_cancelled_write_bytes_total counter\n\
         elara_process_io_cancelled_write_bytes_total {proc_io_cancelled_write_bytes}\n\
         ");

    // ARCH-1: tentative-apply ledger + finality drain observability.
    // Three NodeState AtomicU64 counters (commits/discards/rejections) track
    // the happy + sad paths of the tentative path. Three AWCConsensus u64
    // counters track the finality queue saturation. Two gauges — in-memory
    // PendingLedger depth and current queue depth — surface live pressure.
    // Tentative-apply is now the only ingest path (Phase 3.7); the
    // `elara_tentative_ledger_enabled` gauge below is pinned to 1 for
    // dashboards/alerts that still query it.
    let pl_commits    = state.pending_ledger_commits_total.load(std::sync::atomic::Ordering::Relaxed);
    let pl_discards   = state.pending_ledger_discards_total.load(std::sync::atomic::Ordering::Relaxed);
    let pl_rejections = state.pending_ledger_rejections_total.load(std::sync::atomic::Ordering::Relaxed);
    let pl_fallback   = state.pending_ledger_fallback_direct_apply_total.load(std::sync::atomic::Ordering::Relaxed);
    let pl_hard_discards = state.pending_ledger_hard_discards_total.load(std::sync::atomic::Ordering::Relaxed);
    let pl_drain_apply_failed   = state.pending_drain_apply_failed_total.load(std::sync::atomic::Ordering::Relaxed);
    let pl_drain_missing_record = state.pending_drain_missing_record_total.load(std::sync::atomic::Ordering::Relaxed);
    let pl_boot_reconciled = state.pending_boot_reconciled_total.load(std::sync::atomic::Ordering::Relaxed);
    // KR-3 S2 (W1): rotation-CF finalize-drain writer counters. Zero while the
    // S2 flag is OFF (hook is flag-gated).
    let rot_cf_write_drain = state.rotation_cf_write_drain_total.load(std::sync::atomic::Ordering::Relaxed);
    let rot_cf_write_sweep = state.rotation_cf_write_sweep_total.load(std::sync::atomic::Ordering::Relaxed);
    let rot_cf_write_failed = state.rotation_cf_write_failed_total.load(std::sync::atomic::Ordering::Relaxed);
    // KR-3 S2 (§5-H5): rotation-class reason-vocabulary rejects. Zero flag-OFF.
    let rot_reason_rejected = state.rotation_reason_rejected_total.load(std::sync::atomic::Ordering::Relaxed);
    // KR-3 S2 (§5-H1): rotation-class recent-floor rejects. Zero flag-OFF.
    let rot_recent_floor_rejected = state.rotation_recent_floor_rejected_total.load(std::sync::atomic::Ordering::Relaxed);
    // KR-3 S2 (§5-H2/H3): rotation-class parent-grounding rejects. Zero flag-OFF.
    let rot_parent_grounding_rejected = state.rotation_parent_grounding_rejected_total.load(std::sync::atomic::Ordering::Relaxed);
    // KR-3 S2 (§5-H3b): rotation hops rejected because prev_key has no durably-final
    // introducing hop (fail-closed, never pins a spurious root). Zero flag-OFF.
    let rot_predecessor_ungrounded = state.rotation_predecessor_ungrounded_rejected_total.load(std::sync::atomic::Ordering::Relaxed);
    // KR-3 S2 (W2-D): durable-marker sweep observability. Zero while the S2 flag
    // is OFF (the sweep early-returns before folding these in).
    let rot_canon_mismatch = state.rotation_cf_canonicality_mismatch_total.load(std::sync::atomic::Ordering::Relaxed);
    let rot_sweep_runs = state.rotation_sweep_runs_total.load(std::sync::atomic::Ordering::Relaxed);
    let rot_sweep_scanned = state.rotation_sweep_markers_scanned_total.load(std::sync::atomic::Ordering::Relaxed);
    let rot_sweep_discharged = state.rotation_sweep_markers_discharged_total.load(std::sync::atomic::Ordering::Relaxed);
    let rot_sweep_orphans = state.rotation_sweep_orphan_markers_total.load(std::sync::atomic::Ordering::Relaxed);
    let rot_sweep_pending = state.rotation_sweep_pending_markers.load(std::sync::atomic::Ordering::Relaxed);
    // ZSP Phase D: zone-purge counters and queue gauges. Cheap reads (atomic +
    // mutex-guarded VecDeque); no extra storage IO.
    let zp_purged = state
        .zone_purge_records_purged_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let zp_queue_depth = super::zone_purge::queue_depth(state.as_ref()) as u64;
    let zp_lag_secs = super::zone_purge::oldest_lag_secs(state.as_ref());
    // Orphan-resolver high-count circuit-breaker prune
    // counter. Increments only when orphan_count > 200 after a fetch attempt
    // — the prune-as-circuit-breaker fired because cascade outpaced fetch.
    let or_high_count_pruned = state
        .orphan_resolver_high_count_pruned_total
        .load(std::sync::atomic::Ordering::Relaxed);
    // Saturation-skip counter — ticks the orphan
    // resolver skipped because the host was beyond what coop-yield can
    // rescue. Healthy on a 4 GB node = 0; non-zero on a 2 GB node
    // during post-restart catch-up is expected and self-clearing.
    let or_saturation_skips = state
        .orphan_resolver_saturation_skips_total
        .load(std::sync::atomic::Ordering::Relaxed);
    // /balances response cap + short-prefix rejection counters.
    // Healthy on testnet = both 0 (account set ≤100). Non-zero truncated_total
    // signals clients should migrate off unconditional /balances; non-zero
    // short_prefix_rejected_total flags an unbounded prefix scan attempted.
    let balances_truncated = state
        .balances_response_truncated_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let balances_short_prefix_rejected = state
        .balances_short_prefix_rejected_total
        .load(std::sync::atomic::Ordering::Relaxed);
    // /snapshot + /snapshot/state-delta full-state circuit-breaker.
    // Healthy on testnet = 0 (≤100 accounts; cap is 100K). Non-zero signals the
    // chain has crossed the full-fat-snapshot scale floor and bootstrappers
    // must switch to incremental ?since_epoch=N requests against an
    // archive-baseline node — see MAX_SNAPSHOT_FULL_ACCOUNTS in routes/sync.rs.
    let snapshot_size_rejected = state
        .snapshot_size_rejected_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let (pl_depth, pl_max_id_depth, pl_oldest_age_secs, pl_distinct_ids) = match state.pending_ledger.try_read() {
        Ok(p) => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs_f64())
                .unwrap_or(0.0);
            // No live deltas → emit 0 (Prometheus-friendly; absence of
            // pending work is age-zero, not unknown).
            let age = p
                .oldest_applied_at()
                .map(|a| (now - a).max(0.0))
                .unwrap_or(0.0);
            (
                p.len() as u64,
                p.max_per_identity_depth() as u64,
                age,
                p.distinct_identities() as u64,
            )
        }
        Err(_) => (0, 0, 0.0, 0),
    };
    // PARTITION-MERGE Phase B (Slice 1+2): same-epoch partition reconciliation
    // observability. `orphan_seals_total` is monotonic — bumps each time a
    // seal loses a same-(zone,epoch) weight comparison and is demoted from
    // canonical (its records stay in the DAG, only the seal-level mapping is
    // overwritten). `orphan_siblings_live_count` is the bounded ring footprint
    // (capped at 1024 keys × 256 entries). Slice 3 wires the demotion path
    // into register_seal; until then both gauges stay at 0 fleet-wide and
    // serve as the operator-side scaffolding to confirm wiring once enabled.
    let (orphan_seals_total, orphan_siblings_live, orphan_promotions_total) = {
        let e = state.epoch.read_recover();
        (
            e.orphan_seals_total,
            e.orphan_siblings_live_count() as u64,
            e.orphan_promotions_total,
        )
    };
    // PARTITION-MERGE conservation trip-wire (xzone_demotion_probe).
    let xz_same_epoch_demotions = state
        .same_epoch_seal_demotions_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let xz_demoted_covers_lock = state
        .xzone_demoted_seal_covers_lock_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let xz_demoted_covers_claimed = state
        .xzone_demoted_seal_covers_claimed_lock_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let xz_demoted_scan_dropped = state
        .demoted_seal_scan_queue_dropped_total
        .load(std::sync::atomic::Ordering::Relaxed);
    // AUDIT-9 follow-up #1 (2026-04-26): `unknown_profile_witnesses` is the
    // Milestone B effectiveness gauge — distinct witnesses we've spoken to
    // (have a derived_geo observation for) but lack a profile registration
    // for. The neighboring `unknown_pp` counter measures load (per-call),
    // not health. See consensus.rs:unknown_profile_witness_count.
    let (fq_enq, fq_drn, fq_ovf, fq_depth, ns_enq, ns_drn, ns_ovf, ns_depth, unknown_pp, unknown_profile_witnesses) = {
        let c = state.consensus.lock_recover();
        (
            c.finalization_queue_enqueued_total,
            c.finalization_queue_drained_total,
            c.finalization_queue_overflow_total,
            c.finalization_queue_depth() as u64,
            c.newly_sealed_queue_enqueued_total,
            c.newly_sealed_queue_drained_total,
            c.newly_sealed_queue_overflow_total,
            c.newly_sealed_queue_depth() as u64,
            c.unknown_profile_pairs_total
                .load(std::sync::atomic::Ordering::Relaxed),
            c.unknown_profile_witness_count() as u64,
        )
    };
    // ARCH-1 Phase 3.7: tentative-apply is the only ingest path; flag is gone.
    // Gauge stays pinned at 1 for back-compat with dashboards.
    let tl_enabled: u64 = 1;

    // Gap 2.1 Phase 2c — finality witness gossip counters. Without these
    // exposed, we can't tell whether peer-side cosign propagation is
    // actually flowing in production, which is the load-bearing path for
    // `transitions_finalized_total` and quorum-enforced cross-zone claims.
    let fw_pushed = state
        .finality_witness_pushed_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let fw_received = state
        .finality_witness_received_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let fw_rejected = state
        .finality_witness_rejected_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let fw_committee_mismatch = state
        .finality_witness_committee_mismatch_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let fw_non_member = state
        .finality_witness_non_member_total
        .load(std::sync::atomic::Ordering::Relaxed);
    // Slot-conflict proof gossip counters — Byzantine-evidence path.
    // pushed: this node generated a proof and broadcast it.
    // received: a peer forwarded a proof we hadn't seen.
    // rejected: malformed proof or signature verification failed.
    // Healthy mainnet: pushed/received both rare; rejected near-zero.
    // Sustained rejected > 0 = a peer is sending bad proofs.
    let cp_pushed = state
        .conflict_proof_pushed_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let cp_received = state
        .conflict_proof_received_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let cp_rejected = state
        .conflict_proof_rejected_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let cp_self_suppressed = state
        .conflict_proof_self_suppressed_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let cp_local_unverifiable = state
        .conflict_proof_local_unverifiable_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let ledger_ch_v2_rejected = state
        .ledger_content_hash_v2_rejected_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let (fc_added, fc_evicted, fc_mismatch, fc_collections,
         ac_added, ac_evicted, ac_mismatch, ac_collections,
         ao_inserted, ao_evicted, ao_cleared,
         pri_evictions, pri_evictions_near_settle, committee_rotations,
         evictions_finalized, evictions_age, evictions_zone_purge) = {
        let c = state.consensus.lock_recover();
        (
            c.seal_finality_signers_added_total,
            c.seal_finality_signers_evicted_total,
            c.seal_finality_snapshot_mismatch_total,
            c.seal_finality_signer_entries() as u64,
            c.xzone_abort_signers_added_total,
            c.xzone_abort_signers_evicted_total,
            c.xzone_abort_snapshot_mismatch_total,
            c.xzone_abort_signer_entries() as u64,
            c.xzone_abort_observations_inserted_total,
            c.xzone_abort_observations_evicted_total,
            c.xzone_abort_observations_cleared_total,
            c.evictions_total,
            c.evictions_near_settlement,
            c.committee_rotations_total,
            c.evictions_finalized_total,
            c.evictions_age_total,
            c.evictions_zone_purge_total,
        )
    };

    // Committee-size distribution. The summary was
    // captured under the consensus lock above (line ~1165) — destructure
    // here so the format!() block can use named interpolation.
    let cs_zones_registered = committee_size.zones_registered;
    let cs_size_min = committee_size.size_min;
    let cs_size_max = committee_size.size_max;
    let cs_zones_below_target = committee_size.zones_below_target;

    // Bounded count of tracked records missing a
    // `creator_stakes` row. Captured under the same consensus lock above
    // (line ~1165). See `AWCConsensus::missing_creator_stake_count` for
    // the operator dashboard rule (sustained >0 = backfill stalled OR
    // unknown creators).
    let consensus_missing_creator_stake = missing_creator_stake;

    // Gap 2 sealed-abort P-3e: abort-witness gossip counters. Same shape
    // as the finality witness trio so dashboards can re-use the panel.
    let aw_pushed = state
        .xzone_abort_witness_pushed_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let aw_received = state
        .xzone_abort_witness_received_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let aw_rejected = state
        .xzone_abort_witness_rejected_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let aw_committee_mismatch = state
        .xzone_abort_witness_committee_mismatch_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let aw_non_member = state
        .xzone_abort_witness_non_member_total
        .load(std::sync::atomic::Ordering::Relaxed);
    // Gap 2 sealed-abort P-3f: aggregator-submitted bundles. One increment
    // per local aggregator submit; cross-node redundancy is absorbed by
    // apply-time idempotency on Locked status, so cluster sum can exceed
    // the count of distinct refunded transfers.
    let aw_bundles = state
        .xzone_abort_bundles_submitted_total
        .load(std::sync::atomic::Ordering::Relaxed);

    // Gap 1 fleet observability (2026-04-29): which nodes can serve
    // bound proofs right now. Each seal advances the on-disk SMT, but
    // only the rotating creator's root structurally matches the
    // `account_smt_root` signed in the seal — witnesses drain their
    // own `smt_dirty` set in `flush_witness_smt_for_seal` and land at
    // divergent roots. LightClientPool walks past divergent seeds via
    // soft-fail; these gauges expose the per-node side of that surface
    // so operators can see how often each node is the binding seed.
    let smt_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    let smt_sealed_binding = match state.epoch.read() {
        Ok(es) => es.latest_sealed_account.clone(),
        Err(_) => None,
    };
    let smt_sealed_binding = smt_sealed_binding
        .or_else(|| crate::network::epoch::fallback_latest_sealed_account(&state.rocks));
    let (smt_matches, smt_age_secs, smt_epoch) =
        smt_disk_root_vs_seal(&state.rocks, smt_sealed_binding, smt_now);

    let body = format!("{body}\
         # HELP elara_tentative_ledger_enabled Pinned to 1: tentative-apply is the only ingest path.\n\
         # TYPE elara_tentative_ledger_enabled gauge\n\
         elara_tentative_ledger_enabled {tl_enabled}\n\
         # HELP elara_pending_ledger_commits_total Pending deltas promoted to the committed ledger after consensus finality\n\
         # TYPE elara_pending_ledger_commits_total counter\n\
         elara_pending_ledger_commits_total {pl_commits}\n\
         # HELP elara_pending_ledger_discards_total Pending deltas dropped without commit (stale-sweep or apply-at-commit failure)\n\
         # TYPE elara_pending_ledger_discards_total counter\n\
         elara_pending_ledger_discards_total {pl_discards}\n\
         # HELP elara_pending_ledger_rejections_total Tentative inserts rejected at ingest (per-identity or global quota hit)\n\
         # TYPE elara_pending_ledger_rejections_total counter\n\
         elara_pending_ledger_rejections_total {pl_rejections}\n\
         # HELP elara_pending_ledger_fallback_direct_apply_total Tentative-ledger cap-pinch fallback: records that were rejected from pending_ledger and got direct-applied to the committed ledger to preserve canary/peer consistency. Steady-state non-zero on a canary means cap is too tight or commit latency too slow.\n\
         # TYPE elara_pending_ledger_fallback_direct_apply_total counter\n\
         elara_pending_ledger_fallback_direct_apply_total {pl_fallback}\n\
         # HELP elara_pending_ledger_hard_discards_total Tentative-ledger hard-ceiling sweep: subset of discards where the entry was past PENDING_HARD_DISCARD_TIMEOUT_SECS=1200 and dropped regardless of consensus state. Sustained non-zero means consensus is genuinely stuck on those records (Sealed/Anchored but never Finalized); investigate seal_finality_signers_added_total and 2/3 attestation reach.\n\
         # TYPE elara_pending_ledger_hard_discards_total counter\n\
         elara_pending_ledger_hard_discards_total {pl_hard_discards}\n\
         # HELP elara_pending_drain_apply_failed_total Tentative-ledger drain canary: cumulative apply_single_record failures at commit time. Each bump means consensus finalized the record and the drain pulled its delta, but the canonical apply path rejected the op (insufficient balance, conservation violation, etc.). The delta is dropped — re-applying would not help. Mainnet target: zero. Sustained non-zero is a CRITICAL invariant alert — consensus and ledger disagree on a finalized op.\n\
         # TYPE elara_pending_drain_apply_failed_total counter\n\
         elara_pending_drain_apply_failed_total {pl_drain_apply_failed}\n\
         # HELP elara_pending_drain_missing_record_total Tentative-ledger drain canary: cumulative finalized record_ids whose body is missing from CF_RECORDS at drain time. Should be impossible in steady state (records only leave CF_RECORDS via explicit eviction, and the consensus finality queue only tracks records that were ingested). Sustained non-zero signals a record-pruning bug or a forensic eviction that ran while the record was still in flight.\n\
         # TYPE elara_pending_drain_missing_record_total counter\n\
         elara_pending_drain_missing_record_total {pl_drain_missing_record}\n\
         # HELP elara_pending_boot_reconciled_total Crash-recovery canary: cumulative finalized-but-unapplied deltas re-armed by boot_replay when the node restarted inside the finality-to-drain window (the in-memory finalization queue was lost on crash). Each is committed by the first drain tick via the normal path. Non-zero means this node crashed mid-commit at least once and recovered a delta that would otherwise have silently forked its committed ledger from peers. Mainnet target: 0; sustained growth means the node is crash-looping inside the commit window.\n\
         # TYPE elara_pending_boot_reconciled_total counter\n\
         elara_pending_boot_reconciled_total {pl_boot_reconciled}\n\
         # HELP elara_rotation_cf_write_total KR-3 S2: rotation-chain CF entries written, labelled by writer. writer=drain is the W1 finalize-drain hook (writes on the finalize tick from fresh in-memory seal state); writer=sweep (future W2 slice) is the durable-marker catch-up. Zero while s2_rotation_ordering_enabled is OFF - the hook is flag-gated. Non-zero once the flag flips and rotation-class records finalize.\n\
         # TYPE elara_rotation_cf_write_total counter\n\
         elara_rotation_cf_write_total{{writer=\"drain\"}} {rot_cf_write_drain}\n\
         elara_rotation_cf_write_total{{writer=\"sweep\"}} {rot_cf_write_sweep}\n\
         # HELP elara_rotation_cf_write_failed_total KR-3 S2: rotation-chain CF writes that failed to persist (RocksDB error) in the W1 drain hook. The W2 marker sweep is the durable backstop, so a transient bump self-heals; sustained non-zero signals a storage fault the sweep will also hit. Mainnet target: zero.\n\
         # TYPE elara_rotation_cf_write_failed_total counter\n\
         elara_rotation_cf_write_failed_total {rot_cf_write_failed}\n\
         # HELP elara_rotation_reason_rejected_total KR-3 S2 (5-H5, R-7): rotation-class records rejected at admission for a reason outside the documented vocabulary (rotations: periodic|compromise|upgrade; revocations: compromise|decommission|superseded). Exact-match validation so the cascade trigger (fires on reason==compromise) cannot be half-fired by a case/whitespace/typo variant. Zero while s2_rotation_ordering_enabled is OFF. Non-zero is honest-author friction (re-sign with a documented reason), not a fault.\n\
         # TYPE elara_rotation_reason_rejected_total counter\n\
         elara_rotation_reason_rejected_total {rot_reason_rejected}\n\
         # HELP elara_rotation_recent_floor_rejected_total KR-3 S2 (5-H1, R-4): rotation-class records rejected at admission for a timestamp older than the FIXED 3600s recent-floor (ROTATION_CLASS_MAX_PAST_SECS). A fixed constant, not an adaptive per-node bound, so the sealer and witness agree by construction (the amendment-1 adaptive formula forked under heterogeneous config / cold restart). Honest-user protection only, never an ordering input - the deterministic ordering bound is the seal-committed witness coverage check. The general path still warn-accepts old NON-rotation records. Zero while s2_rotation_ordering_enabled is OFF. Non-zero is honest-author friction (re-sign with a fresh timestamp), not a fault.\n\
         # TYPE elara_rotation_recent_floor_rejected_total counter\n\
         elara_rotation_recent_floor_rejected_total {rot_recent_floor_rejected}\n\
         # HELP elara_rotation_parent_grounding_rejected_total KR-3 S2 (5-H2, 5-H3): rotation-class records rejected at admission for parent grounding - no cited parent (H2), a locally-loadable parent older than the 24h ROTATION_PARENT_MAX_AGE_SECS cap, or no cited parent durably finalized at admission (H3: ordinary/revocation parents via the FinalizedIndex row, rotation-hop parents via a rotation-CF entry at state>=Final, never the transient attestation map). Defense-in-depth only - S2 ordering never reads parent data, so the per-node age clock is correct here. Zero while s2_rotation_ordering_enabled is OFF. Non-zero is honest-author friction (re-parent onto a fresh finalized parent), not a fault.\n\
         # TYPE elara_rotation_parent_grounding_rejected_total counter\n\
         elara_rotation_parent_grounding_rejected_total {rot_parent_grounding_rejected}\n\
         # HELP elara_rotation_predecessor_ungrounded_rejected_total KR-3 S2 (5-H3b): rotation HOPS rejected at admission because prev_key has no durably-final introducing hop (get_rotation_newkey_index None). FAIL-CLOSED: None is ambiguous between a genuine root and a not-yet-final/unseen predecessor (indistinguishable from local state - the payload carries no depth field, the newkey index is finalized-only, admission is async), so admission never silently pins prev_key as a root - doing so writes an immutable zone pin that forks against a node which finalized the predecessor first (audit kr3-s2-h3b-fork-an internal audit). Disambiguating fork-freely needs a positive finalized origin-key predicate that does not exist yet (deferred KR-3 stable-identity), which is why the network-wide flag flip stays blocked. Zero while s2_rotation_ordering_enabled is OFF. Non-zero flag-ON is expected interim: a deep hop retries after its predecessor finalizes; a genuine root stays rejected until the origin primitive lands.\n\
         # TYPE elara_rotation_predecessor_ungrounded_rejected_total counter\n\
         elara_rotation_predecessor_ungrounded_rejected_total {rot_predecessor_ungrounded}\n\
         # HELP elara_rotation_cf_canonicality_mismatch_total KR-3 S2 (W2-D): rotation-CF entries the durable-marker sweep rewrote under a DIFFERENT covering seal than the one already on disk - the canonical winner of the seal's (zone,epoch) slot flipped between ticks (a Burial-evidence reorg, or a W1-optimistic write that lost canonicality). The rewrite self-corrects to the canonical seal; this counter is the alarm. Zero while s2_rotation_ordering_enabled is OFF. A Quorum winner is BFT-unique per slot so it should never legitimately flip - sustained non-zero on a well-connected chain is a fork/partition signal.\n\
         # TYPE elara_rotation_cf_canonicality_mismatch_total counter\n\
         elara_rotation_cf_canonicality_mismatch_total {rot_canon_mismatch}\n\
         # HELP elara_rotation_sweep_runs_total KR-3 S2 (W2-D): durable-marker sweep invocations that actually ran (flag ON). The W2-C loop calls the sweep every 60s but it early-returns while the flag is OFF, so this stays zero until the flag flips - then it is the sweep's liveness heartbeat. Flatlining while the flag is ON means the 60s pending-sweep loop stalled.\n\
         # TYPE elara_rotation_sweep_runs_total counter\n\
         elara_rotation_sweep_runs_total {rot_sweep_runs}\n\
         # HELP elara_rotation_sweep_markers_scanned_total KR-3 S2 (W2-D): cumulative armed rotation_seal_pending:{{zone}}:{{epoch}} markers examined across all sweep runs. Zero while the flag is OFF.\n\
         # TYPE elara_rotation_sweep_markers_scanned_total counter\n\
         elara_rotation_sweep_markers_scanned_total {rot_sweep_scanned}\n\
         # HELP elara_rotation_sweep_markers_discharged_total KR-3 S2 (W2-D): cumulative markers discharged (deleted after every member hop of a winning seal was written). scanned minus discharged is the pending backlog. Zero while the flag is OFF.\n\
         # TYPE elara_rotation_sweep_markers_discharged_total counter\n\
         elara_rotation_sweep_markers_discharged_total {rot_sweep_discharged}\n\
         # HELP elara_rotation_sweep_orphan_markers_total KR-3 S2 (W2-D): cumulative orphan markers seen - an armed (zone,epoch) slot with no stored seal. Kept, never written; a sustained non-zero signals a marker armed without its seal landing (a crash-window or arming-path bug). Zero while the flag is OFF.\n\
         # TYPE elara_rotation_sweep_orphan_markers_total counter\n\
         elara_rotation_sweep_orphan_markers_total {rot_sweep_orphans}\n\
         # HELP elara_rotation_sweep_pending_markers KR-3 S2 (W2-D): armed markers still pending after the LAST sweep run (scanned minus discharged) - a gauge, not a counter. Steady-state near zero once seals bury; a rising value means the sweep is not discharging (pulse-less seals, deferred same-slot lineages, or sub-quorum evidence). Zero while the flag is OFF.\n\
         # TYPE elara_rotation_sweep_pending_markers gauge\n\
         elara_rotation_sweep_pending_markers {rot_sweep_pending}\n\
         # HELP elara_zone_purge_records_purged_total Cumulative records deleted by the zone-purge tick after unsubscribe(). Steady non-zero is normal during subscription churn; a node that never unsubscribes should hold this at 0 fleet-wide.\n\
         # TYPE elara_zone_purge_records_purged_total counter\n\
         elara_zone_purge_records_purged_total {zp_purged}\n\
         # HELP elara_orphan_resolver_high_count_pruned_total Cumulative orphan edges pruned by the orphan_resolver_loop's circuit-breaker prune. The resolver always attempts fetch (bounded MAX_FETCH=50/cycle); when orphan_count > 200 after fetch - i.e. cascade is outpacing fetch - this prune fires to cap growth. Bootstrap-pathology distinguisher: rises during catch-up on a behind node, drains to flat once orphan_count stabilises below 200. Sustained non-zero in steady state means fetch is structurally losing to cascade - investigate peer reachability or trigger snapshot-resync.\n\
         # TYPE elara_orphan_resolver_high_count_pruned_total counter\n\
         elara_orphan_resolver_high_count_pruned_total {or_high_count_pruned}\n\
         # HELP elara_orphan_resolver_saturation_skips_total Cumulative orphan_resolver ticks skipped because SystemLoadSensor::is_saturated() reported the host beyond what cooperative yielding can rescue (normalized 1-min load > 1.5 AND aggregate CPU > total cores together). Skipping the cycle entirely lets /version + /metrics keep serving while orphans wait for the next 60s tick. On a constrained 2-vCPU node during catch-up non-zero is expected and self-clearing. Sustained non-zero in steady state means the host is structurally undersized - investigate snapshot-resync or upsize.\n\
         # TYPE elara_orphan_resolver_saturation_skips_total counter\n\
         elara_orphan_resolver_saturation_skips_total {or_saturation_skips}\n\
         # HELP elara_balances_response_truncated_total Cumulative /balances responses where the account set exceeded MAX_BALANCES_RESPONSE=1000 and the body was truncated. Healthy on testnet = 0 (≤100 accounts). Non-zero in production means the unconditional /balances contract is structurally broken by scale — clients should switch to '?identity=' or paginated reads. Bound prevents the previously 200 MB unbounded body at 1M accounts.\n\
         # TYPE elara_balances_response_truncated_total counter\n\
         elara_balances_response_truncated_total {balances_truncated}\n\
         # HELP elara_balances_short_prefix_rejected_total Cumulative /balances calls rejected because '?identity=' was shorter than MIN_BALANCES_PREFIX_LEN=8 hex chars. Bounds the O(accounts) prefix-scan attack surface — short prefixes that miss the exact-match HashMap probe would otherwise scan every account on every call. Non-zero is normal background (typo/probe traffic); sustained-high is a DoS signal.\n\
         # TYPE elara_balances_short_prefix_rejected_total counter\n\
         elara_balances_short_prefix_rejected_total {balances_short_prefix_rejected}\n\
         # HELP elara_snapshot_size_rejected_total Cumulative /snapshot and /snapshot/state-delta calls rejected because the request would emit a full-state body the chain has outgrown. Three trip conditions feed this counter: (1) /snapshot full-fat read above MAX_SNAPSHOT_FULL_ACCOUNTS=100000; (2) /snapshot/state-delta falling through to full-state — either since_epoch=0 or since_epoch>0 with no archive baseline at-or-before that epoch; (3) /snapshot when CF_APPLIED holds more than MAX_SNAPSHOT_APPLIED_RECORDS=1000000 records — the collect_applied_ids HashSet alone (~64 B/id x 10M = 640 MB) is the OOM driver independent of accounts.len(). Above any cap the full-fat clone+collect_applied_ids+JSON path would push 4 GB nodes into swap. Non-zero on a chain that has crossed any cap is a structural signal: bootstrappers must switch to incremental '?since_epoch=N' against an archive-snapshot node that holds the matching baseline. Pair with elara_archive_snapshot_emitted_total to confirm the migration target is available before flipping the cap.\n\
         # TYPE elara_snapshot_size_rejected_total counter\n\
         elara_snapshot_size_rejected_total {snapshot_size_rejected}\n\
         # HELP elara_zone_purge_queue_depth Zones currently waiting for purge. A zone re-enqueues itself while still draining (>5K records left), so this is a load gauge, not a distinct-zone count. Steady-state should sit at 0; sustained non-zero means purges are arriving faster than the 250ms drain loop can clear them.\n\
         # TYPE elara_zone_purge_queue_depth gauge\n\
         elara_zone_purge_queue_depth {zp_queue_depth}\n\
         # HELP elara_zone_purge_lag_seconds_oldest Head-of-queue age. 0 when the queue is empty. Distinguishes healthy churn (queue head is fresh, <1s) from stuck purges (head age grows past tick cadence). Past ~10s sustained is a paging signal — investigate iter_zone or delete_record latency before raising MAX_PURGE_PER_TICK.\n\
         # TYPE elara_zone_purge_lag_seconds_oldest gauge\n\
         elara_zone_purge_lag_seconds_oldest {zp_lag_secs:.1}\n\
         # HELP elara_pending_ledger_depth In-flight tentative deltas currently waiting on consensus finality\n\
         # TYPE elara_pending_ledger_depth gauge\n\
         elara_pending_ledger_depth {pl_depth}\n\
         # HELP elara_pending_ledger_max_identity_depth Largest per-creator tentative-delta bucket (≤ MAX_PENDING_PER_IDENTITY=4096). At cap → cap-pinch fallback firing on that identity; sustained ≥3686 (90% of cap) indicates one creator saturating the per-identity quota and exiting the conservation-invariant safety path via direct-apply.\n\
         # TYPE elara_pending_ledger_max_identity_depth gauge\n\
         elara_pending_ledger_max_identity_depth {pl_max_id_depth}\n\
         # HELP elara_pending_ledger_oldest_age_seconds Age in seconds of the oldest pending delta (now − min(applied_at)). 0 when the store is empty. Distinguishes high-churn-but-healthy (depth at cap, age stays <60s) from stuck-pending (depth at cap, age grows past PENDING_DISCARD_TIMEOUT_SECS=600); the latter signals consensus stall, sweep skipping Sealed entries, or finality bottleneck — operators should investigate seal_finality_signers_added_total + consensus_settled before raising the cap. Diagnostic shapes: (a) distinct=1 + max=cap → cap-pinch on one hot creator (rate-limit upstream); (b) distinct=N + max=cap/N → broad finality stall (check consensus_settled rate); (c) distinct=1 + max << cap + age > PENDING_HARD_DISCARD_TIMEOUT_SECS=1200 + fallback_direct_apply_total=0 → ONE creator's finality bottleneck (their submit-rate > finality-rate, sweep hard-discards 1200s entries — silent UX drop, conservation invariant preserved). Top-offender identity is logged on each tentative-ledger discard sweep that hits hard-discards; grep journalctl for `top offender: identity=` to identify the bottlenecked creator.\n\
         # TYPE elara_pending_ledger_oldest_age_seconds gauge\n\
         elara_pending_ledger_oldest_age_seconds {pl_oldest_age_secs:.1}\n\
         # HELP elara_pending_ledger_distinct_identities Count of distinct creator identities with at least one live pending delta. Pair with elara_pending_ledger_depth and elara_pending_ledger_max_identity_depth to diagnose cap saturation cause: distinct=1 + max=4096 → single hot creator triggering cap-pinch fallback (rate-limit upstream); distinct=N + max=cap/N → broad-base lag from finality stall (investigate consensus_settled / seal_finality). Bounded by MAX_TOTAL_PENDING=1M but in practice by active creators in the zone.\n\
         # TYPE elara_pending_ledger_distinct_identities gauge\n\
         elara_pending_ledger_distinct_identities {pl_distinct_ids}\n\
         # HELP elara_orphan_seals_total Monotonic count of seals demoted from canonical when a heavier same-(zone, epoch) sibling won weight-based reconciliation (per the protocol spec, the partition-merge operator keeps the higher-attestation-weight chain). Records covered by orphaned seals stay in the DAG (append-only); only the seal-level mapping is overwritten. Sustained non-zero rate after a netsplit heal is the load-bearing signal that the reconciler is firing.\n\
         # TYPE elara_orphan_seals_total counter\n\
         elara_orphan_seals_total {orphan_seals_total}\n\
         # HELP elara_orphan_siblings_live Live entries across all (zone, epoch) orphan-sibling rings. Bounded at 1024 keys × 256 entries (≈12 MB worst case). Sized for 1024 simultaneous partition windows; LRU-by-min evicts the lex-min key on overflow. Steady-state target is 0 outside of active partition healing.\n\
         # TYPE elara_orphan_siblings_live gauge\n\
         elara_orphan_siblings_live {orphan_siblings_live}\n\
         # HELP elara_orphan_promotions_total Monotonic count of canonical seals replaced by a previously-orphaned sibling that accumulated more attestation weight after the original canonicalization. This is the load-bearing signal that the partition-merge operator is doing real work post-heal - each bump means the canonical chain shifted to follow the heavier (more-attested) side of a partition. Gated on partition_merge_weight_reconcile flag.\n\
         # TYPE elara_orphan_promotions_total counter\n\
         elara_orphan_promotions_total {orphan_promotions_total}\n\
         # HELP elara_same_epoch_seal_demotions_total Monotonic count of same-epoch seal DEMOTIONS observed at seal-registration ingest, across BOTH the default lex-min path (register_seal) and the weight-reconcile path (register_seal_with_reconcile). Distinct from elara_orphan_seals_total, which only counts the weight-reconcile path's orphan-ring inserts; this counts every same-epoch canonical swap/drop regardless of the partition_merge_weight_reconcile flag. Non-zero rate is expected during partition heals / dual-proposer races. Feeds the cross-zone coverage scan (xzone_demotion_probe).\n\
         # TYPE elara_same_epoch_seal_demotions_total counter\n\
         elara_same_epoch_seal_demotions_total {xz_same_epoch_demotions}\n\
         # HELP elara_xzone_demoted_seal_covers_lock_total Monotonic count of demoted-seal coverage scans where the demoted seal covered at least one in-flight cross-zone transfer (any status) still tracked in cross_zone.pending. Context for the claimed-lock trip-wire below: a non-zero value here with a zero claimed counter means demotions are touching cross-zone locks but none had been claimed yet (the claim gate's frozen-committee finality check still protects conservation).\n\
         # TYPE elara_xzone_demoted_seal_covers_lock_total counter\n\
         elara_xzone_demoted_seal_covers_lock_total {xz_demoted_covers_lock}\n\
         # HELP elara_xzone_demoted_seal_covers_claimed_lock_total CONSERVATION TRIP-WIRE. Monotonic count of demoted-seal coverage scans where the demoted seal covered a CLAIMED cross-zone transfer — the precondition for the (deferred, design-only) XZoneRevert clawback (internal design notes Gap D; spec/tla/Conservation.tla TAIL 1). Healthy = 0. Supply conservation is NOT broken when this fires: the ledger is an append-only fold independent of seal canonicality, so the lock debit and claim credit both stand (sender -Amt, recipient +Amt, pending 0 = conserved). A non-zero value means a finalized source seal that backed a claim later lost canonical status — which under the frozen-committee claim gate implies a >=2/3 source-committee equivocation (a slashing event), or a cross-partition claim-then-demote. It is the empirical signal to build the sum-neutral XZoneRevert; investigate the logged transfer_ids before then.\n\
         # TYPE elara_xzone_demoted_seal_covers_claimed_lock_total counter\n\
         elara_xzone_demoted_seal_covers_claimed_lock_total {xz_demoted_covers_claimed}\n\
         # HELP elara_demoted_seal_scan_queue_dropped_total Demotion-scan queue entries dropped (drop-oldest) because a demotion burst exceeded DEMOTED_SEAL_SCAN_QUEUE_CAP (1024) between health-loop scan ticks. Sustained non-zero means the trip-wire may have missed some demotions — raise the cap or the scan cadence. Steady-state target 0.\n\
         # TYPE elara_demoted_seal_scan_queue_dropped_total counter\n\
         elara_demoted_seal_scan_queue_dropped_total {xz_demoted_scan_dropped}\n\
         # HELP elara_account_smt_disk_root_matches_latest_seal 1 if the node's on-disk account-SMT root equals the `account_smt_root` signed in the latest sealed binding (`EpochState::latest_sealed_account`, fallback to CF_EPOCHS reverse-scan), 0 if diverged. Empirically only the rotating seal-creator returns 1; witnesses drain a different smt_dirty scope in flush_witness_smt_for_seal and land at divergent roots. LightClientPool absorbs that asymmetry on the read path via soft-fail; this gauge surfaces it on the write path so operators can see per-node binding eligibility. Reports 1 when no seal binding is available yet (genesis / pre-binding chain) so dashboards don't alert on a network with nothing to diverge from.\n\
         # TYPE elara_account_smt_disk_root_matches_latest_seal gauge\n\
         elara_account_smt_disk_root_matches_latest_seal {smt_matches}\n\
         # HELP elara_account_smt_disk_root_age_seconds Seconds since `latest_sealed_account.sealed_at` when this node's on-disk SMT root matches the sealed root, -1 when diverged or no binding. Lets dashboards plot the rotating-creator pattern (only one node has age>=0 at any moment in the current witness-flush regime). Once scope-bounded flush keyed on seal.record_hashes OR embedded SMT delta lands, every node will return age>=0 most of the time and the soft-fail path in LightClientPool becomes a rare retry rather than the steady state.\n\
         # TYPE elara_account_smt_disk_root_age_seconds gauge\n\
         elara_account_smt_disk_root_age_seconds {smt_age_secs:.1}\n\
         # HELP elara_account_smt_latest_seal_epoch Epoch number of the latest sealed account-SMT binding this node is anchored against (`EpochState::latest_sealed_account.epoch_number`, fallback to CF_EPOCHS reverse-scan). -1 when no binding has registered yet. Dashboards can max() this across the fleet to estimate cluster progress; min() vs max() spread shows lag.\n\
         # TYPE elara_account_smt_latest_seal_epoch gauge\n\
         elara_account_smt_latest_seal_epoch {smt_epoch}\n\
         # HELP elara_finalization_queue_enqueued_total Finality events pushed onto the AWCConsensus drain queue\n\
         # TYPE elara_finalization_queue_enqueued_total counter\n\
         elara_finalization_queue_enqueued_total {fq_enq}\n\
         # HELP elara_finalization_queue_drained_total Finality events pulled off the queue by the state-core drain loop\n\
         # TYPE elara_finalization_queue_drained_total counter\n\
         elara_finalization_queue_drained_total {fq_drn}\n\
         # HELP elara_finalization_queue_overflow_total Finality events dropped because the bounded queue was at MAX_FINALIZATION_QUEUE (drain lag signal — commits still happen via reconcile path)\n\
         # TYPE elara_finalization_queue_overflow_total counter\n\
         elara_finalization_queue_overflow_total {fq_ovf}\n\
         # HELP elara_finalization_queue_depth Current AWCConsensus finality-event queue depth\n\
         # TYPE elara_finalization_queue_depth gauge\n\
         elara_finalization_queue_depth {fq_depth}\n\
         # HELP elara_newly_sealed_queue_enqueued_total MAINNET gap #8 Sealed events pushed (Pending→Sealed edge) for WS broadcast\n\
         # TYPE elara_newly_sealed_queue_enqueued_total counter\n\
         elara_newly_sealed_queue_enqueued_total {ns_enq}\n\
         # HELP elara_newly_sealed_queue_drained_total Sealed events drained by NodeState and broadcast via NodeEvent::RecordSealed\n\
         # TYPE elara_newly_sealed_queue_drained_total counter\n\
         elara_newly_sealed_queue_drained_total {ns_drn}\n\
         # HELP elara_newly_sealed_queue_overflow_total Sealed events dropped because the queue was at MAX_SEALED_QUEUE (UX-only signal, no correctness impact)\n\
         # TYPE elara_newly_sealed_queue_overflow_total counter\n\
         elara_newly_sealed_queue_overflow_total {ns_ovf}\n\
         # HELP elara_newly_sealed_queue_depth Current AWCConsensus Sealed-event queue depth\n\
         # TYPE elara_newly_sealed_queue_depth gauge\n\
         elara_newly_sealed_queue_depth {ns_depth}\n\
         # HELP elara_consensus_priority_evictions_total Records evicted from AWCConsensus state (attestations / confirmation_levels / creator_stakes / cross_zone_parents) by the priority-eviction sweep when memory caps are reached. Steady-state non-zero on a node with healthy throughput means the consensus working set is bounded by memory rather than by finality-drain — capacity-pressure signal for the consensus tier.\n\
         # TYPE elara_consensus_priority_evictions_total counter\n\
         elara_consensus_priority_evictions_total {pri_evictions}\n\
         # HELP elara_consensus_priority_evictions_near_settlement_total Subset of priority evictions where the record had >=2 attestations (close to settlement). High ratio (near_settle / total) means we're evicting records right before they would have settled — the cap is too tight or finality is too slow. Mainnet target: ratio < 5%; sustained higher needs the eviction cap raised or the finality path debugged.\n\
         # TYPE elara_consensus_priority_evictions_near_settlement_total counter\n\
         elara_consensus_priority_evictions_near_settlement_total {pri_evictions_near_settle}\n\
         # HELP elara_consensus_evictions_finalized_total Records evicted by `prune_where`/`prune_finalized` from the AWCConsensus attestation map after finalization (either this node finalized them locally or a peer's finalization arrived through FinalizedIndex). Healthy steady-state: tracks roughly with `elara_finalized_count` deltas over time. Pair with elara_consensus_priority_evictions_total + _evictions_age_total + _evictions_zone_purge_total to decompose total ratiable-bucket exit into the 4-mechanism taxonomy.\n\
         # TYPE elara_consensus_evictions_finalized_total counter\n\
         elara_consensus_evictions_finalized_total {evictions_finalized}\n\
         # HELP elara_consensus_evictions_age_total Records evicted by `prune_older_than(24h)` - the memory_prune_loop's age cutoff fires when the newest attestation timestamp on a record is older than 24h. Steady-state non-zero on a quiet node is normal (retroactive imports with pre-aged timestamps land here). High rate vs `elara_finalized_count` delta = records are aging out without ever reaching finality; investigate witness participation or stake distribution. Pair with `_evictions_finalized_total` + `_priority_evictions_total` + `_evictions_zone_purge_total`.\n\
         # TYPE elara_consensus_evictions_age_total counter\n\
         elara_consensus_evictions_age_total {evictions_age}\n\
         # HELP elara_consensus_evictions_zone_purge_total Records evicted by `forget_record` during the ZSP zone-purge tick after a zone subscription change. Counter sums per-record across all unsubscribed zones; only counts evictions where the record was actually present in the attestation map (idempotent no-op calls do NOT bump). Pair with `_evictions_finalized_total` + `_evictions_age_total` + `_priority_evictions_total` for full 4-mechanism eviction decomposition.\n\
         # TYPE elara_consensus_evictions_zone_purge_total counter\n\
         elara_consensus_evictions_zone_purge_total {evictions_zone_purge}\n\
         # HELP elara_consensus_committee_rotations_total Monotonic counter of committee rotations. One increment per register_epoch_committee call. Use rate(...[1h]) to verify the per-epoch rotation engine is firing on the configured cadence — a flat counter on a producing node means epoch boundaries are not being processed.\n\
         # TYPE elara_consensus_committee_rotations_total counter\n\
         elara_consensus_committee_rotations_total {committee_rotations}\n\
         # HELP elara_consensus_committee_zones_registered Number of zones with an active per-epoch committee right now (post-register_epoch_committee, pre-clear). 0 = the per-epoch rotation tick has not registered any committee yet, or every zone is below the bootstrap eligibility threshold and reverted to full-zone-stake denominator. Pair with elara_consensus_committee_rotations_total: rotations climbing while registered = 0 means committees are being computed but the call is clearing every zone (eligible-pool empty).\n\
         # TYPE elara_consensus_committee_zones_registered gauge\n\
         elara_consensus_committee_zones_registered {cs_zones_registered}\n\
         # HELP elara_consensus_committee_size_min Smallest committee size across all zones with a registered committee. 0 when no committee is registered (zones_registered=0). Mainnet-target floor is MAINNET_COMMITTEE_SIZE=7 — values below indicate either bootstrap fallback (sparse stake) or a zone where the eligible-pool filter dropped real witnesses. Pair with elara_consensus_committee_zones_below_target to count how many zones share this floor.\n\
         # TYPE elara_consensus_committee_size_min gauge\n\
         elara_consensus_committee_size_min {cs_size_min}\n\
         # HELP elara_consensus_committee_size_max Largest committee size across all zones with a registered committee. 0 when no committee is registered. Bootstrap-fallback path (eligible < MIN_SCOPED_ELIGIBLE) emits committees up to BOOTSTRAP_FALLBACK_CAP=64 — sustained max in that range = mainnet-mode never reached for at least one zone. Mainnet-mode caps at MAINNET_COMMITTEE_SIZE=7.\n\
         # TYPE elara_consensus_committee_size_max gauge\n\
         elara_consensus_committee_size_max {cs_size_max}\n\
         # HELP elara_consensus_committee_zones_below_target Count of zones whose registered committee is smaller than MAINNET_COMMITTEE_SIZE=7. Load-bearing alarm signal for per-zone committee health. In a fully-staked mainnet zone every committee should reach the target; sustained non-zero on the same zone count = either eligible-pool filter dropped real witnesses (zone subscriber list out of sync - reconcile with zone registry) or stake distribution is too sparse for that zone to reach quorum (operator action: re-balance stake or merge zone via auto-scaling).\n\
         # TYPE elara_consensus_committee_zones_below_target gauge\n\
         elara_consensus_committee_zones_below_target {cs_zones_below_target}\n\
         # HELP elara_consensus_records_missing_creator_stake Count of tracked records (in `attestations` map) whose creator does not yet have a `creator_stakes` row. Steady state should be 0 — every record arriving via `add_attestation` should have its creator stake registered before the next epoch tick (`epoch.rs:3596` backfill). Non-zero is operator-actionable: (a) transient at restart while snapshot loads attestations but creator_stakes hasn't backfilled — drains within ~30-60 s; (b) sustained = epoch backfill loop is stalled OR records are arriving for unknown creators (creator never staked / staked-then-unstaked path). Settlement still works in case (b) because `is_settled` falls back to `creator_stake = 0`, but the math silently allows the creator to self-attest within their own `eligible_stake` denominator. Bounded by hot-tier MAX_ATTESTATION_RECORDS (~50K).\n\
         # TYPE elara_consensus_records_missing_creator_stake gauge\n\
         elara_consensus_records_missing_creator_stake {consensus_missing_creator_stake}\n\
         # HELP elara_consensus_unknown_profile_pairs_total AUDIT-9 Milestone B: per-call counter of correlation_weighted invocations hitting the unknown-profile branch. Measures load, not health — fires once per call regardless of (a,b) pair identity. See elara_consensus_unknown_profile_witnesses_gauge for the actual Milestone B effectiveness signal.\n\
         # TYPE elara_consensus_unknown_profile_pairs_total counter\n\
         elara_consensus_unknown_profile_pairs_total {unknown_pp}\n\
         # HELP elara_consensus_unknown_profile_witnesses_gauge AUDIT-9 follow-up #1: count of distinct witnesses with a derived_geo observation (we've spoken to them) but no profile registration. After Milestone B propagates, this should plateau near 0. Bounded by O(active_peers).\n\
         # TYPE elara_consensus_unknown_profile_witnesses_gauge gauge\n\
         elara_consensus_unknown_profile_witnesses_gauge {unknown_profile_witnesses}\n\
         # HELP elara_finality_witness_pushed_total SealFinalityWitness gossip envelopes broadcast by this node (signed locally OR forwarded). Zero means no committee membership OR the producer-sign hook never fired.\n\
         # TYPE elara_finality_witness_pushed_total counter\n\
         elara_finality_witness_pushed_total {fw_pushed}\n\
         # HELP elara_finality_witness_received_total Distinct (seal_id, witness_pk) gossip envelopes accepted. Pair this with pushed/rejected to size committee fan-in.\n\
         # TYPE elara_finality_witness_received_total counter\n\
         elara_finality_witness_received_total {fw_received}\n\
         # HELP elara_finality_witness_rejected_total Gossip envelopes dropped - duplicate dedup-key, malformed payload, or non-committee signer. High rate indicates a misconfigured peer or an attacker probing the gossip surface.\n\
         # TYPE elara_finality_witness_rejected_total counter\n\
         elara_finality_witness_rejected_total {fw_rejected}\n\
         # HELP elara_finality_witness_committee_mismatch_total Finality witnesses rejected because their wire committee snapshot did not match this node's locally-recomputed canonical committee for the seal (zone, epoch). Healthy mainnet: zero. Sustained non-zero means a peer is attempting cross-zone finality forgery (pinning a self-chosen committee) - escalate.\n\
         # TYPE elara_finality_witness_committee_mismatch_total counter\n\
         elara_finality_witness_committee_mismatch_total {fw_committee_mismatch}\n\
         # HELP elara_finality_witness_non_member_total Finality witnesses rejected because the committee snapshot matched but the signer's witness_pk is not a member of the canonical committee (a valid-signature fake-pk submission). Healthy mainnet: zero. Sustained non-zero means a peer is flooding fake-pk finality witnesses to grow the signers collection (memory DoS) - the insertion-time membership gate drops them; escalate if sustained.\n\
         # TYPE elara_finality_witness_non_member_total counter\n\
         elara_finality_witness_non_member_total {fw_non_member}\n\
         # HELP elara_conflict_proof_pushed_total Slot-conflict proofs THIS node generated and broadcast (a peer signed two records for the same slot, this node detected and proved it). Healthy mainnet: rare. Sustained non-zero means a Byzantine peer is actively equivocating — escalate to slashing review.\n\
         # TYPE elara_conflict_proof_pushed_total counter\n\
         elara_conflict_proof_pushed_total {cp_pushed}\n\
         # HELP elara_conflict_proof_received_total Slot-conflict proofs received from peers (post-dedup against conflict_proof_seen). Healthy mainnet: rare; non-zero when ANY node in the fleet observes equivocation. Compare cluster sum with on-disk CF_SLOT_CONFLICTS rows to verify gossip is converging.\n\
         # TYPE elara_conflict_proof_received_total counter\n\
         elara_conflict_proof_received_total {cp_received}\n\
         # HELP elara_conflict_proof_rejected_total Slot-conflict proofs dropped at ingress — malformed envelope, signature verification failure, or stale duplicate. Sustained > 0 = a peer is sending bad proofs (misconfigured client OR attacker probing the abuse-evidence surface).\n\
         # TYPE elara_conflict_proof_rejected_total counter\n\
         elara_conflict_proof_rejected_total {cp_rejected}\n\
         # HELP elara_conflict_proof_self_suppressed_total Slot-conflict proofs whose offender was THIS node's own identity, so the peer gossip was suppressed (the local slot-mark still fired). Defense-in-depth: a real broadcast equivocation is independently provable by any peer that received both records, so self-naming gossip only spams the mesh (an early production node fired one every 1-3 min from a nonce-reuse bug). Healthy = 0; non-zero means a latent self-equivocation path re-appeared — investigate, but no peer-visible spam resulted.\n\
         # TYPE elara_conflict_proof_self_suppressed_total counter\n\
         elara_conflict_proof_self_suppressed_total {cp_self_suppressed}\n\
         # HELP elara_conflict_proof_local_unverifiable_total Slot conflicts whose locally-built ConflictProof failed verify() and could not be gossiped as accountability evidence (structural failure: pre-v5 record, missing signature). Post the record_hash-discriminator fix this should stay ~0; growth means a conflict class is escaping accountability.\n\
         # TYPE elara_conflict_proof_local_unverifiable_total counter\n\
         elara_conflict_proof_local_unverifiable_total {cp_local_unverifiable}\n\
         # HELP elara_ledger_content_hash_v2_rejected_total Records rejected by the ledger content-hash v2 enforcement gate (enforce_ledger_content_hash_v2): beat_op records whose content_hash does not commit to their signed metadata via the canonical v2 preimage. Gate is OFF until the re-genesis; once on, non-zero = a peer emitting non-canonical or tampered ledger records.\n\
         # TYPE elara_ledger_content_hash_v2_rejected_total counter\n\
         elara_ledger_content_hash_v2_rejected_total {ledger_ch_v2_rejected}\n\
         # HELP elara_seal_finality_signers_added_total Distinct witness signatures folded into a SealFinalityCollection (post-dedup). Quorum-bound metric - at 2/3 committee_size this is the floor for a finalized seal.\n\
         # TYPE elara_seal_finality_signers_added_total counter\n\
         elara_seal_finality_signers_added_total {fc_added}\n\
         # HELP elara_seal_finality_signers_evicted_total Cap-pressure evictions when seal_finality_collections exceeds MAX_SEAL_FINALITY_SIG_ENTRIES. Steady-state non-zero means the cap is too tight for the seal-finalization rate.\n\
         # TYPE elara_seal_finality_signers_evicted_total counter\n\
         elara_seal_finality_signers_evicted_total {fc_evicted}\n\
         # HELP elara_seal_finality_snapshot_mismatch_total Witness signatures dropped because their (seal_epoch, committee_hash, committee_size) snapshot diverged from the pinned set — committee mid-rotation race. High rate signals churn or a deliberate equivocation attempt.\n\
         # TYPE elara_seal_finality_snapshot_mismatch_total counter\n\
         elara_seal_finality_snapshot_mismatch_total {fc_mismatch}\n\
         # HELP elara_seal_finality_collections Gauge: live SealFinalityCollection entries — one per seal currently accumulating witness sigs. Bounded by MAX_SEAL_FINALITY_SIG_ENTRIES with 10%-block evictions.\n\
         # TYPE elara_seal_finality_collections gauge\n\
         elara_seal_finality_collections {fc_collections}\n\
         # HELP elara_xzone_abort_witness_pushed_total XZoneAbortWitness gossip envelopes broadcast by this node (signed locally). Zero means no dest-zone committee membership for any sealed-and-expired transfer OR the producer-sign hook never fired.\n\
         # TYPE elara_xzone_abort_witness_pushed_total counter\n\
         elara_xzone_abort_witness_pushed_total {aw_pushed}\n\
         # HELP elara_xzone_abort_witness_received_total Distinct (transfer_id, witness_pk) abort-witness gossip envelopes accepted. Pair this with pushed/rejected to size committee fan-in for the abort path.\n\
         # TYPE elara_xzone_abort_witness_received_total counter\n\
         elara_xzone_abort_witness_received_total {aw_received}\n\
         # HELP elara_xzone_abort_witness_rejected_total Abort-witness gossip envelopes dropped at ingress - malformed payload. High rate indicates a misconfigured peer or an attacker probing the gossip surface.\n\
         # TYPE elara_xzone_abort_witness_rejected_total counter\n\
         elara_xzone_abort_witness_rejected_total {aw_rejected}\n\
         # HELP elara_xzone_abort_witness_committee_mismatch_total Abort-witness gossip envelopes dropped because their wire committee snapshot did not match this node's seal-frozen canonical dest committee for the transfer (B2 forgery gate). Healthy mainnet: zero. Sustained non-zero means a peer is attempting cross-zone abort forgery (pinning a self-chosen committee to force-refund a sealed transfer) - escalate.\n\
         # TYPE elara_xzone_abort_witness_committee_mismatch_total counter\n\
         elara_xzone_abort_witness_committee_mismatch_total {aw_committee_mismatch}\n\
         # HELP elara_xzone_abort_witness_non_member_total Abort-witness gossip envelopes dropped because the committee snapshot matched the seal-frozen anchor but the signer's witness_pk failed the Merkle inclusion proof against the canonical committee root (a valid-signature fake-pk submission). Healthy mainnet: zero. Sustained non-zero means a peer is flooding fake-pk abort witnesses to grow one transfer's signers collection (memory DoS) - the insertion-time membership gate drops them; escalate if sustained.\n\
         # TYPE elara_xzone_abort_witness_non_member_total counter\n\
         elara_xzone_abort_witness_non_member_total {aw_non_member}\n\
         # HELP elara_xzone_abort_signers_added_total Distinct abort-witness signatures folded into an XZoneAbortCollection (post-dedup). Aggregator needs >=2/3 committee_size to assemble a bundle.\n\
         # TYPE elara_xzone_abort_signers_added_total counter\n\
         elara_xzone_abort_signers_added_total {ac_added}\n\
         # HELP elara_xzone_abort_signers_evicted_total Cap-pressure evictions when xzone_abort_collections exceeds MAX_XZONE_ABORT_SIG_ENTRIES. Steady-state non-zero means the cap is too tight for the active-abort rate.\n\
         # TYPE elara_xzone_abort_signers_evicted_total counter\n\
         elara_xzone_abort_signers_evicted_total {ac_evicted}\n\
         # HELP elara_xzone_abort_snapshot_mismatch_total Abort-witness signatures dropped because their (source_seal_epoch, committee_hash, committee_size) snapshot diverged from the pinned set — committee mid-rotation race. High rate signals churn or a deliberate equivocation attempt.\n\
         # TYPE elara_xzone_abort_snapshot_mismatch_total counter\n\
         elara_xzone_abort_snapshot_mismatch_total {ac_mismatch}\n\
         # HELP elara_xzone_abort_collections Gauge: live XZoneAbortCollection entries — one per cross-zone transfer currently accumulating abort-witness sigs. Bounded by MAX_XZONE_ABORT_SIG_ENTRIES with 10%-block evictions.\n\
         # TYPE elara_xzone_abort_collections gauge\n\
         elara_xzone_abort_collections {ac_collections}\n\
         # HELP elara_xzone_abort_observations_inserted_total Dest-zone observations recorded - one per LOCK record this zone witnesses in an inbound source-zone seal. The periodic abort-emitter walks this map (NOT the full record store) to find transfers past expires_at without claim. Compare with cleared/evicted to see steady-state pressure.\n\
         # TYPE elara_xzone_abort_observations_inserted_total counter\n\
         elara_xzone_abort_observations_inserted_total {ao_inserted}\n\
         # HELP elara_xzone_abort_observations_evicted_total Cap-pressure evictions when xzone_abort_observations exceeds its bounded ceiling (oldest 10% block). Steady-state non-zero means the dest-zone observation cap is too tight for the cross-zone arrival rate — pre-expiry transfers are being dropped from the abort tracker, which weakens the safety net for stuck transfers.\n\
         # TYPE elara_xzone_abort_observations_evicted_total counter\n\
         elara_xzone_abort_observations_evicted_total {ao_evicted}\n\
         # HELP elara_xzone_abort_observations_cleared_total Observations cleared on terminal claim/abort transitions (the natural drain path). Healthy ratio cleared/inserted ≈ 1 in steady state — divergence (cleared << inserted) means transfers are accumulating in the observation map without resolution, paired with rising elara_xzone_abort_observations live count. Operator alert: cleared rate falls > 50% below inserted rate for >5 min.\n\
         # TYPE elara_xzone_abort_observations_cleared_total counter\n\
         elara_xzone_abort_observations_cleared_total {ao_cleared}\n\
         # HELP elara_xzone_abort_bundles_submitted_total XZoneAbortBundle records assembled and self-submitted by THIS node's aggregator after observing 2/3 abort-witness quorum. Cross-node duplicates are absorbed by apply-time idempotency on Locked status, so cluster sum > distinct-refunded-transfers is expected.\n\
         # TYPE elara_xzone_abort_bundles_submitted_total counter\n\
         elara_xzone_abort_bundles_submitted_total {aw_bundles}\n\
    ");

    let req_hist = state.request_latency.to_prometheus(
        "elara_http_request_duration_seconds",
        "HTTP request latency in seconds",
    );
    let req_hist_by_route = state.request_latency_by_route.to_prometheus(
        "elara_http_request_route_duration_seconds",
        "HTTP request latency in seconds, partitioned by axum matched-route pattern. Use to isolate slow paths — e.g. /headers/from/{epoch}, /proof/account/{identity} for light-client; /peers/* for gossip; /pq-ws for ELPQ session establishment.",
    );
    let req_route_labels = state.request_latency_by_route.label_count();
    let req_hist_by_route_meta = format!(
        "# HELP elara_http_request_route_label_count Live label cardinality of elara_http_request_route_duration_seconds. Approaches LABELED_HISTOGRAM_CAP ({cap}) when the router exposes more routes than expected — sustained equality with the cap means new requests are folded into the `<overflow>` label and per-route observability is degraded.\n\
         # TYPE elara_http_request_route_label_count gauge\n\
         elara_http_request_route_label_count {req_route_labels}\n",
        cap = LABELED_HISTOGRAM_CAP,
    );
    let req_status_by_route = state.request_status_by_route.to_prometheus(
        "elara_http_request_status_total",
        "HTTP request count partitioned by axum matched-route pattern and status class (2xx/3xx/4xx/5xx). Companion to elara_http_request_route_duration_seconds — surfaces silent endpoint failures (e.g. /proof/account 5xx during a partial state-snapshot window) without log scraping. status_class=`other` indicates an unexpected status family (1xx/100s or future codes).",
    );
    let gossip_hist = state.gossip_push_duration.to_prometheus(
        "elara_gossip_push_duration_seconds",
        "Gossip push round-trip duration in seconds",
    );

    let public_route_blocked = PUBLIC_ROUTE_BLOCKED_TOTAL.load(std::sync::atomic::Ordering::Relaxed);
    let pq_ws_total = state.pq_ws_sessions_total.load(std::sync::atomic::Ordering::Relaxed);
    let ws_active = state.ws_connections.load(std::sync::atomic::Ordering::Relaxed);
    let route_gate = format!(
        "# HELP elara_public_route_blocked_total HTTPS data-plane requests rejected because the peer was non-loopback and the path is not on the public-route whitelist (/pq-ws, /metrics, /health, /status, /ping, /version, /proof/account, /headers). Steady-state should be 0 once external clients have fully migrated to /pq-ws.\n\
         # TYPE elara_public_route_blocked_total counter\n\
         elara_public_route_blocked_total {public_route_blocked}\n\
         # HELP elara_pq_ws_sessions_total Cumulative /pq-ws (ELPQ-tunneled WebSocket) sessions accepted.\n\
         # TYPE elara_pq_ws_sessions_total counter\n\
         elara_pq_ws_sessions_total {pq_ws_total}\n\
         # HELP elara_ws_connections_active Currently open /pq-ws sessions (the only WebSocket transport - the legacy /ws route is retired).\n\
         # TYPE elara_ws_connections_active gauge\n\
         elara_ws_connections_active {ws_active}\n"
    );

    // MAINNET mandate #3 (floor-push): cardinality-safe per-zone adaptive
    // interval telemetry. Folds `zone_adaptive_interval` (potentially 1M
    // entries on mainnet) into 5 summary scalars so the Prometheus exposition
    // stays O(1). ADVISORY: this interval is computed + displayed but does NOT
    // currently gate seal cadence (the seal loop ticks at the fixed
    // `epoch_seal_interval_secs`); `floor_pinned_zones > 0` is therefore an
    // observability signal for where a wired adaptive gate WOULD bind, not a
    // live finality constraint today (per-zone gating is design-stage).
    let interval_summary = state.epoch.read_recover().adaptive_interval_summary();
    let adaptive_intervals = format!(
        "# HELP elara_adaptive_interval_zones_tracked Number of zones currently producing live adaptive_interval values (zones with at least one observed activity rate).\n\
         # TYPE elara_adaptive_interval_zones_tracked gauge\n\
         elara_adaptive_interval_zones_tracked {zones_tracked}\n\
         # HELP elara_adaptive_interval_min_active_seconds Minimum live adaptive_interval observed across all tracked zones. ADVISORY telemetry — the adaptive interval does not currently gate seal cadence (sealing ticks at the fixed epoch_seal_interval_secs); wiring is a design-stage item.\n\
         # TYPE elara_adaptive_interval_min_active_seconds gauge\n\
         elara_adaptive_interval_min_active_seconds {min_secs:.3}\n\
         # HELP elara_adaptive_interval_max_active_seconds Maximum live adaptive_interval observed across all tracked zones. Approaches elara_adaptive_interval_ceil_seconds when zones are idle.\n\
         # TYPE elara_adaptive_interval_max_active_seconds gauge\n\
         elara_adaptive_interval_max_active_seconds {max_secs:.3}\n\
         # HELP elara_adaptive_interval_mean_seconds Arithmetic mean of live adaptive_interval values across all tracked zones.\n\
         # TYPE elara_adaptive_interval_mean_seconds gauge\n\
         elara_adaptive_interval_mean_seconds {mean_secs:.3}\n\
         # HELP elara_adaptive_interval_floor_pinned_zones Count of zones whose adaptive_interval == MIN_ADAPTIVE_EPOCH_SECS. ADVISORY: the adaptive interval does not currently gate sealing (the seal loop ticks at the fixed epoch_seal_interval_secs); a sustained non-zero value marks where a future wired adaptive gate would bind, not a live finality constraint today.\n\
         # TYPE elara_adaptive_interval_floor_pinned_zones gauge\n\
         elara_adaptive_interval_floor_pinned_zones {floor_pinned}\n\
         # HELP elara_adaptive_interval_floor_seconds Configured MIN_ADAPTIVE_EPOCH_SECS — lower bound applied to every per-zone adaptive interval.\n\
         # TYPE elara_adaptive_interval_floor_seconds gauge\n\
         elara_adaptive_interval_floor_seconds {floor:.3}\n\
         # HELP elara_adaptive_interval_ceil_seconds Configured MAX_ADAPTIVE_EPOCH_SECS — upper bound applied to every per-zone adaptive interval.\n\
         # TYPE elara_adaptive_interval_ceil_seconds gauge\n\
         elara_adaptive_interval_ceil_seconds {ceil:.3}\n",
        zones_tracked = interval_summary.zones_tracked,
        min_secs = interval_summary.min_active_secs,
        max_secs = interval_summary.max_active_secs,
        mean_secs = interval_summary.mean_secs,
        floor_pinned = interval_summary.floor_pinned_zones,
        floor = crate::network::epoch::MIN_ADAPTIVE_EPOCH_SECS,
        ceil = crate::network::epoch::MAX_ADAPTIVE_EPOCH_SECS,
    );

    let raw = format!("{body}{req_hist}{req_hist_by_route_meta}{req_hist_by_route}{req_status_by_route}{gossip_hist}{route_gate}{adaptive_intervals}");

    // Self-reporting tier gauge — operators read this
    // to confirm what they're getting. Always lands at P0 via classify_metric
    // so the filter never drops it. Respects the per-request override
    // so a `?tier=debug` spot-fetch reports the effective tier, not the default.
    let tier = tier_override.unwrap_or_else(current_metric_tier);
    let tier_gauge = format!(
        "# HELP elara_metric_tier Verbosity tier this node is publishing on /metrics. Labels: tier=P0|P1|debug. Value 0=P0 (~50 essential families: consensus + finality + connectivity + resource ceilings — pager-grade), 1=P1 (~150 families: P0 + per-host utilization + error counters — capacity planning), 2=debug (full ~590-family surface — local dev / forensics). Phone-tier nodes should pin tier=P0 to keep /metrics body under 30 KB and scrape CPU under 0.1%; FullZone nodes default to P1; local dev nodes default to debug. Set via --metric-tier or ELARA_METRIC_TIER env.\n\
         # TYPE elara_metric_tier gauge\n\
         elara_metric_tier{{tier=\"{label}\"}} {value}\n",
        label = tier.label(),
        value = tier as u8,
    );

    filter_metrics_by_tier(&format!("{raw}{tier_gauge}{BUILD_INFO_METRIC}"), tier)
}

// ─── Explorer UI (embedded) ──────────────────────────────────────────────────

/// Serve the embedded block explorer HTML page.
async fn explorer_page() -> axum::response::Html<&'static str> {
    // NOTE: relative to this file — server.rs became server/mod.rs (one dir
    // deeper), so the embedded-asset path gains one `../` to still reach repo-root static/.
    axum::response::Html(include_str!("../../../static/explorer.html"))
}

// exchange_page() removed 2026-06-14 (pivot 2026-06-09, not-a-coin): the
// embedded coin-exchange dashboard webpage presented the internal credit as a
// transferable cryptocurrency, contradicting the README's not-a-coin posture and
// the curated public mirror. The backend /exchange/* read routes were
// subsequently removed too — no /exchange route is registered any more; the
// branded webpage no longer ships in the binary or the mirror.

// ─── Router ─────────────────────────────────────────────────────────────────

/// Per-route tight body cap for the unauthenticated `serde_json::Value`-decode
/// command surface (`/rpc/*` + the genesis faucet `/bootstrap/claim`).
///
/// These handlers untyped-`Value`-decode the body in the axum extractor — which
/// runs BEFORE the in-handler auth/genesis check — so an oversized body is an
/// UNAUTHENTICATED ~10× decode-amplifier (≈20 MiB transient heap at the 2 MiB
/// global cap) on a phone-tier node. The Content-Length fast-reject in
/// [`rate_limit_middleware`] only catches an honestly-declared length; a request
/// that omits Content-Length (`Transfer-Encoding: chunked` / streaming body)
/// slips past it. `DefaultBodyLimit` is enforced by the extractor against the
/// ACTUAL streamed byte count (via `http_body_util::Limited`), independent of any
/// header, so applied per-route it closes that bypass and 413s at the extractor.
///
/// Applied INLINE per route (not via a `.merge()`/`.nest()` sub-router) on
/// purpose: `scan-public-route-drift.py`'s flat parser must keep seeing every
/// route to enforce the dual-router public-surface invariant. A per-route limit
/// is applied closer to the handler than the parent `Router`'s 2 MiB
/// `DefaultBodyLimit`, so it wins for these routes while every other route keeps
/// the global cap.
fn rpc_body_cap() -> axum::extract::DefaultBodyLimit {
    axum::extract::DefaultBodyLimit::max(MAX_RPC_BODY_BYTES)
}

/// Explicit cap for the two peer-supplied *list* POST routes
/// (`/records/fetch`, `/announce`) — parity pin against the PQ transport's
/// `MAX_LIST_REQUEST_BODY` (2 MiB, `guard_list_body` in pq_transport/router.rs).
/// Numerically equal to axum's global default TODAY: the explicit layer makes
/// the bound greppable, immune to a future global-default change, and marks
/// the handlers' POST-parse `.take()` truncation as a deliberate contract.
fn list_body_cap() -> axum::extract::DefaultBodyLimit {
    axum::extract::DefaultBodyLimit::max(2 * 1024 * 1024)
}

/// Wider per-route body cap for `POST /transitions/propose` — see
/// [`MAX_TRANSITION_PROPOSE_BODY_BYTES`]. A proposal legitimately bundles up to
/// `MAX_PROPOSER_SIGS` Dilithium3 sigs, so [`rpc_body_cap`]'s 64 KiB would 413
/// a valid full-committee proposal; this still caps 4× under the 2 MiB global.
fn transition_propose_body_cap() -> axum::extract::DefaultBodyLimit {
    axum::extract::DefaultBodyLimit::max(MAX_TRANSITION_PROPOSE_BODY_BYTES)
}

/// Per-route body cap for `POST /slot-conflicts` — see
/// [`MAX_CONFLICT_PROOF_BODY_BYTES`]. A `ConflictProof` bundles two full
/// `ValidationRecord`s, so [`rpc_body_cap`]'s 64 KiB would 413 a legitimate proof
/// carrying two near-max records; this still caps 2× under the 2 MiB global.
fn conflict_proof_body_cap() -> axum::extract::DefaultBodyLimit {
    axum::extract::DefaultBodyLimit::max(MAX_CONFLICT_PROOF_BODY_BYTES)
}

/// Per-route body cap for the single-record ingest routes (`POST /records`,
/// `/slash`, `/witness`, `/validate`). Each decodes ONE binary-wire
/// `ValidationRecord` via `ValidationRecord::from_bytes`, hard-bounded at
/// [`crate::network::ingest::MAX_RECORD_BYTES`] (64 KiB) — the exact ceiling the
/// PQ transport's `guard_record_body` enforces (HTTP/PQ ingress parity). The
/// handlers re-check that bound in-handler, but the `Bytes` extractor still
/// BUFFERS up to the parent router's 2 MiB `DefaultBodyLimit` before the guard
/// runs; this layer 413s at the extractor so a handshaked peer can't force 2 MiB
/// of buffering (32× the PQ parse-work ceiling) per hostile submission. Binary
/// wire, so no JSON number-array expansion — cap == `MAX_RECORD_BYTES` exactly,
/// no headroom needed (unlike [`conflict_proof_body_cap`]'s JSON path).
fn record_body_cap() -> axum::extract::DefaultBodyLimit {
    axum::extract::DefaultBodyLimit::max(crate::network::ingest::MAX_RECORD_BYTES)
}

/// Per-route body cap for `POST /delta_sync`. The body is a serialized
/// [`crate::network::sync::BloomFilter`] of the requester's recent-window record
/// IDs; the only honest senders (the sync loop + gossip `delta_pull`) bound it to
/// `MAX_BLOOM_BUILD` (200K) items @ 1% FPR ≈ 234 KiB. Cap the extractor at
/// [`crate::network::sync::MAX_DELTA_SYNC_BLOOM_BODY`] (512 KiB) — PQ-parity with
/// `handle_delta_sync`'s `guard_command_body`, ~4× tighter than the 2 MiB global
/// so a peer can't force multi-MiB bloom buffering before the length-gated decode.
fn delta_sync_body_cap() -> axum::extract::DefaultBodyLimit {
    axum::extract::DefaultBodyLimit::max(crate::network::sync::MAX_DELTA_SYNC_BLOOM_BODY)
}

/// Build the axum router with all node endpoints.
pub fn routes(state: Arc<NodeState>) -> Router {
    use super::routes::{admin, core, explorer, sync, ledger, transitions};

    let limiter = Arc::new(RateLimiter::new(
        state.config.rate_limit_write,
        state.config.rate_limit_read,
    ));
    let _ = state.rate_limiter.set(limiter.clone());

    // Public router is by-design internet-facing — no cookies, no session auth.
    // All state-changing POSTs require Dilithium3 signatures inside the body,
    // so cross-origin browsers can do nothing they couldn't already do via
    // direct HTTP. Permissive CORS lets verify.html / browser accounts / any
    // light client read headers + proofs from any node without a proxy.
    // Admin + RPC live on a separate localhost-bound router (`admin_routes`).
    // `allow_credentials` defaults to false → cookies never forwarded.
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
        .allow_headers(Any);
    // ELARA_CORS_ALLOW_ALL env var is now a no-op (kept for backwards-compat
    // with old deploy scripts — public CORS is always permissive).

    let router = Router::new()
        // Core protocol
        .route("/ping", get(core::ping))
        .route("/version", get(core::version))
        // Json<ProbeRequest> is two hashes; no in-handler guard, so without this
        // the extractor buffered to the 2 MiB default. Cap at 64 KiB (rpc_body_cap)
        // — same Json-extractor parity class as /attestations (4c1244f0).
        .route("/probe", post(core::handle_probe_endpoint).layer(rpc_body_cap()))
        .route("/status", get(core::status))
        .route("/health", get(core::health))
        .route("/alive", get(core::alive))
        // POST submit_record decodes one binary-wire ValidationRecord bounded at
        // MAX_RECORD_BYTES (64 KiB); cap the extractor there (record_body_cap) to
        // match the PQ guard_record_body cap — without it the Bytes extractor
        // buffered to the 2 MiB global before the in-handler guard fired. GET
        // (query_records) carries no body → no-op.
        .route("/records", get(core::query_records).post(core::submit_record).layer(record_body_cap()))
        // Both decode a peer-supplied JSON list and `.take()` it POST-parse —
        // cap the extractor at the PQ `guard_list_body` bound (2 MiB) so the
        // two transports can't drift (see list_body_cap).
        .route("/records/fetch", post(core::fetch_records_wire).layer(list_body_cap()))
        .route("/announce", post(core::receive_announcements).layer(list_body_cap()))
        // Decodes one binary-wire ValidationRecord (MAX_RECORD_BYTES) → cap the
        // extractor at 64 KiB (record_body_cap), PQ guard_record_body parity.
        .route("/witness", post(core::witness_record).layer(record_body_cap()))
        .route("/peers", get(core::list_peers))
        .route("/merkle_root", get(sync::merkle_root))
        .route("/convergence", get(sync::convergence))
        .route("/delta_sync", post(sync::delta_sync).layer(delta_sync_body_cap()))
        // POST body capped at MAX_RPC_BODY_BYTES (64 KiB) via rpc_body_cap() to
        // match the PQ receive_attestation cap (MAX_ATTESTATION_BODY = 64 KiB) —
        // HTTP/PQ ingress parity (a real Dilithium3 attestation is ~12 KiB; the
        // global 2 MiB DefaultBodyLimit let the HTTP path do 32× the PQ parse work
        // per hostile request). GET (query_attestations) carries no body → no-op.
        .route("/attestations", get(sync::query_attestations).post(sync::receive_attestation).layer(rpc_body_cap()))
        // Json<ConflictProof> embeds two full ValidationRecords and is decoded
        // pre-verification; cap the extractor at MAX_CONFLICT_PROOF_BODY_BYTES
        // (1 MiB) not the 2 MiB global so a hostile peer can't force a 2 MiB
        // parse before verify(). Wider than rpc_body_cap (64 KiB) because two
        // near-max records legitimately exceed it (see conflict_proof_body_cap).
        .route("/slot-conflicts", post(sync::receive_conflict_proof).layer(conflict_proof_body_cap()))
        // Json<OfflineNotification> (node_id + ts + Dilithium3 sig) is small with no
        // in-handler guard; cap the extractor at 64 KiB (rpc_body_cap) not 2 MiB.
        .route("/peers/offline_notification", post(sync::receive_offline_notification).layer(rpc_body_cap()))
        // Both decode one binary-wire ValidationRecord (MAX_RECORD_BYTES); cap
        // the extractor at 64 KiB (record_body_cap) — PQ guard_record_body parity,
        // same as /records + /witness above. /slash shares submit_record.
        .route("/slash", post(core::submit_record).layer(record_body_cap()))
        .route("/validate", post(core::validate_record).layer(record_body_cap()))
        .route("/records/search", get(core::search_records))
        .route("/records/stream", get(core::records_stream))
        // Ledger
        .route("/balances", get(ledger::query_balances))
        .route("/stakes", get(ledger::query_stakes))
        .route("/ledger/summary", get(ledger::ledger_summary))
        .route("/token/enforcement", get(ledger::token_enforcement))
        // Explorer API
        .route("/history", get(ledger::tx_history))
        .route("/transactions/recent", get(ledger::recent_transactions))
        .route("/account/{identity}", get(explorer::account_detail))
        .route("/proof/account/{identity}", get(explorer::account_proof))
        // C4 slice 1: agent-mandate query (also on the public listener).
        .route("/mandate/{mandate_id}", get(explorer::mandate_detail))
        .route("/mandate/status/{record_id}", get(explorer::mandate_status))
        // C4 slice 4: bounded enumeration of acts performed under a mandate.
        .route("/mandate/{mandate_id}/acts", get(explorer::mandate_acts))
        // C4 agent-acts: bounded enumeration of acts SIGNED BY an agent, across
        // all mandates. LOOPBACK-ONLY — registered here on the full router but
        // deliberately NOT on `public_routes()` and NOT in PUBLIC_ROUTE_PREFIXES,
        // so `public_route_gate` 404s it for non-loopback peers (a by-signer index
        // is the same deanon surface already gated for /records/search?creator=).
        // Path is OUTSIDE /mandate on purpose: that prefix is public, and
        // /mandate/agent/... would both leak public + collide with the route above.
        .route("/agent/{agent_hash}/acts", get(explorer::agent_acts))
        .route("/record/{id}", get(explorer::record_detail))
        // §11.23 Layer A slice 0: node-local content-hash lookup. O(1)
        // CF_IDX_HASH point read; 404 on local miss (peer-relay = slice 1).
        .route("/records/by-hash/{content_hash}", get(explorer::record_by_hash))
        .route("/record/{id}/causal-proof", get(explorer::causal_proof))
        // Canonical wire bytes for offline verification (elara-verify /
        // receipts.html step 3) — the JSON detail above has no signature bytes.
        .route("/record/{id}/wire", get(explorer::record_wire))
        .route("/seal/progress/{id}", get(explorer::seal_progress_route))
        .route("/network", get(explorer::network_info))
        .route("/validate_address/{address}", get(explorer::validate_address))
        // Identity Partitioning Phase D: on-miss peer fetch endpoint. Returns
        // PK + tier (anchor/witness/user/legacy) if locally known, or
        // `{pk: null, tier: null}` if not. Public read surface — PKs are
        // public by definition (Protocol §7.5.1).
        .route("/identity/pk/{hash}", get(explorer::identity_pk_route))
        // Supply introspection (circulating / total / max credit supply)
        .route("/supply", get(ledger::supply_circulating))
        .route("/supply/total", get(ledger::supply_total))
        .route("/supply/max", get(ledger::supply_max))
        // Snapshot sync (bootstrap + fast sync)
        .route("/snapshot", get(sync::serve_snapshot))
        .route("/snapshot/latest", get(sync::serve_snapshot_metadata))
        .route("/snapshot/fast", get(sync::serve_snapshot_fast))
        // Gap 7: epoch-indexed signed snapshots (archive nodes serve)
        .route("/snapshot/epochs", get(sync::list_epoch_snapshots_route))
        .route("/snapshot/epoch/{epoch}", get(sync::serve_epoch_snapshot))
        // Audit #3: incremental state-delta sync. Returns only changed
        // accounts since `?since_epoch={N}`. Falls back to full ledger when
        // the archive snapshot at N is unavailable. See routes/sync.rs.
        .route("/snapshot/state-delta", get(sync::serve_state_delta))
        // Epoch sealing
        .route("/epochs", get(explorer::epoch_status))
        // Governance
        .route("/governance/proposals", get(explorer::governance_proposals))
        .route("/governance/proposal/{id}", get(explorer::governance_proposal_detail))
        .route("/governance/summary", get(explorer::governance_summary))
        .route("/governance/delegations/{identity}", get(explorer::governance_delegations))
        .route("/governance/params", get(explorer::governance_params))
        .route("/governance/params/history", get(explorer::governance_params_history))
        // §11.18 Slice 3 — ProtocolUpgrade execution outcomes (Slice 2 storage layer)
        .route("/governance/upgrade_outcomes", get(explorer::governance_upgrade_outcomes))
        .route("/governance/upgrade_outcomes/{proposal_id}", get(explorer::governance_upgrade_outcome_detail))
        .route("/limits", get(core::protocol_limits))
        // Consensus
        .route("/consensus/status", get(explorer::consensus_status))
        .route("/consensus/record/{id}", get(explorer::consensus_record_detail))
        .route("/debug/seal/{id}", get(explorer::seal_debug_route))
        // Witness profiles (sybil resistance)
        // Json<WitnessProfileBody> is 4 short strings; no in-handler guard, so cap
        // the extractor at 64 KiB (rpc_body_cap) rather than the 2 MiB default.
        .route("/witness/profile", post(explorer::register_witness_profile).layer(rpc_body_cap()))
        .route("/witness/profiles", get(explorer::list_witness_profiles))
        .route("/witness/correlation", get(explorer::witness_correlation))
        // Witness reputation (economics §11.2)
        .route("/witness/reputation", get(explorer::witness_reputation))
        // Peer reputation
        .route("/peers/reputation", get(explorer::peer_reputation))
        // Disputes (Protocol §11.13)
        .route("/disputes", get(explorer::list_disputes))
        .route("/disputes/{id}", get(explorer::dispute_detail))
        // Fisherman challenges (economics §10.2)
        .route("/challenges", get(explorer::list_challenges))
        .route("/challenges/{id}", get(explorer::challenge_detail))
        // Light client (Protocol §11.3)
        .route("/proofs/{record_id}", get(explorer::merkle_proof))
        .route("/proofs/cross-zone/{record_id}/{target_zone}", get(explorer::cross_zone_proof))
        .route("/zone/{zone}/proof/{record_hash}", get(explorer::zone_merkle_proof))
        .route("/epochs/headers", get(explorer::epoch_headers))
        // Gap 1 light-client shortcut: `/headers/from/{epoch}` returns headers
        // with `epoch_number >= {epoch}`. Optional `?zone=` and `?limit=` query
        // params work identically to `/epochs/headers`.
        .route("/headers/from/{epoch}", get(explorer::headers_from_epoch))
        // ZSP-C zone-scoped record sync: `/records/from/{epoch}?zone=<id>`
        // returns wire records since the start of `(zone, epoch)`. Iterates
        // CF_RECORD_BY_ZONE (Phase B index) so a light node subscribed to one
        // zone doesn't download the other 999,999.
        .route("/records/from/{epoch}", get(explorer::records_from_epoch))
        // Gap 3 super-seal checkpoints: `/checkpoints/latest/{zone}` returns
        // the latest super-seal (O(1) read from EpochState). `/checkpoints/from/{epoch}`
        // returns all super-seals with end_epoch >= epoch (cached CF scan).
        .route("/checkpoints/latest/{zone}", get(explorer::checkpoint_latest))
        .route("/checkpoints/from/{epoch}", get(explorer::checkpoints_from_epoch))
        // Gap 2 cross-zone transfer introspection. Reads from the in-memory
        // `ledger.cross_zone.pending` map — O(pending_count), no CF scan.
        .route("/xzone/stats", get(explorer::xzone_stats))
        .route("/xzone/transfers", get(explorer::xzone_transfers))
        .route("/xzone/transfer/{transfer_id}", get(explorer::xzone_transfer))
        .route("/xzone/bundle/{transfer_id}", get(explorer::xzone_bundle))
        // Gap 4 zone-split/merge TransitionSeal lifecycle: propose, observe, veto.
        // Threshold + dispute-window enforcement lives in `transition_store` and
        // `zone_transition_seal`; handlers translate HTTP ↔ store.
        .route("/transitions", get(transitions::list_transitions))
        .route(
            "/transitions/finalized",
            get(transitions::list_finalized_transitions),
        )
        .route("/transitions/stats", get(transitions::transition_stats))
        // HTTP/PQ ingress parity, Json-extractor class. propose/sig/veto decode a
        // Json<T> with no in-handler size guard — without a per-route cap they fell
        // back to the 2 MiB global, an unauthenticated parse amplifier (propose's
        // Vec<AnchorSig> materializes BEFORE validate_structure caps it at
        // MAX_PROPOSER_SIGS). sig/veto are single-sig → 64 KiB rpc_body_cap();
        // propose bundles up to MAX_PROPOSER_SIGS Dilithium3 sigs (~423 KiB legit
        // worst-case) → the wider transition_propose_body_cap() (512 KiB).
        .route("/transitions/propose", post(transitions::propose_transition).layer(transition_propose_body_cap()))
        .route("/transitions/{id}", get(transitions::fetch_transition))
        .route("/transitions/{id}/sig", post(transitions::submit_sig).layer(rpc_body_cap()))
        .route("/transitions/{id}/veto", post(transitions::submit_veto).layer(rpc_body_cap()))
        .route(
            "/transitions/{id}/resolve/{account_hash}",
            get(transitions::resolve_account),
        )
        // Zone health
        .route("/zones", get(explorer::zone_health))
        // Gap 5: per-zone VRF committee snapshot. Observability-only —
        // not yet enforced at the attestation layer. Two honest nodes
        // on the same epoch must return byte-identical JSON.
        .route("/committees", get(explorer::committees_snapshot))
        // Gap 5 Phase 6a: membership predicate. Advisory only —
        // consensus hot path does not consult this yet.
        .route("/committees/is_member", get(explorer::committees_is_member))
        // Gap 4 routing close-out: resolve a record's naive zone to its
        // current leaf via the live ZoneRegistry. Observability-only —
        // the 80+ callers of `zone_for_record` are NOT yet rewired
        // through this path.
        .route("/routing/resolve", get(explorer::routing_resolve))
        // VRF registry snapshot — per-anchor VRF public keys (Protocol §11.12).
        // Used to diagnose skipped_no_candidates on committee observer and to
        // see whether peer-anchor VRF registration records are cross-registering.
        .route("/vrf/registry", get(explorer::vrf_registry))
        // Identity activity timeline (Protocol §11.23)
        .route("/activity/{identity}", get(explorer::identity_activity))
        // Content versioning (Protocol §11.30)
        .route("/versions/stats", get(explorer::version_stats))
        .route("/versions/{record_id}", get(explorer::version_info))
        .route("/versions/{record_id}/forks", get(explorer::version_forks))
        // ITC causal clocks (Protocol §11.9)
        .route("/itc", get(explorer::itc_status))
        // Rewards
        .route("/rewards", get(explorer::reward_stats))
        // Genesis allocation + bootstrap phase (economics §5.1, §14.2)
        .route("/genesis/allocation", get(ledger::genesis_allocation))
        .route("/bootstrap/status", get(ledger::bootstrap_status))
        // Gossip protocol health
        .route("/gossip", get(core::gossip_health))
        // DAG lifecycle + graph traversal
        .route("/dag/lifecycle", get(explorer::dag_lifecycle))
        .route("/dag/tips", get(explorer::dag_tips))
        .route("/dag/record/{id}/graph", get(explorer::dag_record_graph))
        .route("/dag/search", get(explorer::dag_search))
        .route("/dag/stats", get(explorer::dag_stats))
        // Node diagnostics
        .route("/node/identity", get(core::node_identity))
        .route("/node/config", get(core::node_config))
        // Admin — PQ-Dilithium3 + allowlist. Most handlers any-node (per-node
        // housekeeping); /admin/zone_transition stays genesis-only (cluster
        // policy). See admin.rs module doc for the full posture.
        .route("/admin/snapshot", post(admin::admin_snapshot))
        .route("/admin/tasks", get(admin::admin_tasks))
        .route("/admin/account-smt/orphans", get(admin::admin_account_smt_orphans))
        .route("/admin/account-smt/reconcile-orphans", post(admin::admin_account_smt_reconcile_orphans))
        .route("/admin/export", get(admin::admin_export))
        .route("/admin/purge_peer", post(admin::admin_purge_peer))
        .route("/admin/force_sync", post(admin::admin_force_sync))
        .route("/admin/force_resync_from", post(admin::admin_force_resync_from))
        .route("/admin/snapshot_rebootstrap_from", post(admin::admin_snapshot_rebootstrap_from))
        .route("/admin/reindex_dag", post(admin::admin_reindex_dag))
        .route("/admin/ban_ip", post(admin::admin_ban_ip))
        .route("/admin/unban_ip", post(admin::admin_unban_ip))
        .route("/admin/bans", get(admin::admin_bans))
        .route("/admin/ban_identity", post(admin::admin_ban_identity))
        .route("/admin/unban_identity", post(admin::admin_unban_identity))
        .route("/admin/banned_identities", get(admin::admin_banned_identities))
        .route("/admin/blocklist/add", post(admin::admin_add_blocked_term))
        .route("/admin/blocklist/remove", post(admin::admin_remove_blocked_term))
        .route("/admin/blocklist", get(admin::admin_content_blocklist))
        .route("/admin/gc", get(admin::admin_gc_status).post(admin::admin_gc_trigger))
        .route("/admin/dag_check", get(admin::admin_dag_check))
        .route("/admin/fork_check", get(admin::admin_fork_check).post(admin::admin_fork_heal))
        .route("/admin/revocations", get(admin::admin_revocations))
        .route("/admin/key_rotations", get(admin::admin_key_rotations))
        .route("/admin/witness_liveness", get(admin::admin_witness_liveness))
        .route("/admin/low_stake_buffer", get(admin::admin_low_stake_buffer))
        .route("/admin/pending_ledger", get(admin::admin_pending_ledger))
        .route("/admin/epoch_prune_shadow", get(admin::admin_epoch_prune_shadow))
        .route("/admin/sunset", get(admin::admin_sunset))
        .route("/admin/conservation_check", get(admin::admin_conservation_check))
        .route("/admin/epoch_health", get(admin::admin_epoch_health))
        .route("/admin/audit_log", get(admin::admin_audit_log))
        .route("/admin/retirement_candidates", get(admin::admin_retirement_candidates))
        .route("/admin/resync", post(admin::admin_resync))
        .route("/admin/zone_transition", post(admin::admin_zone_transition))
        .route("/admin/witness/register", post(admin::admin_witness_register))
        .route("/admin/witness/registry", get(admin::admin_witness_registry))
        .route("/admin/onboard_anchor", post(admin::admin_onboard_anchor))
        .route("/admin/zone_autoscale", get(admin::admin_zone_autoscale))
        .route("/admin/zone_subscriptions", get(admin::admin_zone_subscriptions))
        .route("/admin/zones/scope", get(admin::admin_zones_scope))
        .route("/admin/zones/subscribe", post(admin::admin_zones_subscribe))
        .route("/admin/zones/unsubscribe", post(admin::admin_zones_unsubscribe))
        .route("/admin/forensic/slot/{account_hash}/{nonce_hex}", get(admin::admin_forensic_slot))
        .route("/admin/forensic/slot/{account_hash}/{nonce_hex}/evict_unverifiable", post(admin::admin_evict_unverifiable_slot))
        .route("/admin/forensic/record/{record_id}", get(admin::admin_forensic_record))
        .route("/admin/forensic/record/{record_id}/evict_unverifiable", post(admin::admin_evict_unverifiable_record))
        .route("/admin/content_routing", get(admin::admin_content_routing))
        .route("/admin/epoch_snapshots", get(admin::admin_epoch_snapshots))
        .route("/admin/memory", get(admin::admin_memory))
        .route("/admin/rocks/compact_cf", post(admin::admin_rocks_compact_cf))
        // Bootstrap claim (real node peers only — internal credit mechanics)
        // Local RPC — sign + submit with the node's own identity (desktop app)
        // Each carries the tight extractor-level body cap (rpc_body_cap): the
        // body is untyped-Value-decoded pre-auth, so an oversized payload is an
        // unauthenticated decode-amplifier; the per-route DefaultBodyLimit 413s
        // it on actual bytes, closing the chunked/no-Content-Length bypass.
        .route("/bootstrap/claim", post(ledger::bootstrap_claim).layer(rpc_body_cap()))
        .route("/rpc/transfer", post(ledger::rpc_transfer).layer(rpc_body_cap()))
        .route("/rpc/xzone_lock", post(ledger::rpc_xzone_lock).layer(rpc_body_cap()))
        .route("/rpc/xzone_claim", post(ledger::rpc_xzone_claim).layer(rpc_body_cap()))
        .route("/rpc/xzone_abort", post(ledger::rpc_xzone_abort).layer(rpc_body_cap()))
        .route("/rpc/stake", post(ledger::rpc_stake).layer(rpc_body_cap()))
        .route("/rpc/pool_fund", post(ledger::rpc_pool_fund).layer(rpc_body_cap()))
        .route("/rpc/unstake", post(ledger::rpc_unstake).layer(rpc_body_cap()))
        .route("/rpc/stamp", post(ledger::rpc_stamp).layer(rpc_body_cap()))
        .route("/rpc/stamp-private", post(ledger::rpc_stamp_private).layer(rpc_body_cap()))
        // Slot nonce lookup — external CLI/mobile clients use this to build
        // records with a non-colliding slot_key before submitting to /records
        .route("/slot/next_nonce", get(ledger::slot_next_nonce))
        // DHT + Metrics
        .route("/dht/find_node", get(core::dht_find_node))
        .route("/metrics", get(core::metrics))
        // Block explorer UI (embedded HTML — no external dependencies)
        .route("/explorer", get(explorer_page))
        // /exchange orderbook UI removed (not-a-coin pivot) — see comment
        // above exchange_page's former definition. Backend reads stay below.
        // /ws Slice 3c: legacy JSON-over-WebSocket route deleted. All
        // browser traffic rides /pq-ws via ELPQ now.
        // 4E.1 Phase C: WSS-tunneled ELPQ for browser/explorer accounts.
        // Same `pq_router(state)` dispatch as the TCP PQ listener — same
        // node identity, same handlers, different framing. Browsers can't
        // open raw TCP, so this route is the gateway out of HTTPS for
        // every account operation. 4E.5 retires the HTTP routes once
        // accounts have switched.
        .route("/pq-ws", get(super::pq_transport::ws_session::pq_ws_handler));


    // Security headers — applied to all API responses
    let security_headers = tower_http::set_header::SetResponseHeaderLayer::overriding(
        axum::http::HeaderName::from_static("x-content-type-options"),
        axum::http::HeaderValue::from_static("nosniff"),
    );
    let xfo = tower_http::set_header::SetResponseHeaderLayer::overriding(
        axum::http::HeaderName::from_static("x-frame-options"),
        axum::http::HeaderValue::from_static("DENY"),
    );
    let xss = tower_http::set_header::SetResponseHeaderLayer::overriding(
        axum::http::HeaderName::from_static("x-xss-protection"),
        axum::http::HeaderValue::from_static("1; mode=block"),
    );
    let referrer = tower_http::set_header::SetResponseHeaderLayer::overriding(
        axum::http::HeaderName::from_static("referrer-policy"),
        axum::http::HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    let csp = tower_http::set_header::SetResponseHeaderLayer::overriding(
        axum::http::HeaderName::from_static("content-security-policy"),
        axum::http::HeaderValue::from_static(
            "default-src 'self'; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; connect-src 'self' ws: wss:; img-src 'self' data:"
        ),
    );
    let hsts = tower_http::set_header::SetResponseHeaderLayer::overriding(
        axum::http::HeaderName::from_static("strict-transport-security"),
        axum::http::HeaderValue::from_static("max-age=63072000; includeSubDomains"),
    );

    router
        .layer(security_headers)
        .layer(xfo)
        .layer(xss)
        .layer(referrer)
        .layer(csp)
        .layer(hsts)
        .layer(cors)
        .layer(axum::extract::DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
        .layer(middleware::from_fn_with_state(state.clone(), rate_limit_middleware))
        // L1995 Phase 1 — outer-most layer so non-loopback peers are dropped
        // BEFORE rate-limit accounting / latency measurement / body parsing.
        .layer(middleware::from_fn(public_route_gate))
        .with_state(state)
}

/// L1995 Phase 2 — public-facing router with **only** the whitelisted public
/// surface: PQ tunnel (`/pq-ws`), liveness probes (`/ping`, `/health`,
/// `/status`), observability (`/metrics`). /ws Slice 3c retired the legacy
/// `/ws` route.
///
/// Bound to the public `listen_addr` (`0.0.0.0:9473`). The full data plane
/// (`/peers`, `/dag/*`, `/admin/*`, `/rpc/*`, etc.) lives on a separate
/// loopback-only listener at `data_plane_listen_addr` (`127.0.0.1:9472`).
/// Together they satisfy the strict L1995 criterion that `ss -tlnp` reports
/// only the whitelisted surface on public interfaces — every other axum
/// handler is unreachable from outside the box.
///
/// Caddy/nginx reverse-proxies on the same host route `/pq-ws` to the public
/// listener (so browsers can WSS-tunnel ELPQ) and route everything else to
/// the loopback data-plane listener.
///
/// `public_route_gate` is retained as defense-in-depth — even if a future
/// edit accidentally adds a non-whitelisted route to this builder, the gate
/// will 404 it for non-loopback peers.
pub fn public_routes(state: Arc<NodeState>) -> Router {
    use super::routes::{core, explorer, ledger};

    let cors = tower_http::cors::CorsLayer::new()
        .allow_origin(tower_http::cors::Any)
        .allow_methods([axum::http::Method::GET, axum::http::Method::POST, axum::http::Method::OPTIONS])
        .allow_headers(tower_http::cors::Any);

    let router = Router::new()
        .route("/ping", get(core::ping))
        .route("/version", get(core::version))
        .route("/status", get(core::status))
        .route("/health", get(core::health))
        .route("/alive", get(core::alive))
        .route("/metrics", get(core::metrics))
        // /ws Slice 3c: legacy /ws route deleted (see main router note).
        .route("/pq-ws", get(super::pq_transport::ws_session::pq_ws_handler))
        // Gap 1 light-client surface — read-only, idempotent, signed.
        // External accounts running LightClient SDK pull these from this
        // public listener; internally they share the same handler used by
        // the loopback data plane (`compute_account_proof`).
        .route("/proof/account/{identity}", get(explorer::account_proof))
        .route("/headers/from/{epoch}", get(explorer::headers_from_epoch))
        // §11.23 Layer A slice 0: external explorers can resolve a content
        // hash to the full record without first knowing the record id.
        // Read-only, idempotent, O(1) RocksDB point lookup — same posture
        // as `/proof/account` / `/headers`.
        .route("/records/by-hash/{content_hash}", get(explorer::record_by_hash))
        // Audit-3 light-client incremental sync. Returns SignedStateDelta —
        // changed account balances since `?since_epoch=N` baseline plus state
        // root and Dilithium3 sig. Phone-tier accounts pull this rather than
        // re-downloading the full ledger. Same handler as the loopback HTTP
        // route in `routes()` and the PQ-WS `state_delta` verb — byte-identical
        // bodies via the shared `compute_state_delta` helper.
        .route("/snapshot/state-delta", get(super::routes::sync::serve_state_delta))
        // Gap 8: surfaces { sealed, sealed_at, finalized, state, attestations }
        // so phone-tier accounts render the optimistic Sealed badge at ~3s
        // before 2/3 attestation finalization completes. Read-only, idempotent;
        // same handler as the loopback /seal/progress/{id} route in `routes()`.
        .route("/seal/progress/{id}", get(explorer::seal_progress_route))
        // Protocol §11.18 Slice 4 — promote the Slice 3
        // /governance/upgrade_outcomes read-out routes from loopback-only
        // (admin Router::new() at server.rs:9538) to the public surface so
        // browser-resident accounts/explorers can render the post-vote
        // outcome (Adopted/Vetoed + zone-quorum breakdown) without
        // reverse-proxy plumbing or SSH access. Same handler as the
        // loopback Router::new() route — byte-identical bodies. Read-only,
        // idempotent, O(1) RocksDB point lookup, no auth needed. Mutation
        // flows (proposals, votes, finalizations) stay loopback-only and
        // go through POST /submit_record at the consensus surface.
        .route("/governance/upgrade_outcomes", get(explorer::governance_upgrade_outcomes))
        .route("/governance/upgrade_outcomes/{proposal_id}", get(explorer::governance_upgrade_outcome_detail))
        // C4 slice 1: agent-mandate query (the "queryable over time" differentiator
        // vs OTS/sig). Read-only, public — same posture as /proof/account.
        .route("/mandate/{mandate_id}", get(explorer::mandate_detail))
        .route("/mandate/status/{record_id}", get(explorer::mandate_status))
        // C4 slice 4: bounded enumeration of acts performed under a mandate.
        .route("/mandate/{mandate_id}/acts", get(explorer::mandate_acts))
        // Public block-explorer (static/explorer.html) — fusion-audited 2026-06-23
        // (3 Sonnet + 1 Opus panel + Opus verify against source). The HTML page +
        // its read-only, idempotent, bounded data fetches (same disclosure profile
        // as a public ledger). DELIBERATELY EXCLUDED from this public builder (stay
        // loopback-only): /peers (node IP:port topology + per-peer bad-sig
        // diagnostics), bare /balances (bulk all-account+balance enumeration),
        // /witness/profiles (leaks witness IP /24 via the `subnet` field —
        // config.rs:471 documents it as an IP prefix). Those three explorer panels
        // degrade to empty (api() returns null on 404) — acceptable; a node-IP /
        // topology leak is not. Must be paired with the PUBLIC_ROUTE_PREFIXES
        // allowlist entries above or the defense-in-depth gate 404s them.
        .route("/explorer", get(explorer_page))
        .route("/epochs", get(explorer::epoch_status))
        // /epochs/headers is served directly by `explorer::epoch_headers` — the
        // same handler the already-public `/headers/from/{epoch}` light-client
        // route forwards to (headers_from_epoch is a thin wrapper that just
        // pre-fills `since` from the path param), so it carries ZERO new
        // disclosure: both resolve to `compute_epoch_headers`. Documented public via the
        // PUBLIC_ROUTE_PREFIXES `/epochs` entry, but was missing from this router,
        // so the gate cleared it while public_routes() 404'd it off-host — the
        // dual-router drift class (cf. the §11.18 governance + §11.23
        // records/by-hash fixes). Keep both ends in sync.
        .route("/epochs/headers", get(explorer::epoch_headers))
        .route("/consensus/status", get(explorer::consensus_status))
        .route("/dag/stats", get(explorer::dag_stats))
        .route("/dag/tips", get(explorer::dag_tips))
        .route("/transactions/recent", get(ledger::recent_transactions))
        .route("/record/{id}", get(explorer::record_detail))
        .route("/record/{id}/causal-proof", get(explorer::causal_proof))
        .route("/record/{id}/wire", get(explorer::record_wire))
        .route("/account/{identity}", get(explorer::account_detail));
        // /exchange orderbook viewer HTML removed (not-a-coin pivot).

    let security_headers = tower_http::set_header::SetResponseHeaderLayer::overriding(
        axum::http::HeaderName::from_static("x-content-type-options"),
        axum::http::HeaderValue::from_static("nosniff"),
    );
    let xfo = tower_http::set_header::SetResponseHeaderLayer::overriding(
        axum::http::HeaderName::from_static("x-frame-options"),
        axum::http::HeaderValue::from_static("DENY"),
    );
    let xss = tower_http::set_header::SetResponseHeaderLayer::overriding(
        axum::http::HeaderName::from_static("x-xss-protection"),
        axum::http::HeaderValue::from_static("1; mode=block"),
    );
    let referrer = tower_http::set_header::SetResponseHeaderLayer::overriding(
        axum::http::HeaderName::from_static("referrer-policy"),
        axum::http::HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    let hsts = tower_http::set_header::SetResponseHeaderLayer::overriding(
        axum::http::HeaderName::from_static("strict-transport-security"),
        axum::http::HeaderValue::from_static("max-age=63072000; includeSubDomains"),
    );

    router
        .layer(security_headers)
        .layer(xfo)
        .layer(xss)
        .layer(referrer)
        .layer(hsts)
        .layer(cors)
        .layer(axum::extract::DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
        .layer(middleware::from_fn_with_state(state.clone(), rate_limit_middleware))
        .layer(middleware::from_fn(public_route_gate))
        .with_state(state)
}

/// Build the admin-only router for localhost binding.
/// Contains /admin/*, /rpc/*, /exchange/*, /bootstrap/*.
/// In production, bind this to 127.0.0.1 only — never expose to internet.
pub fn admin_routes(state: Arc<NodeState>) -> Router {
    use super::routes::{admin, ledger};

    Router::new()
        // Admin endpoints
        .route("/admin/snapshot", post(admin::admin_snapshot))
        .route("/admin/tasks", get(admin::admin_tasks))
        .route("/admin/account-smt/orphans", get(admin::admin_account_smt_orphans))
        .route("/admin/account-smt/reconcile-orphans", post(admin::admin_account_smt_reconcile_orphans))
        .route("/admin/export", get(admin::admin_export))
        .route("/admin/purge_peer", post(admin::admin_purge_peer))
        .route("/admin/force_sync", post(admin::admin_force_sync))
        .route("/admin/force_resync_from", post(admin::admin_force_resync_from))
        .route("/admin/snapshot_rebootstrap_from", post(admin::admin_snapshot_rebootstrap_from))
        .route("/admin/reindex_dag", post(admin::admin_reindex_dag))
        .route("/admin/ban_ip", post(admin::admin_ban_ip))
        .route("/admin/unban_ip", post(admin::admin_unban_ip))
        .route("/admin/bans", get(admin::admin_bans))
        .route("/admin/ban_identity", post(admin::admin_ban_identity))
        .route("/admin/unban_identity", post(admin::admin_unban_identity))
        .route("/admin/banned_identities", get(admin::admin_banned_identities))
        .route("/admin/blocklist/add", post(admin::admin_add_blocked_term))
        .route("/admin/blocklist/remove", post(admin::admin_remove_blocked_term))
        .route("/admin/blocklist", get(admin::admin_content_blocklist))
        .route("/admin/gc", get(admin::admin_gc_status).post(admin::admin_gc_trigger))
        .route("/admin/dag_check", get(admin::admin_dag_check))
        .route("/admin/fork_check", get(admin::admin_fork_check).post(admin::admin_fork_heal))
        .route("/admin/revocations", get(admin::admin_revocations))
        .route("/admin/key_rotations", get(admin::admin_key_rotations))
        .route("/admin/witness_liveness", get(admin::admin_witness_liveness))
        .route("/admin/low_stake_buffer", get(admin::admin_low_stake_buffer))
        .route("/admin/pending_ledger", get(admin::admin_pending_ledger))
        .route("/admin/epoch_prune_shadow", get(admin::admin_epoch_prune_shadow))
        .route("/admin/sunset", get(admin::admin_sunset))
        .route("/admin/conservation_check", get(admin::admin_conservation_check))
        .route("/admin/epoch_health", get(admin::admin_epoch_health))
        .route("/admin/audit_log", get(admin::admin_audit_log))
        .route("/admin/retirement_candidates", get(admin::admin_retirement_candidates))
        .route("/admin/resync", post(admin::admin_resync))
        .route("/admin/zone_subscriptions", get(admin::admin_zone_subscriptions))
        .route("/admin/zones/scope", get(admin::admin_zones_scope))
        .route("/admin/zones/subscribe", post(admin::admin_zones_subscribe))
        .route("/admin/zones/unsubscribe", post(admin::admin_zones_unsubscribe))
        .route("/admin/forensic/slot/{account_hash}/{nonce_hex}", get(admin::admin_forensic_slot))
        .route("/admin/forensic/slot/{account_hash}/{nonce_hex}/evict_unverifiable", post(admin::admin_evict_unverifiable_slot))
        .route("/admin/forensic/record/{record_id}", get(admin::admin_forensic_record))
        .route("/admin/forensic/record/{record_id}/evict_unverifiable", post(admin::admin_evict_unverifiable_record))
        .route("/admin/content_routing", get(admin::admin_content_routing))
        .route("/admin/epoch_snapshots", get(admin::admin_epoch_snapshots))
        .route("/admin/memory", get(admin::admin_memory))
        .route("/admin/rocks/compact_cf", post(admin::admin_rocks_compact_cf))
        // Parity with the full router's /admin/* set (2026-07-17 audit found
        // these five present there but missing here, contradicting the boot
        // log's "/admin/*" claim for the dedicated listener — genesis-critical
        // zone_transition included). Keep BOTH lists in sync when adding verbs.
        .route("/admin/zone_transition", post(admin::admin_zone_transition))
        .route("/admin/witness/register", post(admin::admin_witness_register))
        .route("/admin/witness/registry", get(admin::admin_witness_registry))
        .route("/admin/onboard_anchor", post(admin::admin_onboard_anchor))
        .route("/admin/zone_autoscale", get(admin::admin_zone_autoscale))
        // RPC — sign + submit with node's own identity. Tight extractor-level
        // body cap per route (rpc_body_cap) — see routes() above.
        .route("/rpc/transfer", post(ledger::rpc_transfer).layer(rpc_body_cap()))
        .route("/rpc/xzone_lock", post(ledger::rpc_xzone_lock).layer(rpc_body_cap()))
        .route("/rpc/xzone_claim", post(ledger::rpc_xzone_claim).layer(rpc_body_cap()))
        .route("/rpc/xzone_abort", post(ledger::rpc_xzone_abort).layer(rpc_body_cap()))
        .route("/rpc/stake", post(ledger::rpc_stake).layer(rpc_body_cap()))
        .route("/rpc/pool_fund", post(ledger::rpc_pool_fund).layer(rpc_body_cap()))
        .route("/rpc/unstake", post(ledger::rpc_unstake).layer(rpc_body_cap()))
        .route("/rpc/stamp", post(ledger::rpc_stamp).layer(rpc_body_cap()))
        .route("/rpc/stamp-private", post(ledger::rpc_stamp_private).layer(rpc_body_cap()))
        // Slot nonce lookup (also exposed on admin router for localhost tooling)
        .route("/slot/next_nonce", get(ledger::slot_next_nonce))
        .route("/bootstrap/claim", post(ledger::bootstrap_claim).layer(rpc_body_cap()))
        .route("/bootstrap/status", get(ledger::bootstrap_status))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
        .with_state(state)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
