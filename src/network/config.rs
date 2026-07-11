//! Node configuration — TOML file with environment variable overrides.

//!
//! Spec references:
//!   @spec Protocol §3.4

use std::path::PathBuf;

use serde::Deserialize;

use crate::errors::{ElaraError, Result};

/// Genesis authority identity hash baked into zero-config defaults.
///
/// EMPTY by default: there is no public testnet authority, so a zero-config
/// boot warns loudly (`validate()`: "ledger validation will reject all ops")
/// instead of silently trusting a key that can never sign. Real deployments
/// set `genesis_authority` explicitly (TOML / env override); dev-net runbook:
/// internal design notes, join path: `docs/JOIN-DEVNET.md`.
/// Populate when a public testnet with live infrastructure exists.
pub const TESTNET_GENESIS_AUTHORITY: &str = "";

/// Compiled-in light-client trust anchors: hex-encoded raw Dilithium3 PUBLIC
/// KEYS the cold-start `light_sync_loop` accepts as super-seal signers without
/// any peer's cooperation — the same role `PINNED_BTC_HEADER_HASHES` and the
/// drand LoE key play in the offline `elara-verify` binary.
///
/// EMPTY today: no public mainnet genesis has been cut, so there is no stable
/// public key to bake in. The current testnet's genesis-authority pubkey is
/// supplied at runtime via `light_client_trust_anchors` / `ELARA_LIGHT_TRUST_ANCHORS`
/// instead (the live local node IS the genesis authority). Populate this with
/// the public-network genesis pubkey when that chain is cut — the
/// `enforce_mainnet_safety` gate refuses to start a mainnet light node while
/// the effective anchor set is empty, so this cannot ship empty on mainnet.
///
/// The effective anchor set used at runtime is the union of this constant and
/// `NodeConfig::light_client_trust_anchors`.
pub const PINNED_GENESIS_AUTHORITY_PUBKEYS: &[&str] = &[];

/// Seed peers baked into zero-config defaults — bare `host:port`, no scheme
/// prefix: `seed_base_url()` always returns `http://...` since the
/// in-process TLS server was removed (PQ-R6 / 4E.6). Public HTTPS, if any,
/// lives behind nginx / caddy.
///
/// EMPTY by default: there are no public testnet endpoints. A zero-config
/// boot warns "no seed_peers configured" rather than dialing dead boxes.
/// Operators set `seed_peers` explicitly; see `docs/JOIN-DEVNET.md`.
pub const TESTNET_SEED_PEERS: &[&str] = &[];

/// Node configuration. Loaded from TOML, overridable via `ELARA_*` env vars.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct NodeConfig {
    /// Listen address for the public HTTP server.
    pub listen_addr: String,
    /// Listen address for an OPTIONAL dedicated admin/RPC listener (localhost
    /// only in production). Admin verbs are never reachable by non-loopback
    /// callers on any listener (`public_route_gate`, and the split-plane public
    /// router carries no admin handlers at all). On-box they ride the full
    /// router — the data-plane listener under the default split plane, or the
    /// main listener in legacy single-listener mode — so this key is only
    /// needed for a separate admin port. (The old "falls back to the main
    /// listen_addr" claim here was false; rehearsal-verified 2026-07-02.)
    pub admin_listen_addr: String,
    /// L1995 Phase 2 — listen address for the **full data-plane router**
    /// (`/peers`, `/balance`, `/dag/*`, `/explorer`, `/admin/*`, `/rpc/*`,
    /// `/exchange/*`, `/account/*`, etc). When non-empty, the public
    /// `listen_addr` listener carries **only** the whitelisted public surface
    /// (`/pq-ws`, `/ws`, `/metrics`, `/health`, `/status`, `/ping`, `/version`)
    /// and the data-plane router is bound here — defaulting to
    /// `127.0.0.1:9472` so the account/SDK API is reachable only via a
    /// loopback proxy (Caddy/nginx) or local CLI tooling. Closes the strict
    /// `ss -tlnp` criterion at L1995 — the public interface only exposes the
    /// PQ tunnel + observability + liveness probes; everything else lives on
    /// loopback. Set to empty to fall back to legacy single-listener mode
    /// (everything on `listen_addr`).
    #[serde(default = "default_data_plane_listen_addr")]
    pub data_plane_listen_addr: String,
    /// Listen address for the post-quantum RPC server (ML-KEM-768 + Dilithium3).
    /// Empty = auto-derive from `listen_addr` by adding `pq_port_offset`
    /// (e.g. `0.0.0.0:9573` when classical is `0.0.0.0:9473`). See
    /// [`NodeConfig::effective_pq_listen_addr`]. AUDIT-10 / PQ-R1: every
    /// node starts a PQ listener by default. Set to `"disabled"` to opt out.
    #[serde(default)]
    pub pq_listen_addr: String,
    /// Offset from a peer's classical port to its PQ port. Defaults to 100
    /// so a peer listening on `host:9473` for HTTP is dialed at `host:9573`
    /// for PQ.
    #[serde(default = "default_pq_port_offset")]
    pub pq_port_offset: u16,
    /// Require PQ transport for all gossip pushes / sync pulls / discovery /
    /// light-client fetches. AUDIT-10 / PQ-R1 / 4E.5: true by default — PQ-only,
    /// no HTTPS fallback. The data plane has had no HTTPS fallback path since
    /// AUDIT-10 Milestone C; the flag is retained as a runtime invariant
    /// rather than a behaviour switch. `elara_https_fallback_total` remains
    /// exported as a permanent canary at 0. Setting `false` is unsupported on
    /// mainnet and only meaningful in adversarial-downgrade tests.
    #[serde(default = "default_require_pq_transport", alias = "prefer_pq_transport")]
    pub require_pq_transport: bool,
    /// AUDIT-10 Milestone D: gate on the public HTTPS data plane. When `true`
    /// (testnet migration default) the existing `0.0.0.0:9473` HTTPS listener
    /// stays bound for backwards compatibility while accounts / SDKs migrate
    /// to PQ. When `false` (mainnet target) the HTTPS listener binds only to
    /// loopback + documented private ranges, and the public data plane is
    /// PQ-only. Mainnet (`network_id = "mainnet"`) refuses to start with this
    /// flag still `true` — see [`NodeConfig::enforce_mainnet_safety`].
    #[serde(default = "default_allow_public_https")]
    pub allow_public_https: bool,
    /// REALMS P1.5 a3: spawn the live drand pulse fetcher
    /// (`network/drand_fetch.rs`) so this node's seals carry a
    /// BLS-signature-bearing not-before pulse. Default `false` — a producer
    /// must never emit the `drand_signature`/`drand_previous_signature`
    /// metadata keys before its whole fleet runs an allowlist-aware binary
    /// (the `super_seal_committee_hash` silent-rejection fork class), so the
    /// flip is an explicit operator/config act, decoupled from binary
    /// rollout. Composed with [`Self::allow_public_https`] at spawn: a
    /// mainnet node (which must boot with that flag `false`) never makes
    /// classical-TLS drand egress — it uses the out-of-process anchor
    /// sidecar (`scripts/elara-epoch-anchor.sh`) instead. Env override:
    /// `ELARA_DRAND_PULSE`. Enable on seal-producing nodes only; followers
    /// would poll relays for pulses they never embed.
    #[serde(default)]
    pub drand_pulse_enabled: bool,
    /// Relay set for the drand fetcher — cross-relay agreement needs ≥2
    /// usable entries. Defaults to four independent LoE mirrors
    /// (`drand_fetch::DEFAULT_RELAYS`). Env override: `ELARA_DRAND_RELAYS`
    /// (comma-separated). URL policy at spawn: `https://host`, or
    /// `http://127.0.0.1` / `http://localhost` for hermetic test mocks.
    #[serde(default = "default_drand_relays")]
    pub drand_relays: Vec<String>,
    /// Path to the identity JSON file.
    pub identity_path: PathBuf,
    /// Operator opt-in (default `false`): refuse to ever persist or load a
    /// *plaintext* node identity. When `true`, `ELARA_IDENTITY_PASSPHRASE` is
    /// mandatory — the node will neither save a freshly generated identity in
    /// plaintext nor boot from an existing plaintext `identity.json`; it fails
    /// fast with a clear error instead. Default `false` because forcing it on
    /// every node would brick no-passphrase unattended restarts — this is a
    /// security knob a mainnet operator turns ON, never a forced default.
    /// Env override: `ELARA_REQUIRE_ENCRYPTED_IDENTITY`.
    pub require_encrypted_identity: bool,
    /// Path to the main SQLite database.
    pub db_path: PathBuf,
    /// Identity hash of the genesis authority (for ledger validation).
    pub genesis_authority: String,
    /// Seed peer addresses (`host:port`).
    pub seed_peers: Vec<String>,
    /// Node type: leaf, relay, witness, archive, anchor, or gateway (Protocol v0.6.2).
    pub node_type: String,
    /// Retention profile: `light`, `full_zone` (default), or `archive`.
    /// Orthogonal to `node_type` — the role says *what* the node does, the
    /// profile says *how much history* it keeps. See `node_profile.rs`.
    #[serde(default = "default_node_profile")]
    pub node_profile: String,
    /// Gossip pull interval in seconds.
    pub gossip_pull_interval_secs: u64,
    /// Enable automatic witnessing of incoming records.
    pub auto_witness: bool,
    /// Base data directory for all node files.
    pub data_dir: PathBuf,
    // 4E.6 (2026-04-27): tls_enabled / tls_cert_path / tls_key_path /
    // tls_ca_path / tls_allow_insecure deleted. The in-process TLS server
    // was already removed in PQ-R6 — every consumer either branched on a
    // false-only path or hardcoded false. Operators who want public HTTPS
    // front the plain listener with nginx/caddy. Existing operator config
    // files retain these fields harmlessly: serde ignores unknown keys.
    /// Max write (POST) requests per IP per minute.
    pub rate_limit_write: u32,
    /// Max read (GET) requests per IP per minute.
    pub rate_limit_read: u32,
    /// PQ-transport per-peer inbound read-admission token-bucket capacity
    /// (burst). The HTTP read surface is rate-limited in axum middleware
    /// (keyed by IP); this is the PQ-surface analog, keyed by the
    /// Dilithium3-bound `peer_identity_hash`. Default 100 — large enough that
    /// a legitimate follower-join (many small snapshot/header pulls) completes
    /// inside the burst and never trips a 429 (the client aborts a bootstrap
    /// on 429). Raise it if a very large initial sync ever throttles.
    pub pq_read_capacity: f64,
    /// PQ read-admission refill rate (tokens/sec). Default 10 = the
    /// `rate_limit_read` 600/min sustained budget, per peer.
    pub pq_read_refill_per_sec: f64,
    /// Periodic ledger snapshot interval in seconds (0 = disabled).
    pub snapshot_interval_secs: u64,
    /// Max relay hops for gossip push (0 = no relay). Default 6.
    pub gossip_max_hops: u8,
    /// Max consecutive heartbeat failures before a peer is pruned (0 = never prune).
    pub max_peer_failures: u32,
    /// PEX (Peer Exchange) interval in seconds (0 = disabled).
    /// NOTE: PEX is not in the protocol spec. Disabled by default.
    /// Kademlia DHT + seed bootstrap provide sufficient discovery.
    pub pex_interval_secs: u64,
    /// Epoch seal interval in seconds (0 = disabled). Default **60 (1 min)**
    /// — gives ~30s P50 finality, sub-minute mainnet target. Protocol §11.12
    /// uses "5-minute epochs" as an illustrative example and states no SLA;
    /// the interval is a tuning parameter, not a safety bound. Hard upper
    /// bound `MAX_EPOCH_SEAL_INTERVAL_SECS = 3600` is governance-validated.
    pub epoch_seal_interval_secs: u64,
    /// Auto-witness check interval in seconds. Default 10.
    pub auto_witness_interval_secs: u64,
    /// Max records to witness per auto-witness cycle. Default 10.
    pub auto_witness_batch_size: usize,
    /// Witness reward amount in base units (10^9/beat) per attestation on settlement. Default 1 beat.
    /// (`_micros` name is legacy; the unit is base units.) Set to 0 to disable auto-rewards.
    pub witness_reward_micros: u64,
    /// Health check interval in seconds (0 = disabled). Default 30.
    pub health_check_interval_secs: u64,
    /// Minimum connected peers before health degrades. Default 1.
    pub health_min_peers: u32,
    /// Max seconds since last record before sync is flagged. Default 300 (5 min). 0 = disabled.
    pub health_max_sync_lag_secs: u64,
    /// Max seconds since the last *successful* pull from a peer before the
    /// `pull-sync` health check flags a follower. Unlike `health_max_sync_lag_secs`
    /// (record-age, ambiguous on an idle testnet so it ships disabled), a caught-up
    /// follower still records a successful 0-record pull every cycle — so this
    /// cleanly separates "idle but syncing" from "can't reach my seed / wire-
    /// incompatible peer". Pure seeds (zero pull attempts) are auto-exempt.
    /// Default 600 (10 min). 0 = disabled.
    pub health_max_pull_staleness_secs: u64,
    /// Garbage collection interval in seconds (0 = disabled). Default 3600 (1 hour).
    pub gc_interval_secs: u64,
    /// Retention period for finalized records in seconds. Default 90 days.
    /// Finalized records older than this are pruned by GC.
    pub record_retention_secs: f64,
    /// Hard cap on total live on-disk bytes across records/attestations/indexes.
    /// When GC observes storage beyond this cap, it proportionally compresses
    /// the retention window so finalized records are pruned faster. 0 = disabled
    /// (time-only retention). Default 200 GB — sized for mainnet FullZone nodes;
    /// operators on resource-constrained / 2GB nodes override via
    /// `ELARA_DISK_CAP_BYTES` (small canary nodes use ~15 GB).
    /// @spec Protocol §11.8 (epoch-based pruning with bounded storage)
    pub disk_cap_bytes: u64,
    /// Filesystem-avail-MB low watermark — `disk_pressure` trips to ON
    /// when actual filesystem available space drops below this threshold.
    /// Default 2048 (2 GB). An earlier 512 MB (hardcoded) value was too
    /// tight to absorb RocksDB compaction churn (a single L1→L2 compaction
    /// can write 256+ MB before the next 60s sample): pressure tripped and
    /// peers paused via the ingest gate, but in-flight compactions still
    /// pushed the daemon to ENOSPC. With 2 GB headroom the gate now fires
    /// WHILE there is still
    /// meaningful runway. Phone-tier nodes (< 4 GB free total) override via
    /// `ELARA_DISK_PRESSURE_AVAIL_LOW_MB`. Set to 0 to disable the avail-MB
    /// trip path entirely (will still trip on `live_bytes > 95% of cap`).
    #[serde(default = "default_disk_pressure_avail_low_mb")]
    pub disk_pressure_avail_low_mb: u64,
    /// Filesystem-avail-MB high watermark — `disk_pressure` clears
    /// (back to OFF) only when avail rises above this threshold AND live <
    /// 80% of cap. Default 4096 (4 GB). An earlier value was 1024 MB. The 2x
    /// hysteresis vs `disk_pressure_avail_low_mb` (2 GB → 4 GB) prevents
    /// rapid toggling under steady ingest. Override via
    /// `ELARA_DISK_PRESSURE_AVAIL_HIGH_MB`. Must be >=
    /// `disk_pressure_avail_low_mb` or hysteresis breaks.
    #[serde(default = "default_disk_pressure_avail_high_mb")]
    pub disk_pressure_avail_high_mb: u64,
    /// Cadence in seconds between `data_dir_size_loop`
    /// passes — the task that walks `data_dir` recursively to populate
    /// `elara_data_dir_total_bytes`. The walk previously ran every 60 s
    /// inside `disk_pressure_loop`; on a node at 510+ SSTs each stat() taking
    /// 10-50 ms under compaction pressure, the walk dominated the tick and
    /// `disk_pressure_samples_total` slipped to ~7 instead of ~11 over 11 min
    /// of uptime. Now the walk runs in a dedicated `spawn_blocking` at a
    /// slower cadence so the pressure loop keeps its strict 60 s rhythm and
    /// `disk_pressure_lowest_avail_mb` stays trustworthy as a between-scrape
    /// canary. Default 300 s (5 min). Override via
    /// `ELARA_DATA_DIR_SIZE_SAMPLE_INTERVAL_SECS`. Set to 0 to disable the
    /// walk entirely (gauge then stays at its last sampled value, or 0 if
    /// never sampled).
    #[serde(default = "default_data_dir_size_sample_interval_secs")]
    pub data_dir_size_sample_interval_secs: u64,
    /// Minimum PoW difficulty required for peer identities (0 = no requirement).
    /// Default 16 (≈65K attempts ≈ 30-60s on a phone).
    pub min_pow_difficulty: u8,
    /// Profile C Gap C: minimum hardware attestation level a parent must
    /// advertise to author `delegation_op = authorize` records.
    /// Default `SECURE_BOOT` (mainnet floor — economics §11.33). Operators
    /// running a testnet without TPM-attested gateways override via
    /// `ELARA_MIN_ATTESTATION_FOR_GATEWAY=NONE`. Comparisons use
    /// `AttestationLevel::rank()`, so the ordering is None(0) < Software(1)
    /// < SecureBoot(2) < HardwareKey(3) < PUF(4).
    #[serde(default = "default_min_attestation_for_gateway")]
    pub min_attestation_for_gateway: crate::identity::AttestationLevel,
    /// Minimum protocol version accepted from peers (0 = accept all).
    /// Records from peers below this version are rejected.
    pub min_protocol_version: u32,
    /// Max record age in seconds (0 = no limit). Default 7 days.
    /// Records older than this generate a warning but are still accepted (offline-first).
    pub max_record_age_secs: f64,
    /// Per-identity propagation rate limit: max records per hour per identity.
    /// Protocol v0.6.2 Section 11.19 specifies 100 records/hr default.
    /// Set to 0 to disable.
    pub propagation_rate_limit_per_hour: u32,
    /// Minimum unique witnesses per zone for coverage (Protocol §7.5). Default 1.
    pub zone_min_witnesses: usize,
    /// Number of consensus zones. Default 0 (consensus-driven auto mode).
    /// Auto mode: starts at 1; zone_count changes ONLY via signed
    /// authority-emitted ZoneTransition records (Gap-4 activity autoscaler),
    /// applied deterministically fleet-wide. Set >0 to pin a fixed start count
    /// (still overridable at runtime by canonical ZoneTransition records).
    /// NOTE: the former peer-count heuristic ("zone_count = peers /
    /// zone_min_witnesses") was removed 2026-06-19 — it forked followers by
    /// deriving a consensus-critical value from local, non-deterministic peer
    /// state. zone_count is network topology, not a local knob.
    pub zone_count: u64,
    /// Gap 4 / ARCH-2: activity-driven zone auto-scaling. Every node runs the
    /// observer tick; `health.rs::run_auto_scale_tick` gates actual split/merge
    /// emission on `identity_hash == genesis_authority`, so non-authority
    /// nodes just log advisory decisions. Default true — mainnet-correct;
    /// operators disable only to freeze zone count during forensic runs.
    #[serde(default = "default_auto_zone_scale")]
    pub auto_zone_scale: bool,
    /// Gap 4: hard cap on autoscaler-driven zone count. Default 1M per the
    /// mainnet scale target. Lower during rollout if you want a tighter
    /// ceiling. Only consulted when `auto_zone_scale` is true.
    #[serde(default = "default_auto_zone_scale_max")]
    pub auto_zone_scale_max: u64,
    /// B8: max concurrent in-flight PQ responder handshakes. Bounds the
    /// `PqServer` accept path so one slow/half-open inbound peer can no longer
    /// stall new-peer admission (the handshake now runs in a detached task,
    /// gated by a `Semaphore(this)`; over-budget connections are shed, not
    /// queued). 256 is the mainnet-correct default — trivial memory/CPU on the
    /// phone-tier floor, ample headroom for a 10K-node join-storm. Lower it on
    /// constrained hardware; raise it for a high-fan-in relay. Min 1.
    #[serde(default = "default_pq_handshake_concurrency")]
    pub pq_handshake_concurrency: u64,
    /// STREAM-F1 defense-in-depth: max concurrent POST-handshake serve
    /// connections on the PQ server. The handshake limiter above releases its
    /// permit BEFORE serving (by design — long-lived request connections must
    /// not consume the handshake budget), and the 60s idle read-deadline in
    /// `serve_connection` bounds how long an IDLE connection lives, not how
    /// MANY live ones a swarm of handshake-completing peers can pin. This
    /// `Semaphore(this)` is the population bound: over-budget connections are
    /// shed right after the handshake (dropped, `pq_serve_shed_total` bumped),
    /// never queued — a queued connection would hold the very fd this exists
    /// to protect. 4096 is the mainnet-correct default: each slot ≈ one fd +
    /// one tokio task (~KBs), 1/16th of the service's LimitNOFILE=65536, and
    /// an order of magnitude above any realistic seed fan-in today — filling
    /// it costs an attacker 4096 real PQ handshakes plus sub-60s keepalive
    /// traffic on every slot. Lower it on constrained hardware; raise it for
    /// a high-fan-in relay with fd headroom. Min 1.
    #[serde(default = "default_pq_serve_concurrency")]
    pub pq_serve_concurrency: u64,
    /// Global concurrency ceiling on HEAVY PQ reads — the verbs whose handler
    /// does chain-scale work inside `spawn_blocking`: a whole-ledger
    /// clone+serialize (snapshot_full, state_delta), an O(active-stakes) JSON
    /// build (stakes), or an O(zone_count) global-root recompute (merkle_root,
    /// snapshot_latest, snapshot_fast_meta). The per-peer read-admission bucket
    /// bounds a single identity's RATE but not the cross-identity aggregate
    /// CONCURRENCY: in the default Tofu realm a handful of zero-cost Sybil
    /// identities, each under its own bucket, can collectively saturate the
    /// tiny (4-16) shared `spawn_blocking` pool and starve consensus ingest
    /// (the documented 51-98s stall). A global `Semaphore(this)` caps how many
    /// heavy reads run at once. `0` = derive `max_blocking_threads / 2` (heavy
    /// reads never take more than half the blocking pool — the other half stays
    /// free for record-ingest + gossip-push). Non-zero = explicit override,
    /// min 1. See `is_heavy_blocking_read` in pq_transport/router.rs.
    #[serde(default = "default_pq_heavy_read_concurrency")]
    pub pq_heavy_read_concurrency: u64,
    /// Bounded wait (ms) for a HEAVY-read concurrency permit before shedding
    /// (429). NOT a bare shed: the PQ client aborts a bootstrap on any 429
    /// (`ensure_ok`), and a legitimate first-join calls snapshot_full/_latest/
    /// _fast_meta (all HEAVY). A short wait lets a join survive transient
    /// contention while a sustained flood still sheds past the timeout. Must
    /// stay well under the client's 30s DEFAULT_CALL_TIMEOUT. Default 3000.
    #[serde(default = "default_pq_heavy_read_wait_ms")]
    pub pq_heavy_read_wait_ms: u64,
    /// Global concurrency cap on inbound HEAVY-VERIFY verbs — the write-side
    /// twin of `pq_heavy_read_concurrency`
    /// (internal design notes). The PQ verbs that do
    /// genuine inline PQC work per message (`receive_attestation` Dilithium3
    /// verify, `witness` verify + sign, `submit_record` Dilithium3 + SPHINCS+)
    /// are multiplexed over one handshake with no inbound rate limit, so a
    /// handshaked peer — or a swarm of zero-cost Open-realm Sybil identities —
    /// can starve the async workers with inline crypto. The crypto now runs in
    /// `spawn_blocking` gated by a global `Semaphore(this)`. UNLIKE the read
    /// gate this NEVER sheds: a 429'd consensus message is permanently lost
    /// (sender treats 429 as success, `seen` dedup blocks re-push), so excess
    /// work WAITS — per-connection dispatch is sequential, so a flooding peer
    /// stalls only itself. `0` = derive `max_blocking_threads − max_blocking/2`
    /// (the half of the pool the read cap leaves free; ≈ CPU count on typical
    /// boxes, so healthy-node throughput is unchanged). Non-zero = explicit
    /// override, min 1. See `is_heavy_verify_method` in pq_transport/router.rs.
    #[serde(default = "default_pq_verify_concurrency")]
    pub pq_verify_concurrency: u64,
    /// Liveness-decay settlement denominator master switch
    /// (internal design notes). Default FALSE: settlement is
    /// bit-identical to pre-liveness builds. Enable only on networks that
    /// must self-heal from permanently-departed stake (env
    /// ELARA_LIVENESS_DECAY=1).
    #[serde(default)]
    pub liveness_decay_enabled: bool,
    /// Trailing attestation window (epochs) for counting a staker live.
    /// Default 720 (~24 h @ 120 s epochs) — see `default_liveness_window_epochs`
    /// for the fork-vs-stall rationale (shorter forks on partition-heal; longer
    /// stalls on permanent death). Must exceed the longest benign offline period.
    #[serde(default = "default_liveness_window_epochs")]
    pub liveness_window_epochs: u64,
    /// Floor divisor: decayed denominator never drops below base/divisor.
    #[serde(default = "default_liveness_floor_divisor")]
    pub liveness_floor_divisor: u64,
    /// Gap 5: how many epochs a `zone_subscription` record is valid for
    /// before the witness must re-publish. Default 100 (roughly 3.3 hours
    /// at the mainnet 120s epoch). Nodes re-emit within
    /// `zone_subscription_refresh_margin` epochs of expiry.
    #[serde(default = "default_zone_subscription_validity_epochs")]
    pub zone_subscription_validity_epochs: u64,
    /// Gap 5: republish our `zone_subscription` when it's this many epochs
    /// from expiring. Default 20.
    #[serde(default = "default_zone_subscription_refresh_margin")]
    pub zone_subscription_refresh_margin: u64,
    /// Gap 6: peer-count threshold above which originator gossip uses
    /// content-routed DHT placement instead of sqrt(n) flood. Default 100.
    /// Below this, every network is treated as small enough for flood.
    #[serde(default = "default_content_routing_threshold")]
    pub content_routing_threshold: usize,
    /// Gap 6: replication factor K — number of DHT-closest responsible peers
    /// an originator pushes a new record to when content routing is active.
    /// Default 5. Stays compatible with 6-node testnet by being clamped to
    /// `min(K, eligible_peers)`.
    #[serde(default = "default_content_routing_k")]
    pub content_routing_k: usize,
    /// Allow epoch seals to take the K-DHT
    /// content-routing path instead of always flooding. Ledger + governance
    /// ops still flood unconditionally — they are low-rate, safety-critical,
    /// and the verifiable-replication invariant for DHT routing is overkill
    /// for ~10s of ops/day fleet-wide.
    ///
    /// Default `true` (flipped 2026-04-30) — all dependent slices have
    /// landed: slice 1 (`bf3a408`) split is_global_op into bypass/flood
    /// roles, slice 2 (`7786931`) added the R≥3 floor invariant with
    /// flood-fallback, slice 3a (`67e72d7`) wired the bounded
    /// pending-replication queue + observability, slice 3b (`e9d4934`)
    /// activated the periodic reconciler that probes target persistence
    /// and re-pushes under-replicated seals. With slices 1+2+3 wired,
    /// the comment's pre-flip criterion ("flip once R≥3 replication
    /// invariant + on-demand reconciliation are wired") is met.
    ///
    /// Behavioral note for small fleets: K-DHT routing only kicks in
    /// when peer count ≥ `content_routing_threshold` (default 100), so
    /// fleets with < 100 peers (today's testnet) flood seals regardless
    /// of this flag. The reconciler loop is also no-op when the flag
    /// is off OR the queue is empty, so flipping is safe at any scale.
    /// Ledger + governance ops always flood — they are low-rate and
    /// safety-critical, and the verifiable-replication invariant for
    /// DHT routing is overkill for ~10s of ops/day fleet-wide.
    #[serde(default = "default_seal_dht_routing_enabled")]
    pub seal_dht_routing_enabled: bool,
    /// Minimum replication factor R for any K-DHT-routed
    /// gossip push. Until the originator can name at least R distinct DHT-
    /// closest peers (post zone/reachability filtering) the K-DHT path is
    /// abandoned and the push falls back to sqrt(n) flood — preserving
    /// availability on small networks or when DHT membership is sparse.
    ///
    /// Default 3 — verifiable replication (Merkle-of-seal-replicas) ensures
    /// each seal has at least R=3 independent copies.
    /// Lower (e.g. 2) trades availability for bandwidth on tightly-coupled
    /// fleets; higher tightens the invariant at the cost of more frequent
    /// flood-fallbacks. The value also bounds slice 3's peer-side ack
    /// reconciliation: under-replicated seals trigger a re-push.
    #[serde(default = "default_seal_dht_replication_floor")]
    pub seal_dht_replication_floor: usize,
    /// Gap 6.4 slice 3a: maximum entries in the pending seal-replication
    /// reconciliation queue. Bounded so a flood of seal traffic cannot
    /// blow node memory; oldest entries evict on overflow and bump
    /// `gossip_seal_replication_overflow_total` so the operator can detect
    /// reconciler-starvation. Default 1000 — at testnet seal rates (≪10/s)
    /// this gives ~100s of reconciliation horizon; at mainnet rates raise
    /// proportionally OR shorten the slice 3b reconciler interval (which
    /// will be a separate config field once it lands).
    ///
    /// Memory cost: each `PendingSealReplication` is roughly 80 bytes +
    /// `targets.len() * (32 byte hash + Vec overhead)`. At cap=1000 with
    /// K=5 targets each, ≤ 1MB.
    #[serde(default = "default_seal_dht_replication_pending_max")]
    pub seal_dht_replication_pending_max: usize,
    /// Gap 6.4 slice 3b: how often the seal-replication reconciler tick fires.
    /// Each tick drains entries whose age ≥ `seal_dht_ack_timeout_secs` from
    /// the head of `pending_seal_replications`, probes each tracked target
    /// for actual seal persistence, and re-pushes if the realized replication
    /// factor is below `seal_dht_replication_floor`. Default 30s — fast enough
    /// that under-replication is healed in well under a minute, slow enough
    /// that a few hundred entries per tick is bounded work even at mainnet
    /// rates. Operators tune down on small fleets, up on large ones.
    #[serde(default = "default_seal_dht_reconcile_interval_secs")]
    pub seal_dht_reconcile_interval_secs: u64,
    /// Gap 6.4 slice 3b: minimum entry age before the reconciler probes its
    /// targets. Gives the originating push enough time to land at the K-DHT
    /// peers under normal latency before we declare under-replication and
    /// re-push. Default 60s; should be larger than P99 push latency on the
    /// fleet. Too low → false-positive re-pushes wasting bandwidth. Too high
    /// → under-replicated seals stay vulnerable longer.
    #[serde(default = "default_seal_dht_ack_timeout_secs")]
    pub seal_dht_ack_timeout_secs: u64,
    /// Gap 6.4 slice 3b: per-target probe RPC timeout in milliseconds. Each
    /// reconciler probe issues a `records_exist` PQ verb at this deadline;
    /// timeouts count as misses (peer is unreachable → seal not present from
    /// our perspective). Default 2000ms balances the slow-tail latency on
    /// loaded peers against keeping the reconciler tick bounded. Sum of all
    /// probes within a tick ≤ probe_timeout × num_entries (parallel fan-out
    /// per entry, sequential entries).
    #[serde(default = "default_seal_dht_probe_timeout_ms")]
    pub seal_dht_probe_timeout_ms: u64,
    /// Gap 6.4 slice 3b: maximum number of reconciler-driven re-push attempts
    /// per pending entry before it is dropped from the queue with a
    /// `gossip_seal_replication_floor_violation_total` increment. Prevents an
    /// unreachable seal-id from spinning forever. Default 3 — operator can
    /// raise on flaky networks, lower on tight bandwidth budgets. Re-pushes
    /// are still subject to the K-DHT floor invariant: if the topology can't
    /// supply R fresh targets, the entry counts a violation immediately.
    #[serde(default = "default_seal_dht_max_repush_retries")]
    pub seal_dht_max_repush_retries: u8,
    /// Gap 7: how often (in epoch ticks) archive/anchor nodes emit a
    /// signed, epoch-indexed state snapshot to `{data_dir}/snapshots/`.
    /// Default 10 (≈ 20 min at the mainnet 120s epoch). 0 disables archival
    /// snapshots — non-archive nodes leave this at 0.
    #[serde(default = "default_archive_snapshot_every_n_epochs")]
    pub archive_snapshot_every_n_epochs: u64,
    /// Gap 7: how many historical epoch snapshots archive nodes retain on
    /// disk. Default 20. Bounds disk footprint at
    /// `archive_snapshot_retention × snapshot_size`. Older files are pruned
    /// after each new snapshot is written.
    #[serde(default = "default_archive_snapshot_retention")]
    pub archive_snapshot_retention: usize,
    /// Evidence submission window for disputes in seconds (Protocol §11.13). Default 7 days.
    pub dispute_evidence_window_secs: f64,
    /// Maximum concurrent WebSocket connections (0 = disabled). Default 100.
    pub ws_max_connections: u32,
    /// WebSocket heartbeat ping interval in seconds. Default 30.
    pub ws_heartbeat_secs: u64,
    /// Bearer token required for admin endpoints. Empty = reject all remote admin requests.
    /// Set via config file or ELARA_ADMIN_TOKEN env var.
    /// Generate with: openssl rand -hex 32
    pub admin_token: String,
    /// Trusted reverse proxy IPs. When set, X-Real-IP header is only trusted if the
    /// request comes through one of these proxies. When empty (default), X-Real-IP
    /// is ignored entirely to prevent spoofing. Example: ["127.0.0.1", "10.0.0.1"]
    pub trusted_proxy_ips: Vec<String>,
    /// Fixed genesis timestamp (Unix epoch seconds). All nodes must agree on this value
    /// for deterministic genesis. If 0 or unset, uses current system time (legacy behavior).
    /// Set via config file or ELARA_GENESIS_TIMESTAMP env var.
    #[serde(default)]
    pub genesis_timestamp: f64,
    /// VRF public key hex for the epoch sealer (genesis authority).
    /// All nodes use this to verify VRF proofs in epoch seals.
    /// Set via config file or ELARA_VRF_PUBLIC_KEY env var.
    /// Empty = VRF verification disabled (legacy mode).
    #[serde(default)]
    pub vrf_public_key: String,
    /// Path to VRF secret key file. Anchor nodes auto-generate if missing.
    /// Set via ELARA_VRF_KEY env var. Default: "vrf_key.bin" (resolved to data_dir).
    pub vrf_key_path: PathBuf,
    /// Enable mDNS LAN discovery (Protocol §11.14 Layer C).
    /// Announces this node on the local network and discovers peers automatically.
    /// Default: true. Set to false on VPS nodes where LAN discovery is pointless.
    #[serde(default = "default_true")]
    pub mdns_enabled: bool,

    /// Light mode: create Profile B records even with a Profile A identity.
    /// Strips SPHINCS+ public key and signature from outgoing records, reducing
    /// wire size from ~41KB to ~5KB (8x reduction). The identity still holds
    /// SPHINCS+ keys for verifying incoming Profile A records.
    /// Default: false. Enable on resource-constrained nodes.
    #[serde(default)]
    pub light_mode: bool,

    /// Zone paths this light node should follow. Empty = follow every zone the
    /// seed serves (original behaviour). Non-empty restricts sync to exactly
    /// those zones — the client never requests or stores headers for any other
    /// zone, keeping `LightState.headers` O(epochs_per_followed_zone) at 1M-zone
    /// mainnet scale. Only meaningful when `node_profile = "light"` or
    /// `light_mode = true`; silently ignored on full nodes.
    ///
    /// Env: `ELARA_LIGHT_CLIENT_ZONES=medical/eu,finance/global` (comma-separated).
    #[serde(default)]
    pub light_client_zones: Vec<String>,

    /// Light-client cold-start trust anchors: hex-encoded raw Dilithium3
    /// PUBLIC KEYS (not the `genesis_authority` identity hash) that the
    /// `light_sync_loop` accepts as super-seal signers. The effective anchor
    /// set is the union of these and the compiled-in
    /// [`PINNED_GENESIS_AUTHORITY_PUBKEYS`].
    ///
    /// When the effective set is non-empty, cold-start checkpoints are verified
    /// against it (`verify_seal_record_against_anchor`) and earn `AnchorPinned`
    /// trust; a super-seal signed by any non-anchor key is dropped. When EMPTY,
    /// cold-start degrades to `Reference` grade (single-seed trust) — usable for
    /// dev/test against ephemeral-genesis networks, but `enforce_mainnet_safety`
    /// refuses to start a `node_profile = "light"` node on `network_id =
    /// "mainnet"` with an empty set.
    ///
    /// This must enumerate EVERY trusted sealer pubkey, not just genesis: at
    /// multi-validator scale non-genesis VRF anchors also sign super-seals
    /// (`is_seal_eligible`), so a genesis-only set would reject their valid
    /// seals. Today (single seal-eligible authority) the set is just the
    /// genesis pubkey.
    ///
    /// Env: `ELARA_LIGHT_TRUST_ANCHORS=<hex1>,<hex2>` (comma-separated).
    #[serde(default)]
    pub light_client_trust_anchors: Vec<String>,

    /// Adversarial/sim hook (Stage 3c.3): aggregator ranks this node must
    /// NOT propose for. Empty in production — never loaded from TOML
    /// (`#[serde(skip)]`). When set to e.g. `{0}` the node behaves as a
    /// byzantine rank-0 that silently refuses to seal, which is exactly
    /// the liveness-failure scenario that Stage 3c.2 punishes. Set from
    /// `elara_simulate` scenarios; fleet configs leave it empty.
    #[serde(skip)]
    pub muted_aggregator_ranks: std::collections::HashSet<u8>,

    /// Sim/test override for per-zone `base_timeout_ms`. When `Some`, all
    /// zones use this exact value instead of the RTT-derived formula used
    /// in production (`max(2·rtt_p95, 5s)` clamped to [1s, 10min]).
    ///
    /// Used by adversarial scenarios that need to observe the MAX_VIEW_DEPTH
    /// stuck threshold (127·base) within a test-sized duration: with
    /// `Some(100)` the full rank ladder exhausts in 12.7s instead of 635s.
    ///
    /// For proposer/verifier agreement, every node in the simulation must
    /// set the *same* override. `#[serde(skip)]` prevents accidental
    /// leakage into real TOML configs.
    #[serde(skip)]
    pub test_base_timeout_ms_override: Option<u64>,

    /// Witness profile: organizational affiliation (e.g., "navigatorbuilds", "acme-corp").
    /// Used for diversity-weighted consensus — unregistered witnesses get a 0.8 correlation
    /// penalty. Set this so your node gets proper independence credit.
    #[serde(default)]
    pub witness_organization: String,
    /// Witness profile: IP subnet prefix (e.g., "203.0.113", "198.51.100").
    /// Witnesses on the same subnet are correlated (β=0.3 penalty).
    #[serde(default)]
    pub witness_subnet: String,
    /// Witness profile: geographic zone (e.g., "us-east", "eu-central", "ap-northeast").
    /// Currently γ=0.0 (no penalty), but registered for future use.
    #[serde(default)]
    pub witness_geo_zone: String,

    /// Network identifier for isolating testnet from mainnet.
    /// Nodes reject gossip records and peer connections from different networks.
    /// Values: "testnet" (default), "mainnet", or any custom string.
    /// Set via config file or ELARA_NETWORK_ID env var.
    #[serde(default = "default_network_id")]
    pub network_id: String,

    /// REALMS P1 — self-declared realm posture (docs/REALMS-SELF-ASSEMBLY.md
    /// §"Admission model"). Realm confers ZERO public-mesh authority: it only
    /// changes which peers THIS node admits/dials, never consensus weight or
    /// trust. `Open` (default) = today's behavior, zero runtime delta.
    /// `Federated` = the PQ handshake additionally requires a Dilithium3
    /// membership cert signed by `root_pk` (slice b). `Sovereign` = self-exile:
    /// mDNS beaconing / seed dialing / outbound PEX off, unknown inbound
    /// denied (slice c). TOML: `network_realm = { mode = "federated",
    /// root_pk = "<hex>" }` or a `[network_realm]` table. Env: `ELARA_REALM`
    /// (+ `ELARA_REALM_ROOT_PK` when federated).
    #[serde(default)]
    pub network_realm: NetworkRealm,

    /// REALMS P1 slice (b3) — path to this node's own federation membership
    /// cert (JSON, produced by the federation operator via
    /// `RealmMembershipCert::issue`). Presented when a dialed peer's realm
    /// challenges us for admission. Empty (default) = no cert: dials into
    /// federated realms are rejected with `cert_missing`. Relative paths
    /// resolve against `data_dir`. Env: `ELARA_REALM_CERT`. Only meaningful
    /// alongside `network_realm = federated` — a federated node without a
    /// cert can gate inbound but cannot dial fellow members.
    #[serde(default)]
    pub realm_membership_cert_path: PathBuf,

    /// GENESIS VALIDATOR BOOTSTRAP (internal design notes) —
    /// the initial validator set, marked staked directly in the genesis
    /// ledger baseline (carved from the genesis authority's allocation).
    /// Solves the clean-slate finality deadlock: without it, the first
    /// stake op can never finalize (a creator cannot self-finalize and no
    /// other staker exists). GENESIS PARAMETER: must be byte-identical on
    /// every node, like `genesis_authority` — divergence forks the ledger
    /// baseline. Empty (default) = pre-feature behavior, zero delta.
    /// TOML: `[[genesis_validators]]` tables with `identity` + `stake_micros`.
    /// Env: `ELARA_GENESIS_VALIDATORS="<id64>:<stake>,<id64>:<stake>"`.
    #[serde(default)]
    pub genesis_validators: Vec<crate::accounting::types::GenesisValidator>,

    /// Address to advertise to peers (host:port or just host).
    /// Use this when the node is behind NAT and the TCP source IP isn't reachable.
    /// Example: "100.64.0.1:9473" (Tailscale CGNAT IP), "mynode.example.com:9473".
    /// Empty = use TCP source IP (default, works when not behind NAT).
    #[serde(default)]
    pub advertise_addr: String,

    /// Whether this node is behind NAT (not directly reachable from the internet).
    /// When true:
    /// - Peers won't try to push records/attestations TO this node (would fail)
    /// - Peers won't try to pull FROM this node (would fail)
    /// - This node pulls MORE frequently to compensate (15s instead of 30s)
    /// - This node pushes its own records/attestations aggressively (outbound works)
    ///
    /// Auto-detected if not set: node pings itself via advertised address at startup.
    /// Set via config file or ELARA_NAT=true env var.
    #[serde(default)]
    pub behind_nat: bool,

    /// DNS hostnames to resolve for seed peer discovery.
    /// Each hostname is resolved to A/AAAA records at startup, and the resulting
    /// IPs are added as seed peers on the default port (9473).
    /// This allows updating seed peers via DNS without code changes.
    /// Set via config file or ELARA_DNS_SEEDS env var (comma-separated).
    /// Default: EMPTY (disabled). The former default `seeds.elara.network`
    /// was removed 2026-07-02: the parent domain is registered to a third
    /// party, so shipping it would delegate default peer discovery to a
    /// hostname outside the project's control. Operators set their own.
    #[serde(default = "default_dns_seeds")]
    pub dns_seeds: Vec<String>,

    /// Port used when building peer URLs from DNS-resolved addresses.
    /// Default: 9473.
    #[serde(default = "default_dns_seed_port")]
    pub dns_seed_port: u16,

    /// PQ-R2: identity hashes of additional snapshot signers we trust
    /// beyond `genesis_authority`. Snapshot ingest (`sync.rs`) verifies the
    /// signer's identity is in `{genesis_authority} ∪ trusted_snapshot_signers`
    /// before accepting the bootstrap state. Without this gate, the existing
    /// signature check accepts any well-formed snapshot from any peer — a
    /// peer running its own ledger can still produce a valid Dilithium3
    /// signature on it, and onboarding nodes would adopt the forged state.
    /// Default empty: only the genesis authority is trusted, which is the
    /// correct policy for testnet bootstrap.
    #[serde(default)]
    pub trusted_snapshot_signers: Vec<String>,

    /// Gap 2.1 Phase 2b.3 — fallback weight assigned to a finality
    /// candidate that has a captured PK but no bonded beat stake.
    /// Only consulted when `finality_committee_includes_witness_registry=true`.
    /// Default 1 (the smallest non-zero weight) so anchors with real
    /// stake still dominate Efraimidis–Spirakis selection but
    /// witness-tier nodes are not entirely excluded.
    #[serde(default = "default_finality_known_pk_weight")]
    pub finality_committee_known_pk_weight: u64,

    /// Gap 2.1 Phase 2b.3 Slice 3 — when true, expand the
    /// finality-committee candidate pool with bonded witnesses from
    /// `CF_WITNESS_REGISTRY` for the target zone. The CF is populated by
    /// gossip-replicated `WitnessRegister` records, so every node
    /// converges on the same per-zone witness set and computes the
    /// same committee snapshot.
    ///
    /// History: a Slice 1 variant (retired 2026-05-16) iterated the
    /// locally-divergent `CF_IDENTITIES` and caused fleet-wide
    /// committee_snapshot mismatch in the 2026-04-25 soak — replaced by
    /// this gossip-replicated path.
    ///
    /// Default OFF until enough bonded witnesses register on the
    /// fleet — flipping it on with an empty registry would shrink
    /// candidate pools to just the VRF anchors and is a no-op.
    #[serde(default)]
    pub finality_committee_includes_witness_registry: bool,

    /// Gap 5 Phase 6b — FIFO cap on the per-zone committee resolver
    /// cache (`(zone_path, epoch, k, candidates_fingerprint) →
    /// committee`). Sized for a single-node working set; raise on
    /// nodes that serve many zones (light-client RPCs, explorer
    /// front-ends). Default 4096 covers ~512 zones × 8-epoch horizon
    /// at default k.
    #[serde(default = "default_committee_resolver_cache_size")]
    pub committee_resolver_cache_size: usize,

    /// Gap 5 Phase 6b kill-switch. When `true`, the consensus hot
    /// path consults the [`super::zone_committee::ZoneCommitteeResolver`]
    /// for committee membership at attestation gating; when `false`
    /// (default) the resolver is observability-only and the global
    /// VRF path remains the source of truth. Phase 6c flips this
    /// after the resolver soaks under live load. The flag is wired
    /// even before the consensus call site swap so a single config
    /// roll lifts the whole fleet at once.
    #[serde(default)]
    pub enforce_per_zone_vrf: bool,

    /// Gap 5 Phase 6b second-slice selection-algorithm flag.
    /// When `true`, the
    /// consensus hot path at `epoch.rs:select_epoch_committee_scoped_indexed`
    /// is replaced by the unified
    /// [`super::zone_committee::select_committee_v2`] — VRF-entropy +
    /// `ELARA_ZONE_COMMITTEE_V1` domain tag + linear-stake
    /// Efraimidis–Spirakis draw + sort-by-identity output + bootstrap
    /// fallback. When `false` (default), the existing global-VRF +
    /// sqrt(stake) algorithm at `consensus.rs:select_epoch_committee_scoped_indexed`
    /// remains the source of truth, and v2 is dead code in production.
    ///
    /// Distinct from `enforce_per_zone_vrf`: that flag gates
    /// **attestation membership** enforcement via the resolver; this
    /// flag gates **committee selection** at the source. A node may
    /// run with `enforce_per_zone_vrf=true` and `use_committee_v2=false`
    /// (gate the resolver-derived committee, but compute it with the
    /// legacy algorithm) or vice versa during a staged rollout.
    ///
    /// Rollout: see internal design notes. The
    /// single-node-first chaos experiment expects an off-by-one
    /// fleet (5 nodes v1, 1 node v2) to fail to reach quorum on the
    /// dissenting node's epoch — this is intentional, exercises the
    /// divergence-detection path, and proves v1↔v2 are non-bit-identical.
    #[serde(default)]
    pub use_committee_v2: bool,

    /// Enforce the canonical v2 ledger content-hash preimage at ingest
    /// (audit 2026-07-06): reject any beat_op record whose `content_hash`
    /// does not commit to its signed metadata + creator + nonce.
    ///
    /// DEFAULT FALSE until the re-genesis: catch-up/fetch/gossip re-run the
    /// full ingest gates on historical records, and pre-v2 history (old
    /// `"beat:<op>:<amount>"` preimages) would wedge a syncing follower.
    /// Flip ON as part of the supervised re-genesis ceremony (fresh chain —
    /// every record is v2 from block 0), then it MUST stay on: without
    /// enforcement the builder-side fix is cosmetic against an adversary
    /// who hand-sets `content_hash` (equal-hash equivocation pairs, by-hash
    /// index poisoning).
    #[serde(default)]
    pub enforce_ledger_content_hash_v2: bool,

    /// Enable the hourly uptime-vesting loop (`uptime_vesting_loop`).
    ///
    /// DEFAULT FALSE — and must stay false until the uptime-vesting feature is
    /// activated with a deterministic, record-driven design. The loop mutates
    /// `account.uptime_secs` (which is part of the account-SMT leaf,
    /// `account_merkle.rs`) out-of-band on this node's local wall clock, with no
    /// record. That is a non-deterministic mutation of a sealed consensus field:
    /// a follower replaying the chain via records cannot reproduce it, so the
    /// account-SMT root diverges across nodes (a silent fork). The feature is
    /// otherwise inert (`vested_locked == 0` for all production accounts), so the
    /// loop has zero functional value today and only carries this fork risk.
    /// See internal design notes.
    #[serde(default)]
    pub uptime_vesting_enabled: bool,

    /// Phase 6d readiness gate threshold. The flip from Phase 6c
    /// soak (`enforce_per_zone_vrf=false`) to Phase 6d enforcement requires
    /// `vrf_registry_identities >= phase6d_min_committee_size`. Default 7
    /// matches `DEFAULT_COMMITTEE_SIZE` and the BFT-style "5+2" sizing
    /// (5 for f=1 safety, 7 for f=2 headroom). Mainnet operators leave
    /// this at 7. Testnet clusters smaller than 7 must lower it (e.g. 3
    /// for a 6-node testnet) or `phase6d_ready` is unreachable forever.
    ///
    /// Also drives the bootstrap fallback in
    /// `enforce_seal_attestation_committee_membership` — when the
    /// VRF-registered+staked candidate population is below this number,
    /// the per-zone committee gate short-circuits to `true` (degraded
    /// enforcement; `committee_skipped_below_k_total` increments).
    /// Lowering this knob therefore has TWO effects: (1) Phase 6d can
    /// flip earlier, (2) the bootstrap fallback stops firing earlier.
    /// Both are intended on small clusters.
    ///
    /// Env override: `ELARA_PHASE6D_MIN_COMMITTEE_SIZE`. Must be > 0.
    /// Setting to 0 is rejected at config-load time (a 0-threshold gate
    /// is a no-op that gives false-ready signals).
    #[serde(default = "default_phase6d_min_committee_size")]
    pub phase6d_min_committee_size: usize,

    /// Hot-tier capacity for
    /// `FinalizedIndex`. `0` (default) defers to the profile-based
    /// floor in `FinalizedIndex::with_profile`:
    ///   - Light:     1_000   (≈150 KB — phone-tier safe)
    ///   - FullZone: 10_000   (≈1.5 MB — operator default, legacy cap)
    ///   - Archive: 1_000_000 (≈150 MB — answers `is_finalized()` from RAM at scale)
    ///
    /// Set non-zero to override (e.g. 16 GB archives wanting 4M; ultra-
    /// constrained full-zones dropping to 5K). Operators can monitor
    /// the resident set via `elara_finalized_hot_size /
    /// elara_finalized_hot_capacity` — saturation at 1.0 means the LRU
    /// is rotating, not OOM.
    #[serde(default)]
    pub finalized_hot_capacity: usize,

    /// Identity Partitioning Phase B: LRU eviction cap on
    /// `CF_IDENTITIES_USER`. When the user-tier CF exceeds this count,
    /// the periodic evict tick drops oldest entries down to the cap.
    /// 0 = unbounded (no eviction). Recommended values:
    ///   - light profile: 10_000  (≈20 MB cap)
    ///   - full_zone:    100_000  (≈200 MB cap)
    ///   - archive:           0   (unbounded — keep everything)
    ///
    /// Default 100_000 — mainnet-correct for a full_zone node. Light
    /// profiles and constrained operators override via TOML.
    #[serde(default = "default_identity_user_cache_max")]
    pub identity_user_cache_max: usize,

    /// Identity Partitioning Phase B: how often the eviction tick runs.
    /// Default 60s. The tick is cheap when the CF is below the cap
    /// (single point-read on the count) so this is safe to keep low.
    #[serde(default = "default_identity_user_evict_interval_secs")]
    pub identity_user_evict_interval_secs: u64,

    /// Identity Partitioning Phase B: hard cap on evictions per tick.
    /// Bounds the WriteBatch size and keeps a single tick from holding
    /// the DB lock too long when a backlog forms (e.g. cap was lowered
    /// or many writes landed since last tick). Default 5_000.
    #[serde(default = "default_identity_user_evict_max_per_tick")]
    pub identity_user_evict_max_per_tick: usize,

    /// DAM-3D Phase A: gate on cross-zone parents at ingest. When `true`
    /// (testnet default) records whose `parents[i]` resolves to a zone other
    /// than the record's own zone (and not an ancestor of it) are accepted
    /// with a soft-warn counter bump — keeping legacy traffic flowing during
    /// the structural-zone-axis rollout. When `false` (mainnet target) those
    /// records are hard-rejected at `/records` with a clear error and the
    /// `elara_cross_zone_parent_rejected_total` counter ticks. Genesis
    /// records (empty parents) and global ops (epoch seals, beat mints,
    /// governance — `EPOCH_OP_KEY` / `beat_op` metadata) bypass the gate
    /// regardless. See internal design notes §3 Gap A.
    #[serde(default = "default_allow_cross_zone_parents")]
    pub allow_cross_zone_parents: bool,

    /// PARTITION-MERGE Phase B: when `true`, register_seal performs
    /// weight-based reconciliation on same-(zone, epoch) collisions —
    /// the seal with greater accumulated attestation weight (per
    /// `AWCConsensus::attestation_weight_for_seal`) wins, with the loser
    /// recorded in the bounded `orphan_siblings` ring (records covered
    /// by the orphan stay in the DAG, append-only; only the seal-level
    /// mapping is overwritten). Lex-min `record_hash` remains the
    /// tiebreak when weights are equal — preserving Stage 3b.5/3b.6
    /// dual-proposer determinism on a freshly-received seal pair before
    /// any attestations have arrived. Default `false`: pre-rollout we
    /// run the substrate (accessor + ring + metrics) silently for one
    /// soak cycle to confirm fleet-wide cleanliness before flipping the
    /// reconciler on. See internal design notes §3 Gap B.
    ///
    /// LOAD-BEARING PIN (audit 2026-07-01, internal design notes):
    /// this flag does **NOT** fix the crash-before-broadcast phantom-tip freeze.
    /// It is reserved for the real partition-merge (§3.3.3) use case only. The
    /// phantom fix was audit-rejected here as insufficient — weight-reconcile
    /// heals the tip *hash* but not the stranded honest `E+1` (which
    /// `is_forged_sequential_seal` drops without re-offer, `ingest.rs`), and the
    /// boot path (`rebuild_latest_epoch_from_cf_epochs`) re-installs the phantom
    /// via lex-min anyway. The real fix is E+1 successor re-admission (its own
    /// audit-first cycle). Do not flip this to "close the phantom".
    #[serde(default)]
    pub partition_merge_weight_reconcile: bool,

    /// Zone-Parallel state core (Tier 2 stability item, master task list
    /// line 1479): number of worker tasks the state core spawns. Each
    /// worker owns a private (priority, normal) channel pair; records
    /// are routed to a worker by hash of `record.record_zone().path()`
    /// so a single zone always lands on the same worker (preserving
    /// per-zone ordering). `replace_ledger` always pins to worker 0;
    /// `shutdown` broadcasts to all workers.
    ///
    /// Default `1` — Phase 2 ships the routing substrate but keeps
    /// behavior identical to single-worker until operators flip this
    /// per-node. Capped at `MAX_STATE_CORE_WORKERS` (64) by the spawn
    /// helper. Mainnet target: scale workers to ~CPUs/2 once the
    /// per-zone NodeState contention measurements clear (Phase 3).
    #[serde(default = "default_state_core_worker_count")]
    pub state_core_worker_count: u8,

    /// Epoch-based pruning gate (Protocol §11.8). When enabled,
    /// finalized non-seal records below their per-zone super-seal floor
    /// timestamp are eligible for GC even if the time-based retention
    /// window hasn't elapsed. The seal's Merkle root + record hashes
    /// preserve verifiability without the body bytes. Default: enabled
    /// (mainnet target). Operators set `false` to revert to time-based
    /// retention only — useful for archive nodes that need to keep raw
    /// record bodies on disk for historical query (also auto-disabled
    /// when `node_profile == "archive"`).
    #[serde(default = "default_epoch_pruning_enabled")]
    pub epoch_pruning_enabled: bool,
}

/// REALMS P1 — network realm posture. Self-declared and enforced from the
/// inside: each member node verifies peers against its own realm root; no
/// global tier registry exists. This is safe ONLY while realm grants no
/// public-mesh advantage (no extra consensus weight / trust) — never cross
/// that line. See docs/REALMS-SELF-ASSEMBLY.md §"Admission model".
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "lowercase")]
pub enum NetworkRealm {
    /// Public mesh: admit any peer that passes the standard PQ handshake.
    #[default]
    Open,
    /// Members-only: peers must additionally present a membership cert
    /// signed by the federation root (`root_pk` = hex Dilithium3 public
    /// key). "Who decides" = the federation operator, for their own door
    /// only; founding a federation is permissionless.
    Federated { root_pk: String },
    /// Isolated: discovery surfaces off, unknown inbound denied. Declaring
    /// sovereignty is self-exile from the public mesh — it affects nobody
    /// else, which is why self-declaration needs no gatekeeper.
    Sovereign,
}

impl NetworkRealm {
    /// Stable lowercase label for logs / metrics / status surfaces.
    pub fn label(&self) -> &'static str {
        match self {
            NetworkRealm::Open => "open",
            NetworkRealm::Federated { .. } => "federated",
            NetworkRealm::Sovereign => "sovereign",
        }
    }

    /// Slice (c) consumers gate mDNS announce, seed dialing and outbound
    /// PEX on this. Open + Federated keep discovery; Sovereign drops it.
    pub fn discovery_enabled(&self) -> bool {
        !matches!(self, NetworkRealm::Sovereign)
    }

    /// Federation root public key (hex Dilithium3) when federated.
    pub fn federated_root_pk(&self) -> Option<&str> {
        match self {
            NetworkRealm::Federated { root_pk } => Some(root_pk.as_str()),
            _ => None,
        }
    }

    /// Env-side constructor for `ELARA_REALM` (+ `ELARA_REALM_ROOT_PK`).
    /// `None` on an unrecognized mode string — the caller keeps the prior
    /// realm and `validate()` surfaces the ignored override, so a typo'd
    /// override never silently flips a sovereign node open.
    fn from_env_parts(mode: &str, root_pk: Option<String>) -> Option<Self> {
        match mode.trim().to_ascii_lowercase().as_str() {
            "open" => Some(NetworkRealm::Open),
            "sovereign" => Some(NetworkRealm::Sovereign),
            // Missing root key still constructs (empty pk) — validate()
            // then warns loudly instead of the node silently staying Open.
            "federated" => Some(NetworkRealm::Federated {
                root_pk: root_pk.unwrap_or_default(),
            }),
            _ => None,
        }
    }
}

fn default_true() -> bool { true }
fn default_node_profile() -> String { "full_zone".to_string() }
fn default_network_id() -> String { "testnet".to_string() }
fn default_dns_seeds() -> Vec<String> { vec![] }
fn default_dns_seed_port() -> u16 { 9473 }
fn default_pq_port_offset() -> u16 { 100 }
fn default_require_pq_transport() -> bool { true }
/// AUDIT-10 Milestone D: testnet migration default keeps the public HTTPS
/// listener available so legacy accounts / monitoring still connect during the
/// PQ rollout. Mainnet operators must override this to `false`; the startup
/// gate in [`NodeConfig::enforce_mainnet_safety`] aborts boot otherwise.
fn default_allow_public_https() -> bool { true }

/// REALMS P1.5 a3: the four independent LoE relay mirrors the drand fetcher
/// cross-checks against (any two alive satisfy the agreement rule).
fn default_drand_relays() -> Vec<String> {
    crate::network::drand_fetch::DEFAULT_RELAYS
        .iter()
        .map(|s| s.to_string())
        .collect()
}

/// DAM-3D Phase A default: testnet stays in soft-warn mode so legacy traffic
/// (recs with hash-derived sibling parents from before the structural-zone
/// gate landed) still ingests while operators bake. Mainnet flips to `false`
/// — `validate()` warns when the flag is on and `network_id == "mainnet"`.
fn default_allow_cross_zone_parents() -> bool { true }

/// L1995 Phase 2 default: data plane on loopback. Operators wanting the
/// legacy single-listener behavior (everything on `listen_addr`) set this to
/// the empty string explicitly.
fn default_data_plane_listen_addr() -> String { "127.0.0.1:9472".to_string() }

/// PQ-R1: given `listen_addr` like `"0.0.0.0:9473"` (or an IPv6 literal), add
/// `offset` to the port component and return the resulting string. Returns
/// `None` when the address does not parse as `host:port` (IPv4 or `[IPv6]`)
/// OR when the port + offset would overflow `u16`.
fn derive_pq_addr(listen_addr: &str, offset: u16) -> Option<String> {
    let s = listen_addr.trim();
    if s.is_empty() {
        return None;
    }
    // `[::1]:9473` form: split on the last `]:`.
    let (host, port_str) = if let Some(rest) = s.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        let port = after.strip_prefix(':')?;
        (format!("[{host}]"), port.to_string())
    } else {
        let (h, p) = s.rsplit_once(':')?;
        (h.to_string(), p.to_string())
    };
    let port: u16 = port_str.parse().ok()?;
    let new_port = port.checked_add(offset)?;
    Some(format!("{host}:{new_port}"))
}
fn default_auto_zone_scale() -> bool { true }
fn default_auto_zone_scale_max() -> u64 { 1_000_000 }
fn default_pq_handshake_concurrency() -> u64 { 256 }
fn default_pq_serve_concurrency() -> u64 { 4096 }
/// `0` = derive from `max_blocking_threads / 2` at NetworkState construction.
fn default_pq_heavy_read_concurrency() -> u64 { 0 }
fn default_pq_heavy_read_wait_ms() -> u64 { 3000 }
fn default_pq_verify_concurrency() -> u64 { 0 }

/// Tokio blocking-pool size as a function of CPU count — the single source of
/// truth shared by the runtime builder (`bin/elara_node.rs`) and the HEAVY-read
/// concurrency-cap derivation (`network/state.rs`). Kept here (lib) so both the
/// bin and the lib compute it identically and cannot drift. Rationale for the
/// steps: 4 on 1-core (RocksDB puts are <20ms, minimal contention), 8 on 2-core
/// (3 caused 52s queue stalls on constrained boxes), 16 on 4+ core (headroom
/// for concurrent background tasks). A too-small pool starves record-ingest
/// behind gossip's 2 simultaneous `spawn_blocking` calls.
pub fn max_blocking_threads_for(cpus: usize) -> usize {
    if cpus <= 1 { 4 } else if cpus <= 2 { 8 } else { 16 }
}
// ~24 h at the 120 s low-load epoch cadence. The window MUST exceed the
// longest *benign* offline period (an overnight/weekend laptop sleep, 8–16 h)
// or an honest sleeper ages out of every side's settlement denominator. That
// is not merely cosmetic: a *shorter* window ages absent stake out of each
// partition side faster, letting a side self-settle on its collapsed
// denominator sooner → divergent finalization → fork on heal. A *longer*
// window keeps absent stake in the denominator longer, so the minority side
// STALLS (clean heal) instead of forking — at the cost of ~window_epochs of
// stalled finality after a genuine permanent departure. Favour stall over
// fork; operators on reliable infra can tune this down. (Prior default 64 ≈
// 2.1 h was a testing-grade value that aged out overnight sleepers.)
fn default_liveness_window_epochs() -> u64 { 720 }
fn default_liveness_floor_divisor() -> u64 { 10 }
fn default_zone_subscription_validity_epochs() -> u64 { 100 }
fn default_zone_subscription_refresh_margin() -> u64 { 20 }
fn default_content_routing_threshold() -> usize { 100 }
fn default_content_routing_k() -> usize { 5 }
fn default_seal_dht_routing_enabled() -> bool { true }
fn default_seal_dht_replication_floor() -> usize { 3 }
fn default_seal_dht_replication_pending_max() -> usize { 1_000 }
fn default_seal_dht_reconcile_interval_secs() -> u64 { 30 }
fn default_seal_dht_ack_timeout_secs() -> u64 { 60 }
fn default_seal_dht_probe_timeout_ms() -> u64 { 2_000 }
fn default_seal_dht_max_repush_retries() -> u8 { 3 }
fn default_identity_user_cache_max() -> usize { 100_000 }
fn default_identity_user_evict_interval_secs() -> u64 { 60 }
fn default_identity_user_evict_max_per_tick() -> usize { 5_000 }
fn default_state_core_worker_count() -> u8 { 1 }
fn default_epoch_pruning_enabled() -> bool { true }
fn default_archive_snapshot_every_n_epochs() -> u64 {
    crate::network::snapshot::ARCHIVE_SNAPSHOT_EVERY_N_EPOCHS_DEFAULT
}
fn default_archive_snapshot_retention() -> usize { 20 }
fn default_finality_known_pk_weight() -> u64 { 1 }
// 2 GB low / 4 GB high — RocksDB compaction-aware. See
// `disk_pressure_avail_low_mb` / `..._high_mb` doc comments for sizing rationale.
fn default_disk_pressure_avail_low_mb() -> u64 { 2048 }
fn default_disk_pressure_avail_high_mb() -> u64 { 4096 }
// 5 min default cadence for the data_dir recursive size walk.
// The walk is O(SST count) stat() syscalls; at 10-50 ms per stat() on a
// stressed I/O subsystem this can run 30+ s per pass on a busy node, so
// the cadence sits well above that floor to avoid back-to-back walks
// dominating their own task. Override via
// `ELARA_DATA_DIR_SIZE_SAMPLE_INTERVAL_SECS` for benchmarks. Operators on
// archive nodes with 10 K+ SSTs may want to raise to 900-1800 s.
fn default_data_dir_size_sample_interval_secs() -> u64 { 300 }
fn default_committee_resolver_cache_size() -> usize {
    crate::network::zone_committee::DEFAULT_RESOLVER_CACHE_SIZE
}
fn default_phase6d_min_committee_size() -> usize {
    crate::network::zone_committee::DEFAULT_COMMITTEE_SIZE
}
fn default_min_attestation_for_gateway() -> crate::identity::AttestationLevel {
    crate::accounting::delegation::MIN_ATTESTATION_FOR_GATEWAY
}

/// Default data directory: ~/.elara on Unix, %APPDATA%/elara on Windows.
/// Falls back to current directory if home can't be determined.
fn default_data_dir() -> PathBuf {
    // Check ELARA_DATA_DIR first (already handled by env overrides, but
    // this ensures the default() itself uses the right path).
    if let Ok(dir) = std::env::var("ELARA_DATA_DIR") {
        return PathBuf::from(dir);
    }
    #[cfg(unix)]
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".elara");
    }
    #[cfg(windows)]
    if let Ok(appdata) = std::env::var("APPDATA") {
        return PathBuf::from(appdata).join("elara");
    }
    PathBuf::from(".")
}

/// Current protocol version. Incremented on breaking wire-format changes.
///
/// Versioning rules:
/// - Breaking record format changes: bump major (1→2)
/// - New optional metadata fields: no bump needed
/// - New endpoints: no bump needed
///
/// During rolling upgrades, nodes advertise their version via
/// `x-elara-protocol-version` header. Peers can reject records
/// from incompatible versions via `min_protocol_version` config.
pub const PROTOCOL_VERSION: u32 = 1;

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:9473".to_string(),
            admin_listen_addr: String::new(), // Empty = admin endpoints DISABLED (they mount only on this dedicated listener; set e.g. "127.0.0.1:9472")
            data_plane_listen_addr: default_data_plane_listen_addr(), // L1995 Phase 2 — data plane on loopback by default.
            pq_listen_addr: String::new(), // Empty = auto-derive from listen_addr + pq_port_offset (PQ-R1).
            pq_port_offset: 100,
            require_pq_transport: true, // PQ-R1 / 4E.5: PQ-only data plane.
            allow_public_https: true, // AUDIT-10 Milestone D: testnet migration default.
            drand_pulse_enabled: false, // REALMS P1.5 a3: explicit operator opt-in (fork-class rollout discipline).
            drand_relays: default_drand_relays(),
            identity_path: PathBuf::from("identity.json"),
            require_encrypted_identity: false,
            db_path: PathBuf::from("elara.db"),
            genesis_authority: TESTNET_GENESIS_AUTHORITY.to_string(),
            seed_peers: TESTNET_SEED_PEERS.iter().map(|s| s.to_string()).collect(),
            node_type: "witness".to_string(),
            node_profile: default_node_profile(),
            gossip_pull_interval_secs: 30,
            auto_witness: true,
            data_dir: default_data_dir(),
            // 4E.6: classical TLS fields removed. Node-to-node traffic is
            // authenticated/encrypted at the PQ transport layer (ML-KEM-768
            // handshake + Dilithium3 TOFU); the legacy HTTP listener stays
            // plain for account compat and is fronted by nginx/caddy when
            // public HTTPS is required.
            rate_limit_write: 120,
            rate_limit_read: 600,
            pq_read_capacity: 100.0,
            pq_read_refill_per_sec: 10.0,
            snapshot_interval_secs: 300,
            gossip_max_hops: 6,
            max_peer_failures: 10,
            pex_interval_secs: 0, // disabled — not in protocol spec
            epoch_seal_interval_secs: 60,
            auto_witness_interval_secs: 60,
            auto_witness_batch_size: 50,
            witness_reward_micros: 1_000_000_000, // 1 beat (base units, 10^9/beat)
            health_check_interval_secs: 30,
            health_min_peers: 1,
            health_max_sync_lag_secs: 0, // 0 = disabled. Quiet testnet = normal, not a health issue.
            health_max_pull_staleness_secs: 600, // 10 min. ON by default — a follower that can't pull is a real fault; an idle follower still records 0-record pull successes, so no false positive.
            gc_interval_secs: 300,
            record_retention_secs: 7.0 * 24.0 * 3600.0, // 7 days
            disk_cap_bytes: 200 * 1024 * 1024 * 1024, // 200 GB FullZone default
            disk_pressure_avail_low_mb: default_disk_pressure_avail_low_mb(),
            disk_pressure_avail_high_mb: default_disk_pressure_avail_high_mb(),
            data_dir_size_sample_interval_secs: default_data_dir_size_sample_interval_secs(),
            min_pow_difficulty: 20, // Must match identity::DEFAULT_POW_DIFFICULTY (20 bits)
            min_attestation_for_gateway: crate::accounting::delegation::MIN_ATTESTATION_FOR_GATEWAY,
            min_protocol_version: 0,
            max_record_age_secs: 7.0 * 24.0 * 3600.0, // 7 days
            propagation_rate_limit_per_hour: 100, // Protocol v0.6.2 Section 11.19
            zone_min_witnesses: 1,
            zone_count: 0, // auto mode: boots at 1, tracks the signed ZoneTransition chain (NOT peer count — that heuristic was removed 2026-06-19; see field doc)
            auto_zone_scale: default_auto_zone_scale(),
            auto_zone_scale_max: default_auto_zone_scale_max(),
            pq_handshake_concurrency: default_pq_handshake_concurrency(),
            pq_serve_concurrency: default_pq_serve_concurrency(),
            pq_heavy_read_concurrency: default_pq_heavy_read_concurrency(),
            pq_heavy_read_wait_ms: default_pq_heavy_read_wait_ms(),
            pq_verify_concurrency: default_pq_verify_concurrency(),
            liveness_decay_enabled: false,
            liveness_window_epochs: default_liveness_window_epochs(),
            liveness_floor_divisor: default_liveness_floor_divisor(),
            zone_subscription_validity_epochs: default_zone_subscription_validity_epochs(),
            zone_subscription_refresh_margin: default_zone_subscription_refresh_margin(),
            content_routing_threshold: default_content_routing_threshold(),
            content_routing_k: default_content_routing_k(),
            seal_dht_routing_enabled: default_seal_dht_routing_enabled(),
            seal_dht_replication_floor: default_seal_dht_replication_floor(),
            seal_dht_replication_pending_max: default_seal_dht_replication_pending_max(),
            seal_dht_reconcile_interval_secs: default_seal_dht_reconcile_interval_secs(),
            seal_dht_ack_timeout_secs: default_seal_dht_ack_timeout_secs(),
            seal_dht_probe_timeout_ms: default_seal_dht_probe_timeout_ms(),
            seal_dht_max_repush_retries: default_seal_dht_max_repush_retries(),
            archive_snapshot_every_n_epochs: default_archive_snapshot_every_n_epochs(),
            archive_snapshot_retention: default_archive_snapshot_retention(),
            dispute_evidence_window_secs: 7.0 * 24.0 * 3600.0, // 7 days
            ws_max_connections: 100,
            ws_heartbeat_secs: 30,
            admin_token: String::new(),
            trusted_proxy_ips: Vec::new(),
            genesis_timestamp: 0.0, // 0 = use system time (legacy)
            vrf_public_key: String::new(),
            vrf_key_path: PathBuf::from("vrf_key.bin"),
            mdns_enabled: true,
            witness_organization: String::new(),
            witness_subnet: String::new(),
            witness_geo_zone: String::new(),
            network_id: default_network_id(),
            network_realm: NetworkRealm::default(),
            realm_membership_cert_path: PathBuf::new(),
            genesis_validators: Vec::new(),
            advertise_addr: String::new(),
            behind_nat: false,
            dns_seeds: default_dns_seeds(),
            dns_seed_port: default_dns_seed_port(),
            light_mode: false,
            light_client_zones: Vec::new(),
            light_client_trust_anchors: Vec::new(),
            muted_aggregator_ranks: std::collections::HashSet::new(),
            test_base_timeout_ms_override: None,
            trusted_snapshot_signers: Vec::new(),
            finality_committee_known_pk_weight: default_finality_known_pk_weight(),
            finality_committee_includes_witness_registry: false,
            committee_resolver_cache_size: default_committee_resolver_cache_size(),
            enforce_per_zone_vrf: false,
            use_committee_v2: false,
            enforce_ledger_content_hash_v2: false,
            uptime_vesting_enabled: false,
            phase6d_min_committee_size: default_phase6d_min_committee_size(),
            finalized_hot_capacity: 0,
            identity_user_cache_max: default_identity_user_cache_max(),
            identity_user_evict_interval_secs: default_identity_user_evict_interval_secs(),
            identity_user_evict_max_per_tick: default_identity_user_evict_max_per_tick(),
            allow_cross_zone_parents: default_allow_cross_zone_parents(),
            partition_merge_weight_reconcile: false,
            state_core_worker_count: default_state_core_worker_count(),
            epoch_pruning_enabled: default_epoch_pruning_enabled(),
        }
    }
}

impl NodeConfig {
    /// PQ-R1: resolve the PQ listener bind address.
    ///
    /// - If `pq_listen_addr` is `"disabled"` (case-insensitive), return `None`
    ///   → caller should skip starting the PQ listener.
    /// - If `pq_listen_addr` is non-empty (and not the opt-out string), return
    ///   it verbatim.
    /// - Otherwise auto-derive `<host>:<classical_port + pq_port_offset>` from
    ///   `listen_addr` so every node serves PQ by default.
    pub fn effective_pq_listen_addr(&self) -> Option<String> {
        let raw = self.pq_listen_addr.trim();
        if raw.eq_ignore_ascii_case("disabled") {
            return None;
        }
        if !raw.is_empty() {
            return Some(raw.to_string());
        }
        derive_pq_addr(&self.listen_addr, self.pq_port_offset)
    }

    /// AUDIT-9 Milestone B: produce the witness profile this node should
    /// advertise to peers, or `None` if the operator hasn't configured one.
    ///
    /// Mirrors the rule in `elara_node.rs` that decides whether to emit
    /// the DAG registration record: `organization` is the discriminator.
    /// A peer that returns `None` from this getter is announcing "I have
    /// no profile" — the caller should log and move on, not penalize it.
    pub fn effective_witness_profile(&self) -> Option<crate::network::consensus::WitnessProfile> {
        if self.witness_organization.is_empty() {
            return None;
        }
        Some(crate::network::consensus::WitnessProfile {
            organization: self.witness_organization.clone(),
            subnet: self.witness_subnet.clone(),
            geo_zone: self.witness_geo_zone.clone(),
        })
    }

    /// Load config from a TOML file, then apply env var overrides.
    pub fn load(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| ElaraError::Config(format!("failed to read {path}: {e}")))?;
        let mut config: NodeConfig = toml::from_str(&content)
            .map_err(|e| ElaraError::Config(format!("failed to parse config: {e}")))?;
        config.apply_env_overrides();
        config.resolve_paths();
        Ok(config)
    }

    /// Create default config with env var overrides only.
    pub fn from_defaults() -> Self {
        let mut config = Self::default();
        config.apply_env_overrides();
        config.resolve_paths();
        config
    }

    /// Apply `ELARA_*` environment variable overrides.
    fn apply_env_overrides(&mut self) {
        if let Ok(v) = std::env::var("ELARA_LISTEN") {
            self.listen_addr = v;
        }
        if let Ok(v) = std::env::var("ELARA_ADMIN_LISTEN") {
            self.admin_listen_addr = v;
        }
        if let Ok(v) = std::env::var("ELARA_DATA_PLANE_LISTEN") {
            // L1995 Phase 2 override. Empty string forces the legacy
            // single-listener mode (data plane stays on `listen_addr`).
            self.data_plane_listen_addr = v;
        }
        if let Ok(v) = std::env::var("ELARA_PQ_LISTEN") {
            self.pq_listen_addr = v;
        }
        if let Ok(v) = std::env::var("ELARA_PQ_PORT_OFFSET") {
            if let Ok(n) = v.parse::<u16>() {
                self.pq_port_offset = n;
            }
        }
        // 4E.5 flag-day: env name is `ELARA_REQUIRE_PQ`. Legacy
        // `ELARA_PREFER_PQ` still reads in case any test harness or operator
        // env is mid-migration; remove on the next major.
        if let Ok(v) = std::env::var("ELARA_REQUIRE_PQ").or_else(|_| std::env::var("ELARA_PREFER_PQ")) {
            self.require_pq_transport = matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on");
        }
        if let Ok(v) = std::env::var("ELARA_ALLOW_PUBLIC_HTTPS") {
            // AUDIT-10 Milestone D: explicit env override. Mainnet operators
            // set this to "0"/"false" to bind the HTTPS listener loopback-only.
            self.allow_public_https = matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on");
        }
        if let Ok(v) = std::env::var("ELARA_DRAND_PULSE") {
            // REALMS P1.5 a3: opt-in live drand pulse fetcher (seal producers).
            self.drand_pulse_enabled = matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on");
        }
        if let Ok(v) = std::env::var("ELARA_DRAND_RELAYS") {
            // Comma-separated relay override; empty entries dropped. URL
            // policy is enforced at fetcher spawn, not here.
            let relays: Vec<String> = v
                .split(',')
                .map(|s| s.trim().trim_end_matches('/').to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if !relays.is_empty() {
                self.drand_relays = relays;
            }
        }
        if let Ok(v) = std::env::var("ELARA_ALLOW_CROSS_ZONE_PARENTS") {
            // DAM-3D Phase A: explicit env override. Mainnet operators set
            // this to "0"/"false" to hard-reject cross-zone parents at /records.
            self.allow_cross_zone_parents = matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on");
        }
        if let Ok(v) = std::env::var("ELARA_PARTITION_MERGE_WEIGHT_RECONCILE") {
            // PARTITION-MERGE Phase B: enable weight-based same-epoch
            // reconciliation in register_seal. Default off pre-rollout;
            // operators flip on once Slice 1+2 substrate is verified clean
            // fleet-wide (orphan_seals_total stays at 0 with flag off).
            self.partition_merge_weight_reconcile = matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on");
        }
        if let Ok(v) = std::env::var("ELARA_IDENTITY") {
            self.identity_path = PathBuf::from(v);
        }
        if let Ok(v) = std::env::var("ELARA_REQUIRE_ENCRYPTED_IDENTITY") {
            // Opt-in hard gate — refuse to persist/load a plaintext identity.
            // Operators set "1"/"true" to make ELARA_IDENTITY_PASSPHRASE mandatory.
            self.require_encrypted_identity = matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on");
        }
        if let Ok(v) = std::env::var("ELARA_DB") {
            self.db_path = PathBuf::from(v);
        }
        if let Ok(v) = std::env::var("ELARA_GENESIS") {
            self.genesis_authority = v;
        }
        if let Ok(v) = std::env::var("ELARA_NODE_TYPE") {
            self.node_type = v;
        }
        if let Ok(v) = std::env::var("ELARA_NODE_PROFILE") {
            self.node_profile = v;
        }
        if let Ok(v) = std::env::var("ELARA_DATA_DIR") {
            self.data_dir = PathBuf::from(v);
        }
        if let Ok(v) = std::env::var("ELARA_SEEDS") {
            self.seed_peers = v
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
        if let Ok(v) = std::env::var("ELARA_LIGHT_CLIENT_ZONES") {
            self.light_client_zones = v
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
        if let Ok(v) = std::env::var("ELARA_LIGHT_TRUST_ANCHORS") {
            self.light_client_trust_anchors = v
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
        if let Ok(v) = std::env::var("ELARA_AUTO_WITNESS") {
            self.auto_witness = v == "1" || v.to_lowercase() == "true";
        }
        // 4E.6: ELARA_TLS_* env vars deleted — the in-process TLS server
        // was removed in PQ-R6 and the config fields are gone. If an
        // operator's systemd unit still sets ELARA_TLS_*, the env var is
        // silently ignored (no behavioural change vs. the old code path,
        // which also never bound a TLS listener).
        if let Ok(v) = std::env::var("ELARA_GOSSIP_INTERVAL") {
            if let Ok(n) = v.parse() {
                self.gossip_pull_interval_secs = n;
            }
        }
        if let Ok(v) = std::env::var("ELARA_RATE_LIMIT_WRITE") {
            if let Ok(n) = v.parse() {
                self.rate_limit_write = n;
            }
        }
        if let Ok(v) = std::env::var("ELARA_RATE_LIMIT_READ") {
            if let Ok(n) = v.parse() {
                self.rate_limit_read = n;
            }
        }
        if let Ok(v) = std::env::var("ELARA_SNAPSHOT_INTERVAL") {
            if let Ok(n) = v.parse() {
                self.snapshot_interval_secs = n;
            }
        }
        if let Ok(v) = std::env::var("ELARA_GOSSIP_MAX_HOPS") {
            if let Ok(n) = v.parse() {
                self.gossip_max_hops = n;
            }
        }
        if let Ok(v) = std::env::var("ELARA_MAX_PEER_FAILURES") {
            if let Ok(n) = v.parse() {
                self.max_peer_failures = n;
            }
        }
        if let Ok(v) = std::env::var("ELARA_PEX_INTERVAL") {
            if let Ok(n) = v.parse() {
                self.pex_interval_secs = n;
            }
        }
        if let Ok(v) = std::env::var("ELARA_EPOCH_INTERVAL") {
            if let Ok(n) = v.parse() {
                self.epoch_seal_interval_secs = n;
            }
        }
        if let Ok(v) = std::env::var("ELARA_AUTO_WITNESS_INTERVAL") {
            if let Ok(n) = v.parse() {
                self.auto_witness_interval_secs = n;
            }
        }
        if let Ok(v) = std::env::var("ELARA_AUTO_WITNESS_BATCH") {
            if let Ok(n) = v.parse() {
                self.auto_witness_batch_size = n;
            }
        }
        if let Ok(v) = std::env::var("ELARA_WITNESS_REWARD") {
            if let Ok(n) = v.parse() {
                self.witness_reward_micros = n;
            }
        }
        if let Ok(v) = std::env::var("ELARA_HEALTH_INTERVAL") {
            if let Ok(n) = v.parse() {
                self.health_check_interval_secs = n;
            }
        }
        if let Ok(v) = std::env::var("ELARA_HEALTH_MIN_PEERS") {
            if let Ok(n) = v.parse() {
                self.health_min_peers = n;
            }
        }
        if let Ok(v) = std::env::var("ELARA_HEALTH_MAX_SYNC_LAG") {
            if let Ok(n) = v.parse() {
                self.health_max_sync_lag_secs = n;
            }
        }
        if let Ok(v) = std::env::var("ELARA_HEALTH_MAX_PULL_STALENESS") {
            if let Ok(n) = v.parse() {
                self.health_max_pull_staleness_secs = n;
            }
        }
        if let Ok(v) = std::env::var("ELARA_GC_INTERVAL") {
            if let Ok(n) = v.parse() {
                self.gc_interval_secs = n;
            }
        }
        if let Ok(v) = std::env::var("ELARA_RECORD_RETENTION") {
            if let Ok(n) = v.parse() {
                self.record_retention_secs = n;
            }
        }
        if let Ok(v) = std::env::var("ELARA_DISK_CAP_BYTES") {
            if let Ok(n) = v.parse() {
                self.disk_cap_bytes = n;
            }
        }
        if let Ok(v) = std::env::var("ELARA_DISK_PRESSURE_AVAIL_LOW_MB") {
            if let Ok(n) = v.parse() {
                self.disk_pressure_avail_low_mb = n;
            }
        }
        if let Ok(v) = std::env::var("ELARA_DISK_PRESSURE_AVAIL_HIGH_MB") {
            if let Ok(n) = v.parse() {
                self.disk_pressure_avail_high_mb = n;
            }
        }
        // Cadence for the data_dir recursive size walk. 0 disables.
        if let Ok(v) = std::env::var("ELARA_DATA_DIR_SIZE_SAMPLE_INTERVAL_SECS") {
            if let Ok(n) = v.parse() {
                self.data_dir_size_sample_interval_secs = n;
            }
        }
        // Phase 6d readiness threshold + bootstrap-fallback floor.
        // 0 is rejected (a 0-threshold gate is a no-op that fires false-ready);
        // we ignore the env value and keep the default.
        if let Ok(v) = std::env::var("ELARA_PHASE6D_MIN_COMMITTEE_SIZE") {
            if let Ok(n) = v.parse::<usize>() {
                if n > 0 {
                    self.phase6d_min_committee_size = n;
                }
            }
        }
        if let Ok(v) = std::env::var("ELARA_MIN_POW_DIFFICULTY") {
            if let Ok(n) = v.parse::<u8>() {
                self.min_pow_difficulty = n;
            }
        }
        if let Ok(v) = std::env::var("ELARA_MIN_ATTESTATION_FOR_GATEWAY") {
            if let Some(level) = crate::identity::AttestationLevel::parse(&v) {
                self.min_attestation_for_gateway = level;
            }
        }
        if let Ok(v) = std::env::var("ELARA_MIN_PROTOCOL_VERSION") {
            if let Ok(n) = v.parse::<u32>() {
                self.min_protocol_version = n;
            }
        }
        if let Ok(v) = std::env::var("ELARA_LIVENESS_DECAY") {
            self.liveness_decay_enabled = v == "1" || v.eq_ignore_ascii_case("true");
        }
        if let Ok(v) = std::env::var("ELARA_LIVENESS_WINDOW_EPOCHS") {
            if let Ok(n) = v.parse() {
                self.liveness_window_epochs = n;
            }
        }
        if let Ok(v) = std::env::var("ELARA_LIVENESS_FLOOR_DIVISOR") {
            if let Ok(n) = v.parse() {
                self.liveness_floor_divisor = n;
            }
        }
        if let Ok(v) = std::env::var("ELARA_MAX_RECORD_AGE") {
            if let Ok(n) = v.parse() {
                self.max_record_age_secs = n;
            }
        }
        if let Ok(v) = std::env::var("ELARA_PROPAGATION_RATE_LIMIT") {
            if let Ok(n) = v.parse::<u32>() {
                self.propagation_rate_limit_per_hour = n;
            }
        }
        if let Ok(v) = std::env::var("ELARA_ZONE_MIN_WITNESSES") {
            if let Ok(n) = v.parse::<usize>() {
                self.zone_min_witnesses = n;
            }
        }
        if let Ok(v) = std::env::var("ELARA_ZONE_COUNT") {
            if let Ok(n) = v.parse::<u64>() {
                self.zone_count = n;
            }
        }
        if let Ok(v) = std::env::var("ELARA_AUTO_ZONE_SCALE") {
            self.auto_zone_scale = matches!(v.as_str(), "1" | "true" | "TRUE" | "on" | "yes");
        }
        if let Ok(v) = std::env::var("ELARA_AUTO_ZONE_SCALE_MAX") {
            if let Ok(n) = v.parse::<u64>() {
                self.auto_zone_scale_max = n.max(1);
            }
        }
        if let Ok(v) = std::env::var("ELARA_PQ_HANDSHAKE_CONCURRENCY") {
            if let Ok(n) = v.parse::<u64>() {
                self.pq_handshake_concurrency = n.max(1);
            }
        }
        if let Ok(v) = std::env::var("ELARA_PQ_SERVE_CONCURRENCY") {
            if let Ok(n) = v.parse::<u64>() {
                self.pq_serve_concurrency = n.max(1);
            }
        }
        if let Ok(v) = std::env::var("ELARA_PQ_HEAVY_READ_CONCURRENCY") {
            // 0 is a meaningful value here (= derive from max_blocking/2), so do
            // NOT clamp to min 1 like the handshake gate — the clamp happens at
            // construction only for an explicit non-zero override.
            if let Ok(n) = v.parse::<u64>() {
                self.pq_heavy_read_concurrency = n;
            }
        }
        if let Ok(v) = std::env::var("ELARA_PQ_HEAVY_READ_WAIT_MS") {
            if let Ok(n) = v.parse::<u64>() {
                self.pq_heavy_read_wait_ms = n;
            }
        }
        if let Ok(v) = std::env::var("ELARA_PQ_VERIFY_CONCURRENCY") {
            // 0 is meaningful (= derive from the blocking pool), so no min-clamp
            // here — the explicit non-zero override is clamped ≥1 at construction.
            if let Ok(n) = v.parse::<u64>() {
                self.pq_verify_concurrency = n;
            }
        }
        if let Ok(v) = std::env::var("ELARA_ZONE_SUBSCRIPTION_VALIDITY_EPOCHS") {
            if let Ok(n) = v.parse::<u64>() {
                self.zone_subscription_validity_epochs = n.max(10);
            }
        }
        if let Ok(v) = std::env::var("ELARA_ZONE_SUBSCRIPTION_REFRESH_MARGIN") {
            if let Ok(n) = v.parse::<u64>() {
                self.zone_subscription_refresh_margin = n.max(1);
            }
        }
        if let Ok(v) = std::env::var("ELARA_CONTENT_ROUTING_THRESHOLD") {
            if let Ok(n) = v.parse::<usize>() {
                self.content_routing_threshold = n;
            }
        }
        if let Ok(v) = std::env::var("ELARA_CONTENT_ROUTING_K") {
            if let Ok(n) = v.parse::<usize>() {
                self.content_routing_k = n.max(1);
            }
        }
        if let Ok(v) = std::env::var("ELARA_ARCHIVE_SNAPSHOT_EVERY_N_EPOCHS") {
            if let Ok(n) = v.parse::<u64>() {
                self.archive_snapshot_every_n_epochs = n;
            }
        }
        if let Ok(v) = std::env::var("ELARA_ARCHIVE_SNAPSHOT_RETENTION") {
            if let Ok(n) = v.parse::<usize>() {
                self.archive_snapshot_retention = n.max(1);
            }
        }
        if let Ok(v) = std::env::var("ELARA_WS_MAX_CONNECTIONS") {
            if let Ok(n) = v.parse::<u32>() {
                self.ws_max_connections = n;
            }
        }
        if let Ok(v) = std::env::var("ELARA_WS_HEARTBEAT") {
            if let Ok(n) = v.parse::<u64>() {
                self.ws_heartbeat_secs = n;
            }
        }
        if let Ok(v) = std::env::var("ELARA_ADMIN_TOKEN") {
            self.admin_token = v;
        }
        if let Ok(v) = std::env::var("ELARA_GENESIS_TIMESTAMP") {
            // CFG-4 (2026-07-03 audit): "NaN"/"inf" parse as valid f64 and would
            // poison every downstream time-bracket computation. Reject non-finite.
            if let Ok(ts) = v.parse::<f64>() {
                if ts.is_finite() {
                    self.genesis_timestamp = ts;
                }
            }
        }
        if let Ok(v) = std::env::var("ELARA_VRF_PUBLIC_KEY") {
            self.vrf_public_key = v;
        }
        if let Ok(v) = std::env::var("ELARA_VRF_KEY") {
            self.vrf_key_path = PathBuf::from(v);
        }
        if let Ok(v) = std::env::var("ELARA_MDNS") {
            self.mdns_enabled = v == "1" || v.eq_ignore_ascii_case("true");
        }
        if let Ok(v) = std::env::var("ELARA_WITNESS_ORG") {
            self.witness_organization = v;
        }
        if let Ok(v) = std::env::var("ELARA_WITNESS_SUBNET") {
            self.witness_subnet = v;
        }
        if let Ok(v) = std::env::var("ELARA_WITNESS_GEO") {
            self.witness_geo_zone = v;
        }
        if let Ok(v) = std::env::var("ELARA_NETWORK_ID") {
            self.network_id = v;
        }
        // REALMS P1: ELARA_REALM=open|federated|sovereign; federated reads
        // the root key from ELARA_REALM_ROOT_PK. Unrecognized values keep
        // the prior realm and are surfaced as a validate() warning.
        if let Ok(v) = std::env::var("ELARA_REALM") {
            let root_pk = std::env::var("ELARA_REALM_ROOT_PK").ok();
            if let Some(realm) = NetworkRealm::from_env_parts(&v, root_pk) {
                self.network_realm = realm;
            }
        }
        if let Ok(v) = std::env::var("ELARA_REALM_CERT") {
            self.realm_membership_cert_path = PathBuf::from(v);
        }
        // GENESIS VALIDATOR BOOTSTRAP: "<id64>:<stake_micros>,..." — replaces
        // the whole list when set. Malformed pairs are dropped here; the
        // identity-format warnings in validate() surface what survived.
        if let Ok(v) = std::env::var("ELARA_GENESIS_VALIDATORS") {
            let trimmed = v.trim();
            if trimmed.is_empty() {
                // F3: a set-but-empty env var must NOT clobber the TOML
                // [[genesis_validators]] list — doing so silently unstakes
                // genesis and the anchor then seals forever at 0 finalized (the
                // PM-2 failure class). Treat empty as unset.
                eprintln!(
                    "[config] ELARA_GENESIS_VALIDATORS is set but empty — ignoring \
                     (keeping TOML genesis_validators); unset it to silence this"
                );
            } else {
                let fragments: Vec<&str> =
                    trimmed.split(',').filter(|s| !s.trim().is_empty()).collect();
                let parsed: Vec<crate::accounting::types::GenesisValidator> = fragments
                    .iter()
                    .filter_map(|pair| {
                        let (id, stake) = pair.trim().split_once(':')?;
                        Some(crate::accounting::types::GenesisValidator {
                            identity: id.trim().to_string(),
                            stake_micros: stake.trim().parse().ok()?,
                        })
                    })
                    .collect();
                if parsed.len() < fragments.len() {
                    // F3: malformed pairs were silently dropped before — surface
                    // it (a bare "1e15" fails u64 parse and drops the whole pair).
                    eprintln!(
                        "[config] ELARA_GENESIS_VALIDATORS: {} of {} entries dropped \
                         as malformed — expected '<id64>:<stake_micros>' (a bare \
                         '1e15' is NOT a valid u64; write 1000000000000000)",
                        fragments.len() - parsed.len(),
                        fragments.len()
                    );
                }
                if parsed.is_empty() {
                    eprintln!(
                        "[config] ELARA_GENESIS_VALIDATORS parsed to ZERO valid \
                         entries — keeping TOML genesis_validators to avoid an \
                         unstaked genesis"
                    );
                } else {
                    self.genesis_validators = parsed;
                }
            }
        }
        if let Ok(v) = std::env::var("ELARA_ADVERTISE_ADDR") {
            self.advertise_addr = v;
        }
        if let Ok(v) = std::env::var("ELARA_NAT") {
            self.behind_nat = v == "1" || v.to_lowercase() == "true";
        }
        if let Ok(v) = std::env::var("ELARA_DNS_SEEDS") {
            self.dns_seeds = v
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
        if let Ok(v) = std::env::var("ELARA_DNS_SEED_PORT") {
            if let Ok(n) = v.parse::<u16>() {
                self.dns_seed_port = n;
            }
        }
        // Gap 5 fleet toggle — flip to true once staked anchors > 10.
        if let Ok(v) = std::env::var("ELARA_USE_COMMITTEE_V2") {
            self.use_committee_v2 = matches!(v.as_str(), "1" | "true" | "TRUE" | "on" | "yes");
        }
        // Uptime-vesting loop — keep OFF until a record-driven design lands; the
        // hourly loop mutates the SMT-leaf `uptime_secs` out-of-band (silent fork).
        if let Ok(v) = std::env::var("ELARA_UPTIME_VESTING_ENABLED") {
            self.uptime_vesting_enabled = matches!(v.as_str(), "1" | "true" | "TRUE" | "on" | "yes");
        }
    }

    /// Validate config and return warnings for dangerous settings.
    ///
    /// AUDIT-10 Milestone D mainnet safety gate. Returns `Err(reason)` if the
    /// configuration is unsafe to boot under the named network profile —
    /// today the only such gate is `network_id == "mainnet"` paired with the
    /// public HTTPS data plane still enabled. Operators must set
    /// `allow_public_https = false` (or `ELARA_ALLOW_PUBLIC_HTTPS=0`) before
    /// pointing a mainnet node at the network. Testnet boots are always
    /// allowed so the migration window stays usable.
    ///
    /// Wire this into the `elara-node` startup path so a misconfigured
    /// mainnet node fails fast instead of silently exposing the legacy
    /// HTTPS surface.
    pub fn enforce_mainnet_safety(&self) -> std::result::Result<(), String> {
        if self.network_id == "mainnet" && self.allow_public_https {
            return Err(
                "refusing to start: network_id=\"mainnet\" with allow_public_https=true. \
                 AUDIT-10 Milestone D forbids the public HTTPS data plane on mainnet — \
                 set allow_public_https=false in config.toml or export \
                 ELARA_ALLOW_PUBLIC_HTTPS=0 before retry."
                    .to_string(),
            );
        }
        // Witness-class nodes must NOT run node_profile=light. Light short-circuits
        // pull_loop (gossip.rs) so the ledger never seeds and auto_witness skips on
        // staked_amount=0 — the node still answers /health but silently contributes
        // zero attestations. Other peers keep counting its old stake in their
        // settlement denominator, so one misconfigured witness drops the
        // network below the 2/3 threshold. This failure mode is silent — a
        // node can sit in it for hours before the cause is found.
        if self.node_profile == "light"
            && matches!(self.node_type.as_str(), "witness" | "anchor" | "gateway" | "genesis")
        {
            return Err(format!(
                "refusing to start: node_type=\"{}\" with node_profile=\"light\". \
                 Light profile short-circuits the record-sync loop, so a staked \
                 witness silently contributes zero attestations and breaks fleet \
                 settlement (2/3 threshold becomes unreachable when this node's \
                 old stake stays in peers' denominators). Light is for leaf-class \
                 client nodes only. Set node_profile=\"full_zone\" (or \"archive\") \
                 in config.toml.",
                self.node_type
            ));
        }
        // Light-client cold-start MUST pin a trust anchor on mainnet. With an
        // empty effective anchor set (compiled-in ∪ configured),
        // `light_sync_loop` degrades to REFERENCE grade (single-seed trust):
        // a malicious cold-start seed could serve a self-consistent forged
        // super-seal + headers and jump the client onto a forged branch. That
        // silent-open state must not ship on mainnet. Testnet/custom networks
        // stay permissive — ephemeral-genesis dev nets have no stable key to pin.
        if self.network_id == "mainnet" && self.node_profile == "light" {
            let anchors = PINNED_GENESIS_AUTHORITY_PUBKEYS
                .iter()
                .map(|s| s.trim())
                .chain(self.light_client_trust_anchors.iter().map(|s| s.trim()))
                .filter(|s| !s.is_empty())
                .count();
            if anchors == 0 {
                return Err(
                    "refusing to start: node_profile=\"light\" on network_id=\"mainnet\" with \
                     no light-client trust anchor. Cold-start would run in REFERENCE grade \
                     (single-seed trust), letting a malicious seed serve a forged branch. Set \
                     light_client_trust_anchors (or ELARA_LIGHT_TRUST_ANCHORS) to the trusted \
                     sealer Dilithium3 pubkey(s), or ship a binary with \
                     PINNED_GENESIS_AUTHORITY_PUBKEYS populated."
                        .to_string(),
                );
            }
        }
        Ok(())
    }

    /// Returns a list of warning strings. Empty = all good.
    /// Does NOT prevent startup — these are operator warnings.
    pub fn validate(&self) -> Vec<String> {
        let mut warnings = Vec::new();

        if self.genesis_authority.is_empty() {
            warnings.push("genesis_authority is empty — ledger validation will reject all ops".into());
        }
        if self.gossip_max_hops == 0 {
            warnings.push("gossip_max_hops=0 — records will never relay beyond direct peers".into());
        }
        if self.rate_limit_write == 0 {
            warnings.push("rate_limit_write=0 — write rate limiting disabled, DoS risk".into());
        }
        if self.rate_limit_read == 0 {
            warnings.push("rate_limit_read=0 — read rate limiting disabled, DoS risk".into());
        }
        if self.uptime_vesting_enabled {
            warnings.push(
                "uptime_vesting_enabled=true has NO effect — the out-of-band vesting loop is \
                 permanently gated off (it would fork the account-SMT root); vesting requires a \
                 record-driven redesign (C11, see internal design notes)"
                    .into(),
            );
        }
        if self.seed_peers.is_empty()
            && self.node_type != "genesis"
            && self.network_realm.discovery_enabled()
        {
            warnings.push("no seed_peers configured — node will not discover the network".into());
        }
        if !self.network_realm.discovery_enabled() && !self.seed_peers.is_empty() {
            warnings.push(
                "realm=sovereign with seed_peers configured — sovereign nodes never dial seeds \
                 (discovery-off); peers must be operator-pinned"
                    .into(),
            );
        }
        if self.gossip_pull_interval_secs == 0 {
            warnings.push("gossip_pull_interval=0 — pull sync disabled, node relies on push only".into());
        }
        if self.allow_public_https && self.network_id != "mainnet" {
            // Non-fatal on non-mainnet networks; mainnet boots hard-abort via
            // enforce_mainnet_safety. The note keeps operators honest about
            // what surface is still exposed during the AUDIT-10 migration.
            warnings.push(
                "allow_public_https=true — public HTTPS data plane is still bound to \
                 0.0.0.0. Operators rolling forward to mainnet must flip this off and \
                 verify elara_https_fallback_total stays at 0 (AUDIT-10 Milestone D)."
                    .into(),
            );
        }
        if self.allow_cross_zone_parents && self.network_id == "mainnet" {
            warnings.push(
                "allow_cross_zone_parents=true on mainnet — records with parents \
                 in unrelated zones will be soft-warned, not rejected. Set \
                 allow_cross_zone_parents=false (or ELARA_ALLOW_CROSS_ZONE_PARENTS=0) \
                 once elara_cross_zone_parent_observed_total has been at 0 for a full \
                 epoch (DAM-3D Phase A)."
                    .into(),
            );
        }
        if self.max_peer_failures == 0 {
            warnings.push("max_peer_failures=0 — failing peers will never be pruned".into());
        }
        if self.min_pow_difficulty == 0 {
            warnings.push("min_pow_difficulty=0 — Sybil protection disabled, any identity accepted".into());
        }
        if self.min_attestation_for_gateway == crate::identity::AttestationLevel::None {
            warnings.push(
                "min_attestation_for_gateway=NONE — software-only gateways may author \
                 delegation_op authorize records. Acceptable on testnet only; mainnet \
                 must restore SECURE_BOOT (or higher) per economics §11.33."
                    .into(),
            );
        }
        if self.admin_token.is_empty() {
            warnings.push("admin_token is empty — admin endpoints will reject all requests. Set ELARA_ADMIN_TOKEN or admin_token in config.".into());
        } else if self.admin_token.len() < 32 {
            warnings.push("admin_token is too short (< 32 chars) — use `openssl rand -hex 32` for a secure token".into());
        }
        if !["leaf", "relay", "witness", "archive", "anchor", "gateway", "genesis"].contains(&self.node_type.as_str()) {
            warnings.push(format!(
                "unknown node_type '{}' — expected one of: {}",
                self.node_type,
                ["leaf", "relay", "witness", "archive", "anchor", "gateway", "genesis"].join(", "),
            ));
        }
        // light_mode (wire format) and node_profile (storage retention) are
        // independent fields. Operators who only set light_mode often expect
        // light retention too — warn so the disk doesn't fill 90 days deep.
        if self.light_mode && self.node_profile == "full_zone" {
            warnings.push(
                "light_mode=true with node_profile=\"full_zone\" — light_mode only affects \
                 outgoing record wire size (~5KB vs ~41KB); RocksDB still keeps 90 days of \
                 records under full_zone. If you want phone-tier storage too, set \
                 node_profile=\"light\" (72h retention)."
                    .into(),
            );
        }
        // node_profile=light on archive/relay is suspicious but not fatal — the
        // hard-abort case (witness-class) is in enforce_mainnet_safety. Archive
        // is supposed to keep ~1000y of history; light retains 72h, so the two
        // declarations contradict each other.
        if self.node_profile == "light"
            && matches!(self.node_type.as_str(), "archive" | "relay")
        {
            warnings.push(format!(
                "node_type=\"{}\" with node_profile=\"light\" is contradictory — \
                 archive/relay roles imply full record history, but light keeps \
                 only 72h. Pick node_profile=\"full_zone\" (or \"archive\" for \
                 archive nodes) unless this is intentional.",
                self.node_type
            ));
        }
        // REALMS P1 — realm posture sanity. A federated realm with an
        // unusable root key means the slice-(b) admission gate will reject
        // EVERY peer once it lands; catch it at boot, not at first dial.
        if let NetworkRealm::Federated { root_pk } = &self.network_realm {
            if root_pk.is_empty() {
                warnings.push(
                    "network_realm=federated with empty root_pk — no membership cert \
                     can verify, the admission gate will reject every peer. Set \
                     root_pk in the [network_realm] table (hex Dilithium3 public \
                     key) or export ELARA_REALM_ROOT_PK."
                        .into(),
                );
            } else {
                match hex::decode(root_pk) {
                    Ok(bytes) if bytes.len() == crate::crypto::pqc::DILITHIUM3_PUBLIC_KEY_LEN => {}
                    Ok(bytes) => warnings.push(format!(
                        "network_realm=federated root_pk decodes to {} bytes — expected \
                         a {}-byte Dilithium3 public key. Membership certs will not \
                         verify against this root.",
                        bytes.len(),
                        crate::crypto::pqc::DILITHIUM3_PUBLIC_KEY_LEN,
                    )),
                    Err(_) => warnings.push(
                        "network_realm=federated root_pk is not valid hex — membership \
                         certs will not verify against this root."
                            .into(),
                    ),
                }
            }
        }
        // A federated node with no membership cert of its own can gate
        // inbound peers but is rejected (cert_missing) whenever IT dials a
        // fellow member — one-way membership is almost never intended.
        if matches!(self.network_realm, NetworkRealm::Federated { .. })
            && self.realm_membership_cert_path.as_os_str().is_empty()
        {
            warnings.push(
                "network_realm=federated but realm_membership_cert_path is empty — \
                 this node can accept members inbound yet its own outbound dials \
                 into the federation will be rejected with cert_missing. Set \
                 realm_membership_cert_path (or ELARA_REALM_CERT) to the cert \
                 issued by your federation root."
                    .into(),
            );
        }
        // GENESIS VALIDATOR BOOTSTRAP sanity — warnings, not aborts: the
        // ledger-side apply skips bad entries deterministically, but the
        // operator must know the validator set is not what they intended.
        {
            let mut seen = std::collections::HashSet::new();
            let mut total: u128 = 0;
            for v in &self.genesis_validators {
                if v.identity.len() != 64 || !v.identity.chars().all(|c| c.is_ascii_hexdigit()) {
                    warnings.push(format!(
                        "genesis_validators entry '{}' is not a 64-char hex identity \
                         hash — it will never match a real identity (dead config)",
                        v.identity
                    ));
                }
                if !seen.insert(v.identity.to_ascii_lowercase()) {
                    warnings.push(format!(
                        "genesis_validators lists '{}' more than once — only the first \
                         entry applies (synthetic-id idempotence guard)",
                        v.identity
                    ));
                }
                if v.stake_micros == 0 {
                    warnings.push(format!(
                        "genesis_validators entry '{}' has stake_micros=0 — skipped at \
                         baseline apply",
                        v.identity
                    ));
                }
                total += v.stake_micros as u128;
            }
            if total > crate::accounting::types::MAX_SUPPLY as u128 {
                warnings.push(format!(
                    "genesis_validators total stake {total} exceeds MAX_SUPPLY {} — \
                     baseline apply will skip validators once the genesis authority's \
                     allocation is exhausted",
                    crate::accounting::types::MAX_SUPPLY
                ));
            }
            // Settlement fault tolerance of the self-submit topology. is_settled
            // excludes the creator's own stake, so equal-stake validators that
            // submit their OWN transfers need ⌈2(n−1)/3⌉ of the OTHERS — which at
            // n∈{2,3} means ALL of them (zero offline tolerated). The operator
            // standing up the validator set MUST hear this before launch, not
            // discover it when a node reboots (fusion-audited 2026-06-21).
            let staked_validators = self
                .genesis_validators
                .iter()
                .filter(|v| v.stake_micros > 0)
                .count();
            if staked_validators >= 2
                && crate::network::consensus::AWCConsensus::self_submit_settlement_fault_tolerance(
                    staked_validators,
                ) == 0
            {
                warnings.push(format!(
                    "genesis_validators: {staked_validators} staked validators that \
                     submit their own transfers tolerate ZERO offline validators for \
                     settlement (settlement excludes creator stake — one validator down \
                     stalls its peers' transfers). Use N=4+ validators, or route settling \
                     transfers through non-staking submitter identities. See \
                     internal design notes §2."
                ));
            }
        }
        // Typo'd ELARA_REALM is ignored at apply time (fail-closed: keeps
        // the configured realm); surface the ignored override here so a
        // sovereign operator notices before assuming the override took.
        if let Ok(v) = std::env::var("ELARA_REALM") {
            if NetworkRealm::from_env_parts(&v, None).is_none() {
                warnings.push(format!(
                    "ELARA_REALM='{v}' is not one of open|federated|sovereign — \
                     override ignored, realm stays '{}'.",
                    self.network_realm.label(),
                ));
            }
        }

        warnings
    }

    /// Resolve relative paths against data_dir.
    fn resolve_paths(&mut self) {
        if self.identity_path.is_relative() {
            self.identity_path = self.data_dir.join(&self.identity_path);
        }
        if self.db_path.is_relative() {
            self.db_path = self.data_dir.join(&self.db_path);
        }
        if self.vrf_key_path.is_relative() && !self.vrf_key_path.as_os_str().is_empty() {
            self.vrf_key_path = self.data_dir.join(&self.vrf_key_path);
        }
        if self.realm_membership_cert_path.is_relative()
            && !self.realm_membership_cert_path.as_os_str().is_empty()
        {
            self.realm_membership_cert_path = self.data_dir.join(&self.realm_membership_cert_path);
        }
    }

    /// Clamp `disk_cap_bytes` to a fraction of the actual filesystem
    /// capacity at `data_dir`. Returns `(pre_clamp, post_clamp, total_fs_bytes)`
    /// so the caller can log the change.
    ///
    /// Why: the default `disk_cap_bytes=200 GB` was meaningless on
    /// small VPS (24-38 GB filesystems) — `live_bytes > disk_cap` was
    /// physically unreachable, so GC's size-based retention compression
    /// (gc.rs:319-327) never fired. The 90-day FullZone retention ran
    /// uncompressed until the avail-MB watchdog tripped, with no
    /// recovery path — operators had to manually shrink retention.
    ///
    /// What: reads `statvfs(data_dir).f_blocks * f_frsize` for the total
    /// filesystem bytes. If `disk_cap_bytes > total * 0.7`, clamps down to
    /// `total * 0.7`. The 30% headroom covers OS, logs, snapshots, RocksDB
    /// compaction working space, and the avail-MB trip threshold.
    ///
    /// Operator opt-out: setting `ELARA_DISK_CAP_BYTES` explicitly bypasses
    /// the clamp (operator-owned values are honored verbatim — assume the
    /// operator measured their disk).
    #[cfg(unix)]
    pub fn clamp_disk_cap_to_fs(&mut self) -> Option<(u64, u64, u64)> {
        if self.disk_cap_bytes == 0 { return None; }
        if std::env::var("ELARA_DISK_CAP_BYTES").is_ok() { return None; }

        use std::os::unix::ffi::OsStrExt;
        let path = std::ffi::CString::new(self.data_dir.as_os_str().as_bytes()).ok()?;
        let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statvfs(path.as_ptr(), &mut stat) } != 0 { return None; }
        // `statvfs` field widths differ by platform — `f_blocks`/`f_frsize` are
        // u32 on macOS (Darwin) but u64 on Linux. Widen both to u64 so the byte
        // math is correct (and compiles) everywhere; the casts are no-ops on Linux.
        #[allow(clippy::unnecessary_cast)]
        let total_bytes = (stat.f_blocks as u64).saturating_mul(stat.f_frsize as u64);
        if total_bytes == 0 { return None; }

        let max_cap = total_bytes * 7 / 10;
        if self.disk_cap_bytes > max_cap {
            let pre = self.disk_cap_bytes;
            self.disk_cap_bytes = max_cap;
            Some((pre, max_cap, total_bytes))
        } else {
            None
        }
    }

    #[cfg(not(unix))]
    pub fn clamp_disk_cap_to_fs(&mut self) -> Option<(u64, u64, u64)> { None }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_defaults_have_testnet_seeds() {
        // Phase 3: defaults are EMPTY post-decommission (2026-06-09) — a
        // zero-config boot must warn rather than trust a dead authority or
        // dial dead seeds.
        let config = NodeConfig::default();
        let warnings = config.validate();
        assert!(warnings.iter().any(|w| w.contains("genesis_authority")),
            "empty default genesis_authority must warn");
        assert!(warnings.iter().any(|w| w.contains("seed_peers")),
            "empty default seed_peers must warn");
        assert_eq!(config.genesis_authority, super::TESTNET_GENESIS_AUTHORITY);
        assert!(config.seed_peers.is_empty());
        assert_eq!(config.node_type, "witness");
        assert!(config.auto_witness);
    }

    #[test]
    fn test_arch2_auto_zone_scale_default_is_true() {
        let config = NodeConfig::default();
        assert!(config.auto_zone_scale,
            "ARCH-2: mainnet-correct default is true; non-authority nodes observe, only genesis_authority acts");
        assert_eq!(config.auto_zone_scale_max, 1_000_000,
            "scale ceiling stays at mainnet 1M zone target");
    }

    #[test]
    fn require_encrypted_identity_defaults_off_and_parses_opt_in() {
        // Default off — forcing it on every node would brick no-passphrase
        // unattended restarts; it is an opt-in security knob, never a default.
        assert!(!NodeConfig::default().require_encrypted_identity);
        // Omitted from an operator's config → false (container #[serde(default)]),
        // so adding this field never bricks an existing config that omits it.
        let omitted: NodeConfig =
            serde_json::from_str("{}").expect("empty config parses via serde(default)");
        assert!(!omitted.require_encrypted_identity);
        // Explicit opt-in deserializes true.
        let on: NodeConfig = serde_json::from_str(r#"{"require_encrypted_identity": true}"#)
            .expect("opt-in config parses");
        assert!(on.require_encrypted_identity, "explicit true must deserialize");
    }

    #[test]
    fn test_validate_clean_config() {
        // AUDIT-10 Milestone D: validate now nudges any non-mainnet operator
        // who still has the public HTTPS plane bound. Suppress here so the
        // "clean config" test continues to assert clean-baseline behavior.
        let config = NodeConfig {
            genesis_authority: "abc123".into(),
            seed_peers: vec!["127.0.0.1:9473".into()],
            admin_token: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2".into(),
            allow_public_https: false,
            ..Default::default()
        };
        let warnings = config.validate();
        assert!(warnings.is_empty(), "expected no warnings: {warnings:?}");
    }

    #[test]
    fn test_validate_dangerous_settings() {
        let config = NodeConfig {
            genesis_authority: "abc123".into(),
            seed_peers: vec!["127.0.0.1:9473".into()],
            gossip_max_hops: 0,
            rate_limit_write: 0,
            node_type: "potato".into(),
            ..Default::default()
        };
        let warnings = config.validate();
        assert!(warnings.iter().any(|w| w.contains("gossip_max_hops=0")));
        assert!(warnings.iter().any(|w| w.contains("rate_limit_write=0")));
        assert!(warnings.iter().any(|w| w.contains("potato")));
    }

    #[test]
    fn test_validate_all_node_types_accepted() {
        let valid_types = ["leaf", "relay", "witness", "archive", "anchor", "gateway", "genesis"];
        for nt in &valid_types {
            let config = NodeConfig {
                genesis_authority: "abc123".into(),
                seed_peers: vec!["127.0.0.1:9473".into()],
                node_type: nt.to_string(),
                ..Default::default()
            };
            let warnings = config.validate();
            assert!(
                !warnings.iter().any(|w| w.contains("unknown node_type")),
                "node_type '{nt}' should be valid but got warning: {warnings:?}"
            );
        }
    }

    // ─── PQ-R1 defaults ────────────────────────────────────────────────────

    #[test]
    fn pq_r1_defaults_are_pq_only_classical_off() {
        let c = NodeConfig::default();
        assert!(c.require_pq_transport, "4E.5: require_pq_transport must default true");
        assert_eq!(c.pq_port_offset, 100);
    }

    /// 4E.5 flag-day: existing config files / test fixtures that still write
    /// the field as `prefer_pq_transport` must still deserialize to the new
    /// name. The serde alias is the single point of backward-compat — if it
    /// regresses, fleet operator config files would silently fall back to
    /// the field default on first read.
    #[test]
    fn config_accepts_legacy_prefer_pq_transport_alias() {
        let json = r#"{
            "listen_addr": "0.0.0.0:9473",
            "pq_listen_addr": "",
            "pq_port_offset": 100,
            "prefer_pq_transport": false,
            "allow_public_https": false,
            "identity_path": "id.json",
            "db_path": "db.sqlite",
            "genesis_authority": "g",
            "seed_peers": [],
            "node_type": "leaf",
            "gossip_pull_interval_secs": 10,
            "auto_witness": false,
            "data_dir": ".",
            "tls_enabled": false,
            "tls_cert_path": "cert.pem",
            "tls_key_path": "key.pem",
            "tls_allow_insecure": false,
            "rate_limit_write": 1000,
            "rate_limit_read": 1000,
            "snapshot_interval_secs": 0,
            "gossip_max_hops": 6,
            "max_peer_failures": 0,
            "pex_interval_secs": 0,
            "epoch_seal_interval_secs": 60,
            "auto_witness_interval_secs": 10,
            "auto_witness_batch_size": 10,
            "witness_reward_micros": 1,
            "health_check_interval_secs": 30,
            "health_min_peers": 1,
            "health_max_sync_lag_secs": 300,
            "gc_interval_secs": 3600,
            "record_retention_secs": 7776000.0
        }"#;
        let parsed: serde_json::Result<NodeConfig> = serde_json::from_str(json);
        match parsed {
            Ok(c) => assert!(!c.require_pq_transport, "alias must populate require_pq_transport"),
            // The fixture is intentionally minimal; if extra fields become
            // required at deserialize time the alias semantics still hold —
            // we only need to confirm serde does not reject the legacy name.
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    !msg.contains("unknown field `prefer_pq_transport`"),
                    "serde must alias prefer_pq_transport → require_pq_transport: {msg}"
                );
            }
        }
    }

    #[test]
    fn effective_pq_listen_addr_auto_derives_from_listen_addr() {
        let mut c = NodeConfig {
            listen_addr: "0.0.0.0:9473".into(),
            ..Default::default()
        };
        c.pq_listen_addr.clear();
        assert_eq!(c.effective_pq_listen_addr().as_deref(), Some("0.0.0.0:9573"));
    }

    #[test]
    fn effective_pq_listen_addr_preserves_explicit_override() {
        let c = NodeConfig {
            pq_listen_addr: "127.0.0.1:19573".into(),
            ..Default::default()
        };
        assert_eq!(c.effective_pq_listen_addr().as_deref(), Some("127.0.0.1:19573"));
    }

    #[test]
    fn effective_pq_listen_addr_honors_disabled_optout() {
        let mut c = NodeConfig {
            pq_listen_addr: "disabled".into(),
            ..Default::default()
        };
        assert!(c.effective_pq_listen_addr().is_none());
        c.pq_listen_addr = "DISABLED".into();
        assert!(c.effective_pq_listen_addr().is_none());
    }

    // ─── AUDIT-10 Milestone D — allow_public_https mainnet gate ──────────────

    #[test]
    fn allow_public_https_default_is_true_for_testnet_migration() {
        // Migration window: testnet keeps the legacy HTTPS listener bound so
        // accounts / SDKs still connect. Flag flips to false at the Milestone D
        // fleet gate, by which point Milestone C has the PQ SDK out.
        let c = NodeConfig::default();
        assert!(c.allow_public_https, "testnet default must keep public HTTPS available");
        assert_eq!(c.network_id, "testnet");
    }

    #[test]
    fn enforce_mainnet_safety_passes_for_testnet_with_https_on() {
        // Testnet with allow_public_https=true is the supported migration
        // configuration — gate must NOT trip.
        let c = NodeConfig::default();
        assert_eq!(c.network_id, "testnet");
        assert!(c.allow_public_https);
        assert!(c.enforce_mainnet_safety().is_ok());
    }

    // ─── Light-client cold-start trust-anchor gate (mainnet) ─────────────────

    #[test]
    fn enforce_mainnet_safety_blocks_mainnet_light_with_empty_anchor_set() {
        // A mainnet light node with no pinned trust anchor would cold-start in
        // REFERENCE grade (single-seed trust) — the silent-open state the
        // cold-start anchor fix forbids. Boot must hard-abort. node_type="light"
        // is leaf-class so the witness-class guard does not pre-empt this gate.
        let c = NodeConfig {
            network_id: "mainnet".into(),
            allow_public_https: false,
            node_profile: "light".into(),
            node_type: "light".into(),
            light_client_trust_anchors: Vec::new(),
            ..Default::default()
        };
        let err = c
            .enforce_mainnet_safety()
            .expect_err("mainnet light node with empty anchor set must refuse to start");
        assert!(err.contains("no light-client trust anchor"), "unexpected: {err}");
    }

    #[test]
    fn enforce_mainnet_safety_passes_mainnet_light_with_configured_anchor() {
        // Same node WITH a pinned anchor configured: the gate is satisfied.
        let c = NodeConfig {
            network_id: "mainnet".into(),
            allow_public_https: false,
            node_profile: "light".into(),
            node_type: "light".into(),
            light_client_trust_anchors: vec!["deadbeef".into()],
            ..Default::default()
        };
        assert!(
            c.enforce_mainnet_safety().is_ok(),
            "mainnet light node with a configured anchor must start",
        );
    }

    #[test]
    fn enforce_mainnet_safety_permits_testnet_light_without_anchor() {
        // Testnet/dev stays permissive — ephemeral-genesis nets have no stable
        // key to pin, and cold-start degrades to honestly-labelled Reference.
        let c = NodeConfig {
            network_id: "testnet".into(),
            node_profile: "light".into(),
            node_type: "light".into(),
            light_client_trust_anchors: Vec::new(),
            ..Default::default()
        };
        assert!(
            c.enforce_mainnet_safety().is_ok(),
            "testnet light node without anchor must remain permitted",
        );
    }

    #[test]
    fn enforce_mainnet_safety_blocks_mainnet_with_https_on() {
        // The single gate condition: mainnet + flag still true → boot abort.
        let c = NodeConfig {
            network_id: "mainnet".into(),
            allow_public_https: true,
            ..Default::default()
        };
        let err = c.enforce_mainnet_safety().expect_err(
            "mainnet with allow_public_https=true must refuse to start"
        );
        assert!(err.contains("allow_public_https"), "error must name the offending flag: {err}");
        assert!(err.contains("mainnet"), "error must name the network profile: {err}");
    }

    #[test]
    fn enforce_mainnet_safety_passes_for_mainnet_with_https_off() {
        // The intended steady state post-Milestone-D rollout.
        let c = NodeConfig {
            network_id: "mainnet".into(),
            allow_public_https: false,
            ..Default::default()
        };
        assert!(c.enforce_mainnet_safety().is_ok());
    }

    #[test]
    fn enforce_mainnet_safety_passes_for_custom_network_with_https_on() {
        // Custom network IDs (devnet, simnet, etc.) bypass the mainnet gate
        // entirely — only the literal string "mainnet" trips the abort.
        let c = NodeConfig {
            network_id: "devnet-2026-04".into(),
            allow_public_https: true,
            ..Default::default()
        };
        assert!(c.enforce_mainnet_safety().is_ok());
    }

    #[test]
    fn validate_warns_when_public_https_on_for_non_mainnet() {
        // Operator nudge: any non-mainnet config with the flag still on emits
        // a warning so the migration deadline doesn't slip silently.
        let c = NodeConfig {
            admin_token: "a".repeat(40),
            genesis_authority: "abc123".into(),
            seed_peers: vec!["127.0.0.1:9473".into()],
            ..Default::default()
        };
        assert_eq!(c.network_id, "testnet");
        assert!(c.allow_public_https);
        let warnings = c.validate();
        assert!(
            warnings.iter().any(|w| w.contains("allow_public_https=true")),
            "validate must warn on lingering testnet HTTPS exposure: {warnings:?}"
        );
    }

    #[test]
    fn validate_silent_when_public_https_off_or_on_mainnet() {
        // Non-fatal warning is suppressed once the flag is off OR the node is
        // mainnet (mainnet is policed by enforce_mainnet_safety, not validate).
        let off = NodeConfig {
            admin_token: "a".repeat(40),
            allow_public_https: false,
            ..Default::default()
        };
        assert!(!off.validate().iter().any(|w| w.contains("allow_public_https")));

        let mainnet = NodeConfig {
            admin_token: "a".repeat(40),
            network_id: "mainnet".into(),
            allow_public_https: true,
            ..Default::default()
        };
        // validate is intentionally silent on mainnet here — the abort gate
        // is the durable enforcement.
        assert!(!mainnet.validate().iter().any(|w| w.contains("allow_public_https")));
    }

    #[test]
    fn validate_warns_on_zero_fault_tolerance_self_submit_validator_set() {
        // 3 equal-stake validators = the canonical 0-settlement-fault-tolerance
        // self-submit topology. validate() must surface it so the operator
        // standing up the set sees it before launch, not when a node reboots
        // offline (internal design notes §2, fusion-audited).
        use crate::accounting::types::GenesisValidator;
        let gv = |n: u8| GenesisValidator {
            identity: format!("{n:064x}"),
            stake_micros: 100_000_000_000, // 100 beat, equal stake
        };
        let has_ft_warn = |c: &NodeConfig| {
            c.validate().iter().any(|w| w.contains("ZERO offline validators"))
        };

        let n3 = NodeConfig {
            admin_token: "a".repeat(40),
            genesis_validators: vec![gv(1), gv(2), gv(3)],
            ..Default::default()
        };
        assert!(has_ft_warn(&n3), "N=3 self-submit must warn about 0 settlement FT");

        // N=4 restores 1-fault tolerance → silent.
        let n4 = NodeConfig {
            admin_token: "a".repeat(40),
            genesis_validators: vec![gv(1), gv(2), gv(3), gv(4)],
            ..Default::default()
        };
        assert!(!has_ft_warn(&n4), "N=4 tolerates 1 fault — no settlement-FT warning");

        // A single genesis validator is the bootstrap carve-out, not a quorum.
        let one = NodeConfig {
            admin_token: "a".repeat(40),
            genesis_validators: vec![gv(1)],
            ..Default::default()
        };
        assert!(!has_ft_warn(&one), "singleton rides the carve-out, no 0-FT warning");
    }

    // ─── L1995 Phase 2 — data_plane_listen_addr split ────────────────────────

    #[test]
    fn data_plane_listen_addr_default_is_loopback() {
        // Mainnet-correct default: data plane never bound on a public
        // interface. Operators wanting the legacy single-listener mode set
        // this to the empty string explicitly.
        let c = NodeConfig::default();
        assert_eq!(c.data_plane_listen_addr, "127.0.0.1:9472");
    }

    #[test]
    fn data_plane_listen_addr_env_override_supports_empty_for_legacy_mode() {
        // The split-binding code in elara_node.rs treats empty as "fall back
        // to the legacy single-listener layout". Explicitly cover the env
        // path because operators on canary nodes may need the escape hatch.
        let key = "ELARA_DATA_PLANE_LISTEN";
        let prev = std::env::var(key).ok();
        std::env::set_var(key, "");
        let mut c = NodeConfig::default();
        c.apply_env_overrides();
        assert_eq!(c.data_plane_listen_addr, "");
        match prev {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }

    #[test]
    fn derive_pq_addr_handles_ipv4_and_ipv6() {
        assert_eq!(derive_pq_addr("0.0.0.0:9473", 100).as_deref(), Some("0.0.0.0:9573"));
        assert_eq!(derive_pq_addr("127.0.0.1:9474", 100).as_deref(), Some("127.0.0.1:9574"));
        assert_eq!(derive_pq_addr("[::1]:9473", 100).as_deref(), Some("[::1]:9573"));
        assert_eq!(derive_pq_addr("[fe80::1]:9473", 100).as_deref(), Some("[fe80::1]:9573"));
    }

    #[test]
    fn derive_pq_addr_rejects_overflow_and_garbage() {
        assert!(derive_pq_addr("not-an-addr", 100).is_none());
        assert!(derive_pq_addr("", 100).is_none());
        // port 65500 + offset 100 > u16 max → None.
        assert!(derive_pq_addr("0.0.0.0:65500", 100).is_none());
    }

    #[test]
    fn test_dns_seeds_default() {
        // Empty by default since 2026-07-02: the old `seeds.elara.network`
        // default named a domain the project does not own — a fresh node must
        // not resolve discovery through third-party-controlled DNS.
        let config = NodeConfig::default();
        assert!(config.dns_seeds.is_empty());
        assert_eq!(config.dns_seed_port, 9473);
    }

    #[test]
    fn test_dns_seeds_env_parse() {
        let input = "seed1.example.com, seed2.example.com, ";
        let parsed: Vec<String> = input
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        assert_eq!(parsed, vec!["seed1.example.com", "seed2.example.com"]);
    }

    #[test]
    fn test_dns_seeds_empty_disables() {
        let config = NodeConfig {
            dns_seeds: vec![],
            ..Default::default()
        };
        assert!(config.dns_seeds.is_empty());
    }

    // ── AUDIT-9 Milestone B: effective_witness_profile ──────────────────

    #[test]
    fn test_audit9_effective_witness_profile_returns_some_when_org_set() {
        let config = NodeConfig {
            witness_organization: "navigatorbuilds".into(),
            witness_subnet: "88.99.142".into(),
            witness_geo_zone: "earth-eu".into(),
            ..Default::default()
        };
        let profile = config
            .effective_witness_profile()
            .expect("profile expected when org is set");
        assert_eq!(profile.organization, "navigatorbuilds");
        assert_eq!(profile.subnet, "88.99.142");
        assert_eq!(profile.geo_zone, "earth-eu");
    }

    #[test]
    fn test_audit9_effective_witness_profile_none_when_org_empty() {
        // Subnet + geo_zone set but org empty still yields None — matches
        // the DAG-registration-record emission rule in `bin/elara_node.rs`
        // which also gates on organization being set.
        let config = NodeConfig {
            witness_organization: String::new(),
            witness_subnet: "10.0.0".into(),
            witness_geo_zone: "earth-us".into(),
            ..Default::default()
        };
        assert!(config.effective_witness_profile().is_none());
    }

    // ─── node_profile=light witness misconfig guard ──────────────────────
    // Codifies the lesson that a light profile on a witness silently bricks
    // the node. enforce_mainnet_safety must hard-abort the boot before
    // pull_loop even gets a chance to short-circuit.

    #[test]
    fn enforce_mainnet_safety_blocks_light_witness() {
        for ntype in ["witness", "anchor", "gateway", "genesis"] {
            let c = NodeConfig {
                node_type: ntype.into(),
                node_profile: "light".into(),
                ..Default::default()
            };
            let err = c.enforce_mainnet_safety().expect_err(
                &format!("node_type={ntype} with node_profile=light must refuse to start"),
            );
            assert!(err.contains("light"), "error must name the offending profile: {err}");
            assert!(err.contains(ntype), "error must name the offending node_type: {err}");
        }
    }

    #[test]
    fn enforce_mainnet_safety_passes_for_light_leaf() {
        // Leaf is the legitimate light-profile use case (phone-tier client).
        let c = NodeConfig {
            node_type: "leaf".into(),
            node_profile: "light".into(),
            ..Default::default()
        };
        assert!(c.enforce_mainnet_safety().is_ok());
    }

    #[test]
    fn validate_warns_light_archive_or_relay() {
        // Soft warning — contradictory but not fatal. Some operators may know
        // what they're doing (e.g. testing the light-mode path on an archive
        // box temporarily), so we don't hard-abort.
        for ntype in ["archive", "relay"] {
            let c = NodeConfig {
                admin_token: "a".repeat(40),
                genesis_authority: "abc123".into(),
                seed_peers: vec!["127.0.0.1:9473".into()],
                node_type: ntype.into(),
                node_profile: "light".into(),
                ..Default::default()
            };
            let warnings = c.validate();
            assert!(
                warnings.iter().any(|w| w.contains("light") && w.contains(ntype)),
                "validate must warn on light+{ntype}: {warnings:?}"
            );
        }
    }

    // ─── disk-pressure threshold sizing ────────────────────────────────────

    #[test]
    fn ops158_disk_pressure_avail_defaults_have_compaction_headroom() {
        // Mainnet defaults must leave room for RocksDB compaction churn.
        // A single L1→L2 compaction can write 256+ MB before the next
        // 60s sample tick; an earlier trip at 512 MB avail was the gap
        // that let a fleet outage happen even with the ingest gate live.
        let c = NodeConfig::default();
        assert_eq!(
            c.disk_pressure_avail_low_mb, 2048,
            "mainnet trip threshold should default to 2 GB"
        );
        assert_eq!(
            c.disk_pressure_avail_high_mb, 4096,
            "mainnet clear threshold should default to 4 GB"
        );
        assert!(
            c.disk_pressure_avail_high_mb > c.disk_pressure_avail_low_mb,
            "hysteresis: high watermark must exceed low watermark"
        );
    }

    #[test]
    fn ops158_disk_pressure_avail_env_override() {
        // Phone-tier override path: operator can shrink the threshold via
        // ELARA_DISK_PRESSURE_AVAIL_LOW_MB / ELARA_DISK_PRESSURE_AVAIL_HIGH_MB.
        // Setting low=0 disables the FS-avail trip entirely (live-bytes/cap
        // path remains).
        // SAFETY: env mutation is unsafe in Rust 2024 edition.
        unsafe {
            std::env::set_var("ELARA_DISK_PRESSURE_AVAIL_LOW_MB", "256");
            std::env::set_var("ELARA_DISK_PRESSURE_AVAIL_HIGH_MB", "768");
        }
        let mut c = NodeConfig::default();
        c.apply_env_overrides();
        assert_eq!(c.disk_pressure_avail_low_mb, 256);
        assert_eq!(c.disk_pressure_avail_high_mb, 768);
        unsafe {
            std::env::remove_var("ELARA_DISK_PRESSURE_AVAIL_LOW_MB");
            std::env::remove_var("ELARA_DISK_PRESSURE_AVAIL_HIGH_MB");
        }
    }

    #[test]
    fn b8_pq_handshake_concurrency_default_and_env() {
        // Default is the mainnet-correct 256 (B8 accept-path handshake limiter).
        let c = NodeConfig::default();
        assert_eq!(c.pq_handshake_concurrency, 256,
            "B8 default PQ handshake concurrency must be 256");
        // Operator override (phone-tier may lower, a high-fan-in relay may raise).
        // SAFETY: env mutation is unsafe in Rust 2024 edition.
        unsafe { std::env::set_var("ELARA_PQ_HANDSHAKE_CONCURRENCY", "64"); }
        let mut c64 = NodeConfig::default();
        c64.apply_env_overrides();
        assert_eq!(c64.pq_handshake_concurrency, 64, "env override must apply");
        // 0 must clamp to min 1 so the accept-path semaphore can never deadlock.
        unsafe { std::env::set_var("ELARA_PQ_HANDSHAKE_CONCURRENCY", "0"); }
        let mut c0 = NodeConfig::default();
        c0.apply_env_overrides();
        assert_eq!(c0.pq_handshake_concurrency, 1, "0 must clamp to min 1");
        unsafe { std::env::remove_var("ELARA_PQ_HANDSHAKE_CONCURRENCY"); }
    }

    #[test]
    fn stream_f1_pq_serve_concurrency_default_and_env() {
        // Default is the mainnet-correct 4096 (STREAM-F1 post-handshake
        // serve-connection population bound; 1/16th of LimitNOFILE=65536).
        let c = NodeConfig::default();
        assert_eq!(c.pq_serve_concurrency, 4096,
            "STREAM-F1 default PQ serve concurrency must be 4096");
        // Operator override (constrained hardware lowers, a relay raises).
        // SAFETY: env mutation is unsafe in Rust 2024 edition.
        unsafe { std::env::set_var("ELARA_PQ_SERVE_CONCURRENCY", "128"); }
        let mut c128 = NodeConfig::default();
        c128.apply_env_overrides();
        assert_eq!(c128.pq_serve_concurrency, 128, "env override must apply");
        // 0 must clamp to min 1 so the serve semaphore can never deadlock.
        unsafe { std::env::set_var("ELARA_PQ_SERVE_CONCURRENCY", "0"); }
        let mut c0 = NodeConfig::default();
        c0.apply_env_overrides();
        assert_eq!(c0.pq_serve_concurrency, 1, "0 must clamp to min 1");
        unsafe { std::env::remove_var("ELARA_PQ_SERVE_CONCURRENCY"); }
    }

    #[test]
    fn pq_heavy_read_concurrency_default_and_env() {
        // Default sentinel is 0 = "derive max_blocking/2 at construction".
        let c = NodeConfig::default();
        assert_eq!(c.pq_heavy_read_concurrency, 0,
            "default heavy-read concurrency must be the 0 = derive sentinel");
        assert_eq!(c.pq_heavy_read_wait_ms, 3000,
            "default heavy-read wait must be 3000ms (well under the 30s client timeout)");
        // Explicit operator override.
        // SAFETY: env mutation is unsafe in Rust 2024 edition.
        unsafe {
            std::env::set_var("ELARA_PQ_HEAVY_READ_CONCURRENCY", "6");
            std::env::set_var("ELARA_PQ_HEAVY_READ_WAIT_MS", "1500");
        }
        let mut c6 = NodeConfig::default();
        c6.apply_env_overrides();
        assert_eq!(c6.pq_heavy_read_concurrency, 6, "env override must apply");
        assert_eq!(c6.pq_heavy_read_wait_ms, 1500, "wait env override must apply");
        // 0 stays 0 here (unlike the handshake gate) — it is the derive sentinel,
        // not a deadlock hazard; the min-1 clamp lives at construction.
        unsafe { std::env::set_var("ELARA_PQ_HEAVY_READ_CONCURRENCY", "0"); }
        let mut c0 = NodeConfig::default();
        c0.apply_env_overrides();
        assert_eq!(c0.pq_heavy_read_concurrency, 0, "0 must stay the derive sentinel");
        unsafe {
            std::env::remove_var("ELARA_PQ_HEAVY_READ_CONCURRENCY");
            std::env::remove_var("ELARA_PQ_HEAVY_READ_WAIT_MS");
        }
    }

    #[test]
    fn pq_verify_concurrency_default_and_env() {
        // Default sentinel is 0 = "derive the read cap's complement half of the
        // blocking pool at construction" (≈ CPU count).
        let c = NodeConfig::default();
        assert_eq!(c.pq_verify_concurrency, 0,
            "default verify concurrency must be the 0 = derive sentinel");
        // Explicit operator override.
        // SAFETY: env mutation is unsafe in Rust 2024 edition.
        unsafe { std::env::set_var("ELARA_PQ_VERIFY_CONCURRENCY", "5"); }
        let mut c5 = NodeConfig::default();
        c5.apply_env_overrides();
        assert_eq!(c5.pq_verify_concurrency, 5, "env override must apply");
        // 0 stays 0 — derive sentinel, min-1 clamp lives at construction.
        unsafe { std::env::set_var("ELARA_PQ_VERIFY_CONCURRENCY", "0"); }
        let mut c0 = NodeConfig::default();
        c0.apply_env_overrides();
        assert_eq!(c0.pq_verify_concurrency, 0, "0 must stay the derive sentinel");
        unsafe { std::env::remove_var("ELARA_PQ_VERIFY_CONCURRENCY"); }
    }

    #[test]
    fn max_blocking_threads_for_matches_runtime_steps() {
        // The lib helper must reproduce the runtime builder's step function so
        // the HEAVY-read cap derivation cannot drift from the actual pool size.
        assert_eq!(super::max_blocking_threads_for(1), 4);
        assert_eq!(super::max_blocking_threads_for(2), 8);
        assert_eq!(super::max_blocking_threads_for(4), 16);
        assert_eq!(super::max_blocking_threads_for(16), 16);
    }

    #[test]
    fn ops162_phase6d_min_committee_size_default_is_seven() {
        let c = NodeConfig::default();
        assert_eq!(
            c.phase6d_min_committee_size,
            crate::network::zone_committee::DEFAULT_COMMITTEE_SIZE,
            "default must match DEFAULT_COMMITTEE_SIZE so mainnet is BFT-correct out of the box"
        );
    }

    #[test]
    fn ops162_phase6d_min_committee_size_env_override() {
        // Testnet override path: operator lowers the readiness floor so a
        // 6-node cluster can reach phase6d_ready (default 7 is unreachable
        // on small testnets). Zero-or-negative values are rejected — a
        // 0-threshold gate is a no-op that gives false-ready signals.
        // SAFETY: env mutation is unsafe in Rust 2024 edition.
        unsafe {
            std::env::set_var("ELARA_PHASE6D_MIN_COMMITTEE_SIZE", "3");
        }
        let mut c = NodeConfig::default();
        c.apply_env_overrides();
        assert_eq!(c.phase6d_min_committee_size, 3);

        // 0 must be rejected: keep the default in place rather than letting
        // the gate degenerate.
        unsafe {
            std::env::set_var("ELARA_PHASE6D_MIN_COMMITTEE_SIZE", "0");
        }
        let mut c2 = NodeConfig::default();
        c2.apply_env_overrides();
        assert_eq!(
            c2.phase6d_min_committee_size,
            crate::network::zone_committee::DEFAULT_COMMITTEE_SIZE,
            "ELARA_PHASE6D_MIN_COMMITTEE_SIZE=0 must be ignored"
        );
        unsafe {
            std::env::remove_var("ELARA_PHASE6D_MIN_COMMITTEE_SIZE");
        }
    }

    #[cfg(unix)]
    #[test]
    fn ops159_clamp_disk_cap_to_fs_clamps_when_over_70_pct() {
        // Default disk_cap_bytes=200 GB on a 24-38 GB VPS makes GC's
        // size-based retention compression unreachable. The clamp brings
        // cap to 70% of actual filesystem bytes so GC has a real target
        // to drive against.
        let tmp = tempfile::tempdir().unwrap();
        let mut c = NodeConfig {
            data_dir: tmp.path().to_path_buf(),
            disk_cap_bytes: u64::MAX / 2, // way over any real filesystem
            ..Default::default()
        };

        // Make sure no env override is set
        unsafe { std::env::remove_var("ELARA_DISK_CAP_BYTES"); }
        let result = c.clamp_disk_cap_to_fs();

        assert!(result.is_some(), "should clamp when cap exceeds 70% of FS");
        let (pre, post, total) = result.unwrap();
        assert_eq!(pre, u64::MAX / 2);
        assert!(post < pre, "post-clamp must be smaller");
        assert!(post <= total * 7 / 10, "post-clamp must be ≤ 70% of total");
        assert!(post >= total * 7 / 10 - 1, "post-clamp should equal 70% of total");
        assert_eq!(c.disk_cap_bytes, post, "config should mutate to post-clamp value");
    }

    #[cfg(unix)]
    #[test]
    fn ops159_clamp_disk_cap_to_fs_skips_when_under_threshold() {
        // If the configured cap is already below 70% of FS, clamp is a no-op.
        let tmp = tempfile::tempdir().unwrap();
        let mut c = NodeConfig {
            data_dir: tmp.path().to_path_buf(),
            disk_cap_bytes: 1024, // ~1 KB cap, way under any FS
            ..Default::default()
        };

        unsafe { std::env::remove_var("ELARA_DISK_CAP_BYTES"); }
        let result = c.clamp_disk_cap_to_fs();
        assert!(result.is_none(), "should NOT clamp when cap is already below 70% of FS");
        assert_eq!(c.disk_cap_bytes, 1024, "cap unchanged");
    }

    #[cfg(unix)]
    #[test]
    fn ops159_clamp_disk_cap_to_fs_respects_env_override() {
        // Operator opt-out: ELARA_DISK_CAP_BYTES is honored verbatim. The
        // assumption is the operator measured their disk and set the value
        // intentionally — we don't second-guess explicit operator input.
        let tmp = tempfile::tempdir().unwrap();
        let mut c = NodeConfig {
            data_dir: tmp.path().to_path_buf(),
            disk_cap_bytes: u64::MAX / 2,
            ..Default::default()
        };

        unsafe { std::env::set_var("ELARA_DISK_CAP_BYTES", "12345"); }
        let result = c.clamp_disk_cap_to_fs();
        assert!(result.is_none(), "env override path should bypass auto-clamp");
        // Note: clamp doesn't change disk_cap_bytes here — we only check that
        // the function returns None (no clamp). The env value would be applied
        // separately by apply_env_overrides BEFORE clamp_disk_cap_to_fs runs.
        unsafe { std::env::remove_var("ELARA_DISK_CAP_BYTES"); }
    }

    #[cfg(unix)]
    #[test]
    fn ops159_clamp_disk_cap_to_fs_skips_when_disabled() {
        // disk_cap_bytes=0 means size-based retention is disabled. Clamp is
        // a no-op so we don't accidentally re-enable size-based retention
        // for operators who explicitly opted out.
        let tmp = tempfile::tempdir().unwrap();
        let mut c = NodeConfig {
            data_dir: tmp.path().to_path_buf(),
            disk_cap_bytes: 0,
            ..Default::default()
        };

        unsafe { std::env::remove_var("ELARA_DISK_CAP_BYTES"); }
        let result = c.clamp_disk_cap_to_fs();
        assert!(result.is_none(), "should NOT clamp when size-based retention is disabled");
        assert_eq!(c.disk_cap_bytes, 0);
    }

    // ──────────────── constants + Default-shape tests ──────────────────────
    // Fixture-free constant + Default-shape pins. No file I/O, no env mutation,
    // no validate() round-trip — these tests defend the byte-exact values that
    // the testnet boot path and protocol-version handshake depend on.

    #[test]
    fn batch_b_testnet_genesis_authority_pin_empty_post_decommission() {
        // Pinned EMPTY: a zero-config node must NOT silently trust a genesis
        // authority key that can never sign. validate() turns the empty
        // default into a loud boot warning; real deployments set
        // genesis_authority explicitly.
        assert_eq!(TESTNET_GENESIS_AUTHORITY, "");
        let w = NodeConfig::default().validate();
        assert!(
            w.iter().any(|m| m.contains("genesis_authority")),
            "empty default genesis_authority must produce a validate() warning",
        );
    }

    #[test]
    fn batch_b_testnet_seed_peers_pin_empty_post_decommission_format_guard() {
        // Pinned EMPTY — no public testnet endpoints exist (dead IPs must not
        // ship as dial-targets). The format loop below stays armed as the
        // standing wire-format contract for whenever entries return: bare
        // `host:port`, no scheme (seed_base_url() prepends it at use site),
        // exactly one ':', parseable non-zero u16 port.
        assert!(TESTNET_SEED_PEERS.is_empty());
        for peer in TESTNET_SEED_PEERS {
            assert!(
                !peer.starts_with("http://") && !peer.starts_with("https://"),
                "seed peer must not carry scheme prefix: {peer}",
            );
            let colons = peer.matches(':').count();
            assert_eq!(colons, 1, "seed peer must have exactly one ':': {peer}");
            let (_host, port_str) = peer.rsplit_once(':').unwrap();
            let port: u16 = port_str
                .parse()
                .unwrap_or_else(|_| panic!("non-u16 port in seed peer: {peer}"));
            assert!(port > 0, "port=0 in seed peer: {peer}");
        }
        let w = NodeConfig::default().validate();
        assert!(
            w.iter().any(|m| m.contains("seed_peers")),
            "empty default seed_peers must produce a validate() warning",
        );
    }

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_protocol_version_const_pin_strict_u32_one_for_v1_release() {
        // `min_protocol_version` config gates peer compatibility. Drift in
        // PROTOCOL_VERSION (or its type) silently breaks the
        // `x-elara-protocol-version` header semantics across the fleet.
        const PIN: u32 = 1;
        assert_eq!(PROTOCOL_VERSION, PIN);
        let _: u32 = PROTOCOL_VERSION;
        assert!(PROTOCOL_VERSION > 0, "version 0 is reserved for unset");
    }

    #[test]
    fn batch_b_node_config_default_pin_load_bearing_safety_invariants() {
        // The Default impl ships the mainnet-correct values. Pin the
        // load-bearing invariants that the operator playbook relies on:
        // PQ-only data plane required, admin-on-main-port unless explicitly
        // separated, auto-witness on, testnet identity wired through.
        let c = NodeConfig::default();
        assert_eq!(c.listen_addr, "0.0.0.0:9473");
        assert!(c.admin_listen_addr.is_empty(), "default admin = on main port");
        assert!(c.require_pq_transport, "PQ-R1: mainnet-correct = required");
        assert_eq!(c.pq_port_offset, 100, "PQ port = classical + 100");
        assert_eq!(c.node_type, "witness");
        assert!(c.auto_witness, "auto_witness default = true");
        assert_eq!(c.gossip_pull_interval_secs, 30);
        assert_eq!(c.epoch_seal_interval_secs, 60);
        assert_eq!(c.witness_reward_micros, 1_000_000_000, "1 beat in base units (10^9/beat)");
        assert_eq!(c.genesis_authority, TESTNET_GENESIS_AUTHORITY);
        assert_eq!(c.min_protocol_version, 0, "0 = accept all; mainnet default open");
    }

    #[test]
    fn batch_b_node_config_default_seed_peers_owned_strings_independent_of_const() {
        // Default's seed_peers is an owned Vec<String> derived from the
        // &'static [&str] constant. Mutating the runtime Vec must NOT touch
        // the source constant — pin owned-storage semantics so callers can
        // safely splice in extra peers per-deployment.
        let mut c = NodeConfig::default();
        assert_eq!(c.seed_peers.len(), TESTNET_SEED_PEERS.len());
        for (i, peer) in TESTNET_SEED_PEERS.iter().enumerate() {
            assert_eq!(&c.seed_peers[i], peer, "seed_peers[{i}] drift from const");
        }
        // Mutate the runtime list — push, clear, then re-default — and
        // verify the const list is untouched.
        c.seed_peers.push("test:9999".into());
        c.seed_peers.clear();
        assert_eq!(TESTNET_SEED_PEERS.len(), 0, "const must not have been mutated");

        // Fresh default re-derives from the const (empty post-decommission).
        let c2 = NodeConfig::default();
        assert_eq!(c2.seed_peers.len(), TESTNET_SEED_PEERS.len());
    }

    #[test]
    fn validate_sovereign_discovery_off_warnings() {
        // REALMS P1 slice (c): sovereign + seeds → warn the seeds will
        // never be dialed; sovereign + empty seeds is by-design silence,
        // not a "will not discover" warning.
        let mut c = NodeConfig {
            network_realm: NetworkRealm::Sovereign,
            seed_peers: vec!["10.0.0.1:9473".into()],
            ..Default::default()
        };
        let w = c.validate();
        assert!(
            w.iter().any(|m| m.contains("sovereign") && m.contains("never dial")),
            "sovereign with seeds must warn",
        );
        c.seed_peers.clear();
        let w = c.validate();
        assert!(
            !w.iter().any(|m| m.contains("no seed_peers")),
            "sovereign with empty seeds is by design — no discovery warning",
        );
    }

    #[test]
    fn test_use_committee_v2_default_false_and_env_override() {
        // Default must be false — fleet flag-on step is an explicit operator
        // action after staked anchors > 10 (Gap 5, Steps 4+5).
        let c = NodeConfig::default();
        assert!(!c.use_committee_v2, "default must be false until fleet flag-on");

        let mut c2 = NodeConfig::default();
        for truthy in ["1", "true", "TRUE", "on", "yes"] {
            std::env::set_var("ELARA_USE_COMMITTEE_V2", truthy);
            c2.apply_env_overrides();
            assert!(c2.use_committee_v2, "ELARA_USE_COMMITTEE_V2={truthy} must enable v2");
            c2.use_committee_v2 = false; // reset for next iteration
        }
        std::env::set_var("ELARA_USE_COMMITTEE_V2", "0");
        c2.apply_env_overrides();
        assert!(!c2.use_committee_v2, "ELARA_USE_COMMITTEE_V2=0 must keep v2 off");
        std::env::remove_var("ELARA_USE_COMMITTEE_V2");
    }

    #[test]
    fn test_uptime_vesting_enabled_default_false_and_env_override() {
        // Default MUST be false: the loop mutates the SMT-leaf `uptime_secs`
        // out-of-band (silent fork). Only an explicit operator opt-in, after a
        // record-driven redesign, may enable it.
        let c = NodeConfig::default();
        assert!(
            !c.uptime_vesting_enabled,
            "default must be false — out-of-band SMT mutation fork"
        );
        let mut c2 = NodeConfig::default();
        for truthy in ["1", "true", "TRUE", "on", "yes"] {
            std::env::set_var("ELARA_UPTIME_VESTING_ENABLED", truthy);
            c2.apply_env_overrides();
            assert!(c2.uptime_vesting_enabled, "ELARA_UPTIME_VESTING_ENABLED={truthy} must enable");
            c2.uptime_vesting_enabled = false;
        }
        std::env::set_var("ELARA_UPTIME_VESTING_ENABLED", "0");
        c2.apply_env_overrides();
        assert!(!c2.uptime_vesting_enabled, "=0 must keep it off");
        std::env::remove_var("ELARA_UPTIME_VESTING_ENABLED");
    }

    // ---- REALMS P1 slice (a): NetworkRealm config enum (zero runtime delta) ----

    /// validate() warnings that belong to the realm checks specifically.
    fn realm_warnings(c: &NodeConfig) -> Vec<String> {
        c.validate()
            .into_iter()
            .filter(|w| w.contains("network_realm"))
            .collect()
    }

    #[test]
    fn realm_default_is_open_zero_delta() {
        // Slice (a) contract: absent config == Open == today's behavior.
        let c = NodeConfig::default();
        assert_eq!(c.network_realm, NetworkRealm::Open);
        assert!(c.network_realm.discovery_enabled());
        assert_eq!(c.network_realm.label(), "open");
        assert_eq!(c.network_realm.federated_root_pk(), None);
        // A TOML file without the field deserializes to Open too.
        let c: NodeConfig = toml::from_str("").expect("empty config parses");
        assert_eq!(c.network_realm, NetworkRealm::Open);
        // And Open emits no realm warnings.
        assert!(realm_warnings(&NodeConfig::default()).is_empty());
    }

    #[test]
    fn realm_toml_parses_all_three_modes() {
        let c: NodeConfig = toml::from_str("network_realm = { mode = \"open\" }").unwrap();
        assert_eq!(c.network_realm, NetworkRealm::Open);

        // Inline-table and [section] forms must both work for federated.
        let c: NodeConfig =
            toml::from_str("network_realm = { mode = \"federated\", root_pk = \"abcd\" }")
                .unwrap();
        assert_eq!(c.network_realm.federated_root_pk(), Some("abcd"));
        assert_eq!(c.network_realm.label(), "federated");
        let c: NodeConfig =
            toml::from_str("[network_realm]\nmode = \"federated\"\nroot_pk = \"abcd\"\n")
                .unwrap();
        assert_eq!(c.network_realm.federated_root_pk(), Some("abcd"));

        let c: NodeConfig = toml::from_str("network_realm = { mode = \"sovereign\" }").unwrap();
        assert_eq!(c.network_realm, NetworkRealm::Sovereign);
        assert!(!c.network_realm.discovery_enabled(), "sovereign drops discovery");
    }

    #[test]
    fn realm_env_parts_parse_and_reject() {
        assert_eq!(NetworkRealm::from_env_parts("open", None), Some(NetworkRealm::Open));
        assert_eq!(
            NetworkRealm::from_env_parts(" SOVEREIGN ", None),
            Some(NetworkRealm::Sovereign),
        );
        assert_eq!(
            NetworkRealm::from_env_parts("federated", Some("aa".into())),
            Some(NetworkRealm::Federated { root_pk: "aa".into() }),
        );
        // Federated without a root key still constructs (empty pk) so
        // validate() warns loudly instead of the node silently staying Open.
        assert_eq!(
            NetworkRealm::from_env_parts("federated", None),
            Some(NetworkRealm::Federated { root_pk: String::new() }),
        );
        // Typos fail closed: caller keeps the configured realm.
        assert_eq!(NetworkRealm::from_env_parts("soverein", None), None);
        assert_eq!(NetworkRealm::from_env_parts("", None), None);
    }

    #[test]
    fn realm_env_override_applies() {
        // Same set/restore discipline as the other env tests here; the
        // ELARA_REALM* keys are touched only by this test (no parallel race).
        let prev_mode = std::env::var("ELARA_REALM").ok();
        let prev_pk = std::env::var("ELARA_REALM_ROOT_PK").ok();

        std::env::set_var("ELARA_REALM", "federated");
        std::env::set_var("ELARA_REALM_ROOT_PK", "deadbeef");
        let mut c = NodeConfig::default();
        c.apply_env_overrides();
        assert_eq!(c.network_realm.federated_root_pk(), Some("deadbeef"));

        std::env::set_var("ELARA_REALM", "sovereign");
        c.apply_env_overrides();
        assert_eq!(c.network_realm, NetworkRealm::Sovereign);

        // Unrecognized value keeps the prior realm (fail-closed).
        std::env::set_var("ELARA_REALM", "wide-open");
        c.apply_env_overrides();
        assert_eq!(c.network_realm, NetworkRealm::Sovereign);

        match prev_mode {
            Some(v) => std::env::set_var("ELARA_REALM", v),
            None => std::env::remove_var("ELARA_REALM"),
        }
        match prev_pk {
            Some(v) => std::env::set_var("ELARA_REALM_ROOT_PK", v),
            None => std::env::remove_var("ELARA_REALM_ROOT_PK"),
        }
    }

    #[test]
    fn realm_cert_path_defaults_resolution_and_federated_warning() {
        // Default: empty, and resolve_paths leaves empty alone.
        let mut c = NodeConfig::default();
        assert!(c.realm_membership_cert_path.as_os_str().is_empty());
        c.resolve_paths();
        assert!(c.realm_membership_cert_path.as_os_str().is_empty());

        // Relative path resolves against data_dir.
        let mut c = NodeConfig {
            realm_membership_cert_path: PathBuf::from("realm-cert.json"),
            ..Default::default()
        };
        c.resolve_paths();
        assert!(
            c.realm_membership_cert_path.starts_with(&c.data_dir),
            "relative cert path must join data_dir: {:?}",
            c.realm_membership_cert_path,
        );

        // Federated + no cert path warns (one-way membership); setting the
        // path clears that specific warning.
        let mut c = NodeConfig {
            network_realm: NetworkRealm::Federated {
                root_pk: "00".repeat(crate::crypto::pqc::DILITHIUM3_PUBLIC_KEY_LEN),
            },
            ..Default::default()
        };
        assert!(c
            .validate()
            .iter()
            .any(|w| w.contains("realm_membership_cert_path is empty")));
        c.realm_membership_cert_path = PathBuf::from("/etc/elara/realm-cert.json");
        assert!(!c
            .validate()
            .iter()
            .any(|w| w.contains("realm_membership_cert_path is empty")));
    }

    #[test]
    fn realm_validate_warns_on_unusable_federated_root() {
        // This test pins ROOT-KEY validation only — set a cert path so the
        // separate federated-without-own-cert warning (slice b3) stays out
        // of the assertion windows.
        let mut c = NodeConfig {
            realm_membership_cert_path: PathBuf::from("/etc/elara/realm-cert.json"),
            network_realm: NetworkRealm::Federated { root_pk: String::new() },
            ..Default::default()
        };
        let w = realm_warnings(&c);
        assert_eq!(w.len(), 1, "empty root_pk must warn: {w:?}");
        assert!(w[0].contains("empty root_pk"));

        c.network_realm = NetworkRealm::Federated { root_pk: "zzzz".into() };
        let w = realm_warnings(&c);
        assert!(w[0].contains("not valid hex"), "{w:?}");

        c.network_realm = NetworkRealm::Federated { root_pk: "abcd".into() };
        let w = realm_warnings(&c);
        assert!(w[0].contains("expected"), "wrong-length pk must warn: {w:?}");

        // A well-formed (correct-length hex) Dilithium3 root is quiet.
        c.network_realm = NetworkRealm::Federated {
            root_pk: "00".repeat(crate::crypto::pqc::DILITHIUM3_PUBLIC_KEY_LEN),
        };
        assert!(realm_warnings(&c).is_empty(), "well-formed root_pk is quiet");

        c.network_realm = NetworkRealm::Sovereign;
        assert!(realm_warnings(&c).is_empty(), "sovereign has no realm warnings");
    }
}
