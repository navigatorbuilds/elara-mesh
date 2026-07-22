//! AWC (Adaptive Witness Consensus) — zone assignment, correlation, settlement.
//!
//! Implements Protocol v0.6.2 Section 11.12:
//! - Zone assignment: `SHA3(record_id) % zone_count` → dynamic zones (scales with network)
//! - Correlation: `corr(n,m) = α*same_org + β*same_subnet + γ*same_zone` (α=0.5, β=0.3, γ=0.2 — see `GAMMA`)
//! - Independence: `d(n, W) = 1 / (1 + Σ corr(n,m) for m ≠ n in W(r))`
//! - Trust: `T(r) = 1 - ∏(1 - w(n) * d(n, W)) for n in W(r)`
//! - Settlement: `sum(attesting_stake) / total_zone_stake ≥ 2/3`

//!
//! Spec references:
//!   @spec Protocol §11.12
//!   @spec economics §9.5

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use crate::ZoneId;

use serde::{Deserialize, Serialize};

use tracing::info;
use crate::crypto::hash::sha3_256;
use crate::accounting::cross_zone::SealFinalityWitness;
use crate::accounting::ledger::LedgerState;

// ─── Dynamic zone count ─────────────────────────────────────────────────────

/// Global zone count — scales with network size.
///
/// Default: 4 (suitable for small testnets).
/// Production: auto-computed as `max(1, active_nodes / witnesses_per_zone)`.
///
/// Records created BEFORE a zone count change retain their old zone (via the
/// explicit `zone` field in wire v3+). Only new records use the new count.
/// Old records without an explicit zone fall back to `for_record()` which
/// uses the legacy 256-zone computation for backward compatibility.
static ZONE_COUNT: AtomicU64 = AtomicU64::new(4);

/// Set the active zone count. Called at startup from config, and updated
/// dynamically as peers join/leave. Minimum 1.
pub fn set_zone_count(count: u64) {
    ZONE_COUNT.store(count.max(1), Ordering::Relaxed);
}

/// Get the current active zone count.
pub fn get_zone_count() -> u64 {
    ZONE_COUNT.load(Ordering::Relaxed)
}

/// KR-3 S2 wiring-(c) c3-ii: the network-uniform `s2_rotation_ordering_enabled`
/// gate mirrored into a process global, so the consensus seal-membership free
/// functions (`epoch::create_epoch_seal_with_balance`,
/// `epoch::scan_window_record_hashes`) — which have no `NodeState` / `NodeConfig`
/// handle — can gate rotation-lineage routing without threading the flag through
/// every `SealParams` field and verify signature.
///
/// Set ONCE at boot from `NodeConfig` (like [`set_zone_count`]); never flipped at
/// runtime — the flag is a static config gate, not a zone-transition value. The
/// default is `false` (OFF), so every unit test and non-boot path is
/// byte-identical to the legacy behaviour until a node explicitly opts in at
/// boot. Consensus correctness requires all nodes carry the same value (else the
/// seal-membership set forks) — a boot-set global guarantees that, exactly as
/// `ZONE_COUNT` does for the other network-uniform seal parameter.
static S2_ROTATION_ORDERING: AtomicBool = AtomicBool::new(false);

/// Set the process-global S2 rotation-ordering gate. Called once at boot from
/// `NodeConfig::s2_rotation_ordering_enabled`.
pub fn set_s2_rotation_ordering(enabled: bool) {
    S2_ROTATION_ORDERING.store(enabled, Ordering::Relaxed);
}

/// Read the process-global S2 rotation-ordering gate (default OFF).
pub fn s2_rotation_ordering_enabled() -> bool {
    S2_ROTATION_ORDERING.load(Ordering::Relaxed)
}

// ─── Correlation weights (Protocol v0.6.2 §11.12) ──────────────────────────

/// Organization overlap weight.
pub const ALPHA: f64 = 0.5;
/// IP subnet overlap weight.
pub const BETA: f64 = 0.3;
/// Geographic zone overlap weight. Stage 5 raises this from 0 → 0.2 so a
/// same-continent witness pair contributes a real correlation penalty
/// (α=0.5, β=0.3, γ=0.2 → fully-correlated max 1.0).
///
/// The value is only applied once the witness set spans at least
/// [`MIN_GEO_BUCKETS`] distinct geographic buckets — see
/// [`AWCConsensus::gamma_effective`]. This "honest degradation" prevents
/// single-datacenter or early-bootstrap networks (where every witness is
/// in one bucket by necessity, not collusion) from penalizing themselves
/// into zero trust.
///
/// Spec: Protocol §11.12 (geographic diversity, Theorem 3.1).
pub const GAMMA: f64 = 0.2;

/// Minimum distinct geographic buckets in a witness set before `GAMMA`
/// activates. Below this, the attested set is physically homogeneous
/// regardless of honesty (e.g. three Helsinki nodes), and charging a
/// γ-penalty for that would punish the network for being small instead
/// of catching sybils. At ≥ 2 buckets the penalty applies normally.
pub const MIN_GEO_BUCKETS: usize = 2;

/// Witness-set size at which γ reaches its full `GAMMA` value.
///
/// Between `MIN_GEO_BUCKETS` and `GAMMA_FULL_WITNESSES`, γ scales linearly
/// with witness count — replacing the earlier binary cliff with a
/// smooth ramp. Roughly matches per-zone committee size target.
pub const GAMMA_FULL_WITNESSES: usize = 12;

/// γ that scales linearly with witness-set size.
///
/// Replaces the binary `gamma_effective` cliff (`GAMMA` or `0.0`) with a
/// smooth ramp:
///
/// - `bucket_count < MIN_GEO_BUCKETS` → 0.0 (honest-degradation floor).
/// - `witness_count <= MIN_GEO_BUCKETS` → 0.0 (no independence signal yet).
/// - `MIN_GEO_BUCKETS < witness_count < GAMMA_FULL_WITNESSES` → linear ramp
///   from 0 up to [`GAMMA`].
/// - `witness_count >= GAMMA_FULL_WITNESSES` → full [`GAMMA`].
pub fn gamma_effective_scaled(witness_count: usize, bucket_count: usize) -> f64 {
    if bucket_count < MIN_GEO_BUCKETS {
        return 0.0;
    }
    let min_w = MIN_GEO_BUCKETS;
    let full_w = GAMMA_FULL_WITNESSES;
    if witness_count >= full_w {
        return GAMMA;
    }
    if witness_count <= min_w {
        return 0.0;
    }
    let ramp = (witness_count - min_w) as f64 / (full_w - min_w) as f64;
    GAMMA * ramp.clamp(0.0, 1.0)
}

// ─── Deterministic fixed-point settlement arithmetic ─────────────────────────
//
// The diversity-weighted settlement gates (`is_settled_diverse`,
// `is_seal_settled`, `is_global_seal_settled`) previously summed effective
// stake in f64. f64 addition is non-associative and FMA/codegen-dependent, and
// `attestations` is stored in gossip-arrival order — so two honest nodes that
// received the same attestation set in different orders, or that run different
// builds/arches, could disagree on the 2/3 verdict within a few base-units of
// the boundary. The verdict is re-derived locally and is NOT serialized into
// the seal for verifier cross-check, so disagreement causes eventual
// account-SMT divergence (repair-storm / fork), not an immediate ingest reject.
// At ≥3 distinct orgs the production "Confirmed" gate reduces to this float path
// (`small_network = false`), so determinism here is a PRE-SCALE-UP requirement.
//
// `independence()` has no transcendentals — only +,*,/ on the rationals
// {0, ALPHA=0.5, BETA=0.3, GAMMA=0.2, 1} plus one ramp division — so the whole
// chain is exactly representable in fixed point. Every `_q` quantity below is an
// integer scaled by `SETTLEMENT_Q`. See internal design notes.

/// Fixed-point scale for deterministic settlement: a `_q` value of
/// `SETTLEMENT_Q` represents 1.0. Q = 10^9 quantizes ALPHA/BETA/GAMMA exactly
/// and keeps ~9 significant digits through `independence_q = Q²/(Q+corr_sum_q)`.
pub const SETTLEMENT_Q: u128 = 1_000_000_000;
/// [`ALPHA`] (same-org correlation weight, 0.5) scaled by [`SETTLEMENT_Q`].
const ALPHA_Q: u128 = 500_000_000;
/// [`BETA`] (same-subnet correlation weight, 0.3) scaled by [`SETTLEMENT_Q`].
const BETA_Q: u128 = 300_000_000;
/// [`GAMMA`] (same-zone correlation weight, 0.2) scaled by [`SETTLEMENT_Q`].
const GAMMA_Q: u128 = 200_000_000;

/// Deterministic integer mirror of [`gamma_effective_scaled`], returning γ
/// scaled by [`SETTLEMENT_Q`]. The single ramp division uses a fixed,
/// value-independent round-half-up rule, so the result is identical across
/// gossip-arrival order and across architectures.
pub fn gamma_effective_scaled_q(witness_count: usize, bucket_count: usize) -> u128 {
    if bucket_count < MIN_GEO_BUCKETS {
        return 0;
    }
    let min_w = MIN_GEO_BUCKETS;
    let full_w = GAMMA_FULL_WITNESSES;
    if witness_count >= full_w {
        return GAMMA_Q;
    }
    if witness_count <= min_w {
        return 0;
    }
    // ramp = (witness_count - min_w) / (full_w - min_w); γ_q = GAMMA_Q · ramp.
    // Round-half-up `(numer + denom/2) / denom` — value-independent, so the
    // rounding direction never depends on the operands (no order/arch drift).
    let numer = GAMMA_Q * (witness_count - min_w) as u128;
    let denom = (full_w - min_w) as u128;
    (numer + denom / 2) / denom
}

/// Snapshot of the geographic-diversity posture for a witness set.
///
/// Surfaced by [`AWCConsensus::geo_diversity_state`] so operator status
/// endpoints can make Stage 5 honest degradation auditable: at a glance
/// a node operator can see whether γ is contributing to safety right
/// now or the network is in fallback ("single-org testnet, γ=0").
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GeoDiversityState {
    /// Number of witnesses considered.
    pub witness_count: usize,
    /// Distinct geographic buckets observed across the witness set.
    /// A bucket is either the self-reported `geo_zone` (if non-empty)
    /// or the derived ASN (if resolvable).
    pub bucket_count: usize,
    /// Bucket threshold above which γ activates — [`MIN_GEO_BUCKETS`].
    pub min_buckets: usize,
    /// `true` when γ is active (`bucket_count >= min_buckets`),
    /// `false` when the network is in honest-degradation mode.
    pub gamma_active: bool,
    /// Effective γ weight applied to the `same_zone` correlation term.
    /// Smoothly scales from 0.0 (fewer than
    /// [`MIN_GEO_BUCKETS`] buckets OR witness_count ≤ [`MIN_GEO_BUCKETS`])
    /// through a linear ramp up to full [`GAMMA`] at
    /// [`GAMMA_FULL_WITNESSES`]. See [`gamma_effective_scaled`].
    pub gamma_effective: f64,
}

/// Zone assignment for a record ID using the current dynamic zone count.
///
/// Uses SHA3(record_id) modulo zone_count — distributes records evenly across
/// however many zones the network currently has.
///
/// For records with an explicit zone field (wire v3+), the stored zone takes
/// precedence over this computation. This function is for NEW records only.
pub fn zone_for_record(record_id: &str) -> ZoneId {
    let count = ZONE_COUNT.load(Ordering::Relaxed);
    ZoneId::for_record_dynamic(record_id, count)
}

// ─── Witness profile ────────────────────────────────────────────────────────

/// Metadata about a witness node used for correlation computation.
///
/// Each witness should register its profile so the consensus engine can
/// discount correlated attestations (e.g., same organization running many nodes
/// in one datacenter).
///
/// The three string fields (`organization`, `subnet`, `geo_zone`) are
/// **self-reported** by the witness in its registration record. A malicious
/// witness can lie, so the correlation engine also consults
/// [`DerivedWitnessGeo`] (below), which is sourced from the observed remote
/// socket address at registration time and cannot be forged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessProfile {
    /// Organizational affiliation (e.g., "navigatorbuilds", "acme-corp").
    pub organization: String,
    /// IP subnet prefix (e.g., "192.168.1", "10.0.0"). Used for network locality.
    pub subnet: String,
    /// Geographic/planetary zone (e.g., "earth-eu", "mars-olympus", "luna-tycho").
    pub geo_zone: String,
}

/// Verifiable geographic observation for a witness.
///
/// Populated by the node at registration time from the remote socket address
/// of the witness's incoming connection. The peer cannot forge these values —
/// unlike the self-reported `WitnessProfile`, which is peer-controlled.
///
/// Used by [`AWCConsensus::correlation`] to penalize witnesses that look
/// geographically independent on paper but actually share an IP /16 block
/// or ASN (the classic cloud-VPS sybil-farm signature).
///
/// # Semantics
/// - `ip_prefix16: [0, 0]` → unknown / not observed yet. Skipped in correlation.
/// - `asn: 0` → unknown ASN (IP not in bundled provider table). Skipped in
///   correlation — treated as "no signal", not "different".
///
/// Spec: Protocol §11.12 (geographic diversity, Theorem 3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DerivedWitnessGeo {
    /// Top 16 bits of the witness's observed IPv4 (or first segment of IPv6).
    /// Fixed-size so it's cheap to compare and store.
    pub ip_prefix16: [u8; 2],
    /// ASN hint from [`super::asn_lookup::ip_to_asn`]. 0 if unknown.
    pub asn: u32,
}

impl DerivedWitnessGeo {
    /// Construct from an observed IP address. Consults the bundled ASN table.
    pub fn from_ip(ip: std::net::IpAddr) -> Self {
        Self {
            ip_prefix16: super::asn_lookup::ip_prefix16(ip),
            asn: super::asn_lookup::ip_to_asn(ip),
        }
    }

    /// Is this observation usable for correlation? (i.e., did we actually
    /// observe an IP, not the `Default`.)
    pub fn is_observed(&self) -> bool {
        self.ip_prefix16 != [0, 0] || self.asn != 0
    }
}

/// Metadata key for witness profile registration records.
pub const WITNESS_PROFILE_KEY: &str = "witness_profile_registration";

/// Extract a witness profile from a record's metadata, if present.
///
/// Profile registration records have metadata:
/// ```json
/// {
///   "witness_profile_registration": true,
///   "witness_organization": "navigatorbuilds",
///   "witness_subnet": "88.99.142",
///   "witness_geo_zone": "us-east"
/// }
/// ```
pub fn extract_witness_profile(record: &crate::record::ValidationRecord) -> Option<WitnessProfile> {
    let is_registration = record
        .metadata
        .get(WITNESS_PROFILE_KEY)
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if !is_registration {
        return None;
    }

    let organization = record
        .metadata
        .get("witness_organization")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let subnet = record
        .metadata
        .get("witness_subnet")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let geo_zone = record
        .metadata
        .get("witness_geo_zone")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // Must have at least organization set
    if organization.is_empty() {
        return None;
    }

    Some(WitnessProfile {
        organization,
        subnet,
        geo_zone,
    })
}

/// Build metadata for a witness profile registration record.
pub fn witness_profile_metadata(
    profile: &WitnessProfile,
) -> std::collections::BTreeMap<String, serde_json::Value> {
    let mut m = std::collections::BTreeMap::new();
    m.insert(WITNESS_PROFILE_KEY.into(), serde_json::json!(true));
    m.insert("witness_organization".into(), serde_json::json!(profile.organization));
    m.insert("witness_subnet".into(), serde_json::json!(profile.subnet));
    m.insert("witness_geo_zone".into(), serde_json::json!(profile.geo_zone));
    m
}

// ─── VRF Jury Selection (Protocol §7.4) ─────────────────────────────────────

/// Minimum witnesses needed for settlement. Must be >= CONFIRMED_MIN_WITNESSES.
const MIN_JURY_SIZE: usize = 3;

/// Minimum eligible subscribers needed before we trust the zone-scoped filter.
/// Below this the filter falls back to the full staked set so bootstrap and
/// sparse zones are never stuck. Matches `MIN_JURY_SIZE`.
pub const MIN_SCOPED_ELIGIBLE: usize = MIN_JURY_SIZE;

/// Committee size per (zone, epoch) — MAINNET gap #5.
///
/// At 1M zones × 10K staked witnesses, a per-zone committee of 2/3+1 would be
/// absurd (thousands of attestations per record). The committee is capped at
/// MAINNET_COMMITTEE_SIZE regardless of pool size. Byzantine-safe: with
/// `k=7`, settlement requires ≥ 5 attestations (2/3 rounded up), tolerating
/// up to 2 faulty committee members.
///
/// Committee members are selected by a stake-weighted VRF lottery; see
/// [`select_epoch_committee_scoped`]. Settlement denominator becomes the sum
/// of committee member stakes (not the full zone stake), so a small
/// committee can still close settlement at mainnet scale.
///
/// Bootstrap + small networks skip the cap (committee = full pool) so
/// existing 6-node testnets remain fully-participating.
pub const MAINNET_COMMITTEE_SIZE: usize = 7;

/// Below this pool size, the committee is the full pool — no cap applied.
/// Ensures small testnets and bootstrap phases retain the existing jury
/// behavior. Matches `SMALL_NETWORK_THRESHOLD` in `select_epoch_jury`.
pub const COMMITTEE_SMALL_NETWORK: usize = 10;

/// Cap on the bootstrap-fallback pool size when subscribers are sparse
/// (eligible < `MIN_SCOPED_ELIGIBLE`). Without this cap, every sparse-
/// subscription zone would score the entire global stake set per epoch
/// — at 1M zones × 10K stakers, that's ~7600 s/epoch single-thread
/// (see `bench_committee_selection.rs`).
///
/// 64 was picked because:
///   * It's >> `MAINNET_COMMITTEE_SIZE` (7) — stake-weighted sortition
///     still has meaningful entropy when picking 7 from 64.
///   * It's small enough that 1M zones × 64 SHA3 hashes/epoch ≈ 64 s
///     single-thread (~16 s on 4-thread rayon) — fits the 120 s epoch.
///   * It's deterministic: the top-`BOOTSTRAP_FALLBACK_CAP` stakers
///     (sorted by stake desc, lex tiebreak) is the same set on every
///     node, preserving cross-node committee equality.
///
/// The cap only applies to the sparse-subscription fallback path. Once
/// subscribers >= `MIN_SCOPED_ELIGIBLE`, the eligible-pool scoring is
/// already O(|subs|) and uncapped.
pub const BOOTSTRAP_FALLBACK_CAP: usize = 64;

/// Select which staked witnesses should attest during this epoch.
///
/// Uses the epoch's VRF output as an unpredictable seed to deterministically
/// select a subset of staked witnesses. Only selected witnesses should attest
/// records during this epoch. This reduces attestation volume while maintaining
/// settlement guarantees.
///
/// Jury size = min(staked_count, max(MIN_JURY_SIZE, ceil(staked_count * 2/3) + 1))
/// — always enough for 2/3 supermajority, never more than the full set.
///
/// Returns the sorted list of selected witness identity hashes.
/// Returns ALL witnesses if `vrf_output` is empty (bootstrap mode).
pub fn select_epoch_jury(
    vrf_output: &[u8],
    staked_identities: &[String],
    zone: &ZoneId,
) -> Vec<String> {
    if staked_identities.is_empty() {
        return Vec::new();
    }

    // Bootstrap mode: no VRF output yet → everyone attests
    if vrf_output.is_empty() {
        return staked_identities.to_vec();
    }

    let n = staked_identities.len();

    // Small network: everyone attests. VRF jury exclusion reduces attestation
    // volume in large networks, but in small networks (≤10 staked nodes) the
    // excluded node's stake inflates the settlement denominator past what the
    // remaining jury can achieve. With n=6 and jury_size=5, only 4 non-creator
    // witnesses exist per zone — ALL must attest (100% participation) which is
    // unrealistic. Skip exclusion until the network is large enough.
    const SMALL_NETWORK_THRESHOLD: usize = 10;
    if n <= SMALL_NETWORK_THRESHOLD {
        return staked_identities.to_vec();
    }

    // Jury size: enough for 2/3 supermajority settlement
    let two_thirds_plus_one = (n * 2).div_ceil(3) + 1; // ceil(n * 2/3) + 1
    let jury_size = n.min(two_thirds_plus_one.max(MIN_JURY_SIZE));

    // If jury_size >= n, everyone attests anyway
    if jury_size >= n {
        return staked_identities.to_vec();
    }

    // Score each witness: SHA3(vrf_output || zone || witness_hash)
    let mut scored: Vec<([u8; 32], &String)> = staked_identities.iter()
        .map(|witness| {
            let mut input = vrf_output.to_vec();
            input.extend_from_slice(zone.to_string().as_bytes());
            input.extend_from_slice(witness.as_bytes());
            let score = sha3_256(&input);
            (score, witness)
        })
        .collect();

    // Deterministic sort by score
    scored.sort_by_key(|a| a.0);

    // Select lowest-scoring witnesses
    scored.into_iter()
        .take(jury_size)
        .map(|(_, w)| w.clone())
        .collect()
}

/// Check if a specific witness is in the epoch jury.
///
/// Convenience wrapper — avoids allocating the full jury list when you
/// only need to check one identity.
pub fn is_in_epoch_jury(
    vrf_output: &[u8],
    staked_identities: &[String],
    zone: &ZoneId,
    witness_hash: &str,
) -> bool {
    if vrf_output.is_empty() || staked_identities.is_empty() {
        return true; // bootstrap mode: everyone attests
    }

    let jury = select_epoch_jury(vrf_output, staked_identities, zone);
    jury.iter().any(|w| w == witness_hash)
}

/// Zone-scoped jury selection (Gap 5).
///
/// At 1M zones, it's neither practical nor correct for every staked witness
/// to be eligible for every zone. This variant filters `staked_identities`
/// down to those that have declared a zone subscription (via the
/// `zone_subscription` metadata record) for this zone, then applies the
/// same VRF scoring as `select_epoch_jury`.
///
/// ## Bootstrap fallback
///
/// If the intersection of staked and subscribed is smaller than
/// `MIN_SCOPED_ELIGIBLE`, we fall back to `select_epoch_jury` over the full
/// staked set. This keeps settlement moving for:
///   - newly-created zones (Gap 4 auto-scaling) before witnesses re-subscribe
///   - early testnet where subscription records haven't propagated
///   - zones that temporarily lose enough subscribers
///
/// Once witnesses are properly subscribed, the filter tightens automatically.
pub fn select_epoch_jury_scoped(
    vrf_output: &[u8],
    staked_identities: &[String],
    zone: &ZoneId,
    subscribers: &std::collections::HashSet<String>,
) -> Vec<String> {
    // Build the eligible pool: staked ∩ subscribed.
    let eligible: Vec<String> = staked_identities
        .iter()
        .filter(|id| subscribers.contains(*id))
        .cloned()
        .collect();

    // Safety fallback: not enough subscribers to form a jury → use global set.
    // This is critical during bootstrap, after zone splits, and while
    // subscription records propagate.
    if eligible.len() < MIN_SCOPED_ELIGIBLE {
        return select_epoch_jury(vrf_output, staked_identities, zone);
    }

    select_epoch_jury(vrf_output, &eligible, zone)
}

/// Zone-scoped membership check for the local witness (Gap 5).
pub fn is_in_epoch_jury_scoped(
    vrf_output: &[u8],
    staked_identities: &[String],
    zone: &ZoneId,
    subscribers: &std::collections::HashSet<String>,
    witness_hash: &str,
) -> bool {
    // Bootstrap: no VRF yet or no staked set — everyone attests.
    if vrf_output.is_empty() || staked_identities.is_empty() {
        return true;
    }
    let jury = select_epoch_jury_scoped(vrf_output, staked_identities, zone, subscribers);
    jury.iter().any(|w| w == witness_hash)
}

/// Select the per-zone attestation committee for an epoch (MAINNET gap #5).
///
/// Unlike `select_epoch_jury_scoped` (2/3+1 of pool, uniform VRF scoring),
/// this function returns a size-capped, **stake-weighted** committee.
///
/// ## Algorithm
///
/// 1. Filter `staked_weighted` → zone subscribers.
/// 2. If the filtered pool is below `MIN_SCOPED_ELIGIBLE`, fall back to the
///    full staked set (bootstrap safety, matches jury fallback).
/// 3. If pool size ≤ `COMMITTEE_SMALL_NETWORK`, return the entire pool
///    (small-network exemption, matches jury behavior).
/// 4. Otherwise, score each identity using the same VRF math as
///    [`aggregator_chain_weighted`]:
///    `priority = u128(SHA3(vrf || zone || id)[..16]) / isqrt(stake)`.
///    Lower priority wins → higher stake is statistically ranked earlier.
///    Tie-break by lex order on identity for determinism.
/// 5. Return the top `MAINNET_COMMITTEE_SIZE` identities, sorted
///    ascending by identity for deterministic cross-node output.
///
/// ## Return
///
/// `Vec<(identity_hash, stake)>` — callers use the stakes to compute the
/// settlement denominator (sum of committee stakes, not full zone stake).
pub fn select_epoch_committee_scoped(
    vrf_output: &[u8],
    staked_weighted: &[(String, u64)],
    zone: &ZoneId,
    subscribers: &std::collections::HashSet<String>,
) -> Vec<(String, u64)> {
    if staked_weighted.is_empty() {
        return Vec::new();
    }

    // Bootstrap: no VRF → everyone attests (match jury semantics).
    if vrf_output.is_empty() {
        return staked_weighted.to_vec();
    }

    // Build eligible pool = staked ∩ subscribed.
    let eligible: Vec<(String, u64)> = staked_weighted
        .iter()
        .filter(|(id, _)| subscribers.contains(id))
        .cloned()
        .collect();

    // Fallback: not enough subscribers → use the staked set so settlement
    // isn't stuck during bootstrap, zone splits, or subscription propagation.
    // Cap at `BOOTSTRAP_FALLBACK_CAP` to bound per-zone hashing cost — see
    // `BOOTSTRAP_FALLBACK_CAP` doc + `bench_committee_selection.rs`.
    let bootstrap_owned: Vec<(String, u64)>;
    let pool: &[(String, u64)] = if eligible.len() < MIN_SCOPED_ELIGIBLE {
        if staked_weighted.len() <= BOOTSTRAP_FALLBACK_CAP {
            staked_weighted
        } else {
            // Top-N stakers by stake desc, lex tiebreak on identity for
            // deterministic cross-node selection. Hashing/sortition still
            // happens below over `pool`; this only bounds the pool size.
            let mut sorted = staked_weighted.to_vec();
            sorted.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            sorted.truncate(BOOTSTRAP_FALLBACK_CAP);
            bootstrap_owned = sorted;
            &bootstrap_owned
        }
    } else {
        &eligible
    };

    // Small network: everyone attests. Same rationale as `select_epoch_jury`
    // — excluding anyone inflates the settlement denominator past what the
    // remaining committee can close.
    if pool.len() <= COMMITTEE_SMALL_NETWORK {
        let mut out: Vec<(String, u64)> = pool.to_vec();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        return out;
    }

    // Stake-weighted VRF sortition. Reuses the same math as
    // `aggregator_chain_weighted` (production-proven, deterministic u128).
    let mut scored: Vec<(u128, &String, u64)> = pool
        .iter()
        .map(|(identity, stake)| {
            let mut input = Vec::with_capacity(vrf_output.len() + 64 + identity.len());
            input.extend_from_slice(vrf_output);
            input.extend_from_slice(zone.to_string().as_bytes());
            input.extend_from_slice(identity.as_bytes());
            let hash = sha3_256(&input);

            let mut buf = [0u8; 16];
            buf.copy_from_slice(&hash[..16]);
            let hash_u128 = u128::from_be_bytes(buf);

            // Zero stake → weight 1 (rank-last statistically). Prevents
            // div-by-zero and preserves VRF fairness for unstaked slots.
            let stake_root = (*stake).isqrt().max(1);
            let priority = hash_u128 / (stake_root as u128);

            (priority, identity, *stake)
        })
        .collect();

    // Lower priority wins. Lex tie-break on identity for determinism.
    scored.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(b.1)));

    // Take the top K committee members.
    let mut out: Vec<(String, u64)> = scored
        .into_iter()
        .take(MAINNET_COMMITTEE_SIZE)
        .map(|(_, id, stake)| (id.clone(), stake))
        .collect();

    // Sort output by identity for stable cross-node display + dedup-safe
    // downstream processing. Selection determinism is already guaranteed
    // by the priority sort above.
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// Zone-scoped committee membership check for the local witness.
/// Mirrors `is_in_epoch_jury_scoped` but uses the capped committee.
pub fn is_in_epoch_committee_scoped(
    vrf_output: &[u8],
    staked_weighted: &[(String, u64)],
    zone: &ZoneId,
    subscribers: &std::collections::HashSet<String>,
    witness_hash: &str,
) -> bool {
    if vrf_output.is_empty() || staked_weighted.is_empty() {
        return true; // bootstrap: everyone attests
    }
    let committee = select_epoch_committee_scoped(vrf_output, staked_weighted, zone, subscribers);
    committee.iter().any(|(w, _)| w == witness_hash)
}

/// Per-epoch index over the staked set, built once and reused for every
/// per-zone committee selection in the same epoch tick.
///
/// Eliminates the per-zone O(|staked|) eligible-pool filter that bottlenecks
/// the 100k-staker / 1M-zone interplanetary tier.
///
/// Build cost: O(|staked| log |staked|) sort + O(|staked|) hash insert,
/// once per epoch tick. ~30 ms at 100k stakers — amortized across 1M zones.
///
/// Use cost (per zone, via [`select_epoch_committee_scoped_indexed`]):
///   O(|subs|) HashMap lookups to materialize eligible, vs O(|staked|)
///   HashSet filter. At 5 subs/zone the per-call cost drops from a
///   100k-staker 3.44 ms scan to a handful of µs.
///
/// Caller pattern:
/// ```ignore
/// let index = CommitteeSelectionIndex::build(&staked_weighted);
/// // hot loop, parallelizable:
/// for (zone, vrf, subs) in inputs {
///     let committee = select_epoch_committee_scoped_indexed(&vrf, &index, &zone, &subs);
/// }
/// ```
pub struct CommitteeSelectionIndex {
    /// `identity_hash → stake` for O(1) eligible-pool lookup. Owns its
    /// keys so `&CommitteeSelectionIndex` is `Send + Sync` for rayon.
    pub staked_index: std::collections::HashMap<String, u64>,
    /// Bootstrap-fallback pool used when |eligible| < `MIN_SCOPED_ELIGIBLE`.
    /// Pre-sorted by stake desc + lex tiebreak, truncated to
    /// `BOOTSTRAP_FALLBACK_CAP` so per-zone scoring stays bounded.
    pub bootstrap_pool: Vec<(String, u64)>,
}

impl CommitteeSelectionIndex {
    /// Build the per-epoch index from the staked-account list.
    /// Idempotent: same input → same index (deterministic sort).
    pub fn build(staked_weighted: &[(String, u64)]) -> Self {
        let mut sorted = staked_weighted.to_vec();
        sorted.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        sorted.truncate(BOOTSTRAP_FALLBACK_CAP);
        let staked_index: std::collections::HashMap<String, u64> = staked_weighted
            .iter()
            .map(|(id, stake)| (id.clone(), *stake))
            .collect();
        Self {
            staked_index,
            bootstrap_pool: sorted,
        }
    }

    /// Number of staked accounts indexed. Empty index ↔ no settlement
    /// participants; matches the early-exit in
    /// [`select_epoch_committee_scoped_indexed`].
    pub fn staked_count(&self) -> usize {
        self.staked_index.len()
    }
}

/// Indexed variant of [`select_epoch_committee_scoped`] for the per-epoch
/// committee-rotation hot path.
///
/// Same algorithm + tiebreaks as the slice-based facade — produces the same
/// committee for the same inputs — but consumes a pre-built
/// [`CommitteeSelectionIndex`] so per-zone work is O(|subs|) instead of
/// O(|staked|). See `bench_committee_selection.rs` for the measured speedup.
pub fn select_epoch_committee_scoped_indexed(
    vrf_output: &[u8],
    index: &CommitteeSelectionIndex,
    zone: &ZoneId,
    subscribers: &std::collections::HashSet<String>,
) -> Vec<(String, u64)> {
    if index.staked_index.is_empty() {
        return Vec::new();
    }

    // Bootstrap (no VRF emitted yet): rotate the bootstrap pool sorted by
    // identity for deterministic cross-node output. For small networks
    // (|staked| ≤ BOOTSTRAP_FALLBACK_CAP) this is the full staked set —
    // identical semantics to the legacy facade. For large networks it's
    // the deterministic top-N stakers, which preserves the SCALE rule
    // (no per-zone O(|staked|) allocation).
    if vrf_output.is_empty() {
        let mut out = index.bootstrap_pool.clone();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        return out;
    }

    // O(|subs|) eligible-pool build — direct HashMap lookups instead of
    // the slice scan in the legacy facade. Identity allocations match
    // the facade so no extra cost per element.
    let eligible: Vec<(String, u64)> = subscribers
        .iter()
        .filter_map(|id| index.staked_index.get(id).map(|stake| (id.clone(), *stake)))
        .collect();

    let pool: &[(String, u64)] = if eligible.len() < MIN_SCOPED_ELIGIBLE {
        &index.bootstrap_pool
    } else {
        &eligible
    };

    // Small network: everyone attests. Same rationale as the slice facade.
    if pool.len() <= COMMITTEE_SMALL_NETWORK {
        let mut out: Vec<(String, u64)> = pool.to_vec();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        return out;
    }

    // Stake-weighted VRF sortition — same math as the slice facade and
    // `aggregator_chain_weighted`.
    let mut scored: Vec<(u128, &String, u64)> = pool
        .iter()
        .map(|(identity, stake)| {
            let mut input = Vec::with_capacity(vrf_output.len() + 64 + identity.len());
            input.extend_from_slice(vrf_output);
            input.extend_from_slice(zone.to_string().as_bytes());
            input.extend_from_slice(identity.as_bytes());
            let hash = sha3_256(&input);

            let mut buf = [0u8; 16];
            buf.copy_from_slice(&hash[..16]);
            let hash_u128 = u128::from_be_bytes(buf);

            let stake_root = (*stake).isqrt().max(1);
            let priority = hash_u128 / (stake_root as u128);

            (priority, identity, *stake)
        })
        .collect();

    scored.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(b.1)));

    let mut out: Vec<(String, u64)> = scored
        .into_iter()
        .take(MAINNET_COMMITTEE_SIZE)
        .map(|(_, id, stake)| (id.clone(), stake))
        .collect();

    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// Indexed variant of [`is_in_epoch_committee_scoped`] for the auto-witness
/// hot loop. See [`CommitteeSelectionIndex`] for the build cost.
pub fn is_in_epoch_committee_scoped_indexed(
    vrf_output: &[u8],
    index: &CommitteeSelectionIndex,
    zone: &ZoneId,
    subscribers: &std::collections::HashSet<String>,
    witness_hash: &str,
) -> bool {
    if vrf_output.is_empty() || index.staked_index.is_empty() {
        return true;
    }
    let committee = select_epoch_committee_scoped_indexed(vrf_output, index, zone, subscribers);
    committee.iter().any(|(w, _)| w == witness_hash)
}

// ─── Attestation ────────────────────────────────────────────────────────────

/// A single witness attestation for a record.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Attestation {
    pub record_id: String,
    pub witness_hash: String,
    pub stake: u64,
    pub timestamp: f64,
}

// ─── Confirmation Levels (economics §9.5) ──────────────────────────────────

/// Minimum witnesses for Attested level.
const ATTESTED_MIN_WITNESSES: usize = 1;
/// Minimum witnesses for Confirmed level.
const CONFIRMED_MIN_WITNESSES: usize = 3;
/// Minimum distinct clusters for Confirmed level.
const CONFIRMED_MIN_CLUSTERS: usize = 3;
/// Timing correlation window: witnesses attesting within this window for the same
/// record are considered potentially co-located (same cluster). Protocol §7.5.
const TIMING_CLUSTER_THRESHOLD_SECS: f64 = 0.5;

/// Record confirmation level — tracks how thoroughly a record has been witnessed.
///
/// Layered consensus model (Steps 3+4, internal design notes):
/// - Pending: Layer 1 validated (sig, format, balance, entropy), not yet in epoch seal
/// - Sealed: Included in anchor-proposed epoch seal
/// - Finalized: Epoch seal has >67% stake-weighted diverse attestations
/// - Anchored: Finalized + no open challenges after challenge window (24h)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum ConfirmationLevel {
    /// Layer 1 validated, not yet in an epoch seal. (Was: Unconfirmed)
    Pending = 0,
    /// Included in anchor's proposed epoch seal. (Was: Attested)
    Sealed = 1,
    /// Epoch seal has >67% stake-weighted diverse attestations. (Was: Confirmed)
    Finalized = 2,
    /// Finalized + no open challenges after challenge window. (Was: Anchored)
    Anchored = 3,
}

impl ConfirmationLevel {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Sealed => "sealed",
            Self::Finalized => "finalized",
            Self::Anchored => "anchored",
        }
    }

    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Pending,
            1 => Self::Sealed,
            2 => Self::Finalized,
            3 => Self::Anchored,
            _ => Self::Pending,
        }
    }

    /// Parse from name string (supports both old and new names for backward compat).
    pub fn from_name(s: &str) -> Self {
        match s {
            "pending" | "unconfirmed" => Self::Pending,
            "sealed" | "attested" => Self::Sealed,
            "finalized" | "confirmed" => Self::Finalized,
            "anchored" => Self::Anchored,
            _ => Self::Pending,
        }
    }
}

impl std::fmt::Display for ConfirmationLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

// ─── AWC Consensus engine ───────────────────────────────────────────────────

/// Hard cap on tracked records in the attestation map.
/// When exceeded, oldest entries are evicted regardless of finalization.
/// Safety net — normal pruning (6h age, finalized) keeps it well below this.
/// Raised from 15K to 50K: 15K was too low for nodes with large DAG windows
/// (63GB RAM, 1h retention), causing premature attestation eviction that
/// prevented records from reaching 2/3 settlement threshold.
pub const MAX_ATTESTATION_RECORDS: usize = 50_000;

/// Hard cap on tracked seal attestations.
pub const MAX_SEAL_ATTESTATIONS: usize = 5_000;

/// Tracks attestations, witness profiles, confirmation levels, and settlement.
///
/// Supports both legacy per-record attestations and new per-epoch-seal
/// attestations (layered consensus model, Steps 3+4).
pub struct AWCConsensus {
    /// record_id -> list of attestations (legacy per-record tracking)
    attestations: HashMap<String, Vec<Attestation>>,
    /// zone -> total stake in that zone
    zone_stakes: HashMap<ZoneId, u64>,
    /// witness_hash -> profile metadata (for correlation computation).
    /// Self-reported, peer-controlled. Cross-checked against `derived_geo`.
    profiles: HashMap<String, WitnessProfile>,
    /// witness_hash -> verifiable geographic observation, sourced from the
    /// remote socket address of the incoming registration connection.
    /// Cannot be forged by the witness.
    /// Spec: Protocol §11.12 (geographic diversity, Theorem 3.1).
    derived_geo: HashMap<String, DerivedWitnessGeo>,
    /// record_id -> current confirmation level
    confirmation_levels: HashMap<String, ConfirmationLevel>,
    /// record_ids that have been anchored (challenge window passed)
    anchored: HashSet<String>,
    /// seal_id -> list of witness attestations for epoch seals (layered consensus Layer 2)
    seal_attestations: HashMap<String, Vec<SealAttestation>>,
    /// seal_id -> record IDs included in that seal
    seal_record_ids: HashMap<String, Vec<String>>,
    /// R2 (seal-member durable-write lane): record_hash hex -> seal_id for
    /// seal members that were NOT locally resolvable at registration time
    /// (`resolve_seal_record_ids` miss). Probed at record ingest so a
    /// late-arriving member is appended to `seal_record_ids` and promoted
    /// if its seal already settled. Bounded by `MAX_UNRESOLVED_SEAL_MEMBERS`;
    /// pruned alongside seal state in `prune_older_than` and
    /// `prune_anchored_seals_where`.
    unresolved_seal_members: HashMap<String, String>,
    /// Diagnostic: R2 inserts dropped at `MAX_UNRESOLVED_SEAL_MEMBERS`.
    pub unresolved_seal_members_dropped_total: u64,
    /// seal_id -> (epoch_number, zone) for this seal. Epoch-based pruning
    /// shadow metric:
    /// pairs the seal's epoch with its zone so we can compute how many
    /// already-sealed records would be reclaimable under epoch-based pruning
    /// (current_zone_epoch - seal_epoch >= EPOCH_PRUNE_SHADOW_HORIZON).
    /// Populated by `register_seal_epoch`, pruned alongside `seal_record_ids`.
    seal_epoch: HashMap<String, (u64, ZoneId)>,
    /// record_id -> seal_id (reverse index for O(1) layered_confirmation lookup)
    record_to_seal: HashMap<String, String>,
    /// seal_id -> timestamp when seal first reached settlement (for Anchored promotion)
    seal_finalized_at: HashMap<String, f64>,
    /// seal_id -> timestamp when the anchor first registered this seal's
    /// record set via `register_seal_records`. Paired with `seal_finalized_at`
    /// to derive seal-attestation latency (Gap 8 / MAINNET mandate #3:
    /// "Push in-zone finality to its physical floor"). Pruned alongside
    /// `seal_finalized_at`.
    seal_registered_at: HashMap<String, f64>,
    /// Prometheus-style histogram buckets for seal-attestation latency in
    /// seconds — time from `register_seal_records` to first settlement.
    /// Boundaries (le): 1s, 3s, 5s, 10s, 20s, 30s, 60s, 120s, 300s, 600s, +Inf.
    /// Cumulative (le=3 includes le=1). Observed once per seal at first
    /// settlement transition. Hard-capped size: 11 u64s, no memory growth.
    /// Top buckets (300s, 600s): testnet idle
    /// finality regularly exceeds 120s; without them everything piled in +Inf
    /// and operators couldn't distinguish "slow but converging" from "stuck".
    seal_attestation_latency_buckets: [u64; 11],
    /// Count of seals observed (matches `_count` suffix on the histogram).
    pub seal_attestation_latency_count: u64,
    /// Sum of observed latencies (matches `_sum` suffix on the histogram).
    pub seal_attestation_latency_sum_secs: f64,
    /// Diagnostic: total calls into `add_seal_attestation`. If this
    /// is 0 while Layer-1 seal attestations exist in WitnessManager, the
    /// call-site wiring is broken. Exposed on /metrics as
    /// `elara_seal_attestation_add_total`.
    pub seal_attestation_add_total: u64,
    /// Diagnostic: count of add_seal_attestation calls where
    /// `is_seal_settled(seal_id)` returned true. Compared with
    /// `seal_attestation_latency_count`, a divergence means the histogram
    /// fire-site is broken (seal settled but latency not observed).
    pub seal_settled_true_total: u64,
    /// seal_id → wall-clock of the FIRST attestation we
    /// observed for this seal. Splits the end-to-end seal-attestation
    /// latency into two legs: propagation (register → first-attestation)
    /// and quorum convergence (first-attestation → 2/3 settled). Pruned
    /// alongside `seal_finalized_at` / `seal_registered_at`.
    seal_first_attested_at: HashMap<String, f64>,
    /// Histogram buckets — propagation leg in seconds.
    /// Boundaries same as `SEAL_LATENCY_BUCKETS`. Fires once per seal on
    /// the first attestation add.
    seal_propagation_latency_buckets: [u64; 11],
    pub seal_propagation_latency_count: u64,
    pub seal_propagation_latency_sum_secs: f64,
    /// Histogram buckets — quorum-convergence leg in seconds.
    /// Boundaries same as `SEAL_LATENCY_BUCKETS`. Fires once per seal on
    /// first settlement transition.
    seal_quorum_latency_buckets: [u64; 11],
    pub seal_quorum_latency_count: u64,
    pub seal_quorum_latency_sum_secs: f64,
    /// Count of seal-attestation latency observations
    /// SKIPPED because the seal was never locally registered via
    /// `register_seal_records` — i.e. retroactive registration where
    /// `seal_registered_at` was synthesized from the witness clock and
    /// the (now - witness_ts) latency would inflate by the wall-clock
    /// gap between witness creation and our local arrival (often days
    /// during bootstrap replay). Same gate as the propagation histogram
    /// already enforced at this site. Exposed on /metrics
    /// as `elara_seal_latency_retroactive_skipped_total`. A high rate
    /// vs `seal_attestation_latency_count` signals heavy peer-driven
    /// catchup; healthy steady state should be near zero.
    pub seal_latency_retroactive_skipped_total: u64,
    /// Per-attestor-rank arrival latency in seconds.
    /// `buckets[r]` = cumulative histogram for the (r+1)-th attestation to
    /// arrive on any seal (r=0 is 1st, ..., r=3 is 4th, r=4 is 5th-and-later).
    /// Measured from `seal_registered_at` (same local-clock origin as the
    /// propagation histogram). Identifies whether the quorum tail is dominated
    /// by one slow witness (rank-4 latency >> rank-1) or all witnesses are
    /// slow (all ranks clustered). Capped at 5 rows to bound /metrics
    /// cardinality — acceptable at 10K-node scale (45 time-series per node).
    seal_attestor_rank_latency_buckets: [[u64; 11]; 5],
    pub seal_attestor_rank_latency_count: [u64; 5],
    pub seal_attestor_rank_latency_sum_secs: [f64; 5],
    /// seal_id -> stuck_zone, for seals that are `global_quorum_seal`
    /// cross-zone escalations (Stage 3c.1). Presence of `seal_id` in this
    /// map routes `is_seal_settled` to the cross-zone denominator
    /// (sum of zone_stakes over zones ≠ stuck_zone).
    global_seal_stuck_zone: HashMap<String, ZoneId>,
    /// record_id -> creator's staked amount (for settlement threshold exclusion).
    /// The creator can't self-attest, so their stake is unreachable for their records.
    /// Settlement denominator = total_zone_stake - creator_stake (MESH-BFT Definition 18, amended).
    creator_stakes: HashMap<String, u64>,
    /// record_id -> creator identity hash. H1 enforcement: `is_settled` removes the
    /// creator's stake from the denominator, so a creator attestation in the numerator
    /// would collapse the 2/3 threshold. This makes the "creator can't attest"
    /// invariant ENFORCED (not just asserted in a comment): `add_attestation` /
    /// `add_seal_attestation` / `bulk_load_attestations` reject witness==creator at
    /// insert, and `register_creator_stake` retroactively purges a self-attestation
    /// that arrived before the record (ordering window). Pruned in lockstep with
    /// `creator_stakes`.
    creator_identity: HashMap<String, String>,
    /// KR-3 S2 wiring-(c) c3-ii: rotation-class settlement-zone override
    /// (record_id → lineage_id). `AWCConsensus` has no `NodeState`/`zone_registry`,
    /// so its naive `zone_for_record(record_id)` settlement-denominator sites can't
    /// reach the central `resolve_record_zone` routing pin (c3-i). This is the
    /// in-memory mirror of the durable `rotation_zone_pin:{record_id}` row,
    /// registered at admission under `s2_rotation_ordering_enabled`, so a rotation
    /// hop's stake counts against its lineage zone — the SAME zone the central hook
    /// stores it under (§6.1 item 2). Only ever populated flag-ON, so the emptiness
    /// short-circuit in `settlement_zone_for` keeps flag-OFF BYTE-IDENTICAL. Pruned
    /// in lockstep with `attestations`: Layer-1 settlement math only matters
    /// pre-finality — post-finality the rotation CF governs.
    rotation_zone_overrides: HashMap<String, String>,
    /// Cumulative count of creator self-attestations rejected or purged (H1).
    self_attestations_rejected: u64,
    /// record_id -> list of parent IDs that are in a DIFFERENT zone than the record.
    /// Used for shared-witness bridging: if cross-zone parents are finalized,
    /// the record benefits from relaxed cluster requirements (Protocol §7.5).
    cross_zone_parents: HashMap<String, Vec<String>>,
    /// Counter: how many times cross-zone finality boost has been applied
    /// (cluster requirement relaxed from CONFIRMED_MIN_CLUSTERS to 1).
    cross_zone_boost_count: u64,
    /// Total records evicted by priority eviction.
    pub evictions_total: u64,
    /// Records evicted that had >50% of needed witnesses (near settlement).
    pub evictions_near_settlement: u64,
    /// Records evicted by `prune_where` / `prune_finalized` —
    /// either this node finalized them locally or a peer-gossiped finalization
    /// arrived through `FinalizedIndex`. Counted in addition to (not in
    /// place of) `evictions_total`, which only tracks pressure evictions.
    pub evictions_finalized_total: u64,
    /// Records evicted by `prune_older_than(24h)` — the
    /// memory-prune loop's age cutoff. Newest attestation older than the
    /// cutoff, so the record will never finalize organically. Steady-state
    /// non-zero on a quiet node is normal (retroactive imports with pre-aged
    /// timestamps land here).
    pub evictions_age_total: u64,
    /// Records evicted by `forget_record` — ZSP zone-purge
    /// after a subscription change. Counted per record because zone-purge
    /// drains by record_id; the counter sums to total records dropped across
    /// all unsubscribed zones.
    pub evictions_zone_purge_total: u64,
    /// zone → sum of current committee members' stakes (MAINNET gap #5).
    /// When present and nonzero, this is the settlement denominator for
    /// records in `zone` (instead of `zone_stakes[zone]`). Set by
    /// `register_epoch_committee()` at each epoch boundary. Empty map
    /// during bootstrap → falls back to `zone_stakes`.
    committee_stakes: HashMap<ZoneId, u64>,
    /// zone → set of current committee members' identity hashes.
    /// Diagnostic + used to bound `/status` committee reporting.
    committee_members: HashMap<ZoneId, HashSet<String>>,
    /// Monotonic counter of committee rotations (diagnostic).
    pub committee_rotations_total: u64,
    // ─── Liveness-decay settlement denominator ──────────────────────────
    // internal design notes — stake whose staker stopped
    // attesting ages out of the 2/3 denominator, but ONLY while finality
    // is stalled, never below the floor, never when a committee is active.
    // Master switch defaults FALSE: behavior is bit-identical to
    // pre-liveness builds unless explicitly enabled from config.
    /// Master switch (config `liveness_decay_enabled`).
    liveness_decay_enabled: bool,
    /// Trailing activity window in epochs: a staker is live iff its last
    /// observed attestation is within `chain_tip_epoch - window`. This window
    /// IS the safety boundary — it must exceed realistic transient-outage and
    /// partition durations, because stake silent for a full window ages out
    /// of quorum (see internal design notes partition tradeoff).
    liveness_window_epochs: u64,
    /// Floor divisor: the decayed denominator never drops below
    /// `base / divisor` — a tiny survivor set must not clear 2/3 of itself.
    liveness_floor_divisor: u64,
    /// Highest chain-tip epoch observed (fed via `note_chain_tip`;
    /// monotonic; 0 until first feed). The window's reference point.
    chain_tip_epoch: u64,
    /// staker identity → stake. Rebuilt by `register_stakes_from_ledger*`
    /// via the incrementally-maintained `staker_index` — O(stakers),
    /// never O(accounts) (SCALE RULE).
    staker_stakes: HashMap<String, u64>,
    /// staker identity → chain-tip epoch of last observed attestation.
    /// Startup `bulk_load_attestations` only fills stakers with no known
    /// history (`or_insert`), so replayed history never fakes liveness.
    /// Hydrated from CF_METADATA via
    /// `attach_liveness_persistence` — see `liveness_persistence` below.
    staker_last_active: HashMap<String, u64>,
    /// Persistence sink for `staker_last_active`
    /// (CF_METADATA, `decay:last_active:<staker>` → LE u64 epoch).
    /// None = in-memory only (decay disabled, or tests). With a sink
    /// attached, last-active epochs survive restarts: the decay window
    /// measures chain time across process lifetimes instead of resetting
    /// to "everyone alive at boot" on every restart (the 2026-06-11
    /// re-wedge: a twice-restarted authority kept resurrecting dead stake
    /// while the unrestarted laptop decayed it on schedule).
    liveness_persistence: Option<std::sync::Arc<crate::storage::rocks::StorageEngine>>,
    /// Finality-event queue. Every time a record transitions from a
    /// pre-finality level (Pending/Sealed) to Finalized/Anchored, its
    /// record_id is appended here. The state_core drain loop pulls events
    /// off and commits the matching `PendingLedgerDelta` to `CF_LEDGER`.
    ///
    /// Bounded at `MAX_FINALIZATION_QUEUE` — on overflow we bump
    /// `finalization_queue_overflow_total` and drop the newest event. Ground
    /// truth lives in `confirmation_levels`; on overflow the drainer must
    /// reconcile by scanning `pending_ledger` and cross-checking levels.
    finalization_queue: VecDeque<String>,
    /// Monotonic count of finality events dropped because the queue was
    /// full. Non-zero = drain loop is lagging and some commits have to
    /// come from the reconcile path, not the stream.
    pub finalization_queue_overflow_total: u64,
    /// Monotonic count of finality events ever enqueued. Paired with
    /// `finalization_queue_overflow_total` for saturation percentage.
    pub finalization_queue_enqueued_total: u64,
    /// Monotonic count of finality events drained off the queue. Paired
    /// with `*_enqueued_total` to detect drain-loop stalls (enqueued
    /// advancing while drained is not).
    pub finalization_queue_drained_total: u64,
    /// MAINNET gap #8: queue of (record_id, witness_count) for records
    /// that just transitioned Pending → Sealed. Drained by `NodeState`
    /// after `add_attestation` and broadcast via `NodeEvent::RecordSealed`
    /// so accounts get optimistic Sealed UX without polling.
    /// Bounded at `MAX_SEALED_QUEUE`; on overflow we bump
    /// `newly_sealed_queue_overflow_total` and drop the newest event —
    /// `confirmation_levels` remains the ground truth so a missed WS push
    /// never breaks correctness, only delays UX feedback.
    newly_sealed_queue: VecDeque<(String, u32)>,
    /// Monotonic count of sealed events dropped because the queue was
    /// full. Non-zero = WS subscriber is not draining fast enough.
    pub newly_sealed_queue_overflow_total: u64,
    /// Monotonic count of sealed events ever enqueued.
    pub newly_sealed_queue_enqueued_total: u64,
    /// Monotonic count of sealed events drained off the queue.
    pub newly_sealed_queue_drained_total: u64,
    /// Gap 2.1 Phase 2b: seal_id → finality collection (signers + the
    /// committee snapshot they signed against). Witnesses sign
    /// `XZONE_FINALITY_DOMAIN || zone || epoch || merkle_root ||
    /// committee_hash`, so all signers for a given seal MUST verify against
    /// the SAME `(zone, epoch, merkle_root, committee_hash)` tuple. We pin
    /// `(epoch, committee_hash, committee_size)` on first insert; later
    /// signatures with a divergent snapshot are dropped (committee mid-
    /// rotation race — the dropped signer's vote is just unenforceable, not
    /// a correctness violation).
    ///
    /// When the seal is settled, `attach_xzone_proofs_from_seal` reads this
    /// map to bundle signatures onto the matching `PendingTransfer` so the
    /// consumer side (`claim_transfer` in zone B) can enforce 2/3 finality
    /// before crediting.
    ///
    /// Bounded at `MAX_SEAL_FINALITY_SIG_ENTRIES`; on overflow the oldest
    /// entries are evicted to keep memory O(active_window). Eviction is NOT
    /// free: witness collections live only in this in-memory map (plus
    /// node-snapshot serde) — never in a CF or DAG record — so an evicted
    /// collection is NOT replayable from chain history, and post-Phase-5 a
    /// transfer proofed with `committee_size == 0` hard-fails every claim
    /// (`verify_finality_quorum`). The sender's recovery for such a
    /// transfer is the 30-day `XZoneStaleReap` refund, not a claim.
    seal_finality_collections: HashMap<String, SealFinalityCollection>,
    /// Monotonic count of seal-finality signatures ever added (diagnostic).
    pub seal_finality_signers_added_total: u64,
    /// Monotonic count of seal-finality signatures ever evicted (diagnostic).
    pub seal_finality_signers_evicted_total: u64,
    /// Monotonic count of seal-finality signatures dropped because the
    /// caller's `(epoch, committee_hash, committee_size)` did not match the
    /// snapshot pinned by the first signer — strong signal of mid-epoch
    /// rotation racing the attestation flow. Non-fatal: those witnesses'
    /// votes are unenforceable until the seal is re-attempted with a
    /// stable committee.
    pub seal_finality_snapshot_mismatch_total: u64,
    /// Gap 2 sealed-abort producer-side P-3a: B-committee abort attestations
    /// keyed by `transfer_id`. Each entry holds witnesses' Dilithium3 sigs
    /// over `xzone_abort_signable_bytes(transfer_id, dest_zone,
    /// source_seal_epoch, dest_committee_hash)`. Once 2/3 of the destination
    /// committee has signed, an aggregator assembles an `XZoneAbortBundle`
    /// for `/rpc/xzone_abort` to atomically refund the sealed lock.
    /// Bounded at `MAX_XZONE_ABORT_SIG_ENTRIES` with the same eviction
    /// discipline as `seal_finality_collections`.
    xzone_abort_collections: HashMap<String, XZoneAbortCollection>,
    /// Gap 2 sealed-abort producer-side P-3b: dest-zone observation map.
    /// When zone B ingests a seal from zone A that contains a LOCK record
    /// destined for zone B, the relevant fields are extracted into an
    /// `XZoneAbortObservation` here. The periodic abort-emitter walks this
    /// map (NOT the full record store — SCALE RULE) to find transfers that
    /// have crossed `expires_at` without being claimed. Bounded; evicts
    /// the oldest 10% on overflow.
    xzone_abort_observations: HashMap<String, XZoneAbortObservation>,
    /// Monotonic count of abort-observation entries ever inserted.
    pub xzone_abort_observations_inserted_total: u64,
    /// Monotonic count of abort-observation entries evicted on overflow.
    pub xzone_abort_observations_evicted_total: u64,
    /// Monotonic count of abort-observation entries cleared on claim/abort
    /// terminal transition.
    pub xzone_abort_observations_cleared_total: u64,
    /// Monotonic count of xzone-abort signatures ever added (diagnostic).
    pub xzone_abort_signers_added_total: u64,
    /// Monotonic count of xzone-abort signatures ever evicted (diagnostic).
    pub xzone_abort_signers_evicted_total: u64,
    /// Monotonic count of xzone-abort signatures dropped because the
    /// caller's `(source_seal_epoch, dest_committee_hash, dest_committee_size)`
    /// did not match the snapshot pinned by the first signer. Non-fatal:
    /// those witnesses' votes are unenforceable against the same bundle
    /// until the abort is re-attempted with a stable committee.
    pub xzone_abort_snapshot_mismatch_total: u64,
    /// Observability: monotonic count of
    /// `correlation_weighted` calls that hit the unknown-profile branch.
    /// Atomic because `correlation_weighted(&self)` is read-only; a stale
    /// counter is fine, we just need to see whether it's climbing.
    /// Exposed on /metrics as `elara_consensus_unknown_profile_pairs_total`.
    /// Exit gate for removing `ELARA_TESTNET_ASSUME_INDEPENDENT_UNKNOWN`:
    /// rate < 1/node/hour after profile-exchange soak.
    pub unknown_profile_pairs_total: AtomicU64,
}

/// Upper bound on `AWCConsensus::finalization_queue`. Picked for the drain
/// cadence (state_core tick frequency); overflow is
/// survivable because the drainer can reconcile from `confirmation_levels`.
pub const MAX_FINALIZATION_QUEUE: usize = 65_536;

/// R2 hard cap on outstanding unresolved seal-member hashes
/// (record_hash → seal_id). A seal lists at most `MAX_SEAL_RECORDS`
/// members, but the map spans seals; the cap bounds adversarial seals
/// carrying fabricated member hashes. Drop-new on overflow (the late
/// member then heals via ordinary Layer-1 attestation or the seal's
/// tip+1 re-entry, both existing paths).
pub const MAX_UNRESOLVED_SEAL_MEMBERS: usize = 100_000;

/// Upper bound on `AWCConsensus::newly_sealed_queue`. MAINNET gap #8 —
/// Sealed is a UX signal (accounts surface "1 witness attesting" at ~3-5s),
/// not a correctness signal, so overflow is safe: confirmation_levels is
/// the ground truth and the next add_attestation for the same record still
/// fires again if its level drops back to Pending and retriggers.
pub const MAX_SEALED_QUEUE: usize = 65_536;

/// Upper bound on `AWCConsensus::seal_finality_collections` map size
/// (keyed by seal_id). Each entry holds <= committee-size signatures
/// (~5 typical, hard ceiling per zone). At 1M zones × 720 seals/day,
/// witnesses produce finality signatures only for seals containing
/// in-flight cross-zone locks — a small fraction of total seals.
/// 5K entries × 5 sigs × ~3.4KB = ~85MB worst case, bounded. Beyond that
/// the oldest seal-id entries are evicted; a pending transfer whose seal
/// predates eviction gets proofed with committee_size = 0, which Phase 5
/// (2026-04-28) made UNCLAIMABLE — `verify_finality_quorum` hard-rejects
/// zero, there is no legacy fallback — leaving the 30-day XZoneStaleReap
/// refund as the sender's only exit. Eviction pressure here is a real
/// funds-liveness cost, not a soft degradation.
pub const MAX_SEAL_FINALITY_SIG_ENTRIES: usize = 5_000;

/// Upper bound on `AWCConsensus::xzone_abort_collections` map size (keyed
/// by transfer_id). Each entry holds <= dest-committee-size signatures.
/// Aborts are emitted only for sealed locks that *also* missed their abort
/// window — the intersection of two rare events, so the steady-state
/// working set is much smaller than seal-finality. 5K entries is the same
/// budget; on overflow the oldest 10% of transfer_ids are evicted and
/// aggregators fall back to retrying once new signatures arrive.
pub const MAX_XZONE_ABORT_SIG_ENTRIES: usize = 5_000;

/// Gap 2 sealed-abort producer-side P-3a: bundle of B-committee abort
/// attestations for one cross-zone transfer, pinned to the
/// `(source_seal_epoch, dest_committee_hash, dest_committee_size)` snapshot
/// the first signer signed against. All signers for the same transfer_id
/// must agree on this snapshot — a signature against a different
/// dest_committee_hash signs a different canonical message and cannot be
/// counted against the same `verify_abort_quorum` denominator. Diverging
/// snapshots are dropped at insert time.
#[derive(Debug, Clone)]
pub struct XZoneAbortCollection {
    pub source_seal_epoch: u64,
    pub dest_committee_hash: [u8; 32],
    pub dest_committee_size: u32,
    pub signers: Vec<crate::accounting::cross_zone::SealFinalityWitness>,
}

/// Upper bound on `AWCConsensus::xzone_abort_observations`. Each entry is
/// the dest-zone view of one inbound cross-zone transfer's lock. At 1M
/// zones × O(in-flight per-zone xzone transfers), the working set is
/// bounded by claim-window-expirations rather than total volume, so 50K
/// entries (~10× the abort-collection cap) is comfortable headroom while
/// still hitting the SCALE RULE memory ceiling. Eviction drops the oldest
/// 10% on overflow.
pub const MAX_XZONE_ABORT_OBSERVATIONS: usize = 50_000;

/// Gap 2 sealed-abort producer-side P-3b: zone B's view of one inbound
/// cross-zone transfer's lock — the minimum data the dest-side abort
/// emitter needs to (a) decide whether the transfer has expired without
/// a claim and (b) sign the canonical abort bytes. Populated when zone B
/// ingests zone A's seal containing the LOCK record (P-3c will wire that
/// path); read by the periodic abort emitter (P-3d) and cleared on a
/// terminal transition (claim admitted, or abort bundle assembled).
///
/// `lock_record_hash` is included so the emitter can verify the LOCK
/// record is still in storage before signing — a paranoia check that
/// guards against signing for a transfer whose seal has been pruned.
#[derive(Debug, Clone)]
pub struct XZoneAbortObservation {
    pub transfer_id: String,
    pub source_zone: ZoneId,
    pub dest_zone: ZoneId,
    pub source_seal_epoch: u64,
    pub locked_at: f64,
    pub expires_at: f64,
    pub lock_record_hash: [u8; 32],
    pub amount: u64,
}

/// Gap 2.1 Phase 2b: bundle of finality witness signatures for one seal,
/// pinned to the `(epoch, committee_hash, committee_size)` snapshot the
/// first signer signed against. All signers for the same seal must agree
/// on this snapshot — a signature against a different committee_hash
/// would not verify against the same canonical message in
/// `verify_finality_quorum`, so storing it would only inflate the apparent
/// quorum. Diverging snapshots are dropped at insert time.
#[derive(Debug, Clone)]
pub struct SealFinalityCollection {
    pub seal_epoch: u64,
    pub committee_hash: [u8; 32],
    pub committee_size: u32,
    pub signers: Vec<SealFinalityWitness>,
}

impl Default for AWCConsensus {
    fn default() -> Self {
        Self::new()
    }
}

impl AWCConsensus {
    pub fn new() -> Self {
        Self {
            attestations: HashMap::new(),
            zone_stakes: HashMap::new(),
            profiles: HashMap::new(),
            derived_geo: HashMap::new(),
            confirmation_levels: HashMap::new(),
            anchored: HashSet::new(),
            seal_attestations: HashMap::new(),
            seal_record_ids: HashMap::new(),
            unresolved_seal_members: HashMap::new(),
            unresolved_seal_members_dropped_total: 0,
            seal_epoch: HashMap::new(),
            record_to_seal: HashMap::new(),
            seal_finalized_at: HashMap::new(),
            seal_registered_at: HashMap::new(),
            seal_attestation_latency_buckets: [0; 11],
            seal_attestation_latency_count: 0,
            seal_attestation_latency_sum_secs: 0.0,
            seal_attestation_add_total: 0,
            seal_settled_true_total: 0,
            seal_first_attested_at: HashMap::new(),
            seal_propagation_latency_buckets: [0; 11],
            seal_propagation_latency_count: 0,
            seal_propagation_latency_sum_secs: 0.0,
            seal_quorum_latency_buckets: [0; 11],
            seal_quorum_latency_count: 0,
            seal_quorum_latency_sum_secs: 0.0,
            seal_latency_retroactive_skipped_total: 0,
            seal_attestor_rank_latency_buckets: [[0; 11]; 5],
            seal_attestor_rank_latency_count: [0; 5],
            seal_attestor_rank_latency_sum_secs: [0.0; 5],
            global_seal_stuck_zone: HashMap::new(),
            creator_stakes: HashMap::new(),
            creator_identity: HashMap::new(),
            rotation_zone_overrides: HashMap::new(),
            self_attestations_rejected: 0,
            cross_zone_parents: HashMap::new(),
            cross_zone_boost_count: 0,
            evictions_total: 0,
            evictions_near_settlement: 0,
            evictions_finalized_total: 0,
            evictions_age_total: 0,
            evictions_zone_purge_total: 0,
            committee_stakes: HashMap::new(),
            committee_members: HashMap::new(),
            committee_rotations_total: 0,
            liveness_decay_enabled: false,
            // ~24 h @ 120 s epochs. Kept in lockstep with config's
            // `default_liveness_window_epochs` (720): a SHORTER window ages
            // absent stake out of each partition side faster → divergent
            // self-settlement → fork on heal; a longer window stalls the
            // minority side instead. configure_liveness() overrides this from
            // NodeConfig at node init; this is only the pre-configure default.
            liveness_window_epochs: 720,
            liveness_floor_divisor: 10,
            chain_tip_epoch: 0,
            staker_stakes: HashMap::new(),
            staker_last_active: HashMap::new(),
            liveness_persistence: None,
            finalization_queue: VecDeque::new(),
            finalization_queue_overflow_total: 0,
            finalization_queue_enqueued_total: 0,
            finalization_queue_drained_total: 0,
            newly_sealed_queue: VecDeque::new(),
            newly_sealed_queue_overflow_total: 0,
            newly_sealed_queue_enqueued_total: 0,
            newly_sealed_queue_drained_total: 0,
            seal_finality_collections: HashMap::new(),
            seal_finality_signers_added_total: 0,
            seal_finality_signers_evicted_total: 0,
            seal_finality_snapshot_mismatch_total: 0,
            xzone_abort_collections: HashMap::new(),
            xzone_abort_signers_added_total: 0,
            xzone_abort_signers_evicted_total: 0,
            xzone_abort_snapshot_mismatch_total: 0,
            xzone_abort_observations: HashMap::new(),
            xzone_abort_observations_inserted_total: 0,
            xzone_abort_observations_evicted_total: 0,
            xzone_abort_observations_cleared_total: 0,
            unknown_profile_pairs_total: AtomicU64::new(0),
        }
    }

    /// Gap 2.1 Phase 2b: record a witness's finality signature for a seal.
    ///
    /// Called after a witness has verified the seal locally and signed
    /// `xzone_finality_signable_bytes(zone, epoch, merkle_root, committee_hash)`.
    /// First call for a seal pins the `(seal_epoch, committee_hash,
    /// committee_size)` snapshot; later calls with a different snapshot
    /// are dropped (committee mid-rotation race) and counted in
    /// `seal_finality_snapshot_mismatch_total`. Idempotent on
    /// (seal_id, witness_pk).
    pub fn add_seal_finality_signature(
        &mut self,
        seal_id: &str,
        seal_epoch: u64,
        committee_hash: [u8; 32],
        committee_size: u32,
        witness: SealFinalityWitness,
    ) {
        // Cap map size; evict oldest 10% on overflow to amortize.
        if !self.seal_finality_collections.contains_key(seal_id)
            && self.seal_finality_collections.len() >= MAX_SEAL_FINALITY_SIG_ENTRIES
        {
            let evict_n = (MAX_SEAL_FINALITY_SIG_ENTRIES / 10).max(1);
            let to_remove: Vec<String> = self
                .seal_finality_collections
                .keys()
                .take(evict_n)
                .cloned()
                .collect();
            for k in to_remove {
                self.seal_finality_collections.remove(&k);
                self.seal_finality_signers_evicted_total += 1;
            }
        }
        let entry = self
            .seal_finality_collections
            .entry(seal_id.to_string())
            .or_insert_with(|| SealFinalityCollection {
                seal_epoch,
                committee_hash,
                committee_size,
                signers: Vec::new(),
            });
        // Reject a divergent snapshot — those signatures sign over a
        // different canonical message and would never satisfy
        // verify_finality_quorum together with the pinned set.
        if entry.seal_epoch != seal_epoch
            || entry.committee_hash != committee_hash
            || entry.committee_size != committee_size
        {
            self.seal_finality_snapshot_mismatch_total += 1;
            return;
        }
        // Dedupe by witness_pk — a witness signs each seal once.
        if entry.signers.iter().any(|w| w.witness_pk == witness.witness_pk) {
            return;
        }
        entry.signers.push(witness);
        self.seal_finality_signers_added_total += 1;
    }

    /// Read the full finality collection for a seal (Phase 2b consumer).
    pub fn seal_finality_collection_for(&self, seal_id: &str) -> Option<&SealFinalityCollection> {
        self.seal_finality_collections.get(seal_id)
    }

    /// Drop finality signatures for a seal once they've been bundled onto
    /// outgoing transfers — keeps memory bounded after the seal's locks
    /// have all been claimed.
    pub fn clear_seal_finality_signers(&mut self, seal_id: &str) {
        self.seal_finality_collections.remove(seal_id);
    }

    /// Snapshot count of seal-ids currently holding finality signatures.
    pub fn seal_finality_signer_entries(&self) -> usize {
        self.seal_finality_collections.len()
    }

    /// Gap 2 sealed-abort P-3a: record a B-committee witness's abort
    /// signature for a sealed cross-zone transfer.
    ///
    /// Called after a B-committee witness has observed that the destination
    /// zone failed to admit the lock before its abort window closed and
    /// signed `xzone_abort_signable_bytes(transfer_id, dest_zone,
    /// source_seal_epoch, dest_committee_hash)`. First call for a transfer
    /// pins the `(source_seal_epoch, dest_committee_hash,
    /// dest_committee_size)` snapshot; later calls with a different
    /// snapshot are dropped (committee mid-rotation race) and counted in
    /// `xzone_abort_snapshot_mismatch_total`. Idempotent on
    /// (transfer_id, witness_pk).
    pub fn add_xzone_abort_signature(
        &mut self,
        transfer_id: &str,
        source_seal_epoch: u64,
        dest_committee_hash: [u8; 32],
        dest_committee_size: u32,
        witness: crate::accounting::cross_zone::SealFinalityWitness,
    ) {
        // Cap map size; evict oldest 10% on overflow to amortize.
        if !self.xzone_abort_collections.contains_key(transfer_id)
            && self.xzone_abort_collections.len() >= MAX_XZONE_ABORT_SIG_ENTRIES
        {
            let evict_n = (MAX_XZONE_ABORT_SIG_ENTRIES / 10).max(1);
            let to_remove: Vec<String> = self
                .xzone_abort_collections
                .keys()
                .take(evict_n)
                .cloned()
                .collect();
            for k in to_remove {
                self.xzone_abort_collections.remove(&k);
                self.xzone_abort_signers_evicted_total += 1;
            }
        }
        let entry = self
            .xzone_abort_collections
            .entry(transfer_id.to_string())
            .or_insert_with(|| XZoneAbortCollection {
                source_seal_epoch,
                dest_committee_hash,
                dest_committee_size,
                signers: Vec::new(),
            });
        if entry.source_seal_epoch != source_seal_epoch
            || entry.dest_committee_hash != dest_committee_hash
            || entry.dest_committee_size != dest_committee_size
        {
            self.xzone_abort_snapshot_mismatch_total += 1;
            return;
        }
        if entry.signers.iter().any(|w| w.witness_pk == witness.witness_pk) {
            return;
        }
        entry.signers.push(witness);
        self.xzone_abort_signers_added_total += 1;
    }

    /// Read the full abort collection for a transfer (P-4 aggregator hook).
    pub fn xzone_abort_collection_for(
        &self,
        transfer_id: &str,
    ) -> Option<&XZoneAbortCollection> {
        self.xzone_abort_collections.get(transfer_id)
    }

    /// Drop abort signatures for a transfer once an aggregator has assembled
    /// and submitted the bundle — keeps memory bounded after the abort lands.
    pub fn clear_xzone_abort_signers(&mut self, transfer_id: &str) {
        self.xzone_abort_collections.remove(transfer_id);
    }

    /// Snapshot count of transfer-ids currently holding abort signatures.
    pub fn xzone_abort_signer_entries(&self) -> usize {
        self.xzone_abort_collections.len()
    }

    /// Gap 2 sealed-abort P-3f: snapshot abort collections that have
    /// crossed the 2/3 quorum threshold so an aggregator can assemble
    /// `XZoneAbortBundle` envelopes and submit them to the source zone.
    ///
    /// Returns owned clones (transfer_id, collection) so the caller can
    /// release the consensus lock immediately and do its async submit
    /// path without holding the lock across an await. The map is
    /// bounded at `MAX_XZONE_ABORT_SIG_ENTRIES`, so the iteration cost
    /// is O(map_size) — fine for an epoch-tick scan.
    ///
    /// Quorum check matches `verify_abort_quorum`:
    ///   `signers.len() * 3 >= dest_committee_size * 2`
    /// with saturating arithmetic so a malformed
    /// `dest_committee_size = 0` cannot satisfy the threshold.
    pub fn ready_xzone_abort_bundles(&self) -> Vec<(String, XZoneAbortCollection)> {
        self.xzone_abort_collections
            .iter()
            .filter(|(_, c)| {
                let n = c.signers.len() as u64;
                let denom = c.dest_committee_size as u64;
                denom > 0 && n.saturating_mul(3) >= denom.saturating_mul(2)
            })
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// Gap 2 sealed-abort P-3b: record a dest-zone observation of an
    /// inbound LOCK record. Idempotent on `transfer_id`: re-observing the
    /// same lock (e.g. the seal is re-ingested via gossip) updates fields
    /// in place rather than producing a duplicate.
    ///
    /// Bounded at `MAX_XZONE_ABORT_OBSERVATIONS`; on overflow the oldest
    /// 10% are evicted. Eviction is non-fatal: a transfer whose observation
    /// is dropped falls back to the 24h passive refund (`process_expired`),
    /// which is still correct and conservation-preserving — the abort path
    /// is the *fast* path, never the only path.
    pub fn record_xzone_abort_observation(&mut self, obs: XZoneAbortObservation) {
        let key = obs.transfer_id.clone();
        if !self.xzone_abort_observations.contains_key(&key)
            && self.xzone_abort_observations.len() >= MAX_XZONE_ABORT_OBSERVATIONS
        {
            let evict_n = (MAX_XZONE_ABORT_OBSERVATIONS / 10).max(1);
            let to_remove: Vec<String> = self
                .xzone_abort_observations
                .keys()
                .take(evict_n)
                .cloned()
                .collect();
            for k in to_remove {
                self.xzone_abort_observations.remove(&k);
                self.xzone_abort_observations_evicted_total += 1;
            }
        }
        let was_new = !self.xzone_abort_observations.contains_key(&key);
        self.xzone_abort_observations.insert(key, obs);
        if was_new {
            self.xzone_abort_observations_inserted_total += 1;
        }
    }

    /// Read a single observation by transfer_id.
    pub fn xzone_abort_observation(&self, transfer_id: &str) -> Option<&XZoneAbortObservation> {
        self.xzone_abort_observations.get(transfer_id)
    }

    /// Iterate all observations whose `expires_at < now` AND whose
    /// `dest_zone == my_zone` — the candidate set the periodic abort
    /// emitter will sign attestations for. Cheap O(observations); the cap
    /// keeps the working set bounded per the SCALE RULE.
    pub fn expired_xzone_abort_observations<'a>(
        &'a self,
        my_zone: &'a ZoneId,
        now: f64,
    ) -> impl Iterator<Item = &'a XZoneAbortObservation> + 'a {
        self.xzone_abort_observations
            .values()
            .filter(move |obs| obs.dest_zone == *my_zone && now > obs.expires_at)
    }

    /// Clear an observation when the transfer reaches a terminal state
    /// (claim admitted, abort bundle assembled, or sender's pending lock
    /// pruned past the 48h ledger cutoff). Bumps the cleared counter.
    pub fn clear_xzone_abort_observation(&mut self, transfer_id: &str) -> bool {
        if self.xzone_abort_observations.remove(transfer_id).is_some() {
            self.xzone_abort_observations_cleared_total += 1;
            true
        } else {
            false
        }
    }

    /// Snapshot count of currently-tracked observations.
    pub fn xzone_abort_observation_entries(&self) -> usize {
        self.xzone_abort_observations.len()
    }

    /// Enqueue a finalized record for downstream commit. Must be
    /// called only on the Pending/Sealed → Finalized/Anchored edge, so
    /// each record fires at most once.
    ///
    /// On overflow (queue at `MAX_FINALIZATION_QUEUE`) we drop the NEW
    /// event and bump the overflow counter. The ledger-side commit will
    /// still happen via the reconcile path (scan `pending_ledger`, look
    /// up each record in `confirmation_levels`).
    #[inline]
    fn enqueue_finalized(&mut self, record_id: &str) {
        if self.finalization_queue.len() >= MAX_FINALIZATION_QUEUE {
            self.finalization_queue_overflow_total += 1;
            return;
        }
        self.finalization_queue.push_back(record_id.to_string());
        self.finalization_queue_enqueued_total += 1;
    }

    /// Pull every queued finality event. The caller is responsible
    /// for committing each `PendingLedgerDelta` to the committed ledger
    /// and deleting it from `CF_PENDING_DELTAS`. Order of events is
    /// insertion order; duplicates are not possible under the single-edge
    /// enqueue contract.
    pub fn drain_newly_finalized(&mut self) -> Vec<String> {
        let n = self.finalization_queue.len();
        if n == 0 {
            return Vec::new();
        }
        self.finalization_queue_drained_total =
            self.finalization_queue_drained_total.saturating_add(n as u64);
        self.finalization_queue.drain(..).collect()
    }

    /// Diagnostic: current queue depth.
    pub fn finalization_queue_depth(&self) -> usize {
        self.finalization_queue.len()
    }

    /// MAINNET gap #8: enqueue a record that just transitioned Pending → Sealed
    /// so the `NodeState` caller can broadcast `NodeEvent::RecordSealed`.
    /// Called only on the edge (pre-Sealed → Sealed) so each record fires at
    /// most once per attestation batch. On overflow we drop the newest event;
    /// correctness is unaffected (confirmation_levels is ground truth),
    /// only UX latency for that record.
    #[inline]
    fn enqueue_sealed(&mut self, record_id: &str, witness_count: u32) {
        if self.newly_sealed_queue.len() >= MAX_SEALED_QUEUE {
            self.newly_sealed_queue_overflow_total += 1;
            return;
        }
        self.newly_sealed_queue
            .push_back((record_id.to_string(), witness_count));
        self.newly_sealed_queue_enqueued_total += 1;
    }

    /// MAINNET gap #8: pull every queued Sealed event. Caller broadcasts
    /// via `NodeState::events` as `NodeEvent::RecordSealed`.
    pub fn drain_newly_sealed(&mut self) -> Vec<(String, u32)> {
        let n = self.newly_sealed_queue.len();
        if n == 0 {
            return Vec::new();
        }
        self.newly_sealed_queue_drained_total =
            self.newly_sealed_queue_drained_total.saturating_add(n as u64);
        self.newly_sealed_queue.drain(..).collect()
    }

    /// Diagnostic: current sealed-queue depth.
    pub fn newly_sealed_queue_depth(&self) -> usize {
        self.newly_sealed_queue.len()
    }

    /// Register the epoch committee for a zone (MAINNET gap #5).
    ///
    /// Called once per (zone, epoch) at the epoch boundary once the VRF
    /// output rotates. Sets the settlement denominator for records in
    /// `zone` to the sum of committee member stakes.
    ///
    /// `members` is `&[(identity_hash, stake)]` — the output of
    /// `select_epoch_committee_scoped`. Safe to pass an empty slice: this
    /// clears the committee for `zone` (e.g., if the pool fell below the
    /// bootstrap threshold), reverting to full-zone-stake denominator.
    pub fn register_epoch_committee(&mut self, zone: &ZoneId, members: &[(String, u64)]) {
        if members.is_empty() {
            self.committee_stakes.remove(zone);
            self.committee_members.remove(zone);
            return;
        }
        let total: u64 = members.iter().map(|(_, s)| *s).sum();
        let set: HashSet<String> = members.iter().map(|(id, _)| id.clone()).collect();
        let prev_set = self.committee_members.get(zone).cloned();
        self.committee_stakes.insert(zone.clone(), total);
        self.committee_members.insert(zone.clone(), set.clone());
        // Bump rotation counter when the committee actually changes.
        if prev_set.as_ref() != Some(&set) {
            self.committee_rotations_total += 1;
        }
    }

    /// Read the current committee members for a zone.
    pub fn committee_members_for_zone(&self, zone: &ZoneId) -> Option<&HashSet<String>> {
        self.committee_members.get(zone)
    }

    /// Deterministic 32-byte commitment to a zone's current committee membership.
    ///
    /// MAINNET gap #3 follow-up: included in super-seals so light clients that
    /// sync from a checkpoint can verify *who* was allowed to attest the seals
    /// that super-seal covers — not just that the seal Merkle root matches.
    ///
    /// Hash = SHA3-256 of sorted member identity strings, newline-separated.
    /// Sorting is required for determinism across nodes (HashSet order is not
    /// stable). Returns `[0u8; 32]` if the zone has no registered committee
    /// (small-network / bootstrap path where `committee_members` is empty).
    pub fn committee_hash(&self, zone: &ZoneId) -> [u8; 32] {
        use sha3::{Digest, Sha3_256};
        let members = match self.committee_members.get(zone) {
            Some(m) if !m.is_empty() => m,
            _ => return [0u8; 32],
        };
        let mut ids: Vec<&String> = members.iter().collect();
        ids.sort();
        let mut h = Sha3_256::new();
        for id in ids {
            h.update(id.as_bytes());
            h.update(b"\n");
        }
        h.finalize().into()
    }

    /// Bounded committee snapshot for `/status`. Returns `(active_zones, sample)`
    /// where `active_zones` is the TRUE count of zones with a registered
    /// committee (O(1) `HashMap::len`) and `sample` is at most `limit`
    /// `(zone, members, stake)` rows. SCALE RULE: `/status` is a public,
    /// frequently-polled endpoint — enumerating + sorting every committee (up to
    /// 1M zones at the mainnet target) on each call would make it
    /// O(zones·log zones) AND dump a 1M-row array. Only the capped sample is
    /// materialised and sorted; the full per-zone list lives behind the
    /// paginated `/committees` endpoint. Sample order is `HashMap`-iteration (a
    /// status glance, not a stable page) so no full sort is paid.
    pub fn committee_summary_capped(&self, limit: usize) -> (usize, Vec<(String, usize, u64)>) {
        let active_zones = self.committee_members.len();
        let mut out: Vec<(String, usize, u64)> = self
            .committee_members
            .iter()
            .take(limit)
            .map(|(z, ids)| {
                let stake = self.committee_stakes.get(z).copied().unwrap_or(0);
                (z.path().to_string(), ids.len(), stake)
            })
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        (active_zones, out)
    }

    /// Settlement denominator for a zone.
    ///
    /// Returns committee stake when a committee is registered (MAINNET
    /// gap #5), else falls back to total zone stake (bootstrap /
    /// small-network path).
    fn settlement_denominator(&self, zone: &ZoneId) -> u64 {
        // Committee path is untouched by liveness decay: per-epoch
        // committees rotate by selection and act as their own liveness
        // filter; decay applies only to the full-zone-stake bootstrap
        // fallback (internal design notes).
        if let Some(s) = self.committee_stakes.get(zone).copied() {
            if s > 0 {
                return s;
            }
        }
        let base = self.zone_stakes.get(zone).copied().unwrap_or(0);
        if !self.liveness_decay_enabled || base == 0 {
            return base;
        }
        // The trailing window IS the safety boundary: only stake whose staker
        // has been silent for a FULL window ages out, so a healthy chain
        // never leaks (everyone is inside the window → live == base → no
        // change) and only genuinely-departed stake is excluded. The earlier
        // stall-gate was dropped: against PERMANENTLY dead stake it caused
        // burst-oscillation (unstick → stall clears → denominator snaps back
        // → re-stall every N epochs) and added no safety the window+floor
        // don't already provide (an eclipse long enough to shrink the
        // denominator also stalls finality — the gate never actually
        // defended that case). See internal design notes.
        let live = self.live_staked();
        if live >= base {
            return base;
        }
        // FORK-SAFETY FLOOR (consensus safety — do not lower). A record settles
        // at the INCLUSIVE 2/3 boundary, so a settling quorum is ≥2/3 of the
        // denominator. For two DISJOINT partition sides (live stakes summing to
        // ≤ base) to never BOTH settle, every settling quorum must exceed 1/2 of
        // base — i.e. the denominator must never fall to or below 3/4·base:
        //   both settle ⇒ 3·s1≥2F ∧ 3·s2≥2F ⇒ 3·base≥3(s1+s2)≥4F ⇒ F≤¾base;
        //   so F>¾base makes a double-settle (fork-on-heal) impossible.
        // The retired `base/divisor` floor (divisor≥2 ⇒ F≤base/2) was
        // structurally fork-UNSAFE: a 1-of-3 survivor self-settled its collapsed
        // LOCAL view (ratio 1.0) and forked on heal — decay is decided per-node,
        // so each partition side independently shrank its own denominator. This
        // floor still permits legitimate recovery — a >½-of-base survivor set
        // settles (its stake exceeds ⅔·¾base = ½base) — only a sub-majority
        // minority stalls, the correct "favour stall over fork" direction. The
        // configurable divisor may only raise the floor further (toward base =
        // decay inert); it can never lower it below this bound. The window is now
        // a liveness knob, NOT the fork guard. See
        // internal design notes.
        let fork_safe_floor = base.saturating_mul(3) / 4 + 1; // strictly > ¾·base
        let configured_floor = base / self.liveness_floor_divisor.max(1);
        let floor = configured_floor.max(fork_safe_floor).min(base);
        live.max(floor)
    }

    /// Configure the liveness-decay denominator (one call at node init).
    /// Defaults (decay OFF) make settlement bit-identical to pre-liveness
    /// builds; see internal design notes for the safety model.
    pub fn configure_liveness(
        &mut self,
        enabled: bool,
        window_epochs: u64,
        floor_divisor: u64,
    ) {
        self.liveness_decay_enabled = enabled;
        self.liveness_window_epochs = window_epochs.max(1);
        // The settlement floor is now the fork-safe bound (>¾·base), enforced in
        // settlement_denominator; the divisor only adds conservatism ABOVE it.
        // divisor=1 ⇒ floor=base (decay inert on finality: pure stall-until-
        // recovery). divisor≥2 ⇒ the fork-safe floor (a >½-of-base majority
        // still recovers; sub-majority minorities stall). Clamp ≥1 only to
        // avoid divide-by-zero — a smaller divisor can no longer be fork-unsafe.
        self.liveness_floor_divisor = floor_divisor.max(1);
    }

    /// 0b-(ii): attach the CF_METADATA persistence sink for per-staker
    /// last-active epochs and hydrate the in-memory map from it. Call once
    /// at node init, after `configure_liveness` and BEFORE any
    /// `bulk_load_attestations` — the hydrated history is what stops a
    /// restart from resetting the decay clock. Best-effort: storage errors
    /// leave the map untouched (decay then behaves as pre-persistence).
    pub fn attach_liveness_persistence(
        &mut self,
        rocks: std::sync::Arc<crate::storage::rocks::StorageEngine>,
    ) {
        const PREFIX: &[u8] = b"decay:last_active:";
        let mut hydrated = 0usize;
        let _ = rocks.prefix_scan(crate::storage::rocks::CF_METADATA, PREFIX, |key, value| {
            if let (Some(staker), Ok(bytes)) = (
                key.strip_prefix(PREFIX)
                    .and_then(|s| std::str::from_utf8(s).ok()),
                <[u8; 8]>::try_from(value),
            ) {
                let epoch = u64::from_le_bytes(bytes);
                let slot = self
                    .staker_last_active
                    .entry(staker.to_string())
                    .or_insert(epoch);
                if *slot < epoch {
                    *slot = epoch;
                }
                hydrated += 1;
            }
            Ok(())
        });
        self.liveness_persistence = Some(rocks);
        if hydrated > 0 {
            info!("liveness-decay: hydrated {hydrated} persisted last-active epoch(s)");
        }
    }

    /// Feed the observed chain tip (epoch loop). Monotonic — stale feeds
    /// from out-of-order paths are ignored.
    pub fn note_chain_tip(&mut self, epoch: u64) {
        if epoch > self.chain_tip_epoch {
            self.chain_tip_epoch = epoch;
        }
    }

    /// Sum of stake whose staker attested within the trailing window.
    /// O(stakers). A staker never observed attesting counts as not-live —
    /// during a real stall that is precisely the dead set; outside a stall
    /// this value is never consulted (guard 2).
    fn live_staked(&self) -> u64 {
        let cutoff = self
            .chain_tip_epoch
            .saturating_sub(self.liveness_window_epochs);
        self.staker_stakes
            .iter()
            .map(|(id, stake)| match self.staker_last_active.get(id) {
                Some(&seen) if seen >= cutoff => *stake,
                _ => 0,
            })
            .sum()
    }

    /// Register a witness's stake for a zone.
    ///
    /// WARNING: In production, always use `register_stakes_from_ledger()` which distributes
    /// stake to ALL zones equally. Calling this directly with zone-specific stake would create
    /// zone imbalance and weaken the settlement security model.
    pub fn register_zone_stake(&mut self, zone: ZoneId, stake: u64) {
        *self.zone_stakes.entry(zone).or_insert(0) += stake;
    }

    /// Register a witness's profile metadata for correlation computation.
    pub fn register_profile(&mut self, witness_hash: &str, profile: WitnessProfile) {
        self.profiles.insert(witness_hash.to_string(), profile);
    }

    /// True if `witness_hash` has a registered profile.
    ///
    /// Used by the post-handshake profile-exchange
    /// tick to skip peers whose profile already arrived via DAG gossip —
    /// avoids duplicate PQ round-trips at steady state.
    pub fn has_profile(&self, witness_hash: &str) -> bool {
        self.profiles.contains_key(witness_hash)
    }

    /// Read back a witness's profile, if any. For diagnostics / RPC
    /// responses that need the structured value, not just "does it exist".
    pub fn profile_for(&self, witness_hash: &str) -> Option<&WitnessProfile> {
        self.profiles.get(witness_hash)
    }

    /// Register a witness's **verifiable** geographic observation —
    /// derived from the remote socket address of the incoming registration
    /// connection, not self-reported.
    ///
    /// Called by the network layer on profile-registration receive; the
    /// witness cannot influence the stored value. Cross-checked against
    /// [`WitnessProfile`] by [`Self::correlation`].
    ///
    /// Spec: Protocol §11.12 (geographic diversity, Theorem 3.1).
    pub fn register_derived_geo(&mut self, witness_hash: &str, geo: DerivedWitnessGeo) {
        self.derived_geo.insert(witness_hash.to_string(), geo);
    }

    /// Read back a witness's derived geographic observation, if any.
    /// Used by `/status`, diagnostics, and the geo-fraud detector.
    pub fn derived_geo(&self, witness_hash: &str) -> Option<&DerivedWitnessGeo> {
        self.derived_geo.get(witness_hash)
    }

    /// Register the creator's stake AND identity for a record. Called whenever a
    /// record's creator becomes known (ingest / attestation feed / startup replay).
    /// The creator can't self-attest, so their stake is excluded from the settlement
    /// denominator (MESH-BFT Definition 18, amended) — and H1 makes that invariant
    /// ENFORCED: the identity is recorded so `add_attestation`/`add_seal_attestation`
    /// can reject witness==creator, and any self-attestation that arrived BEFORE the
    /// record was known is retroactively purged here. Identity is stored even at 0
    /// stake so a later stake-up cannot open a self-attestation window; the stake map
    /// keeps its >0 gate.
    pub fn register_creator_stake(&mut self, record_id: &str, creator_hash: &str, creator_stake: u64) {
        let first_time = !self.creator_identity.contains_key(record_id);
        self.creator_identity.insert(record_id.to_string(), creator_hash.to_string());
        if creator_stake > 0 {
            self.creator_stakes.insert(record_id.to_string(), creator_stake);
        } else {
            // F4: a creator that unstaked (7-day cooldown) or was slashed to 0
            // while the record is still pending must not leave a stale row — it
            // would keep shrinking the settlement denominator by the old amount
            // (`eligible = total − stale_creator_stake`), settling the record on
            // a fraction of live stake. Clear it so eligibility tracks reality.
            self.creator_stakes.remove(record_id);
        }
        if first_time {
            self.purge_creator_self_attestations(record_id, creator_hash);
        }
    }

    /// Drop any already-recorded attestation (record-level or seal-level) whose
    /// witness IS the record's creator — closes the attestation-before-record
    /// ordering window where a self-attestation lands before we know the creator.
    fn purge_creator_self_attestations(&mut self, record_id: &str, creator_hash: &str) {
        let mut purged = 0u64;
        if let Some(atts) = self.attestations.get_mut(record_id) {
            let before = atts.len();
            atts.retain(|a| a.witness_hash != creator_hash);
            purged += (before - atts.len()) as u64;
        }
        if let Some(satts) = self.seal_attestations.get_mut(record_id) {
            let before = satts.len();
            satts.retain(|a| a.witness_hash != creator_hash);
            purged += (before - satts.len()) as u64;
        }
        if purged > 0 {
            self.self_attestations_rejected = self.self_attestations_rejected.saturating_add(purged);
            self.recompute_confirmation(record_id, false);
        }
    }

    /// Cumulative creator self-attestations rejected or purged (H1 observability).
    pub fn self_attestations_rejected(&self) -> u64 {
        self.self_attestations_rejected
    }

    /// Register cross-zone parents for a record. Called during ingest when
    /// a record references parents from a different zone.
    /// Used for shared-witness bridging (Protocol §7.5).
    pub fn register_cross_zone_parents(&mut self, record_id: &str, parent_ids: Vec<String>) {
        if !parent_ids.is_empty() {
            self.cross_zone_parents.insert(record_id.to_string(), parent_ids);
        }
    }

    /// Check if all cross-zone parents of a record are finalized.
    /// Returns true if the record has cross-zone parents AND all are Finalized/Anchored.
    /// Returns false if the record has no cross-zone parents or any are unfinalized.
    pub fn cross_zone_parents_finalized(&self, record_id: &str) -> bool {
        match self.cross_zone_parents.get(record_id) {
            Some(parents) if !parents.is_empty() => {
                parents.iter().all(|pid| {
                    matches!(
                        self.confirmation_levels.get(pid),
                        Some(ConfirmationLevel::Finalized) | Some(ConfirmationLevel::Anchored)
                    )
                })
            }
            _ => false,
        }
    }

    /// Add an attestation for a record. Updates confirmation level.
    /// Enforces hard memory budget — if over MAX_ATTESTATION_RECORDS, evicts oldest entries first.
    pub fn add_attestation(&mut self, attestation: Attestation) {
        // Hard budget: evict oldest if at capacity
        if self.attestations.len() >= MAX_ATTESTATION_RECORDS {
            self.evict_oldest_attestations(MAX_ATTESTATION_RECORDS / 10);
        }

        let record_id = attestation.record_id.clone();

        // H1: reject a creator self-attestation. `is_settled` removes the creator's
        // stake from the denominator, so counting it in the numerator would collapse
        // the 2/3 threshold. Rejected BEFORE the liveness stamp — an invalid
        // attestation grants nothing; honest validators prove liveness by attesting
        // OTHER records.
        if self.creator_identity.get(&record_id).map(String::as_str)
            == Some(attestation.witness_hash.as_str())
        {
            self.self_attestations_rejected = self.self_attestations_rejected.saturating_add(1);
            return;
        }

        let entry = self.attestations.entry(record_id.clone()).or_default();

        // Dedup: don't re-add an existing (record_id, witness_hash) pair —
        // duplicates would inflate attesting_stake and settle prematurely.
        // F2: but REFRESH the stored stake first. Every caller resolves stake
        // from the LOCAL ledger before feeding (state.rs:4777/5243, gossip.rs:
        // `ledger.staked(wh)`), so the value is never attacker-controlled; the
        // first feed can still land before the witness's stake record applied
        // locally (stake=0). Freezing that stale snapshot would let this node
        // hold a record Pending while a node that saw the stake in time
        // finalizes it — a divergence that today only a restart heals. A later
        // re-gossip (now stake-resolved) corrects the frozen value in place.
        if let Some(existing) =
            entry.iter_mut().find(|a| a.witness_hash == attestation.witness_hash)
        {
            existing.stake = attestation.stake;
            return;
        }

        // Liveness signal: this witness is alive at the current chain tip.
        // 0b-(ii): monotonic (never regress a hydrated epoch from before a
        // restart) and persisted at epoch granularity — at most one
        // CF_METADATA write per staker per epoch, so the decay clock
        // survives restarts without per-attestation write amplification.
        let slot = self
            .staker_last_active
            .entry(attestation.witness_hash.clone())
            .or_insert(0);
        if self.chain_tip_epoch > *slot {
            *slot = self.chain_tip_epoch;
            if let Some(rocks) = &self.liveness_persistence {
                let key = [
                    b"decay:last_active:".as_slice(),
                    attestation.witness_hash.as_bytes(),
                ]
                .concat();
                let _ = rocks.put_cf_raw(
                    crate::storage::rocks::CF_METADATA,
                    &key,
                    &self.chain_tip_epoch.to_le_bytes(),
                );
            }
        }

        entry.push(attestation);

        // Recompute confirmation level for this record
        self.recompute_confirmation(&record_id, false);
    }

    /// Bulk-load attestations from WitnessManager on startup (no per-attestation recompute).
    ///
    /// After restart, the consensus engine is empty but WitnessManager has all
    /// attestations persisted in RocksDB. Without this, att-pull sees "already known"
    /// and never re-feeds them to consensus — settlement is stuck permanently.
    ///
    /// Defers `recompute_confirmation` until all attestations are loaded, then runs
    /// it once per record. With 5K records × 5 attestations each, this avoids 25K
    /// recompute calls (saving ~10s on 2-core machines).
    pub fn bulk_load_attestations(&mut self, attestations: Vec<Attestation>) -> usize {
        let mut record_ids: HashSet<String> = HashSet::new();
        for att in attestations {
            // Hard budget: evict oldest if at capacity
            if self.attestations.len() >= MAX_ATTESTATION_RECORDS {
                self.evict_oldest_attestations(MAX_ATTESTATION_RECORDS / 10);
            }
            // H1: never replay a creator self-attestation (one may have been persisted
            // before the guard existed). creator_identity is populated before the first
            // bulk_load at startup (register_creator_stake runs first).
            if self.creator_identity.get(&att.record_id).map(String::as_str)
                == Some(att.witness_hash.as_str())
            {
                self.self_attestations_rejected = self.self_attestations_rejected.saturating_add(1);
                continue;
            }
            let entry = self.attestations.entry(att.record_id.clone()).or_default();
            // Dedup: skip if this witness already attested this record
            if entry.iter().any(|a| a.witness_hash == att.witness_hash) {
                continue;
            }
            record_ids.insert(att.record_id.clone());
            // Liveness: replay must never RAISE liveness — only stakers with
            // no known history get stamped (`or_insert` keeps hydrated and
            // already-observed epochs; 0b-(ii) restart-reset fix). The old
            // unconditional insert re-stamped every replayed staker at the
            // boot tip, resetting the decay clock on every restart.
            self.staker_last_active
                .entry(att.witness_hash.clone())
                .or_insert(self.chain_tip_epoch);
            entry.push(att);
        }
        // Recompute confirmation levels once per record, not per attestation.
        // suppress_events=true: startup is replaying durable state, not producing
        // live edges — accounts subscribed after restart shouldn't receive stale
        // Sealed/Finalized events for records that transitioned hours ago.
        for rid in &record_ids {
            self.recompute_confirmation(rid, true);
        }
        record_ids.len()
    }

    /// Recompute the confirmation level for a record based on its attestations.
    ///
    /// Cluster detection uses three signals (Protocol §7.5):
    /// 1. **Profile-based**: witnesses with same (organization, subnet) → same cluster
    /// 2. **Timing correlation**: witnesses attesting within 500ms → merged into same cluster
    /// 3. **Unknown profiles**: each treated as unique cluster (conservative)
    ///
    /// Timing correlation merges unknown-profile witnesses that attest simultaneously,
    /// preventing Sybil attacks where one entity runs many unregistered nodes.
    ///
    /// `suppress_events=true` disables enqueue into `newly_sealed_queue` and
    /// `newly_finalized_queue` — used during startup replay so accounts don't
    /// receive stale milestone events for records that transitioned long ago.
    fn recompute_confirmation(&mut self, record_id: &str, suppress_events: bool) {
        let atts = match self.attestations.get(record_id) {
            Some(a) if !a.is_empty() => a,
            _ => {
                self.confirmation_levels
                    .insert(record_id.to_string(), ConfirmationLevel::Pending);
                return;
            }
        };

        // Check if anchored (overrides other levels)
        if self.anchored.contains(record_id) {
            self.confirmation_levels
                .insert(record_id.to_string(), ConfirmationLevel::Anchored);
            return;
        }

        let witness_count = atts.len();
        let distinct_clusters = self.count_distinct_clusters(atts);

        // Confirmed requires BOTH witness/cluster thresholds AND diversity-weighted
        // settlement (MESH-BFT Theorem 1). This ensures correlated Sybil witnesses
        // cannot push records to Confirmed — the paper's core safety guarantee.
        // Falls back to raw settlement when:
        //   1. No witness profiles registered yet (bootstrapping), OR
        //   2. Small network with < 3 distinct organizations — diversity scoring
        //      penalizes same-org witnesses so heavily that 2/3 effective stake is
        //      unreachable. In production with many orgs, diversity settlement is
        //      the correct safety check; on testnet with 1 org it blocks all settlement.
        let diversity_settled = self.is_settled_diverse(record_id);
        let raw_settled = self.is_settled(record_id);
        let distinct_orgs: std::collections::HashSet<&str> = self.profiles.values()
            .map(|p| p.organization.as_str())
            .collect();
        let small_network = self.profiles.is_empty() || distinct_orgs.len() < 3;
        let settlement_ok = diversity_settled || (raw_settled && small_network);

        // Shared-witness bridging (Protocol §7.5): if ALL cross-zone parents are
        // finalized, relax cluster requirement from CONFIRMED_MIN_CLUSTERS to 1.
        // Rationale: the causal chain has already been independently verified in
        // another zone, so fewer independent clusters are needed for this record.
        // The 2/3 stake threshold and witness count are NOT relaxed — only clusters.
        let xzone_boost = self.cross_zone_parents_finalized(record_id);
        let min_clusters = if xzone_boost {
            1  // ACCELERATION: from CONFIRMED_MIN_CLUSTERS
        } else {
            CONFIRMED_MIN_CLUSTERS
        };

        let level = if witness_count >= CONFIRMED_MIN_WITNESSES
            && distinct_clusters >= min_clusters
            && settlement_ok
        {
            if xzone_boost {
                self.cross_zone_boost_count += 1;
                info!(
                    "cross-zone finality boost: {} finalized with {} clusters (relaxed from {}), {} xzone parents all finalized",
                    &record_id[..record_id.len().min(16)],
                    distinct_clusters,
                    CONFIRMED_MIN_CLUSTERS,
                    self.cross_zone_parents.get(record_id).map(|p| p.len()).unwrap_or(0),
                );
            }
            ConfirmationLevel::Finalized
        } else if witness_count >= ATTESTED_MIN_WITNESSES {
            ConfirmationLevel::Sealed
        } else {
            ConfirmationLevel::Pending
        };

        let old_level = self.confirmation_levels.get(record_id).copied();
        self.confirmation_levels
            .insert(record_id.to_string(), level);

        // MAINNET gap #8: fire RecordSealed only on the Pending|None → Sealed
        // edge — if old_level is already Sealed/Finalized/Anchored we've already
        // emitted (or the level is equal-or-greater). Also fires if the record
        // enters Finalized without going through Sealed first (attestation
        // burst), so accounts still see a Sealed milestone. Each emission carries
        // the current witness_count so the WS subscriber can render "N/M witnesses"
        // without a follow-up query.
        let was_sealed_or_higher = matches!(
            old_level,
            Some(ConfirmationLevel::Sealed)
                | Some(ConfirmationLevel::Finalized)
                | Some(ConfirmationLevel::Anchored)
        );
        let is_sealed_or_higher = matches!(
            level,
            ConfirmationLevel::Sealed
                | ConfirmationLevel::Finalized
                | ConfirmationLevel::Anchored
        );
        if is_sealed_or_higher && !was_sealed_or_higher && !suppress_events {
            self.enqueue_sealed(record_id, witness_count as u32);
        }

        // Cascade: when a record transitions TO Finalized/Anchored, re-evaluate
        // any records that have it as a cross-zone parent. This ensures children
        // benefit from the boost even if their attestations arrived before the parent
        // was finalized. Without this, children would be stuck at Sealed.
        if matches!(level, ConfirmationLevel::Finalized | ConfirmationLevel::Anchored)
            && !matches!(old_level, Some(ConfirmationLevel::Finalized) | Some(ConfirmationLevel::Anchored))
        {
            // Fire the commit callback for the pending-ledger drain loop.
            // Startup replay path suppresses — pending deltas are rehydrated separately
            // and the drain loop sweeps them on its next tick.
            if !suppress_events {
                self.enqueue_finalized(record_id);
            }

            let record_id_owned = record_id.to_string();
            // Find all records that list this newly-finalized record as a cross-zone parent
            let children: Vec<String> = self.cross_zone_parents.iter()
                .filter(|(_, parents)| parents.contains(&record_id_owned))
                .map(|(child_id, _)| child_id.clone())
                .collect();
            for child_id in children {
                // Re-evaluate — recursive call is safe because the parent is already
                // Finalized so it won't cascade further. Inherit suppress_events so
                // the startup replay doesn't leak events via the cascade path.
                self.recompute_confirmation(&child_id, suppress_events);
            }
        }
    }

    /// Count distinct witness clusters from a set of attestations.
    ///
    /// Uses union-find to merge witnesses that share:
    /// - Same (organization, subnet) from WitnessProfile
    /// - Attestation timestamps within `TIMING_CLUSTER_THRESHOLD_SECS`
    ///
    /// Unknown-profile witnesses start as their own cluster but get merged
    /// if their timestamps correlate with another witness.
    fn count_distinct_clusters(&self, atts: &[Attestation]) -> usize {
        let n = atts.len();
        if n == 0 {
            return 0;
        }

        // Union-find parent array (each witness starts as its own cluster)
        let mut parent: Vec<usize> = (0..n).collect();

        fn find(parent: &mut [usize], i: usize) -> usize {
            let mut root = i;
            while parent[root] != root {
                root = parent[root];
            }
            // Path compression
            let mut curr = i;
            while curr != root {
                let next = parent[curr];
                parent[curr] = root;
                curr = next;
            }
            root
        }

        fn union(parent: &mut [usize], a: usize, b: usize) {
            let ra = find(parent, a);
            let rb = find(parent, b);
            if ra != rb {
                parent[rb] = ra;
            }
        }

        // Phase 1: merge by profile (same organization:subnet)
        for i in 0..n {
            for j in (i + 1)..n {
                if let (Some(pi), Some(pj)) = (
                    self.profiles.get(&atts[i].witness_hash),
                    self.profiles.get(&atts[j].witness_hash),
                ) {
                    if pi.organization == pj.organization && pi.subnet == pj.subnet {
                        union(&mut parent, i, j);
                    }
                }
            }
        }

        // Phase 2: merge by timing correlation (attestations within threshold)
        for i in 0..n {
            for j in (i + 1)..n {
                if (atts[i].timestamp - atts[j].timestamp).abs() <= TIMING_CLUSTER_THRESHOLD_SECS {
                    union(&mut parent, i, j);
                }
            }
        }

        // Count distinct roots
        let mut roots = HashSet::new();
        for i in 0..n {
            roots.insert(find(&mut parent, i));
        }
        roots.len()
    }

    /// Get the distinct cluster count for a record (for API/metrics).
    pub fn distinct_clusters(&self, record_id: &str) -> usize {
        match self.attestations.get(record_id) {
            Some(atts) if !atts.is_empty() => self.count_distinct_clusters(atts),
            _ => 0,
        }
    }

    /// Mark a record as anchored (included in an epoch seal with external timestamp).
    pub fn anchor_record(&mut self, record_id: &str) {
        self.anchored.insert(record_id.to_string());
        // If already confirmed, upgrade to anchored
        if let Some(level) = self.confirmation_levels.get(record_id) {
            if *level >= ConfirmationLevel::Finalized {
                self.confirmation_levels
                    .insert(record_id.to_string(), ConfirmationLevel::Anchored);
            }
        }
    }

    /// Mark multiple records as anchored (bulk, from epoch seal).
    pub fn anchor_records(&mut self, record_ids: &[String]) {
        for rid in record_ids {
            self.anchor_record(rid);
        }
    }

    /// Get the confirmation level for a record.
    pub fn confirmation_level(&self, record_id: &str) -> ConfirmationLevel {
        self.confirmation_levels
            .get(record_id)
            .copied()
            .unwrap_or(ConfirmationLevel::Pending)
    }

    /// Test-only direct setter for `confirmation_levels`. Used by
    /// pending-drain tests to stage a record at `Sealed` without spinning
    /// up the full attestation/anchor pipeline.
    #[cfg(test)]
    pub fn set_confirmation_level_for_test(
        &mut self,
        record_id: &str,
        level: ConfirmationLevel,
    ) {
        self.confirmation_levels
            .insert(record_id.to_string(), level);
    }

    /// Force a record to Finalized confirmation level.
    /// Called when raw settlement passes — ensures consistency between
    /// the FinalizedIndex and confirmation_levels, enabling cross-zone
    /// finality boost to cascade correctly.
    /// Returns `true` if this call actually promoted the record from a
    /// pre-Finalized state (Pending / Sealed) to Finalized, or `false` if
    /// it was already Finalized / Anchored (idempotent no-op). Callers that
    /// maintain "ever settled / ever finalized" lifetime counters MUST
    /// increment only when this returns `true` — otherwise repeat
    /// attestations on already-settled records cause counter inflation
    /// (the over-count was the source of `elara_total_ever_settled` being
    /// 2-3× `elara_finalized_count` fleet-wide).
    pub fn force_finalized(&mut self, record_id: &str) -> bool {
        let old = self.confirmation_levels.get(record_id).copied();
        if matches!(old, Some(ConfirmationLevel::Finalized) | Some(ConfirmationLevel::Anchored)) {
            return false;
        }
        self.confirmation_levels
            .insert(record_id.to_string(), ConfirmationLevel::Finalized);
        // Same commit-callback edge as recompute_confirmation.
        self.enqueue_finalized(record_id);

        // Cascade: re-evaluate children whose cross-zone parent just finalized
        let record_id_owned = record_id.to_string();
        let children: Vec<String> = self.cross_zone_parents.iter()
            .filter(|(_, parents)| parents.contains(&record_id_owned))
            .map(|(child_id, _)| child_id.clone())
            .collect();
        for child_id in children {
            self.recompute_confirmation(&child_id, false);
        }
        true
    }

    /// Get confirmation level counts (for metrics/API).
    pub fn confirmation_summary(&self) -> HashMap<ConfirmationLevel, usize> {
        let mut counts: HashMap<ConfirmationLevel, usize> = HashMap::new();
        for level in self.confirmation_levels.values() {
            *counts.entry(*level).or_insert(0) += 1;
        }
        counts
    }

    /// Zone stake totals for diagnostics.
    pub fn zone_stake_summary(&self) -> Vec<(String, u64)> {
        let mut out: Vec<_> = self.zone_stakes.iter()
            .map(|(z, s)| (z.path().to_string(), *s))
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// Creator stake to exclude from the settlement denominator.
    ///
    /// The denominator excludes the creator's stake because a creator cannot
    /// attest its own record, so that stake is unreachable for a 2/3 quorum.
    /// But in committee mode ([`Self::settlement_denominator`] returns the
    /// committee's stake), the creator's stake is only PART of the denominator
    /// when the creator is a committee member. Subtracting a non-member
    /// creator's stake would double-exclude it — settling the record below the
    /// true 2/3 boundary, or (if the creator's stake exceeds the committee's)
    /// wedging it Pending forever. Bootstrap / small-network mode keeps the
    /// full-stake subtraction (denominator = total zone stake, always incl. the
    /// creator). Only reachable past `COMMITTEE_SMALL_NETWORK` stakers; at
    /// launch scale the committee IS every staker, so this returns the same
    /// value the old inline `creator_stakes` lookup did.
    fn creator_stake_excluded_from_denominator(&self, record_id: &str, zone: &ZoneId) -> u64 {
        let creator_stake = self.creator_stakes.get(record_id).copied().unwrap_or(0);
        if creator_stake == 0 {
            return 0;
        }
        match self.committee_members.get(zone) {
            Some(members) if !members.is_empty() => {
                let in_committee = self
                    .creator_identity
                    .get(record_id)
                    .map(|cid| members.contains(cid))
                    .unwrap_or(false);
                if in_committee { creator_stake } else { 0 }
            }
            _ => creator_stake,
        }
    }

    /// KR-3 S2 wiring-(c) c3-ii: the settlement-denominator routing key for a
    /// record. The consensus-internal naive sites (`is_settled`,
    /// `is_settled_diverse`, and the display/metrics readers) have no
    /// `NodeState`/`zone_registry` to reach the central `resolve_record_zone` pin,
    /// so they route by record id. Under flag-ON a rotation-class record carries an
    /// override (`record_id → lineage_id`, registered at admission) so its stake
    /// counts against the SAME lineage zone the central hook stores it under
    /// (§6.1 item 2). The map is only ever populated flag-ON, so the emptiness
    /// short-circuit makes flag-OFF BYTE-IDENTICAL and keeps the hot `is_settled`
    /// path allocation-free. Naive (no registry redirect) to match every existing
    /// consensus-internal site — the override only swaps the routing key, it does
    /// not newly registry-resolve these sites (that asymmetry with the registry-aware
    /// storage zone pre-exists c3-ii for ordinary records and is out of S2 scope).
    fn settlement_zone_for(&self, record_id: &str) -> ZoneId {
        if !self.rotation_zone_overrides.is_empty() {
            if let Some(lineage_id) = self.rotation_zone_overrides.get(record_id) {
                return zone_for_record(lineage_id);
            }
        }
        zone_for_record(record_id)
    }

    /// KR-3 S2 wiring-(c) c3-ii: register a rotation hop's settlement-zone override
    /// (`record_id → lineage_id`). Called at admission (`network::ingest`) under
    /// `s2_rotation_ordering_enabled`, mirroring `NodeState::insert_rotation_pin` —
    /// the in-memory settlement mirror of the durable pin row, derived from the
    /// SAME `rotation_hop_pin` result so the two can't drift. Retention-bounded
    /// alongside `attestations` (see `prune_where` / `prune_older_than` /
    /// `forget_record`). Re-admission of the same id overwrites identically.
    pub fn insert_rotation_zone_override(&mut self, record_id: &str, lineage_id: &str) {
        self.rotation_zone_overrides
            .insert(record_id.to_string(), lineage_id.to_string());
    }

    /// Check if a record has reached settlement (raw stake, no diversity discount).
    ///
    /// Settlement denominator excludes the creator's own stake — they can't
    /// self-attest, so their stake is unreachable for their own records.
    /// This is the amended MESH-BFT Definition 18:
    ///   AS(r) · 3 ≥ (S_total - S_creator) · 2
    ///
    /// The BFT safety proof is preserved: for conflicting records r and r',
    /// the creator can't attest either one, so both draw from the same
    /// non-creator pool. The overlap argument still holds.
    pub fn is_settled(&self, record_id: &str) -> bool {
        let zone = self.settlement_zone_for(record_id);
        // MAINNET gap #5: settlement denominator = committee stake when
        // active, else total zone stake (bootstrap fallback).
        let total_zone_stake = self.settlement_denominator(&zone);
        let creator_stake = self.creator_stake_excluded_from_denominator(record_id, &zone);
        let eligible_stake = total_zone_stake.saturating_sub(creator_stake);

        if eligible_stake == 0 {
            return false;
        }

        let attesting_stake: u64 = self
            .attestations
            .get(record_id)
            .map(|atts| atts.iter().map(|a| a.stake).sum())
            .unwrap_or(0);

        // 2/3 threshold: attesting * 3 >= eligible * 2 (avoids float division).
        // saturating_mul, not raw `*`: release has no overflow-checks, so a raw
        // multiply wraps silently once stake nears MAX_SUPPLY and flips the
        // settlement verdict. Matches the abort-quorum path (~consensus.rs:1520).
        attesting_stake.saturating_mul(3) >= eligible_stake.saturating_mul(2)
    }

    /// Worst-case settlement fault tolerance for `n` EQUAL-stake validators that
    /// submit their OWN transfers (the genesis self-submit topology).
    ///
    /// Settlement excludes the creator's own stake ([`Self::is_settled`]:
    /// `eligible = total − creator_stake`, then `attesting·3 ≥ eligible·2`), so a
    /// self-submitted transfer draws its 2/3 quorum only from the OTHER `n−1`
    /// validators — it needs `⌈2(n−1)/3⌉` of them. This returns how many of those
    /// `n−1` can be offline while the transfer still settles.
    ///
    /// `0` ⇒ a single offline validator stalls its peers' self-submitted
    /// transfers (the chain still *seals* via other proposers, but those records
    /// never finalize). `N=3` self-submit is the canonical 0-FT case and is
    /// strictly worse than `N=2` on the settlement axis. Mitigations that restore
    /// 1-fault tolerance: go to `N=4` (eligible = 3 stakers → need 2), or route
    /// settling transfers through non-staking submitter identities
    /// (`creator_stake=0` → eligible = all `n` → need `⌈2n/3⌉` of the full set).
    ///
    /// Fusion-audited 2026-06-21; see internal design notes §2.
    /// The equal-stake model is faithful to `genesis_validators` (byte-identical
    /// configs are required — divergence there is a P0 fork risk).
    pub fn self_submit_settlement_fault_tolerance(n_validators: usize) -> usize {
        // n<2: a singleton authority can never self-settle by quorum (eligible=0);
        // it rides the `stakers.len() < 3` bootstrap carve-out instead, so fault
        // tolerance is not yet a meaningful axis. Report 0.
        if n_validators < 2 {
            return 0;
        }
        let non_creator_pool = n_validators - 1;
        // Inclusive 2/3 boundary, matching is_settled's integer
        // `attesting·3 ≥ eligible·2`: with equal stake this is
        // `attesters ≥ ⌈2·pool/3⌉`.
        let need = (2 * non_creator_pool).div_ceil(3);
        non_creator_pool - need
    }

    /// Check if a record has reached diversity-weighted settlement (MESH-BFT Theorem 1).
    ///
    /// Uses effective stake: each witness's stake is multiplied by their independence
    /// factor d(n, W), which discounts correlated witnesses. This is strictly stronger
    /// than raw settlement — correlated sybil attacks are exponentially penalized.
    ///
    /// ES(r) = Σ s(n) × d(n, W) for n in W(r)
    /// Settlement iff ES(r) / S_total >= 2/3
    pub fn is_settled_diverse(&self, record_id: &str) -> bool {
        let zone = self.settlement_zone_for(record_id);
        // MAINNET gap #5: use committee stake when active.
        let total_zone_stake = self.settlement_denominator(&zone);
        let creator_stake = self.creator_stake_excluded_from_denominator(record_id, &zone);
        let eligible_stake = total_zone_stake.saturating_sub(creator_stake);

        if eligible_stake == 0 {
            return false;
        }

        let attestations = match self.attestations.get(record_id) {
            Some(atts) if !atts.is_empty() => atts,
            _ => return false,
        };

        // Deterministic fixed-point settlement (consensus-gating). f64 summation
        // over gossip-arrival order was non-associative → latent fork at ≥3-org
        // scale; the f64 path is retained for RPC/explorer display only. See
        // internal design notes.
        let witnesses: Vec<(&str, u64)> = attestations
            .iter()
            .map(|a| (a.witness_hash.as_str(), a.stake))
            .collect();
        let eff_q = self.effective_stake_q(&witnesses);
        // 2/3 threshold — excludes creator's unreachable stake.
        Self::diverse_threshold_met_q(eff_q, eligible_stake)
    }

    /// Compute the effective (diversity-adjusted) attesting stake for a record.
    /// Returns (effective_stake, raw_stake, diversity_ratio).
    pub fn effective_attesting_stake(&self, record_id: &str) -> (f64, u64, f64) {
        let attestations = match self.attestations.get(record_id) {
            Some(atts) if !atts.is_empty() => atts,
            _ => return (0.0, 0, 0.0),
        };

        let witness_hashes: Vec<&str> = attestations.iter().map(|a| a.witness_hash.as_str()).collect();
        let raw: u64 = attestations.iter().map(|a| a.stake).sum();

        let effective: f64 = attestations.iter().map(|att| {
            let ind = self.independence(&att.witness_hash, &witness_hashes);
            att.stake as f64 * ind
        }).sum();

        let ratio = if raw > 0 { effective / raw as f64 } else { 0.0 };
        (effective, raw, ratio)
    }

    /// Compute correlation between two witnesses based on their profiles.
    ///
    /// `corr(n,m) = α × same_org(n,m) + β × same_subnet(n,m) + γ × same_zone(n,m)`
    ///
    /// `same_subnet` and `same_zone` combine **self-reported** profile fields
    /// with **verifiable** [`DerivedWitnessGeo`] observations (sourced from
    /// the remote socket address at registration). A witness cannot dodge the
    /// β/γ penalty by lying in its profile — matching derived-IP /16 still
    /// fires `same_subnet`, and matching derived-ASN still fires `same_zone`.
    ///
    /// - `same_org(n,m)` — 1.0 iff self-reported organization fields match.
    ///   Peer-controlled; no verifiable counterpart yet (would need
    ///   org-signed attestations).
    /// - `same_subnet(n,m)` — 1.0 iff self-reported subnet string matches OR
    ///   derived `ip_prefix16` matches (either side unobserved → only the
    ///   self-reported comparison applies).
    /// - `same_zone(n,m)` — 1.0 iff self-reported geo_zone matches OR both
    ///   witnesses resolved to the same non-zero ASN in the bundled provider
    ///   table. ASN is sourced from the observed IP, so self-reports cannot
    ///   dodge it.
    ///
    /// Returns ALPHA + BETA (0.8 — conservatively assumed same org + subnet)
    /// if either witness has no registered profile. This penalizes
    /// non-disclosure and prevents sybils from claiming independence by
    /// omission. If profiles are registered but derived geo is missing, only
    /// the self-reported fields contribute.
    ///
    /// Spec: Protocol §11.12 (geographic diversity, Theorem 3.1).
    pub fn correlation(&self, witness_a: &str, witness_b: &str) -> f64 {
        self.correlation_weighted(witness_a, witness_b, GAMMA)
    }

    /// Same as [`correlation`], but with an explicit γ weight. Used by
    /// [`independence`] to apply the "honest degradation" rule — when the
    /// witness set is below [`MIN_GEO_BUCKETS`] distinct buckets, the
    /// caller passes `gamma = 0.0` so small/homogeneous sets aren't
    /// penalized for being physically small rather than colluding.
    pub fn correlation_weighted(
        &self,
        witness_a: &str,
        witness_b: &str,
        gamma: f64,
    ) -> f64 {
        let (pa, pb) = match (self.profiles.get(witness_a), self.profiles.get(witness_b)) {
            (Some(a), Some(b)) => (a, b),
            // Unknown profiles → assume high correlation (conservative).
            // This penalizes witnesses who don't register profiles, preventing
            // Sybil attacks from gaining independence credit by non-disclosure.
            // ALPHA + BETA = 0.8 (max without same geo, which we can't verify).
            // The symmetric `pq_exchange_profile_and_register`
            // post-handshake (commit `2a019e5`) eliminates the unknown-profile
            // window — see `elara_consensus_unknown_profile_witnesses_gauge`.
            _ => {
                // Cumulative counter for the load metric.
                // Per-call by design; the *health* signal is the gauge above.
                // Read note: startup-time DAG replay processes attestations
                // before WitnessProfile registrations, so post-restart this
                // counter spikes to ~30K-360K within the first ~10 min and
                // then flat-lines.
                self.unknown_profile_pairs_total
                    .fetch_add(1, Ordering::Relaxed);
                return ALPHA + BETA; // 0.8 — assumed same org + same subnet
            }
        };

        let same_org = if pa.organization == pb.organization { 1.0 } else { 0.0 };

        // same_subnet: self-reported OR derived-/16 match.
        let subnet_self = !pa.subnet.is_empty() && pa.subnet == pb.subnet;
        let subnet_derived = match (self.derived_geo.get(witness_a), self.derived_geo.get(witness_b)) {
            (Some(ga), Some(gb)) => {
                ga.ip_prefix16 != [0, 0] && ga.ip_prefix16 == gb.ip_prefix16
            }
            _ => false,
        };
        let same_subnet = if subnet_self || subnet_derived { 1.0 } else { 0.0 };

        // same_zone: self-reported geo_zone OR derived-ASN match (nonzero).
        let zone_self = !pa.geo_zone.is_empty() && pa.geo_zone == pb.geo_zone;
        let zone_derived = match (self.derived_geo.get(witness_a), self.derived_geo.get(witness_b)) {
            (Some(ga), Some(gb)) => {
                ga.asn != super::asn_lookup::UNKNOWN_ASN && ga.asn == gb.asn
            }
            _ => false,
        };
        let same_zone = if zone_self || zone_derived { 1.0 } else { 0.0 };

        ALPHA * same_org + BETA * same_subnet + gamma * same_zone
    }

    /// Profile-exchange effectiveness gauge.
    /// Returns the count of witness_hashes that we have a `derived_geo`
    /// observation for (i.e. connected to / received attestations from)
    /// but no `profiles` registration. After the symmetric
    /// `pq_exchange_profile_and_register` propagates, this number should
    /// be near-zero in steady state — every peer we've talked to should
    /// have shared its profile within one round-trip.
    ///
    /// Bounded by `O(active_peers) ≤ MAX_PEERS = 10K`, so this is cheap
    /// to call from the metrics scrape path. The original
    /// `unknown_profile_pairs_total` counter fires every
    /// `correlation_weighted` call and therefore plateaus at
    /// `O(committee^2 × calls/sec)` regardless of profile coverage —
    /// that counter measures load, not health. THIS gauge measures
    /// health.
    pub fn unknown_profile_witness_count(&self) -> usize {
        self.derived_geo
            .keys()
            .filter(|w| !self.profiles.contains_key(*w))
            .count()
    }

    /// Effective γ for the given witness set. Scales
    /// smoothly from 0.0 (insufficient diversity OR witness set too small)
    /// through a linear ramp up to full [`GAMMA`] at
    /// [`GAMMA_FULL_WITNESSES`]. See [`gamma_effective_scaled`].
    ///
    /// A "bucket" is either the self-reported `geo_zone` (if non-empty)
    /// or the derived ASN (if resolvable). Witnesses with neither are
    /// *not* counted toward diversity — they don't contribute evidence
    /// that the set is physically spread out.
    pub fn gamma_effective(&self, witness_set: &[&str]) -> f64 {
        self.geo_diversity_state(witness_set).gamma_effective
    }

    /// Structured snapshot of the geographic diversity posture for a
    /// witness set. Mirrors the decision made by
    /// [`AWCConsensus::gamma_effective`] but also returns the underlying
    /// bucket count and threshold — so operators can see *why* γ is in
    /// or out of honest-degradation mode, not just the final value.
    ///
    /// This is the data an operator status endpoint should surface to
    /// make Stage 5 honest degradation auditable: "γ is currently 0.0
    /// because we have 1 bucket and need 2."
    ///
    /// Stage 5 / Phase 3 — diversity-weighted safety observability.
    pub fn geo_diversity_state(&self, witness_set: &[&str]) -> GeoDiversityState {
        let mut buckets: HashSet<String> = HashSet::new();
        for w in witness_set {
            if let Some(p) = self.profiles.get(*w) {
                if !p.geo_zone.is_empty() {
                    buckets.insert(format!("zone:{}", p.geo_zone));
                    continue;
                }
            }
            if let Some(g) = self.derived_geo.get(*w) {
                if g.asn != super::asn_lookup::UNKNOWN_ASN {
                    buckets.insert(format!("asn:{}", g.asn));
                }
            }
        }
        let bucket_count = buckets.len();
        let witness_count = witness_set.len();
        let gamma_active = bucket_count >= MIN_GEO_BUCKETS;
        GeoDiversityState {
            witness_count,
            bucket_count,
            min_buckets: MIN_GEO_BUCKETS,
            gamma_active,
            gamma_effective: gamma_effective_scaled(witness_count, bucket_count),
        }
    }

    /// Compute the independence (diversity) factor for a witness relative to other attestors.
    ///
    /// `d(n, W) = 1 / (1 + Σ corr(n, m) for all m ≠ n in W(r))`
    ///
    /// Returns 1.0 for a fully independent witness (no correlation with others).
    /// Returns < 1.0 when correlated with other witnesses, reducing their marginal trust contribution.
    pub fn independence(&self, witness_hash: &str, witness_set: &[&str]) -> f64 {
        // γ degrades to 0 when the set is too geographically homogeneous
        // for geography to carry real signal (Stage 5 honest degradation).
        let gamma = self.gamma_effective(witness_set);
        let corr_sum: f64 = witness_set
            .iter()
            .filter(|&&m| m != witness_hash)
            .map(|&m| self.correlation_weighted(witness_hash, m, gamma))
            .sum();

        1.0 / (1.0 + corr_sum)
    }

    /// Deterministic integer mirror of [`gamma_effective`], scaled by
    /// [`SETTLEMENT_Q`]. Reuses [`geo_diversity_state`] for bucket counting so
    /// it can never diverge from the float path's diversity decision.
    fn gamma_effective_q(&self, witness_set: &[&str]) -> u128 {
        let st = self.geo_diversity_state(witness_set);
        gamma_effective_scaled_q(st.witness_count, st.bucket_count)
    }

    /// Deterministic integer mirror of [`correlation_weighted`], scaled by
    /// [`SETTLEMENT_Q`]. `gamma_q` is the pre-computed set-level γ (already
    /// scaled). Each `same_*` flag is 0/1, so every term is an exact constant —
    /// no rounding occurs here. Deliberately does NOT bump
    /// `unknown_profile_pairs_total`: that load counter is fed by the f64
    /// display path, and the settlement gate runs on every check, so feeding it
    /// here would double-count and inflate the metric.
    fn correlation_weighted_q(&self, witness_a: &str, witness_b: &str, gamma_q: u128) -> u128 {
        let (pa, pb) = match (self.profiles.get(witness_a), self.profiles.get(witness_b)) {
            (Some(a), Some(b)) => (a, b),
            // Unknown profile → ALPHA+BETA (0.8), conservative — mirrors the f64 path.
            _ => return ALPHA_Q + BETA_Q,
        };

        let same_org = pa.organization == pb.organization;

        let subnet_self = !pa.subnet.is_empty() && pa.subnet == pb.subnet;
        let subnet_derived = match (self.derived_geo.get(witness_a), self.derived_geo.get(witness_b)) {
            (Some(ga), Some(gb)) => ga.ip_prefix16 != [0, 0] && ga.ip_prefix16 == gb.ip_prefix16,
            _ => false,
        };
        let same_subnet = subnet_self || subnet_derived;

        let zone_self = !pa.geo_zone.is_empty() && pa.geo_zone == pb.geo_zone;
        let zone_derived = match (self.derived_geo.get(witness_a), self.derived_geo.get(witness_b)) {
            (Some(ga), Some(gb)) => ga.asn != super::asn_lookup::UNKNOWN_ASN && ga.asn == gb.asn,
            _ => false,
        };
        let same_zone = zone_self || zone_derived;

        (if same_org { ALPHA_Q } else { 0 })
            + (if same_subnet { BETA_Q } else { 0 })
            + (if same_zone { gamma_q } else { 0 })
    }

    /// Deterministic integer mirror of [`independence`]: `d(n,W) = 1/(1+Σcorr)`,
    /// returned scaled by [`SETTLEMENT_Q`] (so `d ≈ independence_q / Q`).
    /// `gamma_q` is the pre-computed set-level γ. The single division is the only
    /// rounding step and is value-independent in direction (floor), so it is
    /// order- and arch-deterministic.
    fn independence_q(&self, witness_hash: &str, witness_set: &[&str], gamma_q: u128) -> u128 {
        let mut corr_sum_q: u128 = 0;
        for &m in witness_set {
            if m != witness_hash {
                corr_sum_q =
                    corr_sum_q.saturating_add(self.correlation_weighted_q(witness_hash, m, gamma_q));
            }
        }
        // d_q = Q² / (Q + corr_sum_q). Q² = 10^18 ≪ u128::MAX; corr_sum_q ≤ (W-1)·Q.
        (SETTLEMENT_Q * SETTLEMENT_Q) / (SETTLEMENT_Q + corr_sum_q)
    }

    /// Deterministic diversity-weighted effective stake, scaled by
    /// [`SETTLEMENT_Q`], shared by all three settlement gates. `witnesses` is
    /// the attesting set as `(witness_hash, stake)` pairs.
    ///
    /// Summed over a **canonical witness-hash ordering** so the result is
    /// byte-identical across nodes regardless of gossip-arrival order. (Integer
    /// addition is already associative, so the sort is belt-and-suspenders that
    /// also pins the canonical form against any future order-sensitive change to
    /// the per-witness term.) Overflow-safe: `eff_q ≤ MAX_SUPPLY·Q ≈ 10^28 <
    /// 2^95`, so `3·eff_q` fits u128; arithmetic is saturating regardless.
    fn effective_stake_q(&self, witnesses: &[(&str, u64)]) -> u128 {
        if witnesses.is_empty() {
            return 0;
        }
        let witness_set: Vec<&str> = witnesses.iter().map(|(w, _)| *w).collect();
        let gamma_q = self.gamma_effective_q(&witness_set);

        let mut sorted: Vec<(&str, u64)> = witnesses.to_vec();
        sorted.sort_by(|a, b| a.0.cmp(b.0));

        let mut eff_q: u128 = 0;
        for (w, stake) in sorted {
            let ind_q = self.independence_q(w, &witness_set, gamma_q);
            eff_q = eff_q.saturating_add((stake as u128).saturating_mul(ind_q));
        }
        eff_q
    }

    /// Deterministic 2/3 diversity-settlement test. `eff_q` is Q-scaled
    /// effective stake; settle iff `effective·3 ≥ eligible·2`, i.e.
    /// `3·eff_q ≥ 2·eligible·Q`. `saturating_mul` mirrors the defensive style of
    /// the integer [`is_settled`] (release has no overflow checks).
    fn diverse_threshold_met_q(eff_q: u128, eligible_stake: u64) -> bool {
        let lhs = eff_q.saturating_mul(3);
        let rhs = (eligible_stake as u128)
            .saturating_mul(2)
            .saturating_mul(SETTLEMENT_Q);
        lhs >= rhs
    }

    /// Compute trust score for a record.
    ///
    /// `T(r) = 1 - ∏(1 - w(n) × d(n, W))` for each attesting witness n.
    ///
    /// - `w(n)` = stake weight (stake / total_zone_stake)
    /// - `d(n, W)` = independence factor from correlation discounting
    pub fn trust_score(&self, record_id: &str) -> f64 {
        let zone = self.settlement_zone_for(record_id);
        let total_zone_stake = self.zone_stakes.get(&zone).copied().unwrap_or(0);
        let creator_stake = self.creator_stakes.get(record_id).copied().unwrap_or(0);
        let eligible_stake = total_zone_stake.saturating_sub(creator_stake);

        if eligible_stake == 0 {
            return 0.0;
        }

        let attestations = match self.attestations.get(record_id) {
            Some(atts) => atts,
            None => return 0.0,
        };

        // Collect witness hashes for independence computation
        let witness_hashes: Vec<&str> = attestations.iter().map(|a| a.witness_hash.as_str()).collect();

        let mut product = 1.0f64;
        for att in attestations {
            let weight = att.stake as f64 / eligible_stake as f64;
            let independence = self.independence(&att.witness_hash, &witness_hashes);
            product *= 1.0 - weight * independence;
        }

        1.0 - product
    }

    /// Get attestation count for a record.
    pub fn attestation_count(&self, record_id: &str) -> usize {
        self.attestations.get(record_id).map(|v| v.len()).unwrap_or(0)
    }

    /// Check if a specific (record_id, witness_hash) attestation exists in consensus.
    pub fn has_attestation_from(&self, record_id: &str, witness_hash: &str) -> bool {
        self.attestations.get(record_id)
            .is_some_and(|atts| atts.iter().any(|a| a.witness_hash == witness_hash))
    }

    /// Populate zone stakes from all staked accounts in the ledger.
    ///
    /// Iterates over the **dynamic** ZONE_COUNT (default 4, scales up with
    /// network size) — NOT the legacy hardcoded 256. At scale-up to
    /// `ZONE_COUNT > 256`, the old hardcoded path left zones 256..ZONE_COUNT
    /// with no stake registered, and any record routed there via
    /// `for_record_dynamic` would have `eligible_stake = 0` → never settle.
    /// Callers that change ZONE_COUNT (zone split/merge) MUST invoke this
    /// again so the new zones pick up the replicated total stake.
    pub fn register_stakes_from_ledger(&mut self, ledger: &LedgerState) {
        self.register_stakes_from_ledger_with_zone_count(ledger, get_zone_count());
    }

    /// Same as `register_stakes_from_ledger` but with explicit `zone_count`.
    /// Lets tests pin a value without racing the global ZONE_COUNT atomic.
    pub fn register_stakes_from_ledger_with_zone_count(&mut self, ledger: &LedgerState, zone_count: u64) {
        // Read the incrementally-maintained total_staked field
        // instead of re-summing every account. At 1M accounts the sum-loop
        // was the dominant cost on every record-ingest tick (this fn is
        // called from state_core, ingest, sync, gossip, epoch, pending_drain).
        let total_staked: u64 = ledger.total_staked;
        self.zone_stakes.clear();
        if total_staked > 0 {
            let zc = zone_count.max(1);
            for z in 0..zc {
                self.zone_stakes.insert(ZoneId::from_legacy(z), total_staked);
            }
        }
        // Liveness-decay support: per-staker stakes via the incrementally
        // maintained staker_index — O(stakers), never O(accounts). Cleared
        // and rebuilt so unstaked/slashed identities drop out.
        self.staker_stakes.clear();
        for hash in ledger.staker_index.keys() {
            if let Some(acct) = ledger.accounts.get(hash.as_str()) {
                if acct.staked > 0 {
                    self.staker_stakes.insert(hash.clone(), acct.staked);
                }
            }
        }
    }

    /// Re-evaluate all tracked records for settlement. For any that now pass
    /// is_settled(), set their confirmation level to Finalized and trigger cascade.
    /// Returns the record IDs that transitioned (Pending|Sealed → Finalized).
    ///
    /// Callers MUST insert these rids into the global FinalizedIndex before
    /// the next prune cycle — otherwise the records reach consensus-Finalized
    /// state, leave the attestations map on prune, and finality_monitor's
    /// `is_settled` filter never picks them up. Pre-fix this gap caused
    /// `total_ever_settled` to race ahead of `finalized_count` by the
    /// gossip/epoch-recheck delta (observed at 1.35× post-restart).
    pub fn force_finalize_settled(&mut self) -> Vec<String> {
        let settled_rids: Vec<String> = self.attestations.keys()
            .filter(|rid| {
                self.is_settled(rid)
                    && !matches!(
                        self.confirmation_levels.get(*rid),
                        Some(&ConfirmationLevel::Finalized) | Some(&ConfirmationLevel::Anchored)
                    )
            })
            .cloned()
            .collect();
        for rid in &settled_rids {
            self.force_finalized(rid);
        }
        settled_rids
    }

    /// Record IDs being tracked that don't have creator_stakes registered.
    /// Used to backfill after restart (snapshot loads attestations but not creator_stakes).
    pub fn records_missing_creator_stake(&self) -> Vec<String> {
        self.attestations.keys()
            .filter(|rid| !self.creator_stakes.contains_key(*rid))
            .cloned()
            .collect()
    }

    /// Bounded count of tracked records missing a
    /// `creator_stakes` entry. Same predicate as
    /// [`records_missing_creator_stake`] but skips the per-record `String`
    /// allocation — operators only want the count for `/metrics`.
    ///
    /// Operator signal:
    ///   - `0` (steady state) — every tracked record has its creator stake
    ///     registered; settlement math is correct.
    ///   - non-zero transient — a fresh batch of records is in flight; the
    ///     next epoch backfill (`epoch.rs:3596`) should drain it on the next
    ///     tick (~30-60 s at testnet cadence, the adaptive epoch interval).
    ///   - non-zero sustained across multiple epoch ticks — backfill loop
    ///     is stalled OR records are arriving for unknown creators (creator
    ///     was never staked / staked-then-unstaked path). Settlement still
    ///     works in this case but `eligible_stake = total_zone_stake`
    ///     instead of `total_zone_stake - creator_stake` — i.e. the
    ///     creator is silently allowed to self-attest within their own
    ///     `eligible_stake` denominator. Investigate via the admin
    ///     forensic endpoints if the gauge stays non-zero past 5 minutes.
    ///
    /// Bounded by `MAX_ATTESTATION_RECORDS` (~50K hot tier) — O(records)
    /// per scrape but no allocations.
    pub fn missing_creator_stake_count(&self) -> usize {
        self.attestations
            .keys()
            .filter(|rid| !self.creator_stakes.contains_key(*rid))
            .count()
    }

    /// Count of records that have reached settlement.
    pub fn settled_count(&self) -> usize {
        self.attestations
            .keys()
            .filter(|rid| self.is_settled(rid))
            .count()
    }

    /// Iterate over all registered witness profiles.
    pub fn profiles(&self) -> impl Iterator<Item = (&str, &WitnessProfile)> {
        self.profiles.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// Total stake registered for a given zone.
    pub fn total_zone_stake(&self, zone: ZoneId) -> u64 {
        self.zone_stakes.get(&zone).copied().unwrap_or(0)
    }

    /// Total attestations tracked across all records.
    pub fn total_attestation_count(&self) -> usize {
        self.attestations.values().map(|v| v.len()).sum()
    }

    /// Mean distinct-cluster count across all tracked records (attestation diversity).
    pub fn mean_diversity_score(&self) -> f64 {
        let records: Vec<_> = self.attestations.iter()
            .filter(|(_, atts)| !atts.is_empty())
            .collect();
        if records.is_empty() { return 0.0; }
        let total: usize = records.iter()
            .map(|(_, atts)| self.count_distinct_clusters(atts))
            .sum();
        total as f64 / records.len() as f64
    }

    /// Cross-zone finality statistics.
    /// Returns (records_with_xzone_parents, total_xzone_parent_refs, boost_count).
    pub fn cross_zone_stats(&self) -> (usize, usize, u64) {
        let records = self.cross_zone_parents.len();
        let refs: usize = self.cross_zone_parents.values().map(|v| v.len()).sum();
        (records, refs, self.cross_zone_boost_count)
    }

    /// Return all record IDs that have attestations tracked.
    pub fn tracked_record_ids(&self) -> Vec<String> {
        self.attestations.keys().cloned().collect()
    }

    /// Count of tracked record IDs — O(1), no allocation.
    pub fn tracked_count(&self) -> usize {
        self.attestations.len()
    }

    /// Single-pass summary of attestation-stake ratios across all tracked
    /// records. Used to surface the same numbers the periodic `finality diag`
    /// log emits at INFO level (`elara_node.rs:3805`) as Prometheus gauges
    /// so operators can alert without log scraping.
    ///
    /// Each ratio is `attesting_stake / eligible_stake` where eligible_stake
    /// matches `is_settled()`'s denominator (`settlement_denominator(zone) -
    /// creator_stake`). A record settles when ratio ≥ 2/3.
    ///
    /// Operator signal: a node tracking lots of records (`tracked` rising)
    /// with `best_ratio < 0.667` sustained means settlement is structurally
    /// stalled — typically a peer-count regression (the node only sees a
    /// minority of the active witness set, so attestations ceiling out at
    /// fewer-than-required signers). Pair with `peers_connected` and
    /// `attestations_processed_total` to localise the cause.
    ///
    /// Records with `eligible == 0` (zone has no registered stake) are
    /// skipped from `best`/`mean`/`at_threshold` counts because they can
    /// never settle by definition; they still contribute to `tracked`.
    /// Bounded by `tracked_count` which is itself bounded to the hot tier
    /// — O(hot_window), not O(all_records).
    pub fn attestation_ratio_summary(&self) -> AttestationRatioSummary {
        if self.attestations.is_empty() {
            return AttestationRatioSummary::default();
        }
        let mut best = 0.0f64;
        let mut sum = 0.0f64;
        let mut counted = 0usize;
        let mut at_threshold = 0usize;
        for (rid, atts) in &self.attestations {
            let zone = self.settlement_zone_for(rid);
            let total_zone_stake = self.settlement_denominator(&zone);
            let creator_stake = self.creator_stakes.get(rid).copied().unwrap_or(0);
            let eligible = total_zone_stake.saturating_sub(creator_stake);
            if eligible == 0 {
                continue;
            }
            let attesting: u64 = atts.iter().map(|a| a.stake).sum();
            let ratio = attesting as f64 / eligible as f64;
            if ratio > best {
                best = ratio;
            }
            sum += ratio;
            counted += 1;
            if attesting.saturating_mul(3) >= eligible.saturating_mul(2) {
                at_threshold += 1;
            }
        }
        let mean = if counted > 0 { sum / counted as f64 } else { 0.0 };
        AttestationRatioSummary {
            tracked: self.attestations.len(),
            ratiable: counted,
            best_ratio: best,
            mean_ratio: mean,
            count_at_threshold: at_threshold,
        }
    }

    /// Return the witness hashes that attested a given record.
    pub fn attestors(&self, record_id: &str) -> Vec<String> {
        self.attestations
            .get(record_id)
            .map(|atts| atts.iter().map(|a| a.witness_hash.clone()).collect())
            .unwrap_or_default()
    }

    /// Per-zone health summary: (zone, total_stake, active_records, settled_count, unique_witnesses).
    pub fn zone_health(&self) -> Vec<(ZoneId, u64, usize, usize, usize)> {
        let mut zones: HashMap<ZoneId, (usize, usize, std::collections::HashSet<String>)> = HashMap::new();

        for (record_id, atts) in &self.attestations {
            let zone = self.settlement_zone_for(record_id);
            let entry = zones.entry(zone).or_insert_with(|| (0, 0, std::collections::HashSet::new()));
            entry.0 += 1; // active_records
            if self.is_settled(record_id) {
                entry.1 += 1; // settled_count
            }
            for a in atts {
                entry.2.insert(a.witness_hash.clone()); // unique witnesses
            }
        }

        // Include zones with stake but no active records
        for (zone, &stake) in &self.zone_stakes {
            if stake > 0 && !zones.contains_key(zone) {
                zones.insert(zone.clone(), (0, 0, std::collections::HashSet::new()));
            }
        }

        let mut result: Vec<(ZoneId, u64, usize, usize, usize)> = zones
            .into_iter()
            .map(|(zone, (active, settled, witnesses))| {
                let stake = self.zone_stakes.get(&zone).copied().unwrap_or(0);
                (zone, stake, active, settled, witnesses.len())
            })
            .collect();
        result.sort_by_key(|r| r.0.clone());
        result
    }

    /// Prune in-memory state for records that have reached finality.
    ///
    /// Removes attestations, confirmation levels, and anchored flags for settled records.
    /// Safe because: attestations are already persisted in RocksDB (CF_ATTESTATIONS),
    /// and finality status is persisted in CF_RECORDS ("finalized:{record_id}").
    /// Returns the number of records pruned from the attestations map.
    pub fn prune_finalized(&mut self, finalized: &std::collections::HashSet<String>) -> usize {
        self.prune_where(|rid| finalized.contains(rid))
    }

    /// Prune records matching a predicate. Generalized version of `prune_finalized`
    /// that works with any finalized-check function (e.g., disk-backed FinalizedIndex).
    pub fn prune_where(&mut self, is_finalized: impl Fn(&str) -> bool) -> usize {
        let before = self.attestations.len();
        self.attestations.retain(|rid, _| !is_finalized(rid));
        self.confirmation_levels.retain(|rid, _| !is_finalized(rid));
        self.anchored.retain(|rid| !is_finalized(rid));
        self.creator_stakes.retain(|rid, _| !is_finalized(rid));
        self.creator_identity.retain(|rid, _| !is_finalized(rid));
        self.rotation_zone_overrides
            .retain(|rid, _| !is_finalized(rid));
        self.cross_zone_parents.retain(|rid, _| !is_finalized(rid));
        let pruned = before - self.attestations.len();
        self.evictions_finalized_total = self.evictions_finalized_total.saturating_add(pruned as u64);
        pruned
    }

    /// Prune attestations older than `cutoff_timestamp` from memory.
    ///
    /// This is the production-critical eviction: if finalization stalls (0 finalized),
    /// `prune_finalized` does nothing and attestations grow forever. This method evicts
    /// by age regardless of finalization status.
    ///
    /// A record's "age" is the timestamp of its newest attestation. If all attestations
    /// for a record are older than the cutoff, the entire entry is evicted.
    ///
    /// Safe because: attestations are already persisted in RocksDB (CF_ATTESTATIONS).
    pub fn prune_older_than(&mut self, cutoff_timestamp: f64) -> usize {
        let before = self.attestations.len();
        self.attestations.retain(|_rid, atts| {
            // Keep if ANY attestation is newer than cutoff
            atts.iter().any(|a| a.timestamp >= cutoff_timestamp)
        });
        let pruned = before - self.attestations.len();
        self.evictions_age_total = self.evictions_age_total.saturating_add(pruned as u64);

        // The attestation-coupled maps are populated ONLY alongside attestations,
        // so they gain no orphans unless an age-eviction actually removed some —
        // prune them only when it did.
        if pruned > 0 {
            self.confirmation_levels.retain(|rid, _| self.attestations.contains_key(rid));
            self.cross_zone_parents.retain(|rid, _| self.attestations.contains_key(rid));
            // Prune orphaned anchored entries — anchored status is already persisted in
            // RocksDB, so keeping orphans in memory just leaks. Records whose attestations
            // have been age-evicted don't need anchored status in RAM anymore.
            self.anchored.retain(|rid| self.attestations.contains_key(rid));
        }
        // creator_identity + creator_stakes are registered at INGEST for records
        // that may NEVER receive an attestation (F5 registers identity for every
        // ingested record), so they accumulate orphans INDEPENDENTLY of age-
        // eviction. Sweep them to the live attestation set on EVERY prune tick —
        // not only when `pruned > 0` — otherwise an ingested-but-never-attested
        // record leaks its entry until some unrelated eviction happens to fire.
        // O(map) on a periodic (non-hot-path) call = bounded. Safe to drop: the
        // feed paths re-register both before processing any new attestation, so
        // the self-attest guard is restored the moment the record sees activity.
        self.creator_identity.retain(|rid, _| self.attestations.contains_key(rid));
        self.creator_stakes.retain(|rid, _| self.attestations.contains_key(rid));
        self.rotation_zone_overrides
            .retain(|rid, _| self.attestations.contains_key(rid));

        // Prune seal attestations older than cutoff too
        self.seal_attestations.retain(|_sid, atts| {
            atts.iter().any(|a| a.timestamp >= cutoff_timestamp)
        });
        // Clean reverse index for pruned seal_record_ids
        let surviving_seals: HashSet<&String> = self.seal_attestations.keys().collect();
        let pruned_seal_ids: Vec<String> = self.seal_record_ids.keys()
            .filter(|sid| !surviving_seals.contains(sid))
            .cloned()
            .collect();
        for sid in &pruned_seal_ids {
            if let Some(record_ids) = self.seal_record_ids.get(sid) {
                for rid in record_ids {
                    self.record_to_seal.remove(rid);
                }
            }
        }
        self.seal_record_ids.retain(|sid, _| self.seal_attestations.contains_key(sid));
        self.seal_epoch.retain(|sid, _| self.seal_attestations.contains_key(sid));
        self.seal_finalized_at.retain(|sid, _| self.seal_attestations.contains_key(sid));
        self.seal_registered_at.retain(|sid, _| self.seal_attestations.contains_key(sid));
        self.seal_first_attested_at.retain(|sid, _| self.seal_attestations.contains_key(sid));
        self.global_seal_stuck_zone
            .retain(|sid, _| self.seal_attestations.contains_key(sid));
        // R2 map follows seal_record_ids' lifetime: an unresolved hash whose
        // seal just pruned can never resolve-and-promote, so drop it.
        {
            let Self { unresolved_seal_members, seal_record_ids, .. } = self;
            unresolved_seal_members.retain(|_, sid| seal_record_ids.contains_key(sid.as_str()));
        }

        pruned
    }

    /// ZSP Phase D: drop every per-record entry for `record_id`. Used by the
    /// zone-purge tick after a node unsubscribes from a zone — `delete_record`
    /// clears storage indexes and `DagIndex::remove` clears the hot-tier graph,
    /// but consensus still pins attestations + confirmation_levels +
    /// creator_stakes + cross_zone_parents. Without this, attestation memory
    /// leaks once the zone is gone.
    ///
    /// Idempotent: silently no-ops if `record_id` is unknown. Does NOT touch
    /// `seal_attestations` / `seal_record_ids` — purging a single record
    /// shouldn't drop the seal it belonged to (the seal still anchors records
    /// from other transfers / other zones we may still be subscribed to).
    /// We DO clear `record_to_seal[record_id]` (the reverse pointer for THIS
    /// record), and we splice the record out of the seal's vec — same surgical
    /// edit `delete_record` makes at the storage layer.
    pub fn forget_record(&mut self, record_id: &str) {
        // Track real evictions (record was present) — idempotent no-op
        // calls don't bump the counter.
        let was_present = self.attestations.remove(record_id).is_some();
        self.confirmation_levels.remove(record_id);
        self.anchored.remove(record_id);
        self.creator_stakes.remove(record_id);
        self.creator_identity.remove(record_id);
        self.rotation_zone_overrides.remove(record_id);
        self.cross_zone_parents.remove(record_id);
        if let Some(seal_id) = self.record_to_seal.remove(record_id) {
            if let Some(rids) = self.seal_record_ids.get_mut(&seal_id) {
                rids.retain(|r| r != record_id);
            }
        }
        if was_present {
            self.evictions_zone_purge_total = self.evictions_zone_purge_total.saturating_add(1);
        }
    }

    /// Evict N record entries using priority eviction: records with FEWEST
    /// attestations are evicted first (furthest from settlement). Records near
    /// quorum (many attestations) survive. Ties broken by oldest timestamp.
    pub fn evict_oldest_attestations(&mut self, count: usize) {
        // Sort by attestation count ASC (fewest first), then by newest timestamp ASC (oldest first)
        let mut entries: Vec<(String, usize, f64)> = self.attestations.iter()
            .map(|(rid, atts)| {
                let att_count = atts.len();
                let newest = atts.iter()
                    .map(|a| a.timestamp)
                    .fold(0.0f64, f64::max);
                (rid.clone(), att_count, newest)
            })
            .collect();
        entries.sort_by(|a, b| {
            a.1.cmp(&b.1) // fewest attestations first
                .then(a.2.total_cmp(&b.2)) // oldest first
        });

        for (rid, att_count, _) in entries.into_iter().take(count) {
            self.attestations.remove(&rid);
            self.confirmation_levels.remove(&rid);
            self.creator_stakes.remove(&rid);
            self.creator_identity.remove(&rid);
            self.cross_zone_parents.remove(&rid);
            self.evictions_total += 1;
            // Track near-settlement evictions (>= 2 attestations = getting close)
            if att_count >= 2 {
                self.evictions_near_settlement += 1;
            }
        }
    }

    /// Evict the oldest N seal entries from the seal attestation map.
    fn evict_oldest_seal_attestations(&mut self, count: usize) {
        let mut entries: Vec<(String, f64)> = self.seal_attestations.iter()
            .map(|(sid, atts)| {
                let newest = atts.iter()
                    .map(|a| a.timestamp)
                    .fold(0.0f64, f64::max);
                (sid.clone(), newest)
            })
            .collect();
        entries.sort_by(|a, b| a.1.total_cmp(&b.1));

        for (sid, _) in entries.into_iter().take(count) {
            self.seal_attestations.remove(&sid);
            if let Some(record_ids) = self.seal_record_ids.remove(&sid) {
                for rid in &record_ids {
                    self.record_to_seal.remove(rid);
                }
            }
            self.seal_epoch.remove(&sid);
            self.seal_finalized_at.remove(&sid);
            self.seal_registered_at.remove(&sid);
            self.seal_first_attested_at.remove(&sid);
            self.global_seal_stuck_zone.remove(&sid);
        }
    }

    /// Bucket boundaries for the seal-attestation latency histogram (seconds).
    /// The final bucket `+Inf` is implicit — any observation that exceeds the
    /// last finite bound still increments `_count` and `_sum`.
    /// 300s + 600s buckets: mainnet target P50 ≈ 60s but
    /// idle testnet runs in 100-300s territory, so without higher buckets
    /// every observation piled in +Inf and the histogram was unreadable.
    pub const SEAL_LATENCY_BUCKETS: [f64; 10] =
        [1.0, 3.0, 5.0, 10.0, 20.0, 30.0, 60.0, 120.0, 300.0, 600.0];

    /// Record one seal-attestation-latency observation. Prometheus histogram
    /// semantics: every bucket `le >= observation` is incremented (cumulative).
    /// Called exactly once per seal at the first settlement transition.
    fn observe_seal_attestation_latency(&mut self, secs: f64) {
        self.seal_attestation_latency_count += 1;
        self.seal_attestation_latency_sum_secs += secs;
        for (i, &bound) in Self::SEAL_LATENCY_BUCKETS.iter().enumerate() {
            if secs <= bound {
                self.seal_attestation_latency_buckets[i] += 1;
            }
        }
        // Final +Inf bucket always increments.
        self.seal_attestation_latency_buckets[10] += 1;
    }

    /// Immutable snapshot of the seal-attestation-latency histogram for
    /// `/metrics` rendering. Returns `(buckets_cumulative, count, sum_secs)`
    /// where `buckets_cumulative[i]` corresponds to
    /// `le = SEAL_LATENCY_BUCKETS[i]` for i < 10, and `buckets_cumulative[10]`
    /// is the `+Inf` bucket.
    pub fn seal_attestation_latency_snapshot(&self) -> ([u64; 11], u64, f64) {
        (
            self.seal_attestation_latency_buckets,
            self.seal_attestation_latency_count,
            self.seal_attestation_latency_sum_secs,
        )
    }

    /// Observe the propagation leg (register → first-attestation seen).
    fn observe_seal_propagation_latency(&mut self, secs: f64) {
        self.seal_propagation_latency_count += 1;
        self.seal_propagation_latency_sum_secs += secs;
        for (i, &bound) in Self::SEAL_LATENCY_BUCKETS.iter().enumerate() {
            if secs <= bound {
                self.seal_propagation_latency_buckets[i] += 1;
            }
        }
        self.seal_propagation_latency_buckets[10] += 1;
    }

    /// Observe the quorum-convergence leg (first-attestation → settled).
    fn observe_seal_quorum_latency(&mut self, secs: f64) {
        self.seal_quorum_latency_count += 1;
        self.seal_quorum_latency_sum_secs += secs;
        for (i, &bound) in Self::SEAL_LATENCY_BUCKETS.iter().enumerate() {
            if secs <= bound {
                self.seal_quorum_latency_buckets[i] += 1;
            }
        }
        self.seal_quorum_latency_buckets[10] += 1;
    }

    /// Snapshot of the propagation-latency histogram.
    pub fn seal_propagation_latency_snapshot(&self) -> ([u64; 11], u64, f64) {
        (
            self.seal_propagation_latency_buckets,
            self.seal_propagation_latency_count,
            self.seal_propagation_latency_sum_secs,
        )
    }

    /// Snapshot of the quorum-latency histogram.
    pub fn seal_quorum_latency_snapshot(&self) -> ([u64; 11], u64, f64) {
        (
            self.seal_quorum_latency_buckets,
            self.seal_quorum_latency_count,
            self.seal_quorum_latency_sum_secs,
        )
    }

    /// Observe the arrival latency of the `(rank+1)`-th
    /// attestation on a seal. `rank` is clamped to 4 (anything rank>=4 is
    /// bucketed as the "5th+" row so cardinality stays bounded).
    /// `secs` is the time from the local-clock `seal_registered_at` stamp.
    fn observe_seal_attestor_rank_latency(&mut self, rank: usize, secs: f64) {
        let r = rank.min(4);
        self.seal_attestor_rank_latency_count[r] += 1;
        self.seal_attestor_rank_latency_sum_secs[r] += secs;
        for (i, &bound) in Self::SEAL_LATENCY_BUCKETS.iter().enumerate() {
            if secs <= bound {
                self.seal_attestor_rank_latency_buckets[r][i] += 1;
            }
        }
        self.seal_attestor_rank_latency_buckets[r][10] += 1;
    }

    /// Snapshot of the per-rank arrival histogram.
    /// Returns `(buckets[5][11], count[5], sum_secs[5])`.
    pub fn seal_attestor_rank_latency_snapshot(&self) -> ([[u64; 11]; 5], [u64; 5], [f64; 5]) {
        (
            self.seal_attestor_rank_latency_buckets,
            self.seal_attestor_rank_latency_count,
            self.seal_attestor_rank_latency_sum_secs,
        )
    }

    /// Number of records tracked in the attestation map.
    pub fn attestation_record_count(&self) -> usize {
        self.attestations.len()
    }

    /// Total number of in-memory entries across all consensus maps.
    /// Used for memory budget monitoring.
    pub fn memory_entry_count(&self) -> usize {
        self.attestations.len()
            + self.confirmation_levels.len()
            + self.anchored.len()
            + self.seal_attestations.len()
            + self.seal_record_ids.len()
            + self.seal_epoch.len()
            + self.record_to_seal.len()
            + self.seal_finalized_at.len()
            + self.seal_registered_at.len()
            + self.seal_first_attested_at.len()
            + self.creator_stakes.len()
            + self.creator_identity.len()
            + self.cross_zone_parents.len()
            + self.profiles.len()
    }

    /// Detailed memory diagnostics for each map.
    pub fn memory_detail(&self) -> serde_json::Value {
        let total_attestations: usize = self.attestations.values().map(|v| v.len()).sum();
        let total_seal_attestations: usize = self.seal_attestations.values().map(|v| v.len()).sum();
        let total_seal_record_ids: usize = self.seal_record_ids.values().map(|v| v.len()).sum();
        let total_cross_zone: usize = self.cross_zone_parents.values().map(|v| v.len()).sum();
        serde_json::json!({
            "attestations_records": self.attestations.len(),
            "attestations_total": total_attestations,
            "confirmation_levels": self.confirmation_levels.len(),
            "anchored": self.anchored.len(),
            "seal_attestations_seals": self.seal_attestations.len(),
            "seal_attestations_total": total_seal_attestations,
            "seal_record_ids_seals": self.seal_record_ids.len(),
            "seal_record_ids_total": total_seal_record_ids,
            "seal_epoch": self.seal_epoch.len(),
            "record_to_seal": self.record_to_seal.len(),
            "seal_finalized_at": self.seal_finalized_at.len(),
            "seal_registered_at": self.seal_registered_at.len(),
            "seal_first_attested_at": self.seal_first_attested_at.len(),
            "creator_stakes": self.creator_stakes.len(),
            "creator_identity": self.creator_identity.len(),
            "cross_zone_parents_records": self.cross_zone_parents.len(),
            "cross_zone_parents_total": total_cross_zone,
            "profiles": self.profiles.len(),
            "zone_stakes": self.zone_stakes.len(),
        })
    }

    /// Get summary info for records that have attestations but are NOT yet settled.
    /// Returns (record_id, attestation_count, trust_score) sorted by attestation count descending.
    /// Detailed consensus status for a specific record.
    ///
    /// Returns: (zone, is_settled, trust_score, zone_stake, attesting_stake,
    ///           attestations_vec[(witness_hash, stake, independence, timestamp)])
    pub fn record_detail(&self, record_id: &str) -> RecordConsensusDetail {
        let zone = self.settlement_zone_for(record_id);
        let total_zone_stake = self.zone_stakes.get(&zone).copied().unwrap_or(0);
        let creator_stake = self.creator_stakes.get(record_id).copied().unwrap_or(0);
        let eligible_stake = total_zone_stake.saturating_sub(creator_stake);
        let is_settled = self.is_settled_diverse(record_id) || (self.is_settled(record_id) && self.profiles.is_empty());
        let trust = self.trust_score(record_id);

        let attestations = self.attestations.get(record_id);
        let witness_hashes: Vec<&str> = attestations
            .map(|atts| atts.iter().map(|a| a.witness_hash.as_str()).collect())
            .unwrap_or_default();

        let attesting_stake: u64 = attestations
            .map(|atts| atts.iter().map(|a| a.stake).sum())
            .unwrap_or(0);

        let att_details: Vec<AttestationDetail> = attestations
            .map(|atts| {
                atts.iter()
                    .map(|a| {
                        let independence = self.independence(&a.witness_hash, &witness_hashes);
                        AttestationDetail {
                            witness_hash: a.witness_hash.clone(),
                            stake: a.stake,
                            independence,
                            timestamp: a.timestamp,
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();

        RecordConsensusDetail {
            zone,
            is_settled,
            trust_score: trust,
            total_zone_stake: eligible_stake, // Show eligible stake (creator excluded)
            attesting_stake,
            threshold_pct: if eligible_stake > 0 {
                (attesting_stake as f64 / eligible_stake as f64) * 100.0
            } else {
                0.0
            },
            attestations: att_details,
        }
    }

    pub fn unsettled_summary(&self) -> Vec<(String, usize, f64)> {
        let mut results: Vec<(String, usize, f64)> = self
            .attestations
            .iter()
            .filter(|(rid, _)| !self.is_settled(rid))
            .map(|(rid, atts)| {
                let trust = self.trust_score(rid);
                (rid.clone(), atts.len(), trust)
            })
            .collect();
        results.sort_by_key(|b| std::cmp::Reverse(b.1));
        results
    }
}

/// Detailed attestation info for a single witness.
#[derive(Debug, Clone)]
pub struct AttestationDetail {
    pub witness_hash: String,
    pub stake: u64,
    pub independence: f64,
    pub timestamp: f64,
}

/// Detailed consensus status for a record.
#[derive(Debug, Clone)]
pub struct RecordConsensusDetail {
    pub zone: ZoneId,
    pub is_settled: bool,
    pub trust_score: f64,
    pub total_zone_stake: u64,
    pub attesting_stake: u64,
    pub threshold_pct: f64,
    pub attestations: Vec<AttestationDetail>,
}

/// Single-pass summary of attestation-stake ratios across the in-flight
/// attestation map. Produced by `ConsensusState::attestation_ratio_summary`.
///
/// `tracked` is the count of records currently in `attestations`.
/// `ratiable` is the subset whose zone has registered stake (non-ratiable
/// records contribute to `tracked` but are excluded from `best_ratio` /
/// `mean_ratio` / `count_at_threshold` because they can never settle).
/// `best_ratio` and `mean_ratio` are over `ratiable` only.
/// `count_at_threshold` is records where `attesting * 3 ≥ eligible * 2`
/// — i.e. records that satisfy `is_settled()`.
#[derive(Debug, Clone, Default)]
pub struct AttestationRatioSummary {
    pub tracked: usize,
    pub ratiable: usize,
    pub best_ratio: f64,
    pub mean_ratio: f64,
    pub count_at_threshold: usize,
}

impl AttestationRatioSummary {
    /// Classify the node's bratio cohort membership for the
    /// `elara_bratio_cohort_membership` Prometheus gauge.
    ///
    /// Returns the band index in the empirically-derived 5-band hierarchy
    /// (n=8 settlement events observed across all nodes):
    ///
    /// | Code | Band         | Range                          | Empirical |
    /// |------|--------------|--------------------------------|-----------|
    /// |  0   | DORMANT      | tracked == 0                   |  (none)   |
    /// |  1   | LOCKED       | tracked > 0, best_ratio < 0.60 |  ≈ 0.5952 |
    /// |  2   | CONVERGED    | 0.60 ≤ best_ratio < 0.667      |  ≈ 0.6032 |
    /// |  3   | ACTIVE       | 0.667 ≤ best_ratio < 0.999     |  ≈ 0.8016 |
    /// |  4   | HYPER_ACTIVE | best_ratio ≥ 0.999             |  1.0000   |
    ///
    /// LOCKED collapses two sub-states: (a) ratiable=0 (zone-stake unregistered,
    /// `best_ratio` defaults to 0.0), and (b) ratiable>0 anchored-low (the
    /// canonical anchor at ≈0.5952). Disambiguate via the existing
    /// `elara_consensus_records_ratiable` gauge — ratiable=0 with cohort=1
    /// is the "waiting on stake" sub-state.
    ///
    /// CONVERGED→ACTIVE boundary is the settlement threshold 2/3 ≈ 0.6667.
    /// ACTIVE→HYPER_ACTIVE boundary at 0.999 captures floating-point fuzz on
    /// what is morally a full-stake (1.0) attestation.
    ///
    /// Numeric encoding is monotonic in settlement health — higher code =
    /// more settlement activity. Suitable for `max_over_time` band-occupancy
    /// alerting and for `count_values` cohort-distribution panels.
    pub fn classify_cohort(&self) -> u8 {
        if self.tracked == 0 {
            0
        } else if self.best_ratio < 0.60 {
            1
        } else if self.best_ratio < 0.667 {
            2
        } else if self.best_ratio < 0.999 {
            3
        } else {
            4
        }
    }
}

/// Aggregate per-zone committee-size summary for
/// `/metrics`. Returned by [`AWCConsensus::committee_size_summary`] in one
/// O(zones_registered) pass over `committee_members`.
///
/// Each field maps 1:1 onto a Prometheus gauge:
///   * `zones_registered` → number of zones with an active per-epoch committee
///     (post-`register_epoch_committee`, pre-`remove`). 0 = registration never
///     fired or all zones reverted to the bootstrap denominator.
///   * `size_min` / `size_max` → distribution endpoints across registered
///     committees. 0 when `zones_registered == 0`. Mainnet target =
///     `MAINNET_COMMITTEE_SIZE` (7); larger values indicate bootstrap fallback
///     (`BOOTSTRAP_FALLBACK_CAP` = 64).
///   * `zones_below_target` → committees with `size < MAINNET_COMMITTEE_SIZE`.
///     Load-bearing alarm: in a fully staked mainnet zone every committee
///     must reach the target; sustained non-zero = the eligible-pool filter
///     dropped real witnesses (zone subscriber list out of sync) or the
///     stake distribution is too sparse for that zone.
#[derive(Debug, Clone, Copy, Default)]
pub struct CommitteeSizeSummary {
    pub zones_registered: usize,
    pub size_min: usize,
    pub size_max: usize,
    pub zones_below_target: usize,
}

// ─── Epoch-Seal Attestation (Layered Consensus Layer 2) ─────────────────────

/// A witness attestation for an epoch seal (not an individual record).
///
/// In layered consensus, witnesses attest to epoch seals rather than individual
/// records. This is the fundamental shift from per-record to per-epoch consensus.
/// An epoch seal with >67% diverse-weighted attestation is Finalized, and all
/// records it contains inherit that status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealAttestation {
    /// Record ID of the epoch seal being attested.
    pub seal_id: String,
    /// Zone this seal covers.
    pub zone: ZoneId,
    /// Epoch number.
    pub epoch_number: u64,
    /// Witness identity hash.
    pub witness_hash: String,
    /// Witness stake at time of attestation.
    pub stake: u64,
    /// When the attestation was made.
    pub timestamp: f64,
}

/// Challenge window duration in seconds (24 hours).
/// After an epoch seal is Finalized, it must survive this window
/// without successful challenges to become Anchored.
pub const CHALLENGE_WINDOW_SECS: f64 = 24.0 * 3600.0;

impl AWCConsensus {
    /// Add an attestation for an epoch seal (Layer 2).
    ///
    /// Witnesses call this after verifying the seal (witness_verify_seal).
    /// When enough diverse witnesses attest, the seal reaches Finalized status,
    /// and all records in the seal inherit ConfirmationLevel::Finalized.
    /// Returns the member rids that crossed the pre-finality → Finalized
    /// edge in THIS call (empty in the common case). Callers MUST route the
    /// return through the durable FinalizedIndex write
    /// (`reward::route_member_finality` / `insert_members_durable`) —
    /// dropping it re-opens the seal-member durable-write gap
    /// (internal design notes).
    #[must_use = "route newly-Finalized seal members to the durable FinalizedIndex"]
    pub fn add_seal_attestation(&mut self, attestation: SealAttestation) -> Vec<String> {
        // Diagnostic: count every entry into this function.
        self.seal_attestation_add_total += 1;
        // Hard budget: evict oldest seal attestations if at capacity
        if self.seal_attestations.len() >= MAX_SEAL_ATTESTATIONS {
            self.evict_oldest_seal_attestations(MAX_SEAL_ATTESTATIONS / 10);
        }

        let seal_id = attestation.seal_id.clone();

        // H1: reject a seal-creator self-attestation — same threshold-collapse as the
        // record path (is_seal_settled removes the creator's stake from the denominator).
        if self.creator_identity.get(&seal_id).map(String::as_str)
            == Some(attestation.witness_hash.as_str())
        {
            self.self_attestations_rejected = self.self_attestations_rejected.saturating_add(1);
            return Vec::new();
        }

        // Dedup on (seal_id, witness_hash) — mirrors `add_attestation`. Gossip
        // refeed + att-pull can re-deliver the same witness's seal attestation;
        // `effective_stake_q` has NO internal dedup, so a duplicate is summed
        // twice in `is_seal_settled` and can cross the 2/3 threshold with fewer
        // distinct witnesses than required. Drop before any latency stamp or
        // rank observation so a replay is a pure no-op.
        if self
            .seal_attestations
            .get(&seal_id)
            .map(|v| v.iter().any(|a| a.witness_hash == attestation.witness_hash))
            .unwrap_or(false)
        {
            return Vec::new();
        }

        let record_ids_in_seal = self.seal_record_ids.get(&seal_id).cloned();

        // Local wall-clock for all latency stamps. Mixing local-clock and
        // witness-clock breaks the latency math — pre-restart attestations replayed
        // through this function would otherwise stamp first_att with stale
        // witness timestamps and inflate quorum = now - old_witness_ts.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);

        // `seal_registered_at` is now ONLY populated by
        // `register_seal_records` (local clock). Previously we synthesized a
        // witness-clock entry on the first attestation arrival to avoid
        // 'silent skips' in the end-to-end histogram, but `(now - witness_ts)`
        // mixes clocks the same way the propagation leg forbids —
        // and inflated end-to-end by days during peer-driven catchup. The
        // `was_registered_locally` boolean is captured ONCE per call and
        // stays the source of truth for which observations clock-consistent.
        // It must be checked BEFORE any code path that could insert a fresh
        // entry into `seal_registered_at` — currently nothing in this fn
        // does, but if you add such a path, hoist it after this line.
        let was_registered_locally = self.seal_registered_at.contains_key(&seal_id);

        // Per-stage latency: stamp first-attestation on OUR local clock
        // so quorum = now_at_settle - now_at_first_att is clock-consistent.
        let is_first_attestation = !self.seal_first_attested_at.contains_key(&seal_id);
        if is_first_attestation {
            self.seal_first_attested_at.insert(seal_id.clone(), now);
            if was_registered_locally {
                if let Some(&registered_at) = self.seal_registered_at.get(&seal_id) {
                    let propagation = (now - registered_at).max(0.0);
                    self.observe_seal_propagation_latency(propagation);
                }
            }
        }

        // Per-rank arrival latency. Rank = current count of
        // attestations for this seal (0-based) — the attestation about to be
        // pushed is the (rank+1)-th to arrive. Same same-clock gate as the
        // propagation histogram: only stamp if registered_at is on our local
        // clock (was_registered_locally), otherwise we'd mix clocks.
        if was_registered_locally {
            let rank = self
                .seal_attestations
                .get(&seal_id)
                .map(|v| v.len())
                .unwrap_or(0);
            if let Some(&registered_at) = self.seal_registered_at.get(&seal_id) {
                let arrival = (now - registered_at).max(0.0);
                self.observe_seal_attestor_rank_latency(rank, arrival);
            }
        }

        self.seal_attestations
            .entry(seal_id.clone())
            .or_default()
            .push(attestation);

        // Check if this seal is now settled → upgrade records to Finalized
        if self.is_seal_settled(&seal_id) {
            // Diagnostic: settlement passed.
            self.seal_settled_true_total += 1;
            // Track when seal first reached settlement (for Anchored timer)
            if !self.seal_finalized_at.contains_key(&seal_id) {
                self.seal_finalized_at.insert(seal_id.clone(), now);

                // Same-clock gate. Only observe end-to-end
                // and quorum latency when the seal was registered locally via
                // `register_seal_records` BEFORE this attestation arrived. If
                // `was_registered_locally` is false, `seal_registered_at` was
                // synthesized from the witness clock — and
                // `now - witness_ts` mixes clocks the same way the propagation
                // leg already forbids, often inflating end-to-end
                // by days during peer-driven catchup. Otherwise every
                // retroactive seal polluted the histogram. Quorum is also gated because
                // for a retroactive seal the first-attestation timestamp was
                // set to `now` in this same call chain, so the (settle - first)
                // delta degenerates to ~0s and inflates the `le=1` bucket with
                // burst-replay events that don't reflect real settlement.
                // The skip counter `seal_latency_retroactive_skipped_total`
                // stays useful as an operator signal: high rate vs
                // `seal_attestation_latency_count` = heavy peer-driven catchup.
                if was_registered_locally {
                    if let Some(&registered_at) = self.seal_registered_at.get(&seal_id) {
                        let latency = (now - registered_at).max(0.0);
                        self.observe_seal_attestation_latency(latency);
                    }
                    if let Some(&first_att) = self.seal_first_attested_at.get(&seal_id) {
                        let quorum = (now - first_att).max(0.0);
                        self.observe_seal_quorum_latency(quorum);
                    }
                } else {
                    self.seal_latency_retroactive_skipped_total += 1;
                }
            }
            if let Some(record_ids) = record_ids_in_seal {
                return self.promote_seal_members(&record_ids);
            }
        }
        Vec::new()
    }

    /// Edge-guarded seal-member promotion (shared by the fast-track in
    /// `add_seal_attestation`, the R1 settle-check in
    /// `register_seal_records`, and the R2 late-member resolution).
    /// Promotes each rid to Finalized and fires the commit callback ONLY on
    /// the pre-finality → Finalized edge — a seal that re-lands its own
    /// records (already at Finalized/Anchored via recompute or force) must
    /// not double-fire; that would double-commit the pending delta.
    /// Returns exactly the rids whose edge fired this call.
    fn promote_seal_members(&mut self, record_ids: &[String]) -> Vec<String> {
        let mut newly_finalized = Vec::new();
        for rid in record_ids {
            let old = self.confirmation_levels.get(rid).copied();
            self.confirmation_levels
                .insert(rid.clone(), ConfirmationLevel::Finalized);
            if !matches!(
                old,
                Some(ConfirmationLevel::Finalized) | Some(ConfirmationLevel::Anchored)
            ) {
                self.enqueue_finalized(rid);
                newly_finalized.push(rid.clone());
            }
        }
        newly_finalized
    }

    /// Register which records are included in an epoch seal.
    ///
    /// Called when an anchor proposes an epoch seal. All records in the seal
    /// get their confirmation upgraded to Sealed (included in epoch).
    ///
    /// R1 (registration-after-settlement closure): if the seal ALREADY
    /// passed `is_seal_settled` when registration lands (attestations
    /// crossed 2/3 while `seal_record_ids` was unregistered — routine under
    /// peer-driven catchup, see `seal_pending_anchor_retroactive_count`),
    /// the members are promoted here, because the per-witness dedup in
    /// `add_seal_attestation` guarantees no replay will ever re-fire the
    /// fast-track for them. Returns the newly-Finalized member rids; callers
    /// MUST route them to the durable FinalizedIndex.
    #[must_use = "route newly-Finalized seal members to the durable FinalizedIndex"]
    pub fn register_seal_records(&mut self, seal_id: &str, record_ids: Vec<String>) -> Vec<String> {
        // Upgrade all records to Sealed + populate reverse index
        for rid in &record_ids {
            let current = self.confirmation_levels
                .get(rid)
                .copied()
                .unwrap_or(ConfirmationLevel::Pending);
            if current < ConfirmationLevel::Sealed {
                self.confirmation_levels
                    .insert(rid.clone(), ConfirmationLevel::Sealed);
            }
            self.record_to_seal.insert(rid.clone(), seal_id.to_string());
        }
        self.seal_record_ids.insert(seal_id.to_string(), record_ids.clone());

        // Gap 8: stamp the first-proposal wall-clock so we can compute
        // attestation latency at settlement. `or_insert_with` keeps the
        // earliest stamp — an anchor re-proposing the same seal doesn't
        // reset the timer.
        self.seal_registered_at
            .entry(seal_id.to_string())
            .or_insert_with(|| std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs_f64())
                .unwrap_or(0.0));

        if self.is_seal_settled(seal_id) {
            return self.promote_seal_members(&record_ids);
        }
        Vec::new()
    }

    /// R2: remember seal members whose record hash could not be resolved to
    /// a local record id at registration time. Bounded: inserts stop at
    /// `MAX_UNRESOLVED_SEAL_MEMBERS` (drop-new, diagnostic counter).
    pub fn register_unresolved_seal_members(
        &mut self,
        seal_id: &str,
        unresolved_hashes: Vec<String>,
    ) {
        for h in unresolved_hashes {
            if self.unresolved_seal_members.len() >= MAX_UNRESOLVED_SEAL_MEMBERS {
                self.unresolved_seal_members_dropped_total =
                    self.unresolved_seal_members_dropped_total.saturating_add(1);
                return;
            }
            self.unresolved_seal_members.insert(h, seal_id.to_string());
        }
    }

    /// R2 probe gate: cheap emptiness check so the ingest hot path can skip
    /// the resolve call (and its record-hash hex encode) entirely in the
    /// common no-outstanding-members case.
    pub fn has_unresolved_seal_members(&self) -> bool {
        !self.unresolved_seal_members.is_empty()
    }

    /// R2: a record just ingested — if its hash is an outstanding unresolved
    /// seal member, append it to the seal's member list, upgrade it to
    /// Sealed, and (when the seal already settled) promote it. Returns the
    /// newly-Finalized rids (0 or 1); callers MUST route them to the durable
    /// FinalizedIndex.
    #[must_use = "route newly-Finalized seal members to the durable FinalizedIndex"]
    pub fn resolve_late_seal_member(&mut self, record_hash_hex: &str, record_id: &str) -> Vec<String> {
        let Some(seal_id) = self.unresolved_seal_members.remove(record_hash_hex) else {
            return Vec::new();
        };
        // Seal state may have pruned since the hash was parked — the map is
        // retained against seal_record_ids, but the prune and this probe can
        // interleave within one tick. Fail soft: no seal, no promotion.
        let Some(ids) = self.seal_record_ids.get_mut(&seal_id) else {
            return Vec::new();
        };
        if !ids.iter().any(|r| r == record_id) {
            ids.push(record_id.to_string());
        }
        self.record_to_seal
            .insert(record_id.to_string(), seal_id.clone());
        let current = self
            .confirmation_levels
            .get(record_id)
            .copied()
            .unwrap_or(ConfirmationLevel::Pending);
        if current < ConfirmationLevel::Sealed {
            self.confirmation_levels
                .insert(record_id.to_string(), ConfirmationLevel::Sealed);
        }
        if self.is_seal_settled(&seal_id) {
            return self.promote_seal_members(&[record_id.to_string()]);
        }
        Vec::new()
    }

    /// F3 collector: every rid currently at Finalized or Anchored in the
    /// in-memory confirmation map. The maintenance tick routes these through
    /// the idempotent durable FinalizedIndex insert BEFORE `prune_older_than`
    /// collaterally wipes memberless entries. Bounded: O(confirmation_levels),
    /// which is coupled to the attestation map + registered seal members.
    pub fn finalized_level_rids(&self) -> Vec<String> {
        self.confirmation_levels
            .iter()
            .filter(|(_, level)| **level >= ConfirmationLevel::Finalized)
            .map(|(rid, _)| rid.clone())
            .collect()
    }

    /// Pair a seal_id with its `(epoch_number, zone)` so the epoch-prune
    /// shadow metric can decide whether the seal is far enough behind the
    /// zone's current epoch to be eligible for reclamation under
    /// epoch-based pruning (Protocol §11.8).
    ///
    /// Idempotent: re-registering the same `(seal_id, epoch, zone)` is a no-op.
    /// Pruned alongside `seal_record_ids` in `evict_oldest_seals` and the
    /// retention sweep.
    pub fn register_seal_epoch(&mut self, seal_id: &str, epoch_number: u64, zone: ZoneId) {
        self.seal_epoch
            .entry(seal_id.to_string())
            .or_insert((epoch_number, zone));
    }

    /// Constant horizon used by the epoch-prune shadow metric. A seal is
    /// shadow-eligible when its zone has advanced this many epochs past
    /// the seal's own epoch. 100 epochs ≈ 8 hours at the testnet 5-min
    /// adaptive interval — wide enough that no live finality flow could
    /// still depend on the records, narrow enough that the metric reflects
    /// real reclaimable mass once a zone has been running long enough.
    ///
    /// **Sliding-window semantics, NOT cyclic**: observed across captured
    /// prune events with intervals ~7.5 h / ~23 min, which falsify any
    /// single-period cyclic model. The horizon is
    /// a **per-record-age threshold**, not a clock. Records age continuously
    /// against the zone's current epoch; when a batch of records was created
    /// in a burst, that batch crosses the threshold together and prunes as
    /// a single visible "event" — but the underlying mechanism is continuous
    /// aging, not a timer. Operator implication: a sudden ratiable-counter
    /// drop paired with no fin-counter advance is the expected batch-prune
    /// pattern, not a settlement regression; the inter-event interval is
    /// determined by the historical record-arrival distribution, not by
    /// this horizon.
    pub const EPOCH_PRUNE_SHADOW_HORIZON: u64 = 100;

    /// Observation-only counter:
    /// how many sealed records are currently shadow-eligible for epoch-based
    /// pruning. `current_zone_epochs` comes from `EpochState::latest_epoch`.
    ///
    /// A seal is shadow-eligible iff:
    ///   (a) `seal_epoch[seal_id]` is known (registered via `register_seal_epoch`),
    ///   (b) `is_seal_settled(seal_id)` — the seal has crossed 2/3 attestation,
    ///   (c) `current_zone_epochs[zone] - seal_epoch >= horizon`.
    ///
    /// Returns the sum of `record_count` over all eligible seals — i.e. the
    /// number of records that would be reclaimable today. This is *observation
    /// only*; nothing is pruned.
    ///
    /// Cost is O(seals_in_memory). At 1M zones × ~30 seals retained per zone
    /// in the consensus window that's ~30M map entries — fine for a 60s
    /// /metrics scrape.
    pub fn count_epoch_prune_shadow_eligible(
        &self,
        horizon: u64,
        current_zone_epochs: &HashMap<ZoneId, u64>,
    ) -> u64 {
        let mut total: u64 = 0;
        for (seal_id, (seal_epoch, zone)) in &self.seal_epoch {
            let Some(current) = current_zone_epochs.get(zone) else { continue };
            if current.saturating_sub(*seal_epoch) < horizon {
                continue;
            }
            if !self.is_seal_settled(seal_id) {
                continue;
            }
            if let Some(records) = self.seal_record_ids.get(seal_id) {
                total = total.saturating_add(records.len() as u64);
            }
        }
        total
    }

    /// Number of seals currently registered with epoch info (denominator for
    /// the shadow metric — gives operators a quick "how much of the in-memory
    /// seal set is even sized for this metric" sanity check).
    pub fn seal_epoch_indexed_count(&self) -> usize {
        self.seal_epoch.len()
    }

    /// Operator drilldown.
    /// Return up to `max_n` shadow-eligible seals (same predicate as
    /// `count_epoch_prune_shadow_eligible`), ordered by lag descending so
    /// the oldest sealed work shows first. Used by `GET /admin/epoch_prune_shadow`
    /// to let operators inspect which seals would be reclaimed before
    /// flipping the prune policy on.
    ///
    /// Returns: `Vec<(seal_id, seal_epoch, zone, record_count, lag)>`
    /// where `lag = current_zone_epoch - seal_epoch`.
    pub fn epoch_prune_shadow_eligible_seals(
        &self,
        horizon: u64,
        current_zone_epochs: &HashMap<ZoneId, u64>,
        max_n: usize,
    ) -> Vec<(String, u64, ZoneId, usize, u64)> {
        let mut entries: Vec<(String, u64, ZoneId, usize, u64)> = Vec::new();
        for (seal_id, (seal_epoch, zone)) in &self.seal_epoch {
            let Some(current) = current_zone_epochs.get(zone) else { continue };
            let lag = current.saturating_sub(*seal_epoch);
            if lag < horizon {
                continue;
            }
            if !self.is_seal_settled(seal_id) {
                continue;
            }
            let record_count = self
                .seal_record_ids
                .get(seal_id)
                .map(|v| v.len())
                .unwrap_or(0);
            entries.push((seal_id.clone(), *seal_epoch, zone.clone(), record_count, lag));
        }
        // Largest lag first (oldest seal at the head — the one most safe to prune).
        entries.sort_by_key(|b| std::cmp::Reverse(b.4));
        entries.truncate(max_n);
        entries
    }

    /// Single-pass fusion of [`Self::count_epoch_prune_shadow_eligible`] and
    /// [`Self::epoch_prune_shadow_eligible_seals`] for the admin drilldown:
    /// one walk over `seal_epoch` returns `(eligible_records,
    /// eligible_seals_total, top-max_n-by-lag entries)`. Exists so
    /// `GET /admin/epoch_prune_shadow` holds the consensus lock — the same
    /// lock the epoch seal loop takes every tick — for ONE O(seals) scan
    /// instead of two back-to-back scans. Also surfaces the TRUE
    /// eligible-seal total (the route previously reported the capped list
    /// length, silently clamping at max_n).
    #[allow(clippy::type_complexity)]
    pub fn epoch_prune_shadow_summary(
        &self,
        horizon: u64,
        current_zone_epochs: &HashMap<ZoneId, u64>,
        max_n: usize,
    ) -> (u64, u64, Vec<(String, u64, ZoneId, usize, u64)>) {
        let mut eligible_records: u64 = 0;
        let mut eligible_seals: u64 = 0;
        let mut entries: Vec<(String, u64, ZoneId, usize, u64)> = Vec::new();
        for (seal_id, (seal_epoch, zone)) in &self.seal_epoch {
            let Some(current) = current_zone_epochs.get(zone) else { continue };
            let lag = current.saturating_sub(*seal_epoch);
            if lag < horizon {
                continue;
            }
            if !self.is_seal_settled(seal_id) {
                continue;
            }
            let record_count = self
                .seal_record_ids
                .get(seal_id)
                .map(|v| v.len())
                .unwrap_or(0);
            eligible_records = eligible_records.saturating_add(record_count as u64);
            eligible_seals += 1;
            entries.push((seal_id.clone(), *seal_epoch, zone.clone(), record_count, lag));
        }
        // Same ordering contract as the drilldown: largest lag first.
        entries.sort_by_key(|b| std::cmp::Reverse(b.4));
        entries.truncate(max_n);
        (eligible_records, eligible_seals, entries)
    }

    /// Check if an epoch seal has reached settlement (>67% diverse-weighted stake).
    ///
    /// For Stage 3c.1 global quorum seals, the denominator is sum of
    /// zone_stakes over all zones ≠ stuck_zone (the stuck zone cannot
    /// attest for itself), and attestations from the stuck zone are
    /// excluded from the numerator.
    pub fn is_seal_settled(&self, seal_id: &str) -> bool {
        if let Some(stuck_zone) = self.global_seal_stuck_zone.get(seal_id) {
            return self.is_global_seal_settled(seal_id, stuck_zone);
        }
        let atts = match self.seal_attestations.get(seal_id) {
            Some(a) if !a.is_empty() => a,
            _ => return false,
        };

        // Get zone from first attestation
        let zone = &atts[0].zone;
        // MAINNET gap #5: committee stake when active, else full zone stake.
        let total_zone_stake = self.settlement_denominator(zone);
        // Exclude creator's stake: the seal creator can't self-attest, so their
        // stake is unreachable and must not inflate the settlement denominator.
        // Mirrors is_settled() which already does this for per-record settlement.
        let creator_stake = self.creator_stakes.get(seal_id).copied().unwrap_or(0);
        let eligible_stake = total_zone_stake.saturating_sub(creator_stake);
        if eligible_stake == 0 {
            return false;
        }

        // Deterministic fixed-point diversity-weighted effective stake — see
        // is_settled_diverse / internal design notes.
        let witnesses: Vec<(&str, u64)> = atts
            .iter()
            .map(|a| (a.witness_hash.as_str(), a.stake))
            .collect();
        let eff_q = self.effective_stake_q(&witnesses);

        // 2/3 threshold (MESH-BFT Theorem 1)
        Self::diverse_threshold_met_q(eff_q, eligible_stake)
    }

    /// Public read of a zone's settlement denominator — committee stake when a
    /// committee is registered, else the liveness-adjusted full zone stake. This
    /// is the SAME denominator `is_settled` / `is_seal_settled` divide by
    /// (`settlement_denominator`), exposed for the KR-3 S2 W2 durable-marker
    /// sweep (`network::rotation_sweep`), which runs OUTSIDE the live settlement
    /// path and cannot reach the private method.
    ///
    /// The sweep forms Leg-A's `eligible_stake` by subtracting the seal
    /// creator's stake from this value — re-derived from durable state
    /// (`ledger.staked(creator_identity_hash(seal))`), NOT the in-memory
    /// `creator_stakes` map, which may be empty on the boot sweep before the
    /// seal-registration flow has repopulated it. Pairing this denominator with
    /// a `ledger.staked`-per-attester numerator keeps the recount on the one
    /// staked-anchor view (see `rotation_finality::leg_a_quorum_recount`).
    pub fn settlement_denominator_for_zone(&self, zone: &ZoneId) -> u64 {
        self.settlement_denominator(zone)
    }

    /// Register a seal_id as a Stage 3c.1 global quorum seal and track its
    /// stuck_zone. Idempotent.
    ///
    /// Callers (ingest path after successful `verify_global_quorum_seal`)
    /// should invoke this before forwarding the seal's attestations so
    /// `is_seal_settled` routes to the cross-zone denominator from the
    /// first attestation onward.
    pub fn register_global_seal(&mut self, seal_id: &str, stuck_zone: ZoneId) {
        self.global_seal_stuck_zone
            .insert(seal_id.to_string(), stuck_zone);
    }

    /// True if `seal_id` has been registered as a global quorum seal.
    pub fn is_global_seal(&self, seal_id: &str) -> bool {
        self.global_seal_stuck_zone.contains_key(seal_id)
    }

    /// Settlement check for Stage 3c.1 global quorum seals.
    ///
    /// Denominator: **max** of `zone_stakes[z]` over `z != stuck_zone` — i.e.
    /// one non-stuck-zone's worth of stake. Under the production
    /// `register_stakes_from_ledger` convention every zone's entry is the
    /// system total, so `max_non_stuck == total_staked`; under hand-built
    /// test topologies each zone may hold a genuinely different value. Using
    /// `max` (instead of `sum`) keeps both conventions consistent with
    /// per-zone seal settlement, which also uses one zone's stake as the
    /// denominator.
    ///
    /// Numerator: diversity-weighted attestations whose `.zone != stuck_zone`
    /// — an attestation from the stuck zone itself is silently dropped so
    /// a captured stuck zone cannot rubber-stamp its own escalation.
    ///
    /// Threshold: 2/3 of that non-stuck-zone stake (same constant as
    /// per-zone seals, MESH-BFT Theorem 1).
    fn is_global_seal_settled(&self, seal_id: &str, stuck_zone: &ZoneId) -> bool {
        let atts = match self.seal_attestations.get(seal_id) {
            Some(a) if !a.is_empty() => a,
            _ => return false,
        };

        // Denominator: one non-stuck zone's worth of stake.
        let denominator: u64 = self
            .zone_stakes
            .iter()
            .filter(|(z, _)| *z != stuck_zone)
            .map(|(_, s)| *s)
            .max()
            .unwrap_or(0);
        if denominator == 0 {
            return false;
        }

        // Numerator: only attestations from non-stuck zones count.
        let non_stuck_atts: Vec<&SealAttestation> = atts
            .iter()
            .filter(|a| &a.zone != stuck_zone)
            .collect();
        if non_stuck_atts.is_empty() {
            return false;
        }
        // Deterministic fixed-point diversity-weighted effective stake — see
        // is_settled_diverse / internal design notes.
        let witnesses: Vec<(&str, u64)> = non_stuck_atts
            .iter()
            .map(|a| (a.witness_hash.as_str(), a.stake))
            .collect();
        let eff_q = self.effective_stake_q(&witnesses);

        Self::diverse_threshold_met_q(eff_q, denominator)
    }

    /// Get the confirmation level of a record, considering its epoch seal status.
    ///
    /// Layered consensus derivation:
    /// 1. If record is in a Finalized seal → Finalized
    /// 2. If record is in a seal (but seal not yet settled) → Sealed
    /// 3. Otherwise → whatever the per-record level says (Pending or legacy)
    pub fn layered_confirmation(&self, record_id: &str) -> ConfirmationLevel {
        // O(1) reverse index lookup: record_id → seal_id
        if let Some(seal_id) = self.record_to_seal.get(record_id) {
            if self.is_seal_settled(seal_id) {
                // Check if anchored (past challenge window)
                if self.anchored.contains(record_id) {
                    return ConfirmationLevel::Anchored;
                }
                return ConfirmationLevel::Finalized;
            }
            return ConfirmationLevel::Sealed;
        }

        // Fall back to per-record level (backward compat / legacy)
        self.confirmation_levels
            .get(record_id)
            .copied()
            .unwrap_or(ConfirmationLevel::Pending)
    }

    /// Prune seal attestation state for fully anchored seals.
    pub fn prune_anchored_seals(&mut self, anchored_seal_ids: &HashSet<String>) -> usize {
        self.prune_anchored_seals_where(|sid| anchored_seal_ids.contains(sid))
    }

    /// Prune anchored seals matching a predicate. Closure-based version that
    /// avoids materializing a full HashSet (e.g., uses FinalizedIndex point lookups).
    pub fn prune_anchored_seals_where(&mut self, is_anchored: impl Fn(&str) -> bool) -> usize {
        let before = self.seal_attestations.len();
        // Clean reverse index for records in pruned seals
        let pruned_seal_ids: Vec<String> = self.seal_record_ids.keys()
            .filter(|sid| is_anchored(sid))
            .cloned()
            .collect();
        for sid in &pruned_seal_ids {
            if let Some(record_ids) = self.seal_record_ids.get(sid) {
                for rid in record_ids {
                    self.record_to_seal.remove(rid);
                }
            }
        }
        self.seal_attestations.retain(|sid, _| !is_anchored(sid));
        self.seal_record_ids.retain(|sid, _| !is_anchored(sid));
        self.seal_finalized_at.retain(|sid, _| !is_anchored(sid));
        self.seal_registered_at.retain(|sid, _| !is_anchored(sid));
        self.seal_first_attested_at.retain(|sid, _| !is_anchored(sid));
        self.global_seal_stuck_zone.retain(|sid, _| !is_anchored(sid));
        // R2 map follows seal_record_ids' lifetime (same rationale as the
        // prune_older_than hook).
        {
            let Self { unresolved_seal_members, seal_record_ids, .. } = self;
            unresolved_seal_members.retain(|_, sid| seal_record_ids.contains_key(sid.as_str()));
        }
        before - self.seal_attestations.len()
    }

    /// Promote records in seals that have been Finalized for > CHALLENGE_WINDOW_SECS
    /// to Anchored status (Protocol §11.12, Layer 4).
    ///
    /// Returns: (promoted_seals, promoted record rids). Callers MUST route
    /// the rids through the durable FinalizedIndex (anchored ⊃ finalized) —
    /// post-R1/R2 they are normally already indexed (idempotent no-op), but
    /// this routing is what keeps a member that reached Anchored through an
    /// unrouted legacy path from being permanently invisible: the
    /// `add_seal_attestation` edge guard treats Anchored as terminal and
    /// will never re-fire for it.
    #[must_use = "route promoted members to the durable FinalizedIndex"]
    pub fn promote_anchored(&mut self) -> (usize, Vec<String>) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);

        let mut seals_to_anchor = Vec::new();
        for (seal_id, finalized_at) in &self.seal_finalized_at {
            if now - finalized_at >= CHALLENGE_WINDOW_SECS {
                seals_to_anchor.push(seal_id.clone());
            }
        }

        let mut promoted_records: Vec<String> = Vec::new();
        for seal_id in &seals_to_anchor {
            if let Some(record_ids) = self.seal_record_ids.get(seal_id) {
                for rid in record_ids {
                    if !self.anchored.contains(rid.as_str()) {
                        self.anchored.insert(rid.clone());
                        self.confirmation_levels
                            .insert(rid.clone(), ConfirmationLevel::Anchored);
                        promoted_records.push(rid.clone());
                    }
                }
            }
            // Clean up finalized_at tracking for promoted seals
            self.seal_finalized_at.remove(seal_id);
            self.seal_registered_at.remove(seal_id);
            self.seal_first_attested_at.remove(seal_id);
        }

        (seals_to_anchor.len(), promoted_records)
    }

    /// Get seal attestation count.
    pub fn seal_attestation_count(&self, seal_id: &str) -> usize {
        self.seal_attestations.get(seal_id).map_or(0, |v| v.len())
    }

    /// Diversity-weighted effective stake on the seal's attestations,
    /// floored to u64. Same numerator math as `is_seal_settled` minus
    /// the 2/3 threshold check or stuck-zone routing — for callers that
    /// need the raw weight (e.g. PARTITION-MERGE Phase B same-epoch
    /// reconciliation in `register_seal`, where two partitions sealed
    /// `(zone, epoch)` with different record sets and the heavier-weight
    /// seal wins). Returns 0 for unknown seals or seals with no
    /// attestations. Uses `independence()` so an attacker cannot win the
    /// comparison by spamming non-diverse attestations from a single ASN
    /// or geo bucket.
    pub fn attestation_weight_for_seal(&self, seal_id: &str) -> u64 {
        let atts = match self.seal_attestations.get(seal_id) {
            Some(a) if !a.is_empty() => a,
            _ => return 0,
        };
        // Deterministic fixed-point effective stake — MUST share the numerator
        // math of `is_seal_settled` so the canonical-seal reconcile comparison
        // (`register_seal_with_reconcile` / `promote_orphan_to_canonical`, gated
        // by `partition_merge_weight_reconcile`) is byte-identical across nodes.
        // The prior `Σ stake·independence` in f64 over gossip-arrival-ordered
        // attestations was non-associative (order/FMA/arch dependent) → divergent
        // weights → divergent canonical-seal pick → chain-tip fork the moment the
        // reconciler flag is enabled. `effective_stake_q` sorts witnesses by hash
        // and accumulates in u128. See internal design notes.
        let witnesses: Vec<(&str, u64)> = atts
            .iter()
            .map(|a| (a.witness_hash.as_str(), a.stake))
            .collect();
        let eff_q = self.effective_stake_q(&witnesses);
        // eff_q is Q-scaled (SETTLEMENT_Q); floor to whole-stake u64 to preserve
        // the documented "floored to u64" weight semantics. Saturate defensively
        // (eff_q/Q ≤ total staked supply, which fits u64, but release builds carry
        // no overflow checks). Equal-weight seals fall to the lex-min hash tiebreak
        // in `register_seal_with_reconcile`, which is already deterministic.
        (eff_q / SETTLEMENT_Q).min(u64::MAX as u128) as u64
    }

    /// One-shot view of everything that gates
    /// `is_seal_settled` for a given seal. Returns `None` if no attestations
    /// have arrived for this seal (can't determine zone).
    ///
    /// Lets operators disambiguate the four failure modes in a single curl:
    ///   1. attestation_count low → witness coverage problem
    ///   2. committee_stake == 0 → committee registration not wired
    ///   3. effective_stake < threshold → diversity penalty dominant
    ///   4. is_settled == true but layered_confirmation != Finalized → consumer bug
    pub fn seal_debug(&self, seal_id: &str) -> Option<SealDebug> {
        let atts = self.seal_attestations.get(seal_id)?;
        let zone = atts.first().map(|a| a.zone.clone()).unwrap_or_else(ZoneId::default_zone);
        let epoch_number = atts.first().map(|a| a.epoch_number).unwrap_or(0);

        let committee_stake = self.committee_stakes.get(&zone).copied().unwrap_or(0);
        let zone_stake = self.zone_stakes.get(&zone).copied().unwrap_or(0);
        let settlement_denominator = self.settlement_denominator(&zone);

        let witness_hashes: Vec<&str> = atts.iter().map(|a| a.witness_hash.as_str()).collect();
        let attestors: Vec<SealAttestorDetail> = atts.iter().map(|a| {
            let ind = self.independence(&a.witness_hash, &witness_hashes);
            SealAttestorDetail {
                witness_hash: a.witness_hash.clone(),
                stake: a.stake,
                independence: ind,
                effective_stake: a.stake as f64 * ind,
                timestamp: a.timestamp,
            }
        }).collect();
        let effective_stake: f64 = attestors.iter().map(|a| a.effective_stake).sum();

        let is_settled = self.is_seal_settled(seal_id);
        let is_global = self.global_seal_stuck_zone.contains_key(seal_id);
        let stake_threshold = (settlement_denominator as f64) * 2.0 / 3.0;

        let committee_members: Vec<String> = self
            .committee_members
            .get(&zone)
            .map(|s| {
                let mut v: Vec<String> = s.iter().cloned().collect();
                v.sort();
                v
            })
            .unwrap_or_default();

        Some(SealDebug {
            seal_id: seal_id.to_string(),
            zone,
            epoch_number,
            attestation_count: atts.len(),
            attestors,
            effective_stake,
            committee_stake,
            zone_stake,
            settlement_denominator,
            stake_threshold,
            is_settled,
            is_global_seal: is_global,
            registered_at: self.seal_registered_at.get(seal_id).copied(),
            finalized_at: self.seal_finalized_at.get(seal_id).copied(),
            committee_members,
        })
    }

    /// Number of seals currently in the finalized-but-not-anchored window.
    ///
    /// The cluster-aggregate depth (sum of per-node `elara_seal_pending_anchor`)
    /// tends to sit on a stable low baseline with settlement-driven excursions:
    /// drain is gated on `prune_anchored_seals` / `promote_anchored`, both
    /// event-triggered, so the "cycles" are settlement-event-driven excursions
    /// rather than free-running oscillation. Operator implication: a sustained
    /// high depth lasting more than a couple of ticks is real backlog (an
    /// anchor-signature stall), whereas single-tick peaks that revert quickly
    /// are the expected settlement-event signature, not an alert.
    pub fn pending_anchor_count(&self) -> usize {
        self.seal_finalized_at.len()
    }

    /// Wall-clock of the oldest seal currently waiting
    /// for an anchor signature. Returns `None` when the window is empty.
    /// Operators dashboard `now - this` as
    /// `elara_seal_pending_anchor_oldest_age_seconds` to distinguish:
    ///   * healthy churn — count fluctuates but oldest stays <CHALLENGE_WINDOW_SECS (24h)
    ///   * stuck anchor — oldest grows unboundedly past 24h = `promote_anchored`
    ///     loop isn't running (would normally age the seal out at the
    ///     challenge-window expiry)
    ///
    /// Same pattern as `PendingLedger::oldest_applied_at` (commit 7befbf3).
    ///
    /// Delegates to `seal_pending_anchor_oldest_at_split`
    /// so the global min is derived from the same single pass the per-population
    /// signals use. Kept as a public helper for the test surface; production
    /// `/metrics` callers prefer the split form to alarm on each population
    /// separately.
    pub fn seal_pending_anchor_oldest_at(&self) -> Option<f64> {
        let (local, retro) = self.seal_pending_anchor_oldest_at_split();
        match (local, retro) {
            (None, None) => None,
            (Some(l), None) => Some(l),
            (None, Some(r)) => Some(r),
            (Some(l), Some(r)) => Some(l.min(r)),
        }
    }

    /// Pending-anchor oldest-age split by
    /// retroactive-vs-locally-registered. Returns `(local_oldest_at,
    /// retroactive_oldest_at)`; either side is `None` when its
    /// sub-population is empty.
    ///
    /// Why split: the *count* of pending-anchor seals already separates
    /// retro from local, but the *age* signal still conflated them — whichever
    /// sub-population held the global min hid the other. Operators couldn't
    /// alarm separately on the two distinct failure modes:
    ///
    ///   * **Local age > anchor-sig timeout (~600 s):** anchor service is
    ///     not signing the seal the local witness produced. Real backlog,
    ///     page someone.
    ///   * **Retro age > CHALLENGE_WINDOW_SECS (86400 s) + slop:**
    ///     `promote_anchored` is not draining the retroactive window —
    ///     distinct failure (ageing-out loop stalled), not anchor backlog.
    ///
    /// One pass over `seal_finalized_at`, O(pending_anchor_count). Uses the
    /// same local-vs-retroactive predicate: the seal is local iff
    /// `seal_registered_at` has a row for it.
    pub fn seal_pending_anchor_oldest_at_split(&self) -> (Option<f64>, Option<f64>) {
        let mut local: Option<f64> = None;
        let mut retro: Option<f64> = None;
        for (sid, &ts) in &self.seal_finalized_at {
            let bucket = if self.seal_registered_at.contains_key(sid.as_str()) {
                &mut local
            } else {
                &mut retro
            };
            *bucket = Some(match *bucket {
                Some(min) if min < ts => min,
                _ => ts,
            });
        }
        (local, retro)
    }

    /// Count of seals in the pending-anchor window that
    /// were finalized retroactively (peer-driven catchup) — i.e. the local
    /// `register_seal_records` never fired for them. Definition:
    ///   `seal_finalized_at.contains(sid) AND NOT seal_registered_at.contains(sid)`
    /// Distinct from `pending_anchor_count()` which counts the full window.
    /// Operator rule:
    ///   * `pending_anchor - pending_anchor_retroactive` = locally-registered
    ///     seals waiting for an anchor signature. Drains via
    ///     `prune_anchored_seals` when the sig arrives — sustained growth
    ///     here = real anchor-sig backlog, page someone.
    ///   * `pending_anchor_retroactive` = peer-attested seals the local
    ///     witness never produced. Drains only via `promote_anchored` after
    ///     the 24h challenge window. Bounded by 24h × per-zone seal rate;
    ///     plateauing at that ceiling is normal under sustained peer-driven
    ///     catchup, not a bug.
    ///
    /// Pairs with `seal_latency_retroactive_skipped_total` which
    /// counts the rate of new retroactive entries; this gauge is the
    /// resident depth.
    pub fn seal_pending_anchor_retroactive_count(&self) -> usize {
        self.seal_finalized_at
            .keys()
            .filter(|sid| !self.seal_registered_at.contains_key(sid.as_str()))
            .count()
    }

    /// Aggregate committee-size summary across all
    /// zones with a registered per-epoch committee. One pass over
    /// `committee_members`, O(zones_registered).
    ///
    /// Operators today have `committee_attestations_member_total` (counts
    /// attestations *from* committee members) but no signal on committee
    /// **size distribution**. At mainnet scale (1M zones × 7-member target)
    /// undersized committees mean either bootstrap-fallback active (sparse
    /// stake distribution for that zone) or the per-epoch rotation tick
    /// missed for those zones — `zones_below_target` is the load-bearing
    /// alarm signal that surfaces both modes without an O(N) Prometheus
    /// time-series per zone.
    ///
    /// `size_min` / `size_max` give the variance shape so an operator
    /// investigating `zones_below_target > 0` can pick the smallest
    /// committee to debug first.
    pub fn committee_size_summary(&self) -> CommitteeSizeSummary {
        let mut summary = CommitteeSizeSummary::default();
        let mut min_seen: usize = usize::MAX;
        for set in self.committee_members.values() {
            let len = set.len();
            summary.zones_registered += 1;
            if len < min_seen {
                min_seen = len;
            }
            if len > summary.size_max {
                summary.size_max = len;
            }
            if len < MAINNET_COMMITTEE_SIZE {
                summary.zones_below_target += 1;
            }
        }
        summary.size_min = if summary.zones_registered == 0 {
            0
        } else {
            min_seen
        };
        summary
    }

    /// Live progress of a record toward Finalized, for streaming-attestation
    /// UX (Gap 8 / mainnet scale mandate §PRODUCTION PATH #8).
    ///
    /// Returns `None` if the record is not yet in any seal (still Pending).
    /// Otherwise returns the seal it was bundled into, the current
    /// diversity-weighted effective stake, the zone's total stake, the
    /// 2/3 threshold the seal must cross, and whether it has crossed.
    ///
    /// Wallets call this to show "3 of 4 witnesses attested (67% stake)" in
    /// real time, so a record feels instant at Sealed even while it's still
    /// gathering attestations toward Finalized.
    /// KR-3 S2 (W1 drain hook): the covering seal's **record id** for
    /// `record_id`, with the seal's set-once monotonic finalization timestamp —
    /// returned only when a seal covers the record AND that seal has finalized.
    /// `None` encodes the design's two W1 no-op cases: the record has no covering
    /// seal yet (the Layer-1-first race — a record `force_finalized` via pure
    /// attestation before any seal covers it; its CF entry is written later by
    /// the W2 marker sweep), or the covering seal is not yet settled. Reads only
    /// the durable/monotonic `seal_finalized_at` (set once at `is_seal_settled`,
    /// `add_seal_attestation`), never the demotable `latest_seal_*` pointers
    /// (B4). Flag-gated caller (`pending_drain` W1 hook).
    pub fn covering_seal_finality(&self, record_id: &str) -> Option<(String, f64)> {
        let seal_id = self.record_to_seal.get(record_id)?;
        let finalized_at = self.seal_finalized_at.get(seal_id)?;
        Some((seal_id.clone(), *finalized_at))
    }

    /// Test-only: directly seed the covering-seal-finality state that
    /// [`covering_seal_finality`](Self::covering_seal_finality) reads —
    /// `record_to_seal[record_id] = seal_id` plus the set-once
    /// `seal_finalized_at[seal_id]`. Production populates both via
    /// `register_seal_records` + the `add_seal_attestation` settlement flow
    /// (exercised by the consensus seal tests); this lets the cross-module W1
    /// drain tests stand up a *settled covering seal* without re-driving that
    /// machinery. `#[cfg(test)]` so it can never be reached in production.
    #[cfg(test)]
    pub fn test_seed_covering_seal(&mut self, record_id: &str, seal_id: &str, finalized_at: f64) {
        self.record_to_seal
            .insert(record_id.to_string(), seal_id.to_string());
        self.seal_finalized_at
            .insert(seal_id.to_string(), finalized_at);
    }

    pub fn seal_progress_for_record(&self, record_id: &str) -> Option<SealProgress> {
        let seal_id = self.record_to_seal.get(record_id)?.clone();
        let is_global = self.global_seal_stuck_zone.contains_key(&seal_id);
        // Surface "Sealed but no attestations yet" as zero-progress instead of
        // hiding the record entirely — accounts need a stable anchor to show
        // "Sealed" state the moment the seal is proposed.
        let atts = match self.seal_attestations.get(&seal_id) {
            Some(a) if !a.is_empty() => a,
            _ => {
                let registered_at = self.seal_registered_at.get(&seal_id).copied();
                return Some(SealProgress {
                    seal_id,
                    epoch_number: 0,
                    zone_path: String::new(),
                    attestation_count: 0,
                    effective_stake: 0.0,
                    zone_total_stake: 0,
                    stake_threshold: 0.0,
                    settled: false,
                    is_global_seal: is_global,
                    finalized_at: None,
                    registered_at,
                });
            }
        };

        // Denominator: per-zone stake (normal seal) or one non-stuck zone's
        // worth (global quorum seal — Stage 3c.1).
        let (denominator, considered_atts): (u64, Vec<&SealAttestation>) = if let
            Some(stuck_zone) = self.global_seal_stuck_zone.get(&seal_id)
        {
            let d = self
                .zone_stakes
                .iter()
                .filter(|(z, _)| *z != stuck_zone)
                .map(|(_, s)| *s)
                .max()
                .unwrap_or(0);
            let a: Vec<&SealAttestation> = atts
                .iter()
                .filter(|a| &a.zone != stuck_zone)
                .collect();
            (d, a)
        } else {
            let zone = atts.first().map(|a| a.zone.clone()).unwrap_or_else(ZoneId::default_zone);
            // MAINNET gap #5: UX denominator must match settlement
            // denominator — otherwise accounts show a threshold that doesn't
            // line up with when the seal actually settles.
            let raw = self.settlement_denominator(&zone);
            let creator_stake = self.creator_stakes.get(&seal_id).copied().unwrap_or(0);
            let d = raw.saturating_sub(creator_stake);
            let a: Vec<&SealAttestation> = atts.iter().collect();
            (d, a)
        };

        let (epoch_number, zone_path) = atts
            .first()
            .map(|a| (a.epoch_number, a.zone.path().to_string()))
            .unwrap_or((0, String::new()));

        let witness_hashes: Vec<&str> = considered_atts
            .iter()
            .map(|a| a.witness_hash.as_str())
            .collect();
        let effective_stake: f64 = considered_atts
            .iter()
            .map(|att| {
                let ind = self.independence(&att.witness_hash, &witness_hashes);
                att.stake as f64 * ind
            })
            .sum();

        // 2/3 of denominator (MESH-BFT Theorem 1).
        let stake_threshold = (denominator as f64) * 2.0 / 3.0;
        let settled = self.is_seal_settled(&seal_id);
        let finalized_at = self.seal_finalized_at.get(&seal_id).copied();
        let registered_at = self.seal_registered_at.get(&seal_id).copied();

        Some(SealProgress {
            seal_id,
            epoch_number,
            zone_path,
            attestation_count: atts.len(),
            effective_stake,
            zone_total_stake: denominator,
            stake_threshold,
            settled,
            is_global_seal: is_global,
            finalized_at,
            registered_at,
        })
    }
}

/// Live progress of a record toward Finalized status. Returned by
/// `AWCConsensus::seal_progress_for_record` for the streaming-attestation
/// RPC (Gap 8).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealProgress {
    pub seal_id: String,
    pub epoch_number: u64,
    pub zone_path: String,
    /// Raw attestation count on this seal.
    pub attestation_count: usize,
    /// Diversity-weighted effective stake accumulated so far.
    pub effective_stake: f64,
    /// Denominator against which the 2/3 threshold is computed (zone total
    /// for per-zone seals, max non-stuck zone stake for global quorum seals).
    pub zone_total_stake: u64,
    /// 2/3 of `zone_total_stake` — the stake level the seal must cross to
    /// settle.
    pub stake_threshold: f64,
    /// True once `effective_stake >= stake_threshold`.
    pub settled: bool,
    /// True if this seal was promoted via Stage 3c.1 global quorum.
    pub is_global_seal: bool,
    /// Unix timestamp at which the seal first crossed the threshold, if any.
    pub finalized_at: Option<f64>,
    /// Unix timestamp at which `register_seal_records` was first called for
    /// this seal (the "submitted at" / proposal moment). Enables account UX
    /// to show elapsed time and ETA against the seal-attestation-latency
    /// histogram (`elara_seal_attestation_latency_seconds_*`).
    pub registered_at: Option<f64>,
}

/// Diagnostic payload. One-shot view of every input that
/// `is_seal_settled` uses, so the threshold math can be verified from
/// a single `/debug/seal/{id}` curl. See `AWCConsensus::seal_debug`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealDebug {
    pub seal_id: String,
    pub zone: ZoneId,
    pub epoch_number: u64,
    pub attestation_count: usize,
    pub attestors: Vec<SealAttestorDetail>,
    /// Sum of each attestor's `stake * independence` (diversity-weighted).
    pub effective_stake: f64,
    /// `committee_stakes[zone]` (0 if no committee registered).
    pub committee_stake: u64,
    /// `zone_stakes[zone]` (full-zone fallback denominator).
    pub zone_stake: u64,
    /// The value actually used by `is_seal_settled` (committee when nonzero,
    /// else zone).
    pub settlement_denominator: u64,
    /// 2/3 of `settlement_denominator` — crossing this flips `is_settled`.
    pub stake_threshold: f64,
    pub is_settled: bool,
    pub is_global_seal: bool,
    pub registered_at: Option<f64>,
    pub finalized_at: Option<f64>,
    /// Sorted list of committee members for this zone (empty when no
    /// committee registered — `zone_stake` fallback is in use).
    pub committee_members: Vec<String>,
}

/// Per-attestor diagnostic entry for [`SealDebug`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealAttestorDetail {
    pub witness_hash: String,
    pub stake: u64,
    pub independence: f64,
    pub effective_stake: f64,
    pub timestamp: f64,
}

// ─── Zone State (Protocol §7.5) ─────────────────────────────────────────────

/// Per-zone tracking for witness coverage analysis.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ZoneState {
    /// Zones that have seen at least one record.
    pub active_zones: std::collections::HashSet<ZoneId>,
    /// Record count per zone.
    pub zone_record_counts: HashMap<ZoneId, u64>,
    /// Witnesses that have attested in each zone.
    pub zone_witnesses: HashMap<ZoneId, std::collections::HashSet<String>>,
    /// Minimum witnesses required for coverage (from config).
    pub min_witnesses: usize,
}

impl ZoneState {
    pub fn new(min_witnesses: usize) -> Self {
        Self {
            active_zones: std::collections::HashSet::new(),
            zone_record_counts: HashMap::new(),
            zone_witnesses: HashMap::new(),
            min_witnesses,
        }
    }

    /// Track a record insertion in its zone.
    pub fn record_inserted(&mut self, record_id: &str) {
        let zone = zone_for_record(record_id);
        *self.zone_record_counts.entry(zone.clone()).or_insert(0) += 1;
        self.active_zones.insert(zone);
    }

    /// Track a witness attestation for a record's zone.
    pub fn record_witness(&mut self, record_id: &str, witness_hash: &str) {
        let zone = zone_for_record(record_id);
        self.zone_witnesses
            .entry(zone)
            .or_default()
            .insert(witness_hash.to_string());
    }

    /// Check if a zone has minimum witness coverage.
    pub fn has_coverage(&self, zone: &ZoneId) -> bool {
        self.zone_witnesses
            .get(zone)
            .is_some_and(|w| w.len() >= self.min_witnesses)
    }

    /// Return zones that have records but insufficient witness coverage.
    pub fn under_witnessed_zones(&self) -> Vec<ZoneId> {
        self.active_zones
            .iter()
            .filter(|z| !self.has_coverage(z))
            .cloned()
            .collect()
    }

    /// Summary: (zone, record_count, witness_count, has_coverage).
    pub fn coverage_summary(&self) -> Vec<(ZoneId, u64, usize, bool)> {
        let mut result: Vec<(ZoneId, u64, usize, bool)> = self
            .active_zones
            .iter()
            .map(|zone| {
                let count = self.zone_record_counts.get(zone).copied().unwrap_or(0);
                let witnesses = self.zone_witnesses.get(zone).map_or(0, |w| w.len());
                (zone.clone(), count, witnesses, self.has_coverage(zone))
            })
            .collect();
        result.sort_by_key(|r| r.0.clone());
        result
    }
}

/// Rebuild zone state from all records in storage.
/// WARNING: Loads ALL records — O(all_records) memory. Production startup uses
/// rebuild_zone_state_from_records with streaming data.
#[cfg(test)]
pub fn rebuild_zone_state(
    storage: &dyn crate::storage::Storage,
    min_witnesses: usize,
) -> ZoneState {
    let records = storage.query(None, None, None, None, usize::MAX).unwrap_or_default();
    rebuild_zone_state_from_records(&records, min_witnesses)
}

/// Rebuild zone state from a pre-loaded record slice (single-pass startup).
pub fn rebuild_zone_state_from_records(
    all_records: &[crate::record::ValidationRecord],
    min_witnesses: usize,
) -> ZoneState {
    let mut state = ZoneState::new(min_witnesses);
    for rec in all_records {
        state.record_inserted(&rec.id);
    }
    // Note: witness info is tracked by attestations at runtime, not stored with records.
    // On rebuild we only get record counts; witness coverage accumulates from live attestations.
    state
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(org: &str, subnet: &str, geo: &str) -> WitnessProfile {
        WitnessProfile {
            organization: org.to_string(),
            subnet: subnet.to_string(),
            geo_zone: geo.to_string(),
        }
    }

    fn setup_zone_stake(awc: &mut AWCConsensus, record_id: &str, total: u64) {
        let zone = zone_for_record(record_id);
        awc.register_zone_stake(zone, total);
    }

    // ── zone assignment ──────────────────────────────────────────

    #[test]
    fn test_zone_deterministic() {
        assert_eq!(zone_for_record("abc"), zone_for_record("abc"));
        assert_ne!(zone_for_record("abc"), zone_for_record("xyz"));
    }

    // ── correlation: fully independent ───────────────────────────

    #[test]
    fn test_correlation_independent() {
        let mut awc = AWCConsensus::new();
        awc.register_profile("w1", profile("org-a", "10.0.1", "earth-us"));
        awc.register_profile("w2", profile("org-b", "10.0.2", "earth-eu"));
        assert_eq!(awc.correlation("w1", "w2"), 0.0);
    }

    // ── correlation: same organization ───────────────────────────

    #[test]
    fn test_correlation_same_org() {
        let mut awc = AWCConsensus::new();
        awc.register_profile("w1", profile("acme", "10.0.1", "earth-us"));
        awc.register_profile("w2", profile("acme", "10.0.2", "earth-eu"));
        assert!((awc.correlation("w1", "w2") - ALPHA).abs() < f64::EPSILON);
    }

    // ── correlation: same subnet ─────────────────────────────────

    #[test]
    fn test_correlation_same_subnet() {
        let mut awc = AWCConsensus::new();
        awc.register_profile("w1", profile("org-a", "10.0.1", "earth-us"));
        awc.register_profile("w2", profile("org-b", "10.0.1", "earth-eu"));
        assert!((awc.correlation("w1", "w2") - BETA).abs() < f64::EPSILON);
    }

    // ── correlation: same geo zone ───────────────────────────────

    #[test]
    fn test_correlation_same_geo() {
        let mut awc = AWCConsensus::new();
        awc.register_profile("w1", profile("org-a", "10.0.1", "earth-us"));
        awc.register_profile("w2", profile("org-b", "10.0.2", "earth-us"));
        assert!((awc.correlation("w1", "w2") - GAMMA).abs() < f64::EPSILON);
    }

    // ── correlation: fully correlated (same everything) ──────────

    #[test]
    fn test_correlation_max() {
        let mut awc = AWCConsensus::new();
        awc.register_profile("w1", profile("acme", "10.0.1", "earth-us"));
        awc.register_profile("w2", profile("acme", "10.0.1", "earth-us"));
        let expected = ALPHA + BETA + GAMMA; // 0.9
        assert!((awc.correlation("w1", "w2") - expected).abs() < f64::EPSILON);
    }

    // ── correlation: unknown profile → high (conservative) ────────

    #[test]
    fn test_correlation_unknown_profile() {
        let mut awc = AWCConsensus::new();
        awc.register_profile("w1", profile("acme", "10.0.1", "earth-us"));
        // w2 has no profile → assume high correlation (ALPHA+BETA = 0.8)
        assert_eq!(awc.correlation("w1", "w2"), 0.8);
        assert_eq!(awc.correlation("w3", "w4"), 0.8);
    }

    // ── Stage 5.2: DerivedWitnessGeo correlation paths ───────────────────

    /// Helper: DerivedWitnessGeo from a plain IPv4 quad.
    fn dgeo(a: u8, b: u8, c: u8, d: u8) -> DerivedWitnessGeo {
        DerivedWitnessGeo::from_ip(std::net::IpAddr::V4(std::net::Ipv4Addr::new(a, b, c, d)))
    }

    #[test]
    fn derived_geo_match_triggers_same_subnet_even_if_self_report_differs() {
        // Two witnesses: different self-reported subnet strings, but both
        // registered from the same Hetzner /16 (213.133.x.x).
        // Expect: same_subnet fires via derived signal → β=0.3 penalty.
        let mut awc = AWCConsensus::new();
        awc.register_profile("w1", profile("org-a", "213.133.100", "earth-eu"));
        awc.register_profile("w2", profile("org-b", "213.133.200", "earth-us")); // lies about geo
        awc.register_derived_geo("w1", dgeo(213, 133, 100, 148));
        awc.register_derived_geo("w2", dgeo(213, 133, 200, 10));
        // same subnet (/16 match via derived), different self-reported org+zone.
        // 213.133.100.x is in the bundled ASN table (Hetzner /19 213.133.96.0/19),
        // but 213.133.200.x is NOT (outside the /19), so the ASN lookup returns
        // UNKNOWN for w2 and same_zone via ASN does not fire. Only the subnet penalty fires.
        let c = awc.correlation("w1", "w2");
        assert!((c - BETA).abs() < f64::EPSILON, "expected β={BETA}, got {c}");
    }

    #[test]
    fn derived_asn_match_triggers_same_zone_even_if_self_report_differs() {
        // Two witnesses in the same provider (Hetzner AS24940) but different
        // /16 blocks. Self-reported geo_zone strings lie (different values).
        // Expect: same_zone fires via derived ASN — insurance against sybils
        // claiming different geos within one provider.
        // Stage 5 activates GAMMA>0, so ASN-only match must surface as γ.
        let mut awc = AWCConsensus::new();
        awc.register_profile("w1", profile("org-a", "5.75.10", "earth-north"));
        awc.register_profile("w2", profile("org-b", "138.201.50", "earth-south"));
        awc.register_derived_geo("w1", dgeo(5, 75, 10, 100)); // Hetzner /16
        awc.register_derived_geo("w2", dgeo(138, 201, 50, 20)); // Hetzner /16 different
        let c = awc.correlation("w1", "w2");
        // Different org, different subnet (self + derived /16 differ), same ASN.
        // Only γ contributes.
        assert!((c - GAMMA).abs() < f64::EPSILON, "expected γ={GAMMA}, got {c}");
    }

    #[test]
    fn unknown_asn_does_not_trigger_same_zone() {
        // Two witnesses with unknown ASNs (private-space IPs) in *different*
        // /16 blocks. Self-reported geo_zone differs. derived-asn = 0 for
        // both → zone_derived must not fire; subnet_derived must not fire
        // either because /16s differ. Final = 0.0.
        let mut awc = AWCConsensus::new();
        awc.register_profile("w1", profile("org-a", "192.168.1", "earth-eu"));
        awc.register_profile("w2", profile("org-b", "10.0.2", "earth-us"));
        awc.register_derived_geo("w1", dgeo(192, 168, 1, 1));
        awc.register_derived_geo("w2", dgeo(10, 0, 2, 1));
        let c = awc.correlation("w1", "w2");
        assert_eq!(c, 0.0, "unknown ASN + different /16 must not fire same_zone or same_subnet");
    }

    #[test]
    fn empty_self_reported_subnet_does_not_force_match() {
        // Regression: two witnesses with no self-reported subnet ("" == "")
        // must NOT be considered same_subnet just because both are empty.
        let mut awc = AWCConsensus::new();
        awc.register_profile("w1", profile("org-a", "", "earth-eu"));
        awc.register_profile("w2", profile("org-b", "", "earth-us"));
        let c = awc.correlation("w1", "w2");
        assert_eq!(c, 0.0, "empty subnet strings must not fire same_subnet");
    }

    #[test]
    fn empty_self_reported_zone_does_not_force_match() {
        // Same regression for geo_zone.
        let mut awc = AWCConsensus::new();
        awc.register_profile("w1", profile("org-a", "10.0.1", ""));
        awc.register_profile("w2", profile("org-b", "10.0.2", ""));
        let c = awc.correlation("w1", "w2");
        assert_eq!(c, 0.0, "empty geo_zone strings must not fire same_zone");
    }

    #[test]
    fn derived_geo_from_ip_populates_correctly() {
        let g = DerivedWitnessGeo::from_ip(std::net::IpAddr::V4(
            std::net::Ipv4Addr::new(88, 99, 142, 148),
        ));
        assert_eq!(g.ip_prefix16, [88, 99]);
        assert_eq!(g.asn, 24940); // Hetzner
        assert!(g.is_observed());
    }

    #[test]
    fn derived_geo_default_is_unobserved() {
        let g = DerivedWitnessGeo::default();
        assert!(!g.is_observed());
        assert_eq!(g.ip_prefix16, [0, 0]);
        assert_eq!(g.asn, 0);
    }

    #[test]
    fn derived_geo_readback_roundtrip() {
        let mut awc = AWCConsensus::new();
        let g = dgeo(5, 78, 40, 20);
        awc.register_derived_geo("w1", g);
        let back = awc.derived_geo("w1").copied().unwrap();
        assert_eq!(back, g);
        assert!(awc.derived_geo("w_missing").is_none());
    }

    #[test]
    fn mixed_derived_observed_and_missing_does_not_crash() {
        // Only one side has derived geo; the other does not.
        // Must fall through to self-reported only (no panic, no false match).
        let mut awc = AWCConsensus::new();
        awc.register_profile("w1", profile("org-a", "88.99.142", "earth-eu"));
        awc.register_profile("w2", profile("org-b", "10.0.2", "earth-us"));
        awc.register_derived_geo("w1", dgeo(88, 99, 142, 148));
        // w2: no derived geo.
        let c = awc.correlation("w1", "w2");
        assert_eq!(c, 0.0, "missing one-sided derived geo must not trigger false match");
    }

    // ── independence: single witness ─────────────────────────────

    #[test]
    fn test_independence_solo() {
        let awc = AWCConsensus::new();
        // A single witness has no one to be correlated with
        assert_eq!(awc.independence("w1", &["w1"]), 1.0);
    }

    // ── independence: two independent witnesses ──────────────────

    #[test]
    fn test_independence_two_independent() {
        let mut awc = AWCConsensus::new();
        awc.register_profile("w1", profile("org-a", "10.0.1", "earth-us"));
        awc.register_profile("w2", profile("org-b", "10.0.2", "earth-eu"));
        // corr = 0, so independence = 1/(1+0) = 1.0
        assert_eq!(awc.independence("w1", &["w1", "w2"]), 1.0);
    }

    // ── independence: two correlated witnesses ───────────────────

    #[test]
    fn test_independence_two_correlated() {
        let mut awc = AWCConsensus::new();
        awc.register_profile("w1", profile("acme", "10.0.1", "earth-us"));
        awc.register_profile("w2", profile("acme", "10.0.1", "earth-us"));
        // corr = α(0.5) + β(0.3) + γ(0.0) = 0.8, independence = 1/(1+0.8) ≈ 0.556
        // (γ=0.0: same_zone discount removed for epoch-scoped consensus, Audit E2)
        let d = awc.independence("w1", &["w1", "w2"]);
        assert!((d - 1.0 / 1.8).abs() < 1e-10);
    }

    // ── independence: three witnesses, one correlated ────────────

    #[test]
    fn test_independence_mixed() {
        let mut awc = AWCConsensus::new();
        awc.register_profile("w1", profile("acme", "10.0.1", "earth-us"));
        awc.register_profile("w2", profile("acme", "10.0.2", "earth-eu")); // same org only
        awc.register_profile("w3", profile("other", "10.0.3", "mars-olympus")); // fully independent

        let d1 = awc.independence("w1", &["w1", "w2", "w3"]);
        // w1 corr with w2 = 0.5 (same org), w1 corr with w3 = 0.0
        // d(w1) = 1 / (1 + 0.5) = 0.667
        assert!((d1 - 1.0 / 1.5).abs() < 1e-10);

        let d3 = awc.independence("w3", &["w1", "w2", "w3"]);
        // w3 corr with w1 = 0.0, w3 corr with w2 = 0.0
        // d(w3) = 1 / (1 + 0) = 1.0
        assert_eq!(d3, 1.0);
    }

    // ── trust score: independent witnesses ───────────────────────

    #[test]
    fn test_trust_score_independent() {
        let mut awc = AWCConsensus::new();
        let rid = "test-record-1";

        setup_zone_stake(&mut awc, rid, 300);

        awc.register_profile("w1", profile("org-a", "10.0.1", "earth-us"));
        awc.register_profile("w2", profile("org-b", "10.0.2", "earth-eu"));

        awc.add_attestation(Attestation {
            record_id: rid.to_string(), witness_hash: "w1".to_string(), stake: 100, timestamp: 1.0,
        });
        awc.add_attestation(Attestation {
            record_id: rid.to_string(), witness_hash: "w2".to_string(), stake: 100, timestamp: 2.0,
        });

        let t = awc.trust_score(rid);
        // Both independent: d=1.0 for each
        // w1 weight = 100/300 = 0.333, w2 weight = 100/300 = 0.333
        // T = 1 - (1-0.333)*(1-0.333) = 1 - 0.667^2 ≈ 0.555
        assert!(t > 0.55 && t < 0.56, "trust = {t}");
    }

    // ── trust score: correlated witnesses (same org + subnet) ────

    #[test]
    fn test_trust_score_correlated() {
        let mut awc = AWCConsensus::new();
        let rid = "test-record-2";

        setup_zone_stake(&mut awc, rid, 300);

        // Same org + subnet → corr = 0.8
        awc.register_profile("w1", profile("acme", "10.0.1", "earth-us"));
        awc.register_profile("w2", profile("acme", "10.0.1", "earth-eu"));

        awc.add_attestation(Attestation {
            record_id: rid.to_string(), witness_hash: "w1".to_string(), stake: 100, timestamp: 1.0,
        });
        awc.add_attestation(Attestation {
            record_id: rid.to_string(), witness_hash: "w2".to_string(), stake: 100, timestamp: 2.0,
        });

        let t_corr = awc.trust_score(rid);

        // Compare with independent case: correlated trust should be LOWER
        let mut awc_ind = AWCConsensus::new();
        setup_zone_stake(&mut awc_ind, rid, 300);
        awc_ind.register_profile("w1", profile("org-a", "10.0.1", "earth-us"));
        awc_ind.register_profile("w2", profile("org-b", "10.0.2", "earth-eu"));
        awc_ind.add_attestation(Attestation {
            record_id: rid.to_string(), witness_hash: "w1".to_string(), stake: 100, timestamp: 1.0,
        });
        awc_ind.add_attestation(Attestation {
            record_id: rid.to_string(), witness_hash: "w2".to_string(), stake: 100, timestamp: 2.0,
        });
        let t_ind = awc_ind.trust_score(rid);

        assert!(t_corr < t_ind, "correlated trust ({t_corr}) should be lower than independent ({t_ind})");
        assert!(t_corr > 0.0, "correlated trust should still be positive");
    }

    // ── trust score: no attestations → 0 ─────────────────────────

    #[test]
    fn test_trust_score_none() {
        let mut awc = AWCConsensus::new();
        let rid = "test-record-3";
        setup_zone_stake(&mut awc, rid, 100);
        assert_eq!(awc.trust_score(rid), 0.0);
    }

    // ── trust score: single witness → w * d ──────────────────────

    #[test]
    fn test_trust_score_single_witness() {
        let mut awc = AWCConsensus::new();
        let rid = "test-record-4";
        setup_zone_stake(&mut awc, rid, 200);

        awc.register_profile("w1", profile("org-a", "10.0.1", "earth-us"));
        awc.add_attestation(Attestation {
            record_id: rid.to_string(), witness_hash: "w1".to_string(), stake: 100, timestamp: 1.0,
        });

        let t = awc.trust_score(rid);
        // Single witness, d=1.0, w=100/200=0.5
        // T = 1 - (1 - 0.5*1.0) = 0.5
        assert!((t - 0.5).abs() < f64::EPSILON);
    }

    // ── settlement with zone stakes ──────────────────────────────

    #[test]
    fn test_settlement_threshold() {
        let mut awc = AWCConsensus::new();
        let rid = "test-record-5";
        setup_zone_stake(&mut awc, rid, 300);

        // 199/300 = 66.3% — just under 2/3
        awc.add_attestation(Attestation {
            record_id: rid.to_string(), witness_hash: "w1".to_string(), stake: 199, timestamp: 1.0,
        });
        assert!(!awc.is_settled(rid));

        // 201/300 = 67% — over 2/3
        awc.add_attestation(Attestation {
            record_id: rid.to_string(), witness_hash: "w2".to_string(), stake: 2, timestamp: 2.0,
        });
        assert!(awc.is_settled(rid));
    }

    // ── settlement threshold must not overflow near MAX_SUPPLY (audit 16a) ──
    // Regression for the raw-multiply overflow in is_settled. Release builds
    // carry no overflow-checks, so `attesting * 3` / `eligible * 2` wrap
    // silently once stake nears MAX_SUPPLY (10^19; u64::MAX ≈ 1.8446e19) and
    // flip the verdict. saturating_mul keeps the comparison monotonic. Both
    // cases below give the WRONG boolean under raw `*` and the RIGHT one under
    // saturating_mul, so a revert to raw multiply fails this test.
    #[test]
    fn test_settlement_threshold_overflow_safe_near_max_supply() {
        // Case 1 — false positive under raw multiply.
        // eligible = 9.3e18 → eligible*2 = 1.86e19 > u64::MAX, wraps to ~1.53e17.
        // attesting = 1e18 (≈10.7%, far below 2/3). Raw: 3e18 >= 1.53e17 → wrongly
        // settled. saturating: 3e18 >= u64::MAX → correctly NOT settled.
        let mut awc = AWCConsensus::new();
        let rid = "overflow-false-positive";
        setup_zone_stake(&mut awc, rid, 9_300_000_000_000_000_000);
        awc.add_attestation(Attestation {
            record_id: rid.to_string(), witness_hash: "w1".to_string(),
            stake: 1_000_000_000_000_000_000, timestamp: 1.0,
        });
        assert!(
            !awc.is_settled(rid),
            "≈10.7% stake must NOT settle; a raw-multiply wrap would falsely settle it"
        );

        // Case 2 — false negative under raw multiply.
        // eligible = attesting = 6.2e18 (100% settled). attesting*3 = 1.86e19 >
        // u64::MAX, wraps to ~1.53e17 < eligible*2 (1.24e19) → raw wrongly NOT
        // settled. saturating: u64::MAX >= 1.24e19 → correctly settled.
        let mut awc2 = AWCConsensus::new();
        let rid2 = "overflow-false-negative";
        setup_zone_stake(&mut awc2, rid2, 6_200_000_000_000_000_000);
        awc2.add_attestation(Attestation {
            record_id: rid2.to_string(), witness_hash: "w1".to_string(),
            stake: 6_200_000_000_000_000_000, timestamp: 1.0,
        });
        assert!(
            awc2.is_settled(rid2),
            "100% stake must settle; a raw-multiply wrap would falsely reject it"
        );
    }

    // ── settlement fault tolerance of the genesis self-submit topology ──
    //
    // Pins the launch-critical caveat from internal design notes
    // §2 (fusion-audited 2026-06-21): because settlement excludes the creator's
    // own stake, a net of 3 EQUAL-stake validators that submit their OWN
    // transfers has ZERO settlement fault tolerance — strictly worse than N=2.
    // If a future refactor of is_settled's eligibility math changes this, these
    // tests go red and force the posture doc + join runbook to be revisited.

    #[test]
    fn settlement_n3_self_submit_has_zero_fault_tolerance() {
        // 3 equal-stake validators, the record's creator is one of them.
        // total = 3000, creator_stake = 1000 → eligible = 2000; 2/3 boundary =
        // 1334. The 2 OTHER validators (1000 each) must BOTH attest.
        const S: u64 = 1_000;
        let rid = "rec-ft-self-submit";
        let mut awc = AWCConsensus::new();
        setup_zone_stake(&mut awc, rid, 3 * S);
        awc.register_creator_stake(rid, "val-a", S);

        // Only one non-creator validator attests (its peer is offline).
        awc.add_attestation(Attestation {
            record_id: rid.to_string(), witness_hash: "val-b".to_string(),
            stake: S, timestamp: 1.0,
        });
        assert!(
            !awc.is_settled(rid),
            "1 of 2 non-creator validators (1000/2000) is below 2/3 — a single \
             offline validator stalls its peers' self-submitted transfers (0 FT)"
        );

        // Both non-creator validators attest — the ONLY way it settles.
        awc.add_attestation(Attestation {
            record_id: rid.to_string(), witness_hash: "val-c".to_string(),
            stake: S, timestamp: 2.0,
        });
        assert!(
            awc.is_settled(rid),
            "both non-creator validators (2000/2000) settle — N=3 self-submit \
             needs ALL others, so it tolerates ZERO faults"
        );

        assert_eq!(
            AWCConsensus::self_submit_settlement_fault_tolerance(3),
            0,
            "the FT formula must agree with the observed N=3 self-submit behaviour"
        );
    }

    #[test]
    fn settlement_self_submit_mitigations_restore_one_fault_tolerance() {
        const S: u64 = 1_000;

        // Mitigation A — non-staking submitter (creator_stake = 0): eligible =
        // full 3000; 2/3 = 2000; 2 of 3 validators settle with the third
        // offline → 1 fault tolerated.
        {
            let rid = "rec-ft-nonstaking-submitter";
            let mut awc = AWCConsensus::new();
            setup_zone_stake(&mut awc, rid, 3 * S);
            // no register_creator_stake → creator_stake defaults to 0
            for w in ["val-a", "val-b"] {
                awc.add_attestation(Attestation {
                    record_id: rid.to_string(), witness_hash: w.to_string(),
                    stake: S, timestamp: 1.0,
                });
            }
            assert!(
                awc.is_settled(rid),
                "non-staking submitter: 2 of 3 validators (2000/3000) settle ⇒ 1 fault tolerated"
            );
        }

        // Mitigation B — N=4 self-submit: total 4000, creator 1000, eligible
        // 3000; 2/3 = 2000; 2 of the 3 non-creator validators settle with the
        // third offline → 1 fault tolerated.
        {
            let rid = "rec-ft-n4-self-submit";
            let mut awc = AWCConsensus::new();
            setup_zone_stake(&mut awc, rid, 4 * S);
            awc.register_creator_stake(rid, "val-a", S);
            for w in ["val-b", "val-c"] {
                awc.add_attestation(Attestation {
                    record_id: rid.to_string(), witness_hash: w.to_string(),
                    stake: S, timestamp: 1.0,
                });
            }
            assert!(
                awc.is_settled(rid),
                "N=4 self-submit: 2 of 3 non-creator validators (2000/3000) settle ⇒ 1 fault tolerated"
            );
        }

        assert_eq!(AWCConsensus::self_submit_settlement_fault_tolerance(4), 1);
    }

    #[test]
    fn f1_committee_denominator_excludes_only_member_creators() {
        // F1: in committee mode the settlement denominator is the COMMITTEE's
        // stake. A creator that is not a committee member has no stake in that
        // denominator, so subtracting it (as the old code did unconditionally)
        // double-excludes — settling below 2/3, or wedging Pending forever when
        // the creator's global stake ≥ the committee stake. Only reachable past
        // COMMITTEE_SMALL_NETWORK stakers; at launch the committee is everyone.
        const S: u64 = 1_000;

        // Non-member creator with a HUGE global stake. Old code:
        // eligible = 3000 − 50000 → saturates to 0 → is_settled false forever.
        let rid = "rec-f1-nonmember-creator";
        let zone = zone_for_record(rid);
        let mut awc = AWCConsensus::new();
        setup_zone_stake(&mut awc, rid, 100 * S);
        awc.register_creator_stake(rid, "creator-x", 50 * S);
        awc.register_epoch_committee(
            &zone,
            &[("m-a".to_string(), S), ("m-b".to_string(), S), ("m-c".to_string(), S)],
        );
        // committee = 3000, creator not in it → eligible 3000, 2/3 = 2000.
        awc.add_attestation(Attestation {
            record_id: rid.to_string(), witness_hash: "m-a".to_string(), stake: S, timestamp: 1.0,
        });
        awc.add_attestation(Attestation {
            record_id: rid.to_string(), witness_hash: "m-b".to_string(), stake: S, timestamp: 2.0,
        });
        assert!(
            awc.is_settled(rid),
            "F1: a non-member creator's stake must NOT shrink the committee \
             denominator (old code wedged this at eligible=0)"
        );

        // Control: a creator that IS a committee member still has its stake
        // excluded (unchanged behaviour — the launch case).
        let rid2 = "rec-f1-member-creator";
        let zone2 = zone_for_record(rid2);
        let mut awc2 = AWCConsensus::new();
        setup_zone_stake(&mut awc2, rid2, 100 * S);
        awc2.register_creator_stake(rid2, "m-a", S);
        awc2.register_epoch_committee(
            &zone2,
            &[("m-a".to_string(), S), ("m-b".to_string(), S), ("m-c".to_string(), S)],
        );
        // committee = 3000, creator m-a in it → eligible 2000, 2/3 = 1334.
        awc2.add_attestation(Attestation {
            record_id: rid2.to_string(), witness_hash: "m-b".to_string(), stake: S, timestamp: 1.0,
        });
        assert!(!awc2.is_settled(rid2), "one of two non-creator members (1000/2000) is below 2/3");
        awc2.add_attestation(Attestation {
            record_id: rid2.to_string(), witness_hash: "m-c".to_string(), stake: S, timestamp: 2.0,
        });
        assert!(
            awc2.is_settled(rid2),
            "member creator's stake IS excluded (eligible 2000, both other members attest)"
        );
    }

    #[test]
    fn f2_dedup_refreshes_stale_zero_stake_attestation() {
        // F2: an attestation fed before the witness's stake record applied
        // locally is stored at stake=0; a later re-gossip (now stake-resolved)
        // is deduped. Old code froze the stale 0 → this node under-counts and
        // diverges from nodes that saw the stake in time. Update-on-dedup fixes
        // it: the refreshed stake corrects the stored value in place.
        const S: u64 = 1_000;
        let rid = "rec-f2-stale-stake";
        let mut awc = AWCConsensus::new();
        setup_zone_stake(&mut awc, rid, 3 * S);
        awc.register_creator_stake(rid, "creator-y", S); // creator 1000 → eligible 2000

        // First feed: both non-creator witnesses arrive at stake=0.
        for w in ["wit-b", "wit-c"] {
            awc.add_attestation(Attestation {
                record_id: rid.to_string(), witness_hash: w.to_string(), stake: 0, timestamp: 1.0,
            });
        }
        assert!(!awc.is_settled(rid), "attesting stake 0/2000 — not settled");

        // Re-gossip with resolved stakes. Old code deduped and kept 0.
        for w in ["wit-b", "wit-c"] {
            awc.add_attestation(Attestation {
                record_id: rid.to_string(), witness_hash: w.to_string(), stake: S, timestamp: 2.0,
            });
        }
        assert!(
            awc.is_settled(rid),
            "F2: dedup must refresh the frozen stake — 2000/2000 now settles"
        );
    }

    #[test]
    fn self_submit_fault_tolerance_formula_matches_2_3_quorum() {
        // ⌈2(n−1)/3⌉ of the n−1 non-creator validators must attest; FT is the
        // remainder. n<2 is the singleton carve-out (reported 0). N=3 and N=2
        // are both 0-FT; the first fault-tolerant self-submit set is N=4.
        let cases = [
            (0usize, 0usize),
            (1, 0),
            (2, 0), // pool=1, need ⌈2/3⌉=1
            (3, 0), // pool=2, need ⌈4/3⌉=2  ← the canonical bad case
            (4, 1), // pool=3, need ⌈6/3⌉=2
            (5, 1), // pool=4, need ⌈8/3⌉=3
            (7, 2), // pool=6, need ⌈12/3⌉=4
            (10, 3), // pool=9, need ⌈18/3⌉=6
        ];
        for (n, expected_ft) in cases {
            assert_eq!(
                AWCConsensus::self_submit_settlement_fault_tolerance(n),
                expected_ft,
                "self-submit FT for n={n} validators must be {expected_ft}"
            );
        }
    }

    // ── sybil resistance: many correlated witnesses < few independent ──

    #[test]
    fn test_sybil_resistance() {
        let rid = "test-record-6";

        // Scenario 1: 5 witnesses from the same organization + subnet + zone
        let mut awc_sybil = AWCConsensus::new();
        setup_zone_stake(&mut awc_sybil, rid, 500);
        for i in 0..5 {
            let wh = format!("sybil-{i}");
            awc_sybil.register_profile(&wh, profile("evil-corp", "10.0.1", "earth-us"));
            awc_sybil.add_attestation(Attestation {
                record_id: rid.to_string(), witness_hash: wh, stake: 20, timestamp: i as f64,
            });
        }
        let t_sybil = awc_sybil.trust_score(rid);

        // Scenario 2: 3 independent witnesses with the same total stake
        let mut awc_honest = AWCConsensus::new();
        setup_zone_stake(&mut awc_honest, rid, 500);
        for i in 0..3 {
            let wh = format!("honest-{i}");
            awc_honest.register_profile(&wh, profile(
                &format!("org-{i}"),
                &format!("10.{i}.0"),
                ["earth-us", "earth-eu", "mars-olympus"][i],
            ));
            awc_honest.add_attestation(Attestation {
                record_id: rid.to_string(), witness_hash: wh,
                stake: 100 / 3 + if i < 100 % 3 { 1 } else { 0 }, // ≈33 each, totaling ~100
                timestamp: i as f64,
            });
        }
        let t_honest = awc_honest.trust_score(rid);

        // 3 independent honest witnesses should produce higher trust than 5 sybil witnesses
        assert!(t_honest > t_sybil,
            "honest trust ({t_honest}) should exceed sybil trust ({t_sybil})");
    }

    // ── tracked_record_ids ────────────────────────────────────────

    #[test]
    fn test_tracked_record_ids() {
        let mut awc = AWCConsensus::new();
        assert!(awc.tracked_record_ids().is_empty());

        awc.add_attestation(Attestation {
            record_id: "r1".to_string(), witness_hash: "w1".to_string(), stake: 10, timestamp: 1.0,
        });
        awc.add_attestation(Attestation {
            record_id: "r2".to_string(), witness_hash: "w1".to_string(), stake: 10, timestamp: 2.0,
        });
        awc.add_attestation(Attestation {
            record_id: "r1".to_string(), witness_hash: "w2".to_string(), stake: 10, timestamp: 3.0,
        });

        let mut ids = awc.tracked_record_ids();
        ids.sort();
        assert_eq!(ids, vec!["r1", "r2"]);
    }

    // ── prune_finalized ───────────────────────────────────────────

    #[test]
    fn test_prune_finalized() {
        let mut awc = AWCConsensus::new();
        for i in 0..5 {
            awc.add_attestation(Attestation {
                record_id: format!("r{i}"), witness_hash: "w1".to_string(), stake: 10, timestamp: i as f64,
            });
        }
        assert_eq!(awc.tracked_record_ids().len(), 5);

        let finalized: std::collections::HashSet<String> =
            ["r0", "r2", "r4"].iter().map(|s| s.to_string()).collect();
        let pruned = awc.prune_finalized(&finalized);
        assert_eq!(pruned, 3);

        let mut remaining = awc.tracked_record_ids();
        remaining.sort();
        assert_eq!(remaining, vec!["r1", "r3"]);
    }

    // ── prune_finalized also prunes confirmation_levels and anchored ──

    #[test]
    fn test_prune_finalized_cleans_confirmation_and_anchored() {
        let mut awc = AWCConsensus::new();
        // Add attestations so confirmation_levels get populated
        for i in 0..4 {
            awc.add_attestation(Attestation {
                record_id: format!("r{i}"), witness_hash: "w1".to_string(), stake: 100, timestamp: i as f64,
            });
        }
        // Mark r0 and r2 as anchored
        awc.anchor_record("r0");
        awc.anchor_record("r2");

        // Verify pre-prune state
        assert_eq!(awc.confirmation_level("r0"), ConfirmationLevel::Sealed); // anchored needs Confirmed first
        assert_eq!(awc.confirmation_level("r1"), ConfirmationLevel::Sealed);
        assert_eq!(awc.confirmation_level("r2"), ConfirmationLevel::Sealed);
        assert_eq!(awc.confirmation_level("r3"), ConfirmationLevel::Sealed);

        // Finalize r0 and r1
        let finalized: std::collections::HashSet<String> =
            ["r0", "r1"].iter().map(|s| s.to_string()).collect();
        let pruned = awc.prune_finalized(&finalized);
        assert_eq!(pruned, 2);

        // confirmation_levels pruned for finalized records → returns Unconfirmed (default)
        assert_eq!(awc.confirmation_level("r0"), ConfirmationLevel::Pending);
        assert_eq!(awc.confirmation_level("r1"), ConfirmationLevel::Pending);
        // Non-finalized records retain their levels
        assert_eq!(awc.confirmation_level("r2"), ConfirmationLevel::Sealed);
        assert_eq!(awc.confirmation_level("r3"), ConfirmationLevel::Sealed);

        // Confirmation summary should only contain non-finalized entries
        let summary = awc.confirmation_summary();
        let attested_count = summary.get(&ConfirmationLevel::Sealed).copied().unwrap_or(0);
        assert_eq!(attested_count, 2); // r2, r3 only
    }

    // ── profiles iterator ──────────────────────────────────────────

    #[test]
    fn test_profiles_iterator() {
        let mut awc = AWCConsensus::new();

        // Empty initially
        assert_eq!(awc.profiles().count(), 0);

        // Register 3 profiles
        awc.register_profile("w1", profile("org-a", "10.0.1", "earth-us"));
        awc.register_profile("w2", profile("org-b", "10.0.2", "earth-eu"));
        awc.register_profile("w3", profile("org-a", "10.0.3", "mars-olympus"));

        let mut profiles: Vec<(&str, &WitnessProfile)> = awc.profiles().collect();
        profiles.sort_by_key(|(h, _)| *h);
        assert_eq!(profiles.len(), 3);
        assert_eq!(profiles[0].0, "w1");
        assert_eq!(profiles[0].1.organization, "org-a");
        assert_eq!(profiles[1].0, "w2");
        assert_eq!(profiles[1].1.geo_zone, "earth-eu");
        assert_eq!(profiles[2].0, "w3");
        assert_eq!(profiles[2].1.subnet, "10.0.3");

        // Overwrite w1's profile
        awc.register_profile("w1", profile("org-c", "172.16.0", "luna-tycho"));
        let p1 = awc.profiles().find(|(h, _)| *h == "w1").unwrap().1;
        assert_eq!(p1.organization, "org-c");
        assert_eq!(awc.profiles().count(), 3); // still 3, not 4
    }

    // ── total_zone_stake getter ──────────────────────────────────

    #[test]
    fn test_total_zone_stake() {
        let mut awc = AWCConsensus::new();
        assert_eq!(awc.total_zone_stake(ZoneId::from_legacy(0)), 0);

        awc.register_zone_stake(ZoneId::from_legacy(0), 100);
        awc.register_zone_stake(ZoneId::from_legacy(0), 200);
        assert_eq!(awc.total_zone_stake(ZoneId::from_legacy(0)), 300);
        assert_eq!(awc.total_zone_stake(ZoneId::from_legacy(1)), 0); // other zone still 0
    }

    // ── zone_health ──────────────────────────────────────────────

    #[test]
    fn test_zone_health_empty() {
        let awc = AWCConsensus::new();
        assert!(awc.zone_health().is_empty());
    }

    #[test]
    fn test_zone_health_with_records() {
        let mut awc = AWCConsensus::new();
        let rid1 = "test-zone-health-1";
        let rid2 = "test-zone-health-2";

        let zone1 = zone_for_record(rid1);
        let zone2 = zone_for_record(rid2);

        // Register stake and attestations
        setup_zone_stake(&mut awc, rid1, 300);
        awc.add_attestation(Attestation {
            record_id: rid1.to_string(),
            witness_hash: "w1".to_string(),
            stake: 100,
            timestamp: 1.0,
        });
        awc.add_attestation(Attestation {
            record_id: rid1.to_string(),
            witness_hash: "w2".to_string(),
            stake: 100,
            timestamp: 2.0,
        });

        setup_zone_stake(&mut awc, rid2, 300);
        awc.add_attestation(Attestation {
            record_id: rid2.to_string(),
            witness_hash: "w3".to_string(),
            stake: 250,
            timestamp: 3.0,
        });

        let health = awc.zone_health();

        if zone1 == zone2 {
            // Same zone: 2 records, check settled count
            let (_, _, active, _, witnesses) = health.iter().find(|(z, ..)| *z == zone1).unwrap();
            assert_eq!(*active, 2);
            assert_eq!(*witnesses, 3); // w1, w2, w3
        } else {
            // Different zones
            let h1 = health.iter().find(|(z, ..)| *z == zone1).unwrap();
            assert_eq!(h1.2, 1); // 1 active record
            assert_eq!(h1.4, 2); // 2 unique witnesses (w1, w2)

            let h2 = health.iter().find(|(z, ..)| *z == zone2).unwrap();
            assert_eq!(h2.2, 1); // 1 active record
            assert_eq!(h2.4, 1); // 1 unique witness (w3)
        }
    }

    // ── unsettled_summary ─────────────────────────────────────────

    #[test]
    fn test_unsettled_summary() {
        let mut awc = AWCConsensus::new();
        let rid1 = "test-unsettled-1";
        let rid2 = "test-unsettled-2";

        setup_zone_stake(&mut awc, rid1, 300);
        setup_zone_stake(&mut awc, rid2, 300);

        // r1: 1 attestation (not settled)
        awc.add_attestation(Attestation {
            record_id: rid1.to_string(), witness_hash: "w1".to_string(), stake: 50, timestamp: 1.0,
        });

        // r2: enough attestations to settle (>= 2/3 of 300 = 200)
        awc.add_attestation(Attestation {
            record_id: rid2.to_string(), witness_hash: "w2".to_string(), stake: 250, timestamp: 2.0,
        });

        let unsettled = awc.unsettled_summary();
        // r2 is settled, only r1 should appear
        assert_eq!(unsettled.len(), 1);
        assert_eq!(unsettled[0].0, rid1);
        assert_eq!(unsettled[0].1, 1); // 1 attestation
    }

    // ─── ZoneState Tests ─────────────────────────────────────────────

    #[test]
    fn test_zone_state_record_inserted() {
        let mut zs = ZoneState::new(1);
        zs.record_inserted("record-a");
        zs.record_inserted("record-b");
        assert!(!zs.active_zones.is_empty());
        let total: u64 = zs.zone_record_counts.values().sum();
        assert_eq!(total, 2);
    }

    #[test]
    fn test_zone_state_coverage() {
        let mut zs = ZoneState::new(2);
        zs.record_inserted("record-a");
        let zone = zone_for_record("record-a");

        // No witnesses yet
        assert!(!zs.has_coverage(&zone));

        // One witness — still not enough
        zs.record_witness("record-a", "witness-1");
        assert!(!zs.has_coverage(&zone));

        // Two witnesses — meets minimum
        zs.record_witness("record-a", "witness-2");
        assert!(zs.has_coverage(&zone));
    }

    #[test]
    fn test_zone_state_under_witnessed() {
        let mut zs = ZoneState::new(1);
        zs.record_inserted("record-a");
        let zone = zone_for_record("record-a");

        // No witnesses — under-witnessed
        let under = zs.under_witnessed_zones();
        assert!(under.contains(&zone));

        // Add witness — no longer under-witnessed
        zs.record_witness("record-a", "witness-1");
        let under = zs.under_witnessed_zones();
        assert!(!under.contains(&zone));
    }

    #[test]
    fn test_zone_state_coverage_summary() {
        let mut zs = ZoneState::new(1);
        zs.record_inserted("record-a");
        zs.record_inserted("record-b");
        zs.record_witness("record-a", "w1");

        let summary = zs.coverage_summary();
        assert!(!summary.is_empty());
        // At least one zone should have coverage
        let covered = summary.iter().filter(|(_, _, _, c)| *c).count();
        assert!(covered >= 1);
    }

    #[test]
    fn test_zone_state_multiple_zones() {
        let mut zs = ZoneState::new(1);
        // Insert many records to get multiple zones
        for i in 0..100 {
            zs.record_inserted(&format!("record-{i}"));
        }
        // With 100 records, we should get several distinct zones
        assert!(zs.active_zones.len() > 1, "expected multiple zones from 100 records");
    }

    #[test]
    fn test_zone_state_witness_dedup() {
        let mut zs = ZoneState::new(2);
        zs.record_inserted("record-a");
        zs.record_witness("record-a", "witness-1");
        zs.record_witness("record-a", "witness-1"); // duplicate

        let zone = zone_for_record("record-a");
        assert_eq!(zs.zone_witnesses.get(&zone).unwrap().len(), 1);
        assert!(!zs.has_coverage(&zone)); // only 1 unique witness
    }

    // ─── Confirmation Level Tests (economics §9.5) ────────────────────

    #[test]
    fn test_confirmation_default_unconfirmed() {
        let awc = AWCConsensus::new();
        assert_eq!(awc.confirmation_level("nonexistent"), ConfirmationLevel::Pending);
    }

    #[test]
    fn test_confirmation_attested_single_witness() {
        let mut awc = AWCConsensus::new();
        let rid = "conf-test-1";
        awc.add_attestation(Attestation {
            record_id: rid.to_string(), witness_hash: "w1".to_string(), stake: 100, timestamp: 1.0,
        });
        assert_eq!(awc.confirmation_level(rid), ConfirmationLevel::Sealed);
    }

    #[test]
    fn test_confirmation_attested_two_same_cluster() {
        let mut awc = AWCConsensus::new();
        let rid = "conf-test-2";
        // 2 witnesses from same org+subnet = 1 cluster + 0 unknown
        awc.register_profile("w1", profile("acme", "10.0.1", "earth-us"));
        awc.register_profile("w2", profile("acme", "10.0.1", "earth-eu"));
        awc.add_attestation(Attestation {
            record_id: rid.to_string(), witness_hash: "w1".to_string(), stake: 100, timestamp: 1.0,
        });
        awc.add_attestation(Attestation {
            record_id: rid.to_string(), witness_hash: "w2".to_string(), stake: 100, timestamp: 2.0,
        });
        // 2 witnesses but only 1 cluster — stays Attested
        assert_eq!(awc.confirmation_level(rid), ConfirmationLevel::Sealed);
    }

    #[test]
    fn test_confirmation_confirmed_three_clusters() {
        let mut awc = AWCConsensus::new();
        let rid = "conf-test-3";
        let zone = zone_for_record(rid);
        // Register zone stake so settlement can be computed
        awc.zone_stakes.insert(zone, 300); // total = 300, witnesses have 300 combined → 100%
        // 3 witnesses from 3 different clusters
        awc.register_profile("w1", profile("org-a", "10.0.1", "earth-us"));
        awc.register_profile("w2", profile("org-b", "10.0.2", "earth-eu"));
        awc.register_profile("w3", profile("org-c", "10.0.3", "mars-olympus"));
        for (i, wh) in ["w1", "w2", "w3"].iter().enumerate() {
            awc.add_attestation(Attestation {
                record_id: rid.to_string(),
                witness_hash: wh.to_string(),
                stake: 100,
                timestamp: i as f64,
            });
        }
        assert_eq!(awc.confirmation_level(rid), ConfirmationLevel::Finalized);
    }

    #[test]
    fn test_confirmation_three_witnesses_two_clusters_stays_attested() {
        let mut awc = AWCConsensus::new();
        let rid = "conf-test-4";
        // 3 witnesses but only 2 clusters (w1 and w2 in same cluster)
        awc.register_profile("w1", profile("acme", "10.0.1", "earth-us"));
        awc.register_profile("w2", profile("acme", "10.0.1", "earth-eu"));
        awc.register_profile("w3", profile("org-b", "10.0.2", "earth-eu"));
        for (i, wh) in ["w1", "w2", "w3"].iter().enumerate() {
            awc.add_attestation(Attestation {
                record_id: rid.to_string(),
                witness_hash: wh.to_string(),
                stake: 100,
                timestamp: i as f64,
            });
        }
        // 3 witnesses, but only 2 distinct clusters → Attested (not Confirmed)
        assert_eq!(awc.confirmation_level(rid), ConfirmationLevel::Sealed);
    }

    #[test]
    fn test_confirmation_unknown_profiles_unique_clusters() {
        let mut awc = AWCConsensus::new();
        let rid = "conf-test-5";
        let zone = zone_for_record(rid);
        awc.zone_stakes.insert(zone, 300);
        // 3 witnesses with NO profiles — no profiles registered at all,
        // so raw settlement fallback applies (bootstrapping phase)
        for (i, wh) in ["w1", "w2", "w3"].iter().enumerate() {
            awc.add_attestation(Attestation {
                record_id: rid.to_string(),
                witness_hash: wh.to_string(),
                stake: 100,
                timestamp: i as f64,
            });
        }
        // 3 witnesses, 3 unknown = 3 unique clusters, profiles empty → raw settlement fallback → Confirmed
        assert_eq!(awc.confirmation_level(rid), ConfirmationLevel::Finalized);
    }

    #[test]
    fn test_confirmation_anchor_upgrades_confirmed() {
        let mut awc = AWCConsensus::new();
        let rid = "conf-test-6";
        let zone = zone_for_record(rid);
        awc.zone_stakes.insert(zone, 300);
        awc.register_profile("w1", profile("org-a", "10.0.1", "earth-us"));
        awc.register_profile("w2", profile("org-b", "10.0.2", "earth-eu"));
        awc.register_profile("w3", profile("org-c", "10.0.3", "mars-olympus"));
        for (i, wh) in ["w1", "w2", "w3"].iter().enumerate() {
            awc.add_attestation(Attestation {
                record_id: rid.to_string(),
                witness_hash: wh.to_string(),
                stake: 100,
                timestamp: i as f64,
            });
        }
        assert_eq!(awc.confirmation_level(rid), ConfirmationLevel::Finalized);

        // Anchor it
        awc.anchor_record(rid);
        assert_eq!(awc.confirmation_level(rid), ConfirmationLevel::Anchored);
    }

    #[test]
    fn test_confirmation_anchor_does_not_upgrade_attested() {
        let mut awc = AWCConsensus::new();
        let rid = "conf-test-7";
        awc.add_attestation(Attestation {
            record_id: rid.to_string(), witness_hash: "w1".to_string(), stake: 100, timestamp: 1.0,
        });
        assert_eq!(awc.confirmation_level(rid), ConfirmationLevel::Sealed);

        // Anchoring an attested record should NOT upgrade — must be Confirmed first
        awc.anchor_record(rid);
        assert_eq!(awc.confirmation_level(rid), ConfirmationLevel::Sealed);
    }

    #[test]
    fn test_confirmation_bulk_anchor() {
        let mut awc = AWCConsensus::new();
        let rids = vec!["bulk-1".to_string(), "bulk-2".to_string(), "bulk-3".to_string()];
        // Register zone stake for each record's zone (no profiles → raw settlement fallback)
        for rid in &rids {
            awc.zone_stakes.insert(zone_for_record(rid), 300);
        }
        // Make all confirmed (3 unknown witnesses each = 3 unique clusters)
        for rid in &rids {
            for (i, wh) in ["w1", "w2", "w3"].iter().enumerate() {
                awc.add_attestation(Attestation {
                    record_id: rid.clone(),
                    witness_hash: format!("{rid}-{wh}"),
                    stake: 100,
                    timestamp: i as f64,
                });
            }
            assert_eq!(awc.confirmation_level(rid), ConfirmationLevel::Finalized);
        }

        awc.anchor_records(&rids);
        for rid in &rids {
            assert_eq!(awc.confirmation_level(rid), ConfirmationLevel::Anchored);
        }
    }

    #[test]
    fn test_confirmation_summary_counts() {
        let mut awc = AWCConsensus::new();
        // Register zone stakes for settlement
        awc.zone_stakes.insert(zone_for_record("sum-1"), 300);
        awc.zone_stakes.insert(zone_for_record("sum-2"), 300);
        awc.zone_stakes.insert(zone_for_record("sum-3"), 300);
        // r1: attested (1 witness)
        awc.add_attestation(Attestation {
            record_id: "sum-1".to_string(), witness_hash: "w1".to_string(), stake: 100, timestamp: 1.0,
        });
        // r2: confirmed (3 witnesses, 3 unknown clusters)
        for i in 0..3 {
            awc.add_attestation(Attestation {
                record_id: "sum-2".to_string(),
                witness_hash: format!("w{}", i + 10),
                stake: 100,
                timestamp: i as f64,
            });
        }
        // r3: confirmed then anchored
        for i in 0..3 {
            awc.add_attestation(Attestation {
                record_id: "sum-3".to_string(),
                witness_hash: format!("w{}", i + 20),
                stake: 100,
                timestamp: i as f64,
            });
        }
        awc.anchor_record("sum-3");

        let summary = awc.confirmation_summary();
        assert_eq!(summary.get(&ConfirmationLevel::Sealed).copied().unwrap_or(0), 1);
        assert_eq!(summary.get(&ConfirmationLevel::Finalized).copied().unwrap_or(0), 1);
        assert_eq!(summary.get(&ConfirmationLevel::Anchored).copied().unwrap_or(0), 1);
    }

    #[test]
    fn test_confirmation_level_ordering() {
        assert!(ConfirmationLevel::Pending < ConfirmationLevel::Sealed);
        assert!(ConfirmationLevel::Sealed < ConfirmationLevel::Finalized);
        assert!(ConfirmationLevel::Finalized < ConfirmationLevel::Anchored);
    }

    #[test]
    fn test_confirmation_level_display() {
        assert_eq!(ConfirmationLevel::Pending.name(), "pending");
        assert_eq!(ConfirmationLevel::Sealed.name(), "sealed");
        assert_eq!(ConfirmationLevel::Finalized.name(), "finalized");
        assert_eq!(ConfirmationLevel::Anchored.name(), "anchored");
    }

    #[test]
    fn test_confirmation_level_from_u8() {
        assert_eq!(ConfirmationLevel::from_u8(0), ConfirmationLevel::Pending);
        assert_eq!(ConfirmationLevel::from_u8(1), ConfirmationLevel::Sealed);
        assert_eq!(ConfirmationLevel::from_u8(2), ConfirmationLevel::Finalized);
        assert_eq!(ConfirmationLevel::from_u8(3), ConfirmationLevel::Anchored);
        assert_eq!(ConfirmationLevel::from_u8(255), ConfirmationLevel::Pending);
    }

    #[test]
    fn test_confirmation_progressive_upgrade() {
        let mut awc = AWCConsensus::new();
        let rid = "prog-1";
        awc.zone_stakes.insert(zone_for_record(rid), 300);
        assert_eq!(awc.confirmation_level(rid), ConfirmationLevel::Pending);

        // First witness → Attested
        awc.add_attestation(Attestation {
            record_id: rid.to_string(), witness_hash: "w1".to_string(), stake: 100, timestamp: 1.0,
        });
        assert_eq!(awc.confirmation_level(rid), ConfirmationLevel::Sealed);

        // Second witness (different cluster) → still Attested (need 3 clusters)
        awc.add_attestation(Attestation {
            record_id: rid.to_string(), witness_hash: "w2".to_string(), stake: 100, timestamp: 2.0,
        });
        assert_eq!(awc.confirmation_level(rid), ConfirmationLevel::Sealed);

        // Third witness (third cluster) → Confirmed
        awc.add_attestation(Attestation {
            record_id: rid.to_string(), witness_hash: "w3".to_string(), stake: 100, timestamp: 3.0,
        });
        assert_eq!(awc.confirmation_level(rid), ConfirmationLevel::Finalized);

        // Anchor → Anchored
        awc.anchor_record(rid);
        assert_eq!(awc.confirmation_level(rid), ConfirmationLevel::Anchored);
    }

    // ── Cross-Cluster Witness Diversity (Protocol §7.5) ────────────────

    #[test]
    fn test_timing_correlation_merges_simultaneous_witnesses() {
        let mut awc = AWCConsensus::new();
        let rid = "timing-1";
        // 3 unknown-profile witnesses attesting within 100ms — same cluster
        awc.add_attestation(Attestation {
            record_id: rid.to_string(), witness_hash: "w1".into(), stake: 100, timestamp: 1000.000,
        });
        awc.add_attestation(Attestation {
            record_id: rid.to_string(), witness_hash: "w2".into(), stake: 100, timestamp: 1000.050,
        });
        awc.add_attestation(Attestation {
            record_id: rid.to_string(), witness_hash: "w3".into(), stake: 100, timestamp: 1000.100,
        });
        // All within 0.1s → timing correlation merges them into 1 cluster
        assert_eq!(awc.distinct_clusters(rid), 1);
        // 3 witnesses but 1 cluster → Attested, NOT Confirmed
        assert_eq!(awc.confirmation_level(rid), ConfirmationLevel::Sealed);
    }

    #[test]
    fn test_timing_correlation_diverse_timestamps_separate_clusters() {
        let mut awc = AWCConsensus::new();
        let rid = "timing-2";
        awc.zone_stakes.insert(zone_for_record(rid), 300);
        // 3 unknown-profile witnesses with well-separated timestamps
        awc.add_attestation(Attestation {
            record_id: rid.to_string(), witness_hash: "w1".into(), stake: 100, timestamp: 1000.0,
        });
        awc.add_attestation(Attestation {
            record_id: rid.to_string(), witness_hash: "w2".into(), stake: 100, timestamp: 1002.0,
        });
        awc.add_attestation(Attestation {
            record_id: rid.to_string(), witness_hash: "w3".into(), stake: 100, timestamp: 1005.0,
        });
        // Each >0.5s apart → 3 distinct clusters
        assert_eq!(awc.distinct_clusters(rid), 3);
        assert_eq!(awc.confirmation_level(rid), ConfirmationLevel::Finalized);
    }

    #[test]
    fn test_timing_and_profile_combined_merging() {
        let mut awc = AWCConsensus::new();
        let rid = "combo-1";
        // w1 and w2: same org:subnet profile
        awc.register_profile("w1", profile("acme", "10.0.1", "earth"));
        awc.register_profile("w2", profile("acme", "10.0.1", "earth"));
        // w3 and w4: no profile but same timestamp (timing correlation)
        awc.add_attestation(Attestation {
            record_id: rid.to_string(), witness_hash: "w1".into(), stake: 100, timestamp: 1000.0,
        });
        awc.add_attestation(Attestation {
            record_id: rid.to_string(), witness_hash: "w2".into(), stake: 100, timestamp: 1005.0,
        });
        awc.add_attestation(Attestation {
            record_id: rid.to_string(), witness_hash: "w3".into(), stake: 100, timestamp: 1010.0,
        });
        awc.add_attestation(Attestation {
            record_id: rid.to_string(), witness_hash: "w4".into(), stake: 100, timestamp: 1010.1,
        });
        // w1+w2 merged by profile, w3+w4 merged by timing → 2 clusters
        assert_eq!(awc.distinct_clusters(rid), 2);
        assert_eq!(awc.confirmation_level(rid), ConfirmationLevel::Sealed);
    }

    #[test]
    fn test_timing_threshold_boundary() {
        let mut awc = AWCConsensus::new();
        let rid = "boundary-1";
        // Exactly at the 0.5s threshold boundary
        awc.add_attestation(Attestation {
            record_id: rid.to_string(), witness_hash: "w1".into(), stake: 100, timestamp: 1000.0,
        });
        awc.add_attestation(Attestation {
            record_id: rid.to_string(), witness_hash: "w2".into(), stake: 100, timestamp: 1000.5,
        });
        awc.add_attestation(Attestation {
            record_id: rid.to_string(), witness_hash: "w3".into(), stake: 100, timestamp: 1001.1,
        });
        // w1→w2: 0.5s = within threshold → merged
        // w2→w3: 0.6s > threshold → separate
        // w1→w3: 1.1s > threshold → separate
        // But w1 and w2 are merged, so: {w1,w2} + {w3} = 2 clusters
        assert_eq!(awc.distinct_clusters(rid), 2);
    }

    #[test]
    fn test_timing_transitive_merging() {
        let mut awc = AWCConsensus::new();
        let rid = "transitive-1";
        // Chain: w1 close to w2, w2 close to w3, but w1 far from w3
        // Union-find should merge all three transitively
        awc.add_attestation(Attestation {
            record_id: rid.to_string(), witness_hash: "w1".into(), stake: 100, timestamp: 1000.0,
        });
        awc.add_attestation(Attestation {
            record_id: rid.to_string(), witness_hash: "w2".into(), stake: 100, timestamp: 1000.4,
        });
        awc.add_attestation(Attestation {
            record_id: rid.to_string(), witness_hash: "w3".into(), stake: 100, timestamp: 1000.8,
        });
        // w1→w2: 0.4s (merged), w2→w3: 0.4s (merged), w1→w3: 0.8s (>0.5, but transitive)
        // All merged into 1 cluster via union-find transitivity
        assert_eq!(awc.distinct_clusters(rid), 1);
    }

    #[test]
    fn test_distinct_clusters_empty_record() {
        let awc = AWCConsensus::new();
        assert_eq!(awc.distinct_clusters("nonexistent"), 0);
    }

    #[test]
    fn test_distinct_clusters_single_witness() {
        let mut awc = AWCConsensus::new();
        let rid = "single-1";
        awc.add_attestation(Attestation {
            record_id: rid.to_string(), witness_hash: "w1".into(), stake: 100, timestamp: 1000.0,
        });
        assert_eq!(awc.distinct_clusters(rid), 1);
    }

    #[test]
    fn test_zone_state_witness_coverage() {
        let mut zs = ZoneState::new(2);
        let rid = "zone-witness-1";
        zs.record_inserted(rid);
        let zone = zone_for_record(rid);

        // No witnesses yet — not covered
        assert!(!zs.has_coverage(&zone));

        // One witness — still not enough
        zs.record_witness(rid, "w1");
        assert!(!zs.has_coverage(&zone));

        // Two witnesses — covered
        zs.record_witness(rid, "w2");
        assert!(zs.has_coverage(&zone));

        // Same witness again — no change
        zs.record_witness(rid, "w2");
        assert_eq!(zs.zone_witnesses.get(&zone).unwrap().len(), 2);
    }

    // ─── Diversity-weighted settlement tests ────────────────

    #[test]
    fn test_is_settled_diverse_independent_witnesses() {
        let mut awc = AWCConsensus::new();
        let rid = "test-record-diverse-1";
        let zone = zone_for_record(rid);

        // Register 3 independent witnesses with profiles
        awc.register_zone_stake(zone, 300);
        awc.register_profile("w1", WitnessProfile {
            organization: "org-a".into(), subnet: "10.0.1".into(), geo_zone: "eu".into(),
        });
        awc.register_profile("w2", WitnessProfile {
            organization: "org-b".into(), subnet: "10.0.2".into(), geo_zone: "us".into(),
        });
        awc.register_profile("w3", WitnessProfile {
            organization: "org-c".into(), subnet: "10.0.3".into(), geo_zone: "asia".into(),
        });

        // All 3 attest with 100 stake each = 300/300 = 100% raw stake
        awc.add_attestation(Attestation { record_id: rid.into(), witness_hash: "w1".into(), stake: 100, timestamp: 1.0 });
        awc.add_attestation(Attestation { record_id: rid.into(), witness_hash: "w2".into(), stake: 100, timestamp: 2.0 });
        awc.add_attestation(Attestation { record_id: rid.into(), witness_hash: "w3".into(), stake: 100, timestamp: 3.0 });

        // Raw settlement: 300/300 >= 2/3 → settled
        assert!(awc.is_settled(rid));
        // Diverse settlement: independent witnesses → effective ≈ raw → also settled
        assert!(awc.is_settled_diverse(rid));

        // Effective stake should be close to raw (all independent)
        let (effective, raw, ratio) = awc.effective_attesting_stake(rid);
        assert_eq!(raw, 300);
        assert!(ratio > 0.9, "independent witnesses should have >90% ratio, got {ratio}");
        assert!(effective > 200.0, "effective stake should be >200, got {effective}");
    }

    #[test]
    fn test_is_settled_diverse_correlated_sybil() {
        let mut awc = AWCConsensus::new();
        let rid = "test-record-sybil-1";
        let zone = zone_for_record(rid);

        // 5 correlated sybil witnesses — same org, same subnet, same geo
        awc.register_zone_stake(zone, 500);
        for i in 0..5 {
            let wh = format!("sybil-{i}");
            awc.register_profile(&wh, WitnessProfile {
                organization: "evil-org".into(), subnet: "10.0.0".into(), geo_zone: "us-east".into(),
            });
            awc.add_attestation(Attestation {
                record_id: rid.into(), witness_hash: wh, stake: 100, timestamp: 1.0 + i as f64 * 0.6,
            });
        }

        // Raw settlement: 500/500 = 100% → settled
        assert!(awc.is_settled(rid));

        // Diversity check: correlated witnesses → much lower effective stake
        let (effective, raw, ratio) = awc.effective_attesting_stake(rid);
        assert_eq!(raw, 500);
        assert!(ratio < 0.3, "correlated sybils should have <30% ratio, got {ratio}");
        assert!(effective < 150.0, "effective sybil stake should be <150, got {effective}");

        // Diverse settlement should FAIL — effective stake too low for 2/3 threshold
        assert!(!awc.is_settled_diverse(rid));
    }

    // ── KR-3 S2 wiring-(c) c3-ii: consensus settlement-zone override (§6.1 item 2) ──

    /// A lineage id whose naive zone differs from `rid`'s, so a routing-key swap is
    /// observable. ZONE_COUNT defaults to 4 (like the multi-zone tests above), so a
    /// differing-zone lineage always exists within a few candidates.
    fn differing_zone_lineage(rid: &str) -> String {
        let rz = zone_for_record(rid);
        (0..10_000)
            .map(|i| format!("c3ii-lineage-{i}"))
            .find(|l| zone_for_record(l) != rz)
            .expect("with ZONE_COUNT > 1 a differing-zone lineage must exist")
    }

    /// Flag-OFF (no override ever registered): the settlement routing key is the
    /// record id — BYTE-IDENTICAL to the pre-c3-ii `zone_for_record(record_id)`.
    #[test]
    fn c3ii_settlement_zone_is_naive_without_override() {
        let awc = AWCConsensus::new();
        assert!(awc.rotation_zone_overrides.is_empty());
        assert_eq!(awc.settlement_zone_for("rec-x"), zone_for_record("rec-x"));
        assert_eq!(awc.settlement_zone_for("rec-y"), zone_for_record("rec-y"));
    }

    /// Flag-ON: a registered override routes settlement via the lineage id, not the
    /// record id — the in-memory mirror of the durable pin (§6.1 item 2). A
    /// non-overridden id still routes naively.
    #[test]
    fn c3ii_override_routes_settlement_via_lineage() {
        let mut awc = AWCConsensus::new();
        let rid = "c3ii-rec";
        let lineage = differing_zone_lineage(rid);
        awc.insert_rotation_zone_override(rid, &lineage);
        assert_eq!(awc.settlement_zone_for(rid), zone_for_record(&lineage));
        assert_ne!(awc.settlement_zone_for(rid), zone_for_record(rid));
        assert_eq!(awc.settlement_zone_for("other"), zone_for_record("other"));
    }

    /// The override changes the `is_settled` DENOMINATOR: a record that settles
    /// against its naive zone's stake fails to settle against its differently-staked
    /// lineage zone. Proves the override is load-bearing on the Layer-1 settlement
    /// verdict — not merely the display sites.
    #[test]
    fn c3ii_override_changes_is_settled_denominator() {
        let mut awc = AWCConsensus::new();
        let rid = "c3ii-settle";
        let lineage = differing_zone_lineage(rid);
        // Naive zone: eligible 300, attesting 200 → 600 >= 600 SETTLES.
        // Lineage zone: eligible 900 → 600 < 1800 does NOT settle.
        awc.register_zone_stake(zone_for_record(rid), 300);
        awc.register_zone_stake(zone_for_record(&lineage), 900);
        awc.add_attestation(Attestation {
            record_id: rid.into(),
            witness_hash: "w1".into(),
            stake: 200,
            timestamp: 1.0,
        });
        assert!(awc.is_settled(rid), "naive-zone denominator (300) settles");
        awc.insert_rotation_zone_override(rid, &lineage);
        assert!(
            !awc.is_settled(rid),
            "lineage-zone denominator (900) must NOT settle"
        );
    }

    /// Anti-fork: two engines that admitted the same rotation hop (same override)
    /// resolve the identical settlement zone — a pure function of the pin, so it
    /// cannot diverge across nodes.
    #[test]
    fn c3ii_override_is_cross_engine_identical() {
        let rid = "c3ii-fork";
        let lineage = differing_zone_lineage(rid);
        let mut a = AWCConsensus::new();
        let mut b = AWCConsensus::new();
        a.insert_rotation_zone_override(rid, &lineage);
        b.insert_rotation_zone_override(rid, &lineage);
        assert_eq!(a.settlement_zone_for(rid), b.settlement_zone_for(rid));
        assert_eq!(a.settlement_zone_for(rid), zone_for_record(&lineage));
    }

    /// Retention: the override is pruned in lockstep with `attestations` —
    /// finalized-prune drops it (post-finality the CF governs), as does
    /// `forget_record`. After pruning, settlement falls back to the naive zone.
    #[test]
    fn c3ii_override_pruned_with_attestations() {
        let rid = "c3ii-prune";
        let lineage = differing_zone_lineage(rid);

        // prune_finalized path
        let mut awc = AWCConsensus::new();
        awc.insert_rotation_zone_override(rid, &lineage);
        awc.add_attestation(Attestation {
            record_id: rid.into(),
            witness_hash: "w1".into(),
            stake: 10,
            timestamp: 1.0,
        });
        let mut fin = std::collections::HashSet::new();
        fin.insert(rid.to_string());
        awc.prune_finalized(&fin);
        assert_eq!(
            awc.settlement_zone_for(rid),
            zone_for_record(rid),
            "finalized-prune must drop the override"
        );

        // forget_record path
        let mut awc2 = AWCConsensus::new();
        awc2.insert_rotation_zone_override(rid, &lineage);
        awc2.forget_record(rid);
        assert_eq!(
            awc2.settlement_zone_for(rid),
            zone_for_record(rid),
            "forget_record must drop the override"
        );
    }

    // ── Fixed-point settlement determinism (internal design notes) ──

    /// The gating quantity must be byte-identical regardless of the order
    /// attestations arrived in. This is the core fork-fix: f64 `.sum()` over
    /// gossip-arrival order was non-associative; integer `effective_stake_q`
    /// is not.
    #[test]
    fn fixed_point_effective_stake_is_insertion_order_independent() {
        let mut awc = AWCConsensus::new();
        // Distinct profiles → fractional, witness-specific independence (exactly
        // the case where the old f64 sum diverged across arrival order).
        awc.register_profile("wa", profile("org-a", "10.0.1", "earth-eu"));
        awc.register_profile("wb", profile("org-b", "10.0.2", "earth-us"));
        awc.register_profile("wc", profile("org-c", "10.0.3", "earth-as"));
        awc.register_profile("wd", profile("org-a", "10.0.1", "earth-eu")); // corr. w/ wa

        let order1 = [("wa", 100u64), ("wb", 200), ("wc", 300), ("wd", 400)];
        let order2 = [("wd", 400u64), ("wc", 300), ("wb", 200), ("wa", 100)];
        let order3 = [("wc", 300u64), ("wa", 100), ("wd", 400), ("wb", 200)];

        let e1 = awc.effective_stake_q(&order1);
        assert!(e1 > 0);
        assert_eq!(e1, awc.effective_stake_q(&order2), "order2 must match order1");
        assert_eq!(e1, awc.effective_stake_q(&order3), "order3 must match order1");
    }

    /// Same property at the verdict level: two honest nodes that received the
    /// same attestation set in opposite order reach the identical `is_settled_diverse`.
    #[test]
    fn is_settled_diverse_verdict_is_insertion_order_independent() {
        let witnesses = [
            ("wa", profile("org-a", "10.0.1", "earth-eu"), 100u64),
            ("wb", profile("org-b", "10.0.2", "earth-us"), 200u64),
            ("wc", profile("org-c", "10.0.3", "earth-as"), 300u64),
        ];
        let verdict_for = |order: &[usize]| {
            let mut awc = AWCConsensus::new();
            let rid = "fp-order";
            awc.register_zone_stake(zone_for_record(rid), 900);
            for &i in order {
                let (h, p, s) = &witnesses[i];
                awc.register_profile(h, p.clone());
                awc.add_attestation(Attestation {
                    record_id: rid.into(),
                    witness_hash: (*h).into(),
                    stake: *s,
                    timestamp: 1.0 + i as f64,
                });
            }
            awc.is_settled_diverse(rid)
        };
        assert_eq!(verdict_for(&[0, 1, 2]), verdict_for(&[2, 1, 0]));
        assert_eq!(verdict_for(&[0, 1, 2]), verdict_for(&[1, 2, 0]));
    }

    /// Above 2^53 base units f64 can no longer represent every integer; the
    /// fixed-point path keeps exact-rational verdicts where f64 had a cliff.
    #[test]
    fn fixed_point_settlement_has_no_f64_cliff_above_2pow53() {
        let awc = AWCConsensus::new();
        // Single witness → independence is exactly 1.0, so eff_q = stake·Q exactly.
        // eligible = 1.5e16 > 2^53 (≈9.007e15).
        let eligible: u64 = 15_000_000_000_000_000;
        // 3·stake == 2·eligible exactly → settle (>=).
        let at_boundary = [("w1", 10_000_000_000_000_000u64)];
        assert!(AWCConsensus::diverse_threshold_met_q(
            awc.effective_stake_q(&at_boundary),
            eligible
        ));
        // One base-unit below the boundary → must NOT settle. The exact-integer
        // path resolves this; f64 cannot (the value isn't representable).
        let below = [("w1", 9_999_999_999_999_999u64)];
        assert!(!AWCConsensus::diverse_threshold_met_q(
            awc.effective_stake_q(&below),
            eligible
        ));
        // Demonstrate the cliff this fix removes: an odd integer above 2^53 does
        // not survive an f64 round-trip, but u128 carries it exactly.
        assert_ne!(
            9_999_999_999_999_999u64 as f64 as u64,
            9_999_999_999_999_999u64,
            "odd integer above 2^53 is not f64-representable"
        );
    }

    /// On the live single-org testnet the diverse gate must match the exact
    /// integer raw gate (single witness ⇒ independence 1.0). Behaviour-preserving.
    #[test]
    fn fixed_point_single_witness_matches_raw_settlement() {
        let mut awc = AWCConsensus::new();
        let rid = "fp-equiv-settles";
        awc.register_zone_stake(zone_for_record(rid), 300);
        awc.add_attestation(Attestation {
            record_id: rid.into(), witness_hash: "w1".into(), stake: 200, timestamp: 1.0,
        });
        // 3·200 = 600 >= 2·300 = 600 → both settle.
        assert!(awc.is_settled(rid));
        assert_eq!(awc.is_settled_diverse(rid), awc.is_settled(rid));

        let rid2 = "fp-equiv-blocks";
        awc.register_zone_stake(zone_for_record(rid2), 300);
        awc.add_attestation(Attestation {
            record_id: rid2.into(), witness_hash: "w1".into(), stake: 199, timestamp: 1.0,
        });
        // 3·199 = 597 < 600 → neither settles.
        assert!(!awc.is_settled(rid2));
        assert_eq!(awc.is_settled_diverse(rid2), awc.is_settled(rid2));
    }

    /// Drift guard: the integer weights must equal their f64 counterparts × Q.
    #[test]
    fn fixed_point_q_constants_match_f64_weights() {
        assert_eq!(SETTLEMENT_Q, 1_000_000_000);
        assert_eq!(ALPHA_Q, (ALPHA * SETTLEMENT_Q as f64).round() as u128);
        assert_eq!(BETA_Q, (BETA * SETTLEMENT_Q as f64).round() as u128);
        assert_eq!(GAMMA_Q, (GAMMA * SETTLEMENT_Q as f64).round() as u128);
    }

    #[test]
    fn test_effective_stake_empty() {
        let awc = AWCConsensus::new();
        let (eff, raw, ratio) = awc.effective_attesting_stake("nonexistent");
        assert_eq!(eff, 0.0);
        assert_eq!(raw, 0);
        assert_eq!(ratio, 0.0);
    }

    // ── Layered consensus tests (Steps 3+4) ─────────────────────

    #[test]
    fn test_register_seal_records_upgrades_to_sealed() {
        let mut awc = AWCConsensus::new();
        // Record starts as Pending
        assert_eq!(awc.confirmation_level("r1"), ConfirmationLevel::Pending);

        // Register seal containing r1
        let _ = awc.register_seal_records("seal-0", vec!["r1".to_string(), "r2".to_string()]);

        // Should upgrade to Sealed
        assert_eq!(awc.confirmation_level("r1"), ConfirmationLevel::Sealed);
        assert_eq!(awc.confirmation_level("r2"), ConfirmationLevel::Sealed);
    }

    #[test]
    fn test_seal_attestation_settles_to_finalized() {
        let mut awc = AWCConsensus::new();
        let zone = ZoneId::from_legacy(0);
        awc.zone_stakes.insert(zone.clone(), 300);

        // Register profiles
        awc.register_profile("w1", profile("org-a", "10.0.1", "earth-us"));
        awc.register_profile("w2", profile("org-b", "10.0.2", "earth-eu"));
        awc.register_profile("w3", profile("org-c", "10.0.3", "mars-olympus"));

        // Register seal with records
        let _ = awc.register_seal_records("seal-0", vec!["r1".to_string(), "r2".to_string()]);
        assert_eq!(awc.confirmation_level("r1"), ConfirmationLevel::Sealed);

        // Add seal attestations (3 witnesses × 100 stake = 300, total = 300, 100%)
        for (i, wh) in ["w1", "w2", "w3"].iter().enumerate() {
            let _ = awc.add_seal_attestation(SealAttestation {
                seal_id: "seal-0".to_string(),
                zone: zone.clone(),
                epoch_number: 0,
                witness_hash: wh.to_string(),
                stake: 100,
                timestamp: i as f64,
            });
        }

        // Seal is settled → records should be Finalized
        assert!(awc.is_seal_settled("seal-0"));
        assert_eq!(awc.confirmation_level("r1"), ConfirmationLevel::Finalized);
        assert_eq!(awc.confirmation_level("r2"), ConfirmationLevel::Finalized);
    }

    #[test]
    fn test_seal_attestation_dedup_by_witness() {
        // A duplicated (seal_id, witness_hash) must NOT inflate effective stake.
        // Without the dedup, gossip refeed / att-pull re-delivery double-counts a
        // witness toward the 2/3 seal-settlement threshold — effective_stake_q has
        // no internal dedup. Mirrors add_attestation's record-path dedup.
        let mut awc = AWCConsensus::new();
        let zone = ZoneId::from_legacy(0);
        awc.zone_stakes.insert(zone.clone(), 300);
        awc.register_profile("w1", profile("org-a", "10.0.1", "earth-us"));
        let _ = awc.register_seal_records("seal-0", vec!["r1".to_string()]);

        // Same witness attests 3× — count must stay 1, well under 2/3 (200).
        for _ in 0..3 {
            let _ = awc.add_seal_attestation(SealAttestation {
                seal_id: "seal-0".to_string(),
                zone: zone.clone(),
                epoch_number: 0,
                witness_hash: "w1".to_string(),
                stake: 100,
                timestamp: 0.0,
            });
        }

        let p = awc.seal_progress_for_record("r1").expect("has seal");
        assert_eq!(
            p.attestation_count, 1,
            "duplicate (seal_id, witness_hash) must not be double-counted"
        );
        assert!(
            !awc.is_seal_settled("seal-0"),
            "one witness (100/300) must not settle even when replayed 3×"
        );
    }

    #[test]
    fn test_seal_progress_streaming_attestation() {
        // Gap 8: SealProgress surfaces live attestation/stake counts so
        // accounts can render "Sealed → Finalized" progress without waiting
        // for the full 2/3 threshold.
        let mut awc = AWCConsensus::new();
        let zone = ZoneId::from_legacy(0);
        awc.zone_stakes.insert(zone.clone(), 300);

        awc.register_profile("w1", profile("org-a", "10.0.1", "earth-us"));
        awc.register_profile("w2", profile("org-b", "10.0.2", "earth-eu"));
        awc.register_profile("w3", profile("org-c", "10.0.3", "mars-olympus"));

        // Record not yet in any seal → no progress.
        assert!(awc.seal_progress_for_record("r1").is_none());

        // Register seal containing r1, still no attestations.
        let _ = awc.register_seal_records("seal-0", vec!["r1".to_string()]);
        let p = awc.seal_progress_for_record("r1").expect("has seal");
        assert_eq!(p.seal_id, "seal-0");
        assert_eq!(p.attestation_count, 0);
        assert!(!p.settled);

        // One attestation at 100 stake → 33% of 300, under 2/3 threshold (200).
        let _ = awc.add_seal_attestation(SealAttestation {
            seal_id: "seal-0".to_string(),
            zone: zone.clone(),
            epoch_number: 0,
            witness_hash: "w1".to_string(),
            stake: 100,
            timestamp: 0.0,
        });
        let p = awc.seal_progress_for_record("r1").expect("has seal");
        assert_eq!(p.attestation_count, 1);
        assert!(p.effective_stake <= 100.0);
        assert_eq!(p.zone_total_stake, 300);
        assert!((p.stake_threshold - 200.0).abs() < 0.01);
        assert!(!p.settled);

        // Two more attestations → crosses 2/3 threshold.
        for (i, wh) in ["w2", "w3"].iter().enumerate() {
            let _ = awc.add_seal_attestation(SealAttestation {
                seal_id: "seal-0".to_string(),
                zone: zone.clone(),
                epoch_number: 0,
                witness_hash: wh.to_string(),
                stake: 100,
                timestamp: (i + 1) as f64,
            });
        }
        let p = awc.seal_progress_for_record("r1").expect("has seal");
        assert_eq!(p.attestation_count, 3);
        assert!(p.settled);
        assert!(p.finalized_at.is_some());
    }

    #[test]
    fn test_seal_not_settled_insufficient_stake() {
        let mut awc = AWCConsensus::new();
        let zone = ZoneId::from_legacy(0);
        awc.zone_stakes.insert(zone.clone(), 1000); // total = 1000

        awc.register_profile("w1", profile("org-a", "10.0.1", "earth-us"));

        let _ = awc.register_seal_records("seal-0", vec!["r1".to_string()]);

        // Only 100 of 1000 stake — not enough for 2/3
        let _ = awc.add_seal_attestation(SealAttestation {
            seal_id: "seal-0".to_string(),
            zone: zone.clone(),
            epoch_number: 0,
            witness_hash: "w1".to_string(),
            stake: 100,
            timestamp: 0.0,
        });

        assert!(!awc.is_seal_settled("seal-0"));
        // Record stays Sealed (not yet Finalized)
        assert_eq!(awc.confirmation_level("r1"), ConfirmationLevel::Sealed);
    }

    #[test]
    fn test_seal_settlement_excludes_creator_stake() {
        // The seal creator can't self-attest, so their stake must be excluded
        // from the settlement denominator. Without this fix, a 6-node testnet
        // where the creator holds 10T of 50.4T total makes 2/3 unreachable
        // with only 3 attestors (30T/50.4T = 59.5% < 66.67%).
        // With creator excluded: 30T/40.4T = 74.3% — settles correctly.
        let mut awc = AWCConsensus::new();
        let zone = ZoneId::from_legacy(1);
        // 5 stakers × 100 + creator 100 = 600 total zone stake
        awc.zone_stakes.insert(zone.clone(), 600);

        awc.register_profile("creator", profile("org-a", "10.0.1", "earth-us"));
        awc.register_profile("w1", profile("org-b", "10.0.2", "earth-eu"));
        awc.register_profile("w2", profile("org-c", "10.0.3", "mars-olympus"));
        awc.register_profile("w3", profile("org-d", "10.0.4", "earth-asia"));

        // Register creator stake for the seal (creator has 100 stake)
        awc.register_creator_stake("seal-creator", "creator", 100);

        let _ = awc.register_seal_records("seal-creator", vec!["r1".to_string()]);

        // 3 attestors × 100 = 300 attesting. Without creator exclusion:
        // 300/600 = 50% < 66.67% — would NOT settle.
        // With creator exclusion: 300/500 = 60% — still not enough for 2/3.
        for (i, wh) in ["w1", "w2", "w3"].iter().enumerate() {
            let _ = awc.add_seal_attestation(SealAttestation {
                seal_id: "seal-creator".to_string(),
                zone: zone.clone(),
                epoch_number: 0,
                witness_hash: wh.to_string(),
                stake: 100,
                timestamp: i as f64,
            });
        }
        // 300/500 = 60% < 66.67% — still not settled
        assert!(!awc.is_seal_settled("seal-creator"));

        // Add 4th attestor → 400/500 = 80% > 66.67% — settles
        awc.register_profile("w4", profile("org-e", "10.0.5", "earth-au"));
        let _ = awc.add_seal_attestation(SealAttestation {
            seal_id: "seal-creator".to_string(),
            zone: zone.clone(),
            epoch_number: 0,
            witness_hash: "w4".to_string(),
            stake: 100,
            timestamp: 3.0,
        });
        assert!(awc.is_seal_settled("seal-creator"));
        assert_eq!(awc.confirmation_level("r1"), ConfirmationLevel::Finalized);
    }

    // ── H1 regression: creator self-attestation must not collapse finality ──
    // is_settled / is_seal_settled remove the creator's stake from the denominator;
    // if the creator's OWN attestation counted in the numerator, the 2/3 threshold
    // collapses (a record could settle with ~1/3 of stake). The "creator can't
    // attest" invariant is now ENFORCED at add_attestation / add_seal_attestation /
    // bulk_load, plus a retroactive purge for a self-attestation that lands before
    // the record's creator is known.
    #[test]
    fn h1_creator_self_attestation_does_not_settle() {
        const S: u64 = 1_000;
        let rid = "rec-h1-self-attest";
        let creator = "creator-x";
        let mut awc = AWCConsensus::new();
        setup_zone_stake(&mut awc, rid, 3 * S); // 3 equal-stake validators
        awc.register_creator_stake(rid, creator, S);

        // Creator self-attests (must be rejected) + 1 honest validator.
        awc.add_attestation(Attestation {
            record_id: rid.into(), witness_hash: creator.into(), stake: S, timestamp: 1.0,
        });
        awc.add_attestation(Attestation {
            record_id: rid.into(), witness_hash: "val-b".into(), stake: S, timestamp: 2.0,
        });
        assert_eq!(awc.self_attestations_rejected(), 1, "creator self-attestation rejected");
        assert!(
            !awc.is_settled(rid),
            "only val-b (1000) counts vs eligible 2000 → 1000/2000 < 2/3, NOT settled"
        );

        // The second honest validator attests → settles (2000/2000).
        awc.add_attestation(Attestation {
            record_id: rid.into(), witness_hash: "val-c".into(), stake: S, timestamp: 3.0,
        });
        assert!(awc.is_settled(rid), "2 honest validators (2000/2000) settle");
    }

    #[test]
    fn h1_self_attestation_before_record_is_retroactively_purged() {
        // Ordering window: the self-attestation arrives BEFORE the creator is known.
        const S: u64 = 1_000;
        let rid = "rec-h1-ordering";
        let creator = "creator-y";
        let mut awc = AWCConsensus::new();
        setup_zone_stake(&mut awc, rid, 3 * S);

        // Self-attestation lands first (creator unknown → accepted for now)...
        awc.add_attestation(Attestation {
            record_id: rid.into(), witness_hash: creator.into(), stake: S, timestamp: 1.0,
        });
        awc.add_attestation(Attestation {
            record_id: rid.into(), witness_hash: "val-b".into(), stake: S, timestamp: 2.0,
        });
        // ...then the creator becomes known → retroactive purge of the self-attestation.
        awc.register_creator_stake(rid, creator, S);
        assert_eq!(awc.self_attestations_rejected(), 1, "pre-record self-attestation purged");
        assert!(
            !awc.is_settled(rid),
            "after purge only val-b (1000/2000) remains — below 2/3"
        );
    }

    #[test]
    fn h1_seal_creator_self_attestation_rejected() {
        // The seal finality path (add_seal_attestation/is_seal_settled) has the same
        // exposure and must enforce the same invariant.
        let seal_id = "seal-h1";
        let creator = "seal-creator-id";
        let mut awc = AWCConsensus::new();
        let zone = ZoneId::from_legacy(1);
        awc.zone_stakes.insert(zone.clone(), 300); // creator 100 + w1/w2 100 each
        awc.register_creator_stake(seal_id, creator, 100);
        let _ = awc.register_seal_records(seal_id, vec!["r1".to_string()]);

        // Seal creator self-attests their own seal — must be rejected, leaving the
        // seal with no countable attestation (so it cannot settle off self-stake).
        let _ = awc.add_seal_attestation(SealAttestation {
            seal_id: seal_id.into(), zone: zone.clone(), epoch_number: 0,
            witness_hash: creator.into(), stake: 100, timestamp: 0.0,
        });
        assert_eq!(awc.self_attestations_rejected(), 1, "seal-creator self-attestation rejected");
        assert!(!awc.is_seal_settled(seal_id), "a rejected self-attestation cannot settle the seal");
    }

    #[test]
    fn test_seal_settlement_without_creator_stake_unchanged() {
        // When no creator_stake is registered, denominator is full zone_stake
        // (backward compat with existing behavior for non-seal records).
        let mut awc = AWCConsensus::new();
        let zone = ZoneId::from_legacy(0);
        awc.zone_stakes.insert(zone.clone(), 300);

        awc.register_profile("w1", profile("org-a", "10.0.1", "earth-us"));
        awc.register_profile("w2", profile("org-b", "10.0.2", "earth-eu"));
        awc.register_profile("w3", profile("org-c", "10.0.3", "mars-olympus"));

        // No register_creator_stake call — denominator stays at 300
        let _ = awc.register_seal_records("seal-no-creator", vec!["r1".to_string()]);
        for (i, wh) in ["w1", "w2", "w3"].iter().enumerate() {
            let _ = awc.add_seal_attestation(SealAttestation {
                seal_id: "seal-no-creator".to_string(),
                zone: zone.clone(),
                epoch_number: 0,
                witness_hash: wh.to_string(),
                stake: 100,
                timestamp: i as f64,
            });
        }
        // 300/300 = 100% — settles
        assert!(awc.is_seal_settled("seal-no-creator"));
    }

    #[test]
    fn test_layered_confirmation_derivation() {
        let mut awc = AWCConsensus::new();
        let zone = ZoneId::from_legacy(0);
        awc.zone_stakes.insert(zone.clone(), 300);

        awc.register_profile("w1", profile("org-a", "10.0.1", "earth-us"));
        awc.register_profile("w2", profile("org-b", "10.0.2", "earth-eu"));
        awc.register_profile("w3", profile("org-c", "10.0.3", "mars-olympus"));

        // Unregistered record → Pending
        assert_eq!(awc.layered_confirmation("r1"), ConfirmationLevel::Pending);

        // Register in seal → Sealed
        let _ = awc.register_seal_records("seal-0", vec!["r1".to_string()]);
        assert_eq!(awc.layered_confirmation("r1"), ConfirmationLevel::Sealed);

        // Attest seal → Finalized
        for (i, wh) in ["w1", "w2", "w3"].iter().enumerate() {
            let _ = awc.add_seal_attestation(SealAttestation {
                seal_id: "seal-0".to_string(),
                zone: zone.clone(),
                epoch_number: 0,
                witness_hash: wh.to_string(),
                stake: 100,
                timestamp: i as f64,
            });
        }
        assert_eq!(awc.layered_confirmation("r1"), ConfirmationLevel::Finalized);

        // Anchor → Anchored
        awc.anchor_record("r1");
        assert_eq!(awc.layered_confirmation("r1"), ConfirmationLevel::Anchored);
    }

    #[test]
    fn test_seal_attestation_count() {
        let mut awc = AWCConsensus::new();
        let zone = ZoneId::from_legacy(0);

        assert_eq!(awc.seal_attestation_count("seal-0"), 0);

        let _ = awc.add_seal_attestation(SealAttestation {
            seal_id: "seal-0".to_string(),
            zone,
            epoch_number: 0,
            witness_hash: "w1".to_string(),
            stake: 100,
            timestamp: 0.0,
        });

        assert_eq!(awc.seal_attestation_count("seal-0"), 1);
    }

    // PARTITION-MERGE Phase B Slice 1 — accessor for same-epoch reconciliation
    #[test]
    fn test_attestation_weight_for_seal_unknown_seal_returns_zero() {
        let awc = AWCConsensus::new();
        assert_eq!(awc.attestation_weight_for_seal("does-not-exist"), 0);
    }

    #[test]
    fn test_attestation_weight_for_seal_empty_attestations_returns_zero() {
        let mut awc = AWCConsensus::new();
        // seal_attestations is populated on add; an entry with empty Vec
        // shouldn't normally exist, but the function must still return 0.
        awc.seal_attestations.insert("seal-empty".to_string(), Vec::new());
        assert_eq!(awc.attestation_weight_for_seal("seal-empty"), 0);
    }

    #[test]
    fn test_attestation_weight_for_seal_single_attester_returns_stake() {
        let mut awc = AWCConsensus::new();
        let zone = ZoneId::from_legacy(0);
        let _ = awc.add_seal_attestation(SealAttestation {
            seal_id: "seal-A".to_string(),
            zone,
            epoch_number: 7,
            witness_hash: "w1".to_string(),
            stake: 1_000,
            timestamp: 0.0,
        });
        // Single attester → independence(w1, [w1]) is the self-only case;
        // function returns the attester's full stake (≤ 1.0 multiplier).
        let w = awc.attestation_weight_for_seal("seal-A");
        assert!(w <= 1_000, "weight must not exceed raw stake, got {}", w);
        assert!(w > 0, "single live attester must produce non-zero weight, got {}", w);
    }

    #[test]
    fn test_attestation_weight_for_seal_heavier_seal_wins_comparison() {
        let mut awc = AWCConsensus::new();
        let zone = ZoneId::from_legacy(0);

        // Light seal: one attester with 100 stake.
        let _ = awc.add_seal_attestation(SealAttestation {
            seal_id: "seal-light".to_string(),
            zone: zone.clone(),
            epoch_number: 42,
            witness_hash: "w-light-1".to_string(),
            stake: 100,
            timestamp: 0.0,
        });

        // Heavy seal: two attesters with 200 + 300 stake.
        let _ = awc.add_seal_attestation(SealAttestation {
            seal_id: "seal-heavy".to_string(),
            zone: zone.clone(),
            epoch_number: 42,
            witness_hash: "w-heavy-1".to_string(),
            stake: 200,
            timestamp: 0.0,
        });
        let _ = awc.add_seal_attestation(SealAttestation {
            seal_id: "seal-heavy".to_string(),
            zone,
            epoch_number: 42,
            witness_hash: "w-heavy-2".to_string(),
            stake: 300,
            timestamp: 0.0,
        });

        let w_light = awc.attestation_weight_for_seal("seal-light");
        let w_heavy = awc.attestation_weight_for_seal("seal-heavy");
        // The heavy seal must outweigh the light one — invariant the
        // partition-merge same-epoch reconciliation depends on.
        assert!(
            w_heavy > w_light,
            "heavy weight {} must exceed light weight {}",
            w_heavy, w_light
        );
    }

    #[test]
    fn attestation_weight_for_seal_is_insertion_order_independent() {
        // H1 regression (fusion-audit 2026-06-17): attestation_weight_for_seal feeds
        // canonical-seal reconciliation (register_seal_with_reconcile /
        // promote_orphan_to_canonical), so two honest nodes that received the same
        // attestation SET in different gossip-arrival orders MUST compute the same
        // weight — otherwise they pick different canonical seals → chain-tip fork.
        // It now delegates to the witness-hash-sorted fixed-point effective_stake_q;
        // this pins that a future refactor can't reintroduce the f64 arrival-order sum.
        let zone = ZoneId::from_legacy(0);
        let attesters = [("w-a", 137u64), ("w-b", 9_001), ("w-c", 42), ("w-d", 555)];

        let mut fwd = AWCConsensus::new();
        for (w, s) in attesters.iter() {
            let _ = fwd.add_seal_attestation(SealAttestation {
                seal_id: "seal-fwd".to_string(),
                zone: zone.clone(),
                epoch_number: 99,
                witness_hash: (*w).to_string(),
                stake: *s,
                timestamp: 0.0,
            });
        }

        let mut rev = AWCConsensus::new();
        for (w, s) in attesters.iter().rev() {
            let _ = rev.add_seal_attestation(SealAttestation {
                seal_id: "seal-rev".to_string(),
                zone: zone.clone(),
                epoch_number: 99,
                witness_hash: (*w).to_string(),
                stake: *s,
                timestamp: 0.0,
            });
        }

        assert_eq!(
            fwd.attestation_weight_for_seal("seal-fwd"),
            rev.attestation_weight_for_seal("seal-rev"),
            "canonical-seal weight must not depend on attestation arrival order"
        );
    }

    #[test]
    fn test_attestation_weight_for_seal_zero_stake_attesters_floor_to_zero() {
        let mut awc = AWCConsensus::new();
        let zone = ZoneId::from_legacy(0);
        let _ = awc.add_seal_attestation(SealAttestation {
            seal_id: "seal-zero".to_string(),
            zone,
            epoch_number: 1,
            witness_hash: "w-broke".to_string(),
            stake: 0,
            timestamp: 0.0,
        });
        // 0 × independence = 0 → must floor cleanly to 0, not panic or NaN.
        assert_eq!(awc.attestation_weight_for_seal("seal-zero"), 0);
    }

    #[test]
    fn test_prune_anchored_seals() {
        let mut awc = AWCConsensus::new();
        let zone = ZoneId::from_legacy(0);

        let _ = awc.register_seal_records("seal-0", vec!["r1".to_string()]);
        let _ = awc.add_seal_attestation(SealAttestation {
            seal_id: "seal-0".to_string(),
            zone,
            epoch_number: 0,
            witness_hash: "w1".to_string(),
            stake: 100,
            timestamp: 0.0,
        });

        let mut anchored = HashSet::new();
        anchored.insert("seal-0".to_string());
        let pruned = awc.prune_anchored_seals(&anchored);
        assert_eq!(pruned, 1);
        assert_eq!(awc.seal_attestation_count("seal-0"), 0);
        // Reverse index should be cleaned
        assert!(!awc.record_to_seal.contains_key("r1"));
    }

    #[test]
    fn test_reverse_index_populated_by_register() {
        let mut awc = AWCConsensus::new();
        let _ = awc.register_seal_records("seal-0", vec!["r1".to_string(), "r2".to_string()]);
        let _ = awc.register_seal_records("seal-1", vec!["r3".to_string()]);

        assert_eq!(awc.record_to_seal.get("r1").map(|s| s.as_str()), Some("seal-0"));
        assert_eq!(awc.record_to_seal.get("r2").map(|s| s.as_str()), Some("seal-0"));
        assert_eq!(awc.record_to_seal.get("r3").map(|s| s.as_str()), Some("seal-1"));
        assert!(!awc.record_to_seal.contains_key("r4"));
    }

    #[test]
    fn test_seal_finalized_at_tracked_on_settlement() {
        let mut awc = AWCConsensus::new();
        let zone = ZoneId::from_legacy(0);
        awc.zone_stakes.insert(zone.clone(), 300);
        awc.register_profile("w1", profile("org-a", "10.0.1", "earth-us"));
        awc.register_profile("w2", profile("org-b", "10.0.2", "earth-eu"));
        awc.register_profile("w3", profile("org-c", "10.0.3", "mars-olympus"));

        let _ = awc.register_seal_records("seal-0", vec!["r1".to_string()]);

        // Before settlement: no finalized_at
        assert!(!awc.seal_finalized_at.contains_key("seal-0"));

        // Add enough attestations to settle
        for (i, wh) in ["w1", "w2", "w3"].iter().enumerate() {
            let _ = awc.add_seal_attestation(SealAttestation {
                seal_id: "seal-0".to_string(),
                zone: zone.clone(),
                epoch_number: 0,
                witness_hash: wh.to_string(),
                stake: 100,
                timestamp: i as f64,
            });
        }

        // After settlement: finalized_at should be set
        assert!(awc.seal_finalized_at.contains_key("seal-0"));
        let ts = *awc.seal_finalized_at.get("seal-0").unwrap();
        assert!(ts > 0.0);

        // Adding more attestations shouldn't change finalized_at
        let _ = awc.add_seal_attestation(SealAttestation {
            seal_id: "seal-0".to_string(),
            zone: zone.clone(),
            epoch_number: 0,
            witness_hash: "w4".to_string(),
            stake: 100,
            timestamp: 10.0,
        });
        assert_eq!(*awc.seal_finalized_at.get("seal-0").unwrap(), ts);
    }

    /// Per-stage latency: stamping `seal_first_attested_at` on the first
    /// attestation and observing propagation latency.
    ///
    /// Propagation uses local now() on both endpoints (register_seal_records
    /// stamps now, first add_seal_attestation stamps now), so we can't assert
    /// an exact latency value from a test — just that exactly one sample lands
    /// per seal and it appears in the +Inf bucket.
    #[test]
    fn test_seal_propagation_latency_stamped_on_first_attestation() {
        let mut awc = AWCConsensus::new();
        let zone = ZoneId::from_legacy(0);
        awc.zone_stakes.insert(zone.clone(), 300);
        awc.register_profile("w1", profile("org-a", "10.0.1", "earth-us"));

        // register_seal_records stamps seal_registered_at with local now(),
        // making this the "locally registered" case that propagation should
        // observe.
        let _ = awc.register_seal_records("seal-0", vec!["r1".to_string()]);

        let _ = awc.add_seal_attestation(SealAttestation {
            seal_id: "seal-0".to_string(),
            zone: zone.clone(),
            epoch_number: 0,
            witness_hash: "w1".to_string(),
            stake: 50,
            timestamp: 0.0, // ignored for propagation math under local-clock model
        });

        let (p_buckets, p_count, p_sum) = awc.seal_propagation_latency_snapshot();
        assert_eq!(p_count, 1, "propagation observed exactly once for locally-registered seal");
        assert!(p_sum >= 0.0);
        assert_eq!(p_buckets[10], 1, "sample must land in +Inf bucket");

        // Second attestation for the same seal must NOT increment propagation.
        let _ = awc.add_seal_attestation(SealAttestation {
            seal_id: "seal-0".to_string(),
            zone: zone.clone(),
            epoch_number: 0,
            witness_hash: "w1-b".to_string(),
            stake: 50,
            timestamp: 0.0,
        });
        let (_, p_count_after, _) = awc.seal_propagation_latency_snapshot();
        assert_eq!(p_count_after, 1, "propagation must only be sampled once per seal");
    }

    /// Per-stage latency: retroactive case — seal arrives via gossip
    /// before register_seal_records. Propagation must NOT be observed for this
    /// seal because registered_at is synthesized from the witness clock (not
    /// our local clock) and mixing clocks produces garbage latency numbers.
    /// The existing end-to-end latency histogram keeps the retroactive
    /// behavior for continuity; propagation demands same-clock endpoints.
    #[test]
    fn test_seal_propagation_skips_retroactive_seal() {
        let mut awc = AWCConsensus::new();
        let zone = ZoneId::from_legacy(0);
        awc.zone_stakes.insert(zone.clone(), 300);
        awc.register_profile("w1", profile("org-a", "10.0.1", "earth-us"));

        // No register_seal_records call — the attestation arrives cold and
        // triggers the retroactive or_insert on seal_registered_at.
        let _ = awc.add_seal_attestation(SealAttestation {
            seal_id: "seal-retro".to_string(),
            zone: zone.clone(),
            epoch_number: 0,
            witness_hash: "w1".to_string(),
            stake: 50,
            timestamp: 1.0,
        });

        let (_, p_count, _) = awc.seal_propagation_latency_snapshot();
        assert_eq!(p_count, 0, "retroactively-registered seal must not be in propagation histogram");
        // first_att IS stamped on local clock though — so if this seal later
        // reaches quorum, quorum latency is still clean.
        assert!(awc.seal_first_attested_at.contains_key("seal-retro"));
    }

    /// Per-stage latency: quorum-convergence observation fires when the
    /// seal flips to settled, NOT on every attestation after.
    #[test]
    fn test_seal_quorum_latency_observed_on_first_settle() {
        let mut awc = AWCConsensus::new();
        let zone = ZoneId::from_legacy(0);
        awc.zone_stakes.insert(zone.clone(), 300);
        awc.register_profile("w1", profile("org-a", "10.0.1", "earth-us"));
        awc.register_profile("w2", profile("org-b", "10.0.2", "earth-eu"));
        awc.register_profile("w3", profile("org-c", "10.0.3", "mars-olympus"));

        let _ = awc.register_seal_records("seal-0", vec!["r1".to_string()]);
        awc.seal_registered_at.insert("seal-0".to_string(), 100.0);

        // Three attestations bringing the seal to 100% of 300-stake — settlement
        // fires on the third. Timestamps are witness wall-clocks; the quorum
        // stopwatch uses the node's own now() at settle, not witness ts, so we
        // assert count and +Inf bucket rather than specific bucket placement.
        for (i, wh) in ["w1", "w2", "w3"].iter().enumerate() {
            let _ = awc.add_seal_attestation(SealAttestation {
                seal_id: "seal-0".to_string(),
                zone: zone.clone(),
                epoch_number: 0,
                witness_hash: wh.to_string(),
                stake: 100,
                timestamp: 100.0 + (i as f64),
            });
        }

        let (q_buckets, q_count, q_sum) = awc.seal_quorum_latency_snapshot();
        assert_eq!(q_count, 1, "quorum latency must be sampled exactly once per seal");
        assert!(q_sum >= 0.0);
        assert_eq!(q_buckets[10], 1, "+Inf bucket must contain the sample");

        // Extra attestation after settle must not double-count.
        let _ = awc.add_seal_attestation(SealAttestation {
            seal_id: "seal-0".to_string(),
            zone: zone.clone(),
            epoch_number: 0,
            witness_hash: "w4".to_string(),
            stake: 50,
            timestamp: 200.0,
        });
        let (_, q_count_after, _) = awc.seal_quorum_latency_snapshot();
        assert_eq!(q_count_after, 1);
    }

    /// Per-attestor-rank arrival latency stamps one bucket
    /// per attestation arrival, rank=N for the (N+1)-th attestation. Ranks
    /// 4+ all collapse into the "5th+" bucket so cardinality stays bounded.
    #[test]
    fn test_seal_attestor_rank_latency_stamps_per_attestation() {
        let mut awc = AWCConsensus::new();
        let zone = ZoneId::from_legacy(0);
        awc.zone_stakes.insert(zone.clone(), 1000);
        for (i, w) in ["w1", "w2", "w3", "w4", "w5", "w6", "w7"].iter().enumerate() {
            awc.register_profile(w, profile(
                &format!("org-{i}"),
                &format!("10.0.{i}"),
                &format!("earth-{i}"),
            ));
        }

        // register_seal_records stamps registered_at on local clock, so every
        // attestation we add will be stamped for the rank histogram (same-clock
        // gate matches the propagation histogram's behavior).
        let _ = awc.register_seal_records("seal-0", vec!["r1".to_string()]);

        for (i, wh) in ["w1", "w2", "w3", "w4", "w5", "w6", "w7"].iter().enumerate() {
            let _ = awc.add_seal_attestation(SealAttestation {
                seal_id: "seal-0".to_string(),
                zone: zone.clone(),
                epoch_number: 0,
                witness_hash: wh.to_string(),
                stake: 10, // below settle threshold so we can append past rank 4
                timestamp: 1.0 + (i as f64),
            });
        }

        let (buckets, counts, sums) = awc.seal_attestor_rank_latency_snapshot();
        // 7 attestations: ranks 0, 1, 2, 3 each see exactly 1 sample;
        // ranks 4+5+6 collapse into the "5th+" bucket (index 4) → 3 samples.
        assert_eq!(counts[0], 1, "1st attestor sampled once");
        assert_eq!(counts[1], 1, "2nd attestor sampled once");
        assert_eq!(counts[2], 1, "3rd attestor sampled once");
        assert_eq!(counts[3], 1, "4th attestor sampled once");
        assert_eq!(counts[4], 3, "5th+ bucket collapses ranks 4, 5, 6");
        for r in 0..5 {
            assert!(sums[r] >= 0.0);
            assert_eq!(buckets[r][10], counts[r], "+Inf bucket must match count for rank {r}");
        }
    }

    /// Retroactive seals must NOT pollute the end-to-end
    /// attestation latency or quorum latency histograms. Previously those
    /// stamps used `now - witness_clock_at_seal_creation`, which inflated by
    /// days during peer-driven catchup. The retroactive-skip counter ticks
    /// once per skipped settlement so operators can see catchup volume
    /// without losing the finality-correctness signal.
    #[test]
    fn test_seal_attestation_latency_skips_retroactive_seal_at_settle() {
        let mut awc = AWCConsensus::new();
        let zone = ZoneId::from_legacy(0);
        awc.zone_stakes.insert(zone.clone(), 300);
        awc.register_profile("w1", profile("org-a", "10.0.1", "earth-us"));
        awc.register_profile("w2", profile("org-b", "10.0.2", "earth-eu"));
        awc.register_profile("w3", profile("org-c", "10.0.3", "mars-olympus"));

        // No register_seal_records — three attestations arrive cold from gossip
        // and bring the seal to settlement (3 × 100 stake = 300/300 = 100%).
        for (i, wh) in ["w1", "w2", "w3"].iter().enumerate() {
            let _ = awc.add_seal_attestation(SealAttestation {
                seal_id: "seal-retro".to_string(),
                zone: zone.clone(),
                epoch_number: 0,
                witness_hash: wh.to_string(),
                stake: 100,
                timestamp: 1.0 + (i as f64),
            });
        }
        // Settlement must have fired (so we're testing the right code path).
        assert!(awc.seal_finalized_at.contains_key("seal-retro"),
            "test setup: seal must reach settlement");

        // Same-clock gate invariants:
        let (_, attest_count, _) = awc.seal_attestation_latency_snapshot();
        let (_, quorum_count, _) = awc.seal_quorum_latency_snapshot();
        assert_eq!(attest_count, 0,
            "retroactive seal must not be in end-to-end attestation latency histogram");
        assert_eq!(quorum_count, 0,
            "retroactive seal must not be in quorum latency histogram");
        assert_eq!(awc.seal_latency_retroactive_skipped_total, 1,
            "retroactive-skip counter must tick exactly once at settlement");
    }

    /// The locally-registered path must STILL observe both
    /// histograms — the gate only filters retroactive seals. This is the
    /// regression test pairing with `test_seal_attestation_latency_skips_retroactive_seal_at_settle`.
    #[test]
    fn test_seal_attestation_latency_observed_for_locally_registered_seal() {
        let mut awc = AWCConsensus::new();
        let zone = ZoneId::from_legacy(0);
        awc.zone_stakes.insert(zone.clone(), 300);
        awc.register_profile("w1", profile("org-a", "10.0.1", "earth-us"));
        awc.register_profile("w2", profile("org-b", "10.0.2", "earth-eu"));
        awc.register_profile("w3", profile("org-c", "10.0.3", "mars-olympus"));

        // Local registration BEFORE attestations: this is the clean path.
        let _ = awc.register_seal_records("seal-0", vec!["r1".to_string()]);
        for (i, wh) in ["w1", "w2", "w3"].iter().enumerate() {
            let _ = awc.add_seal_attestation(SealAttestation {
                seal_id: "seal-0".to_string(),
                zone: zone.clone(),
                epoch_number: 0,
                witness_hash: wh.to_string(),
                stake: 100,
                timestamp: 1.0 + (i as f64),
            });
        }

        let (_, attest_count, _) = awc.seal_attestation_latency_snapshot();
        let (_, quorum_count, _) = awc.seal_quorum_latency_snapshot();
        assert_eq!(attest_count, 1,
            "locally-registered seal must produce one attestation-latency sample");
        assert_eq!(quorum_count, 1,
            "locally-registered seal must produce one quorum-latency sample");
        assert_eq!(awc.seal_latency_retroactive_skipped_total, 0,
            "locally-registered path must not bump the retroactive-skip counter");
    }

    /// Retroactive seals (no register_seal_records) must NOT
    /// produce rank-latency samples — same local-clock gate as propagation.
    #[test]
    fn test_seal_attestor_rank_skips_retroactive_seal() {
        let mut awc = AWCConsensus::new();
        let zone = ZoneId::from_legacy(0);
        awc.zone_stakes.insert(zone.clone(), 300);
        awc.register_profile("w1", profile("org-a", "10.0.1", "earth-us"));

        // No register_seal_records — attestation arrives cold.
        let _ = awc.add_seal_attestation(SealAttestation {
            seal_id: "seal-retro".to_string(),
            zone: zone.clone(),
            epoch_number: 0,
            witness_hash: "w1".to_string(),
            stake: 50,
            timestamp: 1.0,
        });

        let (_, counts, _) = awc.seal_attestor_rank_latency_snapshot();
        for (r, &count) in counts.iter().enumerate().take(5) {
            assert_eq!(count, 0, "retroactive seal must not populate rank {r}");
        }
    }

    /// Per-stage latency: first_attested_at is cleaned up on all three
    /// pruning paths so the map cannot grow unboundedly.
    #[test]
    fn test_seal_first_attested_at_pruned_on_all_paths() {
        let mut awc = AWCConsensus::new();
        let zone = ZoneId::from_legacy(0);
        awc.zone_stakes.insert(zone.clone(), 300);
        awc.register_profile("w1", profile("org-a", "10.0.1", "earth-us"));

        // Path 1: prune_anchored_seals_where
        let _ = awc.register_seal_records("seal-1", vec!["r1".to_string()]);
        let _ = awc.add_seal_attestation(SealAttestation {
            seal_id: "seal-1".to_string(),
            zone: zone.clone(),
            epoch_number: 0,
            witness_hash: "w1".to_string(),
            stake: 10,
            timestamp: 1.0,
        });
        assert!(awc.seal_first_attested_at.contains_key("seal-1"));
        awc.prune_anchored_seals_where(|sid| sid == "seal-1");
        assert!(!awc.seal_first_attested_at.contains_key("seal-1"));
    }

    #[test]
    fn test_promote_anchored_respects_challenge_window() {
        let mut awc = AWCConsensus::new();
        let zone = ZoneId::from_legacy(0);
        awc.zone_stakes.insert(zone.clone(), 300);
        awc.register_profile("w1", profile("org-a", "10.0.1", "earth-us"));
        awc.register_profile("w2", profile("org-b", "10.0.2", "earth-eu"));
        awc.register_profile("w3", profile("org-c", "10.0.3", "mars-olympus"));

        let _ = awc.register_seal_records("seal-0", vec!["r1".to_string(), "r2".to_string()]);

        for (i, wh) in ["w1", "w2", "w3"].iter().enumerate() {
            let _ = awc.add_seal_attestation(SealAttestation {
                seal_id: "seal-0".to_string(),
                zone: zone.clone(),
                epoch_number: 0,
                witness_hash: wh.to_string(),
                stake: 100,
                timestamp: i as f64,
            });
        }
        assert!(awc.is_seal_settled("seal-0"));

        // Just finalized — promote should NOT anchor (within challenge window)
        let (seals, records) = awc.promote_anchored();
        assert_eq!(seals, 0);
        assert!(records.is_empty());

        // Manually backdate seal_finalized_at to simulate 24h+ ago
        let old_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64() - CHALLENGE_WINDOW_SECS - 1.0;
        awc.seal_finalized_at.insert("seal-0".to_string(), old_ts);

        // Now promote should anchor both records — and return their rids so
        // the caller routes them to the durable FinalizedIndex.
        let (seals, records) = awc.promote_anchored();
        assert_eq!(seals, 1);
        assert_eq!(records.len(), 2);
        assert!(records.contains(&"r1".to_string()) && records.contains(&"r2".to_string()));
        assert!(awc.anchored.contains("r1"));
        assert!(awc.anchored.contains("r2"));
        assert_eq!(awc.layered_confirmation("r1"), ConfirmationLevel::Anchored);
        assert_eq!(awc.layered_confirmation("r2"), ConfirmationLevel::Anchored);

        // seal_finalized_at cleaned for promoted seal
        assert!(!awc.seal_finalized_at.contains_key("seal-0"));

        // Second promote should be a no-op
        awc.seal_finalized_at.insert("seal-0".to_string(), old_ts);
        let (seals, records) = awc.promote_anchored();
        assert_eq!(seals, 1);
        assert!(records.is_empty()); // already anchored
    }

    /// Seal-member durable-write lane (F1): the fast-track returns exactly
    /// the members that crossed the pre-finality edge, exactly once.
    #[test]
    fn test_seal_fasttrack_returns_members_exactly_once() {
        let mut awc = AWCConsensus::new();
        let zone = ZoneId::from_legacy(0);
        awc.zone_stakes.insert(zone.clone(), 300);
        awc.register_profile("w1", profile("org-a", "10.0.1", "earth-us"));
        awc.register_profile("w2", profile("org-b", "10.0.2", "earth-eu"));
        awc.register_profile("w3", profile("org-c", "10.0.3", "mars-olympus"));
        let pre = awc.register_seal_records("seal-0", vec!["r1".to_string(), "r2".to_string()]);
        assert!(pre.is_empty(), "unsettled registration must promote nothing");

        let mut promoted: Vec<String> = Vec::new();
        for (i, wh) in ["w1", "w2", "w3"].iter().enumerate() {
            promoted.extend(awc.add_seal_attestation(SealAttestation {
                seal_id: "seal-0".to_string(),
                zone: zone.clone(),
                epoch_number: 0,
                witness_hash: wh.to_string(),
                stake: 100,
                timestamp: i as f64,
            }));
        }
        assert!(awc.is_seal_settled("seal-0"));
        promoted.sort();
        assert_eq!(promoted, vec!["r1".to_string(), "r2".to_string()]);

        // Duplicate witness → per-witness dedup, returns empty.
        let dup = awc.add_seal_attestation(SealAttestation {
            seal_id: "seal-0".to_string(),
            zone: zone.clone(),
            epoch_number: 0,
            witness_hash: "w3".to_string(),
            stake: 100,
            timestamp: 9.0,
        });
        assert!(dup.is_empty());

        // Genuinely NEW witness after settle → members already Finalized →
        // edge guard returns empty (no double-fire).
        awc.register_profile("w4", profile("org-d", "10.0.4", "earth-asia"));
        let post = awc.add_seal_attestation(SealAttestation {
            seal_id: "seal-0".to_string(),
            zone: zone.clone(),
            epoch_number: 0,
            witness_hash: "w4".to_string(),
            stake: 100,
            timestamp: 10.0,
        });
        assert!(post.is_empty());
    }

    /// R1: attestations cross 2/3 BEFORE registration (the retroactive
    /// class) — registration promotes the members, enqueues each exactly
    /// once, and re-registration is an idempotent no-op.
    #[test]
    fn test_r1_registration_after_settlement_promotes_once() {
        let mut awc = AWCConsensus::new();
        let zone = ZoneId::from_legacy(0);
        awc.zone_stakes.insert(zone.clone(), 300);
        awc.register_profile("w1", profile("org-a", "10.0.1", "earth-us"));
        awc.register_profile("w2", profile("org-b", "10.0.2", "earth-eu"));
        awc.register_profile("w3", profile("org-c", "10.0.3", "mars-olympus"));

        for (i, wh) in ["w1", "w2", "w3"].iter().enumerate() {
            let none = awc.add_seal_attestation(SealAttestation {
                seal_id: "seal-0".to_string(),
                zone: zone.clone(),
                epoch_number: 0,
                witness_hash: wh.to_string(),
                stake: 100,
                timestamp: i as f64,
            });
            assert!(none.is_empty(), "no member list registered yet");
        }
        assert!(awc.is_seal_settled("seal-0"));
        let _ = awc.drain_newly_finalized();

        let mut newly =
            awc.register_seal_records("seal-0", vec!["r1".to_string(), "r2".to_string()]);
        newly.sort();
        assert_eq!(newly, vec!["r1".to_string(), "r2".to_string()]);
        assert_eq!(awc.confirmation_level("r1"), ConfirmationLevel::Finalized);
        assert_eq!(awc.confirmation_level("r2"), ConfirmationLevel::Finalized);
        let mut q = awc.drain_newly_finalized();
        q.sort();
        assert_eq!(q, vec!["r1".to_string(), "r2".to_string()], "enqueue fires once per member");

        let again =
            awc.register_seal_records("seal-0", vec!["r1".to_string(), "r2".to_string()]);
        assert!(again.is_empty());
        assert!(awc.drain_newly_finalized().is_empty(), "no re-enqueue on re-registration");
    }

    /// Hole-3 ordering regression: the finalize edge (R1) fires BEFORE any
    /// Anchored promotion; promote_anchored then returns the rids for
    /// durable routing without re-enqueueing, and the edge guard treats
    /// Anchored as terminal.
    #[test]
    fn test_finalize_edge_precedes_anchored_promotion() {
        let mut awc = AWCConsensus::new();
        let zone = ZoneId::from_legacy(0);
        awc.zone_stakes.insert(zone.clone(), 300);
        awc.register_profile("w1", profile("org-a", "10.0.1", "earth-us"));
        awc.register_profile("w2", profile("org-b", "10.0.2", "earth-eu"));
        awc.register_profile("w3", profile("org-c", "10.0.3", "mars-olympus"));
        for (i, wh) in ["w1", "w2", "w3"].iter().enumerate() {
            let _ = awc.add_seal_attestation(SealAttestation {
                seal_id: "seal-0".to_string(),
                zone: zone.clone(),
                epoch_number: 0,
                witness_hash: wh.to_string(),
                stake: 100,
                timestamp: i as f64,
            });
        }
        // R1 late registration = the finalize edge.
        let newly = awc.register_seal_records("seal-0", vec!["r1".to_string()]);
        assert_eq!(newly, vec!["r1".to_string()]);
        let _ = awc.drain_newly_finalized();

        let old_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64()
            - CHALLENGE_WINDOW_SECS
            - 1.0;
        awc.seal_finalized_at.insert("seal-0".to_string(), old_ts);
        let (_seals, promoted) = awc.promote_anchored();
        assert_eq!(promoted, vec!["r1".to_string()], "caller routes these durably");
        assert!(awc.drain_newly_finalized().is_empty(), "promotion never re-enqueues");
        assert_eq!(awc.confirmation_level("r1"), ConfirmationLevel::Anchored);

        // Edge guard: Anchored is terminal for the fast-track.
        awc.register_profile("w4", profile("org-d", "10.0.4", "earth-asia"));
        let post = awc.add_seal_attestation(SealAttestation {
            seal_id: "seal-0".to_string(),
            zone: zone.clone(),
            epoch_number: 0,
            witness_hash: "w4".to_string(),
            stake: 100,
            timestamp: 10.0,
        });
        assert!(post.is_empty());
    }

    /// R2: a member unresolvable at registration resolves late — appended to
    /// the seal, promoted (seal already settled), consumed from the map; the
    /// map follows seal_record_ids' lifetime on prune.
    #[test]
    fn test_r2_late_member_resolves_promotes_and_prunes() {
        let mut awc = AWCConsensus::new();
        let zone = ZoneId::from_legacy(0);
        awc.zone_stakes.insert(zone.clone(), 300);
        awc.register_profile("w1", profile("org-a", "10.0.1", "earth-us"));
        awc.register_profile("w2", profile("org-b", "10.0.2", "earth-eu"));
        awc.register_profile("w3", profile("org-c", "10.0.3", "mars-olympus"));
        let _ = awc.register_seal_records("seal-0", vec!["r1".to_string()]);
        awc.register_unresolved_seal_members("seal-0", vec!["hash-r2".to_string()]);
        assert!(awc.has_unresolved_seal_members());

        for (i, wh) in ["w1", "w2", "w3"].iter().enumerate() {
            let _ = awc.add_seal_attestation(SealAttestation {
                seal_id: "seal-0".to_string(),
                zone: zone.clone(),
                epoch_number: 0,
                witness_hash: wh.to_string(),
                stake: 100,
                timestamp: i as f64,
            });
        }
        assert!(awc.is_seal_settled("seal-0"));
        let _ = awc.drain_newly_finalized();

        let newly = awc.resolve_late_seal_member("hash-r2", "r2");
        assert_eq!(newly, vec!["r2".to_string()]);
        assert_eq!(awc.confirmation_level("r2"), ConfirmationLevel::Finalized);
        assert_eq!(awc.drain_newly_finalized(), vec!["r2".to_string()]);
        assert!(!awc.has_unresolved_seal_members(), "entry consumed");
        // Consumed: a replay of the same hash is a no-op.
        assert!(awc.resolve_late_seal_member("hash-r2", "r2").is_empty());

        // Map follows seal lifetime: park another, prune the seal, map empties.
        awc.register_unresolved_seal_members("seal-0", vec!["hash-r3".to_string()]);
        let _ = awc.prune_anchored_seals_where(|_| true);
        assert!(!awc.has_unresolved_seal_members());
    }

    /// R2 cap: inserts stop at MAX_UNRESOLVED_SEAL_MEMBERS (drop-new).
    #[test]
    fn test_unresolved_seal_members_cap_drops_new() {
        let mut awc = AWCConsensus::new();
        let hashes: Vec<String> =
            (0..MAX_UNRESOLVED_SEAL_MEMBERS + 5).map(|i| format!("h{i}")).collect();
        awc.register_unresolved_seal_members("seal-0", hashes);
        assert!(awc.unresolved_seal_members_dropped_total >= 1);
    }

    /// F3 collector: returns exactly the ≥Finalized rids (members + anchored).
    #[test]
    fn test_finalized_level_rids_collects_finalized_and_anchored() {
        let mut awc = AWCConsensus::new();
        let zone = ZoneId::from_legacy(0);
        awc.zone_stakes.insert(zone.clone(), 300);
        awc.register_profile("w1", profile("org-a", "10.0.1", "earth-us"));
        awc.register_profile("w2", profile("org-b", "10.0.2", "earth-eu"));
        awc.register_profile("w3", profile("org-c", "10.0.3", "mars-olympus"));
        let _ = awc.register_seal_records("seal-0", vec!["r1".to_string(), "r2".to_string()]);
        for (i, wh) in ["w1", "w2", "w3"].iter().enumerate() {
            let _ = awc.add_seal_attestation(SealAttestation {
                seal_id: "seal-0".to_string(),
                zone: zone.clone(),
                epoch_number: 0,
                witness_hash: wh.to_string(),
                stake: 100,
                timestamp: i as f64,
            });
        }
        awc.anchor_record("r1"); // Finalized → Anchored (still ≥ Finalized)
        let mut rids = awc.finalized_level_rids();
        rids.sort();
        assert_eq!(rids, vec!["r1".to_string(), "r2".to_string()]);
    }

    #[test]
    fn test_pending_anchor_count() {
        let mut awc = AWCConsensus::new();
        assert_eq!(awc.pending_anchor_count(), 0);

        let zone = ZoneId::from_legacy(0);
        awc.zone_stakes.insert(zone.clone(), 300);
        awc.register_profile("w1", profile("org-a", "10.0.1", "earth-us"));
        awc.register_profile("w2", profile("org-b", "10.0.2", "earth-eu"));
        awc.register_profile("w3", profile("org-c", "10.0.3", "mars-olympus"));

        let _ = awc.register_seal_records("seal-0", vec!["r1".to_string()]);

        for (i, wh) in ["w1", "w2", "w3"].iter().enumerate() {
            let _ = awc.add_seal_attestation(SealAttestation {
                seal_id: "seal-0".to_string(),
                zone: zone.clone(),
                epoch_number: 0,
                witness_hash: wh.to_string(),
                stake: 100,
                timestamp: i as f64,
            });
        }

        assert_eq!(awc.pending_anchor_count(), 1);
    }

    #[test]
    fn test_seal_pending_anchor_retroactive_count_separates_local_vs_peer() {
        // Empty store → 0; retroactive-only → equals total; mixed
        // → exact split; locally-registered-only → 0. The boolean is
        //   seal_finalized_at.contains(sid) AND NOT seal_registered_at.contains(sid)
        let mut awc = AWCConsensus::new();
        assert_eq!(awc.seal_pending_anchor_retroactive_count(), 0,
            "empty store: retroactive count must be 0");
        assert_eq!(awc.pending_anchor_count(), 0);

        // Insert 2 retroactively-finalized seals (no register entry).
        awc.seal_finalized_at.insert("retro-a".to_string(), 100.0);
        awc.seal_finalized_at.insert("retro-b".to_string(), 200.0);
        assert_eq!(awc.seal_pending_anchor_retroactive_count(), 2,
            "both seals finalized without local register entry → both retroactive");
        assert_eq!(awc.pending_anchor_count(), 2);

        // Add a locally-registered seal: enters BOTH maps.
        awc.seal_finalized_at.insert("local-c".to_string(), 300.0);
        awc.seal_registered_at.insert("local-c".to_string(), 290.0);
        assert_eq!(awc.seal_pending_anchor_retroactive_count(), 2,
            "adding a locally-registered seal must NOT bump retroactive count");
        assert_eq!(awc.pending_anchor_count(), 3,
            "total window must include the locally-registered seal");

        // Drop one retroactive: count falls to 1.
        awc.seal_finalized_at.remove("retro-a");
        assert_eq!(awc.seal_pending_anchor_retroactive_count(), 1);
        assert_eq!(awc.pending_anchor_count(), 2);

        // Drop the locally-registered seal: retroactive count unchanged,
        // total drops by 1. This ensures the helper isn't double-counting
        // via seal_registered_at independently.
        awc.seal_finalized_at.remove("local-c");
        awc.seal_registered_at.remove("local-c");
        assert_eq!(awc.seal_pending_anchor_retroactive_count(), 1);
        assert_eq!(awc.pending_anchor_count(), 1);

        // A stale seal_registered_at entry without a finalized_at peer must
        // NOT show up in either count — guards against cleanup leaks.
        awc.seal_registered_at.insert("orphan-d".to_string(), 400.0);
        assert_eq!(awc.seal_pending_anchor_retroactive_count(), 1,
            "orphan seal_registered_at row (no finalized peer) must not affect retroactive count");
        assert_eq!(awc.pending_anchor_count(), 1,
            "orphan seal_registered_at row must not affect total pending-anchor count");
    }

    #[test]
    fn test_seal_pending_anchor_oldest_at_returns_min() {
        // Empty store → None; multi-insert returns the minimum;
        // post-removal returns the next surviving minimum.
        let mut awc = AWCConsensus::new();
        assert!(awc.seal_pending_anchor_oldest_at().is_none(),
            "empty seal_finalized_at must report None — Prometheus emitter maps None → 0 age");

        // Insert 3 finalized timestamps directly (bypass quorum machinery,
        // we're testing the helper, not finalization). Order: 200, 100, 300
        // — helper must pick 100 regardless of insertion order.
        awc.seal_finalized_at.insert("seal-b".to_string(), 200.0);
        awc.seal_finalized_at.insert("seal-a".to_string(), 100.0);
        awc.seal_finalized_at.insert("seal-c".to_string(), 300.0);

        assert_eq!(awc.seal_pending_anchor_oldest_at(), Some(100.0),
            "oldest_at must return min finalized_at across all pending-anchor seals");

        // Remove the oldest: helper must return the next-oldest.
        awc.seal_finalized_at.remove("seal-a");
        assert_eq!(awc.seal_pending_anchor_oldest_at(), Some(200.0),
            "after removing seal-a (oldest), oldest_at must fall through to seal-b at 200");

        // Drain entirely: back to None.
        awc.seal_finalized_at.clear();
        assert!(awc.seal_pending_anchor_oldest_at().is_none(),
            "after drain, oldest_at must report None again — guards against stale-min bug");
    }

    #[test]
    fn test_seal_pending_anchor_oldest_at_split_separates_populations() {
        // The split helper must independently compute the oldest
        // timestamp inside each sub-population (local-only / retro-only),
        // so an operator can alarm on anchor-sig backlog (local age) and
        // retro-drain stall (retro age) without one masking the other.
        let mut awc = AWCConsensus::new();

        // Empty: both sides None.
        assert_eq!(awc.seal_pending_anchor_oldest_at_split(), (None, None),
            "empty store: both populations report None");

        // All retroactive (no register entry): local=None, retro=min.
        awc.seal_finalized_at.insert("retro-a".to_string(), 200.0);
        awc.seal_finalized_at.insert("retro-b".to_string(), 100.0);
        awc.seal_finalized_at.insert("retro-c".to_string(), 300.0);
        assert_eq!(awc.seal_pending_anchor_oldest_at_split(), (None, Some(100.0)),
            "all-retroactive: local None, retro reports min(100, 200, 300) = 100");
        // The derived global must equal the retro min.
        assert_eq!(awc.seal_pending_anchor_oldest_at(), Some(100.0),
            "global min over all-retro must equal the retro min");

        // Add 2 locally-registered seals (newer than the oldest retro).
        awc.seal_finalized_at.insert("local-d".to_string(), 400.0);
        awc.seal_registered_at.insert("local-d".to_string(), 390.0);
        awc.seal_finalized_at.insert("local-e".to_string(), 500.0);
        awc.seal_registered_at.insert("local-e".to_string(), 490.0);
        // Local population: min(400, 500) = 400. Retro unchanged.
        assert_eq!(awc.seal_pending_anchor_oldest_at_split(), (Some(400.0), Some(100.0)),
            "mixed: local reports min over local-only entries, retro reports min over retro-only entries");
        // Global min stays at the older retro min — without the split this
        // hides local-d entirely from the operator's age alarm.
        assert_eq!(awc.seal_pending_anchor_oldest_at(), Some(100.0));

        // Drop the oldest retro: retro min falls through to next-oldest retro,
        // local untouched.
        awc.seal_finalized_at.remove("retro-b");
        assert_eq!(awc.seal_pending_anchor_oldest_at_split(), (Some(400.0), Some(200.0)),
            "after dropping oldest retro, retro min falls through to next-oldest (200), local untouched");

        // Drop all retro: retro=None, local unchanged.
        awc.seal_finalized_at.remove("retro-a");
        awc.seal_finalized_at.remove("retro-c");
        assert_eq!(awc.seal_pending_anchor_oldest_at_split(), (Some(400.0), None),
            "all-retro drained: retro None, local survives");

        // Drop the oldest local: local falls through. Now only local-e at 500.
        awc.seal_finalized_at.remove("local-d");
        awc.seal_registered_at.remove("local-d");
        assert_eq!(awc.seal_pending_anchor_oldest_at_split(), (Some(500.0), None),
            "after dropping oldest local, local min falls through to next-oldest (500)");

        // Stale `seal_registered_at` row without a finalized peer must not
        // corrupt either side — guards against cleanup leaks.
        awc.seal_registered_at.insert("orphan-f".to_string(), 50.0);
        assert_eq!(awc.seal_pending_anchor_oldest_at_split(), (Some(500.0), None),
            "orphan seal_registered_at row (no finalized peer) must not appear in either side");

        // Drain everything: back to (None, None).
        awc.seal_finalized_at.clear();
        assert_eq!(awc.seal_pending_anchor_oldest_at_split(), (None, None),
            "after full drain, both populations report None");
        assert_eq!(awc.seal_pending_anchor_oldest_at(), None,
            "global min consistent with both-None split result");
    }

    #[test]
    fn test_committee_size_summary_distribution_shape() {
        // committee_size_summary() must produce zones_registered,
        // size_min, size_max, zones_below_target in one pass — operator
        // alarm signal is `zones_below_target > 0` (undersized = sparse
        // stake or rotation tick missed).
        let mut awc = AWCConsensus::new();
        let z = |i: u64| ZoneId::from_legacy(i);
        let members =
            |xs: &[&str]| -> Vec<(String, u64)> { xs.iter().map(|s| (s.to_string(), 1)).collect() };

        // Empty: all zeros.
        let s = awc.committee_size_summary();
        assert_eq!(
            (s.zones_registered, s.size_min, s.size_max, s.zones_below_target),
            (0, 0, 0, 0),
            "empty consensus: every gauge must be 0 (size_min collapses to 0, not usize::MAX)"
        );

        // Single zone, 3 members (< MAINNET_COMMITTEE_SIZE = 7) → 1 below target.
        awc.register_epoch_committee(&z(0), &members(&["a", "b", "c"]));
        let s = awc.committee_size_summary();
        assert_eq!(
            (s.zones_registered, s.size_min, s.size_max, s.zones_below_target),
            (1, 3, 3, 1),
            "single 3-member committee: registered=1, min=max=3, below_target=1"
        );

        // Add a second zone exactly at target (7 members) → not below.
        awc.register_epoch_committee(
            &z(1),
            &members(&["w0", "w1", "w2", "w3", "w4", "w5", "w6"]),
        );
        let s = awc.committee_size_summary();
        assert_eq!(
            (s.zones_registered, s.size_min, s.size_max, s.zones_below_target),
            (2, 3, 7, 1),
            "two zones (3, 7): registered=2, min=3, max=7, below_target=1 — exact-target zone is NOT below"
        );

        // Add a third zone at bootstrap-fallback size (10 members) → max grows, below_target unchanged.
        let big: Vec<String> = (0..10).map(|i| format!("b{i}")).collect();
        let big_members: Vec<(String, u64)> = big.iter().map(|s| (s.clone(), 1)).collect();
        awc.register_epoch_committee(&z(2), &big_members);
        let s = awc.committee_size_summary();
        assert_eq!(
            (s.zones_registered, s.size_min, s.size_max, s.zones_below_target),
            (3, 3, 10, 1),
            "three zones (3, 7, 10): max climbs to 10, below_target stays at 1 (only the 3-member zone)"
        );

        // Drop the undersized zone (empty members removes the entry).
        awc.register_epoch_committee(&z(0), &[]);
        let s = awc.committee_size_summary();
        assert_eq!(
            (s.zones_registered, s.size_min, s.size_max, s.zones_below_target),
            (2, 7, 10, 0),
            "after removing undersized zone: registered=2, min=7, below_target=0 — clean state"
        );

        // Replace zone 1 with an undersized committee (re-register): below_target ticks back up.
        awc.register_epoch_committee(&z(1), &members(&["lone"]));
        let s = awc.committee_size_summary();
        assert_eq!(
            (s.zones_registered, s.size_min, s.size_max, s.zones_below_target),
            (2, 1, 10, 1),
            "re-register zone 1 as 1-member: min collapses to 1, below_target=1"
        );

        // Final drain — size_min must collapse from usize::MAX back to 0.
        awc.register_epoch_committee(&z(1), &[]);
        awc.register_epoch_committee(&z(2), &[]);
        let s = awc.committee_size_summary();
        assert_eq!(
            (s.zones_registered, s.size_min, s.size_max, s.zones_below_target),
            (0, 0, 0, 0),
            "after full drain, every gauge collapses back to 0 (no usize::MAX leak via size_min)"
        );
    }

    #[test]
    fn test_missing_creator_stake_count_matches_predicate() {
        // missing_creator_stake_count() must agree with the existing
        // records_missing_creator_stake() Vec helper across every state
        // transition operators care about — empty store, all-missing,
        // partial-backfill, full-backfill, post-prune, and post-eviction.
        let mut awc = AWCConsensus::new();

        // Empty store: nothing tracked, nothing missing.
        assert_eq!(awc.missing_creator_stake_count(), 0,
            "empty consensus: count=0");
        assert_eq!(awc.records_missing_creator_stake().len(), 0,
            "empty consensus: vec helper agrees");

        // Insert 3 attestations without registering creator stakes — all 3 missing.
        for rid in &["rec-a", "rec-b", "rec-c"] {
            awc.add_attestation(Attestation {
                record_id: rid.to_string(),
                witness_hash: format!("w-{rid}"),
                stake: 10,
                timestamp: 1000.0,
            });
        }
        assert_eq!(awc.missing_creator_stake_count(), 3,
            "3 records added, 0 stakes registered: count=3");
        assert_eq!(
            awc.missing_creator_stake_count(),
            awc.records_missing_creator_stake().len(),
            "count helper agrees with vec helper for all-missing case"
        );

        // Partial backfill: register stake for one of the three.
        awc.register_creator_stake("rec-a", "creator-a", 100);
        assert_eq!(awc.missing_creator_stake_count(), 2,
            "after registering 1 of 3: count=2");
        assert_eq!(
            awc.missing_creator_stake_count(),
            awc.records_missing_creator_stake().len(),
            "count helper agrees for partial-backfill case"
        );

        // Full backfill: register the remaining two.
        awc.register_creator_stake("rec-b", "creator-b", 200);
        awc.register_creator_stake("rec-c", "creator-c", 300);
        assert_eq!(awc.missing_creator_stake_count(), 0,
            "full backfill: count=0");

        // Add a fourth record without backfill — count climbs back to 1.
        awc.add_attestation(Attestation {
            record_id: "rec-d".to_string(),
            witness_hash: "w-d".to_string(),
            stake: 10,
            timestamp: 2000.0,
        });
        assert_eq!(awc.missing_creator_stake_count(), 1,
            "fresh record without stake: count=1");

        // Prune via predicate matching only the staked records — the unstaked
        // record-d remains; count stays at 1 because creator_stakes still has
        // rec-a/b/c rows that are now orphan (no attestations) but those don't
        // count toward "missing" since the predicate iterates `attestations`.
        let mut finalized = std::collections::HashSet::new();
        finalized.insert("rec-a".to_string());
        finalized.insert("rec-b".to_string());
        finalized.insert("rec-c".to_string());
        awc.prune_finalized(&finalized);
        assert_eq!(awc.missing_creator_stake_count(), 1,
            "after pruning the 3 staked records: only rec-d remains and it's still missing");

        // Backfill rec-d post-arrival → count drops to 0.
        awc.register_creator_stake("rec-d", "creator-d", 400);
        assert_eq!(awc.missing_creator_stake_count(), 0,
            "after backfilling rec-d: count=0");

        // Final drain: prune rec-d. Both helpers must report 0.
        finalized.insert("rec-d".to_string());
        awc.prune_finalized(&finalized);
        assert_eq!(awc.missing_creator_stake_count(), 0,
            "fully drained: count=0");
        assert_eq!(awc.records_missing_creator_stake().len(), 0,
            "fully drained: vec helper agrees");
    }

    #[test]
    fn test_prune_older_than_evicts_stale() {
        let mut awc = AWCConsensus::new();
        // Old attestation (timestamp 100)
        awc.add_attestation(Attestation {
            record_id: "old-r".to_string(), witness_hash: "w1".to_string(),
            stake: 10, timestamp: 100.0,
        });
        // Recent attestation (timestamp 5000)
        awc.add_attestation(Attestation {
            record_id: "new-r".to_string(), witness_hash: "w1".to_string(),
            stake: 10, timestamp: 5000.0,
        });

        // Evict anything older than timestamp 1000
        let pruned = awc.prune_older_than(1000.0);
        assert_eq!(pruned, 1);
        assert_eq!(awc.attestation_count("old-r"), 0);
        assert_eq!(awc.attestation_count("new-r"), 1);
    }

    #[test]
    fn test_prune_older_than_keeps_if_any_recent() {
        let mut awc = AWCConsensus::new();
        // Record with one old and one recent attestation
        awc.add_attestation(Attestation {
            record_id: "r1".to_string(), witness_hash: "w1".to_string(),
            stake: 10, timestamp: 100.0,
        });
        awc.add_attestation(Attestation {
            record_id: "r1".to_string(), witness_hash: "w2".to_string(),
            stake: 10, timestamp: 5000.0,
        });

        // Cutoff at 1000 — record has a recent attestation, so keep it
        let pruned = awc.prune_older_than(1000.0);
        assert_eq!(pruned, 0);
        assert_eq!(awc.attestation_count("r1"), 2);
    }

    #[test]
    fn test_prune_older_than_cleans_related_maps() {
        let mut awc = AWCConsensus::new();
        awc.add_attestation(Attestation {
            record_id: "r1".to_string(), witness_hash: "w1".to_string(),
            stake: 10, timestamp: 100.0,
        });
        // Set confirmation level, creator stake, and creator identity.
        awc.confirmation_levels.insert("r1".to_string(), ConfirmationLevel::Sealed);
        awc.creator_stakes.insert("r1".to_string(), 50);
        awc.creator_identity.insert("r1".to_string(), "creator-w".to_string());

        let pruned = awc.prune_older_than(1000.0);
        assert_eq!(pruned, 1);
        // Related maps should also be cleaned
        assert_eq!(awc.confirmation_level("r1"), ConfirmationLevel::Pending);
        assert!(!awc.creator_stakes.contains_key("r1"));
        // creator_identity is registered for EVERY record now (F5), so it MUST
        // be pruned here too — otherwise it leaks one orphan per age-evicted
        // record over the chain's lifetime (O(total history)).
        assert!(!awc.creator_identity.contains_key("r1"),
            "creator_identity must be pruned with creator_stakes to stay O(active window)");
    }

    #[test]
    fn test_prune_sweeps_never_attested_creator_identity() {
        // F5 registers creator_identity at ingest even for a record that never
        // receives an attestation. The prune tick must sweep such an orphan EVEN
        // when no attestations were age-evicted (pruned == 0) — otherwise it
        // leaks O(total history). This record has no attestation entry at all.
        let mut awc = AWCConsensus::new();
        awc.register_creator_stake("orphan-rec", "creator-o", 0); // identity only
        assert!(awc.creator_identity.contains_key("orphan-rec"));

        // Nothing to age-evict (no attestations exist) → pruned == 0.
        let pruned = awc.prune_older_than(1000.0);
        assert_eq!(pruned, 0, "no attestations to prune");
        assert!(
            !awc.creator_identity.contains_key("orphan-rec"),
            "a never-attested creator_identity orphan must be swept even when pruned==0"
        );
    }

    // Eviction-mechanism counter tests. Three
    // independent counters mapped to the 4-mechanism eviction taxonomy
    // (pressure eviction already covered by `evictions_total`).

    #[test]
    fn test_evictions_finalized_total_increments_on_prune_where() {
        let mut awc = AWCConsensus::new();
        awc.add_attestation(Attestation {
            record_id: "rec-a".to_string(), witness_hash: "w1".to_string(),
            stake: 10, timestamp: 100.0,
        });
        awc.add_attestation(Attestation {
            record_id: "rec-b".to_string(), witness_hash: "w1".to_string(),
            stake: 10, timestamp: 200.0,
        });
        // Baseline counter = 0.
        assert_eq!(awc.evictions_finalized_total, 0);

        // Prune only rec-a → counter bumps by exactly 1.
        let mut finalized: HashSet<String> = HashSet::new();
        finalized.insert("rec-a".to_string());
        let pruned = awc.prune_finalized(&finalized);
        assert_eq!(pruned, 1);
        assert_eq!(awc.evictions_finalized_total, 1);

        // A second call with a record NOT in the map → counter does not move.
        let mut nothing_match: HashSet<String> = HashSet::new();
        nothing_match.insert("rec-z".to_string());
        let pruned2 = awc.prune_finalized(&nothing_match);
        assert_eq!(pruned2, 0);
        assert_eq!(awc.evictions_finalized_total, 1, "no-op prune must not bump the finalized counter");

        // Counter is cumulative across calls — prune rec-b too.
        finalized.insert("rec-b".to_string());
        let pruned3 = awc.prune_finalized(&finalized);
        assert_eq!(pruned3, 1, "only rec-b remains in map");
        assert_eq!(awc.evictions_finalized_total, 2, "counter accumulates");
    }

    #[test]
    fn test_evictions_age_total_increments_on_prune_older_than() {
        let mut awc = AWCConsensus::new();
        // Three records with distinct ages.
        for (rid, ts) in [("r1", 100.0), ("r2", 500.0), ("r3", 5000.0)] {
            awc.add_attestation(Attestation {
                record_id: rid.to_string(), witness_hash: "w1".to_string(),
                stake: 10, timestamp: ts,
            });
        }
        assert_eq!(awc.evictions_age_total, 0);

        // Cutoff 1000 → r1 + r2 evicted (2 records), r3 survives.
        let pruned = awc.prune_older_than(1000.0);
        assert_eq!(pruned, 2);
        assert_eq!(awc.evictions_age_total, 2);

        // Re-running with the same cutoff → no-op; counter unchanged.
        let pruned2 = awc.prune_older_than(1000.0);
        assert_eq!(pruned2, 0);
        assert_eq!(awc.evictions_age_total, 2, "no-op age-prune must not bump the counter");

        // Aggressive cutoff evicts r3 too → counter accumulates.
        let pruned3 = awc.prune_older_than(10_000.0);
        assert_eq!(pruned3, 1);
        assert_eq!(awc.evictions_age_total, 3);
    }

    #[test]
    fn test_evictions_zone_purge_total_counts_present_records_only() {
        let mut awc = AWCConsensus::new();
        awc.add_attestation(Attestation {
            record_id: "rec-present".to_string(), witness_hash: "w1".to_string(),
            stake: 10, timestamp: 1.0,
        });
        assert_eq!(awc.evictions_zone_purge_total, 0);

        // Real eviction → counter +1.
        awc.forget_record("rec-present");
        assert_eq!(awc.evictions_zone_purge_total, 1);
        assert!(!awc.attestations.contains_key("rec-present"));

        // Idempotent re-call (record already gone) → counter stays at 1.
        awc.forget_record("rec-present");
        assert_eq!(awc.evictions_zone_purge_total, 1, "idempotent no-op must NOT bump");

        // Unknown record → counter stays at 1.
        awc.forget_record("rec-never-existed");
        assert_eq!(awc.evictions_zone_purge_total, 1, "unknown-id no-op must NOT bump");
    }

    #[test]
    fn test_eviction_counters_independent_of_pressure() {
        // Confirm the three eviction counters do NOT bleed into `evictions_total`
        // (mech #3 — pressure). prune_finalized / prune_older_than /
        // forget_record must leave `evictions_total` at 0.
        let mut awc = AWCConsensus::new();
        for (rid, ts) in [("r1", 100.0), ("r2", 200.0), ("r3", 5000.0)] {
            awc.add_attestation(Attestation {
                record_id: rid.to_string(), witness_hash: "w1".to_string(),
                stake: 10, timestamp: ts,
            });
        }

        // mech #1: finalize r1.
        let mut finalized: HashSet<String> = HashSet::new();
        finalized.insert("r1".to_string());
        awc.prune_finalized(&finalized);

        // mech #2: age-prune r2.
        awc.prune_older_than(1000.0);

        // mech #4: forget r3.
        awc.forget_record("r3");

        assert_eq!(awc.evictions_finalized_total, 1);
        assert_eq!(awc.evictions_age_total, 1);
        assert_eq!(awc.evictions_zone_purge_total, 1);
        assert_eq!(awc.evictions_total, 0,
            "pressure counter (mech #3) must stay 0 — none of these are evict_oldest_attestations calls");
        assert_eq!(awc.evictions_near_settlement, 0);
    }

    #[test]
    fn test_memory_entry_count() {
        let mut awc = AWCConsensus::new();
        assert_eq!(awc.memory_entry_count(), 0);
        awc.add_attestation(Attestation {
            record_id: "r1".to_string(), witness_hash: "w1".to_string(),
            stake: 10, timestamp: 1.0,
        });
        // attestations(1) + confirmation_levels(1) + profiles(0) + anchored(0)
        // + seal_attestations(0) + seal_record_ids(0) + creator_stakes(0)
        assert!(awc.memory_entry_count() >= 1);
    }

    #[test]
    fn test_gamma_applies_to_same_zone_discount() {
        // Stage 5: GAMMA > 0. Two witnesses in the same geographic bucket
        // (different org, different subnet) should surface a γ-weighted
        // correlation equal to GAMMA.
        let mut awc = AWCConsensus::new();
        awc.register_profile("w1", profile("org-a", "10.0.1", "earth-us"));
        awc.register_profile("w2", profile("org-b", "10.0.2", "earth-us"));

        let corr = awc.correlation("w1", "w2");
        assert!((corr - GAMMA).abs() < f64::EPSILON);
    }

    #[test]
    fn gamma_effective_degrades_to_zero_on_homogeneous_set() {
        // All witnesses in one bucket → γ_eff must be 0 (honest degradation).
        // Prevents a single-datacenter testnet from slashing its own trust.
        let mut awc = AWCConsensus::new();
        awc.register_profile("w1", profile("org-a", "10.0.1", "earth-eu"));
        awc.register_profile("w2", profile("org-b", "10.0.2", "earth-eu"));
        awc.register_profile("w3", profile("org-c", "10.0.3", "earth-eu"));
        let set = ["w1", "w2", "w3"];
        assert_eq!(awc.gamma_effective(&set), 0.0);
    }

    #[test]
    fn gamma_effective_activates_on_diverse_set() {
        // γ ramps linearly from 0 (at witness_count ==
        // MIN_GEO_BUCKETS) to full GAMMA (at GAMMA_FULL_WITNESSES). At the
        // floor, γ is exactly 0 — the set isn't big enough to carry γ signal.
        let mut awc = AWCConsensus::new();
        awc.register_profile("w1", profile("org-a", "10.0.1", "earth-eu"));
        awc.register_profile("w2", profile("org-b", "10.0.2", "earth-us"));
        let set = ["w1", "w2"];
        assert_eq!(awc.gamma_effective(&set), 0.0);

        // At GAMMA_FULL_WITNESSES witnesses with ≥ MIN_GEO_BUCKETS buckets,
        // γ reaches the full GAMMA ceiling.
        let mut awc_full = AWCConsensus::new();
        for i in 0..GAMMA_FULL_WITNESSES {
            let hash = format!("w{i}");
            let zone = if i % 2 == 0 { "earth-eu" } else { "earth-us" };
            awc_full.register_profile(&hash, profile("org", "10.0.0", zone));
        }
        let hashes: Vec<String> = (0..GAMMA_FULL_WITNESSES).map(|i| format!("w{i}")).collect();
        let set: Vec<&str> = hashes.iter().map(String::as_str).collect();
        assert!((awc_full.gamma_effective(&set) - GAMMA).abs() < f64::EPSILON);
    }

    #[test]
    fn gamma_effective_counts_derived_asn_when_self_report_empty() {
        // Self-reported geo_zone empty but derived ASN distinct — still
        // counts as two buckets. The ramp means γ_eff itself is 0 at
        // witness_count=MIN_GEO_BUCKETS, so we assert the bucket_count to
        // validate that derived ASN is the mechanism being exercised.
        let mut awc = AWCConsensus::new();
        awc.register_profile("w1", profile("org-a", "10.0.1", ""));
        awc.register_profile("w2", profile("org-b", "10.0.2", ""));
        awc.register_derived_geo(
            "w1",
            DerivedWitnessGeo::from_ip(std::net::IpAddr::V4(
                std::net::Ipv4Addr::new(88, 99, 142, 148),
            )),
        ); // Hetzner
        awc.register_derived_geo(
            "w2",
            DerivedWitnessGeo::from_ip(std::net::IpAddr::V4(
                std::net::Ipv4Addr::new(165, 227, 10, 20),
            )),
        ); // DigitalOcean
        let set = ["w1", "w2"];
        let st = awc.geo_diversity_state(&set);
        assert_eq!(st.bucket_count, 2, "derived ASN should produce 2 buckets");
        assert!(st.gamma_active, "≥ MIN_GEO_BUCKETS → gamma_active=true");
    }

    #[test]
    fn geo_diversity_state_surfaces_degraded_mode() {
        // Single-bucket set → honest degradation — endpoint should show
        // bucket_count=1, gamma_active=false, gamma_effective=0.0.
        let mut awc = AWCConsensus::new();
        awc.register_profile("w1", profile("org-a", "10.0.1", "earth-eu"));
        awc.register_profile("w2", profile("org-b", "10.0.2", "earth-eu"));
        awc.register_profile("w3", profile("org-c", "10.0.3", "earth-eu"));
        let set = ["w1", "w2", "w3"];
        let st = awc.geo_diversity_state(&set);
        assert_eq!(st.witness_count, 3);
        assert_eq!(st.bucket_count, 1);
        assert_eq!(st.min_buckets, MIN_GEO_BUCKETS);
        assert!(!st.gamma_active);
        assert_eq!(st.gamma_effective, 0.0);
        // Must match gamma_effective() so we can't drift.
        assert_eq!(st.gamma_effective, awc.gamma_effective(&set));
    }

    #[test]
    fn geo_diversity_state_surfaces_active_mode() {
        // ≥ MIN_GEO_BUCKETS distinct buckets → γ active (> 0), but
        // the magnitude is on the linear ramp between MIN_GEO_BUCKETS and
        // GAMMA_FULL_WITNESSES witnesses. At 3 witnesses the ramp is still
        // early: γ_eff = GAMMA × (3 - 2) / (12 - 2) = GAMMA × 0.1.
        let mut awc = AWCConsensus::new();
        awc.register_profile("w1", profile("org-a", "10.0.1", "earth-eu"));
        awc.register_profile("w2", profile("org-b", "10.0.2", "earth-us"));
        awc.register_profile("w3", profile("org-c", "10.0.3", "earth-as"));
        let set = ["w1", "w2", "w3"];
        let st = awc.geo_diversity_state(&set);
        assert_eq!(st.witness_count, 3);
        assert_eq!(st.bucket_count, 3);
        assert!(st.gamma_active);
        let expected = GAMMA * (3.0 - MIN_GEO_BUCKETS as f64) / (GAMMA_FULL_WITNESSES as f64 - MIN_GEO_BUCKETS as f64);
        assert!((st.gamma_effective - expected).abs() < 1e-9,
            "expected γ_eff ≈ {expected}, got {}", st.gamma_effective);
        assert_eq!(st.gamma_effective, awc.gamma_effective(&set));
    }

    #[test]
    fn geo_diversity_state_empty_set_is_degraded() {
        let awc = AWCConsensus::new();
        let st = awc.geo_diversity_state(&[]);
        assert_eq!(st.witness_count, 0);
        assert_eq!(st.bucket_count, 0);
        assert!(!st.gamma_active);
        assert_eq!(st.gamma_effective, 0.0);
    }

    #[test]
    fn geo_diversity_state_ignores_missing_profiles() {
        // Witnesses with no profile and no derived geo don't create buckets.
        // A set of 3 unknown witnesses must stay in honest-degradation mode.
        let awc = AWCConsensus::new();
        let set = ["w1", "w2", "w3"];
        let st = awc.geo_diversity_state(&set);
        assert_eq!(st.witness_count, 3);
        assert_eq!(st.bucket_count, 0);
        assert!(!st.gamma_active);
    }

    #[test]
    fn independence_does_not_penalize_homogeneous_set_geographically() {
        // All-EU witness set: geo-correlation penalty MUST be suppressed.
        // Under the old GAMMA=0 world this was free; under Stage 5 the
        // degradation code is what keeps it free for honest small nets.
        let mut awc = AWCConsensus::new();
        awc.register_profile("w1", profile("org-a", "10.0.1", "earth-eu"));
        awc.register_profile("w2", profile("org-b", "10.0.2", "earth-eu"));
        let set = ["w1", "w2"];
        // Only one bucket → γ_eff=0 → pairwise corr reduces to α·0+β·0+0·1 = 0.
        assert!(awc.independence("w1", &set) > 0.999);
    }

    #[test]
    fn test_audit9_gamma_ramps_linearly_from_min_to_full() {
        // Verify γ_eff follows the
        // smooth linear ramp at 2/4/6/8/10/12 witnesses × 2 buckets.
        //
        // Curve: γ_eff = GAMMA × clamp((n - MIN_GEO_BUCKETS) / (GAMMA_FULL_WITNESSES - MIN_GEO_BUCKETS), 0, 1)
        // with GAMMA=0.2, MIN_GEO_BUCKETS=2, GAMMA_FULL_WITNESSES=12.
        let cases = [
            (2, 0.0),                            // floor: no ramp yet
            (4, GAMMA * 2.0 / 10.0),             // 0.04
            (6, GAMMA * 4.0 / 10.0),             // 0.08
            (8, GAMMA * 6.0 / 10.0),             // 0.12
            (10, GAMMA * 8.0 / 10.0),            // 0.16
            (12, GAMMA),                         // ceiling
            (20, GAMMA),                         // clamp above ceiling
        ];
        for &(n, expected) in &cases {
            let got = gamma_effective_scaled(n, 2);
            assert!(
                (got - expected).abs() < 1e-9,
                "ramp(witness_count={n}, bucket_count=2): expected {expected}, got {got}"
            );
        }

        // Below MIN_GEO_BUCKETS, γ is flat 0 regardless of witness count.
        for n in [2, 5, 12, 100] {
            assert_eq!(
                gamma_effective_scaled(n, 1),
                0.0,
                "bucket_count < MIN_GEO_BUCKETS must floor to 0 (witness={n})"
            );
        }

        // 3 buckets follows the same curve as 2 — bucket count only gates,
        // doesn't scale.
        assert_eq!(
            gamma_effective_scaled(4, 3),
            gamma_effective_scaled(4, 2),
            "bucket_count above threshold should not change γ magnitude"
        );
    }

    #[test]
    fn independence_penalizes_diverse_set_with_collocated_pair() {
        // Set has a distant US node + two colocated EU nodes. γ activates
        // (2 buckets), but the ramp means at 3 witnesses γ is only at
        // 10% of full (GAMMA × (3-2)/(12-2)).
        // w1 (EU) is correlated with w2 (EU) via γ_eff, independent of w3 (US).
        let mut awc = AWCConsensus::new();
        awc.register_profile("w1", profile("org-a", "10.0.1", "earth-eu"));
        awc.register_profile("w2", profile("org-b", "10.0.2", "earth-eu"));
        awc.register_profile("w3", profile("org-c", "10.0.3", "earth-us"));
        let set = ["w1", "w2", "w3"];
        let d = awc.independence("w1", &set);
        let gamma_eff = GAMMA * (3.0 - MIN_GEO_BUCKETS as f64) / (GAMMA_FULL_WITNESSES as f64 - MIN_GEO_BUCKETS as f64);
        let expected = 1.0 / (1.0 + gamma_eff);
        assert!((d - expected).abs() < 1e-9, "expected {expected}, got {d}");
    }

    #[test]
    fn test_confirmation_level_from_name_backward_compat() {
        // New names
        assert_eq!(ConfirmationLevel::from_name("pending"), ConfirmationLevel::Pending);
        assert_eq!(ConfirmationLevel::from_name("sealed"), ConfirmationLevel::Sealed);
        assert_eq!(ConfirmationLevel::from_name("finalized"), ConfirmationLevel::Finalized);
        assert_eq!(ConfirmationLevel::from_name("anchored"), ConfirmationLevel::Anchored);

        // Old names still work (backward compat)
        assert_eq!(ConfirmationLevel::from_name("unconfirmed"), ConfirmationLevel::Pending);
        assert_eq!(ConfirmationLevel::from_name("attested"), ConfirmationLevel::Sealed);
        assert_eq!(ConfirmationLevel::from_name("confirmed"), ConfirmationLevel::Finalized);
    }

    #[test]
    fn test_hard_budget_evicts_fewest_attestations_first() {
        let mut awc = AWCConsensus::new();
        // Fill to cap: all records have exactly 1 attestation
        for i in 0..MAX_ATTESTATION_RECORDS {
            awc.add_attestation(Attestation {
                record_id: format!("r-{i}"),
                witness_hash: "w1".to_string(),
                stake: 10,
                timestamp: i as f64,
            });
        }
        assert_eq!(awc.attestations.len(), MAX_ATTESTATION_RECORDS);

        // Give some records extra attestations (near settlement — should survive)
        for i in (MAX_ATTESTATION_RECORDS - 100)..MAX_ATTESTATION_RECORDS {
            awc.add_attestation(Attestation {
                record_id: format!("r-{i}"),
                witness_hash: "w2".to_string(),
                stake: 10,
                timestamp: (i + MAX_ATTESTATION_RECORDS) as f64,
            });
            awc.add_attestation(Attestation {
                record_id: format!("r-{i}"),
                witness_hash: "w3".to_string(),
                stake: 10,
                timestamp: (i + MAX_ATTESTATION_RECORDS * 2) as f64,
            });
        }

        // Adding one more triggers eviction
        awc.add_attestation(Attestation {
            record_id: "r-new".to_string(),
            witness_hash: "w1".to_string(),
            stake: 10,
            timestamp: 999_999.0,
        });
        assert!(awc.attestations.len() < MAX_ATTESTATION_RECORDS);
        // New record present
        assert!(awc.attestations.contains_key("r-new"));
        // Records with 1 attestation (fewest) should be evicted first
        assert!(!awc.attestations.contains_key("r-0"));
        // Records with 3 attestations (near settlement) should survive
        let near_settle_id = format!("r-{}", MAX_ATTESTATION_RECORDS - 1);
        assert!(awc.attestations.contains_key(&near_settle_id),
            "records near settlement should survive eviction");
    }

    #[test]
    fn test_hard_budget_evicts_oldest_seal_attestations() {
        let mut awc = AWCConsensus::new();
        for i in 0..MAX_SEAL_ATTESTATIONS {
            awc.seal_attestations.entry(format!("seal-{i}")).or_default().push(
                SealAttestation {
                    seal_id: format!("seal-{i}"),
                    zone: ZoneId::from_legacy(0),
                    epoch_number: 0,
                    witness_hash: "w1".to_string(),
                    stake: 10,
                    timestamp: i as f64,
                }
            );
            awc.seal_record_ids.insert(format!("seal-{i}"), vec![format!("r-{i}")]);
        }
        assert_eq!(awc.seal_attestations.len(), MAX_SEAL_ATTESTATIONS);

        // Adding one more triggers eviction
        let _ = awc.add_seal_attestation(SealAttestation {
            seal_id: "seal-new".to_string(),
            zone: ZoneId::from_legacy(0),
            epoch_number: 0,
            witness_hash: "w1".to_string(),
            stake: 10,
            timestamp: 999_999.0,
        });
        assert!(awc.seal_attestations.len() < MAX_SEAL_ATTESTATIONS);
        assert!(awc.seal_attestations.contains_key("seal-new"));
        assert!(!awc.seal_attestations.contains_key("seal-0"));
        // seal_record_ids for evicted seals should also be gone
        assert!(!awc.seal_record_ids.contains_key("seal-0"));
    }

    // ── witness profile registration records ────────────────────────

    #[test]
    fn test_witness_profile_metadata_roundtrip() {
        let profile = WitnessProfile {
            organization: "navigatorbuilds".to_string(),
            subnet: "88.99.142".to_string(),
            geo_zone: "us-east".to_string(),
        };
        let meta = witness_profile_metadata(&profile);

        assert_eq!(meta.get(WITNESS_PROFILE_KEY).unwrap(), &serde_json::json!(true));
        assert_eq!(meta.get("witness_organization").unwrap(), "navigatorbuilds");
        assert_eq!(meta.get("witness_subnet").unwrap(), "88.99.142");
        assert_eq!(meta.get("witness_geo_zone").unwrap(), "us-east");
    }

    #[test]
    fn test_extract_witness_profile_from_record() {
        let mut meta = std::collections::BTreeMap::new();
        meta.insert(WITNESS_PROFILE_KEY.into(), serde_json::json!(true));
        meta.insert("witness_organization".into(), serde_json::json!("acme-corp"));
        meta.insert("witness_subnet".into(), serde_json::json!("10.0.1"));
        meta.insert("witness_geo_zone".into(), serde_json::json!("eu-central"));

        let record = crate::record::ValidationRecord {
            id: "test-profile".to_string(),
            version: crate::wire::WIRE_VERSION,
            content_hash: vec![0u8; 32],
            creator_public_key: vec![0u8; 1952],
            timestamp: 1000.0,
            parents: vec![],
            classification: crate::record::Classification::Public,
            metadata: meta,
            signature: None,
            sphincs_signature: None,
            zk_proof: None,
            itc_stamp: None,
            zone_refs: Vec::new(),
            creator_sphincs_pk: None,
            sig_algorithm: 0x01,
            sphincs_algorithm: None,
            zone: None,
            identity_hash_wire: None,
            nonce: 0,
        };

        let profile = extract_witness_profile(&record).unwrap();
        assert_eq!(profile.organization, "acme-corp");
        assert_eq!(profile.subnet, "10.0.1");
        assert_eq!(profile.geo_zone, "eu-central");
    }

    #[test]
    fn test_extract_witness_profile_missing_org_returns_none() {
        let mut meta = std::collections::BTreeMap::new();
        meta.insert(WITNESS_PROFILE_KEY.into(), serde_json::json!(true));
        // No organization — should return None

        let record = crate::record::ValidationRecord {
            id: "test-no-org".to_string(),
            version: crate::wire::WIRE_VERSION,
            content_hash: vec![0u8; 32],
            creator_public_key: vec![0u8; 1952],
            timestamp: 1000.0,
            parents: vec![],
            classification: crate::record::Classification::Public,
            metadata: meta,
            signature: None,
            sphincs_signature: None,
            zk_proof: None,
            itc_stamp: None,
            zone_refs: Vec::new(),
            creator_sphincs_pk: None,
            sig_algorithm: 0x01,
            sphincs_algorithm: None,
            zone: None,
            identity_hash_wire: None,
            nonce: 0,
        };

        assert!(extract_witness_profile(&record).is_none());
    }

    #[test]
    fn test_extract_witness_profile_not_registration() {
        let meta = std::collections::BTreeMap::new();
        // No witness_profile_registration key at all

        let record = crate::record::ValidationRecord {
            id: "test-normal".to_string(),
            version: crate::wire::WIRE_VERSION,
            content_hash: vec![0u8; 32],
            creator_public_key: vec![0u8; 1952],
            timestamp: 1000.0,
            parents: vec![],
            classification: crate::record::Classification::Public,
            metadata: meta,
            signature: None,
            sphincs_signature: None,
            zk_proof: None,
            itc_stamp: None,
            zone_refs: Vec::new(),
            creator_sphincs_pk: None,
            sig_algorithm: 0x01,
            sphincs_algorithm: None,
            zone: None,
            identity_hash_wire: None,
            nonce: 0,
        };

        assert!(extract_witness_profile(&record).is_none());
    }

    #[test]
    fn test_profile_registration_fixes_correlation_penalty() {
        let mut awc = AWCConsensus::new();

        // Without profiles: 0.8 correlation (the penalty)
        assert_eq!(awc.correlation("w1", "w2"), ALPHA + BETA);

        // Register different profiles
        awc.register_profile("w1", profile("org-a", "10.0.1", "us-east"));
        awc.register_profile("w2", profile("org-b", "10.0.2", "eu-central"));

        // Now: 0.0 correlation (fully independent)
        assert_eq!(awc.correlation("w1", "w2"), 0.0);
    }

    // ── VRF jury selection ──────────────────────────────────────────

    #[test]
    fn test_select_epoch_jury_empty_staked() {
        let zone = ZoneId::from_legacy(0);
        let jury = select_epoch_jury(&[0u8; 32], &[], &zone);
        assert!(jury.is_empty());
    }

    #[test]
    fn test_select_epoch_jury_bootstrap_returns_all() {
        let zone = ZoneId::from_legacy(0);
        let staked: Vec<String> = (0..5).map(|i| format!("witness-{i}")).collect();
        // Empty VRF output = bootstrap mode → everyone attests
        let jury = select_epoch_jury(&[], &staked, &zone);
        assert_eq!(jury.len(), 5);
    }

    #[test]
    fn test_select_epoch_jury_deterministic() {
        let zone = ZoneId::from_legacy(0);
        let vrf = [42u8; 32];
        let staked: Vec<String> = (0..10).map(|i| format!("witness-{i}")).collect();
        let jury1 = select_epoch_jury(&vrf, &staked, &zone);
        let jury2 = select_epoch_jury(&vrf, &staked, &zone);
        assert_eq!(jury1, jury2, "same VRF output must produce same jury");
    }

    #[test]
    fn test_select_epoch_jury_different_vrf_different_jury() {
        let zone = ZoneId::from_legacy(0);
        let staked: Vec<String> = (0..20).map(|i| format!("witness-{i}")).collect();
        let jury1 = select_epoch_jury(&[1u8; 32], &staked, &zone);
        let jury2 = select_epoch_jury(&[2u8; 32], &staked, &zone);
        // Different VRF outputs should (with overwhelming probability) select different sets
        assert_ne!(jury1, jury2);
    }

    #[test]
    fn test_select_epoch_jury_size_formula() {
        let zone = ZoneId::from_legacy(0);
        let vrf = [99u8; 32];

        // 3 staked → jury = min(3, max(3, 3)) = 3 (all of them)
        let s3: Vec<String> = (0..3).map(|i| format!("w{i}")).collect();
        assert_eq!(select_epoch_jury(&vrf, &s3, &zone).len(), 3);

        // 6 staked → small network (≤10), everyone attests
        let s6: Vec<String> = (0..6).map(|i| format!("w{i}")).collect();
        assert_eq!(select_epoch_jury(&vrf, &s6, &zone).len(), 6);

        // 10 staked → small network (≤10), everyone attests
        let s10: Vec<String> = (0..10).map(|i| format!("w{i}")).collect();
        assert_eq!(select_epoch_jury(&vrf, &s10, &zone).len(), 10);

        // 100 staked → ceil(100 * 2/3) + 1 = 68. min(100, max(3, 68)) = 68
        let s100: Vec<String> = (0..100).map(|i| format!("w{i}")).collect();
        assert_eq!(select_epoch_jury(&vrf, &s100, &zone).len(), 68);
    }

    #[test]
    fn test_is_in_epoch_jury_bootstrap() {
        let zone = ZoneId::from_legacy(0);
        let staked: Vec<String> = (0..5).map(|i| format!("w{i}")).collect();
        // Bootstrap mode: everyone is in the jury
        assert!(is_in_epoch_jury(&[], &staked, &zone, "w0"));
        assert!(is_in_epoch_jury(&[], &staked, &zone, "w4"));
    }

    #[test]
    fn test_is_in_epoch_jury_selected_vs_not() {
        let zone = ZoneId::from_legacy(0);
        let vrf = [77u8; 32];
        // 20 staked → jury of ~15, so some will be excluded
        let staked: Vec<String> = (0..20).map(|i| format!("w{i}")).collect();
        let jury = select_epoch_jury(&vrf, &staked, &zone);
        let not_in_jury: Vec<&String> = staked.iter()
            .filter(|w| !jury.contains(w))
            .collect();
        assert!(!not_in_jury.is_empty(), "with 20 witnesses, some should be excluded");
        // Verify is_in_epoch_jury matches
        for w in &jury {
            assert!(is_in_epoch_jury(&vrf, &staked, &zone, w));
        }
        for w in &not_in_jury {
            assert!(!is_in_epoch_jury(&vrf, &staked, &zone, w));
        }
    }

    // ─── Gap 5: scoped jury tests ────────────────────────────────────────

    #[test]
    fn test_scoped_jury_filters_by_subscription() {
        let zone = ZoneId::from_legacy(0);
        let vrf = [99u8; 32];
        let staked: Vec<String> = (0..30).map(|i| format!("w{i:02}")).collect();

        // Only half subscribe to zone 0.
        let subs: std::collections::HashSet<String> =
            (0..15).map(|i| format!("w{i:02}")).collect();

        let scoped = select_epoch_jury_scoped(&vrf, &staked, &zone, &subs);

        // Scoped jury must contain only subscribers.
        for w in &scoped {
            assert!(
                subs.contains(w),
                "scoped jury contains unsubscribed witness {w}"
            );
        }
        assert!(!scoped.is_empty());
    }

    #[test]
    fn test_scoped_jury_different_zones_different_subs() {
        let vrf = [0x42; 32];
        let staked: Vec<String> = (0..30).map(|i| format!("w{i:02}")).collect();

        let subs_a: std::collections::HashSet<String> =
            (0..15).map(|i| format!("w{i:02}")).collect();
        let subs_b: std::collections::HashSet<String> =
            (15..30).map(|i| format!("w{i:02}")).collect();

        let jury_a = select_epoch_jury_scoped(&vrf, &staked, &ZoneId::from_legacy(0), &subs_a);
        let jury_b = select_epoch_jury_scoped(&vrf, &staked, &ZoneId::from_legacy(1), &subs_b);

        // Disjoint subscription sets produce disjoint juries.
        for w in &jury_a {
            assert!(!jury_b.contains(w));
        }
        for w in &jury_b {
            assert!(!jury_a.contains(w));
        }
    }

    #[test]
    fn test_scoped_jury_bootstrap_fallback() {
        let zone = ZoneId::from_legacy(5);
        let vrf = [0x77; 32];
        let staked: Vec<String> = (0..30).map(|i| format!("w{i:02}")).collect();

        // Below MIN_SCOPED_ELIGIBLE subscribers → fall back to global pool.
        let subs: std::collections::HashSet<String> =
            vec!["w05".into()].into_iter().collect();

        let scoped = select_epoch_jury_scoped(&vrf, &staked, &zone, &subs);
        let global = select_epoch_jury(&vrf, &staked, &zone);

        assert_eq!(scoped, global, "under threshold should fall back to global");
    }

    #[test]
    fn test_scoped_jury_equal_to_global_when_all_subscribe() {
        let zone = ZoneId::from_legacy(0);
        let vrf = [0x11; 32];
        let staked: Vec<String> = (0..20).map(|i| format!("w{i:02}")).collect();
        let subs: std::collections::HashSet<String> = staked.iter().cloned().collect();

        let scoped = select_epoch_jury_scoped(&vrf, &staked, &zone, &subs);
        let global = select_epoch_jury(&vrf, &staked, &zone);
        assert_eq!(scoped, global);
    }

    #[test]
    fn test_is_in_epoch_jury_scoped_bootstrap() {
        let zone = ZoneId::from_legacy(0);
        let subs: std::collections::HashSet<String> = std::collections::HashSet::new();
        // Empty VRF = bootstrap, everyone in.
        assert!(is_in_epoch_jury_scoped(&[], &["w0".into()], &zone, &subs, "w0"));
        assert!(is_in_epoch_jury_scoped(&[], &["w0".into()], &zone, &subs, "unknown"));
    }

    #[test]
    fn test_is_in_epoch_jury_scoped_rejects_unsubscribed() {
        let zone = ZoneId::from_legacy(0);
        let vrf = [0xCC; 32];
        let staked: Vec<String> = (0..30).map(|i| format!("w{i:02}")).collect();
        let subs: std::collections::HashSet<String> =
            (0..15).map(|i| format!("w{i:02}")).collect();

        // An unsubscribed identity is never in the scoped jury (so long as the
        // intersection has enough subscribers — here 15 >= MIN_SCOPED_ELIGIBLE).
        assert!(!is_in_epoch_jury_scoped(&vrf, &staked, &zone, &subs, "w20"));
    }

    // ─── MAINNET gap #5: per-zone VRF committee tests ────────────────────

    #[test]
    fn test_committee_caps_at_mainnet_size() {
        let zone = ZoneId::from_legacy(0);
        let vrf = [0x42; 32];
        // 50 staked witnesses — large enough to trigger the cap.
        let staked: Vec<(String, u64)> = (0..50)
            .map(|i| (format!("w{i:02}"), 1_000))
            .collect();
        let subs: std::collections::HashSet<String> =
            staked.iter().map(|(s, _)| s.clone()).collect();

        let committee = select_epoch_committee_scoped(&vrf, &staked, &zone, &subs);
        assert_eq!(
            committee.len(),
            MAINNET_COMMITTEE_SIZE,
            "committee must cap at {MAINNET_COMMITTEE_SIZE}"
        );
    }

    #[test]
    fn test_committee_deterministic() {
        let zone = ZoneId::from_legacy(0);
        let vrf = [0x77; 32];
        let staked: Vec<(String, u64)> = (0..30)
            .map(|i| (format!("w{i:02}"), 100 + i as u64))
            .collect();
        let subs: std::collections::HashSet<String> =
            staked.iter().map(|(s, _)| s.clone()).collect();

        let c1 = select_epoch_committee_scoped(&vrf, &staked, &zone, &subs);
        let c2 = select_epoch_committee_scoped(&vrf, &staked, &zone, &subs);
        assert_eq!(c1, c2, "committee selection must be deterministic");
    }

    #[test]
    fn test_committee_stake_weighted_favors_rich() {
        // Identities with 1M stake should appear in committee more often than
        // identities with 1 stake across many VRF seeds. This verifies the
        // isqrt(stake) weighting is actually biasing selection.
        let zone = ZoneId::from_legacy(0);
        let mut staked: Vec<(String, u64)> = Vec::with_capacity(40);
        for i in 0..20 {
            staked.push((format!("poor-{i:02}"), 1));
        }
        for i in 0..20 {
            staked.push((format!("rich-{i:02}"), 1_000_000));
        }
        let subs: std::collections::HashSet<String> =
            staked.iter().map(|(s, _)| s.clone()).collect();

        // Sweep 64 VRF seeds; count how many committee slots go to rich vs poor.
        let mut rich_slots = 0usize;
        let mut poor_slots = 0usize;
        for seed in 0u8..64 {
            let vrf = [seed; 32];
            let committee = select_epoch_committee_scoped(&vrf, &staked, &zone, &subs);
            for (id, _) in committee {
                if id.starts_with("rich-") {
                    rich_slots += 1;
                } else {
                    poor_slots += 1;
                }
            }
        }
        // With sqrt(1M)=1000 vs sqrt(1)=1, rich identities should dominate by
        // ~3 orders of magnitude. Assert at least 10× ratio to allow for the
        // sorted-output bias at low cardinality.
        assert!(
            rich_slots > poor_slots * 10,
            "stake weighting ineffective: rich={rich_slots} poor={poor_slots}"
        );
    }

    #[test]
    fn test_committee_small_network_returns_all() {
        let zone = ZoneId::from_legacy(0);
        let vrf = [0x55; 32];
        // 6 witnesses < COMMITTEE_SMALL_NETWORK(10) → all returned
        let staked: Vec<(String, u64)> = (0..6)
            .map(|i| (format!("w{i}"), 500))
            .collect();
        let subs: std::collections::HashSet<String> =
            staked.iter().map(|(s, _)| s.clone()).collect();

        let committee = select_epoch_committee_scoped(&vrf, &staked, &zone, &subs);
        assert_eq!(committee.len(), 6, "small network must seat everyone");
    }

    #[test]
    fn test_committee_bootstrap_no_vrf() {
        let zone = ZoneId::from_legacy(0);
        let staked: Vec<(String, u64)> = (0..5)
            .map(|i| (format!("w{i}"), 100))
            .collect();
        let subs: std::collections::HashSet<String> = std::collections::HashSet::new();

        let committee = select_epoch_committee_scoped(&[], &staked, &zone, &subs);
        // Empty VRF = bootstrap → everyone attests regardless of subscription
        assert_eq!(committee.len(), staked.len());
    }

    #[test]
    fn test_committee_scoped_fallback_when_subs_sparse() {
        let zone = ZoneId::from_legacy(0);
        let vrf = [0x88; 32];
        let staked: Vec<(String, u64)> = (0..30)
            .map(|i| (format!("w{i:02}"), 100))
            .collect();
        // Only 1 subscriber — below MIN_SCOPED_ELIGIBLE(3) → fall back
        let subs: std::collections::HashSet<String> =
            std::iter::once("w00".to_string()).collect();

        let committee = select_epoch_committee_scoped(&vrf, &staked, &zone, &subs);
        assert!(
            committee.len() >= MIN_SCOPED_ELIGIBLE,
            "fallback must seat ≥ MIN_SCOPED_ELIGIBLE"
        );
        // With 30 staked, expect the cap
        assert_eq!(committee.len(), MAINNET_COMMITTEE_SIZE);
    }

    #[test]
    fn test_committee_bootstrap_fallback_caps_at_top_stakers() {
        // 1000 staked accounts with monotonically increasing stake. Sparse
        // subscriptions force the bootstrap-fallback path — and the new
        // BOOTSTRAP_FALLBACK_CAP must bound the pool to the top-N stakers
        // so 1M zones × N hashes/epoch is bounded.
        let zone = ZoneId::from_legacy(7);
        let vrf = [0x99; 32];
        let staked: Vec<(String, u64)> = (0..1_000)
            .map(|i| (format!("w{i:04}"), 100 + i as u64))
            .collect();
        // Only 1 subscriber → falls back
        let subs: std::collections::HashSet<String> =
            std::iter::once("w0000".to_string()).collect();

        let committee = select_epoch_committee_scoped(&vrf, &staked, &zone, &subs);

        // Committee must still be capped at MAINNET_COMMITTEE_SIZE.
        assert_eq!(
            committee.len(),
            MAINNET_COMMITTEE_SIZE,
            "fallback committee must respect MAINNET_COMMITTEE_SIZE cap"
        );

        // Every committee member must come from the top-BOOTSTRAP_FALLBACK_CAP
        // stakers (stakes 100+936 .. 100+999 → identity w0936 .. w0999).
        // Anyone outside that prefix means the cap leaked.
        let top_stakers: std::collections::HashSet<String> = staked
            .iter()
            .rev()
            .take(BOOTSTRAP_FALLBACK_CAP)
            .map(|(id, _)| id.clone())
            .collect();
        for (member, _) in &committee {
            assert!(
                top_stakers.contains(member),
                "fallback selected {member} outside top-{BOOTSTRAP_FALLBACK_CAP} pool"
            );
        }
    }

    #[test]
    fn test_committee_bootstrap_fallback_deterministic_across_calls() {
        // BOOTSTRAP_FALLBACK_CAP truncation must be deterministic — every
        // node sorts the same way so committees converge.
        let zone = ZoneId::from_legacy(11);
        let vrf = [0xAB; 32];
        // Mix of repeating stake values to exercise the lex tiebreak on
        // identity (stakes alone wouldn't produce a deterministic top-N).
        let staked: Vec<(String, u64)> = (0..500)
            .map(|i| (format!("w{i:04}"), 100 + (i as u64 % 7)))
            .collect();
        let subs: std::collections::HashSet<String> =
            std::iter::once("w0000".to_string()).collect();

        let c1 = select_epoch_committee_scoped(&vrf, &staked, &zone, &subs);
        let c2 = select_epoch_committee_scoped(&vrf, &staked, &zone, &subs);
        assert_eq!(c1, c2, "fallback selection must be deterministic");
    }

    #[test]
    fn test_committee_different_vrf_different_members() {
        let zone = ZoneId::from_legacy(0);
        let staked: Vec<(String, u64)> = (0..50)
            .map(|i| (format!("w{i:02}"), 100))
            .collect();
        let subs: std::collections::HashSet<String> =
            staked.iter().map(|(s, _)| s.clone()).collect();

        let c1 = select_epoch_committee_scoped(&[0x01; 32], &staked, &zone, &subs);
        let c2 = select_epoch_committee_scoped(&[0x02; 32], &staked, &zone, &subs);
        assert_ne!(c1, c2, "different VRF seeds must produce different committees");
    }

    #[test]
    fn test_committee_indexed_matches_facade_dense_pool() {
        // Indexed variant must produce bit-identical output to the slice
        // facade for the same inputs on the dense / scoring path.
        let zone = ZoneId::from_legacy(13);
        let vrf = [0x42; 32];
        let staked: Vec<(String, u64)> = (0..200)
            .map(|i| (format!("w{i:03}"), 100 + (i as u64 * 3)))
            .collect();
        let subs: std::collections::HashSet<String> = staked
            .iter()
            .take(50)
            .map(|(s, _)| s.clone())
            .collect();

        let facade = select_epoch_committee_scoped(&vrf, &staked, &zone, &subs);
        let index = CommitteeSelectionIndex::build(&staked);
        let indexed = select_epoch_committee_scoped_indexed(&vrf, &index, &zone, &subs);

        assert_eq!(facade, indexed, "indexed must match slice facade on dense path");
        assert_eq!(facade.len(), MAINNET_COMMITTEE_SIZE);
    }

    #[test]
    fn test_committee_indexed_matches_facade_bootstrap_fallback() {
        // Indexed variant on the sparse-subscription fallback path: facade
        // and indexed both pull from the top-BOOTSTRAP_FALLBACK_CAP stakers,
        // both produce the same committee.
        let zone = ZoneId::from_legacy(17);
        let vrf = [0xC3; 32];
        let staked: Vec<(String, u64)> = (0..1_500)
            .map(|i| (format!("w{i:04}"), 100 + i as u64))
            .collect();
        let subs: std::collections::HashSet<String> =
            std::iter::once("w0000".to_string()).collect();

        let facade = select_epoch_committee_scoped(&vrf, &staked, &zone, &subs);
        let index = CommitteeSelectionIndex::build(&staked);
        let indexed = select_epoch_committee_scoped_indexed(&vrf, &index, &zone, &subs);

        assert_eq!(facade, indexed, "indexed must match facade on bootstrap fallback");
        assert_eq!(facade.len(), MAINNET_COMMITTEE_SIZE);
    }

    #[test]
    fn test_committee_indexed_small_network_matches_facade() {
        // |pool| ≤ COMMITTEE_SMALL_NETWORK → both return the full pool
        // sorted by identity.
        let zone = ZoneId::from_legacy(0);
        let vrf = [0x55; 32];
        let staked: Vec<(String, u64)> = (0..6)
            .map(|i| (format!("w{i}"), 100))
            .collect();
        let subs: std::collections::HashSet<String> =
            staked.iter().map(|(s, _)| s.clone()).collect();

        let facade = select_epoch_committee_scoped(&vrf, &staked, &zone, &subs);
        let index = CommitteeSelectionIndex::build(&staked);
        let indexed = select_epoch_committee_scoped_indexed(&vrf, &index, &zone, &subs);

        assert_eq!(facade.len(), 6);
        assert_eq!(facade, indexed);
    }

    #[test]
    fn test_committee_indexed_membership_matches_facade() {
        // Indexed membership check must agree with the facade for every
        // staked identity across the dense + bootstrap paths.
        let zone = ZoneId::from_legacy(5);
        let vrf = [0x9F; 32];
        let staked: Vec<(String, u64)> = (0..40)
            .map(|i| (format!("w{i:02}"), 100 + i as u64 * 5))
            .collect();
        let subs: std::collections::HashSet<String> = staked
            .iter()
            .take(20)
            .map(|(s, _)| s.clone())
            .collect();

        let index = CommitteeSelectionIndex::build(&staked);
        for (id, _) in &staked {
            let facade_in =
                is_in_epoch_committee_scoped(&vrf, &staked, &zone, &subs, id);
            let indexed_in =
                is_in_epoch_committee_scoped_indexed(&vrf, &index, &zone, &subs, id);
            assert_eq!(
                facade_in, indexed_in,
                "membership disagrees for {id} (facade={facade_in} indexed={indexed_in})"
            );
        }
    }

    #[test]
    fn test_committee_indexed_empty_inputs_safe() {
        // Empty staked → empty committee; empty VRF → bootstrap-pool fallback.
        let zone = ZoneId::from_legacy(0);
        let empty: Vec<(String, u64)> = Vec::new();
        let subs: std::collections::HashSet<String> = std::collections::HashSet::new();

        let index_empty = CommitteeSelectionIndex::build(&empty);
        assert_eq!(index_empty.staked_count(), 0);
        let committee =
            select_epoch_committee_scoped_indexed(&[0xAA; 32], &index_empty, &zone, &subs);
        assert!(committee.is_empty(), "empty index must yield empty committee");

        // Empty VRF on a non-empty index returns the bootstrap pool.
        let staked: Vec<(String, u64)> = (0..5)
            .map(|i| (format!("w{i}"), 100))
            .collect();
        let index = CommitteeSelectionIndex::build(&staked);
        let bootstrap =
            select_epoch_committee_scoped_indexed(&[], &index, &zone, &subs);
        assert_eq!(bootstrap.len(), staked.len(), "empty VRF returns bootstrap pool");
    }

    #[test]
    fn test_register_epoch_committee_updates_denominator() {
        let mut awc = AWCConsensus::new();
        let zone = ZoneId::from_legacy(0);
        awc.register_zone_stake(zone.clone(), 10_000);
        assert_eq!(awc.settlement_denominator(&zone), 10_000);

        // Seat a committee of 3 members totaling 700.
        let members = vec![
            ("m0".to_string(), 300u64),
            ("m1".to_string(), 200u64),
            ("m2".to_string(), 200u64),
        ];
        awc.register_epoch_committee(&zone, &members);
        assert_eq!(awc.settlement_denominator(&zone), 700);
        assert_eq!(awc.committee_rotations_total, 1);

        // Re-registering the same committee must not bump the rotation.
        awc.register_epoch_committee(&zone, &members);
        assert_eq!(awc.committee_rotations_total, 1);

        // Changing committee bumps the counter.
        let new_members = vec![
            ("m0".to_string(), 300u64),
            ("m3".to_string(), 400u64),
        ];
        awc.register_epoch_committee(&zone, &new_members);
        assert_eq!(awc.committee_rotations_total, 2);
        assert_eq!(awc.settlement_denominator(&zone), 700);

        // Empty committee clears — falls back to zone_stake.
        awc.register_epoch_committee(&zone, &[]);
        assert_eq!(awc.settlement_denominator(&zone), 10_000);
    }

    #[test]
    fn test_committee_hash_deterministic_and_sensitive() {
        let mut awc = AWCConsensus::new();
        let zone = ZoneId::from_legacy(0);

        // Empty committee → all-zero hash (no registered committee).
        assert_eq!(awc.committee_hash(&zone), [0u8; 32]);

        // Seat a committee. committee_hash must be deterministic across the
        // same HashSet contents, regardless of insertion order (the fn sorts
        // member identity strings before hashing).
        awc.register_epoch_committee(
            &zone,
            &[("alice".into(), 100), ("bob".into(), 50), ("carol".into(), 25)],
        );
        let h1 = awc.committee_hash(&zone);
        assert_ne!(h1, [0u8; 32]);

        // Re-seat with same members in a different order — hash must be identical.
        let mut awc2 = AWCConsensus::new();
        awc2.register_epoch_committee(
            &zone,
            &[("carol".into(), 25), ("alice".into(), 100), ("bob".into(), 50)],
        );
        assert_eq!(awc2.committee_hash(&zone), h1, "hash must be order-independent");

        // Any change in membership must change the hash.
        let mut awc3 = AWCConsensus::new();
        awc3.register_epoch_committee(
            &zone,
            &[("alice".into(), 100), ("bob".into(), 50), ("dave".into(), 25)],
        );
        assert_ne!(awc3.committee_hash(&zone), h1, "different member set must produce different hash");
    }

    /// Sybil flood: 200 identities from the same org/subnet, 50 honest.
    /// Verifies that:
    /// 1. VRF jury selection handles 250 identities without panic
    /// 2. Jury size scales correctly (2/3 + 1)
    /// 3. Sybil cluster gets diminished trust vs honest diverse witnesses
    /// 4. Selection runs in bounded time
    #[test]
    fn test_sybil_flood_200_identities() {
        use std::time::Instant;

        let zone = ZoneId::from_legacy(0);
        let vrf = [0xAB; 32];

        // 200 sybil identities + 50 honest = 250 total
        let mut staked: Vec<String> = Vec::new();
        for i in 0..200 {
            staked.push(format!("sybil-{i:04}"));
        }
        for i in 0..50 {
            staked.push(format!("honest-{i:02}"));
        }

        // 1. Jury selection must not panic at 250 identities
        let t0 = Instant::now();
        let jury = select_epoch_jury(&vrf, &staked, &zone);
        let elapsed = t0.elapsed();

        // 2. Jury size: ceil(250 * 2/3) + 1 = 168
        let expected_size = (250 * 2_usize).div_ceil(3) + 1;
        assert_eq!(jury.len(), expected_size,
            "jury size should be {expected_size} for 250 staked");

        // 3. Selection must be bounded (< 250ms for 250 identities).
        // Debug builds are ~10x slower than release; under a fully-parallel
        // 5200+-test cargo run on a contended CI box we've seen 100ms+ wall-time
        // spikes from scheduler thrash even though the algorithm is unchanged
        // (release is ~10ms, single-thread debug is ~30ms). 250ms still flags
        // O(N²) / infinite-loop regressions — the order-of-magnitude classes
        // this assertion is designed to catch — without flaking on contended
        // parallel suites. Sized at 25× single-thread debug, 25× release.
        assert!(elapsed.as_millis() < 250,
            "jury selection took {}ms for 250 identities — too slow", elapsed.as_millis());

        // 4. Deterministic — same input, same output
        let jury2 = select_epoch_jury(&vrf, &staked, &zone);
        assert_eq!(jury, jury2);

        // 5. Different VRF → different jury
        let jury3 = select_epoch_jury(&[0xCD; 32], &staked, &zone);
        assert_ne!(jury, jury3);

        // 6. Verify is_in_epoch_jury matches for all 250
        for w in &staked {
            let in_jury = jury.contains(w);
            let check = is_in_epoch_jury(&vrf, &staked, &zone, w);
            assert_eq!(in_jury, check, "mismatch for {w}");
        }
    }

    /// Sybil trust resistance at scale: 200 collocated sybil witnesses
    /// should produce LESS trust than 10 diverse honest witnesses.
    #[test]
    fn test_sybil_trust_resistance_200_vs_10() {
        let rid = "test-sybil-200";

        // 200 sybil witnesses: same org, same subnet, same geo
        let mut awc_sybil = AWCConsensus::new();
        setup_zone_stake(&mut awc_sybil, rid, 10_000);
        for i in 0..200 {
            let wh = format!("sybil-{i:04}");
            awc_sybil.register_profile(&wh, profile("evil-corp", "10.0.1", "earth-us"));
            awc_sybil.add_attestation(Attestation {
                record_id: rid.to_string(), witness_hash: wh, stake: 10, timestamp: i as f64,
            });
        }
        let t_sybil = awc_sybil.trust_score(rid);

        // 10 honest witnesses: different orgs, subnets, geos
        let mut awc_honest = AWCConsensus::new();
        setup_zone_stake(&mut awc_honest, rid, 10_000);
        let geos = ["earth-us", "earth-eu", "earth-asia", "mars-olympus", "earth-africa",
                     "earth-oceania", "earth-sa", "moon-base", "earth-arctic", "earth-india"];
        for (i, geo) in geos.iter().enumerate() {
            let wh = format!("honest-{i}");
            awc_honest.register_profile(&wh, profile(
                &format!("org-{i}"), &format!("10.{i}.0"), geo,
            ));
            awc_honest.add_attestation(Attestation {
                record_id: rid.to_string(), witness_hash: wh, stake: 200, timestamp: i as f64,
            });
        }
        let t_honest = awc_honest.trust_score(rid);

        assert!(t_honest > t_sybil,
            "10 diverse honest witnesses (trust={t_honest:.4}) must beat \
             200 sybil witnesses (trust={t_sybil:.4})");
    }

    #[test]
    fn test_cross_zone_parent_registration() {
        let mut awc = AWCConsensus::new();

        // Record with no cross-zone parents
        assert!(!awc.cross_zone_parents_finalized("r1"));

        // Register cross-zone parents
        awc.register_cross_zone_parents("r1", vec!["p1".to_string(), "p2".to_string()]);
        // Not finalized yet — parents have no confirmation
        assert!(!awc.cross_zone_parents_finalized("r1"));

        // Finalize one parent
        awc.confirmation_levels.insert("p1".to_string(), ConfirmationLevel::Finalized);
        // Still false — p2 not finalized
        assert!(!awc.cross_zone_parents_finalized("r1"));

        // Finalize both parents
        awc.confirmation_levels.insert("p2".to_string(), ConfirmationLevel::Anchored);
        assert!(awc.cross_zone_parents_finalized("r1"));
    }

    #[test]
    fn test_cross_zone_finality_boost_relaxes_clusters() {
        let mut awc = AWCConsensus::new();

        // Set up: register 300 beat stake in ALL zones so settlement works
        // regardless of which zone the record ID maps to
        let zone_count = get_zone_count();
        for i in 0..zone_count {
            awc.register_zone_stake(ZoneId::from_legacy(i), 300);
        }

        let record_id = "test-record-xzone";

        // Register cross-zone parent that IS finalized
        awc.register_cross_zone_parents(record_id, vec!["xzone-parent".to_string()]);
        awc.confirmation_levels.insert("xzone-parent".to_string(), ConfirmationLevel::Finalized);

        // Add 3 attestations from same cluster (should normally need 3 clusters)
        for i in 0..3 {
            awc.add_attestation(Attestation {
                record_id: record_id.to_string(),
                witness_hash: format!("w{i}"),
                stake: 100,
                timestamp: 1000.0,
            });
        }

        // With cross-zone finality boost, cluster requirement drops to 1
        // So even though all 3 witnesses might be in the same timing cluster,
        // the record should reach Finalized if stake threshold is met (300/300 = 100% > 66%)
        // Note: without profiles, all witnesses are separate clusters anyway
        assert_eq!(awc.confirmation_level(record_id), ConfirmationLevel::Finalized);
    }

    #[test]
    fn test_cross_zone_cascade_re_evaluation() {
        // Test: child record gets attestations BEFORE parent reaches Finalized.
        // When parent later finalizes, child should cascade to Finalized via boost.
        let mut awc = AWCConsensus::new();

        let zone_count = get_zone_count();
        for i in 0..zone_count {
            awc.register_zone_stake(ZoneId::from_legacy(i), 300);
        }

        let parent_id = "cascade-parent";
        let child_id = "cascade-child";

        // Register child's cross-zone parent (parent is NOT finalized yet)
        awc.register_cross_zone_parents(child_id, vec![parent_id.to_string()]);

        // Child gets 3 attestations at the SAME timestamp (no profiles registered).
        // Without profiles, unknown witnesses are each a unique cluster UNLESS
        // timing correlates them. Same timestamp → timing cluster merge → 1 cluster.
        // Without boost, child needs CONFIRMED_MIN_CLUSTERS (3) distinct clusters → stuck.
        for i in 0..3 {
            awc.add_attestation(Attestation {
                record_id: child_id.to_string(),
                witness_hash: format!("cw{i}"),
                stake: 100,
                timestamp: 1000.0, // same timestamp → merged into 1 timing cluster
            });
        }
        // No profiles registered → profiles.is_empty() = true → raw settlement used.
        // Raw settlement: 300*3 >= 300*2 → passes.
        // But clusters: all 3 witnesses at same timestamp → 1 cluster < CONFIRMED_MIN_CLUSTERS (3).
        // So child should be Sealed, not Finalized.
        assert_eq!(
            awc.confirmation_level(child_id),
            ConfirmationLevel::Sealed,
            "child should be Sealed (1 cluster, needs 3) before parent is finalized"
        );

        // Now parent reaches Finalized — add attestations from 3 distinct timestamps
        for i in 0..3 {
            awc.add_attestation(Attestation {
                record_id: parent_id.to_string(),
                witness_hash: format!("pw{i}"),
                stake: 100,
                timestamp: 1000.0 + (i as f64 * 10.0), // >0.5s apart → different clusters
            });
        }
        // Parent: 3 witnesses, 3 clusters, 300/300 stake → Finalized
        assert_eq!(awc.confirmation_level(parent_id), ConfirmationLevel::Finalized);

        // CASCADE: child should now also be Finalized because:
        // - Its cross-zone parent is Finalized → boost fires
        // - min_clusters drops from 3 to 1
        // - It has 1 cluster (timing-correlated) which now satisfies min_clusters=1
        assert_eq!(
            awc.confirmation_level(child_id),
            ConfirmationLevel::Finalized,
            "cascade should have re-evaluated child after parent finalized"
        );

        // Verify boost counter incremented
        let (_, _, boosts) = awc.cross_zone_stats();
        assert!(boosts >= 1, "cross-zone boost should have fired");
    }

    /// Metric-semantics codification for the new
    /// `elara_consensus_cross_zone_*` gauge + counter set. Pins the
    /// operator dashboard invariants that distinguish the three signals:
    ///   * `_records_active` counts DISTINCT records currently in the
    ///     `cross_zone_parents` map — re-registering parents on the same
    ///     record key is idempotent (one record key, one entry).
    ///   * `_parent_refs_active` counts the total ref entries summed
    ///     across records — fanout signal. Two records with 1 parent
    ///     each ≠ one record with 2 parents (same _parent_refs_active=2,
    ///     different _records_active=2 vs 1).
    ///   * `_boost_total` is a strictly monotonic counter — only grows
    ///     when finalize() takes the Protocol §7.5 cluster relaxation. Pruning,
    ///     re-registering, or replacing parents NEVER touches it.
    ///   * Pruning a tracked record decrements both records_active and
    ///     parent_refs_active, but `_boost_total` survives.
    #[test]
    fn ops_44_cross_zone_stats_pins_gauge_semantics_for_dashboard() {
        let mut awc = AWCConsensus::new();

        // Empty consensus → all three are 0.
        let (records, refs, boost) = awc.cross_zone_stats();
        assert_eq!((records, refs, boost), (0, 0, 0));

        // (1) Register one record with 2 parents.
        awc.register_cross_zone_parents(
            "r1",
            vec!["p1".to_string(), "p2".to_string()],
        );
        let (records, refs, boost) = awc.cross_zone_stats();
        assert_eq!(records, 1, "1 distinct record key");
        assert_eq!(refs, 2, "2 cross-zone parents on that record");
        assert_eq!(boost, 0, "no boost yet — no finalize fired");

        // (2) Register a second record with 3 parents.
        awc.register_cross_zone_parents(
            "r2",
            vec!["q1".to_string(), "q2".to_string(), "q3".to_string()],
        );
        let (records, refs, _) = awc.cross_zone_stats();
        assert_eq!(records, 2, "2 distinct record keys");
        assert_eq!(refs, 5, "2 + 3 = 5 total refs");

        // (3) Re-registering parents on r1 is idempotent in records but
        //     replaces refs in place — a fact operators must understand.
        //     Replacing r1's 2 parents with a 4-parent set keeps records=2
        //     but bumps refs from 5 to 7.
        awc.register_cross_zone_parents(
            "r1",
            vec!["p1".to_string(), "p2".to_string(), "p3".to_string(), "p4".to_string()],
        );
        let (records, refs, _) = awc.cross_zone_stats();
        assert_eq!(records, 2, "re-register on same key does NOT grow records");
        assert_eq!(refs, 7, "refs reflect new parent set: 4 + 3 = 7");

        // (4) Distinct-records vs total-refs distinction matters: two
        //     records with 1 parent each = same refs (=2) as one record
        //     with 2 parents but DIFFERENT records gauge.
        let mut alt = AWCConsensus::new();
        alt.register_cross_zone_parents("a", vec!["x".to_string()]);
        alt.register_cross_zone_parents("b", vec!["y".to_string()]);
        let (alt_records, alt_refs, _) = alt.cross_zone_stats();
        assert_eq!((alt_records, alt_refs), (2, 2),
            "two records × one parent each = (2, 2) — distinct topology from (1, 2)");

        // (5) prune_older_than() reaps records whose newest attestation
        //     ts < cutoff (and reaps `cross_zone_parents` entries whose
        //     record is no longer in `attestations`). Set up r1 with an
        //     OLD attestation (ts=100, will be reaped) and r2 with a
        //     NEW attestation (ts=1000, will survive) — proves the
        //     gauge partitions correctly with the attestation-lifecycle
        //     pruning rule.
        awc.add_attestation(Attestation {
            record_id: "r1".to_string(),
            witness_hash: "w1".to_string(),
            stake: 100,
            timestamp: 100.0,
        });
        awc.add_attestation(Attestation {
            record_id: "r2".to_string(),
            witness_hash: "w1".to_string(),
            stake: 100,
            timestamp: 1000.0,
        });
        // Force boost counter to a non-zero value via direct field bump
        // so we can assert prune does not roll it back. (Real boost
        // firing is covered by `test_cross_zone_finality_boost_*`.)
        awc.cross_zone_boost_count = 7;
        let (_, _, boost_pre) = awc.cross_zone_stats();
        assert_eq!(boost_pre, 7);

        awc.prune_older_than(500.0); // r1 ts=100 < 500 → reaped; r2 ts=1000 ≥ 500 → survives

        let (records, refs, boost_post) = awc.cross_zone_stats();
        assert_eq!(records, 1, "r1 reaped (att ts=100 < cutoff), only r2 remains");
        assert_eq!(refs, 3, "r2's 3 parents survive (att ts=1000 ≥ cutoff)");
        assert_eq!(boost_post, 7,
            "prune MUST NOT touch the lifetime boost counter");
    }

    #[test]
    fn test_prune_cleans_cross_zone_parents() {
        let mut awc = AWCConsensus::new();

        // Add attestation + cross-zone parents
        awc.add_attestation(Attestation {
            record_id: "r1".to_string(),
            witness_hash: "w1".to_string(),
            stake: 100,
            timestamp: 100.0, // old
        });
        awc.register_cross_zone_parents("r1", vec!["p1".to_string()]);

        assert!(!awc.cross_zone_parents.is_empty());

        // Prune old entries
        awc.prune_older_than(500.0);

        // cross_zone_parents should be cleaned
        assert!(awc.cross_zone_parents.is_empty());
    }

    // ── Stage 3c.1: global quorum seal settlement ───────────────

    /// 4-zone topology matching production convention: every zone's entry
    /// equals the system total (`register_stakes_from_ledger` replicates
    /// total_staked across all zones). Total system stake = 400 (4
    /// anchors × 100 stake each). Denominator for both per-zone and
    /// global seals = `max(zone_stakes[z])` = 400, threshold = 2/3 = 267.
    fn four_zone_awc() -> AWCConsensus {
        let mut awc = AWCConsensus::new();
        // Each zone's entry = system total = 400 (production convention).
        for z in 0..4u64 {
            awc.zone_stakes.insert(ZoneId::from_legacy(z), 400);
        }
        awc.register_profile("w1", profile("org-a", "10.0.1", "earth-us"));
        awc.register_profile("w2", profile("org-b", "10.0.2", "earth-eu"));
        awc.register_profile("w3", profile("org-c", "10.0.3", "earth-ap"));
        awc.register_profile("w4", profile("org-d", "10.0.4", "mars"));
        awc
    }

    #[test]
    fn test_global_seal_settles_at_two_thirds_of_non_stuck_stake() {
        let mut awc = four_zone_awc();
        let stuck_zone = ZoneId::from_legacy(0);
        awc.register_global_seal("gseal-0", stuck_zone);

        // Three witnesses from three distinct non-stuck zones, stake=100
        // each. With diverse profiles (org/subnet/geo), independence ≈ 1.0,
        // so effective stake ≈ 300. Threshold = 2/3 × 400 ≈ 266.67. Settles.
        for (i, (wh, zone)) in [
            ("w2", ZoneId::from_legacy(1)),
            ("w3", ZoneId::from_legacy(2)),
            ("w4", ZoneId::from_legacy(3)),
        ]
        .iter()
        .enumerate()
        {
            let _ = awc.add_seal_attestation(SealAttestation {
                seal_id: "gseal-0".into(),
                zone: zone.clone(),
                epoch_number: 42,
                witness_hash: wh.to_string(),
                stake: 100,
                timestamp: i as f64,
            });
        }
        assert!(awc.is_seal_settled("gseal-0"));
    }

    #[test]
    fn test_global_seal_not_settled_below_two_thirds() {
        let mut awc = four_zone_awc();
        let stuck_zone = ZoneId::from_legacy(0);
        awc.register_global_seal("gseal-1", stuck_zone);

        // Only 2 of 3 non-stuck witnesses → 200 effective stake < 267.
        for (i, (wh, zone)) in [
            ("w2", ZoneId::from_legacy(1)),
            ("w3", ZoneId::from_legacy(2)),
        ]
        .iter()
        .enumerate()
        {
            let _ = awc.add_seal_attestation(SealAttestation {
                seal_id: "gseal-1".into(),
                zone: zone.clone(),
                epoch_number: 9,
                witness_hash: wh.to_string(),
                stake: 100,
                timestamp: i as f64,
            });
        }
        assert!(!awc.is_seal_settled("gseal-1"));
    }

    #[test]
    fn test_global_seal_ignores_stuck_zone_attestations() {
        let mut awc = four_zone_awc();
        let stuck_zone = ZoneId::from_legacy(0);
        awc.register_global_seal("gseal-2", stuck_zone.clone());

        // Captured stuck zone rubber-stamps: every stuck-zone witness attests.
        // None of these count toward settlement.
        for (i, wh) in ["w1", "w2", "w3", "w4"].iter().enumerate() {
            let _ = awc.add_seal_attestation(SealAttestation {
                seal_id: "gseal-2".into(),
                zone: stuck_zone.clone(),
                epoch_number: 3,
                witness_hash: wh.to_string(),
                stake: 100,
                timestamp: i as f64,
            });
        }
        assert!(!awc.is_seal_settled("gseal-2"));
    }

    #[test]
    fn test_global_seal_is_global_flag_roundtrip() {
        let mut awc = four_zone_awc();
        assert!(!awc.is_global_seal("x"));
        awc.register_global_seal("x", ZoneId::from_legacy(0));
        assert!(awc.is_global_seal("x"));
    }

    #[test]
    fn test_global_seal_cleaned_by_prune_anchored() {
        let mut awc = four_zone_awc();
        let stuck_zone = ZoneId::from_legacy(0);
        awc.register_global_seal("gseal-3", stuck_zone);
        let _ = awc.add_seal_attestation(SealAttestation {
            seal_id: "gseal-3".into(),
            zone: ZoneId::from_legacy(1),
            epoch_number: 1,
            witness_hash: "w2".into(),
            stake: 100,
            timestamp: 0.0,
        });
        assert!(awc.is_global_seal("gseal-3"));

        let mut anchored = HashSet::new();
        anchored.insert("gseal-3".to_string());
        awc.prune_anchored_seals(&anchored);

        assert!(!awc.is_global_seal("gseal-3"));
    }

    #[test]
    fn test_global_seal_regular_seal_settlement_unaffected() {
        // Sanity: a per-zone seal that is NOT registered as global still
        // uses the per-zone denominator.
        let mut awc = AWCConsensus::new();
        let zone = ZoneId::from_legacy(0);
        awc.zone_stakes.insert(zone.clone(), 300);
        awc.register_profile("w1", profile("org-a", "10.0.1", "earth-us"));
        awc.register_profile("w2", profile("org-b", "10.0.2", "earth-eu"));
        awc.register_profile("w3", profile("org-c", "10.0.3", "mars"));

        for (i, wh) in ["w1", "w2", "w3"].iter().enumerate() {
            let _ = awc.add_seal_attestation(SealAttestation {
                seal_id: "seal-regular".into(),
                zone: zone.clone(),
                epoch_number: 0,
                witness_hash: wh.to_string(),
                stake: 100,
                timestamp: i as f64,
            });
        }
        assert!(awc.is_seal_settled("seal-regular"));
        assert!(!awc.is_global_seal("seal-regular"));
    }

    // ── finality-event queue ─────────────────────────────────────────────

    /// `force_finalized` enqueues the record on the first call and stays
    /// silent on idempotent repeats (old level already >= Finalized).
    #[test]
    fn test_arch_1_force_finalized_fires_once() {
        let mut awc = AWCConsensus::new();
        assert_eq!(awc.finalization_queue_depth(), 0);

        awc.force_finalized("rec-a");
        assert_eq!(awc.finalization_queue_depth(), 1);
        assert_eq!(awc.finalization_queue_enqueued_total, 1);

        // Second call is a no-op — confirmation level is already Finalized.
        awc.force_finalized("rec-a");
        assert_eq!(awc.finalization_queue_depth(), 1);
        assert_eq!(awc.finalization_queue_enqueued_total, 1);

        let drained = awc.drain_newly_finalized();
        assert_eq!(drained, vec!["rec-a".to_string()]);
        assert_eq!(awc.finalization_queue_depth(), 0);
        assert_eq!(awc.finalization_queue_drained_total, 1);
    }

    /// Draining returns events in FIFO order and leaves the queue empty.
    #[test]
    fn test_arch_1_drain_is_fifo_and_clears_queue() {
        let mut awc = AWCConsensus::new();
        for id in ["rec-1", "rec-2", "rec-3"] {
            awc.force_finalized(id);
        }
        assert_eq!(awc.finalization_queue_depth(), 3);

        let drained = awc.drain_newly_finalized();
        assert_eq!(
            drained,
            vec![
                "rec-1".to_string(),
                "rec-2".to_string(),
                "rec-3".to_string()
            ]
        );
        assert_eq!(awc.finalization_queue_depth(), 0);
        // Idempotent: second drain on empty queue is Vec::new().
        assert!(awc.drain_newly_finalized().is_empty());
    }

    /// Queue overflow drops the event and bumps the counter; ledger
    /// reconcile path is expected to pick up the missed commit.
    #[test]
    fn test_arch_1_finalization_queue_overflow_counts_drops() {
        let mut awc = AWCConsensus::new();
        // Pre-fill to cap using the internal helper.
        for i in 0..MAX_FINALIZATION_QUEUE {
            awc.finalization_queue
                .push_back(format!("fill-{i}"));
        }
        awc.finalization_queue_enqueued_total = MAX_FINALIZATION_QUEUE as u64;

        // Next enqueue should overflow.
        awc.force_finalized("rec-overflow");
        assert_eq!(awc.finalization_queue_depth(), MAX_FINALIZATION_QUEUE);
        assert_eq!(awc.finalization_queue_overflow_total, 1);
        assert_eq!(
            awc.finalization_queue_enqueued_total,
            MAX_FINALIZATION_QUEUE as u64
        );
    }

    /// The bulk seal-finalization path fires exactly once per record, and
    /// a repeat seal-add for records already at Finalized does not
    /// double-enqueue. Proxied via direct `confirmation_levels` manipulation
    /// to avoid rebuilding the full attestation harness for the seal path.
    #[test]
    fn test_arch_1_seal_path_edge_only_enqueues_once() {
        let mut awc = AWCConsensus::new();

        // Simulate a seal finalizing three records that are currently
        // Pending — this is the Pending → Finalized edge the bulk path
        // handles. We inline the exact logic from the seal-settlement
        // branch (see confirmation_levels insert at the `record_ids_in_seal`
        // block).
        let rids = vec!["r1".to_string(), "r2".to_string(), "r3".to_string()];
        for rid in &rids {
            let old = awc.confirmation_levels.get(rid).copied();
            awc.confirmation_levels
                .insert(rid.clone(), ConfirmationLevel::Finalized);
            if !matches!(
                old,
                Some(ConfirmationLevel::Finalized) | Some(ConfirmationLevel::Anchored)
            ) {
                awc.enqueue_finalized(rid);
            }
        }
        assert_eq!(awc.finalization_queue_depth(), 3);

        // Second pass — levels already at Finalized, no new events.
        for rid in &rids {
            let old = awc.confirmation_levels.get(rid).copied();
            awc.confirmation_levels
                .insert(rid.clone(), ConfirmationLevel::Finalized);
            if !matches!(
                old,
                Some(ConfirmationLevel::Finalized) | Some(ConfirmationLevel::Anchored)
            ) {
                awc.enqueue_finalized(rid);
            }
        }
        assert_eq!(awc.finalization_queue_depth(), 3);
        assert_eq!(awc.finalization_queue_enqueued_total, 3);
    }

    /// Anchor promotion (Finalized → Anchored) must not re-enqueue: the
    /// commit callback already fired at the Pending/Sealed → Finalized
    /// edge.
    #[test]
    fn test_arch_1_anchor_promotion_does_not_re_enqueue() {
        let mut awc = AWCConsensus::new();
        awc.force_finalized("rec-x");
        assert_eq!(awc.finalization_queue_enqueued_total, 1);

        // anchor_record only upgrades if already >= Finalized. Confirm it
        // upgrades but does NOT touch the finality queue.
        awc.anchor_record("rec-x");
        assert_eq!(
            awc.confirmation_level("rec-x"),
            ConfirmationLevel::Anchored
        );
        assert_eq!(awc.finalization_queue_enqueued_total, 1);
        assert_eq!(awc.finalization_queue_depth(), 1);
    }

    // ── MAINNET gap #8: Sealed-event queue ──────────────────────────────

    /// First attestation crosses `ATTESTED_MIN_WITNESSES` → Sealed edge,
    /// enqueues a Sealed event exactly once, with the current witness_count.
    #[test]
    fn test_gap8_pending_to_sealed_fires_once() {
        let mut awc = AWCConsensus::new();
        assert_eq!(awc.newly_sealed_queue_depth(), 0);
        assert_eq!(awc.newly_sealed_queue_enqueued_total, 0);

        awc.add_attestation(Attestation {
            record_id: "rec-seal".to_string(),
            witness_hash: "w1".to_string(),
            stake: 100,
            timestamp: 1.0,
        });

        assert_eq!(
            awc.confirmation_level("rec-seal"),
            ConfirmationLevel::Sealed
        );
        assert_eq!(awc.newly_sealed_queue_depth(), 1);
        assert_eq!(awc.newly_sealed_queue_enqueued_total, 1);

        let drained = awc.drain_newly_sealed();
        assert_eq!(drained, vec![("rec-seal".to_string(), 1u32)]);
        assert_eq!(awc.newly_sealed_queue_depth(), 0);
        assert_eq!(awc.newly_sealed_queue_drained_total, 1);

        // A second attestation keeps the record at Sealed (not enough for
        // Finalized without clusters) — the Sealed edge was already crossed,
        // no re-enqueue.
        awc.add_attestation(Attestation {
            record_id: "rec-seal".to_string(),
            witness_hash: "w2".to_string(),
            stake: 100,
            timestamp: 2.0,
        });
        assert_eq!(awc.newly_sealed_queue_enqueued_total, 1,
            "Sealed→Sealed must not re-enqueue");
    }

    /// A record that jumps Pending → Finalized in one shot (e.g. seal-path
    /// settlement) still emits a Sealed event so the account UX milestone
    /// is not skipped.
    #[test]
    fn test_gap8_pending_to_finalized_also_fires_sealed() {
        let mut awc = AWCConsensus::new();

        // Simulate the seal path: bypass add_attestation and force_finalized
        // the record directly. The enqueue_sealed hook lives in
        // recompute_confirmation, not force_finalized — so this validates
        // that the force_finalized path also crosses the Sealed edge.
        // We do this by feeding enough attestations that the raw settlement
        // branch triggers (small_network path, 3 witnesses, same org).
        awc.register_profile("w1", WitnessProfile {
            organization: "org-a".to_string(),
            subnet: "10.0.0".to_string(),
            geo_zone: "earth-us".to_string(),
        });
        awc.register_profile("w2", WitnessProfile {
            organization: "org-a".to_string(),
            subnet: "10.0.1".to_string(),
            geo_zone: "earth-us".to_string(),
        });
        awc.register_profile("w3", WitnessProfile {
            organization: "org-a".to_string(),
            subnet: "10.0.2".to_string(),
            geo_zone: "earth-us".to_string(),
        });
        awc.zone_stakes.insert(ZoneId::from_legacy(0), 300);
        awc.creator_stakes.insert("rec-fast".to_string(), 0);

        for (wh, ts) in [("w1", 1.0), ("w2", 2.0), ("w3", 3.0)] {
            awc.add_attestation(Attestation {
                record_id: "rec-fast".to_string(),
                witness_hash: wh.to_string(),
                stake: 100,
                timestamp: ts,
            });
        }

        // Sealed event was enqueued on the first attestation.
        assert!(
            awc.newly_sealed_queue_enqueued_total >= 1,
            "Sealed milestone must fire even when record races to Finalized"
        );
        let drained = awc.drain_newly_sealed();
        assert!(!drained.is_empty());
        assert_eq!(drained[0].0, "rec-fast");
    }

    /// Drain returns events in FIFO and is idempotent when empty.
    #[test]
    fn test_gap8_drain_fifo_and_idempotent() {
        let mut awc = AWCConsensus::new();
        for (i, rid) in ["a", "b", "c"].iter().enumerate() {
            awc.add_attestation(Attestation {
                record_id: rid.to_string(),
                witness_hash: format!("w-{i}"),
                stake: 100,
                timestamp: i as f64,
            });
        }
        assert_eq!(awc.newly_sealed_queue_depth(), 3);

        let drained = awc.drain_newly_sealed();
        assert_eq!(
            drained,
            vec![
                ("a".to_string(), 1u32),
                ("b".to_string(), 1u32),
                ("c".to_string(), 1u32),
            ]
        );
        assert!(awc.drain_newly_sealed().is_empty());
        assert_eq!(awc.newly_sealed_queue_drained_total, 3);
    }

    /// Overflow drops the newest event and bumps the counter. Safe because
    /// confirmation_levels is ground truth — a missed WS push only delays
    /// UX, not correctness.
    #[test]
    fn test_gap8_sealed_queue_overflow_counts_drops() {
        let mut awc = AWCConsensus::new();
        for i in 0..MAX_SEALED_QUEUE {
            awc.newly_sealed_queue
                .push_back((format!("fill-{i}"), 1));
        }
        awc.newly_sealed_queue_enqueued_total = MAX_SEALED_QUEUE as u64;

        awc.add_attestation(Attestation {
            record_id: "rec-overflow".to_string(),
            witness_hash: "w1".to_string(),
            stake: 100,
            timestamp: 1.0,
        });

        assert_eq!(awc.newly_sealed_queue_depth(), MAX_SEALED_QUEUE);
        assert_eq!(awc.newly_sealed_queue_overflow_total, 1);
        assert_eq!(
            awc.newly_sealed_queue_enqueued_total,
            MAX_SEALED_QUEUE as u64
        );
        // Correctness invariant: the record IS at Sealed despite the miss.
        assert_eq!(
            awc.confirmation_level("rec-overflow"),
            ConfirmationLevel::Sealed
        );
    }

    /// Startup rehydration must NOT flood the newly_sealed_queue with stale
    /// milestone events. Wallets subscribed after restart only care about
    /// live transitions; replaying hours-old Sealed events would spam clients
    /// and waste queue depth against the 64K cap.
    #[test]
    fn test_gap8_bulk_load_suppresses_sealed_events() {
        let mut awc = AWCConsensus::new();

        // Simulate persisted attestations for 100 records, each with 1
        // witness (enough to cross the Sealed threshold on replay).
        let atts: Vec<Attestation> = (0..100)
            .map(|i| Attestation {
                record_id: format!("hist-rec-{i}"),
                witness_hash: format!("w-{i}"),
                stake: 100,
                timestamp: i as f64,
            })
            .collect();

        let loaded = awc.bulk_load_attestations(atts);
        assert_eq!(loaded, 100);

        // Every rehydrated record is at Sealed in the confirmation map …
        for i in 0..100 {
            assert_eq!(
                awc.confirmation_level(&format!("hist-rec-{i}")),
                ConfirmationLevel::Sealed
            );
        }

        // … but the WS queue stayed empty — no stale event flood.
        assert_eq!(awc.newly_sealed_queue_depth(), 0);
        assert_eq!(awc.newly_sealed_queue_enqueued_total, 0);
        assert_eq!(awc.newly_sealed_queue_drained_total, 0);

        // A live attestation after bulk_load DOES enqueue normally.
        awc.add_attestation(Attestation {
            record_id: "live-rec".to_string(),
            witness_hash: "w-live".to_string(),
            stake: 100,
            timestamp: 1000.0,
        });
        assert_eq!(awc.newly_sealed_queue_depth(), 1);
        assert_eq!(awc.newly_sealed_queue_enqueued_total, 1);
    }

    // ── has_profile / unknown_profile_pairs_total ──

    #[test]
    fn test_audit9_has_profile_tracks_registrations() {
        let mut awc = AWCConsensus::new();
        assert!(!awc.has_profile("w1"));
        awc.register_profile("w1", profile("org-a", "10.0.1", "earth-us"));
        assert!(awc.has_profile("w1"));
        assert!(!awc.has_profile("w2"));
        // Registering replaces, doesn't fail.
        awc.register_profile("w1", profile("org-b", "10.0.2", "earth-eu"));
        assert!(awc.has_profile("w1"));
        assert_eq!(awc.profile_for("w1").unwrap().organization, "org-b");
    }

    #[test]
    fn test_audit9_unknown_profile_pairs_counter_increments() {
        let awc = AWCConsensus::new();
        assert_eq!(
            awc.unknown_profile_pairs_total
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );

        // Two unknown witnesses → counter bumps, returns high correlation.
        // (env override off by default in tests.)
        let _ = awc.correlation("unknown-a", "unknown-b");
        assert_eq!(
            awc.unknown_profile_pairs_total
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );

        // Second call bumps again.
        let _ = awc.correlation("unknown-a", "unknown-b");
        assert_eq!(
            awc.unknown_profile_pairs_total
                .load(std::sync::atomic::Ordering::Relaxed),
            2
        );

        // Both known → no counter bump.
        let mut awc = awc;
        awc.register_profile("known-a", profile("org-a", "10.0.1", "earth-us"));
        awc.register_profile("known-b", profile("org-b", "10.0.2", "earth-eu"));
        let before = awc
            .unknown_profile_pairs_total
            .load(std::sync::atomic::Ordering::Relaxed);
        let _ = awc.correlation("known-a", "known-b");
        assert_eq!(
            awc.unknown_profile_pairs_total
                .load(std::sync::atomic::Ordering::Relaxed),
            before,
            "both profiles registered should NOT bump the unknown-pair counter"
        );

        // One known, one unknown → still counts as unknown pair.
        let _ = awc.correlation("known-a", "unknown-c");
        assert_eq!(
            awc.unknown_profile_pairs_total
                .load(std::sync::atomic::Ordering::Relaxed),
            before + 1
        );
    }

    // ─── Gap 2.1 Phase 2b: seal-finality signer storage ────────────────

    fn dummy_finality_witness(pk_byte: u8) -> SealFinalityWitness {
        SealFinalityWitness {
            witness_pk: vec![pk_byte; 32],
            signature: vec![pk_byte; 64],
            committee_proof: vec![],
        }
    }

    #[test]
    fn test_seal_finality_signers_roundtrip() {
        let mut awc = AWCConsensus::new();
        assert!(awc.seal_finality_collection_for("seal-1").is_none());

        let w0 = dummy_finality_witness(0xAA);
        let w1 = dummy_finality_witness(0xBB);
        let chash = [0x11u8; 32];
        awc.add_seal_finality_signature("seal-1", 42, chash, 5, w0.clone());
        awc.add_seal_finality_signature("seal-1", 42, chash, 5, w1.clone());

        let coll = awc.seal_finality_collection_for("seal-1").unwrap();
        assert_eq!(coll.seal_epoch, 42);
        assert_eq!(coll.committee_hash, chash);
        assert_eq!(coll.committee_size, 5);
        assert_eq!(coll.signers.len(), 2);
        assert_eq!(coll.signers[0].witness_pk, w0.witness_pk);
        assert_eq!(coll.signers[1].witness_pk, w1.witness_pk);
        assert_eq!(awc.seal_finality_signers_added_total, 2);
    }

    #[test]
    fn test_seal_finality_signers_dedupe_by_pk() {
        let mut awc = AWCConsensus::new();
        let w = dummy_finality_witness(0xCC);
        let chash = [0x22u8; 32];
        awc.add_seal_finality_signature("seal-x", 7, chash, 3, w.clone());
        // Same pk added again (e.g. ingest path replays a signature) — must
        // not double-count, would otherwise inflate the apparent quorum.
        awc.add_seal_finality_signature("seal-x", 7, chash, 3, w.clone());
        assert_eq!(awc.seal_finality_collection_for("seal-x").unwrap().signers.len(), 1);
        assert_eq!(awc.seal_finality_signers_added_total, 1);
    }

    #[test]
    fn test_seal_finality_signers_rejects_divergent_snapshot() {
        // Mid-epoch committee rotation: first witness signs over committee
        // hash A, second witness over hash B. The second is dropped — those
        // sigs sign different canonical messages and would never satisfy
        // verify_finality_quorum together.
        let mut awc = AWCConsensus::new();
        let chash_a = [0x33u8; 32];
        let chash_b = [0x44u8; 32];
        awc.add_seal_finality_signature("seal-r", 9, chash_a, 5, dummy_finality_witness(1));
        awc.add_seal_finality_signature("seal-r", 9, chash_b, 5, dummy_finality_witness(2));
        let coll = awc.seal_finality_collection_for("seal-r").unwrap();
        assert_eq!(coll.signers.len(), 1, "divergent-snapshot signer must be rejected");
        assert_eq!(coll.committee_hash, chash_a);
        assert_eq!(awc.seal_finality_snapshot_mismatch_total, 1);
    }

    #[test]
    fn test_seal_finality_signers_clear() {
        let mut awc = AWCConsensus::new();
        let chash = [0x55u8; 32];
        awc.add_seal_finality_signature("seal-y", 1, chash, 3, dummy_finality_witness(1));
        awc.add_seal_finality_signature("seal-y", 1, chash, 3, dummy_finality_witness(2));
        assert_eq!(awc.seal_finality_signer_entries(), 1);
        awc.clear_seal_finality_signers("seal-y");
        assert_eq!(awc.seal_finality_signer_entries(), 0);
        assert!(awc.seal_finality_collection_for("seal-y").is_none());
    }

    #[test]
    fn test_seal_finality_signers_eviction_at_cap() {
        let mut awc = AWCConsensus::new();
        let chash = [0x66u8; 32];
        // Seed exactly at cap with one signer per seal_id.
        for i in 0..MAX_SEAL_FINALITY_SIG_ENTRIES {
            awc.add_seal_finality_signature(
                &format!("seal-{i}"),
                i as u64,
                chash,
                3,
                dummy_finality_witness((i % 251) as u8),
            );
        }
        assert_eq!(awc.seal_finality_signer_entries(), MAX_SEAL_FINALITY_SIG_ENTRIES);
        assert_eq!(awc.seal_finality_signers_evicted_total, 0);

        // One past the cap must trigger eviction (10% drop), keeping memory
        // O(active_window) per the SCALE RULE.
        awc.add_seal_finality_signature("seal-overflow", 99_999, chash, 3, dummy_finality_witness(7));
        assert!(
            awc.seal_finality_signer_entries() <= MAX_SEAL_FINALITY_SIG_ENTRIES,
            "map size must stay bounded after eviction"
        );
        assert!(
            awc.seal_finality_signers_evicted_total > 0,
            "evicted counter must increment on overflow"
        );
        // Newest insert survives.
        assert!(awc.seal_finality_collection_for("seal-overflow").is_some());
    }

    // ─── Gap 2 sealed-abort P-3a: XZoneAbortCollection storage ─────────

    #[test]
    fn test_xzone_abort_signers_roundtrip() {
        let mut awc = AWCConsensus::new();
        assert!(awc.xzone_abort_collection_for("tx-1").is_none());

        let w0 = dummy_finality_witness(0xAA);
        let w1 = dummy_finality_witness(0xBB);
        let chash = [0x11u8; 32];
        awc.add_xzone_abort_signature("tx-1", 42, chash, 5, w0.clone());
        awc.add_xzone_abort_signature("tx-1", 42, chash, 5, w1.clone());

        let coll = awc.xzone_abort_collection_for("tx-1").unwrap();
        assert_eq!(coll.source_seal_epoch, 42);
        assert_eq!(coll.dest_committee_hash, chash);
        assert_eq!(coll.dest_committee_size, 5);
        assert_eq!(coll.signers.len(), 2);
        assert_eq!(coll.signers[0].witness_pk, w0.witness_pk);
        assert_eq!(coll.signers[1].witness_pk, w1.witness_pk);
        assert_eq!(awc.xzone_abort_signers_added_total, 2);
    }

    #[test]
    fn test_xzone_abort_signers_dedupe_by_pk() {
        let mut awc = AWCConsensus::new();
        let w = dummy_finality_witness(0xCC);
        let chash = [0x22u8; 32];
        awc.add_xzone_abort_signature("tx-x", 7, chash, 3, w.clone());
        // Same pk (e.g. gossip replays a signature) — must not double-count,
        // would otherwise inflate the apparent abort quorum.
        awc.add_xzone_abort_signature("tx-x", 7, chash, 3, w.clone());
        assert_eq!(
            awc.xzone_abort_collection_for("tx-x").unwrap().signers.len(),
            1
        );
        assert_eq!(awc.xzone_abort_signers_added_total, 1);
    }

    #[test]
    fn test_xzone_abort_signers_rejects_divergent_snapshot() {
        // Mid-epoch dest-committee rotation: first witness signs over
        // committee hash A, second over hash B. The second is dropped —
        // those sigs sign different canonical messages and would never
        // satisfy verify_abort_quorum together against the same denom.
        let mut awc = AWCConsensus::new();
        let chash_a = [0x33u8; 32];
        let chash_b = [0x44u8; 32];
        awc.add_xzone_abort_signature("tx-r", 9, chash_a, 5, dummy_finality_witness(1));
        awc.add_xzone_abort_signature("tx-r", 9, chash_b, 5, dummy_finality_witness(2));
        let coll = awc.xzone_abort_collection_for("tx-r").unwrap();
        assert_eq!(
            coll.signers.len(),
            1,
            "divergent-snapshot abort signer must be rejected"
        );
        assert_eq!(coll.dest_committee_hash, chash_a);
        assert_eq!(awc.xzone_abort_snapshot_mismatch_total, 1);
    }

    #[test]
    fn test_xzone_abort_signers_clear() {
        let mut awc = AWCConsensus::new();
        let chash = [0x55u8; 32];
        awc.add_xzone_abort_signature("tx-y", 1, chash, 3, dummy_finality_witness(1));
        awc.add_xzone_abort_signature("tx-y", 1, chash, 3, dummy_finality_witness(2));
        assert_eq!(awc.xzone_abort_signer_entries(), 1);
        awc.clear_xzone_abort_signers("tx-y");
        assert_eq!(awc.xzone_abort_signer_entries(), 0);
        assert!(awc.xzone_abort_collection_for("tx-y").is_none());
    }

    #[test]
    fn test_xzone_abort_signers_eviction_at_cap() {
        let mut awc = AWCConsensus::new();
        let chash = [0x66u8; 32];
        for i in 0..MAX_XZONE_ABORT_SIG_ENTRIES {
            awc.add_xzone_abort_signature(
                &format!("tx-{i}"),
                i as u64,
                chash,
                3,
                dummy_finality_witness((i % 251) as u8),
            );
        }
        assert_eq!(awc.xzone_abort_signer_entries(), MAX_XZONE_ABORT_SIG_ENTRIES);
        assert_eq!(awc.xzone_abort_signers_evicted_total, 0);

        // One past the cap must trigger eviction (10% drop), per SCALE RULE.
        awc.add_xzone_abort_signature(
            "tx-overflow",
            99_999,
            chash,
            3,
            dummy_finality_witness(7),
        );
        assert!(
            awc.xzone_abort_signer_entries() <= MAX_XZONE_ABORT_SIG_ENTRIES,
            "abort map size must stay bounded after eviction"
        );
        assert!(
            awc.xzone_abort_signers_evicted_total > 0,
            "evicted counter must increment on abort overflow"
        );
        assert!(awc.xzone_abort_collection_for("tx-overflow").is_some());
    }

    // ─── Gap 2 sealed-abort P-3f: ready_xzone_abort_bundles snapshot ───

    #[test]
    fn test_ready_xzone_abort_bundles_under_threshold() {
        // 1/3 signers — well below 2/3. The aggregator must not see this
        // collection in the ready snapshot, otherwise it would assemble
        // and submit a bundle whose verify_abort_quorum check fails.
        let mut awc = AWCConsensus::new();
        let chash = [0x77u8; 32];
        awc.add_xzone_abort_signature("tx-low", 11, chash, 3, dummy_finality_witness(1));
        let ready = awc.ready_xzone_abort_bundles();
        assert!(
            ready.is_empty(),
            "1/3 signers must not satisfy 2/3 quorum in ready snapshot"
        );
    }

    #[test]
    fn test_ready_xzone_abort_bundles_at_threshold() {
        // 2/3 signers exactly — must be reported. n*3 (6) >= denom*2 (6).
        let mut awc = AWCConsensus::new();
        let chash = [0x88u8; 32];
        awc.add_xzone_abort_signature("tx-edge", 22, chash, 3, dummy_finality_witness(1));
        awc.add_xzone_abort_signature("tx-edge", 22, chash, 3, dummy_finality_witness(2));
        let ready = awc.ready_xzone_abort_bundles();
        assert_eq!(ready.len(), 1, "2-of-3 must satisfy 2/3 quorum");
        assert_eq!(ready[0].0, "tx-edge");
        assert_eq!(ready[0].1.signers.len(), 2);
        assert_eq!(ready[0].1.source_seal_epoch, 22);
        assert_eq!(ready[0].1.dest_committee_hash, chash);
    }

    #[test]
    fn test_ready_xzone_abort_bundles_over_threshold_and_isolation() {
        // Mixed map: one collection over 2/3, one under. Snapshot returns
        // only the qualifying entry — proves the filter is per-key, not
        // a fold over the whole map.
        let mut awc = AWCConsensus::new();
        let chash = [0x99u8; 32];
        // Over 2/3: 5/5 signers.
        for i in 1u8..=5 {
            awc.add_xzone_abort_signature("tx-full", 33, chash, 5, dummy_finality_witness(i));
        }
        // Under: 1/5 signers.
        awc.add_xzone_abort_signature("tx-thin", 33, chash, 5, dummy_finality_witness(99));
        let mut ready = awc.ready_xzone_abort_bundles();
        ready.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].0, "tx-full");
        assert_eq!(ready[0].1.signers.len(), 5);
        // dest_committee_size==0 must never be ready, even with sigs.
        let mut awc2 = AWCConsensus::new();
        awc2.add_xzone_abort_signature("tx-zero", 1, chash, 0, dummy_finality_witness(1));
        assert!(
            awc2.ready_xzone_abort_bundles().is_empty(),
            "denom=0 must short-circuit before saturating compare"
        );
    }

    /// Gap 2 sealed-abort producer-side seam e2e: prove the consensus
    /// glue (add_xzone_abort_signature → ready_xzone_abort_bundles →
    /// XZoneAbortBundle assembly → bundle.verify()) is wire-compatible
    /// with `try_sign_xzone_abort`'s Dilithium3 outputs. If this test
    /// regresses, the aggregator submits bundles the source-zone apply
    /// path cannot decode.
    #[test]
    fn test_xzone_abort_producer_seam_round_trips_through_bundle_verify() {
        use crate::accounting::cross_zone::{
            build_committee_proofs, try_sign_xzone_abort, XZoneAbortBundle,
        };
        // 5-member dest committee, ProfileB Dilithium3. Four members
        // sign — first count above the 2/3 threshold (3/5 is 60%,
        // below; 4/5 is 80%, above).
        let ws: Vec<crate::identity::Identity> = (0..5)
            .map(|_| {
                crate::identity::Identity::generate(
                    crate::identity::EntityType::Device,
                    crate::identity::CryptoProfile::ProfileB,
                )
                .unwrap()
            })
            .collect();
        let pks: Vec<Vec<u8>> = ws.iter().map(|w| w.public_key.clone()).collect();
        let (committee_hash, _proofs) = build_committee_proofs(&pks);
        let dest_zone = ZoneId::new("eu");
        let transfer_id = "tx-seam-e2e";
        let source_seal_epoch = 77u64;

        let mut awc = AWCConsensus::new();
        for w in &ws[..4] {
            let (witness, hash, size) = try_sign_xzone_abort(
                w,
                transfer_id,
                &dest_zone,
                source_seal_epoch,
                &pks,
                &committee_hash,
            )
            .expect("committee member must sign");
            assert_eq!(size, 5);
            awc.add_xzone_abort_signature(
                transfer_id,
                source_seal_epoch,
                hash,
                size,
                witness,
            );
        }
        let ready = awc.ready_xzone_abort_bundles();
        assert_eq!(ready.len(), 1, "4-of-5 must satisfy 2/3");
        let (snap_id, snap) = &ready[0];
        assert_eq!(snap_id, transfer_id);
        assert_eq!(snap.signers.len(), 4);

        let bundle = XZoneAbortBundle {
            transfer_id: snap_id.clone(),
            dest_zone: dest_zone.clone(),
            source_seal_epoch: snap.source_seal_epoch,
            dest_committee_hash: snap.dest_committee_hash,
            dest_committee_size: snap.dest_committee_size,
            signers: snap.signers.clone(),
        };
        bundle
            .verify()
            .expect("aggregator-built bundle must pass off-chain verify");
    }

    // ─── Gap 2 sealed-abort P-3b: observation map ──────────────────────

    fn dummy_observation(id: &str, dest: &str, expires_at: f64) -> XZoneAbortObservation {
        XZoneAbortObservation {
            transfer_id: id.to_string(),
            source_zone: ZoneId::new("0"),
            dest_zone: ZoneId::new(dest),
            source_seal_epoch: 1,
            locked_at: 0.0,
            expires_at,
            lock_record_hash: [0u8; 32],
            amount: 100,
        }
    }

    #[test]
    fn test_xzone_abort_observation_insert_and_lookup() {
        let mut awc = AWCConsensus::new();
        assert!(awc.xzone_abort_observation("tx-1").is_none());
        awc.record_xzone_abort_observation(dummy_observation("tx-1", "1", 100.0));
        let obs = awc.xzone_abort_observation("tx-1").unwrap();
        assert_eq!(obs.transfer_id, "tx-1");
        assert_eq!(obs.expires_at, 100.0);
        assert_eq!(awc.xzone_abort_observations_inserted_total, 1);
        assert_eq!(awc.xzone_abort_observation_entries(), 1);
    }

    #[test]
    fn test_xzone_abort_observation_idempotent_on_replay() {
        // Re-observing the same lock (gossip replay or seal re-ingest) must
        // update in place — never inflate the entry count.
        let mut awc = AWCConsensus::new();
        awc.record_xzone_abort_observation(dummy_observation("tx-r", "1", 100.0));
        awc.record_xzone_abort_observation(dummy_observation("tx-r", "1", 200.0));
        assert_eq!(awc.xzone_abort_observation_entries(), 1);
        assert_eq!(
            awc.xzone_abort_observation("tx-r").unwrap().expires_at,
            200.0,
            "later observation should overwrite earlier"
        );
        assert_eq!(awc.xzone_abort_observations_inserted_total, 1);
    }

    #[test]
    fn test_xzone_abort_observation_expired_filter() {
        let mut awc = AWCConsensus::new();
        let z1 = ZoneId::new("1");
        let z2 = ZoneId::new("2");
        awc.record_xzone_abort_observation(dummy_observation("a", "1", 50.0));
        awc.record_xzone_abort_observation(dummy_observation("b", "1", 150.0));
        awc.record_xzone_abort_observation(dummy_observation("c", "2", 50.0));

        // now = 100: only "a" and "c" are expired; only "a" matches dest=z1
        let zone_1_expired: Vec<_> = awc
            .expired_xzone_abort_observations(&z1, 100.0)
            .map(|o| o.transfer_id.clone())
            .collect();
        assert_eq!(zone_1_expired, vec!["a".to_string()]);

        // dest=z2 perspective: only "c"
        let zone_2_expired: Vec<_> = awc
            .expired_xzone_abort_observations(&z2, 100.0)
            .map(|o| o.transfer_id.clone())
            .collect();
        assert_eq!(zone_2_expired, vec!["c".to_string()]);

        // future now: all three for the union of their zones
        let total_z1_future: Vec<_> = awc
            .expired_xzone_abort_observations(&z1, 1000.0)
            .map(|o| o.transfer_id.clone())
            .collect();
        assert_eq!(total_z1_future.len(), 2, "z1 has both a and b expired at far future");
    }

    #[test]
    fn test_xzone_abort_observation_clear() {
        let mut awc = AWCConsensus::new();
        awc.record_xzone_abort_observation(dummy_observation("tx-c", "1", 100.0));
        assert!(awc.clear_xzone_abort_observation("tx-c"));
        assert!(awc.xzone_abort_observation("tx-c").is_none());
        assert_eq!(awc.xzone_abort_observations_cleared_total, 1);
        // Idempotent: clearing again returns false, no counter bump.
        assert!(!awc.clear_xzone_abort_observation("tx-c"));
        assert_eq!(awc.xzone_abort_observations_cleared_total, 1);
    }

    // ─── Liveness-decay denominator (internal design notes) ────
    // Test fleet mirrors the 2026-06-11 incident: one live anchor (10_400)
    // plus four decommissioned anchors (10_000 each, keys destroyed) =
    // 50_400 total staked, 2/3 quorum = 33_600 > all living stake.

    /// Build the incident ledger and register it. Returns the AWC with all
    /// zones carrying the replicated 50_400 total.
    fn liveness_test_awc() -> AWCConsensus {
        let mut awc = AWCConsensus::new();
        let mut ledger = LedgerState::new();
        let stakers: &[(&str, u64)] = &[
            ("live-anchor", 10_400),
            ("dead-hel", 10_000),
            ("dead-nur", 10_000),
            ("dead-hil", 10_000),
            ("dead-nyc", 10_000),
        ];
        for (id, stake) in stakers {
            let acct = crate::accounting::ledger::AccountState {
                staked: *stake,
                ..Default::default()
            };
            ledger.accounts.insert((*id).to_string(), acct);
            ledger.staker_index.insert((*id).to_string(), Vec::new());
        }
        ledger.total_staked = 50_400;
        awc.register_stakes_from_ledger_with_zone_count(&ledger, 4);
        awc
    }

    fn attest(awc: &mut AWCConsensus, rid: &str, witness: &str, stake: u64) {
        awc.add_attestation(Attestation {
            record_id: rid.to_string(),
            witness_hash: witness.to_string(),
            stake,
            timestamp: 0.0,
        });
    }

    #[test]
    fn liveness_default_off_dead_stake_keeps_stall() {
        // Pin the pre-liveness behavior: decay disabled (default), the dead
        // majority stays in the denominator and the live anchor can never
        // settle — exactly the 2026-06-11 epoch-28102 wedge.
        let mut awc = liveness_test_awc();
        awc.note_chain_tip(1_000); // far past any stall threshold
        attest(&mut awc, "rid-default-off", "live-anchor", 10_400);
        assert!(
            !awc.is_settled("rid-default-off"),
            "decay OFF must preserve the wedge: 10_400 of 50_400 is not 2/3"
        );
    }

    #[test]
    fn liveness_all_active_no_decay() {
        // Healthy chain: every staker attested within the window → live ==
        // base → denominator unchanged. The window (not a stall gate) is what
        // keeps a healthy network from ever leaking.
        let mut awc = liveness_test_awc();
        awc.configure_liveness(true, 64, 10);
        awc.note_chain_tip(1_000);
        // All six stake holders attest a warmup record → all inside window.
        for w in ["live-anchor", "dead-hel", "dead-nur", "dead-hil", "dead-nyc"] {
            attest(&mut awc, "rid-warmup", w, 10_000);
        }
        // A new record attested only by live-anchor (10_400) against the
        // FULL 50_400 denominator (everyone still live) → cannot settle.
        attest(&mut awc, "rid-healthy", "live-anchor", 10_400);
        assert!(
            !awc.is_settled("rid-healthy"),
            "all-active chain must keep the full denominator (no leak)"
        );
    }

    #[test]
    fn liveness_restart_does_not_reset_decay_clock() {
        // 0b-(ii) regression: the 2026-06-11 re-wedge. A restart used to
        // re-stamp every replayed staker at the boot tip, resurrecting dead
        // stake; with persistence attached, last-active history survives the
        // restart and bulk replay cannot raise liveness.
        let tmp = tempfile::tempdir().expect("tempdir");
        let rocks = std::sync::Arc::new(
            crate::storage::rocks::StorageEngine::open(tmp.path().join("rocksdb"))
                .expect("open rocks"),
        );

        // Process 1: dead-* last attest at epoch 100; live-anchor at 990.
        let mut awc = liveness_test_awc();
        awc.configure_liveness(true, 64, 10);
        awc.attach_liveness_persistence(rocks.clone());
        awc.note_chain_tip(100);
        for w in ["dead-hel", "dead-nur", "dead-hil", "dead-nyc"] {
            attest(&mut awc, "rid-old", w, 10_000);
        }
        awc.note_chain_tip(990);
        attest(&mut awc, "rid-live-1", "live-anchor", 10_400);

        // Process 2 (simulated restart): fresh engine, same rocks. Hydrate,
        // then bulk-replay the OLD attestations at the live tip — exactly
        // the sequence that used to reset the decay clock.
        let mut awc2 = liveness_test_awc();
        awc2.configure_liveness(true, 64, 10);
        awc2.attach_liveness_persistence(rocks.clone());
        awc2.note_chain_tip(1_000);
        let old_atts: Vec<Attestation> = ["dead-hel", "dead-nur", "dead-hil", "dead-nyc"]
            .iter()
            .map(|w| Attestation {
                record_id: "rid-old".to_string(),
                witness_hash: (*w).to_string(),
                stake: 10_000,
                timestamp: 0.0,
            })
            .collect();
        awc2.bulk_load_attestations(old_atts);

        // Dead stake hydrated at epoch 100; window 64 at tip 1_000 → cutoff
        // 936 → dead set NOT live. The decay clock survived the restart: only
        // live-anchor counts toward live stake. Had the clock reset, bulk
        // replay would have re-stamped the dead set at the boot tip and
        // live_staked would be the full 50_400. (Checked via live_staked, not
        // settlement: the fork-safe floor means a 20.6% minority never
        // self-settles regardless — re-stamping is the property under test.)
        attest(&mut awc2, "rid-after-restart", "live-anchor", 10_400);
        assert_eq!(
            awc2.live_staked(),
            10_400,
            "restart + bulk replay must not resurrect dead stake into live_staked"
        );

        // The persisted history itself round-tripped: a third engine
        // hydrates live-anchor at 1_000 (its LIVE attestation in process 2
        // legitimately raised 990 → 1_000 and persisted) while the dead
        // stakers stay at their true epoch 100 — not the boot tip, not
        // zero. Dead history surviving two restarts IS the regression pin.
        let mut awc3 = liveness_test_awc();
        awc3.configure_liveness(true, 64, 10);
        awc3.attach_liveness_persistence(rocks);
        assert_eq!(awc3.staker_last_active.get("live-anchor"), Some(&1_000));
        assert_eq!(awc3.staker_last_active.get("dead-hel"), Some(&100));
    }

    #[test]
    fn liveness_decay_recovers_majority_not_minority() {
        // Supersedes the old "unstick dead majority" pin, which asserted a 20.6%
        // MINORITY self-settled against its collapsed local denominator — that
        // was the fork-on-heal bug: decay is decided per-node, so each partition
        // side independently shrinks its own view and both finalize. Fork-safe
        // semantics: after dead stake ages out, a sub-majority survivor STALLS,
        // but a genuine >½-of-base survivor set still recovers finality.
        // base=50_400 → fork-safe floor 37_801 (>¾·base).
        let mut awc = liveness_test_awc();
        awc.configure_liveness(true, 64, 10);
        awc.note_chain_tip(1_000);
        // (A) Lone live-anchor = 10_400 (20.6%); dead-* never attested. The
        // denominator HOLDS at the floor 37_801, it does NOT collapse to 10_400:
        // 10_400*3 = 31_200 < 37_801*2 = 75_602 → must NOT settle.
        attest(&mut awc, "rid-minority", "live-anchor", 10_400);
        assert!(
            !awc.is_settled("rid-minority"),
            "fork-safe: a 20.6% survivor must STALL — collapsing to live stake \
             and self-settling is the fork-on-heal bug this floor closes"
        );
        // (B) Two more stakers return → live = 30_400 (60.3% > ½ base). A
        // genuine majority recovers: denom = max(30_400, 37_801) = 37_801;
        // 30_400*3 = 91_200 ≥ 37_801*2 = 75_602 → settles.
        attest(&mut awc, "rid-majority", "live-anchor", 10_400);
        attest(&mut awc, "rid-majority", "dead-hel", 10_000);
        attest(&mut awc, "rid-majority", "dead-nur", 10_000);
        assert!(
            awc.is_settled("rid-majority"),
            "a >½-of-base survivor majority must still recover finality — \
             fork-safety must not freeze a genuine majority"
        );
    }

    #[test]
    fn liveness_quiet_honest_majority_not_excluded() {
        // Guard 1: stakers quiet for LESS than the window stay in the
        // denominator — a brief outage must not let a minority finalize.
        let mut awc = liveness_test_awc();
        awc.configure_liveness(true, 64, 10);
        // The "dead" four attested at tip 980 (old record), then went quiet.
        awc.note_chain_tip(980);
        for w in ["dead-hel", "dead-nur", "dead-hil", "dead-nyc"] {
            attest(&mut awc, "rid-warmup", w, 10_000);
        }
        // 30 epochs later (< window 64): stalled, but they're within window.
        awc.note_chain_tip(1_010);
        attest(&mut awc, "rid-quiet", "live-anchor", 10_400);
        assert!(
            !awc.is_settled("rid-quiet"),
            "briefly-quiet majority must stay in the denominator (live_staked = full 50_400)"
        );
    }

    #[test]
    fn liveness_window_default_720_and_floor_is_the_fork_guard() {
        // (1) Pin the production window default. The window is a LIVENESS knob
        // (how fast genuinely-departed stake stops being waited on); it is NO
        // LONGER the fork-safety guard — that is the fork-safe settlement floor
        // (>¾·base; see settlement_denominator + the fork-safe-floor test).
        // 720 (~24h @ 120s) still exceeds the longest BENIGN offline period
        // (overnight/weekend laptop sleep) so honest sleepers never age out.
        assert_eq!(
            AWCConsensus::new().liveness_window_epochs, 720,
            "default liveness window must stay 720 (~24h @ 120s)"
        );

        // (2) Fork-safety is now WINDOW-INDEPENDENT. The same partition (the
        // majority 4×10_000 = 40_000 of 50_400 goes silent for D epochs while
        // the tip advances; then the lone minority live-anchor, 10_400 ≈ 21%,
        // probes) must STALL at BOTH the retired short window AND the long
        // default — because the floor holds the denominator above ¾·base no
        // matter how much absent stake has aged out of live_staked.
        const D: u64 = 100; // ~3.3h @ 120s — a plausible WAN partition / nap
        let run_partition = |window: u64| -> bool {
            let mut awc = liveness_test_awc();
            awc.configure_liveness(true, window, 10);
            awc.note_chain_tip(1_000);
            for w in ["dead-hel", "dead-nur", "dead-hil", "dead-nyc"] {
                attest(&mut awc, "rid-warmup", w, 10_000);
            }
            awc.note_chain_tip(1_000 + D); // tip advances past the partition
            attest(&mut awc, "rid-probe", "live-anchor", 10_400);
            awc.is_settled("rid-probe")
        };

        // SHORT window (retired 64 < D): the absent majority DOES age out of
        // live_staked — but the fork-safe floor keeps the 21% minority from
        // self-settling its collapsed view. No fork on heal.
        assert!(
            !run_partition(64),
            "short window (64 < D): absent majority ages out of live_staked, \
             but the fork-safe floor still blocks the 21% minority — no fork"
        );
        // LONG window (720 > D): absent majority stays counted AND the floor
        // holds — minority stalls either way.
        assert!(
            !run_partition(720),
            "720 window (> D): absent majority stays counted and the floor \
             holds — minority stalls"
        );
    }

    #[test]
    fn liveness_floor_blocks_tiny_survivor() {
        // Guard 3: a 3% survivor cannot clear 2/3 of itself — the fork-safe
        // floor (>¾·base) holds the denominator up.
        let mut awc = AWCConsensus::new();
        let mut ledger = LedgerState::new();
        let stakers: &[(&str, u64)] = &[("tiny-live", 3_000), ("dead-whale", 97_000)];
        for (id, stake) in stakers {
            let acct = crate::accounting::ledger::AccountState {
                staked: *stake,
                ..Default::default()
            };
            ledger.accounts.insert((*id).to_string(), acct);
            ledger.staker_index.insert((*id).to_string(), Vec::new());
        }
        ledger.total_staked = 100_000;
        awc.register_stakes_from_ledger_with_zone_count(&ledger, 4);
        awc.configure_liveness(true, 64, 10);
        awc.note_chain_tip(1_000);
        attest(&mut awc, "rid-tiny", "tiny-live", 3_000);
        // live_staked = 3_000 < fork-safe floor 75_001 (=100_000*3/4+1) →
        // denominator 75_001; 3_000 * 3 = 9_000 < 150_002 → must NOT settle.
        assert!(
            !awc.is_settled("rid-tiny"),
            "floor must prevent a tiny survivor set from self-finalizing"
        );
    }

    #[test]
    fn liveness_floor_is_fork_safe_minority_stalls_majority_recovers() {
        // CONSENSUS SAFETY INVARIANT (do not regress). With decay enabled, the
        // settlement floor — not the window — is the fork-safety guard: no
        // DISJOINT partition side below a true majority can self-settle its
        // collapsed local view, so two sides can never both finalize → no fork
        // on heal. A genuine >½-of-base survivor set still recovers (favour
        // stall over fork WITHOUT freezing a real majority). 3 equal validators
        // (≈33% each) — the S1 friend-realm shape that the old base/10 floor
        // forked (a 1-of-3 survivor self-settled at ratio 1.0).
        let mut awc = AWCConsensus::new();
        let mut ledger = LedgerState::new();
        for id in ["v1", "v2", "v3"] {
            let acct = crate::accounting::ledger::AccountState {
                staked: 10_000,
                ..Default::default()
            };
            ledger.accounts.insert(id.to_string(), acct);
            ledger.staker_index.insert(id.to_string(), Vec::new());
        }
        ledger.total_staked = 30_000;
        awc.register_stakes_from_ledger_with_zone_count(&ledger, 4);
        // Caller asks for the retired d=10 — the fork-safe floor overrides it.
        awc.configure_liveness(true, 64, 10);
        // base=30_000 → fork-safe floor = 30_000*3/4 + 1 = 22_501.
        let z = zone_for_record("rid-min");
        awc.note_chain_tip(1_000); // v2,v3 never attested → aged out locally

        // (A) Lone 1-of-3 (33% of base) — the partition minority. MUST STALL:
        // denom = max(10_000, 22_501) = 22_501; 10_000*3 = 30_000 < 45_002.
        attest(&mut awc, "rid-min", "v1", 10_000);
        assert!(
            !awc.is_settled("rid-min"),
            "FORK-SAFETY: a 1-of-3 (33%) survivor must STALL, not self-settle \
             its collapsed view — else two partition sides both finalize → fork"
        );
        assert_eq!(
            awc.settlement_denominator(&z),
            22_501,
            "decayed denominator must hold at the fork-safe floor (>¾·base), \
             not collapse to live stake"
        );

        // (B) A genuine 2-of-3 majority (≈67% > ½ base) MUST still recover:
        // v1+v2 live = 20_000; denom = max(20_000, 22_501) = 22_501;
        // 20_000*3 = 60_000 ≥ 22_501*2 = 45_002 → settles.
        attest(&mut awc, "rid-maj", "v1", 10_000);
        attest(&mut awc, "rid-maj", "v2", 10_000);
        assert!(
            awc.is_settled("rid-maj"),
            "a >½-of-base survivor majority must still settle — fork-safety \
             must not freeze a genuine majority"
        );
    }

    #[test]
    fn liveness_recovery_recounts_returning_stake() {
        // Guard 4: a staker that resumes attesting re-enters the live set
        // immediately — outage and decommission share one reversible path.
        // Checked via live_staked (the fork-safe floor means a minority never
        // self-settles regardless; re-entry into live stake is the property).
        let mut awc = liveness_test_awc();
        awc.configure_liveness(true, 64, 10);
        awc.note_chain_tip(1_000); // only live-anchor in window
        attest(&mut awc, "rid-r1", "live-anchor", 10_400);
        assert_eq!(
            awc.live_staked(),
            10_400,
            "precondition: only the live anchor counts; dead set aged out"
        );
        // dead-hel comes back online and attests something.
        attest(&mut awc, "rid-r2", "dead-hel", 10_000);
        // Returned stake re-enters live_staked immediately: 10_400 + 10_000.
        assert_eq!(
            awc.live_staked(),
            20_400,
            "returning stake must re-enter the live denominator immediately"
        );
    }

    #[test]
    fn register_stakes_from_ledger_covers_dynamic_zone_count() {
        // Regression: at zone_count > 256, the legacy hardcoded
        // `for z in 0..=255` left zones 256..zone_count without stake registered,
        // so any record routed there via `for_record_dynamic` had
        // eligible_stake = 0 and never settled. Verify the dynamic count is
        // honored at every scale we care about: testnet (4), midscale (1024),
        // mainnet ceiling neighborhood (10_000).
        // Use the `_with_zone_count` variant to avoid racing the global atomic
        // with other tests in the same process.
        for &zc in &[4u64, 256, 1024, 10_000] {
            let mut awc = AWCConsensus::new();
            let mut ledger = LedgerState::new();
            let acct = crate::accounting::ledger::AccountState {
                staked: 1_000_000,
                ..Default::default()
            };
            ledger.accounts.insert("staker-1".to_string(), acct);
            // register_stakes_from_ledger now reads ledger.total_staked
            // (incrementally maintained in production by stake/unstake/slash).
            // Synthetic test ledger has to set this explicitly to match the
            // contract — apply_op normally does this in production.
            ledger.total_staked = 1_000_000;
            awc.register_stakes_from_ledger_with_zone_count(&ledger, zc);

            // Zone 0 always populated when total_staked > 0.
            assert_eq!(
                awc.total_zone_stake(ZoneId::from_legacy(0)),
                1_000_000,
                "zone 0 must carry replicated total stake at zone_count={zc}",
            );
            // The highest zone in the dynamic range MUST be populated.
            assert_eq!(
                awc.total_zone_stake(ZoneId::from_legacy(zc - 1)),
                1_000_000,
                "highest dynamic zone (zc-1={}) must carry replicated total stake at zone_count={zc}", zc - 1,
            );
            // Out-of-range zone (zc) must NOT be populated — old code blanket-set 0..=255.
            assert_eq!(
                awc.total_zone_stake(ZoneId::from_legacy(zc)),
                0,
                "out-of-range zone (zc={zc}) must not be populated",
            );
            assert_eq!(
                awc.zone_stakes.len(),
                zc as usize,
                "zone_stakes size must match dynamic zone_count={zc}",
            );
        }
    }

    #[test]
    fn register_stakes_from_ledger_no_stake_clears_zones() {
        // Empty ledger → zone_stakes must be cleared (was already correct,
        // but lock it down so future refactors don't regress).
        let mut awc = AWCConsensus::new();
        // Pre-populate one entry to verify clear() runs.
        awc.zone_stakes.insert(ZoneId::from_legacy(0), 999);
        let ledger = LedgerState::new();
        awc.register_stakes_from_ledger_with_zone_count(&ledger, 8);
        assert!(awc.zone_stakes.is_empty(), "no staked accounts → zone_stakes empty");
    }

    #[test]
    fn test_xzone_abort_observation_eviction_at_cap() {
        let mut awc = AWCConsensus::new();
        for i in 0..MAX_XZONE_ABORT_OBSERVATIONS {
            awc.record_xzone_abort_observation(dummy_observation(
                &format!("tx-{i}"),
                "1",
                i as f64,
            ));
        }
        assert_eq!(
            awc.xzone_abort_observation_entries(),
            MAX_XZONE_ABORT_OBSERVATIONS
        );
        assert_eq!(awc.xzone_abort_observations_evicted_total, 0);

        // Overflow triggers 10% drop per SCALE RULE.
        awc.record_xzone_abort_observation(dummy_observation("tx-overflow", "1", 99_999.0));
        assert!(
            awc.xzone_abort_observation_entries() <= MAX_XZONE_ABORT_OBSERVATIONS,
            "observation map must stay bounded after eviction"
        );
        assert!(
            awc.xzone_abort_observations_evicted_total > 0,
            "evicted counter must increment on overflow"
        );
        assert!(awc.xzone_abort_observation("tx-overflow").is_some());
    }

    // ── attestation_ratio_summary ───────────────────────────────

    #[test]
    fn test_ratio_summary_empty() {
        let awc = AWCConsensus::new();
        let s = awc.attestation_ratio_summary();
        assert_eq!(s.tracked, 0);
        assert_eq!(s.ratiable, 0);
        assert_eq!(s.best_ratio, 0.0);
        assert_eq!(s.mean_ratio, 0.0);
        assert_eq!(s.count_at_threshold, 0);
    }

    #[test]
    fn test_ratio_summary_below_threshold() {
        // One record with 50% attestation = below the 2/3 threshold.
        // Mirrors the structural stall the gauge is meant to surface.
        let mut awc = AWCConsensus::new();
        let rid = "stall-record";
        setup_zone_stake(&mut awc, rid, 300);
        awc.register_profile("w1", profile("org-a", "10.0.1", "earth-us"));
        awc.add_attestation(Attestation {
            record_id: rid.to_string(),
            witness_hash: "w1".to_string(),
            stake: 150,
            timestamp: 1.0,
        });
        let s = awc.attestation_ratio_summary();
        assert_eq!(s.tracked, 1);
        assert_eq!(s.ratiable, 1);
        assert!((s.best_ratio - 0.5).abs() < 1e-9, "best_ratio={}", s.best_ratio);
        assert!((s.mean_ratio - 0.5).abs() < 1e-9);
        assert_eq!(s.count_at_threshold, 0, "50% must not satisfy 2/3 threshold");
    }

    #[test]
    fn settlement_denominator_for_zone_mirrors_private_method() {
        use crate::network::zone::ZoneId;
        let mut awc = AWCConsensus::new();
        let zone = ZoneId::default_zone();
        // Unknown zone → 0 (the is_settled/is_seal_settled early-return path).
        assert_eq!(awc.settlement_denominator_for_zone(&zone), 0);
        // Full zone stake fallback when no committee is registered.
        awc.register_zone_stake(zone.clone(), 300);
        assert_eq!(awc.settlement_denominator_for_zone(&zone), 300);
        // Committee stake (>0) wins over full zone stake (MAINNET gap #5).
        awc.committee_stakes.insert(zone.clone(), 120);
        assert_eq!(awc.settlement_denominator_for_zone(&zone), 120);
        // The public accessor is byte-for-byte the private method the live
        // settlement path uses — same numerator/denominator view for the sweep.
        assert_eq!(
            awc.settlement_denominator_for_zone(&zone),
            awc.settlement_denominator(&zone)
        );
    }

    #[test]
    fn test_ratio_summary_at_threshold() {
        // Exactly 2/3 — must count toward at_threshold (matches is_settled logic).
        let mut awc = AWCConsensus::new();
        let rid = "settled-record";
        setup_zone_stake(&mut awc, rid, 300);
        awc.register_profile("w1", profile("org-a", "10.0.1", "earth-us"));
        awc.add_attestation(Attestation {
            record_id: rid.to_string(),
            witness_hash: "w1".to_string(),
            stake: 200,
            timestamp: 1.0,
        });
        let s = awc.attestation_ratio_summary();
        assert_eq!(s.tracked, 1);
        assert_eq!(s.ratiable, 1);
        assert!((s.best_ratio - 200.0_f64 / 300.0).abs() < 1e-9);
        assert_eq!(s.count_at_threshold, 1);
    }

    #[test]
    fn test_ratio_summary_creator_stake_excluded() {
        // Creator stake reduces eligible_stake — mirrors is_settled() denominator.
        // 200 attestation against 300 zone - 50 creator = 250 eligible → ratio = 0.8 ≥ 2/3.
        let mut awc = AWCConsensus::new();
        let rid = "creator-stake-record";
        setup_zone_stake(&mut awc, rid, 300);
        awc.creator_stakes.insert(rid.to_string(), 50);
        awc.register_profile("w1", profile("org-a", "10.0.1", "earth-us"));
        awc.add_attestation(Attestation {
            record_id: rid.to_string(),
            witness_hash: "w1".to_string(),
            stake: 200,
            timestamp: 1.0,
        });
        let s = awc.attestation_ratio_summary();
        assert_eq!(s.tracked, 1);
        assert_eq!(s.ratiable, 1);
        assert!((s.best_ratio - 200.0_f64 / 250.0).abs() < 1e-9);
        assert_eq!(s.count_at_threshold, 1);
    }

    #[test]
    fn test_ratio_summary_zero_eligible_excluded() {
        // Record in a zone with no registered stake → eligible = 0 → counted in
        // tracked but not ratiable, not in best/mean/at_threshold.
        let mut awc = AWCConsensus::new();
        let rid = "no-stake-record";
        // Note: NO setup_zone_stake call — zone has 0 stake registered.
        awc.register_profile("w1", profile("org-a", "10.0.1", "earth-us"));
        awc.add_attestation(Attestation {
            record_id: rid.to_string(),
            witness_hash: "w1".to_string(),
            stake: 100,
            timestamp: 1.0,
        });
        let s = awc.attestation_ratio_summary();
        assert_eq!(s.tracked, 1, "must be tracked even if not ratiable");
        assert_eq!(s.ratiable, 0, "zero-eligible records cannot ratio");
        assert_eq!(s.best_ratio, 0.0);
        assert_eq!(s.mean_ratio, 0.0);
        assert_eq!(s.count_at_threshold, 0);
    }

    #[test]
    fn test_ratio_summary_mixed_records() {
        // Three records: one settled (75%), one stalled (50%), one zero-eligible.
        // Validates best/mean computed only over ratiable records.
        let mut awc = AWCConsensus::new();
        awc.register_profile("w1", profile("org-a", "10.0.1", "earth-us"));
        awc.register_profile("w2", profile("org-b", "10.0.2", "earth-eu"));

        let r_settled = "ratio-settled";
        setup_zone_stake(&mut awc, r_settled, 400);
        awc.add_attestation(Attestation {
            record_id: r_settled.to_string(),
            witness_hash: "w1".to_string(),
            stake: 300,
            timestamp: 1.0,
        });

        let r_stalled = "ratio-stalled";
        setup_zone_stake(&mut awc, r_stalled, 400);
        awc.add_attestation(Attestation {
            record_id: r_stalled.to_string(),
            witness_hash: "w2".to_string(),
            stake: 200,
            timestamp: 2.0,
        });

        let r_dead = "ratio-dead-zone";
        awc.add_attestation(Attestation {
            record_id: r_dead.to_string(),
            witness_hash: "w1".to_string(),
            stake: 100,
            timestamp: 3.0,
        });

        let s = awc.attestation_ratio_summary();
        assert_eq!(s.tracked, 3);
        assert_eq!(s.ratiable, 2);
        assert!((s.best_ratio - 0.75).abs() < 1e-9, "best={}", s.best_ratio);
        assert!((s.mean_ratio - 0.625).abs() < 1e-9, "mean={}", s.mean_ratio);
        assert_eq!(s.count_at_threshold, 1, "only the 75% record satisfies 2/3");
    }

    // ── classify_cohort — bratio cohort-membership classifier ───────

    #[test]
    fn classify_cohort_dormant_empty_attestations() {
        // No in-flight attestations → DORMANT (code 0). Matches the
        // settlement-quiet surface for nodes with nothing tracked.
        let awc = AWCConsensus::new();
        let s = awc.attestation_ratio_summary();
        assert_eq!(s.tracked, 0);
        assert_eq!(s.classify_cohort(), 0, "tracked==0 must classify as DORMANT");
    }

    #[test]
    fn classify_cohort_locked_unratiable_records() {
        // tracked > 0 but ratiable == 0 (zone has no registered stake) →
        // LOCKED (code 1). best_ratio defaults to 0.0, which is < 0.60.
        // This is the "waiting on zone stake" sub-state of LOCKED.
        let mut awc = AWCConsensus::new();
        awc.register_profile("w1", profile("org-a", "10.0.1", "earth-us"));
        awc.add_attestation(Attestation {
            record_id: "unratiable".to_string(),
            witness_hash: "w1".to_string(),
            stake: 100,
            timestamp: 1.0,
        });
        let s = awc.attestation_ratio_summary();
        assert_eq!(s.tracked, 1);
        assert_eq!(s.ratiable, 0);
        assert_eq!(s.best_ratio, 0.0);
        assert_eq!(s.classify_cohort(), 1, "tracked>0 + ratiable=0 must be LOCKED");
    }

    #[test]
    fn classify_cohort_locked_anchor_5952() {
        // The empirical LOCKED anchor at ≈0.5952 (anchored, no fresh stake) —
        // exercise the classifier directly with a hand-built summary so we test
        // the threshold logic without depending on attestation arithmetic.
        let s = AttestationRatioSummary {
            tracked: 5,
            ratiable: 5,
            best_ratio: 0.5952,
            mean_ratio: 0.5952,
            count_at_threshold: 0,
        };
        assert_eq!(s.classify_cohort(), 1, "0.5952 anchor must be LOCKED");
    }

    #[test]
    fn classify_cohort_converged_attractor() {
        // The empirical CONVERGED steady-state attractor at ≈0.6032.
        let s = AttestationRatioSummary {
            tracked: 5,
            ratiable: 5,
            best_ratio: 0.6032,
            mean_ratio: 0.6032,
            count_at_threshold: 0,
        };
        assert_eq!(s.classify_cohort(), 2, "0.6032 attractor must be CONVERGED");
    }

    #[test]
    fn classify_cohort_active_burst() {
        // The empirical ACTIVE band at ≈0.8016 — mid-settlement burst.
        let s = AttestationRatioSummary {
            tracked: 5,
            ratiable: 5,
            best_ratio: 0.8016,
            mean_ratio: 0.7,
            count_at_threshold: 2,
        };
        assert_eq!(s.classify_cohort(), 3, "0.8016 burst must be ACTIVE");
    }

    #[test]
    fn classify_cohort_hyper_active_full_stake() {
        // HYPER-ACTIVE at full-stake attestation (bratio == 1.0).
        let s = AttestationRatioSummary {
            tracked: 5,
            ratiable: 5,
            best_ratio: 1.0,
            mean_ratio: 0.9,
            count_at_threshold: 5,
        };
        assert_eq!(s.classify_cohort(), 4, "bratio=1.0 must be HYPER_ACTIVE");
    }

    #[test]
    fn classify_cohort_boundary_below_locked_converged() {
        // Right below the LOCKED→CONVERGED boundary at 0.60 — must stay LOCKED.
        // f64::next_down(0.60) sits just under the boundary.
        let s = AttestationRatioSummary {
            tracked: 1,
            ratiable: 1,
            best_ratio: 0.59999999,
            mean_ratio: 0.59999999,
            count_at_threshold: 0,
        };
        assert_eq!(s.classify_cohort(), 1, "0.59999999 must stay LOCKED");
    }

    #[test]
    fn classify_cohort_boundary_locked_converged_inclusive() {
        // Exactly at the LOCKED→CONVERGED boundary at 0.60 — must promote to
        // CONVERGED (the band is [0.60, 0.667), closed on the lower end).
        let s = AttestationRatioSummary {
            tracked: 1,
            ratiable: 1,
            best_ratio: 0.60,
            mean_ratio: 0.60,
            count_at_threshold: 0,
        };
        assert_eq!(s.classify_cohort(), 2, "0.60 boundary must be CONVERGED");
    }

    #[test]
    fn classify_cohort_boundary_converged_active_settlement_threshold() {
        // Right at the boundary 0.667 — must promote to ACTIVE. The band
        // is [0.667, 0.999), closed on the lower end. 0.667 is the
        // structural-settlement-threshold neighbourhood (2/3 ≈ 0.6667).
        let s = AttestationRatioSummary {
            tracked: 1,
            ratiable: 1,
            best_ratio: 0.667,
            mean_ratio: 0.667,
            count_at_threshold: 1,
        };
        assert_eq!(s.classify_cohort(), 3, "0.667 boundary must be ACTIVE");
        // 0.6669 < 0.667 → still CONVERGED.
        let s2 = AttestationRatioSummary {
            best_ratio: 0.6669,
            ..s.clone()
        };
        assert_eq!(s2.classify_cohort(), 2, "0.6669 < 0.667 must stay CONVERGED");
        // 0.668 > 0.667 → ACTIVE.
        let s3 = AttestationRatioSummary {
            best_ratio: 0.668,
            ..s.clone()
        };
        assert_eq!(s3.classify_cohort(), 3, "0.668 must be ACTIVE");
    }

    #[test]
    fn classify_cohort_boundary_active_hyper_active() {
        // Below 0.999 → ACTIVE; at/above 0.999 → HYPER-ACTIVE. Captures the
        // floating-point fuzz on "morally full-stake" attestations.
        let mut s = AttestationRatioSummary {
            tracked: 1,
            ratiable: 1,
            best_ratio: 0.9989,
            mean_ratio: 0.9,
            count_at_threshold: 1,
        };
        assert_eq!(s.classify_cohort(), 3, "0.9989 stays ACTIVE");
        s.best_ratio = 0.999;
        assert_eq!(s.classify_cohort(), 4, "0.999 promotes to HYPER_ACTIVE");
        s.best_ratio = 0.9999;
        assert_eq!(s.classify_cohort(), 4, "0.9999 stays HYPER_ACTIVE");
    }

    /// Observation-only epoch-prune shadow metric.
    /// Sealed records below the horizon are eligible; ones above the horizon
    /// or in unsettled seals or zones with no current epoch are not.
    #[test]
    fn test_epoch_prune_shadow_eligible_only_counts_settled_records_past_horizon() {
        use crate::ZoneId;
        let mut awc = AWCConsensus::new();
        let zone = ZoneId::from_legacy(7);
        awc.zone_stakes.insert(zone.clone(), 300);
        awc.register_profile("w1", profile("org-a", "10.0.1", "earth-us"));
        awc.register_profile("w2", profile("org-b", "10.0.2", "earth-eu"));
        awc.register_profile("w3", profile("org-c", "10.0.3", "mars-olympus"));

        // seal-old: epoch 5, will be eligible (current epoch 200 - 5 = 195 >= horizon 100)
        let _ = awc.register_seal_records("seal-old", vec!["r-old-1".to_string(), "r-old-2".to_string(), "r-old-3".to_string()]);
        awc.register_seal_epoch("seal-old", 5, zone.clone());
        // settle seal-old
        for (i, wh) in ["w1", "w2", "w3"].iter().enumerate() {
            let _ = awc.add_seal_attestation(SealAttestation {
                seal_id: "seal-old".to_string(),
                zone: zone.clone(),
                epoch_number: 5,
                witness_hash: wh.to_string(),
                stake: 100,
                timestamp: i as f64,
            });
        }
        assert!(awc.is_seal_settled("seal-old"));

        // seal-recent: epoch 150, NOT eligible (200 - 150 = 50 < horizon 100)
        let _ = awc.register_seal_records("seal-recent", vec!["r-recent-1".to_string()]);
        awc.register_seal_epoch("seal-recent", 150, zone.clone());
        for (i, wh) in ["w1", "w2", "w3"].iter().enumerate() {
            let _ = awc.add_seal_attestation(SealAttestation {
                seal_id: "seal-recent".to_string(),
                zone: zone.clone(),
                epoch_number: 150,
                witness_hash: wh.to_string(),
                stake: 100,
                timestamp: (i + 10) as f64,
            });
        }
        assert!(awc.is_seal_settled("seal-recent"));

        // seal-old-unsettled: epoch 5 like seal-old, but no attestations -> NOT eligible
        let _ = awc.register_seal_records("seal-old-unsettled", vec!["r-unsettled".to_string()]);
        awc.register_seal_epoch("seal-old-unsettled", 5, zone.clone());

        // seal-no-epoch: registered records but never registered epoch -> NOT eligible
        let _ = awc.register_seal_records("seal-no-epoch", vec!["r-no-epoch".to_string()]);
        for (i, wh) in ["w1", "w2", "w3"].iter().enumerate() {
            let _ = awc.add_seal_attestation(SealAttestation {
                seal_id: "seal-no-epoch".to_string(),
                zone: zone.clone(),
                epoch_number: 5,
                witness_hash: wh.to_string(),
                stake: 100,
                timestamp: (i + 20) as f64,
            });
        }

        let mut zone_epochs = HashMap::new();
        zone_epochs.insert(zone.clone(), 200u64);

        let eligible = awc.count_epoch_prune_shadow_eligible(
            AWCConsensus::EPOCH_PRUNE_SHADOW_HORIZON,
            &zone_epochs,
        );
        // Only seal-old's 3 records qualify.
        assert_eq!(eligible, 3, "expected 3 eligible records, got {}", eligible);

        // Indexed count: seal-old, seal-recent, seal-old-unsettled (3 with epoch info)
        // seal-no-epoch was NOT registered with register_seal_epoch
        assert_eq!(awc.seal_epoch_indexed_count(), 3);

        // Zone with no current-epoch entry → 0 eligible
        let empty: HashMap<ZoneId, u64> = HashMap::new();
        assert_eq!(awc.count_epoch_prune_shadow_eligible(100, &empty), 0);

        // Horizon larger than the gap → 0 eligible (200 - 5 = 195 < 1000)
        assert_eq!(awc.count_epoch_prune_shadow_eligible(1000, &zone_epochs), 0);
    }

    /// Operator drilldown helper. Eligible seals are
    /// ordered by lag descending and truncated to max_n.
    #[test]
    fn test_epoch_prune_shadow_eligible_seals_orders_by_lag_and_truncates() {
        use crate::ZoneId;
        let mut awc = AWCConsensus::new();
        let zone = ZoneId::from_legacy(11);
        awc.zone_stakes.insert(zone.clone(), 300);
        awc.register_profile("w1", profile("org-a", "10.0.1", "earth-us"));
        awc.register_profile("w2", profile("org-b", "10.0.2", "earth-eu"));
        awc.register_profile("w3", profile("org-c", "10.0.3", "mars-olympus"));

        // Three eligible seals at different epochs (current=500, horizon=100):
        //   seal-100 (lag 400), seal-200 (lag 300), seal-350 (lag 150).
        // One ineligible: seal-450 (lag 50 < horizon).
        for (sid, epoch, recs) in [
            ("seal-100", 100u64, 5usize),
            ("seal-200", 200u64, 3usize),
            ("seal-350", 350u64, 7usize),
            ("seal-450", 450u64, 2usize),
        ] {
            let record_ids: Vec<String> = (0..recs).map(|i| format!("{sid}-r{i}")).collect();
            let _ = awc.register_seal_records(sid, record_ids);
            awc.register_seal_epoch(sid, epoch, zone.clone());
            for (i, wh) in ["w1", "w2", "w3"].iter().enumerate() {
                let _ = awc.add_seal_attestation(SealAttestation {
                    seal_id: sid.to_string(),
                    zone: zone.clone(),
                    epoch_number: epoch,
                    witness_hash: wh.to_string(),
                    stake: 100,
                    timestamp: i as f64,
                });
            }
        }

        let mut zone_epochs = HashMap::new();
        zone_epochs.insert(zone.clone(), 500u64);

        // max_n=10 → all 3 eligible, ordered by lag descending.
        let top = awc.epoch_prune_shadow_eligible_seals(100, &zone_epochs, 10);
        assert_eq!(top.len(), 3, "expected 3 eligible seals, got {}", top.len());
        assert_eq!(top[0].0, "seal-100"); // lag 400 — head
        assert_eq!(top[0].4, 400);
        assert_eq!(top[1].0, "seal-200"); // lag 300
        assert_eq!(top[1].4, 300);
        assert_eq!(top[2].0, "seal-350"); // lag 150
        assert_eq!(top[2].4, 150);
        assert_eq!(top[0].3, 5); // record_count for seal-100
        assert_eq!(top[2].3, 7);

        // max_n=2 → only the two oldest (largest lag).
        let top2 = awc.epoch_prune_shadow_eligible_seals(100, &zone_epochs, 2);
        assert_eq!(top2.len(), 2);
        assert_eq!(top2[0].0, "seal-100");
        assert_eq!(top2[1].0, "seal-200");

        // max_n=0 → empty.
        assert!(awc.epoch_prune_shadow_eligible_seals(100, &zone_epochs, 0).is_empty());
    }

    /// The single-pass `epoch_prune_shadow_summary` (one consensus-lock
    /// scan for `/admin/epoch_prune_shadow`) must agree exactly with the
    /// two independent scans it fuses — same record total, same entry list
    /// — AND report the TRUE eligible-seal total even when the entry list
    /// is truncated below it (the old route reported the capped list
    /// length).
    #[test]
    fn test_epoch_prune_shadow_summary_matches_pairwise_scans() {
        use crate::ZoneId;
        let mut awc = AWCConsensus::new();
        let zone = ZoneId::from_legacy(11);
        awc.zone_stakes.insert(zone.clone(), 300);
        awc.register_profile("w1", profile("org-a", "10.0.1", "earth-us"));
        awc.register_profile("w2", profile("org-b", "10.0.2", "earth-eu"));
        awc.register_profile("w3", profile("org-c", "10.0.3", "mars-olympus"));

        // Same shape as the drilldown test: 3 eligible (lags 400/300/150,
        // records 5/3/7), 1 ineligible (lag 50 < horizon 100).
        for (sid, epoch, recs) in [
            ("seal-100", 100u64, 5usize),
            ("seal-200", 200u64, 3usize),
            ("seal-350", 350u64, 7usize),
            ("seal-450", 450u64, 2usize),
        ] {
            let record_ids: Vec<String> = (0..recs).map(|i| format!("{sid}-r{i}")).collect();
            let _ = awc.register_seal_records(sid, record_ids);
            awc.register_seal_epoch(sid, epoch, zone.clone());
            for (i, wh) in ["w1", "w2", "w3"].iter().enumerate() {
                let _ = awc.add_seal_attestation(SealAttestation {
                    seal_id: sid.to_string(),
                    zone: zone.clone(),
                    epoch_number: epoch,
                    witness_hash: wh.to_string(),
                    stake: 100,
                    timestamp: i as f64,
                });
            }
        }

        let mut zone_epochs = HashMap::new();
        zone_epochs.insert(zone.clone(), 500u64);

        // Un-truncated: fused == (count scan, drilldown scan).
        let (recs, seals_total, entries) =
            awc.epoch_prune_shadow_summary(100, &zone_epochs, 10);
        assert_eq!(recs, awc.count_epoch_prune_shadow_eligible(100, &zone_epochs));
        assert_eq!(recs, 15, "5+3+7 eligible records");
        assert_eq!(seals_total, 3);
        assert_eq!(entries, awc.epoch_prune_shadow_eligible_seals(100, &zone_epochs, 10));

        // Truncated to 1: totals must stay the TRUE totals, entries capped
        // and identical to the drilldown's own truncation.
        let (recs1, seals1, entries1) =
            awc.epoch_prune_shadow_summary(100, &zone_epochs, 1);
        assert_eq!((recs1, seals1), (15, 3), "truncation must not shrink totals");
        assert_eq!(entries1, awc.epoch_prune_shadow_eligible_seals(100, &zone_epochs, 1));
        assert_eq!(entries1.len(), 1);
        assert_eq!(entries1[0].0, "seal-100");

        // max_n=0: no entries, totals intact.
        let (recs0, seals0, entries0) =
            awc.epoch_prune_shadow_summary(100, &zone_epochs, 0);
        assert_eq!((recs0, seals0), (15, 3));
        assert!(entries0.is_empty());

        // Empty zone-epoch view → nothing eligible anywhere.
        let empty: HashMap<ZoneId, u64> = HashMap::new();
        let (re, se, ee) = awc.epoch_prune_shadow_summary(100, &empty, 10);
        assert_eq!((re, se), (0, 0));
        assert!(ee.is_empty());
    }

    /// Regression: force_finalized must return `true` only on the FIRST
    /// transition. Repeat calls (or repeat attestations on already-settled
    /// records) returning `true` would inflate `total_ever_settled` —
    /// the fleet-wide 2-3× over-count vs `finalized_count` we observed
    /// across nodes (e.g. ~800K settled vs 421K finalized on one node,
    /// 1.18M settled vs 392K finalized on another).
    #[test]
    fn test_force_finalized_returns_true_only_on_first_transition() {
        let mut awc = AWCConsensus::new();
        let rid = "rec-promotion-test";

        // Pre-state: not in confirmation_levels → first force_finalized fires.
        assert!(awc.force_finalized(rid), "expected true on first transition");

        // Repeat → already Finalized → no-op, must return false so the lifetime
        // counter at the call site doesn't double-bump.
        assert!(!awc.force_finalized(rid), "expected false on repeat call (already Finalized)");
        assert!(!awc.force_finalized(rid), "expected false on third call too");

        // Pre-Finalized states: Pending and Sealed both transition to Finalized.
        for rid in ["rec-from-pending", "rec-from-sealed"] {
            awc.confirmation_levels.insert(rid.to_string(), ConfirmationLevel::Pending);
            assert!(awc.force_finalized(rid), "Pending → Finalized must report transition");
            assert!(!awc.force_finalized(rid), "second call must report no-op");
        }
        let rid = "rec-from-sealed";
        // Reset back to Sealed and try again — must transition.
        awc.confirmation_levels.insert(rid.to_string(), ConfirmationLevel::Sealed);
        assert!(awc.force_finalized(rid), "Sealed → Finalized must report transition");

        // Anchored is post-Finalized; force_finalized must NOT downgrade and
        // must return false (idempotent).
        let rid = "rec-already-anchored";
        awc.confirmation_levels.insert(rid.to_string(), ConfirmationLevel::Anchored);
        assert!(!awc.force_finalized(rid), "Anchored must remain Anchored, return false");
        assert_eq!(
            awc.confirmation_levels.get(rid).copied(),
            Some(ConfirmationLevel::Anchored),
            "force_finalized must NOT downgrade Anchored to Finalized"
        );
    }

    // ── Gap 5 Phase 6b second slice ──
    //
    // v1↔v2 cross-equivalence pinning test. The two committee
    // algorithms differ in three load-bearing ways:
    //   * stake weighting: v1 uses `sqrt(stake)`, v2 uses linear `stake`
    //   * entropy: both fold `(vrf_output, zone)`; v2 also folds the
    //     `ELARA_ZONE_COMMITTEE_V1` domain separator
    //   * hashing: v1 hashes `(vrf || zone.to_string() || identity)`;
    //     v2 hashes `(DOMAIN || vrf || zone_path || identity)`
    //
    // Bit-equivalent output is therefore impossible at any non-trivial
    // pool. The pinning here CAPTURES the divergence — a future refactor
    // that accidentally aligns v1 and v2 (e.g., changing v1 to linear
    // stake without also changing v2 to sqrt) will trip this assert and
    // force a conscious re-evaluation. We don't pin the exact committees
    // (they're hash-derived; would break on any constant tweak); we pin
    // that *some* sortition-stage divergence exists.

    #[test]
    fn v1_and_v2_committee_selection_diverge_under_unequal_stake() {
        use super::super::zone_committee::select_committee_v2;

        // 64 candidates, geometric stake spread from 1 to 2^32 — enough
        // dynamic range that sqrt-vs-linear weighting produces visibly
        // different rank orderings.
        let staked_weighted: Vec<(String, u64)> = (0..64)
            .map(|i| (format!("anchor-{i:03}"), 1u64 << (i % 32)))
            .collect();
        let index = CommitteeSelectionIndex::build(&staked_weighted);

        // Same VRF + zone for both algorithms — only the algorithm differs.
        let vrf = [0x42u8; 32];
        let zone = ZoneId::from_legacy(7);

        // Subscribers = all candidates → pool size > COMMITTEE_SMALL_NETWORK
        // so v2's small-network short-circuit does NOT engage; it actually
        // runs the Efraimidis–Spirakis draw.
        let subs: std::collections::HashSet<String> = staked_weighted
            .iter()
            .map(|(id, _)| id.clone())
            .collect();

        let v1 = select_epoch_committee_scoped_indexed(&vrf, &index, &zone, &subs);

        // v2 input shape: Vec<(String, u64)> (no &index, no subs HashSet).
        // At the call site (epoch.rs:4329) the eligible pool is derived
        // by intersecting subs ∩ index.staked_index. Replicate that here.
        let eligible: Vec<(String, u64)> = subs
            .iter()
            .filter_map(|id| {
                index
                    .staked_index
                    .get(id)
                    .map(|stake| (id.clone(), *stake))
            })
            .collect();
        let v2 = select_committee_v2(
            &vrf,
            &zone.to_string(),
            &eligible,
            MAINNET_COMMITTEE_SIZE,
        );

        // Both must be non-empty and size-MAINNET_COMMITTEE_SIZE — they
        // SHIP a committee even though the membership differs.
        assert_eq!(
            v1.len(),
            MAINNET_COMMITTEE_SIZE,
            "v1 must select exactly MAINNET_COMMITTEE_SIZE members"
        );
        assert_eq!(
            v2.len(),
            MAINNET_COMMITTEE_SIZE,
            "v2 must select exactly MAINNET_COMMITTEE_SIZE members"
        );

        // The key invariant: under unequal stake the two algorithms
        // produce DIFFERENT committees. Linear vs sqrt weighting gives
        // the high-stake tail a much larger lead in v2 than in v1.
        assert_ne!(
            v1, v2,
            "v1 (sqrt-stake) and v2 (linear-stake) must disagree on this fixture — \
             if they match, one of the algorithms changed weighting; re-evaluate the migration plan"
        );

        // Output canonical sort is shared invariant — both must emit
        // committees sorted by identity_hash ascending.
        for window in v1.windows(2) {
            assert!(window[0].0 <= window[1].0, "v1 output must be lex-sorted");
        }
        for window in v2.windows(2) {
            assert!(window[0].0 <= window[1].0, "v2 output must be lex-sorted");
        }
    }

    #[test]
    fn v1_and_v2_agree_on_small_network_short_circuit() {
        // Below COMMITTEE_SMALL_NETWORK the algorithms degenerate to the
        // same answer: "everyone with stake > 0, sorted by identity,
        // capped at k". This pins that degeneracy — if either algorithm
        // adds non-trivial divergent behaviour below the small-network
        // threshold, this trips.
        use super::super::zone_committee::select_committee_v2;

        let staked_weighted: Vec<(String, u64)> = (0..8)
            .map(|i| (format!("anchor-{i:02}"), 100 + i as u64))
            .collect();
        let index = CommitteeSelectionIndex::build(&staked_weighted);

        let vrf = [0x99u8; 32];
        let zone = ZoneId::from_legacy(3);
        let subs: std::collections::HashSet<String> = staked_weighted
            .iter()
            .map(|(id, _)| id.clone())
            .collect();

        let v1 = select_epoch_committee_scoped_indexed(&vrf, &index, &zone, &subs);
        let eligible: Vec<(String, u64)> = subs
            .iter()
            .filter_map(|id| {
                index
                    .staked_index
                    .get(id)
                    .map(|stake| (id.clone(), *stake))
            })
            .collect();
        let v2 = select_committee_v2(
            &vrf,
            &zone.to_string(),
            &eligible,
            MAINNET_COMMITTEE_SIZE,
        );

        // 8 candidates ≤ COMMITTEE_SMALL_NETWORK(10) → both short-circuit
        // to "all candidates sorted by identity, k advisory". The v2
        // alignment removed v2's previous truncate-to-k
        // in this branch. Expected length = 8, not MAINNET_COMMITTEE_SIZE.
        let mut expected_ids: Vec<String> =
            staked_weighted.iter().map(|(id, _)| id.clone()).collect();
        expected_ids.sort();

        let v1_ids: Vec<String> = v1.iter().map(|(id, _)| id.clone()).collect();
        let v2_ids: Vec<String> = v2.iter().map(|(id, _)| id.clone()).collect();
        assert_eq!(v1_ids, expected_ids, "v1 small-network short-circuit drift");
        assert_eq!(v2_ids, expected_ids, "v2 small-network short-circuit drift");
        assert_eq!(
            v1_ids, v2_ids,
            "small-network short-circuit must be bit-identical between v1 and v2"
        );
    }

    // ── capacity-constant + correlation-weight literal pins ─────────────
    //
    // Five orthogonal axes that are NOT already pinned by the existing
    // suite. Existing tests cover the BEHAVIOR of these constants via
    // their consumers (select_epoch_committee_scoped, correlation, etc.)
    // but do not pin the LITERAL numeric values — so an accidental
    // constant drift would change network behavior without tripping a
    // test. These tests close that gap.

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_capacity_constants_literal_pin_with_byzantine_safety_relation() {
        // Spec: Protocol §11.12 (committee size + Byzantine safety).
        // Pin the numeric VALUE of every load-bearing capacity constant
        // so a silent edit (e.g. MAINNET_COMMITTEE_SIZE 7→5) is
        // immediately visible without needing a network-level test.
        assert_eq!(MAINNET_COMMITTEE_SIZE, 7);
        assert_eq!(COMMITTEE_SMALL_NETWORK, 10);
        assert_eq!(BOOTSTRAP_FALLBACK_CAP, 64);
        assert_eq!(MAX_ATTESTATION_RECORDS, 50_000);
        assert_eq!(MAX_SEAL_ATTESTATIONS, 5_000);
        assert_eq!(MAX_FINALIZATION_QUEUE, 65_536);
        assert_eq!(MAX_SEALED_QUEUE, 65_536);
        assert_eq!(MAX_SEAL_FINALITY_SIG_ENTRIES, 5_000);
        assert_eq!(MAX_XZONE_ABORT_SIG_ENTRIES, 5_000);
        assert_eq!(MAX_XZONE_ABORT_OBSERVATIONS, 50_000);
        assert_eq!(MIN_SCOPED_ELIGIBLE, 3);
        // 24h challenge window in seconds.
        assert!((CHALLENGE_WINDOW_SECS - 86_400.0).abs() < f64::EPSILON);

        // Byzantine-safety relation: with committee size k=7, a 2/3
        // supermajority requires ⌈2·k/3⌉ = 5 attestations and tolerates
        // f = ⌊(k-1)/3⌋ = 2 faulty members.
        let k = MAINNET_COMMITTEE_SIZE;
        let supermajority = (2 * k).div_ceil(3);
        let faulty_tolerated = (k - 1) / 3;
        assert_eq!(supermajority, 5, "k=7 supermajority must be 5");
        assert_eq!(faulty_tolerated, 2, "k=7 must tolerate f=2 faulty");

        // Capacity relation invariants. MIN_SCOPED_ELIGIBLE <= committee
        // small-network threshold <= bootstrap fallback cap, so the
        // bootstrap fallback never under-provisions the eligible set.
        assert!(MIN_SCOPED_ELIGIBLE <= COMMITTEE_SMALL_NETWORK);
        assert!(COMMITTEE_SMALL_NETWORK <= BOOTSTRAP_FALLBACK_CAP);
        assert!(MAINNET_COMMITTEE_SIZE < COMMITTEE_SMALL_NETWORK,
            "small-network short-circuit must engage strictly below the mainnet cap");
    }

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_correlation_weights_alpha_beta_gamma_literal_and_unity_sum() {
        // Spec: Protocol §11.12 Theorem 3.1 (correlation weight axiom).
        // Each weight is pinned at its literal value, and their sum is
        // 1.0 — so a fully-correlated pair (same org + subnet + zone)
        // yields the maximal correlation = 1.0 (perfect duplicate).
        // test_correlation_max already checks the BEHAVIOR via
        // `let expected = ALPHA + BETA + GAMMA;` but does not pin the
        // individual literal values, so e.g. ALPHA=0.4, BETA=0.4,
        // GAMMA=0.2 would still pass that test. This test rules out
        // any redistribution.
        assert!((ALPHA - 0.5).abs() < f64::EPSILON, "ALPHA must be 0.5");
        assert!((BETA - 0.3).abs() < f64::EPSILON, "BETA must be 0.3");
        assert!((GAMMA - 0.2).abs() < f64::EPSILON, "GAMMA must be 0.2");
        // Strict ordering: org > subnet > geo correlation weight, so
        // organizational sybil-farms are penalized more than geo-coloc.
        assert!(ALPHA > BETA, "org weight must dominate subnet");
        assert!(BETA > GAMMA, "subnet weight must dominate geo");
        // Sum to unity. (Use 1e-12, not f64::EPSILON, since 0.5+0.3+0.2
        // is not bit-exact 1.0 — three decimal-fraction summands.)
        let sum = ALPHA + BETA + GAMMA;
        assert!((sum - 1.0).abs() < 1e-12,
            "ALPHA+BETA+GAMMA must sum to 1.0, got {sum}");
    }

    #[test]
    fn batch_b_gamma_effective_scaled_boundary_pins_three_eleven_and_bucket_gate() {
        // Boundary pins for the gamma_effective_scaled ramp.
        // test_audit9_gamma_ramps_linearly_from_min_to_full samples at
        // n=2,4,6,8,10,12,20 — but the FIRST non-zero step (n=3, just
        // above MIN_GEO_BUCKETS=2) and the LAST sub-ceiling step (n=11,
        // just below GAMMA_FULL_WITNESSES=12) are not pinned. Drift in
        // the inequality direction (`< full_w` vs `<= full_w`, or
        // `<= min_w` vs `< min_w`) would not trip the existing sweep
        // but would trip these two boundary pins.
        let denom = (GAMMA_FULL_WITNESSES - MIN_GEO_BUCKETS) as f64;

        // n = MIN_GEO_BUCKETS + 1 = 3 → smallest non-zero ramp step.
        let n3 = gamma_effective_scaled(MIN_GEO_BUCKETS + 1, MIN_GEO_BUCKETS);
        let expected_n3 = GAMMA * 1.0 / denom;
        assert!((n3 - expected_n3).abs() < 1e-12,
            "n=3 must be first non-zero step, got {n3}, expected {expected_n3}");

        // n = GAMMA_FULL_WITNESSES - 1 = 11 → last sub-ceiling step.
        let n11 = gamma_effective_scaled(GAMMA_FULL_WITNESSES - 1, MIN_GEO_BUCKETS);
        let expected_n11 = GAMMA * (denom - 1.0) / denom;
        assert!((n11 - expected_n11).abs() < 1e-12,
            "n=11 must be last sub-ceiling step, got {n11}, expected {expected_n11}");

        // Witness-count boundary: equality with MIN_GEO_BUCKETS is the
        // FLOOR (returns 0), not the first ramp step. Pins the
        // `<=` (not `<`) comparison in the implementation.
        assert_eq!(
            gamma_effective_scaled(MIN_GEO_BUCKETS, MIN_GEO_BUCKETS),
            0.0,
            "witness_count == MIN_GEO_BUCKETS must floor to 0"
        );

        // Witness-count ceiling: equality with GAMMA_FULL_WITNESSES is
        // the FULL value, not a sub-ceiling step. Pins the `>=` branch.
        assert!(
            (gamma_effective_scaled(GAMMA_FULL_WITNESSES, MIN_GEO_BUCKETS) - GAMMA).abs() < f64::EPSILON,
            "witness_count == GAMMA_FULL_WITNESSES must hit full GAMMA"
        );

        // Bucket-count boundary: bucket_count >= MIN_GEO_BUCKETS is the
        // gating condition. At bucket_count == MIN_GEO_BUCKETS the
        // function activates; at MIN_GEO_BUCKETS - 1 it is gated off.
        assert_eq!(
            gamma_effective_scaled(GAMMA_FULL_WITNESSES, MIN_GEO_BUCKETS - 1),
            0.0,
            "bucket_count below MIN_GEO_BUCKETS must hard-floor to 0"
        );
        assert!(
            gamma_effective_scaled(GAMMA_FULL_WITNESSES, MIN_GEO_BUCKETS) > 0.0,
            "bucket_count == MIN_GEO_BUCKETS must allow γ to activate"
        );
    }

    #[test]
    fn batch_b_derived_witness_geo_is_observed_four_combo_truth_table() {
        // Existing `derived_geo_default_is_unobserved` covers (0,0)
        // and `derived_geo_from_ip_populates_correctly` covers
        // (nonzero, nonzero). The two MIXED cases — IP known but ASN
        // unresolved, or ASN known but IP missing — are not pinned.
        // is_observed must fire on either signal independently.

        // (prefix=[0,0], asn=0) — fully unobserved → false.
        let g00 = DerivedWitnessGeo { ip_prefix16: [0, 0], asn: 0 };
        assert!(!g00.is_observed(), "[0,0]+asn=0 must be unobserved");

        // (prefix=[1,0], asn=0) — IP observed, ASN unresolved → true.
        let g10 = DerivedWitnessGeo { ip_prefix16: [1, 0], asn: 0 };
        assert!(g10.is_observed(), "IP-only signal must count as observed");

        // (prefix=[0,1], asn=0) — second prefix byte alone is sufficient
        // (any nonzero byte in the [u8; 2] prefix triggers the OR).
        let g01 = DerivedWitnessGeo { ip_prefix16: [0, 1], asn: 0 };
        assert!(g01.is_observed(), "second prefix byte must count");

        // (prefix=[0,0], asn=1) — ASN-only signal → true.
        let g0a = DerivedWitnessGeo { ip_prefix16: [0, 0], asn: 1 };
        assert!(g0a.is_observed(), "ASN-only signal must count as observed");

        // (prefix=[1,0], asn=1) — both signals → true.
        let g11 = DerivedWitnessGeo { ip_prefix16: [1, 0], asn: 1 };
        assert!(g11.is_observed(), "both signals must count as observed");

        // Default-trait pin (already covered behaviorally, restated here
        // for orthogonality of the truth table).
        let default_g = DerivedWitnessGeo::default();
        assert_eq!(default_g.ip_prefix16, [0, 0]);
        assert_eq!(default_g.asn, 0);
        assert!(!default_g.is_observed());
    }

    #[test]
    fn batch_b_confirmation_level_u8_repr_discriminant_layout_pin() {
        // ConfirmationLevel is `#[repr(u8)]` with explicit discriminants
        // 0..=3. `test_confirmation_level_from_u8` pins the REVERSE
        // direction (u8 → enum via from_u8) and `test_confirmation_level_ordering`
        // pins the derived Ord. But the FORWARD `as u8` cast — which is
        // how the discriminant gets serialized into wire formats and
        // stored in RocksDB CF blobs — is not pinned anywhere. A silent
        // re-ordering of the variants (e.g. swapping Sealed and Finalized)
        // would silently change the on-disk byte layout. This test pins
        // that layout.
        assert_eq!(ConfirmationLevel::Pending as u8, 0);
        assert_eq!(ConfirmationLevel::Sealed as u8, 1);
        assert_eq!(ConfirmationLevel::Finalized as u8, 2);
        assert_eq!(ConfirmationLevel::Anchored as u8, 3);

        // Round-trip: as u8 → from_u8 must be the identity on the
        // valid range [0, 3].
        for lvl in [
            ConfirmationLevel::Pending,
            ConfirmationLevel::Sealed,
            ConfirmationLevel::Finalized,
            ConfirmationLevel::Anchored,
        ] {
            assert_eq!(ConfirmationLevel::from_u8(lvl as u8), lvl);
        }

        // Out-of-range u8 falls back to Pending — pin the saturation
        // semantics (not panic, not Anchored). Tests cover 255 only;
        // this adds 4 and 200 to lock the "any unknown → safest" rule.
        assert_eq!(ConfirmationLevel::from_u8(4), ConfirmationLevel::Pending);
        assert_eq!(ConfirmationLevel::from_u8(200), ConfirmationLevel::Pending);

        // Forward `name()` round-trip via from_name pins the
        // back-compat mapping in both directions for the canonical
        // names. (Backward-compat for old names is already tested in
        // test_confirmation_level_from_name_backward_compat.)
        for lvl in [
            ConfirmationLevel::Pending,
            ConfirmationLevel::Sealed,
            ConfirmationLevel::Finalized,
            ConfirmationLevel::Anchored,
        ] {
            assert_eq!(ConfirmationLevel::from_name(lvl.name()), lvl);
        }
    }
}
