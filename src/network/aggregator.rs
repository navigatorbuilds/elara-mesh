//! VRF-ranked aggregator chain for epoch seal proposal.
//!
//! Replaces the "anyone-with-VRF-can-propose" seal loop with a bounded,
//! deterministic, stake-weighted rank chain. Per (zone, epoch), staked
//! identities are ranked `0..MAX_VIEW_DEPTH` by VRF-sorted priority.
//! Rank-0 proposes first; if rank-0 times out, rank-1 takes over; etc.
//! After `MAX_VIEW_DEPTH` ranks time out, the zone escalates to cross-zone
//! global quorum (Stage 3b — `session_2`).
//!
//! # Design rationale
//!
//! - **Bounded view depth, not `f+1`.** With `f ≈ 1000` per-zone at mainnet
//!   scale, an `f+1`-deep chain is useless: timeouts approach zero and every
//!   network jitter triggers a spurious view change. Instead we cap depth
//!   at `MAX_VIEW_DEPTH = 7`. Under honest-majority (< 1/3 byzantine),
//!   `Pr[7 consecutive malicious aggregators] = (1/3)^7 ≈ 0.05%`. The rare
//!   case falls through to cross-zone escalation.
//!
//! - **Stake-weighted VRF sampling.** A low-stake sybil farm must not dilute
//!   rank-0 away from honest large stakeholders. Each identity's hash-score
//!   is divided by `isqrt(stake)` (same √-dampening economics uses). Lower
//!   score wins — honest majority stake statistically dominates rank-0.
//!
//! - **Integer-only arithmetic.** All priority math is `u128` / `u64::isqrt`.
//!   No `f64`: determinism must hold across x86/ARM/WASM validators.
//!
//! - **Chained beacon.** `vrf_output` is expected to be
//!   `H(prev_epoch_seal_hash || epoch || zone)`. Chaining the beacon to the
//!   previous seal hash prevents last-moment beacon grinding — a proposer
//!   cannot bias its own rank by choosing the seed.
//!
//! Spec references:
//!   @spec Protocol §11.13 (aggregator chain, bounded view depth)
//!   @spec MESH-BFT §5.6 Theorem 4 (liveness, `O(log n)` finality; §4 is PQ security)

use crate::crypto::hash::sha3_256;
use crate::ZoneId;

/// Maximum aggregator ranks per epoch before cross-zone escalation.
///
/// Chosen as 7: under honest-majority assumption (< 1/3 byzantine),
/// `Pr[7 consecutive malicious] = (1/3)^7 ≈ 0.05%`. Log-bounded depth
/// decouples finality latency from zone size — `O(log n)` finality
/// holds regardless of how many nodes live in a zone.
pub const MAX_VIEW_DEPTH: usize = 7;

/// Return the first `max_rank` aggregator identities for this `(zone, vrf_output)`.
///
/// Sorted by ascending integer priority
/// `priority = hash_u128(vrf_output || zone || identity) / isqrt(stake)`.
/// Ties broken by lex order on identity (deterministic).
///
/// Bootstrap mode — empty `vrf_output` or empty set: lex-sorted identities
/// capped at `max_rank`. Matches `select_epoch_jury` bootstrap behavior.
///
/// # Determinism
///
/// All arithmetic is `u128` / `u64::isqrt`. Same inputs produce byte-identical
/// output on every platform (x86, ARM, WASM).
pub fn aggregator_chain_weighted(
    vrf_output: &[u8],
    staked: &[(String, u64)],
    zone: &ZoneId,
    max_rank: usize,
) -> Vec<String> {
    if staked.is_empty() || max_rank == 0 {
        return Vec::new();
    }

    // Bootstrap: no VRF seed yet → lex-order first `max_rank`
    if vrf_output.is_empty() {
        let mut out: Vec<String> = staked.iter().map(|(id, _)| id.clone()).collect();
        out.sort();
        out.truncate(max_rank);
        return out;
    }

    // Score each identity, then sort by priority.
    //
    // Priority math (all integer, no float):
    //   hash_u128 = top 16 bytes of SHA3-256(vrf_output || zone || identity)
    //   stake_root = max(1, isqrt(stake))  -- stake=0 → weight 1, rank-last
    //   priority  = hash_u128 / (stake_root as u128)
    //
    // Lower priority ⇒ higher rank. Cryptographic hash spreads identities
    // uniformly in [0, 2^128); stake_root compresses the space for
    // high-stake identities, giving them proportionally more probability
    // of landing near 0 (rank-0).
    // Hoist `zone.to_string()` out of the per-identity loop (was one String
    // allocation per identity) and reuse a single hash-input buffer (was one
    // Vec allocation per identity). The hash preimage stays byte-identical to
    // the prior `vrf_output || zone_str || identity` ordering — this is a pure
    // allocation optimization, N+N allocations → ~1.
    let zone_str = zone.to_string();
    let zone_bytes = zone_str.as_bytes();
    let mut input = Vec::with_capacity(vrf_output.len() + zone_bytes.len() + 64);
    let mut scored: Vec<(u128, &String)> = Vec::with_capacity(staked.len());
    for (identity, stake) in staked.iter() {
        input.clear();
        input.extend_from_slice(vrf_output);
        input.extend_from_slice(zone_bytes);
        input.extend_from_slice(identity.as_bytes());
        let hash = sha3_256(&input);

        let mut buf = [0u8; 16];
        buf.copy_from_slice(&hash[..16]);
        let hash_u128 = u128::from_be_bytes(buf);

        // isqrt on u64 stake. Zero stake → weight 1 (rank-last statistically).
        let stake_root = (*stake).isqrt().max(1);
        let priority = hash_u128 / (stake_root as u128);

        scored.push((priority, identity));
    }

    // SCALE (B11): select the `max_rank` smallest by `(priority asc, identity
    // lex asc)` WITHOUT sorting all N. `select_nth_unstable_by` partitions in
    // O(N); the final sort then touches only the k-element prefix (k =
    // MAX_VIEW_DEPTH, ~7), so the step is O(N) + O(k log k) instead of the old
    // O(N log N) full sort — the difference that turns a ~1 s/seal cost at 1 M
    // anchors into a near-linear scan. The comparator is a strict total order:
    // the ONLY pairs that compare `Equal` are byte-identical identities (the
    // unmodified duplicate-identity case), which produce identical output
    // strings regardless of the unstable partition's internal ordering. So the
    // result is bit-identical to the prior `sort_by(..).take(max_rank)`, pinned
    // by `top_k_bit_identical_to_full_sort_fuzz`. Lower priority wins; tie-break
    // by lex order on identity for determinism.
    let k = max_rank.min(scored.len());
    // k >= 1 here: the early return covered `max_rank == 0` and empty `staked`,
    // and `scored.len() == staked.len() >= 1`, so `k - 1` is always in-bounds.
    scored.select_nth_unstable_by(k - 1, |a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(b.1)));
    scored.truncate(k);
    scored.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(b.1)));

    scored.into_iter().map(|(_, id)| id.clone()).collect()
}

/// Rank an identity within the aggregator chain for `(zone, vrf_output)`.
///
/// Returns `Some(rank)` if the identity is among the first `max_rank` ranks,
/// else `None`. Rank 0 = highest priority (may propose first).
///
/// Callers: `epoch_seal_loop` checks `rank_of(self) <= current_allowed_rank`
/// before proposing a seal.
pub fn rank_of(
    vrf_output: &[u8],
    staked: &[(String, u64)],
    zone: &ZoneId,
    identity: &str,
    max_rank: usize,
) -> Option<usize> {
    let chain = aggregator_chain_weighted(vrf_output, staked, zone, max_rank);
    chain.iter().position(|w| w == identity)
}

/// Build the chained-beacon VRF input for a given zone-epoch.
///
/// `beacon = SHA3-256(prev_epoch_seal_hash || epoch_number_be || zone_str)`
///
/// Chaining to the previous seal hash binds rank selection to a value no
/// single node controls at proposal time — preventing beacon grinding.
///
/// Genesis epoch (no prior seal): `prev_epoch_seal_hash = [0u8; 32]`.
pub fn chained_beacon(
    prev_epoch_seal_hash: &[u8; 32],
    epoch_number: u64,
    zone: &ZoneId,
) -> [u8; 32] {
    let mut input = Vec::with_capacity(32 + 8 + 32);
    input.extend_from_slice(prev_epoch_seal_hash);
    input.extend_from_slice(&epoch_number.to_be_bytes());
    input.extend_from_slice(zone.to_string().as_bytes());
    sha3_256(&input)
}

/// Compute `current_allowed_rank` for a `(zone, epoch)` under the HotStuff-
/// style exponential-backoff schedule.
///
/// Rank `k` becomes eligible once elapsed time since the epoch's proposal
/// window opened reaches `(2^k - 1) * base_timeout`:
///
/// | rank | unlock time  |
/// |------|--------------|
/// |  0   | 0            |
/// |  1   | base         |
/// |  2   | 3·base       |
/// |  3   | 7·base       |
/// |  6   | 63·base      |
///
/// Capped at `MAX_VIEW_DEPTH - 1`. Integer-only — no f64.
///
/// # Units
///
/// Both `base_timeout_ms` and `elapsed_ms` are u64 milliseconds. Callers
/// clamp their inputs upstream (base to [1s, 10min]; elapsed to ≤1h) so a
/// misbehaving clock cannot produce absurd thresholds.
pub fn current_allowed_rank(base_timeout_ms: u64, elapsed_ms: u64) -> usize {
    if base_timeout_ms == 0 {
        return MAX_VIEW_DEPTH.saturating_sub(1);
    }
    let mut allowed: usize = 0;
    for k in 1..MAX_VIEW_DEPTH {
        let threshold = (1u64 << k).saturating_sub(1).saturating_mul(base_timeout_ms);
        if elapsed_ms >= threshold {
            allowed = k;
        } else {
            break;
        }
    }
    allowed
}

/// Stage 3c.1 — a zone is "stuck" once the entire rank ladder has timed out
/// without a seal, i.e. elapsed time past `(2^MAX_VIEW_DEPTH - 1) · base`.
///
/// At `MAX_VIEW_DEPTH = 7` that is `127 · base_timeout_ms`. Once this
/// returns `true`, the per-zone chain cannot emit a seal through the normal
/// rank path (even the last rank's timeout has elapsed), and cross-zone
/// escalation is permitted.
///
/// Pure: no async, no clock, no state. `base_timeout_ms` and `elapsed_ms`
/// must be clamped upstream by the caller (same discipline as
/// `current_allowed_rank`).
pub fn is_zone_stuck(base_timeout_ms: u64, elapsed_ms: u64) -> bool {
    if base_timeout_ms == 0 {
        // Degenerate base timeout — treat as never-stuck so escalation
        // cannot fire on a bogus input. Callers enforce the floor.
        return false;
    }
    let last_rank_threshold = (1u64 << MAX_VIEW_DEPTH)
        .saturating_sub(1)
        .saturating_mul(base_timeout_ms);
    elapsed_ms > last_rank_threshold
}

/// Pure rank-gating decision (Protocol §11.13 / MESH-BFT §4).
///
/// Takes all inputs as plain values — no async, no locks, no wall clock —
/// so it is unit-testable without constructing a `NodeState`. The
/// `should_propose_seal` wrapper in `epoch.rs` fetches live inputs from
/// state and delegates here.
///
/// Inputs to [`proposer_rank`] / [`rank_gate_decision`].
///
/// Bundled into a struct so callers don't trip the `too_many_arguments`
/// lint and so the named-field construction reads clearly at every call
/// site. All borrowed; no allocation on the proposal path.
///
/// Fields:
/// - `our_identity`: this node's identity hash.
/// - `genesis_authority`: identity hash of the genesis-authority node.
/// - `staked`: `(identity, stake)` for every active staker on the network.
/// - `zone`, `epoch_number`: the proposal target.
/// - `prev_seal_hash`: previous seal hash for this zone (`[0u8; 32]` if none).
/// - `base_timeout_ms`: `max(2·p95_rtt, 5s)` from the RTT estimator.
/// - `elapsed_ms`: wall-clock time since `epoch_start_ts` for this zone.
/// - `already_sealed`: `true` iff a seal for `epoch_number` is already
///   registered locally (idempotency guard).
pub struct ProposerRankInputs<'a> {
    pub our_identity: &'a str,
    pub genesis_authority: &'a str,
    pub staked: &'a [(String, u64)],
    pub zone: &'a ZoneId,
    pub epoch_number: u64,
    pub prev_seal_hash: &'a [u8; 32],
    pub base_timeout_ms: u64,
    pub elapsed_ms: u64,
    pub already_sealed: bool,
}

pub fn rank_gate_decision(inputs: ProposerRankInputs<'_>) -> bool {
    proposer_rank(inputs).is_some()
}

/// Rank-value variant of [`rank_gate_decision`] (Stage 3b.5).
///
/// Returns `Some(rank)` if this node is currently allowed to propose the
/// epoch seal for `(zone, epoch_number)` — where `rank` is the caller's
/// VRF-stake rank (0-indexed; lower = higher priority). Returns `None`
/// if the caller must not propose right now.
///
/// `rank_gate_decision` is a thin `is_some()` wrapper for callers that
/// only need the boolean; the seal creator uses `proposer_rank` to embed
/// the rank into the seal metadata so verifiers can check the schedule
/// (3b.6).
///
/// Bootstrap carve-out (`staked.len() < 3`) returns `Some(0)` for the
/// genesis authority — by construction the only eligible proposer — and
/// `None` otherwise.
pub fn proposer_rank(inputs: ProposerRankInputs<'_>) -> Option<u8> {
    let ProposerRankInputs {
        our_identity,
        genesis_authority,
        staked,
        zone,
        epoch_number,
        prev_seal_hash,
        base_timeout_ms,
        elapsed_ms,
        already_sealed,
    } = inputs;

    if already_sealed {
        return None;
    }
    // Bootstrap: fewer than 3 stakers → genesis-only proposal at rank 0.
    if staked.len() < 3 {
        return if our_identity == genesis_authority { Some(0) } else { None };
    }
    let beacon = chained_beacon(prev_seal_hash, epoch_number, zone);
    let our_rank = rank_of(&beacon, staked, zone, our_identity, MAX_VIEW_DEPTH)?;
    let allowed = current_allowed_rank(base_timeout_ms, elapsed_ms);
    if our_rank <= allowed {
        // rank_of caps at MAX_VIEW_DEPTH (7) so the u8 cast is safe.
        Some(our_rank as u8)
    } else {
        None
    }
}

/// Pure decision: should this node emit a cross-zone global quorum seal
/// for the given stuck zone? (Stage 3c.1 Part D).
///
/// Returns `true` iff all of:
/// 1. `our_natural_zone != stuck_zone` — MESH-BFT §11.13 requires the
///    emitter to live outside the stuck zone (check 2 in
///    `verify_global_quorum_seal`).
/// 2. `is_zone_stuck(base_timeout_ms, elapsed_ms)` holds — the per-zone
///    rank ladder is fully exhausted for `stuck_zone`.
/// 3. We are a registered staker with positive stake in
///    `our_natural_zone` — check 6 of the verifier. If we can't be
///    found in `stakers_by_zone`, the seal we emit would be rejected
///    downstream; don't waste the cycles.
/// 4. `!already_escalated` — someone already landed a global seal at
///    `(stuck_zone, stuck_epoch)`; duplicate escalations are no-ops
///    (idempotent in `EpochState::register_global_seal`) but we skip
///    to avoid gossip noise and wasted CPU.
///
/// All inputs are plain values — no async, no locks, no wall clock. The
/// seal-loop wrapper fetches the live inputs from state and delegates
/// here. Identity-to-zone assignment is deterministic via
/// `consensus::zone_for_record(&identity_hash)`; callers compute
/// `our_natural_zone` from the node's identity once and pass it in.
///
/// Bootstrap carve-out: unlike `proposer_rank`, global escalation has
/// no bootstrap path — by the time the rank ladder is fully exhausted,
/// the stake set is always large enough that bootstrap is long over.
/// Under `stakers_by_zone.is_empty()` the check in step 3 returns
/// false and we return false overall, which is the safe default.
pub fn escalation_decision(
    our_identity: &str,
    our_natural_zone: &ZoneId,
    stuck_zone: &ZoneId,
    stakers_by_zone: &std::collections::HashMap<ZoneId, Vec<(String, u64)>>,
    base_timeout_ms: u64,
    elapsed_ms: u64,
    already_escalated: bool,
) -> bool {
    if already_escalated {
        return false;
    }
    if our_natural_zone == stuck_zone {
        return false;
    }
    if !is_zone_stuck(base_timeout_ms, elapsed_ms) {
        return false;
    }
    stakers_by_zone
        .get(our_natural_zone)
        .is_some_and(|v| {
            v.iter().any(|(id, s)| id == our_identity && *s > 0)
        })
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn z() -> ZoneId {
        ZoneId::from_legacy(0)
    }

    fn make_staked(ids: &[(&str, u64)]) -> Vec<(String, u64)> {
        ids.iter().map(|(id, s)| (id.to_string(), *s)).collect()
    }

    /// Verbatim copy of the PRE-B11 `aggregator_chain_weighted` body (full
    /// sort + take). Frozen oracle for the differential fuzz test below —
    /// never change this; the optimized production path must match it bit-for-bit.
    fn reference_chain(
        vrf_output: &[u8],
        staked: &[(String, u64)],
        zone: &ZoneId,
        max_rank: usize,
    ) -> Vec<String> {
        if staked.is_empty() || max_rank == 0 {
            return Vec::new();
        }
        if vrf_output.is_empty() {
            let mut out: Vec<String> = staked.iter().map(|(id, _)| id.clone()).collect();
            out.sort();
            out.truncate(max_rank);
            return out;
        }
        let mut scored: Vec<(u128, &String)> = staked
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
                (priority, identity)
            })
            .collect();
        scored.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(b.1)));
        scored
            .into_iter()
            .take(max_rank)
            .map(|(_, id)| id.clone())
            .collect()
    }

    /// Dependency-free deterministic PRNG (xorshift64) — keeps the fuzz test
    /// reproducible in CI without pulling `rand`.
    fn xs(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        x
    }

    #[test]
    fn top_k_bit_identical_to_full_sort_fuzz() {
        // B11 differential oracle: the optimized `aggregator_chain_weighted`
        // (select_nth + k-prefix sort) MUST equal the frozen full-sort reference
        // for EVERY input — forced priority ties, DUPLICATE identity strings,
        // zero stakes, max_rank in {0, 1, .., >N}, N==0, and the bootstrap
        // (empty-VRF) branch. Any divergence would be a consensus fork.
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        for trial in 0..6_000u64 {
            let n = (xs(&mut state) % 60) as usize; // 0..=59 → exercises N==0 and k>N
            let max_rank = (xs(&mut state) % 12) as usize; // 0..=11
            let zone = ZoneId::from_legacy(xs(&mut state) % 8);

            let mut staked: Vec<(String, u64)> = Vec::with_capacity(n);
            for i in 0..n {
                // ~15% duplicate identities (reuse an earlier id verbatim).
                let id = if i > 0 && xs(&mut state).is_multiple_of(7) {
                    let j = (xs(&mut state) % i as u64) as usize;
                    staked[j].0.clone()
                } else {
                    format!("id-{i}")
                };
                // Heavy stake clustering forces isqrt collisions → priority ties.
                let stake = match xs(&mut state) % 4 {
                    0 => 0,                          // zero-stake → weight 1
                    1 => 1,                          // isqrt 1
                    2 => xs(&mut state) % 4 + 1,     // isqrt 1..=2, dense
                    _ => xs(&mut state) % 1_000_000, // spread
                };
                staked.push((id, stake));
            }

            // Every ~9th trial takes the bootstrap (empty-VRF) branch.
            let vrf: Vec<u8> = if xs(&mut state).is_multiple_of(9) {
                Vec::new()
            } else {
                (0..32).map(|_| (xs(&mut state) & 0xFF) as u8).collect()
            };

            let got = aggregator_chain_weighted(&vrf, &staked, &zone, max_rank);
            let want = reference_chain(&vrf, &staked, &zone, max_rank);
            assert_eq!(
                got, want,
                "B11 top-k diverged from full-sort oracle at trial {trial} \
                 (n={n}, max_rank={max_rank}, vrf_empty={})",
                vrf.is_empty()
            );

            // rank_of must agree with the produced chain (first occurrence for
            // duplicate identities — `position` returns the earliest).
            for id in got.iter() {
                assert_eq!(
                    rank_of(&vrf, &staked, &zone, id, max_rank),
                    got.iter().position(|x| x == id),
                    "rank_of mismatch trial {trial}"
                );
            }
        }
    }

    #[test]
    fn empty_set_returns_empty() {
        let out = aggregator_chain_weighted(&[1u8; 32], &[], &z(), MAX_VIEW_DEPTH);
        assert!(out.is_empty());
    }

    #[test]
    fn zero_max_rank_returns_empty() {
        let staked = make_staked(&[("a", 100), ("b", 200)]);
        let out = aggregator_chain_weighted(&[1u8; 32], &staked, &z(), 0);
        assert!(out.is_empty());
    }

    #[test]
    fn bootstrap_empty_vrf_returns_lex_order() {
        let staked = make_staked(&[("c", 1), ("a", 1), ("b", 1)]);
        let out = aggregator_chain_weighted(&[], &staked, &z(), MAX_VIEW_DEPTH);
        assert_eq!(out, vec!["a".to_string(), "b".to_string(), "c".to_string()]);
    }

    #[test]
    fn bootstrap_respects_max_rank() {
        let staked = make_staked(&[("c", 1), ("a", 1), ("b", 1), ("d", 1), ("e", 1)]);
        let out = aggregator_chain_weighted(&[], &staked, &z(), 2);
        assert_eq!(out, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn deterministic_same_input_same_output() {
        let staked = make_staked(&[("alice", 100), ("bob", 200), ("carol", 50)]);
        let vrf = [0x42u8; 32];
        let out1 = aggregator_chain_weighted(&vrf, &staked, &z(), MAX_VIEW_DEPTH);
        let out2 = aggregator_chain_weighted(&vrf, &staked, &z(), MAX_VIEW_DEPTH);
        assert_eq!(out1, out2, "same inputs must produce identical chain");
    }

    #[test]
    fn different_vrf_different_chain() {
        // With enough identities, different VRF seeds should generally produce
        // different rank-0. Uniform stakes to isolate the VRF effect.
        let staked = make_staked(&[
            ("n01", 10), ("n02", 10), ("n03", 10), ("n04", 10), ("n05", 10),
            ("n06", 10), ("n07", 10), ("n08", 10), ("n09", 10), ("n10", 10),
        ]);
        let mut seen_rank0 = std::collections::HashSet::new();
        for i in 0..20u8 {
            let vrf = [i; 32];
            let out = aggregator_chain_weighted(&vrf, &staked, &z(), 1);
            seen_rank0.insert(out[0].clone());
        }
        assert!(
            seen_rank0.len() > 1,
            "different VRF seeds must produce different rank-0 across 20 trials"
        );
    }

    #[test]
    fn different_zones_different_chains() {
        let staked = make_staked(&[
            ("n01", 10), ("n02", 10), ("n03", 10), ("n04", 10), ("n05", 10),
            ("n06", 10), ("n07", 10), ("n08", 10), ("n09", 10), ("n10", 10),
        ]);
        let vrf = [0x11u8; 32];
        let mut seen = std::collections::HashSet::new();
        for z_id in 0u64..20 {
            let out = aggregator_chain_weighted(&vrf, &staked, &ZoneId::from_legacy(z_id), 1);
            seen.insert(out[0].clone());
        }
        assert!(
            seen.len() > 1,
            "same VRF seed across different zones must produce different rank-0"
        );
    }

    #[test]
    fn chain_respects_max_rank() {
        let staked = make_staked(&[
            ("n01", 5), ("n02", 5), ("n03", 5), ("n04", 5), ("n05", 5),
            ("n06", 5), ("n07", 5), ("n08", 5), ("n09", 5), ("n10", 5),
        ]);
        let out = aggregator_chain_weighted(&[0xABu8; 32], &staked, &z(), 3);
        assert_eq!(out.len(), 3);
    }

    #[test]
    fn chain_smaller_than_max_rank_returns_all() {
        let staked = make_staked(&[("a", 1), ("b", 2)]);
        let out = aggregator_chain_weighted(&[0xCDu8; 32], &staked, &z(), MAX_VIEW_DEPTH);
        assert_eq!(out.len(), 2);
        // Both present, order depends on scoring but must be stable
        let mut sorted = out.clone();
        sorted.sort();
        assert_eq!(sorted, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn stake_weighting_dominates_rank_zero() {
        // Honest high-stake node vs many low-stake sybils.
        // Under uniform weighting, rank-0 would be random across all.
        // Under √-weighting, the high-stake node wins rank-0 disproportionately.
        let mut staked = vec![("whale".to_string(), 1_000_000u64)];
        for i in 0..100 {
            staked.push((format!("sybil{:03}", i), 100));
        }

        let mut whale_rank_0 = 0;
        let trials = 100;
        for i in 0..trials as u8 {
            let vrf = [i; 32];
            let out = aggregator_chain_weighted(&vrf, &staked, &z(), 1);
            if out[0] == "whale" {
                whale_rank_0 += 1;
            }
        }

        // Whale has sqrt(1_000_000) = 1000 vs sqrt(100) = 10 per sybil.
        // Whale weight = 1000, sybils total = 100 * 10 = 1000.
        // Expected whale rank-0 probability ≈ 1000 / (1000 + 1000) = 50%.
        // Allow wide margin for 100 trials — assert ≥ 30%.
        assert!(
            whale_rank_0 >= 30,
            "whale (1M stake) should take rank-0 at least 30% of trials; got {}/{}",
            whale_rank_0, trials
        );
    }

    #[test]
    fn zero_stake_ranks_last() {
        // An identity with 0 stake should almost never be rank-0 when
        // competitors have real stake. Zero stake gets weight 1 (minimum),
        // competitors with stake 10_000 get weight 100.
        let staked = make_staked(&[
            ("zero", 0),
            ("rich01", 10_000), ("rich02", 10_000), ("rich03", 10_000),
            ("rich04", 10_000), ("rich05", 10_000),
        ]);

        let mut zero_rank_0 = 0;
        let trials = 50u8;
        for i in 0..trials {
            let vrf = [i; 32];
            let out = aggregator_chain_weighted(&vrf, &staked, &z(), 1);
            if out[0] == "zero" {
                zero_rank_0 += 1;
            }
        }

        // Expected: very rare. zero weight=1, rich weight=100 each, total rich = 500.
        // Pr[zero wins rank-0] ≈ 1/501 ≈ 0.2%. Allow up to 3/50 for noise.
        assert!(
            zero_rank_0 <= 3,
            "zero-stake identity should rarely reach rank-0; got {}/{}",
            zero_rank_0, trials
        );
    }

    #[test]
    fn rank_of_returns_some_for_members() {
        let staked = make_staked(&[("a", 10), ("b", 20), ("c", 30)]);
        let vrf = [0x55u8; 32];
        let chain = aggregator_chain_weighted(&vrf, &staked, &z(), MAX_VIEW_DEPTH);
        for (i, id) in chain.iter().enumerate() {
            assert_eq!(
                rank_of(&vrf, &staked, &z(), id, MAX_VIEW_DEPTH),
                Some(i),
                "rank_of must match chain position"
            );
        }
    }

    #[test]
    fn rank_of_returns_none_beyond_max_rank() {
        // 10 identities, cap rank at 3 — ranks 3..9 must return None.
        let staked = make_staked(&[
            ("n01", 10), ("n02", 10), ("n03", 10), ("n04", 10), ("n05", 10),
            ("n06", 10), ("n07", 10), ("n08", 10), ("n09", 10), ("n10", 10),
        ]);
        let vrf = [0x77u8; 32];
        let full = aggregator_chain_weighted(&vrf, &staked, &z(), 10);
        let bounded = aggregator_chain_weighted(&vrf, &staked, &z(), 3);
        assert_eq!(bounded.len(), 3);
        for id in full.iter().skip(3) {
            assert_eq!(rank_of(&vrf, &staked, &z(), id, 3), None);
        }
    }

    #[test]
    fn rank_of_unknown_identity_returns_none() {
        let staked = make_staked(&[("a", 10), ("b", 20)]);
        assert_eq!(
            rank_of(&[0x01u8; 32], &staked, &z(), "ghost", MAX_VIEW_DEPTH),
            None
        );
    }

    // ── Freeze-trap boundary (C1 keystone): proposer eligibility by count ──
    //
    // The bootstrap carve-out (`staked.len() < 3`) is the protocol's most
    // safety-critical scalar boundary — it decides who may propose an epoch
    // seal. C1's audit fixed the operational invariant "never sit at 2
    // stakers; go 1→3 in one coordinated re-genesis": at <3 stakers ONLY the
    // genesis authority proposes, so a 2nd staker adds no proposer yet enters
    // the finality denominator (the "2 is the worst state" trap). These tests
    // pin the boundary so a future edit to `< 3` (→ `< 2`, `<= 3`, …) or a
    // drift from the verifier's mirror in `verify_aggregator_rank` is caught
    // at test time. Large `elapsed_ms` unlocks every in-view rank, isolating
    // eligibility on the staker-count carve-out, not the rank ladder.
    fn pr_inputs<'a>(
        me: &'a str,
        genesis: &'a str,
        staked: &'a [(String, u64)],
        zone: &'a ZoneId,
        prev: &'a [u8; 32],
    ) -> ProposerRankInputs<'a> {
        ProposerRankInputs {
            our_identity: me,
            genesis_authority: genesis,
            staked,
            zone,
            epoch_number: 1,
            prev_seal_hash: prev,
            base_timeout_ms: 1000,
            elapsed_ms: 1_000_000_000,
            already_sealed: false,
        }
    }

    /// Count how many of `members` (non-genesis) are eligible proposers.
    fn eligible_non_genesis(staked: &[(String, u64)], genesis: &str, members: &[&str]) -> usize {
        let prev = [0u8; 32];
        members
            .iter()
            .filter(|m| proposer_rank(pr_inputs(m, genesis, staked, &z(), &prev)).is_some())
            .count()
    }

    #[test]
    fn proposer_rank_solo_genesis_proposes() {
        let staked = make_staked(&[("genesis", 100)]);
        let prev = [0u8; 32];
        assert_eq!(
            proposer_rank(pr_inputs("genesis", "genesis", &staked, &z(), &prev)),
            Some(0),
            "solo genesis must propose at rank 0"
        );
        assert_eq!(
            proposer_rank(pr_inputs("ghost", "genesis", &staked, &z(), &prev)),
            None,
            "a non-staker is never an eligible proposer"
        );
    }

    #[test]
    fn proposer_rank_two_stakers_is_freeze_trap() {
        // C1 landmine: at exactly 2 stakers the carve-out STILL forces
        // genesis-only proposing — the 2nd staker adds NO proposer.
        let staked = make_staked(&[("genesis", 100), ("b", 100)]);
        let prev = [0u8; 32];
        assert_eq!(
            proposer_rank(pr_inputs("genesis", "genesis", &staked, &z(), &prev)),
            Some(0),
            "genesis still proposes at 2 stakers"
        );
        assert_eq!(
            eligible_non_genesis(&staked, "genesis", &["b"]),
            0,
            "2 stakers must add NO non-genesis proposer — '1→2 adds no proposer' (C1)"
        );
    }

    #[test]
    fn proposer_rank_three_stakers_escapes_trap() {
        // The escape: at 3 stakers the carve-out releases and VRF rotation
        // engages, so ≥1 non-genesis staker becomes eligible. This is exactly
        // why C1's audited path is a single 1→3 re-genesis, never 1→2→3.
        let staked = make_staked(&[("genesis", 100), ("b", 100), ("c", 100)]);
        assert!(
            eligible_non_genesis(&staked, "genesis", &["b", "c"]) >= 1,
            "at 3 stakers a non-genesis staker must be able to propose (rotation engaged)"
        );
    }

    #[test]
    fn proposer_rank_already_sealed_blocks_all() {
        let staked = make_staked(&[("genesis", 100), ("b", 100), ("c", 100)]);
        let prev = [0u8; 32];
        let zone = z();
        let mut inp = pr_inputs("genesis", "genesis", &staked, &zone, &prev);
        inp.already_sealed = true;
        assert_eq!(
            proposer_rank(inp),
            None,
            "an already-sealed epoch blocks every proposer (no double-seal)"
        );
    }

    #[test]
    fn chained_beacon_is_deterministic() {
        let prev = [0x11u8; 32];
        let b1 = chained_beacon(&prev, 42, &z());
        let b2 = chained_beacon(&prev, 42, &z());
        assert_eq!(b1, b2);
    }

    #[test]
    fn chained_beacon_changes_with_prev_hash() {
        let b0 = chained_beacon(&[0u8; 32], 42, &z());
        let b1 = chained_beacon(&[1u8; 32], 42, &z());
        assert_ne!(b0, b1, "beacon must bind to prev seal hash");
    }

    #[test]
    fn chained_beacon_changes_with_epoch() {
        let prev = [0x22u8; 32];
        let b41 = chained_beacon(&prev, 41, &z());
        let b42 = chained_beacon(&prev, 42, &z());
        assert_ne!(b41, b42, "beacon must bind to epoch number");
    }

    #[test]
    fn chained_beacon_changes_with_zone() {
        let prev = [0x33u8; 32];
        let b0 = chained_beacon(&prev, 100, &ZoneId::from_legacy(0));
        let b1 = chained_beacon(&prev, 100, &ZoneId::from_legacy(1));
        assert_ne!(b0, b1, "beacon must bind to zone");
    }

    #[test]
    fn beacon_grinding_resistance() {
        // An adversary controlling the current epoch's input bytes
        // cannot pick a `prev_epoch_seal_hash` that makes them rank-0.
        // Demonstrated by: changing only the prev hash reshuffles the chain
        // so no single input consistently produces a fixed rank-0.
        let staked = make_staked(&[
            ("n01", 100), ("n02", 100), ("n03", 100), ("n04", 100), ("n05", 100),
        ]);
        let mut rank_0_set = std::collections::HashSet::new();
        for i in 0u8..32 {
            let prev = [i; 32];
            let beacon = chained_beacon(&prev, 1000, &z());
            let out = aggregator_chain_weighted(&beacon, &staked, &z(), 1);
            rank_0_set.insert(out[0].clone());
        }
        // Across 32 different prev seals, multiple rank-0 winners must appear.
        assert!(
            rank_0_set.len() >= 2,
            "beacon chaining must reshuffle rank-0 across prev seal values"
        );
    }

    #[test]
    fn max_view_depth_is_seven() {
        // Lock the constant: changing this requires paper update (liveness theorem).
        assert_eq!(MAX_VIEW_DEPTH, 7);
    }

    // ── current_allowed_rank (§11.13 backoff schedule) ─────────────────────

    #[test]
    fn allowed_rank_zero_at_t_zero() {
        assert_eq!(current_allowed_rank(5_000, 0), 0);
    }

    #[test]
    fn allowed_rank_unlocks_at_exact_thresholds() {
        // base = 5s. Rank k unlocks at (2^k - 1) * 5000 ms.
        let b = 5_000;
        assert_eq!(current_allowed_rank(b, 4_999), 0);
        assert_eq!(current_allowed_rank(b, 5_000), 1);
        assert_eq!(current_allowed_rank(b, 14_999), 1);
        assert_eq!(current_allowed_rank(b, 15_000), 2); // 3*5000
        assert_eq!(current_allowed_rank(b, 35_000), 3); // 7*5000
        assert_eq!(current_allowed_rank(b, 315_000), 6); // 63*5000 — last rank
    }

    #[test]
    fn allowed_rank_caps_at_max_view_depth_minus_one() {
        let b = 1_000;
        // Way past all thresholds — must not exceed MAX_VIEW_DEPTH - 1.
        assert_eq!(current_allowed_rank(b, u64::MAX / 2), MAX_VIEW_DEPTH - 1);
    }

    #[test]
    fn allowed_rank_zero_base_degenerate() {
        // Defensive: zero base should not panic or saturate to 0-rank forever.
        // It falls through to "all ranks allowed" — rare / shouldn't happen
        // in production because the wrapper clamps base to ≥1000ms.
        assert_eq!(current_allowed_rank(0, 100), MAX_VIEW_DEPTH - 1);
    }

    // ── is_zone_stuck (Stage 3c.1 escalation trigger) ──────────────────────

    #[test]
    fn zone_stuck_false_before_last_rank_deadline() {
        let b = 5_000;
        // Last rank (rank 6 at MAX_VIEW_DEPTH=7) unlocks at 63·base = 315_000.
        // "Stuck" only fires after the rank-6 timer *itself* has elapsed,
        // i.e. strictly past (2^7 - 1)·base = 127·base = 635_000.
        assert!(!is_zone_stuck(b, 315_000), "just unlocked rank 6 is not stuck");
        assert!(!is_zone_stuck(b, 634_999), "one ms before rank-6 deadline is not stuck");
        assert!(!is_zone_stuck(b, 635_000), "exactly at rank-6 deadline is not stuck");
    }

    #[test]
    fn zone_stuck_true_past_last_rank_deadline() {
        let b = 5_000;
        assert!(is_zone_stuck(b, 635_001), "one ms past rank-6 deadline is stuck");
        assert!(is_zone_stuck(b, 700_000), "well past deadline is stuck");
        assert!(is_zone_stuck(b, u64::MAX / 2), "saturated elapsed is stuck");
    }

    #[test]
    fn zone_stuck_zero_base_never_stuck() {
        // Bogus base_timeout_ms must NOT trigger escalation — the sibling
        // `current_allowed_rank` returns MAX-1 for zero base; stuck would be
        // always-true on any nonzero elapsed, which is the opposite of what
        // we want (cascade escalation on a config bug). Return false instead.
        assert!(!is_zone_stuck(0, 0));
        assert!(!is_zone_stuck(0, u64::MAX));
    }

    // ── rank_gate_decision (full §11.13 policy) ────────────────────────────

    fn ids(n: usize) -> Vec<(String, u64)> {
        (0..n)
            .map(|i| (format!("identity-{i:02}"), 1_000_000))
            .collect()
    }

    #[test]
    fn rank_gate_bootstrap_genesis_only() {
        // < 3 stakers ⇒ only genesis proposes, regardless of rank.
        let staked = ids(2);
        let ours = "identity-01";
        let not_genesis = rank_gate_decision(ProposerRankInputs {
            our_identity: ours,
            genesis_authority: "GENESIS",
            staked: &staked,
            zone: &ZoneId::from_legacy(0),
            epoch_number: 1,
            prev_seal_hash: &[0u8; 32],
            base_timeout_ms: 5_000,
            elapsed_ms: 0,
            already_sealed: false,
        });
        assert!(!not_genesis, "non-genesis must not propose in bootstrap");

        let is_genesis = rank_gate_decision(ProposerRankInputs {
            our_identity: "GENESIS",
            genesis_authority: "GENESIS",
            staked: &staked,
            zone: &ZoneId::from_legacy(0),
            epoch_number: 1,
            prev_seal_hash: &[0u8; 32],
            base_timeout_ms: 5_000,
            elapsed_ms: 0,
            already_sealed: false,
        });
        assert!(is_genesis, "genesis must propose in bootstrap");
    }

    #[test]
    fn rank_gate_idempotent_refuses_already_sealed() {
        let staked = ids(10);
        let ours = &staked[0].0.clone();
        // Even if we're rank-0, already-sealed short-circuits to false.
        let can = rank_gate_decision(ProposerRankInputs {
            our_identity: ours,
            genesis_authority: "GENESIS",
            staked: &staked,
            zone: &ZoneId::from_legacy(0),
            epoch_number: 1,
            prev_seal_hash: &[0u8; 32],
            base_timeout_ms: 5_000,
            elapsed_ms: 60_000,
            already_sealed: true,
        });
        assert!(!can, "already-sealed epoch must not re-propose");
    }

    #[test]
    fn rank_gate_unknown_identity_returns_false() {
        let staked = ids(10);
        let can = rank_gate_decision(ProposerRankInputs {
            our_identity: "not-a-staker",
            genesis_authority: "GENESIS",
            staked: &staked,
            zone: &ZoneId::from_legacy(0),
            epoch_number: 1,
            prev_seal_hash: &[0u8; 32],
            base_timeout_ms: 5_000,
            elapsed_ms: u64::MAX / 2,
            already_sealed: false,
        });
        assert!(!can, "unknown identity must never propose");
    }

    #[test]
    fn rank_gate_rank_zero_proposes_at_t_zero() {
        let staked = ids(10);
        let zone = ZoneId::from_legacy(0);
        // Find the rank-0 winner at epoch 1.
        let beacon = chained_beacon(&[0u8; 32], 1, &zone);
        let chain = aggregator_chain_weighted(&beacon, &staked, &zone, MAX_VIEW_DEPTH);
        let rank_zero = &chain[0];
        let can = rank_gate_decision(ProposerRankInputs {
            our_identity: rank_zero,
            genesis_authority: "GENESIS",
            staked: &staked,
            zone: &zone,
            epoch_number: 1,
            prev_seal_hash: &[0u8; 32],
            base_timeout_ms: 5_000,
            elapsed_ms: 0,
            already_sealed: false,
        });
        assert!(can, "rank-0 must propose immediately at T=0");
    }

    #[test]
    fn rank_gate_rank_one_waits_base_timeout() {
        let staked = ids(10);
        let zone = ZoneId::from_legacy(0);
        let beacon = chained_beacon(&[0u8; 32], 1, &zone);
        let chain = aggregator_chain_weighted(&beacon, &staked, &zone, MAX_VIEW_DEPTH);
        let rank_one = &chain[1];
        // At T=0: blocked.
        let before = rank_gate_decision(ProposerRankInputs {
            our_identity: rank_one,
            genesis_authority: "GENESIS",
            staked: &staked,
            zone: &zone,
            epoch_number: 1,
            prev_seal_hash: &[0u8; 32],
            base_timeout_ms: 5_000,
            elapsed_ms: 0,
            already_sealed: false,
        });
        assert!(!before, "rank-1 must not propose before base_timeout");
        // At T=base: unlocked.
        let after = rank_gate_decision(ProposerRankInputs {
            our_identity: rank_one,
            genesis_authority: "GENESIS",
            staked: &staked,
            zone: &zone,
            epoch_number: 1,
            prev_seal_hash: &[0u8; 32],
            base_timeout_ms: 5_000,
            elapsed_ms: 5_000,
            already_sealed: false,
        });
        assert!(after, "rank-1 must propose at T=base");
    }

    #[test]
    fn rank_gate_rank_two_waits_3x_base() {
        let staked = ids(10);
        let zone = ZoneId::from_legacy(0);
        let beacon = chained_beacon(&[0u8; 32], 1, &zone);
        let chain = aggregator_chain_weighted(&beacon, &staked, &zone, MAX_VIEW_DEPTH);
        let rank_two = &chain[2];
        // At T=base (5s): rank-2 still blocked.
        let before = rank_gate_decision(ProposerRankInputs {
            our_identity: rank_two,
            genesis_authority: "GENESIS",
            staked: &staked,
            zone: &zone,
            epoch_number: 1,
            prev_seal_hash: &[0u8; 32],
            base_timeout_ms: 5_000,
            elapsed_ms: 5_000,
            already_sealed: false,
        });
        assert!(!before, "rank-2 must not propose until 3×base");
        // At T=3*base (15s): unlocked.
        let after = rank_gate_decision(ProposerRankInputs {
            our_identity: rank_two,
            genesis_authority: "GENESIS",
            staked: &staked,
            zone: &zone,
            epoch_number: 1,
            prev_seal_hash: &[0u8; 32],
            base_timeout_ms: 5_000,
            elapsed_ms: 15_000,
            already_sealed: false,
        });
        assert!(after, "rank-2 must propose at T=3·base");
    }

    #[test]
    fn rank_gate_non_top_seven_never_proposes() {
        // Adversarial: even way past all rank thresholds, an identity OUTSIDE
        // the top MAX_VIEW_DEPTH must not propose. That's cross-zone
        // escalation territory (3c.1), not self-promotion.
        let staked = ids(30);
        let zone = ZoneId::from_legacy(0);
        let beacon = chained_beacon(&[0u8; 32], 1, &zone);
        let chain = aggregator_chain_weighted(&beacon, &staked, &zone, MAX_VIEW_DEPTH);
        // Pick an identity NOT in the chain.
        let outsider = staked
            .iter()
            .map(|(id, _)| id.as_str())
            .find(|id| !chain.iter().any(|w| w == *id))
            .expect("should find at least one non-top-7");
        let can = rank_gate_decision(ProposerRankInputs {
            our_identity: outsider,
            genesis_authority: "GENESIS",
            staked: &staked,
            zone: &zone,
            epoch_number: 1,
            prev_seal_hash: &[0u8; 32],
            base_timeout_ms: 5_000,
            elapsed_ms: u64::MAX / 2,
            already_sealed: false,
        });
        assert!(!can, "identity outside top-MAX_VIEW_DEPTH must never propose");
    }

    // ── Stage 3c.1 Part D: escalation_decision ──────────────────────

    /// elapsed > 127·base so `is_zone_stuck` holds at base = 5s.
    const ESCALATION_STUCK_BASE_MS: u64 = 5_000;
    const ESCALATION_STUCK_ELAPSED_MS: u64 = 640_000;

    fn escalation_staker_map(
        entries: &[(ZoneId, &str, u64)],
    ) -> std::collections::HashMap<ZoneId, Vec<(String, u64)>> {
        let mut m: std::collections::HashMap<ZoneId, Vec<(String, u64)>> =
            std::collections::HashMap::new();
        for (zone, id, stake) in entries {
            m.entry(zone.clone())
                .or_default()
                .push((id.to_string(), *stake));
        }
        m
    }

    #[test]
    fn escalation_happy_path() {
        let our_zone = ZoneId::from_legacy(1);
        let stuck_zone = ZoneId::from_legacy(0);
        let stakers = escalation_staker_map(&[(our_zone.clone(), "me", 100)]);
        assert!(escalation_decision(
            "me",
            &our_zone,
            &stuck_zone,
            &stakers,
            ESCALATION_STUCK_BASE_MS,
            ESCALATION_STUCK_ELAPSED_MS,
            false,
        ));
    }

    #[test]
    fn escalation_rejects_same_zone() {
        let same_zone = ZoneId::from_legacy(2);
        let stakers = escalation_staker_map(&[(same_zone.clone(), "me", 100)]);
        assert!(!escalation_decision(
            "me",
            &same_zone,
            &same_zone,
            &stakers,
            ESCALATION_STUCK_BASE_MS,
            ESCALATION_STUCK_ELAPSED_MS,
            false,
        ));
    }

    #[test]
    fn escalation_rejects_not_stuck() {
        let our_zone = ZoneId::from_legacy(1);
        let stuck_zone = ZoneId::from_legacy(0);
        let stakers = escalation_staker_map(&[(our_zone.clone(), "me", 100)]);
        // Exactly at 127·base is NOT stuck (strict >).
        let not_stuck = 127 * ESCALATION_STUCK_BASE_MS;
        assert!(!escalation_decision(
            "me",
            &our_zone,
            &stuck_zone,
            &stakers,
            ESCALATION_STUCK_BASE_MS,
            not_stuck,
            false,
        ));
    }

    #[test]
    fn escalation_rejects_already_escalated() {
        let our_zone = ZoneId::from_legacy(1);
        let stuck_zone = ZoneId::from_legacy(0);
        let stakers = escalation_staker_map(&[(our_zone.clone(), "me", 100)]);
        assert!(!escalation_decision(
            "me",
            &our_zone,
            &stuck_zone,
            &stakers,
            ESCALATION_STUCK_BASE_MS,
            ESCALATION_STUCK_ELAPSED_MS,
            true, // somebody already landed one
        ));
    }

    #[test]
    fn escalation_rejects_unstaked_emitter() {
        let our_zone = ZoneId::from_legacy(1);
        let stuck_zone = ZoneId::from_legacy(0);
        // Zone 1 stakers exist but "me" is not among them.
        let stakers = escalation_staker_map(&[(our_zone.clone(), "somebody-else", 100)]);
        assert!(!escalation_decision(
            "me",
            &our_zone,
            &stuck_zone,
            &stakers,
            ESCALATION_STUCK_BASE_MS,
            ESCALATION_STUCK_ELAPSED_MS,
            false,
        ));
    }

    #[test]
    fn escalation_rejects_zero_stake_emitter() {
        let our_zone = ZoneId::from_legacy(1);
        let stuck_zone = ZoneId::from_legacy(0);
        // Registered but with zero stake → verifier check 6 would fail.
        let stakers = escalation_staker_map(&[(our_zone.clone(), "me", 0)]);
        assert!(!escalation_decision(
            "me",
            &our_zone,
            &stuck_zone,
            &stakers,
            ESCALATION_STUCK_BASE_MS,
            ESCALATION_STUCK_ELAPSED_MS,
            false,
        ));
    }

    #[test]
    fn escalation_rejects_empty_staker_map() {
        let our_zone = ZoneId::from_legacy(1);
        let stuck_zone = ZoneId::from_legacy(0);
        let empty = std::collections::HashMap::new();
        assert!(!escalation_decision(
            "me",
            &our_zone,
            &stuck_zone,
            &empty,
            ESCALATION_STUCK_BASE_MS,
            ESCALATION_STUCK_ELAPSED_MS,
            false,
        ));
    }

    #[test]
    fn escalation_rejects_degenerate_base_timeout() {
        // base_timeout_ms == 0 → is_zone_stuck returns false defensively.
        let our_zone = ZoneId::from_legacy(1);
        let stuck_zone = ZoneId::from_legacy(0);
        let stakers = escalation_staker_map(&[(our_zone.clone(), "me", 100)]);
        assert!(!escalation_decision(
            "me",
            &our_zone,
            &stuck_zone,
            &stakers,
            0,                    // bogus base
            ESCALATION_STUCK_ELAPSED_MS,
            false,
        ));
    }

    // ── end-to-end: all-aggregators-malicious → cross-zone escalation ───────
    //
    // MESH-BFT Phase 3 Stage 3 tickbox #7: "Test: all-aggregators-malicious
    // scenario, verify liveness via AWC degradation."
    //
    // Prior tests in this file exercise each piece in isolation
    // (`aggregator_chain_weighted`, `proposer_rank`, `escalation_decision`,
    // `is_zone_stuck`). This test stitches them together end-to-end with a
    // real `EpochState` so a regression in any single piece — OR in their
    // composition — fails a single assertion instead of silently letting a
    // stuck-zone liveness bug slip through.
    //
    // Scenario (MESH-BFT §4 liveness path):
    //   - Zone A holds 10 stakers. Every one of their top-7 ranks refuses
    //     to propose for `stuck_epoch = 1`. No seal lands.
    //   - `elapsed > 127 * base` on zone A ⇒ `is_zone_stuck(zone A) == true`.
    //   - A staker in zone B is honest, lives outside the stuck zone, and
    //     holds positive stake ⇒ passes `escalation_decision`.
    //   - Zone B emitter synthesizes a `ParsedGlobalQuorumSeal` for
    //     `(stuck_zone=A, stuck_epoch=1)` and registers it via
    //     `EpochState::register_global_seal`.
    //   - Post-register state advances: `latest_epoch[zone A] = 1`,
    //     `latest_seal_id[zone A]` points at the emitter's record, and a
    //     duplicate escalation attempt at the same `(stuck_zone, epoch)` is
    //     a no-op (idempotent — §11.13 design guarantee).
    #[test]
    fn end_to_end_all_aggregators_malicious_escalates() {
        use crate::network::epoch::{EpochState, ParsedGlobalQuorumSeal};

        let zone_a = ZoneId::from_legacy(0);
        let zone_b = ZoneId::from_legacy(1);

        // 10 zone-A stakers + 1 zone-B staker. Enough stakers that the
        // bootstrap carve-out (< 3) is bypassed on BOTH sides.
        let mut zone_a_stakers: Vec<(String, u64)> = (0..10)
            .map(|i| (format!("zone-a-staker-{i:02}"), 1_000_000))
            .collect();
        let zone_b_emitter = ("zone-b-honest-emitter".to_string(), 500_000);
        let mut all_stakers = zone_a_stakers.clone();
        all_stakers.push(zone_b_emitter.clone());
        // Global staker list used by rank-gate — rank assignments are across
        // ALL stakers, not just zone A. (Rank is a VRF-weighted global order;
        // the zone filter applies to escalation, not proposal.)
        zone_a_stakers.sort();

        // Deterministic prev-seal hash so `chained_beacon` output is fixed.
        let prev_seal_hash = [0x42u8; 32];
        let epoch_number: u64 = 1;

        // Base timeout intentionally tiny — 100ms — so stuck threshold
        // is 127 * 100 = 12.7s (easy to express in test arithmetic).
        const BASE_MS: u64 = 100;
        const STUCK_ELAPSED_MS: u64 = 13_000;

        // 1. Zone A's top-7 rank slate. Every identity in this slate is
        //    "malicious" in the test — we assert the BEHAVIOR of the system
        //    when none of them land a seal.
        let beacon = chained_beacon(&prev_seal_hash, epoch_number, &zone_a);
        let top_seven = aggregator_chain_weighted(&beacon, &all_stakers, &zone_a, MAX_VIEW_DEPTH);
        assert_eq!(
            top_seven.len(), MAX_VIEW_DEPTH,
            "with 11 stakers the rank chain must fill all {MAX_VIEW_DEPTH} slots"
        );

        // 2. Before the stuck threshold, escalation is FORBIDDEN — verifies
        //    the time-gate protects against premature escalation.
        assert!(!is_zone_stuck(BASE_MS, BASE_MS * 10));

        // 3. Past the stuck threshold, is_zone_stuck fires AND an 11th-ranked
        //    identity (outside top-7) is never eligible to propose — so the
        //    refusal of the top-7 alone is sufficient to starve zone A.
        assert!(is_zone_stuck(BASE_MS, STUCK_ELAPSED_MS));
        // Find a zone-A staker NOT in the top-7 — guaranteed to exist since
        // zone_a has 10 stakers and top_seven has 7.
        let outside_top_seven: &str = zone_a_stakers
            .iter()
            .map(|(id, _)| id.as_str())
            .find(|id| !top_seven.iter().any(|t| t == *id))
            .expect("zone A has > MAX_VIEW_DEPTH stakers");
        assert!(
            proposer_rank(ProposerRankInputs {
                our_identity: outside_top_seven,
                genesis_authority: "GENESIS",
                staked: &all_stakers,
                zone: &zone_a,
                epoch_number,
                prev_seal_hash: &prev_seal_hash,
                base_timeout_ms: BASE_MS,
                elapsed_ms: STUCK_ELAPSED_MS,
                already_sealed: false,
            })
            .is_none(),
            "identity ranked > MAX_VIEW_DEPTH must never propose, even past the stuck threshold"
        );

        // 4. Zone-B emitter is OUTSIDE the stuck zone and holds stake ⇒
        //    escalation is permitted.
        let stakers_by_zone = escalation_staker_map(&[
            (zone_b.clone(), &zone_b_emitter.0, zone_b_emitter.1),
        ]);
        assert!(
            escalation_decision(
                &zone_b_emitter.0,
                &zone_b,
                &zone_a,
                &stakers_by_zone,
                BASE_MS,
                STUCK_ELAPSED_MS,
                false, /* not yet escalated */
            ),
            "honest zone-B emitter must pass escalation gate"
        );

        // 5. Register the global seal on a real EpochState. This is where
        //    the three pieces above actually converge on state.
        let mut epoch_state = EpochState::new();
        let gseal = ParsedGlobalQuorumSeal {
            stuck_zone: zone_a.clone(),
            emitter_zone: zone_b.clone(),
            stuck_epoch: epoch_number,
            previous_seal_hash: prev_seal_hash,
            observed_base_timeout_ms: BASE_MS,
            observed_elapsed_ms: STUCK_ELAPSED_MS,
            emitted_at: 0.0,
            vrf_output: [0u8; 32],
            vrf_proof: vec![0u8; 80],
            seal_zone_count: None,
        };
        let record_id = "global-seal-escalation-record-001";
        let record_hash = [0xABu8; 32];
        epoch_state.register_global_seal(&gseal, record_id, record_hash);

        // 6. Zone A's chain advanced via the cross-zone path.
        assert_eq!(
            epoch_state.latest_epoch.get(&zone_a).copied(),
            Some(epoch_number),
            "stuck zone's latest_epoch must advance after global seal"
        );
        assert_eq!(
            epoch_state.latest_seal_id.get(&zone_a).map(String::as_str),
            Some(record_id),
        );
        assert_eq!(
            epoch_state.latest_seal_hash.get(&zone_a).copied(),
            Some(record_hash),
        );

        // 7. Idempotence (§11.13): a second register_global_seal at the same
        //    (stuck_zone, stuck_epoch) is a no-op. Attempting to downgrade
        //    to an older epoch must not corrupt latest_epoch either.
        let stale = ParsedGlobalQuorumSeal {
            stuck_epoch: 0,
            ..gseal.clone()
        };
        epoch_state.register_global_seal(&stale, "stale-record", [0xCDu8; 32]);
        assert_eq!(
            epoch_state.latest_epoch.get(&zone_a).copied(),
            Some(epoch_number),
            "stale global seal must NOT rewind latest_epoch"
        );
        assert_eq!(
            epoch_state.latest_seal_id.get(&zone_a).map(String::as_str),
            Some(record_id),
            "stale global seal must NOT overwrite the winning record_id"
        );
    }

    // ─── view-depth threshold pure-helper tests ─────────────────────────────
    //
    // Fixture-free pins on pure helpers — exercise orthogonal axes not
    // covered by the existing tests. No NodeState, no async, no I/O.

    /// MAX_VIEW_DEPTH=7 implies stuck-threshold multiplier 127 and
    /// last-rank threshold multiplier 63; the gap (= 64 = 2^(D-1)) is rank-6's
    /// proposal window before global escalation fires. Cross-checked through
    /// both helpers at the strict-inequality boundary.
    #[test]
    fn batch_b_max_view_depth_derived_thresholds_pin_127_63_and_gap_64() {
        assert_eq!(MAX_VIEW_DEPTH, 7, "view depth must remain 7 for (1/3)^7 invariant");
        let stuck_mult = (1u64 << MAX_VIEW_DEPTH).saturating_sub(1);
        assert_eq!(stuck_mult, 127, "stuck multiplier = 2^7 - 1 = 127");
        let last_rank_mult = (1u64 << (MAX_VIEW_DEPTH - 1)).saturating_sub(1);
        assert_eq!(last_rank_mult, 63, "last-rank multiplier = 2^6 - 1 = 63");
        assert_eq!(
            stuck_mult - last_rank_mult,
            64,
            "rank-6 proposal window must be 64·base = 2^(D-1)·base"
        );
        let base = 1000u64;
        let elapsed_at_rank6 = last_rank_mult * base;
        assert_eq!(
            current_allowed_rank(base, elapsed_at_rank6),
            MAX_VIEW_DEPTH - 1,
            "elapsed = 63·base must unlock rank-6 exactly"
        );
        assert!(
            !is_zone_stuck(base, elapsed_at_rank6),
            "elapsed = 63·base must NOT be stuck (rank-6 window open)"
        );
        let elapsed_at_stuck_bound = stuck_mult * base;
        assert!(
            !is_zone_stuck(base, elapsed_at_stuck_bound),
            "exactly 127·base is the strict-inequality boundary, not yet stuck"
        );
        assert!(
            is_zone_stuck(base, elapsed_at_stuck_bound + 1),
            "127·base + 1ms must be stuck"
        );
    }

    /// chained_beacon input is exactly `prev_hash(32) || epoch_be(8)
    /// || zone_str`. Pins byte layout by manual SHA3-256 reconstruction AND
    /// proves epoch is big-endian (little-endian produces a different beacon).
    #[test]
    fn batch_b_chained_beacon_exact_byte_layout_pin_be_epoch() {
        let prev = [0xABu8; 32];
        let epoch = 0x0102030405060708u64;
        let zone = ZoneId::from_legacy(42);
        let actual = chained_beacon(&prev, epoch, &zone);
        let mut manual = Vec::with_capacity(32 + 8 + 32);
        manual.extend_from_slice(&prev);
        manual.extend_from_slice(&epoch.to_be_bytes());
        manual.extend_from_slice(zone.to_string().as_bytes());
        let expected = sha3_256(&manual);
        assert_eq!(
            actual, expected,
            "chained_beacon must match manual SHA3-256(prev||epoch_be8||zone_str)"
        );
        let mut le_manual = Vec::with_capacity(32 + 8 + 32);
        le_manual.extend_from_slice(&prev);
        le_manual.extend_from_slice(&epoch.to_le_bytes());
        le_manual.extend_from_slice(zone.to_string().as_bytes());
        let with_le = sha3_256(&le_manual);
        assert_ne!(
            actual, with_le,
            "epoch MUST be big-endian; LE encoding produces a different beacon"
        );
    }

    /// aggregator_chain returns up to min(staked.len(), max_rank).
    /// Existing tests cover max_rank < staked.len (truncate down); this pins
    /// the over-request case where max_rank > staked.len (no padding, no panic).
    #[test]
    fn batch_b_aggregator_chain_returns_min_of_staked_len_and_max_rank() {
        let staked = make_staked(&[("a", 100), ("b", 200), ("c", 50)]);
        let out = aggregator_chain_weighted(&[0x42u8; 32], &staked, &z(), 100);
        assert_eq!(
            out.len(),
            3,
            "max_rank=100 > staked.len()=3 must return 3 entries (no padding)"
        );
        let out_boot = aggregator_chain_weighted(&[], &staked, &z(), 100);
        assert_eq!(
            out_boot.len(),
            3,
            "bootstrap mode (empty VRF) must also cap at staked.len()"
        );
        let out_one = aggregator_chain_weighted(&[0x42u8; 32], &staked, &z(), 1);
        assert_eq!(out_one.len(), 1, "max_rank=1 must return exactly 1 entry");
    }

    /// stake=0 is treated as weight 1 via `.max(1)` on `isqrt`:
    /// `0u64.isqrt()=0 → .max(1)=1`, same as `1u64.isqrt()=1 → .max(1)=1`.
    /// Pins (a) no divide-by-zero, (b) zero-stake stays in the chain,
    /// (c) priority identical to stake=1 for the same identity+hash.
    #[test]
    fn batch_b_zero_stake_treated_as_weight_one_via_max1_isqrt() {
        let with_zero = make_staked(&[("a", 0), ("b", 100), ("c", 100)]);
        let with_one = make_staked(&[("a", 1), ("b", 100), ("c", 100)]);
        let vrf = [0x77u8; 32];
        let out_zero = aggregator_chain_weighted(&vrf, &with_zero, &z(), MAX_VIEW_DEPTH);
        let out_one = aggregator_chain_weighted(&vrf, &with_one, &z(), MAX_VIEW_DEPTH);
        assert_eq!(
            out_zero, out_one,
            "stake=0 must produce identical chain to stake=1 (both → weight 1)"
        );
        assert!(
            out_zero.contains(&"a".to_string()),
            "zero-stake identity MUST still appear in the chain (not dropped)"
        );
        assert_eq!(out_zero.len(), 3, "no identity dropped under stake=0");
    }

    /// `rank_of(id)` is consistent with `aggregator_chain_weighted`:
    /// `Some(i)` ⟺ `chain[i]==id`, and `None` ⟺ id not in chain. Also pins
    /// the edge cases: unknown identity → None, max_rank=0 → None for all.
    #[test]
    fn batch_b_rank_of_consistency_with_aggregator_chain() {
        let staked = make_staked(&[("alpha", 50), ("bravo", 200), ("charlie", 100)]);
        let vrf = [0x55u8; 32];
        let chain = aggregator_chain_weighted(&vrf, &staked, &z(), MAX_VIEW_DEPTH);
        assert_eq!(chain.len(), 3, "chain must include all 3 stakers");
        for (i, ident) in chain.iter().enumerate() {
            assert_eq!(
                rank_of(&vrf, &staked, &z(), ident, MAX_VIEW_DEPTH),
                Some(i),
                "rank_of must return Some({}) for chain-member {}",
                i,
                ident
            );
        }
        assert_eq!(
            rank_of(&vrf, &staked, &z(), "unknown_identity", MAX_VIEW_DEPTH),
            None,
            "rank_of for non-staker must return None"
        );
        assert_eq!(
            rank_of(&vrf, &staked, &z(), "alpha", 0),
            None,
            "rank_of with max_rank=0 must return None even for known staker"
        );
    }
}
