//! Per-zone VRF witness committee selection (Gap 5 core).
//!
//! Given a population of eligible anchors (each with a bonded beat
//! stake) and a target committee size `k`, this module selects **which
//! anchors witness a specific zone at a specific epoch** — deterministic
//! across nodes, stake-weighted, unpredictable ahead of the seed.
//!
//! The selection rule is Efraimidis–Spirakis weighted reservoir sampling
//! with the uniform draw replaced by a SHA3-256 hash of `(domain || zone ||
//! epoch || identity)`. Each candidate `i` gets a priority key
//!
//! ```text
//!   key_i = hash(i) / weight_i              (treated as rational)
//! ```
//!
//! and the `k` candidates with the *smallest* key win. Rational
//! comparison is done by cross-multiplication in u128 so the output is
//! bit-for-bit identical on every CPU regardless of float behaviour.
//!
//! ## Why per-zone committees matter at 1M-zone scale
//!
//! If every attestation had to be signed by every bonded anchor, a
//! 10K-anchor fleet with 1M zones × 720 seals/day/zone would drown in
//! O(7.2 trillion) signatures/day. The committee-per-zone design cuts
//! this to k signatures/seal (k ≈ 5-17). Safety is preserved by
//! stake-weighting + per-epoch rotation:
//!
//! * Stake weighting means an adversary with ε of the stake gets ε of
//!   the seats on average — they can't buy majorities cheaply.
//! * Per-epoch rotation means the attacker doesn't know next epoch's
//!   committee ahead of time, so they can't corrupt it in advance.
//!
//! ## Scale
//!
//! * `select_zone_committee`: O(n log n) in eligible-population `n`
//!   (sort dominates). At n = 10K this is microseconds.
//! * Pure function, no I/O, no locks.
//! * Deterministic: every node with the same `(zone, epoch,
//!   eligible_set, stake_map)` computes the same committee.
//!
//! ## Spec references
//!
//! * Protocol §11.12 Multi-anchor VRF sealing
//! * MESH-BFT §5 Diversity-weighted BFT

use crate::crypto::hash::sha3_256;

/// Domain separator so a committee-selection hash can never collide
/// with some other use of `sha3(zone || epoch || id)` elsewhere in the
/// protocol (seal-hashing, fisherman jury, etc.).
const COMMITTEE_DOMAIN: &[u8] = b"ELARA_ZONE_COMMITTEE_V1";

/// Minimum committee size. A fleet with only a handful of eligible
/// anchors can still produce a committee; this just names the floor
/// the protocol considers meaningful. Callers may pass smaller `k`
/// and get a smaller committee — the fn does not clamp.
pub const MIN_COMMITTEE_SIZE: usize = 5;

/// Default committee size target. Used when the caller doesn't have a
/// load-driven size for the zone yet. 7 matches the BFT-style "5+2"
/// sizing — 5 for safety under f=1, 7 for f=2 headroom.
pub const DEFAULT_COMMITTEE_SIZE: usize = 7;

// Compile-time invariants on the committee-size knobs. A future edit that
// drops `MIN_COMMITTEE_SIZE` below 5 violates BFT f=1 (need 3f+1 = 4
// honest, 5 total to tolerate 1 byzantine + 1 fault), or sets
// `DEFAULT_COMMITTEE_SIZE` below `MIN_COMMITTEE_SIZE` (default smaller
// than the named floor), now fails at `cargo build`, not at `cargo test`.
const _: () = assert!(
    MIN_COMMITTEE_SIZE >= 5,
    "MIN_COMMITTEE_SIZE must stay >= 5 — fewer seats than BFT f=1 demands"
);
const _: () = assert!(
    DEFAULT_COMMITTEE_SIZE >= MIN_COMMITTEE_SIZE,
    "DEFAULT_COMMITTEE_SIZE must be at or above MIN_COMMITTEE_SIZE — default below the named floor is incoherent"
);

/// One candidate anchor with its bonded-stake weight.
///
/// `weight` MUST be non-zero. The selector treats weight 0 as "skip
/// this candidate" — a zero-stake anchor cannot win a seat, which
/// matches the intent of stake-gated selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// Stable identity hash (hex or raw — the selector treats it as
    /// opaque bytes). Must match whatever key other layers use to
    /// refer to this node (e.g., `Identity::identity_hash`).
    pub identity_hash: String,
    /// Bonded stake in protocol-native units. Higher weight raises the
    /// probability of selection linearly. Zero means ineligible.
    pub weight: u64,
}

/// Select `k` committee members for `(zone_id, epoch)` using
/// stake-weighted VRF sortition.
///
/// Returns the selected identity hashes in deterministic order (sorted
/// by priority key — lowest first, which the protocol interprets as
/// "highest rank"). If `eligible` is empty, or all weights are zero,
/// returns an empty `Vec`. If `k > eligible.len()` the return is
/// capped at `eligible.len()` (the fn does not pad or error).
///
/// # Invariants
///
/// * Determinism: two nodes with the same `(zone_id, epoch, eligible)`
///   — where `eligible` is the same *set*, order-independent — get the
///   same committee. Callers don't need to pre-sort `eligible`; we
///   re-sort by the derived priority keys.
/// * Stake monotonicity: if candidate A has higher weight than B, A's
///   expected selection probability is higher. The exact distribution
///   is the Efraimidis–Spirakis weighted-without-replacement draw,
///   which is the standard construction with this property.
///
/// # Domain separation
///
/// The hash input is `sha3_256(DOMAIN || zone_bytes || epoch_le ||
/// identity_bytes)`. `zone_bytes` is the path string as UTF-8 — matches
/// `ZoneId::as_path_str()`. `epoch_le` is 8 bytes little-endian so the
/// wire format is unambiguous.
pub fn select_zone_committee(
    zone_path: &str,
    epoch: u64,
    eligible: &[Candidate],
    k: usize,
) -> Vec<String> {
    if k == 0 || eligible.is_empty() {
        return Vec::new();
    }

    // Build (key, identity) pairs, dropping zero-weight candidates.
    // Key is the 128-bit prefix of the SHA3 hash — enough entropy that
    // collisions are astronomically unlikely at any realistic
    // eligible-population size, and small enough that cross-
    // multiplication below fits in u128 × u64 ≤ u192 which we still
    // safely compare via u128-constrained arithmetic.
    let mut keyed: Vec<(u128, u64, &str)> = eligible
        .iter()
        .filter(|c| c.weight > 0)
        .map(|c| {
            let mut buf = Vec::with_capacity(
                COMMITTEE_DOMAIN.len() + zone_path.len() + 8 + c.identity_hash.len(),
            );
            buf.extend_from_slice(COMMITTEE_DOMAIN);
            buf.extend_from_slice(zone_path.as_bytes());
            buf.extend_from_slice(&epoch.to_le_bytes());
            buf.extend_from_slice(c.identity_hash.as_bytes());
            let h = sha3_256(&buf);
            let mut key = [0u8; 16];
            key.copy_from_slice(&h[..16]);
            (u128::from_be_bytes(key), c.weight, c.identity_hash.as_str())
        })
        .collect();

    if keyed.is_empty() {
        return Vec::new();
    }

    // Sort ascending by rank = key / weight (small = high priority).
    // Cross-multiplication in u128 is exact: (key_i / w_i) < (key_j / w_j)
    // iff key_i * w_j < key_j * w_i. `key * w` fits in u128 because key
    // is 128 bits already; u128.checked_mul(u128::from(w)) overflows
    // for key near 2^128 and w > 1. We therefore compare by the
    // "small-argument" form — key_i < key_j / (w_j / w_i), handled via
    // u256 math. Simpler: shift key down by 32 bits so key_trimmed *
    // weight always fits in u128 (96 + 64 = 160 ... still not safe).
    //
    // Simpler-still approach that IS safe: map priority to a u64 via
    // key / weight with a u128 numerator, since u128 / u64 → u128 but
    // the quotient is bounded by u128::MAX / 1 = u128::MAX. That's
    // fine for comparison — just sort by the u128 quotient. No
    // overflow, exactly the rational we want, and deterministic.
    keyed.sort_by(|a, b| {
        let rank_a = a.0 / a.1 as u128;
        let rank_b = b.0 / b.1 as u128;
        rank_a
            .cmp(&rank_b)
            // Tiebreaker: identity hash string. Pure-integer sort above
            // can tie (same rank bucket for two different ids) — a
            // lexicographic tiebreaker keeps the output canonical.
            .then_with(|| a.2.cmp(b.2))
    });

    keyed
        .into_iter()
        .take(k)
        .map(|(_, _, id)| id.to_string())
        .collect()
}

/// Gap 5 Phase 6b second slice — unified committee-selection algorithm.
///
/// Reconciles the two coexisting committee algorithms into one. Folds:
///
/// * **VRF entropy** (`vrf_output`, 32 bytes) — unpredictable per-zone
///   per-epoch seed signed by the prior seal. Strictly stronger than
///   `epoch` alone, which is predictable.
/// * **Domain separation** (`ELARA_ZONE_COMMITTEE_V1`) — free defence
///   against cross-protocol hash collisions.
/// * **Linear stake weighting** (`rank = key / weight`) — proper
///   Efraimidis–Spirakis. Stake-proportional selection probability;
///   matches MESH-BFT §5.
/// * **Sort-by-identity output** — downstream consumers
///   (`committee_hash_from_members`, attestation gating) depend on
///   lexical ordering. Preserved from the consensus-path output shape.
/// * **Small-network short-circuit** — when |eligible| ≤
///   `COMMITTEE_SMALL_NETWORK`, return everyone sorted by identity.
///   Sub-cluster "diversity" is moot below this size.
/// * **Empty-VRF bootstrap** — when `vrf_output.is_empty()`, return
///   the eligible set sorted by identity (deterministic pre-VRF
///   behaviour, matches consensus-path bootstrap).
///
/// **Not bit-identical to either pre-existing algorithm.** The whole
/// point of the slice is to migrate. `select_epoch_committee_scoped_indexed`
/// stays for legacy callers and v1↔v2 cross-equivalence tests; new
/// production use sites consult this function via the `use_committee_v2`
/// `NodeConfig` flag.
///
/// # Parameters
///
/// * `vrf_output` — per-zone per-epoch VRF output (32 bytes). Empty
///   slice triggers the bootstrap pre-VRF path.
/// * `zone_path` — `ZoneId::as_path_str()` of the target zone.
/// * `eligible` — staked-anchor candidates. Each `(identity_hash,
///   stake)`. Zero-stake entries are filtered out (cannot win a seat).
/// * `k` — target committee size (typically `MAINNET_COMMITTEE_SIZE`).
///   `k = 0` or empty eligible returns an empty Vec.
///
/// # Returns
///
/// `Vec<(identity_hash, stake)>` sorted lexicographically by
/// identity, capped at `k`.
///
/// # Determinism
///
/// Same `(vrf_output, zone_path, eligible_as_set, k)` → bit-identical
/// output on every node. Order of `eligible` does not matter — the
/// internal sort by `(rank, identity)` is canonical.
pub fn select_committee_v2(
    vrf_output: &[u8],
    zone_path: &str,
    eligible: &[(String, u64)],
    k: usize,
) -> Vec<(String, u64)> {
    if k == 0 || eligible.is_empty() {
        return Vec::new();
    }

    // Empty-VRF bootstrap (no sealed epoch yet for this zone): return
    // the eligible set sorted by identity, capped at k. Matches the
    // pre-VRF short-circuit in `select_epoch_committee_scoped_indexed`.
    if vrf_output.is_empty() {
        let mut out: Vec<(String, u64)> = eligible.to_vec();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out.truncate(k);
        return out;
    }

    // Small-network short-circuit — everyone with stake > 0 attests,
    // sorted by identity. Same rationale as the consensus-path
    // `COMMITTEE_SMALL_NETWORK` branch: at sub-cluster pool sizes,
    // per-zone diversity is moot.
    let non_zero: Vec<(String, u64)> = eligible
        .iter()
        .filter(|(_, w)| *w > 0)
        .cloned()
        .collect();
    if non_zero.is_empty() {
        return Vec::new();
    }
    if non_zero.len() <= super::consensus::COMMITTEE_SMALL_NETWORK {
        // Small-network branch: k is ADVISORY here. Everyone
        // with stake > 0 attests, matching v1's
        // `select_epoch_committee_scoped_indexed` at consensus.rs:719
        // ("Small network: everyone attests"). An earlier truncation here
        // was a behaviour divergence — pinned by the
        // `v1_and_v2_agree_on_small_network_short_circuit`
        // test, fixed here. Sub-cluster
        // diversity is moot below this size, so the seal carrying
        // a few extra signatures is cheap; the alternative (silently
        // dropping members) breaks bft headroom on small fleets.
        let mut out = non_zero;
        out.sort_by(|a, b| a.0.cmp(&b.0));
        return out;
    }

    // Linear-stake-weighted Efraimidis–Spirakis draw. Identical math
    // to `select_zone_committee` but with `vrf_output` folded into
    // the hash input instead of just `epoch`.
    let mut keyed: Vec<(u128, u64, String)> = non_zero
        .into_iter()
        .map(|(id, w)| {
            let mut buf = Vec::with_capacity(
                COMMITTEE_DOMAIN.len() + vrf_output.len() + zone_path.len() + id.len(),
            );
            buf.extend_from_slice(COMMITTEE_DOMAIN);
            buf.extend_from_slice(vrf_output);
            buf.extend_from_slice(zone_path.as_bytes());
            buf.extend_from_slice(id.as_bytes());
            let h = sha3_256(&buf);
            let mut key = [0u8; 16];
            key.copy_from_slice(&h[..16]);
            (u128::from_be_bytes(key), w, id)
        })
        .collect();

    keyed.sort_by(|a, b| {
        let rank_a = a.0 / a.1 as u128;
        let rank_b = b.0 / b.1 as u128;
        rank_a.cmp(&rank_b).then_with(|| a.2.cmp(&b.2))
    });

    let mut out: Vec<(String, u64)> = keyed
        .into_iter()
        .take(k)
        .map(|(_, w, id)| (id, w))
        .collect();

    // Canonical output ordering — downstream consumers depend on
    // sort-by-identity (committee_hash_from_members, attestation gate
    // lookups).
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// Build a candidate pool from a list of VRF-registered anchor
/// identities and a stake lookup. Only anchors with stake > 0 end up
/// in the pool — zero-stake anchors cannot carry attestation weight
/// (protocol §5, MESH-BFT), so there's no point drawing them.
///
/// Pure function: caller provides both inputs. The live wiring (Phase
/// 5b) threads `state.vrf_registry.registered_identities()` and
/// `state.ledger.staked(id)` into this.
///
/// Order-independent: sorts the output by identity so downstream
/// selection is deterministic regardless of caller iteration order.
pub fn assemble_candidates(
    registered: impl IntoIterator<Item = String>,
    stake_of: impl Fn(&str) -> u64,
) -> Vec<Candidate> {
    assemble_candidates_with_fallback(registered, stake_of, 0)
}

/// Same as [`assemble_candidates`] but assigns `fallback_weight` to
/// any candidate whose `stake_of(id)` returns 0 instead of dropping
/// them. Used by Gap 2.1 Phase 2b.3 finality committees, where
/// witness-tier nodes have a captured Dilithium PK but may not yet
/// have bonded beat — a non-zero `fallback_weight` keeps them in the
/// Efraimidis–Spirakis draw at the smallest possible weight, so
/// staked anchors still dominate selection but small fleets aren't
/// stuck below `MIN_COMMITTEE_SIZE`. `fallback_weight = 0` reproduces
/// the strict (mainnet-correct) behaviour.
pub fn assemble_candidates_with_fallback(
    registered: impl IntoIterator<Item = String>,
    stake_of: impl Fn(&str) -> u64,
    fallback_weight: u64,
) -> Vec<Candidate> {
    let mut out: Vec<Candidate> = registered
        .into_iter()
        .filter_map(|id| {
            let w = stake_of(&id);
            if w > 0 {
                Some(Candidate { identity_hash: id, weight: w })
            } else if fallback_weight > 0 {
                Some(Candidate { identity_hash: id, weight: fallback_weight })
            } else {
                None
            }
        })
        .collect();
    // Sort to make the output canonical. `select_zone_committee` is
    // already order-independent, but downstream observability (e.g.,
    // `/committees` RPC) benefits from stable ordering.
    out.sort_by(|a, b| a.identity_hash.cmp(&b.identity_hash));
    out
}

/// Commit a selected committee to a 32-byte hash for inclusion in
/// [`super::zone_transition_seal::ZoneSnapshot::committee_hash`].
///
/// Domain: `ELARA_COMMITTEE_HASH_V1 || epoch_le || sorted_members_joined_by_|`
/// Members are sorted lexicographically before hashing so the result is
/// identical regardless of call-site ordering.
///
/// An empty committee (no eligible anchors) returns all-zeros — the
/// placeholder value the validator treats as "not yet known." Callers
/// should log a WARN when this happens at runtime, as it indicates no
/// staked anchors exist for the zone.
pub fn committee_hash_from_members(members: &[String], epoch: u64) -> [u8; 32] {
    if members.is_empty() {
        return [0u8; 32];
    }
    const HASH_DOMAIN: &[u8] = b"ELARA_COMMITTEE_HASH_V1";
    let mut sorted = members.to_vec();
    sorted.sort_unstable();
    let mut buf = Vec::with_capacity(
        HASH_DOMAIN.len() + 8 + sorted.iter().map(|s| s.len() + 1).sum::<usize>(),
    );
    buf.extend_from_slice(HASH_DOMAIN);
    buf.extend_from_slice(&epoch.to_le_bytes());
    for m in &sorted {
        buf.extend_from_slice(m.as_bytes());
        buf.push(b'|');
    }
    sha3_256(&buf)
}

/// PK-leaf committee root for the cross-zone seal-finality cycle (Gap 2.1
/// Phase 2b.3). Builds a binary Merkle tree whose leaves are
/// [`crate::accounting::cross_zone::committee_leaf_hash`] applied to each
/// witness's Dilithium3 public key. The output equals the
/// `committee_hash` field that consumer-side
/// [`crate::accounting::cross_zone::verify_finality_quorum`] expects, so a
/// producer can pin this snapshot in a `SealFinalityCollection` and
/// downstream zones can verify Merkle membership of every signing
/// witness against the same root.
///
/// This is **not** the same hash as [`committee_hash_from_members`],
/// which hashes UTF-8 `identity_hash` strings into a one-shot SHA3
/// (used for transition-seal `ZoneSnapshot::committee_hash`). The two
/// coexist intentionally: transition seals already shipped under V1
/// and would break on a hash change, while the finality cycle never
/// had a producer-side hash before — so it adopts the structurally
/// correct PK-leaf tree from day one. Epoch binding for the finality
/// cycle lives in the signable message
/// (`xzone_finality_signable_bytes(zone, seal_epoch, merkle_root,
/// committee_hash)`), so the committee root itself does not need to
/// fold epoch in.
///
/// # Determinism
///
/// PKs are sorted lexicographically before tree construction, so the
/// root is invariant under input ordering. Duplicate PKs are
/// deduplicated up front — a witness signs each seal once.
///
/// # Empty / single-leaf
///
/// * `pks.is_empty()` returns `[0u8; 32]` — same sentinel as
///   [`committee_hash_from_members`].
/// * A single-leaf tree returns the leaf hash directly.
/// * Odd levels duplicate the trailing leaf (standard
///   "duplicate-last" Merkle convention).
pub fn committee_hash_from_pks(pks: &[Vec<u8>]) -> [u8; 32] {
    if pks.is_empty() {
        return [0u8; 32];
    }
    let mut leaves: Vec<[u8; 32]> = pks
        .iter()
        .map(|pk| crate::accounting::cross_zone::committee_leaf_hash(pk))
        .collect();
    leaves.sort_unstable();
    leaves.dedup();
    while leaves.len() > 1 {
        let mut next = Vec::with_capacity(leaves.len().div_ceil(2));
        let mut i = 0;
        while i < leaves.len() {
            let l = leaves[i];
            let r = if i + 1 < leaves.len() { leaves[i + 1] } else { leaves[i] };
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&l);
            buf[32..].copy_from_slice(&r);
            next.push(sha3_256(&buf));
            i += 2;
        }
        leaves = next;
    }
    leaves[0]
}

/// Build a `zone_path → committee` map for every active zone in one
/// sweep. `k` is the committee size target; see
/// [`DEFAULT_COMMITTEE_SIZE`].
///
/// Pure over inputs. Typical call site:
///
/// ```ignore
/// let candidates = assemble_candidates(registered_ids, |id| ledger.staked(id));
/// let active: Vec<String> = state.zone_registry
///     .read_recover()
///     .active_zones()
///     .map(|z| z.as_path_str().to_string())
///     .collect();
/// let committees = build_zone_committees_for_active(active, epoch, &candidates, DEFAULT_COMMITTEE_SIZE);
/// ```
///
/// Scale: O(Z × n log n) where Z is active-zone count and n is
/// eligible population. At 1M zones × 10K eligible this is
/// `~10^10 × log(10^4) = ~10^11` hash operations per full sweep —
/// not hot-path cheap. The wire design is to draw committees **lazily
/// per zone per epoch** from the same primitive, or to cache the
/// per-epoch sweep. This bulk helper is for tests, operator
/// observability (`/committees` RPC), and small fleets.
pub fn build_zone_committees_for_active(
    active_zones: impl IntoIterator<Item = String>,
    epoch: u64,
    candidates: &[Candidate],
    k: usize,
) -> std::collections::BTreeMap<String, Vec<String>> {
    let mut out = std::collections::BTreeMap::new();
    for zone_path in active_zones {
        let committee = select_zone_committee(&zone_path, epoch, candidates, k);
        out.insert(zone_path, committee);
    }
    out
}

/// Check whether `identity_hash` is a member of the committee for
/// `(zone_path, epoch)`.
///
/// Pure function — same inputs on any node give the same answer. This
/// is the predicate Phase 6 enforcement will consult: at attestation
/// ingest, if the signer is not in the committee the attestation is
/// rejected. Phase 6a (this helper) is advisory only — exposed via
/// RPC for operators to diff against peers, never called from the
/// consensus hot path.
///
/// Returns `(is_member, selection_rank)`. The rank is the 0-based
/// position in the committee (0 = strongest draw), or `None` if the
/// identity wasn't selected. Exposing the rank is cheap once we've
/// already computed the committee, and it lets a dashboard show
/// "signer is 3rd of 7" without a second round trip.
pub fn is_in_committee(
    zone_path: &str,
    epoch: u64,
    candidates: &[Candidate],
    k: usize,
    identity_hash: &str,
) -> (bool, Option<usize>) {
    let committee = select_zone_committee(zone_path, epoch, candidates, k);
    match committee.iter().position(|id| id == identity_hash) {
        Some(rank) => (true, Some(rank)),
        None => (false, None),
    }
}

/// Default page size for paginated committee snapshots. At
/// k=DEFAULT_COMMITTEE_SIZE=7 × ~32-byte identity hashes per slot
/// this caps a `/committees` response body at roughly 1 MB before
/// JSON formatting overhead — bounded enough that an operator dash
/// won't OOM the serving node, large enough that a 5-zone testnet
/// fits in a single page.
pub const DEFAULT_COMMITTEES_PAGE_SIZE: usize = 1000;

/// Hard upper bound on a `/committees` page, enforced at the route against the
/// peer-supplied `?limit=` query param. Unclamped, `?limit=1000000` would
/// materialize a million-entry page — each entry runs a per-zone committee draw
/// — which violates the O(active_window) scale rule and can OOM the serving
/// node at 1M-zone mainnet. 5× the default leaves operator headroom while
/// keeping the worst-case body and draw count bounded.
pub const MAX_COMMITTEES_PAGE_SIZE: usize = 5000;

/// Snapshot of active-zone committees at a specific epoch, paginated
/// by zone-path lex order. Designed to serve `/committees` and — once
/// Phase 6 wires this into attestation-path enforcement — to be the
/// single source of truth for "which anchors should sign which zone's
/// seal".
///
/// `from` + `limit` cap the per-call work at `limit` zone
/// committee draws (one resolver lookup per zone). Without this cap,
/// at 1M active zones a single `/committees` request would compute
/// 1M committees and serialize a ~250 MB JSON response, OOM-ing the
/// node. The first item of the returned tuple is the (sorted, lex)
/// page; the second item is `next_from` — `Some(zone_path)` to start
/// the next page from (caller passes it as the next `from`), or
/// `None` if this page exhausted the active set.
///
/// Reads under the `zone_registry`, `vrf_registry`, and `ledger`
/// locks. Returns a `BTreeMap` so repeated calls produce byte-
/// identical JSON (important for operator diff-against-peer checks).
///
/// Any lock poisoning recovers via the `LockRecover`/`RwLockRecover`
/// extension traits — a node does not fail a committee snapshot
/// because some unrelated worker panicked.
pub async fn state_committees_snapshot(
    state: &crate::network::state::NodeState,
    epoch: u64,
    k: usize,
    from: Option<&str>,
    limit: usize,
) -> (
    std::collections::BTreeMap<String, Vec<String>>,
    Option<String>,
) {
    use super::RwLockRecover;

    // 1. Eligible anchors — the VRF-registered set. std::sync lock.
    let registered: Vec<String> = {
        let reg = state.vrf_registry.read_recover();
        reg.registered_identities()
            .iter()
            .map(|s| s.to_string())
            .collect()
    };

    // 2. Stake per anchor — from the ledger (tokio::sync RwLock).
    //    One read-lock acquisition across the sweep for consistency.
    let candidates = {
        let ledger = state.ledger.read().await;
        assemble_candidates(registered, |id| ledger.staked(id))
    };

    // 3. Active leaf zones — from the post-transition zone tree.
    //    Collect into a sorted vec so pagination is deterministic
    //    across nodes. zone_registry's iter order is tree-walk; sort
    //    explicitly so the page boundary is consensus-neutral.
    let mut zones: Vec<String> = {
        let reg = state.zone_registry.read_recover();
        reg.active_zones().map(|z| z.path().to_string()).collect()
    };
    zones.sort();

    // 4. Apply pagination. `from` is the inclusive lower bound (lex);
    //    we skip entries strictly less than it. `limit` caps the page.
    //    Plus one peek to compute `next_from` without a second pass.
    let start_idx = match from {
        Some(f) => zones.partition_point(|z| z.as_str() < f),
        None => 0,
    };
    // saturating_add: `limit` traces to the `?limit=` query param on
    // /committees (clamped to MAX_COMMITTEES_PAGE_SIZE at the route, but this is
    // a pub fn callable with any value). With a `from` cursor start_idx can be
    // > 0 — even on a single-zone node, `from="z"` makes partition_point return
    // 1 — so a raw `start_idx + usize::MAX` panics under overflow-checks=true.
    // Saturating pins at usize::MAX; .min(zones.len()) then yields the correct
    // clamped page boundary (past-the-end → empty page) — same intent, no panic.
    let end_idx = start_idx.saturating_add(limit).min(zones.len());
    let page = &zones[start_idx..end_idx];
    let next_from = if end_idx < zones.len() {
        Some(zones[end_idx].clone())
    } else {
        None
    };

    // 5. Per-zone draw via the shared resolver cache. Bounded by `limit`
    //    — at limit=1000 this is a 1000-entry page, not a million-entry
    //    sweep. Repeat calls under the same `(epoch, k, candidates)` hit
    //    the cache for every zone already drawn this epoch.
    let mut out = std::collections::BTreeMap::new();
    for zone_path in page {
        let committee = state.zone_committee_resolver.resolve(
            zone_path,
            epoch,
            &candidates,
            k,
        );
        out.insert(zone_path.clone(), committee);
    }
    (out, next_from)
}

/// Resolve `(zone, epoch, k)` to the PK-leaf committee — the producer-side
/// primitive for Gap 2.1 Phase 2b.3 cross-zone seal-finality.
///
/// Returns `(pks, committee_hash, committee_size)`:
/// * `pks` — the witness Dilithium PKs of every committee member, in
///   sorted order (sort key is `committee_leaf_hash(pk)` — same order
///   the consumer's Merkle membership check sees). A node can use this
///   to discover whether *itself* is on the committee (compare against
///   own PK) and to bundle the snapshot into a `SealFinalityCollection`.
/// * `committee_hash` — equals [`committee_hash_from_pks`]`(pks)`. This
///   is the value pinned in `SealFinalityCollection.committee_hash`
///   on first signature, so all subsequent signers must agree on it.
/// * `committee_size` — `pks.len()` cast to `u32`.
///
/// Members whose PK is not yet captured in `CF_IDENTITIES` are silently
/// dropped (they cannot sign a finality witness anyway, since
/// `verify_finality_quorum` requires Merkle membership of the signer's
/// PK against the pinned root). This means a node that just registered
/// VRF but has never signed an attestation will not appear in the
/// finality committee until it has produced its first record. That is
/// the correct safety posture: if the network does not know your PK,
/// it cannot verify your signature.
///
/// # Lock discipline
///
/// Same as [`state_committees_snapshot`]:
/// 1. `vrf_registry` (std::sync) — registered identities
/// 2. `ledger` (tokio::sync) — stake-of for each id
/// 3. `rocks` (RocksDB point reads, no async) — pk-of for each selected id
///
/// PK reads are sequential synchronous RocksDB point reads. Bounded by
/// `k` (default 5). At 1M zones × 5 witnesses we'd not call this for
/// every zone in one shot — this is the "one zone, one epoch" lookup;
/// the per-epoch sweep is built lazily in
/// [`build_zone_committees_for_active`].
pub async fn finality_committee_pks(
    state: &crate::network::state::NodeState,
    zone_path: &str,
    epoch: u64,
    k: usize,
) -> (Vec<Vec<u8>>, [u8; 32], u32) {
    use super::RwLockRecover;

    // Gap 2.1 Phase 2b.3 Slice 3: candidate pool starts with
    // VRF-registered anchors (stake-weighted, mainnet-correct). When
    // `finality_committee_includes_witness_registry` is set, expand
    // with bonded witnesses from `CF_WITNESS_REGISTRY` for this zone
    // — gossip-replicated so every node converges on the same
    // per-zone set and computes the same committee snapshot. De-dup
    // against the VRF set, keep the VRF entry first so its (real)
    // stake weight wins over the fallback weight.
    //
    // History: the retired Slice 1 path (removed 2026-05-16) iterated
    // the locally-divergent `CF_IDENTITIES` and caused the 2026-04-25
    // fleet-wide committee_snapshot mismatch.
    let registered: Vec<String> = {
        let mut ids: Vec<String> = state
            .vrf_registry
            .read_recover()
            .registered_identities()
            .iter()
            .map(|s| s.to_string())
            .collect();
        let mut already: std::collections::HashSet<String> = ids.iter().cloned().collect();
        if state.config.finality_committee_includes_witness_registry {
            for (id, _entry) in state.rocks.iter_witnesses_for_zone(zone_path) {
                if !already.contains(&id) {
                    already.insert(id.clone());
                    ids.push(id);
                }
            }
        }
        ids
    };
    let fallback = if state.config.finality_committee_includes_witness_registry {
        state.config.finality_committee_known_pk_weight
    } else {
        0
    };
    let candidates = {
        let ledger = state.ledger.read().await;
        assemble_candidates_with_fallback(registered, |id| ledger.staked(id), fallback)
    };
    // Route the seal/finality hot path through the shared
    // `ZoneCommitteeResolver` cache. At 1M zones × 720 seals/day each
    // anchor ingests the same `(zone, epoch)` repeatedly across seal
    // creation, attestation verification, and xzone-abort retries —
    // every redundant call previously paid the full O(n log n)
    // Efraimidis–Spirakis sort. The resolver collapses repeats to one
    // O(n) fingerprint + O(1) hashmap lookup. Cache key includes the
    // candidates fingerprint so VRF/stake changes invalidate
    // automatically (no TTL needed).
    let members = state
        .zone_committee_resolver
        .resolve(zone_path, epoch, &candidates, k);

    let mut pks: Vec<Vec<u8>> = members
        .iter()
        .filter_map(|id| state.rocks.get_public_key(id))
        .collect();
    // Sort by leaf-hash so the producer order matches the order the
    // consumer's `verify_finality_quorum` Merkle proofs are built
    // against. `committee_hash_from_pks` re-sorts internally, so this
    // sort is purely for caller convenience (e.g. when rendering the
    // committee in `/committees/finality/{zone}/{epoch}`).
    pks.sort_by_cached_key(|pk| crate::accounting::cross_zone::committee_leaf_hash(pk));
    pks.dedup();

    let hash = committee_hash_from_pks(&pks);
    let size = pks.len() as u32;
    (pks, hash, size)
}

/// State-wrapped [`is_in_committee`] that pulls eligible anchors +
/// stakes from live [`NodeState`]. Mirrors
/// [`state_committees_snapshot`]'s lock discipline.
///
/// Phase 6b (Gap 5): routes through the shared
/// `state.zone_committee_resolver` cache so a dashboard polling many
/// zones doesn't re-run the `O(n log n)` Efraimidis–Spirakis sort on
/// every request. Cache key includes a fingerprint of the candidates
/// set, so VRF registrations / stake changes invalidate stale entries
/// automatically.
pub async fn state_is_in_committee(
    state: &crate::network::state::NodeState,
    zone_path: &str,
    epoch: u64,
    k: usize,
    identity_hash: &str,
) -> (bool, Option<usize>) {
    use super::RwLockRecover;

    let registered: Vec<String> = {
        let reg = state.vrf_registry.read_recover();
        reg.registered_identities()
            .iter()
            .map(|s| s.to_string())
            .collect()
    };
    let candidates = {
        let ledger = state.ledger.read().await;
        assemble_candidates(registered, |id| ledger.staked(id))
    };

    state
        .zone_committee_resolver
        .resolve_is_member(zone_path, epoch, &candidates, k, identity_hash)
}

/// Gap 5 Phase 6c — consensus hot-path gate for **Layer 2 epoch seal
/// attestations** (Protocol §11.12). Returns `true` if the witness is
/// allowed to register a seal attestation for `(zone_path, epoch)`,
/// `false` if the per-zone VRF committee enforcement rejects it.
///
/// Behavior axes:
/// - `state.config.enforce_per_zone_vrf == false` (default during
///   Phase 6c soak): always returns `true`. The advisory observer
///   `committee_attestations_member_total` / `nonmember_total` keeps
///   counting in parallel so operators can compare "what would be
///   rejected" vs "what is rejected" before the flip.
/// - `enforce_per_zone_vrf == true` AND no VRF-registered anchors:
///   returns `true` (bootstrap safety — a genesis fleet has no
///   committee to draw from; refusing seal attestations here would
///   freeze finality). Mirrors `is_in_epoch_committee_scoped_indexed`'s
///   bootstrap convention at `consensus.rs:768`.
/// - `enforce_per_zone_vrf == true` AND no positive-stake candidates:
///   returns `true` (same bootstrap protection — VRF-registered but
///   zero-staked anchors can't form a meaningful committee).
/// - `enforce_per_zone_vrf == true` AND `candidates.len() <
///   DEFAULT_COMMITTEE_SIZE`: returns `true` and bumps
///   `committee_skipped_below_k_total` (Phase 6c.5 bootstrap fallback).
///   A K=7 committee can't draw a
///   diversity-enforced selection from <7 candidates; rejecting all
///   attestations during the partial-bootstrap window would stall
///   finality. The counter is the operator signal that enforcement is
///   in degraded mode; once it stops climbing while
///   `vrf_registry_identities >= MAINNET_COMMITTEE_SIZE`, the gate is
///   fully active.
/// - Otherwise: routes through `state.zone_committee_resolver` to get
///   a cached committee draw; returns membership.
///
/// Layer 1 (per-record) attestations are NOT gated here — Protocol §11.12 makes
/// every staked-and-aged witness eligible to attest records; only the
/// epoch-seal layer is committee-restricted. Callers that gate Layer 1
/// on this helper would over-reject and stall settlement.
///
/// **Lock discipline**: callers MUST not hold any `std::sync::Mutex`
/// guard (e.g. `consensus.lock_recover()`) across this `.await` — the
/// helper takes `state.ledger.read().await` (tokio::sync RwLock).
/// Compute the result before acquiring the consensus lock.
pub async fn enforce_seal_attestation_committee_membership(
    state: &crate::network::state::NodeState,
    zone_path: &str,
    epoch: u64,
    identity_hash: &str,
) -> bool {
    if !state.config.enforce_per_zone_vrf {
        return true;
    }

    use super::RwLockRecover;
    let registered: Vec<String> = {
        let reg = state.vrf_registry.read_recover();
        reg.registered_identities()
            .iter()
            .map(|s| s.to_string())
            .collect()
    };
    if registered.is_empty() {
        return true;
    }
    let candidates = {
        let ledger = state.ledger.read().await;
        assemble_candidates(registered, |id| ledger.staked(id))
    };
    if candidates.is_empty() {
        return true;
    }

    // Phase 6c.5 bootstrap fallback: if the
    // VRF-registered+staked population is below the diversity-enforced
    // committee size, no committee draw can satisfy the K-of-N target.
    // Rejecting all attestations here would stall finality on every
    // testnet and on the early days of mainnet, so the gate
    // short-circuits to `true` and the bootstrap counter records the
    // degraded-enforcement state for operator visibility.
    //
    // Threshold is `state.config.phase6d_min_committee_size`
    // (default 7, lowerable for testnet). Lowering it shrinks the
    // bootstrap-fallback window and lets enforcement engage with
    // smaller anchor populations. The committee draw size below stays
    // at `DEFAULT_COMMITTEE_SIZE` (7) — the resolver caps to eligible
    // count when fewer candidates exist, so asking for 7 is safe even
    // when only 3 are available.
    if candidates.len() < state.config.phase6d_min_committee_size {
        state
            .committee_skipped_below_k_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return true;
    }

    let (member, _rank) = state.zone_committee_resolver.resolve_is_member(
        zone_path,
        epoch,
        &candidates,
        DEFAULT_COMMITTEE_SIZE,
        identity_hash,
    );
    member
}

// ─── Phase 6d readiness predicate ───────────────────────────────────────────

/// Snapshot of the conditions that must hold before flipping
/// `enforce_per_zone_vrf` from `false` (Phase 6c soak) to `true`
/// (Phase 6d enforcement). Emitted to `/metrics` as the binary gauge
/// `elara_phase6d_ready` so operators (and future automation) can read
/// a single signal instead of correlating four counters by eye.
///
/// The rule is encoded here, in one place, so it stays consistent
/// across runbooks, dashboards, and any auto-flip logic that lands
/// later.
#[derive(Debug, Clone)]
pub struct Phase6dReadiness {
    /// True iff `blockers` is empty AND the gate is not already on.
    /// Once the flip lands and stays stable, this stays `true` so the
    /// gauge tracks "would I be ready to flip now?" rather than "have
    /// I flipped?".
    pub ready: bool,
    /// Distinct identities currently in the local VRF registry.
    /// Mirrors `elara_vrf_registry_identities` — repeated
    /// here so the readiness payload is self-contained.
    pub registry_size: u64,
    /// Per-node `phase6d_min_committee_size` config (default 7,
    /// matching `DEFAULT_COMMITTEE_SIZE`). Lowered on small testnets to
    /// make the gate reachable. Emitted so the readiness check is
    /// decodable from /metrics alone — operators reading the gauge
    /// against a different threshold (e.g. mainnet 7 vs testnet 3) can
    /// see the local node's interpretation without consulting the toml.
    pub min_committee_size: u64,
    /// `state.config.enforce_per_zone_vrf` at sample time. `false` =
    /// Phase 6c soak; `true` = Phase 6d active. Emitted so operators
    /// can spot half-rolled flips (cluster-wide axis must be uniform).
    pub gate_currently_enforcing: bool,
    /// Cumulative observer count of seal attestations whose witness
    /// IS in the per-zone VRF committee. `> 0` is the proof that real
    /// committee work has been observed at least once on this node;
    /// `== 0` after a soak window means the consensus path never had
    /// a population >= K and the flip would degenerate to the sub-K
    /// fallback anyway.
    pub member_observations: u64,
    /// Reason strings — empty when `ready == true`. Static `&'static
    /// str` so the gauge HELP can enumerate them. Order is stable;
    /// callers that surface the list to operators can rely on it.
    pub blockers: Vec<&'static str>,
}

/// Compute the Phase 6d readiness snapshot from the current node
/// state. Cheap — three atomic loads plus one `vrf_registry.count()`
/// (a HashMap len). Safe to call from any /metrics scrape.
pub fn phase6d_readiness(state: &crate::network::state::NodeState) -> Phase6dReadiness {
    use super::RwLockRecover;

    let registry_size = state.vrf_registry.read_recover().count() as u64;
    // Read from config (default 7, matching DEFAULT_COMMITTEE_SIZE).
    // Testnet operators lower this so the gate is reachable on small clusters.
    let min_k = state.config.phase6d_min_committee_size as u64;
    let member_count = state
        .committee_attestations_member_total
        .load(std::sync::atomic::Ordering::Relaxed);
    let gate_on = state.config.enforce_per_zone_vrf;

    let mut blockers: Vec<&'static str> = Vec::new();
    if registry_size < min_k {
        blockers.push("vrf_registry_below_committee_size");
    }
    if member_count == 0 {
        blockers.push("no_observed_committee_members");
    }

    Phase6dReadiness {
        ready: blockers.is_empty(),
        registry_size,
        min_committee_size: min_k,
        gate_currently_enforcing: gate_on,
        member_observations: member_count,
        blockers,
    }
}

// ─── Phase 6b advisory observer ─────────────────────────────────────────────

/// One seal-attestation entry for the committee observer.
///
/// `zone_path` and `epoch` come from the parsed `EpochSeal` — not guessed
/// from a record id. `witness_hash` is the attester identity.
#[derive(Debug, Clone)]
pub struct SealAttestEntry {
    pub zone_path: String,
    pub epoch: u64,
    pub witness_hash: String,
}

/// Batch-aware advisory observer for **epoch seal** attestation committee
/// membership (Protocol §11.12 Layer 2).
///
/// For every `SealAttestEntry`, computes the VRF-selected committee for the
/// seal's `(zone_path, epoch)` pair and bumps one of three counters on
/// [`NodeState`]:
///
/// * `committee_attestations_member_total` — witness is in the committee
/// * `committee_attestations_nonmember_total` — witness is not in the committee
/// * `committee_observations_skipped_no_candidates_total` — the VRF registry
///   is empty, so no committee can be drawn. Early-bails before the ledger
///   read to keep hot-path cost near zero on genesis fleets.
///
/// **Why only seal attestations, not Layer 1 per-record attestations:**
/// Under the Protocol §11.12 layered consensus model, ANY witness may attest
/// records at Layer 1 (no committee gating). Epoch seals at Layer 2 are proposed and
/// attested by a VRF-selected anchor committee. Observing Layer 1 would
/// always report ~100% nonmember — not a useful signal. Observing Layer 2
/// measures exactly what enforcement will eventually gate.
///
/// ADVISORY ONLY. Consensus still accepts every seal attestation regardless
/// of membership.
///
/// Scale / cost:
/// * One `vrf_registry.read_recover()` per call.
/// * One `ledger.read().await` per call to assemble candidates.
/// * Committee per `(zone, epoch)` is memoized within the call, so a batch
///   containing several seal attestations for the same (zone, epoch) pair
///   draws one committee.
pub async fn observe_seal_committee_batch<I>(
    state: &crate::network::state::NodeState,
    entries: I,
) where
    I: IntoIterator<Item = SealAttestEntry>,
{
    use std::sync::atomic::Ordering;

    let entries: Vec<SealAttestEntry> = entries.into_iter().collect();
    if entries.is_empty() {
        return;
    }

    // Registered anchors. std::sync RwLock.
    let registered: Vec<String> = {
        use super::RwLockRecover;
        let reg = state.vrf_registry.read_recover();
        reg.registered_identities()
            .iter()
            .map(|s| s.to_string())
            .collect()
    };

    // Early-bail: no registered anchors → cannot form a committee. Skip
    // the ledger read entirely, count all entries as skipped.
    if registered.is_empty() {
        state
            .committee_observations_skipped_no_candidates_total
            .fetch_add(entries.len() as u64, Ordering::Relaxed);
        return;
    }

    // Candidates assembled once — ledger read under the shortest possible lock.
    let candidates = {
        let ledger = state.ledger.read().await;
        assemble_candidates(registered, |id| ledger.staked(id))
    };

    // If every registered anchor has zero stake, candidates is empty and
    // no committee can be drawn. Treat same as no-candidates.
    if candidates.is_empty() {
        state
            .committee_observations_skipped_no_candidates_total
            .fetch_add(entries.len() as u64, Ordering::Relaxed);
        return;
    }

    // Observer mirrors the GATE's bootstrap threshold, not the
    // committee draw size. The gate (`seal_attestation_committee_size_below_k`
    // at zone_committee.rs:737) skips below `state.config.phase6d_min_committee_size`
    // — which is config-driven. The observer here was still using
    // the hardcoded `DEFAULT_COMMITTEE_SIZE`, so on testnets that lowered
    // the threshold (e.g. fleet running with `phase6d_min_committee_size=2`)
    // the gate engaged but the observer kept skipping → `committee_attestations_member_total`
    // stayed 0 forever, blocking `phase6d_readiness().ready` permanently.
    let bootstrap_threshold = state.config.phase6d_min_committee_size;
    let draw_k = DEFAULT_COMMITTEE_SIZE;

    // Phase 6c.5 bootstrap fallback: observer
    // mirrors the gate. With < threshold candidates the diversity-enforced
    // selection is degenerate (committee = all candidates); counting
    // every attester from outside the population as a "nonmember" is
    // technically correct but operationally noisy and would force the
    // gate-vs-observer divergence to be falsely non-zero on every
    // genesis fleet. Skip evaluation and bump the bootstrap counter so
    // operators see the partial-bootstrap state as a first-class signal.
    if candidates.len() < bootstrap_threshold {
        state
            .committee_skipped_below_k_total
            .fetch_add(entries.len() as u64, Ordering::Relaxed);
        return;
    }

    // Memoize committee per (zone, epoch) across the batch.
    let mut committee_cache: std::collections::HashMap<(String, u64), Vec<String>> =
        std::collections::HashMap::new();

    let mut member = 0u64;
    let mut nonmember = 0u64;

    for entry in &entries {
        let key = (entry.zone_path.clone(), entry.epoch);
        let committee = committee_cache
            .entry(key)
            .or_insert_with(|| select_zone_committee(&entry.zone_path, entry.epoch, &candidates, draw_k));
        if committee.iter().any(|id| id == &entry.witness_hash) {
            member += 1;
        } else {
            nonmember += 1;
        }
    }

    if member > 0 {
        state
            .committee_attestations_member_total
            .fetch_add(member, Ordering::Relaxed);
    }
    if nonmember > 0 {
        state
            .committee_attestations_nonmember_total
            .fetch_add(nonmember, Ordering::Relaxed);
    }
}

// ─── Phase 6b cached resolver (Gap 5 first slice) ───────────────────────────

/// Default cache cap for the per-zone committee resolver.
///
/// Sized for ~512 active zones × 8-epoch horizon at default k. At
/// mainnet 1M-zone scale the working set is the *active* zones being
/// queried in the current epoch window, not total zones — operators
/// who run a node serving many zones can raise this via
/// `committee_resolver_cache_size` config.
pub const DEFAULT_RESOLVER_CACHE_SIZE: usize = 4096;
const RESOLVER_FINGERPRINT_DOMAIN: &[u8] = b"ELARA_COMMITTEE_RESOLVER_FP_V1";

/// FIFO-bounded cache of `(zone_path, epoch, k, candidates_fingerprint)
/// → committee` for the per-zone VRF committee draw. Two reasons for
/// existence:
///
/// 1. **Performance.** `select_zone_committee` is `O(n log n)` in
///    eligible-population `n`. Re-running it on every committee query
///    (advisory now, hot-path consensus once Gap 5 closes) burns CPU
///    proportional to query rate × `n`. A cache hit collapses that to
///    `O(n)` for the candidates fingerprint plus `O(1)` HashMap lookup
///    — dominated by the fingerprint, which is roughly 7% of a
///    selection on 10K candidates (one SHA3 over 400KB vs ~10K SHA3
///    invocations + sort).
/// 2. **Phase 6b → 6c migration safety.** When the consensus hot path
///    swap lands behind `enforce_per_zone_vrf`, the resolver is the
///    single call site. Cache invariants (determinism, fingerprint
///    eviction) are easier to reason about than ad-hoc memoization
///    scattered across attestation handlers.
///
/// ## Determinism
///
/// The cache is consensus-safe by construction: two nodes with the
/// same `(zone, epoch, k, candidates)` get the same committee whether
/// or not the answer was cached. Candidate-set changes (new VRF
/// registration, stake change, slash) flip the fingerprint and the
/// cache returns a fresh draw. There is no TTL or epoch-based
/// invalidation — the fingerprint *is* the invalidation signal.
///
/// ## Eviction
///
/// FIFO by insertion order (not LRU). At cap-4096 with a per-call
/// `O(1)` push/pop on `VecDeque`, this beats a touch-on-hit LRU's
/// `O(n)` reorder cost while keeping the working set bounded. The
/// access pattern is dominated by current-epoch queries, so FIFO and
/// LRU evict the same entries (oldest = stalest epoch).
///
/// ## Lock discipline
///
/// One `std::sync::Mutex` for the inner state. Held only across sync
/// HashMap/VecDeque ops — never across an `await`. Counters are
/// `AtomicU64::Ordering::Relaxed` (observability, not correctness).
pub struct ZoneCommitteeResolver {
    inner: std::sync::Mutex<ResolverState>,
    pub hits_total: std::sync::atomic::AtomicU64,
    pub misses_total: std::sync::atomic::AtomicU64,
    pub evictions_total: std::sync::atomic::AtomicU64,
}

impl std::fmt::Debug for ZoneCommitteeResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use crate::network::LockRecover;
        let st = self.inner.lock_recover();
        f.debug_struct("ZoneCommitteeResolver")
            .field("size", &st.cache.len())
            .field("capacity", &st.max_entries)
            .field(
                "hits",
                &self
                    .hits_total
                    .load(std::sync::atomic::Ordering::Relaxed),
            )
            .field(
                "misses",
                &self
                    .misses_total
                    .load(std::sync::atomic::Ordering::Relaxed),
            )
            .finish()
    }
}

struct ResolverState {
    cache: std::collections::HashMap<CacheKey, Vec<String>>,
    fifo: std::collections::VecDeque<CacheKey>,
    max_entries: usize,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct CacheKey {
    zone_path: String,
    epoch: u64,
    k: usize,
    candidates_fingerprint: [u8; 32],
}

impl Default for ZoneCommitteeResolver {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_RESOLVER_CACHE_SIZE)
    }
}

impl ZoneCommitteeResolver {
    pub fn with_capacity(max_entries: usize) -> Self {
        // Guard against zero — would cause an unbounded loop in the
        // eviction `while st.cache.len() >= 0` condition. A zero cap
        // is meaningless anyway (every call evicts itself); clamp to
        // the protocol-meaningful floor.
        let cap = max_entries.max(1);
        Self {
            inner: std::sync::Mutex::new(ResolverState {
                cache: std::collections::HashMap::new(),
                fifo: std::collections::VecDeque::new(),
                max_entries: cap,
            }),
            hits_total: std::sync::atomic::AtomicU64::new(0),
            misses_total: std::sync::atomic::AtomicU64::new(0),
            evictions_total: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Resolve `(zone_path, epoch, k)` for the given candidate set.
    /// Cache hit returns the cached committee; miss falls through to
    /// `select_zone_committee` and inserts the result.
    pub fn resolve(
        &self,
        zone_path: &str,
        epoch: u64,
        candidates: &[Candidate],
        k: usize,
    ) -> Vec<String> {
        use crate::network::LockRecover;
        use std::sync::atomic::Ordering;

        let fingerprint = candidates_fingerprint(candidates);
        let key = CacheKey {
            zone_path: zone_path.to_string(),
            epoch,
            k,
            candidates_fingerprint: fingerprint,
        };

        // Cache hit fast path — clone out under the lock, release, return.
        {
            let st = self.inner.lock_recover();
            if let Some(committee) = st.cache.get(&key) {
                self.hits_total.fetch_add(1, Ordering::Relaxed);
                return committee.clone();
            }
        }

        // Miss — compute outside the lock so concurrent resolvers don't serialize.
        let committee = select_zone_committee(zone_path, epoch, candidates, k);
        self.misses_total.fetch_add(1, Ordering::Relaxed);

        // Insert under the lock; evict FIFO entries until under cap.
        let mut st = self.inner.lock_recover();
        // A concurrent resolver may have inserted the same key between
        // our miss read and this insert. Doesn't matter — same key,
        // same value (deterministic), and the duplicate fifo entry
        // self-corrects on next eviction (its cache lookup is a no-op).
        while st.cache.len() >= st.max_entries {
            if let Some(old_key) = st.fifo.pop_front() {
                st.cache.remove(&old_key);
                self.evictions_total.fetch_add(1, Ordering::Relaxed);
            } else {
                break;
            }
        }
        st.cache.insert(key.clone(), committee.clone());
        st.fifo.push_back(key);
        committee
    }

    /// Predicate form: `(is_member, selection_rank)`. Equivalent to
    /// [`is_in_committee`] but caches via [`Self::resolve`].
    pub fn resolve_is_member(
        &self,
        zone_path: &str,
        epoch: u64,
        candidates: &[Candidate],
        k: usize,
        identity_hash: &str,
    ) -> (bool, Option<usize>) {
        let committee = self.resolve(zone_path, epoch, candidates, k);
        match committee.iter().position(|id| id == identity_hash) {
            Some(rank) => (true, Some(rank)),
            None => (false, None),
        }
    }

    pub fn cache_size(&self) -> usize {
        use crate::network::LockRecover;
        self.inner.lock_recover().cache.len()
    }

    pub fn cache_capacity(&self) -> usize {
        use crate::network::LockRecover;
        self.inner.lock_recover().max_entries
    }
}

/// SHA3-256 fingerprint over `(identity_hash, weight)` pairs in input
/// order. `assemble_candidates*` already sorts by `identity_hash`, so
/// the input here is canonical for any caller using the standard
/// assembly path.
fn candidates_fingerprint(candidates: &[Candidate]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(
        RESOLVER_FINGERPRINT_DOMAIN.len() + candidates.len() * 48,
    );
    buf.extend_from_slice(RESOLVER_FINGERPRINT_DOMAIN);
    for c in candidates {
        buf.extend_from_slice(c.identity_hash.as_bytes());
        buf.push(b'|');
        buf.extend_from_slice(&c.weight.to_le_bytes());
        buf.push(b'\n');
    }
    sha3_256(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk(id: &str, w: u64) -> Candidate {
        Candidate {
            identity_hash: id.to_string(),
            weight: w,
        }
    }

    #[test]
    fn empty_eligible_returns_empty() {
        let out = select_zone_committee("medical/eu", 10, &[], 5);
        assert!(out.is_empty());
    }

    #[test]
    fn k_zero_returns_empty() {
        let elig = vec![mk("a", 100), mk("b", 100)];
        let out = select_zone_committee("medical/eu", 10, &elig, 0);
        assert!(out.is_empty());
    }

    #[test]
    fn k_greater_than_pop_caps_at_pop_size() {
        let elig = vec![mk("a", 100), mk("b", 100), mk("c", 100)];
        let out = select_zone_committee("zone", 1, &elig, 10);
        assert_eq!(out.len(), 3, "cap at population, don't pad");
    }

    #[test]
    fn zero_weight_candidates_are_dropped() {
        let elig = vec![mk("a", 0), mk("b", 100), mk("c", 0), mk("d", 100)];
        let out = select_zone_committee("zone", 1, &elig, 10);
        assert_eq!(out.len(), 2);
        assert!(out.contains(&"b".to_string()));
        assert!(out.contains(&"d".to_string()));
    }

    #[test]
    fn deterministic_across_invocations() {
        let elig: Vec<Candidate> = (0..50)
            .map(|i| mk(&format!("anchor-{i:03}"), 100 + i as u64))
            .collect();
        let out_a = select_zone_committee("medical/eu/west", 42, &elig, 7);
        let out_b = select_zone_committee("medical/eu/west", 42, &elig, 7);
        assert_eq!(out_a, out_b, "same inputs must yield identical committee");
    }

    #[test]
    fn order_independent_on_eligible_input() {
        // Determinism must hold when the caller feeds `eligible` in a
        // different order — mimics two nodes that build their set from
        // different iteration paths (HashMap vs BTreeMap).
        let mut a: Vec<Candidate> = (0..30)
            .map(|i| mk(&format!("id-{i:02}"), 1000))
            .collect();
        let b: Vec<Candidate> = a.iter().rev().cloned().collect();

        // Shuffle deterministically (swap pairs) to make really sure
        // we're not accidentally feeding sorted order.
        for i in (0..a.len()).step_by(2) {
            if i + 1 < a.len() {
                a.swap(i, i + 1);
            }
        }

        let out_a = select_zone_committee("zone/x", 7, &a, 5);
        let out_b = select_zone_committee("zone/x", 7, &b, 5);
        // Both outputs must be the same SET — order inside is the
        // priority-sort order, which IS deterministic given inputs.
        let set_a: std::collections::BTreeSet<_> = out_a.iter().collect();
        let set_b: std::collections::BTreeSet<_> = out_b.iter().collect();
        assert_eq!(
            set_a, set_b,
            "order of `eligible` input must not change the committee set"
        );
    }

    #[test]
    fn different_zones_yield_different_committees() {
        let elig: Vec<Candidate> = (0..100)
            .map(|i| mk(&format!("anchor-{i:03}"), 1000))
            .collect();
        let out_a = select_zone_committee("medical/eu", 10, &elig, 7);
        let out_b = select_zone_committee("medical/us", 10, &elig, 7);
        assert_ne!(
            out_a, out_b,
            "zone is part of the seed; two zones in same epoch must differ"
        );
    }

    #[test]
    fn different_epochs_yield_different_committees() {
        let elig: Vec<Candidate> = (0..100)
            .map(|i| mk(&format!("anchor-{i:03}"), 1000))
            .collect();
        let out_a = select_zone_committee("medical/eu", 10, &elig, 7);
        let out_b = select_zone_committee("medical/eu", 11, &elig, 7);
        assert_ne!(
            out_a, out_b,
            "epoch rotation — same zone one epoch apart must differ"
        );
    }

    #[test]
    fn stake_weighting_biases_toward_higher_stake() {
        // 10 small fish (weight 1) + 1 whale (weight 1_000_000). Over
        // many zones the whale should appear in >99% of committees.
        // Deterministic across runs, no statistical flake.
        let mut elig: Vec<Candidate> = (0..10).map(|i| mk(&format!("small-{i}"), 1)).collect();
        elig.push(mk("whale", 1_000_000));

        let mut whale_hits = 0;
        let mut total = 0;
        for epoch in 0u64..200 {
            let out = select_zone_committee("zone", epoch, &elig, 3);
            if out.contains(&"whale".to_string()) {
                whale_hits += 1;
            }
            total += 1;
        }
        let whale_ratio = whale_hits as f64 / total as f64;
        assert!(
            whale_ratio > 0.95,
            "whale with 10^5× stake should dominate; saw {}/{} = {}",
            whale_hits,
            total,
            whale_ratio
        );
    }

    #[test]
    fn small_stake_not_totally_excluded() {
        // Guard against a bug where the rank formula zeros out small
        // stakes. Over 500 epochs a single small fish among 10 small
        // fish + 1 whale (committee size 5) should appear at least once.
        let mut elig: Vec<Candidate> = (0..10).map(|i| mk(&format!("small-{i}"), 1)).collect();
        elig.push(mk("whale", 1_000_000));

        let mut small_0_hits = 0;
        for epoch in 0u64..500 {
            let out = select_zone_committee("zone", epoch, &elig, 5);
            if out.contains(&"small-0".to_string()) {
                small_0_hits += 1;
            }
        }
        assert!(
            small_0_hits > 0,
            "small stake should still occasionally win a seat; saw {small_0_hits} in 500 epochs"
        );
    }

    #[test]
    fn equal_weight_approximates_uniform_sortition() {
        // 100 equal-weight candidates, committee-size 10, run across
        // 200 epochs. Each candidate's hit rate should fall in a
        // reasonable uniform band — 1000 total seats, 10 per candidate
        // expected, tolerate 2–30 (very generous — a tight bound here
        // would be a flake magnet, but we still catch pathological
        // concentration / starvation).
        let elig: Vec<Candidate> = (0..100)
            .map(|i| mk(&format!("id-{i:03}"), 1000))
            .collect();
        let mut counts = std::collections::BTreeMap::<String, u64>::new();
        for epoch in 0u64..200 {
            for winner in select_zone_committee("zone", epoch, &elig, 10) {
                *counts.entry(winner).or_default() += 1;
            }
        }
        assert_eq!(counts.values().sum::<u64>(), 2000);
        for (id, c) in &counts {
            assert!(
                *c >= 2 && *c <= 50,
                "uniform-weight id {id} got {c} seats — pathological"
            );
        }
        // And no candidate should be starved completely.
        assert_eq!(
            counts.len(),
            100,
            "every candidate should appear at least once in 200 epochs"
        );
    }

    #[test]
    fn committee_members_are_unique() {
        let elig: Vec<Candidate> = (0..50)
            .map(|i| mk(&format!("id-{i}"), 100))
            .collect();
        let out = select_zone_committee("zone", 1, &elig, 20);
        let set: std::collections::BTreeSet<_> = out.iter().cloned().collect();
        assert_eq!(set.len(), out.len(), "no duplicates in committee");
    }

    #[test]
    fn single_candidate_always_selected() {
        let elig = vec![mk("only", 100)];
        let out = select_zone_committee("zone", 42, &elig, 5);
        assert_eq!(out, vec!["only".to_string()]);
    }

    #[test]
    fn all_zero_weight_returns_empty() {
        let elig = vec![mk("a", 0), mk("b", 0), mk("c", 0)];
        let out = select_zone_committee("zone", 1, &elig, 5);
        assert!(
            out.is_empty(),
            "if nobody has stake, no committee — protocol halts rather than seal with zero-stake signers"
        );
    }

    #[test]
    fn hierarchical_zone_paths_do_not_collide() {
        // "medical" and "medical/eu" must produce different committees
        // — otherwise a split would inherit its parent's committee and
        // rotation would be useless.
        let elig: Vec<Candidate> = (0..50)
            .map(|i| mk(&format!("id-{i}"), 100))
            .collect();
        let parent = select_zone_committee("medical", 5, &elig, 7);
        let child = select_zone_committee("medical/eu", 5, &elig, 7);
        assert_ne!(parent, child);
    }

    #[test]
    fn min_and_default_committee_size_constants_are_sane() {
        // MIN_COMMITTEE_SIZE >= 5 (BFT f=1) and
        // DEFAULT_COMMITTEE_SIZE >= MIN_COMMITTEE_SIZE are pinned at
        // compile time via the `const _: () = assert!(..)` block next to
        // the const declarations (zone_committee.rs ~L65). A regression
        // now fails at `cargo build`, not at `cargo test`. Runtime
        // asserts removed (clippy::assertions_on_constants — both
        // operands const-eval).
    }

    // ── assemble_candidates ──────────────────────────────────────────

    #[test]
    fn assemble_drops_zero_stake_anchors() {
        let regs = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let stakes: std::collections::HashMap<&str, u64> =
            [("a", 100), ("b", 0), ("c", 500)].into_iter().collect();
        let pool = assemble_candidates(regs, |id| *stakes.get(id).unwrap_or(&0));
        let ids: Vec<_> = pool.iter().map(|c| c.identity_hash.as_str()).collect();
        assert_eq!(ids, vec!["a", "c"], "zero-stake must be filtered");
    }

    #[test]
    fn assemble_is_canonical_regardless_of_input_order() {
        let stakes: std::collections::HashMap<&str, u64> =
            [("a", 10), ("b", 20), ("c", 30)].into_iter().collect();
        let pool1 = assemble_candidates(
            vec!["c".to_string(), "a".to_string(), "b".to_string()],
            |id| *stakes.get(id).unwrap_or(&0),
        );
        let pool2 = assemble_candidates(
            vec!["b".to_string(), "c".to_string(), "a".to_string()],
            |id| *stakes.get(id).unwrap_or(&0),
        );
        assert_eq!(pool1, pool2, "output canonical regardless of input order");
    }

    #[test]
    fn assemble_with_fallback_zero_matches_strict() {
        let regs = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let stakes: std::collections::HashMap<&str, u64> =
            [("a", 100), ("b", 0), ("c", 500)].into_iter().collect();
        let strict = assemble_candidates(regs.clone(), |id| *stakes.get(id).unwrap_or(&0));
        let fb0 = assemble_candidates_with_fallback(
            regs,
            |id| *stakes.get(id).unwrap_or(&0),
            0,
        );
        assert_eq!(strict, fb0, "fallback_weight=0 must reproduce strict behaviour");
    }

    #[test]
    fn assemble_with_fallback_admits_zero_stake_at_fallback_weight() {
        let regs = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let stakes: std::collections::HashMap<&str, u64> =
            [("a", 100), ("b", 0), ("c", 500)].into_iter().collect();
        let pool = assemble_candidates_with_fallback(
            regs,
            |id| *stakes.get(id).unwrap_or(&0),
            1,
        );
        let weights: std::collections::HashMap<_, _> =
            pool.iter().map(|c| (c.identity_hash.as_str(), c.weight)).collect();
        assert_eq!(weights.get("a"), Some(&100), "real stake preserved");
        assert_eq!(weights.get("b"), Some(&1), "zero-stake admitted at fallback weight");
        assert_eq!(weights.get("c"), Some(&500), "real stake preserved");
    }

    #[test]
    fn registry_expansion_dedups_against_vrf_anchors() {
        // Slice 3d shape test: the registered set is the VRF anchor list
        // unioned with iter_witnesses_for_zone (deduped). When a witness
        // is ALSO an anchor, the registry must not produce a duplicate
        // candidate. Same-weight, two-trial check that selecting all
        // candidates yields exactly the unique set.
        let mut regs: Vec<String> = vec!["A".into(), "B".into()];
        let mut already: std::collections::HashSet<String> =
            regs.iter().cloned().collect();
        // Simulate iter_witnesses_for_zone returning ["A", "C"]:
        //   - A is already an anchor → must not be re-pushed
        //   - C is registry-only → pushed
        for id in ["A", "C"] {
            if !already.contains(id) {
                already.insert(id.to_string());
                regs.push(id.to_string());
            }
        }
        assert_eq!(regs, vec!["A", "B", "C"]);
        assert_eq!(regs.len(), 3, "registry expansion must dedup against anchors");

        let cands = assemble_candidates_with_fallback(
            regs.clone(),
            |id| if id == "A" { 1000 } else { 0 },
            1,
        );
        // All three made it through with non-zero weight.
        assert_eq!(cands.len(), 3);
    }

    #[test]
    fn assemble_with_fallback_unstaked_dont_eclipse_anchors() {
        // 1 anchor with 1000 stake, 4 unstaked witnesses at fallback=1.
        // Across many epochs the anchor must dominate selection — its
        // weight is 1000× a witness, so the witness-tier nodes are
        // tie-breakers, not co-equal players.
        let regs: Vec<String> = vec!["A".into(), "w1".into(), "w2".into(), "w3".into(), "w4".into()];
        let stakes: std::collections::HashMap<&str, u64> = [("A", 1000)].into_iter().collect();
        let cands = assemble_candidates_with_fallback(
            regs,
            |id| *stakes.get(id).unwrap_or(&0),
            1,
        );
        let mut anchor_picks = 0;
        let trials = 200u64;
        for epoch in 0..trials {
            let chosen = select_zone_committee("zone-x", epoch, &cands, 1);
            if chosen.first().map(|s| s.as_str()) == Some("A") {
                anchor_picks += 1;
            }
        }
        // With weight ratio 1000:1:1:1:1 = 1000/1004 ≈ 99.6% of single-seat
        // picks should be the anchor. Allow a slack for the small sample.
        assert!(
            anchor_picks > (trials * 95 / 100),
            "anchor with 1000× weight should win ≥95% of single-seat draws, got {anchor_picks}/{trials}"
        );
    }

    // ── build_zone_committees_for_active ─────────────────────────────

    #[test]
    fn build_sweep_produces_one_committee_per_zone() {
        let cands: Vec<Candidate> = (0..20)
            .map(|i| mk(&format!("id-{i:02}"), 100))
            .collect();
        let zones = vec![
            "medical".to_string(),
            "medical/eu".to_string(),
            "medical/us".to_string(),
            "legal".to_string(),
        ];
        let map = build_zone_committees_for_active(zones.clone(), 1, &cands, 5);
        assert_eq!(map.len(), 4);
        for z in &zones {
            let c = map.get(z).unwrap();
            assert_eq!(c.len(), 5);
        }
    }

    #[test]
    fn build_sweep_different_zones_have_different_committees() {
        let cands: Vec<Candidate> = (0..30)
            .map(|i| mk(&format!("id-{i:02}"), 100))
            .collect();
        let zones = vec!["medical/eu".to_string(), "medical/us".to_string()];
        let map = build_zone_committees_for_active(zones, 42, &cands, 5);
        let eu = map.get("medical/eu").unwrap();
        let us = map.get("medical/us").unwrap();
        assert_ne!(eu, us);
    }

    #[test]
    fn build_sweep_empty_zones_returns_empty_map() {
        let cands = vec![mk("a", 100)];
        let map = build_zone_committees_for_active(Vec::<String>::new(), 1, &cands, 5);
        assert!(map.is_empty());
    }

    #[test]
    fn build_sweep_no_candidates_returns_empty_committees_per_zone() {
        let zones = vec!["medical".to_string(), "legal".to_string()];
        let map = build_zone_committees_for_active(zones.clone(), 1, &[], 5);
        // Map entries exist (one per zone), but committees are empty.
        // This lets operators see "zone X has NO committee" rather than
        // silently dropping the zone.
        assert_eq!(map.len(), 2);
        for z in &zones {
            assert!(map.get(z).unwrap().is_empty());
        }
    }

    // ── state_committees_snapshot — live NodeState integration ───────

    fn build_test_state() -> (
        std::sync::Arc<crate::network::state::NodeState>,
        tempfile::TempDir,
    ) {
        use crate::identity::{CryptoProfile, EntityType, Identity};
        use crate::network::config::NodeConfig;
        use crate::network::state::NodeState;
        use crate::network::witness::WitnessManager;
        use crate::storage::rocks::StorageEngine;

        let tmp = tempfile::tempdir().expect("tempdir");
        let data_dir = tmp.path().to_path_buf();
        let config = NodeConfig {
            data_dir: data_dir.clone(),
            identity_path: data_dir.join("identity.json"),
            db_path: data_dir.join("elara.db"),
            admin_token: "test-admin".into(),
            network_id: "gap5-phase5-test".into(),
            mdns_enabled: false,
            health_check_interval_secs: 0,
            min_pow_difficulty: 0,
            ..Default::default()
        };

        let identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
            .expect("generate identity");
        let rocks = std::sync::Arc::new(
            StorageEngine::open(data_dir.join("rocksdb")).expect("open rocks"),
        );
        let wmgr =
            std::sync::Arc::new(WitnessManager::new(rocks.clone()));
        (
            std::sync::Arc::new(NodeState::new(config, identity, rocks, wmgr)),
            tmp,
        )
    }

    #[tokio::test]
    async fn snapshot_empty_when_no_registrations() {
        let (state, _tmp) = build_test_state();
        let (snap, next_from) =
            state_committees_snapshot(&state, 0, 5, None, DEFAULT_COMMITTEES_PAGE_SIZE).await;
        // No active zones seeded in fresh registry (default() = empty
        // tree), no VRF registrations, no stakes. Map is empty.
        assert!(snap.is_empty());
        assert!(next_from.is_none(), "empty page must report no next_from");
    }

    #[tokio::test]
    async fn snapshot_integrates_registry_ledger_and_zones() {
        use crate::network::vrf_registry::VrfRegistration;
        use crate::network::zone::ZoneId;
        use crate::network::zone_registry::ZoneRegistry;

        let (state, _tmp) = build_test_state();

        // Seed active zones.
        {
            let mut reg = state.zone_registry.write().unwrap();
            *reg = ZoneRegistry::with_genesis(vec![
                ZoneId::new("medical/eu"),
                ZoneId::new("medical/us"),
            ]);
        }

        // Seed two VRF-registered anchors.
        {
            let mut vreg = state.vrf_registry.write().unwrap();
            vreg.register(
                "anchor-A",
                VrfRegistration {
                    vrf_public_key_hex: hex::encode([0xAA; 32]),
                    vrf_full_public_key_hex: String::new(),
                    registered_at: 1.0,
                    record_id: "reg-A".into(),
                    node_type: "anchor".into(),
                },
            );
            vreg.register(
                "anchor-B",
                VrfRegistration {
                    vrf_public_key_hex: hex::encode([0xBB; 32]),
                    vrf_full_public_key_hex: String::new(),
                    registered_at: 1.0,
                    record_id: "reg-B".into(),
                    node_type: "anchor".into(),
                },
            );
        }

        // Seed ledger stakes. Inject `AccountState` directly — this
        // is an integration test for the committee snapshot, not for
        // the ledger op pipeline.
        {
            let mut ledger = state.ledger.write().await;
            let acc_a = crate::accounting::ledger::AccountState { staked: 1000, ..Default::default() };
            ledger.accounts.insert("anchor-A".to_string(), acc_a);
            let acc_b = crate::accounting::ledger::AccountState { staked: 500, ..Default::default() };
            ledger.accounts.insert("anchor-B".to_string(), acc_b);
        }

        let (snap, next_from) =
            state_committees_snapshot(&state, 7, 5, None, DEFAULT_COMMITTEES_PAGE_SIZE).await;
        assert!(next_from.is_none(), "2 zones < page size — no next_from");
        assert_eq!(snap.len(), 2, "one committee per active zone");
        assert!(snap.contains_key("medical/eu"));
        assert!(snap.contains_key("medical/us"));

        for (zone, committee) in &snap {
            // k=5 but only 2 eligible anchors — cap at population.
            assert_eq!(
                committee.len(),
                2,
                "zone {zone}: committee capped at eligible-pop"
            );
            // Every committee member is one of our registered anchors.
            for m in committee {
                assert!(
                    m == "anchor-A" || m == "anchor-B",
                    "unexpected committee member {m}"
                );
            }
        }

        // Determinism: calling again produces the same snapshot.
        let (snap2, _) =
            state_committees_snapshot(&state, 7, 5, None, DEFAULT_COMMITTEES_PAGE_SIZE).await;
        assert_eq!(snap, snap2);
    }

    /// With 100 active zones and `limit=30`, a full sweep
    /// must produce 4 pages (30 + 30 + 30 + 10) that together cover
    /// every zone exactly once, in lex order, with no gaps and no
    /// overlaps. Each `next_from` must be the lex-first zone of the
    /// NEXT page; the final page must report `next_from = None`.
    ///
    /// Why this matters: at 1M active zones the un-paginated
    /// `/committees` would compute 1M committees and serialize a ~250
    /// MB body. Pagination caps work-per-call to `limit` zones; it's
    /// only safe if the pages tile the active set without loss.
    #[tokio::test]
    async fn ops151_pagination_tiles_active_zones() {
        use crate::network::vrf_registry::VrfRegistration;
        use crate::network::zone::ZoneId;
        use crate::network::zone_registry::ZoneRegistry;

        let (state, _tmp) = build_test_state();

        // 100 active zones with sortable lex paths. Use 3-digit zero
        // padding so lex order matches numeric order — the test
        // asserts against the lex order, but human-eyeballing diffs
        // is easier when they coincide.
        let zone_ids: Vec<ZoneId> =
            (0..100).map(|i| ZoneId::new(&format!("z/{i:03}"))).collect();
        {
            let mut reg = state.zone_registry.write().unwrap();
            *reg = ZoneRegistry::with_genesis(zone_ids.clone());
        }

        // One registered + staked anchor — enough for committees of
        // size 1 to draw deterministically.
        {
            let mut vreg = state.vrf_registry.write().unwrap();
            vreg.register(
                "anchor-A",
                VrfRegistration {
                    vrf_public_key_hex: hex::encode([0xAA; 32]),
                    vrf_full_public_key_hex: String::new(),
                    registered_at: 1.0,
                    record_id: "reg-A".into(),
                    node_type: "anchor".into(),
                },
            );
        }
        {
            let mut ledger = state.ledger.write().await;
            ledger.accounts.insert(
                "anchor-A".to_string(),
                crate::accounting::ledger::AccountState {
                    staked: 1000,
                    ..Default::default()
                },
            );
        }

        // Lex-sort the expected zones so the test is order-explicit.
        let mut expected: Vec<String> =
            zone_ids.iter().map(|z| z.path().to_string()).collect();
        expected.sort();
        assert_eq!(expected.len(), 100);

        // Sweep with limit=30; expect 4 pages of size 30, 30, 30, 10.
        let limit = 30usize;
        let mut from: Option<String> = None;
        let mut covered: Vec<String> = Vec::new();
        let mut pages: usize = 0;
        loop {
            let (snap, next_from) =
                state_committees_snapshot(&state, 1, 1, from.as_deref(), limit).await;
            pages += 1;

            // No page may exceed the limit.
            assert!(
                snap.len() <= limit,
                "page {pages} returned {} > limit {limit}",
                snap.len()
            );

            // Pages 1..3 must be full at limit=30 (we have 100 zones).
            if pages <= 3 {
                assert_eq!(snap.len(), limit, "page {pages} must be full");
            } else {
                assert_eq!(snap.len(), 10, "final page must hold 10 leftover zones");
            }

            // Append in lex (BTreeMap iter) order.
            for k in snap.keys() {
                covered.push(k.clone());
            }

            match next_from {
                Some(nf) => {
                    // next_from must be strictly greater than every key on
                    // this page (no overlap), and equal to expected[len-so-far].
                    assert!(
                        snap.keys().all(|k| k.as_str() < nf.as_str()),
                        "next_from {nf} overlaps page {pages}"
                    );
                    assert_eq!(
                        nf,
                        expected[covered.len()],
                        "next_from must point to next lex zone after page {pages}"
                    );
                    from = Some(nf);
                }
                None => {
                    break;
                }
            }
            assert!(pages < 10, "runaway pagination — bug in stop condition");
        }

        // 4 pages, every zone covered once in lex order, no duplicates.
        assert_eq!(pages, 4, "100 zones / limit=30 must be 4 pages");
        assert_eq!(covered, expected, "pagination must tile active zones in lex order");
    }

    /// `from` is the inclusive-LB filter — passing a zone
    /// path that exists must include that zone in the page. Pin this
    /// because client paginators that pass `next_from` into `from`
    /// will skip a zone if `from` is misinterpreted as exclusive.
    #[tokio::test]
    async fn ops151_pagination_from_is_inclusive() {
        use crate::network::vrf_registry::VrfRegistration;
        use crate::network::zone::ZoneId;
        use crate::network::zone_registry::ZoneRegistry;

        let (state, _tmp) = build_test_state();
        {
            let mut reg = state.zone_registry.write().unwrap();
            *reg = ZoneRegistry::with_genesis(vec![
                ZoneId::new("a"),
                ZoneId::new("b"),
                ZoneId::new("c"),
                ZoneId::new("d"),
            ]);
        }
        {
            let mut vreg = state.vrf_registry.write().unwrap();
            vreg.register(
                "anchor-A",
                VrfRegistration {
                    vrf_public_key_hex: hex::encode([0xAA; 32]),
                    vrf_full_public_key_hex: String::new(),
                    registered_at: 1.0,
                    record_id: "reg-A".into(),
                    node_type: "anchor".into(),
                },
            );
        }
        {
            let mut ledger = state.ledger.write().await;
            ledger.accounts.insert(
                "anchor-A".to_string(),
                crate::accounting::ledger::AccountState {
                    staked: 1000,
                    ..Default::default()
                },
            );
        }

        // from="b", limit=10 → should yield {b, c, d}, next_from=None.
        let (snap, next_from) =
            state_committees_snapshot(&state, 1, 1, Some("b"), 10).await;
        assert!(next_from.is_none());
        assert_eq!(snap.len(), 3, "from=b inclusive must include b, c, d");
        assert!(snap.contains_key("b"), "from=b must include b (inclusive LB)");
        assert!(snap.contains_key("c"));
        assert!(snap.contains_key("d"));
        assert!(!snap.contains_key("a"), "a < from=b must be excluded");
    }

    /// REGRESSION — `start_idx + limit` overflow panic at the pagination
    /// boundary. The earlier pagination tests all pass a small `limit` and a
    /// `from` that lands at start_idx=0, so the `start_idx + limit` line never
    /// sees a large operand. But `limit` traces to the uncapped `?limit=` query
    /// param (the route clamps to MAX_COMMITTEES_PAGE_SIZE, but this is a `pub
    /// fn`), and a `from` cursor pushes start_idx > 0 — even on a single-zone
    /// node, `from` past the last zone makes partition_point return len. With a
    /// hostile `limit=usize::MAX` the old `start_idx + limit` panics under
    /// overflow-checks=true (on by default in the test profile); the
    /// saturating_add fix pins at usize::MAX and `.min(zones.len())` yields the
    /// correct clamped boundary. A revert to the raw `+` panics this test.
    #[tokio::test]
    async fn committees_pagination_huge_limit_with_cursor_does_not_panic() {
        use crate::network::vrf_registry::VrfRegistration;
        use crate::network::zone::ZoneId;
        use crate::network::zone_registry::ZoneRegistry;

        let (state, _tmp) = build_test_state();
        {
            let mut reg = state.zone_registry.write().unwrap();
            *reg = ZoneRegistry::with_genesis(vec![
                ZoneId::new("a"),
                ZoneId::new("b"),
                ZoneId::new("c"),
                ZoneId::new("d"),
            ]);
        }
        {
            let mut vreg = state.vrf_registry.write().unwrap();
            vreg.register(
                "anchor-A",
                VrfRegistration {
                    vrf_public_key_hex: hex::encode([0xAA; 32]),
                    vrf_full_public_key_hex: String::new(),
                    registered_at: 1.0,
                    record_id: "reg-A".into(),
                    node_type: "anchor".into(),
                },
            );
        }
        {
            let mut ledger = state.ledger.write().await;
            ledger.accounts.insert(
                "anchor-A".to_string(),
                crate::accounting::ledger::AccountState {
                    staked: 1000,
                    ..Default::default()
                },
            );
        }

        // (a) from="z" pushes start_idx to zones.len()=4 (all zones lex < "z"),
        //     so `start_idx + usize::MAX` is the worst case. Saturating →
        //     end_idx clamps to 4 → empty past-the-end page, next_from None.
        let (snap, next_from) =
            state_committees_snapshot(&state, 1, 1, Some("z"), usize::MAX).await;
        assert!(snap.is_empty(), "from past the last zone must yield an empty page");
        assert!(next_from.is_none(), "no zone follows a past-the-end cursor");

        // (b) from="c" → start_idx=2; a huge limit must return the tail {c, d}
        //     (clamped to len), proving saturating preserves the correct page,
        //     not just the no-panic property.
        let (snap, next_from) =
            state_committees_snapshot(&state, 1, 1, Some("c"), usize::MAX).await;
        assert_eq!(snap.len(), 2, "huge limit from mid-cursor returns the tail");
        assert!(snap.contains_key("c") && snap.contains_key("d"));
        assert!(next_from.is_none(), "tail page has no successor");
    }

    // ── is_in_committee predicate ─────────────────────────────────────

    #[test]
    fn is_in_committee_agrees_with_sweep() {
        // Whatever committee `select_zone_committee` picks, the
        // predicate must say "yes, member" for every listed id and
        // "no" for every id not listed. This is the contract Phase 6
        // attestation enforcement will rely on.
        let cands: Vec<Candidate> = (0..40)
            .map(|i| mk(&format!("id-{i:02}"), 100 + i as u64))
            .collect();
        let committee = select_zone_committee("medical/eu", 12, &cands, 7);
        assert_eq!(committee.len(), 7);

        // Every member must be recognized.
        for (rank, id) in committee.iter().enumerate() {
            let (member, r) = is_in_committee("medical/eu", 12, &cands, 7, id);
            assert!(member, "selected id {id} must be recognized as member");
            assert_eq!(r, Some(rank), "rank must match select order for {id}");
        }

        // A non-member must be rejected.
        let non_member = cands
            .iter()
            .map(|c| &c.identity_hash)
            .find(|id| !committee.contains(id))
            .expect("fleet of 40 > committee of 7 always has non-members");
        let (member, r) = is_in_committee("medical/eu", 12, &cands, 7, non_member);
        assert!(!member);
        assert_eq!(r, None);
    }

    #[test]
    fn is_in_committee_zero_stake_is_not_member() {
        // Zone has one real candidate + several zero-stake anchors.
        // Zero-stake must never appear in a committee, even k >> n.
        let mut cands = vec![mk("real", 500)];
        for i in 0..10 {
            cands.push(mk(&format!("ghost-{i}"), 0));
        }

        let (real_in, _) = is_in_committee("zone", 1, &cands, 5, "real");
        assert!(real_in);

        for i in 0..10 {
            let (ghost_in, rank) = is_in_committee("zone", 1, &cands, 5, &format!("ghost-{i}"));
            assert!(!ghost_in, "ghost-{i} must be filtered for zero stake");
            assert_eq!(rank, None);
        }
    }

    #[test]
    fn is_in_committee_unknown_identity_returns_false() {
        let cands: Vec<Candidate> = (0..10).map(|i| mk(&format!("id-{i}"), 100)).collect();
        let (member, rank) = is_in_committee("zone", 1, &cands, 5, "never-registered");
        assert!(!member);
        assert_eq!(rank, None);
    }

    #[tokio::test]
    async fn state_is_in_committee_matches_snapshot() {
        use crate::network::vrf_registry::VrfRegistration;
        use crate::network::zone::ZoneId;
        use crate::network::zone_registry::ZoneRegistry;

        let (state, _tmp) = build_test_state();

        {
            let mut reg = state.zone_registry.write().unwrap();
            *reg = ZoneRegistry::with_genesis(vec![ZoneId::new("medical/eu")]);
        }
        {
            let mut vreg = state.vrf_registry.write().unwrap();
            for i in 0..5 {
                vreg.register(
                    &format!("anchor-{i}"),
                    VrfRegistration {
                        vrf_public_key_hex: hex::encode([i as u8; 32]),
                        vrf_full_public_key_hex: String::new(),
                        registered_at: 1.0,
                        record_id: format!("reg-{i}"),
                        node_type: "anchor".into(),
                    },
                );
            }
        }
        {
            let mut ledger = state.ledger.write().await;
            for i in 0..5 {
                let acc = crate::accounting::ledger::AccountState {
                    staked: 1000 + i as u64,
                    ..Default::default()
                };
                ledger.accounts.insert(format!("anchor-{i}"), acc);
            }
        }

        // Compute snapshot + predicate with the same inputs; they must agree.
        let (snap, _) =
            state_committees_snapshot(&state, 99, 3, None, DEFAULT_COMMITTEES_PAGE_SIZE).await;
        let committee = snap.get("medical/eu").expect("zone present");
        for id in committee {
            let (member, _) = state_is_in_committee(&state, "medical/eu", 99, 3, id).await;
            assert!(member, "{id} was selected; predicate must agree");
        }
        // An unknown anchor is never in a committee.
        let (member, _) = state_is_in_committee(&state, "medical/eu", 99, 3, "ghost").await;
        assert!(!member);
    }

    // ── finality_committee_pks routes through resolver cache ──

    /// At 1M zones × 720 seals/day each anchor calls
    /// `finality_committee_pks` repeatedly for the same `(zone, epoch)`
    /// across seal-create, attestation-verify, and xzone-abort retry
    /// paths. Previously each call paid the full O(n log n)
    /// Efraimidis–Spirakis sort. This test pins that repeat calls now
    /// hit the shared `ZoneCommitteeResolver` cache — one miss, then
    /// hits.
    #[tokio::test]
    async fn ops150_finality_committee_pks_uses_resolver_cache() {
        use crate::network::vrf_registry::VrfRegistration;
        use crate::network::zone::ZoneId;
        use crate::network::zone_registry::ZoneRegistry;
        use std::sync::atomic::Ordering;

        let (state, _tmp) = build_test_state();

        {
            let mut reg = state.zone_registry.write().unwrap();
            *reg = ZoneRegistry::with_genesis(vec![ZoneId::new("medical/eu")]);
        }
        {
            let mut vreg = state.vrf_registry.write().unwrap();
            for i in 0..5 {
                vreg.register(
                    &format!("anchor-{i}"),
                    VrfRegistration {
                        vrf_public_key_hex: hex::encode([i as u8; 32]),
                        vrf_full_public_key_hex: String::new(),
                        registered_at: 1.0,
                        record_id: format!("reg-{i}"),
                        node_type: "anchor".into(),
                    },
                );
            }
        }
        {
            let mut ledger = state.ledger.write().await;
            for i in 0..5 {
                let acc = crate::accounting::ledger::AccountState {
                    staked: 1000 + i as u64,
                    ..Default::default()
                };
                ledger.accounts.insert(format!("anchor-{i}"), acc);
            }
        }

        // Snapshot the resolver counters BEFORE any finality call. Other
        // tests share the per-test state (fresh tempdir), so absolute
        // values are 0 here, but we phrase the asserts as deltas so the
        // test stays correct if shared setup ever touches the resolver.
        let hits_before = state
            .zone_committee_resolver
            .hits_total
            .load(Ordering::Relaxed);
        let misses_before = state
            .zone_committee_resolver
            .misses_total
            .load(Ordering::Relaxed);

        // First call: cold miss.
        let (pks1, hash1, size1) =
            finality_committee_pks(&state, "medical/eu", 7, 5).await;

        let hits_mid = state
            .zone_committee_resolver
            .hits_total
            .load(Ordering::Relaxed);
        let misses_mid = state
            .zone_committee_resolver
            .misses_total
            .load(Ordering::Relaxed);
        assert_eq!(
            misses_mid - misses_before,
            1,
            "first finality call must MISS the resolver cache"
        );
        assert_eq!(
            hits_mid - hits_before,
            0,
            "first finality call must not register a HIT"
        );

        // Second call: same `(zone, epoch, k, candidates)` → hit.
        let (pks2, hash2, size2) =
            finality_committee_pks(&state, "medical/eu", 7, 5).await;

        let hits_after = state
            .zone_committee_resolver
            .hits_total
            .load(Ordering::Relaxed);
        let misses_after = state
            .zone_committee_resolver
            .misses_total
            .load(Ordering::Relaxed);
        assert_eq!(
            hits_after - hits_mid,
            1,
            "second finality call must HIT the resolver cache"
        );
        assert_eq!(
            misses_after - misses_mid,
            0,
            "second finality call must not register a MISS"
        );

        // Determinism: the cached committee answer must match the cold one.
        assert_eq!(pks1, pks2, "cached committee PKs must equal cold draw");
        assert_eq!(hash1, hash2, "cached committee_hash must equal cold");
        assert_eq!(size1, size2, "cached committee_size must equal cold");
    }

    /// Different `(zone, epoch)` keys must MISS the cache and produce
    /// distinct committees — guards against a hash-collision or
    /// fingerprint-only key bug that would fold unrelated lookups.
    #[tokio::test]
    async fn ops150_finality_committee_pks_distinct_keys_distinct_misses() {
        use crate::network::vrf_registry::VrfRegistration;
        use crate::network::zone::ZoneId;
        use crate::network::zone_registry::ZoneRegistry;
        use std::sync::atomic::Ordering;

        let (state, _tmp) = build_test_state();

        {
            let mut reg = state.zone_registry.write().unwrap();
            *reg = ZoneRegistry::with_genesis(vec![
                ZoneId::new("medical/eu"),
                ZoneId::new("medical/us"),
            ]);
        }
        {
            let mut vreg = state.vrf_registry.write().unwrap();
            for i in 0..7 {
                vreg.register(
                    &format!("anchor-{i}"),
                    VrfRegistration {
                        vrf_public_key_hex: hex::encode([i as u8; 32]),
                        vrf_full_public_key_hex: String::new(),
                        registered_at: 1.0,
                        record_id: format!("reg-{i}"),
                        node_type: "anchor".into(),
                    },
                );
            }
        }
        {
            let mut ledger = state.ledger.write().await;
            for i in 0..7 {
                let acc = crate::accounting::ledger::AccountState {
                    staked: 1000 + (i as u64) * 13,
                    ..Default::default()
                };
                ledger.accounts.insert(format!("anchor-{i}"), acc);
            }
        }

        let misses_before = state
            .zone_committee_resolver
            .misses_total
            .load(Ordering::Relaxed);

        // 4 distinct cache keys: 2 zones × 2 epochs.
        let _ = finality_committee_pks(&state, "medical/eu", 1, 5).await;
        let _ = finality_committee_pks(&state, "medical/us", 1, 5).await;
        let _ = finality_committee_pks(&state, "medical/eu", 2, 5).await;
        let _ = finality_committee_pks(&state, "medical/us", 2, 5).await;

        let misses_after = state
            .zone_committee_resolver
            .misses_total
            .load(Ordering::Relaxed);

        assert_eq!(
            misses_after - misses_before,
            4,
            "distinct (zone, epoch) keys must each MISS the cache"
        );
    }

    // ── Phase 6c — seal attestation committee gate ─────────────────────

    fn build_test_state_with_enforce(
        enforce: bool,
    ) -> (
        std::sync::Arc<crate::network::state::NodeState>,
        tempfile::TempDir,
    ) {
        use crate::identity::{CryptoProfile, EntityType, Identity};
        use crate::network::config::NodeConfig;
        use crate::network::state::NodeState;
        use crate::network::witness::WitnessManager;
        use crate::storage::rocks::StorageEngine;

        let tmp = tempfile::tempdir().expect("tempdir");
        let data_dir = tmp.path().to_path_buf();
        let config = NodeConfig {
            data_dir: data_dir.clone(),
            identity_path: data_dir.join("identity.json"),
            db_path: data_dir.join("elara.db"),
            admin_token: "test-admin".into(),
            network_id: "gap5-phase6c-test".into(),
            mdns_enabled: false,
            health_check_interval_secs: 0,
            min_pow_difficulty: 0,
            enforce_per_zone_vrf: enforce,
            ..Default::default()
        };
        let identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
            .expect("generate identity");
        let rocks = std::sync::Arc::new(
            StorageEngine::open(data_dir.join("rocksdb")).expect("open rocks"),
        );
        let wmgr = std::sync::Arc::new(WitnessManager::new(rocks.clone()));
        (
            std::sync::Arc::new(NodeState::new(config, identity, rocks, wmgr)),
            tmp,
        )
    }

    #[tokio::test]
    async fn enforce_no_op_when_flag_off() {
        // Phase 6c default: gate wired but inert. Even an obviously
        // invalid identity must be allowed through, because no
        // enforcement is active until the operator flips the flag.
        let (state, _tmp) = build_test_state_with_enforce(false);
        let allowed = enforce_seal_attestation_committee_membership(
            &state,
            "any/zone",
            42,
            "no-such-identity",
        )
        .await;
        assert!(allowed, "flag off must short-circuit to true");
    }

    #[tokio::test]
    async fn enforce_returns_true_when_no_registered_anchors() {
        // Bootstrap safety: enforcement on, but VRF registry is empty
        // (genesis fleet, fresh boot before any anchor registers).
        // Refusing seal attestations here would freeze finality
        // fleet-wide. Mirrors the bootstrap convention at
        // consensus.rs:768.
        let (state, _tmp) = build_test_state_with_enforce(true);
        let allowed = enforce_seal_attestation_committee_membership(
            &state,
            "medical/eu",
            1,
            "anyone",
        )
        .await;
        assert!(allowed, "empty registry must short-circuit to true");
    }

    #[tokio::test]
    async fn enforce_returns_true_for_committee_member() {
        use crate::network::vrf_registry::VrfRegistration;

        // 10 anchors — strictly above DEFAULT_COMMITTEE_SIZE (7) so this
        // test exercises the real resolver path, not the Phase 6c.5
        // sub-K bootstrap fallback. A separate test
        // `enforce_short_circuits_when_population_below_k` covers the
        // fallback.
        let (state, _tmp) = build_test_state_with_enforce(true);
        {
            let mut vreg = state.vrf_registry.write().unwrap();
            for i in 0..10u8 {
                vreg.register(
                    &format!("anchor-{i:02}"),
                    VrfRegistration {
                        vrf_public_key_hex: hex::encode([i; 32]),
                        vrf_full_public_key_hex: String::new(),
                        registered_at: 1.0,
                        record_id: format!("reg-{i:02}"),
                        node_type: "anchor".into(),
                    },
                );
            }
        }
        let candidates = {
            let mut ledger = state.ledger.write().await;
            for i in 0..10u64 {
                let acc = crate::accounting::ledger::AccountState {
                    staked: 1000 + i,
                    ..Default::default()
                };
                ledger.accounts.insert(format!("anchor-{i:02}"), acc);
            }
            let registered: Vec<String> =
                (0..10u8).map(|i| format!("anchor-{i:02}")).collect();
            assemble_candidates(registered, |id| ledger.staked(id))
        };

        let zone = "medical/eu";
        let epoch = 99u64;
        let committee = select_zone_committee(zone, epoch, &candidates, DEFAULT_COMMITTEE_SIZE);
        assert_eq!(
            committee.len(),
            DEFAULT_COMMITTEE_SIZE,
            "10 staked anchors >= K=7 must yield a full-size committee"
        );

        // Every selected member must pass the gate.
        for id in &committee {
            let allowed =
                enforce_seal_attestation_committee_membership(&state, zone, epoch, id).await;
            assert!(allowed, "{id} is in committee; gate must allow");
        }
        // Bootstrap fallback counter must be untouched on this happy
        // path: gate routed through resolver, not the sub-K shortcut.
        assert_eq!(
            state
                .committee_skipped_below_k_total
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "fallback counter must stay 0 when population >= K"
        );
    }

    #[tokio::test]
    async fn enforce_short_circuits_when_population_below_k() {
        // Phase 6c.5: with `enforce=true` but
        // fewer than DEFAULT_COMMITTEE_SIZE staked-and-registered
        // anchors, the gate must return true (not reject) and bump
        // `committee_skipped_below_k_total`. Otherwise the cluster
        // would freeze finality on every partial-bootstrap fleet
        // (e.g. testnet today: registry=2, K=7).
        use crate::network::vrf_registry::VrfRegistration;

        let (state, _tmp) = build_test_state_with_enforce(true);
        {
            let mut vreg = state.vrf_registry.write().unwrap();
            // Register only 3 anchors — below K=7.
            for i in 0..3u8 {
                vreg.register(
                    &format!("anchor-{i}"),
                    VrfRegistration {
                        vrf_public_key_hex: hex::encode([i; 32]),
                        vrf_full_public_key_hex: String::new(),
                        registered_at: 1.0,
                        record_id: format!("reg-{i}"),
                        node_type: "anchor".into(),
                    },
                );
            }
        }
        {
            let mut ledger = state.ledger.write().await;
            for i in 0..3u64 {
                let acc = crate::accounting::ledger::AccountState {
                    staked: 500 + i,
                    ..Default::default()
                };
                ledger.accounts.insert(format!("anchor-{i}"), acc);
            }
        }

        // Even a non-registered identity must be allowed through the
        // gate during the bootstrap window — the system isn't yet
        // capable of enforcing diversity.
        let allowed = enforce_seal_attestation_committee_membership(
            &state,
            "medical/eu",
            7,
            "stranger-not-in-registry",
        )
        .await;
        assert!(
            allowed,
            "sub-K population must short-circuit gate to true (bootstrap protection)"
        );
        assert_eq!(
            state
                .committee_skipped_below_k_total
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "fallback path must increment committee_skipped_below_k_total"
        );

        // A second call increments by one more — the gate is per-call.
        let _ = enforce_seal_attestation_committee_membership(
            &state,
            "medical/eu",
            8,
            "another-stranger",
        )
        .await;
        assert_eq!(
            state
                .committee_skipped_below_k_total
                .load(std::sync::atomic::Ordering::Relaxed),
            2
        );
    }

    #[tokio::test]
    async fn enforce_returns_false_for_nonmember() {
        use crate::network::vrf_registry::VrfRegistration;

        // 40 anchors, committee of 7 — guarantees non-members exist.
        let (state, _tmp) = build_test_state_with_enforce(true);
        {
            let mut vreg = state.vrf_registry.write().unwrap();
            for i in 0..40u8 {
                vreg.register(
                    &format!("anchor-{i:02}"),
                    VrfRegistration {
                        vrf_public_key_hex: hex::encode([i; 32]),
                        vrf_full_public_key_hex: String::new(),
                        registered_at: 1.0,
                        record_id: format!("reg-{i:02}"),
                        node_type: "anchor".into(),
                    },
                );
            }
        }
        let candidates = {
            let mut ledger = state.ledger.write().await;
            for i in 0..40u64 {
                let acc = crate::accounting::ledger::AccountState {
                    staked: 100 + i,
                    ..Default::default()
                };
                ledger.accounts.insert(format!("anchor-{i:02}"), acc);
            }
            let registered: Vec<String> =
                (0..40u8).map(|i| format!("anchor-{i:02}")).collect();
            assemble_candidates(registered, |id| ledger.staked(id))
        };

        let zone = "medical/eu";
        let epoch = 99u64;
        let committee = select_zone_committee(zone, epoch, &candidates, DEFAULT_COMMITTEE_SIZE);
        assert_eq!(committee.len(), DEFAULT_COMMITTEE_SIZE);

        let non_member = (0..40u8)
            .map(|i| format!("anchor-{i:02}"))
            .find(|id| !committee.contains(id))
            .expect("40 anchors > 7 committee → non-members exist");

        let allowed =
            enforce_seal_attestation_committee_membership(&state, zone, epoch, &non_member).await;
        assert!(!allowed, "{non_member} not in committee; gate must reject");
    }

    // ── Phase 6b advisory observer ─────────────────────────────────────

    #[tokio::test]
    async fn observe_empty_batch_is_noop() {
        // An empty batch must not touch counters or lock anything.
        let (state, _tmp) = build_test_state();
        observe_seal_committee_batch(
            &state,
            std::iter::empty::<SealAttestEntry>(),
        )
        .await;
        assert_eq!(
            state
                .committee_attestations_member_total
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        assert_eq!(
            state
                .committee_attestations_nonmember_total
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        assert_eq!(
            state
                .committee_observations_skipped_no_candidates_total
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    #[tokio::test]
    async fn observe_empty_registry_skips_all_entries() {
        // No VRF-registered anchors → no committee can be drawn →
        // every entry counts as skipped, and the observer early-bails
        // before any ledger read.
        let (state, _tmp) = build_test_state();

        observe_seal_committee_batch(
            &state,
            vec![
                SealAttestEntry { zone_path: "0".into(), epoch: 1, witness_hash: "witness-1".into() },
                SealAttestEntry { zone_path: "0".into(), epoch: 1, witness_hash: "witness-2".into() },
                SealAttestEntry { zone_path: "1".into(), epoch: 1, witness_hash: "witness-3".into() },
            ],
        )
        .await;

        assert_eq!(
            state
                .committee_observations_skipped_no_candidates_total
                .load(std::sync::atomic::Ordering::Relaxed),
            3
        );
        assert_eq!(
            state
                .committee_attestations_member_total
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        assert_eq!(
            state
                .committee_attestations_nonmember_total
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    #[tokio::test]
    async fn observe_bumps_member_vs_nonmember_correctly() {
        use crate::network::vrf_registry::VrfRegistration;

        let (state, _tmp) = build_test_state();

        // Seed 7 anchors with stake — exactly DEFAULT_COMMITTEE_SIZE so
        // the observer routes through the real `select_zone_committee`
        // path, not the Phase 6c.5 sub-K fallback. With candidates ==
        // K, every staked anchor lands in the committee.
        {
            let mut vreg = state.vrf_registry.write().unwrap();
            for i in 0..7u8 {
                vreg.register(
                    &format!("anchor-{i}"),
                    VrfRegistration {
                        vrf_public_key_hex: hex::encode([i; 32]),
                        vrf_full_public_key_hex: String::new(),
                        registered_at: 1.0,
                        record_id: format!("reg-{i}"),
                        node_type: "anchor".into(),
                    },
                );
            }
        }
        {
            let mut ledger = state.ledger.write().await;
            for i in 0..7u64 {
                let acc = crate::accounting::ledger::AccountState {
                    staked: 1000 + i,
                    ..Default::default()
                };
                ledger.accounts.insert(format!("anchor-{i}"), acc);
            }
        }

        // Mix: 2 seal attestations by committee members, 2 by strangers.
        observe_seal_committee_batch(
            &state,
            vec![
                SealAttestEntry { zone_path: "0".into(), epoch: 7, witness_hash: "anchor-0".into() },
                SealAttestEntry { zone_path: "0".into(), epoch: 7, witness_hash: "anchor-1".into() },
                SealAttestEntry { zone_path: "0".into(), epoch: 7, witness_hash: "stranger-X".into() },
                SealAttestEntry { zone_path: "0".into(), epoch: 7, witness_hash: "stranger-Y".into() },
            ],
        )
        .await;

        assert_eq!(
            state
                .committee_attestations_member_total
                .load(std::sync::atomic::Ordering::Relaxed),
            2
        );
        assert_eq!(
            state
                .committee_attestations_nonmember_total
                .load(std::sync::atomic::Ordering::Relaxed),
            2
        );
        assert_eq!(
            state
                .committee_observations_skipped_no_candidates_total
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        assert_eq!(
            state
                .committee_skipped_below_k_total
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "fallback counter must stay 0 when population >= K"
        );
    }

    #[tokio::test]
    async fn observe_routes_to_below_k_fallback_when_population_short() {
        // Phase 6c.5: observer must mirror the
        // gate's bootstrap fallback. When the registry+staked
        // population is below K, every entry in the batch counts as
        // "skipped_below_k" — not nonmember — so operators don't see a
        // false "would have rejected N attestations" signal during the
        // partial-bootstrap window.
        use crate::network::vrf_registry::VrfRegistration;

        let (state, _tmp) = build_test_state();

        // 4 anchors registered + staked, well below DEFAULT_COMMITTEE_SIZE=7.
        {
            let mut vreg = state.vrf_registry.write().unwrap();
            for i in 0..4u8 {
                vreg.register(
                    &format!("anchor-{i}"),
                    VrfRegistration {
                        vrf_public_key_hex: hex::encode([i; 32]),
                        vrf_full_public_key_hex: String::new(),
                        registered_at: 1.0,
                        record_id: format!("reg-{i}"),
                        node_type: "anchor".into(),
                    },
                );
            }
        }
        {
            let mut ledger = state.ledger.write().await;
            for i in 0..4u64 {
                let acc = crate::accounting::ledger::AccountState {
                    staked: 100 + i,
                    ..Default::default()
                };
                ledger.accounts.insert(format!("anchor-{i}"), acc);
            }
        }

        observe_seal_committee_batch(
            &state,
            vec![
                SealAttestEntry { zone_path: "0".into(), epoch: 1, witness_hash: "anchor-0".into() },
                SealAttestEntry { zone_path: "0".into(), epoch: 1, witness_hash: "stranger".into() },
                SealAttestEntry { zone_path: "0".into(), epoch: 2, witness_hash: "anchor-1".into() },
            ],
        )
        .await;

        assert_eq!(
            state
                .committee_skipped_below_k_total
                .load(std::sync::atomic::Ordering::Relaxed),
            3,
            "all 3 entries must land in the sub-K bootstrap counter"
        );
        assert_eq!(
            state
                .committee_attestations_member_total
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "member counter must stay 0 — committee never drawn"
        );
        assert_eq!(
            state
                .committee_attestations_nonmember_total
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "nonmember counter must stay 0 — observer must not pre-reject during bootstrap"
        );
        assert_eq!(
            state
                .committee_observations_skipped_no_candidates_total
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "no_candidates counter is for empty registry; this is a sub-K population"
        );
    }

    #[tokio::test]
    async fn observe_below_default_k_but_above_lowered_threshold_engages() {
        // Regression: when `phase6d_min_committee_size` is lowered
        // (e.g. testnet=3) and the candidate population is below
        // `DEFAULT_COMMITTEE_SIZE` (7) but >= the lowered threshold, the
        // observer must engage — draw the (degenerate, all-candidates)
        // committee and bump member/nonmember counters. Previously the
        // observer used the hardcoded `DEFAULT_COMMITTEE_SIZE` so it always
        // skipped on sub-7 testnets, leaving `committee_attestations_member_total`
        // pinned at 0 and blocking `phase6d_readiness().ready` permanently.
        use crate::identity::{CryptoProfile, EntityType, Identity};
        use crate::network::config::NodeConfig;
        use crate::network::state::NodeState;
        use crate::network::vrf_registry::VrfRegistration;
        use crate::network::witness::WitnessManager;
        use crate::storage::rocks::StorageEngine;

        let tmp = tempfile::tempdir().expect("tempdir");
        let data_dir = tmp.path().to_path_buf();
        let config = NodeConfig {
            data_dir: data_dir.clone(),
            identity_path: data_dir.join("identity.json"),
            db_path: data_dir.join("elara.db"),
            admin_token: "test-admin".into(),
            network_id: "ops164-test".into(),
            mdns_enabled: false,
            health_check_interval_secs: 0,
            min_pow_difficulty: 0,
            enforce_per_zone_vrf: false,
            phase6d_min_committee_size: 3,
            ..Default::default()
        };
        let identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
            .expect("generate identity");
        let rocks = std::sync::Arc::new(
            StorageEngine::open(data_dir.join("rocksdb")).expect("open rocks"),
        );
        let wmgr = std::sync::Arc::new(WitnessManager::new(rocks.clone()));
        let state = std::sync::Arc::new(NodeState::new(config, identity, rocks, wmgr));

        // 4 anchors: above lowered threshold (3) but below DEFAULT_COMMITTEE_SIZE (7).
        {
            let mut vreg = state.vrf_registry.write().unwrap();
            for i in 0..4u8 {
                vreg.register(
                    &format!("anchor-{i}"),
                    VrfRegistration {
                        vrf_public_key_hex: hex::encode([i; 32]),
                        vrf_full_public_key_hex: String::new(),
                        registered_at: 1.0,
                        record_id: format!("reg-{i}"),
                        node_type: "anchor".into(),
                    },
                );
            }
        }
        {
            let mut ledger = state.ledger.write().await;
            for i in 0..4u64 {
                let acc = crate::accounting::ledger::AccountState {
                    staked: 100 + i,
                    ..Default::default()
                };
                ledger.accounts.insert(format!("anchor-{i}"), acc);
            }
        }

        // Mix: 1 attestation from a candidate (anchor-0 will be in any
        // committee draw <= candidates), 1 from a stranger.
        observe_seal_committee_batch(
            &state,
            vec![
                SealAttestEntry { zone_path: "0".into(), epoch: 5, witness_hash: "anchor-0".into() },
                SealAttestEntry { zone_path: "0".into(), epoch: 5, witness_hash: "stranger".into() },
            ],
        )
        .await;

        // With candidates=4 < DEFAULT_COMMITTEE_SIZE=7, `select_zone_committee`
        // returns all 4 anchors (caps at eligible count). So anchor-0 is
        // a member, stranger is not.
        assert_eq!(
            state
                .committee_attestations_member_total
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "OPS-164: observer must engage when candidates >= phase6d_min_committee_size"
        );
        assert_eq!(
            state
                .committee_attestations_nonmember_total
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "stranger is not in the all-candidates committee draw"
        );
        assert_eq!(
            state
                .committee_skipped_below_k_total
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "must NOT bump sub-K counter — population (4) >= threshold (3)"
        );
    }

    // ── Phase 6d readiness predicate ──────────────────────────────────

    #[tokio::test]
    async fn phase6d_readiness_blocks_on_empty_registry() {
        // Genesis fleet: registry empty, no committee work observed.
        // Both blockers must fire; gauge is 0.
        let (state, _tmp) = build_test_state_with_enforce(false);
        let r = phase6d_readiness(&state);
        assert!(!r.ready);
        assert_eq!(r.registry_size, 0);
        assert_eq!(r.min_committee_size, DEFAULT_COMMITTEE_SIZE as u64);
        assert!(!r.gate_currently_enforcing);
        assert_eq!(r.member_observations, 0);
        assert!(r.blockers.contains(&"vrf_registry_below_committee_size"));
        assert!(r.blockers.contains(&"no_observed_committee_members"));
    }

    #[tokio::test]
    async fn phase6d_readiness_blocks_when_only_registry_filled() {
        // Registry has K identities, but no committee observations
        // yet. Gauge must still be 0 — population alone is not proof
        // of working consensus.
        use crate::network::vrf_registry::VrfRegistration;

        let (state, _tmp) = build_test_state_with_enforce(false);
        {
            let mut vreg = state.vrf_registry.write().unwrap();
            for i in 0..DEFAULT_COMMITTEE_SIZE as u8 {
                vreg.register(
                    &format!("anchor-{i}"),
                    VrfRegistration {
                        vrf_public_key_hex: hex::encode([i; 32]),
                        vrf_full_public_key_hex: String::new(),
                        registered_at: 1.0,
                        record_id: format!("reg-{i}"),
                        node_type: "anchor".into(),
                    },
                );
            }
        }

        let r = phase6d_readiness(&state);
        assert!(!r.ready);
        assert_eq!(r.registry_size, DEFAULT_COMMITTEE_SIZE as u64);
        assert!(!r.blockers.contains(&"vrf_registry_below_committee_size"));
        assert!(r.blockers.contains(&"no_observed_committee_members"));
    }

    #[allow(clippy::range_plus_one)]
    #[tokio::test]
    async fn phase6d_readiness_clears_when_both_conditions_met() {
        // Registry >= K AND a member observation has landed. Both
        // blockers cleared — gauge is 1, flip is operationally safe.
        use crate::network::vrf_registry::VrfRegistration;

        let (state, _tmp) = build_test_state_with_enforce(false);
        {
            let mut vreg = state.vrf_registry.write().unwrap();
            for i in 0..(DEFAULT_COMMITTEE_SIZE as u8 + 1) {
                vreg.register(
                    &format!("anchor-{i}"),
                    VrfRegistration {
                        vrf_public_key_hex: hex::encode([i; 32]),
                        vrf_full_public_key_hex: String::new(),
                        registered_at: 1.0,
                        record_id: format!("reg-{i}"),
                        node_type: "anchor".into(),
                    },
                );
            }
        }
        state
            .committee_attestations_member_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let r = phase6d_readiness(&state);
        assert!(r.ready, "expected ready=true; blockers={:?}", r.blockers);
        assert_eq!(r.registry_size, DEFAULT_COMMITTEE_SIZE as u64 + 1);
        assert_eq!(r.member_observations, 1);
        assert!(r.blockers.is_empty());
    }

    #[tokio::test]
    async fn phase6d_readiness_reflects_current_enforcement_flag() {
        // The snapshot must report `gate_currently_enforcing=true`
        // when the flag is on, regardless of whether the readiness
        // conditions still hold. After the flip, operators still need
        // to know whether the conditions remain — a regression
        // (registry shrinking, anchors leaving) is observable here.
        let (state, _tmp) = build_test_state_with_enforce(true);
        let r = phase6d_readiness(&state);
        assert!(r.gate_currently_enforcing);
        assert!(!r.ready, "no committee work yet, must still flag blockers");
    }

    // ── configurable phase6d_min_committee_size ───────────────────────

    /// Helper: state with a specific phase6d threshold. Mirrors
    /// `build_test_state_with_enforce` but lets the test override the
    /// gate floor independently of the enforcement flag.
    fn build_test_state_with_phase6d_min(
        min_committee_size: usize,
    ) -> (
        std::sync::Arc<crate::network::state::NodeState>,
        tempfile::TempDir,
    ) {
        use crate::identity::{CryptoProfile, EntityType, Identity};
        use crate::network::config::NodeConfig;
        use crate::network::state::NodeState;
        use crate::network::witness::WitnessManager;
        use crate::storage::rocks::StorageEngine;

        let tmp = tempfile::tempdir().expect("tempdir");
        let data_dir = tmp.path().to_path_buf();
        let config = NodeConfig {
            data_dir: data_dir.clone(),
            identity_path: data_dir.join("identity.json"),
            db_path: data_dir.join("elara.db"),
            admin_token: "test-admin".into(),
            network_id: "gap5-phase6c-test".into(),
            mdns_enabled: false,
            health_check_interval_secs: 0,
            min_pow_difficulty: 0,
            enforce_per_zone_vrf: false,
            phase6d_min_committee_size: min_committee_size,
            ..Default::default()
        };
        let identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
            .expect("generate identity");
        let rocks = std::sync::Arc::new(
            StorageEngine::open(data_dir.join("rocksdb")).expect("open rocks"),
        );
        let wmgr = std::sync::Arc::new(WitnessManager::new(rocks.clone()));
        (
            std::sync::Arc::new(NodeState::new(config, identity, rocks, wmgr)),
            tmp,
        )
    }

    #[tokio::test]
    async fn phase6d_readiness_emits_default_threshold_of_seven() {
        // Default config must surface min_committee_size=7 so the
        // gauge is mainnet-correct out of the box. If a future refactor
        // accidentally drops the default to 0 or 1, this catches it.
        let (state, _tmp) = build_test_state_with_enforce(false);
        let r = phase6d_readiness(&state);
        assert_eq!(
            r.min_committee_size, DEFAULT_COMMITTEE_SIZE as u64,
            "default config must emit DEFAULT_COMMITTEE_SIZE (=7) as the readiness floor",
        );
    }

    #[tokio::test]
    async fn phase6d_readiness_clears_at_lowered_threshold() {
        // Testnet scenario: 2 anchors registered + threshold lowered
        // to 2. Both blockers must clear so phase6d_ready reports
        // `true`. Previously this was unreachable on a 6-node testnet.
        use crate::network::vrf_registry::VrfRegistration;

        let (state, _tmp) = build_test_state_with_phase6d_min(2);
        {
            let mut vreg = state.vrf_registry.write().unwrap();
            for i in 0..2u8 {
                vreg.register(
                    &format!("anchor-{i}"),
                    VrfRegistration {
                        vrf_public_key_hex: hex::encode([i; 32]),
                        vrf_full_public_key_hex: String::new(),
                        registered_at: 1.0,
                        record_id: format!("reg-{i}"),
                        node_type: "anchor".into(),
                    },
                );
            }
        }
        state
            .committee_attestations_member_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let r = phase6d_readiness(&state);
        assert_eq!(r.min_committee_size, 2);
        assert_eq!(r.registry_size, 2);
        assert!(
            r.ready,
            "registry==threshold + observation > 0 must clear; blockers={:?}",
            r.blockers,
        );
    }

    #[tokio::test]
    async fn phase6d_readiness_blocks_below_lowered_threshold() {
        // Threshold=3, registry=2 → must still block on
        // `vrf_registry_below_committee_size`. Confirms the floor is
        // strict-less-than, not less-than-or-equal.
        use crate::network::vrf_registry::VrfRegistration;

        let (state, _tmp) = build_test_state_with_phase6d_min(3);
        {
            let mut vreg = state.vrf_registry.write().unwrap();
            for i in 0..2u8 {
                vreg.register(
                    &format!("anchor-{i}"),
                    VrfRegistration {
                        vrf_public_key_hex: hex::encode([i; 32]),
                        vrf_full_public_key_hex: String::new(),
                        registered_at: 1.0,
                        record_id: format!("reg-{i}"),
                        node_type: "anchor".into(),
                    },
                );
            }
        }
        state
            .committee_attestations_member_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let r = phase6d_readiness(&state);
        assert_eq!(r.min_committee_size, 3);
        assert_eq!(r.registry_size, 2);
        assert!(!r.ready);
        assert!(
            r.blockers.contains(&"vrf_registry_below_committee_size"),
            "registry < threshold must still flag the registry blocker; got {:?}",
            r.blockers,
        );
    }

    // ── committee_hash_from_members ───────────────────────────────────

    #[test]
    fn committee_hash_empty_returns_zeros() {
        assert_eq!(committee_hash_from_members(&[], 1), [0u8; 32]);
    }

    #[test]
    fn committee_hash_is_deterministic() {
        let members = vec!["alice".to_string(), "bob".to_string(), "carol".to_string()];
        let h1 = committee_hash_from_members(&members, 42);
        let h2 = committee_hash_from_members(&members, 42);
        assert_eq!(h1, h2);
        assert_ne!(h1, [0u8; 32], "non-empty committee must not produce all-zeros");
    }

    #[test]
    fn committee_hash_is_order_independent() {
        // The hash should be the same regardless of input order (sorted internally).
        let a = vec!["alice".to_string(), "bob".to_string(), "carol".to_string()];
        let b = vec!["carol".to_string(), "alice".to_string(), "bob".to_string()];
        assert_eq!(committee_hash_from_members(&a, 10), committee_hash_from_members(&b, 10));
    }

    #[test]
    fn committee_hash_differs_by_epoch() {
        let members = vec!["alice".to_string(), "bob".to_string()];
        let h1 = committee_hash_from_members(&members, 1);
        let h2 = committee_hash_from_members(&members, 2);
        assert_ne!(h1, h2, "different epoch must produce different hash");
    }

    #[test]
    fn committee_hash_differs_by_membership() {
        let a = vec!["alice".to_string(), "bob".to_string()];
        let b = vec!["alice".to_string(), "carol".to_string()];
        assert_ne!(
            committee_hash_from_members(&a, 1),
            committee_hash_from_members(&b, 1),
            "different committee members must produce different hash"
        );
    }

    // ── committee_hash_from_pks (Gap 2.1 Phase 2b.3) ────────────────────

    fn pk(byte: u8) -> Vec<u8> {
        // Dilithium3 PKs are 1952 bytes; for unit tests any non-empty
        // byte vector with a stable byte pattern works — the function
        // only needs `as_ref::<[u8]>()`.
        vec![byte; 32]
    }

    #[test]
    fn pk_committee_hash_empty_returns_zeros() {
        assert_eq!(committee_hash_from_pks(&[]), [0u8; 32]);
    }

    #[test]
    fn pk_committee_hash_single_leaf_equals_leaf_hash() {
        let p = pk(0xAA);
        let root = committee_hash_from_pks(std::slice::from_ref(&p));
        let leaf = crate::accounting::cross_zone::committee_leaf_hash(&p);
        assert_eq!(root, leaf, "single-leaf root must equal the leaf itself");
    }

    #[test]
    fn pk_committee_hash_is_deterministic() {
        let pks = vec![pk(1), pk(2), pk(3), pk(4), pk(5)];
        let h1 = committee_hash_from_pks(&pks);
        let h2 = committee_hash_from_pks(&pks);
        assert_eq!(h1, h2);
    }

    #[test]
    fn pk_committee_hash_is_order_independent() {
        let a = vec![pk(7), pk(3), pk(9), pk(1)];
        let b = vec![pk(1), pk(9), pk(3), pk(7)];
        assert_eq!(
            committee_hash_from_pks(&a),
            committee_hash_from_pks(&b),
            "internal sort means input order does not matter"
        );
    }

    #[test]
    fn pk_committee_hash_dedupes_duplicates() {
        let unique = vec![pk(1), pk(2), pk(3)];
        let with_dups = vec![pk(1), pk(2), pk(3), pk(2), pk(1)];
        assert_eq!(
            committee_hash_from_pks(&unique),
            committee_hash_from_pks(&with_dups),
            "duplicate PKs must dedupe — a witness signs each seal once"
        );
    }

    #[test]
    fn pk_committee_hash_handles_odd_population() {
        // 3 leaves: must duplicate the trailing leaf at the leaf level.
        let pks = vec![pk(1), pk(2), pk(3)];
        let h = committee_hash_from_pks(&pks);
        // Manual construction: sort → leaves L1<L2<L3 → next level
        // [hash(L1||L2), hash(L3||L3)] → root hash(level1[0]||level1[1]).
        let mut leaves: Vec<[u8; 32]> = pks
            .iter()
            .map(|p| crate::accounting::cross_zone::committee_leaf_hash(p))
            .collect();
        leaves.sort_unstable();
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&leaves[0]);
        buf[32..].copy_from_slice(&leaves[1]);
        let n0 = sha3_256(&buf);
        buf[..32].copy_from_slice(&leaves[2]);
        buf[32..].copy_from_slice(&leaves[2]);
        let n1 = sha3_256(&buf);
        buf[..32].copy_from_slice(&n0);
        buf[32..].copy_from_slice(&n1);
        let expected = sha3_256(&buf);
        assert_eq!(h, expected);
    }

    #[test]
    fn pk_committee_hash_differs_from_member_hash() {
        // The two functions exist precisely because they're hashing
        // different inputs (PK bytes vs identity_hash strings). A
        // committee whose members happen to be { hex-encoded PKs }
        // must still produce a different commitment than the PK-leaf
        // form, because the leaf-hashing domain differs.
        let pks = vec![pk(1), pk(2), pk(3)];
        let members: Vec<String> = pks.iter().map(hex::encode).collect();
        assert_ne!(
            committee_hash_from_pks(&pks),
            committee_hash_from_members(&members, 0),
            "PK-leaf root and identity-string root must NOT collide"
        );
    }

    #[test]
    fn pk_committee_hash_two_leaves_matches_manual_construction() {
        let pks = vec![pk(0x10), pk(0x20)];
        let h = committee_hash_from_pks(&pks);
        let mut leaves: Vec<[u8; 32]> = pks
            .iter()
            .map(|p| crate::accounting::cross_zone::committee_leaf_hash(p))
            .collect();
        leaves.sort_unstable();
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&leaves[0]);
        buf[32..].copy_from_slice(&leaves[1]);
        assert_eq!(h, sha3_256(&buf));
    }

    // ── Phase 6b cached resolver ──────────────────────────────────────

    use std::sync::atomic::Ordering;

    fn cands(spec: &[(&str, u64)]) -> Vec<Candidate> {
        spec.iter().map(|(id, w)| mk(id, *w)).collect()
    }

    #[test]
    fn resolver_hit_returns_same_committee_as_pure_fn() {
        // Cache hit MUST equal the pure-fn answer. If they ever
        // diverge, two nodes (one with a warm cache, one cold) compute
        // different committees from the same inputs and consensus
        // forks. This is the resolver's load-bearing invariant.
        let r = ZoneCommitteeResolver::default();
        let c = cands(&[("a", 100), ("b", 200), ("c", 300), ("d", 400), ("e", 500)]);
        let pure = select_zone_committee("zone/x", 7, &c, 3);

        let cached_a = r.resolve("zone/x", 7, &c, 3);
        let cached_b = r.resolve("zone/x", 7, &c, 3);

        assert_eq!(cached_a, pure);
        assert_eq!(cached_b, pure);
        assert_eq!(r.misses_total.load(Ordering::Relaxed), 1, "1 cold miss");
        assert_eq!(r.hits_total.load(Ordering::Relaxed), 1, "1 warm hit");
    }

    #[test]
    fn resolver_invalidates_on_candidates_change() {
        // Adding/removing/reweighting a candidate must change the
        // fingerprint and force a fresh draw — the cached entry under
        // the OLD fingerprint stays put (different key), and a new
        // entry inserts under the NEW fingerprint. This is the
        // protocol-correctness story: a stale cache entry can never
        // mask a real candidate-set change.
        let r = ZoneCommitteeResolver::default();
        let c1 = cands(&[("a", 100), ("b", 200)]);
        let c2 = cands(&[("a", 100), ("b", 200), ("c", 300)]); // new candidate
        let c3 = cands(&[("a", 100), ("b", 999)]);             // re-weighted

        let _ = r.resolve("zone/x", 1, &c1, 5); // miss
        let _ = r.resolve("zone/x", 1, &c1, 5); // hit
        let _ = r.resolve("zone/x", 1, &c2, 5); // miss (new candidate)
        let _ = r.resolve("zone/x", 1, &c3, 5); // miss (reweight)
        let _ = r.resolve("zone/x", 1, &c3, 5); // hit
        let _ = r.resolve("zone/x", 1, &c1, 5); // hit (c1 still cached)

        assert_eq!(r.hits_total.load(Ordering::Relaxed), 3);
        assert_eq!(r.misses_total.load(Ordering::Relaxed), 3);
        assert_eq!(r.cache_size(), 3, "three distinct fingerprints stored");
    }

    #[test]
    fn resolver_invalidates_on_zone_or_epoch_or_k_change() {
        // Cache key includes (zone, epoch, k, fingerprint). Changing
        // any of the first three with the same candidate set must
        // produce a fresh draw and a separate cache slot.
        let r = ZoneCommitteeResolver::default();
        let c = cands(&[("a", 100), ("b", 200), ("c", 300), ("d", 400)]);

        let _ = r.resolve("zone/x", 1, &c, 3); // miss #1
        let _ = r.resolve("zone/y", 1, &c, 3); // miss #2 (zone)
        let _ = r.resolve("zone/x", 2, &c, 3); // miss #3 (epoch)
        let _ = r.resolve("zone/x", 1, &c, 4); // miss #4 (k)
        let _ = r.resolve("zone/x", 1, &c, 3); // hit

        assert_eq!(r.misses_total.load(Ordering::Relaxed), 4);
        assert_eq!(r.hits_total.load(Ordering::Relaxed), 1);
        assert_eq!(r.cache_size(), 4);
    }

    #[test]
    fn resolver_fifo_evicts_oldest_at_cap() {
        // Cap-2 resolver: insert 3 distinct entries → 1 eviction;
        // then re-resolve the first inserted key → it MUST miss
        // (FIFO evicted it) and the new entry replaces the second-
        // oldest. This pins the eviction order so a future LRU swap
        // is a deliberate choice, not an accidental rewrite.
        let r = ZoneCommitteeResolver::with_capacity(2);
        let c = cands(&[("a", 100), ("b", 200)]);

        let _ = r.resolve("zone-1", 1, &c, 2); // miss, cache=[1]
        let _ = r.resolve("zone-2", 1, &c, 2); // miss, cache=[1,2]
        let _ = r.resolve("zone-3", 1, &c, 2); // miss, cache=[2,3], evict zone-1
        assert_eq!(r.evictions_total.load(Ordering::Relaxed), 1);
        assert_eq!(r.cache_size(), 2);

        let _ = r.resolve("zone-1", 1, &c, 2); // miss again (was evicted)
        assert_eq!(r.misses_total.load(Ordering::Relaxed), 4);
        assert_eq!(r.evictions_total.load(Ordering::Relaxed), 2, "zone-2 evicted now");
    }

    #[test]
    fn resolver_capacity_floor_clamps_zero_to_one() {
        // A zero-cap resolver would loop forever in the eviction
        // `while cache.len() >= 0` check. Constructor clamps to 1 so
        // every miss self-evicts but the call still terminates.
        let r = ZoneCommitteeResolver::with_capacity(0);
        assert_eq!(r.cache_capacity(), 1);
        let c = cands(&[("a", 100), ("b", 200)]);
        let _ = r.resolve("zone-1", 1, &c, 2);
        let _ = r.resolve("zone-2", 1, &c, 2);
        // Two misses, second triggers an eviction of the first.
        assert_eq!(r.misses_total.load(Ordering::Relaxed), 2);
        assert_eq!(r.evictions_total.load(Ordering::Relaxed), 1);
        assert_eq!(r.cache_size(), 1);
    }

    #[test]
    fn fingerprint_is_order_independent_when_input_canonical() {
        // `assemble_candidates*` already sorts by identity_hash
        // ascending. The fingerprint matches that contract: feed the
        // same set in the canonical order and get the same hash.
        // This pins the dependency between the candidate-assembly
        // helper and the resolver — a future "let's not pre-sort"
        // refactor would silently break determinism, so this test
        // documents the coupling.
        let canon_a = assemble_candidates(
            ["b", "c", "a"].iter().map(|s| s.to_string()),
            |id| match id {
                "a" => 100,
                "b" => 200,
                "c" => 300,
                _ => 0,
            },
        );
        let canon_b = assemble_candidates(
            ["c", "a", "b"].iter().map(|s| s.to_string()),
            |id| match id {
                "a" => 100,
                "b" => 200,
                "c" => 300,
                _ => 0,
            },
        );
        assert_eq!(canon_a, canon_b, "assemble_candidates pre-sorts");
        assert_eq!(
            candidates_fingerprint(&canon_a),
            candidates_fingerprint(&canon_b),
            "fingerprint determinism rests on canonical input order"
        );
    }

    #[test]
    fn resolver_same_inputs_diff_resolvers_match() {
        // Two independent resolver instances (think: two nodes) must
        // agree on the committee for the same inputs. The cache is a
        // node-local optimization; consensus correctness rests on
        // pure-fn equality, not shared cache state.
        let r1 = ZoneCommitteeResolver::default();
        let r2 = ZoneCommitteeResolver::default();
        let c = cands(&[("x", 100), ("y", 200), ("z", 300), ("w", 400)]);
        assert_eq!(
            r1.resolve("zone/finance/eu", 99, &c, 3),
            r2.resolve("zone/finance/eu", 99, &c, 3),
            "node-local resolver cannot diverge from peer for same inputs"
        );
    }

    #[test]
    fn resolver_is_member_matches_pure_predicate() {
        // resolve_is_member must match `is_in_committee(...)`.
        let r = ZoneCommitteeResolver::default();
        let c = cands(&[("a", 100), ("b", 200), ("c", 300), ("d", 400), ("e", 500)]);
        let committee = select_zone_committee("zone/x", 1, &c, 3);
        assert_eq!(committee.len(), 3);
        for id in &["a", "b", "c", "d", "e"] {
            let (pure_member, pure_rank) = is_in_committee("zone/x", 1, &c, 3, id);
            let (cached_member, cached_rank) =
                r.resolve_is_member("zone/x", 1, &c, 3, id);
            assert_eq!(pure_member, cached_member, "membership mismatch for {id}");
            assert_eq!(pure_rank, cached_rank, "rank mismatch for {id}");
        }
    }

    // ── Gap 5 second slice — select_committee_v2 property tests ──────
    //
    // These pin the documented invariants in
    // internal design notes. The unified algorithm is
    // additive in this slice (call sites still consult the legacy
    // function); the tests cover correctness of the new function in
    // isolation so Step 2's call-site wire-up has a known-good baseline.

    fn elig_set(n: usize, base_stake: u64) -> Vec<(String, u64)> {
        (0..n)
            .map(|i| (format!("id{i:02}"), base_stake + i as u64))
            .collect()
    }

    #[test]
    fn gap5_v2_empty_inputs_return_empty() {
        // Both axes of empty-input must short-circuit cleanly.
        let vrf = [0xAAu8; 32];
        assert!(select_committee_v2(&vrf, "zone", &[], 7).is_empty());
        assert!(select_committee_v2(&vrf, "zone", &elig_set(5, 1), 0).is_empty());
        // All-zero-stake eligible — non-empty Vec but all filtered.
        let zero_stake: Vec<(String, u64)> = vec![("a".into(), 0), ("b".into(), 0)];
        assert!(select_committee_v2(&vrf, "zone", &zero_stake, 5).is_empty());
    }

    #[test]
    fn gap5_v2_empty_vrf_bootstrap_returns_identity_sorted() {
        // Pre-VRF state (`vrf_output.is_empty()`) — the algorithm
        // returns the eligible set sorted lexicographically by id,
        // capped at k. Matches consensus-path bootstrap shape so the
        // call-site swap doesn't silently change pre-VRF testnet
        // committees.
        let elig = vec![
            ("zz".into(), 100u64),
            ("aa".into(), 1u64),
            ("mm".into(), 50u64),
        ];
        let out = select_committee_v2(&[], "any-zone", &elig, 5);
        // Capped at k=5, but only 3 inputs — all included, identity-sorted.
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].0, "aa");
        assert_eq!(out[1].0, "mm");
        assert_eq!(out[2].0, "zz");

        // k=2 caps the output regardless of input cardinality.
        let out2 = select_committee_v2(&[], "any-zone", &elig, 2);
        assert_eq!(out2.len(), 2);
        assert_eq!(out2[0].0, "aa");
        assert_eq!(out2[1].0, "mm");
    }

    #[test]
    fn gap5_v2_small_network_short_circuit() {
        // |non_zero_eligible| ≤ COMMITTEE_SMALL_NETWORK → everyone
        // attests, sorted by identity. The hash + linear-stake math
        // is skipped at this size.
        let vrf = [0xCDu8; 32];
        let elig = elig_set(super::super::consensus::COMMITTEE_SMALL_NETWORK, 1);
        let out = select_committee_v2(
            &vrf,
            "small",
            &elig,
            super::super::consensus::COMMITTEE_SMALL_NETWORK,
        );
        assert_eq!(out.len(), super::super::consensus::COMMITTEE_SMALL_NETWORK);
        // identity-sorted
        let ids: Vec<&str> = out.iter().map(|(id, _)| id.as_str()).collect();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted);
    }

    #[test]
    fn gap5_v2_determinism_input_order_invariant() {
        // Same eligible SET (different input order) → bit-identical
        // output. This is the load-bearing determinism property —
        // across-fleet consensus depends on every node computing the
        // same committee from the same (vrf, zone, eligible).
        let vrf = [0x42u8; 32];
        let mut elig_a = elig_set(20, 100);
        let mut elig_b = elig_a.clone();
        elig_b.reverse();
        let out_a = select_committee_v2(&vrf, "zone/path", &elig_a, 7);
        let out_b = select_committee_v2(&vrf, "zone/path", &elig_b, 7);
        assert_eq!(out_a, out_b, "input order must not affect output");

        // Same input twice — bit-identical.
        elig_a.sort_by(|x, y| y.0.cmp(&x.0));
        let out_a2 = select_committee_v2(&vrf, "zone/path", &elig_a, 7);
        assert_eq!(out_a, out_a2, "shuffled input must not affect output");
    }

    #[test]
    fn gap5_v2_vrf_change_changes_committee() {
        // Different vrf_output → different committee output. This
        // pins the "VRF entropy folds in" invariant — a buggy
        // algorithm that ignored vrf_output would still pass the
        // empty/bootstrap tests above.
        let elig = elig_set(20, 100);
        let out_a = select_committee_v2(&[0x01u8; 32], "zone", &elig, 7);
        let out_b = select_committee_v2(&[0xFEu8; 32], "zone", &elig, 7);
        assert_ne!(
            out_a, out_b,
            "different VRF must produce different committees on a large enough pool",
        );
    }

    #[test]
    fn gap5_v2_zone_change_changes_committee() {
        // Different zone_path → different committee. Pins the
        // per-zone-diversity invariant: at 1M zones, the same VRF
        // seed must produce different committees per zone so no
        // single stake holder dominates all zones.
        let vrf = [0x99u8; 32];
        let elig = elig_set(20, 100);
        let out_a = select_committee_v2(&vrf, "alpha", &elig, 7);
        let out_b = select_committee_v2(&vrf, "beta", &elig, 7);
        assert_ne!(
            out_a, out_b,
            "same VRF + different zone must produce different committees",
        );
    }

    #[test]
    fn gap5_v2_output_lexically_sorted() {
        // Output sort-by-identity invariant. Downstream
        // committee_hash_from_members + attestation gate lookups
        // depend on this; a regression here would silently corrupt
        // committee_hash digests.
        let vrf = [0x77u8; 32];
        let elig = elig_set(50, 100);
        let out = select_committee_v2(&vrf, "zone", &elig, 7);
        let ids: Vec<&str> = out.iter().map(|(id, _)| id.as_str()).collect();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted, "output must be sorted by identity");
    }

    #[test]
    fn gap5_v2_zero_stake_filtered() {
        // Zero-stake entries in the eligible set MUST NOT win seats.
        // The consensus path filters via the index; v2 filters via
        // an explicit non_zero pass. Mix zero and non-zero stakes
        // and pin that no zero-stake id appears in the output.
        let vrf = [0x33u8; 32];
        let mut elig: Vec<(String, u64)> = (0..50)
            .map(|i| {
                let stake = if i % 2 == 0 { 0u64 } else { 100u64 };
                (format!("id{i:02}"), stake)
            })
            .collect();
        // Add a guaranteed-zero-stake high-priority lex-first id —
        // would dominate output if zero-stake filtering regressed.
        elig.push(("aaaa".into(), 0));
        let out = select_committee_v2(&vrf, "zone", &elig, 7);
        for (id, w) in &out {
            assert!(*w > 0, "zero-stake id {id} must not appear in committee");
        }
    }

    #[test]
    fn gap5_v2_k_caps_output_size() {
        // Output length ≤ k for every k. Pin both small-k and
        // k > |eligible| edge cases.
        let vrf = [0xBBu8; 32];
        let elig = elig_set(50, 100);
        for k in [1, 3, 7, 25, 49, 50, 51, 100] {
            let out = select_committee_v2(&vrf, "zone", &elig, k);
            assert!(out.len() <= k, "output {} > k {} for elig=50", out.len(), k);
            assert!(out.len() <= elig.len(), "output > eligible");
        }
    }

    #[test]
    fn gap5_v2_higher_stake_higher_selection_probability() {
        // Statistical / Monte-Carlo: over many distinct VRF seeds,
        // a high-stake candidate must win seats *more often* than a
        // low-stake candidate. Pins the linear-weight Efraimidis–
        // Spirakis invariant.
        let mut elig: Vec<(String, u64)> = (0..30)
            .map(|i| (format!("normal{i:02}"), 100u64))
            .collect();
        elig.push(("WHALE".into(), 100_000u64)); // 1000× normal stake
        elig.push(("MOUSE".into(), 1u64));        // 1/100 normal stake

        let mut whale_wins = 0;
        let mut mouse_wins = 0;
        let trials = 200;
        for seed in 0..trials {
            let mut vrf = [0u8; 32];
            vrf[..8].copy_from_slice(&(seed as u64).to_be_bytes());
            let out = select_committee_v2(&vrf, "zone", &elig, 7);
            if out.iter().any(|(id, _)| id == "WHALE") {
                whale_wins += 1;
            }
            if out.iter().any(|(id, _)| id == "MOUSE") {
                mouse_wins += 1;
            }
        }
        // Whale at 1000× stake should dominate; mouse at 0.01× should
        // be extremely rare. Generous bounds — this is a probabilistic
        // test, exact thresholds risk flake.
        assert!(
            whale_wins > mouse_wins * 3,
            "whale wins {whale_wins}, mouse wins {mouse_wins} — linear stake weighting regressed",
        );
    }

    #[test]
    fn gap5_v2_diversity_across_zones() {
        // Different zones with the same VRF seed should rotate
        // selections across the eligible pool — no single id should
        // dominate every zone. Pins the per-zone-diversity invariant
        // at 1M-zone scale (the whole reason this slice exists).
        let vrf = [0x55u8; 32];
        let elig = elig_set(50, 100);
        let mut all_winners: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        for z in 0..30 {
            let out = select_committee_v2(&vrf, &format!("zone{z}"), &elig, 7);
            for (id, _) in out {
                all_winners.insert(id);
            }
        }
        // Across 30 zones × 7 seats = 210 selection slots over a
        // 50-candidate pool. With diversity working, most candidates
        // should win at least one slot somewhere. Loose bound to
        // accommodate stake-weighted clustering at the high end.
        assert!(
            all_winners.len() >= 25,
            "only {} of 50 candidates won any seat — diversity regressed",
            all_winners.len(),
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    // Committee-constant and selection invariant tests (5 distinct axes)
    // ─────────────────────────────────────────────────────────────────────

    /// **Axis 1**: literal-value pin for the four committee module
    /// constants. The existing `min_and_default_committee_size_constants_are_sane`
    /// is empty — it relies on a compile-time `const _: () = assert!(>=)`
    /// block that allows ANY value satisfying the ordering relations
    /// (e.g., a future-me bump to k=9 to "increase safety" would compile
    /// silently). Pin the EXACT numbers so accidental drift is caught.
    ///
    /// Load-bearing context:
    /// - `MIN_COMMITTEE_SIZE = 5` is the BFT f=1 floor (3f+1 with f=1 = 4,
    ///   so 5 gives one margin).
    /// - `DEFAULT_COMMITTEE_SIZE = 7` is what `phase6d_readiness` and the
    ///   `state_committees_snapshot` default tests assume.
    /// - `DEFAULT_COMMITTEES_PAGE_SIZE = 1000` caps `/committees` response
    ///   body at roughly 1 MB; a drift to 10_000 would OOM serving nodes
    ///   at 1M-zone scale.
    /// - `DEFAULT_RESOLVER_CACHE_SIZE = 4096` is the FIFO cap; reducing it
    ///   silently degrades resolver hit rate on hot-zone clusters.
    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_zone_committee_constants_literal_pin() {
        assert_eq!(MIN_COMMITTEE_SIZE, 5, "BFT f=1 floor must stay at 5");
        assert_eq!(
            DEFAULT_COMMITTEE_SIZE, 7,
            "default k=7 wires phase6d + committees snapshot defaults"
        );
        assert_eq!(
            DEFAULT_COMMITTEES_PAGE_SIZE, 1000,
            "~1 MB response cap at k=7 × 32-byte identities — do not raise without OOM check"
        );
        assert_eq!(
            DEFAULT_RESOLVER_CACHE_SIZE, 4096,
            "FIFO cap; lowering silently degrades resolver hit rate"
        );
        // Ordering relations: relied on by const-assert and call sites.
        assert!(DEFAULT_COMMITTEE_SIZE >= MIN_COMMITTEE_SIZE);
    }

    /// **Axis 2**: known-vector pin of `committee_hash_from_members`'s
    /// wire format. Existing tests cover relative invariants
    /// (deterministic, order-independent, epoch-distinguishing,
    /// membership-distinguishing) but NEVER pin an absolute output, so a
    /// future-me change to the domain prefix (`"V1"` → `"V2"`), the byte
    /// order of the epoch encoding (little → big endian), or the
    /// delimiter (`|` → `,`) would pass every existing test and silently
    /// invalidate every historical transition-seal `committee_hash`.
    /// Reconstruct the expected hash inline so the test pins the
    /// algorithm shape, not the hash function output.
    #[test]
    fn batch_b_committee_hash_from_members_wire_format_known_vector() {
        let members = vec!["alice".to_string(), "bob".to_string()];
        let epoch: u64 = 42;
        // Algorithm spec (pinned here): sha3_256(DOMAIN || epoch.to_le() ||
        // member1|member2|...|) with members sorted lexicographically.
        const DOMAIN: &[u8] = b"ELARA_COMMITTEE_HASH_V1";
        let mut buf = Vec::new();
        buf.extend_from_slice(DOMAIN);
        buf.extend_from_slice(&epoch.to_le_bytes());
        // alphabetical sort → alice before bob.
        buf.extend_from_slice(b"alice");
        buf.push(b'|');
        buf.extend_from_slice(b"bob");
        buf.push(b'|');
        let expected = sha3_256(&buf);
        let actual = committee_hash_from_members(&members, epoch);
        assert_eq!(
            actual, expected,
            "wire-format drift: domain/endianness/delimiter changed"
        );
        // Also verify that swapping epoch endianness produces a different
        // output (sanity check that the LE encoding pin is meaningful).
        let mut buf_be = Vec::new();
        buf_be.extend_from_slice(DOMAIN);
        buf_be.extend_from_slice(&epoch.to_be_bytes());
        buf_be.extend_from_slice(b"alice");
        buf_be.push(b'|');
        buf_be.extend_from_slice(b"bob");
        buf_be.push(b'|');
        let alt = sha3_256(&buf_be);
        assert_ne!(
            actual, alt,
            "if LE and BE encodings agree, epoch=42 is byte-palindromic; pick a non-palindromic test value"
        );
    }

    /// **Axis 3**: `committee_hash_from_pks` dedup-down-to-one equals the
    /// single-leaf root. `pk_committee_hash_dedupes_duplicates` proves
    /// {a,b,c,b,a} == {a,b,c} (dedup), and
    /// `pk_committee_hash_single_leaf_equals_leaf_hash` proves a one-
    /// element input returns the leaf hash directly. This axis pins the
    /// COMPOSITION: a multi-element input that dedupes down to one leaf
    /// must yield the leaf hash directly (no Merkle level), so an
    /// "always at least one level" refactor (e.g., wrapping single-leaf
    /// in `sha3(leaf||leaf)`) breaks here, not in production.
    #[test]
    fn batch_b_committee_hash_from_pks_dedup_to_single_leaf() {
        fn pk(b: u8) -> Vec<u8> {
            vec![b; 32]
        }
        let single = vec![pk(0xAB)];
        let dedupes_to_single = vec![pk(0xAB), pk(0xAB), pk(0xAB), pk(0xAB)];
        let leaf = crate::accounting::cross_zone::committee_leaf_hash(&pk(0xAB));

        let h_single = committee_hash_from_pks(&single);
        let h_dedup = committee_hash_from_pks(&dedupes_to_single);
        assert_eq!(h_single, leaf, "single-leaf root must equal leaf hash");
        assert_eq!(
            h_dedup, leaf,
            "dedup-to-single must short-circuit to the leaf hash, not wrap it in an extra sha3(leaf||leaf) level"
        );
        assert_eq!(h_single, h_dedup);

        // Two distinct PKs that interleave with their own duplicates
        // still collapse to the two-leaf root.
        let two_with_dups = vec![pk(0x01), pk(0x02), pk(0x01), pk(0x02), pk(0x01)];
        let two_distinct = vec![pk(0x01), pk(0x02)];
        assert_eq!(
            committee_hash_from_pks(&two_with_dups),
            committee_hash_from_pks(&two_distinct),
        );
    }

    /// **Axis 4**: `committee_hash_from_members([])` and
    /// `committee_hash_from_pks([])` BOTH return `[0u8; 32]` — that
    /// collision is **intentional sentinel behavior** documented as
    /// "not yet known" / "no eligible anchors". The
    /// `pk_committee_hash_differs_from_member_hash` test proves the two
    /// hashes diverge on a specific non-empty pair; this axis pins:
    /// (a) the empty-empty collision is reproducible (defends against a
    /// future-me "fix" that introduces different empty sentinels and
    /// breaks every downstream "all zeros = placeholder" check);
    /// (b) the empty-empty case is the ONLY input shape under which the
    /// two functions are allowed to agree across a sweep of small inputs.
    #[test]
    fn batch_b_committee_hash_empty_sentinel_is_the_only_collision() {
        let zero = [0u8; 32];
        // (a) empty-empty collision pinned.
        assert_eq!(committee_hash_from_members(&[], 0), zero);
        assert_eq!(committee_hash_from_members(&[], 7), zero, "epoch ignored on empty");
        assert_eq!(committee_hash_from_pks(&[]), zero);

        // (b) any non-empty input MUST diverge. Sweep small inputs.
        for byte in [0x01u8, 0x55, 0xAA, 0xFF] {
            let id = format!("{byte:02x}");
            let pk_v = vec![byte; 32];
            let member_hash = committee_hash_from_members(std::slice::from_ref(&id), 0);
            let pk_hash = committee_hash_from_pks(&[pk_v]);
            assert_ne!(
                member_hash, zero,
                "non-empty member set must not return zero sentinel"
            );
            assert_ne!(
                pk_hash, zero,
                "non-empty pk set must not return zero sentinel"
            );
            assert_ne!(
                member_hash, pk_hash,
                "different leaf-hashing domains must not collide on byte={byte}",
            );
        }
    }

    #[allow(clippy::doc_lazy_continuation, clippy::doc_overindented_list_items)]
    /// **Axis 5**: `assemble_candidates_with_fallback` boundary
    /// semantics. The existing tests cover:
    ///   - zero-stake drop with fallback=0;
    ///   - canonical sort regardless of input order;
    ///   - fallback admits zero-stake at fallback weight;
    ///   - registry expansion dedups against VRF anchors.
    /// This axis pins the unprobed corners:
    ///   (1) empty registered → empty pool (no panic, no synthetic);
    ///   (2) all-zero-stake + fallback=0 → empty (consistent with single-
    ///       zero-stake drop);
    ///   (3) mixed staked + zero-stake under fallback>0 keeps the REAL
    ///       weight for staked (not the fallback) — i.e. fallback is
    ///       ONLY applied to zero-stake entries, not as a floor;
    ///   (4) output is always lex-sorted by identity_hash regardless of
    ///       fallback path taken.
    #[test]
    fn batch_b_assemble_candidates_with_fallback_boundary_semantics() {
        // (1) empty registered → empty pool, with or without fallback.
        let empty: Vec<String> = vec![];
        assert!(
            assemble_candidates_with_fallback(empty.clone(), |_| 100, 0).is_empty(),
            "empty registered must return empty pool"
        );
        assert!(
            assemble_candidates_with_fallback(empty, |_| 100, 99).is_empty(),
            "empty registered must return empty pool even with fallback>0"
        );

        // (2) all-zero-stake + fallback=0 → empty (drop-all).
        let regs = vec!["z1".to_string(), "z2".to_string(), "z3".to_string()];
        let pool = assemble_candidates_with_fallback(regs.clone(), |_| 0, 0);
        assert!(pool.is_empty(), "all-zero-stake + fallback=0 must drop all");

        // (3) fallback applies ONLY to zero-stake entries; staked entries
        // keep their REAL weight, not the fallback floor.
        let regs2 = vec![
            "alice".to_string(),
            "bob".to_string(),
            "carol".to_string(),
            "dave".to_string(),
        ];
        let stakes: std::collections::HashMap<&str, u64> =
            [("alice", 100), ("bob", 0), ("carol", 500), ("dave", 0)].into_iter().collect();
        let fallback = 1u64;
        let pool = assemble_candidates_with_fallback(
            regs2,
            |id| *stakes.get(id).unwrap_or(&0),
            fallback,
        );

        // All four included (none dropped because fallback>0).
        let by_id: std::collections::HashMap<&str, u64> = pool
            .iter()
            .map(|c| (c.identity_hash.as_str(), c.weight))
            .collect();
        assert_eq!(by_id.len(), 4);
        assert_eq!(*by_id.get("alice").unwrap(), 100, "alice keeps real stake, not fallback");
        assert_eq!(*by_id.get("bob").unwrap(), fallback, "bob gets fallback");
        assert_eq!(*by_id.get("carol").unwrap(), 500, "carol keeps real stake");
        assert_eq!(*by_id.get("dave").unwrap(), fallback, "dave gets fallback");

        // (4) output is lex-sorted by identity_hash regardless of input
        // order or fallback path.
        let ids: Vec<&str> = pool.iter().map(|c| c.identity_hash.as_str()).collect();
        let mut sorted_ids = ids.clone();
        sorted_ids.sort_unstable();
        assert_eq!(ids, sorted_ids, "output must be lex-sorted on identity_hash");
        assert_eq!(ids, vec!["alice", "bob", "carol", "dave"]);
    }
}
