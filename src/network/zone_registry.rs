//! Zone Registry — authoritative state of the zone tree.
//!
//! The registry answers two questions the protocol needs at 1M-zone scale:
//!
//! 1. **Routing** — given an account/record and its initial naive zone, which
//!    leaf zone owns it *right now*? Naive flat-modulo assignment (as used by
//!    [`super::zone::ZoneId::for_record_dynamic`]) picks a starting zone; if
//!    that zone has since been split — possibly multiple times — the registry
//!    walks the resulting tree to the current leaf.
//!
//! 2. **Committee sweep** — which zones are currently active leaves? Gap 5
//!    (per-zone VRF committees) needs to iterate exactly the live zones when
//!    drawing committees per-epoch, not the full historical set.
//!
//! The registry is a pure, finite-state data structure. It consumes finalized
//! [`TransitionSeal`] events; it does no I/O and does not verify signatures.
//! The Dilithium3 anchor-cosign check happens at the seal/orchestrator layer
//! before a seal is handed to [`ZoneRegistry::apply_transition`]. Callers
//! persist the registry (or a rebuild log of seals) via the storage layer.
//!
//! Scale:
//! * `apply_transition` is O(1).
//! * `resolve` is O(depth_of_tree) — in practice ≤ log₂(global_rec_rate),
//!   a small constant (≤20 for any plausible fleet size).
//! * `active_zones` iteration is O(active_leaf_count), which is exactly the
//!   bound on committee-draw work anyway.
//!
//! Gap 5 will wire this; Gap 4 routing close-out (`zone_for_record`) consumes
//! it on top of Gap 5's committee registry. This module is load-bearing for
//! both and ships before either.
//!
//! Phase 1 (this commit): data structure + apply/resolve + unit tests. No
//! runtime wiring. No persistence. Those land in subsequent phases.

use std::collections::{BTreeSet, HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::errors::{ElaraError, Result};
use crate::network::zone::ZoneId;
use crate::network::zone_transition_seal::{TransitionKind, TransitionSeal};
use crate::storage::rocks::{StorageEngine, CF_TRANSITIONS_FINAL};

/// Hard cap on seals read from [`CF_TRANSITIONS_FINAL`] during
/// [`rebuild_from_finalized`]. At 1M zones × ~O(1) lifetime splits/merges
/// per zone, total finalized seals stays well under 10M. This cap catches
/// runaway corruption (repeated near-identical entries) without ever
/// blocking a healthy fleet. If the cap is reached, the rebuild returns
/// what it has and callers should trigger snapshot-based recovery.
pub const MAX_REPLAY_SEALS: usize = 10_000_000;

/// State of a single zone in the registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ZoneEntry {
    /// Zone is a currently active leaf — records route to it, committees
    /// draw against it.
    Active,
    /// Zone has been split at `effective_epoch` into two children along
    /// `split_key`. Accounts with `account_hash < split_key` → `child_low`;
    /// accounts with `account_hash >= split_key` → `child_high`.
    Split {
        effective_epoch: u64,
        split_key: [u8; 32],
        child_low: ZoneId,
        child_high: ZoneId,
    },
    /// Zone has been merged into `merged_into` (alongside `peer`) at
    /// `effective_epoch`. Resolution follows the `merged_into` pointer.
    Merged {
        effective_epoch: u64,
        peer: ZoneId,
        merged_into: ZoneId,
    },
}

impl ZoneEntry {
    pub fn is_active(&self) -> bool {
        matches!(self, ZoneEntry::Active)
    }

    pub fn effective_epoch(&self) -> Option<u64> {
        match self {
            ZoneEntry::Active => None,
            ZoneEntry::Split { effective_epoch, .. }
            | ZoneEntry::Merged { effective_epoch, .. } => Some(*effective_epoch),
        }
    }
}

/// Authoritative zone-tree state.
///
/// The registry tracks every zone that has ever existed and its current
/// status. Construction starts from a set of genesis zones (typically the
/// flat-modulo legacy zones `"0"`..`"ZONE_COUNT-1"`); subsequent
/// split/merge transitions mutate the tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZoneRegistry {
    /// All zones known to the registry, with their current state.
    entries: HashMap<ZoneId, ZoneEntry>,
    /// Fast-path iterator set — contains exactly the zones in `entries`
    /// whose state is [`ZoneEntry::Active`]. Kept in sync with `entries`.
    active: BTreeSet<ZoneId>,
    /// `SHA3-256(canonical_bytes)` of every transition seal applied.
    /// Used to make [`apply_transition`] idempotent on replay.
    applied_seals: HashSet<[u8; 32]>,
    /// Largest `effective_epoch` seen across applied transitions. Not used
    /// for gating (transitions may apply in any order as long as they touch
    /// disjoint subtrees) but exposed for observability / health.
    highest_effective_epoch: u64,
}

impl ZoneRegistry {
    /// Empty registry — no zones yet. Use [`ZoneRegistry::with_genesis`]
    /// to seed initial active zones, or construct via replay.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            active: BTreeSet::new(),
            applied_seals: HashSet::new(),
            highest_effective_epoch: 0,
        }
    }

    /// Registry seeded with a genesis set of active zones.
    ///
    /// At network boot the flat-modulo legacy zones `"0"`..`"ZONE_COUNT-1"`
    /// are the starting leaves; those are what this constructor takes.
    /// Duplicates are tolerated (de-duplicated by the `active` set).
    pub fn with_genesis<I>(zones: I) -> Self
    where
        I: IntoIterator<Item = ZoneId>,
    {
        let mut reg = Self::new();
        for z in zones {
            reg.entries.insert(z.clone(), ZoneEntry::Active);
            reg.active.insert(z);
        }
        reg
    }

    /// Number of zones ever known (active + closed).
    pub fn total_zones(&self) -> usize {
        self.entries.len()
    }

    /// Number of currently active leaf zones.
    pub fn active_count(&self) -> usize {
        self.active.len()
    }

    /// Iterator over currently active leaf zones, in sorted order.
    ///
    /// Gap 5 iterates this for per-zone committee VRF draws. Sorted order
    /// makes the iteration deterministic across nodes.
    pub fn active_zones(&self) -> impl Iterator<Item = &ZoneId> {
        self.active.iter()
    }

    /// Look up the entry for a zone. Returns `None` if the zone is
    /// unknown to the registry (never been active, never been a transition
    /// participant).
    pub fn entry(&self, zone: &ZoneId) -> Option<&ZoneEntry> {
        self.entries.get(zone)
    }

    /// Is the zone currently active (a leaf)?
    pub fn is_active(&self, zone: &ZoneId) -> bool {
        self.entries.get(zone).is_some_and(ZoneEntry::is_active)
    }

    /// Highest `effective_epoch` observed across applied transitions. `0`
    /// if no transitions have been applied.
    pub fn highest_effective_epoch(&self) -> u64 {
        self.highest_effective_epoch
    }

    /// Number of distinct transition seals applied (split + merge). Strictly
    /// monotonic — `applied_seals` is an insert-only dedup set (for idempotent
    /// replay) — so this is a faithful version token for `resolve_current_leaf`
    /// routing: it advances iff a transition changed the active-leaf
    /// partition, and never returns to a prior value (unlike
    /// `active_zones().count()`, which a split followed by a merge can net
    /// back). Keys the zone dimension of the staked-anchor view cache.
    pub fn applied_transition_count(&self) -> u64 {
        self.applied_seals.len() as u64
    }

    /// Resolve `start` to its current active leaf, using `routing_key`
    /// (typically an account hash) to disambiguate splits.
    ///
    /// Walks the registry tree. For each hop:
    /// * `Active` → return this zone.
    /// * `Split` → descend into `child_low` or `child_high` based on
    ///   `routing_key < split_key`.
    /// * `Merged` → follow `merged_into` (which itself may have been split
    ///   or merged again).
    ///
    /// If `start` is unknown to the registry, returns `start` unchanged —
    /// the caller's naive routing is treated as the genesis assignment.
    /// This keeps new nodes from rejecting records whose initial zone
    /// simply hasn't been observed yet.
    ///
    /// Bounded by a hard step cap (`MAX_RESOLVE_DEPTH`) so a corrupt
    /// registry (which shouldn't be reachable given apply-time invariants)
    /// can't cause an infinite walk.
    pub fn resolve(&self, start: &ZoneId, routing_key: &[u8; 32]) -> ZoneId {
        const MAX_RESOLVE_DEPTH: usize = 64;
        let mut current = start.clone();
        for _ in 0..MAX_RESOLVE_DEPTH {
            match self.entries.get(&current) {
                None => return current,
                Some(ZoneEntry::Active) => return current,
                Some(ZoneEntry::Split {
                    split_key,
                    child_low,
                    child_high,
                    ..
                }) => {
                    current = if routing_key < split_key {
                        child_low.clone()
                    } else {
                        child_high.clone()
                    };
                }
                Some(ZoneEntry::Merged { merged_into, .. }) => {
                    current = merged_into.clone();
                }
            }
        }
        // Corruption guard. Return whatever we have rather than looping.
        current
    }

    /// Apply a finalized transition seal to the registry.
    ///
    /// Preconditions (caller's responsibility):
    /// * `seal.validate_structure()` has passed.
    /// * Dilithium3 anchor-cosign threshold has been met.
    ///
    /// This function enforces only *state-consistency* invariants: the
    /// zones being closed must be Active, the zones being opened must be
    /// unknown (or Active with no state churn, for idempotent replay), and
    /// the same seal applied twice is a no-op.
    ///
    /// Returns `Ok(())` on first apply, `Ok(())` on idempotent replay of
    /// the exact same seal, and `Err` on any consistency violation.
    pub fn apply_transition(&mut self, seal: &TransitionSeal) -> Result<()> {
        // ZR-2 (2026-07-03 audit): apply_split/apply_merge index seal.parents/
        // seal.children by fixed position (parents[0], children[0], children[1]).
        // validate_structure is only a *documented* precondition, so enforce the
        // exact cardinality here as a hard gate — a malformed seal that reaches
        // this path with the wrong parent/child count must return Err, never
        // panic on an out-of-bounds index.
        match seal.kind {
            TransitionKind::Split => {
                if seal.parents.len() != 1 || seal.children.len() != 2 {
                    return Err(ElaraError::Wire(format!(
                        "zone_registry: split seal must have 1 parent + 2 children (got {}+{})",
                        seal.parents.len(),
                        seal.children.len()
                    )));
                }
            }
            TransitionKind::Merge => {
                if seal.parents.len() != 2 || seal.children.len() != 1 {
                    return Err(ElaraError::Wire(format!(
                        "zone_registry: merge seal must have 2 parents + 1 child (got {}+{})",
                        seal.parents.len(),
                        seal.children.len()
                    )));
                }
            }
        }

        // Hash the seal's canonical bytes to detect replays.
        let seal_hash = seal.seal_hash_for_sig().map_err(|e| {
            ElaraError::Wire(format!("zone_registry: seal hash failed: {e}"))
        })?;
        if self.applied_seals.contains(&seal_hash) {
            return Ok(());
        }

        match seal.kind {
            TransitionKind::Split => self.apply_split(seal)?,
            TransitionKind::Merge => self.apply_merge(seal)?,
        }

        self.applied_seals.insert(seal_hash);
        if seal.effective_epoch > self.highest_effective_epoch {
            self.highest_effective_epoch = seal.effective_epoch;
        }
        Ok(())
    }

    fn apply_split(&mut self, seal: &TransitionSeal) -> Result<()> {
        // validate_structure guarantees: 1 parent, 2 children, split_key Some.
        let parent = &seal.parents[0].zone_id;
        let child_low = seal.children[0].zone_id.clone();
        let child_high = seal.children[1].zone_id.clone();
        let split_key = seal.split_key.ok_or_else(|| {
            ElaraError::Wire("zone_registry: split seal missing split_key".into())
        })?;

        // Parent must be Active. Anything else is a consistency violation.
        match self.entries.get(parent) {
            Some(ZoneEntry::Active) => {}
            Some(other) => {
                return Err(ElaraError::Wire(format!(
                    "zone_registry: split parent {parent} not active (is {other:?})"
                )));
            }
            None => {
                return Err(ElaraError::Wire(format!(
                    "zone_registry: split parent {parent} unknown to registry"
                )));
            }
        }

        // Children must be currently unknown. A split that tried to open
        // an existing zone would collide with prior state.
        for child in [&child_low, &child_high] {
            if self.entries.contains_key(child) {
                return Err(ElaraError::Wire(format!(
                    "zone_registry: split child {child} already known"
                )));
            }
        }

        // Children must be distinct.
        if child_low == child_high {
            return Err(ElaraError::Wire(
                "zone_registry: split children must be distinct".into(),
            ));
        }

        // Apply: parent → Split; children → Active.
        self.entries.insert(
            parent.clone(),
            ZoneEntry::Split {
                effective_epoch: seal.effective_epoch,
                split_key,
                child_low: child_low.clone(),
                child_high: child_high.clone(),
            },
        );
        self.active.remove(parent);
        self.entries.insert(child_low.clone(), ZoneEntry::Active);
        self.active.insert(child_low);
        self.entries.insert(child_high.clone(), ZoneEntry::Active);
        self.active.insert(child_high);
        Ok(())
    }

    fn apply_merge(&mut self, seal: &TransitionSeal) -> Result<()> {
        // validate_structure guarantees: 2 parents, 1 child, parents distinct.
        let parent_a = &seal.parents[0].zone_id;
        let parent_b = &seal.parents[1].zone_id;
        let child = seal.children[0].zone_id.clone();

        for p in [parent_a, parent_b] {
            match self.entries.get(p) {
                Some(ZoneEntry::Active) => {}
                Some(other) => {
                    return Err(ElaraError::Wire(format!(
                        "zone_registry: merge parent {p} not active (is {other:?})"
                    )));
                }
                None => {
                    return Err(ElaraError::Wire(format!(
                        "zone_registry: merge parent {p} unknown to registry"
                    )));
                }
            }
        }

        // If `child` already exists (e.g., the merged-into zone is one of
        // the parents), reject — seals must open a fresh child.
        if self.entries.contains_key(&child) {
            return Err(ElaraError::Wire(format!(
                "zone_registry: merge child {child} already known"
            )));
        }

        // Apply.
        self.entries.insert(
            parent_a.clone(),
            ZoneEntry::Merged {
                effective_epoch: seal.effective_epoch,
                peer: parent_b.clone(),
                merged_into: child.clone(),
            },
        );
        self.entries.insert(
            parent_b.clone(),
            ZoneEntry::Merged {
                effective_epoch: seal.effective_epoch,
                peer: parent_a.clone(),
                merged_into: child.clone(),
            },
        );
        self.active.remove(parent_a);
        self.active.remove(parent_b);
        self.entries.insert(child.clone(), ZoneEntry::Active);
        self.active.insert(child);
        Ok(())
    }
}

impl Default for ZoneRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Boot-time rebuild from durable storage ─────────────────────────────────

/// Summary of a [`rebuild_from_finalized`] pass. Every field is cheap to
/// serialize — intended for /health or /stats surfacing so operators can
/// confirm the registry came up coherent after a restart.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebuildStats {
    /// Total rows read from [`CF_TRANSITIONS_FINAL`], including any that
    /// later failed to decode or apply.
    pub seals_read: usize,
    /// Seals that decoded AND applied cleanly.
    pub seals_applied: usize,
    /// Seals whose stored bytes failed JSON deserialization. A non-zero
    /// value indicates on-disk corruption and should page an operator.
    pub seals_skipped_decode: usize,
    /// Seals that decoded but failed [`ZoneRegistry::apply_transition`]
    /// (consistency violation). Stored as `(hex_id, error_message)` so
    /// operators can track the specific offender. Should be zero on a
    /// coherent fleet — seals land in [`CF_TRANSITIONS_FINAL`] only
    /// after clearing M-of-N cosign + dispute window, so any non-zero
    /// tail is either a bug in the apply logic or two seals racing for
    /// the same parent zone (which the orchestrator must have prevented
    /// upstream).
    pub seals_skipped_apply: Vec<(String, String)>,
    /// Gap 4 close-out: seals that decoded but failed the M-of-N
    /// Dilithium3 verify against the locally-registered anchor pubkey
    /// set (`CF_IDENTITIES`). Stored as `(hex_id, error_message)`.
    /// Expected empty on nodes that only finalized seals after the
    /// close-out commit shipped; non-empty means old unverified seals
    /// from before the gate landed — those must NOT be replayed into
    /// the live registry regardless of how they got onto disk.
    pub seals_skipped_sig_verify: Vec<(String, String)>,
    /// Whether the [`MAX_REPLAY_SEALS`] ceiling was hit. True means the
    /// CF contained more rows than we read — registry is incomplete and
    /// caller should fall back to a snapshot-driven path.
    pub truncated: bool,
}

/// Rebuild a [`ZoneRegistry`] from `CF_TRANSITIONS_FINAL`.
///
/// Used at boot to re-hydrate the registry without a snapshot. Reads every
/// finalized seal, sorts by `effective_epoch` ascending (with `seal_hash`
/// as the tiebreaker so the sort is total and deterministic across nodes),
/// and applies each in order starting from the supplied genesis zones.
///
/// Fault tolerance:
/// * Seals that fail to deserialize are counted in
///   [`RebuildStats::seals_skipped_decode`] and skipped — one corrupt row
///   must not stop boot.
/// * Seals that decode but whose `apply_transition` errors are counted in
///   [`RebuildStats::seals_skipped_apply`] with the error message so
///   operators can dig in. They too are skipped to keep boot progressing.
///
/// Scale: O(N × log N) in the number of finalized seals (the sort). Caller
/// receives the partial registry even when some seals were skipped so the
/// node can still serve routing for the zones it did successfully rebuild.
///
/// Transitions-F1 boot-trust basis (deliberate — do NOT add a live-stake
/// gate here): the staked-anchor gate runs at ingest (`verify_anchor_sig`)
/// and at the finalize tick (`run_transition_tick` pubkey pre-filter), and
/// that tick is the ONLY production writer of `CF_TRANSITIONS_FINAL` — so
/// presence in the CF already proves the seal passed the stake gate at
/// finalize time. Re-checking LIVE stake at boot would let a
/// post-finalization unstake retroactively drop a legitimately-finalized
/// transition on the next reboot while non-rebooted nodes keep it — a
/// permanent ZoneRegistry fork (the registry is never cross-node
/// reconciled). F1 audit 2026-07-05 §5 MISS-2: boot trust = CF presence,
/// fail-closed and fork-free. The M-of-N Dilithium3 re-verify below still
/// runs — crypto validity is stable across time; stake is not.
pub fn rebuild_from_finalized<I>(
    storage: &StorageEngine,
    genesis_zones: I,
) -> Result<(ZoneRegistry, RebuildStats)>
where
    I: IntoIterator<Item = ZoneId>,
{
    let mut stats = RebuildStats::default();
    let mut registry = ZoneRegistry::with_genesis(genesis_zones);

    // Read every row under MAX_REPLAY_SEALS. list_cf_raw stops when the
    // internal Vec hits `limit`, so we ask for one-past-the-cap and then
    // check whether the cap was met; that's how we detect truncation
    // without needing a separate count.
    let rows = storage.list_cf_raw(CF_TRANSITIONS_FINAL, MAX_REPLAY_SEALS + 1)?;
    stats.truncated = rows.len() > MAX_REPLAY_SEALS;
    let rows: Vec<_> = if stats.truncated {
        rows.into_iter().take(MAX_REPLAY_SEALS).collect()
    } else {
        rows
    };
    stats.seals_read = rows.len();

    // Decode all seals first. Failed decodes are counted and dropped.
    let mut decoded: Vec<([u8; 32], TransitionSeal)> = Vec::with_capacity(rows.len());
    for (key, val) in rows {
        let mut id = [0u8; 32];
        if key.len() != 32 {
            // Malformed key — shouldn't happen, CF keys are always 32 bytes.
            stats.seals_skipped_decode += 1;
            continue;
        }
        id.copy_from_slice(&key);
        match serde_json::from_slice::<TransitionSeal>(&val) {
            Ok(seal) => decoded.push((id, seal)),
            Err(_) => stats.seals_skipped_decode += 1,
        }
    }

    // Sort by (effective_epoch ASC, seal_id ASC). Tiebreaker keeps the
    // apply order deterministic across nodes even if two seals share an
    // effective_epoch — otherwise a second-level split whose parent was
    // created in the same epoch could apply before its parent, raising
    // "unknown parent" needlessly.
    decoded.sort_by(|(id_a, a), (id_b, b)| {
        a.effective_epoch
            .cmp(&b.effective_epoch)
            .then_with(|| id_a.cmp(id_b))
    });

    for (id, seal) in &decoded {
        // Gap 4 close-out: gate on M-of-N anchor-sig verify BEFORE apply.
        // A seal that reached CF_TRANSITIONS_FINAL before the tick-time
        // verify gate shipped (2026-04-21) could otherwise flip routing
        // at boot without ever having been cryptographically checked.
        let mut anchor_pubkeys: std::collections::HashMap<[u8; 32], Vec<u8>> =
            std::collections::HashMap::with_capacity(seal.proposer_sigs.len());
        for sig in &seal.proposer_sigs {
            let hex_key = hex::encode(sig.anchor_identity_hash);
            if let Some(pk) = storage.get_public_key(&hex_key) {
                anchor_pubkeys.insert(sig.anchor_identity_hash, pk);
            }
        }
        if let Err(e) = seal.verify_sigs(&anchor_pubkeys, seal.required_threshold()) {
            stats
                .seals_skipped_sig_verify
                .push((hex::encode(id), format!("{e}")));
            continue;
        }
        match registry.apply_transition(seal) {
            Ok(()) => stats.seals_applied += 1,
            Err(e) => stats
                .seals_skipped_apply
                .push((hex::encode(id), format!("{e}"))),
        }
    }

    Ok((registry, stats))
}

// ─── Gap 4 routing close-out: resolve naive → current leaf ──────────────────

/// Outcome of a routing-resolve query.
///
/// Surfaced by the `/routing/resolve` RPC and by the underlying
/// [`resolve_current_leaf`] helper so operators, clients, and integration
/// tests can reason about post-split routing without re-implementing the
/// walk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutingResolution {
    /// Naive flat-modulo zone that a legacy `zone_for_record` call would
    /// have returned for this record_id.
    pub naive_zone: ZoneId,
    /// Current leaf zone after walking the registry's split/merge tree
    /// with the supplied routing key.
    pub resolved_zone: ZoneId,
    /// `true` iff `resolved_zone != naive_zone` — i.e., at least one
    /// split or merge hop was taken.
    pub redirected: bool,
}

/// Pure helper — given a naive starting zone and a 32-byte routing key
/// (typically `sha3(identity_hash)` for stable per-account routing under
/// splits), return the current leaf plus a redirected-flag for observability.
///
/// Does not read or mutate any shared state; the caller holds the
/// [`ZoneRegistry`] reference. HTTP handlers wrap this and bump counters.
pub fn resolve_current_leaf(
    registry: &ZoneRegistry,
    naive: &ZoneId,
    routing_key: &[u8; 32],
) -> RoutingResolution {
    let resolved = registry.resolve(naive, routing_key);
    let redirected = resolved != *naive;
    RoutingResolution {
        naive_zone: naive.clone(),
        resolved_zone: resolved,
        redirected,
    }
}

/// Derive a stable 32-byte routing key from a record_id.
///
/// Records route through the registry by `sha3_256(record_id)` — the same
/// input space as the naive flat-modulo [`super::consensus::zone_for_record`]
/// (which collapses to a small zone count via modulo). Using the full 256-bit
/// digest as the routing key means records with the same record_id always
/// route to the same leaf, even after multi-level splits.
pub fn routing_key_for_record(record_id: &str) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(record_id.as_bytes());
    h.finalize().into()
}

/// Derive a stable 32-byte routing key from a hex-encoded identity hash.
///
/// Identity hashes are already canonical SHA-3-256 digests of public keys,
/// so the decoded 32 bytes ARE the routing key — hashing again would just
/// reshuffle the split tree for no benefit and break alignment with the
/// flat-modulo zone that [`super::consensus::zone_for_record(identity_hex)`]
/// returns. If the input is not 32 bytes of valid hex, fall back to hashing
/// the raw string so the function is total (malformed input still routes
/// deterministically — it just doesn't align with the fast path).
pub fn routing_key_for_identity(identity_hex: &str) -> [u8; 32] {
    if let Ok(bytes) = hex::decode(identity_hex) {
        if bytes.len() == 32 {
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes);
            return out;
        }
    }
    routing_key_for_record(identity_hex)
}

// ─── Registry snapshot CF helpers (forward-looking) ─────────────────────────
//
// The rebuild path above is O(N × log N) in the finalized seal count. At
// current fleet scale (N small) this is fine — boot-replay cost is
// measured in microseconds. When the snapshot-optimization becomes
// worthwhile, add a dedicated snapshot CF and write/read helpers here;
// the registry already serializes cleanly via serde.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::zone_transition_seal::{
        newborn_child_snapshot, TransitionSeal, ZoneSnapshot, TRANSITION_DISPUTE_WINDOW_EPOCHS,
    };

    // ─── Helpers ─────────────────────────────────────────────────────────────

    fn parent_snapshot(zone: ZoneId) -> ZoneSnapshot {
        ZoneSnapshot {
            zone_id: zone,
            state_root: [0u8; 32],
            last_seal_record_id: String::new(),
            record_count: 0,
            committee_hash: [0u8; 32],
        }
    }

    fn make_split_seal(
        parent: ZoneId,
        child_low: ZoneId,
        child_high: ZoneId,
        split_key: [u8; 32],
        effective_epoch: u64,
    ) -> TransitionSeal {
        TransitionSeal {
            kind: TransitionKind::Split,
            effective_epoch,
            proposed_at_epoch: effective_epoch - TRANSITION_DISPUTE_WINDOW_EPOCHS,
            parents: vec![parent_snapshot(parent)],
            children: vec![
                newborn_child_snapshot(child_low, [1u8; 32]),
                newborn_child_snapshot(child_high, [2u8; 32]),
            ],
            split_key: Some(split_key),
            proposer_sigs: vec![],
        }
    }

    fn make_merge_seal(
        parent_a: ZoneId,
        parent_b: ZoneId,
        child: ZoneId,
        effective_epoch: u64,
    ) -> TransitionSeal {
        TransitionSeal {
            kind: TransitionKind::Merge,
            effective_epoch,
            proposed_at_epoch: effective_epoch - TRANSITION_DISPUTE_WINDOW_EPOCHS,
            parents: vec![parent_snapshot(parent_a), parent_snapshot(parent_b)],
            children: vec![newborn_child_snapshot(child, [3u8; 32])],
            split_key: None,
            proposer_sigs: vec![],
        }
    }

    fn key_from_byte(b: u8) -> [u8; 32] {
        let mut k = [0u8; 32];
        k[0] = b;
        k
    }

    // ─── Core construction ───────────────────────────────────────────────────

    #[test]
    fn new_registry_is_empty() {
        let r = ZoneRegistry::new();
        assert_eq!(r.total_zones(), 0);
        assert_eq!(r.active_count(), 0);
        assert_eq!(r.highest_effective_epoch(), 0);
    }

    #[test]
    fn genesis_seeds_active_zones() {
        let r = ZoneRegistry::with_genesis(vec![
            ZoneId::from_legacy(0),
            ZoneId::from_legacy(1),
            ZoneId::from_legacy(2),
        ]);
        assert_eq!(r.active_count(), 3);
        assert!(r.is_active(&ZoneId::from_legacy(0)));
        assert!(r.is_active(&ZoneId::from_legacy(1)));
        assert!(r.is_active(&ZoneId::from_legacy(2)));
        assert!(!r.is_active(&ZoneId::from_legacy(3)));
    }

    #[test]
    fn genesis_dedupes_duplicates() {
        let r = ZoneRegistry::with_genesis(vec![
            ZoneId::from_legacy(0),
            ZoneId::from_legacy(0),
            ZoneId::from_legacy(1),
        ]);
        assert_eq!(r.active_count(), 2);
    }

    // ─── Resolution on a bare registry ───────────────────────────────────────

    #[test]
    fn resolve_unknown_zone_returns_start() {
        let r = ZoneRegistry::new();
        let start = ZoneId::from_legacy(42);
        assert_eq!(r.resolve(&start, &[0u8; 32]), start);
    }

    #[test]
    fn resolve_active_zone_returns_itself() {
        let r = ZoneRegistry::with_genesis(vec![ZoneId::from_legacy(7)]);
        let start = ZoneId::from_legacy(7);
        assert_eq!(r.resolve(&start, &[0u8; 32]), start);
    }

    // ─── Split apply + resolve ───────────────────────────────────────────────

    #[test]
    fn apply_split_transitions_parent_to_split() {
        let mut r =
            ZoneRegistry::with_genesis(vec![ZoneId::from_legacy(0)]);
        let seal = make_split_seal(
            ZoneId::from_legacy(0),
            ZoneId::new("0/a"),
            ZoneId::new("0/b"),
            key_from_byte(0x80),
            5,
        );
        r.apply_transition(&seal).unwrap();

        // Parent demoted, both children active.
        assert!(!r.is_active(&ZoneId::from_legacy(0)));
        assert!(r.is_active(&ZoneId::new("0/a")));
        assert!(r.is_active(&ZoneId::new("0/b")));
        assert_eq!(r.active_count(), 2);
        assert_eq!(r.highest_effective_epoch(), 5);

        match r.entry(&ZoneId::from_legacy(0)).unwrap() {
            ZoneEntry::Split { split_key, child_low, child_high, effective_epoch } => {
                assert_eq!(*effective_epoch, 5);
                assert_eq!(*split_key, key_from_byte(0x80));
                assert_eq!(child_low, &ZoneId::new("0/a"));
                assert_eq!(child_high, &ZoneId::new("0/b"));
            }
            other => panic!("expected Split, got {other:?}"),
        }
    }

    #[test]
    fn ops_39_total_zones_minus_active_count_equals_closed_zones() {
        // Codifies the operator dashboard rule for the new
        // `elara_zone_registry_active_zones` and `_total_zones` gauges.
        // `total_zones - active_zones` must equal the number of historically
        // closed zones (split parents + merged-into intermediates). After
        // each split: +1 parent moves from Active → Split (still in entries
        // but not in active), +2 children land in both. Net: total +2,
        // active +1, so the gap grows by exactly one per split.
        let mut r = ZoneRegistry::with_genesis(vec![
            ZoneId::from_legacy(0),
            ZoneId::from_legacy(1),
        ]);
        // Genesis: no closures yet.
        assert_eq!(r.total_zones(), 2);
        assert_eq!(r.active_count(), 2);
        assert_eq!(
            r.total_zones() - r.active_count(),
            0,
            "fresh registry has no closed zones"
        );

        // Split zone 0 into 0/a + 0/b: parent moves to Split, children Active.
        r.apply_transition(&make_split_seal(
            ZoneId::from_legacy(0),
            ZoneId::new("0/a"),
            ZoneId::new("0/b"),
            key_from_byte(0x80),
            5,
        ))
        .unwrap();
        assert_eq!(r.total_zones(), 4, "0 + 1 + 0/a + 0/b");
        assert_eq!(r.active_count(), 3, "1 + 0/a + 0/b — parent demoted");
        assert_eq!(
            r.total_zones() - r.active_count(),
            1,
            "exactly one closed zone (the split parent)"
        );

        // Split 0/a too: another parent moves to Split.
        r.apply_transition(&make_split_seal(
            ZoneId::new("0/a"),
            ZoneId::new("0/a/lo"),
            ZoneId::new("0/a/hi"),
            key_from_byte(0x40),
            10,
        ))
        .unwrap();
        assert_eq!(r.total_zones(), 6);
        assert_eq!(r.active_count(), 4);
        assert_eq!(
            r.total_zones() - r.active_count(),
            2,
            "two closed parents (0 and 0/a)"
        );

        // Invariant: total_zones >= active_count, always.
        assert!(
            r.total_zones() >= r.active_count(),
            "total_zones must never be less than active_count"
        );
    }

    #[test]
    fn resolve_split_parent_picks_correct_child() {
        let mut r = ZoneRegistry::with_genesis(vec![ZoneId::from_legacy(0)]);
        r.apply_transition(&make_split_seal(
            ZoneId::from_legacy(0),
            ZoneId::new("0/a"),
            ZoneId::new("0/b"),
            key_from_byte(0x80),
            5,
        ))
        .unwrap();

        let low_key = key_from_byte(0x10);
        let high_key = key_from_byte(0xF0);
        let boundary_key = key_from_byte(0x80); // == split_key → goes high

        assert_eq!(
            r.resolve(&ZoneId::from_legacy(0), &low_key),
            ZoneId::new("0/a")
        );
        assert_eq!(
            r.resolve(&ZoneId::from_legacy(0), &high_key),
            ZoneId::new("0/b")
        );
        assert_eq!(
            r.resolve(&ZoneId::from_legacy(0), &boundary_key),
            ZoneId::new("0/b"),
            "account_hash == split_key must go to child_high"
        );
    }

    #[test]
    fn resolve_recursive_split_descends_multiple_levels() {
        let mut r = ZoneRegistry::with_genesis(vec![ZoneId::from_legacy(0)]);
        // First split: 0 → 0/a (< 0x80) + 0/b (>= 0x80)
        r.apply_transition(&make_split_seal(
            ZoneId::from_legacy(0),
            ZoneId::new("0/a"),
            ZoneId::new("0/b"),
            key_from_byte(0x80),
            5,
        ))
        .unwrap();
        // Second split: 0/a → 0/a/lo (< 0x40) + 0/a/hi (>= 0x40)
        r.apply_transition(&make_split_seal(
            ZoneId::new("0/a"),
            ZoneId::new("0/a/lo"),
            ZoneId::new("0/a/hi"),
            key_from_byte(0x40),
            8,
        ))
        .unwrap();

        assert_eq!(r.active_count(), 3);
        assert_eq!(r.highest_effective_epoch(), 8);

        // Key 0x10 → < 0x80 → 0/a → < 0x40 → 0/a/lo
        assert_eq!(
            r.resolve(&ZoneId::from_legacy(0), &key_from_byte(0x10)),
            ZoneId::new("0/a/lo")
        );
        // Key 0x50 → < 0x80 → 0/a → >= 0x40 → 0/a/hi
        assert_eq!(
            r.resolve(&ZoneId::from_legacy(0), &key_from_byte(0x50)),
            ZoneId::new("0/a/hi")
        );
        // Key 0xF0 → >= 0x80 → 0/b (still active)
        assert_eq!(
            r.resolve(&ZoneId::from_legacy(0), &key_from_byte(0xF0)),
            ZoneId::new("0/b")
        );
    }

    #[test]
    fn apply_split_on_non_active_parent_errors() {
        let mut r = ZoneRegistry::with_genesis(vec![ZoneId::from_legacy(0)]);
        r.apply_transition(&make_split_seal(
            ZoneId::from_legacy(0),
            ZoneId::new("0/a"),
            ZoneId::new("0/b"),
            key_from_byte(0x80),
            5,
        ))
        .unwrap();

        // Attempt to split zone 0 again — it's already Split.
        let err = r
            .apply_transition(&make_split_seal(
                ZoneId::from_legacy(0),
                ZoneId::new("0/x"),
                ZoneId::new("0/y"),
                key_from_byte(0x80),
                8,
            ))
            .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("not active"), "got: {msg}");
    }

    #[test]
    fn apply_split_on_unknown_parent_errors() {
        let mut r = ZoneRegistry::new();
        let err = r
            .apply_transition(&make_split_seal(
                ZoneId::from_legacy(99),
                ZoneId::new("99/a"),
                ZoneId::new("99/b"),
                key_from_byte(0x80),
                5,
            ))
            .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("unknown"), "got: {msg}");
    }

    #[test]
    fn apply_split_with_colliding_child_errors() {
        let mut r = ZoneRegistry::with_genesis(vec![
            ZoneId::from_legacy(0),
            ZoneId::new("already-here"),
        ]);
        let err = r
            .apply_transition(&make_split_seal(
                ZoneId::from_legacy(0),
                ZoneId::new("already-here"),
                ZoneId::new("0/b"),
                key_from_byte(0x80),
                5,
            ))
            .unwrap_err();
        assert!(format!("{err}").contains("already known"));
    }

    // ─── Merge apply + resolve ───────────────────────────────────────────────

    #[test]
    fn apply_merge_transitions_both_parents() {
        let mut r = ZoneRegistry::with_genesis(vec![
            ZoneId::from_legacy(0),
            ZoneId::from_legacy(1),
        ]);
        let seal = make_merge_seal(
            ZoneId::from_legacy(0),
            ZoneId::from_legacy(1),
            ZoneId::new("merged"),
            5,
        );
        r.apply_transition(&seal).unwrap();

        assert!(!r.is_active(&ZoneId::from_legacy(0)));
        assert!(!r.is_active(&ZoneId::from_legacy(1)));
        assert!(r.is_active(&ZoneId::new("merged")));
        assert_eq!(r.active_count(), 1);
    }

    #[test]
    fn resolve_merged_parent_follows_pointer() {
        let mut r = ZoneRegistry::with_genesis(vec![
            ZoneId::from_legacy(0),
            ZoneId::from_legacy(1),
        ]);
        r.apply_transition(&make_merge_seal(
            ZoneId::from_legacy(0),
            ZoneId::from_legacy(1),
            ZoneId::new("merged"),
            5,
        ))
        .unwrap();

        assert_eq!(
            r.resolve(&ZoneId::from_legacy(0), &[0u8; 32]),
            ZoneId::new("merged")
        );
        assert_eq!(
            r.resolve(&ZoneId::from_legacy(1), &[0u8; 32]),
            ZoneId::new("merged")
        );
    }

    #[test]
    fn resolve_merge_then_split_descends_correctly() {
        let mut r = ZoneRegistry::with_genesis(vec![
            ZoneId::from_legacy(0),
            ZoneId::from_legacy(1),
        ]);
        r.apply_transition(&make_merge_seal(
            ZoneId::from_legacy(0),
            ZoneId::from_legacy(1),
            ZoneId::new("m"),
            5,
        ))
        .unwrap();
        r.apply_transition(&make_split_seal(
            ZoneId::new("m"),
            ZoneId::new("m/lo"),
            ZoneId::new("m/hi"),
            key_from_byte(0x80),
            10,
        ))
        .unwrap();

        // Resolve via the old parent — must walk merge → split → leaf.
        assert_eq!(
            r.resolve(&ZoneId::from_legacy(0), &key_from_byte(0x10)),
            ZoneId::new("m/lo")
        );
        assert_eq!(
            r.resolve(&ZoneId::from_legacy(1), &key_from_byte(0xF0)),
            ZoneId::new("m/hi")
        );
    }

    #[test]
    fn apply_merge_on_non_active_parent_errors() {
        let mut r = ZoneRegistry::with_genesis(vec![
            ZoneId::from_legacy(0),
            ZoneId::from_legacy(1),
        ]);
        r.apply_transition(&make_split_seal(
            ZoneId::from_legacy(0),
            ZoneId::new("0/a"),
            ZoneId::new("0/b"),
            key_from_byte(0x80),
            5,
        ))
        .unwrap();

        // Zone 0 is now Split, can't be merged.
        let err = r
            .apply_transition(&make_merge_seal(
                ZoneId::from_legacy(0),
                ZoneId::from_legacy(1),
                ZoneId::new("merged"),
                8,
            ))
            .unwrap_err();
        assert!(format!("{err}").contains("not active"));
    }

    // ─── Idempotency ─────────────────────────────────────────────────────────

    #[test]
    fn apply_same_seal_twice_is_idempotent() {
        let mut r = ZoneRegistry::with_genesis(vec![ZoneId::from_legacy(0)]);
        let seal = make_split_seal(
            ZoneId::from_legacy(0),
            ZoneId::new("0/a"),
            ZoneId::new("0/b"),
            key_from_byte(0x80),
            5,
        );
        r.apply_transition(&seal).unwrap();
        // Second apply: must not error, must not double-mutate.
        r.apply_transition(&seal).unwrap();
        assert_eq!(r.active_count(), 2);
        assert_eq!(r.total_zones(), 3);
    }

    // ─── Active zones iteration (Gap 5 consumer) ────────────────────────────

    #[test]
    fn active_zones_iteration_is_sorted_and_leaves_only() {
        let mut r = ZoneRegistry::with_genesis(vec![
            ZoneId::from_legacy(0),
            ZoneId::from_legacy(1),
            ZoneId::from_legacy(2),
        ]);
        // Split zone 1 into 1/a + 1/b. Zone 1 should leave the active set,
        // children should enter.
        r.apply_transition(&make_split_seal(
            ZoneId::from_legacy(1),
            ZoneId::new("1/a"),
            ZoneId::new("1/b"),
            key_from_byte(0x80),
            5,
        ))
        .unwrap();

        let leaves: Vec<_> = r.active_zones().cloned().collect();
        assert_eq!(leaves.len(), 4);
        // Sorted order (ZoneId is Ord by path string):
        // "0", "1/a", "1/b", "2"
        assert_eq!(leaves[0], ZoneId::from_legacy(0));
        assert_eq!(leaves[1], ZoneId::new("1/a"));
        assert_eq!(leaves[2], ZoneId::new("1/b"));
        assert_eq!(leaves[3], ZoneId::from_legacy(2));

        // None of the returned leaves should be the Split parent.
        for z in &leaves {
            assert!(r.is_active(z));
        }
    }

    // ─── Serde round-trip (persistence prep) ────────────────────────────────

    // ─── Boot rebuild from CF_TRANSITIONS_FINAL ─────────────────────────────

    fn test_storage() -> (StorageEngine, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let engine = StorageEngine::open(dir.path()).unwrap();
        (engine, dir)
    }

    fn persist_seal(storage: &StorageEngine, seal: &TransitionSeal) -> [u8; 32] {
        // Gap 4 close-out: `rebuild_from_finalized` now gates on
        // `verify_sigs`. Tests that used to hand-craft bare seals must
        // attach threshold-many valid sigs AND register the anchor
        // pubkeys in `CF_IDENTITIES` so the rebuild's inline lookup
        // resolves them. Signs a *clone* so the caller's seal stays
        // immutable (some tests assert against the original).
        let mut signed = seal.clone();
        sign_seal_threshold(storage, &mut signed);
        let id = signed.seal_hash_for_sig().unwrap();
        let bytes = serde_json::to_vec(&signed).unwrap();
        storage
            .put_cf_raw(CF_TRANSITIONS_FINAL, &id, &bytes)
            .unwrap();
        id
    }

    /// Gap 4 close-out test helper: attach `required_threshold()`
    /// valid Dilithium3 sigs to a seal AND register each signing
    /// anchor's pubkey in `storage` (`CF_IDENTITIES`) so
    /// `rebuild_from_finalized`'s verify step resolves them.
    ///
    /// Mirrors the production-side helper in
    /// `health.rs::tests::sign_seal_for_test`.
    fn sign_seal_threshold(storage: &StorageEngine, seal: &mut TransitionSeal) {
        use crate::crypto::hash::sha3_256;
        use crate::crypto::pqc::{dilithium3_keygen, dilithium3_sign_with_pk};
        use crate::network::zone_transition_seal::AnchorSig;

        let hash = seal.seal_hash_for_sig().expect("seal hash");
        let threshold = seal.required_threshold();
        let mut sigs: Vec<AnchorSig> = Vec::with_capacity(threshold);
        for _ in 0..threshold {
            let kp = dilithium3_keygen().expect("keygen");
            let id = sha3_256(&kp.public_key);
            storage
                .store_public_key_anchor(&hex::encode(id), &kp.public_key)
                .expect("register anchor pubkey");
            let sig = dilithium3_sign_with_pk(&hash, &kp.secret_key, &kp.public_key)
                .expect("sign");
            sigs.push(AnchorSig {
                anchor_identity_hash: id,
                dilithium3_sig: sig,
            });
        }
        sigs.sort_by_key(|s| s.anchor_identity_hash);
        seal.proposer_sigs = sigs;
    }

    #[test]
    fn rebuild_empty_cf_yields_genesis_only() {
        let (storage, _dir) = test_storage();
        let (registry, stats) = rebuild_from_finalized(
            &storage,
            vec![ZoneId::from_legacy(0), ZoneId::from_legacy(1)],
        )
        .unwrap();

        assert_eq!(stats.seals_read, 0);
        assert_eq!(stats.seals_applied, 0);
        assert!(stats.seals_skipped_apply.is_empty());
        assert!(!stats.truncated);
        assert_eq!(registry.active_count(), 2);
        assert_eq!(registry.highest_effective_epoch(), 0);
    }

    #[test]
    fn rebuild_applies_single_finalized_split() {
        let (storage, _dir) = test_storage();
        let seal = make_split_seal(
            ZoneId::from_legacy(0),
            ZoneId::new("0/a"),
            ZoneId::new("0/b"),
            key_from_byte(0x80),
            5,
        );
        persist_seal(&storage, &seal);

        let (registry, stats) =
            rebuild_from_finalized(&storage, vec![ZoneId::from_legacy(0)]).unwrap();

        assert_eq!(stats.seals_read, 1);
        assert_eq!(stats.seals_applied, 1);
        assert_eq!(stats.seals_skipped_decode, 0);
        assert!(stats.seals_skipped_apply.is_empty());
        assert_eq!(registry.active_count(), 2);
        assert!(registry.is_active(&ZoneId::new("0/a")));
        assert!(registry.is_active(&ZoneId::new("0/b")));
    }

    #[test]
    fn rebuild_sorts_by_effective_epoch_not_insert_order() {
        // Persist in reverse chronological order — the second-level split
        // lands in the CF BEFORE the first-level split. A naive iterator
        // would try to split `0/a` before it exists. The rebuild's sort
        // must put the earlier-effective seal first regardless of CF scan
        // order.
        let (storage, _dir) = test_storage();

        let seal_level2 = make_split_seal(
            ZoneId::new("0/a"),
            ZoneId::new("0/a/lo"),
            ZoneId::new("0/a/hi"),
            key_from_byte(0x40),
            8,
        );
        let seal_level1 = make_split_seal(
            ZoneId::from_legacy(0),
            ZoneId::new("0/a"),
            ZoneId::new("0/b"),
            key_from_byte(0x80),
            5,
        );
        // Write level-2 first — RocksDB scan order is key-ordered, not
        // insert-ordered, so this doesn't directly force a bad order in
        // the CF. But this test still exercises the sort: we prove the
        // rebuild doesn't depend on either insertion order.
        persist_seal(&storage, &seal_level2);
        persist_seal(&storage, &seal_level1);

        let (registry, stats) =
            rebuild_from_finalized(&storage, vec![ZoneId::from_legacy(0)]).unwrap();

        assert_eq!(stats.seals_applied, 2);
        assert!(stats.seals_skipped_apply.is_empty());
        assert_eq!(registry.active_count(), 3);
        assert!(registry.is_active(&ZoneId::new("0/a/lo")));
        assert!(registry.is_active(&ZoneId::new("0/a/hi")));
        assert!(registry.is_active(&ZoneId::new("0/b")));
        assert_eq!(registry.highest_effective_epoch(), 8);

        // Resolution through the old parent should now reach the grandchild.
        assert_eq!(
            registry.resolve(&ZoneId::from_legacy(0), &key_from_byte(0x10)),
            ZoneId::new("0/a/lo")
        );
    }

    #[test]
    fn rebuild_skips_corrupt_bytes_but_applies_others() {
        let (storage, _dir) = test_storage();

        // Good seal.
        let good = make_split_seal(
            ZoneId::from_legacy(0),
            ZoneId::new("0/a"),
            ZoneId::new("0/b"),
            key_from_byte(0x80),
            5,
        );
        persist_seal(&storage, &good);

        // Corrupt row: 32-byte key so decode is attempted, but value is
        // not valid JSON for TransitionSeal.
        let corrupt_key = [0xee; 32];
        storage
            .put_cf_raw(CF_TRANSITIONS_FINAL, &corrupt_key, b"{not-a-seal")
            .unwrap();

        // Malformed key (short) — counted as decode skip even before JSON.
        storage
            .put_cf_raw(CF_TRANSITIONS_FINAL, b"short", b"irrelevant")
            .unwrap();

        let (registry, stats) =
            rebuild_from_finalized(&storage, vec![ZoneId::from_legacy(0)]).unwrap();

        assert_eq!(stats.seals_read, 3);
        assert_eq!(stats.seals_applied, 1);
        assert_eq!(stats.seals_skipped_decode, 2);
        assert!(stats.seals_skipped_apply.is_empty());
        assert!(!stats.truncated);
        // Registry still reflects the good seal.
        assert!(registry.is_active(&ZoneId::new("0/a")));
    }

    #[test]
    fn rebuild_skip_apply_records_error_for_unknown_parent() {
        // A finalized seal whose parent zone isn't in the genesis set (and
        // isn't created by a preceding seal) should be reported in
        // seals_skipped_apply rather than poisoning the whole boot. In a
        // coherent fleet this never fires — the orchestrator only
        // finalizes seals whose parent is known — but the rebuild is
        // defensive so a single stray CF row can't crash the node.
        let (storage, _dir) = test_storage();
        let orphan = make_split_seal(
            ZoneId::new("does-not-exist"),
            ZoneId::new("does-not-exist/a"),
            ZoneId::new("does-not-exist/b"),
            key_from_byte(0x80),
            5,
        );
        persist_seal(&storage, &orphan);

        let (registry, stats) =
            rebuild_from_finalized(&storage, vec![ZoneId::from_legacy(0)]).unwrap();

        assert_eq!(stats.seals_read, 1);
        assert_eq!(stats.seals_applied, 0);
        assert_eq!(stats.seals_skipped_apply.len(), 1);
        assert!(stats.seals_skipped_apply[0].1.contains("unknown"));
        // Genesis zone still active.
        assert!(registry.is_active(&ZoneId::from_legacy(0)));
    }

    /// Gap 4 close-out: `rebuild_from_finalized` rejects seals whose
    /// M-of-N Dilithium3 sigs don't meet the threshold against the
    /// local anchor pubkey registry. The seal must be counted in
    /// `seals_skipped_sig_verify` and must NOT mutate the rebuilt
    /// registry. Protects the boot path against pre-close-out CF
    /// entries that were persisted without verification.
    #[test]
    fn rebuild_rejects_unsigned_seal_in_sig_verify() {
        let (storage, _dir) = test_storage();

        // Write an UNSIGNED seal directly to CF, bypassing persist_seal.
        // This simulates a seal that landed on disk before the sig
        // verify gate shipped — or a malicious CF injection.
        let seal = make_split_seal(
            ZoneId::from_legacy(0),
            ZoneId::new("0/a"),
            ZoneId::new("0/b"),
            key_from_byte(0x80),
            5,
        );
        assert!(seal.proposer_sigs.is_empty(), "precondition: unsigned");
        let id = seal.seal_hash_for_sig().unwrap();
        let bytes = serde_json::to_vec(&seal).unwrap();
        storage
            .put_cf_raw(CF_TRANSITIONS_FINAL, &id, &bytes)
            .unwrap();

        let (registry, stats) =
            rebuild_from_finalized(&storage, vec![ZoneId::from_legacy(0)]).unwrap();

        assert_eq!(stats.seals_read, 1);
        assert_eq!(stats.seals_applied, 0, "unsigned seal must NOT apply");
        assert!(
            stats.seals_skipped_apply.is_empty(),
            "must fail at sig-verify step, not apply step"
        );
        assert_eq!(
            stats.seals_skipped_sig_verify.len(),
            1,
            "unsigned seal must be counted in sig-verify skips"
        );
        assert_eq!(stats.seals_skipped_sig_verify[0].0, hex::encode(id));

        // Registry still shows only the genesis zone — tree untouched.
        assert!(registry.is_active(&ZoneId::from_legacy(0)));
        assert!(!registry.is_active(&ZoneId::new("0/a")));
        assert!(!registry.is_active(&ZoneId::new("0/b")));
    }

    #[test]
    fn rebuild_matches_incremental_apply() {
        // Building a registry via rebuild_from_finalized must produce the
        // exact same state as applying the same seals to a fresh registry
        // in ascending-effective-epoch order.
        let (storage, _dir) = test_storage();

        let seals = vec![
            make_split_seal(
                ZoneId::from_legacy(0),
                ZoneId::new("0/a"),
                ZoneId::new("0/b"),
                key_from_byte(0x80),
                5,
            ),
            make_split_seal(
                ZoneId::new("0/a"),
                ZoneId::new("0/a/lo"),
                ZoneId::new("0/a/hi"),
                key_from_byte(0x40),
                8,
            ),
            make_merge_seal(
                ZoneId::new("0/a/lo"),
                ZoneId::new("0/a/hi"),
                ZoneId::new("0/a/re"),
                12,
            ),
        ];
        for s in &seals {
            persist_seal(&storage, s);
        }

        let (rebuilt, _stats) =
            rebuild_from_finalized(&storage, vec![ZoneId::from_legacy(0)]).unwrap();

        let mut manual = ZoneRegistry::with_genesis(vec![ZoneId::from_legacy(0)]);
        for s in &seals {
            manual.apply_transition(s).unwrap();
        }

        assert_eq!(rebuilt, manual);
    }

    #[test]
    fn registry_serde_round_trip() {
        let mut r = ZoneRegistry::with_genesis(vec![ZoneId::from_legacy(0)]);
        r.apply_transition(&make_split_seal(
            ZoneId::from_legacy(0),
            ZoneId::new("0/a"),
            ZoneId::new("0/b"),
            key_from_byte(0x80),
            5,
        ))
        .unwrap();

        let bytes = serde_json::to_vec(&r).unwrap();
        let decoded: ZoneRegistry = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded, r);
        // Idempotent replay on decoded registry.
        let seal = make_split_seal(
            ZoneId::from_legacy(0),
            ZoneId::new("0/a"),
            ZoneId::new("0/b"),
            key_from_byte(0x80),
            5,
        );
        let mut d2 = decoded.clone();
        d2.apply_transition(&seal).unwrap();
        assert_eq!(d2, decoded);
    }

    // ─── Gap 4 routing close-out helpers ─────────────────────────────────────

    #[test]
    fn resolve_current_leaf_no_transitions_is_not_redirected() {
        let r = ZoneRegistry::with_genesis(vec![ZoneId::from_legacy(0)]);
        let naive = ZoneId::from_legacy(0);
        let res = resolve_current_leaf(&r, &naive, &[0u8; 32]);
        assert_eq!(res.naive_zone, naive);
        assert_eq!(res.resolved_zone, naive);
        assert!(!res.redirected);
    }

    #[test]
    fn resolve_current_leaf_after_split_flags_redirected() {
        let mut r = ZoneRegistry::with_genesis(vec![ZoneId::from_legacy(0)]);
        r.apply_transition(&make_split_seal(
            ZoneId::from_legacy(0),
            ZoneId::new("0/a"),
            ZoneId::new("0/b"),
            key_from_byte(0x80),
            5,
        ))
        .unwrap();

        // Low-half key → 0/a, should be flagged as redirected.
        let res_low =
            resolve_current_leaf(&r, &ZoneId::from_legacy(0), &key_from_byte(0x10));
        assert_eq!(res_low.naive_zone, ZoneId::from_legacy(0));
        assert_eq!(res_low.resolved_zone, ZoneId::new("0/a"));
        assert!(res_low.redirected);

        // High-half key → 0/b.
        let res_high =
            resolve_current_leaf(&r, &ZoneId::from_legacy(0), &key_from_byte(0xF0));
        assert_eq!(res_high.resolved_zone, ZoneId::new("0/b"));
        assert!(res_high.redirected);
    }

    #[test]
    fn resolve_current_leaf_on_still_active_zone_is_not_redirected() {
        // Genesis with multiple zones, split only zone 0. Resolving a
        // record that naively lands in zone 1 (which is still Active) must
        // NOT be flagged redirected — Gap 4 observability must be precise
        // about what "redirected" means: only reports actual tree-walks.
        let mut r = ZoneRegistry::with_genesis(vec![
            ZoneId::from_legacy(0),
            ZoneId::from_legacy(1),
        ]);
        r.apply_transition(&make_split_seal(
            ZoneId::from_legacy(0),
            ZoneId::new("0/a"),
            ZoneId::new("0/b"),
            key_from_byte(0x80),
            5,
        ))
        .unwrap();

        let res = resolve_current_leaf(&r, &ZoneId::from_legacy(1), &[0x55u8; 32]);
        assert_eq!(res.resolved_zone, ZoneId::from_legacy(1));
        assert!(!res.redirected);
    }

    #[test]
    fn resolve_current_leaf_walks_multi_level_splits() {
        let mut r = ZoneRegistry::with_genesis(vec![ZoneId::from_legacy(0)]);
        r.apply_transition(&make_split_seal(
            ZoneId::from_legacy(0),
            ZoneId::new("0/a"),
            ZoneId::new("0/b"),
            key_from_byte(0x80),
            5,
        ))
        .unwrap();
        r.apply_transition(&make_split_seal(
            ZoneId::new("0/a"),
            ZoneId::new("0/a/lo"),
            ZoneId::new("0/a/hi"),
            key_from_byte(0x40),
            8,
        ))
        .unwrap();

        let res =
            resolve_current_leaf(&r, &ZoneId::from_legacy(0), &key_from_byte(0x10));
        assert_eq!(res.resolved_zone, ZoneId::new("0/a/lo"));
        assert!(res.redirected);
    }

    #[test]
    fn resolve_current_leaf_unknown_start_is_identity() {
        // An unknown start zone returns itself unchanged, not redirected.
        // Matches `ZoneRegistry::resolve` contract: new nodes that haven't
        // seen a seal for a given genesis bucket don't spuriously reject
        // routing for it.
        let r = ZoneRegistry::with_genesis(vec![ZoneId::from_legacy(0)]);
        let stranger = ZoneId::from_legacy(42);
        let res = resolve_current_leaf(&r, &stranger, &[0u8; 32]);
        assert_eq!(res.resolved_zone, stranger);
        assert!(!res.redirected);
    }

    // ─── routing_key_for_record / routing_key_for_identity ─────────────

    #[test]
    fn routing_key_for_record_is_deterministic() {
        // Same input → same key, across calls and across invocations.
        let a = routing_key_for_record("abc123");
        let b = routing_key_for_record("abc123");
        assert_eq!(a, b);
        // Different inputs produce different keys (vanishingly small chance
        // of collision from sha3-256).
        assert_ne!(a, routing_key_for_record("abc124"));
    }

    #[test]
    fn routing_key_for_record_drives_split_walk() {
        // Wire up a single split, compute a routing key from a record_id,
        // and confirm resolve_current_leaf takes the expected branch.
        let mut r = ZoneRegistry::with_genesis(vec![ZoneId::from_legacy(0)]);
        r.apply_transition(&make_split_seal(
            ZoneId::from_legacy(0),
            ZoneId::new("0/lo"),
            ZoneId::new("0/hi"),
            [0x80u8; 32],
            5,
        ))
        .unwrap();

        let record_id = "record-alpha";
        let rk = routing_key_for_record(record_id);
        let naive = ZoneId::from_legacy(0);
        let res = resolve_current_leaf(&r, &naive, &rk);
        // Redirected either way (both 0/lo and 0/hi are leaves; naive zone
        // "0" is no longer active). Branch choice is deterministic by the
        // sha3 digest of the record_id vs the split key.
        assert!(res.redirected);
        assert!(
            res.resolved_zone == ZoneId::new("0/lo") || res.resolved_zone == ZoneId::new("0/hi")
        );
    }

    #[test]
    fn routing_key_for_identity_decodes_hex() {
        // A 32-byte hex identity hash must decode to its raw bytes — any
        // other behavior would misalign with the `identity_hash` fields the
        // rest of the protocol writes into records.
        let hex_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let k = routing_key_for_identity(hex_id);
        let expected = hex::decode(hex_id).unwrap();
        assert_eq!(&k[..], &expected[..]);
    }

    #[test]
    fn routing_key_for_identity_malformed_falls_back() {
        // Non-hex input must still produce a deterministic key, not panic.
        let k1 = routing_key_for_identity("not-hex");
        let k2 = routing_key_for_identity("not-hex");
        assert_eq!(k1, k2);
        // Falls back to sha3(input) — different from the hex-path result.
        assert_eq!(k1, routing_key_for_record("not-hex"));
    }

    // ── MAX_REPLAY_SEALS + ZoneEntry/ZoneRegistry method pins ───
    //
    // Pins five uncovered pure surfaces:
    //
    //   1. `MAX_REPLAY_SEALS` (line 50) — 10M hard cap on
    //      `rebuild_from_finalized`. Sized for 1M-zone × O(1)-lifetime
    //      mainnet; a drift here would either OOM rebuilds or silently
    //      truncate honest histories.
    //
    //   2. `ZoneEntry::is_active()` (line 77) — predicate matches only the
    //      `Active` variant; `Split` and `Merged` return false. Underpins
    //      `ZoneRegistry::is_active` and `active_count`.
    //
    //   3. `ZoneEntry::effective_epoch()` (line 81) — returns `None` for
    //      `Active`, `Some(epoch)` for `Split`/`Merged`. Used by replay
    //      ordering + audit queries.
    //
    //   4. `ZoneRegistry::default()` (line 372) — must equal
    //      `ZoneRegistry::new()` (empty entries, 0 highest_effective_epoch).
    //      `derive(Default)` is NOT used here — the `impl Default` is
    //      hand-written, so the equivalence is a behavioral pin, not a
    //      derive-shape pin.
    //
    //   5. `ZoneRegistry::is_active(&zone)` (line 167) — wiring test:
    //      dispatches through `entry.is_some_and(ZoneEntry::is_active)`.
    //      Unknown zone → false (None.is_some_and = false); active zone →
    //      true; split/merged zone (non-leaf) → false.

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_max_replay_seals_const_pin_strict_10m_seal_safety_cap_value() {
        // Hard cap on seals read from CF_TRANSITIONS_FINAL during
        // `rebuild_from_finalized`. Mainnet sizing (per doc comment):
        // 1M zones × O(1) lifetime splits/merges ≪ 10M.
        // Strict equality on the literal — any change here is a
        // capacity-policy change and must be a deliberate decision.
        assert_eq!(
            MAX_REPLAY_SEALS, 10_000_000,
            "MAX_REPLAY_SEALS must be exactly 10M for the documented 1M-zone fleet headroom"
        );
        // Sanity: the cap MUST exceed any reasonable mainnet bound. The
        // doc comment promises < 10M; this is a tripwire if someone
        // halves the constant without realizing.
        assert!(
            MAX_REPLAY_SEALS >= 1_000_000,
            "cap must comfortably exceed 1M-zone fleet bound"
        );
        // usize storage — pins that the constant is not silently u32 on
        // 32-bit targets (which would overflow at 4.29B and wrap).
        let _typecheck: usize = MAX_REPLAY_SEALS;
    }

    #[test]
    fn batch_b_zone_entry_is_active_predicate_matches_active_variant_only() {
        // Three-variant predicate dispatch. `Active` true, all others
        // false. Locks down the `matches!(self, ZoneEntry::Active)` shape
        // at zone_registry.rs:78.
        let active = ZoneEntry::Active;
        assert!(active.is_active(), "Active variant must be active");

        let split = ZoneEntry::Split {
            effective_epoch: 42,
            split_key: [0x80u8; 32],
            child_low: ZoneId::from_legacy(1),
            child_high: ZoneId::from_legacy(2),
        };
        assert!(!split.is_active(), "Split variant must NOT be active");

        let merged = ZoneEntry::Merged {
            effective_epoch: 99,
            peer: ZoneId::from_legacy(3),
            merged_into: ZoneId::from_legacy(4),
        };
        assert!(!merged.is_active(), "Merged variant must NOT be active");
    }

    #[test]
    fn batch_b_zone_entry_effective_epoch_returns_some_for_split_and_merged_none_for_active() {
        // Active has no transition epoch — None is the semantic
        // "this zone hasn't been transformed".
        let active = ZoneEntry::Active;
        assert_eq!(active.effective_epoch(), None, "Active has no transition epoch");

        // Split + Merged each surface their effective_epoch field.
        let split = ZoneEntry::Split {
            effective_epoch: 1_234,
            split_key: [0xFFu8; 32],
            child_low: ZoneId::from_legacy(10),
            child_high: ZoneId::from_legacy(11),
        };
        assert_eq!(
            split.effective_epoch(),
            Some(1_234),
            "Split must surface its effective_epoch field verbatim"
        );

        let merged = ZoneEntry::Merged {
            effective_epoch: u64::MAX,
            peer: ZoneId::from_legacy(20),
            merged_into: ZoneId::from_legacy(21),
        };
        assert_eq!(
            merged.effective_epoch(),
            Some(u64::MAX),
            "Merged must surface effective_epoch even at u64::MAX (no overflow)"
        );

        // Edge: effective_epoch = 0 is still Some(0), not None.
        let split_zero = ZoneEntry::Split {
            effective_epoch: 0,
            split_key: [0u8; 32],
            child_low: ZoneId::from_legacy(30),
            child_high: ZoneId::from_legacy(31),
        };
        assert_eq!(
            split_zero.effective_epoch(),
            Some(0),
            "epoch == 0 returns Some(0), not None — Active is the only None case"
        );
    }

    #[test]
    fn batch_b_zone_registry_default_equivalent_to_new_empty_entries_zero_epoch() {
        // `impl Default for ZoneRegistry` at line 372 is hand-written
        // (not derived), so equivalence with `ZoneRegistry::new()` is a
        // behavioral pin: changing either constructor must update the
        // other. Total/active/highest_effective_epoch all 0; serde
        // round-trip equality holds across the pair.
        let by_default = ZoneRegistry::default();
        let by_new = ZoneRegistry::new();

        assert_eq!(by_default.total_zones(), 0);
        assert_eq!(by_default.active_count(), 0);
        assert_eq!(by_default.highest_effective_epoch(), 0);
        assert!(by_default.active_zones().next().is_none(), "no active zones");
        assert!(
            by_default.entry(&ZoneId::from_legacy(0)).is_none(),
            "no entries for any legacy zone"
        );

        // Equality between Default and new() — guards against silent
        // drift in either constructor.
        assert_eq!(by_default, by_new, "Default and new() must produce equal registries");
    }

    #[test]
    fn batch_b_zone_registry_is_active_method_unknown_zone_returns_false_dispatches_through_zone_entry() {
        // `ZoneRegistry::is_active(&zone)` wires
        // `self.entries.get(zone).is_some_and(ZoneEntry::is_active)`.
        // Three cases:
        //   (a) unknown zone → entries.get is None → is_some_and = false
        //   (b) active zone → entries.get is Some(Active) → true
        //   (c) split zone (non-leaf) → entries.get is Some(Split{..}) → false
        //
        // Catches a regression where the dispatch is mistakenly inverted
        // or where an unknown zone is treated as active (false positive
        // that would crash committee draws on phantom zones).
        let z_unknown = ZoneId::from_legacy(999);
        let z_active = ZoneId::from_legacy(0);
        let z_to_split = ZoneId::from_legacy(1);

        let mut reg = ZoneRegistry::with_genesis([z_active.clone(), z_to_split.clone()]);

        // (a) Unknown zone — never been seen.
        assert!(
            !reg.is_active(&z_unknown),
            "unknown zone must return false (None.is_some_and = false)"
        );

        // (b) Active zone — genesis seeded.
        assert!(
            reg.is_active(&z_active),
            "genesis-seeded zone must be active"
        );

        // (c) Split zone — mutate to non-leaf state directly via entries
        // map (avoids needing a full TransitionSeal for the predicate
        // pin). Mirrors what `apply_transition` does after a Split:
        // parent entry flips to Split{..}, children become Active.
        let z_child_low = ZoneId::from_legacy(100);
        let z_child_high = ZoneId::from_legacy(101);
        reg.entries.insert(
            z_to_split.clone(),
            ZoneEntry::Split {
                effective_epoch: 7,
                split_key: [0x80u8; 32],
                child_low: z_child_low,
                child_high: z_child_high,
            },
        );
        // active set membership is not touched here — we're pinning the
        // entries-based dispatch path only.
        assert!(
            !reg.is_active(&z_to_split),
            "Split entry must NOT report active — dispatch through ZoneEntry::is_active"
        );
    }
}
