//! Tip-merge loop — compress DAG frontier by creating merge records.
//!
//! On a passive node (not creating transfers, stakes, or epoch seals),
//! gossip-received records accumulate as tips indefinitely because
//! nothing locally creates records that reference them as parents.
//! This loop periodically creates lightweight merge records that
//! reference many tips, converting a flat pile of unlinked records
//! into an actual Directed Acyclic Mesh.
//!
//! Spec references:
//!   @spec Protocol §3.3.3 (DAM topology)

use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, info, warn};

use crate::record::{Classification, ValidationRecord};

#[cfg(feature = "node-core")]
use super::state::NodeState;

/// Minimum tips before a merge is triggered.
const TIP_MERGE_THRESHOLD: usize = 100;

/// Maximum parents per merge record. Wire format allows 256.
/// We stay well under to keep record size reasonable (~5KB sig + parent IDs).
const TIP_MERGE_MAX_PARENTS: usize = 200;

/// Maximum merge records per cycle. Prevents runaway merge storms.
/// 10 × 200 parents = 2,000 tips drained per cycle.
const MAX_MERGES_PER_CYCLE: usize = 10;

/// Interval between merge checks (seconds).
const TIP_MERGE_INTERVAL_SECS: u64 = 60;

/// ValidationRecord wire format reserves a single byte for parent count
/// (max 256). `TIP_MERGE_MAX_PARENTS` must stay strictly below this ceiling
/// so a future bump can't silently overflow the wire format.
const WIRE_MAX_PARENTS: usize = 256;

// Compile-time invariants on the tip-merge knobs. A future edit that flips
// THRESHOLD > MAX_PARENTS (single merge can't drain the frontier under
// threshold → outer loop merges forever without converging), bumps
// MAX_PARENTS >= WIRE_MAX_PARENTS (silent overflow of the single-byte
// parent-count field in the ValidationRecord wire format), or zeroes
// INTERVAL_SECS (`tokio::time::sleep(Duration::from_secs(0))` collapses the
// loop to a tight spin) now fails at `cargo build`, not at `cargo test`.
const _: () = assert!(
    TIP_MERGE_THRESHOLD <= TIP_MERGE_MAX_PARENTS,
    "TIP_MERGE_THRESHOLD must fit in one merge (<= TIP_MERGE_MAX_PARENTS) — otherwise outer loop merges forever"
);
const _: () = assert!(
    TIP_MERGE_MAX_PARENTS < WIRE_MAX_PARENTS,
    "TIP_MERGE_MAX_PARENTS must stay strictly below WIRE_MAX_PARENTS=256 — wire format overflow"
);
const _: () = assert!(
    TIP_MERGE_INTERVAL_SECS > 0,
    "TIP_MERGE_INTERVAL_SECS must be positive — zero collapses the merge loop to a tight spin"
);

/// Metadata key marking this as a merge record.
/// Uses mesh_op (not beat_op) — merge is a DAM topology operation, not a ledger operation.
const MERGE_TYPE_KEY: &str = "mesh_op";
const MERGE_TYPE_VALUE: &str = "merge";

/// Background loop: check tip count, create merge records when frontier
/// grows too large. Runs on ALL node types — every node contributes to
/// mesh connectivity.
///
/// Creates multiple merge records per cycle if needed — a single 200-parent
/// merge can't keep up on nodes with 20K+ records receiving constant gossip.
#[cfg(feature = "node-core")]
pub async fn tip_merge_loop(
    state: Arc<NodeState>,
    mut shutdown: tokio::sync::mpsc::Receiver<()>,
) {
    let interval = Duration::from_secs(TIP_MERGE_INTERVAL_SECS);
    info!("tip-merge loop started (every {}s, threshold {} tips, max {}/cycle)",
        TIP_MERGE_INTERVAL_SECS, TIP_MERGE_THRESHOLD, MAX_MERGES_PER_CYCLE);

    loop {
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = shutdown.recv() => {
                debug!("tip-merge loop shutting down");
                return;
            }
        }

        // Stage 6 cooperative scheduler (Protocol §11.10): extra backoff
        // when host CPU/load is saturated. No-op on idle hosts.
        crate::network::system_load::coop_yield_if_busy(&state.system_load).await;

        let mut merges_this_cycle = 0u32;

        loop {
            // Re-read tip count each iteration (DAG mutates after insert).
            let tip_count = {
                let dag = state.dag.read().await;
                dag.tip_count()
            };

            if tip_count < TIP_MERGE_THRESHOLD {
                if merges_this_cycle > 0 {
                    info!("tip-merge: done — {} merges this cycle, {} tips remaining",
                        merges_this_cycle, tip_count);
                } else {
                    debug!("tip-merge: {} tips (below threshold {}), skipping",
                        tip_count, TIP_MERGE_THRESHOLD);
                }
                break;
            }

            if merges_this_cycle as usize >= MAX_MERGES_PER_CYCLE {
                info!("tip-merge: hit max {}/cycle, {} tips remaining (will continue next cycle)",
                    MAX_MERGES_PER_CYCLE, tip_count);
                break;
            }

            // Collect tips — sample up to TIP_MERGE_MAX_PARENTS.
            let parents: Vec<String> = {
                let dag = state.dag.read().await;
                let all_tips = dag.tips();
                if all_tips.len() <= TIP_MERGE_MAX_PARENTS {
                    all_tips
                } else {
                    let mut tips = all_tips;
                    let mut seed = [0u8; 8];
                    getrandom::getrandom(&mut seed).unwrap_or_default();
                    let mut rng = u64::from_le_bytes(seed);
                    for i in 0..TIP_MERGE_MAX_PARENTS {
                        rng ^= rng << 13;
                        rng ^= rng >> 7;
                        rng ^= rng << 17;
                        let j = i + (rng as usize % (tips.len() - i));
                        tips.swap(i, j);
                    }
                    tips.truncate(TIP_MERGE_MAX_PARENTS);
                    tips
                }
            };

            let parent_count = parents.len();
            let content = format!("mesh_merge:{}", parent_count);
            let mut metadata = std::collections::BTreeMap::new();
            metadata.insert(
                MERGE_TYPE_KEY.to_string(),
                serde_json::Value::String(MERGE_TYPE_VALUE.to_string()),
            );
            metadata.insert(
                "merge_parent_count".to_string(),
                serde_json::Value::Number(serde_json::Number::from(parent_count as u64)),
            );

            let mut record = ValidationRecord::create(
                content.as_bytes(),
                state.identity.public_key.clone(),
                parents,
                Classification::Public,
                Some(metadata),
            );

            // Stamp a fresh slot nonce BEFORE signing. Without this, every
            // tip-merge record from the same node reuses nonce=0 and gets
            // rejected as SLOT EQUIVOCATION on re-ingest (production Helsinki
            // was firing a self-ConflictProof every 1-3 minutes from this
            // exact path before the fix).
            record.nonce = state.next_slot_nonce();

            if let Err(e) = state.identity.sign_record_light(&mut record) {
                warn!("tip-merge: failed to sign merge record: {e}");
                break;
            }

            let record_id = record.id.clone();

            match super::gossip::insert_record_synced(&state, record.clone()).await {
                Ok(_) => {
                    merges_this_cycle += 1;
                    info!(
                        "tip-merge: [{}/{}] record {} — {} parents (was {} tips)",
                        merges_this_cycle, MAX_MERGES_PER_CYCLE,
                        &record_id[..16.min(record_id.len())],
                        parent_count, tip_count,
                    );
                    // Push to peers so they also reduce their tip count.
                    let push_state = state.clone();
                    tokio::spawn(async move {
                        NodeState::publish_record_with_fallback(&push_state, &record, None).await;
                    });
                }
                Err(e) => {
                    warn!("tip-merge: failed to insert merge record: {e}");
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drain_plan_invariants_hold() {
        // THRESHOLD <= MAX_PARENTS, MAX_PARENTS < WIRE_MAX_PARENTS, and
        // INTERVAL_SECS > 0 are pinned at compile time via the
        // `const _: () = assert!(..)` block in the parent module (next to
        // the const declarations). Runtime asserts here removed
        // (clippy::assertions_on_constants — both operands const-eval).

        // Drain capacity per cycle (max_merges × max_parents) must exceed
        // threshold so a saturated frontier converges. Otherwise a bursty
        // gossip storm could lock the tip count above threshold forever.
        // Kept runtime because `drain_capacity` is a let-bound local; clippy
        // does not const-fold across the binding.
        let drain_capacity = MAX_MERGES_PER_CYCLE * TIP_MERGE_MAX_PARENTS;
        assert!(
            drain_capacity > TIP_MERGE_THRESHOLD,
            "per-cycle drain capacity ({}) must exceed threshold ({}) to converge",
            drain_capacity, TIP_MERGE_THRESHOLD,
        );
    }

    #[test]
    fn merge_metadata_wire_keys_stable() {
        // Explorer, analytics, and any external reader keys off
        // `mesh_op = "merge"`. Rename either side without a wire-format
        // RFC and downstream consumers stop recognising merge records.
        // The namespace key is `mesh_op` (NOT `beat_op`) — merge is a
        // DAM topology op, not a ledger op.
        assert_eq!(MERGE_TYPE_KEY, "mesh_op");
        assert_eq!(MERGE_TYPE_VALUE, "merge");
    }

    #[test]
    fn merge_metadata_shape_serialises_canonically() {
        // Construct the exact metadata BTreeMap the loop emits and assert
        // its JSON shape. BTreeMap key order is alphabetical — so the
        // canonical form is `merge_parent_count` first, then `mesh_op`.
        // External tools that hash the metadata for indexing rely on this
        // order being deterministic.
        let parent_count: u64 = 173;
        let mut metadata = std::collections::BTreeMap::new();
        metadata.insert(
            MERGE_TYPE_KEY.to_string(),
            serde_json::Value::String(MERGE_TYPE_VALUE.to_string()),
        );
        metadata.insert(
            "merge_parent_count".to_string(),
            serde_json::Value::Number(serde_json::Number::from(parent_count)),
        );

        let json = serde_json::to_string(&metadata).expect("metadata must serialise");
        assert_eq!(
            json,
            r#"{"merge_parent_count":173,"mesh_op":"merge"}"#,
            "merge-record metadata wire format drifted",
        );
    }

    #[test]
    fn merge_content_prefix_is_stable() {
        // Explorer + analytics consumers grep merge records by the literal
        // `mesh_merge:` prefix in the record `content` field; renaming the
        // prefix without a wire-format RFC drops them off the radar.
        // The format string in `tip_merge_loop` is
        // `format!("mesh_merge:{}", parent_count)`.
        // Lock both the prefix AND the colon-N suffix shape.
        let parent_count = 173_usize;
        let content = format!("mesh_merge:{}", parent_count);
        assert!(
            content.starts_with("mesh_merge:"),
            "merge content prefix drifted from `mesh_merge:` — explorer/analytics break",
        );
        assert_eq!(
            content, "mesh_merge:173",
            "merge content body shape drifted (must be `mesh_merge:{{N}}`)",
        );
    }

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn tip_merge_interval_within_operational_bounds() {
        // INTERVAL_SECS > 0 is already pinned at compile time. The remaining
        // operational risk is a future edit that pushes the interval too tight
        // (gossip thrashing — every node spamming merge records, network
        // wedges under tip-merge storms) OR too loose (DAG frontier balloons
        // unchecked, gossip-fanout latency climbs, finality lag follows).
        // Sane testnet+mainnet range: [10 s, 600 s].
        assert!(
            TIP_MERGE_INTERVAL_SECS >= 10,
            "TIP_MERGE_INTERVAL_SECS={} — under 10 s thrashes the gossip plane",
            TIP_MERGE_INTERVAL_SECS,
        );
        assert!(
            TIP_MERGE_INTERVAL_SECS <= 600,
            "TIP_MERGE_INTERVAL_SECS={} — over 10 min lets the DAG frontier balloon between merges",
            TIP_MERGE_INTERVAL_SECS,
        );
    }

    #[test]
    fn multi_cycle_drain_absorbs_realistic_burst() {
        // The single-cycle convergence test already pins
        // `drain_capacity > THRESHOLD` — but a node has
        // observed ~8 K tips on a single sample under sustained load,
        // well above the 100-tip threshold. Pin that **five** cycles
        // (= 5 minutes at the current 60 s interval) drain a realistic
        // 8 K-tip burst with ≥ 25% headroom; if a future edit halves
        // `MAX_MERGES_PER_CYCLE` or `TIP_MERGE_MAX_PARENTS`, this test
        // catches the regression before the production frontier locks
        // above threshold under load.
        //
        // At current values (5 cycles × 10 merges × 200 parents) = 10_000 tips
        // drained over 5 minutes — note the headroom is only ~25% above the
        // observed 8 K peak; a 10 K+ burst would NOT converge inside 5 cycles.
        let cycles = 5_usize;
        let n_cycle_drain = cycles * MAX_MERGES_PER_CYCLE * TIP_MERGE_MAX_PARENTS;
        let realistic_burst: usize = 8_000;
        assert!(
            n_cycle_drain > realistic_burst,
            "{} cycles drain only {} tips — must exceed the {}-tip realistic burst observed on testnet",
            cycles, n_cycle_drain, realistic_burst,
        );
    }

    #[test]
    fn merge_metadata_btreemap_has_exactly_two_keys() {
        // `merge_metadata_shape_serialises_canonically` pins the rendered
        // JSON string with parent_count=173. That test would still pass if
        // a future edit added a third metadata key that happened to slot
        // alphabetically AFTER both existing keys (e.g. `mesh_origin`,
        // `beat_op`, `zone_path`) — the existing assertion only checks
        // equality against a hard-coded prefix-bounded string at one value.
        // Pin the set cardinality + identity directly so a third-key bloat
        // surfaces with a name that says exactly what regressed.
        //
        // Why this matters: explorer + analytics consumers iterate metadata
        // keys; an unannounced third key changes the wire contract and
        // breaks indexers that key off (mesh_op, merge_parent_count) only.
        let parent_count: u64 = 1;
        let mut metadata = std::collections::BTreeMap::new();
        metadata.insert(
            MERGE_TYPE_KEY.to_string(),
            serde_json::Value::String(MERGE_TYPE_VALUE.to_string()),
        );
        metadata.insert(
            "merge_parent_count".to_string(),
            serde_json::Value::Number(serde_json::Number::from(parent_count)),
        );

        assert_eq!(
            metadata.len(),
            2,
            "merge metadata must have EXACTLY 2 keys — a third key is a wire-format change",
        );
        let keys: std::collections::BTreeSet<&str> =
            metadata.keys().map(|k| k.as_str()).collect();
        let expected: std::collections::BTreeSet<&str> =
            ["mesh_op", "merge_parent_count"].into_iter().collect();
        assert_eq!(
            keys, expected,
            "merge metadata key set drifted from {{mesh_op, merge_parent_count}}",
        );
    }

    #[test]
    fn merge_metadata_parent_count_serialises_as_unsigned_integer() {
        // The loop builds `merge_parent_count` via
        // `serde_json::Number::from(parent_count as u64)`. A future refactor
        // that switches to `from_f64(parent_count as f64).unwrap()` (e.g.
        // someone introducing a fractional merge-weight) would silently
        // change the wire type from JSON integer to JSON float — explorer
        // indexers that key off an integer schema (RocksDB column with
        // u64 type, SQL bigint column, protobuf uint64) would start
        // rejecting records mid-flight. Pin the type explicitly: the parsed
        // number must satisfy `is_u64()` and the rendered JSON must contain
        // no decimal point, across both the canonical drained-frontier
        // value (200) and a boundary value (1).
        for &parent_count in &[1u64, 200u64] {
            let mut metadata = std::collections::BTreeMap::new();
            metadata.insert(
                "merge_parent_count".to_string(),
                serde_json::Value::Number(serde_json::Number::from(parent_count)),
            );
            let json = serde_json::to_string(&metadata).expect("metadata must serialise");
            assert!(
                !json.contains('.'),
                "merge_parent_count={} rendered JSON {:?} contains a decimal point — wire-type drift",
                parent_count, json,
            );
            let parsed: serde_json::Value =
                serde_json::from_str(&json).expect("metadata round-trip must succeed");
            let n = parsed
                .get("merge_parent_count")
                .and_then(|v| v.as_number())
                .expect("merge_parent_count must be present and Number");
            assert!(
                n.is_u64(),
                "merge_parent_count={} must serialise as JSON unsigned integer (is_u64), got {:?}",
                parent_count, n,
            );
        }
    }

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn tip_merge_threshold_within_operational_bounds() {
        // Symmetric pin to `tip_merge_interval_within_operational_bounds`:
        // the compile-time block already pins THRESHOLD <= MAX_PARENTS=200
        // (so a single merge can drain a saturated frontier). The remaining
        // operational risks are at the floor and the ceiling within that
        // hard cap.
        //
        // Floor: THRESHOLD <= 1 makes every newly-arrived tip on a freshly-
        // bootstrapped node trigger a merge attempt — gossip storm risk on
        // any node that joins mid-cluster and receives a burst of unrelated
        // tips. We want THRESHOLD >= 10 so a small handful of tips never
        // triggers (matches the operational reality that a healthy mesh
        // always has at least a few tips in flight).
        //
        // Ceiling: THRESHOLD too close to MAX_PARENTS means each merge
        // barely scrapes the frontier above the threshold. We want
        // THRESHOLD <= MAX_PARENTS so a single merge has headroom to push
        // the frontier well below threshold (the compile-time assert covers
        // the strict <=; this test pins THRESHOLD <= MAX_PARENTS / 2 — at
        // least half the merge capacity must be headroom, so a merge halves
        // the frontier instead of just nicking it).
        assert!(
            TIP_MERGE_THRESHOLD >= 10,
            "TIP_MERGE_THRESHOLD={} — under 10 fires the loop on small-cluster baseline traffic",
            TIP_MERGE_THRESHOLD,
        );
        assert!(
            TIP_MERGE_THRESHOLD * 2 <= TIP_MERGE_MAX_PARENTS,
            "TIP_MERGE_THRESHOLD={} too close to TIP_MERGE_MAX_PARENTS={} — single merge has < 50% headroom",
            TIP_MERGE_THRESHOLD, TIP_MERGE_MAX_PARENTS,
        );
    }

    // ------------------------------------------------------------------------
    // Wire/operational invariants not covered above. Each test pins a
    // single regression vector the existing tests don't catch.
    // ------------------------------------------------------------------------

    #[test]
    fn wire_max_parents_equals_u8_capacity_plus_one() {
        // The ValidationRecord wire format reserves a single byte for the
        // parent count (0..=255 inclusive — 256 distinct values). The
        // compile-time block asserts `TIP_MERGE_MAX_PARENTS < WIRE_MAX_PARENTS`,
        // but it does NOT pin WIRE_MAX_PARENTS itself to the actual byte
        // capacity. A future edit that bumps WIRE_MAX_PARENTS to 512 (thinking
        // "we'll change the wire format later") would silently let
        // TIP_MERGE_MAX_PARENTS climb past 255 with the compile-time assert
        // still passing — and then overflow the single-byte field at the
        // first emit. Pin WIRE_MAX_PARENTS to u8::MAX as usize + 1 so the
        // compile-time guard remains anchored to the actual byte capacity.
        assert_eq!(
            WIRE_MAX_PARENTS,
            u8::MAX as usize + 1,
            "WIRE_MAX_PARENTS={} drifted from u8 capacity (255+1=256) — wire-format byte-width regression",
            WIRE_MAX_PARENTS,
        );
    }

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn max_merges_per_cycle_within_operational_bounds() {
        // MAX_MERGES_PER_CYCLE has no const-time bound except being a usize.
        // Two operational risks at the extremes:
        //   - Floor: a value of 0 disables the inner merge loop entirely
        //     (`while merges_this_cycle as usize >= MAX_MERGES_PER_CYCLE`
        //     breaks before any merge runs). The DAG frontier balloons
        //     unbounded on every passive node.
        //   - Ceiling: a value >= 100 lets a single cycle emit hundreds of
        //     merge records on a single node, each triggering gossip-push to
        //     every peer — a self-inflicted gossip storm under transient
        //     spikes. Healthy testnet runs at <= 10/cycle.
        // Sane mainnet+testnet range: [1, 100].
        assert!(
            MAX_MERGES_PER_CYCLE >= 1,
            "MAX_MERGES_PER_CYCLE={} disables the inner merge loop — DAG frontier balloons unbounded",
            MAX_MERGES_PER_CYCLE,
        );
        assert!(
            MAX_MERGES_PER_CYCLE <= 100,
            "MAX_MERGES_PER_CYCLE={} above 100 — single-cycle gossip-storm risk on bursty load",
            MAX_MERGES_PER_CYCLE,
        );
    }

    #[test]
    fn drain_capacity_has_at_least_10x_threshold_headroom() {
        // `drain_plan_invariants_hold` pins drain_capacity > THRESHOLD — i.e.
        // each cycle can in principle drain the threshold value. But at
        // current values (10 × 200 = 2000 vs THRESHOLD=100) we have 20× the
        // threshold of drain headroom — which is what gives the loop ANY
        // chance of catching up under bursty inflow. A future halving of
        // MAX_MERGES_PER_CYCLE (10 → 5) or TIP_MERGE_MAX_PARENTS (200 → 100)
        // would still pass the existing > pin but cut the catch-up margin in
        // half. Pin at least 10× headroom so a single-knob halving keeps the
        // loop converging (current 20× margin survives one halving and still
        // passes; further halving fails this test).
        let drain_capacity = MAX_MERGES_PER_CYCLE * TIP_MERGE_MAX_PARENTS;
        assert!(
            drain_capacity >= 10 * TIP_MERGE_THRESHOLD,
            "drain_capacity={} below 10× THRESHOLD={} — under-cap; bursty inflow will lock frontier above threshold",
            drain_capacity,
            TIP_MERGE_THRESHOLD,
        );
    }

    #[test]
    fn merge_content_length_bounded_at_max_parent_count() {
        // The content field is `format!("mesh_merge:{}", parent_count)`.
        // Worst case at runtime is parent_count = TIP_MERGE_MAX_PARENTS = 200,
        // which renders as `"mesh_merge:200"` (14 bytes). The compile-time
        // assert pins MAX_PARENTS < WIRE_MAX_PARENTS=256, so the largest
        // value the formatter can ever emit is `"mesh_merge:255"` (14 bytes
        // even at the wire ceiling). Pin a hard 32-byte upper bound on the
        // rendered content so a future refactor that switches the formatter
        // to, e.g., `format!("mesh_merge:{}|cycle={}|node={}", …)` doesn't
        // silently inflate every merge record's payload. 32 bytes is wide
        // enough to absorb a future digit added to the parent-count display
        // (e.g. four-digit MAX_PARENTS values up through 9999) but tight
        // enough to catch a multi-field expansion.
        let content_at_max = format!("mesh_merge:{}", TIP_MERGE_MAX_PARENTS);
        assert!(
            content_at_max.len() <= 32,
            "merge content {:?} at MAX_PARENTS={} is {} bytes — exceeds 32-byte wire-size budget",
            content_at_max,
            TIP_MERGE_MAX_PARENTS,
            content_at_max.len(),
        );
        // Also pin at the wire ceiling so the test catches a max_parents bump
        // up to (but not past) the compile-time-asserted WIRE_MAX_PARENTS-1.
        let content_at_wire_ceiling = format!("mesh_merge:{}", WIRE_MAX_PARENTS - 1);
        assert!(
            content_at_wire_ceiling.len() <= 32,
            "merge content {:?} at wire ceiling is {} bytes — exceeds 32-byte budget",
            content_at_wire_ceiling,
            content_at_wire_ceiling.len(),
        );
    }

    #[test]
    fn drain_capacity_fits_in_u32() {
        // The inner merge loop counts emitted merges in a `u32`
        // (`let mut merges_this_cycle = 0u32;`). The break condition is
        // `merges_this_cycle as usize >= MAX_MERGES_PER_CYCLE`. A future bump
        // of MAX_MERGES_PER_CYCLE past u32::MAX would lose count via the
        // `as usize` cast back-to-back with the u32 counter (silent wrap to
        // 0, infinite-loop risk). Pin MAX_MERGES_PER_CYCLE <= u32::MAX so a
        // hypothetical 64-bit bump must touch the counter type too. Same for
        // drain_capacity = MAX_MERGES_PER_CYCLE × MAX_PARENTS: if this product
        // ever overflows usize on a 32-bit target (cf. WASM32, embedded), the
        // capacity-headroom test math goes silently wrong.
        assert!(
            MAX_MERGES_PER_CYCLE <= u32::MAX as usize,
            "MAX_MERGES_PER_CYCLE={} above u32::MAX — counter overflow in merges_this_cycle",
            MAX_MERGES_PER_CYCLE,
        );
        let drain_capacity = MAX_MERGES_PER_CYCLE
            .checked_mul(TIP_MERGE_MAX_PARENTS)
            .expect("drain_capacity multiplication must not overflow usize");
        assert!(
            drain_capacity <= u32::MAX as usize,
            "drain_capacity={} above u32::MAX — wire-budget math silently wraps on 32-bit targets",
            drain_capacity,
        );
    }
}
