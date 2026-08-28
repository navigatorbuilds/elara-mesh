//! Compiled-in chain-identity pins — the release-channel trust roots that
//! discriminate the canonical chain from its five abandoned same-key siblings.
//!
//! Lives OUTSIDE the `node-core`-gated `network` module because the consumers
//! span feature sets: the §E epoch fence (network/epoch.rs, network/sync.rs —
//! node-gated) AND the genesis-mint pin's always-compiled enforcement layers
//! (accounting/validate.rs, storage/rocks.rs). `network::config` re-exports
//! everything here, so node-side code keeps its `config::PINNED_*` paths.
//!
//! Full design records: internal design notes
//! (epoch anchor) and internal design notes
//! (mint pin).

/// The ONE network these pins bind to. On any other `network_id` (private
/// devnets, future re-genesis networks) every pin below is deactivated —
/// without that scoping a young devnet would alarm until epoch 49986, wedge
/// there when its natural seal hash differs, and never seed its own genesis
/// mint. Deliberately a SEPARATE const from `DEFAULT_NETWORK_ID`: if the
/// default ever changes, the pin binding must not silently follow it.
pub const PINNED_CHAIN_ANCHORS_NETWORK_ID: &str = "testnet";

/// §E re-genesis fence — compiled-in chain-identity anchors
/// (internal design notes).
///
/// Entries are `(zone_path, epoch, seal_record_hash)`: at `(zone, epoch)` the
/// canonical seal record's hash MUST equal the pinned value. The check is a
/// positive point-assertion — a no-op for every other epoch — so honest
/// lagging nodes (below the pinned epoch) and honest past-anchor nodes are
/// untouched (non-forking by construction). It discriminates the post-re-genesis
/// chain from the frozen pre-ceremony chain, whose genesis KEY was reused —
/// which is why the trust root here is the RELEASE CHANNEL (this compiled
/// constant), NOT an on-chain signature: a genesis signature proves WHO
/// signed, never WHICH chain, and a hostile bootstrap peer simply never
/// serves a chain-carried pin.
///
/// Enforcement sites (all mandatory, fail-closed):
///   1. `EpochState::apply_canonical_seal` (epoch.rs) — the funnel for the
///      ZONE-seal register family: live ingest, boot replay via
///      `process_record`, F-10 recovery, orphan promotion — AND
///      `EpochState::register_global_seal`, the second tip-mutation funnel
///      (cross-zone escalation seals, also replayed by `process_record`).
///   2. `apply_bootstrap_snapshot_full` pre-mutation check + the bounded
///      `/headers/from/{E}` peer probe in `snapshot_bootstrap` (sync.rs) —
///      the snapshot tip-install path structurally bypasses `register_seal`.
///
/// Plus a periodic completion guard (health.rs `health_check_loop`): a node
/// whose epoch state is populated yet still below the pinned epoch after a
/// debounce window ALARMS and keeps syncing — never bricks. That guard closes
/// the vacuity gap: the old chain froze at epoch 35245 < 49986, so a node fed
/// only frozen history parks below the pin and the point-assertion never
/// fires. (An empty epoch state is "not yet replayed", never an alarm.)
///
/// MAINTENANCE:
/// - Any future INTENTIONAL re-genesis that resets epoch numbering MUST update
///   or clear these entries AND `PINNED_GENESIS_MINT_ID`/`_RECORD_HASH` below
///   in the same release, or virgin re-joins self-brick / stay mint-less.
/// - The pinned VALUE was live-verified 4× (2026-08-25 21:20 / 23:47 / 01:36 /
///   2026-08-26 08:15) against the authority seed, 45k+ epochs deep and
///   chain-linked by epoch 49987's previous_seal_hash. Its DERIVATION must
///   never enter the enforcement path — hard-coded const only.
///
/// STATED RESIDUALS (not closed by this fence): total eclipse (a node fed ONLY
/// hostile data that never reaches an honest peer — a peer-diversity problem no
/// checkpoint closes; mitigated by the empty default seed list forcing explicit
/// trusted-seed config), and the genesis-mint poisoning follow-up — closed
/// separately by the mint pin below.
pub const PINNED_CHAIN_ANCHORS: &[(&str, u64, [u8; 32])] = &[(
    "0",
    49986,
    [
        0xc5, 0x83, 0x2a, 0xb4, 0xb9, 0x74, 0x0a, 0xb1, 0x8a, 0xd8, 0x2d, 0xd8, 0xf4, 0x54, 0x5b,
        0xbb, 0x8e, 0xfa, 0x87, 0x8b, 0x5c, 0x56, 0x10, 0x53, 0xc3, 0x78, 0x0e, 0xf3, 0xe0, 0x77,
        0x08, 0x79,
    ],
)];

/// Genesis-mint pin (SEC-GENESIS-MINT-PIN-VERDICT-2026-08-26): the record id of
/// the CANONICAL chain's one true genesis total-allocation mint. Same
/// release-channel trust root and same `PINNED_CHAIN_ANCHORS_NETWORK_ID`
/// scoping as the epoch anchor above — under genesis-key reuse a signature
/// proves WHO minted, never WHICH ceremony, and there were SIX ceremonies
/// (2026-06-12, 06-16, 06-17, 07-06 ×3); five were abandoned, all validly
/// signed by the same reused key. The newest ABANDONED mint precedes this one
/// by 24m44s, which is why a timestamp cutover was REJECTED by the panel
/// (no safe margin in either direction) in favor of positive identification.
///
/// THREAT MODEL (stated exactly — this wording is load-bearing): a foreign
/// ceremony's mint does NOT inflate supply (all six mint the same MAX_SUPPLY
/// to the same authority, and the MAX_SUPPLY guard caps duplicates); it
/// silently DIVERGES consensus — `last_active`, vesting keyed on record
/// id/timestamp, and `applied_record_ids` take the wrong chain's values, the
/// account-SMT root forks, and the REAL mint is thereafter refused as a
/// duplicate. Supply looks right; the chain is quietly forked. This pin does
/// NOT repair an already-poisoned node (recovery = wipe + re-bootstrap), and
/// the total-eclipse residual (a virgin node that never reaches an honest
/// peer) remains open, same as for the epoch anchor.
///
/// Enforcement layers (each states what it covers; none claims the others'):
///   1. `accounting::validate::pinned_genesis_mint_admits` at
///      `insert_record_inner` (live funnel: HTTP submit, PQ push, timestamp/
///      full/delta pull) — id check; records here already passed signature
///      admission.
///   2. The RocksDB ledger-rebuild loops (`rebuild_ledger_streaming`,
///      `incremental_ledger_replay`) — same predicate, covers replay of
///      anything already on disk.
///   3. `bootstrap_pull_from_zero`'s pre-store filter (gossip.rs) — FULL
///      positive check (id + record_hash + creator == genesis authority),
///      because that path deliberately bypasses ledger validation and must
///      never even store a foreign mint (a stored record is re-applied by
///      rebuild regardless of any flag).
///
/// NOT covered, filed separately: legacy signed snapshots with `epoch=None`
/// bypassing the §E snapshot precheck while installing a wholesale ledger;
/// the authority's own `auto_genesis_mint` self-boot path (not
/// attacker-reachable — it requires the key; a 7th intentional ceremony is
/// the MAINTENANCE case above).
///
/// A stale mint pin fails SOFT: virgin joins on the canonical network stay
/// mint-less and keep retrying with `elara_pinned_genesis_mint_absent_total`
/// alarming — never a brick.
///
/// Value re-derived in Rust from the record's actual wire bytes and locked by
/// the checked-in fixture test `pinned_genesis_mint_fixture_locked`
/// (tests/fixtures/genesis_mint_019f36c4.wire.hex); live-probed 2026-08-26 by
/// two independent panel seats via different methods (data-plane record query;
/// SST scan + reimplemented signable_bytes validated against the epoch
/// anchor). Timestamp for provenance only: 1783330262.683914
/// (2026-07-06T09:31:02.683Z) — NEVER an enforcement input.
pub const PINNED_GENESIS_MINT_ID: &str = "019f36c4-4e9b-7733-9b63-35006ca6c0dc";

/// sha3-256 of the pinned genesis mint's `signable_bytes` (== its
/// `record_hash()`). Consumed by the gossip pre-store filter's full positive
/// check; see [`PINNED_GENESIS_MINT_ID`] for the whole story.
pub const PINNED_GENESIS_MINT_RECORD_HASH: [u8; 32] = [
    0xe3, 0x45, 0xd0, 0xac, 0x77, 0x90, 0x10, 0x57, 0xb3, 0x82, 0xa5, 0x10, 0x39, 0xae, 0xa6,
    0xdf, 0x94, 0x0f, 0x06, 0xa7, 0x2c, 0x83, 0x8d, 0xee, 0x35, 0xf3, 0x79, 0x76, 0x84, 0x36,
    0x43, 0xdc,
];

// ─── KNOWN BENIGN ARTIFACT — NOT a bug, NOT a deferred fix (panel verdict ─────
//     SEC-FOREIGN-RECORD-DENYLIST-VERDICT-2026-08-26, 3/3 unanimous TOLERATE) ──
//
// Record `019f2c92-9f5d-7f02-852a-eb98414e3ee0` (ts 2026-07-04T10:00:34Z, ~2
// days before the Jul-6 genesis mint; metadata epoch_op=super_seal, zone 0,
// epochs 32001-32064, count 64) sits in the authority seed's live store and is
// served as record #1 by the DATA-PLANE `/records?since=0`. It is an abandoned
// pre-ceremony chain's super-seal that survived the 2026-07-06 wipe via gossip
// from a then-frozen follower node, back when `bootstrap_pull_from_zero` had no
// signature check (that hole = T85/T86, closed 20124f77 — but this record is
// GENUINELY signed by the reused genesis-authority key, so the sig-gate admits
// it by design; the hardening blocks FORGERIES, not validly-signed litter).
//
// WHY IT IS INERT AND STAYS UNFENCED (deliberate, not an oversight):
// A super-seal is NOT canonical-consensus state. `register_super_seal`
// (epoch.rs) is pure newest-wins — end_epoch 32064 can never beat the live tip
// (~96k+), so it never wins zone-0's slot; `/checkpoints/from` serves ONLY the
// per-zone newest super-seal, so a foreign one is permanently unreachable the
// moment the live chain produces its own (long true here). The record types
// that CAN enter consensus state — mints, zone-seal tips, global-quorum-seals —
// ARE fenced by positive-identification pins above (`PINNED_GENESIS_MINT_ID`,
// `PINNED_CHAIN_ANCHORS`). Super-seals structurally cannot, and a fence for them
// would be new negative-polarity governance surface for zero risk reduction.
//
// THIS IS A RECURRING CLASS, NOT A ONE-OFF: all five prior abandoned-ceremony
// data dirs on the seed machine carry super-seal populations (7-1417 records
// each — routine Gap-3 checkpoint output). Every future re-genesis abandons a
// chain that has been generating the same litter; expect more instances after
// the two follower laptops' pending virgin rejoins. Realized LIVE contamination is nonetheless
// tiny (one record) — leakage needs a still-running stale peer during a virgin
// bootstrap, a bounded ceremony-gated trickle, not an ongoing leak.
//
// DO NOT re-open as a bug, DO NOT build a `PINNED_FOREIGN_RECORDS` denylist, and
// DO NOT weaken `admin_evict_unverifiable_record`'s sig-valid refusal (that
// refusal is WHY no live tool removes it — a security property). The denylist is
// a DOMINATED move: the only re-injectors are our own two followers (both need
// virgin wipes anyway) and future nodes pull from our clean seed, so a one-shot
// OFFLINE delete on the seed during that wipe window achieves identical cleanliness
// with zero permanent surface. RE-OPEN ONLY IF: (a) a discovered instance is a
// mint/zone-seal/global-quorum-seal (→ that's the mint-pin/§E-fence's job, not
// here); (b) the newest-wins/unreachability property is ever defeated; (c)
// volume threatens disk (it won't at ceremony cadence). Root cause of the whole
// class = the reused genesis-authority key across all six ceremonies — a fresh
// key at the next intentional re-genesis is the real close (strategic, filed).
