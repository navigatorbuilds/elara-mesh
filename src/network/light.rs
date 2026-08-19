//! Light Client Mode — Protocol §11.3.
//!
//! Header-only sync: light clients verify records via Merkle proofs against
//! epoch seal roots without storing the full DAG.
//!
//! Light clients receive `EpochHeader` summaries and verify chain integrity
//! (each seal references the previous seal hash). Individual records are
//! verified by requesting a `MerkleProof` from a full node.

//!
//! Spec references:
//!   @spec Protocol §11.3

use std::collections::HashMap;

use crate::ZoneId;

use super::sync::{MerkleProof, MerkleTree};

// ─── Types ───────────────────────────────────────────────────────────────────

/// Compact epoch header for light client consumption.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EpochHeader {
    /// Zone this epoch belongs to.
    pub zone: ZoneId,
    /// Epoch sequence number within the zone.
    pub epoch_number: u64,
    /// Merkle root over all records in this epoch.
    pub merkle_root: [u8; 32],
    /// Content hash of the previous epoch seal record (chain link).
    pub previous_seal_hash: [u8; 32],
    /// Number of records in this epoch.
    pub record_count: u64,
    /// Epoch start timestamp.
    pub start: f64,
    /// Epoch end timestamp.
    pub end: f64,
    /// Gap 1: Global account-state SMT root at seal time. Light clients
    /// verify account proofs (`/proof/account/{id}`) against this root.
    /// None for legacy seals (pre-Gap 1).
    #[serde(default)]
    pub account_smt_root: Option<[u8; 32]>,
    /// Content hash (`sha3_256(signable_bytes)`) of THIS header's seal
    /// record on the emitting node. Used by the next header's
    /// `previous_seal_hash` for chain-link verification. `None` on
    /// pre-fix responses where the endpoint didn't expose it; in that
    /// case `add_header` falls back to a best-effort accept (chain
    /// verification is skipped for that edge). Always `Some` for
    /// headers emitted by nodes running this version or later.
    #[serde(default)]
    pub seal_record_hash: Option<[u8; 32]>,
}

/// Gap 3: a single zone's accepted super-seal checkpoint, recorded on the
/// light client. On cold start, the sync loop queries `/checkpoints/from/0`
/// on a seed and uses the returned `end_epoch` per zone to jump forward —
/// avoiding a genesis replay across potentially millions of seals. The
/// checkpoint itself is the root of trust from that epoch onward; subsequent
/// epoch headers chain-link forward from the covered range.
/// Trust grade of an accepted checkpoint, mirroring the offline `elara-verify`
/// `Pass`/`Partial` distinction. The cold-start `light_sync_loop` stamps each
/// `CheckpointMark` with the grade it earned so the trust posture is explicit
/// in the data, never inferred.
///
/// `Reference` is NOT trustless — it means the super-seal signature was checked
/// only against the wire-supplied `creator_public_key` (single-seed trust),
/// because no out-of-band anchor was configured. Honest-claims: a `Reference`
/// checkpoint must never be presented as verified-against-a-pinned-root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TrustGrade {
    /// Super-seal signature verified against a pinned Dilithium3 anchor key
    /// (`verify_seal_record_against_anchor`). Trustless within the strength of
    /// the lattice signature + the pinned anchor set.
    AnchorPinned,
    /// No anchor configured; signature verified only against the wire-supplied
    /// `creator_public_key`. Single-seed trust — not trustless.
    Reference,
}

impl Default for TrustGrade {
    /// `Reference` is the safe default: a checkpoint with no explicit grade has
    /// earned no anchor-pinned trust. Legacy marks deserialize to `Reference`.
    fn default() -> Self {
        TrustGrade::Reference
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CheckpointMark {
    pub zone: ZoneId,
    pub start_epoch: u64,
    pub end_epoch: u64,
    pub seal_count: u64,
    pub record_id: String,
    pub record_hash: [u8; 32],
    pub committee_hash: [u8; 32],
    /// Set to `true` after the super-seal's `merkle_root` has been verified
    /// end-to-end against the fetched seal_record_hash values for
    /// `[start_epoch, end_epoch]`.
    /// Defaults to `false` so legacy checkpoints serialized to
    /// disk are treated as not-yet-verified and re-checked once headers
    /// cover the range. Mismatch increments `super_seal_coverage_failures_total`
    /// — colluding seeds that signed a forged aggregate are caught here.
    #[serde(default)]
    pub coverage_verified: bool,
    /// Trust grade the super-seal signature earned at acceptance: `AnchorPinned`
    /// when verified against a configured anchor set, `Reference` otherwise.
    /// Legacy marks default to `Reference`.
    #[serde(default)]
    pub trust_grade: TrustGrade,
    /// The `seal_record_hash` of the `end_epoch` header, captured during
    /// coverage verification. This is the trusted baseline the first
    /// post-checkpoint header must chain to (`add_header`): its
    /// `previous_seal_hash` must equal this value. `None` when coverage was
    /// skipped (legacy emitter / no PQ addr) and the baseline is unknown — in
    /// that case `add_header` falls back to best-effort first-header accept.
    #[serde(default)]
    pub baseline_seal_hash: Option<[u8; 32]>,
}

/// Light client state — tracks verified epoch headers per zone.
#[derive(Default)]
pub struct LightState {
    /// Verified epoch headers per zone, ordered by epoch number.
    pub headers: HashMap<ZoneId, Vec<EpochHeader>>,
    /// Latest verified Merkle root per zone.
    pub latest_roots: HashMap<ZoneId, [u8; 32]>,
    /// Gap 3: per-zone super-seal checkpoints accepted as the sync starting
    /// point. Empty until the loop's one-shot checkpoint fetch runs on cold
    /// start. Subsequent header pulls use `max(checkpoint.end_epoch) + 1`
    /// as the `since_epoch` floor so we don't re-pull seals already covered
    /// by a trusted super-seal.
    pub checkpoints: HashMap<ZoneId, CheckpointMark>,
    /// Whether this process has already tried the checkpoint-skip path.
    /// Stops us hammering the seed's `/checkpoints/from/0` endpoint every
    /// tick when no checkpoints are available (small network / pre-N-epochs).
    pub checkpoint_skip_attempted: bool,
}

impl LightState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an epoch header. Returns `Err` if the chain link is broken.
    pub fn add_header(&mut self, header: EpochHeader) -> Result<(), String> {
        // Capture the anchored checkpoint baseline (if any) BEFORE taking the
        // mutable `headers` borrow — a disjoint-field read of `self.checkpoints`,
        // released before the borrow below. `Some((end_epoch, baseline_hash))`
        // only when a checkpoint exists for this zone AND its coverage verified
        // (so the baseline is known). When the baseline is unknown
        // (coverage-skipped / Reference grade), this is `None` and the first
        // header falls back to best-effort accept.
        let checkpoint_baseline: Option<(u64, [u8; 32])> = self
            .checkpoints
            .get(&header.zone)
            .and_then(|cp| cp.baseline_seal_hash.map(|b| (cp.end_epoch, b)));

        let zone_headers = self.headers.entry(header.zone.clone()).or_default();

        // Verify chain link: the new header's `previous_seal_hash` must
        // match the last header's seal-record content hash. The record
        // hash lives on the emitting node (it's `sha3_256` over the seal
        // record's canonical signable bytes). We get it from the header
        // response via `seal_record_hash`; fall back to accept if the
        // emitting node predates this field.
        if let Some(last) = zone_headers.last() {
            if header.epoch_number != last.epoch_number + 1 {
                return Err(format!(
                    "epoch gap: expected {}, got {}",
                    last.epoch_number + 1,
                    header.epoch_number
                ));
            }
            if let Some(last_record_hash) = last.seal_record_hash {
                if header.previous_seal_hash != last_record_hash {
                    return Err(format!(
                        "chain break at epoch {}: previous_seal_hash does not \
                         match previous seal's record_hash",
                        header.epoch_number
                    ));
                }
            }
            // else: previous header came from a pre-fix emitter with no
            // seal_record_hash — best-effort accept, logged at caller.
        } else if let Some((cp_end, baseline)) = checkpoint_baseline {
            // First header for this zone after an anchor-verified checkpoint
            // with a known baseline. It MUST be `end_epoch + 1` and its
            // `previous_seal_hash` MUST equal the checkpoint's `end_epoch`
            // seal_record_hash. This roots the chain-link sequence in a
            // super-seal signed by a pinned anchor — closing the forged
            // first-header hole (without it, a single malicious cold-start
            // seed could inject an arbitrary baseline header and fork forward,
            // since every subsequent header chains cleanly off that forgery).
            if header.epoch_number != cp_end + 1 {
                return Err(format!(
                    "first post-checkpoint header for zone {} has epoch {}, expected {} \
                     (checkpoint end_epoch + 1)",
                    header.zone,
                    header.epoch_number,
                    cp_end + 1,
                ));
            }
            if header.previous_seal_hash != baseline {
                return Err(format!(
                    "first post-checkpoint header for zone {}: previous_seal_hash does not \
                     match the anchored checkpoint baseline (end_epoch {} seal_record_hash) \
                     — forged-branch jump rejected",
                    header.zone, cp_end,
                ));
            }
        } else if header.epoch_number != 0 {
            // First header we see, no anchored baseline (no checkpoint for this
            // zone, or its coverage was skipped → Reference grade). Accept any
            // epoch number but warn (light client may be starting mid-chain).
        }

        self.latest_roots.insert(header.zone.clone(), header.merkle_root);
        zone_headers.push(header);
        Ok(())
    }

    /// Verify the chain integrity for a zone.
    ///
    /// Returns `true` if all consecutive headers link correctly — i.e.
    /// each header's `previous_seal_hash` matches the prior header's
    /// `seal_record_hash`. If any prior header lacks `seal_record_hash`
    /// (pre-fix data), that edge is skipped rather than failing the
    /// whole chain.
    pub fn verify_chain(&self, zone: &ZoneId) -> bool {
        let headers = match self.headers.get(zone) {
            Some(h) => h,
            None => return true, // empty = trivially valid
        };

        for window in headers.windows(2) {
            let prev = &window[0];
            let curr = &window[1];

            if curr.epoch_number != prev.epoch_number + 1 {
                return false;
            }
            if let Some(prev_hash) = prev.seal_record_hash {
                if curr.previous_seal_hash != prev_hash {
                    return false;
                }
            }
        }
        true
    }

    /// Verify a record exists in a given epoch using a Merkle proof.
    ///
    /// Checks that the proof root matches the epoch's Merkle root.
    pub fn verify_record(&self, zone: &ZoneId, epoch_number: u64, proof: &MerkleProof) -> bool {
        let headers = match self.headers.get(zone) {
            Some(h) => h,
            None => return false,
        };

        let header = headers.iter().find(|h| h.epoch_number == epoch_number);
        match header {
            Some(h) => {
                if proof.root != h.merkle_root {
                    return false;
                }
                MerkleTree::verify_proof(proof)
            }
            None => false,
        }
    }

    /// Get latest verified epoch number for a zone.
    pub fn latest_epoch(&self, zone: &ZoneId) -> Option<u64> {
        self.headers
            .get(zone)
            .and_then(|h| h.last())
            .map(|h| h.epoch_number)
    }

    /// Get all headers for a zone since a given epoch number.
    pub fn headers_since(&self, zone: &ZoneId, since_epoch: u64) -> Vec<&EpochHeader> {
        self.headers
            .get(zone)
            .map(|h| h.iter().filter(|eh| eh.epoch_number >= since_epoch).collect())
            .unwrap_or_default()
    }

    /// Build the per-zone work list for the next sync tick.
    ///
    /// Returns `(zone_filter, since_epoch)` pairs. With known zones,
    /// each entry pulls one zone independently so the response is
    /// single-zone and ordered, which keeps `add_header`'s chain-link
    /// check stable. Cold start (no zones known) returns
    /// `vec![(None, 0)]` — one unfiltered probe to discover what zones
    /// the seed serves.
    ///
    /// Per-zone `since_epoch = max(last_header_epoch, checkpoint_end_epoch) + 1`,
    /// matching the previous global behaviour but no longer collapsing
    /// across zones.
    ///
    /// Pure read of `LightState` — extracted so the test suite can
    /// regression-cover the per-zone since fix without standing up a
    /// full `NodeState`.
    pub fn compute_zone_pulls(&self) -> Vec<(Option<ZoneId>, u64)> {
        let mut zones: std::collections::BTreeSet<ZoneId> =
            self.headers.keys().cloned().collect();
        zones.extend(self.checkpoints.keys().cloned());
        if zones.is_empty() {
            return vec![(None, 0)];
        }
        zones
            .into_iter()
            .map(|z| {
                let h_max = self
                    .headers
                    .get(&z)
                    .and_then(|hs| hs.last().map(|h| h.epoch_number));
                let c_end = self.checkpoints.get(&z).map(|m| m.end_epoch);
                let since = match (h_max, c_end) {
                    (Some(h), Some(c)) => h.max(c) + 1,
                    (Some(h), None) => h + 1,
                    (None, Some(c)) => c + 1,
                    (None, None) => 0,
                };
                (Some(z), since)
            })
            .collect()
    }

    /// Like `compute_zone_pulls` but restricted to `whitelist`.
    ///
    /// When `whitelist` is non-empty, the client only ever requests headers for
    /// whitelisted zones — the `(None, 0)` "pull everything" cold-start probe is
    /// replaced by one `(Some(z), 0)` per whitelisted zone. This keeps
    /// `LightState.headers` bounded to `O(epochs_per_followed_zone)` at 1M-zone
    /// mainnet scale, where an un-filtered cold start would otherwise discover
    /// and begin tracking every zone the seed knows.
    ///
    /// Empty `whitelist` delegates to `compute_zone_pulls` (follow everything).
    pub fn compute_zone_pulls_filtered(&self, whitelist: &[ZoneId]) -> Vec<(Option<ZoneId>, u64)> {
        if whitelist.is_empty() {
            return self.compute_zone_pulls();
        }
        whitelist
            .iter()
            .map(|z| {
                let h_max = self
                    .headers
                    .get(z)
                    .and_then(|hs| hs.last().map(|h| h.epoch_number));
                let c_end = self.checkpoints.get(z).map(|m| m.end_epoch);
                let since = match (h_max, c_end) {
                    (Some(h), Some(c)) => h.max(c) + 1,
                    (Some(h), None) => h + 1,
                    (None, Some(c)) => c + 1,
                    (None, None) => 0,
                };
                (Some(z.clone()), since)
            })
            .collect()
    }

    /// Summary: zone count, total headers, latest epochs per zone.
    pub fn summary(&self) -> serde_json::Value {
        let zones: Vec<serde_json::Value> = self.headers.iter().map(|(zone, headers)| {
            serde_json::json!({
                "zone": zone.path(),
                "headers": headers.len(),
                "latest_epoch": headers.last().map(|h| h.epoch_number),
                "latest_root": headers.last().map(|h| hex::encode(h.merkle_root)),
            })
        }).collect();

        serde_json::json!({
            "zones": zones.len(),
            "total_headers": self.headers.values().map(|h| h.len()).sum::<usize>(),
            "zone_details": zones,
        })
    }
}

/// Generate a sparse Merkle proof of inclusion for a record within its zone.
///
/// SCALE FIX (Gap 4 Phase C2 follow-up): The previous implementation built a
/// flat MerkleTree over ALL records in the zone — an O(total_records) scan
/// that timed out on any node past ~100K records. It also produced a root
/// that did not match ANY sealed root, so the proof was unverifiable by
/// clients regardless of scale.
///
/// The scale- and verification-correct path is to use the same
/// [`super::merkle::SparseMerkleTree`] that epoch seals commit to via
/// `sparse_merkle_root`. Proof generation is O(depth ≤ 64) in RocksDB
/// reads and the resulting proof verifies directly against the zone's
/// current sparse root (which gets checkpointed into every seal).
///
/// Gap 4 Phase C2: `zone_registry` resolves the record's zone through the
/// active ZoneRegistry when `Some`, so proofs land in the correct post-split
/// leaf. `None` preserves the naive flat-modulo path for tests and
/// pre-split callers.
pub fn generate_proof(
    rocks: &crate::storage::rocks::StorageEngine,
    record_id: &str,
    zone_registry: Option<&super::zone_registry::ZoneRegistry>,
) -> crate::errors::Result<Option<(super::merkle::SparseMerkleProof, ZoneId)>> {
    use super::consensus::zone_for_record;
    use super::merkle::SparseMerkleTree;

    // Find the target record.
    let record = match rocks.get_record(record_id)? {
        Some(r) => r,
        None => return Ok(None),
    };

    // Use record_hash() (sha3 of signable_bytes) — this is what the SMT indexes.
    // NOT content_hash: the SMT insert in ingest.rs calls rec.record_hash(), and
    // epoch seals commit zone_root (the SMT root) which is keyed by record_hash.
    // content_hash = sha3(raw_content), record_hash = sha3(signable_bytes) — different.
    let record_hash = record.record_hash();

    // KR-3 S2 (c3-ii-2b): a rotation-hop's SMT leaf lives in its LINEAGE zone
    // (c3-i storage routing), so its proof must be built against that zone's
    // tree. This is a LOCAL, non-consensus path — this node holds the durable
    // `rotation_zone_pin` row iff it admitted the hop; flag-OFF there are no pin
    // rows, so `route_id == record_id` ⇒ byte-identical legacy behaviour.
    let route_id = rocks
        .get_rotation_zone_pin(record_id)
        .unwrap_or_else(|| record_id.to_string());
    // Resolve the record's zone through the registry (Phase C2 semantics).
    let zone = {
        let naive = zone_for_record(&route_id);
        if let Some(reg) = zone_registry {
            let rk = super::zone_registry::routing_key_for_record(&route_id);
            super::zone_registry::resolve_current_leaf(reg, &naive, &rk).resolved_zone
        } else {
            naive
        }
    };

    // O(depth) proof against the zone's current sparse Merkle root —
    // matches `sparse_merkle_root` in the zone's latest epoch seal.
    let tree = SparseMerkleTree::new(rocks, zone.clone());
    match tree.proof(&record_hash)? {
        Some(proof) => Ok(Some((proof, zone))),
        None => Ok(None),
    }
}

// ─── Light-client header sync loop (Gap 1) ───────────────────────────────────

/// Hard client-side ceiling on items accepted from one seed's `/checkpoints/from`
/// or `/headers/from` response. The server pages BOTH at 2000
/// (`compute_epoch_headers` does `limit.min(2000)`; checkpoints are pulled with
/// `Some(2000)`), so 4× headroom never false-rejects an honest seed while bounding
/// a hostile seed that ignores the limit and packs a 16-MiB `MAX_PAYLOAD` frame of
/// tiny objects — which would otherwise clone/parse into hundreds of MB on a
/// phone-tier cold-start before any downstream validation drops them.
const MAX_LIGHT_RESPONSE_ITEMS: usize = 8192; // 4× the 2000-per-page server cap
// Compile-time floor: keep the cap ≥ 2× the 2000-per-page server cap so an honest
// seed's full page is never false-rejected. Enforced on every build, not just tests.
const _: () = assert!(MAX_LIGHT_RESPONSE_ITEMS >= 2000 * 2);

/// Parse a peer `checkpoints` JSON array into marks, bounded to
/// `MAX_LIGHT_RESPONSE_ITEMS`. `take` precedes `parse_checkpoint_json` so a hostile
/// oversized array never drives an unbounded parse loop or `collect`; taking the
/// leading slice is safe because marks are cross-verified + deduplicated by
/// `(zone, end_epoch)` downstream, and an honest seed never returns > 2000.
fn parse_checkpoints_capped(arr: &[serde_json::Value]) -> Vec<CheckpointMark> {
    arr.iter()
        .take(MAX_LIGHT_RESPONSE_ITEMS)
        .filter_map(parse_checkpoint_json)
        .collect()
}

/// True when a `/headers/from` coverage response is too large to be a legitimate
/// single-zone super-seal cover. An honest seed returns ≤ `seal_count+1` headers
/// and a super-seal aggregates at most `SUPER_SEAL_INTERVAL` (=64) epoch seals, so
/// any response past a generous 16× headroom (1024) is a hostile/buggy seed packing
/// tiny objects into a 16-MiB `MAX_PAYLOAD` frame to balloon the coverage `hashes`
/// Vec (~5.5M × 32 B ≈ 176 MB) on a phone-tier cold-start. Rejected before the
/// allocation; the checkpoint is kept with `coverage_verified=false`.
fn coverage_headers_response_too_large(returned: usize) -> bool {
    const COVERAGE_HEADER_HEADROOM: u64 = 16;
    returned > (crate::network::epoch::SUPER_SEAL_INTERVAL * COVERAGE_HEADER_HEADROOM) as usize
}

/// Background loop for `NodeProfile::Light` nodes.
///
/// Periodically pulls `/headers/from/{epoch}` from seed peers, applies each
/// header via `LightState::add_header` (which enforces chain linking), and
/// updates `state.light_state`. Light nodes never ingest full records — this
/// loop is their entire sync story.
///
/// Scale:
///   - Each header is ~200 bytes. At 1M zones × 1 seal / 2 min = 8K headers/s
///     steady-state *globally*. A Light node following a handful of zones
///     (typical account workload) pulls tens-of-kB/s, not MB/s.
///   - `LightState.headers` is `O(verified_epochs_per_zone_followed)` —
///     trimmed to most-recent-N in a future pass (Gap 3 super-seals will let
///     us drop pre-checkpoint headers entirely).
///
/// @spec Protocol §11.3
pub async fn light_sync_loop(
    state: std::sync::Arc<super::state::NodeState>,
    mut shutdown: tokio::sync::mpsc::Receiver<()>,
) {
    use std::time::Duration;
    use tracing::{debug, info, warn};

    let interval = Duration::from_secs(state.config.gossip_pull_interval_secs.max(10));

    // Parse operator-configured zone whitelist once (ELARA_LIGHT_CLIENT_ZONES).
    // Empty = follow every zone the seed serves (original behaviour).
    let zone_whitelist: Vec<ZoneId> = state
        .config
        .light_client_zones
        .iter()
        .map(|s| ZoneId::new(s))
        .collect();

    if zone_whitelist.is_empty() {
        info!(
            "light_sync_loop starting (interval={}s, zones followed = all seals)",
            interval.as_secs()
        );
    } else {
        info!(
            "light_sync_loop starting (interval={}s, zone filter = {} zone(s): {:?})",
            interval.as_secs(),
            zone_whitelist.len(),
            zone_whitelist.iter().map(|z| z.path()).collect::<Vec<_>>(),
        );
    }

    // Resolve the cold-start trust-anchor set once (compiled-in ∪ config),
    // decoded from hex Dilithium3 pubkeys. Non-empty → super-seal checkpoints
    // are verified against these pinned keys via `verify_seal_record_against_anchor`
    // (AnchorPinned grade), and a super-seal signed by any non-anchor key is
    // dropped. Empty → cold-start keeps the legacy wire-key integrity check and
    // stamps Reference grade (single-seed trust). `enforce_mainnet_safety`
    // already refused the empty-set case for a mainnet light node.
    let trust_anchors: Vec<Vec<u8>> = crate::network::config::PINNED_GENESIS_AUTHORITY_PUBKEYS
        .iter()
        .map(|s| s.trim().to_string())
        .chain(
            state
                .config
                .light_client_trust_anchors
                .iter()
                .map(|s| s.trim().to_string()),
        )
        .filter(|s| !s.is_empty())
        .filter_map(|s| hex::decode(&s).ok())
        .collect();
    if trust_anchors.is_empty() {
        warn!(
            "light_sync_loop: NO trust anchor configured — cold-start checkpoints are \
             REFERENCE grade (single-seed trust, NOT trustless). Set ELARA_LIGHT_TRUST_ANCHORS \
             to the trusted sealer Dilithium3 pubkey(s) for anchor-pinned cold start."
        );
    } else {
        info!(
            "light_sync_loop: {} trust anchor(s) pinned — cold-start super-seals verified \
             against the anchor set (AnchorPinned grade)",
            trust_anchors.len(),
        );
    }

    loop {
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = shutdown.recv() => {
                debug!("light_sync_loop shutting down");
                return;
            }
        }

        // Stage 6 cooperative scheduler (Protocol §11.10): extra backoff
        // when host is saturated. Light sync downloads + verifies headers
        // — Dilithium3 sig verification is non-trivial; on a phone-tier
        // host we yield to ingest/seal first.
        super::system_load::coop_yield_if_busy(&state.system_load).await;

        // Pick any seed peer — Light nodes don't need DHT discovery (they
        // don't route, don't witness, don't seal). Seeds are enough.
        let seed_url = match state.config.seed_peers.first() {
            Some(u) => {
                // Normalize: seed_peers in config are typically bare `host:port`
                // strings. reqwest::Client::get() rejects scheme-less URLs with
                // a "builder error", spamming every gossip tick. Use the same
                // helper discovery uses so explicit schemes are honored.
                super::discovery::seed_base_url(u)
            }
            None => {
                warn!("light_sync_loop: no seed peers configured");
                continue;
            }
        };

        // Gap 3: cold-start checkpoint skip. On a fresh light node,
        // `/checkpoints/from/0` tells us the most-recent super-seal per
        // zone. We jump forward to `max(end_epoch) + 1` instead of
        // replaying every seal since genesis — 65× compression at N=64.
        // Only runs once per process: if the seed doesn't expose
        // checkpoints (pre-N-epochs network), we flip
        // `checkpoint_skip_attempted` and fall through to normal header
        // sync on every subsequent tick. Single-seed trust for now;
        // Dilithium3 sig verification of the super-seal record itself is
        // tracked as a follow-up.
        let should_try_checkpoint_skip = {
            let ls = match state.light_state.read() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            !ls.checkpoint_skip_attempted && ls.headers.is_empty()
        };

        if should_try_checkpoint_skip {
            let url = format!("{seed_url}/checkpoints/from/0?limit=2000");
            // 4E.5 flag-day: PQ-only checkpoints fetch. No HTTPS fallback —
            // if `pq_addr` cannot be derived or the PQ call fails, the loop
            // skips this seed and tries again next tick.
            let mut pq_body: Option<serde_json::Value> = None;
            // PQ-only checkpoints_from fetch. AUDIT-10 directive (2026-04-24):
            // no HTTPS fallback. `url` is kept for log context only.
            let _ = &url;
            if let Some(pq_addr) = super::gossip::http_to_pq_addr(
                &seed_url,
                state.config.pq_port_offset,
            ) {
                match state
                    .pq_client
                    .checkpoints_from(&pq_addr, 0, None, Some(2000))
                    .await
                {
                    Ok(v) => pq_body = Some(v),
                    Err(e) => debug!(
                        "light_sync_loop: pq checkpoints_from({pq_addr}) failed: {e}"
                    ),
                }
            } else {
                debug!("light_sync_loop: cannot derive PQ addr from {seed_url}");
            }
            let fetched: Option<serde_json::Value> = pq_body;

            let primary_marks: Vec<CheckpointMark> = fetched
                .as_ref()
                .and_then(|body| body.get("checkpoints").and_then(|v| v.as_array()))
                .map(|arr| parse_checkpoints_capped(arr))
                .unwrap_or_default();

            // Gap 3 pass 2: cross-verify against up to 2 other seeds. A
            // compromised primary that lies about `record_hash` is dropped
            // once any peer returns a different hash for the same
            // (zone, end_epoch). Other-peer silence is NOT a conflict —
            // they may be behind or not archive. Mirrors
            // `epoch_indexed_snapshot_bootstrap` in sync.rs.
            let other_seed_urls: Vec<String> = state
                .config
                .seed_peers
                .iter()
                .map(|u| super::discovery::seed_base_url(u))
                .filter(|u| u != &seed_url)
                .take(2)
                .collect();

            let mut other_bodies: Vec<serde_json::Value> = Vec::with_capacity(other_seed_urls.len());
            for other in &other_seed_urls {
                // PQ-only cross-verify fetch (AUDIT-10 directive 2026-04-24).
                // Skip the peer if it has no reachable PQ port.
                let Some(pq_addr) = super::gossip::http_to_pq_addr(
                    other,
                    state.config.pq_port_offset,
                ) else {
                    debug!("light_sync_loop: skipping cross-peer {other} (no PQ addr)");
                    continue;
                };
                match state
                    .pq_client
                    .checkpoints_from(&pq_addr, 0, None, Some(2000))
                    .await
                {
                    Ok(v) => other_bodies.push(v),
                    Err(e) => debug!(
                        "light_sync_loop: pq cross-peer checkpoints_from({pq_addr}) failed: {e}"
                    ),
                }
            }

            let (marks, dropped) = cross_verify_checkpoints(primary_marks, &other_bodies);
            if !dropped.is_empty() {
                warn!(
                    "light_sync_loop: cross-peer rejected {} checkpoint(s) from {seed_url} \
                     (record_hash disagreement): {:?}",
                    dropped.len(),
                    dropped,
                );
            }

            // Gap 3 pass 3: fetch the super-seal record wire bytes for each
            // cross-verified mark and verify Dilithium3 sig + record_hash
            // locally. Catches a colluding-seed scenario that pass 2 can't:
            // if every peer returns the same forged (zone, end_epoch,
            // record_hash) triple, cross-verify sees agreement and accepts.
            // The signed record itself is the one trust anchor the light
            // client can check without any peer's cooperation.
            //
            // Pass 3 returns `kept_with_wire: Vec<(mark, wire_bytes)>` so
            // pass 4 (coverage) can re-verify against fetched seal hashes
            // without re-fetching the super-seal record.
            let kept_with_wire: Vec<(CheckpointMark, Vec<u8>)> = if marks.is_empty() {
                Vec::new()
            } else {
                let ids: Vec<String> = marks.iter().map(|m| m.record_id.clone()).collect();
                // PQ-only fetch_records (AUDIT-10 directive 2026-04-24).
                let mut pq_wire: Option<Vec<String>> = None;
                if let Some(pq_addr) = super::gossip::http_to_pq_addr(
                    &seed_url,
                    state.config.pq_port_offset,
                ) {
                    match state.pq_client.fetch_records(&pq_addr, &ids).await {
                        Ok(bytes_list) => {
                            pq_wire = Some(
                                bytes_list.iter().map(hex::encode).collect()
                            );
                        }
                        Err(e) => debug!(
                            "light_sync_loop: pq fetch_records({pq_addr}) failed: {e}"
                        ),
                    }
                }
                // PQ failed (None) → no HTTPS fallback; keep original mark set
                // unverified at the record-bytes layer. The cross-peer signature
                // check (pass 2 above) still applies.
                let fetched_wire: Option<Vec<String>> = pq_wire;

                match fetched_wire {
                    Some(wire_list) => {
                        // Build id→wire map so marks match up by record_id
                        // regardless of the server's return order or gaps.
                        let mut by_id: HashMap<String, Vec<u8>> = HashMap::new();
                        for hx in &wire_list {
                            if let Ok(bytes) = hex::decode(hx) {
                                if let Ok(r) = crate::record::ValidationRecord::from_bytes(&bytes) {
                                    let id = r.id.clone();
                                    by_id.insert(id, bytes);
                                }
                            }
                        }

                        let mut kept: Vec<(CheckpointMark, Vec<u8>)> = Vec::with_capacity(marks.len());
                        let mut integrity_dropped: Vec<(String, u64, String)> = Vec::new();
                        for mut m in marks {
                            match by_id.get(&m.record_id) {
                                Some(bytes) => {
                                    // Anchor gate (pure seam: `classify_super_seal_trust`).
                                    // With a pinned set the super-seal's Dilithium3 sig is
                                    // verified against it via the audited
                                    // `verify_seal_record_against_anchor` primitive
                                    // (also used by the offline elara-verify CLI) →
                                    // AnchorPinned, hard-drop on any non-anchor signer.
                                    // Without a set, legacy wire-key integrity check →
                                    // Reference grade (single-seed trust).
                                    match classify_super_seal_trust(
                                        m.record_hash,
                                        bytes,
                                        &trust_anchors,
                                    ) {
                                        Ok(grade) => {
                                            m.trust_grade = grade;
                                            kept.push((m, bytes.clone()));
                                        }
                                        Err(e) => integrity_dropped.push((
                                            m.zone.to_string(),
                                            m.end_epoch,
                                            e,
                                        )),
                                    }
                                }
                                None => integrity_dropped.push((
                                    m.zone.to_string(),
                                    m.end_epoch,
                                    "record not returned by /records/fetch".to_string(),
                                )),
                            }
                        }
                        if !integrity_dropped.is_empty() {
                            warn!(
                                "light_sync_loop: integrity-rejected {} checkpoint(s) from \
                                 {seed_url} (Dilithium3/hash failure): {:?}",
                                integrity_dropped.len(),
                                integrity_dropped,
                            );
                        }
                        kept
                    }
                    None => {
                        // If the fetch fails outright, don't accept any
                        // checkpoint — we can't prove integrity without the
                        // wire bytes. Cold-start will retry next tick.
                        warn!(
                            "light_sync_loop: /records/fetch unavailable at {seed_url}, \
                             dropping {} unverified checkpoint(s) this tick",
                            marks.len(),
                        );
                        Vec::new()
                    }
                }
            };

            // Super-seal coverage verification.
            // For each integrity-passed checkpoint, fetch the
            // headers covering [start_epoch, end_epoch] for that zone,
            // extract `seal_record_hash` from each, and confirm the
            // super-seal's `merkle_root` reconstructs from those hashes
            // via `verify_super_seal_full`.
            //
            // Catches the threat pass 3 can't: a colluding seed pool that
            // signs a valid Dilithium3 super-seal but whose `merkle_root`
            // doesn't actually cover the seals it claims. Without coverage,
            // a light client trusting the integrity-only check is vulnerable
            // to that forge — the audit's "single-seed-trust" caveat.
            //
            // Mismatch → drop the checkpoint + bump
            // `super_seal_coverage_failures_total`. Operator pages on
            // sustained growth.
            //
            // Cost: one `headers_from(start-1, zone, seal_count+1)` per
            // accepted checkpoint at cold-start. At 64 zones × seal_count=64,
            // that's ~64 PQ calls per cold-start, one-time. Within phone-tier
            // budget; comparable to the existing pass-3 fetch_records call.
            let marks: Vec<CheckpointMark> = if kept_with_wire.is_empty() {
                Vec::new()
            } else {
                let mut accepted: Vec<CheckpointMark> = Vec::with_capacity(kept_with_wire.len());
                let mut coverage_dropped: Vec<(String, u64, String)> = Vec::new();
                let mut coverage_skipped: Vec<(String, u64, String)> = Vec::new();
                let pq_addr_opt = super::gossip::http_to_pq_addr(
                    &seed_url,
                    state.config.pq_port_offset,
                );
                for (mut mark, wire_bytes) in kept_with_wire {
                    // Need PQ addr for the headers_from call. If no PQ
                    // address (cannot happen post-AUDIT-10 on healthy seeds,
                    // but defensive), keep mark with coverage_verified=false.
                    let Some(pq_addr) = pq_addr_opt.as_ref() else {
                        coverage_skipped.push((
                            mark.zone.to_string(),
                            mark.end_epoch,
                            "no PQ addr for coverage fetch".to_string(),
                        ));
                        accepted.push(mark);
                        continue;
                    };
                    // Fetch headers covering [start_epoch, end_epoch]. Use
                    // since_epoch = start_epoch.saturating_sub(1) so the
                    // server's `epoch_number > since` filter returns
                    // start_epoch as the first row. `seal_count + 1` slop
                    // tolerates a one-off off-by-one on the server side.
                    let since = mark.start_epoch.saturating_sub(1);
                    let limit: usize = (mark.seal_count.saturating_add(1)) as usize;
                    let body: serde_json::Value = match state
                        .pq_client
                        .headers_from(
                            pq_addr,
                            since,
                            Some(mark.zone.path()),
                            Some(limit),
                        )
                        .await
                    {
                        Ok(v) => v,
                        Err(e) => {
                            coverage_skipped.push((
                                mark.zone.to_string(),
                                mark.end_epoch,
                                format!("headers_from failed: {e}"),
                            ));
                            // Defensive: keep the integrity-passed checkpoint
                            // so cold-start skip still works. coverage_verified
                            // stays false, and the loop will retry verification
                            // on a future tick if/when the headers become
                            // available via another seed.
                            accepted.push(mark);
                            continue;
                        }
                    };
                    let headers_arr = match body.get("headers").and_then(|v| v.as_array()) {
                        Some(a) => a,
                        None => {
                            coverage_skipped.push((
                                mark.zone.to_string(),
                                mark.end_epoch,
                                "no headers array in response".to_string(),
                            ));
                            accepted.push(mark);
                            continue;
                        }
                    };
                    // DoS guard: reject an oversized coverage response BEFORE the
                    // `hashes` allocation + per-header push loop below can balloon it.
                    // A 16-MiB MAX_PAYLOAD frame of tiny objects would otherwise drive
                    // ~176 MB on a phone-tier cold-start; an honest seed never returns
                    // more than seal_count+1 ≤ SUPER_SEAL_INTERVAL+1 headers.
                    if coverage_headers_response_too_large(headers_arr.len()) {
                        coverage_skipped.push((
                            mark.zone.to_string(),
                            mark.end_epoch,
                            format!(
                                "oversized headers response ({}) — DoS guard",
                                headers_arr.len()
                            ),
                        ));
                        accepted.push(mark);
                        continue;
                    }
                    // Filter to [start_epoch, end_epoch] and gather
                    // seal_record_hash. A header missing seal_record_hash
                    // (legacy emitter) blocks the coverage check for this
                    // checkpoint — keep with coverage_verified=false.
                    // Capacity is bounded to the already-materialized response
                    // (`headers_arr.len()`), NOT the peer-claimed `mark.seal_count`.
                    // `seal_count` is an unbounded u64 decoded straight off a peer's
                    // /checkpoints/from JSON (`parse_checkpoint_json`): a hostile or
                    // buggy seed claiming `seal_count = u64::MAX` would make
                    // `with_capacity(seal_count * 32B)` panic with "capacity overflow"
                    // (>isize::MAX), and a merely-large value (1e9 → 32 GB) OOM-aborts
                    // the cold-starting node. We push at most one hash per header, so
                    // the response length is the tight, network-bounded upper bound;
                    // `seal_count` is still validated against `hashes.len()` below.
                    let mut hashes: Vec<[u8; 32]> = Vec::with_capacity(headers_arr.len());
                    let mut missing_seal_hash = false;
                    // The seal_record_hash of the END_EPOCH header is the trusted
                    // baseline the first post-checkpoint header must chain to
                    // (set on the mark only after coverage verifies). Captured by
                    // matching epoch_number == end_epoch explicitly — the fetched
                    // header order is NOT guaranteed epoch-sorted, so hashes.last()
                    // would bind to an arbitrary epoch.
                    let mut baseline: Option<[u8; 32]> = None;
                    for h_val in headers_arr {
                        let Some(h) = parse_header_json(h_val) else { continue };
                        if h.zone != mark.zone {
                            continue;
                        }
                        if h.epoch_number < mark.start_epoch || h.epoch_number > mark.end_epoch {
                            continue;
                        }
                        match h.seal_record_hash {
                            Some(rh) => {
                                if h.epoch_number == mark.end_epoch {
                                    baseline = Some(rh);
                                }
                                hashes.push(rh);
                            }
                            None => {
                                missing_seal_hash = true;
                                break;
                            }
                        }
                    }
                    if missing_seal_hash {
                        coverage_skipped.push((
                            mark.zone.to_string(),
                            mark.end_epoch,
                            "header missing seal_record_hash (legacy emitter)".to_string(),
                        ));
                        accepted.push(mark);
                        continue;
                    }
                    if (hashes.len() as u64) != mark.seal_count {
                        coverage_skipped.push((
                            mark.zone.to_string(),
                            mark.end_epoch,
                            format!(
                                "header count {} != seal_count {} (gap in fetched range)",
                                hashes.len(),
                                mark.seal_count,
                            ),
                        ));
                        accepted.push(mark);
                        continue;
                    }
                    match verify_super_seal_full(mark.record_hash, &wire_bytes, &hashes) {
                        Ok(()) => {
                            mark.coverage_verified = true;
                            // Bind the trusted baseline for the first
                            // post-checkpoint header (add_header chain-link root).
                            // None only if the end_epoch header was absent from the
                            // fetched range — then add_header falls back to
                            // best-effort accept.
                            mark.baseline_seal_hash = baseline;
                            accepted.push(mark);
                        }
                        Err(e) => {
                            // Coverage explicitly rejected: drop this
                            // checkpoint + bump operator-paging counter.
                            // This is the audit's "single-seed-trust"
                            // close: the seeds signed a forged aggregate
                            // and we caught it.
                            state
                                .super_seal_coverage_failures_total
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            coverage_dropped.push((
                                mark.zone.to_string(),
                                mark.end_epoch,
                                e,
                            ));
                        }
                    }
                }
                if !coverage_dropped.is_empty() {
                    warn!(
                        "light_sync_loop: COVERAGE-rejected {} checkpoint(s) from \
                         {seed_url} (forged super-seal merkle_root): {:?}",
                        coverage_dropped.len(),
                        coverage_dropped,
                    );
                }
                if !coverage_skipped.is_empty() {
                    debug!(
                        "light_sync_loop: coverage check skipped for {} checkpoint(s) \
                         (kept with coverage_verified=false): {:?}",
                        coverage_skipped.len(),
                        coverage_skipped,
                    );
                }
                accepted
            };

            let mut ls = match state.light_state.write() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            let mark_count = marks.len();
            for m in marks {
                let keep = ls
                    .checkpoints
                    .get(&m.zone)
                    .map(|existing| m.end_epoch > existing.end_epoch)
                    .unwrap_or(true);
                if keep {
                    ls.checkpoints.insert(m.zone.clone(), m);
                }
            }
            let max_end = ls.checkpoints.values().map(|m| m.end_epoch).max().unwrap_or(0);
            ls.checkpoint_skip_attempted = true;
            drop(ls);

            if mark_count > 0 {
                info!(
                    "light_sync_loop: checkpoint skip accepted {mark_count} zones \
                     (cross-verified against {} peer(s)), max_end_epoch={max_end} — \
                     skipping genesis replay",
                    other_bodies.len(),
                );
            } else {
                debug!("light_sync_loop: no checkpoints available at {seed_url} (normal sync)");
            }
        }

        // Per-zone resume: the previous global `max(epoch_number) + 1`
        // approach interleaved headers from multiple zones in one
        // response, breaking add_header's per-zone chain check whenever
        // a slower zone's epochs trailed a faster zone's. Symptom in the
        // wild (Hillsboro, 2026-04-19): first batch 500/0 accept,
        // second 250/250 reject. Switch to a per-zone since_epoch and
        // pull each zone independently — responses are now single-zone,
        // ordered, and chain-link cleanly. Cold start (no zones known)
        // returns a single (None, 0) entry so we can discover what
        // zones the seed serves.
        let zone_pulls: Vec<(Option<ZoneId>, u64)> = {
            let ls = match state.light_state.read() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            ls.compute_zone_pulls_filtered(&zone_whitelist)
        };
        let cold_start = zone_pulls.iter().all(|(_, since)| *since == 0);
        let pull_count = zone_pulls.len();

        // AUDIT-10 Milestone C: PQ-only. No HTTPS fallback. If the PQ
        // address can't be derived or the PQ call fails, skip this seed —
        // we don't downgrade to harvest-now-decrypt-later transport.
        let pq_addr = match super::gossip::http_to_pq_addr(
            &seed_url,
            state.config.pq_port_offset,
        ) {
            Some(a) => a,
            None => {
                debug!("light_sync_loop: no PQ addr for {seed_url}, skipping");
                continue;
            }
        };

        let mut total_added = 0usize;
        let mut total_rejected = 0usize;
        for (zone_opt, since_epoch) in zone_pulls {
            let zone_path: Option<String> = zone_opt.as_ref().map(|z| z.path().to_string());
            let body: serde_json::Value = match state
                .pq_client
                .headers_from(
                    &pq_addr,
                    since_epoch,
                    zone_path.as_deref(),
                    None,
                )
                .await
            {
                Ok(v) => v,
                Err(e) => {
                    warn!(
                        "light_sync_loop: PQ headers_from({pq_addr}, zone={:?}, since={}) failed: {e}",
                        zone_path,
                        since_epoch,
                    );
                    continue;
                }
            };
            let headers_json = match body.get("headers").and_then(|v| v.as_array()) {
                Some(a) if a.len() > MAX_LIGHT_RESPONSE_ITEMS => {
                    // DoS guard: reject BEFORE `a.clone()` materializes the whole
                    // peer array. The server pages at 2000; a response past 8192 is a
                    // hostile seed packing tiny objects into a 16-MiB frame, which
                    // would otherwise clone hundreds of MB before parse_header_json
                    // drops them. Skip this pull — the watermark is unchanged so an
                    // honest reload from another seed still advances. Reject (not
                    // truncate): the array may be unsorted, so a leading slice could
                    // drop the contiguous epochs add_header needs.
                    warn!(
                        "light_sync_loop: oversized headers response ({}) from {seed_url} \
                         zone={:?} — DoS guard, skipping pull",
                        a.len(), zone_path,
                    );
                    continue;
                }
                Some(a) => a.clone(),
                None => {
                    debug!(
                        "light_sync_loop: no headers in response (zone={:?}, since={since_epoch})",
                        zone_path,
                    );
                    continue;
                }
            };

            // Defensive client-side group + sort by (zone, epoch ASC).
            // Server already does this for the indexed path, but a
            // legacy or pre-fix server might return interleaved data;
            // sorting client-side keeps add_header's chain check robust
            // even if the server's contract drifts.
            let mut parsed: Vec<EpochHeader> = headers_json
                .iter()
                .filter_map(parse_header_json)
                .collect();
            parsed.sort_by(|a, b| {
                a.zone
                    .path()
                    .cmp(b.zone.path())
                    .then_with(|| a.epoch_number.cmp(&b.epoch_number))
            });

            let mut added = 0usize;
            let mut rejected = 0usize;
            {
                let mut ls = match state.light_state.write() {
                    Ok(g) => g,
                    Err(p) => p.into_inner(),
                };
                for header in parsed {
                    // Client-side zone guard: if a whitelist is configured, drop
                    // headers for zones we didn't ask for. A conforming seed only
                    // returns the requested zone, but a legacy or misbehaving seed
                    // might return extras — silently ignoring them keeps LightState
                    // bounded to O(epochs_per_followed_zone) at 1M-zone scale.
                    if !zone_whitelist.is_empty()
                        && !zone_whitelist.contains(&header.zone)
                    {
                        debug!(
                            "light_sync_loop: dropping header for non-whitelisted zone {:?}",
                            header.zone.path(),
                        );
                        rejected += 1;
                        continue;
                    }
                    match ls.add_header(header) {
                        Ok(()) => added += 1,
                        Err(e) => {
                            debug!("light_sync_loop: add_header rejected: {e}");
                            rejected += 1;
                        }
                    }
                }
            }
            total_added += added;
            total_rejected += rejected;
            if added > 0 {
                debug!(
                    "light_sync_loop: zone={:?} since={} added={} rejected={}",
                    zone_path, since_epoch, added, rejected,
                );
            }
        }

        if total_added > 0 {
            info!(
                "light_sync_loop: +{} headers across {} pull(s) (rejected {}, cold_start={})",
                total_added,
                pull_count,
                total_rejected,
                cold_start,
            );
        }
    }
}

/// Parse a JSON header (as emitted by `/epochs/headers`) into an `EpochHeader`.
/// Returns `None` if any required field is missing or malformed. `pub(crate)`
/// so the decoder-fuzz sweep can drive it with hostile seed responses.
pub(crate) fn parse_header_json(v: &serde_json::Value) -> Option<EpochHeader> {
    let zone_val = v.get("zone")?;
    let zone: ZoneId = if let Some(s) = zone_val.as_str() {
        ZoneId::new(s)
    } else if let Some(n) = zone_val.as_u64() {
        ZoneId::from_legacy(n)
    } else {
        return None;
    };
    let epoch_number = v.get("epoch_number")?.as_u64()?;
    let merkle_root = decode_hex32(v.get("merkle_root")?.as_str()?)?;
    let previous_seal_hash = decode_hex32(v.get("previous_seal_hash")?.as_str()?)?;
    let record_count = v.get("record_count")?.as_u64()?;
    let start = v.get("start")?.as_f64()?;
    let end = v.get("end")?.as_f64()?;
    let account_smt_root = v.get("account_smt_root")
        .and_then(|a| a.as_str())
        .and_then(decode_hex32);
    let seal_record_hash = v.get("seal_record_hash")
        .and_then(|a| a.as_str())
        .and_then(decode_hex32);

    Some(EpochHeader {
        zone, epoch_number, merkle_root, previous_seal_hash,
        record_count, start, end, account_smt_root, seal_record_hash,
    })
}

/// Parse a single checkpoint entry from `/checkpoints/from/{epoch}` into a
/// [`CheckpointMark`]. Returns `None` if a required field is missing or
/// malformed. `committee_hash` defaults to `[0u8; 32]` when absent (legacy
/// super-seals predating the committee-hash follow-up).
pub fn parse_checkpoint_json(v: &serde_json::Value) -> Option<CheckpointMark> {
    let zone_str = v.get("zone")?.as_str()?;
    let start_epoch = v.get("start_epoch")?.as_u64()?;
    let end_epoch = v.get("end_epoch")?.as_u64()?;
    if end_epoch < start_epoch {
        return None;
    }
    let seal_count = v.get("seal_count")?.as_u64()?;
    let record_id = v.get("record_id")?.as_str()?.to_string();
    let record_hash = decode_hex32(v.get("record_hash")?.as_str()?)?;
    let committee_hash = v
        .get("committee_hash")
        .and_then(|x| x.as_str())
        .and_then(decode_hex32)
        .unwrap_or([0u8; 32]);
    Some(CheckpointMark {
        zone: ZoneId::new(zone_str),
        start_epoch,
        end_epoch,
        seal_count,
        record_id,
        record_hash,
        committee_hash,
        coverage_verified: false,
        // Stamped at the integrity gate (anchor-pinned vs reference) and the
        // coverage pass (baseline) in `light_sync_loop`; safe defaults here.
        trust_grade: TrustGrade::Reference,
        baseline_seal_hash: None,
    })
}

/// Pure helper: given a `/checkpoints/from/{epoch}` response body, return
/// the highest `end_epoch` across all checkpoints — the epoch a light
/// client should skip to. Returns `None` if the body has no checkpoints.
pub fn pick_checkpoint_skip_epoch(body: &serde_json::Value) -> Option<u64> {
    body.get("checkpoints")?
        .as_array()?
        .iter()
        .filter_map(|c| c.get("end_epoch").and_then(|v| v.as_u64()))
        .max()
}

/// Gap 3 pass 3: verify a fetched super-seal record against the
/// expected `record_hash` from a checkpoint.
///
/// The cross-peer `cross_verify_checkpoints` step only protects against
/// **disagreement** between seeds. If a single seed (or a colluding set
/// of seeds) all return the same forged `record_hash`, cross-verify
/// can't catch it — every peer agrees, so the client skips forward into
/// the forged branch. The final line of defence is to fetch the RECORD
/// itself, recompute its content hash, and verify the creator's
/// Dilithium3 signature.
///
/// Returns `Ok(())` only if **all** checks pass:
///   1. `wire_bytes` deserialize into a [`ValidationRecord`].
///   2. `rec.record_hash() == expected_record_hash` — otherwise the
///      seeds handed us a record that doesn't match the checkpoint.
///   3. `rec.signature` is present (no unsigned super-seals accepted).
///   4. `dilithium3_verify(signable_bytes, signature, creator_public_key)`
///      returns `Ok(true)`.
///
/// This is a PURE function: the caller fetches `wire_bytes` via
/// `/records/fetch`; the helper only does local decode + crypto so the
/// trust decision stays unit-testable.
///
/// @spec Protocol §11.3, §11.12 (super-seal signature integrity)
pub fn verify_super_seal_record_integrity(
    expected_record_hash: [u8; 32],
    wire_bytes: &[u8],
) -> std::result::Result<(), String> {
    let rec = crate::record::ValidationRecord::from_bytes(wire_bytes)
        .map_err(|e| format!("wire decode: {e}"))?;
    let actual = rec.record_hash();
    if actual != expected_record_hash {
        return Err(format!(
            "record_hash mismatch: expected {} actual {}",
            hex::encode(expected_record_hash),
            hex::encode(actual),
        ));
    }
    let sig = rec
        .signature
        .as_ref()
        .ok_or_else(|| "record has no Dilithium3 signature".to_string())?;
    if rec.creator_public_key.is_empty() {
        return Err("record has empty creator_public_key".to_string());
    }
    let signable = rec.signable_bytes();
    let ok = crate::crypto::pqc::dilithium3_verify(&signable, sig, &rec.creator_public_key)
        .map_err(|e| format!("dilithium3 verify error: {e}"))?;
    if !ok {
        return Err("dilithium3 signature invalid".to_string());
    }
    Ok(())
}

/// Classify a cold-start super-seal's integrity and the [`TrustGrade`] it earns,
/// given the resolved cold-start anchor set. Pure decision seam extracted from
/// `light_sync_loop` so the branch selection and grade stamping are unit-pinnable
/// independent of the async loop — the soundness-critical signature/anchor checks
/// themselves live in the two verifiers this dispatches to, each separately
/// tested (`light_verify::anchor_verify_*`, super-seal integrity tests).
///
/// - Non-empty `trust_anchors`: the super-seal's Dilithium3 signature is verified
///   against the pinned anchor keys via the audited
///   [`crate::light_verify::verify_seal_record_against_anchor`] primitive (the
///   same check the offline `elara-verify` CLI runs). `Ok(AnchorPinned)` on a
///   match; `Err` (caller drops the checkpoint) on any non-anchor signer.
/// - Empty `trust_anchors`: falls back to the legacy wire-key integrity check
///   ([`verify_super_seal_record_integrity`]) and earns the honestly-labelled
///   `Reference` grade — single-seed trust, NOT trustless.
fn classify_super_seal_trust(
    record_hash: [u8; 32],
    wire_bytes: &[u8],
    trust_anchors: &[Vec<u8>],
) -> std::result::Result<TrustGrade, String> {
    if trust_anchors.is_empty() {
        verify_super_seal_record_integrity(record_hash, wire_bytes).map(|()| TrustGrade::Reference)
    } else {
        crate::light_verify::verify_seal_record_against_anchor(
            wire_bytes,
            record_hash,
            trust_anchors,
        )
        .map(|()| TrustGrade::AnchorPinned)
        .map_err(|e| e.to_string())
    }
}

/// Combined integrity + coverage verification of a super-seal.
///
/// Layers two distinct trust checks:
///   1. `verify_super_seal_record_integrity`: record bytes round-trip,
///      `record_hash` matches, Dilithium3 sig is valid against the
///      creator's public key. Catches a single seed substituting a
///      forged record body.
///   2. `epoch::verify_super_seal_coverage`: the supplied `seal_hashes`
///      Merkle-roll up to the super-seal's claimed `merkle_root`.
///      Catches a colluding seed pool that signs a forged aggregate
///      whose `merkle_root` doesn't actually cover the seals it claims.
///
/// Without (2), a light client trusts the super-seal's `merkle_root` on
/// the strength of one Dilithium3 sig alone — the single-seed-trust
/// caveat. With (2), forging the aggregate requires also forging
/// every constituent seal record (or at least their content hashes),
/// which the chain-link check at `add_header` then catches independently.
///
/// Pure function: caller supplies wire bytes (already fetched via
/// `/records/fetch`) and seal hashes (gathered from the `seal_record_hash`
/// field of the `EpochHeader`s for `[start_epoch, end_epoch]`). No I/O,
/// no mutation — keeps the trust decision unit-testable.
///
/// Returns `Ok(())` only if BOTH checks pass. Errors are tagged so the
/// caller can attribute the rejection (integrity vs. coverage) when
/// bumping `super_seal_coverage_failures_total`.
///
/// @spec Protocol §11.12 (super-seal aggregation)
pub fn verify_super_seal_full(
    expected_record_hash: [u8; 32],
    wire_bytes: &[u8],
    seal_hashes: &[[u8; 32]],
) -> std::result::Result<(), String> {
    verify_super_seal_record_integrity(expected_record_hash, wire_bytes)?;

    let rec = crate::record::ValidationRecord::from_bytes(wire_bytes)
        .map_err(|e| format!("wire decode: {e}"))?;
    let parsed = match super::epoch::extract_super_seal(&rec) {
        Ok(Some(p)) => p,
        Ok(None) => {
            return Err(
                "record is not a super-seal (no epoch_op=super_seal metadata)".to_string()
            );
        }
        Err(e) => return Err(format!("super-seal meta extract: {e}")),
    };

    if !super::epoch::verify_super_seal_coverage(&parsed, seal_hashes) {
        return Err(format!(
            "merkle coverage mismatch: super-seal claims merkle_root={} over {} seals, \
             {} hashes supplied",
            hex::encode(parsed.merkle_root),
            parsed.seal_count,
            seal_hashes.len(),
        ));
    }
    Ok(())
}

/// Gap 3 cross-peer verification: reject any primary checkpoint that a
/// second seed disagrees with on `record_hash`.
///
/// Protocol §11.12 (super-seal consolidation): a light client that trusts
/// one seed's checkpoint opens a single-point-of-trust vulnerability — a
/// compromised or lying seed can jump the client forward into a forged
/// branch. Same pattern as `epoch_indexed_snapshot_bootstrap` in
/// `sync.rs` (Gap 7 cross-peer checksum match).
///
/// Rules:
///   - If any other seed returns the **same** `(zone, end_epoch)` with a
///     **different** `record_hash` → drop that primary mark. Fork signal.
///   - Other seeds missing that `(zone, end_epoch)` are NOT a conflict
///     (they may be behind, not archive nodes, or pruned).
///   - Primary marks no other seed has ANY opinion on are kept (accepted
///     on single-seed trust — unavoidable at cold start when only one
///     seed answers). This matches Gap 7's degenerate-network behaviour.
///
/// Returns `(kept, dropped_zones)` so callers can log the rejection.
///
/// Pure function: takes only parsed data, makes no I/O calls — callers
/// do the HTTP fetches and hand the bodies in. This keeps the trust
/// decision deterministic and unit-testable.
pub fn cross_verify_checkpoints(
    primary: Vec<CheckpointMark>,
    other_bodies: &[serde_json::Value],
) -> (Vec<CheckpointMark>, Vec<(ZoneId, u64)>) {
    // Collect (zone, end_epoch) -> record_hash from each other seed.
    // A mismatch is any body that maps (zone, end_epoch) to a hash
    // different from the primary's.
    let others_marks: Vec<Vec<CheckpointMark>> = other_bodies
        .iter()
        .map(|body| {
            body.get("checkpoints")
                .and_then(|v| v.as_array())
                .map(|arr| parse_checkpoints_capped(arr))
                .unwrap_or_default()
        })
        .collect();

    let mut kept: Vec<CheckpointMark> = Vec::with_capacity(primary.len());
    let mut dropped: Vec<(ZoneId, u64)> = Vec::new();

    for p in primary {
        let mut conflict = false;
        for other in &others_marks {
            for o in other {
                if o.zone == p.zone && o.end_epoch == p.end_epoch && o.record_hash != p.record_hash
                {
                    conflict = true;
                    break;
                }
            }
            if conflict {
                break;
            }
        }
        if conflict {
            dropped.push((p.zone.clone(), p.end_epoch));
        } else {
            kept.push(p);
        }
    }

    (kept, dropped)
}

fn decode_hex32(s: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(s).ok()?;
    if bytes.len() != 32 { return None; }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

/// Build an EpochHeader from a ParsedEpochSeal. The caller should set
/// `seal_record_hash` afterwards (or use `header_from_seal_with_hash`)
/// — the parsed seal alone doesn't carry the seal record's content hash.
pub fn header_from_seal(seal: &super::epoch::ParsedEpochSeal) -> EpochHeader {
    EpochHeader {
        zone: seal.zone.clone(),
        epoch_number: seal.epoch_number,
        merkle_root: seal.merkle_root,
        previous_seal_hash: seal.previous_seal_hash,
        record_count: seal.record_count,
        start: seal.start,
        end: seal.end,
        account_smt_root: seal.account_smt_root,
        seal_record_hash: None,
    }
}

/// Build an EpochHeader from a parsed seal plus the seal record's content
/// hash (`Record::record_hash()`). This is the variant the HTTP endpoint
/// should use so light clients can chain-verify subsequent headers.
pub fn header_from_seal_with_hash(
    seal: &super::epoch::ParsedEpochSeal,
    seal_record_hash: [u8; 32],
) -> EpochHeader {
    let mut h = header_from_seal(seal);
    h.seal_record_hash = Some(seal_record_hash);
    h
}

/// Gap 1 SDK helper: Verify an account-state proof against a signed epoch
/// header.
///
/// The proof itself verifies inclusion of `(account_id, state_hash)` under
/// `proof.root`. This helper additionally binds the proof to a signed header
/// by requiring `header.account_smt_root == proof.root`.
///
/// Returns `true` only if:
///   1. `header.account_smt_root` is `Some` (i.e. header came from a Gap 1+
///      seal — legacy pre-Gap 1 seals lack account binding and MUST NOT
///      be trusted for balance verification).
///   2. `header.account_smt_root == proof.root`.
///   3. The proof's siblings reconstruct `proof.root` from `proof.state_hash`
///      along the path derived from `proof.account_id`.
///
/// Used by light-client SDKs: fetch proof via `/proof/account/{id}`, fetch
/// latest header via `/epochs/headers` or `/headers/from/{epoch}`, then call
/// this helper to confirm balance-as-of-sealed-state.
pub fn verify_account_proof_against_header(
    proof: &super::account_merkle::AccountStateProof,
    header: &EpochHeader,
) -> bool {
    let signed_root = match header.account_smt_root {
        Some(r) => r,
        None => return false, // pre-Gap 1 header — cannot bind
    };
    if proof.root != signed_root {
        return false;
    }
    super::account_merkle::verify_proof(proof)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hash::sha3_256;

    /// §9 (c3-ii-2b): `generate_proof` serves a rotation hop's proof from its
    /// pinned LINEAGE zone's SMT (where c3-i storage-routing placed the leaf),
    /// and from the naive record-id zone when there is NO pin row — the
    /// flag-OFF / non-rotation byte-identical path. Same one-line
    /// `get_rotation_zone_pin(record_id).unwrap_or(record_id)` substitution that
    /// `merkle::generate_cross_zone_proof` uses (that path additionally needs a
    /// seeded seal to expose `source_zone`, so the substitution is exercised here).
    #[test]
    fn generate_proof_routes_by_rotation_zone_pin() {
        use crate::crypto::hash::sha3_256_hex;
        use crate::network::consensus::{set_zone_count, zone_for_record};
        use crate::network::merkle::SparseMerkleTree;
        use crate::record::{Classification, ValidationRecord};
        use crate::storage::rocks::StorageEngine;

        set_zone_count(8);
        let dir = tempfile::tempdir().unwrap();
        let rocks = StorageEngine::open(dir.path().join("r")).unwrap();

        let rec = ValidationRecord::create(
            b"c",
            b"pk0".to_vec(),
            vec![],
            Classification::Public,
            None,
        );
        rocks.put_record(&rec.id, &rec).unwrap();
        let leaf = rec.record_hash();
        let naive_zone = zone_for_record(&rec.id);

        // A fabricated lineage whose zone differs from the naive record-id zone,
        // so routing by lineage is observably different.
        let lineage = (0..2000)
            .map(|i| sha3_256_hex(format!("lin-{i}").as_bytes()))
            .find(|c| zone_for_record(c) != naive_zone)
            .expect("a differing-zone lineage exists");
        let lineage_zone = zone_for_record(&lineage);

        // Case A — NO pin row: the leaf lives in the naive zone, proof served there.
        {
            let mut t = SparseMerkleTree::new(&rocks, naive_zone.clone());
            t.insert(&leaf).unwrap();
            t.commit().unwrap();
            let (_, z) = generate_proof(&rocks, &rec.id, None)
                .unwrap()
                .expect("proof from naive zone");
            assert_eq!(z, naive_zone, "no pin ⇒ naive record-id zone (byte-identical)");
        }

        // Case B — pin present: the leaf lives in the LINEAGE zone, proof served there.
        {
            let mut t = SparseMerkleTree::new(&rocks, lineage_zone.clone());
            t.insert(&leaf).unwrap();
            t.commit().unwrap();
            rocks.pin_rotation_zone_for_test(&rec.id, &lineage).unwrap();
            let (_, z) = generate_proof(&rocks, &rec.id, None)
                .unwrap()
                .expect("proof from lineage zone");
            assert_eq!(z, lineage_zone, "pin row ⇒ lineage zone");
        }
    }

    #[test]
    fn coverage_headers_response_oversized_is_rejected() {
        use crate::network::epoch::SUPER_SEAL_INTERVAL;
        let cap = (SUPER_SEAL_INTERVAL * 16) as usize; // 1024
        // Honest: a single-zone super-seal cover is ≤ seal_count+1 ≤ 65 headers.
        assert!(!coverage_headers_response_too_large(0));
        assert!(!coverage_headers_response_too_large(65));
        assert!(!coverage_headers_response_too_large(cap)); // exactly at cap = allowed
        // Malicious: millions of tiny `{}` objects packed into one 16-MiB frame —
        // this is what would balloon the coverage `hashes` Vec before the count check.
        assert!(coverage_headers_response_too_large(cap + 1));
        assert!(coverage_headers_response_too_large(5_000_000));
        // Headroom must comfortably exceed any legit single-zone cover.
        assert!(
            cap > (SUPER_SEAL_INTERVAL as usize) + 1,
            "cap must exceed the max honest response"
        );
    }

    #[test]
    fn parse_checkpoints_capped_bounds_oversized_array() {
        // Valid checkpoint JSON, same shape as test_parse_checkpoint_json_roundtrip.
        let mk = |i: u64| {
            serde_json::json!({
                "zone": format!("z{i}"),
                "start_epoch": 0,
                "end_epoch": 63,
                "seal_count": 64,
                "merkle_root": hex::encode([0u8; 32]),
                "record_id": format!("super_seal:z{i}:0-63"),
                "record_hash": hex::encode(sha3_256(format!("rh{i}").as_bytes())),
                "committee_hash": hex::encode(sha3_256(b"c")),
            })
        };
        // Oversized array of VALID checkpoints (a hostile seed ignoring the 2000
        // server page) is bounded to the cap — proves `take` precedes the parse.
        let oversized: Vec<serde_json::Value> =
            (0..(MAX_LIGHT_RESPONSE_ITEMS as u64 + 500)).map(mk).collect();
        assert_eq!(
            parse_checkpoints_capped(&oversized).len(),
            MAX_LIGHT_RESPONSE_ITEMS,
            "oversized valid array must cap to MAX_LIGHT_RESPONSE_ITEMS"
        );
        // An honest-sized response (≤ the 2000 server page) passes through whole.
        let honest: Vec<serde_json::Value> = (0..2000).map(mk).collect();
        assert_eq!(parse_checkpoints_capped(&honest).len(), 2000);
    }

    fn make_header(zone: impl Into<ZoneId>, epoch: u64, prev_hash: [u8; 32]) -> EpochHeader {
        let zone: ZoneId = zone.into();
        // Deterministic per-(zone, epoch) stand-in for the real seal record
        // content hash. Tests use this to build valid chains:
        //     h_next.previous_seal_hash = mock_seal_hash(zone, epoch)
        let seal_record_hash = Some(sha3_256(format!("seal_hash_{zone}_{epoch}").as_bytes()));
        EpochHeader {
            zone: zone.clone(),
            epoch_number: epoch,
            merkle_root: sha3_256(format!("root_{zone}_{epoch}").as_bytes()),
            previous_seal_hash: prev_hash,
            record_count: 10,
            start: epoch as f64 * 100.0,
            end: (epoch + 1) as f64 * 100.0,
            account_smt_root: None,
            seal_record_hash,
        }
    }

    fn mock_seal_hash(zone: &ZoneId, epoch: u64) -> [u8; 32] {
        sha3_256(format!("seal_hash_{zone}_{epoch}").as_bytes())
    }

    // ── First-header baseline bind (cold-start anchor-trust close) ────────────

    fn cp_with_baseline(zone: &ZoneId, end_epoch: u64, baseline: Option<[u8; 32]>) -> CheckpointMark {
        CheckpointMark {
            zone: zone.clone(),
            start_epoch: end_epoch.saturating_sub(63),
            end_epoch,
            seal_count: 64,
            record_id: format!("ss:{zone}:{end_epoch}"),
            record_hash: [1u8; 32],
            committee_hash: [0u8; 32],
            coverage_verified: true,
            trust_grade: TrustGrade::AnchorPinned,
            baseline_seal_hash: baseline,
        }
    }

    #[test]
    fn first_post_checkpoint_header_chaining_to_anchored_baseline_is_accepted() {
        // An anchor-verified checkpoint at end_epoch=100 with a known baseline.
        // The first header (epoch 101) whose previous_seal_hash equals the
        // baseline is accepted — the header chain roots in the pinned anchor.
        let mut state = LightState::new();
        let zone = ZoneId::from_legacy(2);
        let baseline = mock_seal_hash(&zone, 100);
        state
            .checkpoints
            .insert(zone.clone(), cp_with_baseline(&zone, 100, Some(baseline)));
        let h = make_header(zone.clone(), 101, baseline);
        assert!(
            state.add_header(h).is_ok(),
            "first header chaining to the anchored baseline must be accepted",
        );
    }

    #[test]
    fn first_post_checkpoint_header_with_wrong_prev_hash_is_rejected_forged_branch() {
        // The kill-shot: a forged first header whose previous_seal_hash does NOT
        // match the anchored baseline must be rejected. Without this bind a
        // single malicious cold-start seed could inject an arbitrary baseline
        // header and fork the client forward (every later header chains cleanly
        // off the forgery). This is the core soundness close.
        let mut state = LightState::new();
        let zone = ZoneId::from_legacy(2);
        let baseline = mock_seal_hash(&zone, 100);
        state
            .checkpoints
            .insert(zone.clone(), cp_with_baseline(&zone, 100, Some(baseline)));
        let forged = make_header(zone.clone(), 101, [0xABu8; 32]);
        let err = state
            .add_header(forged)
            .expect_err("forged-branch first header must be rejected");
        assert!(
            err.contains("does not match the anchored checkpoint baseline"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn first_post_checkpoint_header_with_epoch_gap_is_rejected() {
        // First post-checkpoint header must be exactly end_epoch + 1.
        let mut state = LightState::new();
        let zone = ZoneId::from_legacy(2);
        let baseline = mock_seal_hash(&zone, 100);
        state
            .checkpoints
            .insert(zone.clone(), cp_with_baseline(&zone, 100, Some(baseline)));
        let gap = make_header(zone.clone(), 102, baseline);
        let err = state
            .add_header(gap)
            .expect_err("epoch-gap first header must be rejected");
        assert!(err.contains("expected 101"), "unexpected error: {err}");
    }

    #[test]
    fn first_header_with_unknown_baseline_falls_back_to_best_effort_accept() {
        // A coverage-skipped checkpoint (baseline None — legacy emitter / no PQ
        // addr) must NOT brick the zone: the first header is accepted
        // best-effort, mirroring the legacy mid-chain-start behaviour. The
        // checkpoint is honestly Reference-grade in that case.
        let mut state = LightState::new();
        let zone = ZoneId::from_legacy(2);
        state
            .checkpoints
            .insert(zone.clone(), cp_with_baseline(&zone, 100, None));
        let h = make_header(zone.clone(), 101, [0x77u8; 32]);
        assert!(
            state.add_header(h).is_ok(),
            "unknown-baseline first header must best-effort accept (no brick)",
        );
    }

    #[test]
    fn first_header_with_no_checkpoint_best_effort_accepts_mid_chain_start() {
        // No checkpoint at all (pure mid-chain start) — unchanged legacy
        // behaviour, the baseline bind only fires when a checkpoint exists.
        let mut state = LightState::new();
        let zone = ZoneId::from_legacy(2);
        let h = make_header(zone.clone(), 500, [0x11u8; 32]);
        assert!(
            state.add_header(h).is_ok(),
            "no-checkpoint first header must accept (mid-chain start)",
        );
    }

    // ── Cold-start anchor gate decision seam (`classify_super_seal_trust`) ────
    //
    // The soundness-critical signature/anchor checks are pinned in
    // `light_verify::anchor_verify_*` and the super-seal integrity tests. These
    // pin the GATE WIRING the async `light_sync_loop` relies on: that the right
    // verifier is dispatched for the anchor-set state and the right TrustGrade is
    // stamped. A regression stamping AnchorPinned on a Reference-grade seal (or
    // vice versa) is a silent honest-claims break no helper test would catch.

    fn signed_super_seal_wire() -> ([u8; 32], Vec<u8>, Vec<u8>) {
        use crate::identity::{CryptoProfile, EntityType, Identity};
        use crate::record::{Classification, ValidationRecord};
        use std::collections::BTreeMap;

        let id = Identity::generate(EntityType::Device, CryptoProfile::ProfileB).unwrap();
        let mut rec = ValidationRecord::create(
            b"epoch-super-seal-body",
            id.public_key.clone(),
            vec![],
            Classification::Public,
            Some(BTreeMap::new()),
        );
        rec.version = 5;
        rec.nonce = 11;
        rec.zone = Some(ZoneId::from_legacy(0));
        id.sign_record_light(&mut rec).unwrap();
        let wire = rec.to_bytes();
        (rec.record_hash(), wire, rec.creator_public_key.clone())
    }

    #[test]
    fn classify_super_seal_trust_anchorpinned_on_anchor_match() {
        // Signer's pubkey is in the pinned set → AnchorPinned grade.
        let (rh, wire, pk) = signed_super_seal_wire();
        let grade = classify_super_seal_trust(rh, &wire, &[pk])
            .expect("anchor-signed seal with matching anchor must pass");
        assert_eq!(grade, TrustGrade::AnchorPinned);
    }

    #[test]
    fn classify_super_seal_trust_drops_non_anchor_signer() {
        // The soundness wiring: a genuinely-signed seal whose signer is NOT in
        // the pinned set is DROPPED (Err) — the cold-start forged-seed close.
        let (rh, wire, pk) = signed_super_seal_wire();
        let other = vec![0xAAu8; pk.len()];
        let err = classify_super_seal_trust(rh, &wire, &[other])
            .expect_err("seal signed by a non-anchor key must be dropped");
        assert!(
            err.contains("anchor set"),
            "expected an untrusted-anchor drop, got: {err}",
        );
    }

    #[test]
    fn classify_super_seal_trust_reference_grade_on_empty_anchor_set() {
        // No anchors configured → legacy wire-key integrity check, Reference
        // grade (single-seed trust, honestly labelled — never AnchorPinned).
        let (rh, wire, _pk) = signed_super_seal_wire();
        let grade = classify_super_seal_trust(rh, &wire, &[])
            .expect("valid record under empty anchor set passes integrity → Reference");
        assert_eq!(grade, TrustGrade::Reference);
    }

    #[test]
    fn classify_super_seal_trust_empty_anchors_rejects_corrupt_wire() {
        // Empty anchor set is NOT permissive-accept: a corrupt wire body still
        // fails the integrity check and is dropped (no silent accept).
        let (rh, _wire, _pk) = signed_super_seal_wire();
        let garbage = vec![0u8; 16];
        assert!(
            classify_super_seal_trust(rh, &garbage, &[]).is_err(),
            "corrupt wire must be dropped even with no anchors",
        );
    }

    #[test]
    fn test_light_state_add_first_header() {
        let mut state = LightState::new();
        let header = make_header(0, 0, [0u8; 32]);
        assert!(state.add_header(header).is_ok());
        assert_eq!(state.latest_epoch(&ZoneId::from_legacy(0)), Some(0));
    }

    #[test]
    fn test_light_state_chain_link() {
        let mut state = LightState::new();
        let h0 = make_header(0, 0, [0u8; 32]);
        state.add_header(h0).unwrap();

        let prev_hash = mock_seal_hash(&ZoneId::from_legacy(0), 0);
        let h1 = make_header(0, 1, prev_hash);
        assert!(state.add_header(h1).is_ok());
        assert_eq!(state.latest_epoch(&ZoneId::from_legacy(0)), Some(1));
    }

    #[test]
    fn test_light_state_chain_break() {
        let mut state = LightState::new();
        let h0 = make_header(0, 0, [0u8; 32]);
        state.add_header(h0).unwrap();

        // Wrong previous hash
        let h1 = make_header(0, 1, [99u8; 32]);
        assert!(state.add_header(h1).is_err());
    }

    #[test]
    fn test_light_state_epoch_gap() {
        let mut state = LightState::new();
        let h0 = make_header(0, 0, [0u8; 32]);
        state.add_header(h0).unwrap();

        let h2 = make_header(0, 2, [0u8; 32]); // skip epoch 1
        assert!(state.add_header(h2).is_err());
    }

    #[test]
    fn test_light_state_verify_chain() {
        let mut state = LightState::new();
        let z0 = ZoneId::from_legacy(0);

        let h0 = make_header(0, 0, [0u8; 32]);
        state.add_header(h0).unwrap();

        let h1 = make_header(0, 1, mock_seal_hash(&z0, 0));
        state.add_header(h1).unwrap();

        let h2 = make_header(0, 2, mock_seal_hash(&z0, 1));
        state.add_header(h2).unwrap();

        assert!(state.verify_chain(&z0));
        assert!(state.verify_chain(&ZoneId::from_legacy(1))); // empty zone = trivially valid
    }

    // ── Gap 1 fix: per-zone since_epoch tracking (2026-04-26) ──────────

    #[test]
    fn test_compute_zone_pulls_cold_start_returns_single_unfiltered_probe() {
        let state = LightState::new();
        let pulls = state.compute_zone_pulls();
        assert_eq!(pulls.len(), 1);
        assert!(pulls[0].0.is_none(), "cold start must not pin a zone");
        assert_eq!(pulls[0].1, 0, "cold start since=0 to walk from genesis");
    }

    #[test]
    fn test_compute_zone_pulls_per_zone_since_uses_per_zone_max() {
        // The pre-fix bug: zone A at epoch 100, zone B at epoch 50, the
        // global max+1 would request since=101 and skip zone B's
        // 51..=100 entirely. The fix returns one pull per zone with
        // each zone's own next epoch.
        let mut state = LightState::new();
        state
            .add_header(make_header(0, 0, [0u8; 32]))
            .unwrap();
        state
            .add_header(make_header(0, 1, mock_seal_hash(&ZoneId::from_legacy(0), 0)))
            .unwrap();
        state.add_header(make_header(1, 0, [0u8; 32])).unwrap();

        let mut pulls = state.compute_zone_pulls();
        pulls.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(pulls.len(), 2, "one pull per known zone");
        assert_eq!(pulls[0].0, Some(ZoneId::from_legacy(0)));
        assert_eq!(pulls[0].1, 2, "zone 0 next = last epoch (1) + 1");
        assert_eq!(pulls[1].0, Some(ZoneId::from_legacy(1)));
        assert_eq!(pulls[1].1, 1, "zone 1 next = last epoch (0) + 1");
    }

    #[test]
    fn test_compute_zone_pulls_uses_checkpoint_floor_when_higher() {
        // Gap 3 super-seal interaction: a checkpoint at end_epoch=500
        // for a zone with no live headers yet should resume at 501,
        // not 0.
        let mut state = LightState::new();
        let zone = ZoneId::from_legacy(7);
        state.checkpoints.insert(
            zone.clone(),
            CheckpointMark {
                zone: zone.clone(),
                start_epoch: 437,
                end_epoch: 500,
                seal_count: 64,
                record_id: "ss-7".to_string(),
                record_hash: [0u8; 32],
                committee_hash: [0u8; 32],
                coverage_verified: false,
                trust_grade: TrustGrade::Reference,
                baseline_seal_hash: None,
            },
        );
        let pulls = state.compute_zone_pulls();
        assert_eq!(pulls.len(), 1);
        assert_eq!(pulls[0].0, Some(zone));
        assert_eq!(pulls[0].1, 501, "checkpoint end + 1");
    }

    #[test]
    fn test_compute_zone_pulls_header_max_takes_precedence_over_older_checkpoint() {
        // If headers have advanced past the checkpoint floor (steady
        // state), since_epoch must follow the headers, not regress to
        // checkpoint+1.
        let mut state = LightState::new();
        let zone = ZoneId::from_legacy(3);
        state.checkpoints.insert(
            zone.clone(),
            CheckpointMark {
                zone: zone.clone(),
                start_epoch: 0,
                end_epoch: 100,
                seal_count: 64,
                record_id: "ss-3".to_string(),
                record_hash: [0u8; 32],
                committee_hash: [0u8; 32],
                coverage_verified: false,
                trust_grade: TrustGrade::Reference,
                baseline_seal_hash: None,
            },
        );
        state.headers.insert(
            zone.clone(),
            vec![make_header(3, 200, [0u8; 32])],
        );
        let pulls = state.compute_zone_pulls();
        assert_eq!(pulls[0].1, 201, "header max wins when ahead of checkpoint");
    }

    // ── compute_zone_pulls_filtered (Gap 1 zone-filter follow-up) ──────────────

    #[test]
    fn test_zone_filter_cold_start_returns_per_whitelisted_zone_not_none_probe() {
        // Empty LightState + non-empty whitelist: must return one (Some(z), 0)
        // per whitelisted zone instead of the unfiltered (None, 0) cold-start
        // probe. This is the core invariant — a filtered light client must never
        // request "pull everything" even on its very first tick.
        let state = LightState::new();
        let wl = vec![ZoneId::from_legacy(5), ZoneId::from_legacy(9)];
        let mut pulls = state.compute_zone_pulls_filtered(&wl);
        pulls.sort_by_key(|(z, _)| z.as_ref().map(|z| z.path().to_string()));
        assert_eq!(pulls.len(), 2, "one pull per whitelisted zone");
        assert!(pulls.iter().all(|(z, _)| z.is_some()), "no unfiltered (None, _) probe");
        let zones: Vec<_> = pulls.iter().map(|(z, _)| z.clone().unwrap()).collect();
        assert!(zones.contains(&ZoneId::from_legacy(5)));
        assert!(zones.contains(&ZoneId::from_legacy(9)));
        assert!(pulls.iter().all(|(_, since)| *since == 0), "cold zones start at epoch 0");
    }

    #[test]
    fn test_zone_filter_excludes_non_whitelisted_warm_zones() {
        // LightState has headers for zone 0 (epoch 3) and zone 1 (epoch 7).
        // Whitelist only zone 0: zone 1 must be excluded even though it has
        // known headers — the filter bounds LightState to operator-chosen zones.
        let mut state = LightState::new();
        state.add_header(make_header(ZoneId::from_legacy(0), 3, [0u8; 32])).unwrap();
        state.add_header(make_header(ZoneId::from_legacy(1), 7, [0u8; 32])).unwrap();
        let wl = vec![ZoneId::from_legacy(0)];
        let pulls = state.compute_zone_pulls_filtered(&wl);
        assert_eq!(pulls.len(), 1, "only whitelisted zone 0 returned");
        assert_eq!(pulls[0].0, Some(ZoneId::from_legacy(0)));
        assert_eq!(pulls[0].1, 4, "since = last_epoch + 1 = 4");
    }

    #[test]
    fn test_zone_filter_empty_whitelist_matches_unfiltered() {
        // Empty whitelist must delegate to compute_zone_pulls — cold start
        // returns the (None, 0) probe, warm state returns per-zone pulls.
        let state = LightState::new();
        assert_eq!(
            state.compute_zone_pulls_filtered(&[]),
            state.compute_zone_pulls(),
            "empty whitelist is a no-op alias for compute_zone_pulls",
        );
    }

    #[test]
    fn test_zone_filter_checkpoint_only_starts_after_checkpoint() {
        // Zone has a checkpoint (end_epoch=19) but no headers yet — the
        // (None, Some(c)) branch of compute_zone_pulls_filtered must return
        // since = end_epoch + 1 = 20, not 0.  This path fires on cold start
        // when the sync loop loads checkpoints before any header pull completes.
        let mut state = LightState::new();
        let zone = ZoneId::from_legacy(3);
        state.checkpoints.insert(zone.clone(), CheckpointMark {
            zone: zone.clone(),
            start_epoch: 0,
            end_epoch: 19,
            seal_count: 20,
            record_id: "ckpt-rid".to_string(),
            record_hash: [0u8; 32],
            committee_hash: [0u8; 32],
            coverage_verified: true,
            trust_grade: TrustGrade::Reference,
            baseline_seal_hash: None,
        });
        let pulls = state.compute_zone_pulls_filtered(std::slice::from_ref(&zone));
        assert_eq!(pulls.len(), 1);
        assert_eq!(pulls[0].0, Some(zone));
        assert_eq!(pulls[0].1, 20, "since must be checkpoint end_epoch + 1");
    }

    #[test]
    fn test_zone_filter_headers_and_checkpoint_takes_max() {
        // Zone has both headers (latest epoch 10) and a checkpoint (end_epoch 25).
        // (Some(h), Some(c)) branch: since = max(10, 25) + 1 = 26.
        // Also verifies the header-wins case: header epoch 30, checkpoint 20 → 31.
        let mut state = LightState::new();
        let zone_a = ZoneId::from_legacy(4);
        let zone_b = ZoneId::from_legacy(5);

        // zone_a: checkpoint ahead of headers
        state.add_header(make_header(ZoneId::from_legacy(4), 10, [0u8; 32])).unwrap();
        state.checkpoints.insert(zone_a.clone(), CheckpointMark {
            zone: zone_a.clone(),
            start_epoch: 0,
            end_epoch: 25,
            seal_count: 26,
            record_id: "a-ckpt".to_string(),
            record_hash: [0u8; 32],
            committee_hash: [0u8; 32],
            coverage_verified: true,
            trust_grade: TrustGrade::Reference,
            baseline_seal_hash: None,
        });

        // zone_b: header ahead of checkpoint
        state.add_header(make_header(ZoneId::from_legacy(5), 30, [0u8; 32])).unwrap();
        state.checkpoints.insert(zone_b.clone(), CheckpointMark {
            zone: zone_b.clone(),
            start_epoch: 0,
            end_epoch: 20,
            seal_count: 21,
            record_id: "b-ckpt".to_string(),
            record_hash: [0u8; 32],
            committee_hash: [0u8; 32],
            coverage_verified: true,
            trust_grade: TrustGrade::Reference,
            baseline_seal_hash: None,
        });

        let mut pulls = state.compute_zone_pulls_filtered(&[zone_a.clone(), zone_b.clone()]);
        pulls.sort_by_key(|(z, _)| z.as_ref().map(|z| z.path().to_string()));

        let since_a = pulls.iter().find(|(z, _)| z.as_ref() == Some(&zone_a)).map(|(_, s)| *s);
        let since_b = pulls.iter().find(|(z, _)| z.as_ref() == Some(&zone_b)).map(|(_, s)| *s);
        assert_eq!(since_a, Some(26), "checkpoint(25) > header(10): since=26");
        assert_eq!(since_b, Some(31), "header(30) > checkpoint(20): since=31");
    }

    #[test]
    fn test_light_state_multi_zone() {
        let mut state = LightState::new();
        let h0z0 = make_header(0, 0, [0u8; 32]);
        let h0z1 = make_header(1, 0, [0u8; 32]);
        state.add_header(h0z0).unwrap();
        state.add_header(h0z1).unwrap();

        assert_eq!(state.latest_epoch(&ZoneId::from_legacy(0)), Some(0));
        assert_eq!(state.latest_epoch(&ZoneId::from_legacy(1)), Some(0));
        assert_eq!(state.latest_epoch(&ZoneId::from_legacy(2)), None);
    }

    #[test]
    fn test_merkle_proof_roundtrip() {
        let hashes: Vec<[u8; 32]> = (0..8u8)
            .map(|i| sha3_256(&[i]))
            .collect();
        let mut sorted = hashes.clone();
        sorted.sort();

        let root = MerkleTree::root(&sorted);

        for leaf in &sorted {
            let proof = MerkleTree::proof(&sorted, leaf).unwrap();
            assert_eq!(proof.root, root);
            assert!(MerkleTree::verify_proof(&proof));
        }
    }

    #[test]
    fn test_merkle_proof_single_leaf() {
        let leaf = sha3_256(b"only");
        let hashes = vec![leaf];
        let proof = MerkleTree::proof(&hashes, &leaf).unwrap();
        assert!(proof.siblings.is_empty());
        assert!(MerkleTree::verify_proof(&proof));
    }

    #[test]
    fn test_merkle_proof_missing_leaf() {
        let hashes: Vec<[u8; 32]> = (0..4u8).map(|i| sha3_256(&[i])).collect();
        let missing = sha3_256(b"not_in_tree");
        assert!(MerkleTree::proof(&hashes, &missing).is_none());
    }

    #[test]
    fn test_merkle_proof_tampered() {
        let hashes: Vec<[u8; 32]> = (0..4u8).map(|i| sha3_256(&[i])).collect();
        let mut sorted = hashes;
        sorted.sort();

        let mut proof = MerkleTree::proof(&sorted, &sorted[0]).unwrap();
        // Tamper with a sibling
        if let Some(node) = proof.siblings.first_mut() {
            node.hash[0] ^= 0xFF;
        }
        assert!(!MerkleTree::verify_proof(&proof));
    }

    #[test]
    fn test_verify_record_with_proof() {
        let hashes: Vec<[u8; 32]> = (0..4u8).map(|i| sha3_256(&[i])).collect();
        let mut sorted = hashes;
        sorted.sort();
        let root = MerkleTree::root(&sorted);

        let proof = MerkleTree::proof(&sorted, &sorted[1]).unwrap();

        let mut state = LightState::new();
        state.add_header(EpochHeader {
            zone: ZoneId::from_legacy(0),
            epoch_number: 0,
            merkle_root: root,
            previous_seal_hash: [0u8; 32],
            record_count: 4,
            account_smt_root: None,
            start: 0.0,
            end: 100.0,
            seal_record_hash: None,
        }).unwrap();

        assert!(state.verify_record(&ZoneId::from_legacy(0), 0, &proof));
        // Wrong epoch
        assert!(!state.verify_record(&ZoneId::from_legacy(0), 1, &proof));
        // Wrong zone
        assert!(!state.verify_record(&ZoneId::from_legacy(1), 0, &proof));
    }

    // ── Gap 1: account-proof binds to signed header root ─────────────
    #[test]
    fn test_verify_account_proof_against_header_end_to_end() {
        use crate::network::account_merkle::AccountStateSMT;
        use crate::storage::rocks::StorageEngine;

        // Build a real account SMT and capture a real proof + root.
        let dir = tempfile::tempdir().unwrap();
        let storage = StorageEngine::open(dir.path()).unwrap();
        let mut tree = AccountStateSMT::new(&storage);
        let alice: [u8; 32] = sha3_256(b"alice");
        let bob: [u8; 32] = sha3_256(b"bob");
        tree.update(&alice, &sha3_256(b"alice=1000")).unwrap();
        tree.update(&bob, &sha3_256(b"bob=500")).unwrap();
        tree.commit().unwrap();

        let tree = AccountStateSMT::new(&storage);
        let signed_root = tree.root().unwrap();
        let proof_alice = tree.proof(&alice).unwrap().expect("alice exists");

        // Bound header: signed account_smt_root matches the tree root.
        let bound_header = EpochHeader {
            zone: ZoneId::from_legacy(0),
            epoch_number: 10,
            merkle_root: sha3_256(b"zone-records"),
            previous_seal_hash: [0u8; 32],
            record_count: 0,
            account_smt_root: Some(signed_root),
            start: 0.0,
            end: 100.0,
            seal_record_hash: None,
        };
        assert!(
            verify_account_proof_against_header(&proof_alice, &bound_header),
            "real proof must verify against header signed with matching root",
        );

        // Legacy / unbound header — must refuse.
        let legacy_header = EpochHeader {
            account_smt_root: None,
            ..bound_header.clone()
        };
        assert!(
            !verify_account_proof_against_header(&proof_alice, &legacy_header),
            "headers without account_smt_root must never verify (pre-Gap-1)",
        );

        // Tampered header root — must refuse.
        let mut tampered = signed_root;
        tampered[0] ^= 0xFF;
        let tampered_header = EpochHeader {
            account_smt_root: Some(tampered),
            ..bound_header.clone()
        };
        assert!(
            !verify_account_proof_against_header(&proof_alice, &tampered_header),
            "tampered root must not verify",
        );

        // Tampered proof.state_hash — must refuse.
        let mut bad_proof = proof_alice.clone();
        bad_proof.state_hash[0] ^= 0xFF;
        assert!(
            !verify_account_proof_against_header(&bad_proof, &bound_header),
            "proof with forged state_hash must not verify",
        );

        // Proof for a different account (bob) against alice's identity — the
        // underlying proof must still verify on its own terms, proving the
        // binding logic is honest: we only reject when the root mismatches.
        let proof_bob = tree.proof(&bob).unwrap().expect("bob exists");
        assert!(
            verify_account_proof_against_header(&proof_bob, &bound_header),
            "bob's proof against the same signed root must also verify",
        );
    }

    // ── Gap 3: checkpoint-skip parsing + LightState.checkpoints wiring ─────

    #[test]
    fn test_pick_checkpoint_skip_epoch_picks_max_end_epoch() {
        let body = serde_json::json!({
            "total": 3,
            "super_seal_interval": 64,
            "checkpoints": [
                { "zone": "test-a", "end_epoch": 63 },
                { "zone": "test-b", "end_epoch": 127 },
                { "zone": "test-a", "end_epoch": 191 },
            ]
        });
        assert_eq!(pick_checkpoint_skip_epoch(&body), Some(191));
    }

    #[test]
    fn test_pick_checkpoint_skip_epoch_empty_and_missing() {
        let empty = serde_json::json!({ "total": 0, "checkpoints": [] });
        assert_eq!(pick_checkpoint_skip_epoch(&empty), None);
        let missing = serde_json::json!({ "other": "field" });
        assert_eq!(pick_checkpoint_skip_epoch(&missing), None);
    }

    #[test]
    fn test_parse_checkpoint_json_roundtrip() {
        let record_hash = sha3_256(b"super-seal-record-bytes");
        let committee_hash = sha3_256(b"committee");
        let v = serde_json::json!({
            "zone": "test-a",
            "start_epoch": 0,
            "end_epoch": 63,
            "seal_count": 64,
            "merkle_root": hex::encode([0u8; 32]),
            "record_id": "super_seal:test-a:0-63",
            "record_hash": hex::encode(record_hash),
            "committee_hash": hex::encode(committee_hash),
        });
        let mark = parse_checkpoint_json(&v).expect("valid");
        assert_eq!(mark.zone.to_string(), "test-a");
        assert_eq!(mark.start_epoch, 0);
        assert_eq!(mark.end_epoch, 63);
        assert_eq!(mark.seal_count, 64);
        assert_eq!(mark.record_id, "super_seal:test-a:0-63");
        assert_eq!(mark.record_hash, record_hash);
        assert_eq!(mark.committee_hash, committee_hash);
    }

    #[test]
    fn test_parse_checkpoint_json_missing_committee_defaults_zero() {
        // Legacy super-seals (pre committee-hash follow-up) omit the field.
        let v = serde_json::json!({
            "zone": "test-b",
            "start_epoch": 64,
            "end_epoch": 127,
            "seal_count": 64,
            "record_id": "super_seal:test-b:64-127",
            "record_hash": hex::encode([7u8; 32]),
        });
        let mark = parse_checkpoint_json(&v).expect("valid (legacy)");
        assert_eq!(mark.committee_hash, [0u8; 32]);
    }

    #[test]
    fn test_parse_checkpoint_json_rejects_inverted_epochs() {
        let v = serde_json::json!({
            "zone": "test-c",
            "start_epoch": 100,
            "end_epoch": 50,
            "seal_count": 1,
            "record_id": "x",
            "record_hash": hex::encode([0u8; 32]),
        });
        assert!(parse_checkpoint_json(&v).is_none());
    }

    #[test]
    fn test_parse_checkpoint_json_rejects_bad_hash() {
        let v = serde_json::json!({
            "zone": "test-d",
            "start_epoch": 0,
            "end_epoch": 63,
            "seal_count": 64,
            "record_id": "x",
            "record_hash": "not-hex",
        });
        assert!(parse_checkpoint_json(&v).is_none());
    }

    // ── Gap 3 pass 2: cross-peer record_hash verification ─────────────────

    fn mark(zone: &str, end_epoch: u64, rh: [u8; 32]) -> CheckpointMark {
        CheckpointMark {
            zone: ZoneId::new(zone),
            start_epoch: end_epoch.saturating_sub(63),
            end_epoch,
            seal_count: 64,
            record_id: format!("super_seal:{zone}:{end_epoch}"),
            record_hash: rh,
            committee_hash: [0u8; 32],
            coverage_verified: false,
            trust_grade: TrustGrade::Reference,
            baseline_seal_hash: None,
        }
    }

    fn body_with(marks: &[CheckpointMark]) -> serde_json::Value {
        let arr: Vec<serde_json::Value> = marks
            .iter()
            .map(|m| {
                serde_json::json!({
                    "zone": m.zone.to_string(),
                    "start_epoch": m.start_epoch,
                    "end_epoch": m.end_epoch,
                    "seal_count": m.seal_count,
                    "record_id": m.record_id,
                    "record_hash": hex::encode(m.record_hash),
                    "committee_hash": hex::encode(m.committee_hash),
                })
            })
            .collect();
        serde_json::json!({ "checkpoints": arr })
    }

    #[test]
    fn test_cross_verify_accepts_matching_peers() {
        // Two peers both return the SAME record_hash for (zone-a, epoch 63).
        // Cross-verify must keep it.
        let h = sha3_256(b"super-seal-bytes");
        let primary = vec![mark("zone-a", 63, h)];
        let other = body_with(&[mark("zone-a", 63, h)]);
        let (kept, dropped) = cross_verify_checkpoints(primary, &[other]);
        assert_eq!(kept.len(), 1);
        assert!(dropped.is_empty());
    }

    #[test]
    fn test_cross_verify_drops_mismatched_peers() {
        // Primary says hash=A, other seed says hash=B for the same
        // (zone, end_epoch). Cross-verify must drop — fork signal.
        let h1 = sha3_256(b"primary-bytes");
        let h2 = sha3_256(b"other-bytes");
        let primary = vec![mark("zone-a", 63, h1)];
        let other = body_with(&[mark("zone-a", 63, h2)]);
        let (kept, dropped) = cross_verify_checkpoints(primary, &[other]);
        assert!(kept.is_empty());
        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0].0.to_string(), "zone-a");
        assert_eq!(dropped[0].1, 63);
    }

    #[test]
    fn test_cross_verify_missing_opinion_is_not_conflict() {
        // Other seed has ZERO checkpoints (not-an-archive or empty network).
        // Cross-verify must keep primary's marks — silence ≠ conflict.
        let h = sha3_256(b"super-seal-bytes");
        let primary = vec![mark("zone-a", 63, h), mark("zone-b", 127, h)];
        let other = serde_json::json!({ "checkpoints": [] });
        let (kept, dropped) = cross_verify_checkpoints(primary, &[other]);
        assert_eq!(kept.len(), 2);
        assert!(dropped.is_empty());
    }

    #[test]
    fn test_cross_verify_different_epoch_is_not_conflict() {
        // Other seed reports same zone but different end_epoch — one is
        // ahead or behind, not a fork. Primary's mark must be kept.
        let h1 = sha3_256(b"primary-bytes");
        let h2 = sha3_256(b"other-bytes");
        let primary = vec![mark("zone-a", 63, h1)];
        let other = body_with(&[mark("zone-a", 127, h2)]);
        let (kept, dropped) = cross_verify_checkpoints(primary, &[other]);
        assert_eq!(kept.len(), 1);
        assert!(dropped.is_empty());
    }

    #[test]
    fn test_cross_verify_one_peer_agrees_one_silent() {
        // Peer A agrees, peer B silent → kept. Silence on B doesn't undo
        // the agreement from A.
        let h = sha3_256(b"super-seal-bytes");
        let primary = vec![mark("zone-a", 63, h)];
        let agreeing = body_with(&[mark("zone-a", 63, h)]);
        let silent = serde_json::json!({ "checkpoints": [] });
        let (kept, dropped) = cross_verify_checkpoints(primary, &[agreeing, silent]);
        assert_eq!(kept.len(), 1);
        assert!(dropped.is_empty());
    }

    #[test]
    fn test_cross_verify_any_disagreement_drops_even_with_agreements() {
        // Peer A agrees, peer B DISAGREES → drop. Fork signal overrides
        // majority — one dishonest mismatch is enough to reject.
        let h = sha3_256(b"primary-bytes");
        let h_bad = sha3_256(b"forged-bytes");
        let primary = vec![mark("zone-a", 63, h)];
        let agreeing = body_with(&[mark("zone-a", 63, h)]);
        let disagreeing = body_with(&[mark("zone-a", 63, h_bad)]);
        let (kept, dropped) = cross_verify_checkpoints(primary, &[agreeing, disagreeing]);
        assert!(kept.is_empty());
        assert_eq!(dropped.len(), 1);
    }

    #[test]
    fn test_cross_verify_empty_others_keeps_all_primary() {
        // Single-seed network — no cross-verify possible. Primary marks
        // kept on single-seed trust. This matches the Gap 7 degenerate
        // case ("single-archive network is still accepted").
        let h = sha3_256(b"super-seal-bytes");
        let primary = vec![mark("zone-a", 63, h), mark("zone-b", 127, h)];
        let (kept, dropped) = cross_verify_checkpoints(primary, &[]);
        assert_eq!(kept.len(), 2);
        assert!(dropped.is_empty());
    }

    #[test]
    fn test_checkpoint_mark_defaults_on_light_state() {
        // LightState::new() must start with empty checkpoints and the
        // cold-start skip flag un-tripped — otherwise a fresh light node
        // would skip the one-shot checkpoint fetch on boot.
        let state = LightState::new();
        assert!(state.checkpoints.is_empty());
        assert!(!state.checkpoint_skip_attempted);
    }

    #[test]
    fn test_headers_since() {
        let mut state = LightState::new();
        let z0 = ZoneId::from_legacy(0);
        let h0 = make_header(0, 0, [0u8; 32]);
        state.add_header(h0).unwrap();
        let h1 = make_header(0, 1, mock_seal_hash(&z0, 0));
        state.add_header(h1).unwrap();

        let since_1 = state.headers_since(&ZoneId::from_legacy(0), 1);
        assert_eq!(since_1.len(), 1);
        assert_eq!(since_1[0].epoch_number, 1);

        let since_0 = state.headers_since(&ZoneId::from_legacy(0), 0);
        assert_eq!(since_0.len(), 2);
    }

    // ---- Gap 3 pass 3: verify_super_seal_record_integrity ----
    //
    // Builds a signed v5 ValidationRecord using the same helper pattern as
    // conflict_proof tests. The integrity helper must accept the round-
    // tripped bytes if (and only if) record_hash and Dilithium3 sig both
    // check out locally — this is the final trust hop in the light-client
    // checkpoint skip after cross-peer agreement.

    fn signed_super_seal_record() -> (crate::record::ValidationRecord, Vec<u8>) {
        use crate::identity::{CryptoProfile, EntityType, Identity};
        use crate::record::{Classification, ValidationRecord};
        use std::collections::BTreeMap;

        let id = Identity::generate(EntityType::Device, CryptoProfile::ProfileB).unwrap();
        let mut rec = ValidationRecord::create(
            b"super-seal-body",
            id.public_key.clone(),
            vec![],
            Classification::Public,
            Some(BTreeMap::new()),
        );
        rec.version = 5;
        rec.nonce = 7;
        rec.zone = Some(ZoneId::from_legacy(0));
        id.sign_record_light(&mut rec).unwrap();
        let wire = rec.to_bytes();
        (rec, wire)
    }

    #[test]
    fn verify_super_seal_integrity_valid_record_passes() {
        let (rec, wire) = signed_super_seal_record();
        let hash = rec.record_hash();
        verify_super_seal_record_integrity(hash, &wire).expect("valid record must pass");
    }

    #[test]
    fn verify_super_seal_integrity_mismatched_hash_fails() {
        let (_rec, wire) = signed_super_seal_record();
        let wrong_hash = [0xAAu8; 32];
        let err = verify_super_seal_record_integrity(wrong_hash, &wire)
            .expect_err("wrong hash must fail");
        assert!(
            err.contains("record_hash mismatch"),
            "expected mismatch error, got: {err}"
        );
    }

    #[test]
    fn verify_super_seal_integrity_missing_signature_fails() {
        let (mut rec, _wire) = signed_super_seal_record();
        let hash = rec.record_hash();
        rec.signature = None;
        let wire = rec.to_bytes();
        let err = verify_super_seal_record_integrity(hash, &wire)
            .expect_err("missing sig must fail");
        assert!(
            err.contains("no Dilithium3 signature"),
            "expected missing-sig error, got: {err}"
        );
    }

    #[test]
    fn verify_super_seal_integrity_forged_signature_fails() {
        // Flip the last byte of the signature so the wire record still
        // decodes and its record_hash still matches (sig is NOT part of
        // signable_bytes), but dilithium3_verify rejects the sig.
        let (mut rec, _wire) = signed_super_seal_record();
        let hash = rec.record_hash();
        if let Some(sig) = rec.signature.as_mut() {
            let last = sig.len() - 1;
            sig[last] ^= 0x01;
        }
        let wire = rec.to_bytes();
        let err = verify_super_seal_record_integrity(hash, &wire)
            .expect_err("forged sig must fail");
        assert!(
            err.contains("signature invalid") || err.contains("verify error"),
            "expected sig-invalid error, got: {err}"
        );
    }

    #[test]
    fn verify_super_seal_integrity_garbage_wire_fails() {
        // Non-decodable wire bytes must surface a decode error rather than
        // panicking — the light-client path hits this if a seed returns
        // truncated or corrupt bytes from /records/fetch.
        let err = verify_super_seal_record_integrity([0u8; 32], b"not-a-record")
            .expect_err("garbage wire must fail");
        assert!(
            err.contains("wire decode"),
            "expected wire-decode error, got: {err}"
        );
    }

    // ---- verify_super_seal_full ----
    //
    // Builds a real super-seal via `create_super_seal` over a known set of
    // seal hashes, then exercises every failure mode the coverage check
    // closes. This is the audit's explicit ask: a unit test that catches a
    // super-seal whose Merkle root doesn't match the stated range.

    fn build_real_super_seal(
        seal_count: u64,
    ) -> (
        Vec<u8>,                // wire bytes of the signed super-seal
        [u8; 32],               // expected record_hash
        Vec<[u8; 32]>,          // canonical seal_hashes
    ) {
        use crate::identity::{CryptoProfile, EntityType, Identity};
        use crate::network::epoch::{create_super_seal, SuperSealParams};

        let id = Identity::generate(EntityType::Device, CryptoProfile::ProfileB).unwrap();
        let zone = ZoneId::from_legacy(0);
        let hashes: Vec<[u8; 32]> = (0..seal_count)
            .map(|i| {
                let mut h = [0u8; 32];
                h[0..8].copy_from_slice(&i.to_le_bytes());
                h[8] = 0x01; // distinct from coverage-tampered byte 0xAA
                h
            })
            .collect();
        let (rec, _parsed) = create_super_seal(SuperSealParams {
            identity: &id,
            zone,
            start_epoch: 0,
            end_epoch: seal_count.saturating_sub(1),
            seal_hashes: &hashes,
            previous_super_seal_hash: [0u8; 32],
            committee_hash: [0u8; 32],
            timestamp: 0.0,
            slot_nonce: 1,
        })
        .expect("create_super_seal must succeed");
        let wire = rec.to_bytes();
        let record_hash = rec.record_hash();
        (wire, record_hash, hashes)
    }

    #[test]
    fn verify_super_seal_full_valid_passes() {
        let (wire, rh, hashes) = build_real_super_seal(8);
        verify_super_seal_full(rh, &wire, &hashes)
            .expect("valid super-seal + correct hashes must pass");
    }

    #[test]
    fn verify_super_seal_full_reordered_hashes_pass() {
        // Coverage uses sorted hashes — order-independent.
        let (wire, rh, mut hashes) = build_real_super_seal(8);
        hashes.reverse();
        verify_super_seal_full(rh, &wire, &hashes)
            .expect("reordered hashes must still pass coverage");
    }

    #[test]
    fn verify_super_seal_full_tampered_hash_fails_coverage() {
        // The audit's explicit ask: catch a super-seal whose merkle_root
        // does not match the stated range.
        let (wire, rh, mut hashes) = build_real_super_seal(8);
        hashes[3] = [0xAAu8; 32];
        let err = verify_super_seal_full(rh, &wire, &hashes)
            .expect_err("tampered hash must fail coverage");
        assert!(
            err.contains("merkle coverage mismatch"),
            "expected coverage error, got: {err}"
        );
    }

    #[test]
    fn verify_super_seal_full_missing_hash_fails_coverage() {
        // One short → seal_count check rejects (count mismatch), then
        // even if count matched, root reconstruction would diverge.
        let (wire, rh, hashes) = build_real_super_seal(8);
        let err = verify_super_seal_full(rh, &wire, &hashes[..7])
            .expect_err("short hash list must fail coverage");
        assert!(
            err.contains("merkle coverage mismatch"),
            "expected coverage error, got: {err}"
        );
    }

    #[test]
    fn verify_super_seal_full_extra_hash_fails_coverage() {
        let (wire, rh, hashes) = build_real_super_seal(8);
        let mut extra = hashes.clone();
        extra.push([0xFFu8; 32]);
        let err = verify_super_seal_full(rh, &wire, &extra)
            .expect_err("extra hash must fail coverage");
        assert!(
            err.contains("merkle coverage mismatch"),
            "expected coverage error, got: {err}"
        );
    }

    #[test]
    fn verify_super_seal_full_integrity_failure_short_circuits() {
        // Wrong record_hash must surface as integrity error, NOT coverage
        // — the helper layers checks in order.
        let (wire, _rh, hashes) = build_real_super_seal(8);
        let wrong_hash = [0xCDu8; 32];
        let err = verify_super_seal_full(wrong_hash, &wire, &hashes)
            .expect_err("wrong record_hash must fail integrity");
        assert!(
            err.contains("record_hash mismatch"),
            "expected integrity error, got: {err}"
        );
    }

    #[test]
    fn verify_super_seal_full_non_super_seal_fails_meta_extract() {
        // A record without super-seal metadata must surface a clear
        // "not a super-seal" error rather than a coverage error.
        let (rec, wire) = signed_super_seal_record();
        let rh = rec.record_hash();
        let err = verify_super_seal_full(rh, &wire, &[])
            .expect_err("non-super-seal must fail meta extract");
        assert!(
            err.contains("not a super-seal"),
            "expected meta error, got: {err}"
        );
    }

    // ─── Pin the residual pure-helper surface left
    // uncovered by the existing tests above. The 9-field EpochHeader
    // and 8-field CheckpointMark wire shapes feed every light-client SDK
    // and every cross-peer checkpoint comparison; a silent rename of any
    // field would break SDK compatibility across versions. The
    // header_from_seal vs header_from_seal_with_hash asymmetry is the
    // load-bearing distinction between best-effort-accept (pre-fix
    // emitter) and chain-verifiable (post-fix emitter) header paths.
    // ────────────────────────────────────────────────────────────────────

    #[test]
    fn batch_b_epoch_header_serde_round_trip_pins_nine_field_wire_shape_with_serde_defaults() {
        // PIN: light.rs:23 — EpochHeader is the wire body for every
        // /epochs/headers + /headers/from/{epoch} response. 9 pub fields.
        // Two of them (account_smt_root, seal_record_hash) carry
        // `#[serde(default)]` so legacy pre-Gap-1 / pre-fix headers
        // without these fields still deserialize. Pin (a) the full
        // 9-field shape, (b) the serde-default behavior on the two
        // Option fields, (c) the type pins on the numeric and array
        // fields.
        let header = EpochHeader {
            zone: ZoneId::from_legacy(0),
            epoch_number: 42,
            merkle_root: [1u8; 32],
            previous_seal_hash: [2u8; 32],
            record_count: 100,
            start: 1000.5,
            end: 2000.5,
            account_smt_root: Some([3u8; 32]),
            seal_record_hash: Some([4u8; 32]),
        };

        let v = serde_json::to_value(&header).expect("EpochHeader must serialize");
        let map = v.as_object().expect("serializes to an object");
        assert_eq!(
            map.len(),
            9,
            "EpochHeader MUST be exactly 9 fields — got {} ({:?})",
            map.len(),
            map.keys().collect::<Vec<_>>(),
        );
        for k in [
            "zone", "epoch_number", "merkle_root", "previous_seal_hash",
            "record_count", "start", "end", "account_smt_root", "seal_record_hash",
        ] {
            assert!(map.contains_key(k), "EpochHeader wire MUST carry `{k}` — SDK pins on this name");
        }

        // Round-trip: full Some-fields preserves both Optional fields.
        let json = serde_json::to_string(&header).unwrap();
        let back: EpochHeader = serde_json::from_str(&json)
            .expect("EpochHeader MUST round-trip via JSON");
        assert_eq!(back.epoch_number, header.epoch_number);
        assert_eq!(back.merkle_root, header.merkle_root);
        assert_eq!(back.previous_seal_hash, header.previous_seal_hash);
        assert_eq!(back.account_smt_root, header.account_smt_root);
        assert_eq!(back.seal_record_hash, header.seal_record_hash);

        // serde(default) pin: pre-Gap-1 / pre-fix wire (account_smt_root +
        // seal_record_hash absent) MUST still deserialize successfully
        // with both fields → None. A regression that drops the
        // `#[serde(default)]` attribute would make legacy wire payloads
        // fail at the extractor → silently dropped headers on the SDK.
        let zeros: Vec<u8> = vec![0u8; 32];
        let legacy = serde_json::json!({
            "zone": "0",
            "epoch_number": 5,
            "merkle_root": zeros,
            "previous_seal_hash": zeros,
            "record_count": 10,
            "start": 0.0,
            "end": 100.0
        });
        let legacy_back: EpochHeader = serde_json::from_value(legacy)
            .expect("legacy wire without account_smt_root + seal_record_hash MUST still deserialize (serde(default) on both)");
        assert!(
            legacy_back.account_smt_root.is_none(),
            "missing account_smt_root MUST deserialize to None via serde(default)",
        );
        assert!(
            legacy_back.seal_record_hash.is_none(),
            "missing seal_record_hash MUST deserialize to None via serde(default)",
        );
    }

    #[test]
    fn batch_b_checkpoint_mark_serde_round_trip_pins_ten_field_wire_shape_with_serde_default_on_trust_fields() {
        // PIN: CheckpointMark is the Gap 3 super-seal wire body for
        // /checkpoints/from/{epoch}. 10 pub fields. coverage_verified,
        // trust_grade, and baseline_seal_hash each carry `#[serde(default)]`
        // so legacy disk-serialized checkpoints (missing those fields)
        // deserialize to false / Reference / None and get re-verified on
        // the next pass. Pin (a) full 10-field shape, (b) serde-default
        // behaviour for all three trust fields.
        let mark = CheckpointMark {
            zone: ZoneId::from_legacy(0),
            start_epoch: 0,
            end_epoch: 63,
            seal_count: 64,
            record_id: "checkpoint-abc".to_string(),
            record_hash: [5u8; 32],
            committee_hash: [6u8; 32],
            coverage_verified: true,
            trust_grade: TrustGrade::AnchorPinned,
            baseline_seal_hash: Some([7u8; 32]),
        };

        let v = serde_json::to_value(&mark).expect("CheckpointMark must serialize");
        let map = v.as_object().expect("serializes to an object");
        assert_eq!(
            map.len(),
            10,
            "CheckpointMark MUST be exactly 10 fields — got {} ({:?})",
            map.len(),
            map.keys().collect::<Vec<_>>(),
        );
        for k in [
            "zone", "start_epoch", "end_epoch", "seal_count",
            "record_id", "record_hash", "committee_hash", "coverage_verified",
            "trust_grade", "baseline_seal_hash",
        ] {
            assert!(map.contains_key(k), "CheckpointMark wire MUST carry `{k}`");
        }

        // Round-trip.
        let json = serde_json::to_string(&mark).unwrap();
        let back: CheckpointMark = serde_json::from_str(&json)
            .expect("CheckpointMark MUST round-trip via JSON");
        assert_eq!(back.start_epoch, mark.start_epoch);
        assert_eq!(back.end_epoch, mark.end_epoch);
        assert_eq!(back.seal_count, mark.seal_count);
        assert_eq!(back.record_id, mark.record_id);
        assert_eq!(back.record_hash, mark.record_hash);
        assert_eq!(back.committee_hash, mark.committee_hash);
        assert_eq!(back.coverage_verified, mark.coverage_verified);
        assert_eq!(back.trust_grade, mark.trust_grade);
        assert_eq!(back.baseline_seal_hash, mark.baseline_seal_hash);

        // serde(default) pin: legacy disk wire without the three trust fields
        // → false / Reference / None. A regression that drops `#[serde(default)]`
        // on any of them would break legacy disk-load on every restart.
        let zeros: Vec<u8> = vec![0u8; 32];
        let legacy = serde_json::json!({
            "zone": "0",
            "start_epoch": 0,
            "end_epoch": 63,
            "seal_count": 64,
            "record_id": "legacy",
            "record_hash": zeros,
            "committee_hash": zeros
        });
        let legacy_back: CheckpointMark = serde_json::from_value(legacy)
            .expect("legacy wire without the trust fields MUST still deserialize (serde(default))");
        assert!(
            !legacy_back.coverage_verified,
            "missing coverage_verified MUST default to false (legacy → re-verify on next pass)",
        );
        assert_eq!(
            legacy_back.trust_grade,
            TrustGrade::Reference,
            "missing trust_grade MUST default to Reference (no anchor trust earned)",
        );
        assert!(
            legacy_back.baseline_seal_hash.is_none(),
            "missing baseline_seal_hash MUST default to None (best-effort first-header accept)",
        );
    }

    #[test]
    fn batch_b_header_from_seal_vs_with_hash_pin_load_bearing_seal_record_hash_asymmetry() {
        // PIN: light.rs:1184 (header_from_seal) and light.rs:1201
        // (header_from_seal_with_hash). The two builders DIFFER only in
        // the seal_record_hash field:
        //   - header_from_seal:           seal_record_hash = None
        //   - header_from_seal_with_hash: seal_record_hash = Some(h)
        // This asymmetry is load-bearing: chain-link verification in
        // add_header (L123) ONLY runs when seal_record_hash is Some.
        // A producer that calls header_from_seal accidentally instead
        // of header_from_seal_with_hash emits headers that pass through
        // the best-effort-accept branch — silently disabling chain
        // verification for downstream light clients.
        //
        // We can't easily construct a ParsedEpochSeal without dragging
        // in epoch internals, so instead pin the asymmetry at the
        // higher level: build two headers with identical content
        // except for seal_record_hash, prove that LightState's
        // chain-link verification trusts one and refuses to verify
        // through the other.

        let zone = ZoneId::from_legacy(0);

        // Pre-fix style header (seal_record_hash = None) at epoch 0
        // followed by a chained header at epoch 1. The chain-link
        // check in add_header sees seal_record_hash = None → best-
        // effort accept (no break possible).
        let mut state_pre_fix = LightState::new();
        let h0_pre_fix = EpochHeader {
            zone: zone.clone(),
            epoch_number: 0,
            merkle_root: sha3_256(b"root_0"),
            previous_seal_hash: [0u8; 32],
            record_count: 1,
            start: 0.0,
            end: 100.0,
            account_smt_root: None,
            seal_record_hash: None, // ← header_from_seal would emit THIS
        };
        let h1_wild = EpochHeader {
            zone: zone.clone(),
            epoch_number: 1,
            merkle_root: sha3_256(b"root_1"),
            // Any garbage previous_seal_hash passes because prior had None.
            previous_seal_hash: sha3_256(b"unrelated-hash"),
            record_count: 1,
            start: 100.0,
            end: 200.0,
            account_smt_root: None,
            seal_record_hash: None,
        };
        state_pre_fix.add_header(h0_pre_fix).expect("first header always accepted");
        state_pre_fix
            .add_header(h1_wild)
            .expect("seal_record_hash=None on prior header MUST best-effort accept any previous_seal_hash on follower — that's the legacy compat path");

        // Post-fix style header (seal_record_hash = Some). The chain-
        // link check in add_header sees Some → strict mismatch check.
        let mut state_post_fix = LightState::new();
        let real_seal_hash = sha3_256(b"actual-seal-record-hash");
        let h0_post_fix = EpochHeader {
            zone: zone.clone(),
            epoch_number: 0,
            merkle_root: sha3_256(b"root_0"),
            previous_seal_hash: [0u8; 32],
            record_count: 1,
            start: 0.0,
            end: 100.0,
            account_smt_root: None,
            seal_record_hash: Some(real_seal_hash), // ← header_from_seal_with_hash emits THIS
        };
        let h1_wrong_link = EpochHeader {
            zone: zone.clone(),
            epoch_number: 1,
            merkle_root: sha3_256(b"root_1"),
            previous_seal_hash: sha3_256(b"unrelated-hash"), // ← does NOT match real_seal_hash
            record_count: 1,
            start: 100.0,
            end: 200.0,
            account_smt_root: None,
            seal_record_hash: None,
        };
        state_post_fix.add_header(h0_post_fix).expect("first header always accepted");
        let chain_err = state_post_fix
            .add_header(h1_wrong_link)
            .expect_err("seal_record_hash=Some on prior MUST strict-check previous_seal_hash on follower");
        assert!(
            chain_err.contains("chain break"),
            "chain-link mismatch error MUST mention 'chain break'; got {chain_err}",
        );
    }

    #[test]
    fn batch_b_light_state_latest_epoch_returns_none_for_unknown_zone_and_some_when_populated() {
        // PIN: LightState::latest_epoch (light.rs:195) returns None
        // for any zone that has no headers AND for any zone that's
        // never been seen. Existing tests exercise the populated
        // happy path indirectly; pin the None-on-unknown branch
        // explicitly — it's the cold-boot SDK guard that prevents
        // panics when a account calls latest_epoch before any sync
        // tick has run.
        let mut state = LightState::new();
        let z0 = ZoneId::from_legacy(0);
        let z1 = ZoneId::from_legacy(1);

        // Unknown zone → None.
        assert!(
            state.latest_epoch(&z0).is_none(),
            "latest_epoch on empty state MUST return None",
        );

        // Populate z0; z0 returns Some(last_epoch), z1 still None.
        let h0 = make_header(z0.clone(), 0, [0u8; 32]);
        let h1 = make_header(z0.clone(), 1, mock_seal_hash(&z0, 0));
        let h2 = make_header(z0.clone(), 2, mock_seal_hash(&z0, 1));
        state.add_header(h0).unwrap();
        state.add_header(h1).unwrap();
        state.add_header(h2).unwrap();

        assert_eq!(
            state.latest_epoch(&z0),
            Some(2),
            "latest_epoch on populated zone MUST return the LAST epoch (not first, not max — last in insertion order)",
        );
        assert!(
            state.latest_epoch(&z1).is_none(),
            "latest_epoch on never-touched zone MUST still return None even after sibling zone populated",
        );
    }

    #[test]
    fn batch_b_verify_account_proof_against_header_refuses_legacy_header_and_root_mismatch() {
        // PIN: verify_account_proof_against_header (light.rs:1228) has
        // a 2-branch guard before the proof.verify_proof inner call:
        //   1. header.account_smt_root is None → false (pre-Gap-1 refuse)
        //   2. proof.root != header.account_smt_root.unwrap() → false
        // The existing end-to-end test covers both branches with real
        // SMT data, but the deeper invariant is that the guard fires
        // BEFORE delegating to verify_proof — i.e. a totally bogus proof
        // (all-zero state_hash, empty siblings) still returns false on
        // the None-header path without invoking the inner verify.
        // Pin this short-circuit so a refactor that swaps the guard
        // order can't accidentally call verify_proof on un-bound data.
        let zone = ZoneId::from_legacy(0);
        let header_none = EpochHeader {
            zone: zone.clone(),
            epoch_number: 0,
            merkle_root: sha3_256(b"root"),
            previous_seal_hash: [0u8; 32],
            record_count: 1,
            start: 0.0,
            end: 100.0,
            account_smt_root: None, // ← pre-Gap-1
            seal_record_hash: None,
        };

        // Build a syntactically valid but trivial AccountStateProof.
        // Empty siblings → reconstruction collapses to state_hash.
        let bogus_proof = crate::network::account_merkle::AccountStateProof {
            account_id: [0u8; 32],
            state_hash: [0u8; 32],
            root: [0u8; 32],
            present: [0u8; 32],
            siblings: vec![],
        };
        assert!(
            !verify_account_proof_against_header(&bogus_proof, &header_none),
            "header.account_smt_root=None MUST return false WITHOUT delegating to verify_proof (pre-Gap-1 short-circuit)",
        );

        // Bound header, but root mismatch → still false.
        let header_bound = EpochHeader {
            account_smt_root: Some([0xFF; 32]), // ← does NOT match bogus_proof.root ([0u8; 32])
            ..header_none.clone()
        };
        assert!(
            !verify_account_proof_against_header(&bogus_proof, &header_bound),
            "header.account_smt_root != proof.root MUST return false WITHOUT delegating to verify_proof (root mismatch short-circuit)",
        );
    }
}
