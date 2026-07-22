# Known Limitations

Honest, operator-facing list of the current release's known gaps — what
happens, how you see it, and the manual path where one exists. If behavior
contradicts this document, the code is authoritative and this document is a
bug (file an issue).

## 1. A node offline longer than ~24 h does not fully self-heal its DAG history

**What happens.** Reconnecting after a long gap, a node header-syncs to the
current epoch quickly and resumes normal operation — but the record-level
delta sync scans a bounded ~24 h window, so records older than the window are
not pulled automatically. The node is *live* but may lack historical records
until healed. (Within the window, depth is no longer a limit: since
2026-07-05 delta-sync pages carry a cross-page cursor, so a backlog deeper
than one server scan is walked incrementally across cycles instead of
silently stopping at the first 50K index entries. Throughput per cycle is
still bounded — snapshot sync remains the right catch-up path for deep/cold
gaps.)

**How you see it.** The node persists the peer-reported missing count after
every delta pull, and tracks sealed-epoch completeness deficits (epochs whose
seal names records the node doesn't hold locally):

- `/status` → `delta_peer_total_missing` (non-zero = gap),
- `/health` → check `dag_gap` goes **WARN** with the counts (peer-reported
  missing, open sealed-epoch deficits, and — when the automatic escalation
  is running without progress — the consecutive no-progress sweep streak),
- `/metrics` → `elara_dag_deficit_open` / `elara_dag_deficit_epochs_total` /
  `elara_dag_deficit_resolved_total` and
  `elara_full_pull_zero_progress_streak`,
- log line `dag-gap OPEN: peer reports N records missing…` on the transition
  (and `dag-gap HEALED` when it clears).

**What heals automatically.** Open deficits force the full-history pull to
run every cycle (instead of its ~200-cycle backstop cadence) and re-seed its
cursor below the earliest hole, so in-window gaps close on their own. The
deficit gauge dropping while `_resolved_total` climbs = self-heal is working.

**Manual recovery** (rehearsed end-to-end 2026-07-02; healed a real 2,700-record
gap). Three prerequisites, then one call:

1. **Admin listener.** With the default split data plane, `/admin/*` already
   answers on-box at `127.0.0.1:9472` — the loopback data-plane listener
   (`data_plane_listen_addr`) carries the full router, admin verbs included.
   Nothing to configure. Admin verbs are deliberately unreachable from
   off-box: the public listener's route table has no admin handlers, and
   non-loopback callers are 404-gated everywhere else. Set
   `admin_listen_addr` only if you changed or disabled the data plane and
   want a dedicated admin port.
2. **Admin keypair (one-time).** `elara-cli pq-admin-keygen` produces a
   Dilithium3 keypair JSON; authorize its public key on the node via the
   `ELARA_ADMIN_PUBKEYS` environment variable (e.g. a systemd drop-in).
   Bearer-token auth was removed (PQ-R7) — admin calls are PQ-signed.
3. **Per-call header.** `admin-sign` binds the exact method + request target —
   the path INCLUDING any `?query`, byte-identical to what curl sends (V2):

```bash
# peer_addr rides the SIGNED query (V2) — single-quote the target so `&` and
# `?` never hit the shell, and sign the exact same string you curl:
TARGET='/admin/snapshot_rebootstrap_from?peer_addr=http://<seed-host>:<seed-http-port>'
HDR=$(elara-cli admin-sign --key ~/.elara/admin/admin.dilithium3.json \
      --method POST --path "$TARGET")

# Full snapshot re-bootstrap from a named healthy peer (the true full heal;
# peer_addr must be in the connected peer table):
curl -X POST "http://127.0.0.1:9472$TARGET" -H "X-PQ-Admin: $HDR"
#    (the port the seed serves HTTP on — compiled default 9473; the value
#     must match that peer's entry in your node's peer table)
#    Rollback override — ONLY when the local ledger is known-bad and the
#    rewind is intended: append `&force=true` to TARGET *before* signing.
#    `force` is a signed query param, never a body field, so a captured
#    header can't be replayed with it flipped on.

# Lighter alternatives (same auth, sign the matching --path / full target):
#   POST /admin/force_sync        — delta pull from every connected peer
#   POST /admin/force_resync_from — cursor/snapshot sync from ONE named peer
#                                   (JSON body {"peer_addr": …}; body stays
#                                    unsigned but its rollback lever is
#                                    hardcoded off server-side)
#   POST /admin/resync            — auto-picks the best-known peer
```

**Roadmap.** Persistent-gap detection + automatic full_pull escalation
shipped (per-record deficit ring, periodic batch re-check, and every-cycle
full_pull escalation while deficits stay open). The remaining manual
step is snapshot re-bootstrap for gaps the connected peers cannot supply —
the signal for that is `elara_full_pull_zero_progress_streak` climbing while
deficits stay open.

## 2. The drand *not-before* time bound is opt-in, not yet network-default

The **drand not-before** lower bound is
supported end-to-end — seal format, offline verifier (BLS against the pinned
League-of-Entropy key), and the node-side beacon fetcher — but the fetcher is
deliberately opt-in: `drand_pulse_enabled` defaults to `false`, so a producer
never emits new seal metadata by surprise. Until it is the network default,
the not-before guarantee applies only to seals that carry an embedded pulse,
and the verifier reports the distinction honestly rather than overstating it.

This is a *default*, not a gap you have to take on faith: a production seal
that carries an embedded pulse is committed in this repo (harvested from the
project's dev-net seed, a producer running with the fetcher enabled), and its
pulse's BLS signature verifies fully offline — `examples/verify/verify.sh`
exercises it (the seal leg prints the `drand not-before … TRUSTLESS` line),
and `examples/verify/README.md` carries the current bundle's filename and
pins for running `elara-verify --seal` on it directly. One committed,
checkable artifact — not a live feed, and not a claim that every live seal
carries a pulse (see the opt-in default above).

## 2b. Older builds and newer metadata: what stays compatible

Unknown non-blocked metadata keys are **admitted and inert** (since
2026-07-02): a node built before a new key existed still ingests, stores,
relays, and seals over records carrying it — it just doesn't interpret the
key. `elara_unknown_metadata_keys_admitted_total` climbing on your node means
peers run a newer schema; you stay in sync, but plan an upgrade. Two rules
keep this sound: key names are frozen to `[a-z0-9_]`, ≤ 128 bytes; and any
key a node must *read* to stay in consensus ships behind a wire/schema
version bump instead (that path fails loudly — see §4).

## 3. Peer counts are asymmetric for inbound-only connections

A seed that only *receives* connections can show `peers_connected: 0` while
followers are actively pulling from it (their sessions are dial-in, not
entries in the seed's dial-out table). Serving activity is visible instead
via `/metrics`: `elara_delta_sync_served_total` climbing = followers are
syncing from this node. A unified peer view is roadmap.

## 4. Mixed-build fleets reject each other's PQ handshakes — by design

The PQ transport binds its frame wire version (currently `0x02`) into the
handshake transcript; builds on different frame versions fail the handshake
cleanly and increment `elara_pq_handshake_wire_mismatch_total`. If a fresh
join "looks like the network is dead", compare `git_sha` from `/status` (or
`/version`) on both sides first — rebuild the older side. Policy: any change
to the frame crypto bumps the frame wire version in the same commit (guarded
by a build-failing fingerprint test), so same-source builds always agree.

## 5. Release binaries: macOS is Apple-Silicon only

The release pipeline ships Linux x86_64/aarch64, Windows x86_64, and macOS
**aarch64** archives. Intel-mac users build from source
(`cargo build --release --features node`).

Two Windows caveats: the Windows archive carries `elara-node.exe` only (no
`elara-cli` yet — drive the node from WSL2 or another machine for CLI
operations), and the `node-windows` build is compile-verified but not yet
runtime-tested on real Windows — treat it as experimental until a tagged
release says otherwise.

## 6. Building with GCC 15+ needs one extra flag

RocksDB 8.10 (vendored by `librocksdb-sys 0.16`) relies on transitive
`<cstdint>` includes that libstdc++ 15 removed, so on GCC 15 distros
(Ubuntu 25.10+, Fedora 42+) the C++ build fails with
`'uint64_t' has not been declared` in `blob_file_meta.h`. Workaround until
the crate is bumped:

```bash
CXXFLAGS="-include cstdint" cargo build --release --features node
```

Found live on 2026-07-02 during the first external-machine join test
(fresh Ubuntu, g++ 15.2). Clang on the same box shares libstdc++ and fails
identically — the flag, not the compiler, is the fix.

## 7. Multi-anchor / multi-zone consensus features not yet exercised at scale

The v0.2.0 release runs correctly as a single-authority testnet (one sealing
anchor, one or few zones, low record rate — the configuration every current
soak uses). Several consensus features that only engage with **multiple staked
anchors or multiple active zones** are shipped but not yet hardened for that
regime, and an internal audit (2026-07-03/04) confirmed real gaps in them.
They do not affect a single-authority deployment; we surface them here rather
than let an operator discover them the hard way. Each is queued for a
design-review-first fix after launch:

- **Zone split/merge authority** — **FIXED 2026-07-05.** Zone-transition
  seal signatures are now accepted only from the staked-anchor trust set
  (the ledger staker set at the witness stake floor, plus the genesis
  authority), enforced at every ingest path (`verify_anchor_sig`) and again
  as a pubkey pre-filter at the finalize tick before a seal can persist or
  mutate routing. Boot replay trusts `CF_TRANSITIONS_FINAL` presence —
  entries can only be written by the stake-gated tick, and re-checking
  *live* stake at boot would let a later unstake retroactively drop a
  legitimately-finalized transition on reboot (registry fork). A
  registered-but-unstaked signer is rejected before any signature
  verification and counted in `elara_transition_sig_stake_rejected_total`.
  (Finding transitions-routes/F1; the fix's design passed an independent
  multi-model adversarial audit on 2026-07-05 before it was built.)
- **Challenge juries** require 100% juror turnout to reach a verdict, and the
  voting window does not resolve on partial turnout — one unavailable juror can
  stall a challenge. Only relevant once real multi-party juries exist.
  (Finding FISH-01.)
- **Cross-zone stuck-zone escalation** (a recovery seal for a zone that stops
  finalizing) cannot currently trigger under the production timing clamp —
  relevant only with multiple zones. (Finding AGG-01.)
- **Per-identity submission rate-limits** anchor their daily counter on a
  record-supplied timestamp and are not yet atomic under concurrency, so the
  cap is bypassable by a determined submitter. Not security-load-bearing at
  single-authority. (Findings TRUST-01/02.)
- **Ledger-record content-hash enforcement is staged behind the re-genesis.**
  The 2026-07-06 fix (finding TOKEN-TYPES/F1) closed the equivocation-proof
  gap two ways: conflict proofs now discriminate duplicate-vs-conflict on the
  full signed record hash (ungameable — previously an attacker could hand-set
  equal content hashes on two different same-slot transfers and make the pair
  unprovable, and the old preimage in fact hashed every amount as 0), and all
  ledger builders emit a canonical v2 content-hash preimage binding creator,
  nonce, and every signed metadata field. What remains staged: the ingest
  gate that REJECTS a record whose content hash does not commit to its
  metadata (`enforce_ledger_content_hash_v2`) defaults OFF, because
  catching-up nodes re-ingest pre-v2 history and would wedge mid-chain. It
  flips ON at the coordinated re-genesis; until then a hand-set content hash
  can still shadow entries in the non-consensus by-hash lookup index
  (equivocation accountability itself is already closed by the record-hash
  discriminator).
- **Seal merkle-root is not recomputed at ingest.** Production seal
  verification (`verify_epoch_seal_no_merkle`) trusts a seal's committed
  `merkle_root` rather than recomputing it from local records, so a malicious
  **staked anchor** could sign a self-consistent seal that finalizes an
  arbitrary subset of the real records it holds (selective finality). Records
  are still individually signature-checked, so this is censorship / selective
  finality, not record forgery, and it is moot with a single sealing authority.
  Queued for a committee-side verify-before-attest (recompute) fix before the
  network runs more than one staked anchor. (Finding seal-verify / R3-9.)
- **Staked/seed relay gossip bypasses node-local rate limits.** A gossip push
  from a peer that is a seed, the genesis authority, or holds **any** nonzero
  stake is treated as a trusted relay: its records skip the node-local
  admission gauntlet (timestamp defense, per-identity and global rate windows,
  trust-tier checks). This is deliberate fork-avoidance — relayed records
  already passed admission at their origin, and re-enforcing node-local
  limiter state on the gossip path would fork snapshot-bootstrapped followers
  from since-genesis nodes — but it means one compromised staked peer could
  push records unbounded by rate limits (still bounded by per-record size
  caps, signature-verification backpressure, and storage dedup). Moot while
  stake admission is operator-controlled; queued for the same
  design-review-first pass as the other multi-staker items before the network
  admits a non-operator staked identity.
  (Finding ingest / skip_timestamp_defense relay trust.)

## 8. Key rotation is specified but not yet operational — do not rely on it

Key **revocation** (the compromised-key tombstone, Protocol §11.2) is live and
authenticated (self-revocation only). Key **rotation** — replacing your signing
key while keeping the same account — is **not yet functional**: an identity is
addressed by the hash of its current signing key, so a rotated key resolves to
a different account and would strand the original account's stake and trust
(findings KR-2/KR-3). Until a versioned fix lands (stable on-record identity +
an identity→active-key index consulted during verification), treat your initial
signing key as long-lived and keep it safe. If a key is compromised, use
revocation, not rotation.
