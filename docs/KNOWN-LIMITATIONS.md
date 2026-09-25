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
   ML-DSA-65 (FIPS 204, "Dilithium3") keypair JSON; authorize its public key on the node via the
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
exercises it (the seal leg prints the `drand not-before … VERIFIED not-before for the seal` line),
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
- **Per-identity submission rate-limits** — **FIXED 2026-07-19**, hardened
  2026-07-29 and 2026-08-29. The daily cap is now a single atomic
  check-and-increment under its own short-lived lock (`DailyCapCounter`),
  keyed on the node's wall clock rather than the record-supplied timestamp,
  persisted across restarts (a restart used to reset every identity's
  quota), and every lock-contention fallback fails closed to the strictest
  tier cap. (Findings TRUST-01/02.)
- **Per-identity entropy profiles are time-bounded, not count-bounded.** The
  7-day event window that feeds the trust tiers is pruned by age only; a
  single identity sustaining thousands of records a day (possible only for a
  staked identity, or through a trusted relay) grows its profile and the
  per-record scoring pass with it. Harmless at today's record rate; queued as
  a bounded-reservoir refactor. (Finding TRUST-03.)
- **DAG parent edges are not checked for self-reference or cycles at
  re-link.** Every DAG walk is visited-guarded and depth-capped, so a
  malformed parent set cannot loop a node; it can only pollute the
  root/tip/orphan gauges. Moot while the operator's authority is the only
  record creator. (Finding DAG-01.)
- **Ledger-record content-hash enforcement is staged behind the re-genesis.**
  The 2026-07-06 fix (finding TOKEN-TYPES/F1) closed the equivocation-proof
  gap two ways: conflict proofs now discriminate duplicate-vs-conflict on the
  full signed record hash (ungameable — previously an attacker could hand-set
  equal content hashes on two different same-slot transfers and make the pair
  unprovable, and the old preimage in fact hashed every amount as 0), and all
  ledger builders emit a canonical v2 content-hash preimage binding creator,
  nonce, and every signed metadata field. The ingest gate that REJECTS a
  record whose content hash does not commit to its metadata
  (`enforce_ledger_content_hash_v2`) has run ON at the authority node since
  the coordinated re-genesis of 2026-07-11; its compiled default stays OFF so
  that a node replaying a pre-v2 archive is not wedged mid-chain. On a node
  running that default, a hand-set content hash can still shadow entries in
  the non-consensus by-hash lookup index (equivocation accountability itself
  is closed by the record-hash discriminator).
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

## 9. Integer metadata values above `i64::MAX` produce records that cannot verify

A record whose metadata holds an integer larger than `i64::MAX` (for example
`2^63 + 12345`) is signed over the exact integer, but the binary wire format
carries it as a float. A receiver re-derives the signature preimage from the
decoded value, gets a different preimage, and rejects the record as if it were
a forgery. No error is raised when the record is created.

This fails closed: nothing is admitted that should not be. The cost is that
this value class is unusable and the rejection is hard to diagnose. Until it
is fixed, store such values as strings. The reproducer is the ignored test
`wire03_large_u64_metadata_must_roundtrip_losslessly` in
`crates/elara-record/src/wire.rs` (finding WIRE-03). Rejecting these values at
encode time with a typed error would not fork the network, since every record
it would newly reject already fails verification; carrying them losslessly
would need a new wire tag, which is a wire-format change.

## 10. On Linux the node runs jemalloc's default memory settings

The node binary allocates through jemalloc. The source carries a tuning string
that releases freed memory to the operating system more aggressively, but on
Linux jemalloc reads its settings from the `MALLOC_CONF` environment variable
instead, so a Linux node runs jemalloc's defaults. To apply the same tuning,
set it in the service environment:

```bash
MALLOC_CONF=dirty_decay_ms:0,muzzy_decay_ms:0,narenas:2,background_thread:true
```

The effect of this setting on a running node's memory has not been measured.

## 11. The second signature does not yet protect against an ML-DSA break

Profile A identities sign every record twice, with ML-DSA-65 and with
SPHINCS+-SHA2-192f, so that forging a record should need both broken. The code
does not enforce that yet. The SPHINCS+ public key travels inside the record:
it is not part of the identity (an identity is the hash of its ML-DSA key
alone) and it is not covered by the ML-DSA signature. Verifiers check the
SPHINCS+ signature against whatever key the record carries. So anyone who can
forge ML-DSA signatures for an identity can strip the SPHINCS+ fields, or attach
a key pair of their own, and the record verifies, dual-signed or not. Epoch
seals need only ML-DSA. Until the SPHINCS+ key is bound to the identity and
required for it, a record's authenticity rests on ML-DSA-65 alone. That binding
is a versioned change and is not scheduled.

## 12. The SPHINCS+ signature is not FIPS 205 SLH-DSA

The SPHINCS+ library (`lattice-slh-dsa` 0.3.3) hashes with SHA-256 throughout.
FIPS 205 requires SHA-512 for several of its functions (H_msg, PRF_msg, H and
T_l) at security categories 3 and 5, which includes the 192f parameter set used
here. So Elara's signatures do not verify under a FIPS 205 SLH-DSA-SHA2-192f
implementation, and FIPS 205 signatures do not verify under Elara's.
`crates/elara-record/tests/acvp_slhdsa192f.rs` pins this against NIST's test
vectors. A third-party verifier has to reproduce the shipped hashing, not FIPS
205, to check today's records. What the difference does to the security level
at category 3 has not been analysed. The same library's SHAKE parameter set
does match NIST's vectors (`crates/elara-record/tests/acvp_slhdsa_shake192f.rs`),
so SLH-DSA-SHAKE-192f is one migration path. A migration would be a new
algorithm ID and a versioned change, and it is not scheduled.

## 13. The light-client balance check needs keys you pin, and does not prove the seal is current

`LightClient::verify_balance` checks that a node's account proof is consistent:
it re-hashes the leaf and rebuilds the Merkle path up to the root the node
supplied. That catches a node whose balance disagrees with its own proof. It
does not catch a node that fabricates a whole consistent proof, root included,
and the "sealed" flag it returns is the node's own claim (see the trust-boundary
note in `src/network/light_sdk.rs`).

`LightClient::verify_balance_anchored` (added 2026-09-25) closes that gap for
the root. It fetches the seal record the node names, checks its Dilithium3
signature against anchor keys you pin, and requires the proof root to equal the
account root that the signed seal commits. What it still leaves to you:

- **Freshness.** It proves that a pinned key signed this root at this epoch, not
  that the seal is the latest one. A node can replay an older signed seal
  together with a proof against its root. The method returns the epoch and seal
  time read from the signed record; whether they are recent enough is your call.
- **The keys.** The check is exactly as good as the keys you pin. It does not
  follow changes to the validator set, and keys read from the node you are
  checking prove nothing.
- **Nodes that lag.** A node returns a bound proof only when its tree root
  equals the latest seal's root. Propagation lag can keep that false for a
  while; the check then stops at `ProofUnsealed` and a pool tries its next seed.
- **Accounts that changed since the last seal.** The proof covers the account
  as it was at the last seal, while the balance the node reports is its live
  one. When the node says the two differ, every balance method returns
  `StateAheadOfSeal`, and nothing can be verified until a later seal covers the
  account; a busy account can spend much of its time in this state. Until
  2026-09-25 the SDK reported this honest case as `LeafHashMismatch`, which
  accused the node of lying and stopped a pool.
- **One bad seed stops a pool.** A seed whose proof fails the leaf or path
  check (`LeafHashMismatch`, `ProofInvalid`) or whose answer does not parse
  ends the pool's search instead of being skipped. That is deliberate, so a
  lying or broken node is reported rather than hidden, but it means one such
  seed early in the list blocks an answer the later seeds could give.

`verify_balance_against_trusted_seal` compares the proof against a seal epoch
and root that you supply, and it is exactly as good as your source for them.

## 14. Records without a network identifier are accepted on every network

Current nodes build wire-version-7 records, and from version 6 on a record signs
over a network identifier. Two kinds of record carry none. Versions 4 and 5 have
no such field, and nodes still accept them (`WIRE_VERSION_MIN = 4` in
`crates/elara-record/src/wire.rs`). And a record of version 6 or later signs over
an empty identifier when the program that built it never set one: `elara-node`
and `elara-cli` set it at start-up (`set_emission_network_id`), but other code
does not, including the browser client in `browser-node/`. Ingest admits a
record with an empty identifier on any network (`network_id_admits` in
`src/network/ingest.rs`). So such a record, signed for one network, could be
admitted on another. Replay has not been traced end to end. The fix is to have
every client set its network and then, at a flag day, stop admitting records
without one. Neither step is scheduled.

## 15. Peer keys are trusted on first use

When a node dials a peer, it accepts whatever Dilithium3 key the peer presents
on first contact and pins it for later dials (`<data_dir>/pq-peer-pins.json`).
Seed peers are configured as plain addresses, so a node's first dial to a seed
is trust-on-first-use too, and a man-in-the-middle on that first connection is
not detected. Inbound connections are open to any key, except on a node running
a sovereign realm, which admits only pinned identities. The ProVerif model
in `spec/proverif/` proves authentication for a peer the initiator has already
pinned, so first contact is outside what it proves. To close the gap for a known
peer, write its identity hash into the pin file before first contact, with the
node stopped (the store is `PeerIdentityStore` in
`src/network/pq_transport/peer_store.rs`).

## 16. Records signed with retired algorithms no longer verify

Crypto agility as designed would keep old records valid under the algorithm
they were signed with. Current builds do not. Signatures from the round-3 Dilithium3
submission (3,293 bytes) are rejected (`crates/elara-record/src/pqc.rs`), as are
proofs from the retired elliptic-curve VRF (`src/crypto/vrf.rs`), and wire
versions 1 to 3 no longer decode. Such records need the older build that
produced them to verify. Keeping retired verifiers as a separate, verify-only
component is possible but not built.

## 17. Identity keys are stored in plaintext by default

A node's identity file holds its secret keys as plaintext JSON unless
`ELARA_IDENTITY_PASSPHRASE` is set, in which case the file is encrypted with
Argon2id + AES-256-GCM. Set `ELARA_REQUIRE_ENCRYPTED_IDENTITY=1` to make the node
refuse to start on a plaintext file. The VRF key file that sealing nodes keep
is always plaintext. Setting a passphrase on an existing node
encrypts the file in place, but that cannot erase plaintext already written to
the disk, its backups or its snapshots.

Since 2026-09-25 identity files, and the VRF key file that sealing nodes keep,
are created owner-only (0600) from the first byte and replaced atomically.
Earlier builds wrote them at the default file mode and tightened them to 0600
straight afterwards, so under a typical umask a file written by an older build
could be read by other local users for a moment. Some in-memory copies of secret keys
(`Identity::secret_key_bytes`) are still not wiped when freed.

## 18. Finality counts attesting stake; the diversity weighting does not gate it yet

MESH-BFT's design weighs witnesses by independence: witnesses that share an
organization, subnet or location count for less, so that one operator's clones
cannot settle a record alone. The shipped code computes that weighting but does
not gate finality on it. A record becomes durably final once attesting stake
reaches two-thirds of the zone's eligible stake, excluding the creator, and every
durable-finality path reads that raw-stake check (`is_settled` in
`src/network/consensus.rs`). The diversity-weighted check (`is_settled_diverse`)
feeds only the reported confirmation level and the record detail view, and even
there it falls back to the raw check when no witness profiles are known or fewer
than three distinct organizations attest. Organizations are self-declared, and
the default configuration advertises no witness profile.

So today stake is what holds a clone committee off, as in any proof-of-stake
system. Even once the weighting gates finality, it cannot raise the classical
one-third bound against an adversary whose identities are spread across distinct
organizations, subnets and networks: those identities look independent.
Editions of the MESH-BFT paper before 2026-09-25 said the weighting works
"beyond the classical n/3 bound" and "regardless of stake"; that was wrong, and
the 2026-09-25 edition corrects it (§24). Gating finality on the diversity check
is a consensus change and is not scheduled.

## 19. Seal-level settlement does not complete today

Above per-record finality, the design settles whole epoch seals: witnesses
attest a seal, and it settles at a diversity-weighted two-thirds of eligible
stake, excluding the proposer (`is_seal_settled` in `src/network/consensus.rs`).
Under the default configuration that threshold cannot be reached. With no witness
profiles known, every pair of attesters is treated as correlated (0.8), and at
that correlation two or more attesters of similar stake never reach two-thirds of
the weighted stake. The proposer's own stake does not count as a vote. On a
network with one staker there is no eligible stake at all. And a seal that fails
to settle is not escalated, because escalation fires only for an epoch with no
seal. The authority node's metrics agree: no seal has settled. Records still
finalize one by one (§18), so the practical effect is that the seal-settlement
layer, and the liveness argument the MESH-BFT paper builds on it, does nothing
yet; the paper's 2026-09-25 edition says so. Counting the proposer's stake and
escalating on non-settlement are consensus changes and are not scheduled.

## 20. Witness attestations carry one signature

A witness attestation carries one ML-DSA-65 signature. Profile A's second
signature protects record authorship (and only once §11 is fixed), not
consensus: if ML-DSA-65 is broken, attestations, and so settlement, can be
forged. Editions of the MESH-BFT paper before 2026-09-25 said the protocol
enforces a minimum Profile A quorum among attesters; no code does, and the
2026-09-25 edition says so. Dual-signed attestations and an enforced quorum are
a consensus change and are not scheduled.

## 21. The previous sealer can bias the order of the next sealers

The order in which anchors may seal the next epoch is ranked from a beacon that
includes the previous seal's hash; the VRF output is not used for the rank. So
the anchor that sealed the previous epoch chooses fields that feed the next
beacon, and it can search them for an order that favours it or its allies. The
MESH-BFT paper's bound, under which the chance that all seven ranked sealers are
faulty falls as (1/3)^7, assumes an unbiased draw and does not hold against such
a sealer. In a single zone such a sealer can stall sealing; with several zones,
cross-zone escalation bounds the delay. This is moot with one sealing authority.
Ranking from the VRF output is a hard-fork change and is not scheduled.

## 22. The genesis authority's powers have no expiry, and a slash needs no evidence

Privileged actions, including slashes and zone transitions, are accepted from
exactly one key, the genesis authority's (`is_privileged_emitter` in
`src/accounting/authority.rs`), with no expiry and no hand-over. The whitepaper
says bootstrap mechanisms become inert; in code this one does not, and its expiry
is a roadmap item. A slash carries a free-text reason and no offense proof, and
validation (`validate_slash` in `src/accounting/validate.rs`) checks none. Each
slash takes at most half of a stake, but a partly slashed stake stays active, so
slashes can repeat, and the challenger and jury shares go to whichever identities
the slash names, which may include the authority itself. On today's
single-authority network this is simply the operator's power, stated plainly. A
network that admits other stakers has to trust the authority key with it until a
slash requires a verified offense proof, carries a per-offense de-duplication key,
and excludes the authority and the offender as payees. Those are consensus
changes and are not scheduled.

## 23. Attestations that arrive by pull skip the minimum-stake and identity-age checks

An attestation pushed to a node passes two admission gates: the witness must
hold at least the minimum witness stake (100 beats), or the attestation is
buffered until the stake arrives; and the node must have known the witness's
identity for at least an hour, or the attestation is refused. Attestations that
arrive by the pull paths, or that wait in the deferred queue for a record the
node does not hold yet, skip both gates; their signatures are still checked.
Zero-stake witnesses add nothing to finality, but a stake below the minimum, or
an identity too new, counts on some nodes and not on others, so verdicts can
diverge near the threshold. And up to 128 zero-stake witnesses per record can join the
diversity set and depress the seal-level and confirmation-level weighting, a
liveness effect rather than a safety one. One shared admission check for every
path is a consensus change and is not scheduled.

The same three pull paths (the targeted attestation pull and the two
auto-witness pull phases) also do not check the optional proof-of-work-at-stake
(PoWaS) that the push paths and the batch pull verify when it is present. That
check belongs in the same shared admission change.

Related, fixed 2026-09-25: those three pull paths checked an attestation's
signature under the public key the peer sent, but not that the key hashes to the
witness identity the attestation names, so a peer could have had a node credit
another identity's stake. All three now run one shared check
(`verify_pulled_attestation` in `src/network/witness.rs`). The push paths and the
batch pull always bound the key.

## 24. The MESH-BFT paper describes the design, and some of its proofs are sketches

The MESH-BFT paper (`site/papers/MESH-BFT-PAPER.pdf`) states the consensus
design; where the shipped code differs, §18 to §23 say how. A self-audit on
2026-09-25 found claims in earlier editions that were false or unsupported, and
the 2026-09-25 edition corrects them, each marked "Correction (2026-09-25)". The
safety theorem now states the assumption it needs, Byzantine stake below one
third of the eligible stake (§18), and has a quorum-intersection proof. That
proof needs two conflicting records to be settled against the same stake total,
which the code does not guarantee once there are several zones (the settlement
zone follows the record identifier) or an active zone committee (the numerator
counts every attester, the denominator only committee stake); both are latent on
today's single-zone network. The post-quantum theorem covers record authorship
only, since attestations carry one signature (§20), and the dual-signature level
is about 192 bits, not 384. The liveness theorem is marked as a design target
that the shipped seal layer (§19) and a grinding sealer (§21) do not meet. The
hop-count formula, written O(log n / log √n) in earlier editions and equal to 2
for every n, is restated for a fixed fan-out of 3, and the evaluation now matches
the six-node testnet. What remains: the liveness theorem and one lemma have proof
sketches only, machine checking is limited to bounded TLA+ models and ProVerif
(the paper's §8.2), and hop counts and throughput beyond the testnet are
projections, not measurements.

## 25. Some performance figures are design targets, not measurements

- **Phones.** The Rust implementation has been measured on x86 only. On a 2014
  desktop CPU a record is signed in under 1 ms with ML-DSA-65, and the optional
  SPHINCS+ signature adds about 125 ms (README benchmarks). No phone or low-cost
  ARM device has been measured; sub-second signing on a cheap phone is a design
  target.
- **Seal latency.** The default epoch is 60 seconds, and a record is sealed at
  the next epoch boundary. An optimistic "sealed" state within seconds is
  designed, not measured.
- **Proof checks.** Light-client proof checks have been run in desktop browsers,
  not measured on phones.

## 26. Splitting stake across identities raises a staker's chance to be selected

Two selections weight each identity by the square root of its stake: the order in
which anchors may seal an epoch, and the witness committee once a zone's pool
exceeds ten identities. The root is taken per identity, so a staker who divides
the same stake among k identities gains about √k in selection weight. Dividing is
cheap. Anchor status is declared by the identity itself, and each stake needs
only the 100-beat minimum. One identity holding 99% of stake ties 100 identities
that share the other 1% for the first sealing slot (the case pinned by
`sqrt_weighting_whale_ties_split_farm` in `src/network/aggregator.rs`). Majority
stake therefore does not guarantee majority selection. The first-ranked anchor
proposes the epoch's seal, and with section 21 it can also steer the next
epoch's order. The per-zone committee draw (`select_zone_committee`, which
also fixes the committees recorded in zone split and merge seals) and a
flag-gated alternative (`use_committee_v2`, off by default) divide a hash by the
stake itself. That is not proportional to stake either, and it biases the other
way: at 2:1 stake the larger identity takes the first seat three times in four,
not two in three, and stake held by one identity wins more often than the same
stake split across many. Turning the flag on would swap one bias for the other.
Moving all three selections to stake-proportional weighting is a consensus
change and is not scheduled. This is moot with one sealing authority: ranking
starts at three staked anchors.

## 27. Governance records reach the ledger only when a node replays records

A running node validates each governance record (proposal, vote, execution,
cancellation, delegation) when it arrives, then stores and gossips it, but does
not apply it to its ledger. The live apply step (`apply_ledger_op_phase4` in
`src/network/ingest.rs`) handles ledger operations only; the governance delta of
the tentative-ledger design was never built,
and the direct path that used to cover governance was removed with the
tentative-ledger feature flag in April 2026. Governance records are applied only
when a node replays records into its ledger (`rebuild_ledger_streaming` and
`incremental_ledger_replay` in `src/storage/rocks.rs`). A full rebuild applies
them all. A restart from the ledger checkpoint replays only records newer than
the newest record already in the checkpoint, and every live ledger operation
moves that point forward, so a governance record that arrived before the last
ledger operation is skipped until the next full rebuild (`POST /admin/rebuild`,
node-local).

So a vote fails validation ("proposal not found") on any node that has not
applied its proposal, and two nodes can hold different governance state
depending on when each last rebuilt. Applying governance records in the same
order on every node, live and at rebuild, is a consensus change and is queued.

## 28. A proposal's tally depends on when it is settled

A proposal is settled when the first governance record after its voting
deadline is applied (`apply_governance_op` in `src/accounting/ledger.rs`), and
`settle_proposal` (`src/accounting/governance.rs`) computes the tally at that
record's timestamp, not at the deadline. Conviction keeps growing after the
deadline, and the quorum is measured against the governance stake at settlement.
The outcome therefore depends on which record triggers settlement and on stake
changes after the deadline, not only on the votes and stake at the deadline.
Tallying at the deadline, with the quorum measured at the deadline, is a
consensus change and is queued.

## 29. A vote keeps its weight after the voter unstakes

A vote records the voter's own governance stake when it is cast
(`cast_vote_with_own`); settlement adds the stake delegated to the voter at that
time (`reconcile_effective_stakes`) but does not check that the voter's own stake
is still staked. Staked beats can be unstaked 7 days after staking
(`UNSTAKE_COOLDOWN` in `src/accounting/types.rs`). The capital behind a vote is
therefore locked for 7 days, not until the tally, and the conviction curve does
not change that. Re-checking the voter's stake at settlement is queued.

## 30. The emergency veto and critical-proposal committees are not wired in

The governance state machine implements the anchor veto's threshold (more than
75% of anchors) and its limit of two vetoes per zone per quarter
(`anchor_veto_signal`), and trust-weighted committee selection
(`select_committee`), both in `src/accounting/governance.rs`. No record type
carries a veto signal and nothing in the node calls `select_committee`, so the
veto cannot be invoked on the network, and its 72-hour public disclosure and
its override by a second vote with more than 80% conviction are not
implemented. A critical proposal submitted as a record fails when applied,
because no committee is supplied. Wiring both is a consensus change and is
queued.

## 31. Classified records do not yet hide their content

A record classified Private or Restricted must carry a proof (`zk_proof`), which
the node checks when the record arrives (`src/network/ingest.rs`). The Phase-1
proof is a SHA3-256 commitment (`src/crypto/commitment.rs`), and it hides
nothing: the proof carries its own opening (the content hash and the blinding
value), the verifier checks only that the commitment matches that opening, and
nothing compares the opened hash with the record's own content hash, so a proof
is not bound to the record it travels with. Every record also carries its plain
content hash. Legacy proofs (version `0x01`) get structural checks only, and
Groth16-format proofs (`0x02`) are always rejected because no verifier exists.
Records from the genesis authority, and records that arrive through sync, are
accepted without a proof, and a Sovereign record needs none. A classification
is therefore a label today, not a confidentiality guarantee; confidentiality
comes only from what a creator keeps off the network, for example by
encrypting content before hashing it. Binding the commitment to the record's
content hash and requiring proofs on every ingest path are a consensus change
and are queued; hiding the content hash itself needs the zero-knowledge layer,
which is specified, not built.

## 32. A node contacts public STUN servers at startup

A node with no configured advertise address runs NAT detection at startup
(`auto_detect_nat` in `crates/elara-nat/src/lib.rs`, called from
`src/bin/elara_node.rs`). It sends STUN requests to public servers operated by
Google, Cloudflare and stunprotocol.org (`STUN_SERVERS`), which learn the
node's public IP address and the time of the request, but nothing about its
records. The check ignores the network realm, so a node configured as a
Sovereign realm, whose other outbound discovery is off, still makes these
requests. Setting `advertise_addr`, or blocking outbound traffic to those
servers, avoids them. Skipping NAT detection in a Sovereign realm, or making it
opt-in, is queued.

## 33. Snapshot replay protection is best-effort above one million records

A snapshot served to a joining node carries the set of record ids already
applied to the ledger only while the serving chain has at most one million
applied records (`MAX_SNAPSHOT_APPLIED_RECORDS` in
`src/network/routes/sync.rs`). Above that the set is sent empty, and the
joining node's protection against applying a record the snapshot already
contains is best-effort. A bounded watermark that removes this limit is
designed and queued.

## 34. The whitepaper's witness requirements are only partly enforced

The whitepaper (section 7.5.1) lists four requirements for acting as a
witness. The node enforces them as follows.

- **Minimum stake of 100 beats.** Checked for attestations pushed to a node;
  the pull paths skip it (section 23).
- **Proof of work** (`min_pow_difficulty`, 20 bits by default). Checked when a
  node admits a peer to its peer table (`src/network/peer.rs`), not when it
  counts an attestation; the witness an attestation names is not checked for it.
  An attestation may carry its own optional proof of work (PoWaS), which the
  push paths and the batch pull verify when present (section 23).
- **Identity age of at least 48 hours.** The push paths require one hour,
  counted from when the checking node first saw the identity, so it differs
  between nodes and resets when a node restarts from a stale trust snapshot.
  Genesis validators are exempt, and the genesis authority skips both push
  checks. The 48-hour branch in the code is unreachable, because a witness below
  the minimum stake is deferred before the age check runs.
- **Diversity:** no single entity or /24 subnet may control more than 33% of a
  zone's staked weight. The check exists as `can_witness` in
  `src/network/zone.rs`, keyed by a self-declared organization name rather than
  a subnet, but only tests call it, and no admission path enforces the cap. The
  peer-discovery table limits entries per /24 subnet, but that bounds routing
  entries, not staked weight.

Enforcing all four in one shared admission check is a consensus change and is
queued.
