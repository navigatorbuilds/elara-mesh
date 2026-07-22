# Joining the Elara Dev-Net — Virgin Machine Guide

> **Verified against the live runtime by a full virgin-node join dry-run (fresh
> PoW dual-sig identity → seed discovery → snapshot bootstrap → delta sync →
> converged to the chain head): a throwaway node — built from the curated
> public-mirror tree (the exact artifact an external joiner gets) — joins the live
> seed over the PQ channel and converges to a byte-identical account-SMT root in
> well under 60 s (virgin-join last re-proven 2026-07-11 against the fresh
> post-re-genesis chain — the exact chain-replacing event this gate exists to
> catch — root_local == root_authority `64ff9e19…` at epoch 41669, at-tip in
> 19 s) — snapshot
> path self-verified, with repair_attempts=0 and divergence_epochs=0. The join
> path runs node-to-node over the PQ channel (never public HTTP), so the
> public-surface hardening — loopback-gated `/status` fields, `/metrics` tier
> clamp — does not affect it.** Written for the first external node join. Values
> in `<angle brackets>` are realm-specific and come from the operator — never
> from this document. There are **no public seed endpoints**; the dev-net seed
> address is shared privately, and this is a **pre-launch dev-net that may be
> reset or re-genesised at any time** — always use the current values the
> operator gives you.

## 1. What you need from the operator

- `<SEED-ADDRESS — ask the operator>` — host:port of a reachable dev-net node
- `<GENESIS-AUTHORITY-HASH — ask the operator>` — 64-char hex identity hash
- `<NETWORK-ID — ask the operator>` — realm name; mismatch = handshake rejected

> **Reachability (check this BEFORE you build):** the seed must be reachable from
> your network on **both** its HTTP port **and** its PQ port — the PQ port is the
> seed's HTTP port **+ 100** (so the default `:9473` → `:9573`). All sync, snapshot, and gossip
> traffic runs over the PQ port; there is **no HTTP fallback**. If only the HTTP
> port is open, your node starts cleanly and then sits at `peers_connected: 0`
> **silently, forever** — it looks like a config bug but it's a blocked port.
> Confirm both are open before you spend 20 minutes building (see §7.1). This is
> the *seed's* reachability (the operator's port-forward); as a joining witness you
> need only **outbound** access — you forward nothing.

> **If the SEED-ADDRESS is a Tailscale / WireGuard overlay IP** (`100.x` or
> similar, not a public one): many dev-net operators run behind NAT and **cannot
> port-forward**, so the seed is reachable only inside a private mesh-VPN — the
> overlay *is* the reachability story, there is no public port. Install Tailscale,
> run `tailscale up`, accept the operator's invite, then confirm `tailscale status`
> lists the seed node as online **before** you run the reachability test — and run
> the same both-ports check against the `100.x` address. If the seed isn't in your
> `tailscale status`, you are not on the operator's tailnet and cannot reach it no
> matter which ports are open — ask the operator to (re-)share the node with your
> tailnet. Both seed ports already bind `0.0.0.0`, so they are live on the overlay
> interface automatically; nothing extra is needed operator-side beyond the invite.

## 1.5 The fast path — let `init-join.sh` set you up (recommended)

Once you have the triple **and** you're on the operator's tailnet, you don't have
to hand-check reachability (§7.1) or hand-write the config (§3). The repo ships a
helper that does both — and refuses to let you build into a dead end:

```bash
git clone https://github.com/navigatorbuilds/elara-mesh.git && cd elara-mesh
scripts/init-join.sh <SEED-ADDRESS> <AUTHORITY-HASH> <NETWORK-ID>
```

It proves the seed is reachable on **both** ports *before* you spend 20 minutes
building, format-checks your 64-char authority hash and cross-checks it against
the seed's own report (catching a typo that would otherwise fail your handshake
**silently**), reads the canonical `zone_count` live, and writes a correct
`elara-node.toml`. On success it prints the exact build/boot commands; if
anything is wrong it stops and tells you what — having written nothing. Then
continue at §2's `cargo build`.

> **On Windows/WSL2?** Run `scripts/wsl2-join.sh <SEED-ADDRESS> <AUTHORITY-HASH> <NETWORK-ID>` instead of `init-join.sh`. Under WSL2 NAT the operator's overlay *is* your reachability (§1), so it does the Tailscale setup first, then hands off to `init-join.sh` automatically. See §2's WSL2 section.

The rest of this guide (§2–§4) is the longhand the helper automates — read it to
understand each step, or to configure by hand.

## 2. Build from source

### Linux (Ubuntu 22.04+, 2 GB RAM, 20 GB disk)

```bash
sudo apt update && sudo apt install -y build-essential pkg-config libssl-dev git curl cmake clang jq
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh && source $HOME/.cargo/env
rustup default stable    # Elara needs Rust 1.87+. A fresh rustup gives ≥1.93; if you already had an OLDER rust (e.g. distro `apt` rustc) this line is REQUIRED or the build fails with cryptic proc-macro errors.
git clone https://github.com/navigatorbuilds/elara-mesh.git && cd elara-mesh
cargo build --release --features node     # ~10-20 min first build
```

### Windows via WSL2 (a NAT-constrained witness setup)

```powershell
wsl --install -d Ubuntu-22.04    # then reboot, open Ubuntu, follow Linux steps above
```

**Fast path (recommended).** Inside Ubuntu, clone the repo and run the WSL2
on-ramp — it does the one setup step plain `init-join.sh` doesn't:
```bash
git clone https://github.com/navigatorbuilds/elara-mesh.git && cd elara-mesh
scripts/wsl2-join.sh <SEED-ADDRESS> <AUTHORITY-HASH> <NETWORK-ID>
```
It installs Tailscale and starts `tailscaled` in `--tun=userspace-networking`
mode — the WSL2-safe path, since WSL2 has no reliable `/dev/net/tun` — runs
`tailscale up` (one browser click to join the operator's tailnet), then hands the
triple to `init-join.sh` (§1.5) to prove the seed and write your config. Then
build at §2's `cargo build`. The notes below are the longhand it automates.

WSL2 notes:
- WSL2 NAT is **outbound-only**: your node can dial out, sync, and gossip-pull,
  but cannot be dialed inbound. That is fine for joining — you run as a
  pull-capable witness; you do not need to port-forward anything.
- Keep the WSL clock honest: `sudo hwclock -s` after laptop sleep, or install
  `systemd-timesyncd`. Clock skew breaks attestation freshness.

## 3. Configure

> **`scripts/init-join.sh` (§1.5) writes this file for you**, with every value
> verified live against the seed. This section is the by-hand reference — what
> each field means and why it matters.

Create `elara-node.toml` next to the binary (or pass `--config <path>`):

```toml
network_id        = "<NETWORK-ID — ask the operator>"
genesis_authority = "<GENESIS-AUTHORITY-HASH — ask the operator>"
seed_peers        = ["<SEED-ADDRESS — ask the operator>"]
node_type         = "witness"
auto_witness      = true
data_dir          = "./data"
zone_count        = 1   # MUST match the network's current zone_count — ask the operator
# PQ transport listens on your HTTP port + pq_port_offset (outbound-only is fine under NAT/WSL2)
```

**Do not rely on compiled defaults** — the built-in `seed_peers` is now empty
(the old dev-net fleet was decommissioned and not replaced in code), so a
default-config node dials nobody and sits at `peers_connected: 0` forever. Set
every value above explicitly.

**`zone_count` is network topology, not a local preference.** Records route by
`hash(record_id) % zone_count`; if your node disagrees with the authority it
routes the same record to a different zone and silently forks. Pin it to the
network's **current** canonical value (ask the operator, or read the `zone_count`
field from any seed's `/status`). Today that is `1`. Leaving it at `0` (auto)
boots you at `1` and then tracks the authority's signed `ZoneTransition` chain —
correct only while the network has never split; a snapshot-bootstrapped joiner
does not replay pre-snapshot transitions, so until the network publishes the
canonical count in the bootstrap snapshot, **pin it explicitly.**

## 4. First boot

Pass the **same `--config` on both commands** so the identity is created in the
same `data_dir` the node will boot from (skip it on `--generate-identity` and
the key lands in the *default* dir, not yours):

```bash
./target/release/elara-node --config elara-node.toml --generate-identity   # PoW mining, ~30-90 s
./target/release/elara-node --config elara-node.toml
```

Your identity (Profile A: Dilithium3 + SPHINCS+ dual-signature) lands in
`data/identity.json` — **back it up; it is your node.** For a node you intend
to keep, set `ELARA_IDENTITY_PASSPHRASE` before both commands to encrypt the
key at rest (AES-256-GCM + Argon2id); without it the key is stored in plaintext
(the node warns you).

**Admin token (optional):** the node auto-generates one for its local RPC but
logs only the first 8 chars — the full value is *never* printed to stdout. A
joining follower doesn't need it — you run no admin RPC on join day (you're a
follower, §6). To use admin RPC on your own box, set the value yourself *before* first
boot — `export ELARA_ADMIN_TOKEN='<your-secret>'` or `admin_token = "<…>"` in
the TOML — and reuse it.

## 5. What syncing looks like

You will NOT replay the chain from genesis. Expect, in order:

1. Handshake with the seed (network_id + protocol version checked).
2. **Snapshot bootstrap** — latest signed state snapshot pulled and verified
   (Dilithium3 signature + SMT-root cross-check).
3. **Delta sync** — incremental records since the snapshot's epoch.
4. Live gossip. `curl http://localhost:9473/status` → `peers_connected ≥ 1`
   and `current_epoch` tracking the network's chain head — **that** is the
   "I'm caught up" signal, not `dag_size`. Snapshot bootstrap loads account
   *state* + post-snapshot records and deliberately skips pre-snapshot history,
   so a freshly-joined node showing e.g. 40 records against a seed's 3,500 is
   **synced, not broken**. Watch `current_epoch`; expect `dag_size` to stay far
   below a long-running seed's and to grow only with new records.

> **The easy way — run the bundled self-check instead of eyeballing JSON.**
> It inspects your running node (and the seed, if you give its address) and
> prints a plain-language verdict plus exactly what to fix:
>
> ```bash
> scripts/check-my-join.sh http://localhost:9473 http://<SEED-ADDRESS>
> ```
>
> Read-only and safe to re-run as often as you like. Exit code is `0` once you're
> synced, so you can poll it while you wait:
> `until scripts/check-my-join.sh http://localhost:9473 http://<SEED-ADDRESS>; do sleep 15; done`.
> A green **"🎉 You're in"** means snapshot bootstrap verified, your `network_id` /
> `genesis_authority` / `zone_count` agree with the seed (a silent mismatch on any
> of these forks you even while epochs look caught up — see §3), you're caught up to
> the seed's epoch, **and** your account state is byte-identical to the seed's. If
> it isn't synced yet it tells you which of those is missing and which §7
> troubleshooting step applies (the `peers_connected: 0` PQ-port case especially).

## 6. Your role on day one: a non-staked **follower** (by design)

Day one you join as a **non-staked follower** — the intended, deliberately
restricted posture, not a limitation to "fix" by staking.

- **What a follower does:** syncs to the chain head, verifies every seal against
  the genesis authority, and **submits records** that the authority seals and
  settles network-wide. You are a full verifying replica.
- **Zero consensus weight — on purpose** (the sybil gate). Your attestations do
  not move finality and do not need to; the authority finalizes. **There is no
  join-day staking step.** `/rpc/stake` is *self*-stake only — a node can only
  stake its own identity, so the operator cannot stake you remotely, and on a
  single-authority chain you should not self-stake to "become a validator"
  either (next bullet).
- **Becoming a staked validator is a separate, planned ceremony — not a runtime
  call you make on join day.** The safe path to a real multi-validator set is a
  **coordinated re-genesis straight to ≥3 validators** pinned in
  `genesis_validators` (exercised on a dedicated realm first). Going 1→2 is a
  known liveness-stall trap: only the genesis authority proposes below 3 stakers,
  so a lone second staker that goes dark would wedge finality. Until that planned
  event, every external node is a follower — exactly what the dev-net wants now.

> **Identity age gate (informational):** fresh identities are rate-gated on
> *direct* attestation pushes for ~1 h after first boot (sybil protection). For a
> non-staked follower it is moot — your pushes carry no consensus weight anyway,
> and records you submit still settle via the authority. Not a bug.

## 7. Troubleshooting

> **Expected benign log lines (NOT errors).** `dns_seeds` is empty by default
> (there is no public DNS seed yet — the former `seeds.elara.network` default
> was removed 2026-07-02 because the project does not control that domain), so
> discovery uses only your configured `seed_peers`. If you set a `dns_seeds`
> hostname yourself and it cannot be resolved you will see a
> `DNS seed <name>: resolution failed` warning — the node then falls back to
> `seed_peers`. On a healthy bootstrap you will see `snapshot bootstrap: seeded
> CF_APPLIED with N record ids from snapshot` — that is the normal path (the seed
> ships its dedup set so you skip re-applying already-folded records). The older
> `applied_record_ids empty on wire …` warn now appears only against a pre-fix
> seed or a chain with >1M applied records, and is still harmless: your bootstrap
> verifies the state-tree (SMT) root **before** applying, so your ledger is correct.

### 7.1 The seed's PQ port (HTTP+100) — the #1 silent first-join failure

The PQ port carries **all** sync, snapshot, and gossip traffic — there is **no HTTP
fallback**. A seed whose `/ping` answers but whose PQ port is blocked leaves you at
`peers_connected: 0` **forever**, with no error line. Rule this out *first*.

Test **both** ports from your box:

- HTTP: `curl http://<SEED-ADDRESS>/ping`
- PQ — the seed's HTTP port **+ 100** (`:9473` → `:9573`): `nc -z <SEED-HOST> <PQ-PORT>`;
  no `nc`? `timeout 5 bash -c 'echo > /dev/tcp/<SEED-HOST>/<PQ-PORT>' && echo open`

Or let the script do it: `scripts/check-my-join.sh <my-url> <seed-url>` probes that exact
PQ port and prints **CONFIRMED unreachable** vs **ruled out** — one command tells you
whether it's the port or your config. Connection-refused/timeout on the PQ port = the
operator's port-forward is missing it; refusal on **both** = egress/seed down.
**Overlay seeds:** if SEED-ADDRESS is a Tailscale `100.x` IP, "refusal on both" almost
always means you are not on the operator's tailnet (not a port problem) — run
`tailscale status` and confirm the seed node is listed and online before suspecting ports.

### 7.2 Other issues

1. **`network_id mismatch` in logs** — your `network_id` ≠ realm's; fix the TOML, restart.
2. **Handshake rejected / protocol_version_too_low** — `git pull && cargo build --release --features node`.
3. **Clock skew / stale-timestamp rejections** — `timedatectl` (Linux) or `sudo hwclock -s` (WSL2); NTP must be active.
4. **`peers_connected: 0` for 5+ min** — first rule out the seed's **PQ port** (§7.1); also: seed address wrong, or you set compiled defaults instead of explicit `seed_peers`. Fastest triage: `scripts/check-my-join.sh <my-url> <seed-url>` — given the seed URL it probes that exact PQ port for you and prints **CONFIRMED unreachable** vs **ruled out**, so one command tells you whether it's the port or your config.
5. **Sync stalls mid-snapshot** — restart the node; it resumes from the snapshot baseline, not zero.
6. **Attestations rejected first hour** — the age gate (§6). Wait it out.
7. **`database lock` / `Resource temporarily unavailable` on startup** — another
   `elara-node` is already holding the RocksDB. Check first: `pgrep -a elara-node` and stop
   the stray process (or a duplicate systemd unit). RocksDB releases its lock on clean
   process exit, so only if nothing is running is it a genuinely stale lock from a hard
   crash — then remove `data/rocksdb/LOCK` and restart.
8. **`fatal: failed to bind data-plane listener 127.0.0.1:9472: Address already in use`** —
   the node binds a loopback-only data-plane port (default `127.0.0.1:9472`) **separate** from
   its HTTP/PQ ports, and `listen_addr` does **not** move it. Something already holds 9472
   (`ss -ltnp | grep 9472` — usually a second `elara-node` on the same box). Running one node?
   Stop the stray. Genuinely need two nodes on one machine, or 9472 is taken by another service?
   Add `data_plane_listen_addr = "127.0.0.1:<free-port>"` to the TOML. Not a concern for a normal
   single-node join on a fresh machine — 9472 is free there.
9. **OOM on 2 GB box** — set `gossip_pull_interval_secs = 60`, keep `auto_witness_batch_size ≤ 50`.
10. **Anything else** — capture `journalctl -u elara-node --since "-10 min"` (or stdout) and send it to the operator.

### 7.3 Operator-side: "can't reach me" vs "built the wrong commit"

The two silent first-join failures look **identical to the joiner** (`peers_connected: 0`,
no error line), but the **operator** can tell them apart from the seed's metrics in one
glance:

```
curl -s http://127.0.0.1:<SEED-HTTP-PORT>/metrics | grep -E 'pq_handshake_(failed|wire_mismatch)_total'
```

- **Both flat / zero** while the joiner is stuck at `peers_connected: 0` → the dial never
  arrived. It's the **PQ port** (§7.1) or the joiner isn't on the operator's tailnet — a
  *reachability* problem, not a build problem.
- **`pq_handshake_wire_mismatch_total` climbing** → the dial arrived but the handshake was
  rejected because the joiner built an **incompatible PQ `WIRE_VERSION`** (a different commit
  than the seed). This is the deterministic signature of §7.2 item 2, now visible on the seed
  instead of "looks like the network is dead". Fix on the **joiner**:
  `git fetch && git checkout <operator's commit> && cargo build --release --features node`,
  then restart.

**Two seed-side numbers that will mislead you during a join — and the ones that won't.**
The framing above assumes the *only* handshake traffic is the one joiner; in a real fleet
that is rarely true, so before you read the seed's counters know these two traps:

- **The seed's `peers_connected` stays `0` even when followers are healthily synced.** Sync is
  pull-based: a follower pulls *from* you and the seed keeps no counted session for a pull
  client, so `/status` on the seed shows `peers_connected: 0` as its normal steady state —
  **not** "nobody connected." (The joiner's *own* `/status` correctly shows
  `peers_connected: 1`.) Confirm the join from the joiner, not from the seed's peer count.
  The seed's `/health` `peers` check, however, DOES see inbound liveness: while followers
  sync it reads `ok` — "0 dialed; serving inbound sync (last Ns ago)". "running solo" /
  "mesh lost" on a seed now genuinely means no follower has pulled records for >10 min.
- **`pq_handshake_wire_mismatch_total` is a network-wide aggregate with no per-peer attribution.**
  If *any other* node is on an incompatible `WIRE_VERSION` (e.g. an un-redeployed fleet box), it
  bumps this counter every few seconds regardless of your new joiner. So a *rising*
  `wire_mismatch_total` does **not** by itself mean the new joiner built the wrong commit — note
  its value just before they dial and watch the delta, or trust the positive signals below.

**The reliable "they're in" signals (use these, in order):**
1. **The joiner's own `check-my-join.sh` green verdict** — it ends in a byte-identical
   account-state cross-check against you, the definitive proof. Ask the joiner to send it.
2. **`elara_delta_sync_served_total` climbing on the seed** — the positive "someone is pulling
   from me" gauge. It lags the handshake by a few seconds (snapshot bootstrap and attestation
   pull run first), and it's aggregate (confirms *a* pull is flowing, not *which* peer — there
   is intentionally no per-peer handshake-success counter).

**Joiner-side, before you even dial:** `scripts/check-my-join.sh <my-url> <seed-url>` now
compares the seed's `pq_wire_version` against your own (both read from `/version` over plain
HTTP — which answers even when the PQ port would reject you) and prints **PQ-wire compatible**
or a mismatch with the exact rebuild command. This rules the wire-version trap in/out *before*
the silent `peers_connected: 0`, so you don't need the operator watching their metrics.
