# Run an Elara Node — 5 Minute Setup

> **No public testnet endpoints yet.** The previous VPS testnet fleet was
> decommissioned on 2026-06-09. To try Elara today, run your own local
> realm, or contact the project to arrange a dev-net joining slot
> (see `docs/JOIN-DEVNET.md`).

## Requirements

- Any Linux machine (Ubuntu 22.04+, 2 GB RAM minimum for the witness role), or
- Any Linux/macOS machine with Rust installed (WSL2 works — see `docs/JOIN-DEVNET.md`)

## Option A: Pre-built Binary (fastest)

> **Available from the first tagged release (v0.2.x) onward.** Until that
> release is cut, the download link below returns 404 — use **Option B (build
> from source)** below, which works today.

```bash
# Download + extract the latest Linux x86_64 release (bundles elara-node + elara-cli)
curl -L https://github.com/navigatorbuilds/elara-mesh/releases/latest/download/elara-node-linux-x86_64.tar.gz -o elara-node.tar.gz
tar xzf elara-node.tar.gz
chmod +x elara-node
# Optional, recommended: verify the download (SHA256SUMS + build attestation) — see ../VERIFY.md (repo root)

# Generate your identity (takes ~30 seconds for PoW mining).
# Copy the "identity hash" it prints — you need it in the next step.
./elara-node --generate-identity

# Start a solo node — you are the genesis authority of your own realm.
# Paste the identity hash from the previous step into ELARA_GENESIS: that is
# what makes you the authority. Without it the node has no genesis authority
# and rejects all token ops ("genesis_authority is empty" warning at startup).
# (No ELARA_NETWORK_ID is set, so the node runs on the default network and the
# bundled elara-cli can submit to it out of the box. For a *named* private realm,
# set ELARA_NETWORK_ID here and pass the same id to the CLI: elara-cli --network <id>.)
ELARA_GENESIS=<paste-your-identity-hash-here> \
ELARA_NODE_TYPE=witness \
ELARA_AUTO_WITNESS=true \
./elara-node
```

To **join an existing realm** instead, you need two values from that
realm's operator — never guess them:

```bash
ELARA_GENESIS=<GENESIS-AUTHORITY-HASH — ask the operator> \
ELARA_SEEDS=<SEED-ADDRESS — ask the operator> \
ELARA_NETWORK_ID=<NETWORK-ID — ask the operator> \
ELARA_NODE_TYPE=witness \
ELARA_AUTO_WITNESS=true \
./elara-node
```

Joining nodes sync via state snapshot + incremental deltas (no genesis
replay). The full join path, including staking and the identity age gate,
is in `docs/JOIN-DEVNET.md`.

## Option B: Build from Source

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Clone and build
git clone https://github.com/navigatorbuilds/elara-mesh.git
cd elara-mesh
cargo build --release --features node
# GCC 15+ (e.g. Ubuntu 25.10): if the build fails inside librocksdb-sys with
# "'uint64_t' has not been declared", prefix the build with the missing
# transitive include and rerun:  CXXFLAGS="-include cstdint" cargo build --release --features node

# Generate identity (copy the identity hash it prints — see Option A)
./target/release/elara-node --generate-identity

# Run (same env vars as Option A, including ELARA_GENESIS=<your-identity-hash>)
./target/release/elara-node
```

## Verify It Works

```bash
# In another terminal:
curl http://localhost:9473/health
```

A **solo** node reports `{"status":"degraded",...}` (readiness `yellow`), and
that is **expected** — the only failing check is `peers` ("no connected peers
(running solo)"); the rest read `ok`. `"status":"healthy"` requires connected
peers, so it appears only once your node joins or is joined by others.

```bash
curl http://localhost:9473/status   # dag_size = records held; finalized_count = finalized
```

Submit a record with the bundled CLI:

```bash
./elara-cli --node http://localhost:9473 \
  transfer --to <any-64-hex-hash> --amount 50 --identity ~/.elara/identity.json
# → accepted: <record-id>
```

On a **solo** node a record created by the staked identity itself is
*accepted* but stays `pending` — a creator cannot attest its own records, so
finality needs a staked validator **other than the record's creator**. A
record emitted by a different, non-staker identity finalizes even on a solo
staked node (the docker demo does exactly this); the staker's own records stay
pending, with balances and `finalized_count` unchanged (this is correct, not a
failure). To make those finalize, start a second node that joins this one (same `ELARA_GENESIS` and
`ELARA_NETWORK_ID`, with `ELARA_SEEDS` pointing back here) and stake it — the
full join + staking flow is in `docs/JOIN-DEVNET.md`.

## Run as Service (recommended)

The node installs itself — one flag registers it with the operating system so
it starts on every boot and restarts on failure:

```bash
# Set your configuration first (same env vars as above), then:
sudo -E ./elara-node --install-service          # system-wide (recommended)
./elara-node --install-service                  # or per-user (no root; prints a lingering hint)
```

The installer snapshots your current `ELARA_*` environment variables and
command-line flags into the service definition, so the service runs exactly
the node you configured. On **WSL2** it also adds a Windows logon entry that
wakes WSL at login (WSL does not boot on its own), and on **Windows** it
creates a logon autostart entry. Preview everything without changing anything
with `--service-dry-run`; inspect with `--service-status`; remove with
`--uninstall-service`.

<details>
<summary>Manual alternative (write the systemd unit yourself)</summary>

```bash
sudo tee /etc/systemd/system/elara-node.service > /dev/null <<EOF
[Unit]
Description=Elara Node
After=network-online.target
Wants=network-online.target
# Bound the restart loop: a state_core worker panic aborts the process by design,
# so without this a deterministic panic crash-loops forever instead of paging.
# Interval must exceed (StartLimitBurst-1)*RestartSec = 20s (systemd's default 10s
# is too low). Mirrors deploy/elara-node.service; --install-service sets it too.
StartLimitIntervalSec=30
StartLimitBurst=5

[Service]
Type=simple
WorkingDirectory=/opt/elara
ExecStart=/opt/elara/elara-node
Environment=ELARA_DATA_DIR=/opt/elara
# Solo realm: you are the genesis authority — paste your own identity hash here
# (the same one from --generate-identity above). The bare binary does NOT
# auto-resolve genesis, so without this the node rejects all token ops.
Environment=ELARA_GENESIS=<paste-your-identity-hash-here>
Environment=ELARA_NODE_TYPE=witness
Environment=ELARA_AUTO_WITNESS=true
# Joining an existing realm instead? Use the operator's hash for ELARA_GENESIS
# above, and add their seed + network id:
# Environment=ELARA_SEEDS=<SEED-ADDRESS — ask the operator>
# Environment=ELARA_NETWORK_ID=<NETWORK-ID — ask the operator>
Restart=on-failure
RestartSec=5
# RocksDB fds + the node's connection-admission defaults are sized against 65536;
# the systemd default (1024) strangles a node under load (EMFILE → gossip deaf).
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

sudo mkdir -p /opt/elara
sudo cp elara-node /opt/elara/
sudo cp ~/.elara/identity.json /opt/elara/
cd /opt/elara && sudo systemctl enable --now elara-node
```

</details>

## What Your Node Does

- **Witnesses** records created by other nodes (earns beats)
- **Stores** the full DAG (contributes to network resilience)
- **Gossips** records to peers (keeps the network connected)
- **Validates** signatures using post-quantum cryptography (Dilithium3)

## Need Help?

- Issues: https://github.com/navigatorbuilds/elara-mesh/issues
- Email: nenadvasic@protonmail.com
