# Install & build troubleshooting — the "it didn't work" page

Almost every first-run problem is one of the items below, and each has a
copy-paste fix. **Before anything: you probably don't need to build at all** —
after the first tagged release, [download a prebuilt binary](https://github.com/navigatorbuilds/elara-mesh/releases)
(no Rust, no compiler). If you *are* building from source, run
`scripts/build.sh` instead of raw `cargo` — it applies most of these fixes for
you automatically and checks your toolchain *before* the 20-minute compile.

If none of these match, open an issue with the full error and your OS + `rustc
--version` + `cmake --version` — a failing first build is a bug in *this page*,
and it'll get a new entry.

---

## Build failures

### `'uint64_t' has not been declared` (or similar, deep in a rocksdb / C++ error)
**The single most common one on fresh 2024+ Linux.** gcc 13+ tightened its header
rules and RocksDB 8.x trips on it. Fix — force-include the header:
```bash
CXXFLAGS="-include cstdint" cargo build --release --features node
```
`scripts/build.sh` detects gcc 13+ and does this automatically.

### `error: could not find 'cargo'` / `cargo: command not found`
Rust isn't installed (or isn't on your PATH). Install it — 2 minutes:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

### Cryptic `proc-macro` / `edition2021` / "feature X is stable" errors
You have an **old** Rust (usually a distro `apt`/`dnf` rustc, ~1.7x). Elara needs
**1.87+**. Switch to rustup's toolchain:
```bash
rustup default stable      # a fresh rustup gives >= 1.93
```

### `cmake: not found`, `clang: not found`, or `failed to run custom build command for librocksdb-sys / oqs-sys`
The native C dependencies (RocksDB, liboqs) need a C/C++ toolchain:
```bash
# Debian/Ubuntu
sudo apt install -y build-essential pkg-config libssl-dev cmake clang libclang-dev git
# Fedora/RHEL
sudo dnf install -y gcc gcc-c++ make cmake clang clang-devel openssl-devel git
# macOS
xcode-select --install && brew install cmake
# Windows (PowerShell, admin)
choco install cmake llvm
```

### The build gets `Killed` / the machine freezes near the end
**Out of memory.** The RocksDB compile is the peak — each parallel job can use
~1.5–2 GB, so a 4 GB box with default parallelism gets OOM-killed. Cap the jobs:
```bash
CARGO_BUILD_JOBS=2 cargo build --release --features node    # or =1 on <=3 GB
```
On a very small box also add swap (the final binary link needs headroom):
```bash
sudo fallocate -l 4G /swapfile && sudo chmod 600 /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile
```
`scripts/build.sh` sets the job cap automatically from your detected RAM.

### "It's been 15 minutes — is it stuck?"
No. A first release build is **10–30 minutes** (RocksDB + liboqs + ~350k lines of
Rust). There's no per-line output during the big C compiles — that's normal.
Re-runs are cached and take seconds.

### Windows: `aws-lc-rs` / `ring` build fails
You need LLVM and CMake on PATH: `choco install cmake llvm`, then open a **new**
terminal so PATH updates. Building inside **WSL2** (Ubuntu) is the smoother path
and is fully supported — see [`docs/JOIN-DEVNET.md`](JOIN-DEVNET.md) §2.

---

## Running a prebuilt binary

### macOS: "cannot be opened because the developer cannot be verified"
The release binaries are checksummed + SLSA-attested but not Apple-notarized.
Clear the quarantine flag, then run:
```bash
xattr -d com.apple.quarantine ./elara-node    # or right-click → Open, once
```

### Linux AppImage won't run
Make it executable first: `chmod +x elara-node-*.AppImage`. If it complains about
FUSE, either install it (`sudo apt install libfuse2`) or extract and run:
`./elara-node-*.AppImage --appimage-extract && ./squashfs-root/AppRun`.

### "Which file do I download?"
- **Linux desktop (Intel/AMD):** the `-linux-x86_64` archive, or the AppImage (double-click).
- **Linux on ARM / Raspberry Pi:** the `-linux-aarch64` archive.
- **Mac (Apple Silicon, M1–M4):** the `-macos-aarch64` archive.
- **Mac (Intel, pre-2020):** the `-macos-x86_64` archive.
- **Windows:** the `-windows-x86_64.zip`, or the installer.

Every archive also ships `elara-verify` (`elara-verify.exe` on Windows) — the
offline verifier — alongside the node, so no compile is needed for it either.

Verify your download before running it (checksum + provenance): see [`VERIFY.md`](../VERIFY.md).

---

## Joining a network

### My node runs but sits at `peers_connected: 0` forever
Almost always a **blocked port**, not a config bug. All sync runs over the seed's
**PQ port = its HTTP port + 100** (e.g. `:9474` → `:9574`); if only the HTTP port
is open, you connect, then silently never sync. Prove both ports *before* you
build with the guard-rail script — it refuses to let you build into a dead end:
```bash
scripts/init-join.sh <seed-host:httpport> <authority-hash> <network-id>
```
Then, after boot, get a plain-language synced/not verdict any time:
```bash
scripts/check-my-join.sh http://localhost:9473 http://<seed-host>:<httpport>
```
Full guided walkthrough (including WSL2 and Tailscale-overlay seeds):
[`docs/JOIN-DEVNET.md`](JOIN-DEVNET.md).

### On WSL2 / behind home NAT — do I need to port-forward?
No. A joining node is **outbound-only**: it dials the seed and pulls. You forward
nothing. Only the *operator running the seed* forwards ports. See JOIN-DEVNET §1.
