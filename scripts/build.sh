#!/usr/bin/env bash
# build.sh — the "it just works" source build for Elara.
#
# You do NOT need this script to build — `cargo build --release --features node`
# is the whole story. This wrapper exists so a FIRST build doesn't fail on one of
# the handful of environment footguns that make people give up: it checks your
# toolchain BEFORE the 20-minute compile, applies the known compiler workaround
# automatically, and caps parallelism so a low-RAM box doesn't get OOM-killed
# halfway. Every failure it can foresee, it fixes or explains — it never leaves
# you staring at a cryptic C++ error.
#
# Prefer not to build at all? After the first tagged release you can just
# download a prebuilt binary — no Rust, no compiler. See the README top.
#
# Usage:  scripts/build.sh              # build elara-node + elara-cli (release)
#         scripts/build.sh --verify     # also build the offline verifier (elara-verify)
#         scripts/build.sh --check      # check the environment and exit (no build)
set -euo pipefail
cd "$(dirname "$0")/.."

say()  { printf '\033[36m▸ %s\033[0m\n' "$*"; }
ok()   { printf '\033[32m  ✓ %s\033[0m\n' "$*"; }
warn() { printf '\033[33m  ⚠ %s\033[0m\n' "$*"; }
die()  { printf '\033[31m  ✗ %s\033[0m\n' "$*" >&2; exit 1; }

WANT_VERIFY=0; CHECK_ONLY=0
for a in "$@"; do
  case "$a" in
    --verify) WANT_VERIFY=1 ;;
    --check)  CHECK_ONLY=1 ;;
    -h|--help) grep -E '^# ' "$0" | sed 's/^# //'; exit 0 ;;
    *) die "unknown arg: $a (try --verify, --check, --help)" ;;
  esac
done

say "1/4  Rust toolchain"
if ! command -v cargo >/dev/null 2>&1; then
  die "Rust is not installed. Install it (2 minutes), then re-run this script:
       curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
       source \$HOME/.cargo/env"
fi
RUST_V="$(rustc --version | awk '{print $2}')"
# need >= 1.87; a stale distro rustc (apt) is the classic 'cryptic proc-macro error' cause
RUST_MAJ="$(printf '%s' "$RUST_V" | cut -d. -f1)"; RUST_MIN="$(printf '%s' "$RUST_V" | cut -d. -f2)"
if [ "$RUST_MAJ" -eq 1 ] && [ "$RUST_MIN" -lt 87 ]; then
  die "Rust $RUST_V is too old (need >= 1.87). If you installed rust via apt/dnf, switch to rustup's:
       rustup default stable      # then re-run this script
     A fresh rustup gives >= 1.93."
fi
ok "cargo $(cargo --version | awk '{print $2}'), rustc $RUST_V"

say "2/4  C/C++ toolchain (rocksdb + liboqs compile native code)"
MISSING=""
command -v cmake >/dev/null 2>&1 || MISSING="$MISSING cmake"
{ command -v clang >/dev/null 2>&1 || command -v cc >/dev/null 2>&1 || command -v gcc >/dev/null 2>&1; } || MISSING="$MISSING clang"
if [ -n "$MISSING" ]; then
  OS="$(uname -s)"
  case "$OS" in
    Linux)  HINT="sudo apt install -y build-essential pkg-config libssl-dev cmake clang libclang-dev git   # Debian/Ubuntu" ;;
    Darwin) HINT="xcode-select --install && brew install cmake" ;;
    *)      HINT="install: cmake + a C/C++ compiler (clang or gcc) + git" ;;
  esac
  die "missing build tools:$MISSING
     $HINT"
fi
ok "cmake $(cmake --version | head -1 | awk '{print $3}'), C compiler present"

say "3/4  Compiler workaround + memory budget"
# gcc 13+ tightened <cstdint> include hygiene; RocksDB 8.x fails to compile with
# it ("'uint64_t' has not been declared") unless cstdint is force-included. This
# is the single most common first-build failure on fresh 2024+ distros. Fix it
# transparently so nobody ever sees that error.
if command -v gcc >/dev/null 2>&1; then
  GCC_MAJ="$(gcc -dumpversion 2>/dev/null | cut -d. -f1 || echo 0)"
  if [ "${GCC_MAJ:-0}" -ge 13 ] 2>/dev/null; then
    export CXXFLAGS="${CXXFLAGS:-} -include cstdint"
    ok "gcc $GCC_MAJ detected — applied CXXFLAGS='-include cstdint' (avoids the RocksDB build error)"
  fi
fi
# Cap parallelism by RAM: each C++/rustc job can spike ~1.5-2 GB; the RocksDB
# compile is the peak. A 4 GB box with the default -j<ncpu> gets OOM-killed.
RAM_KB="$( (grep -m1 MemTotal /proc/meminfo 2>/dev/null || echo 'x 8000000') | awk '{print $2}')"
RAM_GB=$(( RAM_KB / 1024 / 1024 ))
if   [ "$RAM_GB" -le 3 ]; then JOBS=1
elif [ "$RAM_GB" -le 6 ]; then JOBS=2
else JOBS=""; fi
if [ -n "$JOBS" ]; then
  export CARGO_BUILD_JOBS="$JOBS"
  warn "only ${RAM_GB} GB RAM — capping to $JOBS build job(s) so the RocksDB compile doesn't get OOM-killed (slower, but it finishes)."
  [ "$RAM_GB" -le 3 ] && warn "on <=3 GB, also make sure you have some swap: builds link a ~50 MB binary."
else
  ok "${RAM_GB} GB RAM — full parallelism"
fi

if [ "$CHECK_ONLY" -eq 1 ]; then say "environment OK — ready to build (re-run without --check)"; exit 0; fi

say "4/4  Building (first build ~10-30 min depending on cores; it is NOT hung — RocksDB + liboqs are large C libraries)"
cargo build --release --features node --bin elara-node --bin elara-cli
ok "node built: ./target/release/elara-node"
if [ "$WANT_VERIFY" -eq 1 ]; then
  say "building the offline verifier (elara-verify)"
  cargo build --release --features verify-cli --bin elara-verify
  ok "verifier built: ./target/release/elara-verify"
fi
printf '\n\033[32m✓ Done.\033[0m Next: create an identity and join — see docs/JOIN-DEVNET.md,\n  or run scripts/init-join.sh <seed> <authority-hash> <network-id> for the guided path.\n'
