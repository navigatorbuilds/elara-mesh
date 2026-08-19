#!/usr/bin/env bash
# Build a Windows NSIS installer for elara-node.
#
# Builds the Windows NSIS installer. Runs from Linux too —
# Ubuntu's `nsis` package ships a fully working `makensis` cross-compiler,
# so this same script is what CI uses on the Windows runner AND what a
# developer can use locally without booting a Windows VM.
#
# Usage:
#   packaging/windows/build.sh [exe_path] [output_path] [version]
#
#     exe_path:    elara-node.exe path (default: target/x86_64-pc-windows-msvc/release/elara-node.exe)
#     output_path: output installer path (default: dist/Elara_Node_Setup-x86_64.exe)
#     version:     version string baked into the installer (default: 0.2.1)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
EXE_PATH="${1:-$REPO_ROOT/target/x86_64-pc-windows-msvc/release/elara-node.exe}"
OUT_PATH="${2:-$REPO_ROOT/dist/Elara_Node_Setup-x86_64.exe}"
VERSION="${3:-0.2.1}"

if [[ ! -f "$EXE_PATH" ]]; then
    echo "FAIL: $EXE_PATH not found" >&2
    echo "      Cross-build first: cargo build --release --features node-windows --target x86_64-pc-windows-msvc" >&2
    exit 1
fi

if ! command -v makensis >/dev/null 2>&1; then
    echo "FAIL: makensis not found" >&2
    echo "      Linux: apt install nsis  |  Windows CI: choco install nsis" >&2
    exit 1
fi

mkdir -p "$(dirname "$OUT_PATH")"

makensis \
    -DBIN_PATH="$EXE_PATH" \
    -DOUT_PATH="$OUT_PATH" \
    -DVERSION="$VERSION" \
    "$REPO_ROOT/packaging/windows/elara-node.nsi" >&2

echo ">> built $OUT_PATH"
ls -lh "$OUT_PATH" >&2
