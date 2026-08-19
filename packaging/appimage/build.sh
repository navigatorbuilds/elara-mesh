#!/usr/bin/env bash
# Build a Linux AppImage from a release elara-node binary.
#
# A two-click installer for Linux.
# The AppImage is single-file, single-click, no install needed — `chmod +x`
# and double-click. The bundled AppRun defaults --data-dir to
# ~/.local/share/elara-node so the user does not pick a path.
#
# Usage:
#   packaging/appimage/build.sh [binary_path] [output_path]
#
#     binary_path:  path to release elara-node binary
#                   (default target/release/elara-node)
#     output_path:  output AppImage path
#                   (default dist/Elara_Node-x86_64.AppImage)
#
# Requires: convert (ImageMagick) for icon generation.
# appimagetool is downloaded to /tmp/elara-appimagetool if not on PATH.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BINARY="${1:-$REPO_ROOT/target/release/elara-node}"
OUTPUT="${2:-$REPO_ROOT/dist/Elara_Node-x86_64.AppImage}"

if [[ ! -x "$BINARY" ]]; then
    echo "FAIL: $BINARY not found or not executable" >&2
    echo "      Run: cargo build --release --features node" >&2
    exit 1
fi

if ! command -v convert >/dev/null 2>&1; then
    echo "FAIL: ImageMagick 'convert' required for icon generation" >&2
    echo "      apt install imagemagick" >&2
    exit 1
fi

# Download appimagetool if missing. The official AppImage doesn't bundle into
# the repo (multi-MB binary).
APPIMAGETOOL="$(command -v appimagetool || true)"
if [[ -z "$APPIMAGETOOL" ]]; then
    APPIMAGETOOL=/tmp/elara-appimagetool
    if [[ ! -x "$APPIMAGETOOL" ]]; then
        echo ">> downloading appimagetool..." >&2
        curl -sSL -o "$APPIMAGETOOL" \
            https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-x86_64.AppImage
        chmod +x "$APPIMAGETOOL"
    fi
fi

# Assemble the AppDir.
APPDIR=$(mktemp -d -t elara-appdir.XXXXXX)
trap 'rm -rf "$APPDIR"' EXIT
mkdir -p "$APPDIR/usr/bin" "$APPDIR/usr/share/applications" \
         "$APPDIR/usr/share/icons/hicolor/256x256/apps"

install -m755 "$BINARY"                              "$APPDIR/usr/bin/elara-node"
install -m755 "$REPO_ROOT/packaging/appimage/AppRun" "$APPDIR/AppRun"
install -m644 "$REPO_ROOT/packaging/appimage/elara-node.desktop" \
              "$APPDIR/elara-node.desktop"
install -m644 "$REPO_ROOT/packaging/appimage/elara-node.desktop" \
              "$APPDIR/usr/share/applications/elara-node.desktop"

# Icon — placeholder lattice rendered into a solid teal square. Real logo
# slots in by replacing packaging/appimage/icon.png with a 256x256 PNG.
if [[ -f "$REPO_ROOT/packaging/appimage/icon.png" ]]; then
    cp "$REPO_ROOT/packaging/appimage/icon.png" "$APPDIR/elara-node.png"
else
    convert -size 256x256 xc:'#0d4d4d' \
        -fill '#7fd6c8' -draw 'circle 128,128 128,40' \
        -fill '#0d4d4d' -draw 'circle 128,128 128,80' \
        -fill '#7fd6c8' -pointsize 64 -gravity center \
        -annotate +0+0 'E' \
        "$APPDIR/elara-node.png"
fi
cp "$APPDIR/elara-node.png" "$APPDIR/.DirIcon"
cp "$APPDIR/elara-node.png" "$APPDIR/usr/share/icons/hicolor/256x256/apps/elara-node.png"

mkdir -p "$(dirname "$OUTPUT")"

# ARCH env var required by appimagetool when invoked outside of a packaging
# context that auto-detects it (e.g. GitHub Actions runner).
ARCH=x86_64 "$APPIMAGETOOL" --no-appstream "$APPDIR" "$OUTPUT" >&2

echo ">> built $OUTPUT"
ls -lh "$OUTPUT" >&2
