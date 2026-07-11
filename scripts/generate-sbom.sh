#!/usr/bin/env bash
#
# generate-sbom.sh — produce a standalone Software Bill of Materials for the
# Elara node, in both CycloneDX 1.6 and SPDX 2.3 JSON.
#
# WHY a standalone SBOM when release binaries are already built with
# `cargo auditable` (which embeds the dependency tree INSIDE the binary)?
# Because supply-chain scanners (Dependency-Track, Grype, Trivy, OSV-Scanner)
# and grant/enterprise intake processes ingest a *file*, not an embedded blob.
# This is the file form of the same dependency truth — the resolved closure of
# the `elara-runtime` package (which carries the `elara-node` + `elara-cli`
# binaries), read from Cargo.lock.
#
# The release workflow (.github/workflows/release.yml) runs these exact
# commands and attaches the output to every tagged release alongside
# SHA256SUMS, so the published SBOM is reproducible by anyone:
#     ./scripts/generate-sbom.sh
#     sha256sum elara-sbom.cdx.json elara-sbom.spdx.json   # compare to release
#
# Pinned tool version keeps the output deterministic across machines.
set -euo pipefail

SBOM_TOOL_VERSION="0.10.0"
PKG="elara-runtime"

# Resolve the output dir to an absolute path BEFORE we cd into the repo root,
# so a relative arg is relative to the caller's cwd (intuitive), not the repo.
OUT_DIR="${1:-.}"
mkdir -p "${OUT_DIR}"
OUT_DIR="$(cd "${OUT_DIR}" && pwd)"
CDX="${OUT_DIR}/elara-sbom.cdx.json"
SPDX="${OUT_DIR}/elara-sbom.spdx.json"

cd "$(dirname "$0")/.."

if ! command -v cargo-sbom >/dev/null 2>&1; then
  echo "cargo-sbom not found. Install the pinned version with:" >&2
  echo "    cargo install cargo-sbom --locked --version ${SBOM_TOOL_VERSION}" >&2
  exit 1
fi

echo "Generating SBOM for package '${PKG}' (cargo-sbom $(cargo-sbom --version | awk '{print $2}'))..."

cargo sbom --cargo-package "${PKG}" --output-format cyclone_dx_json_1_6 > "${CDX}"
cargo sbom --cargo-package "${PKG}" --output-format spdx_json_2_3       > "${SPDX}"

# Fail loudly if either file is not well-formed JSON — an SBOM that does not
# parse is worse than none (a scanner silently skips it).
if command -v jq >/dev/null 2>&1; then
  jq -e . "${CDX}"  >/dev/null || { echo "CycloneDX SBOM is not valid JSON" >&2; exit 2; }
  jq -e . "${SPDX}" >/dev/null || { echo "SPDX SBOM is not valid JSON" >&2; exit 2; }
  echo "  CycloneDX 1.6 -> ${CDX}  ($(jq '.components | length' "${CDX}") components)"
  echo "  SPDX 2.3      -> ${SPDX} ($(jq '.packages | length' "${SPDX}") packages)"
else
  echo "  CycloneDX 1.6 -> ${CDX}"
  echo "  SPDX 2.3      -> ${SPDX}"
  echo "  (install jq to validate JSON + count components)"
fi
