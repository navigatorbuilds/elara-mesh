# Verifying Elara Release Artifacts

Every binary in an Elara GitHub Release carries two independent proofs you can
check before running anything (releases v0.2.0 and v0.2.1 are live on the
Releases page with `SHA256SUMS` + SLSA attestations; building from source
remains an option if you prefer). Neither proof requires trusting us — only the
math and publicly auditable infrastructure.

---

## What each proof covers

| Proof | Proves | Requires |
|---|---|---|
| `SHA256SUMS` checksum | Your download is bit-identical to what was published | `sha256sum` (pre-installed on Linux/macOS) |
| SLSA build attestation | The binary was compiled from this exact tagged commit by GitHub Actions | `gh` CLI |

They are complementary: the checksum protects against CDN corruption or
download errors; the attestation protects against a compromised release page
(an attacker swapping a binary without changing the source commit).

---

## Step 1 — SHA256 checksum

Download `SHA256SUMS` alongside your artifact, then:

```bash
sha256sum -c SHA256SUMS
```

Every line should print `OK`. If any line prints `FAILED`, discard the
download — the file does not match the digest that was published.

On macOS the tool is `shasum -a 256 -c SHA256SUMS` (same output format).

On Windows (PowerShell):
```powershell
Get-FileHash elara-node-windows-x86_64.zip -Algorithm SHA256
# compare the output manually against the line in SHA256SUMS
```

---

## Step 2 — SLSA build attestation

Install the [GitHub CLI](https://cli.github.com/) if you don't have it, then:

```bash
# Verify any individual artifact (replace the filename as needed):
gh attestation verify elara-node-linux-x86_64.tar.gz \
  --repo navigatorbuilds/elara-mesh

# Verify the SHA256SUMS manifest itself:
gh attestation verify SHA256SUMS \
  --repo navigatorbuilds/elara-mesh
```

Exit code 0 and output like `✓ Attestation verified` means:

- The file's SHA256 digest matches a provenance record in GitHub's public
  Sigstore/Fulcio transparency log.
- That record was signed by a short-lived OIDC certificate issued to the
  `navigatorbuilds/elara-mesh` repository's Actions workflow at the time the
  build ran.
- The certificate is traceable to the exact commit and workflow run.

**What this does NOT prove:** that the source code itself is trustworthy, or
that the GitHub infrastructure is uncompromised. For the current threat model
(verifying you downloaded an official release, not a tampered binary) it is
sufficient. The source code is auditable — you can read it and build your own
binary with `cargo build --release --features node`. (Bit-identical
reproducible builds are not yet a CI-verified property; your locally-built
binary will differ byte-wise from the release artifact even on the same
commit. Trust for the release artifact comes from the SLSA provenance
attestation above, not from hash-comparing your own build.)

---

## Note on signing keys and post-quantum honesty

These release binaries are not signed with a long-lived maintainer key
(GPG/minisign/cosign). The reason is architectural: Elara uses post-quantum
signatures (Dilithium3 / ML-DSA-65 + SPHINCS+ / SLH-DSA) for all on-chain
record authentication. Signing release artifacts with Ed25519 (the classical
choice for minisign/cosign) would be technically dishonest for a project whose
explicit purpose is post-quantum verifiability.

The SLSA build attestation above is the verifiable trust anchor instead. It
is keyless (no long-lived classical key to lose or rotate), the binding to
source is enforced by GitHub's OIDC certificate infrastructure rather than a
secret key, and the record is immutable in a public transparency log. This is
a better security posture than a long-lived Ed25519 key for the current scale
and threat model.

**Roadmap:** a native release-signing path using Elara's own SPHINCS+
verifier — signing the `SHA256SUMS` manifest with the same PQ primitives used
on-chain and verifying it with `elara-verify` — is planned. This document will
be updated when that ships.

---

## Note on unsigned installers (Windows SmartScreen / macOS Gatekeeper)

The Windows installer (`Elara_Node_Setup-x86_64.exe`) and macOS binaries are
not signed with commercial OS vendor certificates:

- **Windows Authenticode** requires a certificate from a paid CA (~$400/yr minimum).
- **Apple Developer notarization** requires an Apple Developer account ($99/yr).

These are incompatible with the project's free, open-source, no-spend model.

**Windows:** SmartScreen may display "Windows protected your PC" on first run.
This warning means "unsigned publisher", not "malware".

To run:
1. Click "More info" → "Run anyway".
2. Or: right-click the .exe → Properties → Unblock → OK → then run.
3. Preferred: verify the build attestation first (Step 2 above), which is a
   stronger assurance than Authenticode (it proves source commit, not just
   that someone paid a CA).

**macOS:** Gatekeeper may say the app "cannot be opened because the developer
cannot be verified". To run:

1. System Settings → Privacy & Security → scroll down → click "Open Anyway".
2. Or, from Terminal (removes the quarantine attribute):
   ```bash
   xattr -d com.apple.quarantine elara-node-macos-aarch64.tar.gz
   tar xzf elara-node-macos-aarch64.tar.gz
   ./elara-node --help
   ```

The build attestation proves the binary was compiled in a clean GitHub-hosted
environment from the exact tagged source commit. That is a stronger technical
guarantee than a code-signing certificate, which only proves a key was used —
not what built the binary or from which source.

---

## Building from source (strongest assurance)

If you want zero trust in the binary distribution:

```bash
git clone https://github.com/navigatorbuilds/elara-mesh.git
cd elara-mesh
git checkout v<version>
git verify-tag v<version>  # optional: verify the tag signature if present
cargo build --release --features node --bin elara-node --bin elara-cli
# binary is at target/release/elara-node
```

The build requires Rust stable, `cmake`, and `clang`. Full prerequisites:

```bash
# Linux (Debian/Ubuntu)
sudo apt install -y build-essential cmake clang libclang-dev pkg-config libssl-dev

# macOS
brew install cmake

# Windows
choco install cmake llvm
```
