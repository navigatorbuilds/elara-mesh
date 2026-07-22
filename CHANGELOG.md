# Changelog

All notable changes to elara-runtime.

## [0.2.2] — unreleased

### Security
- **Public-surface fingerprint gate** — node-local host state (`listen_addr`, `system_load`, `rss_mb`, `memory_pressure`, `disk_usage`, `peer_bandwidth`, `subscribed_zones`, `committees`, `zone_timing`, GC/auto-slash counters, continuity/reincarnation fields) and build identity (`git_sha`, `git_ref`, `git_dirty`, `build_ts_secs`) are now withheld from **non-loopback** callers across `/status`, `/version`, and `/metrics`. The build `git_sha` is the private-repo HEAD (absent from the public mirror); serving it — together with the host resource fingerprint — to anonymous callers leaked a private identifier and aided vulnerability targeting. On `/metrics` the `elara_build_info` gauge is reclassified to the loopback-only **Debug** tier: non-loopback scrapes are capped at P1 (`clamp_public_metric_tier`), which drops the whole family, while loopback operators keep it via `?tier=debug` (and via bare `/version` / `/status`). Chain-anchor discovery fields a follower needs to bootstrap (`genesis_authority`, `public_key_hex`, `network_id`, `current_epoch`, latest-seal anchor) stay public. Verified end-to-end from the external (non-loopback) view by an adversarial public-surface probe: public routes answer 200; gated routes stay 404 under 17 path-traversal/encoding/case variants; fingerprint fields null; `git_sha` gated on all three surfaces.

### Fixed
- **`current_epoch` reflects the live epoch tip** — `/status` and the admin surface now derive `current_epoch` from the canonical `active_zone_max_epoch` (the live tip) instead of a stale `state_core` snapshot, so a freshly-sealed epoch is visible immediately rather than lagging a snapshot cycle.
- **Seed inbound path pinned against DHCP drift** — the local seed binds a static address with an IP-drift guard, after a DHCP lease change silently darkened its inbound path for ~35 h.

## [0.2.1] — 2026-07-11

### Added
- **Cross-platform release binaries** — the release now ships prebuilt artifacts for macOS (`elara-node-macos-aarch64.tar.gz`), Windows (`elara-node-windows-x86_64.zip` plus an `Elara_Node_Setup-x86_64.exe` NSIS installer), and Linux aarch64, alongside the existing Linux x86_64 tarball and `Elara_Node-x86_64.AppImage`. The macOS and Windows binaries are built and attested but not yet runtime-tested by the maintainers; Linux x86_64 remains the release-gating target.
- **Supply-chain provenance for releases** — every artifact is covered by a `SHA256SUMS` manifest and a GitHub build attestation (verifiable with `gh attestation verify`, stored in GitHub's public transparency log independently of asset storage). Two standalone SBOMs are attached — `elara-sbom.cdx.json` (CycloneDX 1.6) and `elara-sbom.spdx.json` (SPDX 2.3), reproducible via `scripts/generate-sbom.sh` — and the binaries embed the same dependency tree via `cargo auditable` for runtime re-scanning.

### Changed
- **Gossip pull-jitter decorrelated** — both the record-pull and attestation-pull loops previously derived their jitter from a shared wall-clock value, so nodes acting in the same second drew identical offsets, preserving the very herd the jitter was meant to break up. Jitter is now derived from `sha3(identity ‖ domain ‖ pull_cycle)`: per-node, domain-separated between the two loops, and deterministic per pull cycle.

## [0.2.0] — 2026-07-06

### Added
- **Offline verifier (`elara-verify`) + in-browser verify demo** — a zero-network CLI verifies a record end-to-end (post-quantum signature, identity binding, epoch inclusion, seal, and the trustless Bitcoin/drand time bracket); a verify-only WASM widget runs the record-integrity legs in the browser. Honest tri-state — VERIFIED / PARTIAL / FAILED — never prints a green it can't prove.
- **Gap 7 state-snapshot autonomous repair** — `chain_divergence_monitor_loop` now repairs ≥50-epoch divergence without operator intervention. Pulls signed `StateDelta` from max-tip peer (HTTP `/snapshot/state-delta?since_epoch=<local_tip>`), verifies Dilithium3 + checksum + trust-gate against `{genesis_authority} ∪ trusted_snapshot_signers`, applies via `account_merkle::snapshot_scoped` + `apply_snapshot` in `spawn_blocking`. Five distinct counters: `repair_attempts_total`, `repair_failures_total`, `repair_verify_fails_total`, `repair_apply_fails_total`, `repair_success_total`.
- **Gap 7 post-apply SMT-root verify** — `apply_state_delta_for_repair` now cross-checks the computed post-apply SMT root against the producer's signed `delta.account_state_root`. Counter-only signal `elara_chain_divergence_repair_root_mismatch_total`; ledger mutation already committed when this fires (rolling back mid-repair is out of scope), so the visibility hit IS the fix — operators see a non-zero rate, cross-check `latest_sealed_account_smt_root` against the trusted seal, escalate to a manual seed-peer reset if the producer is on a different chain. Closes the deepest available integrity probe between repair-apply and the next sealed root arrival. Test coverage: counter bumps under bogus `account_state_root`, stays put on matching root.
- **`/alive` endpoint** — lightweight liveness probe, zero NodeState reads, ideal for load-balancer real-time checks (distinct from `/health` which caches for 30 s).
- **`elara_build_info` gauge** — operator-visible binary identity surface. Labels: `git_sha`, `git_ref`, `git_dirty`, `build_ts`. (In 0.2.0 this rendered on the public `/metrics` body; 0.2.2 reclassifies it loopback-only — see the 0.2.2 public-surface fingerprint gate.)
- **Light client protocol** — `network/node_profile.rs` (Light/FullZone/Archive), `/proof/account/{identity}` endpoint with Merkle proof, `network/account_merkle.rs`. Light nodes verify balances without downloading records.
- **Cross-zone async settlement** — debit-finality on local epoch inclusion, credit-application reactive on zone-B observation, XZoneAbort recovery path for sealed transfers under partition. Full lifecycle + threat model specified in the protocol spec §5 (cross-zone settlement).
- LICENSE-MIT + LICENSE-APACHE files at repo root (matches `Cargo.toml` dual-license declaration).
- CI: `cargo test --features node --lib` baseline now 5,700+ tests / 0 failures.

### Changed
- **Strategic repositioning (2026-06-09)** — the tradeable-coin ambition was dropped; the project is now an open-source post-quantum validation mesh. the internal protocol credit (formerly “TYOS”, now the **beat** — earned by validating, never bought or sold) is non-tradeable; no exchange listings, no token marketing. Staking stays in-code for sybil resistance.
- **Development fleet decommissioned to 3 machines** — the rented VPS testnet (Helsinki / Nuremberg / Hillsboro / NYC) was retired 2026-06-09; the fleet is now one desktop + two laptops. Any "6 testnet nodes" figure below describes that retired fleet, not current infrastructure.
- **Node relicensed AGPL-3.0-only** — the node/network crate is AGPL-3.0-only; the SDKs and extracted commons crates stay MIT/Apache.
- **Account state → 256-bit identity-bound sparse Merkle tree** — replaced the 64-bit-keyed, identity-free account leaf (collision-prone at scale) with a 256-bit identity-bound compressed SMT plus non-membership (exclusion) proofs.
- **MIN_ADAPTIVE_EPOCH_SECS lowered** 15 s → 5 s (`27b3b5b`) — pushing in-zone finality toward physical floor.
- **README baseline figures re-baselined** — 1,180 → 4,000+ tests, 53 → 76+ HTTP endpoints, plus a scale *design target* (1M zones / 10T records/day / 10K+ nodes — designed-for, not tested-at). (The contemporaneous 6-node testnet figure refers to the VPS fleet retired 2026-06-09.)
- **Storage backend documented correctly** — CONTRIBUTING.md previously said SQLite; actual is RocksDB + tiled hot/cold storage.

### Security
- `feedback_no_usize_max_vec_query` scale rule enforced — runtime queries are streaming-bounded, never O(all_records). Eliminates OOM risk on production-scale ledgers.
- Repair-path trust-gate uses the same `{genesis_authority} ∪ trusted_snapshot_signers` union as `epoch_indexed_snapshot_bootstrap` — no widened attack surface for autonomous reconciliation.

### Fixed
- Deploy `.gitignore` scrub — removed 134K lines of runtime log noise from git tracking. `git status --porcelain` returns clean on a fresh worktree; subsequent builds will emit `git_dirty="0"` in the build_info gauge.

## [0.1.2] — 2026-03-13

### Security
- Admin bearer token authentication on all 20+ admin endpoints
- Full metadata field scanning (all string values, not just named fields)
- Extended URL detection (14 URI schemes + domain patterns + IP addresses)
- Browser-node governance keys fixed (`gov_*` → `governance_*`)

### Changed
- Burn operation now redirects to Conservation Pool (was destroying supply)
- Burn restricted to genesis authority only
- Governance quorum: 10% → 25%
- Demurrage (now "idle decay"): `BURN_FRACTION` renamed to `POOL_FRACTION`

### Added
- GenesisState persistence: `rebuild_from_records()` on startup
- Genesis verification script
- Load test script
- CI/CD: GitHub Actions (unit, integration, WASM, clippy, supply check)
- Terms of Service and Privacy Policy pages
- Show HN draft
- 14 new unit tests, 7 new integration tests

### Fixed
- Attestation signature errors resolved (old binary issue)
- Clippy warnings cleaned
- Data files removed from git tracking

### Docs
- CONTENT-POSTURE.md: layered content-safety documentation
- API reference: admin auth + ban/blocklist endpoints
- README: test count, admin token config

### Testing
- 1,143 unit tests + 20 integration tests (0 failures)
- Cross-node conservation E2E test
- Double-spend partition recovery E2E test
- Governance lifecycle E2E test
- Staking lifecycle E2E test (with cooldown enforcement)
- API validation test (6 checks)
- Admin auth enforcement E2E test
- Dilithium3 verified on all 3 VPS production kernels

---

## [0.1.1] — 2026-03-12

- Phase 1-2 surface layer: staking UI, governance UI, onboarding
- API docs extended (+1001 lines, 73+ routes)
- PWA network-first caching strategy
- Deployed to all 3 VPS nodes
- 1,127 tests pass, 0 failures

## [0.1.0] — 2026-03-11

- Initial testnet deployment
- 5 Sybil defense phases: WS trust pipeline, PoW, identity registration, origin tracking, key encryption
- Dilithium3 fix: PQClean → OQS fallback (one-character fix)
- 6-layer content safety system
- 1,114 tests pass, 0 failures
