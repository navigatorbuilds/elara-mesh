# ── Build stage ────────────────────────────────────────────────────────────────
# Pin to the toolchain the project is built and tested with. Do NOT trail it:
# transitive deps raise their MSRV over time (clap_lex 1.1.0 now requires Rust
# 1.85's edition2024), so an older pin silently breaks `docker build` on a fresh
# clone while every local build passes; CI guards the pinned toolchain.
FROM rust:1.96-bookworm AS builder

# Native build deps, mirroring the README "Requirements" apt line: bindgen
# (rocksdb/zstd sys crates) needs libclang, liboqs (oqs-sys) builds via cmake.
# The rust image ships neither, so a fresh-clone `docker compose up --build`
# dies in the builder stage without both (libclang for bindgen, cmake for oqs).
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang libclang-dev cmake pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

# Build the node binary with all network features
RUN cargo build --release --features node --bin elara-node --bin elara-cli

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 curl jq \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/elara-node /usr/local/bin/elara-node
COPY --from=builder /src/target/release/elara-cli  /usr/local/bin/elara-cli
COPY scripts/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

# Data directory
RUN mkdir -p /data
VOLUME /data

ENV ELARA_LISTEN=0.0.0.0:9473
ENV RUST_LOG=elara_node=info,elara_runtime=info

EXPOSE 9473

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["--data-dir", "/data"]
