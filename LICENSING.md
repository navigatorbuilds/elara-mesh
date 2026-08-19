# Licensing

Elara Protocol uses a split license model: **strong copyleft on the node, permissive on the client SDKs.**

## The node and network code — AGPL-3.0

The Elara node, network daemon, consensus engine, and protocol implementation
— everything in the `elara-runtime` Rust crate (the `elara-node` binary and the
`src/` tree) — are licensed under the **GNU Affero General Public License v3.0**
([LICENSE](LICENSE)).

The AGPL is deliberate. Its §13 ("Remote Network Interaction") means anyone who
runs a **modified** Elara node as a network service must make their source
changes available to that service's users. This is the Grafana / MinIO /
Mastodon pattern: it keeps the network's substrate open and prevents a closed,
proprietary fork from enclosing the protocol while keeping its improvements
private. Running the **unmodified** node imposes no source-publication
obligation — only modifications that are served over a network do.

## The client SDKs — MIT OR Apache-2.0

The client SDKs under [`sdks/`](sdks/) — Python, TypeScript, the GitHub Action,
and the MCP server — are licensed under **MIT OR Apache-2.0** at your option
([LICENSE-MIT](LICENSE-MIT), [LICENSE-APACHE](LICENSE-APACHE)). Each SDK package
declares this in its own manifest.

These talk to a node over the network protocol; they are not derivative works
of the AGPL node. They are permissively licensed on purpose: frictionless
integration grows the network the node operates. Embed them in any application,
open or closed, without copyleft obligations.

## Crates extracted from this tree — MIT OR Apache-2.0

Standalone Rust crates extracted from this codebase (post-quantum transport,
light-client SDK, sparse-Merkle tree, zone auto-scaler, active-inference engine)
carry **MIT OR Apache-2.0** at extraction time, declared in each crate's own
`Cargo.toml`. Until a component is extracted into its own crate it is part of
the AGPL-licensed `elara-runtime` crate and is covered by the AGPL.

## Summary

| Component | License |
|-----------|---------|
| Node / network daemon / protocol (`elara-runtime` crate, `elara-node`) | AGPL-3.0-only |
| Client SDKs (`sdks/`) | MIT OR Apache-2.0 |
| Extracted standalone crates | MIT OR Apache-2.0 |

## Contributions

Contributions are accepted under the license of the component they modify
(inbound = outbound): changes to the AGPL node are contributed under AGPL-3.0;
changes to a permissively-licensed SDK or crate are contributed under
MIT OR Apache-2.0. No separate contributor license agreement is required.
