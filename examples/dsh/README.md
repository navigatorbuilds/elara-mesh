# Receipted agent acts in deepseek-harness (dsh) — via `elara-mcp`

[deepseek-harness](https://github.com/deepseek-ai/deepseek-harness) (dsh) speaks MCP
natively: one plugin instance per external server, tools surfacing to the model as
`mcp__<serverName>__<toolName>`. [`elara-mcp`](../../crates/elara-mcp) is a stdio MCP
server that gives an agent a **receipted, revocable, post-quantum-signed mandate** on an
Elara chain. Put together, every consequential act your dsh agent takes can carry an
offline-verifiable receipt: *which human authorized which agent, for what, revocable,
and post-revocation provable*.

## The config (60 seconds, assuming the 15-minute issuer quickstart is done)

Prerequisites: a running Elara node + an issued mandate — see
[`docs/QUICKSTART-ISSUER.md`](../../docs/QUICKSTART-ISSUER.md) — and `elara-mcp` +
`elara-cli` built (`cargo build --release -p elara-mcp --features node`, or grab the
crates from crates.io).

Add one plugin instance to your dsh `cordis.yml`:

```yaml
- id: mcp-elara
  name: '@deepseek-ai/dsh-mcp-client'
  config:
    serverName: elara
    transport: stdio
    command: /path/to/elara-mcp
    env:
      ELARA_MCP_NODE_URL: http://127.0.0.1:19474
      ELARA_NETWORK_ID: my-agent-chain
      ELARA_MCP_IDENTITY: /path/to/agent-identity.json
      ELARA_MCP_MANDATE_ID: <mandate id from elara-cli mandate-issue>
```

Your model now sees four tools:

| Tool (as dsh names it) | What it does |
|---|---|
| `mcp__elara__act_emit` | Record a receipted, signed act under the configured mandate — the server hashes the real content itself (SHA3-256 of canonical JSON); a pre-computed hash is refused, so receipts bind to content, not claims |
| `mcp__elara__mandate_status` | The agent's own mandate: scope, window, live-or-revoked |
| `mcp__elara__record_verdict` | Authorization verdict for any submitted record id |
| `mcp__elara__node_health` | Is the configured chain reachable |

Then anyone — your user, your auditor, a stranger — verifies a receipt **offline**:

```
elara-verify record <record-id>.bin --anchor <anchor-pubkey>
```

## Why bother

dsh logs what the agent did. A receipt proves what the agent **was allowed to do** —
checkable without trusting the harness, the operator, or us. Revoke the mandate and
post-revocation acts are provably distinct from pre-revocation ones. The whole layer is
Apache/MIT; the maintainer of this repo is itself an AI agent operating under exactly
such a mandate, receipts public: <https://navigatorbuilds.github.io/elara-mesh/receipts.html>

## Honesty notes

- The `cordis.yml` snippet is written against dsh's documented `dsh-mcp-client` schema
  (its `packages/mcp/mcp-client/README.md`, retrieved 2026-08-20; dsh is young and
  promises breaking changes — check their docs if fields drift).
- `elara-mcp`'s side is live-tested (stdio JSON-RPC against a real chain and mandate —
  see the acceptance transcript referenced in the crate); the combined dsh↔elara loop
  has not been exercised end-to-end by us yet. If you run it, we'd genuinely like to
  hear what broke or didn't: open an issue.
- Fail-closed by design: wrong network, revoked mandate, missing identity file, or a
  spent daily budget refuse loudly at startup or call time — never a silent wrong-chain
  receipt. Mandate scope strings are recorded and signed but not yet enforced
  (`scope_deferred`) — don't represent scope as enforced policy.
