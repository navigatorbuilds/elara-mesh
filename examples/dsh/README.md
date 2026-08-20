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

Your model now sees four tools (verified live against `dsh-mcp-client` 0.0.1-rc.1 —
these are the exact registered names):

| Tool (as dsh names it) | What it does |
|---|---|
| `mcp__elara__mandate_act_emit` | Record a receipted, signed act under the configured mandate — the server hashes the real content itself (SHA3-256 of canonical JSON); a pre-computed hash is refused, so receipts bind to content, not claims |
| `mcp__elara__mandate_act_status` | Authorization verdict for any submitted record id (flag, lineage, completeness) |
| `mcp__elara__mandate_my_mandate` | The agent's own mandate: scope, window, live-or-revoked |
| `mcp__elara__mandate_bundle_verify` | Verify a committed mandate bundle — touches no network at all |

(Node reachability isn't a tool: an unreachable or wrong-network chain surfaces as a
loud startup refusal or per-call error — see the fail-closed note below.)

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
- The combined dsh↔elara loop IS exercised end-to-end: on 2026-08-20 we ran
  `@deepseek-ai/dsh-mcp-client` 0.0.1-rc.1 (dsh's real bridge plugin — stdio spawn, env
  scrubbing, discovery, public naming, dispatch) against the release `elara-mcp` binary
  on a live chain: 4/4 — all four tools registered under the names above, and a real
  act was emitted *through dsh's own dispatch path* (record
  `01a0201b-23cc-7100-99d4-590da36f9be5`, args hashed server-side, status
  `authorized`/`valid`). Reproduce it with [`interop-test.mjs`](interop-test.mjs).
  What is NOT yet exercised: a full model-driven dsh composition (that needs a DeepSeek
  runtime; the plugin↔server surface below the model is the part tested here). If you
  run the full harness, we'd genuinely like to hear what broke or didn't: open an issue.
- Fail-closed by design: wrong network, revoked mandate, missing identity file, or a
  spent daily budget refuse loudly at startup or call time — never a silent wrong-chain
  receipt. Mandate scope strings are recorded and signed but not yet enforced
  (`scope_deferred`) — don't represent scope as enforced policy.
