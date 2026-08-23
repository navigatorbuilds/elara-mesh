# Receipted agent acts in AWS Strands — via `elara-mcp`

[Strands Agents](https://github.com/strands-agents/sdk-python) is AWS's open-source
agent SDK. It speaks MCP natively: an `MCPClient` spawns an external MCP server and
surfaces its tools straight into an `Agent`'s toolset.
[`elara-mcp`](../../crates/elara-mcp) is a stdio MCP server that gives an agent a
**receipted, revocable, post-quantum-signed mandate** on an Elara chain. Put together,
every consequential act your Strands agent takes can carry an offline-verifiable
receipt: *which human authorized which agent, for what, revocable, and post-revocation
provable*.

## The config (60 seconds, assuming the 15-minute issuer quickstart is done)

Prerequisites: a running Elara node + an issued mandate — see
[`docs/QUICKSTART-ISSUER.md`](../../docs/QUICKSTART-ISSUER.md) — plus `elara-mcp` built
from this repo (`cargo build --release -p elara-mcp --features node` — it is not on
crates.io) and `pip install strands-agents`.

Point a Strands `MCPClient` at the `elara-mcp` binary over stdio:

```python
from mcp import StdioServerParameters, stdio_client
from strands import Agent
from strands.tools.mcp import MCPClient

elara = MCPClient(lambda: stdio_client(StdioServerParameters(
    command="/path/to/elara-mcp",
    env={
        "ELARA_MCP_NODE_URL": "http://127.0.0.1:9474",
        "ELARA_NETWORK_ID":   "my-agent-chain",
        "ELARA_MCP_IDENTITY": "/path/to/agent-identity.json",
        "ELARA_MCP_MANDATE_ID": "<mandate id from elara-cli mandate-issue>",
    },
)))

with elara:                                  # the context manager owns the subprocess
    agent = Agent(tools=elara.list_tools_sync())
    agent("Record that you finished the migration, then show me the receipt.")
```

Your model now sees four tools (verified live against `strands-agents` 1.53.0 with the
`mcp` SDK 1.29.0 — Strands surfaces each MCP tool under its bare server name):

| Tool | What it does |
|---|---|
| `mandate_act_emit` | Record a receipted, signed act under the configured mandate — the server hashes the real content itself (SHA3-256 of canonical JSON); a pre-computed hash is refused, so receipts bind to content, not claims |
| `mandate_act_status` | Authorization verdict for any submitted record id (flag, lineage, completeness) |
| `mandate_my_mandate` | The agent's own mandate: scope, window, live-or-revoked |
| `mandate_bundle_verify` | Verify a committed mandate bundle — touches no network at all |

(Node reachability isn't a tool: an unreachable or wrong-network chain surfaces as a
loud startup refusal or per-call error — see the fail-closed note below.)

Then anyone — your user, your auditor, a stranger — verifies a receipt **offline**:

```
elara-verify record <record-id>.bin --anchor <anchor-pubkey>
```

## Why bother

Strands logs what the agent did. A receipt proves what the agent **was allowed to do** —
checkable without trusting the SDK, the operator, or us. Revoke the mandate and
post-revocation acts are provably distinct from pre-revocation ones. The whole layer is
Apache/MIT; the maintainer of this repo is itself an AI agent operating under exactly
such a mandate, receipts public: <https://navigatorbuilds.github.io/elara-mesh/receipts.html>

## Honesty notes

- The snippet is written against Strands' documented MCP surface
  (`strands.tools.mcp.MCPClient` + `list_tools_sync`, SDK 1.53.0, retrieved 2026-08-23;
  Strands is young — check their docs if the API drifts).
- The combined Strands↔elara loop IS exercised at the registration surface: on
  2026-08-23 [`strands_interop_test.py`](strands_interop_test.py) drove Strands' own
  `MCPClient` (its real stdio spawn + MCP `initialize`/`tools/list`/`call_tool` path,
  via the `mcp` 1.29.0 SDK) against the release `elara-mcp` binary on a live chain
  (`testnet`): **2/2 — all four tools registered under the bare names above, and
  `mandate_my_mandate` returned a live mandate (revoked=false) through Strands' own
  `call_tool_sync` dispatch.** Reproduce it with that script.
- What is NOT yet exercised: (a) a full model-driven Strands `Agent(...)` composition —
  that needs a live model provider (Bedrock or another) and is the layer *above* the
  tool surface tested here; (b) the `mandate_act_emit` write leg, which the script runs
  only under `EMIT=1` — left off in the recorded pass so it does not spend the shared
  maintainer build-agent's daily emission budget while that identity is in active use.
  Both are one flag / one model-key away; if you run either, we'd genuinely like to hear
  what broke or didn't — open an issue.
- Fail-closed by design: wrong network, revoked mandate, missing identity file, or a
  spent daily budget refuse loudly at startup or call time — never a silent wrong-chain
  receipt. Mandate scope strings are recorded and signed but not yet enforced
  (`scope_deferred`) — don't represent scope as enforced policy.
