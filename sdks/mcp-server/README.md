# `@elara/mcp-server`

MCP (Model Context Protocol) server giving AI agents cryptographic identity on
the Elara mesh. One JSON config in your AI client and the agent can read
balances, fetch state proofs, and submit signed records to any Elara node (a
public testnet node, or your own).

## Tools

| Tool             | Mode  | What it does |
|------------------|-------|--------------|
| `elara_balance`  | read  | `GET /proof/account/{identity}` — proof-backed balance (available + staked + `bound_to_seal`) |
| `elara_prove`    | read  | `GET /proof/account/{identity}` — full Merkle proof against latest signed seal |
| `elara_record`   | write | `POST /records` — submit a record already signed by the agent's wallet |
| `elara_witness`  | both  | build mode returns to-sign hex; submit mode posts to `/witness` |
| `elara_sign`     | local | builds the canonical to-sign bytes for transfer / stake / unstake / burn / witness |

The split between `elara_sign` (build) and `elara_record` / `elara_witness`
(submit) keeps Dilithium3 private keys out of the MCP server process — the
agent's wallet (browser, hardware, or `elara-cli`) signs the bytes and hands
the signature back. This is the right default for "AI agent has cryptographic
identity": the tool runner handles canonicalization, the wallet handles keys.

## Install

```bash
cd sdks/mcp-server
npm install
npm run build
```

## Configure your AI client

Add this to your client's MCP config (e.g. `~/.claude/mcp.json` or the Claude
Desktop app's config):

```json
{
  "mcpServers": {
    "elara": {
      "command": "node",
      "args": ["/abs/path/to/sdks/mcp-server/dist/index.js"],
      "env": {
        "ELARA_NODE_URL": "http://127.0.0.1:9473",
        "ELARA_DEFAULT_IDENTITY": "<your-32-byte-hex-identity>"
      }
    }
  }
}
```

Or run it directly:

```bash
node dist/index.js \
  --node-url=http://127.0.0.1:9473 \
  --default-identity=<hex>
```

## Endpoint surface

The server is a thin HTTP wrapper around the node's REST API. The **read** tools
(`elara_balance`, `elara_prove`) hit the node's public surface (`/proof/account`)
and work against any reachable node. The **write** tools (`elara_record` →
`POST /records`, `elara_witness` → `/witness`) hit the **data plane**, which is
loopback-only (`127.0.0.1:9472`) by default — point `ELARA_NODE_URL` at the
data-plane port, or run the node in single-listener mode (`ELARA_DATA_PLANE_LISTEN=`).

There are no public testnet endpoints yet — run your own node and point the
server at it (`http://127.0.0.1:9473` by default). See the repository
quickstart for starting a local realm.

## Tests

```bash
npm test
```

Spins up an in-process HTTP stub that mirrors the public REST shape and
exercises all 5 tool handlers — no live node required.
