# Elara Agent Register — GitHub Action

One YAML line in your CI proves an Elara agent identity exists on the
mesh and emits its account proof as job outputs.

## Why

The action is the on-ramp from "I have an Elara identity" to "every deploy
of my code carries a verifiable account proof against the network's latest
signed epoch seal."

## Usage

```yaml
- uses: navigatorbuilds/elara-mesh/sdks/github-action@main
  with:
    node-url: https://node.elara.dev
    identity: ${{ secrets.ELARA_IDENTITY }}
```

That's it. The action:
1. Probes the node's `/status` endpoint (fail-fast on a wrong/dead node).
2. Reads `/proof/account/{identity}` — the public, seal-bound account read.
   It carries both the balance (`available`/`staked`) and the proof, so one
   call yields `available`, `staked`, `total`, `exists`, `proof-root`, and
   `bound-to-seal`. Fails the workflow if the identity has no account on this
   node (flip `fail-if-missing: false` to allow). An unknown identity returns
   `exists: false`, not an HTTP error.

The agent's private key never enters CI — the action is read-only.
Sign-and-submit flows belong in `@elara/sdk` or `@elara/mcp-server`.

## Inputs

| name              | required | default | description                                                                                            |
|-------------------|----------|---------|--------------------------------------------------------------------------------------------------------|
| `node-url`        | yes      | —       | Public URL of an Elara node you run or have access to (no public testnet endpoints yet).              |
| `identity`        | yes      | —       | 64-hex-char SHA3-256 identity. Pass via `${{ secrets.ELARA_IDENTITY }}` so it's redacted in logs.       |
| `fail-if-missing` | no       | `true`  | Fail the workflow when the identity has no account on the node. Set `false` for "register-on-first-CI". |

## Outputs

| name             | description                                                                          |
|------------------|--------------------------------------------------------------------------------------|
| `available`      | Available beat base units (1 beat = 1\_000\_000\_000 units).                         |
| `staked`         | Staked beat base units (1 beat = 1\_000\_000\_000 units).                            |
| `total`          | Total beat base units (`available + staked`).                                        |
| `exists`         | `"true"` if the account exists on the node, otherwise `"false"`.                     |
| `proof-root`     | Account-Merkle root the proof was emitted against.                                   |
| `bound-to-seal`  | `"true"` if `proof-root` matches the latest signed epoch seal — verifiable finality. |

## Worked example

```yaml
name: deploy
on: [push]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: navigatorbuilds/elara-mesh/sdks/github-action@main
        id: elara
        with:
          node-url: https://node.elara.dev
          identity: ${{ secrets.ELARA_IDENTITY }}

      - name: Block deploy without verifiable finality
        if: steps.elara.outputs.bound-to-seal != 'true'
        run: |
          echo "::error::Account proof is not bound to the latest seal — refusing to deploy."
          exit 1

      - name: Show agent state
        run: |
          echo "available=${{ steps.elara.outputs.available }} base units"
          echo "staked=${{ steps.elara.outputs.staked }} base units"
          echo "proof-root=${{ steps.elara.outputs.proof-root }}"
```

## Implementation

- Node 20 (`runs.using: 'node20'`).
- Pure stdlib (`http` / `https` / `url` / `fs`) — **no `npm install` at
  action runtime**, so the action works in every workflow without
  bundling `node_modules`.
- The committed entrypoint is `dist/index.js`. There is no build step.
- 7 smoke tests against an in-process `http.Server` stub:
  ```bash
  cd sdks/github-action
  node test/smoke.test.js
  ```

## Related

- [`@elara/sdk`](../typescript/) — TypeScript SDK (read + submit).
- [`elara`](../python/) — Python SDK (read + submit, pure-stdlib).
- [`@elara/mcp-server`](../mcp-server/) — MCP server for AI agents.
- [`examples/verify/`](../../examples/verify/) — offline proof checker (CLI + sample bundle).
