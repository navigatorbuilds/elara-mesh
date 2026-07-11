# `@elara/sdk`

TypeScript SDK for the Elara mesh network. Wraps the public REST API in a
small, strictly-typed client so apps can read balances, fetch state proofs,
and submit signed records in three lines.

## Quickstart

```ts
import { Agent } from "@elara/sdk";

const agent = await Agent.create({
  nodeUrl: "http://127.0.0.1:9473",
  identity: "<64-hex-char identity>",
});

const balance = await agent.balance();   // { available, staked, total, … }
const proof   = await agent.prove();      // Merkle proof against latest seal
```

## Submitting records

The SDK is read-and-submit only — signing happens in your wallet (browser,
hardware, `elara-cli`, or `@elara/mcp-server`'s `elara_sign` tool). Records
arrive at `agent.record()` already carrying a Dilithium3 signature:

```ts
await agent.record({
  id, identity, signature, public_key, payload, timestamp,
});
```

This boundary mirrors the public REST API's contract — the node validates
the signature on submission and rejects unsigned records.

## Why no key handling

Browser wallets, hardware wallets, and AI agent runtimes each prefer to
keep keys local. Pushing signing into the SDK would either pin one
strategy (bad for hardware) or duplicate the post-quantum stack (bad for
bundle size). Two clean halves — `@elara/sdk` for I/O, your wallet of
choice for keys — composes cleanly with the existing `@elara/mcp-server`
which already exposes a canonical `elara_sign` tool.

## Endpoints used

| Method | Path                          | Purpose                       |
|--------|-------------------------------|-------------------------------|
| GET    | `/status`                     | liveness probe in `Agent.create` |
| GET    | `/proof/account/{identity}`   | `agent.balance()` (projects `account_state` + `bound_to_seal`) and `agent.prove()` (full proof) |
| POST   | `/records`                    | `agent.record()`              |

> `balance()` and `prove()` both read the seal-bound `/proof/account` endpoint —
> the only publicly-routable account read. (The raw `/account/{identity}` route is
> loopback/data-plane only; off-host clients get 404.) `balance()` returns the
> projected balance fields plus verification flags; `prove()` returns the full
> Merkle proof (`root`, `siblings`, `state_hash`).

> **`record()` writes to the data plane.** `POST /records` is not on the node's
> public surface, so `agent.record()` reaches a node only via its data-plane port
> (`127.0.0.1:9472` by default) or a node run in single-listener mode
> (`ELARA_DATA_PLANE_LISTEN=`). Reads (`balance()`, `prove()`) work on the public
> `--listen` port either way — set `nodeUrl` to match what you need.

Cross-origin reads against any reachable node are unblocked by the
permissive CORS rule on the public router (`pq_server.rs`).

## Tests

```bash
npm install
npm test
```

12 smoke tests against an in-process HTTP stub — no live node required.
