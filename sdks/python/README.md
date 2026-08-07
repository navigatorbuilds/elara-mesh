# `elara` (Python SDK)

Pure-stdlib Python SDK for the Elara mesh network. Mirrors `@elara/sdk`'s
three-line integration. Zero third-party deps — uses `urllib` + `json` from
the standard library.

## Quickstart

```python
from elara import Agent

agent = Agent.create(
    node_url="http://127.0.0.1:9473",
    identity="<64-hex-char identity>",
)
balance = agent.balance()   # {"available": ..., "staked": ..., "exists": ..., "bound_to_seal": ...}
proof = agent.prove()        # full Merkle proof against latest signed seal
```

## Submitting records

```python
agent.record({
    "id": ..., "identity": ..., "signature": ..., "public_key": ...,
    "payload": {...}, "timestamp": ...,
})
```

The record must already be signed. Pair this SDK with one of:

- `elara-cli` for CLI-based Dilithium3 signing
- `@elara/mcp-server`'s `elara_sign` tool (canonicalization + your own key)
- The Rust `pq_client_sdk::WalletClient` (heavyweight, native)

> **`record()` uses the data plane.** `POST /records` is not on the node's public
> surface, so `agent.record()` reaches a node only via its data-plane port
> (`127.0.0.1:9472` by default) or a node run in single-listener mode
> (`ELARA_DATA_PLANE_LISTEN=` — the Docker-compose default). Reads (`balance()`,
> `prove()`) work on the public `--listen` port either way. Set `node_url` to match.

## Endpoints used

| Method | Path                          | Surfaces as           |
|--------|-------------------------------|-----------------------|
| GET    | `/status`                     | liveness probe        |
| GET    | `/proof/account/{identity}`   | `agent.balance()` (projects `account_state` + `bound_to_seal`) and `agent.prove()` (full proof) |
| POST   | `/records`                    | `agent.record()`      |

> `balance()` and `prove()` share the seal-bound `/proof/account` endpoint —
> the only publicly-routable account read. (The raw `/account/{identity}` route
> is loopback/data-plane only; an off-host client gets 404.) `balance()` returns
> the projected balance fields plus the verification flags; `prove()` returns the
> full Merkle proof (`root`, `siblings`, `state_hash`).

## Install (local)

```bash
pip install -e sdks/python
```

(`pip install elara` once published.)

## Tests

```bash
cd sdks/python
python -m unittest discover -s tests
```

13 smoke tests against an in-process `http.server` stub — no live node needed.

## Related

- `sdks/typescript/` — `@elara/sdk` (TypeScript twin)
- `sdks/mcp-server/` — `@elara/mcp-server` (MCP for AI agents)
