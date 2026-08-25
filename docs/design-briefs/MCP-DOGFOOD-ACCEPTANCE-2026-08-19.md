# elara-mcp v0 — dogfood acceptance record (2026-08-19)

Per MCP-MANDATE-SERVER-VERDICT-2026-08-19.md Q8: dogfood is v0's acceptance
gate, run BEFORE any external mention. Harness: `scripts/mcp-dogfood.py`
(real stdio JSON-RPC against the release binary, live authority-seed node, network
`testnet`).

## Run 1 — fail-closed proof (unplanned, kept deliberately)
Under the standing maintainer mandate (`605d8e66…`), whose agent identity had
already spent its daily cap: `mandate_act_emit` returned
`ok:false, error: "…daily record limit exceeded: identity limited to 10/day"`
verbatim from the node, with the attempted record id included for later
resolution — and the harness's follow-up `act_status` was answered honestly by
the node (`outside_coverage`, `is_mandate_act:false`). No retry, no bypass.
The live "10/day" is the entropy-throttle HALVING of `TIER_0_DAILY = 20`
(trust.rs `daily_limit_for`, band [0.3, 0.6)) — the exact reconciliation the
audit shipped hours earlier, confirmed in anger. All four tools + the honest
failure path: proven.

## Run 2 — acceptance PASS (7/7)
A fresh 24h wildcard dogfood mandate was issued for the run (principal
`7b4f7b17…` → build-agent `2b743c00…`, self-expiring):
mandate `b0348f26…`, carrier record `01a01b51-0628-7003-aa03-2833097c7f23`.

| Check | Result |
|---|---|
| initialize (rmcp handshake) | PASS |
| tools/list = exactly the 4 designed tools | PASS |
| mandate_my_mandate found + not revoked | PASS |
| mandate_bundle_verify on committed vector → CONSISTENT/authorized | PASS |
| mandate_act_emit → accepted, args hashed server-side | PASS |
| mandate_act_status on the new record → authorized, flag=valid, depth 1 | PASS |
| no unwrapped ledger-text key anywhere in the status response | PASS |

**Acceptance act: `01a01b51-9825-7223-bbb8-7f6270acfe6a`** — emitted THROUGH
the MCP server (this process never read the key; `elara-cli agent-emit
--json` subprocess signed and submitted), `args_hash ce1073bc…` computed
server-side from the real args, resolvable at
`/mandate/status/01a01b51-9825-7223-bbb8-7f6270acfe6a`.

## What the run taught (already folded back)
- The wrong-identity class is REAL: the first configuration pointed at a key
  that was not the mandate's agent — caught in pre-flight hash comparison.
  README now states plainly that a wrong key surfaces as `agent_mismatch` at
  first emit, not at startup (the server refuses to read the key file, so it
  cannot pre-check this).
- `#[tool_handler]` defaults to `Self::tool_router()` — the router FIELD is
  dead (and rebuilt per call) unless `router = self.tool_router` is passed;
  the dead_code warning was the tell.
- `/mandate/status` currently echoes no ledger-authored free text, so the
  ledger_text envelope's live-path assertion is "no BARE ledger-text key",
  with the wrapping behavior pinned in the crate's unit tests.
