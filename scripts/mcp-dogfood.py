#!/usr/bin/env python3
"""elara-mcp stdio dogfood — drives the release binary over real JSON-RPC
exactly as an MCP client would, against a LIVE node, and emits one real
receipted act. This is the crate's acceptance harness (v0 gate per
docs/design-briefs/MCP-MANDATE-SERVER-VERDICT-2026-08-19.md, Q8: dogfood
before any external mention) — first run PASSED 2026-08-19, acceptance act
01a01b51-9825-7223-bbb8-7f6270acfe6a (flag=valid, lineage depth 1).

Sequence: initialize -> tools/list -> my_mandate -> bundle_verify (offline,
committed vector) -> act_emit (REAL act; args hashed server-side) ->
act_status on the record just created + the unwrapped-ledger-text invariant.

Config comes from the same env the server itself uses — no defaults here, by
design (the server's own fail-loud rule):
  ELARA_MCP_NODE_URL, ELARA_NETWORK_ID, ELARA_MCP_IDENTITY,
  ELARA_MCP_MANDATE_ID, ELARA_MCP_CLI, ELARA_MCP_BIN (path to elara-mcp),
  ELARA_MCP_VECTOR (optional; default examples/verify/mandate-bundle-valid.json)
NOTE: each PASS emits one real record and spends 1 of the identity's daily
cap — that is the system working; a cap refusal exercises the fail-closed
path instead (ok:false with the node's verbatim error).
"""
import json, os, subprocess, sys, time, threading, queue

def need(k):
    v = os.environ.get(k, "").strip()
    if not v:
        sys.exit(f"{k} is required (this harness inherits the server's fail-loud rule)")
    return v

BIN = need("ELARA_MCP_BIN")
for k in ("ELARA_MCP_NODE_URL", "ELARA_NETWORK_ID", "ELARA_MCP_IDENTITY",
          "ELARA_MCP_MANDATE_ID", "ELARA_MCP_CLI"):
    need(k)
VECTOR = os.environ.get("ELARA_MCP_VECTOR",
                        os.path.join(os.path.dirname(__file__), "..",
                                     "examples/verify/mandate-bundle-valid.json"))
OUT = os.environ.get("ELARA_MCP_TRANSCRIPT", "mcp-dogfood-transcript.jsonl")

proc = subprocess.Popen([BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, text=True, bufsize=1)

q: "queue.Queue[str]" = queue.Queue()
def _reader():
    for line in proc.stdout:
        q.put(line)
threading.Thread(target=_reader, daemon=True).start()

transcript = open(OUT, "w")
def log(direction, obj):
    transcript.write(json.dumps({"t": time.strftime("%H:%M:%S"),
                                 "dir": direction, "msg": obj}) + "\n")
    transcript.flush()

def send(obj):
    log("->", obj)
    proc.stdin.write(json.dumps(obj) + "\n"); proc.stdin.flush()

def recv_until(want_id, timeout=60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            line = q.get(timeout=max(0.1, deadline - time.time()))
        except queue.Empty:
            break
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            log("<-raw", line); continue
        log("<-", msg)
        if msg.get("id") == want_id:
            return msg
    sys.exit(f"TIMEOUT waiting for response id={want_id}")

def tool_result_json(msg):
    content = msg["result"]["content"]
    text = next(c["text"] for c in content if c.get("type") == "text")
    return json.loads(text)

fails = []
def check(name, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))
    if not cond:
        fails.append(name)

send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
    "protocolVersion": "2025-06-18", "capabilities": {},
    "clientInfo": {"name": "elara-mcp-dogfood", "version": "0"}}})
init = recv_until(1)
check("initialize", "result" in init,
      init.get("result", {}).get("serverInfo", {}).get("name", "?"))
send({"jsonrpc": "2.0", "method": "notifications/initialized"})

send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
names = sorted(t["name"] for t in recv_until(2)["result"]["tools"])
check("tools/list = the 4 designed tools",
      names == ["mandate_act_emit", "mandate_act_status",
                "mandate_bundle_verify", "mandate_my_mandate"], ",".join(names))

send({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
      "params": {"name": "mandate_my_mandate", "arguments": {}}})
mm = tool_result_json(recv_until(3))
check("my_mandate ok + found",
      mm.get("ok") is True and mm["mandate"].get("found") is not False,
      f"revoked={mm['mandate'].get('revoked')}")

with open(VECTOR) as f:
    bundle = f.read()
send({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {
    "name": "mandate_bundle_verify", "arguments": {"bundle_json": bundle}}})
bv = tool_result_json(recv_until(4))
check("bundle_verify = CONSISTENT/authorized",
      bv.get("ok") is True and bv["bundle_verdict"]["verdict"] == "CONSISTENT"
      and bv["bundle_verdict"]["authorized"] is True, bv["bundle_verdict"]["verdict"])

send({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {
    "name": "mandate_act_emit", "arguments": {
        "tool": "elara-mcp", "action": "dogfood",
        "args": {"event": "elara-mcp stdio dogfood",
                 "design": "docs/design-briefs/MCP-MANDATE-SERVER-VERDICT-2026-08-19.md",
                 "claim": "act emitted through the MCP server, args hashed server-side"},
        "session_id": "elara-mcp-dogfood"}}})
em = tool_result_json(recv_until(5, timeout=90))
rid = em.get("record_id")
check("act_emit accepted", em.get("ok") is True and isinstance(rid, str) and len(rid) > 8,
      f"record_id={rid} args_hash={str(em.get('args_hash',''))[:16]}… "
      f"error={em.get('emit',{}).get('error','-')}")

if isinstance(rid, str) and em.get("ok") is True:
    send({"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {
        "name": "mandate_act_status", "arguments": {"record_id": rid}}})
    st = tool_result_json(recv_until(6))
    s = st.get("status", {})
    check("act_status authorized+valid",
          st.get("ok") is True and s.get("authorized") is True and s.get("flag") == "valid",
          f"flag={s.get('flag')} depth={s.get('chain_depth')}")
    # Envelope invariant: no ledger-text key may appear as a BARE string —
    # today /mandate/status echoes no free text (lineage = hashes only), so
    # absence passes; an unwrapped appearance is the only failure. The
    # wrapping itself is pinned by the crate's unit tests.
    KEYS = {"tool", "action", "agent_id", "session_id", "explanation",
            "reason", "scope_note", "ops", "note"}
    def bare(v, path="$"):
        out = []
        if isinstance(v, dict):
            for k, val in v.items():
                if k in KEYS and isinstance(val, str):
                    out.append(f"{path}.{k}")
                else:
                    out.extend(bare(val, f"{path}.{k}"))
        elif isinstance(v, list):
            for i, item in enumerate(v):
                out.extend(bare(item, f"{path}[{i}]"))
        return out
    viol = bare(s)
    check("no unwrapped ledger-text keys in status", not viol,
          ",".join(viol) if viol else f"lineage_hops={len(s.get('lineage') or [])}")

proc.stdin.close()
try:
    proc.wait(timeout=10)
except subprocess.TimeoutExpired:
    proc.kill()
transcript.close()
print("--- server stderr ---")
print(proc.stderr.read().strip()[:800])
print(f"transcript: {OUT}")
if fails:
    print(f"DOGFOOD: FAIL ({', '.join(fails)})"); sys.exit(1)
print(f"DOGFOOD: PASS — record {rid} is the acceptance act")
