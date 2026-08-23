#!/usr/bin/env python3
# Strands <-> elara-mcp interop test — drives the AWS Strands Agents SDK's OWN
# native MCP client (`strands.tools.mcp.MCPClient`, which wraps the official
# `mcp` Python SDK: stdio spawn, initialize handshake, tools/list, call_tool)
# against a release `elara-mcp` binary on a LIVE chain. Everything that crosses
# the process boundary is Strands' + the MCP SDK's own code; no model runtime is
# involved (the registration surface is below the model, exactly the layer this
# tests).
#
# Setup (see README.md + ../../docs/QUICKSTART-ISSUER.md):
#   pip install strands-agents
#   export ELARA_MCP_BIN=/path/to/elara-mcp     # cargo build --release -p elara-mcp --features node
#   export ELARA_MCP_NODE_URL=http://127.0.0.1:9474
#   export ELARA_NETWORK_ID=<your network id>
#   export ELARA_MCP_IDENTITY=/path/to/agent-identity.json
#   export ELARA_MCP_MANDATE_ID=<mandate id from elara-cli mandate-issue>
#   python strands_interop_test.py            # registration proof (read-only)
#   EMIT=1 python strands_interop_test.py      # also emit ONE real receipted act
#
# The EMIT leg writes a REAL record to the configured chain under the configured
# mandate and spends one unit of the identity's daily emission cap; off by default.
import json, os, sys

from mcp import StdioServerParameters, stdio_client
from strands.tools.mcp import MCPClient

EXPECTED = ["mandate_act_emit", "mandate_act_status",
            "mandate_bundle_verify", "mandate_my_mandate"]

def need(k):
    v = (os.environ.get(k) or "").strip()
    if not v:
        print(f"{k} is required", file=sys.stderr); sys.exit(2)
    return v

BIN = need("ELARA_MCP_BIN")
passthru = ["ELARA_MCP_NODE_URL", "ELARA_NETWORK_ID", "ELARA_MCP_IDENTITY",
            "ELARA_MCP_MANDATE_ID"]
env = {k: need(k) for k in passthru}
env["ELARA_MCP_AGENT_ID"] = os.environ.get("ELARA_MCP_AGENT_ID", "strands-interop-test")
# elara-mcp is fail-closed on config; inherit PATH so it can resolve libs.
env["PATH"] = os.environ.get("PATH", "")

results = []
def check(name, ok, detail=""):
    results.append(ok)
    print(f"{'PASS' if ok else 'FAIL'}  {name}{'  — ' + detail if detail else ''}")

# Strands' native MCP client: a factory returning an MCP stdio transport.
client = MCPClient(lambda: stdio_client(
    StdioServerParameters(command=BIN, args=[], env=env)))

with client:
    tools = client.list_tools_sync()
    # Strands wraps each MCP tool; the underlying MCP name is the authority.
    names = sorted(getattr(t, "tool_name", None)
                   or t.mcp_tool.name for t in tools)
    check("Strands MCPClient registers the 4 mandate tools",
          names == EXPECTED, json.dumps(names))

    # Strands' call_tool_sync returns a dict:
    # {status, toolUseId, content:[{text:...}], isError}.
    def text_of(res):
        content = res.get("content", []) if isinstance(res, dict) else \
            getattr(res, "content", [])
        return "".join(c.get("text", "") for c in content if isinstance(c, dict))

    # Read-only mandate introspection through Strands' own call path.
    res = client.call_tool_sync(tool_use_id="probe-mandate",
                                name="mandate_my_mandate", arguments={})
    txt = text_of(res)
    live = ('"revoked": false' in txt) and ('"found": true' in txt)
    check("mandate_my_mandate returns a live mandate via Strands", live,
          "revoked=false, found=true" if live else txt[:120].replace("\n", " "))

    if os.environ.get("EMIT") == "1":
        act = client.call_tool_sync(
            tool_use_id="probe-emit", name="mandate_act_emit",
            arguments={"content": {"interop": "strands", "ts": "probe"},
                       "op": "commit"})
        atxt = text_of(act)
        check("mandate_act_emit writes a receipted act via Strands dispatch",
              ("record_id" in atxt or "recordId" in atxt), atxt[:160].replace("\n", " "))

ok = all(results) and len(results) >= 2
print(f"\n{'ALL PASS' if ok else 'FAILURES PRESENT'} — {sum(results)}/{len(results)} checks")
sys.exit(0 if ok else 1)
