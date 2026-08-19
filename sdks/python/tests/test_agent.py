"""Smoke tests for the elara SDK against an in-process HTTP stub.

Run with: ``python -m unittest -v tests/test_agent.py``
(or via pytest if you'd rather: ``pytest tests/``).
"""

from __future__ import annotations

import json
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Dict, List, Tuple

# Allow `python -m unittest` to discover tests when run from the repo root
# without `pip install -e .` first.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from elara import Agent, ElaraHttpError, NodeClient  # noqa: E402


ID = "a" * 64
OTHER = "b" * 64


class StubHandler(BaseHTTPRequestHandler):
    routes: Dict[Tuple[str, str], Tuple[int, Any]] = {}
    hits: List[Dict[str, str]] = []

    def _route(self) -> Tuple[int, Any] | None:
        for (method, prefix), payload in self.routes.items():
            if method == self.command and self.path.startswith(prefix):
                return payload
        return None

    def _serve(self, body: str = "") -> None:
        self.hits.append(
            {"method": self.command, "path": self.path, "body": body}
        )
        match = self._route()
        if match is None:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"not found")
            return
        status, payload = match
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode("utf-8"))

    def do_GET(self) -> None:  # noqa: N802
        self._serve()

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(length).decode("utf-8") if length else ""
        self._serve(body)

    def log_message(self, *args: Any, **kwargs: Any) -> None:
        # silence the default per-request log noise
        pass


def start_stub(routes: Dict[Tuple[str, str], Tuple[int, Any]]) -> Tuple[
    HTTPServer, str, List[Dict[str, str]]
]:
    hits: List[Dict[str, str]] = []
    handler = type(
        "_BoundHandler",
        (StubHandler,),
        {"routes": routes, "hits": hits},
    )
    srv = HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_port}", hits


class AgentTests(unittest.TestCase):
    def test_create_probes_status(self) -> None:
        srv, url, hits = start_stub({("GET", "/status"): (200, {"ok": True})})
        try:
            agent = Agent.create(node_url=url, identity=ID)
            self.assertEqual(agent.identity, ID)
            self.assertEqual(hits[0]["path"], "/status")
        finally:
            srv.shutdown()
            srv.server_close()

    def test_create_surfaces_http_error_when_node_down(self) -> None:
        srv, url, _ = start_stub({("GET", "/status"): (500, "boom")})
        try:
            with self.assertRaises(ElaraHttpError) as ctx:
                Agent.create(node_url=url, identity=ID)
            self.assertEqual(ctx.exception.status, 500)
        finally:
            srv.shutdown()
            srv.server_close()

    def test_create_rejects_malformed_identity_before_any_io(self) -> None:
        # Use an unreachable URL to prove the validator runs first.
        with self.assertRaises(ValueError) as ctx:
            Agent.create(node_url="http://127.0.0.1:1", identity="not-hex")
        self.assertIn("64 hex chars", str(ctx.exception))

    def test_balance_projects_proof_account_state(self) -> None:
        # balance() reads the public /proof/account endpoint and projects its
        # account_state overlaid with the verification flags.
        srv, url, hits = start_stub(
            {
                ("GET", "/status"): (200, {}),
                ("GET", f"/proof/account/{ID}"): (
                    200,
                    {
                        "identity": ID,
                        "exists": True,
                        "root": "0" * 64,
                        "state_hash": "1" * 64,
                        "account_state": {
                            "available": 7_500_000,
                            "staked": 1_500_000,
                            "total_received": 9_000_000,
                            "total_sent": 0,
                            "tx_count": 12,
                            "last_active": 1_700_000_000,
                        },
                        "live_state_matches_sealed": True,
                        "bound_to_seal": True,
                    },
                ),
            }
        )
        try:
            agent = Agent.create(node_url=url, identity=ID)
            bal = agent.balance()
            self.assertEqual(bal["available"], 7_500_000)
            self.assertEqual(bal["staked"], 1_500_000)
            self.assertTrue(bal["exists"])
            self.assertTrue(bal["bound_to_seal"])
            # balance() must hit the public proof endpoint, never raw /account.
            self.assertTrue(any(h["path"] == f"/proof/account/{ID}" for h in hits))
            self.assertFalse(any(h["path"].startswith("/account/") for h in hits))
        finally:
            srv.shutdown()
            srv.server_close()

    def test_balance_unknown_identity_reports_not_exists(self) -> None:
        # Unknown identity → /proof/account returns 200 with exists:false and
        # NO account_state. balance() must surface exists=False, not crash.
        srv, url, _ = start_stub(
            {
                ("GET", "/status"): (200, {}),
                ("GET", f"/proof/account/{OTHER}"): (
                    200,
                    {"identity": OTHER, "exists": False, "root": "0" * 64},
                ),
            }
        )
        try:
            agent = Agent.create(node_url=url, identity=ID)
            bal = agent.balance(OTHER)
            self.assertEqual(bal["identity"], OTHER)
            self.assertFalse(bal["exists"])
            self.assertFalse(bal["bound_to_seal"])
            self.assertNotIn("available", bal)
        finally:
            srv.shutdown()
            srv.server_close()

    def test_prove_returns_siblings(self) -> None:
        srv, url, _ = start_stub(
            {
                ("GET", "/status"): (200, {}),
                ("GET", f"/proof/account/{ID}"): (
                    200,
                    {
                        "identity": ID,
                        "exists": True,
                        "root": "0" * 64,
                        "state_hash": "1" * 64,
                        "siblings": [{"hash": "2" * 64, "is_right": True}],
                        "depth": 1,
                        "bound_to_seal": True,
                    },
                ),
            }
        )
        try:
            agent = Agent.create(node_url=url, identity=ID)
            proof = agent.prove()
            self.assertEqual(proof["depth"], 1)
            self.assertTrue(proof["bound_to_seal"])
        finally:
            srv.shutdown()
            srv.server_close()

    def test_record_rejects_unsigned(self) -> None:
        srv, url, _ = start_stub({("GET", "/status"): (200, {})})
        try:
            agent = Agent.create(node_url=url, identity=ID)
            with self.assertRaises(ValueError) as ctx:
                agent.record(
                    {
                        "id": "rec1",
                        "identity": ID,
                        "signature": "",
                        "public_key": "pk",
                        "payload": {},
                        "timestamp": 0,
                    }
                )
            self.assertIn("signature", str(ctx.exception))
            self.assertIn("public_key", str(ctx.exception))
        finally:
            srv.shutdown()
            srv.server_close()

    def test_record_posts_when_fully_signed(self) -> None:
        srv, url, hits = start_stub(
            {
                ("GET", "/status"): (200, {}),
                ("POST", "/records"): (200, {"accepted": True, "id": "rec1"}),
            }
        )
        try:
            agent = Agent.create(node_url=url, identity=ID)
            out = agent.record(
                {
                    "id": "rec1",
                    "identity": ID,
                    "signature": "ff",
                    "public_key": "aa",
                    "payload": {"kind": "transfer"},
                    "timestamp": 1700000000,
                }
            )
            self.assertTrue(out["accepted"])
            posted = next(h for h in hits if h["method"] == "POST")
            self.assertIn('"signature": "ff"', posted["body"])
        finally:
            srv.shutdown()
            srv.server_close()

    def test_unchecked_skips_liveness_probe(self) -> None:
        agent = Agent.unchecked(node_url="http://127.0.0.1:1", identity=ID)
        self.assertEqual(agent.identity, ID)
        self.assertEqual(agent.client.url, "http://127.0.0.1:1")

    def test_no_default_identity_errors_on_method_call(self) -> None:
        srv, url, _ = start_stub({("GET", "/status"): (200, {})})
        try:
            agent = Agent.create(node_url=url)
            with self.assertRaises(ValueError) as ctx:
                agent.balance()
            self.assertIn("identity is required", str(ctx.exception))
        finally:
            srv.shutdown()
            srv.server_close()

    def test_three_line_quickstart_against_stub(self) -> None:
        srv, url, _ = start_stub(
            {
                ("GET", "/status"): (200, {}),
                ("GET", f"/proof/account/{ID}"): (
                    200,
                    {
                        "identity": ID,
                        "exists": True,
                        "root": "0" * 64,
                        "account_state": {"available": 1, "staked": 0},
                        "bound_to_seal": True,
                    },
                ),
            }
        )
        try:
            agent = Agent.create(node_url=url, identity=ID)
            balance = agent.balance()
            proof = agent.prove()
            self.assertTrue(balance["exists"])
            self.assertTrue(proof["exists"])
        finally:
            srv.shutdown()
            srv.server_close()


class NodeClientTests(unittest.TestCase):
    def test_url_property_strips_trailing_slash(self) -> None:
        c = NodeClient("http://x/")
        self.assertEqual(c.url, "http://x")

    def test_node_url_required(self) -> None:
        with self.assertRaises(ValueError):
            NodeClient("")


if __name__ == "__main__":
    unittest.main()
