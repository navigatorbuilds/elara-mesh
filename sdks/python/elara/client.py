"""Low-level HTTP client. Most callers want :class:`elara.Agent`."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Mapping


class ElaraHttpError(Exception):
    """Raised when an HTTP call to a node returns a non-2xx response."""

    def __init__(self, request: str, status: int, body: str) -> None:
        super().__init__(f"{request} → HTTP {status}: {body}")
        self.request = request
        self.status = status
        self.body = body


class NodeClient:
    """Thin wrapper around an Elara node's public REST API.

    Pure-stdlib (``urllib``) — no third-party dependencies. The Agent class
    layers a tidier API on top; reach for NodeClient when you need direct
    GET/POST against an arbitrary path.
    """

    def __init__(self, node_url: str, timeout_s: float = 8.0) -> None:
        if not node_url:
            raise ValueError("node_url is required")
        self._base = node_url.rstrip("/")
        self._timeout_s = timeout_s

    @property
    def url(self) -> str:
        return self._base

    # ── high-level shortcuts ────────────────────────────────────────────

    def status(self) -> Mapping[str, Any]:
        return self._get_json("/status")

    def account_detail(self, identity: str) -> Mapping[str, Any]:
        """Normalized, proof-backed account view: the balance fields
        (``available``/``staked``/…) overlaid with the verification flags
        (``exists``, ``bound_to_seal``, ``live_state_matches_sealed``).

        Reads the PUBLIC ``/proof/account/{id}`` endpoint and projects its
        ``account_state``. The raw ``/account/{id}`` route is loopback/
        data-plane only and 404s for off-host clients, so the SDK reads the
        seal-bound proof endpoint instead — every balance is therefore
        self-describing as verified-against-a-signed-seal (``bound_to_seal``)
        or not. ``exists`` is ``False`` for an unknown identity (the endpoint
        returns 200, not 404, in that case).
        """
        proof = self.account_proof(identity)
        state = dict(proof.get("account_state") or {})
        state["identity"] = proof.get("identity", identity)
        state["exists"] = bool(proof.get("exists", False))
        state["bound_to_seal"] = bool(proof.get("bound_to_seal", False))
        if "live_state_matches_sealed" in proof:
            state["live_state_matches_sealed"] = proof["live_state_matches_sealed"]
        if proof.get("pending_first_seal"):
            state["pending_first_seal"] = True
        return state

    def account_proof(self, identity: str) -> Mapping[str, Any]:
        return self._get_json(
            f"/proof/account/{urllib.parse.quote(identity, safe='')}"
        )

    def submit_record(self, record: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._post_json("/records", record)

    # ── plumbing ────────────────────────────────────────────────────────

    def _get_json(self, path: str) -> Mapping[str, Any]:
        req = urllib.request.Request(self._base + path, method="GET")
        return self._dispatch(req, f"GET {path}")

    def _post_json(self, path: str, body: Mapping[str, Any]) -> Mapping[str, Any]:
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            self._base + path,
            data=data,
            method="POST",
            headers={"content-type": "application/json"},
        )
        return self._dispatch(req, f"POST {path}")

    def _dispatch(
        self, req: urllib.request.Request, label: str
    ) -> Mapping[str, Any]:
        try:
            with urllib.request.urlopen(req, timeout=self._timeout_s) as resp:
                raw = resp.read().decode("utf-8")
                if 200 <= resp.status < 300:
                    return json.loads(raw) if raw else {}
                raise ElaraHttpError(label, resp.status, raw)
        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read().decode("utf-8", errors="replace")
            except Exception:
                pass
            raise ElaraHttpError(label, e.code, body) from None
