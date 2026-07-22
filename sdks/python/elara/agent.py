"""High-level Agent API matching ``@elara/sdk``."""

from __future__ import annotations

import re
from typing import Any, Mapping, Optional

from .client import NodeClient

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _normalize_identity(identity: Optional[str]) -> Optional[str]:
    if identity is None:
        return None
    trimmed = identity.strip().lower()
    if not _HEX64.match(trimmed):
        raise ValueError(
            f"identity must be 64 hex chars (32-byte SHA3-256), "
            f"got {len(identity)} chars"
        )
    return trimmed


class Agent:
    """Three-line integration with the Elara mesh:

    >>> agent = Agent.create(node_url="http://...", identity="<hex>")
    >>> agent.balance()                # noqa: doctest skipped (network call)
    >>> agent.prove()                  # noqa
    """

    def __init__(self, client: NodeClient, identity: Optional[str]) -> None:
        self.client = client
        self.identity = identity

    # ── constructors ────────────────────────────────────────────────────

    @classmethod
    def create(
        cls,
        node_url: str,
        identity: Optional[str] = None,
        timeout_s: float = 8.0,
    ) -> "Agent":
        """Construct an Agent and verify the configured node is reachable.

        Raises :class:`ValueError` for a malformed identity hex BEFORE any
        I/O so a bad config fails fast. Raises :class:`ElaraHttpError` if
        the node returns non-2xx for ``/status``.
        """
        normalized = _normalize_identity(identity)
        client = NodeClient(node_url, timeout_s=timeout_s)
        client.status()  # liveness probe
        return cls(client, normalized)

    @classmethod
    def unchecked(
        cls,
        node_url: str,
        identity: Optional[str] = None,
        timeout_s: float = 8.0,
    ) -> "Agent":
        """Same shape as :meth:`create` but skips the liveness probe.

        Useful in tests or for lazy connections.
        """
        return cls(
            NodeClient(node_url, timeout_s=timeout_s),
            _normalize_identity(identity),
        )

    # ── methods ─────────────────────────────────────────────────────────

    def balance(self, identity: Optional[str] = None) -> Mapping[str, Any]:
        """Proof-backed balance for ``identity`` (default: this agent).

        Returns the account's state fields (``available``, ``staked``, …)
        overlaid with ``exists`` and ``bound_to_seal`` — so the balance is
        self-describing as verified against the latest signed seal. Sourced
        from the public ``/proof/account`` endpoint; ``exists`` is ``False``
        for an unknown identity. Use :meth:`prove` for the full Merkle proof.
        """
        return self.client.account_detail(self._require_id(identity))

    def prove(self, identity: Optional[str] = None) -> Mapping[str, Any]:
        """Merkle proof of ``identity``'s account state.

        ``bound_to_seal`` is true when the proof root matches the latest
        signed epoch seal — verifiable finality.
        """
        return self.client.account_proof(self._require_id(identity))

    def record(self, signed_record: Mapping[str, Any]) -> Mapping[str, Any]:
        """Submit a fully-signed record.

        ``signed_record`` must already carry ``signature`` and
        ``public_key`` fields produced by your wallet (browser, hardware,
        ``elara-cli``, or ``@elara/mcp-server``'s ``elara_sign`` tool).
        """
        if not signed_record.get("signature") or not signed_record.get("public_key"):
            raise ValueError(
                "record must carry `signature` and `public_key` — sign with "
                "your wallet (or @elara/mcp-server's elara_sign tool) before "
                "calling agent.record()."
            )
        return self.client.submit_record(signed_record)

    # ── plumbing ────────────────────────────────────────────────────────

    def _require_id(self, override: Optional[str]) -> str:
        identity = override if override is not None else self.identity
        if not identity:
            raise ValueError(
                "identity is required — pass one to the method, or supply "
                "`identity` to Agent.create()."
            )
        return identity
