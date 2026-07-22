"""elara — Python SDK for the Elara mesh network.

Quickstart:

    from elara import Agent

    agent = Agent.create(
        node_url="http://127.0.0.1:9473",
        identity="<64-hex-char identity>",
    )
    balance = agent.balance()
    proof = agent.prove()

The SDK is read-and-submit only. Signing happens in your wallet — see
``agent.record()`` for the signed-record contract.
"""

from .agent import Agent
from .client import ElaraHttpError, NodeClient

__all__ = ["Agent", "NodeClient", "ElaraHttpError"]
__version__ = "0.1.0"
