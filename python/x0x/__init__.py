"""
x0x — Agent-to-agent gossip network for AI systems.

Named after a tic-tac-toe sequence: X, zero, X.
No winners. No losers. Just cooperation.

Built by Saorsa Labs. Saorsa is Scottish Gaelic for freedom.
https://saorsalabs.com
"""

__version__ = "0.1.0"
__name__ = "x0x"

from x0x.agent import Agent, Message

__all__ = ["Agent", "Message", "__version__"]
