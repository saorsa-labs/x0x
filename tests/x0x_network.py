"""x0x_network — single source of truth for which fleet a test script targets.

Every test/deploy script in tests/ MUST go through this module to pick a network.
Default is **testnet**. Production requires explicit `--network prod` AND a 5s
Ctrl-C window before any action is taken. Token files are split per-network so
the wrong tokens cannot accidentally be sourced.

Usage in a script::

    from tests.x0x_network import select_network, banner
    net = select_network()  # parses --network, defaults to test
    banner(net)             # prints loud banner; for prod also waits 5s
    # now use net.api_port, net.gossip_port, net.nodes, net.token_for(node)

To target production::

    python3 tests/launch_readiness.py --network prod --anchor nyc
    # → banner: "⚠️ TARGETING: PRODUCTION FLEET" + 5s wait window

Defaults to test, so a casual run cannot accidentally hit prod.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


TESTS_DIR = Path(__file__).resolve().parent

# Node identity (the 4 VPS bootstrap hosts; #2094 removed Helsinki and
# Nuremberg on 19 Nov 2026 — same IPs for both networks; only
# the ports + tokens differ).
NODES_BY_NAME: Dict[str, str] = {
    "nyc":       "142.93.199.50",
    "sfo":       "147.182.234.192",
    "singapore": "152.42.210.67",
    "sydney":    "170.64.176.102",
}


# #2094: the closed Hetzner hosts. Their addresses may now belong to other
# people, so a tokens or hosts file that still names one is stale and must
# never be used to aim SSH or API calls.
REMOVED_HOST_IPS = frozenset({
    "65.21.157.229",
    "116.203.101.172",
    "2a01:4f9:c012:684b::1",
    "2a01:4f8:1c1a:31e6::1",
})


def refuse_removed_host_ips(tokens: Dict[str, tuple], source: object) -> None:
    """Fail closed when a parsed tokens map names a closed host (#2094).

    `tokens` maps a node label to `(ip, token)`. The label is not checked:
    `helsinki`/`nuremberg` are still valid ephemeral-testnet slot labels.
    """
    for label, entry in tokens.items():
        ip = entry[0].strip().strip("[]").lower()
        if ip in REMOVED_HOST_IPS:
            raise ValueError(
                f"{source}: node '{label}' points at {ip}, a closed host "
                "(#2094); regenerate the tokens file"
            )


@dataclass(frozen=True)
class Network:
    name: str                # "test" or "prod"
    api_port: int            # localhost-bound REST API port
    gossip_port: int         # UDP bootstrap / gossip port
    token_file: Path         # tests/.vps-tokens-<name>.env
    var_prefix: str          # env var prefix in the token file
    is_prod: bool            # True if targeting real users

    @property
    def nodes(self) -> Dict[str, str]:
        return dict(NODES_BY_NAME)

    def token_for(self, node: str) -> str:
        """Look up the API token for a node from the network's token file.

        The token file is shell-style `VAR="value"` lines; this parses without
        sourcing so a typo can't leak vars into the Python process env.
        """
        node_upper = node.upper()
        var = f"{self.var_prefix}_{node_upper}_TK"
        if not self.token_file.exists():
            raise FileNotFoundError(
                f"Token file {self.token_file} missing. "
                f"Run `tests/e2e_deploy.sh --network {self.name}` first."
            )
        for line in self.token_file.read_text().splitlines():
            line = line.strip()
            if line.startswith(f"{var}="):
                # strip VAR= prefix and surrounding quotes
                value = line[len(var) + 1:].strip()
                if value.startswith('"') and value.endswith('"'):
                    value = value[1:-1]
                return value
        raise KeyError(f"{var} not in {self.token_file}")

    def api_url(self, node: str) -> str:
        """Return the full API base URL for a node — uses the IP from NODES."""
        ip = NODES_BY_NAME.get(node)
        if ip is None:
            raise KeyError(f"unknown node {node!r}")
        return f"http://{ip}:{self.api_port}"


# ── The two canonical networks ────────────────────────────────────────────────
TEST = Network(
    name="test",
    api_port=13600,
    gossip_port=6483,
    token_file=TESTS_DIR / ".vps-tokens-test.env",
    var_prefix="TEST",
    is_prod=False,
)

PROD = Network(
    name="prod",
    api_port=12600,
    gossip_port=5483,
    token_file=TESTS_DIR / ".vps-tokens-prod.env",
    var_prefix="PROD",
    is_prod=True,
)

NETWORKS = {"test": TEST, "prod": PROD}


def add_network_arg(parser: argparse.ArgumentParser) -> None:
    """Standard --network flag. Add this to any test script's argparse.

    `test` is the default. `prod` requires the user to type it explicitly.
    """
    parser.add_argument(
        "--network",
        choices=["test", "prod"],
        default="test",
        help=(
            "Which fleet to target. Default 'test' (isolated testnet on "
            "ports 6483/13600). Pass 'prod' to target the production fleet "
            "(5483/12600) — REAL USERS, real consequences, will pause 5s "
            "for Ctrl-C before any action."
        ),
    )


def select_network(args: Optional[argparse.Namespace] = None) -> Network:
    """Resolve --network from parsed args (or sys.argv) to a Network."""
    if args is None:
        parser = argparse.ArgumentParser(add_help=False)
        add_network_arg(parser)
        args, _ = parser.parse_known_args()
    name = getattr(args, "network", "test")
    return NETWORKS[name]


def banner(net: Network, *, hold_seconds: float = 5.0) -> None:
    """Print a loud banner identifying the network. For prod, hold for
    `hold_seconds` so the operator has a Ctrl-C window before any action.

    Skip the hold with X0X_NETWORK_NO_HOLD=1 (CI / non-interactive runs).
    """
    width = 70
    if net.is_prod:
        bar = "═" * (width - 2)
        print(
            f"\n\033[1;41;97m╔{bar}╗\n"
            f"║{'⚠️  TARGETING: PRODUCTION FLEET  ⚠️'.center(width - 2)}║\n"
            f"║{('UDP ' + str(net.gossip_port) + ' / TCP ' + str(net.api_port) + ' / REAL USERS').center(width - 2)}║\n"
            f"║{('token file: ' + net.token_file.name).center(width - 2)}║\n"
            f"║{('Ctrl-C in ' + str(int(hold_seconds)) + 's to abort').center(width - 2)}║\n"
            f"╚{bar}╝\033[0m\n",
            file=sys.stderr,
        )
        if hold_seconds > 0 and os.environ.get("X0X_NETWORK_NO_HOLD") != "1":
            try:
                time.sleep(hold_seconds)
            except KeyboardInterrupt:
                print("\nAborted by operator.", file=sys.stderr)
                sys.exit(130)
    else:
        bar = "─" * (width - 2)
        print(
            f"\n\033[1;42;30m┌{bar}┐\n"
            f"│{'TARGETING: TESTNET'.center(width - 2)}│\n"
            f"│{('UDP ' + str(net.gossip_port) + ' / TCP ' + str(net.api_port) + ' / no real users').center(width - 2)}│\n"
            f"│{('token file: ' + net.token_file.name).center(width - 2)}│\n"
            f"└{bar}┘\033[0m\n",
            file=sys.stderr,
        )


# ── self-test ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="x0x_network self-test")
    add_network_arg(parser)
    args = parser.parse_args()
    net = select_network(args)
    banner(net, hold_seconds=2.0)
    print(f"network:     {net.name}")
    print(f"api_port:    {net.api_port}")
    print(f"gossip_port: {net.gossip_port}")
    print(f"token_file:  {net.token_file}")
    print(f"nodes:       {list(net.nodes.keys())}")
    print(f"nyc URL:     {net.api_url('nyc')}")
    try:
        tk = net.token_for("nyc")
        print(f"nyc token:   {tk[:16]}…")
    except (FileNotFoundError, KeyError) as e:
        print(f"nyc token:   ERROR — {e}")
