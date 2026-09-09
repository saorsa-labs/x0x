"""Render a temporary live-test daemon config; requires Python 3.11+, no network."""

import argparse
import ipaddress
import json
from pathlib import Path
import sys
import tomllib


def toml_string(value: str) -> str:
    # TOML requires Unicode scalar values and also forbids literal DEL. JSON
    # escapes the other forbidden controls; preserve supplementary Unicode.
    value.encode("utf-8")
    return json.dumps(value, ensure_ascii=False).replace("\x7f", "\\u007f")


def testnet_bootstrap_peers(repository: Path) -> list[str]:
    authority = repository / ".deployment/config/bootstrap-config-testnet.toml"
    with authority.open("rb") as stream:
        config = tomllib.load(stream)
    peers = config.get("bootstrap_peers")
    if not isinstance(peers, list) or not peers:
        raise ValueError("tracked testnet bootstrap_peers must be a nonempty array")
    for peer in peers:
        if not isinstance(peer, str):
            raise ValueError("tracked testnet bootstrap entries must be strings")
        address, separator, port = peer.rpartition(":")
        if separator != ":" or port != "6483":
            raise ValueError("tracked testnet bootstrap entries must use port 6483")
        if address.startswith("[") and address.endswith("]"):
            literal = address[1:-1]
            if "%" in literal or not isinstance(
                ipaddress.ip_address(literal), ipaddress.IPv6Address
            ):
                raise ValueError("invalid bracketed testnet IPv6 address")
        elif not isinstance(ipaddress.ip_address(address), ipaddress.IPv4Address):
            raise ValueError("testnet IPv6 addresses must be bracketed")
    return peers


def render_config(network: str, repository: Path, data_dir: str) -> str:
    if network not in ("test", "prod"):
        raise ValueError("network must be test or prod")
    # Resolve all authority before returning any usable configuration.
    peers = testnet_bootstrap_peers(repository) if network == "test" else None
    lines = [
        'instance_name = "e2e-live"',
        f"data_dir = {toml_string(data_dir)}",
        'bind_address = "0.0.0.0:15483"',
        'api_address = "127.0.0.1:19200"',
        'log_level = "warn"',
    ]
    if peers is not None:
        lines.extend([
            "# Selected testnet seeds from the tracked deployment configuration.",
            f"bootstrap_peers = {json.dumps(peers)}",
        ])
    else:
        lines.append("# Explicit prod mode preserves the daemon's default seed list.")
    # Neither tracked fleet config defines a separate network_id. Do not invent one.
    lines.extend([
        "",
        "# This temporary test child must not update itself; fleet configs differ.",
        "[update]",
        "enabled = false",
        "gossip_updates = false",
    ])
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--network", choices=("test", "prod"), required=True)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--data-dir", required=True)
    args = parser.parse_args()
    try:
        config = render_config(args.network, args.repository, args.data_dir)
    except (OSError, ValueError) as error:
        print(f"Cannot prepare live-test configuration: {error}", file=sys.stderr)
        return 1
    sys.stdout.write(config)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
