"""Two-daemon DM demo for the typed Python client.

Boots two hermetic, loopback-only ``x0xd`` instances (no hard-coded
bootstrap peers, mDNS off, fixed loopback QUIC ports — the pattern from
``tests/e2e_local_mesh.sh``), then:

1. reads each daemon's identity (``GET /agent``),
2. exchanges signed agent cards so the two agents know each other,
3. opens agent B's ``/ws/direct`` WebSocket subscription,
4. sends a DM from agent A (``POST /direct/send``, durable receipt),
5. proves delivery by receiving the DM on B's subscription.

Run it from the repository root::

    cargo build --bin x0xd
    python3 examples/python-client/demo.py

The daemons never join the real network. Isolation comes from their
config: loopback-only binds, ``--no-hard-coded-bootstrap``, an empty or
loopback-only peer list, mDNS and port mapping off. In CI the demo also
runs inside the loopback-only network namespace of
``scripts/ci/isolated-runtime.py``, per ``tests/AGENTS.md``.

Exit code 0 means the DM arrived on B's subscription with the exact bytes
A sent. Any other outcome is non-zero, with both daemons' log tails printed.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from x0x_client import (
    ApiError,
    DirectMessage,
    RecipientKeyNotConverged,
    RecipientNeedsUpgrade,
    RecipientUndiscovered,
    RecipientUnknown,
    RecipientUpgradeRequired,
    X0xClient,
    X0xError,
    X0xTimeout,
    read_api_token,
)

HEALTH_DEADLINE_SECS = 60.0
SEND_DEADLINE_SECS = 90.0
RECEIVE_DEADLINE_SECS = 30.0

# Transient /direct/send outcomes worth retrying (see send_with_retry).
TRANSIENT_SEND_ERRORS = (
    RecipientUnknown,
    RecipientUndiscovered,
    RecipientKeyNotConverged,
    RecipientNeedsUpgrade,
    RecipientUpgradeRequired,
    X0xTimeout,
)
CONNECTED_OUTCOMES = frozenset({"Direct", "Coordinated", "AlreadyConnected"})


@dataclass
class Daemon:
    name: str
    api_port: int
    quic_port: int
    data_dir: Path
    log: Path
    process: subprocess.Popen[bytes]


def write_config(
    path: Path, name: str, data_dir: Path, api_port: int, quic_port: int, bootstrap: list[str]
) -> None:
    peers = ", ".join(f'"{peer}"' for peer in bootstrap)
    path.write_text(
        f'instance_name = "{name}"\n'
        # Hermetic either way (loopback bind, no bootstrap, mDNS off); the
        # testnet plane keeps these throwaway identities off the prod plane.
        'network_id = "x0x.testnet"\n'
        f'data_dir = "{data_dir}"\n'
        f'api_address = "127.0.0.1:{api_port}"\n'
        f'bind_address = "127.0.0.1:{quic_port}"\n'
        "mdns_enabled = false\n"
        "port_mapping_enabled = false\n"
        f"bootstrap_peers = [{peers}]\n"
        'log_level = "info"\n',
        encoding="utf-8",
    )


def start_daemon(
    x0xd: Path, work_dir: Path, name: str, api_port: int, quic_port: int, bootstrap: list[str]
) -> Daemon:
    data_dir = work_dir / name
    data_dir.mkdir(parents=True)
    config = work_dir / f"{name}.toml"
    write_config(config, name, data_dir, api_port, quic_port, bootstrap)
    log = work_dir / f"{name}.x0xd.log"
    # X0X_HOME keeps identity keys inside the work dir (fresh identities per
    # run); a named instance writes to a `.x0x-<name>` sibling of X0X_HOME.
    home = work_dir / f"{name}-home"
    home.mkdir()
    env = dict(os.environ, X0X_HOME=str(home))
    with log.open("wb") as sink:
        process = subprocess.Popen(
            [str(x0xd), "--config", str(config), "--no-hard-coded-bootstrap", "--skip-update-check"],
            stdout=sink,
            stderr=subprocess.STDOUT,
            env=env,
        )
    return Daemon(name, api_port, quic_port, data_dir, log, process)


def wait_healthy(daemon: Daemon) -> None:
    deadline = time.monotonic() + HEALTH_DEADLINE_SECS
    url = f"http://127.0.0.1:{daemon.api_port}/health"
    while time.monotonic() < deadline:
        if daemon.process.poll() is not None:
            raise X0xError(f"daemon {daemon.name} exited early (code {daemon.process.returncode})")
        try:
            with urllib.request.urlopen(url, timeout=2.0):
                return
        except (urllib.error.URLError, OSError):
            time.sleep(0.5)
    raise X0xError(f"daemon {daemon.name} did not answer /health within {HEALTH_DEADLINE_SECS}s")


def wait_token(daemon: Daemon) -> str:
    deadline = time.monotonic() + HEALTH_DEADLINE_SECS
    while time.monotonic() < deadline:
        try:
            token = read_api_token(daemon.data_dir)
        except OSError:
            token = ""
        if token:
            return token
        time.sleep(0.5)
    raise X0xError(f"daemon {daemon.name} wrote no api-token within {HEALTH_DEADLINE_SECS}s")


def send_with_retry(client: X0xClient, recipient: str, payload: bytes) -> str:
    """Send a durable DM, retrying the documented transient conditions.

    Right after a card import the sender's view of the recipient's KEM key
    and capability advert may not have converged, and discovery may still
    have a gap; those answer 404/409/503 codes that are transient. A client
    timeout is also retried: the same ``logical_id`` makes the resend the
    same request, not a duplicate. Everything else propagates.
    """
    deadline = time.monotonic() + SEND_DEADLINE_SECS
    attempt = 0
    while True:
        attempt += 1
        try:
            receipt = client.send_dm(recipient, payload, logical_id="python-client-demo:1")
            return receipt.path
        except TRANSIENT_SEND_ERRORS as exc:
            if time.monotonic() >= deadline:
                raise X0xError(f"send did not converge within {SEND_DEADLINE_SECS}s: {exc}") from exc
            print(f"  send attempt {attempt}: {exc} — retrying")
            time.sleep(2.0)


def tail(path: Path, lines: int = 25) -> str:
    try:
        content = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return "(no log)"
    return "\n".join(content[-lines:])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--x0xd",
        type=Path,
        default=Path("target/debug/x0xd"),
        help="path to the x0xd binary (default: target/debug/x0xd)",
    )
    parser.add_argument(
        "--api-port-a", type=int, default=24710, help="agent A API port (default: 24710)"
    )
    parser.add_argument(
        "--api-port-b", type=int, default=24711, help="agent B API port (default: 24711)"
    )
    parser.add_argument("--keep-work-dir", action="store_true", help="keep logs and data dirs")
    args = parser.parse_args()

    x0xd = args.x0xd.resolve()
    if not x0xd.is_file():
        print(f"x0xd not found at {x0xd} — run: cargo build --bin x0xd", file=sys.stderr)
        return 2

    work_dir = Path(tempfile.mkdtemp(prefix="x0x-python-client-demo."))
    print(f"work dir: {work_dir}")
    daemons: list[Daemon] = []
    rc = 1
    try:
        quic_a, quic_b = args.api_port_a + 100, args.api_port_b + 100
        a = start_daemon(x0xd, work_dir, "demo-a", args.api_port_a, quic_a, [])
        daemons.append(a)
        b = start_daemon(
            x0xd, work_dir, "demo-b", args.api_port_b, quic_b, [f"127.0.0.1:{quic_a}"]
        )
        daemons.append(b)

        for daemon in daemons:
            wait_healthy(daemon)
            print(f"{daemon.name}: healthy on 127.0.0.1:{daemon.api_port}")

        client_a = X0xClient(f"http://127.0.0.1:{a.api_port}", token=wait_token(a))
        client_b = X0xClient(f"http://127.0.0.1:{b.api_port}", token=wait_token(b))

        identity_a = client_a.agent()
        identity_b = client_b.agent()
        print(f"agent A: {identity_a.agent_id[:16]}…")
        print(f"agent B: {identity_b.agent_id[:16]}…")

        # Cards carry the KEM key and DM capabilities the sender needs.
        # include_local_addresses is for loopback test cards only.
        card_a = client_a.agent_card_link(include_local_addresses=True)
        card_b = client_b.agent_card_link(include_local_addresses=True)
        client_a.import_agent_card(card_b)
        client_b.import_agent_card(card_a)
        print("agent cards exchanged")

        # The gossip path still delivers without a live direct connection,
        # so a failed connect is reported, not fatal.
        try:
            outcome = str(client_a.connect(identity_b.agent_id).get("outcome", ""))
        except ApiError as exc:
            outcome = f"error: {exc.error}"
        except X0xTimeout:
            outcome = "client timeout"
        if outcome in CONNECTED_OUTCOMES:
            print(f"A → B direct connection: {outcome}")
        else:
            print(f"A → B connect not established ({outcome}) — gossip path will carry the DM")

        payload = b"hello from agent A via the typed Python client"
        with client_b.ws_direct() as subscription:
            first = subscription.recv(timeout=10.0)
            print(f"B subscribed: {first!r}")

            path = send_with_retry(client_a, identity_b.agent_id, payload)
            print(f"A sent the DM (durable receipt, path: {path})")

            deadline = time.monotonic() + RECEIVE_DEADLINE_SECS
            while time.monotonic() < deadline:
                try:
                    event = subscription.recv(timeout=max(0.1, deadline - time.monotonic()))
                except X0xTimeout:
                    break
                if isinstance(event, DirectMessage):
                    if event.payload != payload:
                        print(f"FAIL: payload mismatch: {event.payload!r}", file=sys.stderr)
                        return rc
                    if event.sender != identity_a.agent_id:
                        print(f"FAIL: unexpected sender {event.sender}", file=sys.stderr)
                        return rc
                    print(
                        f"B received the DM from {event.sender[:16]}… "
                        f"(verified={event.verified}): {event.payload.decode()!r}"
                    )
                    print("PASS")
                    rc = 0
                    return rc
            print(
                f"FAIL: no DM arrived on B's subscription within {RECEIVE_DEADLINE_SECS}s",
                file=sys.stderr,
            )
            return rc
    except (X0xError, OSError, TimeoutError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return rc
    finally:
        for daemon in daemons:
            daemon.process.terminate()
        time.sleep(1.0)
        for daemon in daemons:
            if daemon.process.poll() is None:
                daemon.process.kill()
            daemon.process.wait()
        if rc != 0:
            for daemon in daemons:
                print(f"--- {daemon.name} log tail ---\n{tail(daemon.log)}", file=sys.stderr)
        if args.keep_work_dir:
            print(f"work dir kept: {work_dir}")
        else:
            shutil.rmtree(work_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
