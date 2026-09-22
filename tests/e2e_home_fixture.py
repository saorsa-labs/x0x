#!/usr/bin/env python3
"""Provision an isolated synthetic-owner Home fixture and run #565 Home acceptance.

Every daemon, key and token belongs to a fresh /var/tmp/x0x-home-e2e-<uuid>
root. Existing x0x services and identities are never inspected or modified.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shlex
import subprocess
import uuid
from dataclasses import dataclass
from typing import Any, Callable

from e2e_tunnel import TunnelHandle, start_ssh_tunnel, stop_ssh_tunnel
from e2e_vps_groups import load_tokens
from e2e_vps_kv import Api, Evidence, active_provider_ids, enc, poll
from e2e_vps_private_kv import Scenario

ROOT_RE = re.compile(r"/var/tmp/x0x-home-e2e-[0-9a-f]{32}\Z")
SSH = ("ssh", "-o", "ControlMaster=no", "-o", "ControlPath=none",
       "-o", "BatchMode=yes", "-o", "ConnectTimeout=10")

START_SCRIPT = r'''set -eu
root=$1 marker=$2 binary=$3
[ "$(cat "$root/fixture.marker")" = "$marker" ]
[ ! -e "$root/daemon.pid" ]
sha256sum "$binary" | awk '{print $1}' > "$root/binary.sha256.tmp"
mv "$root/binary.sha256.tmp" "$root/binary.sha256"
setsid sh -c 'start=$(awk '"'"'{print $22}'"'"' /proc/$$/stat); printf "%s %s\n" "$$" "$start" > "$1/daemon.pid.tmp"; mv "$1/daemon.pid.tmp" "$1/daemon.pid"; exec "$2" --config "$1/config.toml"' sh "$root" "$binary" >>"$root/logs/daemon.log" 2>&1 </dev/null &
launcher=$!
i=0
while [ ! -s "$root/daemon.pid" ] && [ $i -lt 50 ]; do sleep .1; i=$((i+1)); done
[ -s "$root/daemon.pid" ]
set -- $(cat "$root/daemon.pid")
[ "$#" = 2 ] && [ "$1" = "$launcher" ]
kill -0 "$1"
'''

def stop_script(proc_root: str = "/proc", *, terminate: bool = True,
                kill_command: str = "/bin/kill", sleep_command: str = "/bin/sleep") -> str:
    proc, kill_bin, sleep_bin = map(shlex.quote, (proc_root, kill_command, sleep_command))
    finish = rf'''same_identity() {{
    [ -r "$proc/$pid/stat" ] && [ "$(awk '{{print $22}}' "$proc/$pid/stat")" = "$expected_start" ]
}}
wait_gone() {{
    i=0
    while same_identity && [ $i -lt 50 ]; do "$sleep_bin" .1; i=$((i+1)); done
    ! same_identity
}}
"$kill_bin" -TERM -- "-$pid"
if wait_gone; then rm -f "$root/daemon.pid"; exit 0; fi
# Re-check the recorded identity immediately before escalation. A replacement
# PID is never sent KILL; disappearance/change proves the owned process ended.
if ! same_identity; then rm -f "$root/daemon.pid"; exit 0; fi
"$kill_bin" -KILL -- "-$pid"
if wait_gone; then rm -f "$root/daemon.pid"; exit 0; fi
# Retain the receipt so cleanup is visibly incomplete and safely retryable.
exit 42''' if terminate else ":"
    return rf'''set -eu
root=$1 marker=$2 binary=$3
proc={proc}
kill_bin={kill_bin}
sleep_bin={sleep_bin}
[ "$(cat "$root/fixture.marker")" = "$marker" ]
[ -s "$root/daemon.pid" ] || exit 0
set -- $(cat "$root/daemon.pid")
[ "$#" = 2 ] || exit 41
pid=$1 expected_start=$2
case "$pid:$expected_start" in *[!0-9:]*) exit 41;; esac
if [ ! -r "$proc/$pid/cmdline" ]; then
    if [ -r "$proc/$pid/stat" ] && [ "$(awk '{{print $22}}' "$proc/$pid/stat")" = "$expected_start" ]; then
        exit 41
    fi
    rm -f "$root/daemon.pid"
    exit 0
fi
[ "$(awk '{{print $22}}' "$proc/$pid/stat")" = "$expected_start" ]
[ "$(sha256sum "$root/config.toml" | awk '{{print $1}}')" = "$(cat "$root/config.sha256")" ]
[ "$(sha256sum "$proc/$pid/exe" | awk '{{print $1}}')" = "$(cat "$root/binary.sha256")" ]
expected_argv=$(printf '%s\0%s\0%s\0' "$binary" --config "$root/config.toml" | sha256sum | awk '{{print $1}}')
actual_argv=$(sha256sum "$proc/$pid/cmdline" | awk '{{print $1}}')
[ "$actual_argv" = "$expected_argv" ]
pgid=$(awk '{{print $5}}' "$proc/$pid/stat")
[ "$pgid" = "$pid" ]
{finish}
'''




@dataclass(frozen=True)
class Node:
    label: str
    host: str
    api_port: int
    quic_port: int
    root: str


class Remote:
    """Bounded SSH calls whose errors never include stdout/stderr or stdin."""

    @staticmethod
    def command(script: str, args: list[str], *, input_bytes: bool) -> str:
        invocation = ["bash", "-c" if input_bytes else "-s", "--", *args]
        if input_bytes:
            invocation.insert(2, script)
        return shlex.join(invocation)

    def run(self, host: str, script: str, args: list[str], *, timeout: float = 20,
            input_bytes: bytes | None = None, capture: bool = False) -> bytes:
        remote_command = self.command(script, args, input_bytes=input_bytes is not None)
        payload = script.encode() if input_bytes is None else input_bytes
        result = subprocess.run([*SSH, f"root@{host}", remote_command], input=payload,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=timeout, check=False)
        if result.returncode != 0:
            raise RuntimeError(f"owned remote operation failed ({result.returncode})")
        return result.stdout if capture else b""


class SyntheticProcessCustody:
    def __init__(self, remote: Remote, binary: str, marker: str) -> None:
        if not os.path.isabs(binary):
            raise ValueError("--daemon-binary must be an absolute remote path")
        self.remote, self.binary, self.marker = remote, binary, marker
        self.started: dict[str, Node] = {}
        # Labels whose recorded daemon identity the stop script proved gone.
        self.offline: set[str] = set()

    @staticmethod
    def validate(node: Node) -> None:
        if not ROOT_RE.fullmatch(node.root):
            raise ValueError("fixture root must be a generated /var/tmp/x0x-home-e2e UUID path")
        if not (1024 <= node.api_port <= 65535 and 1024 <= node.quic_port <= 65535):
            raise ValueError("fixture ports must be unprivileged")

    def prepare(self, node: Node, config: bytes) -> None:
        self.validate(node)
        script = r'''set -eu
root=$1 marker=$2
[ ! -e "$root" ]
umask 077
mkdir -p "$root/identity" "$root/data" "$root/logs"
printf '%s\n' "$marker" > "$root/fixture.marker"
'''
        self.remote.run(node.host, script, [node.root, self.marker])
        self.remote.run(node.host, "set -eu; umask 077; cat >\"$1/config.toml.tmp\"; mv \"$1/config.toml.tmp\" \"$1/config.toml\"",
                        [node.root], input_bytes=config)
        self.remote.run(node.host, r'''set -eu
root=$1 marker=$2
[ "$(cat "$root/fixture.marker")" = "$marker" ]
sha256sum "$root/config.toml" | awk '{print $1}' > "$root/config.sha256.tmp"
mv "$root/config.sha256.tmp" "$root/config.sha256"
''', [node.root, self.marker])

    def create_owner_key(self, node: Node, cli_binary: str) -> None:
        if not os.path.isabs(cli_binary):
            raise ValueError("--cli-binary must be an absolute remote path")
        script = r'''set -eu
root=$1 marker=$2 cli=$3
[ "$(cat "$root/fixture.marker")" = "$marker" ]
"$cli" user-id create "$root/identity/user.key" >/dev/null
'''
        self.remote.run(node.host, script, [node.root, self.marker, cli_binary], timeout=30)

    def start(self, node: Node) -> None:
        self.validate(node)
        # The child writes its own durable pid/pgid receipt before exec. If SSH
        # breaks after spawn, finally can still identify and reap this process.
        try:
            self.offline.discard(node.label)
            self.remote.run(node.host, START_SCRIPT,
                            [node.root, self.marker, self.binary], timeout=15)
        finally:
            # Record the obligation even when SSH failed after the remote spawn.
            self.started[node.label] = node

    def _stop(self, node: Node) -> None:
        self.remote.run(node.host, stop_script(),
                        [node.root, self.marker, self.binary], timeout=15)
        self.offline.add(node.label)

    def stop(self, label: str) -> None:
        node = self.started.get(label)
        if node is None:
            raise RuntimeError("cannot stop an unowned fixture process")
        self._stop(node)

    def restart(self, label: str) -> None:
        node = self.started.get(label)
        if node is None:
            raise RuntimeError("cannot restart an unowned fixture process")
        self._stop(node)
        self.start(node)

    def write_certificate(self, node: Node, certificate_b64: str) -> None:
        try:
            certificate = base64.b64decode(certificate_b64, validate=True)
        except ValueError as error:
            raise RuntimeError("owner returned an invalid certificate encoding") from error
        if not certificate:
            raise RuntimeError("owner returned an empty certificate")
        self.remote.run(node.host,
                        'set -eu; umask 077; cat >"$1/identity/agent.cert.tmp"; mv "$1/identity/agent.cert.tmp" "$1/identity/agent.cert"',
                        [node.root], input_bytes=certificate)

    def key_fingerprint(self, node: Node) -> str | None:
        """sha256 of the node's fixture user.key, or None; the key never leaves the host."""
        self.validate(node)
        raw = self.remote.run(node.host, r'''set -eu
root=$1 marker=$2
[ "$(cat "$root/fixture.marker")" = "$marker" ]
if [ -e "$root/identity/user.key" ]; then sha256sum "$root/identity/user.key" | awk '{print $1}'; else echo none; fi
''', [node.root, self.marker], capture=True)
        value = raw.decode().strip()
        if value == "none":
            return None
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            raise RuntimeError("invalid synthetic key fingerprint receipt")
        return value

    def copy_owner_key(self, source: Node, target: Node) -> str:
        """Install the fixture-generated owner key on a stopped same-owner device.

        The bytes travel only over SSH stdin/stdout; only their sha256 is returned.
        """
        self.validate(source); self.validate(target)
        if source.label == target.label:
            raise ValueError("owner key copy needs a distinct target device")
        if target.label in self.started and target.label not in self.offline:
            raise RuntimeError("owner key may only be installed on a stopped fixture device")
        key = self.remote.run(source.host, r'''set -eu
root=$1 marker=$2
[ "$(cat "$root/fixture.marker")" = "$marker" ]
[ -s "$root/identity/user.key" ]
cat "$root/identity/user.key"
''', [source.root, self.marker], capture=True)
        if not key:
            raise RuntimeError("synthetic owner key unavailable")
        fingerprint = hashlib.sha256(key).hexdigest()
        try:
            self.remote.run(target.host, r'''set -eu
root=$1 marker=$2
[ "$(cat "$root/fixture.marker")" = "$marker" ]
[ ! -e "$root/identity/user.key" ]
umask 077
cat >"$root/identity/user.key.tmp"
mv "$root/identity/user.key.tmp" "$root/identity/user.key"
''', [target.root, self.marker], input_bytes=key)
        finally:
            del key
        if self.key_fingerprint(target) != fingerprint:
            raise RuntimeError("synthetic owner key copy did not verify")
        return fingerprint

    def token(self, node: Node) -> str:
        raw = self.remote.run(node.host, r'''set -eu
root=$1 marker=$2
[ "$(cat "$root/fixture.marker")" = "$marker" ]
[ -s "$root/data/api-token" ]
cat "$root/data/api-token"
''', [node.root, self.marker], capture=True)
        token = raw.decode().strip()
        if not token:
            raise RuntimeError("synthetic daemon token unavailable")
        return token

    def hashes(self, node: Node) -> tuple[str, str]:
        raw = self.remote.run(node.host, r'''set -eu
root=$1 marker=$2
[ "$(cat "$root/fixture.marker")" = "$marker" ]
printf '%s %s\n' "$(cat "$root/config.sha256")" "$(cat "$root/binary.sha256")"
''', [node.root, self.marker], capture=True)
        fields = raw.decode().strip().split()
        if len(fields) != 2 or any(not re.fullmatch(r"[0-9a-f]{64}", value) for value in fields):
            raise RuntimeError("invalid synthetic custody hash receipt")
        return fields[0], fields[1]

    def restore(self) -> list[str]:
        errors = []
        for label, node in reversed(list(self.started.items())):
            try:
                self._stop(node)
            except Exception as error:
                errors.append(f"cleanup {label}: {type(error).__name__}")
        return errors


def config_bytes(node: Node, plane: str, bootstrap: str | None) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", plane):
        raise ValueError("invalid isolated network id")
    peers = "[]" if bootstrap is None else f'["{bootstrap}"]'
    return (f'instance_name = "home-{node.label}"\n'
            f'data_dir = "{node.root}/data"\nidentity_dir = "{node.root}/identity"\n'
            f'bind_address = "0.0.0.0:{node.quic_port}"\n'
            f'api_address = "127.0.0.1:{node.api_port}"\n'
            f'bootstrap_peers = {peers}\nnetwork_id = "{plane}"\n'
            'mdns_enabled = false\nport_mapping_enabled = false\n'
            'rendezvous_enabled = false\nlog_level = "info"\n').encode()


def run_fixture(args: argparse.Namespace, remote: Remote, evidence: Evidence,
                resources: dict[str, Any]) -> bool:
    run_id = uuid.uuid4().hex
    plane, root = f"x0x.home.e2e.{run_id}", f"/var/tmp/x0x-home-e2e-{run_id}"
    tokens = load_tokens(args.hosts_file, var_prefix="TEST")
    missing = [label for label in args.nodes if label not in tokens]
    if missing: raise RuntimeError("fixture host mapping missing")
    hosts = [tokens[label][0] for label in args.nodes]
    if len(set(hosts)) != len(hosts): raise RuntimeError("fixture requires distinct hosts")
    nodes = {label: Node(label, host, args.api_port_base + i, args.quic_port_base + i, root)
             for i, (label, host) in enumerate(zip(args.nodes, hosts))}
    custody = SyntheticProcessCustody(remote, args.daemon_binary, run_id)
    tunnels: list[TunnelHandle] = []
    resources["custody"], resources["tunnels"] = custody, tunnels
    clients: dict[str, Api] = {}
    owner = args.nodes[0]
    bootstrap = f"{nodes[owner].host}:{nodes[owner].quic_port}"
    for label, node in nodes.items():
        custody.prepare(node, config_bytes(node, plane, None if label == owner else bootstrap))
    custody.create_owner_key(nodes[owner], args.cli_binary)
    for label, node in nodes.items():
        custody.start(node)
        tunnel = start_ssh_tunnel(node.host, args.local_port_base + len(tunnels), remote_port=node.api_port)
        tunnels.append(tunnel)
        clients[label] = Api(f"http://127.0.0.1:{tunnel.local_port}", custody.token(node))
    receipts = {label: custody.hashes(node) for label, node in nodes.items()}
    binary_hashes = {receipt[1] for receipt in receipts.values()}
    evidence.check("fixture custody receipt is reproducible", len(binary_hashes) == 1,
                   run_id=run_id, network_id=plane,
                   binary_sha256=next(iter(binary_hashes), None),
                   config_sha256={label: receipt[0] for label, receipt in receipts.items()})
    resources["manifest"] = {
        "run_id": run_id, "network_id": plane,
        "binary_sha256": next(iter(binary_hashes), None),
        "config_sha256": {label: receipt[0] for label, receipt in receipts.items()},
    }
    owner_api = clients[owner]
    home_status, home = owner_api.request("GET", "/home")
    evidence.check("synthetic owner provisions verified local Home", home_status == 200
                   and home.get("state") == "local"
                   and (home.get("primary_agent") or {}).get("verified") is True,
                   status=home_status, state=home.get("state"))
    owner_id = home.get("owner_user_id")
    evidence.check("synthetic Home owner id", isinstance(owner_id, str) and len(owner_id) == 64)

    # Home admission needs each device's own user-identity announcement, which
    # requires the owner key on that device; every Home device is therefore a
    # same-owner device that is ALSO issued its own owner certificate.
    owner_key_sha = custody.key_fingerprint(nodes[owner])
    evidence.check("synthetic owner key fingerprint recorded", owner_key_sha is not None,
                   owner_key_sha256=owner_key_sha)

    def certify_same_owner_device(label: str) -> None:
        card_status, card = clients[label].request("GET", "/agent/card")
        public_key = card.get("agent_public_key")
        evidence.check(f"{label} signed card exposes public key", card_status == 200
                       and isinstance(public_key, str) and bool(public_key), status=card_status)
        custody.stop(label)
        issue_status, issued = owner_api.request("POST", "/owner/agents/issue",
                                                 {"agent_public_key": public_key, "mode": "acp",
                                                  "label": f"home-e2e-{label}"})
        certificate = (issued.get("certificate") or {}).get("storage_b64")
        evidence.check(f"owner certifies {label}", issue_status == 200 and isinstance(certificate, str),
                       status=issue_status)
        custody.write_certificate(nodes[label], certificate)
        fingerprint = custody.copy_owner_key(nodes[owner], nodes[label])
        evidence.check(f"{label} holds the synthetic owner key", fingerprint == owner_key_sha,
                       owner_key_sha256=fingerprint)
        custody.start(nodes[label])
        poll(f"{label} restarts certified", args.poll_timeout,
             lambda label=label: clients[label].request("GET", "/health"),
             lambda result: result[0] == 200 and result[1].get("ok") is True)
        announce_status, _ = clients[label].request("POST", "/announce",
                                                    {"include_user_identity": True, "human_consent": True})
        evidence.check(f"{label} publishes owner certificate", announce_status in (200, 201), status=announce_status)

    for label in args.nodes[1:4]:
        certify_same_owner_device(label)

    writer, late, revoked, outsider = args.nodes[1:5]
    evidence.check("outsider holds no owner key before denial",
                   custody.key_fingerprint(nodes[outsider]) is None)
    invite_status, invite_body = owner_api.request("POST", "/home/seat", {"agent_id": clients[outsider].agent_id()})
    evidence.check("owner may address uncertified outsider", invite_status == 200, status=invite_status)
    denied_status, _ = clients[outsider].request("POST", "/groups/join", {
        "invite": invite_body.get("invite"), "mode": "home", "expected_owner_user_id": owner_id})
    evidence.check("uncertified outsider is refused Home", denied_status == 403, status=denied_status)

    # Only after the refusal is proven does the fifth device become the second
    # owner-key device: it is the promoted Admin that admits the late device
    # while the original owner device is offline.
    admin = outsider
    certify_same_owner_device(admin)

    scenario = Scenario(clients, evidence, args.poll_timeout)
    stopped: set[str] = set()
    def stop_owner() -> None: custody.stop(owner); stopped.add(owner)
    def stop_admin() -> None: custody.stop(admin); stopped.add(admin)
    def is_offline(label: str) -> bool:
        # True only after custody's stop script proved the recorded process gone.
        return label in custody.offline
    def restart_writer(gid: str, expected: set[str]) -> None:
        status, body = clients[writer].request("GET", f"/groups/{enc(gid)}/members")
        active = active_provider_ids(status, body)
        evidence.check("exact synthetic retained providers", active == expected,
                       active_count=len(active), expected_count=len(expected))
        evidence.check("owner and admin devices stopped before writer restart",
                       is_offline(owner) and is_offline(admin))
        custody.stop(late); stopped.add(late); custody.restart(writer)
        poll("writer health after isolated restart", 60,
             lambda: clients[writer].request("GET", "/health"),
             lambda result: result[0] == 200 and result[1].get("ok") is True)
    scenario.run_home(owner, writer, late, admin, revoked, stop_owner, stop_admin, is_offline, restart_writer)
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--network", choices=["synthetic-home"], required=True)
    parser.add_argument("--hosts-file", required=True)
    parser.add_argument("--nodes", nargs=5, required=True,
                        metavar=("OWNER", "WRITER", "LATE", "REVOKED", "OUTSIDER"))
    parser.add_argument("--daemon-binary", required=True)
    parser.add_argument("--cli-binary", required=True)
    parser.add_argument("--api-port-base", type=int, default=14600)
    parser.add_argument("--quic-port-base", type=int, default=7483)
    parser.add_argument("--local-port-base", type=int, default=24700)
    parser.add_argument("--poll-timeout", type=float, default=120)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    if len(set(args.nodes)) != 5: parser.error("five distinct node labels are required")
    evidence, resources, succeeded = Evidence(), {}, False
    try:
        succeeded = run_fixture(args, Remote(), evidence, resources)
    except Exception as error:
        evidence.assertions.append({"label": f"fixture {type(error).__name__}", "passed": False})
    finally:
        custody = resources.get("custody")
        if custody is not None:
            for error in custody.restore(): evidence.assertions.append({"label": error, "passed": False}); succeeded = False
        for tunnel in resources.get("tunnels", []):
            try: stop_ssh_tunnel(tunnel)
            except Exception as error: evidence.assertions.append({"label": f"tunnel cleanup {type(error).__name__}", "passed": False}); succeeded = False
        try:
            with open(args.report, "w", encoding="utf-8") as output:
                json.dump({"scenario": "synthetic-home", "custody": resources.get("manifest"),
                           "stores": evidence.stores, "polls": evidence.polls,
                           "assertions": evidence.assertions}, output, indent=2)
        except Exception: succeeded = False
    return 0 if succeeded and all(row["passed"] for row in evidence.assertions) else 1


if __name__ == "__main__": raise SystemExit(main())
