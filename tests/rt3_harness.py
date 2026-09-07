#!/usr/bin/env python3
"""#491 RT3 real-process diagnostic. Execution requires the namespace wrapper."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.request


STAGES = {
    "prerequisites", "identity", "fixture_start", "fixture_identity",
    "fixture_announce", "fixture_create", "fixture_join", "fixture_converge",
    "fixture_witness", "fixture_shutdown", "split", "lane_compare",
    "positive_start", "positive_precheck", "positive_hydrate", "positive_seal",
    "positive_shutdown", "negative_start", "negative_precheck", "negative_hydrate",
    "negative_seal", "negative_shutdown",
    "complete",
}
ERROR_CLASSES = {
    "none", "assertion", "filesystem", "http", "process", "timeout",
    "unexpected",
}
COUNTER_KEYS = {
    "positive_hydration_state_before",
    "positive_hydration_state_after",
    "positive_hydration_roster_before",
    "positive_hydration_roster_response",
    "positive_hydration_roster_after",
    "positive_seal_state_before",
    "positive_seal_state_commit",
    "positive_seal_state_after",
    "positive_seal_roster_before",
    "positive_seal_roster_after",
    "negative_hydration_state_before",
    "negative_hydration_state_after",
    "negative_hydration_roster_before",
    "negative_hydration_roster_after",
    "negative_seal_state_before",
    "negative_seal_state_after",
    "negative_seal_roster_before",
    "negative_seal_roster_after",
}


def loopback_api_base(advertisement: str) -> str | None:
    host, separator, port_text = advertisement.rpartition(":")
    if (
        separator != ":"
        or host != "127.0.0.1"
        or not port_text.isascii()
        or not port_text.isdigit()
    ):
        return None
    port = int(port_text)
    if not 1 <= port <= 65535:
        return None
    return f"http://{host}:{port}"


def active_agent_ids(group_body: dict[str, object]) -> set[str]:
    members = group_body.get("members")
    if not isinstance(members, list):
        return set()
    return {
        str(member.get("agent_id"))
        for member in members
        if isinstance(member, dict)
        and member.get("state") == "active"
        and isinstance(member.get("agent_id"), str)
    }


def positive_observation(
    before_state: dict[str, object],
    before_group: dict[str, object],
    status: int,
    seal: dict[str, object],
    after_state: dict[str, object],
    after_group: dict[str, object],
) -> dict[str, bool]:
    revision = before_state.get("state_revision")
    commit = seal.get("commit")
    incremented = (
        type(revision) is int
        and isinstance(commit, dict)
        and type(commit.get("revision")) is int
        and commit.get("revision") == revision + 1
        and type(after_state.get("state_revision")) is int
        and after_state.get("state_revision") == revision + 1
    )
    return {
        "status": status == 200 and seal.get("ok") is True,
        "state_revision_increment": incremented,
        "roster_revision_unchanged": (
            type(before_group.get("roster_revision")) is int
            and type(after_group.get("roster_revision")) is int
            and after_group.get("roster_revision") == before_group.get("roster_revision")
        ),
        "roster_unchanged": (
            after_state.get("roster_root") == before_state.get("roster_root")
        ),
        "no_eviction": seal.get("evicted") == [],
    }


def positive_hydration_observation(
    before_state: dict[str, object],
    before_group: dict[str, object],
    status: int,
    mutation: dict[str, object],
    after_state: dict[str, object],
    after_group: dict[str, object],
) -> dict[str, bool]:
    state_revision = before_state.get("state_revision")
    roster_revision = before_group.get("roster_revision")
    return {
        "status": status == 200 and mutation.get("ok") is True,
        "state_revision_increment": type(state_revision) is int
        and type(after_state.get("state_revision")) is int
        and after_state.get("state_revision") == state_revision + 1,
        "roster_revision_increment": type(roster_revision) is int
        and type(after_group.get("roster_revision")) is int
        and after_group.get("roster_revision") == roster_revision + 1,
        "response_revision_matches_roster": (
            type(mutation.get("revision")) is int
            and mutation.get("revision") == after_group.get("roster_revision")
        ),
        "roster_unchanged": (
            after_state.get("roster_root") == before_state.get("roster_root")
        ),
        "description_updated": (
            mutation.get("description") == "rt3-hydration-probe"
            and after_group.get("description") == "rt3-hydration-probe"
        ),
    }


def negative_hydration_observation(
    before_state: dict[str, object],
    before_group: dict[str, object],
    status: int,
    mutation: dict[str, object],
    after_state: dict[str, object],
    after_group: dict[str, object],
) -> dict[str, bool]:
    error = mutation.get("error")
    return {
        "status": status == 500,
        "pending_class": isinstance(error, str)
        and "pending certificate resolution" in error,
        "state_unchanged": all(
            after_state.get(key) == before_state.get(key)
            for key in (
                "state_revision",
                "state_hash",
                "prev_state_hash",
                "security_binding",
                "withdrawn",
                "roster_root",
                "policy_hash",
                "public_meta_hash",
            )
        ),
        "roster_revision_unchanged": (
            type(before_group.get("roster_revision")) is int
            and type(after_group.get("roster_revision")) is int
            and after_group.get("roster_revision") == before_group.get("roster_revision")
        ),
        "description_unchanged": (
            after_group.get("description") == before_group.get("description")
        ),
    }


def negative_observation(
    before_state: dict[str, object],
    before_group: dict[str, object],
    status: int,
    seal: dict[str, object],
    after_state: dict[str, object],
    after_group: dict[str, object],
) -> dict[str, bool]:
    error = seal.get("error")
    return {
        "status": status == 409,
        "pending_class": isinstance(error, str)
        and error.startswith(
            "owner-certified group has members pending certificate resolution"
        ),
        "state_unchanged": all(
            after_state.get(key) == before_state.get(key)
            for key in (
                "state_revision",
                "state_hash",
                "prev_state_hash",
                "security_binding",
                "withdrawn",
                "roster_root",
                "policy_hash",
                "public_meta_hash",
            )
        ),
        "roster_revision_unchanged": (
            type(before_group.get("roster_revision")) is int
            and type(after_group.get("roster_revision")) is int
            and after_group.get("roster_revision") == before_group.get("roster_revision")
        ),
    }


def owner_join_request(invite: str, owner_user: str) -> dict[str, str]:
    return {
        "invite": invite,
        "display_name": "rt3-device",
        "mode": "home",
        "expected_owner_user_id": owner_user,
    }


def children_accepted(children: list[dict[str, object]]) -> bool:
    expected = {"owner", "device", "positive", "negative"}
    return (
        len(children) == len(expected)
        and {child.get("name") for child in children} == expected
        and all(
            child.get("shutdown_status") == 200
            and child.get("escalation") == "none"
            and child.get("exit_status") == 0
            and child.get("reaped") is True
            for child in children
        )
    )


class DiagnosticFailure(RuntimeError):
    def __init__(self, error_class: str, message: str):
        super().__init__(message)
        if error_class not in ERROR_CLASSES:
            raise ValueError("unclosed diagnostic error class")
        self.error_class = error_class


class Child:
    def __init__(self, name: str, process: subprocess.Popen[bytes], log_handle):
        self.name = name
        self.process = process
        self.log_handle = log_handle
        self.shutdown_status: int | None = None
        self.escalation = "none"
        self.exit_status: int | None = None

    def receipt(self) -> dict[str, object]:
        return {
            "name": self.name,
            "shutdown_status": self.shutdown_status,
            "escalation": self.escalation,
            "exit_status": self.exit_status,
            "reaped": self.exit_status is not None,
        }


class Harness:
    def __init__(self, arguments: argparse.Namespace):
        self.arguments = arguments
        self.artifacts = Path(arguments.artifacts).resolve()
        self.root = Path("/tmp/rt3-hydration")
        self.stage = "prerequisites"
        self.error_class = "none"
        self.error_line = 0
        self.children: dict[str, Child] = {}
        self.api: dict[str, tuple[str, str]] = {}
        self.observations: dict[str, object] = {
            "same_owner": False,
            "distinct_agents": False,
            "distinct_machines": False,
            "fixture_converged": False,
            "cache_witness": False,
            "lane_difference_cache_only": False,
            "lane_identity_preserved": False,
            "positive_hydration_status": None,
            "positive_hydration_state_revision_increment": False,
            "positive_hydration_roster_revision_increment": False,
            "positive_hydration_response_revision_matches_roster": False,
            "positive_hydration_roster_unchanged": False,
            "positive_description_updated": False,
            "positive_seal_status": None,
            "positive_seal_state_revision_increment": False,
            "positive_seal_roster_revision_unchanged": False,
            "positive_seal_roster_unchanged": False,
            "positive_no_eviction": False,
            "negative_hydration_status": None,
            "negative_hydration_pending_class": False,
            "negative_hydration_state_unchanged": False,
            "negative_hydration_roster_revision_unchanged": False,
            "negative_hydration_description_unchanged": False,
            "negative_seal_status": None,
            "negative_seal_pending_class": False,
            "negative_seal_state_unchanged": False,
            "negative_seal_roster_revision_unchanged": False,
            "negative_sidecar_unchanged": False,
        }
        self.counters: dict[str, int | None] = {key: None for key in COUNTER_KEYS}

    def fail(self, error_class: str, message: str) -> None:
        raise DiagnosticFailure(error_class, message)

    def require(self, condition: bool, message: str) -> None:
        if not condition:
            self.fail("assertion", message)

    def set_stage(self, stage: str) -> None:
        if stage not in STAGES:
            self.fail("unexpected", "attempted unknown stage")
        self.stage = stage

    def record_result(
        self,
        status_key: str,
        status: int,
        predicates: dict[str, bool],
    ) -> None:
        self.observations[status_key] = status
        for key, value in predicates.items():
            self.observations[key] = value

    def record_counters(self, values: dict[str, object]) -> None:
        for key, value in values.items():
            if key not in self.counters:
                self.fail("unexpected", "attempted unknown counter")
            self.counters[key] = value if type(value) is int and value >= 0 else None

    def run_checked(
        self,
        argv: list[str],
        *,
        stdout: Path | None = None,
        timeout: int = 30,
    ) -> subprocess.CompletedProcess[bytes]:
        output = subprocess.PIPE
        handle = None
        if stdout is not None:
            handle = stdout.open("wb")
            output = handle
        try:
            result = subprocess.run(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.STDOUT,
                timeout=timeout,
                check=False,
                close_fds=True,
            )
        except subprocess.TimeoutExpired as error:
            self.fail("timeout", f"subprocess deadline: {argv[0]}")
            raise AssertionError from error
        finally:
            if handle is not None:
                handle.close()
        if result.returncode != 0:
            self.fail("process", f"subprocess failed: {argv[0]}")
        return result

    def wait_cache_witness(self, argv: list[str], output: Path) -> None:
        deadline = time.monotonic() + 30
        with output.open("wb") as handle:
            while time.monotonic() < deadline:
                try:
                    result = subprocess.run(
                        argv,
                        stdin=subprocess.DEVNULL,
                        stdout=handle,
                        stderr=subprocess.STDOUT,
                        timeout=5,
                        check=False,
                        close_fds=True,
                    )
                except subprocess.TimeoutExpired:
                    result = None
                if result is not None and result.returncode == 0:
                    return
                time.sleep(0.25)
        self.fail("timeout", "verified remote certificate cache witness deadline")

    @staticmethod
    def reserve_udp_port() -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(("127.0.0.1", 0))
            return int(sock.getsockname()[1])

    @staticmethod
    def write_config(
        path: Path,
        identity: Path,
        data: Path,
        bind_port: int,
        peers: list[str],
    ) -> None:
        peer_json = json.dumps(peers)
        text = (
            f'identity_dir = "{identity}"\n'
            f'data_dir = "{data}"\n'
            f'bind_address = "127.0.0.1:{bind_port}"\n'
            'api_address = "127.0.0.1:0"\n'
            f"bootstrap_peers = {peer_json}\n"
            "port_mapping_enabled = false\n"
            'network_id = "x0x.rt3"\n'
            'log_level = "info"\n'
            'log_format = "json"\n'
            "[update]\n"
            "enabled = false\n"
        )
        path.write_text(text)
        path.chmod(0o600)

    def start_child(
        self,
        name: str,
        config: Path,
        data: Path,
    ) -> tuple[str, str]:
        log_path = self.artifacts / f"{name}.log"
        log_handle = log_path.open("wb")
        process = subprocess.Popen(
            [
                self.arguments.x0xd,
                "--config",
                str(config),
                "--skip-update-check",
                "--no-hard-coded-bootstrap",
                "--no-port-mapping",
            ],
            stdin=subprocess.DEVNULL,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            close_fds=True,
            start_new_session=True,
        )
        child = Child(name, process, log_handle)
        self.children[name] = child
        deadline = time.monotonic() + 45
        port_path = data / "api.port"
        token_path = data / "api-token"
        while time.monotonic() < deadline:
            if process.poll() is not None:
                self.stop_child(name, attempt_shutdown=False)
                self.fail("process", f"{name} exited before health")
            if port_path.is_file() and token_path.is_file():
                base = loopback_api_base(port_path.read_text().strip())
                token = token_path.read_text().strip()
                if base is not None and token:
                    try:
                        status, body = self.http("GET", base, token, "/health")
                        if status == 200 and body.get("ok") is True:
                            self.api[name] = (base, token)
                            return base, token
                    except DiagnosticFailure:
                        pass
            time.sleep(0.25)
        self.stop_child(name, attempt_shutdown=False)
        self.fail("timeout", f"{name} health deadline")
        raise AssertionError

    def http(
        self,
        method: str,
        base: str,
        token: str,
        path: str,
        body: dict[str, object] | None = None,
        timeout: float = 4,
    ) -> tuple[int, dict[str, object]]:
        data = None if body is None else json.dumps(body).encode()
        headers = {"Authorization": f"Bearer {token}"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            base + path, data=data, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                status = response.status
                raw = response.read()
        except urllib.error.HTTPError as error:
            status = error.code
            raw = error.read()
        except (TimeoutError, urllib.error.URLError) as error:
            raise DiagnosticFailure("http", "HTTP transport failure") from error
        try:
            parsed = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise DiagnosticFailure("http", "HTTP response is not JSON") from error
        if not isinstance(parsed, dict):
            self.fail("http", "HTTP response is not an object")
        return status, parsed

    def stop_child(self, name: str, *, attempt_shutdown: bool = True) -> None:
        child = self.children[name]
        process = child.process
        if process.poll() is None and attempt_shutdown and name in self.api:
            base, token = self.api[name]
            try:
                status, _ = self.http("POST", base, token, "/shutdown", timeout=3)
                child.shutdown_status = status
            except DiagnosticFailure:
                child.shutdown_status = 0
        if process.poll() is None:
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                child.escalation = "term"
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.escalation = "kill"
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
        child.exit_status = process.returncode
        child.log_handle.close()
        self.api.pop(name, None)
        if attempt_shutdown:
            self.require(child.shutdown_status == 200, f"{name} shutdown status")
            self.require(child.exit_status == 0, f"{name} clean exit")
            self.require(child.escalation == "none", f"{name} required escalation")

    def cleanup(self) -> bool:
        clean = True
        for name, child in list(self.children.items()):
            if child.exit_status is not None:
                continue
            try:
                self.stop_child(name, attempt_shutdown=False)
            except Exception:
                clean = False
        return clean and all(child.exit_status is not None for child in self.children.values())

    def poll_convergence(
        self, group: str, expected_agents: set[str]
    ) -> tuple[dict[str, object], dict[str, object]]:
        deadline = time.monotonic() + 120
        last: tuple[dict[str, object], dict[str, object]] | None = None
        while time.monotonic() < deadline:
            rows = []
            complete = True
            for name in ("owner", "device"):
                base, token = self.api[name]
                status, body = self.http("GET", base, token, f"/groups/{group}")
                if status != 200:
                    complete = False
                rows.append(body)
            last = (rows[0], rows[1])
            if complete:
                member_sets = [active_agent_ids(row) for row in rows]
                if (
                    all(row.get("membership_state") == "active" for row in rows)
                    and member_sets == [expected_agents, expected_agents]
                ):
                    owner_state = self.http(
                        "GET", *self.api["owner"], f"/groups/{group}/state"
                    )
                    device_state = self.http(
                        "GET", *self.api["device"], f"/groups/{group}/state"
                    )
                    if (
                        owner_state[0] == 200
                        and device_state[0] == 200
                        and owner_state[1].get("state_revision")
                        == device_state[1].get("state_revision")
                        and owner_state[1].get("roster_root")
                        == device_state[1].get("roster_root")
                    ):
                        return last
            time.sleep(0.5)
        self.fail("timeout", "two-device group convergence deadline")
        raise AssertionError

    @staticmethod
    def regular_manifest(root: Path) -> dict[str, str]:
        manifest: dict[str, str] = {}
        for path in sorted(root.rglob("*")):
            relative = str(path.relative_to(root))
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode):
                raise DiagnosticFailure("filesystem", "symlink in persisted fixture")
            if stat.S_ISREG(mode):
                manifest[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
            elif not stat.S_ISDIR(mode):
                raise DiagnosticFailure("filesystem", "non-regular persisted fixture")
        return manifest

    def run(self) -> None:
        self.artifacts.mkdir(parents=True, exist_ok=True)
        self.require(self.artifacts.is_absolute(), "artifacts path must be absolute")
        self.require(not self.artifacts.is_relative_to("/tmp"), "artifacts must survive namespace")
        if self.root.exists():
            shutil.rmtree(self.root)
        self.root.mkdir(mode=0o700)
        for executable in (
            self.arguments.x0xd,
            self.arguments.x0x,
            self.arguments.fixture,
        ):
            self.require(Path(executable).is_file(), "required executable missing")
            self.require(os.access(executable, os.X_OK), "required executable is not executable")

        self.set_stage("identity")
        owner_identity = self.root / "owner-identity"
        device_identity = self.root / "device-identity"
        owner_data = self.root / "owner-data"
        device_data = self.root / "device-data"
        configs = self.root / "configs"
        for directory in (owner_identity, device_identity, owner_data, device_data, configs):
            directory.mkdir(mode=0o700)
        owner_key = owner_identity / "user.key"
        self.run_checked(
            [self.arguments.x0x, "user-id", "create", str(owner_key)],
            stdout=self.artifacts / "user-id-create.log",
        )
        self.require(owner_key.is_file(), "user-id create did not write key")
        owner_key.chmod(0o600)
        device_key = device_identity / "user.key"
        shutil.copyfile(owner_key, device_key)
        device_key.chmod(0o600)
        self.require(owner_key.read_bytes() == device_key.read_bytes(), "owner key copy mismatch")

        owner_quic = self.reserve_udp_port()
        device_quic = self.reserve_udp_port()
        self.require(owner_quic != device_quic, "QUIC port collision")
        owner_config = configs / "owner.toml"
        device_config = configs / "device.toml"
        self.write_config(
            owner_config,
            owner_identity,
            owner_data,
            owner_quic,
            [f"127.0.0.1:{device_quic}"],
        )
        self.write_config(
            device_config,
            device_identity,
            device_data,
            device_quic,
            [f"127.0.0.1:{owner_quic}"],
        )

        self.set_stage("fixture_start")
        self.start_child("owner", owner_config, owner_data)
        self.start_child("device", device_config, device_data)

        self.set_stage("fixture_identity")
        agents: dict[str, dict[str, object]] = {}
        for name in ("owner", "device"):
            status, body = self.http("GET", *self.api[name], "/agent")
            self.require(status == 200 and body.get("ok") is True, f"{name} agent response")
            agents[name] = body
        owner_user = agents["owner"].get("user_id")
        device_user = agents["device"].get("user_id")
        owner_agent = agents["owner"].get("agent_id")
        device_agent = agents["device"].get("agent_id")
        owner_machine = agents["owner"].get("machine_id")
        device_machine = agents["device"].get("machine_id")
        self.require(isinstance(owner_user, str) and len(owner_user) == 64, "owner user id")
        self.require(owner_user == device_user, "devices do not share owner")
        self.require(
            isinstance(owner_agent, str)
            and isinstance(device_agent, str)
            and owner_agent != device_agent,
            "agent identities are not distinct",
        )
        self.require(
            isinstance(owner_machine, str)
            and isinstance(device_machine, str)
            and owner_machine != device_machine,
            "machine identities are not distinct",
        )
        self.observations["same_owner"] = True
        self.observations["distinct_agents"] = True
        self.observations["distinct_machines"] = True

        self.set_stage("fixture_announce")
        announce = {"include_user_identity": True, "human_consent": True}
        for name in ("owner", "device"):
            status, body = self.http("POST", *self.api[name], "/announce", announce)
            self.require(status == 200 and body.get("ok") is True, f"{name} announce")

        self.set_stage("fixture_create")
        policy = {
            "discoverability": "hidden",
            "admission": {"owner_certified": owner_user},
            "confidentiality": "mls_encrypted",
            "read_access": "members_only",
            "write_access": "members_only",
        }
        status, created = self.http(
            "POST",
            *self.api["owner"],
            "/groups",
            {"name": "rt3", "description": "", "policy": policy},
        )
        self.require(status == 201 and created.get("ok") is True, "group create response")
        self.require(created.get("policy") == policy, "effective policy echo mismatch")
        group = created.get("group_id")
        self.require(isinstance(group, str) and len(group) == 64, "created group id")

        self.set_stage("fixture_join")
        status, invite = self.http(
            "POST",
            *self.api["owner"],
            f"/groups/{group}/invite",
            {"expiry_secs": 600, "intended_joiner": device_agent},
        )
        self.require(status == 200 and invite.get("ok") is True, "invite response")
        link = invite.get("invite_link")
        self.require(isinstance(link, str) and link, "invite link")
        status, joined = self.http(
            "POST",
            *self.api["device"],
            "/groups/join",
            owner_join_request(link, owner_user),
            timeout=10,
        )
        self.require(status == 200 and joined.get("ok") is True, "join response")
        self.require(
            joined.get("join_state") in {"pending_authority_commit", "active"},
            "join response state",
        )

        self.set_stage("fixture_converge")
        expected = {str(owner_agent), str(device_agent)}
        self.poll_convergence(str(group), expected)
        self.observations["fixture_converged"] = True

        self.set_stage("fixture_witness")
        sidecar = owner_data / "home-suite-groups.json"
        cache = owner_identity / "announce-blob-cache.bin"
        witness_log = self.artifacts / "fixture-witness.log"
        self.wait_cache_witness(
            [
                self.arguments.fixture,
                "cache-check",
                str(cache),
                str(sidecar),
                str(group),
                str(device_agent),
                str(owner_user),
            ],
            witness_log,
        )
        self.observations["cache_witness"] = True

        self.set_stage("fixture_shutdown")
        self.stop_child("device")
        self.stop_child("owner")

        self.set_stage("split")
        prepared = self.root / "prepared"
        positive = self.root / "positive"
        negative = self.root / "negative"
        (prepared / "data").parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(owner_data, prepared / "data")
        shutil.copytree(owner_identity, prepared / "identity")
        prepared_sidecar = prepared / "data" / "home-suite-groups.json"
        self.run_checked(
            [
                self.arguments.fixture,
                "strip-cert",
                str(prepared_sidecar),
                str(group),
                str(device_agent),
            ],
            stdout=self.artifacts / "strip-witness.log",
        )
        shutil.copytree(prepared, positive)
        shutil.copytree(prepared, negative)
        positive_cache = positive / "identity" / "announce-blob-cache.bin"
        negative_cache = negative / "identity" / "announce-blob-cache.bin"
        self.require(positive_cache.is_file() and negative_cache.is_file(), "cloned cache missing")
        negative_cache.unlink()

        self.set_stage("lane_compare")
        positive_manifest = self.regular_manifest(positive)
        negative_manifest = self.regular_manifest(negative)
        cache_relative = "identity/announce-blob-cache.bin"
        self.require(cache_relative in positive_manifest, "positive cache absent")
        self.require(cache_relative not in negative_manifest, "negative cache retained")
        positive_without = dict(positive_manifest)
        positive_without.pop(cache_relative)
        self.require(positive_without == negative_manifest, "lanes differ beyond cache")
        self.observations["lane_difference_cache_only"] = True

        baseline: dict[str, object] | None = None
        for lane in ("positive", "negative"):
            lane_root = positive if lane == "positive" else negative
            config = configs / f"{lane}.toml"
            port = self.reserve_udp_port()
            self.write_config(
                config,
                lane_root / "identity",
                lane_root / "data",
                port,
                [],
            )
            self.set_stage(f"{lane}_start")
            self.start_child(lane, config, lane_root / "data")
            status, lane_agent = self.http("GET", *self.api[lane], "/agent")
            self.require(status == 200 and lane_agent.get("ok") is True, "lane agent response")
            self.require(
                lane_agent.get("user_id") == owner_user
                and lane_agent.get("agent_id") == owner_agent
                and lane_agent.get("machine_id") == owner_machine,
                "lane restart did not preserve exact owner agent and machine identity",
            )
            self.set_stage(f"{lane}_precheck")
            status, group_body = self.http(
                "GET", *self.api[lane], f"/groups/{group}"
            )
            self.require(status == 200 and group_body.get("ok") is True, "lane group precheck")
            members = active_agent_ids(group_body)
            self.require(members == expected, "lane roster precheck")
            status, before = self.http(
                "GET", *self.api[lane], f"/groups/{group}/state"
            )
            self.require(status == 200 and before.get("ok") is True, "lane state precheck")
            if baseline is None:
                baseline = {
                    key: before.get(key)
                    for key in ("state_revision", "state_hash", "roster_root")
                }
            else:
                self.require(
                    all(before.get(key) == baseline.get(key) for key in baseline),
                    "lane baselines differ",
                )
            sidecar_before = hashlib.sha256(
                (lane_root / "data" / "home-suite-groups.json").read_bytes()
            ).hexdigest()

            self.set_stage(f"{lane}_hydrate")
            mutation_status, mutation = self.http(
                "PATCH",
                *self.api[lane],
                f"/groups/{group}",
                {"description": "rt3-hydration-probe"},
            )
            self.observations[f"{lane}_hydration_status"] = mutation_status
            status, after_mutation = self.http(
                "GET", *self.api[lane], f"/groups/{group}/state"
            )
            group_status, after_mutation_group = self.http(
                "GET", *self.api[lane], f"/groups/{group}"
            )
            self.record_counters(
                {
                    f"{lane}_hydration_state_before": before.get("state_revision"),
                    f"{lane}_hydration_state_after": after_mutation.get(
                        "state_revision"
                    ),
                    f"{lane}_hydration_roster_before": group_body.get(
                        "roster_revision"
                    ),
                    f"{lane}_hydration_roster_after": after_mutation_group.get(
                        "roster_revision"
                    ),
                    **(
                        {
                            "positive_hydration_roster_response": mutation.get(
                                "revision"
                            )
                        }
                        if lane == "positive"
                        else {}
                    ),
                }
            )
            self.require(
                status == 200 and group_status == 200,
                "lane state after hydration trigger",
            )
            if lane == "positive":
                hydrated = positive_hydration_observation(
                    before,
                    group_body,
                    mutation_status,
                    mutation,
                    after_mutation,
                    after_mutation_group,
                )
                self.record_result(
                    "positive_hydration_status",
                    mutation_status,
                    {
                        "positive_hydration_state_revision_increment": hydrated[
                            "state_revision_increment"
                        ],
                        "positive_hydration_roster_revision_increment": hydrated[
                            "roster_revision_increment"
                        ],
                        "positive_hydration_response_revision_matches_roster": hydrated[
                            "response_revision_matches_roster"
                        ],
                        "positive_hydration_roster_unchanged": hydrated[
                            "roster_unchanged"
                        ],
                        "positive_description_updated": hydrated["description_updated"],
                    },
                )
                self.require(all(hydrated.values()), "positive hydration observation incomplete")
            else:
                refused = negative_hydration_observation(
                    before,
                    group_body,
                    mutation_status,
                    mutation,
                    after_mutation,
                    after_mutation_group,
                )
                self.record_result(
                    "negative_hydration_status",
                    mutation_status,
                    {
                        "negative_hydration_pending_class": refused["pending_class"],
                        "negative_hydration_state_unchanged": refused["state_unchanged"],
                        "negative_hydration_roster_revision_unchanged": refused[
                            "roster_revision_unchanged"
                        ],
                        "negative_hydration_description_unchanged": refused[
                            "description_unchanged"
                        ],
                    },
                )
                self.require(all(refused.values()), "negative hydration observation incomplete")

            self.set_stage(f"{lane}_seal")
            seal_status, seal = self.http(
                "POST", *self.api[lane], f"/groups/{group}/state/seal", {}
            )
            self.observations[f"{lane}_seal_status"] = seal_status
            status, after_seal = self.http(
                "GET", *self.api[lane], f"/groups/{group}/state"
            )
            group_status, after_seal_group = self.http(
                "GET", *self.api[lane], f"/groups/{group}"
            )
            commit = seal.get("commit")
            self.record_counters(
                {
                    f"{lane}_seal_state_before": after_mutation.get("state_revision"),
                    f"{lane}_seal_state_after": after_seal.get("state_revision"),
                    f"{lane}_seal_roster_before": after_mutation_group.get(
                        "roster_revision"
                    ),
                    f"{lane}_seal_roster_after": after_seal_group.get(
                        "roster_revision"
                    ),
                    **(
                        {
                            "positive_seal_state_commit": (
                                commit.get("revision")
                                if isinstance(commit, dict)
                                else None
                            )
                        }
                        if lane == "positive"
                        else {}
                    ),
                }
            )
            self.require(
                status == 200 and group_status == 200,
                "lane state after explicit seal",
            )
            if lane == "positive":
                sealed = positive_observation(
                    after_mutation,
                    after_mutation_group,
                    seal_status,
                    seal,
                    after_seal,
                    after_seal_group,
                )
                self.record_result(
                    "positive_seal_status",
                    seal_status,
                    {
                        "positive_seal_state_revision_increment": sealed[
                            "state_revision_increment"
                        ],
                        "positive_seal_roster_revision_unchanged": sealed[
                            "roster_revision_unchanged"
                        ],
                        "positive_seal_roster_unchanged": sealed["roster_unchanged"],
                        "positive_no_eviction": sealed["no_eviction"],
                    },
                )
                self.require(all(sealed.values()), "positive seal observation incomplete")
            else:
                sealed = negative_observation(
                    after_mutation,
                    after_mutation_group,
                    seal_status,
                    seal,
                    after_seal,
                    after_seal_group,
                )
                self.record_result(
                    "negative_seal_status",
                    seal_status,
                    {
                        "negative_seal_pending_class": sealed["pending_class"],
                        "negative_seal_state_unchanged": sealed["state_unchanged"],
                        "negative_seal_roster_revision_unchanged": sealed[
                            "roster_revision_unchanged"
                        ],
                    },
                )
                self.require(all(sealed.values()), "negative seal observation incomplete")

            self.set_stage(f"{lane}_shutdown")
            self.stop_child(lane)
            sidecar_after = hashlib.sha256(
                (lane_root / "data" / "home-suite-groups.json").read_bytes()
            ).hexdigest()
            if lane == "negative":
                self.require(sidecar_after == sidecar_before, "negative sidecar mutated")
                self.observations["negative_sidecar_unchanged"] = True
            else:
                self.run_checked(
                    [
                        self.arguments.fixture,
                        "cache-check",
                        str(positive_cache),
                        str(positive / "data" / "home-suite-groups.json"),
                        str(group),
                        str(device_agent),
                        str(owner_user),
                    ],
                    stdout=self.artifacts / "positive-witness.log",
                )

        self.observations["lane_identity_preserved"] = True
        self.set_stage("complete")

    def write_receipt(self, status: int, cleanup_complete: bool) -> None:
        children = [child.receipt() for child in self.children.values()]
        receipt = {
            "schema": 2,
            "stage": self.stage,
            "status": status,
            "error_class": self.error_class,
            "error_line": self.error_line,
            "cleanup_complete": cleanup_complete,
            "children": children,
            "observations": self.observations,
            "counters": self.counters,
            "accepted": (
                status == 0
                and cleanup_complete
                and self.stage == "complete"
                and self.error_class == "none"
                and self.error_line == 0
                and children_accepted(children)
                and all(type(value) is int and value >= 0 for value in self.counters.values())
                and all(
                    value is True
                    for key, value in self.observations.items()
                    if not key.endswith("_status")
                )
                and self.observations["positive_hydration_status"] == 200
                and self.observations["positive_seal_status"] == 200
                and self.observations["negative_hydration_status"] == 500
                and self.observations["negative_seal_status"] == 409
            ),
        }
        temporary = self.artifacts / "harness-outcome.tmp"
        temporary.write_text(json.dumps(receipt, sort_keys=True) + "\n")
        os.replace(temporary, self.artifacts / "harness-outcome.json")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--artifacts", required=True)
    parser.add_argument("--x0xd", required=True)
    parser.add_argument("--x0x", required=True)
    parser.add_argument("--fixture", required=True)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    if not arguments.run:
        print("RT3 preparation mode: execution requires --run and the namespace wrapper")
        return 1
    harness = Harness(arguments)
    status = 0
    try:
        harness.run()
    except DiagnosticFailure as error:
        status = 1
        harness.error_class = error.error_class
        trace = traceback.extract_tb(error.__traceback__)
        harness.error_line = trace[-1].lineno if trace else 0
        print(f"RT3 diagnostic failed at {harness.stage}: {error.error_class}", file=sys.stderr)
    except Exception:
        status = 1
        harness.error_class = "unexpected"
        trace = traceback.extract_tb(sys.exc_info()[2])
        harness.error_line = trace[-1].lineno if trace else 0
        print(f"RT3 diagnostic failed at {harness.stage}: unexpected", file=sys.stderr)
    cleanup_complete = harness.cleanup()
    try:
        harness.write_receipt(status, cleanup_complete)
    except Exception:
        return 2
    return status


if __name__ == "__main__":
    raise SystemExit(main())
