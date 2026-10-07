#!/usr/bin/env python3
"""Testnet survivor-rekey fixture (#1216): remove and ban, survivors decrypt, excluded members cannot.

For each selected variant (``plain``, ``restart``) and secure plane (``gss``: an
MlsEncrypted public-directory group on the legacy GSS plane; ``treekem``: a
``private_secure`` group), the fixture builds one fresh group whose members are
every ``--nodes`` label, then runs two cases on it:

* remove: the remover (the group creator, ``--nodes[0]``) removes ``--nodes[-2]``;
* ban:    the remover bans ``--nodes[-1]``. The member removed earlier is an
  excluded node of this case too, so a ban rotation that reaches it is caught.

At least five nodes are required, so each group has five or more members at the
removal and four or more at the ban. Each case:

1. key barrier: the remover seals a message and every other member decrypts it.
   Readiness is always proven by decrypting, never by roster state alone (#1214),
   and every joiner proves its key the same way right after its join;
2. restart variant only: the remover's ``x0xd-testnet.service`` restarts and the
   removal starts 10-20 s later (the #1190 owner-restart shape);
3. the remover removes or bans the target, then seals a message at an advanced
   secret epoch;
4. every survivor decrypts that message: the class-K share on GSS, the commit on
   TreeKEM. The rekey latency from the removal is recorded per survivor;
5. no excluded node decrypts it, while the survivors converge and for a further
   ``--watch-secs`` that covers the share resend and the withheld re-checks;
6. every survivor's roster stops listing the target as active;
7. GSS: the remover answers the explicit recipient-ineligible refusal when asked
   to re-seal the current secret to the target. Ban: the target re-joins with an
   invite minted before the ban; the join outcome is checked, it is never seated
   and it gains no key;
8. a final message sealed after all of that decrypts on every survivor and on no
   excluded node.

Verdicts. A check passes, fails, or is INCONCLUSIVE, and an inconclusive check
stays inconclusive in its case, the report ``verdict`` and the exit code
(0 pass, 1 fail, 3 inconclusive). Transport errors, timeouts, HTTP 5xx, fork
quarantine, untyped 4xx and invalid or malformed reads never count as an
exclusion or a refusal. Only exact typed responses do: for an excluded node's
decrypt, 403 ``not a member`` or 404 ``group not found`` (gate), or a typed
key-material answer; for a join, a 409 carrying a known refusal code.

Evidence classes for "an excluded node holds no post-removal key" (D60):

* ``key``: the node's LAST decrypt answer came from its key material (GSS no
  secret, epoch mismatch that reports a local epoch below the new one, or AEAD
  failure; TreeKEM group not loaded or decrypt failure);
* ``limited``: no key evidence. A removed member's daemon answers ``not a
  member`` before it consults any key material, TreeKEM logs no key install,
  and an epoch mismatch without the local epoch proves nothing. The check is NOT
  claimed: it is listed under ``limitations`` in the report, not under
  ``assertions``.

The GSS share-install journal line ("stored new group shared secret (epoch N)")
can only FAIL the check: a line for this group at the new epoch or later is a
leak. Its absence is never evidence, because x0xd's non-blocking log writer drops
lines without a signal and log filters can hide it. Journal windows start at the
node's own clock, read before the action.

Mixed versions: nothing assumes one binary. Each node's live ``/health`` version
and the sha256 of its running x0xd (``/proc/<MainPID>/exe`` over SSH) are
recorded per node and per case role. When the eph hosts file is available
(``--hosts-json``, or ``testnet-hosts.json`` next to ``--tokens-file``), every
selected node must have a valid deployed sha256 and version there, its address
must match the tokens file, and its live version and live sha256 must equal what
was deployed to THAT node. ``--expect-mixed`` also requires two or more distinct
verified running binaries among the selected nodes.

Only ``x0xd-testnet.service`` is ever addressed. Restarts need
``--allow-service-restart`` and every restarted unit is restored in ``finally``.
Journals are read-only grep counts (recipient_undiscovered, share installs) and
the report never holds log lines. The report holds labels, status codes,
response classes, epochs, timings and hashes; never tokens, ciphertexts,
invites, envelopes, log lines or bodies.
"""
from __future__ import annotations

import argparse
import base64
import concurrent.futures
import datetime
import hashlib
import json
import math
import os
import re
import shlex
import subprocess
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from e2e_tunnel import TunnelHandle, start_ssh_tunnel, stop_ssh_tunnel
from e2e_vps_groups import NODES_DEFAULT, load_tokens
from e2e_vps_kv import (Api, Evidence, PollTimeout, ServiceCustody, enc, poll, safe_error_outcome,
                        safe_identifier, with_poll_timeout)
from e2e_vps_private_kv import Scenario as PrivateScenario

SERVICE = "x0xd-testnet.service"
PLANES = ("gss", "treekem")
VARIANTS = ("plain", "restart")
ACTIONS = ("remove", "ban")
MIN_NODES = 5
RESTART_LEAD_BOUNDS = (10.0, 20.0)
# CLI bounds (seconds). The watch minimum covers the share resend (+8 s) and one
# withheld re-check (15 s) with margin.
DURATION_BOUNDS = {
    "--poll-timeout": (10.0, 3600.0),
    "--rekey-timeout": (10.0, 3600.0),
    "--watch-secs": (30.0, 3600.0),
    "--rejoin-watch-secs": (10.0, 3600.0),
    "--restart-lead-secs": RESTART_LEAD_BOUNDS,
}
# Membership operations await their own publish and can outlast the default 20 s.
ACT_TIMEOUT_SECS = 60.0
HOSTS_JSON_NAME = "testnet-hosts.json"
SHA256_HEX = re.compile(r"\A[0-9a-f]{64}\Z")
VERSION_RE = re.compile(r"(\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?)")
# The GSS (legacy plane) policy: MlsEncrypted and not hidden. The server selects
# TreeKEM only for hidden MlsEncrypted groups such as the private_secure preset.
GSS_POLICY = {
    "discoverability": "public_directory",
    "admission": "request_access",
    "confidentiality": "mls_encrypted",
    "read_access": "members_only",
    "write_access": "members_only",
}
# Decrypt response classes for an EXCLUDED node.
# leak: a 200 means it held a usable key.
LEAK_CLASSES = frozenset({"decrypted", "wrong_plaintext"})
# key: the daemon passed the membership gate and consulted its key material.
KEY_EVIDENCE_CLASSES = frozenset({"no_secret", "epoch_mismatch", "decrypt_failed",
                                  "treekem_not_loaded", "treekem_decrypt_failed"})
# gate: the two typed membership refusals answered before any key material is
# consulted (403 "not a member", 404 "group not found"). Nothing else counts.
GATE_CLASSES = frozenset({"not_member", "group_not_found"})
# Everything else (transport errors, 5xx, fork quarantine, other 4xx) is an
# error: no evidence, so the check is inconclusive.
RESEAL_REFUSALS = frozenset({"recipient_not_member", "recipient_not_active"})
JOIN_STATES = frozenset({"active", "pending_authority_commit", "idle", "timed_out"})
JOIN_STATUS_STATES = frozenset({"pending_authority_commit", "idle"})
# Typed `POST /groups/join` refusals: a 409 whose `error` (or `reason`) is one of
# these codes (docs/api-reference.md, join_group_via_invite). Untyped 4xx are not
# refusals. Fork quarantine is deliberately absent: it is inconclusive everywhere,
# because it refuses for the group's state, not for the joiner.
JOIN_REFUSAL_CODES = frozenset({
    "invite_unsigned", "invite_signature_invalid", "invite_malformed", "invite_base_inconsistent",
    "invite_downgraded", "invite_not_addressed_to_me", "inviter_key_mismatch", "inviter_key_revoked",
    "invite_owner_countersignature_missing", "invite_owner_countersignature_invalid",
    "use_home_mode", "pin_requires_home_mode", "home_mode_requires_pin", "owner_mismatch",
    "join_already_pending"})
KNOWN_MEMBER_STATES = frozenset({"active", "pending", "removed", "banned"})
JOIN_OUTCOMES = frozenset({"refused", "timed_out"})
JOIN_OUTCOME_REASONS = frozenset({
    "invite_secret_unknown", "invite_secret_consumed", "invite_role_exceeds_cap",
    "invite_event_before_creation", "invite_expired", "invite_not_addressed",
    "banned", "member_banned"})
LOCAL_UNSEATED_STATES = frozenset({"pending_authority_commit", "pending", "not_member"})
# Journal markers counted on the remover after each case. The first two are
# warn-level (visible at the eph RUST_LOG=info); the share-resend lines are
# debug-level and are counted only when debug logging is enabled.
JOURNAL_PATTERNS = (
    ("recipient_undiscovered", "err_recipient_undiscovered"),
    ("welcome_fetch_failed", "failed to fetch TreeKEM Welcome blob"),
    ("share_resend_undiscovered", "secure share recipient not yet discovered"),
    ("share_write_retry", "secure share write failed"),
)
# The GSS share receive arm logs every install at info level, with the group's
# stable id: "Phase D.2: stored new group shared secret (epoch N) via KEM-sealed envelope".
SHARE_INSTALL_MARKER = "stored new group shared secret"
SHARE_INSTALL_RE = re.compile(r"stored new group shared secret \(epoch (\d+)\)")
INFO_LINES_RE = re.compile(r"^x0x-rekey-info-lines=(\d+)\s*$", re.MULTILINE)
WAITED_MS_RE = re.compile(r"waited_ms[\"']?\s*[=:]\s*(\d+)")
SSH_BASE = ("ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15",
            "-o", "ControlMaster=no", "-o", "ControlPath=none")
# $1 = the node's OWN clock (unix seconds), read before the action it covers.
JOURNAL_SCRIPT = r'''set -u
since=$1; shift
args=()
for needle in "$@"; do args+=(-e "$needle"); done
journalctl -u ''' + SERVICE + r''' --since "@$since" -o cat --no-pager 2>/dev/null \
  | grep -F "${args[@]}" | head -n 20000
printf 'x0x-rekey-info-lines=%s\n' "$(journalctl -u ''' + SERVICE + r''' --since "@$since" -o cat --no-pager 2>/dev/null | grep -c -F INFO || true)"
exit 0
'''
REMOTE_CLOCK_SCRIPT = "date +%s\n"
# Exit codes: inconclusive is distinct from a failure end to end.
EXIT_PASS, EXIT_FAIL, EXIT_INCONCLUSIVE = 0, 1, 3
LIVE_SHA_SCRIPT = r'''set -eu
pid=$(systemctl show -p MainPID --value ''' + SERVICE + r''')
[ "${pid:-0}" -gt 0 ]
sha256sum "/proc/$pid/exe"
'''


# --------------------------------------------------------------------------- pure helpers

def utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def normalize_version(value: Any) -> Optional[str]:
    """`0.46.3` from `/health`'s `0.46.3` or the deploy record's `x0xd 0.46.3`."""
    if not isinstance(value, str):
        return None
    match = VERSION_RE.search(value)
    return match.group(1) if match else None


def bounded_seconds(flag: str, low: float, high: float) -> Callable[[str], float]:
    """argparse type: a finite number of seconds within [low, high]."""
    def parse(text: str) -> float:
        try:
            value = float(text)
        except ValueError:
            raise argparse.ArgumentTypeError(f"{flag} must be a number of seconds") from None
        if not math.isfinite(value) or not low <= value <= high:
            raise argparse.ArgumentTypeError(f"{flag} must be a finite number of seconds within {low:g}-{high:g}")
        return value
    return parse


def assign_roles(nodes: List[str]) -> Dict[str, Any]:
    """remover = first, remove target = second-last, ban target = last, survivors between."""
    if len(nodes) < MIN_NODES:
        raise ValueError(f"survivor rekey needs at least {MIN_NODES} nodes")
    if len(set(nodes)) != len(nodes):
        raise ValueError("--nodes must be distinct")
    return {"remover": nodes[0], "survivors": list(nodes[1:-2]),
            "remove_target": nodes[-2], "ban_target": nodes[-1]}


def resolve_hosts_json(explicit: Optional[str], tokens_file: str) -> Tuple[Optional[str], str]:
    """The eph run writes testnet-hosts.json next to its tokens file."""
    if explicit:
        return explicit, "explicit"
    sibling = os.path.join(os.path.dirname(os.path.abspath(tokens_file)), HOSTS_JSON_NAME)
    if os.path.isfile(sibling):
        return sibling, "sibling"
    return None, "absent"


def node_binary_map(doc: Any, endpoints: Dict[str, str]) -> Tuple[Dict[str, Dict[str, Any]], List[str]]:
    """Per-node deployed binary from an eph hosts document. Never one value for all nodes.

    Every selected node needs a valid sha256 and a parseable version; anything
    missing or malformed is a problem. Problems name labels only, never addresses.
    """
    if not isinstance(doc, dict) or doc.get("schema_version") != 1 or doc.get("kind") != "x0x-testnet-hosts":
        return {}, ["hosts file is not an x0x-testnet-hosts schema 1 document"]
    hosts = doc.get("hosts")
    if not isinstance(hosts, list):
        return {}, ["hosts file has no hosts list"]
    problems: List[str] = []
    by_label: Dict[str, Dict[str, Any]] = {}
    for host in hosts:
        if isinstance(host, dict) and isinstance(host.get("label"), str):
            if host["label"] in by_label:
                problems.append(f"hosts file lists {host['label']} twice")
            by_label[host["label"]] = host
    out: Dict[str, Dict[str, Any]] = {}
    for label, address in endpoints.items():
        host = by_label.get(label)
        if host is None:
            problems.append(f"hosts file has no entry for {label}")
            continue
        if host.get("public_ipv4") != address:
            problems.append(f"hosts file address for {label} differs from the tokens file")
            continue
        sha = host.get("daemon_sha256")
        if not isinstance(sha, str) or not SHA256_HEX.fullmatch(sha):
            problems.append(f"hosts file has no valid daemon_sha256 for {label}")
            continue
        version = normalize_version(host.get("daemon_version"))
        if version is None:
            problems.append(f"hosts file has no parseable daemon_version for {label}")
            continue
        out[label] = {"daemon_sha256": sha, "deployed_version": version}
    return out, problems


def binary_checks(node_binaries: Dict[str, Dict[str, Any]], live_versions: Dict[str, Optional[str]],
                  live_shas: Dict[str, Optional[str]]) -> List[Tuple[str, str, Dict[str, Any]]]:
    """(node, verdict, facts): the live version AND the running sha256 must equal what
    was deployed to that node. A missing live reading is inconclusive, never a pass."""
    results = []
    for node, deployed in sorted(node_binaries.items()):
        live_version, live_sha = live_versions.get(node), live_shas.get(node)
        facts = {"node": node, "live_version": live_version, "deployed_version": deployed["deployed_version"],
                 "live_sha256": live_sha, "deployed_sha256": deployed["daemon_sha256"]}
        if live_version is None or live_sha is None:
            verdict = "inconclusive"
        elif live_version == deployed["deployed_version"] and live_sha == deployed["daemon_sha256"]:
            verdict = "pass"
        else:
            verdict = "fail"
        results.append((node, verdict, facts))
    return results


def mixed_check(node_binaries: Dict[str, Dict[str, Any]], live_shas: Dict[str, Optional[str]]) -> Tuple[str, Dict[str, Any]]:
    """--expect-mixed: two or more distinct RUNNING binaries, each matching its deploy record."""
    verified = {node: live_shas.get(node) for node in node_binaries
                if live_shas.get(node) is not None and live_shas.get(node) == node_binaries[node]["daemon_sha256"]}
    facts = {"verified_nodes": len(verified), "selected_nodes": len(node_binaries),
             "distinct_running_binaries": len(set(verified.values()))}
    if len(verified) != len(node_binaries):
        return "inconclusive", facts
    return ("pass" if len(set(verified.values())) >= 2 else "fail"), facts


def plane_of_encrypt(body: Any) -> Optional[str]:
    """TreeKEM says so; the GSS response carries a per-message nonce and no plane."""
    if not isinstance(body, dict):
        return None
    if body.get("secure_plane") == "treekem":
        return "treekem"
    nonce = body.get("nonce_b64")
    if "secure_plane" not in body and isinstance(nonce, str) and nonce:
        return "gss"
    return None


def sealed_from_encrypt(body: Any) -> Optional[Dict[str, Any]]:
    """The decrypt request body for an encrypt response, or None if it is malformed."""
    if not isinstance(body, dict) or body.get("ok") is False:
        return None
    ciphertext, epoch = body.get("ciphertext_b64"), body.get("secret_epoch")
    if not isinstance(ciphertext, str) or not ciphertext or type(epoch) is not int:
        return None
    sealed: Dict[str, Any] = {"ciphertext_b64": ciphertext, "secret_epoch": epoch}
    nonce = body.get("nonce_b64")
    if isinstance(nonce, str) and nonce:
        sealed["nonce_b64"] = nonce
    return sealed


def _text(body: Dict[str, Any], key: str) -> str:
    value = body.get(key)
    return value if isinstance(value, str) else ""


def classify_decrypt(status: Optional[int], body: Any, expected_b64: str) -> Tuple[str, Optional[int]]:
    """(response class, epoch). The epoch is the message epoch on success and the
    caller's LOCAL secret epoch on a GSS epoch mismatch; otherwise None.

    Only fixed class names leave this function, never body text.
    """
    body = body if isinstance(body, dict) else {}
    error, reason = _text(body, "error"), _text(body, "reason")
    epoch = body.get("secret_epoch")
    if status == 200:
        decrypted = body.get("ok") is not False and body.get("payload_b64") == expected_b64
        return ("decrypted" if decrypted else "wrong_plaintext"), (epoch if type(epoch) is int else None)
    # Each typed class needs its exact status AND its exact body. A matching
    # body on any other status, or any other body, is an untyped response.
    if status == 409:
        if error.startswith("epoch mismatch") and not reason:
            local = body.get("local_epoch")
            return "epoch_mismatch", (local if type(local) is int else None)
        return ("fork_quarantined" if reason == "fork_quarantined" else "conflict"), None
    if status == 424 and not reason:
        if error == "no shared secret available":
            return "no_secret", None
        if error.startswith("TreeKEM group not loaded"):
            return "treekem_not_loaded", None
    if status == 403 and not reason:
        if error == "not a member":
            return "not_member", None
        if error == "decryption failed":
            return "decrypt_failed", None
    if status == 400 and not reason and error.startswith("treekem decrypt failed"):
        return "treekem_decrypt_failed", None
    if status == 404 and not reason and error == "group not found":
        return "group_not_found", None
    if reason == "fork_quarantined":
        return "fork_quarantined", None
    if status in (400, 403, 404, 424):
        return {400: "bad_request", 403: "forbidden", 404: "not_found_other", 424: "failed_dependency"}[status], None
    return "http_other", None


def exclusion_kind(cls: str) -> str:
    """leak | key | gate | error for an excluded node's decrypt class."""
    if cls in LEAK_CLASSES:
        return "leak"
    if cls in KEY_EVIDENCE_CLASSES:
        return "key"
    if cls in GATE_CLASSES:
        return "gate"
    return "error"


def single_probe_verdict(cls: str) -> Tuple[str, str]:
    """One excluded-node probe: (verdict, evidence kind)."""
    kind = exclusion_kind(cls)
    return ("fail" if kind == "leak" else "inconclusive" if kind == "error" else "pass"), kind


def classify_reseal(status: Optional[int], body: Any) -> str:
    """`POST /groups/:id/secure/reseal` outcome. A 200 carries a sealed secret: never stored."""
    body = body if isinstance(body, dict) else {}
    if status == 200:
        return "sealed"
    if status == 404 and _text(body, "error") == "recipient is not a member":
        return "recipient_not_member"
    if status == 409 and _text(body, "reason") == "recipient_not_active":
        return "recipient_not_active"
    if status == 403:
        return "forbidden"
    if status == 424:
        return "failed_dependency"
    return "http_other" if status is not None else "transport_error"


def reseal_verdict(cls: str) -> str:
    """Only the explicit recipient-ineligible refusals count as a refusal."""
    if cls in RESEAL_REFUSALS:
        return "pass"
    return "fail" if cls == "sealed" else "inconclusive"


def classify_join_attempt(status: Optional[int], body: Any) -> Dict[str, Any]:
    """`POST /groups/join`: allow-listed fields only. `refusal_code` is set only for a
    typed refusal (409 with a known code in `error` or `reason`)."""
    body = body if isinstance(body, dict) else {}
    state = body.get("join_state")
    already = body.get("already_joined")
    code = None
    if status == 409:
        for value in (_text(body, "reason"), _text(body, "error")):
            if value in JOIN_REFUSAL_CODES:
                code = value
                break
    return {"status": status,
            "join_state": state if state in JOIN_STATES else ("other" if state is not None else None),
            "already_joined": already if isinstance(already, bool) else None,
            "refusal_code": code}


def classify_join_status(status: Optional[int], body: Any) -> Dict[str, Any]:
    """`GET /groups/:id/join-status`: allow-listed fields and whether the read is valid.

    Valid: 200 with a known join_state, or 404 (the local stub is gone; #477 puts any
    terminal outcome in the body).
    """
    body = body if isinstance(body, dict) else {}
    last = body.get("last_join_outcome")
    last = last if isinstance(last, dict) else {}
    outcome, reason, state = last.get("outcome"), last.get("reason"), body.get("join_state")
    return {"status": status,
            "join_state": state if state in JOIN_STATUS_STATES else ("other" if state is not None else None),
            "outcome": outcome if outcome in JOIN_OUTCOMES else ("other" if outcome is not None else None),
            "reason": reason if reason in JOIN_OUTCOME_REASONS else ("other" if reason is not None else None),
            "valid": (status == 200 and state in JOIN_STATUS_STATES) or status == 404}


def classify_local_membership(status: Optional[int], body: Any) -> str:
    """The node's own `GET /groups/:id`: seat | unseated | invalid."""
    if status in (403, 404):
        return "unseated"
    if status == 200 and isinstance(body, dict):
        state = body.get("membership_state")
        if state == "active":
            return "seat"
        if state in LOCAL_UNSEATED_STATES:
            return "unseated"
    return "invalid"


def rejoin_verdict(attempt: Dict[str, Any], roster_reads: Sequence[Optional[bool]], local: str,
                   join_status: Dict[str, Any]) -> Tuple[str, str]:
    """A banned member's re-join: (verdict, reason). Failed requests and invalid reads are
    inconclusive, never 'not seated'."""
    status = attempt.get("status")
    accepted = isinstance(status, int) and 200 <= status < 300
    typed_refusal = attempt.get("refusal_code") in JOIN_REFUSAL_CODES
    if any(read is True for read in roster_reads):
        return "fail", "seated_on_remover_roster"
    if local == "seat":
        return "fail", "target_reports_active"
    if accepted and (attempt.get("join_state") == "active" or attempt.get("already_joined") is True):
        return "fail", "join_reported_active"
    if isinstance(status, int) and 400 <= status < 500 and not typed_refusal:
        return "inconclusive", "untyped_join_refusal"
    if not (accepted or typed_refusal):
        return "inconclusive", "join_request_error"
    if not roster_reads or any(read is None for read in roster_reads):
        return "inconclusive", "invalid_roster_read"
    if local != "unseated":
        return "inconclusive", "invalid_local_read"
    if not join_status.get("valid"):
        return "inconclusive", "invalid_join_status"
    if typed_refusal or join_status.get("outcome") == "refused":
        return "pass", "refused"
    return "pass", "unseated"


def member_is_active(status: Optional[int], body: Any, agent_id: str) -> Optional[bool]:
    """None when the roster could not be read or any row is malformed: every row
    needs a string agent_id and a known string state, so a row missing its state
    is never read as a valid absence."""
    if status != 200 or not isinstance(body, dict) or not isinstance(body.get("members"), list):
        return None
    active = False
    for row in body["members"]:
        if not isinstance(row, dict) or not isinstance(row.get("agent_id"), str):
            return None
        state = row.get("state")
        if not isinstance(state, str) or state.lower() not in KNOWN_MEMBER_STATES:
            return None
        if row["agent_id"] == agent_id and state.lower() == "active":
            active = True
    return active


def restart_lead_ok(lead_seconds: float, bounds: Tuple[float, float] = RESTART_LEAD_BOUNDS) -> bool:
    return math.isfinite(lead_seconds) and bounds[0] <= lead_seconds <= bounds[1]


def restart_observed(uptime_after: Any, since_restart_seconds: float) -> bool:
    """The daemon answering after the restart started no earlier than the restart."""
    return type(uptime_after) is int and uptime_after <= since_restart_seconds + 5


def parse_info_lines(text: str) -> Optional[int]:
    match = INFO_LINES_RE.search(text)
    return int(match.group(1)) if match else None


def parse_journal_matches(text: str) -> Dict[str, Any]:
    """Counts per marker and the recipient_undiscovered `waited_ms` values; no line text."""
    counts = {name: 0 for name, _ in JOURNAL_PATTERNS}
    waited: List[int] = []
    for line in text.splitlines():
        for name, needle in JOURNAL_PATTERNS:
            if needle in line:
                counts[name] += 1
                if name == "recipient_undiscovered":
                    match = WAITED_MS_RE.search(line)
                    if match:
                        waited.append(int(match.group(1)))
    return {"counts": counts, "recipient_undiscovered_waited_ms": waited[:200],
            "recipient_undiscovered_waited_ms_max": max(waited) if waited else None,
            "info_lines": parse_info_lines(text)}


def parse_share_installs(text: str, stable_gid: str) -> Dict[str, Any]:
    """GSS share installs on one node: epochs attributed to this group, and installs
    that cannot be attributed (no group id on the line). No line text."""
    attributed: List[int] = []
    unattributed = 0
    for line in text.splitlines():
        if SHARE_INSTALL_MARKER not in line:
            continue
        match = SHARE_INSTALL_RE.search(line)
        if stable_gid and stable_gid in line and match:
            attributed.append(int(match.group(1)))
        else:
            unattributed += 1
    return {"attributed_epochs": attributed[:200],
            "attributed_max_epoch": max(attributed) if attributed else None,
            "unattributed": unattributed, "info_lines": parse_info_lines(text)}


def parse_sha256sum(text: str) -> Optional[str]:
    token = text.strip().split()[0] if text.strip() else ""
    return token if SHA256_HEX.fullmatch(token) else None


def safe_error_class(error: BaseException) -> str:
    return safe_error_outcome(error)["error_class"]


@dataclass
class ExclusionObservation:
    """Every decrypt probe of one excluded node for one message."""
    probes: int = 0
    classes: Dict[str, int] = field(default_factory=dict)
    local_epochs: List[int] = field(default_factory=list)
    leaked: bool = False
    errors: int = 0
    key_probes: int = 0
    gate_probes: int = 0
    last_class: Optional[str] = None
    last_epoch: Optional[int] = None
    last_at: Optional[float] = None

    def observe(self, at: float, cls: str, epoch: Optional[int]) -> None:
        self.probes += 1
        self.last_class, self.last_at = cls, at
        self.last_epoch = epoch if type(epoch) is int else None
        self.classes[cls] = self.classes.get(cls, 0) + 1
        kind = exclusion_kind(cls)
        if kind == "leak":
            self.leaked = True
        elif kind == "error":
            self.errors += 1
        elif kind == "gate":
            self.gate_probes += 1
        else:
            self.key_probes += 1
            if cls == "epoch_mismatch" and epoch is not None:
                self.local_epochs.append(epoch)

    def max_local_epoch(self) -> Optional[int]:
        return max(self.local_epochs) if self.local_epochs else None

    def summary(self, started: float) -> Dict[str, Any]:
        return {"probes": self.probes, "classes": dict(self.classes), "errors": self.errors,
                "key_probes": self.key_probes, "gate_probes": self.gate_probes,
                "last_class": self.last_class, "last_epoch": self.last_epoch,
                "max_local_epoch": self.max_local_epoch(),
                "leaked": self.leaked,
                "observed_until_s": round(self.last_at - started, 3) if self.last_at is not None else None}


def exclusion_verdict(obs: ExclusionObservation) -> Tuple[str, str]:
    """'The node cannot decrypt the message': (verdict, evidence). Errors and an
    unobserved node are inconclusive; only typed refusals or key failures pass."""
    if obs.leaked:
        return "fail", "leak"
    if obs.probes == 0:
        return "inconclusive", "unobserved"
    if obs.errors:
        return "inconclusive", "error_responses"
    return "pass", ("key" if obs.key_probes else "gate")


def d60_verdict(obs: ExclusionObservation, post_epoch: int,
                journal: Optional[Dict[str, Any]]) -> Tuple[str, str]:
    """'No post-removal key reaches the node': (verdict, evidence class).

    verdict is pass | fail | inconclusive | limited. Only key evidence passes: the
    node's LAST decrypt answer came from its key material, and an epoch mismatch
    must report the node's local epoch, below the new one. The journal can only
    FAIL the check (an install line for this group at the new epoch or later is
    proof). Its silence proves nothing: x0xd's non-blocking log writer drops
    lines without a signal and log filters can hide the marker. 'limited' means
    no key evidence exists: the check is not claimed.
    """
    if obs.leaked:
        return "fail", "leak"
    if (journal is not None and "error_class" not in journal
            and type(journal.get("attributed_max_epoch")) is int and journal["attributed_max_epoch"] >= post_epoch):
        return "fail", "journal_install"
    max_local = obs.max_local_epoch()
    if max_local is not None and max_local >= post_epoch:
        return "fail", "local_epoch_reached"
    if obs.probes == 0:
        return "inconclusive", "unobserved"
    if obs.errors:
        return "inconclusive", "error_responses"
    # Keys only arrive: a key-material answer on the LAST probe covers the window.
    if obs.last_class == "epoch_mismatch":
        if obs.last_epoch is not None and obs.last_epoch < post_epoch:
            return "pass", "key"
        return "limited", "epoch_unreported"
    if obs.last_class in KEY_EVIDENCE_CLASSES:
        return "pass", "key"
    return "limited", "membership_gate"


@dataclass
class RekeyTracker:
    """Probe outcomes for one post-removal message: survivors until they decrypt,
    every excluded node (the target, and earlier removed members) always."""
    survivors: Tuple[str, ...]
    excluded: Tuple[str, ...]
    started: float
    first_success: Dict[str, float] = field(default_factory=dict)
    survivor_epochs: Dict[str, Optional[int]] = field(default_factory=dict)
    survivor_classes: Dict[str, Dict[str, int]] = field(default_factory=dict)
    exclusions: Dict[str, ExclusionObservation] = field(default_factory=dict)

    def __post_init__(self) -> None:
        overlap = set(self.survivors) & set(self.excluded)
        if overlap:
            raise ValueError(f"nodes both survive and are excluded: {sorted(overlap)}")
        for node in self.excluded:
            self.exclusions.setdefault(node, ExclusionObservation())

    def observe(self, node: str, at: float, cls: str, epoch: Optional[int]) -> None:
        if node in self.exclusions:
            self.exclusions[node].observe(at, cls, epoch)
            return
        if node not in self.survivors:
            raise ValueError(f"{node} is neither a survivor nor excluded")
        if node in self.first_success:
            return
        counts = self.survivor_classes.setdefault(node, {})
        counts[cls] = counts.get(cls, 0) + 1
        if cls == "decrypted":
            self.first_success[node] = round(at - self.started, 3)
            self.survivor_epochs[node] = epoch

    def pending(self) -> List[str]:
        return [node for node in self.survivors if node not in self.first_success]

    def leaked(self) -> bool:
        return any(obs.leaked for obs in self.exclusions.values())

    def summary(self) -> Dict[str, Any]:
        latencies = dict(self.first_success)
        slowest = max(latencies, key=lambda node: latencies[node]) if latencies else None
        return {
            "rekey_latency_s": latencies,
            "rekey_latency_max_s": latencies[slowest] if slowest else None,
            "slowest_survivor": slowest,
            "unconverged": self.pending(),
            "survivor_epochs": dict(self.survivor_epochs),
            "survivor_probe_classes": {k: dict(v) for k, v in self.survivor_classes.items()},
            "excluded": {node: obs.summary(self.started) for node, obs in self.exclusions.items()},
        }


# --------------------------------------------------------------------------- transport

class RekeyApi(Api):
    """The shared Api with a per-call timeout (membership operations can outlast 20 s)."""

    def request(self, method: str, path: str, body: Optional[Dict[str, Any]] = None,
                timeout: float = 20.0) -> Tuple[int, Dict[str, Any]]:
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.base + path, data=data, method=method, headers={
            "Authorization": f"Bearer {self.token}", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                payload = json.loads(response.read() or b"{}")
                return response.status, payload if isinstance(payload, dict) else {}
        except urllib.error.HTTPError as error:
            try:
                payload = json.loads(error.read() or b"{}")
            except json.JSONDecodeError:
                payload = {}
            return error.code, payload if isinstance(payload, dict) else {}


def ssh_read(address: str, script: str, args: Sequence[str], timeout: float) -> Tuple[Optional[str], Dict[str, Any]]:
    """Run a read-only script on the node; (stdout or None, error facts)."""
    remote = shlex.join(["bash", "-s", "--", *args])
    try:
        result = subprocess.run([*SSH_BASE, f"root@{address}", remote], input=script.encode(),
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout, check=False)
    except Exception as error:
        return None, {"error_class": safe_error_class(error)}
    if result.returncode != 0:
        return None, {"error_class": "ssh_failed", "returncode": result.returncode}
    return result.stdout.decode("utf-8", errors="replace"), {}


def parse_remote_clock(text: Optional[str]) -> Optional[int]:
    value = text.strip() if isinstance(text, str) else ""
    return int(value) if re.fullmatch(r"[0-9]{9,11}", value) else None


def read_remote_clock(address: str, timeout: float = 30.0) -> Optional[int]:
    """The node's own unix clock. Journal windows start here, read BEFORE the action,
    so SSH delay at scan time can never move the window past the action."""
    text, _error = ssh_read(address, REMOTE_CLOCK_SCRIPT, [], timeout)
    return parse_remote_clock(text)


def journal_since(since_unix: Optional[int]) -> Optional[str]:
    """journalctl --since argument: the node clock minus one second of margin."""
    return str(since_unix - 1) if type(since_unix) is int and since_unix > 1 else None


def scan_journal(address: str, since_unix: Optional[int], timeout: float = 45.0) -> Dict[str, Any]:
    """Read-only count of the JOURNAL_PATTERNS markers since a node-clock instant."""
    since = journal_since(since_unix)
    if since is None:
        return {"error_class": "no_remote_clock"}
    text, error = ssh_read(address, JOURNAL_SCRIPT, [since, *(needle for _, needle in JOURNAL_PATTERNS)], timeout)
    if text is None:
        return {"since_unix": since_unix, **error}
    parsed = parse_journal_matches(text)
    parsed["since_unix"] = since_unix
    return parsed


def scan_share_installs(address: str, since_unix: Optional[int], stable_gid: str,
                        timeout: float = 45.0) -> Dict[str, Any]:
    """Read-only: GSS share installs the node logged since a node-clock instant."""
    since = journal_since(since_unix)
    if since is None:
        return {"error_class": "no_remote_clock"}
    text, error = ssh_read(address, JOURNAL_SCRIPT, [since, SHARE_INSTALL_MARKER], timeout)
    if text is None:
        return {"since_unix": since_unix, **error}
    parsed = parse_share_installs(text, stable_gid)
    parsed["since_unix"] = since_unix
    return parsed


def read_live_sha(address: str, timeout: float = 30.0) -> Optional[str]:
    """sha256 of the RUNNING x0xd (/proc/<MainPID>/exe), or None."""
    text, _error = ssh_read(address, LIVE_SHA_SCRIPT, [], timeout)
    return parse_sha256sum(text) if text is not None else None


# --------------------------------------------------------------------------- evidence

@dataclass
class RekeyEvidence(Evidence):
    cases: List[Dict[str, Any]] = field(default_factory=list)
    limitations: List[Dict[str, Any]] = field(default_factory=list)

    def soft_check(self, label: str, condition: bool, **facts: Any) -> bool:
        """Record a check without raising, so sibling checks still run."""
        self.assertions.append({"label": label, "passed": bool(condition), **facts})
        return bool(condition)

    def verdict_row(self, label: str, verdict: str, **facts: Any) -> str:
        """pass | fail | inconclusive, recorded without raising. Inconclusive is a failed row
        that says so: it never counts as a pass."""
        if verdict not in ("pass", "fail", "inconclusive"):
            raise ValueError(f"unknown verdict {verdict}")
        row: Dict[str, Any] = {"label": label, "passed": verdict == "pass", **facts}
        if verdict == "inconclusive":
            row["verdict"] = "inconclusive"
        self.assertions.append(row)
        return verdict

    def verdict(self) -> str:
        failed = [row for row in self.assertions if not row["passed"]]
        if not failed:
            return "pass"
        return "inconclusive" if all(row.get("verdict") == "inconclusive" for row in failed) else "fail"

    def report(self) -> Dict[str, Any]:
        return {"scenario": "survivor_rekey", "verdict": self.verdict(), "cases": self.cases,
                "limitations": self.limitations, "polls": self.polls, "assertions": self.assertions}


def rows_outcome(rows: List[Dict[str, Any]], completed: bool) -> str:
    failed = [row for row in rows if not row["passed"]]
    if any(row.get("verdict") != "inconclusive" for row in failed):
        return "failed"
    if failed:
        return "inconclusive"
    return "passed" if completed else "failed"


class Inconclusive(AssertionError):
    """A check could not be decided. Handlers record it as inconclusive, never as a failure."""


def require_all_pass(case: str, verdicts: Sequence[str]) -> None:
    """Raise Inconclusive when every non-pass verdict is inconclusive, else AssertionError."""
    bad = [verdict for verdict in verdicts if verdict != "pass"]
    if not bad:
        return
    if all(verdict == "inconclusive" for verdict in bad):
        raise Inconclusive(f"{case}: checks were inconclusive")
    raise AssertionError(f"{case}: checks did not pass")


def aborted_row(label: str, error: BaseException) -> Dict[str, Any]:
    """The row a block or harness handler records for an exception. An Inconclusive
    stays inconclusive; anything else is a failure. Class only, never str(error)."""
    row: Dict[str, Any] = {"label": label, "passed": False, "error_class": type(error).__name__}
    if isinstance(error, Inconclusive):
        row["verdict"] = "inconclusive"
    return with_poll_timeout(row, error)


def final_verdict(evidence: "RekeyEvidence", completed: bool) -> str:
    """pass | fail | inconclusive for the report and the CLI. A run with no completed
    harness or no case cannot pass, but an inconclusive run stays inconclusive."""
    verdict = evidence.verdict()
    if verdict == "pass" and not (completed and evidence.cases):
        return "fail"
    return verdict


def exit_code(verdict: str) -> int:
    return {"pass": EXIT_PASS, "inconclusive": EXIT_INCONCLUSIVE}.get(verdict, EXIT_FAIL)


# --------------------------------------------------------------------------- scenario

class RekeyScenario(PrivateScenario):
    """Reuses the private fixture's strict join readiness; adds the decrypt-based checks."""

    def __init__(self, clients: Dict[str, Any], evidence: RekeyEvidence, timeout: float = 120, *,
                 rekey_timeout: float = 120, watch_secs: float = 40, rejoin_watch_secs: float = 30,
                 restart_lead_secs: float = 15, probe_period: float = 1.0,
                 versions: Optional[Dict[str, Optional[str]]] = None,
                 journal_scan: Optional[Callable[[str, Optional[int]], Dict[str, Any]]] = None,
                 share_install_scan: Optional[Callable[[str, Optional[int], str], Dict[str, Any]]] = None,
                 remote_clock: Optional[Callable[[str], Optional[int]]] = None,
                 binary_sha: Optional[Callable[[str], Optional[str]]] = None,
                 clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        for name, value in (("timeout", timeout), ("rekey_timeout", rekey_timeout), ("watch_secs", watch_secs),
                            ("rejoin_watch_secs", rejoin_watch_secs), ("restart_lead_secs", restart_lead_secs)):
            if not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
                raise ValueError(f"{name} must be a finite positive number of seconds")
        if not math.isfinite(probe_period) or probe_period < 0:
            raise ValueError("probe_period must be finite and not negative")
        super().__init__(clients, evidence, timeout)
        self.e: RekeyEvidence = evidence
        self.rekey_timeout, self.watch_secs = rekey_timeout, watch_secs
        self.rejoin_watch_secs, self.restart_lead_secs = rejoin_watch_secs, restart_lead_secs
        self.probe_period = probe_period
        self.versions: Dict[str, Optional[str]] = dict(versions or {})
        self.journal_scan = journal_scan
        self.share_install_scan = share_install_scan
        self.remote_clock = remote_clock
        self.binary_sha = binary_sha
        self.now, self.sleep = clock, sleep
        self._aids: Dict[str, str] = {}

    def node_clock(self, node: str) -> Optional[int]:
        """The node's own clock, or None. Journal windows start here."""
        if self.remote_clock is None:
            return None
        try:
            value = self.remote_clock(node)
        except Exception:
            return None
        return value if type(value) is int else None

    # -- primitives ---------------------------------------------------------

    def aid(self, node: str) -> str:
        if node not in self._aids:
            self._aids[node] = self.c[node].agent_id()
        return self._aids[node]

    def safe_request(self, node: str, method: str, path: str,
                     body: Optional[Dict[str, Any]] = None) -> Tuple[Optional[int], Dict[str, Any]]:
        """A request whose transport failure is a None status, never an exception."""
        try:
            status, payload = self.c[node].request(method, path, body)
        except Exception:
            return None, {}
        return status, payload if isinstance(payload, dict) else {}

    def seal(self, label: str, sealer: str, gid: str, plane: str) -> Tuple[Dict[str, Any], str]:
        """Seal a fresh random message; returns (decrypt body, expected payload_b64)."""
        payload = base64.b64encode(f"x0x-rekey-{uuid.uuid4().hex}".encode()).decode()
        status, body = self.c[sealer].request("POST", f"/groups/{enc(gid)}/secure/encrypt",
                                              {"payload_b64": payload})
        sealed = sealed_from_encrypt(body) if status == 200 else None
        got = plane_of_encrypt(body) if status == 200 else None
        self.e.check(label, sealed is not None and got == plane, node=sealer, status=status,
                     plane=got, expected_plane=plane,
                     secret_epoch=sealed["secret_epoch"] if sealed else None)
        return sealed, payload  # type: ignore[return-value]

    def decrypt(self, node: str, gid: str, sealed: Dict[str, Any],
                expected: str) -> Tuple[Optional[int], str, Optional[int]]:
        try:
            status, body = self.c[node].request("POST", f"/groups/{enc(gid)}/secure/decrypt", sealed)
        except Exception as error:
            return None, f"transport:{safe_error_class(error)}", None
        cls, epoch = classify_decrypt(status, body, expected)
        return status, cls, epoch

    def await_decrypt(self, label: str, node: str, gid: str, sealed: Dict[str, Any], expected: str,
                      **context: Any) -> float:
        started = time.monotonic()

        def receipt(facts: Dict[str, Any], last: Any) -> None:
            self.e.record_poll(facts, operation="decrypt", node=node, group_id=safe_identifier(gid),
                               response_class=last[1] if isinstance(last, tuple) else None, **context)
        try:
            result = poll(label, self.timeout, lambda: self.decrypt(node, gid, sealed, expected),
                          lambda got: got[1] == "decrypted", receipt)
        except PollTimeout as error:
            self.e.assertions.append(with_poll_timeout(
                {"label": label, "passed": False, "node": node, **context}, error))
            raise
        elapsed = round(time.monotonic() - started, 3)
        self.e.check(label, True, node=node, elapsed_seconds=elapsed, secret_epoch=result[2], **context)
        return elapsed

    def await_not_active(self, label: str, observer: str, gid: str, target_aid: str) -> None:
        def receipt(facts: Dict[str, Any], _last: Any) -> None:
            self.e.record_poll(facts, operation="roster_drop", node=observer, group_id=safe_identifier(gid))
        try:
            poll(label, self.timeout,
                 lambda: self.c[observer].request("GET", f"/groups/{enc(gid)}/members"),
                 lambda got: member_is_active(got[0], got[1], target_aid) is False, receipt)
        except PollTimeout as error:
            self.e.assertions.append(with_poll_timeout({"label": label, "passed": False, "node": observer}, error))
            raise
        self.e.check(label, True, node=observer)

    def mint_invite(self, label: str, inviter: str, gid: str) -> str:
        status, body = self.c[inviter].request("POST", f"/groups/{enc(gid)}/invite", {})
        invite = body.get("invite_link") if isinstance(body, dict) else None
        self.e.check(label, status in (200, 201) and isinstance(invite, str)
                     and invite.startswith("x0x://invite/"), status=status)
        return invite  # type: ignore[return-value]

    # -- group setup --------------------------------------------------------

    def create_group(self, block: str, plane: str, owner: str) -> Tuple[str, Optional[str]]:
        """(map-key group id, stable group id or None)."""
        name = f"rekey-{plane}-{uuid.uuid4().hex[:10]}"
        request = ({"name": name, "policy": GSS_POLICY} if plane == "gss"
                   else {"name": name, "preset": "private_secure"})
        status, body = self.c[owner].request("POST", "/groups", request)
        gid = body.get("group_id") or (body.get("group") or {}).get("id")
        self.e.check(f"{block}: group created", status in (200, 201) and isinstance(gid, str) and bool(gid),
                     status=status, group_id=safe_identifier(gid))
        policy = body.get("policy") or {}
        hidden = policy.get("discoverability") == "hidden"
        self.e.check(f"{block}: group policy is MlsEncrypted on the {plane} path",
                     policy.get("confidentiality") == "mls_encrypted" and hidden == (plane == "treekem"),
                     confidentiality=policy.get("confidentiality"), discoverability=policy.get("discoverability"))
        # The stable id attributes share-install journal lines to this group.
        sstatus, state = self.safe_request(owner, "GET", f"/groups/{enc(gid)}/state")
        stable = state.get("group_id") if sstatus == 200 else None
        return gid, (stable if isinstance(stable, str) and SHA256_HEX.fullmatch(stable) else None)

    def join_member(self, block: str, plane: str, owner: str, member: str, gid: str) -> None:
        invite = self.mint_invite(f"{block}: invite for {member}", owner, gid)
        self._join_with_local_readiness(
            owner, member, gid, {"invite": invite},
            accepted_label=f"{block}: {member} join accepted",
            readiness_label=f"{block}: {member} on owner roster and locally active",
            operation="rekey_join_readiness")
        # #1214: roster + local active is not key readiness. Prove the key.
        sealed, payload = self.seal(f"{block}: remover seals post-join message for {member}", owner, gid, plane)
        self.await_decrypt(f"{block}: {member} key installed after join (decrypts post-join message)",
                           member, gid, sealed, payload, phase="join_key")

    def key_barrier(self, case: str, plane: str, sealer: str, gid: str, members: List[str]) -> int:
        sealed, payload = self.seal(f"{case}: remover seals key-barrier message", sealer, gid, plane)
        for member in members:
            self.await_decrypt(f"{case}: {member} holds the current key (decrypts barrier message)",
                               member, gid, sealed, payload, phase="barrier")
        return sealed["secret_epoch"]

    # -- the case -----------------------------------------------------------

    def restart_before_act(self, case: str, remover: str,
                           restart_fn: Callable[[str], None]) -> Tuple[float, Dict[str, Any]]:
        status, before = self.safe_request(remover, "GET", "/health")
        aid_before = self.aid(remover)
        sha_before = self.binary_sha(remover) if self.binary_sha is not None else None
        restart_fn(remover)
        restarted_at = self.now()
        poll(f"{case}: remover health after restart", 60,
             lambda: self.c[remover].request("GET", "/health"),
             lambda got: got[0] == 200 and got[1].get("ok") is True,
             lambda facts, _last: self.e.record_poll(facts, operation="health", node=remover))
        healthy_s = round(self.now() - restarted_at, 3)
        status_after, after = self.safe_request(remover, "GET", "/health")
        aid_after = self.c[remover].agent_id()
        sha_after = self.binary_sha(remover) if self.binary_sha is not None else None
        version_after = normalize_version(after.get("version")) if status_after == 200 else None
        uptime_after = after.get("uptime_secs") if status_after == 200 else None
        facts = {"health_after_restart_s": healthy_s,
                 "uptime_before_s": before.get("uptime_secs") if status == 200 else None,
                 "uptime_after_s": uptime_after, "version_after": version_after,
                 "binary_sha256_before": sha_before, "binary_sha256_after": sha_after}
        self.e.check(f"{case}: remover restarted and kept its identity",
                     aid_after == aid_before and restart_observed(uptime_after, self.now() - restarted_at),
                     node=remover, **facts)
        if self.binary_sha is not None:
            verdict = ("inconclusive" if sha_before is None or sha_after is None
                       else "pass" if sha_before == sha_after else "fail")
            require_all_pass(case, [self.e.verdict_row(f"{case}: remover runs the same binary after the restart",
                                                       verdict, node=remover, binary_sha256_before=sha_before,
                                                       binary_sha256_after=sha_after)])
        if version_after is not None:
            self.versions[remover] = version_after
        return restarted_at, facts

    def act(self, action: str, remover: str, gid: str, target_aid: str) -> Tuple[Optional[int], Dict[str, Any]]:
        method, path, body = (("DELETE", f"/groups/{enc(gid)}/members/{target_aid}", None) if action == "remove"
                              else ("POST", f"/groups/{enc(gid)}/ban/{target_aid}", {}))
        try:
            return self.c[remover].request(method, path, body, timeout=ACT_TIMEOUT_SECS)
        except Exception as error:
            return None, {"transport_error_class": safe_error_class(error)}

    def seal_after(self, case: str, action: str, plane: str, remover: str, gid: str,
                   before_epoch: int) -> Tuple[Dict[str, Any], str, int]:
        """A post-removal message at an epoch above the barrier's; retried briefly."""
        deadline = self.now() + 30
        attempts = 0
        while True:
            attempts += 1
            sealed, payload = self.seal(f"{case}: remover seals post-{action} message", remover, gid, plane)
            if sealed["secret_epoch"] > before_epoch or self.now() >= deadline:
                break
            self.sleep(1.0)
        self.e.check(f"{case}: remover secret epoch advanced past the barrier",
                     sealed["secret_epoch"] > before_epoch, epoch_before=before_epoch,
                     epoch_after=sealed["secret_epoch"], attempts=attempts)
        return sealed, payload, attempts

    def _timed_decrypt(self, node: str, gid: str, sealed: Dict[str, Any],
                       expected: str) -> Tuple[str, float, str, Optional[int]]:
        _status, cls, epoch = self.decrypt(node, gid, sealed, expected)
        return node, self.now(), cls, epoch

    def _probe_round(self, pool: concurrent.futures.Executor, tracker: RekeyTracker, nodes: List[str],
                     gid: str, sealed: Dict[str, Any], expected: str) -> None:
        started = self.now()
        futures = [pool.submit(self._timed_decrypt, node, gid, sealed, expected) for node in nodes]
        for future in concurrent.futures.as_completed(futures):
            node, at, cls, epoch = future.result()
            tracker.observe(node, at, cls, epoch)
        rest = self.probe_period - (self.now() - started)
        if rest > 0:
            self.sleep(rest)

    def converge(self, gid: str, sealed: Dict[str, Any], expected: str, survivors: List[str],
                 excluded: List[str], acted_at: float) -> RekeyTracker:
        """Round-robin: every pending survivor and every excluded node each round, then
        the excluded nodes alone for the watch window."""
        tracker = RekeyTracker(tuple(survivors), tuple(excluded), acted_at)
        deadline = acted_at + self.rekey_timeout
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(survivors) + len(excluded)) as pool:
            while tracker.pending() and self.now() < deadline and not tracker.leaked():
                self._probe_round(pool, tracker, [*tracker.pending(), *excluded], gid, sealed, expected)
            watch_until = self.now() + self.watch_secs
            while self.now() < watch_until and not tracker.leaked():
                self._probe_round(pool, tracker, list(excluded), gid, sealed, expected)
        return tracker

    def share_witness(self, plane: str, node: str, since_unix: Optional[int],
                      stable_gid: Optional[str]) -> Optional[Dict[str, Any]]:
        """Leak detection only: a GSS install line for this group proves a leak; its
        absence proves nothing."""
        if plane != "gss" or self.share_install_scan is None or stable_gid is None:
            return None
        if since_unix is None:
            return {"error_class": "no_remote_clock"}
        try:
            return self.share_install_scan(node, since_unix, stable_gid)
        except Exception as error:
            return {"error_class": safe_error_class(error)}

    def exclusion_checks(self, case: str, plane: str, action: str, target: str, tracker: RekeyTracker,
                         post_epoch: int, clocks: Dict[str, Optional[int]], stable_gid: Optional[str],
                         record: Dict[str, Any]) -> List[str]:
        verdicts: List[str] = []
        witnesses: Dict[str, Any] = {}
        evidence: Dict[str, Any] = {}
        for node, obs in tracker.exclusions.items():
            role = "target" if node == target else "departed"
            verdict, kind = exclusion_verdict(obs)
            verdicts.append(self.e.verdict_row(
                f"{case}: {node} cannot decrypt the post-{action} message", verdict, node=node, role=role,
                evidence_class=kind, probe_classes=dict(obs.classes)))
            witness = self.share_witness(plane, node, clocks.get(node), stable_gid)
            if witness is not None:
                witnesses[node] = witness
            d60, d60_class = d60_verdict(obs, post_epoch, witness)
            evidence[node] = {"decrypt": kind, "d60": d60_class, "d60_verdict": d60}
            label = f"{case}: no post-{action} key reaches {node} during the watch (D60)"
            facts = {"node": node, "role": role, "evidence_class": d60_class, "watch_seconds": self.watch_secs,
                     "observed_until_seconds": obs.summary(tracker.started)["observed_until_s"],
                     "last_class": obs.last_class, "last_epoch": obs.last_epoch,
                     "max_local_epoch": obs.max_local_epoch(), "post_epoch": post_epoch}
            if d60 == "limited":
                # Not claimed: no key evidence. A missing install line is not evidence.
                if d60_class == "epoch_unreported":
                    reason = "last answer was an epoch mismatch without the node's local epoch"
                elif plane == "treekem":
                    reason = "membership gate answers before key material; TreeKEM logs no key install"
                else:
                    reason = ("membership gate answers before key material; a missing share-install "
                              "line proves nothing (non-blocking log writer may drop lines)")
                self.e.limitations.append({"case": case, "check": label, "reason": reason, "plane": plane,
                                           **facts, "gate_evidence": d60_class, "evidence_class": "limited"})
            else:
                verdicts.append(self.e.verdict_row(label, d60, **facts))
        record["share_install_witness"] = witnesses
        record["exclusion_evidence"] = evidence
        return verdicts

    def banned_rejoin(self, case: str, plane: str, remover: str, target: str, gid: str,
                      invite: str) -> Dict[str, Any]:
        """The banned target re-joins with an invite minted before the ban."""
        status, body = self.safe_request(target, "POST", "/groups/join", {"invite": invite})
        attempt = classify_join_attempt(status, body)
        sealed, payload = self.seal(f"{case}: remover seals post-rejoin-attempt message", remover, gid, plane)
        target_aid = self.aid(target)
        obs = ExclusionObservation()
        roster_reads: List[Optional[bool]] = []
        deadline = self.now() + self.rejoin_watch_secs
        while self.now() < deadline:
            rstatus, roster = self.safe_request(remover, "GET", f"/groups/{enc(gid)}/members")
            read = member_is_active(rstatus, roster, target_aid)
            roster_reads.append(read)
            _status, cls, epoch = self.decrypt(target, gid, sealed, payload)
            obs.observe(self.now(), cls, epoch)
            if read is True or obs.leaked:
                break
            self.sleep(self.probe_period)
        join_status = classify_join_status(*self.safe_request(target, "GET", f"/groups/{enc(gid)}/join-status"))
        local = classify_local_membership(*self.safe_request(target, "GET", f"/groups/{enc(gid)}"))
        seat_verdict, seat_reason = rejoin_verdict(attempt, roster_reads, local, join_status)
        key_verdict, key_kind = exclusion_verdict(obs)
        reads = {"total": len(roster_reads), "invalid": sum(1 for r in roster_reads if r is None),
                 "active": sum(1 for r in roster_reads if r is True)}
        result = {"attempt": attempt, "join_status": join_status, "local_membership": local,
                  "roster_reads": reads, "probe_classes": dict(obs.classes),
                  "watch_seconds": self.rejoin_watch_secs, "seat_verdict": seat_verdict,
                  "seat_reason": seat_reason, "key_verdict": key_verdict}
        verdicts = [
            self.e.verdict_row(f"{case}: banned {target} re-join is never seated", seat_verdict, node=target,
                               reason=seat_reason, attempt=attempt, join_status=join_status,
                               local_membership=local, roster_reads=reads),
            self.e.verdict_row(f"{case}: banned {target} gains no key from the re-join attempt", key_verdict,
                               node=target, evidence_class=key_kind, probe_classes=dict(obs.classes)),
        ]
        require_all_pass(f"{case}: banned re-join", verdicts)
        return result

    def run_case(self, block: str, variant: str, plane: str, action: str, gid: str, remover: str,
                 target: str, survivors: List[str], restart_fn: Optional[Callable[[str], None]],
                 departed: Sequence[str] = (), stable_gid: Optional[str] = None) -> None:
        case = f"{block}/{action}"
        case_started = self.now()
        first_row = len(self.e.assertions)
        excluded = [target, *departed]
        completed = False
        record: Dict[str, Any] = {
            "case": case, "variant": variant, "plane": plane, "action": action,
            "group_id": safe_identifier(gid), "stable_group_id": stable_gid, "remover": remover,
            "target": target, "departed": list(departed), "survivors": list(survivors),
            "started_utc": utc_now(), "outcome": "failed",
            "versions": {"remover": self.versions.get(remover), "target": self.versions.get(target),
                         "departed": {node: self.versions.get(node) for node in departed},
                         "survivors": {node: self.versions.get(node) for node in survivors}},
        }
        self.e.cases.append(record)
        print(f"[rekey] {case}: remover={remover} target={target} survivors={','.join(survivors)}"
              f"{' departed=' + ','.join(departed) if departed else ''}", flush=True)
        # The remover's journal window starts at its own clock, read before anything runs.
        clocks: Dict[str, Optional[int]] = {remover: self.node_clock(remover)}
        try:
            self.e.check(f"{case}: group has at least four members before the {action}",
                         len(survivors) + 2 >= 4, members=len(survivors) + 2)
            target_aid = self.aid(target)
            record["epoch_before"] = self.key_barrier(case, plane, remover, gid, [*survivors, target])
            if plane == "gss" and self.share_install_scan is not None:
                # Each excluded node's install window starts at ITS clock, read before
                # the action, so SSH delay at scan time cannot hide an early install.
                for node in excluded:
                    clocks[node] = self.node_clock(node)
            record["node_clocks"] = dict(clocks)
            pre_ban_invite = (self.mint_invite(f"{case}: remover mints an invite before the ban", remover, gid)
                              if action == "ban" else None)
            if restart_fn is not None:
                restarted_at, record["restart"] = self.restart_before_act(case, remover, restart_fn)
                record["versions"]["remover"] = self.versions.get(remover)
                wait = restarted_at + self.restart_lead_secs - self.now()
                if wait > 0:
                    self.sleep(wait)
                lead = round(self.now() - restarted_at, 3)
                record["restart"]["lead_seconds"] = lead
                require_all_pass(case, [self.e.verdict_row(
                    f"{case}: {action} starts 10-20 s after the remover restart",
                    "pass" if restart_lead_ok(lead) else "inconclusive",
                    lead_seconds=lead, bounds=list(RESTART_LEAD_BOUNDS))])
            else:
                record["restart"] = None

            act_started = self.now()
            status, body = self.act(action, remover, gid, target_aid)
            acted_at = self.now()
            record["act"] = {"status": status, "seconds": round(acted_at - act_started, 3)}
            self.e.check(f"{case}: {action} of {target} accepted",
                         status == 200 and body.get("ok") is not False, status=status,
                         seconds=record["act"]["seconds"])

            sealed, payload, _attempts = self.seal_after(case, action, plane, remover, gid, record["epoch_before"])
            post_epoch = sealed["secret_epoch"]
            record["epoch_after"] = post_epoch
            record["seal_after_seconds"] = round(self.now() - acted_at, 3)

            tracker = self.converge(gid, sealed, payload, survivors, excluded, acted_at)
            summary = tracker.summary()
            record["rekey"] = summary
            print(f"[rekey] {case}: latency_s={summary['rekey_latency_s']} unconverged={summary['unconverged']}",
                  flush=True)
            verdicts: List[str] = []
            for node in survivors:
                latency = tracker.first_success.get(node)
                epoch = tracker.survivor_epochs.get(node)
                verdicts.append(self.e.verdict_row(
                    f"{case}: {node} rekeyed and decrypts the post-{action} message",
                    "pass" if latency is not None and (epoch is None or epoch >= post_epoch) else "fail",
                    node=node, latency_seconds=latency, secret_epoch=epoch, post_epoch=post_epoch,
                    probe_classes=summary["survivor_probe_classes"].get(node, {}),
                    version=self.versions.get(node)))
            verdicts += self.exclusion_checks(case, plane, action, target, tracker, post_epoch, clocks,
                                              stable_gid, record)
            require_all_pass(case, verdicts)

            for node in [remover, *survivors]:
                self.await_not_active(f"{case}: {node} roster no longer lists {target} as active",
                                      node, gid, target_aid)

            if plane == "gss":
                rstatus, rbody = self.safe_request(remover, "POST", f"/groups/{enc(gid)}/secure/reseal",
                                                   {"recipient": target_aid})
                reseal = classify_reseal(rstatus, rbody)
                record["reseal"] = {"status": rstatus, "response_class": reseal}
                require_all_pass(case, [self.e.verdict_row(
                    f"{case}: remover refuses to seal the current secret to {target} (recipient ineligible)",
                    reseal_verdict(reseal), status=rstatus, response_class=reseal)])

            if pre_ban_invite is not None:
                record["rejoin"] = self.banned_rejoin(case, plane, remover, target, gid, pre_ban_invite)

            final, final_payload = self.seal(f"{case}: remover seals final message", remover, gid, plane)
            for node in survivors:
                self.await_decrypt(f"{case}: {node} decrypts the final message", node, gid, final,
                                   final_payload, phase="final")
            final_verdicts = []
            for node in excluded:
                _status, cls, _epoch = self.decrypt(node, gid, final, final_payload)
                verdict, kind = single_probe_verdict(cls)
                final_verdicts.append(self.e.verdict_row(
                    f"{case}: {node} cannot decrypt the final message", verdict, node=node,
                    response_class=cls, evidence_class=kind))
            require_all_pass(case, final_verdicts)
            completed = True
        finally:
            record["outcome"] = rows_outcome(self.e.assertions[first_row:], completed)
            record["finished_utc"] = utc_now()
            record["seconds"] = round(self.now() - case_started, 3)
            if self.journal_scan is not None:
                try:
                    record["journal_remover"] = self.journal_scan(remover, clocks.get(remover))
                except Exception as error:
                    record["journal_remover"] = {"error_class": safe_error_class(error)}

    def run_block(self, variant: str, plane: str, roles: Dict[str, Any],
                  restart_fn: Optional[Callable[[str], None]]) -> None:
        block = f"{variant}/{plane}"
        remover = roles["remover"]
        joiners = [*roles["survivors"], roles["remove_target"], roles["ban_target"]]
        print(f"[rekey] {block}: creating group, {len(joiners)} joiners", flush=True)
        gid, stable_gid = self.create_group(block, plane, remover)
        for member in joiners:
            self.join_member(block, plane, remover, member, gid)
        members = [remover, *joiners]
        departed: List[str] = []
        targets = {"remove": roles["remove_target"], "ban": roles["ban_target"]}
        for action in ACTIONS:
            target = targets[action]
            survivors = [node for node in members if node not in (remover, target)]
            self.run_case(block, variant, plane, action, gid, remover, target, survivors,
                          restart_fn if variant == "restart" else None, departed=list(departed),
                          stable_gid=stable_gid)
            members.remove(target)
            departed.append(target)


# --------------------------------------------------------------------------- main

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--network", choices=["test"], required=True)
    parser.add_argument("--tokens-file", required=True)
    parser.add_argument("--hosts-json", default=None,
                        help="eph testnet-hosts.json (default: the one next to --tokens-file, if present)")
    parser.add_argument("--nodes", nargs="+", default=NODES_DEFAULT[:5],
                        help="REMOVER SURVIVOR... REMOVE_TARGET BAN_TARGET (at least five)")
    parser.add_argument("--variant", action="append", choices=VARIANTS,
                        help="repeatable; default: plain then restart")
    parser.add_argument("--plane", action="append", choices=PLANES, help="repeatable; default: gss then treekem")
    parser.add_argument("--local-port-base", type=int, default=23900)
    defaults = {"--poll-timeout": 120.0, "--rekey-timeout": 120.0, "--watch-secs": 40.0,
                "--rejoin-watch-secs": 30.0, "--restart-lead-secs": 15.0}
    for flag, default in defaults.items():
        low, high = DURATION_BOUNDS[flag]
        parser.add_argument(flag, type=bounded_seconds(flag, low, high), default=default,
                            help=f"seconds, {low:g}-{high:g} (default {default:g})")
    parser.add_argument("--expect-mixed", action="store_true",
                        help="require two or more distinct verified running binaries among --nodes "
                             "(needs the hosts file)")
    parser.add_argument("--allow-service-restart", action="store_true")
    parser.add_argument("--no-journal-scan", action="store_true")
    parser.add_argument("--report", required=True)
    return parser


def parse_and_validate(argv: Optional[List[str]] = None) -> argparse.Namespace:
    """Parse argv and check everything that needs no network. Exits 2 on a bad invocation."""
    parser = build_parser()
    args = parser.parse_args(argv)
    args.variant = args.variant or list(VARIANTS)
    args.plane = args.plane or list(PLANES)
    for name in ("variant", "plane"):
        values = getattr(args, name)
        if len(set(values)) != len(values):
            parser.error(f"each --{name} may be selected only once")
    if "restart" in args.variant and not args.allow_service_restart:
        parser.error("the restart variant requires --allow-service-restart")
    try:
        args.roles = assign_roles(args.nodes)
    except ValueError as error:
        parser.error(str(error))
    try:
        tokens = load_tokens(args.tokens_file, var_prefix="TEST")
    except OSError:
        parser.error("--tokens-file is missing or unreadable")
    missing = [node for node in args.nodes if node not in tokens]
    if missing:
        parser.error(f"missing testnet token/IP entries: {missing}")
    args.endpoints = {node: tokens[node][0] for node in args.nodes}
    args.api_tokens = {node: tokens[node][1] for node in args.nodes}
    if len(set(args.endpoints.values())) != len(args.nodes):
        parser.error("--nodes must resolve to distinct endpoints")
    path, source = resolve_hosts_json(args.hosts_json, args.tokens_file)
    args.hosts_json_source, args.hosts_json_sha256, args.node_binaries = source, None, {}
    if path is not None:
        try:
            with open(path, "rb") as handle:
                raw = handle.read()
            doc = json.loads(raw)
        except (OSError, ValueError):
            parser.error("--hosts-json is unreadable or not JSON")
        args.hosts_json_sha256 = hashlib.sha256(raw).hexdigest()
        args.node_binaries, problems = node_binary_map(doc, args.endpoints)
        if problems:
            parser.error("hosts file does not describe these nodes completely: " + "; ".join(problems))
    if args.expect_mixed and not args.node_binaries:
        parser.error("--expect-mixed needs the eph hosts file")
    return args


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_and_validate(argv)
    roles: Dict[str, Any] = args.roles
    remover = roles["remover"]
    started_utc = utc_now()
    tunnels: Dict[str, TunnelHandle] = {}
    clients: Dict[str, RekeyApi] = {}
    evidence = RekeyEvidence()
    custody = ServiceCustody(args.endpoints)
    succeeded = False
    live_versions: Dict[str, Optional[str]] = {}
    live_shas: Dict[str, Optional[str]] = {}
    start_clocks: Dict[str, Optional[int]] = {}
    journal_totals: Dict[str, Any] = {}

    def await_health(node: str) -> None:
        client = clients.get(node)
        if client is None:
            raise RuntimeError(f"no owned API client available to verify {node} health")
        poll(f"{node} health", 60, lambda: client.request("GET", "/health"),
             lambda result: result[0] == 200 and result[1].get("ok") is True)

    try:
        for index, node in enumerate(args.nodes):
            tunnel = start_ssh_tunnel(args.endpoints[node], args.local_port_base + index, remote_port=13600)
            tunnels[node] = tunnel
            clients[node] = RekeyApi(f"http://127.0.0.1:{tunnel.local_port}", args.api_tokens[node])
        identities = {node: clients[node].agent_id() for node in args.nodes}
        if len(set(identities.values())) != len(args.nodes):
            raise RuntimeError("survivor rekey requires distinct daemon agent identities")
        if "restart" in args.variant:
            custody.require_active(remover)

        for node in args.nodes:
            # Each node's own clock, read before any action: the run-wide journal window.
            start_clocks[node] = read_remote_clock(args.endpoints[node])
            status, body = clients[node].request("GET", "/health")
            live_versions[node] = normalize_version(body.get("version")) if status == 200 else None
            live_shas[node] = read_live_sha(args.endpoints[node])
        metadata = [evidence.verdict_row("live version recorded for every node",
                                         "pass" if all(live_versions.values()) else "inconclusive",
                                         versions=dict(live_versions))]
        metadata += [evidence.verdict_row(f"{node} runs the version and binary deployed to it", verdict, **facts)
                     for node, verdict, facts in binary_checks(args.node_binaries, live_versions, live_shas)]
        if args.expect_mixed:
            verdict, facts = mixed_check(args.node_binaries, live_shas)
            metadata.append(evidence.verdict_row("selected nodes run two or more distinct verified binaries",
                                                 verdict, **facts))
        require_all_pass("node metadata", metadata)

        scenario = RekeyScenario(
            clients, evidence, args.poll_timeout, rekey_timeout=args.rekey_timeout,
            watch_secs=args.watch_secs, rejoin_watch_secs=args.rejoin_watch_secs,
            restart_lead_secs=args.restart_lead_secs, versions=live_versions,
            journal_scan=None if args.no_journal_scan else lambda node, since: scan_journal(
                args.endpoints[node], since),
            share_install_scan=None if args.no_journal_scan else lambda node, since, gid: scan_share_installs(
                args.endpoints[node], since, gid),
            remote_clock=lambda node: read_remote_clock(args.endpoints[node]),
            binary_sha=lambda node: read_live_sha(args.endpoints[node]))

        def restart(node: str) -> None:
            custody.restart(node)

        for variant in args.variant:
            for plane in args.plane:
                try:
                    scenario.run_block(variant, plane, roles, restart if variant == "restart" else None)
                except Exception as error:
                    # Class only: str(error) could echo a server body or bearer token.
                    evidence.assertions.append(aborted_row(f"{variant}/{plane}: block aborted", error))
        succeeded = True
    except Exception as error:
        evidence.assertions.append(aborted_row("harness", error))
    finally:
        for error in custody.restore(await_health):
            evidence.assertions.append({"label": error, "passed": False})
            succeeded = False
        if not args.no_journal_scan:
            for node in args.nodes:
                journal_totals[node] = scan_journal(args.endpoints[node], start_clocks.get(node))
        for tunnel in list(tunnels.values()):
            try:
                stop_ssh_tunnel(tunnel)
            except Exception as error:
                evidence.assertions.append({"label": f"cleanup: {type(error).__name__}", "passed": False})
                succeeded = False
        report = evidence.report()
        running = sorted({sha for sha in live_shas.values() if sha})
        verdict = final_verdict(evidence, succeeded)
        report.update({
            "verdict": verdict, "exit_code": exit_code(verdict),
            "issue": 1216, "started_utc": started_utc, "finished_utc": utc_now(),
            "roles": roles, "variants": args.variant, "planes": args.plane,
            "settings": {"poll_timeout": args.poll_timeout, "rekey_timeout": args.rekey_timeout,
                         "watch_secs": args.watch_secs, "rejoin_watch_secs": args.rejoin_watch_secs,
                         "restart_lead_secs": args.restart_lead_secs, "expect_mixed": args.expect_mixed},
            "hosts_json_source": args.hosts_json_source, "hosts_json_sha256": args.hosts_json_sha256,
            "node_versions": {node: {"live_version": live_versions.get(node), "live_sha256": live_shas.get(node),
                                     **args.node_binaries.get(node, {"daemon_sha256": None,
                                                                     "deployed_version": None})}
                              for node in args.nodes},
            "running_binaries": running,
            "mixed_binaries": len(running) > 1 or len({v for v in live_versions.values() if v}) > 1,
            "journal_totals": journal_totals,
        })
        try:
            with open(args.report, "w", encoding="utf-8") as output:
                json.dump(report, output, indent=2)
        except Exception:
            verdict = "fail"  # no report, no evidence
    print(f"[rekey] {verdict.upper()}: {sum(1 for a in evidence.assertions if a['passed'])}/"
          f"{len(evidence.assertions)} assertions, {len(evidence.cases)} cases, "
          f"{len(evidence.limitations)} unclaimed (limited evidence)", flush=True)
    return exit_code(verdict)


if __name__ == "__main__":
    raise SystemExit(main())
