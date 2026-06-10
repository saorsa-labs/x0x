#!/usr/bin/env python3
"""x0x cross-daemon TreeKEM membership-churn harness (ADR-0012 Phase 3).

Validates the *real* TreeKEM secure-group membership transport across live
testnet daemons — the surface the local single-host harness and the
steady-state launch soak both cannot exercise (the former lacks direct-DM
connectivity between local daemons; the latter never touches TreeKEM).

One churn iteration, driven over SSH tunnels to each node's local API
(127.0.0.1:13600 by default — testnet; prod requires --network prod + banner):

  1. anchor creates a private_secure group  -> resolves to TreeKem plane
  2. anchor mints an invite
  3. member JOINs via invite (daemon auto-mints the joiner's per-group
     KeyPackage, publishes the signed MemberJoined; owner add_member ->
     MemberAdded{Commit,Welcome,epoch}; member joins from Welcome)
  4. poll until the member is Active in the anchor's roster
  5. cross-daemon secure round-trip BOTH directions via /secure/encrypt|decrypt
     (asserts secure_plane == "treekem")
  6. anchor BANs the member (= verified TreeKEM removal + epoch advance)
  7. forward-secrecy check: a post-ban anchor ciphertext must NOT decrypt for
     the banned member
  8. anchor deletes the group (cleanup)

Membership ops await direct-DM delivery server-side, so per-call HTTP timeouts
are deliberately generous and convergence is polled rather than assumed.

Usage::

    python3 tests/e2e_treekem_membership.py --anchor nyc --member sfo \
        --iterations 1
    # soak: loop many iterations, report per-iteration + cumulative
    python3 tests/e2e_treekem_membership.py --anchor nyc --member sfo \
        --iterations 200 --settle-secs 90
"""
from __future__ import annotations

import argparse
import base64
import json
import logging
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

LOG = logging.getLogger("treekem_membership")
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)


# ─── token-file parsing (mirrors tests/e2e_vps_groups.py) ───────────────
def load_tokens(path: str, var_prefix: str) -> Dict[str, Tuple[str, str]]:
    import re
    if not os.path.isfile(path):
        raise FileNotFoundError(f"token file not found: {path}")
    ips: Dict[str, str] = {}
    toks: Dict[str, str] = {}
    pat = re.compile(r'^' + re.escape(var_prefix) + r'_([A-Z]+)_(IP|TK)="?([^"]+)"?\s*$')
    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            m = pat.match(raw.strip())
            if not m:
                continue
            n, kind, value = m.group(1).lower(), m.group(2), m.group(3)
            (ips if kind == "IP" else toks)[n] = value
    return {n: (ips[n], toks[n]) for n in ips if n in toks}


# ─── HTTP client ────────────────────────────────────────────────────────
class ApiError(Exception):
    def __init__(self, status: int, body: str) -> None:
        super().__init__(f"HTTP {status}: {body[:200]}")
        self.status = status
        self.body = body


class X0xClient:
    def __init__(self, base_url: str, token: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token

    def req(self, method: str, path: str, body: Optional[Dict[str, Any]] = None,
            timeout: float = 60.0) -> Dict[str, Any]:
        data = None if body is None else json.dumps(body).encode("utf-8")
        r = urllib.request.Request(
            self.base_url + path, data=data, method=method,
            headers={"Authorization": f"Bearer {self.token}",
                     "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(r, timeout=timeout) as resp:
                return json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as e:
            raise ApiError(e.code, e.read().decode("utf-8", "replace")) from e


# ─── SSH tunnel (mirrors tests/e2e_vps_groups.py) ───────────────────────
@dataclass
class Tunnel:
    proc: subprocess.Popen
    local_port: int


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def start_tunnel(ip: str, remote_port: int = 13600) -> Tunnel:
    if shutil.which("ssh") is None:
        raise RuntimeError("ssh not on PATH")
    local = _free_port()
    proc = subprocess.Popen(
        ["ssh", "-N",
         "-o", "ConnectTimeout=10", "-o", "BatchMode=yes",
         "-o", "ExitOnForwardFailure=yes", "-o", "ControlMaster=no",
         "-o", "ControlPath=none", "-o", "StrictHostKeyChecking=accept-new",
         # Keepalive so a long-running soak survives idle gaps and a genuinely
         # dead connection exits promptly (the soak wrapper then reconnects).
         "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=4",
         "-L", f"{local}:127.0.0.1:{remote_port}", f"root@{ip}"],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    base = f"http://127.0.0.1:{local}"
    for _ in range(30):
        if proc.poll() is not None:
            err = proc.stderr.read().decode("utf-8", "replace") if proc.stderr else ""
            raise RuntimeError(f"ssh tunnel to {ip} exited: {err}")
        try:
            urllib.request.urlopen(f"{base}/health", timeout=2)
            return Tunnel(proc=proc, local_port=local)
        except Exception:
            time.sleep(0.5)
    proc.terminate()
    raise RuntimeError(f"ssh tunnel to {ip}:{remote_port} not ready in 15s")


def stop_tunnel(t: Tunnel) -> None:
    t.proc.terminate()
    try:
        t.proc.wait(timeout=5)
    except Exception:
        t.proc.kill()


# ─── churn scenario ─────────────────────────────────────────────────────
@dataclass
class IterResult:
    ok: bool
    step: str = "complete"
    detail: str = ""
    timings: Dict[str, float] = field(default_factory=dict)


def _poll_member_active(anchor: X0xClient, gid: str, member_agent: str,
                        settle_secs: float) -> bool:
    deadline = time.monotonic() + settle_secs
    while time.monotonic() < deadline:
        try:
            members = anchor.req("GET", f"/groups/{gid}/members",
                                 timeout=10.0).get("members", [])
            for m in members:
                if m.get("agent_id", "").lower() == member_agent.lower() and \
                        str(m.get("state", "")).lower() == "active":
                    return True
        except Exception:  # slow call / transient — keep polling until settle
            pass
        time.sleep(3.0)
    return False


def _tk_encrypt(client: X0xClient, gid: str, text: str) -> str:
    """Encrypt and ASSERT the TreeKEM plane (catches silent GSS fallback)."""
    r = client.req("POST", f"/groups/{gid}/secure/encrypt",
                   body={"payload_b64": base64.b64encode(text.encode()).decode()})
    if r.get("secure_plane") != "treekem":
        raise AssertionError(f"encrypt secure_plane={r.get('secure_plane')!r}, want treekem")
    return r.get("ciphertext_b64", "")


def _tk_decrypt(client: X0xClient, gid: str, ct: str) -> str:
    """Decrypt and ASSERT the TreeKEM plane; returns the recovered plaintext."""
    r = client.req("POST", f"/groups/{gid}/secure/decrypt", body={"ciphertext_b64": ct})
    if r.get("secure_plane") != "treekem":
        raise AssertionError(f"decrypt secure_plane={r.get('secure_plane')!r}, want treekem")
    return base64.b64decode(r.get("payload_b64", "")).decode("utf-8", "replace")


def _poll_member_in_tree(member: X0xClient, gid: str, settle_secs: float) -> bool:
    """Member is genuinely in the TreeKEM tree iff it can encrypt on the TreeKEM
    plane (treekem_group_encrypt requires the live group to be loaded — proving
    the Welcome was received+processed, not just that the anchor's roster row
    flipped Active)."""
    deadline = time.monotonic() + settle_secs
    while time.monotonic() < deadline:
        try:
            r = member.req("POST", f"/groups/{gid}/secure/encrypt", timeout=10.0,
                           body={"payload_b64": base64.b64encode(b"probe").decode()})
            if r.get("secure_plane") == "treekem":
                return True
        except Exception:  # slow call / not-yet-joined — keep polling
            pass
        time.sleep(3.0)
    return False


def _invite_join_converge(anchor: X0xClient, gid: str, member: X0xClient,
                          member_agent: str, settle_secs: float, idx: int,
                          tag: str, timed) -> Optional[IterResult]:
    """Mint an invite, join `member`, and converge it into the anchor roster AND
    the TreeKEM tree. Returns None on success, or a failing IterResult.

    `tag` distinguishes timing/step labels per member (e.g. "m1", "m2") so a
    multi-member iteration's steps don't collide. The second+ member exercises
    exactly the path 0.21.0 repaired: a new joiner converging while an earlier
    member is already Active (a stale-clone GroupInfo overwrite used to drop the
    new joiner's invite -> invite_secret_unknown -> never converges)."""
    inv = timed(f"invite_{tag}", lambda: anchor.req(
        "POST", f"/groups/{gid}/invite", body={}))
    link = inv.get("invite_link") or inv.get("invite") or ""
    if not link:
        return IterResult(False, f"invite_{tag}", f"no invite link: {inv}")
    timed(f"join_{tag}", lambda: member.req(
        "POST", "/groups/join", body={"invite": link, "display_name": f"{tag}-{idx}"}))
    if not timed(f"converge_roster_{tag}", lambda: _poll_member_active(
            anchor, gid, member_agent, settle_secs)):
        return IterResult(False, f"converge_roster_{tag}",
                          f"{tag} not Active in anchor roster")
    if not timed(f"converge_member_{tag}", lambda: _poll_member_in_tree(
            member, gid, settle_secs)):
        return IterResult(False, f"converge_member_{tag}",
                          f"{tag} never joined the TreeKEM tree (Welcome not processed)")
    return None


def run_iteration(anchor: X0xClient, member: X0xClient, member_agent: str,
                  settle_secs: float, idx: int,
                  member2: Optional[X0xClient] = None,
                  member2_agent: str = "") -> IterResult:
    t: Dict[str, float] = {}
    gid = ""
    cur = {"step": "start"}

    def timed(label: str, fn):
        cur["step"] = label
        s = time.monotonic()
        out = fn()
        t[label] = round(time.monotonic() - s, 2)
        return out

    try:
        # 1. anchor creates a private_secure (TreeKem) group
        created = timed("create", lambda: anchor.req(
            "POST", "/groups",
            body={"name": f"tk-churn-{idx}", "preset": "private_secure"}))
        gid = created.get("group_id", "")
        if not gid:
            return IterResult(False, "create", f"no group_id: {created}", t)

        # 2-4. first member: invite -> join -> converge (roster + tree)
        fail = _invite_join_converge(
            anchor, gid, member, member_agent, settle_secs, idx, "m1", timed)
        if fail:
            fail.timings = t
            return fail

        # 4c. MULTI-MEMBER (the 0.21.0 fix surface): add a SECOND member while
        #     the first is already Active. Then re-confirm the first is STILL
        #     Active in the anchor roster (a second add must not clobber it).
        if member2 is not None:
            fail = _invite_join_converge(
                anchor, gid, member2, member2_agent, settle_secs, idx, "m2", timed)
            if fail:
                fail.timings = t
                return fail
            if not timed("m1_still_active", lambda: _poll_member_active(
                    anchor, gid, member_agent, settle_secs)):
                return IterResult(False, "m1_still_active",
                                  "first member dropped from roster after second add", t)

        # 5. cross-daemon secure round-trip, asserting the treekem plane on every
        #    leg (no silent GSS fallback). anchor<->m1 both ways; with m2 present,
        #    anchor<->m2 and m1<->m2 too (all members share the same epoch tree).
        msg_am = f"a->m1 #{idx}"
        if timed("m1_decrypt", lambda: _tk_decrypt(
                member, gid, _tk_encrypt(anchor, gid, msg_am))) != msg_am:
            return IterResult(False, "m1_decrypt", "a->m1 payload mismatch", t)
        msg_ma = f"m1->a #{idx}"
        if timed("anchor_decrypt", lambda: _tk_decrypt(
                anchor, gid, _tk_encrypt(member, gid, msg_ma))) != msg_ma:
            return IterResult(False, "anchor_decrypt", "m1->a payload mismatch", t)
        if member2 is not None:
            msg_am2 = f"a->m2 #{idx}"
            if timed("m2_decrypt", lambda: _tk_decrypt(
                    member2, gid, _tk_encrypt(anchor, gid, msg_am2))) != msg_am2:
                return IterResult(False, "m2_decrypt", "a->m2 payload mismatch", t)
            msg_m12 = f"m1->m2 #{idx}"
            if timed("m1_to_m2", lambda: _tk_decrypt(
                    member2, gid, _tk_encrypt(member, gid, msg_m12))) != msg_m12:
                return IterResult(False, "m1_to_m2", "m1->m2 payload mismatch", t)

        # 6. ban the LAST-added member (m2 if present, else m1): verified TreeKEM
        #    removal + epoch advance.
        ban_target = member2_agent if member2 is not None else member_agent
        banned_client = member2 if member2 is not None else member
        ban_tag = "m2" if member2 is not None else "m1"
        timed("ban", lambda: anchor.req(
            "POST", f"/groups/{gid}/ban/{ban_target}", body={}))

        # 6b. with a second member present, the NON-banned member (m1) must
        #     survive the ban — still Active and still able to encrypt on the
        #     post-ban epoch tree (epoch advanced under it without eviction).
        if member2 is not None:
            if not timed("m1_survives_ban", lambda: _poll_member_in_tree(
                    member, gid, settle_secs)):
                return IterResult(False, "m1_survives_ban",
                                  "non-banned member lost the TreeKEM tree after ban", t)

        # 7. forward secrecy: the banned member was PROVEN in-tree above, so a
        #    post-ban failure to decrypt fresh anchor content is genuine FS, not
        #    "never joined". Poll: a LEAK = banned member recovers the matching
        #    plaintext at any point; any error/non-match = FS holding.
        def fs_check() -> Optional[str]:
            deadline = time.monotonic() + min(settle_secs, 45.0)
            n = 0
            while time.monotonic() < deadline:
                secret = f"post-ban #{idx}-{n}"
                ct = _tk_encrypt(anchor, gid, secret)  # anchor at post-ban epoch
                try:
                    if _tk_decrypt(banned_client, gid, ct) == secret:
                        return f"banned member ({ban_tag}) decrypted post-ban content"
                except (ApiError, AssertionError):
                    pass  # rejection / not-loaded = FS holds (member is out)
                n += 1
                time.sleep(3.0)
            return None
        leak = timed("forward_secrecy", fs_check)
        if leak:
            return IterResult(False, "forward_secrecy", leak, t)

        return IterResult(True, "complete", "", t)
    except ApiError as e:
        return IterResult(False, cur["step"], f"HTTP {e.status}: {e.body[:160]}", t)
    except Exception as e:  # network/tunnel/parse — keep the soak loop alive
        return IterResult(False, cur["step"], f"{type(e).__name__}: {e}", t)
    finally:
        if gid:
            try:
                anchor.req("DELETE", f"/groups/{gid}", timeout=60.0)
            except Exception:
                pass


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Cross-daemon TreeKEM membership churn")
    p.add_argument("--network", choices=["test", "prod"], default="test")
    p.add_argument("--tokens-file", default=None)
    p.add_argument("--anchor", default="nyc")
    p.add_argument("--member", default="sfo")
    p.add_argument("--member2", default=None,
                   help="optional second member node — exercises multi-member "
                        "TreeKEM convergence (the 0.21.0 fix surface)")
    p.add_argument("--iterations", type=int, default=1)
    p.add_argument("--settle-secs", type=float, default=90.0,
                   help="max time to wait for cross-daemon membership convergence")
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s")

    from x0x_network import select_network, banner  # type: ignore
    net = select_network(args)
    banner(net)
    tokens_path = args.tokens_file or str(net.token_file)
    tokens = load_tokens(tokens_path, var_prefix=net.var_prefix)
    roles = [("anchor", args.anchor), ("member", args.member)]
    if args.member2:
        roles.append(("member2", args.member2))
    for role, name in roles:
        if name not in tokens:
            LOG.error("no token/IP for %s node %r in %s", role, name, tokens_path)
            return 2

    a_ip, a_tok = tokens[args.anchor]
    m_ip, m_tok = tokens[args.member]
    a_tun = m_tun = m2_tun = None
    try:
        LOG.info("opening tunnels: anchor=%s member=%s%s", args.anchor, args.member,
                 f" member2={args.member2}" if args.member2 else "")
        a_tun = start_tunnel(a_ip)
        m_tun = start_tunnel(m_ip)
        anchor = X0xClient(f"http://127.0.0.1:{a_tun.local_port}", a_tok)
        member = X0xClient(f"http://127.0.0.1:{m_tun.local_port}", m_tok)
        member_agent = member.req("GET", "/agent").get("agent_id", "")
        if not member_agent:
            LOG.error("could not resolve member agent_id")
            return 2

        member2 = None
        member2_agent = ""
        if args.member2:
            m2_ip, m2_tok = tokens[args.member2]
            m2_tun = start_tunnel(m2_ip)
            member2 = X0xClient(f"http://127.0.0.1:{m2_tun.local_port}", m2_tok)
            member2_agent = member2.req("GET", "/agent").get("agent_id", "")
            if not member2_agent:
                LOG.error("could not resolve member2 agent_id")
                return 2

        passed = 0
        for i in range(1, args.iterations + 1):
            r = run_iteration(anchor, member, member_agent, args.settle_secs, i,
                              member2=member2, member2_agent=member2_agent)
            if r.ok:
                passed += 1
                LOG.info("iter %d/%d PASS  timings=%s", i, args.iterations, r.timings)
            else:
                LOG.error("iter %d/%d FAIL @%s: %s  timings=%s",
                          i, args.iterations, r.step, r.detail, r.timings)
        LOG.info("=== TreeKEM membership churn: %d/%d passed ===",
                 passed, args.iterations)
        return 0 if passed == args.iterations else 1
    finally:
        if a_tun:
            stop_tunnel(a_tun)
        if m_tun:
            stop_tunnel(m_tun)
        if m2_tun:
            stop_tunnel(m2_tun)


if __name__ == "__main__":
    raise SystemExit(main())
