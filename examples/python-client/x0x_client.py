"""Typed Python client for the x0xd local REST + WebSocket API.

Standard library only. Python 3.10 or later. One file: copy it into your
project, or run it next to a local ``x0xd``.

The daemon listens on loopback (default ``http://127.0.0.1:12700``). Every
endpoint except ``GET /health`` needs the durable API token from
``<data_dir>/api-token`` (see :func:`read_api_token`).

Endpoint truth comes from the shared registry in ``src/api/mod.rs`` and from
``docs/api-reference.md``. Error bodies are ``{"ok": false, "error": <code or
prose>}`` with an optional machine-readable ``reason`` and ``detail``. Where a
``reason`` is present, match on ``reason``; ``error`` prose is not a contract,
except on ``POST /direct/send`` where ``error`` carries the documented code.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import socket
import struct
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from types import TracebackType
from typing import Any, Union
from urllib.parse import urlsplit

__all__ = [
    "AgentIdentity",
    "ApiError",
    "Connected",
    "DaemonStatus",
    "DirectMessage",
    "DirectSendError",
    "Health",
    "HealthVerdict",
    "IdempotencyConflict",
    "Live",
    "PairingDenied",
    "PayloadTooLarge",
    "RecipientKeyNotConverged",
    "RecipientNeedsUpgrade",
    "RecipientUnknown",
    "SendReceipt",
    "SendTimeout",
    "WsDirectSession",
    "WsEvent",
    "X0xClient",
    "X0xError",
    "read_api_token",
]


# ─── Errors ──────────────────────────────────────────────────────────────────


class X0xError(Exception):
    """Base class for every error this client raises deliberately."""


class ApiError(X0xError):
    """A non-2xx HTTP response from the daemon.

    ``error`` is the body's ``error`` field (a code on ``/direct/send``,
    prose elsewhere). ``reason`` is the optional machine-readable field some
    responses add; when it is present, match on it.
    """

    def __init__(
        self,
        status: int,
        error: str,
        reason: str | None = None,
        detail: str | None = None,
        body: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(f"HTTP {status}: {error}" + (f" (reason: {reason})" if reason else ""))
        self.status = status
        self.error = error
        self.reason = reason
        self.detail = detail
        self.body: dict[str, Any] = body or {}


class DirectSendError(ApiError):
    """A typed ``POST /direct/send`` failure. ``error`` holds the code."""


class RecipientUnknown(DirectSendError):
    """404 ``recipient_key_unavailable`` — no KEM key, no contact card at all.

    Import the recipient's agent card first, or wait for discovery.
    """


class RecipientKeyNotConverged(DirectSendError):
    """409 ``recipient_key_invalid`` — key view not converged yet. Retry."""


class RecipientNeedsUpgrade(DirectSendError):
    """409 ``recipient_ack_semantics_unavailable`` — the durable (v2) ACK the
    send required is not advertised by the recipient. Retry later, tell the
    user to upgrade the peer, or resend with ``require_durable_app_ack=False``.
    Do not conflate with :class:`IdempotencyConflict`.
    """


class PairingDenied(DirectSendError):
    """403 ``recipient_pairing_denied`` — the local ADR-0043 binding/placement
    gate denied the (agent, machine) pairing. Retrying fails the same way
    until the binding or placement changes.
    """


class IdempotencyConflict(DirectSendError):
    """409 ``idempotency_conflict`` — this ``logical_id`` is already bound to
    different bytes at the recipient. Retrying cannot succeed: resend the
    original bytes, or pick a new ``logical_id``.
    """


class PayloadTooLarge(DirectSendError):
    """413 ``payload_too_large`` — payload exceeds the DM envelope cap."""


class SendTimeout(DirectSendError):
    """504 ``timeout`` — the overall send budget ended the send. The DM may
    or may not have arrived; a durable resend with the same ``logical_id`` is
    the same request, not a duplicate.
    """


_DIRECT_SEND_ERRORS: dict[str, type[DirectSendError]] = {
    "recipient_key_unavailable": RecipientUnknown,
    "recipient_key_invalid": RecipientKeyNotConverged,
    "recipient_ack_semantics_unavailable": RecipientNeedsUpgrade,
    "recipient_pairing_denied": PairingDenied,
    "idempotency_conflict": IdempotencyConflict,
    "payload_too_large": PayloadTooLarge,
    "timeout": SendTimeout,
}


# ─── Response types ──────────────────────────────────────────────────────────


@dataclass(frozen=True)
class HealthVerdict:
    """The structured ``verdict`` object on ``GET /health`` (ADR 0096 §6)."""

    verdict: str
    reasons: tuple[str, ...]
    raw: dict[str, Any] = field(repr=False)


@dataclass(frozen=True)
class Health:
    """``GET /health`` — public, no token. ``status`` is ``"healthy"`` or
    ``"degraded"`` (the process is alive either way; ``ok`` stays true).
    ``verdict`` matches ``x0x doctor``; its node-specific ``inputs`` detail is
    loopback/authenticated-gated and lives in ``verdict.raw``.
    """

    ok: bool
    status: str
    version: str
    peers: int
    send_ready_peers: int
    uptime_secs: int
    degraded_reason: str | None
    verdict: HealthVerdict | None
    raw: dict[str, Any] = field(repr=False)


@dataclass(frozen=True)
class DaemonStatus:
    """``GET /status`` — bearer."""

    ok: bool
    status: str
    version: str
    uptime_secs: int
    api_address: str
    agent_id: str
    peers: int
    send_ready_peers: int
    external_addrs: tuple[str, ...]
    warnings: tuple[str, ...]
    raw: dict[str, Any] = field(repr=False)


@dataclass(frozen=True)
class AgentIdentity:
    """``GET /agent`` — the daemon's three-layer identity. Every ID is the
    SHA-256 of an ML-DSA-65 public key, as 64 lowercase hex characters.
    ``user_id`` is None unless a user key is configured (never auto-generated).
    """

    agent_id: str
    machine_id: str
    user_id: str | None
    raw: dict[str, Any] = field(repr=False)


@dataclass(frozen=True)
class SendReceipt:
    """A successful ``POST /direct/send``.

    ``path`` names the payload send strategy, not the transport that carried
    the winning ACK. With the durable default (``require_durable_app_ack``,
    on since v0.38.0), a receipt means the recipient daemon durably committed
    the message and completed local dispatch — at-least-once across a
    recipient restart, never exactly-once and never "a human read it".
    ``observed_ack_ingress`` (``"direct_typed"`` or ``"subscription"``) is the
    ACK's return transport when known; absence proves nothing.
    """

    path: str
    observed_ack_ingress: str | None
    raw: dict[str, Any] = field(repr=False)


@dataclass(frozen=True)
class DirectMessage:
    """A received DM: a ``direct_message`` frame on ``/ws/direct`` (the SSE
    row on ``/direct/events`` is the same shape). ``payload`` is the decoded
    bytes; senders choose the content format.
    """

    sender: str
    machine_id: str
    payload: bytes
    received_at: int
    verified: bool
    trust_decision: str | None
    raw: dict[str, Any] = field(repr=False)


@dataclass(frozen=True)
class Connected:
    """The first frame on every WebSocket session."""

    session_id: str
    agent_id: str


@dataclass(frozen=True)
class Live:
    """Backfill-to-live boundary marker (best-effort, not a completeness
    claim — reconcile through ``GET /history``)."""

    topic: str


WsEvent = Union[Connected, Live, DirectMessage, dict[str, Any]]
"""Parsed ``/ws/direct`` frames. Frames this module does not model
(``pong``, ``error``, future types) pass through as the raw dict."""


# ─── Helpers ─────────────────────────────────────────────────────────────────


def read_api_token(data_dir: str | Path) -> str:
    """Read the durable API token from ``<data_dir>/api-token``.

    Default data dirs: ``~/.local/share/x0x`` (Linux),
    ``~/Library/Application Support/x0x`` (macOS); ``--name NAME`` appends
    an instance suffix. Treat the token as a secret: never put it in a URL.
    """
    return (Path(data_dir) / "api-token").read_text(encoding="utf-8").strip()


def _as_obj(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise X0xError(f"expected a JSON object, got {type(value).__name__}")
    return value


def _opt_str(obj: dict[str, Any], key: str) -> str | None:
    value = obj.get(key)
    return value if isinstance(value, str) else None


def _str_tuple(obj: dict[str, Any], key: str) -> tuple[str, ...]:
    value = obj.get(key)
    if isinstance(value, list):
        return tuple(str(item) for item in value)
    return ()


def _parse_ws_event(obj: dict[str, Any]) -> WsEvent:
    kind = obj.get("type")
    if kind == "connected":
        return Connected(session_id=str(obj.get("session_id", "")), agent_id=str(obj.get("agent_id", "")))
    if kind == "live":
        return Live(topic=str(obj.get("topic", "")))
    if kind == "direct_message":
        return DirectMessage(
            sender=str(obj.get("sender", "")),
            machine_id=str(obj.get("machine_id", "")),
            payload=base64.b64decode(str(obj.get("payload", ""))),
            received_at=int(obj.get("received_at", 0)),
            verified=bool(obj.get("verified", False)),
            trust_decision=_opt_str(obj, "trust_decision"),
            raw=obj,
        )
    return obj


# ─── Minimal RFC 6455 WebSocket session ──────────────────────────────────────

_WS_ACCEPT_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class WsDirectSession:
    """A ``/ws/direct`` session: auto-receives DMs, no subscribe needed.

    Minimal RFC 6455 client over a plain socket so the example stays
    standard-library only. Text frames only (the daemon speaks JSON text).
    Use as a context manager; :meth:`recv` returns one parsed event.

    Live delivery is best-effort: expect duplicates after reconnects, carry
    your own application ID for exactly-once effects, and reconcile missed
    messages through ``GET /history``. A reader that stops draining is closed
    with code 1013 ("Try Again Later"): reconnect and reconcile.
    """

    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock
        self._buffer = b""

    def __enter__(self) -> "WsDirectSession":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def recv(self, timeout: float | None = None) -> WsEvent:
        """Return the next event. Raises ``socket.timeout`` on no frame in
        ``timeout`` seconds, :class:`X0xError` on a closed session. Protocol
        pings are answered internally and never surface.
        """
        self._sock.settimeout(timeout)
        while True:
            opcode, payload = self._read_frame()
            if opcode == 0x1:  # text
                return _parse_ws_event(_as_obj(json.loads(payload.decode("utf-8"))))
            if opcode == 0x9:  # ping → pong, carry the payload back
                self._send_frame(0xA, payload)
                continue
            if opcode == 0x8:  # close
                code = struct.unpack("!H", payload[:2])[0] if len(payload) >= 2 else 1005
                self.close()
                raise X0xError(f"WebSocket closed by daemon (code {code})")
            # Binary and unsolicited pong frames are not part of the protocol;
            # skip rather than fail so a future server addition stays harmless.

    def send_json(self, obj: dict[str, Any]) -> None:
        """Send one client command, e.g. ``{"type": "ping"}``. Note that
        ``send_direct`` over WebSocket is an internal-tier surface with v1
        receipt semantics — product sends belong on ``POST /direct/send``.
        """
        self._send_frame(0x1, json.dumps(obj).encode("utf-8"))

    def close(self) -> None:
        try:
            self._send_frame(0x8, struct.pack("!H", 1000))
        except OSError:
            pass
        try:
            self._sock.close()
        except OSError:
            pass

    # frame plumbing ──────────────────────────────────────────────────────

    def _read_exact(self, n: int) -> bytes:
        while len(self._buffer) < n:
            chunk = self._sock.recv(65536)
            if not chunk:
                raise X0xError("WebSocket connection ended unexpectedly")
            self._buffer += chunk
        out, self._buffer = self._buffer[:n], self._buffer[n:]
        return out

    def _read_frame(self) -> tuple[int, bytes]:
        """Read one message, reassembling continuation frames."""
        opcode: int | None = None
        payload = b""
        while True:
            head = self._read_exact(2)
            fin = bool(head[0] & 0x80)
            frame_opcode = head[0] & 0x0F
            masked = bool(head[1] & 0x80)
            length = head[1] & 0x7F
            if length == 126:
                length = struct.unpack("!H", self._read_exact(2))[0]
            elif length == 127:
                length = struct.unpack("!Q", self._read_exact(8))[0]
            mask = self._read_exact(4) if masked else b""
            data = self._read_exact(length)
            if masked:
                data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
            if frame_opcode in (0x8, 0x9, 0xA):  # control frames never fragment
                return frame_opcode, data
            if frame_opcode != 0x0:
                opcode = frame_opcode
            payload += data
            if fin:
                if opcode is None:
                    raise X0xError("WebSocket continuation frame without a start")
                return opcode, payload

    def _send_frame(self, opcode: int, payload: bytes) -> None:
        mask = secrets.token_bytes(4)
        head = bytes([0x80 | opcode])
        if len(payload) < 126:
            head += bytes([0x80 | len(payload)])
        elif len(payload) < 1 << 16:
            head += bytes([0x80 | 126]) + struct.pack("!H", len(payload))
        else:
            head += bytes([0x80 | 127]) + struct.pack("!Q", len(payload))
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self._sock.sendall(head + mask + masked)


# ─── Client ──────────────────────────────────────────────────────────────────


class X0xClient:
    """A typed client for one local x0xd instance.

    >>> client = X0xClient("http://127.0.0.1:12700", token=read_api_token(data_dir))
    >>> client.health().status
    'healthy'
    """

    def __init__(self, base_url: str, token: str | None = None, timeout: float = 10.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    # core endpoints ──────────────────────────────────────────────────────

    def health(self) -> Health:
        """``GET /health`` — public. The ``verdict`` matches ``x0x doctor``."""
        body = self._request("GET", "/health", auth=False)
        verdict_raw = body.get("verdict")
        verdict = None
        if isinstance(verdict_raw, dict):
            verdict = HealthVerdict(
                verdict=str(verdict_raw.get("verdict", "")),
                reasons=_str_tuple(verdict_raw, "reasons"),
                raw=verdict_raw,
            )
        return Health(
            ok=bool(body.get("ok", False)),
            status=str(body.get("status", "")),
            version=str(body.get("version", "")),
            peers=int(body.get("peers", 0)),
            send_ready_peers=int(body.get("send_ready_peers", 0)),
            uptime_secs=int(body.get("uptime_secs", 0)),
            degraded_reason=_opt_str(body, "degraded_reason"),
            verdict=verdict,
            raw=body,
        )

    def status(self) -> DaemonStatus:
        """``GET /status`` — connection summary, agent id, warnings."""
        body = self._request("GET", "/status")
        return DaemonStatus(
            ok=bool(body.get("ok", False)),
            status=str(body.get("status", "")),
            version=str(body.get("version", "")),
            uptime_secs=int(body.get("uptime_secs", 0)),
            api_address=str(body.get("api_address", "")),
            agent_id=str(body.get("agent_id", "")),
            peers=int(body.get("peers", 0)),
            send_ready_peers=int(body.get("send_ready_peers", 0)),
            external_addrs=_str_tuple(body, "external_addrs"),
            warnings=_str_tuple(body, "warnings"),
            raw=body,
        )

    def agent(self) -> AgentIdentity:
        """``GET /agent`` — the local agent identity."""
        body = self._request("GET", "/agent")
        return AgentIdentity(
            agent_id=str(body.get("agent_id", "")),
            machine_id=str(body.get("machine_id", "")),
            user_id=_opt_str(body, "user_id"),
            raw=body,
        )

    def agent_card_link(self, include_local_addresses: bool = False) -> str:
        """``GET /agent/card`` — a shareable, signed identity card, returned
        as its ``x0x://agent/...`` link (the form ``import_agent_card`` takes;
        the response's structured ``card`` object is in the raw body).

        ``include_local_addresses=True`` adds loopback/RFC1918 addresses; use
        it only for local testnet cards, never for cards you share.
        """
        path = "/agent/card"
        if include_local_addresses:
            path += "?include_local_addresses=true"
        body = self._request("GET", path)
        link = body.get("link")
        if not isinstance(link, str):
            raise X0xError("GET /agent/card returned no card link")
        return link

    def import_agent_card(self, card: str, trust_level: str | None = None) -> dict[str, Any]:
        """``POST /agent/card/import`` — verify a card (an ``x0x://agent/...``
        link or raw base64) and add it to contacts.

        Never raises trust: the floor is the existing level, Blocked is sticky.
        ``trust_level`` defaults to ``"known"`` daemon-side.
        """
        request: dict[str, Any] = {"card": card}
        if trust_level is not None:
            request["trust_level"] = trust_level
        return self._request("POST", "/agent/card/import", body=request)

    def connect(self, agent_id: str) -> dict[str, Any]:
        """``POST /agents/connect`` — establish a direct connection."""
        return self._request("POST", "/agents/connect", body={"agent_id": agent_id})

    def send_dm(
        self,
        agent_id: str,
        payload: bytes,
        *,
        durable: bool = True,
        logical_id: str | None = None,
    ) -> SendReceipt:
        """``POST /direct/send`` — send a direct message.

        ``durable=True`` (the daemon default since v0.38.0): a receipt means
        the recipient durably committed the message. ``logical_id`` (durable
        only; ``[a-z0-9._:-]``, 1–128 chars) makes a resend after a timeout or
        restart the *same* request instead of a duplicate.

        Raises a :class:`DirectSendError` subclass on the documented codes —
        see each class's docstring for the repair it prescribes. The two 409s
        differ: :class:`RecipientNeedsUpgrade` means retry later or downgrade
        deliberately; :class:`IdempotencyConflict` means retrying can never
        succeed.
        """
        request: dict[str, Any] = {
            "agent_id": agent_id,
            "payload": base64.b64encode(payload).decode("ascii"),
        }
        if not durable:
            request["require_durable_app_ack"] = False
        if logical_id is not None:
            request["logical_id"] = logical_id
        try:
            body = self._request("POST", "/direct/send", body=request)
        except ApiError as exc:
            mapped = _DIRECT_SEND_ERRORS.get(exc.reason or exc.error)
            if mapped is not None:
                raise mapped(exc.status, exc.error, exc.reason, exc.detail, exc.body) from None
            raise DirectSendError(exc.status, exc.error, exc.reason, exc.detail, exc.body) from None
        return SendReceipt(
            path=str(body.get("path", "")),
            observed_ack_ingress=_opt_str(body, "observed_ack_ingress"),
            raw=body,
        )

    def ws_direct(self, backfill: int | None = None) -> WsDirectSession:
        """Open ``GET /ws/direct`` — a WebSocket session that auto-receives
        DMs as :class:`DirectMessage` events (first event: :class:`Connected`).

        ``backfill=N`` requests up to N stored DM rows before a :class:`Live`
        marker — best-effort, not a completeness claim.

        The token rides the ``Authorization`` header, never the URL (the
        ``?token=`` query form exists only for browser session tokens).
        """
        if self.token is None:
            raise X0xError("ws_direct requires the API token")
        parts = urlsplit(self.base_url)
        if parts.scheme != "http" or parts.hostname is None:
            raise X0xError(f"unsupported base URL for WebSocket: {self.base_url}")
        path = "/ws/direct" + (f"?backfill={backfill}" if backfill is not None else "")
        key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
        sock = socket.create_connection(
            (parts.hostname, parts.port or 80), timeout=self.timeout
        )
        try:
            handshake = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {parts.netloc}\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {key}\r\n"
                "Sec-WebSocket-Version: 13\r\n"
                f"Authorization: Bearer {self.token}\r\n"
                "\r\n"
            )
            sock.sendall(handshake.encode("ascii"))
            response = b""
            while b"\r\n\r\n" not in response:
                chunk = sock.recv(65536)
                if not chunk:
                    raise X0xError("daemon closed the connection during the WebSocket handshake")
                response += chunk
            head, _, rest = response.partition(b"\r\n\r\n")
            status_line = head.split(b"\r\n", 1)[0].decode("ascii", "replace")
            if " 101 " not in f"{status_line} ":
                raise X0xError(f"WebSocket upgrade refused: {status_line}")
            expected = base64.b64encode(
                hashlib.sha1((key + _WS_ACCEPT_GUID).encode("ascii")).digest()
            ).decode("ascii")
            accept = ""
            for line in head.decode("ascii", "replace").split("\r\n")[1:]:
                name, _, value = line.partition(":")
                if name.strip().lower() == "sec-websocket-accept":
                    accept = value.strip()
            if accept != expected:
                raise X0xError("WebSocket handshake failed: bad Sec-WebSocket-Accept")
        except BaseException:
            sock.close()
            raise
        session = WsDirectSession(sock)
        session._buffer = rest  # bytes that arrived with the handshake reply
        return session

    # plumbing ────────────────────────────────────────────────────────────

    def _request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        auth: bool = True,
    ) -> dict[str, Any]:
        headers = {"Accept": "application/json"}
        if auth:
            if self.token is None:
                raise X0xError(f"{method} {path} requires the API token")
            headers["Authorization"] = f"Bearer {self.token}"
        data: bytes | None = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode("utf-8")
        request = urllib.request.Request(
            self.base_url + path, data=data, method=method, headers=headers
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return _as_obj(json.load(response))
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                parsed = _as_obj(json.loads(raw))
            except (ValueError, X0xError):
                parsed = {"ok": False, "error": raw.decode("utf-8", "replace")}
            raise ApiError(
                status=exc.code,
                error=str(parsed.get("error", "")),
                reason=_opt_str(parsed, "reason"),
                detail=_opt_str(parsed, "detail"),
                body=parsed,
            ) from None
        except urllib.error.URLError as exc:
            raise X0xError(f"{method} {self.base_url}{path} failed: {exc.reason}") from None
