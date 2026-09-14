"""Bounded framing and reassembly for test-runner result DMs."""
from __future__ import annotations

import base64
import hashlib
import json
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Optional

RESULT_PREFIX_V1 = b"x0xtest|res|"
RESULT_PREFIX_V2 = b"x0xtest|res2|"
DM_MAX_BYTES = 49_152
CHUNK_BYTES = 24 * 1024
MAX_RESULT_BYTES = 4 * 1024 * 1024
MAX_TRANSFERS = 128
MAX_REQUESTS = 256
MAX_BUFFERED_BYTES = 16 * 1024 * 1024
MAX_TOMBSTONES = 512
MAX_IDENTIFIER_BYTES = 256
MAX_SENDERS_PER_REQUEST = 8


def compact_json(value: Dict[str, Any]) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


def frame_result(payload: bytes, transfer_id: str, request_id: str) -> list[bytes]:
    if len(payload) > MAX_RESULT_BYTES:
        raise ValueError("result exceeds bounded reassembly size")
    if (len(transfer_id.encode()) > MAX_IDENTIFIER_BYTES
            or len(request_id.encode()) > MAX_IDENTIFIER_BYTES):
        raise ValueError("result identifiers exceed framing limit")
    count = max(1, (len(payload) + CHUNK_BYTES - 1) // CHUNK_BYTES)
    digest = hashlib.sha256(payload).hexdigest()
    frames = []
    for index in range(count):
        chunk = payload[index * CHUNK_BYTES:(index + 1) * CHUNK_BYTES]
        envelope = compact_json({
            "v": 2, "transfer_id": transfer_id, "request_id": request_id,
            "index": index, "count": count, "total": len(payload),
            "sha256": digest, "data": base64.b64encode(chunk).decode("ascii"),
        })
        wire = RESULT_PREFIX_V2 + base64.b64encode(envelope)
        if len(wire) > DM_MAX_BYTES:
            raise ValueError("result chunk exceeds DM wire limit")
        frames.append(wire)
    return frames


@dataclass
class _Transfer:
    sender: str
    request_id: str
    deadline: float
    count: int
    total: int
    digest: str
    chunks: Dict[int, bytes] = field(default_factory=dict)


@dataclass
class _Request:
    senders: frozenset[str]
    deadline: float
    armed: bool


class ResultReassembler:
    def __init__(self, clock=time.monotonic, max_buffered_bytes=MAX_BUFFERED_BYTES) -> None:
        self.clock = clock
        self.requests: Dict[str, _Request] = {}
        self.transfers: Dict[tuple[str, str], _Transfer] = {}
        self.completed: Dict[tuple[str, str], float] = {}
        self.buffered = 0
        self.max_buffered_bytes = max_buffered_bytes
        self._lock = threading.RLock()

    def register(
        self, request_id: str, senders: Iterable[str], deadline: float,
    ) -> bool:
        with self._lock:
            return self._register(request_id, senders, deadline, True)

    def register_pending(
        self, request_id: str, senders: Iterable[str], dispatch_deadline: float,
    ) -> bool:
        with self._lock:
            return self._register(request_id, senders, dispatch_deadline, False)

    def _register(
        self, request_id: str, senders: Iterable[str], deadline: float, armed: bool,
    ) -> bool:
        self._prune()
        allowed = frozenset(senders)
        if (not request_id or len(request_id.encode()) > MAX_IDENTIFIER_BYTES
                or not allowed or len(allowed) > MAX_SENDERS_PER_REQUEST
                or any(len(sender.encode()) > MAX_IDENTIFIER_BYTES for sender in allowed)):
            return False
        existing = self.requests.get(request_id)
        if existing is not None:
            return existing.senders == allowed
        if request_id not in self.requests and len(self.requests) >= MAX_REQUESTS:
            oldest = min(self.requests, key=lambda key: self.requests[key].deadline)
            self.deregister(oldest)
        self.requests[request_id] = _Request(allowed, deadline, armed)
        return True

    def arm(self, request_id: str, deadline: float) -> bool:
        with self._lock:
            request = self.requests.get(request_id)
            if request is None:
                return False
            if request.armed:
                return deadline == request.deadline
            request.deadline = deadline
            request.armed = True
            for transfer in self.transfers.values():
                if transfer.request_id == request_id:
                    transfer.deadline = deadline
            return True

    def deregister(self, request_id: str) -> None:
        with self._lock:
            self.requests.pop(request_id, None)
            for key in [k for k, v in self.transfers.items() if v.request_id == request_id]:
                self._drop(key)

    def accept(self, sender: str, wire: bytes) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._accept(sender, wire)

    def _accept(self, sender: str, wire: bytes) -> Optional[Dict[str, Any]]:
        self._prune()
        if len(wire) > DM_MAX_BYTES or not wire.startswith(RESULT_PREFIX_V2):
            return None
        try:
            meta = json.loads(base64.b64decode(wire[len(RESULT_PREFIX_V2):], validate=True))
            chunk = base64.b64decode(meta["data"], validate=True)
            request_id, transfer_id = meta["request_id"], meta["transfer_id"]
            index, count, total = meta["index"], meta["count"], meta["total"]
            digest = meta["sha256"]
        except Exception:
            return None
        if (meta.get("v") != 2 or type(index) is not int or type(count) is not int
                or type(total) is not int
                or not isinstance(request_id, str) or not isinstance(transfer_id, str)
                or not isinstance(digest, str)
                or len(request_id.encode()) > MAX_IDENTIFIER_BYTES
                or len(transfer_id.encode()) > MAX_IDENTIFIER_BYTES
                or len(digest) != 64):
            return None
        request = self.requests.get(request_id)
        now = self.clock()
        if (not request or sender not in request.senders or now >= request.deadline
                or not (1 <= count <= 192) or not (0 <= index < count)
                or not (0 <= total <= MAX_RESULT_BYTES) or len(chunk) > CHUNK_BYTES):
            return None
        key = (sender, transfer_id)
        if key in self.completed:
            return None
        current = self.transfers.get(key)
        identity = (sender, request_id, request.deadline, count, total, digest)
        if current is None:
            if len(self.transfers) >= MAX_TRANSFERS:
                return None
            current = _Transfer(*identity)
            self.transfers[key] = current
        elif (current.sender, current.request_id, current.deadline, current.count,
              current.total, current.digest) != identity:
            self._drop(key)
            return None
        prior = current.chunks.get(index)
        if prior is not None:
            if prior != chunk:
                self._drop(key)
            return None
        transferred = sum(map(len, current.chunks.values()))
        if (transferred + len(chunk) > total
                or self.buffered + len(chunk) > self.max_buffered_bytes):
            self._drop(key)
            return None
        current.chunks[index] = chunk
        self.buffered += len(chunk)
        if len(current.chunks) != count:
            return None
        payload = b"".join(current.chunks[i] for i in range(count))
        self._drop(key)
        if len(payload) != total or hashlib.sha256(payload).hexdigest() != digest:
            return None
        try:
            result = json.loads(payload)
        except Exception:
            return None
        if not isinstance(result, dict) or result.get("request_id") != request_id:
            return None
        self.completed[key] = request.deadline
        if len(self.completed) > MAX_TOMBSTONES:
            oldest = min(self.completed, key=self.completed.get)
            self.completed.pop(oldest, None)
        return result

    def _drop(self, key: tuple[str, str]) -> None:
        transfer = self.transfers.pop(key, None)
        if transfer:
            self.buffered -= sum(map(len, transfer.chunks.values()))

    def _prune(self) -> None:
        now = self.clock()
        self.requests = {k: v for k, v in self.requests.items() if now < v.deadline}
        for key in [k for k, v in self.transfers.items() if now >= v.deadline]:
            self._drop(key)
        self.completed = {k: deadline for k, deadline in self.completed.items() if now < deadline}
