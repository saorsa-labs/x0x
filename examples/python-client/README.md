# x0x Python client example

A typed Python client for the `x0xd` local REST + WebSocket API, in one
file with no dependencies outside the standard library (Python 3.10+).
This is the "any agent that sees x0x knows how to use it" example
(ADR 0095): copy `x0x_client.py` into your project and talk to a local
daemon.

| File | What it is |
|---|---|
| `x0x_client.py` | The client: typed wrappers for health, status, identity, agent cards, connect, direct send, and a `/ws/direct` WebSocket subscription. Typed exceptions for the documented `/direct/send` error codes. |
| `demo.py` | Runnable proof: boots two hermetic loopback daemons, A sends B a DM, B receives it on its WebSocket subscription. |

Endpoint truth comes from the shared registry in [`src/api/mod.rs`](../../src/api/mod.rs)
and [`docs/api-reference.md`](../../docs/api-reference.md). Read the API
reference for everything the client does not wrap (groups, KV stores,
task lists, history, files).

## Run the demo

From the repository root:

```bash
cargo build --bin x0xd
python3 examples/python-client/demo.py
```

Expected output ends with:

```text
B received the DM from <agent-id>… (verified=True): 'hello from agent A via the typed Python client'
PASS
```

Options: `--x0xd <path>` (default `target/debug/x0xd`), `--api-port-a` /
`--api-port-b` (defaults 24710/24711; QUIC ports are API+100),
`--keep-work-dir` to keep logs and data directories.

### Network isolation

The demo daemons never join the real x0x network: both run with
`--no-hard-coded-bootstrap`, a loopback-only `bind_address`, mDNS off, and
daemon B's only bootstrap peer is daemon A's loopback address — the same
hermetic pattern as `tests/e2e_local_mesh.sh`. In CI the demo also runs
inside the loopback-only network namespace of
`scripts/ci/isolated-runtime.py`, as `tests/AGENTS.md` requires for
anything that starts a daemon.

## Use the client against your own daemon

```python
from x0x_client import X0xClient, read_api_token

# Default data dirs: ~/.local/share/x0x (Linux),
# ~/Library/Application Support/x0x (macOS).
client = X0xClient("http://127.0.0.1:12700", token=read_api_token(data_dir))

print(client.health().status)        # "healthy" — GET /health, no token needed
print(client.status().peers)         # GET /status
me = client.agent()                  # GET /agent — agent_id / machine_id / user_id

# Send a DM (durable receipt by default: 200 = recipient committed it).
receipt = client.send_dm(peer_agent_id, b"hello", logical_id="my-app:greeting:1")

# Receive DMs.
with client.ws_direct() as sub:
    event = sub.recv(timeout=30.0)   # Connected, then DirectMessage events
```

Error handling: HTTP failures raise `ApiError` (`status`, `error`,
`reason`, `detail`). `send_dm` raises typed subclasses for the documented
codes — `RecipientUnknown`, `RecipientKeyNotConverged`,
`RecipientNeedsUpgrade`, `PairingDenied`, `IdempotencyConflict`,
`PayloadTooLarge`, `SendTimeout`. The two 409s prescribe opposite repairs:
`RecipientNeedsUpgrade` means retry later or deliberately resend with
`durable=False`; `IdempotencyConflict` means a retry can never succeed.

Delivery semantics worth knowing before you build on this (details in the
API reference):

- A durable send receipt is at-least-once across a recipient restart,
  never exactly-once. Dedupe on your own application ID, and pass a
  `logical_id` so your retries are recognised as the same request.
- Live WebSocket delivery is best-effort. Expect duplicates after a
  reconnect, and reconcile missed messages through `GET /history`.
- The token rides the `Authorization` header, never a URL.

## Checks

CI (`.github/workflows/python-client-example.yml`) runs `ruff check`,
`mypy --strict`, and the demo end-to-end on Linux. Locally:

```bash
ruff check examples/python-client
mypy --strict examples/python-client
```
