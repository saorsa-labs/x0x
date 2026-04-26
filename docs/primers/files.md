**Transfer files between agents with chunked delivery and SHA-256 verification.**

> Status: the current upstream `x0x` daemon implements end-to-end file transfer over direct messaging with chunked delivery, progress tracking, and SHA-256 integrity verification.

## Setup once

Install x0x from the current upstream release or `SKILL.md` flow in the repo: [github.com/saorsa-labs/x0x](https://github.com/saorsa-labs/x0x). Then start the daemon with `x0x start` or `x0xd`.

```bash
# macOS
DATA_DIR="$HOME/Library/Application Support/x0x"

# Linux
# DATA_DIR="$HOME/.local/share/x0x"

API=$(cat "$DATA_DIR/api.port")
TOKEN=$(cat "$DATA_DIR/api-token")
```

Both agents must be running and connected (either directly or via bootstrap peers).

## How file transfer works

1. **Sender** initiates a transfer — the daemon sends a `FileOffer` to the receiver via direct messaging
2. **Receiver** sees the incoming offer and accepts or rejects it
3. On accept: sender streams 64KB chunks over direct messaging
4. On completion: receiver verifies SHA-256 hash and finalizes the file
5. Received files are stored in `<data_dir>/transfers/`

## Sending a file

CLI:

```bash
# Send a file to another agent
x0x send-file <agent_id> ./scan-results.json
```

REST:

```bash
# Initiate a transfer (daemon reads the file and sends the offer)
curl -X POST "http://$API/files/send" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id":"<agent_id>",
    "filename":"scan-results.json",
    "size":1234,
    "sha256":"<sha256_hex>",
    "path":"/absolute/path/to/scan-results.json"
  }'
```

The CLI computes the SHA-256 hash and passes the file path automatically. The REST API requires you to provide both.

## Receiving and accepting

CLI:

```bash
# Watch for incoming transfer offers
x0x receive-file

# Accept a transfer (starts byte delivery)
x0x accept-file <transfer_id>

# Reject a transfer
x0x reject-file <transfer_id> --reason "not needed"
```

REST:

```bash
# List all transfers
curl -H "Authorization: Bearer $TOKEN" \
  "http://$API/files/transfers"

# Accept a pending transfer
curl -X POST -H "Authorization: Bearer $TOKEN" \
  "http://$API/files/accept/<transfer_id>"

# Reject a pending transfer
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"reason":"rejected by user"}' \
  "http://$API/files/reject/<transfer_id>"
```

## Monitoring progress

```bash
# Check a specific transfer's status
x0x transfer-status <transfer_id>

# Or via REST
curl -H "Authorization: Bearer $TOKEN" \
  "http://$API/files/transfers/<transfer_id>"
```

Transfer state includes:

```json
{
  "transfer_id": "<uuid>",
  "filename": "scan-results.json",
  "direction": "Receiving",
  "status": "InProgress",
  "total_size": 1234,
  "bytes_transferred": 640,
  "sha256": "<sha256_hex>",
  "chunk_size": 65536,
  "total_chunks": 1
}
```

SSE events are emitted for `file:offer` (incoming offer) and `file:complete` (transfer finished) on the `/events` stream.

## Good fits

- Transferring scan results, logs, or artifacts between agents
- Agent-to-agent file handoff with integrity verification
- Building file approval/review workflows
- Transfer coordination where both sender and receiver need to consent

## Current limits

- No resumable transfers. If the connection drops mid-transfer, start over.
- No streaming reads — the receiver gets the complete file only after all chunks arrive.
- Transfer state is in-memory only — daemon restart loses transfer records.
- No shared-folder sync or automatic file distribution.
- Received files go to `<data_dir>/transfers/` — no per-transfer output directory yet.
- No rate limiting beyond what QUIC congestion control provides.

## References

- [API reference](https://github.com/saorsa-labs/x0x/blob/main/docs/api-reference.md)
- [Source](https://github.com/saorsa-labs/x0x)
