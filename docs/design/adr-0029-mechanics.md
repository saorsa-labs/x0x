# ADR-0029 mechanics — Ingest, read-surface, bridge-mapping detail and validation inventory

> Extracted 2026-08-29 from the immutable [ADR 0029](../adr/0029-public-message-threading.md) per the
> 2026-08-23 ADR audit. The ADR remains the complete decision record; the
> sections below are the ingest/read-surface/bridge-mapping mechanics and the
> validation inventory relocated verbatim so this file is their maintained home — future updates
> belong here, not in the ADR.

**Ingest validation** (`validate_public_message` additions):

- Each present field must be exactly 64 lowercase hex chars.
- `thread_parent` present ⇒ `thread_root` present. A direct reply to the
  root sets both to the root's `msg_id` (NIP-10 semantics).
- `thread_root`/`thread_parent` must not equal the message's own `msg_id`
  (structurally impossible to construct, cheap to check).
- The referenced parent is **not** required to exist locally. Gossip
  history is partial by design; per ADR 0028, delivery order and local
  completeness are not authorization signals. Clients render orphaned
  replies as they see fit.

---

**Read surface.** `GET /groups/:id/messages` accepts an optional
`thread_root=<msg_id>` query filter returning only that thread's messages
(root included when known). No history-store schema change: rows carry
the signed JSON artifact verbatim, so thread fields round-trip today;
filtering parses the artifact, with an indexed column as a later
optimization if profiling demands it.

---

**Bridge mapping (informative, separate repo).** `thread_root` /
`thread_parent` ↔ NIP-10 marked e-tags (`["e", <id>, "", "root"|"reply"]`)
with a bidirectional Nostr-event-id ↔ x0x-msg-id table in the bridge's
existing store.

---

## Validation

- **Frozen v1 vector:** a signed v1 fixture (bytes checked into the test
  suite) must verify unchanged under the new code.
- **Byte-identity:** a v2-built message with no thread fields must
  serialize and sign byte-identically to v1 (assert on bytes, not just
  round-trip).
- **Fail-closed:** a v1-only verifier (simulated by recomputing v1
  signable bytes) must reject a threaded message.
- **Tamper:** stripping or adding thread fields to a signed message must
  fail verification.
- **Ingest rules:** property tests over hex validity, parent-implies-root,
  and orphan acceptance.
- **Soak:** a multi-daemon local soak on an isolated plane exchanging
  mixed threaded/non-threaded traffic, asserting cross-daemon thread
  reconstruction and zero regression in non-threaded delivery.
