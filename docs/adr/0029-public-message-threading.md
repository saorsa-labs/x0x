# ADR 0029: First-Class Threading on Signed Public Group Messages

- **Status:** Proposed
- **Date:** 2026-08-06
- **Decision owners:** David Irvine
- **Reviewers:** (pending)
- **Supersedes:** none
- **Superseded by:** none
- **Related:** ADR 0023 (durable local history); ADR 0028 (delivery order is
  not an authorization signal); `docs/design/named-groups-full-model.md`
  §"Public groups"; x0x-nostr-bridge M1a thread-vector gate; Nostr NIP-10

## Context

`GroupPublicMessage` — the signed, state-bound message used by
`POST /groups/:id/send` for `SignedPublic` groups — has no way to express
that one message replies to another, and no spec-defined message identity
for a reply to reference. Consumers have improvised three incompatible
workarounds:

1. The embedded GUI fakes threads with side-channel gossip topics
   (`x0x.group.<id>.thread/<msgId>`) and a client-side parent cache. Replies
   live outside the group's real feed: unsigned parent binding, no history
   scope, no REST visibility, unbounded topic growth.
2. Applications can smuggle JSON conventions into `body`. Signed, but
   private per-app schema that pollutes FTS search and clashes with the
   GUI's convention.
3. The Nostr bridge carries whole Nostr events opaquely, so Buzz↔Buzz
   threading (NIP-10 `root`/`reply` e-tags) survives *transit* — but an
   x0x-native agent cannot author a reply into a Buzz thread, and the
   bridge cannot project a Nostr thread onto x0x group messages, because
   the x0x schema has no field to map the tags onto.

Message identity is equally improvised: the read-path merge dedupes on the
signature string, the ADR-0023 history store keys on `BLAKE3(signed JSON
artifact)`, and `GET /groups/:id/messages` returns no ID at all.

The hard constraint is the signature format. `signable_bytes()` is a
fixed-order, length-prefixed canonical encoding under the domain
`x0x.group.public-message.v1`. Any new signed field changes the bytes old
verifiers compute. The wire form is JSON, so old receivers *parse* unknown
fields fine (no bincode mid-struct break) and then reject the message at
signature verification — fail-closed, never mis-verified.

## Decision Drivers

- Agents and the GUI need structured conversations in public groups today;
  the side-channel topic hack fragments history and trust.
- The Nostr bridge M1a gate requires thread vectors; NIP-10 mapping needs
  a field to map onto and a stable message ID to translate.
- Wire changes to a signed format must keep non-threaded traffic fully
  interoperable with old nodes and must fail closed for new semantics.
- Gossip delivers with gaps and reordering; per ADR 0028, missing
  predecessors must not gate acceptance of otherwise-valid messages.

## Considered Options

1. **First-class optional `thread_root`/`thread_parent` fields plus a
   defined `msg_id`, versioned signing domain (chosen).**
2. **Body-embedded JSON convention.** Zero protocol change and fully
   signed, but a permanent private schema: invisible to validation, breaks
   FTS, competes with the GUI's existing different convention.
3. **Standardize the per-thread side-topic scheme.** No signature change,
   but replies stay outside the group feed and history scope, parent
   binding stays unsigned, and topic count grows per-thread.
4. **Full causal DAG references (every message cites predecessors).**
   Strictly more general, but a much larger wire and validation change
   than the proven need; NIP-10-shaped root/reply covers the use cases.

## Decision

We will add threading to `GroupPublicMessage` as follows.

**Message identity.** `msg_id = BLAKE3(signable_bytes())`, lowercase hex
(64 chars). Deterministic, recomputable by any verifier from the signed
content, independent of JSON re-serialization. It is the direct analogue
of Nostr's `event.id`, making bridge translation a table lookup. Hash
references make thread cycles impossible without a hash collision. The
ID is exposed (additively) everywhere messages appear: the
`GET /groups/:id/messages` items and the `POST /groups/:id/send`
response. (No SSE event exists for group public messages today —
delivery is gossip-topic plus DM push; if one is added later it must
carry `msg_id` too.)

**Thread fields.** Two new optional fields on `GroupPublicMessage`:

```rust
#[serde(default, skip_serializing_if = "Option::is_none")]
pub thread_root: Option<String>,    // msg_id of the thread's first message
#[serde(default, skip_serializing_if = "Option::is_none")]
pub thread_parent: Option<String>,  // msg_id of the direct parent
```

`POST /groups/:id/send` accepts optional `thread_root` / `thread_parent`
request fields and passes them through to signing.

**Signing rule (the compatibility core).** When both fields are `None`,
`signable_bytes()` is byte-identical to today's v1 encoding under the v1
domain `x0x.group.public-message.v1` — non-threaded traffic interoperates
with every existing node, forever. When either field is set, the message
signs under a new domain `x0x.group.public-message.v2` with the two
fields appended length-prefixed (absent field ⇒ empty string) after
`timestamp`. Verification selects the domain by field presence. The
explicit domain bump removes any v1/v2 byte-string ambiguity; stripping
or injecting thread fields breaks the signature in either direction.

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

**Read surface.** `GET /groups/:id/messages` accepts an optional
`thread_root=<msg_id>` query filter returning only that thread's messages
(root included when known). No history-store schema change: rows carry
the signed JSON artifact verbatim, so thread fields round-trip today;
filtering parses the artifact, with an indexed column as a later
optimization if profiling demands it.

**Bridge mapping (informative, separate repo).** `thread_root` /
`thread_parent` ↔ NIP-10 marked e-tags (`["e", <id>, "", "root"|"reply"]`)
with a bidirectional Nostr-event-id ↔ x0x-msg-id table in the bridge's
existing store.

The GUI's side-topic thread scheme is deprecated by this ADR and should
migrate to the first-class fields, then be removed.

## Consequences

### Positive

- Threads become signed, validated, history-scoped, and REST-visible.
- Non-threaded messages remain wire- and signature-identical to v1: zero
  risk to existing traffic.
- Old nodes fail closed on threaded messages (signature reject), never
  mis-attribute or corrupt.
- The bridge gains a lossless NIP-10 mapping and a stable ID to key it.

### Negative / Trade-offs

- Until the fleet converges (self-update handles this quickly), threaded
  messages are invisible to old nodes — a temporary visibility partition.
- Two signing domains must be maintained and tested against each other.
- `msg_id` recomputation on read paths costs one BLAKE3 over signable
  bytes per message (negligible at current volumes).

### Neutral / Operational

- History store, dedup keys, and retention are unchanged.
- The GUI migration is follow-up work; both schemes coexist briefly.

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

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without
human review**. Accepted ADRs are immutable: create a new superseding ADR
rather than editing an Accepted ADR.
