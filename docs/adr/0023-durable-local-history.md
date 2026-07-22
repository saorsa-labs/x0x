# ADR 0023: Durable Local History Is a Core x0x Capability

- **Status:** Proposed
- **Date:** 2026-07-22
- **Decision owners:** David Irvine
- **Reviewers:** <pending>
- **Supersedes:** none (extends the storage posture of ADR 0015)
- **Superseded by:** none
- **Related:** x0x-nostr-bridge spike (2026-07-21), ADR 0009/0013 (receive-pump shedding), ADR 0012 (TreeKEM), ADR 0015 (no app-layer at-rest encryption), issue #110 (embedded `serve()`), tic-tac-toe frontend (saorsa-labs/tic-tac-toe)

## Context

x0x today persists *state* but not *communication*. Across daemon restarts we
keep: identity keys, TreeKEM group snapshots, revocation sets, KV stores,
CRDT task lists, the group state-commit chain, and the bootstrap cache. We do
**not** keep: direct messages (`dm_inbox.rs` is an in-memory map, a documented
v1 non-goal of the DM design), group message history (`/groups/:id/messages`
serves an in-memory listener buffer), or any pub/sub payloads. MLS-encrypted
groups expose no plaintext history at all.

Two events forced this decision:

1. **The x0x-nostr-bridge spike (2026-07-21).** To run an unmodified Nostr
   workspace client (Block's Buzz) against x0x, the bridge had to add a
   SQLite event store — durable history with query and full-text search —
   because the workspace product category is unusable without it. The store
   was not Nostr plumbing; it was the capability x0x itself lacked.
2. **Agents need memory.** x0x positions itself as the agent-to-agent
   transport. An agent that loses its conversation record on every restart
   cannot audit what it agreed to, resume work, or be held accountable. For
   the agent-workspace use case (tic-tac-toe, symphony), history is not a
   feature — it is the substrate.

The tension: x0x's gossip plane is deliberately fire-and-forget (epidemic
broadcast, bounded queues, shed-under-pressure per ADR 0009/0013), and our
privacy posture (ADR 0015) is that local disk is protected by OS user
isolation + full-disk encryption, not by app-layer crypto. Durable history
must not compromise either.

## Decision Drivers

- Agent accountability and resumability require a durable, queryable local
  record of communication.
- The workspace product category (Buzz-parity via tic-tac-toe) requires
  history + search; the bridge spike proved the shape and the demand.
- PQC end-to-end differentiation: history over native x0x envelopes keeps
  ML-DSA-65 authorship; the bridge's Schnorr-signed store cannot.
- The gossip receive path must never block on disk (ADR 0009/0013).
- Participant-held data philosophy (ADR 0006): each node records what it
  witnessed; there is no global archive to query or poison.
- Unbounded disk growth is unacceptable on long-lived daemons.

## Considered Options

1. **Durable history as a core, default-on x0xd capability (SQLite).**
2. Durable history as an opt-in feature flag, default off.
3. Keep history an application concern (each app ships its own store, as the
   nostr-bridge did).
4. Extend the existing bincode-file persistence (no SQL dependency).

Option 2 makes the flagship use case (agent memory) a configuration
afterthought and forks the ecosystem into daemons-with-memory and
daemons-without. Option 3 duplicates a hard-to-get-right store (write-path
backpressure, retention, search) into every app and loses the shared CLI/API
surface. Option 4 cannot serve bounded-latency scoped queries or full-text
search, which are the point.

## Decision

We will make **durable local history a core x0xd capability, enabled by
default**, implemented on SQLite (bundled `rusqlite`, no system dependency)
in the instance data directory (`~/.x0x/history.db`; per-instance for named
instances).

**Message-class taxonomy.** Every stored surface is classified once, in code:

| Class | Semantics | Examples |
|---|---|---|
| **Durable** | Append to history, subject to retention | DMs (sent + received), named-group messages, application topics that opt in |
| **Replaceable** | Latest-per-key only | Agent cards, presence-adjacent profile state |
| **Ephemeral** | Never written | Presence beacons, typing/control frames, discovery anti-entropy, upgrade manifests, keepalives |

Transport/control traffic is ephemeral by definition; history records
*communication*, not protocol chatter.

**Write path.** History writes go through a dedicated writer task fed by a
bounded channel. Under pressure the writer sheds (counted,
`history_dropped_full`) — the receive pump and DM/group hot paths never
block on disk. This is the ADR 0009/0013 posture applied to storage.

**MLS groups.** We store **reader-side decrypted plaintext**. TreeKEM epochs
rotate; retaining ciphertext would orphan history at every epoch advance.
Forward secrecy is a wire property; local plaintext-at-rest is exactly the
ADR 0015 posture (OS user isolation + FDE), and stored history is
**local-only — never served to the network** (see non-goals).

**Retention.** Default-on but bounded: `[history]` config with
`enabled = true`, `max_bytes` (default 1 GiB), optional `max_age_days`,
optional per-scope overrides. A periodic reaper (same pattern as
`discovery_cache_reaper`) enforces bounds by evicting oldest-first.

**API surface** (registered in `ENDPOINTS`, so CLI + parity tests follow
automatically):

- `GET /history?scope=dm:<agent_id>|group:<id>|topic:<name>&since&until&limit`
- `GET /history/search?q=<fts>&scope=…` (FTS5)
- WS/SSE subscriptions gain an optional `backfill` mode: stored events
  first, then a `live` marker, then the live stream (the one protocol shape
  worth taking from NIP-01's REQ→EOSE).
- `DELETE /history?scope=…` — local deletion only.

`dm_inbox` and the group in-memory buffers become read-through caches over
the store; `/groups/:id/messages` becomes store-backed and restart-stable.

**Library embedders** (issue #110 context): `AgentBuilder` gains
`.with_history(HistoryConfig | Disabled)`; the daemon defaults on, the bare
library defaults off so embedding stays zero-footprint unless asked.

**Non-goals of this ADR (explicitly deferred):**

- **Serving history to the network.** V1 history is a private local record
  of what this node witnessed/decrypted. Cross-node backfill/anti-entropy
  (e.g. over ADR 0022 byte streams) is a separate future ADR with its own
  trust model.
- Network-propagated deletion/redaction.
- History export/import tooling.

## Consequences

### Positive

- Agents (and tic-tac-toe) get restart-stable memory, scoped query, and
  full-text search from the daemon they already run.
- One hardened store instead of N per-app stores; the bridge's tested
  design (parameterized SQL, FTS5, replaceable semantics, size caps) is
  lifted rather than reinvented.
- PQC story stays intact end-to-end: history rows are native x0x envelopes
  with ML-DSA-65 authorship.
- Participant-held philosophy preserved: no archive servers, no global
  query surface, nothing new to attack remotely.

### Negative / Trade-offs

- First SQL dependency in x0x core (bundled rusqlite; ~1 MB binary growth,
  new fuzz/audit surface in the query builders — mitigated by binding every
  user value, as the bridge does).
- Plaintext-at-rest for decrypted MLS content on the local disk. This is
  ADR 0015's stance, but history makes it *larger*; documentation must say
  so plainly.
- Disk usage on busy daemons; bounded by retention, but eviction means
  history is a window, not an archive.
- Write amplification on gossip-heavy nodes; bounded writer + shed counters
  make it observable, not free.

### Neutral / Operational

- `history.db` joins the per-instance data dir; multi-instance (`--name`)
  isolation comes for free.
- Test daemons already use per-instance temp dirs; restart-survival tests
  become possible and required.
- Registry-driven parity means `x0x history …` CLI commands appear with the
  endpoints.

## Validation

- Unit: insert/query/replace/ephemeral-never-stored/retention-eviction/FTS
  round-trips.
- Integration: send DM → restart daemon → `GET /history` returns it
  (the restart-survival test that is impossible today).
- Backpressure: flood the gossip plane; assert the receive pump never
  blocks on the writer and `history_dropped_full` counts the shed.
- Parity: `api_coverage.rs` / `parity_cli.rs` enforce endpoint + CLI
  coverage automatically once registered.
- Product: tic-tac-toe's acceptance suite reads history-after-restart and
  search as its first two assertions — the proof point this exists for.
- Review trigger: if cross-node backfill is proposed, it requires a new ADR;
  this ADR's local-only privacy claim is load-bearing.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without
human review**. Accepted ADRs are immutable: create a new superseding ADR
rather than editing an Accepted ADR.
