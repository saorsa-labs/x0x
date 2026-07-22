# Durable history — implementation design (ADR-0023)

**Status:** Design for implementation — ADR-0023 accepted 2026-07-22
**Owner:** David Irvine
**Related:** ADR-0023 (decision), ADR-0009/0013 (shed posture), ADR-0012 (TreeKEM), ADR-0015 (at-rest posture), x0x-nostr-bridge `src/store.rs` (donor implementation)

## 1. Scope

Implements ADR-0023 in x0xd: a default-on, bounded, local-only SQLite history
store for DMs and named-group messages, with scoped query, FTS5 search, and
WS backfill-then-live. Non-goals repeat the ADR's: no network serving of
history, no propagated deletion, no export tooling.

## 2. Module layout

```
src/history/
├── mod.rs        // HistoryService: handle, spawn, shutdown
├── store.rs      // SQLite open/migrate/insert/query/search/retain
│                 //   (adapted from x0x-nostr-bridge/src/store.rs)
├── writer.rs     // bounded-channel writer task + shed counters
├── record.rs     // HistoryRecord, Scope, MessageClass taxonomy
└── reaper.rs     // retention enforcement (discovery_cache_reaper pattern)
```

`HistoryService` is owned by `AppState` (daemon) or `Agent` (library, opt-in
via `AgentBuilder::with_history`). All producers hold a cheap
`HistoryHandle` (clonable mpsc sender + Arc<Store> for reads).

## 3. Schema

```sql
CREATE TABLE history (
  id            INTEGER PRIMARY KEY,          -- rowid, insertion order
  msg_id        BLOB NOT NULL,                -- BLAKE3(signed_artifact); BLAKE3(payload) when unsigned (MLS rows)
  scope_kind    INTEGER NOT NULL,             -- 0=dm, 1=group, 2=topic
  scope_id      TEXT NOT NULL,                -- agent_id hex | group stable_id | topic
  author_agent  TEXT,                         -- hex AgentId (NULL for MLS rows — see below)
  author_machine TEXT,                        -- hex MachineId when known
  author_pubkey BLOB,                         -- ML-DSA-65 public key used at verify time
  sent_at_ms    INTEGER NOT NULL,             -- sender claim
  seen_at_ms    INTEGER NOT NULL,             -- local receipt (authoritative for ordering)
  direction     INTEGER NOT NULL,             -- 0=inbound, 1=outbound
  content_type  TEXT NOT NULL DEFAULT 'text/plain',
  payload       BLOB NOT NULL,                -- decrypted application payload (what the UI renders/searches)
  signed_artifact BLOB,                       -- verbatim signed wire bytes (DmEnvelope wire form /
                                              --   GroupPublicMessage JSON) — the offline-reverify artifact
  signature     BLOB,                         -- ML-DSA-65 sig (verbatim; NULL for MLS rows)
  sig_context   TEXT,                         -- domain string used at verify time
  provenance    INTEGER NOT NULL,             -- 0=verified-envelope, 1=local-app-decrypt (MLS), 2=local-send
  replace_key   TEXT,                         -- non-NULL ⇒ replaceable class
  UNIQUE(msg_id)
);
CREATE INDEX idx_scope_time ON history(scope_kind, scope_id, seen_at_ms);
CREATE INDEX idx_author     ON history(author_agent, seen_at_ms);
CREATE UNIQUE INDEX idx_replace ON history(replace_key) WHERE replace_key IS NOT NULL;

CREATE VIRTUAL TABLE history_fts USING fts5(
  payload_text, content='history', content_rowid='id'
);
-- FTS rows written only for text/* content types; triggers keep in sync.
```

Notes:
- **Offline re-verification requires `signed_artifact`, not just the sig.**
  The DM signature covers the *encrypted* body (`DmEnvelope::signed_bytes`
  spans protocol_version/request_id/ids/timestamps + the KEM ciphertext +
  AEAD body — `src/dm.rs:1069`, `:184-196`); group public-message signatures
  span `signable_bytes` incl. `state_hash_at_send`/`revision_at_send`
  (`src/groups/public_message.rs:100-122`). Neither is reconstructable from
  a decrypted-payload column. We therefore store the signed wire bytes
  verbatim (~3.3 KB extra per row, bounded by retention); rows re-verify
  offline by re-running the same verify path over `signed_artifact` with
  `author_pubkey`. The group artifact also preserves the Phase-D.3
  state-hash anchor an auditor wants.
- **MLS rows are honestly unsigned.** The daemon only sees MLS plaintext
  when the local app calls `secure_group_encrypt` /
  `treekem_group_decrypt` / `secure_group_decrypt`
  (`src/server/routes/named_groups.rs:11753-11917`); those responses carry
  plaintext + epoch but no per-message author signature
  (`SecureShareDelivered` is ML-KEM epoch-key delivery, not a message).
  MLS rows record `provenance = local-app-decrypt`, `signature = NULL`,
  `author_agent = NULL` unless the app supplies attribution. If per-message
  MLS authorship is wanted later, that is a wire-format change and its own
  design.
- `msg_id = BLAKE3(signed_artifact)` (or of `payload` for unsigned rows)
  dedupes redundant delivery channels (DM gossip + raw-QUIC overlap, group
  direct-push + metadata topic + pull) — retries re-publish byte-identical
  envelopes, so second arrival is a no-op. Self-DM loopback
  (`DmPath::Loopback`) is written at send and again at delivery;
  first-writer-wins keeps `direction = outbound` (unit-tested).
- Replaceable class uses `replace_key` (e.g. `agent-card:<agent_id>`), upsert
  keeps latest by `sent_at_ms`; on equal timestamps the **lowest `msg_id`
  wins** (donor semantics, `x0x-nostr-bridge/src/store.rs:573`).
- Pragmas: WAL; `synchronous=NORMAL`; `busy_timeout=5000`;
  `auto_vacuum=INCREMENTAL` set at creation (required for the reaper's
  `incremental_vacuum`). Single writer connection, read pool.
- `schema_version` table + forward-only migrations (new work — the donor
  uses bare `CREATE TABLE IF NOT EXISTS`).

## 4. Taxonomy wiring (the complete producer list)

Class assignment happens at the producer, once, in code:

| Producer (today) | Class | Wiring point |
|---|---|---|
| DM inbound (gossip inbox) | Durable | `dm_inbox.rs` delivery path (`handle_payload`), after signature (`:402`) + trust/revocation gates — the full `DmEnvelope` incl. signature is in scope for verbatim capture |
| DM inbound (raw QUIC) | Durable | same `DirectMessaging::handle_incoming` convergence (post-verify); `msg_id` dedupes the two paths |
| DM outbound (REST **and** WS `send_direct`) | Durable | the single envelope-build point `Agent::send_direct_*` → `EnvelopeBuilder::build_payload_envelope` (`src/lib.rs:~4455`, `src/dm.rs:1223`) — NOT the REST handler, which only sees a `DmReceipt` with no envelope; wiring here covers REST, WS, and internal senders once |
| Group public message | Durable | all three delivery paths (per-group listener, global fallback listener, DM direct-push) converge on `ingest_public_message` → `cache_public_message`; wire there + the local `send_group_public_message` path |
| Group MLS plaintext | Durable | the app-driven endpoints only: `secure_group_encrypt` (outbound) and `treekem_group_decrypt`/`secure_group_decrypt` (inbound), `named_groups.rs:11753-11917`. `provenance = local-app-decrypt`, no author signature (see §3). `SecureShareDelivered` is epoch-key delivery — control traffic, Ephemeral |
| a2a protocol messages | **Durable** | `src/a2a/binding.rs` loop — agent-to-agent task traffic is the ADR's headline "agents need memory" case |
| App topics | Durable **opt-in** | a **local per-topic recording option** on this daemon's subscribe/ingest (a remote publisher's flag cannot oblige a receiver); default off |
| File-transfer offer / accept / reject / complete | Durable | `FileMessage` dispatch in the DM path — the *record* of the transfer |
| File-transfer chunks + chunk-ACKs | Ephemeral | 32 KiB base64 plumbing; the received file on disk IS the durable artifact |
| WelcomeBlob chunks + acks | Ephemeral | same flood shape as file chunks (`WelcomeBlobMessage::Chunk`, 32 KiB base64) |
| JoinResult / TreeKemCatchup / metadata-event DM fallbacks / KV-delta DM fallback | Ephemeral | group/KV control plumbing riding the DM path; their durable effects live in group state + KV stores |
| exec typed payloads (`x0x-exec-v1`) | Ephemeral (default) | exec has its own JSONL audit log; double-recording is redundant — revisit if the audit log is ever retired |
| Agent cards | Replaceable | card import paths (`import_agent_card`, `import_group_card`), `replace_key = agent-card:<id>` |
| Presence beacons, typing, control frames, discovery anti-entropy, upgrade manifests, keepalives, tracker internals | Ephemeral | no call sites |

Classification at the DM wiring point is **payload-shape aware** (typed
prefixes / serde tags), not topic-based. The deny-test injects each
Ephemeral payload family through the real DM wiring point and asserts the
store stays empty — not a topic-prefix grep.

Trust gate invariant: **nothing is written that failed signature or trust
evaluation** — history records communication the node accepted, not spam it
rejected. (Rejected traffic is already counted in diagnostics.)

## 5. Write path (ADR-0009/0013 posture)

```
producer ──try_send──▶ mpsc(4096) ──▶ writer task ──batch──▶ SQLite (WAL)
              │
              └─ full ⇒ drop + history_dropped_full += 1  (never block)
```

- Writer batches up to 64 records / 50 ms per transaction. **rusqlite is
  synchronous** — the writer runs on a dedicated OS thread (or
  `spawn_blocking`); the async side only ever `try_send`s. On shutdown the
  writer drains the channel (bounded grace, then abandon-with-count) —
  not `abort()`, which would strand queued records.
- Counters in `/diagnostics/history` (one-per-subsystem convention, like
  `/diagnostics/dm`): `written_total`, `dropped_full`, `dedup_hits`,
  `db_bytes`, `oldest_ms`, `reaper_evicted_total`, per-class counts.
- Prod context for sizing: bootstrap nodes idle at 18–19 peers with
  chat-free gossip (verified on the live fleet 2026-07-22); the 4096 queue
  and 64-batch writer are over-provisioned for workspace chat rates by
  orders of magnitude. The cap exists for pathological floods, and the shed
  counter makes any drop visible.

## 6. Retention

`[history]` config (daemon TOML + `AgentBuilder`):

```toml
[history]
enabled = true            # ADR-0023: default on in x0xd
max_bytes = 1073741824    # 1 GiB
max_age_days = 0          # 0 = no age bound
# optional per-scope overrides
[[history.scope_limits]]
scope = "group:<stable_id>"
max_bytes = 268435456
```

Reaper task every 300 s (constant, `HISTORY_REAPER_INTERVAL_SECS`), evicts
oldest-first by `seen_at_ms` until under bounds, then `PRAGMA
incremental_vacuum` (enabled by `auto_vacuum=INCREMENTAL` at creation).
Replaceable rows are exempt from **age** eviction (they are current state,
not log) but **do count against `max_bytes`** — a card-refresh loop cannot
bypass the byte bound.

Operational constraints: `history.db` must live on local disk (WAL requires
working file locks — no NFS/SMB; documented for embedded `serve()` hosts).
Two daemon processes must not share a data dir; x0xd takes an exclusive
lock file beside the DB and fails loud if it is held.

## 7. API surface (ENDPOINTS registry entries ⇒ CLI + parity for free)

| Method | Path | CLI | Notes |
|---|---|---|---|
| GET | `/history` | `x0x history list` | `scope`, `since_ms`, `until_ms`, `limit` (≤500), `before_id` cursor |
| GET | `/history/search` | `x0x history search` | `q` (FTS5, sanitized like donor `fts_match_expr`), same filters |
| GET | `/history/stats` | `x0x history stats` | db size, counts, retention state |
| DELETE | `/history` | `x0x history purge` | scope-required; local only |
| GET | `/diagnostics/history` | `x0x diagnostics history` | writer/reaper counters (§5) |

Registry grows **142 → 147**; `api_coverage.rs`/`parity_cli.rs` enforce CLI
parity, `api_manifest.rs` regenerates the manifest count.

WS: `Subscribe` frames gain an optional `"backfill": {"limit": N}` field
(additive on the serde-tagged enums — existing subscribers unaffected) →
stored events (oldest→newest, same JSON shape as live) → `{"type":"live"}`
marker → live stream. **Seam rule:** the live broadcast tap is established
*before* the backfill query runs, and events are deduped by `msg_id` across
the marker — no gap, no duplicate (this is §9's dedicated test). Scope
mapping is explicit: WS topic subscriptions map topic→`topic:<name>` scope;
`/ws/direct`'s auto-subscription maps to the `dm:<peer>` scopes. SSE
mirrors with an additive event type on `/direct/events`.
`/groups/:id/messages` becomes store-backed (its existing contract stands:
400 for MlsEncrypted groups — encrypted history is served via the secure
surfaces, not plaintext listing); in-memory buffers remain as read-through
caches for the hot tail.

## 8. Migration & compatibility

- First boot creates `history.db`; no data migration exists (nothing durable
  to migrate). `dm_inbox` keeps its in-memory dedupe/expiry semantics as the
  hot cache; the store is the source of truth for reads beyond the cache.
- `schema_version` table + forward-only migrations (donor pattern).
- Test daemons: per-instance temp dirs already isolate `history.db`; every
  existing fixture keeps `[update] enabled=false` (unrelated, standing rule).
- Feature interaction: `--name` instances get separate DBs; embedded
  `serve()` hosts choose via `AgentBuilder`.

## 9. Test plan

Unit (`src/history/` + `tests/history_store.rs`):
insert/query/cursor-pagination, dedupe via `msg_id` (incl. loopback
outbound-wins direction), offline re-verify from `signed_artifact` +
`author_pubkey`, replaceable upsert + lowest-msg_id tie-break, ephemeral
deny-test (payload-shape injection at the DM wiring point, per §4), FTS
hit/miss + injection literal (`" OR 1=1`), retention eviction incl.
per-scope override and replaceable-counts-against-bytes, WAL crash-recovery
(kill mid-batch, reopen, no corruption).

Integration (`tests/history_integration.rs` + daemon fixtures):
- **Restart survival** (the ADR's headline): DM + group message → SIGKILL →
  restart → `GET /history` and `/groups/:id/messages` return them.
- MLS: 2-member TreeKEM group, message, epoch advance (ban), restart →
  plaintext history intact (extends `e2e_treekem_membership.py` family).
- Backfill-then-live: WS subscribe with backfill during active publishing —
  no gap, no duplicate across the `live` marker (the seam bug this design
  exists to prevent).
- Backpressure: flood publisher, assert recv-pump latency unaffected (the
  synchronous-rusqlite placement test — catches executor-thread stalls, not
  just corruption) and `dropped_full` counts (pattern: existing shed tests).

Fleet validation (testnet plane, UDP 6483 / API 13600):
deploy to the 6 co-located testnet daemons, run the Phase-A DM matrix
(`e2e_vps_mesh.py`) for an hour, then assert on every node: `history.db`
bounded, `dropped_full == 0` at chat rates, `/history/search` returns
matrix payloads, restart one node → its history survives. Fleet is
confirmed healthy for this today (0.34.2, 18–19 peers).

## 10. Rollout

1. `src/history/` + store lift from the bridge (unit tests green).
2. Producer wiring behind `[history] enabled` (default **on**; `false` is
   the escape hatch).
3. Endpoints + registry + CLI + parity suite update (142 → 147 endpoints;
   api-manifest regenerates).
4. Testnet soak (§9) before release; release notes call out plaintext-at-rest
   (ADR-0015/0023 posture) and the `enabled=false` opt-out.
5. tic-tac-toe M0 gate: acceptance tests #1/#2 (restart survival, search)
   run against the shipped daemon.
