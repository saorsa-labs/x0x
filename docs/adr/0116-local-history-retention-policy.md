# ADR 0116: Local History Retention by Class and Topic

- **Status:** Proposed
- **Date:** 2026-10-09
- **Decision owners:** David Irvine
- **Author:** Codex (GPT-6)
- **Reviewers:** TBD
- **Supersedes:** none; amends ADR 0023's local recording and retention policy upon acceptance
- **Superseded by:** none
- **Related:** [#1264](https://github.com/saorsa-labs/x0x/issues/1264), [#1263 embedder report](https://github.com/saorsa-labs/x0x/issues/1263#issuecomment-6050996198); ADR 0023, ADR 0030, ADR 0068, ADR 0085, ADR 0087; R6, R10, goal E

## Context

Use local class and topic rules to limit history. Reuse `Ephemeral` for
messages that this node must never write to history. Give embedders a
supported runtime trim operation.

An iOS embedder reports excessive history from application DMs and MLS
encrypt/decrypt calls. It trims SQLite before `serve()` as a stopgap.
Unknown DM payloads default to Durable. Application topic recording is
opt-in. The reaper first runs after 300 seconds.

ADR 0023 already defines Durable, Replaceable and Ephemeral. The missing
surface is local policy. Stored rows distinguish Durable from Replaceable
by `replace_key`; they have no separate class column. MLS plaintext has
`LocalAppDecrypt` provenance. A missing canonical message ID does not make
that plaintext useless history.

This decision covers #1264 part 2. The byte-reclamation repair in part 1
and the boot backfill repair in #1263 remain separate. It does not change
the frozen quarantine rules or activate the consolidated ADR drafts.

## Decision Drivers

- Embedders need explicit limits without direct database access.
- Unset options must preserve current recording and retention behavior.
- Pins, durable receipts and protocol state must keep their guarantees.
- Local policy needs no peer agreement or wire change.
- Work and incomplete progress must be bounded and visible.

## Considered Options

1. **Local policy and a shared trim service.** Chosen. The recording node
   owns its storage policy.
2. Sender metadata that orders receivers not to persist. Rejected. It
   needs wire and receipt changes and cannot constrain older receivers.
3. Disable all history or let each embedder edit SQLite. Rejected. Neither
   provides selective policy with the daemon's pin and concurrency rules.

## Decision

### 1. Configuration and rule selection

Extend `HistoryConfig`, used by both the builder and `[history]`. These
are example opt-ins, not new defaults:

```toml
[history]
enabled = true
max_bytes = 134217728
max_age_days = 30
record_topics = ["app.chat", "app.sync.presence"]
dm_recording = "ephemeral"

[[history.class_limits]]
class = "durable"
max_bytes = 67108864
max_age_days = 7

[[history.class_limits]]
class = "replaceable"
max_bytes = 8388608
max_age_days = 30

[[history.topic_rules]]
prefix = "app.sync."
recording = "ephemeral"

[[history.topic_rules]]
prefix = "app.chat"
max_bytes = 16777216
max_age_days = 3

[[history.scope_limits]]
scope = "group:example-stable-id"
max_bytes = 33554432
```

`dm_recording` defaults to `inherit`; its other value is `ephemeral`.
It applies to ordinary inbound and outbound DMs on this node. It does not
reclassify a registered protocol handler or its separate durable store.
DMs have no application topic field. Topic rules therefore cannot select
DMs by an invented topic or by parsing arbitrary payload fields.

`class_limits` defaults to empty. It accepts one entry each for `durable`
and `replaceable`, with optional `max_bytes` and `max_age_days`.
`ephemeral` is not a retained class and cannot have a retention budget.

`topic_rules` defaults to empty. Each rule has a non-empty, case-sensitive
literal UTF-8 prefix. There are no glob, regex or SQL wildcard semantics.
The longest matching prefix selects one whole rule; fields omitted from
that rule do not inherit from a shorter prefix. `recording` defaults to
`inherit`; its other value is `ephemeral`. Topic rules only filter topics
already selected by the existing exact-name `record_topics` list. They
neither subscribe to a topic nor opt it into recording.

Reject duplicate classes or prefixes, unknown values or keys in the new
rule objects, empty limit entries, and arithmetic overflow before opening
history. Limit the combined new rule count to 256 and each prefix to 256
UTF-8 bytes. Unset byte limits impose no extra bound. Zero bytes means
retain no eligible rows. An omitted or zero age adds no age bound; a
positive age is measured from local `seen_at_ms`, in 24-hour days.

### 2. Retention precedence

With all new options unset, keep the daemon default enabled, the library
default disabled, the 1 GiB byte cap, age eviction off, and existing exact
scope limits. Replaceable rows keep their existing exemption from ordinary
age and byte eviction. Their bytes still contribute to existing measures.

For Durable rows, every applicable positive age limit applies: global,
class and the selected topic rule. The shortest age wins. A local zero
cannot disable a global age bound. Delete only rows strictly older than
the cutoff. Class and topic byte budgets are additional aggregate ceilings,
not reservations and not replacements for the global or exact-scope cap.
A topic budget covers all rows assigned to that winning prefix, not a
separate allowance for each topic.

An explicit Replaceable class limit opts current-state history rows into
that class's age or byte eviction. A topic limit also applies to matching
Replaceable rows. These opt-ins do not expose unrelated Replaceable rows
to global eviction. No rule converts a Durable row into Replaceable.

Each pass applies age limits, pin ceilings, class budgets, topic budgets,
exact-scope budgets, then the global budget. Process classes in Durable,
Replaceable order and topic rules in prefix byte order. New budget phases
evict by `(seen_at_ms, id)`, oldest first. A row larger than the remaining
excess is eligible; a class or topic cap must not stall on that row.

Class and topic bytes use the existing scope measure: payload length plus
signed-artifact length, with a missing artifact counting as zero. They
are logical byte budgets. The global cap retains part 1's live-page
accounting and bounded reclamation behavior. Neither figure is a hard
limit on the database file or WAL. Do not delete extra rows merely because
the physical file has not yet shrunk.

ADR 0068 pins win over every ordinary age, class, topic, scope and global
rule. Exclude pinned rows from new aggregate budgets and their eviction
candidates. Keep both group ID spellings and the existing per-group
ceiling: `min(4 * base, max_bytes / 16)`, where `base` is the explicit
scope byte limit or `max_bytes / 64`. New rules never reduce that ceiling.
Only the existing ceiling path may evict pinned rows. Preserve its
Replaceable exemption, counters and residual overshoot. On marker clear,
the next pass applies ordinary rules. No force option bypasses a pin.

Unsigned and unprojectable MLS rows remain Durable. Class and exact-scope
bounds can expire them. Do not discard them merely because canonical
projection fails, and do not retry them outside the backfill cursor rules.

### 3. Ephemeral is a local history decision

Apply built-in classification first. Protocol traffic already classified
Ephemeral stays Ephemeral. Local `dm_recording` or the winning topic rule
may then suppress an otherwise recordable DM or topic message. Group
history has no Ephemeral opt-out in this decision: quarantine ingest must
remain tag-and-retain. This also prevents a broad rule from discarding
future group evidence before a pin is installed.

Resolve policy before history enqueue and enforce it at the shared write
boundary. An effective Ephemeral message writes no history row, payload,
signed artifact, FTS entry, canonical projection or history replay record.
Apply this to every ingress and local-send history path, including
committed writes. In-memory live delivery remains available. Other protocol
stores and application-owned storage are outside this history guarantee.
Existing rows are not erased by a recording rule; ordinary retention or
the existing authorized purge surface handles them.

This is not a new transport priority or a sender instruction. Change no
envelope, signature, capability bit or network ACK format. A sender cannot
use a payload tag to request this new opt-out on another node. Each node
controls its own copy, including its outbound history copy.

Preserve ADR 0030: never acknowledge a generic durable DM without its
required commit. If receiver policy suppresses that commit, withhold the
durable ACK before new dispatch and record the local policy reason in the
counters below. Send no typed refusal, including `AckSemanticsUnavailable`.
Do not silently use a weaker ACK. The sender sees its existing bounded
retry or timeout result. The ADR 0030 capability advert is unchanged: a
node with history enabled still advertises durable-ACK protocol version 2
while its local policy suppresses generic durable commits. Strict v2
senders therefore see a timeout, not the 409
`recipient_ack_semantics_unavailable` refusal. A typed route may still acknowledge its own completed
durable effect under its existing contract. Embedders that use transient
DMs must explicitly select the existing non-durable send mode when needed.

Expose typed policy fields in the Rust API and `GET /history/policy` in the
local API. This owner-only, bearer-authenticated read returns the active
rules, defaults, class derivation and protected-group exception. It works
when history is disabled. Add bounded counters for policy-suppressed DMs,
topics and durable-receipt refusals; never label metrics with arbitrary
topics or payloads. Do not add an Ephemeral row to history queries.

### 4. Supported runtime trim

Add `POST /history/retain`, `x0x history retain`, and asynchronous
`HistoryHandle::retain(options)`. All use one service over the already-open
store, its immutable startup policy and its live pin source. A library
without an installed pin source keeps ADR 0068's existing no-pin contract.
The daemon installs its source before exposing this route.

Require the durable local API token in `Authorization: Bearer ...` for
the POST. Missing or invalid tokens return 401. Session and rider tokens
return 403. Do not accept query-string tokens or network peer authority.

The JSON body accepts only `max_rows` and `budget_ms`. Defaults are 4096
rows and 2000 ms. Allowed ranges are 1–65536 rows and 1–10000 ms. The body
limit is 1 KiB; malformed or out-of-range values return 400 and oversized
bodies return 413. No SQL, database path, force flag, replacement policy
or scope selector is accepted. This operation applies policy, not a purge.

Admit at most one retention operation per store, shared with the reaper.
Return 409 `history_retention_busy` instead of queueing another operation.
Disabled history returns 409 `history_disabled`. Execute SQLite work off
the async executor. Delete at most 256 rows per transaction, including
age eviction. Count pin-ceiling deletions against the request's row budget.

Check the time budget before each statement. One in-flight SQLite
statement may overrun it; this is a work-admission budget, not a hard
response deadline. Keep connection ownership through each observation and
its resulting deletion. Stop at a committed boundary when either budget
is spent. Preserve part 1's settled-index check and forced-progress rules.
Keep at most one bounded in-memory phase cursor per store so repeated
calls cannot starve later classes or scopes. Refresh pins on continuation;
a marker installed during a pass retains ADR 0068's next-pass semantics.

Return 200 with committed deletion counts, pin-ceiling counts, elapsed
time, and `state`: `complete`, `more_work`, or `blocked_by_protected_rows`.
`complete` means this observed pass has no eligible policy work pending;
it promises neither physical file shrinkage nor a limit on future writes.
Reclamation still pending returns `more_work`.
`blocked_by_protected_rows` means no eligible policy work remains, but
pinned or exempt rows still keep a configured bound exceeded. It is
never returned while eligible work remains. SQLite failure returns a
typed 500 with counts for prior committed batches. Never claim rollback
of those batches. Caller cancellation stops new batches at the next
boundary. The periodic reaper can continue later.

Policy changes require restart in this version. There is no hidden startup
purge or new scheduled task. Embedders can trim through the handle before
`serve()` or through the API after startup, without opening SQLite again.

### 5. Persistence and compatibility

Keep history schema version 4 and all stored row layouts unchanged. Derive
class from `replace_key`; derive topic selection from the stored topic
scope. Persist no policy decision, trim job or Ephemeral tombstone. No
binary type or format magic changes under ADR 0085.

Older binaries can still read and write retained rows. They do not enforce
the new options; the current permissive history config decoder can ignore
unknown fields. Downgrade can therefore resume recording and broader
retention. It cannot recover rows already trimmed or messages never stored.
Release notes must state this policy loss. An embedder requiring the
opt-out must prevent downgrade or disable history using the old supported
switch before running the older binary. Do not claim fail-closed policy
enforcement from a format that did not change.

Mixed-version peers exchange unchanged messages. Each receiver applies
its own policy. No remote non-storage promise follows from local
Ephemeral. Older local API servers do not offer these new endpoints;
clients must report unsupported operation and must not fall back to SQL.
Future persisted fields must follow ADR 0085's version and fixture rules.

## Consequences

### Positive

- Mobile applications can reduce writes and retained history explicitly.
- One policy and pin-aware trim surface serves library, REST and CLI users.
- Existing installations and wire peers need no migration.

### Negative / Trade-offs

- Ephemeral messages cannot be recovered from this node's history.
- Receiver opt-out can prevent a generic durable DM from completing.
- Explicit Replaceable limits can remove its current history value.
- Old binaries cannot preserve a new recording policy on downgrade.

### Neutral / Operational

- Accepted ADRs stay unchanged. ADR 0087 governs implementation ordering.
- Prefix matching is compiled once from bounded configuration. Retention
  cost remains proportional to examined rows; no new per-message SQL read
  or payload parsing is allowed to select a rule.
- E-D15 review must measure queue pressure, write reduction, trim lock time,
  WAL growth and delivery results. There is no claimed network byte saving.

## Validation

These are implementation gates, not claims that this documentation adds tests.

| Rule | Required proof |
|---|---|
| Defaults and validation | Old configs and an empty new policy produce identical stored rows and eviction results. Reject duplicates, unknown new fields, overflow and count/length limits. Check zero and omitted values separately. |
| Class and topic precedence | Controlled timestamps prove the shortest positive age, global/exact-scope caps, aggregate class and winning-prefix budgets, literal prefix matching, deterministic ties and oversized-row progress. A longer prefix never inherits a shorter rule. |
| Replaceable behavior | Default current-state rows survive ordinary reaping. Only explicit matching limits evict them. Unrelated current-state rows survive; replacement semantics remain unchanged. |
| Ephemeral paths | Exercise inbound/outbound DM, topic, library and committed-write paths. Live non-durable delivery succeeds while row, FTS and canonical tables remain empty after restart. Remove the policy gate as a negative control and observe a stored row. |
| Pins and MLS | Old unpinned MLS rows expire without canonical IDs. Pinned groups survive all new phases, including alias IDs and runtime trim. Only the unchanged ceiling evicts its own rows. Clear the marker and observe normal retention. Test absent-pin-source behavior separately. |
| Receipts | Suppressed generic durable DMs get no durable or downgraded ACK and no new dispatch. Typed durable completion retains its own receipt contract. Exercise retries, restart and a pre-policy committed duplicate without fabricating a new commit. |
| Policy read and counters | `GET /history/policy` passes the full token matrix, works with history disabled and reports the protected-group exception. Each suppression path increments its bounded counter. No metric label carries a topic or payload. |
| Runtime bounds | REST/CLI/library parity, full token matrix, invalid bodies, busy and disabled results. A fixture whose only bound overshoot is protected rows returns `blocked_by_protected_rows`, never `more_work`. Large fixtures prove row limits, bounded transactions, partial progress, phase fairness, cancellation, error counts and reaper serialization under concurrent writers. Inject a slow statement to prove the documented time overrun. |
| Storage and downgrade | Use a released schema-4 fixture with provenance and hashes. Upgrade, trim, open with the released older binary, then upgrade again. Check retained rows, unchanged schema, derived-index consistency and explicit loss of new policy enforcement. Unknown newer schemas still fail closed without file changes. |
| Efficiency and compatibility | Preserve part 1's FTS convergence/WAL regressions and part 2's backfill cursor tests. Compare default-policy delivery on sealed candidate and mixed-version meshes in both directions under pressure. Explicit opt-out changes local history only, except the stated durable-receipt refusal. |

Use deterministic clocks and byte fixtures. Network tests run only in the
required isolated Linux test environment. Test the new API's absence on an
older daemon. Keep each required negative control red when its guard is removed.

## Open Questions for David

- Should this first version allow explicit expiry of Replaceable history?
  The proposal says yes, only under a matching opt-in limit. ADR 0023 calls
  it current state, while the existing reaper exempts it. Acceptance must
  confirm that trade-off; unset policy keeps the exemption.

## Notes for AI-assisted work

AI tools may help draft this ADR, but must not mark it Accepted without
human review. Accepted ADRs are immutable. Create a superseding ADR for
later decision changes.
