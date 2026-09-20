# ADR 0068: Fork Quarantine Pins History Retention and Buffers Inbound Task Deltas

- **Status:** Accepted
- **Date:** 2026-09-20
- **Decision owners:** David Irvine
- **Reviewers:** David Irvine (ratification, 2026-09-20: "I accept the recommendations in
  732"); cross-model (omp) review required on the implementing PR
- **Supersedes:** none
- **Superseded by:** none
- **Extends:** ADR 0066 (does not edit it). ADR 0066 §1's 26-row coverage map, its counts,
  R1–R5 and every other section stand unchanged. This ADR adds two paths that map never
  enumerated; it removes nothing from it and re-dispositions none of its rows. ADR 0067's
  §4 token identity is used as-is.
- **Related:** #732; `docs/adr/0066-ordinary-group-fork-anchors-and-data-plane-quarantine-coverage.md`,
  `docs/adr/0067-lifecycle-epoch-token-is-derived-marker-identity.md`,
  ADR 0023 §6 (retention), `docs/runbooks/fork-quarantine.md` gaps (b) and (c)

## Context

ADR 0066 slices 1–8 and ADR 0067 are on main, `OPEN_ROWS == &[]` and
`PENDING_RECHECK == &[]` are asserted, and every marker lookup goes through the one
resolver (`src/server/mod.rs::resolve_group_entry_locked`). Cross-model review of that
finished work found two paths that destroy or mutate a quarantined group's state and that
**ADR 0066 §1 never enumerated** — so they are not regressions of a row, they are gaps in
the census itself. Both are recorded, visible, in the runbook as known gaps (b) and (c).

**(b) The retention reaper ignores quarantine.** `src/history/reaper.rs` runs
`Store::retain` every 300 s (ADR 0023 §6) and evicts oldest-first by age and by bytes,
whole-database and per-scope, with no idea that a `group:<id>` scope is contested. ADR 0066
R3 makes history ingest *tag-and-retain, never refused*, precisely so the forensic record
survives; slice 4 therefore refuses the explicit purge (row 14) because "a missed marker is
not a degraded answer, it is a deletion of the forensic record row 14 exists to protect".
The reaper is that same deletion through another door — and worse, it is *drivable*: a peer
that floods the node with recordable events for the quarantined group (or for any other
scope) raises byte pressure and makes the reaper do the deleting.

**(c) Inbound peer task-CRDT deltas apply ungated.** Slice 5 (row 20) refuses *local* REST
mutations on a quarantined group's task list. Deltas arriving from peers take a different
path: the listener in `src/crdt/sync.rs::TaskListSync::start_with_spawner` merges them with
`TaskList::merge_delta`, whose only admission test is the `authorized_agents` set that
`tasks.rs::apply_group_authorization` derived from the group's active members — **the
contested roster itself**. The asymmetry is the defect: the local operator is refused while
a peer seated by the disputed roster keeps claiming and completing, moving the CRDT's
deterministic winner during the incident. Row 20 does not cover this, and row 24's
deliberate "keep ungated" is about group *metadata*/state-commit apply, which must stay
ungated so the clearing commit can arrive.

Both gaps share ADR 0066's own shape: the act is destructive or authority-bearing, the
marker is knowable cheaply at the point of the act, and the containment must not blind the
operator or make a quarantine unclearable.

## Decision Drivers

- Containment must not destroy evidence (R3, row 14) **and** must not hand a flooder a
  node-level disk DoS: a hard pin with no ceiling trades one failure for a worse one.
- A quarantine must remain clearable. Anything that gates the arrival of the clearing
  commit is forbidden (row 24).
- No schema change. `history.db` is at `SCHEMA_VERSION = 4` and `migrate` refuses a
  database newer than the running binary, so a schema bump is a breaking, non-downgradable
  change for a containment feature that can be computed live.
- Both spellings, one resolver. The `named_groups` map is keyed by whichever alias this
  node learned the group under, while history rows and task-list ids carry the **stable**
  id. Every marker lookup added here goes through `resolve_group_entry_locked`.
- Cost: the reaper may add O(scopes) per pass, never O(rows × groups); the task ingest hot
  path may add one resolver read and a scalar compare when no marker is live.
- Blast radius bounded to group-scoped surfaces: DM and topic history scopes, and task
  lists not bound to a named group, must behave exactly as before.

## Considered Options

Recorded from the #732 decision brief, with the ratified choice first.

**D1 — retention reaper.**

1. **A (ratified) — pin quarantined scopes with a per-group byte ceiling.** The reaper
   skips rows whose `group:<id>` scope has a live marker (both spellings); pinned rows are
   bounded by a per-group ceiling, beyond which the oldest rows *within that group only*
   are evicted and counted.
2. B — hard pin, no ceiling. Unbounded disk growth under flood; node-level DoS.
3. C — ops-only: leave the code, tell the operator to raise the retention bounds during an
   incident (already in the runbook). Relies on a human noticing inside the retention
   window.

**D2 — inbound peer task deltas.**

1. **A (ratified) — tag-and-retain: buffer, do not apply.** A bounded per-list buffer holds
   inbound deltas while the marker is live and applies them in arrival order on clear.
   Mirrors R3's "never refuse, never act".
2. B — drop while quarantined and rely on anti-entropy after clear. Simplest, silent loss,
   slower convergence.
3. C — keep applying (status quo). The disputed roster keeps mutating shared state during
   the incident, which contradicts the point of quarantine.
4. D — apply but annotate the read. Visible, not contained.

## Decision

### D1-A — the retention reaper pins quarantined scopes, subject to a per-group ceiling

**What is pinned.** Before each retention pass the reaper asks for the set of canonical
scope strings that are currently quarantined. That set is derived live from
`state.named_groups` — no new persisted field, no schema change, exactly as slice 4's
derived `fork_quarantined_at_ingest` tag is derived per read — and it lists **both
spellings** (map key and `stable_group_id()`) for every entry holding a marker, reusing
`history.rs::all_quarantine_markers`, which already resolves that way for
`/history/stats` and `/diagnostics/history`. Rows live under the stable id; the alias
spelling costs one extra set member and is what makes an alias-keyed group pinned rather
than silently unprotected.

**What pinning does.** In `Store::retain`, all three eviction phases — the age bound, the
per-scope byte budgets and the whole-database byte budget — exclude rows in a pinned
scope. Global bounds continue to hold for everyone else: an unpinned scope is evicted
exactly as before, so a flood cannot make a quarantine cost other groups their history.

**The ceiling.** Pinned rows are not unbounded. Each pinned group has its own ceiling,
derived from the retention bounds the code actually has (`RetentionPolicy.max_bytes`,
default `DEFAULT_MAX_BYTES` = 1 GiB; `scope_limits`, default empty; `max_age_days`,
default 0 = age eviction off):

```text
base(g)    = explicit ScopeLimit.max_bytes for group:<g>, if the operator configured one
           = policy.max_bytes / HISTORY_QUARANTINE_PIN_BASE_DIVISOR   (64)  otherwise
ceiling(g) = min( HISTORY_QUARANTINE_PIN_MULTIPLIER (4) * base(g),
                  policy.max_bytes / HISTORY_QUARANTINE_PIN_ABSOLUTE_DIVISOR (16) )
```

*Why these numbers.* The multiplier is the brief's 4× "relative to the normal per-scope
bound": a quarantined group may keep roughly four retention windows' worth of its own
history so the record spans the incident rather than the last few minutes of it. A scope
with no configured limit has no per-scope bound in the code at all — its only bound is the
whole-database budget — so one has to be synthesised, and 1/64 of the database budget
(16 MiB at the default) makes the *pinned* ceiling 1/16 of the budget, 64 MiB at the
default. That is large enough for a real forensic record and small enough that a dozen
simultaneously quarantined groups still fit inside one database budget's worth of
overshoot. The absolute divisor is a cap, not a second policy: it only bites when an
operator has configured a per-scope limit larger than 1/64 of the database budget, and
stops `4 ×` a large explicit limit from swallowing the whole store. At the defaults the
two arms coincide at 64 MiB, which is the intended common case.

**Beyond the ceiling.** When a pinned group's measured bytes exceed its ceiling, the
reaper evicts oldest-first **within that group only** (`replace_key IS NULL`, in the same
`RETAIN_EVICT_BATCH` = 256 steps as the normal path) and adds each row to
`history_quarantine_pinned_evictions`. No other scope's rows are ever chosen to pay for a
pinned group's overshoot: a flooder can burn its own group's ceiling and nothing else.

**Worst-case disk bound.** With `G` groups simultaneously quarantined on this node, the
database is bounded by

```text
bytes <= policy.max_bytes + G * (policy.max_bytes / 16)
      =  policy.max_bytes * (1 + G/16)
```

i.e. ≤ 2 GiB at the 1 GiB default for G ≤ 16, and this is the bound that matters: `G` is
the number of groups **this node has joined** that are simultaneously forked. A remote
attacker can inflate rows, which the ceiling bounds, but it cannot inflate `G` — joining is
a local act. That asymmetry is the reason option A is safe where option B is not, and it is
also the accepted residual: an operator in hundreds of groups, all forked at once, must
raise or lower `[history] max_bytes` deliberately. `history_quarantine_pinned_scopes`
reports `G` each pass so the operator can see it.

**On clear.** Nothing is unwound. The marker disappears from the derived set, the scope
stops being excluded, and the very next pass evicts it under the normal age and byte rules
— including rows the pin kept alive past the age bound.

**No schema change.** The pinned set is materialised per pass into a connection-local
`TEMP` table and joined against; `SCHEMA_VERSION` stays 4, `migrate` is untouched, and an
older binary reading the same `history.db` sees nothing new. Cost is O(pinned scopes)
inserts per pass plus one indexed lookup per eviction candidate — never O(rows × groups) —
and the common case (no marker anywhere) skips the table and runs the original statements
unchanged.

**Library embeddings.** `HistoryService` lives in the `x0x` library and knows nothing about
named groups, so the pin source is injected by the daemon after `AppState` exists, through
a set-once slot the reaper reads each pass. It holds a `Weak<AppState>` so the injection
cannot form an `Arc` cycle with the Agent that owns the store (#661's deterministic drop
ordering depends on that). A library embedding that never installs a source pins nothing
and retains exactly as it does today; a source whose `Weak` has expired (shutdown) pins
nothing, which is safe because the reaper is being torn down in the same breath.

### D2-A — inbound peer task CRDT deltas are buffered, not applied, while a marker is live

**The gate.** A task list is bound to a named group by its id shape,
`x0x.group.<group_id>.symphony.<list_id>`
(`tasks.rs::parse_group_scoped_task_list_id`) — a stable, cheap binding. For such a list,
and only for such a list, the daemon installs an ingest gate at the one choke point that
already derives group facts for the CRDT layer, `tasks.rs::apply_group_authorization`
(called by the create/join route and by subscription rehydration). The gate resolves the
marker through `delegations::fork_quarantine_marker`, i.e. through
`resolve_group_entry_locked`, so an **alias-keyed** group is found by the stable id its
list carries. A list with no group binding gets no gate and is byte-for-byte unaffected.

**What happens while the marker is live.** The listener does not merge. It appends
`(peer_id, delta, verified writer)` to a per-list buffer, in arrival order, and leaves the
`TaskList` **byte-identical**. Bounds per list:

```text
TASK_QUARANTINE_BUFFER_MAX_DELTAS = 1024
TASK_QUARANTINE_BUFFER_MAX_BYTES  = 1_048_576   (1 MiB)
```

Whichever bound is reached first, the **oldest** buffered delta is dropped to make room and
`task_deltas_quarantine_dropped` is incremented. Dropping the oldest keeps the newest
state-bearing deltas, and dropped work is not lost: CRDT merges are idempotent and the
state-sync side channel re-serves full state, so anti-entropy refills anything dropped
after the clear. `task_deltas_quarantine_buffered` counts what went into the buffer and
`task_deltas_quarantine_applied` what came out, all three per group in `GroupCounters`
(`/diagnostics/groups`), next to `fork_quarantine_refusals`.

Worst-case memory: ≤ 1 MiB plus per-entry overhead per group-scoped task list this node
replicates — bounded, like `G` above, by what the operator has joined, not by what a peer
sends.

**On clear (manual or owner-anchored).** The buffer is applied in arrival order through the
same `merge_delta` call the listener would have made, with the same verified writer
identity, and the list is persisted once at the end. Order is preserved because CRDT
idempotence makes replay safe but does not make it order-free for the LWW registers.
Application is driven by the listener itself observing the marker gone — on the next
inbound delta, or on a bounded poll while the buffer is non-empty — rather than by hooking
each of the several sites that can clear a marker. That is deliberate: `fork_quarantine` is
cleared at a manual route, at the metadata-apply path, at an explicit owner seal and at
rollback arms, and an enumeration of writers whose failure mode is "one clear forgot to
drain" is exactly the fail-open census ADR 0067 rejected. Observing the marker's absence
has one code path and cannot be forgotten. An explicit resume entry point exists on the
handle for the clear route and for deterministic tests.

**Process-local, by design.** The buffer is memory only. A daemon restart loses it; the
CRDT then converges by anti-entropy, exactly as it does for any delta the node was offline
for. Buffered deltas are never persisted and never published onward.

**Reads during quarantine.** Unchanged in shape and unchanged in openness. `GET
/task-lists` and `GET /task-lists/:id/tasks` keep serving — they are row 20's read half —
and keep the existing `fork_quarantined: true` plus `fork_quarantine` annotation object
(`tasks.rs::list_tasks`). What they show is the **frozen** pre-quarantine state: the local
replica as of the moment the marker installed, plus any purely local reads of it. Nothing
new is added to the response: an operator reading a quarantined list sees the annotation
that says why it is frozen, and the same annotation on the list index. The buffer is not
exposed as task content, because content the node has decided not to apply must not read
back as if it had been applied.

**Group metadata ingest stays ungated (row 24).** Untouched here. The clearing commit
arrives on that path; gating it would make quarantines unclearable. Nothing in this
decision may be read as widening row 24.

**Marker installed mid-apply.** The listener's decision and its merge are one step under
the list write lock, and the buffering path takes no persistence lock and produces no
persisted effect, so there is no window in which a delta is half-applied. Where a *persist*
is involved — the snapshot after a merge, and the drain's single persist — the ADR 0067
lifecycle-epoch-token re-check applies under the same guard that performs the persist: the
token is captured with the decision and re-checked before the persisted effect, and a
mismatch abandons the drain, leaving the buffer for the next observation rather than
writing state derived from a stale marker reading.

## Consequences

### Positive

- A quarantined group's history survives age and byte pressure, including pressure a
  flooder manufactures, so the forensic record is still there when the operator reads it —
  which is what R3 and row 14 already promise and what the reaper quietly broke.
- Local refusals and remote ingest finally agree: while membership is disputed, *nobody*
  moves the task list, not the local operator and not a peer seated by the disputed roster.
- Both mechanisms are bounded, and both bounds are stated in bytes with a worst case that
  an operator can compute: `max_bytes * (1 + G/16)` on disk, 1 MiB per group-scoped list in
  memory.
- No schema change, no new persisted field, no migration, no downgrade hazard.
- Counters make both mechanisms observable: pinned scopes and pinned evictions on
  `/diagnostics/history`, buffered/dropped/applied per group on `/diagnostics/groups`.

### Negative / Trade-offs

- Disk can exceed `[history] max_bytes` by up to `G/16` of it while `G` groups are
  quarantined. Accepted, bounded, and reported; the operator's lever is `max_bytes` itself.
- A quarantined group's task list is frozen for everyone on this node until the marker
  clears. That is the intended containment, and it is the same trade-off row 20 already
  makes for local mutations, now applied symmetrically.
- Buffer overflow drops deltas. Recovery depends on anti-entropy, so convergence after a
  clear can be slower than a pure replay; the drop is counted, never silent.
- The buffer is lost on restart, so a restart during quarantine converts "replay on clear"
  into "anti-entropy after clear".
- The reaper's pin set is a read of live state taken once per pass: a marker that installs
  *during* a pass is honoured on the next one, up to 300 s later. Accepted — the window is
  one retention pass and eviction is oldest-first, so what it can cost is bounded by the
  same age and byte pressure that existed before this ADR.
- Two more injection points from the daemon into the library (pin source, ingest gate),
  each a set-once slot holding a `Weak`. The alternative — teaching the library about named
  groups — is worse.

### Neutral / Operational

- Runbook gaps (b) and (c) close, with the operator-visible behaviour named: pinned history
  with a per-group ceiling and two counters; task lists freeze and catch up on clear.
- The "raise the retention bounds before triage" mitigation in (b) stops being necessary
  and stays as advice for very long incidents (it raises the ceiling too, since the
  ceiling is derived from `max_bytes`).
- DM and topic history scopes, non-group task lists, and every ADR 0066 §1 row keep their
  current behaviour exactly.

## Validation

### Attack / regression matrix

| Scenario | Expected behaviour |
|---|---|
| Flood a quarantined group's history to evict it | Pinned rows survive the age and global passes; only that group's own ceiling overflow evicts, oldest-first, counted in `history_quarantine_pinned_evictions` |
| Flood a quarantined group to evict a **healthy** group | Healthy scopes keep their normal bounds and are evicted exactly as before; the pin never redirects pressure onto another scope |
| Many groups quarantined at once | Disk bounded by `max_bytes * (1 + G/16)`; `history_quarantine_pinned_scopes` reports `G`; residual accepted and documented |
| Disputed-roster peer claims/completes a task during quarantine | Delta buffered, `TaskList` byte-identical, nothing published; applied in arrival order after clear |
| Buffer exhaustion (> 1024 deltas or > 1 MiB) | Oldest dropped, `task_deltas_quarantine_dropped` incremented, newest retained; anti-entropy refills after clear |
| Alias-keyed group (map key ≠ `stable_group_id()`) | Pinned in the reaper and gated in task ingest under the stable id the rows and the list id carry; a bare `groups.get()` would miss both |
| Marker installed mid-apply | Buffer/merge decision and merge are one step under the list write lock; where a persist follows, the ADR 0067 token is re-checked under the same guard and a mismatch abandons the drain |
| Marker cleared | History: the next pass evicts under normal rules. Tasks: buffer applied in order, then ingest is ungated |
| Non-group task list, DM/topic history scope | No gate, no pin, no behaviour change |
| Group METADATA ingest (row 24) | Still ungated, so the clearing commit still arrives |

### Fixtures

- The ADR 0066 coverage fixture gains explicit entries for these two surfaces, asserted
  exactly, while ADR 0066's own 26 rows, its disposition counts, `OPEN_ROWS == &[]` and
  `PENDING_RECHECK == &[]` stay asserted and unchanged.
- Reaper: a quarantined group's rows survive a pass that evicts an equally old healthy
  group's rows; the ceiling is enforced within the group only, with the counter; healthy
  groups' bounds are unaffected under a quarantined-group flood; an alias-keyed group is
  pinned; after clear the next pass evicts normally. Deterministic — rows carry an explicit
  `seen_at_ms`, so no test sleeps.
- Tasks: an inbound delta for a quarantined group's list is buffered and the CRDT state is
  byte-identical; the buffer applies in arrival order on clear; bounds drop the oldest and
  count it; a non-group list is unaffected; the alias-keyed variant is gated; metadata
  ingest still applies.
- Each mechanism ships with a negative control proving the test can fail: the same fixture
  run with the pin source absent (rows die) and with the gate absent (delta merges).
- `adr0066_lookup_guard`'s waiver census stays at 12: nothing added here spells the
  two-spelling rule out for itself.

### Migration notes

None required. No schema change (`SCHEMA_VERSION` stays 4), no new persisted field, no
config key. `[history] max_bytes` and `scope_limits` keep their meanings and now also
determine the pinned ceiling. A node running an older binary against the same data dir
behaves as it does today. A daemon restart during quarantine loses the in-memory task
buffer and converges by anti-entropy.

### Residuals

1. Disk overshoot up to `G/16` of `max_bytes`; `G` is operator-controlled, not
   attacker-controlled.
2. One retention pass (≤ 300 s) of latency before a newly installed marker pins.
3. Task deltas dropped on buffer overflow, and the whole buffer on restart, both recovered
   only by anti-entropy.
4. Reads of a quarantined task list show frozen state; a viewer who does not read the
   annotation could mistake it for a quiet list. The annotation shape is row 20's and is
   unchanged.
5. The pin source and the ingest gate are absent in library embeddings, which therefore
   get today's behaviour. Documented, not asserted by a fixture, because a library
   embedding has no marker to honour.

## Notes for AI-assisted work

Ratified by David Irvine on 2026-09-20 (D1 option A, D2 option A) from the #732 decision
brief. This ADR is Accepted and therefore immutable: its bytes freeze at the commit that
introduces it, and any change of substance requires a superseding ADR. The implementing PR
requires cross-model (omp) review; the author model must not review its own work.
