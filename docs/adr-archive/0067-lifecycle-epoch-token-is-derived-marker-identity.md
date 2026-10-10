# ADR 0067: The Lifecycle Epoch Token Is Derived Marker Identity, Not a Generation Counter

- **Status:** Accepted
- **Date:** 2026-09-20
- **Decision owners:** David Irvine
- **Reviewers:** David Irvine (ratification); cross-model (omp) review required on the
  implementing PR
- **Supersedes:** ADR 0066 §4 token composition and Ratified decision R4 **only** —
  every other section of ADR 0066 (the §1 coverage map, §2, §3a–§3d, §5, R1, R2, R3,
  R5, the Migration/Compatibility table, the Attack/Regression matrix, the Validation
  fixtures and the Implementation slices) stands unchanged and is not touched here
- **Superseded by:** none
- **Related:** #732 (ADR 0066 slice 7), #472, #468, #469;
  `docs/adr/0066-ordinary-group-fork-anchors-and-data-plane-quarantine-coverage.md`

## Context

ADR 0066 §4 introduces a "lifecycle epoch token": every gate in slices 1–6 checks the
`fork_quarantine` marker at the *start* of an operation, so a marker installed —
or cleared, or advanced to a new evidence revision — *between* that check and the
irreversible step lets a contested write through, or wrongly refuses a permitted one.
§4's remedy is to capture a token at the authorization check and re-validate it inside
the same critical section as the mutation.

Implementation of slice 7 stalled on a contradiction **inside** ADR 0066 between its
own §4 and its own ratified R4. Both were read against the tree at `origin/main`
`00a9428`.

**§4 says the counter is a field on the record:**

> The token is the tuple `(state_revision, quarantine_generation)`, where
> `quarantine_generation` is a process-local monotonic `u64` **on the group entry**,
> incremented on every marker install and every clear (manual, owner-anchored, or
> explicit seal).

**R4 says the token adds no such participant:**

> **R4 — Compound epoch token.** *As recommended.* `(state_revision,
> quarantine_generation)` per §4, with no new persisted `lifecycle_epoch` field — no new
> serde surface, **no new #470 full-equality participant**, no new bootstrap-strip
> obligation for information already derivable.

These cannot both hold. `GroupInfo` derives `PartialEq`
(`src/groups/mod.rs:332`), and the doc comment immediately above it
(`src/groups/mod.rs:~322`) makes that equality load-bearing on purpose:

> #470: FULL record equality — derived over EVERY field, including the
> `#[serde(skip)]`/local-only ones (`owner_cert_reverify_required`,
> `issued_invite_secrets`, `issued_invites`, Home metadata, commit log, and the
> ADR-0064 `fork_quarantine` marker). The compare-and-restore rollback in
> `persist_named_groups_mutation_unlocked` uses this to decide whether a concurrent
> writer touched a key; any subset equality would call a concurrently changed record
> "unchanged" and clobber it (the original #470 failure).

So a `quarantine_generation` field on `GroupInfo` — even `#[serde(skip)]`, which is
what "no new *persisted* field" permits — is unavoidably a new #470 full-equality
participant and changes the compare-and-restore CAS semantics. Placing it anywhere
else contradicts §4's "on the group entry". §4 itself defers representation to R4
("Representation is settled by R4"), and R4 is internally consistent only if the
generation is not a `GroupInfo` field; §4's prose is consistent only if it is.

A second, independent problem surfaced in the same census. Any *process-local
counter*, wherever it lives, has to be incremented at every marker write, and the
tree has writers a counter cannot reach:

**Census of marker writers on `origin/main` `00a9428`** (production only;
`src/server/ws.rs:1624`, `src/server/routes/history.rs:1763` and
`src/groups/kv_context.rs:1009` are inside `#[cfg(test)]`/`mod tests` and are
excluded):

| Kind | Site | Reaches the persist chokepoint? |
|---|---|---|
| Install (in-memory) | `named_groups.rs:3566` `install_fork_evidence`, persisting at `:3609`/`:3611`; callers `:3839`, `:3970`, `:28366` | Yes |
| Install (on-disk recovery) | `named_groups.rs:24203` — writes the store files directly, never touching the in-memory map | **No — no in-process event at all** |
| Clear | `named_groups.rs:4210` `try_adopt_member_added_across_gap` | Yes |
| Clear | `named_groups.rs:12690` manual clear | Yes |
| Clear | `named_groups.rs:18554`, `:18623` via `GroupInfo::clear_fork_quarantine_on_explicit_owner_seal`, inside the persist closure at `:18543` | Yes |
| Clear | `named_groups.rs:3562` `rollback_live_fork_evidence` | **No — raw `state.named_groups.write()` at `:3531`** |
| Clear | `named_groups.rs:9633` metadata-apply | **No — raw `state.named_groups.write()`** |
| *Not a clear* | `named_groups.rs:2946` strips local state from an **outbound snapshot copy** and must never count as a lifecycle event | n/a |

Two real clears and one install therefore bypass the persistence lock. For a counter
that means either hand-placing a bump at each of eight sites — where a missed site
leaves a **stale generation that makes the re-check pass**, i.e. fails open, which is
the exact failure this ADR exists to prevent — or bumping inside
`persist_named_groups_mutation_unlocked` by diffing `before`/`after`, which is
provably incomplete for the three sites above. The counter's completeness cannot be
established by construction on this tree.

## Decision Drivers

- The re-check is a **security** gate: its failure mode must be refusal, never
  admission. A mechanism that can silently go stale is disqualified.
- Completeness must hold **by construction**, not by an enumeration that a future
  patch can quietly extend past.
- R4's three "no new …" clauses are the ratified constraint on representation and
  must all survive.
- ADR 0066 is Accepted and immutable; governance CI freezes Accepted ADRs at their
  first Accepted commit. The correction must be a superseding ADR, not an edit.
- The mechanism must observe the on-disk recovery install and the two lock-bypassing
  clears without needing a hook at each of them.

## Considered Options

1. **Option A — `#[serde(skip)] quarantine_generation: u64` on `GroupInfo`,** bumped
   by new `install`/`clear` methods so every writer of the field must go through them.
   Literal §4. Complete by construction for in-memory writes. **Rejected:** it is a
   new #470 full-equality participant, so it falsifies R4 and changes
   compare-and-restore CAS semantics (a concurrent bump makes `current != after`, so a
   failed transaction declines that key's rollback) in the same slice as a security
   gate. It still cannot see the on-disk recovery install at `named_groups.rs:24203`.

2. **Option B — a process-local side map in `AppState`** keyed by
   `stable_group_id()`. Satisfies all three R4 clauses; "on the group entry" reads as
   "per group entry". **Rejected:** completeness rests on hand-placing a bump at all
   eight writer sites above, two of which do not hold the persistence lock, so the
   bump could not even be made atomic with the field write; a missed or future site
   fails **open**. Still blind to `:24203`.

3. **Option C — derive the identity from the marker itself; keep no counter.**
   The token is `(state_revision, marker_identity)` where `marker_identity` is
   `Option<(revision, state_hash, committed_by, observed_at_ms, no_anchor)>` — the
   `ForkQuarantine` fields that identify *which* marker this is — or a hash of that
   tuple. Nothing is stored, so nothing can go stale.

## Decision

We will adopt **Option C**. The lifecycle epoch token is

```text
(state_revision, marker_identity)
    marker_identity := Option<(revision, state_hash, committed_by, observed_at_ms, no_anchor)>
```

derived on demand from the live `GroupInfo` — `state_revision` from the state-commit
chain, `marker_identity` from `GroupInfo::fork_quarantine` (`None` when the group
carries no marker). There is **no `quarantine_generation` counter and no new field on
any type that `GroupInfo` contains or that participates in its `PartialEq`**. The
token is a derived value: a new type with its own `PartialEq`, produced by a method on
`GroupInfo`, never stored on it.

David Irvine ratified this on 2026-09-20, choosing Option C over A and B.

Because the token is derived from the marker, every lifecycle event is observable
without a hook at its site:

- **install** — `None` → `Some(identity)`;
- **clear** — `Some(identity)` → `None`, including the two clears that bypass the
  persistence lock (`named_groups.rs:3562`, `:9633`) and the on-disk recovery install
  (`:24203`), because the token is read from whatever the live record says at
  re-check time rather than from a counter somebody had to remember to bump;
- **revision advance** — `Some(a)` → `Some(b)`, since a new evidence observation
  changes `revision`/`state_hash`/`committed_by`/`observed_at_ms`;
- **roster/lifecycle advance with no marker change** — `state_revision` moves.

The token is captured at the authorization check and re-validated **inside the same
`state.named_groups` write critical section that runs the mutation**, i.e. within
`persist_named_groups_mutation_unlocked`. A mismatch aborts before the mutation
closure runs, so no partial effect is possible, and the operation fails closed with
the ADR 0066 §5 refusal (`fork_quarantined`, with its informational reason). Both
spellings of the group key are resolved at capture and at re-check (direct map key,
then scan by `stable_group_id()`), matching the resolver ADR 0066 slice 3 established.

**A mismatch aborts even when the marker was CLEARED.** ADR 0066 §4 says "a mismatch
aborts the act before the irreversible step" without qualification, and that is kept
literally: the captured authorization was computed against a record that no longer
exists, and re-deriving it belongs to the caller, not to the re-check. A clear is not
a hazard, so the refusal is immediately retryable and the retry succeeds on its first
attempt — there is no backoff, no request budget and no retry loop, so a refusal can
neither freeze a queue head nor spin.

**The captured token is an `Option`.** `None` means "this node held no record for the
id at capture", the normal state of a first join. Comparing `Option` to `Option` makes
absent→absent a match, absent→present a refusal (a marker landed on a group the
operation was about to seat), present→present a match only on the same identity, and
present→absent a refusal. A missing record is never read as "unchanged", because that
is the fail-open reading.

**One site compares only the marker half, and says so.** The TreeKEM roster+snapshot
atomic persist exists to write an *advanced* state, so its captured and live
`state_revision` are expected to differ and a full-token comparison would refuse every
legitimate write. That site uses a separately named `same_marker` comparison; every
other site compares the full token with `==`. Naming the weaker comparison is the
point — it cannot be mistaken for the full one in review, and it is the only place the
compound token is deliberately reduced.

**Scope of the correction.** Only ADR 0066 §4's token composition and R4 are
superseded. ADR 0066 slice 7's *other* two obligations are unchanged and are
implemented as written: the `kv_context.rs` bind-time gap (rows 10–12) is closed by
making a marker change a refresh trigger for the cached KV authorization contexts, and
the race fixture is the one §4's Validation names — install a marker between a KV
authorization bind and its delta apply, and assert the apply aborts with state
byte-identical.

**Deferral (ADR 0066 §1 rows 1, 2, 4, 6).** ADR 0066's §1 Decision column asks for a
§4 re-check on outbound signed-public send, TreeKEM encrypt, GSS encrypt and GSS
reseal, but slice 7's own scope paragraph names only the persist-lock re-check, the
`kv_context` refresh trigger and the race fixture. Those four rows perform no roster
mutation and take no persistence lock, so "inside the same critical section as the
mutation" does not define a site for them; ADR 0066 defines no critical section for an
outbound publish. David ruled on 2026-09-20 that they get their own later slice. They
are already recorded `closed: true` (as `Gated`) in the coverage fixture, so the
fixture would pass either way and the gap would ship unverified. Slice 7 therefore
makes the gap **visible and asserted**: the fixture distinguishes "gated at entry"
from "re-checked before effect" and carries rows 1, 2, 4 and 6 as an
exact-equality `PENDING_RECHECK` set, so `OPEN_ROWS` can be empty while that set is
non-empty. Emptying `PENDING_RECHECK` is the later slice's job.

## Consequences

### Positive

- **Cannot go stale.** The token is read from the record it describes, so
  completeness is a property of the derivation, not of an enumeration. A future
  marker writer added anywhere — including one that bypasses the persistence lock, or
  writes the store files directly — is observed with no change to this mechanism.
- **Observes the three writers a counter cannot.** `named_groups.rs:3562`, `:9633`
  and `:24203` are covered without a hook at any of them.
- All three R4 clauses hold with room to spare: no new serde surface, no new #470
  full-equality participant, no new bootstrap-strip obligation. `GroupInfo`'s
  `PartialEq` and the compare-and-restore CAS semantics are untouched.
- The refusal direction is fail-closed: any observed difference, including a
  cosmetic one such as a case change in `committed_by`, refuses rather than admits.

### Negative / Trade-offs

- **The token is not monotonic.** It is an identity, not a clock: given two tokens
  one can say "same" or "different", not "newer". Nothing in §4's use requires
  ordering — the re-check is an equality test — but a future consumer that wants
  "has the epoch moved forward" cannot get it from this token and must not pretend
  otherwise.
- **ABA is theoretically possible.** If a marker is installed, cleared, and
  re-installed with a byte-identical identity *and* `state_revision` returns to its
  captured value, all within one operation's window, the re-check sees no change.
  This is accepted: an identical re-identity requires the same `revision`,
  `state_hash`, `committed_by`, millisecond `observed_at_ms` and `no_anchor` from a
  distinct fork observation, while `state_revision` is monotonic in the state-commit
  chain and is the token's other half. The residual window is narrower than the
  TOCTOU §4 exists to close, and unlike a counter its failure requires an active
  coincidence rather than a forgotten line of code.
- `marker_identity` reads five `ForkQuarantine` fields and deliberately excludes the
  forensic `snapshot`, which is derived from the same evidence and so cannot differ
  between two markers whose identity fields agree. A future field added to
  `ForkQuarantine` must be considered: the derivation destructures `ForkQuarantine`
  **exhaustively, with no `..`**, so adding a field fails the BUILD there rather than
  silently widening the set of marker changes the token cannot see.
- The token must not be folded into anything that crosses daemons. The census found
  `stores.rs`'s `authorization_binding` — a `(stable_group_id, state_revision,
  roster_root, security_binding, access)` hash that already behaves like a local epoch
  token — is embedded in the sealed record payload and verified by the receiving peer
  (`kv/treekem.rs:118`, `:152`). The quarantine marker is strictly local containment
  state that never rides an outbound snapshot, and two honest peers routinely disagree
  about holding one, so adding it there would be a wire-compatibility break that made
  records from an unquarantined peer unopenable. The re-check stays local.

### Neutral / Operational

- No migration, no wire change, no persisted-format change, no bootstrap-strip
  change; the token exists only in memory for the life of one operation.
- No new error code and no new counter: a mismatch refuses with the existing
  ADR 0066 §5 `fork_quarantined` refusal and its reason, so operators see the same
  condition and the same manual-clear remedy as any other quarantine refusal.
- The re-check runs inside the existing `state.named_groups` write critical section
  and performs no I/O and takes no additional lock, so the established lock order
  (membership → roster → persistence → outbox) is unchanged and no await is newly
  held under a lock.

## Validation

- **The §4 race fixture, as ADR 0066's Validation specifies it:** install a marker
  between a KV authorization bind and its delta apply; assert the apply aborts and
  state is byte-identical.
- **Per re-check site, four deterministic cases** driven by a `cfg(test)`-only
  barrier between capture and persist (no production field, parameter or branch; a
  release build must show no new warnings): marker installed mid-operation ⇒ refused
  with nothing persisted or published; marker cleared mid-operation ⇒ the outcome
  this ADR specifies for a clear; marker revision advanced mid-operation ⇒ refused;
  no marker at all ⇒ behaviour byte-identical to the pre-slice tree.
- **A negative control per site:** removing the re-check must make that site's
  install-mid-operation test fail.
- **Alias-key regression per re-check site:** a group stored under a map key that is
  not its `stable_group_id()`, with a negative control, so a bare `groups.get(id)`
  cannot creep back in.
- **A derivation-completeness test** that fails if `ForkQuarantine` gains a field the
  token's identity does not consider.
- **Coverage fixture:** ADR 0066 §1 row 22 closes; `OPEN_ROWS` becomes empty and that
  emptiness is asserted explicitly; `PENDING_RECHECK` is asserted exactly equal to
  rows 1, 2, 4, 6.
- **Review trigger (inherited from ADR 0066 §4):** if #639 or #646 land an
  alternate-chain fetch or a content-addressed base, re-examine this token — both
  introduce new irreversible steps that would need to capture it.

## Notes

- **Stale anchor in ADR 0066.** §4 cites
  `persist_named_groups_mutation_unlocked` at `named_groups.rs:4330`. On `origin/main`
  `00a9428` that function is at **`:4398`**. Recorded here rather than corrected
  there, because ADR 0066 is Accepted and immutable.
- ADR 0066's `named_groups.rs:2946` note is worth repeating in code review: that site
  clears `fork_quarantine` on an **outbound snapshot copy** and is not a lifecycle
  event. A mechanism that treated it as one would emit a spurious epoch change on
  every outbound snapshot.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human
review**. That review has happened: the contradiction and the three options were
found and drafted by Claude Opus during the slice 7 census and put to David Irvine,
who ratified Option C on 2026-09-20. The implementing PR additionally requires
cross-model (omp) review.

**This ADR is Accepted and therefore immutable.** Governance CI freezes an ADR's bytes
at the first commit where it becomes Accepted. Do not edit it — create a superseding
ADR instead.
