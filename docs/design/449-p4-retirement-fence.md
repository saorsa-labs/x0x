# Design: what a safe duplicate-Home retirement would require (#449 P4)

- **Status:** Design only — **nothing here is implemented.** Interim shipped
  behaviour is read-only inventory (ADR-0065).
- **Date:** 2026-09-06
- **Related:** #449; ADR 0060; ADR 0065; ADR 0023 (durable history)

## Why this document exists

An earlier revision implemented automatic retirement behind a
"provable-emptiness" gate. Independent review found the proof unsound. Two of
the three defects are not local fixes, so this records what would actually be
needed *before* any code grows, rather than iterating on a destructive path.

## The problem, precisely

Retirement is a **terminal** withdrawal. Its safety claim is:

> at the instant of withdrawal, no durable artifact keyed by this group id
> exists that would be orphaned by it.

Everything below is about the words *at the instant of*.

The evidence lives in five subsystems, each with its own lock and its own
durability model:

| Evidence | Owner | Written by |
|---|---|---|
| Roster, invites, join requests | `named_groups` + per-group membership lock | REST handlers, gossip listeners |
| Durable history rows | `history.db` (sqlite) | async history writer task |
| Group delegations | history rows (`Scope::Group`) — no separate store | same writer |
| CRDT task-list subscriptions | `crdt-subscriptions.json` + in-memory manifest | REST handlers, rehydration |
| Rider grants | `rider-tokens.json` | REST handlers |
| Canonical-Home election | owner-sync record store | sync passes, remote peers |

`leave_group` takes **only** the per-group membership lock. Nothing serializes
the other five. So a proof assembled by reading them in sequence is stale
before it is used, and the review's P1 is exactly that: the proof is neither
held nor revalidated through the withdrawal.

## Three defects and what each needs

### D1 — startup ordering (P1)

The retirement pass ran before `crdt_subscriptions::load`, so persisted
task-list entries were invisible to the probe.

*Requirement:* retirement may only run after every evidence source has
completed its durable load, and that completion must be **observable**, not
assumed from statement order. A `startup_evidence_ready` signal each subsystem
sets, awaited by the retirement pass, with a startup fixture that persists a
`x0x.group.<id>.symphony.*` entry and asserts the pass does not run before it
is visible.

### D2 — no fence across the withdrawal (P1)

*Requirement:* a shared retirement fence. Two candidate shapes, neither
implemented:

**(a) Epoch validation — preferred.** Cheap, no new cross-subsystem lock.
Give each evidence source a monotonic change counter. Take the proof, record
the tuple of counters, then perform the withdrawal and — inside the same
membership-lock critical section that already exists — re-read the counters
and abort the withdrawal if any moved. This needs the withdrawal to be
abortable up to its commit point, which the terminal seal currently is not.

**(b) A retirement lock ordered above the five subsystems.** Correct but
expensive: it must be acquired before the membership lock and released after
the terminal commit, and every writer to the five subsystems must respect the
ordering. High deadlock risk, and it puts a coarse lock on the history writer's
hot path.

**Explicitly rejected:** an ad-hoc mutex held across the existing async I/O
calls. That is how deadlocks and priority inversions get shipped, and the
review warned against inventing one.

Also required regardless of shape: the terminal precondition recheck must cover
what the current one omits — `leave_disposition` rechecks pending join requests
but **not outstanding invites** — plus history, manifest, rider grants, and the
canonical-pointer identity that authorised the retirement in the first place.

### D3 — fail-open evidence (P2, FIXED in the interim)

The manifest and rider loaders map read/parse failure to *empty*. Fixed by
probing the durable files directly and treating unreadable/corrupt as evidence
against deletion. Those probes are reusable unchanged under either fence shape.

## Sequencing

1. **(done)** Read-only inventory + fail-closed probes — ADR-0065.
2. Startup evidence-ready signal (D1) with its fixture. Independent of the
   fence and useful on its own.
3. Choose and review a fence shape (D2). Needs a decision on whether the
   terminal seal can be made abortable, which is the crux of option (a).
4. Complete terminal precondition recheck, including outstanding invites.
5. Only then: automatic retirement, gated on the fence, with a race regression
   that writes evidence concurrently with the withdrawal and asserts the
   withdrawal aborts.

## What would still be out of scope

Forced retirement of a **non-empty** duplicate (`POST /home/retire`) and the
purge/repoint of history, delegations, task lists and rider grants it would
require. That is a separate decision about deleting user data on request, not
about automation safety.

## Open questions for review

1. Is clearing the residue worth a cross-subsystem fence at all? The
   user-visible #449 complaint is fixed by ADR-0060; duplicates are inert.
   Manual deletion plus the inventory may be the right permanent answer.
2. Can the terminal seal be made abortable up to commit? If not, option (a)
   is out and the cost of (b) has to be justified.
3. Should an unreadable evidence store be a *permanent* refusal or an explicit
   quarantine state an operator can clear after repairing the file?
