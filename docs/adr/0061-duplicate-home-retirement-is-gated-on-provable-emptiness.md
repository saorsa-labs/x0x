# ADR 0061: Duplicate-Home Retirement Is Gated on Provable Emptiness

- **Status:** Proposed
- **Date:** 2026-09-06
- **Decision owners:** David Irvine (direction), Claude (drafting)
- **Reviewers:** — (independent review pending)
- **Supersedes:** none
- **Superseded by:** none
- **Amends:** none. Fills the retirement gap [ADR 0060](./0060-one-home-per-owner.md)
  explicitly deferred ("adoption, retirement and any device-vs-rider Home
  eligibility rule are out of scope for this ADR").
- **Related:** issue #449 (P4); #506/PR #509 (Hidden-group card leak, merged);
  ADR 0023 (durable local history); ADR 0038; ADR 0039

## Context

ADR 0060 made the owner's canonical Home an elected value and left every
losing device holding its own duplicate. Those duplicates are inert — they no
longer resolve as Home and are no longer advertised — but they persist, and
until they are cleared the fork #449 reported is still visible in the roster.

Retiring one is not a tidy-up. Withdrawal is **terminal**, and
`withdraw_named_group_terminal` cleans **crypto material only**:
`clear_group_info_key_material` clears exactly `shared_secret`. Everything else
keyed by the dead group id survives with nothing left to reach it:

| Data | Where | Keyed by group id |
|---|---|---|
| Durable message history | `history.db`, `(scope_kind=1, scope_id=<stable id>)` | yes |
| Group delegations | **only** in history under `Scope::Group`, rebuilt by rescan | yes |
| CRDT task lists | `x0x.group.<gid>.symphony.<list>` — naming convention only | by convention |
| Rider-token grants | `rider-tokens.json`, raw group ids | yes |
| TreeKEM material | `treekem/<gid>.snap\|.journal\|.hsjournal` | yes (filename) |

`Store::purge(&Scope)` exists but its only caller is `DELETE /history`. So a
naive "delete the duplicate" silently orphans a user's messages and, because
delegations live only in history, their group delegations too.

Two further hazards had to be closed before any retirement was safe, and both
were: `find_home` had no `!withdrawn` filter, so a retired Home still resolved
and would have wedged `GET /home` and re-provisioning permanently (fixed in
ADR 0060's change); and withdrawing a **Hidden** group published a public
discovery card carrying its name, description, owner and member count (#506,
fixed in PR #509).

## Decision Drivers

- Nothing a user could still want may be deleted without their say-so.
- A device must never be left with no Home.
- The common case — a Home auto-provisioned by the fork and never touched — is
  genuinely empty, so the safe path should also be the quiet one.
- "Cannot prove empty" must behave like "not empty".

## Considered Options

1. **Auto-retire whenever the join succeeds.** Simplest, leaves no residue.
2. **Never auto-retire**; always require an explicit owner action.
3. **Auto-retire only when the duplicate is provably empty**, otherwise report.

## Decision

We will adopt option 3.

- A duplicate is retired automatically **only** when every condition holds:
  this device is seated in the canonical Home; the duplicate is not already
  withdrawn; it is Home-shaped for the current owner; this device is its
  **sole** active member; it has no pending join requests and no outstanding
  invites; it has **no durable history rows**; no group-scoped CRDT task list
  names it; and no rider token grants it.
- The order is **join first, retire second**, never the reverse. Retirement
  only runs once `resolve_home` reports `Local` on the canonical Home, so a
  device that has not adopted retires nothing however empty its duplicate
  looks.
- The gate **fails closed**: a probe that cannot prove emptiness — an
  unreadable history store, a failed probe — is itself a blocker.
- Anything not provably empty is **kept and reported**. `GET /home` returns a
  `duplicates` array carrying, per duplicate, `safe_to_retire` and the list of
  `blockers`, plus a `warnings.unretired_duplicate_home` flag. Home itself
  works; this is the owner's cleanup list, not an error state.
- Retirement goes through the audited `leave_group` terminal path rather than
  reaching for internals, so the sole-member disposition, terminal seal,
  TreeKEM prune and member-scoped `GroupDeleted` all still apply.

## Consequences

### Positive

- The common case (an untouched forked Home) clears itself silently.
- No automated path can orphan history, delegations, task lists or rider
  grants, because their presence is exactly what blocks the automation.
- The owner is told *why* a duplicate survived, not merely that it did.

### Negative / Trade-offs

- A duplicate holding any content persists indefinitely: there is no forced
  `POST /home/retire` yet, so the only exit is manual group deletion with the
  orphaning consequences above. That endpoint, and the purge/repoint work it
  needs, remain open.
- The gate is conservative by construction and will keep duplicates that a
  human would judge disposable.
- Reporting cost: `GET /home` now runs a history probe per duplicate. Bounded
  by duplicate count (normally zero) and by `limit: 1`.

### Neutral / Operational

- Retirement runs at daemon start, after `provision_home`, so a device that
  adopted while offline clears its duplicate on next start.
- Un-owned installs are untouched: no owner key, no Home, no retirement.

## Validation

- A device **not** seated in the canonical Home retires nothing, even with a
  provably empty duplicate (`nothing_is_retired_before_adoption_completes`).
- A freshly created, untouched duplicate is retired once the device is seated
  in the canonical Home, and the canonical Home survives
  (`empty_duplicate_is_retired_once_seated_in_canonical`).
- A duplicate carrying one durable history row is **kept**, and the blocker is
  reported (`duplicate_with_history_is_kept_and_reported`).
- A pointer to a Home retired before shutdown does not, after a real restart
  from the same data dir, suppress a replacement
  (`a_retired_pointer_does_not_survive_restart_to_suppress_replacement`) —
  this also closes the restart gap ADR 0060 recorded as unvalidated.
- **Not validated here:** forced retirement of a non-empty duplicate, and the
  history/delegation/task-list/rider-grant purge or repoint that it would
  require. Deliberately out of scope; see Negative above.
