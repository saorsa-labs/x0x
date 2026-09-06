# ADR 0065: Duplicate Homes Are Inventoried, Not Retired

- **Status:** Proposed
- **Date:** 2026-09-06
- **Decision owners:** David Irvine (direction), Claude (drafting)
- **Reviewers:** — (independent review pending; number 0065 centrally allocated to #449)
- **Supersedes:** none
- **Superseded by:** none
- **Amends:** none. Addresses — without closing — the retirement gap
  [ADR 0060](./0060-one-home-per-owner.md) explicitly deferred.
- **Related:** issue #449 (P4); #506/PR #509 (merged); ADR 0023 (durable local
  history); ADR 0038; ADR 0039; `docs/design/449-p4-retirement-fence.md`

## Context

ADR 0060 made the owner's canonical Home an elected value and left every losing
device holding its own duplicate. The duplicates are inert — they no longer
resolve as Home and are no longer advertised — but they persist, so the fork
#449 reported is still visible in the roster.

Deleting one is not a tidy-up. Withdrawal is **terminal**, and
`withdraw_named_group_terminal` cleans **crypto material only**
(`clear_group_info_key_material` clears exactly `shared_secret`). Durable
history, the group delegations that live **only** in history,
`x0x.group.<id>.symphony.*` task lists and rider-token grants all key off the
group id and would be orphaned; `Store::purge(&Scope)` is reachable only from
`DELETE /history`.

An earlier revision of this work implemented automatic retirement behind a
"provable emptiness" gate. Independent review found the proof unsound in three
distinct ways, and the fixes are not local:

1. **Startup ordering.** The retirement pass ran before
   `crdt_subscriptions::load`, so a duplicate carrying a durable task-list
   manifest entry could pass an "empty" probe and be terminally withdrawn
   *before its own evidence was loaded*.
2. **No fence across the withdrawal.** The evidence was gathered under
   several independent, sequential reads and then released. `leave_group`
   takes only the per-group membership lock, which does not serialize history
   writes, manifest writes, rider-grant changes, invite issuance, or the
   owner-sync election. A concurrent write — or a canonical-pointer change —
   can invalidate the proof while the duplicate is withdrawn anyway.
3. **Fail-open evidence.** The task-list manifest loader and the rider-token
   store both map read/parse failure to *empty*. That is correct for their own
   fail-closed uses (rehydration, token authentication grant nothing), but for
   a destructive decision it turns "could not read the evidence" into "there
   is none".

## Decision Drivers

- A terminal, unrecoverable deletion needs a proof that is *held*, not sampled.
- "Cannot read the evidence" must never read as "there is no evidence".
- Partial safety is not safety: an automated destructive path with a known
  race is worse than no automation, because it converts a cosmetic residue
  into silent data loss.
- The user-visible complaint in #449 (a device silently forking) is already
  addressed by ADR 0060; clearing residue is cleanup, not the fix.

## Considered Options

1. **Ship automatic retirement behind the emptiness gate.** Rejected: the
   three defects above make the gate unsound, and #1/#2 are not local fixes.
2. **Add a lock around the proof and the withdrawal.** Rejected for now:
   a correct fence must span history writes, the CRDT manifest, the rider
   store, invite issuance and the election — several async I/O subsystems with
   independent locks. Inventing an ad-hoc lock across them is how deadlocks
   and priority inversions get shipped; the shared fence needs its own design
   and review.
3. **Report duplicates read-only; do not delete anything automatically.**

## Decision

We will adopt option 3 as the **interim** position.

- **No automatic retirement.** The startup hook is removed; nothing in this
  code path deletes a group. Deleting a duplicate remains an explicit operator
  action through the existing audited `DELETE /groups/:id`.
- `GET /home` reports a read-only `duplicates[]` inventory. Each entry carries
  `group_id`, `retirement: "manual_only"`, and
  `evidence_against_deletion[]` — the concrete reasons found.
- **`safe_to_retire` is deliberately NOT reported.** A safety verdict is
  precisely what this device cannot currently establish; publishing one would
  invite an operator, or a later automation, to trust it.
- Evidence probes **report unavailability rather than absence**. An absent
  history handle, and a task-list manifest or rider-token store that is
  missing, unreadable or **of the wrong schema**, are each reported as
  evidence against deletion. The durable files are parsed under their REAL
  typed schemas — a generic-JSON probe is insufficient, because `null` and
  `{"entries":"corrupt"}` are valid JSON the typed loaders reject — and the
  validated durable entries, not the in-memory maps, are what the observation
  reads. The loaders' own fail-to-empty behaviour is unchanged for their own
  uses.

## Consequences

### Positive

- No automated path can orphan history, delegations, task lists or rider
  grants, because no automated path deletes anything.
- The owner can see exactly which duplicates exist and what is holding each
  one, which is the information a safe retirement would need anyway.
- The probes give an operator the same evidence a future retirement decision
  would need. Whether they are sufficient for a *destructive* decision is NOT
  claimed here: that depends on a fence that does not exist, and an
  observation taken at one instant is not a proof held across a mutation.

### Negative / Trade-offs

- **Duplicates persist.** #449's residue is visible and inventoried, not
  cleared. An owner wanting them gone must delete them by hand and accept the
  orphaning consequences above.
- `GET /home` runs an evidence probe per duplicate (normally zero).

### Neutral / Operational

- Un-owned installs are untouched: no owner key, no Home, no inventory.

## Validation

- A duplicate carrying one durable history row is reported as evidence
  against deletion (`duplicate_with_history_is_kept_and_reported`).
- An **absent** history store is evidence against deletion
  (`an_unavailable_history_store_blocks_retirement`).
- An unreadable task-list manifest is evidence against deletion
  (`an_unreadable_task_list_manifest_is_evidence_against_deletion`).
- An unreadable rider-token store is evidence against deletion
  (`an_unreadable_rider_store_is_evidence_against_deletion`).
- Valid JSON of the WRONG schema (`null`, `{"entries":"corrupt"}`, a
  wrong-typed `tokens` field) is reported unavailable, not absent
  (`wrong_schema_evidence_files_are_reported_unavailable`).
- A schema-valid durable task-list entry is observed FROM DISK, with the
  in-memory manifest untouched — the positive control, and the state the
  startup-ordering defect used to act on
  (`a_durable_task_list_entry_is_observed_from_disk`).
- **Not validated, because not implemented:** any automatic retirement. The
  conditions under which it could become safe are specified in
  `docs/design/449-p4-retirement-fence.md`; that design is unreviewed and
  unimplemented.
