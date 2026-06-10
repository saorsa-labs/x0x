# Scope: Owner-Driven Rekey on TreeKEM Self-Leave

**Status:** Proposed (follow-up to [ADR-0014](../adr/0014-treekem-self-leave-owner-driven-rekey.md))
**Created:** 2026-06-07
**Owner:** unassigned
**Decision basis:** ADR-0014 (accepted). This doc scopes the *second half* — the
owner responsive rekey. The *first half* (metadata-only self-leave) shipped in
PR #99.

## Problem

After PR #99, a TreeKEM self-leave reliably removes the member from the roster
but performs **no key rotation**, so the departed member can still decrypt the
group's current epoch traffic until some unrelated event rekeys. A leaver cannot
rekey themselves (RFC-9420 / `saorsa_mls::TreeKemGroup::remove_member`
`treekem_group.rs:454` rejects self-removal). PCS must be delivered by a
**remaining** member — per ADR-0014, the **owner**.

## Goal / success criteria

1. When the owner observes a self-leave `MemberRemoved` for a TreeKEM group it
   owns, it issues a `remove_member` commit that advances the epoch and is
   fanned out to remaining members.
2. A daemon that self-left **provably cannot** `process_commit` / decrypt the
   post-rekey epoch (the ADR-0012 "removed member cannot read next epoch"
   criterion, applied to self-leave).
3. Remaining members converge to the new epoch (single-writer, no epoch race).
4. If the owner was **offline** at leave time, the rekey lands on the owner's
   next online reconciliation pass; the deferral is logged, not silent.
5. Owner-only: a non-owner member that observes a self-leave updates its roster
   and **waits** — it must not attempt a rekey.
6. fmt + clippy `-D warnings` + nextest green; no `unwrap`/`expect`/`panic` in
   prod paths.

## Design

### Trigger (owner online)
In `apply_named_group_metadata_event_inner` (`src/bin/x0xd.rs`), `MemberRemoved`
arm, the `self_leave_auth` branch (~`x0xd.rs:8284-8332`). After the roster
removal is applied and persisted:

- Guard: `info.secure_plane == TreeKem` **and** `local_agent == info.creator`
  (we are the owner) **and** `agent_id != local_agent_hex` (not our own leave —
  the owner can't self-leave anyway; that path is `CreatorMustDelete`).
- Load `state.treekem_groups[id]`, lock, call the x0x wrapper
  `guard.remove_member(leaver_agent_id)` — the same call the **admin/creator
  remove** path uses (the wrapper maps `AgentId → leaf` and, since the leaver is
  not the owner, the self-removal guard does not fire). This yields a
  `TreeKemCommit` and advances `guard.epoch()`.
- Build a follow-up `MemberRemoved` with `actor = creator_hex`, `agent_id =
  leaver`, `treekem_commit_b64 = Some(encode(commit))`, `treekem_epoch =
  Some(new_epoch)`, signed `GroupStateCommit` (owner-sealed), and publish it via
  the existing `publish_named_group_metadata_event`. This reuses the
  `creator_auth` apply path verbatim — remaining members apply it as a normal
  admin-removal rekey.
- All of the above under the per-group `group_membership_lock` (single-writer;
  prevents the dueling-commit / RMW clobber class — see
  `treekem_multimember_fix_2026_06_03`).

### Catch-up (owner was offline)
- When the owner applies a self-leave but cannot rekey immediately (e.g. the
  TreeKEM group isn't loaded yet at startup, or it's mid-reconciliation), record
  the group in a **pending-rekey set** (persisted alongside named-group state).
- On the owner's reconciliation pass (startup + the existing periodic group
  reconcile), drain the pending-rekey set: for each group, detect members
  present in the TreeKEM tree but absent from the active roster and issue the
  rekey commit (same path as the online trigger). Log each deferred rekey when
  queued and when drained.
- Detection signal: roster active-member set vs. TreeKEM tree leaf occupancy, or
  a simple `secret_epoch < roster_revision`-style marker — pick one and make it
  the single source of truth; document it.

### Ordered delivery (do not regress ADR-0012 Phase 3.5)
The rekey is an epoch N→N+1 Commit. It MUST reach all remaining members and be
applied in order. Reuse the group's existing Commit-delivery path; do not invent
a parallel one. A member behind by a commit recovers via the existing
catch-up/anti-entropy already built for TreeKEM membership.

## Affected files (expected)

- `src/bin/x0xd.rs` — `apply_named_group_metadata_event_inner` `MemberRemoved`
  self-leave branch (trigger); owner reconciliation pass (catch-up drain);
  pending-rekey persistence.
- `src/groups/` (or `src/mls/treekem.rs`) — only if the `AgentId → leaf` remove
  wrapper or a "rekey-removed-member" helper needs to be exposed; prefer reusing
  the existing creator/admin-remove helper.
- Persistence for the pending-rekey set (same `0600` model as other named-group
  state; ADR-0012 decision #6).

## Edge cases

- **Owner self-leave:** impossible — `TreeKemLeaveDisposition::CreatorMustDelete`
  forces delete, so the owner is always a remaining member when a self-leave
  occurs. Simplifies the design (no "owner left, who rekeys" race here).
- **Leaver already not in tree** (`LocalOnlyDrop` / pending stub): no rekey
  needed; skip.
- **Concurrent self-leaves:** owner processes serially under
  `group_membership_lock`; each leave gets its own epoch bump (or batch into one
  commit removing multiple leaves — decide; batching is fewer epochs but must
  still be ordered).
- **Non-owner observers:** roster-update only; never rekey.
- **Owner permanently absent:** out of scope (ADR-0014 open question — group is
  PCS-frozen; accepted for now).

## Test plan (Rule 9 — encode intent)

1. **Unit** (`x0xd.rs` tests): owner applying a self-leave `MemberRemoved`
   emits a `creator_auth` follow-up with `treekem_commit_b64: Some` and an
   advanced epoch; a non-owner applying the same self-leave emits nothing.
2. **Integration** (3 daemons — owner + member A + member B; use
   `trio_with_extra_config("")`, not the leaky `cluster()` singleton — see
   `treekem_multimember_fix_2026_06_03`):
   - Member A self-leaves.
   - Assert owner's `secret_epoch` advances and member B converges to it.
   - Assert member A (departed) **cannot decrypt** a message owner sends at the
     new epoch (`process_commit` / decrypt fails). **This is the PCS assertion**
     and the test that must fail on the pre-rekey behaviour.
3. **Offline-owner**: owner down when A leaves; bring owner up; assert the rekey
   lands on reconciliation and B converges; A still locked out.

## Risks

- **Convergence races** — mitigated by owner-only + `group_membership_lock`.
- **Missed-commit recovery** — reuse existing TreeKEM catch-up; do not fork it.
- **Test flake** — TreeKEM multi-member tests are historically flaky; use the
  non-singleton trio harness and the `treekem.trace` instrumentation.

## Out of scope

- Ownerless-group PCS (ADR-0014 open question).
- Any change to admin/ban removal (already rekeys correctly).
- The Dioxus-hook pubsub delivery op (separate communitas-repo follow-up; see
  the note in `tests/e2e_communitas_dioxus.sh`).
