# ADR-0014 mechanics — self-leave implementation & acceptance criteria

> Extracted 2026-08-29 from the immutable [ADR 0014](../adr/0014-treekem-self-leave-owner-driven-rekey.md) per the
> 2026-08-23 ADR audit. The ADR remains the complete decision record; the
> sections below are the implementation status and acceptance criteria
> relocated verbatim so this file is their maintained home — future updates
> belong here, not in the ADR.

## Implementation

- **Shipped (PR #99):** metadata-only self-leave (`leave_treekem_group`
  `LocalOnlyDrop`/`ActiveMember` dispositions; `authorized_treekem_membership_
  event_for_queue` self-leave branch; apply path `self_leave_auth` →
  `treekem_payload = None`). This half is safe to merge as-is — it is strictly
  more correct than the 409 it replaces, provided this ADR records that the
  rekey is a follow-up.
- **Follow-up (tracked):** owner responsive rekey on observed self-leave +
  lazy catch-up, reusing the admin-remove commit path; a test that a self-leaver
  provably cannot `process_commit` the post-rekey epoch.

---

## Acceptance criteria

- Self-leave succeeds and removes the member from the roster **even when the
  owner is offline and even when the leaver's TreeKEM group is not loaded**.
- On observing a self-leave, the owner issues a `remove_member` commit that
  advances the epoch; remaining members converge to it (single-writer, no epoch
  race).
- A member who self-left provably cannot derive/`process_commit` the
  post-rekey epoch (the ADR-0012 "removed member cannot read the next epoch"
  criterion, applied to self-leave).
- If the owner was offline at leave time, the rekey lands on the owner's next
  online pass; the deferral is logged, not silent.
- No production `unwrap`/`expect`/`panic`; fmt + clippy `-D warnings` + nextest
  green.
