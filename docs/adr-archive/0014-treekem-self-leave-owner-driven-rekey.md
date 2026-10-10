# ADR 0014: TreeKEM Self-Leave Is a Roster Removal; PCS Comes From an Owner-Driven Rekey

- Status: Accepted (2026-06-07). The roster-removal half ships in PR #99
  (codex/x0x-gui-full-dogfood); the owner responsive-rekey half is the tracked
  follow-up (see "Implementation").
- Date: 2026-06-07
- Amends: [ADR 0012](./0012-treekem-default-secure-groups.md) — refines its
  acceptance criterion "a removed member provably cannot read the next epoch"
  for the **self-leave** sub-case.

## Context

PR #99 reworked the TreeKEM self-leave handler (`leave_treekem_group` in
`src/bin/x0xd.rs`). The previous implementation tried to rekey the group from
the **leaving member's own** `TreeKemGroup` (`guard.remove_member(local_agent)`)
and publish the resulting commit. That path could not work:

- `saorsa_mls::TreeKemGroup::remove_member` explicitly rejects self-removal —
  `treekem_group.rs:454`: `if self.tree.own_leaf() == Some(leaf) { return
  Err(InvalidGroupState("cannot remove self via remove_member")) }`. This is
  RFC-9420 behaviour, not a library quirk: **the committer of a Remove cannot be
  the member being removed.**
- It also required the group's `TreeKemGroup` to be loaded in `treekem_groups`,
  returning `FAILED_DEPENDENCY` otherwise.

So pre-PR self-leave typically returned `409 CONFLICT` ("TreeKEM self removal
failed") — the member could not leave, and **no forward secrecy was ever
delivered by it**. The "FS/PCS on removal" guarantee in ADR-0012 was always
carried by **owner/admin removal** (a *remaining* member commits), which still
works and which PR #99 preserves (`creator_auth` keeps `treekem_commit_b64`).

The reason a leaver cannot rekey themselves is fundamental. A TreeKEM rekey
provides post-compromise security because the **committer** generates a fresh
secret down its own direct path (`make_commit` → `generate_update_path` →
`commit_secret`, `treekem_group.rs:479/495`) that the removed leaf never sees;
`process_commit` refuses to advance for "the member who was removed". If the
*leaver* authored that commit, the leaver would know the new epoch secret, so it
would protect against nobody. **PCS against a departed member requires a
remaining member to author the rotation.**

PR #99 replaced the broken self-rekey with a reliable **metadata-only** leave: a
signed `GroupStateCommit` that removes the member from the roster, with
`treekem_commit_b64: None` and `treekem_epoch: None`. That is the correct first
half. The consequence to make explicit: because leave now *succeeds* without a
rotation, the group continues at the same epoch and the departed member retains
the ability to read future group traffic until something else rekeys.

## Decision

Model self-leave as the MLS **propose → commit** split, with a single,
well-defined committer:

1. **Self-leave is a signed self-targeted roster removal** (PR #99's behaviour).
   The leaver publishes a `MemberRemoved` carrying a signed `GroupStateCommit`,
   `treekem_commit_b64: None`, authorized iff `sender_hex == agent_id &&
   actor == sender_hex` (the member removing only themselves). The leaver does
   **not** — and cannot — rekey. This always succeeds locally regardless of
   whether the TreeKEM group is loaded, so leave is reliable.

2. **The owner issues the responsive rekey.** On applying a self-leave
   `MemberRemoved`, the group **owner** (a remaining member) issues a
   `TreeKemGroup::remove_member(leaver_leaf)` commit — the existing admin-remove
   path — which rotates keys, advances the epoch, and is fanned out to remaining
   members as a `creator_auth` `MemberRemoved` carrying `treekem_commit_b64`.
   This is what delivers PCS against the departed member.

3. **Owner-only (single-writer).** Only the owner commits the rekey. This
   codebase's TreeKEM convergence history (dueling commits / read-modify-write
   roster clobber, the reason `group_membership_lock` exists) makes a
   single-writer rotation the safe choice. We **accept** that the owner is a
   single point of failure for *PCS timing*: if the owner is offline when a
   member leaves, the rotation is deferred.

4. **Lazy catch-up.** If the owner was offline at leave time, the rekey happens
   on the owner's next online reconciliation pass / next group commit. The
   exposure window is bounded by owner availability, not left open indefinitely
   by design.

5. **Admin/ban removal is unchanged.** Involuntary removal already rekeys (a
   remaining member commits); PR #99 keeps the `treekem_commit_b64` requirement
   on that path. No change.

## Security properties

- **Forward secrecy is unaffected.** A self-leaver legitimately held the
  current and prior epoch secrets; FS is about protecting *past* content from a
  *future* compromise and is not weakened by how leave is handled.
- **Post-compromise security against the departed member is delivered by the
  owner's responsive commit**, not by the leave itself. Between the self-leave
  and the owner's rekey, the departed member can still read group traffic. This
  is exactly the window any MLS group has between a Remove **proposal** and its
  **commit** — bounded and well understood, now made explicit rather than hidden
  behind a 409.
- **Honest labelling (ADR-0010/0012 carry-over).** We do not claim self-leave
  alone provides PCS. The guarantee is "PCS once the owner rekeys"; docs and any
  status surface must say so.

## Consequences

### Positive
- Leave actually works (was effectively broken: 409 on the self-remove).
- Symmetric with admin/ban removal — one rotation mechanism (remaining-member
  commit), reused, not a second crypto path.
- Sidesteps the library's correct refusal to self-remove instead of fighting it.

### Negative / cost
- Owner is a SPOF for PCS *timing*; a permanently-gone owner leaves the group
  unable to rotate out a self-leaver (see open question).
- Adds an owner-side "on observed self-leave → issue remove commit" trigger plus
  its lazy catch-up, with the same ordered-Commit-delivery care ADR-0012
  Phase 3.5 calls out (epoch N's commit must apply before N+1's).

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

## Open questions

1. **Permanently-absent owner.** With owner-only rotation, a group whose owner
   never returns cannot rekey out a self-leaver and is PCS-frozen at that epoch.
   Do we (a) accept this (owner is expected to be available, as today for
   creation/upgrade), or (b) add an "any remaining member, lowest leaf index"
   fallback after a timeout — which reopens the dueling-commit risk
   `group_membership_lock` exists to prevent? Lean (a) for now; revisit if
   ownerless-group resilience becomes a requirement.
