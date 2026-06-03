# TreeKEM 2nd-Member Welcome / Join-Result Delivery Gap

**Date:** 2026-06-03 (found right after the x0x 0.21.0 release)
**Severity:** multi-member secure groups non-functional end-to-end (single-member works)

## Summary

x0x 0.21.0 fixed the **owner-side** multi-member roster convergence (per-group
`group_membership_lock`). A cross-region **testnet** e2e then revealed a *distinct*
remaining bug: the **2nd (or later) member's join result (`MemberAdded` + `Welcome`)
is never delivered to it**, so it never enters the TreeKEM tree and cannot
encrypt/decrypt. Multi-member secure *participation* does not work yet.

## Reproduction (testnet, 0.21.0 on all nodes)

```
python3 tests/e2e_treekem_membership.py --anchor sfo --member helsinki --member2 nuremberg --iterations 1 --settle-secs 90
python3 tests/e2e_treekem_membership.py --anchor sfo --member helsinki --member2 singapore --iterations 1 --settle-secs 150
```

Both FAIL identically at `converge_member_m2`:

```
converge_roster_m1=0.34  converge_member_m1=3.31   ← 1st member: full tree-join, 3.3s
converge_roster_m2=0.34  converge_member_m2=TIMEOUT ← 2nd member: in owner roster, never joins tree
```

- Single-member (`--member helsinki`, no `--member2`): **PASS** end-to-end.
- Reproduces on two different 2nd-member nodes (nuremberg, singapore) and with 90s and 150s settle → **hard bug, not slowness / not node-specific.**

## Evidence (root-cause pointer)

On the 2nd member (singapore) journal:

```
WARN x0xd: timed out polling anchor for TreeKEM join result group_id=ee95... member=b217...
```

So:
- The anchor **does** add the 2nd member to its roster (Active) and advances the tree (owner side works — that's the 0.21.0 fix).
- The 2nd member **does** fall back to polling the anchor for its join result (the `JoinResultMessage::FetchRequest` recovery path).
- The anchor **does not return a staged result** for the 2nd member → the joiner times out → no Welcome → not in tree.

The 1st member's join-result delivery works; the 2nd member's does not. So the gap is
specific to staging/serving (or direct-delivering) the join result for a 2nd+ member.

## Where to look (x0xd.rs)

- `stage_join_result(state, event_group_id, member_agent_id, event)` — is the
  `MemberAdded`+`WelcomeRef` for the 2nd member actually staged, and under a key the
  2nd member's `FetchRequest` resolves? (The owner roster converges, so the
  `MemberJoined`→`MemberAdded` path *runs* for m2 — but the result isn't served back.)
- The join-result fetch/serve handler (the path that logs "join-result fetch before
  result was staged" locally) — does it find m2's staged result? Possible key mismatch
  (local group key vs stable id) for the 2nd member, or the staged entry is overwritten
  by a later membership mutation (note: `group_membership_lock` serializes apply, but
  verify the join-result store isn't a separate clobber-prone map).
- `WelcomeRef` fetch-by-reference for the 2nd member: is the oversized-Welcome content
  actually retrievable by m2, or only staged for m1?
- Direct delivery of `MemberAdded` to the new joiner: confirm the 2nd member is in the
  `extra_recipients` and that delivery succeeds (it should, given m2 reaches the roster).

## Test surface (now exists)

`tests/e2e_treekem_membership.py` gained `--member2` (this session): adds a 2nd joiner
while the 1st is Active, asserts BOTH converge into the tree (encrypt on treekem plane),
3-way secure round-trips, bans the 2nd, asserts the non-banned member survives + FS.
This is the regression surface that catches the bug — the local `d4_mls_ban` test only
checks roster *state*, not Welcome processing, so it cannot catch this.

## Recommendation

- Treat multi-member secure participation as **not shipped** until the 2nd-member
  join-result/Welcome delivery is fixed and `e2e_treekem_membership.py --member2`
  passes on testnet (ideally a short soak).
- 0.21.0 docs/CHANGELOG corrected this session to scope the claim to owner-side roster
  convergence + single-member.
