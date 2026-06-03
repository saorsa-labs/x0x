# TreeKEM Multi-Member Direct Delivery Fix

**Date:** 2026-06-02

## What changed

Implemented the first product fix for TreeKEM multi-member reliability: order-sensitive membership events are now delivered over direct messages in addition to metadata gossip.

### Direct join trigger to inviter

In `join_group_via_invite`, the joiner-authored `MemberJoined` event is now:

- published on metadata gossip as before,
- direct-DM delivered to the inviter immediately,
- direct-DM delivered again after `GROUP_BACKGROUND_PUBLISH_DELAY`.

This addresses the owner-side failure where a second joiner can fail to appear in Alice's roster because Alice never reliably receives the `MemberJoined` trigger.

### Direct authoritative commit delivery to members

Added helpers:

- `spawn_named_group_event_delivery_after`
- `spawn_named_group_event_delivery_to_active_members`

TreeKEM membership commit publishers now direct-deliver to relevant members:

- Invite-based authoritative `MemberAdded`: to the new joiner plus all active members.
- Direct TreeKEM add: to the new joiner plus all active members.
- TreeKEM join-request approval: to the requester plus all active members.
- TreeKEM remove/ban: to remaining active members plus target for cleanup.

Gossip remains as broadcast/backup; direct messages are now the reliability path for order-sensitive membership changes.

## Clock / ordering note

A full vector clock was not added in this patch. For current TreeKEM membership commits, the effective causal clock is the existing owner-authored state-commit chain plus `treekem_epoch`:

- `GroupStateCommit.prev_state_hash`
- `state_revision`
- `treekem_epoch`

That is a scalar causal frontier because current membership commits are creator/authority authored. A full vector clock would become useful if multiple admins can concurrently author TreeKEM membership commits. The remaining hardening item is to add bounded pending/replay for events that arrive before local TreeKEM readiness or with an epoch/state-hash gap.

## Test update

Strengthened ignored integration test:

- `tests/named_group_d4_apply.rs::d4_mls_ban_commit_advances_binding_and_converges`

It now uses Alice/Bob/Charlie:

1. Alice creates `private_secure` group.
2. Bob joins as non-banned observer.
3. Charlie joins as real target member.
4. Alice observes Bob+Charlie active.
5. Bob is confirmed on TreeKEM plane.
6. Alice bans Charlie.
7. Alice's TreeKEM epoch advances.
8. Charlie becomes `banned` in both Alice's and Bob's rosters.

## Validation

```bash
cargo test --test named_group_d4_apply d4_mls_ban_commit_advances_binding_and_converges -- --ignored --nocapture
# PASS: 1 passed, finished in ~39.8s

cargo fmt --all -- --check
# PASS

cargo clippy --all-features --lib -- -D warnings -D clippy::panic -D clippy::unwrap_used -D clippy::expect_used
# PASS

cargo check --workspace --all-targets
# PASS
```

## Remaining recommended hardening

- Add bounded pending/replay queue for TreeKEM membership events that fail because the local group is not ready or the event is ahead of local epoch/state hash.
- Add explicit catch-up requests for missing membership commits using the existing state revision/hash and TreeKEM epoch as a scalar causal frontier.
- If multi-admin concurrent membership commits are introduced later, upgrade from scalar frontier to vector-clock/dotted-version style tracking.
