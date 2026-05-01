# Joiner membership not published to metadata topic

**Status:** open ticket — symptom verified, root cause located
**Filed:** 2026-05-01
**Filed by:** dogfood harness team
**Related:** [TEST_SUITE_GUIDE.md §7c](../../TEST_SUITE_GUIDE.md), `tests/e2e_dogfood_groups.py`, `tests/e2e_vps_groups.py`, commit `0ca5133` (related-but-different first-message-after-join fix)
**Severity:** medium — application-correctness gap on `public_open` groups, no security impact

## Symptom

In the Phase-B groups dogfood (`tests/e2e_dogfood_groups.sh`), once
bob and charlie have joined alice's `public_open` group via invite,
alice does **not** see bob's or charlie's posted messages in her
`/groups/:id/messages` cache:

```
alice creates group c29c... (preset=public_open)
bob joins via invite
charlie joins via invite
alice posts "phase-b: please reply"
bob posts "phase-b: ack from bob"
charlie posts "phase-b: ack from charlie"

alice:   GET /groups/c29c.../messages
  → ["phase-b: please reply"]                             ← only own
bob:     GET /groups/c29c.../messages
  → ["phase-b: please reply", "phase-b: ack from bob"]    ← sees alice's via 0ca5133 fix
charlie: GET /groups/c29c.../messages
  → ["phase-b: please reply", "phase-b: ack from charlie"]
```

Bob and charlie can read alice's message — that's the
`first-message-after-join` path that commit `0ca5133` fixed (joiner now
subscribes to the public-message topic before the first ingest).

But alice never picks up bob's or charlie's replies. The harness
records this as a **non-blocking INFO** check today (see §7c) so it
doesn't block CI.

## Root cause

`join_group_via_invite` (`src/bin/x0xd.rs:~7578`) updates the
joiner's **own** local view:

```rust
state.named_groups.write().await.insert(group_id_hex, info.clone());
save_named_groups(&state).await;
ensure_named_group_listeners(...).await;     // OK — subscribes joiner

// fire-and-forget announcement on the CHAT topic
let chat_topic = info.general_chat_topic();
tokio::spawn(async move {
    state.agent.publish(&chat_topic_for_join, announcement_bytes).await;
});
```

The "joined" announcement goes on the **chat topic**
(`x0x.group.<gid>.chat/general`) — a free-form chat channel that
nobody consumes for member-roster updates.

Member-roster mutations are consumed via the **metadata topic**
(`info.metadata_topic`) by `ensure_named_group_metadata_listener`,
which routes payloads through `apply_named_group_metadata_event`. That
listener is the only path that updates `info.members_v2` from gossip.

Owner-driven adds (`POST /groups/:id/members`,
`src/bin/x0xd.rs:~7783`) correctly publish to the metadata topic via
`publish_named_group_metadata_event`. Joiner-side joins do not.

Net effect: the owner's `members_v2` for a public_open group is
permanently stuck at `{owner_only}` regardless of how many members
join via invite. When the joiner posts a signed public message and
the owner's listener ingests it,
`validate_public_message` rejects it as
`WritePolicyViolation { policy: MembersOnly }` because the author
isn't in the owner's view of the roster.

`grep "dropped public message" alice.x0xd.log` confirms the rejection
cleanly.

## Code path inspection

Owner (alice) state after bob joins:

```
$ curl /groups/<gid>/members      # on alice
{ "members": [{ "agent_id": "alice_aid", ... }] }      # only herself

$ curl /groups/<gid>/members      # on bob
{ "members": [
    { "agent_id": "alice_aid", ... },
    { "agent_id": "bob_aid",   ... },                  # bob added himself locally
] }
```

The asymmetry is the bug: bob's local `info.members_v2` reflects his
join, but no gossip event ever reaches alice's metadata listener.

## Proposed fix

### 1. Publish a `MemberJoined` metadata event on join

Add to `join_group_via_invite` (right after the local `info.add_member`
call), an analogue of the owner-side `publish_named_group_metadata_event`:

```rust
let event = NamedGroupMetadataEvent::MemberJoined {
    group_id: group_id_hex.clone(),
    member_agent_id: joiner_hex.clone(),
    role: GroupRole::Member,
    display_name: req.display_name.clone(),
    epoch: info.roster_revision,
    inviter: invite.inviter.clone(),
    signature: signing_kp.sign(&serialise_join_payload(...)),
    ts_ms: now_ms,
};
publish_named_group_metadata_event(&state, &info.metadata_topic, &event).await;
```

The event must be **signed by the joiner**, and the receiver-side
`apply_named_group_metadata_event` must:

1. Verify the signature.
2. Verify that the inviter named in the event is currently an admin or
   member of the group (i.e. they were authorised to issue invites at
   the time the join happened — the invite_secret already binds this
   but the metadata-channel handler should re-check).
3. Apply the join to the local `info.members_v2`.

Pure additive change — no existing behaviour breaks because today
nobody publishes this event so there's no apply-side regression risk.

### 2. Backfill on owner-side ingest

Defence-in-depth: when the owner's public-message listener receives a
signed message from an `author_agent_id` not in `members_v2`, instead
of dropping with `WritePolicyViolation`, check whether the author has
a valid invite-derived join card (the invite_secret is verifiable). If
so, add them to `members_v2` with role=Member and re-attempt validate.

This handles the race where alice's metadata-listener is briefly
behind and bob's first message arrives first.

Lower priority than (1) — without (1), backfill alone doesn't help
because the chain of evidence (the invite + signed join) isn't on the
public-message channel.

### 3. Add `/diagnostics/groups`

Per group, expose:

- `members_v2_size: usize`
- `subscribed_metadata: bool`
- `subscribed_public: bool`
- `messages_received: u64`
- `messages_dropped: u64` (with reason buckets:
  `decode_failed | author_banned | write_policy_violation | other`)
- `last_message_at_ms: Option<u64>`

The `messages_dropped { write_policy_violation }` counter would have
caught this bug at first observation. Today the only signal is a
DEBUG-level `tracing::warn!` line.

## Acceptance criteria

The bug is fixed when **all** of these hold on a fresh local 3-daemon
setup (no persisted state) and on the live VPS fleet:

1. New unit test in `tests/named_group_join_metadata_event.rs`:
   - Daemon A creates a public_open group, generates an invite.
   - Daemon B joins via the invite.
   - Within 2 s, A's `state.named_groups[gid].members_v2` contains B.
   - B publishes a signed message.
   - A's `/groups/:id/messages` cache contains B's body within 2 s.

2. `tests/e2e_dogfood_groups.py` flips its current
   `INFO alice observed 0/N member replies` line to a hard PASS:
   ```
   PASS alice sees bob's reply in /messages cache
   PASS alice sees charlie's reply in /messages cache
   ```

3. `tests/e2e_vps_groups.py` flips the same — within 30 s on a live
   cross-region matrix.

4. `GET /diagnostics/groups` exposes the per-group counters above;
   `x0x diagnostics groups` CLI maps to it.

5. No regression in the existing 30+ named-group integration tests.

## Out of scope

- MLS-encrypted groups (this is the `SignedPublic` / `Public` path
  only — encrypted groups update membership via Welcome messages).
- Owner authorisation of joiners on `request_access` groups (a
  separate flow that already publishes a metadata event on approval).
- Changing the `/groups/:id/members` POST flow (already correct).

## Why the 0ca5133 fix doesn't cover this

`0ca5133 fix(daemon): subscribe to public-message topic at every
group-insert site` ensures every group member is subscribed to the
public-message topic at all times. That fixed **first-message-after-
join** — the joiner missing the kickoff message because their
subscription was set up after the message was already broadcast.

This ticket is a different gap: even when subscriptions are correct
on both sides, the **owner's view of who's a member** is incomplete,
so messages from joiners are dropped at `validate_public_message`
with `WritePolicyViolation` rather than at the subscriber.

The two fixes compose: 0ca5133 ensures the message reaches the
listener; this ticket ensures the listener accepts it.

## Why this is a separate ticket

This was discovered while building Phase B of the dogfood-test family
(2026-05-01). It's outside the harness's job to fix — Phase B
intentionally treats cross-member convergence as INFO-only so the
harness can ship without blocking on the daemon work. Once this
ticket lands, the Phase-B harness toggles its soft-info assertions
to hard PASSes and gains a real cross-member correctness gate.
