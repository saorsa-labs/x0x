# Named-Group Join and Roster Propagation

**Status:** reference implementation — public-open path implemented;
request-access causal-predecessor correction proposed
**Filed:** 2026-05-01
**Filed by:** dogfood harness team
**Governing decision:**
[ADR 0028](../adr/0028-authenticated-causal-predecessor-delivery.md)
**Proposed grounding (freezes with ADR acceptance):**
[ADR 0028 grounding](../grounding/0028-authenticated-causal-predecessor-delivery.md)
**Source baseline for the request-access extension:**
`0bf0da5b9c8a1a58594c027c0f472ad7c7ddf55d`
**Related:** [TEST_SUITE_GUIDE.md §7c](../../TEST_SUITE_GUIDE.md),
`tests/e2e_dogfood_groups.py`, `tests/e2e_vps_groups.py`, commit `0ca5133`
(related-but-different first-message-after-join fix)

## Request-access causal predecessor delivery

This section is the mutable reference implementation for Proposed ADR 0028.
It specifies one narrow recovery relationship:
`JoinRequestCreated` is an authenticated causal ancestor required by the
matching `JoinRequestApproved`, but it need not be the approval's immediately
preceding state commit. This mechanism does not generalize the TreeKEM frontier
log or change admission policy.

### Security objects and bindings

- The **origin envelope** is the existing V2 pubsub wire envelope for the
  group's metadata topic. Its ML-DSA-65 signature binds the requester AgentId,
  public key, topic, and exact serialized `JoinRequestCreated` payload.
- The **relay carrier** is an authenticated active admin that forwards the
  origin envelope unchanged. Carrier authorization controls relay resource
  use; it is never accepted as proof that the requester authored the payload.
- The **approval queue key** is the authenticated approval envelope digest,
  computable at admission. Its signed group/revision/previous-hash/state-hash
  coordinates and its `request_id` / `requester_agent_id` dependency identities
  are stored and checked by ordinary apply.
- `approval.commit.prev_state_hash` names the authority's group frontier
  immediately before approval. It is not assumed to equal the matching request
  commit's state hash.

The receiver independently verifies the origin envelope, derives its sender
from the embedded public key, requires that sender to equal
`requester_agent_id`, and then runs the ordinary `NonMemberRequest` apply.
Decoded JSON re-published under an authority signature is not equivalent and
must be rejected as predecessor evidence.

### Producer and relay flow

1. The requester creates the serialized event once, obtains its signed V2
   metadata envelope, publishes it on the metadata topic, and directly offers
   the same envelope to the group-card authority. The direct offer does not
   create a second author.
2. An authority verifies and applies the request before admitting a relay
   obligation. It persists the exact origin envelope and the current active
   witness target set before dispatch.
3. Approval creation refreshes the target set from the post-approval active
   roster and ensures the predecessor obligation is durable before approval
   fan-out begins. This ordering protects crash recovery; it is not assumed to
   determine receiver arrival order.
4. The relay sends the unchanged origin envelope on the bounded schedule
   below. A receiver verifies both the active-admin carrier and the requester's
   origin signature before the event may reach state apply.

The implementation must retain or expose the original V2 bytes before the
current pubsub decoder discards signature bytes. Reconstructing a decoded
message under the relay's key is forbidden. Existing event variants and fields
remain unchanged.

### Approval queue admission and drain

An out-of-order `JoinRequestApproved` may enter the causal queue only when all
checks that do not depend on the missing request succeed:

- envelope and commit sizes are within bounds;
- the group exists and is live;
- the approval origin, `actor`, and `commit.committed_by` are the same agent;
- the commit structure and signature verify;
- the actor is an active admin in the receiver's current view; and
- the request and requester identities are syntactically valid and not already
  terminal locally.

Admission writes only to the causal-queue sidecar; no call path from admission
may reach stored group state. The queue stores the exact approval envelope, its
digest, first-seen time, absolute expiry, queue key, request identity, and
requester identity.

After any accepted stateful group event advances the group under the per-group
membership lock, and after restart restoration, drain entries in signed
revision order:

```text
for queued approval in signed revision order:
    current := reread the durable group state
    if approval is already the durable current state: remove as already applied
    if approval revision is stale or conflicting: reject without mutation
    if the matching pending request is absent: retain until advance or expiry
    if approval.prev_state_hash != current.state_hash: retain until advance or expiry
    otherwise rerun the full ordinary approval apply with queueing disabled
    on success persist group state before removing the queue entry
```

Every drain reruns signature, current-admin authority, pending-request,
requester, revision, previous-hash, post-state-hash, and domain invariants.
There is no reduced "queued apply" validator.

The only chain check is the ordinary validator's
`approval.prev_state_hash == current.state_hash`; no request-to-approval
adjacency check exists. For example, authority order request(B), request(C),
approve(B), approve(C) converges even when witness arrival order is approve(B),
approve(C), request(B), request(C). The requests advance the witness through
both request commits; the drain re-reads `current` after every successful
queued apply, so each approval runs against its own signed previous hash.

If two non-identical approvals claim the same group, request, requester, and
revision, mark the `(group, request, requester, revision)` conflict identity
and apply neither automatically. A wrong request, wrong requester, wrong
previous hash, malformed signature, or expired predecessor is rejected and
cannot become a queue success.

### Bounds, expiry, and retry policy

These values are mutable implementation policy. The lower applicable limit
wins.

| Resource | Default bound |
|---|---:|
| One signed envelope | 64 KiB |
| Queued approvals per group | 64 entries and 1 MiB serialized |
| Queued approvals per daemon | 1,024 entries and 16 MiB serialized |
| Relayed predecessor outbox per group | 64 envelopes and 1 MiB serialized |
| Relayed predecessor outbox per daemon | 1,024 envelopes and 16 MiB serialized |
| Relay target obligations per daemon | 4,096 |
| Queue and relay retention | 5 minutes from first observation |
| Retry offsets from first durable enqueue | 0, 1, 2, 4, 8, 16, 30, 60, 120, 240 seconds |

On saturation, reject the new obligation or approval and record the bounded
failure; never evict a live entry and report success. Exact duplicate digests
coalesce and do not refresh the original expiry. Retry dispatch is
at-least-once and finite. State application is exactly-once through the group
lock, signed revision/hash checks, and durable completion ordering.

The 64 KiB entry ceiling means the configured causal queue and relay outbox
each retain at most 16 MiB of serialized untrusted event material per daemon
(32 MiB combined), excluding bounded map/index overhead. Relay outboxes store
one origin envelope plus a bounded target set rather than copying the envelope
per target.

### Persistence and restart

Pending approvals and predecessor relay obligations live in a versioned
sidecar under the daemon's effective data root, separate from the signed
`GroupInfo` projection. Writes use the same atomic replace and parent-directory
durability discipline as other daemon state.

On restart:

1. load with byte and count caps enforced before allocation;
2. drop malformed, oversized, expired, unknown-group, and withdrawn-group
   records;
3. revalidate signatures, bindings, and current carrier/actor authority;
4. resume remaining relay offsets from the absolute first-seen time; and
5. drain only after reloading the durable group state.

The group state must become durable before a successful queue entry is removed.
If a crash occurs between those actions, replay observes the already-current
approval `state_hash`, records it as previously applied, and removes the stale
queue entry without a second mutation. No path deletes the only durable
approval before its roster transition is durable.

### Deduplication and observability

Exact delivery duplicates key on the cryptographic envelope digest. Applied
events additionally dedupe on signed group revision and state hash. A queued
entry exposes only one terminal outcome: applied, expired, invalid, conflict,
withdrawn, or capacity-rejected.

Diagnostics expose per-group gauges for queue entries/bytes and relay
obligations, plus counters for relayed, retried, queued, deduplicated, applied,
expired, invalid, conflicted, and capacity-rejected events. Structured logs
name group, request, revision, digest prefix, carrier, cryptographic origin,
and outcome without logging request messages, key material, or full envelopes.

An `apply_metadata_event_entry` trace remains a receipt marker, not proof of
successful mutation. Validation must observe an apply-success outcome and the
resulting roster/state hash.

### Option comparison

| Option | Sender binding | Wire compatibility | Persistence/restart | Memory and scope |
|---|---|---|---|---|
| Authenticated relay + causal queue (selected) | Preserves the original requester-signed V2 envelope; separately authenticates the admin carrier | Existing request/approval schema and V2 envelope | Bounded relay outbox and approval sidecar survive restart | Narrow request/approval relationship; defaults cap serialized event material at 32 MiB combined |
| Predecessor carried inside approval | Can preserve requester evidence if the full signed envelope is embedded | Adds and versions approval fields; increases every approval | Bundles still need durable retention when an earlier state gap exists | Larger messages and duplicated predecessor bytes |
| General signed-event gap log | Can model origin and authority for many event kinds | Likely requires a versioned generic envelope/protocol | Requires ordering, pruning, migration, and replay rules for every admitted event | Widest attack surface and resource budget; exceeds the proven gap |

The selected mechanism may later be superseded by a general log, but this
proposal does not treat future reuse as evidence for present complexity.
Only requester-authored request events gain the new relay. The queue tolerates
any number of intervening commits that arrive through existing delivery, but it
does not recover an independently missing non-request transition; such an
approval remains bounded and expires. A general signed-event log would address
that wider case.

### Acceptance governance prerequisite

The separate same-stem grounding remains amendable while ADR 0028 is Proposed
and must become immutable with it on acceptance. Following decision-owner
approval, the first implementation step is to repair repository governance so
changing or deleting an Accepted ADR's grounding fails while Proposed
grounding remains amendable. The repair must also match required headings
exactly and compare against the branch/pull-request base so a newly introduced
ADR remains structurally checked across amendment commits. ADR 0028 must not be
marked Accepted before those controls and their positive/negative tests land.

### Behavioural controls

The implementation is not complete until independent controls demonstrate:

1. the authority authors request(B), request(C), approve(B), approve(C), while
   the witness receives approve(B), approve(C), request(B), request(C): neither
   approval mutates the roster before the requests; after request(C), both
   apply exactly once in signed revision order. A sibling case places a
   delivered non-request state transition between request and approval: no
   approval-driven roster mutation occurs before the signed transition arrives,
   then the approval applies exactly once after that transition advances the
   witness to the approval's signed frontier;
2. with one requester and no intervening state transition, approval before
   request queues with no mutation and applies exactly once after the matching
   signed request arrives;
3. a permanently missing predecessor stays within count/byte/time bounds,
   expires, and never becomes success;
4. tampered origin evidence, wrong request/requester, and wrong previous hash
   each fail closed with no roster mutation;
5. immediate, delayed, and post-restart duplicates are idempotent; and
6. the unchanged five-daemon `active_recipient_sealing_gates` family reports
   5 passed and 0 failed within its existing barrier.

Each negative control must attribute the intended condition. A longer barrier,
skipped row, changed roster observation, or receipt-only trace does not satisfy
the control.

Sensitivity is mandatory: restoring the deleted equality between an
approval's previous hash and its matching request's state hash must fail
control 1, while control 2 restricted to one requester with no intervening
state transition and the unchanged five-daemon family remain green.

## Historical public-open symptom

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

But alice never picks up bob's or charlie's replies. The dogfood harness now records this as a **blocking PASS/FAIL** check:
the owner must first observe committed roster convergence and then cache each
joiner's reply.

## Historical public-open root cause

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

## Historical public-open code-path inspection

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

## Implemented public-open mechanism

### 1. Publish a `MemberJoined` metadata event on join

Add to `join_group_via_invite` (right after the local `info.add_member`
call), a joiner-authored request on the metadata topic:

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

1. Verify the joiner's signature and derived AgentId.
2. Reject any requested role other than `Member` for invite-join v1.
3. Apply the request only on the original local inviter, where the structured
   one-time invite record can be checked for role cap, expiry, and prior
   consumption.
4. Publish an inviter/authority-signed `MemberAdded` event carrying a
   `GroupStateCommit`; third-party receivers ignore `MemberJoined` and apply
   only the signed commit.

This keeps durable roster and `state_hash` mutations inside the D.3 signed
state-commit chain.

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

## Public-open acceptance record

The bug is fixed when **all** of these hold on a fresh local 3-daemon
setup (no persisted state) and on the live VPS fleet:

1. New integration tests in `tests/named_group_join_metadata_event.rs`:
   - Daemon A creates a public_open group, generates an invite.
   - Daemon B joins via the invite.
   - Within the local mesh budget (15 s), A's `members_v2` contains B via an
     authority-signed `MemberAdded` commit.
   - B publishes a signed message.
   - A's `/groups/:id/messages` cache contains B's body within the same local
     mesh budget.
   - A forged `MemberJoined { role: admin }` does not admit or promote B.

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

## Public-open historical scope

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
(2026-05-01). The first harness revision treated cross-member convergence as
INFO-only so dogfood coverage could land while the daemon fix was pending.
With this ticket implemented, Phase B treats owner roster convergence and
owner-observed member replies as hard PASS/FAIL gates.
