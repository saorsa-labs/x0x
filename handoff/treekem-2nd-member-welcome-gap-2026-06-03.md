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

## Refined root cause (investigation 2026-06-03, evidence-backed)

Narrowed from "TreeKEM logic" to **the anchor's join-result *reply send* to the
2nd member timing out during the join flow**. Evidence chain:

1. The 2nd member reaches the owner's roster (owner-side `group_membership_lock`
   fix works) and falls back to polling the anchor (`poll_join_result_until_treekem_ready`
   → `JoinResultMessage::FetchRequest`).
2. The anchor **receives** the FetchRequest, finds the staged result, and calls
   `send_direct_with_config(m2, Result, direct_message_send_config())` — which
   **times out**: `WARN failed to send join-result response: timed out after 1
   retries over 12.003s member=<m2>`. The 2nd member's journal shows nothing
   (it never receives the Result).
3. It is **NOT** any of: gap-check (`is_local_welcome` correctly bypasses gaps
   for a member's own `MemberAdded`), config (`direct_message_send_config()` ==
   `DmSendConfig::default()`, same as plain `/direct/send`), payload size
   (isolated DMs anchor→m2 up to 48 KB succeed via `gossip_inbox` in ~1 s; 64 KB
   is a clean 400 over `MAX_PAYLOAD_BYTES`), or raw node connectivity (isolated
   plain DM anchor→nuremberg AND anchor→singapore succeed in <1 s via
   `gossip_inbox`).
4. So the **same** anchor→m2 DM that works in ~1 s in isolation times out at 12 s
   **only inside the concurrent multi-member join flow** (m2 polling + applying +
   fetching its Welcome, anchor adding + serving). 1st member never fails because
   the anchor's reply to it lands before that contention builds.

### Leading hypotheses for the team
- **App-level gossip-inbox ACK stall**: the gossip-inbox path waits for m2's
  authenticated *application* ACK. During the join flow m2 is busy (repeated
  poll-Result applies + `fetch_treekem_welcome` round-trip), so the ACK is
  delayed past the 12 s send timeout. Plain DM in isolation ACKs in ~1 s.
- **Lock-across-network-fetch (introduced by the 0.21.0 fix — check this first)**:
  `apply_named_group_metadata_event_inner` holds the per-group
  `group_membership_lock` for the WHOLE apply, and the `MemberAdded` arm calls
  `fetch_treekem_welcome` (a network round-trip to the anchor) *while holding the
  lock* (src/bin/x0xd.rs ~7807). On m2, repeated poll-Result applies then
  serialize behind a lock held across a network call → m2's processing/ACK
  stalls. **Candidate fix:** do not hold `group_membership_lock` across the
  Welcome-blob fetch — fetch first (no lock), then take the lock only for the
  state mutation; or make the join-result delivery non-blocking + idempotent so a
  slow ACK doesn't wedge the anchor's join-result listener task.
- **Anchor listener head-of-line blocking**: the join-result listener `.await`s
  the 12 s send inline, so it can't service m2's rapid re-polls (every ~2 s)
  during the timeout — spawning the send would decouple it.

### UPDATE: lead #2 (lock-across-fetch) ruled OUT as the primary lever

Read of `src/dm_inbox.rs:322-355`: the gossip-inbox ACK is `publish_ack(Accepted)`
sent **immediately after enqueuing** the message into the typed-payload route
channel (`route.sender.send(typed).await`), **not** after the application apply.
So m2 holding `group_membership_lock` during its apply does **not** directly delay
the ACK the anchor is waiting on → the lock-scope change will **not** fix the
anchor→m2 send timeout. (The lock is still worth not holding across a network
call on principle, but it is not the root cause.)

The ACK *can* be delayed only via **route-channel backpressure**: m2's membership
consumer is single-threaded and **blocks on the network Welcome-blob fetch**
(`fetch_treekem_welcome`, itself an anchor→m2 round-trip on the same flaky path).
If that fetch hangs, the consumer stalls, the route channel fills,
`route.sender.send().await` blocks, and the ACK is delayed → the anchor's send
times out. Self-reinforcing with the anchor's own welcome-blob serve timing out.

### Real fix directions (transport / flow — team domain)

1. **Reliable anchor→member membership delivery under load.** The anchor→m2
   `send_direct` (join-result Result AND Welcome blob) times out (12s) under the
   concurrent join flow though it succeeds in ~1s in isolation. Make these
   critical membership sends robust: warm/raw-QUIC-first to a just-active member,
   a longer/adaptive ACK window, or idempotent retry that doesn't wedge the
   listener.
2. **Don't block the membership-event consumer on a network Welcome fetch.** The
   single consumer awaiting `fetch_treekem_welcome` causes route-channel
   backpressure that delays ACKs. Fetch the Welcome without blocking the consumer
   (e.g. inline the Welcome bytes in the `MemberAdded` for the 2nd+ member when it
   fits under `MAX_PAYLOAD_BYTES`, or fetch+apply on a per-member task).

### Suggested next steps
1. Add temporary instrumentation to confirm whether m2's `fetch_treekem_welcome`
   completes (and whether m2 holds the membership lock across it) during a
   failing run.
2. Try the lock-scope fix (release before the Welcome fetch) and re-run
   `tests/e2e_treekem_membership.py --member2` on testnet.
3. Consider a longer / fallback-friendly send for join-result delivery.

## Recommendation

- Treat multi-member secure participation as **not shipped** until the 2nd-member
  join-result/Welcome delivery is fixed and `e2e_treekem_membership.py --member2`
  passes on testnet (ideally a short soak).
- 0.21.0 docs/CHANGELOG corrected this session to scope the claim to owner-side roster
  convergence + single-member.
