# TreeKEM Pending Replay + Catch-up Result

**Date:** 2026-06-02

## Summary

Implemented a bounded in-memory anti-entropy layer for order-sensitive TreeKEM membership metadata events. Events that arrive before local TreeKEM readiness or ahead of the local scalar frontier are now queued and trigger explicit direct-message catch-up requests.

## Code changed

Primary file:

- `src/bin/x0xd.rs`

## What was added

### Bounded queues/logs

Added per-daemon state:

- `treekem_pending_events`: bounded per-group pending queue for verified TreeKEM membership events.
- `treekem_event_log`: bounded per-group log of locally authored/applied TreeKEM membership events for catch-up responses.
- `treekem_catchup_throttle`: bounded request-throttle map keyed by group/peer/frontier.

Caps:

- pending events per group: 64
- event-log events per group: 128
- catch-up response events: 32
- catch-up request throttle: 5 seconds

### Explicit catch-up messages

Added direct-message payloads with explicit `message_type` tags:

- `TreeKemCatchupRequest`
- `TreeKemCatchupResponse`

Requests include:

- `group_id`
- requester agent id
- local `from_revision`
- local `from_treekem_epoch`
- local `current_state_hash`
- missing `prev_state_hash`
- response limit

Responses contain sorted cached membership events and a `truncated` flag.

### Gap/readiness detection

TreeKEM membership events are queued only after the existing direct/gossip verification gate and authorization checks. Queue-worthy cases include:

- state revision gap
- roster revision gap
- signed `prev_state_hash` not matching local `state_hash`
- TreeKEM epoch gap
- local TreeKEM group missing for an existing member event

Stale/duplicate events are not queued.

### Replay behavior

- Catch-up responses feed events back through the normal `apply_named_group_metadata_event` path.
- Replay sorts pending events by `(revision, treekem_epoch)`.
- Pending entries are deduped by event kind, group, revision, epoch, actor, and target.
- Pending entries are bounded and old entries are dropped when over cap.

### Catch-up authorization

Catch-up requests are answered only when the direct message is verified and the requester is either:

- currently active in the local group, or
- the target of a cached `MemberAdded` / `JoinRequestApproved` event.

Responses never bypass validation; every returned event is processed through the regular signed metadata apply path.

### Event log population

The catch-up log records locally authored/applied TreeKEM membership events including:

- invite-based authoritative `MemberAdded`
- direct TreeKEM add
- TreeKEM self-remove and owner-remove
- TreeKEM ban
- TreeKEM join-request approval
- successfully applied remote TreeKEM membership commits

## Advisor follow-up fixes

After review, patched additional edge cases:

- Local Welcome events now bypass authority state-chain gap checks. This prevents a joiner stub/base hash from incorrectly queueing its own `MemberAdded`/`JoinRequestApproved` Welcome instead of bootstrapping from it.
- Replay now uses an inner apply mode with `allow_queue = false`, avoiding self-requeue / repeated catch-up request loops while draining pending events.
- Catch-up request handling resolves both local and stable group keys when reading event logs, so stable-id requests do not miss locally keyed cache entries.
- Truncated catch-up responses now log and request a follow-up page after applying the received page.
- Added unit coverage for the local-Welcome gap-bypass predicate.

## Tests / validation

Passed:

```bash
cargo test --bin x0xd treekem_ -- --nocapture
# 12 passed

cargo test --test named_group_d4_apply d4_mls_ban_commit_advances_binding_and_converges -- --ignored --nocapture
# 1 passed

cargo fmt --all -- --check
# PASS

cargo clippy --all-features --lib --bins -- -D warnings -D clippy::panic -D clippy::unwrap_used -D clippy::expect_used
# PASS

cargo check --workspace --all-targets
# PASS
```

Attempted but blocked by pre-existing test-suite lint debt unrelated to this patch:

```bash
cargo clippy --all-features --all-targets -- -D warnings -D clippy::panic -D clippy::unwrap_used -D clippy::expect_used
```

This fails in `tests/daemon_api_integration.rs` due many existing `unwrap`/`expect`/`panic` uses.

## Remaining limitation

This intentionally uses the existing scalar causal frontier:

- `GroupStateCommit.prev_state_hash`
- `state_revision`
- `roster_revision`
- `treekem_epoch`

That is appropriate for the current authority-authored TreeKEM membership chain. If concurrent multi-admin TreeKEM membership authorship is added later, this should be upgraded to a dotted/vector-clock-style frontier.
