# TreeKEM Multi-Member Convergence Investigation

**Date:** 2026-06-02  
**Scope:** `private_secure` / TreeKEM named-group membership with 2+ non-owner members.

## Executive Summary

The concern is valid: current `main` only proves TreeKEM groups with owner + one member. The strengthened 3-daemon `d4_mls_ban` test is not present on `main`/`origin/main`, and the current test still bans the only non-owner member while checking only the owner's roster/binding.

The codebase contains two credible failure stages for flaky 2nd+ member convergence. The report that Charlie never reaches Alice's roster (`owner+bob` only) points first to an **owner-side ingestion problem**: Alice either does not reliably receive Charlie's joiner-authored `MemberJoined`, rejects it, or fails `TreeKEM add_member` / persistence before publishing Charlie's authoritative `MemberAdded`. A second-stage gap also exists: TreeKEM `MemberAdded` commits are order-sensitive but are delivered/applied through best-effort gossip plus a direct path only to the joiner, so existing members can miss/drop later commits with no queue or replay.

This is the same class of gap ADR-0012 warned about in **Phase 3.5 — Commit/Welcome transport**: TreeKEM join triggers and commits must be reliably delivered, ordered, and recoverable. Current evidence proves a multi-member reliability gap; the exact failing stage needs targeted diagnostics/logs.

## Repository Evidence

### Current main still has weak 2-daemon coverage

- Current `main` / `origin/main`: `tests/named_group_d4_apply.rs::d4_mls_ban_commit_advances_binding_and_converges` uses `pair()`.
- It bans Bob directly and checks Alice's `security_binding` and Alice's roster state only.
- No `cluster::cluster`, `charlie-ban-target`, `bob-ban-observer`, or TreeKEM 3-daemon ban test is present on `main`, `origin/main`, `89cecce`, or `0bdc089`.

### Existing tests do not prove multi-member TreeKEM

- `tests/e2e_treekem_membership.py` is a solid owner+one-member churn harness: create, invite, one member joins, encrypt/decrypt, ban, forward-secrecy check.
- It does not add a second non-owner member to the same TreeKEM group.
- Older `charlie` tests found on other refs are GSS-era or non-main; they do not prove current `private_secure` TreeKEM multi-member convergence.

### ADR-0012 explicitly identifies the transport gap

`docs/adr/0012-treekem-default-secure-groups.md` says Phase 3.5 must define:

- how TreeKEM `Commit`s reach **all** members,
- how `Welcome`s reach joiners,
- how a member that misses a commit recovers,
- ordered delivery / gap detection because TreeKEM epoch N must be applied before N+1.

Current code has partial Commit/Welcome transport, but not ordered all-member delivery with gap recovery.

## Code Path Findings

### Joiner flow

`join_group_via_invite`:

1. Joiner creates local TreeKEM KeyPackage.
2. Joiner stores a local TreeKEM stub (without a live TreeKEM group until Welcome is processed).
3. Joiner publishes `MemberJoined` on the metadata topic.
4. Joiner starts `poll_join_result_until_treekem_ready`, fetching its own authoritative `MemberAdded` result from the creator until its live TreeKEM group exists.

`MemberJoined` handling on creator:

1. Only the inviter/creator applies `MemberJoined`.
2. Creator consumes invite, mutates roster, calls `guard.add_member`, stages Welcome, publishes authoritative `MemberAdded` with `treekem_commit_b64`, `welcome_ref`, and `treekem_epoch`.
3. Creator direct-delivers that event only to the new member (`spawn_named_group_event_delivery(state, &member_agent_id, &event)`).

### Existing-member flow for someone else's add

`apply_named_group_metadata_event::MemberAdded` on non-joiner members:

- Requires the local live TreeKEM group to already be loaded:
  ```rust
  let Some(group) = group else { return false; };
  ```
- Processes the commit once:
  ```rust
  guard.process_commit(&commit_bytes)
  ```
- If the group is not loaded, commit fails, epoch mismatches, or state-commit predecessor is not current, the event returns `false` and is dropped.

There is no pending queue and no retry/replay after the member later becomes ready.

### Owner-side join-trigger gap

For Charlie to appear in Alice's roster, Alice must receive and accept Charlie's joiner-authored `MemberJoined`:

- Charlie publishes `MemberJoined` via metadata-topic gossip in `join_group_via_invite`.
- Alice handles `MemberJoined` only if she is the original inviter, then consumes the invite, runs `guard.add_member`, persists the TreeKEM snapshot/named-group state, and publishes authoritative `MemberAdded`.
- Any failure in delivery, invite validation, `TreeKEM add_member`, or persistence returns `false` from the applier. Without diagnostics, this can look like Charlie simply never arrived.

The reported `member_count` stuck at owner+bob means this owner-side stage is the primary suspect for that specific failure.

### Existing-member commit delivery gap

For a new `MemberAdded` that Alice does publish:

- Direct delivery goes only to the joiner.
- Existing active members rely on metadata-topic gossip.
- If an existing member misses the gossip event, gets it before its own Welcome is processed, or sees commits out of order, it drops the event permanently.

This explains a second failure mode: Bob can drop Charlie's `MemberAdded`, so Charlie may appear in Alice's roster but not Bob's, or Bob may never advance to the epoch containing Charlie. Under load/full-suite timing this also becomes flaky.

## Focused Reproducer Design

A minimal diagnostic should be ignored/non-CI until fixed:

1. Start a 3-daemon cluster: Alice, Bob, Charlie.
2. Alice creates `private_secure` group.
3. Bob joins via invite.
4. Wait for Bob to be **TreeKEM-ready**, not just local state available:
   - Bob can `/groups/:id/secure/encrypt` on `secure_plane == "treekem"`, or
   - Bob's `security_binding` reaches the owner's post-Bob-add epoch.
5. Charlie joins via invite.
6. Assert all of the following converge:
   - Alice roster: Bob active, Charlie active.
   - Bob roster: Charlie active.
   - Charlie can encrypt/decrypt on TreeKEM plane.
   - Alice and Bob can decrypt each other's post-Charlie-add TreeKEM messages.
7. Then Alice bans Charlie.
8. Assert Bob observes Charlie -> banned and can continue TreeKEM secure traffic with Alice.

A second negative/bug-reproducer variant should intentionally join Bob and Charlie back-to-back without waiting for Bob TreeKEM readiness. Today this is expected to reproduce the race/drop.

## Root-Cause Hypotheses

### H1 — Highest confidence for reported owner+bob-only roster: Charlie's `MemberJoined` is not reliably ingested by Alice

Charlie is absent from Alice's roster, so Alice likely never completed the authoritative add. Candidate causes:

- Charlie's joiner-authored `MemberJoined` is gossip-only and may not reach the inviter promptly/reliably under full-suite load.
- Alice rejects it during invite validation (`invite_secret_unknown`, expired/consumed secret, wrong stable group id).
- Alice's `TreeKEM add_member` or atomic persistence fails and returns `false` before publishing `MemberAdded`.

### H2 — High confidence secondary issue: dropped out-of-order TreeKEM commits

Existing members can receive `MemberAdded(epoch=N+1)` before they have processed their own `MemberAdded(epoch=N)` / Welcome. Because `treekem_groups` is absent or epoch is behind, the event returns `false` and is not retried.

### H3 — High confidence secondary issue: direct delivery only targets the joiner

The creator stages and direct-delivers `MemberAdded` only to the new member. Existing members depend entirely on gossip for order-sensitive TreeKEM commits, even though the code comments already acknowledge gossip cannot backfill events published before a peer is in the eager set.

### H4 — Medium confidence: no per-group membership operation serialization/readiness gate

The owner can issue/consume multiple invites and process multiple `MemberJoined` events without ensuring the previous add commit has reached all current members. TreeKEM permits sequential adds locally, but distributed members need commit order and gap recovery.

## Diagnostic Plan

Run two ignored/non-CI reproducers with structured logs:

1. **Sequenced join:** Bob joins; wait for Alice roster active **and** Bob TreeKEM encrypt works; only then create Charlie invite/join.
2. **Back-to-back join:** Bob and Charlie join without waiting for Bob TreeKEM readiness.

For each poll and capture:

- Alice/Bob/Charlie `/groups/{id}/members`.
- Alice/Bob/Charlie `/groups/{id}/state` including `security_binding`.
- `/diagnostics/groups` for listener/roster diagnostics.
- x0xd stderr logs from each harness data dir.

Log signatures to search for:

- `MemberJoined: invite validation failed`.
- `invite_secret_unknown`.
- `MemberJoined: TreeKEM add_member failed`.
- `failed to persist TreeKEM snapshot after invite add`.
- `failed to process TreeKEM MemberAdded commit`.
- `join-result fetch before result was staged`.
- `failed to join TreeKEM group from Welcome`.

## Concrete Fix Plan

### P0/P1 product fixes

1. **Reliable join-trigger delivery to inviter**
   - Direct-DM the joiner-authored `MemberJoined` to the inviter in addition to metadata-topic gossip.
   - Keep gossip as broadcast/backup, but do not rely on it to trigger the authoritative add.
   - Make owner-side failure reasons visible in diagnostics.

2. **Introduce per-group pending TreeKEM metadata queue**
   - Store events that fail only because of:
     - live TreeKEM group not loaded yet,
     - expected predecessor state hash/epoch missing,
     - commit epoch gap.
   - Replay queue when:
     - joiner processes its Welcome,
     - a TreeKEM commit advances successfully,
     - metadata listener receives a newer event.

3. **Direct-deliver membership commits to all active members**
   - For `MemberAdded`, direct-deliver the event to:
     - the new joiner (needs Welcome), and
     - every active existing member except the creator.
   - For remove/ban, direct-deliver to all remaining active members and possibly the removed member for self-removal cleanup.
   - Existing members ignore `welcome_ref`; only the target joiner fetches it.

4. **Add per-group membership mutation serialization on the owner**
   - Ensure multiple invite joins/adds are committed in a single owner-side order.
   - Optionally delay issuing/processing the next add until the previous commit has been published/staged and durable.
   - Do not require global consensus, but do require local deterministic epoch sequencing.

5. **Add commit gap detection**
   - If event epoch is not exactly local epoch + 1, queue and request missing commit(s) rather than dropping.
   - Use ADR-0012 Phase 3.5 design: per-group ordered Commit log or recovery via snapshot/resync.

6. **Add tests**
   - Unit-level: event apply returns a queueable reason for missing TreeKEM group / epoch gap instead of silent false.
   - Integration ignored diagnostic: 3-daemon Bob+Charlie join, Bob observes Charlie, ban Charlie, Bob observes banned.
   - Soak: repeated 2-member join churn in one TreeKEM group, not just owner+one-member churn.

## Recommendation

Do not claim `private_secure` TreeKEM groups are production-ready for arbitrary group sizes until Phase 3.5-style ordered commit delivery/recovery lands.

Short-term public limitation: TreeKEM secure groups are validated for owner + one member; 2nd+ concurrent/sequential member convergence is a known reliability gap.

Next engineering step: first implement reliable direct `MemberJoined` delivery to the inviter with diagnostics, then implement pending/replay + all-active-member direct delivery for TreeKEM membership commits. After that, land the 3-daemon ban/convergence regression test.
