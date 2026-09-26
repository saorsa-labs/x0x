# ADR 0077: Share-Grant Redelivery Is an Owner-Side Durable Outbox; Grantee Fetch Deferred

<!-- File name: docs/adr/0077-share-grant-owner-side-redelivery-outbox.md -->

- **Status:** Proposed
- **Date:** 2026-09-26
- **Decision owners:** David Irvine (direction), Claude (drafting)
- **Reviewers:** pending (cross-model review required before acceptance)
- **Supersedes:** none. It amends one sentence of Accepted ADR-0070 §2 by
  supersession *if accepted*; ADR-0070 itself is not edited.
- **Superseded by:** none
- **Serves:** vision requirement **R5** (sharing a subset of an owner's agents
  with another human, reliably)
- **Related:** ADR-0070 §2 (ShareGrant), ADR-0030 §5 (public-group bootstrap
  outbox, the pattern reused), ADR-0018 (revocation subjects); issue #926;
  PR #983 (implementation); PR #967 (parked grantee-fetch alternative)

## Context

ADR-0070 §2 delivers a `ShareGrant` by durable typed DM to the grantee's
agents and to each shared agent's daemon. #924 (slice 3) implemented it: the
receiver withholds the v2 ACK until the grant is verified and stored, and the
sender makes 3 idempotent retries and then reports failure. A shared agent's
daemon that is offline through all three attempts holds no grant. It denies
the grantee (fail closed) until the owner re-issues.

§2 also says: *"The grantee also attaches the grant `grant_id` when opening a
DM/stream so a daemon that missed delivery can request it."* That describes a
grantee-driven fetch. Implementing it needs:

- a new wire carrier on DM/stream opens, which old peers must ignore;
- a new durable typed request/response to fetch the grant;
- per-peer rate limits and bounds on that fetch.

Issue #926 listed that fetch (options 1–3) or, "alternatively or as well", a
durable owner-side redelivery outbox like the public-group bootstrap outbox
(option 4).

## Decision Drivers

- **R5 reliability:** a daemon that was offline at issue time must gain the
  grant later without a re-issue.
- **No protocol change:** avoid a new wire carrier and a new request type
  while the vision scope freeze (ADR-0072) is in force.
- **Receiver verification unchanged:** the receiving path reviewed in #924
  must stay exactly as it is.
- **Revocation must win:** a revoked grant must never be delivered after the
  revoke is acknowledged, including across restarts.
- **Bounded resources:** the owner install must not grow without limit.

## Considered Options

1. **Grantee-attached fetch (ADR-0070 §2 as written).** It repairs delivery
   even when the owner install is offline, and it covers grantee agents the
   owner never knew of. It costs a wire carrier, a request type, and
   rate-limit machinery, and it adds a new authority surface: the fetch reply
   must be verified exactly like a delivery.
2. **Owner-side durable redelivery outbox.** Failed deliveries are persisted
   on the owner install and retried with the same typed DM and logical
   request id until ACK, revocation or deadline. There is no wire change.
3. **Both.** The outbox now, the fetch later if coverage gaps matter.

## Decision

We will make the **owner-side durable redelivery outbox** (option 2) the
ADR-0070 §2 mechanism for missed deliveries. The **grantee-attached fetch is
deferred**. It may be added later under its own ADR (option 3) if the coverage
gaps below prove material.

The outbox, as implemented in PR #983:

- **Enqueue:** a recipient that has not ACKed after the #924 retries is
  written to `<data_dir>/share-grant-outbox.bin` before `POST /grants`
  returns. The write is durable (temp, fsync, rename, dir fsync), mode 0600,
  `X0GO` magic plus strict bincode.
- **Retry:** backoff starts at 5 s and doubles up to a 5 min cap. It caps the
  interval, not the number of attempts. At most 8 sends go out per pass. When
  the recipient's machine connects (`PeerConnected`), its entries become due
  immediately.
- **Same wire bytes:** a retry sends the exact `x0x-sharegrant-v1\0` typed DM
  with the same logical request id as the original. The receiver verifies
  and stores it through the #924 handler and answers a replay as
  `Duplicate`.
- **Drop:** an entry is removed on the recipient's durable ACK, on
  revocation, or at `min(grant.expiry, queued_at + 7 days)`.
- **Revocation ordering:** a worker pass holds a send gate (shared) from its
  revocation check until its sends complete. A local revoke takes the gate
  exclusively before it records the revocation. As a result, no send of a
  revoked grant can start after the revoke returns, and every pass
  re-checks the revocation set before sending. That second check covers
  revocations gossiped from another owner install and a crash between the
  revoke and the outbox rewrite.
- **Fail loud:** `DELETE /grants/:id` answers success only when both
  `revocations-v3.bin` and the outbox removal are durable. Otherwise it
  answers 503, and a retry is idempotent.
- **Bounds:** 128 entries per grantee (the grant's `Grantee`) and 1024 in
  total. A new entry past a bound is refused and reported. A file that is
  over-bound, malformed, or holds a foreign or non-verifying entry loads as
  empty with `load_error` and refuses writes. It is never silently truncated.

The sentence in ADR-0070 §2 about the grantee attaching `grant_id` is
**superseded by this ADR if it is accepted**. Until then it stays an
unimplemented part of ADR-0070.

## Consequences

### Positive

- A daemon that was offline at issue time gains the grant later with no
  re-issue.
- No wire change, no new request type, no new receiver code: the attack
  surface is the one already reviewed in #924.
- Revocation is ordered strictly against redelivery and is durable before it
  is acknowledged.

### Negative / Trade-offs

- **The owner install must come back online to retry.** The fetch would let
  the grantee repair delivery while the owner is offline.
- **Coverage is limited to recipients the owner install knew at issue time:**
  the grantee's cached agents, the shared agents, and `deliver_to`. A grantee
  agent the owner install never saw is not covered.
- Obligations older than 7 days lapse, and the owner must re-issue.
- A revoke can wait for an in-flight redelivery pass, which is bounded by one
  send attempt and its retry.

### Neutral / Operational

- New data file `share-grant-outbox.bin`. `GET /grants` reports
  `outbox_error`, and `POST /grants` delivery rows gain `queued`.
- `revocations-v3.bin` is now written durably on local revocation.

## Validation

- Unit tests in `src/share_grant/tests/redelivery.rs` cover:
  - an offline-then-online daemon gains access without a re-issue;
  - persistence across restart;
  - a revocation removes the entry and nothing is delivered;
  - a grant revoked while queued is not redelivered after a restart;
  - a revoke cannot return while a send of the grant is in flight;
  - both write-failure paths return an error, and a retry is durable;
  - per-grantee and total bounds, the TTL, and fail-closed over-bound load.
- A CI red/green proof disables the enqueue and shows the offline-daemon test
  failing.
- **Review triggers:** revisit option 3 (add the fetch) if field reports show
  grants missed by agents the owner never knew of, or owners offline for
  longer than the 7-day TTL.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human review**. Accepted ADRs are immutable: create a new superseding ADR rather than editing an Accepted ADR.
