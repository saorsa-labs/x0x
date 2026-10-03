# ADR 0080: Grant Revocation Is Also Pushed Directly to the Grantee; Gossip Remains the Backstop

- **Status:** Proposed
- **Date:** 2026-09-27
- **Decision owners:** David Irvine (decision, #994 Root ruling 2026-09-27)
- **Reviewers:** cross-model review required before acceptance
- **Supersedes:** none
- **Superseded by:** none
- **Extends:** ADR-0077 (revocation ordering and propagation; does not edit it). ADR-0070 §2 (ShareGrant), ADR-0018 (revocation subjects) unchanged.
- **Serves:** vision requirement **R5** (sharing a subset of an owner's agents with another human, safely)
- **Related:** #994 (Root decision), #1003 (this follow-up), #924 (typed-DM delivery + receiver verification), #910 (v3 revocation carrier), PR #983/#1010 (outbox)

## Context

`DELETE /grants/:id` today guarantees only OWNER-SIDE ordering (ADR-0077): when it returns, the owner install has durably recorded the revocation, made no new send and no new enqueue of the grant, and removed the outbox entry. But a grant DM already on the wire is revoked at a RECEIVER only when the `x0x.revocation.v3` gossip record reaches it. Until then, a receiver that stored the in-flight grant still honours it — an attacker who still holds the delivered grant bytes keeps access for the gossip propagation window (typically seconds on a connected mesh, but unbounded across partitions and offline receivers).

ADR-0077's validation section already names revocation-arrival latency as a live concern; issue #1003 (Root decision, 2026-09-27) directs the fix.

## Decision Drivers

- Revocation latency to the RECEIVERS that actually hold the grant is the gap; owner-side ordering is already sound and must stay exactly as ADR-0077 specified it.
- The wire freeze discipline (ADR-0072) still applies: any new carrier must be ignorable by old peers with no ACK dependency, exactly like the typed routes #924 introduced.
- Verification must not fork: a pushed revocation must verify through the SAME code as the gossip v3 carrier, and ingest through the SAME revocation barrier, or ordering against redelivery regresses.
- Best-effort is acceptable: gossip v3 already converges; the push only shortens the window.

## Considered Options

1. **Direct revocation push on DELETE** (chosen): after the revoke is durably recorded, the owner sends the signed v3 revocation record as a typed DM to the grantee's known agents and every `deliver_to` daemon. Best-effort; gossip stays the backstop.
2. **Amend ADR-0077.** Rejected: Accepted ADRs are immutable; the wire-change class is the one 0077 deferred to its own ADR; propagation and delivery are separate lifecycles (see the decision note above).
3. **Status quo (gossip only).** Rejected by the #994 Root decision: the window is attacker-relevant.
4. **Grantee-side poll for revocations.** Rejected: more wire surface (a new request type), a new authority surface (the reply must verify like a carrier), and it cannot reach the `deliver_to` daemons that hold grants but never poll the owner.

## Decision

We will push the signed revocation record directly on revoke, as a typed DM, best-effort, with gossip v3 unchanged as the backstop.

- **Trigger:** `DELETE /grants/:id`, AFTER the ADR-0077 durable ordering completes (revocation recorded, outbox entry removed, send gate released). The push is a propagation accelerator, never an ordering participant — the recorded revocation is the authority whether or not any push succeeds.
- **Recipients:** every daemon the owner install knows holds or may hold the grant — the grantee's cached agents at revoke time, the shared agents, and every `deliver_to` daemon. Bounded by the same recipient set the delivery path uses; no discovery fan-out beyond it.
- **Wire format:** a new typed-DM prefix, `x0x-revocation-push-v1\0`, whose payload is EXACTLY the v3 carrier payload (the serialized `Vec<RevocationRecord>` the gossip carrier publishes). Sharing the payload bytes is what keeps verification from forking.
- **Registration:** plain typed route (NOT durable-registered). Old receivers have no route for the prefix: the payload falls through to the generic-DM path and is ignored safely — no ACK is expected, so the sender never blocks on an old peer. New receivers register the prefix and handle it as below.
- **Verification:** byte-for-byte the v3 carrier's verify — owner ML-DSA over each record's canonical bytes, subject `ShareGrant`, owner key derivation, and the v3 payload cap. A forged or foreign push is dropped with the same counters as a forged gossip record.
- **Ingest:** through the SAME `ingest_share_grant_revocations` path and the SAME owner-trust revocation barrier the gossip carrier uses — so ordering against in-flight redelivery and the barrier's accounting hold identically whichever carrier arrives first. Idempotent: the gossip record and the pushed record are the same bytes; whichever arrives second is a duplicate.
- **Sender behaviour:** 3 idempotent attempts (the #924 delivery pattern), no outbox persistence, no ACK dependency. Failure to push is logged and reported in the DELETE response as `push_attempted` / `push_failures` — informational, never a failure of the DELETE itself (its success contract is ADR-0077's and unchanged).
- **Bounds:** one push per revoke per recipient; the payload is the already-bounded v3 payload; no new durable state on either side.

## Consequences

### Positive

- The revocation window at grant-holding receivers shrinks from "gossip propagation" to "one DM round trip" for every reachable recipient.
- Old fleets are unaffected (safe ignore, no ACK dependency); the mechanism deploys entirely on the sender's side.
- No verification or ingest fork; no new durable state.

### Negative / Trade-offs

- A receiver behind a partition that misses both the push and the gossip still honours the grant until one arrives — unchanged from today, now with two carriers chasing it.
- The owner learns nothing from a successful push (no ACK by design); observability is sender-side counters only.
- One more typed-DM prefix to carry in the compat table.

### Neutral / Operational

- `DELETE /grants/:id` response gains informational push fields; `/diagnostics` gains push counters (attempted/failed per recipient class).
- ADR-0077's revocation-ordering text remains authoritative for ordering; this ADR adds only propagation.

## Validation

- A receiver that stored an in-flight grant STOPS honouring it after the direct push alone (gossip disabled in the test).
- An old receiver (no route registered) ignores the push safely and the grant is still revoked when the gossip record arrives.
- A forged push (wrong key, foreign owner, tampered bytes) is refused with the forged-carrier counters.
- Ordering: a pushed revocation and a concurrent outbox redelivery pass through the same barrier — no redelivery of the revoked grant after either carrier ingests.
- Rule 9: each test's red run (push disabled → window test fails; verify disabled → forged test fails) recorded in the PR body.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human review**. Accepted ADRs are immutable: create a new superseding ADR rather than editing an Accepted ADR.
