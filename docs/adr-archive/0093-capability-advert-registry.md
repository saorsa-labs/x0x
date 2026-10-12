# ADR 0093: Capability Advertisement Registry

- **Status:** Accepted
- **Accepted:** 2026-09-29 by David Irvine (charter decision D08: the grant capability bit ships in v0.46.0; accepted on the text merged with #1064 at c44dd2b, which holds sends only for peers whose current verified advert lacks the bit, while unknown, expired or card-only capabilities send as before; OMP cross-model review r2 APPROVE; status change applied by Claude at his instruction)
- **Date:** 2026-09-29
- **Decision owners:** David Irvine (D08 ratification), Codex (author)
- **Reviewers:** OMP (cross-model review, 2 rounds); David Irvine (acceptance)
- **Supersedes:** none
- **Superseded by:** none
- **Vision requirement:** R5 (share a subset of my agents with other people),
  R6 (agents collaborate across machines), R11 (easy onboarding).
- **Related:** charter D08, I9 and §8.3 limitations 6 and 10;
  mixed-version matrix A5a, A5c, B1 and Structural gap; #924 #983 #903
  #913 #942 #988; ADR 0030, ADR 0077.

## Context

The 0.45 and pre-D08 candidate DM transport adverts are identical. A 0.45
host accepts an unknown ShareGrant as an ordinary DM without applying the
grant. Its false Accepted ACK cancels the owner's retries. A predecessor
or requester offer requiring a durable application ACK instead reaches a
non-durable route, is dropped, and retries indefinitely. Transport protocol
v2 alone says nothing about these application routes.

David ratified D08 as a v0.46.0 MUST-LAND on 2026-09-29. That instruction
supersedes older deferral recommendations in the planning documents; this
ADR remains Proposed pending its own review and acceptance.

## Decision Drivers

- R5: delivery must not claim that an unapplied grant succeeded.
- R6/R11: join offers must wait visibly for compatible receivers.
- I9: a wire change a previous release mishandles needs a signed capability.
- Preserve the legacy announcement decoder and signature byte layouts.
- Keep receiver authority checks and existing bounded retry policies.

## Considered Options

1. Upgrade instructions alone: leaves false delivery and silent loss.
2. Infer support from version strings or durable DM v2: neither identifies
   individual handlers and backports reliably.
3. Fall back to non-durable receipts: cannot certify application and allows
   false success to discard an obligation.
4. Insert fields inside the existing postcard capability struct: rejected;
   it is positional, precedes the signature, and breaks old decoders.
5. Extend the existing announcement with a signed trailing registry (chosen).
   A separate gossip topic would also work but adds subscriptions, ordering
   and independently expiring state unnecessarily.

## Decision

### Registry and allocation

Registry version 1 is a `u64` bitmap. Within a verified current advert,
absence, version 0, an unknown registry version, or an unset bit means
**not supported**. Unknown bits are ignored.
The version identifies the bitmap's interpretation, not the software release.

| Bit | Name | Meaning |
| --- | --- | --- |
| 0 | `share_grant_v1` | Understands and validates the ShareGrant v1 typed DM |
| 1 | `predecessor_offer_v1` | Understands the predecessor/requester offer route and its application handling |
| 2–63 | unallocated | Must not be advertised until allocated |

Allocate a bit by a reviewed ADR updating this table, the named code constant,
the sender gate and a compatibility regression test. Never reuse a bit or
change its meaning. Retire by stopping advertisement and retaining the reserved
number and historical definition. Incompatible semantics receive a new bit;
a new registry version is needed only for an incompatible registry encoding.

### Advertisement and compatibility

Reuse `DmCapabilities`, the existing `x0x/caps/v1` announcement service,
steady announcements and targeted refresh responses. Keep the frozen legacy
capability body and its original signature byte-for-byte in their old layout.
Append an optional `X0CR` trailer containing postcard `(version, bits,
signature)`. The second agent-key signature covers a distinct domain,
the original advert's canonical signed bytes (including agent, machine and
creation timestamp), and fixed-width registry version and bits.

The registry on the in-memory `DmCapabilities` is excluded from its legacy
serde shape; it travels only through this explicit trailer. The released
0.45 decoder uses `postcard::from_bytes`, which ignores the trailing field,
and reconstructs precisely the legacy signed bytes. New readers consume the
base and trailer separately and require exact trailer consumption. Missing
trailer decodes as no bits. Malformed or forged trailers are rejected.
AgentCard imports cannot authorize bits: card signatures cover only the
frozen base, so imported registry state is cleared.

A ready 0.46 DM receiver advertises both bits. A pending receiver advertises
none. The durable-ACK gate remains independent: a history-disabled peer may
understand a route but cannot satisfy a strict grant delivery's durable ACK.

### Freshness and sending

Use only the latest verified, machine-bound announcement in `CapabilityStore`.
Existing signed-timestamp ordering and the 900-second TTL apply to the whole
advert, including the trailer. A newer legacy announcement clears the bits;
an old replay cannot restore them or extend their lifetime. Unknown, stale,
and card-only capability state is not positive evidence of missing support.
A registry claim from a different machine cannot be combined with an older
machine's advert.

At the common direct-message egress, before product transport work
or ACK waiter creation, inspect the typed payload prefix. Check bit 0 for
ShareGrant, bit 1 for both authority predecessor relays and requester offers.
A bounded targeted announcement refresh is allowed before refusal, so
on-demand advertisement can converge. Local loopback is unchanged.
Only a verified, current advert lacking the required bit holds a send. Unknown,
expired and card-only state sends exactly as before, without waiting for an
advert; existing transport and durable-ACK requirements still apply.
Known missing support returns typed `DmError::RecipientUpgradeRequired`, rendered
as `recipient_upgrade_required` with the required named capability. It is
retryable after a fresh advert; do not send any payload or accept a receipt.

The owner's outbox queues a failed first grant send and retains failed retry
items. Offer workers retain obligations and use their existing backoff.
Their diagnostic logs surface the typed failure. A compatible fresh advert
allows the next scheduled attempt without reissuing. Existing grant expiry,
revocation, seven-day retry lifetime, offer resolution and resource limits
still apply: upgrade waiting does not extend an expired obligation.

### Security

Bits are advisory compatibility claims, never grants of authority. Both
signatures and the authenticated sender identity are checked before caching.
Spoofing support can at most cause a message to be sent; the receiver still
validates its signatures, grant scope, expiry, revocation, trust and group
rules as today. Stripping a trailer can suppress delivery but cannot grant
access. No fallback bypasses validation or treats a transport ACK as proof
that a newer application understood a message.

## Consequences

### Positive

- With a current verified advert, 0.46 sends neither payload to a 0.45
  recipient; a false Accepted ACK from that recipient cannot cancel a send
  that was never started.
- Pending grants and offers resume automatically when fresh support arrives.
- Future application changes have an explicit, reviewable allocation rule.

### Negative / Trade-offs

- Unknown or stale peers retain existing delivery behaviour, including the
  mixed-version risk until a current verified advert arrives.
- The trailer adds one ML-DSA signature per advert and verification on ingest.
- Pre-D08 development builds also lack the bits and must upgrade.
- Already lost mixed-era grants are not reconstructed; owners must reissue them.

### Neutral / Operational

- 0.45→0.46 messages keep existing receiver behaviour. Ordinary DMs retain
  existing semantics. 0.46→0.46 uses the existing payload and ACK formats.
- No outbox binary format changes. There is no new authority or permission.

## Validation

Inert exact-name tests cover signed advertisement round-trip, legacy base
read/verification, absence yielding no bits, forged/unverified/card claims,
stale state, per-bit gating, zero transport calls while blocked, grant queue
retention, unknown-capability delivery and delivery after an upgraded
announcement. Local tests do not claim to exercise live transport. Red/green
SHAs and gate results belong in the implementing PR body.

**Release gate row 4b (CI/sealed testnet only):** run a real 0.45.0 peer with
history enabled beside the candidate. Queue a ShareGrant and both an
authority relay and requester offer. Assert zero such DMs reach 0.45, typed
`recipient_upgrade_required`, and retained obligations across retries and
sender restart. Upgrade the recipient; receive a fresh signed advert; assert
all three deliver and leave their outboxes only after the required receipt.
Repeat with missing/stale adverts (existing send behaviour must continue)
and a history-disabled receiver; ordinary DMs must still work. Check that
a 0.45 reader verifies candidate adverts.
Row 4b is required release acceptance, not replaced by the inert unit tests.

## Notes for AI-assisted work

Do not mark this ADR Accepted without human review. Accepted ADRs are
immutable. Never append fields inside positional signed capability bodies,
trust card-only registry claims, or bypass receiver validation based on bits.
