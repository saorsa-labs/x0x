# T-join-loss-pacing: a JOIN seed that answers and then closes waits a loss cooldown

- **Status:** Accepted (David, D256, 2026-10-12)
- **Target slot:** A05
- **Date:** 2026-10-12
- **Decision owners:** David Irvine
- **Reviewers:** <pending>
- **Ruling:** D252 (David, in chat, 12 Oct 2026). D248 keeps the JOIN driver in saorsa-gossip.
- **Related:** x0x #1321, C-1321-2, E-D15 rule 22, saorsa-gossip ADR-015 (Proposed), D253

## Context

`join_network` joins the HyParView overlay through its dialled peers. For #1321, the JOIN frame goes only to a peer that the plane gate admits (#292 invariant A). saorsa-gossip drives each attempt through its step API (D248): `join_dial`, then x0x checks admission, then `join_send`. One `JoinLedger` per join keeps ten attempts per seed address (C-1321-2).

Sometimes a peer answers the dial and then closes the connection before its plane hello reaches us. For example, the remote has already refused us. We then have no tombstone for it, and it reads as not connected. The old JOIN treated this case like a failed send and retried at once. So a peer that answers and closes got up to ten handshakes in a burst, with no wait.

E-D15 rule 22 requires backoff when a peer is known to be gone. A burst of handshakes to such a peer breaks that rule.

## Decision

When the peer that answered a JOIN dial is not connected at the admission check, x0x reports a loss to saorsa-gossip (`JoinLedger::record_loss`). saorsa-gossip then starts a loss cooldown for that seed address:

1. The cooldown is 100 ms, doubled after each loss, at most 30 s, plus the JOIN jitter.
2. The cooldown belongs to the address for the whole join. It does not reset when the peer answers and closes again.
3. The next attempt starts at the later of the dial backoff and the loss cooldown. The delays are not added.
4. `join_dial` makes no dial before that time, and uses no attempt.
5. While a lost address waits, a ready admitted address goes first.

These rules do not change:

- The dial backoff after a failed dial is the same as in saorsa-gossip 0.5.87.
- A plain send failure to an admitted peer still retries at once.
- A suppressed peer gets no further attempt.
- The budget stays at ten attempts per address.

## Attempt limit and timing

- **Attempt limit:** at most ten dials per seed address per join, as before. With C distinct candidate addresses, the JOIN makes at most 10C dial calls.
- **Timing change:** this applies only to a peer that answers and then loses its connection before admission. Before, its ten attempts came in a burst. Now nine cooldowns separate them (100 ms to 25.6 s): 51.1 s, plus up to 6.379 s of jitter in total. No cooldown follows the tenth attempt. Such a peer gets no JOIN frame. The join can take longer only when no other admitted address is ready.

## Rejected options

- **Keep the burst.** It matches the old failed-send path, but it breaks rule 22 for a peer that we know is gone.
- **A small fixed cooldown.** It meets the words of rule 22, but each answered-and-closed handshake would cost the same, with no growth.
- **Grow the dial backoff instead.** This is the round-4 defect. A failed send would then delay a later failed dial.

## Consequences

- The known-loss path follows rule 22, with exponential pacing that does not reset.
- The attempt budget and the failed-dial schedule stay the same as before.
- The loss timing is a deliberate change from the old timing.
