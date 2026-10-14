# T-self-leave-catchup-before-seal: finish catch-up before a self-leave rekey

- **Status:** Proposed
- **Date:** 2026-10-14
- **Target slot:** A09
- **Decision owners:** David Irvine
- **Reviewers:** pending
- **Supersedes:** none
- **Superseded by:** none
- **Related:** T-self-leave-rekey-committer (Accepted, D274, slot A09, PR #1337); issue #1113; ADR 0016 decision 6

## Context

David accepted `T-self-leave-rekey-committer` (D274, 14 Oct 2026, slot A09). Its single committer is the lowest active admin. A 250 ms startup wait proves nothing. That record adds no timeout and no second committer.

A09 says group encryption must follow committed membership. The responder sets `truncated` from an in-memory event log that is empty after restart, so an empty page can come from a peer whose saved head is newer. A KeyPackage reply carries no head.

## Decision Drivers

A timed wait cannot prove that catch-up finished. `truncated: false` cannot prove that the saved heads match. The designated committer stays the lowest active admin. A failed send must not leave the leaver able to read new ciphertext.

## Considered Options

1. Keep the 250 ms startup wait, or make it longer.
2. Seal after any non-truncated catch-up page.
3. Require a saved-head match, retry within a bound, and withhold new ciphertext while the live leaf remains.
4. Add a second committer that seals if the first does not answer.

## Decision

We will require verified head evidence before the designated committer seals a startup self-leave rekey, when a removed member still has a live ratchet leaf and another active member remains.

On startup, the daemon installs every such obligation before it resumes an outbox, sends a request, or lets a live rekey path seal. A page clears one peer only when `responder_state_hash` equals the local saved head after the page is applied. An empty page, a truncated page, a missing hash, a different hash, and a KeyPackage reply do not clear the peer.

The obligation may send at most three catch-up requests. Startup sends the first. A successful network join sends another. A 30 second backoff sends what remains. A failed send does not seal. When the bound is spent, the obligation stays open. There is no fallback committer. While that obligation is open and the removed leaf is still live, TreeKEM encrypt refuses new ciphertext.

When no other active member remains, the daemon retires the obligation under the membership lock and may seal. A Removed row with no live leaf does not start the obligation. A leave applied as the next head, with an empty queue and no open obligation, stays the positive local signal from the accepted record. The response gains optional `responder_state_hash`. An omitted hash does not clear a startup obligation.

## Consequences

A restarted committer does not seal because a timer fired or because a cold peer sent an empty page. New ciphertext stays withheld while a live removed leaf remains. If the three sends find no peer, the leaf stays and new ciphertext stays withheld. The outbox and the lowest-admin rule stay as accepted in A09. This record stays Proposed until David accepts it. A09 may hold it beside the accepted rekey record.

## Validation

The epoch stays still until a page reports the local saved head. A newer head, a missing hash, and a KeyPackage reply do not seal. A failed send stays pending, a later retry sends again, and a send past the bound does not. Encrypt returns conflict while the leaf remains. The epoch advances when the last other member leaves. A historical Removed row does not open the wait. Two groups install their gates before either seals, in sorted group-key order.
