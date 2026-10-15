# T-self-leave-catchup-before-seal: finish catch-up before a self-leave rekey

- **Status:** Proposed
- **Date:** 2026-10-14
- **Target slot:** A07
- **Decision owners:** David Irvine
- **Reviewers:** pending
- **Supersedes:** none
- **Superseded by:** none
- **Related:** T-self-leave-rekey-committer (Accepted, D274, slot A09, PR #1337); issue #1113; ADR 0016 decision 6

## Context

David accepted `T-self-leave-rekey-committer` (D274, 14 Oct 2026, slot A09). Its single committer is the lowest active admin. A 250 ms startup wait proves nothing. v0.47 and v0.48 peers omit `responder_state_hash`.

## Decision Drivers

A timed wait cannot prove that catch-up finished. `truncated: false` cannot prove that the saved heads match. The designated committer stays the lowest active admin. The wait must end after every peer has been asked.

## Considered Options

1. Keep the 250 ms startup wait, or make it longer.
2. Seal after any non-truncated catch-up page.
3. Ask each peer within a bound, and withhold new ciphertext while a peer can still answer.
4. Add a second committer that seals if the first does not answer.

## Decision

We will require verified head evidence before the designated committer seals a startup self-leave rekey, when a removed member still has a live ratchet leaf and another active member remains.

On startup, the daemon installs every such obligation before it resumes an outbox, sends a request, or lets a live rekey path seal. A page clears one peer only when `responder_state_hash` equals the local saved head. An empty page, a truncated page, a missing hash, a different hash, and a KeyPackage reply do not clear the peer. A terminal page records that peer even when another peer's page stream is open. Open streams still refuse the seal.

Each other active member may be asked at most three times. The bound is per peer. The attempt is reserved before the request is awaited, and a failed send still spends it. A peer who leaves the roster is dropped. A peer who remains keeps the sends already spent and the satisfied bit. When every remaining peer has reported the saved head or has spent its three sends, the designated committer may seal. There is no second committer. While a remaining peer still blocks and the removed leaf is live, REST encrypt and the group-store protector both refuse new ciphertext.

When no other active member remains, the daemon retires the obligation and may seal. A Removed row with no live leaf does not start the obligation. The response gains optional `responder_state_hash`. An omitted hash does not clear a startup obligation. The per-peer bound ends that wait.

## Consequences

A restarted committer does not seal because a timer fired or because a cold peer sent an empty page. When every peer has spent its three sends, the designated committer seals. The outbox and the lowest-admin rule stay as accepted in A09. This record stays Proposed until David accepts it. It is not folded.

## Validation

The epoch stays still until a page reports the local saved head, or until every remaining peer has spent its three sends. A newer head, a missing hash, and a KeyPackage reply do not clear a peer. Four peers are each asked. Encrypt returns conflict, and the group-store protector refuses, while a peer still blocks. The epoch advances when the last other member leaves, when a departed peer is dropped and the survivor is satisfied, and when the per-peer bound is spent. A matching head kept behind another open stream lets the seal proceed when that stream closes. Overlapping retries do not send a fourth request after three are reserved. A historical Removed row does not open the wait.
