# T-self-leave-catchup-author: who may deliver a signed self-leave

- **Status:** Accepted (David, 16 Oct 2026, slot A09, PR #1337).
- **Date:** 2026-10-14
- **Target slot:** A09
- **Decision owners:** David Irvine
- **Reviewers:** pending
- **Supersedes:** none
- **Superseded by:** none
- **Related:** issue #1113; ADR 0016 decision 6; `T-self-leave-rekey-committer` (Accepted, D274, slot A09)

This record is Proposed. It does not change Accepted ADR bytes and adds no wire field.

## Context

A TreeKEM self-leave is a signed `MemberRemoved`. On the direct path the transport sender must be the leaver, and the actor must name that sender. The responsive rekey is a second `MemberRemoved`. Its actor is the admin who committed it. `T-self-leave-rekey-committer` stores both events so a restarted node can serve them on catch-up.

Catch-up delivers those saved events from an active member who still has them. That member is not the leaver. The apply path treated the transport sender as the author. It rejected the roster-only leave. The rekey then had no parent. A restart did not close that gap.

The commit already carries an ML-DSA-65 signature. `GroupStateCommit::verify_structure` checks the signature, the state hash, and that `committed_by` is the agent id of the signing key. `GroupDeleted` already applies by that signer. The actor string is not that check.

A catch-up fence that is one flag per group has a second fault. Any peer's last page, including a member-keyed KeyPackage reply, cleared it. A truncated page from one peer could then seal while that peer still owed a page.

## Decision

On the catch-up recovery path only, apply a `MemberRemoved` as its verified signer when all of the following hold. The transport sender is an active member. The existing response gate stays. `verify_structure` succeeds. The event actor equals `committed_by`. The roster checks then run against that signer. A self-leave still requires the signer to be the removed member. An admin removal still requires the signer to be an active admin.

The direct path does not change. A transport sender who is not the signer cannot apply a `MemberRemoved` by writing the actor field. A failed signature is not applied under the transport sender's authority.

A truncated membership page opens a fence for that peer only. A later page from another peer does not close it. A member-keyed KeyPackage reply does not close it. The fence closes when that peer returns a non-truncated membership page. The next-page request has three send attempts. A failed send does not seal. This record adds no timeout that seals and no second committer. The Accepted consequence in `T-self-leave-rekey-committer` still stands. A node that does not know it is behind can seal.

The outbound rekey record includes the TreeKEM commit bytes in its identity. A retry that finds a pending record for the current head restores that record's saved post-commit tree. It does not create a second commit. A publish that returns an error or times out leaves the record pending.

## Rejected options

- **Trust the actor field.** An active transport sender could then name any author.
- **Close every open page on any terminal response.** That seals over a known gap.
- **Treat two TreeKEM commits with one roster hash as one outbound event.** The roster hash does not cover the commit bytes.

## Consequences

- An offline member can apply a leave that a survivor serves, then apply the rekey that follows it.
- A forged actor on a catch-up page does not authorize the removal.
- A known truncated page stays open until that peer finishes or the process restarts. This record adds no seal timeout.
