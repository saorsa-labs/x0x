# T-self-leave-rekey-committer: who commits a TreeKEM self-leave

- **Status:** Proposed
- **Date:** 2026-10-13
- **Target slot:** A09
- **Decision owners:** David Irvine
- **Reviewers:** pending
- **Supersedes:** none
- **Superseded by:** none
- **Related:** issue #1113; ADR 0014; ADR 0016 decision 6; ADR 0016 decision 7; PR #1337

This record is Proposed. It does not change Accepted ADR bytes. It does not add a wire field.

## Context

ADR 0016 decision 6 names one committer after a TreeKEM self-leave: the lowest active admin, by raw agent id. Other admins hold off. If that admin is gone, another admin removes them and the choice is made again.

A daemon that does not run this rekey applies the roster removal and does not seal a TreeKEM commit. If that daemon is the lowest admin, newer admins hold off. The leaver keeps a live leaf.

No message says that an admin runs this rekey. A missing advertisement is not proof that the peer is old. Two admins would then both commit.

ADR 0016 decision 7 says two commits over one parent can fork. A commit is allowed only when the leave is still the local head and the TreeKEM queue is empty. The sender checks that head again under the membership lock before the new epoch is saved. A catch-up page and a replay batch seal once, after the batch. Startup waits one short quiet interval, then skips a group whose queue is not empty.

Two leaves can still be signed against the same parent before either removal commit arrives. This record adds no timeout and no second committer. ADR 0110 is still Proposed and is not used here.

## Decision

Until David accepts a capability bit, election stays ADR 0016 decision 6. Every active admin stays eligible. Absence of an advertisement is not a reason to skip an admin.

When that bit is accepted, it must ride an existing signed capability advertisement. The committer is then the lowest active admin who advertised the bit. There is still one committer. A test may mark an admin as silent. That mark is local. It is not a wire field.

Save the removal event, including `treekem_commit_b64` and `treekem_epoch`, before the new epoch is durable. After a restart, load that event into the catch-up log and send it again. Drop a saved event whose epoch is not in the loaded tree. The pass may then seal a new commit. This store is not the TreeKEM journal.

A pass that hits its batch limit schedules one more pass. It does not start a timer. A demotion, removal, or ban that changes the lowest eligible admin runs the pass again. A missing KeyPackage is a logged deferral, not a finished rekey.

## Rejected options

- **Skip a silent admin in this PR.** Two upgraded admins can both commit before a bit arrives.
- **Use the DM protocol version as the bit.** That version does not name this rekey.
- **Hand the commit to the next admin on a timer.** That is the Proposed ADR 0110 path.
- **Publish the roster-only hash, then seal.** A restart can observe the first hash and load the second. The durable hash must be the hash a restart serves.

## Consequences

- One committer remains while every active admin is eligible.
- A mixed group waits until the lowest admin runs this code, or until that admin is removed. That is ADR 0016 until the bit is accepted.
- Catch-up does not seal a second head between queued events.
- A crash after the epoch is saved still has the event for catch-up.
