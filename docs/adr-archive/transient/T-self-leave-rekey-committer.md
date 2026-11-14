# T-self-leave-rekey-committer: who commits a TreeKEM self-leave

- **Status:** Accepted (David, D274, 14 Oct 2026, slot A09, PR #1337). Acceptance includes the fork-quarantine consequence.
- **Date:** 2026-10-13
- **Target slot:** A09
- **Decision owners:** David Irvine
- **Reviewers:** pending
- **Supersedes:** none
- **Superseded by:** none
- **Related:** issue #1113; ADR 0014; ADR 0016 decision 6; ADR 0016 decision 7; PR #1337

This record is Proposed. It does not change Accepted ADR bytes. A self-leave rekey sets `security_binding` to `treekem:epoch=<n>:commit=<blake3>`. A v0.48 receiver rebuilds `treekem:epoch=<n>`, gets `StateHashMismatch`, and leaves a group that contains an upgraded member. Admin removal keeps `treekem:epoch=<n>`.

## Context

ADR 0016 decision 6 names one committer after a TreeKEM self-leave: the lowest active admin, by raw agent id. Other admins hold off. Removal of that admin makes the choice again.

A daemon that does not run this rekey does not seal. Newer admins then hold off, and the leaver keeps a live leaf. No message names this rekey. A missing advertisement is not proof the peer is old. Two upgraded admins would both commit.

A commit runs only when the leave is the local head and the TreeKEM queue is empty. The sender checks that head again under the membership lock. A truncated catch-up page does not seal. The pass runs after the last page. Replay holds a fence until its batch ends.

A node that does not know it is behind can still seal. An in-order backlog is one case. Startup is another: a 250 ms wait runs no catch-up and proves nothing. That seal can fork the group into quarantine. This record adds no timeout and no second committer. ADR 0110 stays Proposed.

## Decision

Until a capability bit is accepted, election stays ADR 0016 decision 6. Every active admin stays eligible. That bit must ride an existing signed advertisement. The committer is then the lowest active admin who advertised it. A test may mark an admin silent. That mark is local, not a wire field.

One JSON file per group is stored at `data_dir/treekem-self-leave-outbox/<blake3 of the group key>.json`. It lists the roster-only self-leave, unpublished rekeys, and published rekeys. Save the rekey, with `treekem_commit_b64` and `treekem_epoch`, before the epoch is durable. Save the predecessor so restart can serve it on catch-up. After publish, keep the rekey for catch-up and do not send it again. Publish a saved rekey only when the stored chain holds its commit hash. Delete it if persist fails before the epoch is installed. Keep it if the epoch is installed or completion is uncertain. This file is not the TreeKEM journal.

A full pass schedules one more pass and does not start a timer. A demotion, removal, or ban, including the author's route, runs the pass after the membership guard drops. A missing KeyPackage on a live leaf is a logged deferral. Only the designated admin asks for the bytes.

## Rejected options

- **Skip a silent admin now.** Two upgraded admins can both commit.
- **Use the DM protocol version as the bit.** It does not name this rekey.
- **Hand the commit to the next admin on a timer.** That is Proposed ADR 0110.
- **Seal after the roster-only hash.** Restart must serve the hash peers saw.
- **Use a longer startup wait.** A wait cannot prove catch-up finished.

## Consequences

- One committer remains while every active admin is eligible. A mixed group waits until the lowest admin runs this code or is removed.
- A node that seals while it does not know it is behind can quarantine the group. Accept this record only with that consequence.
- A crash after the epoch is saved keeps the event. A crash before the epoch does not publish it.
- The outbox file is a new stored format. Accept this record before merge.
