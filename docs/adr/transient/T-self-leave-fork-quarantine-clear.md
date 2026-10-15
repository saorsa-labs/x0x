# T-self-leave-fork-quarantine-clear: clear a local self-leave fork marker

- **Status:** Proposed
- **Date:** 2026-10-14
- **Target slot:** A14
- **Decision owners:** David Irvine
- **Reviewers:** pending
- **Supersedes:** none
- **Superseded by:** none
- **Related:** T-self-leave-rekey-committer (Accepted, D274, slot A09, PR #1337); T-self-leave-catchup-before-seal (Proposed, slot A07); ADR 0064; ADR 0066; `docs/runbooks/fork-quarantine.md`; issue #1113

## Context

David accepted `T-self-leave-rekey-committer` (D274, 14 Oct 2026, slot A09). A node that seals while it is behind can sign a second child of the same parent. ADR 0064 and ADR 0066 then set the local marker. The two sealed epochs stay split. This record does not merge them.

A14 owns this local clear. It does not repair membership, so it does not target A08.

## Decision Drivers

The accepted A09 record already names the marker. One node's clear does not clear another node. A clear that leaves the evidence gate closed would hide the next conflict. A journal rollback would hide the fork.

## Considered Options

1. Lift the local marker with the existing quarantine clear, then follow the runbook.
2. Roll the TreeKEM journal back to the parent epoch and drop the marker in the same write.
3. Add a self-leave quarantine flag with its own clear route.

## Decision

We will lift a self-leave fork marker with the existing local clear. The clear does not choose a TreeKEM epoch.

The marker is the ADR 0066 marker. It is never gossiped. Each node that holds it must clear its own copy. Before a force clear, the operator follows `docs/runbooks/fork-quarantine.md` §4.3c: compare `GET /groups/:id/state` heads, read `snapshot.classification`, have an admin of the agreed chain advance it, re-seat members who still hold the disowned sibling, then clear. The reason names that runbook and what was verified.

A relayed TreeKEM commit that the signed roster binding does not cover is rejected and sets no marker. This clear does not apply to that fork.

`POST /groups/:id/quarantine/clear` is the route. `clear_group_quarantine` implements it. Only the durable API token may call it. A session token is refused and the marker stays.

An ordinary TreeKEM group carries `no_anchor`. Force true and a non-empty reason are its only exit. An owner-axis group can clear without force when this install holds the owner user key and the route mints a quarantine-clear attestation over the current head. The same force override also clears an owner-axis group. `POST /groups/:id/state/seal` (`clear_fork_quarantine_on_explicit_owner_seal`) clears an owner-axis marker only when this install holds the owner user key and the sealed revision is strictly greater than the evidenced revision. A same-revision sibling does not clear it. An ordinary group does not clear on that seal.

Every clear calls `reset_fork_evidence_after_quarantine_clear`. The evidence gate is armed again. The next authenticated conflicting commit quarantines the group again. TreeKEM encrypt and TreeKEM decrypt are separate gated surfaces. The clear lifts both refusals on this node. The sealed epoch remains the local epoch.

## Consequences

The operator can serve the group on this node after the clear. The other sealed epoch remains. A later conflicting commit quarantines this node again. This record stays Proposed until David accepts it. The accepted A09 bytes stay unchanged.

## Validation

One test applies a roster-only self-leave, then lets startup seal after the other admin is gone. A conflicting self-leave rekey (`MemberRemoved` with a different TreeKEM commit) arrives through `apply_named_group_metadata_event`. The marker is set, `no_anchor` is true, and the group is refused. A session token is forbidden and the marker stays. The durable force clear removes the marker and leaves the sealed epoch. A second conflicting self-leave rekey on that same receive path quarantines the group again.
