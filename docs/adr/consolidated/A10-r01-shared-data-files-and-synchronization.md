# A10 Shared Data Files and Synchronization

- **Status:** Accepted (David, course-correction directive, 7 Nov 2026, ruling 2)
- **Revision:** 1
- **Date:** 2026-10-05
- **Decision owner:** David Irvine
- **Direction:** Confirmed by David (D198) on 2026-10-05 for this team review.
- **Replacement activation:** Active since 7 November 2026. The 15 accepted slots are the live decision authority.
- **Supersedes:** The archived numbered records mapped to this slot in [TRANSFER.md](TRANSFER.md). The archive stays the historical record. Existing implementation gates remain in force.

David accepted the 15 slots at their current revisions on 7 November 2026 (course-correction directive, ruling 2). They are the live decision authority. The numbered records stay in [docs/adr-archive](../../adr-archive/ARCHIVE.md) as the historical record. [docs/adr-archive/move.json](../../adr-archive/move.json) records the archive transfer David accepted on 10 October 2026. Use the [index](README.md) for the current rules.

x0x stores and shares data through authorized peers. It must state who holds the data, how changes merge, and what happens when a peer is offline.

## Context

The product contains key-value stores, task data, local history, file transfer and owner synchronization. Scratchpads are core planned work. Rich collaborative text has a separate parked design.

These data types do not have the same merge, retention or authority rules.

## Decision

We will keep data with explicit holders and scopes. Existing relationships must not depend on a global DHT for user or group data.

Each shared data type must specify its identity, author, permission, merge rule, retention rule and recovery source. Applications must not infer durability from a successful live notification.

Replicated key-value data uses its defined CRDT policy. Last-writer selection can discard a concurrent value. It is not a general collaborative text editor or a transaction service.

Task state follows [A12](A12-r01-agent-teams-delegation-and-task-coordination.md). Membership and key state follow [A08](A08-r01-groups-home-membership-and-repair.md) and [A09](A09-r01-group-encryption-and-key-changes.md). They must not use a data-merge shortcut that changes security authority.

## Synchronization and repair

Use change exchange for prompt updates and a bounded state-repair path for missed updates. The receiver must verify authorship and access before applying data.

A node that returns after an outage must be able to detect missing state. A digest or version comparison may trigger repair. The exact beacon and transfer format require a reviewed specification.

A holder can serve retained data only when the requester is currently entitled to it. The holder must also be entitled to serve it.

A new member does not gain all historical data by default. Each group data type must define the history available at admission and after a key change.

## Owner state and scratchpads

Owner synchronization is limited to its declared state classes. Enrollment, names, profile and group pointers do not imply that all direct-message history or private group data is copied between devices.

Scoped scratchpads will use the group's data and encryption rules. Rider and shared-agent access must be explicit. Scratch access must not expose unrelated stores or daemon state.

Each entry of a group store names its writer (amendment of 16 Nov 2026, #1094 slice P1, revised after review; Claude under David's delegation of 10 Nov 2026 and A15 as amended on 12 Nov 2026). A store record's verified author is not the writer of every entry it carries, because retained images and full state serves relay co-writers' entries. Decision: the writer signs each entry it writes to a store whose topic starts `x0x/group/`, and the mark rides inside the entry in reserved metadata keys (prefix `x0x.writer.`): `x0x.writer.agent.v1` (the writer's agent id, hex), `x0x.writer.sig.v1` (base64 of the ML-DSA-65 signature), `x0x.writer.for.v1` (`<updated_at>:<content hash>`, the version the mark was made for) and, when a rider wrote through the agent, `x0x.writer.rider.v1` (its label, at most 64 bytes). The signature covers the store id, the key the entry sits under, the writer, the content hash, the content type, `updated_at`, the rider label and every other metadata pair, under the domain `x0x.kv.entry-writer.v2`; it leaves out `created_at`, which a merge can change: since 16 Nov 2026 (review of #1974) every merge keeps the earlier `created_at` of the two entries whichever wins, so all replicas at this version converge on it; it stays outside the mark and the LWW order. An owner checkpoint commits to `created_at`. A replica adopts a checkpoint by merging the verified entries into its own under the same LWW rule, so a later local entry or an earlier local `created_at` can win. After 17 Nov 2026 (review of #1987, Claude under David's delegation of 10 Nov 2026 and A15) the replica recomputes the root over its own state after the merge and caches the checkpoint only when it still matches; otherwise it caches none, so it never relays a checkpoint that does not match the entries beside it, and a receiver takes the sender-auth path. The checkpoint's sequence still becomes the replica's high-water mark. The public key is not in the entry: a reader takes it from the keys this daemon has seen proved, by a verified signed gossip message or a verified group mutation (agent id = SHA-256 of the key). A reader gets `verified` (agent and rider), `unverified` (the writer's key is not known here; never shown as verified), `unsigned` (no mark for the current version: an older writer, a rewrite by a writer that does not mark, or a store outside `x0x/group/`) or `invalid` (a mark that does not cover the entry's content, key or store). A delta that holds an entry under another key than its own is refused, so a mark cannot move to another key. No merge path verifies a mark (decision of the reviewer under A15, 16 Nov 2026, reversing an earlier ranked tie-break): verification depends on which keys a daemon knows, and a CRDT merge must be a pure function of the two entries. Every merge path (deltas, SelfKeyed, checkpoints, retained images, legacy history) uses the one LWW rule of `KvEntry::merge`: the greater of `updated_at`, then content hash, then content type, then the sorted metadata. On a tie of time and content the value is identical and only the mark can differ, so the rule keeps one mark the same way on every replica, without checking it. The guarantee is one-way. `verified` with agent A means A signed exactly these bytes for this store and key, so there is no false attribution. The other three states mean "writer unknown" and prove nothing: any group member or relay can replace a mark on such a tie, as any member can overwrite the entry, and a daemon may not know the writer's key. So verification is read-side only (`KvStoreHandle::entry_writer`), and the API and the Scratch app (P2) show `unverified`, `unsigned` and `invalid` as writer unknown, never as evidence of tampering. A rewrite here drops the old mark, and a signing failure leaves the entry unmarked rather than failing an applied put. Entry metadata is already encoded, merged and committed with the entry, so older peers store and relay the mark unchanged: no new wire field, no storage migration and no capability bit, against the versioned-entry plan posted on #1094. A mark adds about 4.7 KB to an entry (at most 4 800 bytes, checked by a test), so a group store of small entries holds about 3 300 of them before its complete image reaches the 16 MiB retained-image limit. A put that would take the image past that limit is refused with `store full` (HTTP 507 on `PUT /stores/:id/:key`), so new and lagging members keep getting the store's history; the image is not paged further. Until 16 Nov 2026 this check ran only on the writer's own node: concurrent writers, or peers on an older version, could still take the merged image past the limit, which #1970 tracks (page the image, or bound incoming merges). Since 16 Nov 2026 the same limit also bounds incoming merges; the next paragraph records that amendment. Slice P2 (16 Nov 2026) shows it: `GET /stores/:id/:key` returns `writer` as `{"verified": true, "agent", "rider"}` only for a mark that verifies for the value returned, and `{"verified": false}` otherwise, without the raw mark keys; a rider's write names the rider's sub-agent id; the Scratch app shows the writer or "Writer unknown", never a warning. Every merge path also refuses an entry whose content hash is not the hash of its value, so two replicas never hold different bytes under one LWW identity.

The same 16 MiB retained-image limit as the put gate bounds every remote entry point that merges into a store which serves its complete state as a retained group image (content deltas and retained-image merges, GroupSigned/Encrypted/TreeKemEncrypted) and the serve boundary (amendment of 16 Nov 2026, #1970, revised after review; Claude under David's delegation of 10 Nov 2026 and A15 as amended on 12 Nov 2026). The exception is owner-checkpoint full-snapshot adoption (`try_adopt_full_snapshot` returns ahead of the gate): its entries are bounded only by the 4 MiB frame, and retained OR-Set tombstones and changelog are not wire-bounded there. The bound is measured on the canonical retained image: the complete store image with the OR-Set's replica-local delta bookkeeping (changelog, version) cleared, exactly the bytes a served retained image carries. A replica trial-merges the incoming data and measures that canonical result, so it is not an estimate; re-deliveries and same-tag re-adds grow only the bookkeeping and are not growth. Every replica computes the same measure for the same retained content, so the writer and the receivers agree near the limit. A replica refuses an incoming delta or retained-image merge that would grow the canonical image past the limit; nothing from a refused merge applies, and the refusal is typed (`KvError::StoreFull`). Near the limit, a replica's state can depend on which remote input arrives first: two replicas whose union would pass the limit can stay apart, each refusing the other. This divergence is not silent: every refusal is typed, counted and surfaced in the state-sync diagnostics (`GET /diagnostics/state-sync`), and a joiner converges on whichever complete image reaches it first. A merge that does not grow the canonical image past the limit commits, so removals and shrinking images always apply; a store already past the limit (merged before this bound, or grown through owner-checkpoint adoption) recovers by merging removals and serves again. A holder past the limit cannot serve its retained image until it shrinks; the serve fails with the same typed refusal. Paging the image past the limit (options 1 and 3 of #1970) is deliberately not taken in this change: raising the practical size means raising the receiver-side page reassembly and pool bounds, and the wire-visible 64-page limit that older peers refuse. A finite bound would still leave arrival-order convergence just below the new limit. #1970 tracks that work.

Rich-text notes remain parked. If that work resumes, use the accepted Loro direction unless a reviewed revision changes it. Text operations need causal and author checks in addition to group encryption.

## File transfer and retention

A file transfer must bind the declared content identity, size and recipient. Check the complete content hash before reporting verified completion.

File control frames have an application acknowledgement (accepted by David, 12 Oct 2026, option (b); archived as [T-file-control-ack](../../adr-archive/transient/T-file-control-ack.md)). `FileMessage::ControlAck` (wire tag `file-control-ack`) names the transfer id and the operation: `offer`, `accept` or `reject`. Capability bit 3 is `file_control_ack_v1`; this allocation does not edit archived ADR 0093. A node waits for the acknowledgement only when the peer's current verified advert sets bit 3, and a missing acknowledgement then fails the call. A verified advert without bit 3 is a v0.47.0 peer: do not wait, do not send the frame, and a stored offer is success. With no verified advert, do not wait but still send the frame. A chunk acknowledgement whose id is `ctrl:<op>:<id>` must not complete the wait, an acknowledgement from any other agent must not complete it, and history classifies the frame as ephemeral.

Bound transfer size, concurrency, temporary storage and retained content. An interrupted transfer must have a clear retry or cleanup result.

Deletion has a defined local or replicated meaning. It does not promise erasure from another participant's backups or previously exported plaintext.

A local acknowledgment must state what was saved. It must not imply that a remote replica or backup exists.

## Consequences

Each data type has an explicit merge and retention contract. Peers can work during a partition, but availability still depends on authorized holders. Applications must expose conflicts, replica state and storage limits.

## Alternatives

A global storage layer could offer broader availability, but would change custody, cost and trust assumptions.

Using one whole-document last-writer value for every data type is simple, but can discard edits that users expect to merge.

## Current implementation

KV stores, task lists, file transfer and scoped owner sync exist. The full scratch-store surface and several any-holder recovery paths remain work in progress. Rich-text work remains parked.

## Validation

Test concurrent edits, missed updates, restart, owner-offline repair, corrupted files and storage limits. Verify deterministic merge behavior and author checks.

Test removal during fetch and key delivery. Confirm that an unauthorized rider cannot recover another scope through a history or repair endpoint.

## Matters to settle

Set retention and storage budgets per data class. Define which authorized peers must hold a copy before the product reports replicated durability.

## Existing decision records

Read the [design direction and rulings digest](../../design/x0x-direction.md)
and the [rulings transfer map](TRANSFER.md#rulings) with these records.

These records are the primary sources for this draft. This mapping does not complete the clause by clause transfer required by A15.

[ADR 0006 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0006-no-global-dht-for-user-and-group-data.md) · [ADR 0041 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0041-cross-machine-state-sync-tiers.md) · [ADR 0047 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0047-crdt-kv-store-delta-gossip.md) · [ADR 0055 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0055-dm-file-transfer-protocol.md) · [ADR 0075 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0075-collaborative-notes-and-agent-scratchpads.md) · [ADR 0081 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0081-notes-use-loro-crdt.md) · [ADR 0082 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0082-notes-epoch-bound-writer-rule.md)

Decision source snapshot: 5 October 2026, commit `eacf68591dffcb6f949e2a12bc6f05cfb6e8d481`. Implementation checked on 12 October 2026 at commit `8cb6488331e6c1226913104ddb99ca4ec18bec37`.

[All 15 ADRs](README.md)
