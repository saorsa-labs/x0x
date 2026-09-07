# Issue #321: canonical group-history projection

`GroupPublicMessage::msg_id()` remains the ADR-0029 identity:
`BLAKE3(signable_bytes())`, represented as 32 bytes in the local index and
lowercase hex on REST surfaces. `HistoryRecord.msg_id` remains the
artifact/payload hash dedupe key required by ADR-0023 and `validate()`.

The history store maintains the canonical identity in the rebuildable
`history_canonical_ids` auxiliary table. It is keyed by the existing unique
`history.msg_id`, records the group scope, and has a `(canonical_msg_id,
scope_kind, scope_id)` lookup index. New rows populate it in the same SQLite
transaction as their history row. A persistent delete trigger removes the
projection when a history row is deleted; store retention and purge also
reconcile orphaned entries.

Every store open reconciles missing projections from group rows whose signed
artifact decodes as `GroupPublicMessage`, whose group matches `scope_id`, and
whose body matches the stored payload; rows that are undecodable or have a
scope/body mismatch are skipped. The immutable existing history hash plus the
delete trigger make incremental reconciliation safe for older writers.
Retention and scope purge explicitly remove orphaned projection rows. This
keeps the existing artifact shape and REST fallback behavior while preventing
an invalid artifact from becoming an indexed canonical hit.

The auxiliary table is deliberately outside `schema_version`: older binaries
can open, read, insert, replace, and delete the unchanged v4 `history` table,
while a newer binary reconstructs entries on its next open. Canonical point
lookup uses the scoped index first and retains the bounded scan only for
legacy rows predating the projection. Signing, wire fields, dedupe, retention,
and actor-scope authorization are unchanged.
