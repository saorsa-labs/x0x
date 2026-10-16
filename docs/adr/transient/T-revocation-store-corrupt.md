# T-revocation-store-corrupt: a corrupt revocation store is quarantined and x0xd keeps running

- **Status:** Accepted (David, 2026-10-13)
- **Target slot:** A03
- **Date:** 2026-10-13
- **Decision owners:** David Irvine
- **Reviewers:** <pending>
- **Supersedes:** none
- **Superseded by:** none
- **Related:** x0x #1116, PR #1336. This record stops the D266 refuse-to-start design.

## Context

x0xd stores revocations in three files. A missing file means no revocations are known yet, and membership stays open. A present file that cannot be decoded is different. The old load treated that file as empty and left membership open. That can admit a member whose revocation was lost. D266 said x0xd must refuse to start. David stops that design.

## Decision Drivers

- The operator must see one log line and one status event.
- Unknown revocation state must not count as proof that a member is still valid.
- The hold must not be stored as a revocation record.
- The live path must not keep the bad bytes. The next start must not read that payload.

## Considered Options

1. Refuse to start and require a hand recovery command.
2. Load an empty set and admit every member.
3. Store a revocation record for every subject.
4. Move the bad bytes to a quarantine file, keep running, report the state, and fail membership closed until resync.

## Decision

When a revocation file is present and x0xd cannot decode it, x0xd must do these four things.

1. x0xd moves the bad bytes to `<file>.quarantined-<unix-ms>`. A taken name gets `-<seq>`. The live path does not hold the payload. The next start must not read those bytes. It sees the quarantine name and keeps membership closed. A readable file placed on the live path is a rebuild.
2. x0xd starts and keeps running. A corrupt revocation store must not refuse startup.
3. x0xd writes one error log line and emits a status event. `GET /status` and `x0x status` set `revocation_resync_required` to true and include the same sentence in `warnings`. The first status read also sends one `status` event on `/events`.
4. Until revocation state has been rebuilt or resynced from the group, membership fails closed. x0xd treats any member whose non-revocation cannot be verified as revoked. x0xd must not silently re-admit anyone. The hold is not a revocation record. An empty snapshot does not open membership. A carrier opens only when every record in its snapshot has verified. A verified revoked subject stays revoked. A missing live file with a quarantine sibling stays closed.

A bad signature on a valid structure does not close membership.

## Consequences

### Positive

- The daemon can receive a group snapshot. The log line and the status event use the same sentence.
- The bad bytes stay in the quarantine file. The live path does not hold them.

### Negative / Trade-offs

- Named-group membership reads fail closed until each corrupt carrier has a verified snapshot.

### Neutral / Operational

- David accepted this text for slot A03. Fold it only when David asks. Do not edit the consolidated slot file.

## Validation

Tests must show the quarantine file and a live path that is not the corrupt payload. The daemon starts and serves. Status shows the flag, the warning, and the `/events` event. The next start stays closed and does not read the quarantined bytes. An empty snapshot leaves membership closed. Daemon cases use the isolated test network.

## Notes for AI-assisted work

David accepted this revised text on 2026-10-13. Do not mark another record Accepted. Do not fold this file.
