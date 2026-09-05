# ACP placement: prevention and separate recovery

PR #512 prevents new issue-time pins to the wrong machine. A non-local ACP
harness is not minted until discovery supplies a nonzero machine ID. The
owner daemon's machine is never a fallback for an ACP harness. The local
Home agent remains Roaming; rider placement retains its existing behavior.

Inbound identity announcements remain subject to the normal ADR-0043 B/P
pairing gate. `PlacementPinned` and binding tombstones are hard denials;
an ACP issuance journal entry does not override placement authority.

## Recovery entrypoint specification (not implemented)

Already-minted bad pins are outside this prevention patch. Re-running mint
or announcing from another machine does not rewrite an existing placement.
There is no live-owner workaround and no automatic repair on ingest.

A future explicit operator/API repair entrypoint must be reviewed separately:

- Accept the affected agent, expected current placement/epoch, and intended
  harness machine, with authenticated owner authorization.
- Verify the harness binding independently of the denied announce and reject
  stale expected state. ACP mode alone is not authority to change a pin.
- Define an owner-signed, epoch-consistent correction and its durable audit
  record, persistence, replica propagation, and compatibility with move logs
  and binding tombstones before enabling any mutation.
- Keep the existing pin enforced until the approved correction is committed.
  Do not delete placement files or bypass ingest to make discovery succeed.

This is a documentation stub, not a callable route or a repair procedure.
Existing bad pins therefore remain denied pending that separate work.
