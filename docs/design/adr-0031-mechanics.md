# ADR-0031 mechanics — Validation and property-test detail

> Extracted 2026-08-29 from the immutable [ADR 0031](../adr/0031-sole-member-self-leave-deletes-group.md) per the
> 2026-08-23 ADR audit. The ADR remains the complete decision record; the
> sections below are the validation inventory relocated verbatim so this file is their maintained home — future updates
> belong here, not in the ADR.

## Validation

- `leave_disposition` unit tests over every roster shape: sole-active, sole
  with removed/banned residue, sole-active + pending request (both the
  KEM-less and mirrored shapes), pending + another active member, two-active
  (member proceeds / sole admin blocked), and request-resolution
  (reject/cancel) unlocking the deletion.
- Handler tests: sole-member leave deletes with a withdrawn keyless
  tombstone; pending-request leave 409s with the distinct string; a sole
  non-admin Member still deletes; withdrawn tombstones are hidden from
  `GET /groups` and flagged on `GET /groups/:id`; the two-member 409 keeps
  the exact ADR-0016 §3 string.
- Property tests drive the shipped predicate: the sequence model maps
  `LastAdminBlocked`/`PendingJoinBlocked` to their 409s and records-and-skips
  `SoleMemberDelete` (no tombstone model), with a deterministic sole-member
  case proving the branch is exercised; the withdrawal-authority property
  generates sole-member and empty rosters so the rank-blind terminal
  carve-out is falsifiable.
- Integration: create → join → leave → sole-member DELETE disposes the group
  (`deleted` body, withdrawn tombstone, snapshot wipe) and the ex-member's
  daemon never resurrects the group from cache or discovery.
