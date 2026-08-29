# ADR 0031: Sole-Member Self-Leave Deletes the Group

- **Status:** Accepted (2026-08-20)
- **Date:** 2026-08-20
- **Decision owners:** Claude (design/review), omp (implementation)
- **Reviewers:** David Irvine
- **Supersedes:** none
- **Superseded by:** none
- **Amends:** [ADR 0016](./0016-role-based-group-authority-flat-admin.md) §3 (last-admin invariant)
- **Related:** issue #369 (sole-member group undeletable), PR #370, issue #372
  (concurrent last-two-leaves race), ant-quic #244/#305 (stream reset / close-by-address
  lessons, cited for future work)
- **Mechanics:** Leave-disposition test inventory: unit/handler/property/integration are maintained in [`docs/design/adr-0031-mechanics.md`](../design/adr-0031-mechanics.md) (extracted 2026-08-29; ADR body unchanged)

## Context

`DELETE /groups/:id` routed every self-leave through the ADR-0016 §3 last-admin
pre-check, which evaluates the post-removal roster remainder. For a sole-member
group the remainder is empty by construction, so the invariant can never be
satisfied by waiting: the API answered 409 — "make another member an admin
before leaving" — to a user for whom no other member exists. An empty group was
permanently undisposable (#369).

## Decision Drivers

- A live group always keeps an active admin (ADR-0016 §3), so a sole member is
  necessarily admin-or-higher or the roster already violates the invariant
  (legacy data); either way the empty remainder makes plain leave impossible.
- Pending joiners are real members-in-being: deleting the group under an
  in-flight admission request destroys the joiner's pending state.
- The pending view must be authoritative wherever it drives routing: the
  roster's Pending entry is only a mirror seeded at request time — a KEM-less
  join request (a legal wire shape) seeds none, and a request resolved by
  reject/cancel must not leave a stale mirror behind.
- Tombstones left by deletion are anti-resurrection records and must remain
  locally, but must not surface as live groups.
- Two members leaving concurrently is a real interleaving; the decision must
  describe it honestly rather than wish it into a conversion.

## Considered Options

1. **Weaken `enforce_last_admin_invariant`** to accept empty remainders —
   rejected: every group with more than one member keeps the §3 409, and the
   invariant's apply-side authority is the load-bearing security property.
2. **Force flag / separate delete call** (`x0x group delete` already exists) —
   rejected: the user's intent ("I am out") is unambiguous when they are the
   only member; a 409 telling them to invent a second member is a bug, not a
   safety feature.
3. **Route the sole-member self-leave into the existing terminal withdrawal
   flow** (the same one behind `POST /groups/:id/state/withdraw`) — chosen.

## Decision

A sole-member `DELETE /groups/:id` **is** a group deletion. One predicate —
`x0x::groups::leave_disposition` — classifies every self-leave into exactly one
of `Proceed`, `LastAdminBlocked`, `PendingJoinBlocked`, `SoleMemberDelete`, and
the REST route resolves it before the secure-plane dispatch so GSS and TreeKEM
groups behave identically. The TreeKEM leave helper consumes the same
predicate and treats a non-`Proceed` outcome at its (unreachable) defense point
as an internal error, never re-emitting a user-facing recovery hint.

- **SoleMemberDelete** (the carve-out amending ADR-0016 §3): the leaver is the
  only non-terminal roster entry (Active or Pending) **and** no join request is
  pending. The leave runs the terminal withdrawal flow — signed withdrawn
  commit, keyless tombstone, `GroupDeleted` propagation, `#333` bounded resend
  armed unconditionally — and answers `{"ok":true,"deleted":...}`, distinct
  from a plain leave's `{"ok":true,"left":...}` so clients can tell the
  outcomes apart. ADR-0016 §3 itself is unchanged for every group with more
  than one member-in-being.
- **Pending joiners block the deletion.** Pending is derived from
  `join_requests` status (the authoritative view), never from the roster's
  seeded Pending mirror — a KEM-less request seeds no roster entry yet its
  joiner is real, and reject/cancel clear the mirror when the request resolves
  so a resolved request can never keep the group undeletable. The sole active
  member with a still-pending request receives a distinct 409: "resolve
  pending join requests before leaving".
- **Sole-member authority is rank-blind at the terminal only.** A legacy
  roster whose only member is a plain `Member` may still withdraw:
  `seal_withdrawal` and terminal apply authorize the sole member-in-being
  regardless of role. The carve-out does not extend to any non-terminal admin
  act — ordinary commits keep the AdminOrHigher requirement.
- **Tombstone visibility.** Deleted groups keep a withdrawn tombstone
  locally. `GET /groups` hides withdrawn records; `GET /groups/:id` serves
  them with `"withdrawn": true`; `GET /groups/discover` deliberately still
  emits withdrawn cards so stale public discovery listings are superseded.

**Two-member race (pre-existing, unfixed):** each daemon evaluates
`leave_disposition` once, on its own roster snapshot. When the last two
members leave concurrently, both observe a non-sole roster, both take the
plain-leave path, and both remove their local record — the group can end up
live with zero members and no anti-resurrection tombstone. The second leave
does **not** convert into a deletion. This race predates this ADR (the old
path merely 409'd one of the two leavers); it is tracked in issue #372 and is
accepted here rather than fixed. Clients discriminate a completed outcome via
the `deleted` vs `left` response field; no force flag is added.

## Consequences

- An empty group is always disposable by its sole member; the ADR-0016 §3
  invariant is untouched for multi-member groups.
- Client UX branches on the response field (`deleted` vs `left`); the GUI
  already toasts "Space deleted" vs "Left space" accordingly.
- Explicit deletion (`POST /groups/:id/state/withdraw`) and sole-member
  deletion share one terminal flow, so key-wipe and propagation semantics
  cannot drift between them.
- The #372 race remains open by decision; closing it requires cross-daemon
  coordination (or a reconciliation sweep) and is out of scope here.

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
