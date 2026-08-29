# ADR-0016 mechanics — implementation phases & validation lists

> Extracted 2026-08-29 from the immutable [ADR 0016](../adr/0016-role-based-group-authority-flat-admin.md) per the
> 2026-08-23 ADR audit. The ADR remains the complete decision record; the
> sections below are the staged implementation plan and validation inventory
> relocated verbatim so this file is their maintained home — future updates
> belong here, not in the ADR.

## Implementation

Phased; each phase independently shippable.

- **Phase 1 — authority alignment** (absorbs #107 (a) + (c)): delete the
  creator gates and owner special-casing per Decision 1–4; last-admin
  invariant in `validate_apply` + REST pre-checks; legacy-alias evaluation
  (`Owner` ⇒ Admin authority); genesis seeds first Admin; role-assignment
  API restricted to `admin`/`member`; invite issuable by any Admin,
  issued/consumed per-issuer.
- **Phase 2 — KeyPackage distribution** (#107 (b)): carry the target's
  TreeKEM KeyPackage in `MemberAdded` roster propagation so any admin's
  daemon holds the material to commit a removal. Delegated ban is only
  *operational* once this lands; wire shape sketched on the issue first
  (touches the signed commit format).
- **Phase 3 — deterministic committer + race handling**: generalised
  ADR 0014 responsive rekey (lowest active-admin id), rebase-and-retry on
  stale rejection, sibling-commit diagnostics counter.
- **Future (recorded, not planned):** fork-choice rule for equal-revision
  siblings; optional "seal" act if sealed groups ever earn demand; mandate
  layer if two ranks prove too coarse.

---

## Validation

- A promoted Admin can invite, add, remove, ban, change policy, change
  roles, and delete, with commits that validate and converge to all members
  including the actor (the #107 repro passes with B acting).
- No commit sequence — on any path — can produce a non-withdrawn state with
  zero active admins (legacy Owner counted); property test over generated
  commit sequences.
- Historical chains containing `Owner` entries still verify byte-for-byte;
  a legacy Owner can administer unchanged and can self-normalize to Admin
  with one ordinary role commit.
- Role-assignment API rejects `owner`, `moderator`, `guest` with explicit
  errors; rosters render legacy `owner` readably.
- A self-leaver provably cannot read the post-rekey epoch when the
  deterministic committer rekeys (ADR 0014 criterion, re-targeted).
- No production `unwrap`/`expect`/`panic`; fmt + clippy `-D warnings` +
  nextest green.
