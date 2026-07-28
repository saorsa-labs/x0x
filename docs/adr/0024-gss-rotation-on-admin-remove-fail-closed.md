# ADR 0024: GSS Rotation on Admin Remove Is Fail-Closed and Seals Before It Persists

- **Status:** Proposed
- **Date:** 2026-07-27
- **Decision owners:** David Irvine
- **Reviewers:** Sam, Dario (author), Watson
- **Supersedes:** none — closes a gap in the legacy GSS plane described by ADR 0010
- **Superseded by:** none
- **Related:** ADR 0010 (GSS before MLS TreeKEM), ADR 0012 (TreeKEM as the
  default secure-group plane), ADR 0014 (self-leave is a roster removal), ADR
  0016 (flat Admin/Member authority), and the governed
  [GSS admin-remove reference chapter](../design/gss-admin-remove-fail-closed.md)

## Summary

On the legacy GSS plane, administrative removal rotates the shared secret and
reseals it to every eligible survivor. All envelopes are built before commit,
persistence, or publication; any preflight failure discards the rotated clone.
The additive wire change and pre-lock self-removal refusal knowingly trade
availability and lock contention for a fail-closed boundary.

## Context

Ban rotated the GSS secret while administrative remove did not, so a removed
member could decrypt later content. Sealing after persistence can also strand
a survivor after the new epoch is live. State-hash convergence cannot see that
failure, and no enrollment invariant proves a keyless survivor never held the
live secret.

## Decision Drivers

- A removed member must not decrypt content published at the rotated epoch.
- A visible refusal is safer than an undetectably stranded survivor.
- No failed preflight may make a rotation live, persistent, or published.
- Secret material and values derived from it must never be logged.
- Proven constraints and conservative policy must remain distinguishable.

## Considered Options

Mirroring ban is rejected because its seal-after-persist ordering is
structurally fail-open. Skipping a survivor whose envelope cannot be built is
rejected because that survivor may hold the live secret. We choose complete
in-memory preflight followed by one fail-closed commit path.

## Decision

1. **Rotate on remove.** Reseal the new GSS secret to every active non-actor
   survivor.
2. **Fail closed.** Build and validate all survivor envelopes before commit,
   persistence, or publication. Missing or unusable keys, seal failures, and
   invalid secret lengths discard the private clone.
3. **Ordering is normative.** Removal and rotation precede preflight; preflight
   precedes `seal_commit`; commit precedes map insertion and persistence;
   buffered envelopes and `MemberRemoved` publish last. Preflight uses a
   side-effect-free builder.
4. **Conversion is non-disclosing.** The `Vec<u8>` to `[u8; 32]` conversion is
   fallible and never logs its secret-bearing error. This binds remove, not ban.
5. **Self-removal is refused before locking.** It is not redirected while the
   membership lock is held.
6. **The wire remains additive.** `MemberRemoved` carries a defaulted optional
   GSS epoch. Epoch and binding update unconditionally; secret clearing uses
   strict epoch ordering; a GSS epoch on self-leave is rejected.
7. **Availability is traded for confidentiality.** A keyless active survivor
   blocks removal until publishing a key. Relaxation needs a superseding ADR.
8. **Hold the map lock through preflight.** Dropping it requires a fresh writer
   audit and explicit revision or state-hash compare-and-swap.

## Consequences

Removal and ban gain the same intended GSS confidentiality outcome, and
preflight cannot partially commit. The cost is refusal for keyless survivors
and global named-group serialization during preflight. Construction, not
transport delivery, is guaranteed; ban's zero-fill residue remains out of
scope. Clear and recipient-selection predicates differ, leaving pending-member
reachability unresolved rather than declared defective.

## Validation

Every control must be shown to fail when its own source is run against the
production code at `e3013710d7ed69077de9a799dffdbeb5ac80535a`, or against a
declared mutation satisfying the break-disclosure requirement below, and to
pass on the patched tree.

Acceptance requires independent controls showing that:

- a survivor decrypts content published at the rotated epoch;
- both metadata-first and envelope-first delivery orderings install the new
  secret;
- the removed member is excluded from published survivor envelopes and its
  retained secret cannot open new-epoch content;
- missing-key and seal-failure preflights leave stored, persisted, and
  published state unchanged;
- an old receiver reproduces the mixed-version wedge and rollout prevents it;
  and
- the rotated-secret producer preserves its length, epoch, and stored-value
  invariants.

**Break disclosure — required of every control in this section.**

Resolves at: `e3013710d7ed69077de9a799dffdbeb5ac80535a`

A control is evidence only against the ways of breaking that someone named.
Mutation-redness does not establish that a control observes its property: the
metadata-first and envelope-first delivery controls are mutation-red on the
`src/server/routes/named_groups.rs:5832` conjunct and were still blind to the
survivor being removed alongside the victim, because that break was never on
anyone's list. So each control must be accompanied by a list of the breaks
considered, and for each either **the mutation that makes the control fail, an
assertion or precondition in the control that refuses the path, or a statement
that the control does not observe that break and why that is accepted.** A
refusing precondition ranks with a mutation and is often the honest form: a
control asserting an exact plaintext already cannot pass on any error exit,
and demanding a bespoke mutation per exit would buy ceremony rather than
evidence. This is a requirement to disclose, not a prohibition on assertions:
a rule forbidding any assertion a broken property could still produce would
forbid the length assertion on the rotated-secret producer, which still yields
32 if rotation breaks by returning a constant.

A list drawn from the author's imagination fails the same way the controls do
— an author names the breaks their control already catches. The minimum content
is therefore mechanical: **name the target operation and the observation the
control makes of it, then enumerate from the source every control-flow exit or
alternate dispatch between the control's entry point and that operation which
could bypass or substitute for it — explicit returns, `?` propagation,
`let`-`else` bindings, `match` and `if` arms, and returns from delegated
handlers — and account for each.** A scan for `return` is a floor, not a
completeness proof; the `secure_group_decrypt` handler ends in a tail `match`,
whose arms exit the handler without an explicit `return`. The endpoint of that
path is the code that performs the property, not the code that reads its
inputs.

Runner, receipt, mutation, and gate-mapping mechanisms live in the
[reference chapter](../design/gss-admin-remove-fail-closed.md). As recorded on
2026-07-27, survivor decryptability and removed-member exclusion block
acceptance; abort and mixed-version controls remain required follow-up.
Acceptance with follow-up outstanding is not full validation discharge.

## Grounding

### G-001 — Remove and ban had different confidentiality outcomes

Resolves at: `e3013710d7ed69077de9a799dffdbeb5ac80535a`

Supports: Context and Decisions 1 through 3.

In `src/server/routes/named_groups.rs`, ban seals its commit at `:10325`, stores
the roster at `:10334`, persists at `:10338`, and only then attempts survivor
envelopes at `:10349-10355`. The administrative remove path did not rotate and
reseal. This establishes both the confidentiality gap and why ban's later
ordering is not a fail-closed template.

### G-002 — Convergence cannot detect a stranded secret holder

Resolves at: `e3013710d7ed69077de9a799dffdbeb5ac80535a`

Supports: Context and Decision 2.

`src/groups/state_commit.rs:219-228` enumerates the state-hash inputs without
`shared_secret`. A survivor can therefore retain a matching `state_hash` while
lacking the new secret. Convergence is not a valid oracle for survivor
decryptability.

### G-003 — A keyless state is reachable and no contrary invariant was found

Resolves at: `e3013710d7ed69077de9a799dffdbeb5ac80535a`

Supports: Context and Decision 7.

`GroupInfo::with_policy` creates a secret for encrypted groups
(`src/groups/mod.rs:346-354`, installed at `src/groups/mod.rs:390`), while the
non-TreeKEM invite path clears it only for TreeKEM
(`src/server/routes/named_groups.rs:7632-7638` and `:7656-7658`) and the invite
snapshot strips roster ML-KEM keys (`src/server/routes/identity.rs:382`, copied
at `src/server/routes/named_groups.rs:7671-7672`). This proves that
`shared_secret: Some(..)` and a missing roster KEM key can coexist; it does not
prove that locally generated secret is the authority's live secret.

### G-004 — The conservative lock rule was screened, not proved

Resolves at: `e3013710d7ed69077de9a799dffdbeb5ac80535a`

Supports: Decision 8.

A syntax-aware census found 73 `named_groups.write()` expressions under
`src/`, including 32 production writes before the inline test module. The
review reduced the writers without a lexical membership-lock reference to 13
production candidates and found no path mutating an existing named group
outside that group's membership mutex. The negative is commit-scoped and its
classifier is textual; it is evidence for caution, not a permanent invariant.
The complete audit and reproduction command are retained in the reference
chapter.

### G-005 — The landed implementation demonstrates the preflight boundary

Resolves at: `56d0c4bc61fbb649042aad8ea42d25d8f0c85c39`

Supports: Decisions 2 through 6 and Consequences.

In `src/server/routes/named_groups.rs`, the wrong-length conversion aborts at
`:8590-8598` before `seal_commit` (`:8640`), map insertion (`:8651`),
persistence (`:8667`), and publication (`:8688`). The survivor set is selected
at `:8602-8606`, and preflight failures return before the sealed commit becomes
live. These observations establish the boundary; they do not prove delivery
after persistence.

## Open, and deliberately not decided here

Whether the secret generated for a non-TreeKEM invite stub is ever the
authority's live secret remains open. Making the map-lock rule permanent also
remains out of scope; that requires a compare-and-swap design rather than a
commit-scoped audit.

## Notes for AI-assisted work

AI tools may help draft this ADR, but must not mark it Accepted without human
review. Accepted ADRs are immutable; a later decision requires a superseding
ADR. The detailed reference chapter remains mutable under this decision.
