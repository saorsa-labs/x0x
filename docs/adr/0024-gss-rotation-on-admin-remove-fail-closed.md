# ADR 0024: GSS Rotation on Admin Remove Is Fail-Closed and Seals Before It Persists

- **Status:** Proposed
- **Date:** 2026-07-27
- **Decision owners:** David Irvine
- **Reviewers:** Sam, Dario (author), Watson
- **Supersedes:** none — closes a gap in the legacy GSS plane described by ADR 0010
- **Superseded by:** none
- **Related:** ADR 0010 (GSS before MLS TreeKEM), ADR 0012 (TreeKEM as the default secure-group plane), ADR 0014 (self-leave is a roster removal), ADR 0016 (flat Admin/Member authority), `~/.buzz/PLANS/F1_GSS_ROTATION_SPEC.md` rev 4.2 (581 lines, implementation spec, outside this repo)

All line citations are `src/server/routes/named_groups.rs` unless stated, at
`e3013710d7ed69077de9a799dffdbeb5ac80535a`, `git status --porcelain src/` empty.
The implementation spec lives outside this repository and is mutable; this ADR
therefore carries its own evidence rather than referring to it for load-bearing facts.

**Two coordinate systems.** Code that F1 itself introduced does not exist at the baseline
and cannot be cited there, so every such citation is stamped **at `56d0c4b`** in place —
the F1 implementation commit `56d0c4bc61fbb649042aad8ea42d25d8f0c85c39` on `glm/f1-fix`,
which changes exactly one file, `src/server/routes/named_groups.rs` (+231/-40). **An
unstamped citation is at the baseline.** Because that commit touches no other file, cites
into `src/groups/` resolve identically at either. The +231 lines shift everything below
them, so a `named_groups.rs` number read during implementation review is not the same
number at the baseline and must be translated rather than carried across.

**Citation convention.** Multi-line write sites are cited as **statements** — the full
statement including `.insert(...)`. The ast-grep pattern used for the audit below matches
only the sub-expression ending at `.await`, so the matched expression is one line shorter
than each statement cited here (`:6649-6652` vs `:6649-6653`). Statement ranges are what
a reader needs to find the write; the expression range is an artefact of the instrument.

## Context

On the legacy GSS plane (ADR 0010 — still the plane grandfathered groups run on),
`ban_treekem_group_member` rotates the group shared secret and reseals it to the
survivors, but `remove_named_group_member` does not. **An admin-removed member keeps a
working group secret and can decrypt everything published after the removal.** Removal
and ban differ in outcome for the same authority.

Three properties of the surrounding code shape the fix:

1. **Ban is a partial model.** Its statement order up to `seal_commit` at `:10325` is
   correct and must be followed. Past that line it is the anti-pattern: it commits the
   roster to the map at `:10334`, persists with `save_named_groups` at `:10338`, and only
   then seals per-recipient envelopes — so at `:10349` a survivor with no KEM key can only
   be `warn`ed and skipped. Ban's fail-open is **structural**, a consequence of sealing
   after persistence, not an unchecked return value.
2. **A stranded survivor is invisible to consensus.** `shared_secret` is not one of the
   eight inputs to `compute_state_hash` — its parameter list, `src/groups/state_commit.rs`
   `:219-228`, is group id, revision, prev hash, roster root, policy hash, public meta
   hash, `security_binding`, withdrawn. A member who never receives the new secret keeps a
   matching `state_hash` forever while decrypting nothing. Any convergence-based
   assertion passes on this bug.
3. **Nothing proves that a survivor without a roster KEM key never held the secret.** A
   non-TreeKEM invite stub reaches `shared_secret: Some(..)` with an active roster whose
   `kem_public_key_b64` is `None`: `GroupInfo::with_policy` generates a secret for every
   `MlsEncrypted` group (`src/groups/mod.rs:346-354`, installed by field shorthand at
   `:390`); `invite_join_group_info` (`:7632-7638`) clears it only for TreeKEM
   (`:7656-7658`); and the invite snapshot strips every roster ML-KEM key
   (`src/server/routes/identity.rs:382`, copied at `:7671-7672`). **Stated at exactly the
   strength the evidence carries:** that path proves `shared_secret: Some(..)` and
   `kem_public_key_b64: None` coexist on a reachable state — it does *not* prove that
   particular secret is the live group secret, because `with_policy` generates it locally
   and whether it is ever the authority's is an open question (see the final section). What
   makes the decision is the negative: **no positive enrollment invariant proves a keyless
   survivor never held the live secret**, and fail-closed is the only safe reading of that
   gap.

## Decision Drivers

- A removed member must be unable to decrypt content published at the rotated epoch, on
  both planes — the same claim the gate asserts, stated as the goal rather than the looser
  "loses read access at the moment of removal", which the transport cannot guarantee.
- Silent partial failure is worse than refusal: a stranded survivor is undetectable
  (driver 2 above), an aborted removal is immediately visible to the caller.
- The fix must not reproduce ban's ordering, which makes fail-closed impossible.
- Nothing may write the group secret, or a value derived from it, to a log.
- The record must distinguish what was **proved** from what was **conservatively
  assumed**, so a future optimisation can tell which constraints are load-bearing.

## Considered Options

1. **Mirror ban step for step.** Rejected: reproduces the structural fail-open, and the
   abort would have to undo a persisted save.
2. **Rotate and reseal, fail open on a survivor whose envelope cannot be built** (skip
   them, as ban does). Rejected: strands a member who may hold the secret, undetectably.
3. **Rotate and reseal, fail closed** — build and validate every survivor envelope in
   memory before any commit, persistence or publication; abort the whole removal on the
   first failure. **Chosen.**

## Decision

**D1 — Rotate on remove.** The GSS admin-remove path rotates the group shared secret and
reseals it to every active non-actor survivor, so removal matches ban in effect.

**D2 — Fail closed, for missing and unusable keys alike.** Every survivor envelope is
built and validated in memory before `seal_commit`. On any missing KEM key, unusable key
or seal error the handler bare-returns. Ban's `warn + continue` at `:10349-10355` is not
mirrored. The abort guarantee is stated precisely: `rotate_shared_secret` has *already*
mutated the clone (`next`, `:8478`) by the time the preflight can fail, so the guarantee
is that **no rotation becomes live, persisted or published — the rotated clone is
discarded**, not that nothing was rotated.

**D3 — Ordering is normative, and diverges from ban after `:10325`.** Between `:8481` and
`:8482`: `remove_member` → `is_encrypted` → `rotate_shared_secret` → fallible secret
conversion (D5) → collect active non-actor survivors → **build every envelope** → abort on
any failure → only then `seal_commit` (`:8482`), `named_groups.insert` (`:8494`),
`save_named_groups` (`:8510`), and finally publish the buffered envelopes and the
`MemberRemoved` event (`:8524`). Sealing moves **ahead** of persistence; that inversion is
the whole of D2's mechanism.

**D4 — The preflight needs a side-effect-free builder, not a `#[must_use]`.**
`publish_secure_share` (`:877-929`) seals *and* broadcasts in one async function, so its
`bool` only exists after publication and cannot gate anything. A builder covering
`:888-919` (base64 decode, AAD, KEM seal, event construction) is extracted;
`publish_secure_share` keeps `:920-928` and its current signature for the approval and ban
callers. Every builder input exists before `seal_commit` — the AAD is
`secure_share_aad(group_id, recipient_hex, secret_epoch)` (`:898`), none of whose three
inputs depends on the sealed commit — so this is a pure reordering, not a restructuring.

**D5 — The `Vec<u8>` → `[u8; 32]` conversion is fallible, and never logs its error.**
`rotate_shared_secret` returns `Vec<u8>` (`src/groups/mod.rs:429`) while
`seal_group_secret_to_recipient` requires `&[u8; 32]` (`src/groups/kem_envelope.rs:140-144`).
Both idioms already in the file are silent: ban's `:10313-10316` leaves `sec` as
`[0u8; 32]` and rotates the group onto a known-zero key; approval's guard at `:10880`
falls through to a catch-all that drops the envelope. Neither is acceptable. The
conversion aborts with a 500. `impl TryFrom<Vec<T>> for [T; N]` has `Error = Vec<T>`, so
the error value **is the secret material** — only its length may be read or logged.
Scoped honestly: not a live defect at this commit (`rotate_shared_secret` allocates 32
bytes at `mod.rs:431`), but it is the one failure mode the fail-closed design does not
otherwise cover, because sealing a zero secret *succeeds*. **Scope: D5 binds the remove
path only.** It does not reach ban's `:10313-10316`, which this ADR leaves as it found it;
that surviving instance is recorded under Negative / Trade-offs. D5 must not be read as a
repo-wide property of the conversion.

**D6 — Self-removal is rejected before the membership lock.** A self-targeted remove is
rejected between `:8439` and `:8440`, before the lock at `:8443-8444`. It is not
redirected: `leave_group` (`:9651-9654`) re-acquires the same per-group lock at
`:9663-9664` and `tokio::sync::Mutex` is not reentrant, so a redirect self-deadlocks while
holding that lock. The pre-lock placement also short-circuits a divergence live on the
TreeKEM plane at this commit — `remove_treekem_named_group_member` sets `treekem_epoch`
unconditionally at `:9327` and receivers reject it at `:4956-4958` whenever
`self_leave_auth` holds.

**D7 — The wire stays additive; the apply arm mirrors ban's branch.** `MemberRemoved`
gains `secret_epoch: Option<u64>` with `#[serde(default)]`; only the GSS sender at `:8512`
ever populates it. The apply mutator gains ban's `else if` (`:5247-5254`) at `:4979`:
epoch and `security_binding` are written **unconditionally** and only the secret clear is
gated on strict `<`. Conditioning the `security_binding` write on local secret state would
make two receivers in different local states compute different `state_hash` values for the
same commit — it is a hashed input: the parameter is `state_commit.rs:226` and its
absorption into the hash buffer is `:237` (`:238` absorbs `withdrawn`, a different input).
A step-0 guard rejecting
`self_leave_auth && secret_epoch.is_some()` sits outside the plane split, as the backstop
against a crafted `MemberSelf` commit, which validates by construction
(`state_commit.rs:737`).

**D8 — Availability cost of D2, knowingly accepted.** A group containing any active member
without a roster KEM key cannot remove anyone until that member publishes one. This is
taken deliberately while no positive enrollment invariant exists; the remedy is to publish
the key. If such an invariant is later established, fail-open for the missing-key case
becomes reconsiderable — by a new ADR, not by an implementation change.

**D9 — Lock-contention cost of the preflight, knowingly accepted.** The preflight places N
ML-KEM encapsulations inside the `state.named_groups` **write** guard (acquired `:8459`,
released `:8495`), which is global over every named group, not the per-group membership
lock. Ban pays none of this because its sealing loop runs after `drop(groups)` at `:10337`.
For the duration of one removal every named-group operation on the node serialises behind
it. The work is synchronous — `seal_group_secret_to_recipient` is `pub fn`, not async —
so there is no await inside the guard and no deadlock risk. We take the contention.

**D10 — Do not drop and re-acquire the map lock mid-preflight. Conservative; its necessity
is unproven.** `next` is inserted under the same guard that produced it. This is the rule
D9 is the invoice for: holding the map guard through the preflight is exactly what it
mandates. Recorded as policy, not as a proved requirement — see the audit below. The rule
adds no rollback and no compare-and-swap machinery, and knowingly pays D9's cost. We take
that trade because the failure it forecloses — writing a stale `next` over a concurrent
write — is silent and unrecoverable, while contention is neither. **A future optimisation
that drops the guard needs a fresh audit at that commit plus an explicit
revision/state-hash compare-and-swap, not a lock-gap argument.**

### The audit behind D10, and exactly what it establishes

The membership lock taken at `:8443-8444` is held to the end of the handler, so dropping
the *map* lock mid-preflight is already safe against every writer that also takes the
membership lock. The residual risk class is exactly: **writers that mutate an existing
`GroupInfo` under `named_groups.write()` without the membership lock.**

That class was screened structurally, with ast-grep — the only instrument that sees
multi-line receiver chains:

```bash
sg run --lang rust -p '$STATE.named_groups.write().await' --json=stream src
```

`$STATE` is a metavariable, so it matches any receiver and matches across line breaks.
Note that `range.start.line` in that output is **0-indexed**; every line number here is
the 1-indexed value.

| Figure | Value |
|---|---|
| structural matches under `src/` | 73 |
| of those, in `src/server/routes/named_groups.rs` | 72 |
| the single match elsewhere | `src/server/routes/named_groups/tests/cache_hardening_followup.rs:955` (a test) |
| before the inline `mod tests` (`#[cfg(test)]` `:14002`, `mod tests` `:14003`) | 33 |
| less the `#[cfg(test)]` helper write at `:9832` (fn `:9820-9821`) | **32 production** |
| test-only across `src/` (39 in-module + `:9832` + the file above) | 41 |

**A line grep cannot do this job, and the difference is not cosmetic.** A text pattern
requires receiver and `.write()` on one line, so it sees 49 of the 72 in this file; the
23 it misses are exactly the multi-line chains, three of them production:

| statement | enclosing fn |
|---|---|
| `:6649-6653` | `create_named_group` (`:6466`) |
| `:7845-7849` | `join_group_via_invite` (`:7712`) |
| `:12628-12632` | `persist_treekem_and_named_groups_atomic_with_info` (`:12564`) |

**The enumeration is complete, not merely self-consistent.** The **33 pre-inline-test-module
writes** live in **32** enclosing functions; exactly **14** of those contain no lexical
`group_membership_lock`; one of the 14 is `#[cfg(test)]`; that leaves **13 production
candidates**. (33 is the pre-`mod tests` count and still includes the `#[cfg(test)]` helper
subtracted in the table above — the 32 production figure and the 32 enclosing functions are
different quantities that coincide numerically.)

| fn | decl | write |
|---|---|---|
| `publish_group_card_to_discovery_inner` | `:1006` | `:1018` |
| `store_named_group_info` | `:2062` | `:2067` |
| `apply_recovered_member_key_package_locked` | `:3684` | `:3718` |
| `create_named_group` | `:6466` | `:6649` |
| `add_treekem_named_group_member` | `:8181` | `:8351` |
| `wipe_local_group_crypto_material` | `:8872` | `:8879` |
| `retain_withdrawn_group_tombstone` | `:9008` | `:9018` |
| `drop_local_named_group_state` | `:9036` | `:9045` |
| `leave_treekem_group` | `:9085` | `:9148` |
| `remove_treekem_named_group_member` | `:9177` | `:9314` |
| `ban_treekem_group_member` | `:10416` | `:10539` |
| `approve_treekem_join_request` | `:10966` | `:11129` |
| `persist_treekem_and_named_groups_atomic_with_info` | `:12564` | `:12628` |
| — excluded — `maybe_force_withdrawn_group_for_test` | `:9821` (`#[cfg(test)]` `:9820`) | `:9832` |

Reproduced independently four times (Sam, Dario, Watson, and one further re-derivation).
Sam derived the 13 by hand first; deriving the same 13 from the structural census is what
makes the set **exhaustive** rather than merely agreed.

**Screening result: the residual class is empty at this commit.** All 13
`store_named_group_info` call sites (`:4918, :5051, :5149, :5199, :5301, :5357, :5447,
:5641, :5685, :5722, :5788, :5887, :6253`) take `resolved_group_key`, the key the
serialized apply's guard is acquired on at `:4583-4584`. `create_named_group` is the one
genuinely unlocked map writer and is not a counter-example: it generates a fresh random
32-byte id at `:6470-6474` and inserts under it (`:6649-6653`), so it does not overwrite
existing state in intended execution; a random-id collision would be a different defect
shape, not a basis for this rule.

**Three limits on that negative, stated so it is not over-read:**

- It is a **scoped negative at one commit**: *at `e3013710d7ed69077de9a799dffdbeb5ac80535a`,
  in the production `src` tree, no path was found that mutates an existing named group
  outside that group's membership mutex.* It is not a proven invariant and does not hold
  itself tomorrow. F1 must not silently move the lock boundary on the strength of it.
- The classifier partitioning locked from unlocked is **textual** ("the body contains
  `group_membership_lock`, delimited by the next top-level `fn`"). It reproduces the
  partition exactly; it is **not** proof of lock coverage for the 18 functions marked
  locked — none was checked for locking the *same key*.
- The per-delegate chains (the `_locked` helpers and
  `persist_treekem_and_named_groups_atomic_with_info` running under a parent handler's live
  guard) rest on Sam's call-site work, not re-derived here.

**The justification originally offered for D10 was refuted and is withdrawn.** Group-card
import was put forward as a live writer outside the membership lock; it is not.
`import_group_card` binds a *named* `_membership_guard` at `:11571-11572`, live to the end
of the function, covering both the map write at `:11682` and the `get_mut` refresh at
`:11727`; it is the same lock, since `group_membership_lock` normalises through
`stable_group_id()` (`:4407-4422`) and the stub is inserted under the card's own
`group_id`. The strongest alternative candidate fails too:
`publish_group_card_to_discovery_inner` (`:1006`) takes `get_mut` at `:1019` but its only
`&mut` use is `seal_commit` at `:1027` behind `if reseal` (`:1022`), and its two call sites
are `:992` (`false`) and `:1003` (`true`, inside `publish_group_card_with_reseal`, which
takes the membership lock first at `:1001-1002`). This is recorded as **false** precisely
so a later reader does not rediscover the refutation and delete D10 believing the rule
rested on it. D10 rests on conservatism, and on nothing else.

### The finding that argues hardest for D10

`join_group_via_invite` writes at `:7845` in multi-line form. Every text search in the
review missed it — **and it does take the membership lock**, which is why it correctly
never appeared in the candidate 13. It was invisible and harmless. That is luck, not
method: an invisible write could as easily have been an unlocked existing-group mutator,
and the scoped negative would have been false with three reviewers' sign-off on it. It
surfaced only because a figure flagged as non-blocking was chased anyway. **The next
claim of this shape must be run structurally, not derived from a text search.**

## Consequences

### Positive

- Removal and ban have the same security outcome on the GSS plane: the removed member
  **cannot decrypt content published at the rotated epoch**.
- **No KEM/preflight-induced partial commit is reachable:** either every survivor envelope
  is buildable or the removal aborts. Scoped deliberately to what the preflight proves —
  see the delivery limit under Neutral / Operational.
- Rotation never becomes observable from a failed attempt: the mutation happens on a
  private clone that is dropped.
- **The remove path** can no longer rotate onto an all-zero key through a silent conversion
  (D5). Scoped to the remove path deliberately — see the ban residue under Negative /
  Trade-offs; D5 is not a repo-wide property and this consequence must not be read as one.
- The correctness of D10's evidence is now checkable — the audit's instrument, figures and
  enumeration are recorded, so re-running it is mechanical.

### Negative / Trade-offs

- **Availability (D8):** one active member without a roster KEM key blocks all removals in
  that group until they publish one.
- **The clear predicate and the delivery predicate are not the same predicate, and this
  ADR does not reconcile them.** The receiver clears on an epoch comparison alone —
  `if old_epoch < secret_epoch { next.shared_secret = None }` (`:5052-5054` **at
  `56d0c4b`**, in the arm at `:5048-5055`), which does not consult the receiving node's
  own membership state. The sender selects envelope recipients by roster state:
  `active_members()` minus the actor (`:8602-8606` **at `56d0c4b`**), and `active_members()`
  admits only `GroupMemberState::Active` (`src/groups/mod.rs:1080-1082`,
  `src/groups/member.rs:226-228`). So any node that holds the old secret and is not
  `Active` on the sender's roster clears it and receives no replacement. For `Removed` and
  `Banned` that is the intent. For **`Pending` it is undecided** — D2 is written over
  "survivors" and never states which predicate defines the set. **Nobody has established
  that a `Pending` node can hold the live secret when the event applies**, so this is an
  unexamined reachability and availability risk, not a demonstrated defect; it is recorded
  so the next reader does not have to rediscover it. There is a standing promise in tension
  with it: the approval path's `(None, _)` arm (`:10895-10900`) logs *"requester will
  receive via next rekey"* (`:10898`), and both rekey paths draw from `active_members()`,
  so that promise holds only for a requester who is `Active` when the next rekey runs.
  **Pre-existing, not introduced here:** ban already pairs the same two predicates — it
  clears on the epoch alone at `:5251-5253` (in the arm at `:5247-5254`) and selects
  `remaining_targets` from `active_members()` at `:10317-10320`.
- **D5 is scoped to the remove path; ban's silent zero-fill survives F1 untouched.** At
  ban's `:10313-10316` — the site D5 already cites — the rekey still does
  `let mut sec = [0u8; 32];` and copies only `if sec_vec.len() == 32`, so a wrong-length
  rotation there seals an **all-zero key** with no error, the exact defect D5 closes in
  remove. Out of F1's scope by decision, not by oversight, and recorded here so that D5 is
  not misread as a repo-wide invariant and the surviving instance is not rediscovered as
  new. This bullet is what the Positive consequence on D5 points at.
- **Contention (D9):** N synchronous ML-KEM encapsulations inside the global
  `named_groups` write guard; every named-group operation on the node serialises behind
  one removal.
- **D10 is conservative policy, not a proved requirement.** It may cost more than it buys;
  it stays until someone pays for the compare-and-swap design that would let it go.
- Two documentation contracts must move with the code, or they will mislead the next
  reader: the fail-open guidance at `:870-875` ("log and proceed without the envelope"),
  from which the remove path now departs, and the doc comment at `:11815-11823` claiming
  the legacy GSS rekey path belongs only to the remaining guarded handlers.

### Neutral / Operational

- Rollout is mixed-version by nature: `#[serde(default)]` keeps the wire additive, and old
  receivers ignore `secret_epoch`. Their behaviour is a gate item, not an assumption.
- The abort path is a bare `return` inside the block expression opened at `:8458` — no
  transaction, no rollback machinery. An implementation that builds one has misread D2.
- **Preflight abort status codes are recorded, not decided.** Cited as the three
  `return api_error(...)` statements **at `56d0c4b`**, per the convention stated above: the
  implementation returns **424 FAILED_DEPENDENCY** for a keyless survivor (`:8613-8618`)
  and for a build/seal failure (`:8630-8635`), and **500** for the wrong-length rotated
  secret (`:8593-8596`).
  424 is the honest shape — a dependency the caller can fix (the survivor's published KEM
  key) is absent; 500 is right for the conversion because §2a is unreachable through the
  public API, so reaching it is a server bug rather than a client one. No decision in this
  ADR fixes these, and a future change to them does not require superseding it.
- **What makes both publish orderings work is one conjunct, and it is load-bearing.** The
  clear is gated on *strict* `<` (D7), so an envelope that installed first survives the
  later commit. The reverse ordering — commit first, envelope second at equal epoch —
  works only because the stale-envelope guard is
  `if secret_epoch < info.secret_epoch || (secret_epoch == info.secret_epoch &&
  info.shared_secret.is_some())` (statement `:5831-5835`; the conjunct is `:5832`), whose
  own doc comment (`:5827-5830`) states the intent. That guard is pre-existing and F1 does
  not change it — it is cited at the baseline, and its comment names only a *prior
  `MemberBanned` commit*, because remove had no GSS rotation to produce the same ordering
  when it was written. Tightening that predicate to
  `secret_epoch <= info.secret_epoch` would silently strand every survivor on the
  commit-first ordering: cleared by the commit, then refusing its own replacement, in
  consensus with a matching `state_hash` and decrypting nothing. That is the F1 failure
  re-created by a one-token edit, which is why Validation item 3 must be written to fail
  when the conjunct is deleted rather than merely to exercise both orderings.
- **The preflight bounds construction, not delivery, and this ADR claims nothing beyond
  that.** `publish_named_group_metadata_event` (`:1797-1833`) returns `()` and folds both a
  publish error and a timeout into `tracing::warn!`; the direct path's own doc comment
  (`:1835-1837`) calls its delivery best-effort. So a crash or a failed publish *after* the
  commit has been persisted can still leave a survivor without its envelope. That residue is
  a delivery property of the transport, unchanged by F1 and not addressed here. **No
  validation item reaches it:** Validation item 2 proves survivor decryptability from the
  envelope; neither it nor the publish-attempt oracle proves delivery. Item 4 asserts the
  removed member's non-decryption against the published envelopes; items 2 and 4 test the
  cryptographic behaviour of event objects, not delivery.

## Validation

An F1 runner registered as **`just adr-gates-f1`**, filtering `test(/(^|::)f1_/)` — one
recipe, not a parallel harness. Named explicitly because the base commit's justfile has
**no** `adr-gates` recipe at all (`grep -i adr justfile` at `e3013710d7`: no match), so an
ADR citing that name would point at a command the branch does not add. Every F1 gate's test
function name must begin with `f1_`, and the recipe body must carry this expression
character for character; a recipe filtering differently from this document reintroduces the
same defect one indirection away. Item 5 asserts against the **stored**
`GroupInfo`, never against the discarded clone; item 6 is the load-bearing one, because a
green all-new soak proves nothing about a mixed fleet.

**The expression is not anchored solely at `^`, because nextest's `test()` predicate matches
a test's full path from the crate root and some F1 gates — currently items 3 and 7a — are
nested in-crate unit tests.** A gate in `server::routes::named_groups::tests` is named
`server::routes::named_groups::tests::f1_…`, so a bare `test(/^f1_/)` cannot reach it.
Measured on this repo at the implementation commit `56d0c4b`:
`test(/^server::routes::named_groups::tests::/)` selects 131 tests,
`test(/^named_groups::tests::/)` selects 0, `test(/::named_groups::tests::/)` selects 131.
The `^` branch is retained rather than dropped because this section permits a future F1 gate
to be written as an integration test under `tests/`: such a gate has the unqualified name
`f1_…` with no `::` in it, and `test()` does not see the binary id, so the `::` in
`x0x::f1_whatever` cannot supply one. `test(/::f1_/)` alone would drop it in silence, and
`test(/^f1_/)` alone drops every nested gate. `(^|::)` selects both shapes and admits no
third, since the matched segment must still begin with `f1_`.

A filter fails by selecting **too few** tests, and only one of the two ways of doing that is
caught by the runner. An empty selection is already a hard failure: measured at
cargo-nextest 0.9.126, a filter matching nothing yields `error: no tests to run` and exit
code 4. That measurement was taken in a crate carrying no nextest configuration at all, and
this repo's `.config/nextest.toml` sets no `no-tests` key at `e3013710d7`, `56d0c4b` or this
commit, so nothing checked in overrides it; environment-level overrides were not enumerated
and are not relied on below. A **non-empty subset** is not caught — a filter that
selects some required gates and omits others runs them, passes them, and exits 0. That is
the false green this section must exclude, and it is invisible in a pass/fail split.
Therefore **a receipt for this recipe must state how many tests were selected, and must name
the gate functions that count is made of.** This section fixes no single number and must not
be read as implying one: item 1 states a property every gate has to have rather than naming
a gate of its own, item 7a requires exactly three functions, item 7b requires none because
no gate observes it, and the remaining items each require at least one without fixing how
many. A receipt therefore names the items it discharges — which may be a subset, since items
gain gates as the work lands — and the `f1_` functions discharging them, and the selected
count must equal the length of that list. Below it, the filter dropped a gate, and that is a
failing receipt however green the split. This section is discharged only once every item
requiring a gate has been named across those receipts. Zero is likewise
invalid, but by the runner's own exit code rather than by this rule — and stating the rule
over a per-receipt list rather than over a fixed count keeps it sound both as further items
gain gates and if that runner default is ever configured away.

1. Fails on the pinned pre-fix commit (or on a mutation) and passes on the patched tree.
2. Asserts each surviving member can **decrypt content published at the new epoch** — not
   that its `state_hash` matches. Convergence is the wrong assertion (Context, driver 2):
   it passes on the bug.
3. Exercises both publish orderings, metadata-first and envelope-first, and asserts the new
   secret installs under each.
4. Asserts the removed member's non-decryption against the **published envelopes**, not
   final state: a reseal aimed at the removed member must fail the gate even when the end
   state looks tidy.
5. Covers a missing-KEM survivor **and** a keyed survivor whose seal fails — both assert
   the removal is refused with zero externally visible state change: unchanged
   `secret_epoch` and `shared_secret` in the map, no persisted revision, no published
   envelope or event. Includes the stripped-roster GSS invite state
   (`shared_secret: Some(..)` with `kem_public_key_b64: None`) as a concrete instance.
   This item also gates D3: a ban-shaped implementation that seals after store/save fails
   the persisted-revision assertion even though its final state looks tidy.
6. Mixed-version negative control: an old receiver must reproduce the permanent wedge on
   pre-fix code, and the rollout guard must prevent it.
7. Covers D5, which is unchanged, split by **evidence class**. The two halves are not
   interchangeable and 7a does not subsume 7b: 7a pins the invariant §2a defends, 7b is the
   defence itself and no gate observes it.

   **7a — gate-enforced (producer invariant). Citations in this sub-item are
   `src/groups/mod.rs` at the baseline.** `GroupInfo::rotate_shared_secret` (`:429-437`) is
   the sole production producer of the value §2a converts, and allocates it at `:431`. The
   gate calls that method on a real `GroupInfo` and asserts three linked producer
   properties: the returned secret is 32 bytes; `secret_epoch` advanced by exactly one
   (`:433`); the stored `shared_secret` is the same bytes as the returned one (`:434`). The
   pinning mutation is `vec![0u8; 32]` → `vec![0u8; 31]` at `:431`, and it turns the
   **length** assertion red and only that one — under the mutation the epoch and
   stored-identity assertions still execute and still pass, so they are carried by this
   gate but not pinned by this mutation. **The three properties must therefore sit in three
   separate test functions.** Combined into one, the length assertion panics first and the
   other two never run: the receipt would then show only that "7a turned red" and would
   demonstrate nothing about which assertion the mutation pins, leaving the claim in this
   sub-item unfalsifiable by its own gate. **Three functions are necessary but not
   sufficient**, because `cargo nextest` is fail-fast by default: with no flag it cancels
   the run on the first failure. The repo's `.config/nextest.toml` sets no `fail-fast` key —
   it is byte-identical at the baseline and at `56d0c4b` — so that default governs here.
   That default's effect on the receipt is a race, not a property: fail-fast cancels only
   what is still queued at the instant of failure, so whether either unaffected test is
   omitted depends on scheduling — thread count, ordering, and how long the siblings run.
   In Watson's measured matrix the serial no-flag run stopped after two of three results,
   while in six default-parallel no-flag runs all three tests were already scheduled when
   the failure landed and the complete PASS/PASS/FAIL split survived — and those runs still
   reported `Cancelling due to test failure:`. Both halves are observations of that matrix,
   not guarantees of either scheduling mode. **The split is therefore an
   outcome, not a proof of execution shape — a compliant-looking receipt can be produced
   without the flag**, which is why reporting the split cannot be the criterion. The receipt
   must evidence the invocation. Primary evidence is the exact command, which must contain
   `--no-fail-fast` or be three separate invocations, one per test; corroborating evidence
   is the runner's verbatim output naming all three tests. Verbatim output alone does not
   suffice — it can be excerpted or reformatted, so the absence of `Cancelling due to test
   failure:` is a tell and not a guarantee. If `just adr-gates-f1` is the recorded
   invocation, the recipe body must be quoted beside it so that its `--no-fail-fast` is
   visible; otherwise the recipe silently reintroduces the ambiguity this paragraph exists
   to remove. `--test-threads=1 --no-fail-fast` is the least ambiguous shape, though serial
   execution is not required once the flag is explicit. A separate broken-expectation
   control proves the runner can report red.

   **7b — source-reviewed defence, not a gate. All citations in this sub-item are at
   `56d0c4b` except those naming `src/groups/`, which are at the baseline.** If the 7a
   invariant ever fails despite the gate, the §2a conversion (`:8590-8598`) aborts: its
   `return api_error(...)` statement (`:8593-8596`) precedes `seal_commit` (`:8640`), the
   map insert (`:8651`), persistence (`:8667`) and publication (`:8688`). Between the
   `named_groups.write()` acquisition (`:8548`) and that return, **no live group entry is
   mutated**, and the reason is structural rather than an enumeration: the only handle to
   the entry in that window is the shared reference `info` from `named_groups.get(&id)`
   (`:8549`), through which no mutation is expressible, and the guard is not used again
   until the insert at `:8651`. Two private clones *are* mutated and both are discarded on
   return: the ADR-0016 precheck at `:8563` calls `last_admin_precheck` (`:10169-10175`),
   which delegates to `last_admin_precheck_error` (`src/groups/mod.rs:268-277`) and applies
   the caller's roster mutation to its own `proposed` clone (`src/groups/mod.rs:272-273`);
   the handler then mutates its private `next` clone (`:8567`). So there is no stored,
   persisted or published state for the abort to change. The `Err(v)` arm (`:8592`) binds
   the secret-bearing `Vec` solely to read `v.len()` (`:8595`).
   **No gate observes the abort, the zero state change, or the absence of an all-zero-key
   envelope** — the branch has no production producer that can reach it, and the only ways
   to drive it are a `#[cfg(test)]` hook on `GroupInfo`, a test parameter on
   `rotate_shared_secret`, or moving rotation out of the handler. D5 does not justify that
   production surface. If a future change gives the wrong-length value a real producer, 7b
   becomes a required gate.

**Review triggers.** Re-run the structural audit above, and re-open D10, if any of these
change: a new `named_groups.write()` writer is added, the membership-lock boundary moves,
or a positive enrollment invariant for roster KEM keys is established (which would reopen
D8).

## Open, and deliberately not decided here

Whether the secret `GroupInfo::with_policy` generates for an invite stub
(`src/groups/mod.rs:346-354`, installed at `:390`) is ever the *authority's* secret, or a
locally-random value the joiner can decrypt nothing with. If the latter, the GSS invite
path has a separate and possibly worse defect. It is Sam's finding, it needs its own
record, and it does not change any decision above.

Making D10 a permanent invariant rather than a commit-scoped policy is out of scope: it
requires a revision/state-hash compare-and-swap design, not an audit.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human review**.
Accepted ADRs are immutable: create a new superseding ADR rather than editing an Accepted
ADR. David approved the design this ADR records (F1 spec rev 4.2) on 2026-07-27; the
status flips to Accepted only after Sam's and Watson's review of this file against the
implementation branches.
