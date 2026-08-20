# ADR 0016: Role-Based Group Authority — Flat Admin/Member, Retiring `Owner`

- Status: Accepted (2026-06-11)
- Date: 2026-06-11
- Amends: [ADR 0014](./0014-treekem-self-leave-owner-driven-rekey.md) — the
  single-writer rekey discipline survives, with "the owner" generalised to "a
  deterministic committer among active admins". Resolves ADR 0014 open
  question 1 (permanently-absent owner).
- Relates to: [ADR 0012](./0012-treekem-default-secure-groups.md) (TreeKEM
  secure groups), issue #107 (creator-routed administration), PR #88 review
  (checkpoint authority / dueling commits).
- Origin: design proposal by @JimCollinson on #107 (comment 4682770966),
  ground-truthed against `main` @ `5f086cf`; adopted here with the
  refinements in "Decision".

## Context

Issue #107 showed that the signed state-commit chain and the runtime disagree
about who may administer a `private_secure` named group. `validate_apply`
(`src/groups/state_commit.rs`) defines role-based authority — add/remove/ban/
approve are `AdminOrHigher` — but the daemon retains **five literal
creator-identity gates** (invite, add-member ×2, remove-member ×2 in
`src/bin/x0xd.rs`), an **`OwnerOnly` action class** with three apply sites
(`GroupDeleted`, `PolicyUpdated`, role-change-of-admin), a **`require_owner`**
REST helper, **four "cannot ban/remove owner|creator" special cases**, a
**two-tier role-change matrix** (an Admin may not touch an Admin; enforced
separately on the REST and gossip-apply paths), and a
**`400 ownership transfer not supported yet`** stub. Net effect: a promoted
Admin still cannot administer the group; every membership mutation routes
through the creating daemon, which is a single administrative point of
failure.

The triage call on #107 was already: **the signed state chain is the
contract**; the creator gates are the bugs; invites are admission/routing
handles, not authority declarations. The remaining question was the shape of
the role model itself. The proposal adopted here argues that a special
`Owner` is not needed at all, and that x0x should define ranks only for acts
x0x itself must validate. Its state machine asks exactly one question — *may
this signer mutate the roster or the group?* — and that question needs
exactly two answers.

Precedents: MLS (RFC 9420) ships no roles at all and leaves authorization to
the application; Signal groups run flat Admin+Member in production at scale,
with mutually-demotable admins and no special creator. Matrix's 2025 move in
the opposite direction (undemotable room creators, MSC4289) defends huge
public federated rooms against state-*resolution* takeovers — concurrent
power-level events merged across servers. x0x's strictly linear signed chain
admits no merges and enforces invariants per-commit, so that motivation does
not transfer.

## Decision

1. **Authority is decided by role on the committed roster** (`ctx.members_v2`
   in `validate_apply`, the committed *parent* state) at validate time —
   never by comparison with `GroupInfo.creator`. The five creator gates, both
   sites of the two-tier role matrix, and the receive-path creator checks are
   deleted and replaced with the existing role lookup.

2. **Retire `Owner`: flat `Admin` + `Member`.** Every former `OwnerOnly` act
   (`GroupDeleted`, `PolicyUpdated`, role-change-of-admin) becomes
   `AdminOrHigher`. `require_owner` is deleted. Any Admin may promote,
   demote, remove, ban, change policy, invite, or delete. **Admin is root
   for the group** — the security boundary is promotion into the role, and
   documentation must say so plainly. Richer gradations (moderators,
   figurehead owners, quorums, consented deletion) are application-layer
   constructs built by reading ranks from the signed roster; if the network
   ever needs protocol-level richness, the path is a signed **mandate layer**
   above the chain, never another rank inside it.

3. **Last-admin invariant.** A new check in `validate_apply` rejects any
   commit whose **post-mutation, non-withdrawn** state contains zero active
   members of rank ≥ Admin (legacy `Owner` counts as Admin). Enforced
   apply-side on every path (REST and gossip) so no delivery route bypasses
   it; REST handlers add friendly pre-checks. Group deletion (`withdrawn`)
   is exempt — deletion is an ordinary admin act and is the last admin's
   exit valve. The last admin cannot self-demote or self-leave; they promote
   a successor or delete. This one invariant replaces "cannot ban owner",
   "cannot remove creator" (×2 paths), and the protected-founder idea.

4. **Ownership transfer dissolves** (#107 item (d)). With no special Owner
   there is nothing to transfer: promoting someone to Admin *is* granting
   full administration; demoting yourself *is* relinquishing it. The 400
   stub is removed; requests to assign the `owner` role return a clear
   "legacy role; assign admin instead" error.

5. **Invites are admission/routing handles**, signable by any Admin; the
   roster commit is the authority record. The joiner's
   `GroupInfo.creator` seeding from `invite.inviter` stops mattering for
   authority (no act consults it); it is corrected to provenance derived
   from the seeded base state / genesis as part of the cleanup, not by
   trusting unsigned invite metadata.

6. **Single-writer rekey discipline survives (ADR 0014, generalised).**
   Role-based authority does not repeal the dueling-commit history. For
   TreeKEM-bound commits:
   - **Involuntary remove/ban:** the initiating admin commits the rekey (it
     already authors the removal — matches the PR #88 checkpoint
     mitigation).
   - **Responsive rekey after self-leave:** the **lowest active-admin
     agent-id at the leave revision** is the deterministic committer; other
     admins hold off. Lazy catch-up on that admin's next online pass, as in
     ADR 0014.
   - This **resolves ADR 0014 open question 1**: if the designated committer
     is permanently gone, any other admin removes them from the roster, and
     the responsibility re-derives over the new admin set. A
     permanently-absent `Owner` froze PCS forever; a flat admin set is
     self-healing.

7. **Concurrency is exposed, not solved, by this ADR.** The chain check
   already serialises per replica: a commit must extend the current
   `state_hash`, and stale commits (including any pre-signed by a
   since-demoted admin) are rejected. What it does not give is convergence
   when two admins concurrently sign different commits over the same parent
   — different replicas may accept different winners. Mitigations adopted
   now: TreeKEM-bound commits stay single-committer (point 6); REST-initiated
   metadata commits that lose the race get **rebase-and-retry** (refresh
   head, re-validate, re-sign); equal-revision sibling detection (same
   revision, different `state_hash`) is surfaced in diagnostics rather than
   silently dropped. A deterministic fork-choice rule (e.g. lowest
   `state_hash` wins at equal revision, with bounded rollback/re-apply) is
   **future work**, recorded as the one genuine protocol question under
   #107 — out of scope here because it requires state rollback machinery,
   and creator-routing's removal makes the race *possible*, not *common*,
   in the small admin sets this model recommends.

8. **Migration without rewriting history.**
   - Stored roster entries are never rewritten: `role_byte` feeds
     `roster_root` which feeds `state_hash`; rewriting `Owner`→`Admin` on
     read would break verification of historical chains.
   - `GroupRole::Owner` remains in the enum (serde `"owner"`, `as_u8` 0) as
     a **legacy alias evaluated as Admin-equivalent at validation time**. No
     API path may assign it.
   - New groups seed the creator as the ordinary **first Admin**
     (`GroupMember::new_owner` genesis call sites change; the constructor
     itself may be kept for legacy-roster tests).
   - An optional, ordinary `MemberRoleUpdated` **normalization commit**
     (owner self-demotes to admin) can retire legacy entries group-by-group
     later; never required.
   - `Moderator` and `Guest` stay as **reserved, non-assignable** variants
     (their serde names and `role_byte` values are wire/hash-stable, so
     deleting them is riskier than parking them). The role-assignment API
     accepts exactly `admin` and `member`. `Guest`'s imagined read-only
     semantics are cryptographically unenforceable on a shared symmetric
     secret; `Moderator` is application vocabulary.
   - `GroupGenesis.creator_agent_id` stays: it feeds `derive_group_id` and
     is **history, not authority**. Audit fields (`added_by`, `removed_by`)
     stay as provenance.

## Security properties

- **The trade-off, stated plainly:** admins can demote or remove each other;
  there is no protected founder. The group's safety rests on "only promote
  identities you trust with full administration" — the same trust the
  current model demands of the one creator, extended to each promotion
  decision instead of frozen at genesis. A hostile admin who commits first
  wins races (chain order decides). The flat answer is to keep the admin set
  small whatever the member count; a fully-mediated topology (Admin held
  only by the application's own instances) is expressible without protocol
  change.
- **What is given up:** an unimpeachable recovery anchor against admin
  compromise (the Matrix MSC4289 concern). Accepted: x0x groups are private
  and invite-only on a linear chain; if large open communities become a
  target, the additive path is the mandate layer, not a resurrected Owner.
- **What is not weakened:** the signed-chain validation pipeline (group-id →
  structure/signature → revision monotonicity → `prev_state_hash` chain →
  withdrawal terminality → authority) is untouched except for a simpler
  authority step plus the last-admin invariant. Demoted admins cannot author
  valid commits against any later state. FS/PCS mechanics are exactly
  ADR 0014's, with a deterministic committer instead of a privileged one.
- **Restricting deletion is ceremony without safety:** a hostile admin can
  empty a group member-by-member via bans, so a delete restriction stops no
  attack. Deletion stays an ordinary admin act.

## Consequences

### Positive
- Net **deletion**: 5 creator gates, `OwnerOnly` + 3 apply sites,
  `require_owner`, 4 ban/remove special cases, the two-tier role matrix
  (both enforcement sites), the ownership-transfer stub, and `new_owner`
  genesis — replaced by one role lookup and one invariant.
- #107 items (a), (c), (d) are resolved or dissolved by this design; Jim's
  "true creator propagation" question on item (a) becomes moot (no act is
  creator-gated, so a mis-seeded `creator` cannot mis-validate anything).
- Two-human-co-administrator groups — impossible today — become trivial.
- Integrators get a minimal, queryable rank substrate; richer permission
  models compose above (existence proof: the #107 reporter's application).

### Negative / cost
- Mutually-demotable admins; no founder recovery anchor (accepted above).
- The equal-revision fork question is now reachable in principle (point 7);
  it was previously masked by creator-routing, not absent.
- Docs must be blunt that Admin = group root, and that application roles
  must not be mapped onto x0x Admin casually.

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

## Open questions

1. **External observers of the `owner` role string.** The GUI, CLI output,
   and `docs/api-reference.md` surface role values. Alias-now /
   normalize-later keeps `"owner"` readable indefinitely; audit those
   surfaces in Phase 1 so none *requires* an owner to exist.
2. **Fork-choice for equal-revision siblings** (Decision 7) — deliberately
   deferred; needs rollback machinery and its own ADR when prioritised.
