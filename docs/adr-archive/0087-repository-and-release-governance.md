# ADR 0087: Repository and Release Governance: Protected Main, Admin-Only Release Tags, a Reviewed Release Environment, and ADRs Before Code

<!-- File name: docs/adr/0087-repository-and-release-governance.md -->

- **Status:** Accepted
- **Accepted:** 2026-09-30 by David Irvine (accepted as written, including the "dependency change" definition in rule 8 and rule 4's requirement that release-workflow changes are merged by David; status change applied by Claude at his instruction)
- **Date:** 2026-09-30
- **Decision owners:** David Irvine (decisions D04, D05, D15 and D36, and
  the ADR process rule from the 2026-09-30 design health check; acceptance),
  Claude (drafting)
- **Reviewers:** cross-model review pending (arranged before acceptance);
  David Irvine (acceptance)
- **Supersedes:** none
- **Superseded by:** none
- **Amends:** [ADR 0025](./0025-required-gates-prove-observation-completeness.md)
  (merge-gate enforcement: which checks are required on `main`, and how that
  is enforced). ADR 0025 itself is unedited.
- **Goal served:** process governance and goal **M** (self-sustaining). Every
  node applies a signed release on first sight (ADR 0045), so the path from
  merge to signed release is the security boundary for the whole network. It
  supports the proposed R12 (D20: x0x is maintained by its own agents). It
  serves none of R1–R11 directly: it is a fix to shipped merge and release
  behaviour and records deployment governance, which ADR 0072 rule 5 and the
  pre-promotion moratorium both admit.
- **Related:** [`docs/cicd.md`](../cicd.md) (the maintained description of
  the workflows and protections);
  [`docs/design/x0x-direction.md`](../design/x0x-direction.md) (rulings D04,
  D05, D15, D29, D32 and D36; invariants I9 and I11); ADR 0025; ADR 0026;
  ADR 0045; ADR 0061; ADR 0069 and ADR 0084 (records accepted after their
  code); ADR 0086 and ADR 0093 (accepted hours after their code merged);
  #1061 (SKILL.md signing gated on the environment; `cargo publish
  --locked`); `.github/workflows/release.yml`,
  `.github/workflows/publish-promoted-release.yml`,
  `.github/workflows/sign-skill.yml`, `.github/scripts/test_release_metadata.py`,
  `scripts/adr-governance.py`.

## Context

- **What every node runs is decided by the release pipeline.** Under
  ADR 0045 every enabled node applies a signed release on first sight. There
  is no staged rollout or supervised rollback yet (Track M-safety, ADR 0094
  prov.), so a signed release reaches the whole network within minutes. What
  merges to `main`, which commit is tagged, which dependency graph is built,
  and who approves signing are therefore network-wide security decisions.
- **What the pipeline allowed before these rulings:**
  - CI ran only on pull requests to `main`. Work stacked on integration
    branches got CI only through CI-only "mirror" PRs to `main`; 80 of 235
    PRs in one period were mirrors.
  - `main` had no protection: a direct push or force-push was possible.
  - Anyone with write access could create or move a `v*` tag, and a tag
    triggers the release workflow.
  - `Cargo.lock` was gitignored, and the release job re-resolved the
    dependency graph with `cargo generate-lockfile`. The `--locked` builds
    then locked a graph CI had never tested, so a new upstream publish could
    change the shipped bytes with no x0x change.
  - Release tags could carry prerelease suffixes, while the self-update
    listener ignores `include_prereleases`.
  - Signing and publishing ran with no human approval step.
- **One identity.** Every agent working on this repository acts through the
  single admin account. A separate bot identity for agents was considered and
  declined (D15). Any control keyed on identity therefore cannot separate an
  agent from David: such controls are procedural. This ADR says so rather
  than implying technical separation.
- **ADR drift.** ADRs were accepted after the code they govern had merged:
  ADR 0084 retroactively for #1044, ADR 0086 about three hours after #1059,
  ADR 0093 about four hours after #1064 (with its text edited to match the
  code), and ADR 0069 as a record. Two PR bodies misstated what shipped. The
  repository rule ("a Proposed ADR before the code merges") did not say when
  acceptance must happen, and nothing distinguished a record of shipped
  behaviour from a decision.
- **Lost findings.** Review findings on merged PRs stayed in PR threads with
  no tracker entry. The 2026-09-30 design health check found several that
  were still untracked.

## Decision Drivers

- Released bytes equal the graph CI tested (invariant I11).
- A human approves anything every node will apply.
- Integration and stacked branches get the same CI as `main`, with no mirror
  PRs.
- For changes that older peers or later readers cannot undo (wire,
  protocol, dependency), the decision exists before the code does.
- No review finding is lost after merge.
- Be honest about which gates are technical and which are procedural.

## Considered Options

1. **Conventions only** (the status quo before these rulings). Rejected: every
   failure listed in Context happened under it.
2. **Repository rulesets, a protected release environment and a tracked
   lock, with agents acting as the admin account (chosen).** The protections
   stop accidents, force every promotion through an explicit and logged
   approval, and make released bytes reproducible. Identity-keyed gates are
   procedural.
3. **Option 2 plus a separate bot identity for agents** with narrower
   permissions, so identity-keyed gates become technical. Declined by David
   Irvine (D15). It remains the route to technical separation if procedural
   gates prove insufficient.
4. **Threshold or offline release signing now.** Deferred. The protected
   environment is the minimum protection for v0.46.0 (D05); threshold or
   offline signing stays open and is decided before goal M's owner update
   policy (M4).

## Decision

We will govern the repository and the release pipeline as follows.

1. **CI on every pull-request base (D15).** `ci.yml`, `build.yml`,
   `integration.yml` and `security.yml` run on pull requests to any base
   branch. Push-triggered runs stay `main`-only. CI-only mirror PRs are
   retired.
2. **`main` ruleset (D15).** `main` changes only through pull requests;
   force-push and deletion are blocked; the required status checks are
   `Format Check`, `Clippy Lint`, `Test Suite`, `Documentation` and
   `Build linux-x64-gnu`. The ruleset has **no bypass actors**, so it binds
   the admin account too. A required check is a merge gate. It is not a claim
   that ADR 0025's comprehensive observation-completeness gate is met.
   Changing the required list is a governance change: it is recorded in
   `docs/cicd.md` in the same PR that changes it, and read back afterwards.
3. **Admin-only release tags (D15).** Creating, moving or deleting a
   `refs/tags/v*` tag is restricted to repository admins by a tag ruleset.
   Only David promotes a release.
4. **No bot identity (D15).** Agents act as the admin account. Rules 3 and 5
   are therefore procedural for agents, and agents follow them as rules:
   - an agent never creates, moves or deletes a `v*` tag, and never approves
     a `release` environment deployment, unless David has instructed that
     specific action;
   - changes to the release workflows (`release.yml`,
     `publish-promoted-release.yml`, `sign-skill.yml`) are merged by David
     (E-D13).
5. **Protected `release` environment (D05).** The jobs that build, sign,
   create and publish a release (`build-release`, `sign-release` and
   `create-release` in `release.yml`; `publish-clawhub` and `publish-crates`
   in `publish-promoted-release.yml`) and ad-hoc SKILL.md signing
   (`sign-skill.yml`, #1061) run in the GitHub `release` environment. The
   environment admits only `v*` tag refs and requires David's approval for
   every deployment. Every job that reads a signing or publishing secret runs
   in that environment. `cargo publish` runs with `--locked`.
6. **Released bytes are the tested graph (D04).** `Cargo.lock` is tracked on
   `main`. `resolve-release-lock` refuses a missing, untracked or stale lock
   (`cargo metadata --locked`) and never runs `cargo generate-lockfile`;
   release builds run `--locked`. The exact pins on `ant-quic` and the
   `saorsa-gossip-*` crates are kept. A dependency moves only through a
   reviewed PR that changes the lock.
7. **Prerelease tags are refused (D04, D03).** Only an exact
   `vMAJOR.MINOR.PATCH` tag can release: the first job refuses prerelease
   (`-rc.1`, `-alpha`) and build-metadata (`+build`) tags. No GitHub
   prerelease is published until a signed release channel exists (goal M,
   M2).
8. **ADRs before code.** Two rules apply together; the second adds to the
   first and never replaces it.
   - **Proposed on `main` before any merge.** A change to a network
     behaviour, a storage format, a protocol or a security bound has a
     **Proposed** ADR on `main` before its code merges to **any** branch,
     integration and stacked branches included (the charter's §5 ADR
     invariant, unchanged). The same holds for the other changes the
     repository's ADR rule covers (architecture, crypto, public APIs,
     operational invariants).
   - **Accepted before `main`.** In addition, a change to the wire format, a
     network protocol, or the dependency set has its ADR **Accepted before
     the code merges to `main`**. Code may sit on an integration branch
     under a Proposed ADR, but it does not reach `main` until the ADR is
     Accepted. Here a "dependency change" means a new dependency, or a pin
     change that alters network behaviour, a persisted format or a security
     bound; a routine lock refresh or patch bump that changes none of these
     is not one.
   - An ADR written after the fact to record behaviour that has already
     shipped uses the status **`Accepted (record)`**, states what it records
     and the ruling that accepted it, and is not a precedent for skipping
     rule 8. The ADR governance check reads the leading word (`Accepted`), so
     no tooling change is needed.
   - Only David marks an ADR Accepted. Accepted ADRs are immutable: a change
     is a new ADR that amends or supersedes, or a README erratum for a
     factual correction that changes no decision. Holding further
     implementation of an Accepted ADR is a recorded decision, not a status
     change (D28); holds, parks and pending supersessions are recorded in the
     status overlay of `docs/adr/README.md`.
9. **Review findings are tracked (D36).** Every review finding on a merged PR,
   from a human, a cross-model reviewer or a bot, becomes an issue or a
   written dismissal with its reason on the PR within 24 hours of the merge
   or of the finding, whichever is later.

**Out of scope.** The managed-deployment half of the provisional scope first
planned for this number (the sealed testnet on dedicated hosts, and the
deployment drop-in inventory; D14, amending ADR 0026) records operations
rather than repository governance, and is left to its own ADR.

## Consequences

### Positive

- The bytes a node applies are the bytes CI tested at the tagged commit, and
  a new upstream publish can no longer change a release (or break a fresh CI
  resolve) without a reviewed lock change.
- Every release, and every signature every node will trust, passes an
  explicit, logged approval by David.
- Integration and stacked branches get full CI, so mirror PRs and the
  retargeting traps they caused go away.
- No ADR-governed change reaches any branch without a Proposed ADR on
  `main`, and decisions that cannot be undone once peers see them are
  Accepted before the code reaches `main`. Records of shipped behaviour are
  labelled as records.
- Review findings on merged code reach the tracker instead of being lost.

### Negative / Trade-offs

- Rules 3, 4 and 5 rely on agent discipline, because agents hold the admin
  credential. A mistaken or compromised agent session could still tag or
  approve. The mitigation is the rule itself, the audit trail, and option 3
  if that proves insufficient.
- Releases wait for David's approval, and release-workflow changes wait for
  his merge.
- An urgent fix that changes the wire, a protocol or the dependency set waits
  for an accepted ADR. In practice the ADR is drafted alongside the fix.
- Dependency updates are explicit lock PRs rather than implicit resolves.
- The 24-hour findings rule adds tracker work after every merge.

### Neutral / Operational

- `docs/cicd.md` remains the maintained description of workflows, required
  checks and the environment. The ruleset names cite this ADR.
- When a previous-release fixture job (a checked-in `data_dir` from the prior
  release, invariant I9) exists and is stable, adding it to the required
  checks is expected. It is not required today because no such job exists.
- Release-signing custody beyond the environment (threshold or offline
  signing) is still open (option 4).

## Validation

- **Readback of the protections**, after any change and at each release:
  - `gh api repos/saorsa-labs/x0x/rulesets` lists an active `main` ruleset
    with the five required contexts above, pull-request-only changes,
    deletion and non-fast-forward blocked, and **no bypass actors**; and an
    active tag ruleset on `refs/tags/v*` restricting creation, update and
    deletion to the admin role.
  - `gh api repos/saorsa-labs/x0x/environments/release` shows David as the
    required reviewer and a deployment policy limited to `v*` tags.
- **Static checks in CI.** `.github/scripts/test_release_metadata.py` asserts
  that the five release build, sign, create and publish jobs run in the
  `release` environment, runs the lock guard against a fixture repository,
  and asserts that prerelease and build-metadata tags are refused. It does
  not yet cover `sign-skill.yml`; extending it to every job that reads a
  signing or publishing secret is a follow-up.
- **Negative controls.** An intentionally failing PR cannot merge to `main`
  (ADR 0025 rule 5). A pushed `vX.Y.Z-rc.N` tag fails in the first release
  job before anything is built.
- **ADR ordering audit at each release.** For every ADR-governed change in
  the release, the governing ADR was Proposed on `main` before the first
  merge of its code to any branch. For every wire, protocol or dependency
  change, the ADR's acceptance date is also on or before the date its code
  merged to `main`. Any exception carries the `Accepted (record)` status and
  is listed in the release notes.
- **Findings audit at each release.** Every review finding on a PR merged in
  the cycle links to an issue or a written dismissal.
- **Review triggers.** Revisit this ADR if an agent tags, approves a
  deployment or merges a release-workflow change without instruction; if a
  separate agent identity becomes practical; or before goal M's owner update
  policy (M4), when release-signing custody is decided.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without
human review**. Accepted ADRs are immutable: create a new superseding ADR
rather than editing an Accepted ADR.
