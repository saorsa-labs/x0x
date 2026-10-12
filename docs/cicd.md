# CI/CD

Eight workflows in `.github/workflows/`:

- **ci.yml**: fmt, clippy, nextest, line coverage, doc, API/GUI parity, skill token budget
- **security.yml**: `cargo audit` (daily schedule + PRs)
- **release.yml**: Multi-platform builds (7 targets), macOS code signing, publishes to crates.io. Also generates `release-manifest.json` and signature for the self-update system (see [`upgrade-system.md`](upgrade-system.md)).
- **build.yml**: PR validation
- **sign-skill.yml**: GPG-signs `SKILL.md` (manual dispatch)
- **integration.yml**: integration tests on pushes to `main` and on PRs to any base; the soak and timing suites run only on the weekly schedule
- **adr-governance.yml**: ADR checks on PRs touching `docs/adr/**` or `.adr-kit.yaml`
- **claude.yml**: Claude Code responses to issue/PR review comments

## PR CI and main protection (ADR 0087, charter D15)

Recorded in [ADR 0087](adr/0087-repository-and-release-governance.md) (Proposed);
the rulings D04, D05, D15 and D36 are summarised in
[`design/x0x-direction.md`](design/x0x-direction.md).

- `ci.yml`, `build.yml`, `integration.yml` and `security.yml` run on pull requests to **any** base branch,
  so a PR into an integration or stacked branch gets full CI. CI-only mirror PRs to `main` are no longer needed.
  Push-triggered runs are still `main` only.
- `main` is protected by a repository ruleset: changes land only through pull requests, force-push and deletion
  are blocked, and the required checks are `Format Check`, `Clippy Lint`, `Test Suite`, `Documentation` and
  `Build linux-x64-gnu`. There is no bypass.
- The Documentation job runs `python3 scripts/ci/check-skill-size.py` before rustdoc.
  `SKILL.md` must stay at or under 8,000 tokens. Each file in `docs/skill/` must stay at or under 4,000.
  One token is 4 UTF-8 bytes, rounded up. The same step runs `--self-test`, which fails the job
  if an over-budget fixture is accepted.
- `v*` tags can be created, moved or deleted only by repository admins (tag ruleset). Every agent currently acts
  as the `dirvine` admin account, so this and the `release` environment reviewer are procedural gates, not
  technical separation between agents and David (a separate bot identity was declined, D15).

## Release CI Gate (#128)

`release.yml` will not build, sign, or publish any artifact unless the tagged
commit has a **green CI** run. The `require-green-ci` job (first gate, before
`build-release`) queries the CI workflow runs for the tagged SHA via the
GitHub Actions API and fails unless `ci.yml` concluded `success` for that
commit.

- A tag pushed on a commit whose CI failed (or is still running, or was never
  run) cannot ship: `build-release` depends on `require-green-ci`, and the
  entire `sign-release → create-release → publish-*` chain depends on
  `build-release`, so a red/unknown gate blocks every downstream job.
- The gate polls for up to 45 minutes so a CI run still in flight may finish
  before the release proceeds; after that it fails with a clear message.
  (#476: raised from 20 minutes — the Coverage Gate alone now runs longer
  than the old ceiling, which forced a manual rerun on the v0.41.0 tag.)
- `ci.yml` is not triggered by the tag push itself (it gates on branch
  `main`), so the observed run is the one from when the commit was merged.

To exercise it locally, push a scratch `vX.Y.Z` tag on a commit with
intentionally-red CI and confirm `require-green-ci` fails before any artifact
is built; delete the tag/release afterward. (A prerelease-shaped tag such as
`v0.46.0-rc.1` never reaches this gate; see below.)

## Release inputs (v0.46.0 gate row 6)

- **Tags**: only an exact `vMAJOR.MINOR.PATCH` tag can release.
  `validate_release_metadata.py --mode release_tag` refuses prerelease
  (`-rc.1`, `-alpha`) and build-metadata (`+build`) tags in the first job,
  even when Cargo.toml, SKILL.md, and agent.json carry the same suffix.
- **Dependency graph**: `Cargo.lock` is tracked. `resolve-release-lock` fails
  if the lock is missing, untracked, or stale (`cargo metadata --locked`), and
  otherwise captures the committed lock. The release never runs
  `cargo generate-lockfile`, so it ships the graph CI tested on the tagged
  commit.
- **Environment**: `build-release`, `sign-release`, and `create-release` in
  `release.yml`, and `publish-clawhub` and `publish-crates` in
  `publish-promoted-release.yml`, run in the `release` environment, which
  admits only `v*` tag refs. The promotion workflow runs on
  `release: published`, whose ref is `refs/tags/<tag>`.
- `.github/scripts/test_release_metadata.py` asserts all three statically,
  and runs the lock guard against a fixture repository.

## Convergence Release Gate (manual, pre-tag)

`just convergence-release` is the authoritative multi-daemon convergence gate
(10/10 clean runs of `tests/convergence/convergence_soak.py --expect-fixed`,
including the owner-offline checkpoint-recovery and mixed-version skew gates).
It is **not** wired into `release.yml`: it takes on the order of an hour and
requires an authenticated v0.30.1 legacy binary (`X0XD_LEGACY_BINARY`) that
cannot be built from this tree, so it runs manually on the release engineer's
machine **before tagging**. The v0.31.1 external retest flagged that this gate
had not been exercised for that release — treat it as a required pre-tag step
for any release touching the KV/store, CRDT, or gossip planes.

```bash
X0XD_LEGACY_BINARY=/path/to/authentic/x0xd-0.30.1 just convergence-release
```

## Coverage Gate

The CI coverage job runs on Linux with `cargo-llvm-cov` and `cargo-nextest`.
It emits `lcov.info`, uploads it as a workflow artifact, and enforces the
active global floor from `coverage-thresholds.toml`.

Local equivalents:

```bash
just coverage-summary
just coverage-check
```

`coverage-thresholds.toml` also defines advisory per-module targets for the
90% ratchet workstreams. Advisory misses warn in CI; required thresholds fail.
Coverage exclusions must be listed in `docs/coverage-exclusions.md`.

## Local full-suite runs

`cargo nextest` is fail-fast by default: the first failure cancels everything
still queued. On this suite that hides up to ~800 unexecuted tests (observed
2503/3300 and 2885/3300 partial runs during v0.41.1 post-release verification),
which makes an ordinary local run unsuitable as release or flake-triage
evidence. Any run that must prove the whole suite uses:

```bash
just test-full   # cargo nextest run --all-features --workspace --no-fail-fast
```

Test processes run under the `.config/nextest.toml` wrapper, which pins
`X0X_HOME`/`HOME` to a scratch directory; plain `cargo test` bypasses it and
trips the #456 real-home guard, so always drive the suite through nextest.
