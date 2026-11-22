# CI/CD

The main workflows in `.github/workflows/`:

- **ci.yml**: the slim hosted set on pushes to `main` and on PRs: fmt, clippy, the library unit tests
  (`Test Suite`), inert CI script controls, doc, API/GUI parity, deployment authority, skill token budget
- **ci-full.yml** (`CI (full)`): the heavy suites, nightly on `main` and on `workflow_dispatch`: the full
  workspace Test Suite, the W3-H shards and determinism gate, the released-binary rows, the Linux systemd and
  100k signing acceptances, Windows, and the Coverage Gate
- **security.yml**: `cargo audit` (daily schedule + PRs)
- **release.yml**: Multi-platform builds (7 targets), macOS code signing, publishes to crates.io. Also generates `release-manifest.json` and signature for the self-update system (see [`upgrade-system.md`](upgrade-system.md)).
- **build.yml**: PR validation
- **sign-skill.yml**: GPG-signs `SKILL.md` (manual dispatch)
- **integration.yml**: integration tests on pushes to `main` and on PRs to any base; the soak and timing suites run only on the weekly schedule
- **adr-governance.yml**: ADR checks on PRs touching `docs/adr/**` or `.adr-kit.yaml`
- **claude.yml**: Claude Code responses to issue/PR review comments

## PR CI and main protection (ADR 0087, charter D15)

Recorded in [ADR 0087](adr/0087-repository-and-release-governance.md) (Accepted);
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

## Hosted CI is the slim set

GitHub-hosted runners have 4 vCPUs and 16 GB of RAM. From 13 Nov 2026 the full set in `ci.yml` did not go
green there. The `Test Suite` job stopped with exit 143 ("The runner has received a shutdown signal") while
rustc built the workspace test graph, before any test ran (#1789, run 44976569803). The W3-H shards, the
H-S3-rm rows and the Coverage Gate lost their runners ("lost communication with the server"). The same tree
was green on studio1. The likely cause is memory exhaustion on the runner; the logs end without a
compiler or test error.

- `ci.yml` runs only what fits a hosted runner. Its `Test Suite` job runs the x0x library unit tests
  (`--all-features --lib`) in the isolated namespace, with `--no-fail-fast`. It builds them with the
  `ci-hosted` Cargo profile (no debuginfo, x0x at `opt-level = 0` with 256 codegen units) and adds 12 GB of
  swap. It skips two sets of lib tests:
  - the W3-H cases (`(^|::)w3h_`, the `w3h-gate` default filter). Other unit tests under `src/server/w3h/`
    still run;
  - the tests that took 60 s or more on a hosted runner, named in `X0X_HOSTED_SKIP` in `ci.yml`:
    `evidence_wire::lookup::tests::s4_machine_resolution_work_is_independent_of_registry_size` (459 s),
    `evidence_wire::admission_tests::issue1207_late_readiness_preserves_denials` (76 s) and
    `gossip::pubsub::tests::slice1_pinned_sg_concurrent_publishers_after_maintenance_timers` (62 s).
  Keep this list and `X0X_HOSTED_SKIP` in step.
- Measured on a hosted runner (job 137137607557): the cold `ci-hosted` build took 11m31s with swap near
  zero, and 4,876 of 7,807 tests ran in 786 s. That projects to about 21 min for all of them, or about
  18 min without the skipped slow tests. The test deadline is 2400 s and the job limit is 75 min, at least
  2x the projection.
- The `Inert CI script controls` job runs the script self-tests behind the `ci-full.yml` jobs (W3-H shard
  plan and trace gate, systemd acceptance, M2 signing gate, the #703 proof validator, the Coverage Gate
  step controls) on every PR. They take seconds.
- The studio1 trains run the full suite and are the merge gate.
- `ci-full.yml` runs the heavy jobs nightly on `main` and on `workflow_dispatch` for any branch. They gate
  neither merges nor releases. That includes `Test Suite (Windows)` and the `Coverage Gate`, which no
  longer run on PRs at all.
- The 20 W3-H reruns that D196 (A08) requires for a harness case are not automatic on a PR. Someone must
  dispatch `CI (full)` on the PR branch by hand.
- `integration.yml`, `build.yml` and `security.yml` still run on every PR (ADR 0087 rule 1).
- Every PR workflow cancels an older run for the same PR. Push runs on `main` are never cancelled, so each
  merge commit keeps a terminal `ci.yml` result for the release gate. `ci-full.yml` cancels only an older
  run of the same event on the same ref, so a dispatch never cancels a nightly run.

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
- The gate reads `ci.yml` runs only. A `ci-full.yml` (`CI (full)`) run does
  not gate a release.

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
  `announce-release` in the same workflow runs outside the `release`
  environment on purpose. It reads no secret and signs nothing: it runs the
  promoted x0xd, which relays the manifest that CI already signed, and peers
  accept it only on that signature. The job runs a downloaded binary, so it
  is kept away from the environment's secrets, and its checkout does not
  persist the token.
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

The coverage job (`ci-full.yml`, nightly and on dispatch) runs on Linux with
`cargo-llvm-cov` and `cargo-nextest`.
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
