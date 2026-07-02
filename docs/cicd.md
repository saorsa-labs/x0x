# CI/CD

Five workflows in `.github/workflows/`:

- **ci.yml**: fmt, clippy, nextest, line coverage, doc, API/GUI parity
- **security.yml**: `cargo audit`
- **release.yml**: Multi-platform builds (7 targets), macOS code signing, publishes to crates.io. Also generates `release-manifest.json` and signature for the self-update system (see [`upgrade-system.md`](upgrade-system.md)).
- **build.yml**: PR validation
- **sign-skill.yml**: GPG-signs `SKILL.md`

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
- The gate polls for up to 20 minutes so a CI run still in flight may finish
  before the release proceeds; after that it fails with a clear message.
- `ci.yml` is not triggered by the tag push itself (it gates on branch
  `main`), so the observed run is the one from when the commit was merged.

To exercise it locally, push a scratch tag on a commit with intentionally-red
CI (e.g. a draft/prerelease) and confirm `require-green-ci` fails before any
artifact is built; delete the tag/release afterward.

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
