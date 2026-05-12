# CI/CD

Five workflows in `.github/workflows/`:

- **ci.yml**: fmt, clippy, nextest, line coverage, doc, API/GUI parity
- **security.yml**: `cargo audit`
- **release.yml**: Multi-platform builds (7 targets), macOS code signing, publishes to crates.io. Also generates `release-manifest.json` and signature for the self-update system (see [`upgrade-system.md`](upgrade-system.md)).
- **build.yml**: PR validation
- **sign-skill.yml**: GPG-signs `SKILL.md`

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
