## Summary

- _What changed and why?_

## Validation

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --all-targets --all-features -- -D warnings`
- [ ] `cargo nextest run --all-features --workspace`

## Coverage

- Current line coverage:
- Delta vs `main`:
- Coverage workstream, if applicable:
- Exclusions added: none / see `docs/coverage-exclusions.md`

## Test Quality Checklist

- [ ] Each new test has a why-named name that states the invariant or regression.
- [ ] No new test is a tautology against the implementation.
- [ ] Each new test checks one business invariant.
- [ ] Assertion failures include enough context to diagnose the broken invariant.
- [ ] Coverage delta is reported from CI or `just coverage-summary`.
- [ ] Any coverage exclusion has a `coverage-skip:` comment and a matching register entry.
