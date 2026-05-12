# Coverage Exclusions Register

This register is the source of truth for every intentional coverage exclusion.
The default is no exclusions: refactor for testability before adding one.

Current excluded executable lines: 0
Current executable-line budget: less than 2% of executable lines

## Policy

Every exclusion must have both:

- A one-line source comment immediately above the excluded code:
  `// coverage-skip: <one-line reason> (<reviewer initials>, <YYYY-MM-DD>)`
- A row in the register below with the same reason.

Allowed with justification:

- OS-error paths that require fault-injection drivers.
- Defensive impossible-state code whose only purpose is to prove an invariant.
- Generated code, if generated code is added later.

Not allowed:

- REST handler error mapping.
- CLI command paths.
- Public API `Result::Err(_)` paths.

## Register

| File | Lines | Reason | Reviewer | Date |
|---|---:|---|---|---|
| _None_ | - | - | - | - |
