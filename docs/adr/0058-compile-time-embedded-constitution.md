# ADR 0058: The Constitution Is Embedded Compile-Time in Every Binary

- **Status:** Proposed
- **Date:** 2026-08-29
- **Decision owners:** David Irvine (direction), omp (drafting)
- **Reviewers:** pending
- **Supersedes:** none
- **Superseded by:** none
- **Related:** `docs/api.md` (System section). Backfill record for shipped behavior; the audit flagged it as minor/product.

## Context

`src/constitution.rs` compiles the project Constitution into the shared
library with no deciding ADR: `CONSTITUTION_MD: &str =
include_str!("../CONSTITUTION.md")` (`src/constitution.rs:6-7`), plus
compile-time `CONSTITUTION_VERSION` ("0.91") and `CONSTITUTION_STATUS`
("Draft") (`src/constitution.rs:9-13`). The module is exported from
`src/lib.rs:189-190`, so every binary linking the x0x library carries it.

## Decision Drivers

- Every x0x node should be able to state the principles it runs under,
  offline, with zero configuration.
- Version skew between node and Constitution text must be impossible
  within one build.

## Considered Options

1. Ship `CONSTITUTION.md` as a sidecar data file.
2. Serve it from a website only.
3. `include_str!` into the library, surfaced via API and CLI (chosen).

## Decision

1. The Constitution text, version, and status are compile-time constants
   of the shared library (`src/constitution.rs:6-13`); binaries cannot
   drift from their library.
2. It is surfaced, not computed: `GET /constitution` returns the compiled
   Markdown (`src/server/routes/status.rs:248-254`, routed at
   `src/server/mod.rs:1845-1846`) and `GET /constitution/json` exposes
   text, version, and status (`src/server/routes/status.rs:257-264`); the
   CLI mirrors this via `x0x constitution`
   (`src/bin/x0x.rs:1409-1410`, `src/cli/commands/constitution.rs:3`).
3. The embedded status constant is the source of truth for what stage the
   Constitution is at — currently "Draft" (`src/constitution.rs:13`);
   surfaces must not present it as ratified.

## Consequences

### Positive

- Always-available, version-matched principles on every node; one edit in
  `CONSTITUTION.md` propagates by rebuild.

### Negative / Trade-offs

- Any text change rebuilds every binary; a superseded Constitution in an
  old build stays embedded there.

### Neutral / Operational

- The REST surfaces are documented in `docs/api.md` (System, lines 22-24).

## Validation

- `constitution_is_embedded` test asserting nonempty content
  (`src/constitution.rs:20-24`); route tests for both endpoints.

## Notes for AI-assisted work

AI tools may draft this ADR but must not mark it Accepted without human
review. Accepted ADRs are immutable — supersede, don't edit.
