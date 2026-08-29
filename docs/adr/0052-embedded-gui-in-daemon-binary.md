# ADR 0052: The GUI Is a Compile-Time-Embedded HTML Asset Served by the Daemon

- **Status:** Proposed
- **Date:** 2026-08-29
- **Decision owners:** David Irvine (direction), omp (drafting)
- **Reviewers:** pending
- **Supersedes:** none
- **Superseded by:** none
- **Related:** ADR-0044 (control plane); `src/bin/gui_coverage.rs`. Backfill record for shipped behavior.

## Context

The web GUI ships inside the daemon binary with no deciding ADR. The
single-file asset (`src/gui/x0x-gui.html`, 289,762 bytes at HEAD — the
2026-08-23 audit's "276 KB" figure is stale) is embedded with
`include_str!` (`GUI_HTML`, `src/server/ws.rs:997`) and served by
`serve_gui()` at `GET /gui` and `/gui/` under the standard bearer-token
middleware (`src/server/mod.rs:1847-1869`), with a token-injection marker
replaced before serving (`src/server/ws.rs:1004-1006`).

## Decision Drivers

- `x0xd` must be a single self-contained binary: no asset directory, no
  separate GUI server, no packaging step.
- The GUI is a first-class API client; its endpoint coverage must be
  enforced, not assumed.

## Considered Options

1. External static files served from a data directory.
2. Separate GUI binary/process.
3. Compile-time `include_str!` of one HTML file, served from the existing
   authenticated router (chosen).

## Decision

1. The GUI is exactly one HTML asset embedded at compile time
   (`src/server/ws.rs:997`); there is no runtime asset path and no second
   listener. It is served under the same auth as every route
   (`src/server/mod.rs:1856-1869`).
2. Endpoint coverage is gated by `src/bin/gui_coverage.rs`: every GUI
   `api(...)` call is compared against `api::ENDPOINTS`, unknown GUI paths
   fail the check, and coverage must meet a 95.0% threshold
   (`src/bin/gui_coverage.rs:16-18,392-425`).
3. The coverage denominator excludes only the 17 whitelisted entries in
   `src/gui/coverage-whitelist.txt` — deliberately non-`api(...)`
   surfaces (WS/SSE/event routes, superseded REST pub/sub, aliases,
   self-mount, shutdown, Home navigation), with the whitelist itself
   reviewed rather than grown silently.

## Consequences

### Positive

- Zero-deployment GUI always version-matched to its API; the coverage
  gate makes UI/API drift a build failure.

### Negative / Trade-offs

- Every GUI change rebuilds the binary; a ~290 KB string sits in every
  binary whether or not the GUI is used.

### Neutral / Operational

- The whitelist is the lever for deliberate exclusions; each entry is a
  recorded decision to not call that endpoint from the GUI JS layer.

## Validation

- `cargo run --bin gui_coverage` (threshold 95.0%); `GET /gui` auth tests
  in the server suite.

## Notes for AI-assisted work

AI tools may draft this ADR but must not mark it Accepted without human
review. Accepted ADRs are immutable — supersede, don't edit.
