# ADR 0057: Local Apps Reach the Daemon via REST/WS with Filesystem Discovery; `serve()` Is the Embedded Form

- **Status:** Proposed
- **Date:** 2026-08-29
- **Decision owners:** David Irvine (direction), omp (drafting)
- **Reviewers:** pending
- **Supersedes:** none
- **Superseded by:** none
- **Related:** ADR-0044 (control plane); ADR-0023 (#110 local history surface); `docs/local-apps.md`; `docs/design/content-store-and-apps.md` (proposal only). Backfill record for shipped behavior.

## Context

Two local-app integration paths exist with no deciding ADR. External apps
discover a running daemon through the filesystem — `<data_dir>/api.port`
and owner-readable `<data_dir>/api-token` — then speak REST/WebSocket
(`docs/local-apps.md:1-13`), exchanging the durable token for a 600 s
session token before browser use (`docs/local-apps.md:29-45`). Embedders
get an in-process API: `serve(config: DaemonConfig) -> ServerHandle`
(`src/server/mod.rs:319-328`), which disables self-update and skips the
startup update check (`src/server/mod.rs:313-318`), completes
data/listener/router setup and publishes `api.port` before returning
(`src/server/mod.rs:331-335,885-961`), and hands lifecycle ownership to
the caller via `ServerHandle` (`src/server/state.rs:159-193`).

## Decision Drivers

- Native/script/web apps on the same machine need zero-config discovery
  and safe auth.
- Embedding x0xd inside another process must not fight the updater or
  own conflicting lifecycle.
- Named instances must stay isolated.

## Considered Options

1. Fixed port + config-file handoff.
2. IPC/Unix sockets.
3. Filesystem discovery (`api.port` + `api-token`) over the standard
   loopback REST/WS plane, plus a first-class embedded `serve()` (chosen).

## Decision

1. Local apps never get a new protocol: they use the ADR-0044 control plane, discovering it via `api.port`/`api-token` files; the durable
   token never appears in URLs (session exchange instead, `docs/local-apps.md:29-45`).
2. Embedded consumers call `server::serve()` instead of spawning `x0xd`;
   embedding disables self-update (`src/server/mod.rs:313-318`) and the
   returned `ServerHandle` owns shutdown (`src/server/state.rs:159-193`).
3. The two-plane bind stays distinct in both forms: HTTP `api_address` (default `127.0.0.1:12700`) vs QUIC `bind_address`
   (`src/server/state.rs:217-226,439-441`); `api.port` always records the
   actual resolved address, including port-zero selection (`src/server/mod.rs:885-961`).
4. Static app hosting (`GET /apps/<name>/<path>` from a content store) is
   **proposal only** (`docs/design/content-store-and-apps.md` — "Status:
   Proposal"; no `/apps` route, `AppManifest`, or `apps_dir` exists in `src/`); it is not part of this decision.

## Consequences

### Positive

- One auth/discovery story for CLI, GUI, and external apps; embedders
  can't brick themselves via the updater.

### Negative / Trade-offs

- Filesystem discovery assumes same-user/same-host trust — the token file
  is the trust boundary.

### Neutral / Operational

- Named instances isolate identity, contacts, groups, and API token
  (`docs/local-apps.md:158-178`).

## Validation

- `serve()` lifecycle tests via `ServerHandle`; api.port publication
  tests in `src/server/mod.rs`.

## Notes for AI-assisted work

AI tools may draft this ADR but must not mark it Accepted without human
review. Accepted ADRs are immutable — supersede, don't edit.
