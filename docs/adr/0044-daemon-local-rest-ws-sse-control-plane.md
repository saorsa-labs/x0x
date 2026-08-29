# ADR 0044: The Daemon Exposes a Loopback REST + WebSocket + SSE Control Plane

- **Status:** Proposed
- **Date:** 2026-08-29
- **Decision owners:** David Irvine (direction), omp (drafting)
- **Reviewers:** pending
- **Supersedes:** none
- **Superseded by:** none
- **Related:** `docs/api.md`; issue #127 (WS workstream); ADR-0023 (history/SSE seam); ADR-0036 (profile/agent routes). Backfill record for a decision already shipped in code.

## Context

x0xd grew an HTTP control surface with no ADR: REST endpoints, WebSocket
sessions, and SSE event streams behind one axum router and one auth
middleware (`src/server/mod.rs:1637-1866`). The API binds loopback by
default (`127.0.0.1:12700`, `src/server/state.rs:439-440`) but accepts a
configured non-loopback address with a loud bearer-only warning
(`src/server/mod.rs:614-629`). Two token classes exist: durable API tokens
and short-lived session tokens.

## Decision Drivers

- Local clients (CLI, GUI, local apps) need a synchronous control surface
  distinct from the QUIC gossip plane.
- Browsers cannot put bearer headers on WebSocket/SSE query strings safely;
  durable secrets must not appear in URLs.
- One authorization model should cover every route and channel.

## Considered Options

1. Unix-domain-socket-only API.
2. Loopback HTTP with per-route auth schemes.
3. Loopback HTTP, one middleware, two token classes, three channel roles (chosen).

## Decision

1. The daemon control plane is HTTP on `api_address`, default
   `127.0.0.1:12700` (`src/server/state.rs:439-440`), separate from the QUIC
   `bind_address`. Non-loopback binds are permitted but warned as bearer-only (`src/server/mod.rs:614-629`).
2. Three channel roles: REST for request/response, WebSocket (`/ws`,
   `/ws/direct`, `src/server/mod.rs:1834-1836`) for bidirectional sessions,
   and SSE (`/events`, `/presence/events`, `/peers/events`, `src/server/sse.rs:27-30`) for server-to-client streams.
3. Two token classes (`src/server/auth.rs:31-35`): durable bearer tokens
   accepted everywhere, and 10-minute session tokens (`SESSION_TOKEN_TTL`,
   `src/server/auth.rs:247-249`) minted only by durable tokens
   (`src/server/auth.rs:151-171`); sessions are stored as SHA-256 digests
   (`src/server/auth.rs:251-288`). Query-string tokens are allowed only on `/ws` and `/events` (`src/server/auth.rs:178-190`).
4. All routes share `auth_middleware`; CORS accepts only literal loopback origins (`src/server/auth.rs:192-224`).
5. The serving API is reusable in-process: embedded callers may `serve()`
   the same router, with self-update disabled (`src/server/mod.rs:313-318`).

## Consequences

### Positive

- One auth story for every surface; durable secrets never enter URLs.
- Browsers get SSE/WS without protocol extension; CLIs get plain REST.

### Negative / Trade-offs

- Non-loopback exposure rests on bearer tokens alone — no rate limiting,
  no TLS; operators must treat the warning seriously.

### Neutral / Operational

- `docs/api.md` is the user-facing map; `src/api/mod.rs` is the canonical
  endpoint registry the api_manifest tests enforce.

## Validation

- `api_manifest` gates (`tests` binary `api_manifest`): every endpoint has
  a CLI name, names unique, manifest matches registry.
- Auth behavior covered by the `src/server/auth.rs` session-minting and
  query-token restrictions (issue #127 / WS1.6 references in-file).

## Notes for AI-assisted work

AI tools may draft this ADR but must not mark it Accepted without human
review. Accepted ADRs are immutable — supersede, don't edit.
