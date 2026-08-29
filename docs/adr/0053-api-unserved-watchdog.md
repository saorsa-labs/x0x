# ADR 0053: An API-Unserved Watchdog on a Dedicated Thread Aborts a Wedged Daemon

- **Status:** Proposed
- **Date:** 2026-08-29
- **Decision owners:** David Irvine (direction), omp (drafting)
- **Reviewers:** pending
- **Supersedes:** none
- **Superseded by:** none
- **Related:** issue #384; ADR-0033 (#384-class wedged consumer); `docs/diagnostics.md`. Backfill record for shipped behavior.

## Context

Issue #384 showed a daemon whose listener accepted TCP while `/health`
never answered — a blocked Tokio worker wedging the async runtime.
`src/server/api_watchdog.rs` answers that failure class: a **dedicated
std thread** that survives a fully wedged async runtime
(`src/server/api_watchdog.rs:9-17`), armed after the API listener binds
(`src/server/mod.rs:736-748`).

## Decision Drivers

- A daemon that is up-but-unserving is worse than a crash: supervision
  never fires, gossip peers see a live node.
- The detector must not share the runtime it monitors.
- Self-inflicted downtime from a flaky probe is unacceptable.

## Considered Options

1. In-runtime health task.
2. External liveness prober (systemd/monitor).
3. Dedicated std thread performing its own HTTP probe with a consecutive-
   miss threshold and supervision-aware abort (chosen).

## Decision

1. The watchdog runs on its own std thread (`x0x-api-watchdog`) and probes
   with a raw loopback `GET /health HTTP/1.0` — no async, no client
   library (`src/server/api_watchdog.rs:209-235`); `ProbeOutcome`
   distinguishes `Timeout` — any of connect, write, or read timeout
   (`src/server/api_watchdog.rs:220-247`) — from `Refused`/`Io`/`Served`.
   #384's accepted-but-unanswered listener is one cause of a read
   timeout, not the definition of the class.
2. Defaults: 10 s interval, 3 s connect/read timeout, 3 consecutive
   misses, 90 s startup grace; one success resets the streak
   (`src/server/api_watchdog.rs:43-60,145-165`); shutdown disarms before
   probing (`src/server/api_watchdog.rs:284-296`).
3. On trip: synchronously gather thread-dump summary and gossip stats,
   then abort — but abort is **supervision-aware**: absent explicit
   config it resolves from supervision signals, so terminal-launched
   daemons log-only rather than abort (`src/server/api_watchdog.rs:266-268,
   362-374`). Watchdog thread-spawn failure is best-effort nonfatal
   (`src/server/api_watchdog.rs:325-334`).

## Consequences

### Positive

- Wedged-runtime detection independent of the runtime; crash evidence
  (thread dump) lands in logs before death; unsupervised desktops are never surprise-aborted.

### Negative / Trade-offs

- An abort loses in-flight work by design; the alternative is an
  indefinitely unserved daemon.

### Neutral / Operational

- `[api_watchdog]` TOML config: enabled/interval/timeout/threshold/grace/
  abort_on_stall, per `docs/diagnostics.md`.

## Validation

- `ApiWatchdogMachine` threshold state-machine tests; probe-outcome
  classification tests in `src/server/api_watchdog.rs`.

## Notes for AI-assisted work

AI tools may draft this ADR but must not mark it Accepted without human
review. Accepted ADRs are immutable — supersede, don't edit.
