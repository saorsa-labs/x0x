# T-health-verdict-v1: the `/health` structured verdict and delivery probe

- **Status:** Proposed
- **Target slot:** A14
- **Date:** 2026-10-19
- **Decision owners:** David Irvine
- **Related:** #1380, #1119 (M1), ADR 0096 §6, #600, #262, #1419, #288

## Context

`GET /health` answered liveness only. `status: healthy|degraded` came from peer
counts, so a node could serve HTTP while its delivery pipeline was wedged
(#288), its disk filled, or an upgrade attempt failed. M1 (#1119) asks for one
verdict an operator and an agent can parse. This record governs that schema
and its probe. The schema is a public API surface. Only David accepts this
record.

## Decision

`GET /health` stays auth-exempt and serves one additive `verdict` object.
`verdict.verdict` is `ok`, `degraded`, or `error`. `degraded` means at least
one input degraded, or a stale sample. `error` means the node cannot do its
job: a missing agent or machine identity, or under 64 MiB free on the
data-dir filesystem. The outer `ok` stays `true` while the process answers;
it is the watchdog liveness signal. The legacy `status` and
`degraded_reason` fields keep their peer-only semantics. The schema is
additive only: a client must ignore unknown fields.

The verdict reports counts, booleans and classifications only. It must not
report agent or machine ids, a custom plane id, seed addresses, or the upgrade
repository.

`verdict.inputs` carries ten badges, each `ok`, `degraded` or `error`:

- `plane` — an open plane (`network_id = ""`) degrades: isolation is off.
- `peers` — the #262/#1419 classification behind legacy `status`.
- `seed_reachable` — `connected` of `configured` seeds, measured from the
  connection table the node holds, not from a counter the join path never
  updates. Zero of N past the 120 s grace degrades.
- `send_failure_rate` — at least 5 publishes in the last 60 s with a failure
  rate of 0.5 or more degrades. Under 5 attempts the rate is `null`.
- `delivery_probe` — the last completed probe decides; a failure degrades.
- `recv_pump_shed` — any shed control frame or full-queue drop in 60 s
  degrades.
- `disk` — under 1 GiB free degrades; under 64 MiB is `error`.
- `log` — 50 or more ERROR events in 60 s degrades.
- `identity` — a missing agent or machine identity is `error`.
- `upgrade` — a staged handoff or the `UPGRADE_FAILED` artifact degrades. An
  available update stays `ok`.

`verdict.sample_age_secs` states the sample's age. Past 15 s the
overall verdict degrades with a staleness reason. A sample that never arrived
ages from process start. Peer counts, uptime and probe results are read live
at serve time, so a stalled sampler cannot hide a probe failure.

The probe: every 30 s the daemon publishes one signed frame on
`x0x.health.probe.v1` — a fixed magic prefix plus 16 random bytes, unique
per round. The first probe runs 10 s after start. The whole round trip,
publish included, must return the same payload through this daemon's own
subscription within 5 s. The probe records only its own outcome. It sends
no ids and no addresses.

The handler stays O(1) and lock-free over transport state (#600). A 5 s
refresher samples every expensive input off the request path.

## Consequences

A monitor can page on `degraded` and parse the reason. Probe traffic stays
below presence-beacon traffic. `error` is reserved; most faults degrade.

## Alternatives

Keep liveness only, or put the verdict on an authed endpoint. Both leave the
monitor blind to what hid #288 and the NYC bootstrap outage.

## Validation

`src/server/health_verdict.rs` and `src/server/routes/status.rs` hold the
classifier, probe and merge, with regression tests per input, for the probe
deadline, the join-path seed count and the stalled refresher.
