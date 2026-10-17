# T-doctor-json-summary: `x0x doctor --json` health summary

- **Status:** Proposed
- **Target slot:** A14
- **Date:** 2026-10-16
- **Decision owners:** David Irvine
- **Related:** #1382, #1167, #1119 (M1), ADR 0096 §6

## Context

Agents and operators need one local health summary they can parse. The global
`--json` flag already exists. `x0x doctor` ignored it and printed text only.
It also returned success after a failed health probe. M1 (#1167) names
connectivity, key health, store integrity and upgrade state as that summary.
This record sets the CLI contract. It does not change the wire format, the
daemon REST schema, or the upgrade apply path.

## Decision Drivers

- A scripted agent must detect FAIL without scraping text.
- Exit status must match the summary: non-zero only when a check is `fail`.
- Sibling M1 routes (`/health` verdict, `GET /diagnostics/upgrade`) may land
  later; doctor must work with today's endpoints.

## Considered Options

1. Keep text-only doctor and teach agents to scrape labels.
2. Emit JSON from `x0x doctor --json` with four named checks and exit non-zero
   on FAIL.
3. Wait for the full `/health` verdict (#1380) before any CLI JSON.

## Decision

`x0x doctor --json` prints one JSON object:

```json
{
  "ok": true,
  "connectivity": { "status": "ok|warn|fail", "detail": "...", "evidence": {} },
  "key_health": { "status": "ok|warn|fail", "detail": "...", "evidence": {} },
  "store_integrity": { "status": "ok|warn|fail", "detail": "...", "evidence": {} },
  "upgrade": { "status": "ok|warn|fail", "detail": "...", "evidence": {} }
}
```

`evidence` is optional and omitted when absent. `ok` is false when any check
status is `fail`. Warnings alone leave `ok` true and the process exits zero.
A failed check exits non-zero after the JSON is written.

When `--name <instance>` has no `api.port`, doctor still prints this object
with all four checks as `fail` (daemon unreachable). It does not target the
default daemon. The first `/health` probe uses a two-second timeout so a
wedged accept path cannot hold the report for the client default of thirty
seconds.

Current sources (until sibling M1 routes replace them):

| Check | Source | FAIL when | WARN when |
|---|---|---|---|
| connectivity | `GET /health` (2 s timeout) | unreachable, or status not healthy/ok/connected/degraded | status `degraded` |
| key health | `GET /agent` | request fails, or `agent_id` / `machine_id` missing | — |
| store integrity | `GET /stores` | request fails, or any store has `durability_degraded` | — |
| upgrade | `GET /diagnostics/upgrade`, else `GET /upgrade` | failed upgrade *attempt* (M2 / diagnostics apply health) | release *lookup* fails (`ok: false`, HTTP error, or timeout on `/upgrade`) |

Degraded connectivity is `warn`, not `fail`. Today's `GET /upgrade` reports
release lookup only (`update_available`, versions). An available update is
evidence under an `ok` upgrade check and does not fail doctor. A failed
lookup (offline host, GitHub unreachable, monitor error) is `warn` so local
key/store/connectivity health can still exit zero. Text mode uses the same
checks and the same exit rule. The contacts probe from older doctor text is
not part of this four-check summary.

## Consequences

### Positive

- Agents parse one stable object and trust the exit code.
- M2 exit tests can assert a failed upgrade attempt through this surface once
  `/diagnostics/upgrade` exposes apply/rollback health as `fail`.

### Negative / Trade-offs

- Doctor makes up to five GETs per run.
- Until #1381 lands, upgrade evidence comes from `GET /upgrade` lookup only.
  Offline hosts see upgrade `warn`, not `fail`.

### Neutral / Operational

- No change to ant-quic, Cargo pins, upgrade apply code, or the plane gate.

## Validation

Unit tests serialize the report, parse captured JSON stdout as one value, and
assert a non-zero exit (`Err`) when a check fails and when named-instance
discovery has no `api.port`. A hanging `/health` acceptor finishes within the
two-second bound. A failed upgrade lookup is `warn` with exit zero.
`x0x doctor --json` on a healthy mock daemon exits zero with `ok: true`.

## Notes for AI-assisted work

Do not fold this Proposed record in the same PR. Do not edit upgrade apply
code to satisfy this CLI surface.
