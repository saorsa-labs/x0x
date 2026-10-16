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

`ok` is false when any check status is `fail`. Warnings alone leave `ok`
true and the process exits zero. A failed check exits non-zero after the
JSON is written.

Current sources (until sibling M1 routes replace them):

| Check | Source | FAIL when |
|---|---|---|
| connectivity | `GET /health` | unreachable, or status not healthy/ok/connected/degraded |
| key health | `GET /agent` | request fails, or `agent_id` / `machine_id` missing |
| store integrity | `GET /stores` | request fails, or any store has `durability_degraded` |
| upgrade | `GET /diagnostics/upgrade`, else `GET /upgrade` | request fails, or body `ok: false` |

Degraded connectivity is `warn`, not `fail`. An available update is evidence
under an `ok` upgrade check. Text mode uses the same checks and the same
exit rule.

## Consequences

### Positive

- Agents parse one stable object and trust the exit code.
- M2 exit tests can assert a failed upgrade attempt through this surface.

### Negative / Trade-offs

- Doctor makes up to five GETs per run.
- Until #1381 lands, upgrade evidence comes from `GET /upgrade`.

### Neutral / Operational

- No change to ant-quic, Cargo pins, upgrade apply code, or the plane gate.

## Validation

A unit test serializes the report, parses the JSON, and asserts a non-zero
exit (`Err`) when key health fails. A second case covers an unreachable
daemon. `x0x doctor --json` on a healthy mock daemon exits zero with
`ok: true`.

## Notes for AI-assisted work

Do not fold this Proposed record in the same PR. Do not edit upgrade apply
code to satisfy this CLI surface.
