# ACP harness placement — local-first acceptance (#512)

**Owner:** Tester
**Product PR:** [#512](https://github.com/saorsa-labs/x0x/pull/512) `fix(discovery): prevent ACP owner-machine pins without bypassing pairing`
**Current tip reviewed:** `f1418a0898194b692061c1bf219cb83d74746899` — prevention and restored pairing source reviewed CLEAN. **HOLD:** authenticated identity-ingest regression evidence remains pending; the new helper-only pairing test does not guard the original caller bypass.
**This document:** local-only user-acceptance brief. Does **not** implement product fixes. Does **not** amend Accepted [ADR-0039](../adr/0039-agent-harness-boundary.md) or [ADR-0043](../adr/0043-agent-key-move-protocol.md).

**Gate:** this slice provides an offline oracle, not live acceptance. G3 remains unaccepted pending review of authenticated identity-ingest evidence on the exact corrected #512 tip. External Tester claims without retained status/body captures are not acceptance evidence. No Ben Mac / production mesh.

Matrix row: [reliability-acceptance-scenarios.md § G](reliability-acceptance-scenarios.md#g-acp-harness-placement-512). Offline oracle: [`reliability-s1-acp-harness-placement-smoke.sh`](reliability-s1-acp-harness-placement-smoke.sh).

## Problem

ACP-attached harnesses generate their own machine key (`~/.saorsa-keys/…`). Lazy `GET /owner/placement` → `move_mint_placements` used to **sign an epoch-0 pin to the owner daemon machine** when discovery had not seen the harness yet. ADR-0043 ingest then dropped identity announces from the real harness machine (`Pinned(owner) ≠ announce.machine`). Machine beats have no pairing gate, so replicas kept a fresh machine record with `agent_ids: []`. Local self-announce still bound (gate skipped). Field symptom (saorsa-ops `harness-ping`): QUIC/machine present, ACP agent id absent.

[#512](https://github.com/saorsa-labs/x0x/pull/512) @ `833bfe86` tried:

1. Skip minting ACP agents until discovery knows their harness machine (the intended narrow correction).
2. **Fail-open `PlacementPinned`** on inbound identity announces when the owner journal says ACP (already-minted wrong pins).

HOLD P1 on (2): the exception accepts **every** `PlacementPinned` denial whenever any matching local journal line has `mode=Acp`. It is not limited to a demonstrably wrong epoch-0 fallback pin. A legitimately owner-pinned ACP agent announcing from a third unrevoked machine would pass ingest. The predicate is also unsound as hosting-mode authority: `OwnerSyncService::apply_journal_line` materializes **all** synced issuance records as `mode=Acp`, **including Riders**. Accepted ADR-0039 keeps ACP agents `Pinned` to **their** machine. Accepted ADR-0043 requires rejecting non-pinned-machine identity announcements when a qualifying placement is cached.

The corrected `f1418a0` **removes the identity-ingest bypass** and **defers minting when the machine is absent or zero**. The API represents deferral by omission from a successful ledger response, not a new `pending` wire enum. That **prevents new bad records**. It does **not** repair existing ones. The move ceremony is not automatic recovery (source export needs the agent key on the recorded source, which the wrongly pinned owner daemon may never have possessed). Do not replace the bypass with cache deletion or an epoch-0 heuristic. Any repair of existing pins needs a Proposed ADR.

## ADRs (unchanged)

| ADR | Binding constraint |
|---|---|
| [ADR-0039](../adr/0039-agent-harness-boundary.md) | ACP-attached: always `Pinned` to **its** machine. Home/delegation policy is **mode-agnostic**. `OwnerIssuedCert.mode` is not placement authority. |
| [ADR-0043](../adr/0043-agent-key-move-protocol.md) | Placement ledger + pairing enforcement. Announce ingest rejects a pinned agent announcing from a non-pinned machine when a qualifying record is cached. Repair placement only through authenticated owner-controlled ledger state. |
| [ADR-0037](../adr/0037-agent-placement-and-key-custody.md) | ACP-harness agents are always `Pinned` — the harness process is the key custodian. |

## Status

| Surface | Status |
|---|---|
| G1–G6 scenario text | Ready (this brief + matrix § G) |
| Offline S1 fixtures / `--self-test` | Ready now (no daemon, no mesh) |
| Live single-host dual-daemon (G3) | **Unaccepted** — corrected source at `f1418a0`; authenticated listener regression and retained live evidence still required. No Ben Mac. |
| Silent repair of existing bad pins | **Out of scope** (G6). Do not claim it. |

## Scenarios G1–G6

Observe via CLI / REST on isolated named local instances: explicit disposable `identity_dir` and data directories, loopback, empty bootstrap peers and disabled persistent peer cache, mDNS and UPnP. A shared `network_id` alone is not network isolation. Assemble one observational snapshot and retain the underlying HTTP captures (without tokens):

```json
{
  "ledger_capture": {"method": "GET", "path": "/owner/placement", "http_status": 200,
    "body": {"ok": true, "placements": []}},
  "agent_id": "…",
  "owner_machine_id": "…",
  "placement": {"kind": "pending", "machine_id": null},
  "journal_mode": "acp",
  "harness_machine": null
}
```

`ledger_capture` must preserve the actual successful durable-owner `GET /owner/placement` response after issuance (and again after discovery). The abbreviated empty `placements` above illustrates pending only. For a pinned snapshot retain its actual ledger row, including `agent_id`, `kind`, `pinned_machine`, and `epoch`; the oracle checks it agrees with the assembled pin. This hand-built format is not a product wire response or cryptographic attestation.

G1 maps to `placement.kind=pending` only after HTTP 200, `body.ok=true`, a valid `placements` array, and **no row for this agent**. Also require no pin and an explicitly observed absent harness (`null`) or a valid machine observation whose `agent_ids` array excludes this agent. Preserve the observation showing absence; missing or malformed captures are inconclusive. A per-agent 404 alone proves neither that mint ran nor that prevention worked.

Sources when live evidence is collected: `GET /owner/placement` / `GET /owner/agents/:id/placement` (`kind`, `pinned_machine`, `epoch`); identity / health for `owner_machine_id`; `GET /machines/discovered/:id` / `x0x machines get` for `agent_ids`.

| ID | Scenario | Steps (product path) | Acceptance (PASS) | FAIL signature |
|---|---|---|---|---|
| G1 | Defer mint until harness machine known | Issue ACP cert; trigger `GET /owner/placement` **before** harness announce/discovery and retain status/body | Successful ledger capture omits agent; normalize to pending with no pin/binding; **no** epoch-0 `Pinned(owner)` | Epoch-0 pin to owner machine while harness unknown |
| G2 | After discovery, pin = harness ≠ owner | Harness announces; trigger `GET /owner/placement` again; read ledger + `machines get` | `Pinned(harness_machine)`; `harness ≠ owner`; `agent_ids` contains ACP id | Still `Pinned(owner)` and/or `agent_ids: []` |
| G3 | Second local daemon binds agent | Second isolated named instance on the same test `network_id`; observe presence / `agent_ids` | Replica machine record lists the ACP id | Replica `agent_ids: []` while QUIC/machine present |
| G4 | Intentional/current pin still enforced | Pin ACP to machine X (epoch ≥ 0, including later epochs); announce from unrevoked machine Y; journal may say `mode=Acp` | `PlacementPinned` **denies**; Y must **not** bind solely because journal `mode=Acp` | Ingest accepts Y and `agent_ids` gains the ACP id on Y (**P1** @ `833bfe86`) |
| G5 | Synced Rider issuance must not inherit ACP fail-open | Sync / apply a Rider journal line (materializes `mode=Acp`); Rider or ACP pin still current; announce from wrong machine | Pairing gate still enforces the pin. Synced `mode=Acp` is **not** a waiver | Fail-open because synced line is `Acp` |
| G6 | No silent repair of existing bad pins | Inspect a pre-existing epoch-0 `Pinned(owner)` ACP record after upgrade | Docs/product do **not** claim auto-heal. Recovery needs an authenticated, auditable transition (Proposed ADR). Do not delete cache / guess epoch-0 | “Upgrade fixed old pins” without a ledger transition |

G4 regressions the HOLD asked for: intentional/current pin, later placement epoch, third unrevoked machine, and a synced Rider issuance (G5) — not merely asserting a fail-open branch.

## Offline S1 oracle

[`reliability-s1-acp-harness-placement-smoke.sh`](reliability-s1-acp-harness-placement-smoke.sh) `--self-test` / `--fixture <name>` over [`reliability-s1-acp-fixtures/`](reliability-s1-acp-fixtures/).

Classifier (one snapshot; no daemon):

- **PASS (0):** `Pinned` to harness machine **≠** owner **and** `harness_machine.agent_ids` contains `agent_id`. **Or** pending/unbound with no pin or harness bind **and** a successful lazy-mint ledger capture omitting this agent (G1). All PASS results require consistent ledger evidence.
- **FAIL (1):** `Pinned` to **owner** with valid empty `agent_ids` or an explicitly absent harness (current hole). **Or** agent bound on a machine that is **not** the pin (wrong-machine / `mode=Acp` fail-open — never PASS).
- **INCONCLUSIVE (3):** missing/error ledger capture, missing `placement` or required ids, malformed binding evidence, contradictory pending/pin observations, or any other unclassifiable shape.

Required fixtures:

| name | expected |
|---|---|
| `pass-pin-harness-machine` | 0 |
| `pass-pending-unknown-harness` / `pass-pending-known-empty-binding` | 0 |
| `inconclusive-pending-*` (missing/error/contradictory evidence controls) | 3 |
| `fail-pinned-to-owner-empty-agent-ids` | 1 |
| `inconclusive-missing-placement` | 3 |
| `fail-open-wrong-machine-must-not-pass` | 1 |

## Live dual-daemon outline (not yet accepted)

Do **not** run against unsafe `833bfe86`. Review the corrected tip and its real listener regression first; use exact binary/source identities and retain observations. This outline has not been executed by the offline oracle:

1. Two (or three) **named local** instances: `owner`, `harness` (ACP key under a distinct data dir), optional `replica`. Use the complete isolation settings above and a shared test `network_id`. **Not** Ben Mac, not public discovery.
2. Owner issues ACP cert for the harness public key (`x0x owner agents issue` / `POST /owner/agents/issue`).
3. **G1:** invoke durable-owner `GET /owner/placement` **before** the harness is discovered. Retain HTTP status and complete body; require 200/`ok=true` and no placement row for this agent. Only then normalize to pending/no pin. `GET /owner/agents/:id/placement` is an optional read-only cross-check: its 404 alone is not a mint trigger or PASS.
4. Start harness daemon; announce; invoke `GET /owner/placement` again and retain its response. **G2:** pin `machine_id` = harness ≠ owner; `x0x machines get <harness>` `agent_ids` contains the ACP id.
5. **G3:** on the replica instance, presence / discovered machine `agent_ids` contains the ACP id.
6. **G4:** owner-signed pin to machine X (including a later epoch); announce from Y; expect `PlacementPinned` even if journal `mode=Acp`.
7. **G5:** apply a synced Rider issuance line; repeat a wrong-machine announce; pin still enforced.
8. **G6:** if an old `Pinned(owner)` record exists, record it; do not claim the upgrade repaired it.

Feed a hand-built snapshot to the oracle with `--classify-snapshot <file>` (same schema as the fixtures). Live fetching is not implemented; self-test results prove only this oracle.

## Out of scope

- Product patches on #512 / #507 / #508 / #509
- Weakening ADR-0043 pairing or inventing `mode=Acp` waivers
- Nextest budget / retry changes (#510 harness risk)
- Merge / self-approve / release from this docs slice
