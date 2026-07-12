# Convergence Soak Harness

Repeatable, in-repo version of the external three-machine (macOS + 2 WAN
droplets) convergence test of v0.30.1 that exposed restart-recovery,
claim-semantics, and signed-store defects. It spins N (default 3) local
`x0xd` instances that bootstrap **only to each other** and drives the same
five scenarios with independent gates, per-primitive (TaskList vs KV)
arrival timing, and per-phase gossip-diagnostics deltas. It exists to
verify the fixes for those defects and to keep them fixed.

Python 3 stdlib only (`urllib`, never curl — curl is intercepted in some
environments).

## Running

```bash
cargo build --release --bin x0xd     # or set X0XD_TEST_BINARY
just convergence-soak-quick          # 1 run, ~3 min
just convergence-soak                # 10 runs (soak)
just convergence-soak 5              # custom run count

# Direct invocation with custom gates:
python3 tests/convergence/convergence_soak.py \
    --runs 10 --nodes 3 --live-gate 60 --expect-fixed
```

Logs, per-run `report.json`, an aggregate `report.json`, and `summary.txt`
land under `tests/convergence/out/<timestamp>/` (gitignored). Data dirs of
failing runs are kept for debugging; passing runs are cleaned unless
`--keep-data`.

## Topology

- N local daemons `conv1..convN`, each with its own config TOML, isolated
  `data_dir` (fresh identities per run), pinned API port (`--api-base`+i)
  and pinned QUIC `bind_address` port (`--quic-base`+i).
- `conv1` has `bootstrap_peers = []`; every other node lists only conv1's
  QUIC address. The explicit (possibly empty) `bootstrap_peers` list in the
  config overrides the hardcoded global bootstrap network, so the cluster
  is fully isolated. `--no-hard-coded-bootstrap` is deliberately NOT used:
  it clears config-provided peers too.
- Rolling start: 15 s between node launches (`--stagger-secs`, a known
  network requirement).
- API tokens are discovered from `<data_dir>/api-token`.

## Phases and gates

Each phase snapshots `GET /diagnostics/gossip` on every node before and
after, and reports the delta of `pubsub_stages.admission` counters
(especially `dropped_critical_hard_error` and cooling) so counter growth is
attributable per phase. Convergence is sampled every `--poll-interval`
(default 1.5 s) with the exact arrival time recorded separately for the
task and the KV key.

| Phase | What happens | Gate (default) |
|---|---|---|
| `cold_join` | conv1 creates a task list + task and a store + key **before** peers exist; each peer then starts, joins, and must see both primitives | task and key visible per node within `--cold-gate` (120 s) — hard |
| `live_propagation` | after all joined and converged, conv1 adds a task and puts a key; per-primitive latency to each peer | all arrivals within `--live-gate` (60 s) — hard |
| `restart_recovery` | convN stopped; conv1 adds a task + key; convN restarted; state must be visible **without** explicit re-create/join | `--restart-gate` (90 s) — known-gap |
| `restart_recovery_eventual` | if auto-recovery failed, explicit rejoin (re-POST `/task-lists` + `/stores/join`) must restore all state incl. the offline mutation | within `--cold-gate` — hard, always |
| `concurrent_claims` | conv1 adds a task; once visible on conv2+conv3 both PATCH `{"action":"claim"}` simultaneously (thread barrier); both HTTP responses recorded; all nodes polled until they agree on one winner | convergence to a single `claimed:*` state within `--claim-gate` (60 s) — hard |
| `concurrent_claims_structured_fields` | are structured claim fields (`claimed_by`/`claimed_at`/`version`) present on the task? | known-gap |
| `signed_store_nonowner_write` | conv2 (joiner) PUTs a new key into conv1's Signed store | HTTP 403 and no local fork — known-gap |
| `signed_store_no_owner_propagation` | the intruder key must never become visible on the owner within `--fork-window` (20 s) | hard, always (a propagation would be a new inbound-enforcement regression) |

## Known-gap flags vs `--expect-fixed`

Three defects confirmed on current main are tracked as **known-gap**
expectations so the harness runs green pre-fix:

1. `restart_recovery` — task-list/store subscriptions are not restored
   after daemon restart (server handle maps start empty).
2. `concurrent_claims_structured_fields` — claim ownership is only encoded
   in the formatted `state` string; no `claimed_by`/`claimed_at`/`version`.
3. `signed_store_nonowner_write` — non-owner PUT returns local `200` and
   forks locally instead of `403`.

Without `--expect-fixed`, observing the legacy behavior reports the phase
as `known-gap` (tolerated, run still passes); observing the fixed behavior
reports `fixed`. With `--expect-fixed`, all three become hard gates — use
this mode to verify the fixes and in CI afterwards.

## Soak mode and reports

`--runs N` repeats the full scenario N times with fresh data dirs (fresh
identities, fresh topic/store names). The aggregate `report.json` contains
per-run, per-phase, per-primitive latencies, pass/known-gap/fail status,
raw claim responses, and per-phase diagnostics deltas. `summary.txt` (also
printed) has a min/median/p95/max latency table, gate pass rates, per-phase
`dropped_critical_hard_error` growth, and the known gaps observed.

## Acceptance criteria (fix verification)

- 10 runs (`just convergence-soak`), 100% eventual convergence for
  cold-join, live-propagation, and offline-rejoin.
- Zero unexplained `dropped_critical_hard_error` growth in the per-phase
  diagnostics deltas.
- With the fixes landed: `--expect-fixed` passes 10/10 (auto restart
  recovery, structured claim fields, non-owner PUT rejected with 403 and
  no local fork).

## Teardown

Daemons are terminated (SIGTERM then SIGKILL) on any failure or exception;
logs and reports are always kept. If a run aborts hard, check for stray
`x0xd` processes on API ports 27810+ before re-running (the harness refuses
to start if an API port is busy).
