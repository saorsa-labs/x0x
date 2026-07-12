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
just convergence-soak-quick          # 1-run smoke (~3 min, NON-authoritative)
just convergence-soak                # 10-run dev soak (NON-authoritative)
just convergence-soak 5              # custom run count
just convergence-release             # AUTHORITATIVE release gate (needs X0XD_LEGACY_BINARY)

# Direct invocation with custom gates:
X0XD_LEGACY_BINARY=/path/to/x0xd-0.30.1 \
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
- Once the cluster is up the harness records each node's identity for the
  report: AgentId (`GET /agent`), PeerId (`GET /diagnostics/connectivity`),
  API/QUIC addresses, `data_dir`, and bootstrap siblings. These are used to
  attribute the deterministic claim winner (`claimed_by`) and the store
  owner to a real node.

## Phases and gates

Each phase snapshots `GET /diagnostics/gossip` on every node before and
after, and reports the delta of `pubsub_stages.admission` counters
(especially `dropped_critical_hard_error` and cooling) so counter growth is
attributable per phase. Convergence is sampled every `--poll-interval`
(default 1.5 s) with the exact arrival time recorded separately for the
task and the KV key.

Each KV convergence gate asserts EXACT decoded bytes (and records the
owner-signed `content_hash`), not mere key presence; the report also records
each node's actual connected peer set and reconnect path (from
`/diagnostics/connectivity`), not just the configured bootstrap list.

| Phase | What happens | Gate (default) |
|---|---|---|
| `cold_join` | conv1 creates a task list + task and a store + key **before** peers exist; each peer then starts, joins, and must see both primitives | task and key visible per node within `--cold-gate` (120 s) — hard |
| `live_propagation` | after all joined and converged, conv1 adds a task and puts a key; per-primitive latency to each peer | all arrivals within `--live-gate` (60 s) — hard |
| `restart_recovery` | convN stopped; conv1 adds a task + key; convN restarted; state must be visible **without** explicit re-create/join | `--restart-gate` (90 s) — known-gap |
| `restart_recovery_eventual` | if auto-recovery failed, explicit rejoin (re-POST `/task-lists` + `/stores/join`) must restore all state incl. the offline mutation | within `--cold-gate` — hard, always |
| `concurrent_claims` | conv1 adds a task; once visible on conv2+conv3 both PATCH `{"action":"claim","fence_token":F_i}` simultaneously (thread barrier), where each F_i is the claimant's OWN local fence_token read right after the barrier; all nodes polled until they agree on one deterministic winner (`claimed_by`) | convergence to a single winner within `--claim-gate` (60 s); winner attributable to a real claimant — hard |
| `concurrent_claims_advisory_both_commit` | each claimant used its own local fence_token, so BOTH must commit (200) — two replicas at their own current token both pass the local fence (advisory). A 409 would mean the fence fired on cross-replica skew and masked the contract. | known-gap |
| `concurrent_claims_structured_fields` | are `claimed_by` (hex AgentId), `claimed_at` (Unix-ms), and list `version` present, and the winner ∈ claimants? | known-gap |
| `concurrent_claims_honest_semantics` | no commit response POSITIVELY claims exclusivity (a top-level `exclusive:false` negation is honest); every 200 carries `committed:"local"`; positive honesty signals (`exclusive`/`execution.authorization`/`cas.scope`/`resolution`) if present must be correct | known-gap |
| `concurrent_claims_cas_fence` | on ONE replica: read F, claim with `fence_token=F` (commits, token→F'), then claim with the now-stale `fence_token=F` — must NOT mutate (non-200, echoes `fence_token`). Asserts non-mutation, never the literal error string. | known-gap |
| `concurrent_claims_remote_invalidation` | the local fence must reject a token invalidated by a merged REMOTE delta: a peer adds a NAMED task, the harness waits for THAT task to be visible on local AND for the fence to advance (not just any revision churn), then a local claim guarded by the pre-merge token is rejected | known-gap |
| `signed_store_nonowner_write` | conv2 (joiner, anchored to conv1) PUTs a new key into conv1's Signed store | HTTP 403 and no local fork — known-gap |
| `signed_store_owner_binding` | joins pin `expected_owner`=creator; creator + joiner both `ownership_status:"anchored"` with `owner`==creator. First-self-claim impossible by construction. **Hard gate** (owner/policy/version/ownership_status now exposed). | hard |
| `signed_store_no_owner_propagation` | the intruder key must never become visible on the owner within `--fork-window` (20 s) | hard, always (a propagation would be a new inbound-enforcement regression) |

| `fence_malformed_rejected` | a malformed `fence_token` (u64 overflow, non-token string) is PATCHed; must be rejected (non-200) WITHOUT mutating the list — present-but-invalid must not collapse to 'absent' | known-gap |
| `fence_pre_restart_rejected` | a `fence_token` captured before a daemon restart is PATCHed after restart; must be rejected (the fence epoch is a fresh incarnation) | known-gap |
| `named_new_port_reconnect` | a peer is restarted on a FORCED different QUIC port (same MachineId, no manual rejoin); must reconnect to the creator (actual peer set) and recover the down-window task | known-gap |
| `owner_offline_checkpoint_recovery` *(prereq)* | owner multi-writes/updates/deletes (incl. delete-to-empty); replicas match EXACT bytes each step; owner OFFLINE, a fresh anchored joiner via relay-only recovers the exact final state with no key resurrection | prerequisite gate (P0; fail ⇒ run fail) |
| `forged_first_seen_task` *(prereq)* | the in-repo `x0xd-forge-injector` publishes an unattested first-seen TaskItem (`Claimed{victim,ts:1}`, no attestation) over real gossip; the receiver's `admit()` must purge it (forged task absent, no version/fence churn, legit post-attack claim still resolves) | prerequisite gate (in-repo injector; fail ⇒ run fail) |

## Claim semantics (advisory — read this before reading the gates)

Claims are an **advisory** CRDT OR-Set, not a distributed lock. `fence_token`
is a **local fence only**: two replicas that both read token F can BOTH pass the
guard and BOTH commit locally — that is correct, not a bug. The single
deterministic winner (earliest timestamp) is resolved at convergence and read
from `claimed_by`. Accordingly:

- `concurrent_claims` asserts convergence to **one** winner and that the winner is
  a real claimant — it does **not** assert "only one claim succeeded".
- `concurrent_claims_cas_fence` tests the fence on a **single replica** where the
  token has already advanced; it asserts non-mutation + `fence_token` echo,
  never the literal error string (the wording is intentionally in flux).
- `concurrent_claims_honest_semantics` asserts no commit response misrepresents
  advisory local commit as exclusive ownership.

## Known-gap flags vs `--expect-fixed`

Defects confirmed on current main are tracked as **known-gap** expectations so
the harness runs green pre-fix:

1. `restart_recovery` — task-list/store subscriptions are not restored after
   daemon restart (server handle maps start empty).
2. `concurrent_claims_advisory_both_commit` — a 409 on a same-version local
   claim masked the advisory contract (now each claimant uses its own local
   version and both must commit).
3. `concurrent_claims_structured_fields` — `claimed_by`/`claimed_at`/`version`
   absent (ownership only in the formatted `state` string).
4. `concurrent_claims_honest_semantics` — a commit response implying exclusive
   ownership the protocol cannot provide.
5. `concurrent_claims_cas_fence` — a stale `fence_token` still mutates.
6. `concurrent_claims_remote_invalidation` — the local fence ignored a token
   invalidated by a merged remote delta.
7. `signed_store_nonowner_write` — non-owner PUT returns local `200` and forks
   instead of `403`.
8. `fence_malformed_rejected` — a malformed fence_token collapsed to 'absent'
   and mutated unconditionally.
9. `fence_pre_restart_rejected` — a pre-restart fence_token was still accepted
   after restart (the epoch was wall-clock, not a durable incarnation nonce).
10. `named_new_port_reconnect` — proactive reconnect / CRDT recovery on a new
    port was not established.

(`signed_store_owner_binding` is now a **hard** gate — owner/policy/version/
`ownership_status` are exposed and joins pin `expected_owner`=creator.)

Without `--expect-fixed`, observing the legacy behavior reports the phase as
`known-gap` (tolerated, run still passes); observing the fixed behavior reports
`fixed`. With `--expect-fixed`, all of the above become hard gates — use this
mode to verify the fixes and in CI afterwards.

## Soak mode and reports

`--runs N` repeats the full scenario N times with fresh data dirs (fresh
identities, fresh topic/store names). The aggregate `report.json` contains
per-run `topology` (each node's AgentId, PeerId, addresses, bootstrap
siblings), per-phase, per-primitive latencies, pass/known-gap/fail status,
raw claim responses (with `fence_token`), fence observations,
store owner/policy/version probes, per-phase diagnostics deltas, and each
node's connected peer set; plus top-level `provenance` (binary SHA-256 +
`--version` + git HEAD/dirty-tree/source cutoff), `release_environment`
(hard-error growth + mDNS contamination), and `provenance_errors`, alongside
the `prerequisite_gates` array. `summary.txt` (also printed) has a
min/median/p95/max latency table, gate pass rates (pass/gap/unsupp/fail),
per-phase `dropped_critical_hard_error` growth, the known gaps observed, the
same-host topology, and the prerequisite-gate statuses.

## Version-skew, hostile-announce, checkpoint & forged-first-seen gates

Threats the single-version same-host soak cannot cover on its own.

### Release-oracle provenance

Every run records and (under `--expect-fixed`) **verifies** binary/source
provenance — attesting the release from digests and a source cutoff rather
than paths alone:

- **current binary** — SHA-256, `--version`, and mtime; the oracle REFUSES a
  binary whose mtime predates the newest reviewed source file (rebuild
  required).
- **legacy binary** — SHA-256 + `--version`; must be EXACTLY `v0.30.1`. File
  existence alone is not authentication — a wrong-version "legacy"
  hard-fails both mixed-version directions.
- **git source cutoff** — HEAD, `HEAD^{tree}`, branch, a dirty-tree
  fingerprint (sha256 of `git diff HEAD` + `git status`), and the HEAD
  commit timestamp, so the report binds to the exact working tree.
- **actual peer set + reconnect path** — each node's connected PeerIds and
  connection-pool counters (from `/diagnostics/connectivity`), recorded in
  topology and before/after restart for attribution.

Under `--expect-fixed` a provenance refusal (stale binary / wrong legacy
version) fails fast. Without it the refusals are warnings (smoke stays
available).

### `mixed_version_skew` (load-bearing + degraded) — needs a real v0.30.1 binary

- **`mixed_version_skew_load_bearing`** — a real v0.30.1 binary is the OWNER
  (creates+writes); the current binary is the anchored joiner that pins
  `expected_owner`=<legacy owner> and MUST recover the historical key and a
  live key with EXACT decoded bytes (+ owner-signed `content_hash`).
  Online-owner convergence-with-anchor across skew.
- **`mixed_version_skew_degraded`** — current owner + legacy v0.30.1 joiner.
  The owner's key replicates to the legacy joiner with EXACT bytes, AND the
  legacy non-owner write must NOT propagate to the current owner (no
  unauthorized propagation) while owner state stays exact. Degraded-safety is
  proven by the ABSENCE of the rogue write — not by mere liveness.

Both directions need a REAL legacy binary; the skew is never faked by
degrading the current binary. `--expect-fixed` requires BOTH; UNSUPPORTED
fails the run under `--expect-fixed`.

### `malicious_owner_announce` (in-repo, no external binary)

A rogue daemon self-claims the SAME store topic; its sync loop publishes a
genuine `OwnerAnnounce{owner: rogue}`. PASS requires a **positive** attack
receipt — a `conflict` status observed with the rogue identity — PLUS a
stable legit owner (never flips to rogue), NO rogue content on the joiner
(exact bytes), and a legitimate **post-attack** write the joiner recovers
(proving the anchor is not wedged). Anchored-alone is not enough: the gate
must prove the rogue announce arrived and was rejected.

### `owner_offline_checkpoint_recovery` (P0, in-repo)

Owner multi-writes/updates/deletes (including delete-to-empty); replicas must
match EXACT bytes after each step. Then the owner is STOPPED and a fresh
anchored joiner bootstrapping ONLY to a relay (not the owner) recovers the
EXACT final state with no key resurrection. Exercises checkpoint epoch
persistence, content-root integrity, and delete reconciliation end to end.

### `forged_first_seen_task` (in-repo injector)

A hostile gossip publisher ships a first-seen TaskItem carrying a
`Claimed{victim,ts:1}` element with NO matching attestation. The in-repo
`x0xd-forge-injector` binary crafts it via
`x0x::crdt::forge_unattested_delta_bytes` (the exact bincode `(PeerId,
TaskListDelta)` wire bytes) and publishes over REAL gossip through the daemon's
`/publish` wire API — never faked via REST. The receiver's fail-closed
admission (`admit()`) must purge it: the forged task never appears, the list
version/fence does not churn, and a legit post-attack claim still resolves.
Built by `just convergence-release` (and `cargo build --release --bin
x0xd-forge-injector`); a missing injector is a hard setup failure (UNSUPPORTED,
FAIL under `--expect-fixed`). The other variants (malformed-sig, attacker-key,
wrong-agent, wrong-scope) are proven at the store/CRDT regression layer.

## Release-environment gates (hard-error + mDNS)

Two environmental signals are gated, not merely reported:

- **`dropped_critical_hard_error` growth** — any per-phase growth across the
  soak. Under `--expect-fixed` growth FAILS the run (a critical pubsub
  admission failure is never acceptable); reported otherwise.
- **mDNS mesh contamination** — non-zero `discovered_peers` on the isolated
  cluster (stray x0xd daemons on the host). Under `--expect-fixed` a
  contaminated mesh FAILS the run; for a clean release, ensure no other x0xd
  daemons are active.

A gate that runs and **fails** always fails the harness.
`malicious_owner_announce` and `owner_offline_checkpoint_recovery` always run
(in-repo); under `--expect-fixed` they must PASS. `mixed_version_skew` and
`forged_first_seen_task` are UNSUPPORTED without their prerequisites; that
does not fail the run by default — **except under `--expect-fixed`**, where
UNSUPPORTED FAILS: the release recipe demands every phase be exercised, never
silently skipped.

## Release recipe (authoritative) vs one-run smoke

- **`just convergence-release`** is the AUTHORITATIVE release gate: it
  requires `--expect-fixed` (every known-gap becomes a hard gate), an
  authenticated v0.30.1 legacy binary (`X0XD_LEGACY_BINARY`), and 10/10 clean
  runs. UNSUPPORTED or unproven phases are NO-GO; provenance refusal fails
  fast. **This is the recipe that gates a release.**
- **`just convergence-soak-quick`** (1 run) and **`just convergence-soak`**
  (10 runs) remain available as non-authoritative smokes / dev soaks.

## Acceptance criteria (fix verification)

- 10 runs (`just convergence-release`), 100% eventual convergence for
  cold-join, live-propagation, and offline-rejoin, with EXACT decoded KV
  values (not presence).
- Zero `dropped_critical_hard_error` growth; clean (uncontaminated) mDNS mesh.
- With the fixes landed: `--expect-fixed` passes 10/10 — auto restart
  recovery, structured claim fields, honest claim semantics, CAS local fence,
  remote-invalidation by a NAMED mutation, malformed/pre-restart fence
  rejection, non-owner PUT rejected with 403 and no local fork, store owner
  bound to the creator, owner-offline checkpoint/delete recovery, named
  new-port reconnect, positive hostile-announce conflict, and exact-value
  mixed-version interop with no degraded-direction propagation.

## Teardown

Daemons are terminated (SIGTERM then SIGKILL) on any failure or exception;
logs and reports are always kept. If a run aborts hard, check for stray
`x0xd` processes on API ports 27810+ before re-running (the harness refuses
to start if an API port is busy).
