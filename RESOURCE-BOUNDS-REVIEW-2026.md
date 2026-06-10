# x0x Resource Bounds Review — 2026 Publisher OOM & Long-Term Mitigation

**Branch**: `resource-bounds-review` (worktree at `../x0x-resource-bounds`)  
**Date**: 2026-05 (post deep-dive)  
**Status**: Ready for team review + soak validation  
**Authors**: Grok (investigation + minimal patch) + David Irvine (context)

---

## Executive Summary

We had two documented resource incidents in 2026:

1. **glibc allocator RSS amplification** (~50 MB+ "invisible" heap growth after free) — fixed by switching the daemon to `tikv-jemalloc` + aggressive `MALLOC_CONF` decay. Still opt-in for library consumers.

2. **Publisher-side memory growth / OOM** (the big one). During a modest sustained publish soak (~150 KB/s aggregate), publisher nodes grew to 1.2–3.7 GiB RSS while idle subscribers stayed flat at ~40-100 MB. One node hit ~3.5 GiB in 53 minutes (~150× payload retained in RAM). This was the open issue after the CPU-spin fix in v0.19.2.

**Current state (excellent progress)**: The root cause class (PlumTree message cache + per-peer outbound queues under back-pressure) has received **major investment** in `saorsa-gossip` (X0X-0074 series + follow-ups visible in the local sibling checkout). Message caches are now strictly bounded (count + bytes + age), there is real admission control with per-peer Bulk depth tracking and `BulkBackpressure` drops, dedicated Critical lanes, etc.

**Remaining x0x-owned gap**: The three discovery caches (`identity_discovery_cache`, `machine_discovery_cache`, `user_discovery_cache`) inside `Agent` were (and still are in `main`) append-mostly HashMaps. TTL filtering only happened at read time (`discovered_agents`, `online_agents`, etc.). No active reaper. Long-running nodes in a large or churny mesh would retain every agent/machine/user ever seen.

**Patch in this worktree**: A minimal, surgical active reaper (120 s interval) that performs the same TTL retain the query paths already do, plus shutdown/Drop wiring and a new cheap diagnostic `discovery_cache_entry_counts()`. Exposed in `/diagnostics/gossip` for immediate operator visibility.

The change is **production-code clean** under the project's strict clippy gate (the only clippy noise is pre-existing `expect` in x0xd test code).

---

## Historical Context (What Actually Happened)

### Incident 1 — Allocator (2026-04-25 soak)
- Symptom: Retired glibc arenas holding pages → 50 MB+ RSS amplification.
- Evidence: `Cargo.toml:78-91` (still has the comment), multiple `dhat-heap-*.json` artefacts in repo root.
- Fix: `jemalloc` feature + `background_thread:true,dirty_decay_ms:1000,muzzy_decay_ms:0`.
- dhat + `profile-heap` feature added for future post-mortems.

### Incident 2 — Publisher Memory Growth (documented in NEXT-SESSION-PROMPT.md)
- Load: 3 publishers, ~10-17 real msgs/s each (curl-limited), 133k messages total, ~24 MB raw per publisher.
- Outcome: 3 nodes OOM-killed (anon-rss 1.2 GiB → 3.7 GiB). Idle nodes unaffected.
- Hypotheses at the time (in priority order):
  1. PlumTree IHAVE / message-id cache growing without bound.
  2. Per-peer outbound queues retaining messages under back-pressure.
  3. Self-publish subscriber channel backlog.
  4. Heartbeat/SWIM piggyback growth.
  5. New v0.19 wire-v2 announcement caches.

The CPU spin (ant-quic poller) was fixed first and shipped. Memory growth on publishers remained the blocker.

---

## Current State of Mitigations (as of this review)

### saorsa-gossip (the real heavy lifting)

Local checkout (`../saorsa-gossip`, dirty on `main`, recent commits visible):

- **Message cache** (`lib.rs`):
  - `MAX_CACHE_SIZE` reduced from 10 000 → **2 048**.
  - `MAX_CACHE_AGE_SECS` reduced from 300 → **60**.
  - New hard `MAX_CACHE_BYTES_PER_TOPIC = 16 MiB` with byte accounting (important for large group cards / discovery payloads).
- **Admission control** (X0X-0074 + 0074b/c, `admission.rs` + integration in `lib.rs`):
  - Real per-peer `bulk_depth` tracking inside `AdmissionControl`.
  - `BulkBackpressure` drop when depth ≥ `per_peer_bulk_slack_threshold` (default 64).
  - `release_bulk()` called on send completion / drop paths.
  - Dedicated Critical Data lane (prevents Normal/Bulk from starving Critical).
  - Health-based drops (Dead / Suspect) for Normal + Bulk.
  - Rich telemetry (`dropped_bulk_backpressure`, `dropped_*_peer_cooled`, per-peer depths in diagnostics).
- **Outbound budget**:
  - `PeerOutboundBudgetEntry` with in-flight counters + 10-minute idle reaping (`OUTBOUND_BUDGET_REAP_AFTER`).
- **Adaptive cooling** (timing.rs) + fan-out detach work also landed recently.

**Conclusion on gossip layer**: The exact failure mode from the 2026 incident has been directly attacked with multiple overlapping controls (admission before enqueue + tighter caches + visibility). The local sibling even has uncommitted tweaks in `admission.rs`. No further changes are proposed from the x0x side in this cycle.

### x0x (this repo) — before the patch in this worktree

- Connection pool: LRU + 300 s idle eviction + background task (good).
- Subscriber channels: 10 000 bounded, slow-sub drop with counters (good).
- DM dedupe cache: 10 k entries + 5 min TTL + LRU (good).
- Groups shards: 512 subscription cap + 4 096 LRU per shard (good).
- Presence peer stats: 10-entry window + explicit eviction on offline (good).
- **Discovery caches**: the gap. Three `RwLock<HashMap<...>>` that only ever grew. TTL was a query filter only.

---

## The Patch (Minimal + Surgical)

**Location**: worktree `../x0x-resource-bounds`, branch `resource-bounds-review`.

### Changes (all in x0x-owned code)

1. New consts (`DISCOVERY_CACHE_REAPER_INTERVAL_SECS = 120`).
2. New private field on `Agent` + initializer + `Drop` handling.
3. `stop_discovery_cache_reaper`, `start_discovery_cache_reaper`, and the loop body `discovery_cache_reaper_loop`.
4. The reaper does exactly the same `retain(last_seen >= cutoff)` that `discovered_agents` / `online_agents` etc. already perform — just on a timer instead of only at read time.
5. Public diagnostic: `discovery_cache_entry_counts() -> (usize, usize, usize)`.
6. One-line wiring in `join_network` (after heartbeat start) and `shutdown`.
7. Labelled exposure in `/diagnostics/gossip` under `discovery_cache_entries.{agents,machines,users}`.
8. Documentation hardened for the “unfiltered” discovery helpers: after the reaper starts, those helpers expose all currently retained entries, not an archival “all ever seen” view.

**Verification in the worktree**:
- `cargo fmt --all -- --check` — clean
- `cargo check --workspace --all-targets` — clean
- `cargo clippy --all-features --all-targets -- -D warnings -D clippy::panic -D clippy::unwrap_used -D clippy::expect_used` — currently fails on pre-existing test/lib-test `expect`/`panic` violations outside this patch (for example `tests/named_group_join_metadata_event.rs`, `src/direct.rs`, `src/dm.rs`, `src/dm_send.rs`, and `src/exec/acl.rs`). The patch-added production paths add no new `unwrap`/`expect`/`panic`.

No new `unwrap`/`expect`/`panic` in patch-added production code. No adjacent refactoring beyond documentation and labelled diagnostics.

### Design Rationale (why this shape)

- Matches the existing heartbeat / presence task patterns exactly.
- Zero new dependencies or complex data structures (no LRU crate, no sorting on hot path — simple retain is sufficient for the documented risk).
- The hard cap (10 k) was considered but deferred; the active TTL reaper alone converts "grows forever" into "bounded working set + retention window". A future size-based cap can be added on top with almost no diff if soak shows it is needed.
- Diagnostic is cheap (three read locks) and immediately useful; the daemon JSON uses labelled fields so operators do not need to remember tuple order.

---

## Remaining Risks & Recommendations

1. **Discovery caches** (now mitigated by this patch).
2. **No global memory pressure signal** yet. Individual components are well bounded, but nothing coordinates "we are under RSS pressure → shed harder / slow beacons / refuse new Bulk publishes".
3. **Gossip layer** is now the strong side; continue the X0X-0074 / 0075 work there.
4. **Soak discipline**: The existing 65-minute sustained-publish + RSS watch pattern in the proof reports is the correct one. Add an explicit assertion or post-run check that `discovery_cache_entry_counts()` stays flat after the reaper has had a few cycles.
5. Consider (low priority) exposing the reaper interval and/or a hard cap via `DaemonConfig` for very large deployments.

---

## How to Review & Test This Work

1. `cd ../x0x-resource-bounds && git diff main --stat` (or `--no-color`).
2. Build the daemon with the worktree: `cargo build --bin x0xd --features jemalloc`.
3. Run a local sustained publish test while watching the new diagnostic:
   ```
   curl -H "Authorization: Bearer <token>" http://127.0.0.1:12700/diagnostics/gossip | jq '.discovery_cache_entries'
   ```
   Expected shape: `{ "agents": N, "machines": N, "users": N }`. Publish loop for 10-15 min; counts should stabilize instead of climbing.
4. Full validation (in the worktree):
   ```bash
   cargo fmt --all
   cargo clippy --all-features --all-targets -- -D warnings -D clippy::panic -D clippy::unwrap_used -D clippy::expect_used
   cargo check --workspace --all-targets
   cargo nextest run --all-features --workspace   # optional but recommended
   ```
5. For a real mesh soak: use the existing harness + the new diagnostic counter as an explicit success criterion.

---

## Appendix: Files Changed in This Worktree

- `src/lib.rs` — Agent struct, Drop, shutdown, join_network, reaper task + prune logic, new public diagnostic.
- `src/bin/x0xd.rs` — labelled addition of the counts into the gossip diagnostics JSON.

All other risk areas (connection pool, subscriber channels, DM dedupe, groups shards, presence stats, upgrade temp guards, deserialize size limits, adaptive dispatch workers) were already in good shape and untouched.

---

**Ready for team soak and merge review.**

The patch is intentionally tiny because the heavy lifting for the 2026 publisher OOM class of problem was already done in the gossip crate. This closes the last obvious x0x-owned unbounded-growth vector with the same engineering style the rest of the resource work has followed.