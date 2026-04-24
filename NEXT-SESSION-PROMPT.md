# Next-session prompt — x0x v0.19.2 shipped, **memory growth on publishers** is the remaining issue

**Read this before doing anything.** State of the network: all 6 VPS bootstrap
nodes are running `x0x v0.19.2` from crates.io — `316436de…` build of the
stripped release binary. Mesh is stable at rest (~30-100 MB RSS per node, all
6 peers connected). The CPU-spin bug from the prior session is **fixed** and
shipped. **Don't restart the spin hunt.**

The new outstanding issue is a **memory-growth leak that fires only on nodes
acting as sustained publishers**.

---

## What shipped (the closed work)

- `ant-quic 0.27.4` on crates.io — dual-stack `create_io_poller` switched
  from OR-combine (`tokio::select!`) to AND-combine (`tokio::join!`) so a
  stale `Ready` on the non-target socket can no longer satisfy the poller
  while the target socket is back-pressured. Closes the 100 % CPU spin in
  `drive_transmit`.
- `saorsa-gossip-* 0.5.20` on crates.io — lockstep republish across all 11
  workspace crates with `ant-quic = 0.27.4`; no gossip source changes.
- `x0x 0.19.2` on crates.io — depends on the two above, strips the
  `[patch.crates-io]` ant-quic path hack, syncs `SKILL.md` so the release
  validator passes, bundles the v0.19.0 wire-v2 / UserAnnouncement /
  IntroductionCard signing work that v0.19.0 + v0.19.1 tags failed to
  publish.

Validated end-to-end on the live 6-continent mesh from published crates only:
288 CPU samples across 65 min, **0 samples > 50 %**, **0 nodes ever had 2
consecutive samples > 50 %**, **0 gossip drops** in any of 72 diagnostic
snapshots. Proof under `proofs/v0.19.0-validation-20260423T131419Z/`.

---

## The new bug — memory growth on publishers

### Symptom

Three of six VPS daemons OOM-killed during a 65-min sustained-load watch
(`proofs/v0.19.0-validation-20260423T131419Z/12-60min-sustained-watch/`).
Every one of those three was running the publisher loop. The other three
(idle subscribers) stayed flat at 40-100 MB RSS the whole time.

```
Apr 24 07:22:23 sfo       systemd: x0xd.service: oom-kill (anon-rss 1.2 GiB)
Apr 24 07:27:53 nyc       kernel:  Killed process 90697 (x0xd) anon-rss 3 719 MB
Apr 24 07:43:08 sfo       systemd: x0xd.service: oom-kill again
Apr 24 07:52:20 helsinki  kernel:  Killed process 37081 (x0xd) anon-rss 3 571 MB
```

Load was modest:
- 50 msg/s × 4 KB target per publisher (curl-overhead capped to ~10-17 msg/s
  actual; aggregate ~150 KB/s into mesh)
- 133 579 messages published total over ~58 min by the 3 publishers
- ~24 MB raw payload sent per publisher node

Helsinki hit 3.5 GiB RSS after 53 min ≈ **150× the raw payload throughput
retained in memory.** Clearly unbounded caching / accumulation somewhere.

CPU stayed calm throughout (max 36.4 % single sample), so this is **not**
the spin path firing in a different shape — it's a separate memory-side
issue.

### Notable second-order effect

Helsinki's publisher rate fell from ~18 msg/s (first 15 min) to < 8 msg/s
(remaining 40 min). Wall-clock correlated with its RSS climb. Either the
local `/publish` REST handler slows under memory pressure, or the
`saorsa-gossip-pubsub` publish path takes longer to enqueue when its
internal buffers are full.

### Hypotheses (priority order)

1. **PlumTree IHAVE / message-id cache** on the publisher side accumulating
   `msg_id` entries without TTL eviction. At 4 KB × 100k messages =
   400 MB raw, but msg_ids alone are 32 B × 100k = 3.2 MB so this would
   need significant per-id metadata to hit GiB.
2. **Per-peer outbound queue** retains buffered messages per `(peer, topic)`
   under sustained back-pressure. A 5-peer fan-out × 100k msgs × 4 KB
   payload + headers could legitimately reach the GiB range.
3. **`delivered_to_subscriber` backlog** if no local subscriber is draining
   the local copy of self-published messages. Worth checking whether the
   publish path's own subscriber channel is bounded.
4. **Heartbeat / SWIM piggyback growth** carrying ever-longer membership
   digests.
5. Something in the new (v0.19.x) wire-v2 / UserAnnouncement /
   IntroductionCard cache paths — the v0.18.x→v0.19.0 deps were heavy on
   cache additions.

### First moves

1. **Reproduce locally on a single daemon.** No mesh needed — start one
   `x0xd`, `subscribe` to topic `T`, then publish to `T` at 100 msg/s ×
   4 KB in a tight loop. Watch `/proc/PID/status | grep VmRSS` every 30 s
   for 15 min. If RSS climbs predictably, we have a clean repro.
2. **Bisect with `dhat-rs` or `heaptrack`.** Add `dhat::Profiler::new_heap()`
   guard at `Agent::build()` exit, run the repro, post-mortem the dump.
   Will name the largest live allocations directly.
3. **Cross-check `/diagnostics/gossip` counters** under repro. If
   `delivered_to_subscriber` is racing way ahead of consumer reads (i.e.
   `recv_tx` queue is filling), the leak is in the subscriber pipeline.
   Already saw `subscriber_channel_closed` bumping during VPS-e2e harness
   churn — same code path could grow under publish load.
4. **systemd guard rails** — even after the fix lands, set `MemoryMax=2G`
   + `Restart=on-failure` + `RestartSec=30s` on the `x0xd.service` unit so
   any future regression bounces gracefully rather than waiting for the
   kernel OOM killer. Currently the kernel kill is silent and loses
   in-flight state.

### Out of scope for the bug, in scope for the launch

The bug is **not a v0.19.2 launch blocker** for typical client/agent use.
End-user agents (laptops, phones, CLIs) don't sustain publisher-level rates
for an hour. It only bites operators running an x0xd daemon as a high-rate
publisher / gateway. Document the workaround (run on ≥ 8 GiB RAM, restart
weekly) until the actual fix lands.

---

## Don't repeat these

1. Cargo.toml's `[patch.crates-io] ant-quic = { path = "../ant-quic" }`
   was load-bearing for v0.19.0 — without it, the crates.io tarball
   shipped without the spin fix. **It's gone in v0.19.2.** Don't add it
   back unless you also tag a fresh ant-quic and a fresh x0x.
2. `SKILL.md`'s `version` field MUST match `Cargo.toml`'s `version`
   field at release time. The release workflow fails fast on this; v0.19.0
   and v0.19.1 tags both stillborned because nobody updated SKILL.md.
   `v0.19.2` finally synced them.
3. `tests/e2e_stress_gossip.sh` doesn't read its `NODES` / `MESSAGES` env
   vars — they're hard-coded. If you want different params, edit the script
   or pass them as positional args (need to add support).
4. The release-profiling binary is **452 MB** with embedded debuginfo.
   Don't deploy it to the live mesh — use it locally for gdb / perf only.

---

## Repo state

- Branch `main`, latest commit `chore(release): v0.19.2`.
- Three uncommitted commits ahead before the v0.19.2 release commit:
  flake fix in `tests/comprehensive_integration.rs`, rolling-delay patch
  in `tests/e2e_deploy.sh`, the release commit itself.
- Tags on the repo: `v0.19.0`, `v0.19.1` (both stillborn, never on
  crates.io), `v0.19.2` (live).
- `proofs/v0.19.0-validation-20260423T131419Z/` is the curated proof from
  this session and contains the full forensics chain. Read its `README.md`
  for the go/no-go report and `12-60min-sustained-watch/README.md` for
  the comprehensive memory-growth evidence.

---

## VPS state at session close

| Node | Provider | Service | RSS | Peers |
|------|----------|---------|------|-------|
| nyc / saorsa-2 | DO NYC1 | active | ~36 MB | 6 |
| sfo / saorsa-3 | DO SFO3 | active | ~60 MB | 6 |
| helsinki / saorsa-6 | Hetzner HEL | active | ~30 MB | 6 |
| nuremberg / saorsa-7 | Hetzner NUR | active | ~50 MB | 4–6 |
| singapore / saorsa-8 | DO SGP1 | active | ~50 MB | 5–6 |
| sydney / saorsa-9 | DO SYD1 | active | ~50 MB | 6 |

All on `316436de…` (x0x 0.19.2 stripped release built from published crates,
no path patches). Tokens for SSH-based REST API access are in
`tests/.vps-tokens.env` (gitignored).
