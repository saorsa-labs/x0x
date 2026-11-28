# #1172 Track E: E0-b soak baseline and allocator A/B report

This report records the committed Track E baseline artefact for
[#1172](https://github.com/saorsa-labs/x0x/issues/1172) (E0-b 26 h soak and
12 h allocator A/B soak).

## Summary

- **Idle nodes (the E0-b question): slowing growth, 7–10% total from hour 1.**
  Over 26 h on v0.49.1 (`80064f77`), idle nodes `q1` and `q2` rose from 67 MB
  at hour 1 to 72 and 74 MB at hour 26 (slope h4–26: `+0.11` and `+0.24` MB/h;
  hours 12–26 added 1 MB on `q1` and 3 MB on `q2`). All growth was anonymous
  allocator memory (`RssAnon`), with no diagnostics gauge growing.
- **Workload nodes: large step at group join, lower residual slopes afterward,
  no unbounded leak observed in 26 h.** The 4 → 6 member join at hour 5.5 drove
  the h4–26 slope; residual slopes were h13–26 `a` +1.85, `b` +4.5, `c` −0.02
  MB/h and h20.5–26 `a` +2.4, `b` 0.0, `c` +5.3 MB/h. All growth was `RssAnon`
  in glibc arenas.
- **Configured jemalloc A/B (12 h, `main` `3d74075f1`):** With
  `_rjem_malloc_conf` applied (`dirty_decay_ms=1000`, `muzzy_decay_ms=0`),
  jemalloc work nodes averaged ~20% lower RSS at hour 12 (mean 118.0 vs
  147.3 MB; per-node 16–25% lower) and returned 8–18 MB below high-water mark
  (HWM) at no measurable CPU cost.
- **Functional regressions observed during the 26 h soak (v0.49.1):** After the
  4 → 6 join, steady-state DM `ack_wait` timeouts ran at 3.8–5.1%, W1 logged
  74 KV errors, and group re-adds dropped from 9/9 (pre-join) to 11/39
  (post-join). These findings are tracked in
  [#2189](https://github.com/saorsa-labs/x0x/issues/2189) (gossip load step and
  DM timeouts) and [#2202](https://github.com/saorsa-labs/x0x/issues/2202)
  (re-add failures after churn; self-healing landed in #2205). Allocator
  changes landed in #2191 (apply `_rjem_malloc_conf`) and #2192 (jemalloc
  release builds, A06 amendment of 24 Nov 2026).

---

## 1. 26 h E0-b soak (v0.49.1, `80064f77`)

- **Run window:** 2026-11-22T14:04:33Z → 2026-11-23T16:05Z (main driver ended
  cleanly at hour 26.0; 5-minute RSS samples).
- **Environment:** One local Linux VM, loopback network namespaces, `netem`
  15 ± 5 ms delay and 0.2% loss.
- **Health:** 0 panics, 0 unplanned unit restarts (`d` had 25 planned
  restarts). File descriptors (16–17) and threads (20–23) stayed flat for 26 h.

### Timeline

| Hour | Event |
|---|---|
| 0 | `a`–`d` (workload) and `q1`, `q2` (idle) start. |
| 5.5 | `e` (glibc, `MALLOC_ARENA_MAX=2`) and `f` (jemalloc) join the workload mesh and group. |
| 20.0 | `e` and `f` are removed via owner `a` (epochs 77, 78) and stopped (switch 10:05:00–10:07:06Z). |
| 20–26 | `a`–`d` run alone. |

### Idle nodes (`q1`, `q2`)

| Node | h1 | h12 | h26 | Slope h4–26 |
|---|---|---|---|---|
| `q1` | 67 MB | 71 MB | 72 MB | +0.11 MB/h (+0.16 %/h) |
| `q2` | 67 MB | 71 MB | 74 MB | +0.24 MB/h (+0.34 %/h) |

- Measured from hour 1, total growth is 7–10%. The rate slows over the 26 h
  run (hours 12–26 add 1 MB on `q1` and 3 MB on `q2`, ~0.2 MB/h on `q2`); a
  26 h run does not prove zero growth beyond 26 h.
- Percentage slopes (`%/h`) in this section use each node's RSS at the start of
  the named window as the denominator.
- Attribution: `RssAnon` rose on `q1` from 14.7 → 20.0 → 21.2 MB (h0.5 / h12 /
  h26). `RssFile` stayed flat. No diagnostics gauge grew (`peer_scores` and
  `topic_caches` moved from 20 to 19).
- Reading: allocator warm-up that slows sharply over 26 h; no subsystem table
  grows.

### Workload nodes (`a`–`c`; `d` omitted due to hourly restarts)

| Node | Slope h4–26 | Slope h13–26 | Slope h20.5–26 (4-node) | h26 RSS (HWM) |
|---|---|---|---|---|
| `a` | +10.3 MB/h (5.8 %/h) | +1.85 MB/h (0.4 %/h) | +2.4 MB/h | 480 MB (480) |
| `b` | +10.7 MB/h (7.9 %/h) | +4.5 MB/h (1.2 %/h) | 0.0 MB/h | 383 MB (431) |
| `c` | +8.0 MB/h (6.0 %/h) | −0.02 MB/h (0.0 %/h) | +5.3 MB/h | 366 MB (414) |

- Node `d` restarted every hour by design, so it has no continuous slope row
  (see Limits below).
- All growth was `RssAnon` in glibc arena maps (maps ≥ 8 MB rose from 0–1 to
  12 on each of `a`, `b`, and `c`; `[heap]` stayed 0 and `RssFile` flat).
- No diagnostics gauge grew.
- When traffic fell ~45% after hour 20, glibc RSS did not drop (`a` 466 → 480,
  `b` 388 → 383, `c` 341 → 366 MB): `a` ended at its 480 MB HWM, while `b` and
  `c` stayed 48 MB below their earlier HWMs (431 and 414 MB) without returning
  memory further in W2.
- Over hours 6.5–20, `f` (jemalloc running with **defaults** because prefixed
  builds read `_rjem_malloc_conf`, fixed later in #2191) grew 176 → 256 MB
  (+6.2 MB/h, HWM 338 MB), rose mainly in hours 11–14, then flattened and
  returned memory below HWM (240–276 MB). `e` (`MALLOC_ARENA_MAX=2`) grew
  +3.5 MB/h (`[heap]` 53 → 89 MB).

### Cost of the 4 → 6 member join (hourly rates)

Windows: `W0` = hours 1.0–5.4 (before join), `W0b` = hours 5.5–6.0 (first
30 min after join), `W1` = hours 8–20 (6 members; hours 6.0–8.0 are a
post-join transition gap excluded from steady-state `W1`), `W2` = hours 20.5–26
(after `e` and `f` left).

| Node, window | Peers | `publish_fanout` | `relay_forward` | `anti_entropy_push` | `iwant_reply` | Eager msgs/h | Eager MB/h | All sent MB/h |
|---|---|---|---|---|---|---|---|---|
| `a` W0 | 3 | 1 517 | 2 812 | 1 042 | 1 854 | 7 224 | 216 | 244 |
| `a` W1 | 5 | 4 510 | 16 212 | 13 491 | 13 175 | 47 724 | 2 241 | 2 092 |
| `a` W2 | 3 | 3 079 | 7 209 | 8 895 | 7 992 | 27 345 | 1 195 | 1 155 |
| `b` W0 | 3 | 1 325 | 3 225 | 832 | 1 742 | 7 123 | 190 | 218 |
| `b` W1 | 5 | 2 681 | 14 734 | 14 038 | 11 542 | 43 021 | 1 638 | 1 738 |
| `b` W2 | 3 | 2 084 | 7 310 | 9 030 | 8 051 | 26 505 | 1 099 | 1 105 |
| `c` W0 | 3 | 1 167 | 2 883 | 1 044 | 1 661 | 6 754 | 184 | 214 |
| `c` W1 | 5 | 2 241 | 14 527 | 14 028 | 12 685 | 43 518 | 1 673 | 1 768 |
| `c` W2 | 3 | 2 106 | 7 469 | 8 485 | 7 945 | 26 044 | 1 136 | 1 129 |
| `d` W0 | 3 | 1 271 | 3 145 | 828 | 1 544 | 6 789 | 183 | 208 |
| `d` W1 | 5 | 1 512 | 11 659 | 12 132 | 12 372 | 37 725 | 1 487 | 1 531 |
| `d` W2 | 3 | 1 672 | 6 819 | 7 959 | 7 416 | 23 908 | 995 | 985 |
| `e` W1 | 5 | 3 167 | 13 865 | 11 787 | 12 081 | 40 936 | 1 790 | 1 854 |
| `f` W1 | 5 | 3 356 | 14 590 | 11 394 | 12 161 | 41 549 | 1 831 | 1 889 |
| `q1`/`q2` any | 1 | 27 | 0 | 0 | 0 | 27 | 0.4 | 1.7 |

- `Eager msgs/h` is the total across all eager send causes; the four breakdown
  columns omit smaller residual eager causes (26–336 msgs/h in W1/W2, such as
  unclassified/other eager sends).
- `Eager MB/h` (gossip-stage eager byte counter) and `All sent MB/h`
  (transport-stage sent byte counter) are separate diagnostic counters sampled
  at different layers, so `Eager MB/h` slightly exceeds `All sent MB/h` in four
  rows (`a` W1, `a` W2, `c` W2, `d` W2).

### Offered load and outcomes (26 h soak)

| Window | DMs offered | DM failures | KV writes offered | KV errors | Re-adds OK | Group size |
|---|---|---|---|---|---|---|
| W0 (h1.0–5.4) | 682/h | 0 | 29/h | 0 | 9/9 | 4 |
| W0b (h5.5–6.0) | 584/h | 12 (4.1%) | 40/h | 0 | 0/1 | 6 |
| W1 (h8.0–20.0) | 649/h | 298 (3.8%) | 42/h | 74 | 8/23 | 5–6 |
| W2 (h20.5–26.0) | 323/h | 90 (5.1%) | 19/h | 0 | 3/11 | 3–4 |

- Dispatcher `over_1s` per hour on node `a` (membership / pubsub): W0 `8 / 2`,
  W1 `1 722 / 1 074`, W2 `359 / 408`.
- Egress poller: `a`–`d` stayed over the 128 KB/s hard rate from the join
  through W2 (`observe_only`); `q1` and `q2` never exceeded it.
- These traffic, DM-timeout, and re-add findings are tracked in #2189 and #2202.

### Limits (26 h soak)

- One local Linux VM, loopback `netem` (no WAN, NAT, or multi-region latency).
- Peer degree 3 in W0/W2 and 5 in W1; 1 for idle nodes.
- `d` restarted hourly, so `d`'s slopes are piecewise and omitted from the
  continuous workload slope table.
- `f` ran jemalloc defaults (pre-#2191).
- In W2, `c` spent most of the window outside the group because re-adds failed.

---

## 2. 12 h configured-jemalloc A/B soak (`main` `3d74075f1`, post-#2191)

- **Run window:** 2026-11-23T16:32Z → 2026-11-24T04:35Z, one `aarch64` Lima VM,
  two isolated planes of 3 work nodes + 1 idle node each, equal offered load
  (DMs: 2 790 vs 2 766 in h0–8, ~349/h vs ~346/h; 354 vs 354 in h8–12).
- **Health (both planes):** 0 panics, 0 unit restarts, 0 DM failures, 0 KV
  errors, 17/17 re-adds at 3 members.

### RSS MB at h1 / h4 / h8 / h12 (high-water mark)

| Node | glibc | jemalloc (`dirty_decay_ms=1000`, `muzzy_decay_ms=0`) |
|---|---|---|
| work 1 | 126 / 137 / 152 / 158 (158) | 108 / 111 / 118 / 119 (137) |
| work 2 | 112 / 128 / 138 / 140 (141) | 101 / 105 / 114 / 117 (128) |
| work 3 | 110 / 127 / 139 / 144 (144) | 104 / 107 / 115 / 118 (126) |
| idle | 60 / 61 / 63 / 63 | 64 / 65 / 65 / 65 |

- At h12, jemalloc work nodes averaged ~20% lower RSS (mean 118.0 vs 147.3 MB;
  per-node: work 1 −25%, work 2 −16%, work 3 −18%) and returned 8–18 MB below
  HWM; glibc stayed at or within 1 MB of HWM.
- Idle nodes were flat on both planes (jemalloc idle 2–4 MB higher).
- CPU cost of jemalloc was within noise (+1 CPU-s/h per node), with 4–5 more
  threads.
- After the h8 load cut, growth slowed on both planes (h9–12: glibc +0.8 to
  1.2 MB/h; jemalloc +0.4 to 1.0 MB/h). On the jemalloc plane, because
  `dirty_decay_ms=1000` and `muzzy_decay_ms=0` release unused pages promptly,
  this residual rise is inferred to be live working set rather than allocator
  retention; a slow shared working-set rise remains open on both builds.
- **Limits:** One VM, loopback `netem`, 3-node groups, ~1/20 of the 26 h soak
  gossip byte volume (offered DM rate was ~half: ~349/h vs ~649/h in W1), idle
  nodes had 0 peers, 12 h duration.

---

## 3. Release binary allocator verification (`v0.50.1`)

- **`x0x-linux-arm64-gnu` (`aarch64` Linux VM):** PASS —
  `_RJEM_MALLOC_CONF=stats_print:true x0xd --version` confirmed
  `Page size: 65536`, `opt.background_thread: true`, `opt.dirty_decay_ms: 1000`,
  `opt.muzzy_decay_ms: 0`.
- **`x0x-macos-arm64`:** PASS — starts and reports
  `allocator: { name: jemalloc, background_thread: false, dirty_decay_ms: 1000, muzzy_decay_ms: 0 }`.
- **Remaining before closing #1172:** One start check of the released
  `x0x-linux-x64-musl` binary.
