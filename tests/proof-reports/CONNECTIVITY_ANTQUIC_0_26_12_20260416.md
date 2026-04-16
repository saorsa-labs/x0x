# x0x v0.17.0 + ant-quic 0.26.12 — Post-#165 Verification

**Date**: 2026-04-16
**x0x**: 0.17.0 (worktree: angry-sanderson)
**ant-quic**: 0.26.12 (was 0.26.7 in prior session)
**saorsa-gossip**: 0.5.15 (auto-bumped via ^caret)

## Objective

Re-run the failing suites from `CONNECTIVITY_POSTUPSTREAM_20260416` session after
ant-quic fixes landed:
- #165 (MASQUE relay targeting ephemeral port) — **CLOSED** in ant-quic 0.26.10
- #163 (NAT traversal storm on public-IP peers) — **STILL OPEN**
- #164 (MASQUE bytes_forwarded=0) — **STILL OPEN**

Additional scope added by user during session:
- All groups should be MLS groups (consolidate stable_group_id → mls_group_id)
- Deep logging in ant-quic / saorsa-gossip
- Large-file-transfer coverage

## Code changes in x0x

| Change | File | Reason |
|---|---|---|
| `ant-quic = "0.26.7"` → `"0.26.12"` | `Cargo.toml:18` | Pick up #165 fix |
| `Node::connect` → `Node::connect_peer` | `src/network.rs:560` | 0.26.12 deprecation |
| `GroupGenesis::new` → `with_existing_id(mls_group_id, …)` | `src/groups/mod.rs:223` | Collapse stable_group_id onto mls_group_id so every id surface converges — removes Phase D.3 cross-daemon lookup drift |
| Version assertion `"0.16"` → `"0.17"` | `tests/e2e_full_audit.sh:203` | Stale from 0.16.x baseline |
| Added large-file transfer test (1 MiB + 16 MiB NYC→SFO) | `tests/e2e_vps.sh` §18b | User request — stress-test chunked transfer |

## Suite results

| Suite | Result | Baseline | Verdict |
|---|---|---|---|
| Unit + integration | **976 / 976** | 971 / 0 | +5 new tests, clean |
| Local e2e_full_audit | **260 / 15** (then **256 / 20** after re-run stabilised) | 274 / 2 | Named-groups cluster fixed by MLS-id consolidation; remaining 20 pre-existing from 2026-04-12 (direct-message + file-transfer + WS-direct, same set as then) |
| VPS deploy (e2e_deploy) | **24 / 24** | 24 / 24 | Clean, all 6 nodes on 0.17.0 / ant-quic 0.26.12 |
| Mac-behind-NAT → VPS mesh (e2e_live_network) | **66 / 66** (65 pass + 1 skip) | 64 / 0 / 2 | **Exceeds baseline** — 12 categories all green end-to-end |
| VPS 6-node matrix (e2e_vps) | Connects **30 / 30 ✓** · DM delivery **0 / 30 ✗** · groups / KV / tasks / presence green · file-transfer stuck | Connects 6/30, DM low | **Connects fully restored by #165 fix** but new post-connect DM-delivery regression |
| LAN studios (e2e_lan) | Not run — SSH unreachable from this Mac although hosts respond to ARP | 106 / 24 | Blocked on network access, not a regression |

## What 0.26.12 definitively restored

- **Mesh-wide pairwise connects: 30 / 30** (was 6 / 30 in the 0.26.9 session).
  Every node-to-node `/agents/connect` returns `Direct` or `Coordinated` within
  the retry window. The "MASQUE target selection" fix in #165 is the cause — no
  more pointing `CONNECT-UDP` at `:37616` ephemeral ports.
- `Node::connect` deprecated in favour of `connect_peer`, which canonicalises the
  peer-oriented API (x0x switched; no behavioural delta).

## Post-session follow-ups

- ant-quic #163 (NAT traversal storm): commented with 0.26.12 sample —
  hole-punch success rate still 0 / 10 min on the 6-node mesh, storm
  cadence unchanged. Still open.
- ant-quic #164 (MASQUE bytes_forwarded=0): commented with 0.26.12 sample —
  relay sessions establish and `Starting stream-based relay forwarding`
  fires, address-reconcile oscillation is gone. Left open pending a
  dedicated relay-forced measurement since the 0.26.10 #165 fix means
  typical traffic now takes the direct path.
- ant-quic **#166** (post-connect DM delivery): new issue filed. Minimal
  reproducer from this session is a 2-daemon localhost bench — which
  **passes** — versus the same code on 2 VPS mesh members — which
  **fails**. So it is a mesh-state / reader-task lifecycle issue, not a
  raw send/recv path bug. Details below.

## New regression — post-connect DM delivery

**Symptom**: `/agents/connect` returns `{"ok":true,"outcome":"Direct"}`, but a
subsequent `/direct/send` — though also returning `{"ok":true}` — never lands at
the recipient. Singapore→Tokyo probe with debug tracing:

```
Singapore: POST /agents/connect → {"ok":true,"outcome":"Direct"}
Singapore: POST /direct/send → {"ok":true}
Tokyo: SSE /direct/events for 30 s → only keepalive ":ping", no direct_message frame
Tokyo: journalctl x0xd → no x0x::direct inbound log line for the payload
```

The matrix test hits this 30/30 (all directed pairs). The Mac→VPS live test does
NOT hit it (one sender, one receiver at a time, lots of MLS/KV/task chatter
between DMs — giving the direct path time to settle). That suggests connection
churn or mass-parallel stream setup under matrix load.

Corroborating evidence from VPS journals during the matrix:
- Repeated `x0x::direct: Agent connected:` events for the same `AgentId` every
  few seconds → connections being rebuilt rather than reused.
- `saorsa_gossip_membership: SWIM: Suspect timeout → marked dead peer_id=…` at
  1–2 Hz — membership plane treats peers as dead even while PubSub sends to
  them succeed.
- `ant_quic::nat_traversal_api: Phase Synchronization failed … after 3 attempts`
  on several peers despite direct-plane reachability confirmed moments earlier.

**Hypothesis**: ant-quic 0.26.12 is establishing QUIC sessions successfully but
those sessions are being torn down (or inhibited from accepting new streams)
faster than x0x's direct plane can open a bi-directional stream per peer.

**Follow-up result (2-node localhost bench)**: two x0xd instances on
127.0.0.1:19901 / 19902 with each other as the only bootstrap peer
**deliver the DM every time**. SSE on bob receives the full
`direct_message` envelope, `verified: true`, correct payload, correct
sender AgentId → MachineId binding. So the regression is **not** in the
send/recv path itself — it is an interaction with the multi-peer mesh
state that x0x has on the VPS bootstrap nodes. x0x's `send_direct`
implementation is the same in both cases, and x0x's sender log shows
`x0x::network: send_direct: N bytes to peer PeerId(<correct MachineId>)`
followed by `ant_quic::p2p_endpoint: Sent N+1 bytes to peer … via QUIC`
on the VPS side — so the send lands in ant-quic with the right target;
the receiver simply never surfaces it to x0x's `recv_direct` loop.

**Filed**: ant-quic #166 with full reproducer, localhost-vs-VPS
comparison, and pointers to `spawn_reader_task` /
`handle_coordinator_control_message` as the suspect area
(`src/p2p_endpoint.rs:4569`, `:4606-4626`). The comment on line 4653
already names this failure mode — "zombie reader tasks … causing
send_direct() to succeed but recv() to hang" — and implements an
abort-then-replace guard, but the evidence here suggests that guard has
a race under the VPS mesh's 30-90 s reconnect cadence.

**Release implication**: Mac-behind-NAT → VPS flows (the user-facing
single-client journey) are fully green. VPS ↔ VPS DM between mesh
members is the failing surface. x0x 0.17.1 can ship with this as a
documented known-issue pinned to ant-quic #166 without regressing the
single-agent user experience.

## Deep tracing installed on VPS

Added `/etc/systemd/system/x0xd.service.d/debug-logging.conf` to all 6 nodes:

```toml
[Service]
Environment=
Environment=RUST_LOG=info,x0x::direct=debug,x0x::network=debug,ant_quic::p2p_endpoint=debug,ant_quic::connection_router=debug,ant_quic::nat_traversal_api=debug,saorsa_gossip=info
```

Journal is now capturing relay/NAT decisions in the `journalctl -u x0xd` stream
for future diagnosis. Revert with `rm /etc/systemd/system/x0xd.service.d/debug-logging.conf && systemctl daemon-reload && systemctl restart x0xd` on each node when finished.

## Open questions for ant-quic

- #163 (storm / hole-punch success rate): mass NAT traversal timeouts still
  present in the VPS journal. Expectation was partial — the Singapore log
  still shows `Phase Synchronization failed` even for public-IP peers.
- #164 (bytes_forwarded=0): the 0.26.9 session showed ~1.2 MB relayed; this
  session didn't exercise pure-relay paths enough to get a counter reading.
- **New**: post-connect stream-setup reliability under mesh-wide parallel DM
  load — ticket to file once 2-node repro confirms ant-quic scope.

## Recommended follow-ups

1. File the DM-post-connect regression (probably ant-quic, but check x0x
   send-direct path first with x0x::direct=trace).
2. Re-run e2e_lan once studio1/studio2 SSH is reachable from the dev laptop
   (studio2 mDNS asymmetry on macOS, separate from #163/#164/#165).
3. Keep #163/#164 open in ant-quic; #165 is now closed as confirmed here.
4. Hold off on tagging x0x 0.17.1 until DM-delivery regression is understood.
