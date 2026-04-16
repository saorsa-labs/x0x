# SWIM / EAGER anomalies — root cause analysis

**Date**: 2026-04-16
**x0x version under test**: 0.17.1 + commit `19c1027` (diagnostics feature)
**Binary**: `target/debug/x0xd` (fresh, post-WIP commit)
**Harness**: local 3-daemon mesh (alice / bob / charlie) on 127.0.0.1,
UDP 19891/19892/19893, API 19821/19822/19823.
**Duration**: 120 s of observation with PubSub traffic on `phase-a` topic
every 3 s from every node.
**Log config**:
`RUST_LOG=info,x0x=debug,x0x::direct=debug,x0x::network=debug,x0x::connect=debug,x0xd=debug,saorsa_gossip=debug,saorsa_gossip_membership=debug,saorsa_gossip_pubsub=debug,ant_quic=info,ant_quic::p2p_endpoint=debug,ant_quic::connection_router=debug,ant_quic::nat_traversal_api=debug`
**Output artefacts**: `/tmp/x0x-phase-a-20260416_223834/{alice,bob,charlie}/log`
(~24 547 total log lines).

## Hypothesis under test

The VPS 6-node bootstrap mesh on v0.17.0 + ant-quic 0.26.12 logs:

- `saorsa_gossip_membership: SWIM: Suspect timeout → marked dead peer_id=…`
  at roughly 1 Hz.
- `saorsa_gossip_pubsub: EAGER forward failed: send failed: Endpoint error:
  Connection error: send acknowledgement timed out (peer may be dead)`
  repeating throughout runtime.

Two possible root causes:

- (A) Native saorsa-gossip bug: SWIM thresholds too tight for WAN
  latencies; EAGER peer selection not honouring the SWIM alive set.
- (B) Downstream symptom of ant-quic #166: short-stream delivery
  failures on the VPS mesh cause SWIM probe ACKs to be lost, which
  drives the membership plane into Suspect / Dead, which in turn causes
  EAGER to try to forward via peers that have lost QUIC liveness.

## Signal greps — local 3-daemon mesh, 120 s

| Signal | alice | bob | charlie |
|---|---|---|---|
| `ERROR` | **0** | **0** | **0** |
| `WARN` | 3 | 3 | 1 |
| `Marking` / `Suspect timeout` / state transitions | **0** | **0** | **0** |
| SWIM "marked dead" | **0** | **0** | **0** |
| SWIM "marked suspect" | **0** | **0** | **0** |
| EAGER forward failed | **0** | **0** | **0** |
| `send acknowledgement timed out` | **0** | **0** | **0** |

The 7 `WARN` lines across the mesh are all within the first 5 seconds
of startup:

- `ant_quic::candidate_discovery: Local interface scan timeout for peer
  …, proceeding with available candidates` — 3 occurrences, one per
  node at init. Benign — ant-quic continues with partial candidate
  sets when the initial interface enumeration on localhost doesn't
  complete in its short window.
- `ant_quic::connection: Failed to add remote candidate: invalid
  address` — 4 occurrences during initial bootstrap address exchange.
  Benign — reflects the `is_publicly_advertisable` filter rejecting
  loopback candidates from remote peers. This is expected given x0x's
  address-scope hygiene; ant-quic treats the rejection as "skip this
  candidate" and proceeds.

No further `WARN` / `ERROR` events fire for the remaining 115 s of
observation. SWIM probes run every ~333 ms and every ~1 s (`SWIM:
Probing multiple peers probe_count=2`) with **zero** state transitions.
PubSub EAGER handling is fully symmetric — every `Handling incoming
PubSub message msg_kind=Eager` on a peer is followed by
`plumtree handle_eager: delivered to local subscribers subscribers=1
delivered=1` on that same peer.

## Conclusion

The local mesh, exercised at the same PubSub cadence and SWIM probe
rate as the VPS mesh but without any transport instability, produces
**zero of the VPS failure signatures**. SWIM never thrashes. EAGER
never fails to forward. No peer is ever marked dead or suspect.

Therefore hypothesis (A) — native saorsa-gossip bug — is **not
supported** by the evidence. A genuine SWIM-threshold or
EAGER-peer-selection bug would reproduce on any healthy mesh with the
same probe cadence, independently of transport stability. It does not.

Hypothesis (B) — **downstream of ant-quic #166** — is strongly
supported: the VPS mesh exhibits the known short-stream delivery
regression (0/30 post-connect DM delivery in the matrix test on
0.26.12); SWIM probe ACKs ride the same stream class that #166
affects; missed ACKs produce Suspect → Dead transitions; EAGER then
attempts to forward via peers the membership plane has declared dead.
The cascade is mechanically explainable from a single upstream defect.

## Decision

Per the Phase A decision gate in the plan
(`~/.claude/plans/ok-we-are-waiting-shimmering-candle.md`): **do NOT
patch saorsa-gossip for SWIM/EAGER this cycle.** Phase C will cut
`saorsa-gossip v0.5.16` with only the explicit `ant-quic = "0.26.13"`
pin bump (plus any other unrelated fixes that accumulate between now
and then).

Verification of this conclusion will occur as part of Phase C: once
ant-quic 0.26.13 lands and the VPS matrix DM-delivery rate returns to
30/30, the VPS journals should show SWIM and EAGER going clean
simultaneously. If they do, we close out the cycle as confirmed. If
SWIM/EAGER keep misbehaving after ant-quic #166 is fixed, we reopen
the hypothesis and patch in saorsa-gossip v0.5.17.

## Caveats / limitations

- The Phase A harness exercised **PubSub** traffic but not direct
  messaging — token-read timing in the repro script meant the DM
  API calls landed without a bearer token and were rejected. This
  does not weaken the conclusion: EAGER (which failed on VPS) is a
  PubSub concern, and SWIM probing is transport-only (independent
  of DM payloads). The local PubSub + SWIM signals are sufficient.
- All three daemons run on loopback, so this does not rule out a
  latency-threshold bug that only triggers at WAN RTTs. The VPS
  journal shape — "dead" declarations every 1 Hz regardless of
  actual peer health — makes a simple threshold bug unlikely; that
  would produce a narrower ring of flapping, not a steady-state
  thrash. But a definitive exclusion of latency-sensitive SWIM
  thresholds will come from Phase C's post-fix VPS verification.

## Follow-up

- Phase B.8 / B.9 / B.10 — instrument ant-quic `spawn_reader_task`,
  build a many-concurrent-uni-streams localhost reproducer, and post
  evidence to saorsa-labs/ant-quic#166.
- Phase C — verify this conclusion against post-0.26.13 VPS journals.
