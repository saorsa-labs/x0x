# X0X-0021 Nuremberg Reachability Gap Investigation

Window: 2026-05-04 06:16-07:18 UTC during
`proofs/launch-readiness-soak-20260503T201513Z`.

## Classification

Root-cause category: **single-VPS/path reachability gap, not PubSub
dispatcher saturation**.

The evidence is not strong enough to blame a published Hetzner or
DigitalOcean incident. It is strong enough to rule out the overload class
that X0X-0009/X0X-0010 addressed: during the gap, Nuremberg's
`dispatcher.pubsub.timed_out` and `recv_pump.pubsub.dropped_full`
counters stayed flat.

Because production cannot rely on degraded nodes "being ignored", the
soak harness should continue to treat Phase A gaps as **NO-GO**. X0X-0020
only tolerates dispatcher-only transient windows; it does not soften
directed-pair reachability failures.

## Local Evidence

Phase A failures were concentrated on directed pairs to or from
Nuremberg:

| Window | Probe time UTC | Phase A | Pattern |
|---:|---|---:|---|
| 18 | 05:45-05:46 | 30/30 | Clean before gap |
| 19 | 06:15-06:17 | 20/20 | Nuremberg not discovered; one Sydney command DM timeout |
| 20 | 06:45-06:48 | 15/12 | Nuremberg discovered, but every selected send to/from Nuremberg timed out |
| 21 | 07:15-07:18 | 22/20 | Nuremberg discovered, but every selected send to/from Nuremberg timed out |
| 22 | 07:45-07:46 | 30/30 | Clean after self-heal |

Nuremberg diagnostics across the same windows:

| Window | Snapshot | dispatcher.timed_out | dropped_full | latest_depth | per_peer_timeout | suppressed | known scores | workers |
|---:|---|---:|---:|---:|---:|---:|---:|---:|
| 18 | post | 1 | 0 | 1 | 18808 | 127 | 1288 | 29 |
| 19 | post | 1 | 0 | 1 | 19382 | 123 | 1441 | 26 |
| 20 | post | 1 | 0 | 65 | 19971 | 134 | 0 | 32 |
| 21 | post | 1 | 0 | 17 | 20519 | 121 | 1359 | 32 |
| 22 | post | 1 | 0 | 1 | 20986 | 134 | 1422 | 31 |

The temporary depth increase in windows 20-21 is real, but it cleared
without drops or dispatcher watchdog timeouts. That makes the event a
reachability/control-plane gap rather than a recv-pump saturation event.

Live host check after the soak:

```text
ActiveState=active
SubState=running
ActiveEnterTimestamp=Sun 2026-05-03 18:56:32 UTC
up 125 days, 21:50
```

The service was not restarted during the gap window, and the host did
not reboot.

## Provider Status Check

Official Hetzner status for May 4 showed no general cloud/server or
backbone incident during 06:16-07:18 UTC. The only same-day planned FSN1
item visible in the status feed was Object Storage maintenance from
10:00-14:00 UTC, after the gap and for a different service class:
<https://status.hetzner.com/> and
<https://status.hetzner.com/incident/fec8b509-84c1-4e60-b155-87a406ea460b>.

DigitalOcean's May 4 status page showed no incident for the gap window.
The visible same-day maintenance was SFO2 networking and control-plane
maintenance starting at 13:00 UTC, also after the gap:
<https://status.digitalocean.com/>.

## Decision

Do not treat this as evidence that X0X-0009/X0X-0010 failed. The
dispatcher and drop counters were clean.

Also do not hide this in broad-launch evidence. A production launch gate
should distinguish the failure class in the summary, but a one-node
directed-pair reachability gap is still a NO-GO until the fleet can
repair or route around it within the advertised window.

X0X-0020 implements that split: dispatcher-only transient windows can be
tolerated cumulatively, while Phase A reachability failures remain
effective failed windows.
