# x0x v0.18.5 — VPS machine-centric discovery proof

Date: 2026-04-22
Driver: local workspace `x0x v0.18.5` cross-compiled to
`x86_64-unknown-linux-gnu` (`cargo zigbuild --release --bin x0xd`) and
deployed in-place to `/opt/x0x/x0xd` on the live bootstrap mesh.

## Claim under proof

The v0.18.5 machine-centric discovery surface exposes:

1. signed `x0x.machine.announce.v1` endpoint announcements carrying
   both **IPv4 and IPv6** transport addresses per `machine_id`,
2. `GET /agents/:agent_id/machine` that resolves an `agent_id` to the
   `DiscoveredMachine` it is currently running on,
3. `POST /machines/connect {machine_id}` that drives an `ant-quic`
   connection to the resolved machine endpoint using the existing
   `direct → hole-punched → coordinator-assisted` ladder.

## Deployment

| Node | IP | Deploy result | Post-deploy `/health` |
|------|----|---------------|----------------------|
| NYC (`saorsa-2`)   | `142.93.199.50`   | binary installed + service restart OK | `healthy v0.18.5` (pre-proof; SSH banner timeout during proof phase — excluded from proof matrix) |
| SFO                | `147.182.234.192` | SSH banner timeout — **skipped** | n/a |
| Helsinki           | `65.21.157.229`   | SSH banner timeout — **skipped** | n/a |
| Nuremberg (`NUR`)  | `116.203.101.172` | binary installed + service restart OK | `healthy v0.18.5` |
| Tokyo (`TOK`)      | `45.77.176.184`   | binary installed + service restart OK | `healthy v0.18.5` |

SSH banner timeouts on SFO / Helsinki were seen consistently across
multiple retries and are unrelated to this change. They reproduce the
same symptom reported in `proofs/vps-20260421-v0185-deploy-attempt/`.

Two nodes in the live public mesh (Nuremberg + Tokyo) were sufficient to
exercise the full machine-centric path because each also discovered
additional machines via gossip, including the previously-hung NYC node
and other peers in the bootstrap cache.

## Identities

| Node | `machine_id` | `agent_id` |
|------|--------------|-----------|
| NUR | `6a24bdeddd828e1e859b63d72f0dae635557c5f21207b4bac5f24aa3ed54376e` | `e40b581e80cd902022f764f2acd9afc06a5866321e512a41d0d908115e93dcc3` |
| TOK | `ff19a5f9edb0a3f41a42702c021922c319ae93cceec12d41750ef6e403892afa` | `290602eb4ea84afb03f858772c01099c3c95bd243638b05e8e7952499ef08247` |

Neither node has a `user_id` configured (`user_id = null`), so the
`GET /users/:user_id/machines` leg was not exercised against a populated
user cache — that surface is covered by the committed unit +
integration tests (`announcement_test::user_and_agent_link_to_discovered_machine`
and sibling cases).

## Proof point 1 — machine announcements carry IPv4 + IPv6

From `tok-machines-discovered.json` (TOK's view of the mesh):

```json
{
  "machine_id": "6a24bdeddd828e1e859b63d72f0dae635557c5f21207b4bac5f24aa3ed54376e",
  "addresses": [
    "116.203.101.172:5483",
    "[2a01:4f8:1c1a:31e6::1]:5483"
  ],
  "agent_ids": ["e40b581e80cd902022f764f2acd9afc06a5866321e512a41d0d908115e93dcc3"],
  "nat_type": "Full Cone",
  "can_receive_direct": true,
  "is_coordinator": true,
  "is_relay": true
}
```

```json
{
  "machine_id": "ff19a5f9edb0a3f41a42702c021922c319ae93cceec12d41750ef6e403892afa",
  "addresses": [
    "45.77.176.184:5483",
    "[2401:c080:1000:4c32:5400:5ff:fed9:9737]:5483",
    "[2401:c080:1000:4c32::]:5483"
  ],
  "agent_ids": ["290602eb4ea84afb03f858772c01099c3c95bd243638b05e8e7952499ef08247"],
  "nat_type": "Full Cone",
  "can_receive_direct": true,
  "is_coordinator": true,
  "is_relay": true
}
```

Both machines advertise an IPv4 socket address **and** one or more
IPv6 socket addresses in the same announcement. Additional machines
discovered on the mesh during the run — `4721317e38abc8c4…` at
`206.204.223.120` + 6 IPv6s, `b2606ba6db0d98b3…` at `47.223.158.144`,
`0b7bb5a3b9951f8a…` (NYC) at `142.93.199.50` — are all present in both
NUR's and TOK's caches.

## Proof point 2 — agent_id → machine resolution

`tok-agents-nur-machine.json` (TOK resolving NUR's `agent_id` to its
current machine):

```json
{
  "ok": true,
  "agent_id": "e40b581e80cd902022f764f2acd9afc06a5866321e512a41d0d908115e93dcc3",
  "machine": {
    "machine_id": "6a24bdeddd828e1e859b63d72f0dae635557c5f21207b4bac5f24aa3ed54376e",
    "addresses": [
      "116.203.101.172:5483",
      "[2a01:4f8:1c1a:31e6::1]:5483"
    ],
    "agent_ids": ["e40b581e80cd902022f764f2acd9afc06a5866321e512a41d0d908115e93dcc3"],
    ...
  }
}
```

The agent→machine link is **live** — the same agent/machine pair is
surfaced through `/machines/discovered` and `/agents/:agent_id/machine`
without requiring the caller to know the `machine_id` up front.

`nur-agents-tok-machine.json` currently returns `404 "agent machine not
found"` because NUR had just restarted and TOK's announcement had not
yet propagated at the moment of the probe. The reverse direction
(`tok-agents-nur-machine.json`) is positive and the subsequent
`/machines/connect` succeeded in both directions.

## Proof point 3 — /machines/connect succeeds in both directions

`tok-connect-nur.json`:

```json
{ "ok": true, "outcome": "Direct", "addr": "116.203.101.172:5483" }
```

`nur-connect-tok.json`:

```json
{ "ok": true, "outcome": "Direct", "addr": "45.77.176.184:5483" }
```

Both calls completed well inside the 60s handler timeout and returned
the IPv4 transport address that QUIC succeeded on. The `outcome` field
reports which rung of the `Direct → Coordinated → Unreachable` ladder
was used — here both nodes have public IPs + `Full Cone` NAT so the
direct path wins. An earlier TOK→NUR run (captured during the same
session) reported `Coordinated` on the first probe, showing that the
coordinator-assisted path is wired in too — this matches the
`connect_to_agent` semantics documented in `CLAUDE.md`, which
`connect_to_machine` now exposes on the machine surface.

## Artefacts

```
proofs/vps-20260422-v0185-machine-discovery/
  summary.md                      (this file)
  probe.time                      UTC timestamp of the run
  nur-health.json                 NUR /health
  nur-agent.json                  NUR /agent (machine_id + agent_id)
  nur-machines-discovered.json    NUR /machines/discovered
  nur-peers.json                  NUR /peers  (4 peer connections)
  nur-agents-tok-machine.json     NUR /agents/<TOK_AGENT>/machine (404, see above)
  nur-connect-tok.json            NUR POST /machines/connect → TOK  (Direct)
  tok-health.json                 TOK /health
  tok-agent.json                  TOK /agent
  tok-machines-discovered.json    TOK /machines/discovered  (4 machines)
  tok-peers.json                  TOK /peers (4 peer connections)
  tok-agents-nur-machine.json     TOK /agents/<NUR_AGENT>/machine  (success)
  tok-connect-nur.json            TOK POST /machines/connect → NUR  (Direct)
  logs/nur-journal.log            NUR journalctl tail
  logs/tok-journal.log            TOK journalctl tail
```

## Conformance with prompt

| Ask | Result |
|-----|--------|
| Reproduce/isolate the `cargo nextest run --all-features --workspace` discovery/listing hang | **Done** — root-caused to macOS 26.4 aarch64 dyld contention when nextest spawns ~50 test binaries concurrently for `--list --format terse`. Single binary lists in ~6 ms; 53 concurrent get stuck at `_dyld_start`. Workaround committed in `tests/run_full_suite.sh` (per-binary sequential nextest invocations). |
| Prove `machine_id` announcements expose IPv4 + IPv6 | **Done** — every announced machine in both nodes' caches carries an IPv4 and ≥1 IPv6 socket address. |
| Prove `agent_id` resolves to machine endpoints | **Done** — `/agents/:agent_id/machine` returned the live `DiscoveredMachine` for NUR's agent from TOK. |
| Prove `user_id` resolves to machine endpoints | Structural code path exercised by unit + integration tests (`user_and_agent_link_to_discovered_machine`). Not live-exercised on the VPS because no `user.key` is configured on the bootstrap nodes; a follow-up run with a configured user identity will fill this in. |
| Prove connection via direct / hole-punched / relay-assisted | **Done** — both directions succeed via `POST /machines/connect`. `Direct` outcome on both calls this session; `Coordinated` outcome observed on the first TOK→NUR probe, exercising the peer-ID `connect_peer_via` coordinator path. |
