# ADR 0074: Tailnet Phase 2 — Names, Persistent Forwards, SOCKS5 and Open-Stream Revocation

- **Status:** Accepted
- **Accepted:** 2026-09-25 by David Irvine (decisions Q1–Q6; status change applied by Claude at his instruction)
- **Date:** 2026-09-25
- **Decision owners:** David Irvine (decisions Q1–Q6, 2026-09-25); Claude (drafting)
- **Reviewers:** cross-model (omp) review required; acceptance by David Irvine only
- **Supersedes:** none
- **Superseded by:** none
- **Extends:** ADR 0020 and ADR 0022 (edits neither). It decides the ADR 0020 "Phase 2
  deferrals" list. It builds on ADR 0070 (owner trust, `ShareGrant`, ACL overlay).
- **Vision requirement:** R4, "a better-than-Tailscale ability to connect to our own
  computers, and to others' who allow us to connect to theirs"; also R3, R5, R7.
- **Related:** #132, #405; ADR 0019, 0036, 0041, 0070, 0071, 0072; PR #911, #920 (ADR
  0070 slices 1–2, draft); `src/forward.rs`, `src/streams.rs`, `src/connect/`,
  `tests/tailnet_streams_integration.rs`, `tests/e2e_tailnet_forward.sh`

## Context

On `origin/main` today:

- **Hex only.** `x0x forward add --peer <hex>`; ADR 0036 names exist (`/profile`,
  announced self-name) but nothing resolves them, and announced names are self-asserted.
- **Forwards die with the daemon.** `ForwardService.forwards` is an in-memory `Vec`.
- **No dynamic ports.** One `forward add` per port; `SocksV1 = 0x02` is reserved, unused.
- **Open streams outlive revocation.** Revocation is re-checked only before the header
  read (`revoked_mid_flight`); a bridged stream runs on (ADR 0020 Phase 2).
- **ACL targets are exact** loopback `SocketAddr`s. ADR 0070 adds `owner`/`grant`
  principals and a REST overlay (#911, #920, unmerged).
- **No tailnet test runs in CI** (9 `#[ignore]` tests unselected); the #132 relayed proof
  is owed (ADR 0071). #405: David's ISP drops Hetzner UDP, so Mac ↔ Helsinki is relay-only.

Tailscale leads on names, set-and-forget connections, any-port access, sharing and
revocation; x0x's advantages (PQC, no coordination server or DERP) are unproven in CI.

## Decision Drivers

- User value against Tailscale first; each slice must be usable on its own.
- Keep ADR 0020/0022 invariants: identity gate in open/accept, ACL second, loopback only.
- No new wire protocol, crypto, DHT or coordination server (ADR 0072 scope freeze).
- Reuse ADR 0070 (owner trust, `ShareGrant`, overlay persistence); no parallel mechanism.
- A name must never silently point at a different key than the user meant.

## Considered Options

1. **Names, persistent forwards, SOCKS5 front-end, open-stream teardown, sharing via
   ADR 0070** (chosen). Userspace only; works unprivileged on every OS.
2. **TUN + virtual IPs + MagicDNS now.** Rejected: privileged per-OS driver, address
   allocator, resolver hook; breaks the unprivileged install (§6).
3. **SOCKS5 on the reserved `SocksV1` byte.** Rejected: SOCKS only picks the target
   locally; a `CONNECT` becomes an ordinary `ForwardV2` stream, needing no new gate.
4. **Names from announced self-names alone.** Rejected: an impostor could capture them.

## Decision

### 1. Names for agents and machines (Q1, Q2)

- Syntax `[agent:|machine:]<label>.<owner>` (CLI/REST); SOCKS hostnames use
  `<label>[.agent|.machine].<owner>.x0x`. DNS-label rules (lowercase `[a-z0-9-]`, ≤63).
  `me`, `agent` and `machine` are reserved. Hex `AgentId` stays valid everywhere.
- **Owner label → `UserId` is a local, pinned petname** (Q2), never a network claim.
  `me` is the local owner (ADR 0036). Other labels are bound when importing a contact or
  accepting a `ShareGrant` (default: the announced `owner_name`), frozen at first bind
  and editable only by the local owner.
- **Agent label → `AgentId`:** among agents whose valid, unexpired `AgentCertificate`
  chains to that `UserId`, match the announced self-name (`me`: `GET /owner/agents`).
- **Machine label → `MachineId`:** own machines are those with a current ADR 0041
  `OwnerEnrollment` by the local owner, labelled by their ADR 0036 `machine_name` as
  synced across the owner's devices. A shared machine is one hosting an agent in a
  received `ShareGrant`, labelled at grant acceptance. Both are pinned at first bind.
  A machine target reaches **that machine's daemon**: the stream opens to the agent
  that daemon announces for that `MachineId` (for a shared machine, only a granted
  agent). The connect gate evaluates the real `(AgentId, MachineId)` pair, so the
  ACL principals (exact/`owner`/`grant`) apply unchanged.
- **Machine binding (review fix):** every pinned target (any `machine:` name, any
  persisted forward) must reach its pinned `MachineId`. Before the forward header is
  sent, `PeerStream::peer()` must equal it; on mismatch (agent moved, discovery changed)
  the stream is reset with zero header bytes and `machine_mismatch` is counted.
- **Failure is loud:** `UnknownName`, `UnverifiedOwner` (no valid chain or enrollment),
  `AmbiguousName` (two candidates of one kind; lists hex ids), and `AmbiguousKind` (a
  bare label names both an agent and a machine: refused, retry with `agent:`/`machine:`).
  Resolution is local, makes no network query, and the identity gate still decides.
- Forwards, `/streams` and SOCKS accept names. MagicDNS stays a later option (§6).

### 2. Persistent forwards

- Forwards persist in `<data_dir>/forwards.json`: versioned JSON, `deny_unknown_fields`,
  written with `storage::write_private_bytes_durable` (temp file, fsync, `0600`, atomic
  rename), the same format and helper as the ADR 0070 ACL overlay in #920.
- Each record holds `{id, local_addr, name?, kind, pinned_agent_id, pinned_machine_id,
  target_host, target_port}` (as `ForwardSpec`; `target_host` is the numeric loopback
  host, e.g. `::1`, re-validated on load). On restart the daemon rebinds and re-resolves. If the name now
  resolves to a different id the forward stays down as `name_changed` (known_hosts
  semantics; the user re-pins). A busy port or unresolvable name gives a per-forward
  `error` in `GET /forwards` and never blocks startup.
- Forwards persist by default; `--ephemeral` opts out (Q3). `DELETE /forwards/:id`
  deletes the record.

### 3. SOCKS5 front-end

- An optional listener, configured as `[socks] listen = "127.0.0.1:1080"`. The bind
  address must be loopback (the loader refuses otherwise). Off until configured (Q6).
- **Auth (Q7):** loopback is shared by every local user and process, so the bind alone
  is no boundary. Clients must use RFC 1929 username/password; the password is the
  daemon's API token from the same-user token file (the ADR 0057 trust boundary),
  compared in constant time. `NO AUTH` is refused (`0xFF`), a wrong token fails.
- RFC 1928 `CONNECT` only. `BIND` and `UDP ASSOCIATE` get `0x07`. Only `DOMAINNAME` addresses ending `.x0x` are accepted;
  IP addresses get `0x08`, unresolvable names `0x04`. x0x is not an exit node.
- `CONNECT <name>.x0x:P` resolves the name (§1) and opens a `ForwardV2` stream to
  `127.0.0.1:P`. The peer applies the unchanged connect gate; a denial maps to `0x02`
  with zero bytes sent to the target.
- Port ranges (Q4): `principal = "owner"` entries (own machines) may list loopback port
  ranges. Shared machines stay exact: grant entries match only `Connect{ports}`.

### 4. Open streams close on revocation

- `ForwardService` keeps a registry of bridged streams: peer `(AgentId, MachineId)`,
  target, and the matching principal (`exact`, `owner`, or `grant(grant_id)`).
- Triggers: a revocation-set insert (ADR 0018), grant revoke or expiry, ACL reload,
  contact downgrade or `Blocked`, owner enrollment removal. Each trigger re-runs
  `stream_gate` and `evaluate_connect_gate` on every live stream. On deny, both QUIC
  halves and the local TCP socket are reset, and `torn_down_reauth` is counted.
- **Bound:** a stream is closed ≤5 s after the exposing daemon applies the triggering
  event, and ≤35 s after a grant's `expiry` (30 s sweep plus slack) (Q5). Gossip
  propagation to that daemon is outside the bound; grant expiry bounds it.
- Both ends enforce; the exposing side is the security boundary.

### 5. Sharing a machine with another human

There is no new mechanism. The owner issues an ADR 0070 `ShareGrant{agents:[agent
resident on that machine], caps:{Connect{ports}}}` and adds a `principal = "grant"`
connect entry. The grantee reaches it as `<agent>.<petname>` or `machine:<label>.
<petname>` (§1) by forward or SOCKS. Revoking or expiring the grant closes open streams
(§4). Grants still share agents (ADR 0070); a machine name only resolves to a granted agent.

### 6. Still deferred

| Item | Why not now | Revisit when |
|---|---|---|
| TUN / virtual IPs | Privileged driver per OS, IP allocator, breaks unprivileged install | A recorded user need that SOCKS and forwards cannot meet (UDP apps, apps with no proxy support), plus a per-OS privilege plan |
| MagicDNS | Needs an OS resolver hook. §1 names cover CLI and SOCKS | Names ship and are used, and there is a resolver plan that needs no root |
| Subnet routers | Break loopback-only (ADR 0019/0020). Expose third-party LAN hosts. Rebinding risk | After an adversarial review of a non-loopback ACL grammar |
| Exit nodes | Turn peers into open internet proxies. Abuse and bandwidth cost. Relay work is frozen (ADR 0071) | A dedicated ADR with metering, after ADR 0071's freeze lifts |
| SOCKS `UDP ASSOCIATE` | No UDP forwarding exists | Voice/datagram lanes (ADR 0073) prove a UDP path |

## Consequences

### Positive

- R4 use: `curl` via token-authed SOCKS to `studio.machine.me.x0x:8080`; no hex or
  per-port setup; survives reboots; revocation reaches live sessions; sharing is one grant.

### Negative / Trade-offs

- Owner port ranges widen one ACL entry (owner-trusted pairs and loopback only).
- Petnames add a first-bind trust decision (SSH TOFU); SOCKS clients need the API token.
- Each trigger re-evaluates all live streams: O(streams), bounded by the permit caps.
- Owner/grant principals and machine names depend on ADR 0070 slices 1–3 (#911, #920).

### Neutral / Operational

- New `[socks]` config, `forwards.json`, counters `torn_down_reauth`/`socks_denied`;
  `/streams` gains `path: direct|relayed` (acceptance evidence). `SocksV1` stays reserved.

## Validation

**Slicing** (each slice ships alone with an intent test that includes its negative case):

0. **CI + #132 proof first.** Add a `tailnet` job to `integration.yml`:
   `nextest-isolated.sh --all-features --test tailnet_streams_integration --test
   forward_v2_attestation_e2e -- --run-ignored ignored-only --no-tests=fail`, then close
   #132 with the relayed run below on current code. Everything later rests on this.
1. **Names** (§1). Tests: a same-name impostor of another owner is not resolved; `me`
   resolves only certified agents; a machine name resolves only for an enrolled (or
   granted) machine, and an unenrolled machine announcing the same `machine_name` is
   refused; an agent/machine label collision gives `AmbiguousKind` until prefixed.
2. **Persistent forwards** (§2). Tests: survives restart (agent and machine names);
   `--ephemeral` does not; a re-pinned name stays down; a `::1` target round-trips; a
   stream whose `peer()` differs from the pinned machine is reset with zero header bytes.
3. **Open-stream teardown** (§4). This comes before SOCKS and sharing because those widen
   exposure. Tests: revocation and grant expiry close a live stream within the bound.
4. **SOCKS5** (§3). Tests: an allowed port works; a disallowed port returns `0x02` with
   zero target bytes; a non-loopback bind is refused; `NO AUTH`, an absent or a wrong
   token are refused before any stream opens; the right token is accepted.
5. **Sharing** (§5), after ADR 0070 slice 3. Tests: grantee `:22` allowed, `:80` denied,
   denied after revoke.

**Cross-NAT acceptance `tailnet-r4-e2e`** (extends `tests/e2e_tailnet_forward.sh`). It
runs two pairs: a *direct* pair (two DO testnet nodes) and a *relayed* pair (David's Mac
on the #405 ISP ↔ Helsinki). The relayed pair must report `path=relayed` in ≥95% of
sessions or the run is INCONCLUSIVE, not a pass. Per pair:

- ≥19/20 forward sessions establish (10 by agent name, 10 by machine name). Connect
  p95 ≤3 s direct, ≤6 s relayed.
- 64 MiB each way with SHA-256 match (100%). Throughput floor ≥10 Mbit/s direct and
  ≥2 Mbit/s relayed. These are initial floors, raised only by amendment.
- An SSH session idles 30 min and stays up.
- `systemctl restart x0xd` on the opener: the forward is back ≤30 s after `/health`.
- SOCKS via `<machine>.machine.me.x0x` to 3 ports in an owner range succeeds; a port
  outside it, and a shared-machine port outside `Connect{ports}`, get `0x02`, zero bytes.
- Revocation mid-transfer closes the stream ≤5 s after the exposing daemon applies it.
- Negatives: unknown, ambiguous, ambiguous-kind and impostor names are refused.

Review trigger: non-loopback targets, privileged drivers or network-claimed names.

## Decisions (David Irvine, 2026-09-25)

Q1 names address **both agents and machines** (§1). Q2 owner labels are **local
petnames, pinned**. Q3 forwards **persist by default**, `--ephemeral` opts out. Q4 port
ranges **on own machines only**, exact ports for shared machines. Q5 close **≤5 s after
revoke, ≤35 s after grant expiry**. Q6 SOCKS listener **off until configured**.

Q7 (David Irvine, 2026-09-26): **SOCKS auth = API token** (§3). Review fixes (Codex,
2026-09-26): pinned forwards enforce the pinned `MachineId` (§1); persisted records
carry `target_host` (§2).

## Notes for AI-assisted work

Accepted ADRs are immutable; changes need a superseding ADR. ADR 0020 invariants are
unchanged. Verify each enforcement point against the real merged code path.
