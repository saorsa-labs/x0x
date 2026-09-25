# ADR 0074: Tailnet Phase 2 — Names, Persistent Forwards, SOCKS5 and Open-Stream Revocation

- **Status:** Proposed
- **Date:** 2026-09-25
- **Decision owners:** David Irvine (decisions listed under "Open questions"); Claude (drafting)
- **Reviewers:** cross-model (omp) review required; acceptance by David Irvine only
- **Supersedes:** none
- **Superseded by:** none
- **Extends:** ADR 0020 and ADR 0022 (edits neither). It decides the ADR 0020 "Phase 2
  deferrals" list. It builds on ADR 0070 (owner trust, `ShareGrant`, ACL overlay).
- **Vision requirement:** R4, "a better-than-Tailscale ability to connect to our own
  computers, and to others' who allow us to connect to theirs". Also R3 (my machines),
  R5 (sharing with another human) and R7 (machine-resident agents reachable).
- **Related:** #132, #405; ADR 0019, 0036, 0070, 0071, 0072; PR #911, PR #920 (ADR 0070
  slices 1–2, draft); `src/forward.rs`, `src/streams.rs`, `src/connect/`,
  `src/cli/commands/forward.rs`, `tests/tailnet_streams_integration.rs`,
  `tests/forward_v2_attestation_e2e.rs`, `tests/e2e_tailnet_forward.sh`

## Context

On `origin/main` today:

- **Forwards address peers by hex only.** `x0x forward add --peer <hex>` and
  `ForwardSpec.peer_agent: AgentId`. ADR 0036 made names daemon state (`/profile`,
  announced agent self-name, `AgentCard.owner_name`), but nothing resolves a name to a
  peer. Announced names are self-asserted: anyone can announce `display_name = "laptop"`.
- **Forwards die with the daemon.** `ForwardService.forwards` is an in-memory `Vec`.
- **No dynamic ports.** Each remote port needs its own `forward add`. `StreamProtocol::
  SocksV1 = 0x02` is reserved in `src/streams.rs` with no acceptor.
- **Open streams outlive revocation.** The accept path re-checks revocation before the
  header read (`revoked_mid_flight`), but an already-bridged stream runs until it ends.
  ADR 0020 names this Phase-2 work.
- **ACL targets are exact.** `ConnectAllowEntry.targets: Vec<SocketAddr>`, loopback only.
  ADR 0070 adds `principal = "owner" | "grant"` and a REST-edited overlay (#911, #920,
  both unmerged).
- **Nothing tailnet runs in CI.** The 8 `#[ignore]` tests in
  `tailnet_streams_integration.rs` and the one in `forward_v2_attestation_e2e.rs` are
  not selected by any workflow. ADR 0071 records that the relayed-forward proof (#132)
  is still owed. #405 documents a real network where the relayed path is the only path
  (David's ISP drops UDP from Hetzner, so Mac ↔ Helsinki is MASQUE-relayed or nothing).

Tailscale's user-visible advantages over this are: names, set-and-forget connections,
any port without per-port setup, node sharing, and revocation that takes effect. x0x's
advantages (PQC end to end, no coordination server, NAT traversal without DERP operators,
per-port default-closed ACLs) exist but are unproven in CI.

## Decision Drivers

- User value against Tailscale first; each slice must be usable on its own.
- Keep every ADR 0020/0022 invariant: the identity gate inside open/accept, the connect
  ACL second, loopback-only targets, numeric IPs only at the target.
- No new wire protocol, crypto, DHT or coordination server (ADR 0072 scope freeze).
- Reuse ADR 0070 (owner trust, `ShareGrant`, overlay persistence) instead of inventing
  a parallel sharing or storage mechanism.
- A name must never silently point at a different key than the user meant.

## Considered Options

1. **Names, persistent forwards, SOCKS5 front-end, open-stream teardown, sharing via
   ADR 0070** (chosen). Userspace only; works unprivileged on every OS.
2. **TUN + virtual IPs + MagicDNS now** (Tailscale parity by imitation). Rejected for
   this ADR: needs a privileged driver per OS, an address allocator and an OS resolver
   hook, and breaks the unprivileged daemon-only install. See "Still deferred".
3. **SOCKS5 as a new wire protocol on the reserved `SocksV1` byte.** Rejected: SOCKS is
   only a different way to pick the target locally. A SOCKS `CONNECT` becomes an
   ordinary attested `ForwardV2` stream, so the peer needs no new acceptor and no new
   gate. `0x02` stays reserved.
4. **Names from announced self-names alone.** Rejected: self-asserted, so an impostor
   announcing the same name could capture a forward.

## Decision

### 1. Names (first: the largest daily-use gap)

- Syntax `<agent>.<owner>`, DNS-label rules (lowercase `[a-z0-9-]`, ≤63 per label),
  optional `.x0x` suffix. `<owner>` may be `me`. Hex `AgentId` stays valid everywhere.
- **Owner label → `UserId` is a local binding, never a network claim:** `me` is the
  local owner (ADR 0036); any other label must be a local petname for a `UserId`, set
  when importing a contact or accepting a `ShareGrant` (default: the announced
  `owner_name`, frozen at first bind, editable only by the local owner).
- **Agent label → `AgentId`:** among agents whose valid, unexpired `AgentCertificate`
  chains to that `UserId`, match the announced self-name. For `me` the candidate set is
  `GET /owner/agents`. Resolution is local and makes no network query.
- **Failure is loud:** `UnknownName` (no candidate), `AmbiguousName` (two or more; lists
  the hex ids; the user must use hex), `UnverifiedOwner` (no valid certificate chain).
  A name is a lookup; the identity gate still decides.
- Forwards, `/streams` and SOCKS accept names. Resolution happens at `forward add` and
  stores the resolved `AgentId` beside the name (see §2).
- MagicDNS-style OS resolution stays a later option (§6).

### 2. Persistent forwards

- Forwards persist in `<data_dir>/forwards.json`: versioned JSON, `deny_unknown_fields`,
  written with `storage::write_private_bytes_durable` (temp file, fsync, `0600`, atomic
  rename), the same format and helper as the ADR 0070 ACL overlay in #920.
- Each record holds `{id, local_addr, name?, pinned_agent_id, target_port}`. On
  restart the daemon rebinds the listener and re-resolves the name. If the name now
  resolves to a different `AgentId` the forward stays down with status `name_changed`
  (known_hosts semantics; the user re-pins). A port-in-use or unresolvable name gives a
  per-forward `error` in `GET /forwards` and never blocks startup.
- `DELETE /forwards/:id` deletes the record. Default persistence is Q3.

### 3. SOCKS5 front-end

- An optional listener, configured as `[socks] listen = "127.0.0.1:1080"`. The bind
  address must be loopback (the loader refuses otherwise). Off by default (Q6).
- RFC 1928 `CONNECT` only, `NO AUTH` (loopback bind is the boundary, as for forwards).
  `BIND` and `UDP ASSOCIATE` get reply `0x07`. Only `DOMAINNAME` addresses of the form
  `<agent>.<owner>.x0x` are accepted; IP-address and other-name requests get `0x08`
  or `0x04`. x0x is not an exit node.
- A `CONNECT <agent>.<owner>.x0x:P` resolves the name (§1) and opens a `ForwardV2`
  stream to target `127.0.0.1:P`. The peer applies the unchanged connect gate. A denial
  maps to reply `0x02`, with zero bytes sent to the target.
- To make "any port on my other machine" work, `principal = "owner"` entries may list
  loopback port ranges (Q4). Grant entries stay limited to `Connect{ports}`.

### 4. Open streams close on revocation

- `ForwardService` keeps a registry of bridged streams: peer `(AgentId, MachineId)`,
  target, and the matching principal (`exact`, `owner`, or `grant(grant_id)`).
- Triggers: a revocation-set insert (ADR 0018), grant revoke or expiry, ACL reload,
  contact downgrade or `Blocked`, owner enrollment removal. Each trigger re-runs
  `stream_gate` and `evaluate_connect_gate` on every live stream. On deny, both QUIC
  halves and the local TCP socket are reset, and `torn_down_reauth` is counted.
- **Bound:** a stream is closed ≤5 s after the exposing daemon applies the triggering
  event, and ≤35 s after a grant's `expiry` (30 s sweep plus slack) (Q5). Gossip
  propagation to that daemon is not covered by the bound. Grant expiry bounds it.
- Both ends enforce; the exposing side is the security boundary.

### 5. Sharing a machine with another human

There is no new mechanism. The owner issues an ADR 0070 `ShareGrant{agents:[agent
resident on that machine], caps:{Connect{ports}}}` and adds a `principal = "grant"`
connect entry. The grantee reaches it as `<agent>.<petname>` by forward or SOCKS.
Revoking or expiring the grant closes open streams (§4). Grants share agents, not
machines (ADR 0070 non-goal). "Share a machine" means sharing its resident agent.

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

- Everyday R4 use becomes `ssh -o ProxyCommand` or `curl --socks5-hostname` to
  `laptop.me.x0x`, with no hex and no per-port setup, and it survives reboots.
- Revocation takes effect on live sessions, which Tailscale's key expiry does not
  guarantee per flow.
- Sharing with another human is one grant, reusing ADR 0070 end to end.

### Negative / Trade-offs

- Owner port ranges widen what one ACL entry allows. They are limited to
  owner-trusted pairs and loopback.
- Petnames add local state and a first-bind trust decision (like SSH TOFU).
- Every trigger re-evaluates all live streams. Cost is O(streams) per event, bounded
  by the existing inbound/outbound permit caps.
- Depends on ADR 0070 slices 1–3 (#911, #920, grants) for owner/grant principals.
  §1 (for hex and `me`), §2 and exact-target SOCKS do not.

### Neutral / Operational

- New config `[socks]`, new file `forwards.json`, new counters `torn_down_reauth` and
  `socks_denied`. `/streams` entries gain `path: direct|relayed` from ant-quic connection
  state (needed for §7 evidence).
- `SocksV1` (0x02) remains reserved and unassigned.

## Validation

**Slicing** (each slice ships alone with an intent test that includes its negative case):

0. **CI + #132 proof first.** Add a `tailnet` job to `integration.yml`:
   `nextest-isolated.sh --all-features --test tailnet_streams_integration --test
   forward_v2_attestation_e2e -- --run-ignored ignored-only --no-tests=fail`, then close
   #132 with the relayed run below on current code. Everything later rests on this.
1. **Names** (§1). Tests: an impostor with the same self-name and a different owner is
   not resolved; ambiguity errors; `me` resolves only certified agents.
2. **Persistent forwards** (§2). Tests: survives restart; a re-pinned name stays down.
3. **Open-stream teardown** (§4). This comes before SOCKS and sharing because those widen
   exposure. Tests: revocation and grant expiry close a live stream within the bound.
4. **SOCKS5** (§3). Tests: an allowed port works; a disallowed port returns `0x02` with
   zero target bytes; a non-loopback bind is refused.
5. **Sharing** (§5), after ADR 0070 slice 3. Tests: grantee `:22` allowed, `:80` denied,
   denied after revoke.

**Cross-NAT acceptance `tailnet-r4-e2e`** (extends `tests/e2e_tailnet_forward.sh`). It
runs two pairs: a *direct* pair (two DO testnet nodes) and a *relayed* pair (David's Mac
on the #405 ISP ↔ Helsinki). The relayed pair must report `path=relayed` in ≥95% of
sessions or the run is INCONCLUSIVE, not a pass. Per pair:

- ≥19/20 forward sessions by name establish. Connect p95 ≤3 s direct, ≤6 s relayed.
- 64 MiB each way with SHA-256 match (100%). Throughput floor ≥10 Mbit/s direct and
  ≥2 Mbit/s relayed. These are initial floors, raised only by amendment.
- An SSH session idles 30 min and stays up.
- `systemctl restart x0xd` on the opener: the forward is back ≤30 s after `/health`.
- SOCKS to 3 allowed ports succeeds; 1 disallowed port is refused, zero target bytes.
- Revocation mid-transfer closes the stream ≤5 s after the exposing daemon applies it.
- Negatives: unknown, ambiguous and impostor names are refused, with zero bytes sent.

Review trigger: non-loopback targets, a privileged driver, or names resolved from
network claims alone need a new ADR.

## Open questions (David)

Q1 agent vs machine names · Q2 owner-label binding · Q3 persistence default · Q4 owner
port ranges · Q5 teardown bounds · Q6 SOCKS default. Options are in the PR description.

## Notes for AI-assisted work

AI tools may draft this ADR but **must not mark it Accepted without human review**. The
ADR 0020 invariants (gate inside open/accept, loopback-only, two fail-closed layers in
fixed order) are unchanged. Verify every enforcement point against the real merged code
path, not a mirror test.
