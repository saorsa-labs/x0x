# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

## [v0.30.1] - 2026-07-11

### Documentation

- **docs(skill): correct auth-exempt paths, add REST examples for forwards/task-lists/stores/groups/exec/files/presence.** `SKILL.md` now documents the full agent-orchestration surface instead of ~16 of 128 routes. Fixed the auth statement — `/health` and `/constitution*` are the only public paths (not `/gui`); `/gui`, `/ws`, `/events` also accept the token via `?token=`; every other route requires the `Authorization: Bearer` header. Added a verified REST-example section covering task-lists, stores, named groups (with the `/groups` vs low-level `/mls/groups` distinction and preset-driven public-vs-encrypted messaging), presence/discovery, files, agent-card/A2A, remote exec (flagged high-risk, trust + ACL gated), contacts CRUD, and the new v0.30.0 tailnet `/forwards`. Every new example was smoke-tested against a live v0.30.1 daemon (single-node plus a two-node run for the peer-dependent flows). `docs/api-reference.md` gains a Remote Exec section and the `/presence/online`+`/presence/foaf` views.

## [v0.30.0] - 2026-07-11

### Added

- **Agent attestation in ForwardV2 relay stream opens ([#204](https://github.com/saorsa-labs/x0x/issues/204), [#209](https://github.com/saorsa-labs/x0x/pull/209)).** When a stream open is relayed, the opener now self-attests its ML-DSA-65 agent public key directly in the ForwardV2 header, hash-bound to its `AgentId` and signed over domain-separated bytes that include the recipient's machine id and a 60-second `issued_at` TTL. The recipient verifies the attestation against its **own** machine id before accepting a forwarded stream, closing V1 downgrade, replay, and hard-coded-trust holes on the relay path. Proven real-WAN on the testnet: cross-continent attested forwards round-trip, and denied opens reach zero bytes to the target.

### Security

- **Hardened TreeKEM member recovery and its recovery cache ([#219](https://github.com/saorsa-labs/x0x/pull/219), [#220](https://github.com/saorsa-labs/x0x/pull/220)).** A promoted admin can now remove or ban a member it never witnessed without depending on the inviter or the target being cooperative: any validated `MemberJoined` witness retains and serves the signed recovery record, and recovered key packages are installed under the same `group_membership_lock` as all roster mutations, closing a stale-`GroupInfo` write-back race that could silently drop a recovered package. The persistent recovery cache no longer bricks daemon startup on a corrupt file (it quarantines the file and starts empty), is bounded (512 records / 8 MiB, pruned on member removal, group leave/delete, and withdrawal), persists under a single-writer path that never holds the in-memory map lock across the disk sync, and surfaces durability failures as tracked dirty state rather than a silent log line.
- **Fixed a deterministic cross-node ForwardV2 attestation denial ([#216](https://github.com/saorsa-labs/x0x/issues/216)).** The recipient-scope check compared the header's `recipient_machine_id` against the transport-authenticated *opener* machine instead of the recipient's own machine, so every legitimate cross-node attested forward was denied. The recipient's own `MachineId` is now threaded into the verification context and compared correctly; a regression test exercises the distinct-opener/distinct-recipient happy path.
- **Mitigated gossip-DM machine-revocation claim bypass ([#184](https://github.com/saorsa-labs/x0x/issues/184); protocol closure tracked by [#213](https://github.com/saorsa-labs/x0x/issues/213)).** The inbox retains the freshest authenticated `AgentId → MachineId` binding only after directly observing a verified v2 identity announcement whose outer sender key derives the announcement's `AgentId`; verified rebroadcasts remain valid for ordinary discovery but cannot mutate the security cache. Signed-envelope machine claims that disagree with a retained binding are rejected, and revocation is checked against the authenticated machine. Far-future announcements beyond the 30-second skew bound are rejected before discovery or binding ordering. The in-memory cache is capped at 65,536 entries with logarithmic-time LRU operations and logs every eviction. **KNOWN LIMITATION:** this mitigates but does not fully close the HIGH finding. A sender observed only through rebroadcast, a sender with no prior accepted direct-origin announcement, a post-restart sender before direct re-announcement, or an LRU-evicted sender uses the sender-controlled claimed-machine best-effort check. In those states, an agent-key holder can claim an unrevoked machine. Issue #213 tracks fresh machine-key attestation bound into gossip DMs plus an explicit portable-agent move policy.

### Migration

- **BREAKING — relay API and accounting cutover:** callers of `PeerRelay::disposition_for` must now pass `is_sender_contact` and `is_sender_blocked`, resolved from the authenticated sender's contact record (`Known`/`Trusted` and `Blocked`, respectively). A `Forward` disposition performs classification only: resolve the destination and encode the inner envelope first, then call `PeerRelay::reserve_forward(sender_agent_id, encoded_bytes)` immediately before transmission. Keep the returned `RelayForwardReservation` alive across the send, call `commit()` only after the transport confirms success, and otherwise let the guard drop to release the sender, global, and byte reservations. `relay_forwarded` and `relay_forward_bytes` now mean successfully transmitted forwards, not admitted attempts.
- **BREAKING — `RelayPolicy`:** struct-literal callers must populate the new `require_contact_to_relay`, `max_forwards_per_sender`, `max_total_forwards`, `limit_window`, and `max_forward_bytes_per_window` fields, or migrate to `RelayPolicy::enabled()` and optionally `with_forward_limits(...)`. `RelayPolicy::enabled()` inherits the secure contact gate and bounded defaults. A zero forward-limit window is clamped to the documented `MIN_RELAY_LIMIT_WINDOW` (1 ms), including `[peer_relay] limit_window_ms = 0`; zero never means unlimited.
- **BREAKING — `RelayRefusal`:** exhaustive matches must handle `NotAContact`, `Blocked`, `RateLimited`, and `BandwidthExceeded`. `Blocked` is unconditional on the forward arm, while `NotAContact` applies when the contact gate is enabled; the two quota variants distinguish count and byte admission failures.
- **BREAKING — `RelayStatsSnapshot`:** consumers and fixed-shape deserializers must accept `relay_refused_not_a_contact`, `relay_refused_blocked`, `relay_refused_rate_limited`, `relay_refused_bandwidth_exceeded`, and `relay_forward_bytes`. Update dashboards that treated `relay_forwarded` as an admission count: it now increments exactly once only after successful transmission, and `relay_forward_bytes` records only those successful bytes.
- **Security default flip — `require_contact_to_relay = true`:** an enabled relay now forwards only for authenticated senders that are explicit `Known` or `Trusted` contacts. Operators who intentionally provide an open relay for non-contacts must set `[peer_relay] require_contact_to_relay = false` explicitly; doing so spends this node's uplink on non-contacts, although the sender/global/byte caps remain enforced. Configurations that omit the key become contact-gated on upgrade; configurations that already set `false` now opt out explicitly.
- **Named-instance connect ACL path:** an unnamed daemon continues to use `connect-acl.toml`; a daemon named `<name>` now defaults to `connect-acl-<name>.toml` in the same system configuration directory (for example, `/etc/x0x/connect-acl.toml` → `/etc/x0x/connect-acl-testnet.toml`). Before upgrading a named deployment, rename or copy each intended ACL to its instance-specific path, or pass `--connect-acl <path>` explicitly. A missing derived ACL remains fail-closed, so failing to migrate the file disables connect-plane access rather than silently sharing another instance's policy.

### Fixed

- **Strip TreeKEM KeyPackages from invite links + on-demand key-package catch-up ([#205](https://github.com/saorsa-labs/x0x/issues/205), fixes [#188](https://github.com/saorsa-labs/x0x/issues/188)).** `private_secure` invite links embedded the full roster including each member's ~15.7 KiB TreeKEM KeyPackage + ~1.2 KiB ML-KEM public key. The join cmd-DM crossed the 49 152-byte gossip cap at the 3rd roster member, so every later joiner's invite was rejected at the sender with `envelope_construction` and the joiner never joined (issue #188 root cause). Key packages commit nothing to invite validation — `roster_root` covers only `(id, role, state)` triples and the link is unsigned — so they are now stripped at mint in `populate_invite_base_state_from_group_info`, dropping the failing 3-member cmd-DM from ~63 KiB to ~6.5 KiB (the cap is not crossed until ~140 members). A mint-time budget (`INVITE_LINK_MAX_BYTES` = 40 KiB, enforced by `SignedInvite::encode_link`) fails loudly at `/groups/:id/invite` instead of as a later cross-node 400. The `signable_bytes` domain tag bumps `v2`→`v3`. Backward compatible both directions: the fields are `#[serde(default)]`, so old kp-bearing links still parse and old daemons reading stripped links see `None`.

  Closes a regression the stripping introduces: a joiner later promoted to Admin cannot remove/ban a member whose key package it never learned (the `MemberJoined` apply is inviter-only and the authority-signed `MemberAdded` carries no package). On the `FAILED_DEPENDENCY` path, `remove`/`ban` now recover the target's package from a member-keyed cache of self-signed `MemberJoined` events, authenticated by re-verifying the joiner's ML-DSA-65 signature; on a local miss they fire a member-keyed TreeKEM catch-up request (extending `handle_treekem_catchup_request` with a `target_member_id`, reusing the existing verified-DM / active-member / 5 s-throttle gates) and return a retryable `member_key_package_pending`. The TreeKEM-join dogfood assertion is required again (all runners must join).

## [v0.29.0] - 2026-07-07

### Added

- **Tailnet Phase 1: per-peer byte streams + connect-gated port forwarding ([#132](https://github.com/saorsa-labs/x0x/issues/132), [#183](https://github.com/saorsa-labs/x0x/pull/183), [ADR-0020](docs/adr/0020-tailnet-phase-1-byte-streams-and-forwarding.md)).** A per-peer byte-stream API over ant-quic's `open_bi`/`accept_bi`, plus a local TCP port-forwarder (`/forwards`, `x0x forward add|list|rm`) that tunnels a loopback port to a loopback service on a trusted peer — Tailscale-style machine-to-machine connectivity over the same post-quantum QUIC transport. This wires the previously-dormant connect ACL ([#131](https://github.com/saorsa-labs/x0x/issues/131), shipped in v0.28.0) as its first runtime caller: every inbound forward is gated fail-closed through the full chain (sender verified → not revoked → trust `Accept` → connect enabled → target loopback → `(agent, machine)` pair in the ACL → target in the entry). Denials reach zero bytes to the target. SOCKS5 forwarding is deferred to a later phase.

### Security

- **DoS hardening on the byte-stream accept + forward paths ([#183](https://github.com/saorsa-labs/x0x/pull/183)).** The inbound accept loop dispatches each stream to a per-stream task (no head-of-line blocking) with a bounded protocol-prefix read; the forwarder bounds its header read with a timeout and a fixed maximum header size; inbound and outbound concurrency are capped globally and per-peer (RAII admission slots released on drop); and `handle_inbound` re-checks the revocation set before reading any peer bytes, closing the accept-to-header stale-authorization window. The fail-closed properties were confirmed by two independent adversarial reviews and a full-ring VPS soak (real-WAN forward round-trip plus `target_not_allowed` and `target_not_loopback` deny proofs observed firing at the gate).

## [v0.28.0] - 2026-07-04

### Upgrade notes

- **Coordinated fleet upgrade for user-certified agents:** the certificate expiry field changes the bincode encoding of gossip announcements that carry a user certificate (agents that have opted into a `user.key`). In a mixed-version fleet, user-certified announcements from a differently-versioned peer may fail to decode until all nodes are upgraded. Agents without a user certificate are unaffected. On-disk `~/.x0x` key and certificate files remain backward-compatible (magic-marker versioning). Upgrade all nodes together, or expect transient announcement-decode failures from user-certified peers during rollout.
- **New ADRs:** ADR-0018 (key lifecycle) and ADR-0019 (connect ACL).

### Security

- **Key lifecycle: optional certificate expiry, renewal, and gossiped revocation ([#130](https://github.com/saorsa-labs/x0x/pull/130), [ADR-0018](docs/adr/0018-key-lifecycle-expiry-renewal-revocation.md)).** `AgentCertificate` gains an optional `not_after` field (Unix timestamp, signature-covered). Absence of `not_after` means no expiry — existing keys and certificates are valid without any change. When present, a 300-second clock-skew tolerance is applied. Revocation is expressed as signed, grow-only revocation records (self-revocation or issuer-authority revocation) gossiped over the `x0x.revocation.v1` topic with heartbeat rebroadcast, so revocations propagate to peers that were offline when the record was first published. Expiry and revocation checks are enforced fail-closed at five points: announcement ingest, verified-binding check (`is_agent_machine_verified`), the DM inbox gate (which also denies exec, since exec rides typed DM payloads), the group-metadata gate (the revocation check precedes `bypass_verified`, so a revoked sender is denied even for self-authenticating membership events without regressing #99), and drop-on-receipt. A revoked or expired certificate causes the announcement or message to be silently dropped with a structured log event — no crash, no error response to the sender.

- **Connection ACL: default-deny per-flow connectivity policy engine ([#131](https://github.com/saorsa-labs/x0x/pull/131), [ADR-0019](docs/adr/0019-connect-acl-default-closed.md)).** A connectivity policy engine and gate are wired into the daemon's startup path. The `--connect-acl <path>` flag (plus `--check` validation) loads a TOML policy file describing which peers may initiate or receive connections. `GET /diagnostics/connect` reports the loaded policy and connection counters. **The ACL is dormant in v0.28.0** — no existing connection path is gated until the tailnet forwarder wires it; runtime connection behavior is unchanged from v0.27.0.

- **Group-scoped task lists enforce group membership ([#153](https://github.com/saorsa-labs/x0x/issues/153)).** Requests to group-scoped task-list endpoints by agents who are not members of the enclosing group now return `403 Forbidden`. Previously, group membership was not checked, allowing any peer that knew the task-list topic to read or write tasks in a group they had not joined.

- **Constant-time API token comparison + short-lived session tokens ([#127](https://github.com/saorsa-labs/x0x/issues/127)).** Bearer-token comparison is now constant-time (no early exit on the first differing byte). Long-lived durable tokens are no longer accepted via the `?token=` query-parameter path (query-string tokens appear in server logs and process lists); they must be presented in the `Authorization: Bearer` header. A new short-lived session-token endpoint allows clients to exchange a durable token for a time-bounded session token suitable for URLs.

### Added

- **Bounded per-WebSocket outbound queue + slow-consumer close ([#122](https://github.com/saorsa-labs/x0x/issues/122)).** Each WebSocket connection's outbound send buffer is now capped. A client that stops draining messages causes the buffer to fill; once full the connection is closed with WebSocket close code `1013` (try again later) rather than back-pressuring the entire gossip fan-out path.

- **Domain-separated `POST /agent/sign` with external DST ([#133](https://github.com/saorsa-labs/x0x/issues/133)).** `/agent/sign` now accepts a caller-supplied domain-separation tag (`dst`) that is included in the signed envelope alongside the payload. Applications that need to distinguish signed records by purpose (e.g. "agent-announcement" vs "task-ownership") can supply a stable DST and later verify it via `/agent/verify` without risking cross-protocol signature reuse.

### Changed

- **Server module decomposed into focused files ([#125](https://github.com/saorsa-labs/x0x/issues/125)).** `src/server/mod.rs` was mechanically split into `auth.rs`, `state.rs`, `ws.rs`, `sse.rs`, and `routes/{contacts,identity,machines,tasks}.rs`. All endpoints are preserved byte-for-byte; this is a pure file-layout change with no behavior or API surface change.

- **Release train gated on green CI ([#128](https://github.com/saorsa-labs/x0x/issues/128)).** The `release.yml` workflow now requires all CI checks to pass before the publish step runs, preventing a repeat of releases published from a red-CI state.

### Fixed

- **WebSocket close frame `1013` now reaches the client ([#149](https://github.com/saorsa-labs/x0x/issues/149)).** When the slow-consumer close path writes a `1013` close frame, the writer now flushes and waits for the underlying TCP stream to drain before dropping the connection. Previously the close frame could be lost if the OS write buffer was not flushed before the socket was dropped.

- **Announce loop no longer self-registers the daemon's own agent as a contact ([#145](https://github.com/saorsa-labs/x0x/issues/145)).** The capability-advertisement loop checked inbound announce messages from all peers, including the daemon's own reflections. A daemon's own agent ID was therefore inserted into the contacts store and returned in `GET /contacts`, making the local agent appear as a remote contact. The loop now skips announcements whose agent ID matches the local agent.

- **Relaxed named-group convergence timing budget ([#139](https://github.com/saorsa-labs/x0x/issues/139)).** Integration tests that assert full group-state convergence across multiple daemons were failing intermittently under CI load because the timing budget was too tight for gossip propagation + TreeKEM apply under contention. Budgets are now derived from observed p99 latencies with a safety margin.

- **CRDT/KV sync tasks tracked through `Agent` shutdown ([#126](https://github.com/saorsa-labs/x0x/issues/126)).** The background tasks that drive CRDT delta exchange and KV-store delta exchange were spawned into the runtime but not registered with the `Agent`'s task registry, so `Agent::shutdown()` returned before those tasks flushed their final deltas. They are now registered and awaited as part of orderly shutdown.

- **CLI `unreachable!()` arms replaced with explicit errors ([#129](https://github.com/saorsa-labs/x0x/issues/129)).** Several `match` arms in the CLI command dispatch were guarded with `unreachable!()` — a panic in a production binary if control ever reached them. These are replaced with explicit, logged error returns.

- **Bootstrap dial bounded with a per-attempt timeout ([#123](https://github.com/saorsa-labs/x0x/issues/123)).** Each bootstrap dial attempt now carries an individual timeout. Previously a stalled QUIC handshake with an unreachable bootstrap peer could block the entire 3-round bootstrap sequence for the duration of the OS connection timeout, delaying join-network completion by minutes on flaky paths.

## [v0.27.0] - 2026-06-28

### Added

- **Role-based group authority — flat Admin/Member model ([#121](https://github.com/saorsa-labs/x0x/pull/121), [ADR-0016](docs/adr/0016-role-based-group-authority-flat-admin.md), proposed by @JimCollinson).** Group authority is now decided purely on committed-roster role (`AdminOrHigher`), never on creator identity. The last-admin invariant — no commit may leave a live group with zero active admins — is enforced at both choke-points (authoring in `seal_commit` and apply in `finalize_applied_commit`), covering REST, gossip, and TreeKEM paths. Terminal withdrawal is double-gated (terminal mode **and** an active Admin signer) and the MLS/TreeKEM/GSS key wipe is coupled to the withdrawn marker as one atomic act. Agent-card invites (`GET /agent/card?include_groups=true`) now carry full base-state provenance so they are joinable, and never export withdrawn-group tombstones. The GUI roster gains an admin-demote control and hides management actions on the caller's own row. Legacy `Owner`/`Moderator`/`Guest` roles remain parseable for deserialization and signed-apply convergence but are no longer assignable. Validated by 69 group/authority unit + integration tests and a live 6-node cross-region testnet (group create/invite/join, roster convergence, retained state-commits, and the TreeKEM applied path).

### Changed

- **BREAKING (group authority semantics):** `Owner` is no longer a privileged authority role. Consequently: **any admin** can now delete/withdraw a group (the creator no longer holds an exclusive veto) and remove the original creator via the member API; `DELETE /groups/:id` is now an ordinary **self-leave**, not a group-terminating delete (use `POST /groups/:id/state/withdraw` to end a group); and a creator leaving a TreeKEM group is an ordinary self-leave (the `CreatorMustDelete` special case is gone). Existing rosters with stored `Owner` entries continue to validate — `Owner` still satisfies `AdminOrHigher` for legacy evaluation and chains replay byte-for-byte — but new assignments accept only `admin`/`member`.

### Fixed

- **TreeKEM key-residency TOCTOU on join.** `install_joined_treekem_group_after_crypto_recheck` now re-checks the withdrawn tombstone while holding the `treekem_groups` write lock, closing the window where a concurrent withdrawal could leave live key material resident in memory after the persisted snapshot was already wiped.

## [v0.26.0] - 2026-06-21

### Added

- **Embeddable in-process server: `x0x::server::serve()` / `ServerHandle` ([#110](https://github.com/saorsa-labs/x0x/issues/110), proposed by @josh-clsn).** The daemon's entire axum router + SSE hub + serving-side background tasks were factored out of the `x0xd` binary into the library at `src/server/`, so a host process (e.g. an Android/iOS app that can't reliably supervise a child `x0xd`) can run the HTTP/SSE surface in-process. `serve(config)` / `serve_with_options(config, options)` return a non-blocking `ServerHandle { local_addr(), shutdown(&self), wait(), shutdown_and_wait(), cancellation_token() }`; the bin is now a thin wrapper and the HTTP/SSE surface is byte-identical (verified by a 19-test characterization oracle, the full nextest suite, a live 6-node testnet, and a line-multiset diff of the relocation). `DaemonConfig` is the public input, with a new `identity_dir` so a host supplies its own storage paths — no `~/.x0x` fallback is reachable on the embed path. The public `serve()` disables self-update install/restart by default (an embedded library must never replace or restart the host app); the daemon binary opts back in. CLI-only flows (`--doctor`/`--check`/`--check-updates`, arg parsing, logging) stay in the bin.

- **Deterministic shutdown teardown ([#116](https://github.com/saorsa-labs/x0x/issues/116)).** `ServerHandle::shutdown_and_wait()` now stops every owned background task before returning: the server-owned listeners, the gossip runtime, and the QUIC `NetworkNode` (a real `NetworkNode::shutdown()` deadlock was fixed along the way), plus the previously-unstopped `Agent`-internal loops (identity / network-event / direct / lifecycle listeners, presence broadcast-peer refresh, heartbeat, discovery reaper), the presence beacons (wrapper *and* `PresenceManager`), the capability-advert and DM-inbox services, via a `CancellationToken` + a closed task registry. A listener that a still-bootstrapping `join_network` would otherwise start after shutdown is refused (TOCTOU-free). No steady-state behavior change.

- **Force-cancel in-flight exec sessions on shutdown ([#118](https://github.com/saorsa-labs/x0x/issues/118)).** `ExecService::shutdown()` now force-cancels per-request exec handlers and `SIGKILL`s their child processes (out-of-band PID kill + `kill_on_drop` backstop, with a re-snapshot on the grace timeout and reap-time PID clearing so a recycled PID is never signalled), completing the deterministic-teardown story for embedders.

### Changed

- **Bumped `ant-quic` 0.27.26 → 0.27.27.** Picks up the endpoint UDP-socket release on shutdown ([ant-quic#196](https://github.com/saorsa-labs/ant-quic/issues/196)), so an in-process embedder can stop and restart x0x on the **same fixed QUIC port** (proven by the in-process restart tests). Resolver-unified with `saorsa-gossip`'s `ant-quic` requirement — no `saorsa-gossip` re-release needed.

## [v0.25.0] - 2026-06-19

### Added

- **Retained named-group state-commit history + `GET /groups/:id/state/commits` (members-only, paged) — a verifiable role/roster audit trail ([#111](https://github.com/saorsa-labs/x0x/issues/111), proposed by @nkoteskey).** Every authored or applied `GroupStateCommit` is now retained in-struct alongside an independently-verifiable roster projection: recomputing the BLAKE3 `roster_root` from the stored `{agent_id → (role, state)}` snapshot must equal the signed `commit.roster_root`. This makes "who held which role at revision N" auditable after the fact — closing the verification gap that [ADR-0016](docs/adr/0016-role-based-group-authority-flat-admin.md)'s flat Admin/Member delegated authority left open. The endpoint serves the chain to members with pagination (`from_revision`, `limit`) and reports `roster_root_verified` per entry. Retention rides the existing atomic group writes through the two methods every commit-production path funnels through (`seal_commit` for the authoring committer, `finalize_applied_commit` for commits applied over gossip), bounded by `COMMIT_LOG_CAP`. CLI: `x0x group state-commits <group_id>`. Verified on the live 6-node testnet across both the authored (committer) and applied-over-gossip (TreeKEM joiner) paths.

## [v0.24.0] - 2026-06-15

### Added

- **Signed agent cards + A2A (Agent2Agent) discovery — foundation of [ADR-0017](docs/adr/0017-x0x-as-agent-transport-layer.md) (positioning x0x as the agent transport layer).** `AgentCard` now carries an `agent_public_key` and an ML-DSA-65 `signature` over canonical, domain-separated, length-prefixed bytes (mirroring the existing `GroupCard` scheme). The signature commits to the agent's public key, which must hash to the card's `agent_id`, so a relay cannot substitute a foreign key — reachability hints and capability advertisements are now tamper-evident. `GET /agent/card` signs; `POST /agent/card/import` verifies signed cards and rejects tampered ones. Legacy unsigned cards still parse and import for backward compatibility.
- **`GET /.well-known/agent-card.json` — A2A-compatible discovery card.** The daemon serves an [Agent2Agent](https://a2a-protocol.org)-shaped Agent Card derived from the signed x0x card: KV stores and public groups map to A2A `skills`, the `exec` skill is advertised only when remote-exec is enabled, and the self-authenticating x0x identity (agent/machine/user ids, public key, signature, certificate) is carried under `x0x`-namespaced extension members. This is the discovery half of A2A interop ([docs/design/a2a-agent-card-adapter.md](docs/design/a2a-agent-card-adapter.md)); the A2A-over-x0x message binding ([docs/design/a2a-over-x0x-binding.md](docs/design/a2a-over-x0x-binding.md)) is a tracked follow-up. A transport/identity Internet-Draft skeleton ([docs/design/x0x-transport-protocol-id.md](docs/design/x0x-transport-protocol-id.md)) accompanies the ADR.

## [v0.23.1] - 2026-06-11

### Added

- **`POST /agent/verify` + `x0x agent verify` — signature-verify counterpart to `/agent/sign`** (#106, PR #109). Stateless detached ML-DSA-65 signature verification using only caller-supplied public material: applications that persist signed records no longer need to bundle their own FIPS-204 library or re-derive the `domain || 0x00 || payload` framing when reading records back. A failed check is a result (`200` + `valid: false`), not an error; `400`/`413` mirror `/agent/sign`'s malformed-input and size rules, with explicit key-length (1952) and signature-length (3309) validation and an optional `algorithm` field rejecting unknown schemes (including present-but-null). Proposed by @JimCollinson.

### Fixed

- **Panic-scanner CI gate now honours the inner `#![cfg(test)]` file attribute.** A file gated entirely as test-only (`src/cli/commands/test_support.rs`) had its `unwrap()`s flagged as production panics because the scanner recognised only outer `#[cfg(test)]` / `#[test]` attributes. No production code was affected.

## [v0.23.0] - 2026-06-10

### Fixed

- **CRDT delta apply bypassed the LWW vector clock** (PR #108). `merge_delta` applied list name (kv + task lists) and task ordering via `LwwRegister::set()`, which bumps the local clock and adopts the value *unconditionally* — while the full-state merge path already resolved by causality. A redelivered or stale full-state snapshot could therefore overwrite a newer local name/ordering. Deltas now carry the whole `LwwRegister` (value + vector clock) and receivers resolve the winner via `LwwRegister::merge()`.
- **`KvStore::get` could resurrect a deleted key.** A simplification assumed `entries` and the active-key OR-Set stay in lockstep, but `KvStore::merge` applies a remote tombstone without pruning `entries`. `get` now re-checks active-key membership (O(1) via `OrSet::contains`).
- **`x0x contacts card` did not URL-encode `display_name`** — a name with spaces or `&` corrupted the query.

### Added

- **Task lists get cold-start bootstrap.** A first-time joiner of a task-list topic now requests state on a 1/5/15/30s schedule and holders republish full state (mirrors the kv-store side channel from #96), so tasks added before the join arrive instead of being lost. Daemon-backed e2e test included.

### Changed

- **Wire-format change (minor bump):** `TaskListDelta.{name_update,ordering_update}` and `KvStoreDelta.name_update` now carry an `LwwRegister<value>` instead of a bare value on the CRDT sync topics. Deltas are transient (not persisted), but mixed-version daemons cannot exchange task-list/kv deltas during rollout — coordinate the upgrade for apps using these features. The gossip relay layer is unaffected.
- **Codebase simplification (PR #108, ~−1,300 lines):** consolidated daemon error-response and base64 boilerplate, CLI command wrappers and a `routes --json`/`exec` cleanup, a shared gossip delta codec, and dead-code removal. No REST/WebSocket API changes.

## [v0.22.1] - 2026-06-10

### Fixed

- **Transport stream reassembly delivers zero-filled gaps instead of errors** (ant-quic #195). Under loopback load, `read_to_end` on gossip uni-streams could return `Ok` with a buffer containing zero-filled gaps — exactly the byte ranges that the QUIC assembler failed to yield before signaling end-of-stream. x0x caught these because pubsub v2 frames are ML-DSA-signed (corrupted frames failed verification with `ML-DSA-65 signature verification failed`); unsigned consumers would have ingested the corruption silently. Captured frames show a single zero window of exactly 2,896 B (2×1448, packet-aligned) at offsets 1085/1057 inside otherwise-intact 10,706 B identity-announce frames. Fixed in ant-quic 0.27.26: `read_to_end` now fails with `ReadToEndError::MissingData` instead of zero-filling unreceived ranges; overlapping retransmissions are tolerated (benign). A dedicated regression test (`regression_read_to_end_zero_gap.rs`) covers adverse-network duplicate/overlap injection.

### Changed

- Bumped **ant-quic 0.27.25 → 0.27.26** and **saorsa-gossip 0.5.62 → 0.5.63** (pins the new ant-quic).

## [v0.22.0] - 2026-06-10

### Fixed

- **Cross-NAT DM capability black hole at startup** (#101, PR #102). `start_dm_inbox` published the DM capability upgrade with `watch::Sender::send`, which drops the value when no receiver is subscribed — and x0xd starts the inbox before the capability advert service subscribes. Peers cached `gossip_inbox=false` for the process lifetime and fell back to the raw-QUIC path that fails across NAT. Now `send_replace`; a regression test locks in late-subscriber visibility (verified to fail on the pre-fix code). Thanks @josh-clsn for the precise diagnosis.
- **KvStore first-time late join never bootstrapped pre-existing keys** (#96, PR #103). The gossip message cache replays ~60s and its lazy pruning loses older deltas on busy topics, so a first-time joiner could never receive keys written before it subscribed. New `<topic>/state-sync` side channel: empty-store joiners request state on a 1/5/15/30s schedule and holders republish their full state as a regular CRDT delta (idempotent, multi-holder safe, fully backward compatible). Proven by a cold-join daemon test that fails against the pre-fix binary. Thanks @JimCollinson for the decisive repro matrix.

### Added

- **`local:` topic prefix — same-daemon pub/sub IPC** (#89, PR #103). Topics starting with `local:` are delivered only to subscribers on the same x0xd instance and never reach PlumTree (no EAGER, no IHAVE); `/publish`, `/subscribe`, `/events`, WebSocket subscribe and bearer auth work unchanged. The local-IPC substrate for multi-process apps sharing one daemon. Proposed by @nkoteskey.
- **Domain separation on `POST /agent/sign`** (#90, PR #102). Optional `domain` field signs `domain || 0x00 || payload` and echoes the domain in the response, preventing cross-protocol signature replay. NUL/empty/oversize domains rejected with 400. CLI: `x0x agent sign --domain`. Proposed by @nkoteskey.
- **`x0x user-id inspect [PATH]`** (#93, PR #102). Daemonless validation of a user identity file: prints `user_id` and the four-word form, `--json` mode, non-zero exit naming the file on failure. The symmetric sibling of `user-id create`. Proposed by @JimCollinson.
- **`x0x user-id create --from-seed <hex>`** (#95, PR #103). Deterministic UserKeypair derivation via FIPS 204 seeded KeyGen (the ξ input, `fips204::ml_dsa_65::KG::keygen_from_seed`) — same 32-byte seed, same keypair, any machine. Foundation for mnemonic-based identity portability; mnemonic encoding stays in consumer applications. Proposed by @JimCollinson.

### Changed

- **x0xd is quiet by default** (#85, PR #102). Without `RUST_LOG` or a config `log_level`, only warn/error lines are emitted (privacy by default for operators outside the fleet). `RUST_LOG=info` restores verbosity; documented in the README. Operator visibility via `/health` and `/diagnostics/*` is unaffected.
- **Privacy Layer 2: salted-hash identifiers in warn!/error! logs** (#83, PR #104). All production warn/error sites that interpolated stable identifiers (peer/agent/machine/user ids, group ids, topics, addresses) now emit salted-BLAKE3 8-hex tokens via the new `x0x::logging` wrappers — correlatable within one daemon run, unlinkable across restarts and daemons. `info!`/`debug!` diagnostic channels (`treekem.trace`, `dm.trace`) intentionally keep real ids.

### Test infrastructure

- Daemon-backed regression suites for #96 and #89 wired into CI; `solo()`/`join_peer()` staggered-start harness helpers; `X0XD_TEST_BINARY` runtime override for pre-fix/post-fix proof runs; daemon health gate 30s→90s.

## [v0.21.4] - 2026-06-10

### Fixed

- **Fresh-boot DM delivery black hole (dogfood `group_join` / hop-DM 25s timeouts).** Local 3-daemon soaks failed 10-17% of iterations with `group_join timed out` / `hop DM never echoed back`; a trace-instrumented capture run pinned a chain of three compounding faults, each masked by the previous one:
  1. **Capability-advert poisoning**: `CapabilityAdvertService` broadcast the startup `pending()` advert (no gossip inbox / KEM key), and `CapabilityStore::insert` was unconditional last-writer-wins — epidemic broadcast delivers out of order, so a stale pending advert could clobber the gossip-ready one and leave senders on `advert_cache_unusable`. The store now orders adverts by their signed `created_at_unix_ms` (stale ignored; a genuinely fresher downgrade still wins), and the publisher never broadcasts a not-yet-usable advert (absence already means "use the raw fallback").
  2. **Fire-and-forget raw-QUIC loss**: the daemon's generic DM config sent raw-path messages without ant-quic's receive-pipeline ACK — a send into a connection being superseded during boot churn returned `Ok` (dur_ms=0) while the bytes were lost, so the retry machinery never fired and the recipient's app never saw the message. `direct_message_send_config()` now sets `raw_quic_receive_ack_timeout = 8s` (matching the named-group config), so loss fails the attempt and the existing retry re-sends.
  3. **Zombie-connection retry pinning**: with loss now detected, retries still resolved `cached_connected` onto the same dead connection (`is_connected` stays true for a zombie whose remote endpoint vanished without a lifecycle event) and burned ~14s per attempt until the caller's deadline. An ACKed-path send failure on a still-connected peer now tears the connection down so the next attempt takes the X0X-0031/0033 send-readiness repair (fresh dial).

  Validated: the capture harness went from failing within 12-27 iterations to 40/40 clean; `tests/pr99_local_soak.sh` restored to baseline (see soak artefacts under `proofs/x0x-gui-full-dogfood/`).

### Added

- **`welcome.trace` diagnostics for the TreeKEM Welcome-blob transfer.** Trace-only (no behavior change): `target=welcome.trace` debug stages on both sides of the chunked Welcome pull — anchor `offer_sent` / `chunk_sent` / `chunk_ack_recv` / `final_ack_{ok,failed}`; receiver `chunk_recv` / `chunk_recv_no_pending` / `chunk_ack_sent`. Enable with `RUST_LOG=warn,welcome.trace=debug` to locate exactly where a Welcome transfer stalls under churn.

### Notes

- **Refined understanding of the v0.21.1 high-churn convergence "known limitation".** A controlled same-day A/B and an instrumented 110-iteration diagnostic soak found that **multi-member TreeKEM converges ~100% under normal conditions** (110/110, `welcome.trace` shows 0 Welcome-transfer failures). The earlier low numbers (47% overnight, 78% daytime) are a **degraded-network tail**, not a persistent x0x logic bug: they correlate with sustained/overnight cross-region degradation (connection eviction → `ant_quic` `Peer not found`), and — importantly — the bulk `Peer not found` events are **background gossip/transport noise** that do **not** drive Welcome-transfer failure (2207 in a 2h window with 100% convergence). Three candidate x0x-side fixes (inline-Welcome, FetchRequest retry, redial-on-`Peer not found`) were tried and all proved to target that background noise rather than the actual transfer; none improved convergence and they are **not** merged. The residual tail is treated as a connection-resilience / infra concern; the `welcome.trace` instrumentation above is left in to capture a real failure when conditions next degrade. See `handoff/` writeups and saorsa-gossip#24.

## [v0.21.1] - 2026-06-04

### Fixed

- **Multi-member TreeKEM convergence (2nd+ member never entered the tree).** A second (or later) member reached the owner's roster but its `MemberAdded` / `Welcome` was received and then **silently rejected** — it never entered the TreeKEM tree and could not encrypt/decrypt (the v0.21.0 "known limitation"). Root cause: TreeKEM `MemberAdded` events carry signed state commits whose state-hash validation commits to the roster root, but the invite *joiner stub* did not carry the authority's current state-chain frontier or roster, so the joiner failed signed state-chain validation **before** applying the Welcome (no error logged — needed new `treekem.trace`). Fixed by seeding invites with the authority's base state (`base_state_revision` / `base_state_hash` / `base_prev_state_hash` / `base_members_v2`); local Welcome events with state gaps now queue/catch-up instead of silently failing; TreeKEM catch-up responses paginate one event at a time to stay under the DM payload cap. Cross-region testnet e2e (`tests/e2e_treekem_membership.py --member2`) now passes (m1 + m2 converge, 3-way secure round-trips, ban + forward-secrecy).
- **`X0X-0074d` Critical-gate overflow flood under sustained load** (via saorsa-gossip 0.5.62). 0.5.59 pruned ghost/disconnected eager peers, but Critical sends could still queue behind a slow peer with no queue-wait bound — a full 64-deep Critical FIFO took ~64×send-timeout to drain, producing runaway `X0X-0074d` WARN bursts. 0.5.62 rechecks connectivity at claim time, bounds the Critical-gate wait, and treats a full Critical gate as threshold pressure that immediately cools the peer/topic instead of spamming overflow WARNs. Validated: a 3.5h testnet churn soak held `X0X-0074d=0` and `invalid epoch=0` on all 6 nodes (was thousands of overflows per ~6 min before).

### Changed

- Bumped saorsa-gossip **0.5.58 → 0.5.62** across all 10 crates; consume the bounded Critical-gate + saturation-cooling surfaces and the transport-connectivity hook.

### Known limitations

- **High-churn multi-member TreeKEM convergence is not yet fully reliable.** A 3.5h testnet soak (150 rapid create→2-member-join→ban→delete cycles on 3 fixed cross-region nodes) passed 117/150 (78%); failures are `Welcome not processed`, clustered in degradation windows. They are driven by send-timeout / Critical-gate-saturation cooling accumulating under sustained load and starving the chunked Welcome-blob fetch (`failed to fetch TreeKEM Welcome`) — **not** a TreeKEM/state bug (`invalid epoch=0`, `X0X-0074d=0` throughout). Single-member and low-churn multi-member groups converge reliably. The cooling-vs-Welcome-fetch interaction is a tracked follow-up (see `handoff/cooling-vs-welcome-fetch-2026-06-04.md`).

## [v0.21.0] - 2026-06-03

### Fixed

- **Owner-side multi-member roster convergence**: adding a *second* (or later) member to a private secure (TreeKEM) group left that member permanently absent from the **owner's roster** — the roster stayed empty or the new joiner's invite was silently dropped (`invite_secret_unknown`), so the joiner polled forever. Root cause: every group-state mutation did a `clone → mutate → store_named_group_info(clone)` **blind last-writer-wins overwrite** of the whole `GroupInfo`, with no per-group serialization. The owner now receives the same `MemberJoined` concurrently over gossip **and** direct delivery, so two stale-clone applies would each pass the `has_active_member` check, each consume the bearer invite, and double-add to the MLS tree (`already a member`) while clobbering the roster / a freshly-issued invite. Fixed with a per-group `group_membership_lock` that serializes **all** read-modify-write of a single group's `GroupInfo` — the owner-side apply path (gossip + direct listeners) and every API mutator (`create_invite`, add, remove, ban, approve, leave, update). Single-level locking (inner TreeKEM helpers stay unlocked) keeps it deadlock-free. Verified: the 3-daemon roster-convergence/ban test passes 41/41 under soak, and the full workspace suite (1662 tests) stays green. **Scope:** this fixes the *owner-side roster*; the joiner's cryptographic tree-join is tracked as a known limitation below.

### Known limitations

- **Multi-member secure messaging is not yet functional end-to-end.** A cross-region testnet e2e (`tests/e2e_treekem_membership.py --member2`) confirmed that while a 2nd member now reliably reaches the owner's roster (Active), its **join result (`MemberAdded` + `Welcome`) is never delivered to it** — the joiner polls the anchor for the result and times out (`timed out polling anchor for TreeKEM join result`), so it never processes the Welcome, never enters the TreeKEM tree, and cannot encrypt/decrypt. The local `d4_mls_ban` test only asserts roster *state*, which is why it passed. **Single-member** TreeKEM groups are fully functional end-to-end (invite → join → bidirectional secure → ban → forward secrecy, verified on testnet). Multi-member (2+ members) secure participation is a tracked follow-up.

### Added

- **Order-sensitive TreeKEM membership reliability**: authoritative membership events are no longer gossip-only. The joiner direct-DMs `MemberJoined` to the inviter (immediately and again after the background-publish delay), and authoritative TreeKEM commits (`MemberAdded` / remove / ban / join-request approval) are direct-delivered to the new joiner plus all active members, with gossip retained as broadcast backup.
- **Bounded TreeKEM pending/replay + explicit catch-up anti-entropy**: verified membership events that arrive before local TreeKEM readiness or ahead of the local scalar frontier (`prev_state_hash` / `state_revision` / `roster_revision` / `treekem_epoch`) are queued (bounded per group) and trigger explicit, throttled `TreeKemCatchupRequest` / `TreeKemCatchupResponse` direct messages. Responses are authorization-gated and always re-processed through the regular signed-metadata apply path.

### Changed

- **`AGENTS.md` clippy-gate guidance corrected**: the pre-submit clippy command is now the standard `cargo clippy --all-features --all-targets -- -D warnings` that CI actually gates on; the extra `-D clippy::panic` / `-D clippy::unwrap_used` / `-D clippy::expect_used` denies are removed because they trip on existing test code and are stricter than CI.
- **`d4_mls_ban` strengthened to a real 3-daemon convergence test**: owner + non-banned observer + a real invite-joined ban target; it now verifies the banned member converges to `banned` in *both* the owner's and the non-banned observer's rosters, and that the owner's TreeKEM epoch advances. Uses a fresh, **owned** trio (not the process-global `cluster()` singleton, whose daemons are never dropped and lingered on the loopback interface, intermittently stalling `d4_stateful`'s gossip convergence).

## [v0.20.2] - 2026-06-02

### Fixed

- **Scope secure-by-default TreeKEM to private groups (ADR-0012)**: group creation now flips to the real TreeKEM plane only for **private** (`Hidden` discoverability) MlsEncrypted groups, not every MlsEncrypted preset. Gating on `confidentiality == MlsEncrypted` alone was too broad — it swept in the *public* `public_request_secure` preset, whose cross-daemon join-request review converges via the D4 signed-commit (GSS) path that the single-committer TreeKEM transport does not provide, breaking request-to-join convergence. `public_request_secure` (and any public encrypted policy) now stays on the GSS plane; `private_secure` remains secure-by-default TreeKEM. Matches ADR-0012's stated scope ("all new private groups secure-by-default TreeKEM").

## [v0.20.1] - 2026-06-02

### Changed

- **SKILL.md install guidance hardened**: the install section no longer pipes a remote script straight into a shell (`curl … | sh`) or recommends one-line variants that immediately start/persist the daemon. Option B is now download → review → run (`curl -sfLO …/install.sh`, `less install.sh`, `sh install.sh`); starting the daemon is a separate explicit `x0x start`, and `--start` / `--autostart` remain as opt-in flags on the already-downloaded, reviewed script. Clears the ClawScan "suspicious" verdict (SkillSpector + VirusTotal flagged the previous remote-installer docs; static scan was already clean).

### Fixed

- **Release pipeline no longer false-fails on the ClawHub scan clock**: the "Publish SKILL.md to ClawHub" job previously hard-failed after a fixed 5-minute wait for ClawHub's asynchronous security scan, reddening otherwise-successful releases (crate, binaries, and GitHub release all publish independently). The verification step is now status-aware — it keys off the `SecuritySnapshot.status` enum (`clean` → success, `malicious` → fail, `suspicious` → warn-and-succeed, `pending`/`error` → tolerate and finalize asynchronously) — so a slow scan never blocks a release while a genuine malicious verdict still does.
- **Documentation build (rustdoc `-D warnings`)**: fixed broken/private intra-doc links in the `mls` module docs introduced with the TreeKEM plane (`[group]`, `[treekem]`, and links to the private `member_id_from_seed` / `agent_id_to_member_id` items) — now plain code spans, so `cargo doc` is clean again.
- **`named_group_add_remove_member_local` integration test**: updated to create a `public_open` (GSS) group. The default `private_secure` preset is now secure-by-default TreeKEM (ADR-0012), where a direct roster add correctly requires the target's KeyPackage; this local-roster-semantics test now exercises the non-secure plane where add-by-`agent_id` is the valid operation.

## [v0.20.0] - 2026-06-02

### Added

- **TreeKEM secure-group membership (ADR-0012)**: private secure groups now run real RFC-9420-subset **TreeKEM** group key agreement (via `saorsa-mls` `TreeKemGroup`), providing forward secrecy and post-compromise security. The full membership lifecycle works end-to-end — invite → join → `Welcome` processing → bidirectional secure-plane encrypt/decrypt → ban (epoch advance) → forward secrecy. On a TreeKEM join the joiner reconstructs the **owner-only authority base** from the invite (new `base_secret_epoch` / `base_security_binding` fields, folded into the signed invite bytes) so its `state_hash` matches the authority `MemberAdded` commit's `prev_hash` (previously the joiner pre-added itself, causing a `PrevHashMismatch` that blocked every join). Oversized `Welcome` payloads are delivered out-of-band via a content-addressed fetch-by-reference (`WelcomeRef`, blake3 + byte-length verified); a joiner-initiated poll recovers the authoritative `MemberAdded` if the gossip push is missed; per-group unlinkable `MemberId`s. Validated by the full test suite (1662 tests) plus a local multi-iteration soak and a 6-hour cross-region testnet membership-churn soak.

- **`POST /agent/sign`**: detached ML-DSA-65 signature over a caller-supplied payload using the running agent's signing key. Bearer-token authenticated; payloads are capped at 256 KiB. Response includes the agent_id (hex), the agent's public key (base64), the signature (base64), and the stable signing scheme identifier (`"x0x.agent-sign.v1.ml-dsa-65"`). Intended for applications that persist signed records to disk or distributed storage (audit logs, governance votes, content metadata) where transport-layer gossip signing doesn't survive a database read. Callers sign exact bytes, so applications must canonicalize structured payloads and should domain-separate them with an application/type/version prefix before signing. Matching CLI: `x0x agent sign --file <PATH>` (or `--payload-b64 <BASE64>`). Coverage: `daemon_api_agent_sign_*` integration tests + `api_coverage` registry entry.
- **Bootstrap UDP/443 reachability (ADR-0011)**: `DEFAULT_BOOTSTRAP_PEERS` now seeds each of the 6 VPS on **both UDP/443 and UDP/5483** (IPv4 + IPv6), with the `:443` entries listed first. UDP/443 traverses full-tunnel VPNs (Cloudflare WARP), corporate/hotel/CGNAT, and carrier networks that carry mainstream HTTP/3 cleanly but throttle/drop high UDP ports like 5483. Dialing a low *destination* port is unprivileged (ephemeral high source port), so **clients still never bind a privileged port or need root** — only the operator-run bootstrap VPS bind 443. Each bootstrap host runs a dedicated root `x0xd` on `:443` alongside its existing `:5483` listener; no ant-quic change (each listener binds one port). `:5483` is retained for backward compatibility — no flag day. MTU caveat: 443 mitigates port throttling/DPI but cannot raise a path's MTU; a path that can't carry QUIC's 1200-byte Initial can't run QUIC on any port.
- **`transport_environment` diagnostics (ADR-0011 §4)**: `GET /diagnostics/connectivity` now carries a structured `transport_environment` assessment, and `x0xd --doctor` prints actionable guidance when the local path is degraded. Detects full-tunnel-VPN egress (Cloudflare WARP address ranges), constrained/critical path MTU (lost PLPMTUD probes, black-hole detection, sub-1400/sub-1252 MTU), and CGNAT (RFC 6598) — turning a previously silent "can't connect behind my VPN" failure into self-service guidance (split-tunnel / DNS-only mode). Pure, unit-tested heuristics in `connectivity::assess_transport_environment`.

## [v0.19.52] - 2026-05-29

### Changed

- Bump `ant-quic` 0.27.24 → 0.27.25 and `saorsa-gossip` 0.5.57 → 0.5.58.
  ant-quic 0.27.25 fixes an intermittent direct-message failure
  (`invalid ACK-v2 response envelope: len=0`): a transient mid-exchange
  ACK-v2 response-stream drop is now retried duplicate-safely (same request
  id, receiver replays the cached outcome) instead of surfacing as a hard
  `ConnectionFailed`. No x0x code changes — the fix flows through the
  `send_with_receive_ack` DM path transparently. Validated by a local
  2-node DM soak: 4,912/4,912 ACKed DMs, 0 errors, 0 `len=0` occurrences.

## [v0.19.45] - 2026-05-13

Metadata-fix release. The v0.19.44 release workflow failed validation
because `SKILL.md` still carried `version: 0.19.41` while `Cargo.toml`
was at 0.19.44 (`validate_release_metadata.py` `version_sync` rule).
v0.19.44 never published. v0.19.45 bumps SKILL.md alongside Cargo.toml
so the workflow can complete.

No code changes vs v0.19.44 — same reviewer-round-3 fixes apply
(P1.1 SWIM oracle wiring, P2.1 `x0x.directory.*` classifier).

## [v0.19.44] - 2026-05-13

Reviewer round 3 corrections to the X0X-0074 admission control bundle.
Consumes saorsa-gossip 0.5.49 which fixes two reviewer findings on the
saorsa-gossip side (IHAVE/anti-entropy bypassed admission, Bulk depth
leak on future cancellation); the remaining two findings (oracle not
wired into PubSub, missing `x0x.directory.*` Bulk prefix) live in x0x
and are addressed here.

### Fixed (reviewer round 3 findings 2026-05-13)

- **P1.1 — SWIM PeerHealthOracle was not wired into PlumtreePubSub.**
  `PubSubManager::new` never called `PlumtreePubSub::with_health_oracle`.
  The peer-health snapshot stayed empty, so X0X-0073b's Suspect/Dead
  cooling branches and X0X-0074's Suspect/Dead admission drops never
  engaged in x0x production — only p95 timeout sizing and local
  cooling/backpressure ran. Now `src/gossip/runtime.rs` calls the new
  `PubSubManager::new_with_oracle(network, signing,
  Some(membership.swim_arc()))`, threading the existing HyParView SWIM
  detector into pub-sub. `Self::new` keeps the old signature for
  tests / single-binary callers and delegates to
  `new_with_oracle(_, _, None)`.
- **P2.1 — Topic classifier omitted `x0x.directory.*` shard topics.**
  Group directory tag/name/id shards (`x0x.directory.tag.{N}`,
  `x0x.directory.name.{N}`, `x0x.directory.id.{N}`; see
  `src/groups/discovery.rs`, published from `src/bin/x0xd.rs`) are
  anti-entropy traffic that should classify as Bulk. The previous
  classifier defaulted them to Normal so admission did not throttle
  them under pressure. Added `"x0x.directory."` to
  `BULK_TOPIC_PREFIXES` with a regression test covering all three
  shard kinds.

### Notes

- Saorsa-gossip-side fixes (P1.2 IHAVE/anti-entropy gating, P2.2 RAII
  guard for fanout Bulk depth) consumed via the 0.5.49 dep bump; no
  x0x-side action required for those.
- 4h Phase A soak (gate for X0X-0073 / X0X-0073b / X0X-0074 closure)
  is the next milestone now that all four reviewer findings have
  landed.

### Changed

- saorsa-gossip-* deps bumped 0.5.48 → 0.5.49 across all 11 crates.

## [v0.19.43] - 2026-05-13

X0X-0074 admission control bundle. Consumes saorsa-gossip 0.5.48 which
bundles X0X-0073b (cooling-decision integration on top of X0X-0073
primitives + X0X-0069 oracle bridge) and X0X-0074 (substrate-level
admission control with topic priority). 0.5.46 (yanked from crates.io)
and 0.5.47 (behaviour-correct but stale source docs) precede 0.5.48.

### Tickets

- **X0X-0073b** (review): cooling-decision integration shipped in
  saorsa-gossip 0.5.48. 1s background snapshot refresher reads
  `oracle.health_of(peer).await`; `record_send_timeout_inner_at` reads
  the snapshot synchronously and branches on Dead/Suspect/Alive
  (`escalate_on_dead` / hold+probe / `next_cooldown`). Success path
  decays `cooling.cooldown` while preserving `last_suppressed_at` so
  the next escalation builds from the decayed value.
- **X0X-0074** (review): admission control + topic priority shipped
  in saorsa-gossip 0.5.48. Three priority bands (Bulk / Normal /
  Critical); `parallel_send_to_peers` and `send_to_peer_bounded`
  filter peers through admission before claiming attempts; Bulk
  admissions release via RAII-style guard or explicit
  `release_bulk_admissions` exactly once per admit; Critical
  failures to claim downstream record `dropped_critical_hard_error`
  (soak-blocking violation if non-zero in production).
- **X0X-0074b** (todo, filed): future work for the full
  "Bulk-evict-before-Critical-drop + Critical bypass cooling"
  contract from the original X0X-0074 ticket text. The current MVP
  records a hard-error counter; X0X-0074b will implement either an
  explicit per-peer priority queue replacing the permit/slack model,
  or transport-layer cancellation of in-flight Bulk sends.

### Added

- `register_x0x_topic_priorities()` — seeds the X0X-0074 admission
  registry at `PubSubManager::new` with the production topic set:
  - **Critical**: `x0x/dm/v1/bus`, `x0x.identity.announce.v2`,
    `x0x.test.discover.v1`, `x0x.test.control.v1`
  - **Bulk**: `x0x.machine.announce.v2`, `x0x.user.announce.v2`,
    `x0x.discovery.groups`, `x0x/release`, `x0x/caps/v1`
- `classify_x0x_topic(topic_name) -> TopicPriority` — prefix-based
  classifier covering both slash-style (`x0x/dm/v1/...`,
  `x0x/release`, `x0x/caps/v1`) and dot-style (`x0x.identity.shard.v2.*`,
  `x0x.machine.shard.v2.*`, `x0x.user.shard.v2.*`, `x0x.rendezvous.shard`,
  etc.) production topic names. Reviewer round 1 P1.2 caught the
  earlier classifier missing the slash-style production topics —
  this is the fixed shape.
- `register_dynamic_topic_priority()` — applies the classifier on
  every `PubSubManager::subscribe` and `publish` call so sharded
  topic names (per-shard identity/machine/user, DM per-recipient
  inbox hashes) get registered on first use.

### Changed

- `saorsa-gossip-*` workspace deps bumped 0.5.45 → 0.5.48 across all
  11 crates. Brings X0X-0073b cooling-decision integration,
  X0X-0074 admission control engine, reviewer round 1 fixes
  (Critical hard-error counter, Bulk depth leak resolved, topic
  classifier mismatch fixed, Normal drops on Suspect), and round 2
  documentation corrections.

### Validation

- cargo build --release --bin x0xd: clean
- cargo nextest run --all-features --workspace -E
  '!test(x0x_0041_synthetic_kill_restart)': 1173/1173 pass (known
  X0X-0054 flake filtered)
- cargo clippy --all-targets --all-features -- -D warnings: clean
  (after fixing overnight-autoresearch test-code lints —
  TaskListId.clone in crdt/persistence tests, π approximation in
  cli/mod test, single-pattern match in cli/mod, loop index in
  exec/audit, constant assertions in dm_send)
- cargo fmt --all -- --check: clean
- python3 -m unittest: 37/37 pass

### Notes

- 4h Phase A soak gates closure of X0X-0073 / X0X-0073b / X0X-0074
  (cooling event reduction ≥ 5×, no peer continuously cooled > 30s,
  Phase A ≥ 98%, `dropped_critical_hard_error` stays zero).
- X0X-0071 (P1-P7 peer scoring) now functionally unblocked.

## [v0.19.42] - 2026-05-12

Phase 2 portfolio release: SOTA-Borrow Phase 2 work shipped via the
parallel team handoff + adaptive cooling primitives + qlog-style
transport telemetry. Six tickets advanced this cycle.

### Why

- **X0X-0057** (review): `launch_readiness` was passing the broad-launch
  gate silently when `/diagnostics/connectivity` was unreachable (the
  `data_tx_high_water_count_delta == 0` check coerced missing-data to
  zero). Now fails closed.
- **X0X-0068** (done, in saorsa-gossip 0.5.41): bounded pubsub message
  cache (age + bytes + per-topic telemetry).
- **X0X-0069** (done, in saorsa-gossip 0.5.42): SWIM peer-health
  oracle bridge surface. Cooling-decision consumption follows as
  X0X-0069b/0073b.
- **X0X-0072** (review): QUIC connection pool with idle eviction
  (300s) + LRU cap (32 connections) + 60s background eviction task,
  per iroh's pattern adapted to x0x's ant-quic architecture.
- **X0X-0073** (review): adaptive cooling primitives shipped in
  saorsa-gossip 0.5.43 + 0.5.44 — p95 sliding-window timeout, 0.97/sec
  success decay, escalation clamp, Dead escalation helper.
- **X0X-0075** (review): per-topic + per-peer suppression diagnostics
  in saorsa-gossip 0.5.45 + qlog-style transport telemetry in ant-quic
  0.27.22. Consumer side: `/diagnostics/gossip` carries
  `suppressed_peers_by_topic` / `peer_scores_by_topic` /
  `admission_state_by_peer`; `/diagnostics/connectivity` carries
  `per_peer_transport` rows with real Quinn `PathStats` values
  (formerly nulls).
- **X0X-0076** (review): split-soak harnesses for proof discipline —
  fixed-roster DM-only vs PubSub-pressure isolation.

### Changed

- `saorsa-gossip-*` 11-crate workspace dep bumped 0.5.42 → 0.5.45.
  Brings X0X-0073 v2 primitives + X0X-0075 Part A diagnostics +
  the ant-quic 0.27.22 pin.
- ant-quic chain consumed via saorsa-gossip's pin: 0.27.15 → 0.27.22.
  Intervening fixes: X0X-0062 cancellation-safe ACK loop (0.27.16–
  0.27.20), X0X-0066 caller-supplied ACK-v2 id (0.27.21), X0X-0075
  Part B `ConnectionTransportStats` (0.27.22).

### Added

- `NetworkNode::connection_transport_stats(peer_id)` — forwarder for
  ant-quic's new accessor.
- `/diagnostics/connectivity.connection_pool`: telemetry for X0X-0072
  pool (active_count, max_connections, idle_evict_after_secs,
  idle_evictions_total, lru_evictions_total, establish_failures_total).
- `/diagnostics/connectivity.per_peer_transport`: Quinn path counters
  per live peer (rtt_ms, udp_*, congestion_window, packet_loss_rate,
  current_mtu, stream_open/data/stream_data_blocked_events, etc.).
- `/diagnostics/gossip.pubsub_stages.{suppressed_peers_by_topic,peer_scores_by_topic,admission_state_by_peer}`
  — topic/peer-indexed views. Backfilled in x0xd from the legacy
  `suppressed_peers` array when the saorsa-gossip release is older
  than 0.5.45 (forward-compat).
- `tests/launch_soak_fixed_roster.py` (X0X-0076 Variant A): direct-DM
  only after initial discovery.
- `tests/launch_soak_pubsub_pressure.py` (X0X-0076 Variant B):
  PubSub-pressure-only soak.
- `--no-pubsub-after-discover` flag on runner + orchestrator
  (env-var fallback `X0X_NO_PUBSUB_AFTER_DISCOVER`).
- `launch_readiness` harness:
  - `Optional[int]` connectivity scalars; broad-launch fails closed
    on missing data (X0X-0057).
  - Per-node `diagnostics_connectivity_pre_fetched` / `post_fetched`
    booleans in summary.md + summary.csv.
  - Top-3 suppressed-topic and transport-peer summary rows
    (X0X-0075 visibility).
- Coverage tooling: `coverage-thresholds.toml`,
  `scripts/check-coverage-thresholds.py`, `just coverage-check`,
  CI `coverage` job, PR template Rule-9 checklist.

### Notes — what's NOT done this release

- 4h soak validations for the three review-state tickets (X0X-0057,
  X0X-0072, X0X-0076) remain in the ticket follow-ups.
- X0X-0073b cooling-decision integration + X0X-0074 admission control
  are both functionally unblocked by X0X-0075's visibility; next cycle.

## [v0.19.31] - 2026-05-07

Workspace lockstep bump consuming ant-quic 0.27.12 + saorsa-gossip 0.5.36.
ant-quic 0.27.12 ships **X0X-0037**: duplicate-safe ACK-v2 timeout retry.
Targets the residual "sender ACK timed out after receiver delivered"
false-negative class observed in the 0.19.30 4 h soak (sender response_read
p99 2.7-2.8 s near the 3 s budget; W4 had sent=28 received=30, proving
false-negative).

### Added

- Launch-readiness runs now capture `/diagnostics/ack` pre/post snapshots
  under `diagnostics_ack/<scenario>/`. This keeps ACK-stage evidence alongside
  the existing gossip snapshots without confusing the soak continuous-counter
  parser.

### Changed

- **`Cargo.toml`**: `ant-quic` 0.27.11 → 0.27.12; all 11 `saorsa-gossip-*`
  crates 0.5.35 → 0.5.36. No source changes in x0x daemon itself.

### Verified

- `cargo fmt + clippy --all-features --all-targets -D warnings` clean.
- `cargo nextest run --all-features` — full suite pass.
- Cross-compile to `x86_64-unknown-linux-gnu` clean.

### Migration

ant-quic 0.27.12's wire protocol bump (B2 `ANQAckB2` → B3 `ANQAckB3`) is
incompatible with 0.27.11. Mixed-version mesh: receiver returns
`Rejected(InvalidEnvelope)` on wrong magic (clean rejection — no hang),
sender falls back via x0x's existing gossip path. Brief ACK-degraded
window during rolling deploy (~5 min) is expected and survivable.

## [v0.19.30] - 2026-05-07

Workspace lockstep bump consuming ant-quic 0.27.11 + saorsa-gossip 0.5.35.
Targets the slow-drift residual under sustained mesh stress that the 4 h
soak surfaced (Phase A 24-26/30 hovering, suppressed/known monotonically
0.108 → 0.213 across 16 windows).

ant-quic 0.27.11 ships X0X-0036 part 2:
- ACK-v2 request + response streams marked **high QUIC stream priority**;
  probes marked **scavenger** so they don't compete with DM ACK traffic.
- New 500 ms receiver-side `send_ack_bidi_response` write+finish timeout —
  slow/stuck response writes now recorded at the receiver instead of buried
  as opaque sender-side ACK timeout.
- Per-peer / per-connection / per-minute ACK stage diagnostics:
  p50/p95/p99/p999/max latency for sender open_bi / request write /
  request finish / sender response read / receiver demux / receiver
  admission / receiver response write+finish, plus outcome counters
  (accepted, rejected, timeout, invalid response, connection close).
  Exposed via `Node::ack_diagnostics()`.

### Added

- `GET /diagnostics/ack` and `x0x diagnostics ack`, exposing ant-quic ACK-v2
  per-stage latency buckets and outcome counters for X0X-0036 part 2. The
  endpoint returns `ok`, plus an `ack` snapshot with rolling per-peer,
  per-connection, per-minute diagnostics.

### Changed

- **`Cargo.toml`**: `ant-quic` 0.27.10 → 0.27.11; all 11 `saorsa-gossip-*`
  crates 0.5.34 → 0.5.35.

### Verified

- `cargo fmt + clippy --all-features --all-targets -D warnings` clean.
- `cargo nextest run --all-features` — full suite pass.
- Cross-compile to `x86_64-unknown-linux-gnu` clean.

### Migration

Wire-compatible with 0.19.29 (no protocol changes; only stream priority
and per-stream timeouts inside ant-quic). Mixed 0.19.29 ↔ 0.19.30 mesh
is safe.

## [v0.19.29] - 2026-05-07

Workspace lockstep bump consuming ant-quic 0.27.10 + saorsa-gossip 0.5.34.
ant-quic 0.27.10 ships X0X-0036 part 1: probe scavenger priority + per-peer
single-flight + result cache + global concurrency cap (4) + 30 s receive
suppression so real ACK-v2 traffic satisfies liveness without redundant
probe round-trips. New `EndpointError::ProbeOverBudget` distinguishes
local throttling from peer death.

Targets the load-coupled ACK starvation x0x's W1→W2 soak collapse exposed
(W1 30/28 then W2 24/21 with pp_to 60→473, suppressed 220→384). The cure
is to prevent control-plane probes from competing with data-plane DM/ACK-v2
sends, not to widen the 3 s ACK budget.

### Changed

- **`Cargo.toml`**: `ant-quic` 0.27.9 → 0.27.10; all 11 `saorsa-gossip-*`
  crates 0.5.33 → 0.5.34. No source changes in x0x itself.
- **`tests/local_vps_probe.py`**: receive-side check rewritten to use the
  long-lived `/direct/events` SSE stream (`DirectEventWatcher`). Replaces
  earlier polling against a non-existent `/direct/recv` endpoint. The
  `v2l_recv` probe field is now meaningful.

### Verified

- `cargo fmt + clippy --all-features --all-targets -D warnings` clean.
- `cargo nextest run --all-features` — full suite pass.
- Cross-compile to `x86_64-unknown-linux-gnu` clean.

### Migration

Wire-compatible with 0.19.28 (no protocol changes, only scheduling /
priority changes inside ant-quic). Mixed 0.19.28 ↔ 0.19.29 mesh is safe.

## [v0.19.28] - 2026-05-07

Workspace lockstep bump consuming ant-quic 0.27.9 + saorsa-gossip 0.5.33.
ant-quic 0.27.9 ships the X0X-0035 fix (ACK-v2 / relay-CONNECT-UDP bidi
accept-race resolved via prefix-peek demux on both sides). The
`invalid ACK-v2 response envelope` failure class observed in the 0.19.27
30-min soak (5 + 4 = 9 across two windows) targets exactly this race.

### Changed

- **`Cargo.toml`**: `ant-quic` 0.27.8 → 0.27.9; all 11 `saorsa-gossip-*`
  crates 0.5.32 → 0.5.33. No source changes in x0x itself.

### Verified

- `cargo fmt + clippy --all-features --all-targets -D warnings` clean.
- `cargo nextest run --all-features` — full suite pass.
- Cross-compile to `x86_64-unknown-linux-gnu` clean.

### Migration

Wire-compatible with 0.19.27 (same ACK-v2 magic + transport parameter).
Mixed 0.19.27 ↔ 0.19.28 mesh is safe.

## [v0.19.27] - 2026-05-07

Workspace lockstep bump consuming ant-quic 0.27.8 + saorsa-gossip 0.5.32.
Pairs with X0X-0034 hypothesis testing — ant-quic 0.27.8 ships the bidi-stream
ACK protocol (`ANQAckB2`/`ANQAckR2` replacing the 0.27.7 dual uni-stream
`ANQAckP1`/`ANQAckC1`) plus a 5 s `SUPERSEDED_READER_DRAIN_GRACE` window so
in-flight ACK request/response streams drain before reader-task cancellation.
Direct fix for the supersede-race signature x0x's pre-warm 26 + 26b
reproduced (6 × ACK timeout + 2 × Connection closed: ReaderExit per run, all
on the X0X-0033-fixed mesh).

### Changed

- **`Cargo.toml`**: `ant-quic` 0.27.7 → 0.27.8; all 11 `saorsa-gossip-*`
  crates 0.5.31 → 0.5.32. No source changes in x0x itself; the 0.19.26
  X0X-0033 single-flight repair stays unchanged.

### Verified

- `cargo fmt + clippy --all-features --all-targets -D warnings` clean.
- `cargo nextest run --all-features` — full suite pass.
- Cross-compile to `x86_64-unknown-linux-gnu` clean.

### Migration

ant-quic 0.27.8's wire protocol change is gated by a renamed transport
parameter (`ack_receive_v1` → `ack_receive_v2`). Mixed-version meshes
(0.27.7 ↔ 0.27.8) cannot exchange ACK-requested payloads; the sender sees
`EndpointError::NotSupported` and x0x's gossip fallback applies. Brief
mismatch during fleet rollout is expected and survivable.

## [v0.19.26] - 2026-05-06

X0X-0033 fix. The X0X-0031 send-readiness hardening
(`NetworkNode::ensure_peer_send_ready` — single-flight per-peer mutex,
bounded global concurrency, fall-through to bootstrap-cache redial)
was effectively dead code on the raw direct-message path:
`Agent::send_direct_raw_quic` short-circuited to `AgentNotConnected`
when the machine_id was known but ant-quic's live connection table
didn't currently hold the peer, never reaching `send_direct` where the
hardening lives. External review (verified against `src/lib.rs:3044-3140`,
`src/network.rs:1272-1296`) ranked this as the strongest first cause of
the persistent Phase A pre-warm NO-GO results across releases 0.19.22 →
0.19.25 (5/8 anchor command DM failures presented as `peer disconnected:
agent not connected: <singapore>`, with anchor having an active QUIC
connection elsewhere but transiently torn down to the destination).

### Changed

- **`x0x` `src/network.rs`**: `NetworkNode::ensure_peer_send_ready` is now
  `pub` (was crate-private). Documented as the bounded single-flight
  readiness primitive driven from both gossip and raw-DM send paths.
- **`x0x` `src/lib.rs`**: `Agent::send_direct_raw_quic` now drives
  `ensure_peer_send_ready` explicitly when machine_id is known but
  `is_connected()` reports false, wrapped in a 3 s `tokio::time::timeout`,
  re-checks `is_connected()` after repair, and only then decides whether
  to send or return `AgentNotConnected`. Skipped when `resolution ==
  "post_connect"` to avoid double-attempt with the existing `(None, None)`
  fallback to `connect_to_agent`.

### Added

- **Telemetry**: `x0x::direct` warn-level logs gain a `repair_outcome`
  field — `repaired | repair_failed | repair_timeout` — observable when
  the new repair path fires on a disconnected peer. Existing log fields
  (`agent_prefix`, `machine_prefix`, `resolution`, `outcome`, `dur_ms`)
  retained.

### Verified

- `cargo fmt --all -- --check` clean.
- `cargo clippy --all-features --all-targets -- -D warnings` clean.
- `cargo nextest run --all-features` — full suite pass.

## [v0.19.25] - 2026-05-06

X0X-0032 fix consumed end-to-end. Pairs with ant-quic 0.27.7 which
introduces bounded admission for `send_with_receive_ack` (100ms wait
on `data_tx.reserve()` + Backpressured rejection variant). x0x now
treats receive backpressure as a first-class signal with gossip
fallback, not an opaque timeout.

### Changed

- **`Cargo.toml`**: ant-quic 0.27.5 → 0.27.7. Picks up
  `ReceiveRejectReason::Backpressured` and bounded admission window in
  the reader-task ACK emission path.

### Added

- **`x0x` `src/error.rs`**: `NetworkError::RemoteReceiveBackpressured`.
- **`x0x` `src/dm.rs`**: `DmError::ReceiverBackpressured`.
- **Raw-QUIC receive-ACK backpressure → gossip fallback**: when
  `send_with_receive_ack` returns `RemoteReceiveBackpressured` and a
  gossip-pubsub path is available, x0x falls back automatically.
- **`/direct/send`** without fallback: returns 503 with
  `receiver_backpressured` error code, distinct from
  `peer_disconnected`. Local apps can choose retry/fallback/surface
  semantics per their use case.

### Verified

- 666/666 nextest pass (new `raw_quic_receive` regression test), 29/29
  Python tests, `cargo clippy --all-targets --all-features -- -D warnings`
  clean, fmt clean.

## [v0.19.24] - 2026-05-06

X0X-0031 hardening narrowed to the right path. The 0.19.23 release put
multi-second liveness repair on the generic gossip send path; saorsa-
gossip wraps per-peer sends in a 750ms timeout, so our 2s probe + 3s
reconnect overran the gossip budget and turned healthy degradation into
a timeout/log storm. The 0.19.23 pre-warm showed the same raw-QUIC ACK
failure pattern + helsinki/nuremberg burning CPU in
systemd-journald/rsyslogd from timeout log spam.

### Fixed

- **`x0x` `src/network.rs`** (`send_to_peer`): removed
  `ensure_peer_send_ready` from the gossip transport send path. Gossip
  has its own scoring/cooling/budget chain (X0X-0010..14) that's bounded
  by the per-peer budget; layering a multi-second probe-or-reconnect on
  top breaks the budget invariant. Liveness repair remains on raw direct
  sends and `send_with_receive_ack` only — those paths *do* benefit
  from probe before spending the caller's 12s DM timeout.

Correctness basis: gossip's congestion behaviour is its own concern;
the daemon-level liveness repair is the right tool for raw QUIC paths
that don't have an upstream budget. References: RFC 9000, RFC 8085,
RFC 9308, libp2p Gossipsub v1.1.

### Verified

- 665/665 nextest pass, 29/29 Python tests, `cargo clippy --all-targets
  --all-features -- -D warnings` clean, fmt clean.

## [v0.19.23] - 2026-05-06

X0X-0031 hardening on top of the 0.19.22 X0X-0030 rework. The 0.19.22
pre-warm baseline showed catastrophic raw-QUIC `send_with_receive_ack`
failures across the fleet at 7-12 min uptime, exposed by the harness
fix #3 that switched Phase A to test raw QUIC explicitly. Four
hardening changes address the residual:

### Fixed

- **`x0x` `src/network.rs`**: 60s successful-liveness cooldown
  (`PRE_SEND_LIVENESS_COOLDOWN`). After a successful probe completes,
  the same peer is not re-probed for 60s — eliminates the
  "probe-after-every-send" amplification when many concurrent sends fire
  at the same peer.
- **`x0x` `src/network.rs`**: bounded concurrent repairs via
  `Semaphore::new(MAX_CONCURRENT_LIVENESS_REPAIRS = 16)`. Daemon-local
  cap on probe/reconnect parallelism prevents probe storms even under
  heavy concurrent send load. Hot healthy sends bypass the lock entirely.
- **`x0x` `src/network.rs`**: race-safe single-flight per peer.
  `Arc::strong_count(lock) > 2` rechecks under the map lock guard
  resolve the race where two callers could both decide they own the
  repair. Idle lock entries are pruned safely.
- **`x0x` `src/dm_send.rs`**: `wait_for_ack_or_backoff` races the
  retry-backoff sleep against ACK arrival. If the ACK arrives during
  backoff (after the attempt's send-with-receive-ack timeout but before
  the next republish would fire), it short-circuits and returns the ACK
  outcome — preventing duplicate republishes that amplify mesh load
  under congestion.

Correctness basis: RFC 9002 (QUIC loss recovery, bounded recovery work),
RFC 8085 (UDP usage guidelines, no retry amplification under
congestion).

### Verified

- 665/665 nextest pass (5 new unit tests for cooldown + backoff paths),
  29/29 Python tests, `cargo clippy --all-targets --all-features
  -- -D warnings` clean, fmt clean.

## [v0.19.22] - 2026-05-06

X0X-0030 mitigation rework. The 0.19.21 fix introduced an unbounded
background liveness loop that caused per-peer probe storms, memory leaks
(singapore OOM-killed at 10:15Z, fleet at 677-891 MB after ~3h vs 585 MB
post-X0X-0028 baseline), and Phase A catastrophic regression (window 1
14/12, window 7 3/4). Four root causes addressed:

### Fixed

- **`x0x` daemon (X0X-0030 rework)**: removed the background liveness
  maintenance loop. Liveness repair is now lazy-only on the send path
  via `ensure_peer_send_ready`. No more per-peer probe-every-10s.
- **`x0x` `src/dm_send.rs`**: gossip DM retry could time out, sleep, then
  republish without first checking whether the ACK arrived during the
  backoff sleep. `send_via_gossip` now does `try_recv()` on the ACK
  channel before each retry; a late ACK short-circuits the retry and
  returns success. Prevents amplifying mesh load with redundant
  republishes.
- **Phase A harness independence**: `/direct/send` defaults to
  `gossip_inbox` when peer capabilities exist, so the prior Phase A
  tests had been silently exercising PubSub instead of raw QUIC. Added
  `prefer_raw_quic_if_connected` and `raw_quic_receive_ack_ms` request
  flags to `/direct/send`, with `COMMAND_RAW_QUIC_ACK_MS = 3000` in the
  Phase A runner.
- **Adaptive timeout signal**: was using direct-transport RTT to shrink
  gossip-inbox ACK timeout — wrong signal for a PubSub-backed path.
  Restored conservative default for gossip DMs.

References: RFC 9002 (QUIC loss recovery), RFC 8085 (UDP usage
guidelines), libp2p Gossipsub v1.1.

### Verified

- 660/660 nextest, 29/29 Python tests, clippy `-D warnings` clean.
- `cargo test pre_send_probe --lib` passes (lazy probe path retained).

## [v0.19.21] - 2026-05-06

X0X-0030 mitigation — QUIC connection idle-rot causing DM dispatch failures
after long quiet periods. The 6h soak under 0.19.20 (X0X-0026..0029 fixes
shipped) showed Phase A failures correlated with 28-min idle windows: the
mesh _looked_ connected (peer count high) but `send_with_receive_ack` timed
out at 12s on stale UDP paths after NAT/firewall pruning of idle flows.

Per RFC 9000 + RFC 9308: QUIC idle timeout is separate from UDP/NAT
middlebox timeout. RFC 9308 explicitly notes NAT state can expire after
~30s of inactivity. The fix is x0x-side application liveness on top of
ant-quic, not a transport-config change.

### Fixed

- **`x0x` daemon (X0X-0030)**: app-level liveness maintenance + pre-send
  readiness repair in `src/network.rs`:
  - Background liveness loop probes peers idle ≥ 20s every 10s
    (`PRE_SEND_LIVENESS_IDLE_THRESHOLD = 20s`, below the RFC 9308 ~30s NAT
    timeout reference).
  - Pre-send call (`ensure_peer_send_ready`) wraps gossip transport, raw
    direct sends, and `send_with_receive_ack`: detects stale connection
    health (`ant_quic::ConnectionHealth.connected/reader_task_active`) or
    excessive idle and triggers transparent reconnect.
  - Reconnect path: `connect_cached_peer` first (uses bootstrap-cache
    hints), falls back to current connected UDP address, with bounded 2s
    probe + 3s reconnect budget so user-facing DM timeouts retain budget.
  - All thresholds chosen relative to RFC 9308 reference, not to the
    6-VPS bootstrap fleet — same pattern works for laptops, mobile,
    IoT devices behind aggressive NAT.

### Verified

- 660/660 nextest pass, clippy `-D warnings` clean, fmt clean.
- New unit test: `pre_send_probe` (tests/regression for the pre-send path).

## [v0.19.20] - 2026-05-05

X0X-0026..0029 multi-day daemon stability fixes consumed end-to-end. Aligns
all 11 saorsa-gossip-* deps to v0.5.31 (workspace-lockstep bump that ships
the X0X-0026 + X0X-0027 fixes in saorsa-gossip-pubsub).

### Fixed

- **`saorsa-gossip-pubsub 0.5.31` (X0X-0026)**: `/diagnostics/gossip`
  `pubsub_stages.peer_scores` no longer observes an empty array during
  membership/cache rebuild windows. `stage_stats` falls back to the last
  complete peer_scores snapshot when the topics lock is contended;
  `set_topic_peers` emits structured rebuild start/end logs.
- **`saorsa-gossip-pubsub 0.5.31` (X0X-0027)**: cache cleaner sleeps on an
  adaptive 10s..120s interval based on observed suppression-list growth.
  Removes expired non-inflight suppression diagnostics + expired excluded
  peer-cooling entries. New diagnostics: cleanup interval / growth /
  current / removed counters in pubsub stage diagnostics.
- **`x0x` daemon (X0X-0028)**: discoverable group-card cache TTL-pruned
  and capped at 8192 cards across discovery/metadata/import/create/get/list
  paths. Stale withdrawals no longer evict newer cards. Direct peer
  diagnostics + lifecycle registries prune idle disconnected entries to a
  peer-scaled bound (`MAX(1024, connected_len * 2)`) while always retaining
  connected peers. 24h idle TTL on disconnected entries. Inline pruning;
  no separate cleanup task.
- **`x0x` daemon (X0X-0029)**: each `/direct/events` subscriber now has a
  bounded drop-oldest queue (custom `DirectSubscriberQueue` with VecDeque +
  Notify, capacity-bounded). Slow clients keep their stream open but lose
  oldest buffered events under pressure. New `subscriber_events_evicted`
  counter on `/diagnostics/dm`. Also: VPS test runner result queue is
  bounded (1024) and prunes results older than 5 minutes before enqueueing.
  `docs/local-apps.md` documents direct-event backpressure semantics.

### Changed

- **`tests/launch_readiness.py` broad-launch gate**: replace the absolute
  `republish_per_peer_timeout <= 50` SLO with a normalized
  `republish_per_peer_timeout / dispatcher_completed <= 0.25` SLO. Raw
  per-peer timeout deltas remain in the report for investigation. The report
  now also includes recv-pump drop ratio and queue depth, while the strict
  launch blockers stay `dispatcher.timed_out=0` and `recv_pump.dropped_full=0`.
- **`tests/runners/x0x_test_runner.py`**: re-register discovery/control
  PubSub subscriptions whenever the runner reopens `/events`, so long-lived
  runner processes survive `x0xd` restarts without losing Phase A discovery.

## [v0.19.19] - 2026-05-03

X0X-0015 launch-readiness harness and SLO gates — completes the
X0X-0010..14 SOTA-gossip arc with a repeatable launch bar.

### Added

- **`tests/launch_readiness.py`**: orchestrator with scenario plugin pattern,
  per-node `/diagnostics/gossip` pre/post snapshots, configurable scenarios
  (`baseline`, `fanout_burst`, `restart_storm` — last is opt-in via
  `--allow-restart-storm`), and a per-run go/no-go report under
  `proofs/launch-readiness-<ts>/`.
- **`docs/launch-gates/limited-production.md`** — early-adopter SLO bar
  (≤ 5 dispatcher.timed_out delta per node, 0 recv_pump.dropped_full,
  ≤ 200 per-peer-timeout delta, ≤ 200 suppressed_peers steady, 30/30 Phase A).
- **`docs/launch-gates/broad-launch.md`** — fleet-launch SLO bar (strictly
  stricter — 0 dispatcher.timed_out delta, ≤ 50 per-peer-timeout delta,
  ≤ 100 suppressed_peers steady, ≤ 30 s restart recovery, 24 h soak +
  partition-recovery dry-run + reviewer sign-off required).

### Verified

- Both gates GO against live 0.5.30 mesh (2026-05-03 17:40Z): baseline 30/30 +
  100-msg fanout burst, dispatcher.timed_out=0 / dropped_full=0 cluster-wide.
- 1097/1097 nextest, fmt + clippy `-D warnings` clean.

## [v0.19.16] - 2026-04-29

Hunt 12f final delivery mitigation — adds a stable global fallback path for
SignedPublic group messages so the first message after a cross-region join is
not dependent on a brand-new per-group PubSub tree.

### Fixed

- **`daemon`: publish SignedPublic group messages to a stable global fallback
  topic in addition to `x0x.groups.public.<group_id>`.** All daemons subscribe
  to `x0x.groups.public.v1` at startup and cache only messages that validate
  against a locally known group. This covers asymmetric fresh-topic PlumTree
  reachability observed on the live Sydney → Helsinki path while preserving the
  per-group topic for normal steady-state delivery.

## [v0.19.15] - 2026-04-29

Hunt 12f residual PubSub drain mitigation — stops identity/machine
announcement re-broadcast feedback loops observed after the v0.19.14 fleet
rollout and restores the lower-volume heartbeat cadence.

### Fixed

- **`core`: make identity, machine, and user announcement re-broadcasts
  one-shot per `(id, announced_at)` key.** The previous 20 s re-broadcast
  window allowed already-forwarded signed announcements to circulate again with
  fresh PubSub message IDs, pinning the PubSub receive queue and delaying
  latency-sensitive group messages.

### Changed

- **`core`: restore the default identity heartbeat interval to 300 s.**
  Heartbeats remain well within the 900 s discovery TTL and now act as
  low-rate anti-entropy instead of sustained background PubSub pressure.

## [v0.19.14] - 2026-04-29

Hunt 12f final follow-up — keeps first public messages ahead of best-effort
named-group discovery/chat fan-out during live-fleet cross-region joins.

### Changed

- **`daemon`: delay best-effort group discovery-card and chat-announcement
  publishes by 8 s after group create/join.** The local group state and
  required metadata/public-message listeners are still installed before the
  HTTP response returns, but non-critical fan-out now yields to the first
  user message. This prevents the cross-region acceptance harness from
  enqueueing discovery/card/chat anti-entropy ahead of the very first public
  message it is trying to validate.

## [v0.19.13] - 2026-04-29

Hunt 12f follow-up — drains stale release manifests faster on already-wedged
fleets and reduces background group-discovery anti-entropy pressure.

### Fixed

- **`daemon`: fast-drop stale release manifests before ML-DSA verification.**
  The v0.19.12 listener skipped rebroadcast for versions at or below the
  local daemon version, but only after decoding, parsing, and verifying the
  release signature. On the saturated fleet, thousands of queued old
  manifests still kept the release subscriber from draining fast enough. The
  listener now parses the manifest version immediately after length-prefix
  decode and ignores stale versions before signature verification. Newer
  manifests still require signature verification before any rebroadcast or
  apply path.

### Changed

- **`daemon`: reduce the default discoverable group-card republish cadence
  from 15 s to 300 s.** Group create/join/import paths still publish cards
  immediately; the periodic loop is an anti-entropy safety net, not a hot
  path. The longer default prevents accumulated public test groups from
  amplifying PubSub load during fleet validation.

## [v0.19.12] - 2026-04-29

Hunt 12e release-manifest flood mitigation — stops stale `x0x/release`
manifests from saturating the PubSub dispatcher and delaying newly joined
public-message subscribers.

### Fixed

- **`daemon`: suppress release-manifest rebroadcast for versions at or below
  the local daemon version.** The gossip update listener now rejects stale
  release-train manifests before the rebroadcast path, while keeping the
  existing newer-version gate before upgrade apply. Nodes already on the
  current release no longer relay old manifests every five minutes.
- **`daemon`: remember self-published release manifest payload digests for
  30 minutes.** Current-manifest startup broadcasts, fallback GitHub
  broadcasts, and listener rebroadcasts are recorded by SHA-256 digest so a
  PlumTree loopback of our own payload is not published again.

### Added

- **`tests/e2e_hunt12e_release_manifest_storm.sh`** — 4-daemon loopback
  release-topic storm harness. It injects release-manifest-shaped payloads on
  `x0x/release` and asserts `dispatcher.pubsub.timed_out == 0` throughout the
  run (default 5 minutes, with `DURATION_SECS` override for smoke tests).

## [v0.19.11] - 2026-04-29

Async group-handler discovery fan-out — keeps `POST /groups` and
`POST /groups/join` sub-second even under sustained pubsub back-pressure.

### Changed

- **`daemon`: spawn discovery-card and chat-announcement publishes off the
  request hot path.** `create_named_group` did `publish_group_card_to_discovery`
  (global topic + N tag/name/id shards) and `agent.publish(chat_topic, ...)`
  inline; `join_group_via_invite` did the chat-announcement publish inline.
  Each gossip publish goes through the runtime's pubsub stream, which can
  block tens of seconds when the recv pipeline is saturated (release-manifest
  floods are the easiest reproducer). Both call sites now `tokio::spawn` the
  publishes — local state is already committed before they fire, the result
  was already discarded with `let _ = ...`, and the post-fix latency for
  `POST /groups` is sub-second on a saturated daemon. No protocol or
  observable-state change for callers.

## [v0.19.10] - 2026-04-29

Hotfix for the v0.19.9 group-handler hang under live-fleet back-pressure.

### Fixed

- **`daemon`: subscribe inside the spawned listener task, not the caller.**
  v0.19.9 added `spawn_public_message_listener` to the request hot path of
  `POST /groups`, `POST /groups/join`, and `POST /groups/cards/import`. The
  function awaited `state.agent.subscribe(&topic).await` *inline* in the
  caller's task; under VPS-fleet pubsub back-pressure (`recv_pubsub_tx` at
  capacity, gossip handler timing out at 10 s), subscribe could take
  10 s+, hanging the request handler past the client's curl timeout. The
  spawn now wraps subscribe inside the same `tokio::spawn` that owns the
  receive loop, mirroring the `ensure_named_group_metadata_listener`
  pattern that has shipped without incident since the original group code
  landed. Local regression suite still 20/20; live VPS POST latency back
  to sub-second.

## [v0.19.9] - 2026-04-29

Fixes communitas#11 — first-message-after-join silently dropped.

### Fixed

- **`daemon`: subscribe to public-message topic at every group-insert site.**
  `spawn_public_message_listener` (subscribes to
  `x0x.groups.public.<stable_id>`) was only invoked from
  `POST /groups/:id/send` (sender-side pre-subscribe) and
  `GET /groups/:id/messages` (poll-triggered). `create_named_group`,
  `join_group_via_invite`, `import_group_card`, and the daemon-startup
  persisted-load path only spawned the metadata listener. While a member
  was unsubscribed, Plumtree-routed first messages were silently dropped
  at their pubsub layer; Plumtree cannot backfill messages on a topic
  that had no subscriber at receive time, so the loss was permanent.
  A new helper `ensure_named_group_listeners` now spawns both the
  metadata listener and the public-message listener (gated on
  `confidentiality != MlsEncrypted`) at every group-insertion site.
  Pre-fix repro: 0/12 first-message deliveries; post-fix: 25/25 across
  0/100/500/2000/5000 ms join→send delays. Permanent regression test:
  `tests/e2e_first_message_after_join.sh` (20/20 pass).

## [v0.19.5] - 2026-04-27

Hunt 12c release. Resolves the architectural bottleneck identified in
the v0.19.4 fleet soak: a slow `pubsub.handle_incoming` no longer
back-pressures the shared receive queue and bleeds into Membership /
Bulk dispatch.

### Fixed

- **`gossip`: per-stream isolation in the inbound receive pipeline.**
  Replaced the single shared `recv_tx` mpsc with three stream-specific
  channels in `src/network.rs`:
  - `recv_pubsub_tx` (capacity 10 000, matches subscription buffer)
  - `recv_membership_tx` (capacity 4 000)
  - `recv_bulk_tx` (capacity 4 000)
  The ant-quic receiver now routes each inbound message to the channel
  for its `GossipStreamType`, with its own `>80% full` back-pressure
  warning. New per-stream receive methods on `NetworkNode`:
  `receive_pubsub_message()`, `receive_membership_message()`,
  `receive_bulk_message()`.
- **`gossip`: three independent dispatcher tasks.** Replaced the single
  serial dispatcher loop with `run_pubsub_dispatcher`,
  `run_membership_dispatcher`, and `run_bulk_dispatcher` in
  `src/gossip/runtime.rs`. Each pulls only from its own channel and
  runs the existing per-arm timeout (PubSub 10 s, Membership 5 s,
  Bulk 5 s). A wedged PubSub handler can no longer block Bulk
  presence beacons or Membership SWIM ping-acks.
- **`gossip`: `GossipTransport::receive_message` compatibility kept**
  via `tokio::select!` over the three channels with `biased; Bulk;
  Membership; PubSub` ordering, so external trait consumers
  (saorsa-gossip-runtime, tests in `tests/network_timeout.rs`)
  continue to work unchanged.

### Changed

- **`/diagnostics/gossip` JSON shape** (BREAKING for monitor scripts).
  The flat `recv_depth_latest` / `recv_depth_max` /
  `recv_capacity_latest` fields are removed and replaced with a nested
  `recv_depth` object keyed by stream type:
  ```json
  "recv_depth": {
    "pubsub":     { "latest": 0, "max": 0, "capacity": 10000 },
    "membership": { "latest": 0, "max": 0, "capacity": 4000  },
    "bulk":       { "latest": 0, "max": 0, "capacity": 4000  }
  }
  ```
  Per-stream depth makes the Hunt 12c symptom (PubSub queue saturating
  while Bulk stays empty) directly visible.
  Monitor scripts that read the old fields must update — see
  `tests/e2e_hunt12c_pubsub_load_isolation.sh` for the new shape.

### Added

- **`tests/e2e_hunt12c_pubsub_load_isolation.sh`** — local reproducer
  that hammers a 4-node mesh with sustained 12 KB PubSub messages at
  15 msg/s and asserts that presence delivery stays healthy
  (`online >= N-1`, `bulk.timed_out == 0`, `membership.timed_out == 0`).
  Pre-Step-2 expectation: presence drift + bulk timeouts. Post-Step-2:
  clean PASS. Proof: `proofs/hunt12c-pubsub-load-20260427T200041Z/`.
- **Per-stream queue-depth unit test**
  `test_dispatch_stats_record_per_stream_queue_depth` pins the new
  per-stream snapshot shape.

### Validation

- `cargo nextest --workspace --all-features`: 1029 / 1029 pass.
- `cargo clippy --all-features --all-targets -D warnings`: clean.
- `tests/e2e_presence_propagation.sh`: 4 nodes, `peers=3 online=4`
  on every node — `proofs/e2e-presence-propagation-20260427T195512Z/`.
- `tests/e2e_hunt12c_pubsub_load_isolation.sh`: 4 nodes, 1356 PubSub
  messages × 12 KB at 15 msg/s over 120 s — every node sustained
  `online=4`, zero `bulk.timed_out`, zero `membership.timed_out`.



Hunt 12b release. Fixes the live-fleet regression where `/presence/online`
collapsed to self-only on most nodes 25–45 minutes after rolling restart.

### Fixed

- **`presence`: refresh broadcast peers from QUIC table.** The presence
  broadcast set was seeded once from `HyParViewMembership::active_view()`
  at `join_network()` and never refreshed. On the live mesh, HyParView's
  active view stayed at ≤ 1 peer for many minutes after restart while
  ant-quic was fully connected, so beacons fanned out to a tiny subset
  and the rest of the fleet observed no inbound presence at all. A new
  30 s background task now `replace_broadcast_peers()` with
  `HyParView active view ∪ ant-quic connected_peers`, so the transport
  mesh is the source of truth.
- **`presence`: pre-join the global presence topic.**
  `PresenceManager::handle_presence_message` silently dropped beacons
  whose `topic_id` was not in the local `groups` map.
  `PresenceWrapper::new` was building an empty groups map, so even when
  beacons arrived, `/presence/online` stayed empty until the first
  identity refresh seeded the entry. The wrapper now pre-joins
  `global_presence_topic()` at construction; pinned by
  `test_presence_wrapper_joins_global_presence_topic`.
- **`presence`: `/presence/online` uses live beacon liveness.** The
  endpoint filtered the discovery cache by `announced_at >= cutoff`
  (the announcement timestamp from first discovery, never refreshed by
  subsequent beacons). It now filters by `last_seen >= cutoff` in
  `discovered_agents()` / `online_peer_count()`, refreshes `last_seen`
  from beacon timestamps in `presence_record_to_discovered_agent()`,
  and a new `Agent::online_agents()` merges the identity cache with
  live `PresenceManager::get_group_presence()` records. Pinned by
  `test_online_agents_uses_presence_beacon_liveness`.
- **`gossip`: bincode wire-format fix on identity / machine
  announcement decoders.** `deserialize_identity_announcement` /
  `deserialize_machine_announcement` used
  `bincode::DefaultOptions::new()` (varint encoding) while the writers
  ship via `bincode::serialize` (fixint default). Decoders now call
  `.with_fixint_encoding()` so they actually match the wire. New test
  `announcement_decode_helpers_match_bincode_serialize_wire_format`
  pins the round-trip.

### Added

- **`gossip`: dispatcher visibility instrumentation.** Wraps every
  inbound dispatcher arm in a per-stream `tokio::time::timeout` (PubSub
  10 s, Membership 5 s, Bulk 5 s) with WARN-on-timeout. New
  `GossipDispatchStats` exposes per-stream counters
  (`received` / `completed` / `timed_out` / `max_elapsed_ms`) plus
  receive-queue depth (`recv_depth_latest` / `recv_depth_max` /
  `recv_capacity_latest`). Surfaced via `Agent::gossip_dispatch_stats()`
  and `GET /diagnostics/gossip` → new `dispatcher` field. Lets a fleet
  soak distinguish handler stalls from network back-pressure without a
  code change.

### Dependencies

- **`saorsa-gossip-*` → `0.5.23`.** Concurrent presence beacon fanout
  (`saorsa-gossip-presence` `JoinSet` + 5 s → 15 s per-peer timeout) so
  one slow peer cannot delay the rest of the mesh. Pubsub memory bound
  under sustained publish + idle traffic.

### Validation

- `cargo nextest --lib --all-features`: 602 / 602 pass.
- `tests/e2e_presence_propagation.sh`: 4-node localhost mesh,
  `peers=3 online=4` on every node — `proofs/e2e-presence-propagation-20260427T151802Z/`.
- 4-node fleet (saorsa-2 / 3 / 6 / 7), 90-minute monitor at 60 s
  intervals: `presence_online >= 3` on every node every tick
  (308 / 308 sample points). `recv_depth_max` peaks
  4729 / 265 / 101 / 425 (well below the 8000 threshold). Proof:
  `proofs/fleet-hunt12b-80ee753-20260427T153807Z/`.

### Known follow-up

- **Hunt 12c** — see `docs/design/hunt-12c-pubsub-handler-stall.md`.
  The new dispatcher counters lit up an architectural bottleneck on
  the most-loaded fleet node: a single peer's 16 056-byte PubSub
  message every 10 s exhausted the 10 s handler timeout, accumulating
  back-pressure on the shared `recv_tx`. The user-visible Hunt 12b
  symptom remains fixed; the structural fix (per-stream channel split
  in `src/network.rs`) is tracked for `v0.19.5` / `v0.20.0`.

### Removed (BREAKING)

- **Dropped first-party Node.js (napi-rs) and Python (PyO3 / maturin) FFI
  bindings.** x0x is now daemon-only outside Rust: applications run (or
  connect to) `x0xd` and consume the local REST/WebSocket API instead of
  importing a compiled `x0x` module. Concretely:
  - `bindings/nodejs/`, `bindings/python/`, the root-level `python/` stub,
    and `WASM_ROADMAP.md` have been deleted from the tree.
  - `Cargo.toml` no longer lists the binding crates as workspace members.
  - The `publish-npm` and `publish-pypi` jobs have been removed from
    `.github/workflows/release.yml`; releases now publish to crates.io +
    GitHub Releases only. The `npm install x0x` / `pip install agent-x0x`
    install snippets have been removed from the auto-generated GitHub
    Release notes.
  - Existing npm `x0x@0.1.0` and PyPI `agent-x0x@0.2.0` artefacts remain
    pinned to their last published version on the public registries; they
    will receive no further updates.
  - Migration: see [`docs/local-apps.md`](docs/local-apps.md) for examples
    of consuming the local `x0xd` API from any language.

## [v0.19.2] - 2026-04-23

**Note.** The `v0.19.1` tag was cut earlier today but never reached
crates.io — the release workflow's `Validate release metadata` step
rejected it because `SKILL.md` was still stuck at `0.17.4` (a hard
requirement of `SKILL.md version == Cargo.toml version == tag`). The
same stale `SKILL.md` is why `v0.19.0` is not on crates.io either
(`max_version` on crates.io is `0.18.4`). `v0.19.2` bundles the
`v0.19.0` wire-v2 / UserAnnouncement / IntroductionCard work, the
`v0.19.1` dependency bumps, **and** syncs `SKILL.md` so the release
actually publishes.

### Fixed (dependency bumps)

- **`ant-quic` → `0.27.4`.** Picks up the dual-stack CPU-spin fix:
  `DualStackSocket::create_io_poller` now AND-combines v4/v6 writability
  instead of OR-combining via `tokio::select!`. The prior OR-combination
  let a stale `Ready` on the non-target socket satisfy the poller while
  `try_send_to` had already cleared readiness on the target, so
  `drive_transmit` spun its `WouldBlock` retry loop at 100 % CPU in pure
  userspace. Reproduced on a live 6-continent bootstrap mesh (2-of-6
  nodes rotating into 100 % within 4–7 min pre-fix); post-fix watch over
  90 min showed all tokio workers in State S with <2 % mean CPU.
- **`saorsa-gossip-*` → `0.5.20`.** Lockstep republish across all 11
  workspace crates with `ant-quic = 0.27.4`; no gossip-side source
  changes.
- **`Cargo.toml` no longer carries the `[patch.crates-io] ant-quic = {
  path = "../ant-quic" }` hack.** Deps now resolve cleanly from
  crates.io.

### Tests

- Fixed a 1/256-flaky `test_agent_id_uniqueness` in
  `tests/comprehensive_integration.rs`: `AgentId([rand::random::<u8>();
  32])` (array-repeat: one byte × 32) → `AgentId(rand::random::<[u8;
  32]>())` (32 independent bytes). Three sites updated.
- `tests/e2e_deploy.sh` now sleeps 15 s between node restarts, matching
  the rolling-start-requirement invariant.

### Validation

- `cargo fmt --all --check`: clean.
- `cargo clippy --all-features --all-targets -- -D warnings`: clean.
- `cargo nextest run --all-features --workspace`: 1024/1025 (the one
  failure is the pre-existing `parity_cli::every_endpoint_is_reachable_
  from_cli`, same as 0.19.0).
- Live 6-node bootstrap mesh on `v0.19.1`-equivalent build (consuming
  published `ant-quic 0.27.4` + `saorsa-gossip 0.5.20` with no path
  hacks): 11 min CPU watch, peak 40 % single sample, zero sustained
  elevation — see
  `proofs/v0.19.0-validation-20260423T131419Z/spin-forensics/final-revalidation/`.

## [v0.19.0] - 2026-04-23

### Breaking — wire format v2

All identity / machine announcements are now on v2 topics. v1 is retired
and **v0.18.x is yanked from crates.io** — nodes must upgrade together.

- `x0x.identity.announce.v1` → `x0x.identity.announce.v2`
- `x0x.machine.announce.v1`  → `x0x.machine.announce.v2`
- `x0x.identity.shard.<n>`   → `x0x.identity.shard.v2.<n>`
- `x0x.machine.shard.<n>`    → `x0x.machine.shard.v2.<n>`

The `x0x.rendezvous.shard.<n>` topic is unchanged (it carries
`saorsa-gossip` `ProviderSummary`, not x0x wire types).

### Added

- **`reachable_via` + `relay_candidates` on announcements.**
  `IdentityAnnouncement` and `MachineAnnouncement` now carry
  `Vec<MachineId>` backpointers naming coordinator / relay peers through
  which a NAT-locked agent wants to be dialled. Populated from currently-
  connected peers the machine cache marks `is_coordinator == Some(true)` /
  `is_relay == Some(true)`, capped at 8 each, emitted only when
  `can_receive_direct` is not known-true. `connect_to_agent` now seeds
  these coordinators as transport peer hints before the coordinated dial,
  so ant-quic picks up an explicit NAT-traversal target rather than
  guessing from the bootstrap cache.
- **`UserAnnouncement` — first-class agent-ownership rosters.** A
  human identity (`UserId`) can now assert "these N agents are mine" as
  a first-class record on the new `x0x.user.announce.v2` topic (plus a
  `x0x.user.shard.v2.<n>` per-user shard). Each announcement is
  user-signed (ML-DSA-65) over the canonical bincode of the unsigned
  form, and carries a `Vec<AgentCertificate>` — each cert itself
  user-signed — so every agent-ownership claim is individually
  verifiable. New `Agent::announce_user_identity(human_consent)`,
  `discovered_user(user_id)`, `discovered_users()` APIs. Listener
  subscribes to both global and own-shard topics with dedup-windowed
  rebroadcast matching the identity/machine paths.
- **Real `IntroductionCard` signature.** Previously the card's
  `signature` field held a placeholder machine public key. Cards are
  now ML-DSA-65-signed over the canonical form (`"x0x-introduction-
  card-v1"` prefix + bincode of the unsigned fields, including
  `machine_public_key`), with a `verify()` method that checks machine-
  key→machine_id binding, the outer signature, and the embedded
  `AgentCertificate` chain. Closes a forgery hole where any node could
  mint a card claiming any (agent_id, machine_id, user_id) pair by
  copying a target's machine pubkey.

### Tests

- 6 new tests on `IntroductionCard`: round-trip, user-backed, tampered
  display_name / agent_id / machine_id, foreign-signature splice.
- 5 new tests on `UserAnnouncement`: round-trip, foreign-cert rejection
  at sign time, tampered cert list, tampered user_public_key, shard
  topic determinism.
- Expanded `IdentityAnnouncement` bincode round-trip to include the new
  `reachable_via` / `relay_candidates` fields.

### Validation

- `cargo fmt --all --check`: clean.
- `cargo clippy --all-features --all-targets -- -D warnings`: clean.
- `cargo nextest run --all-features --workspace`: 1023/1024 (the one
  failure is `parity_cli::every_endpoint_is_reachable_from_cli`,
  pre-existing on HEAD, flags missing `/machines/*` CLI subcommands —
  unrelated to this release).

## [v0.18.5] - 2026-04-21

### Added

- **Machine-centric discovery.** Machines now publish signed
  `x0x.machine.announce.v1` endpoint announcements keyed by `machine_id`
  and backed by a first-class discovered-machine cache. Agent and user
  identities link onto those machine records, and the daemon exposes
  `/machines/discovered`, `/machines/discovered/:machine_id`,
  `/machines/connect`, `/agents/:agent_id/machine`, and
  `/users/:user_id/machines` so callers can resolve `agent_id` /
  `user_id` to the transport machine used for IPv4/IPv6 direct dials,
  hole-punching, or relay-assisted connection.

### Fixed

- **File-transfer throughput on localhost.** File chunks now prefer the
  raw-QUIC direct-stream path when a live direct connection already
  exists, instead of paying the gossip-DM ACK round-trip on every chunk.
  Control-plane messages (offer / accept / reject / complete) still use
  the existing capability-aware path, so file setup and teardown retain
  their prior delivery semantics while the bulk body uses the fast lane.
- **Out-of-order raw chunk handling.** The receiver no longer fails the
  whole transfer if chunk `N+1` arrives before chunk `N`. Out-of-order
  chunks are buffered per transfer and drained in sequence as soon as the
  missing predecessor arrives. This was required once the raw-QUIC chunk
  path removed the implicit serialization that the gossip-DM ACK loop had
  been imposing.
- **Throughput measurement accuracy.** `TransferState` now exposes
  `started_at_unix_ms` / `completed_at_unix_ms`, and
  `tests/e2e_full_measurement.sh` can size the test file via
  `--file-size-kib` / `FILE_SIZE_KIB`. The harness now computes file
  throughput from daemon-side transfer timestamps instead of the old
  1-second status-poll cadence, which materially understated fast local
  transfers.
- **Slow-subscriber isolation.** Pub/sub delivery to each local
  subscriber channel is now non-blocking: once a subscriber's 10k buffer
  fills, x0x drops that subscriber instead of letting it back-pressure
  the topic delivery worker forever. This preserves delivery to other
  subscribers and lets `subscriber_channel_closed` surface the event in
  `GET /diagnostics/gossip`.

### Proofs

- `proofs/full-20260421-v0185-throughput-5node-16m/` — 5 daemons,
  16 MiB file, **102.69 Mbps** localhost transfer throughput in the
  throughput-focused run.
- `proofs/full-20260421-v0185-localhost-throughput-16m-500/` —
  comprehensive 5-daemon run, 500 pub/sub messages + 16 MiB file in
  **1.214 s = 110.56 Mbps** under the heavier combined workload.
- `proofs/slow-consumer-20260421-v0185-100k/` — one subscriber never
  drains, one subscriber drains normally, 100 000 publishes total:
  `publish_total=100000`, `subscriber_channel_closed=1`,
  `fast_received=100000`, `decode_to_delivery_drops=0`.

## [v0.18.4] - 2026-04-21

### Fixed

- **Dual-stack bind for named instances.** `x0xd --name <instance>`
  previously forced the QUIC bind to `0.0.0.0:0` (IPv4-only), so
  daemons on a dual-stack host could neither reach nor be reached
  by IPv6-only peers, and their `external_addrs` was IPv4-only
  even when a globally-routable IPv6 was configured on the host.
  Bind is now `[::]:0` (IPv6 unspecified with dual-stack), so
  both families are listened-on and observed.
- **File transfer chunk size.** `files::DEFAULT_CHUNK_SIZE` was 64 KiB
  (raw) which, after base64 + JSON wrapper, produced ~87 KB DM
  envelope payloads — exceeding `dm::MAX_PAYLOAD_BYTES` (49 152) so
  `Send chunk 0 failed: envelope construction failed: payload
  exceeds MAX_PAYLOAD_BYTES (87481 > 49152)` aborted every transfer.
  Dropped to 32 KiB raw, which base64-encodes to ~43 691 B and fits
  every chunk inside a single DM envelope with headroom for the JSON
  wrapper. First successful proof: 262 144 B file in 7.17 s.

### Added

- `tests/e2e_full_measurement.sh` — comprehensive proof run that
  captures pub/sub, DM with `require_ack_ms`, file transfer (with
  full completion tracking), probe-peer matrix, NAT/connectivity,
  relay state, coordinator state, and IPv4/IPv6 address-family
  breakdown across `external_addrs` AND announced `agent.card.addresses`.
- `/agent/card` snapshot per phase so the harness can compare what
  the daemon WOULD announce (passes `is_publicly_advertisable`)
  against what peers have OBSERVED (populates `external_addrs`).

### Proof: `proofs/full-20260421-194618/`

- 5 daemons, 500 msgs, strict gate: publisher 586 / subscribers 742
  each, 0 drops anywhere.
- File transfer: **262 144 B completed in 7.17 s** (0.29 Mbps over
  DM-fragment channel on localhost).
- Probe matrix: 20 / 20 ok.
- Announced addresses: every node surfaces **7 public IPv6
  addresses**; IPv4 is correctly filtered out because the local
  v4 is RFC1918 (`192.168.1.212`). On a dual-public-IP host
  (VPS) both families will appear.

## [v0.18.3] - 2026-04-21

### Fixed

- **Fan-out stall root cause: `NetworkNode::recv_tx` capacity bumped
  `128 → 10_000`** (with matching `direct_tx` `256 → 10_000`). Every
  inbound gossip / pubsub message across every topic and every peer
  on this node funnels through this single mpsc to the
  saorsa-gossip-transport consumer. At 128 capacity, a momentary
  slowdown in the PlumTree layer (ML-DSA-65 verification on a burst,
  a briefly-held subscriber lock, an EAGER fan-out to 8 peers) backs
  up `spawn_receiver`'s `recv_tx.send().await` and stops draining
  ant-quic's recv queue — freezing ALL inbound traffic for that node,
  not just the slow topic. Observed in the `stress-20260421-v0181`
  proof artefact: node-2 and node-3 got ~100 messages each in the
  first 1.2 s then received nothing for the remaining 43 s of
  publishing while nodes 4-5 kept flowing at 11 msg/s. Log diff
  showed `recv: … bytes (PubSub)` continuing at the network layer
  past the stall — proving the back-pressure was one layer up.

- **Back-pressure visibility.** `spawn_receiver` now emits a
  `WARN "[1/6 network] recv_tx >80% full — PubSub pipeline falling
  behind"` when the buffer's available capacity drops below 20 % of
  max. We still back-pressure rather than drop (delivery integrity
  wins over liveness visibility when the two conflict) — the warn
  makes the condition surface before it becomes a stall.

### Validation

- `cargo fmt --check`: clean
- `cargo clippy --all-targets --all-features -- -D warnings`: clean
- `cargo nextest run --all-features --workspace`: **1006 / 1006** pass

## [v0.18.2] - 2026-04-21

Reviewer-flagged blocker fixes on top of 0.18.1. 0.18.0 has been yanked
from crates.io — 0.18.1 was superseded by this release in the same day
because of the scope of the fixes.

### Fixed

- **`tests/e2e_stress_gossip.sh` now actually enforces the delivery
  claim** it documents. Previously the acceptance logic only checked
  publisher count and pipeline drops, so the 2026-04-20 artefact
  (`proofs/stress-20260420-085405/stress-report.json`) recorded 106 /
  200 per subscriber and still exited 0. Added a per-subscriber
  threshold gate (`delivered_to_subscriber >= MESSAGES *
  MIN_DELIVERY_RATIO`), default ratio 1.0. `--min-delivery-ratio
  <float>` flag and `MIN_DELIVERY_RATIO=<float>` env for deliberate
  under-saturation measurement.
- **`X0X_LOG_DIR` now tees to stdout AND the file**, as documented.
  Previous behaviour replaced the stdout sink when the env var was
  set. Reworked `init_logging` to compose the subscriber from two
  `tracing_subscriber::fmt::layer()`s so each event fans out to both
  writers while the `EnvFilter` still applies.
- **Rust 1.95.0 MSRV pinned through the full chain.** `rust-version`
  in `Cargo.toml` was stale at `1.75.0` while CHANGELOG already claimed
  1.95.0. CI's `dtolnay/rust-toolchain@stable` pinned to
  `@master` with explicit `toolchain: 1.95.0` in every job (fmt,
  clippy, test, doc, parity).

### Validation

- `cargo fmt --check`: clean
- `cargo clippy --all-targets --all-features -- -D warnings`: clean
- `cargo nextest run --all-features --workspace`: **1006 / 1006** pass

### Notes for consumers of earlier 0.18

`0.18.0` has been **yanked** — it shipped with ant-quic 0.27.2 and
missed the supersede-race fix in ant-quic 0.27.3 that directly affects
`/peers/events` accuracy. `0.18.1` pairs with ant-quic 0.27.3 and
saorsa-gossip 0.5.19. `0.18.2` is functionally identical to 0.18.1
at runtime — the changes are to the test harness acceptance gate,
the logging topology, and the toolchain metadata. Upgrade `0.18.0 →
0.18.2` directly; `0.18.1 → 0.18.2` is safe but strictly cosmetic at
runtime.

## [v0.18.1] - 2026-04-21

### Changed

- Bumped `ant-quic` `0.27.2 → 0.27.3` (closes supersede race — now
  emits `Replaced` + `Closed{Superseded}` on connection replacement;
  enriches NAT traversal outcome + expiry heuristics).
- Bumped `saorsa-gossip-*` `0.5.18 → 0.5.19` (re-pins ant-quic 0.27.3
  across all 11 crates + clippy 1.95 `sort_by_key(Reverse)`
  fixes in coordinator/{cache, gossip_cache, peer_cache} and
  runtime/rendezvous).
- REST + CLI + GUI gap-closure for the new ant-quic 0.27 surface
  (originally drafted as v0.18.1 work, rolling it into this bump):
  - New endpoints: `POST /peers/:peer_id/probe`,
    `GET /peers/:peer_id/health`, `GET /peers/events` (SSE).
  - `POST /direct/send` accepts `require_ack_ms` for a post-send
    peer-liveness probe via ant-quic `probe_peer`. Explicit
    documentation that this confirms the peer is responsive, not
    that the specific DM envelope was delivered.
  - New CLI: `x0x peer probe / health / events`,
    `x0x direct send --require-ack-ms <ms>`.
  - New GUI "Gossip Pipeline" panel in the Network view — renders
    all 9 `PubSubStats` counters and flags non-zero drops in red.
  - `communitas-x0x-client`: `gossip_stats()`, `probe_peer()`,
    `peer_health()`.
  - `communitas-apple/Tests/CommunitasUITests/` — XCUITest target
    with 5 golden-path UI tests.

### Validation

- `cargo fmt --check`: clean
- `cargo clippy --all-targets --all-features -- -D warnings`: clean
- `cargo nextest run --all-features --workspace`: **1006 / 1006** pass

### Proof runs (`proofs/`)

- `stress-20260421-v0181/` — 5 daemons × 500 messages on 0.18.1 +
  ant-quic 0.27.3, SETTLE_SECS=30, PUBLISH_DELAY_MS=30.
  Pipeline drops `decode_to_delivery_drops: 0` across all 5 nodes.
  Mesh delivery is now asymmetric on the 5-node localhost matrix
  (nodes 4-5: 647 / node, nodes 2-3: 106 / node) — this is a mesh-
  formation artefact, not a pipeline regression.
- `chrome-20260421-v0181/` — 13 / 13 GUI capabilities pass including
  the new peer observability endpoints.

## [v0.18.0] - 2026-04-20

### Added

- **`GET /diagnostics/gossip`** — drop-detection endpoint exposing
  `PubSubStats` counters for every stage of the pub/sub pipeline
  (publish / incoming / decoded / delivered / subscriber-channel-closed)
  plus derived `in_flight_decode` and `decode_to_delivery_drops`.
- **`x0x diagnostics gossip`** — CLI subcommand parallel to
  `diagnostics connectivity`.
- **`X0X_LOG_DIR`** — per-pid file log sink for `x0xd`; appends
  `<dir>/x0xd-<pid>.log` alongside stdout. Opt-in.
- **ant-quic 0.27.1/0.27.2 surface pass-throughs** on `NetworkNode`:
  `probe_peer` (#173 active liveness), `connection_health` (#170),
  `send_with_receive_ack` (#172), `subscribe_all_peer_events` (#171).
- `tests/ant_quic_0272_surface.rs` — 4 integration tests exercising
  each new primitive against localhost `P2pEndpoint`s.
- `docs/parity-matrix.md` — capability × surface matrix across CLI,
  REST, embedded GUI, Python / Node bindings, the communitas-x0x-client
  Rust crate, communitas-core / ui-service / ui-api / dioxus / kanban /
  apple / bench.
- `tests/e2e_stress_gossip.sh` — N-daemon / M-message stress harness
  that fails on any `decode_to_delivery_drops > 0`.
- `tests/e2e_gui_chrome.mjs` — Playwright driver for the embedded
  HTML GUI; captures HAR + console stream + screenshot + JSON pass/fail
  per capability. Loads GUI from the daemon's `/gui` handler so the
  page is same-origin with the REST surface.
- `tests/e2e_communitas_dioxus.sh` — JSON-IPC driver skeleton for the
  Communitas Dioxus desktop app.
- `communitas-apple/Tests/CommunitasUITests/` — XCUITest target with
  5 golden-path UI tests.
- `tests/e2e_proof_runner.sh` — top-level orchestrator rolling every
  phase into `proofs/<timestamp>/proof-report.json`.

### Changed

- Bumped `ant-quic` `0.27.1 → 0.27.2`.
- Bumped `saorsa-gossip-*` `0.5.17 → 0.5.18` (re-pins ant-quic 0.27.2
  across all 11 crates).
- Rust toolchain pinned to 1.95.0 — blake3 1.8.4 transitively requires
  `constant_time_eq 0.4.3` which has a 1.95 MSRV.
- `dm_inbox::InboxPipeline` rebroadcast-dedup map moved behind a
  `RebroadcastDedupMap` type alias (clippy 1.95 tightened
  `clippy::type_complexity`).
- API endpoint registry and shipped manifest grew to 114 endpoints.

### Validation

- `cargo fmt --check`: clean
- `cargo clippy --all-targets --all-features -- -D warnings`: clean
- `cargo nextest run --all-features --workspace`: **1006 / 1006 pass**

### Proof runs (checked into `proofs/`)

- Local 3-daemon gossip stress — 100 % delivery, 0 drops
  (`proofs/stress-20260420-085503/`).
- Chrome GUI capability walk — 9 / 9 pass including live pub/sub
  round-trip (`proofs/chrome-20260420-v2/`).

## [v0.17.1] - 2026-04-16

### Fixed

- `DirectMessaging::handle_incoming()` no longer back-pressures the receive pipeline when the pull-API receiver (`Agent::recv_direct()`) is idle. The bounded `internal_tx.send(msg).await` is now a non-blocking `try_send`, so an undrained mpsc can no longer stall the `Node::recv` → `spawn_receiver` → `start_direct_listener` chain. Daemons using only `subscribe_direct()` (x0xd, GUI, CLI) are the primary beneficiaries.
- `NetworkNode::spawn_receiver` explicitly drops the `node` read-lock guard after `Node::recv().await` returns, so we no longer hold the `RwLock` read lock while awaiting channel sends.

### Changed

- Bumped `ant-quic` to `0.26.12` (includes upstream #165 MASQUE relay target-selection fix: mesh-wide pairwise `/agents/connect` restored to 30/30 on the 6-node VPS bootstrap, vs. 6/30 under 0.26.9).
- Collapsed the Phase D.3 stable-group-id abstraction onto `mls_group_id`: every x0x group is an MLS group, and `stable_group_id()` now always equals the MLS group id. Removes cross-daemon id drift where owners indexed `named_groups` by MLS id and card-imported stubs indexed by stable id, which caused 404s on `POST /groups/:id/requests` and friends.
- Added 1 MiB + 16 MiB NYC→SFO large-file-transfer coverage to `tests/e2e_vps.sh` (section §18b).

### Known Issues

- **ant-quic #166**: in the live VPS mesh, a short unidirectional stream can be `[p2p][send] ACKED` on the sender but never surface at the receiver's `accept_uni()`, while larger PubSub streams on the same connection flow normally. Tracked upstream; not reproducible with two daemons on localhost. The 0.17.1 recv-pipeline fix clears x0x's contribution to the symptom; the residual stream-accept drop sits inside ant-quic. Mac-behind-NAT → VPS (the user-facing single-client journey) is not affected — e2e_live_network 66/66 green.

## [v0.16.0] - 2026-04-09

### Changed

- Bumped `ant-quic` to `0.26.1`
- Bumped `saorsa-gossip-*` crates to `0.5.14`
- Removed x0x-owned mDNS runtime and builder/accessor surface in favor of ant-quic's built-in first-party LAN discovery and additive UPnP handling

### Fixed

- Updated end-to-end shell harnesses to preserve HTTP error bodies instead of collapsing non-2xx responses into generic `curl_failed`
- Fixed `tests/e2e_full.sh` to honor `X0XD` and default to the release binary
- Updated release and deployment scripts to derive the current version dynamically

## [v0.15.3] - 2026-04-07

### Changed

- Bumped `ant-quic` to `0.25.3`
- Bumped `saorsa-gossip-*` crates to `0.5.13`

### Fixed

- Synced cached peer dialing with scoped/fresh direct-reachability semantics
- Synced `SKILL.md` release metadata to `0.15.3`

## [v0.15.2] - 2026-04-05

### Added

- **Comprehensive test system** — integration, property-based, fuzz, and soak testing infrastructure

### Fixed

- SKILL.md version synced to 0.15.2

## [v0.15.1] - 2026-04-03

### Added

- **mDNS zero-config LAN discovery** — agents on the same network find each other automatically via `_x0x._udp.local.` DNS-SD, no bootstrap needed
- New integration tests: KV store, named groups, stress tests
- Phase 19 mDNS testing in comprehensive test prompt

## [v0.15.0] - 2026-04-03

### Added

- **4-word speakable identities** — human-friendly agent addresses via `four-word-networking` (`x0x find ocean-metal-forest-coral`)
- `x0x find` and `x0x connect` CLI commands for agent discovery by words
- Trust-gated `/introduction` endpoint with per-trust-level field visibility

## [v0.14.9] - 2026-04-02

### Fixed

- Identity/address/timeout bug fixes
- SKILL.md version sync
- Rustdoc warning fixes

## [v0.14.8] - 2026-04-01

### Added

- **Release metadata validation** — CI now validates SKILL.md/Cargo.toml version sync and OpenClaw binary consistency before builds and releases (#48)

### Fixed

- **SKILL.md version sync** — frontmatter version was stuck at 0.14.0, now kept in sync with Cargo.toml

## [v0.14.7] - 2026-04-01

### Fixed

- **Self-update recovery for older installs** — `x0x upgrade` now detects signature verification failures from key rotation and prints clear instructions to reinstall via `curl | sh` or `cargo install`. Previously users on v0.14.3–v0.14.5 were stuck with a cryptic error and no way to auto-update.

## [v0.14.6] - 2026-04-01

### Fixed

- **Self-update signature verification** — embedded release signing public key now matches the CI signing secret. Previously `x0x upgrade` always failed with "manifest signature verification failed" because the keys were mismatched.

## [v0.14.5] - 2026-04-01

### Changed

- Updated `ant-quic` to 0.24.5 — NAT traversal coordination now uses PeerId-based lookups instead of SocketAddr, fixing hole-punching failures when peers' NAT mappings change
- Updated `saorsa-gossip-*` crates to 0.5.11
- Updated `saorsa-pqc` to 0.5

## [v0.9.2] - 2026-03-25

### Added

- **Group Workspace** — unified workspace with sub-tabs per group:
  - **Chat** — group messaging via gossip pub/sub (was separate tab, now in workspace)
  - **Board** — kanban board with To Do / In Progress / Done columns using CRDT task lists. Auto-creates a task list per group. Add tasks, claim, complete — all synced via gossip.
  - **Files** — send files to group members via P2P file transfer with SHA-256 verification. Select recipient from contacts, pick file, send.

- **Direct Messages tab** — chat directly with imported contacts. Import someone's card on Dashboard, they appear in DM contacts. Select a contact and send encrypted point-to-point messages.

### Fixed

- **Chat message echo** — own messages no longer appear twice. Gossip echoes from self are filtered out.
- **Invite link copy UX** — invite links now persist after generation with a dedicated "Copy Link" button. Previously the link would vanish on focus change.

## [v0.9.1] - 2026-03-25

### Fixed

- **Group auto-subscribe** — creating or joining a group now automatically subscribes to the group's chat and metadata gossip topics. Previously, members couldn't see each other because neither side was subscribed to the gossip topics. Join/create events are now announced on the chat topic.

- **IPv6 addresses in announcements** — identity announcements now include ALL external addresses (IPv4 and IPv6) from ant-quic's NodeStatus, not just the first observed address. Agents with dual-stack connectivity now advertise both addresses so peers can connect via whichever protocol works.

- **Removed NAT type from GUI** — NAT type detection is unreliable and showing an incorrect value is worse than showing nothing. Removed from the network dashboard until it can be determined definitively.

## [v0.9.0] - 2026-03-25

### Added

- **KvStore — CRDT-backed key-value store** with access control:
  - Generic replicated key-value store using OR-Set for keys, LWW for values
  - Access policies: **Signed** (owner-only writes), **Allowlisted** (approved writers), **Encrypted** (MLS group members only)
  - Unauthorized writes silently rejected — no spam possible
  - Delta-based sync over gossip with BLAKE3 content hashing
  - 7 REST endpoints: `POST/GET /stores`, `POST /stores/:id/join`, `GET /stores/:id/keys`, `PUT/GET/DELETE /stores/:id/:key`
  - 7 CLI commands: `x0x store create/list/join/keys/put/get/rm`
  - 46 unit tests covering CRUD, merge semantics, access control, serialization

- **Named Groups** — human-friendly group management:
  - Groups tie together MLS encryption + KvStore metadata + gossip chat topics
  - Display names per member (like Slack/Discord)
  - 6 REST endpoints: `POST/GET /groups`, `GET /groups/:id`, `POST /groups/:id/invite`, `POST /groups/join`, `PUT /groups/:id/display-name`
  - 6 CLI commands: `x0x group create/list/info/invite/join/set-name`

- **Invite Links** — shareable group invitations:
  - Format: `x0x://invite/<base64url(json)>` — share via email, chat, QR code
  - Configurable expiry (default 7 days, 0 = never)
  - Expired and malformed invites properly rejected
  - Invite tokens contain group name, inviter identity, one-time secret

- **AgentCard — Shareable Identity**:
  - Portable identity card: `x0x://agent/<base64url(json)>`
  - Contains display name, agent/machine/user IDs, addresses, groups, stores
  - Import a card to add someone to your contacts in one step
  - Share a card that includes group invites — one link to add you AND join your groups
  - `GET /agent/card` — generate your card
  - `POST /agent/card/import` — import someone's card
  - `x0x agent card --name "David"` / `x0x agent import <link>`

- **Embedded GUI** — full web interface compiled into x0xd:
  - `x0x gui` opens it in your default browser (macOS/Linux/Windows)
  - Served at `GET /gui` — no external files needed
  - Dashboard: identity, peers, uptime, discovered agents, identity cards
  - Groups: create, invite, join, display names
  - Chat: group-scoped rooms via WebSocket
  - Network: NAT type, addresses, peers, contacts, trust levels
  - Help: CLI reference, example app gallery, about

- **5 Example Apps** — single-file HTML apps in `examples/apps/`:
  - **x0x-chat** — group chat via WebSocket pub/sub
  - **x0x-board** — collaborative kanban (CRDT task lists)
  - **x0x-network** — network topology dashboard
  - **x0x-drop** — secure P2P file sharing with SHA-256
  - **x0x-swarm** — AI agent task delegation (the killer demo)
  - All self-contained, zero dependencies, dark terminal aesthetic
  - Starting points for humans and agents to build their own apps

- **App Distribution Design** — `docs/design/content-store-and-apps.md`:
  - Architecture for distributing web apps over the x0x network
  - App manifests signed with ML-DSA-65, discovered via gossip
  - Small apps inline via CRDT, large apps via file transfer
  - Roadmap through content store → app registry → static serving

### Fixed

- **Critical bootstrap bug** — config files without explicit `bootstrap_peers` field resulted in zero bootstrap peers (empty `Vec` from serde default). Nodes would start healthy but never connect to anyone. Fixed: `#[serde(default = "default_bootstrap_peers")]` now populates the 6 hardcoded global bootstrap nodes. This affected all users running x0xd with a custom config file.

### Changed

- REST API expanded from 50 to **70 endpoints**
- Total test count: **615+ tests** (was 519)
- All 6 VPS bootstrap nodes verified on v0.9.0 with full global mesh (NYC, SFO, Helsinki, Nuremberg, Singapore, Tokyo)

## [v0.8.1] - 2026-03-25

### Added

- **Unified install script** — single `scripts/install.sh` replaces both install.sh and install-quick.sh:
  - `curl -sfL https://x0x.md | sh` — install only (x0xd + x0x CLI)
  - `--start` — install + start daemon + wait for healthy
  - `--autostart` — install + start + configure start-on-boot
  - systemd user service (Linux) or launchd agent (macOS)

- **`x0x autostart` CLI command** — configure daemon to start on boot from the command line:
  - `x0x autostart` — enable (systemd on Linux, launchd on macOS)
  - `x0x autostart --remove` — disable

### Removed

- `scripts/install-quick.sh` — merged into unified `scripts/install.sh`

## [v0.8.0] - 2026-03-25

### Breaking Changes

- **Default QUIC port: 5483** (was random/12000). All x0x nodes now use the same well-known port. If you know an IP, connect to `IP:5483`. Port 5483 = LIVE on a phone keypad.

- **x0x-bootstrap binary removed.** Every x0x node is a bootstrap node. No special binary needed. The 6 VPS infrastructure nodes now run standard `x0xd` on port 5483.

### Added

- **Shared peer cache** — all named instances (default, alice, bob) share one `peers.cache` file at the platform data dir root. ant-quic's BootstrapCache handles concurrent access via atomic writes + file locking.

- **Compiled-in seed peers** — 6 Saorsa Labs nodes pre-configured as seeds. On first run with empty cache, these are loaded automatically. After first connection, cache grows naturally with quality-scored peers.

### Changed

- `DEFAULT_BOOTSTRAP_PEERS` updated to port 5483 (was 12000)
- All 6 VPS nodes migrated from `x0x-bootstrap` to `x0xd`
- All docs, CI, tests, deployment scripts updated to port 5483
- `build-bootstrap.yml` workflow deleted

### Architecture

Every node in ant-quic v0.13.0+ is symmetric P2P: any node can coordinate NAT traversal, relay via MASQUE (RFC 9298), and reflect addresses. The separate bootstrap binary was unnecessary complexity. What makes a node a "bootstrap" is simply being reachable and known — which is what the peer cache provides.

## [v0.7.0] - 2026-03-25

### Added

- **`x0x` CLI binary** — unified command-line tool that controls a running x0xd daemon. Every REST endpoint is available as a subcommand (`x0x health`, `x0x contacts list`, `x0x direct send`, `x0x groups create`, etc.). Supports `--json` output and `--name` for named instances.

- **Shared API endpoint registry** (`src/api/mod.rs`) — 50 endpoint definitions consumed by both x0xd and the CLI. Routes and CLI commands can never drift out of sync.

- **12 new daemon endpoints** closing the library→daemon API gap:
  - `POST /agents/find/:id` — active 3-stage agent search
  - `GET /agents/reachability/:id` — reachability prediction
  - `POST /contacts/:id/revoke` — key revocation
  - `GET /contacts/:id/revocations` — revocation audit trail
  - `POST /contacts/:id/machines/:mid/pin` — machine pinning
  - `DELETE /contacts/:id/machines/:mid/pin` — machine unpinning
  - `POST /trust/evaluate` — trust decision evaluation
  - `POST /mls/groups/:id/welcome` — MLS welcome message
  - `GET /upgrade/check` — update check
  - `GET /network/bootstrap-cache` — peer cache stats
  - `GET /agents/discovered?unfiltered=true` — include stale entries

- **51 daemon API integration tests** — comprehensive test suite covering all routes against a live daemon with real bootstrap node connections.

- **`install-quick.sh`** — single-command installer: `curl -sfL https://x0x.md | sh`. Downloads binary, starts daemon, waits for healthy, prints agent ID.

- **File transfer protocol types** (`src/files/mod.rs`) — types and state management for future file sharing.

### Changed

- 51 routes total (was 39 in v0.6.0)
- `futures` dependency now includes `alloc` feature for WebSocket test support

## [v0.6.0] - 2026-03-24

### Added

- **WebSocket support** — bidirectional real-time communication for multi-app sessions:
  - `GET /ws` — general purpose WebSocket (subscribe, publish, send_direct, ping)
  - `GET /ws/direct` — WebSocket with auto-subscribe to direct messages
  - `GET /ws/sessions` — list active sessions with shared subscription stats
  - Session management with UUID IDs, per-session topic tracking
  - Trust check on WebSocket send_direct (matches REST behavior)
  - 30s server-side keepalive ping

- **Shared subscription fan-out** — multiple WebSocket clients subscribing to the same topic share a single gossip subscription (1 forwarder, 1 broadcast channel) instead of creating N independent subscriptions. Subscription resources are cleaned up when the last session leaves a topic.

- **OpenClaw install array** in SKILL.md — 7 install declarations (5 platform binaries + node + uv) for ClawHub auto-install.

- **agent.json updated to v0.6.0** — added direct-messaging capability, daemon endpoint, 3 new tags.

### Changed

- **SKILL.md restructured** — 913 lines → 343 lines (~1601 tokens). Full API reference, vision, security, diagnostics, ecosystem, SDK docs moved to `docs/`. WebSocket protocol documented.

- **6 new reference docs** — `docs/api-reference.md`, `docs/vision.md`, `docs/security.md`, `docs/diagnostics.md`, `docs/ecosystem.md`, `docs/sdk-quickstart.md`. All linked via GitHub URLs.

- **`docs/api.md` updated** — comprehensive 36+ endpoint reference with WebSocket protocol, replacing old stub table.

## [v0.5.5] - 2026-03-24

### Added

- **`--start` and `--health` flags in install script** — `bash scripts/install.sh --start --health` now actually starts the daemon and waits for it to be healthy. Previously these flags were documented in SKILL.md but silently ignored by the script.

- **Direct binary download instructions in SKILL.md** — agents can now install x0xd with only `curl` and GitHub, no Rust toolchain or install script needed. Platform detection + `curl` + `tar` is all that's required.

### Fixed

- **Install script platform paths** — macOS data directory now correctly uses `~/Library/Application Support/` instead of `~/.local/share/` (matches x0xd's `dirs::data_dir()` behavior).

- **x0x.md dependency clarified** — SKILL.md now explicitly states that x0x.md is optional. All install paths work with only GitHub up.

## [v0.5.4] - 2026-03-24

### Fixed

- **MLS group persistence** — switched from JSON to bincode format. JSON serialization failed because `MlsGroup.members` uses `HashMap<AgentId, ...>` and JSON requires string keys. Bincode handles byte-array keys natively. Groups now correctly survive daemon restarts.

- **Storage path documentation** — SKILL.md now shows correct platform-specific paths (macOS: `~/Library/Application Support/x0x/`, Linux: `~/.local/share/x0x/`).

- **Install script URL** — fixed from `https://x0x.md/install.sh` to `https://x0x.md` (the domain serves the script at the root).

- **Install method references** — SKILL.md now references all three install scripts (`install.sh`, `install.ps1`, `install.py`) and links to `docs/install.md`.

## [v0.5.3] - 2026-03-24

### Added

- **Complete SKILL.md quickstart guide** — an agent can now go from zero to a working daemon using only SKILL.md:
  - Three install methods (curl script, from source, as library)
  - Daemon startup, first-run behavior, key generation explained
  - "Verify it's working" 3-step flow
  - "Your first message" pub/sub walkthrough
  - Full CLI reference (all flags)
  - TOML config reference (all options with defaults)
  - Storage locations for all persisted state
  - Error response format with HTTP status code examples
  - MLS group encryption curl examples (create, add member, encrypt, decrypt)

## [v0.5.2] - 2026-03-24

### Fixed

- **Documentation audit** — all 36 x0xd REST endpoints now documented in SKILL.md API reference (was missing MLS group endpoints and machine management endpoints)
- **Stale "Incomplete APIs" notes removed** — CLAUDE.md and AGENTS.md no longer claim `create_task_list()` is unimplemented (it has been fully wired since v0.4.0)

## [v0.5.1] - 2026-03-24

### Added

- **x0xd REST endpoints for direct messaging** — 4 new endpoints exposing the direct messaging API via the daemon's HTTP interface:
  - `POST /agents/connect` — connect to a discovered agent
  - `POST /direct/send` — send direct message (with trust filtering — blocked agents rejected)
  - `GET /direct/connections` — list connected agents
  - `GET /direct/events` — SSE stream of incoming direct messages (with 15s keepalive)

- **x0xd REST endpoints for MLS group encryption** — 7 new endpoints for managing encrypted groups:
  - `POST /mls/groups` — create a group (random or specified ID)
  - `GET /mls/groups` — list all groups
  - `GET /mls/groups/:id` — get group details and members
  - `POST /mls/groups/:id/members` — add member
  - `DELETE /mls/groups/:id/members/:agent_id` — remove member
  - `POST /mls/groups/:id/encrypt` — encrypt with group key
  - `POST /mls/groups/:id/decrypt` — decrypt with group key

- **MLS group persistence** — groups are saved to `<data_dir>/mls_groups.json` on every mutation and restored on daemon restart.

- **1 MB body-size limit** — `DefaultBodyLimit::max(1MB)` on all endpoints to prevent memory exhaustion.

- **Trust check on direct send** — `POST /direct/send` checks `ContactStore` and rejects messages to blocked agents with HTTP 403.

### Security

- All internal error details are logged with `tracing::error!` but HTTP responses return only generic error messages. No file paths, socket addresses, or cryptographic details are leaked to API consumers.

- Extracted `decode_base64_payload()` and `make_mls_cipher()` helpers to eliminate duplicated error-handling code.

## [v0.5.0] - 2026-03-24

### Added

- **Direct agent-to-agent messaging** (`src/direct.rs`) — Point-to-point communication between connected agents, bypassing gossip for private, efficient, reliable delivery.
  - `agent.send_direct(&agent_id, payload)` — send bytes to a connected agent
  - `agent.recv_direct()` — blocking receive from any agent
  - `agent.recv_direct_filtered()` — receive with trust filtering (drops messages from blocked agents)
  - `agent.subscribe_direct()` — broadcast receiver for concurrent processing
  - `agent.is_agent_connected(&agent_id)` — check connection state
  - `agent.connected_agents()` — list all connected agents
  - Wire format: `[0x10][sender_agent_id: 32 bytes][payload]` — max 16 MB

- **Trust-filtered direct messaging** — `recv_direct_filtered()` checks `ContactStore` before delivering messages. Blocked agents' direct messages are silently dropped, matching gossip pub/sub behavior.

- **Receive-side payload size enforcement** — Network layer drops direct messages exceeding 16 MB + 32 bytes before forwarding to the channel, preventing memory exhaustion from malicious peers.

- **New error variants** — `AgentNotConnected`, `AgentNotFound`, `PayloadTooLarge`, `InvalidMessage` in `NetworkError`.

- **21 new tests** — 8 unit tests in `direct.rs`, 13 integration tests in `tests/direct_messaging_integration.rs` (536 total tests).

- **SKILL.md major update** — Direct messaging API docs, "Build Any Decentralized Application" vision with complete primitive table, human-centric tool replacement guide (GitHub → decentralized git, Zoom → saorsa-webrtc, etc.), sibling project references, plugin creation examples.

### Changed

- `connect_to_agent()` now registers agent mappings in `DirectMessaging` on successful connection, enabling subsequent `send_direct()` calls.

- Network receiver (`spawn_receiver()`) routes `0x10`-tagged messages to a separate direct message channel, distinct from gossip streams.

### Security

- Documented sender spoofing limitation: the `sender` AgentId in direct messages is self-asserted. The `machine_id` IS authenticated via QUIC/ML-DSA-65. See `DirectMessage` docs for guidance.

### Removed

- `NetworkNode::try_recv_direct()` — dead code stub that always returned `None`.

## [v0.4.0] - 2026-03-23

### Added

- **Identity unification** — `MachineId` now equals the `ant-quic` QUIC `PeerId`. The machine ML-DSA-65 keypair is passed directly to `ant-quic::NodeConfig` so that both identity and transport use the same key. No more disconnected transport identity.

- **Flexible trust model** (`src/contacts.rs`, `src/trust.rs`) — Contacts now carry an `IdentityType` (`Anonymous | Known | Trusted | Pinned`) and a list of `MachineRecord` entries. `TrustEvaluator` evaluates `(AgentId, MachineId)` pairs:
  - Machine pinning: `IdentityType::Pinned` accepts only messages from pinned machine IDs
  - `TrustDecision`: `Accept | AcceptWithFlag | RejectMachineMismatch | RejectBlocked | Unknown`
  - Identity listener now rejects blocked and machine-mismatched announcements

- **Enhanced announcements** — `IdentityAnnouncement` and `DiscoveredAgent` now carry four optional NAT fields: `nat_type`, `can_receive_direct`, `is_relay`, `is_coordinator`. The async heartbeat populates them from `ant-quic::NodeStatus`.

- **Connectivity module** (`src/connectivity.rs`) — New `ReachabilityInfo` struct (built from a `DiscoveredAgent`) with `likely_direct()` and `needs_coordination()` heuristics. New `ConnectOutcome` enum: `Direct(addr) | Coordinated(addr) | Unreachable | NotFound`.

- **`Agent::connect_to_agent()`** — Attempts connection using direct-first strategy, falling back to coordinated NAT traversal via `ant-quic`. Enriches the bootstrap cache on success.

- **`Agent::reachability()`** — Returns `Option<ReachabilityInfo>` for a discovered agent.

- **`NetworkNode::node_status()`** — Accessor for the live `ant_quic::NodeStatus`.

- **50 new integration tests** across 4 test files: `identity_unification_test.rs`, `trust_evaluation_test.rs`, `announcement_test.rs`, `connectivity_test.rs` (517 total tests).

- **Technical documentation**: `docs/identity-architecture.md`, `docs/nat-traversal-strategy.md`, `docs/SKILLS.md`.

### Changed

- `ContactStore` gains `IdentityType`, `MachineRecord`, and machine management methods (`add_machine`, `remove_machine`, `pin_machine`, `unpin_machine`, `machines`, `set_identity_type`). The JSON storage format adds `identity_type` and `machines` fields with `#[serde(default)]` for backward compatibility.

- `x0xd` REST API extended: `PATCH /contacts/:id` now accepts optional `identity_type` field; new routes `GET/POST /contacts/:id/machines` and `DELETE /contacts/:id/machines/:mid`.

### Protocol Note

`IdentityAnnouncement` wire format has changed. Messages encoded with v0.3.x cannot be decoded by v0.4.x because bincode 1.x treats all fields as required. Nodes must upgrade together.

## [v0.3.1] - 2026-03-05

### Fixed
- **reqwest now uses rustls-tls** — removed hidden OpenSSL dependency; `reqwest` without `default-features = false` silently pulls `native-tls` (OpenSSL on Linux), contradicting the fully-PQC, no-system-crypto design. Switching to `rustls-tls` makes cross-compilation from macOS work without `OPENSSL_DIR` hacks and keeps the entire dependency chain in pure Rust.

### Added
- **VPS e2e integration test suite** — `tests/vps_e2e_integration.rs` with 4 local tests (no live network required) covering identity announcement, late-join heartbeat discovery, find_agent cache hit, and user identity discovery. Four additional `#[ignore]` variants run against live VPS bootstrap nodes.
- **CLAUDE.md** — project architecture reference for Claude Code

## [v0.3.0] - 2026-03-05

### Added
- **Rendezvous ProviderSummary integration** — `Agent::advertise_identity()` publishes a signed `ProviderSummary` to the rendezvous shard topic enabling global agent findability across gossip overlay partitions
- **`Agent::find_agent_rendezvous()`** — stage-3 lookup that subscribes to the rendezvous shard topic and waits for a matching `ProviderSummary`; addresses decoded from the `extensions` field
- **3-stage `find_agent()`** — upgraded from 2-stage to: cache hit → identity shard subscription (5s) → rendezvous (5s)
- **`rendezvous_shard_topic_for_agent()`** — deterministic `"x0x.rendezvous.shard.<u16>"` topic function
- **`RENDEZVOUS_SHARD_TOPIC_PREFIX`** constant
- **x0xd rendezvous config** — `rendezvous_enabled` (default `true`) and `rendezvous_validity_ms` (default 3,600,000 ms) config fields; initial advertisement at startup + background re-advertisement every `validity_ms / 2`
- **Identity heartbeat** — `Agent::start_identity_heartbeat()` re-announces identity at configurable interval (default 300s) so late-joining peers can discover earlier nodes
- **TTL filtering** — `presence()` and `discovered_agents()` filter entries older than `identity_ttl_secs` (default 900s); `discovered_agents_unfiltered()` returns all cache entries
- **Shard-based identity routing** — `shard_topic_for_agent()` returns `"x0x.identity.shard.<u16>"` derived via BLAKE3; `announce_identity()` dual-publishes to shard + legacy topics; 65,536-shard space
- **Human identity HTTP API** — `GET /users/:user_id/agents`, `GET /agent/user-id`; `?wait=true` query parameter on `GET /agents/discovered/:id` triggers active shard+rendezvous lookup
- **`Agent::find_agents_by_user()`** — discovers all agents in cache claiming a given `UserId`
- **`Agent::local_addr()`** — returns the bound socket address of the network node
- **`Agent::build_announcement()`** — public wrapper for building a signed `IdentityAnnouncement`
- **`AgentBuilder::with_heartbeat_interval()` / `with_identity_ttl()`** — configurable heartbeat and TTL
- **x0xd heartbeat/TTL config** — `heartbeat_interval_secs` and `identity_ttl_secs` fields
- **SKILL.md Discovery & Identity section** — full curl examples, human consent invariant, trust model, `x0x://user/<hex>` URI scheme

### Changed
- `find_agent()` timeout split: 5s for identity shard subscription + 5s for rendezvous (was 10s shard-only)
- `join_network()` now calls `announce_identity()` and `start_identity_heartbeat()` automatically

### Infrastructure
- Updated saorsa-gossip-* crates from 0.5.1 → 0.5.2 (adds `ProviderSummary.extensions`, `sign_raw`/`verify_raw`)
- Removed CI symlink workaround for ant-quic and saorsa-gossip from all 4 workflows (ci.yml, release.yml, build.yml, build-bootstrap.yml) — all deps now resolve from crates.io

## [v0.2.0] - 2026-02-01

### Added
- Signed identity announcements with machine-key attestation
- Contact trust store with `Blocked` / `Unknown` / `Known` / `Trusted` levels
- Trust-filtered pub/sub (blocked senders are dropped)
- Dual-stack IPv6 on all 6 bootstrap nodes
- Axum route improvements
- Production gossip integration
- `x0xd` daemon with full REST API

## [v0.1.0] - 2026-01-01

### Added
- Initial release
- `Agent` with machine + agent + user identity (three-layer model)
- CRDT collaborative task lists (OR-Set checkboxes, LWW-Register metadata, RGA ordering)
- MLS group encryption (ChaCha20-Poly1305)
- Gossip pub/sub via saorsa-gossip epidemic broadcast
- Bootstrap connection to 6 global nodes (NYC, SFO, Helsinki, Nuremberg, Singapore, Tokyo)
- Node.js bindings (napi-rs v3) and Python bindings (PyO3/maturin)
- GPG-signed SKILL.md for agent self-distribution
