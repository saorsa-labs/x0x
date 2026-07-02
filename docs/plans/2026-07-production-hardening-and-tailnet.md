# Workplan: Production Hardening + Tailnet Phase 1 (2026-07)

Status: ACTIVE — execution plan for the team; every PR is reviewed by the session lead against this document.
Source: 2026-07-02 production-readiness review (three-agent audit: panic safety, security surface, resilience) + Tailscale gap analysis.
Tracking: GitHub issues #122–#133.

---

## Context & goals

**Review verdict.** x0x v0.27.0 is production-ready with no blockers: zero reachable production panics (all 1,378 unwrap/expect are test-only), a loopback-only bearer-token API with locked-down CORS, a fail-closed multi-gate exec ACL, 0600 key files with Debug redaction and zeroize-on-drop, a PQC-signed self-update path, and thorough graceful shutdown. The review produced 8 concrete hardening items (4 medium, 4 low) — Workstream 1.

**Tailnet direction.** The strategic goal is Tailscale-like UX: a user connects their own computers over any network. The gap analysis found ant-quic already carries the two hardest pieces (native QUIC NAT traversal; always-on symmetric MASQUE relay — every node relays, no DERP fleet), and the transport is post-quantum end-to-end, which WireGuard/Tailscale structurally are not. The gap is above the wire: x0x uses only message-level `Node::send`/`recv` while ant-quic's `high_level::Connection` stream API sits unused. The agreed path is **B then A**: Phase 1 (this plan, Workstream 2) ships app-level port-forwarding/SOCKS5 over per-peer streams — weeks of work, no TUN, every OS; Phase 2 (not this plan) builds the post-quantum TUN tailnet on the same plumbing.

**Non-negotiable quality gates (every PR).** `cargo fmt --all -- --check` clean; `cargo clippy --all-targets --all-features -- -D warnings` clean; `cargo nextest run --all-features --workspace` green; no `.unwrap()`/`.expect()`/`panic!`/`todo!`/`unimplemented!`/`unreachable!` in production code; public APIs documented (`RUSTDOCFLAGS="-D warnings"`); conventional commit messages; PR references its issue.

---

## Workstream 1 — Production hardening

### WS1.1 — Bound the per-WebSocket outbound queue (#122) — **medium, size M**

**Background.** `src/server/mod.rs:18316` holds the only unbounded channel in production code: the per-WS-session outbound queue (`mpsc::unbounded_channel::<WsOutbound>()`). Feeders: keepalive pinger (30s), direct-message forwarder (~:18358–18374, remote-driven), per-topic forwarders (~:18542+, remote-driven, each draining a bounded `broadcast::channel(256)`). Consumer: writer task (~:18344). A stalled local WS reader plus remote topic/DM flood grows daemon memory without bound.

**Design.**
- Replace with `mpsc::channel(1024)` (constant `WS_OUTBOUND_CAPACITY`, module-level, documented).
- Feeders switch from `send()` to `try_send()`:
  - Topic-frame and presence-frame feeders: on `Full`, drop the frame and increment a `ws_outbound_dropped` counter (topic data is re-obtainable via gossip; dropping is safe).
  - DM forwarder and keepalive: on `Full`, treat the session as a slow consumer — trigger session close with WS close code 1013 ("try again later") / reason "slow consumer". DMs must not be silently dropped: the DM stays in the daemon inbox (per-recipient inbox from PR #100 wip semantics — verify current inbox behavior; if DMs are fire-and-forget to WS only, closing the session is the correct fail-loud behavior).
- Writer task unchanged (drains bounded channel).
- Diagnostics: add `ws_outbound_dropped` and `ws_slow_consumer_closes` counters to the existing diagnostics surface (`/diagnostics` family — follow the `PubSubStats` atomic-counter pattern).

**Tasks.**
1. Introduce capacity constant + swap channel construction at :18316; fix compile errors at all feeder sites.
2. Implement per-feeder `try_send` policy as above; wire close-on-full for DM/keepalive path into the existing session-abort logic (`server/mod.rs:18432-18437` teardown).
3. Add counters + expose in diagnostics endpoint; document in `docs/diagnostics.md`.
4. Tests: (a) unit — feeder `try_send` policies (drop vs close) with a full channel; (b) integration — WS session with a deliberately stalled reader while a topic floods: assert session closes with 1013 within N seconds and process memory stays bounded (assert channel never exceeds capacity via counter, not RSS).

**Acceptance.** No `unbounded_channel` on the WS path; stalled-reader test passes; counters visible; gates green.
**Dependencies.** None. **Conflicts:** touches `server/mod.rs` — coordinate with WS1.4 (do this either before the decomposition or rebase onto it; do not run concurrently in the same region).

### WS1.2 — Timeout on bootstrap dial (#123) — **medium, size S**

**Background.** `src/bootstrap.rs:85` `node.connect_addr(addr).await` is the only dial not wrapped in `tokio::time::timeout`; all seven lib.rs call sites wrap it. A hung dial stalls the retry loop (backoff sleep only runs after a returned error).

**Design.** Wrap in `timeout(BOOTSTRAP_DIAL_TIMEOUT, …)` with `BOOTSTRAP_DIAL_TIMEOUT = 10s` (constant beside the existing retry constants); timeout maps to a retryable error so the existing capped backoff (max_retries=3, cap 5s) proceeds to the next attempt/peer unchanged.

**Tasks.** 1-line wrap + error mapping; unit test with a mock/blackhole dial asserting the attempt fails at the timeout and the loop advances.

**Acceptance.** Dial bounded; test proves failover; gates green. **Dependencies.** None.

### WS1.3 — Coverage ratchet (#124) — **medium, size M (ongoing)**

**Background.** `ci.yml` gates `cargo llvm-cov --fail-under-lines 48`. Too low for a security/crypto daemon; unit CI is the only always-on gate (202 `#[ignore]`d e2e tests run in separate workflows).

**Design.** Ratchet, don't jump: (1) measure actual coverage on main; (2) set floor to actual−1 immediately; (3) schedule +3–5 points per release toward 70%; (4) each ratchet PR adds targeted tests in priority order: exec ACL denial paths, auth middleware (401/exempt/query-token matrix), storage/identity error paths, shutdown ordering. Keep `docs/coverage-exclusions.md` as the justified-exclusion mechanism.

**Tasks.** Measure; bump floor; commit ratchet schedule into this plan + a comment in ci.yml; first tranche of tests (auth middleware matrix is the highest value/effort ratio).

**Acceptance.** Floor = actual−1; schedule written; first tranche merged; gates green. **Dependencies.** None; ongoing after.

**Ratchet schedule (committed 2026-07-02, #124 tranche 1).** Keep the gate ~1 point below *current actual*; raise it +3–5 points per release toward 70%. Baseline measured on `main` = **66.43%**; after the auth-matrix tranche = **66.46%** (WS-2 REST/API 64.63→64.66%). Floor raised **48 → 65** in both `.github/workflows/ci.yml` (`--fail-under-lines`) and `coverage-thresholds.toml` (`[global].line_floor`). Each future bump must add targeted tests (priority: exec ACL denial → auth middleware → storage/identity errors → shutdown ordering) or a documented `docs/coverage-exclusions.md` entry — never lower the floor. Tranche 1 (auth-middleware matrix: 401-without/wrong/correct-token, exempt `/health`+`/constitution*`, `?token=` on browser endpoints only, CORS loopback predicate) lives in `src/server/mod.rs::tests` as an in-process router suite.

**Tranche 2 (exec ACL denial paths, #141).** Coverage **66.46% → 66.61%** (WS-3 Exec 86.88→87.95%). Floor raised **65.0 → 65.6** (`floor((actual−1)×10)/10`). Added: `handle_request` gate-order matrix (unverified > trust > disabled > not-in-ACL priority, + the `trust_decision: None` and not-in-ACL gates); `check_request` shell-metacharacter table (`;`, `$()`, backticks, `|`, `&`, newline); `load_exec_policy` fail-closed matrix (missing-at-default→disabled, missing-at-explicit→hard error, malformed TOML→hard error, missing `[exec]`→disabled, `enabled=false`→disabled); `match_command` token semantics (Literal exact-match only; `LiteralWithUrlPathSuffix` rejecting `https://a` ≠ `https://a.evil`). Tests in `src/exec/acl.rs` + `src/exec/service.rs`.

**Tranche 3 (storage/identity error paths, #124).** Coverage **66.61% → 66.70%** (Identity/storage/presence/contacts 93.74→94.39%). Floor raised **65.6 → 65.7**. Added: `write_private_file` failure paths (unwritable destination surfaces as structured `Storage` error, no committed file left on failure); corrupt/truncated/garbage keyfile deserialization for all three keypair types → structured `Serialization` error (no panic); valid-bincode-but-wrong-size key material → structured `InvalidPublicKey`/`InvalidSecretKey` (no panic); agent + user keypair file round-trips (machine was already covered); `AgentCertificate` corrupted-signature and wrong-length-signature verification failures → structured `CertificateVerification` error. Tests in `src/storage.rs` + `src/identity.rs`. (Note: this tranche's commit avoids embedding the issue-closing verb for #124, which had auto-closed it twice.)

**Tranche 4 (shutdown ordering, #124 — final committed tranche).** Coverage **66.70% → 66.79%** (+115 lines). Floor **unchanged at 65.7** (`floor((actual−1)×10)/10` = 65.7; the gain does not cross a 0.1 boundary). Added: `begin_shutdown()` closes the registry + cancels the token (the synchronous prefix); `spawn_tracked` refuses after `begin_shutdown()` (pins the closed-flag no-op that defeats a racing `join_network` leak); idempotent double `shutdown()` (never panics, registry stays drained); the grace-before-abort ordering — a token-respecting tracked task completes gracefully (sets its completed flag) rather than being force-aborted. (An earlier draft also asserted the task observes the token as cancelled at first-poll, but that is a *race*, not an invariant — on a multi-thread runtime `tokio::spawn` may poll the task before `shutdown()` runs on the calling thread — so it was removed; verified 30/30 stable.) The WS/SSE close-on-shutdown notification path was NOT re-duplicated — it is already covered at integration tier by `daemon_api_shutdown_with_sse_client`, and re-duplicating it would touch `src/server/mod.rs` during Eng B's #125 window. Tests in `src/lib.rs::tests`.

**Tranche 4 (shutdown ordering, #124 — final committed tranche).** Coverage **66.70% → 66.79%**. Floor **unchanged at 65.7**. Four committed priority tranches complete; coverage **66.43% → 66.79%** across them (+0.36pt); floor **48 → 65.7** (~1pt below actual). Per schedule: the floor now moves **bump-per-release only** (+3–5 points per release toward 70%), each bump backed by targeted tests or a `docs/coverage-exclusions.md` entry — never lowered.

### WS1.4 — Decompose `src/server/mod.rs` (#125) — **medium, size L**

**Background.** 25,334 lines in one file: routes, handlers, WS/SSE, auth, state, tests. Biggest maintainability hotspot; precursor to the #110 `serve()` extraction (whose approved plan is P0 characterization tests → P1 move → P2 `serve()` — this task IS essentially P0+P1 and must stay aligned with that plan).

**Design — mechanical moves only, zero behavior change.**
- Target layout: `src/server/{auth.rs, ws.rs, sse.rs, state.rs, routes/{agent,groups,tasks,kv,presence,exec,upgrade,diagnostics,…}.rs}`, with `mod.rs` reduced to module wiring + router assembly.
- Route grouping mirrors the shared endpoint registry in `src/api/mod.rs` so registry ↔ module mapping is 1:1.
- Tests move with their code (colocated `#[cfg(test)]` blocks travel with the handlers they test).
- Characterization guard: snapshot `x0x routes` output (full endpoint table) before and after; must be byte-identical.

**Tasks.**
1. P0: snapshot endpoint registry output + record current public API surface (`cargo doc` inventory).
2. Extract `auth.rs` (middleware, token load/gen `2682-2719`, CORS predicates `2632-2650`) — smallest seam, proves the pattern.
3. Extract `state.rs` (AppState, ServerHandle, shutdown tail `2470-2530`).
4. Extract `ws.rs` + `sse.rs`.
5. Extract `routes/` groups, one PR per 2–3 groups to keep reviews scoped.
6. Final: `mod.rs` < ~2,000 lines; registry snapshot identical.

**Acceptance.** Diff is moves + `use` fixes only; `x0x routes` snapshot unchanged; full nextest green per extraction PR; no public-API change.
**Dependencies.** Serializes with WS1.1 and WS1.6 (same file). Recommended order: WS1.1 + WS1.6 first (small), then WS1.4 as a PR series.

### WS1.5 — Track crdt/kv sync tasks in shutdown (#126) — **low, size S**

**Background.** `src/crdt/sync.rs:136,162` and `src/kv/sync.rs:95,125` spawn long-lived subscription loops with dropped handles, outside both `spawn_tracked` (`lib.rs:3387`) and server `bg_tasks`; `Agent::shutdown()` doesn't abort them. Matters for embedded `serve()` (#110) restart-in-process scenarios.

**Design.** Route through `spawn_tracked` (Agent-owned; registry already refuses post-shutdown spawns) — requires threading the Agent's spawn facility into the sync constructors, OR store handles on `TaskListSync`/`KvStoreSync` and abort in a teardown called from the owning handle's drop/shutdown path. Prefer `spawn_tracked` for consistency; fall back to owned handles if the dependency direction is awkward (sync structs may not see the Agent).

**Tasks.** Pick mechanism after reading ownership (Rule 8); convert 4 spawn sites; test: create store+list, `agent.shutdown()`, assert loops terminated (completion-channel signal or task-handle `is_finished`).

**Acceptance.** All 4 sites tracked+aborted; termination test; gates green. **Dependencies.** None.

### WS1.6 — Token hygiene (#127) — **low, size S/M**

**Background.** `src/server/mod.rs:2579,2592` compare tokens with `==` (timing side-channel, theoretical at loopback); `accepts_query_token` (:2611-2623) lets browser endpoints pass the durable token as `?token=` (client-side leak surface: history, Referer, HAR).

**Design.**
- Part A (S): add `subtle` dep; compare via `ConstantTimeEq` on byte slices (length-equalize by hashing both sides first, or compare fixed-length hex decodings).
- Part B (M): `POST /auth/session` (bearer-auth) → random short-lived token (e.g. 10 min TTL, single-purpose) stored in an expiring in-memory map; `accepts_query_token` paths accept only session tokens; GUI JS (`src/gui/`) does the exchange on load; WS/SSE clients in tests updated. Durable token no longer valid in query strings.

**Tasks.** A then B (separate commits, same PR ok). Tests: 401 matrix unchanged for headers; query-string with durable token → 401; session token works then expires.

**Acceptance.** No `==` on token paths; durable token rejected in query; GUI/WS/SSE e2e green; gates green. **Dependencies.** Touches auth region of `server/mod.rs` — serialize with WS1.4 (do before, or target `auth.rs` after extraction).

### WS1.7 — Release can't ship on red CI (#128) — **low, size S**

**Background.** `release.yml` validates metadata and signs artifacts but doesn't gate on tests/clippy for the tagged SHA.

**Design.** First job in release.yml queries the Checks API for the tagged commit and fails unless the CI workflow concluded success (handle in_progress by waiting or failing with a clear message). Alternative accepted: run fmt+clippy+nextest inline. Prefer the check-gate (no duplicate CI minutes).

**Tasks.** Add gate job; make build/sign/publish jobs `needs:` it; test with a scratch tag on a red commit (use a draft/prerelease flow, delete after); document in `docs/cicd.md`.

**Acceptance.** Demonstrated red-CI tag → release fails pre-publish; doc updated. **Dependencies.** None.

### WS1.8 — Remove dead `unreachable!()` arms (#129) — **low, size S**

**Background.** `src/bin/x0x.rs:1718,1755` — exhaustiveness arms for variants dispatched by early `return` at ~:1152–1206. Dead today; a refactor removing an early-return makes one a live panic.

**Design.** Replace with explicit error return ("command dispatched earlier — dispatch table out of sync") using the CLI's existing error style.

**Tasks.** 2-line change + confirm existing CLI tests cover every listed variant's happy path (add any missing). **Acceptance.** Zero `unreachable!()` in production code; CLI behavior unchanged; gates green. **Dependencies.** None.

### WS1.9 — `POST /agent/sign` endpoint (#133) — **feature, size S**

**Background.** x0x-symphony (XSY-0020, cross-repo blocker "x0x:agent-sign-endpoint") needs to sign claims/handoffs with the agent's ML-DSA-65 key via REST without touching key material. The verify half (`POST /agent/verify`) shipped in v0.23.1.

**Design.** `POST /agent/sign {context, payload}` → signature, following the `/agent/verify` + endpoint-registry pattern. Mandatory domain separation: sign `DST(context) || payload` with a length-prefixed external-signing namespace provably disjoint from every internal x0x signing input (announcements, group commits, certificates, upgrade manifests) so callers can never obtain a signature on a valid protocol message. Required context regex, internal-context denylist, 64 KiB payload cap, standard bearer auth (never auth-exempt). Full detail + acceptance criteria in #133.

**Acceptance.** Sign→verify REST roundtrip across two daemons; negative tests (bad context 400, oversize 413, no auth 401, denylisted context rejected); disjointness note documented; gates green. **Dependencies.** None. Unblocks x0x-symphony XSY-0020.

---

## Workstream 2 — Tailnet Phase 1 (#132, prereqs #130 #131)

Ordered tasks T1–T8. Security invariants apply to ALL of them:
- **Default-closed:** nothing is reachable until explicitly enabled + allowed.
- **Verified identity only:** every stream accept requires the transport `verified` flag + `TrustDecision::Accept`, exactly like `src/exec/service.rs:756-826`.
- **No LAN pivot:** Phase 1 forward targets are restricted per the connect ACL; subnet/CIDR-wide and default-route grants are DENIED (Phase 2 capability).
- Relays never see plaintext (QUIC E2E PQC) — do not add any code path that terminates crypto at a relay.

### T1 — Per-peer stream API (size L) — the keystone

**Design.**
- ant-quic surface: `high_level::Connection::open_bi()/accept_bi()` (exported `ant-quic/src/lib.rs:296-299`; streams at `high_level/connection.rs:447`). x0x's `NetworkNode` (`src/network.rs`) currently exposes only message-level send/recv (`network.rs:2313-2360` framing `[0x10][agent_id:32][payload]`).
- Add to `NetworkNode`: `open_stream(peer: PeerId, protocol: StreamProtocol) -> NetworkResult<PeerStream>` and an accept loop surfacing `IncomingStream { peer, protocol, stream }` events. `StreamProtocol` is a u8/varint namespace written as the first bytes of every opened stream (e.g. `0x01 = forward-v1`, `0x02 = socks-v1`; `0x00` reserved), so app streams coexist with gossip/DM traffic and unknown protocols are rejected cleanly. **Verify how saorsa-gossip uses streams on the same connection** (GossipStreamType lanes) and pick protocol IDs / stream dispatch so the two multiplexers cannot collide — this is the highest-risk integration point; read `saorsa-gossip-transport`'s stream accept path before writing code (Rule 8).
- `PeerStream` wraps the ant-quic send/recv stream halves implementing `AsyncRead + AsyncWrite`; backpressure is QUIC-native flow control (no intermediate unbounded buffers — copy loops use `tokio::io::copy_bidirectional` with bounded buffers).
- Gate on identity: `open_stream`/accept require the peer to be transport-verified and trust-accepted; deny otherwise with a typed error. Expired/revoked identities (T2) refuse here too.
- Agent surface: `agent.open_peer_stream(agent_id, protocol)` resolving agent→machine→PeerId via the existing presence/identity cache.

**Files.** `src/network.rs`, `src/lib.rs` (Agent methods), new `src/streams.rs` (PeerStream, StreamProtocol, dispatch), `src/error.rs` (new variants).
**Acceptance.** Two-daemon loopback test: open stream, echo 1 MiB both directions, verify integrity + clean close + half-close semantics; unknown-protocol streams rejected; unverified peer denied; no clippy/fmt violations; rustdoc on all new public items.
**Dependencies.** None (can start immediately, in parallel with T2/T3).

### T2 — Key lifecycle: expiry, re-auth, revocation (#130) (size L) — **hard prereq gate**

**Design.**
- Expiry: optional `not_after: Option<SystemTime>` on AgentCertificate (new cert version; old certs = no expiry, still valid — no breaking change) and optional machine-identity expiry record. Verified gate (the path that sets `inbound.verified`) rejects expired.
- Re-auth: `x0x identity renew` — user key re-signs a fresh AgentCertificate; REST endpoint + CLI; zero-downtime (new cert announced, old superseded).
- Revocation: signed revocation record `{revoked_id, issuer_sig, timestamp}` gossiped on a dedicated topic + persisted locally; verified gate consults the revocation set; partition-tolerant (applies on receipt; anti-entropy via existing gossip patterns). Only the binding user key (for agent certs) or the key itself (self-revocation) may revoke.
- Clock skew: accept ±5 min on expiry checks; document.

**Files.** `src/identity.rs`, `src/storage.rs`, verified-gate site (network/lib), new `src/identity/revocation.rs` (or module), REST+CLI (`src/api/mod.rs` registry + `src/cli/`), ADR.
**Acceptance.** Tests: expired cert → DM/exec/stream denied; revoked peer → denied after revocation propagates (two-daemon test); renewal round-trip without downtime; old-format certs still verify. ADR accepted. Gates green.
**Dependencies.** None to start; **blocks T4/T5 shipping** (streams may merge behind a feature/config flag before this, but the forwarder does not ship enabled without it).

### T3 — Connectivity ACL (#131) (size M) — **hard prereq gate**

**Design.** Mirror `src/exec/acl.rs` structure and semantics exactly:
- File: `connect-acl.toml` beside the exec ACL (same default paths per OS); `[connect] enabled = false` default.
- `[[allow]]` entries: `{agent_id, machine_id, targets = ["127.0.0.1:22", "127.0.0.1:5900", "localhost-port-range:8000-8100"]}` — exact host:port literals and explicit port ranges on loopback only in Phase 1. Any non-loopback target in the file is a validation error (fail-closed, loud).
- Load semantics copied from `load_exec_policy` (`acl.rs:55-78`): missing at default path → disabled; missing at explicit `--connect-acl` → hard error; malformed → hard error; missing section → disabled.
- Enforcement: in the T4 accept path, after verified+trust gates, before local TCP connect. Denials get typed error frames + `connect_denied` diagnostics counter.
- `x0xd --check` validates it.

**Files.** New `src/connect/acl.rs` (mirror exec), `src/bin/x0xd.rs` (flag + check), tests incl. property tests on target parsing/matching.
**Acceptance.** Default = all denied (test); fail-closed matrix matches exec ACL's (parameterized tests mirroring exec's); non-loopback target rejected at load; gates green.
**Dependencies.** None to start; blocks T4 enablement.

### T4 — x0xd forwarder service (size M)

**Design.**
- Outbound: `forward add --local 127.0.0.1:8022 --peer <agent-or-four-words> --target 127.0.0.1:22` → x0xd binds the local TCP listener; each accepted conn opens a `forward-v1` stream to the peer carrying a header `{target_host, target_port}` (bincode, length-prefixed), then `copy_bidirectional`.
- Inbound: on `forward-v1` accept → verified+trust gates → T3 ACL check on `{peer, target}` → `TcpStream::connect(target)` with timeout (10s) → `copy_bidirectional`. Connect failure/deny → typed error frame back, stream closed.
- Lifecycle: forwards persist in daemon state (config-file section + runtime adds via REST); per-forward and per-stream counters (bytes, active conns) in diagnostics; forwards torn down on shutdown via `bg_tasks`/`spawn_tracked` (learn from #126 — every spawn tracked from day one).
- Limits: max concurrent streams per peer (default 32) + per-forward; idle timeout (no bytes for 10 min → close).

**Files.** New `src/forward/` (service, header codec, listener), `src/server/` wiring, config.
**Acceptance.** Two-daemon loopback e2e: forward local port → peer's sshd-stub (test TCP echo server), verify data integrity, concurrent connections, deny-without-ACL, idle timeout, clean shutdown kills listeners+streams. Gates green.
**Dependencies.** T1, T3 (enforcement), T2 (shipping gate).

### T5 — SOCKS5 listener (size M)

**Design.** Single local SOCKS5 endpoint (`127.0.0.1:1080` default, disabled by default): CONNECT-only, no auth (loopback + daemon token model doesn't fit SOCKS auth; document), destination addressing scheme: `<four-word-name>.x0x:port` or `<agent-id-hex>.x0x:port` domain names route to that peer with the port as target (target still ACL-checked on the remote side); non-`.x0x` domains are refused (this is not a general proxy). Implement RFC 1928 subset by hand or a minimal audited crate (prefer hand-rolled ~300 lines; CONNECT-only is small; no new heavyweight dep).
**Files.** `src/forward/socks.rs`, config, REST/CLI toggle.
**Acceptance.** e2e: `curl --socks5-hostname 127.0.0.1:1080 http://<four-words>.x0x:8080/` hits a test HTTP server on the peer; UDP ASSOCIATE and BIND refused cleanly; non-.x0x refused. Gates green.
**Dependencies.** T4 (shares the stream/ACL path).

### T6 — REST + CLI surface (size S/M)

**Design.** Follow the shared endpoint registry (`src/api/mod.rs`) so routes and CLI stay in sync: `GET/POST/DELETE /forwards`, `GET /streams` (active, with peer/bytes/age), `GET /diagnostics/streams`; CLI `x0x forward add|list|rm`, `x0x streams`. Auth: standard bearer (WS1.6 rules). All mutating endpoints require the connect feature enabled.
**Acceptance.** `x0x routes` shows the new endpoints; CLI round-trip tests against a live daemon (existing CLI test harness pattern); api-reference.md updated. Gates green.
**Dependencies.** T4 (T5 for socks toggles).

### T7 — e2e proof (size M)

**Design.** Extend the existing harness patterns (`tests/e2e_*`):
- Loopback: 3-daemon suite covering T4/T5 acceptance + revocation-cuts-stream (T2 integration: revoke mid-stream → stream torn down on next check or immediately if hooked into the verified-cache invalidation).
- VPS testnet: two nodes behind different NATs (use the isolated `--network test` plane, ports 13600/6483 — never prod): prove forward works via direct NAT traversal AND via relay fallback (force relay by config or by choosing an APAC/EU pair known to relay). Record proof artifacts under `proofs/` per repo convention.
**Acceptance.** Both suites green and committed; relay-path and direct-path both demonstrated in artifacts.
**Dependencies.** T4, T5, T2, T3.

### T8 — ADR + docs (size S)

ADR: "Tailnet Phase 1: application-level streams, forwarder, SOCKS; key lifecycle; connect ACL" — decisions: B-then-A path, protocol-id stream namespace, loopback-only targets, deferred TUN/DNS/subnet/exit/mobile. Docs: `docs/tailnet.md` (user guide: forward + SOCKS quickstart), api-reference.md, exec.md-style ACL doc for connect ACL. Obsidian vault mirror per repo convention.
**Dependencies.** Content finalizes with T4/T5; ADR draft can start immediately.

---

## Sequencing & assignment

```
Week 0 (parallel):   WS1.2  WS1.5  WS1.7  WS1.8  WS1.9   (5 × S — one engineer/agent each, or one batch; WS1.9 unblocks symphony XSY-0020)
                     WS1.1  WS1.6                  (server/mod.rs region — serialize these two, land before WS1.4)
                     T1 (streams)   T2 (keys)   T3 (ACL)   T8-draft (ADR)   ← independent, 3 parallel tracks
Week 1–2:            WS1.4 PR series (after WS1.1/WS1.6 merge)   WS1.3 tranche 1
                     T4 (needs T1+T3; T2 may still be in review — merge T4 behind disabled-by-default flag)
Week 2–3:            T5, T6 (need T4)             T2 must merge before anything ships enabled
Week 3–4:            T7 e2e + VPS proof, T8 finalize, release train
```

| Slot | Scope | Issues |
|---|---|---|
| Eng A | Small hardening batch | #123 #126 #128 #129 #133 |
| Eng B | WS queue + token hygiene, then server decomposition series | #122 #127 #125 |
| Eng C | Streams keystone + forwarder + SOCKS | #132 (T1→T4→T5) |
| Eng D | Key lifecycle | #130 (T2) |
| Eng E | Connect ACL, then REST/CLI + e2e | #131 (T3) → T6, T7 |
| Lead (this session) | Review every PR against this plan; coverage ratchet decisions (#124); ADR review (T8) | — |

Blocking edges: `#131 → T4-enable`, `#130 → Phase-1-ship`, `T1 → T4 → T5/T6 → T7`, `WS1.1+WS1.6 → WS1.4`.

## Review protocol

1. Every PR references its issue and the plan section (e.g. "WS2/T4"). PRs that drift from the plan's design must say so explicitly and why (Rule 7 — surface conflicts).
2. The session lead reviews each PR against: the section's acceptance criteria, the security invariants (Workstream 2), and the zero-tolerance gates. No PR merges with skipped tests, `#[ignore]` additions without justification, or silent scope changes (Rule 12).
3. Subagent/engineer reports are verified against the actual diff + CI, not the report text (fabrication precedent: 2026-06-10).
4. Workstream 2 tasks additionally get an adversarial security pass on the accept-path code (T1/T4/T5) before merge.
5. Release: Workstream 1 items can ride normal minor releases. Phase 1 tailnet ships as one minor release once T2/T3/T4/T6/T7 are all green — feature-flagged default-off surfaces may land earlier.

## Out of scope (Phase 2+ — do not build, do not scaffold)

TUN device / virtual IPs / userspace netstack; MagicDNS or any OS DNS integration; subnet routers and CIDR forwarding; exit nodes / default routes; mobile (NEPacketTunnelProvider, VpnService); device-enrollment UX beyond `identity renew`; UDP forwarding (QUIC datagrams reserved for Phase 2).
