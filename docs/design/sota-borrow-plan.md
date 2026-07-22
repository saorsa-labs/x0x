# SOTA-Borrow Plan — Quinn / iroh / noq adoption

**Status:** approved 2026-05-08
**Revision:** 2026-05-08 — backward-compat constraints removed (project not yet launched, all bootstrap + VPS test nodes redeployable). Wire-format and Rust-API breaking changes are permitted; all coordination via planned redeploy.
**Owner:** transport lead (assign per ticket)
**Tickets:** X0X-0038 .. X0X-0050 (13 total, this initiative)
**Soak gate runner:** `tests/launch_readiness.py`

---

## 1. Why this exists

The 0.27.7 → 0.27.12 ant-quic releases plus saorsa-gossip 0.5.32 → 0.5.36 (X0X-0030 .. X0X-0037) closed the obvious framing and protocol-mechanics defects in the raw-DM + ACK-v2 path. Residual signal from the 4h soak under v0.19.30 + probes-off, and from the in-flight v0.19.31 retry pass, is **load-coupled scheduling pressure** — not protocol bugs. A SOTA review (this turn, 2026-05-08) compared ant-quic / saorsa-gossip / x0x against:

- **Quinn** main as of 2026-05-05 (no 0.12 release in 14 months).
- **iroh** `1.0.0-rc.0` (2026-05-07) and **iroh-gossip** `0.98.0` (2026-04-20).
- **noq** `1.0.0-rc.0` (2026-05-07), iroh's Quinn fork.
- **Cloudflare tokio-quiche** (open-sourced 2025-12).

Three pieces of borrowable surface emerged:

1. iroh-style **single-router ingress dispatch** (already partially adopted in X0X-0036 part 2).
2. iroh's **AddressLookup** discovery trait + parallel-error-tolerant resolution.
3. noq's **Path / WeakPathHandle / WeakConnectionHandle** lifecycle and per-path stats retention — the lever behind iroh's "20s → 3s path-switch recovery" claim.

Plus five smaller wins that fell out of the comparison.

---

## 2. Decisions

| # | Decision | Rationale |
|---|---|---|
| D1 | **Selective port from noq, no fork.** Lift surface APIs into ant-quic's vendored quinn-proto base. | noq uses n0-private NAT frame numbers (`0x3d7f9x`) while ant-quic uses the IETF draft-seemann range (`0x3d7e9x`). Wire-incompat with deployed mesh. PQC layer is plumbed under ant-quic-private crypto. ant-quic vendors quinn-proto sources rather than depending on the crate, so no rebase. |
| D2 | **Stay on the IETF draft-seemann NAT frame range (`0x3d7e9x`) by default.** Spec alignment preference, not a wire invariant. Wire-format breaking changes are permitted in this initiative; all deployed nodes can be redeployed. | Project not yet launched. Spec-alignment preserves a path to interop with future external implementers tracking the IETF draft. Switching to noq's n0-private `0x3d7f9x` range gains nothing (iroh's QNT semantics also diverge from the draft, so we wouldn't interop with iroh either). |
| D3 | **No Quinn 0.12 wait.** Cherry-pick from `quinn-rs/quinn` `main` and from noq into vendored sources on demand, attributed in commit messages. | Quinn proper hasn't cut a release in 14 months. iroh chose the same posture and forked. ant-quic already vendors, so the cost is just the cherry-pick discipline. |
| D4 | **AddressLookup trait lives in ant-quic** (not saorsa-gossip), since address resolution happens pre-QUIC-connect. | Existing bootstrap_cache + mDNS + hardcoded peers all live in ant-quic; the trait wraps them. |
| D5 | **Soak gates remain authoritative.** Every phase ends with a launch-readiness gate run, not a code-review approval alone. | The work is motivated by soak data; soak data validates the work. |

---

## 3. Phases

| Phase | Tickets | Length (realistic) | Exit gate |
|---|---|---|---|
| **A — Quick wins** | 0038–0043 (6) | 1 dev-week | 30-min soak GO + Phase A 30/30 + no Phase B 59/59 regression |
| **B — Foundation lifts** | 0044–0047 (4) | 2 dev-weeks | 4h soak GO + broad-launch limited-production gate |
| **C — Path semantics** | 0048–0050 (3) | 4 dev-weeks | 12h soak GO + broad-launch full gate + 3 consecutive 30-min pre-warms ≥ 30/30 |
| **D — Deferred** | — | — | scoped review after C lands |

Phase A tickets are independent and parallelisable. Phase B mostly independent. Phase C must serialise (0048 → 0049 → 0050).

---

## 4. Phase A — Quick wins

### X0X-0038 — `AddressLookup` trait + parallel resolver registry

Introduce `pub trait AddressLookup` in ant-quic with parallel-error-tolerant resolution; wrap existing sources as default impls; add an `AddrFilter` ordering hook. Mirrors iroh PR #3960 + #4126 shape.

**Files.** New: `ant-quic/src/discovery/{mod,lookup,filter}.rs`. Modify: `ant-quic/src/lib.rs` (re-exports), `ant-quic/src/p2p_endpoint.rs` (mdns plug-in point), `ant-quic/src/bootstrap_cache/cache.rs` (impl trait). Touch: `x0x/src/network.rs` (DEFAULT_BOOTSTRAP_PEERS becomes a `HardcodedLookup`).

**Surface.**
```rust
pub trait AddressLookup: Send + Sync + 'static {
    fn name(&self) -> &'static str;
    fn lookup(&self, peer_id: PeerId)
        -> BoxStream<'static, Result<SocketAddr, LookupError>>;
}
pub trait AddrFilter: Send + Sync + 'static {
    fn filter(&self, addrs: Vec<SocketAddr>) -> Vec<SocketAddr>;
}
pub struct LookupRegistry { /* parallel fanout, per-service errors do not abort the resolve */ }
```

**Default impls.** `BootstrapCacheLookup`, `MdnsLookup`, `HardcodedLookup`.

**Acceptance.**
- All three default impls resolve in unit tests; one panicking impl does not abort the registry.
- Existing `Endpoint::connect` routes through the registry; `tests/e2e_local_mesh.sh` 6-pair matrix unchanged.
- New unit test `discovery_parallel_error_tolerance` proves: 3 services, 1 errors, 2 succeed → resolve succeeds with 2 addresses.

**Soak impact.** None expected. If DEFAULT_BOOTSTRAP_PEERS resolution slows, Phase A 30/30 must still hit.

---

### X0X-0039 — `data_tx` capacity audit + bump + high-water WARN

Audit the single-shared-mpsc-fed-by-all-readers pattern at `ant-quic/src/p2p_endpoint.rs:2626` (default 256). Bump default capacity, add a high-water WARN at < 20% headroom, expose depth metric on `/diagnostics/connectivity`.

**Files.** `ant-quic/src/p2p_endpoint.rs:2626` (channel creation), `ant-quic/src/unified_config.rs:471` (`DEFAULT_DATA_CHANNEL_CAPACITY`), `ant-quic/src/p2p_endpoint.rs:~2900,~2950` (`data_tx.send` call sites — currently silently drop on full), `x0x/src/lib.rs` `/diagnostics/connectivity` handler.

**Tuning.** Default 256 → **8192** (matches saorsa-gossip's per-subscriber buffer). Configurable via existing `P2pConfigBuilder::data_channel_capacity`.

**WARN policy.** Mirror saorsa-gossip v0.18.3 lesson: WARN-level when free slots < 20% of capacity, throttled to once per 10s per endpoint.

**Acceptance.**
- Local 5-daemon stress (model `tests/e2e_stress_gossip.sh`) shows zero silent drops in `data_tx` under burst that previously triggered them.
- `/diagnostics/connectivity` exposes `data_tx_depth`, `data_tx_capacity`, and `data_tx_high_water_count`.
- 30-min soak window with `data_tx_high_water_count == 0` on all 6 VPS nodes.

**Soak impact.** Likely fixes a class of false-positive ACK timeouts under W2-W4 burst. Watch: does the W1→W2 collapse pattern from X0X-0036 weaken?

---

### X0X-0040 — Cooling reset on first inbound frame (saorsa-gossip)

Mirror iroh relay-actor pattern: per-peer cooling state resets on the first inbound frame from that peer, not on probe-success.

**Files.** `saorsa-gossip/crates/pubsub/src/lib.rs:1408` (`peer_cooling: HashMap<PeerId, PeerCoolingState>`). New helper `record_inbound_from_peer(peer_id)` called from gossip dispatcher's incoming-message handler, presence beacon receiver, PlumTree EAGER-receive.

**Constraint.** Must NOT touch `PEER_TIMEOUT_THRESHOLD: 5` / `PEER_TIMEOUT_WINDOW: 30s` constants — those are X0X-0036 part 2 tuning. Only the *reset trigger* changes.

**Acceptance.**
- Unit test: peer accumulates 4 timeouts (under threshold), receives an inbound frame, cooling counter resets to 0; subsequent timeouts do not trip suppression prematurely.
- 30-min soak: `suppressed_peers / known_peer_topic_pairs` ratio stays below the X0X-0018 0.12 broad-launch ceiling. (No regression — should improve.)

**Soak impact.** Lower suppressed/known ratio expected, especially in W3-W4 of long soaks.

---

### X0X-0041 — "Prefer newest connection" on x0x raw-DM path

Mirror iroh-gossip #43 and iroh #3921. When the lifecycle bus emits `Replaced { new_generation, .. }`, raw-DM treats it as an immediate retry signal rather than waiting for a fresh connect cycle.

**Files.** `x0x/src/lib.rs:5854–5899` (lifecycle watcher loop), `x0x/src/lib.rs:3003–3082` (`send_direct_raw_quic` consumes "active generation per peer" hint), `x0x/src/dm_send.rs` (retry loop short-circuits on `Replaced` between attempts).

**Edge case.** Race between `Replaced` and new `Established` — DM holds for a bounded `prefer_newest_grace_ms` (config, default 250ms) before declaring failure.

**Acceptance.**
- Synthetic test: kill+restart a peer's QUIC connection mid-DM → `/direct/send` lands on the new connection in ≤ 500ms without surfacing a Timeout.
- Long soak: residual ACK timeouts attributable to supersede races drop to 0 (currently nonzero per X0X-0034 tail evidence).

**Soak impact.** Closes a documented residual failure class in X0X-0034.

---

### X0X-0042 — Quinn PR #2616 supersede-race diff-and-validate

Pure documentation ticket. Read [Quinn PR #2616](https://github.com/quinn-rs/quinn/pull/2616) (Ralith removed `ZeroRttAccepted` future, replaced with `Connection::authenticated()`); compare to ant-quic's X0X-0034 fix shape; produce a comparison doc.

**Files.** New: `x0x/docs/design/quinn-2616-supersede-race-comparison.md` (delivered; removed 2026-07-19 — see git history). Update X0X-0034 in `issues/issues.jsonl` with cross-reference.

**Output.** A 1–2 page comparison: "Quinn killed the racy signal at layer X by removing the future. ant-quic's X0X-0034 gates at layer Y. They are/are-not at the same layer because Z." If the layers diverge, file a follow-up ticket.

**Acceptance.** Reviewed by transport lead. May spawn a follow-up ticket; that is an OK outcome.

**Soak impact.** None directly. Confidence-validation only.

---

### X0X-0043 — GSO-bundle tail-drop instrumentation

Capture per-bundle drop signal to test [Quinn issue #2627](https://github.com/quinn-rs/quinn/issues/2627) hypothesis as alternative root cause for X0X-0030 idle-rot 12s timeouts. The hypothesis: GSO bundles ship 10 packets in ~12 µs (~5.8 Gbps spike at the wire) and CDN/CGNAT rate-limiters tail-drop the bundle. Quinn's pacer paces *between* sendmsgs, not within a bundle.

**Files.** `ant-quic/src/p2p_endpoint.rs` UDP send paths (search `quinn_udp::Transmit`); new counters in `ant-quic/src/diagnostics/`: `gso_bundle_send_total` and `gso_bundle_partial_send`. Expose on `/diagnostics/connectivity.transport`.

**Hypothesis under test.** If the 28-min-idle-then-burst pattern correlates with `gso_bundle_partial_send` spikes at the very first burst, X0X-0030 is tail-drop, not idle-rot. Fix path then forks: deploy `max_outgoing_bytes_per_second` (Quinn PR #2556) or pace within bundle.

**Acceptance.**
- 4h soak proof artefact has `gso_bundle_send_total` and `gso_bundle_partial_send` per-window per-node.
- Brief findings doc `x0x/docs/debug/gso-bundle-tail-drop-x0x-0030.md` with one of: confirmed / not-the-cause / inconclusive.

**Soak impact.** Diagnostic only. Followup tickets if confirmed.

---

## 5. Phase B — Foundation lifts

### X0X-0044 — ACK-v2 vs IETF AckFrequency decision spike

1-day spike: can ant-quic's custom B3-envelope ACK-v2 be replaced or composed with Quinn's wired-but-defaulted `AckFrequencyConfig` (draft-ietf-quic-ack-frequency-04) + `IMMEDIATE_ACK` frame (`0x1f`)?

**Files.** Read `ant-quic/src/frame.rs:205` (`ImmediateAck` already in the enum), `ant-quic/src/ack_frame.rs` (full ACK-v2 envelope), `ant-quic/src/p2p_endpoint.rs:2632` (dedupe cache). New: `x0x/docs/design/ack-v2-vs-ietf-ack-frequency.md`.

**Decision matrix to fill.**

| Criterion | ACK-v2 (status quo) | IMMEDIATE_ACK + AckFrequency | Hybrid |
|---|---|---|---|
| Receiver-drained semantic | yes | ? | ? |
| App-level idempotency (request_id dedupe) | yes | no (transport-level only) | yes |
| Wire compat with deployed mesh | yes | breaks | migration story |
| Maintenance surface | high (custom protocol) | low (IETF) | medium |

**Acceptance.** Decision doc produced. Bound options: keep ACK-v2; migrate fully to IETF; hybrid (control via IMMEDIATE_ACK, app-idempotency above). Spawns implementation ticket if migration chosen — that ticket is **not** part of this initiative.

**Soak impact.** None. Decision-only.

---

### X0X-0045 — Port `WeakConnectionHandle` into ant-quic

Mechanical lift from noq (`noq/src/connection.rs:1357`). ~50 LoC. Pure addition.

**Files.** `ant-quic/src/connection.rs` (or wherever `Connection` lives — confirm in ticket). Replace ad-hoc `Arc<Mutex<Option<...>>>` weak-ref patterns in `ant-quic/src/connection_router.rs` and `ant-quic/src/peer_directory.rs`.

**Surface.**
```rust
pub struct WeakConnectionHandle(Weak<ConnectionInner>);
impl WeakConnectionHandle {
    pub fn is_alive(&self) -> bool;
    pub fn upgrade(&self) -> Option<Connection>;
    pub fn is_same_connection(&self, other: &Self) -> bool;
}
impl Connection {
    pub fn weak_handle(&self) -> WeakConnectionHandle;
    pub fn on_closed(&self) -> impl Future<Output = ConnectionError>;
}
```

**Acceptance.**
- All existing `Arc<Mutex<Option<Connection>>>` watcher patterns migrated.
- Unit test: weak handle does not keep connection alive after last strong drop.
- No new test failures in ant-quic suite (currently 2240/2240).

**Soak impact.** None expected; refactor only.

---

### X0X-0046 — `Path` + `WeakPathHandle` skeleton (read-only)

Introduce `Path` and `WeakPathHandle` types modelled on noq (`noq/src/path.rs:107,289`) but read-only: stats accessors, no `set_status`, no `open_path` (those land in Phase C). The point of this ticket is to surface paths in the API without rewiring the send pipeline.

**Files.** New: `ant-quic/src/path.rs`. Modify: `ant-quic/src/connection.rs` to add `paths() -> Vec<Path>` and `path_stats(PathId) -> Option<PathStats>`. Wrap (do not rewrite) existing path-tracking in `ant-quic/src/transport/`.

**API.**
```rust
pub struct Path { /* (conn_handle: WeakConnectionHandle, id: PathId) */ }
impl Path {
    pub fn id(&self) -> PathId;
    pub fn stats(&self) -> PathStats;
    pub fn remote_address(&self) -> SocketAddr;
    pub fn observed_external_addr(&self) -> Option<SocketAddr>;
}
```

**Constraint.** No wire-format changes in this ticket (those land in X0X-0049). No new transport parameters yet. Types are `pub` from day 1 — backward-compat is not a constraint.

**Acceptance.**
- Single-path connections expose exactly one `Path` with sane stats.
- Stats remain readable via `WeakPathHandle` after underlying path is closed (drop-based refcounting that retains final `PathStats`).
- New integration test `path_stats_retention.rs`.

**Soak impact.** None expected.

---

### X0X-0047 — `AsyncUdpSocket` + `UdpSender` trait alignment

Refactor ant-quic's UDP provider abstraction (`ant-quic/src/transport/provider.rs`) to match noq's `AsyncUdpSocket` + `UdpSender` shape — the split that allows multiple senders with independent wakers.

**Files.** `ant-quic/src/transport/provider.rs`; replace `tokio::net::UdpSocket` direct uses with the trait.

**Why.** Preparation for clean MASQUE relay plug-in (currently `src/masque/` reaches into connection state).

**Acceptance.**
- Existing tokio-backed UDP usage works unchanged via a default impl.
- Smoke: a no-op mock `AsyncUdpSocket` impl can be wired into a test endpoint and round-trips a packet.
- No production behaviour change (regression-free against ant-quic 2240/2240).

**Soak impact.** None.

---

## 6. Phase C — Path semantics (the "20s → 3s" lever)

### X0X-0048 — Per-path stats retention end-to-end

Wire `PathStats` retention into the transport state machine so an abandoned path's final stats are still readable. Extends X0X-0046 from "API skeleton" to "carries data."

**Files.** `ant-quic/src/transport/path_data.rs` (or equivalent — confirm in ticket). `ant-quic/src/connection.rs` (path event emission).

**Wire impact.** None. Internal state only.

**Acceptance.**
- Multi-pair test (single connection, two paths via re-binding) shows both paths' stats independently and survives one path's abandonment.
- New test `path_stats_lost_packets.rs` verifies `lost_packets` and `lost_bytes` per noq CHANGELOG #560.

**Risk.** Touches internal connection state machine — highest-risk Phase B/C ticket. Pair-program / extra review.

**Blocked by.** X0X-0046.

---

### X0X-0049 — Path-aware send pipeline + multipath wire format

Make outbound writes routable to a specific path AND ship multipath on the wire, gated behind a transport parameter. Required for path-switch recovery (the actual "20s → 3s" lever).

**Files.** `ant-quic/src/connection.rs` (`SendStream` write path; new explicit `write_on_path(PathId, ...)`). `ant-quic/src/transport/` packet number space per path. `ant-quic/src/frame.rs` (new multipath frames — see below). `ant-quic/src/transport_parameters.rs` (negotiate multipath enable).

**Wire format additions.** Following draft-ietf-quic-multipath:
- `PathAck` (`0x3e`) and `PathAckEcn` (`0x3f`) — replace `Ack` / `AckEcn` once multipath is negotiated.
- `PathAbandon` (`0x3e75`)
- `PathStatusBackup` (`0x3e76`), `PathStatusAvailable` (`0x3e77`)
- `PathNewConnectionId` (`0x3e78`), `PathRetireConnectionId` (`0x3e79`)
- `MaxPathId` (`0x3e7a`), `PathsBlocked` (`0x3e7b`), `PathCidsBlocked` (`0x3e7c`)
- New transport parameter `max_concurrent_multipath_paths` (default 8, mirror noq).

**Negotiation rule.** Multipath is opt-in per connection via the transport parameter. A connection with one peer not advertising the parameter falls back to standard single-path `Ack` / `AckEcn`. This preserves interop with any future external QUIC implementation that does not implement draft-ietf-quic-multipath.

**Acceptance.**
- App API: `Connection::open_path(addr) -> OpenPath`, `SendStream::write_on_path(PathId, ...)`.
- Multipath transport parameter negotiates correctly between two ant-quic peers (multipath active) and between an ant-quic peer and an artificially-non-multipath peer (single-path fallback active, no `PathAck` frames sent).
- Packet number space correctly partitioned per path.
- Existing single-path tests pass without modification (auto fall-back).
- New test `multipath_two_path_send_receive.rs`: open two paths, write on each, verify per-path stats diverge.

**Risk.** High — largest ticket in the initiative. Touches frame parsing, transport-parameter negotiation, packet-number-space tracking, send-path routing. May split into "wire format + negotiation" + "send-pipeline routing" sub-tickets at planning time.

**Blocked by.** X0X-0048.

---

### X0X-0050 — Apply path status for path selection

Mirror iroh PR #4233. Path status (`Available` / `Backup`) influences which path the connection sends on. Builds on X0X-0048 + X0X-0049.

**Files.** New: `ant-quic/src/transport/path_selection.rs`. Modify: `ant-quic/src/connection.rs` (`Path::set_status` becomes effectful).

**Acceptance.**
- Two-path test: setting one to `Backup` causes sends to prefer `Available`; failover when `Available` becomes unhealthy is observable in soak diagnostics.
- 12h soak with path-switch recovery measurable — log a histogram of "ms from path-fail-detect to first successful send on alternate path." Target: P95 ≤ 3s.

**Soak impact.** Primary value-delivery of the entire initiative. The 12h soak is the gate.

**Blocked by.** X0X-0049.

---

## 7. Phase D — Explicit deferrals

| Item | Reason for deferral | Re-evaluation trigger |
|---|---|---|
| Per-path congestion controller state | Massive scope; the actual "20s → 3s" recovery lever. Eligible for promotion into Phase C as a 14th ticket (X0X-0051) — see decision note below. | If kept in D: after Phase C 12h soak GO. |
| `NetworkChangeHint` plumbing (OS-level netwatch) | Requires `netwatch` crate or equivalent; cross-platform surface. | If Phase C measured P95 still > 5s. |
| BBRv3 swap | Whole congestion stack rework; Quinn rejected BBRv2; ant-quic ships its own BBR. | Out of scope; revisit when CUBIC tail latency becomes a soak signal. |
| Migrating QNT to noq's `0x3d7f9x` numbering | Spec-alignment preference (D2). No backward-compat reason; iroh's QNT semantics also diverge from draft-seemann so we wouldn't interop with iroh either. | Recommended: don't, but no longer "never". |
| Switching to noq as upstream | PQC plumbing under ant-quic-private crypto, ant-quic's existing 2240-test suite, noq is rc.0 (pre-stable). | Re-evaluate after noq 1.0 final. |

**Decision note on per-path CC promotion.** Without backward-compat as a constraint, X0X-0049 ships true multipath wire format. The technical dependency that kept per-path congestion controller in Phase D (needs Path semantics) is then satisfied by Phase C. Per-path CC is the change that delivers the iroh "20s → 3s" recovery claim — without it, multipath ships but path-switch recovery still re-grows CWND from MSS on the new path. Promoting it into Phase C as X0X-0051 is gated on operator approval; absent that approval it remains in Phase D.

---

## 8. Risk register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Phase A or B touches wire format (out of phase) | Low | Medium | Phase discipline — wire-format changes belong in X0X-0049 only; review checklist flags any `frame.rs` constant addition outside that ticket |
| Phase C multipath wire format breaks single-path peers via mis-negotiation | Medium | Medium | Test matrix: multipath ↔ multipath, multipath ↔ artificially-non-multipath, must both pass before X0X-0049 exits review |
| `WeakConnectionHandle` migration regresses an ad-hoc cleanup path | Low | Medium | X0X-0045 acceptance includes "no new test failures"; ant-quic 2240 suite is the gate |
| AddressLookup parallel resolve introduces latency on hot path | Low | Low | Bound parallel concurrency; instrument resolve latency per service |
| `data_tx` 256→8192 reveals downstream consumer back-pressure that was previously masked | Medium | Low | Add `data_tx_high_water_count` to soak assertions; if tripped, bump consumer drain rate |
| API churn in Phase B noq-port surfaces (X0X-0045/0046/0047) cascades through downstream consumers | Medium | Low | All three repos (`ant-quic`, `saorsa-gossip`, `x0x`) are co-developed; breaking changes are coordinated in pinned-bump PRs. No external consumers to surprise. |

---

## 9. Soak strategy

| Phase exit | Soak length | Gate |
|---|---|---|
| A | 30-min × 3 consecutive | Phase A 30/30, Phase B 59/59 (no regression), broad-launch limited-production GO |
| B | 4h | broad-launch limited-production GO, dispatcher.timed_out cluster-wide ≤ X0X-0036 baseline |
| C | 12h | broad-launch full GO, peak suppressed/known ≤ 0.12, P95 path-switch-recovery ≤ 3s |

Runner: `python3 tests/launch_readiness.py --gate broad-launch --anchor nyc --proof-dir <iso8601-ts>`. Already shipped per X0X-0015.

---

## 10. Rollback

Each ticket lands as one PR, paired with bumps where required (`ant-quic` minor + `saorsa-gossip` pin + `x0x` pin). Rollback = revert PRs in reverse pin order. Phase A and B tickets are independent — rolling back any one does not block another. Phase C tickets cascade (0049 depends on 0048, 0050 depends on 0049); a Phase C rollback rolls back the whole phase.

---

## 11. References

- This plan was synthesised from the SOTA review on 2026-05-08 (transcript: agent reports on Quinn / iroh / noq / ant-quic-saorsa-gossip mapping).
- Quinn: https://github.com/quinn-rs/quinn — main as of 2026-05-05.
- iroh: https://github.com/n0-computer/iroh — `1.0.0-rc.0` (2026-05-07).
- iroh-gossip: https://github.com/n0-computer/iroh-gossip — `0.98.0` (2026-04-20).
- noq: https://github.com/n0-computer/noq — `1.0.0-rc.0` (2026-05-07).
- Cloudflare tokio-quiche: open-sourced 2025-12.
- Quinn PR #2616 (supersede-race fix): https://github.com/quinn-rs/quinn/pull/2616
- Quinn PR #2556 (`max_outgoing_bytes_per_second`): https://github.com/quinn-rs/quinn/pull/2556
- Quinn issue #2627 (GSO-bundle tail-drop): https://github.com/quinn-rs/quinn/issues/2627
- iroh PR #3921 (relay supersede policy): https://github.com/n0-computer/iroh/pull/3921
- iroh PR #4233 (apply path status for selection): https://github.com/n0-computer/iroh/pull/4233
- iroh PR #4126 (parallel address-lookup error tolerance): https://github.com/n0-computer/iroh/pull/4126
- iroh-gossip PR #43 (always prefer newest connection): https://github.com/n0-computer/iroh-gossip/pull/43

Existing soak-ladder doc: [`p2p-timeout-elimination.md`](p2p-timeout-elimination.md). Existing X0X-0036 / X0X-0037 issues in `issues/issues.jsonl`.
