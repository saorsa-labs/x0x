# ADR Hygiene Sign-off List — 2026-09-25

Source: `.planning/adr-vision-alignment-2026-09-25.md` §4, each item re-verified
against `origin/main` at `4d59da8`. AI drafted this list; **no ADR was marked
Accepted and no Accepted ADR body was edited**. Every row needs David's decision.

Safe edits already made in this PR: README index now files ADR 0043, 0061,
0064, 0066, 0067, 0068 under Accepted (their files say Accepted) and ADR 0005
under a new Superseded heading (its file says Superseded); factual drift fixed
in Proposed ADR 0047 (`Encrypted` policy ships) and ADR 0052 (asset size,
whitelist count, line refs).

## A. Proposed ADRs whose mechanism already ships on main (Proposed → Accepted?)

| ADR | Shipping evidence (file:line) |
|-----|-------------------------------|
| 0024 GSS rotation on admin remove | `src/server/routes/named_groups.rs:17468` (remove path), F1 rotate tests `:40412-40457`; shipped v0.35.0 |
| 0044 Loopback REST/WS/SSE control plane | `src/server/mod.rs:328` (`serve`), `:2105-2125` (routes + bearer auth) |
| 0045 Decentralized self-update | `src/upgrade/manifest.rs:11` (`RELEASE_TOPIC = "x0x/release"`) |
| 0046 Exec fail-closed ACL | `src/exec/acl.rs:112` (`ExecAcl`) |
| 0047 CRDT KV store + delta gossip | `src/kv/store.rs:892-960` (`new_encrypted`), `src/lib.rs:17407` |
| 0048 Task-list CRDTs + signed provenance | `src/crdt/provenance.rs:58` (`x0x.task.claim.v2`) |
| 0049 Presence beacons + FOAF | `src/presence.rs:54` (`x0x.presence.global`) |
| 0050 DM over gossip base | `src/dm.rs:249` (`DmEnvelope`) |
| 0052 Embedded GUI | `src/server/ws.rs:1313` (`include_str!`), `src/bin/gui_coverage.rs:22` |
| 0053 API-unserved watchdog | `src/server/api_watchdog.rs:345` |
| 0054 External agent signing DST | `src/api/agent_signing.rs:78` |
| 0055 DM file transfer, 1 GiB cap | `src/files/mod.rs:20,23` |
| 0057 Embedded `serve()` / local apps | `src/server/mod.rs:328` |
| 0058 Compile-time constitution | `src/constitution.rs:7` |
| 0059 InviteV4 + seating provenance | `src/groups/invite.rs:168` (`INVITE_VERSION_V4`); status line says acceptance follows v0.41.0, which has shipped |
| 0060 Owner's Home is elected | `src/server/routes/home.rs:93,350` (election loser adopts canonical) |

## B. Proposed status changes (not applied — David to decide)

| ADR | Proposal | Rationale |
|-----|----------|-----------|
| 0056 | Superseded by 0042 | Self-described "Historical Record" of the pre-0042 voice design; 0042 is Accepted |
| 0065 | Superseded by / folded into 0060 | Interim P4 position for 0060's election; inventory ships (`src/server/routes/home.rs:107`) |
| 0062 | Freeze new work (not reject) | Home persistence pair recovery; partial #471 code at `named_groups.rs:30430` stays |
| 0066 | Freeze new work, no reversal | Fork-quarantine coverage; shipped slices stay |
| 0067 | Freeze new work, no reversal | Derived lifecycle token; shipped |
| 0068 | Freeze new work, no reversal | Quarantine history pin + task-delta buffer; shipped |
| 0043 | Freeze new work: move ceremony stays disabled | Announce v3 ships (`src/lib.rs:694`); ceremony disabled (`src/lib.rs:11129`) |
| 0063 | Freeze new work: legacy-compat gates stay open | Draft; G1–G8 open, adoption disabled |
| 0035 | Freeze new work beyond metering | Relay decentralization; keep metering only |
| 0051 | Freeze new work | Default-off one-hop DM relay (`src/peer_relay.rs:167`) |
| 0010 / 0024 | Freeze new GSS group *creation* work (not reject) | GSS stays the legacy/grandfathered plane |

## C. Contradictions involving Accepted ADRs (need David's edit, an erratum, or a superseding ADR)

| ADRs | Contradiction (verified) |
|------|--------------------------|
| 0020 vs 0035 | 0020 assumes an always-on symmetric relay fallback on every node (0020:16); 0035 says the relay backbone is effectively the bootstrap fleet (0035:14) |
| 0020 vs code | 0020:143 says `src/api/mod.rs` registry is not extended; it now carries `/forwards` (`src/api/mod.rs:1706-1722`) |
| 0037 vs 0043 | Both Accepted with different move designs; 0043 amends 0037 but 0037 body is unchanged; ceremony disabled in code (`src/lib.rs:11129`) |
| 0038 vs code | 0038:42 requires ≥1 Roaming agent in Home; roaming-move ceremony is disabled (`src/lib.rs:503,11129`) |
| 0064 vs 0059 | Accepted 0064 builds on 0059 (InviteV4), which is still Proposed (0064:7,9) |
| 0004 vs code vs index | 0004:49 says `max_concurrent_uni_streams` 50,000; code is 256 (`src/network.rs:1873`); README index says 4,096 |
| 0017 | Links `0011-multi-port-bootstrap.md`, which does not exist (real file: `0011-bootstrap-dual-listen-udp-443.md`) |
| 0010 | Status says forward path superseded by 0012, yet GSS remains a first-class plane in code (`src/groups/mod.rs:544-589,1006`) and in 0024 |

Dropped as not verified in this pass: 0036 "roster source ≠ code"; 0020
"ForwardV1 denied by default".
