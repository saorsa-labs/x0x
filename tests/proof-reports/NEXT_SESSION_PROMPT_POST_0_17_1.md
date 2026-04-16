# Next-session prompt — x0x / ant-quic / saorsa-gossip rock-solid hardening

## Context to load at the top of the next session

You are continuing the stabilisation cycle for the `saorsa-labs` p2p stack
across three repositories that ship together:

- `~/Desktop/Devel/projects/x0x` — current release: **v0.17.1** (tagged 2026-04-16 from commit `7b07ca9`)
- `~/Desktop/Devel/projects/ant-quic` — current release: **v0.26.12**
- `~/Desktop/Devel/projects/saorsa-gossip` — current release: **v0.5.15**

x0x v0.17.1 was cut at the end of a long diagnostic session. The highlights:

- ant-quic 0.26.12 picks up upstream #165 (MASQUE relay target selection). The 6-node VPS pairwise-connect matrix went from 6/30 to 30/30.
- x0x collapsed the Phase D.3 `stable_group_id` abstraction onto `mls_group_id` — every x0x group is an MLS group. This cleared a cluster of 404s in `e2e_full_audit.sh` that were cross-daemon id drift.
- x0x `DirectMessaging::handle_incoming()` changed from `internal_tx.send(msg).await` on a bounded mpsc whose receiver is idle in daemons, to `try_send`. That fixed an end-to-end recv-pipeline stall where ant-quic's reader task forwarded ~567 items / 5 min while x0x's `Node::recv` only surfaced ~65.
- A residual ant-quic bug is tracked upstream as **saorsa-labs/ant-quic#166**: a short unidirectional stream is `[p2p][send] ACKED` on the sender but never surfaces at the receiver's `accept_uni()` in the live VPS mesh. Larger PubSub streams on the same connection are fine. Not reproducible with two daemons on localhost. Tracked, not blocked by x0x.
- ant-quic #163 (hole-punch storm on public-IP peers) and #164 (MASQUE bytes_forwarded=0) are still open upstream with 0.26.12 follow-up comments.

Proof report for that cycle: `tests/proof-reports/CONNECTIVITY_ANTQUIC_0_26_12_20260416.md` — read this before you touch anything.

## Your job this session

Make ant-quic + saorsa-gossip + x0x **100% rock solid for release**. Not
"green on the easy suites", not "user-facing single-client works" —
**every error in every log eliminated, every suite fully green, zero
mystery timeouts, zero silent drops, no warnings outside of expected
configuration paths**. David was explicit: *check ALL logs for ANY
errors*, then fix / test / repeat until you are 100% sure.

The primary open upstream issue (ant-quic #166) and the secondary ones
(#163, #164) all need to be driven to resolution this session, not
filed-and-forgotten.

## Methodology — non-negotiable

1. **Always run with debug logging during diagnosis.** On VPS nodes,
   install a systemd drop-in like:

   ```toml
   [Service]
   Environment=
   Environment=RUST_LOG=info,x0x=debug,x0x::direct=debug,x0x::network=debug,x0xd=debug,ant_quic=info,ant_quic::p2p_endpoint=debug,ant_quic::nat_traversal_api=debug,saorsa_gossip=info
   ```

   Place at `/etc/systemd/system/x0xd.service.d/debug-logging.conf`,
   `systemctl daemon-reload && systemctl restart x0xd`. Remove before
   calling any verification "final" — production should run at
   `RUST_LOG=info`. Keep the drop-in during active investigation.

2. **Read ALL the logs, not just the grep result you expect.** After
   each probe, pull:

   - `journalctl -u x0xd --since "5 min ago"` on every VPS touched, and
     scan for `WARN`, `ERROR`, and `panic`. A single repeating WARN is a
     real signal, not noise to filter past.
   - Local daemon logs at `/tmp/x0x-debug-*/log` when running the
     2-daemon localhost harness.
   - SSE capture files from `start_remote_direct_listener` helpers —
     they must contain the `direct_message` event, not just keepalive
     `: ping`.

3. **Fix / test / repeat until 100%.** Land one focused fix, rerun the
   relevant suite, confirm the suite fully green before moving to the
   next issue. Partial wins are not wins — each suite has a pass count
   and a baseline; you either match or beat the baseline or you are not
   done.

4. **Baselines to match or beat**:

   | Suite | Target |
   |---|---|
   | `cargo nextest run --all-features --workspace` | 976 / 976 / 0 fail |
   | `cargo clippy --all-targets --all-features -- -D warnings` | clean |
   | `cargo fmt --all -- --check` | clean |
   | `tests/e2e_full_audit.sh` (local 3-daemon) | current baseline 256 / 20; target: 275+ / 0 after ant-quic #166 lands |
   | `tests/e2e_live_network.sh` (Mac → VPS mesh) | 66 / 66 (already green — keep green) |
   | `tests/e2e_deploy.sh` (6 VPS deploy+health) | 24 / 24 |
   | `tests/e2e_vps.sh` (6-node matrix, all pairs) | current 30/30 connects, 0/30 DM; target: 30 / 30 connects, 30 / 30 DM, 30 / 30 CLI, 30 / 30 GUI, file transfer 1M + 16M both end `Complete` with sha256 match |
   | `tests/e2e_lan.sh` (studio1 / studio2 LAN) | currently blocked on SSH reachability; 106 / 24 last run — target 130 / 0 once SSH works |

5. **Use debug logs to prove every fix.** Don't just declare a suite green — show the log line that moved. E.g., "post-fix, Tokyo journal contains `[p2p][reader] RECEIVED 41 bytes peer=Singapore gen=XX` AND `x0x::network: recv direct: 40 bytes` AND the SSE `direct_message` event inside 1 second of the send."

## The specific work, in priority order

### (1) ant-quic #166 — primary blocker

**Status**: short unidirectional stream ACKed by sender, never surfaces at receiver. Only in live VPS mesh, not in 2-daemon localhost.

**Evidence captured in the previous session** (see `CONNECTIVITY_ANTQUIC_0_26_12_20260416.md` and the #166 comments):

- Singapore `[p2p][send] BEGIN … bytes=41 conn=132260032188384 addr=udp://45.77.176.184:5483` → `WROTE+FINISH` → `ACKED`.
- Tokyo reader gen=65 on the corresponding incoming connection is receiving 16108-byte PubSub streams from the same peer immediately before and after the send window, but no `[p2p][reader] RECEIVED 41 bytes` for Singapore ever fires for that probe.
- No `ABORT-OLD` on that peer between the two surrounding PubSub receives, so it is not a reader-task-generation race.

**Hypotheses still on the table**:

- Short streams race with the larger PubSub streams on the same connection such that the small one's `accept_uni()` resolution is lost in quinn's stream queue under back-pressure.
- MASQUE relay path is being chosen despite `outcome: Direct` being returned to x0x, and relay strips short streams while passing long ones.
- The reader task body has a window where `connection.accept_uni().await` misses a ready stream because the previous iteration was stuck in `handle_coordinator_control_message` (line ~4606 of `src/p2p_endpoint.rs`).

**Next-step moves you should actually execute**:

- Instrument `spawn_reader_task` in `ant-quic/src/p2p_endpoint.rs` to INFO-level every `accept_uni` entry, every `read_to_end` start/end, every queue size, every coordinator-control decision, so you can see in the journal exactly which iteration the 41-byte probe was expected to land on and whether any stream was accepted and discarded.
- Verify by reading `quinn` upstream what the semantics of `connection.accept_uni()` are when multiple unidirectional streams arrive during a slow `read_to_end`. Confirm or rule out queue-loss.
- Build a local reproducer that opens many uni streams at once from one side to test the ordering semantics. Run with `cargo test --release` and tokio's test runtime.
- When the mechanism is understood, apply the fix narrowly (don't rewrite the reader task) and cut `ant-quic v0.26.13`.
- Bump x0x to the new ant-quic, re-run `tests/e2e_vps.sh`, confirm `0 / 30 DM` becomes `30 / 30 DM`, and confirm the large-file §18b section reaches `Complete` on both ends with sha256 match.

### (2) ant-quic #163 — hole-punch storm

**Status**: on 0.26.12, Tokyo journal shows ~196 NAT-traversal failure events per 10 min, 0 hole-punch successes, despite every mesh peer being public-IP.

**Your move**:

- Read the `nat_traversal_api.rs` path that fires these warnings. The VPS nodes don't need hole punching — they have public IPs — so the machinery shouldn't even engage. Figure out why it does, gate it behind an actual "peer is behind NAT" check, and confirm with live journal sampling that the warning rate drops to zero.

### (3) ant-quic #164 — MASQUE relay byte-forward counter

**Status**: relay sessions establish and the stream-based forwarding loop starts, but under normal traffic most sends go direct (post #165), so the `bytes_forwarded` counter barely moves. The old "=0 always" bug might still lurk in the relay-forced path.

**Your move**:

- Drive a deliberately relay-forced scenario (e.g., two daemons that force MASQUE via config, bypassing the direct path) and confirm `bytes_forwarded` increments match sent bytes within the session window. Close #164 if green.

### (4) saorsa-gossip — check for errors

The gossip layer produced repeating `saorsa_gossip_pubsub: EAGER forward failed: send failed: Endpoint error: Connection error: send acknowledgement timed out (peer may be dead)` warnings throughout the last session's logs, and `saorsa_gossip_membership: SWIM: Suspect timeout → marked dead peer_id=…` at ~1 Hz on the 6-node mesh.

**Your move**:

- Read the SWIM timeouts: are the Suspect/Dead thresholds set too tight for a 6-node WAN mesh? 1 Hz "dead" declarations are a red flag — no steady-state cluster should be churning membership every second.
- The repeated `EAGER forward failed … send acknowledgement timed out` means EAGER PubSub is trying to push through peers that are transport-dead. Either the liveness check in front of EAGER is missing or the gossip runtime isn't honouring SWIM's dead set. Trace from `saorsa_gossip_pubsub::EAGER`'s peer selection back to whatever view it's reading — SWIM or a stale cache — and fix.

### (5) x0x local e2e_full_audit — 20 failures still on the pre-2026-04-12 pattern

**Status**: even with the MLS-id consolidation, the 3-daemon local audit shows 20 failures clustered around direct messaging + WS direct + file transfer. This was present BEFORE the ant-quic bump, so it's not a transport regression — it's likely the same pipeline stall the recv_direct try_send fix addresses, but more aggressively exercised on localhost.

**Your move**:

- Re-run `bash tests/e2e_full_audit.sh` against the 0.17.1 binary. If the 20 failures persist, capture the specific assertions that fail with their daemon logs (`/tmp/x0x-fulltest-{alice,bob,charlie}/log`) and trace them the same way we traced the VPS matrix — ant-quic `[p2p][send]` vs `[p2p][reader]` vs `x0x::network recv`, with debug logging on.
- Fix until 0 / 275+.

### (6) Studio LAN test — unblock SSH, then run

**Status**: studios 1 and 2 respond to ARP from the dev Mac but SSH is refused. Last real run was 106 / 24 (studio2 mDNS isolated on macOS).

**Your move**:

- First: check with David whether SSH is meant to be reachable from the dev Mac (Tailscale? VPN? firewall rule?) and get to a state where `ssh studio1@studio1.local hostname` works.
- Then: `bash tests/e2e_lan.sh`. Confirm the studio2-mDNS-asymmetry is either resolved or clearly documented as a macOS mDNS issue, not an x0x or ant-quic issue.

### (7) Close the loop

Once (1)-(6) are all GREEN:

- `tests/proof-reports/ROCK_SOLID_<date>.md` with every suite's pass count, the diffs that got you there, and the debug-log evidence for each fix.
- Bump x0x to `v0.17.2` (or `v0.18.0` if the ant-quic fix is substantial) and release.
- Bump ant-quic to `v0.26.13` and release.
- Bump saorsa-gossip if any fixes land there.

## Important reminders

- **Deploy only instrumented builds during diagnosis; production must run `RUST_LOG=info`**. Don't leave debug drop-ins in place after you sign off.
- **Cargo.lock in x0x is gitignored; Cargo.toml uses crates.io** — if you want to test a local ant-quic during the fix cycle, use `[patch.crates-io] ant-quic = { path = "../../../../ant-quic" }` in the worktree's `Cargo.toml` (NOT the repo root). Revert before committing the fix.
- **All group id logic is now `mls_group_id`**. Do NOT reintroduce any concept of a separate stable id.
- **The x0x repo's release workflow validates SKILL.md version against Cargo.toml and the tag** — bump both or the release will fail in ~10s with `SKILL.md version X does not match Cargo.toml version Y`.
- **Path dep gotcha**: x0x depends on `saorsa-gossip-*` 0.5.15, which in turn depends on `ant-quic = "0.26.12"` from crates.io. If you `[patch.crates-io]` ant-quic locally, you MUST also patch saorsa-gossip so the whole dep graph picks up the same ant-quic — otherwise `rustc` errors with `expected ant_quic::BootstrapCache, found ant_quic::BootstrapCache` type mismatch between crate versions.
- **VPS bootstrap mesh uses port 5483/UDP transport, port 12600/TCP for API bound to 127.0.0.1**. The `tests/e2e_vps.sh` helper calls the API via SSH-tunneled curl because the API isn't public. This is by design.
- **The 6 VPS nodes in the bootstrap mesh are shared infrastructure**. Before you `systemctl restart x0xd` on any of them, confirm there's no other active testing, and remove your debug drop-ins before leaving.

## Ship criteria — do not declare "rock solid" until all of these are true

- [ ] `cargo fmt --all -- --check` clean on all three repos
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` clean on all three repos
- [ ] `cargo nextest run --all-features --workspace` 100% pass on all three repos
- [ ] `bash tests/e2e_full_audit.sh` 0 failures
- [ ] `bash tests/e2e_deploy.sh` 24 / 24
- [ ] `bash tests/e2e_live_network.sh` 66 / 66
- [ ] `bash tests/e2e_vps.sh` every section 100% pass including all 30 matrix DM deliveries and both 1 MiB + 16 MiB large transfers with sha256 match
- [ ] `bash tests/e2e_lan.sh` 100% pass (once SSH is reachable)
- [ ] ant-quic #166, #163, #164 all closed
- [ ] `journalctl -u x0xd --since "10 min ago" | grep -E "WARN|ERROR"` on every mesh node shows zero non-expected entries (expected = e.g. known config warnings documented in-repo; unexpected = stream drops, NAT storm, SWIM thrash, relay bytes_forwarded=0)
- [ ] Proof report written, memory updated, releases cut

Start with task (1). Do not skip steps.
