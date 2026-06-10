> **⚠️ CORRECTION (later same day): the "self-contention" root cause below was REFUTED and
> the fix it describes did NOT work (m2 still fails 6/6 runs). Read
> `handoff/treekem-convergence-SECOND-OPINION-2026-06-04.md` for the honest current state
> and the full ruled-out evidence. Keep this file only for the still-valid ruled-out items
> (flood, size, receiver-ACK) and the code map.**

# TreeKEM member-convergence failure — ROOT CAUSE (supersedes 3 prior handoffs)

**Date:** 2026-06-04
**Status:** root-caused with live evidence; fix in progress
**Supersedes:**
- `handoff/treekem-2nd-member-welcome-gap-2026-06-03.md` (right area, wrong mechanism)
- `handoff/treekem-2nd-member-is-gossip-critical-gate-2026-06-03.md` (**wrong** — flood is not the cause)
- `handoff/gossip-connectivity-fix-status-2026-06-04.md` ("flood mitigated" was optimistic)

---

## TL;DR

`e2e_treekem_membership.py --member2` fails at `converge_member_*`: a member reaches
the anchor's roster but never enters the TreeKEM tree (its Welcome/MemberAdded is never
delivered). This was blamed on a saorsa-gossip Critical-lane flood. **That is wrong.**

Live evidence proves the failure is an **x0x application-layer self-contention bug**: the
anchor fires **redundant concurrent ~41 KB critical membership DMs** to a just-joining
member (immediate push + delayed push + a fresh `Result` send on *every* 2 s poll, all
carrying the same `MemberAdded`). Bursts of 19–28 large sends land in single 1-second
windows; with a **4 s per-attempt timeout** they serialize behind the per-peer
single-in-flight send slot and **~50 % time out**. The failure is **intermittent and
not 2nd-member-specific** (one repro failed at m1/helsinki, others at m2/nuremberg).

---

## What was ruled OUT (with evidence)

All experiments on the live testnet (testnet daemons, API 13600, `x0xd-testnet`),
x0x 0.21.0 + the locally-patched saorsa-gossip 84c53fb, fresh daemons.

1. **NOT the gossip Critical-lane flood.** During the failing window, anchor→member DMs
   of **1 KB through 47 KB succeed in ~0.4 s** over the *same* `gossip_inbox` path. A
   controlled burst gave **SMALL 20/20 and LARGE(41 KB) 20/20** delivered at the exact
   moment the anchor's 41 KB named-group sends were failing ~50 %. The 84c53fb prune fix
   reduces overflow (1839/90s → ~8/30s fresh) but is **irrelevant to this bug**.
2. **NOT payload size / `MAX_PAYLOAD_BYTES`.** Size is exonerated by the 47 KB probes
   above. (Separately, the **catch-up** response *does* hard-fail on size — see below —
   but that is a distinct fallback-path defect, not the primary blocker.)
3. **NOT the receiver ACK pipeline.** With `dm.trace=info` on the member,
   **48/48 payloads that reached `handle_payload` were decrypted and ACKed**
   (`dm_inbox.rs:353`). Decrypt-fail / request-id-mismatch (the only silent-no-ACK paths)
   never fired for the anchor's sends.
4. **NOT raw-QUIC vs gossip.** Named-group delivery and the probe both use
   `direct_message_send_config()` = `DmSendConfig::default()` (`prefer_raw_quic=false`,
   gossip_inbox). Identical config.
5. **NOT connection replacement.** `outbound_send_replaced_short_circuit = 0` in the
   failing run.
6. **NOT the original "consumer blocks on `fetch_treekem_welcome`" theory.** The member
   shows **zero** MemberAdded/welcome-fetch/apply processing — it never *receives* the
   MemberAdded, so it never reaches the fetch.

## What it IS (root cause)

The anchor's per-member delivery fan-out sends the same ~41 KB `MemberAdded` event to a
member via **multiple concurrent paths**:
- `spawn_named_group_event_delivery` (immediate) — `x0xd.rs:6852`
- `spawn_named_group_event_delivery_after` (delayed) — `x0xd.rs:6889`
- a fresh `JoinResultMessage::Result` send on **every 2 s `FetchRequest` poll** —
  `handle_join_result_message` `x0xd.rs:17470` (awaited **inline** in the catch-up
  listener loop, so it also head-of-line-blocks that listener for up to the timeout)
- (plus the gossip metadata topic publish, `publish_named_group_metadata_event`)

Each is a ~41 KB **critical** DM over `pubsub.publish(member_inbox_topic, wire)` with a
**4 s per-attempt** budget (`dm.trace` `path_chosen … timeout_ms=4000`, `max_retries=1`).
Under the member's own join load these pile up — measured **19–28 large sends per 1 s
window** — serialize behind the per-peer single-in-flight send slot, and **~50 % exceed
the 4 s budget and time out**. Strictly **sequential** probes (any size) never contend
→ 100 % delivered. The redundant "deliver it 3 ways to be safe" design is *causing* the
contention it was meant to hedge against.

### Evidence index (live, 2026-06-04, all reverted after)
- Probe burst: SMALL 20/20, LARGE(41 KB) 20/20 during the failing window.
- Size ladder under load: 1 KB–47 KB all ~0.2–0.5 s.
- Anchor `dm.trace=debug`: every named-group DM to a member = `bytes≈41245`; of 14 distinct
  sends to the failing member, **7 ACKed, 7 never ACKed**; large sends bunched 19–28 per
  1 s window; `timeout_ms=4000`; `replaced_short_circuit=0`.
- Member `dm.trace`: 48/48 reaching `handle_payload` ACKed; the failing event never
  appears in `inbound_envelope_received`.
- Member `x0xd=debug`: 0 MemberAdded / welcome-fetch / apply.

## Secondary, independent defect (must also fix)

`handle_treekem_catchup_request` (`x0xd.rs:7452`) bundles events capped by **count**
(`TREEKEM_CATCHUP_RESPONSE_EVENT_CAP=32`), not bytes; with inline PQC blobs it serializes
to ~76 KB > `MAX_PAYLOAD_BYTES=49152` and is hard-rejected (`failed to send TreeKEM
catch-up response: payload exceeds MAX_PAYLOAD_BYTES (76554 > 49152)`). So the catch-up
*fallback* can never serve a multi-event delta. Fix: byte-budget the page + paginate on
`truncated` (which already exists).

## Fix direction (in progress)

x0x-side, `src/bin/x0xd.rs`:
1. **Stop self-contending.** Coalesce/dedupe redundant concurrent membership deliveries
   to a member into a single idempotent delivery; don't issue a new `Result` send while
   one is in-flight for that (group, member); make the inline `Result` send non-blocking.
2. **Relax the budget for critical membership sends.** A membership-specific send config
   with a generous per-attempt timeout + backed-off idempotent retry (4 s is far too tight
   for a ~41 KB critical DM to a just-joining, possibly cross-region member).
3. **Byte-budget the catch-up response** (secondary).

## Reusable facts
- DM delivery = `pubsub.publish(DmInboxService::inbox_topic_name(recipient), wire)`; the
  receiver ACKs at `dm_inbox.rs:353` after decrypt (or re-acks cached on dedupe `:221`).
- `direct_message_send_config()` (`x0xd.rs:2477`) = `DmSendConfig::default()`:
  gossip_inbox, `max_retries=1`, per-attempt ~4 s.
- `dm.trace` target: outbound stages (`path_chosen`/`wire_encoded`/`outbound_send_returned_ok`)
  are **DEBUG**; inbound stages (`inbound_*`) are **INFO**. Use `RUST_LOG=warn,dm.trace=debug`.
- Testnet repro: `python3 tests/e2e_treekem_membership.py --anchor sfo --member helsinki
  --member2 nuremberg --settle-secs 90`. Failure is intermittent across members.
- All instrumentation reverted; the 6-node testnet is clean (`RUST_LOG=warn`).
