> **✅ RESOLVED — commit `70b5f86` "fix(treekem): seed invite joiners with authority state".**
> Root cause = hypothesis **H-C / the E1 "ACKed-but-not-applied gap"**: the TreeKEM invite
> joiner stub did not carry the authority's base state frontier + roster, so the member's
> Welcome/MemberAdded **failed signed state-chain validation and was silently rejected
> before apply** (no log at `x0xd=debug`; needed the new `treekem.trace`). Fix: invites now
> carry `base_state_revision`/`base_state_hash`/`base_prev_state_hash`/`base_members_v2`;
> Welcome events with state gaps queue/catch-up instead of silently failing; catch-up
> responses paginate under the DM cap (= E7). e2e now 1/1, `converge_member_m2 ~3.38s`.
> Everything ruled out below (§4) held; the gap was the **silent crypto-validation reject**
> on the apply path — instrument *that* next time, not delivery. The Critical-gate overflow
> (E8) remains separately open. The rest of this doc is kept as the evidence record.

# TreeKEM member-convergence failure — SECOND-OPINION handoff

**Date:** 2026-06-04
**Purpose:** Independent review wanted. A member joins a TreeKEM group, reaches the
owner's roster, but **never enters the tree** (`converge_member_*` TIMEOUT). Multiple
diagnoses this session were each refuted by the next experiment, and a deployed fix did
**not** work. **Do not trust the conclusions below — read the EVIDENCE section and form
your own.** Hypotheses are labelled as such.

---

## 0. How to reproduce (≈3 min/run)

Testnet daemons (NOT prod): API `127.0.0.1:13600`, service `x0xd-testnet`, UDP 6483.
Build = x0x **0.21.0** + saorsa-gossip **84c53fb** (local `[patch.crates-io]` in
`Cargo.toml`) + an uncommitted dedupe change in `src/bin/x0xd.rs` (see §6, it does NOT fix
the bug).

```bash
# from x0x repo root
python3 tests/e2e_treekem_membership.py --anchor sfo --member helsinki \
    --member2 nuremberg --settle-secs 90
```

Result (every run): `converge_member_m2 = TIMEOUT (90s)` (occasionally fails at m1 instead —
**the failure is intermittent across members, not 2nd-member-specific**). Single-member
(`--member helsinki`, no `--member2`) PASSES.

What the failing assertion checks: `_poll_member_in_tree` calls the **member's own**
`POST /groups/{gid}/secure/encrypt` and requires `secure_plane=="treekem"` — i.e. the
member has actually loaded the TreeKEM group (Welcome received **and applied**). TIMEOUT =
the member never got there.

### Node map (testnet)
| role | node | IP | agent_id (DM identity) | machine_id |
|------|------|----|----|----|
| anchor/creator | sfo | 147.182.234.192 | `14bee4d5…e47fb6` | `a597…` |
| m1 | helsinki | 65.21.157.229 | `c860b686…27ad46` | `cf5de3de…` |
| m2 | nuremberg | 116.203.101.172 | `e620679b…dc6ac` | `7135…` |

(+ singapore 152.42.210.67 `816f…`, sydney 170.64.176.102 `4834…`, nyc.)
SSH `root@<ip>` (studio monitor key). Tokens in `tests/.vps-tokens-test.env`
(`TEST_<NODE>_TK`). All 6 nodes currently on the dedupe-fix 0.21.0 binary, `RUST_LOG=warn`.

### Instrumentation that works
- Outbound DM trace: `RUST_LOG=warn,dm.trace=debug` (stages `path_chosen`, `wire_encoded`
  [has `bytes`,`recipient`,`request_id`], `outbound_send_returned_ok` [= ACK received]).
- Inbound DM trace: `dm.trace=info` (stages `inbound_envelope_received`,
  `inbound_signature_verified`, `inbound_trust_evaluated`, `inbound_broadcast_published`).
- App-layer trace: `x0xd=debug` (join-result/catch-up/welcome/apply logs).
- Apply via systemd drop-in: `/etc/systemd/system/x0xd-testnet.service.d/zz-debuglog.conf`
  `[Service]\nEnvironment=RUST_LOG=...`, `daemon-reload`, `systemctl restart x0xd-testnet`.
  **Always revert after.** `journalctl -u x0xd-testnet --since "Nmin ago"`.

Probe a DM and time it (uses the SAME path as the real sends):
```bash
curl -s -w '%{http_code} %{time_total}' -H "Authorization: Bearer $TK" \
  -H 'Content-Type: application/json' -X POST http://127.0.0.1:13600/direct/send \
  -d '{"agent_id":"<recipient_agent_hex>","payload":"cHJvYmU="}'   # ok+path:gossip_inbox
```

---

## 1. EVIDENCE (raw, draw your own conclusions)

All on the live testnet this session. "probe" = a DM via `/direct/send`, which uses the
exact same `send_direct_with_config(..., direct_message_send_config())` as the real
membership sends.

**E1 — the member receives almost everything, applies nothing.** With `dm.trace=debug` on
the anchor: of the anchor's distinct sends to m2, **37/38 were ACKed** (`wire_encoded`
followed by `outbound_send_returned_ok`). With `x0xd=debug` on m2 during the same failure:
**0** `MemberAdded`, **0** apply, **0** `fetch_treekem_welcome`, **0** "ignoring …". m2's
only join-result log: `join-result fetch attempt failed: timed out after 1 retries over
12.00s` (m2's own outbound FetchRequest send) and finally `timed out polling anchor for
TreeKEM join result`.

**E2 — anchor→m2 DMs deliver 100% under the failing load, any size.** Interleaved burst
during the failing window: **SMALL(1 KB) 20/20, LARGE(41 KB) 20/20** delivered ~0.2–0.5 s.
Size ladder 1 KB–47 KB all ~0.2–0.5 s. (Exonerates payload size and the gossip transport.)

**E3 — m2→anchor DMs also deliver 100%, idle AND during the join.** 5/5 idle, 12/12 during
the join window (one 9.4 s blip, still ACKed).

**E4 — the receiver ACK pipeline is healthy.** With `dm.trace=info` on m2: every payload
that reached `handle_payload` (`dm_inbox.rs`) was decrypted and ACKed
(`inbound_trust_evaluated == inbound_broadcast_published`, 48/48). (Refutes
decrypt-failure / silent-reject as the cause.)

**E5 — no subscriber-queue eviction.** m2 logged `evicted oldest buffered event` = **0**,
`direct subscriber queue full` = **0** during a failure. (Refutes `subscribe_direct`
`push_drop_oldest` dropping the Result.)

**E6 — anchor staging is intermittent / inconsistent.** Anchor oscillates between
`DEBUG join-result fetch before result was staged group_id=… member=e620679b…` (lookup
found nothing) and `WARN failed to send join-result response: timed out after 1 retries
over 12s member=e620679b…` (lookup found a staged result, but the Result send timed out).
Both observed in different runs for the same member.

**E7 — the catch-up fallback hard-fails on size (separate defect).**
`WARN failed to send TreeKEM catch-up response: payload exceeds MAX_PAYLOAD_BYTES
(76554 > 49152)`. `handle_treekem_catchup_request` caps events by **count**
(`TREEKEM_CATCHUP_RESPONSE_EVENT_CAP=32`), not bytes. This blocks the anti-entropy
fallback but is **not** the primary blocker (the primary path is the push + poll).

**E8 — gossip Critical-lane flood exists but is irrelevant here.** Member nodes show
`X0X-0074d Critical gate overflow … op="EAGER"` to ghost/slow peers; the saorsa-gossip
84c53fb prune fix cuts it (1839/90s → ~8/30s fresh). E2/E3 prove DMs deliver under it, so
it does not explain convergence. (This **refutes** the 2026-06-03 "it's the gossip flood"
handoff.)

**E9 — single-member works; first-member usually converges fast** (`converge_member_m1`
0.2–3.3 s). The failure appears when a member must converge via the
push/poll/catch-up recovery rather than the immediate happy path.

---

## 2. The core unresolved contradiction

`send_direct_with_config(&recipient, payload, direct_message_send_config())`:
- As an external **probe** to the anchor or the member → **succeeds in ~0.2–0.5 s** (E2/E3),
  even during the join, even at 41–47 KB.
- As the real **FetchRequest** (m2→anchor) or **Result/MemberAdded** (anchor→m2) inside the
  join flow → **intermittently times out at 12 s**, and the member applies nothing.

Same function, same `DmSendConfig::default()` (gossip_inbox, `max_retries=1`,
RTT-derived per-attempt timeout), same recipients, both directions proven reachable. **The
distinguishing variable was not isolated.** Candidate differences not yet eliminated:
message *content* vs opaque probe bytes; the *handshake ordering* (stage vs poll vs
listener); state at the precise join instant.

---

## 3. Code map (by function — line numbers drift; `src/bin/x0xd.rs` unless noted)

Owner side (anchor), in the `MemberJoined` handler:
- stages the result: `stage_join_result(state, event_group_id=info.stable_group_id(), member, event)`
- pushes it: `spawn_named_group_event_delivery` (immediate) + `…_after`
  (`GROUP_BACKGROUND_PUBLISH_DELAY = 8 s`) + `publish_named_group_metadata_event` (gossip topic)
- serves polls: `handle_join_result_message` — `FetchRequest` arm looks up
  `pending_join_results[join_result_key(group_id, member)]`; `Result` arm →
  `apply_named_group_metadata_event`.
- `join_result_key(group_id, member)`; `stage_join_result`; `PENDING_JOIN_RESULT_TTL=10min`.

Joiner side (member):
- `poll_join_result_until_treekem_ready(state, group_id, event_group_id=info.stable_group_id(),
  inviter=creator, member)` — loops every `JOIN_RESULT_POLL_INTERVAL=2 s` until
  `treekem_groups.contains_key(group_id)` or `JOIN_RESULT_POLL_TIMEOUT=120 s`; each iter sends a
  `FetchRequest` to `inviter`. Logs `join-result fetch attempt failed: {e}` on send error.
- `apply_named_group_metadata_event(_inner)` `MemberAdded` arm: applies commit, then for an
  oversized Welcome calls `fetch_treekem_welcome(welcome_ref)` (chunked pull,
  `WELCOME_FETCH_TIMEOUT=90 s`) **while holding `group_membership_lock`**.
- Four independent `agent.subscribe_direct()` listeners (join-result / welcome-blob /
  catch-up; each processes inline).

DM plumbing:
- `src/dm.rs`: `MAX_PAYLOAD_BYTES=49152`, `MAX_ENVELOPE_BYTES=65536`,
  `direct_message_send_config()` = `DmSendConfig::default()` (gossip_inbox,
  `max_retries=1`, per-attempt timeout `dm_attempt_timeout(None)`=4 s floor but replaced by
  peer EWMA RTT — observed ~12 s). DM = `pubsub.publish(inbox_topic_name(recipient), wire)`.
- `src/dm_inbox.rs`: `handle_payload` → ACK `Accepted` after decrypt (or re-ack cached on
  dedupe). Silent no-ACK only on decrypt-fail / request_id-mismatch (E4 shows neither fires).
- `src/direct.rs`: `handle_incoming` fans each DM to per-subscriber queues via
  `push_drop_oldest` (evicts oldest on full — E5 shows it isn't firing); capacity
  `DIRECT_SUBSCRIBER_BUFFER`.

Catch-up size bug: `handle_treekem_catchup_request` (E7).

---

## 4. Ruled out (with the evidence that rules each out)
| Hypothesis | Status | Evidence |
|---|---|---|
| saorsa-gossip Critical-lane flood starves delivery | **refuted** | E2, E3, E8 |
| Payload size > limit / near-limit unreliable | **refuted** | E2 (47 KB delivers) |
| Receiver decrypt-fail / trust-reject / silent no-ACK | **refuted** | E4 |
| `subscribe_direct` queue eviction drops the Result | **refuted** | E5 |
| One-directional connectivity (m2→anchor or reverse broken) | **refuted** | E2, E3 |
| "2nd-member-specific" (owner roster clobber) | **refuted** | intermittent across m1/m2; 0.21.0 fixed the roster |
| Member consumer blocks on `fetch_treekem_welcome` | **refuted** | E1 (0 fetch — never reaches it) |

## 5. Open hypotheses (UNCONFIRMED — for the reviewer)
- **H-A (staging/lookup race or key skew):** anchor `stable_group_id()` (writer) vs the
  member's `event_group_id` in the FetchRequest (reader) intermittently disagree, or the
  result is staged *after* the member's polls (E6). Check: log the exact write-key in
  `stage_join_result` and the lookup-key in the `FetchRequest` arm in ONE run and diff.
- **H-B (content-specific send failure):** something about the real payload (typed
  JoinResultMessage / MemberAdded JSON) vs opaque probe bytes changes the send/ack outcome.
  Check: send the *exact* serialized FetchRequest bytes as a probe and see if it ACKs.
- **H-C (handshake liveness / ordering):** the push + poll + gossip-topic + catch-up
  interleave such that the member's apply never fires even when individual DMs land (e.g.
  the pushed raw `MemberAdded` has **no direct-DM listener** — verify which consumer, if
  any, applies a bare `NamedGroupMetadataEvent` delivered as a direct DM, vs only the
  gossip-topic subscriber and the `JoinResultMessage::Result` listener).
- **H-D (gossip metadata-topic delivery):** the member never receives the `MemberAdded`
  via the metadata topic either (0 apply). Is the just-joined member subscribed + in the
  anchor's eager mesh for that topic in time?

H-C is the one I'd start on: **trace exactly which receive path is supposed to drive the
member's `apply_named_group_metadata_event`, and confirm at runtime that the bytes the
anchor pushes/serves actually reach that path.** E1 says they do not (0 apply) despite
37/38 ACKs — so the gap is between "ACKed by `dm_inbox`" and "applied". Find that gap.

## 6. Fix attempt #1 (deployed, did NOT work — consider reverting)
Hypothesis was self-contention from redundant concurrent identical sends. Added
`AppState.membership_delivery_inflight: Arc<RwLock<HashSet<String>>>` + a
`deliver_membership_dm_once(agent, inflight, recipient, payload)` helper keyed by
`recipient:blake3(payload)` that admits one identical in-flight send per recipient; wired
into `spawn_named_group_event_delivery`, `…_after`, and the (now non-blocking) join-result
`Result` send. **Result: m2 still fails (6/6 runs).** Side effect: m1 converges more
consistently. The change is harmless but is **not the fix**; revert or keep as a minor
robustness tweak. (fmt+clippy clean, builds, deployed to all 6 testnet nodes.)

## 7. Recommended next step
One run with `x0xd=debug,dm.trace=debug` on **both** anchor and the failing member,
correlated by the **stage key** (not just DM request_id):
1. anchor: log the key written by `stage_join_result` and the key looked up in the
   `FetchRequest` arm → confirm/deny H-A.
2. anchor: for each `FetchRequest` from the member, log whether a Result was sent and its
   `wire_encoded` request_id + whether it ACKed.
3. member: log every `inbound_envelope_received` request_id AND every
   `apply_named_group_metadata_event` entry → find request_ids that arrived but never
   applied (the "ACKed but not applied" gap from E1).
Also resolve H-C (which listener applies a pushed `MemberAdded`). Separately, fix E7
(byte-budget the catch-up page; `truncated`+pagination already exist).

## 8. State / loose ends
- Testnet: all 6 nodes on the dedupe-fix 0.21.0 binary, `RUST_LOG=warn`, debug drop-ins
  removed, daemons fresh. No prod touched.
- Working tree: dedupe change uncommitted in `src/bin/x0xd.rs`; `Cargo.toml` has the
  temporary `[patch.crates-io]` → local saorsa-gossip (84c53fb); `audit.jsonl`/
  `autoresearch.jsonl` are autoresearch noise.
- Superseded: `handoff/treekem-2nd-member-is-gossip-critical-gate-2026-06-03.md` (flood
  thesis — refuted by E2/E8) and the "root-cause" claim in
  `handoff/treekem-member-welcome-delivery-rootcause-2026-06-04.md` (self-contention thesis
  — refuted; its fix did not work). This document is the current, honest state.
- Local test note: `cargo nextest --all-features` deadlocks on this Mac (dhat allocator
  from `profile-heap`); run without `--all-features`.
