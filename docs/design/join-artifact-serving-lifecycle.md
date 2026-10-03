# Join-artifact serving lifecycle

- **Status:** r4. A design note, not an ADR. r1 (`b1bb561`) was reviewed UNSOUND; r2 (`cfaeb0a`) SOUND-WITH-CORRECTIONS; r3 added the per-exchange deadline and D60. r4 records the round-5 implementation (section 8). Section 7 maps each review item to its correction.
- **Implements:** [ADR 0107](../adr/0107-stuck-join-rearm-and-serving-guard.md) (Accepted by David, D57; the header on this branch still reads Proposed). ADR 0107 is immutable; this note says how the code meets it.
- **Code baseline:** sections 2–5 describe `85bea26` (r3) plus `61533e0` (r4 WIP) on `fix/1150-stuck-join-rearm` (PR #1190, target v0.46.2). Section 8 records what round 5 (`37d9133`..`447670a`) changed.
- **Pinned dependencies:** saorsa-gossip-pubsub 0.5.86, ant-quic 0.27.54. Neither changes for v0.46.x. Section 2.7 specifies a send path that needs no change to either.

## 1. Terms

### 1.1 Byte classes

| Class | What | Governed by |
|---|---|---|
| **R, guarded recovery response** | Bytes the authority selects for one requester on a recovery fetch: the staged `JoinResult` (seat proof, chain, head attestation, roster certificates, intervening events), its control-blob copy (chunks), and the staged TreeKEM Welcome (chunks; key material). The class is defined by **role**, not content: the committed seat inside a `JoinResult` is also in the ordinary `MemberAdded`. | ADR 0107 serving guard (line 62): INV-R1 to INV-R7 |
| **K, commit-time key delivery** | GSS `SecureShareDelivered` envelopes: the current group secret sealed to one recipient's ML-KEM key (section 2.8). | Sealing and epoch only. Whether current eligibility also governs delivery is the open question in section 6 (G11). |
| **D, committed-membership dissemination** | Signed metadata events (`MemberAdded`, `MemberRemoved`, ...) on the group metadata topic, plus direct, delayed and redelivery pushes. TreeKEM `MemberAdded` carries the `WelcomeRef`, never Welcome bytes. | Existing signature, chain and apply rules. Gossip is allowed. Disseminating a committed fact after a later invalidation reveals only committed history. |
| **M, metadata frame** | Welcome `Offer`/`Complete`/`FetchRequest`/`ChunkAck`, control-blob `Reference`/`Fetch`/`Release`, staged join refusals. | Gossip is allowed; the existing binding, integrity and terminal-state checks stay. |

### 1.2 Transport terms

| Term | Meaning |
|---|---|
| Original | The staged entry in `pending_join_results` (key `group:member`) or `pending_welcomes` (content-addressed id). In memory only. Its 10-minute TTL runs from staging; a retry never restarts it. |
| Copy | A staged control-blob entry bound to its original by `StagedOrigin {staged_at, deadline}`, or the `PendingWelcome` clone a Welcome stream holds. |
| `L(g)` | Group `g`'s membership lock (`group_membership_lock_for_known_group`, lookup-gated). |
| Guard `G(g,r)` | `join_artifact_serving_refusal`: withdrawn, fork-quarantined, banned, agent revoked, Active seat, the roster-embedded certificate verified against the owner, the revocation set and the clock, and a Clean roster verdict (OwnerCertified only). |
| Physical exchange | One QUIC stream that carries one copy of the bytes. A **resend** is any further exchange of the same bytes, whether x0x or ant-quic starts it. |
| Observation | One read the admission makes. Each one is separate, with awaits between them: **O-binding** (pairing/placement: revocation set plus `move_state`), **O-gen** (connection generation), **O-rev** (agent revocation), **O-clock** (`restore_clock_now`, `Instant::now`), **O-roster** (`named_groups`), **O-evidence** (`owner_cert_evidence_for`, then the verdict), **O-staged** (the original and copy). An invalidation that lands after an observation is unseen by that exchange. |
| Handoff `H` | Per physical exchange: the interval from the last successful `write_all` return to `finish()`, with no await inside it. Before `finish()`, dropping the stream resets it (ant-quic 0.27.54 `SendStream::drop`, `high_level/send_stream.rs` around line 329). The receiver's `read_to_end` then fails (`p2p_endpoint.rs` around line 6489), so **no complete message** reaches its receive pipeline. Bytes already transmitted are not recalled. A successful `finish()` gives up cancellation. It proves **neither transmission nor reception**. |
| Egress registry `E(g,r)` | `AppState::join_artifact_egress`. A task body runs only after its handle is registered. `quiesce(g,r)` removes the handles, aborts them and awaits each one. |

### 1.3 The machine for class R

| ID | Invariant |
|---|---|
| INV-R1 | No class-R byte is handed to a path x0x cannot cancel before `H`: no gossip inbox and no relay. |
| INV-R2 | **Every physical exchange**, including every resend, is preceded by a complete set of observations taken after any earlier exchange of the same bytes, and all of them passed. |
| INV-R3 | Lock-ordered invalidations (removal, ban, withdrawal, deletion) linearize at `L(g)`. They quiesce before they commit, so each exchange either passed `finish()` before the commit or delivers no complete message. |
| INV-R4 | An invalidation with no lock (revocation, expiry, verdict change, quarantine, binding change, deadline) is honoured from its next observation onward. The exposure window runs from each observation to that exchange's `finish()`. No **fresh** exchange starts after an invalidation that the exchange's own observations could have seen. |
| INV-R5 | A copy never outlives its original: it shares the deadline, it is tied to the same `staged_at`, and it is purged with the original. |
| INV-R6 | No egress bookkeeping (registry handle, staging-guard map entry, Welcome stream handle, ACK slot) outlives its task, whether the task completes, is cancelled or panics. Cleanup is generation-safe: an old task never deletes its replacement's state. |
| INV-R7 | Fetch handling is admitted fairly: one group cannot exhaust handler or slot capacity that other groups share. |

## 2. Egress paths

### 2.1 Class-R transport at 61533e0 (shared by P1, P2c and P3 chunks)

`send_join_artifact` calls `Agent::send_direct_raw_admitted` with an 8 s receive ACK. That runs `send_direct_raw_quic`, then `send_ack_racing_replaced`, then ant-quic `Node::send_with_receive_ack`.

| Step | Where | Observations | Physical exchange |
|---|---|---|---|
| T1 Resolve and pair | `send_direct_raw_quic` | O-binding before and after resolution (async) | none |
| T2 Admission `A` | `send_direct_raw_quic` | Takes `L(g)`, then O-rev, O-clock, O-roster, O-evidence, O-staged, with awaits between them | none |
| T3 Exchange 1 | ant-quic `send_ack_exchange_once` (`FirstAttempt`, `p2p_endpoint.rs` around line 7439) | Inside ant-quic: O-gen and ACK-v2 support (around line 7714) | `open_bi` (around 7726), `write_all` (7744), `H`, `finish` (7754), then the ACK read; 8 s bound |
| T4 Exchange 2 | ant-quic retry after `AckTimeout` or `AckResponseIncomplete` (`Retry`, around line 7480); same request id; bound `min(8 s, 6 s)` | **None by x0x** | A full ACK-v2 exchange, **without admission** |
| T5 Exchanges 3–4 | x0x X0X-0053: a same-peer `Replaced` during T3/T4 abandons them, waits up to 250 ms grace, and calls `send_with_receive_ack` again (which can repeat T3 and T4) | **None by x0x** | Up to two more exchanges, **without admission** |

One call can make up to **four physical exchanges** and run for about 8 + 6 + 0.25 + 8 + 6 s. Only the first is admitted. T4 and T5 break INV-R2 (G3). The ACK-v2 requirement means a live direct connection to a peer without ACK-v2 support fails with `NotSupported`, and there is no fallback (G10).

### 2.2 P1: inline join result (payload ≤ `MAX_PAYLOAD_BYTES`)

| State | Entered when | Lock | Checks | Next |
|---|---|---|---|---|
| S0 Staged | `MemberJoined` apply seats the joiner and inserts the original (`created_at = t0`) | `L(g)` | none | S1 |
| S1 Selected | Join-result listener gets a `FetchRequest`. On the listener it runs `retry_pending_owner_cert_joins`, waits for `L(g)`, sweeps the TTL, reads the result and `t0`, and runs `G` | `L(g)` | `G`, TTL | S2. Refusal: an M-class reply. **Definitive refusal: purge.** |
| S2 Registered | `spawn_join_artifact_egress` registers the task in `E(g,r)` | none | none | S3 |
| S3 Pre-check | `join_result_still_servable` | `L(g)`, released after | `G`, original is `t0`, unexpired (return false; no purge) | Section 2.1, or done (withheld) |

Cancellation: `quiesce(g,r)` aborts the task in S2 or anywhere in section 2.1. An abort before `finish()` delivers no complete message.

### 2.3 P2: control-blob copy (payload > `MAX_PAYLOAD_BYTES`; verified, ref-capable, attempt-bound fetch)

| Sub-path | Sequence | Class | Cancelled by |
|---|---|---|---|
| P2a Staging | S1, then the per-`(g,r)` staging permit (an RAII `OwnedSemaphorePermit` held in a map entry; a duplicate is dropped). Then an `E(g,r)` task loops: under `L(g)`, if still servable at `t0`, `stage_with_origin(copy, {t0, t0 + TTL})`. If the budget is exhausted, sleep 2 s and retry, at most 6 times. | Local | `quiesce(g,r)`. An abort releases the permit, but the **idle map entry stays** until the next acquire (G9). |
| P2b Reference | `send_reference_message` with the existing gossip-preferred control config | M | Task abort (the DM layer may already have published to gossip) |
| P2c Per chunk | The control-blob listener checks the `Fetch` header (sender is the recipient, verified), takes one of 16 global chunk slots, and spawns an `E(g,r)` task. Under `L(g)`: copy staged before its deadline, original still `staged_at`, unexpired, `G` (return none; no purge); then it reads the chunk. Then section 2.1. | R | `quiesce(g,r)`, deadline, purge |

Copy lifecycle: the copy is pruned at the earlier of the original's deadline and its own TTL, and a refresh never extends the deadline. It is purged on removal, ban or a definitive refusal, dropped by `prune_groups` on withdrawal, and released by the recipient's `Release` after a verified pull.

### 2.4 P3: Welcome stream

| State | Entered when | Lock | Checks | Next |
|---|---|---|---|---|
| S0 Staged | Seal stages `pending_welcomes[id] = {g, joiner, bytes, t0}` | `L(g)` | none | S1 |
| S1 Dispatched | The Welcome listener decodes a `FetchRequest` and takes one of 16 global slots. A supervisor watches the **fetch handler** task. | none | **none before the slot (G6)** | S2 |
| S2 Handler | `handle_welcome_fetch_request_via`: lookup, TTL (if expired, remove it and stop the stream with abort and await), group and joiner binding, `G` (**definitive: purge**). Then `replace_welcome_stream` (abort and await the previous stream, clear its ACK slot) spawns the stream into `pending_welcome_streams`, **not** `E(g,r)`. Nothing supervises the stream task. | `L(g)` | `G`, TTL, binding | S3 |
| S3 Streaming | Every frame first runs `welcome_frame_servable` under `L(g)` (an error stops the stream; no purge). **Offer**: gossip-preferred DM (M, advisory). **Chunk k**: wait for the ACK window, then section 2.1 (R). Then the final-ACK wait, then **Complete** (gossip-preferred DM, M). | per frame | as S2 | done |

Cancellation: `stop_welcome_streams` (abort and await) runs from `quiesce(g,r)`, expiry and restaging. The withdrawal wipe aborts streams **without awaiting them** (G4). A finished stream's handle stays in `pending_welcome_streams` until it is replaced, stopped, expired or wiped. A panicking stream leaves its ACK slot behind (G9).

### 2.5 P4: fetch ingress

| Listener | Work on the listener | Work off the listener | Bound today |
|---|---|---|---|
| Join result | Parse, `retry_pending_owner_cert_joins`, **wait for `L(g)`**, selection, `G` | One `E(g,r)` task per request | None per `(g,r)` for inline results; 1 staging per `(g,r)` |
| Welcome | Decode | Handler (waits for `L(g)`) | 16 global slots, no validation first, no coalescing |
| Control blob | Header check | Chunk task (waits for `L(g)`) | 16 global chunk slots |

### 2.6 P5: queued retries and resends

| Retry | Runs in | Carries | Cancelled by | Fresh observations |
|---|---|---|---|---|
| Staging budget retry (≤ 6 × 2 s) | Authority `E(g,r)` task | Nothing until staged | `quiesce(g,r)` | Yes, every attempt under `L(g)` |
| **ant-quic ACK retry (T4)** | Inside `send_with_receive_ack_with_request_id` | **R bytes** | Task abort | **No (G3)** |
| **X0X-0053 reissue (T5)** | `send_ack_racing_replaced` | **R bytes** | Task abort | **No (G3)** |
| DM attempt retries (`send_direct_with_config`) | Caller task | M and K bytes | Task abort | No (not class R) |
| Joiner fetch retries (Welcome absolute schedule; join-result poll for 120 s on TreeKEM, the full TTL otherwise; re-arm) | Joiner | Requests (M) | Joiner timeout | The authority runs S1/S2 again |
| `retry_pending_owner_cert_joins` | Authority, on the join-result listener, per `FetchRequest` | Nothing (it may seat and stage) | none | Seal-path checks |
| GSS share DM now, and again at +8 s (`GROUP_BACKGROUND_PUBLISH_DELAY`) | Detached tasks | **K bytes** | **Nothing** (G11) | No |
| Gossip stranded retry (+8 s) and IWANT serve | saorsa-gossip 0.5.86, detached (`lib.rs` around line 9364) | Whatever was published (K, D, M) | Nothing x0x can reach | No |

### 2.7 P6: DM layer and the recommended class-R transport

| Entry point | Route | Resends | Used by at 61533e0 |
|---|---|---|---|
| `send_direct_with_config` | Signing gate, capability, raw QUIC first if connected, then the gossip inbox (sealed to the recipient's KEM key) with ACK retries, then relay (off by default; a third party reseals) | Many | M, K, D |
| `send_direct_raw_admitted` | Section 2.1 | Up to 3 without admission | R |
| ant-quic `Node::send_on_generation_with_admission` (public in 0.27.54, `node.rs` around line 734; x0x already uses it in `NetworkNode::send_to_peer_guarded`, `network.rs` around line 6072) | Uni stream on one pinned connection generation. A **synchronous** `admit(generation)` runs exactly once, after `open_uni` (and any stream-credit wait), immediately before `write_all`. Refusal writes nothing. The generation is checked before and after `admit`. | **None.** No reconnect, no constrained engine, no ACK, no retry. | Not used for R yet |

**Recommended class-R transport (fixes G2 and G3; no dependency change).** Replace the ACK-v2 path with `send_on_generation_with_admission`, in two phases.

1. **Async pre-phase (x0x):**
   - Resolve agent to machine to ant `PeerId`.
   - Check O-binding.
   - Capture the generation (`current_connection_generation`).
   - Run the existing `A` under `L(g)` and release it.
   - Snapshot the owner-certificate evidence.
   - This phase is advisory; it only avoids allocating a stream for a send that would be refused.
2. **Synchronous `admit` (authoritative):**
   - Re-run every observation without awaiting, using `try_read`/`try_lock`. **Contention refuses**: fail closed, and the application retries.
   - O-rev covers both agent **and resolved machine** (`revocation_set`).
   - O-binding: `key_move::enforce_pairing` over `revocation_set` and `move_state`.
   - O-roster: `join_artifact_serving_refusal_for` over `named_groups`, which also covers quarantine, withdrawal, ban and the Active seat.
   - O-clock.
   - O-evidence: re-evaluate the verdict over the pre-phase snapshot with the current clock.
   - O-staged: `pending_join_results`, `pending_welcomes`, `control_blobs`.
   - Then return the framed `[0x10][sender][payload]` bytes.
   - `admit` does **not** take `L(g)`. Lock-ordered invalidations are covered by quiesce: a task inside `open_uni` or `write_all` is aborted before the commit, and an unfinished stream resets.
3. **No transport resend.** Every further copy is an application-level retry (the joiner's fetch, a Welcome restream) that runs S1/S2 and both phases again, which satisfies INV-R2.
4. **Window (INV-R4):** for lock-free invalidations, the exposure runs from the synchronous observations to `finish()`: `write_all` only, which can stall on flow control. For O-evidence it starts at the pre-phase snapshot. ACK-v2 support is no longer needed.
5. **Liveness cost:** there is no transport-level receive ACK. Delivery confirmation comes from the application: Welcome `ChunkAck`, the control-blob `Release`, and the joiner's adoption ending its fetches. Recovery from a lost write relies on the joiner's existing retries, which must be shown under G10 and G13.
6. **Deadlines (r3).** Dropping the ACK-v2 exchange also drops its whole-exchange timeout. The uni API leaves `open_uni` (stream-credit wait) and `write_all` (flow control) unbounded, and nothing on the joiner side cancels an authority task. So there are two bounds:
   - **Per exchange:** each class-R exchange (resolution, any redial, the pre-phase, stream allocation, `write_all` and `finish`) runs under `timeout_at(min(now + JOIN_ARTIFACT_EXCHANGE_TIMEOUT, artifact deadline))`, with a 10 s bound. On timeout the future is dropped, so an unfinished stream resets (no complete message) and the exchange fails.
   - **Per task:** every class-R egress task runs under `timeout_at(artifact deadline)`. That covers the registry task, the Welcome stream (`created_at + PENDING_WELCOME_TTL`) and the chunk task (the copy's origin deadline). A stalled task therefore ends by the original's deadline at the latest, and its drop guards (G9) release the registry handle, staging slot, admission ticket, Welcome stream handle and ACK slot.
   - The deadline only cancels. It never purges: an original that is still valid stays staged for the joiner's next fetch.

**Fallback, only if a transport receive ACK turns out to be required for class R:** an ant-quic API change. Smallest shape: `Node::send_with_receive_ack_once_with_admission(peer, generation, request_id, timeout, admit: FnOnce(u64) -> Result<B, EndpointError>)`. It would run one ACK-v2 exchange with `admit` at the `open_bi` seam and no internal retry, so x0x owns every retry with fresh admission and reuses the request id for receiver dedupe. Today `send_ack_exchange_once` is private, and no public single-exchange ACK API exists.

### 2.8 P7 and P8: gossip, and class-K producers

**P7, gossip.** A publish to the per-recipient DM inbox topic or the group metadata topic is pushed eagerly to peers. If it is stranded, pubsub queues a self-IHAVE, spawns a detached retry after 8 s (`STRANDED_PUBLISH_RETRY_DELAY` = 2 × 4 s), and keeps the message in **this node's** cache for 60 s (`MAX_CACHE_AGE_SECS`) to serve IWANTs. Other peers cache and forward on their own clocks, so 60 s is not a global delivery or recall bound. After `publish()` returns, x0x cannot cancel any of this. Gossip cannot meet INV-R1 or INV-R3, even with a cancel API, because other peers' caches cannot be recalled.

**P8, class-K producers.** Each one is sealed to the recipient's KEM key. Each one goes out as a metadata-topic gossip publish, plus a detached DM now, plus a detached DM at +8 s. None is registered or admitted.

| Producer | Function | Recipients | Epoch |
|---|---|---|---|
| Joiner share after the durable seat (#794 Gap 2) | `MemberJoined` apply (around line 14140) | The joiner | Current |
| Approved joiner share | `approve_join_request` (around line 25452) | The approved joiner | Current |
| Survivor envelopes after admin removal | `remove_named_group_member` (around lines 19973 and 20093; buffered until after `MemberRemoved`) | Remaining active members | New (rotated) |
| Survivor envelopes after OwnerCertified eviction | `owner_certified_seal_with_eviction` (around lines 21912 and 21985) | Remaining members | New (rotated) |
| Survivor envelopes after ban | `ban_group_member` (around line 24304) | Remaining members | New (rotated) |
| Reseal envelope | `secure_group_reseal` (around line 27314) | Returned to the local API caller; not sent | Current |

Receive side: the `SecureShareDelivered` arm (around line 13176) installs a share addressed to the local agent. It does **not** check the recipient's own current eligibility.

Only removal, ban and OwnerCertified eviction rotate the secret. Agent or machine revocation, certificate expiry, a verdict change and fork quarantine leave the epoch unchanged. A share that is in flight, delayed or cached when one of those lands therefore delivers the **current** secret to a now-ineligible recipient. That is the policy question in section 6.

## 3. Invalidations and linearization points

### 3.1 Where refusals purge and where they only return false

| Site | On | Action |
|---|---|---|
| S1 fetch selection (P1/P2) | Definitive refusal | `purge_member_join_artifacts` |
| S2 Welcome handler (P3) | Definitive refusal | `purge_member_join_artifacts` |
| Mutation sites (I1, I2) | After commit, if still ineligible | `purge_join_artifacts_if_ineligible`, inside `L(g)` |
| Withdrawal and deletion wipe (I6, I7a) | Always | Wipe every artifact of the group |
| S3 pre-check, Welcome frame check, chunk read, `A` | Any refusal | Return false or an error. **No purge**: originals stay until a purge site or the TTL. |

Definitive refusals: withdrawn, banned, not Active, agent revoked, certificate invalid. Withholding refusals: quarantined, unknown group, `DigestPending`, `InGrace`, verdict `Failed`, certificate missing.

### 3.2 Invalidation table

"In flight" describes 61533e0. "Rec." is the recommended design in section 2.7.

| Invalidation | Lands via | Observed at | Staged originals | In flight (61533e0) | Rec. | Gap |
|---|---|---|---|---|---|---|
| I1 Member removal (`remove_named_group_member`, TreeKEM remove, OwnerCertified seal eviction, replayed `MemberRemoved` apply) | `L(g)`: `quiesce(g,r)` **before** commit, then commit, then purge-if-ineligible **inside** the same critical section | All checks after the commit return `NotActive` | Purged | Aborted and awaited; an unfinished stream resets. Past `finish()`: committed before the removal (not proof of delivery). | Same | none for R; K: G11 |
| I2 Ban (`ban_group_member`, `ban_treekem_group_member`, replayed apply) | As I1, plus GSS rotation | As I1 | Purged | As I1 | Same | As I1 |
| I3 Agent revocation | Revocation-set update; no group event, no lock | O-rev at S1/S2, S3, every frame, `A` | Kept until the next S1/S2 hit (definitive, so purged then) | Window from O-rev to `finish()` of exchange 1; **exchanges 2–4 are not observed** | Window from the `admit` O-rev to `finish()`; no resend | G1 (accept), G3 |
| I3b Machine revocation | Revocation-set update | **Not observed by `G` or `A`**; O-binding (`enforce_pairing`) reads the revocation set at T1 only | Kept | Not refused after T1 | `admit` checks the resolved machine | G2 |
| I4 Certificate expiry | Time | O-clock at every check | Purged at the next S1/S2 (definitive) | As I3 | As I3 | G1, G3 |
| I5 Verdict change (`DigestPending`, `InGrace`, `Failed`; OwnerCertified) | Evidence or time | O-evidence and O-clock at every check | Withheld, not purged | As I3; the window starts at the O-evidence read | `admit` re-evaluates the verdict over the pre-phase evidence snapshot; the window starts at that snapshot | G1, G3 |
| I6 Group withdrawal (withdraw route; sole-member leave) | `L(g)` held by `withdraw_named_group_terminal`. Then `retain_withdrawn_group_tombstone`: persist the tombstone (`G` returns `GroupWithdrawn` from here), then wipe originals, Welcome receives, streams and blob copies. | O-roster after the persist | Wiped | **Not quiesced.** A task that read O-roster before the persist writes; Welcome streams are aborted without await. | `quiesce(g,*)` with awaits before the persist | G4 |
| I7a Deletion (`GroupDeleted` metadata apply) | `L(g)` held by the apply, then the same tombstone path | As I6 | Wiped | As I6 | As I6 | G4 |
| I7b Local leave of a TreeKEM group (`leave_treekem_group`, `drop_local_named_group_state`) | Group dropped under the persistence lock; no quiesce, no purge | O-roster returns `UnknownGroup` (withhold); the lock lookup fails | **Not purged**; they expire at the TTL | **A task already past its last observation is neither quiesced nor reset, and it writes.** Later checks refuse. A re-join within the TTL could re-expose stale originals. | Quiesce and purge on local drop and active leave | G5 |
| I8 Artifact deadline (10 min from staging) | Time | O-clock / O-staged at S1 (TTL sweep), S3, every frame, chunk read (copy deadline = original deadline), `A`. An expired Welcome at S2 is removed and its stream stopped (abort and await). | Expired | As I3 | As I3 | G1, G3 |
| I9 Fork quarantine | `install_fork_evidence` persists a marker under the roster persistence lock, not `L(g)` | O-roster (`is_fork_quarantined`) at every check | Withheld, not purged | As I3 | `admit` re-reads the roster | G1, G3 |
| I10 Recipient binding retired or placement changed (ADR-0043 B/P) | `move_state` and revocation-set updates; no lock | O-binding at T1 only (pre- and post-resolution `recipient_pairing_denied`) | Unaffected | Not re-observed after T1; the resends reuse the connection | `admit` runs `enforce_pairing` synchronously; the generation pin refuses a replaced connection | G2, G3 |

Class K is not governed by any of these rows today (section 2.8, G11).

## 4. Fault matrix

Evidence labels: **Test** means a named in-process test passes. **Inspection** means source reading only. In-process tests use a `cfg(test)` stand-in transport and park before admission, so they never exercise the production lock-wait, write or ACK steps (G13).

| Fault point | Expected outcome (the machine) | 61533e0 | Evidence |
|---|---|---|---|
| F1a Abort before `A` (parked, or at redial) | Nothing written; the quiescer's await returns | Meets | Inspection. Test covers the stand-in only: `s8a_r2_ban_racing_{inline_join_result,join_result_chunk,welcome_frame}_egress_sends_nothing` |
| F1b Abort while `A` waits for `L(g)` | Nothing written; the abort lands at the lock wait | Meets | Inspection |
| F1c Abort after `A`, during `open_bi`/`write_all` (ACK-v2 bidi path) | Stream reset; **no complete message** reaches the receive pipeline (bytes already sent are not recalled) | Meets | Inspection (`send_stream.rs` around line 329, `p2p_endpoint.rs` around line 6489) |
| F1d Abort after `finish()`, during the ACK wait | Cancellation already given up; the message may or may not be delivered; quiesce returns | Meets (local FIN only, not delivery) | Inspection |
| F1e Resend: ant-quic ACK retry after `AckTimeout`/`AckResponseIncomplete`, or X0X-0053 reissue after `Replaced` | Every resend only after fresh observations | **Violates** (G3): up to 3 resends without admission | Inspection |
| F1f Withdrawal wipe aborts a Welcome stream | The wipe awaits the abort before it returns | **Violates** (G4) | Inspection |
| F1g Staging task aborted | Permit and map entry both released at the abort | **Partial** (G9): the RAII permit is released; the idle map entry stays | Test: `s8a_r4_aborted_staging_releases_its_staging_guard` (ignored) |
| F2a Authority restarts with staged artifacts | All originals, copies, tasks and guards are gone (in memory). The joiner's fetch finds nothing and ends `TimedOut`/`Refused`. Operator exit: owner remove-member + re-invite (ADR 0107 line 74). | Meets | Test: `s8a_1150_lost_staging_never_claims_recovery` |
| F2b Authority exits mid-exchange | Before `finish()`: the connection closes and no complete message is delivered. After it: local FIN only, delivery unknown. | Meets | Inspection |
| F2c Joiner restarts | TreeKEM identity re-derived; re-arm fetches the original | Meets | Test: `s8a_1150_rearm_recovers_after_joiner_restart_without_stored_secrets` |
| F2d Bytes published to gossip before a restart | Each peer's cache keeps them on its own clock (60 s locally, not a global bound). No class R is published (INV-R1); class K is (G11). | Partial (G11) | Inspection |
| F3 Re-admission concurrent with a purge | The purge runs inside the removal's `L(g)` section and re-checks eligibility. A re-admission takes `L(g)` afterwards and stages fresh artifacts, which are never erased. | Meets | Test: `s8a_r2_removal_purge_cannot_erase_a_concurrent_readmission`, `s8a_r2_replayed_member_removal_purges_staged_artifacts` |
| F4a Duplicate Welcome `FetchRequest` flood for one locked group | Provisionally validated without the lock, coalesced per `welcome_id`, capped per group; other groups still admitted; authoritative checks still under `L(g)` | **Violates** (G6) | Test: `s8a_r4_welcome_fetch_admission_is_fair_across_groups` (ignored) |
| F4b Welcome listener under that flood | The listener keeps draining | Meets | Test: `s8a_r2_welcome_listener_progresses_while_a_group_lock_is_held` |
| F4c Join-result `FetchRequest` flood for one locked group | The listener never waits for `L(g)` or for `retry_pending_owner_cert_joins`; inline egress coalesced per `(g,r)` | **Violates** (G7) | Inspection |
| F4d Control-blob chunk `Fetch` flood for one locked group | Validated (staged reference exists, binding, sequence in range); per-group fairness | **Violates** (G8) | Inspection |
| F5a Raw write stalls (flow control, redial) | Holds no lock; quiesce aborts it and the stream resets | Meets | Inspection |
| F5b ACK wait stalls | Holds no lock; quiesce aborts it. One `send_with_receive_ack` call lasts up to 8 + 6 s; a `Replaced` reissue adds up to 0.25 + 8 + 6 s | Meets for cancellation; resends violate (F1e) | Inspection |
| F5c Welcome ACK window stalls | The stream waits without a lock; quiesce aborts it | Meets | Inspection |
| F5d M-class frame on the gossip-preferred DM | May arrive after an invalidation; no key material | Accepted (G12) | Inspection |
| F5e No usable direct exchange: NAT traversal fails, **or the peer lacks ACK-v2** (`NotSupported`) | The artifact is not delivered. The joiner retries until its attempt ends (**120 s on TreeKEM**; the full TTL otherwise), while the authority keeps the original for 10 minutes for a re-arm. | Liveness risk (G10). ACK-v2 incompatibility is a mixed-version risk that the recommended uni path removes. | Needs e2e and mixed-version evidence |
| F6 Panic in an egress task, fetch handler or Welcome stream | All bookkeeping released, generation-safely | **Partial** (G9): the fetch-handler supervisor logs; nothing supervises the stream; a panicking stream leaves its ACK slot and handle; the staging map entry stays | Inspection |
| F7 Egress task or Welcome stream finishes | Its registry handle and stream handle leave at completion | **Violates** (G9): registry handles are pruned only when the next egress spawns; finished stream handles stay until replaced, stopped, expired or wiped | Test: `s8a_r4_finished_egress_tasks_leave_the_registry` (ignored); stream handles: inspection |

## 5. Gaps and rulings

Rulings follow the r1 review. "Code fix within 0107" means the fix is compatible with ADR 0107; it does not mean ADR 0107 expressly mandates every invariant here. No recommended fix needs a superseding ADR. Weakening 0107's eligibility checks, or allowing a fresh class-R exchange after an observable invalidation, would need one.

| ID | Gap | Ruling | Fix |
|---|---|---|---|
| G1 | The exposure window for lock-free invalidations runs from each observation to `finish()`. ADR 0107 orders eligibility checking and artifact selection under `L(g)`; it does not require a global revocation-to-FIN lock. | **Accept** | Describe it honestly (section 3.2). With section 2.7 the window shrinks to `write_all`, and to the evidence snapshot for verdicts. Margins or a revocation epoch remain optional engineering choices. |
| G2 | Machine revocation and binding changes are not observed by `G` or `A`, and not on resends. | Code fix within 0107 | Section 2.7 `admit`: revocation of agent and resolved machine, plus `enforce_pairing`, on every exchange. |
| G3 | Resends without admission: the ant-quic ACK retry (T4) and the X0X-0053 reissue (T5). | Code fix within 0107 | Section 2.7: `send_on_generation_with_admission`, one exchange, no transport resend, x0x owns every retry. **No dependency change.** Only if a transport receive ACK is required: the ant-quic single-exchange admitted ACK API in section 2.7. |
| G4 | Withdrawal and deletion do not quiesce the group; the wipe does not await its aborts. | Code fix within 0107 | `quiesce_group_join_egress(g)` over every alias: all `E(g,*)` tasks and all of `g`'s Welcome streams, aborted and awaited before the tombstone persist (under `L(g)`). |
| G5 | Local drop and active leave neither quiesce nor purge. | Code fix within 0107 | Collect the aliases before deletion; quiesce and purge on both the local-drop and active-leave paths. |
| G6 | Welcome fetch admission is not fair. | Code fix within 0107 | Provisional validation without the lock (`pending_welcomes` has the id, the same group, and joiner == sender), coalescing per `welcome_id`, per-group (2) and global (16) caps, an RAII ticket and a handler timeout. The authoritative checks stay under `L(g)`. |
| G7 | The join-result listener waits for `L(g)` and runs `retry_pending_owner_cert_joins` inline; inline egress is not coalesced. | Code fix within 0107 | Move selection **and** the owner-certificate retry off the listener, under the same fair admission as G6, and coalesce per `(g,r)`. |
| G8 | Control-blob chunk slots are global and not validated. | Code fix within 0107 | Before taking a slot, validate that the staged reference exists, its binding, and the sequence range; add a per-group sub-cap. |
| G9 | Bookkeeping residue: the idle staging-map entry; registry handles not pruned at completion; finished Welcome stream handles; a panicking stream's ACK slot; no stream supervisor. | Code fix within 0107 | A guard that removes the map entry on drop; self-removal by task id for registry and stream handles; ACK-slot removal by `Arc::ptr_eq` from a drop guard; a stream supervisor. All cleanup is generation-safe. |
| G10 | Class R has no gossip fallback. NAT failure, or no ACK-v2 at 61533e0, means no delivery; the TreeKEM attempt ends at 120 s. Without a transport ACK, a stalled exchange is bounded only by the deadlines in section 2.7 (item 6). | **Accept, conditional on evidence** | Raw-only is within 0107's transport freedom. Show eligible-join non-regression in the e2e Home suite and mixed-version runs (section 2.7 removes the ACK-v2 dependency). The per-exchange and per-task deadlines must cancel, reset and release without purging. If eligible joins regress, the question for David is release scope or postponement, not waiving the guard. |
| G11 | Class K delivery: three paths per share, unregistered, unadmitted, gossip-capable; the receive arm does not check eligibility; non-rotating invalidations deliver the current secret. | **Code fix per D60** (section 6) | An **epoch-bound share admission**: the recipient is eligible on the current roster (`G`), and the share's epoch is the group's current secret epoch with its secret still held. It runs on every delivery and every resend, through the section 2.7 single-admission transport, in a registered task. There is no gossip publish of sealed shares. A definitive refusal or an epoch change ends the delivery (purge). A withholding refusal (quarantine, a non-Clean verdict, a missing certificate, a revoked or denied machine binding, contention) skips that attempt and keeps the share pending until its horizon. Reusing the `JoinResult` admission would wrongly reject survivor and approval deliveries. |
| G12 | M-class frames use gossip and can arrive after an invalidation. | **Accept** | Keep the existing binding, integrity and terminal-state checks. |
| G13 | No real-transport evidence: the placement of `admit`, resends, cancellation, stalls, deadline expiry and invalidations are covered by inspection only. | Code fix within 0107 | A loopback two-agent suite under `scripts/dev/test-isolated.py` (Linux netns) in CI, covering each fault-matrix row marked Inspection, including a stalled `open_uni`/`write_all` cut by the exchange deadline. |
| G14 | The class-R send path skips the DM metrics. | Code fix within 0107 | Add `record_outgoing_*`. Decide the phi "likely offline" short-circuit from recovery behaviour, not by default, because stale suspicion can suppress the recovery probe. |

## 6. Decisions

**D60 (David, 2026-10-03), decided.** The refined question was:

> "For class-K GSS envelopes still under x0x's control, is entitlement fixed at the committing epoch, or must every delivery/resend require current recipient eligibility and the current secret epoch — including after agent/machine revocation, certificate expiry, verdict change or quarantine?"

Ruling: **current eligibility is required.** Every delivery and every resend of a class-K envelope still under x0x's control needs the recipient's current eligibility and the current secret epoch. That holds after agent or machine revocation, certificate expiry, a verdict change or quarantine. Entitlement is not fixed at the committing epoch. G11 is implemented as described in section 5, for every producer in section 2.8. The reseal envelope is returned to the local API caller and never leaves the process, so it is unchanged.

## 7. Revision history

| Review item (Codex, `b1bb561`) | Change in r2 |
|---|---|
| P1: ant-quic internal ACK retry | Section 2.1 (T4), section 2.6, F1e, G3 widened to every resend. Section 2.7: x0x-owned single-exchange path on the public `send_on_generation_with_admission`, plus the fallback ant-quic API shape. |
| P2: handoff definition | Section 1.2 `H` per physical exchange; ACK-v2 `open_bi` path; `finish()` gives up cancellation and proves no delivery; a reset prevents a complete message and recalls nothing. |
| P2: G1 observation window | Section 1.2 observations; section 3.2 "Observed at"; G1 ruled accept; D-a dropped. |
| P2: missing invalidations | I9 fork quarantine, I10 binding/placement; I7b post-admission exposure; section 3.1 purge versus return-false. |
| P2: P8/G11 coverage | Section 2.8 lists every class-K producer, the receive arm and the non-rotating invalidations; epoch-bound share admission; one David question. |
| P2: classification | Section 1.1 classes R/K/D/M, each with its own rules. |
| P2: G9 scope | Staging permit already RAII; map entry, stream handles, ACK slots and stream supervision added; generation-safe cleanup. |
| P2: G10/F5e | ACK-v2 incompatibility, the 120 s TreeKEM attempt, conditional accept; D-b dropped. |
| P3: evidence and phi | Fault matrix splits Test from Inspection; G14 no longer recommends the phi short-circuit by default. |
| Fault-matrix corrections | F1a/b, F1c, F1d/F2b, F1e, F2d, F5b, F5e, F6/F7 as listed in the review. |
| r2 re-check (Codex, `cfaeb0a`): no whole-exchange timeout on the uni path | Section 2.7 item 6: per-exchange and per-task deadlines that cancel, reset and release without purging; G10 and G13 updated. Contention at the seam is a retryable withhold, never a purge. |
| D60 | Section 6 records the ruling; G11 becomes a code fix with an epoch-bound share admission. |

## 8. Implementation status (round 5)

Each gap below was fixed red-then-green: the test commit is red on its parent, the fix commit turns it green. Unless noted, the evidence is the named in-process tests in `src/server/routes/named_groups/tests/adr0107_stuck_join_rearm.rs`, run in debug and in release.

| Gap | Status | Red, then fix | Evidence |
|---|---|---|---|
| G2 | Fixed: the seam checks agent and resolved-machine revocation and `enforce_pairing` on every exchange | `37d9133`, `ffb8536` | `s8a_r5_g2_machine_revocation_before_admission_sends_nothing`; real path `s8a_r5_g13_real_machine_revocation_before_the_seam_writes_nothing` (CI only) |
| G3 | Fixed: class R and class K use `Agent::send_direct_pinned_admitted` (section 2.7) — one exchange, admitted at the seam, no resend; no dependency change | `37d9133`, `ffb8536` | `s8a_r5_g3_recovery_responses_take_one_admitted_exchange`; real path `s8a_r5_g13_real_pinned_exchange_is_admitted_once_and_delivered_once`, `s8a_r5_g13_real_refusals_write_nothing` (CI only) |
| Deadline (section 2.7 item 6) | Fixed: per-exchange `min(now + 10 s, artifact deadline)`; per-task artifact deadline (registry task, chunk task, Welcome stream) | `37d9133`, `ffb8536` | `s8a_r5_deadline_cuts_stalled_exchanges`; real path `s8a_r5_g13_real_deadline_cuts_a_stalled_exchange` (CI only; the stall is in the pre-phase — a stalled `write_all` is not reproducible on loopback) |
| G14 | Fixed: DM metrics recorded; no phi short-circuit, because these sends answer the recipient's own fetch | `37d9133`, `ffb8536` | `s8a_r5_g14_recovery_response_sends_record_dm_metrics` |
| G9 | Fixed: RAII staging slot; registry handles removed by task id; Welcome streams supervised (`catch_unwind`) and removed by task id; ACK slot released by `Arc::ptr_eq` drop guard | `aca4880`, `b8bf183` | `s8a_r4_aborted_staging_releases_its_staging_guard`, `s8a_r4_finished_egress_tasks_leave_the_registry` (un-ignored), `s8a_r5_g9_finished_welcome_stream_leaves_its_handle`, `s8a_r5_g9_panicking_welcome_stream_releases_its_bookkeeping` |
| G4 | Fixed: `quiesce_group_join_egress` (every alias, every recipient, every Welcome stream; awaited) before the tombstone persist; the wipe awaits its aborts | `68e4719`, `3aba7e3` | `s8a_r5_g4_withdrawal_quiesces_all_group_egress_before_its_commit` (the `GroupDeleted` apply shares the code path; inspection) |
| G5 | Fixed: `retire_local_group_join_artifacts` (quiesce, then purge) on the local drop, the active TreeKEM leave, the GSS leave and the removed-self apply | `3712cf2`, `fdb5ac0` | `s8a_r5_g5_local_drop_quiesces_and_purges_the_groups_join_artifacts`; the other three call sites share the helper (inspection) |
| G6 | Fixed: provisional validation without the lock, `FairAdmission` (per Welcome; 2 per group; 16 global), RAII ticket, 10 s handler bound | `c173709`, `f2a27ae` | `s8a_r4_welcome_fetch_admission_is_fair_across_groups` (un-ignored), `fair_admission::tests::duplicates_coalesce_and_groups_share_fairly` |
| G7 | Fixed: `dispatch_join_result_message` handles a `FetchRequest` (and the owner-certificate retry) off the listener: one handler per `(group, member)`; 4 per group; 32 global; 20 s bound | `f79ec5a`, `34eafc0` | `s8a_r5_g7_join_result_listener_never_waits_on_a_group_lock` |
| G8 | Fixed: a chunk fetch must name a staged, bound copy and an existing sequence before it takes capacity; one task per chunk; 4 per group; 16 global | `b7710d2`, `fd7d8b2` | `s8a_r5_g8_chunk_fetch_admission_is_validated_and_fair` |
| G11 (D60) | Fixed: every class-K share (joiner share, approval, ban, removal and eviction survivors) goes through a registered, epoch-bound, single-admission delivery. There is no gossip publish. Withheld shares re-check every 15 s until a 10-minute horizon; definitive refusals and epoch moves purge; transport failures back off from 8 s to 120 s. The reseal envelope stays local. | `98f7e3d`, `9210ec3` | `s8a_r5_g11_{agent_revocation_withholds_nothing_and_purges_the_share, machine_revocation_withholds_the_share, certificate_expiry_purges_the_share, verdict_change_withholds_the_share, quarantine_withholds_the_share, share_resend_is_admitted_afresh}` |
| G13 | Added: four real loopback QUIC tests | `447670a` | CI only (isolated namespace); compiled and clippy-clean locally |
| G1, G12 | Accepted (section 5) | — | — |
| G10 | Accept, conditional on evidence | — | Needs e2e Home and mixed-version runs. Class K is now raw-only too: an unreachable recipient retries until the horizon. |

### Round 6 (Codex review of `a8acd0d`: changes required, narrow)

The review found the call-site audit clean: every class-R and class-K write converges on the single-exchange seam, and no gossip or general-DM path is left. It also confirmed that agent/machine revocation and pairing are checked at the seam, and that G4/G5 quiesce, the G6/G8 caps, G9 cleanup, the deadline calculation and panics are correct. On mixed versions, v0.46.0 already accepts `[0x10][sender][payload]` and `SecureShareDelivered` through its direct metadata listener, so there is no decoder break and no new ADR.

| Item | Status | Red, then fix | Evidence |
|---|---|---|---|
| P1: the seam took the verdict at the pre-phase snapshot's clock | Fixed: `OwnerCertEvidence::at_time`; the seam re-takes the snapshot's verdict at its own clock (the same clock as the embedded-certificate check), for class R and class K | `01eab83`, `c0c4a5c` | `s8a_r6_verdict_expiry_between_pre_phase_and_seam_is_refused` (a test-only skew of the seam's clock; the announced certificate expires past its 300 s tolerance while the embedded one stays valid) |
| P2: the chunk seam took the staging registry's blocking lock and pruned | Fixed: `ControlBlobState::try_staged_origin` (`try_lock`, no pruning, explicit TTL and deadline checks); contention is a retryable withhold | `8eeeec0`, `21d7fa3` | `s8a_r6_seam_staged_copy_check_never_blocks` |
| P3: inline egress outlived its G7 handler ticket, so duplicate fetches overlapped | Fixed: `join_result_egress_admission` (one per (stable group, recipient), 8 per group, 64 global); the ticket lives in the egress task | `388a42f`, `a2d7d68` | `s8a_r6_duplicate_fetches_never_overlap_inline_egress` (6 duplicate fetches against a stalled egress leave 1 in flight) |
| P4: withholding masked terminal share invalidations | Fixed: the serving guard decides every definitive refusal before quarantine or pending evidence (class R and K); the share verdict checks the epoch first | `96d103c`, `d12a42e` | `s8a_r6_terminal_share_invalidations_outrank_withholding` (quarantine plus agent revocation, and quarantine plus a moved epoch: both purged) |

Still outstanding for merge: the G10 evidence (e2e Home joins, survivor rekeys, mixed-version delivery on raw-only), from Root's ephemeral-testnet gate.

Remaining notes:
- **Retry classification.** Certificate expiry is classified as definitive and purges, consistent with the existing serving guard. A later certificate renewal does not re-send a purged share; the next rotation does.
- **Joiner side.** A `Result` arm handled on the joiner's listener still waits inline for the joiner's own group lock. That is outside these gaps.
- **Shared fault cell.** The in-process local-delete tests (`r9_local_delete_completes_without_deadlock`, `r10_delete_fault_matrix_through_production_path`) share a global delete-fault cell, so they must run in separate processes (as nextest does). This predates round 5.
