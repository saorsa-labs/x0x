# ADR 0089: Relationship-Peer Evidence Survives Restart (Evidence Rule, Slice 1)

- **Status:** Accepted
- **Accepted:** 2026-09-30 by David Irvine (as written; relayed by Root, who verified the r4 diff at 6571d6c). The status change was applied by Claude (x0x-32) at his instruction.
- **Date:** 2026-09-30
- **Decision owners:** David Irvine (decision; charter D29), Claude x0x-32 (drafting)
- **Reviewers:** Codex or OMP (cross-model review); David Irvine (acceptance, required before any code merges)
- **Supersedes:** none. It replaces the #1092 reconnect re-announce stopgap (D31) once implemented.
- **Superseded by:** none
- **Amends:** [ADR 0021](./0021-dm-origin-machine-attestation.md) (Accepted, not edited):
  - It rejected option 2, "a persistent binding cache", because it "adds disk state to a security boundary".
  - This ADR adopts a persistent binding store **for relationship peers only**, as an *addition* to stateless origin attestation, which stays as it is.
  - ADR 0021's rule that origin authentication "MUST work with zero prior discovery-cache state" still holds.
- **Also:**
  - **Amends [ADR 0093](./0093-capability-advert-registry.md)'s allocation procedure** (0093 is Accepted and not edited, since Accepted files are immutable and CI enforces that). 0093 says "Allocate a bit by a reviewed ADR updating this table". From this ADR on, **the canonical allocation table is the "ADR 0093 capability registry" table in `docs/adr/README.md`**: bits 0 and 1 as in 0093, and bits added by later ADRs. This ADR adds bit 2, `peer_evidence_v1`, effective when 0089 is Accepted, plus the code constant. No other part of 0093 changes.
  - The persisted file follows [ADR 0085](./0085-persisted-binary-formats-are-versioned.md).
- **Vision requirement and goals:**
  - **R3** (all my machines connected);
  - **R5 / R6** (sharing and collaboration survive a restart);
  - goals **F** (it works) and **E** (measured efficiency).
- **Related:** #1040, #1088, #1089, #1091, #1092, #843, #891, #1055, #1064; charter D29, D30, D31, D33–D35, E-D10; `.planning/design-health-check-2026-09-30.md` §2 R1; `omp-reports/testnet-runs/g46r2/finding3-mechanism.md`; `omp-reports/1088-root-review.md`; `omp-reports/1091-root-review.md`.
- **Scope note:** this is slice 1 of the W3 evidence rule (D17). `Authority::decide`, persisted consent and certificate-in-band admission come later, as a separate ADR that extends this one.

## Context

A restarted daemon forgets everything it knew about the peers it works with. Each piece of that knowledge lives only in memory:

| State | Where (origin/main) | Lifetime |
|---|---|---|
| agent → machine binding (authenticated) | `AuthenticatedMachineBindings`, `src/dm_inbox.rs:145`, 65,536-entry LRU | process only |
| discovery entry (addresses, agent key, `AgentCertificate`) | discovery cache, `src/lib.rs:2040` | 900 s TTL, process only |
| recipient ML-KEM key for DM sealing | `CapabilityStore`, `src/dm_capability.rs:295` (`DmCapabilities.kem_public_key`) | 900 s TTL, process only |
| verified identity announcement | re-broadcast every 600 s on `x0x.identity.announce.v2` | next heartbeat |

Nothing rebuilds them after a restart:
- `announce-blob-cache.bin` persists certificates only, keyed by digest, with no machine and no KEM key.
- `contacts.json` holds unauthenticated machine records.

The only recovery clock is the peer's next 600 s announcement. Each security tightening, while correct on its own, has turned that gap into an outage:

- **#1088 / #1089, receive side.**
  - The raw 0x10 lane marks a frame `verified` only from the discovery cache or the binding registry.
  - #1070 gates Welcome, files, join-result and control-blob on `verified`. The #898 rule says raw claims verify only against recorded evidence.
  - A restarted joiner therefore drops the owner's TreeKEM Welcome, and the seat stalls about 9 min (g46r2, mechanism A).
- **#1091, send side.** A restarted node cannot seal a DM to a peer it already knew: `AgentNotFound` becomes "recipient key material unavailable". The Welcome fetch fails the same way (g46r2, mechanism B).
- **#1040, owner sync.** A restarted device denied its own enrolled machine. ADR 0084 patched this path alone.
- **Grants.** `evaluate_grant_access` (`src/share_grant.rs:~785`) needs the in-memory binding plus a cached certificate, so a grant is inert after a restart.
- **#1092, the stopgap (D31).** It re-broadcasts the node's own announcement on reconnect, which puts point-to-point recovery on a global bus:
  - every re-announce costs every node about 7.4 KB and at least one ML-DSA verify;
  - a fleet restart at N = 1000 is O(N) per node (see §10).

The design health check (R1) judges this a design flaw, not a set of bugs. The node needs durable, self-verifying evidence about the peers it has a relationship with, and a cheap point-to-point way to refresh it.

## Decision Drivers

- **F:** after a restart, DM, TreeKEM Welcome, file offers, grants and owner sync to known peers work immediately, not after 600 s.
- **Keep #898 and #1070:** a raw sender claim is `verified` only on authenticated evidence naming this transport-authenticated machine. No relaxation.
- **E / E-D10:**
  - no global broadcast for point-to-point recovery;
  - bounded bytes, verifies and disk;
  - strangers stay TTL-only.
- **Self-verifying state:** anything persisted is re-verified on load, so a tampered file cannot forge evidence (ADR 0015 posture: no secrets at rest are added).
- **Versioned storage (ADR 0085) and mixed-version safety (ADR 0093).**

## Considered Options

1. **Keep the #1092 reconnect re-announce as the fix.**
   - It is O(N) per node on a global topic.
   - It recovers only when the reconnecting peer is subscribed.
   - Grants and the Welcome fetch still wait for it.
2. **Persist the derived caches (bindings, discovery entries, adverts) as plain records.**
   - Cheap, but the store becomes an unauthenticated security input: disk tamper forges bindings.
   - Rejected for the reason ADR 0021 gave.
3. **Persist signed source evidence for relationship peers, re-verify it on load, and refresh it point-to-point on connect and on demand** (chosen).
4. **Persist evidence for every peer ever seen.**
   - Unbounded disk.
   - Violates E-D10, which keeps strangers TTL-only.

## Decision

### 1. What is persisted: mutual, self-verifying evidence

For each **relationship peer** agent A on machine M, the node keeps one `EvidenceRecord`:

| Part | Bytes | Proves |
|---|---|---|
| `announcement` | the V3 identity announcement wire bytes (`IdentityAnnouncementV3`, `src/announce_v3.rs:97`, about 7.4 KB) | **machine-signed**: M claims to host A. Also carries A's and M's public keys and addresses. |
| `advert` | the DM capability advert wire bytes, with its optional `X0CR` registry trailer (`CapabilityAdvert`, `src/dm_capability.rs:111`, about 8 KB) | **agent-signed** over `agent_id ‖ machine_id ‖ created_at`: A claims to be on M. Carries A's DM **ML-KEM key**. |
| `certificate` (optional) | `AgentCertificate` bytes (about 7.2 KB) | the owner's certificate for A, needed for owner trust and `Grantee::User` matching |
| `relation` | `u8` flags: enrolled-device, grant-party, group-member | why the record is kept |
| `stored_at_ms` | `u64` | local bookkeeping only; never trusted as evidence |

A record is **valid** only when all of these hold:
- both signatures verify;
- the ids are hash-consistent with the embedded public keys;
- the announcement and the advert name the same (A, M);
- the certificate, if present, verifies, binds A and is unexpired.

This is the same mutual evidence that the registry accepts today:
- an agent-signed claim naming the machine;
- plus the machine's own signature, or its live transport authentication.

It must never be derived state.

### 2. Who is a relationship peer

The set is computed from state that already persists, and is re-evaluated on each change and at least every 60 s:

- **Enrolled devices:** the agents on machines in `sync/devices.json` with a current, owner-signed, unrevoked enrollment (ADR 0041, ADR 0084).
- **Grant parties:**
  - the grantees in `share-grants.bin` (an agent, or the agents whose certificate names a granted user);
  - the owner agent of every grant this node holds.
- **Group members:** the active `members_v2` agent ids of every non-withdrawn named group this node is an active member of.

Everything else stays TTL-only, in memory (E-D10). Trusted contacts are not included in this slice.

### 3. Freshness: acceptance is strict, use is bounded (r2, Codex P1-1)

Each signed component is judged **on its own**. The pair is never judged by its newest timestamp.

| Rule | Limit |
|---|---|
| **Future skew** (every component, always) | `announced_at` and advert `created_at` are each ≤ now + 5 min. |
| **Ingest window W** (evidence arriving from the network: gossip, `Hello` or `Lookup`) | Each component must be at most **W** old. W = **15 min**, equal to today's advert TTL of 900 s. An older component is rejected, so a stale agent advert cannot be paired with a fresh machine announcement. |
| **Stored-authority lifetime L** (using a stored record) | Each stored component must be at most **L** old. **L = 7 days** (David, 2026-09-30), via `[evidence] max_age_days` (default 7, minimum 1, maximum 7). **Any ingest-fresh `Hello` from the peer re-validates it:** the record's stored bytes are replaced with the Hello's, which restarts the clock. Past that, the record is treated as absent and needs a fresh `Hello` or `Lookup`. |
| **Move watermark** (persisted, per agent) | `(t, M)`: the newest advert `created_at` ever accepted for agent A **that named a machine other than the one in A's stored record**, and that machine. A stored record (A, M_r, advert time t_r) is accepted, or used, only if there is no watermark with **M ≠ M_r and t > t_r**. Newer adverts naming the **same** machine (routine 600 s refreshes) never disqualify the stored record. |

**Coherent update policy (r3, Codex r2 new blocker (a)).** All of these happen in one in-memory transaction under the store lock. A file write is a single atomic replace of the whole snapshot, so the persisted record and its move watermark can never disagree.

| Event for agent A (verified, ingest-fresh) | Record | Move watermark | Material (persisted)? |
|---|---|---|---|
| Same machine as the stored record, arriving by **`Hello`** | stored bytes replaced with the Hello's, re-validating for a full L (David's ruling) | unchanged | **yes** (at most one `Hello` per machine per 60 s) |
| Same machine as the stored record, arriving by gossip (routine refresh) | the live bytes in memory are updated; the stored bytes are kept unless older than L/2 | unchanged | **no**, unless the stored bytes are older than L/2, which triggers a refresh write |
| **Different** machine M_new (a move), and both parts are available | replaced by (A, M_new) | set to `(t_new, M_new)` | **yes**, in the same snapshot |
| Different machine M_new, and only the advert is available | the old record is **removed** | set to `(t_new, M_new)` | **yes**, in the same snapshot |
| Revocation, relationship ended, or age exceeded | removed | unchanged | yes |

**Moves are durable before they take effect (r4, the Root/David crash-rollback item).** A move is **accepted** only once it is on disk. The order is:
1. Observe ingest-fresh, verified evidence of A on M_new ≠ M_r.
2. **Suspend** the old record (A, M_r) in memory. `usable()` returns `None` for it from this moment, which fails closed.
3. Build the new snapshot: the new record, or none if only the advert is known, and the watermark `(t_new, M_new)`.
4. Write it through to disk immediately, bypassing the 60 s coalescing: temp file, fsync, rename, fsync the directory.
5. **Only then** make the new record usable and drop the suspended old one.

**What a crash does.**
- A crash **after** step 4 restarts with the new snapshot. The old machine's authority is **not** restored.
- A crash **before** step 4 completes means the move was never accepted. The old snapshot comes back, and the move is re-learned from the next fresh evidence: A's `Hello`, a `Lookup` reply, or gossip.
- A failed write leaves the old record suspended (fail closed) until the next retry, and is counted (`evidence_move_write_failed`).

Move writes are rate-limited only by the rate of moves, at most one per agent per ingest of new evidence. They are not subject to the 60 s coalescing. Other material changes stay coalesced.

**Watermark cap.**
- Watermarks are capped at **4096**.
- When full, a watermark is evicted only if its agent has **no** stored record, has been out of the relationship set the longest, and its `t` is older than L. That means it can no longer disqualify anything usable.
- If no watermark qualifies, the **incoming record** is refused rather than dropping protection, and `evidence_watermark_full` is counted.
- A watermark is never evicted while a record for its agent exists. The 512-record cap is below 4096, so this always terminates.

**Replay exposure (r3; the r2 "same as today" claim is withdrawn, per Codex r2 P1-1).**
- **The attack.** A former machine M_old that kept its machine key can present A's advert, which is at most W old and still names M_old, to a node that has never accepted a newer advert for A naming another machine. If the node stores it, M_old can then send raw frames as A for up to **L**. There's no need to replay the advert again.
- **When it ends.** When the first fresh advert naming a different machine arrives (move watermark), on an ADR-0043 retired-binding or other revocation, or when L expires.
- **Compared with today.** Today the in-memory capability expires 900 s after its **signed** timestamp (`src/dm_capability.rs:699`). This ADR therefore **extends** the authorization lifetime from about 15 min to **L = 7 days**, for relationship peers. David accepted this extension on 2026-09-30, with the 7-day cap and re-validation by any fresh `Hello`.

**The rollback claim is corrected.**
- Replacing `peer-evidence.bin` with an older genuine copy **does** roll back the watermark and can restore an old binding.
- That needs write access to the data directory, which already allows replacing the node's own keys (the ADR 0015 posture). It is out of scope, not "only colder".
- Tampering *without* genuine old signed bytes still cannot forge anything.

### 4. How evidence is used: at the point of use, never copied (r2, Codex P1-2, P2-3)

The store is **consulted**, never used to seed another cache. There is one call:

`peer_evidence.usable(agent, machine, now) -> Option<EvidenceView>`

It returns a view only if the record exists and all of these hold, re-evaluated on **every call**:
- the record verified at load or ingest;
- it names exactly (agent, machine);
- every component is within the use limit;
- no move watermark disqualifies it (§3);
- the certificate, if present, is unexpired **now**;
- agent A is still in `relationship_set()` **now**;
- none of the agent, machine, (agent, machine) binding or certificate user is revoked **now**.

Removing a record, or any of these conditions failing, removes its authority **immediately**. No other cache holds a derived copy.

**Consumers, each falling back to the store only when its current source has nothing:**

| Consumer | Today's source (origin/main) | Evidence fallback |
|---|---|---|
| Raw delivery `verified` (#1088/#1089) | discovery cache or `AuthenticatedMachineBindings` (`raw_delivery_verified`, `src/lib.rs:3962`) | `usable(A, M)` is `Some`, with cert expiry taken from the view |
| Raw durable-ACK sender key (P2-3) | discovery `agent_public_key` (`src/lib.rs:13740-13761`) | the agent key from the view's announcement |
| Send-side KEM key (#1091) | `capability_store`, then the contact card | order becomes capability store, then **view advert**, then contact card. The strict durable-ACK path accepts the view, never the card. |
| Dial address | discovery | the view's announcement addresses |
| Grant rule 2 binding / rule 4 certificate | registry / discovery certificate | `usable(A, M)` / the view's certificate |
| Owner trust certificate | discovery certificate | the view's certificate |

`AuthenticatedMachineBindings` keeps being filled **only from live evidence**, as today. The store never writes to it. **The discovery cache and ADR-0093 bits are not seeded.** A stored advert's registry bits are treated as unknown.

### 5. What recovers, and what does not (r2, Codex P2-4)

**Guaranteed within the §10 bounds after a restart:** a relationship peer with a **usable stored record**.

**Not guaranteed, with the defined path for each:**

| Case | Path |
|---|---|
| **No file** (first 0.46 start, or an unreadable file) | Cold. On connect, a `Hello` arrives from any peer that sends one (§6). Otherwise `Lookup`, then gossip. |
| **Record past L, evicted, or disqualified by a move watermark** | Treated as absent: `Lookup` to eligible peers, then gossip. |
| **Contact-only peer** (not a relationship) | Excluded in this slice (E-D10): gossip only, as today. See Open Questions. |
| **Moved peer with no eligible connected intermediary** | Its record names the old machine and verifies nothing new. Recovery waits for its `Hello` when it connects, or for gossip. |
| **Traffic before the background load finishes** | See below. |

**Traffic before the background load finishes.**
- Raw frames and sends that would consult the store wait on a **load barrier**. The wait is bounded: at most 5 s, and at most 64 frames or 1 MiB queued.
- When the barrier releases, they are evaluated normally.
- **Barrier timeout and queue overflow are outside the recovery guarantee (r3, Codex r2 P2-4).**
  - A frame that times out, or doesn't fit in the queue, is evaluated immediately as "no record". It fails closed exactly as today: it is delivered `verified = false`, and the #1070 gates drop it.
  - The sender's own retry is the only recovery path. The Welcome fetch retries, and durable DMs are retried by the sender's outbox.
  - Each case is counted (`evidence_barrier_timeout`, `evidence_barrier_overflow`).
  - A send in either case returns the retryable `RecipientUndiscovered` (from #1092), not a terminal error.
- **The recovery guarantee therefore holds only when:** a usable stored record exists, **and** the load completes within 5 s, **and** the frame fits in the barrier queue. At the 512-record cap this needs `t_v` ≤ about 2.4 ms (§10).

### 6. Wire: `EvidenceV1` (r2, Codex P2-5)

**Protocol.** A new ADR-0022 stream protocol, `EvidenceV1 = 0x06`.
- It is admitted from any **transport-authenticated** machine, even with no known agent.
- It goes only to the evidence acceptor, never the default channel. This is the same narrow pattern as ADR 0084.

**Framing.**
- A 1-byte type, then a length-prefixed bincode body.
- Signed parts are carried verbatim.
- A message is at most 32 KiB, and a stream carries exactly one request and one reply.

**Hello (on connect).** Each side sends its **own** current announcement and advert, plus its certificate digest. The certificate itself follows only if the peer lacks it.
- **Sent** when the connected machine is enrolled, or hosts an agent with a usable stored record or a live relationship.
- **Accepted** only if (A, M) names the transport-authenticated machine and every component passes §3 ingest freshness. Then the evidence is stored if A is a relationship peer. Otherwise it only refreshes the in-memory TTL caches.

**Lookup (pull).** `Lookup { agent_id: X }` is answered with `Found { announcement, advert, certificate? }` or `NotFound`.

**Responder authorization.** The responder serves a request only if all of these hold, and otherwise answers `NotFound` without signalling why:
- the requesting transport machine hosts an agent R that is itself one of the responder's relationship peers, with a usable record or live evidence;
- R and X share a relationship context at the responder: the same group roster, the same owner (both enrolled to the responder's owner), or one is the grant counterparty of the other;
- the reply is built only from **ingest-fresh material**, never from TTL caches of strangers. That means either:
  - the responder's own current announcement and advert, minted on demand; or
  - the **live** (in-memory) announcement and advert bytes it holds for X, where each component is at most W old at reply time. The responder keeps the latest verified live bytes for every relationship peer in memory, updated on each routine refresh, separately from the stored bytes.

  A stored record older than W is **never served**. Serving it is useless, because the requester must reject it under §3. The responder answers `NotFound` instead (r3, Codex r2 new blocker (b)).

**Responder budgets.**
- Per requesting machine: ≤ 2 open `EvidenceV1` streams, ≤ 1 `Lookup` per 2 s and ≤ **64 KiB/s** of replies.
- Globally: ≤ **256 KiB/s** of replies and ≤ 32 evidence verifies/s, including verifies of `Hello`s received.
- Every stream has a **5 s deadline** covering the first byte to the end of the body. Incomplete or slow streams are reset, and the reset counts against the budget.
- Anything over budget gets `NotFound` or a reset. It is never queued.
- **Implementation conditions (Codex r2 P2-5):**
  - budgets are accounted **per transport machine identity across all its connections**, not per connection;
  - `NotFound` replies are charged against the byte and rate budgets;
  - the existing stream prefix timeout (`src/lib.rs:14750`) stays in front, so a peer that sends no first byte cannot evade the body deadline;
  - pre-verification buffering is bounded in aggregate: ≤ 32 KiB per stream and ≤ 1 MiB in total across all `EvidenceV1` streams awaiting verification.

**Requester budgets.**
- ≤ 1 `Lookup` per target per 30 s, to ≤ 3 responders.
- ≤ 16 outstanding `Lookup`s in total.
- Replies are re-verified in full (§1, §3) and are never trusted on their own.

**Capability bit.** This ADR allocates ADR 0093 bit 2, **`peer_evidence_v1`**, meaning "accepts `EvidenceV1`".
- A current verified advert lacking the bit means the `Hello` is skipped.
- Unknown state means one try per connection. A reset marks the connection "no evidence" until it drops.
- **Allocation route:** ADR 0093 is Accepted and immutable. This ADR amends its allocation procedure so the canonical table is the "ADR 0093 capability registry" table in `docs/adr/README.md`. Bit 2 is added there, marked reserved by 0089 and effective on acceptance, together with the code constant in S5.

### 7. Mixed versions

- **v0.45 maps the unknown byte `0x06` to `None` and resets the stream** (`src/streams.rs:464-471` on main). The 0.45 behaviour must be proven by a test against the **released v0.45.0 binary** (Validation): the reset, then ordinary DM traffic on the same connection.
- **The 0.46 side uses stored evidence for 0.45 peers,** because 0.45 publishes the announcement and advert pair, and stores it only if the peer is a relationship peer.
- **Row 4b** (a restarted rc sender to a 0.45 receiver within 5 min) is covered by stored evidence. It fails over to gossip when no record exists.
- **The #1092 reconnect re-announce** is retired once `EvidenceV1` ships. `RecipientUndiscovered` stays.

### 8. Storage (r2, Codex P2-7)

**File layout.**
- **Path:** `<data_dir>/peer-evidence.bin`, magic `X0PEV1\0\0`, then bincode `EvidenceFileV1 { records, watermarks }`.
- **Rules:** ADR 0085 rules 1, 2 and 6, with exact consumption.

**Record limits (enforced at ingest, not estimates).**
- announcement ≤ 8 KiB, advert ≤ 12 KiB, certificate ≤ 10 KiB, so a record is ≤ **30 KiB**;
- ≤ **512 records** (store hard cap ≤ 15 MiB) and ≤ **4096 watermarks** (about 330 KiB);
- eviction order: group-member, then grant-party, then enrolled-device, least recently used first.

**An unreadable file is never replaced.**
- On an unknown magic or a failed decode, the store runs **memory-only for the lifetime of the process**. It never writes to or renames over that path.
- A WARN names the file.
- Recovery is manual: move the file aside.
- A test proves the file is byte-identical after the process has received fresh evidence.

**Write coalescing.**
- The file is rewritten only on a **material change**, as defined by the update-policy table in §3:
  - a record is added, replaced or removed;
  - a move watermark is set;
  - a certificate changes;
  - a stored component is older than L/2 while newer live same-machine bytes exist (a refresh, so stored records stay inside L).
- A routine same-machine re-announcement is **not** material.
- At most one write per 60 s, and only if dirty. A dirty store is also flushed on clean shutdown. **The exception is moves:** they are written through synchronously before they take effect (§3).
- **File hard cap:** ≤ **16 MiB** in total. That is records (≤ 15 MiB) plus watermarks (≤ 4096 × 80 B ≈ 320 KiB) plus framing. An insert that would exceed it is refused.
- **Writes.**
  - **Worst case:** 1440 writes/day × 16 MiB ≈ 22.5 GiB/day, only if a material change arrives every minute.
  - **Refresh term:** with R records, refreshes are about R per L/2. At R = 512 and L = 7 days that's about 146/day, coalesced into ≤ 1440 writes.
  - **Typical:** R ≈ 50 gives about 14 refreshes/day plus moves and membership changes, coalesced to a few dozen writes per day.
  - `evidence_writes` and `evidence_bytes_written` are counters. The goal-E budget for them is set by E0 measurement.

**Downgrade.** v0.45 never reads the file. A re-upgrade reuses it, and a test covers the round trip.

### 9. Security argument: #898 and #1070 still hold

1. **Nothing becomes `verified` without evidence naming this transport-authenticated machine.**
   - It must be mutual signed evidence, individually fresh at ingest (§3), and currently usable (§4).
   - A frame from (A, M′) with a record for (A, M) stays unverified and never rebinds.
2. **Replay.**
   - A stale advert cannot be paired with a fresh announcement, because ingest freshness is per component.
   - A superseded binding cannot come back once a newer advert naming another machine has been accepted, because the move watermark is persisted with it.
   - **The residual is larger than today's, and stated in §3:** a replayed advert at most W old can yield stored authority for up to L, where today the limit is about 900 s. Also a local-disk rollback, which is out of scope under ADR 0015.
3. **Lifetime enforcement is at the point of use.** Revocation, certificate expiry, the age limit and relationship removal take effect on the next call, because the store's authority is never copied (§4).
4. **`Hello` carries only the sender's own evidence.** `Lookup` replies are fully re-verified.
5. **Amplification is bounded by the responder** (§6), not by requester goodwill.
6. **The #1070 gates are unchanged.** They now receive `verified = true` for usable relationship peers after a restart.
7. **Strangers are never stored and never served** (E-D10).
8. **Nothing secret is at rest:** only public keys, signatures and certificates (ADR 0015).

### 10. Costs: measured, estimated and enforced (r2, Codex P2-6)

**Verify cost is an assumption to be measured.** `t_v` = one ML-DSA-65 verify.
- 1.5 ms is the saturated-VPS figure from #656 and is used here as a pessimistic **assumption**, not a bound.
- S1 must benchmark `t_v` on the fleet's VPS class and on a Mac, and update this table.

| Item | Enforced ceiling | Typical estimate |
|---|---|---|
| Startup load (R records, 4 verifies each) | R ≤ 512, so 2048 verifies (about 3 s at 1.5 ms, in the background) | R ≈ 50: 200 verifies |
| `Hello` in and out, per connection establishment | 1 per machine per 60 s; ≤ 32 KiB each way | about 16–23 KiB each way; 4 verifies inbound |
| `Lookup` served | 64 KiB/s per requester; 256 KiB/s total | rare: only on a cache miss |
| `Lookup` sent | 16 outstanding; 1 per target per 30 s × 3 responders | rare |
| Evidence verifies (all inbound) | 32/s | — |
| Disk | file ≤ 16 MiB; ≤ 1 write per 60 s | a few dozen writes per day at R ≈ 50 |

**Fleet restart, per node, full duplex,** with C = connections (typical 8, capped by `max_connections`) and R = relationship records:

| | This ADR | #1092 re-announce |
|---|---|---|
| **N = 100** | load: 4R verifies (R = 50: 200). Hellos: 2 × min(C, R) × about 23 KiB, which is about **368 KiB** at C = 8, plus 4 × min(C, R) verifies inbound = **32**. Worst case at C = 64: about 2.9 MiB, 256 verifies. Lookups: ≤ 256 KiB/s served. | receive about 100 × 7.4 KB = **740 KB** and ≥ 100 verifies, per re-announce round |
| **N = 1000** | **the same as N = 100.** The load, Hello and Lookup terms depend on R and C, not N. | about **7.4 MB** and ≥ **1000 verifies** per round |

The Hello term is O(C), and the load and refresh-write terms are O(R). `Lookup` is **rate-bounded** by the §6 budgets (≤ 256 KiB/s served, ≤ 16 outstanding sent); it is not shown to be O(C). None of these grows with N.

## Decisions recorded at acceptance (David, 2026-09-30)

1. **Contacts are excluded from this slice.** Trusted contacts that are not group, grant or enrollment peers stay TTL-only (E-D10). Widening this needs a later ADR.
2. **Open pre-identity admission is accepted.** `EvidenceV1` is admitted from any transport-authenticated machine, with the responder authorization, budgets and implementation conditions of §6.
3. **Ingest window W = 15 min**, today's advert TTL.
4. **Stored-authority lifetime L = 7 days, re-validated by any fresh `Hello` (§3).** The extension of authorization lifetime from about 900 s to up to 7 days for relationship peers, stated in §3 and §9, is accepted.

## Consequences

### Positive

- **Relationship peers with a usable record recover after a restart.** DM, Welcome push and fetch, file offers, grants, owner sync and the raw durable-ACK receipt all work without waiting 600 s.
- **The #1088/#1091 and grant-after-restart gaps close by construction,** and lifetime checks sit at one point of use.
- **Recovery is point-to-point.** It is O(C) for Hellos, plus O(R) for load and refresh writes, plus a separate rate-bounded `Lookup` term (≤ 256 KiB/s served, ≤ 16 outstanding) per node. It is not O(N) global re-announces (goal E).

### Negative / Trade-offs

- **New surfaces:** a new stream protocol with pre-identity admission (bounded, §6), a new persisted file (≤ 16 MiB), a load barrier (≤ 5 s) and a new ADR 0093 bit.
- **Not every case recovers immediately.** No file, an expired or evicted record, contact-only peers and moved peers without an intermediary are not guaranteed (§5).
- **Replay residual, larger than today:** a replayed advert at most W old can become stored authority for up to L (today about 900 s), plus local-disk rollback (§3; L = 7 days by David's ruling).
- **Stored capability bits stay unknown after a restart** (D35 is separate).

### Neutral / Operational

- **Diagnostics counters:** `evidence_{loaded,rejected_on_load{reason},usable_hits,usable_misses{reason}}`, `evidence_hello_{sent,received,refused}`, `evidence_lookup_{sent,served,refused,unauthorized}`, `evidence_bytes_{in,out,written}`, `evidence_verifies`, `evidence_writes` and `evidence_load_barrier_waits`.
- **ADR 0021's stateless attestation is unchanged.**

## Validation

**Unit tests (inert):**
- **Format:**
  - a round-trip;
  - a fixture from the released encoder;
  - an unknown magic leaves the store memory-only, and the file stays **byte-identical after fresh evidence arrives**;
  - trailing bytes are rejected;
  - the per-component byte limits hold;
  - the 512-record and 4096-watermark caps hold.
- **Freshness (§3):**
  - a stale advert plus a fresh announcement is rejected at ingest;
  - a future-skewed component is rejected;
  - a record past the use limit is unusable;
  - a record disqualified by a move watermark is rejected, including across a restart;
  - **routine refresh then restart:** a stored record, then 3 routine same-machine refreshes, then a restart; the record is still usable (Codex r2 blocker (a));
  - **move:** after a move, the record and watermark are replaced or removed in one snapshot. **Kill test:** crash just after the move is accepted (after fsync), then restart; `usable(A, M_old)` must be `None` and the old machine's authority must not come back. Crash before the fsync: the move was not accepted, and the old record is restored until the next fresh evidence. A failed move write keeps the old record suspended;
  - the watermark survives record eviction;
  - **at the 4096 cap:** only eligible watermarks are evicted, and otherwise the incoming record is refused (`evidence_watermark_full`).
- **Point of use (§4), each tested *after* load:**
  - revoking the agent, machine, binding or certificate user makes `usable()` return `None` on the next call;
  - so do certificate expiry at the next call, and removing the relationship (member removed, grant expired or revoked, device unenrolled);
  - the store never writes to `AuthenticatedMachineBindings`.
- **Raw path and ACK:**
  - with an empty discovery cache plus a usable record, a frame from (A, M) is verified;
  - (A, M′) is not;
  - a revoked A is dropped;
  - the raw durable ACK verifies against the record's agent key.
- **`EvidenceV1`:**
  - a `Hello` naming another machine is refused;
  - a stale component in a `Hello` is refused;
  - an **unauthorized `Lookup` gets `NotFound`**;
  - **age mismatch:** a responder holding only a stored record older than W answers `NotFound`, and one holding fresh live bytes answers `Found`, which the cold requester accepts (Codex r2 blocker (b));
  - budgets hold across multiple connections from one machine;
  - `NotFound` is charged against the budget;
  - no-first-byte streams hit the prefix timeout;
  - the aggregate pre-verify cap holds;
  - a hostile requester is held to 64 KiB/s, 2 open streams and 1 lookup per 2 s;
  - slow and incomplete streams are reset at 5 s;
  - reconnect churn is held to 1 `Hello` per 60 s;
  - the global verify cap holds;
  - an old-peer reset is marked once.
- **Load barrier:**
  - a raw frame and a send arriving during load are held, then evaluated;
  - a timeout and a queue overflow each fail closed, are counted, and are recovered only by the sender's retry;
  - the send returns `RecipientUndiscovered`.

**Integration (CI, isolated), red on origin/main and green on the fix:**
- **Welcome:** restart B cold with a usable record; warm A pushes a Welcome; the seat leaves `pending_authority_commit` within 5 s.
- **DM:** restart B cold; **B sends first**; the DM and its **durable receipt** complete within 10 s.
- **Grant:** restart the grant host; the first request is admitted within 10 s.
- **Owner sync:** restart an owner device cold; owner sync completes within one pass (≤ 60 s) with no gossip announcement.
- **No file:** the first start after upgrade recovers through `Hello` or `Lookup`; this is a timed measurement, not a pass/fail bound.
- **Expired record:** an expired or evicted record recovers through `Lookup`.
- **Contact-only peer:** it waits for gossip (a pinned current limitation).
- **Traffic during load:** sends and frames arriving during load are held by the barrier, then complete.
- **Barrier timeout and overflow (D30):** force a slow load (> 5 s) and a burst of more than 64 frames. The excess is dropped `verified = false` and counted, and the sender's retry completes the flow once the load finishes. The gate row records this outcome separately from the guaranteed path.

**D30 release-gate row, restart-cold (CI test plus a testnet row):**
- Restart a node cold. Within the bounds above, run a DM both ways, a TreeKEM join with Welcome, a file offer and owner sync.
- **Row 4b:** a restarted rc sender reaches a 0.45 receiver within 5 min.
- **0.45 interop:** use the **released v0.45.0 binary** (the CI release artifact) in the isolated harness. Confirm the `EvidenceV1` reset, then ordinary DM traffic on the same connection, and that the 0.46 side marks the connection and doesn't retry.
- **Cost:** record the fleet-restart bytes, verifies and writes per node against §10. E-D17 requires delivered == published for every gate-row flow.

**Review triggers:**
- any change to the freshness limits, the watermark, `usable()` conditions, the relationship set, the caps, the budgets or `EvidenceV1` admission;
- any proposal to persist strangers, or to seed another cache from the store.

## Notes for AI-assisted work

- **Persist the verified signed wire bytes** (never re-serialized structs), and re-verify them on load.
- **The store is consulted at the point of use and is never copied into other caches.**
- **Freshness is per component.** Ingest (W = 15 min) and stored-authority lifetime (L = 7 days, David's ruling) are separate limits.
- **Never mark `verified` from a record naming a different machine.**
- **A `Hello` carries only the sender's own evidence.** A `Lookup` reply is re-verified and served only to authorized requesters.
- **Never overwrite an unreadable evidence file.**
- **Accepted by David 2026-09-30; the body is now immutable.** Changes need a superseding ADR, or a README errata entry for factual corrections.
