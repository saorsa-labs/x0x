# ADR 0080: A Grant Revocation Is Also Pushed as One Signed Record to Capable Recipients; Gossip Remains the Backstop

- **Status:** Proposed
- **Date:** 2026-09-27 (first draft); revised 2026-10-04 under D63; rulings
  D108–D114 recorded 2026-10-04; round-2 rulings D120 and D139–D143
  recorded 2026-10-04; round-3 rulings D147, D148 and D169 recorded
  2026-10-04
- **Decision owners:** David Irvine (#994 Root decision, 2026-09-27; D23;
  D63; D108–D114; D120; D139–D143; D147; D148; D169)
- **Author:** OMP (first draft); revised by Claude (Opus)
- **Reviewers:** cross-model review required before acceptance; David Irvine (acceptance)
- **Supersedes:** none
- **Superseded by:** none
- **Extends:** [ADR 0077](./0077-share-grant-owner-side-redelivery-outbox.md)
  (owner-side revocation ordering). ADR 0077 is not edited. ADR 0070 §2
  (ShareGrant) and ADR 0018 (revocation records) are not changed.
- **Serves:** goal **A** (an owner shares a chosen agent with another
  person, scoped, expiring and revocable) and requirement **R5** (share a
  subset of my agents). Invariants **I7** (revocation reaches every gate
  within a bound) and **I9** (a wire change is gated by a signed capability
  bit). Wave W4, item A4.
- **Related:** #1003 (this work), #994, #1108 (revocation surface gaps),
  #1111 (Critical revocation carriers), #1116 (corrupt store fails open),
  #891; rulings D23, D35 and D28 in the
  [rulings digest](../design/x0x-direction.md), D63 (2026-10-04: revise
  this ADR), D108–D114 and D139–D143 (2026-10-04: this ADR's open
  questions) and D120 (2026-10-04: unreadable sidecars are quarantined);
  [ADR 0085](./0085-persisted-binary-formats-are-versioned.md) (the
  `deliver_to` sidecar; rule 4 amended for it, section 3a); [ADR 0093](./0093-capability-advert-registry.md) (capability
  bits) and its allocation table in the [ADR index](./README.md);
  [ADR 0089](./0089-relationship-peer-evidence-survives-restart.md) (the
  allocation procedure); ADR 0098 (prov., the revocation surface); ADR 0074
  s3 (live-session teardown); ADR 0072 (scope freeze).

## Context

**What happens today (main).** `DELETE /grants/:id` signs a `ShareGrant`
revocation record with the owner key. ADR 0077 orders it against grant
redelivery. When the call returns, the owner install has made the record
durable, removed the outbox entry, and will start no new send of the grant.

The record then reaches other daemons only by gossip on
`x0x.revocation.v3`. A daemon that holds the grant keeps honouring it
until that gossip arrives. A grant DM that was already on the wire can
also land after the revoke. The window is seconds on a connected mesh. It
has no bound across partitions or for offline daemons.

The v3 carrier has two more limits:
- It is Normal priority, so it is sheddable (#1111).
- It re-publishes the owner's whole v3 set, not the one new record. A v3
  batch may be up to 2 MiB.

**The first draft of this ADR** pushed the whole v3 batch to each
recipient under a new typed-DM prefix, with no capability check. Review
found three faults:
- An old receiver does not ignore an unknown typed prefix. It treats the
  payload as an ordinary DM: it stores it in DM history and passes the raw
  bytes to DM subscribers.
- A whole v3 batch can exceed the DM payload limit of 49,152 bytes.
- "One push" against "three attempts" was ambiguous.

**The rulings.** D23 gives the revocation surface to ADR 0098 (prov., not
yet drafted). ADR 0098 supersedes ADR 0018 and covers: no revocation sweep
before `not_after`, an owner issuer path for Machine revocation, Critical
carriers for the revocation topics, a fail-closed store, one listing, and
a lost-device response. D35 adds a 90-day maximum ShareGrant lifetime with
renewal (ADR 0098). D35 also holds obligation-carrying typed sends to a
peer of unknown capability for up to one advert period after a restart.
D23 says to revise this ADR as a **capability-gated single-record push**,
and to apply both before any `shed_normal` default. D63 orders that
revision.

**A hold applies.** D28 holds ADR 0070 and ADR 0077: no new slices until
their review is recorded. Code under this ADR is a new grant slice, so it
waits for that review (D114).

## Decision Drivers

- Close the window at the daemons that hold the grant. Owner-side
  ordering (ADR 0077) is already sound and stays as written.
- An old receiver must never get the push (I9). A capability bit is the
  only safe test.
- One record per recipient. It must fit one DM with a wide margin.
- One verify path and one ingest path. A pushed record and a gossiped
  record are the same bytes and must have the same effect.
- Stay inside ADR 0098's scope. Decide only what David ruled for the push
  (D108, D110, D142). Leave the rest to ADR 0098.
- Goal E: small, bounded bytes per revoke; no new periodic task. The only
  new durable state is the recorded `deliver_to` list (D112).

## Considered Options

1. **Capability-gated single-record push** (chosen). Push the one new
   record to each recipient whose current verified advert sets a new ADR
   0093 bit. Gossip stays the backstop.
2. **The first draft: an ungated whole-batch push.** Rejected. Old
   receivers leak the bytes into DM history and subscribers. The batch can
   exceed the DM limit. It also re-sends records the recipient does not
   need. It conflicts with D23.
3. **A durable push with an ACK through the owner outbox.** Rejected for
   now. It turns a best-effort accelerator into an obligation with new
   per-recipient durable state. Gossip, the ADR 0098 store rules and
   in-band grant presentation already cover a missed push. Revisit if
   `Outbox<T>` (ADR 0090, prov.) makes the cost small.
4. **Critical carriers only (ADR 0098).** Not enough alone. Priority stops
   shedding, but it does not shorten gossip latency or cross a partition.
   D23 rules for both.
5. **Status quo (gossip only).** Rejected by the #994 Root decision and by
   D23.
6. **Grantee-side poll.** Rejected. It adds a request type and a reply that
   must verify like a carrier. It does not reach the hosts that enforce the
   grant.
7. **Amend ADR 0077.** Rejected. ADR 0077 is Accepted and immutable, and
   delivery and revocation propagation are separate lifecycles.

## Decision

We will push the one signed revocation record of a revoked grant, as a
typed DM, to each recipient of that grant whose current verified capability
advert sets `grant_revocation_push_v1`. The push is best-effort. The
`x0x.revocation.v3` gossip carrier is unchanged and stays the backstop.

### 1. Capability bit

- **Name:** `grant_revocation_push_v1`.
- **Meaning:** "Accepts the single-record grant revocation push
  (`x0x-grant-revocation-push-v1\0`) and ingests it through the v3
  revocation path."
- **Number:** allocated at acceptance, in acceptance order, as the next
  free bit in the README registry. This ADR reserves no numbered row now.
  The accepting PR adds the row and fixes the number in this ADR, the code
  constant and the compatibility tests together. After that the number and
  meaning are frozen. No build advertises the bit before then.
- **Advertising:** a receiver advertises the bit only when its typed route
  for the prefix is registered and ready. A pending receiver does not.
- **Gate direction (D113):** the sender needs **positive evidence**.
  `share_grant_v1` and `predecessor_offer_v1` hold a send only when a
  current advert lacks the bit. This bit is stricter: the sender pushes
  only when a current verified advert **has** the bit. Unknown, expired and
  card-only state means "no push". The push is optional and an old
  receiver mishandles it, so a missed push costs only latency.

### 2. Wire format

- **Payload:** `x0x-grant-revocation-push-v1\0` followed by
  `bincode(RevocationRecord)`.
- **Exactly one record.** It is not a `Vec`. Its bytes are the same as that
  record's encoding inside the v3 gossip batch.
- **Subject:** `ShareGrant` only, with a finite `grant_expiry`. A record
  for an unknown grant (`grant_expiry = u64::MAX`) is never pushed. It
  travels by gossip only.
- **Size:** at most 8 KiB, prefix included. The record that
  `DELETE /grants/:id` signs is about 5.4 KB: an ML-DSA-65 public key
  (1,952 B), a signature (3,309 B) and about 100 B of fields, with no
  reason text. That is well under the 49,152-byte DM limit.
- **Signer:** the grant owner's user key. That is the record's existing
  signature. Nothing new is signed. The DM envelope is signed by the
  sending agent as for any DM, but it gives no authority.

### 3. Sender

- **Trigger:** `DELETE /grants/:id`, after ADR 0077's durable step
  succeeds (the record and the outbox removal are both durable). If the
  DELETE answers 503, there is no push. The caller's retry pushes. The
  owner never pushes a revocation that a restart could forget.
- **Grant:** only a grant in this install's issued store. Its expiry gives
  the record a finite `grant_expiry`.
- **Recipients:** the grant's delivery recipient set, computed at revoke
  time:
  1. the daemons of the shared agents, other than this one. These hosts
     enforce the grant, so they come first;
  2. the grantee's known agents;
  3. the `deliver_to` agents recorded for the grant (section 3a, D112).

  The push adds no discovery fan-out beyond this set. Only the issuing
  install records item 3. A revoke from another owner install, or of a
  grant issued before the record existed, pushes to items 1 and 2 only.
- **Gate per recipient** (section 1, D113):
  - A current verified advert has the bit: push.
  - A current verified advert lacks the bit: skip, and count
    `skipped_not_capable`.
  - Capability is unknown (for example after a restart): ask for one
    bounded targeted advert refresh, as ADR 0093 allows. Wait up to one
    advert period, 600 s (D35, D113), for a current advert. Push if it
    has the bit. Otherwise skip, and count `skipped_unknown_capability`.
    Gossip runs during the wait, so after a restart a push can be up to
    600 s late but the revocation is never held back.
- **Send:** an ordinary typed DM. The route is not durable-registered. The
  sender waits for no ACK.
- **One push:** one logical push per recipient per revoke. It is at most 3
  send attempts. The sender retries only when the local send returns an
  error. A send that returns success ends that push, because no ACK
  exists.
- **The push adds no durable state.** Pending pushes live in memory only,
  at most 1,024 at a time. A push over that bound is skipped and counted. A
  restart drops pending pushes. Gossip still carries the record.
- **The DELETE response:** the success contract stays ADR 0077's. The
  DELETE does not wait for pushes. It reports `push_recipients`, the
  number of pushes scheduled, and the grant's `deliver_to_record` state
  (section 3a). Results go to counters in `GET /diagnostics/grants`:
  `pushed`, `send_failed`, `skipped_not_capable`,
  `skipped_unknown_capability` and `skipped_bound`.
- **Pending pushes are visible.** `GET /diagnostics/grants` lists each
  pending push with its `grant_id`, its recipient and its state:
  - `awaiting_capability`: waits for a current verified advert from the
    recipient, after one targeted refresh. It shows its deadline, 600 s
    after the wait began. Exits: the advert has the bit (`sending`), the
    advert lacks it (`skipped_not_capable`), or the deadline passes
    (`skipped_unknown_capability`).
  - `sending`: shows attempt n of 3. Exits: `pushed` or `send_failed`.
  - A restart drops every pending push. Gossip still carries the record.

  The same endpoint keeps the last 1,024 outcomes in memory, oldest out
  first, each with its `grant_id`, its recipient and its outcome (D143).
  A restart clears the list. The counters keep running totals for the
  life of the process.

### 3a. The recorded `deliver_to` list (D112)

The implementing slice records each issued grant's `deliver_to` list, so
the push reaches those daemons too (D112).

- **What.** When `POST /grants` issues a grant, the issuing install records
  the request's validated `deliver_to` agents against the grant's
  `grant_id`. The list is local delivery metadata. It is never sent on the
  wire and gives no authority. Its only use is recipient item 3 at revoke
  time.
- **Where.** In a new versioned sidecar next to the share-grant store,
  under ADR 0085: its own magic, a file extension that no released binary
  reads, and a strict decode that consumes every byte (the file and its
  header are below). The `X0SG`
  share-grant store file does not change format. A new `X0SG` magic would
  make a downgraded v0.46.1 install refuse its whole share-grant store, so
  it would hold and enforce no grants. The sidecar leaves the released
  store as it is.
- **Atomic persistence.** Each sidecar persist writes the whole in-memory
  map with the share-grant store's durable write: a temp file, fsync,
  rename over the sidecar, then a directory fsync. A crash leaves the old
  file or the new one, never a mix. No sidecar write runs before ADR
  0094's host commit (ADR 0094 allows no persisted-format upgrade write
  before it).
- **One sidecar writer at a time.** A single writer lock serializes every
  sidecar persist, from issue and from prune. A persist holds it from the
  moment it takes its snapshot of the map, through the durable rename, to
  the update of each entry's state. So a later snapshot always holds every
  entry that an earlier completed persist wrote, and a stale snapshot can
  never overwrite a newer file. An entry becomes `recorded` only when a
  persist whose snapshot held it has completed. A revoke never takes this
  lock.
- **Order against revoke.** The in-memory map is the only source for
  item 3. The issue call runs these steps in order:
  1. Insert the list into the in-memory map under the new `grant_id`.
  2. Persist the sidecar, when writes are allowed (see the states below).
  3. Only then insert the grant into the issued store. Before this step,
     `GET /grants` does not list the grant, and its random id has not been
     returned, so no caller can revoke it.
  4. If step 3 fails, the issue fails and the map entry is removed.

  A revoke reads the issued grant first and the map second. So a revoke
  that can see the grant always sees its list. A paused or slow sidecar
  write delays its own issue call and any issue call queued behind it on
  the writer lock. No revoke waits for it.
- **Crash outcomes.**
  - Before the sidecar write lands: neither the entry nor the grant is
    durable, and the issue never returned.
  - After the sidecar write, before the grant is durable: the entry is an
    orphan. Load drops an entry whose grant is not in the issued store,
    and the next persist removes it.
  - After both: the two are consistent.
  - An entry held only in memory (below) is lost on restart, and its
    grant becomes `not_recorded`.
- **Lifetime.** An entry lives as long as its grant stays in the issued
  store. A revoke reads the entry and does not remove it, so a retried
  DELETE pushes to the same set. When the issued store prunes a grant, its
  entry goes too. The issued store's cap (1,024 grants) bounds the entry
  count.
- **The list cap (D141).** An entry records at most 64 agents, the
  shared-agent cap. A longer `deliver_to` list is still delivered in full
  at issue, but it is not recorded. The grant's state is `not_recorded`,
  cause `over_cap`, and a revoke pushes to items 1 and 2 only. The cap
  keeps `POST /grants` compatible and bounds the sidecar at about 2 MiB
  (1,024 grants × 64 × 32 B).
- **The file and its header.** The sidecar is `share-grants.deliverto`
  in the data directory, next to `share-grants.bin`. No released binary
  reads that extension. Its family prefix is `X0GDT`, reserved for this
  path forever. A valid header is eight bytes: the prefix, the family
  version as one ASCII digit from `1` to `9` in byte 5, and two zero
  bytes. This build supports version 1 only (`X0GDT1\0\0`). The version 1
  body is bincode, consumed exactly: first ADR 0108 §5a's `rebuilt_from`
  list of quarantine `txid`s (empty after an ordinary write), then the map
  from `grant_id` to the recorded agents. Every future layout keeps the
  prefix and takes a higher version, which is the new magic that ADR 0085
  rule 1 asks for. Versions above 9 need a later ADR first.
- **Unreadable files: the shared lifecycle (D120).** This sidecar uses
  ADR 0108 §5a: its classification, quarantine transaction, resume,
  history and failure rules, and its states `sidecar_unavailable`,
  `sidecar_newer_format` and `sidecar_quarantine_failed`, each with
  `file: share-grants.deliverto`. This ADR adds only these points:
  - Every lifecycle step, resume included, holds the sidecar writer lock
    and runs only after ADR 0094's host commit. Before the commit, a
    damaged file stays at its path, and the sidecar shows
    `sidecar_unavailable { file, cause: awaiting_host_commit }`. At the
    commit, the lifecycle runs in the same process.
  - A missing file with no pending copy, whether or not history copies
    exist, is a fresh start: an empty map, and every grant is
    `not_recorded`, cause `absent`.
  - **The step 4 replacement (D169)** is an empty map whose
    `rebuilt_from` lists the transaction's `txid`. No second local copy
    is kept.
- **What no holder has (D120).** The list is issuer-only state. No
  grantee, host or `deliver_to` agent keeps a copy, and no protocol asks
  for one. So nothing can be rebuilt from holders, and this ADR claims no
  such rebuild. David accepted this loss outcome (D147, D169): each grant
  whose entry was in the quarantined file becomes `not_recorded`, cause
  `quarantined`, and its list is lost. Its `deliver_to` daemons get gossip
  only at revoke, so revocation still reaches them. The grants themselves
  live in the `X0SG` store, so they are unaffected. Nothing is silently
  trusted: the loss is a typed state, and the next step is gossip.
- **The amendment.** This ADR amends ADR 0085 rule 4 for
  `share-grants.deliverto` only, as ADR 0108 §5a describes, ruled by David
  (D120 for the quarantine, D169 for the empty replacement). ADR 0085
  rule 5 is not amended. The amendment takes effect when this ADR is
  Accepted.
- **Retention (D148).** Quarantined copies follow ADR 0108 §5a's
  retention rule. The lifecycle never deletes them. This file belongs to
  no group, so its copies stay until an operator removes them.
  `GET /diagnostics/grants` lists each copy with its `txid`, hash and
  size.
- **Typed states.** Each issued grant has one `deliver_to_record` state.
  The `POST /grants` response, each `GET /grants` entry and the
  `DELETE /grants/:id` response report it with its `grant_id`.
  `GET /diagnostics/grants` reports the sidecar's state (`ok`,
  `awaiting_host_commit` for a held persist, `write_failed` with its
  error, or one of ADR 0108 §5a's states with all its fields), a count
  per grant state, and each quarantined copy with its `txid`, its hash
  and whether it is pending. A revoke uses the list in `recorded` and
  `held_in_memory`. In every other state it pushes to items 1 and 2 only.
  In `unavailable` it also counts `deliver_to_unavailable`.

  | State | Cause | Waits for | Deadline | Exit |
  |---|---|---|---|---|
  | `none_requested` | the request's `deliver_to` was empty | nothing | none | terminal |
  | `recorded` | the list is durable in the sidecar | nothing | none | terminal; removed with the grant |
  | `held_in_memory`, cause `awaiting_host_commit` | ADR 0094 has not yet host-committed the running binary | ADR 0094's host commit | none of its own; ADR 0094's commit or rollback ends it | host commit, then a persist: `recorded`. A rollback or restart first: `not_recorded`, cause `absent` |
  | `held_in_memory`, cause `write_failed`, with the error | an ordinary sidecar persist failed | the next successful persist (the next issue or prune) | none | that persist: `recorded`. A restart first: `not_recorded`, cause `absent` |
  | `held_in_memory`, cause one of ADR 0108 §5a's sidecar states, with its fields | the sidecar is not usable, so it runs memory-only and no write runs | §5a's exit for that state; for `awaiting_host_commit`, the host commit | none | host commit: the quarantine runs, then a persist: `recorded`. Otherwise a restart: `not_recorded`, cause `absent` |
  | `unavailable`, cause one of ADR 0108 §5a's sidecar states, with its fields | the grant was in the issued store at load; its list, if any, is in that file | §5a's exit for that state; for `awaiting_host_commit`, the host commit | none | a load that reads the file: `recorded` if it holds an entry, else `not_recorded`, cause `absent`. A quarantine: `not_recorded`, cause `quarantined` (D169) |
  | `not_recorded`, cause `over_cap` (D141) | the request named more than 64 agents | nothing | none | terminal |
  | `not_recorded`, cause `quarantined` (D120, D147, D169) | the entry was in a quarantined file, and the replacement does not restore it | nothing | none | terminal. After a restart the grant shows cause `absent`, because the damaged file cannot say which grants it held |
  | `not_recorded`, cause `absent` | no entry: issued before the sidecar existed, on another owner install, while downgraded, or lost at a restart | nothing | none | terminal |
- **Mixed versions and downgrade.** There is no wire change. A released
  binary never reads the sidecar or a quarantined copy, so a downgrade
  keeps its share-grant store and its grants as they are. After a re-upgrade, a grant issued
  while downgraded has no entry, so its `deliver_to` daemons get gossip
  only.
- **Security.** The list gives no authority, and the push carries a record
  that gossip delivers to everyone anyway. A corrupt or altered sidecar
  can only add or drop push recipients. An added recipient still passes
  the positive gate in section 1 and learns nothing that gossip does not
  carry. A dropped recipient falls back to gossip. So a quarantine (D120)
  costs only push latency: every revocation still reaches those daemons
  by gossip, and no grant is widened or kept alive.

### 4. Receiver

**Prefix ownership comes first, and it is unconditional.** A payload that
starts with `x0x-grant-revocation-push-v1\0` never reaches DM history or
DM subscribers. This holds:
- on every DM ingress path: the raw direct path and the gossip DM path;
- for verified and unverified frames;
- before and after the inbox is ready, and on success or failure.

Before the typed route is ready, the payload is dropped and counted
`not_ready`. Gossip still carries the record. This case is real: a sender
can still hold the receiver's advert from before a restart (the ADR 0093
TTL is 900 s) and push during the startup window. Today the static
typed-prefix table suppresses only **unverified** frames. A verified frame
with no registered route still falls through to history and subscribers,
and startup supplies an empty route list. The implementation must close
that gap for this prefix.

After ownership, the receiver handles the payload in this order. It stops
at the first failure. Steps 1 to 5 use no signature verify.

1. **Decode.** At most 8 KiB. Decode exactly one `RevocationRecord` and
   consume every byte. Otherwise drop and count `malformed`.
2. **Subject.** `ShareGrant` with a finite `grant_expiry`. Otherwise drop
   and count `wrong_subject`.
3. **Stale.** If the record is past its GC horizon (`grant_expiry` plus
   the existing slack), drop and count `stale`. The grant can no longer
   be honoured.
4. **Known record.** If the record's hash is already in the set, drop and
   count `duplicate`. Every record in the set was verified when it entered,
   so this needs no verify. The test is the **record hash**, not
   `(owner, grant_id)`. A distinct record for the same grant goes on to
   step 6. A retried DELETE makes one (a new `revoked_at`). A distinct
   record may also carry a later `grant_expiry`, and v3 must keep the
   latest horizon.
5. **Rate.** At most 16 pushes per minute from one sending agent, and 256
   per minute in total. Drop the excess and count `rate_limited`.
6. **Ingest.** Hand the one record, as a one-record batch, to the shared
   v3 ingest. That ingest does the **only** verify: the owner's ML-DSA-65
   signature over the record's canonical bytes, and the issuer key must
   hash to the record's `owner`. The push handler has no verify of its
   own. A failure is counted with the forged-v3 counter. A distinct valid
   record is merged through v3: it is kept, and the grant's horizon
   becomes the maximum `grant_expiry`. Persistence follows section 6.
   Everything a v3 insert triggers also fires for a pushed record. That
   includes live-session re-evaluation once ADR 0074 s3 lands. The ingest
   runs in two phases (D139):
   - **6a, insert.** After the verify, insert the record into the
     in-memory revocation set at once, and start live-session
     re-evaluation. This phase never waits for the outbox send gate.
   - **6b, order the outbox.** Then take the outbox send gate
     exclusively, and release it. Only then does the ingest count as done
     for outbox ordering (section 5). 6b runs whenever 6a inserted a new
     record.
   The ingest holds the revocation set only for the insert. It never holds
   the set while it waits for the gate, so the lock order has no cycle.
   The split applies to every remote carrier: the push, `x0x.revocation.v3`
   gossip, and share-grant records on the v1 and v2 carriers. The local
   revoke keeps ADR 0077's order: it takes the gate before it records.

The receiver does not need to hold the grant. A push can arrive before the
grant DM that it revokes. The receiver stores the revocation, and the
existing revocation check refuses the late grant.

The sending agent's identity gives no authority. It is used only for the
rate limit and the counters. A valid record relayed by anyone has the same
effect, because the record carries its own authority.

**The live-session bound starts at receipt (D111, D140).** ADR 0074 s3
closes a live session within 5 s. That bound starts when the host first
receives the record, by push or by gossip, whichever comes first.
- **Receipt** is the first copy that reaches the shared ingest: a pushed
  copy that passes steps 1 to 5, or a gossip batch that holds the record
  (D140). A copy dropped before step 6, as `not_ready` or `rate_limited`,
  starts nothing. The next copy that reaches the ingest starts the bound.
  So during startup or a flood, the bound can slip until gossip or a later
  push arrives. Each drop is counted, by kind, in
  `GET /diagnostics/grants`.
- Live-session re-evaluation runs on the in-memory insert (step 6a). It
  does not wait for the outbox send gate (D139), the coalesced persist
  (section 6) or a store hold. So the bound holds on a daemon whose own
  grant sends hold the gate.
- **The 6b wait is visible.** `GET /diagnostics/grants` lists each ingest
  waiting in 6b as `awaiting_send_gate`, with the record's grant and the
  time the wait began. It waits for this daemon's own in-flight grant
  sends to return, so the outbox send deadline (30 s) plus local I/O
  bounds it. Its exit is the gate. The revocation is already in force
  during the wait.

### 5. Idempotence, replay and ordering

- **Idempotence.** The dedupe key is the record hash. A second push of the
  same record, or its gossip copy, is a duplicate. It changes nothing and
  costs no verify. A distinct record for the same grant, such as one from
  a retried DELETE, costs one verify and is merged by v3. The grant is
  revoked either way. Only its GC horizon can move, and only later.
- **Replay.** A revocation only ever removes access. A replayed valid
  record cannot grant or widen access. It can only re-state a revocation
  the owner signed. Steps 3 to 5 bound the work a replay can cause: a
  stale record is dropped, a known record is dropped before any verify,
  and each sender is rate-limited. The push needs no nonce and no
  recipient binding. The record is public and is gossiped to everyone
  anyway.
- **Order on the owner.** Durable record (ADR 0077), then the v3 gossip
  publish (unchanged), then the push. The push never runs before the
  record is durable. Gossip and push do not wait for each other.
- **Order on the receiver.** Either carrier can arrive first. The result
  is the same.
- **Order against the grant DM.** See section 4: a late grant is refused.
- **Order against outbox redelivery (D139).** A redelivery pass holds the
  send gate shared from its revocation check until its sends return, and
  it re-checks the revocation set before it sends (ADR 0077). A pass that
  checks after step 6a sees the record and skips the grant. A pass that
  checked before 6a may still start its sends, but step 6b waits for it to
  finish. So no send of the grant starts after the ingest is done (6b),
  as before the split. The only change is that enforcement now starts at
  6a instead of after the gate. This relaxes no acceptance rule: the
  verify still comes first, and a revocation only removes access. The
  split is local to each daemon, with no wire or format change, so mixed
  versions are unaffected.
- **Gossip schedule.** The v3 carrier still re-publishes the whole set on
  change and on its fallback tick. This ADR does not change that.

### 6. The revocation store (#1116)

**Today.**
- A `revocations-v3.bin` that fails to decode loads as an empty set
  (fail-open, #1116).
- Every v3 persist re-reads the file. If the file does not decode, the
  writer replaces it with the in-memory set. So any later insert, from any
  carrier, can destroy the corrupt file's bytes.
- Every v3 persist also decodes and re-verifies every record in the file
  and every record in the live snapshot, then rewrites the whole set. For
  a set of N records, that is about 2N signature verifies and one O(N)
  rewrite per persist.

ADR 0098 makes the store fail closed (D23) and decides the recovery. This
ADR does not. It requires only what keeps the push from adding a new
overwrite path or new O(N) work.

**One store.** A pushed record is written only through the shared v3
writer. There is no separate push store and no separate listing. The one
listing that ADR 0098 defines shows pushed records too.

**A shared store-failure latch.**
- There is one latch for the v3 store file. Every v3 writer checks it: the
  local revoke, the v3 gossip ingest, share-grant records that arrive on
  the v1 and v2 carriers, and the push.
- The latch is set when the file fails to load, or when any writer finds
  that the file does not decode.
- While the latch is set, no writer replaces, truncates or renames over
  the file. Its original bytes are preserved for ADR 0098's recovery.
- A writer that is held counts `persist_held`. New records stay in the
  in-memory set, as gossip records do today, so this run fails closed.
  Pushed records do the same under an ADR 0098 hold (D110, below).
- On the owner, a local revoke cannot be durable while the latch is set.
  `DELETE /grants/:id` answers 503, as ADR 0077 requires, and no push is
  sent (section 3).
- Only ADR 0098's recovery clears the latch.

**Bounded persistence work.**
- One verify per distinct new record, in the shared ingest (section 4,
  step 6). Nothing verifies it twice.
- The shared writer coalesces. At most one v3 persist is in flight and at
  most one is pending. A pending persist takes the latest in-memory
  snapshot when it starts. A record that arrives while a persist is
  pending adds no persist work. So at most one snapshot is ever queued.
- A persist triggered only by pushed records starts at most once every
  5 s. A crash inside that window loses only those in-memory records.
  Gossip still carries them.
- The live snapshot is built from verified memory. The writer merges it
  from memory and does not decode and re-verify it.
- The writer re-verifies the disk copy only when its bytes differ from
  what this process last read or wrote. That happens, for example, when
  another process that shares the identity directory wrote it.
- With these rules, a burst of K pushes costs K verifies and at most 2
  persists. A persist costs no verifies unless another process changed
  the file, plus one O(N) rewrite. This ADR does not bound N. With D35's
  90-day maximum lifetime, each record becomes collectable within about
  90 days.
- These writer rules also apply to gossip-triggered persists. They change
  no file format.

**Holds and repair.**
- **During an ADR 0098 hold (D110),** a pushed record enters the in-memory
  set and acts at once. The store file stays untouched, and the latch
  rules above still apply. The record is lost on restart; gossip
  re-delivers it. ADR 0098 must keep this for pushed records.
- A push never lifts the hold. It carries one record and never counts as
  a full re-sync.
- **Gossiped records follow the same rule (D142).** This is a
  requirement on ADR 0098: during its hold, a gossiped record also enters
  the in-memory set and acts at once, with the file untouched. So both
  carriers give the same result, as the Decision Drivers require.
- The push does not repair #1116. It is sent once, at revoke time. It does
  not restore the older records that a lost store held.

### 7. Alignment with ADR 0098 and D35

- This ADR does not depend on ADR 0098 to be correct. David's rulings set
  three points that ADR 0098 must keep: it reuses this push pattern for
  Machine and Agent revocations (D108), and during its hold both a pushed
  record (D110) and a gossiped record (D142) enter the in-memory set and
  act at once. Renewal identity stays with ADR 0098 (D109).
- **No sweep before `not_after`.** Share-grant revocations are already
  collected only at their grant's GC horizon, not by the 90-day sweep. The
  push uses the same horizon. With D35's 90-day maximum lifetime, every
  pushed record becomes collectable within about 90 days.
- **Critical carriers (#1111).** The push complements Critical carriers.
  It does not replace them. D23 requires both before any `shed_normal`
  default.
- **Machine issuer path and lost device (#1108, D108).** This ADR's push
  carries `ShareGrant` records only. ADR 0098 reuses the same pattern for
  Machine and Agent revocations, including the lost-device response: a
  single-record, capability-gated push under its own bit and its own
  prefix, with positive evidence, unconditional prefix ownership, dedupe
  before verify, a rate limit and the shared ingest. ADR 0098 sizes its
  records and names its receivers. This prefix stays `ShareGrant`-only,
  and its receiver keeps refusing other subjects (section 4, step 2).
- **One listing.** Pushed records live in the same set, so they appear in
  the same listing.
- **Renewal (D35, D109).** ADR 0098 decides whether a renewal keeps its
  `grant_id`, and this ADR follows that choice. The wire format holds for
  either choice. If the id is kept, the record's `grant_expiry` must cover
  the latest renewal, and v3 already keeps the latest horizon (section 4,
  steps 4 and 6). If each renewal gets a new id, ADR 0098 defines how one revoke
  covers the chain, and each record it signs goes as its own one-record
  push.

### 8. Sequencing

- ADR 0087 rule 8: this is a wire change. The code merges to `main` only
  after this ADR is Accepted.
- D28 and D114: the code is a new ADR 0070 and ADR 0077 slice, and it is
  not exempt as D23 work. It merges only after the D28 cross-model review
  of ADRs 0070 and 0077 is recorded, even once this ADR is Accepted. Until
  then, revocation stays at gossip speed.
- D23: both this push and ADR 0098's Critical carriers land before any
  `shed_normal` default. So no `shed_normal` default lands before the D28
  review either.
- D112: the `deliver_to` sidecar (section 3a) lands in the same
  implementing slice as the push.
- D139: the split ingest changes the shared revocation barrier and its
  lock order for every remote carrier. The D28 review covers that change,
  and the code waits for it (D114).

## Consequences

### Positive

- At each capable host, the window shrinks from "gossip propagation" to
  "one DM". That includes hosts behind a partition that a direct path still
  reaches.
- Old receivers never see the push. Nothing leaks into DM history or to DM
  subscribers.
- One record per recipient. It fits one DM with a wide margin.
- One verify path, one ingest path and one store. The push adds no durable
  state; the only new file is the local `deliver_to` sidecar (D112), which
  no released binary reads.
- ADR 0098 gets a tested push pattern to reuse for Machine and Agent
  revocations (D108).

### Negative / Trade-offs

- One more typed-DM prefix and one more capability bit to carry.
- A host without the bit, or with unknown capability, gets only gossip.
  During a mixed-version period, many hosts may be in that state.
- The owner learns nothing from a successful push, because there is no
  ACK. The DELETE reports what it scheduled, not what arrived.
- A `deliver_to` daemon that is neither a host nor a grantee agent gets
  only gossip for a grant in state `not_recorded` or `unavailable`: one
  issued before the sidecar existed, issued while downgraded, revoked from
  another owner install, held only in memory across a restart, listed with
  more than 64 agents (D141), in a quarantined file (D120), or present
  while the sidecar is unreadable (section 3a).
- A quarantine loses the lists in that file for good, because no holder
  has a copy (D120, D147, D169). The lifecycle never deletes a
  quarantined copy, so each damaged file leaves one copy of at most about
  2 MiB until an operator removes it (D148).
- The split ingest (D139) changes the shared barrier and its lock order
  for every remote carrier, not only the push.
- The issue call now persists the sidecar before the grant becomes
  visible, so a slow sidecar write delays that issue call (section 3a).
- One store format to add (the sidecar), with its fixture and downgrade
  tests (D112).
- The code waits for the D28 review of ADRs 0070 and 0077, so revocation
  stays at gossip speed until then (D114).
- After a restart, a push to a peer of unknown capability can be up to
  600 s late (D113). Gossip still runs.
- The push does not repair #1116 or #1111. ADR 0098 must still land.
- The latch and the writer rules change the shared v3 writer, so they
  also affect gossip ingest and the local revoke. While the latch is set,
  `DELETE /grants/:id` answers 503 until ADR 0098's recovery runs.
- A receiver downgraded to a build without the route can still get a push
  while the sender holds its earlier advert. That build shows the push as
  an ordinary DM. The advert TTL (900 s) bounds the window.

### Neutral / Operational

- ADR 0077's ordering text stays authoritative. This ADR adds propagation
  only.
- A new `GET /diagnostics/grants` carries the sender counters, pending
  pushes and the last 1,024 outcomes (section 3), the receiver counters
  and `awaiting_send_gate` ingests (section 4), `persist_held`
  (section 6), and the sidecar state, quarantined copies and
  `deliver_to_unavailable` (section 3a). The `POST /grants`,
  `GET /grants` and `DELETE /grants/:id` responses gain the
  `deliver_to_record` state.
- The startup gap in section 4 (a verified frame with no registered route
  reaches history) also applies to the existing production typed
  prefixes. This ADR closes it only for its own prefix.
- **Efficiency (E-D15).**
  - Audience: the recipients of one grant only.
  - Rate: once per revoke per recipient, plus at most 2 retries on a local
    send error.
  - Bytes: about 5.4 KB of record plus about 4.5 KB of DM envelope (an
    ML-KEM-768 ciphertext, an agent ML-DSA-65 signature and headers), so
    about 10 KB per recipient in one direction, and no ACK bytes. These
    figures are estimates from the key and signature sizes, not
    measurements.
  - Verifies: one per distinct new record at the receiver, in the shared
    ingest. A known record costs none. All are counted.
  - Persistence (section 6): today every v3 persist costs about 2N
    verifies and one O(N) rewrite. Under this ADR's writer rules, a burst
    of K pushes costs K verifies and at most 2 persists. A persist costs
    one O(N) rewrite and no verifies, unless another process changed the
    file. Push-only persists start at most once every 5 s. N is not
    bounded here.
  - No new periodic task. The queues are the bounded in-memory pending
    pushes (at most 1,024), at most one pending persist snapshot, and the
    last 1,024 outcomes (D143).
  - Storage (D112, D141): the `deliver_to` sidecar holds at most one entry
    per issued grant (at most 1,024), each at most 64 agent IDs of 32 B,
    so about 2 MiB at most. A revoke reads it once.
  - Compatibility carrier: none. The push is never sent to a peer without
    the bit, so no sunset is needed. The cost of the v3 whole-set
    re-publication is out of scope.

## Validation

Tests for the implementing PR.

**Merge gate.** Cases 12 and 13 are W3-H harness cases (#1164). Each red
variant is committed and shown red on main before this slice's code
merges. A control variant passes on main and must stay green. Cases 1 to
11 are the implementing PR's own tests, and each needs a recorded red run
as marked. Until the harness exists, a tracking issue should list cases 12
and 13 and their variants.

1. **The push alone revokes.** With gossip disabled, a capable host that
   stored the grant stops honouring it after the push. Red: push disabled.
2. **The push arrives before the grant.** The push lands first. The
   delayed grant DM is refused and not stored.
3. **The gate.**
   - A recipient whose current advert lacks the bit gets no push DM.
   - Unknown capability (D113), on a deterministic clock: one refresh is
     requested. A current advert with the bit that arrives before 600 s
     gets the push. With no such advert by 600 s, the push is skipped and
     counted `skipped_unknown_capability`. During the wait,
     `GET /diagnostics/grants` lists the push as `awaiting_capability`
     with its grant, its recipient and its deadline. Afterwards the
     outcome list shows how it ended. Gossip revokes the grant in both
     runs.
   - A card-only claim does not count.
   - A receiver without the route gets nothing in DM history or
     subscribers.

   Red: gate disabled, or a gate that pushes on unknown capability.
4. **Prefix ownership at startup.** A **verified** push frame arrives
   before the inbox is ready, on the raw direct path and on the gossip DM
   path. The sender used the receiver's pre-restart advert. Each frame is
   dropped and counted `not_ready`. Nothing reaches DM history or
   subscribers. An unverified frame and a frame after readiness give the
   same result. Red: ownership limited to unverified frames, as today.
5. **Forged or malformed pushes are refused.** Each case is dropped, counted
   and leaves no state and no DM history: a wrong key, a foreign owner,
   tampered bytes, a non-`ShareGrant` subject, an unknown grant
   (`u64::MAX`), a `Vec` payload, trailing bytes, and an oversize payload.
   Each forged case costs exactly one verify. Red: verify disabled.
6. **Idempotence, horizon and replay.**
   - The same record twice, gossip then push, and push then gossip each
     give one effect. The second copy leaves the verify counter unchanged.
   - Two distinct records for one grant, the second with a later
     `grant_expiry`: both are verified once and kept, and the horizon is
     the later expiry. Red: dedupe on `(owner, grant_id)`.
   - A record past its GC horizon is dropped.
7. **Order against outbox redelivery (D139).** At another owner install,
   a redelivery pass for the grant holds the send gate when a push
   arrives. The record is in the in-memory set at once (6a). The pass
   that checked before 6a finishes, and 6b completes only after it. No
   send of the grant starts after 6b, and a pass that starts after 6a
   skips the grant. Red: an ingest that skips 6b.
8. **The store latch.**
   - Corrupt `revocations-v3.bin`, start the daemon, deliver a push (held,
     `persist_held`), then deliver a distinct gossip record. The file is
     still byte-identical to the corrupt original. Red: today's writer.
   - The same with a local revoke: the DELETE answers 503, no push is sent,
     and the file is unchanged.
   - A failed persist keeps the record in memory and counts it.
   - Once ADR 0098 lands (D110, D142): a push during a hold enters the
     in-memory set, and the host refuses the grant at once. A gossiped
     record during the hold does the same. The file stays byte-identical,
     and the hold stays set. Red: a push or a gossiped record dropped
     during the hold, or one that clears it.
9. **Persistence bounds.** A burst of K distinct pushes gives exactly K
   verifies and at most 2 persists. A persist does not re-verify the live
   snapshot, and it re-verifies the disk copy only after another process
   wrote it. Push-only persists start at most once every 5 s.
10. **The owner.** A DELETE that answers 503 sends no push. Its retry does.
11. **Mixed versions** (sealed testnet, the release-gate row style). 0.45
   and pre-bit 0.46 receivers get no push and no DM history entry, and
   gossip still revokes the grant.
12. **The recorded `deliver_to` list (D112).** A W3-H case.
   - **Nodes.** Four daemons on the candidate build, each advertising the
     bit:
     - O: the owner install, with the user key. It issues and revokes,
       and it holds the sidecar.
     - H: a second install of the same owner. It hosts the shared agent A.
     - G: an agent of the grantee user U. O's discovery cache knows it.
     - D: a second agent of U. It is not in O's discovery cache, so only
       `deliver_to` names it.
   - **Clock and schedule.** One deterministic clock from T = 0 s. Direct
     DMs arrive 100 ms after send. Capability adverts from H, G and D
     reach O at T = 1 s, and again 1 s after each O restart. D's identity
     announcements never reach O. `x0x.revocation.v3` gossip to D is held
     for the whole case. To H and G it flows.
   - **The issue call.** `POST /grants` on O with `grantee_user: U`,
     `agents: [A]`, `caps: ["dm"]`, `ttl_secs: 86400` and
     `deliver_to: [D's agent]`.
   - **"D refuses Gn"** means that D's `GET /grants/received` lists Gn
     with `revoked: true` while v3 gossip to D is still held.
   - Each variant is its own run. Variants 12d, 12d2, 12d3, 12i and the
     second run of 12e need G0 at startup. They seed it in a separate
     clean setup run: start O, issue G0, wait for `recorded`, then stop
     O. Any file change the variant names is made while O is stopped. The
     variant's own run then starts at T = 0 s. Variant 12b issues its own
     G0 during its run, with no setup run.

   Variants:
   - **12a, the list survives a restart (red).** Issue G1 at T = 2 s. The
     response state is `recorded`. Restart O at T = 10 s. Call
     `DELETE /grants/G1` at T = 20 s. By T = 21 s, D refuses G1, and O's
     `GET /diagnostics/grants` shows the outcome `pushed` for D. Red on
     main: there is no push, so D still honours G1.
   - **12b, a paused write and a concurrent DELETE (red).** Issue G0 at
     T = 2 s (`recorded`). A harness fault hook pauses O's next sidecar
     write. Issue G1 at T = 5 s. The call blocks in the paused write.
     - From T = 5 s to T = 15 s, `GET /grants` lists G0 and not G1.
     - `DELETE /grants/G0` at T = 6 s answers 200 by T = 7 s, and D
       refuses G0 by T = 8 s.
     - The hook releases the write at T = 15 s. The G1 call returns
       `recorded`, and `GET /grants` lists G1 as `recorded`.
     - `DELETE /grants/G1` at T = 16 s. D refuses G1 by T = 17 s.

     Red on main: G1 is listed at once, and D refuses neither grant.
   - **12c, a failed write and crashes (red).**
     - The hook fails O's next sidecar write with an I/O error. Issue G2.
       The response and `GET /grants` show `held_in_memory`, cause
       `write_failed`, with the error. `DELETE /grants/G2`: D refuses G2.
     - The hook fails the next write again. Issue G3, then kill O with
       SIGKILL and restart it. `GET /grants` shows G3 as `not_recorded`.
       `DELETE /grants/G3` pushes to H and G only, and D gets no push.
     - The hook pauses the sidecar write for G4. Kill O. After the
       restart, G4 is not listed, and the sidecar's bytes equal the file
       from before the pause.
     - The hook pauses O's share-grant store write for G5, after its
       sidecar write. Kill O. After the restart, G5 is not listed, and the
       sidecar holds no G5 entry after the next persist.

     Red on main: none of these states exists.
   - **12d, a damaged sidecar is quarantined (D120, red).** After the
     setup run, keep the `X0GDT1\0\0` header, overwrite the body with
     random bytes, and record the file's sha256. Start O
     (host-committed) at T = 0 s. The assertions follow D169. Then:
     - `GET /diagnostics/grants` lists one history copy whose sha256
       equals the recorded one. The sidecar state is `ok`, and the
       replacement's `rebuilt_from` lists that copy's `txid`.
     - G0 shows `not_recorded`, cause `quarantined`.
       `DELETE /grants/G0` pushes to H and G only, and D gets no push.
     - Issue G6: `recorded`. `DELETE /grants/G6`: D refuses G6.
     - Restart O. G6 is still `recorded`, and the history copy is still
       there, unchanged.

     Red on main: there is no sidecar and no state.
   - **12d2, a newer format is not quarantined (red).** After the setup
     run, replace the sidecar with a valid `X0GDT2\0\0` file, as a newer
     build would write it. Record its sha256. Start O at T = 0 s. The
     sidecar shows `sidecar_newer_format { file, version: 2 }`, and no
     quarantined copy exists. G0 shows `unavailable` with that state.
     `DELETE /grants/G0` pushes to H and G only and counts
     `deliver_to_unavailable`. Issue G6b: `held_in_memory` with that
     state. `DELETE /grants/G6b`: D refuses G6b. At the end, the file's
     sha256 is unchanged. Red on main: there is no sidecar and no state.
   - **12d3, a read error (red).** G0 is durable from the setup run. In
     the faulted run, a hook fails O's sidecar reads with an I/O error.
     Start O at T = 0 s. The sidecar shows
     `sidecar_unavailable { file, cause: read_error }`, and G0 shows
     `unavailable` with that state. Issue G12 at T = 10 s:
     `held_in_memory` with that state, and `DELETE /grants/G12` reaches
     D. Release the hook and restart O at T = 40 s. The next load reads
     the file: G0 shows `recorded`, G12 shows `not_recorded`, cause
     `absent`, because it was held only in memory, and no quarantined
     copy exists. Red on main: there is no sidecar and no state.
   - **12i, the shared lifecycle's fault cases (D120, red).** This ADR
     instantiates every W3-H fault case of ADR 0108 §5a for
     `share-grants.deliverto`, with G0 seeded in the setup run. The header
     forms are `X0GDT` (cut short), `X0GDT1` (6 bytes), `X0GDT0\0\0`,
     `X0GDTx\0\0` (not a digit), `X0GDT1\0\x01` (bad padding), a file
     without the prefix, and a version 1 body with trailing bytes. A valid
     `X0GDT2\0\0` file is the control, as in 12d2. Besides §5a's
     assertions, each run checks this ADR's outcome by its kind:
     - **Replacement runs.** §5a writes a replacement at step 4: the file
       was damaged at load, or a pending copy sits beside a missing file.
       The loss outcome of 12d applies. G0 has no list and shows
       `not_recorded`, cause `quarantined` in that run. A new issue is
       `recorded`, and `DELETE /grants/G0` pushes to H and G only.
     - **Finalize-only runs.** §5a finds a pending copy beside a healthy
       file and only finalizes the copy as history. The file stays
       byte-identical, and no replacement is written. When the healthy
       file is not from this transaction and still records G0, G0 stays
       `recorded`, and `DELETE /grants/G0` reaches D. When the healthy
       file is this transaction's completed replacement, it stands
       unchanged: G0 still has no list, and its revoke pushes to H and G
       only. No loss is asserted for a grant whose list the healthy file
       holds.
     - **Failure runs.** §5a stops in a failure state. A file still at
       its path stays byte-identical. G0 shows `unavailable` with that
       state. A new issue is `held_in_memory` with that state, and its
       revoke still reaches D.

     Red on main: there is no sidecar, no quarantine and no state.
   - **12e, the host-commit wait (red).** O starts the candidate as an
     ADR 0094 update that is not yet host-committed. Issue G7:
     `held_in_memory`, cause `awaiting_host_commit`, and no sidecar file
     is written. `DELETE /grants/G7`: D refuses G7. The harness completes
     the host commit. Issue G8: `recorded`, and the sidecar exists. In a
     second run, the sidecar body is damaged at start. The sidecar shows
     `sidecar_unavailable { file, cause: awaiting_host_commit }`, G0
     shows `unavailable` with that state, and nothing is moved until the
     host commit. After it, the quarantine runs, and G0 shows
     `not_recorded`, cause `quarantined` (D169).
     Red on main: none of these states exists.
   - **12f, a downgrade (control).** The candidate O issues G9
     (`recorded`) and stops. The released v0.46.1 binary starts on the
     same data dir. It lists G9 in `GET /grants` with no `store_error`.
     After it stops, the sidecar's sha256 is unchanged. The candidate
     starts again and shows G9 as `recorded`. ADR 0085 rule 6: the `X0SG`
     fixture from the released encoder still loads. Control: on a data
     dir from main, the released binary gives the same result.
   - **12g, two issues that complete in reverse order (red).** At
     T = 2 s, issue G10. The hook pauses its sidecar write after the
     snapshot is taken. At T = 3 s, issue G11. Release G10's write at
     T = 10 s. Both calls return `recorded`, and G11's call returns no
     earlier than G10's write completes. Restart O at T = 12 s.
     `GET /grants` shows G10 and G11 as `recorded`, and the sidecar holds
     both entries. Revoke both: D refuses both. Red on main: there is no
     sidecar. It is also red against a writer that does not serialize
     snapshots, because G10's stale snapshot overwrites G11's entry and
     the restart loses it.
   - **12h, the list cap (D141, red).** Issue G14 with `deliver_to` naming
     D and 64 more agent IDs, 65 in all. D receives the grant DM. The
     response and `GET /grants` show `not_recorded`, cause `over_cap`.
     `DELETE /grants/G14` pushes to H and G only, and D still honours G14
     while v3 gossip to D is held. Issue G15 with D and 63 more, 64 in
     all: `recorded`, and its revoke reaches D. Red on main: there is no
     state and no push.
13. **The live-session bound from receipt (D111).** A W3-H case. It needs
   ADR 0074 s3.
   - **Nodes.** Three daemons on the candidate build, each advertising the
     bit: O (the owner install, which issues and revokes), H (a second
     install of the owner, which hosts agent A, with a loopback TCP echo
     target on port p), and G (the grantee agent's daemon).
   - **Connect fixtures.** G and H each start with a connect ACL that sets
     `[connect] enabled = true`. H's ACL also has one
     `[[connect.allow]]` entry with `principal = "grant"` and
     `targets = ["127.0.0.1:p"]`. Without both, `POST /forwards` answers
     409 or the grant authorises nothing (see the grant principal in
     [the connect ACL](../connect-acl.md)).
   - **Clock and schedule.** One deterministic clock from T = 0 s. Direct
     DMs arrive 100 ms after send. Capability adverts reach O at T = 1 s.
   - **Steps.** At T = 2 s, `POST /grants` on O with `grantee_agent: G`,
     `agents: [A]`, `caps: [{"connect": {"ports": [p]}}]` and
     `ttl_secs: 86400`. At T = 4 s, `POST /forwards` on G to A, port p.
     The harness opens a TCP connection through G's forward and sends
     1 KiB every 100 ms. Before T = 10 s, the harness checks that the
     stream is up: each 1 KiB echoes back, and H's
     `GET /diagnostics/connect` counts the stream as allowed. If not, the
     run is invalid, not a pass. At T = 10 s, `DELETE /grants/:id` on O.
   - **Assertion.** Let t0 be the time the first copy of the record
     reaches H. The harness connection is reset by t0 + 5 s, and H counts
     one live-stream teardown.

   Variants:
   - **13a, push only (red).** v3 gossip to H is held for the whole case.
     The push reaches H at t0 = 10.1 s. Red on main: there is no push, so
     the stream runs on.
   - **13b, gossip only (control).** The harness drops O's push frames to
     H. The v3 gossip batch reaches H at t0 = 12 s. Control: it passes on
     main once ADR 0074 s3 is there.
   - **13c, a slow persist (red).** As 13a, with H's `revocations-v3.bin`
     write paused for 30 s. The stream is still reset by t0 + 5 s. Red on
     main: there is no push. It is also red against an implementation
     whose re-evaluation waits for the persist.
   - **13d, a daemon that is sending grants (D139, red).** H holds the
     owner's user key. At T = 8 s, `POST /grants` on H issues a grant to
     an agent X whose DMs the harness holds, so H's delivery holds the
     outbox send gate until its 30 s send deadline. The push reaches H at
     t0 = 10.1 s, and v3 gossip to H is held. The stream is reset by
     t0 + 5 s, while H's `GET /diagnostics/grants` still lists the ingest
     as `awaiting_send_gate`. That entry clears once H's send to X returns,
     by about T = 38 s plus I/O. Red on main: there is no push. It is also
     red against an ingest that inserts only after the gate, because the
     reset then comes near T = 38 s.
   - **13e, a rate-limited copy starts nothing (D140, red).** Before
     T = 10 s, O sends H 16 pushes for 16 other revoked
     grants, within one minute. The push for this grant reaches H at
     T = 10.1 s and is dropped as `rate_limited`. The v3 gossip batch
     reaches H at t0 = 14 s. The stream is reset by t0 + 5 s, and H counts
     one `rate_limited` drop. The assertion holds the bound from the
     gossip copy, not from the dropped push. Red on main: the
     `rate_limited` count does not exist.

   If ADR 0074 s3 is not on main when this slice is ready, 13a and 13c
   are still committed and shown red on main, because no teardown exists
   there. 13b then becomes a control when s3 lands.

**Revisit** when ADR 0098 is drafted, when renewal is designed, or if
`Outbox<T>` makes a durable push cheap.

## Rulings and open questions

**Blocking David's Accept:** only the cross-model review named under
Reviewers. No open question remains. The code also waits for the D28
review of ADRs 0070 and 0077 (D114).

David ruled Q1–Q7 on 2026-10-04 (D108–D114):

- **Q1, lost device:** reuse the push. ADR 0098 uses the same
  single-record, capability-gated push for Machine and Agent revocations,
  under its own bit and prefix, and sizes its records and receivers
  (D108; section 7).
- **Q2, renewal:** left to ADR 0098. This ADR follows its choice of
  renewal identity (D109; section 7).
- **Q3, pushed records during a store hold:** a pushed record enters the
  in-memory set and acts at once. The file stays untouched, and a push
  never lifts the hold (D110; section 6).
- **Q4, live sessions:** the ADR 0074 s3 5 s bound starts when the host
  first receives the record, by push or gossip (D111; section 4). D139
  and D140 settle the two cases the earlier text could not meet.
- **Q5, `deliver_to`:** recorded in the implementing slice, as a versioned
  share-grant store change under ADR 0085 (D112; section 3a). It is a
  new sidecar, not a new `X0SG` magic, so a downgraded v0.46.1 keeps its
  grants.
- **Q6, the gate:** confirmed. Push only on positive evidence, and wait up
  to 600 s for a peer of unknown capability (D113; sections 1 and 3). The
  bit number is still fixed at acceptance.
- **Q7, the D28 hold:** the slice waits. Code merges only after the D28
  review of ADRs 0070 and 0077 is recorded (D114; section 8).

David ruled the round-2 questions on 2026-10-04 (D120, D139–D143):

- **D139, the 5 s bound on a daemon that is sending grants:** split the
  ingest. A remote record enters the in-memory set and starts
  re-evaluation at once (6a), then takes the send gate for outbox
  ordering (6b) (section 4, step 6; section 5).
- **D140, valid copies dropped before the ingest:** excluded. The bound
  starts at the first copy that reaches the ingest. In startup or a
  flood it can slip until gossip or a later push arrives (section 4).
- **D141, the list cap:** 64 agents. A longer list is still delivered but
  not recorded: `not_recorded`, cause `over_cap` (section 3a).
- **D142, gossiped records during a store hold:** the same rule as pushed
  records. This is a requirement on ADR 0098 (sections 6 and 7).
- **D143, recent outcomes:** keep the last 1,024 in memory, oldest out
  first (section 3).
- **D120, an unreadable sidecar:** quarantine and rebuild, against the
  recommendation. Applied to the quarantine of this ADR's one sidecar, the
  `deliver_to` list (section 3a), through the shared lifecycle of ADR 0108
  §5a. A damaged file is moved aside byte-identical. A valid newer
  version is never quarantined, so ADR 0085 rule 5 holds. The rebuild
  part cannot be met as written, because no holder has the lists; D169
  settles what replaces the file. This ADR is not an ADR 0088 slice, so
  it adds no ADR 0088 §2 entry.

David ruled the round-3 questions on 2026-10-04 (D147, D148, D169):

- **D169, lost `deliver_to` lists:** an empty replacement. The lists in
  a quarantined file are lost, and those grants become `not_recorded`,
  cause `quarantined`. Revocation still reaches their `deliver_to`
  daemons by gossip. No second local copy is kept (section 3a).
- **D147, local-only state lost to a corrupt file:** the stated outcome
  is accepted. The loss ends in a typed state with a stated next step,
  gossip at revoke, and nothing is silently trusted (section 3a).
- **D148, keeping quarantined copies:** kept until an operator removes
  them, by ADR 0108 §5a's rule. This file belongs to no group.
  Diagnostics list each copy with its size (section 3a). The earlier
  retention question is dropped.
- With D169, the ADR 0085 rule 4 amendment for `share-grants.deliverto`
  is complete, ruled by David (D120, D169).

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human review**. Accepted ADRs are immutable: create a new superseding ADR rather than editing an Accepted ADR.
