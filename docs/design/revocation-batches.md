# Revocation batches and the round marker (#1857)

Status: built. Decided 11 Nov 2026 by the coordinating Claude session under
David's delegation of 10 Nov 2026. The rule is in A03 (Revocation).

## Why

A daemon sends its revocation set on three gossip topics
(`x0x.revocation.v1`, `.v2`, `.v3`). One message is one batch: a bincode
`Vec<RevocationRecord>`. A receiver ignores a batch above 2 MiB (about 380
records). Revocation records are not removed by age (#1108), so a set can
pass that size. Before #1857 such a set was one batch that every peer
ignored, and no revocation from that daemon reached any peer.

## What a daemon sends

| Set | What goes out |
|---|---|
| Fits in one batch (at most 2 MiB less 64 KiB of records, about 370 records) | One batch, with no marker. The bytes are the same as before #1857. |
| Larger | A **round**: several batches. Each batch holds records in record-hash order and ends with one **round-marker record**. |

One record that is larger than the batch size goes in a batch of its own,
with its marker.

**A record that cannot be sent.** A record that is over the receive limit
by itself (only a record from an old store can be) is not sent: no receiver
accepts a batch that holds it. Its hash **stays in the round's `set`**, and
every batch of that publish carries a marker, also when only one batch is
left. The offered records then never match `set`. So:

- peers still get every other record by ordinary gossip;
- **no daemon that waits for a resync can open from this sender**, new or
  released. That is correct: it would otherwise open with that subject not
  revoked;
- the sender logs the record hash at WARN on every publish, and
  `GET /identity/revocations` shows the count as `unsendable_records`.

What an operator does: revoke the subject again with a short reason. The
set prefers a record with a reason inside the limit for the same subject
and issuer, so the new record takes the place of the large one, and the
sender can resync a waiting peer again.

A daemon publishes a set as one step: it reads the set, encodes it and
sends every batch while it holds one lock for that agent's set. The
heartbeat, a new revocation and a share-grant revocation use the same
lock, so parts of two rounds are not sent mixed together.

## The round-marker record

A marker is an ordinary `RevocationRecord` value, so the batch format does
not change. It is the last element of the batch. It can never verify.

| Field | Value | Bincode bytes |
|---|---|---|
| `subject` | `RevokedSubject::Machine(MachineId([0; 32]))` | `01 00 00 00` (variant 1), then 32 zero bytes |
| `issuer_public_key` | the 30 ASCII bytes `x0x-revocation-round-marker-v1` | `1e 00 00 00 00 00 00 00` (length 30), then the 30 bytes |
| `revoked_at` | `0` | 8 zero bytes |
| `reason` | `Some(text)`, see below | `01`, then the length as 8 bytes little-endian, then the text |
| `signature` | empty | 8 zero bytes (length 0) |

The `reason` text is one line of four words, with one space between them:

```
x0x-revocation-round-v1 n=<batches> i=<index> set=<digest>
```

- `n` — the number of batches in the round, decimal, 1 to 512, no leading
  zero.
- `i` — the index of this batch, decimal, 0 to `n` − 1, no leading zero.
- `set` — 64 lower-case hex characters: BLAKE3 over the bytes
  `x0x-revocation-round-set-v1` followed by every record hash of the
  sender's set for this carrier, in ascending order. A record hash is
  BLAKE3 of the record's signed bytes (`RevocationRecord::record_hash`).

A marker is about 210 bytes. A receiver knows a marker by its exact
`issuer_public_key` value. A real ML-DSA-65 public key has 1952 bytes, so
no real record has that value. A record with that value and any other
shape (another subject, a non-zero time, a signature, a `reason` that is
not the exact text) is a bad marker: it is removed, and its batch is never
a resync snapshot.

## What a receiver does

**Ordinary receipt (every daemon).** The marker is removed when the batch
is decoded. It is not verified, stored, listed, counted or sent again. The
other records are handled as before. A marker that reaches the store or a
single-record path is refused with a WARN log line.

**A daemon that waits for a resync** (its revocation store was unreadable,
A03). It opens a carrier only from a sender that is a trusted authority:

- A batch with **no marker** is the sender's whole set. The rule of #1116
  applies as before.
- A batch with a **marker** is one part of a round. The daemon keeps one
  open round for each sender and carrier. A part of another round (another
  `set` or `n`) replaces the open round; parts of two rounds are never
  put together. The same index with other content is refused.
- The round is a snapshot only when the daemon holds all `n` parts and the
  digest of all the offered record hashes equals `set`. Then the #1116
  rule applies to the union. A lost first, middle or last batch leaves the
  carrier closed until the sender's next full publish (at most 2 hours).
  The daemon logs this state at WARN after each part.
- A marker from a sender that is not a trusted authority is ignored.
- A newer batch from a sender, marked or not, replaces what that sender
  offered before. An older whole set never opens the carrier after it.
  One exception: a part of the round that the daemon already holds
  complete (the same `set`) changes nothing, because the sender publishes
  the same set again every 2 hours.
- A batch from a trusted sender that the daemon cannot use (a bad marker,
  a count or index out of range, a record of another carrier, an empty
  batch) also removes what that sender offered before (#1864). The batch
  shows that the sender's set has changed, so the earlier offer is stale.
  The carrier stays closed for that sender until it sends a set that the
  daemon can read.
- **A held record that the sender has replaced (#1864).** The #1116 rule
  refuses a snapshot that omits a revocation the daemon holds. A held
  record is not omitted when the snapshot has a record for the same
  subject and issuer that the daemon keeps in its place (the order rule
  of #1857). The offer then stays, the ingest admits that record, and the
  carrier opens when the daemon's held records equal the snapshot's kept
  records, each one verified. A snapshot whose record for the pair is
  worse than the held one is still refused.

Bounds on what a waiting daemon holds for one sender and carrier:

| Bound | Value |
|---|---|
| Open rounds | 1 |
| Batches in a round (`n`) | at most 512. This is the real limit for an honest sender: about 190,000 records. A sender with a larger set cannot resync a waiting peer; it logs that at WARN. Its markers are bad markers for the receiver, so they also remove what that sender offered before. |
| Records in an open round | at most 262,144 (512 batches of 512 records, about 30 MB of hashes and order keys); over that the round is dropped. A full batch of real records holds about 370, so a round inside the batch limit is always inside this one. A part that arrives again at the same index is counted once. |
| Time with no new part | 10 minutes; a part that arrives later starts the round again |

The records of a part are not verified when the part is recorded; they are
verified when they are ingested. Only a trusted authority can fill this
state.

## Self-revocations of strangers (#1863)

Any key can revoke itself, and each new key is a new (subject, issuer)
pair. Without a limit, one new key and one signature put about 5.3 KB in
every daemon's store for good, and every daemon sent it again every 2
hours. Decision (Claude, under David's delegation of 10 Nov 2026):

- A daemon keeps the self-revocation of a **stranger** in force and in its
  store, but leaves it out of the set that it publishes. Pubsub spreads the
  record once when it is first sent. A daemon that was offline then does
  not learn it from the 2-hour publish.
- A subject is **seen**, and its self-revocation is published, when this
  daemon has a **relationship** with it that a peer cannot create alone
  for a fresh key (decided 11 Nov 2026, #1868 review round 2). The gossip
  ingest, the local apply path and the heartbeat use this one rule.

  | Subject | Seen when | Can a peer with no relationship make it for a fresh key? |
  |---|---|---|
  | agent | it is this daemon's own agent | no |
  | agent | a contact with trust Known or Trusted | no: only the local user sets this (REST, CLI, GUI) |
  | agent | in this owner's issued-certificate journal | no: only this owner writes it |
  | agent | an active or removed member of a named group that this node is an active member of and that needs approval to join (not `OpenJoin`) | no; but an admin of such a group can add members (see below) |
  | machine | it is this daemon's own machine | no |
  | machine | in this owner's verified device roster | no: needs this owner's signed enrollment |
  | machine | listed on a Known or Trusted contact | no; but that contact can list a new machine (see below) |

  **Not seen:** the discovery caches, an Unknown or Blocked contact, a
  pending entry (a join request) or a banned entry in a group, any member
  of an `OpenJoin` group. A verified announce from a fresh key fills the
  discovery caches and makes an Unknown contact entry with its machine;
  applying a revocation blocks its subject as a contact. None of these is
  a relationship.

  A removed group member counts because the revocation path removes a
  revoked member; in a group that needs approval, a member was admitted
  by an invite, an approval or the owner rule before it could be removed.

  **Remaining trust in related peers.** An admin of a group that this
  node is in can add fresh keys as members, and a Known or Trusted
  contact can announce fresh machines. Their self-revocations are then
  published. This needs a relationship that the local user or owner made.
- Applying a revocation blocks its subject as a contact, so a Known
  contact is no longer a relationship after that. A daemon checks the
  rule **before** that change, and keeps the result in memory. The
  heartbeat checks again every 10 minutes. A record whose subject gets a
  relationship later (for example the user raises a contact to Known) is
  published at the next heartbeat.
- A mark changes the set's generation, so the next heartbeat publishes.
- A self-revocation that this daemon applies itself (an operator revokes
  this agent or machine) is marked at once and is in the immediate publish.
- The mark is in memory only. After a restart, a subject whose only
  relationship was a Known or Trusted contact is a stranger again (the
  revocation blocked the contact), and its record is no longer published
  by this daemon. An agent of this owner, an owner machine and a group
  member stay seen.
- Owner revocations, binding tombstones and share-grant records are always
  published.
- No disk bound: removing a record would make its subject valid again.
  `GET /diagnostics/gossip` shows the number of held stranger records as
  `identity_authority.revocation_stranger_self_held`.

**The resync rule changes for self-revocations only.** A daemon that waits
for a resync compares the sender's set with its held records. The sender
now leaves out strangers, so a waiting daemon that holds a stranger's
record (from the one pubsub spread) would never open. So a held
self-revocation for which the sender's set has **no record of the same
subject and issuer** does not block opening, in both checks (the cover
check and the equality check). Every other held record keeps the exact
rules. Opening never removes a held record, so an ignored record stays in
force. The cost: an omitted self-revocation is no longer a sign that the
sender is behind.

**Known gap.** A waiting daemon that lost a self-revocation for a subject
that only it knows does not get the record back from senders to whom the
subject is a stranger. It opens without that record. Follow-up:
[#1867](https://github.com/saorsa-labs/x0x/issues/1867).

**Known stall: an empty published set.** A sender whose held v1 records
are all self-revocations of strangers publishes an empty set, and an
empty batch never opens a waiting carrier. If every trusted sender is in
that state, a waiting daemon stays closed (fail closed) until a sender
has a record that it publishes. Whether a signed empty statement from an
authority should open a waiter is open in
[#1867](https://github.com/saorsa-labs/x0x/issues/1867).

**Mixed versions.** A released daemon (v0.48.1 and earlier) that waits for
a resync compares exact record sets. If it holds a stranger's
self-revocation, it cannot open from a new sender, only from a released
sender that still publishes the record. It stays closed (fail closed)
until a released sender publishes, or it is upgraded. This is accepted.

## A legacy record with a long reason

A new record's `reason` is at most 1024 bytes. A store from a released
daemon can hold a record with a longer reason. That record stays in force
on the daemon that holds it, and it is sent to peers.

- A daemon that waits for a resync admits it from a trusted authority,
  also when it takes the place of a long-reason record that the daemon
  already holds for the same subject and issuer.
- **A daemon that is not waiting refuses it from gossip.** A new or freshly
  installed daemon therefore does not learn that a subject is revoked when
  the ONLY record for it has a long reason.

This is accepted: without a limit, one signature could put megabytes in
every daemon's store for good, and no released code path makes a long
reason by itself (the text comes from an operator). What an operator does:
revoke the subject again with a short reason. The set prefers a record
with a reason inside the limit for the same subject and issuer, so the new
record takes the place of the long one and reaches every peer.

## Known limit: a bad clock at load

The order between two records of one subject and issuer puts a record
with a credible time before a record with a far-future time, by the local
clock. A daemon whose clock is far behind at load can see a normal record
as far in the future. If the store also holds a legacy long-reason record
for the same subject and issuer, both are then "not credible", the short
one wins the pair, and the far-future sweep at load drops it. The subject
is then not revoked on that daemon until gossip brings the record again.
This needs a legacy long reason and a clock that is wrong by more than the
record's age. A daemon before #1857 also drops far-future records at load
by design; it would have kept the other record of the pair.

## Released daemons

Read at tags `v0.48.1` and `v0.46.0` (files as of each tag):

| Path | Function | A record that does not verify |
|---|---|---|
| v1 | `apply_legacy_revocation_records` in `src/lib.rs` (`v0.48.1`); the `DiscoveryMessage::Revocation` arm of the identity listener (`v0.46.0`) | Rejected alone, `debug!("revocation record rejected")`. The other records are applied. No penalty. |
| v2 | `apply_v2_revocation_records` (`v0.48.1`); the `DiscoveryMessage::RevocationV2` arm (`v0.46.0`) | Rejected alone, `debug!("v2 binding revocation rejected")`. |
| v3 | `ingest_share_grant_revocations` (both tags) | A record that is not a share-grant subject is skipped with no log line. |
| Waiter | `observe_remote_carrier_snapshot` and `try_complete_carrier` in `src/revocation.rs` (`v0.48.1`; `v0.46.0` has no waiter) | The carrier opens only when the held record hashes equal a trusted snapshot's hashes. The marker is never held, so a marked batch never opens the carrier. On v2 and v3 the marker is not a subject of that carrier, so the snapshot is ignored. |

The pubsub layer (saorsa-gossip-pubsub 0.5.86 and 0.5.90) scores a peer
only for a bad signature on the pubsub message
(`record_invalid_message` after `verify_message_signature`). It does not
read the payload.

So for a released daemon: a set of one batch is the same bytes as before;
a set above one batch, which did not arrive at all before, now arrives by
ordinary gossip, and a released daemon that waits for a resync stays
closed against it, as before.

Not read: the tags between `v0.46.0` and `v0.48.1`.
