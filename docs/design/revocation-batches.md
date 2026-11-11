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

One record that is larger than the batch size goes in a batch of its own.

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

- `n` — the number of batches in the round, decimal, 1 to 4096, no leading
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
