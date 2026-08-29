# ADR 0055: File Transfer Is a DM-Chunked, SHA-256-Verified Protocol with a 1 GiB Cap

- **Status:** Proposed
- **Date:** 2026-08-29
- **Decision owners:** David Irvine (direction), omp (drafting)
- **Reviewers:** pending
- **Supersedes:** none
- **Superseded by:** none
- **Related:** ADR-0050 (DM base transport); `docs/primers/files.md`. Backfill record for shipped behavior.

## Context

`src/files/` and `src/server/routes/files.rs` implement peer file transfer
with no deciding ADR. The wire is JSON-tagged `FileMessage` frames
(offer/chunk/complete/accept/reject/ack, `src/files/mod.rs:194-230`) carried
over the DM transport; chunks ride a live raw-QUIC path when available with
capability-aware gossip fallback (`src/server/routes/files.rs:40-45`).

## Decision Drivers

- Reuse the authenticated/encrypted DM plane instead of a new secured
  channel.
- Receiver must prove complete-file integrity before a transfer counts.
- Host resources need explicit bounds.

## Considered Options

1. QUIC-stream file protocol with its own framing/auth.
2. Gossip messages with no whole-file integrity binding.
3. DM-framed offer/chunk/ack with whole-file SHA-256 and size caps
   (chosen).

## Decision

1. A `FileOffer` binds transfer ID, filename, declared size, complete-file
   SHA-256, chunk size, and chunk count (`src/files/mod.rs:36-48`); the
   receiver approves before any data flows (`docs/primers/files.md`,
   "How file transfer works").
2. Chunk size is 32 KiB (`DEFAULT_CHUNK_SIZE`, `src/files/mod.rs:20`),
   chosen so base64 JSON framing fits the 49,152-byte DM payload limit —
   the earlier 64 KiB chunks overflowed it (`src/files/mod.rs:12-18`); at
   most 8 chunks are in flight pending receiver acks
   (`FILE_CHUNK_WINDOW`, `src/server/routes/files.rs:55-58`).
3. Received offers above `MAX_TRANSFER_SIZE` (1 GiB,
   `src/files/mod.rs:23`) are rejected before state is created
   (`src/server/routes/files.rs:547-554`). Chunks write to a `.part` path
   through an incremental SHA-256 (`src/server/routes/files.rs:1019-1116`);
   on final mismatch the partial file is removed and the transfer marked
   `Failed` (`src/server/routes/files.rs:1163-1176`).
4. Trust: offers from a contact recorded as `TrustLevel::Blocked` are
   rejected (`src/server/routes/files.rs:531-535`); unknown contacts are
   not rejected by this gate — receiver approval is the consent step.

## Consequences

### Positive

- No new security surface; integrity is end-to-end and verifiable;
  caps bound disk and memory.

### Negative / Trade-offs

- No resume, no streaming read, in-memory transfer state only
  (`docs/primers/files.md`, "Current limits").

### Neutral / Operational

- The primer's "64KB chunks" examples are stale; the shipped value is
  32 KiB.

## Validation

- `src/server/routes/files.rs` offer/chunk/mismatch tests; primer CLI/REST
  walkthrough.

## Notes for AI-assisted work

AI tools may draft this ADR but must not mark it Accepted without human
review. Accepted ADRs are immutable — supersede, don't edit.
