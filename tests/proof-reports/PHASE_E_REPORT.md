# Phase E Proof Report — Public-Group Messaging

> **Honesty clause.** Phase E delivers the signed public-message plane
> and its write-access + banned-author enforcement truth-table. It does
> **not** claim anything C.2 hasn't proven (discovery stays under C.2's
> open proof-debt in `.planning/c2-proof-hardening.md`). Claims here
> are bounded to what Phase E adds.

## Scope of E

Per `docs/design/named-groups-full-model.md` §"Public groups":

1. `GroupPublicMessage` — signed wire type with
   `state_hash_at_send` / `revision_at_send` binding to the D.3 chain.
2. ML-DSA-65 signing + standalone verification (signer public key
   embedded, `author_agent_id` ↔ derived-from-key binding checked).
3. Ingest validator with write-access truth-table:
   - `MembersOnly` → only active members send;
   - `ModeratedPublic` → any non-banned author;
   - `AdminOnly` → active `Admin` or `Owner` only.
4. `Banned` authors rejected in every mode.
5. `POST /groups/:id/send` endpoint-side enforcement mirroring the
   ingest validator, signs + publishes + caches.
6. `GET /groups/:id/messages` — returns the per-group ring buffer
   (cap 512). Public `read_access` opens it to non-members with a
   valid API token; `MembersOnly` requires active membership;
   `MlsEncrypted` groups return 400.
7. Public-chat listener validates each incoming message against the
   **current** group view before caching so ban/role changes take
   effect on receive.

## Explicit claims

1. **Sign/verify integrity.** Every field of `GroupPublicMessage`
   (group_id, state_hash_at_send, revision_at_send, author_agent_id,
   author_public_key, author_user_id, kind, body, timestamp) is
   covered by the signature; tampering any field fails
   `verify_signature()`.
2. **Author binding.** `author_agent_id` must equal the AgentId
   derived from `author_public_key`; swapping either alone is
   detected.
3. **Confidentiality gate.** `validate_public_message` returns
   `ConfidentialityMismatch` if the group is not `SignedPublic`; the
   `/send` endpoint returns 400 with the same intent.
4. **group_id match.** `GroupIdMismatch` rejection if the embedded
   `group_id` does not equal the group being delivered to.
5. **Banned author.** Rejection in every `write_access` mode
   (`MembersOnly`, `ModeratedPublic`, `AdminOnly`).
6. **MembersOnly rejects non-members.**
7. **ModeratedPublic accepts non-members (non-banned).**
8. **AdminOnly rejects plain members AND non-members.**
9. **AdminOnly accepts Admin AND Owner.**
10. **Size bound.** Bodies exceeding `MAX_PUBLIC_MESSAGE_BYTES` (64 KiB)
    return `MessageTooLarge`.
11. **Receive-side revalidation.** The public-chat listener looks up
    the current `GroupInfo` on every inbound message and revalidates;
    a message whose author is now banned is dropped.
12. **Public read honoured.** `GET /groups/:id/messages` returns cached
    history to a non-member when `read_access == Public`; rejects
    non-members when `MembersOnly`.

## Explicit non-claims

- No moderation tooling (admin "delete message" / "mute user"). Ban
  already gates ingest and endpoint; granular moderation is follow-up.
- No history backlog sync — a new peer sees only messages that arrive
  after their listener starts. History replication for late joiners
  is future scope.
- No federation with external directory servers.
- Anything C.2-related (shard convergence, LTC positive delivery,
  restart persistence) remains C.2's open proof-debt and is unchanged
  by Phase E.

## Evidence — unit + integration

- `src/groups/public_message.rs`: **19 unit tests** covering sign/
  verify roundtrip, tamper detection on body / group_id / kind /
  author, ingest truth-table for all three write_access values
  against active/banned/missing/admin/owner authors, confidentiality
  gate, oversize rejection, and preset shape assertions.
- `tests/named_group_public_messages.rs`: **14 integration tests**
  covering the same surface at the crate-public API plus a loop
  asserting banned authors are rejected in every `write_access`
  mode.
- `cargo fmt --all -- --check`: clean.
- `cargo clippy --all-features --all-targets -- -D warnings`: clean.
- `cargo nextest run --lib --test api_coverage
  --test named_group_public_messages --test named_group_state_commit
  --test named_group_discovery`: all pass (combined count at HEAD
  reported in commit message).

## Evidence — end-to-end

`tests/e2e_named_groups.sh` new **Phase E section** (~100 assertions
added over D.3/C.2 sections) exercises on three fresh daemons:

- Owner publishes to `public_open` (MembersOnly) — accepted.
- Non-member bob retrieves `/messages` on Public read — allowed.
- Non-member bob tries to `/send` to MembersOnly — rejected.
- Owner publishes announcement on `public_announce` (AdminOnly) —
  accepted.
- Plain-member bob tries to publish an announcement — rejected.
- `MlsEncrypted` group: `/send` rejects, `/messages` rejects.
- `ModeratedPublic` group: non-member bob sends successfully; owner
  bans bob; bob's subsequent send is rejected (live ingest-side
  enforcement of the ban).

Three archived clean runs under
`tests/proof-reports/named-groups-e-run{1,2,3}.log`.

### Honest run-summary framing

The overall suite still contains the same ~32 pre-existing
environment-dependent failures in sections 2 / 5 / 7 (P0-1 discovery
timing, P0-6 patch convergence, authz 404 checks). They are **not** E
regressions. The Phase E section itself is clean (all checks pass on
each run). The report documents this split explicitly — we are
**not** calling the whole suite clean.

## Live paths using Phase E

- `POST /groups/:id/send` signs + publishes + caches for SignedPublic.
- Public-chat listener validates + caches incoming messages.
- `GET /groups/:id/messages` serves the ring buffer under read policy.
- Ban enforcement: publish-time (endpoint-side) + ingest-time
  (validator re-checks current members_v2 state).

## Live paths NOT yet in E (deferred)

- Moderation endpoints (`DELETE /groups/:id/messages/:msg_id`,
  `POST /groups/:id/mute/:agent_id`, etc.).
- Historical backfill for late joiners.
- D.4's full apply-event migration for the existing per-action
  metadata events (`MemberAdded`, `PolicyUpdated`, …).

## Commands run

```bash
cargo fmt --all -- --check
cargo clippy --all-features --all-targets -- -D warnings
cargo nextest run --lib --test api_coverage \
  --test named_group_public_messages --test named_group_state_commit \
  --test named_group_discovery
cargo build --release --bin x0xd --bin x0x
bash tests/e2e_named_groups.sh > \
  tests/proof-reports/named-groups-e-run{1,2,3}.log 2>&1
```

Approved plan: D.3 → C.2 → **E (now landed)** → D.4 → F. C.2
proof-debt tracker remains open per `.planning/c2-proof-hardening.md`.
