# Phase E Proof Report — Public-Group Messaging

> **Honesty clause.** Phase E delivers the signed public-message plane
> and its write-access + banned-author enforcement truth-table. C.2 is
> now separately signoff-ready, so this report no longer inherits C.2
> proof-debt language. Claims here remain bounded to what Phase E adds:
> public-message signing, receive-side enforcement, and real cross-daemon
> receive proof on the public plane.

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
- This report does not claim anything beyond the public-message plane;
  C.2, D.4, and broader final signoff are tracked separately.

## Evidence — unit + integration

- `src/groups/public_message.rs`: **23 unit tests** covering sign/
  verify roundtrip, tamper detection on body / group_id / kind /
  author / `state_hash_at_send` / `revision_at_send` / `timestamp` /
  `author_user_id`, ingest truth-table for all three write_access
  values against active/banned/missing/admin/owner authors,
  confidentiality gate, oversize rejection, and preset shape
  assertions.
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

`tests/e2e_named_groups.sh` Phase E section exercises on three fresh
local daemons. Evidence comes in two layers:

1. Archived baseline runs under
   `tests/proof-reports/named-groups-e-run{1,2,3}.log` showing the
   original E section stayed green while the rest of the suite still
   had the same unrelated pre-existing failures.
2. A strengthened shell rerun archived at
   `tests/proof-reports/named-groups-phasef-clean.log`.
3. A dedicated live daemon proof archived at:
   - `tests/proof-reports/named-groups-e-live-run1.log`
   - `tests/proof-reports/named-groups-e-live-run2.log`
   - `tests/proof-reports/named-groups-e-live-run3.log`
   - `tests/proof-reports/named-groups-e-live-nextest.log`

What the strengthened rerun **does** prove:

- Owner publishes to `public_open` (MembersOnly) — accepted.
- Non-member bob imports the card, primes his listener, and receives
  the **exact** body via `GET /groups/:id/messages` under Public read.
- Non-member bob tries to `/send` to MembersOnly — rejected.
- Owner publishes announcement on `public_announce` (AdminOnly) —
  accepted.
- Plain-member bob tries to publish an announcement — rejected.
- `MlsEncrypted` group: `/send` rejects, `/messages` rejects.
- `ModeratedPublic` group: non-member bob can successfully hit the
  send endpoint after importing the authority card.
- Positive cross-daemon `ModeratedPublic` receive is now proven:
  `bob sends` → `alice sees exact body`.
- After alice bans bob, a post-ban message does **not** land in
  alice's cache; receive-side ingest rejection is therefore proven.

The dedicated live test `tests/named_group_e_live.rs` specifically proves the
previous gap on a fresh two-daemon pair and now passes in three consecutive
archived runs.

### Honest run-summary framing

The latest full shell rerun is now clean overall:
- `tests/proof-reports/named-groups-phasef-clean.log`
- **98 PASS / 0 FAIL**

The earlier shell failures were not Phase E logic regressions; they traced to
separate state/routing issues that have now been cleaned up:
- local-route-id vs stable-group-id confusion in cross-daemon shell paths
- stable-id binding gaps in GSS encrypt/decrypt/reseal
- stale local group-card cache entries after owner-side state changes
- over-coupled reject/cancel shell proof steps that depended on unrelated
  prior cross-stub convergence

So the E section is now clean both in isolation and inside a fully clean
named-groups shell rerun.

## Live paths using Phase E

- `POST /groups/:id/send` signs + publishes + caches for SignedPublic.
- Public-chat listener validates + caches incoming messages.
- `GET /groups/:id/messages` serves the ring buffer under read policy.
- Ban enforcement: authoritative receive-side ingest rejection is
  proven. Publish-time rejection applies when the local daemon's roster
  view is fresh; imported stubs may still briefly lag metadata updates,
  so the receive-side rejection remains the strongest proof.
- Reverse-direction public-message receive on a creator-owned local group
  is now proven after fixing stable-id listener resolution and subscribing
  the sender's public topic before first publish.

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
cargo test --lib groups::public_message::tests --quiet
cargo test --test named_group_public_messages --quiet
cargo test --test named_group_discovery --quiet
cargo build --release --bin x0xd --bin x0x
cargo test --test named_group_e_live -- --ignored --nocapture \
  > tests/proof-reports/named-groups-e-live-run1.log 2>&1
cargo test --test named_group_e_live -- --ignored --nocapture \
  > tests/proof-reports/named-groups-e-live-run2.log 2>&1
cargo test --test named_group_e_live -- --ignored --nocapture \
  > tests/proof-reports/named-groups-e-live-run3.log 2>&1
cargo nextest run --test named_group_e_live --run-ignored ignored-only \
  > tests/proof-reports/named-groups-e-live-nextest.log 2>&1
bash tests/e2e_named_groups.sh > \
  tests/proof-reports/named-groups-phasef-clean.log 2>&1
```

`x0x-user-keygen` remains buildable from source as a deprecated compatibility shim;
runtime scripts use the canonical `x0x user-id create` command.

Approved plan: D.3 → C.2 → **E (now landed)** → D.4 → F. C.2
proof-hardening is now closed; broader final signoff remains under Phase F.
