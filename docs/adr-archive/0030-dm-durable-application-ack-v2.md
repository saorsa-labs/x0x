# ADR 0030: DM Protocol v2 — Durable Application ACK, Capability-Gated

- **Status:** Accepted (2026-08-13, approved by David Irvine)
- **Date:** 2026-08-13
- **Decision owners:** David Irvine
- **Reviewers:** Grok (cross-review closed 2026-08-13, three amendments
  applied); David Irvine (acceptance, 2026-08-13)
- **Supersedes:** none (amends the receipt-level model of
  `docs/design/dm-over-gossip.md`; extends ADR 0023's durable-history role)
- **Related:** ADR 0021 (origin attestation — Accepted 2026-08-12; ACK
  attestation interacts), ADR 0023 (durable local history), ADR 0028
  (delivery order ≠ authorization), ADR 0029 (public-message threading —
  group messages only, NOT DMs), `wip/codex-durable-app-ack` (`b60b995`,
  the campaign implementation this ADR governs)

## Context

Today a DM send's `Ok` means **level 2**: the recipient daemon verified the
envelope and enqueued it locally (`dm-over-gossip.md` receipt levels). The
field campaign behind v0.36.2–v0.37.2 showed that products built on x0x
(tic-tac-toe) need a stronger receipt: "the recipient daemon has durably
committed this message to ADR-0023 history and completed local dispatch" —
otherwise a crash between transport receipt and commit silently loses a
message the sender was told was delivered.

The unmerged campaign branch (`wip/codex-durable-app-ack`) implements this
as **DM protocol v2**: same envelope layout, new ACK semantics. It also
implements a **v3** (thread metadata inside the AEAD payload) that this ADR
deliberately does NOT cover — see Scope.

Landing the tip as-is was rejected (2026-08-12 handoff): the branch makes
product `/direct/send` fail closed against every 0.37 peer with no written
mixed-version policy, diverges the four send surfaces, grows
`named_groups.rs` from 28k to 33.7k lines, and updates neither
`docs/api-reference.md` nor `CHANGELOG.md`.

Key implementation facts (verified on the branch, 2026-08-13):

- Envelope layout is unchanged between v1 and v2; only ACK semantics differ
  (`src/dm.rs:1586-1588`). `protocol_version` is already in the signed
  bytes and mirrored in the ADR-0021 attestation.
- Strict sends fail closed with a clean, typed error — not a black hole:
  missing/insufficient capability ⇒ `DmError::AckSemanticsUnavailable` ⇒
  REST **409 `recipient_ack_semantics_unavailable`**, after a targeted
  capability refresh attempt (`src/lib.rs:5252-5262`, routes/direct.rs).
- `DmCapabilities.max_protocol_version` already exists on v0.37.x cards
  and adverts; 0.37 peers advertise 1. The branch adds strict predicates,
  signed capability adverts on `x0x/caps/v1`, and a targeted refresh
  protocol.
- Receiver ordering under v2: per-logical-request lock → replay-cache
  binding check → durable-history lookup → dispatch → **history commit
  awaited** → ACK. Commit failure withholds the ACK
  (`src/dm_inbox.rs:1157-1608`).
- Durable v2 is **at-least-once across restart** (documented on the
  branch in `dm-over-gossip.md`): the replay cache is memory-only; a
  restart can re-dispatch an already-committed envelope.

## Decision Drivers

- A crash-durable receipt level is a real product need, proven in the
  field; the daemon must be able to promise it or refuse honestly.
- Rolling upgrades against the production mesh MUST NOT silently black-hole
  messages: every mixed-version behavior must be explicit, typed, and
  documented.
- One send contract: a product developer must not get different delivery
  semantics depending on which surface (REST/WS/CLI/library) they used.
- ADR 0025: fail states must be observable; silent degradation is the
  house defect class this campaign repeatedly hit.
- Reviewability: `named_groups.rs` at 33.7k lines is not reviewable; the
  outbox must be its own module before it can merge.

## Considered Options

### Mixed-version policy

1. **Strict product sends with explicit refusal (chosen).** Product
   surfaces default `require_durable_app_ack = true`; a peer without a
   current, signed, machine-bound v2 capability advert yields 409
   `recipient_ack_semantics_unavailable` after a forced refresh. The
   caller (product UI) decides whether to retry, surface "peer needs
   upgrade", or explicitly downgrade per message.
2. **Transparent downgrade to v1 when the peer advertises < 2.**
   Rejected: reintroduces silent degradation — the sender's `Ok` would
   mean level 3 or level 2 depending on invisible peer state, which is
   exactly the ambiguity this protocol exists to remove. A downgrade must
   be the *caller's* explicit choice (`require_durable_app_ack = false`),
   never the daemon's guess.
3. **Fleet min-version bump (refuse v1 peers entirely).** Rejected for
   now: unnecessarily breaks non-product traffic that is well-served by
   v1 semantics; the capability gate already scopes strictness to the
   sends that asked for it.

### Send-contract unification

1. **Two named tiers, all surfaces classified (chosen).**
   - **Product tier** (durable by default): REST `POST /direct/send` and
     CLI `x0x direct send` (which posts to it).
   - **Internal tier** (v1 semantics, explicit config): library
     `Agent::send_direct` default config, WS `send_direct`, and daemon
     control-plane sends (welcome blobs, TreeKEM plumbing, group
     metadata) — each internal use is an explicit named config, and the
     WS surface is **documented as internal** in `api-reference.md` until
     it grows the product fields.
2. **Everything durable by default.** Rejected: control-plane messages
   (welcome fetch, catch-up) intentionally race connection establishment
   and must not inherit strict gating (see v0.37.0's welcome-blob
   opt-out); forcing durable semantics there causes livelock.
3. **Everything v1 unless flagged.** Rejected: the product bug class this
   fixes came precisely from products forgetting to opt in.

### Threading (v3)

The branch ships `DM_PROTOCOL_THREADED = 3` (thread metadata wrapped
inside the AEAD plaintext behind `b"x0x-dm-thread-v1"`). **Deferred to a
separate ADR.** ADR 0029 covers threading for *group public messages*
only; DM threading is a distinct wire commitment that no accepted ADR
covers, and it must not ride in under this one. Implementation
consequence: the slice that lands v2 must either ship with
`DM_PROTOCOL_VERSION = DM_PROTOCOL_DURABLE_ACK` (ceiling 2) or gate the
v3 wrapper off; the v3 code may stay in-tree behind the version ceiling.

## Decision

Adopt DM protocol v2 (durable application ACK) as specified by the
campaign implementation, landed in reviewable slices, under the following
binding requirements:

### 1. Receipt-level contract

`Accepted` under v2 means: verified envelope, durably committed to the
ADR-0023 store (SQLite transaction awaited — `record_committed`), and
local dispatch completed. It is **at-least-once across restart** and never
implies read or exactly-once application delivery. Applications requiring
restart-spanning exactly-once must dedupe on `(sender, request_id)`.

### 2. Mixed-version policy (normative)

- New sender → v2-capable peer: durable ACK path.
- New sender (strict) → v1/0.37 peer: **409
  `recipient_ack_semantics_unavailable`** after one forced targeted
  capability refresh. Never a silent downgrade, never a hang.
- New sender (caller explicitly sets `require_durable_app_ack = false`) →
  v1 peer: v1 semantics, `Ok` = level 2, response says so.
- v1/0.37 sender → new receiver: unchanged v1 behavior (envelope layout
  identical; receiver ACKs v1 semantics for v1 envelopes).
- Receiver ceiling: envelopes with `protocol_version >` local ceiling are
  dropped without ACK (sender times out and retries/errors) — a v4+
  future is a new ADR.
- A logical request completed under weaker semantics is answered
  `AckSemanticsUnavailable`, never re-ACKed as durable
  (`cached_ack_for_protocol`).

### 3. Capability advertisement (normative)

Daemons advertise `max_protocol_version = 2` **iff** durable history is
enabled (else 1); adverts are ML-DSA-signed, machine-bound, published on
`x0x/caps/v1` with the targeted-refresh protocol. Card-imported capability
claims of durable support require a signed card; a live binding's version
is never lowered by an unsigned source. (The branch's v3-iff-history
constructor is amended to v2 until the v3 ADR is accepted.)

### 4. Send surfaces (normative)

Per "two named tiers" above. Additionally: the REST field
`require_gossip_ack` is **deprecated**; the branch silently discards
`require_gossip_ack: false` — that silence is not acceptable. The route
rejects a request that sets the field with **400** (documented in
`api-reference.md` in the same PR); a silent no-op or WARN-only is not
sufficient (Grok review, 2026-08-13).

### 5. Bootstrap outbox

The durable consent-bootstrap outbox (obligations keyed by
`(recipient, group, frontier, payload-digest)`, disk sidecar, 1024-entry
cap, exponential backoff to 60 s, cleared only by a frontier-matching v2
application ACK) is accepted in design — and MUST be extracted from
`named_groups.rs` into its own module (`src/server/routes/` sibling or
`src/server/public_group_bootstrap_outbox.rs`) before merge.
`named_groups.rs` must not grow past its pre-branch size in the landing
PR. `LegacyV1Sent` is never completion.

### 6. Documentation in the same PR as behavior

`docs/api-reference.md` (`/direct/send` body: `logical_id`, deprecated
`require_gossip_ack`, the 409/409/503 error codes; WS surface marked
internal), `CHANGELOG.md`, `docs/design/dm-over-gossip.md` (already
partially updated on the branch), and this ADR's status link. The new
daemon config keys (`dm_capability_cache_ttl_secs`,
`dm_capability_test_controls`) and the outbox sidecar file must be
documented.

### 7. Known gap to close before or at merge

The typed-route durable path skips the receiver-side durable-history
lookup (`src/dm_inbox.rs:1330` gates on `!matches_typed_route`), so typed
durable payloads have no restart-spanning receiver dedupe in the inbox.
Either extend the history lookup to typed routes or document the
obligation on every typed-route handler (the bootstrap outbox handler
satisfies it via `Inserted|Duplicate` completion); the landing PR states
which.

## Consequences

### Positive

- Products get an honest crash-durable receipt or an explicit, typed
  refusal — no invisible downgrade, no black hole (drivers 1–2).
- Envelope-layout stability keeps v1 interop trivially true; the entire
  compatibility surface is ACK semantics + capability adverts.
- The 409 contract gives tic-tac-toe a deterministic "peer needs upgrade"
  UX hook instead of a timeout.

### Negative / Trade-offs

- Strict sends to not-yet-upgraded peers fail until the fleet converges;
  product UX must handle 409. Note: the tic-tac-toe **bundled sidecar
  daemon runs `--skip-update-check` by design**, so its 409 window closes
  at app-release cadence, not fleet self-update cadence (Grok review,
  2026-08-13) — the UX handling is load-bearing, not transitional.
- Capability adverts add gossip traffic (5-min publish, 15-min TTL) and a
  targeted-refresh protocol to maintain.
- At-least-once means applications keep a dedupe obligation; we document
  rather than hide it.
- Two receipt semantics coexist permanently (internal tier stays v1).

### Neutral / Operational

- History schema advances to v4 (`ingress_sender_agent`,
  `logical_request_id`; thread columns land dormant pending the v3 ADR).
  Migration continuity is normative: v0.37.2 shipped FTS schema v2, so
  the landing slice must apply 2→3→4 migrations on top of it — the
  campaign `store.rs` must not be dropped in wholesale over the released
  schema (Grok review, 2026-08-13).
- ADR 0021 alignment: ACK envelopes carry origin attestations; the v2 ACK
  binding additionally pins `(protocol_version, recipient, machine)` on
  the sender's waiter.
- Landing order after acceptance: (1) capability + strict-send slice with
  mixed-version tests; (2) receiver durable path; (3) outbox module +
  admission; (4) REST/CLI product defaults + docs. Each slice passes the
  validation matrix below.

## Validation

Required before any slice merges; the full matrix before the 0.38 tag:

- new→new durable ACK: receiver history row committed before sender 200.
- new(strict)→0.37 peer: 409 `recipient_ack_semantics_unavailable`,
  bounded latency (no hang), after one forced refresh.
- new(explicit non-strict)→0.37 peer: delivered, `Ok` = level 2.
- 0.37→new: unchanged v1 delivery both message classes (DM + group).
- Restart + same `logical_id`/`request_id`: exactly one durable history
  row (`Duplicate` re-ACK), possible re-dispatch documented.
- Reused `logical_id` with different bytes: 409 `idempotency_conflict`.
- Consent bootstrap: stranger refused; Known + remove/re-add installs;
  outbox survives sender restart; obligation cleared only by
  frontier-matching v2 ACK.
- Wiring tests per ADR 0025 (dispatch-level, revert-guarded), not only
  unit tests — the F2 standard.

## Notes for AI-assisted work

Drafted with AI assistance from the verified campaign-branch survey
(2026-08-13); must not be marked Accepted without human review. Accepted
ADRs are immutable — supersede, don't edit.
