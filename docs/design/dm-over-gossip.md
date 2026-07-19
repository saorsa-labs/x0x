# x0x C — Direct Messaging over Gossip

**Status**: Implemented — `src/dm.rs` / `src/dm_send.rs` / `src/dm_inbox.rs` implement this design (shipped in the 0.18/0.19 cycle; status updated 2026-07-19)
**Target release**: x0x 0.18.0 (with raw-QUIC DM overlap); full cutover landed in 0.19.0
**Motivation**: The current `DirectMessaging` path sits directly on
ant-quic's transport-level `send`. Transport-level Ok is not
application-level delivery, and in a churning mesh the two diverge
(see post-0.17.4 VPS investigation and ant-quic#166 follow-up). This
design moves DMs onto the layer that was actually designed for
best-effort mesh delivery: saorsa-gossip's PlumTree pub/sub, with an
explicit application-layer ACK protocol on top.
**Related**: `ant-quic/docs/design/connection-lifecycle-sync.md` (D)
fixes the transport symptom but does not change the responsibility
gap — C is x0x's own architectural fix and is independent of D's
release timing.

## Goals

- DMs have an explicit application-layer receipt at the level
  **"recipient agent accepted"** — not "transport delivered", not
  "human read". This is the only receipt level v1 implements.
- `send_direct` returns `Ok` only after an authenticated ACK from the
  recipient's agent process is received by the sender.
- Lost-DM symptoms (transport churn, idle timeouts, hole-punch
  replacement) become retriable timeouts, not silent drops.
- Mixed-version meshes (pre-0.18 and 0.18+) interoperate during the
  overlap release.
- Replay and duplicate-delivery protections are first-class, not
  afterthoughts.

## Non-goals

- Durable local storage of DMs (no inbox persistence in v1 — DMs are
  still ephemeral unless the caller persists them).
- User-level read receipts. "Human read" is not a receipt level v1
  implements.
- Forward secrecy at session level. v1 uses per-message ML-KEM-768;
  forward secrecy is per-message, not conversation-level. MLS 2-member
  sessions remain an option for a future C.2 if needed.
- Onion-style relay routing. DMs propagate over PlumTree EAGER paths
  like any other pub/sub message — not source-routed.
- Replacing pub/sub, MLS groups, named groups, or KV stores. This
  touches `DirectMessaging` only.

## Wire format

### Envelope

Each DM is published as a `DmEnvelope` on the recipient's
recipient-specific pub/sub topic. The envelope is
postcard-serialised (same codec saorsa-gossip uses for its own wire
formats, for consistency).

```rust
/// Protocol version. Bump on any backward-incompatible change.
pub const DM_PROTOCOL_VERSION: u16 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DmEnvelope {
    /// Protocol version. Receivers reject envelopes with version
    /// greater than their supported max, with a small versioning
    /// tolerance documented per-release.
    pub protocol_version: u16,

    /// Deduplication key (together with `sender_agent_id` below) —
    /// 128 random bits per message, stable across retries of the
    /// same logical send.
    pub request_id: [u8; 16],

    /// Sender's AgentId (SHA-256 of ML-DSA-65 pubkey). Authenticates
    /// the sender after signature verification.
    pub sender_agent_id: [u8; 32],

    /// Sender's MachineId. Needed for trust-policy evaluation.
    pub sender_machine_id: [u8; 32],

    /// Recipient's AgentId. Receivers drop envelopes addressed to a
    /// different agent_id even if they somehow receive them
    /// (defence-in-depth; normally topic filtering prevents this).
    pub recipient_agent_id: [u8; 32],

    /// Sender-local unix-ms timestamp. Used for timestamp-acceptance
    /// window (replay protection) and for client-side ordering.
    pub created_at_unix_ms: u64,

    /// Wire-format envelope expiry: after this time, receivers MUST
    /// drop without processing. Caps how long a retransmit of the
    /// same request_id can still be accepted. Default 120 s from
    /// `created_at_unix_ms`.
    pub expires_at_unix_ms: u64,

    /// Kind — Payload or Ack.
    pub body: DmBody,

    /// ML-DSA-65 signature over the above fields serialised in a
    /// deterministic domain-separated form.
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DmBody {
    Payload(DmPayload),
    Ack(DmAckBody),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DmPayload {
    /// ML-KEM-768 encapsulation of the content key. Decapsulated with
    /// the recipient's ML-KEM secret key.
    pub kem_ciphertext: Vec<u8>,

    /// Per-message content nonce (12 bytes, random).
    pub body_nonce: [u8; 12],

    /// ChaCha20-Poly1305 AEAD of the inner `DmPlaintext`, keyed by
    /// the KEM-derived content key.
    pub body_ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DmAckBody {
    /// The request_id of the `Payload` envelope this ACK acknowledges.
    pub acks_request_id: [u8; 16],

    /// Outcome from the recipient's agent pipeline. See "ACK
    /// semantics" below.
    pub outcome: DmAckOutcome,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DmAckOutcome {
    /// Successfully decrypted, signature verified, trust-policy
    /// passed, enqueued to the recipient's DM handler/inbox.
    Accepted,
    /// Envelope valid but trust policy (block list, machine
    /// mismatch, etc.) rejected it at the recipient.
    RejectedByPolicy { reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DmPlaintext {
    /// Repeated here for binding — AEAD AD includes the envelope hash.
    pub request_id: [u8; 16],
    /// Actual user payload bytes.
    pub payload: Vec<u8>,
    /// Optional content type hint — free-form, e.g. "application/json".
    pub content_type: Option<String>,
}
```

### Topic derivation

Each agent subscribes to exactly one DM inbox topic on startup:

```rust
fn dm_inbox_topic(agent_id: &AgentId) -> TopicId {
    // Domain-separated blake3 hash of constant prefix || agent_id.
    // Same agent_id → same topic deterministically on every node.
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"x0x/dm/v1/inbox/");
    hasher.update(agent_id.as_bytes());
    TopicId::from_bytes(hasher.finalize().into())
}
```

ACKs travel back on the **sender's** inbox topic — no separate "ack
topic". The envelope kind (`DmBody::Ack`) disambiguates.

### Signature coverage

Signed-domain bytes (what ML-DSA-65 signs):

```
b"x0x-dm-v1" || protocol_version || request_id || sender_agent_id
 || sender_machine_id || recipient_agent_id || created_at_unix_ms
 || expires_at_unix_ms || postcard(body)
```

AEAD associated-data for `DmPayload`:

```
b"x0x-dm-payload-v1" || request_id || sender_agent_id
 || recipient_agent_id || created_at_unix_ms
```

Both bind the cryptographic layer to the envelope's metadata so you
can't swap identifiers around.

## Delivery semantics — the four levels

Documented explicitly so we don't overclaim:

| Level | Name | v1? | What Ok means |
|---|---|---|---|
| 1 | Transport accepted | — | Gossip `publish()` returned Ok. We don't expose this as a receipt. |
| 2 | **Recipient agent accepted** | **YES** | Recipient's process decrypted, verified, passed policy, enqueued to the DM handler. This is what `send_direct` returns on success. |
| 3 | Durable locally stored | future | Recipient wrote the DM to a persistent inbox. Not in v1. |
| 4 | User read | future/never | Human read the DM in a UI. Out of scope. |

`DmReceipt::delivered_at` corresponds to **level 2**. Docs and API
names use "accepted" rather than "delivered" to avoid confusion.

## Capability negotiation

### Advertisement

AgentCard and the identity-announcement heartbeat both carry a new
`dm_capabilities` field:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DmCapabilities {
    /// Highest protocol version this agent supports on the receive path.
    pub max_protocol_version: u16,
    /// True if this agent supports the gossip DM inbox topic.
    /// False during rollout for pre-0.18 agents.
    pub gossip_inbox: bool,
    /// KEM algorithm identifier — "ML-KEM-768" for v1.
    pub kem_algorithm: String,
    /// Maximum accepted envelope size in bytes (soft cap).
    pub max_envelope_bytes: usize,
}
```

`dm_capabilities` is signed as part of the AgentCard's existing
signature (AgentCard version bump required — see *Identity evolution*
below).

### Sender path selection

```
send_direct(recipient_agent_id, payload)
  ↓
lookup_recipient_capabilities(recipient_agent_id)
  ├─ Known + gossip_inbox = true     → gossip path only (C)
  ├─ Known + gossip_inbox = false    → raw-QUIC path only (legacy)
  └─ Unknown / stale / no AgentCard  → raw-QUIC path + retry with
                                        refreshed card on failure
```

**No dual-send**. Receivers running both paths on 0.18 would get
duplicate deliveries otherwise. Capability advertisement is the single
source of truth for path selection.

### Mixed-version matrix

| Sender \ Recipient | 0.17 | 0.18 |
|---|---|---|
| 0.17 | raw | raw (recipient accepts both, sender only sends raw) |
| 0.18 | raw (sender sees no gossip capability) | gossip |

## Replay protection and dedupe

### Dedupe key

`(sender_agent_id, request_id)` — 48 bytes.

Any envelope whose key is already in the recent-deliveries cache is:

- Not re-dispatched to the DM handler (no duplicate user-visible
  delivery).
- Re-ACKed with the original `DmAckOutcome` so a retrying sender
  still learns the outcome.

### Recent-deliveries cache

```rust
struct RecentDeliveryCache {
    entries: LruCache<DedupeKey, CachedOutcome>,
    ttl: Duration,   // default 5 minutes
    max_size: usize, // default 10_000 entries
}

struct CachedOutcome {
    outcome: DmAckOutcome,
    first_seen_at: Instant,
}
```

- `ttl` of 5 minutes caps how long a retry of the same `request_id`
  can still be deduped. After that, a new copy is treated as a fresh
  DM (and the sender is expected to have given up by then —
  `expires_at_unix_ms` caps it further).
- `max_size` of 10_000 caps memory. LRU eviction under pressure. A
  high-traffic node receiving >10K distinct DMs in <5 min would start
  losing dedupe, which is an acceptable degradation mode (duplicates
  re-delivered).

### Timestamp-acceptance window

Envelope acceptance checks, in order:

1. `now_unix_ms >= created_at_unix_ms - 30_000` (tolerate 30 s clock
   skew backwards).
2. `now_unix_ms < expires_at_unix_ms`.
3. `expires_at_unix_ms <= created_at_unix_ms + 600_000` (cap envelope
   lifetime at 10 min — bounds how far in the future an attacker
   could replay).

Envelopes failing any of these are silently dropped (logged at debug).

### Signature-first rule

Order of expensive work on receive (cheap → expensive, fail-fast):

1. Envelope bytes within size limit → drop oversized.
2. Envelope deserialises → drop malformed.
3. Timestamp window checks pass → drop stale/future.
4. Dedupe-cache hit → short-circuit with cached ACK, no further work.
5. Signature verification (ML-DSA-65) — expensive but gatekeeps step 6.
6. Trust-policy evaluation.
7. KEM decapsulation + AEAD decryption (only for `Payload` envelopes).
8. Enqueue to DM handler.
9. Insert into dedupe cache.
10. Emit ACK.

Signature before decrypt means an attacker spraying garbage envelopes
spends signature-verify CPU (expensive for them too) but never
triggers our decrypt path or touches our KEM state.

### Size limits

- `max_envelope_bytes` soft cap: 64 KiB (gossip PlumTree handles
  larger payloads but we want DMs to be small).
- Inner `DmPlaintext::payload` hard cap: 48 KiB (leaves room for
  envelope overhead).
- Oversized envelopes dropped at step 1 with a debug log. No ACK —
  attacker doesn't get a probe confirming we saw the message.

## Trust-policy integration

x0x's existing `TrustEvaluator` is already wired for direct messages.
Integration point in the new flow:

```
receive DmEnvelope
  → decrypt/verify (steps 5, 7 above)
  → trust_evaluator.evaluate(sender_agent_id, sender_machine_id)
     ├─ Accept                 → enqueue + ACK Accepted
     ├─ AcceptWithFlag         → enqueue (marked) + ACK Accepted
     ├─ Unknown                → enqueue (flagged unknown) + ACK Accepted
     ├─ RejectBlocked          → drop + ACK RejectedByPolicy { reason }
     └─ RejectMachineMismatch  → drop + ACK RejectedByPolicy { reason }
```

Policy is checked **after** signature verification (so we know the
sender claim is authentic) and **before** decryption (so a blocked
sender never costs us KEM decap). This is a deliberate ordering
choice — verifying first means we can trust the `sender_agent_id`
for the policy lookup.

`RejectedByPolicy` ACKs are a deliberate trade-off: they let a blocked
sender confirm they're blocked rather than leave them guessing. If
this is undesirable (e.g. to avoid stalker confirmation), a config
flag `trust.silent_reject: bool` (default false) suppresses the ACK
for policy rejections. The sender's `send_direct` then times out as
if the recipient were offline.

## ACK protocol

### Happy path

```
t=0ms   sender:    publish DmPayload(request_id=R, body=encrypted(payload))
                  → sender-local dedupe cache marks R as in-flight
                  → sender awaits Ack{acks_request_id=R}
                    on own inbox topic with timeout=10s

t=RTT   recipient: receive via gossip → verify/decrypt/policy/enqueue
                  → publish DmAck(acks_request_id=R, outcome=Accepted)
                    on sender's inbox topic

t=2·RTT sender:    receive DmAck{R, Accepted}
                  → resolve send_direct(...) Future with Ok(DmReceipt)
```

### Retry path

If the sender's `send_direct` timeout elapses (default 10s) without an
ACK, the send is retried automatically **up to N=3 times** using the
**same `request_id`**. Recipient dedupes on key, re-ACKs with the
cached outcome. Sender sees the ACK on retry N, resolves with
`Ok(DmReceipt { hops: retry_count })`.

After 3 retries without any ACK, `send_direct` returns
`DmError::Timeout`.

### Exponential backoff

Retry intervals: 10 s, 20 s, 40 s. Full send-direct budget: ~70 s.
Configurable via `DmConfig { retry: RetryConfig { .. } }`.

### Mid-retry delivery

If a late ACK arrives for a `request_id` whose send has already
resolved (ACK arrived during a retry), the ACK is accepted and
logged. `send_direct` remains `Ok`. No double-resolve.

## Error model

```rust
#[derive(Debug, thiserror::Error)]
pub enum DmError {
    /// Recipient agent is not known, or its AgentCard doesn't carry
    /// a KEM public key. Caller should retry after discovery cache
    /// refresh.
    #[error("recipient key material unavailable: {0}")]
    RecipientKeyUnavailable(String),

    /// No application-layer ACK received within the retry budget.
    /// The DM may or may not have been delivered (recipient's ACK
    /// may have been lost). Caller may retry — recipient dedupes.
    #[error("timed out after {retries} retries over {elapsed:?}")]
    Timeout { retries: u8, elapsed: Duration },

    /// Recipient agent accepted the envelope but their trust policy
    /// rejected the sender.
    #[error("recipient rejected: {reason}")]
    RecipientRejected { reason: String },

    /// Gossip publish failed locally — e.g. not yet joined mesh,
    /// not subscribed to any peers on the topic. Distinct from
    /// Timeout (which is "remote didn't respond").
    #[error("local gossip publish failed: {0}")]
    LocalGossipUnavailable(String),

    /// Envelope construction failed — signing, serialisation, KEM,
    /// or AEAD error on the sender side.
    #[error("envelope construction failed: {0}")]
    EnvelopeConstruction(String),

    /// Generic transport failure that couldn't be classified as
    /// one of the above.
    #[error("gossip transport error: {0}")]
    PublishFailed(String),
}
```

There is no `NoRoute` variant. Gossip has no routing layer — if we
can publish, we can reach anyone subscribed to the topic; if not,
it's a local problem (`LocalGossipUnavailable`) or a remote
unresponsive problem (`Timeout`).

## Public API

Existing:

```rust
pub async fn send_direct(&self, to: &AgentId, payload: Vec<u8>)
    -> Result<(), DmError>;
```

New signature (backwards-compatible — old signature preserved as a
thin wrapper):

```rust
pub async fn send_direct(&self, to: &AgentId, payload: Vec<u8>)
    -> Result<DmReceipt, DmError>;

pub async fn send_direct_with_config(
    &self,
    to: &AgentId,
    payload: Vec<u8>,
    config: DmSendConfig,
) -> Result<DmReceipt, DmError>;

#[derive(Debug, Clone)]
pub struct DmReceipt {
    pub request_id: [u8; 16],
    pub accepted_at: Instant,
    pub retries_used: u8,
    pub path: DmPath,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmPath {
    /// New gossip inbox path (C).
    GossipInbox,
    /// Legacy raw-QUIC direct stream (pre-0.18).
    RawQuic,
}

#[derive(Debug, Clone)]
pub struct DmSendConfig {
    pub timeout_per_attempt: Duration,    // default 10s
    pub max_retries: u8,                  // default 3
    pub backoff: BackoffPolicy,           // default exponential 2x
    pub require_gossip: bool,             // default false — allow legacy fallback
}
```

## Backward compatibility / overlap release

**x0x 0.18.0** carries both code paths:

- **Receivers** accept envelopes on the gossip DM topic AND on the
  legacy raw-QUIC `[0x10][...]` path. No change to the raw path's
  on-the-wire format.
- **Senders** consult recipient capabilities:
  - Gossip capable → gossip only.
  - Legacy → raw-QUIC only.
- Dedupe cache key covers both paths (an envelope-wrapped DM and a
  raw-QUIC DM can share a `request_id`), so a migration from one to
  the other mid-conversation doesn't double-deliver.

**x0x 0.18.1** (follow-up): config flag `direct_messaging.allow_legacy`
defaults to `true`. Docs announce deprecation.

**x0x 0.19.0**: `allow_legacy` defaults to `false`. Receivers still
accept inbound raw-QUIC DMs for compatibility but senders no longer
use that path. Release notes call out deprecation.

**x0x 0.20.0**: legacy raw-QUIC DM receive path removed. `[0x10]`
stream-type byte rejected.

## Identity evolution

AgentCard gets a new optional field `dm_capabilities:
Option<DmCapabilities>`. Pre-0.18 cards have this as `None`; senders
interpret `None` as "legacy only, no gossip DM support".

AgentCard version bump: no — `dm_capabilities` is additive under
postcard's default-for-missing semantics. Existing verification
signatures cover the new field because signature coverage is
"all-fields-with-defaults" over the current type definition. New
nodes sign with the field present; old nodes verifying new cards do
not see a signature mismatch because they deserialise into an older
type whose signature bytes they recompute from their view — actually
this needs care, see below.

**Open for review — AgentCard signature compatibility**: need to
confirm the existing `AgentCard::verify()` reserialises from the
deserialised view (in which case adding a field IS a breaking
change for old verifiers) or verifies against the received bytes
(in which case it's additive). If it's the former, we need a proper
version field + signature-format version. Deferring the final
decision to design review; in the worst case we introduce
`AgentCardV2` alongside `AgentCardV1` and senders sign both during
overlap.

## Observability

Structured tracing at `info` for:

- `dm_send_initiated { request_id, to, size }`
- `dm_send_attempt { request_id, attempt, path }`
- `dm_ack_received { request_id, outcome, elapsed }`
- `dm_send_failed { request_id, error }`
- `dm_receive_accepted { request_id, from, outcome }`
- `dm_receive_rejected { request_id, from, reason }`
- `dm_receive_deduped { request_id, from, first_seen_elapsed }`

Metrics (behind `features = ["metrics"]`):

- Counters: sent_total, received_total, dedupe_hits_total,
  failed_by_reason_total{reason}, retry_attempts_total.
- Histograms: ack_rtt_ms, payload_bytes.

## Test plan

**Unit** (in `src/dm.rs`):

- Envelope round-trip (encrypt → decrypt).
- Signature verify success/failure.
- Dedupe cache TTL + LRU eviction.
- Timestamp-window acceptance (all four edge cases).
- Capability-driven path selection.

**Integration** (in `tests/dm_over_gossip_integration.rs`):

1. 3-daemon local: A→B DM, full ACK round-trip, observable receipt.
2. 3-daemon local: A→B with simulated packet loss on first publish →
   retry succeeds.
3. 3-daemon local: A→B duplicate send (same `request_id`) → recipient
   delivers once, re-ACKs.
4. 3-daemon local: A→B with B blocked on trust store → `RecipientRejected`.
5. 3-daemon local: A→B where B is pre-0.18 (simulated via capability
   advert) → sender uses raw-QUIC path, receipt distinguishes path.
6. 3-daemon local: expired envelope dropped, no ACK, sender times out.

**E2E** (extends `tests/e2e_full_audit.sh`):

- Every DM assertion switches to gossip path (verify `DmReceipt::path`
  is `GossipInbox`).
- Add explicit retry-scenario test.

**VPS** (extends `tests/e2e_vps.sh`):

- All 30 pairwise DMs must complete with `GossipInbox` path,
  `retries_used <= 1` at p95. This is the acceptance bar for
  declaring the VPS #166-follow-up investigation closed.

## Rollout checklist

- [ ] Design doc reviewed and merged (this doc).
- [ ] `src/dm.rs` implementation on `claude/c-dm-over-gossip`.
- [ ] Unit + integration tests pass.
- [ ] `tests/e2e_full_audit.sh` adapted for gossip path; passes 275+/0
      on local 3-daemon.
- [ ] AgentCard capability advert lands (with signature-compat
      resolution above).
- [ ] x0x 0.18.0 tagged, pushed, release CI green.
- [ ] VPS deploy + `tests/e2e_vps.sh` 30/30 DM matrix green.
- [ ] Deprecation notice in x0x 0.18.1.
- [ ] Hard cutover in x0x 0.20.0.

## Agent-to-Machine Resolution

The DM system maintains its own agent→machine mapping separate from the discovery cache. This is necessary because:

1. **Discovery cache is ephemeral** — entries may be evicted or stale
2. **DM requires active connections** — we need to know which machine is currently reachable
3. **One agent may have multiple machines** — the discovery cache tracks all, DM needs the active one

### Resolution Flow

When `send_direct` is called with a recipient `AgentId`:

1. **Check DM registry** — `direct_messaging.get_machine_id(agent_id)` returns the last known MachineId
2. **Check discovery cache** — If no DM mapping, look up in `identity_discovery_cache`
3. **Check active connections** — `network.is_connected(machine_id)` verifies QUIC connection exists
4. **Attempt connection** — If not connected, use `connect_to_agent()` with reachability heuristics

### DM Registry Maintenance

The DM registry is updated in several contexts:

- **Identity announcement receipt** — `register_agent(agent_id, machine_id)` maps announced agent to machine
- **Connection establishment** — `mark_connected(agent_id, machine_id)` confirms active QUIC connection
- **Direct message receipt** — Inbound messages on a QUIC stream update the mapping
- **Connection loss** — Transport disconnects invalidate the mapping

### Why Separate from Discovery Cache

The discovery cache answers "what do we know about this agent?" while the DM registry answers "which machine should we send to right now?". The separation allows:

- Discovery to cache multiple machines per agent (for reachability queries)
- DM to track exactly one active machine per agent (for message routing)
- Independent TTL policies — discovery entries persist longer than DM mappings

## Open questions for review

1. **AgentCard signature compatibility** — needs confirmation before
   implementation. See *Identity evolution* above.
2. **`trust.silent_reject` default** — false (ACKs block decisions)
   or true (silent timeout on block)? Current design says false;
   privacy-sensitive deployments may prefer true.
3. **DM inbox topic subscription scope** — all agents subscribe to
   their own inbox only (current design) vs. also subscribing to
   inboxes of well-known contacts to pre-warm PlumTree trees (faster
   first-message latency, more gossip state). Stick with own-only
   for v1.
4. **Inner `DmPlaintext::content_type`** — useful hint or scope
   creep? Leaving in as optional since it costs nothing to carry.
