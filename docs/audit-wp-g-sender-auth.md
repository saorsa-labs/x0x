# Audit WP-G: saorsa-gossip pubsub sender authentication

- **Issue:** #215 (follow-up to PR #214, gossip-DM machine-revocation origin authentication)
- **Date:** 2026-07-17
- **Question:** can any receive path in the gossip stack deliver a message whose
  application-visible `sender` is self-declared / unsigned, with
  `verified == true`? `identity_announcement_has_direct_agent_origin`
  (src/lib.rs:1015) relies on the answer being "no".

## Dependency under audit

- Crate: `saorsa-gossip-pubsub` **0.5.67** (version requirement `0.5.67` in
  Cargo.toml:48; resolved to exactly 0.5.67 via `cargo metadata` — Cargo.lock
  is gitignored, .gitignore:3).
- Source audited: the extracted registry copy
  `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/saorsa-gossip-pubsub-0.5.67/src/lib.rs`
  (cited below as "dep lib.rs:N").

## What the dependency actually delivers to x0x

- Local subscribers receive `(PeerId, Bytes)` tuples — dep lib.rs:2466
  (`subscribers: Vec<mpsc::UnboundedSender<(PeerId, Bytes)>>`), registered by
  `subscribe` (dep lib.rs:6482-6496). On inbound EAGER the tuple sent is
  `(from, payload.clone())` (dep lib.rs:5337, 5346), where `from` is the
  **immediate transport peer that forwarded the frame**, not an application
  origin.
- x0x discards that peer ID: `let Some((_peer, encoded_payload)) = received`
  (src/gossip/pubsub.rs:478). The dependency therefore has **no
  application-visible sender field at all** — x0x's `PubSubMessage.sender`
  (src/gossip/pubsub.rs:164-176) is computed entirely inside x0x's own
  `decode_v2`.

## Receive-path signature enforcement in the dependency

- `handle_message` (dep lib.rs:6530) postcard-decodes the `GossipMessage`
  (dep lib.rs:6533) and dispatches on `header.kind` (dep lib.rs:6556).
- `GossipMessage` carries a sender-supplied `signature` and `public_key`
  alongside the header and optional payload (dep lib.rs:1889-1898). The
  signature is ML-DSA-65 over the postcard-serialized `MessageHeader`:
  `sign_message` (dep lib.rs:5063-5083, "Per SPEC2 §2, all gossip messages
  MUST be signed"), verified by `verify_signature` via
  `saorsa_gossip_identity::MlDsaKeyPair::verify(public_key, header_bytes,
  signature)` (dep lib.rs:5092-5118, verify call at 5109), wrapped by
  `verify_message_signature` (dep lib.rs:4108-4114).
- **EAGER** (the only inbound kind that delivers payload to subscribers):
  `handle_eager` (dep lib.rs:5205) verifies the signature **first**
  (dep lib.rs:5213); on failure it logs, records an invalid-message penalty
  against the forwarding peer, and returns `Err` **without caching or
  delivering** (dep lib.rs:5214-5218). Subscriber delivery happens only after
  verification, dedupe, and replay checks (dep lib.rs:5334-5346).
- **Anti-entropy**: verified before any processing (dep lib.rs:5581-5583); it
  serves only messages already in the local cache (i.e. verified on original
  ingest), re-sent as EAGER, which recipients re-verify through
  `handle_eager`.
- **IHAVE / IWANT**: verified before processing (dep lib.rs:6559-6561,
  6586-6588); they carry no subscriber payload. IWANT responses re-send cached
  (previously verified) messages as EAGER (dep lib.rs:5534-5560).
- **publish_local** self-delivers the node's own freshly signed payload to its
  own subscribers without a verification step (dep lib.rs:5197-5198): local
  origin by construction, benign.

## How x0x populates `sender` / `verified` (for completeness)

- `decode_v2` (src/gossip/pubsub.rs:1080) parses the v2 wire format
  (`0x02 || agent_id(32) || lp(public_key) || lp(signature) || lp(topic) ||
  payload`), computes `verified = verify_signature(...)`
  (src/gossip/pubsub.rs:1114-1120), then sets `sender: Some(agent_id)` and
  `verified` from that result (src/gossip/pubsub.rs:1129-1136).
- `verify_signature` (src/gossip/pubsub.rs:1171) binds the wire `agent_id` to
  the embedded public key (`AgentId::from_public_key(&public_key) ==
  agent_id`, src/gossip/pubsub.rs:1184-1188) and verifies the ML-DSA-65
  signature over `b"x0x-msg-v2" || agent_id(32) || topic_bytes || payload`
  (`build_signing_payload`, src/gossip/pubsub.rs:1161-1167; prefix constant at
  src/gossip/pubsub.rs:104; verify call at src/gossip/pubsub.rs:1198-1202).
- Legacy v1 decode yields `sender: None`, `verified: false`
  (src/gossip/pubsub.rs:996-1003). `publish_local` yields the local agent with
  `verified: true` — local origin by construction (src/gossip/pubsub.rs:620-633).
- Delivery-time backstop: `decode_for_delivery` drops any signed message with
  `verified == false` (src/gossip/pubsub.rs:781-789).

## Findings

1. **No receive path in saorsa-gossip-pubsub 0.5.67 delivers an unverified
   remote payload to local subscribers.** Every payload-delivering inbound
   path verifies the envelope ML-DSA-65 signature first and drops on failure
   (evidence above). There is also no code path by which a remote peer could
   choose an application-level sender identity: the only sender-ish value the
   dependency propagates is the transport `PeerId` of the immediate forwarder,
   which x0x discards (src/gossip/pubsub.rs:478).
2. **The dependency's envelope signature covers only the serialized
   `MessageHeader`** (dep lib.rs:1896-1897). Payload binding is indirect:
   `msg_id` embeds `blake3(payload)` at publish time (dep lib.rs:5053-5056),
   but `handle_eager` trusts `header.msg_id` (dep lib.rs:5210) without
   recomputing it from the received payload. A relay could therefore in
   principle attach a different payload to a captured, validly signed header.
   This does **not** weaken x0x's sender-auth invariant: the substituted
   payload fails x0x's inner v2 ML-DSA-65 verification, which covers the exact
   payload bytes (src/gossip/pubsub.rs:1161-1167, 1198-1202), so
   `verified == false` and the message is dropped (src/gossip/pubsub.rs:781-789).
   Worth re-checking on any dependency bump, since x0x's defense here is
   single-layer by design (the inner signature), not double-layer.
3. x0x's `sender` is self-declared wire data, but it can only carry
   `verified == true` when (a) the declared agent ID equals
   `AgentId::from_public_key(embedded_key)` and (b) the ML-DSA-65 signature
   over the domain-separated payload verifies under that key. A relay without
   the origin's private key cannot satisfy both.

## Conclusion

In saorsa-gossip-pubsub 0.5.67, no receive path can populate an
application-visible sender with `verified == true` absent a valid ML-DSA-65
signature from the claimed origin's key; x0x derives `msg.sender` solely from
its inner v2 signature, so a relay cannot spoof `msg.sender` past
`identity_announcement_has_direct_agent_origin`.

## Tripwire — what breaks if the invariant is violated

The guard tests issue #215 refers to as tests 8–9 construct a `PubSubMessage`
by hand (verified sender fields, no decode) and call the binding function
directly. They therefore trip ONLY on regressions of the guard itself
(`identity_announcement_has_direct_agent_origin` /
`record_authenticated_machine_binding_from_message`) — NOT on a
saorsa-gossip-pubsub bump or a `decode_v2` change, which they never exercise:
- `wrong_origin_machine_announcement_cannot_populate_or_overwrite_binding`
  (src/lib.rs:15399) — attacker's verified envelope carrying the victim's
  announcement must not populate/overwrite the victim's binding.
- `verified_rebroadcast_cannot_populate_or_overwrite_authenticated_binding`
  (src/lib.rs:15440) — a relay's verified rebroadcast of the origin's
  announcement must not populate/overwrite the retained binding.

The decode-layer tripwire — the test that fails if `decode_v2` ever accepts a
forged or tampered signature — is `test_v2_tampered_payload_fails_verification`
(src/gossip/pubsub.rs:1523). No unit test cited here covers a dependency bump:
`saorsa-gossip-pubsub` upgrades need an integration-level check (a live
relay/forward scenario) before merge; the pair above must not be read as
covering that case.

Supporting guards: `direct_origin_identity_ingest_populates_authenticated_binding`
(src/lib.rs:15377, positive control),
`missing_or_invalid_sender_key_cannot_populate_authenticated_binding`
(src/lib.rs:15478).
Run on any `saorsa-gossip-pubsub` bump:
`cargo nextest run -E 'test(wrong_origin_machine_announcement_cannot_populate_or_overwrite_binding) or test(verified_rebroadcast_cannot_populate_or_overwrite_authenticated_binding)'`
