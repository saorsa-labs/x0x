# ADR-0051 Mechanics — Peer Relay (X0X-0070)

Maintained mechanics and post-decision corrections for
[ADR-0051](../adr/0051-application-level-peer-relay.md). The ADR body is a
snapshot; changes to shipped behavior are recorded here.

## RESOLVED by #437: header now binds inner via `inner_digest`

ADR-0051's Decision bullet 2 and Negative section record the pre-fix
weakness: `RelayHeader::signing_bytes()` signed **no digest of
`RelayedDm.inner`**, so a relay (or any on-path holder of a valid header)
could carry a *different* valid `DmEnvelope` under an unrelated header.

### Threat model (scope of the fix)

- **Final-recipient integrity never depended on the header.** The inner
  `DmEnvelope` carries its own ML-DSA-65 origin signature and
  recipient-bound encryption: a substituted envelope, if delivered at all,
  is delivered as a message validly authored by *its* real author — never
  as a forgery of the original sender. #437 does not change (and did not
  need to change) this end-to-end property.
- **What was broken is the relay hop.** An intermediate node's #193
  contact gate and forward rate/bandwidth accounting act on the
  **header's** authenticated sender. Without a header↔inner binding, a
  relay or on-path holder could spend the relay's uplink and quota
  carrying a payload authored by anyone while attributing the forward to
  the header's sender — gating and accounting were bypassable.
- **Recipient-side header↔inner verification is out of scope by
  construction**: the forward arm delivers only the inner envelope to the
  final recipient; the header never travels past the relay hop.

### Mechanics

- **Wire**: `RelayHeader` gains `inner_digest: Option<[u8; 32]>`. The
  digest is `blake3(postcard(DmEnvelope))` — the canonical wire bytes a
  relay forwards verbatim and the recipient re-injects onto the direct-DM
  channel, so the binding covers the exact payload that travels.
- **Signing**: a header **with** a digest signs under a new domain
  (`x0x-relay-hdr-v2`): same field layout as v1 plus the trailing digest.
  A header **without** one keeps the legacy v1 layout byte-for-byte, so
  pre-#437 signatures still verify. The digest (and its presence) is
  inside the signed bytes, so stripping it changes the signing bytes —
  downgrade is cryptographically impossible.
- **Send path**: `PeerRelay::build_relayed_dm` always computes and signs
  the digest (serialization failure fails the build). New senders always
  bind and always emit v2 wire bytes.
- **Receive path**: `PeerRelay::disposition_for` enforces
  `header.inner_digest == blake3(inner)` immediately after header
  signature verification and **before** freshness counting, the
  `DeliverLocally` receive accounting (`relay_received`), the #193
  contact/blocked sender gates, and forward-quota admission. A mismatch
  hard-drops with `RelayRefusal::InnerDigestMismatch`, counted as
  `relay_refused_inner_digest_mismatch`. One choke point covers both the
  final-recipient and intermediate-relay arms.

## Wire compatibility (v1 ↔ v2 decode)

Postcard encodes structs **positionally**: inserting `inner_digest` into
`RelayHeader` changes the byte layout, so a naive single-struct decode
would reject every v1 frame from a pre-#437 sender (the `Option` tag
would be parsed from the signature's length bytes — an ML-DSA-65
signature is ~3309 bytes, whose varint length prefix decodes as an
invalid variant index). Therefore:

- `RelayedDm::from_postcard` performs a **two-stage decode**: the v2
  (digest-bearing) shape first; on failure, the byte-exact v1 legacy
  shape (`RelayedDmV1Wire` mirror), lifted with `inner_digest: None`.
  The network demux uses this decoder.
- Ambiguity is fail-closed: a frame that misparses across shapes
  necessarily splits the byte stream at the wrong field boundary, which
  invalidates the ML-DSA-65 signature — `verify()` drops it.
- **Known limitation (positional formats)**: an *old* node cannot parse
  *new* v2 frames — they fail decode and are dropped as malformed. New
  senders' relayed DMs need a #437-aware relay during the transition
  window. Sending v1-look-alike bytes from new nodes was rejected
  because it would require emitting digest-less (unbound) headers,
  re-opening #437 for every new sender.

## Transition (honest scope; mirrors ADR-0021's shape)

- **Present-but-mismatched** digest → hard-drop, always. A mismatch is
  active relay-hop substitution under a valid header.
- **Absent** digest (legacy pre-#437 sender) → accepted with exactly the
  pre-fix relay-hop guarantees. **This is fail-open and stays fail-open
  until the follow-up lands** — it is NOT an implemented end-state:
  tracked as issue
  [#442](https://github.com/saorsa-labs/x0x/issues/442) (add a
  digest-support flag to `DmCapabilities`; once a peer's confirmed
  advert shows support, `disposition_for` rejects digest-less headers
  from that peer and the residual closes).
- Rationale for not hard-requiring immediately: there is no capability
  negotiation on the relay path today; hard-requiring would silently
  sever every pre-#437 sender, exactly the trade-off ADR-0021 documented
  for attestations.

## Tests

- `src/peer_relay.rs`:
  - `build_relayed_dm_binds_inner_digest` — new senders always bind; v2
    header verifies; fresh build self-binds.
  - `substituted_inner_is_refused_before_gating_or_accounting` — both
    arms, counters, no accounting attributed.
  - `legacy_digestless_header_still_accepted_per_transition`.
  - `bound_header_rejects_digest_strip_downgrade`.
  - `legacy_v1_wire_decodes_via_two_stage_and_verifies` — pins the wire
    break the two-stage decode fixes (v1 bytes must NOT parse as v2) and
    verifies a genuinely signed v1 header after decode.
  - `v2_wire_round_trips_through_two_stage_decode`.
  - `frozen_v1_wire_vector_still_decodes` — frozen byte-level v1 frame
    (explicit varints transcribed from a canonical encoding) decodes
    with `inner_digest: None`; pins the v1 mirror against layout drift.
- `tests/peer_relay_integration.rs`:
  - `relay_hop_substituted_inner_is_refused_before_forward_accounting` —
    the relay-hop attack through the real `spawn_relay_dm_listener`:
    Alice's bound header for inner A addressed to Bob, inner swapped to
    B, handed to Charlie-the-relay; the mismatch refusal advances,
    `relay_forwarded`/`relay_received` stay flat, nothing is re-injected.
  - `relay_round_trip_alice_to_bob_via_charlie` — full three-party QUIC
    round trip over the always-bound build path.
  - `signed_relayed` helper remains the legacy (digest-less) sender
    shape; its consumers keep passing — v1 acceptance is pinned.
