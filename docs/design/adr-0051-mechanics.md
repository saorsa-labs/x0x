# ADR-0051 Mechanics — Peer Relay (X0X-0070)

Maintained mechanics and post-decision corrections for
[ADR-0051](../adr/0051-application-level-peer-relay.md). The ADR body is a
snapshot; changes to shipped behavior are recorded here.

## RESOLVED by #437: header now binds inner via `inner_digest`

ADR-0051's Decision bullet 2 and Negative section record the pre-fix
weakness: `RelayHeader::signing_bytes()` signed **no digest of
`RelayedDm.inner`, so a relay (or any on-path holder of a valid header)
could carry a *different* valid `DmEnvelope` under an unrelated header.

### Threat model (scope of the fix)

- **Final-recipient integrity never depended on the header.** The inner
  `DmEnvelope` carries its own ML-DSA-65 origin signature and
  recipient-bound encryption: a substituted envelope, if delivered at all,
  is delivered as a message validly authored by *its* real author — never
  as a forgery of the original sender.
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
- **Signing**: a digest-bearing header signs under the `x0x-relay-hdr-v2`
  domain (v1 fields + trailing digest); a digest-less header keeps the v1
  layout and domain byte-for-byte. The digest (and its presence) is
  inside the signed bytes, so stripping it breaks the signature —
  downgrade by stripping is cryptographically impossible.
- **Receive path**: `PeerRelay::disposition_for` enforces the binding
  immediately after header signature verification, **before** freshness
  counting, `relay_received` accounting, the #193 contact/blocked gates,
  and forward-quota admission. Mismatch hard-drops
  (`RelayRefusal::InnerDigestMismatch`, counted as
  `relay_refused_inner_digest_mismatch`).

## Capability signal (`DmCapabilities::digest_support`) — round 4

The mixed-fleet behavior is capability-driven end to end:

- `DmCapabilities` gains `digest_support: bool` (additive,
  serde-defaulted, `skip_serializing_if = false`). **This build's wired
  constructors advertise `true`**; `pending()` stays `false`.
- **Send path** (`try_relay_fallback`): emit the bound v2 frame **only**
  when the relay candidate's confirmed advert sets `digest_support`
  (`peer_relay::peer_advertises_inner_digest`); otherwise emit the
  byte-identical v1 frame (`RelayedDm::to_postcard` routes digest-less
  frames through the v1 mirror). Default when capability is unknown =
  v1 — a new sender never produces a frame an old relay cannot decode,
  gate, or forward.
- **Receive path**: `disposition_for` rejects digest-less headers from a
  sender whose **confirmed** advert sets `digest_support`
  (`RelayRefusal::MissingInnerDigest`, counted as
  `relay_refused_missing_inner_digest`) — a v2-capable sender cannot
  silently unbind. Unknown/unconfirmed capability keeps the documented
  legacy acceptance (pre-#437 senders). The listener resolves the
  sender's advert from the `CapabilityStore` per frame.

### Advert wire compatibility (postcard positional, verified empirically)

- `digest_support: false` encodes **byte-identically** to the pre-#437
  caps (skip-when-false), so this build's `pending()` state and any
  false-valued advert remain verifiable by old peers.
- New nodes decode old adverts via a two-stage decode
  (`CapabilityAdvert::from_postcard`): v2 shape first, then the v1
  mirror lifted with `digest_support: false`. Because a false bit is
  omitted on re-serialization, signature verification of a v1-decoded
  advert passes against the signer's original bytes.
- **Known transition cost**: an old peer cannot verify a `digest_support
  = true` advert (advert verification re-serializes the decoded struct;
  the appended byte changes the signed bytes) and drops it — old peers
  fall back to raw-QUIC DM path selection for this node until they
  upgrade. Adverts republish every 10 min; the cost is transient and
  self-healing on fleet upgrade. Issue #442 remains open only for any
  richer policy on top.

## Relay-frame wire compatibility (v1 ↔ v2 decode)

Postcard encodes structs **positionally**: `RelayedDm::from_postcard`
two-stage decodes (v2 first, byte-exact v1 mirror fallback,
`inner_digest: None`); the network demux uses it. Cross-shape misparse
is fail-closed (wrong field boundary invalidates the ML-DSA signature).
New→old relay frames never occur: the send path degrades to v1 for
peers without confirmed support (above).

## Transition summary

| Frame | Sender capability known? | Receiver action |
|---|---|---|
| digest present + matches | — | accept (bound) |
| digest present + mismatches | — | hard-drop `InnerDigestMismatch` |
| digest absent | sender confirmed `digest_support` | reject `MissingInnerDigest` (downgrade) |
| digest absent | unknown / pre-#437 sender | accept (legacy guarantees) |

## Tests

- `src/peer_relay.rs`:
  - `build_relayed_dm_binds_inner_digest` — bound build self-binds, v2
    verifies (v2-to-v2 send shape).
  - `substituted_inner_is_refused_before_gating_or_accounting` — both
    arms, no accounting attributed (enforcement).
  - `legacy_digestless_header_still_accepted_per_transition`.
  - `bound_header_rejects_digest_strip_downgrade`.
  - `legacy_v1_wire_decodes_via_two_stage_and_verifies`,
    `v2_wire_round_trips_through_two_stage_decode`,
    `frozen_v1_wire_vector_still_decodes` (wire compat).
  - `unbound_relayed_dm_emits_v1_wire_an_old_relay_parses` —
    v2-sender-to-v1-peer degrades to byte-exact v1; old-relay (v1-struct
    alone) parse; seam decision (None/pending → v1, wired advert → v2).
  - `digestless_header_from_known_v2_sender_is_rejected` — downgrade
    closure + unconfirmed-capability control leg.
- `src/dm_capability.rs`:
  - `false_digest_support_encodes_byte_identical_to_v1_caps`,
    `legacy_advert_decodes_and_verifies_on_new_node` (advert wire).
- `tests/peer_relay_integration.rs`:
  - `relay_hop_substituted_inner_is_refused_before_forward_accounting` —
    relay-hop substitution through the real listener.
  - `digestless_frame_from_known_v2_sender_is_rejected_via_listener` —
    downgrade closure through the real listener + capability store.
  - `relay_round_trip_alice_to_bob_via_charlie` — full three-party round
    trip over the v1 emit path (mixed-fleet default).
