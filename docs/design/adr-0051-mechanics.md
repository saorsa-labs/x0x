# ADR-0051 Mechanics — Peer Relay (X0X-0070)

Maintained mechanics and post-decision corrections for
[ADR-0051](../adr/0051-application-level-peer-relay.md). The ADR body is a
snapshot; changes to shipped behavior are recorded here.

## RESOLVED by #437: header now binds inner via `inner_digest`

ADR-0051's Decision bullet 2 and Negative section record the pre-fix
weakness: `RelayHeader::signing_bytes()` signed **no digest of
`RelayedDm.inner`**, so a relay (or any on-path holder of a valid header)
could carry a *different* valid `DmEnvelope` under an unrelated header.
Inner-envelope crypto still gated final delivery, but header-level sender
gating (#193 contact gate) and forward accounting were attributable to a
sender who did not author the carried payload.

The fix (branch `fix/437-relay-inner-binding`, 2026-08-29):

- **Wire**: `RelayHeader` gains `inner_digest: Option<[u8; 32]>`
  (`#[serde(default)]`, additive — old peers decode it as `None`).
  The digest is `blake3(postcard(DmEnvelope))` — the canonical wire bytes
  that a relay forwards verbatim and the recipient re-injects onto the
  direct-DM channel, so the binding covers the exact payload that travels.
- **Signing**: a header **with** a digest signs under a new domain
  (`x0x-relay-hdr-v2`): same field layout as v1 plus the trailing digest.
  A header **without** one keeps the legacy v1 layout byte-for-byte, so
  pre-#437 signatures still verify. Because the digest (and its presence)
  is inside the signed bytes, stripping `inner_digest` from a bound header
  changes the signing bytes — the signature fails. The binding is
  un-strippable; downgrade is impossible.
- **Send path**: `PeerRelay::build_relayed_dm` always computes and signs
  the digest (serialization failure fails the build — a digest-less build
  would re-open #437). New senders always bind.
- **Receive path**: `PeerRelay::disposition_for` enforces
  `header.inner_digest == blake3(inner)` immediately after header
  signature verification and **before** freshness counting, the
  `DeliverLocally` receive accounting (`relay_received`), the #193
  contact/blocked sender gates, and forward-quota admission. A mismatch
  hard-drops with `RelayRefusal::InnerDigestMismatch` and increments
  `relay_refused_inner_digest_mismatch`. Enforcing at this single choke
  point covers both arms (final recipient and intermediate relay) and
  guarantees no gating or accounting is attributed to a substituted
  payload.

## Transition (mirrors ADR-0021's attestation transition)

- **Present-but-mismatched** digest → hard-drop, always. A mismatch is
  active substitution under a valid header.
- **Absent** digest (legacy pre-#437 sender) → accepted with exactly
  today's (pre-fix) guarantees. The header still authenticates routing;
  inner-envelope crypto still gates final delivery; the residual
  substitution window remains for those senders only.
- **End-state**: once a `DmCapabilities`-style advert confirms digest
  support on the peer fleet, absence becomes rejectable and the residual
  closes. (Analogous to ADR-0021: "once attestation support is ubiquitous
  … receivers hard-require attestations and the residual closes.")

## Tests

- `src/peer_relay.rs`: `build_relayed_dm_binds_inner_digest`,
  `substituted_inner_is_refused_before_gating_or_accounting` (both arms,
  counters, no accounting), `legacy_digestless_header_still_accepted_per_transition`,
  `bound_header_rejects_digest_strip_downgrade`.
- `tests/peer_relay_integration.rs`:
  `substituted_inner_under_bound_header_is_hard_dropped` — drives the
  real `spawn_relay_dm_listener` path via the synthetic-inbound seam:
  counter advances, `relay_received` unchanged, nothing reaches the
  direct subscribers.
- Existing legacy-shape tests (unit `relay_header_*`, integration
  `signed_relayed` consumers) keep passing unchanged — proof the v1
  layout is byte-compatible.
