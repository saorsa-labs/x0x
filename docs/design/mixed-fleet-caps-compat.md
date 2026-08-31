# Mixed-fleet capability + card compatibility (#448 / #450)

Status: implemented 2026-08-31 (Home-Suite hs-F3). Fixes issues #448 and #450
against the v0.40.4 fleet. Companion fixtures live in the module tests named
below.

## Problem

Two independent breaks hit every v0.40.4 (pre-#437) peer the moment a new
binary joins the mesh:

1. **#448 — advert drop.** The capability advert is positional postcard and
   the caps struct sits *inside* it before `signature`. A true
   `digest_support` appends one byte; an old peer's single-struct decode
   misparses that byte as the start of the signature, verification fails, and
   the advert is dropped. The old peer then holds **no** capability entry for
   the new daemon: old→new strict (product-default) DMs 409 for the whole
   mixed window, relay seeding loses `kem_public_key`, and non-strict sends
   degrade to raw-QUIC (broken NAT↔NAT). Nothing heals in place — the
   targeted refresh just fetches another undecodable advert.
2. **#450 — card signature break.** `AgentCard::signable_bytes` embeds
   `bincode(dm_capabilities)`. Cards travel as JSON; the old reader's caps
   struct has no `digest_support` and no `deny_unknown_fields`, so the field
   is dropped on parse and the verifier's re-encoded bincode differs from the
   signer's bytes → every card from a new binary fails verification on old
   peers.

## Design (single source of truth)

The daemon's live `DmCapabilities` watch value remains the ONLY source of
truth. Both wire artifacts are projections of it, and every encoding a peer
re-serializes during signature verification is frozen to the pre-#437
five-field shape (`dm::DmCapabilitiesV1Wire`):

| Carrier | Bytes on the wire | Signed bytes | Old peer (v0.40.4) |
|---|---|---|---|
| Steady advert (`x0x/caps/v1`) | frozen v1 shape — the true bit is **never published** here | same v1-shape bytes | decodes natively, verifies, retains FULL v1 knowledge (protocol version, inbox, KEM key) |
| Digest extension (`x0x/caps/v2/digest`, NEW topic) | signed `DigestSupportExtension`: one machine-bound bit | own domain `x0x-caps-digest-v1` | never subscribed — invisible, exactly the X0A3/X0A4 topic-versioning pattern |
| AgentCard `dm_capabilities` | JSON, full struct incl. the bit (informational) | signable bytes encode ONLY the frozen v1 projection | drops the bit on parse, rebuilds identical bincode, signature verifies |

Rationale for the extension over dual-publishing two full adverts: the base
advert keeps ONE canonical signed form on the steady topic (no same-timestamp
flip-flop between two encodings in receiver caches), the bit merges
orthogonally to the advert's own ordering, and the extension is 6 fields
instead of a duplicate advert.

### Trust rules for the digest bit

The card's signable bytes cannot cover `digest_support` (that is the whole
fix), so the bit is accepted ONLY from signed sources:

- the runtime advert when it still carries the bit inline (pre-#448 peer
  publishing the v2 shape — new peers decode it via the existing two-stage
  `from_postcard`), or
- the signed extension.

`CapabilityStore::insert_from_card` clamps a card-carried bit to `false`:
a mid-flight flip of an unsigned field can never steer relay lane selection
(the bit's only consumer, via `peer_relay::peer_advertises_inner_digest`).
Fail-safe in both directions — `false` only ever degrades relay frames to the
byte-identical v1 shape, which every receiver accepts.

### Store merge semantics

`CapabilityStore` keeps `digest_exts` beside the advert map:

- extension recorded with the same freshness/skew/replay ordering as adverts
  (`apply_digest_extension`);
- merged into a cached binding only when machine ids match (churn-safe);
- either arrival order converges: extension-first waits in the lane and is
  applied at the next base-advert insert; extension-after flips the cached
  bit in place;
- an expired extension never colors a later advert.

## Population matrix (mixed window)

| Sender → Receiver | Base advert | Digest bit | Strict DMs old→new |
|---|---|---|---|
| new (this fix) → v0.40.4 | decodes + verifies | invisible (fine) | restored — full v1 caps knowledge |
| new (this fix) → pre-#448 new | two-stage decode | not learned → v1 relay frames (safe) | fine |
| new (this fix) → new (this fix) | two-stage decode | via extension | fine, digest semantics kept |
| v0.40.4 → new | two-stage decode | false (correct) | fine (unchanged) |
| pre-#448 new → new | v2-shape decode, bit inline | inline | fine (unchanged) |

Known fail-closed residue: **cards signed by a pre-#448 build with
`digest_support: true`** fail signature verification on this build (the
signer's bytes included the bit; ours cannot recompute them). Those cards
exist only between dev builds of the unreleased 0.40.x line; re-import or
any advert refresh restores the binding. Not fixable without accepting an
unsigned bit (see trust rules).

## Positional-wire audit (the postcard trap)

No field was INSERTED before an existing one anywhere:

- the advert body LOSES a byte (the bit is skipped exactly like a `false`
  bit always was — byte-identical to the pre-#437 encoder);
- `DigestSupportExtension` is a new record on a new topic (no legacy decoder
  exists);
- card signable bytes keep the pre-#437 caps encoding for every caps value
  an old peer can produce;
- new frozen-bytes vectors pin `MachineAnnouncementV3` (bincode unsigned
  body) and the X0R2 file (`PersistedRevocation` carrying
  `RevokedSubject::AgentMachineBinding`) against future insertion.

## Convergence story

The steady advert stays v1-shaped for as long as v0.40.4 peers exist in the
fleet. Once telemetry/announces show the fleet fully upgraded past 0.40.4,
the extension lane can be retired by folding the bit into a bumped advert
protocol version — the same two-step X0A3→X0A4 playbook.

## Fixture index

- `groups::card::tests::true_digest_card_verifies_under_frozen_v0404_decoder`
  (#450, new→old) and `old_signed_card_verifies_on_new_decoder` (old→new);
  `frozen_projection_is_the_only_old_compatible_encoding` pins that the full
  struct encoding remains old-incompatible (the freeze is load-bearing).
- `dm_capability::tests::true_caps_advert_from_new_code_is_old_decoder_verifiable`
  (#448, new→old against the `CapabilityAdvertV1Wire` replica);
  `legacy_advert_decodes_and_verifies_on_new_node` (pre-existing, old→new);
  `false_digest_support_encodes_byte_identical_to_v1_caps` (pre-existing,
  false-bit pin).
- Extension: `digest_extension_{before_base_advert_merges_on_arrival,
  after_base_advert_applies_immediately,is_machine_bound,rejects_replay_and_stale_timestamps}`,
  `card_imported_digest_bit_is_clamped_untrusted`, and service-level
  `service_publishes_signed_digest_extension_on_loopback`,
  `service_emits_no_digest_extension_when_bit_is_false`,
  `peer_advert_plus_extension_converge_in_the_store`.
- Review-gap vectors: `machine_announcement_v3_unsigned_bytes_match_frozen_vector`
  (lib.rs), `revocations_v2_file_bytes_match_frozen_vector` (revocation.rs).
