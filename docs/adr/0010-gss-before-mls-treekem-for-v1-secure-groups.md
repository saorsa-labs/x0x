# ADR 0010: GSS Before MLS TreeKEM for v1 Secure Groups

- Status: Accepted
- Date: 2026-05-11

## Context

x0x named groups expose a `MlsEncrypted` confidentiality mode for private
group content. The long-term security target is full MLS TreeKEM semantics,
but the current v1 named-group work has a different immediate requirement:
cross-daemon encrypted group content must work honestly today, with clear
rekey-on-ban behavior, without overstating the security properties that are
actually implemented.

The low-level MLS helper surface exists separately, but the high-level named
group product needs a secure plane that is integrated with:

- invite-based named groups;
- the signed `GroupStateCommit` chain;
- ban/remove authority and epoch changes;
- ML-KEM-768 recipient envelopes;
- the DHT-free, participant-held group data model from ADR 0006.

Full MLS TreeKEM integration for named groups would add larger product and
protocol surface before v1 launch: welcome processing, epoch/exporter
semantics, per-message ratchet behavior, resumption/PSK handling, recovery
UX, and cross-daemon join flows. Shipping those before the rest of the named
group model is stable risks a partially integrated "MLS" claim that users and
reviewers could reasonably read as stronger than the product currently proves.

The implementation and docs already describe the shipped v1 secure model as
GSS (Group Shared Secret):

- generate a 32-byte shared secret at group creation;
- derive per-message AEAD keys from `(secret, epoch, group_id)`;
- rotate the secret on ban/remove to a new epoch;
- seal the new secret individually to each remaining member's ML-KEM-768
  public key;
- fold the current epoch into `security_binding` so secure-plane changes are
  committed into the named-group `state_hash`.

That architectural choice needs an ADR because it defines the security claims
and the boundary between v1 launch scope and future MLS TreeKEM work.

## Decision

x0x v1 named groups SHALL use GSS as the production secure plane for
`MlsEncrypted` named groups. x0x SHALL NOT present this as full MLS TreeKEM.

For v1:

1. A `MlsEncrypted` group has one current shared secret and a monotonic
   `secret_epoch`.
2. Secure group messages derive AEAD keys from the current shared secret,
   epoch, and stable `group_id`.
3. Ban/remove operations rotate the shared secret and increment the epoch.
4. The new secret is sealed only to remaining members' published ML-KEM-768
   public keys.
5. The current epoch is included in the group's `security_binding`, and that
   binding is included in the signed `GroupStateCommit` state hash.
6. Public plaintext group-message endpoints reject `MlsEncrypted` groups; secure
   content uses the secure encrypt/decrypt/reseal endpoints.
7. Documentation and API references must call this model GSS and must state
   that full MLS TreeKEM is future work.

Full MLS TreeKEM remains the target follow-up for stronger group key
management. It is not a v1 launch blocker as long as the shipped docs, API
surfaces, tests, and release notes keep the GSS security claims precise.

## Security Properties

GSS provides:

- cross-daemon encrypted group content using a real shared secret;
- recipient-confidential secret distribution via ML-KEM-768 envelopes;
- rekey-on-ban for future content, because removed members do not receive the
  new epoch secret;
- stable-group binding by deriving message keys from the stable `group_id`;
- state-chain binding by committing `secret_epoch` into `security_binding`.

GSS does not provide:

- per-message forward secrecy within an epoch;
- TreeKEM path-secret updates;
- MLS exporter, PSK, resumption, or welcome semantics;
- post-compromise security equivalent to full TreeKEM;
- erasure of plaintext or ciphertext already received by a removed member.

## Consequences

### Positive

- v1 can ship an honest secure-group model that is already integrated with the
  named-group state chain and ban/remove flow.
- The implementation is simpler to audit than a partial TreeKEM integration.
- Ban/remove semantics are explicit: future content is protected by epoch
  rotation, while previously received content cannot be clawed back.
- The `security_binding` keeps group authority and secure-plane epoch from
  silently drifting.
- Users and reviewers get a precise statement of what "MlsEncrypted" means in
  v1.

### Negative

- The enum name `MlsEncrypted` is stronger than the v1 mechanism. Docs and API
  references must keep correcting that expectation until TreeKEM lands.
- Members share one epoch secret, so compromise of a current member's local
  state compromises current-epoch content.
- GSS gives less cryptographic agility and less fine-grained membership churn
  behavior than TreeKEM.
- A later TreeKEM migration will need explicit compatibility and migration
  design for existing GSS groups.

## Non-goals

- This ADR does not design the eventual TreeKEM migration.
- This ADR does not rename `MlsEncrypted`.
- This ADR does not claim MLS RFC 9420 compliance for named groups.
- This ADR does not weaken the separate low-level MLS helper surface.
- This ADR does not provide data recovery for members who lose their local
  secret material.

## Required Follow-up Work

1. Keep `docs/primers/groups.md`, API docs, and release notes explicit that v1
   uses GSS, not full TreeKEM.
2. Keep tests proving cross-daemon encrypt/decrypt and rekey-on-ban behavior.
3. Keep `security_binding` tied to GSS epoch changes for `MlsEncrypted` groups.
4. **Migration trigger**: Migrate to full MLS TreeKEM when `saorsa-mls`
   implements the post-quantum ciphersuites from `draft-ietf-mls-pq-ciphersuites-04`
   (or its successor RFC) AND named-group v1 has been stable in production for
   at least one release cycle. Until then, keep GSS as the shipped secure plane.
5. Before migrating existing groups, define whether GSS groups are upgraded in
   place, bridged for a transition period, or recreated as TreeKEM groups.

## Acceptance Criteria

This ADR is satisfied only when:

- `MlsEncrypted` named-group docs say GSS, not full MLS TreeKEM;
- ban/remove rotates the GSS secret epoch and excludes removed members from the
  reseal set;
- secure-plane epoch changes are reflected in `security_binding` and therefore
  in the signed group state hash;
- plaintext public-message endpoints reject `MlsEncrypted` groups;
- tests or proof reports cover cross-daemon encrypted round-trip and
  rekey-on-ban behavior;
- future work tracks full MLS TreeKEM as a migration, not as a hidden v1
  assumption.
