# ADR-0018 — Key Lifecycle: Expiry, Renewal, and Revocation

<!-- File name: docs/adr/0018-key-lifecycle-expiry-renewal-revocation.md -->

- **Status:** Accepted (2026-07-04)
- **Date:** 2026-07-04
- **Decision owners:** David Irvine
- **Reviewers:** TBD
- **Supersedes:** none
- **Superseded by:** none
- **Related:** [ADR 0012](./0012-treekem-default-secure-groups.md) (TreeKEM group encryption); [ADR 0014](./0014-treekem-self-leave-owner-driven-rekey.md) (self-leave / owner-driven rekey); [ADR 0016](./0016-role-based-group-authority-flat-admin.md) (flat Admin/Member authority); `src/revocation.rs`; `docs/trust-and-connectivity.md`
- **Follow-up issues:** [#130](https://github.com/saorsa-labs/x0x/issues/130) (implementation ticket); [#127](https://github.com/saorsa-labs/x0x/issues/127) (cryptographic primitives)

## Context

x0x identities — `AgentId` and `MachineId` — are SHA-256 hashes of ML-DSA-65
public keys. Before this ADR there was no mechanism to:

1. Time-limit a certificate so a compromised key self-heals without an out-of-band
   coordinator.
2. Immediately invalidate a specific key that is known to be compromised.
3. Propagate either of these facts across the network.

The cryptographic primitives (`AgentCertificate.not_after`, `is_expired()`,
`RevocationRecord`, `RevocationSet`) were merged to `main` in commit `752a8dc`
as part of issue #127.  This ADR governs how those primitives are wired into
the verified path.

---

## Decision

### Fail-closed on revocation, fail-open on absent expiry

Two distinct failure modes require different defaults:

* **Revocation** is *positive knowledge* — a signed assertion that a key is
  bad.  We always fail **closed**: if the local `RevocationSet` contains a
  record for an identity, every trust gate rejects it immediately, regardless of
  whether a certificate or discovery-cache entry exists.

* **Certificate expiry** is *negative knowledge from a field that may be
  absent* — pre-#130 peers do not set `not_after`.  We fail **open** on absent
  expiry: if `cert_not_after` is `None` we do not block the identity.  This
  preserves interoperability with older peers during rollout.

### Five enforcement points

1. **Announcement ingest** (`lib.rs` — `start_identity_listener`):
   Before inserting any newly-received announcement into the
   `identity_discovery_cache`, check the `RevocationSet`.  Revoked
   announcements are silently dropped.  Expired certificates (where
   `not_after` is present and in the past) are also dropped.
   `DiscoveredAgent` gains `cert_not_after: Option<u64>` so expiry can be
   re-checked later without re-parsing the full certificate.

2. **Verified-path query** (`lib.rs` — `is_agent_machine_verified`):
   The verification query checks revocation before returning `true`.  An
   identity whose `AgentId` or `MachineId` is in the `RevocationSet` returns
   `false`.  An expired certificate (`cert_not_after` present and past
   `unix_timestamp_secs()`) also returns `false`.

3. **DM inbox** (`dm_inbox.rs` — `DmInboxService`):
   After verifying the envelope signature, the pipeline checks whether the
   sender's `AgentId` is revoked.  Revoked-sender messages are dropped and
   counted in `incoming_dropped_revoked` (surfaced in `GET /diagnostics/dm`).

4. **Named-group metadata gate** (`server/mod.rs` —
   `apply_named_group_metadata_event_inner`):
   Revocation is checked **before** the `bypass_verified` branch (the bypass
   handles absent cache entries from the race described in PR #99 — it is not a
   blanket skip of security checks).  A revoked sender's group-metadata events
   are dropped.

5. **Active eviction** (`lib.rs` — `evict_revoked_subject`):
   Whenever a revocation is applied (local issue or gossip receipt), the subject
   is removed from the `identity_discovery_cache` and the `contact_store` entry
   is set to `TrustLevel::Blocked`.  This ensures that cached "verified" entries
   do not persist after revocation.

### Gossip propagation

Revocation records are gossiped on the `x0x.revocation.v1` topic
(`REVOCATION_TOPIC`).  Each payload is a `bincode`-encoded
`Vec<RevocationRecord>` (the current full local set, not a delta).  The full
set is re-broadcast on every identity heartbeat for partition-tolerant eventual
convergence: a node that was offline when a revocation was issued will receive
it on the next heartbeat it hears.

### Storage

The local `RevocationSet` is persisted to `revocations.bin` in `identity_dir`
(magic prefix `X0XR`, versioned, bincode-encoded, atomic-rename write).  On
startup the daemon loads the file; `NotFound` is treated as an empty set.  A
corrupt file logs a warning and falls back to empty (fail-open: the gossip
subscription will re-populate the set on first receipt).

### REST surface

| Method | Path                    | Description                                               |
|--------|-------------------------|-----------------------------------------------------------|
| `POST` | `/identity/revoke`      | Sign and publish a revocation for an agent-id or machine-id |
| `GET`  | `/identity/revocations` | List all revocation records held by this daemon           |

The `POST /identity/revoke` endpoint uses the daemon's own agent keypair as the
issuer.  Authority rules (from `RevocationRecord::verify_authority`):
- **Self-revocation**: always accepted (issuer key equals subject).
- **Issuer-revocation**: accepted only when the issuer keypair signed the
  subject agent's `AgentCertificate`; i.e., the user who vouched for an agent
  may un-vouch it.

There is no `/identity/renew` endpoint in this phase.  Key renewal is handled
at the CLI layer (`x0x agent` key rotation) by issuing a new certificate with
an updated `not_after`; the implementation is deferred to a follow-up.

---

## Validation

The enforcement is proven by automated tests that exercise genuine denial (not
just API contracts):

- **EP2 — verified gate** (`src/lib.rs::revoked_agent_fails_machine_verification_even_when_cached`):
  `is_agent_machine_verified` goes `true → false` after a self-revocation is
  applied via the real `verify_and_insert` receive path, with the identity
  still cached.
- **EP3 — DM inbox** (`src/dm_inbox.rs::revoked_sender_dm_is_dropped_and_counted`):
  a DM from a revoked sender is dropped and increments
  `incoming_dropped_revoked`; a non-revoked sender passes and does not move the
  counter. The gate decision is a pure `drop_if_sender_revoked` helper so the
  counter side-effect cannot silently regress.
- **EP4 — group metadata gate**
  (`src/server/mod.rs::metadata_revoked_sender_denied_even_for_bypass_verified_event`):
  a revoked committer's self-authenticating `GroupDeleted{commit:Some}` is
  denied *before* `bypass_verified` (the group is left intact), while a
  non-revoked but unverified committer's identical event still applies
  (#99 non-regression).
- **End-to-end through a real daemon**
  (`tests/revocation_integration.rs::revocation_denies_verified_binding_end_to_end`):
  `GET /agents/:id/machine` transitions `200 → 404` purely by applying a
  self-revocation via `POST /identity/revoke`, plus the REST contract tests for
  `/identity/revoke` and `/identity/revocations`.
- Cross-daemon gossip propagation of records is exercised by the e2e scripts.

---

## Consequences

### Positive

* Compromised keys can be blocked immediately across the fleet via gossip,
  without requiring a coordinator or certificate authority.
* The grow-only `RevocationSet` G-Set structure eliminates the replay/rollback
  attack class: replaying a revocation is idempotent; there is no "restore"
  message to forge.
* Cert expiry provides time-limited credentials without central issuance —
  suitable for x0x's self-sovereign model.

### Negative / trade-offs

* **No un-revocation**: once revoked, an identity cannot be un-revoked.  The
  operator must issue a new keypair.
* **Gossip-delay window**: a revocation is enforced locally immediately, but
  remote peers receive it on the next gossip propagation cycle.  The heartbeat
  piggyback (≈30 s default) bounds the window.
* **Fail-open on absent expiry**: peers running pre-#130 software have no
  `not_after` field and are not blocked by the expiry gate.  This is by design
  for rollout compatibility; tightening to fail-closed can be done in a later
  ADR once the fleet is fully upgraded.
* **No cross-peer revocation authority**: a third party cannot revoke another
  agent's key.  Only self-revocation and issuer-revocation (user → agent) are
  supported.  This is intentional: it prevents social engineering attacks where
  an attacker convinces the network to revoke a victim's key.

---

## Alternatives considered

### Central revocation authority / CRL

A designated CRL node was considered and rejected:
- Introduces a trust anchor that x0x's self-sovereign model explicitly avoids.
- Creates a single point of failure / censorship.
- Incompatible with the offline-first gossip topology.

### OCSP-style online check per connection

Rejected: adds latency to every connection, requires the issuer to be reachable,
and fails open on network partitions anyway.

### Delta gossip (only new records)

Delta propagation was considered for efficiency.  Rejected in favour of
full-set rebroadcast for correctness: a late-joining node needs the entire set,
and the expected size (tens to low hundreds of records over the daemon's
lifetime) makes the payload overhead acceptable.

---

## Related

- Issue #130 (this ADR's implementation ticket)
- Issue #127 (cryptographic primitives: `not_after`, `RevocationRecord`)
- ADR-0012 (TreeKEM group encryption)
- ADR-0014 (deterministic committer)
- ADR-0016 (flat Admin/Member authority)
- `src/revocation.rs` — record signing, authority verification, set operations
- `docs/trust-and-connectivity.md` — broader trust model
