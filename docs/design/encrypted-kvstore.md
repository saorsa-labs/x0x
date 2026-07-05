# Design: Encrypted Group-Scoped KvStore

## Status

Proposal — design document only, not implemented.

This document describes the application requirement and a suggested architecture
for encrypting KvStore sync traffic for `MlsEncrypted` named groups. It is meant
to be reviewed by x0x maintainers before any implementation PR.

The companion guardrail PR is
<https://github.com/saorsa-labs/x0x/pull/87>. That PR only clarifies current
KvStore behavior; this document proposes the desired encrypted store behavior.

## Review focus

The main request is not a particular struct layout. The request is that x0x
provide a private, group-scoped replicated state store whose security properties
match the named-group secure plane.

Maintainers only need to decide these points before implementation:

| Decision | Recommended default |
|---|---|
| Secure abstraction | Add a `SecureContext`-style boundary so KvStore sync does not depend directly on one group-key backend. |
| Secure backend target | Maintainers should choose whether v1 binds `SecureContext` to the named-group GSS secure plane, the current MLS/TreeKEM module, or an abstraction with both backends. |
| Author binding | Require sign-then-encrypt: each mutation is ML-DSA-65-signed by the author, with `author_id` bound inside the signed bytes, before it is sealed. |
| AAD contract | Bind at least domain/version, `group_id`, `store_id`, and epoch. Do not bind `state_hash` unless maintainers explicitly want stricter stale-state rejection. |
| Rekey behavior | After rekey, publish a current-state checkpoint/snapshot at the new epoch. Do not require late joiners to receive historical epoch keys. |
| API shape | Prefer `POST /groups/:id/stores` as the primary group-scoped API; keep existing `/stores` signed/plaintext behavior compatible. |

## Required use case: private group application state

A group application needs a private replicated state store for a secure named
group. New members should receive the current state, removed members should lose
access to future updates, store structure must not leak on gossip, and every
accepted mutation must carry a verified agent author so the application can
enforce trust, review, moderation, and provenance policies.

The application should be able to use this through the daemon API. It should not
need to hand-roll encryption over `/groups/:id/secure/encrypt` or encrypt values
before writing them into a plaintext KvStore.

## User stories

- As an app developer, I want to create a replicated KvStore bound to a secure
  named group, so my app can store shared private workspace state without
  building its own encryption layer.

- As a group member, I want store keys, values, content types, metadata, and
  mutation structure to be confidential on gossip, so observers and non-members
  cannot infer what the group is working on.

- As a group member, I want every accepted store mutation to have a verified
  agent author, so the app can show who changed shared state and can reject
  updates forged as another member.

- As a member of a group store with mixed roles, I want some members to be
  read-only and others to be writers, so a member who joins to consume shared
  state cannot modify it.

- As a contributor in an author-owned or moderated store, I want records I
  authored to be modifiable or removable only by me or a designated moderator, so
  another member cannot silently overwrite or delete my contribution.

- As the owner/moderator of a curated store, I want to control which members may
  commit changes, so the shared state reflects governed curation rather than
  unrestricted member writes.

- As a daemon/API client, I want to create and use this encrypted store through
  x0xd REST endpoints, so non-Rust applications can rely on x0x's secure plane
  directly.

- As a newly invited member, I want to receive the current store state after
  joining, so I can participate without needing old epoch keys or historical
  ciphertext.

- As a group admin, I want removing or banning a member to prevent them from
  reading future store updates, so the store follows the same rekey-on-ban
  expectation as secure group messaging.

- As an offline member, I want to catch up to the latest valid state when I
  reconnect, so temporary disconnection does not corrupt or permanently fork the
  shared store.

- As an app developer, I want this to work whether the secure backend is the
  named-group GSS plane, the MLS/TreeKEM module, or both, so application code
  depends on a stable secure-store abstraction rather than the current
  key-management implementation.

## Hard requirements

1. Encrypted stores MUST NOT publish plaintext `KvStoreDelta`s or plaintext
   full-state checkpoints on gossip.

2. Confidentiality MUST cover key names, values, content types, application
   metadata, allowlist mutations if present, and the logical mutation shape. A
   value-only encryption wrapper that leaves keys or store shape visible is not
   sufficient.

3. Every accepted mutation MUST have non-forgeable per-agent authorship. GSS is
   a shared-secret system, so successful AEAD decryption only proves that some
   current key holder wrote the record. The encrypted KvStore must preserve
   author accountability by verifying an ML-DSA-65 signature over the mutation.

4. The encrypted wire format MUST bind records to the intended group and store.
   At minimum, AEAD AAD should include a domain/version string, `group_id`,
   `store_id`, and epoch. This prevents cross-protocol, cross-group, and
   cross-store replay.

5. Late joiners MUST be able to bootstrap from a current-state checkpoint at the
   current group epoch. They SHOULD NOT need previous epoch secrets or a replay
   of historical ciphertexts.

6. Removed or banned members MUST lose access to future encrypted store updates
   after the group rekeys. This matches the GSS guarantee: old content already
   received cannot be clawed back, but future content is protected.

7. The daemon API MUST expose the feature. A Rust-library-only encrypted store
   would not serve daemon clients.

8. The design MUST keep the chosen secure-backend claim honest. If v1 uses GSS,
   it must not claim full MLS TreeKEM or per-message forward secrecy within an
   epoch. If v1 uses the MLS/TreeKEM module, the implemented TreeKEM properties
   and limitations must be documented explicitly.

### Forward-compatible write authorization

v1 MAY enforce only active group membership as the write rule. That is acceptable
as an initial scope, but it means any active member can overwrite or delete any
key under LWW semantics.

The design MUST preserve the verified author identity at the receive/merge
decision point and MUST NOT adopt a wire format, checkpoint format, or store-id
model that prevents a later per-store write-authorization layer.

A follow-up iteration SHOULD add policy over the verified author identity, such
as writer allowlists, read-only members, author-owned records, moderator-gated
removals, and role-gated checkpoint publication.

This is the natural completion of author binding: v1 establishes who wrote a
record; the policy layer decides whether they were allowed to write it.

## Non-goals

- Do not require late joiners to decrypt historical values or old deltas.

- Do not preserve a full application-level audit log inside x0x. x0x should
  provide verified authorship; applications can decide what history, moderation,
  review queues, or reputation data to retain.

- Do not introduce new cryptography. Use the existing named-group secure plane
  and agent ML-DSA signing identity.

- Do not require full MLS TreeKEM before encrypted stores can ship.

- Do not solve local at-rest encryption in this document. This design concerns
  group-scoped sync confidentiality and authorization on the gossip path.

## Current state

The relevant pieces already exist, but they are not connected:

- `src/kv/sync.rs` publishes and receives bincode-encoded `(PeerId,
  KvStoreDelta)` values directly on a gossip topic.

- `src/kv/store.rs` has `AccessPolicy::Encrypted { group_id }`, but current
  sync does not encrypt deltas. The REST create path also hardcodes signed
  stores.

- `src/kv/delta.rs` places key names, entries, metadata, allowlist changes, and
  version information inside the plaintext delta.

- `docs/adr/0010-gss-before-mls-treekem-for-v1-secure-groups.md` defines the
  accepted v1 secure-group model: GSS, epoch rotation on ban/remove, and
  ML-KEM-sealed secret delivery to remaining members.

- `src/mls/` also contains the current `saorsa-mls` / TreeKEM-backed MLS module.
  The low-level MLS capability and the named-group GSS secure plane are both
  present in the codebase; maintainers should choose which backend encrypted
  KvStore targets first.

- `/groups/:id/secure/encrypt`, `/groups/:id/secure/decrypt`, and
  `/groups/:id/secure/reseal` prove the named-group secure plane works across
  daemons, including rekey-on-ban.

- `/agent/sign` already exposes detached ML-DSA-65 signing for daemon clients
  that need durable author signatures over stored records.

This is therefore integration work over existing primitives, not a request for a
new cryptographic system.

## Proposed model

An encrypted KvStore is a KvStore whose replication topic carries encrypted
records instead of raw `KvStoreDelta`s. The store remains a CRDT; encryption is a
wire envelope around deltas and checkpoints.

The logical layering is:

```text
KvStore mutation/checkpoint
  -> canonical signed record with author identity
  -> AEAD seal using the group's secure context
  -> gossip payload on the store topic
```

On receive:

```text
gossip payload
  -> AEAD open using the group's secure context
  -> verify author signature and membership/write authorization
  -> merge delta or checkpoint into the local KvStore
```

### Store scope and identity

Each encrypted store is bound to exactly one stable named-group id and one stable
store id.

The store id must be stable across members. It should not be derived from each
local agent id in a way that causes different members to compute different store
ids for the same group store.

Suggested inputs for store identity:

- stable `group_id`;
- application-supplied store name or purpose;
- creator or authority id, if needed;
- a random nonce if the same group can create multiple stores with the same
  display name.

The chosen `store_id` is security-relevant because it is included in AAD and in
the signed payload. A delta from one store must not be replayable into another
store owned by the same group.

### SecureContext boundary

KvStore sync should not know whether group security is backed by the named-group
GSS secure plane, the current MLS/TreeKEM module, or a backend abstraction that
can support both. It should depend on a small secure-context capability for a
given `group_id`.

The secure-backend target is an explicit maintainer decision. Current x0x has two
relevant surfaces: named-group secure endpoints documented as GSS, and a
`src/mls/` module backed by `saorsa-mls` / TreeKEM. This proposal should not
silently assume which one defines encrypted KvStore v1.

Possible v1 targets:

- bind `SecureContext` to the current named-group GSS secure plane;
- bind `SecureContext` to the current MLS/TreeKEM module;
- define `SecureContext` as a backend abstraction that can select either GSS or
  MLS/TreeKEM behind the same KvStore sync call sites.

Conceptual operations:

- return the stable `group_id`;
- return the current encryption epoch;
- seal plaintext with caller-supplied AAD;
- open ciphertext for a declared epoch and AAD;
- report whether a verified author is an active member or otherwise authorized
  to write.

If maintainers choose a GSS-backed v1, the implementation can wrap existing GSS
state from `GroupInfo`:

- `shared_secret`;
- `secret_epoch`;
- `stable_group_id()`;
- `secure_message_key()` / `derive_message_key(secret, epoch, group_id)`;
- the AEAD and nonce strategy chosen by maintainers for encrypted store records.

If maintainers choose the MLS/TreeKEM module, `SecureContext` should expose the
equivalent current epoch, seal/open, and membership checks from that backend. In
either case, encrypted KvStore call sites should continue to use the same
secure-context boundary.

### Sign-then-encrypt

Encrypted stores need both confidentiality and attributable writes.

Because GSS is a shared secret, AEAD authentication alone means only "someone
with the current group secret produced this." That is not enough for applications
that enforce per-agent trust, review, blocking, moderation, or provenance.

The proposed construction is sign-then-encrypt:

1. Build a canonical mutation or checkpoint payload.
2. Domain-separate it for encrypted KvStore signing.
3. Sign it with the author's ML-DSA-65 agent key.
4. Include the author id, public key, signature algorithm, signature, and signed
   payload inside the plaintext record.
5. AEAD-seal the signed record with the group secure context.

The signature is inside the ciphertext so passive observers do not learn which
member authored each update. Receivers decrypt first, then verify the author's
signature and authorization before applying the mutation.

The signed bytes should include at least:

- domain/version string, for example `x0x.kv.signed-mutation.v1`;
- `group_id`;
- `store_id`;
- epoch;
- author id;
- mutation kind: delta or checkpoint;
- canonical serialized payload bytes.

The author id must be deterministically derived from the included ML-DSA-65
public key using the same derivation as `AgentId::from_public_key` (currently a
32-byte public-key hash). Receivers must derive the `AgentId` from the included
public key, compare it to the claimed `author_id`, and reject the record before
signature verification or authorization if they differ. A record signed by one
agent but claiming another agent id must be rejected.

### AEAD envelope and AAD

The encrypted outer envelope should carry only routing and decryption metadata.
It should not expose logical store contents.

Illustrative fields:

```text
EncryptedKvStoreRecordV1 {
  group_id,
  store_id,
  epoch,
  nonce,
  ciphertext
}
```

The epoch is plaintext so receivers can select the right backend epoch/key before
decryption. That is an intentional tradeoff: observers can see epoch boundaries
even though they cannot decrypt the record contents.

AAD should be deterministic and domain-separated. Recommended minimum:

```text
x0x.kv.encrypted-record.v1 || group_id || store_id || epoch
```

Preferred nonce strategy: use XChaCha20-Poly1305 with a 192-bit nonce if the
chosen secure backend accepts that AEAD for store records. If maintainers choose
ChaCha20-Poly1305 with a 96-bit nonce, the implementation should guarantee nonce
uniqueness per epoch key, preferably with a persisted per-store/per-epoch
counter. Random 96-bit nonces should be used only with an explicit per-epoch-key
record bound; around 2^32 records under one key gives roughly 2^-32 collision
risk by the birthday bound.

Do not bind `state_hash` by default. Binding `state_hash` would make records
tighter to a specific signed group-state revision, but it also risks dropping
otherwise valid in-flight deltas when metadata-only group revisions occur without
a secure-epoch change. If maintainers prefer stronger stale-state binding, make
that an explicit decision and document the in-flight behavior.

### Publish flow

For an encrypted store, `publish_delta` conceptually becomes:

1. Check that the local agent is an active member and authorized writer for the
   group/store.
2. Build a `KvStoreDelta` as today.
3. Canonically serialize and sign the delta payload with the local agent key.
4. Build AAD from domain, `group_id`, `store_id`, and epoch.
5. Seal the signed record with the current `SecureContext`.
6. Publish the encrypted envelope to the store topic.

Plaintext `KvStoreDelta` publication must be impossible for stores created as
encrypted.

### Receive flow

For an encrypted store, the subscriber should:

1. Decode the encrypted envelope.
2. Recompute AAD from envelope metadata and local store binding.
3. Open the ciphertext with the group secure context for that epoch.
4. Parse the included ML-DSA-65 public key, derive `AgentId` from it, and require
   it to equal the claimed author id.
5. Verify the signed inner record domain, `group_id`, `store_id`, epoch, author
   id, and signature with the derived author's public key.
6. Check that the author is allowed to write under the store's agreed
   authorization model, at minimum active group membership for v1.
7. Merge the decrypted delta or checkpoint.
8. Drop undecryptable, unauthenticated, cross-store, stale, or unauthorized
   records without applying them.

Logging should avoid printing decrypted keys or values.

## Rekey and checkpoint semantics

Rekey is the highest-risk part of this design. The proposal is to make it
simple: after a group rekeys, the encrypted store converges via a new-epoch
current-state checkpoint.

Required behavior:

- After ban/remove, new store writes use the new group epoch.

- Removed members do not receive the new epoch secret, so they cannot decrypt
  future deltas or checkpoints.

- At least one remaining authorized member publishes a full current-state
  checkpoint encrypted at the new epoch.

- Late joiners bootstrap from the latest valid checkpoint at the current epoch.
  They do not need old epoch secrets.

- Old-epoch ciphertext can remain on gossip or in local caches, but it is not
  required for a new member to become useful.

For late-join and post-rekey bootstrap, a checkpoint should act as a full-state
compaction boundary. A receiver that starts from checkpoint N applies only deltas
authorized after that checkpoint's watermark. Older deltas are ignored for that
store view. Existing replicas may retain older material locally, but it is not
required for convergence from the checkpoint.

The checkpoint must contain enough CRDT state to prevent removed keys from
resurrecting during merge. For OR-Set-style structures, that means the checkpoint
format must account for active entries and the relevant tombstone/remove state,
not just visible key/value pairs, unless maintainers choose an explicit reset
semantics for checkpoints.

If tombstones grow without bound, implementations need a compaction or GC rule
tied to checkpoint acceptance. That rule must not let old deltas resurrect keys
that were deleted before the accepted checkpoint.

### Partitioned concurrent rekeys

The hardest unresolved case is concurrent rekey across a network partition. For
example, two admins in separate partitions each ban a different member, each
advances the secure epoch, and each publishes a new-epoch checkpoint. When the
partition heals, the implementation must not blindly merge both encrypted store
branches.

The encrypted store needs an explicit reconciliation rule tied to the group
authority/state-commit model. Candidate rule: only accept checkpoints and deltas
whose epoch/backend state belongs to the winning accepted group-state branch;
after roster reconciliation, an authorized remaining member publishes a fresh
checkpoint for the reconciled group state. Deltas/checkpoints from superseded
branches are ignored or retained only as local conflict material, never merged
silently.

This is a maintainer design-session topic because the correct answer depends on
named-group state-chain conflict handling, admin authority, partition behavior,
and secure-secret distribution.

Open implementation choice: who publishes the checkpoint?

This is a checkpoint-authority decision, not just an availability decision. A
valid-AEAD checkpoint can rewrite the visible store, so receivers need a rule for
whose checkpoints are authoritative. A removed or soon-to-be-removed member must
not be able to pre-publish a stale or malicious checkpoint that remaining members
apply after a rekey.

Candidate mitigations include:

- the authority/admin who caused the rekey publishes immediately;
- checkpoint publication requires a quorum or co-signature from active members;
- receivers accept the highest checkpoint sequence only from a non-removed
  authority on the winning group-state branch;
- checkpoints include the relevant `GroupStateCommit` / removed-member set, and
  receivers verify both the checkpoint author and their own membership against
  that state before applying.

This choice should be made by maintainers because it interacts with group
authority, offline behavior, and anti-entropy.

## API shape

Preferred primary route:

```http
POST /groups/:id/stores
```

Example request shape:

```json
{
  "name": "private-app-state",
  "purpose": "application-state"
}
```

The group id is implicit from the route, so the daemon can reject creation if the
caller is not an active member or if the group is not `MlsEncrypted`.

Existing `/stores` behavior should remain compatible. It can continue to create
signed/plaintext stores by default. If maintainers prefer adding optional fields
to `/stores`, the important requirement is that daemon clients can request a
group-scoped encrypted store without falling back to application-side encryption.

Suggested response fields:

- `store_id`;
- `group_id`;
- `topic`;
- `policy: "encrypted"`;
- current epoch;
- whether a current checkpoint is available.

Existing key operations can remain store-id based if the handle is already bound
to the encrypted store. The implementation must ensure that `PUT`, `GET`,
`DELETE`, join, and list behavior does not accidentally expose plaintext keys or
values over gossip for encrypted stores.

## Compatibility and migration

No existing store should silently change behavior.

- Existing signed stores remain signed/plaintext.

- Existing `/stores` clients continue to work.

- Encryption is fixed at store creation. A signed/plaintext store should not
  silently become encrypted in place, because `group_id`, `store_id`, AAD, topic
  expectations, and historical plaintext exposure are creation-time properties.
  Migrating means creating a new encrypted group-scoped store, copying the
  current state into a new encrypted checkpoint, and moving clients to the new
  store id.

- `AccessPolicy::Encrypted { group_id }` should either become the real encrypted
  policy only when the secure sync path is available, or remain clearly rejected
  / reserved until then.

- If encrypted stores are introduced for persisted daemon state, the store format
  should include a version marker so future TreeKEM-backed contexts can migrate
  without changing application-visible store ids.

## Security properties

This design aims to provide:

- confidentiality of encrypted store contents and structure on gossip;
- AEAD integrity for sealed records;
- non-forgeable per-agent authorship for accepted mutations;
- preservation of the verified author at the receive/merge decision point, so a
  later write-policy layer can authorize by author, role, or store policy;
- cross-store and cross-group replay protection through AAD and signed payload
  binding;
- rekey-on-ban future confidentiality matching the chosen secure backend;
- current-state bootstrap for late joiners.

This design does not provide:

- per-message forward secrecy within a GSS epoch;
- deletion of plaintext or ciphertext already received by a removed member;
- hiding network-level traffic timing, topic membership, or approximate message
  sizes;
- hiding the timing or frequency of epoch rotations from gossip observers,
  because the encrypted envelope carries epoch in plaintext for key selection;
- per-store or per-key write policy unless maintainers choose to include that in
  v1. With active group membership as the only write rule, any active member can
  overwrite or delete any key under LWW semantics;
- application-level history, reputation, moderation UX, or rollback policy.

## Test plan

Implementation should include tests at three levels.

Unit tests:

- encrypted delta round-trip with correct group/store/epoch;
- decrypt failure for wrong `group_id`, wrong `store_id`, wrong epoch, wrong AAD,
  or tampered ciphertext;
- signature verification failure for forged author id, wrong public key, tampered
  payload, or missing signature;
- checkpoint merge does not resurrect removed keys.

Integration tests:

- encrypted store creation is rejected for non-members;
- encrypted store creation is rejected for non-`MlsEncrypted` groups unless
  maintainers explicitly support a signed-public variant;
- encrypted stores never call the plaintext `KvStoreDelta` publish path;
- offline member catches up from encrypted checkpoint.

End-to-end tests mirroring `tests/e2e_named_groups.sh`:

- Alice creates an `MlsEncrypted` group and encrypted store; Bob joins and reads
  a value written by Alice.

- A gossip observer or non-member cannot deserialize plaintext key names or
  values from the store topic.

- Bob writes an update; Alice verifies Bob as the author after decrypting.

- A forged update attributed to Alice but signed by Bob is rejected.

- Alice bans Bob; the group rekeys; Charlie or Alice can decrypt new-epoch store
  updates; Bob cannot.

- A late joiner receives current state from a new-epoch checkpoint without old
  epoch secrets.

## Open implementation questions

These are implementation details for maintainers. They should not change the
required use case above.

1. Should encrypted stores bind `state_hash` or `state_revision` in AAD, or is
   epoch binding sufficient for v1?

2. Who is responsible for publishing post-rekey and late-join checkpoints?

3. Should checkpoints be modeled as full CRDT state, a full delta from genesis, or
   an explicit reset-plus-state operation?

4. Does the primary API live only under `/groups/:id/stores`, or should `/stores`
   also accept `policy: "encrypted"` and `group_id`?

5. Given the forward-compatible write-authorization requirement, can v1 ship with
   active group membership as the only write rule while preserving the author and
   policy hook needed for read-only members, writer allowlists, author-owned
   records, and moderator-gated removals later?

6. How much previous-epoch grace should receivers allow for in-flight deltas
   around a rekey, if any?

## Summary

The desired feature is an encrypted and authenticated KvStore for secure named
groups. The important product outcomes are private group state, encrypted store
structure, verified per-agent authorship with a path to later write-policy
enforcement, rekey-on-ban future confidentiality, current-state bootstrap for
late joiners, and daemon API access.

The suggested implementation is to wrap KvStore deltas and checkpoints in a
sign-then-encrypt envelope backed by a `SecureContext` abstraction. Maintainers
should decide whether the first backend is the named-group GSS secure plane, the
current MLS/TreeKEM module, or an abstraction that supports both without changing
the application-facing store model.
