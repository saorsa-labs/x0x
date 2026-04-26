**Use named groups for invite-based coordination, and MLS helpers for encryption.**

> Status: the current upstream `x0x` daemon has two separate group surfaces: `x0x group ...` for named groups and invites, and `x0x groups ...` for low-level MLS helpers. They are related, but they are not yet one turnkey secure group-chat product.

## Stable identity + evolving validity (Phase D.3)

Every named group has two identifiers:

- a **stable `group_id`** derived from the creator's agent id + creation
  timestamp + a random nonce. This never changes — renames, role changes,
  roster churn all preserve it.
- an **evolving `state_hash`** that commits to the group's current
  effective state: roster (active + banned), role assignments, policy,
  public metadata, security binding, and withdrawal status.

Every authoritative state change produces a signed
[`GroupStateCommit`](../design/named-groups-full-model.md#stable-identity-vs-evolving-validity)
with a monotonic `revision`, a `prev_state_hash` linking to the previous
commit, and an ML-DSA-65 signature by the actor. Peers verify the
signature, revision monotonicity, and chain linkage before accepting the
commit; stale actions and chain breaks are rejected.

Public directory cards carry the same authority signature. Higher
revisions supersede lower ones immediately on peers — TTL is only cache
cleanup, not the primary validity mechanism. Owners can seal a terminal
**withdrawal** commit that instructs peers to evict any prior public
card regardless of TTL.

```bash
# Inspect the signed state chain
x0x group state <group_id>
# or
curl -H "Authorization: Bearer $TOKEN" "http://$API/groups/<group_id>/state"

# Advance the chain + republish the signed card (owner/admin)
curl -X POST -H "Authorization: Bearer $TOKEN" \
  "http://$API/groups/<group_id>/state/seal"

# Terminally withdraw / hide the group (owner)
curl -X POST -H "Authorization: Bearer $TOKEN" \
  "http://$API/groups/<group_id>/state/withdraw"
```

### Honest v1 secure model — Group Shared Secret (GSS)

For `MlsEncrypted` groups x0x v1 ships **GSS**, not MLS TreeKEM:

- a 32-byte shared secret is generated at group creation;
- on ban / remove, the secret is rotated to a new `epoch` and the new
  secret is sealed individually to each remaining member's published
  ML-KEM-768 public key (see `/groups/:id/secure/reseal`);
- per-message AEAD keys are derived from `(secret, epoch, group_id)`
  with BLAKE3;
- the current `secret_epoch` is folded into `security_binding` and
  therefore into `state_hash` — changes to membership and the secure
  plane cannot silently drift.

**What GSS provides**
- cross-daemon encrypt/decrypt proven end-to-end (alice/bob/charlie with
  independent keystores round-trip in `tests/e2e_named_groups.sh`);
- rekey-on-ban: a banned peer loses access to future epoch content
  because the new secret is never sealed to them;
- post-quantum confidentiality on the envelope (ML-KEM-768 + ChaCha20-Poly1305).

**What GSS does NOT provide**
- per-message forward secrecy within a single epoch;
- full MLS TreeKEM semantics (PSK, exporter secrets, resumption, etc.);
- forgetting plaintext/ciphertext a removed peer already received.

Full MLS TreeKEM is planned follow-up work and is not a v1 blocker.

## Distributed shard discovery (Phase C.2)

Public group discovery is a **sharded gossip index** over PlumTree — no
DHT, no special node roles. Each `PublicDirectory` group publishes its
signed `GroupCard` to:

- one **tag shard** per normalised tag (`x0x.directory.tag.{N}`),
- one **name shard** per whitespace-delimited name word
  (`x0x.directory.name.{N}`),
- exactly one **exact-id shard** (`x0x.directory.id.{N}`).

Where `N = BLAKE3("x0x-group-tag" || lowercase(key)) % 65536`.

Peers subscribe to shards of interest; subscriptions persist across
daemon restart and resubscribe with 0–30s random jitter to avoid
anti-entropy storms. Every 60s each subscriber emits a `Digest` on its
shards; peers compare and issue `Pull` requests for missing/stale
entries. Receivers verify each card's ML-DSA-65 signature before caching;
the cache supersedes by revision and evicts on withdrawal regardless of
TTL.

```bash
# Subscribe to a tag shard
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  "http://$API/groups/discover/subscribe" \
  -d '{"kind":"tag","key":"ai"}'

# List my subscriptions
curl -H "Authorization: Bearer $TOKEN" "http://$API/groups/discover/subscriptions"

# Presence-social browse (PublicDirectory only)
curl -H "Authorization: Bearer $TOKEN" "http://$API/groups/discover/nearby"

# Unsubscribe
curl -X DELETE -H "Authorization: Bearer $TOKEN" \
  "http://$API/groups/discover/subscribe/tag/42"
```

### Privacy contract — hard guarantees

- **`Hidden`** groups never reach any public topic. They live entirely
  in local state.
- **`ListedToContacts`** groups never touch public shards. On every
  authority seal, the signed card is pushed to each Trusted/Known
  contact via direct-message with the framing
  `X0X-LTC-CARD-V1\n<card-json>`. Receivers verify and cache into the
  local card cache, never into the public shard cache.
- **`PublicDirectory`** groups publish to tag + name + id shards. The
  shard listener defensively drops any received card whose
  discoverability is not `PublicDirectory` (would-be leak).

## Public-group messaging (Phase E)

Groups configured with `SignedPublic` confidentiality (the
`public_open` and `public_announce` presets) carry signed chat /
announcement messages on `x0x.groups.public.{group_id}`:

```bash
# Send a chat message to a public_open group (members-only write).
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  "http://$API/groups/<group_id>/send" \
  -d '{"body":"hello world","kind":"chat"}'

# Publish an announcement (AdminOnly write — owner/admin only).
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  "http://$API/groups/<group_id>/send" \
  -d '{"body":"v1 released","kind":"announcement"}'

# Read the cache. Public read_access: any API client.
curl -H "Authorization: Bearer $TOKEN" \
  "http://$API/groups/<group_id>/messages"
```

**Write-access rules (enforced at endpoint AND ingest):**

| `write_access`       | Who may publish                                      |
|----------------------|------------------------------------------------------|
| `MembersOnly`        | active members                                       |
| `ModeratedPublic`    | any non-banned author (moderators clean up later)    |
| `AdminOnly`          | active `Admin` or `Owner` only                       |

Banned authors are **always** rejected regardless of write-access mode.
Every message carries a ML-DSA-65 signature, the signer's public key
(so verification is standalone), a `state_hash_at_send` + `revision_at_send`
binding to the D.3 chain, and is capped at 64 KiB body.

`MlsEncrypted` groups do not use this path — use
`/groups/:id/secure/encrypt` (Phase D.2) for encrypted content.

## Setup once

Install x0x from the current upstream release or `SKILL.md` flow in the repo: [github.com/saorsa-labs/x0x](https://github.com/saorsa-labs/x0x). Then start the daemon with `x0x start` or `x0xd`.

```bash
# macOS
DATA_DIR="$HOME/Library/Application Support/x0x"

# Linux
# DATA_DIR="$HOME/.local/share/x0x"

API=$(cat "$DATA_DIR/api.port")
TOKEN=$(cat "$DATA_DIR/api-token")
```

## Named groups: invite links and shared context

Named groups are the higher-level surface. They are useful when you need:
- a stable shared group id
- invite links
- per-group display names
- shared group metadata, including `chat_topic` and `metadata_topic`

CLI:

```bash
# Create a named group
x0x group create "ops-team" \
  --description "Private ops coordination" \
  --display-name "Coordinator"

# List and inspect groups
x0x group list
x0x group info <group_id>

# Generate and share an invite link
x0x group invite <group_id>

# Join from another agent
x0x group join <invite_link> --display-name "Worker"

# Inspect or mutate the current local space roster
x0x group members <group_id>
x0x group add-member <group_id> <agent_id> --display-name "Worker"
x0x group remove-member <group_id> <agent_id>

# Change your display name or leave
x0x group set-name <group_id> "Worker-1"
x0x group leave <group_id>
```

REST:

```bash
# Create a named group
curl -X POST "http://$API/groups" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name":"ops-team",
    "description":"Private ops coordination",
    "display_name":"Coordinator"
  }'

# List groups
curl -H "Authorization: Bearer $TOKEN" \
  "http://$API/groups"

# Group info
curl -H "Authorization: Bearer $TOKEN" \
  "http://$API/groups/<group_id>"

# Invite
curl -X POST "http://$API/groups/<group_id>/invite" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"expiry_secs":604800}'

# Join
curl -X POST "http://$API/groups/join" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"invite":"<invite_link>","display_name":"Worker"}'
```

Important: x0xd does not currently expose a named-group `send` endpoint. If you want group messaging, use the returned `chat_topic` with the normal `/publish` and `/subscribe` APIs, or use direct messaging between members.

Important: creator-authored member add/remove and creator delete now propagate across subscribed peers, so removed members drop the space locally. That said, this is still not yet a complete distributed admin/ACL system on its own.

## MLS helpers: encrypt, decrypt, and manage key material

The lower-level MLS surface is where encryption helpers live.

CLI:

```bash
# Create and inspect an MLS group
x0x groups create
x0x groups list
x0x groups get <group_id>

# Encrypt and decrypt payloads
x0x groups encrypt <group_id> "shared secret"
x0x groups decrypt <group_id> <ciphertext> --epoch 0

# Create a welcome message for another agent
x0x groups welcome <group_id> <agent_id>
```

REST:

```bash
# Create an MLS group
curl -X POST "http://$API/mls/groups" \
  -H "Authorization: Bearer $TOKEN"

# Encrypt for the group
curl -X POST "http://$API/mls/groups/<group_id>/encrypt" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"payload":"c2hhcmVkIHNlY3JldA=="}'

# Decrypt
curl -X POST "http://$API/mls/groups/<group_id>/decrypt" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ciphertext":"<ciphertext>","epoch":0}'
```

Treat these MLS endpoints as app-building primitives. They are useful when your app wants to carry encrypted payloads over another x0x channel.

## Good fits today

- invite-based group formation
- shared group metadata and per-group display names
- app-defined messaging on top of a named group's `chat_topic`
- custom encrypted payload workflows built on top of MLS helpers

## Current limits

- Named groups are not yet a full secure group-chat surface.
- Named-group member views now converge across subscribed peers for creator-authored membership changes, but they should still not yet be treated as complete distributed access control.
- There is no built-in named-group send/receive API in x0xd.
- No backlog/history sync for new members.
- No admin-role model in the current named-group daemon surface.

## References

- [API reference](https://github.com/saorsa-labs/x0x/blob/main/docs/api-reference.md)
- [Source](https://github.com/saorsa-labs/x0x)
