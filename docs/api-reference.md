# x0x API Reference

Complete REST and WebSocket reference for the `x0xd` daemon and the matching `x0x` CLI.

- Default daemon base URL: `http://127.0.0.1:12700`
- Override from the CLI with: `x0x --api 127.0.0.1:12700 ...`
- Named instances use their own auto-discovered local API port: `x0x --name alice ...`

## Response shape

Most successful endpoints return a **flattened** JSON object with `ok: true` plus resource-specific fields.
There is **not** a single universal `data` wrapper.

Examples:

```json
{"ok":true,"status":"healthy","version":"<x.y.z>","peers":4,"uptime_secs":300}
```

```json
{"ok":true,"agent_id":"...","machine_id":"...","user_id":null}
```

Errors use:

```json
{"ok":false,"error":"description"}
```

## System

| Method | Endpoint | CLI | Purpose |
|---|---|---|---|
| GET | `/health` | `x0x health` | Health probe |
| GET | `/status` | `x0x status` | Runtime status, bound API address, connectivity, peers, warnings |
| POST | `/shutdown` | `x0x stop` | Gracefully stop the daemon |
| POST | `/auth/session` | `x0x auth session` | Exchange the durable API token for a short-lived browser session token (WS1.6) |

### Example: health

```bash
curl http://127.0.0.1:12700/health
# {"ok":true,"status":"healthy","version":"<x.y.z>","peers":4,"uptime_secs":300}
```

### Example: status

```bash
curl http://127.0.0.1:12700/status
# {
#   "ok": true,
#   "status": "connected",
#   "version": "<x.y.z>",
#   "uptime_secs": 300,
#   "api_address": "127.0.0.1:12700",
#   "external_addrs": ["203.0.113.5:5483"],
#   "agent_id": "8a3f...",
#   "peers": 4,
#   "warnings": []
# }
```

## Identity

| Method | Endpoint | CLI | Purpose |
|---|---|---|---|
| GET | `/agent` | `x0x agent` | Local agent identity |
| POST | `/announce` | `x0x announce` | Re-announce identity to the network |
| GET | `/agent/user-id` | `x0x agent user-id` | Current user ID if configured |
| GET | `/agent/card` | `x0x agent card` | Generate a shareable, signed identity card |
| GET | `/.well-known/agent-card.json` | — | A2A-compatible discovery card (ADR-0017) |
| POST | `/agent/card/import` | `x0x agent import` | Import a card into contacts (verifies signature) |
| POST | `/agent/sign` | `x0x agent sign` | Detached ML-DSA-65 signature over caller-supplied bytes |
| POST | `/agent/verify` | `x0x agent verify` | Verify a detached ML-DSA-65 signature against a caller-supplied public key |

### Announce request body

```json
{
  "include_user_identity": false,
  "human_consent": false
}
```

Notes:
- Set `include_user_identity: true` only when the daemon has a configured user key.
- Set `human_consent: true` when intentionally sharing human identity.

### Agent card query params

`GET /agent/card?display_name=Alice&include_groups=true`

### Agent card signing (ADR-0017)

Generated cards are signed with the agent's ML-DSA-65 key. The card carries two
extra fields:

- `agent_public_key` — hex ML-DSA-65 public key of the signer.
- `signature` — hex ML-DSA-65 signature over the canonical card bytes.

Verification binds the embedded public key to the card's `agent_id`
(`agent_id == SHA-256(agent_public_key)`) and then checks the signature, so a
relay cannot substitute a foreign key. `POST /agent/card/import` rejects a signed
card whose signature fails; legacy unsigned cards (`signature` absent) still
import for backward compatibility.

### A2A discovery card

`GET /.well-known/agent-card.json` returns an
[Agent2Agent (A2A)](https://a2a-protocol.org)-compatible Agent Card
(`application/json`) derived from the local agent's signed card. x0x-native data
is carried under `x0x`-prefixed extension members (`x0xAgentId`,
`x0xAgentPublicKey`, `x0xSignature`, `x0xCertificate`, …); KV stores and public
groups become A2A `skills`; the `exec` skill is advertised only when remote-exec
is enabled. This is the discovery half of A2A interop — see
`docs/design/a2a-agent-card-adapter.md`. The A2A-over-x0x message binding
(`docs/design/a2a-over-x0x-binding.md`) is a tracked follow-up.

### Sign request body

```json
{
  "context": "x0x-symphony-handoff-v1",
  "payload_b64": "<base64 bytes to sign>"
}
```

Notes:
- `context` is **required** (issue #133): a caller-chosen ASCII string
  matching `[a-z0-9._-]{1,64}` naming the application protocol the
  signature is bound to. The daemon signs the length-prefixed external DST
  `[0xF0] | b"x0x.external-agent-sign.v1" | len(context):u32 BE | context | payload`,
  provably disjoint from every internal x0x signing input (announcements,
  group commits, certificates, …). A denylist rejects `context` strings
  naming internal signing domains. There is no raw-payload signing path.
- `payload_b64` is decoded and signed verbatim under the DST (max 64 KiB —
  external signing is for hashes/manifests, not blobs). Callers canonicalize
  structured payloads themselves.
- Response: `ok`, `agent_id` (hex), `public_key_b64`, `signature_b64`,
  `context` (echoed), and `algorithm` (`x0x.agent-sign.v2.ml-dsa-65`).
- `400` for an invalid/denied `context`; `413` over the 64 KiB cap.

### Verify request body

```json
{
  "context": "x0x-symphony-handoff-v1",
  "payload_b64": "<base64 payload bytes>",
  "signature_b64": "<base64 detached ML-DSA-65 signature>",
  "public_key_b64": "<base64 ML-DSA-65 public key>",
  "algorithm": "x0x.agent-sign.v2.ml-dsa-65"
}
```

Notes:
- Stateless: verification uses only the caller-supplied public material —
  no key access, no identity state. The counterpart to `/agent/sign` for
  applications reading signed records back from disk or distributed
  storage. `context` is **required** and must match the value used at
  signing time — verification reconstructs the same external DST.
- A failed signature check is a **result, not an error**: the response is
  `200` with `{ "ok": true, "valid": false, "algorithm": "x0x.agent-sign.v2.ml-dsa-65" }`.
- `400` is reserved for malformed input: bad base64 in any field, empty
  payload, a public key that is not exactly 1952 bytes, a signature that
  is not exactly 3309 bytes, an invalid/denied `context`, or an unknown
  `algorithm`. `413` for payloads over the 64 KiB cap. Limits mirror
  `/agent/sign` exactly.
- `algorithm` is optional; when the field is present — including as JSON
  null — it must be the exact scheme string
  `x0x.agent-sign.v2.ml-dsa-65`, so any future scheme migration is
  explicit rather than silent.
- Response: `ok`, `valid` (boolean), `algorithm`.

## Network

| Method | Endpoint | CLI | Purpose |
|---|---|---|---|
| GET | `/peers` | `x0x peers` | Connected gossip peers |
| GET | `/presence` | `x0x presence` | Presence view of online agents |
| GET | `/presence/online` | `x0x presence online` | Online agents (network-view trust filter) |
| GET | `/presence/foaf` | `x0x presence foaf` | Friends-of-friends discovery walk (`?ttl=<hops>`, default 3; social-view trust filter) |
| GET | `/presence/status/:id` · `/presence/find/:id` | `x0x presence status/find` | One agent's presence status / lookup |
| GET | `/network/status` | `x0x network status` | NAT and connectivity diagnostics |
| GET | `/network/bootstrap-cache` | `x0x network cache` | Bootstrap cache stats |

## Gossip messaging

| Method | Endpoint | CLI | Purpose |
|---|---|---|---|
| POST | `/publish` | `x0x publish <topic> <payload>` | Publish a base64 payload to a topic |
| POST | `/subscribe` | `x0x subscribe <topic>` | Create a topic subscription |
| DELETE | `/subscribe/:id` | `x0x unsubscribe <id>` | Remove a subscription |
| GET | `/events` | `x0x events` | SSE stream of subscribed messages |

### Publish request body

```json
{
  "topic": "updates",
  "payload": "aGVsbG8="
}
```

### `local:` topics (same-daemon IPC)

Topics whose name starts with `local:` (e.g. `local:my-app/events`) are
never gossipped: messages are delivered only to subscribers attached to
the same `x0xd` instance — they never enter the PlumTree EAGER set or
IHAVE digests. All primitives work unchanged (`/publish`, `/subscribe`,
`/events`, WebSocket subscribe, bearer-token auth). Use them as a local
pub/sub substrate for multi-process applications sharing one daemon,
without leaking events to the mesh.

## Discovery

| Method | Endpoint | CLI | Purpose |
|---|---|---|---|
| GET | `/agents/discovered` | `x0x agents list` | List discovered agents |
| GET | `/agents/discovered/:agent_id` | `x0x agents get <agent_id>` | Get one discovered agent |
| GET | `/agents/:agent_id/machine` | `x0x agents machine <agent_id>` | Resolve an agent to its current machine endpoint |
| GET | `/machines/discovered` | `x0x machines discovered` | List discovered machine endpoints |
| GET | `/machines/discovered/:machine_id` | `x0x machines get <machine_id>` | Get one discovered machine endpoint |
| POST | `/agents/find/:agent_id` | `x0x agents find <agent_id>` | Actively look up an agent |
| GET | `/agents/reachability/:agent_id` | `x0x agents reachability <agent_id>` | Reachability heuristics |
| GET | `/users/:user_id/agents` | `x0x agents by-user <user_id>` | List agents linked to a user |
| GET | `/users/:user_id/machines` | `x0x machines by-user <user_id>` | List machine endpoints linked to a user |

Query params:
- `/agents/discovered?unfiltered=true`
- `/agents/discovered/:agent_id?wait=<seconds>`
- `/machines/discovered?unfiltered=true`
- `/machines/discovered/:machine_id?wait=<seconds>`

## Contacts, machines, and trust

### Contacts

| Method | Endpoint | CLI | Purpose |
|---|---|---|---|
| GET | `/contacts` | `x0x contacts list` | List contacts |
| POST | `/contacts` | `x0x contacts add ...` | Add a contact |
| POST | `/contacts/trust` | `x0x trust set ...` | Quick trust update |
| PATCH | `/contacts/:agent_id` | `x0x contacts update ...` | Update trust or identity type |
| DELETE | `/contacts/:agent_id` | `x0x contacts remove <agent_id>` | Remove a contact |
| POST | `/contacts/:agent_id/revoke` | `x0x contacts revoke ...` | Revoke a contact |
| GET | `/contacts/:agent_id/revocations` | `x0x contacts revocations <agent_id>` | List revocations |

### Machines

| Method | Endpoint | CLI | Purpose |
|---|---|---|---|
| GET | `/contacts/:agent_id/machines` | `x0x machines list <agent_id>` | List machine records |
| POST | `/contacts/:agent_id/machines` | `x0x machines add <agent_id> <machine_id> [--pin]` | Add a machine record |
| DELETE | `/contacts/:agent_id/machines/:machine_id` | `x0x machines remove <agent_id> <machine_id>` | Remove a machine record |
| POST | `/contacts/:agent_id/machines/:machine_id/pin` | `x0x machines pin <agent_id> <machine_id>` | Pin a machine |
| DELETE | `/contacts/:agent_id/machines/:machine_id/pin` | `x0x machines unpin <agent_id> <machine_id>` | Unpin a machine |

### Trust evaluation

| Method | Endpoint | CLI | Purpose |
|---|---|---|---|
| POST | `/trust/evaluate` | `x0x trust evaluate <agent_id> <machine_id>` | Evaluate trust decision for a pair |

### Example: add machine

```bash
curl -X POST http://127.0.0.1:12700/contacts/<agent_id>/machines \
  -H "Content-Type: application/json" \
  -d '{"machine_id":"<hex>","pinned":true}'
```

Trust levels: `blocked`, `unknown`, `known`, `trusted`

Identity types: `anonymous`, `known`, `trusted`, `pinned`

## Direct messaging

| Method | Endpoint | CLI | Purpose |
|---|---|---|---|
| POST | `/agents/connect` | `x0x direct connect <agent_id>` | Establish a direct connection |
| POST | `/machines/connect` | `x0x machines connect <machine_id>` | Establish a machine-id transport connection |
| POST | `/direct/send` | `x0x direct send <agent_id> <message>` | Send a direct base64 payload |
| GET | `/direct/connections` | `x0x direct connections` | List active direct connections |
| GET | `/direct/events` | `x0x direct events` | SSE stream of direct messages |

### Direct send request body

```json
{
  "agent_id": "8a3f...",
  "payload": "aGVsbG8="
}
```

## MLS encrypted groups

Operational invariant (maintainer follow-up): legacy/raw `/mls/groups` helpers
must not expose usable key material or reactivate a withdrawn named group. A
named-group tombstone/terminality marker remains authoritative for group
terminality; this is a documented maintainer invariant, not a new low-level MLS
helper API.

| Method | Endpoint | CLI | Purpose |
|---|---|---|---|
| POST | `/mls/groups` | `x0x groups create` | Create an encrypted group |
| GET | `/mls/groups` | `x0x groups list` | List groups |
| GET | `/mls/groups/:id` | `x0x groups get <group_id>` | Group details |
| POST | `/mls/groups/:id/members` | `x0x groups add-member ...` | Add a member |
| DELETE | `/mls/groups/:id/members/:agent_id` | `x0x groups remove-member ...` | Remove a member |
| POST | `/mls/groups/:id/encrypt` | `x0x groups encrypt <group_id> <payload>` | Encrypt plaintext for the group |
| POST | `/mls/groups/:id/decrypt` | `x0x groups decrypt ... --epoch <n>` | Decrypt ciphertext |
| POST | `/mls/groups/:id/welcome` | `x0x groups welcome <group_id> <agent_id>` | Create a welcome message |

### Encrypt request body

```json
{
  "payload": "c2VjcmV0"
}
```

### Decrypt request body

```json
{
  "ciphertext": "...base64...",
  "epoch": 1
}
```

## Named groups

| Method | Endpoint | CLI | Purpose |
|---|---|---|---|
| POST | `/groups` | `x0x group create <name>` | Create a named group |
| GET | `/groups` | `x0x group list` | List named groups |
| GET | `/groups/:id` | `x0x group info <group_id>` | Get group info |
| GET | `/groups/:id/members` | `x0x group members <group_id>` | List named-group members |
| POST | `/groups/:id/members` | `x0x group add-member <group_id> <agent_id>` | Admin-authored member add (propagates to subscribed peers) |
| DELETE | `/groups/:id/members/:agent_id` | `x0x group remove-member <group_id> <agent_id>` | Admin-authored member removal (propagates to subscribed peers) |
| POST | `/groups/:id/invite` | `x0x group invite <group_id>` | Generate an invite link |
| POST | `/groups/join` | `x0x group join <invite>` | Join via invite |
| PUT | `/groups/:id/display-name` | `x0x group set-name <group_id> <name>` | Set your display name |
| PATCH | `/groups/:id` | `x0x group update <group_id>` | Update name/description (admin-authored) |
| PATCH | `/groups/:id/policy` | `x0x group policy <group_id>` | Update group policy (admin-authored) |
| PATCH | `/groups/:id/members/:agent_id/role` | `x0x group set-role <group_id> <agent_id> <role>` | Assign `admin` or `member` (admin-authored) |
| POST | `/groups/:id/ban/:agent_id` | `x0x group ban <group_id> <agent_id>` | Ban a member (admin-authored) |
| DELETE | `/groups/:id/ban/:agent_id` | `x0x group unban <group_id> <agent_id>` | Unban a member (admin-authored) |
| GET | `/groups/:id/requests` | `x0x group requests <group_id>` | List join requests (admin-only) |
| POST | `/groups/:id/requests` | `x0x group request-access <group_id>` | Submit a join request |
| POST | `/groups/:id/requests/:request_id/approve` | `x0x group approve-request <group_id> <request_id>` | Approve a join request (admin-authored) |
| POST | `/groups/:id/requests/:request_id/reject` | `x0x group reject-request <group_id> <request_id>` | Reject a join request (admin-authored) |
| DELETE | `/groups/:id/requests/:request_id` | `x0x group cancel-request <group_id> <request_id>` | Cancel your own pending request |
| GET | `/groups/:id/state` | `x0x group state <group_id>` | **Phase D.3**: inspect the signed state-commit chain |
| GET | `/groups/:id/state/commits` | `x0x group state-commits <group_id>` | **issue #111**: read retained state-commit history (members only, paged) |
| POST | `/groups/:id/state/seal` | `x0x group state-seal <group_id>` | **Phase D.3**: advance the chain + republish signed card |
| POST | `/groups/:id/state/withdraw` | `x0x group delete <group_id>` | **Phase D.3**: any admin permanently deletes the group with a signed terminal withdrawal |
| POST | `/groups/:id/send` | `x0x group send` | **Phase E**: publish a signed message to a SignedPublic group |
| GET | `/groups/:id/messages` | `x0x group messages` | **Phase E**: retrieve cached public messages (non-members on Public read) |
| GET | `/groups/discover/nearby` | `x0x group discover-nearby` | **Phase C.2**: presence-social browse of PublicDirectory groups |
| GET | `/groups/discover/subscriptions` | `x0x group discover-subscriptions` | **Phase C.2**: list active shard subscriptions |
| POST | `/groups/discover/subscribe` | `x0x group discover-subscribe` | **Phase C.2**: subscribe to a tag/name/id shard |
| DELETE | `/groups/discover/subscribe/:kind/:shard` | `x0x group discover-unsubscribe` | **Phase C.2**: unsubscribe from a shard |
| DELETE | `/groups/:id` | `x0x group leave <group_id>` | Leave the group by self-removing, for any rank. The last admin is blocked; promote another admin first or use `x0x group delete` |

### Roles

Admin is root for the group. A hostile or compromised Admin can admit members,
remove members, rekey secure material, change policy, assign roles, and delete
the group for everyone. Keep the admin set small, and do not map softer
application roles onto x0x Admin.

`x0x group set-role` accepts only:

- `admin` — full group control, including membership, policy, rekey, role
  assignment, and deleting the group.
- `member` — ordinary participant.

Stored legacy `owner` entries still render/read as admin-equivalent for old
groups, but `owner` is not assignable. `moderator` and `guest` remain reserved
and non-assignable.

### Leaving vs deleting a group

`x0x group leave` (`DELETE /groups/:id`) is self-removal: **I'm out; the
group lives on**. Any rank may leave, but the last admin receives `409` and must
promote another admin first (or delete instead). Local secure material is wiped
on leave.

`x0x group delete` (`POST /groups/:id/state/withdraw`) is admin-only and
irreversible: **group over for everyone, permanently**. It seals the unchanged
signed terminal `GroupDeleted` commit over metadata/direct delivery; the
withdrawn public card supersedes discovery. After delete, each recipient keeps
only a withdrawn keyless tombstone/terminality marker: MLS/TreeKEM/GSS key
material is wiped, the terminal record remains to block stale-card reanimation,
and all authoring is rejected. Delivery is best-effort to online/reachable peers;
offline peers are not guaranteed to receive the delete event.

### Phase C.2 — distributed shard discovery

x0x indexes `PublicDirectory` groups across **tag / name / exact-id
shards** over PlumTree gossip. No DHT, no special node roles.

Topic format: `x0x.directory.{tag|name|id}.{shard}` where
`shard = BLAKE3(domain || lowercase(key)) % 65536`.

- A group's tags fan out to tag shards (one per tag).
- The group name fans out to name shards (one per whitespace-delimited word).
- The `group_id` fans out to exactly one id shard.

Peers subscribe to shards of interest via
`POST /groups/discover/subscribe {"kind":"tag","key":"ai"}`. Subscriptions
persist to `~/.x0x/directory-subscriptions.json` and are restored on
restart with random jitter (0–30s) to avoid anti-entropy storms.

Messages on shard topics are `DirectoryMessage::{Card, Digest, Pull}`:
- `Card` — signed `GroupCard` (data plane). Receivers verify the
  authority signature before caching; unsigned or bad-sig cards are
  dropped. A defensive check drops any non-PublicDirectory card that
  leaks onto a public shard.
- `Digest` — periodic AE summary of known entries
  `(group_id, revision, state_hash, expires_at)`.
- `Pull` — peer asks the authority to re-broadcast specific group_ids
  it's missing or has at a stale revision.

**Privacy contract (hard guarantees):**
- `Hidden` — never published to any topic.
- `ListedToContacts` — never published to public shards; delivered
  pairwise to Trusted/Known contacts via direct-message framing
  (`X0X-LTC-CARD-V1\n<card-json>`).
- `PublicDirectory` — published to tag + name + id shards.

### Phase E — public-group messaging

For groups whose `confidentiality == SignedPublic` (the `public_open`
and `public_announce` presets), messages are signed ML-DSA-65 artefacts
on `x0x.groups.public.{group_id}`:

```rust
GroupPublicMessage {
    group_id, state_hash_at_send, revision_at_send,
    author_agent_id, author_public_key, author_user_id,
    kind: Chat | Announcement,
    body, timestamp, signature,
}
```

Write-access is enforced at both endpoint and ingest:

- `MembersOnly` — only active members may send.
- `ModeratedPublic` — any non-banned author may send (moderators
  remove inappropriate content later).
- `AdminOnly` — only active admins may send; legacy `Owner` entries count as
  Admin-equivalent.

Banned authors are rejected in **every** write-access mode. `POST
/groups/:id/send` also rejects `MlsEncrypted` groups (route to
`/secure/encrypt` instead). `GET /groups/:id/messages` returns the
cached history:

- `read_access == Public` — open to any caller with a valid API token.
- `read_access == MembersOnly` — requires active membership.
- `MlsEncrypted` — returns 400 (encrypted history belongs elsewhere).
- Withdrawn groups return 409 and do not restart public-message listeners.

### Phase D.3 — state-commit chain

Each named group maintains a signed commit chain:

- `GET /groups/:id/state` returns `{ group_id (stable), genesis,
  state_revision, state_hash, prev_state_hash, security_binding,
  withdrawn, roster_root, policy_hash, public_meta_hash }`.
- `POST /groups/:id/state/seal` (any admin) advances the chain by one
  revision and republishes the authority-signed public `GroupCard` to
  the global discovery topic. Returns the signed `GroupStateCommit`.
- `POST /groups/:id/state/withdraw` (`x0x group delete`, any admin)
  permanently ends the group by sealing a terminal higher-revision commit with
  `withdrawn=true`. Members are notified with the unchanged signed
  `GroupDeleted` metadata event over the group metadata topic plus direct
  delivery; recipients verify the terminal commit, retain the withdrawn
  tombstone/terminality marker, and wipe local MLS/TreeKEM/GSS key material. The
  terminal commit remains signed/verifiable in that retained record.
  A withdrawn card is also refreshed to supersede public discovery listings on
  receipt regardless of TTL; Hidden groups rely on the metadata/direct delete
  event, not public-card discovery.
  Explicit `POST /groups/cards/import` keeps passive discovery/listed/shard
  delete/withdrawal handling cache-only for live/keyed local groups: a withdrawn card
  alone cannot terminally mark or wipe a group that has local GSS/MLS/TreeKEM key
  material, even if the card's `authority_agent_id` names an active Admin. Live
  keyed terminality requires the signed terminal `GroupStateCommit` delivered via
  metadata/direct delete. Withdrawn cards can still supersede discovery
  stubs/listings that have no local key material to protect.

#### Retained commit history (issue #111)

`GET /groups/:id/state` exposes only the chain **head**. To answer
"what did the signed roster say at revision N" long after the fact (for
verification and group-governance integrators per ADR-0016), each daemon
retains every commit it applies — from both local authorship and peer
commits — paired with the roster projection it effected:

- `GET /groups/:id/state/commits?from_revision=0&limit=100` —
  **members only while live** (retained roster projections are member content,
  so this does *not* use `/state`'s public-projection gate). Withdrawn local
  tombstones remain readable so terminal delete preserves keyless audit history.
  Returns `{ ok, group_id, state_revision, withdrawn, total_retained,
  first_available_revision, latest_retained_revision, from_revision,
  limit, count, has_more, next_from_revision, commits }`, where each
  `commits[]` entry is `{ commit, roster, roster_root_verified }`.
  `roster` is the `{ agent_id: { role, state } }` projection of `Active` +
  `Banned` members; `roster_root_verified` recomputes the root over that
  projection and compares it to the commit's signed `roster_root`, so any
  at-rest corruption surfaces rather than serving silently-wrong history.
  `limit` is capped at 500.

Scope and honest limits: retention is **not retroactive** — history begins
at the first release that retains it, and each daemon holds only the suffix
it witnessed (a member who joined at revision 50 has no earlier entries;
`first_available_revision` lets callers distinguish a real gap from an empty
result). Each retained entry is independently verifiable against its
commit's `roster_root` with no dependence on the prior chain. Storage is
bounded per group (`COMMIT_LOG_CAP`, oldest dropped past the cap with a
logged warning — never silent); checkpoint-and-truncate and cross-peer
backfill are deferred.

Cards and commits carry ML-DSA-65 signatures. Peers verify both the
signature and the chain link (`prev_state_hash`) before accepting; stale
revisions are silently dropped.

**Secure-group plane (ADR-0012, x0x 0.21.0):** private groups (`private_secure`
preset — `Hidden` + `MlsEncrypted`) run **real TreeKEM** (forward secrecy +
post-compromise security). **Single-member** private groups work end-to-end
(invite → join → bidirectional secure → ban → forward secrecy). **Multi-member
limitation:** a 2nd+ member converges into the authority roster but its
`MemberAdded`+`Welcome` is not yet delivered, so it cannot yet encrypt — tracked
follow-up. Public encrypted presets (`public_request_secure`) and grandfathered
groups remain on the legacy **GSS** plane. See `docs/primers/groups.md`.

## Collaborative task lists

| Method | Endpoint | CLI | Purpose |
|---|---|---|---|
| GET | `/task-lists` | `x0x tasks list` | List task lists |
| POST | `/task-lists` | `x0x tasks create <name> <topic>` | Create a task list |
| GET | `/task-lists/:id/tasks` | `x0x tasks show <list_id>` | List tasks |
| POST | `/task-lists/:id/tasks` | `x0x tasks add ...` | Add a task |
| PATCH | `/task-lists/:id/tasks/:tid` | `x0x tasks claim/complete ...` | Update task state |

Update task request body:

```json
{"action":"claim"}
```

or

```json
{"action":"complete"}
```

## Key-value stores

| Method | Endpoint | CLI | Purpose |
|---|---|---|---|
| GET | `/stores` | `x0x store list` | List stores |
| POST | `/stores` | `x0x store create <name> <topic>` | Create a store |
| POST | `/stores/:id/join` | `x0x store join <topic>` | Join an existing store |
| GET | `/stores/:id/keys` | `x0x store keys <store_id>` | List keys |
| PUT | `/stores/:id/:key` | `x0x store put <store_id> <key> <value>` | Put a base64 value |
| GET | `/stores/:id/:key` | `x0x store get <store_id> <key>` | Get a value |
| DELETE | `/stores/:id/:key` | `x0x store rm <store_id> <key>` | Remove a value |

### Store put request body

```json
{
  "value": "aGVsbG8=",
  "content_type": "text/plain"
}
```

## File transfers

| Method | Endpoint | CLI | Purpose |
|---|---|---|---|
| POST | `/files/send` | `x0x send-file <agent_id> <path>` | Create an outgoing transfer |
| GET | `/files/transfers` | `x0x transfers` | List transfers |
| GET | `/files/transfers/:id` | `x0x transfer-status <transfer_id>` | Inspect one transfer |
| POST | `/files/accept/:id` | `x0x accept-file <transfer_id>` | Accept a pending transfer |
| POST | `/files/reject/:id` | `x0x reject-file <transfer_id> [--reason ...]` | Reject a pending transfer |

### Send-file request body

```json
{
  "agent_id": "8a3f...",
  "filename": "notes.txt",
  "size": 1234,
  "sha256": "...hex..."
}
```

### Reject-file request body

```json
{"reason":"rejected by user"}
```

## Remote exec

Run a command on **another** agent's machine. Disabled by default; every request is authorized on the **responder** (target) daemon, not the caller. The target runs `argv` only if remote exec is enabled there, the sender is a verified `Accept`-trust contact, and the `(agent_id, machine_id)` pair + exact argv are allow-listed in its exec ACL (`docs/exec.md`). `argv` is never shell-interpreted. A denied request still returns `200` with a non-null `denial_reason` (e.g. `exec_disabled`, `unverified_sender`, `trust_rejected`, `agent_machine_not_in_acl`, `argv_not_allowed`, `cwd_not_allowed`, `shell_metachar_in_argv`) — the refusal is carried in the body, not the HTTP status.

| Method | Endpoint | CLI | Purpose |
|---|---|---|---|
| POST | `/exec/run` | `x0x exec <agent_id> -- <argv...>` | Run a command on a peer |
| POST | `/exec/cancel` | `x0x exec cancel <request_id>` | Cancel an in-flight request |
| GET | `/exec/sessions` | `x0x exec sessions` | List pending client + active server sessions |

### Run request body

```json
{
  "agent_id": "8a3f...",
  "argv": ["echo", "hi"],
  "stdin_b64": "aGVsbG8=",
  "timeout_ms": 30000
}
```

`argv` must be non-empty; `stdin_b64` and `timeout_ms` are optional. Any `cwd` is rejected by the v1 ACL. The response carries `code`, `signal`, `duration_ms`, `stdout_b64`, `stderr_b64`, `truncated`, and `denial_reason` (null on success).

### Cancel request body

```json
{"request_id":"<32-hex>","agent_id":"8a3f..."}
```

`agent_id` is optional; when omitted the local pending-session table resolves the target.

## Upgrade

| Method | Endpoint | CLI | Purpose |
|---|---|---|---|
| GET | `/upgrade` | `x0x upgrade` | Check for updates |

## WebSocket and GUI

### WebSocket endpoints

| Method | Endpoint | CLI | Purpose |
|---|---|---|---|
| GET | `/ws` | — | General-purpose WebSocket session |
| GET | `/ws/direct` | — | WebSocket session that auto-receives direct messages |
| GET | `/ws/sessions` | `x0x ws sessions` | Inspect active WebSocket sessions |

### WebSocket protocol

Client → server:

```json
{"type":"ping"}
{"type":"subscribe","topics":["topic-a","topic-b"]}
{"type":"unsubscribe","topics":["topic-a"]}
{"type":"publish","topic":"topic-a","payload":"aGVsbG8="}
{"type":"send_direct","agent_id":"hex64...","payload":"aGVsbG8="}
```

Server → client:

```json
{"type":"connected","session_id":"uuid","agent_id":"hex64..."}
{"type":"message","topic":"topic-a","payload":"aGVsbG8=","origin":"hex64..."}
{"type":"direct_message","sender":"hex64...","machine_id":"hex64...","payload":"aGVsbG8=","received_at":1234567890}
{"type":"subscribed","topics":["topic-a","topic-b"]}
{"type":"unsubscribed","topics":["topic-a"]}
{"type":"pong"}
{"type":"error","message":"..."}
```

### GUI

| Method | Endpoint | CLI | Purpose |
|---|---|---|---|
| GET | `/gui` | `x0x gui` | Open the embedded browser UI |
| GET | `/gui/` | — | Alias for `/gui` |

## Error handling

Common status codes:

| Code | Meaning |
|---|---|
| 200 | Success |
| 201 | Created |
| 400 | Bad request |
| 403 | Forbidden |
| 404 | Not found |
| 422 | Invalid JSON body / schema mismatch |
| 500 | Internal error |
| 503 | Service temporarily unavailable |

## CLI quick examples

```bash
x0x health
x0x status
x0x agent
x0x contacts list
x0x publish updates hello
x0x direct connect <agent_id>
x0x direct send <agent_id> hello
x0x groups create
x0x group create team-chat --display-name alice
x0x tasks create inbox team.tasks
x0x store create notes team.notes
x0x send-file <agent_id> ./notes.txt
x0x transfer-status <transfer_id>
x0x accept-file <transfer_id>
x0x reject-file <transfer_id> --reason "not now"
x0x ws sessions
x0x gui
```

## Diagnostics

All diagnostics endpoints require the normal local daemon bearer token and return counters/snapshots that never expose sensitive content (no ACL allow-entries, no agent secrets).

| Method | Endpoint | CLI | Purpose |
|---|---|---|---|
| GET | `/diagnostics/connectivity` | `x0x diagnostics connectivity` | ant-quic NodeStatus snapshot (UPnP, NAT, relay, mDNS) |
| GET | `/diagnostics/ack` | `x0x diagnostics ack` | ACK-v2 per-stage latency buckets and outcome counters |
| GET | `/diagnostics/gossip` | `x0x diagnostics gossip` | PubSub drop-detection counters (publish/deliver deltas) |
| GET | `/diagnostics/dm` | `x0x diagnostics dm` | Direct-message send/receive counters and per-peer health |
| GET | `/diagnostics/groups` | `x0x diagnostics groups` | Per-group ingest counters, listener state, and drop buckets |
| GET | `/diagnostics/exec` | `x0x diagnostics exec` | Remote exec counters, warnings, active sessions, and ACL summary |
| GET | `/diagnostics/connect` | `x0x diagnostics connect` | Connect-ACL policy summary and stream allow/deny counters |
| GET | `/diagnostics/ws` | `x0x diagnostics ws` | WebSocket outbound-queue health: capacity and drop/slow-consumer-close counters |

### `GET /diagnostics/connect`

Connect-ACL policy summary and allow/deny counters. Counters read `0` until the T4 forwarder (issue #132) is wired.

```json
{
  "streams_allowed": 0,
  "streams_denied": 0,
  "denial_breakdown": {},
  "acl_summary": {
    "enabled": false,
    "loaded_from": "/usr/local/etc/x0x/connect-acl.toml",
    "loaded_at_unix_ms": 0,
    "allow_entry_count": 0,
    "target_entry_count": 0,
    "disabled_reason": "acl_missing"
  }
}
```

See `docs/connect-acl.md` for full documentation including the `denial_breakdown` key reference.


## Tailnet port-forwarding (#132)

Local `ssh -L`-style port forwarding over x0x byte-streams. The forwarder runs only when a connect ACL is loaded (see `docs/connect-acl.md`); a peer's inbound forward is gated by the connect ACL + the key lifecycle before any local `TcpStream::connect`. Phase 1 targets are loopback-only numeric IPs.

| Method | Endpoint | CLI | Purpose |
|---|---|---|---|
| POST | `/forwards` | `x0x forward add` | Register a local loopback listener that tunnels to a peer's loopback service |
| GET | `/forwards` | `x0x forward list` | List registered forwards |
| DELETE | `/forwards/:local_addr` | `x0x forward rm <local_addr>` | Tear down a forward by its local bind address |
| GET | `/streams` | `x0x streams` | Active forward-stream count + connect-failed counter + connect-ACL snapshot |

### `POST /forwards` request body

```json
{
  "local_addr": "127.0.0.1:8022",
  "peer_agent": "<peer agent id hex>",
  "target_host": "127.0.0.1",
  "target_port": 22
}
```

`local_addr` must be loopback; `target_host` must be a numeric loopback IP (no DNS). Returns `409` when connect is disabled (no ACL loaded). The peer denies (and the local TCP closes) if its connect ACL does not allow the `(agent, machine, target)` triple.

See also: [docs/api.md](api.md), [troubleshooting.md](troubleshooting.md), [patterns.md](patterns.md)
