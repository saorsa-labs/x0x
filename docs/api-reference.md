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
{"ok":true,"status":"healthy","version":"<x.y.z>","peers":4,"send_ready_peers":4,"uptime_secs":300}
```

`status` is `"healthy"`, or `"degraded"` when the daemon has had zero peers
for its whole uptime past a 120 s bootstrap grace (issue #262 — the wedged
transport signal; `ok` stays `true` because the process itself is alive). A
degraded response carries a `degraded_reason` string. Fleet deployments under
a supervisor can additionally set `zero_peer_restart_secs = <secs>` in the
daemon TOML to make the process exit (for `Restart=always` self-heal) after
that long at zero peers — off by default.

```json
{"ok":true,"agent_id":"...","machine_id":"...","user_id":null}
```

Errors use:

```json
{"ok":false,"error":"description"}
```

## Authentication and token classes

Every endpoint except `GET /health` and `GET /constitution*` requires an
`Authorization: Bearer <token>` header. Three token classes exist:

| Class | Lifetime | Source | Can act as |
|---|---|---|---|
| **Durable API token** | until rotated | `<data_dir>/api-token` | the local owner (full control) |
| **Session token** | 10 minutes | `POST /auth/session` (exchanged from the durable token) | browser/GUI surfaces |
| **Rider token** | ≤ 90 days (default 7) | `POST /owner/riders` | a scoped sub-agent principal |

Auth-class labels used throughout this reference:

- **public** — no token (`/health`, `/constitution*` only).
- **bearer** — the durable API token or a session token in the
  `Authorization` header (the default for ordinary surfaces).
- **durable-owner** — requires the durable API token; a session token or
  rider token answers a typed `403`. Enforced at the ROUTE layer
  (`requires_durable_owner` in `src/server/auth.rs`, before any body
  extraction) plus handler-side defense-in-depth. Applies to the whole
  owner registry and ledger: `POST /owner/agents/issue`,
  `DELETE /owner/agents/:id`, `POST /owner/riders`, `GET /owner/riders`,
  `DELETE /owner/riders/:id`, `/owner/placement`,
  `/owner/agents/:id/placement`, the `/agent/move*` ceremony, the
  ADR-0043 binding form of `/identity/revoke`, and (since #446) the
  owner-act surfaces `POST /agent/sign` (detached signatures outlive
  any session token), `POST /exec/run`, `POST /exec/cancel`,
  `POST /shutdown`, `POST /upgrade/apply` (binary swap + restart =
  lifecycle act), `POST /sync/devices/enroll`,
  `POST /groups/:id/delegate` (signed capability with caller-chosen
  expiry), `POST /home/rename`, and `PATCH /groups/:id` /
  `PATCH /groups/:id/policy` **when the target carries Home metadata**
  (metadata presence is the marker — never the current policy axes, so
  the Home cannot be policy-flipped around the rename gate).
  Payload-conditional durable gates (body or prefix inspected, enforced
  in the handler): `POST /announce` **with
  `include_user_identity: true`**, and `POST /direct/send` / WS
  `send_direct` carrying a reserved `x0x-exec-v1\0` exec frame.
- **rider-allowed** — the three surfaces a rider token may reach (see the
  harness-boundary section below). Rider tokens authenticate in the
  `Authorization` header only.

**#446 resolution notes:** `POST /announce` without
`include_user_identity` and `PATCH /groups/:id` on ordinary
 (non-Home) groups stay bearer — no credential or capability is
involved. `DELETE /groups/:id` requires **active membership** for any
group (self-leave is its purpose; a non-member cannot delete the local
view of a foreign group). The GUI prompts for the durable token (kept
in tab-scoped `sessionStorage`, never a URL) the first time an
owner-act surface is used from a session.

`GET /gui`, `/ws`, `/ws/direct`, and the SSE streams additionally accept a
**session token** as a `?token=` query parameter (browser constraint). The
durable API token and rider tokens are **never** valid in a query string
(#127/WS1.6 — no long-lived secret in URLs), and query tokens are rejected
everywhere else.

## Changed in v0.41 (pre-release)

The Home Suite campaign (ADRs 0036–0043, plus the 0044–0058 backfills) added:

- **Owner identity & naming (ADR-0036):** opt-in `user.key`; `GET/PUT /profile`;
  `GET /owner/agents` roster; V3 announces carry a signed self-name
  (`display_name`); `GET /agent/card?display_name=` is deprecated in favour of
  the profile.
- **Home (ADR-0038):** `GET /home`, `POST /home/rename`; an auto-provisioned
  `Hidden + OwnerCertified + MlsEncrypted` space per owned install;
  `GroupAdmission::OwnerCertified` admission is checked at invite-accept and at
  every state seal.
- **Sub-agent harness boundary (ADR-0039):** `POST /owner/agents/issue`
  (ACP/rider modes), `DELETE /owner/agents/:id`, and the rider-token lifecycle
  (`POST/GET /owner/riders`, `DELETE /owner/riders/:id`).
- **Delegation & mentions (ADR-0040):** `POST /groups/:id/delegate`,
  `GET /groups/:id/delegations`; `mentions` and `delegation_digest` fields on
  `POST /groups/:id/send` and on the signed `GroupPublicMessage` wire object;
  the WS `mention` event.
- **Device sync (ADR-0041):** `GET /sync/devices`, `POST /sync/devices/enroll`,
  `DELETE /sync/devices/:machine_id`; owner-to-owner SyncV1 streams.
- **Placement & key-move (ADR-0043):** `GET /owner/placement`,
`GET /owner/agents/:id/placement`, the `/agent/move*` ceremony endpoints
  (**501 while `[key_move] ceremony_enabled = false`** — the default), and the
  both-ids binding form of `POST /identity/revoke`.
- **DM capabilities (issue #437):** `DmCapabilities.digest_support` advertises
  relay-header digest verification; mixed-fleet behaviour is described with the
  DM surfaces.
- **New diagnostics:** `GET /diagnostics/relay`, `GET /diagnostics/history`,
  `GET /diagnostics/ws`.

Open issues for this release are listed in the README's *Known limitations*
table (#446–#451). This reference documents **174 endpoints — exactly the set
`x0x routes` prints** (two further served paths sit outside the registry:
`/.well-known/agent-card.json` and the `/gui/` alias).

## System

| Method | Endpoint | CLI | Purpose |
|---|---|---|---|
| GET | `/health` | `x0x health` | Health probe |
| GET | `/status` | `x0x status` | Runtime status, bound API address, connectivity, peers, warnings |
| POST | `/shutdown` | `x0x stop` | Gracefully stop the daemon |
| POST | `/auth/session` | `x0x auth session` | Exchange the durable API token for a short-lived browser session token (WS1.6) |
| GET | `/constitution` | `x0x constitution` | Display the x0x Constitution (Markdown) |
| GET | `/constitution/json` | `x0x constitution --json` | Constitution with version metadata (JSON) |

### Example: health

```bash
curl http://127.0.0.1:12700/health
# {"ok":true,"status":"healthy","version":"<x.y.z>","peers":4,"send_ready_peers":4,"uptime_secs":300}
```

### Example: status

```bash
TOKEN=$(cat "$HOME/Library/Application Support/x0x/api-token")   # Linux: ~/.local/share/x0x
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:12700/status
# {
#   "ok": true,
#   "status": "connected",
#   "version": "<x.y.z>",
#   "uptime_secs": 300,
#   "api_address": "127.0.0.1:12700",
#   "external_addrs": ["203.0.113.5:5483"],
#   "agent_id": "8a3f...",
#   "peers": 4,
#   "send_ready_peers": 4,
#   "warnings": []
# }
```

## Identity

| Method | Endpoint | CLI | Purpose |
|---|---|---|---|
| GET | `/agent` | `x0x agent` | Local agent identity |
| POST | `/announce` | `x0x announce` | Re-announce identity to the network |
| GET | `/agent/user-id` | `x0x agent user-id` | Current user ID if configured |
| GET | `/agent/card` | `x0x agent card [DISPLAY_NAME] [--include-groups] [--include-local-addresses]` | Generate a shareable, signed identity card (`--include-local-addresses` adds loopback/RFC1918 addresses for local testnet cards; off by default so shared cards don't leak unroutable addresses) |
| GET | `/.well-known/agent-card.json` | — | A2A-compatible discovery card (ADR-0017) |
| POST | `/agent/card/import` | `x0x agent import` | Import a card into contacts (verifies signature; never changes existing trust: floor at existing level, Blocked is sticky) |
| POST | `/agent/sign` | `x0x agent sign` | Detached ML-DSA-65 signature over caller-supplied bytes |
| POST | `/agent/verify` | `x0x agent verify` | Verify a detached ML-DSA-65 signature against a caller-supplied public key |
| GET | `/introduction` | `x0x agent introduction` | Trust-gated introduction card (`?peer=<64-hex>` scopes it to that peer's trust) |
| POST | `/identity/revoke` | `x0x identity revoke [--agent-id <hex>] [--machine-id <hex>] [--move-epoch <n>] [--reason <text>]` | Issue a signed key revocation (self-revocation always allowed; revoking a third party requires a user-signed AgentCertificate; exactly one of `agent_id` / `machine_id` — or **both plus `move_epoch`** for the ADR-0043 binding form, which the CLI reaches via `--move-epoch`) |
| GET | `/identity/revocations` | `x0x identity revocations` | List signed identity revocations known to this daemon |

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
(`agent_id` is the domain-separated hash of `agent_public_key`) and then
checks the signature, so a relay cannot substitute a foreign key. `POST /agent/card/import` rejects a signed
card whose signature fails; legacy unsigned cards (`signature` absent) still
import for backward compatibility.

**Mixed-fleet caveat (#450, pre-v0.41):** cards embed live DM capabilities in
their signed bytes; a v0.40.x peer drops the `digest_support` field during
re-serialization and therefore **fails to verify AgentCards from new daemons**.
Upgrade peers together — see the README's Known limitations table.

### Agent card import trust floor

`POST /agent/card/import` never **changes an existing deliberate trust
decision**. Two rules protect prior intent:

1. **Blocked is sticky.** A deliberately blocked agent cannot be un-blocked
   by a card re-import. Blocked contacts have gossip and DMs silently
   dropped; un-blocking is only available via `PATCH /contacts/:agent_id` or
   `POST /contacts/trust`.
2. **Floor at existing level.** For non-blocked contacts, the effective
   trust is `max(existing, requested)`, so a re-import (which defaults to
   `"known"`) cannot downgrade a manually-trusted peer.

For a new contact the requested `trust_level` (default `"known"`) is applied
as-is. The response includes `trust_change_ignored: true` when the requested
level conflicted with an existing trust decision and was therefore ignored.

To explicitly change trust (upgrade, downgrade, block, or un-block), use
`PATCH /contacts/:agent_id` or `POST /contacts/trust` — those are
unambiguous user intent and always apply the requested level.

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

### Sub-agent harness boundary (ADR-0039)

| Method | Endpoint | CLI | Purpose |
|---|---|---|---|
| GET | `/owner/agents` | `x0x owner agents` | Roster of owner-certified agents (journal-backed) |
| POST | `/owner/agents/issue` | `x0x owner agents issue <PUB_HEX>` | Owner-sign an `AgentCertificate` over a harness-submitted agent **public** key |
| DELETE | `/owner/agents/:id` | `x0x owner agents revoke <AGENT_ID>` | ADR-0018 owner issuer-revocation of a registered sub-agent |
| POST | `/owner/riders` | — (REST/library only; see below) | Mint a scoped rider token for a registered rider-mode sub-agent |
| GET | `/owner/riders` | `x0x owner riders` | List rider-token records (no secrets) |
| DELETE | `/owner/riders/:id` | `x0x owner riders revoke <TOKEN_ID>` | Revoke a rider token (fails on next request) |

All six are owner-only: every `/owner/*` route rejects a rider token with
`403` in the auth middleware before any handler runs. `409` when the
daemon has no owner user key.

**Issuance** takes `{ "agent_public_key": <hex ML-DSA-65 public key>,
"mode": "acp"|"rider", "label"?: string, "not_after"?: unix-seconds }`.
The harness generates and custodies the keypair; the daemon never sees
the secret. The record lands in the owner-scoped ADR-0036 issuance
journal (`owner-cert-journal.jsonl`) with the mode, label, and the full
certificate bytes (retained so revocation can present the exact ADR-0018
authority evidence), and the response returns the certificate
(`certificate.storage_b64`) for ACP-attached harness instances.

**Rider tokens** (`{ "sub_agent_id": <hex>, "groups": [gid…], "label"?:
string, "ttl_secs"?: ≤ 90 days, default 7, "delegation": {
"payload_b64", "signature" } }`) are stored hashed at rest (SHA-256),
expire, and are revocable per-token or by revoking their sub-agent.
The `delegation` capability is REQUIRED — a request without it answers
`400 delegation is required…`. The CLI `x0x owner riders issue` mints
fine **when given both `--delegation-payload-b64` and
`--delegation-signature`** (clap-required, mutually `requires`-bound).
Certify the sub-agent first (`POST /owner/agents/issue` with
`"mode": "rider"` — the CLI equivalent is `x0x owner agents issue
<PUB_HEX> --mode rider`), then mint with a harness-side capability:

the harness signs `rider_delegation_bytes(sub_agent_id,
daemon_agent_id, groups, not_after)` with the sub-agent's OWN key
(helper: `x0x::groups::sign_rider_delegation`); the daemon verifies it
against the certified sub-agent key before minting, binds it into the
token, and re-verifies it before every send. A rider token
authenticates as a distinct principal that may reach exactly:

- `POST /groups/:id/send` — `SignedPublic` groups in its grant list
- `POST /groups/:id/secure/encrypt` — `MlsEncrypted` groups (incl. Home)
  **in its grant list** — there is no implicit Home grant; Home's group id
  must be listed explicitly like any other group (`rider_allows_group`
  checks the explicit list only)
- `GET /history` — `group:` scopes it is granted, limit clamped to 100

Every other route — including `/agent/sign`, `/exec/*`, `/identity/*`,
and `/shutdown` — answers `403`. Rider sends are signed by the daemon's
own agent key carrying a provenance envelope **inside the signed
bytes** — `sub_agent_id`, `rider_token_id`, `rider_token_hash`,
`scope`, and the sub-agent-signed delegation capability itself. The
delegation makes the attribution cryptographic instead of asserted:
receivers verify the embedded owner certificate, the capability
signature under the certified sub-agent key, that the capability names
the actual message-signing daemon, the group scope, and the expiry —
then enforce ban/write policy against the sub-agent. A daemon can
therefore only speak for sub-agents that explicitly authorized it. The
per-message envelope carries the certificate (~10 KB overhead) so
verification is self-contained. `/agent/sign` stays owner-only. Rider
Home encrypts record the sub-agent id as the history row's author.

**Verified rider lifecycle** (run against a live daemon this campaign):

```json
// POST /owner/riders -> 200 (token secret returned exactly once)
{"ok":true,"sub_agent_id":"df4eca…","token_id":1,"label":"…",
 "groups":["home"],"issued_at_unix":1788091312,"expires_at_unix":1788092212,
 "token":"bfc14e49…"}
```

- `GET /owner/riders` lists records with **no secrets** — `token_id`,
  `sub_agent_id`, `cert_digest`, `groups`, `issued_at_unix`,
  `expires_at_unix`, `revoked_at_unix`. Durable-owner only.
- With the rider token: `GET /history?scope=group:home` → `200`;
  `GET /owner/agents` → `403`; `POST /agent/sign` → `403`.
- `DELETE /owner/riders/:id` → the very next rider request answers `401`
  (persist-or-fail: a failed disk write returns `500` and the token stays
  live everywhere).
- `DELETE /owner/agents/:id` (sub-agent revocation) → ADR-0018
  issuer-revocation; all rider tokens bound to the agent are revoked in the
  same stroke. `404` when the agent is not on this owner's journal; `409`
  when no retained certificate exists.
- The delegation capability must not outlive
  `min(cert expiry, token expiry)` — a longer `not_after` answers
  `400` with the bound named.



## Owner profile and naming (ADR-0036)

| Method | Endpoint | CLI | Auth | Purpose |
|---|---|---|---|---|
| GET | `/profile` | `x0x profile` | bearer | Daemon-persisted self-profile names |
| PUT | `/profile` | `x0x profile set --display-name … --machine-name … --human-name …` | bearer | Partial update of the self-profile |
| GET | `/owner/agents` | `x0x owner agents` | bearer | Roster of agents certified by this owner (journal-backed) |

The profile is daemon state (`<data_dir>/profile.json`), not client state:
names survive GUI resets and are consistent across every client of the
daemon.

**GET /profile response** (all fields nullable):

```json
{"ok":true,"human_name":null,"display_name":"Alice","machine_name":"desk"}
```

**PUT /profile request** — every field optional; only present fields are
applied (partial update):

| Field | Type | Notes |
|---|---|---|
| `human_name` | string? | Owner's human name; feeds the agent card's `owner_name` |
| `display_name` | string? | This agent's display name; rides the next V3 announce as the signed self-name |
| `machine_name` | string? | Label for this machine |

Clearing a name is done with an **empty string** (`""`); JSON `null` and
omitted fields both mean "leave unchanged". A cleared display name keeps
publishing explicit no-name X0A4 beats so peers erase it.

**GET /owner/agents** answers `409` on an un-owned install. Each roster row:
`agent_id` (hex), `cert_not_after` (unix seconds, null = no expiry), `label`
(contact-store label), `self_name` (V3 announce name, when seen), `machine_id`
(last announced machine, if discovered), `is_local` (bool), `from_journal`
(bool — persisted issuance journal `owner-cert-journal.jsonl`, survives
restarts), `mode` (`"acp"` \| `"rider"`), `journal_label`, `revoked` (bool),
`placement` (nullable enrichment: `"pinned"`/`"roaming"` + epoch — null when
no owner-verified placement record is held; P enforcement fails open for such
agents).

## Home (ADR-0038)

| Method | Endpoint | CLI | Auth | Purpose |
|---|---|---|---|---|
| GET | `/home` | `x0x home` | bearer | Resolve the owner's Home space |
| POST | `/home/rename` | `x0x home rename <NAME>` | durable-owner (#446) | Rename the Home (admin-gated, sealed into the state chain) |

The first start of an owned install provisions exactly one Home:
`Hidden + OwnerCertified(owner) + MlsEncrypted + MembersOnly/MembersOnly`,
named "Home". The daemon's own owner-certified agent is the founding member
and **primary agent** — the owner speaks *through* an agent; there is no human
wire signer. Admission is cryptographic: joining requires an agent certificate
chaining to the owner's user key, re-checked at every state seal. An
uncertified holder of a valid invite is refused (`403`).

**GET /home response** (`404` with `no Home provisioned (un-owned install)` /
`no Home provisioned` otherwise):

```json
{
  "ok": true,
  "group_id": "3277a3c3…",
  "name": "Home",
  "description": "Owner's personal space (auto-provisioned)",
  "human_name": "Alice",
  "primary_agent": {
    "agent_id": "414529…",
    "self_name": "Alice",
    "verified": false
  },
  "members": [
    {"agent_id":"414529…","role":"Admin","placement":"roaming","self_name":"Alice"}
  ],
  "warnings": {"no_roaming_agent": false, "primary_agent_unverified": true}
}
```

- `placement` per member: `"roaming"` | `"pinned"` (from Home metadata).
- `primary_agent.verified` is the fail-closed trust check that the primary's
  certificate chains to the owner (a committed certificate must be present);
  the GUI shows the owner chip only when true.
- `warnings.no_roaming_agent` — ADR-0038 invariant: Home should always
  contain ≥ 1 Roaming agent.

**POST /home/rename** takes `{"name": "…"}`; it is a convenience wrapper over
`PATCH /groups/:id` (admin-gated, sealed, persisted). Errors: `404` un-owned /
no Home; `409` admin-gate failures. Requires the **durable-owner** token
(#446) — and `PATCH /groups/:id` **and** `PATCH /groups/:id/policy` require
it too when the target carries Home metadata. Home is identified by metadata
presence, NEVER by its current policy axes, so a session cannot
policy-flip around the rename gate. Ordinary groups keep the bearer
PATCH paths.

**Known limitation (#449):** Home dedup is per-machine — each of the owner's
devices provisions its own Home (observed live: two daemons sharing one
`user.key` minted two different `group_id`s). Cross-device reconciliation is
ADR-0041 follow-up. **Known limitation (#447):** a certified second device
becomes join-eligible only after its second announce beat (~600 s); a premature
join is rejected (`MemberJoined: rejecting uncertified joiner`) and the joiner
must locally delete + rejoin.

## Device sync (ADR-0041, Tier 1)

| Method | Endpoint | CLI | Auth | Purpose |
|---|---|---|---|---|
| GET | `/sync/devices` | `x0x sync devices` | bearer | Owner device set + last-sync status |
| POST | `/sync/devices/enroll` | `x0x sync enroll` | durable-owner (#446) | Owner-key-sign a DeviceEnrollment for a machine |
| DELETE | `/sync/devices/:machine_id` | `x0x sync revoke <MACHINE_ID>` | durable-owner (#446) | Remove a machine from the device set |

All three answer `409` when no owner identity is configured. Sync replicates
owner state **owner-to-owner only** — Tier 1: profile/names, the Home
history, DMs, and exec data
never replicate, and no third party receives the state. Inbound SyncV1 streams
are refused at the enrollment gate unless the enrollment signature and
currency (expiry) verify — corrupt, foreign-key, or stale enrollments never
open the sync gate; non-enrolled machines are refused at stream accept.

**GET /sync/devices response:**

```json
{
  "ok": true,
  "owner_user_id": "02492c…",
  "this_machine_id": "e55130…",
  "devices": [
    {"machine_id":"e55130…","enrolled_at_ms":1788090728080,
     "expires_at_ms":null,"last_session_ms":null,"last_session_ok":null,
     "is_this_machine":true}
  ]
}
```

**POST /sync/devices/enroll** request — `machine_id` optional (64-hex;
omitted = enroll THIS machine), `ttl_secs` optional (bounds the enrollment's
lifetime; omitted = until deleted). Response: `machine_id`, `enrolled_at_ms`,
`expires_at_ms` (null = no expiry), `device_count`. A persistence failure is a
`500` — success is never reported on a swallowed write.

**Enrollment is per-machine and must be bilateral.** A daemon dials sync only
to machines in *its own* enrolled set (minus itself), and the receiving side
accepts a stream only from a machine *it* has enrolled. Two machines sync
when each holds the other's enrollment — run `enroll` on **both** machines,
each naming the other's machine id (plus itself), or no session is ever
established.

**Trust prerequisite:** SyncV1 rides ADR-0022 byte streams through the same
stream gate as every other protocol — each side's peer-trust decision for the
other's agent must be plain `Accept` (`trusted`), or the stream is refused with
`stream peer trust rejected: agent […]`. Symptom of a missing trust mark: the
dialer logs `Tier-1 dial skipped/failed until next pass` every sync pass and
`GET /sync/devices` shows `last_session_ok: false` forever despite bilateral
enrollment. Set trust on **both** sides (`x0x trust set <agent_id> trusted` /
`POST /contacts/trust`).

**What Tier 1 actually applies today:** profile/names converge; the Home
pointer is synced and **stored for future adoption — it is not applied**
(each device keeps its own Home, #449); sub-agent issuance journal lines are
synced as the issuance fact only (digest + time) — `mode` defaults to `acp`,
`label` is dropped, and **no certificate bytes travel Tier 1** (Tier-3
boundary), so a synced roster row is not itself mint-capable for riders.

**DELETE /sync/devices/:machine_id** — the *next* inbound stream from that
machine is refused; existing streams are not torn down mid-flight. `404` when
the machine is not enrolled; `400` for a malformed id — but the owner gate runs
FIRST: on a daemon with no owner identity the DELETE answers `409 no owner
identity configured` regardless of the id's shape.

## Placement and agent key-move (ADR-0043)

| Method | Endpoint | CLI | Auth | Purpose |
|---|---|---|---|---|
| POST | `/agent/move` | `x0x move authorize` | durable-owner | Owner-authorize a move (chains `MoveAuthorization`; source seals when run there) |
| POST | `/agent/move/export` | `x0x move export` | durable-owner | Source machine seals the export envelope + `ExportReceipt` |
| POST | `/agent/move/import` | `x0x move import` | durable-owner | Target machine imports a transfer bundle (unwrap + store + receipt) |
| POST | `/agent/move/activate` | `x0x move activate` | durable-owner | Owner commits a move (`ActivationBundle` on the activation topic) |
| POST | `/agent/move/abort` | `x0x move abort` | durable-owner | Roll back a pre-activation move (epoch burned) |
| POST | `/agent/move/retire` | `x0x move retire` | durable-owner | Source retires after activation (delete key + receipt) |
| GET | `/agent/moves` | `x0x move list` | durable-owner | Move-log view + derived state (`?agent_id=` filters) |
| GET | `/owner/placement` | `x0x owner placement` | durable-owner | Derived placement ledger (lazy mint + ≥1-Roaming Home invariant) |
| GET | `/owner/agents/:id/placement` | `x0x owner agents placement <AGENT_ID>` | durable-owner | One agent's placement record |

**The roaming-move ceremony is experimental and OFF by default** — every
`/agent/move*` endpoint answers **501** with an explanatory body until the
daemon config sets `[key_move] ceremony_enabled = true`. Shipped posture:
no move can occur; every roster agent stays **Pinned** at its mint machine —
except the local agent itself, which the lazy mint deliberately records as
**Roaming** (epoch 0, inert without the ceremony) to satisfy the ADR-0038
≥-1-Roaming Home invariant. Placement *records* and their enforcement gates
(identity ingest, DM inbox, forward, connect-send) are live.

Owned agents are `Pinned(MachineId)` or `Roaming` in an owner-signed
placement ledger. **Binding revocation** is the permanent tombstone form of
`POST /identity/revoke`: send **both** `agent_id` and `machine_id` (32-byte
hex each) **plus** `move_epoch` (u64, orders the tombstone against placement
records). CLI (all three flags together):
`x0x identity revoke --agent-id <hex> --machine-id <hex> --move-epoch <N>`.
Durable-owner only — a session token answers `403`; a missing
`move_epoch` answers `400`. The one-id forms remain the agent/machine
self- or user-authority revocations.

`GET /owner/placement` lazily mints epoch-0 records on first read and
returns `owner_user_id`, `minted_now`, `roaming_count`, `home_invariant_ok`
(≥ 1 Roaming agent), and `placements[]` (`agent_id`, `kind`
`"roaming"|"pinned"`, `pinned_machine`, `epoch`, `issued_at`, `digest`).
`GET /agent/moves` returns per-agent `records[]` (kind + hash) and a
`derived` fold: `custodian`, `phase` (`idle|mid_move|retire_pending`),
`retired_bindings`, `placement`, and this-machine flags `holds_key`,
`may_sign`, `quiesced`, `quarantined`.

Move-ceremony errors: `403` non-durable token; `409` no owner key / no mint /
a move already in flight / activation-coherence refusal; `400` malformed ids
or an illegal placement; `501` ceremony disabled.

## Network

| Method | Endpoint | CLI | Purpose |
|---|---|---|---|
| GET | `/peers` | `x0x peers` | Connected gossip peers |
| GET | `/presence` | `x0x presence` | Presence view of online agents |
| GET | `/presence/online` | `x0x presence online` | Online agents (network-view trust filter) |
| GET | `/presence/foaf` | `x0x presence foaf` | Friends-of-friends discovery walk (`?ttl=<hops>`, default 3; social-view trust filter) |
| GET | `/presence/status/:id` | `x0x presence status <agent_id>` | One agent's presence status (local cache) |
| GET | `/presence/find/:id` | `x0x presence find <agent_id>` | Find a specific agent by ID via FOAF random walk |
| GET | `/presence/events` | `x0x presence events` | Server-Sent Events stream of presence online/offline events |
| GET | `/network/status` | `x0x network status` | NAT and connectivity diagnostics |
| GET | `/network/bootstrap-cache` | `x0x network cache` | Bootstrap cache stats |
| GET | `/peers/:peer_id/health` | `x0x peer health <peer_id>` | Connection health snapshot for a peer |
| POST | `/peers/:peer_id/probe` | `x0x peer probe <peer_id>` | Active `probe_peer` liveness + RTT check |
| GET | `/peers/events` | `x0x peer events` | SSE stream of peer lifecycle events |

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

### `/events` SSE message shape

Each gossip message arrives as an envelope with the fields nested under
`data` (unlike the flat WebSocket `message` frame):

```json
{
  "type": "message",
  "data": {
    "subscription_id": "8daec1f568bc0a54",
    "topic": "updates",
    "payload": "aGVsbG8=",
    "sender": "8a3f...",
    "verified": true,
    "trust_level": "known"
  }
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
- `/agents/discovered/:agent_id?wait=true`
- `/machines/discovered?unfiltered=true`
- `/machines/discovered/:machine_id?wait=true`

`wait` is a **boolean**: the daemon waits its fixed discovery window when
`true` (a numeric value such as `wait=5` is a query-deserialize 400).

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
| POST | `/contacts/:agent_id/machines` | `x0x machines add <agent_id> <machine_id> [--label <LABEL>] [--pin]` | Add a machine record |
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
  -H "Authorization: Bearer $TOKEN" \
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
| POST | `/direct/send` | `x0x direct send <agent_id> <message> [--require-ack-ms <ms>] [--prefer-raw-quic-if-connected <BOOL>] [--raw-quic-receive-ack-ms <ms>] [--stop-fallback-on-raw-error] [--require-gossip] [--no-durable-ack] [--logical-id <token>]` | Send a direct base64 payload. Durable-by-default since v0.38.0 |
| GET | `/direct/connections` | `x0x direct connections` | List active direct connections |
| GET | `/history/message/:msg_id` | `x0x history message` | Point lookup of one durable history row by exposed `msg_id` (64 hex; canonical group ids need `?scope=`); 404 when absent, 400 on malformed id. Same record shape as `/history` (issue #319) |
| GET | `/direct/events` | `x0x direct events` | SSE stream of direct messages; `?backfill=N` first replays up to N stored `dm:` rows as `history_direct_message` events, then a `live` marker, then live frames (ADR-0023 §7) — this (or `/ws/direct?backfill=N`) is how a client READS already-delivered DMs |

### Direct send request body

```json
{
  "agent_id": "8a3f...",
  "payload": "aGVsbG8=",
  "logical_id": "order-42"
}
```

`agent_id` and `payload` are the only required fields. Everything below is
optional.

Optional field `prefer_raw_quic_if_connected` (bool): when a live transport
connection to the recipient exists, deliver over raw QUIC instead of the
gossip inbox. **Defaults to `true` since v0.37.0** (previously `false`);
omitting the field selects the daemon default, so clients that relied on the
old default must now send `"prefer_raw_quic_if_connected": false` explicitly.

Optional field `require_durable_app_ack` (bool): choose the receipt semantics.
**Defaults to `true` since v0.38.0** (ADR 0030 §4) — this endpoint is a
*product-tier* surface, so a `200` means the recipient daemon durably
committed the message to its history store and completed local dispatch, not
merely that it accepted the envelope.

Pass `false` to opt out and get v1 semantics, where `200` means "accepted for
delivery". Opting out is the right choice when reaching a peer that has not
upgraded matters more than the stronger receipt: a durable send to a peer
running 0.37.x — or to any peer without durable history enabled — answers
**409 `recipient_ack_semantics_unavailable`** instead of delivering.

Two consequences worth planning for:

- A durable send never uses the raw-QUIC fast path, because raw QUIC yields a
  transport receipt that cannot certify a durable commit. `prefer_raw_quic_if_connected`
  is therefore ignored unless you also pass `require_durable_app_ack: false`.
- Durable delivery is **at-least-once across a recipient restart** (ADR 0030
  §1). It never implies read, and never implies exactly-once application
  delivery. Applications needing restart-spanning exactly-once dedupe on
  `(sender, request_id)`.

Optional field `logical_id` (string): a caller-supplied idempotency key for
this logical send, **valid only on a durable send**. 1–128 characters of
`a`–`z`, `0`–`9`, `-`, `_`, `.`, or `:`; uppercase, whitespace, and non-ASCII
are rejected rather than normalized, so two tokens that differ only in case
stay two distinct requests.

The durable requirement is not a formality: everything below is a promise the
*recipient's* durable path makes — its replay binding and its durable-history
lookup are what recognise a retry. A v1 send would carry a derived id on the
wire that no receiver consults, so the guarantee would not exist. Sending
`logical_id` with `require_durable_app_ack: false` is therefore a **400
`logical_id_requires_durable_ack`**, not a silent no-op: a caller who asked for
retry identity and quietly got fire-and-forget would not find out until
duplicates appeared. (`x0x direct send` rejects `--logical-id` with
`--no-durable-ack` at the CLI, before the round trip.)

Resending the same `logical_id` to the same recipient — after a timeout, a
reconnect, or a full process restart — is *the same request*, not a second
message: the recipient recognises it and re-ACKs the original commit instead of
storing a duplicate. Omitting the field draws a fresh random id per call, which
is correct for fire-and-forget sends.

The daemon derives the 128-bit wire request id as
`blake3::derive_key("x0x dm logical request id v1", sender_agent_id ‖
recipient_agent_id ‖ logical_id)` truncated to its leading 16 bytes. Both agent
ids are mixed in, so the same token addressed to two different recipients
yields two different requests. The token itself never goes on the wire.

Reusing a `logical_id` for *different* payload bytes is a **409
`idempotency_conflict`** — see below.

> **Removed (ADR 0030 §4): `require_gossip_ack`.** Setting this field in any
> form — `true`, `false`, or a non-boolean — is now **400
> `require_gossip_ack_removed`**. An explicit `null`, like omitting it, is
> accepted. Accepting the field as a silent no-op was rejected in review: a
> client that passed `require_gossip_ack: false` for fire-and-forget would
> otherwise get a blocking durable send and no signal that its request had been
> reinterpreted. Choose receipt semantics with `require_durable_app_ack`
> instead.

### Direct send error codes

`/direct/send` failures answer with
`{"ok": false, "error": "<code>", "detail": "<human-readable>"}`.
Notable codes:

| Status | `error` | Meaning |
|---|---|---|
| 400 | `require_gossip_ack_removed` | The request set the removed `require_gossip_ack` field. Drop it; use `require_durable_app_ack`. |
| 400 | `invalid_logical_id` | `logical_id` was empty, longer than 128 characters, or contained a character outside `[a-z0-9._:-]`. |
| 400 | `logical_id_requires_durable_ack` | `logical_id` was sent with `require_durable_app_ack: false`. Only the durable path honours the id; drop one or the other. |
| 404 | `recipient_key_unavailable` | The recipient has published no KEM key, or is entirely unknown to this daemon — **no capability advert and no contact card at all**. A durable send to a stranger answers this, not the 409 below. |
| 409 | `recipient_key_invalid` | Our view of the recipient's key material has not converged. Transient — retry. |
| 409 | `recipient_ack_semantics_unavailable` | The send required ADR 0030 durable application-ACK semantics and the recipient advertises no current v2 capability. A peer you hold **any** contact card for lands here rather than on the 404 — including one whose advert has not converged yet, since that peer is known and may simply need upgrading. Returned after one forced targeted capability refresh, so it is fast and deterministic rather than a timeout. The caller retries, surfaces "peer needs upgrade", or resends with `require_durable_app_ack: false` — the daemon never downgrades silently. |
| 409 | `idempotency_conflict` | The recipient already holds this `logical_id` bound to different bytes. **Retrying cannot succeed.** Either resend the original bytes under this id, or pick a new `logical_id`. |
| 413 | `payload_too_large` | Payload exceeds the DM envelope cap. |
| 504 | `timeout` | No application ACK within the retry budget. The DM may or may not have arrived. On a durable send the body also includes `strict_gate_ms`, `publish_ms`, `ack_wait_ms`, `elapsed_ms`, and `budget_stage` so the stage that consumed the budget is named. Durable 200 and 504 also include recipient ACK-publish diagnostics `last_ack_publish_ms` and `ack_publish_route_failed` (same fields on `GET /diagnostics/dm`). These are diagnostics, not a latency SLA. |

The two 409s prescribe opposite repairs and must not be conflated in client
code: `recipient_ack_semantics_unavailable` means *retry later or tell the user
to upgrade the peer*; `idempotency_conflict` means *these bytes will never be
accepted under this id*. Before v0.38.0 the conflict case was reported as
`recipient_ack_semantics_unavailable`, which sent clients down the wrong branch.

**Rollout note.** Because the default flipped to durable, clients that
previously got `200` from a 0.37.x peer will now get
`409 recipient_ack_semantics_unavailable` until that peer upgrades. This is
deliberate (ADR 0030 §2: never a silent downgrade). Handle the 409 as a
first-class UX state; where delivery matters more than the receipt, send
`require_durable_app_ack: false`.

### Recipient capabilities: `DmCapabilities`

Peers advertise their DM capabilities in signed capability adverts and on
agent cards (`dm_capabilities` member; a card predating the field means
legacy raw-QUIC-only):

| Field | Type | Meaning |
|---|---|---|
| `max_protocol_version` | u16 | Highest receive-path DM protocol the peer understands |
| `gossip_inbox` | bool | `true` = the peer subscribes to its gossip inbox and published a KEM key |
| `kem_algorithm` | string | `"ML-KEM-768"` |
| `max_envelope_bytes` | usize | Maximum accepted envelope size |
| `kem_public_key` | bytes | ML-KEM-768 public key (empty = unavailable, raw-QUIC fallback) |
| `digest_support` | bool | **v0.41 / issue #437**: `true` advertises verify/enforce support for the signed `RelayHeader.inner_digest` (`x0x-relay-hdr-v2`). Omitted when `false`, preserving byte-identical pre-#437 adverts |

Mixed-fleet behaviour (#448): a v0.40.x peer cannot verify a `digest_support:
true` advert after re-serialization and drops it (self-healing once both sides
upgrade); old→new *strict* durable DMs answer `409
recipient_ack_semantics_unavailable` until the old side upgrades. Plan
upgrades as a coordinated roll-forward.

### `/direct/events` SSE message shape

Direct messages arrive flat — no `data` envelope:

```json
{
  "sender": "8a3f...",
  "machine_id": "b2c4...",
  "payload": "aGVsbG8=",
  "received_at": 1774860000,
  "verified": true,
  "trust_decision": "Accept"
}
```

Opt-in (issue #120): when the daemon sets `observed_prefix_enabled = true`
and the message arrived over the live point-to-point transport connection,
an `observed_origin` field is added — a coarse, masked origin token such as
`{"observed_prefix": "203.0.113.0/24", "direct": true, "cgnat": false}`
(`/24` IPv4, `/48` IPv6; `direct=false` marks a relayed observation; `cgnat`
marks RFC 6598 space). When the option is off (the default) the field is
entirely absent. The same optional field appears on `/ws` and `/ws/direct`
`direct_message` frames and on per-peer rows of `GET /diagnostics/dm`;
it is never gossiped, never announced, and never on `/peers`.

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
| POST | `/groups/:id/members` | `x0x group add-member <group_id> <agent_id> [--display-name <n>] [--key-package <b64>]` | Admin-authored member add (propagates to subscribed peers). `--key-package` carries the base64 TreeKEM key package required for direct adds to encrypted groups |
| DELETE | `/groups/:id/members/:agent_id` | `x0x group remove-member <group_id> <agent_id>` | Admin-authored member removal (propagates to subscribed peers) |
| POST | `/groups/:id/invite` | `x0x group invite <group_id>` | Generate a SIGNED v4 invite link. Body `{"expiry_secs":u64,"intended_joiner":"<64-hex agent id, optional>"}`. Owner-axis (Home-capable) groups additionally require the durable owner's loaded user key (else 409 `owner_key_unavailable`). Typed 413 `invite_too_large` (per-field caps + final encoded size; roster cap 20) and 429 `invite_cap_reached` (64 live unconsumed records/group) |
| POST | `/groups/join` | `x0x group join <invite> [--display-name <n>] [--home --owner <hex>]` | Join via signed v4 invite. Body `{"invite":..., "display_name":..., "mode":"group"|"home", "expected_owner_user_id":"<64-hex>"}`. Typed 409 refusals: `invite_unsigned` (pre-v4), `invite_signature_invalid`, `inviter_key_mismatch|revoked`, `invite_base_inconsistent`, `invite_owner_countersignature_missing|invalid`, `invite_not_addressed_to_me`, and the mode matrix `use_home_mode` / `pin_requires_home_mode` / `home_mode_requires_pin` / `invite_downgraded` / `owner_mismatch`; unknown mode 400 |
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
| POST | `/groups/:id/send` | `x0x group send <group_id> <body> [--kind chat\|announcement] [--thread-root <id>] [--reply-to <id>] [--mentions <hex>...] [--delegation-digest <hex>]` | **Phase E**: publish a signed message to a SignedPublic group. `--mentions` (repeatable) routes structured ADR-0040 mentions daemon-side; `--delegation-digest` authorizes send-as attribution |
| POST | `/groups/:id/delegate` | `x0x group delegate <group_id> --to-agent … --scope … --expiry-ms …` | Issue a signed delegation (ADR-0040; effective on durable history commit) |
| GET | `/groups/:id/delegations` | `x0x group delegations <group_id>` | List effective delegations re-derived from durable history |
| GET | `/groups/:id/messages` | `x0x group messages` | **Phase E**: retrieve cached public messages (non-members on Public read) |
| GET | `/groups/discover/nearby` | `x0x group discover-nearby` | **Phase C.2**: presence-social browse of PublicDirectory groups |
| GET | `/groups/discover/subscriptions` | `x0x group discover-subscriptions` | **Phase C.2**: list active shard subscriptions |
| POST | `/groups/discover/subscribe` | `x0x group discover-subscribe` | **Phase C.2**: subscribe to a tag/name/id shard |
| DELETE | `/groups/discover/subscribe/:kind/:shard` | `x0x group discover-unsubscribe` | **Phase C.2**: unsubscribe from a shard |
| GET | `/groups/discover` | `x0x group discover` | **Phase C.2**: list locally known discoverable groups |
| GET | `/groups/cards/:id` | `x0x group card <group_id>` | Fetch a single group card |
| POST | `/groups/cards/import` | `x0x group card-import` | Import a group card into local cache |
| POST | `/groups/:id/secure/encrypt` | `x0x group secure-encrypt <group_id>` | Encrypt content with the group's shared secret (member-only) |
| POST | `/groups/:id/secure/decrypt` | `x0x group secure-decrypt <group_id>` | Decrypt content with the group's shared secret (member-only, epoch must match) |
| POST | `/groups/:id/secure/reseal` | `x0x group secure-reseal <group_id>` | Re-seal the current group shared secret to a named recipient (`SecureShareDelivered`-format envelope) |
| POST | `/groups/secure/open-envelope` | `x0x group secure-open-envelope` | Attempt to open a `SecureShareDelivered` envelope with this daemon's KEM key (adversarial test) |
| DELETE | `/groups/:id` | `x0x group leave <group_id>` | Leave the group by self-removing, for any rank. A sole-member leave deletes the group (`{"ok":true,"deleted":...}`); otherwise the last admin is blocked — promote another admin first or use `x0x group delete` |

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
on leave. Exception (#369): when the leaver is the group's only remaining
member, the self-leave IS a deletion — it runs the same terminal withdrawal as
`x0x group delete` below (withdrawn tombstone, key wipe, `GroupDeleted`
propagation) and answers `{"ok":true,"deleted":"<name>"}` instead of
`{"ok":true,"left":...}` so clients can tell the two outcomes apart. Tombstone
visibility: `GET /groups` hides withdrawn records; `GET /groups/:id` serves
them with `"withdrawn": true`; `GET /groups/discover` deliberately still
emits withdrawn cards so stale public discovery listings are superseded.

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

**Send request — ADR-0040 fields.** `POST /groups/:id/send` accepts two
optional attribution fields alongside `body` / `kind` / `thread_root` /
`thread_parent`:

| Field | Type | Validation | Meaning |
|---|---|---|---|
| `mentions` | array of string | each exactly 64 lowercase hex (an AgentId); structural check at ingest — malformed items fail decode and the message is dropped by receivers | Structured mentions. A receiver whose local AgentId is in the list gets a WS `mention` event. Mentions are never inferred from message text. |
| `delegation_digest` | string? | exactly 64 lowercase hex (BLAKE3 of the authorizing delegation); owner-daemon-only on send | The message author acts under a `send_as` grant: the author signs with its OWN key and cites the grant by digest. Receivers require a locally durably-committed delegation authorizing that author before caching/routing — unauthorized attribution is dropped. |

On the wire, both fields live inside the signed `GroupPublicMessage` (v3
signature domain when populated; byte-identical to earlier domains when both
are absent). A `kind: "delegation"` carrier must NOT also carry
`delegation_digest`. Both fields are CLI-reachable: `x0x group send`
takes `--mentions <hex>` (repeatable) and `--delegation-digest <hex>`;
grant *issuance* works via `x0x group delegate`.

### Delegation (ADR-0040)

`POST /groups/:id/delegate` issues a signed, bounded, expiring grant **inside
a space**. The delegator (A) signs the `Delegation` with A's own ML-DSA-65
key; the delegate (B) never holds A's secret. A later B message cites the
grant via `delegation_digest`; authority is re-derived from durable group
history on every use — a forged digest, expired grant, or depth>2 chain is
rejected before the message is cached or routed. There is deliberately no
owner-transfer verb on the wire (task-ownership transfer was descoped — see
the ADR README erratum).

Request body:

| Field | Type | Required | Notes |
|---|---|---|---|
| `to_agent` | string | yes | 64-hex AgentId of an active group member |
| `scope` | string | yes | `"task_execute"` or `"send_as"` |
| `verbs` | array of string? | no | omitted = all verbs in scope; each of `claim`, `complete`, `send_public_message`; must belong to the scope; non-empty |
| `expiry_ms` | u64 | yes | unix ms; must be strictly after issuance |
| `task` | string? | task_execute only | 64-hex TaskId; rejected for `send_as` |
| `parent` | string? | no | 64-hex parent delegation digest for depth-2 re-delegation; parent must be live, name the caller as delegate, and bound/attenuate the child |

Success `200`:

```json
{
  "ok": true,
  "effective": true,
  "effectiveness": "durable_group_history",
  "delegation_digest": "589cac…",
  "depth": 1,
  "expiry_ms": 1788093176000,
  "notification": "durable_ack",
  "msg_id": "db3c02…"
}
```

Effectiveness is exactly "the carrier message is durably committed in this
group's history" — never "the notification was received". `notification`
reports the best-effort DM handoff to the delegate (`"durable_ack"` or
`"unreachable:<error>"`) and is informational only. The notification DM
payload is the ASCII prefix `x0x-delegation:v1:` followed by the signed
delegation JSON (arrays-of-bytes fields; no outer wrapper).

`GET /groups/:id/delegations` lists effective delegations re-derived from
durable history (survives restarts; fail-closed on incomplete history scans).
Each row: `delegation_digest`, `from_agent`, `to_agent`, `scope`, `verbs`,
`issued_at_ms`, `expiry_ms`, `depth`, `task_ref`.

Verified behaviour (this campaign): delegate → B sends citing the digest →
message accepted and attributed (author = B); the same send with a forged
digest answers `409 send_as unauthorized: referenced delegation is not durably
committed in this group's history`.

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

#### Bootstrap outbox sidecar (ADR 0030 §5)

Adding a member to a SignedPublic group owes that member a roster snapshot.
Since v0.38.0 the delivery is a durable obligation rather than a
fire-and-forget send, so an offline recipient still receives it. Obligations
are persisted to **`<data_dir>/public_group_bootstrap_outbox.json`**, capped at
1024 entries, and retried with exponential backoff to 60 s until the recipient
returns a durable (v2) application ACK for that exact frontier.

Two operator-visible consequences:

- The sidecar is loaded **fail-closed** at startup. An unsupported version, an
  over-cap file, a duplicate key, or a payload contradicting the frontier it
  claims **aborts daemon startup** rather than silently dropping a promised
  delivery. If a daemon refuses to start citing this file, the file is the
  problem — inspect it rather than deleting it blindly, since each entry is a
  delivery someone is still waiting for.
- Deleting the sidecar discards outstanding obligations permanently. Affected
  members will not receive their snapshot until they are re-added.

#### Threading (ADR-0029)

`POST /groups/:id/send` accepts two optional threading fields:

```json
{
  "body": "text",
  "thread_root":   "<64-char lowercase hex msg_id>",
  "thread_parent": "<64-char lowercase hex msg_id>"
}
```

- `thread_root` — `msg_id` of the first message in the thread.
- `thread_parent` — `msg_id` of the direct parent reply target. Requires
  `thread_root` to also be set. A direct reply to the root sets both fields
  to the root's `msg_id` (NIP-10 semantics).
- Both fields must be exactly 64 lowercase hex characters; 400 is returned
  otherwise.

The response includes `"msg_id"` — the stable BLAKE3 identity of the message —
and `"fan_out"` — the eager-peer publish count at gossip `publish_local`
(issue #296). `fan_out` is always present. `0` means no remote eager peer
was offered the message (solo node, or every eligible peer cooled/excluded).
HTTP 200 is preserved when the local ledger/cache write succeeded; delivery
is a separate fact.

```json
{ "ok": true, "msg_id": "<64-char hex>", "group_id": "...", "timestamp": ..., "fan_out": 1 }
```

Every message item returned by `GET /groups/:id/messages` also includes
`"msg_id"`. The endpoint accepts an optional `thread_root=<msg_id>` query
parameter that filters the result set to messages in that thread (the root
message itself is included when present):

```
GET /groups/:id/messages?thread_root=<64-char hex>
```

**Compatibility:** messages without thread fields sign under the v1 domain
(`x0x.group.public-message.v1`) and are byte-identical to the pre-ADR-0029
wire format — old nodes accept them unchanged. Threaded messages sign under
`x0x.group.public-message.v2`; old nodes reject them at signature
verification (fail-closed, never mis-attributed). The referenced parent is
not required to exist locally (partial gossip history is normal per
ADR-0028).

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
post-compromise security). Single- and **multi-member** private groups work
end-to-end (invite → join → bidirectional secure → ban → forward secrecy): a
2nd+ member's `MemberAdded`+`Welcome` is delivered over redundant channels
(direct push, the gossip metadata topic, a chunked welcome-blob pull, and the
anchor join-result poll, with a catch-up listener for repair) and the joiner
installs the tree and encrypts on the TreeKEM plane. Covered by
`tests/e2e_treekem_membership.py` (m1+m2 converge; anchor↔m1, anchor↔m2, m1↔m2
cross-decrypt; ban epoch-advance; post-ban forward secrecy). Convergence
*latency* depends on direct-connection/gossip formation — a timing
consideration, not a capability gap. Public encrypted presets
(`public_request_secure`) and grandfathered groups remain on the legacy **GSS**
plane. See `docs/primers/groups.md`.

## Collaborative task lists

| Method | Endpoint | CLI | Purpose |
|---|---|---|---|
| GET | `/task-lists` | `x0x tasks list` | List task lists |
| POST | `/task-lists` | `x0x tasks create <name> <topic>` | Create a task list |
| GET | `/task-lists/:id/tasks` | `x0x tasks show <list_id>` | List tasks |
| POST | `/task-lists/:id/tasks` | `x0x tasks add ...` | Add a task |
| PATCH | `/task-lists/:id/tasks/:tid` | `x0x tasks claim <list> <task> [--fence-token <t>] [--delegation <hex>]` / `x0x tasks complete ...` | Update task state (`action` is chosen by the subcommand). `--fence-token` is the local-replica CAS precondition (409 on mismatch); `--delegation` is the hex ADR-0040 digest authorizing the claim |

**Joining from a second machine = create a list with the SAME topic.** There
is no join verb: the list id derives from the topic alone (`TaskListId::from_topic`),
so another replica runs `POST /task-lists {"name":…,"topic":"<same topic>"}` and
converges via the state-sync side channel (cold-start bootstrap request, then
deltas). A plain topic subscription does NOT materialize the list on the new
machine — the create is what arms the bootstrap. (KV stores differ: they have
`POST /stores/:id/join` with `expected_owner`.)

Update task request body:

```json
{"action":"claim"}
```

or

```json
{"action":"complete"}
```

### Task mutation request fields (ADR-0040 `delegation`)

Task mutations accept optional authority evidence alongside `action`:

| Field | Type | Meaning |
|---|---|---|
| `fence_token` | string? | Local-replica fencing precondition; echo a prior token verbatim or the mutation is `409`-rejected |
| `delegation` | string? | Hex delegation digest — authorization evidence for a `task_execute` claim/complete performed under a delegation. Validated against the group's durably-committed delegation set before the mutation runs; invalid ⇒ `403` and nothing changes. CLI: `--delegation <hex>` on `x0x tasks claim/complete` |

### Task versions, advisory claims, and local-replica fencing

Every task-list response carries the list's `version` — a local counter bumped
on each local or merged mutation. Mutation responses (create list, add task,
claim, complete) return the new version plus `"committed":"local"`:

```json
{"ok":true,"version":7,"committed":"local"}
```

`"committed":"local"` is explicit about the consistency model: success means
the mutation was committed to the **local** CRDT replica and a delta was
published to peers — it does NOT mean any peer has observed it yet.
Replication is eventual (gossip anti-entropy).

Each task in `GET /task-lists/:id/tasks` includes structured ownership fields
alongside the legacy `state` string (unchanged for backward compatibility):

- `claimed_by` / `claimed_at` — hex AgentId and Unix-ms timestamp of the
  deterministic claim winner (the OR-Set resolution both replicas converge
  to). Non-null once claimed; `claimed_by` survives completion.
- `completed_by` / `completed_at` — same, for the winning completion; null
  unless done.
- `assignee` — hex AgentId from the task's LWW assignee register, populated
  by claim/complete.

#### Claims are advisory, never exclusive

A successful `claim` records a *candidate* in the OR-Set. It does **not**
grant exclusive ownership and does **not** prevent another agent (on this or
any other replica) from also claiming. Concurrent claims coexist and resolve
to a single deterministic winner (earliest timestamp, then lexicographic
agent id) only after convergence — a strictly earlier-timestamp candidate
arriving via a later merge can still displace the current winner. There is no
distributed lock.

The claim/complete response makes this advisory status explicit:

```json
{
  "ok": true,
  "version": 8,
  "fence_token": "<opaque epoch:revision — echo on next mutation>",
  "committed": "local",
  "resolution": {
    "agent_id": "<hex>",
    "locally_winning": true,
    "current_winner": { "agent_id": "<hex>", "timestamp_ms": 1700000000000 },
    "pending_convergence": true
  },
  "cas": { "scope": "local_replica" },
  "execution": { "authorization": "advisory" },
  "exclusive": false
}
```

- `resolution.locally_winning` — whether the caller is the local OR-Set's
  current deterministic winner at commit time. **Provisional**: a
  strictly-earlier candidate arriving via merge flips it to `false`.
- `resolution.current_winner` — the local deterministic winner (claim or
  completion), or `null`; lets a superseded caller see who currently beats
  them.
- `resolution.pending_convergence` — always `true` under CRDT: a later
  earlier-timestamp candidate may still arrive.
- `cas.scope` — `"local_replica"`: the `fence_token` guard (below)
  serializes ops on ONE daemon only.
- `execution.authorization` — `"advisory"`: callers MAY begin
  idempotent/reconcilable work and MUST re-check the winner after
  convergence. Exactly-once side effects are NOT provided.
- `exclusive` — always `false`.
#### `fence_token`: restart-safe local fence, not distributed CAS

The update-task request accepts an optional `fence_token` — an **opaque**
`"epoch:revision"` string returned by GET and by every mutation. Clients echo
it verbatim and MUST NOT construct or interpret it:

```json
{"action":"claim","fence_token":"1779123456789:7"}
```

This is a **local-replica fencing precondition**, not a distributed
compare-and-swap. When it does not match THIS daemon's current
`(epoch, revision)`, nothing is mutated and the daemon returns **409 Conflict**:

```json
{"ok":false,"error":"stale_local_version","current_version":9,"fence_token":"1779123456789:9","cas":{"scope":"local_replica"}}
```

A 409 means "this replica moved" (stale revision) or "the daemon restarted
under you" (stale epoch) — never "a peer beat you". The epoch is regenerated
when the daemon restarts, so a token captured before a restart can never
ABA-match a post-restart token even if the revision counter later reaches the
same value. Two daemons at the same token will BOTH accept, because the guard
cannot provide cross-replica exclusion. Without `fence_token`, the mutation is
unconditional (still advisory).

## Key-value stores

| Method | Endpoint | CLI | Purpose |
|---|---|---|---|
| GET | `/stores` | `x0x store list` | List stores |
| POST | `/stores` | `x0x store create <name> <topic>` | Create a store |
| POST | `/stores/:id/join` | `x0x store join <topic> --owner <hex>` or `x0x store join <topic> --policy self_keyed` | Join an existing store. An owner-anchored join REQUIRES `expected_owner` (a bare join is a 422 `owner_required`); `--policy self_keyed` is the one owner-free join and must be sent WITHOUT `--owner` (422 `owner_not_allowed` otherwise) |
| GET | `/stores/:id/keys` | `x0x store keys <store_id>` | List keys |
| PUT | `/stores/:id/:key` | `x0x store put <store_id> <key> <value>` | Put a base64 value |
| GET | `/stores/:id/:key` | `x0x store get <store_id> <key>` | Get a value |
| DELETE | `/stores/:id/:key` | `x0x store rm <store_id> <key>` | Remove a value |

### Store create request body

```json
{
  "name": "events",
  "topic": "my-app/events",
  "policy": "append_only"
}
```

`policy` is optional: `"signed"` (default) or `"append_only"`. Any other
value is a **400**. CLI: `x0x store create <name> <topic> --policy append_only`.
`GET /stores` and the create/join responses report the store's policy string.

### Store put request body

```json
{
  "value": "aGVsbG8=",
  "content_type": "text/plain"
}
```

### Store write authorization

Stores default to the `Signed` policy: only the creating agent (the owner)
may write. `PUT` and `DELETE` on `/stores/:id/:key` return **403** with
`{"ok":false,"error":"not authorized: store policy is signed; owner is <hex>"}`
when this daemon's agent is not authorized — including on a joined replica
that has not yet learned the store's authoritative owner from the
owner-signed announcement (`"not authorized: store owner unknown: ..."`).
Reads are always allowed.

### Append-only stores

A store created with `"policy": "append_only"` behaves like `Signed`
(owner-only writes) with one addition: **existing keys are immutable, even
to the owner**. `PUT` on an existing key with different content and `DELETE`
on any existing key return **409 Conflict** with
`{"ok":false,"error":"immutable key: <key> — append-only store; ..."}`.
Re-putting byte-identical content (same value and content type) is accepted
as an idempotent no-op, so retries are safe (and no new owner checkpoint is
produced). The policy is terminal: once a replica knows a store is
append-only, no owner announce or checkpoint can transition it back to
`signed`. The daemon snapshots every store's full state to
`<data_dir>/kv-stores/<store-id-hex>.bin` after each mutation (local
writes, gossip deltas, and direct-delivery deltas alike), so immutability
knowledge survives restarts; a corrupt or conflicting snapshot fails closed
at startup rather than silently starting empty. If a snapshot write FAILS,
the local write returns **500**, the delta is NOT published (durability
before announcement), the store reports `"durability_degraded": true` in
`GET /stores` and create/join responses, and further local writes are
refused until a snapshot succeeds; remote replication continues.

**Exact guarantee**: keys are immutable *after first observation by a
continuously-persistent replica*. Such a replica rejects every rewrite or
removal — including owner-signed deltas and owner-signed checkpoints. A
**fresh joiner with no prior state necessarily trusts the owner's current
signed snapshot**: signatures alone cannot prove that snapshot is the
original history rather than a rewrite, and two fresh joiners fed different
owner-signed snapshots will diverge (detectable by comparing adopted
checkpoint content roots). Applications that need fresh-joiner rewrite
detection must layer content chaining above the store (per-author sequence
numbers + previous-entry hashes) — x0x-symphony's tracker-integrity-v2 does
exactly this (saorsa-labs/x0x-symphony#10).

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

## Durable history (ADR-0023)

Local, per-daemon history store for `dm:` / `group:` / `topic:` scopes.

| Method | Endpoint | CLI | Purpose |
|---|---|---|---|
| GET | `/history` | `x0x history list <SCOPE> [--limit N]` | List durable history for one scope, keyset-paginated |
| GET | `/history/message/:msg_id` | `x0x history message <MSG_ID>` | Point lookup of one row by exposed `msg_id` (`?scope=` for canonical group ids; 404 when absent, 400 malformed) |
| GET | `/history/search` | `x0x history search <SCOPE> <QUERY>` | Full-text search over text payloads within a scope |
| GET | `/history/stats` | `x0x history stats` | Row counts, database size, retention bounds |
| DELETE | `/history` | `x0x history purge <SCOPE>` | Purge one scope from the local store (local-only) |

Rider tokens may call `GET /history` for scopes they are granted, with the
limit clamped to 100. Durable DM sends (`require_durable_app_ack: true`)
commit here before the sender's `200` (ADR-0030).

## Remote exec

Run a command on **another** agent's machine. Disabled by default; every request is authorized on the **responder** (target) daemon, not the caller. The target runs `argv` only if remote exec is enabled there, the sender is a verified `Accept`-trust contact, and the `(agent_id, machine_id)` pair + exact argv are allow-listed in its exec ACL (`docs/exec.md`). `argv` is never shell-interpreted. A denied request still returns `200` with a non-null `denial_reason` (e.g. `exec_disabled`, `unverified_sender`, `trust_rejected`, `agent_machine_not_in_acl`, `argv_not_allowed`, `cwd_not_allowed`, `shell_metachar_in_argv`) — the refusal is carried in the body, not the HTTP status.

| Method | Endpoint | CLI | Purpose |
|---|---|---|---|
| POST | `/exec/run` | `x0x exec <agent_id> [--timeout <secs>] [--stdin-file <path>] [--cwd <dir>] -- <argv...>` | Run a command on a peer (`cwd` is recorded on the wire; the remote ACL currently rejects non-empty values) |
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
| GET | `/upgrade` | — (CLI does not call this) | Daemon-side check for updates (release manifests over the `x0x/release` gossip topic; GitHub first-discovery fallback) |
| POST | `/upgrade/apply` | — (CLI does not call this) | Daemon applies the latest verified release manifest with transactional restart |

**The CLI is a separate, standalone updater.** `x0x upgrade [--check]` (and
`--apply`, which dispatches to the same standalone path — the flag does not
target the daemon) checks GitHub directly and needs **no running daemon**.
Drive the daemon-side endpoints above over REST or the GUI. See
[docs/upgrade-system.md](upgrade-system.md).

**#451 caveat:** never downgrade an owned install to v0.40.x — the old
binary cannot read the `owner_certified` policy variant and crash-loops; the
upgrade helper auto-respawns the previous binary on a failed health check.

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

> **`send_direct` over WebSocket is an internal-tier surface** (ADR 0030 §4).
> It carries none of the product fields `POST /direct/send` accepts — no
> `require_durable_app_ack`, no `logical_id` — and keeps v1 receipt semantics:
> the frame is accepted for delivery, with no durable-commit guarantee and no
> idempotency key. It shares its send configuration with the daemon's own
> control-plane traffic (welcome blobs, TreeKEM plumbing, group metadata),
> which must not inherit strict gating: those messages deliberately race
> connection establishment and would livelock under it.
>
> Product code that needs a durable receipt or at-least-once retry identity
> should use `POST /direct/send`, not this frame. This surface will be
> reclassified only if it grows the product fields.

Server → client (complete outbound frame set):

```json
{"type":"connected","session_id":"uuid","agent_id":"hex64..."}
{"type":"message","topic":"topic-a","payload":"aGVsbG8=","origin":"hex64..."}
{"type":"direct_message","sender":"hex64...","machine_id":"hex64...","payload":"aGVsbG8=","received_at":1234567890,"verified":true,"trust_decision":"Accept"}
{"type":"live","topic":"topic-a"}
{"type":"subscribed","topics":["topic-a","topic-b"]}
{"type":"unsubscribed","topics":["topic-a"]}
{"type":"mention","topic":"…","group_id":"…","msg_id":"…","author_agent_id":"hex64...","reason":"mention","mentions":["hex64..."],"timestamp":1788091402064}
{"type":"pong"}
{"type":"error","message":"..."}
```

### Outbound event reference

| `type` | Fields | Emitted when |
|---|---|---|
| `connected` | `session_id`, `agent_id` | Session registered (`/ws` and `/ws/direct`) |
| `message` | `topic`, `payload` (base64), `origin?` | Gossip arrives on a subscribed topic. Home/delegation group traffic arrives here as opaque base64 — decode `GroupPublicMessage` payloads yourself |
| `direct_message` | `sender`, `machine_id`, `payload`, `received_at`, `verified`, `trust_decision?`, `observed_origin?` | DM arrives (`/ws/direct` only; `?backfill=N` replays history rows first) |
| `live` | `topic` (`"direct"` on `/ws/direct?backfill=N`) | Backfill ended, live frames begin (ADR-0023) |
| `subscribed` / `unsubscribed` | `topics[]` | After the corresponding client command |
| `mention` | `topic`, `group_id`, `msg_id`, `author_agent_id`, `reason` (`"mention"` \| `"delegation"`), `mentions[]` (omitted when empty), `timestamp` | An ingested, validated group message names the local agent (ADR-0040). **Emitted only on the group's shared topic channel — the session must be subscribed to the group's topic; an unsubscribed `/ws` session gets nothing (routing still happens daemon-side).** A delegation carrier directed at the local agent produces the same frame with `reason: "delegation"` — there is no separate `delegation` event type |
| `pong` | — | Reply to `ping`; also the 30 s keepalive |
| `error` | `message` | Malformed command, invalid base64, publish/send failure |

**Delivery semantics.** Topic/control/error frames are best-effort and may be
dropped for a full per-session queue; DM/keepalive pressure closes the socket
with close code `1013` instead of emitting another event.

**What is deliberately *not* a WS/SSE event:** Home renames, member changes
and rekeys (REST/state-commit operations — re-fetch `GET /home` or the group
state), sync/device enrollment (REST surface — `x0x sync enroll` from the CLI), voice call signaling (DM payloads
prefixed `x0x-voice-sig-v1\n`, ADR-0042), and rider provenance (a signed field
*inside* group-message payloads). `mention` is the only Home-Suite-specific
structured push.

### SSE streams

| Stream | `event:` name | `data:` shape |
|---|---|---|
| `GET /events` | `message` | outer `{"type":"message","data":{subscription_id, topic, payload, sender?, verified, trust_level?}}` — only for active REST `/subscribe` subscriptions |
| `GET /events` | `file:offer` / `file:complete` | transfer notifications (`transfer_id`, `filename`, `size`, `sender` / `sha256`, `path`) |
| `GET /presence/events` | `presence` | `{"event":"online","agent_id","reachable"}` / `{"event":"offline","agent_id"}` |
| `GET /direct/events` | `direct_message` | flat DM row (`sender`, `machine_id`, `payload`, `received_at`, `verified`, `trust_decision?`, `observed_origin?`); `?backfill=N` first replays `history_direct_message` rows then emits `live` `{}`; 15 s keepalive is a `ping` comment |
| `GET /peers/events` | `peer-lifecycle` | `{"peer_id","event","at_ms"}` — `event` is the Debug text of the transition (`Established`, `Replaced`, `Closing`, `Closed`, `ReaderExited`); treat as open string |

## Voice (ADR-0042)

Voice has **no REST endpoints** — it is not part of the endpoint registry and
does not appear in `x0x routes`. What ships today is **point-to-point
(two-party) calls**, feature-gated behind the `voice` cargo feature:

- **Signaling** rides direct messages: payloads prefixed `x0x-voice-sig-v1\n`
  followed by the serialized `SignalingMessage`
  (`CapabilityExchange → ConnectionConfirm → ConnectionReady`). They are
  classified Ephemeral by the ADR-0023 taxonomy — control traffic, not
  conversation history — and reach an API client only as ordinary
  `direct_message` frames (opaque base64).
- **Media** ride `WebRtcV1` (0x04) byte-streams (u32-BE records), audio only.
  The unreliable-datagram lane is **opt-in** via a mutual capability advert
  exchanged over the signaling DMs; until (and unless) the peer advertises
  back, audio keeps the reliable stream. Calls inherit ordinary identity,
  trust, and ACL gates.
- **Multi-party mesh** (ADR-0042 design-bounds it at four participants), SFU,
  and browser access are recorded **ADR follow-ups**, not shipped.
- **Surface today:** the `x0x::voice` library module (adapters:
  `X0xSignaling`, `X0xLinkTransport`). There is no CLI command and no GUI
  call button yet.

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
x0x direct send <agent_id> hello --logical-id order-42   # retry-safe identity
x0x direct send <agent_id> hello --no-durable-ack        # reach a 0.37.x peer
x0x direct send <agent_id> hello --prefer-raw-quic-if-connected false  # gossip-first (pre-v0.37 behavior)
x0x direct send <agent_id> hello --prefer-raw-quic-if-connected true --raw-quic-receive-ack-ms 4000 --stop-fallback-on-raw-error
x0x direct events --backfill 20        # replay 20 stored DM rows, then live (ADR-0023 §7)
x0x ws direct --backfill 20            # same replay via the WebSocket stream URL
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
| GET | `/diagnostics/gossip` | `x0x diagnostics gossip` | PubSub drop-detection counters (publish/deliver deltas) plus Leaf/Full participation (`participation.mode`, `passthrough_refresh_runs`, C0 `relay_bytes` = non-subscribed forward, `unsubscribed_refused_frames`) |
| GET | `/diagnostics/transport` | `x0x diagnostics transport` | Transport connection accounting (zombie-connection hunt, #368) |
| GET | `/diagnostics/dm` | `x0x diagnostics dm` | Direct-message send/receive counters, per-peer health, last durable-send stage timers (`last_durable_send`), recipient ACK-publish diagnostics (`last_ack_publish_ms`, `stats.ack_publish_route_failed`) |
| GET | `/diagnostics/groups` | `x0x diagnostics groups` | Per-group ingest counters, listener state, and drop buckets |
| GET | `/diagnostics/exec` | `x0x diagnostics exec` | Remote exec counters, warnings, active sessions, and ACL summary |
| GET | `/diagnostics/connect` | `x0x diagnostics connect` | Connect-ACL policy summary and stream allow/deny counters |
| GET | `/diagnostics/ws` | `x0x diagnostics ws` | WebSocket outbound-queue health: capacity and drop/slow-consumer-close counters |
| GET | `/diagnostics/relay` | `x0x diagnostics relay` | ADR-0035 relay-decentralization metering: advert census + inbound-dialer evidence |
| GET | `/diagnostics/history` | `x0x diagnostics history` | Durable-history writer/reaper counters (ADR-0023) |

### `GET /diagnostics/groups`

Per-group counters for the public-message ingest pipeline and the sender-side write-policy gate. Each row in `groups` corresponds to a locally-known group.

Key counter fields (flattened into each group row):

| Field | Side | Meaning |
|---|---|---|
| `messages_dropped_write_policy_violation` | Receiver | Inbound public messages rejected by the ingest pipeline for write-policy reasons (e.g. `MembersOnly` author not in `members_v2`). The canary for the join-roster-propagation regression: a spike here on the owner side after a joiner posts means `members_v2` is stale. |
| `sends_rejected_write_policy` | Sender | Outgoing sends from this daemon rejected locally by a members-only write-access policy. A non-zero value means this daemon is absent from its own roster copy. Tracked separately so operators can distinguish "I cannot see joiners" from "I am missing from my own roster". |

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
