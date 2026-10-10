# Owner, Home, and riders

Home seating, sub-agents, rider limits, and session tokens. Install, the first direct message, a group join, and a scratch write stay in [SKILL.md](../../SKILL.md).

## 3. Acting on Behalf of Your Owner

### 3.1 Home — the owner's space (ADR-0038)

An owned install provisions one **Home** at first daemon start, but only when it can and should: it needs both a live owner key and a builder-issued agent certificate, and it yields without creating one if another of the owner's devices has already advertised a Home (that device then reports `state:"elsewhere"`). An un-synced or first device still provisions, so an offline install is never left without a Home. When it does provision:

- Policy: `Hidden + OwnerCertified(owner) + MlsEncrypted + MembersOnly/MembersOnly`.
- **`GroupAdmission::OwnerCertified(UserId)`**: a joiner is admitted ONLY with a valid, unexpired `AgentCertificate` chaining to the Home's owner — verified at invite-accept **and re-verified at every state-commit seal**, so a leaked invite or compromised admin cannot admit another human. Admin role is inert here; enforcement is cryptographic.
- Membership = the owner's agents only. The owner speaks through the **primary agent** (the founding member); group messages stay agent-signed.

```bash
x0x home                                       # group id, primary agent, members, warnings
curl "http://$API/home" -H "Authorization: Bearer $TOKEN"
x0x home rename "David's Home"                 # renamable (sealed state update)
```

Home always keeps ≥1 agent placed `Roaming` so it is *designed* to follow the user across machines — nominal in v1 while the move ceremony is gated off ([SKILL.md](../../SKILL.md) §5.2).

**Second owner device joining the Home (#447, fixed in v0.41.0).** On the new device, run `POST /announce` **with body** `{"include_user_identity":true,"human_consent":true}` before joining, **and again after every restart of that daemon** (including a self-update restart: the consent is not persisted, so the daemon falls back to the anonymous announce until the human consents again) — a bodyless announce publishes the ANONYMOUS cert digest, which the owner can never resolve. Then join with `x0x group join --home --owner <owner-user-id> <invite>` (the owner id is shown by `x0x home`); the certified join is admitted from that single announce, and a join that arrives before the certificate is visible stays in a typed `pending` state instead of wedging. Uncertified joiners holding a stolen invite are always rejected — the gate fails closed.

**A pending join lives in memory only.** Until the joiner observes its own
`MemberAdded` commit from the Home authority, the join is a stub that is
*not* written to `named_groups.json` (an unconfirmed join must never be
recorded as durable). If the joining daemon restarts before that commit
arrives, the pending join is gone. Do not replay the same link: the invite's
one-time secret is consumed when the **authority validates the first
`MemberJoined`** — after that, a replay fails `invite_secret_consumed`; if
the authority has NOT validated it yet (event still in flight, or the
authority itself restarted first) the secret is not yet burned, and a replay
by an already-active member is refused earlier as an idempotent no-op
rather than with a consumed-secret error. In every case the replay proves
nothing about YOUR join — mint a **fresh** invite on the owner
(`POST /groups/<home-gid>/invite`) and join again.

**One Home per owner, elected — and seating a second device is a human act (#449, ADR-0060).** The owner's Home is the Tier-1 `("home")` register winner, not a per-install artifact. `GET /home` reports which Home this device actually serves — **three `200` shapes plus two `404`s**:

| Answer | Meaning |
|---|---|
| `200 state:"local"` | this device holds the canonical Home (or is uncontested) — full payload |
| `200 state:"adoption_pending"` | this device holds a Home that LOST the election; still usable until seated in `canonical_group_id`. Full payload **plus `next_step`** |
| `200 state:"elsewhere"` | the owner's Home is on another device and this one is not a member. **Short** body (`owner_user_id`, `canonical_group_id`, `local_group_id`, `detail`, `next_step`) with no `group_id`/`members`/`duplicates`/`warnings` |
| `404 no Home provisioned (un-owned install)` | no user key is loaded on this device at all |
| `404 no Home provisioned` | owned, but no Home this device can see |

`"elsewhere"` is deliberately a `200`, not a `404` — answering `404` there is what let a second device look Home-less and quietly provision a duplicate. `next_step` is carried on **both** `adoption_pending` and `elsewhere`, never on `local`.

Seating is **owner-driven and never inferred**. Run it on the device that holds the canonical Home:

Before seating works, the joining device must already be **owned by the same owner**. Home admission is `GroupAdmission::OwnerCertified(UserId)`, so the joiner needs a current certificate chaining to this Home's owner; an install with a different owner id can never be admitted.

That setup is human-managed and documented in the README's [*Add a second device*](https://github.com/saorsa-labs/x0x/blob/main/README.md#quickstart) step: put the **same** user key on the new machine, either by re-deriving it from the 32-byte seed (`x0x user-id create <path> --from-seed <HEX>` — same seed, same `UserId` on any machine) or by copying the `user.key` file yourself. A plain `x0x user-id create` with no seed generates a **random** key and therefore a different owner. The seed and the key file are yours to hold and move; the daemon never fetches either, and no agent can retrieve them for you. If your existing key was generated randomly, there is no seed to recover — copy the file.

Then, on the seating device:

- read the joining device's agent id there with `x0x agent` (it must be a different agent);
- use the **durable** `api-token` from the canonical device's data dir ([Operations](operations.md)), not a session token.

`x0x home seat` mints an invite and nothing more: it does not copy keys, enroll machines, issue certificates, or deliver the invite. Owner keys are never auto-generated or auto-rotated — replacing one is the explicit `x0x user-id create --rotate-owner` ([SKILL.md](../../SKILL.md) §2).

```bash
# On the CANONICAL device, as the human, with the DURABLE token (not a session token):
x0x home seat <64-lowercase-hex agent id of the OTHER device>
```

- Requires the **durable owner token** — a session token a harness holds gets `403`. The human authorizes on the canonical device.
- The `agent_id` must be a **different** agent; passing this daemon's own id is refused (it already holds the seat).
- Run on a losing or Home-less device it refuses with a typed conflict (`adoption_pending` / `elsewhere` / `unknown`) naming where to run instead.
- It mints an **addressed** invite (`intended_joiner` bound to that one agent) and returns `owner_user_id` plus a `join_hint`. The response carries **`"seated": false`** — a mint is an OFFER, not a seat.
- The named device then joins with the **owner pin explicitly set**: `x0x group join <invite> --home --owner <owner_user_id>`. An unpinned Home join can be answered by any group.

Adoption is only complete once that join is accepted and the joiner observes its own `MemberAdded`; a `pending` join is in-memory only and does not survive a restart (see the paragraph above). **A `200` from `x0x home seat` is not completion, and neither is a `pending` join — the durable proof is the joiner still seated after a restart.**

Duplicate Homes are listed read-only under `duplicates` in `GET /home`, with `retirement: "manual_only"` and `evidence_against_deletion`. **Automatic retirement is not implemented, and an empty blocker list is not permission to delete** — nothing infers that a duplicate is safe to remove.

Not yet runtime-accepted: #449 stays open until the seating command is shipped, reviewed and proven at runtime. No multi-device convergence claim is made here.

### 3.2 Sub-agents via the harness (ADR-0039)

Two hosting modes over one owner-issued identity — the owner key certifies a fresh keypair generated and custodied by the harness (the daemon never sees the secret):

- **ACP-attached** — the harness process owns the key (`~/.saorsa-keys/` pattern) and runs as its own daemon/library instance. Always `Pinned` to its machine.
- **API-key rider** — the harness calls the owner's daemon REST API with a scoped rider token; the daemon signs as the registered sub-agent and stamps cryptographic provenance on every send.

**Register a sub-agent** (works for both modes):

```bash
# harness generates the keypair, passes only the PUBLIC key:
x0x owner agents issue <PUBLIC_KEY_HEX> --mode rider --label "my-sub-agent"
curl -X POST "http://$API/owner/agents/issue" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"agent_public_key":"<hex ML-DSA-65 public key>","mode":"rider","label":"my-sub-agent"}'
# -> {agent_id, certificate:{storage_b64,...}}   (certificate returned for ACP-attached instances)
```

**Mint a rider token** — REST or CLI. Both carry the harness-signed delegation capability (minting without it answers `400 delegation is required…`):

```bash
# harness signs rider_delegation_bytes(sub_agent_id, daemon_agent_id, groups, not_after) with the sub key
# (helper: x0x::groups::sign_rider_delegation in the Rust crate), then the owner mints —
x0x owner riders issue <AGENT_ID> --group <gid> --group <home_gid> \
    --delegation-payload-b64 <base64> --delegation-signature <hex>   # both flags required (clap-enforced)
curl -X POST "http://$API/owner/riders" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"sub_agent_id":"<64-hex>","groups":["<gid>","<home_gid>"],"ttl_secs":604800,
       "delegation":{"payload_b64":"<base64>","signature":"<hex>"}}'
# -> {token, token_id, expires_at_unix} — token is stored hashed, lives ≤90 days, default 7
```

`groups` is the rider's COMPLETE grant list — **there is no implicit Home grant**: to let a rider reach the Home space you must list the Home group id explicitly (it is delegated like any other group, or not reachable at all). The delegation capability you sign must cover exactly the same scopes. Max 32 granted groups.

### 3.3 What a rider CAN and CANNOT do

Rider tokens are **deny-by-default**: every route not listed returns **403** before any handler runs.

| A rider token CAN | A rider token CANNOT (403) |
|---|---|
| `POST /groups/:id/send` — SignedPublic groups in its grant list | `/agent/sign`, `/agent/verify`-write paths |
| `POST /groups/:id/secure/encrypt` — MlsEncrypted groups in its grant list (Home only if its gid was granted explicitly) | `/exec/*` (never an exec oracle) |
| `GET /history` — granted `group:` scopes only, limit clamped to 100 | `/owner/*`, `/identity/*`, `/sync/*` |
| | `/announce`, `/home/rename`, `/shutdown`, all diagnostics/admin |

Rider sends are signed by the daemon's key but carry a provenance envelope **inside the signed bytes** (sub_agent_id, token id/hash, scope, and the sub-agent-signed delegation capability, ~10 KB) — receivers verify the embedded owner certificate and capability signature, then enforce policy against the **sub-agent**. A daemon can only speak for sub-agents that explicitly authorized it. For Home (`MlsEncrypted`/TreeKEM) the sub-agent must also hold a roster role; TreeKEM member adds need a `treekem_key_package_b64` from the target (an ACP-attached instance provides one).

**Lifecycle:** revoke a token (`DELETE /owner/riders/:id`) → it fails on the next request, no restart. Revoke the sub-agent (`DELETE /owner/agents/:id`, ADR-0018 issuer revocation) → its tokens die too and the roster shows `revoked: true`.

### 3.4 Durable token vs session token — and issue #446

- **Durable API token** (`<data_dir>/api-token`) — full control plane including owner acts. Keep it secret; never in a URL.
- **Session token** — mint via `POST /auth/session` (`{"session_token":"...","expires_in":600}`); accepted as a bearer everywhere and in `?token=` on browser endpoints. Intended as a read-mostly browser credential.

> ℹ️ **Owner-act fence (#446, fixed in v0.41.0):** session tokens are refused on the owner-act surfaces — `/agent/sign`, `POST /exec/run` and `/exec/cancel`, `/shutdown`, `/upgrade/apply`, `/sync/devices/enroll` and `DELETE /sync/devices/:id`, `POST /groups/:id/delegate`, `/home/rename`, `/announce` with `include_user_identity=true`, exec-prefixed payloads on `POST /direct/send` and WebSocket `send_direct`, and the administrative control-plane mutators of the Home or any OwnerCertified group (invites, roles, removals, policy, rename, delegation — not per-member display names). Perform owner acts with the durable token; still treat session tokens as secrets and never paste one into pages or logs.

Back to [SKILL.md](../../SKILL.md).
