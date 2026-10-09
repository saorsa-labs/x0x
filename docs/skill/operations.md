# Operations

Relay, self-update, diagnostics, troubleshooting, and configuration.

## 7. Operations

### 7.1 Relay & bootstraps

Relay is an application-level fallback for DMs that cannot hole-punch (ADR-0035). `x0xd --relay` marks a daemon as a relay candidate: Full participation + capability advertisement. The relay header v2 (`digest_support`, #445) binds the RelayHeader to the inner payload — substituted-payload relays are refused, downgrades are TTL-bounded.

```bash
x0xd --relay                        # offer relay service (needs Full participation, not Leaf)
curl "http://$API/diagnostics/relay" -H "Authorization: Bearer $TOKEN"   # advert census + dialer evidence
```

Bootstrap peers: 6 global nodes by default; override with `bootstrap_peers = [...]` in the config TOML (`[]` = none) or `--no-hard-coded-bootstrap` to drop only the embedded list. `x0x network status` / `network cache` cover connectivity and the peer cache.

### 7.2 Self-update

```bash
curl "http://$API/upgrade" -H "Authorization: Bearer $TOKEN"           # DAEMON surface: GET /upgrade (check)
curl -X POST "http://$API/upgrade/apply" -H "Authorization: Bearer $TOKEN"   # USE THIS to upgrade a running daemon
x0x upgrade --check                 # standalone CLI check only (no daemon involved)
```

`x0x upgrade`, `x0x upgrade --apply`, and `x0x upgrade --force` refuse installation and direct callers to authenticated `POST /upgrade/apply`. This also applies when no daemon is running: the CLI cannot prove that no other instance is using the installed binary. `x0x upgrade --check` remains a standalone, read-only GitHub release check; `--check --force` fetches the current manifest regardless of version.

The daemon REST surface owns installation and restart and is governed by the daemon config. `[update] enabled = false` disables the daemon side (`GET /upgrade` → `{"update_available":false,"reason":"updates disabled"}`). `--skip-update-check` also disables the process's self-update install/restart paths, including `POST /upgrade/apply` (which returns `"self-update disabled for this process"`); both it and `[update] enabled` must allow an apply. Verified-release manifests only. See [docs/upgrade-system.md](https://github.com/saorsa-labs/x0x/blob/main/docs/upgrade-system.md).

> ℹ️ **Downgrade safety (#451, fixed in v0.41.0):** Home state now lives in a sidecar; a v0.40.x binary reads the legacy store and starts cleanly, so a failed upgrade that respawns the previous binary no longer crash-loops. Still back up the data dir before upgrading an owned install, and expect Home features to be absent while downgraded.

### 7.3 Diagnostics

```bash
x0x diagnostics <area>              # connectivity|ack|gossip|transport|relay|dm|groups|history|connect|ws|exec
x0x peer probe|health|events        # per-peer liveness, health snapshot, SSE lifecycle
x0x network status                  # NAT type, external addrs, direct capability
```

The complete read-only snapshot inventory is `/diagnostics/connectivity`
(NodeStatus: UPnP, NAT, relay, mDNS), `/diagnostics/ack` (ACK-v2 latency
buckets), `/diagnostics/gossip` (drop detection and participation),
`/diagnostics/transport` (connection accounting), `/diagnostics/relay` (ADR-0035
metering), `/diagnostics/dm` (DM counters and per-peer state),
`/diagnostics/groups` (ingest and drop buckets; ADR-0064 fork-quarantine and owner-mandate counters, plus per-agent `mandate_capability` rows — see the [fork quarantine runbook](https://github.com/saorsa-labs/x0x/blob/main/docs/runbooks/fork-quarantine.md)), `/diagnostics/history`
(writer/reaper), `/diagnostics/connect` (ACL allow/deny),
`/diagnostics/ws` (outbound-queue health), and `/diagnostics/exec` (counters
and ACL summary).

The three routes detailed below are `GET` with no request body and require the
normal local bearer token. They return snapshots, not SLAs or proof that a peer
is reachable; a node that has not initialized the relevant runtime returns 503
with `{"ok":false,"error":"..."}`.

- `/diagnostics/ack` returns `{"ok":true,"ack":{...}}` (503 `network not
  initialized` or `ACK diagnostics unavailable`). The `ack` object is the
  ant-quic ACK-v2 per-stage latency/outcome snapshot; its bucket and counter
  names are versioned by the installed ant-quic dependency.
- `/diagnostics/gossip` returns `{"ok":true,"stats":{...},...}`. `stats`
  contains publish/receive/decode/delivery/drop and in-flight deltas; the
  envelope also includes `participation`, `subscribed_topics`,
  `outbound_by_topic_named`, `egress_budget`, `outer_signature_policy`,
  `legacy_grants_enabled` (currently `false`), `outer_v1_receipts`,
  `gossip_publish_zero_fanout`, `pubsub_stages`, `dispatcher`, `recv_pump`,
  and `discovery_cache_entries` (`agents`, `machines`, `users`). For soak
  baselines it also carries `uptime_secs`, `inner_envelope_verify`
  (`count`, `failed`, `total_ns`: cumulative inner-envelope ML-DSA-65
  verifies) and, per `dispatcher` lane, `over_100ms_count`. The route
  returns 503 `gossip runtime not initialized` when gossip has no snapshot.
- `/diagnostics/transport` returns `{"ok":true,"transport":{...}}` (503
  `network node not initialized`). The transport object includes active versus
  x0x-visible connections, `peer_entries` (`peer_id`, `remote_addr`), successful
  and failed establishments, NAT/direct/relayed counters, bootstrap totals,
  churn and connection-pool/read-pump counters such as open connections,
  buffered bytes, and orphan closures.

Use the [full API reference](https://github.com/saorsa-labs/x0x/blob/main/docs/api-reference.md#diagnostics) for the route table and the versioned field context; do not interpret a non-zero counter alone as a failure.

### 7.4 Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Second device can't join owner's Home (`no agent certificate resolved` / `pending`) | a BODYLESS announce publishes the anonymous digest, which the owner can never resolve (#447 single-announce admission is fixed in v0.41.0) | `POST /announce` with `{"include_user_identity":true,"human_consent":true}` (repeat after any daemon restart — consent is not persisted), then `x0x group join --home --owner <owner-user-id> <invite>`; a `pending` join clears once the joiner's owner-issued certificate reaches the Home authority and the committed add reaches the joiner |
| Two Homes for one owner | this device holds a Home that lost the `("home")` election — `GET /home` shows `state:"adoption_pending"` and names `canonical_group_id` | on the device holding the canonical Home, as the human with the durable token: `x0x home seat <this device's agent id>`, then on this device `x0x group join <invite> --home --owner <owner_user_id>`. The local Home stays usable meanwhile. Duplicates are read-only inventory (`retirement:"manual_only"`) — do NOT delete one, an empty `evidence_against_deletion` is not a safe-delete signal |
| Strict (durable-ack) DM → 409 `recipient_ack_semantics_unavailable` | no current usable signed, machine-bound v2 advert for the recipient after one refresh (missing/unconverged, expired, v1-only, gossip-unready, bad machine binding); v0.40.x peers interoperate via frozen v1 adverts (#448 fixed); no auto-fallback | retry later, or resend with `require_durable_app_ack:false` (v1 best-effort) |
| Peer rejects your agent card | #450: ownerless cards interoperate with v0.40.x; owner-named v2 cards are rejected by pre-ADR-0036 peers by design | upgrade the verifying peer |
| Daemon downgraded to v0.40.x on an owned install | #451 fixed in v0.41.0: the legacy store is readable, Home state waits in the sidecar | expected; Home features return on re-upgrade — keep a data-dir backup before upgrading |
| `403 rider tokens are denied on this route` | deny-by-default rider scope (ADR-0039) | use a granted surface (`groups/:id/send`, `secure/encrypt`, `GET /history`) or act as the owner |
| `403 ... Home must be delegated explicitly` | rider token's `groups` list lacks the Home gid (no implicit grant) | re-mint the token with the Home group id in `groups` (and in the signed capability) |
| `409` on `/owner/*` or `/sync/*` | install has no owner key | `x0x user-id create`, restart daemon |
| `404 no placement record cached` on `GET /owner/agents/:id/placement` (even ownerless) | the route is durable-owner gated (`403` for a session token), but after auth it performs no owner-key/mint-presence check — it only reads the cached placement record, which exists after the lazy mint / a seen bundle, on owned and ownerless installs alike | create the owner key where THIS daemon loads it, restart, then run the lazy mint before retrying: default install `x0x user-id create` (`~/.x0x/user.key`); named instance `x0x --name <name> user-id create` (`~/.x0x-<name>/user.key`) and keep `--name <name>` on every later command; daemon configured with `user_key_path`/`identity_dir` needs the explicit path (`x0x user-id create <user_key_path>` or `<identity_dir>/user.key` — it never falls back to `~/.x0x`). Then `x0x owner placement` (the lazy mint happens only on that route's first read — creating the key alone records nothing), then retry |
| `501` on `/agent/move*` | ceremony gated off in v1 | leave it off; placements don't move (founding Home agent is nominally Roaming, inert) |
| Join then immediate post → `403 members-only` | membership commits asynchronously | poll `GET /groups/<gid>/members` until your id is `active` |
| `sub-agent lacks the required roster role` | rider scope granted but sub-agent not a member | add the sub-agent to the group (TreeKEM adds need its key package) |
| `recipient_ack_semantics_unavailable` (same fleet) | peer's capability advert not cached yet | the daemon publishes ONE bounded capability refresh before refusing — if the 409 still comes back, YOU retry the send (it is not retried for you); check `/diagnostics/dm` |
| **409 `fork_quarantined`** on group send / secure / TreeKEM routes — **ADR-0066 §5: match `body["reason"]`, NOT `body["error"]`** (`error` is now a human sentence; the old literal `error == "fork_quarantined"` is a one-time break, `ok:false` + 409 unchanged), and the body carries `fork_quarantine.{revision,observed_at_ms,no_anchor,clear_with}` | ADR-0064/ADR-0066 §2: this node holds authenticated fork evidence for the group (ordinary groups too, with `no_anchor: true` — nothing clears those automatically) (persistent per-node marker on `GET /groups/:id`; snapshot `classification` names `owner_anchored_conflict` / `signer_only` / `unauthorized_signer`) | read the `error` sentence — it names the clearing path that actually works for that group; let the owner anchor advance past the evidence revision (adoption, mandate-carrying apply, or an explicit owner-key `state/seal`), or run the manual clear per the [fork quarantine runbook](https://github.com/saorsa-labs/x0x/blob/main/docs/runbooks/fork-quarantine.md) — `x0x groups quarantine clear <id>` on the owner-key node, else `--force --reason`; every clear re-arms, so resolve the divergence, don't just force |
| **409 `owner_mandate_missing`** on a group event (retryable) | ADR-0064 §1b: post-grace absent mandate from an authority agent whose capability was observed (`mandate_capability` rows on `/diagnostics/groups`: `state:"refusing"`, `first_seen_ms`, `refusals`) | fix the AUTHORITY — it needs the group's owner user key to mint mandates (upgrade/re-key it); then retry; never-observed (keyless) authorities warn-accept and never hit this |

### 7.5 Configuration (TOML) & storage

```toml
bind_address = "0.0.0.0:0"           # QUIC port (0 = random)
api_address = "127.0.0.1:12700"      # REST API (loopback by default — see [SKILL.md](../../SKILL.md) §1.3 before binding wider)
log_level = "info"                    # trace|debug|info|warn|error
log_format = "text"                   # text|json
bootstrap_peers = []                  # unset = the 6 global bootstraps; [] = none
heartbeat_interval_secs = 300         # re-announce identity
identity_ttl_secs = 900               # expire stale discoveries
rendezvous_enabled = true             # global findability
network_id = "x0x.prod"               # gossip plane isolation ("" = open)
port_mapping_enabled = true           # UPnP IGD mapping
mdns_enabled = true                   # ant-quic LAN discovery + auto-connect.
                                      # false = hermetic (no LAN advertise/browse);
                                      # network_id only NAMESPACES mDNS, it does not
                                      # disable it. Test fixtures set false.
observed_prefix_enabled = false       # masked origin prefix on DM surfaces
# identity_dir = "/srv/x0x/identity"  # keep ALL identity material (machine.key, agent.key, agent.cert,
#                                     # and the opt-in user.key lookup) out of ~/.x0x — with this set the
#                                     # daemon never falls back to ~/.x0x (the embedding storage boundary)
# user_key_path = "/srv/x0x/user.key" # explicit owner key file (opt-in; never auto-generated).
#                                     # Overrides <identity_dir>/user.key when both are set
# zero_peer_restart_secs = 600        # TOP-LEVEL KEY (keep it ABOVE the first [section] or it
#                                     # lands in the wrong table!). SUPERVISOR-ONLY (systemd
#                                     # Restart=always): exit at zero peers so the supervisor
#                                     # restarts us. Default OFF; unsupervised, it just dies.

[update]                              # daemon self-update (the CLI updater is separate — §7.2)
enabled = true

[history]                             # ADR-0023 durable local history
enabled = true                        # db at <data_dir>/history.db

[gossip]                              # overlay tuning

[peer_relay]                          # DM relay fallback (opt-in)
enabled = false
candidates = []                       # relay-candidate hex agent ids

[key_move]                            # ADR-0043 roaming moves — experimental; 501 while false
ceremony_enabled = false

[groups]                              # ADR-0064 owner-mandate enforcement
mandate_grace_days = 60               # grace before a recorded-capable authority's mandate-less
                                      # MemberAdded is refused (owner_mandate_missing). Default 60
                                      # (one release cycle); validated >= 1 — x0xd refuses to start on 0.

```

```
~/.x0x/machine.key machine · agent.key agent · user.key owner (opt) · owner.json owner singleton
            (all relocated by `identity_dir`; `user_key_path` relocates the owner key + its sibling owner.json)
~/.x0x-skilltest/... named instances: ~/.x0x-<name>/
<data_dir>/ api.port · api-token · contacts.json · history.db · mls_groups.bin · named_groups.json
            home.json (Home marker) · owner-cert-journal.jsonl · rider-tokens.json (hashed) · peers/bootstrap_cache.json
Default data_dir: Linux ~/.local/share/x0x/ · macOS ~/Library/Application Support/x0x/ · named: -<name> suffix
```

### 7.6 Error responses

```
400 Bad Request    {"ok":false,"error":"invalid hex: ..."}     # your input is wrong
401 Unauthorized   {"error":"missing or invalid Authorization: Bearer token"}
403 Forbidden      {"error":"agent is blocked"} / rider deny-by-default
404 Not Found      {"ok":false,"error":"group not found"}
409 Conflict       {"ok":false,"error":...}   # no owner key; typed DM refusal; join races
422 Unprocessable  owner_required (unanchored Signed-store join) etc.
501 Not Implemented ceremony gated off ([key_move] ceremony_enabled = false)
```

Back to [SKILL.md](../../SKILL.md).
