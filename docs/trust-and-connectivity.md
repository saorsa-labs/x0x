# Trust Model & Connectivity

Reference notes for `contacts.rs`, `trust.rs`, `connectivity.rs`, and the NAT
fields on `IdentityAnnouncement` / `DiscoveredAgent`.

## Trust Model (`contacts.rs`, `trust.rs`)

Each agent maintains a `ContactStore` of known peers with:

- `TrustLevel`: Blocked | Unknown | Known | Trusted
- `IdentityType`: Anonymous | Known | Trusted | Pinned
- `MachineRecord`: Tracks machine IDs an agent has been observed running on

`TrustEvaluator` evaluates `(AgentId, MachineId)` pairs against the store:
1. Blocked → `RejectBlocked`
2. `Pinned` identity type + wrong machine → `RejectMachineMismatch`
3. `Pinned` identity type + right machine → `Accept`
4. `TrustLevel::Trusted` → `Accept`
5. `TrustLevel::Known` → `AcceptWithFlag`
6. Not in store → `Unknown`

The identity listener applies trust evaluation to every incoming announcement. Blocked and machine-mismatched announcements are silently dropped.

## Connectivity (`connectivity.rs`)

`ReachabilityInfo` summarises how reachable a discovered agent is:
- `should_attempt_direct()`: true if we have at least one address AND `can_receive_direct` is not explicitly `false`. Unknown reachability still gets a direct probe.
- `needs_coordination()`: true if `can_receive_direct == Some(false)` (e.g. symmetric NAT)
- `likely_direct()`: true only when `can_receive_direct == Some(true)` — peer has verified direct inbound connectivity

`Agent::connect_to_agent(agent_id)` strategy:
1. Look up agent in discovery cache → `NotFound` if absent
2. No addresses → `Unreachable`
3. `should_attempt_direct()` → try `network.connect_addr()` for each address → `Direct(addr)` on success
4. `needs_coordination()` or direct failed → for each reachable coordinator peer: connect to coordinator, then use `network.connect_peer_via(peer_id, coordinator)` for peer-ID hole-punching (QUIC extension frames, PUNCH_ME_NOW) → `Coordinated(addr)` on success
5. All attempts failed → `Unreachable`

The coordination path uses explicit peer-ID-based NAT traversal via `connect_peer_via` (which calls `connect_to_peer(peer_id, Some(coordinator))`), not raw `connect_addr`. This triggers QUIC extension-frame hole-punching through the coordinator peer (typically a bootstrap node). MASQUE relay fallback is planned but not yet wired in ant-quic.

Successful connections enrich the bootstrap cache via `add_from_connection()`.

## Enhanced Announcements (`lib.rs`, `network.rs`)

`IdentityAnnouncement` and `DiscoveredAgent` carry four optional NAT fields:
- `nat_type: Option<String>` — e.g. "FullCone", "Symmetric", "None"
- `can_receive_direct: Option<bool>` — whether inbound connections are accepted
- `is_relay: Option<bool>` — whether the node is relaying for others
- `is_coordinator: Option<bool>` — whether the node is coordinating NAT punch timing

The sync `build_announcement()` leaves these as `None` (no network access). The async heartbeat queries `NetworkNode::node_status()` to populate them.

**Protocol note**: These fields use bincode 1.x serialization. Old→new messages will fail to decode because bincode 1.x treats every field as required. This is a deliberate protocol version bump.

## Peer Relay (`peer_relay.rs`, X0X-0070b + #193)

When a direct DM to peer `P` fails `fail_threshold` times within `fail_window`,
`P` is marked `needs_relay` and the sender wraps the (end-to-end encrypted,
origin-signed) `DmEnvelope` inside a `RelayedDm`. A relay candidate `R` verifies
the `RelayHeader` signature and forwards `inner` directly to `dst` — one hop
only, no re-wrapping.

**Default-off.** `enabled = false` ships in code; the relay path only engages
when a runtime explicitly opts in via `[peer_relay] enabled = true`.

### Forward-path hardening (#193)

Enabling the relay no longer opens an unbounded relay. The forward arm is
gated and bounded — all enforced in `PeerRelay::disposition_for`, fail-closed,
before any byte is forwarded:

| Knob (`[peer_relay]`) | Default | Refusal | Effect |
|---|---|---|---|
| `require_contact_to_relay` | `true` | `NotAContact` | Refuse to forward on behalf of any sender that is not an **explicitly-trusted** contact (`Known`/`Trusted`). A merely-discovered `Unknown` entry does **not** pass, so the gate means "my contacts", not "anyone I've seen". Set `false` only for an explicitly-open relay. |
| — (always on) | — | `Blocked` | A `Blocked` contact is refused on the forward arm **unconditionally** — even on an open relay and before rate/bandwidth caps. The operator's blocklist always wins. |
| `max_forwards_per_sender` | `10` | `RateLimited` | Per-sender forward cap over `limit_window_ms`. |
| `max_total_forwards` | `100` | `RateLimited` | Global forward cap (all senders) over `limit_window_ms` — the concurrent-forward budget. |
| `max_forward_bytes_per_window` | `1048576` (~1 MiB) | `BandwidthExceeded` | Total forwarded bytes per window. |
| `limit_window_ms` | `60000` (60 s) | — | Sliding window for the three caps above. |

The listener resolves the sender's trust level from `ContactStore` (async) per
relay frame and passes it to the sync `disposition_for`. Membership is
snapshotted per message: a contact removed/blocked mid-flight can have one
forward slip through before the next frame re-snapshots — acceptable, since the
inner `DmEnvelope` is end-to-end encrypted and origin-signed. The origin
revocation gate (PR #177) still runs after classification for both arms.

### `DeliverLocally` is not rate-limited

A relayed DM addressed to this node (`DeliverLocally`, i.e. `dst == local`) is
**receiving**, not relaying — it spends no uplink. It therefore intentionally
**bypasses** the contact gate, the Blocked gate, and all rate/bandwidth caps. It
still requires `enabled = true`, a valid `RelayHeader` signature, and freshness
(within `freshness` / clock-skew bounds), and the origin revocation gate still
applies. Inbound local-delivery is consequently **not** bounded by the knobs
above; operators who want to suppress a specific inbound sender should block or
revoke that agent.

### Observability

`RelayStatsSnapshot` exposes per-refusal-reason counters
(`relay_refused_not_a_contact`, `relay_refused_blocked`, `relay_refused_rate_limited`,
`relay_refused_bandwidth_exceeded`) plus `relay_forward_bytes` (total bytes
committed to forward) so operators can see and alert on refusals.

## Gossip-plane isolation (#206)

Co-located daemons (prod + testnet on one host) discovered each other via
ant-quic's first-party mDNS (`_ant-quic._udp.local.`, no namespace) and
auto-connected, regardless of `--no-hard-coded-bootstrap`. Every transport
connection became a gossip carrier — PlumTree eager sets are seeded from
the live connection table — so revocations and CRDT state crossed planes,
and the cross-plane peer persisted in each plane's bootstrap cache, making
the contamination survive restarts.

### The plane hello

`NetworkConfig.network_id = Some(id)` puts a node on a named gossip plane.
Every new connection (any source: mDNS auto-connect, bootstrap dial, cache
redial, inbound accept) then exchanges a one-frame plane hello
(`[0x20][len][plane_id]` on the gossip data channel; unknown to older
peers, who drop it harmlessly):

- **Matching plane** → the peer is *cleared* and becomes gossip-eligible.
- **Mismatched plane** → the peer is evicted from the bootstrap cache and
  disconnected with a `PolicyRejection` tombstone (never proactively
  redialed). Hard refusal.
- **No hello** (pre-#206 code, open-plane embedders) → the peer is held
  out of gossip sets for a 10 s legacy grace window, then admitted. This
  keeps rolling upgrades from partitioning the fleet; full isolation
  requires both sides on the new code.

Until cleared, a peer is excluded from eager sets, membership keepalives,
and CRDT sync targets, and its inbound gossip frames are dropped — the
handshake window carries no gossip in either direction. The DM bytes
(0x10/0x11) deliberately bypass the gate: direct messaging is
authenticated agent-to-agent traffic, and an agent deliberately bridging
planes is operator behaviour, not a discovery bug.

### Configuration

| TOML `network_id` | Effective plane |
|---|---|
| unset | `x0x.prod` (well-known default; prod, `x0xd-443`, and personal named instances all land here and keep meshing) |
| `""` (empty) | open — no isolation (embedders/legacy rigs that deliberately bridge) |
| any valid id | that plane, e.g. `"x0x.testnet"` |

Plane ids are ≤64 bytes of ASCII alphanumerics plus `.`, `-`, `_`
(`x0x::network::validate_plane_id`). The library default
(`NetworkConfig::default()`) is open; the daemon maps unset to
`x0x.prod`, so **planes are isolated by default once each declares its
id** — the co-located testnet needs one line in
`/etc/x0x/config-testnet.toml`:

```toml
network_id = "x0x.testnet"
```

The bootstrap peer cache is now strictly per-data-dir
(`<data_dir>/peers`); the former shared-default arm (the #189 shape) is
removed.

### Downstream (ant-quic) need

x0x cannot disable ant-quic's mDNS or set its namespace today:
`ant-quic` 0.27.33's `NodeConfig` (the API x0x uses) exposes no mDNS
knob — `MdnsConfig` (enabled / service / namespace / auto_connect) only
exists on `P2pConfig`, which `Node::with_config` fills with
`DiscoveryPolicy::current_default()` (mDNS on, `namespace: None`,
auto-connect on). The gossip-layer plane hello above is therefore the
enforcement point, and cross-plane mDNS auto-connects still happen and
are refused after one frame (small connect/refuse churn per mDNS
re-resolution). The proper downstream fix is a `NodeConfig` mDNS knob so
x0x can map `network_id` → mDNS namespace (cross-plane peers are then
never dial candidates at all) and/or disable mDNS entirely for
server-class daemons. Filed as a doc note here until an ant-quic release
ships the surface.
## Observed-Origin Token (issue #120, `connectivity.rs`, opt-in)

The transport already observes every connected peer's remote address (the same
live connection-table data `connected_peer_snapshot()` reads and
`add_from_connection()` enriches the bootstrap cache from). Issue #120 surfaces
that observation as a coarse, masked *origin token* on **point-to-point DM
surfaces only**:

```json
{ "observed_prefix": "203.0.113.0/24", "direct": true, "cgnat": false }
```

- `observed_prefix` — the observed IP with host bits zeroed at a fixed mask
  (`/24` IPv4, `/48` IPv6). Never a raw IP; no GeoIP; no new dependencies.
  Loopback/unspecified observations yield no token at all.
- `direct` — `false` marks a relayed observation (the connection is via a
  relay, per the transport's `TraversalMethod`).
- `cgnat` — the observed address is in the RFC 6598 range (100.64.0.0/10),
  reusing the existing `connectivity.rs` check.

**Default-off.** Set `observed_prefix_enabled = true` in the daemon TOML to
opt in (no CLI flag — same pattern as `[peer_relay]`). When disabled the
token is never computed and every surface is byte-identical to before.

**Surfaces** (each carries the token as an optional field, entirely absent —
not `null` — when disabled or unobserved):

- DM-receive WS (`/ws`, `/ws/direct`) and SSE (`/direct/events`)
  `direct_message` events, as `observed_origin` — populated only for
  messages that arrived over the live point-to-point transport connection
  (gossip-inbox, relay-injected, and loopback deliveries never carry it).
- Per-peer rows of `GET /diagnostics/dm`, as `observed_origin` (latest
  captured token per sender agent).

The token is **never gossiped, never announced, and never on `/peers`**: it
is populated only in the raw-QUIC DM receive path and serialized only on the
DM surfaces above.

## Persistent fork quarantine (ADR-0064, Guard A — slice 1)

Owner-axis groups (Home-suite / OwnerCertified admission — the groups whose
commits go through `seal_commit_owner_certified` and the owner head
attestation) carry a persistent, per-node fork-quarantine marker
(`fork_quarantine` on the group record, exposed via `GET /groups/:id`). The
marker is set only when a conflicting state-commit passes the authenticated
fork-evidence gate (valid signature, committer an active admin in the
retained predecessor roster — the same gate ADR-0059's deduplicated evidence
uses), and it is written in the same atomic group-store mutation as the
evidence record (through the standard `persist_named_groups_mutation`
compare-and-restore path), so it survives restarts. For owner-axis groups the
authoritative record is the `home-suite-groups.json` sidecar; the legacy
`named_groups.json` view holds a placeholder that also carries the marker.
While set, the
membership-gated routes — public send, TreeKEM encrypt/decrypt, and the
secure encrypt/open/reseal family — refuse with the typed HTTP **409
`fork_quarantined`** (counted per group in `/diagnostics/groups` as
`fork_quarantine_set` / `fork_quarantine_refusals`). The marker carries a
forensic snapshot of both conflicting commit headers (no shared secrets, no
TreeKEM material). The clear rule (round-2 maintainer decision, ADR-0064 §3
"owner anchor = owner key") is deliberately narrow — the marker clears ONLY
through an owner-anchored path, and BOTH local conditions must hold in
addition to the strictly-greater-revision requirement:

- **Explicit seal route**: the evidence-bearing seal endpoint
  (`POST /groups/:id/state/seal` → `owner_certified_seal_with_eviction`),
  AND the local install holds the **owner USER key** (the same
  `owner_key_unavailable` fence as owner-axis invite minting: key loaded and
  its derived user id equal to the policy owner — an agent-key seal carrying
  only an ADR-0038 certificate verdict is NOT an owner anchor), AND the
  sealed commit's revision is **strictly greater** than the evidenced
  revision. The shared `seal_commit_owner_certified` wrapper used by ~22
  routine mutation sites (rename, policy, add/ban/promote, …) never clears —
  routine mutations on a quarantined group leave the marker in place.
- **Tier-1 attestation-verified adoption**: across-gap adoption of a
  `MemberAdded` anchored by the owner-signed head attestation, with the
  terminal revision **strictly greater** than the evidenced revision.

A contested branch's own commits never clear it (a same-revision sibling, a
lower revision, or a seal without the owner user key all refuse); there is
deliberately no
automated eviction (ADR-0064 Decision 2). The marker is strictly local
containment state: stripped from outbound signed-public bootstrap snapshots
and rejected inbound, exactly like `invite_lineage` — a member that never
received the authenticated evidence is not contained (per-node scope,
ADR-0064 Decision 3). **Non-owner-axis groups are out of scope for this
slice**: they never receive a marker and their behaviour is byte-for-byte
unchanged; their quarantine/recovery semantics (indefinite
`quarantine_no_anchor` quarantine and the manual operator runbook) are
deferred to the ADR follow-up (#472). Mixed-fleet note: the marker is a
serde-default JSON field, so v0.41.4 binaries ignore it (and silently drop
it if they rewrite the record — a downgrade loses containment, it never
bricks).

## Owner mandate (ADR-0064, Decision §1 — slice 2, verify-if-present)

When a seating authority that holds the owner USER key seats a member through
an invite (`MemberJoined` → `MemberAdded`), it mints an **owner mandate**: an
owner-user-key signature over a preimage deterministically derived at the
pre-mutation point — the group's stable id, the authority agent, the roster
root over the authority's CURRENT roster plus the seat-write (never the
possibly-stale invite projection), the terminal revision/parent hash the
commit will chain from, the declared TreeKEM epoch, the joiner, the invite
secret's hash, and the admission certificate digest. The mandate rides the
`MemberAdded` event as an optional serde-default field (`owner_mandate`), so
older binaries simply ignore it (#451 mixed-fleet safety), and installs that
hold no owner key (the keyless tier) omit it. In this slice the mandate is
**verify-if-present** on every receiver: a present mandate that fails any
binding (signature, roster-root triple-equality against the receiver's own
re-derived candidate and the terminal commit, anchor revision/parent,
authority/joiner identity, epoch) rejects the event with the local state
byte-identical (`owner_mandate_invalid` in `/diagnostics/groups`), while an
absent mandate applies exactly as before (warned and counted as
`owner_mandate_absent`) — refusal for absence is deliberately NOT implemented
yet. Each verified mandate (or owner-countersigned InviteV4 observed at join)
records a per-authority-agent capability entry (`mandate_capability` on the
group record, local-only like `invite_lineage`) that slice 3's grace state
machine will read to decide when a mandate-capable authority's mandate-less
events must be refused. The existing post-mutation head attestation remains
the terminal CAS confirmation and now additionally requires the terminal's
TreeKEM epoch to match the mandate's declared epoch when both are present.

Preimage errata (recorded for #472; the Accepted ADR body is immutable):
 the implemented v2 preimage signs the §1a members PLUS a `version` byte,
 the `authority_agent_id`, and `issued_at_ms` — strictly stronger bindings
 the per-authority capability map (§1b) requires; every later
 implementation must diff against this v2 shape, not the §1a formula
 alone.

## Mandate grace enforcement + manual quarantine clear (ADR-0064 §1b, slice 3)

**Grace state machine (per group, per authority agent).** The capability
entries slice 2 persists (`mandate_capability` → `first_seen_ms`) drive a
derived state: an agent with NO entry is `Unknown` (never observed
capability — the keyless tier, warn-accept indefinitely, #472 decision 7);
an agent WITH an entry is `Capable` until `now ≥ first_seen_ms + grace`,
then `Refusing`. The grace window defaults to **60 days** (one release
cycle) and is configured per daemon as `[groups] mandate_grace_days`
(validated ≥ 1 at startup — 0 would refuse every capable authority's
events the moment capability is recorded, so the daemon refuses to start
on it). The clock is LOCAL wall-clock and persisted with the map; a later
valid mandate from the same agent does NOT reset it (`Refusing → Capable`
on that event, clock retained — a compromised authority cannot reset its
own window at will).

**The refusal.** An owner-axis `MemberAdded` with NO mandate whose event
actor is in the `Refusing` phase is rejected with the typed, retryable
reason `owner_mandate_missing`: the local record stays byte-identical,
nothing is queued as a revision gap, and queue admission is unaffected
(the sender-side bounded resend, or a mandate-carrying re-issue, is the
redelivery path). Counters: `owner_mandate_missing` (refused events) and
`mandate_capability_refusing_transitions` (one-shot Capable→Refusing
transitions per agent — a valid mandate restores Capable, so the next
refusal counts again) in `/diagnostics/groups`, with the per-agent
refusal totals on the capability rows. Absent mandates from `Unknown` or in-grace
`Capable` authorities keep applying with warn + `owner_mandate_absent`,
exactly as in slice 2 — non-owner-axis groups are entirely unchanged.

**Direct admin adds mint too.** Every seat path on a node holding the
owner user key mints the pre-mutation mandate: the invite-derived
`MemberJoined` handler AND the direct admin-add routes
(`POST /groups/:id/members` on both planes; the invite-secret slot in the
preimage binds the empty string's hash for direct adds). A capable
authority's own direct adds therefore never hit the refusal.

**Per-agent diagnostics.** `GET /diagnostics/groups` now exposes, per
group, `mandate_capability: [{agent_id, state: "capable"|"refusing",
first_seen_ms, refusals}]` — the derived phases under the configured
grace window plus the per-agent refused-event count
(`unknown` agents have no row; the absent map entry IS that state). The
refusal writes only these observational fields on the local-only
capability map; the COMMITTED group state stays byte-identical.

**Manual quarantine clear (#472 decision 1, r2 maintainer decision).**
`POST /groups/:id/quarantine/clear` (local API token; CLI
`x0x groups quarantine clear <id> --force --reason <REASON>`) clears the
LOCAL, per-node marker — it is never gossiped — when EITHER

- the node itself holds the owner USER key for the group (the #469 A1b
  fence): the endpoint MINTS a fresh quarantine-clear attestation over
  the group's CURRENT terminal head (revision + state hash) for this
  node's agent under the dedicated `x0x.quarantine-clear-attest.v1`
  domain — deliberately distinct from the join-attestation domain, so a
  join attestation over the same head can never clear a quarantine —
  verifies it, and clears (`cleared_by: "owner-key"`); or
- `force == true` AND a non-empty `reason` (the operator override).

Remote-owner attestation submission is OUT of scope for this endpoint:
an attestation minted on another node cannot be supplied in the body. A
keyless node asking without force gets a typed 409
(`owner_key_unavailable`); a group with no owner axis gets
`force_required`. A group with no marker (including every non-owner-axis
group, which never sets one) answers 409. Every successful clear
increments `fork_quarantine_manual_clears` and logs at info with the
reason (the audit trail; the logged reason is capped at 256 chars) and
returns the updated `fork_quarantine: null` view. The owner-key path is
owner-controlled; the force path is the documented operator escape hatch
and should name a runbook/reference in the reason.

**Clock and validation caveats.** The grace deadline uses the node's
local wall clock (the same source as `first_seen_ms`, so a node is
self-consistent); a backwards clock jump flips a `Refusing` authority
back to warn-accept until the clock recovers — accepted because both
sides of the skew fail toward the ADR-0016 checks rather than any new
attack surface, and the `refusing` PHASE itself is never persisted: it
is derived from `first_seen_ms` at read time (what persists is the
per-agent observation data — `first_seen_ms`, `refusals`, and the
episode flag — all local-only). Cost note: every refused event writes
the capability map once (one `named_groups` persist per refused event,
bounded by the stale install's event rate; the committed group state is
untouched).
`[groups] mandate_grace_days` is validated (≥ 1) only in `x0xd`'s config
loader (`load_config`, which also serves `--check`); embedded
`serve_with_options` callers construct `DaemonConfig` programmatically
and bypass the check.

## Alternate-chain classification + complete clear rule (ADR-0064, slice 4)

**The ancestor walk is shared machinery.** The per-link chain fold the
joiner adoption path has used since #458 r4 — consecutive revisions,
prev-hash linkage anchored at the base's signed hash, per-link signature
and roster/meta re-derivation, policy stability, committer an active
admin in the RECONSTRUCTED predecessor roster, last-admin invariant, and
the terminal's chaining and authority against the reconstruction — is
extracted into `x0x::groups::state_commit::validate_alternate_chain`, a
pure function over `(base, chain, terminal)`. The adoption path calls
it unchanged; the fork-evidence classifier below reuses the identical
rules. This is what makes the promoted-admin fix real: a chain that
promotes B at N+1 validates B's N+2 commit against the FOLDED roster,
never the stale base (and a member signer never passes against any
reconstruction).

**Full-member fork classification (#472 decision 3).** A conflicting
state-commit on an owner-axis group is now classified against the
retained commit log before it becomes evidence. The retained commit
whose `state_hash` equals the conflicting commit's `prev_state_hash` is
its **claimed parent** — the fork point ADR-0064 §2 walks from; the
first link is all a full member can anchor, because gossip carries no
alternate-chain fetch surface yet (issue #639 tracks it — do not fake
a chain the node cannot see):

| Classification | Condition | Outcome |
|---|---|---|
| `owner_anchored_conflict` | the commit carries an `OwnerMandate` that **anchors** its exact header (owner USER-key signature over the terminal revision/parent/roster-root/policy/meta; `OwnerMandate::anchors_commit` under the owner key derived from committed roster certificates) AND chains consecutively through retained ancestry, at a revision strictly greater than the evidence | evidence + quarantine marker with `classification: "owner_anchored_conflict"` — the owner anchored a successor this node CANNOT apply (it holds the disowned sibling); **the conflict path never clears** (r2, ADR §3) |
| `signer_only` | the signer was an ACTIVE ADMIN at the claimed parent (or, for a joiner whose adoption was refused, the served chain walked clean from the joiner's base) but no owner anchor is reachable | evidence + quarantine marker; `classification: "signer_only"` on the forensic snapshot |
| `unauthorized_signer` | the signer held a seat somewhere in the retained history but NOT active-admin at the claimed parent — an admin removed by the very commit the fork chains from, or a plain member signer | evidence + quarantine marker; `classification: "unauthorized_signer"` |
| unauthenticated | the signature/structure fails, or the signer is unknown to the ENTIRE retained log | never evidence (the slice-1 invariant: an unauthenticated conflict cannot contain the node) |
| degraded | the claimed parent is not retained (the fork chains from history this node never held) | the pre-slice-4 revision−1 retained-predecessor check decides, with no label |

The owner-anchor evaluation runs BEFORE the stored-evidence silence
gate so an anchored conflicting commit is always classified, and every
verifying anchor counts the attributable
`fork_quarantine_owner_anchored_refusals` — r2 (ADR §3): the CONFLICT
path never clears. A marker clears ONLY when this node APPLIES an
owner-anchored commit at strictly greater revision (see below);
clearing on a conflicting anchored successor would un-gate a node that
still holds the disowned sibling, and the next canonical commit would
re-quarantine the same divergence. An anchor that additionally fails
the ancestry or strictly-greater fence (the contested branch
publishing an owner-anchored N+3 from its own head) records nothing at
all — the counter alone is the probe signal, never a silent chain
failure. Counters `fork_evidence_signer_only` /
`fork_evidence_unauthorized_signer` /
`fork_quarantine_owner_anchored_clears` ride `/diagnostics/groups`.
Joiners whose tier-1 adoption was refused (the #468 stale-removal
shape: a removed admin serving its own walk-perfect chain with no owner
head attestation) run the walk over the SERVED chain and quarantine on
the walk-authenticated evidence with the `signer_only` label — the
joiner stays pending. A served chain that does not validate from the
base records nothing. Non-owner-axis groups keep the pre-slice-4
evaluation byte-for-byte.

**The complete clear rule.** The marker clears through owner-anchored
paths ONLY, and every one of them clears on a commit this node APPLIES
at a revision strictly greater than the evidence (r2, ADR §3 — a
same-revision sibling, the contested branch itself, can never clear,
and neither can a conflicting successor however well anchored):

- the explicit seal route with the owner USER key and strictly greater
  revision (slice 1 r2) — now INCLUDING its eviction arm: an explicit
  seal that evicted failing members clears under exactly the same fence
  (before slice 4 an evicting seal left the marker until the next
  seal; r2 additionally moved the clear INSIDE the persist transaction
  so a non-durable clear answers 503 with the marker intact in memory
  and on disk);
- tier-1 attestation-verified adoption at strictly greater revision
  (slice 1 r2);
- **a mandate-carrying `MemberAdded` whose `OwnerMandate` verifies** —
  the ADR's "owner-anchored commit" is not only a seal: on the APPLY
  path (gapless or walked adoption, so retained ancestry holds by
  construction) it clears at strictly greater revision;
- the manual endpoint (slice 3).

EVERY clear re-arms the stored fork-evidence silence gate
(`invite_lineage.fork_evidence` is reset with the marker): containment
is no longer one-shot per group per node — after a clear, the next
authenticated conflict re-evaluates, re-installs evidence, and
re-quarantines. The in-process once-only diagnostics remain
identity-keyed, so a genuinely new fork identity still fires its warn.

**Sidecar mirroring (#472 decision 6).** For owner-axis groups the
quarantine marker AND the `mandate_capability` map were ALREADY carried
by the `home-suite-groups.json` sidecar — the authoritative record —
through the pre-existing #451 split write (sidecar first, the
`named_groups.json` placeholder second, #471 rollback restoring the
sidecar) with serde-default fields since slices 1–2; the load path
merges sidecar-wins for owner-axis groups, so an old (or downgraded)
binary rewriting `named_groups.json` alone — dropping fields it does
not know — can never drop containment or the grace clocks. Slice 4
PINS that guarantee by test. Caveat: the protection covers legacy-view
rewrites only — an OLD SIDECAR-AWARE binary that rewrites the SIDECAR
itself (not just the placeholder) drops both fields from the
authoritative record; a downgrade across a sidecar-aware version loses
containment exactly as the ADR's migration table accepts ("never
bricks").
