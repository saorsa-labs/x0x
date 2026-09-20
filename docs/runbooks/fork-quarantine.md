# Fork-Quarantine Operator Runbook

> ADR-0066 (Accepted) · ADR-0067 (Accepted) · slice 8 — runbook and ops docs
>
> This file supersedes the slice 1–7 patchwork. Symbols verified at commit
> bb77a61 (see Appendix A), plus the #732 resolver-unification change that
> closed gaps (d) and (e); line numbers kept only where no named symbol exists.

Operator procedures for the persistent fork-quarantine marker and the owner
mandate grace machinery. Everything here is **LOCAL, per-node state**: a marker
on this daemon says this daemon holds authenticated evidence of a conflicting
group state chain; it is never gossiped, and a member that never received the
evidence has no marker and is not contained (ADR-0064 Decision §3). Design
context: [`docs/trust-and-connectivity.md`](../trust-and-connectivity.md),
[ADR-0064](../adr/0064-owner-anchored-fork-authority.md),
[ADR-0066](../adr/0066-ordinary-group-fork-anchors-and-data-plane-quarantine-coverage.md),
[ADR-0067](../adr/0067-lifecycle-epoch-token-is-derived-marker-identity.md),
issues #468/#469/#472/#732.

---

## 1. What fork quarantine is

A **fork-quarantine marker** is installed when this node applies and retains
authenticated fork evidence: a conflicting state-commit whose signature verifies
and whose committer was an Active Admin in the retained predecessor roster — the
same deduplicated gate ADR-0059 uses. The marker says "this daemon holds evidence
that the group's commit chain has branched"; it is containment, not a verdict.

Containment scope (inherited from ADR-0064, unchanged):
- **Per-node and local-only.** A marker on this daemon says nothing about any
  other daemon. Another node that never received the conflicting commit has no
  marker and serves the group normally.
- **No fleet-wide propagation.** Nothing here makes a marker travel.
- **No automated eviction.** The membership-event ingest path is deliberately
  NOT gated — the anchored clearing commit must still be able to arrive.

### Owner-axis groups vs ordinary (`no_anchor`) groups

**Owner-axis groups** have an `OwnerCertified` admission policy and carry an
owner key. Their markers auto-clear when an owner-anchored commit advances the
chain past the evidenced revision (see §4.1–4.2).

**Ordinary groups** (the majority population) have no owner key by construction.
ADR-0066 §2 extends the persistent marker to them; the marker carries
`no_anchor: true` on the `GroupInfo` record. **Nothing auto-clears a `no_anchor`
marker.** The only exit is the manual clear endpoint (§4.3). This is accepted
design (R1/R5): a founder-key anchor was rejected because a compromised founder
key would be an unreviewable eviction oracle; a quorum anchor was rejected because
a two-member group's quorum is the attacker.

**The blunt operational truth (R1/R5, ADR-0066 Consequences):** a current admin's
signed conflicting commit quarantines an ordinary group on every node that receives
it — permanently, until a human runs the manual clear on each of those nodes. The
trigger does not ask whether the admin was malicious or merely partitioned; it asks
only that the committer held an active admin seat. A benign network split that
produces authenticated conflicting commits strands the group. That is the accepted
cost; the §5 refusal message (§3.1) is the mitigation — not a delay, an
explanation the operator can act on.

---

## 2. How a marker gets installed

The install path is `fork_quarantine_for_evidence`
(`named_groups.rs::install_fork_evidence` — the former early-return fence for
owner-axis-only is removed by ADR-0066 §2 / slice 2). Evidence must pass
`evaluate_fork_evidence_candidate` and the ADR-0059 dedup gate before the marker
is written.

1. A conflicting state-commit arrives through the live apply path
   (`named_groups.rs::apply_named_group_metadata_event_inner` — deliberately ungated, see §3.3 row 24).
2. The evidence authenticates: the committer's signature verifies, and the
   committer was an active admin in the retained predecessor roster.
3. The ADR-0059 dedup gate checks the evidence is not a replay.
4. `install_fork_evidence` (`named_groups.rs::install_fork_evidence`) writes the
   marker into the in-memory record; it is persisted in the same write.
5. `no_anchor` is set to `true` when the group's policy has no owner axis
   (inside `install_fork_evidence`; field `src/groups/mod.rs::ForkQuarantine`).
6. `fork_quarantine_set` counter is bumped (inside `install_fork_evidence`).
7. **The quarantine generation in the lifecycle epoch token** (ADR-0067) is not a
   counter: the token is derived on demand from the live record as
   `(state_revision, marker_identity)` (`src/groups/mod.rs`, `LifecycleEpochToken`
   type) — no new field, no new serde surface. It observes every install and clear
   automatically, including the on-disk recovery install at
   `named_groups.rs::record_recovery_fork_evidence`
   and the two clears that bypass the persistence lock (`at bb77a61:3562 inside
   named_groups.rs::rollback_live_fork_evidence`, and the owner-anchored auto-clear
   inside `named_groups.rs::apply_named_group_metadata_event_inner_serialized`),
   because the token is read from the live record at re-check time.

**Evidence path widened by ADR-0066 R2.** Ordinary groups formed without an invite
are covered too (fence inside `install_fork_evidence` widened). "Ordinary group"
is one population, not two.

**Retry rollback is NOT a clear.** A non-durable install retried on exact identity
match (revision + state hash + committer) is rolled back by
`rollback_live_fork_evidence` (`named_groups.rs::rollback_live_fork_evidence`) — an
undo of an install that never durably happened. This is deliberately not gated on
`no_anchor`; gating it would strand a group on a transient persist failure.

---

## 3. Surface behaviour

**All 26 ADR-0066 §1 data-plane paths have landed** (`OPEN_ROWS == &[]`,
asserted in the exhaustiveness fixture
`src/server/routes/named_groups/tests/adr0066_coverage_map.rs`), **and every row
§1 asks to re-check before its effect now does** — slice 9 closed the last four,
so `PENDING_RECHECK == &[]` in the same fixture. §4 is therefore discharged
across the censused surface; the rows 1/2/4/6 block in §3.3 says what that
re-check refuses and what it leaves behind.

### 3.1 Refused surfaces — 409 `fork_quarantined`

Match on **`reason`**, not on `error`. The body is (ADR-0066 §5):

```json
{
  "ok": false,
  "reason": "fork_quarantined",
  "error": "group is fork-quarantined on this node: authenticated fork evidence at revision 7 means the roster is contested, so this operation is refused here. It clears when an owner-anchored commit advances past revision 7, or immediately with the manual clear POST /groups/:id/quarantine/clear (CLI: `x0x groups quarantine clear <GROUP_ID>` …).",
  "fork_quarantine": {
    "revision": 7,
    "observed_at_ms": 1700000000123,
    "no_anchor": false,
    "clear_with": "POST /groups/:id/quarantine/clear"
  }
}
```

- `reason` — the stable machine code; **this is the field clients match**.
- `error` — prose; branches on `no_anchor` so the remedy it names is the one
  that can actually succeed for that group. Not a matchable contract.
- `fork_quarantine.no_anchor: true` — ordinary group; nothing clears automatically.
- `fork_quarantine.clear_with` — the remedy, machine-readable.

| Row | Surface | Symbol anchor |
|-----|---------|--------------|
| 1 | `POST /groups/:id/send` — outbound signed-public send | `named_groups.rs::send_group_public_message` |
| 2 | TreeKEM group encrypt | `named_groups.rs::treekem_group_encrypt` |
| 3 | TreeKEM group decrypt | `named_groups.rs::treekem_group_decrypt` |
| 4 | `POST /groups/:id/secure/encrypt` (GSS) | `named_groups.rs::secure_group_encrypt` |
| 5 | `POST /groups/:id/secure/decrypt` (GSS) | `named_groups.rs::secure_group_decrypt` |
| 6 | `POST /groups/:id/secure/reseal` (GSS) | `named_groups.rs::secure_group_reseal` |
| 7 | TreeKEM group-store resolution | `stores.rs::resolve_gss_group_store` |
| 8 | TreeKEM group-store live info re-read | `stores.rs::resolve_treekem_group_store` |
| 9 | KV group-writer predicate | `src/server/routes/stores.rs::group_writer` |
| 10 | Signed-public KV authorization snapshot (bind-time) | `src/groups/kv_context.rs::from_group (signed-public type)` |
| 11 | TreeKEM KV authorization context construct | `src/groups/kv_context.rs::from_group (TreeKEM type)` |
| 12 | TreeKEM KV authorization context refresh | `src/groups/kv_context.rs::update_from_group` |
| 14 | `DELETE /history?scope=group:<ID>` — purge | `history.rs::history_purge` |
| 15 | `POST /groups/:id/delegate` — grant delegation | `src/server/delegations.rs::delegate_group_authority` |
| 17 | Delegation authorization predicate (`authorize`) | `src/server/delegations.rs::authorize` |
| 18 | Delegated send-as authorization | `src/server/delegations.rs::authorize_send_as` |
| 19 | Committed-delegation registry rebuild / index | `src/server/delegations.rs::rebuild_global_delegation_registry`, `::index_committed` |
| 20 (mutations) | `POST /task-lists`, `POST /task-lists/:id/tasks`, `PATCH /task-lists/:id/tasks/:tid` | `tasks.rs::reject_quarantined_task_mutation` |
| 21 | Signed-public bootstrap outbox publish (withheld — see §3.3) | `src/server/routes/public_group_bootstrap_outbox.rs::withhold_bootstrap_publication`, `::quarantined_markers` |

Rows 1–12 were already gated before ADR-0066; they now refuse for ordinary groups
too (ADR-0066 §2). Rows 14–21 are new refusals added by slices 3–5.

**Every refusal is effective from the FIRST request after the marker installs.
There is no warn-only window and no request budget (R5, no grace).**

Every new refusal uses `reject_fork_quarantined` / `reject_fork_quarantined_marker`
(`named_groups.rs::reject_fork_quarantined`) — the single helper that owns the
status, the body, and the one `fork_quarantine_refusals` increment. No route can
refuse without explaining itself and none can double-count (§3e).

### 3.2 Annotated surfaces — pass-through with annotation

These surfaces continue to serve while the group is quarantined. Each response
gains `"fork_quarantined": true` and a `"fork_quarantine"` object. Both keys are
**absent entirely** (never `null`, never `false`) when the group is not quarantined,
so unaffected groups are byte-identical.

**Single-group annotation shape** (delegations, tasks, WS):

```json
{
  "fork_quarantined": true,
  "fork_quarantine": {
    "revision": 7,
    "observed_at_ms": 1700000000123,
    "no_anchor": false,
    "clear_with": "POST /groups/:id/quarantine/clear"
  }
}
```

**Multi-scope annotation shape** (history endpoints, WS backfill): the
`fork_quarantine` object carries `clear_with` and a `scopes` array (each entry:
`scope`, `revision`, `observed_at_ms`, `no_anchor`), because these surfaces can
span multiple quarantined groups in one response.

| Row | Surface | Shape |
|-----|---------|-------|
| 13 | `GET /history`, `/history/message/:msg_id`, `/history/search`, `/history/scopes`, `/history/stats`, `GET /groups/:id/messages` | multi-scope |
| 16 | `GET /groups/:id/delegations` | single-group |
| 20 (reads) | `GET /task-lists`, `GET /task-lists/:id/tasks` | single-group |
| 25 | WebSocket `mention` frames and ADR-0023 `Subscribe` backfill frames | multi-scope (one-entry `scopes` array) |
| 26 | `GET /diagnostics/history` | multi-scope |

### 3.3 Special surfaces

**Row 13 — History reads: annotated, and `fork_quarantined_at_ingest` tag.**
History reads (row 13) are **never** refused: containment must not blind the
operator to the forensic record. Rows of a quarantined group whose `seen_at_ms`
is at or after `observed_at_ms` carry `"fork_quarantined_at_ingest": true`. This
tag is **derived from the live marker and is NOT persisted** (no schema bump); a
manual clear keeps every row but drops the label. **Read the history you need
BEFORE clearing.** Ingest of new group-scoped rows is tag-and-retain, never
refused (ADR-0066 R3).

**Row 14 — History purge: REFUSED.** `DELETE /history?scope=group:<ID>` is
refused while quarantined — before anything is deleted, so the store is
untouched. Purge is the irreversible destruction of the forensic record. Clear
first if you genuinely need to purge.

**Row 19 — Delegation index and registry.** The global delegation-id registry
(`src/server/delegations.rs::rebuild_global_delegation_registry`) and per-group
index (`::index_committed`) skip quarantined groups: a contested group's grants
are not indexed and do not seed the registry. After a clear, the index re-derives
from durable history automatically; no re-issuance is needed. Non-REST delegation
paths (gossip ingest, boot rebuild) have no HTTP response; they record the same
single `fork_quarantine_refusals` increment and log the §5 sentence at WARN
(WARN dedupe keyed by `(group_id, revision)`, bounded 1024 —
`src/server/delegations.rs::first_index_refusal_for`). Carrier history rows are
still retained (R3).

**Row 20 — Tasks: mutations refused, reads annotated.** Task-list mutations are
refused from the first request; reads annotate. An inbound peer CRDT delta still
applies ungated (see §6c).

**Row 21 — Bootstrap outbox: WITHHELD, not dropped.** The outbox worker declines
to send a contested group's snapshot. This is a suppression, not a deletion: the
obligation and its retry schedule are left untouched. Delivery resumes by itself
on the first worker pass after the manual clear — the poll interval (~0.5 s), with
no backoff to wait out. A `no_anchor` marker never auto-clears, so dropping the
debt would permanently strand a member on the roster. **One quarantined group does
not delay any other group's bootstrap:** quarantined groups are excluded when the
candidate is CHOSEN (not refused after the choice), so the outbox never stalls.
The withheld publication has no HTTP response; it logs the §5 sentence at WARN
and records one `fork_quarantine_refusals` increment, **deduplicated per
`(group_id, revision, observed_at_ms)`, bounded 1024** —
`src/server/routes/public_group_bootstrap_outbox.rs::withhold_bootstrap_publication`. A new evidence revision or a clear
followed by a re-quarantine logs and counts again.

**Row 22 — Lifecycle epoch token (ADR-0067, slice 7).** Every persist-path
operation captures the lifecycle epoch token `(state_revision, marker_identity)`
at its authorization check and re-validates it inside the same
`state.named_groups` write critical section that performs the mutation. A mismatch
aborts before anything irreversible, leaving state byte-identical:

| Path | What you see | What it means |
|------|-------------|---------------|
| Invite join | 409 `fork_quarantined` "changed while this join was being installed" | Evidence landed during the join's two fsyncs; seating refused. **Retry** — succeeds on the first retry unless a marker is still present. |
| TreeKEM roster+snapshot persist | log line `ADR-0066 §4: refusing TreeKEM atomic persist` | Same window. Nothing written: no journal, no snapshot, no `named_groups.json`. |
| Home seal / reseal | 409 `fork_quarantined` | Marker installed during the seal; refuses rather than erasing the marker. Retried on the next provisioning pass. |

A mismatch aborts even when the marker was **cleared** mid-operation (a cleared
marker is stale authorization, not a retry hazard — the retry sees the cleared
state and succeeds immediately). These refusals are retryable and are not a
lockout; nothing parks.

**Rows 1, 2, 4 and 6 — outbound send and crypto: re-checked immediately before
the effect (§4, slice 9).** The row 22 sites above all persist a roster record,
so §4's "inside the same critical section as the mutation" named a site for them.
These four mutate no roster and take no persistence lock: their effect is
something LEAVING the node, so they get the same §4 rule at the only site they
have — the last point before the effect with no suspension between. One helper,
`named_groups.rs::reject_fork_quarantine_installed_before_effect`, is called from
all four.

| Row | Path | The effect protected |
|------|------|---------------------|
| 1 | `named_groups.rs::send_group_public_message` | the gossip publish — once the bytes are handed to gossip the contested message is on the wire |
| 2 | `named_groups.rs::treekem_group_encrypt` | the send-ratchet advance and the ciphertext |
| 4 | `named_groups.rs::secure_group_encrypt` | the ciphertext and its durable history row (GSS plane) |
| 6 | `named_groups.rs::secure_group_reseal` | the group's shared secret, sealed to a member's ML-KEM key, in the response |

**What you see.** A 409 `fork_quarantined` (the same §5 body — same `reason`,
same prose, same `clear_with`) on a send or crypto route whose earlier attempts
succeeded: evidence landed while that request was in flight. **Nothing was
exported** — no message published, no ciphertext or envelope returned, no history
row, no ratchet generation burned, every durable file byte-identical. The
ordinary remedy applies (§4); there is nothing extra to clean up.

**Not retryable, unlike row 22.** A retry meets the ENTRY gate and refuses
again, because the marker is now installed. That is correct — the group is
contested until cleared. Do not loop the client.

**Only the marker half of the token is compared**
(`groups::LifecycleEpochToken::same_marker`), so a concurrent legitimate roster
advance — a rename, a role change — does not refuse a send. Comparing the full
token would refuse every send that raced a rename, with no containment benefit.

**A marker CLEARED mid-operation does not refuse, and cannot occur.** The
operation was admitted only because the entry gate saw no marker, so the captured
marker identity is always absent. This differs deliberately from row 22, which
does refuse on a clear; it is not an inconsistency.

**Residual window, stated honestly.** Between the re-check and the bytes actually
reaching the wire or the caller, nothing holds the roster lock, so a marker
installed in that last stretch does not stop that one effect. The window is **one
message wide** and is irreducible without a send-path critical section — a lock
held from the authorization check until the client has the bytes — which ADR-0066
does not define and which would serialize the hot path behind a network write. It
is acceptable because containment is about stopping the flow, not about the
instant of the install: the re-check shrinks the exposure from the whole request
duration (which includes awaits on the rider-token mutex, a revocation lookup,
delegation verification and the TreeKEM group mutex) to a tail with no suspension
point, and the very next request refuses. **Operationally: after installing or
observing a marker, assume at most ONE message per in-flight request may already
have left**, and check the group's history and the peers' view accordingly.

**Row 24 — Inbound metadata / state-commit apply: deliberately ungated.** The
clearing commit must still be able to arrive. Gating this would make some
quarantines unclearable.

**Row 25 — WebSocket: annotated, never cut.** A WS subscriber watching a
quarantined group keeps receiving everything. `mention` frames (validated group
messages, delegation grants) on the group topic channel, and ADR-0023 `Subscribe`
backfill frames, carry the annotation. **Live raw-topic `Publish` frames are NOT
annotated by design** (row 25 covers only mention and backfill; a raw-topic
publish is not a group-scoped send and is covered by row 1 only when routed
through `POST /groups/:id/send`). The marker is read when each frame is emitted,
not when the subscription opens; a session that subscribed before the marker was
installed starts seeing the label on its next frame and stops on the frame after a
clear — no reconnect needed.

**Home seals / invite-join / TreeKEM persist / KV persists: re-checked under the
persist lock (ADR-0067 slice 7).** The lifecycle epoch token closes the bind-time
gap in rows 10–12: `kv_context.rs` snapshots authorization at `from_group`
(`:109`, `:360`) and only refreshes via `update_from_group` (`:370`), driven by
roster change. ADR-0066 §2 makes a marker install a refresh trigger, and the
epoch token closes the remaining window from both ends.

**Encrypted (GSS) stores fail closed, and recover.** A GSS marker suspension
drops the shared secret and empties the roster, so sealing, opening and
membership all fail closed. Unlike a withdrawal, this is recoverable: the next
refresh after a clear re-arms the context from live state.

---

## 4. Diagnose → decide → clear

### 4.1 Reading the marker

```bash
x0x group info <GROUP_ID>
# or:
curl -H "Authorization: Bearer $TOKEN" $API/groups/<GROUP_ID>
```

The group record carries `fork_quarantine` (null when not quarantined):

- `revision`, `state_hash` — the CONFLICTING commit this node evidenced (not your
  own head);
- `committed_by` — hex agent id of the admin that committed the fork;
- `observed_at_ms` — local observation time (unix ms);
- `no_anchor` — `true` when the group has no owner axis; the manual
  force-clear is the only exit (§4.3);
- `snapshot` — forensic snapshot of both competing commit headers, with
  `snapshot.classification`:
  - `"owner_anchored_conflict"` — the conflicting commit carries an OwnerMandate
    anchoring its exact header. Strongest signal that YOUR chain is the disowned
    one. Contact the owner; do not force-clear repeatedly while the live
    divergence persists.
  - `"signer_only"` — the signer was an active admin at the claimed parent, but
    no owner anchor is reachable (the classic #468 shape).
  - `"unauthorized_signer"` — the signer held a seat in retained history but was
    NOT an active admin at the claimed parent.
  - `null`/absent — pre-slice-4 record shape.

No shared secrets or TreeKEM material appear in the snapshot — it is
header-only by construction.

### 4.2 Diagnostics counters

```bash
x0x diagnostics groups
# or:
curl -H "Authorization: Bearer $TOKEN" $API/diagnostics/groups
```

Key counters per group (`GET /diagnostics/groups`):

- `fork_quarantine_set` — durable marker installs (process-lifetime).
- `fork_quarantine_refusals` — gated-route refusals (process-lifetime); becomes
  a fleet-health signal after upgrade. Set alerting thresholds before rolling
  out.
- `fork_evidence_signer_only` / `fork_evidence_unauthorized_signer` — classified
  conflict observations.
- `fork_quarantine_owner_anchored_refusals` — owner-anchored conflicting commits
  refused at the strictly-greater fence; non-zero with a persistent marker
  usually means the contested branch is publishing owner-anchored successors this
  node cannot apply — do not force-clear while this is rising.
- `fork_quarantine_owner_anchored_clears` / `fork_quarantine_manual_clears` —
  apply-path anchored clears and manual endpoint clears.

History surfaces for the marker: `GET /history/stats` and
`GET /diagnostics/history` annotate quarantined groups and list both spellings
of the group id (roster map key and stable id), so you can match the scope your
history rows carry as well as the id the clear route accepts.

**WARN dedupe semantics.** Background workers that cannot return an HTTP response
record a `fork_quarantine_refusals` increment and log the §5 sentence at WARN,
deduplicated:
- Bootstrap outbox (row 21): keyed by `(group_id, revision, observed_at_ms)`,
  bounded 1024 (`src/server/routes/public_group_bootstrap_outbox.rs::withhold_bootstrap_publication`).
- Delegation index / registry (row 19): keyed by `(group_id, revision)`, bounded
  1024 (`src/server/delegations.rs::first_index_refusal_for`).

Read row 21's `fork_quarantine_refusals` contribution as "this group's publication
is being withheld", not as a rate. A new evidence revision, or the same revision
re-observed after a clear, logs and counts again.

### 4.3 Clearing the marker

**A `no_anchor` marker (ordinary group) has NO automatic path at all.** Use the
force path (4.3c) — none of the anchored arms below can clear it. Each one tests
`no_anchor` and declines by design (ADR-0066 §2). The retry rollback of a
non-durable install is not a clear and is deliberately not gated.

For owner-axis groups, the automatic paths additionally require the clearing
commit to be applied at a revision **strictly greater** than the evidenced
revision.

#### 4.3a Apply-path anchored clears (owner-axis only)

Keep the node online and reachable by the authority. The clear rides the normal
apply — no operator action needed:
- Tier-1 attestation-verified adoption of a `MemberAdded` anchored by the
  owner-signed head attestation (the joiner recovery path).
- A mandate-carrying `MemberAdded` whose `OwnerMandate` verifies (gapless or
  walked adoption).

#### 4.3b Explicit seal (owner-axis, owner-key node only)

```bash
x0x group state-seal <GROUP_ID>
# or:
curl -X POST -H "Authorization: Bearer $TOKEN" $API/groups/<GROUP_ID>/state/seal
```

Requires: the local install holds the group's owner USER key (an agent-key seal
carrying only an ADR-0038 certificate verdict is NOT an owner anchor), AND the
sealed revision is strictly greater than the evidenced revision. The ~22 routine
mutation sites that share the sealing wrapper (rename, policy, add/ban/promote, …)
NEVER clear.

#### 4.3c Manual clear — the operator escape hatch

```bash
# On a node holding the group's owner USER key (no flags needed):
x0x groups quarantine clear <GROUP_ID>

# On any node — the documented operator override:
x0x groups quarantine clear <GROUP_ID> --force --reason "<what you verified and why>"
```

REST: `POST /groups/:id/quarantine/clear`

The `reason` is logged (info, capped at 256 chars) and counted
(`fork_quarantine_manual_clears`). **Include this runbook and what you verified.**

Typed 409 responses from the endpoint:
- `owner_key_unavailable` — this node does not hold the group's owner user key;
  re-run with `--force --reason "<…>"`.
- `force_required` — the group has no owner axis to mint an attestation with;
  pass `--force --reason "<…>"` (exact message: `"force_required: group has no
  owner axis to attest with — clear with force=true and a non-empty reason"`).
- Plain 409, text `"force=true requires a non-empty reason (the audit trail)"` —
  `--force` was passed but `--reason` was empty or whitespace-only.
- Plain 409 `"group is not quarantined (no fork_quarantine marker)"` — no marker
  is set.

**EVERY clear re-arms the evidence gate.** After a clear, the next authenticated
conflict re-evaluates, re-installs evidence, and re-quarantines. Force-clearing
without resolving the underlying divergence will re-quarantine on the next
conflicting commit.

**Before force-clearing:** establish which chain is canonical out of band with the
group's admins (compare `GET /groups/:id/state` heads across members), check
`snapshot.classification`, have an active admin of the AGREED chain advance it
(revision strictly greater), re-seat members still holding the disowned sibling,
then force-clear — naming this runbook and what you verified in `--reason`.

### 4.4 Two spellings of one group — either clears

A group's *stable* id is what history rows, `GET /history/scopes`, the WS/SSE
`fork_quarantine` annotation and a delegation envelope all carry. The local
roster — and therefore the marker — is keyed by whichever id this daemon learned
the group under, which is not always the same string.

`clear_group_quarantine` (`named_groups.rs::clear_group_quarantine`) resolves
**both** spellings through the shared resolver
(`src/server/mod.rs::resolve_group_entry_locked`): direct key first, then a scan
by `stable_group_id()`. Whichever id you are holding is the id to use.

**Note:** on builds *before* the resolver-unification change (§6d), the clear
took the MAP KEY only and answered 404 to the stable id. On those builds, clear
by the key the refusal body's `error` field names in prose — `GET /history/stats`
and `GET /diagnostics/history` list both spellings when they differ.

A 404 from a current build therefore means the group is not on this node at all,
under either name — not that you used the wrong spelling.

---

## 5. Upgrade notes

- **No retroactive quarantine at startup.** A startup scan does not run. The
  marker is installed only when authenticated conflicting evidence arrives through
  the live apply path. A group that was already silently forked is not quarantined
  until the next authenticated conflicting commit arrives after the upgrade.
- **Expect `fork_quarantine_set` to rise on the upgrade wave.** Groups that were
  already silently forked begin refusing from the FIRST authenticated conflicting
  commit after the upgrade — immediately, with no grace period (R5). Set alerting
  thresholds on `fork_quarantine_set` and `fork_quarantine_refusals` BEFORE
  rolling out.
- **One-time compatibility break for literal `error` matchers.** The 409 body
  previously was `{"ok": false, "error": "fork_quarantined"}`. The stable machine
  code moved to `reason`. A client matching the literal `error == "fork_quarantined"`
  must move to `body["reason"] == "fork_quarantined"`. HTTP 409 and `ok: false` are
  unchanged.
- **CLI error output now appends `reason:`.** The `x0x` CLI renders
  `<message> (HTTP <code>, reason: <reason>)` for all `api_error_with_reason`
  responses — today that means the `fork_quarantined` refusal and the pre-existing
  409 `recipient_not_active`. Scripts matching CLI error output positionally
  should match on the `reason:` key.

### 5.1 Mixed-fleet notes

- `fork_quarantine` and `mandate_capability` are `#[serde(default)]` JSON
  fields: older binaries ignore them — no wire break, no brick.
- **A downgrade loses containment, it never bricks.** An old binary that rewrites
  `named_groups.json` drops fields it does not know.
- For owner-axis groups the AUTHORITATIVE persisted record is the
  `home-suite-groups.json` sidecar (`named_groups.json` holds a legacy placeholder
  also carrying the fields; the load path merges sidecar-wins). Pinned by test:
  rewriting `named_groups.json` without the fields loses nothing — the marker and
  grace clocks survive from the sidecar.
- Residual caveat: an old sidecar-aware binary that rewrites the sidecar itself
  drops both fields from the authoritative record — a downgrade across a
  sidecar-aware version loses containment (accepted; matches the ADR migration
  table's "never bricks").

---

## 6. Known gaps and follow-ups

These are open items that ship visible, not closed silently. Each is asserted or
noted at the symbol cited.

**(a) Send-path §4 re-check — CLOSED by slice 9.** Rows 1, 2, 4 and 6 now
re-check the marker immediately before their effect; see §3.3 ("outbound send and
crypto"), including the one-message-wide residual window that remains and why it
is accepted. `PENDING_RECHECK == &[]` is asserted, and the fixture additionally
counts one re-check CALL per row so a deletion fails the suite rather than quietly
re-opening the gap.
Source: `adr0066_coverage_map.rs::PENDING_RECHECK`,
`adr0066_coverage_map.rs::SEND_PATH_RECHECK_CALL`.

**(b) History reaper ignores quarantine — CLOSED by ADR-0068 D1.**
The reaper used to run ADR-0023 §6 age and byte eviction against every scope
unconditionally, so a quarantined group's forensic record could be destroyed —
and a flooder could *drive* that by sending the node a stream of recordable
events (ingest is never refused: `R3: tag-and-retain`). **What you now see as an
operator:** a group with a live marker has its `group:<id>` history rows PINNED —
skipped by the age bound, by the per-scope budgets and by the whole-database
budget — up to a **per-group ceiling** of `min(4 × base, [history] max_bytes/16)`,
where `base` is that scope's configured `scope_limits` entry or
`max_bytes / 64`. At the shipped 1 GiB default the ceiling is **64 MiB per
quarantined group**. Past the ceiling the reaper sheds that group's **own** oldest
rows and nothing else — no other scope pays for it — and counts them.
Read both numbers from `GET /diagnostics/history`:
`history_quarantine_pinned_scopes` (how many scopes are pinned right now, the
`G` below) and `history_quarantine_pinned_evictions` (cumulative; **non-zero
means a pinned group is at its ceiling and losing its oldest rows**, so copy the
record out or raise `max_bytes` before continuing triage). Disk is bounded by
`max_bytes × (1 + G/16)`; `G` counts groups this node has joined that are
forked at the same time, which an attacker cannot inflate. Under whole-database
pressure unpinned scopes are still evicted exactly as before — the pin protects
the contested scope, it does not suspend the budget for everyone. On clear the
scope returns to normal retention on the **next** pass (≤ 300 s), including rows
the pin kept past the age bound. Raising `[history] max_age_days` and
`max_bytes` during an incident is still useful for a very long one — it raises
the ceiling too, since the ceiling is derived from `max_bytes`.
**Residual you must know BEFORE an incident (cross-model review, 2026-09-20).**
The ceiling and the `max_bytes × (1 + G/16)` bound are measured in **payload
bytes**, while the whole-database phase measures the SQLite **file** (page count,
which SQLite does not return promptly after a delete). A history row's file
footprint here is roughly **4× its payload**, because the FTS5 projection is
indexed alongside it. So in file terms one pinned group can hold about
`4 × max_bytes/16 = max_bytes/4`, and **healthy-history displacement reaches
100 % at around G≈4–5** simultaneously forked-and-joined groups rather than the
G≈16 the payload arithmetic suggests: past that point the whole-database phase
cannot reach enough unpinned bytes to get under budget, so it evicts every
durable unpinned row it *can* reach. **Mitigation:** watch
`history_quarantine_pinned_scopes` — at 4 or more, raise `[history] max_bytes`
(which raises the ceiling proportionally, since the ceiling is derived from it)
or copy the forensic record out and clear the quarantines you have finished
triaging. **Recommended follow-up, needing its own ADR (not this one):** a GLOBAL
pinned cap — total pinned ≤ `max_bytes/4`, evicting the oldest pinned rows across
groups once reached — which would bound displacement independently of `G`, at the
cost of letting one group's flood reach another group's pinned rows. ADR-0068
deliberately did not make that trade.
Source: `src/history/store.rs::retain_with_pins`,
`src/history/store.rs::pinned_ceiling`,
`src/history/store.rs::evict_pinned_scope_to_ceiling`,
`src/history/store.rs::db_bytes`,
`src/server/routes/history.rs::ReaperQuarantinePins`.

**(c) Inbound peer task-CRDT deltas apply ungated — CLOSED by ADR-0068 D2.**
Row 20 gates the LOCAL REST mutations. Inbound deltas from peers used to merge
regardless, admitted by the `authorized_agents` set that
`tasks.rs::apply_group_authorization` derives from the group's active members —
the contested roster itself — so a peer seated by the disputed roster could keep
claiming and completing, and move the deterministic winner, while this node's own
agent was refused. **What you now see as an operator:** a quarantined group's
task lists **freeze and then catch up**. While the marker is live, inbound deltas
are held in arrival order (bounded: 1024 deltas / 1 MiB per list, oldest dropped)
and the CRDT is left byte-identical; reads keep serving that frozen state with
the usual `fork_quarantined` annotation, so a list that looks quiet is quiet
*because* it is contained. Once the marker is gone — manual clear or
owner-anchored — the held deltas are applied in order, within seconds, without
an operator step. Watch `GET /diagnostics/groups` for
`task_deltas_quarantine_buffered` (held), `task_deltas_quarantine_dropped`
(**non-zero means the quarantine is outlasting the buffer**; the dropped work is
recovered by anti-entropy after the clear, not by a replay) and
`task_deltas_quarantine_applied` (caught up). The hold is process-local: a
daemon restart during quarantine discards it and the list re-converges by
anti-entropy after the clear instead. Group **metadata** ingest (row 24) is
deliberately untouched, so the commit that clears the quarantine still arrives.
A manual clear applies the held deltas **at once** (the clear route calls the
drain after its roster write is durable); every other clear path — metadata
apply, explicit owner seal, rollback arms — is picked up by the listener's own
poll within `TASK_QUARANTINE_DRAIN_POLL_SECS` (5 s), which is the guarantee.
The drain re-checks the ADR-0067 token (marker half) inside the same critical
section as the merge, so a marker that re-installs while it is deciding abandons
the drain and leaves the deltas buffered in order rather than applying them on a
stale reading. A single delta larger than 1 MiB is dropped rather than held, so
the per-list bound is the one stated here and not the transport's frame cap.

**Residual (cross-model review, 2026-09-20):** a list's `authorized_agents` set
is captured when the subscription is set up, so a delta buffered during the
quarantine from an agent whom the *clearing* commit removes still applies at
drain time. This is identical to the live path's admission — the same delta
arriving one second before the marker installed would also have been applied —
so containment is not weakened relative to an unquarantined node; it simply does
not retro-apply the cleared roster to work it held. Pre-existing behaviour,
recorded rather than silently inherited.
Source: `src/crdt/sync.rs::admit_or_buffer`,
`src/crdt/sync.rs::drain_quarantine_buffer`,
`src/crdt/task_list.rs::is_authorized_content_writer`,
`src/server/routes/tasks.rs::TaskQuarantineIngestGate`,
`src/server/routes/tasks.rs::install_task_ingest_gate`,
`src/server/routes/tasks.rs::resume_group_task_ingest`.

**(d) `clear_group_quarantine` single-spelling: alias vs stable id — RESOLVED.**
The clear used to resolve the MAP KEY only, so a group stored under an alias
could not be cleared by its stable id. It now goes through
`src/server/mod.rs::resolve_group_entry_locked` like the other marker lookups,
and both spellings clear (§4.4). Every precondition, the audit log and the
`fork_quarantine_manual_clears` counter are unchanged, and an id this node holds
no record for is still 404. Operators on older builds: see the note in §4.4.

**(e) Three marker resolvers still local — RESOLVED.**
The per-slice copies are gone: `src/server/routes/history.rs::markers_for_scopes`
and the purge gate, `src/server/ws.rs::fork_quarantine_annotation` and the
public-group bootstrap install check all call
`src/server/mod.rs::resolve_group_entry_locked`, alongside
`src/server/delegations.rs::fork_quarantine_marker` and the TreeKEM protector in
`src/server/routes/stores.rs`. A `#[cfg(test)]` source scan
(`named_groups/tests/adr0066_lookup_guard.rs`) now fails the build if a
quarantine-relevant roster lookup spells the two-spelling rule out for itself
again without an `ADR0066-LOOKUP-WAIVER:` comment giving the reason. The same
change taught `named_groups.rs::treekem_group_encrypt` and
`named_groups.rs::treekem_group_decrypt` to resolve both spellings: both of their
pre-crypto gates sat inside one single-spelling lookup, so a miss skipped both
and advanced the ratchet — reachable only as a TOCTOU behind their callers, but
the only arm in that family that failed open rather than answering 404.

**(f) `fork_quarantine` fault-injection test parallel-run flake under plain `cargo test`.**
The `adr0064`/`adr0066` fault-injection tests use process-global statics
(`#[cfg(test)]` `LazyLock<Mutex<HashSet>>` barriers) to trigger race windows.
Under plain `cargo test` (which runs tests in the same process), concurrent test
threads that touch the same static can interfere and produce spurious failures.
`cargo nextest` runs each test in a separate process and is unaffected. Always use
`cargo nextest` or the project's `just test` recipe.

**(g) TreeKEM snapshot persist was single-spelling; a stable-id caller could burn
a generation — CLOSED.** Found while building slice 9's stable-id fixture, NOT
introduced by it, and on a non-quarantine path.
`named_groups.rs::persist_treekem_snapshot_bound` resolved one spelling
(`groups.get(group_id_hex)`), so in the state #750 named — the roster re-keyed to
an alias while `treekem_groups` still holds the live ratchet under the stable id —
a stable-id encrypt advanced the send ratchet and then failed its persist with a
500 `failed to persist secure group state`. The generation was burned with no
snapshot written, so it was lost across a restart rather than reused (fail-safe
for nonce reuse, not for availability), and the path self-healed once the alias
spelling or a reseal caught up. That lookup now goes through
`server::resolve_group_entry_locked` like the gates #750 fixed, so the envelope
binds to the same entry the gates resolved. The snapshot FILE is still written
under the caller's spelling — only the roster resolution widened, so no persisted
layout changed. All four callers benefit through the one function:
`named_groups.rs::treekem_group_encrypt`, `named_groups.rs::treekem_group_decrypt`
and `stores.rs::TreeKemGroupStoreProtector::{seal_record, open_record}`.
`adr0066_treekem_gates.rs::issue732_treekem_encrypt_persists_the_snapshot_for_an_alias_keyed_group`
asserts the clean direction end to end: 200, the snapshot on disk carrying the
ADVANCED ratchet byte-for-byte, the generation advancing exactly once per accepted
encrypt, and a round-trip decrypt. Slice 9's
`row2_stable_id_spelling_reaches_the_recheck_and_is_refused` still asserts
reachability as "not 424 and the ratchet moved" rather than as a 200, so the §4
fixture stays uncoupled from this path's status. Note the §4 re-check already made
this less reachable for a quarantined group, which refuses before the advance.

---

## 7. Mandate grace and the `owner_mandate_missing` refusal

On owner-axis groups, an absent-mandate `MemberAdded` from an authority agent
whose capability has been observed and whose grace window has elapsed is refused
with the typed, **RETRYABLE** `owner_mandate_missing` (nothing is queued as a
revision gap; the sender-side bounded resend or a mandate-carrying re-issue is the
redelivery path — retry the operation, do not rejoin). Semantics:

- Capability is recorded per AUTHORITY AGENT the first time that agent produces a
  valid mandate or an owner-countersigned InviteV4 (`first_seen_ms`).
- `unknown` agents (never observed capability — the keyless tier, #472 decision 7)
  warn-accept indefinitely; A's capability never implicates B.
- The grace window defaults to **60 days** (one release cycle) and is configured
  per daemon as `[groups] mandate_grace_days` (validated ≥ 1 at startup).
- A later valid mandate from the same agent restores `capable` but RETAINS the
  original clock — a compromised authority cannot reset its own window.
- The clock is the node's LOCAL wall clock: a backwards clock jump flips a
  refusing authority back to warn-accept until the clock recovers.

If a legitimate admin's events start refusing: upgrade that admin's install
(mandate production needs the owner user key on the authority), or have the
owner/keyed authority perform the seating. Do NOT delete the capability map to
"fix" refusals — the map is observational state; the durable fix is a
mandate-producing authority.

---

## 8. Quick triage

| Observation | Meaning | Action |
|---|---|---|
| 409 `fork_quarantined` on send/encrypt | local marker set; authenticated fork evidence held | read `fork_quarantine` snapshot + classification (§4.1); let the owner anchor advance (§4.3a–4.3b); for `no_anchor` groups use manual clear only (§4.3c) |
| 409 `fork_quarantined` on `DELETE /history` | purge refused to preserve forensic record (§3.3 row 14) | read the history first; purge only after a deliberate clear |
| history reads carry `fork_quarantined: true` | scope spans a contested chain (§3.2 row 13) | expected; use `fork_quarantined_at_ingest` on rows to find the incident window; export what you need before clearing |
| `classification: "owner_anchored_conflict"` | owner anchored a successor this node cannot apply | this node likely holds the disowned chain — coordinate with the owner before any force-clear |
| `fork_quarantine_owner_anchored_refusals` rising, marker persists | contested branch publishing owner-anchored successors | divergence still live; do not force-clear |
| 409 `fork_quarantined` with `"no_anchor": true` | ordinary group contained; NO automatic clear (§1, §4.3c) | agree canonical chain out of band, re-seat stragglers, then `x0x groups quarantine clear <ID> --force --reason "…"` |
| `force_required` from the clear endpoint | no owner axis to attest with | re-run with `--force` and a reason — this is the documented path, not a fault |
| `fork_quarantine_set` rising fleet-wide right after upgrade | groups already silently forked are being contained | expected (ADR-0066 Migration / §5); triage per §4.3; do not mass force-clear; set alerting thresholds |
| 409 `owner_mandate_missing` (retryable) | post-grace absent mandate from a recorded-capable authority | upgrade/repair the authority; retry the send |
| `mandate_capability` row `state: "refusing"` | that agent's grace window elapsed | same as above, per-agent |
| 409 `fork_quarantined` "changed while this join was being installed" | evidence landed inside the join's persist window (§3.3 row 22) | retry the join; a leftover install marker is self-healing |
| encrypted (GSS) store refuses after a marker set | cached authorization context is suspended (§3.3) | expected; re-arms on the next refresh after a clear; a store still dead after a clear is a bug, capture `/diagnostics` |
| marker vanished after an old binary ran | downgrade dropped containment (§5.1) | re-upgrade; re-quarantines on the next authenticated conflict |
| `signed-public bootstrap publication withheld` in log | row 21 suppression active (§3.3) | clear the marker per §4.3; delivery resumes automatically |
| `clear` returns 404 on the stable id | pre-resolver build (§4.4, §6d); on a current build the group is simply not here | older build: use the roster key from the refusal message or `/history/stats` |

---

## Appendix A: Code reference

| Claim | Symbol (symbols verified at bb77a61) |
|---|---|
| Marker install path | `named_groups.rs::install_fork_evidence` |
| Former owner-axis-only fence (removed by §2) | inside `named_groups.rs::install_fork_evidence` |
| `no_anchor` set for ordinary groups | inside `named_groups.rs::install_fork_evidence` |
| `no_anchor` field declaration | `src/groups/mod.rs::ForkQuarantine` |
| `invite_lineage` fence widened by R2 | inside `named_groups.rs::install_fork_evidence` |
| `fork_quarantine_set` counter bump | inside `named_groups.rs::install_fork_evidence` |
| `is_fork_quarantined()` | `src/groups/mod.rs::GroupInfo::is_fork_quarantined` |
| Retry rollback (NOT a clear) | `named_groups.rs::rollback_live_fork_evidence` |
| Apply path (deliberately ungated, row 24) | `named_groups.rs::apply_named_group_metadata_event_inner` |
| Single refusal helper | `named_groups.rs::reject_fork_quarantined` |
| Refusal body builder | `named_groups.rs::fork_quarantine_refusal_body` |
| Refusal message (branches on `no_anchor`) | `named_groups.rs::fork_quarantine_refusal_message` |
| Annotation shape (single-group) | `named_groups.rs::fork_quarantine_annotation` |
| `api_error_with_reason` | `src/server/mod.rs::api_error_with_reason` |
| `clear_group_quarantine` (resolves both spellings) | `named_groups.rs::clear_group_quarantine` |
| Owner-anchor apply-path clear | `named_groups.rs::apply_named_group_metadata_event_inner` |
| Adoption clear | `named_groups.rs::try_adopt_member_added_across_gap` |
| Owner-seal clear | `src/groups/mod.rs::clear_fork_quarantine_on_explicit_owner_seal` |
| `resolve_group_entry_locked` | `src/server/mod.rs::resolve_group_entry_locked` |
| Resolver unification (gap (e) closed) | inside `src/server/mod.rs::resolve_group_entry_locked` |
| Single-spelling lookup guard | `src/server/routes/named_groups/tests/adr0066_lookup_guard.rs` |
| Waiver marker for a justified single-spelling site | `ADR0066-LOOKUP-WAIVER:` |
| TreeKEM pre-crypto gates (both spellings) | `named_groups.rs::treekem_group_encrypt`, `named_groups.rs::treekem_group_decrypt` |
| `lifecycle_epoch_token_locked` | `src/server/mod.rs::lifecycle_epoch_token_locked` |
| Lifecycle epoch token type | `src/groups/mod.rs::LifecycleEpochToken` |
| History annotation function | `history.rs::fork_quarantine_annotation` |
| WS annotation function | `src/server/ws.rs::fork_quarantine_annotation` |
| WS scopes-array shape | inside `src/server/ws.rs::fork_quarantine_annotation` |
| `fork_quarantine_refusals` counter declaration | `src/groups/diagnostics.rs::GroupCounters.fork_quarantine_refusals` |
| `fork_quarantine_set` counter declaration | `src/groups/diagnostics.rs::GroupCounters.fork_quarantine_set` |
| History reaper (no quarantine check) | `src/history/reaper.rs` (47 lines, zero quarantine mentions) |
| Task CRDT delta admission (ungated) | `src/crdt/task_list.rs::is_authorized_content_writer` |
| Task group authorization setup (uses contested roster) | `tasks.rs::apply_group_authorization` |
| Task quarantine check | `tasks.rs::reject_quarantined_task_mutation` |
| Bootstrap outbox WARN dedupe | `src/server/routes/public_group_bootstrap_outbox.rs::withhold_bootstrap_publication` |
| Bootstrap outbox dedup key | `(group_id, revision, observed_at_ms)`, bound 1024 |
| Delegation index WARN dedupe | `src/server/delegations.rs::first_index_refusal_for` |
| Delegation index dedup key | `(group_id, revision)`, bound 1024 |
| ADR-0066 §1 coverage fixture | `src/server/routes/named_groups/tests/adr0066_coverage_map.rs` |
| `OPEN_ROWS == &[]` (all 26 rows landed) | `adr0066_coverage_map.rs::OPEN_ROWS` |
| `PENDING_RECHECK == &[]` (§4 discharged) | `adr0066_coverage_map.rs::PENDING_RECHECK` |
| Send-path re-check call, counted per row | `adr0066_coverage_map.rs::SEND_PATH_RECHECK_CALL` |
| Before-effect re-check (rows 1/2/4/6) | `named_groups.rs::reject_fork_quarantine_installed_before_effect` |
| Send-path race barrier (`cfg(test)`) | `named_groups.rs::send_recheck_barrier` |
| Slice-9 fixtures | `src/server/routes/named_groups/tests/adr0066_send_path.rs` |
| Exhaustiveness fixture | `adr0066_coverage_map.rs` (const array assertion) |
