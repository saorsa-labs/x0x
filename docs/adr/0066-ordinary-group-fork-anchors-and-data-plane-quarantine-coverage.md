# ADR 0066: Ordinary-Group Fork Anchors and Data-Plane Quarantine Coverage

- **Status:** Proposed
- **Date:** 2026-09-18
- **Decision owners:** David Irvine (direction), Claude Opus (design drafting)
- **Reviewers:** pending — requires cross-model (omp) review and human ratification
- **Supersedes:** none (completes the staged residuals of ADR 0064 §§2 and 3; does not edit any Accepted ADR)
- **Superseded by:** none
- **Related:** #732 (this decision), #472 (parent, closed into this ADR), #468, #469; ADR 0064 (owner-anchored fork authority, Accepted), ADR 0059 (InviteV4 + seating provenance), ADR 0016 (flat-admin state-commit chain), ADR 0023 (durable local history), ADR 0040 (agent delegation in spaces), ADR 0047 (CRDT KV delta gossip); #639 (alternate-chain fetch surface) and #646 (content-addressed base snapshot) are explicitly NOT absorbed

## Context

ADR 0064 shipped in slices 1–4 and is Accepted. It closed the owner-axis
question and deliberately left two residuals open, naming them as its own
"explicitly NOT decided here" (ADR 0064 Consequences, line 103):

1. **Ordinary (non-owner-axis) groups have no anchor.** ADR 0064 Decision §2
   claims *no* automatic canonical anchor for non-owner-axis groups, and
   Decision §3 states such groups would hold `quarantine_no_anchor`
   indefinitely with manual recovery. **The shipped code is weaker than the
   ADR's own text**: `fork_quarantine_for_evidence`
   (`src/server/routes/named_groups.rs:3733`) opens with
   `current.policy.admission.owner_certified_user_id()?;` — an early return
   for any group without an owner axis. An ordinary group therefore never
   receives a marker at all, and the reserved `no_anchor` flag
   (`src/groups/mod.rs:280`) is hard-coded `false` at the only construction
   site (`named_groups.rs:3744`). The evidence path is additionally fenced to
   invite-derived groups by `current.invite_lineage.is_some()`
   (`named_groups.rs:3765`). Ordinary groups are evidence-and-diagnostics-only,
   exactly as #732 states.
2. **Data-plane coverage was staged, never enumerated.** ADR 0064 Decision §3
   committed only to "the membership-gated group surfaces", with
   "history/delegations/kv and the ratchet lifecycle epoch token … explicitly
   enumerated as the follow-on review". That enumeration is this ADR. The
   #732 tip census is confirmed on this tree: `grep -c quarantin` returns **0**
   for both `src/server/routes/history.rs` and `src/server/delegations.rs`.

A source census on the current tree (tip `252c3fb`, v0.45.0 lineage) produced
the coverage map in Decision §1. It corrects the packet/issue premise in one
direction: **KV is already partially gated** — six sites across
`src/server/routes/stores.rs` (`:807`, `:1191`, `:2054`) and
`src/groups/kv_context.rs` (`:122`, `:364`, `:376`), which are map rows 7–12 —
a surface ADR 0064 listed as undecided. It confirms the premise in the other:
**no lifecycle epoch token exists anywhere** — `lifecycle_epoch`, `epoch_token`
and `LifecycleEpoch` have zero hits across `src/`.

> **Evidence-provenance note (fail loud).** The design/evidence packet
> `.planning/472-remaining-adr-packet.md` referenced by #732 **could not be
> recovered**. The named archive
> `_salvage-20260918/x0x/x0x-472-design` contains only a verified four-commit
> bundle of the ADR-0064 drafting rounds (`427bf1b`…`89a9ffb`, base `3030de4`)
> and records `dirty_untracked=0`; the packet is in no commit, no tree, and no
> other salvage directory. This ADR is therefore drafted from **ADR 0064 plus a
> first-hand source census**, not from the packet. Every claim below is anchored
> to `file:line` on the current tree and is independently re-checkable. Any §§4–7
> scope statement the packet made that is not reproduced here was not available
> to the drafter — a reviewer holding the packet must diff it against this ADR
> before ratification.

## Decision Drivers

- The staged boundary in ADR 0064 is now the *whole* residual risk: a
  quarantined owner-axis group still serves history, still grants and honours
  delegations, and still publishes signed-public bootstrap snapshots. The
  marker contains six route surfaces and leaks through at least nine others.
- Containment must not destroy forensics. History is the ADR-0023 durable local
  record and the primary post-hoc artefact for a fork; refusing reads on it
  would delete the operator's only view of the incident at the moment it
  matters most.
- Ordinary groups are the *majority* population and have no owner key by
  construction. Any anchor invented for them must not smuggle back the quorum
  model ADR 0064 rejected (Option 6) nor the automated eviction it rejected
  (Option 3).
- Gate placement must survive the gap between an authorization check and the
  irreversible act it authorizes. Several shipped KV gates bind a *cached*
  authorization snapshot (`kv_context.rs:109`, `:360`), so a marker installed
  after the bind is not re-consulted by work already in flight.
- No fleet-wide propagation. ADR 0064 Decision §3's per-node scope is load-
  bearing and is inherited unchanged; nothing here makes a marker travel.

## Considered Options

**Option 1 — Leave ordinary groups unmarked (status quo).**
Ordinary groups keep evidence + diagnostics only; the marker stays owner-axis.
*Rejected:* it is precisely the state #472's triage forbade ("no fake closure
from observability"), and it makes ADR 0064's own Decision §3 text —
`quarantine_no_anchor`, indefinite preservation, manual recovery — a
description of code that does not exist. The inconsistency between ADR and
implementation is itself a defect.

**Option 2 — Extend the persistent marker to ordinary groups with
`no_anchor: true`, cleared only by the existing manual endpoint.**
Drop the `owner_certified_user_id()?` fence at `named_groups.rs:3733`, set
`no_anchor = true` when the policy has no owner axis, and let the already-
shipped `POST /groups/:id/quarantine/clear` (`named_groups.rs:12510`,
`fork_quarantine_manual_clears`) be the only exit.
*Accepted as Decision §2.* It uses the field ADR 0064 already reserved for this
case and the endpoint already built for it; it adds no new anchor, no new key,
no new wire surface, and no automatic clear — so it cannot recreate the
undecidable-sibling eviction.

**Option 3 — Founder/creator-key anchor for ordinary groups.**
Treat the group creator's agent key as a weak canonical anchor: a commit
carrying a founder signature clears the marker.
*Rejected as a decision, retained as Open Question 1.* The founder is an
ordinary member with no special custody, is frequently the first party to
leave, and a compromised or coerced founder key becomes an unreviewable
eviction oracle. It is, however, the only candidate anchor that does not
require quorum, and David may judge the availability trade worth it.

**Option 4 — Quorum or convergence anchor for ordinary groups.**
*Rejected, restating ADR 0064 Option 6 and the r4 removal:* flat-admin groups
have no membership floor; a two-member group's quorum is the attacker; and
"two successive valid commits on the contested ancestry" satisfies any
convergence rule. Nothing has changed to reopen this.

**Option 5 — Gate every enumerated data-plane path uniformly with the
existing 409 `fork_quarantined`.**
*Rejected as stated:* applied to history reads it destroys the forensic record
(see Drivers); applied to inbound metadata apply it would prevent the anchored
clearing commit from ever arriving — the trap `reject_fork_quarantined`'s own
doc comment (`named_groups.rs:19904`) already warns about.

**Option 6 — Per-path disposition (refuse / annotate / re-check), enumerated.**
Classify every data-plane path into `refuse` (write and authority paths),
`annotate` (read and forensic paths, which serve but carry an explicit
`fork_quarantined: true` field), and `re-check` (long-running paths that must
re-validate under the persist lock).
*Accepted as Decision §3.* It is the only option that contains authority
without blinding the operator.

**Option 7 — New monotonic `lifecycle_epoch` field on `GroupInfo`.**
*Rejected in favour of a compound token, see Decision §4 and Open Question 4:*
a new persisted field is a new serde surface, a new #470 full-equality
participant, and a new bootstrap-strip obligation, to carry information
`state_revision` plus a quarantine generation counter already carries.

## Decision

### §1 — Coverage map (normative; every data-plane path enumerated)

Census base: current tree, tip `252c3fb`. "Gated" means the path consults
`GroupInfo::is_fork_quarantined()` (`src/groups/mod.rs:636`) or the
`fork_quarantine` field directly on the path that performs the act.

| # | Data-plane path | Anchor (`file:line`) | Gated today? | Decision |
|---|---|---|---|---|
| 1 | `POST /groups/:id/send` — signed-public outbound send | `named_groups.rs:13113`, gate `:13178` | **Yes** (409) | Keep; add §4 re-check before publish |
| 2 | TreeKEM group encrypt | `named_groups.rs:22778`, gate `:22799` | **Yes** (409) | Keep; add §4 re-check |
| 3 | TreeKEM group decrypt | `named_groups.rs:22885`, gate `:22905` | **Yes** (409) | Keep |
| 4 | `POST /groups/:id/secure/encrypt` (GSS) | `named_groups.rs:22967`, gate `:22986` | **Yes** (409) | Keep; add §4 re-check |
| 5 | `POST /groups/:id/secure/decrypt` (GSS) | `named_groups.rs:23177`, gate `:23193` | **Yes** (409) | Keep |
| 6 | `POST /groups/:id/secure/reseal` (GSS) | `named_groups.rs:23337`, gate `:23356` | **Yes** (409) | Keep; add §4 re-check |
| 7 | TreeKEM group-store resolution | `stores.rs:1180`, gate `:1191` | **Yes** (409 `group is unavailable`) | Keep |
| 8 | TreeKEM group-store live info re-read | `stores.rs:796`, gate `:807` | **Yes** (`KvError::Unauthorized`) | Keep — this is the closest shipped analogue of §4 |
| 9 | KV group-writer predicate | `stores.rs:2051`, gate `:2054` | **Yes** | Keep |
| 10 | Signed-public KV authorization snapshot | `kv_context.rs:109`, gate `:122` (`valid`) | **Yes**, but **bind-time only** | Keep; §4 re-check at delta apply |
| 11 | TreeKEM KV authorization context construct | `kv_context.rs:360`, gate `:364` | **Yes**, bind-time | Keep |
| 12 | TreeKEM KV authorization context refresh | `kv_context.rs:370`, gate `:376` | **Yes** (clears roster) | Keep — refresh is driven by roster change, not by marker install; §4 makes the marker a refresh trigger |
| 13 | History list / message / search / scopes / stats | `history.rs:116`, `:203`, `:322`, `:397`, `:430` | **No** — zero group-state checks of any kind | **Annotate**, never refuse (§3a) |
| 14 | History purge | `history.rs:464` | **No** | **Refuse** while quarantined (§3a) — purge is irreversible destruction of the forensic record |
| 15 | `POST /groups/:id/delegate` — grant delegation | `delegations.rs:540`; checks `withdrawn` at `:639`, **no** quarantine check | **No** | **Refuse** (409 `fork_quarantined`) (§3b) |
| 16 | `GET /groups/:id/delegations` — list | `delegations.rs:871`; `withdrawn` at `:881` | **No** | **Annotate** (§3b) |
| 17 | Delegation authorization predicate | `delegations.rs:349` (`authorize`), `:413` (`chain_members_active`) | **No** | **Refuse / fail closed** (§3b) — this is an authority path, not a read |
| 18 | Delegated send-as authorization | `delegations.rs:448` (`authorize_send_as`) | **No** | **Refuse / fail closed** (§3b) |
| 19 | Committed-delegation registry rebuild / index | `delegations.rs:252`, `:304` | **No** | **Refuse to index** from a quarantined group (§3b) |
| 20 | Group task-list read/mutate | `tasks.rs:118`, `:157` — membership check only | **No** | **Refuse mutations, annotate reads** (§3c) |
| 21 | Signed-public bootstrap outbox publish | `public_group_bootstrap_outbox.rs:394`, `:627` — `withdrawn` only | **No** | **Refuse** (§3c) — this is outbound publication of contested state |
| 22 | Ratchet / persist lifecycle epoch re-check | **does not exist** (`lifecycle_epoch`/`epoch_token`/`LifecycleEpoch`: 0 hits in `src/`) | **No** | **Introduce** (§4) |
| 23 | File transfer | `files.rs` — no `named_groups` reference at all | **No** | **Out of scope** — the DM-plane protocol of ADR 0055 is not group-state bound; recorded so the enumeration is complete, not to be gated |
| 24 | Inbound metadata / state-commit apply | `named_groups.rs:8922` | **No, deliberately** | **Keep ungated** — the anchored clearing commit must be able to arrive (`named_groups.rs:19904`) |
| 25 | WebSocket fan-out — ADR-0040 `Mention` events for validated group messages and delegation grants on the group topic channel, plus ADR-0023 stored-history backfill on `Subscribe` | `ws.rs:217` (`ws_handler`), event shape `:116`–`:123`, backfill `:145`–`:163` and `:527`; `grep -c quarantin src/server/ws.rs` → **0** | **No** | **Annotate** (§3d) — the live mirror of rows 13 and 16, and it must not be refused for the same forensic reason |
| 26 | History diagnostics | `history.rs:488` | **No** | **Annotate** (§3a) |

**Counts.** 26 enumerated paths: **12 gated** today (1–12), **13 ungated**
(13–23, 25, 26), **1 deliberately ungated** (24).

Dispositions for the 13 ungated, one class each (no row is counted twice):

| Disposition | Rows | Count |
|---|---|---|
| **Refuse** (409 `fork_quarantined`) | 14, 15, 17, 18, 19, 21 | 6 |
| **Split** — mutations refuse, reads annotate | 20 | 1 |
| **Annotate** only | 13, 16, 25, 26 | 4 |
| **Introduce** a new mechanism | 22 | 1 |
| **Out of scope** | 23 | 1 |

*Exhaustiveness caveat (scope, not oversight).* Row 25 was missed by the first
draft of this map and found in cross-model review. A map that calls itself
normative must be defended by a test, not by a reading — hence the
exhaustiveness fixture in Validation, which is the only durable guarantee that
a route added later cannot silently join the ungated set. Row 25's WS
`Publish { topic, payload }` verb (`ws.rs:152`) is a raw gossip-topic publish,
not a group-scoped send, and is therefore **not** part of this row; it is
covered by row 1 only when a client routes through `POST /groups/:id/send`.

**The count that matters.** For **ordinary (non-owner-axis) groups the gated
count is 0 of 26**, because `named_groups.rs:3733` prevents the marker from
ever being set. Gates 1–12 are unreachable for that population. This is the
single largest finding of the census and is what Decision §2 repairs.

### §2 — Ordinary groups receive the marker with `no_anchor: true`; manual clear only

Remove the `owner_certified_user_id()?` early return at
`named_groups.rs:3733` so that authenticated fork evidence installs a marker
for **every** group, and set `no_anchor = true`
(`named_groups.rs:3744`, field reserved at `src/groups/mod.rs:280`) whenever
the group's policy has no owner axis.

- **Trigger is unchanged.** Only evidence that already passed
  `evaluate_fork_evidence_candidate` and the ADR-0059 dedup installs a marker.
  No new trigger, no new evidence class, no relaxation of authentication.
- **Clear is manual and only manual.** A `no_anchor` marker is **never**
  cleared by any commit, of any revision, on any ancestry. The only exit is the
  shipped `POST /groups/:id/quarantine/clear` (`named_groups.rs:12510`),
  counted by `fork_quarantine_manual_clears`.

  **Enumerated clear sites and their treatment under `no_anchor` (normative —
  the first draft of this ADR named the wrong arm and is corrected here):**

  | Site | What it is | Treatment |
  |---|---|---|
  | `named_groups.rs:4142` (`try_adopt_member_added_across_gap`) | Owner-anchored clear via the owner-signed head attestation CAS on adoption; already fenced by `owner_certified_user_id().is_some()` at `:4136` and by strict revision at `:4140` | Must test `no_anchor` and **decline**. The existing owner-axis fence already excludes ordinary groups, so this is belt-and-braces — but the fence is a *policy* test and `no_anchor` is the *marker's own* claim, and §2 makes the marker's claim authoritative. |
  | `named_groups.rs:9554` (`apply_named_group_metadata_event_inner`) | Owner-anchored clear via a mandate-carrying `MemberAdded` that verifies; strict revision at `:9556`; counts `fork_quarantine_owner_anchored_clears` | Must test `no_anchor` and **decline**. This arm has **no** owner-axis policy fence of its own — it relies on the marker only ever existing for owner-axis groups, an assumption §2 invalidates. **This is the load-bearing change**: without the `no_anchor` test here, extending the marker to ordinary groups would hand them an automatic clear and silently contradict the manual-only rule. |
  | `src/groups/mod.rs:1001` (`clear_fork_quarantine_on_explicit_owner_seal`) | Explicit owner-key seal route, both arms including eviction | Must test `no_anchor` and **decline** — an ordinary group has no owner key, so the route is unreachable for it in practice; the test documents the invariant rather than changing behaviour. |
  | `named_groups.rs:3536`–`:3541` (`rollback_live_fork_evidence`) | **NOT a clear.** This is the retry-rollback arm: it undoes a non-durable install on an exact identity match (revision + state hash + committer, `:3525`–`:3529`) when the mutation that installed it is retried. | **Left exactly as-is — must NOT test `no_anchor`.** Gating it would strand a marker whose evidence was retracted on a benign retry, creating an unclearable quarantine from a transient persist failure. An undo of an install is not a clear, and the manual-only rule in §2 governs clears. |

  The distinction matters because the two categories look identical at the
  call site (`info.fork_quarantine = None`) and differ only in provenance:
  a *clear* asserts the fork was resolved; a *rollback* asserts the install
  never durably happened. Only the former is constrained by §2.
- **`invite_lineage` fence.** The evidence path is currently reached only for
  invite-derived groups (`named_groups.rs:3765`). Ordinary groups formed
  without an invite still record nothing. Widening that fence is **not**
  decided here — see Open Question 2.
- **Scope inherited verbatim from ADR 0064 §3:** per-node, local-only,
  bootstrap-stripped outbound and rejected inbound. Nothing propagates.

*Rejected variant:* auto-clearing a `no_anchor` marker on "sufficient
convergence" — this is ADR 0064's removed r3 convergence quorum and stays
removed.

### §3 — Per-path disposition for the ungated set

**§3a — History (paths 13, 14).** Reads are **never** refused; they gain an
explicit `fork_quarantined: true` field in the response envelope alongside the
marker's `revision` and `observed_at_ms`, so an operator reading history during
an incident can see that the record spans a contested chain. `history_purge`
(`history.rs:464`) **is** refused with 409 `fork_quarantined`: purge destroys
the forensic record ADR 0064 Decision §4 exists to preserve. Whether *ingest*
of new group-scoped history entries should also be refused, or tagged and
retained, is Open Question 3.

**§3b — Delegations (paths 15–19).** Delegation is an authority transfer, not a
read: a quarantined group's roster is exactly the thing under dispute, so
minting new authority from it, or honouring authority derived from it, must
fail closed. `delegate_group_authority` (`delegations.rs:540`) refuses with 409
`fork_quarantined` at the same site as its existing `withdrawn` check
(`:639`); `authorize` (`:349`), `chain_members_active` (`:413`) and
`authorize_send_as` (`:448`) return "not authorized" for a quarantined group;
`index_committed` (`:304`) and `rebuild_global_delegation_registry` (`:252`)
skip quarantined groups so the global registry cannot be seeded from contested
state. `list_group_delegations` (`:871`) continues to serve, annotated.

**§3c — Tasks and outbound publication (paths 20, 21).** Group task-list
mutations refuse; reads annotate. The signed-public bootstrap outbox
(`public_group_bootstrap_outbox.rs:394`, `:627`) refuses to publish a
quarantined group's snapshot at the same predicate that already tests
`withdrawn` — this is the one ungated path that *exports* contested state to
other nodes, and is the highest-severity item in the census after §2.

**§3d — WebSocket fan-out (path 25).** The WS plane is the live mirror of the
annotated read paths: `ws_handler` (`ws.rs:217`) emits ADR-0040 `Mention`
events for validated group messages and delegation grants on the group topic
channel (`:116`–`:123`) and replays ADR-0023 stored history on `Subscribe`
backfill (`:145`–`:163`, `:527`), with zero quarantine consults. It is
**annotated, never refused**, for the same reason as §3a: an operator watching
a live incident must not lose the stream at the moment it matters. The
`fork_quarantined` flag rides the `Mention` envelope and the backfill frames,
so a subscribed client can distinguish contested traffic without a second
round trip. Note that a `Mention` for a *delegation grant* may be annotated as
contested while §3b independently refuses the grant itself — the annotation
describes what was observed, not what was authorized.

**§3e — Typed refusal is uniform.** Every new refusal reuses
`reject_fork_quarantined` (`named_groups.rs:19910`) or its exact contract — 409,
body `fork_quarantined`, one `fork_quarantine_refusals` increment
(`diagnostics.rs:150`) — so that a single diagnostic counts the whole
data-plane. No new error code, no new counter per route.

### §4 — Lifecycle epoch token as a compound value, re-checked under the persist lock

No new persisted field. The token is the tuple
`(state_revision, quarantine_generation)`, where `quarantine_generation` is a
process-local monotonic `u64` on the group entry, incremented on every marker
install and every clear (manual, owner-anchored, or explicit seal). A path that
performs an irreversible act — ratchet advance, persist, cache write, or
outbound publish — captures the token at its authorization check and
re-validates it inside the same critical section as the mutation
(`persist_named_groups_mutation_unlocked`, `named_groups.rs:4330`). A mismatch
aborts the act before the irreversible step with the typed 409, leaving state
byte-identical, in the same style as ADR 0064 §1a's isolated-candidate rule.

This closes the bind-time gap in paths 10–12: `kv_context.rs` snapshots
authorization into `PublicState`/`GssState` at `from_group`
(`:109`, `:360`) and only refreshes via `update_from_group` (`:370`), which is
driven by roster change. A marker installed after the bind is invisible to work
already in flight; making marker install a refresh trigger *and* carrying the
generation in the token closes it from both ends. `stores.rs:796`
(`current_info`) is the existing shipped precedent for a per-operation re-read
and is the model to generalize.

Representation is Open Question 4.

## Migration / Compatibility

| Population | Behaviour |
|---|---|
| Owner-axis groups | Unchanged trigger and clear semantics; strictly more routes refuse while marked. |
| Ordinary groups, no evidence | Byte-for-byte unchanged — no marker, no annotation, no refusal. |
| Ordinary groups, authenticated evidence | New: persistent `no_anchor: true` marker, data-plane refusals per §3, manual clear only. This is a **new availability failure mode** for a population that previously degraded silently; see Open Question 5. |
| Mixed fleet | The marker is already a serde-default `GroupInfo` field ignored by older binaries (`src/groups/mod.rs:262`); `no_anchor` is likewise `#[serde(default)]`. Older binaries continue to serve a group this node quarantines — per-node scope, unchanged from ADR 0064. |
| Bootstrap / signed-public snapshots | Marker and snapshot remain stripped outbound and rejected inbound. §3c additionally suppresses the whole snapshot while quarantined. |
| Annotation fields | Purely additive response fields; no client is required to read them. |

## Attack / Regression matrix

| Scenario | Today (v0.45.0) | This design |
|---|---|---|
| Ordinary-group equal-revision fork | No marker; every route serves both branches | Marker with `no_anchor`; data-plane refuses; operator-visible |
| Quarantined owner-axis group grants a delegation | Succeeds (`delegations.rs:540` checks only `withdrawn`) | Refused (§3b) |
| Delegated send-as from a contested roster | Honoured (`delegations.rs:448`) | Fails closed (§3b) |
| Quarantined group's snapshot published to the fleet | Published (`public_group_bootstrap_outbox.rs:394`) | Suppressed (§3c) |
| Operator investigating a live fork | History serves, unlabelled | History serves, labelled `fork_quarantined` (§3a) |
| WS client watching a quarantined group | Mentions and backfill stream unlabelled (`ws.rs:217`) | Stream continues, every frame labelled (§3d) |
| Marker retracted by a benign persist retry | Rolled back (`named_groups.rs:3541`) | Unchanged — rollback is not a clear (§2 table) |
| Operator/attacker purges evidence mid-incident | Permitted | Refused (§3a) |
| Marker installed mid-operation on a bound KV store | Cached snapshot still authorizes | Token mismatch aborts before persist (§4) |
| Anchored clearing commit arrives at a quarantined node | Applies (apply path ungated) | Unchanged — deliberately still applies (path 24) |
| Ordinary group stranded after a benign split | n/a | Manual clear required — accepted cost, Open Question 5 |
| False quarantine | Bounded by authenticated-evidence-only trigger | Same trigger; blast radius now larger by design |

## Consequences

### Positive

- The data plane is enumerated rather than asserted: 26 paths, each with a
  `file:line` anchor and a disposition, re-checkable by any reviewer.
- The largest silent gap — ordinary groups being completely uncontained
  despite ADR 0064's text claiming otherwise — is named and closed.
- Authority paths (delegation, outbound publication) fail closed; forensic
  paths (history reads) stay open. Containment does not cost visibility.
- No new anchor, no new key custody, no new wire surface, no fleet propagation.

### Negative / Trade-offs

- A new availability failure mode for ordinary groups with **no automatic
  exit**: a benign network split that produces authenticated conflicting
  commits now strands the group until an operator calls the manual clear.
- Blast radius of a false positive grows from the 6 shipped route surfaces
  (rows 1–6) to 19 refusing or split surfaces once §3 lands.
- §4 adds a re-check to hot paths (KV delta apply, send, encrypt); the cost is
  a compare under a lock already taken, but it is on every operation.
- History annotation is an additive response-shape change across seven
  handlers.

### Neutral / Operational

- The manual clear endpoint becomes load-bearing for ordinary groups and needs
  a runbook entry, not just an API reference line.
- `fork_quarantine_refusals` becomes a fleet-health signal rather than a niche
  counter; alerting thresholds should be set before rollout.
- Still explicitly **not** decided here: automated eviction (rejected by ADR
  0064 §3/Option 3), quorum anchors (Option 4 above), the #639 alternate-chain
  fetch surface, the #646 content-addressed base snapshot, and any change to
  OwnerMandate or owner-axis quarantine.

## Open questions for David

1. **Founder-key anchor for ordinary groups?** Option 3 is the only non-quorum
   anchor available. *Recommendation:* no — manual clear only (§2). The founder
   has no special custody and a compromised founder key becomes an eviction
   oracle. Reopen only if the manual-clear availability cost proves intolerable
   in practice.
2. **Widen the `invite_lineage` fence (`named_groups.rs:3765`)?** Ordinary
   groups formed without an invite currently reach no evidence path at all, so
   §2 does not cover them. *Recommendation:* widen it in the same change, so
   "ordinary group" means one population rather than two. Flagged because it
   enlarges the trigger surface, which §2 otherwise promises not to touch.
3. **History ingest while quarantined — refuse or tag-and-retain?**
   *Recommendation:* tag and retain. Refusing ingest creates a gap in the
   record precisely across the incident window, which contradicts §3a's reason
   for existing.
4. **Epoch token representation — compound `(state_revision,
   quarantine_generation)` or a new persisted `lifecycle_epoch` field?**
   *Recommendation:* compound (§4). A new field is a new serde surface, a new
   #470 full-equality participant, and a new bootstrap-strip obligation for
   information already derivable.
5. **Rollout posture for the new ordinary-group refusals — warn-only first
   release, or fail-closed immediately?** *Recommendation (revised after
   cross-model review — a blanket warn-only window was unsafe as first
   drafted):* **split by reversibility, not by population.**
   - **Fail closed immediately**, with no warn-only window, for every path
     whose act is irreversible or outlives the window: history purge (row 14 —
     destroys the forensic record ADR 0064 §4 exists to preserve), delegation
     minting and honouring (rows 15, 17, 18 — authority granted during the
     window survives the window), registry seeding (row 19), and signed-public
     bootstrap publication (row 21 — exports contested state to other nodes,
     which cannot be recalled).
   - **Warn-only for one release** (annotate + count
     `fork_quarantine_refusals`, do not refuse) for task mutations (row 20),
     which are CRDT-recoverable, and for the purely additive annotations
     (rows 13, 16, 25, 26), which refuse nothing in either posture.

   The original blanket recommendation traded containment for availability
   uniformly; the defect is that "warn-only" is only a *deferral* for a
   reversible act, but a *permanent grant* for an irreversible one. Owner-axis
   behaviour is unchanged throughout. Still an open question because the split
   itself — and whether row 20 deserves even one release of grace — is David's
   call, not the drafter's.

## Validation

- **Design-level (this ADR):** the §1 coverage map is a first-hand census with
  `file:line` anchors on tip `252c3fb`; every "no" row is a negative result a
  reviewer can reproduce (`grep -c quarantin src/server/routes/history.rs` → 0;
  `… src/server/delegations.rs` → 0; `lifecycle_epoch|epoch_token|LifecycleEpoch`
  across `src/` → 0). The packet-absence note above is part of the record.
- **Implementation (future PRs, each with its own gates):**
  - An **exhaustiveness test** over the §1 table: a fixture that installs a
    marker and asserts the disposition of every one of the 26 paths, so a new
    data-plane route added later fails the test until it is classified. This
    fixture is not optional garnish: row 25 was missed by the first draft of
    the map and caught only in cross-model review, which is direct evidence
    that a hand-maintained enumeration degrades.
  - Ordinary-group fixtures: authenticated evidence installs a `no_anchor`
    marker; a valid higher-revision commit on **any** ancestry does **not**
    clear it; the manual endpoint does.
  - **Clear-arm discrimination fixtures (§2 table), one per site:** a
    `no_anchor` marker survives an owner-anchored adoption clear
    (`named_groups.rs:4142`), survives a mandate-carrying `MemberAdded`
    (`:9554` — the arm with no independent owner-axis fence, so this is the
    fixture that would have caught the bug), and survives an explicit owner
    seal (`src/groups/mod.rs:1001`); **and, in the opposite direction**, a
    `no_anchor` marker installed by a mutation that is then retried IS rolled
    back by `rollback_live_fork_evidence` (`:3536`–`:3541`) on exact identity
    match — asserting that the rollback arm was NOT gated, since gating it
    would strand the group on a transient persist failure.
  - Negative control inherited from ADR 0064: the contested branch's own valid
    commits never clear an owner-axis marker.
  - §3b fail-closed fixtures for `authorize`, `authorize_send_as` and registry
    indexing, each asserting the group is contested rather than merely absent.
  - §3c fixture: a quarantined group's signed-public snapshot is absent from
    the outbox, and reappears after a clear.
  - §3d fixture: a WS subscriber receives `Mention` events and ADR-0023
    backfill frames for a quarantined group — the stream is **not** cut — and
    every frame carries `fork_quarantined: true`.
  - §4 race fixture: install a marker between a KV authorization bind and its
    delta apply; assert the apply aborts with state byte-identical.
  - Mixed-version serde fixtures both directions for `no_anchor`.
  - The four ordered Rust gates on the final tree.
- **Review trigger:** if #639 or #646 land an alternate-chain fetch or a
  content-addressed base, re-examine §4's token — both introduce new
  irreversible steps that would need to capture it.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human
review**. Accepted ADRs are immutable: create a new superseding ADR rather than
editing an Accepted ADR. This draft was produced by Claude Opus without the
referenced design packet and requires cross-model (omp) review plus David's
ratification of the five open questions before any implementation begins.
