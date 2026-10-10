# ADR 0066: Ordinary-Group Fork Anchors and Data-Plane Quarantine Coverage

- **Status:** Accepted
- **Date:** 2026-09-18 (proposed); 2026-09-19 (accepted)
- **Decision owners:** David Irvine (direction), Claude Opus (design drafting)
- **Reviewers:** omp / GLM-5.3 — cross-model review, 2 rounds (round 1 REQUEST-CHANGES on the §2 clear-arm set, the missing WS row, and the OQ5 recommendation; round 2 APPROVE-WITH-NITS); David Irvine — ratified 2026-09-19, overriding the OQ5 recommendation (see Ratified decisions §5)
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
*Rejected as a decision; raised as Open Question 1 and settled by R1 (no
founder anchor).* The founder is an
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
*Rejected in favour of a compound token, see Decision §4; confirmed by R4:*
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
- **`invite_lineage` fence — widened by R2.** The evidence path today is
  reached only for invite-derived groups (`named_groups.rs:3765`), so ordinary
  groups formed without an invite record nothing. R2 ratifies widening that
  fence in slice 2, so "ordinary group" is one population rather than two.
  Consequently this ADR's "the trigger is unchanged" statement above is scoped
  to how evidence is *authenticated*, not to which groups can reach the
  evidence path — that set grows.
- **Scope inherited verbatim from ADR 0064 §3:** per-node, local-only,
  bootstrap-stripped outbound and rejected inbound. Nothing propagates.

*Rejected variant:* auto-clearing a `no_anchor` marker on "sufficient
convergence" — this is ADR 0064's removed r3 convergence quorum and stays
removed.

### §3 — Per-path disposition for the ungated set

**Posture (R5).** Every refusal below is **effective immediately in the release
that ships its slice** — there is no warn-only window, no grace period and no
per-row phasing, for ordinary and owner-axis groups alike. Every refusal carries
the §5 informational message. The annotate-class rows refuse nothing and are
unaffected by R5.

**§3a — History (paths 13, 14).** Reads are **never** refused; they gain an
explicit `fork_quarantined: true` field in the response envelope alongside the
marker's `revision` and `observed_at_ms`, so an operator reading history during
an incident can see that the record spans a contested chain. `history_purge`
(`history.rs:464`) **is** refused with 409 `fork_quarantined`: purge destroys
the forensic record ADR 0064 Decision §4 exists to preserve. Ingest of new
group-scoped history entries is **tagged and retained, never refused** (R3) —
refusing it would blank the record across the incident window, which is the
opposite of §3a's purpose.

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
machine code `fork_quarantined`, one `fork_quarantine_refusals` increment
(`diagnostics.rs:150`) — so that a single diagnostic counts the whole
data-plane. No new error code, no new counter per route. Under R5 that shared
helper is also the single place the §5 message is built, so no route can refuse
without explaining itself and no two routes can drift in wording.

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

Representation is settled by R4: compound, no new persisted field.

### §5 — The refusal must explain itself (mandatory; added by R5)

R5 removed the warn-only window on the condition that a user always learns why
an operation was refused. This section is that contract. It is normative for
every refusal this ADR adds, and a slice that ships a refusal without it is
incomplete.

**What ships today is a bare code.** `reject_fork_quarantined`
(`named_groups.rs:19910`) returns
`api_error(StatusCode::CONFLICT, "fork_quarantined")` at `:19919`. `api_error`
(`src/server/mod.rs:2454`) builds `{ "ok": false, "error": <msg> }`, so the
entire user-visible payload is the string `fork_quarantined` — a machine code in
the human field, with no explanation and no remedy. For owner-axis groups that
was tolerable because the marker cleared automatically on the next
owner-anchored advance. Under R5 it is not: an ordinary group's marker never
auto-clears, so a bare code becomes a permanent, unexplained refusal.

**The contract.** Refusals move to `api_error_with_reason`
(`src/server/mod.rs:2465`), which exists for exactly this case — its own doc
comment says "adds a machine-readable `reason` field … Use when two responses
share an HTTP status yet must stay machine-separable (e.g. two distinct 409
CONFLICT conditions)". The response body becomes:

| Field | Value | Role |
|---|---|---|
| `ok` | `false` | unchanged |
| `reason` | `fork_quarantined` | **the stable machine code** — clients match on this |
| `error` | human-readable sentence naming the condition, why the operation is refused, and the remedy | the informational message R5 requires |
| `fork_quarantine.revision` | evidenced fork revision | which divergence |
| `fork_quarantine.observed_at_ms` | local observation time | when this node saw it |
| `fork_quarantine.no_anchor` | `true` for ordinary groups | says plainly that nothing will clear this automatically |
| `fork_quarantine.clear_with` | `POST /groups/:id/quarantine/clear` | the remedy, machine-readable |

The `error` sentence must state all three of: the group is fork-quarantined on
this node; the operation was refused because the roster is contested; and that
the exit is the manual clear (naming `x0x groups quarantine clear` for CLI
users). A message that names the condition but not the remedy does not satisfy
R5 — "actionable" is the acceptance bar, and the Validation fixtures assert it.

**Where it is surfaced.**
- **REST** — the body above, on every refusing row (14, 15, 17, 18, 19, 20-mutations, 21).
- **CLI** — `src/cli/commands/groups.rs` already owns
  `quarantine_clear` (`:85`, documented `:81`–`:84`); the refusal path prints the
  `error` sentence and the `clear_with` remedy rather than a raw status code.
- **WS** — `WsOutbound::Error { message }` (`ws.rs:134`–`135`) carries the same
  sentence. Note this variant has only a `message` field, so the machine code
  must be carried inside the annotation on the affected frames (§3d), not in
  the error variant.
- **GUI** — `grep -c quarantin src/gui/*.html` → **0** today; the embedded GUI
  renders the `error` sentence wherever it renders other 409s.
- **Diagnostics** — unchanged: one `fork_quarantine_refusals` increment
  (`diagnostics.rs:150`) per refusal, per §3e.

**Compatibility cost, stated plainly.** Moving the machine code from `error` to
`reason` changes the `error` field's content from `fork_quarantined` to prose.
Three existing tests assert the old shape —
`named_groups/tests/hs_f2_membership_cluster.rs:5226` and `:5338`, and
`named_groups/tests/adr0038_owner_certified.rs:1509`, each
`assert_eq!(body["error"].as_str(), Some("fork_quarantined"))` — and must be
updated to assert `body["reason"]` plus a non-empty, remedy-bearing `error`.
Any out-of-tree client matching the literal `error == "fork_quarantined"` sees a
one-time break; `reason` is the field to match from now on. This is a deliberate
cost of R5, not an incidental refactor.

## Migration / Compatibility

| Population | Behaviour |
|---|---|
| Owner-axis groups | Unchanged trigger and clear semantics; strictly more routes refuse while marked. |
| Ordinary groups, no evidence | Byte-for-byte unchanged — no marker, no annotation, no refusal. |
| Ordinary groups, authenticated evidence | New: persistent `no_anchor: true` marker, data-plane refusals per §3 **effective immediately** (R5 — no warn-only window), manual clear only. This is a **new availability failure mode** for a population that previously degraded silently; the §5 message is what makes it diagnosable rather than mysterious. |
| **Upgraded node meeting an already-diverged ordinary group** | The marker is set by *evidence*, not by a startup scan, and evidence is produced on the apply path (`named_groups.rs:3756`). So on first start the group is **not** retroactively quarantined: nothing is marked until the next authenticated conflicting commit arrives, at which point the marker installs and refusals begin **at once**, with no grace. The practical consequence is a group that worked before the upgrade can begin refusing minutes after it, on the first conflicting commit — which is precisely why R5 required §5. Operators should expect `fork_quarantine_set` to rise on the upgrade wave for groups that were already silently forked. |
| Already-quarantined owner-axis groups on upgrade | Marker persists (it always did); the newly gated rows begin refusing immediately, and the refusal text changes from the bare code to the §5 sentence. |
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
| Ordinary group stranded after a benign split | n/a | Manual clear required — accepted cost (R1/R5); the §5 message names the remedy so the operator is not left guessing |
| Upgraded node, ordinary group already silently forked | Serves both branches indefinitely | No retroactive scan; refuses from the next authenticated conflicting commit, immediately and with no grace (R5) |
| User hits a refusal and cannot tell why | n/a — bare `fork_quarantined` code today (`named_groups.rs:19919`) | §5: machine `reason` + human sentence naming condition, cause and remedy across REST/CLI/WS/GUI |
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
- **R5's cost, accepted deliberately: refusals land on upgrade with no grace.**
  An ordinary group that was already silently forked begins refusing on the
  first authenticated conflicting commit after the upgrade — no warn-only
  release softens the landing, and because the marker is `no_anchor` nothing
  clears it but a human. This is the sharpest edge in the whole design and is
  the direct reason §5 is mandatory rather than advisory: the mitigation for
  an abrupt refusal is not a delay, it is an explanation the user can act on.
- Blast radius of a false positive grows from the 6 shipped route surfaces
  (rows 1–6) to 19 refusing or split surfaces once §3 lands, and it grows on
  the first release rather than over two.
- The §5 shape change moves the machine code from `error` to `reason`, breaking
  any client matching the old literal (three in-tree tests, listed in §5).
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

## Ratified decisions (2026-09-19)

The five questions this ADR left open for David are settled. Four were ratified
as recommended; **the fifth was overridden**, and the override is the reason
§5 (the message contract) exists at all.

**R1 — No founder-key anchor for ordinary groups.** *As recommended.* Manual
clear only (§2). The founder has no special custody and a compromised founder
key would become an unreviewable eviction oracle. Reopen only if the
manual-clear availability cost proves intolerable in practice.

**R2 — Widen the `invite_lineage` fence (`named_groups.rs:3765`).** *As
recommended.* Ordinary groups formed without an invite are covered too, so
"ordinary group" means one population rather than two. This deliberately
enlarges the evidence trigger surface; §2's "trigger is unchanged" promise is
therefore scoped to the *authentication* of evidence, not to the set of groups
that can reach the evidence path.

**R3 — History ingest is tag-and-retain, never refused.** *As recommended.*
Refusing ingest would create a gap in the record precisely across the incident
window, contradicting §3a's reason for existing. Row 14 (purge) is still
refused; ingest is not purge.

**R4 — Compound epoch token.** *As recommended.* `(state_revision,
quarantine_generation)` per §4, with no new persisted `lifecycle_epoch` field —
no new serde surface, no new #470 full-equality participant, no new
bootstrap-strip obligation for information already derivable.

**R5 — Fail closed immediately on every gated path, with an informational
message. DAVID OVERRODE THE RECOMMENDATION.** The ADR recommended splitting by
reversibility and granting task mutations (row 20) plus the annotations one
warn-only release. David chose **no warn-only window anywhere**: every path
this ADR gates refuses from the first release that ships it, including row 20.

The condition attached to the override is substantive, not cosmetic: **the
refusal must tell the user what happened.** A silent 409 on a group that worked
yesterday is an unexplained outage; the same refusal carrying "this group is
fork-quarantined, here is why operations are refused, here is how to clear it"
is a diagnosis. **§5 specifies that contract and is a mandatory part of every
slice that adds a refusal** — a slice that adds a refusal without its message
is incomplete, not merely unpolished.

Annotate-class rows (13, 16, 20-reads, 25, 26) remain annotations. They refuse
nothing, so the warn-only question never applied to them; R5 does not convert
them into refusals.

*Why the override is defensible against the drafter's own argument:* the ADR
argued warn-only was safe for row 20 because CRDT task mutations are
recoverable. That is true of the *data* and false of the *authority* — a task
mutation accepted on a contested roster is still an act taken under disputed
membership, and "recoverable" describes the cleanup, not the exposure. The
split also asked operators to hold two mental models of one marker for one
release. One rule plus a clear message is simpler and stricter.

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
  - **§5 message fixtures (R5's acceptance bar — a refusal without its message
    is a failing test, not a cosmetic gap).** For **every** refusing row:
    `body["reason"] == "fork_quarantined"`; `body["error"]` is non-empty, is
    **not** equal to the machine code, and mentions both the quarantine
    condition and the clear remedy; `body["fork_quarantine"]` carries
    `revision`, `observed_at_ms`, `no_anchor` and `clear_with`. A negative
    control asserts a refusal built without the message helper fails the
    suite — the message must be structurally impossible to omit, since §3e
    makes one helper the only refusal path. A CLI fixture asserts the printed
    output contains the remedy and not a raw status code. The three existing
    `body["error"] == "fork_quarantined"` assertions
    (`hs_f2_membership_cluster.rs:5226`, `:5338`,
    `adr0038_owner_certified.rs:1509`) are migrated to the new shape in the
    same slice.
  - **R5 no-grace fixture:** a refusing row refuses on the *first* request
    after the marker installs — there is no request budget, counter threshold
    or elapsed-time window that permits one through. This is the regression
    test for the rejected warn-only design, so a future re-introduction of
    grace fails loudly rather than silently weakening containment.
  - §4 race fixture: install a marker between a KV authorization bind and its
    delta apply; assert the apply aborts with state byte-identical.
  - Mixed-version serde fixtures both directions for `no_anchor`.
  - The four ordered Rust gates on the final tree.
- **Review trigger:** if #639 or #646 land an alternate-chain fetch or a
  content-addressed base, re-examine §4's token — both introduce new
  irreversible steps that would need to capture it.

## Implementation slices

Ordered, each PR-sized and independently reviewable. Every slice carries the
four ordered Rust gates.

**Ordering constraint (normative).** §5's message is not a trailing slice: any
slice that adds a refusal — or that makes an existing refusal reachable by a new
population — must ship that refusal's message. **The message contract is
therefore slice 1**, ahead of everything, and slices 3–6 each depend on it. The
epoch-token slice depends on the marker slice.

*Why this order and not the obvious one:* an earlier draft put the ordinary-group
marker first. Cross-model review found that this would make rows 1–6 newly
refusing for ordinary groups while the refusal still carried the bare machine
code — and because a `no_anchor` marker never auto-clears, the result is a
**permanent unexplained refusal**, exactly the state §5 declares intolerable.
The marker slice has no dependency the message slice needs, so the message goes
first. This ordering is part of the decision, not a scheduling preference.

**Slice 1 — §5 refusal message contract.**
*Scope:* move `reject_fork_quarantined` (`named_groups.rs:19910`) to
`api_error_with_reason` (`src/server/mod.rs:2465`) with the §5 body; surface it
in the CLI (`src/cli/commands/groups.rs`) and the GUI; migrate the three
existing `body["error"]` assertions.
*Files:* `src/server/routes/named_groups.rs`, `src/cli/commands/groups.rs`,
`src/gui/`, the three test files named in §5.
*Tests:* §5 message fixtures for rows 1–6 (the already-refusing owner-axis
set); the no-grace fixture; CLI output fixture.
*Rows closed:* none new — it re-shapes the existing six so every later slice,
and every newly reachable population, inherits the message for free.
*Depends on:* nothing.

**Slice 2 — Marker for ordinary groups + exhaustiveness fixture.**
*Scope:* remove the `owner_certified_user_id()?` early return at
`named_groups.rs:3733`; set `no_anchor = true` when the policy has no owner
axis (`:3744`); widen the `invite_lineage` fence at `:3765` per R2; add the
`no_anchor` decline test to the three owner-anchored clear sites
(`:4142`, `:9554`, `src/groups/mod.rs:1001`) and **leave the rollback arm
`:3536`–`:3541` untouched**.
*Files:* `src/server/routes/named_groups.rs`, `src/groups/mod.rs`.
*Tests:* the §1 exhaustiveness fixture (26 rows, fails on any unclassified
route); clear-arm discrimination fixtures in both directions; `no_anchor`
serde round-trip and mixed-version fixtures; and — because this slice is what
makes rows 1–6 refuse for ordinary groups — a fixture asserting those refusals
carry the slice-1 message with `no_anchor: true` surfaced in it.
*Rows closed:* none directly — this slice makes rows 1–12 **reachable** for
ordinary groups, which is the whole point of the ADR; it changes 0-of-26 to
12-of-26 for that population.
*Depends on:* slice 1 (a refusal this slice makes reachable must already
explain itself).

**Slice 3 — Delegations fail closed (§3b).**
*Scope:* quarantine checks in `delegate_group_authority` (`delegations.rs:540`,
beside the `withdrawn` check at `:639`), `authorize` (`:349`),
`chain_members_active` (`:413`), `authorize_send_as` (`:448`),
`index_committed` (`:304`) and `rebuild_global_delegation_registry` (`:252`);
annotation on `list_group_delegations` (`:871`).
*Files:* `src/server/delegations.rs`.
*Tests:* fail-closed fixtures per predicate asserting *contested* rather than
merely absent; registry-seeding fixture; §5 message on each refusal.
*Rows closed:* **15, 16, 17, 18, 19.**
*Depends on:* slice 1.

**Slice 4 — History purge refused, reads and ingest annotated (§3a, R3).**
*Scope:* refuse `history_purge` (`history.rs:464`); add the
`fork_quarantined` annotation to `history_list` (`:116`), `history_message`
(`:203`), `history_search` (`:322`), `history_scopes` (`:397`),
`history_stats` (`:430`) and `history_diagnostics` (`:488`); tag-and-retain on
ingest.
*Files:* `src/server/routes/history.rs`.
*Tests:* purge refused with the §5 message; every read still serves and is
annotated; ingest retained and tagged (the R3 fixture).
*Rows closed:* **13, 14, 26.**
*Depends on:* slice 1.

**Slice 5 — Bootstrap publication and task mutations (§3c).**
*Scope:* suppress a quarantined group's signed-public snapshot at the existing
`withdrawn` predicates (`public_group_bootstrap_outbox.rs:394`, `:627`); refuse
group task-list mutations and annotate reads (`tasks.rs:118`, `:157`).
*Files:* `src/server/routes/public_group_bootstrap_outbox.rs`,
`src/server/routes/tasks.rs`.
*Tests:* snapshot absent while quarantined and present after a clear; task
mutation refused with the §5 message on the *first* attempt (R5, no grace);
task reads annotated.
*Rows closed:* **20, 21.**
*Depends on:* slice 1.

**Slice 6 — WebSocket annotation (§3d).**
*Scope:* carry `fork_quarantined` on `Mention` events (`ws.rs:116`–`:123`) and
ADR-0023 backfill frames (`:145`–`:163`, `:527`); the stream is never cut.
*Files:* `src/server/ws.rs`.
*Tests:* the §3d fixture — subscriber keeps receiving, every frame annotated.
*Rows closed:* **25.**
*Depends on:* slice 1 (annotation only, but the WS plane shares the refusal vocabulary).

**Slice 7 — Compound epoch token (§4, R4).**
*Scope:* process-local `quarantine_generation` incremented on every install and
every clear; capture `(state_revision, quarantine_generation)` at
authorization and re-validate inside
`persist_named_groups_mutation_unlocked` (`named_groups.rs:4330`); make marker
install a refresh trigger for the cached KV contexts (`kv_context.rs:370`).
*Files:* `src/server/routes/named_groups.rs`, `src/groups/kv_context.rs`,
`src/server/routes/stores.rs`.
*Tests:* the race fixture — install a marker between a KV authorization bind
and its delta apply; assert the apply aborts with state byte-identical.
*Rows closed:* **22**, and it closes the bind-time gap in rows 10–12.
*Depends on:* slice 2 (the generation counter must count ordinary-group installs too).

**Slice 8 — Runbook and ops docs.**
*Scope:* the manual-clear runbook entry the Consequences call for; alerting
guidance on `fork_quarantine_set` / `fork_quarantine_refusals`; the upgrade
expectation from the Migration table.
*Files:* `docs/`, SKILL.md as applicable.
*Tests:* n/a (docs), but the runbook must be referenced from the §5 message's
remedy wording.
*Rows closed:* none — it makes R5's "actionable" claim true outside the API.
*Depends on:* slice 1 (the message's remedy wording points at the runbook).

## Notes for AI-assisted work

AI tools may help draft an ADR, but **must not mark it Accepted without human
review**. That review has happened: drafted by Claude Opus (without the
referenced design packet — see the provenance note in Context), reviewed
cross-model by omp / GLM-5.3 over two rounds, and ratified by David Irvine on
2026-09-19 with one recommendation overridden (R5).

**This ADR is now Accepted and therefore immutable.** Do not edit it — including
to "fix" the record of the R5 override, which is deliberate. Any later change of
direction requires a superseding ADR. Implementation proceeds through the
Implementation slices section; a slice that diverges from a Decision or a
Ratified decision needs the superseding ADR first, not a quiet edit here.
