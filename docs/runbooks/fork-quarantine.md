# Fork quarantine runbook (ADR-0064, ADR-0066)

Operator procedures for the persistent fork-quarantine marker and the owner
mandate grace machinery. Everything here is LOCAL, per-node state: a marker
on this daemon says this daemon holds authenticated evidence of a conflicting
group state chain; it is never gossiped, and a member that never received the
evidence has no marker and is not contained (ADR-0064 Decision 3). Design
context: [docs/trust-and-connectivity.md](../trust-and-connectivity.md)
(ADR-0064 sections), [ADR-0064](../adr/0064-owner-anchored-fork-authority.md),
[ADR errata](../adr/README.md) (maintainer decisions of 2026-09-10/11),
issues #468/#469/#472.

Scope: **every group.** ADR-0064 gated owner-axis groups (Home-suite /
`OwnerCertified` admission) only. ADR-0066 §2 extends the marker to ordinary
(non-owner-axis) groups, where it carries `no_anchor: true` and **only the
manual clear lifts it** — see §5.

> **Upgrade expectation (ADR-0066 Migration).** Expect `fork_quarantine_set`
> to RISE on the upgrade wave, for groups that were already silently forked.
> Nothing is quarantined retroactively — there is no startup scan — but the
> first authenticated conflicting commit after the upgrade installs a marker
> on an ordinary group that previously degraded silently, and that group's
> data plane begins refusing at once, with no grace period (R5). Set alerting
> thresholds on `fork_quarantine_set` and `fork_quarantine_refusals` before
> rolling out, and read §5 first: for these groups a human is the only exit.

## 1) What the 409 `fork_quarantined` refusal means

While the marker is set, the membership-gated routes refuse with the typed
HTTP 409 `fork_quarantined`:

- `POST /groups/:id/send` (public group messages)
- TreeKEM encrypt/decrypt
- the `secure/encrypt`, `secure/decrypt`, `secure/reseal` family
- `DELETE /history?scope=group:<ID>` — the durable-history purge (ADR-0066
  §3a). Refused **before** anything is deleted, so the store is left
  unchanged: a purge is the irreversible destruction of the forensic record
  the quarantine exists to preserve. Clear the marker first if you genuinely
  need to purge.

**History READS are never refused — they are annotated.** `GET /history`,
`/history/message/:msg_id`, `/history/search`, `/history/scopes`,
`/history/stats`, `GET /diagnostics/history` and `GET /groups/:id/messages`
keep serving during an incident and add `"fork_quarantined": true` plus a
`fork_quarantine.scopes[]` list (each entry carrying `scope`, `revision`,
`observed_at_ms`, `no_anchor`) to the envelope; both keys are absent when
nothing in view is quarantined. Rows of a quarantined group that arrived at or
after `observed_at_ms` also carry `"fork_quarantined_at_ingest": true`, so you
can separate the incident window from the group's earlier traffic — ingest is
tag-and-retain, never refused (ADR-0066 R3), so nothing is missing from the
record. That label is derived from the live marker: **read the history you need
BEFORE clearing**, because a clear keeps every row but drops the labels.

**Two spellings of one group.** History scopes name the group's *stable* id
(that is what `x0x history scopes` lists and what the rows carry); the local
roster, and therefore the marker, is keyed by whichever id this daemon learned
the group under. On the history surface either spelling reaches the gate and the
annotation, so a purge cannot slip through under the stable name. Where it
matters is the clear: `x0x groups quarantine clear` takes the **roster key**,
which is the id the refusal's own message quotes — and `x0x diagnostics history`
/ `GET /history/stats` list both spellings when they differ, so you do not have
to guess which one a command wants.

### The refusal body (ADR-0066 §5)

**Match on `reason`, not on `error`.** ADR-0066 §5 moved the stable machine
code out of the human field so the human field can explain itself:

```json
{
  "ok": false,
  "reason": "fork_quarantined",
  "error": "group is fork-quarantined on this node: authenticated fork evidence at revision 7 means the roster is contested, so this operation is refused here. It clears when an owner-anchored commit advances past revision 7, or immediately with the manual clear POST /groups/:id/quarantine/clear (CLI: `x0x groups quarantine clear <GROUP_ID>`, which needs `--force --reason \"<why>\"` unless this install holds the group's owner user key).",
  "fork_quarantine": {
    "revision": 7,
    "observed_at_ms": 1700000000123,
    "no_anchor": false,
    "clear_with": "POST /groups/:id/quarantine/clear"
  }
}
```

- `reason` — the stable machine code. This is the field clients match.
- `error` — prose, and NOT a matchable contract: its wording may change, and
  it branches on `no_anchor` so the remedy it names is the one that can
  actually succeed for that group (a `no_anchor` marker never auto-clears, and
  its clear requires `--force` with a reason because there is no owner axis to
  attest with — §4.3).
- `fork_quarantine.clear_with` — the remedy, machine-readable, so a GUI or a
  script can offer it without parsing the sentence.

**One-time compatibility break.** Before ADR-0066 §5 the body was
`{"ok": false, "error": "fork_quarantined"}`. A client matching the literal
`error == "fork_quarantined"` stops matching and must move to `reason`. HTTP
409 and `ok: false` are unchanged. The `x0x` CLI prints the sentence, the
remedy and the code (`… (HTTP 409, reason: fork_quarantined)`).

The refusal means: this node has applied and retained authenticated
fork evidence (a conflicting state-commit whose signature verifies and whose
committer was an active admin in the retained predecessor roster — the same
deduplicated gate ADR-0059 uses), and the node refuses to keep mutating
group-keyed data until an owner-anchored path (§4) advances the chain past
the evidenced revision. It is containment, not a verdict: ADR-0064
deliberately has NO automated eviction, and the membership-event ingest path
is NOT gated (the owner-anchored clearing commit must still be able to
arrive). ADR-0066 §1 enumerates all 26 data-plane paths with a disposition
each, and every one of them has now landed except the §4 lifecycle epoch token
(row 22, slice 7) — so treat the tables in this section as the complete list of
what refuses and what is annotated.

**Delegations (ADR-0066 §3b, slice 3) are gated now.** Delegation is an
authority transfer, and a quarantined group's roster is the thing under
dispute, so minting new authority from it — or honouring authority derived
from it — fails closed:

| Surface | Behaviour while quarantined |
|---|---|
| `POST /groups/:id/delegate` (row 15) | **409 `fork_quarantined`.** Nothing is minted: no envelope is signed, no carrier row reaches history, nothing is published to the group bus. |
| `GET /groups/:id/delegations` (row 16) | **Still serves**, with `fork_quarantined: true` and a `fork_quarantine` object (same shape as the refusal's) added to the response. Reading who holds authority during a fork is exactly what an operator needs. |
| Delegated task-execute (`POST /task-lists/:id/tasks/:tid` citing `delegation`, row 17) | **409 `fork_quarantined`** before the claim/complete mutation. Task mutations *not* citing a delegation refuse too, as row 20 (see below) — since slice 5 the row-20 gate runs first, so either way there is exactly one refusal. |
| Send-as authorization (row 18) | Fails closed. A peer's gossiped send-as message for a quarantined group is dropped at ingest, as it already is for any unauthorized attribution. |
| Delegation index / global id registry (row 19) | A contested group's grants are not indexed and do not seed the registry — including at daemon start, where `rebuild_global_delegation_registry` skips the group entirely. An unregistered grant cannot authorize. |

Rows 17–19 have no HTTP response of their own on the gossip-ingest path, so
there the refusal is recorded (one `fork_quarantine_refusals` increment, the
same counter as the REST rows) and the §5 sentence is logged at WARN, rather
than the message being dropped silently. Carrier history rows are still
committed and retained — refusing to *honour* a delegation never blanks the
forensic record.

Existing delegations stop being honoured for the group, so **a quarantine on a
group that delegates work is an availability event for that work.** The exit is
the same clear as everything else (§4/§5); after it, the next use re-derives
the index from durable history and service resumes with no re-issuance.

Group membership reads, `/groups/:id/state`, and the diagnostics surfaces
keep working while quarantined.

### Task lists and bootstrap publication (§3c, slice 5)

| Surface | Behaviour while quarantined |
|---|---|
| `POST /task-lists` with a group-scoped topic (row 20) | **409 `fork_quarantined`.** Refused before the CRDT is created, before the durable subscription registration is written and before a sync listener starts — nothing is left behind. |
| `POST /task-lists/:id/tasks`, `PATCH /task-lists/:id/tasks/:tid` (row 20) | **409 `fork_quarantined`** before any CRDT mutation, any `task-lists/<id>.bin` snapshot write and any delta publish. First attempt, no grace. |
| `GET /task-lists`, `GET /task-lists/:id/tasks` (row 20) | **Still serve**, with `fork_quarantined: true` and a `fork_quarantine` object added (the collection annotates the affected entries). |
| Signed-public bootstrap publication (row 21) | **Withheld.** The outbox worker declines to send a contested group's snapshot — this is the one path that *exports* contested state to another node, and the snapshot a recipient installs is a whole roster/state frontier. |

**Row 21 is a suppression, not a deletion — nothing is lost.** The bootstrap
debt stays in the outbox with its retry schedule untouched, and reconciliation
retains it rather than refreshing it from the contested frontier, so
**delivery resumes by itself on the first worker pass after the manual clear
(the poll interval, ~0.5 s — there is no backoff to wait out, because the
withheld obligation's schedule was never advanced)**, with no operator action
beyond the clear. That matters because dropping the obligation would leave a
member on the roster that nobody remembers to bootstrap, permanently, since a
`no_anchor` marker never auto-clears.

**One quarantined group does not delay any other group's bootstrap.**
Quarantined groups are excluded when the worker chooses which obligation to
send, not merely refused after it has chosen: a pass sends at most one
obligation and picks the oldest due one, so gating after the choice would make
a contested group the permanent head of the line and stall the whole outbox for
as long as the marker stood. If you are triaging "no group is receiving its
bootstrap", a single quarantined group is **not** the explanation.

Both the periodic worker and the REST nudge a member-add fires go through the
same gate, so there is no path by which a background job publishes a contested
group's snapshot. A withheld publication has no HTTP response to carry the §5
message, so it logs the sentence at WARN and records one
`fork_quarantine_refusals` increment — **deduplicated per (group, marker
revision, observation time)**, deliberately: this is a polling worker, and one
record per poll would turn the counter operators alert on into a measure of
uptime. A new evidence revision, or the same revision observed again after a
clear, logs and counts again. So in triage, read row 21's contribution to
`fork_quarantine_refusals` as "this group's publication is being withheld", not
as a rate.

If you see `signed-public bootstrap publication withheld` in the log for a
group whose members are complaining they never received the group state, the
answer is §4/§5 (clear the marker) — not restarting the daemon, which loses
only the dedupe memory and changes nothing about the suppression.

### The WS plane is annotated, never cut (§3d, slice 6)

A WebSocket subscriber watching a quarantined group keeps receiving
everything it received before — the stream is deliberately NOT refused,
because an operator watching a live incident must not lose the feed at the
moment it matters. Two frame classes carry a label instead:

- ADR-0040 `mention` frames (a validated group message or a delegation grant
  naming the local agent) on the group's topic channel;
- ADR-0023 `Subscribe` backfill frames replayed for a group topic, including
  the `live` boundary frame that closes the backfill.

Each carries `"fork_quarantined": true` plus a `fork_quarantine` object with
`clear_with` and a one-entry `scopes` array (`scope`, `revision`,
`observed_at_ms`, `no_anchor`) — the same shape the REST envelopes use, so
one parser serves both. Both keys are **absent entirely** when the group is
not quarantined, so unaffected groups and all non-group topics are
byte-identical to before.

A label on a `delegation` mention says what was OBSERVED, not what was
authorized: the grant itself is refused independently (§3b).

The marker is resolved when each frame is emitted, so a session that
subscribed before the marker was installed starts seeing the label on its
next frame, and stops on the next frame after the manual clear — no
reconnect needed either way.

## 2) Reading the marker

```bash
x0x group info <GROUP_ID>            # or: curl -H "Authorization: Bearer $TOKEN" $API/groups/<GROUP_ID>
```

The group record carries `fork_quarantine` (null when not quarantined):

- `revision`, `state_hash` — the CONFLICTING commit the node evidenced
  (not your own head; your head is in the snapshot below);
- `committed_by` — hex agent id of the admin that committed the fork;
- `observed_at_ms` — local observation time (unix ms);
- `snapshot` — the forensic snapshot: both conflicting commit HEADERS
  (`terminal_commit` = this node's own head at evidence time,
  `conflicting_commit` = the fork), with `snapshot.classification`
  (slice 4):
  - `"owner_anchored_conflict"` — the conflicting commit carries an
    OwnerMandate that anchors its exact header: the OWNER anchored a
    successor this node cannot apply (it holds the disowned sibling).
    Strongest signal that YOUR chain is the disowned one — contact the
    owner; do not force-clear repeatedly and keep operating the losing
    chain;
  - `"signer_only"` — the signer was an active admin at the claimed
    parent, but no owner anchor is reachable. The classic #468 shape
    (a removed or rogue admin serving a self-consistent fork);
  - `"unauthorized_signer"` — the signer held a seat somewhere in retained
    history but was NOT an active admin at the claimed parent (an admin
    removed by the very commit the fork chains from, or a plain member);
  - `null`/absent — pre-slice-4 record shape (the claimed parent was not
    retained, so only the legacy revision−1 signer check ran).
- `no_anchor` — `true` when the group's policy has NO owner axis, i.e. there
  is no anchor any commit could carry: nothing clears the marker
  automatically and the manual clear (§4.3, force path) is the only exit
  (§5). `false` on owner-axis groups, and on every marker persisted before
  ADR-0066 (the field is `#[serde(default)]`, so an old record decodes as
  the owner-axis marker it was).

No shared secrets or TreeKEM material appear in the snapshot — it is
header-only by construction.

## 3) Diagnostics

```bash
x0x diagnostics groups
```

Per group (`GET /diagnostics/groups`):

- `fork_quarantine_set` / `fork_quarantine_refusals` — durable marker
  installs and gated-route refusals;
- `fork_evidence_signer_only` / `fork_evidence_unauthorized_signer` —
  classified conflict observations;
- `fork_quarantine_owner_anchored_refusals` — owner-anchored conflicting
  commits that were refused (the §4 strictly-greater/ancestry fence);
  a non-zero value with a persistent marker usually means the contested
  branch is publishing owner-anchored successors you cannot apply;
- `fork_quarantine_owner_anchored_clears` / `fork_quarantine_manual_clears`
  — apply-path anchored clears and manual endpoint clears;
- `owner_mandate_minted` / `owner_mandate_valid` / `owner_mandate_invalid`
  / `owner_mandate_absent` / `owner_mandate_missing` — mandate traffic
  (see §7);
- `mandate_capability_refusing_transitions` — one-shot Capable→Refusing
  transitions per authority agent;
- `mandate_capability: [{agent_id, state, first_seen_ms, refusals}]` —
  per-authority-agent rows for agents whose capability has been OBSERVED:
  `state` is the derived phase `"capable"` or `"refusing"` under the
  configured grace window; `first_seen_ms` is the grace-clock anchor;
  `refusals` is that agent's refused-event count. An agent with NO row is
  `unknown` (never observed capability) — the absent entry IS that state.

The marker is derived for reads from the same persisted group record that
survives restarts; counters are process-lifetime.

## 4) Clearing the marker — owner-anchored paths only

**A `no_anchor` marker (ordinary group) has NO automatic path at all.** Skip
to §4.3 — none of the anchored arms below can clear it; each one tests
`no_anchor` and declines, by design (ADR-0066 §2). Note that the *retry
rollback* of a non-durable install is not a clear and is deliberately not
gated, so a transient persist failure never leaves a marker stranded.

For an owner-axis marker, it clears ONLY through an owner-anchored path, and
every automatic path additionally requires the clearing commit to be one this node APPLIES
at a revision STRICTLY GREATER than the evidenced revision (ADR-0064 §3 as
clarified in the 2026-09-11 errata). The contested branch's own commits —
same-revision siblings, lower revisions, however well-formed — NEVER clear;
a conflicting owner-anchored successor does not clear either (it would
un-gate a node still holding the disowned sibling and re-quarantine on the
next canonical commit). The clears are:

1. **An owner-anchored commit this node applies at strictly greater
   revision.** Concretely:
   - tier-1 attestation-verified adoption of a `MemberAdded` anchored by
     the owner-signed head attestation (the joiner recovery path), or
   - a mandate-carrying `MemberAdded` whose `OwnerMandate` verifies
     (gapless or walked adoption) — the apply-path anchored clear.
   No operator action needed: keep the node online and reachable by the
   authority; the clear rides the normal apply.
2. **The explicit seal route on an owner-key node** —
   `POST /groups/:id/state/seal` (`x0x group state-seal <GROUP_ID>`) —
   BOTH arms (the all-clean seal and the seal that evicts failing
   members), requiring: the local install holds the group's owner USER
   key (the `owner_key_unavailable` fence — an agent-key seal carrying
   only an ADR-0038 certificate verdict is NOT an owner anchor), AND the
   sealed revision is strictly greater than the evidenced revision. The
   ~22 routine mutation sites (rename, policy, add/ban/promote, …) that
   share the sealing wrapper NEVER clear.
3. **The manual clear endpoint** (the operator escape hatch, #472
   decision 1) —
   `POST /groups/:id/quarantine/clear`:

   ```bash
   # On a node holding the group's owner USER key (no flags needed —
   # the endpoint mints and verifies a fresh quarantine-clear attestation
   # over the current head under x0x.quarantine-clear-attest.v1):
   x0x groups quarantine clear <GROUP_ID>

   # On any node, as the documented operator override:
   x0x groups quarantine clear <GROUP_ID> --force --reason "<what you verified and why>"
   ```

   The owner-key path is owner-controlled; the force path is the operator
   escape hatch — the `reason` is logged (info, capped at 256 chars) and
   counted (`fork_quarantine_manual_clears`), and SHOULD name this runbook
   plus what was verified. Typed 409s otherwise: `owner_key_unavailable`
   (keyless node, no force), `force_required` (no owner axis / missing
   reason), and a plain 409 when no marker is set. Remote-owner
   attestation submission is out of scope.

EVERY clear re-arms the stored fork-evidence silence gate: after a clear,
the next authenticated conflict re-evaluates, re-installs evidence, and
re-quarantines. Containment is not one-shot-per-group — force-clearing
without resolving the underlying divergence will re-quarantine on the next
conflicting commit.

**Before force-clearing, establish which chain is canonical.** Compare the
snapshot's two commit headers with the owner's view (the owner-key node's
`GET /groups/:id/state`), check `snapshot.classification`, and prefer the
automatic paths: they exist so the marker cannot be cleared while the
divergence is live. Force-clear is for: the evidenced fork is understood
and abandoned, the owner is permanently unavailable, or containment is
blocking an agreed recovery the automatic paths cannot express.

## 5) Ordinary (non-owner-axis) groups — `no_anchor: true`, manual clear only

**Changed by ADR-0066 §2 (supersedes #472 decision 2 of 2026-09-10).**
Ordinary groups ARE now contained. An ordinary group has no owner key by
construction, so there is no anchor to wait for: the marker it receives
carries `no_anchor: true`, and **only a human clears it**.

- **Trigger:** unchanged in how evidence is authenticated. Only a
  conflicting commit whose signature verifies AND whose committer was an
  active admin in the retained predecessor roster installs a marker. An
  unauthenticated or forged conflict still records nothing (this is the
  security boundary: a marker that any stranger could install would be a
  remote denial of service with no automatic recovery). What DID widen is
  which groups reach the evidence path — ADR-0066 R2 covers ordinary groups
  formed without an invite too, so "ordinary group" is one population.
- **Refusals:** the same rows as owner-axis groups — `POST /groups/:id/send`,
  TreeKEM encrypt/decrypt, and the `secure/encrypt|decrypt|reseal` family —
  effective on the FIRST request after the marker installs. No warn-only
  window, no request budget (R5).
- **No automatic clear, ever.** No commit, of any revision, on any ancestry
  clears a `no_anchor` marker. All three owner-anchored clear arms test the
  flag and decline.
- **Said plainly: a CURRENT admin's own signed conflicting commit permanently
  quarantines the group on every node that receives it, until a human runs the
  manual `--force --reason` clear on each of those nodes.** The trigger asks
  only that the committer was an Active Admin in the retained predecessor
  roster — not whether that admin was malicious, confused, or merely
  partitioned. An admin committing from a stale head (a laptop that was
  offline; two admins sealing concurrently) therefore contains the group for
  everyone who receives that commit, with no automatic recovery, and — because
  the marker is per-node and never gossiped — no fleet-wide clear either: the
  remedy is per-node too. This is accepted design, not an oversight: R1
  rejected a founder-key anchor (a compromised founder key would be an
  unreviewable eviction oracle) and R5 rejected every grace window, on the
  condition that the refusal explains itself. Plan for it — an ordinary group
  with several admins committing concurrently is the population most likely to
  need this procedure.
- **A recovery-time conflict on a lineage-less ordinary group records
  nothing.** The journal-recovery evidence path
  (`record_recovery_fork_evidence`) stays fenced to groups carrying an
  `invite_lineage` record, because that record is where recovery-time evidence
  is stored; ADR-0066 slice 2 widened the LIVE apply path only. So a conflict
  discovered while replaying the persist journal for an ordinary group formed
  without an invite installs no marker and fires no counter — the group is
  contained on the next authenticated conflicting commit that arrives through
  the live path instead. Treat a restart that logged a journal conflict on such
  a group as NOT yet quarantined.
- **The exit** is the manual clear with the operator override, because there
  is no owner axis to attest with:

  ```bash
  x0x groups quarantine clear <GROUP_ID> --force --reason "<what you verified and why>"
  ```

  Without `--force` the endpoint answers 409 `force_required` — that is
  correct, not a bug: there is nothing to mint an attestation with.

**What an operator should do before clearing.** Establish the canonical
chain out of band with the group's admins (compare `GET /groups/:id/state`
heads across members), have an active admin of the AGREED chain advance it
(revision strictly greater), re-seat members still holding the disowned
sibling (fresh invite/re-add), and only then force-clear — naming this
runbook and what you verified in `--reason`, which is logged and counted.
Clearing while the divergence is still live re-quarantines on the next
authenticated conflicting commit (every clear re-arms the evidence gate).

**The accepted cost (ADR-0066 Consequences).** A benign network split that
produces authenticated conflicting commits now strands an ordinary group
until an operator intervenes. This was chosen over a founder-key anchor (R1:
a compromised founder key would become an unreviewable eviction oracle) and
over a quorum anchor (a two-member group's quorum is the attacker). The
mitigation is the §1 refusal message, which names the condition, the cause
and this exact remedy — not a delay.

## 6) Mixed-fleet notes

- `fork_quarantine` and `mandate_capability` are serde-default JSON
  fields: v0.41.4 binaries ignore them — no wire break, no brick.
- **A downgrade loses containment, it never bricks.** An old binary that
  rewrites `named_groups.json` drops fields it does not know.
- For owner-axis groups the AUTHORITATIVE persisted record is the
  `home-suite-groups.json` sidecar (`named_groups.json` holds a legacy
  placeholder also carrying the fields; the load path merges
  sidecar-wins). Pinned by test: rewriting `named_groups.json` without
  the fields loses nothing — the marker and grace clocks survive from
  the sidecar.
- Residual caveat: an OLD SIDECAR-AWARE binary that rewrites the SIDECAR
  itself drops both fields from the authoritative record — a downgrade
  across a sidecar-aware version loses containment (accepted; matches the
  ADR migration table's "never bricks").
- Upgrade order for the mandate machinery: authorities/owners first
  (mandate production), then members (enforcement), then the grace window
  closes.

## 7) Mandate grace and the `owner_mandate_missing` refusal

On owner-axis groups, an absent-mandate `MemberAdded` from an authority
agent whose capability has been observed and whose grace window has
elapsed is refused with the typed, RETRYABLE `owner_mandate_missing`
(nothing is queued as a revision gap; the sender-side bounded resend or a
mandate-carrying re-issue is the redelivery path — retry the operation,
do not rejoin). Semantics:

- capability is recorded per AUTHORITY AGENT the first time that agent
  produces a valid mandate or an owner-countersigned InviteV4
  (`first_seen_ms`);
- `unknown` agents (never observed capability — the keyless tier,
  #472 decision 7) warn-accept indefinitely; A's capability never
  implicates B;
- the grace window defaults to **60 days** (one release cycle) and is
  configured per daemon as `[groups] mandate_grace_days` (validated ≥ 1
  at startup; the daemon refuses to start on 0);
- a later valid mandate from the same agent restores `capable` but
  RETAINS the original clock — a compromised authority cannot reset its
  own window;
- the clock is the node's LOCAL wall clock: a backwards clock jump flips
  a refusing authority back to warn-accept until the clock recovers
  (accepted; both skew directions fail toward the ADR-0016 checks).

If a legitimate admin's events start refusing: upgrade that admin's
install (mandate production needs the owner user key on the authority),
or have the owner/keyed authority perform the seating. Do NOT delete the
capability map to "fix" refusals — the map is observational state; the
durable fix is a mandate-producing authority.

## 8) Quick triage

| Observation | Meaning | Action |
|---|---|---|
| 409 `fork_quarantined` on send/encrypt | local marker set; authenticated fork evidence held | read `fork_quarantine` snapshot + classification (§2); let the owner anchor advance (§4.1–4.2); manual clear only per §4.3 |
| 409 `fork_quarantined` on `DELETE /history` | the purge is refused to preserve the forensic record (§1) | read the history first; purge only after a deliberate clear — the store is untouched by the refusal |
| history reads carry `fork_quarantined: true` | that scope spans a contested chain (§1) | expected; use `fork_quarantined_at_ingest` on the rows to find the incident window, and export what you need before clearing |
| `classification: "owner_anchored_conflict"` | the owner anchored a successor this node cannot apply | this node likely holds the disowned chain — coordinate with the owner before any force-clear |
| `fork_quarantine_owner_anchored_refusals` rising, marker persists | contested branch publishing owner-anchored successors | divergence still live; do not force-clear |
| 409 `fork_quarantined` with `"no_anchor": true` | ordinary group contained; NO automatic clear exists (§5) | agree the canonical chain out of band, re-seat stragglers, then `x0x groups quarantine clear <ID> --force --reason "…"` |
| `force_required` from the clear endpoint | the group has no owner axis to attest with (§5) | re-run the clear with `--force` and a reason — this is the documented path, not a fault |
| `fork_quarantine_set` rising across a fleet right after an upgrade | groups already silently forked are being contained for the first time | expected (ADR-0066 Migration); triage per §5, do not mass force-clear |
| 409 `owner_mandate_missing` (retryable) | post-grace absent mandate from a recorded-capable authority | upgrade/repair the authority (owner user key); retry the send |
| `mandate_capability` row `state: "refusing"` | that agent's grace window elapsed | same as above, per-agent |
| marker vanished after an old binary ran | downgrade dropped containment (§6) | re-upgrade; the node re-quarantines on the next authenticated conflict (gate re-arms on every clear/set) |
