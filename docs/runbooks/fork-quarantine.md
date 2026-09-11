# Fork quarantine runbook (ADR-0064)

Operator procedures for the persistent fork-quarantine marker and the owner
mandate grace machinery. Everything here is LOCAL, per-node state: a marker
on this daemon says this daemon holds authenticated evidence of a conflicting
group state chain; it is never gossiped, and a member that never received the
evidence has no marker and is not contained (ADR-0064 Decision 3). Design
context: [docs/trust-and-connectivity.md](../trust-and-connectivity.md)
(ADR-0064 sections), [ADR-0064](../adr/0064-owner-anchored-fork-authority.md),
[ADR errata](../adr/README.md) (maintainer decisions of 2026-09-10/11),
issues #468/#469/#472.

Scope: **owner-axis groups** (Home-suite / `OwnerCertified` admission).
Ordinary (non-owner-axis) groups are NOT gated — see §5.

## 1) What the 409 `fork_quarantined` refusal means

While the marker is set, the membership-gated routes refuse with the typed
HTTP 409 `fork_quarantined`:

- `POST /groups/:id/send` (public group messages)
- TreeKEM encrypt/decrypt
- the `secure/encrypt`, `secure/decrypt`, `secure/reseal` family

The refusal means: this node has applied and retained authenticated
fork evidence (a conflicting state-commit whose signature verifies and whose
committer was an active admin in the retained predecessor roster — the same
deduplicated gate ADR-0059 uses), and the node refuses to keep mutating
group-keyed data until an owner-anchored path (§4) advances the chain past
the evidenced revision. It is containment, not a verdict: ADR-0064
deliberately has NO automated eviction, and the membership-event ingest path
is NOT gated (the owner-anchored clearing commit must still be able to
arrive). History/delegations/kv routes are not yet gated either (route
coverage is deferred — #472 residual list).

Group membership reads, `/groups/:id/state`, and the diagnostics surfaces
keep working while quarantined.

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
- `no_anchor` — reserved flag; always `false` today (see §5).

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

A marker clears ONLY through an owner-anchored path, and every automatic
path additionally requires the clearing commit to be one this node APPLIES
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

## 5) Ordinary (non-owner-axis) groups — `quarantine_no_anchor`

Ordinary groups are NOT gated (#472 decision 2, 2026-09-10): indefinite
quarantine with no recovery path would brick ordinary groups in the wild,
which is worse than the ADR-0016 equal-revision fork risk it prevents.
Their behaviour is byte-for-byte unchanged:

- they never receive a marker — no 409 `fork_quarantined`, no
  `fork_quarantine` field set;
- authenticated fork evidence is still recorded (ADR-0059
  `invite_lineage`) and visible through the diagnostics counters, so the
  divergence is observable, not silent;
- the marker type's `no_anchor` flag — the would-be "can never auto-clear"
  case for groups with no owner axis — is reserved and always `false`.

What an operator should do: treat rising fork-evidence counters on an
ordinary group as an investigation signal. Establish the canonical chain
out-of-band with the group's admins (compare `GET /groups/:id/state`
heads across members), have an active admin of the AGREED chain advance it
(revision strictly greater), and re-seat members still holding the
disowned sibling (fresh invite/re-add). Gating for ordinary groups waits
for an ADR that defines their anchor (#472 tracker).

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
| `classification: "owner_anchored_conflict"` | the owner anchored a successor this node cannot apply | this node likely holds the disowned chain — coordinate with the owner before any force-clear |
| `fork_quarantine_owner_anchored_refusals` rising, marker persists | contested branch publishing owner-anchored successors | divergence still live; do not force-clear |
| fork-evidence counters rising on an ORDINARY group | divergence observed, not gated (§5) | out-of-band canonical-chain agreement + re-seat stragglers |
| 409 `owner_mandate_missing` (retryable) | post-grace absent mandate from a recorded-capable authority | upgrade/repair the authority (owner user key); retry the send |
| `mandate_capability` row `state: "refusing"` | that agent's grace window elapsed | same as above, per-agent |
| marker vanished after an old binary ran | downgrade dropped containment (§6) | re-upgrade; the node re-quarantines on the next authenticated conflict (gate re-arms on every clear/set) |
