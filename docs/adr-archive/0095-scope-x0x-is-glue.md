# ADR 0095: Scope — x0x Is Glue Between People, Their Machines and Their Agents

<!-- File name: docs/adr/0095-scope-x0x-is-glue.md -->

- **Status:** Accepted
- **Accepted:** 2026-10-03 by David Irvine (D58, as written: the Proposed text merged via #1185, commit 80d448e; his instruction to Claude directly). The Open questions remain open for later rulings. The status change was applied by Claude at his instruction.
- **Date:** 2026-10-03
- **Decision owners:** David Irvine (ruling D19, revised 2026-09-29; only
  David marks this ADR Accepted)
- **Author:** Claude (Opus)
- **Reviewers:** Codex (cross-model r1)
- **Supersedes:** [ADR 0017](./0017-x0x-as-agent-transport-layer.md)
  **in part: its positioning text only.** Its interop posture and its three
  workstreams stay (§2).
- **Superseded by:** none
- **Amends:** none. [ADR 0072](./0072-scope-freeze-deferred-and-legacy-maintenance.md)
  stays unchanged (§5). ADR 0096 adds R12 to it.
- **Parks (priority only, §4):** ADR 0042 and ADR 0073 (R8 media calling);
  the notes half of ADR 0075, ADR 0081 and ADR 0082 (the R9 notes merge
  path). No Accepted ADR is edited.
- **Goal served:** all goals (F, A, D, E, M). It records the scope that
  later ADRs are checked against.
- **Related:** [`docs/design/x0x-direction.md`](../design/x0x-direction.md)
  (§1–§3, §7, §8; rulings D09, D19, D21, D28, D36, D52, E-D1, E-D15);
  [ADR 0096](./0096-r12-x0x-is-maintained-by-its-own-agents.md) (R12);
  ADR 0103 (prov., scratch store); ADR 0083; ADR 0087; #112, #113, #892,
  #965, #1029, #1094, PR #1035.

## Context

- ADR 0017 (2026-06-15) positioned x0x as "the transport layer beneath
  MCP/A2A". But x0x also ships owner identity and trust, share grants,
  TreeKEM groups, KV stores, task lists, delegation, a tailnet and a GUI.
- ADR 0072 (2026-09-25) froze mechanisms that no requirement needed, and
  made every new ADR name one of R1–R11. Its list is flat. It does not rank
  R8 or R9 against sharing or efficiency.
- On 2026-09-29 David revised D19 (digest §1, §3). x0x is the glue between
  people, their machines and their agents, and it does not provide agents.
  Shared places, sharing whole agent teams and efficiency are core. R8 media
  calling and the loro notes merge path are lower priority, not in scope
  now. The D19 decision record adds: "The primary user is an AI agent
  acting for one owner with 2–5 machines."
- D19 deferred this ADR until v0.46.0 was promoted, which happened on
  2026-10-03 (D52).

## Decision Drivers

- One checkable test for "is this core?" that applies to every ADR and PR.
- State what x0x is in David's framing, and stay beneath MCP and A2A.
- Decide only what David has ruled. Unruled policy becomes an open question.
- Keep shipped behaviour working. A park is not a removal.

## Considered Options

1. **Keep ADR 0017's "transport layer" positioning and ADR 0072's flat
   list.** Rejected. It undersells identity, trust, sharing and shared
   places, and it sets no priority.
2. **"The network-and-trust layer for one owner"** (the D19 wording of
   2026-09-28). Rejected by David on 2026-09-29. It undersold shared places,
   team sharing, embedders and efficiency.
3. **A full agent platform that hosts or runs agents.** Rejected. We do not
   provide agents, and a platform would compete with the protocols x0x sits
   beneath.
4. **Record D19 as ruled: the glue positioning, the core, and the parks.
   Leave unruled scope policy to David as open questions.** Chosen.

## Decision

We will position x0x as glue, and record the D19 scope and parks.

### 1. Positioning (replaces ADR 0017's positioning text)

- x0x is the glue between people, their machines and their agents.
- **We do not provide agents.** People bring their own agents, running
  anywhere. x0x is how those agents find, trust and reach each other and
  their human.
- x0x stays beneath agent protocols such as MCP and A2A, and does not
  define what agents mean or do. But the glue is not "just transport": it
  includes identity, owner authority, trust, reach, sharing, groups and
  shared places.
- The primary user is an AI agent acting for one owner with 2–5 machines.
  People who share agent teams, and embedders, are also users. Embedder
  field reports are first-class input.
- Headline requirement (D19): any agent that sees x0x knows how to use it,
  through a compact onboarding recipe, a JSON API with typed errors and an
  event stream (digest §1).

### 2. ADR 0017: replaced text, and retained workstreams

**Replaced (positioning text only):**

- the Decision's lead sentence as the scope boundary, which positions x0x
  as "the transport layer beneath MCP/A2A";
- the risk note that the transport story must stay cleanly separable, so
  that adopters see "just transport".

**Retained, unchanged:**

- **The interop posture.** x0x serves a signed agent card
  (`GET /agent/card`, `GET /.well-known/agent-card.json`) and stays beneath
  MCP and A2A. It is not a rival full-stack agent protocol (ADR 0017's
  option A stays rejected).
- **Workstream 1, publish a spec.** The Internet-Draft candidate exists
  (#113). The commitment stands as ADR 0017 states it until David answers
  open question 1.
- **Workstream 2, A2A interop.** The discovery card stays. The delivery
  binding (#112) stays deferred, as ADR 0017 and the digest (§3) record.
  The shipped unary A2A path stays as shipped.
- **Workstream 3, the narrative.** Post-quantum and zero-registry identity
  stay the lead differentiators.

### 3. Core

**Membership test (digest §3).** A capability is core if people, their
machines and their agents need it to find, trust, reach, share with or
coordinate through each other, or to keep that efficient and
self-sustaining. Core is:

- identity and owner authority (R1, R2);
- reach: all my machines connected, with ports and names (R3, R4);
- scoped, expiring, revocable sharing of single agents and whole agent
  teams (R5, R7), including the team record planned after M3 (D36);
- swarm and team coordination: DM, groups, task lists, delegation (R6);
- shared places: the scratch store, message boards and project data in
  public and private groups (the R9 primitives);
- agent-opened views (R10), onboarding (R11) and self-maintenance (R12);
- efficiency (goal E). Every PR and ADR applies the E-D15 efficiency
  checklist. Budgets become release criteria through their own ADR (E-D1).

Core work follows the W4 order in the digest (§7; D21, D36), one R at a
time.

**Out of scope (digest §3):** providing, hosting or running AI agents; MCP
tool semantics; A2A task semantics beyond serving a card; and a global DHT
for user data (ADR 0006) or a central registry, apart from the compiled-in
release key.

### 4. Parked: lower priority, not in scope now

Parked (D19, as the README status overlay defines it) means: shipped code
stays and gets bug and security fixes only, and no new slices start. Paused
branches stay paused. Issues carry the `deferred` label.

- **R8 media calling:** ADR 0042, ADR 0073 and #892.
  - Release builds do not enable the `voice` feature. The release change in
    ADR 0073 decision 3 is not made while R8 is parked.
  - The `/calls` signalling lifecycle (ADR 0073 slice 1) stays as shipped.
    It is labelled experimental, carries no media and gets no new gate
    (D09).
- **The R9 rich-text notes merge path:** ADR 0075 decisions 1–3 (this
  includes the Wiki move to notes) and its note deep link, ADR 0081,
  ADR 0082, #965, #1029 and PR #1035.
- **Not parked: the ADR 0075 scratchpad half.** Decisions 4 and 5 (the
  `scratch` store and the rider `scratch` scope) and the `#/scratch` deep
  link are core. ADR 0103 (prov.) will re-specify and supersede them as a
  sealed scratch store with rider and grant scope (A5, #1094). New scratch
  work starts from ADR 0103.

### 5. What this ADR does not change

- **ADR 0072 stays in force, unchanged.** Its freezes (Decision items 1–4)
  and its meaning of "frozen" stand. The parks in §4 record D19's priority
  ruling beside those freezes. Any re-tiering is open question 2.
- **Rule 5** accepts R1–R12 once ADR 0096 adds R12 (D20). Its exception
  stays as written: an ADR that serves no requirement is rejected unless it
  is a correctness or security fix to shipped behaviour. That exception
  does not waive a freeze, an implementation hold (D28) or ADR 0087's
  ADR-before-code ordering.
- **The efficiency checklist (E-D15)** is a review on every PR and ADR. It
  does not replace naming a requirement under rule 5 (open question 4).
- **Rule 6** stays: lifting a freeze needs a new ADR that names the
  requirement and explains why no smaller change serves it. How a park is
  lifted is open question 3.
- **ADR 0087** governs every change in scope here, non-wire API and
  architecture changes included.
- **D09** keeps `/calls` as shipped. **D28's** implementation holds stand,
  and ADR 0083 keeps its accepted GUI-show defaults.

## Consequences

### Positive

- One test decides "is this core?", and reviewers can apply it.
- The positioning matches what x0x ships and what its users need, and
  effort goes first to shared places, team sharing and efficiency.
- Nothing shipped is removed. Parked code stays safe through fixes.

### Negative / Trade-offs

- Calls with media do not ship. People who want calls use another tool.
- Concurrent Wiki edits can still be lost, the defect ADR 0075 set out to
  fix. Agents use the scratch store or KV for shared working state.
- Paused notes branches drift from `main`, so un-parking costs rework.
- Several scope rules stay open until David answers the questions below.

### Neutral / Operational

- The README status overlay records the parks (ADR 0087 rule 8).
- The `/calls` routes stay in the endpoint registry and the CLI.

## Validation

- **Review check:** a new ADR names one of R1–R12, or it is a correctness
  or security fix to shipped behaviour (ADR 0072 rule 5). Otherwise it is
  sent back. The fix exception waives no freeze, hold or ADR 0087 ordering.
- **Review check:** a PR that adds a feature to a parked mechanism is
  declined while the park holds.
- **Release check:** `release.yml` builds `x0xd` and `x0x` without the
  `voice` feature while R8 is parked. Any doc that describes `/calls` says
  it is experimental and carries no media.
- **Tracker check:** #892, #965 and #1029 carry `deferred`. PR #1035 stays
  unmerged while the notes path is parked.
- **Revisit** when David answers the open questions, or asks to un-park R8
  or the notes path.

## Open questions for David

1. **Internet-Draft (#113).** Submit the candidate, keep it as a reference,
   or drop it? Until you answer, ADR 0017 workstream 1 stands as written.
2. **Scope tiers.** Should ADR 0072 be re-tiered into core, parked, frozen
   and out of scope, with "frozen" for a mechanism that no requirement needs
   now and "parked" for a valid requirement that waits? This draft keeps
   ADR 0072's freeze rules unchanged.
3. **Lifting a park.** Does it need a new ADR, as rule 6 does for a freeze,
   plus evidence that the core is efficient and proven (for example goal
   A's exit test and the v0.47 goal E targets, E-D2)? Or is your ruling
   alone enough?
4. **Goal E under rule 5.** The digest (§2) says every new ADR names "the R
   or goal E it serves". Should goal E count in place of an R, stay a review
   only (E-D15), or become R13? This draft keeps rule 5 at R1–R12.
5. **Parked-requirement ADRs.** Should an ADR that serves only a parked
   requirement (R8, or the notes path) be declined while the park holds, or
   drafted and held? This draft decides neither.
6. **Placement rule.** The digest (§3) states one: a feature with no new
   wire semantics may ship in `x0xd` as a default-off reference app, and
   new protocol surface needs an ADR. No numbered ruling settles it. Adopt
   it? If so, placement would not lift a park (a notes UI stays parked), and
   remote GUI show is not an example, because it uses ADR 0083's messages.
7. **Team sharing.** Keep it under R5 and R7 (this draft), or give it an R?
8. **`/calls`.** Keep the lifecycle routes in default builds while R8 is
   parked (this draft, per D09), or put them behind a default-off flag at
   the next minor release?

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human review**. Accepted ADRs are immutable: create a new superseding ADR rather than editing an Accepted ADR.
