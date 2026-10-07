# x0x design direction and rulings digest

- **Status:** maintained digest, not an ADR. It records the design rulings
  David Irvine made from 2026-09-28 to 2026-10-05 (decisions D01–D200 and the
  efficiency decisions E-D1–E-D17).
- **Updated:** 2026-10-05.
- **Relationship to ADRs:** ADRs remain the decision records, and only David
  marks an ADR Accepted. Where a ruling here changes what an Accepted ADR
  means in practice, the status overlay at the top of the
  [ADR README](../adr/README.md) says so. New work follows the ruling until the named successor ADR is
  decided.
- **ADR numbers marked (prov.)** are provisional. The real number is
  allocated when the ADR PR is opened on `main`.
- **Keep in sync:** a PR that changes a ruling updates this file and the ADR
  README overlay together.

## 1. What x0x is

x0x is **glue**. It binds a person, their machines and their agents into one
trusted, reachable whole, and then lets people join their wholes together.

- **We do not provide agents.** Users bring any agent, running anywhere: on
  their own machines, in a cloud, or behind a vendor API. x0x is how those
  agents find, trust and reach each other and their human.
- **Machines.** Every machine an owner enrols is connected and reachable
  (reach, ports, names). The model is Tailscale, but leaner, post-quantum,
  and with no central coordinator.
- **Agents.** Any agent joins through the local daemon. Agents form swarms and
  teams (messaging, groups, task lists, delegation, scratchpads) that do work
  for their human.
- **Humans.** People collaborate by sharing whole agent teams with each other,
  under scoped, expiring, revocable capabilities.
- **Shared places.** Scratchpads, message boards and project data, in public
  and private groups, for agents and humans alike. This is a core capability,
  not an add-on.
- **Self-explaining.** Any agent that sees x0x knows how to use it: a compact
  onboarding recipe, a JSON API with typed errors, and an event stream. Agents
  teach other agents to join.
- **Self-sustaining.** Agents keep x0x healthy and upgraded, under owner
  policy.
- **Efficient.** Idle cost, bytes per useful message, CPU per verified frame,
  memory, disk growth and battery or metered-link cost all have explicit
  budgets that releases are measured against.
- **For everyone.** David's own use, embedders already building on x0x, and
  any human or agent. Embedder field reports are first-class input.

x0x stays beneath agent protocols such as MCP and A2A and does not define what
agents mean or do. It ships as the `x0x` Rust crate, the `x0xd` daemon
(loopback REST/WS/SSE plus an embedded GUI) and the `x0x` CLI. Every machine
and agent has a self-authenticating post-quantum identity (SHA-256 of an
ML-DSA-65 key; no registry), and the human owner is the root of authority.

## 2. Goals and requirements

| Goal | Meaning |
|---|---|
| **F: it connects and works** | Machines, agents and their human are always reachable and mutually trusted, with no setup rituals. Every capability is correct, bounded and observable. |
| **A: people collaborate through agent teams** | An owner's agents across many machines trust each other with no manual contact editing. The owner shares a chosen agent or team with another person, scoped, expiring and revocable, and the teams work together (DM, groups, shared places, forwards, exec). |
| **D: shared places** | Scratchpads, message boards and project data (KV, task lists, boards, scratch stores) in public and private groups. Private groups are end-to-end encrypted, with forward secrecy on membership change (TreeKEM). Rich real-time collaborative text is a later layer on top of these primitives. |
| **E: highly efficient** | Explicit, measured budgets for bandwidth in both directions, CPU, memory, storage, log growth, radio wakeups and latency. Budgets become release criteria, and no efficiency change may lose a message. |
| **M: self-sustaining** | Health verdicts, release verification, safe upgrade and rollback under owner policy, agent-assisted install and join, and problem reporting. |

The requirement yardstick from [ADR 0072](../adr/0072-scope-freeze-deferred-and-legacy-maintenance.md)
still applies: R1 a human owner · R2 many agents · R3 all my machines
connected · R4 connectivity better than Tailscale · R5 share a subset of my
agents · R6 agents collaborate across machines · R7 machine-resident agents
reachable by my agents and sharees · R8 video/audio calling · R9 CRDT shared
notes and agent scratchpads · R10 an agent opens a GUI view for its human ·
R11 agents teach others to install and join. **R12**, "x0x is maintained by
its own agents", is agreed (D20) and is recorded by ADR 0096 (prov.) after
v0.46.0 is promoted. Every new ADR names the R or goal E it serves.

## 3. Scope

**Membership test.** A capability belongs in x0x core if people, their
machines and their agents need it to find, trust, reach, share with or
coordinate through each other, or to keep that efficient and self-sustaining.

- **In scope:** identity and owner authority (R1, R2); reach, ports and names
  (R3, R4); scoped, revocable sharing of agents and teams (R5, R7); swarm and
  team coordination: DM, groups, task lists, delegation (R6); shared places:
  scratchpads, boards, project data (the R9 primitives); agent-opened views
  (R10); onboarding (R11); self-maintenance (R12); efficiency budgets (E).
- **Lower priority, not in scope now (D19):** R8 media calling (the browser
  media gateway, voice in release builds) and the rich-text notes merge path
  (loro). Both are reconsidered after the core is efficient and proven.
- **Out of scope:** providing, hosting or running AI agents; MCP tool
  semantics; A2A task semantics beyond serving a card (#112 deferred); any
  global DHT for user data ([ADR 0006](../adr/0006-no-global-dht-for-user-and-group-data.md))
  or central registry, apart from the compiled-in release key.
- **Placement rule.** A feature that needs no new wire semantics (the calls
  lifecycle, a notes UI, GUI show) may ship inside `x0xd` as a default-off
  reference application. New protocol surface needs an ADR that names an R or
  goal E.

## 4. Invariants

Each invariant has one owning chokepoint. Several are violated today, and the
wave that fixes each is in section 7.

| # | Invariant |
|---|---|
| I1 | **Delivery.** An obligation acknowledged to a caller survives restart and is retried until ACKed, revoked or expired. Nothing is ACKed and then dropped. |
| I2 | **Delivery honesty.** A caller can always tell sent, deferred, shed and delivered apart. No "Ok but dropped" without a counter and a queryable id. |
| I3 | **Authenticity at ingress.** Nothing unsigned or unverified reaches an app or internal consumer as authenticated. |
| I4 | **Epochs and sealing.** Seal only under the currently committed epoch. Hold a future-epoch record for a bounded time, never drop it silently. Every departure, self-leave included, ends the leaver's read access at the next epoch. |
| I5 | **Admission evidence.** The evidence needed to admit (certificate, attestation, enrollment, grant) travels with the request. No gate depends on a warm gossip cache. |
| I6 | **Authorization.** Every remote decision uses one `Authority::decide`; every local owner-effect route is in one durable-owner table; group access goes through one extractor. |
| I7 | **Revocation.** A revocation never expires while the credential it kills can still verify, survives a corrupt store, and reaches every gate and every live session (group membership included, D34) within a bound. |
| I8 | **Liveness with offline peers.** Only an enumerated list of rules may block forever. Admission, catch-up and repair complete when any one active admin or holder is online. |
| I9 | **Upgrade continuity.** State written by release N−1 opens under N, and a wire change an older version mishandles is gated by a signed capability bit. |
| I10 | **Upgrade reversibility and blast radius.** Every applied release can be undone on that machine without human SSH, and no release reaches more than ring 0 before evidence exists. |
| I11 | **Released bytes equal the tested graph.** |
| I12 | **Resource bounds.** A daemon never fills its host's disk, spends a user's uplink as infrastructure, or grows queues without bound, and every bound is visible. |
| I13 | **Plane isolation.** A test or named daemon never joins production by accident. |

## 5. Decisions D01–D200

Status key: **implemented** = in effect on `main` (code, configuration or an
Accepted ADR); **ruled** = decided by David, work outstanding or ongoing;
**pending ADR** = the ruling needs the named ADR, which is not yet Accepted.

Each row records David's ruling, not the charter's recommendation. They
differ for D08 (the capability bit moved into v0.46), D10 (ratified as-is),
D14 (dedicated hosts), D15 (no bot identity), D19 (scope revised 2026-09-29)
and D29 (an ADR 0089 slice pulled into v0.46).

| Id | Ruling (one line) | Status |
|---|---|---|
| D01 | v0.46 failing to read v0.45 KV snapshots (C1) is a release blocker; the fail-closed downgrade of `X0XKVS2` is accepted (files kept, unreadable on 0.45). #1046 lands on `main` with a storage ADR and a gate row that loads a real v0.45.0 `data_dir`. | Implemented: #1046, [ADR 0085](../adr/0085-persisted-binary-formats-are-versioned.md); W2 gate complete |
| D02 | The v0.46.0 gate is relative to a v0.45.0 baseline, with exactly three Home gating rows, a Home stopping rule and a drop rule for should-land fixes. | Ruled; W2 gate complete (2026-10-03) |
| D03 | Canary: a draft-bytes deploy before publish, a 0.46→0.46.x self-upgrade rehearsal on a real systemd host, and no GitHub prerelease publishing. | Ruled; W2 complete (2026-10-03) |
| D04 | Released bytes equal the CI-tested graph: `Cargo.lock` is tracked, `release.yml` consumes it, and prerelease tags are refused. | Implemented; recorded by ADR 0087 (Accepted) |
| D05 | Release-key protection: release build, sign, create and publish jobs, and ad-hoc SKILL.md signing, run in a protected `release` environment with David as required reviewer, limited to `v*` tags. | Implemented; recorded by ADR 0087 (Accepted) |
| D06 | #1044 (owner-sync admission on verified enrollment) is kept and recorded retroactively, amending ADR 0041; the SyncV1-acceptor machine-revocation re-check is must-land. | Implemented: [ADR 0084](../adr/0084-enrolled-owner-sync-admission.md) |
| D07 | The v0.46 should-land fix set is approved under the drop rule. The review-only model lanes may also author small fixes, each reviewed by another model family. Persisted consent moves to W3. | Ruled |
| D08 | The grant capability bit ships **in v0.46**, with an ADR and W2 implementation. David ruled this over the recommendation to defer it to W3. | Implemented: #1064, [ADR 0093](../adr/0093-capability-advert-registry.md) |
| D09 | The v0.46 known limitations and the 0.46→0.45 downgrade procedure are signed; `/calls` is labelled experimental. | Implemented; signed release notes published (2026-10-03) |
| D10 | Three criteria changes are **ratified as-is (David, 2026-09-29)**: #903 (predecessor loss is a mixed-version limitation), #952 folded into #504, and #1021's private-KV precondition barrier. The ruling carries no control-run condition; the charter's recommendation had proposed one for #1021. | Ruled |
| D11 | ADR 0069 (Home waits for owner sync) is accepted as a record of shipped behaviour, to be superseded by ADR 0088. | Implemented: [ADR 0069](../adr/0069-home-wait-for-sync-before-auto-provisioning.md) |
| D12 | #613 stays separate from #807 and keeps its measurement row. | Ruled |
| D13 | #646 (invites stop past 20 Active+Banned members) is a product limit, not parked; fixed in W4. | Ruled |
| D14 | Testnet evidence runs on **dedicated testnet hosts**, sealed from production. David chose dedicated hosts over the open "dedicated hosts or 4 vCPU" option. | Ruled |
| D15 | CI runs on PRs to every base; `main` has a ruleset with required checks and no bypass; `v*` tags are admin-only. **No bot identity:** David declined the recommended separate agent identity, so agents act as the admin account. | Implemented; recorded by ADR 0087 (Accepted) |
| D16 | Group liveness contract, **ruled in full (David, 2026-09-29)**: a promoted admin carrying the evidence may admit while the owner device is offline, and any active admin may redeem invites; stale ordinary-group joiners catch up; Home becomes an explicit owner group, with the owner certificate checked at admission; the simulation harness must reproduce each failure first. D34 closes the three holes this left (who attests catch-up, eviction on revocation, certificate size). | Pending ADR 0088 (prov.), W3 |
| D17 | Trust gates decide only from in-band evidence plus persisted state, through one `Authority::decide`. | ADR 0089 Accepted; unified authority pending W3 |
| D18 | One group crypto (TreeKEM only) and one acknowledged-delivery primitive (`Outbox<T>`), enforced in CI: no new bespoke queues in fix PRs. | Pending ADRs 0090, 0091 (prov.), W3 |
| D19 | Scope, **revised by David on 2026-09-29** (it supersedes the 09-28 "network-and-trust layer" wording): x0x is the glue between people, their machines and their agents and does not provide agents. Core: shared places, sharing whole agent teams, and efficiency (goal E). Headline requirement: any agent that sees x0x knows how to use it. R8 media calling and the loro notes merge path are lower priority, not in scope now. | Pending ADR 0095 (prov.), after promotion |
| D20 | R12, "x0x is maintained by its own agents", is agreed; its ADR is accepted after promotion. The charter plans ADR 0097 (prov.) to supersede ADR 0045 alongside it. | Pending ADR 0096 (prov.), after promotion |
| D21 | Track M-safety (M1 health verdict, M2 safe apply with self-rollback) starts right after v0.46.0, in parallel with W3; W3 gets a second author lane. | Ruled |
| D22 | Owner-key custody: a rotate/recertify and lost-device runbook now, and ADR 0100 after promotion. ADR 0015 stands until then; the planned ADR 0100 supersedes it for the owner root only, together with device delegation. | Ruled; ADR 0100 (prov.) after promotion |
| D23 | Revocation permanence and priority: no sweep before `not_after`, a Machine issuer path, Critical carriers, a fail-closed store, one listing. ADR 0080 is revised as a capability-gated single-record push. Both apply before any `shed_normal` default. | Pending ADR 0098 (prov.), W4 |
| D24 | A protocol-aware stream gate: the connect ACL governs forward and exec targets, owner protocols pass on owner trust, unregistered protocols are reset. | Pending ADR 0099 (prov.), W4 |
| D25 | An inbox policy `[dm] accept = open / contacts / owner_and_grants` on both DM paths, default open. | Pending ADR 0099 (prov.), W4 |
| D26 | The Leaf egress default (ADR 0078, Proposed) is decided after v0.46 as one bundle together with unicast capability responses, a gated DM bus and envelope collapse (ADR 0101, prov.), in the E-D6 order. Revocation topics are exempt first, and the shed estimate is re-measured first. | Ruled (decision deferred to W4) |
| D27 | Cuts after v0.46, as removal-only PRs: roaming (retire ADR 0037/0043), `/mls/groups`, the peer relay (reject ADR 0051) at ADR 0071's exit, the KV DM fallback once `Outbox<T>` exists, dead code. Withdraw ADR 0063. Decline grantee fetch; the number 0076 stays unused. | Ruled; ADR 0102 (prov.) retires roaming |
| D28 | ADR hygiene: ADR 0083 implementation is held after slice 1 until a cross-model review is recorded; new slices of ADR 0070, 0077 and 0079 are held until their reviews are recorded; the other "Reviewers pending" ADRs get a README note. | Implemented in the ADR README overlay |
| D29 | An ADR 0089 slice is pulled into v0.46, overriding the moratorium for this slice only: persist verified agent→machine bindings and KEM keys for relationship peers (enrolled devices, grant parties, group members); an on-connect evidence exchange; a pull lookup ("who hosts agent X; send me its signed announce"); ADR 0021's no-persistent-cache rule amended for relationship peers only. Amended (David, 2026-09-30): stored authority is capped at 7 days and re-validated by a fresh Hello. | ADR 0089 Accepted (2026-09-30, #1095); S1–S5 merged and shipped in v0.46.0 |
| D30 | v0.46 gains a restart-cold gate row backed by a CI test (DM, TreeKEM join/Welcome, file offer and owner sync after a cold restart), plus row 4b: a restarted rc sender to a 0.45 receiver within 5 minutes. | Ruled |
| D31 | PR #1092 (reconnect re-announce) is fixed, then merged as a stopgap until the D29 slice supersedes it: no debug print, per-node bytes and verifies stated including churn, a minimum peer absence before re-announcing, and a cross-model review. Amended (David, 2026-09-30): the absence threshold is 20 s, not about 5 minutes, because real restarts (15–30 s) never reached 5 minutes; the global 30 s rate limit stays. | Superseded by ADR 0089 evidence slices |
| D32 | Fix the paper drift now, docs only: this digest, the ADR README status overlay, ADR 0087, #966, the missing planned issues, tracker hygiene, and W3, M-safety and W4 milestones. | In progress |
| D33 | ADR 0089's scope is a pull lookup plus persisted evidence for relationship peers, on top of D17. | Implemented: ADR 0089 Accepted; S1–S5 merged |
| D34 | The three D16 holes: (1) in ownerless groups, an active admin's signed terminal snapshot attests stale-base catch-up (a mandate layer above ADR 0016, which gives #871 a re-seat path); (2) any online admin that receives a revocation evicts and rekeys within a bound, and group membership joins I7's live-session rule; (3) up to K certificates travel inline and the rest by hash, fetched from any holder (ADR 0088 owns fetch-by-hash). | Pending ADR 0088 (prov.) |
| D35 | Sharing and mixed versions: a 90-day maximum ShareGrant lifetime with renewal (ADR 0098); after a restart, obligation-carrying typed sends to peers of unknown capability are held for up to one advert period; a minimum supported version and support window for embedders is published, owned by M1's census. | Ruled; lifetime pending ADR 0098 (prov.) |
| D36 | Planning: W4 is re-sequenced so A5 (scratch store plus Data capability) and a team record come right after M3; named-group fanout joins E-D17's protected delivery classes before any shed default; every review finding on a merged PR becomes an issue or a written dismissal within 24 hours. | Ruled; the review rule is recorded by ADR 0087 (Accepted) |
| D37 | ADR 0088 is a short I8 contract (the may-block-forever list, completion with any one admin or holder online, supersessions and numbered slices); each mechanism has a separate ADR, reproduced in the harness and Accepted separately. Drafting starts at W3-0 after promotion. | Ruled (2026-10-01); ADR 0106 Accepted and shipped in v0.46.0; remaining slices pending |
| D38 | Home ownership implies consent to disclose the owner's user certificate **to Home members only**; public announces stay anonymous without explicit consent. The fix must stop an anonymous public announce contradicting the Home-scoped certificate; size it before promising a date. | Pending ADR 0088 slice, v0.46.x (2026-10-01) |
| D39 | Before promotion, test (A) retained membership state after a refused or timed-out join and (B) a repeated seal after 300 s; any reproduction needs a blocker-or-limitation ruling. A reproduced; B did not. The initial fix and then known-limitation rulings for A were superseded by D43; joiner re-arm and authority re-Welcome remain v0.46.x work. | Implemented: CI-only hazard probes; final recovery ruling D43 (2026-10-02) |
| D40 | Revocation eviction is designated-first: the lowest online active-admin agent ID evicts and rekeys; another admin acts only after the bound expires. The slice amends ADR 0016's committer rule and proposes the bound for acceptance. | Pending ADR 0088 slice (2026-10-01) |
| D41 | An active admin's signed terminal snapshot lets a stale joiner or forked node adopt state and clear **its own** marker only; it cannot mark another member forked, evict anyone or clear another member's marker. | Pending ADR 0088 slice (2026-10-01) |
| D42 | Adopt the canonical Home in place as the explicit owner group, preserving its group, roster and data; stop auto-provisioning and election. Duplicates stay until their user retires them; test that 0.45/0.46 peers see no new closed-enum Tier-1 kind. | Pending ADR 0088 slice (2026-10-01) |
| D43 | Restore #1148 to v0.46.0: a stuck non-member recovers through owner removal and a fresh invite; an active device without keys needs removal while online, restart and a fresh invite. Rewrite the tests to this recovery, re-gate Home and re-tag. | Implemented in v0.46.0 (2026-10-02); supersedes the D39(A) drop ruling |
| D44 | Run the two missing mixed-version checks before row 8: ShareGrant to a 0.45 recipient and a 0.45 joiner against a 0.46 authority. Accept the other measured row-4 results, including the fail-closed old-to-new DM result. | Ruled (2026-10-02); W2 complete |
| D45 | Merge #1155 to keep `Cargo.lock` LF on checkout, then move the v0.46.0 tag to that merge after the Windows source-custody failure; approve the replacement release run. | Implemented (2026-10-02) |
| D46 | Merge #1157 so custody verification accepts GNU sha256sum's binary-mode `*` marker, then move the v0.46.0 tag to that merge and approve the replacement release run. | Implemented (2026-10-02) |
| D47 | A designated release operator may approve build, sign and draft-creation environments for David-authorized `v*` tags checked against their commit; each approval is rechecked and recorded. Publishing, tag changes, draft downloads and production changes still need David's specific approval. | Ruled; standing instruction (2026-10-03) |
| D48 | Authorize downloading verified v0.46.0 draft Linux bytes (`cea64f2`) for row 7a's sealed testnet arm and six-fixture batch after signature, checksum and provenance checks; production deployment still needs separate approval. | Ruled (2026-10-03); W2 complete |
| D49 | Authorize row 7a's production pair to run the draft daemon with retained backups, hash and configuration checks, rolling restarts 15 s apart and a 30-minute watch; rollback restores the backup. Keep the draft unpublished and do not use self-update for this step. | Ruled (2026-10-03); W2 complete |
| D50 | Sign row 8's v0.46.0 known limitations as written: 15 items, including 7b and 7c. | Implemented; signed 2026-10-03 |
| D51 | Run the signed-update canary on two production hosts while holding two others; re-enable the held hosts only after health passes, otherwise keep the hold and manually roll back the canary pair. | Passed (2026-10-03); all six production hosts (12 daemons) upgraded and healthy |
| D52 | Publish v0.46.0 as Latest (tag `v0.46.0`, commit `cea64f2`) and promote crates.io and ClawHub. | Implemented; published 2026-10-03 |
| D53 | v0.46.1 includes #1103 (fork-clear seal arms), #1150(a) (joiner re-arm, under D55), #1144 (exact-basename extraction and magic check), #1086 (update check after API bind), release-note lines for #1120, #336 and #1103, and #857 (gossip fan-out). #857 waits for saorsa-gossip PR #106 and a saorsa-gossip release; its crates.io publish needs David's approval at the time. | Ruled (2026-10-03) |
| D54 | ADR 0088 uses S5 fetch-by-hash from any holder for missed group events, with catch-up control blobs under S5, instead of a persisted authority catch-up log; S5 is the single certificate-carry rule and #1143 becomes a rule change. Record ADR 0062 as Accepted (option 1, #617 shipped) and ADR 0063 as Rejected. In-process red tests do not satisfy D16's harness-first rule. Add to I8's may-block-forever list: groups with a signed owner delete, removed members' catch-up on epochs after removal, ordinary group forks without an owner anchor until manual admin action (ADR 0066), and evidence fetches while all holders are offline. | Ruled (2026-10-03); ADR 0088 pending |
| D55 | Allow #1150(a) alone to ship in v0.46.1 with its committed red test; its W3-H harness case follows later. Every other liveness fix still requires harness reproduction first (D16, D54). | Ruled (2026-10-03); exception for #1150(a) only |
| D56 | #857 (gossip fan-out) moves to v0.46.2: saorsa-gossip PR #106 failed its second review. v0.46.1 ships without it, and the known limitation stays. | Ruled (2026-10-03) |
| D57 | ADR 0107 (0088 S8 (a)) is Accepted as written. The #1150 (a) code must conform to it. | Implemented (2026-10-03) |
| D58 | ADRs 0088, 0094, 0095 and 0096 are Accepted as written. Their open questions stay open. | Implemented (2026-10-03) |
| D59 | Cut v0.46.1 without #1150 (a), which moves to v0.46.2. | Implemented (v0.46.1 released 2026-10-04) |
| D60 | Every delivery and resend of a class-K group key share requires the recipient's current eligibility and the current secret epoch (G11). | Ruled (2026-10-03); #1190, v0.46.2 |
| D61 | GO for the v0.46.1 draft-bytes check on test hosts, then a hand install on two production hosts. | Implemented (2026-10-03) |
| D62 | GO for the v0.46.1 publish and canary. | Implemented (2026-10-04) |
| D63 | Bind each ADR 0088 slice to an ADR (S2 0108, S3 0109, S4 0110, S5 0111, S6 0112, S7 0113, S8 (b) 0114). Each lands Proposed after a cross-model review and is accepted separately, in 0088's order. Revise ADR 0080 to a capability-gated single-record push. | Ruled (2026-10-04); ADRs Proposed |
| D64 | ADR 0088 (G7), does L3 bind every slice? **Hard rule, every slice**. Each slice must show a typed refusal or typed wait for every block it adds or touches, including the 120 s poll and upgrade or backoff waits. | Ruled (2026-10-04); ADR 0088 Accepted |
| D65 | ADR 0088, 'S8' in the order means S8(a): **Confirm**. Use the order the slice ADRs already use. | Ruled (2026-10-04); ADR 0088 Proposed |
| D66 | ADR 0108, certificate push timing and rounds: **Accept recommended policy**. A 30 s fallback and retry slot, with shared rounds anchored to the signed commit that triggered delivery and ranked on the same verified roster, so reconnect or restart never resets the anchor and divergent views wait for reconciliation. | Ruled (2026-10-04); ADR 0108 Proposed |
| D67 | ADR 0108, certificate file cap, pruning and fairness: **Accept recommended limits**. A 16 MiB file cap, pruning for departed Home seats only after their membership is invalidated, and fair scheduling by Home inside ADR 0089's existing budgets. | Ruled (2026-10-04); ADR 0108 Proposed |
| D68 | ADR 0108, joiner's own certificate on Home gossip: **S5 owns it**. S5 adds the digest-only-add rule, with its security argument and mixed-version plan, and fills the bytes by fetch-by-hash. | Ruled (2026-10-04); ADR 0108 Proposed |
| D69 | ADR 0110, designated window W and completion bound: **Size from measurement**. Set both from the harness p99.9 (99.9th percentile) of hand-off skew plus disk, CPU and propagation time, with margin. | Ruled (2026-10-04); ADR 0110 Proposed |
| D70 | ADR 0110, machine-only revocation and seat eviction: **Deny that device only**. Keep the seat and block every delivery and resend to the revoked machine. | Ruled (2026-10-04); ADR 0110 Proposed |
| D71 | ADR 0110, certificate expiry as an eviction trigger: **Yes, an S4 trigger**. Expiry creates the same bounded eviction work as a revocation. | Ruled (2026-10-04); ADR 0110 Proposed |
| D72 | ADR 0110, retention of eviction work records: **Accept recommended rule**. Keep pending evidence until verified completion or a signed group deletion, and the authors propose limits for completed evidence. | Ruled (2026-10-04); ADR 0110 Proposed |
| D73 | ADR 0110, fallback stagger Δ and restart sync wait: **Accept recommended values**. Δ at least the measured p99.9 seal-and-propagation time, compared at 2 to 5 s in the harness, and a restart sync wait at least the measured p99.9 head catch-up, provisionally 10 to 30 s, after which the node uses its verified local head only if it found no other holder and no conflicting evidence. | Ruled (2026-10-04); ADR 0110 Proposed |
| D74 | ADR 0110, lowest roster admin or lowest reachable: **Lowest roster admin**. Every node picks the same admin with no reachability data. | Ruled (2026-10-04); ADR 0110 Proposed |
| D75 | ADR 0110, sole eligible admin is revoked: **Typed wait, block sends**. Show 'waiting_for_eligible_admin_revocation' to every member and block member sends, and you rule the recovery or deletion exit before implementation. | Ruled (2026-10-04); ADR 0110 Proposed |
| D76 | ADR 0110, legacy survivors and crypto-only removal: **Draft rule**. Hold only for known Active legacy survivors and strand the rest until they upgrade. | Ruled (2026-10-04); ADR 0110 Proposed |
| D77 | ADR 0109, removed-admin attestation exposure: **Accept as stated**. Any active admin on the node's own roster may attest, in both group types. | Ruled (2026-10-04); ADR 0109 Proposed |
| D78 | ADR 0109, owner-axis forked nodes: manual or automatic: **Manual, ruled under item 7**. Rule that item 7 covers this wait, and an admin re-seats the node by hand. | Ruled (2026-10-04); ADR 0109 Proposed |
| D79 | ADR 0109, does a re-seat need subject consent? **Admin authorisation is enough**. The subject applies a valid authorisation with no human step. | Ruled (2026-10-04); ADR 0109 Proposed |
| D80 | ADR 0109, who may act under §2 item 7: **Keep both**. The operator clear handles a stale sibling marker on a node that is on the chain, and the admin re-seat brings a forked node back. | Ruled (2026-10-04); ADR 0109 Proposed |
| D81 | ADR 0109, home exclusion from S3 and S6: **Lift behind a test**. Allow Home only after released v0.45.0 and v0.46.1 binaries, with no owner-sync pointer, show no duplicate Home and no home.json change through reload and provisioning, and block Home activation if any test fails. | Ruled (2026-10-04); ADR 0109 Proposed |
| D82 | ADR 0109, scope of the pre-Welcome link rule: **Every link kind**. Gaps with renames or role changes, and the promoted-admin case, converge in S3. | Ruled (2026-10-04); ADR 0109 Proposed |
| D83 | ADR 0109, S3 attestation and limit values: **Accept recommended values**. At most 64 links per ATA, a 10-minute arm window, a 30-minute armed lifetime, a 10-minute gate stall, request backoff from 60 s doubling to 1 h, responder limits of 1 response per requester per interval, 4 concurrent builds and 32 signatures and 1 MiB per minute, a recovery list of 32 per group for 24 h, and 16 retired records per group. | Ruled (2026-10-04); ADR 0109 Proposed |
| D84 | ADR 0114, new joiner with an old authority: **LegacyCompatible completion**. Complete under today's checks, visibly marked as lacking new confirmation, while encrypted keyless attempts end in a bounded typed timeout. | Ruled (2026-10-04); ADR 0114 Proposed |
| D85 | ADR 0114, recovery after confirmed key loss: **Manual exit is enough**. Keep the typed refusal and D43's remedy. | Ruled (2026-10-04); ADR 0114 Proposed |
| D86 | ADR 0114, trigger for leaf replacement without invite: **Only with recorded evidence**. Replace only when this device recorded the seat as never confirmed, and receipt-less older seats use the manual exit. | Ruled (2026-10-04); ADR 0114 Proposed |
| D87 | ADR 0114, who signs a Home repair mandate: **Repair and promoted-admin forms**. The owner device signs with its USER key, or a promoted admin signs a form checked against the owner-anchored parent, its current Admin seat and every member's valid owner certificate. | Ruled (2026-10-04); ADR 0114 Proposed |
| D88 | ADR 0114, widen ADR 0016 §6 to repair rekeys: **Widen it**. The committer excludes the requesting seat and admins without current verified crypto state, the lowest online eligible admin commits first, and fallback uses S4's Accepted rules. | Ruled (2026-10-04); ADR 0114 Proposed |
| D89 | ADR 0114, repair time, link and byte bounds: **Accept recommended bounds**. S4's final window and completion bound plus 120 s for terminal delivery and install, ADR 0107's poll windows and 10-minute staging lifetime unchanged, at most three buffered links (remove, add, role) within existing byte caps, and a 10 s exchange cap that also bounds the sealer lookup. | Ruled (2026-10-04); ADR 0114 Proposed |
| D90 | ADR 0114, repair abuse budget: **Accept recommended budget**. One pre-verify request per group and member per 30 s (burst two), the same allowance per group and forwarding admin, at most two automatic replacement seals without a receipt and then D43's manual exit, backoff of 1 then 10 minutes, all surviving restarts, with retention proposed by the authors. | Ruled (2026-10-04); ADR 0114 Proposed |
| D91 | ADR 0114, ship the #1191 fix early: **Ship with S8(b)**. Hold it for the full slice. Not the recommendation. | Ruled (2026-10-04); ADR 0114 Proposed |
| D92 | ADR 0114, receipt MAC construction: **BLAKE3, as specified**. Domain-separated BLAKE3 derive_key and keyed MAC. | Ruled (2026-10-04); ADR 0114 Proposed |
| D93 | ADR 0111, inline certificate cap K = 4: **Accept K = 4**. About 38.7 KB per message, so one event or one S2 push covers a 5-seat group. | Ruled (2026-10-04); ADR 0111 Proposed |
| D94 | ADR 0111, private-KV history (#811) in S5: **Yes, a fourth kind**. S5 serves KV images under the same serving guard. | Ruled (2026-10-04); ADR 0111 Proposed |
| D95 | ADR 0111, pre-member roster fetch for #646: **Allow invite-bound fetch**. A joiner with a signed invite that binds the root may fetch that roster. | Ruled (2026-10-04); ADR 0111 Proposed |
| D96 | ADR 0111, when to retire the #946 topic fetch: **Keep until the D35 minimum**. Keep topic answers and the 10-minute refusal for legacy peers until D35's minimum supported version drops them. Not the recommendation. | Ruled (2026-10-04); ADR 0111 Proposed |
| D97 | ADR 0111, exit when a member falls behind retention: **Treat it as admission**. Any admin re-Welcomes the member, through S8(b) or a later ADR. | Ruled (2026-10-04); ADR 0111 Proposed |
| D98 | ADR 0111, S5 retention, fetch and timeout values: **Accept recommended values**. Retain 128 events per group (about 6.6 MB) under 16 MiB per group and 256 MiB per node, allow 16 outstanding fetches to 3 holders with one request per digest and holder per 30 s, limit responders to the existing staging caps and 8 requests per requester per 10 s, time out at 10 s inline and 115 s per blob pull, and probe the head every 5 minutes. | Ruled (2026-10-04); ADR 0111 Proposed |
| D99 | ADR 0112, invite single use and admin failover: **Addressed only, refuse unresolved**. V5 any-admin works only for invites addressed to one agent, and another admin refuses a fresh spend while the first may have committed ('redemption_unresolved'). | Ruled (2026-10-04); ADR 0112 Proposed |
| D100 | ADR 0112, owner-certified redemption forks: **Prevent the forks**. S6 must show before acceptance how V5 avoids OwnerCertified forks. | Ruled (2026-10-04); ADR 0112 Proposed |
| D101 | ADR 0112, upgrade barrier before S6 activation: **All-member upgrade barrier**. A group activates only when every member runs S6. | Ruled (2026-10-04); ADR 0112 Proposed |
| D102 | ADR 0112, S6 attempt and retry budgets: **Accept the shipped windows**. Use 120 s for TreeKEM and 10 minutes for GSS, and the authors propose the discovery, fetch and retry limits for your ruling before acceptance. | Ruled (2026-10-04); ADR 0112 Proposed |
| D103 | ADR 0112, V5 invite role cap: **Member-only for now**. Admin grants stay on V4 until a reviewed extension. | Ruled (2026-10-04); ADR 0112 Proposed |
| D104 | ADR 0112, V5 expiry, tombstones and backpressure: **Mandatory finite expiry**. Every V5 invite expires, an admin prunes tombstones only by a committed change after expiry and clock checks, and the authors propose lifetime, clock-skew, storage and exhaustion values for your ruling. | Ruled (2026-10-04); ADR 0112 Proposed |
| D105 | ADR 0112, approve S6's wider amendments: **Approve them**. S6 amends 0064 §1 and §1b, 0107, 0110 and 0109 as listed, leaving Accepted texts untouched. | Ruled (2026-10-04); ADR 0112 Proposed |
| D106 | ADR 0113, create Home during owner setup? **Create at setup**. Setup creates the Home through the same create path and guards, which refuse when a binding exists or is pending. | Ruled (2026-10-04); ADR 0113 Proposed |
| D107 | ADR 0113, old-binary duplicate Homes: **Known limitation**. State it in release notes until all owner devices upgrade. | Ruled (2026-10-04); ADR 0113 Proposed |
| D108 | ADR 0080, reuse the push for lost devices? **Yes, reuse it**. ADR 0098 uses the same single-record, capability-gated push with its own bit and prefix. | Ruled (2026-10-04); ADR 0080 Proposed |
| D109 | ADR 0080, revocation horizon across grant renewal: **Leave to ADR 0098**. This ADR follows 0098's choice. | Ruled (2026-10-04); ADR 0080 Proposed |
| D110 | ADR 0080, pushed records during a store hold: **Enter the in-memory set**. The revocation acts at once in memory, the file stays untouched, and a push never lifts the hold. | Ruled (2026-10-04); ADR 0080 Proposed |
| D111 | ADR 0080, live-session bound starts at receipt: **Confirm, from receipt**. The bound starts when the host first receives the record, by push or gossip. | Ruled (2026-10-04); ADR 0080 Proposed |
| D112 | ADR 0080, record deliver_to for the push: **Yes, in the implementing slice**. Record it as a versioned share-grant store change (ADR 0085). | Ruled (2026-10-04); ADR 0080 Proposed |
| D113 | ADR 0080, positive-evidence gate and unknown wait: **Confirm both**. Push only on positive evidence and wait up to 600 s for an unknown peer. | Ruled (2026-10-04); ADR 0080 Proposed |
| D114 | ADR 0080, does the D28 hold cover this? **Wait for the review**. Code merges after the D28 review is recorded. | Ruled (2026-10-04); ADR 0080 Proposed |
| D115 | GO to publish saorsa-gossip 0.5.87 (#106 and #108, for x0x#857); the x0x exact-pin bump follows as a normal PR gated by the v0.46.2 test-host checks. | Ruled (2026-10-04) |
| D116 | Cut v0.46.2 without #1190: the test-host run found late or missing key shares after an owner restart. v0.46.2 = #857, #1196, #1100; #1150 moves to v0.46.3. | Ruled (2026-10-04) |
| D117 | ADR 0088 slices, cause notice for the 120 s join timeout: **One notice, owned by S2**. The admin signs an attempt-bound pending notice with a cause, served on the joiner's existing join-result poll under ADR 0107's guard. Later slices reuse it. | Ruled (2026-10-04); ADR 0088 slices Proposed |
| D118 | ADR 0088 slices, confirm the named additions to 0088 §2: **Confirm all four**. Cost: the §2 list grows from 8 to 12 entries, each with a harness case. | Ruled (2026-10-04); ADR 0088 slices Proposed |
| D119 | ADR 0088 slices, confirmed member behind every holder's retention: **Widen S8(b) now**. 0114 also repairs confirmed members. Not the recommendation. | Ruled (2026-10-04); ADR 0088 slices Proposed |
| D120 | ADR 0088 slices, unreadable slice sidecar files: **Automatic rebuild**. Each slice quarantines the file and rebuilds it from holders. Not the recommendation. | Ruled (2026-10-04); ADR 0088 slices Proposed |
| D121 | ADR 0088 slices, D78 and 0088 §2 item 7: **Named amendment**. Add the owner-axis case to §2 explicitly. | Ruled (2026-10-04); ADR 0088 slices Proposed |
| D122 | ADR 0088 slices, 'Lowest online' or 'lowest roster' admin: **D74 everywhere**. 'Online' in D88 and 0088 §3 reads as 'eligible on the roster'. The others fall back after W. | Ruled (2026-10-04); ADR 0088 slices Proposed |
| D123 | ADR 0108, push pair with no anchor proof: **Re-anchor on the current head**. Capture the node's current verified head as the new proof and persist it. | Ruled (2026-10-04); ADR 0108 Proposed |
| D124 | ADR 0108, two Home disclosures to non-members: **Keep both and name them**. I add both to the ADR 0007 overlay in the ADR README. | Ruled (2026-10-04); ADR 0108 Proposed |
| D125 | ADR 0108, end date for the D96 and D68 exceptions: **Later ruling**. The exceptions have no date until then. | Ruled (2026-10-04); ADR 0108 Proposed |
| D126 | ADR 0110, exit when no eligible admin remains: **Proposed set**. Owner-certified groups: an owner-signed recovery commit removes the revoked admin and promotes one eligible member. Every admin expired: the self-rebind in the rebinding question below. Ordinary groups: a deletion exit, typed `group_admin_revoked`, with a re-create offer, as a named §2 entry. | Ruled (2026-10-04); ADR 0110 Proposed |
| D127 | ADR 0110, expiry tolerance τ: **τ = 300 s**. Today's `EXPIRY_CLOCK_SKEW_SECS`, so eviction and D60's delivery refusal use one test. | Ruled (2026-10-04); ADR 0110 Proposed |
| D128 | ADR 0110, limits for completed eviction evidence: **Accept**. Drop evidence bodies 30 days after verified completion. Keep a compact record, at most 4,096 per group, until group deletion. A node that leaves ends local retention once it has handed its evidence to an eligible admin, or at once if it may no longer send. | Ruled (2026-10-04); ADR 0110 Proposed |
| D129 | ADR 0110, in-place certificate rebinding commit: **Define it; admins or the seat's own agent**. As (a), and the seat's own agent may rebind its own seat. This supplies the every-admin-expired exit. | Ruled (2026-10-04); ADR 0110 Proposed |
| D130 | ADR 0112, ownerCertified fork prevention: **Develop the candidate**. The authors write it as normative text with its L4 argument, for your review. | Ruled (2026-10-04); ADR 0112 Proposed |
| D131 | ADR 0112, discovery, fetch and retry limits: **Accept**. Discovery: 8 candidates per round, 3 lookups in flight, 30 s rounds, then every 5 min. Fetch: S5's ruled values. Redeemer: answer within 90 s (TreeKEM) or 9 min (GSS). The 2 s poll with a resend about every 6 s. Probes at 30 s, 1, 2 and 4 min, then every 5 min, ±10% jitter. | Ruled (2026-10-04); ADR 0112 Proposed |
| D132 | ADR 0112, V5 lifetime, skew, storage and exhaustion: **Accept**. Lifetime: default 7 days, maximum 30. Skew: 5 min. Storage: 4,096 tombstones per group and 16 MiB per node. Exhaustion exit: a 5-minute maintenance pass with designated-first prune. With no admin online, the wait falls under §2 item 3. | Ruled (2026-10-04); ADR 0112 Proposed |
| D133 | ADR 0112, promotion chain for a joiner before membership: **Yes, narrowly**. Only that chain, and only on that admin's direct, guarded result path. | Ruled (2026-10-04); ADR 0112 Proposed |
| D134 | ADR 0113, home setup for seeded identities: **Exception**. Setup creates a Home only for a new random identity on a fresh install. Seeded, rotated or re-created identities report `home: not_requested` with the next step. | Ruled (2026-10-04); ADR 0113 Proposed |
| D135 | ADR 0113, announced renewals no longer keep a seat: **Accept**. An expiring seat needs a rebinding commit. | Ruled (2026-10-04); ADR 0113 Proposed |
| D136 | ADR 0114, evidence that a seat was never confirmed: **Admission-time marker**. The sealing admin signs a marker bound to the seating commit, carried on the chain, so any admin can check it. Seats without a marker, including every pre-upgrade seat, use the manual exit. | Ruled (2026-10-04); ADR 0114 Proposed |
| D137 | ADR 0114, retention of repair budget records: **Accept**. Keep a seat's limiter and budget record while that seat generation is on the roster and unconfirmed. Delete it on a verified receipt. Keep an exhausted budget until removal, ban or group deletion, so restarts cannot reset it. Drop entries for identities that leave the roster. | Ruled (2026-10-04); ADR 0114 Proposed |
| D138 | ADR 0114, roles that repair cannot restore: **Add to the S8(b) §2 entry**. Part of the named 'S8(b) manual-exit repair' entry. | Ruled (2026-10-04); ADR 0114 Proposed |
| D139 | ADR 0080, 5 s bound on a daemon that is sending grants: **Split the ingest**. Insert into the in-memory set and start re-evaluation at once, then take the gate for outbox ordering. | Ruled (2026-10-04); ADR 0080 Proposed |
| D140 | ADR 0080, valid copies dropped before the ingest: **No, exclude them**. The bound starts at the first copy that reaches the ingest. | Ruled (2026-10-04); ADR 0080 Proposed |
| D141 | ADR 0080, cap on a recorded deliver_to list: **64 agents**. The shared-agent cap. A longer list is still delivered but not recorded (`not_recorded`, cause `over_cap`). It bounds the file at about 2 MiB. | Ruled (2026-10-04); ADR 0080 Proposed |
| D142 | ADR 0080, gossiped records during a store hold: **Same rule**. Recorded as a requirement on ADR 0098: a gossiped record also acts in memory during a hold. | Ruled (2026-10-04); ADR 0080 Proposed |
| D143 | ADR 0080, recent outcomes kept for the grants diagnostics: **Keep the last 1,024 outcomes**. In memory, oldest first out. | Ruled (2026-10-04); ADR 0080 Proposed |
| D145 | ADR 0088 slices, replies to a joiner that is not yet a member: **Named amendment to 0107**. Same rule, written as an amendment owned by 0108 §8 and reused by 0112. | Ruled (2026-10-04); ADR 0088 slices Proposed |
| D146 | ADR 0088 slices, exceptions to Accepted authority rules: **Approve all four**. Each follows a design you chose (D126, D129, D87, D130). | Ruled (2026-10-04); ADR 0088 slices Proposed |
| D147 | ADR 0088 slices, local-only state lost to a corrupt file: **Accept them**. Each loss ends in a typed state with a stated next step; nothing is silently trusted. | Ruled (2026-10-04); ADR 0088 slices Proposed |
| D148 | ADR 0088 slices, keeping quarantined copies: **Keep until the operator or group deletion**. Never deleted automatically, except that a group's copies go when that group's own files are deleted. Diagnostics list each copy with its size. | Ruled (2026-10-04); ADR 0088 slices Proposed |
| D149 | ADR 0108, review the JoinPendingNotice design: **Approve**. S2's Accept still waits on the other S2 items. | Ruled (2026-10-04); ADR 0108 Proposed |
| D150 | ADR 0108, withdraw retry interval: **Once per 30 s slot**. Once per D66 30 s slot per (Home, holder), about 126 bytes each; it stops when nothing is missing. | Ruled (2026-10-04); ADR 0108 Proposed |
| D151 | ADR 0110, review the rebinding and owner-recovery designs: **Approve**. S4's Accept still waits on the other items here and the harness numbers. | Ruled (2026-10-04); ADR 0110 Proposed |
| D152 | ADR 0110, an owner who never acts: **Named §2 entry**. "OwnerCertified group waiting for its owner", typed `waiting_for_eligible_admin_revocation` or `waiting_for_admin_certificate_renewal`, exit: the owner signs or renews. | Ruled (2026-10-04); ADR 0110 Proposed |
| D153 | ADR 0110, legacy members across the new exit commits: **Extend it**. Same hold-and-strand rule, written into §6's named entry. | Ruled (2026-10-04); ADR 0110 Proposed |
| D154 | ADR 0110, joiner notice when no eligible admin exists: **Any Active member signs one cause**. Any Active member may serve the notice with the single cause `no_eligible_admin`. It grants nothing. 0108's signer rule changes to match. | Ruled (2026-10-04); ADR 0110 Proposed |
| D155 | ADR 0110, self-rebind cutoff: **Cutoff, then hand to the admin**. Before `not_after − τ` the agent self-rebinds; after it, the agent hands the renewal to the designated admin, who commits it. | Ruled (2026-10-04); ADR 0110 Proposed |
| D156 | ADR 0109, owner-axis re-seat needs the owner's key: **Promoted-admin re-seat mandate**. A `ReseatMandateV1` modelled on D87's repair mandate. | Ruled (2026-10-04); ADR 0109 Proposed |
| D157 | ADR 0111, what the promotion chain shows the joiner: **Accept it**. The joiner is already seated when it receives the chain, and would see the roster anyway. | Ruled (2026-10-04); ADR 0111 Proposed |
| D158 | ADR 0111, rebuild attempts per file: **Once per file per run**. A failed rebuild waits for the next daemon start. | Ruled (2026-10-04); ADR 0111 Proposed |
| D159 | ADR 0112, review the replay design: **Approve**. Includes the new acceptance rule (retiring a valid sibling). | Ruled (2026-10-04); ADR 0112 Proposed |
| D160 | ADR 0112, forks that replay cannot settle: **Demotion precedence plus a §2 entry**. When one branch first demotes or removes an admin and every rival commit is by that admin, the demoting branch survives. Anything else becomes the named §2 entry `owner_fork_unanchored`, exit: an owner-anchored advance. | Ruled (2026-10-04); ADR 0112 Proposed |
| D161 | ADR 0112, a joiner that sent two requests: **Keeps the seat**. The evidence is shown to admins, who may remove it the normal way. | Ruled (2026-10-04); ADR 0112 Proposed |
| D162 | ADR 0112, s6 values not yet ruled: **Accept**. Prune margin 10 min after expiry; 256 bytes per consumption entry; a terminal's validation time no earlier than its predecessor's minus 5 min; replay on the 5-minute maintenance pass; members keep fork-point tree state, and joiners their init keys, for 30 days (the maximum invite lifetime). | Ruled (2026-10-04); ADR 0112 Proposed |
| D163 | ADR 0112, replay over the tombstone cap: **Bounded overflow**. The replay lands and may exceed the caps by the retired branches' entries; new V5 mints and redemptions refuse with `invite_capacity_exhausted` until prunes bring it under. | Ruled (2026-10-04); ADR 0112 Proposed |
| D164 | ADR 0112, which redemption wins when two retired branches used one invite: **Branch hash, then entry order**. Order retired branches by terminal hash, lowest first, then entries within each branch; the first redemption keeps the seat, and the other consumes nothing more. | Ruled (2026-10-04); ADR 0112 Proposed |
| D165 | ADR 0112, two admins add different late admissions at once: **Narrow exception**. A replay-fork marker that depends only on the original fork's evidence may be settled by one combined replay that covers both sets. Unrelated containment stays. The combined evidence is recorded durably. | Ruled (2026-10-04); ADR 0112 Proposed |
| D166 | ADR 0114, adoption exception, vouchers and residuals: **As proposed**. Allow the exception for §7 only, two vouchers or the owner mandate, and add both residuals to the S8(b) manual-exit entry. | Ruled (2026-10-04); ADR 0114 Proposed |
| D167 | ADR 0114, proof that a member kept its group keys: **Retention token**. At each confirmation the member derives a token from its epoch exporter secret; its receipt records the token's hash. The member keeps the token wrapped under its current epoch key and reveals it once to prove retention. Losing the snapshot loses the token. | Ruled (2026-10-04); ADR 0114 Proposed |
| D168 | ADR 0114, ciphertext from skipped epochs: **Named §2 entry**. "Skipped-epoch ciphertext", typed `history_gap {from_epoch, to_epoch}`, no exit; current store state still arrives through S5. | Ruled (2026-10-04); ADR 0114 Proposed |
| D169 | ADR 0080, lost deliver_to lists: **Empty replacement**. Lists are lost; those grants become `not_recorded`, cause `quarantined`. Revocation still works by gossip. | Ruled (2026-10-04); ADR 0080 Proposed |
| D170 | ADR 0109, which removals a promoted admin may undo: **only its own removals**. A node removed by another admin needs that admin or an owner-key admin (a named L1 limit). | Ruled (2026-10-04); ADR 0109 Proposed |
| D171 | ADR 0108, Withdraw retries: **a monotonic 30 s interval**, separate from D66 slots. David's note led to a Lamport recovery generation with no wall time. | Ruled (2026-10-04); ADR 0108 Proposed |
| D172 | ADR 0108, D66 push slots: **wall time read once, then monotonic**, keeping the fractional slot phase. | Ruled (2026-10-04); ADR 0108 Proposed |
| D173 | ADR 0108, future-dated slot anchor: **hold with a typed `anchor_future_dated` wait** on the shared signed `committed_at`; only rank 1 pushes once wall time passes it. | Ruled (2026-10-04); ADR 0108 Proposed |
| D174 | #1190 may ship in v0.46.3 without a real-network survivor-rekey check, given in-process coverage and a clean short eph re-check; the fixture follows (#1216). | Ruled (2026-10-05) |
| D175 | Ship v0.46.3 with #1190; the removal-notice finding (#1217) moves to v0.46.4. | Implemented (v0.46.3 released 2026-10-05) |
| D176 | Full GO for v0.46.3, including the crates.io and ClawHub promotion. | Implemented (2026-10-05) |
| D177 | Continue the v0.46.3 rollout after a harness-setup timeout on the first Home run (second run at the 103/104 baseline). | Implemented (2026-10-05) |
| D178 | ADR 0108 (S2, Home-scoped owner certificate) is Accepted as written, including its §5a shared quarantine lifecycle, its §8 JoinPendingNotice and its named amendment to ADR 0107. | Implemented (2026-10-05); ADR 0108 Accepted |
| D179 | Claude takes over as controller of the agent team; Root stays release manager. | Implemented (2026-10-05) |
| D180 | Codex and OMP author code on every lane (extends D07's W2-only exception); every PR is reviewed by a different model family; lanes follow the resolution plan §4. | Implemented (2026-10-05) |
| D181 | Red cases in the W3-H simulation harness (#1164), shown red on main in CI, satisfy harness-first (D16); standalone in-process tests still do not (D54 stands). | Ruled (2026-10-05) |
| D182 | ADR 0094: release manifests may be at most 5 min in the future (same 300 s rule as certificates and V5 invites). | Ruled (2026-10-05) |
| D183 | ADR 0094: compiled rollout window 60 min for installs with self-update enabled. | Ruled (2026-10-05) |
| D184 | ADR 0094: fleet rollout default 60 min and minimum 60 min; private rehearsal hosts with the test key may use 0. | Ruled (2026-10-05) |
| D185 | ADR 0094: an authenticated API apply waits for staging unless it asks `now=true`; eligibility, holds and transaction checks always apply. | Ruled (2026-10-05) |
| D186 | ADR 0094 / ADR 0087 rule 7: the prerelease ban stays; lifting it needs a later human-accepted ADR with census evidence. | Ruled (2026-10-05) |
| D187 | ADR 0094: probe time limit 90 s (Defender's 60 s maximum plus 30 s to run). | Ruled (2026-10-05) |
| D188 | ADR 0094: host faults are Interrupted, classified by phase; failures during rollback or a hold write are recovery-failed. | Ruled (2026-10-05) |
| D189 | ADR 0094: interrupted attempts retry as fresh transactions at 30, 60 and 120 min (N = 3), then hold with `retries_exhausted`. | Ruled (2026-10-05) |
| D190 | ADR 0094: a failed-release hold clears on a newer release or an authenticated, recorded local clear; never for recovery-failed. | Ruled (2026-10-05) |
| D191 | ADR 0094: shutdown flush limit 30 s. | Ruled (2026-10-05) |
| D192 | ADR 0094: trial budget 11 min — 30 s flush, 3 launches of 120 s readiness + 60 s stable health, 10 s reap and 10 s gap; restore allowances defined. | Ruled (2026-10-05) |
| D193 | ADR 0094: local checks block commit; a host that had a send-ready peer must reach one and keep it through the stable interval (a miss is Interrupted). | Ruled (2026-10-05) |
| D194 | ADR 0094: keep the last committed binary pair as recovery material; refuse staging below 1 GiB free. | Ruled (2026-10-05) |
| D195 | ADR 0094: SKILL.md installs only after the verified candidate's health holds; the prior guide is kept and restored in recovery. | Ruled (2026-10-05) |
| D196 | W3-H is verdict-stable: all 20 CI reruns give the same verdict with complete structured receipts (setup, evidence, delivered request, exact cause for RED; every precondition for GREEN). Byte-identical canonical traces are reported but non-blocking; ordering and entropy work continues. This satisfies D181 and supersedes the old identical-trace criterion. | Ruled (2026-10-05) |
| D197 | EvidenceV1 admission for relationship peers (same group roster, same owner, grant counterparty) needs not-Blocked trust; Unknown is allowed, Blocked is refused, and the evidence must verify. This matches ADR 0089 decision 2. | Ruled (2026-10-05) |
| D198 | The 100 numbered ADRs consolidate into 15 replacement slots A01–A15. The direction and approximately 80% ASD-STE100 target for ADRs, docs and PR text are confirmed by David; drafts stay Proposed until he accepts the transfer. Keep technical terms; no claim of formal compliance. | Ruled (2026-10-05); transfer Pending |
| D199 | During transfer, new or changed decisions use the numbered ADR series only (ADR 0087). Slot revisions are drafts. Reserved numbers stand: 0090/0091 (D18), 0097 (D20), 0098 (D35), 0084–0105 (D63). Slices 0109–0114 continue to numbered acceptance. | Ruled (2026-10-05) |
| D200 | Accepted ADR 0040 stands: task-list CRDT `owner_agent`, with transfers signed by the current owner. A12 states that decision and reports implementation separately; the decision is not deferred. | Ruled (2026-10-05) |
| COMMS | Use plain controlled language (about 80% toward ASD-STE100), fixed decision templates and one release contact; record and share each ruling, check live GitHub before requesting approval, keep the release dashboard current and include diagrams in briefs. Trial explainer videos after promotion. | Ruled; adopted 2026-10-02 |

## 6. Efficiency decisions E-D1–E-D17 (Track E)

Levers are ranked by evidence: measure first, then quick wins with no wire
change, then structural wire work under ADRs. v0.46.0 carries no efficiency
code; it only measures.
Lever codes in parentheses (S1, Q14, U1 and so on) are the efficiency plan's
identifiers. E-D1 and E-D2 were approved in staged form, E-D3 and E-D17
as ruled, and E-D4 to E-D16 as recommended.

| Id | Ruling (one line) | Status |
|---|---|---|
| E-D1 | Efficiency budgets become release criteria through an ADR drafted after promotion. v0.47 gates on exact tier-0 tests plus a relative A/B rule on a sealed mesh (N ≥ 5 deploys per arm); absolute ceilings start in the wave whose levers can reach them. | Ruled; budgets ADR after promotion |
| E-D2 | The v0.47 target column is accepted; later-wave targets are revisited after the first baseline and the first v0.47 A/B. | Ruled |
| E-D3 | The first efficiency baseline (E0) runs on a dedicated, ephemeral testnet and is non-gating for v0.46. Preconditions: the ephemeral-testnet harness has passed its adversarial review, and host metrics (SK-1) and a different binary per node (SK-2) have landed. Provisioning, teardown and cleanup of the ephemeral hosts run under a standing approval from David (given 2026-09-29, expiring 2026-10-30). It covers ephemeral hosts only and requires the production hosts to stay up. Anything beyond it (extra spend, a lifetime over 72 hours, more than 12 hosts, adopting an existing host, discarding evidence) needs his explicit approval. | Ruled; run outstanding |
| E-D4 | Testnet daemons move off the production bootstrap hosts after promotion, not mid-gate. An earlier move is recorded in the gate sheet as an environment break. | Ruled |
| E-D5 | jemalloc ships in release builds in v0.47 (not in frozen v0.46), after a 24-hour no-restart A/B that shows RSS/allocated ≤ 1.5×. | Ruled |
| E-D6 | The Leaf egress bundle (D26) is decided as one bundle, in this order. (1) Unicast capability responses (S1) and capability-gated DM-bus hedges (Q14/S2). Q14 lands only with an **Accepted** ADR, the #952 per-kind bus counters, and a mixed-version DM matrix that is green in both directions, with the hedge evidence showing no rise in 504-after-delivery. (2) Consume-only Leaves (S3), only once Full-node relay capacity is budgeted. (3) An enforced Leaf budget (S4), with revocation topics exempt first. Every step passes the delivery guard (E-D17); enforcement never goes first or alone. | Ruled |
| E-D7 | Session-authenticated hop-local control frames (U1) in saorsa-gossip, in W4, after message-id-to-signer binding (U4). Negotiated per session; legacy sessions stay signed. Ranked from measured per-kind verify counters, not from the unmeasured estimate. | Ruled; upstream design issue and ADR after promotion |
| E-D8 | Post-quantum envelope collapse (U5): the lock on it is lifted after promotion **for drafting only**. The draft moves ADR 0021 machine binding and message-id-to-publisher binding into the inner envelope, because the outer signature is end-to-end origin authentication on eager forwards. Implementation waits for W4, and only after U1 (session-authenticated control frames), U4 (message-id-to-signer binding) and E0's measurement of the key cache's fleet effect. | Pending ADR 0101 (prov.) |
| E-D9 | Direct-first durable DM (persist-then-ACK on a live authenticated connection, gossip inbox as fallback) is W3's one delivery primitive, amending ADR 0030/0050. It is gated strictly on an ADR 0093 capability bit, because 0.45 receivers ACK and drop unknown typed DMs. Its latency target is set against RTT + fsync + ACK measured in E0. | Pending ADR (amends ADR 0030/0050), W3 |
| E-D10 | Gossip-learned strangers are no longer persisted as contacts; they stay in the TTL-bounded discovery cache, and apps use `/agents/discovered`. W3, with an ADR drafted after promotion. | Pending ADR, W3 |
| E-D11 | A metered/edge profile and an embedder power API (foreground, background, suspend) come in W4, after the transport liveness contract (ADR 0104, prov.) and with the resume work. After promotion, embedders are asked for measurement rigs (OS bytes per day, wakeups, battery). | Ruled |
| E-D12 | SKILL.md splits into a signed core of at most 2k tokens plus on-demand topic pages, with a CI token budget, right after promotion (not during the gate, to avoid signing churn mid-release). | Ruled |
| E-D13 | A binary size gate and release-profile tuning (LTO, codegen-units=1, strip on all platforms) in v0.47. A 1 MiB stripped growth in one PR needs David's sign-off; the stripped `x0xd` size is measured directly first. `.tar.gz` assets stay for ADR 0061 updaters, and a daemon-only update-asset split needs its own ADR. `release.yml` changes are merged by David. | Ruled |
| E-D14 | A new ML-DSA backend (SIMD, expanded-key caching) is benchmarked only. An ADR follows only for a candidate showing ≥ 2× on x86_64 and arm64, with KAT/ACVP vectors and a constant-time review. | Ruled |
| E-D15 | The efficiency rules apply to every PR and ADR, fixes included: as a review checklist now, and as CI lints in v0.47 (tier-0 size and count tests, the cache-registry test, the log-storm test, the size gate and the delivery matrix). | Ruled; checklist in force |
| E-D16 | UDP receive buffers: E0 records the configured maximum and the effective socket buffer now, with no change. The sysctl is raised on production hosts after promotion (a mid-gate change is an environment break). ant-quic reports the effective size in v0.47, and the setting is documented for embedders. | Ruled |
| E-D17 | A delivered/published matrix **and** the hedge bytes-versus-latency evidence are a hard gate on every lever that sheds, prunes, gates or re-routes bytes. Own-origin, inbox, targeted and revocation classes deliver 100%, and no pair falls below baseline. It is measured on a sealed all-RC mesh **and** on a mixed 0.45↔RC mesh, in both directions, under budget pressure. A byte saving that loses a message is a failure. Named-group fanout joins the protected classes (D36). | Ruled |

**The efficiency rules in brief (E-D15).** A byte saving that loses a message
is a failure. Every topic declares its audience and rate, and request/response
and ACK traffic goes to the requester only. Costs are stated as wire bytes in
both directions, including post-quantum envelopes. Every periodic task, cache,
queue and map states its budget, is bounded and is visible. Persistence is
O(change). Signatures are used only where transferable authenticity is needed,
and every verify is counted. Compatibility carriers name a sunset.
`[profile.test]` never raises `opt-level` for x0x crates. Measurements are
repeated, sealed-mesh and stated with their evidence level.

## 7. Wave plan

Calendar figures are estimates.

| Wave | What it is | State (2026-10-03) |
|---|---|---|
| **W0: ops now** | Stop the bleeding (the log flood), seal the testnet, lock scope, answer field reports. | Started 2026-09-28 |
| **W1: land #802** | The final-acceptance candidate lands on `main` as one integration merge, with no tag. | Done (merge `952ed18`, 2026-09-28) |
| **W2: v0.46.0 gate** | Fixes only, released against the signed relative gate (D02, D03, D30). Must-land: C1 (#1046, ADR 0085), the #1044 panic follow-up, the tracked lock and prerelease refusal, the self-upgrade rehearsal, the release environment, and any regression the gate finds. Should-land fixes merge by the cutoff or drop to a signed known limitation. Efficiency is measured only. | Complete; v0.46.0 published 2026-10-03 (tag `v0.46.0`, commit `cea64f2`) |
| **v0.47 (early W3)** | Efficiency quick wins with no wire change, counters and tier-0/1 gates; the budgets ADR and ADR 0101 drafted; the SKILL.md split. | After promotion |
| **W3: group consolidation (Track G)** | ADR 0088 liveness contract; a deterministic multi-node simulation harness that reproduces #1023, #811, #818 and #969 before they are fixed; `Outbox<T>` (ADR 0090); one seal-and-publish service; in-band evidence and `Authority::decide` (ADR 0089); a `GroupAccess` extractor; one roster-commit path; one group crypto (ADR 0091); a digest beacon for KV and task lists (ADR 0092). Efficiency rides these chokepoints. | 10–14 weeks after promotion |
| **Track M-safety (parallel with W3)** | M1 health truth (a `/health` verdict, census, `x0x doctor --json`); M2 safe apply (supervised readiness and self-rollback, one binary writer per host, StagedRollout wired or deleted; ADR 0094). Exit: a crash-looping release on a supervised host is restored by the new binary with no SSH, and reported. | M-safe about 4–6 weeks after promotion |
| **W4: goal build (A, M)** | Scope ADR 0095 and R12 (ADR 0096) first. Then one R at a time, behind default-off flags, on a weekly train: M3 recall → A5 scratch store, Data capability and a team record (D36) → A2 lost device and revocation permanence → A4 sharing completeness → A3 device delegation → M4 owner update policy and canary → A6 offline delivery → M5/M6 problem reports and install help → A7 reach. The Leaf egress bundle (D26/E-D6) and the envelope work (E-D7, E-D8) also land here. | A and M exits Q1–Q2 2027 |

**Exit tests.** Goal A: the two-human end-to-end test passes in CI, and a
restarted owner device keeps owner trust with zero manual steps. Goal M: one
release is promoted under an owner's policy with a ring-0 attestation, and one
deliberately bad canary is rolled back and recalled automatically.

## 8. Parked, frozen, deprecated and cut

- **Parked (lower priority, D19).** R8 media calling: ADR 0042 and ADR 0073
  (the `/calls` signalling lifecycle stays, labelled experimental), #892. The
  rich-text notes merge path: ADR 0081, ADR 0082 and the notes half of
  ADR 0075, #1029, PR #1035. The scratchpad half of ADR 0075 is **not**
  parked; it is core and is re-specified as a sealed scratch store (ADR 0103,
  prov.).
- **Frozen (bug and security fixes only).** The placement ledger; relay
  metering and ADR 0035 steps 2–6 (ADR 0071); fork-quarantine layers beyond
  the marker and manual clear (ADR 0059, 0064, 0066, 0067, 0068), except
  where D16/D34 supersede them; Home auto-provisioning and election
  (ADR 0038, 0060, 0069), where after promotion Home failures are known
  limitations unless they are security defects; legacy Wiki/Web import; the
  A2A binding (#112, deferred); the constitution; public-message threading
  (ADR 0029).
- **Parked issues.** #442 and #443 (won't-do, D27), #639, #871, #112, #892,
  #1029. #646 is not parked (D13).
- **Deprecated.** The legacy DM bus (after a version floor); GSS group
  creation; raw 0x10 as a silent fallback; `x0xd --check-updates` as an apply
  path.
- **Cut after v0.46 (D27, removal-only PRs).** The roaming key-move ceremony
  and `/agent/move*`; `/mls/groups` and the MlsGroup side map; the X0X-0070
  peer relay (ADR 0051 rejected) at ADR 0071's exit; the KV DM fallback once
  `Outbox<T>` exists; dead code (`EncryptedTaskListDelta`, X0K2,
  `BootstrapConnector`, FOAF scoring, `combined_to_bytes`, the ADR 0063 V3
  publish path); dead config fields; the standalone apply path of
  `x0x upgrade` when a daemon answers.

## 9. Process rules

- **Moratorium through v0.46.0 promotion (completed 2026-10-03).** Only fix ADRs were admissible:
  ones that record a fix to shipped or merged behaviour, a storage format, or
  deployment governance. The D29 slice of ADR 0089 was the one exception.
- **ADRs before code** (ADR 0087, Accepted). Two rules apply together. A
  change to a network behaviour, a storage format, a protocol or a security
  bound has a Proposed ADR on `main` before its code merges to any branch,
  integration branches included. In addition, a wire, protocol or dependency
  change has its ADR Accepted before its code merges to `main`. An ADR
  written after the fact to record shipped behaviour uses the status
  `Accepted (record)`.
- **Accepted ADRs are immutable.** A change is a new ADR that amends or
  supersedes, or a README erratum for a factual correction. Only David marks
  an ADR Accepted. Implementation holds are decisions, not status changes
  (D28).
- **Cross-model review.** A change is reviewed by a model family other than
  its author's. A should-land fix that is not green within two
  review rounds by the cutoff drops to a known limitation.
- **Review findings** on merged PRs become an issue or a written dismissal
  within 24 hours (D36, ADR 0087).
- **Fix PRs shrink the system.** A fix may not add an AppState map, outbox,
  background loop or per-call-site gate; prefer removing one.
- **Efficiency.** Every PR applies the E-D15 checklist.
