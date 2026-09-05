# x0x reliability campaign — slice (2) user acceptance scenarios

**Owner:** Tester
**Scope:** Reproducible user-acceptance matrix. Observes real product paths (CLI/REST against **local named instances**). Does **not** implement product fixes on #507 / #508 / #509 / #512.
**Out of scope as product pass:** [#510](https://github.com/saorsa-labs/x0x/issues/510) (P2 — test scheduling/diagnostics; [source-grounded triage](https://github.com/saorsa-labs/x0x/issues/510#issuecomment-5551971328)). Treat as **harness risk only**. Never close a product gate because an isolation re-run was green. Do **not** weaken required observations, skip/quarantine the tests, inflate deadlines, or add retries to paper over flakes (ADR-0025: completed observations; a genuine production-path bug has presented with the same isolated-pass signature).

**Target regressions (product):**

| PR | Closes / refs | Failure class |
|---|---|---|
| [#507](https://github.com/saorsa-labs/x0x/pull/507) | Partial #449 / ADR-0060 (**#449 stays open**) | Election + honest `GET /home` + provision suppression + withdrawn-Home guards. Does **not** seat a second device. HomeInvite / cross-device adoption **withdrawn**. |
| [#508](https://github.com/saorsa-labs/x0x/pull/508) | #341 Phase B | Encrypted group KV publishes plaintext / leave retains write / fail-open without context |
| [#509](https://github.com/saorsa-labs/x0x/pull/509) | #506 | **Proved class (a):** local discovery residual (`GET /groups/discover` synthesizing withdrawn Hidden cards). **Unproved class (b):** public broadcast to the mesh — do not claim PASS/FAIL without evidence. |
| [#512](https://github.com/saorsa-labs/x0x/pull/512) | Corrected source `f1418a0`; live acceptance pending | Unknown/zero-machine ACP mint deferred and old unsafe ingest bypass removed. Authenticated listener regression remains required; helper-only test is insufficient. Offline G1–G6 / S1 are oracle evidence only. |

**Durable DM baseline:** ADR-0030 — product `POST /direct/send` is durable-by-default; 200 = recipient committed + dispatched; 409 `recipient_ack_semantics_unavailable` against non-v2; no silent downgrade.

**Fixture rules (all scenarios):**

1. Two (or three) **named local instances** under distinct `X0X_HOME` / data dirs and ports — e.g. `alice`, `bob`, `alice-device-b`. Prefer loopback + shared hermetic `network_id`, **not** production mesh / public discovery daemons.
2. Observe via CLI (`x0x …`) and matching REST. Prefer CLI when it is the product surface.
3. Each scenario names **PASS** and the **FAIL signature** that proves the target regression is still live.
4. Do not bump timeouts, quarantine/skip required tests, or add retries to paper over flakes and make a scenario green (#510 / ADR-0025).
5. No merge / release from this slice. Authors do not approve their own PR.

## Matrix

### A. Install / update

| ID | Scenario | Steps (product path) | Acceptance (PASS) | Fails for |
|---|---|---|---|---|
| A1 | Fresh owned install provisions Home | New `X0X_HOME`, start daemon, load owner, `GET /home` / `x0x home` | Exactly one Home; `state` `local`; version healthy | Pre-#507 duplicate-mint class |
| A2 | Un-owned install has no Home | Fresh install without owner key; `GET /home` | Documented 404 / un-owned message; no silent Home | False Home invent |
| A3 | Upgrade path does not invent a second Home | Install A on tip; enroll device B sharing owner; both `GET /home` | Same canonical Home (`group_id` when `state` is `local` / pre-#507; `canonical_group_id` when `elsewhere` / `adoption_pending`); never two authoritative Homes. Seating B is #449 (open), not current #507. | **#507** (report + no mint); #449 open |
| A4 | Downgrade caveat surface | Owned install on tip; ops #451 forbids on old bins | Product refuses or docs warn | Related #451 |

### B. Identity / Home

| ID | Scenario | Steps | Acceptance (PASS) | Fails for |
|---|---|---|---|---|
| B1 | Single Home per owner (enrolled) | Device A provisions; enroll B; B reconciles | B does not mint; both agree on pointer. Seating is not required for current #507. | **#507** |
| B2 | Honest `GET /home` reporting | On B before seat: `GET /home` | 200 `state=elsewhere` (`canonical_group_id`, no `group_id`) or `state=adoption_pending` (`canonical_group_id` = winner; `group_id` may be the local loser) naming **A's** Home — not B's duplicate as canonical | **#507** |
| B3 | Withdrawn Home excluded | Withdraw Home; `GET /home` / provision | Tombstone not canonical; provision not wedged | **#507** D5 |
| B4 | Rider / device auto-seat | Owner-certified Rider present | **Out of scope for current #507.** Mode-based exclusion (`OwnerIssuedCert.mode`) is unsound under Accepted [ADR-0039](../adr/0039-agent-harness-boundary.md) (mode-agnostic Home eligibility; synced journal materializes mode `Acp`). Inventing a device-only filter would amend ADR-0039 — forbidden for the current #507 PR. Full device-vs-rider Home eligibility needs future ADR / #449 work. Do **not** require “Rider never joins Home” as a #507 PASS. | future ADR / #449 — not a current #507 gate |
| B5 | Pointer election terminates | Two enrolled conflicting Homes; wait ≥2 reconciles | Pointer stops flipping | **#507** D3 |

### C. Invite / join / leave / revoke

| ID | Scenario | Steps | Acceptance (PASS) | Fails for |
|---|---|---|---|---|
| C1 | Home adoption invite | Winner mints HomeInvite; joiner redeems mode home | **Pending future #449 implementation / ADR review** — not current #507 acceptance. HomeInvite / cross-device adoption is **withdrawn** from current #507. Current #507 multi-device PASS is honest reporting + no new mint when a pointer already names a Home (B1 / B2 / A3), not seating. | future #449 — not a current #507 gate |
| C2 | Ordinary invite single-use | Invite; join; replay | Replay refused; no double seat | baseline |
| C3 | Leave encrypted group cuts KV | Leave; attempt put/get | Fail closed | **#508** |
| C4 | Remove member cuts encrypted KV | Ban/remove; peer put | Fails | **#508** |
| C5 | Hidden withdraw local residual | Withdraw Hidden/Home; probe **local** `GET /groups/discover` | **Proved class (a):** local discovery must not synthesize a live card for a withdrawn Hidden/Home. **Unproved class (b):** public broadcast to the mesh — do not claim PASS/FAIL without evidence. | **#509** (local residual) |
| C6 | Public withdraw still tombstones | Public group withdraw; probe **local** discovery | Local view: tombstone supersedes the prior public card. Mesh-wide public broadcast is unproved — do not claim PASS/FAIL without evidence. | #509 local residual |

### D. Durable DMs (ADR-0030)

| ID | Scenario | Steps | Acceptance (PASS) | Fails for |
|---|---|---|---|---|
| D1 | Durable both-ways warm | Two local v2 instances; durable send both ways | 200 under budget; incoming increases; C5c on 200/504 | ACK-return residual |
| D2 | Strict vs non-v2 | Durable to non-v2 | 409 recipient_ack_semantics_unavailable | ADR-0030 |
| D3 | Opt-out nodur | require_durable_app_ack false | 200 accepted-for-delivery | confusion |
| D4 | logical_id idempotency | Same logical_id twice | Re-ACK / conflict on different bytes | ADR-0030 |
| D5 | Restart mid-durable | Kill recipient mid-ACK; restart; retry | At-least-once commit | history |

### E. Offline / restart / reconnect

| ID | Scenario | Steps | Acceptance (PASS) | Fails for |
|---|---|---|---|---|
| E1 | Home survives restart | Restart same X0X_HOME | Same Home local; no second mint | **#507** |
| E2 | Encrypted KV survives restart | Put; restart; get | Value present; sealed on wire | **#508** |
| E3 | Offline then enroll | B comes online enrolled | Honest `GET /home` (same canonical via `state`); no second mint. Seating is #449, not current #507. | **#507** (report + no mint) |
| E4 | Kill during Hidden withdraw | Withdraw; kill; restart; scan **local** discovery | Still no synthesized Hidden card on local discover. Do not treat unproved public broadcast as the gate. | **#509** (local residual) |

### F. Tasks + group KV

| ID | Scenario | Steps | Acceptance (PASS) | Fails for |
|---|---|---|---|---|
| F1 | Task list CRUD | x0x tasks create/add/claim/complete | Consistent after restart | baseline |
| F2 | Encrypted store create + put/get | POST /groups/:id/stores Encrypted | Round-trip sealed | **#508** |
| F3 | Plaintext delta rejected | Plaintext on encrypted topic | Never merges | **#508** |
| F4 | Unconfigured encrypted sync | Publish without secure context | Hard error; no plaintext publish | **#508** |
| F5 | Home tasks follow elected Home | Tasks on A; B adopts | **Pending #449 seating.** After B is seated on the elected Home, B sees lists; loser not authoritative. Not a current #507 gate. | future #449 |

### G. ACP harness placement (#512)

Full brief: [`reliability-acp-harness-placement-acceptance.md`](reliability-acp-harness-placement-acceptance.md). **Local-first only.** Corrected #512 source `f1418a0` removes the unsafe bypass; live G3 remains unaccepted pending authenticated identity-ingest regression and retained captures. No Ben Mac. Offline S1 fixtures are ready now.

| ID | Scenario | Steps | Acceptance (PASS) | Fails for |
|---|---|---|---|---|
| G1 | Defer mint until harness machine known | Issue ACP cert; invoke durable-owner `GET /owner/placement` before discovery and retain 200/ok body | Agent absent from successful ledger; pending / unbound — **no** epoch-0 pin to owner machine | **#512** epoch-0 `Pinned(owner)` |
| G2 | After discovery, pin = harness ≠ owner | Harness announces; `GET /owner/placement` + `machines get` | `Pinned(harness)`; harness ≠ owner; `agent_ids` contains ACP id | **#512** still `Pinned(owner)` / empty `agent_ids` |
| G3 | Second local daemon binds agent | Isolated local dual-daemon fixtures | Replica `agent_ids` contains ACP id | Replica empty `agent_ids` (QUIC present) |
| G4 | Intentional/current pin still enforced | Pin to X; announce from Y; journal may say `mode=Acp` | `PlacementPinned` denies; Y must not bind because `mode=Acp` | **#512 HOLD P1** fail-open |
| G5 | Synced Rider issuance must not inherit ACP fail-open | Synced Rider line materializes `mode=Acp`; wrong-machine announce | Pin still enforced | Fail-open via synced `Acp` |
| G6 | No silent repair of existing bad pins | Pre-existing `Pinned(owner)` after upgrade | Do **not** claim auto-heal; recovery needs Proposed ADR | “Upgrade fixed old pins” |

S1 offline oracle: [`reliability-s1-acp-harness-placement-smoke.sh`](reliability-s1-acp-harness-placement-smoke.sh) `--self-test` over [`reliability-s1-acp-fixtures/`](reliability-s1-acp-fixtures/). Retain successful `GET /owner/placement` status/body as `ledger_capture`, then compare `owner_machine_id`, `placement.{kind,machine_id,epoch}`, `harness_machine.{machine_id,agent_ids}` against its rows. A per-agent read-only 404 does not trigger mint. PASS when pinned to harness ≠ owner and `agent_ids` contains the agent, or pending unbound with no pin and no ledger row for the agent. Missing/error captures and malformed/contradictory fields are inconclusive. FAIL when pinned to owner with empty `agent_ids`, or bound on a machine that is not the pin. Missing `placement` → 3. Wrong-machine bind never PASS.

## Harness risk (#510)

[#510](https://github.com/saorsa-labs/x0x/issues/510) is **P2** (test scheduling/diagnostics; keep open). Triage: [comment 5551971328](https://github.com/saorsa-labs/x0x/issues/510#issuecomment-5551971328). This UAT slice treats it as **harness risk only** — not a product acceptance gate.

Isolation PASS is insufficient to dismiss `hs_f2_membership_cluster` / a2a deadline failures under full-suite load. The same isolated-pass signature has already hidden a genuine production-path defect. Product scenarios run as dedicated local-instance scripts, not saturated nextest.

Do **not**:

- weaken or drop required observations
- skip / quarantine the discovered tests
- inflate wall-clock deadlines first
- add retries / retry-until-green to paper over flakes

Prefer reducing contention (scheduling) over hiding the failure. #510 remains harness-risk only; it does not change product gates on #507 / #508 / #509 / #512.

## First runnable smoke (S0)

Two named local instances sharing owner key (enrolled). Compare `GET /home` using the **#507 wire** (`home.rs` @ `413028e`): read `state`.

Canonical identity by `state`:

| `state` | Canonical id | Authoritative local? | Notes |
|---|---|---|---|
| `local` | `group_id` (required) | yes | `canonical_group_id` is null |
| absent (`pre507_local`) | `group_id` (required) | yes | pre-#507 200 body |
| `elsewhere` | `canonical_group_id` (required) | no | **no `group_id`** on the wire |
| `adoption_pending` | `canonical_group_id` (required) | no | `group_id` is the **losing** local Home — not the comparison key |
| unknown / missing required id / `ok` false | — | — | inconclusive |

- **PASS (0):** both HTTP statuses in 2xx (prefer exactly 200) **and** `A.canonical_id == B.canonical_id` (both non-empty). Covers both-local same `group_id`; A local + B `elsewhere` same canonical; A local + B `adoption_pending` whose `canonical_group_id` matches A even when B.`group_id` is a different local loser.
- **FAIL (1):** both 2xx, both authoritative local, different non-empty `group_id`s.
- **INCONCLUSIVE (3):** non-2xx on either side (never PASS); JSON/schema errors; missing required id for that `state`; contradictory canonicals (e.g. A local/`home-a` + B `adoption_pending` `group_id=home-a` `canonical_group_id=home-c`); anything else.

Runnable skeleton: [`reliability-s0-home-dedup-smoke.sh`](reliability-s0-home-dedup-smoke.sh).

- **Live daemon mode** still uses `ALICE_URL` / `ALICE_B_URL` / `ALICE_TOK` / `ALICE_B_TOK` against already-running local named instances (no mesh).
- **Fixture mode** is the acceptance-oracle proof without a daemon or mesh: `--fixture <name>` or `--self-test` over [`reliability-s0-fixtures/`](reliability-s0-fixtures/). Required fixtures: `pass-same-id`, `pass-elsewhere-canonical`, `pass-adoption-pending-canonical`, `fail-duplicate-local`, `inconclusive-b-500-elsewhere`, `inconclusive-b-503-same-id`, `inconclusive-elsewhere-wrong-id`, `inconclusive-adoption-contradictory-canonical`.

## Future / #449 complete (not current #507 gates)

These remain open until #449 seating lands and any rider/device Home eligibility rule is **ADR-reviewed**. They must **not** be used to declare partial #507 complete.

| ID | Scenario | Why it is not a current #507 gate |
|---|---|---|
| C1 (complete) | HomeInvite redeem seats the joiner on the elected Home | HomeInvite / cross-device adoption **withdrawn** from current #507 |
| B4 (complete) | Device vs Rider Home eligibility | Requires a future ADR. Must not invent `OwnerIssuedCert.mode` exclusion — Accepted [ADR-0039](../adr/0039-agent-harness-boundary.md) is **mode-agnostic** Home eligibility; the synced journal materializes mode `Acp` |
| F5 (complete) | Home tasks follow elected Home after B is seated | Requires #449 seating; current #507 only converges the pointer and reports honestly |
