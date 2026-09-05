# x0x reliability campaign — slice (2) user acceptance scenarios

**Owner:** Tester
**Scope:** Reproducible user-acceptance matrix. Observes real product paths (CLI/REST against **local named instances**). Does **not** implement product fixes on #507 / #508 / #509.
**Out of scope as product pass:** #510 (harness flakiness under parallel load) — treat as harness risk; never close a product gate because an isolation re-run was green.

**Target regressions (product):**

| PR | Closes / refs | Failure class |
|---|---|---|
| [#507](https://github.com/saorsa-labs/x0x/pull/507) | #449 / ADR-0060 | Second enrolled device mints a second Home; `GET /home` lies; pointer oscillation; withdrawn Home still resolves |
| [#508](https://github.com/saorsa-labs/x0x/pull/508) | #341 Phase B | Encrypted group KV publishes plaintext / leave retains write / fail-open without context |
| [#509](https://github.com/saorsa-labs/x0x/pull/509) | #506 | Withdrawing a Hidden group (incl. Home) publishes a public discovery card |

**Durable DM baseline:** ADR-0030 — product `POST /direct/send` is durable-by-default; 200 = recipient committed + dispatched; 409 `recipient_ack_semantics_unavailable` against non-v2; no silent downgrade.

**Fixture rules (all scenarios):**

1. Two (or three) **named local instances** under distinct `X0X_HOME` / data dirs and ports — e.g. `alice`, `bob`, `alice-device-b`. Prefer loopback + shared hermetic `network_id`, **not** production mesh / public discovery daemons.
2. Observe via CLI (`x0x …`) and matching REST. Prefer CLI when it is the product surface.
3. Each scenario names **PASS** and the **FAIL signature** that proves the target regression is still live.
4. Do not bump timeouts or quarantine tests to make a scenario green (#510).
5. No merge / release from this slice. Authors do not approve their own PR.

## Matrix

### A. Install / update

| ID | Scenario | Steps (product path) | Acceptance (PASS) | Fails for |
|---|---|---|---|---|
| A1 | Fresh owned install provisions Home | New `X0X_HOME`, start daemon, load owner, `GET /home` / `x0x home` | Exactly one Home; resolution `local`; version healthy | Pre-#507 duplicate-mint class |
| A2 | Un-owned install has no Home | Fresh install without owner key; `GET /home` | Documented 404 / un-owned message; no silent Home | False Home invent |
| A3 | Upgrade path does not invent a second Home | Install A on tip; enroll device B sharing owner; both `GET /home` | Same `group_id` / honest resolution; never two authoritative Homes | **#507 / #449** |
| A4 | Downgrade caveat surface | Owned install on tip; ops #451 forbids on old bins | Product refuses or docs warn | Related #451 |

### B. Identity / Home

| ID | Scenario | Steps | Acceptance (PASS) | Fails for |
|---|---|---|---|---|
| B1 | Single Home per owner (enrolled) | Device A provisions; enroll B; B reconciles | B does not mint; both agree on pointer | **#507** |
| B2 | Honest `GET /home` reporting | On B before seat: `GET /home` | 200 `elsewhere` or `adoption_pending` — not B's duplicate as owner's Home | **#507** |
| B3 | Withdrawn Home excluded | Withdraw Home; `GET /home` / provision | Tombstone not canonical; provision not wedged | **#507** D5 |
| B4 | Rider agents not auto-seated | Owner-certified Rider present | Rider never joins Home | **#507** |
| B5 | Pointer election terminates | Two enrolled conflicting Homes; wait ≥2 reconciles | Pointer stops flipping | **#507** D3 |

### C. Invite / join / leave / revoke

| ID | Scenario | Steps | Acceptance (PASS) | Fails for |
|---|---|---|---|---|
| C1 | Home adoption invite | Winner mints HomeInvite; joiner redeems mode home | Seats; refused admission retries, never second Home | **#507** |
| C2 | Ordinary invite single-use | Invite; join; replay | Replay refused; no double seat | baseline |
| C3 | Leave encrypted group cuts KV | Leave; attempt put/get | Fail closed | **#508** |
| C4 | Remove member cuts encrypted KV | Ban/remove; peer put | Fails | **#508** |
| C5 | Hidden withdraw must not publicize | Withdraw Hidden/Home; probe discovery | No public card for strangers | **#509** |
| C6 | Public withdraw still tombstones | Public group withdraw | Tombstone supersedes prior public card | #509 regression |

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
| E3 | Offline then enroll | B comes online enrolled | Honest adopt; no duplicate | **#507** |
| E4 | Kill during Hidden withdraw | Withdraw; kill; restart; scan discovery | Still no public Hidden card | **#509** |

### F. Tasks + group KV

| ID | Scenario | Steps | Acceptance (PASS) | Fails for |
|---|---|---|---|---|
| F1 | Task list CRUD | x0x tasks create/add/claim/complete | Consistent after restart | baseline |
| F2 | Encrypted store create + put/get | POST /groups/:id/stores Encrypted | Round-trip sealed | **#508** |
| F3 | Plaintext delta rejected | Plaintext on encrypted topic | Never merges | **#508** |
| F4 | Unconfigured encrypted sync | Publish without secure context | Hard error; no plaintext publish | **#508** |
| F5 | Home tasks follow elected Home | Tasks on A; B adopts | B sees lists; loser not authoritative | **#507** |

## Harness risk (#510)

Isolation PASS is insufficient to dismiss hs_f2 / a2a deadline failures under full-suite load. Product scenarios run as dedicated local-instance scripts, not saturated nextest. Do not raise budgets/auto-retry first.

## First runnable smoke (S0)

Two named local instances sharing owner key (enrolled). Compare GET /home. FAIL if both 200 local-ish with different group_ids. PASS if same group_id or B reports elsewhere/adoption_pending.

Runnable skeleton (observes already-running local named instances; does not start daemons): [`reliability-s0-home-dedup-smoke.sh`](reliability-s0-home-dedup-smoke.sh).
