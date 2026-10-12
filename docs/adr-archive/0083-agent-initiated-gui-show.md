# ADR 0083: Agents Show Their Owner a GUI View, Locally or on the Owner's Active Machine

<!-- File name: docs/adr/0083-agent-initiated-gui-show.md -->

- **Status:** Accepted
- **Accepted:** 2026-09-28 by David Irvine (decisions Q1–Q5; remote show on by default; status change applied by Claude at his instruction)
- **Date:** 2026-09-27
- **Decision owners:** David Irvine (decision), Claude (drafting)
- **Reviewers:** pending — David Irvine (acceptance); omp (cross-model review)
- **Supersedes:** none
- **Superseded by:** none
- **Extends (edits nothing in):** ADR 0039 (adds one rider scope, `gui:show`),
  ADR 0044 (adds one loopback route), ADR 0052 (the GUI gains an origin banner
  and a `gui.show` navigation event), ADR 0070 (a new consumer of §1 owner trust)
- **Related:** vision requirement **R10** ("an agent can open a GUI/browser view
  for its human", ADR 0072 table); issue #893 items 2 and 3; PR #906 (#893 item 1:
  deep links and session refresh); ADR 0050 (DM base); ADR 0057 (local apps);
  ADR 0073 and ADR 0075 (both name R10 deep links as a dependency);
  `.planning/adr-vision-alignment-2026-09-25.md` §5 item 5

## Context

R10 is the last vision requirement without an owning ADR. The 2026-09-25 audit
rated it Partial: `x0x gui` opens the GUI home page on the agent's own machine
only, needs the owner's durable token, and no API lets an agent put a specific
view in front of its human.

Shipped so far (on `codex/final-acceptance-candidate` at 74c34f2, via PR #906):

- **Deep links.** `applyHashRoute()` in `src/gui/x0x-gui.html` (~L891) accepts
  exactly: `#/dm/<hex 16–128>`, `#/groups/<hex>[/<app>]` with `<app>` in
  `HASH_SPACE_APPS` (`chat board files swarm feed wiki web`), and the
  single-segment views in `HASH_VIEWS` (`home homespace discover people network
  presence mls admin settings constitution about`). Anything else is a toast,
  never a navigation.
- **`x0x gui --view <route>`** (`gui_view_fragment`, `src/bin/x0x.rs` ~L3210)
  checks only a character set (`[A-Za-z0-9/_-]`); the GUI decides whether the
  route is a view. There is no Rust-side view grammar.
- **Session refresh.** `POST /auth/session/refresh` gives a sliding 10-minute
  session with a 12 h hard cap (`SESSION_MAX_LIFETIME`, `src/server/auth.rs`).
  The GUI refreshes only while `document.visibilityState === 'visible'`.

Not shipped, and not authorised by any Accepted ADR:

- **No API opens a view.** None of the registry endpoints (`src/api/mod.rs`)
  causes a browser window or GUI navigation.
- **No cross-machine display.** Nothing lets an agent on machine A affect what
  the human sees on machine B. ADR 0070 §1 defines *owner trust* but applies it
  only to trust evaluation, the stream gate and the connect/exec ACLs. ADR 0070
  §4 excludes "UI design beyond REST/CLI parity".
- **Riders cannot reach it.** `rider_route_allowed` (`src/server/rider_auth.rs`
  ~L119) is ADR 0039's complete deny-by-default set: group send, secure encrypt
  and `GET /history`. `RiderTokenRecord` has `groups` but no capability scopes.
- **No "active machine" signal.** Presence (ADR 0049) says a machine is online,
  not that a human is looking at it. `owner_sync` records enrollment, not
  activity.

Opening a window on another machine is a new capability with a new attack
surface. A malicious or buggy agent could spam windows, steal focus, or try to
steer the human to an attacker-controlled page. The capability therefore needs
an explicit decision.

## Decision Drivers

- **R10:** an agent says "look at this" and the human sees exactly that view,
  on the machine they are using.
- **No new authority for riders.** A rider must never obtain a GUI session.
  A session is owner-class authority (`ActorContext::Owner { durable: false }`),
  far wider than any rider scope.
- **Only the GUI's own views.** The target opens its own loopback GUI at a
  validated route. It never opens a URL, host, port or scheme taken from a
  request.
- **The human stays in control.** The human can see who caused a window, can
  turn the feature off, and cannot be flooded.
- **Reuse, don't invent.** ADR 0070 owner trust for authority, the ADR 0050 DM
  base for transport, the #906 session and deep-link machinery for display.
  No new crypto, no new topic, no DHT.

## Considered Options

1. **Local only (`POST /gui/show` on the caller's own daemon).** Simple and
   safe, but fails R10 whenever the agent and the human are on different
   machines, which is the common case: agents live on servers, humans on
   laptops.
2. **Return a URL and let the agent deliver it (DM text, email).** Rejected.
   The URL either carries a session token, which hands GUI authority to
   whoever holds the message, or it carries none and the human still has to
   authenticate. It also trains humans to click agent-supplied links.
3. **Broadcast to every owner machine.** Rejected. It opens windows on
   unattended machines, including headless servers, and multiplies the spam
   surface.
4. **Local show plus an owner-trusted typed DM to one chosen owner machine,
   which opens only its own GUI at an allow-listed route (chosen).**

## Decision

### 1. Surface

- **REST:** `POST /gui/show` on the ADR 0044 loopback plane.
  Body: `{ "view": "<route>", "target_machine": "<hex MachineId>" | "active" | null }`.
  `null` or absent means this machine.
- **CLI:** `x0x show <route> [--on <machine|active>]`, a registry entry in
  `src/api/mod.rs` (CLI/REST parity per ADR 0044), documented in
  `docs/api-reference.md`.
- **Response:** `{ "outcome": …, "machine_id": …, "request_id": … }`, where
  `outcome` is one of `opened`, `navigated`, `refused`, `disabled`,
  `rate_limited`, `no_display`, `invalid_view`, `no_active_machine` or
  `unconfirmed`. **The response never contains a URL or a session token**,
  for any caller. This is what stops a rider from turning `gui:show` into a
  GUI session.

### 2. Who may trigger a show

| Caller | Local show | Remote show |
|--------|-----------|-------------|
| Durable owner token (CLI, local apps) | yes | yes |
| GUI session token | yes | yes |
| Rider token **with** `gui:show` scope | yes | yes, to the owner's own machines only |
| Rider token without `gui:show` (the default) | `403` | `403` |
| Remote agent that is owner-trusted (ADR 0070 §1) | — | accepted by the target |
| Remote agent that is not owner-trusted, including sharees under any `ShareGrant` | — | refused by the target |

- **Rider scope.** `RiderTokenRecord` gains `scopes: Vec<String>` with
  `#[serde(default)]`, so existing records load with no scopes.
  `gui:show` is the only value defined here. Unknown scope strings are
  rejected at mint time.
- **Rider route gate.** `rider_route_allowed` admits `POST /gui/show` only when
  the presented rider record holds `gui:show`. This widens ADR 0039's
  allow-list by one route. ADR 0075 describes its `scratch` scope as the only
  such widening, so accepting this ADR records a second, deliberate one.
- **Remote authority.** The target machine enforces authority by evaluating
  owner trust on the sending `(AgentId, MachineId)` with
  `OwnerTrust::is_owner_trusted` (`src/owner_trust.rs`). That check covers the
  certificate chain to the local owner, machine enrollment, revocation and the
  authenticated machine binding, and a `Blocked` contact still refuses. No
  contact entry or ACL entry makes a non-owner-trusted sender acceptable.
- **Riders on remote shows.** A rider's request leaves its daemon signed as
  the registered sub-agent, whose certificate chains to the same owner. The
  `gui:show` scope is therefore enforced at the **originating** daemon. The
  target cannot tell a rider from any other owner agent, and it does not need
  to: both are the owner's. The request carries a provenance flag for the
  banner only (§5).
- **No `ShareCap` for display.** Sharees can never open windows on the
  grantor's machines. Adding such a capability would need its own ADR.

### 3. Choosing the target machine

- **Explicit id.** `target_machine = <MachineId>` must name a machine enrolled
  in the local owner's device set (`OwnerSyncStore::is_enrolled`); otherwise
  the result is `refused`.
- **`active`.** The *owner's active machine* is the enrolled owner machine
  whose GUI most recently reported visible activity:
  - Each daemon records `last_gui_visible_at`. It is updated by any
    authenticated GUI request made while the page is visible; the #906 refresh
    tick already runs only then.
  - The sender asks each online enrolled owner machine for this value with a
    `GuiActivityQuery` typed DM (§6) and picks the most recent value that is
    no older than `ACTIVE_WINDOW` (15 minutes).
  - The local machine takes part like any other.
  - If no machine qualifies, the result is the error `no_active_machine`. It
    asks for an explicit machine and lists the candidate machines so the agent
    can pick one.
  - The query is answered only to owner-trusted senders. Anyone else gets no
    reply, so activity is not observable by strangers.
- **Absent.** The target is this machine.

### 4. What the target does

On a request that passes §2 and §5, the target machine:

1. **Validates `view`** against a Rust-side view grammar,
   `gui::view_route::parse`. It mirrors `applyHashRoute` exactly: `dm/<hex>`,
   `groups/<hex>[/<HASH_SPACE_APPS>]` and the `HASH_VIEWS` singletons, plus the
   ADR 0075 note routes once they ship. A test parses `HASH_VIEWS` and
   `HASH_SPACE_APPS` out of `x0x-gui.html` and fails if the two lists diverge.
   Anything else is `invalid_view`. The request is never forwarded to a
   browser with an unchecked route.
2. **If a GUI tab is live and visible** (it has an open WS), it pushes a
   `gui.show` WS event carrying the validated route and the banner text. The
   GUI navigates in place (`navigated`). No new process or window is created,
   so the human's current tab changes view instead of a new window stealing
   focus.
3. **Otherwise**, it mints a **fresh** session (`SessionStore::issue`, the same
   path as `POST /auth/session`), builds
   `http://<own loopback api_address>/gui?token=<session>#/<route>` itself, and
   launches the platform opener (`open`, `xdg-open`, `cmd /C start`, as
   `x0x gui` does) (`opened`).
   - Host, port and scheme always come from the target's own configuration,
     never from the request.
   - A non-loopback `api_address` is replaced by `127.0.0.1:<port>`.
   - The durable token never appears in the URL (ADR 0044 §3, ADR 0057 §1).
4. **If the opener cannot run** (no display, a headless service), it returns
   `no_display`. It does not retry or fall back.

### 5. Protecting the human

- **Origin banner.** Every show, whether navigated in place or opened in a new
  window, displays a non-dismissable-for-3-seconds banner: "Opened by
  *<agent name or short id>* on *<machine name or short id>*" (with "(rider)"
  when the provenance flag is set). The names are resolved locally, never
  taken from the request. The banner has a "Stop shows from this agent"
  control, which adds the sender to a local `gui_show_blocked` list.
- **Rate limit.** Per requesting `AgentId`: burst 3, then 1 per 20 s, and at
  most 30 per hour per target machine across all senders. Excess requests get
  `rate_limited`. Local and remote shows share the same buckets on the
  machine that displays.
- **Config.** In the `x0xd` config:

  ```toml
  [gui_show]
  local_enabled = true    # POST /gui/show without a remote target
  remote_enabled = true   # accept shows from other owner machines
  ```

  When `remote_enabled = false`, the target answers `disabled`, and activity
  queries are answered `disabled` (with no timestamp). The settings are read
  at startup and on `POST /acl/reload`.
- **Defaults (decided by David Irvine, 2026-09-28; see Decisions on the open
  questions).**
  - Local show is **on** by default: it is no more than `x0x gui --view`
    behind an API.
  - Remote show is **on** by default (`remote_enabled = true`). The draft
    recommended off. David chose on so the R10 acceptance ("machine A shows,
    machine B opens") needs zero setup, since owner trust already bounds who
    can use it. He accepted the remaining risk with the origin banner, the
    per-agent block list and the rate limit as the mitigations. Any machine
    can still opt out with `remote_enabled = false`.

### 6. Wire messages

The messages are typed DMs on the ADR 0050 base, following the ADR 0070
`ShareGrant` pattern (`SHARE_GRANT_DM_PREFIX`, `src/share_grant.rs`): a prefix
followed by a bincode body, and the prefixed DM is consumed by the daemon,
never surfaced to the inbox or history.

```
b"x0x-gui-show-v1\0"        ‖ GuiShowRequest {
    request_id: [u8; 16], view: String /* ≤ 256 bytes, validated again on receipt */,
    issued_at: u64, via_rider: bool }
b"x0x-gui-show-result-v1\0" ‖ GuiShowResult { request_id: [u8; 16], outcome: GuiShowOutcome }
b"x0x-gui-activity-v1\0"    ‖ GuiActivityQuery { request_id: [u8; 16] }
                            | GuiActivityReply { request_id: [u8; 16], last_gui_visible_at: Option<u64>, remote_enabled: bool }
```

- **Authentication.** The DM envelope signature and KEM sealing (ADR 0050)
  authenticate the sender and protect the payload. The receiver then runs the
  §2 owner-trust check before it parses anything beyond the prefix.
- **Freshness.** `issued_at` must be within ±120 s of the receiver's clock.
  The ADR 0050 replay cache (630 s) rejects duplicates, and `request_id`
  de-duplicates retries.
- **Timeouts.** The sender waits up to 10 s for `GuiShowResult`, then returns
  `unconfirmed`. It does not retry automatically: a late window is worse than
  none.
- **Older daemons.** A daemon without this ADR receives the typed DM as an
  opaque direct message. Before sending, the sender checks the target's
  advertised capability `gui_show_v1` and returns `refused` with reason
  `target_needs_upgrade` if it is missing.

### 7. Failure modes

| Failure | Result | Human impact |
|---------|--------|--------------|
| Sender not owner-trusted (other owner, sharee, revoked, `Blocked`, unenrolled machine) | no display; `GuiShowResult{refused}` only if the sender is authenticated | none |
| Route not in the grammar (URL, `..`, unknown view, bad hex) | `invalid_view` at both sender and target | none |
| Rider without `gui:show` | `403` at the originating daemon; nothing is sent | none |
| Remote disabled in target config | `disabled` | none |
| Rate limit exceeded | `rate_limited` | none |
| No display or headless service | `no_display` | none |
| Target offline or DM undelivered | `unconfirmed` after 10 s | none; the agent may retry explicitly |
| No machine active within `ACTIVE_WINDOW` | `no_active_machine` plus candidates | none |
| Stale or replayed request | dropped (freshness or replay cache) | none |
| Clock skew beyond ±120 s | refused `stale_request` | none |

### 8. Non-goals

- Opening arbitrary URLs or `/apps` pages. ADR 0057 §4 keeps `/apps`
  proposal-only.
- Pushing content, rather than a route, to the GUI.
- OS notifications. ADR 0073 depends on this deep-link path but adds no
  notification code, and neither does this ADR.
- Showing to other humans (sharees).
- Any change to ADR 0038 Home or to roaming (ADR 0072).

### 9. Slicing

Each slice ships alone, with its negative tests.

1. **Local show plus the Rust view grammar.** `POST /gui/show` without a
   target, `x0x show`, registry, manifest and docs parity, `[gui_show]
   local_enabled`, the WS `gui.show` navigate-in-place, the origin banner and
   the rate limit.
2. **Rider scope `gui:show`.** The `scopes` field, mint-time validation, the
   route gate and the response-carries-no-token assertion.
3. **Remote show.** The typed DMs, owner-trust receive check,
   `remote_enabled`, the `gui_show_v1` capability, and `active` target
   selection with the activity query.

## Consequences

### Positive

- R10 closes. An agent anywhere in the owner's device set can put a specific
  view in front of the human, on the machine the human is using, with a
  refreshable session (#906).
- The only thing that crosses machines is a validated route name. No URL,
  host or token is ever transmitted.

### Negative / Trade-offs

- **A new owner-trust consumer.** Owner-key compromise, or compromise of any
  owner-certified agent, now also lets the attacker open GUI windows on the
  owner's machines. This is bounded by the route grammar, the rate limit, the
  banner, the per-agent block list and the `remote_enabled` switch, and
  removed by ADR 0018 revocation, but not eliminated.
- **A second widening of the ADR 0039 rider allow-list**, and the first
  rider scope that is not per-group.
- **"Active machine" is a heuristic.** A human at a machine with no visible
  GUI tab is invisible to it, so the agent must name the machine explicitly.
- **Session token in the opener's argv.** When a new window is spawned, the
  session token briefly appears in the opener's argument list and in browser
  history, exactly as `x0x gui` does today. It is short-lived and refreshable,
  never the durable token.

### Neutral / Operational

- Three new typed-DM prefixes and one new capability flag. All are additive,
  and older daemons are detected before sending.
- The GUI view list now has two definitions (JS and Rust), kept equal by a
  test.

## Validation

Every test below runs in CI (not `#[ignore]`), and each fails if the check it
covers is removed.

- **Local:**
  - A durable token shows `people` and gets `opened` or `navigated`.
  - The response JSON contains no `token` or URL field.
  - `view = "https://evil.example"`, `"../x"`, `"dm/zz"` and
    `"groups/<hex>/unknownapp"` each return `invalid_view`, and no opener
    is invoked (the opener is behind a test seam).
  - `local_enabled = false` gives `disabled`.
  - A fourth request inside the burst window gives `rate_limited`.
- **Riders:**
  - A rider without `gui:show` gets `403` on `POST /gui/show`.
  - A rider with `gui:show` gets `opened`, and the response carries no
    session token.
  - A `gui:show` rider still gets `403` on every other non-allow-listed
    route, for example `/auth/session`.
  - A mint request with an unknown scope is rejected.
  - A pre-change rider record deserialises with an empty `scopes`.
- **Remote** (two daemons, same owner, enrolled; the opener behind a seam):
  - A to B with `remote_enabled = true` gives `opened` on B.
  - A daemon with a *different* owner is refused.
  - The same owner with the machine unenrolled is refused.
  - After `POST /identity/revoke` of the sending agent, the sender is refused.
  - A `Blocked` sender is refused.
  - A sharee holding a `ShareGrant` with every cap is refused.
  - A request whose `view` is a URL, sent by a patched sender that skips its
    own validation, gives `invalid_view` on B.
  - A replayed request is dropped.
  - `remote_enabled = false` gives `disabled`.
  - `active` picks the machine with the newest `last_gui_visible_at` inside
    the window, and gives `no_active_machine` when none qualifies.
  - A target without the `gui_show_v1` capability gives
    `target_needs_upgrade`.
- **Grammar parity:** a test extracts `HASH_VIEWS` and `HASH_SPACE_APPS` from
  `x0x-gui.html` and asserts they equal the Rust grammar's lists.
- **R10 acceptance (#893):** an agent on machine A runs
  `x0x show groups/<id>/board --on active`; the human's browser on machine B
  shows that board, and the window still works after 30 minutes (the #906
  refresh).
- **Review trigger:** any change that lets a request carry a URL, host, port
  or token, or that adds a `ShareCap` for display, needs a superseding ADR.

## Decisions on the open questions (David Irvine, 2026-09-28)

- **Q1 — remote show default: ON.** `[gui_show] remote_enabled` defaults to
  `true`. David chose this over the drafted recommendation of off, and
  accepted the risk with three mitigations: the origin banner, the per-agent
  block list and the rate limit (§5).
- **Q2 — local show default: ON.** `[gui_show] local_enabled` defaults to
  `true`.
- **Q3 — `active` target:** the owner machine whose GUI was most recently
  visible within 15 minutes (`ACTIVE_WINDOW`). If there is none, the error
  `no_active_machine` asks for an explicit machine (§3).
- **Q4 — rate limits as drafted:** burst 3, then 1 per 20 s, and at most 30
  per hour per target machine (§5).
- **Q5 — display:** switch the visible open GUI tab to the view, and open a
  new window only when no GUI is open (§4 steps 2–3).

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human
review**. Accepted ADRs are immutable: create a new superseding ADR rather than
editing an Accepted ADR.
