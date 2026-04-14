# Named-Groups Parity — Signoff Report

**Status:** ✅ signoff candidate (with explicit, enumerated gaps)
**Date:** 2026-04-14
**Scope:** `docs/design/named-groups-full-model.md` — all four presets
across every consumer surface.

This report summarises the static and runtime proofs that collectively
demonstrate the named-groups REST API, CLI, embedded GUI, Communitas
Rust client, Communitas Swift client, Communitas Dioxus UI, and
Communitas SwiftUI are feature-equivalent **for everything explicitly
listed as covered**, and clearly enumerates the items that are **not**
yet covered so the reader does not have to infer them.

## The surface-of-truth

`src/api/mod.rs::ENDPOINTS` is the single source of truth.
`tests/api_manifest.rs` projects it to
`docs/design/api-manifest.json` (schema `x0x-api-manifest/v1`). Every
downstream surface reads this manifest to assert coverage.

Named-groups surface: **36 endpoints** (the registry has grown since
the original audit) spanning core CRUD, policy, membership/roles/bans,
join requests, invite/join, public messaging (Phase E), state chain
(Phase D.3), discovery (Phase C + C.2), and the secure plane (Phase
D.2).

## Surface coverage matrix

The number after each surface is **wired endpoints / total with an
explicit, manifest-driven count**. "Deferred" means the endpoint is
intentionally not exposed on that surface for a stated reason and is
listed in the parity test's `DEFERRED` list; "Missing" would mean an
unrecorded gap (zero across all surfaces below).

| Surface | Wired / Total | Static proof | Runtime proof |
|---------|--------------|--------------|---------------|
| **x0xd REST** | **36 / 36** | `tests/api_coverage.rs` — every route handler in `src/bin/x0xd.rs` is in `ENDPOINTS` and has a test entry. 12 tests. | `tests/e2e_named_groups.sh` — 98 REST-driven assertions over a 3-daemon mesh; 3× clean archived. |
| **x0x CLI** | **36 / 36** | `tests/parity_cli.rs` — spawns `x0x <cli_name> --help` for every endpoint. | `tests/e2e_feature_parity.sh` — 18 assertions per run, 3× clean archived. |
| **x0x embedded GUI** (`src/gui/x0x-gui.html`) | **24 / 36** wired, 12 deferred (with reasons) | `tests/gui_named_group_parity.rs` — manifest-driven scan; **fails if a new endpoint is added without either a GUI call site or a `DEFERRED` entry**. Per-endpoint coverage report at `tests/proof-reports/parity/gui-named-groups-coverage.txt`. | Manual; headless harness still queued. |
| **Communitas Rust client** | **36 / 36** named-groups | `parity_manifest.rs` (vendored manifest copy). The IMPLEMENTED list contains 36 entries; the test fails if any named-groups endpoint in the vendored manifest has no client method. 14 tests. | `live_mutation_contract.rs`. |
| **Communitas Dioxus UI** | consumes the Rust client; UI surfaces `enum SpacePreset`, discover view, admin sheet, requests panel | preset round-trip unit test; 419/419 unit tests | UI driver queued for Phase 7. |
| **Communitas Swift client** | **36 / 36** named-groups (every Rust method has a Swift counterpart) | `swift_parity.rs` — `parity_map_covers_all_rust_methods` walks `client.rs` for every public method and `swift_client_has_all_rust_methods` greps the Swift source for each one. | `swift test` — 42/42 pass. |
| **Communitas SwiftUI** | preset picker, discover sheet, manage sheet (policy + state + roster + requests) | `swift build` clean | XCUITest queued for Phase 7. |

## Embedded GUI — explicit DEFERRED list (13 endpoints)

The GUI parity test enumerates every named-groups endpoint and checks
the GUI HTML for a matching `api(...)` call. The following endpoints
are **deliberately not wired in the GUI**, each with the reason
recorded in `tests/gui_named_group_parity.rs::DEFERRED`:

| Method | Path | Reason |
|--------|------|--------|
| POST | `/groups/:id/members` | admin flow; GUI uses invite links instead of direct add-by-agent |
| DELETE | `/groups/:id/members/:agent_id` | admin flow; GUI uses ban rather than direct remove-by-agent |
| GET | `/groups/:id/messages` | GUI gap: signed-message HISTORY read-back from `/messages` not yet wired (SignedPublic SEND now is — see `sendSpaceChatSignedPublic`) |
| DELETE | `/groups/:id/requests/:request_id` | requester-side cancel-request UI not yet wired (admin approve/reject is) |
| GET | `/groups/discover/subscriptions` | power-user surface; CLI covers it |
| POST | `/groups/discover/subscribe` | power-user surface; CLI covers it |
| DELETE | `/groups/discover/subscribe/:kind/:shard` | power-user surface; CLI covers it |
| GET | `/groups/cards/:id` | card inspection-by-id UI not yet wired (the import action is) |
| POST | `/groups/:id/secure/encrypt` | secure-plane primitive; consumed implicitly by encrypted chat |
| POST | `/groups/:id/secure/decrypt` | secure-plane primitive; consumed implicitly by encrypted chat |
| POST | `/groups/:id/secure/reseal` | secure-plane primitive; server-side rekey on approve/ban |
| POST | `/groups/secure/open-envelope` | adversarial test endpoint, not a user-facing action |

**Phase 7 update:** The `POST /groups/:id/send` cross-surface gap is
now closed across all three surfaces (GUI, Dioxus, SwiftUI). Each
chat view fetches the group's `confidentiality` axis on mount and
routes the send through `POST /groups/:id/send` for SignedPublic
groups (so the daemon ML-DSA-signs the body and binds it to the
current state-hash). MlsEncrypted groups keep the existing gossip
path. The remaining piece — pulling **history** for non-member
authored signed posts via `GET /groups/:id/messages` so they appear
in the chat view alongside live-gossip messages — is still queued.

## Static-proof commands (one-line)

```bash
# x0x repo
cargo nextest run --test api_manifest --test parity_cli \
                  --test api_coverage --test gui_smoke --test gui_named_group_parity

# communitas repo
cargo nextest run -p communitas-x0x-client --test parity_manifest \
                     --test client_coverage --test swift_parity
cargo test -p communitas-dioxus --bin communitas-dioxus
(cd communitas-apple && swift build && swift test)
```

All currently green. The GUI parity test additionally writes a
per-endpoint coverage report to
`tests/proof-reports/parity/gui-named-groups-coverage.txt` on every
run.

## Runtime proof — `tests/e2e_feature_parity.sh`

Spins up two daemons (alice + bob), drives every preset's lifecycle
through the `x0x` CLI, and verifies state via REST. **18 assertions
per run, 3× clean archived** at:

- `tests/proof-reports/parity/feature-parity-clean-run1.log`
- `tests/proof-reports/parity/feature-parity-clean-run2.log`
- `tests/proof-reports/parity/feature-parity-clean-run3.log`

### What each preset proves

| Preset | Proof |
|--------|-------|
| `private_secure` | create via CLI ✓ · REST reflects group ✓ · **hidden does not leak into `/groups/discover`** ✓ · state chain initialised ✓ |
| `public_request_secure` | create via CLI ✓ · card published / imported ✓ · **bob.request-access via CLI** ✓ · approve flow only asserted when alice actually observes the request via gossip — otherwise we explicitly log "skipped" rather than fake-passing on a synthetic id |
| `public_open` | create via CLI ✓ · **alice.send via CLI for SignedPublic** ✓ · `/messages` returns the signed body ✓ · **bob joins via invite link via CLI** ✓ |
| `public_announce` | create via CLI ✓ · **owner.send via CLI** ✓ · signed message observable in `/messages` ✓ · policy round-trip `write_access=admin_only` ✓ |

### Real authz checks (member-not-admin, against a group bob actually knows)

After bob joins the public_open group via an invite — so he has a
local view of the group_id rather than just being unknown to his
daemon — we test:

- non-admin `PATCH /groups/:bob_open_gid/policy` → **must return 403**
  (a 404 would mean "bob doesn't know the group", which would NOT
  prove authorization). The previous version of this test accepted
  404; that has been fixed.
- non-admin `POST /groups/:bob_open_gid/ban/:alice_aid` → **must
  return 403**.
- non-admin `GET /groups/:bob_open_gid/requests` → 403, or 200-empty
  if the daemon allows members to read an empty request list (logged
  explicitly so we don't quietly accept a privilege escalation).

### Honest scope notes

- The non-member send rejection check was removed from this test
  because on a 2-daemon loopback bob may simply not know the group at
  all (404), which doesn't prove the daemon's `MembersOnly` write
  enforcement. That guarantee is exercised by `e2e_named_groups.sh`'s
  3-daemon mesh.
- The public_request_secure approve flow is only asserted when
  cross-daemon gossip propagates within 60 s. Otherwise we **log a
  skip and do not increment the pass counter**. The CLI surface
  (`x0x group request-access`, `x0x group approve-request`) is
  separately proven by `parity_cli.rs`; cross-daemon convergence
  belongs to `e2e_named_groups.sh`.

## Deferred / known gaps (this is the complete list)

These are non-regressions, listed so a reader can see exactly what is
not yet proven on which surface. Each maps to either the GUI
`DEFERRED` entries above or a tracked follow-up.

1. ~~**SignedPublic send-path routing inside chat views**~~ —
   **Closed in Phase 7.** `sendSpaceChat` (GUI), `send_message`
   (Dioxus `channel_chat.rs`), and `ChannelManager.sendMessage`
   (SwiftUI) now branch on the group's `confidentiality` axis and
   route SignedPublic groups through `POST /groups/:id/send`. The
   `confidentiality` field is fetched once on mount via the
   per-client `groupInfo`/`get_group` call, which now exposes the
   full `policy` field on the `GroupInfo` shape.
2. **Public-message history read-back** in chat views
   (`GET /groups/:id/messages`). Sender-side path is closed; reading
   non-member-authored signed posts from the daemon's history cache
   is still queued.
3. **Headless GUI / UI drivers**. Playwright for the embedded HTML
   GUI, `dioxus-testing` for Dioxus, and XCUITest for SwiftUI remain
   queued. Phase 7's CI parity gates close the static-coverage
   feedback loop; UI-level e2e remains future work.
4. **GUI-side card inspection by id** (`GET /groups/cards/:id`) — the
   import action is now wired; per-id inspection still queued.
5. **GUI requester-side cancel-request UI**
   (`DELETE /groups/:id/requests/:request_id`) — admin approve/reject
   is wired; requester cancel is queued.
6. **Cross-daemon convergence of join requests** in this CLI runtime
   matrix — out of scope here (handled by `e2e_named_groups.sh`).
7. **Moderation tooling**, **backlog sync for late-joiners**, **MLS
   TreeKEM**, and **federation with external directory servers** —
   explicitly out of scope for v1 per the design doc.

## Signoff criteria

| Criterion | Status |
|-----------|--------|
| REST API has 36 named-groups endpoints, each covered by a handler, test, and registered cli_name | ✅ |
| CLI subcommand exists for every endpoint | ✅ |
| Rust client method exists for every endpoint | ✅ |
| Swift client method exists for every Rust method | ✅ |
| Embedded HTML GUI parity is **manifest-driven** (no hand-picked subset) | ✅ — `gui_named_group_parity.rs` enumerates every endpoint |
| GUI deferrals are **enumerated with reasons** | ✅ — 13 deferred, 0 unrecorded missing |
| Create modal surfaces all 4 presets | ✅ (x0x GUI + Dioxus + SwiftUI) |
| Discover view exists with query, nearby, request-access | ✅ (x0x GUI + Dioxus + SwiftUI) |
| Admin surfaces exist: policy editor, state readout, roster roles/bans, request approve/reject, rename | ✅ |
| Runtime parity test for CLI × 4 presets, with **real 403 authz checks** | ✅ (`e2e_feature_parity.sh`, 3× clean) |
| 404 from "group unknown locally" no longer counted as authz proof | ✅ (fixed in this revision) |
| Existing design proofs (C.2, D.3, D.4, E, F) remain green | ✅ |

## Phase 7 additions (2026-04-14)

1. **CI parity gate jobs** added to both repositories' `ci.yml`:
   - `x0x.parity` — runs `api_manifest`, `parity_cli`, `api_coverage`,
     `gui_smoke`, `gui_named_group_parity` and uploads the per-endpoint
     GUI coverage as a CI artifact. Builds only the `x0x` binary.
     Fails any PR that adds an endpoint without updating each surface.
   - `communitas.parity` — runs `parity_manifest`, `client_coverage`,
     `swift_parity`, plus a vendored-manifest schema sanity check.
3. **SignedPublic chat-view send routing** wired in all three
   surfaces (GUI, Dioxus, SwiftUI). See "Deferred / known gaps" #1
   above. To enable the routing, `GroupInfo` on both clients now
   exposes the full `policy` field from `GET /groups/:id`; the chat
   views read `policy.confidentiality` on mount.

## Changes from the previous revision (2026-04-14, before this audit)

This revision tightened two issues raised in review:

1. **GUI parity test was a hand-picked subset**, claiming 33/33
   coverage. **Now manifest-driven**; the test enumerates every
   `named-groups` endpoint and explicitly distinguishes WIRED vs
   DEFERRED vs MISSING. The coverage report is regenerated on each
   run. Three additional GUI flows were wired (Join, Card import,
   Rename); the chat-view send-path gap stays explicitly DEFERRED
   with a CROSS-SURFACE GAP marker.
2. **Runtime test accepted HTTP 404 as proof of authz rejection.**
   This was a false-green: 404 just meant "bob does not know this
   group locally". The test now invites bob into the public_open
   group via the CLI invite/join flow, then asserts **403** (not
   404) for non-admin actions. The synthetic-id approve probe was
   removed; the request/approve cross-daemon flow now explicitly
   logs "skipped" rather than fake-passing.

## Recommendation

**Approve named-groups feature parity for the surfaces enumerated in
the matrix above, with the explicitly listed deferrals.** The
cross-surface chat-view send-path gap is the only known remaining
parity gap of substance, tracked as Phase 7's primary target.

## Appendix — reproducing this report

```bash
cargo build --release --bin x0xd --bin x0x --bin x0x-user-keygen

# Static proofs (fast)
cargo nextest run --test gui_named_group_parity --test api_manifest \
                  --test parity_cli --test api_coverage --test gui_smoke

# Runtime proof (3 minutes per run; gossip-bounded)
for i in 1 2 3; do bash tests/e2e_feature_parity.sh; done
```

Logs land in `tests/proof-reports/parity/feature-parity-*.log`.
The GUI per-endpoint coverage lands in
`tests/proof-reports/parity/gui-named-groups-coverage.txt`.
