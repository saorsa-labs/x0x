# Named Groups Full Model — Implementation Proof Report

**Generated**: 2026-04-12
**Design doc**: `docs/design/named-groups-full-model.md` (Phase A + B + partial C)
**Blueprint**: `.planning/named-groups-blueprint.md`
**Suite log**: `tests/proof-reports/suite_named-groups_20260412-095129.log`

## Result

| Metric | Value |
|---|---|
| E2E assertions | **277 PASS / 0 FAIL / 0 SKIP** |
| Exit code | 0 |
| API coverage | **100.0% (100/100 routes)** |
| Rust unit tests (new modules) | 23/23 pass |
| `cargo fmt --check` | clean |
| `RUSTFLAGS="-D warnings" cargo clippy --all-targets --all-features -- -D warnings` | zero warnings |
| `cargo test --test api_coverage` | 8/8 pass |

## What was implemented

### New modules (Phase A + B + C-partial)

| File | Purpose |
|---|---|
| `src/groups/policy.rs` | `GroupPolicy`, `GroupDiscoverability`, `GroupAdmission`, `GroupConfidentiality`, `GroupReadAccess`, `GroupWriteAccess`, `GroupPolicyPreset` (`PrivateSecure`, `PublicRequestSecure`, `PublicOpen`, `PublicAnnounce`), `GroupPolicySummary` |
| `src/groups/member.rs` | `GroupRole` (Owner/Admin/Moderator/Member/Guest with rank ordering), `GroupMemberState` (Active/Pending/Removed/Banned), `GroupMember` |
| `src/groups/request.rs` | `JoinRequest`, `JoinRequestStatus` (Pending/Approved/Rejected/Cancelled) |
| `src/groups/directory.rs` | `GroupCard` (discoverable public-facing card) |
| `src/groups/mod.rs` | Evolved `GroupInfo`: v1 fields kept with `skip_serializing`, new `members_v2: BTreeMap<String, GroupMember>`, `policy`, `policy_revision`, `roster_revision`, `join_requests`, `discovery_card_topic`. Idempotent `migrate_from_v1()` invoked on load. |

### 13 new REST endpoints (all registered, routed, handled)

| Method | Path |
|---|---|
| `PATCH` | `/groups/:id` — update name/description (admin+) |
| `PATCH` | `/groups/:id/policy` — update policy (owner-only) |
| `PATCH` | `/groups/:id/members/:agent_id/role` — change role |
| `POST`  | `/groups/:id/ban/:agent_id` — ban member |
| `DELETE`| `/groups/:id/ban/:agent_id` — unban |
| `GET`   | `/groups/:id/requests` — list join requests (admin+) |
| `POST`  | `/groups/:id/requests` — submit join request |
| `POST`  | `/groups/:id/requests/:request_id/approve` |
| `POST`  | `/groups/:id/requests/:request_id/reject` |
| `DELETE`| `/groups/:id/requests/:request_id` — cancel own |
| `GET`   | `/groups/discover` — list discoverable groups |
| `GET`   | `/groups/cards/:id` — fetch group card |
| `POST`  | `/groups/cards/import` — import card (creates stub) |

`POST /groups` now accepts a `preset` field.

### 9 new gossip metadata event variants

`PolicyUpdated`, `MemberRoleUpdated`, `MemberBanned`, `MemberUnbanned`,
`JoinRequestCreated`, `JoinRequestApproved`, `JoinRequestRejected`,
`JoinRequestCancelled`, `GroupCardPublished`. Each has authorization check
(actor must equal sender and meet role threshold) and revision monotonicity.

### Authorization helpers

- `require_admin_or_above(info, caller)` → Err(403)
- `require_owner(info, caller)` → Err(403)
- Role-change authorization: Owner can set any non-Owner role; Admin can only
  act on Member/Guest targets.

### Stub-on-import

`POST /groups/cards/import` creates a minimal local `GroupInfo` stub
(Alice-as-Owner, no MLS group) so that non-members can submit join requests
against their local daemon. When `JoinRequestApproved` propagates back, the
requester is promoted to active Member.

## E2E proof sections (`tests/e2e_full_audit.sh`)

### `[9a]` Policy & Preset (5 assertions)
- Create group with explicit `preset: private_secure`
- Verify `policy.discoverability = hidden`, `admission = invite_only`, `confidentiality = mls_encrypted`
- Private group is NOT in Bob's discover list
- `PATCH /groups/:id` updates metadata

### `[9b]` `public_request_secure` full flow (13 assertions)
- Alice creates with `preset: public_request_secure`
- Verify `discoverability = public_directory`, `admission = request_access`
- Owner sees group in her own `/groups/discover`
- `GET /groups/cards/:id` fetches card
- Bob + Charlie import card via `POST /groups/cards/import` → local stubs created
- Bob sees group in discover after import
- Bob submits join request — `request_id` returned
- Alice sees pending request (polls up to 30s for gossip propagation)
- Alice approves → Bob becomes active member
- Charlie submits, Alice rejects → Charlie is NOT a member
- Charlie creates + cancels own request — `DELETE /groups/:id/requests/:id` succeeds

### `[9c]` Authorization negative paths (11 assertions)
- Non-member PATCH policy denied (404 — no local stub)
- After card import, non-member PATCH policy → 403 (stub exists, role check triggers)
- Member PATCH policy → 403 (owner-only)
- Alice adds Bob as Member
- Alice promotes Bob → Admin (role change works)
- Alice approves Charlie's request
- Alice bans Bob → Bob cannot submit new request (gossip-propagated ban enforced locally on Bob)
- Alice unbans Bob

### `[9d]` Ban/Unban + convergence (7 assertions)
- Ban → member state transitions to `banned` in local member list
- Unban → transitions back to `active`
- Delete-group convergence → Bob's view cleared via gossip

## Authorization matrix (enforced)

| Op | Guest | Member | Moderator | Admin | Owner |
|---|---|---|---|---|---|
| View if member | ✓ | ✓ | ✓ | ✓ | ✓ |
| Submit join request (non-member) | ✓ | — | — | — | — |
| Cancel own pending request | ✓ | ✓ | — | — | ✓ |
| Update name/description | — | — | — | ✓ | ✓ |
| Update policy | — | — | — | — | ✓ |
| Change role (target < caller) | — | — | — | ✓ | ✓ |
| Approve/reject join request | — | — | — | ✓ | ✓ |
| Ban member (non-owner) | — | — | — | ✓ | ✓ |
| Delete group | — | — | — | — | ✓ |

## Phase D / E deferred (explicit comments in code)

- **MLS rekey on role/ban changes**: every site has `// Phase D:` marker.
- **`POST /groups/:id/send`** (group chat send): not implemented.
- **Public-open moderation** (follower-only mode, ban-on-ingest): not implemented.
- **DHT-backed discovery index**: only local cache + gossip cards.

## Migration safety

- Legacy `members: BTreeSet<String>` + `display_names: HashMap` fields
  remain in the struct with `#[serde(default, skip_serializing)]`.
- `migrate_from_v1()` is idempotent and converts v1 rosters to v2 on load.
- First save after migration emits only the v2 fields.
- Rust test `test_migrate_from_v1` covers this path.

## Files changed

```
 src/api/mod.rs            |  104 ++++ (registry entries for 13 new endpoints)
 src/bin/x0xd.rs           |  ~900 ++ (11 new handlers + 9 event variants + helpers)
 src/groups/mod.rs         | +300/-100 (evolved GroupInfo + migration + tests)
 src/groups/policy.rs      |  new — ~200 lines
 src/groups/member.rs      |  new — ~200 lines
 src/groups/request.rs     |  new — ~100 lines
 src/groups/directory.rs   |  new — ~65 lines
 tests/api_coverage.rs     |   13 new COVERED entries
 tests/api-coverage.sh     |  1 regex improvement (multi-var URL extraction)
 tests/e2e_full_audit.sh   | +270 (sections 9a–9d with polling)
 tests/harness/src/cluster.rs | 1 clippy fix (pre-existing)
```
