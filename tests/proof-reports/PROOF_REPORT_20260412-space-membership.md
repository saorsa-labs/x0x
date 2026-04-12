# Space membership API + proof update (2026-04-12)

## What changed
Implemented a direct named-space membership surface and updated docs/tests.

### New REST endpoints
- `GET /groups/:id/members`
- `POST /groups/:id/members`
- `DELETE /groups/:id/members/:agent_id`

### New CLI commands
- `x0x group members <group_id>`
- `x0x group add-member <group_id> <agent_id> [--display-name ...]`
- `x0x group remove-member <group_id> <agent_id>`

## Important semantics
These endpoints currently expose and mutate the daemon's **local named-group + local MLS view**.
They are honest local membership APIs, but they are **not yet a full distributed ACL / remote revocation system**.

## Validation evidence

### 1. API registry / route coverage
- `cargo test --test api_coverage --quiet` ✅
- `bash tests/api-coverage.sh` ✅
  - `Routes in x0xd.rs: 87`
  - `Tested in ANY suite: 87`
  - `UNTESTED anywhere: 0`

### 2. Named-group integration suite
- `cargo test --test named_group_integration -- --ignored --nocapture` ✅
- Result: `19 passed / 0 failed`
- Includes new tests:
  - `named_group_members_endpoint`
  - `named_group_add_remove_member_local`

### 3. Strengthened local full E2E proof
From `/tmp/e2e_proof_local_full_membership.log`:
- `POST /groups/:id/members` ✅
- `GET /groups/:id/members` ✅
- `named-group members include bob` ✅
- `named-group members include bob display name` ✅
- `GET /groups/:id/members after remove` ✅
- `named-group members cleared bob` ✅

Note: that local-full run still had unrelated pre-existing flakes in SSE/direct/file/GUI sections; the new named-space membership checks passed.

### 4. Strengthened LAN E2E proof
From `/tmp/e2e_lan_membership_rerun.log`:
- `studio1 adds studio2 to named-space roster` ✅
- `studio1 named-space members` ✅
- `studio1 named-space members include studio2` ✅
- `studio1 named-space display name includes studio2-space-member` ✅
- `studio1 removes studio2 from named-space roster` ✅
- `studio1 named-space members after remove` ✅
- `studio1 named-space roster cleared studio2` ✅
- `studio2 leaves named group` ✅
- `studio2 space removed from group list after leave` ✅

The LAN suite still retains its separate zero-bootstrap mDNS discovery failures, unchanged from prior analysis.

## Docs updated
- `README.md`
- `docs/api-reference.md`
- `docs/api.md`
- `docs/primers/groups.md`

## Remaining limitation
The product still needs a future distributed membership / revocation design so that removing a member from a space also becomes authoritative across peers and enforced for space access.
