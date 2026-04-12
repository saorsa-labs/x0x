# Space membership authoritative propagation update (2026-04-12)

## What changed
Named spaces now have a stronger membership model than before:

### New / strengthened REST surface
- `GET /groups/:id/members`
- `POST /groups/:id/members`
- `DELETE /groups/:id/members/:agent_id`

### New CLI
- `x0x group members <group_id>`
- `x0x group add-member <group_id> <agent_id> [--display-name ...]`
- `x0x group remove-member <group_id> <agent_id>`

### New behavior
- creator-authored member add/remove is published on the group's metadata topic
- subscribed peers apply those updates locally
- creator delete propagates to subscribed peers
- removed peers drop the space locally
- member leave propagates as a removal event to other subscribed peers

## Important remaining limit
This is now **authoritative across subscribed peers for the local named-group state**, but it is still **not yet a complete distributed ACL / cryptographic revocation system** for all space access paths.

## Validation

### API route coverage
- `bash tests/api-coverage.sh`
- Result:
  - `Routes in x0xd.rs: 87`
  - `Tested in ANY suite: 87`
  - `UNTESTED anywhere: 0`
  - `Coverage: 100.0%`

### Named-group integration suite
- `cargo test --test named_group_integration -- --ignored --nocapture`
- Result: `21 passed / 0 failed`
- Includes distributed tests:
  - `named_group_creator_removal_propagates_to_removed_peer`
  - `named_group_creator_delete_propagates_to_peer`

### Local full proof
- `bash tests/e2e_proof.sh --local-full`
- Result: `227 PASS / 0 FAIL / 0 SKIP`
- Evidence file:
  - `tests/proof-reports/suite_local-full_20260412-080233-64688.log`
- Relevant space-membership proof lines include:
  - `POST /groups/:id/members`
  - `GET /groups/:id/members`
  - `named-group members include bob`
  - `DELETE /groups/:id/members/:agent_id`
  - `GET /groups/:id/members after remove`
  - `named-group members cleared bob`
  - `named-group removal propagated to bob`

### LAN proof
- Command:
  - `STUDIO1_HOST=studio1.local STUDIO2_HOST=studio2.local STUDIO1_SSH_TARGET=studio1@studio1.local STUDIO2_SSH_TARGET=studio2@studio2.local bash tests/e2e_lan.sh`
- Relevant passing lines from `/tmp/e2e_lan_authoritative.log`:
  - `studio1 adds studio2 to named-space roster`
  - `studio1 named-space members include studio2`
  - `studio1 removes studio2 from named-space roster`
  - `studio2 authoritative removal propagated`
  - `studio2 space removed from group list after authoritative remove`
- Remaining LAN failures are still the independent mDNS/seedless discovery problem.

## Docs updated
- `README.md`
- `docs/api-reference.md`
- `docs/api.md`
- `docs/primers/groups.md`

## Summary
This closes the biggest honesty gap in named-space membership:
- before: member add/remove was only local bookkeeping
- now: creator-authored membership and deletion changes converge across subscribed peers and are covered in integration + E2E proof
