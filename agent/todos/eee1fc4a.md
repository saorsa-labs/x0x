{
  "id": "eee1fc4a",
  "title": "Phase 2: Markdown documentation audit — DONE (findings below)",
  "tags": [
    ">doc-audit",
    "phase-2"
  ],
  "status": "completed",
  "created_at": "2026-05-11T21:04:54.546Z"
}

## Findings

### Stale version numbers
1. **README.md line 680**: `x0x = "0.16"` → should be `"0.19"` or at least not a specific outdated version (the crate version is 0.19.41)
2. **SKILL.md line 4**: `version: 0.19.32` → should be `0.19.41`
3. **CHANGELOG.md**: Only goes to v0.19.31 (dated 2026-05-07), current version is 0.19.41

### Outdated CLAUDE.md claims
4. **CLAUDE.md line 11**: "No justfile exists yet" → justfile DOES exist with standard recipes
5. **CLAUDE.md line 363**: Phase C.2 shard subscriptions "designed not yet implemented" → endpoints exist in code (implemented)

### Incorrect route count
6. **README.md**: Claims "128 REST endpoints" — actual count is 130 endpoint definitions (with ~114 unique paths, some paths serve multiple HTTP methods)
7. **CLAUDE.md line 359**: Also claims "128 REST endpoints"
8. **src/bin/x0x.rs line 1685**: CLI help says "Print all 70 REST API routes" — wrong, should be ~130

### Missing modules in CLAUDE.md architecture diagram
9. **CLAUDE.md lines 85-102**: Module dependency flow diagram omits: `dm.rs`, `dm_capability.rs`, `dm_capability_service.rs`, `dm_inbox.rs`, `dm_send.rs`, `connectivity.rs`, `contacts.rs`, `trust.rs`, `exec/`, `files/`, `hedge.rs`, `constitution.rs`

### Minor documentation gaps
10. **docs/api-reference.md**: Does not document `/health`, `/introduction`, `/ws`, `/ws/direct`, `/ws/sessions` endpoints (but documents most others)
11. **docs/api.md**: Does not document `routes`, `ws`, `ws direct`, `diagnostics ack` CLI commands

### No broken relative links found
All relative markdown links resolve correctly. The only "broken" results were anchor links and directory references which are valid Markdown constructs.
