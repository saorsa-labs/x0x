# ADR 0046: Exec Runs Only Exact-Argv Allowlisted Commands, Fail-Closed, Audited

- **Status:** Proposed
- **Date:** 2026-08-29
- **Decision owners:** David Irvine (direction), omp (drafting)
- **Reviewers:** pending
- **Supersedes:** none
- **Superseded by:** none
- **Related:** ADR-0019 (cites exec as fail-closed precedent); `docs/exec.md`; `docs/design/x0x-exec.md`. Backfill record for shipped behavior.

## Context

The exec service lets remote agents run local commands under an ACL that
predates its recording: ADR-0019 cites it as precedent but no ADR decides
it. Matching is exact argv vector length — never prefix
(`src/exec/acl.rs:515`); literal tokens require exact equality
(`src/exec/acl.rs:529`); only constrained template tokens exist
(`Int`, `UrlPath`, `LiteralWithUrlPathSuffix`,
`src/exec/acl.rs:176-179`).

## Decision Drivers

- Remote code execution is the highest-risk surface; ambiguity is a
  vulnerability.
- The audit trail is the only forensic record; it must not be lossy.
- Missing or malformed configuration must disable, not broaden.

## Considered Options

1. Prefix/wildcard command matching.
2. Shell snippets with a parser-side filter.
3. Exact argv vectors with typed token templates, no shell (chosen).

## Decision

1. An allow entry binds an exact `(AgentId, MachineId)` pair and an exact
   argv vector; `AllowedCommand::matches` enforces same cardinality
   (`src/exec/acl.rs:515`); template tokens are only the constrained
   built-ins (`src/exec/acl.rs:176-179`).
2. Policy fails closed: `ExecPolicy::Disabled` denies with
   `ExecDisabled` (`src/exec/service.rs:817-832`); a missing default ACL
   disables exec (`docs/exec.md`, ACL location); the config uses
   `#[serde(deny_unknown_fields)]` (`src/exec/acl.rs:221,254,265`).
3. Gate order is pair membership, then argv, then stdin-size caps, before
   any child spawn (`src/exec/service.rs:946-963`); children are spawned
   without a shell (`Command::new(&argv[0]).args(&argv[1..])`,
   `src/exec/service.rs:1031-1032`).
4. Every request, denial, and exit is appended to a local JSONL audit log
   with fsync per entry (`src/exec/audit.rs:157-176`; `docs/exec.md`,
   Runtime behaviour). JSONL is authoritative; the CRDT TaskList audit
   mirror is an explicit v1.1 waiver, not implemented (`docs/design/x0x-exec.md` §10.2).

## Consequences

### Positive

- No shell-injection class; every mutation of trust is reconstructable
  from the audit log.

### Negative / Trade-offs

- Exact-argv entries are verbose for versioned binaries; operators must
  enumerate rather than pattern.

### Neutral / Operational

- `audit_log_path` is configurable with a default
  (`src/exec/acl.rs:245-299`), not caller-required as the older design text says.

## Validation

- ACL matcher and gate-order tests in `src/exec/`; denial-audit coverage
  per `src/exec/service.rs:1004-1008`; `x0x-exec --check` validation
  (ADR-0019 precedent).

## Notes for AI-assisted work

AI tools may draft this ADR but must not mark it Accepted without human
review. Accepted ADRs are immutable — supersede, don't edit.
