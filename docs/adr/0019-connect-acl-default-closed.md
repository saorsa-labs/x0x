# ADR 0019: Connect ACL — default-closed connectivity policy

<!-- File name: docs/adr/0019-connect-acl-default-closed.md -->

- **Status:** Proposed
- **Date:** 2026-07-04
- **Decision owners:** David Irvine
- **Reviewers:** x0x core team
- **Supersedes:** none
- **Superseded by:** none
- **Related:** issue #131, PR #167 (PR1 — policy engine), PR2 (wiring + proptest + docs), issue #132 (T4 forwarder — runtime enforcement), ADR-0017 (x0x as agent transport layer)

## Context

x0x v1 exposes no TCP/UNIX forwarding surface at all — there is no connect forwarder yet. Issue #132 (Tailnet T4) will add one. Before that forwarder ships, we need a **fail-closed policy engine** that:

1. Is fully specified, implemented, and formally tested **before** any runtime enforcement is wired.
2. Provides the security invariants the T4 forwarder can simply call into, rather than inventing them under time pressure.
3. Does not silently grant access if the ACL file is absent, malformed, or missing a field.

The exec ACL (`src/exec/acl.rs`) already set the precedent: fail-closed load semantics, exact-triple allowlists, `--check` startup validation. The connect ACL mirrors that design.

## Decision Drivers

- **Fail-closed by default.** No connect ACL configured → all connections denied. An embedder that builds `ServeOptions` without a connect policy gets `ConnectPolicy::Disabled` (deny) for free.
- **Loopback-only targets in v1.** The only safe initial scope. LAN/subnet targets introduce firewall bypass risk; port ranges introduce matcher complexity; hostnames introduce DNS rebinding risk. All three are deferred.
- **Numeric IP only.** `localhost` is rejected at load time: name resolution is ambiguous (`localhost` may resolve to `::1`, `127.0.0.1`, or — via `/etc/hosts` tampering — a non-loopback address). Removing the resolver from the TCB eliminates a whole class of rebinding attacks.
- **Exact `host:port` only.** Matches exec's exact-argv philosophy. Port ranges and CIDR add matcher/overlap/fencepost ambiguity in the security-critical path with zero v1 need; a dozen ports is a dozen TOML lines; extension is backward-compatible later.
- **`deny_unknown_fields` on ACL structs.** A misspelled key (`taregts`, `enable`) must fail loudly, not silently yield a different (more permissive) policy. This is a deliberate divergence from exec (which does not yet have `deny_unknown_fields`); a follow-up issue (#TBD) will give exec the same treatment.
- **Startup validation.** A malformed or non-loopback ACL must block daemon startup and fail `x0xd --check` — never silently disable at runtime.

## Considered Options

1. **Mirror exec ACL exactly — loopback-only, exact targets, fail-closed load** ← chosen.
2. **Allow LAN/subnet targets from day one.** Rejected: firewall bypass risk, more complex matcher, no v1 need.
3. **Accept `localhost` hostname.** Rejected: DNS rebinding; numeric-only removes the resolver from the TCB entirely.
4. **Port ranges (`127.0.0.1:8000-8100`).** Rejected: fencepost/overlap ambiguity, no v1 need, breaks backward-compatibility if the syntax changes later.
5. **Single unified ACL file with exec.** Considered but deferred: the exec and connect grant surfaces are orthogonal; merging would complicate the `deny_unknown_fields` enforcement and the separate `--exec-acl` / `--connect-acl` override flags. Left for a future config unification ADR.

## Decision

We will implement a **fail-closed connect ACL** (`src/connect/`) that:

- Mirrors `src/exec/acl.rs` structure and load semantics byte-for-byte.
- Validates all targets as **numeric loopback IP:port literals** at load time (hard error otherwise).
- Uses **exact `(agent_id, machine_id, SocketAddr)` matching** — no wildcards, no ranges, no CIDR.
- Applies `#[serde(deny_unknown_fields)]` to the `[connect]` section and allow entries.
- Ships fully tested (unit matrices A–C, integration D, proptest E) **before** the T4 forwarder is wired.
- Exposes `/diagnostics/connect` (allow/deny counters + ACL summary) so operators can observe the policy surface.
- Is loaded by `x0xd` before the `--check`/`--doctor` branches, so a malformed or missing-at-explicit-path file blocks startup.

The T4 forwarder (issue #132) will call `evaluate_connect_gate` at its accept seam. This ADR covers the policy engine only — no stream code changes in v1.

## Consequences

### Positive

- **Security invariant formally proven.** Four proptest properties (never-panic, IPv4 soundness, IPv6 soundness, matcher no-false-accepts) provide machine-checked evidence of the loopback-only invariant.
- **Default-deny for embedders.** `ServeOptions::connect_policy` defaults to `ConnectPolicy::Disabled`; no host effort required to stay safe.
- **Load-time validation.** Non-loopback targets, malformed TOML, and missing-at-explicit-path all block startup rather than silently disabling at runtime.
- **Diagnostic surface ready.** `/diagnostics/connect` is wired from day one, so when T4 ships the counters are already queryable.

### Negative / Trade-offs

- **No hostname support.** Operators must write `127.0.0.1:22` not `localhost:22`. Actionable error messages mitigate this.
- **No port ranges.** Operators with many ports need multiple TOML entries. This is intentional — see Decision Drivers.
- **`deny_unknown_fields` divergence from exec.** A misspelled exec ACL key silently disables exec (the safer side of fail-closed); a misspelled connect ACL key hard-errors. The exec follow-up (separate issue) will align them.

### Neutral / Operational

- Default ACL path: `/usr/local/etc/x0x/connect-acl.toml` (macOS), `/etc/x0x/connect-acl.toml` (Linux).
- Missing at default path → `ConnectPolicy::Disabled` (daemon starts, connect disabled).
- Missing at explicit `--connect-acl` path → hard error (daemon exits).
- `x0xd --check` prints both Exec ACL summary and Connect ACL summary.

## Validation

- **Unit tests (matrix A–C):** load/parse matrix (enabled, disabled, malformed, missing), target validation matrix (loopback accept/reject, port 0, hostname, v4-mapped, leading zeros), gate-order matrix.
- **Integration tests (matrix D):** `tests/connect_acl_unit.rs` — TOML string round-trips through `parse_connect_policy`.
- **Property tests (matrix E):** `tests/connect_acl_proptest.rs` — four proptest properties, machine-checked.
- **`--check` end-to-end:** `x0xd --check --connect-acl <valid>` exits 0 and prints summary; `x0xd --check --connect-acl <malformed>` and `<non-loopback>` exit non-zero.
- **API coverage test:** `tests/api_coverage.rs` requires `/diagnostics/connect` in ENDPOINTS and `daemon_api_diagnostics_connect` as a coverage marker.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human review**. Accepted ADRs are immutable: create a new superseding ADR rather than editing an Accepted ADR.

The security invariant here — loopback-only, numeric-IP-only, exact-triple matching, fail-closed — must not be softened without a new ADR. Any PR that relaxes these constraints (e.g. adding hostname support, port ranges, or LAN targets) requires explicit ADR amendment and adversarial security review.
