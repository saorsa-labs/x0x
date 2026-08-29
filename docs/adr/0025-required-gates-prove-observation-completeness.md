# ADR 0025: Required Gates Must Prove Observation Completeness

- **Status:** Accepted 2026-07-28 by the decision owner at commit `c35336a3f7044b03191b6ef270be9298d30a9373`, recorded as Buzz event `00c8063894d4070f87c5ed9ab19c337b248a043fb0a963d960b3279b2fe8cf4d`. Kimi's ruling was waived by the decision owner, not obtained.
- **Date:** 2026-07-28
- **Decision owners:** David Irvine
- **Reviewers:** Sam (author); Dario; Watson. Kimi did not review; his ruling was waived (see Status).
- **Supersedes:** none
- **Superseded by:** none
- **Mechanics:** Grounding G-001–G-006 are maintained in [`docs/design/required-gates-observation-completeness.md`](../design/required-gates-observation-completeness.md) (extracted 2026-08-29; ADR body unchanged)

## Summary

A required gate may pass only when it can account for everything it promises to test and prove that each required observation occurred. New tests run by default; only explicit, machine-checkable opt-outs may remove work from a context. One executable authority defines classification and reachability for local and CI execution. Detailed schemas, algorithms, pseudocode, and rollout mechanics belong in governed mutable reference material.

## Context

A green test command is not proof of coverage. A test may be undiscovered, excluded, ignored, selected but never reach its assertion, or converted into success by an unmet precondition. Audits of one mechanism cannot prove the absence of the others.

The architectural requirement is therefore about observation, not today's syntax: a required gate must account for the complete discovered set, the authority that selected or excluded each member, and whether each required observation actually completed.

For this decision, a test's **required observation** is the property for which the gate claims coverage. It is complete only when the test executes the checks that evaluate that property and produces a terminal pass or fail result.

## Decision Drivers

- Forgetting policy metadata must increase execution, not reduce it.
- Local and CI gates must derive from one execution authority.
- Selection alone is insufficient; required observation must be proven.
- Legitimate isolation, infrastructure, and scheduling needs must remain expressible without becoming defect quarantine. [G-001]
- Merge enforcement must be demonstrated, not inferred from a green command.

## Considered Options

A maintained allowlist is rejected because omissions silently remove coverage. Runner-specific ignore metadata, scheduling groups, and workflow filters are rejected as routing authorities because each describes only one container. We choose default execution as the mechanically computed complement of explicit non-default declarations, governed by one executable authority.

## Decision

1. **Default is the complement.** Every discovered test belongs either to ordinary required execution or to exactly one explicit non-default declaration. No ordinary-test allowlist exists. A missing or mistyped declaration makes the test run by default; overlapping declarations fail governance.

2. **One authority owns execution policy.** Required local and pull-request CI execution derive classification, reachability, and observation policy from the same executable source. Nothing outside that authority may change a required inventory or its execution policy, in whatever file or tool expresses it. No mode inside the authority may narrow, replace, or extend a required run's inventory, and no selection path for such a mode may accept a caller-supplied target. A required run is reachable from the authority; a command that merely exists in a file is not evidence that it executes.

3. **Passing requires positive, closed accounting.** Every required run accounts for each discovered test exactly once: required to execute, or declared out of scope before execution. A required selected test passes only when its required observation completes and produces a matching terminal result. Missing output, a start event, inventory equality, or a self-reported zero is not proof. An observation that cannot be read, parsed, or recognised is a failure of the gate, not an absence of evidence; an unrecognised value is never an extensibility point. Complete accounting never converts a semantic test failure into success.

4. **Non-observation cannot masquerade as coverage.** Non-observation, however it arises and in whatever file or tool expresses it, may not resolve to an ordinary pass. Runtime preconditions, regeneration paths, retry-only results, and other bypasses are examples rather than a closed taxonomy. Legitimate context differences are explicit, machine-checkable, owned, expiring where temporary, and reconciled against the discovered set. Neither flakiness nor a known defect is a ground for a non-default declaration.

5. **Enforcement is honest and staged.** The comprehensive status is not described as complete or made required while legacy bypasses remain. A CI job becomes a merge gate only after the exact status is protected, the protection is read back, and an intentionally failing pull request is refused merge.

## Consequences

New tests fail safe into execution, and selected-but-self-voiding tests can no longer masquerade as coverage. Local and CI behavior becomes comparable because both consume one authority. Isolation and external execution remain possible, but every exception becomes visible and accountable.

The migration is substantial: current bypasses must be classified or removed, and some green tests will become explicit failures. The observation adapter and audits become maintained infrastructure. Required gates may take longer because required work cannot be silently deferred.

## Validation

The decision is satisfied only when independent controls demonstrate all of the following.

Each control names one condition. Run unchanged, the control passes. With an independently applied change that violates that condition, the gate fails and attributes the failure to that condition. With a change that violates a different condition instead, the gate fails without that attribution. The three runs differ only in the applied change. A failure arising from any other cause does not satisfy the control.

- a newly discovered test with no declaration enters required execution;
- an overlap, unaccounted identity, unauthorized exclusion, selected test without its required observation, or semantic test failure makes the gate fail;
- a self-reported empty inventory or zero receipt cannot satisfy any control;
- required local and pull-request CI inventories derive from the same authority and reconcile with discovery;
- the comprehensive gate is withheld until the legacy-bypass complement is empty; and
- protection readback names the exact required status and an intentionally failing pull request cannot merge.

A new runner, workflow, retry layer, coverage tool, or success-producing bypass requires review of this decision.

## Grounding


### G-001 — Required isolation remains required execution

Resolves at: `e3013710d7ed69077de9a799dffdbeb5ac80535a`

Supports: Decision Drivers, the requirement that legitimate isolation remain expressible without becoming an opt-out.

Related repository surfaces: `justfile`, `.github/workflows/ci.yml`, `.github/workflows/integration.yml`, `.config/nextest.toml`, and `tests/**`.

External source: Buzz measurement event `b1dc8e11e419913f4cba0d86f49c8e638c4ce9296fb54bb65d1ad4ea1372fe6c`.

Observed result: a serial tailnet backpressure test passed four of five times under concurrent compile load and five of five times without that load; the sole loaded failure reached the substantive network body. The evidence supports required isolated scheduling, not exclusion from required execution.

### G-002 — Selection and runner authority were fragmented

Resolves at: `e3013710d7ed69077de9a799dffdbeb5ac80535a`

Supports: Context, Decision 1, and Decision 2.

Related repository surfaces: `justfile`, `.github/workflows/ci.yml`, `.github/workflows/integration.yml`, `.config/nextest.toml`, `tests/e2e_named_groups.sh`, and `tests/e2e_slow_consumer.sh`.

External sources: Buzz measurement events `091570762d7bcd8f5235c7691509aa92fff98cf6214e2139e2f62e2409513bca`, `4b3f2fcf52b4de8f2ab8754ba18d91311b878422ac03c116b0452eef041d30a0`, and `eb12ce28c0907cdaa4f0adb7acc74dba695b58d2b64b0589e7b4d688f587a792`.

Observed result: nextest reported 2,685 test cases across 30 binaries, including 245 ignored tests; 196 ignore attributes were bare and 49 carried a reason. Local tests, CI Test Suite, and Coverage had distinct inventories; Coverage excluded five non-ignored tests that an ignore census could not see. No CI workflow invoked `just`, two shell entry points were orphaned from tracked workflow and `justfile` reachability, and nextest scheduling policy also existed outside a common authority.

### G-003 — Selection did not prove observation

Resolves at: `e3013710d7ed69077de9a799dffdbeb5ac80535a`

Supports: Context, Decision 3, and Decision 4.

Related repository surfaces: `tests/**`, `src/exec/service.rs`, `justfile`, and `.config/nextest.toml`.

External sources: Buzz measurement events `58149e7b076b8e19aa531c794d28122aea896546bb7965edf916526f6f2e18f8`, `9d9402c3b234359ae2407607c497f550eff0f93c3ff6ad9c525b23fb9cc8ec42`, and `da7d7dfcae4c375948ea20b2e5ab74247ab948ff1528cb214f917ce38a2ee885`.

Observed result: a structural sweep found 33 live early-success sites across 27 non-ignored integration-test functions; 31 were runtime-precondition paths and two were regeneration paths. Source review found 22 dormant self-void sites inside ignored tests, 15 of them in `tailnet_streams_integration`, plus two further live unit-test self-void paths. Ten assertion-dominated success returns needed explicit divergence, and three separately defined build-or-skip helpers showed that silent success was a repeated convention rather than isolated accidents. Separate heuristic walks disagreed on nested-control-flow and assertion-dominance cases, which supports a syntax-aware shipping audit rather than carrying the census script forward as a gate. A measured nextest stream emitted start events for ignored tests without terminal results, so event absence could not distinguish a declared non-run from an interrupted observation.

### G-004 — Defects were stored in bypass containers

Resolves at: `e3013710d7ed69077de9a799dffdbeb5ac80535a`

Supports: Decision 4.

Related repository surfaces: `tests/crdt_convergence_concurrent.rs`, `.github/workflows/ci.yml`, and `justfile`.

External source: Buzz measurement event `eb12ce28c0907cdaa4f0adb7acc74dba695b58d2b64b0589e7b4d688f587a792`.

Observed result: deterministic CRDT convergence failures were labelled `Flaky`, while a historically retry-passing synthetic-kill test was excluded in CI but not in the local `justfile`. The same defect-quarantine hazard therefore existed in both test metadata and workflow selection.

### G-005 — Automatic CI was not demonstrated merge enforcement

Resolves at: `e3013710d7ed69077de9a799dffdbeb5ac80535a`

Supports: Decision 5.

Related repository surfaces: `.github/workflows/ci.yml`, `.github/workflows/build.yml`, and `.github/workflows/integration.yml`.

External sources: Buzz measurement events `091570762d7bcd8f5235c7691509aa92fff98cf6214e2139e2f62e2409513bca`, `d621fda1717661c14118ab6c50ea4aebbf21b86f226cd67e3c8a24968a7c6643`, and `f9975d6926bc8cc6200476921a64c2e90fe04ad8ed81e09f265a210452dcc5d2`.

Observed result: at measurement time, the GitHub branch-protection endpoint reported `main` unprotected and the repository ruleset list was empty, with administrator permission checked as a control. A separate 60-run sample contained substantive CI, Build, and Integration failures; Security Audit was green without always exercising the test suite, and Claude Code had 18 skipped conclusions. No substantive green status had therefore been verified as a protection anchor. Workflow execution reported status but had not been demonstrated capable of refusing a merge. This is an external-state observation preserved by the cited relay events, not a claim derived from the repository tree.

### G-006 — The available runner interfaces constrain the adapter

Resolves at: `e3013710d7ed69077de9a799dffdbeb5ac80535a`

Supports: Decisions 1 through 3.

Related repository surface: `.config/nextest.toml`.

External sources: Buzz measurement events `4b3f2fcf52b4de8f2ab8754ba18d91311b878422ac03c116b0452eef041d30a0` and `da7d7dfcae4c375948ea20b2e5ab74247ab948ff1528cb214f917ce38a2ee885`.

Observed result: cargo-nextest 0.9.126 could select binary and test filtersets and choose ignore-state behavior, but did not expose ignore-reason text or a `test_group(...)` filter predicate. Its experimental `libtest-json-plus` stream could supply per-test events, but its absence, malformation, and unknown values required a version-pinned, fail-closed adapter. The default profile could terminate slow tests after ten 60-second periods, making missing terminal output a live accounting case rather than a theoretical one.
