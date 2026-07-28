# ADR 0025: Required Gates Must Prove Observation Completeness

- **Status:** Proposed — pre-consensus (Kimi ruling outstanding)
- **Date:** 2026-07-28
- **Decision owners:** David Irvine
- **Reviewers:** Dario (amended-draft review pending); Kimi (required ruling outstanding); Watson (evidence verification)
- **Supersedes:** none
- **Superseded by:** none
- **Related:** `justfile`, `.github/workflows/ci.yml`,
  `.github/workflows/integration.yml`, `.config/nextest.toml`, `tests/**`;
  Buzz measurement event
  `b1dc8e11e419913f4cba0d86f49c8e638c4ce9296fb54bb65d1ad4ea1372fe6c`

> **Pre-consensus draft:** David has selected default-run with a declared,
> machine-checkable opt-out. The remaining design records the current Sam and
> Dario position plus Watson's verified corrections. Kimi's ruling on the
> remaining clauses is outstanding. This ADR must not be presented as
> consensus, marked Accepted, or implemented before that review and David's
> explicit approval.

## Context

x0x's test commands can report success without observing all of the properties
the repository treats as covered. The investigation began with `#[ignore]`,
but the failure is not specific to an attribute. At commit
`e3013710d7ed69077de9a799dffdbeb5ac80535a`, at least three mechanisms have
the same effect:

1. `#[ignore]` keeps a discovered test out of the ordinary test run.
2. A hand-written nextest exclusion keeps a non-ignored test out of one CI
   context.
3. A runtime precondition returns success before the test reaches its
   assertions, so the harness records `PASS` rather than an unmet
   precondition.

These mechanisms defeat different audits. Counting ignored tests cannot find
workflow exclusions. Comparing selected inventories cannot find a selected
test that returns success before observing its property. Naming each current
mechanism would leave the policy open to the next container.

The governing problem is therefore property-level:

> A required gate may report success only if it can account for every
> discovered test, the tier and required context that selected it, whether it
> executed its promised observation, and every declared reason it did not.

The measured repository state illustrates the gap:

- nextest discovers 2,685 test cases across 30 binaries, including 245 ignored
  tests; 196 ignores are bare and 49 carry a reason;
- `just test`, CI Test Suite, and CI Coverage have three different effective
  inventories;
- CI Test Suite excludes
  `binary(x0x_0041_synthetic_kill_restart)`;
- CI Coverage additionally excludes
  `binary(x0x_0041_prefer_newest_test)` and
  `binary(named_group_join_metadata_event)`;
- those workflow filters remove five non-ignored tests from Coverage, so the
  245-test ignore census cannot see the divergence;
- local `just` recipes, CI workflows, and two orphaned shell scripts select
  ignored tests with separately maintained commands; the orphaned shell
  runner graph also reaches `tests/runners/x0x_test_runner.py`, which has its
  own retry accounting and is not invoked directly by a tracked workflow or
  `justfile` recipe;
- no CI workflow invokes `just`, so local and CI gates share no dispatcher;
- `.config/nextest.toml` separately owns three
  `profile.default.overrides` filtersets that assign the serialized
  `quic-localhost` test group; these change scheduling rather than selection,
  but they are already a hand-maintained tier definition outside any
  registry;
- a structural evidence sweep over `tests/**` found 33 early-success sites
  across 27 non-ignored test functions; an independent reproduction found 29
  candidate dormant sites, then source review reclassified seven as
  fail-closed and left 22 genuine dormant self-void sites across 12 ignored
  test functions;
- two of the 33 live sites are regeneration escape hatches; the other 31 are
  runtime-precondition paths across 25 test functions;
- a follow-up over unit-test modules found two further live self-void paths in
  `src/exec/service.rs`, including an issue-118 regression guard, plus three
  already-fail-closed success returns that the syntactic rule below will make
  explicit;
- three separately defined `build_or_skip_network_bind_error`-style helpers
  institutionalize the silent-success convention; and
- 15 of the 22 genuine dormant self-void sites are in
  `tailnet_streams_integration`, so enabling ignored cohorts before
  observation accounting exists could manufacture a green migration result.

The structural sweeps are evidence, not the proposed implementation. A
brace-depth walk misclassified returns from nested async blocks and closures;
a lookback heuristic misclassified assertion-dominated returns. The shipping
audit must be syntax-aware, cover integration tests and unit-test modules, and
enforce a syntactic test-exit rule that does not depend on heuristic data-flow
classification or log messages.

Tool constraints also shape the decision. cargo-nextest 0.9.126 can select
`binary(...)` and `test(...)` filtersets and can choose ignore-state behavior
with `--run-ignored default|only|all`. It cannot select the reason string in
`#[ignore = "..."]`. Its test groups control scheduling, and this version has
no `test_group(...)` filterset predicate.

Its experimental `libtest-json-plus` stream also does not emit a per-test
ignored or skipped outcome. In a measured default run over a binary with seven
ignored tests and one active test, all eight identities emitted `started`,
only the active test emitted a terminal `ok`, and nextest reported the other
seven only in its aggregate skipped count. Absence of a terminal event
therefore cannot mean "declared not run": the same shape would also occur if a
selected test stopped before producing a result. This matters because the
repository's default nextest profile can terminate slow tests after ten
60-second periods.

Finally, a green command is not a merge gate by itself. `main` currently has
no verified substantive green baseline context suitable for protection and no
verified rule requiring the comprehensive test status. Recent substantive
workflows include failures; Security Audit's scheduled green runs do not
exercise the test suite, and Claude Code has produced skipped rather than
pass/fail conclusions. Selecting whichever context looks green would create
another proxy.

## Decision Drivers

- New tests must run by default. A missing or mistyped opt-out must increase
  execution rather than silently reduce it.
- Required local and CI contexts must be derived from one execution
  definition rather than independently maintained command lines.
- A gate must account for both selection and actual observation; inventory
  equality alone is insufficient.
- Runtime preconditions must be observable and machine-reconciled.
- Isolation, external infrastructure, and soak budgets are legitimate
  scheduling concerns, but `flaky` and `known-defect` are not opt-out tiers.
- The design must be enforceable with the nextest capabilities actually
  present in the repository.
- Branch protection must be proven with both configuration readback and a
  merge-blocking negative control.
- Migration must not grandfather the mechanisms that created the current
  blind spots.

## Considered Options

1. **Curated allowlist of tests that must run.**
2. **Use `#[ignore]` and its reason string as the routing authority.**
3. **Use nextest test-group membership as the routing authority.**
4. **Run by default; declare only non-default tiers in a source-carried
   namespace, with one executable registry and observation accounting.**

Option 1 is rejected because completeness would depend on continuously adding
new tests to a second list. A forgotten entry removes coverage.

Option 2 is rejected because nextest exposes only the ignored bit, not the
reason string, and one bit cannot route required-isolated, external, and soak
work independently.

Option 3 is rejected because test groups are scheduling configuration, not an
opt-out property, and nextest 0.9.126 cannot select a test group in a
filterset.

Option 4 is selected. It makes ordinary execution the fail-safe complement of
explicit non-default selectors and makes the registry the executable source
of routing, reachability, and observation policy.

## Decision

### 1. Scope the policy to observation, not to current bypass mechanisms

The policy governs anything that allows a declared gate to report success
without observing a property it promises to observe. `#[ignore]`, workflow
filtersets, runtime early-success returns, retry-only success, and
environment-controlled regeneration paths are known instances, not a closed
taxonomy.

Governance must test the invariant, not merely search for those tokens.

### 2. Default is the complement

Every discovered test is classified mechanically:

- if it matches no non-default selector, it is in `default`;
- if it matches exactly one non-default selector, it is in that tier;
- if it matches more than one non-default selector, governance fails.

Ordinary tests do not carry a `default_*` name and the registry does not
enumerate them. Requiring that would recreate the rejected allowlist across
the ordinary suite.

Only non-default tiers carry a source-level, machine-selectable namespace:

- use an integration-target name when the whole binary has one non-default
  policy;
- use a module or test-name namespace when one binary contains multiple
  policies.

The non-default selectors must be pairwise disjoint. A missing or mistyped
non-default namespace falls into `default` and runs.

Where cargo's ordinary runner must also skip a non-default case,
`#[ignore = "..."]` remains structured human-readable metadata. It is not the
routing authority. In the enforced steady state, the primary dispatcher uses
`--run-ignored all`, so an unclassified ignore does not disappear from the
default inventory. The advisory migration stage in Decision 11 deliberately
retains `--run-ignored default` until the dormant self-void paths are migrated
and the ignored cohort is ready to activate.

The initial tiers are:

| Tier | Required execution |
|---|---|
| `default` | `just check` and pull-request CI |
| `required-isolated` | `just check` and pull-request CI, after compilation with declared isolation/concurrency |
| `external` | only in the context that supplies its declared infrastructure |
| `soak` | on its declared schedule and budget |
| `governance-fixture` | only in the registry-declared `fixture` context; never in a functional required inventory |

There is no `flaky` or `known-defect` tier.

`governance-fixture` is a non-functional control tier, not a product-test
opt-out. It contains only the exact governance fixtures that certify the
dispatcher itself and is unreachable through ordinary or required-tier
selectors.

A compile-contention measurement for
`tailnet_streams_integration::backpressure_throttles_writer_with_bounded_buffering`
produced four passes and one `bob accepted` failure while clean workspace
builds were active, versus five passes in five unloaded controls. All ten test
invocations were compile-free, and the loaded tests began and ended while
their competing builds remained active. This sample supports
`required-isolated` placement without claiming statistical proof of
causation. That tier remains required locally and in pull-request CI.

### 3. One executable registry owns routing and reachability

The registry enumerates tier definitions, not individual default tests. Its
context schema contains `local`, `pull-request`, `external`, `scheduled`, and
`fixture`. Each functional tier definition owns:

- its positive `binary(...)` / `test(...)` selector;
- every permitted context-specific exclusion;
- the non-fixture execution contexts in which it runs;
- scheduling, isolation, concurrency, timeout, termination, and retry policy;
- infrastructure preconditions;
- failure policy;
- owner; and
- reason and expiry for any declared context-specific divergence.

The non-functional `governance-fixture` definition instead owns the exact
fixture identities and the `fixture` context. That context has one entry point
and is the only context permitted to select those identities.

A single dispatcher consumes the registry. Any policy that affects selection,
scheduling, isolation, concurrency, timeout, termination, or retry behavior
for a required tier must be derived from the registry, irrespective of the
tool or file in which that policy is expressed. A workflow, nextest profile,
script, `justfile` recipe, or successor container may consume generated policy
but may not become an independent authority.

Hand-written tier-specific nextest commands, inline workflow exclusions, and
separately maintained test lists are known violations of that property, not a
closed taxonomy. The three existing `quic-localhost` scheduling overrides and
the default profile's slow-test termination policy are migration inputs. Their
selectors and execution policy must move under the registry, and any generated
nextest configuration must be derived from it rather than maintained as a
second source.

`run-required` iterates the registry definitions for `default` and
`required-isolated`; `just check` invokes `run-required`. CI derives its
required and scheduled matrices from the same registry and invokes the same
dispatcher.

The dispatcher exposes exactly one registry-declared governance-fixture target
mode as the sole entry point for the `fixture` context. It accepts only a
closed registry fixture key, never a caller-supplied selector or arbitrary
target, and resolves that key only to exact identities in the
`governance-fixture` tier. It executes the same runner adapter, outcome mapping,
reconciliation, and semantic-failure propagation path as a required run. A
governance audit may invoke that mode as a separate self-test, but the mode
cannot supply, replace, narrow, or extend the inventory of any required local
or CI context.

The invariant is one execution definition per tier, reachable in every
context that definition declares. It is not "exactly one process" or "exactly
one call site": local and CI contexts may invoke the same definition.

Reachability is proven from the dispatcher graph. A command that merely
appears in an otherwise orphaned shell script does not prove execution.

Required dispatchers must propagate semantic failure to a failing status.
Governance follows the result rather than rejecting token shapes: for example,
`|| true` may preserve captured output only when a later fail-closed check
turns the captured failure into a failing status.

### 4. Reconcile selection and one positive outcome per discovered identity

The registry-derived required inventory is the union of `default` and
`required-isolated`. Each required local and CI context emits its effective
selected inventory before execution and reconciles it against that required
inventory. Selection is derived from registry selectors before the runner's
ignore-state disposition is applied. During the advisory migration, an
ignored identity in the default complement therefore remains selected even
though it receives a declared not-executed outcome.

In governance-fixture target mode, the exact identities declared by the
`governance-fixture` tier are that run's required inventory. The same
selection and outcome reconciliation applies. Its inventory reconciliation
must succeed before the audit may attribute a non-zero exit to the behavior a
fixture is intended to certify.

Each required context and governance-fixture run also emits exactly one
positive outcome for every identity in its discovery scope from this closed
set:

- `executed-and-passed`: the identity was selected and emitted a passing
  per-test terminal event;
- `executed-and-failed`: the identity was selected and emitted a failing
  per-test terminal event;
- `declared-not-selected`: the registry declares that identity's tier out of
  scope for this context; or
- `declared-not-executed-with-reason`: the dispatcher or declared skip helper
  positively records why an otherwise selected identity did not execute its
  promised observation.

Each label is valid only when every predicate in its definition holds. The
reconciler therefore rejects an executed outcome for an unselected identity;
an executed outcome whose pass/fail polarity lacks the matching terminal
event; a `declared-not-selected` outcome for a selected identity or without a
pre-run registry declaration; and a
`declared-not-executed-with-reason` outcome for an unselected identity, without
one of the permitted positive sources, or alongside a terminal event. An
unknown outcome label is not an extensibility point and fails closed.

Accounting an `executed-and-failed` outcome does not convert semantic failure
into success; the dispatcher still returns a failing status.

A `started` event is evidence only that an identity appeared in the stream,
not that it executed: ignored tests emit `started` without running.
`declared-not-selected` must come from the registry before execution.
`declared-not-executed-with-reason` may come only from a dispatcher
declaration made before execution or from the machine-readable skip helper; it
is never inferred from a missing runner event.

During rollout steps 3 and 4, the sole temporary authority for declaring an
ignored default-complement identity not executed is the dispatcher's pre-run
discovery of runner ignore state, reconciled with the runner's aggregate
not-run count. It is not a per-test registry entry or allowlist. After step 5
removes that migration state, the registry's context and tier policy is the
only authority for a pre-run not-selected declaration.

The dispatcher reconciles the outcome table one-to-one against nextest
discovery, the effective selected inventory, the closed outcome definitions,
and the runner's own run/pass/fail/not-run totals. An identity with zero or
multiple outcomes fails the run. A selected identity with no terminal event
and no positive declared-not-executed record fails the run. A selected identity
carrying `declared-not-selected` fails the run. An executed outcome or reported
terminal result outside the selected inventory fails the run. A terminal event
for an identity declared not executed also fails the run. Selected-set equality
is necessary but insufficient.

The initial dispatcher may obtain executed outcomes from cargo-nextest 0.9.126
with `NEXTEST_EXPERIMENTAL_LIBTEST_JSON=1` and
`--message-format libtest-json-plus`. Because that interface is experimental,
the registry version-pins the recognized raw event-to-outcome mapping, and the
dispatcher owns the environment flag and parser. Unknown events or an
unavailable or malformed stream fail closed. The dispatcher reconciles
explicit not-run declarations with nextest's aggregate skipped/not-run count;
it does not translate raw event absence into an outcome.

Outcome reconciliation has a governance mutation manifest derived from the
union of the rejection rules above and every predicate in the closed outcome
definitions. The registry declares one case per atomic mutation in the
non-functional `governance-fixture` tier:

- zero outcomes and multiple outcomes for one identity are separate cases;
- an `executed-and-passed` or `executed-and-failed` outcome for an unselected
  identity, without its matching terminal event, or with the opposite terminal
  polarity is mutated separately;
- `declared-not-selected` on a selected identity and without its pre-run
  registry declaration, and alongside a terminal event are separate cases;
- `declared-not-executed-with-reason` on an unselected identity, without a
  permitted positive source, and alongside a terminal event are separate
  cases;
- an unknown outcome label is a separate fail-closed parser case; and
- an otherwise valid outcome table disagreeing with the runner's aggregate
  run/pass/fail/not-run totals is a separate case.

Each fixture mutates exactly one predicate from an otherwise valid state. When
that state also satisfies an umbrella rejection sentence above, the mutation
manifest names the canonical diagnostic and no other diagnostic may satisfy
the control. The audit passes only when selected-inventory reconciliation
succeeds, the dispatcher reports that named outcome-reconciliation failure,
attributes its non-zero status to that failure, and exits non-zero. A
skip-helper record, semantic test failure, unrelated inventory failure, another
reconciliation condition, or a self-reported zero receipt cannot satisfy a
control.

Governance checks the mutation manifest and the outcome-accounting rows in the
Decision 10 receipt in both directions: every atomic invalid state has a
specific diagnostic and receipt row, and every such receipt row is justified
by at least one independently reddening mutation case. The steady-state
readiness row that requires zero valid
`declared-not-executed-with-reason` outcomes is identified separately and is
not misrepresented as an invalid-state mutation.

A context-specific difference may exist only when the registry declares it
with a reason, owner, and expiry. It cannot be expressed as an inline
workflow filter. A known product or dependency defect is not a permitted
reason.

The same accounting applies to external and soak tiers: a tier that is not
scheduled in a context is accounted for by its registry execution policy,
not by running a test that returns success without infrastructure.

### 5. A selected test must account for whether it observed its property

An unmet runtime precondition may not resolve to an ordinary passing test.
The default behavior is to fail with the unmet precondition.

Where Rust's test harness cannot express a native skip result, test code may
use one declared skip-exit helper that emits a machine-readable skip record
keyed to the discovered test identity and exits the test. The helper must be
the exit operation itself: one macro or equivalent syntax-level construct
performs both actions, and its call site contains no separate success return.
`record_skip("reason"); return Ok(())` is forbidden because recognizing it
would require the audit to infer statement domination.

The one allowed helper is pinned to an exact definition rather than accepted
by a name pattern. Governance verifies that definition emits the
machine-readable record. The registry declares its positive-control fixture in
the non-functional `governance-fixture` tier, outside the workspace's ordinary
discovered test inventory. The audit invokes it through the dispatcher's
closed fixture mode as a subprocess and passes only when all of these hold:
the helper record maps the fixture identity to
`declared-not-executed-with-reason`; inventory and outcome reconciliation
otherwise succeed; the dispatcher attributes its failure to the non-zero
skip-helper record count; and the dispatcher exits non-zero. An inventory or
reconciliation failure cannot satisfy the control. The fixture is not an
ordinary test and is not placed in a functional tier, because either placement
would make the required inventory permanently red or certify the wrong
execution context.

The helper is diagnostic accounting, not an observation or a bypass. Its
record maps to `declared-not-executed-with-reason`, never to
`executed-and-passed`:

- a required dispatcher fails if its skip-helper record count is non-zero;
  that count includes only machine-readable records emitted by the pinned
  helper, never dispatcher pre-run declarations;
- a scheduled external or soak context fails if its promised infrastructure
  is absent; and
- a tier not scheduled in a context is accounted for by the registry, not by
  a passing test.

Within a test function's own control-flow scope, every precondition-failure or
destructuring-failure arm must either diverge through an assertion, `panic!`,
or `unreachable!`, or exit through the declared skip-exit helper. Direct
success returns such as `return;`, `return Ok(())`, and
`let ... else { return Ok(()) }` are forbidden. An assertion-dominated
destructuring arm must use explicit divergence rather than retain an
unreachable success return.

The audit must be syntax-aware and cover integration-test functions and unit
test modules. It distinguishes a return from the test function from a return
inside a nested closure or async block, and recognizes only the single
skip-exit construct as an allowed success-exit mechanism. It does not try to
infer whether an assertion or a preceding skip-record call dominates a
success return, and it does not grep for `return`, `Ok(())`, or a "skipping"
message. The current brace-depth censuses may seed the implementation and
migration, but are not the normative audit.

### 6. Regeneration and validation are separate entry points

An environment variable may not turn a required validation test into a green
regeneration no-op. Artifact generation moves to an explicit non-test command
such as an `xtask` or equivalent dispatcher action. Required tests always
validate the committed artifact.

Until those paths are separated, the required dispatcher rejects the
regeneration environment variables and the structural audit continues to
report the early-success paths.

### 7. Known defects cannot be stored in an observation bypass

No ignore, exclusion, early-success precondition, retry-only success, or
successor mechanism may store a deterministic product or dependency defect.

The two CRDT convergence cases must be triaged against intended conflict
semantics:

- if the expectation is correct, fix the product or dependency and run the
  regression normally;
- if the current behavior is intended, convert the test to a passing
  characterization and track any desired semantic change separately; or
- if intent is unresolved, remove the disputed test from the executable suite
  rather than ignoring or tiering it, preserve the reproducer and competing
  expectations in an issue with an owner and expiry, and do not claim the
  property as covered until the decision produces either a normal regression
  or an honest characterization test.

`Flaky` requires measured pass/fail evidence. Even measured intermittence is
evidence for diagnosis, not a permanent tier. The historically retry-passing
`x0x_0041_synthetic_kill_restart` exclusion therefore requires an owner and a
resolution rather than continued storage in a workflow filter.

An environmental requirement may justify an `external` tier only when the
registry names the infrastructure, owning context, owner, and fail-closed
behavior.

### 8. `just check` and CI use the same required dispatcher

`just check` includes:

- formatting;
- lint;
- build;
- documentation;
- the `default` test filter;
- the `required-isolated` filter; and
- the observation-completeness governance audit.

Pull-request CI invokes the same registry-derived required dispatcher and
publishes the same selected-inventory, closed-outcome, and skip-accounting
receipt. Coverage tooling may add instrumentation, but it may not silently
shrink the required inventory or omit an outcome.

### 9. A merge gate requires proven branch enforcement

A CI command is advisory until `main` has a ruleset or branch-protection rule
requiring its exact status context. The rule covers administrators and normal
pushes, with only a documented break-glass bypass.

Enforcement requires both:

1. API readback of the configured rule and exact required status context; and
2. an intentionally red pull request that GitHub refuses to merge.

Dispatcher failure propagation has its own governance negative control,
separate from the transient red pull request. The registry declares a
deliberately failing fixture in the non-functional `governance-fixture` tier,
outside the workspace's ordinary discovered test inventory. Governance invokes
it through the dispatcher's closed fixture mode as a subprocess. The audit
passes only when the fixture receives `executed-and-failed`, inventory and
outcome reconciliation otherwise succeed, the dispatcher attributes its
failing status to that semantic failure, and it exits non-zero. An inventory
or reconciliation failure cannot satisfy the control. The fixture is not an
ordinary test and is not assigned to a functional tier, because either
placement would make a normal required run permanently red or exercise a
different context from the one being certified.

Security Audit, Claude Code, or another context that does not produce a
substantive pass/fail test observation cannot substitute for the required
test context.

### 10. No open-ended grandfathering

The ADR may be reviewed before migration, but the comprehensive status cannot
be required or described as complete until the final receipt is green:

```text
bare #[ignore]                              0
non-default tests outside registry naming  0
multi-tier matches                         0
unreachable declared tiers                 0
undeclared required-context divergence     0
hand-written exclusion filtersets          0
non-registry scheduling overrides          0
required-tier policy not registry-derived  0
dispatcher bypasses                        0
silent early-success paths                 0
regeneration-as-passing-test paths          0
required-run skip-helper records           0
unknown outcome labels                     0
identities without exactly one outcome      0
executed-outcome / terminal mismatches       0
selected identities declared not selected   0
outcomes without authorized declaration     0
not-executed outcomes contradicting state    0
reported results outside selected inventory 0
outcome / runner-summary mismatches          0
required-run declared-not-executed outcomes 0
legacy baseline allowlist                  0
```

There is deliberately no `unclassified default test` metric: a discovered
test that matches no non-default selector is default by construction.

The 196 bare ignore attributes, current workflow exclusions, 31 live
integration-test runtime-precondition paths, two further live unit-test
self-void paths, 22 dormant self-void paths, ten already-fail-closed success
returns that must become explicit divergence, two regeneration escape
hatches, and fragmented legacy runners are migration work. The legacy runner
scope includes two orphaned shell entry points and
`tests/runners/x0x_test_runner.py`, which those scripts invoke and which owns
retry accounting of its own. Moving a bypass from one container to another
does not satisfy the policy. The three existing `quic-localhost` scheduling
overrides and the default profile's slow-test termination policy are also
migration work under the registry's single-source rule; the measured tailnet
backpressure case matches none of those test groups and currently receives no
declared isolation.

### 11. Enforcement order is part of the decision

There is no verified current substantive green baseline context. Rollout is:

1. Produce substantive green CI and Build runs on `main` at a recorded SHA,
   and record every effective test inventory at that SHA. The next approved
   substantive merge may provide this anchor; if either workflow is red,
   stop and diagnose that SHA.
2. Protect those exact observed contexts, including administrators, and read
   the rule back. This is a provisional branch-control anchor, not proof that
   the current smaller CI inventory is complete.
3. Introduce the registry, dispatcher, inventory reconciliation,
   syntax-aware test-exit audit, single skip-recording helper, skip
   reconciliation, the non-functional governance tier and its closed fixture
   mode with the complete outcome-reconciliation mutation manifest,
   skip-helper positive control, and semantic-failure control outside the
   ordinary workspace inventory, and tier jobs in advisory mode; absorb the
   three existing scheduling overrides and the default profile's termination
   policy into the registry. At this stage the dispatcher intentionally retains
   `--run-ignored default`. Before execution it emits a temporary
   `declared-not-executed-with-reason` outcome for each ignored identity that
   remains selected in that context, scoped to this advisory migration and
   reconciled with nextest's aggregate skipped count. That declaration has an
   owner and expires at step 5; it is derived from discovered ignore state,
   not a per-test allowlist.
   Outcome accounting can therefore pass honestly while the separate
   comprehensive-readiness receipt reports the remaining migration work. The
   dispatcher does not claim comprehensive coverage.
4. Migrate the currently live integration-test and unit-test
   runtime-precondition paths, convert already-fail-closed success returns to
   explicit divergence, and move regeneration out of validation tests. Do not
   activate ignored cohorts before this observation machinery exists.
5. Migrate every dormant early-success path and classify all 245 ignored
   tests. Only then switch the primary dispatcher to `--run-ignored all`,
   activate the ignored cohorts, remove undeclared workflow exclusions, and
   reach the comprehensive zero receipt.
6. Require the exact comprehensive status and prove an intentionally red
   pull request cannot merge.
7. Only then remove the fragmented legacy runners and supersede the
   provisional baseline context.

## Consequences

### Positive

- New tests run by default even when their author forgets the policy
  namespace.
- Local and CI selection derive from one executable definition.
- The gate proves both selection and observation; a selected-but-self-voiding
  test can no longer masquerade as coverage.
- Every discovered identity has a positive, closed-set outcome; raw absence
  can no longer mean either "ignored" or "process died."
- Isolation, external infrastructure, and soak budgets remain expressible
  without creating a defect quarantine.
- Required status claims become independently testable through inventory
  receipts, protection readback, and a negative merge control.

### Negative / Trade-offs

- The migration covers all 245 ignores, existing workflow exclusions, silent
  precondition paths, regeneration escape hatches, and legacy runners.
- A syntax-aware Rust audit and machine-readable skip reconciliation add
  tooling that must be maintained with test-language changes.
- Executed-outcome reconciliation initially depends on cargo-nextest's
  experimental `libtest-json-plus` interface; its adapter must fail closed and
  be reviewed when nextest changes the format or stabilizes a replacement.
- Required local and pull-request gates will take longer because
  `required-isolated` remains required rather than being silently deferred.
- Some currently green tests will become explicit failures when their
  preconditions are unavailable.
- External and soak jobs need declared owners, infrastructure contracts,
  schedules, and budgets.

### Neutral / Operational

- `#[ignore = "..."]` remains useful metadata for cargo's ordinary runner,
  but no longer decides routing.
- The registry defines policies and selectors, not an exhaustive test list.
- The registry also owns scheduling selectors currently hand-maintained as
  nextest profile overrides.
- Target-level namespaces classify homogeneous binaries efficiently; mixed
  binaries pay the cost of module/test-level naming.
- Context-specific inventory divergence is visible, owned, and expiring
  rather than forbidden in all circumstances.
- The measured tailnet backpressure case belongs in `required-isolated`; that
  changes scheduling within the required set, not whether the property is
  required.

## Validation

Before the comprehensive status can become required:

- nextest discovery plus registry evaluation shows every test in the default
  complement or exactly one non-default tier;
- all non-default selectors are pairwise disjoint;
- every declared tier is reachable from every context it names;
- `just check` and pull-request CI emit and reconcile their effective
  selected inventories against the registry-derived required inventory;
- each context assigns exactly one declared closed-set outcome to every
  discovered identity;
- every executed outcome has a matching per-test terminal event, every
  not-selected or not-executed outcome is positively declared rather than
  inferred from absence, and outcome counts reconcile with nextest's own
  run/pass/fail/not-run totals;
- coverage uses the same required inventory and closed-outcome
  reconciliation;
- governance proves every required-tier selection, scheduling, isolation,
  concurrency, timeout, termination, and retry policy is derived from the
  registry, in whatever file or tool expresses it;
- the governance-fixture mode accepts only a closed registry fixture key,
  never a caller-supplied target or selector, selects only its
  registry-declared identities, follows the required reconciliation path, and
  cannot change a required context's inventory;
- the governance-tier mutation manifest independently proves every atomic
  invalid state derived from the outcome-reconciliation rejection rules and
  the closed outcome definitions, including cardinality, selection,
  per-identity terminal polarity, declaration source, and runner-aggregate
  mismatches; the audit checks the manifest and every outcome-accounting
  receipt row in both directions, and each control requires selected-inventory
  reconciliation to succeed and attributes the non-zero dispatcher exit only
  to its named condition;
- a syntax-aware audit over integration tests and unit-test modules finds no
  direct success return from a precondition or destructuring failure arm; the
  only allowed success exit is the single skip-exit construct, whose call site
  contains no separate return;
- governance pins that skip-exit construct to one exact definition and its
  governance-tier positive-control fixture proves that the helper record
  caused the non-zero dispatcher exit while inventory and outcome
  reconciliation succeeded;
- a governance-tier deliberately failing fixture proves that its
  `executed-and-failed` outcome caused the non-zero dispatcher exit while
  inventory and outcome reconciliation succeeded;
- a required run emits zero skip-helper records, zero
  declared-not-executed outcomes, and propagates semantic failure;
- regeneration commands and validation tests are distinct;
- the migration receipt in Decision 10 is all zero;
- API readback shows the exact comprehensive status required for `main`,
  including administrators; and
- an intentionally red pull request is refused merge.

Review triggers after acceptance:

- a new test harness, runner, retry layer, coverage tool, or workflow that can
  change the effective inventory;
- a new mechanism that can convert an unmet observation into success;
- a new non-default tier or context-specific divergence;
- a branch-protection or status-context rename; or
- evidence that the static audit cannot recognize a Rust control-flow form
  used by the test suite.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without
human review**. This draft is explicitly pre-consensus until Kimi rules and
David approves it. Accepted ADRs are immutable: create a new superseding ADR
rather than editing an Accepted ADR.
