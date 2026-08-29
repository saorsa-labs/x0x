# Required-Gate Observation Completeness

- **Status:** Draft reference implementation
- **Governing decision:** [ADR 0025](../adr/0025-required-gates-prove-observation-completeness.md)
- **Source migration:** ADR 0025 at
  `102ab0e53acf35c2dcebc716d6de9127b9bb50ab`

This chapter owns the mutable mechanisms that implement ADR 0025. The ADR owns
the stable architectural decision and its body remains the immutable decision
record; the Grounding evidence is maintained in the
[Extracted from ADR-0025 section](#extracted-from-adr-0025-2026-08-29) below.
Changes here do not amend the ADR; a mechanism that cannot satisfy the ADR
requires a superseding decision.

The chapter declares its governing ADR. ADR-to-chapter membership must be
computed from that field; no ADR-side chapter allowlist is maintained.

## 1. Registry model

Resolves at: `e3013710d7ed69077de9a799dffdbeb5ac80535a`

Resolution scope: repository inputs at this commit. The registry described
below is specified work and is not asserted to exist at that commit.

The registry enumerates non-default policy definitions, never individual
ordinary tests. Discovery computes ordinary required execution as the
complement of those definitions.

The initial functional tiers are:

| Tier | Required execution |
|---|---|
| `default` | local `just check` and pull-request CI |
| `required-isolated` | local `just check` and pull-request CI, after compilation and with declared isolation |
| `external` | only in the context supplying its declared infrastructure |
| `soak` | on its declared schedule and budget |

There is no `flaky` or `known-defect` tier. A test requiring a different
schedule may remain required; scheduling does not imply exclusion.

Each functional tier definition owns:

- a positive `binary(...)` or `test(...)` selector;
- every permitted context-specific exclusion;
- its non-fixture execution contexts;
- scheduling, isolation, concurrency, timeout, termination, and retry policy;
- infrastructure preconditions and failure policy;
- an owner; and
- a reason and expiry for every context-specific divergence.

The initial contexts are `local`, `pull-request`, `external`, `scheduled`, and
`fixture`. New contexts extend the registry schema; they do not create a
second routing authority.

### Classification algorithm

Resolves at: `e3013710d7ed69077de9a799dffdbeb5ac80535a`

Every discovered identity is classified mechanically:

```text
matches = registry.non_default_selectors_matching(identity)

if matches.count == 0:
    tier = default
elif matches.count == 1:
    tier = matches.only
else:
    fail("overlapping non-default declarations")
```

Only non-default tiers carry a source-level, machine-selectable namespace. A
homogeneous integration target uses its target name. A mixed target uses a
module or test-name namespace. A missing or mistyped namespace therefore
falls into `default` and runs.

`#[ignore = "..."]` may remain human-readable metadata for cargo's ordinary
runner, but it is not routing authority. The steady-state dispatcher uses
`--run-ignored all`; the temporary migration state is described in Section 10.

## 2. Governance fixtures

Resolves at: `102ab0e53acf35c2dcebc716d6de9127b9bb50ab`

Resolution scope: the fixture governance design recorded in the source ADR.
The mechanism remains specified rather than implemented.

`governance-fixture` is a non-functional control tier. Its reserved
`governance_fixture_*` source namespace classifies governance fixtures out of
the default complement without making their identities a routing allowlist.

The fixture definition owns:

- its positive source-namespace selector;
- a closed list of exact fixture identities;
- the `fixture` context; and
- a closed fixture key for each control.

The following relations reconcile in both directions:

- every listed identity matches the fixture selector exactly once;
- every discovered selector match appears in the identity list;
- no functional test matches the fixture selector; and
- fixture identities never appear in a functional required inventory.

The fixture context has one entry point. It accepts only a registry fixture
key, never a caller-supplied selector or arbitrary test target. The key
resolves to exact fixture identities and traverses the same runner adapter,
outcome mapping, reconciliation, and semantic-failure propagation path as a
required run. Fixture mode cannot alter any required run's inventory.

## 3. Dispatcher ownership and reachability

Resolves at: `e3013710d7ed69077de9a799dffdbeb5ac80535a`

Resolution scope: fragmented runner surfaces at this commit are migration
inputs; the dispatcher is specified work.

A single dispatcher consumes the registry. Workflow files, nextest profiles,
scripts, `justfile` recipes, and successor containers may consume generated
policy but cannot become independent authorities.

`run-required` iterates `default` and `required-isolated`. Local `just check`
invokes `run-required`. CI derives required, external, and scheduled matrices
from the same registry and invokes the same dispatcher.

Reachability is proven from the dispatcher graph:

```text
declared tier
  -> registry context
  -> generated entry point
  -> dispatcher mode
  -> runner invocation
```

The invariant is one execution definition per tier, not one process or one
call site. A command found in an otherwise orphaned script is not reachable.

Required dispatchers propagate semantic failure to a failing status.
Governance follows values rather than rejecting token shapes. For example,
`|| true` may preserve output only when a later fail-closed check turns the
captured failure into a non-zero result.

## 4. Inventory and outcome accounting

Resolves at: `e3013710d7ed69077de9a799dffdbeb5ac80535a`

Resolution scope: nextest 0.9.126 and the repository's current runner settings
at this commit define the initial adapter boundary.

The required inventory is the union of `default` and `required-isolated`.
Before execution, each required context emits its effective selected inventory
and reconciles it against that required inventory. Selection is computed
before the runner applies ignore-state behavior.

Each run emits exactly one outcome per identity in its discovery scope:

| Outcome | Required predicates |
|---|---|
| `executed-and-passed` | selected identity plus matching passing terminal event |
| `executed-and-failed` | selected identity plus matching failing terminal event |
| `declared-not-selected` | pre-run registry declaration that the tier is out of scope |
| `declared-not-executed-with-reason` | selected identity plus a permitted positive dispatcher or skip-helper declaration |

An executed failure remains a semantic failure. Accounting it never converts
the dispatcher to success.

A `started` event proves only presence in the stream. It is not a terminal
observation. A missing terminal event never becomes a declared non-run by
inference.

The reconciler compares the outcome table one-to-one with:

- discovery;
- the effective selected inventory;
- the closed outcome definitions;
- per-identity terminal events; and
- the runner's aggregate run, pass, fail, skipped, and not-run totals.

It fails on zero or multiple outcomes, a result outside selection, a terminal
polarity mismatch, a selected identity declared not selected, a declaration
without its authority, a not-executed declaration alongside a terminal event,
or a selected identity with neither a terminal event nor a positive
not-executed declaration. Selected-set equality is necessary and insufficient.

### Initial nextest adapter

Resolves at: `e3013710d7ed69077de9a799dffdbeb5ac80535a`

The initial adapter may invoke cargo-nextest 0.9.126 with:

```text
NEXTEST_EXPERIMENTAL_LIBTEST_JSON=1
--message-format libtest-json-plus
```

The dispatcher owns the environment flag, parser, and version-pinned raw
event-to-outcome mapping. An unavailable or malformed stream, or an unknown
event or outcome label, fails closed. Unknown values are not extension points.
The adapter reconciles explicit declarations with aggregate runner totals and
does not translate event absence into an outcome.

## 5. Differential controls and mutation manifest

Resolves at: `102ab0e53acf35c2dcebc716d6de9127b9bb50ab`

Resolution scope: this section preserves the detailed control mechanism that
was compressed into ADR 0025 Validation.

The mutation manifest is derived from every predicate in the closed outcome
definitions and from every reconciler rejection rule. It contains a case for
each atomic invalid state, including:

- zero outcomes and multiple outcomes for one identity;
- an executed outcome for an unselected identity;
- a missing or opposite-polarity terminal event;
- `declared-not-selected` on a selected identity, without its registry
  declaration, or alongside a terminal event;
- `declared-not-executed-with-reason` on an unselected identity, without a
  permitted source, or alongside a terminal event;
- an unknown outcome label; and
- a valid-looking table that disagrees with runner aggregates.

Each fixture changes one predicate from an otherwise identical state and names
one canonical diagnostic. Governance checks the manifest and receipt rows in
both directions: every atomic invalid state has a fixture and receipt row, and
every mutation-backed receipt row has a fixture.

For a named condition C, the control has three runs:

1. unchanged, the control passes;
2. a change violating C makes the gate fail and attribute the failure to C;
3. a change violating another condition makes the gate fail without
   attributing the failure to C.

Only the applied change differs between runs. Compile errors, unrelated
inventory failures, semantic failures, other reconciliation failures, and
self-reported zero receipts cannot substitute for the named control.

The steady-state requirement for zero valid not-executed outcomes is a
readiness condition, not an invalid-state mutation, and is identified
separately.

## 6. Runtime preconditions and the skip helper

Resolves at: `e3013710d7ed69077de9a799dffdbeb5ac80535a`

Resolution scope: integration and unit-test control-flow shapes at this commit
are migration inputs. The syntax-aware audit and helper are specified work.

An unmet precondition fails by default. Where the test harness cannot express a
native skip, test code may use one pinned syntax-level helper that both emits a
machine-readable record keyed to the discovered identity and exits the test.
The helper call is the exit operation; a separate success return is forbidden.

The helper maps only to `declared-not-executed-with-reason`. It never maps to
`executed-and-passed`.

- a required dispatcher fails when any skip-helper record exists;
- an external or soak context fails when scheduled but missing its promised
  infrastructure; and
- a tier not scheduled in a context is accounted for by registry policy, not
  by a passing test.

The helper's positive-control fixture runs through closed fixture mode. It
passes its control only when the record maps to its exact identity, inventory
and outcome reconciliation otherwise hold, the dispatcher attributes the
non-zero result to the skip-helper count, and the dispatcher exits non-zero.

### Syntax-aware exit audit

Resolves at: `e3013710d7ed69077de9a799dffdbeb5ac80535a`

Within a test function's own control-flow scope, a precondition-failure or
destructuring-failure arm must:

- diverge through an assertion, `panic!`, or `unreachable!`; or
- exit through the single pinned skip construct.

Direct success exits such as `return`, `return Ok(())`, and
`let ... else { return Ok(()) }` are forbidden. An assertion-dominated arm
still uses explicit divergence instead of retaining an unreachable success
return.

The audit parses Rust syntax across integration tests and unit-test modules. It
distinguishes test-function exits from returns inside nested closures or async
blocks. It does not infer assertion domination, scan for log messages, or use
the earlier brace-depth census as its normative implementation.

## 7. Regeneration and known-defect handling

Resolves at: `e3013710d7ed69077de9a799dffdbeb5ac80535a`

Resolution scope: regeneration escape hatches, defect-labelled tests, and
workflow exclusions at this commit are migration inputs.

Artifact generation and validation have separate entry points. An `xtask` or
equivalent command generates an artifact; required tests always validate the
committed artifact. Until separated, required dispatch rejects regeneration
environment variables and the exit audit continues reporting their
early-success paths.

A deterministic product or dependency defect is not stored in an ignore,
exclusion, early-success precondition, retry-only success, or successor
mechanism. Triage chooses one honest state:

- fix the behavior and run the regression normally;
- record intended behavior as a passing characterization and track any desired
  change separately; or
- if intent is unresolved, remove the disputed executable claim, preserve the
  reproducer and competing expectations in an owned, expiring issue, and do not
  claim coverage.

`Flaky` requires measured pass/fail evidence, and measured intermittence is
diagnostic evidence rather than a permanent tier. An external tier is valid
only when the registry names its infrastructure, owning context, owner, and
fail-closed behavior.

## 8. Local, CI, coverage, and protection

Resolves at: `e3013710d7ed69077de9a799dffdbeb5ac80535a`

Resolution scope: current `justfile` and workflow commands at this commit are
migration inputs. No branch-protection state is inferred from this SHA.

The target `just check` composition is:

- formatting;
- lint;
- build;
- documentation;
- the default test filter;
- the required-isolated filter; and
- the observation-completeness audit.

Pull-request CI invokes the same registry-derived required dispatcher and
publishes the same selected-inventory, closed-outcome, and skip-accounting
receipt. Coverage may add instrumentation but cannot shrink the required
inventory or omit outcomes.

A deliberately failing fixture outside the ordinary workspace inventory
proves semantic-failure propagation. The control succeeds only when the
fixture receives `executed-and-failed`, reconciliation otherwise holds, the
dispatcher attributes the non-zero result to that semantic failure, and it
exits non-zero.

Branch enforcement is a separate control. It requires:

1. API readback naming the exact protected comprehensive status, including
   administrator coverage and any documented break-glass path; and
2. an intentionally failing pull request that the platform refuses to merge.

A workflow that reports green without a substantive pass/fail observation
cannot substitute for the protected test context.

## 9. Comprehensive-readiness receipt

Resolves at: `102ab0e53acf35c2dcebc716d6de9127b9bb50ab`

Resolution scope: this is the complete receipt schema migrated from the source
ADR. Values are requirements, not assertions about the current tree.

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

There is no `unclassified default test` row because a discovered identity
matching no non-default selector is default by construction. Receipt
generation computes its population; a self-reported empty population or zero
does not satisfy a control.

## 10. Rollout

Resolves at: `e3013710d7ed69077de9a799dffdbeb5ac80535a`

Resolution scope: source measurements at this commit define migration inputs.
The sequence is prescribed work, not an assertion that any step has landed.

1. Produce substantive green CI and Build runs on `main` at one recorded SHA
   and record every effective test inventory there. Stop and diagnose if
   either workflow is red.
2. Protect those exact observed contexts, including administrators, and read
   the rule back. This is a provisional branch-control anchor, not evidence
   that the smaller legacy inventory is complete.
3. Add the registry, dispatcher, inventory and outcome reconciliation,
   syntax-aware exit audit, skip helper, governance fixtures, mutation
   manifest, semantic-failure control, and tier jobs in advisory mode. Move
   existing scheduling and termination policy under the registry.
4. During this advisory stage retain `--run-ignored default`. Before
   execution, positively declare every ignored identity still selected in the
   context as temporarily not executed, reconcile those declarations with
   nextest aggregates, give the declaration an owner, and expire it at step 6.
   Do not claim comprehensive coverage.
5. Migrate live integration and unit-test precondition paths, convert
   already-fail-closed success returns to explicit divergence, and separate
   regeneration from validation. Do not activate ignored cohorts first.
6. Migrate dormant early-success paths and classify every ignored test. Then
   switch to `--run-ignored all`, activate the cohorts, remove undeclared
   workflow exclusions, and reach the zero receipt.
7. Require the exact comprehensive status and prove an intentionally failing
   pull request cannot merge.
8. Only then remove fragmented legacy runners and supersede the provisional
   branch-control context.

Moving a bypass between an attribute, workflow, shell script, test body,
retry layer, or environment-controlled mode does not satisfy the rollout.

## 11. Implementation validation matrix

Resolves at: `102ab0e53acf35c2dcebc716d6de9127b9bb50ab`

Resolution scope: detailed controls migrated from source ADR Validation.

Before the comprehensive status becomes required, controls prove:

- discovery and registry evaluation classify every identity as default or
  exactly one non-default tier;
- non-default selectors are pairwise disjoint;
- fixture namespace discovery and the closed fixture list reconcile both
  ways, and fixtures are absent from functional inventories;
- each declared tier is reachable from every context it names;
- local and pull-request selected inventories reconcile with discovery and the
  registry-derived required inventory;
- each context assigns exactly one valid closed-set outcome per discovered
  identity;
- executed outcomes match terminal events, declarations are positive rather
  than inferred from absence, and outcome totals match runner totals;
- coverage uses the same required inventory and reconciliation;
- every required selection, scheduling, isolation, concurrency, timeout,
  termination, and retry policy derives from the registry;
- fixture mode accepts only a closed key, selects only registry identities,
  follows the required reconciliation path, and cannot change a required
  inventory;
- every atomic invalid outcome state has its differential control and
  canonical attribution;
- the syntax-aware audit finds no direct precondition or destructuring success
  exit outside the pinned helper;
- the helper definition and positive-control fixture are exact;
- a deliberately failing fixture proves semantic-failure propagation;
- a required run has zero helper records and zero not-executed outcomes;
- regeneration and validation are distinct;
- every readiness-receipt row is zero;
- protection readback names the exact comprehensive status; and
- an intentionally failing pull request is refused merge.

## 12. Reference-implementation review triggers

Resolves at: `102ab0e53acf35c2dcebc716d6de9127b9bb50ab`

Review this chapter and ADR 0025 when:

- a new test harness, runner, retry layer, coverage tool, or workflow can
  change effective inventory;
- a new mechanism can convert an unmet observation into success;
- a new non-default tier or context-specific divergence is proposed;
- a branch-protection rule or status context is renamed; or
- evidence shows that an adapter or static audit cannot recognise a
  control-flow or observation form the suite actually uses.

The first four triggers identify policy or integration changes. The final
trigger prevents a currently complete-looking audit from silently becoming a
screen as test or runner syntax evolves.

## 13. Source migration manifest

Resolves at: `102ab0e53acf35c2dcebc716d6de9127b9bb50ab`

This ledger maps every source line exactly once to its primary destination.
The ADR carries stable decisions, its Grounding blocks carry evidence, and
this chapter carries mutable mechanisms. Blank lines and headings travel with
their enclosing range.

| Source lines | Primary destination |
|---:|---|
| 1–20 | ADR register, status, and Grounding G-001 |
| 21–46 | ADR Summary and Context |
| 47–118 | ADR Grounding G-002, G-003, G-005, and G-006 |
| 119–136 | ADR Decision Drivers |
| 137–159 | ADR Considered Options |
| 160–183 | ADR Decisions 1 and 4 |
| 184–224 | Chapter §§1–2 |
| 225–233 | ADR Grounding G-001 |
| 234–287 | Chapter §§1–3 |
| 288–299 | ADR Decisions 2 and 3 |
| 300–407 | Chapter §§4–5 |
| 408–420 | ADR Decision 4 |
| 421–476 | Chapter §6 |
| 477–483 | ADR Decision 4 |
| 484–487 | Chapter §§7 and 10 |
| 488–492 | ADR Decision 4 |
| 493–514 | Chapter §7 |
| 515–531 | Chapter §8 |
| 532–543 | ADR Decision 5 |
| 544–555 | Chapter §§2 and 8 |
| 556–559 | ADR Decision 5 |
| 560–564 | ADR Decision 5 |
| 565–589 | Chapter §9 |
| 590–592 | ADR Decision 1 |
| 593–606 | ADR Grounding G-002 through G-004 |
| 607–647 | Chapter §10 |
| 648–663 | ADR Consequences |
| 664–690 | Chapter §§4, 6, 7, and 8 |
| 691–694 | ADR Grounding G-001 |
| 695–699 | ADR Validation |
| 700–749 | Chapter §§5 and 11 |
| 750–759 | Chapter §12 |
| 760–765 | ADR register and Status |

The table's ranges are contiguous, non-overlapping, and cover source lines
1–765. Future edits update this chapter in place; they do not rewrite the
source migration or amend the Proposed decision.

## F1 removed-member exclusion evidence — ADR 0025 ownership

Resolves at: `e04b73a73fd44ebeb7af661bcf623dbd20b2f88e`.

The phase-aware R3 observation, execution classification, and F1 fixture
controls belong in
`docs/design/required-gates-observation-completeness.md`, governed by Accepted
ADR 0025. They do not amend ADR 0025 and do not belong in either the deployment
chapter or the new active-recipient chapter.

The current R3 is not one weak observation but a race between two reasons for
the same `None`. Its helper discards every non-200 response. Before Bob applies
`MemberRemoved`, his record still contains epoch E and an E+1 ciphertext
returns 409. A valid self-removal apply then removes Bob from the roster,
deletes his entire named-group record, clears the related caches and returns
(`named_groups.rs:5058,5074-5111`). The same decrypt request thereafter
returns 404 because the record is absent (`:12304-12305`). The one-shot
`is_none()` assertion at `tests/f1_gss_remove_live.rs:349-352` neither
establishes nor reports which phase it sampled.

The ADR 0025-governed chapter owns these mutable mechanisms:

1. **Bind epoch E to Bob's real baseline without a secret-export route.**
   While Bob is active, production `secure_group_reseal` seals E to Bob
   (`named_groups.rs:12446-12528`). The integration-test target loads Bob's
   actual persisted `<data_dir>/agent_kem.key` and opens that real envelope
   with the public production `open_group_secret` primitive. The recovered E
   key must open the same baseline content that Bob's stored-state decrypt
   endpoint already opened through the production content derivation, nonce,
   AAD, and AEAD inputs.
2. **Bind the survivor sensitivity lane.** After R2, production reseal to
   active Charlie must succeed. The integration-test target opens that
   envelope with Charlie's actual persisted key; the recovered E+1 key must
   open the exact survivor ciphertext, while Bob's captured E key must fail
   authentication. The test needs a shared production AAD builder extracted
   from private `secure_share_aad` (`named_groups.rs:878-886`); duplicating
   that wire binding in the test is not acceptable.
3. **Model the R3 phase honestly.** During any pre-terminal interval, Bob's
   stored-state decrypt response must be 409 with a parseable body,
   `ciphertext_epoch == post_epoch`, and `local_epoch < ciphertext_epoch`.
   HTTP 200 is red. A prompt correct apply may make this interval empty; the
   gate must not hold removal unfinished merely to obtain 409. In its own
   bounded window, the same previously proven group must transition to 404.
   That 404 is a terminal phase marker, not key-exclusion evidence; 403, 424,
   malformed, unreadable, and unmodelled responses fail.
4. **Retain the Bob-lane vacuity/sensitivity control.** In the
   integration-test target only, call the public production
   `seal_group_secret_to_recipient` primitive with the real E+1 secret,
   Bob's retained KEM public key, and the shared production AAD. Open it with
   Bob's actual persisted private key and require the recovered secret to
   decrypt the real survivor ciphertext. This proves Bob's recipient-bound
   envelope fixture is usable and possession would compromise content. It is
   not production enforcement evidence and is not the product mutation. The
   new active-recipient chapter, not the ADR 0025 chapter, owns the evidence
   that the test call path which selects Bob is excluded from production
   builds at compile time. The shared sealing primitive is not excluded.
5. **Keep delivery observations phase-specific.** A pre-terminal
   test-constructed valid E+1 envelope may be delivered behind a barrier that
   proves installation and E+1 decrypt before removal continues; that is an
   installation sensitivity arm, not the product-rule mutation. After
   terminal 404, `SecureShareDelivered` resolution rejects `unknown_group`
   before KEM open/install (`:4629-4647`). That post-terminal arm pins
   non-resurrection only and must not be counted as key-exclusion evidence or
   attributed to `ensure_named_group_key_material_install_allowed`, which
   models withdrawn groups rather than removed-self record deletion.

At `e04b73a`, `just adr-gates-f1-live` is the only tracked invocation and no
GitHub workflow reaches it. Under ADR 0025, the repository may not claim this
property is covered until the gate is classified by the single execution
authority and reached in its declared context.

## Local and CI validation contract

Resolves at: `e04b73a73fd44ebeb7af661bcf623dbd20b2f88e`.

Use one named, registry-derived required integration recipe. `just check`
invokes that recipe after compilation, and pull-request CI invokes the same
dispatcher and selector. Deterministic tests that spawn only local daemons are
classified as required-isolated; VPS, external-network, and soak tests remain
explicit non-default declarations owned by their actual contexts. A global
unclassified `--run-ignored all` is not the contract.

Gemma's measured inventory at
`RESEARCH/X0X_IGNORED_TEST_INVENTORY_2026_07_30.md` has SHA-256
`15dc15197a2a11585d8a98c09085a9a05a470e44b0929fd6571d8ecf0c55a52c`.
Under CI's all-feature set it discovers 2,695 tests and 246 ignored
identities. The nine CI commands select 156; `just adr-gates-f1-live` selects
one disjoint identity; 89 are unaccounted. Eleven of those 89 explicitly
require live VPS or external-network access.

The execution authority must classify all 246 identities exactly once before
the selector is frozen. The current 156 CI-selected, one F1-only, and 89
unaccounted partitions are inventory evidence, not the final context
classification. In particular, the remaining 78 unaccounted identities
cannot be inferred local merely because they are not among the eleven
explicit external cases. The measured 180.96 seconds is cold
discovery/compilation wall time; no test body ran, so it is not test runtime.

Using the same dispatcher locally and in CI proves shared authority and
reachability, not merge enforcement. Current `main` is unprotected. Under
Accepted ADR 0025 Decision 5, the comprehensive status may be called a merge
gate only after protection for that exact status is enabled and read back and
an intentionally failing pull request is refused merge. CI may land before
that staged proof, but its status must be described as CI-only until the
readback and red-PR receipt exist.

## Extracted from ADR-0025 (2026-08-29)

> Relocated verbatim from the immutable ADR body per the 2026-08-23 ADR audit;
> this chapter is the maintained home for it.

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
