# ADR 0026: Managed x0xd Deployment Has Distinct Roots and Closed Resolution

- **Status:** Accepted
- **Date:** 2026-07-30
- **Decision owners:** David Irvine
- **Reviewers:** Sam; Dario; Watson. Watson made Kimi's reserved rulings under
  David Irvine's delegation (Buzz event `eb6a888a`); Kimi reviews at
  implementation.
- **Supersedes:** none
- **Superseded by:** none
- **Related:** issue #281; ADR 0011; ADR 0023; ADR 0025; ADR 0027;
  `docs/design/managed-x0xd-deployment.md`

## Summary

Concurrently running `x0xd` processes on one host use distinct effective data
roots. A managed host has one repository-identified path that determines how
each daemon is installed and how every input affecting identity or
`data_dir` is resolved. That path proves the rule over the complete running
process set without changing service state and closes every controlled
transition with a fail-closed preflight and postflight.

## Context

ADR 0011 correctly requires a second `x0xd` listener on bootstrap hosts and
gives it separate state. It does not govern every later multi-daemon
installation path, configuration source, default, environment input, or
runtime transition. It remains Accepted and unchanged.

The repository and measured fleet no longer have one reproducible account of
what runs. Tracked deployment surfaces select conflicting production config
paths, the live fleet relies on defaulted roots, and testnet units running on
the fleet have no tracked installation path. A shared root can also be hidden
by a subsystem-specific override, while a correctly derived named-instance
root can be made non-reproducible by leaving the load-bearing flag in an
untracked host-local unit.

The decision must therefore bind the effective host state and its
reproducibility, not freeze today's TOML, systemd, shell, or probe mechanics.

## Decision Drivers

- Concurrent daemons must not share an effective `data_dir`.
- Supported named-instance derivation must remain valid.
- Every load-bearing input must be deterministically bound or rejected,
  regardless of whether it comes from a file, flag, default, generator, or
  process environment.
- An untracked or unreadable running daemon must enlarge failure, not shrink
  the observed population.
- Host drift and unattended restarts must remain observable even when no
  deployment command is running.
- ADR 0011 is still correct and Accepted ADRs are immutable.

## Considered Options

1. **Edit ADR 0011.** Rejected. Its dual-listener decision remains correct,
   and Accepted ADRs are immutable.
2. **Freeze the present systemd, TOML, shell, and `lsof` procedure in an
   ADR.** Rejected. Those are mutable implementation mechanisms.
3. **Require exactly one source file per daemon.** Rejected. A valid
   deployment may compose a unit, drop-ins, configuration, generated values,
   and fixed environment under explicit precedence.
4. **Add a property-level ADR with Grounding and a governed design
   chapter.** Chosen.

## Decision

1. **Distinct effective roots.** Every concurrently running `x0xd` on one
   host resolves to a distinct effective `data_dir`. A subsystem-specific
   override such as `history.db_path` does not make a shared root a supported
   deployment.

2. **Authoritative resolution.** Each managed host has one
   repository-identified authoritative installation and resolution path. A
   path is authoritative only when it is repository-tracked, reaches every
   input capable of changing an instance identity or effective `data_dir`,
   and defines deterministic composition and precedence. Each such input,
   regardless of origin, is bound to a determinate value or rejected. A
   competing root, unreachable alternative, or unbound load-bearing input
   makes the deployment non-reproducible.

3. **Standing isolation and closed transitions.** On a managed host, every
   running `x0xd` is attributable to the authoritative path, its effective
   `data_dir` is observable, and its root is distinct from every other
   running `x0xd` root. The path can demonstrate this property over the
   complete running set on demand without changing service state. A missing,
   unknown, unreadable, or unattributed member fails the control.

   Before a transition it controls, the path accounts for the union of the
   running set and every instance selected by the transition. Afterward it
   re-enumerates the actual running set and re-proves the standing property.
   A non-remediation transition may not proceed from a failed preflight. A
   bounded transition whose declared purpose is to remove or govern every
   accounted pre-existing violation may proceed, but it is not complete
   until postflight proves full compliance. No transition may leave a newly
   introduced non-compliant process running.

## Consequences

### Positive

- Root collisions, untracked daemons, orphan deployment alternatives, and
  unbound environment/default inputs fail closed.
- `--name`, generated configuration, and multi-file systemd composition
  remain valid when the authoritative path binds them deterministically.
- Drift can be detected without waiting for another deployment.

### Negative / Trade-offs

- The repository needs maintained static authority checks and the fleet needs
  a side-effect-free runtime observation.
- Adoption knowingly records the current untracked testnet units and
  contradictory production deployment paths as non-compliant.
- An unrelated fleet transition cannot complete until every pre-existing
  process is tracked or removed. A remediation transition remains possible.

### Neutral / Operational

- ADR 0011 remains additive and unchanged.
- Exact config paths, unit layouts, generators, probes, receipts, rollback,
  and scheduling live in the governed design chapter.
- Explicit production and testnet `data_dir` changes remain later fleet work
  requiring approval, controlled restarts, and testnet soak.

## Validation

Acceptance requires independent controls for the following properties. Each
control passes unchanged and fails under a disclosed single-condition break
that targets that property.

- every tracked managed instance is reachable from exactly one authoritative
  installation path;
- every input that can affect identity or effective `data_dir` is bound or
  rejected under explicit precedence;
- a competing unit/config path, an orphan alternative, or an untracked
  managed instance fails repository validation;
- two running daemons with the same effective root fail the runtime
  observation;
- an extra, unreadable, or unattributed running `x0xd` fails the observation;
- a compliant multi-daemon host passes without changing service state;
- a controlled transition accounts for existing and proposed instances
  before state change and for the actual complete running set afterward;
- failed postflight cannot resolve to success or leave a newly introduced
  non-compliant process running; and
- the executable repository check is reached by both the required local
  recipe and pull-request CI.

A new deployment entry point, service manager, configuration resolver,
default, instance-identity input, or runtime probe requires review of this
decision.

## Grounding

### G-001 — Effective roots have load-bearing inputs outside explicit TOML

Resolves at:
`e04b73a73fd44ebeb7af661bcf623dbd20b2f88e`.

Supports: Context, Decision 1, and Decision 2.

Repository surfaces: `src/server/state.rs`, `src/bin/x0xd.rs`,
`src/history/mod.rs`, `Cargo.toml`.

Observed result: `data_dir` is a top-level `DaemonConfig` field with a
default; the process environment participates in the platform default; named
instances deliberately derive instance-scoped roots; and
`HistoryConfig.db_path` may override only the history database. Therefore
neither "explicit TOML only" nor an enumerated input-kind list is a sound
architectural invariant.

External evidence: Buzz events
`d3766357fd854693454163a5e706e958810e3d7a0549b31a92be553f0011ab0e`
and
`175eb61f92cc87064bf7a898a5c72e397fd12e66a19ab1219a909034f6378fdd`.

### G-002 — Accepted decisions require separate state but do not govern the path

Resolves at:
`e04b73a73fd44ebeb7af661bcf623dbd20b2f88e`.

Supports: Context, the additive relationship, and Decision 1.

Repository surfaces:
`docs/adr/0011-bootstrap-dual-listen-udp-443.md`,
`docs/adr/0023-durable-local-history.md`,
`src/history/mod.rs`.

Observed result: ADR 0011 requires two bootstrap listeners and describes a
separate state directory for the 443 instance. ADR 0023 binds ordinary
history storage to the per-instance data directory. Neither decision defines
one authoritative installation/configuration resolution path or a
complete-running-set observation. The new decision is additive, not
superseding.

### G-003 — The tracked production deployment paths contradict one another

Resolves at:
`e04b73a73fd44ebeb7af661bcf623dbd20b2f88e`.

Supports: Context, Decision 2, and the known non-compliance consequence.

Repository surfaces: `.deployment/deploy.sh`,
`.deployment/x0xd.service`, `.deployment/systemd/x0xd.service`,
`.deployment/README.md`, `.deployment/deploy-443.sh`.

Observed result: `deploy.sh` uploads `/etc/x0x/bootstrap.toml` and installs a
unit that reads `/etc/x0x/x0xd.toml`. The reproducible-bring-up section and
the measured live unit instead identify a unit reading
`/etc/x0x/config.toml`. `deploy-443.sh` also names one source path in its
header and reads another in its executable body. The tree does not determine
one reproducible production resolution path.

External evidence: Buzz events
`0f99a9f608ef80da00289525d74c6bbcab07a6b67c6c6bb452fb8b060e3893e7`
and
`2d230d6dfc9f32c7b0932acf93ab166c832e7c6127757f78c035a978653ee582`,
with the current pinned-tree audit in
`3a28517b1ef436f9a8e78b0b29372f7e0d07948995087698308e1f45de4035ed`.

### G-004 — Live configs omit `data_dir`; open files show current separation

Observation date: 2026-07-29.

Supports: Context, Decision 2, and standing runtime observation.

External evidence: Buzz event
`cb63c05940159ca1065bec1c12545251adbea879ce0ac3b2a6d1c35cb1c4c593`.

Observed result: on the five requested reachable nodes
`saorsa-2/3/6/8/9`, `/etc/x0x/config.toml` contained no `data_dir`, while
read-only open-file observation showed production history under
`/root/.local/share/x0x`, testnet under
`/root/.local/share/x0x-testnet`, and the 443 listener under
`/var/lib/x0x-443/data`. The open history files corroborate current
separation but are not, alone, an effective-root authority because a
subsystem override is possible. This is a dated, scoped fleet observation,
not a timeless claim.

### G-005 — Running testnet daemons have no tracked authority

Repository resolution:
`e04b73a73fd44ebeb7af661bcf623dbd20b2f88e`.

Fleet observation date: 2026-07-29.

Supports: Decision 3 and the known non-compliance consequence.

Repository surface: `.deployment/**`.

Observed result: the repository contains no testnet unit or installation
path, while the measured fleet ran `x0xd-testnet` on all six nodes on
2026-07-29. The processes are therefore not attributable to a tracked
authoritative path even though their roots happened to be distinct.

External evidence: Buzz events
`175eb61f92cc87064bf7a898a5c72e397fd12e66a19ab1219a909034f6378fdd`
and the exact six-node observation at
`ed87f4ccfc934a1d34bf913ace7f6bacc56116ef1126be25defa7777be609448`
(published 2026-07-29T08:24:11Z).

### G-006 — No required gate observes `.deployment/`

Resolves at:
`e04b73a73fd44ebeb7af661bcf623dbd20b2f88e`.

Supports: Validation.

Repository surfaces: `.github/**`, `justfile`, `.deployment/**`.

Observed result: `.github/` contains no reference to `.deployment/`, and
`just check` runs Rust formatting, lint, build, ordinary tests, and
documentation only. The deployment scripts and unit files have no required
static authority check or runtime observation.

External evidence: Buzz event
`737753aa4df467796a88638cdadbfeee937eed6e0620676febc0fd6f43424f30`.

## Notes for AI-assisted work

AI tools may help draft this ADR, but must not mark it Accepted without human
review. Accepted ADRs are immutable: create a new superseding ADR rather than
editing an Accepted ADR.
