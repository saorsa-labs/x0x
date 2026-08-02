# Managed x0xd Deployment

- **Status:** Draft reference implementation
- **Governing decision:** [ADR 0026](../adr/0026-managed-x0xd-deployment.md)
- **Source baseline:** `e04b73a73fd44ebeb7af661bcf623dbd20b2f88e`

## Citation coordinates

Resolves at: `e04b73a73fd44ebeb7af661bcf623dbd20b2f88e`.

Repository-baseline citations in this chapter resolve at
`e04b73a73fd44ebeb7af661bcf623dbd20b2f88e`. Each later mechanism section
must carry its own `Resolves at:` pin to that baseline or a later exact source
commit.

## 1. Authoritative deployment inventory

Resolves at: `e04b73a73fd44ebeb7af661bcf623dbd20b2f88e`.

- the selected production, 443, testnet, and runner instance definitions;
- the chosen live installation entry point;
- unit, drop-in, config, generator, flag, environment, binary, default, and
  identity-input composition and precedence;
- exact disposition of every competing `.deployment/` artifact;
- retirement of legacy `.deployment/deploy.sh` and
  `.deployment/x0xd.service`;
- an executable authoritative replacement that installs
  `.deployment/systemd/x0xd.service` and the production `config.toml`
  generated from the tracked bootstrap config source; and
- a rule that a new managed artifact enters the inventory by default and
  cannot become an unreachable alternative.

The chapter may define a machine-readable schema. The ADR must not.

Dario's pinned-tree audit supplies the retirement ruling: the legacy script
uploads a file that its installed unit does not read, and a separate tracked
hardening script removes that uploaded filename as legacy. Kimi should
confirm this source-history reading. If Kimi finds contrary authority or
product intent, the exact retire-versus-repair choice goes to David.

## 1a. Machine-readable inventory schema and single-source migration

Resolves at: `e04b73a73fd44ebeb7af661bcf623dbd20b2f88e`.

The canonical record authority is a strict JSON manifest at
`.deployment/authority-inventory.json`. This chapter governs its schema; the
manifest owns the instance records; installers, generators, and repository
checks are consumers. Markdown must not carry a second instance list, and an
executable consumer must not retain an inline copy.

The top-level object contains:

- `schema_version`, a positive integer whose current value is `1`; and
- `instances`, a non-empty array of records with unique stable `id` values.

Each instance record contains:

- `id`;
- `unit.source`, `unit.destination`, and a possibly empty `unit.dropins` array
  whose records each carry `source` and `destination`;
- `config.destination` and exactly one config authority:
  `config.source` for a tracked config, or `config.generator` plus its declared
  `config.input_instances` for generated config;
- `binary.destination`; and
- `installation.entrypoint` plus literal `installation.selector_args` used
  only to select that instance when an entry point serves more than one.

Selector arguments carry only a stable instance selector, such as
`--instance testnet`. They do not repeat unit, config, binary, source, or
destination values owned by the manifest record or its referenced artifacts.
A shared entry point reads those values from the selected manifest record;
path-valued flags such as `--config /etc/x0x/config-testnet.toml` are not
conforming selector arguments.

Repository source paths are deployment-root-relative and must remain inside
`.deployment/` after canonicalization. Live destinations are absolute. Unknown
keys, unknown schema versions, duplicate identifiers, an empty inventory, a
missing referenced artifact, a config with both or neither source authority,
or a non-literal selector fail validation.

The manifest does not copy values that the referenced artifacts own. The
consumer derives the actual binary, `--name`, `--config`, environment,
generator inputs, and effective-root inputs from the unit, config, generator,
and installer, then reconciles those derived values with the manifest and
discovered repository artifacts in both directions.

Moving the inventory out of an executable is one atomic repository change:
add the manifest, make every consumer read and validate it, delete all inline
instance records, and keep the gate red if neither authority is usable, both
persist, or any consumer still obtains instance records from executable code.
Adding a manifest beside the current inline inventory is non-compliant even
temporarily in a reviewable revision.

## 2. Effective-resolution adapter

Resolves at: `e04b73a73fd44ebeb7af661bcf623dbd20b2f88e`.

- one daemon-owned resolution surface or a version-pinned adapter that
  reproduces the daemon's real precedence;
- explicit handling of process environment and supported `--name`
  derivation;
- config-section validation and wrong-section diagnostics;
- identity and effective-root output;
- refusal of unknown, unreadable, ambiguous, or unbound values; and
- evidence that the adapter fails when daemon resolution behavior changes
  without a matching adapter update.

The deployment checker must not invent a second, silently divergent
`data_dir` algorithm.

## 3. Static repository authority check

Resolves at: `e04b73a73fd44ebeb7af661bcf623dbd20b2f88e`.

- a repository script that reconciles discovered deployment artifacts with
  the authoritative inventory;
- reachability from the selected install entry point;
- no duplicate authority, competing root, orphan unit/config, or unbound
  load-bearing input;
- shell/unit/config syntax checks appropriate to the chosen mechanism;
- a named local recipe, included in required validation;
- pull-request CI invoking the same recipe; and
- disclosed controls for the current contradictory prod units, the
  comment/body mismatch in `deploy-443.sh`, a missing testnet unit, a
  duplicate root, an orphan alternative, and disagreement between the config
  path uploaded by the installer and the config path read by its selected
  unit.

## 4. Side-effect-free running-set observation

Resolves at: `e04b73a73fd44ebeb7af661bcf623dbd20b2f88e`.

- complete `x0xd` process discovery on a host;
- PID, executable provenance, instance identity, authority attribution, and
  effective `data_dir` for each process;
- pairwise root comparison;
- explicit refusal of an empty self-reported inventory, unreadable process,
  unknown unit, or unattributed process;
- a stable machine-readable receipt; and
- on-demand and scheduled execution without changing service state.

An open `history.db` path may be corroborating evidence, but it is not by
itself the effective-root authority because `history.db_path` can override
only that subsystem.

Benjamin's count-only live probe is not the acceptance mechanism. Comparing
the host-wide count of distinct open `history.db` paths with the host-wide
`x0xd` process count does not join either observation by PID: two daemons
sharing one database plus an unrelated process holding a second database can
pass. The replacement must map every discovered `x0xd` PID to that process's
own authority attribution and effective root, then compare those PID-bound
roots pairwise.

## 5. Closed transition protocol

Resolves at: `e04b73a73fd44ebeb7af661bcf623dbd20b2f88e`.

- preflight over the complete running set plus every proposed instance;
- the narrow remediation exception for a known failed starting state;
- deterministic activation order;
- postflight over the actual complete running set;
- rollback or removal of a newly introduced non-compliant process;
- no success result on missing or malformed observations; and
- retained before/after receipts tied to the deployed repository revision.

## 6. Migration sequence

Resolves at: `e04b73a73fd44ebeb7af661bcf623dbd20b2f88e`.

1. Land repository-only governance first: additive ADR, Grounding, design
   chapter, selected deployment authority, static check, and CI reachability.
2. First make the tracked `systemd/x0xd.service` plus production
   `config.toml` path executable and authoritative. The installer must upload
   the tracked production config to the same path its selected unit reads.
   Then retire legacy `.deployment/deploy.sh` and
   `.deployment/x0xd.service` in the same repository change so there is no
   interval with either zero or two claimed authorities.
3. Preserve Benjamin's section-aware generator code from unpushed commit
   `9318824574bd525679e5036b262979ed2e5b3529`, but omit its edit to Accepted
   ADR 0011 and do not carry the count-only live probe forward as acceptance
   evidence. The commit is not present on the GitHub remote; the implementation
   owner must obtain Benjamin's local patch rather than assume the abbreviated
   SHA can be fetched. Replace the live probe with the PID-bound observation
   specified above.
4. Keep daemon product hardening separate: resolved database path in startup
   errors and rejection or loud warning for known keys in the wrong TOML
   section.
5. Define the tracked testnet unit and explicit production/testnet
   `data_dir` inputs in the repository without changing fleet state.
6. After approval and testnet soak, perform controlled fleet restarts with
   preflight/postflight receipts. Retain `--name testnet`.
7. Identify the exact Obsidian target and governing sync rule, then perform
   the `tests/CLAUDE.md` sync as post-merge housekeeping.
