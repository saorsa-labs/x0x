# ADR 0032: The `:443` Bootstrap Listener Runs Its Own Identity

- **Status:** Accepted (2026-08-23)
- **Date:** 2026-08-23
- **Decision owners:** Claude (investigation/implementation)
- **Reviewers:** David Irvine
- **Supersedes:** none
- **Superseded by:** none
- **Amends:** [ADR 0011](./0011-bootstrap-dual-listen-udp-443.md) (ops section: the
  generated `:443` config overrides `identity_dir`, not `machine_key_path`)
- **Related:** issue #385, PR #386, issue #380 (gossip storm), `tests/e2e_vps.sh`

## Context

ADR 0011 added a second `x0xd` per bootstrap host listening on UDP/443 with
"its own state dir and machine identity". The deploy script implemented that by
writing `machine_key_path = "/var/lib/x0x-443/machine.key"` into the generated
config. `machine_key_path` has never been a `DaemonConfig` field; `DaemonConfig`
carries no `deny_unknown_fields`, so the key was parsed, dropped, and the `:443`
daemon resolved its keys from the default `~/.x0x/` — the prod daemon's
`machine.key` and `agent.key`. Verified 2026-08-23 on all six hosts: both
instances reported identical `agent_id` and `machine_id`.

Consequences observed: agent-addressed traffic to a bootstrap agent (durable DMs,
exec, file offers, group invites) was committed by whichever instance's inbox
subscription the gossip path reached first — two processes with independent
history DBs, outboxes and dispatch. `tests/e2e_vps.sh` counted those as lost
deliveries (17/30) and a durable `POST /direct/send` that returned 200 was found
committed in the `:443` instance's history while `:12600`'s `/direct/events`
never saw it.

## Decision Drivers

- ADR 0011's stated intent ("own state dir and machine identity") was never in
  effect; this ADR records what is now deployed rather than what was assumed.
- Identity is key-based; the seed list is address-only and no ACL pins the old
  `:443` machine id, so re-keying the `:443` instance breaks nothing.
- A silently-ignored config key must not be able to cause this class again.

## Considered Options

1. **Own `identity_dir` per `:443` instance (chosen).** Top-level
   `identity_dir = "/var/lib/x0x-443/identity"`; fresh `machine.key` +
   `agent.key` are generated on first start.
2. Keep one identity and make the two instances share history/dispatch. Rejected:
   it re-creates the split-brain at every other per-agent surface and ADR 0011
   never asked for it.
3. Reject unknown config keys (`deny_unknown_fields`). Rejected for now per the
   0.35.1 ruling — a drifted live config must not brick on upgrade.

## Decision

- `.deployment/deploy-443.sh` overrides `identity_dir` (a real top-level
  `DaemonConfig` field) instead of the non-existent `machine_key_path`, and its
  placement check covers it.
- `x0xd` deserialises its config through `serde_ignored` and logs
  `config key \`<path>\` is not a recognised setting and is ignored` for every
  dropped key at any depth (`src/server/config.rs::parse_with_ignored_keys`).
  Warn-only; rejection remains a later minor with notice.
- Rolled out 2026-08-23 ~06:55Z to saorsa-2/3/6/7/8/9 by adding the key to
  `/etc/x0x/x0xd-443.toml` and restarting `x0xd-443` with 20 s spacing; each
  instance now reports a distinct `agent_id`/`machine_id` from its host's prod
  daemon.

## Consequences

- Positive: one agent identity ↔ one process on every bootstrap host; durable
  delivery to a bootstrap agent is deterministic; a misspelt config key is
  visible in the first lines of the startup log.
- Negative: the `:443` instance is a new, unknown agent to the network (no
  contacts, no trust); it is a transport listener only, which is all ADR 0011
  needs from it.
- Neutral: the #380 connection churn rate was measured before and after the
  rollout and did not change; that is an ant-quic behaviour and is tracked
  separately.

## Validation

- `tests/e2e_vps.sh --network=prod` after rollout: a durable SFO→NYC and
  Nuremberg→NYC send lands in the `:12600` instance's `/direct/events` and
  history; the `:443` instance's history no longer grows.
- `src/server/config.rs` tests: `ignored_keys_are_reported_with_their_path`
  (top-level and `[gossip]`-scoped `machine_key_path` both reported) and
  `recognised_keys_are_not_reported`.
- On each host: `x0xd --config /etc/x0x/x0xd-443.toml --check` passes and the
  startup log carries no "not a recognised setting" warning for the generated
  file.
