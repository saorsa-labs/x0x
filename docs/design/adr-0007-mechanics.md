# ADR-0007 mechanics — Identity key file layout

> Extracted 2026-08-29 from the immutable [ADR 0007](../adr/0007-three-layer-identity-model.md) per the
> 2026-08-23 ADR audit. The ADR remains the complete decision record; the
> sections below are the operational rules and acceptance criteria relocated verbatim
> so this file is their maintained home — future updates
> belong here, not in the ADR.

## Operational Rules

Default unnamed instances store identity material under `~/.x0x`:

```text
machine.key
agent.key
user.key      # optional
agent.cert    # optional
```

Named daemon instances use separate identity directories such as `~/.x0x-alice` and `~/.x0x-bob`.

`machine.key` and `agent.key` are generated when missing. `user.key` is not generated automatically. Create it explicitly with `x0x user-id create [PATH]`; without `PATH`, the command writes `~/.x0x/user.key`, overwriting any existing target file.

If an existing `agent.cert` does not match the configured user key and current agent key, x0x should treat it as stale and issue a new certificate when a user key is active. Without an active user key, the certificate is inert local state.

Shareable agent cards are identity metadata and contact-import aids. They are not key backups and are not, by themselves, proof of a human-backed identity.

---

## Acceptance Criteria

This ADR is satisfied only when:

- documentation distinguishes `machine_id`, `agent_id`, and `user_id`;
- user identity is documented as opt-in and consent-gated;
- docs explain that `machine_id` equals the ant-quic transport `PeerId`;
- docs explain that `agent_id` is the portable day-to-day identity;
- docs explain that trust/machine pinning evaluates `(AgentId, MachineId)`;
- docs do not present agent cards as key backups or standalone human identity proof.
