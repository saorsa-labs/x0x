# ADR 0034: Leaf Gossip Participation Is the Desktop Default; `--relay` Is One Operator Concept

- **Status:** Accepted (2026-08-25)
- **Date:** 2026-08-25
- **Decision owners:** David Irvine (direction), Claude + omp (review/landing), Grok (implementation, PR #395/#397)
- **Supersedes:** none
- **Superseded by:** none
- **Amends:** none (complements ADR-0011 backbone role and ADR-0033 pump policy)
- **Related:** issue #380 (demand measurements), #398 (connectivity arc), PR #395, PR #397, PR #406

## Context

sg 0.5.74 outbound metering (issue #380, 2026-08-24) measured an idle desktop daemon
relaying ~444–557 KB/s continuously — ~150 pass-through PlumTree topics it never
subscribed to, ~12 KB ML-DSA-signed messages, 100% relay traffic (local origination
≈ 0 msg/s). Every desktop was acting as a full mesh router for the always-on fleets'
application traffic, saturating residential uplinks and driving the per-peer send
timeouts behind the #380 cooling storms. Desktop *connectivity* is first-class via
the #398 NAT arc (direct → coordinated punch → MASQUE relay); desktop *routing duty*
is what this ADR changes.

Separately, PR #406 introduced `--relay`/`X0X_RELAY_OPT_IN=1` as the announcement
opt-in (a non-public node may advertise relay/coordinator capability). PR #395
introduced `--relay` as the Full-participation opt-in. One token, two meanings.

## Decision

1. **Leaf is the default participation mode for ordinary daemons.** A Leaf node
   subscribes, publishes, and consumes normally, but does not maintain
   pass-through PlumTree state for unsubscribed topics (no `set_topic_peers`
   refresh for them; PR #397 adds inbound refusal). Bootstrap/managed binaries
   resolve to Full automatically; resolution fail-closes to Full when detection
   is uncertain.
2. **`--relay` is one operator concept: "be a relay node."** Any of the three
   equivalent sources — CLI `--relay` (or `--relay-opt-in`), env
   `X0X_RELAY_OPT_IN=1`, TOML `gossip.relay = true` — selects BOTH Full gossip
   participation AND relay/coordinator capability advertisement (#406's gate).
   The daemon normalises the env var at startup so both consumers observe any
   source. A relay that refuses pass-through gossip is not a relay; a node
   volunteering pass-through duty should be discoverable as a helper.
3. Diagnostics: `/diagnostics/gossip` reports the resolved mode and reason
   (`bootstrap_binding`, `managed_binary`, `operator_relay`, `default_leaf`).

## Consequences

- Positive: desktop uplink demand from pass-through relaying drops to ~zero;
  the storm inputs measured in #380 lose their bandwidth engine; residential
  nodes stop being load-bearing mesh routers.
- Negative: dissemination capacity concentrates on Full nodes (the six
  bootstraps + opt-ins). This is the ADR-0011 backbone by design; capacity is
  added by running `--relay` nodes, which the honesty gate (#406) makes
  discoverable and selectable.
- Neutral: connectivity is unaffected — Leaf nodes still hole-punch, accept
  relays, and exchange direct traffic as first-class peers.

## Validation

- Metering before: `outbound_publish_origin.relay_bytes` ≈ 570 KB/s idle desktop
  (#380 comment 2026-08-24). After (soak gate in PR #397's
  `docs/380-c0-soak-gate.md`): ≥90% drop in pass-through forwarding on a Leaf
  desktop, with subscribed-topic delivery unchanged.
- Tests: participation resolution truth table (PR #395, 11 tests); C0
  refuse/accept split (PR #397, 17 tests); `--relay` unification asserted at
  the server resolution site.
