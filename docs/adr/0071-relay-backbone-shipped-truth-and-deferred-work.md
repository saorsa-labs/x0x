# ADR 0071: Relay Backbone — What Relays Today and What Is Deferred

<!-- File name: docs/adr/0071-relay-backbone-shipped-truth-and-deferred-work.md -->

- **Status:** Accepted
- **Accepted:** 2026-09-25 by David Irvine ("accept ADR-0070, 0071 and 0072"; status change applied by Claude at his instruction)
- **Date:** 2026-09-25
- **Decision owners:** David Irvine (decision, 2026-09-25 vision-alignment review), Claude (drafting)
- **Reviewers:** pending — David Irvine (acceptance); omp (cross-model review)
- **Supersedes:** none
- **Superseded by:** none
- **Amends:** ADR 0020 (its relay-fallback premise); ADR 0035 (scope — work beyond Rollout step 1 frozen)
- **Related:** ADR 0011, ADR 0034, ADR 0051 (Proposed), ADR 0072; #807, #731, #132; PR #897 (ADR hygiene sweep)

## Context

Three ADRs describe the relay layer differently:

- **ADR 0020** (Accepted) says x0x "carries … an always-on symmetric MASQUE
  relay fallback" (0020 Context, lines 16–17) and builds Tailnet Phase 1 on it.
- **ADR 0035** (Accepted) says the relay/coordinator backbone "is effectively
  the bootstrap fleet" (0035 Context, line 14) and plans earned promotion,
  spread selection and bootstrap demotion. Its Rollout step 1 is "meter first".
- **ADR 0051** (Proposed) ships peer relay (X0X-0070) default-off with
  first-eligible selection "pending ADR-0035's spread model".

Shipped code on `main` (verified 2026-09-25) says:

1. **ant-quic MASQUE server runs on every daemon.** `relay_service_enabled` is
   true on every default daemon; x0x does not configure ant-quic relaying
   beyond defaults (`src/network.rs` has no relay knob besides peer relay).
2. **Only plausibly-public nodes advertise it.** Since #398 an announce claims
   `relay_capable` / `coordinator_capable` only with peer-verified Global
   reachability, an active UPnP mapping, or explicit `--relay` /
   `X0X_RELAY_OPT_IN=1` (`AnnouncementAssistSnapshot::from_node_status`,
   `src/lib.rs`). A NATed desktop runs the server but is never selected.
   In practice the advertised pool is the bootstrap fleet plus opt-ins.
3. **Gossip pass-through relaying is backbone-only.** Per ADR 0034, desktops
   are `ParticipationMode::Leaf` and refuse eager/IHAVE/IWANT work on topics
   they do not subscribe to; seed, `:443`, managed and `--relay` processes
   stay `Full` (`src/gossip/participation.rs`).
4. **Peer relay is off.** `RelayPolicy::default()` has `enabled: false`
   (`src/peer_relay.rs`).
5. **ADR 0035 shipped only metering.** `GET /diagnostics/relay` (census,
   selection-skew counters, `distinct_inbound_dialers_1h`) exists; there is no
   auto-promotion, spread selection or bootstrap demotion in `src/`.

Meanwhile delivery on the paths that already exist is not yet reliable:
#807 (Leaf eager-set truncation black-holes DM-inbox/join envelopes) and #731
(low-traffic topics on default-Leaf peers can have no eager path to a
publisher). Adding relay roles on top of an unreliable delivery path adds
complexity where the vision (R4 better-than-Tailscale, R6 cross-machine
collaboration) is currently lost.

## Decision Drivers

- ADRs must describe shipped behaviour; readers of 0020 and 0035 cannot tell
  who actually relays today.
- Delivery correctness (#807, #731) comes before new relay roles.
- Scope narrowing per the 2026-09-25 vision-alignment review (ADR 0072).

## Considered Options

1. Leave 0020/0035/0051 as they are — rejected: the contradiction misleads
   design work and reviews.
2. Continue ADR 0035 rollout steps 2–6 and promote ADR 0051 now — rejected:
   builds relay selection on delivery paths with open black-hole defects.
3. **Record the shipped truth and freeze the remaining relay work until the
   delivery defects close** — chosen.

## Decision

We will treat the following as the authoritative description of relaying
in x0x until this ADR is superseded:

1. **Who relays what today.**
   - *Transport (NAT) relaying:* ant-quic MASQUE, server present on every
     daemon; it is **used** only via advertised relays, which are the
     bootstrap fleet (ADR 0011) and `--relay` opt-in nodes, plus nodes that
     prove public reachability. This amends ADR 0020's premise: the relay
     fallback is "always available via the advertised backbone", not
     "symmetric on every node".
   - *Gossip relaying:* bootstrap / `:443` / managed / `--relay` nodes (Full).
     Leaf desktops do not forward topics they do not subscribe to.
   - *Application peer relay (ADR 0051):* default-off; operator opt-in only.
2. **Frozen (no new work):** ADR 0035 Rollout steps 2–6 (promotion telemetry,
   auto-promotion, spread-weighted selection, default-on, bootstrap demotion)
   and any promotion of ADR 0051 (default-on, spread selection). Step 1
   metering (`/diagnostics/relay`) stays and receives bug fixes.
3. **Exit condition.** The freeze may be lifted by a new ADR once **#807 and
   #731 are closed with fleet evidence** (delivery proved on the prod or
   testnet fleet with default-Leaf desktops, not local-only tests) **and** the
   ADR names the vision requirement it serves (ADR 0072 rule).

This ADR amends ADR 0035's scope only; its target model is not rejected.

## Consequences

### Positive

- One place states who relays today; ADR 0020/0035/0051 readers are pointed
  at shipped behaviour.
- Effort moves to delivery correctness (#807, #731) that R4/R6 depend on.

### Negative / Trade-offs

- Relay bandwidth and trust stay concentrated on the ~6 operator VPS nodes
  (ADR 0035's centralization problem persists) until the freeze lifts.
- NATed desktops with good connectivity remain unused as relays.

### Neutral / Operational

- **#132 relayed-forward proof is still owed.** Tailnet forwards over a
  MASQUE-relayed path have not been proven on real NATs; ADR 0020's
  relay-fallback claim is unverified for forwards until #132 closes. This
  ADR does not freeze #132 — it is proof of existing behaviour, not new
  relay work.
- `--relay` remains the single operator concept (ADR 0034).

## Validation

- Every code fact in Context is re-checked (file + symbol) when this ADR is
  proposed for acceptance; any drift is corrected here before acceptance.
- Review trigger: closure of #807 and #731, or any PR touching relay
  selection, promotion or `RelayPolicy::default()` — such a PR must cite a
  superseding ADR or be rejected under item 2.
- `/diagnostics/relay` selection-skew counters are the metric for bootstrap
  concentration when the freeze is revisited.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human review**. Accepted ADRs are immutable: create a new superseding ADR rather than editing an Accepted ADR.
