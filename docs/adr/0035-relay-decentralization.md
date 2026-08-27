# ADR 0035: Relay Decentralization to SOTA — Earned Promotion, Spread Selection, Bootstrap Demotion

- **Status:** Accepted (2026-08-27, David Irvine)
- **Date:** 2026-08-27
- **Decision owners:** David Irvine (direction + approval), omp (design/research), Claude (review)
- **Reviewers:** Claude (review correction baked in: self-assertion caveat on `verified_inbound`)
- **Supersedes:** none
- **Superseded by:** none
- **Amends:** none
- **Related:** [[0034-leaf-participation-default]] (orthogonal axis: gossip participation vs transport relay role), issue #380 (demand measurements), ADR-0011 (backbone role), PR #406 (`--relay` announcement opt-in)

## Context

The x0x mesh's relay/coordinator backbone is effectively the bootstrap fleet.
`GossipCacheAdapter` carries coordinator adverts alongside bootstrap peers;
`relay_candidates` / `reachable_via` in announces are populated from a small
operator-curated set; NAT'd peers dial bootstrap-hosted coordinators first.

Consequences:

1. **Centralization** — relay bandwidth, traversal coordination, and presence
   concentration on ~6 operator VPS nodes. Cost, trust, and attack surface sit
   on infrastructure we run.
2. **No promotion path** — a desktop on a static IP with fat bandwidth never
   becomes a relay/coordinator no matter how healthy it is; the role set is
   configured, not earned.
3. **No load-balancing** — consumers pick bootstrap-first: we systematically
   over-subscribe our own nodes, the opposite of considerate selection.

## Decision Drivers

- Bootstrap infra is a seed mechanism ([[0031-...]] bootstrap-hints lineage), not
  a service tier; the network must outgrow it.
- Desktops on stable connections are the majority of fleet capacity at rest.
- SOTA networks (below) all converge on: role = f(measured reachability,
  sustained health history, resource budget), spread in consumption, relay as
  fallback not data plane.

## Prior Art (SOTA survey)

### libp2p: AutoNAT + AutoRelay + Circuit Relay v2 + DCUtR

- **Role by measured reachability** (AutoNAT): public dialability determined by
  probes through other peers, not self-assertion; public nodes run the relay
  server service, private nodes activate AutoRelay as consumers.
- **Reservation-based relay slots** (CRv2): every relayed connection holds an
  explicit reservation with duration + data caps; relays bound concurrent slots.
- **Relay as hole-punch facilitator** (DCUtR): steady state is a DIRECT
  connection upgraded through the relay introduction.
- **Considerate selection**: min-candidates wait (boot delay), bounded relay
  set, spread across relays — never first-seen, never all-on-one.

### Tor: verification and earned seniority

- Authorities independently connect to a relay's ORPort before consensus
  listing — self-report is insufficient.
- Flags (Stable, Guard) are earned over days-to-weeks of uptime/bandwidth
  history; new relays get ramp-up traffic before full utilization.

### BitTorrent DHT (BEP-32 / mainline norms)

- Public nodes join the routing table as full DHT nodes; NAT'd nodes are
  clients — role split by reachability.
- Node status (good/questionable/bad) by responsiveness history — continuous
  evaluation with demotion.

## Decision

1. **Reachability-based auto-promotion.** A daemon promotes itself to
   relay/coordinator advertisement when, sustained over a rolling window
   (initially 24h): NAT probes report `can_receive_direct == true`; its
   external address set is stable across ≥2 probe windows; it has budget
   headroom (see 4). Promotion is orthogonal to [[0034-leaf-participation-default]]
   Leaf/Full gossip mode — a promoted desktop relay stays gossip-Leaf; the two
   axes are separate decisions surfaced separately in diagnostics. Demotion is
   symmetric: reachability lost or budget exhausted → withdraw at the next
   announce. Advertised `relay_weight` ramps with sustained health (Tor-style),
   so consumers can prefer proven relays.

2. **Peer-verified dialability — with the self-assertion caveat.** Promotion
   requires ≥3 distinct recent successful inbound dials from distinct peers;
   the announce carries `verified_inbound: u16` (capped count). **This count
   is self-asserted** — a malicious node can claim any number. Consumers
   therefore weight **their own dial evidence first**: a consumer's direct
   observation that a coordinator/relay answered is authoritative, and the
   announced `verified_inbound` is a **tie-break hint only**, never a primary
   ranking input. No global authorities; the mesh verifies by trying.

3. **Spread selection across ALL advertised relays.** Consumers switch from
   bootstrap-first to spread selection: maintain the advertised-relay set from
   announces; wait for min-candidates before committing; choose by weighted
   random over (own dial evidence, `relay_weight`, measured RTT); hold 2–3
   concurrent relay relationships and rotate on failure.

4. **Budget caps** (CRv2 lesson): promoted relays bound concurrent relayed
   sessions, per-peer throughput, and session duration with re-reservation;
   coordinator traversal gets the same bounded-orchestration caps.

5. **Bootstrap demotion.** Bootstraps remain seed/rendezvous infrastructure
   but stop being the default relay/coordinator set: once a node sees
   ≥ min-candidates of verified non-bootstrap relays, bootstrap-hosted relays
   leave its selection pool (last-resort fallback with a warn metric).
   Operator infra becomes the floor, not the ceiling.

## Considered Options

1. Operator-curated relay lists only (status quo) — rejected: centralization
   permanent, no path to SOTA.
2. Global authorities à la Tor dir-auths — rejected: wrong scale, adds
   infrastructure trust we exist to remove.
3. Pure self-assertion (announce flags stay config bits) — rejected: unverifiable
   backbone claims; the peer-verified dial count with consumer-side-first
   weighting (Decision 2) is the trust floor.
4. **Chosen:** earned self-promotion bounded by peer verification and budgets,
   spread consumption, bootstrap last-resort.

## Rollout

1. **Meter first** (this ADR's current phase): advertised-relay census,
   selection-skew counters at relay/coordinator choice sites, distinct-inbound-
   dialer tracking, `/diagnostics/relay` surface. Zero behavior change.
2. Promotion telemetry + `verified_inbound` counting (still no behavior change).
3. Auto-promotion behind a default-off flag; soak on the 6-node testnet +
   desktops.
4. Consumer selection switches to spread-weighted; measure bootstrap offload.
5. Default-on after soak.
6. Bootstrap demotion to last-resort, last.

## Validation

- **Metering baseline (this PR, rollout step 1)**: `GET /diagnostics/relay`
  must show, on the live network, (a) a non-zero relay/coordinator advert
  census with the bootstrap-vs-community split populated, (b)
  `distinct_inbound_dialers_1h` > 0 on publicly reachable nodes and ≈ 0 on
  NAT'd desktops, (c) selection-skew counters accumulating with
  `chosen_bootstrap` initially dominant — the "before" picture every later
  step is judged against.
- **Promotion (step 3)**: a testnet desktop with sustained reachability
  auto-advertises within one window and withdraws within one announce of
  losing it; soak per the rollout section before default-on.
- **Spread selection (step 4)**: `chosen_non_bootstrap / (chosen_bootstrap +
  chosen_non_bootstrap)` rises with the community pool; bootstrap share of
  relay selections trends toward last-resort-only.
- Tests: census classification + TTL-stale exclusion; selection-choice
  classification with IP-deduped bootstrap bridge; inbound-dialer window
  accounting; `/diagnostics/relay` route wiring + CLI parity + coverage
  marker (all in PR #427).

## Consequences

**Positive:** operator VPS load falls as healthy peers take relay duty;
capacity scales with the fleet; single-operator trust shrinks to seed duty.

**Negative:** more relays of unknown quality — mitigated by own-evidence-first
weighting (Decision 2), ramp weights, and budget caps; more announce surface
(one u16 field); promotion/demotion churn adds announce variance — bounded by
the 24h window and symmetric withdrawal.

**Risks / open questions:** desktop opt-in default (`relay_offer = auto|on|off`);
min-candidates and ramp window calibration for a ~50-node mesh; whether a
measurable-bandwidth signal is ever needed beyond own-dial-evidence + RTT;
full CRv2-style vouchers vs simple caps.
