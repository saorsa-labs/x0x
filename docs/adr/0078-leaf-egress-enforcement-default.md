# ADR 0078: Leaf Egress Enforcement Default — `shed_normal` by Default, Observe-Only on Opt-Out

- **Status:** Proposed
- **Date:** 2026-09-27
- **Decision owners:** David Irvine (acceptance; only David may move this to Accepted)
- **Reviewers:** cross-model (omp) review required
- **Supersedes:** none
- **Superseded by:** none
- **Extends:** ADR 0034 (Leaf participation) and the #504 slice-2 policy ("a non-zero `leaf_egress_hard_bytes_per_sec` is a meter"), which this ADR proposes to amend for the **default** configuration only. It edits neither ADR; if accepted, a one-line pointer is added to each.
- **Vision requirement:** R4, "connectivity better than Tailscale" — a default install must not quietly spend the user's uplink/battery as mesh infrastructure.
- **Related:** #945 (default Leaf forwarded 635 MB in 17 min ≈ 653 KiB/s ≈ 5× the default 128 KiB/s hard budget); #504 (Leaf egress budget design; measured 716 KiB/s `epidemic_forward_bytes`); #501 (`x0x/dm/v1/bus` whole-mesh compat DM bus); #807 (Leaf eager-set truncation black-holes DM-inbox/join envelopes); #731 (low-traffic topics with no eager path); `docs/design/504-leaf-egress-budget.md`; `src/gossip/config.rs` (`LeafBytePolicy`), `src/gossip/egress.rs`, saorsa-gossip-pubsub `src/egress.rs` + `src/lib.rs:8052` (eager-path reservation)

## Context

A default desktop daemon is a participation **Leaf**. A Leaf refuses
pass-through for topics it is *not* subscribed to (ADR 0034 / #380 C0) but
**eager-forwards every topic it is subscribed to**, and every daemon
unconditionally subscribes to global buses — identity/machine/user announce,
`x0x/dm/v1/bus` (#501), capability adverts, group discovery — so a default
Leaf epidemic-forwards the mesh's global traffic to its eager set.

The Leaf egress budget exists and is on by default (soft 64 KiB/s, hard
128 KiB/s, burst 4 MiB), but #504 slice 2 made enforcement **opt-in**:
`LeafBytePolicy::ObserveOnly` ("account and meter every send, but deny none")
is the default, and `byte_policy = "shed_normal"` must be written explicitly.
The stated reason: "dropping gossip is a behaviour change that must be
attributable to a deliberate operator decision, never to the side effect of
setting a non-zero byte rate."

The consequence, measured twice now: #504 §3.2 recorded ~716 KiB/s of
`epidemic_forward_bytes` on a true Leaf; #945 recorded 635 MB in 17 minutes
(≈ 653 KiB/s, ≈ 5× the default hard budget) with only the exceed counters
ticking. Nothing sheds. The deny machinery in saorsa-gossip is complete,
narrow and tested — under `ShedNormal` only **forwarded, non-Critical**
traffic may be deferred; Critical topics (DM inbox, control plane),
local-origin publishes, own-inbox delivery and targeted sends are structurally
un-sheddable — but it cannot arm under the default policy. Meanwhile the
operators the opt-in was designed to protect (deliberate-change attribution)
mostly do not know the field exists: the default network behaviour of a
desktop app is "forward the mesh's global buses at full line rate", which is
itself a behaviour nobody deliberately chose.

## Decision Drivers

- R4: a default install consuming the user's uplink (hundreds of KiB/s
  sustained) is a product defect, not a tuning question.
- #504's attribution principle is respected by *documented default changes*
  (release notes + visible counters), not only by opt-in flags.
- Any cap must not regress delivery correctness — #807 and #731 show eager-set
  restrictions on a Leaf can black-hole DM-inbox/join envelopes and starve
  low-traffic topics.
- The structural cause — Leaves sitting on global buses (#501) — is a larger,
  separate change; a byte cap is the safety net until and after it.

## Considered Options

1. **(a) `shed_normal` by default for Leaf participation** (operator can
   restore `observe_only` explicitly; Full/relay nodes unchanged — shedding
   stays ignored there exactly as today).
2. **(b) Leave the default and fix the flood structurally**: remove Leaves
   from the global buses (#501 dm bus; announce topics per-shard). No default
   behaviour change; the budget stays a meter.
3. **(c) Keep `observe_only` and only lower eager degree** (default is 2
   today; stock saorsa-gossip caps at 12). Bounds copies per message, not
   bytes per second.

## Decision (Proposed)

Adopt **(a)** as the default-config policy, shipped together with **(b) as
the accepted structural follow-up** (tracked separately; (a) is not blocked
on it):

- `GossipConfig::byte_policy` default becomes `ShedNormal`. A config that
  writes `byte_policy = "observe_only"` keeps today's exact behaviour.
- The change applies only where enforcement can exist: a Leaf with a non-zero
  hard rate. Full/relay participation keeps `leaf_egress_config → None`
  (pass-through, unbudgeted) unchanged.
- **Interaction with #807 (Leaf eager truncation):** `ShedNormal` does not
  truncate the eager set and does not drop — over-budget forwarded frames are
  **deferred** (flushed as the bucket refills) and remain IHAVE-serveable
  via the lazy path, which is exactly the repair path #807's black-holes
  bypassed. Risk stated plainly: under *sustained* over-budget plus a
  *truncated* eager set, deferral adds latency on top of #807's loss; the
  mitigation is that DM-inbox/control topics are Critical-class and never
  deferred, so the black-holed envelope classes of #807 are structurally
  exempt. #807/#731 closure with fleet evidence remains the gate for any
  further eager-path restriction (per ADR 0071).
- **Critical/DM-inbox protections (unchanged, restated as acceptance
  criteria):** never sheds Critical-class topics, local-origin publishes,
  own-inbox delivery, or targeted sends — enforced in saorsa-gossip's
  reservation layer, not by convention.
- Release notes must carry the default change prominently, and the exceed and
  shed counters must be visible (diagnostics + GUI) before this ADR is
  accepted — a cap users cannot see is indistinguishable from a fault.

## Consequences

### Positive

- A default Leaf's egress is bounded (~128 KiB/s hard) instead of ~5× that;
  R4 stops regressing by default.
- The #504 attribution principle is preserved at the fleet level: the change
  is a reviewed, released, documented default — the most deliberate decision
  process the project has.
- Deferral (not drop) + lazy-path service preserves delivery for honest
  traffic; Critical classes are untouched.

### Negative / Trade-offs

- Long-standing installs see a real behaviour change on upgrade without
  editing config (mitigated by release notes and the one-line opt-out).
- Sustained global-bus floods now surface as latency (deferred eager sends)
  instead of silent bandwidth burn; users on very slow links could perceive
  slower convergence of non-Critical topics.
- Does not reduce the volume the mesh *generates* — only what a Leaf re-sends.
  (b) is still needed.

### Neutral / Operational

- Operators who tuned `leaf_egress_*` rates already get the same accounting;
  only the policy flag flips.
- Diagnostics gain `soft_exceeded`/`hard_exceeded`, `epidemic_forward_bytes`,
  and the sg `LeafEgressSnapshot` (visibility shipped independently of this
  ADR's acceptance).

## Validation

- Fleet soak: `Δepidemic_forward_bytes/Δt ≤ leaf_egress_hard_bytes_per_sec`
  on default-config Leaves; `observe_only` opt-out restores prior rates.
- #807/#731 regression suites stay green; DM-inbox and join-envelope delivery
  latency under sustained over-budget load is within the lazy-path bound.
- Shed/defer events visible in `/diagnostics/gossip` and the GUI diagnostics
  view; no shed events on Critical topics, ever (counter must read zero).

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without
human review**. Only David Irvine accepts this ADR. Accepted ADRs are
immutable: create a new superseding ADR rather than editing an Accepted ADR.
