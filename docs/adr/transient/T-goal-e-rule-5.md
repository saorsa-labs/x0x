# T-goal-e-rule-5: goal E can stand in for an R under rule 5

- **Status:** Proposed
- **Target slot:** A01
- **Date:** 2026-10-11
- **Ruling:** D246 (David, in chat, 11 Oct 2026). D247 asks for this record.
- **Related:** ADR 0095 open question 4, ADR 0072 rule 5, A15 decision rules, the E-D15 efficiency rules

## Context

ADR 0072 rule 5 says that every new decision names the requirement (R) that it serves. A decision that serves no R is rejected, unless it fixes correctness or security in shipped behaviour.

ADR 0095 makes efficiency (goal E) part of the core. Its open question 4 asks if goal E can count in place of an R. ADR 0095 is Accepted, so its text does not change. This record gives the answer.

Without an answer, an efficiency decision must claim a loose R. For example, "fewer presence bytes serve R3". That claim is only paperwork. It does not filter scope.

Two risks need guards:

1. The efficiency changes that need a decision are usually trade-offs. Examples are the cadence change from 300 s to 600 s in v0.39.10, the storm-control validators, and pruning or deferring traffic.
2. Efficiency measurements in this project have been wrong before. A benchmark artifact showed a false 3x regression. A cumulative counter showed a false 50x regression.

## Decision

Goal E counts in place of an R under rule 5 when the change keeps the wire format, API, stored format and dependencies unchanged, and the rule-21 delivery matrix shows no loss. The decision states a target gain when Proposed. It is Folded only after a measured before-and-after result that meets E-D15 rule 15. Any wire, protocol, API or dependency change needs a transient ADR (D242) that names an R.

## How to apply it

1. **Scope test.** Check four surfaces: the wire format, the API, the stored format and the dependencies. If one of them changes, goal E alone is not enough. Name an R. You can name goal E as related.
2. **Delivery.** Attach the rule-21 delivered and published matrix. Own-origin, inbox, targeted and revocation classes stay at 100%. No pair falls below the baseline.
3. **Target.** The Proposed record states the target gain and the measurement plan.
4. **Measurement.** The result meets E-D15 rule 15. Measure on a sealed eph mesh, with at least 5 deploys per arm. Use histograms, not means. p90 needs at least 30 samples, and p95 needs at least 60. Public-mesh rows never gate. Collect evidence at the shipped default log level.
5. **Lifecycle.** David accepts the record. It is Folded only after the measured result is attached. The other E-D15 rules apply to every PR, as before.

## Rejected options

- **Goal E becomes R13.** If efficiency became a requirement in its own right, nearly every change could claim it. Rule 5 would stop filtering anything.
- **Goal E stays a review only.** Efficiency decisions would then keep making loose R claims.
- **"Behaviour stays the same."** This was the first wording. It excluded the trade-offs that need a decision. A change that keeps behaviour the same is a normal PR and needs no decision record.

## Consequences

- Efficiency decisions get a direct route, with a delivery guard and a measurement guard.
- A decision that changes a contract still names an R, so rule 5 still filters scope.
- The 15-slot limit stays. This record lives in `docs/adr/transient/` and does not count toward the 15.
- ADR 0095 stays byte-unchanged. A01 Open questions points to this record.
