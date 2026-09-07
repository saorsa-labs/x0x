# Modern-only convergence gate (ADR-014 harness)

**Owner:** Tester  
**Recipe:** `just convergence-release-modern` (additive; stock `convergence-release` unchanged)  
**Soak flag:** `--modern-only`

## Behaviour

1. **Fail closed** if `X0XD_LEGACY_BINARY` is set (justfile + soak refuse).
2. Build `x0xd` + `x0xd-forge-injector`, then run  
   `convergence_soak.py --runs 10 --expect-fixed --modern-only`.
3. Stock mixed-version gates are **not** PASS: labeled `not_in_modern_predicate`.
4. Stock `just convergence-release` (legacy hard-require) is left intact.
5. **RejectV1** diagnostics assert is **TODO until #546** — do not fake policy readback.
6. **No fake 10/10.** Filled receipt awaits modern freeze tip + real run.

## Hermetic self-tests

`python3 -m unittest tests.convergence.test_convergence_soak`  
covers env-refuse + classifier (`ModernOnlyPredicateTests`).

## Receipt stub

`tests/convergence/modern_receipt.py` — field skeleton only; see #545 template
for the seated docs path. Do not invent a filled PASS receipt here.

## Non-goals

- Do not touch #529 / #545 / #546 tips.
- No tag. No weaken of #517 / run `34058040463` FAIL evidence.
