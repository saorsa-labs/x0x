# Modern-only convergence receipt (template)

**Status:** template — fill per candidate; not a PASS by itself.
**ADR:** saorsa-gossip ADR-014 (Accepted 2026-09-07).
**Instance path when filled:** `docs/release/receipts/modern-only-YYYYMMDD-<tip>.md`

| Field | Value |
| --- | --- |
| `adr` | ADR-014 — status: Accepted |
| `named_modern_version` | version / tip / tree: ________ |
| `deps` | saorsa-gossip-pubsub … + archive SHA-256: ________ |
| `outer_signature_policy` | `reject_v1` (required) |
| `legacy_grants` | `disabled` (required) |
| `stock_v0_30_1_phases` | `not_in_modern_predicate` (required — not PASS) |
| `failed_compat_evidence` | #517 FAIL; run 34058040463 FAIL (cite if referenced) |
| `ordered_rust_gates` | fmt / clippy / check: ________ |
| `full_suite` | no-fail-fast: ________ |
| `ci` | green / run ids: ________ |
| `convergence` | 10/10 non-stock `--expect-fixed` only: ________ |
| `build_sign_package_audit` | ________ |
| `signer` | human release owner: ________ |

Do not set `X0XD_LEGACY_BINARY` / authentic v0.30.1 as a modern predicate.
Do not silently skip `just convergence-release` without this filled receipt.
