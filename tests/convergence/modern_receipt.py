"""Lightweight modern-only receipt helper stub (ADR-014).

Filled 10/10 receipt instances are Tester-owned and blocked until the modern
freeze tip includes RejectV1 (#546). This module only exposes field names and
a skeleton builder — it does NOT claim PASS or invent a 10/10 run.

RejectV1 diagnostics assert: TODO until #546 lands (do not wire fake policy).
"""

from __future__ import annotations

# ADR-014 named receipt fields (must stay aligned with the #545 template).
RECEIPT_FIELDS = (
    "adr",
    "named_modern_version",
    "deps",
    "outer_signature_policy",
    "legacy_grants",
    "stock_v0_30_1_phases",
    "failed_compat_evidence",
    "ordered_rust_gates",
    "full_suite",
    "ci",
    "convergence",
    "build_sign_package_audit",
    "signer",
)

NOT_IN_MODERN_PREDICATE = "not_in_modern_predicate"
REJECT_V1_TODO = "TODO until #546 (RejectV1 product tip)"


def skeleton_receipt(*, tip_sha: str = "UNSET", adr_status: str = "Accepted"):
    """Return an unfilled receipt dict — never a PASS claim."""
    return {
        "adr": f"ADR-014 ({adr_status})",
        "named_modern_version": tip_sha,
        "deps": "UNSET",
        "outer_signature_policy": REJECT_V1_TODO,
        "legacy_grants": "disabled",
        "stock_v0_30_1_phases": NOT_IN_MODERN_PREDICATE,
        "failed_compat_evidence": (
            "cite #517 and run 34058040463 as FAIL (do not relabel PASS)"),
        "ordered_rust_gates": "UNSET",
        "full_suite": "UNSET",
        "ci": "UNSET",
        "convergence": "UNSET — no fake 10/10; run just convergence-release-modern",
        "build_sign_package_audit": "UNSET",
        "signer": "UNSET",
    }


def assert_stock_phases_not_pass(receipt: dict) -> None:
    """Hermetic guard: stock phases must never be labeled PASS."""
    val = receipt.get("stock_v0_30_1_phases")
    if val == "pass" or val == "PASS":
        raise AssertionError(
            "stock_v0_30_1_phases must be not_in_modern_predicate, not PASS")
    if val != NOT_IN_MODERN_PREDICATE:
        raise AssertionError(
            f"stock_v0_30_1_phases expected {NOT_IN_MODERN_PREDICATE!r}, "
            f"got {val!r}")
