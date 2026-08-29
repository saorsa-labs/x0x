# ADR-0019 mechanics — connect ACL considered options and test inventory

> Extracted 2026-08-29 from the immutable [ADR 0019](../adr/0019-connect-acl-default-closed.md) per the
> 2026-08-23 ADR audit. The ADR remains the complete decision record; the
> sections below are the considered-options rationale and validation inventory
> relocated verbatim so this file is their maintained home — future updates
> belong here, not in the ADR.

## Considered Options

1. **Mirror exec ACL exactly — loopback-only, exact targets, fail-closed load** ← chosen.
2. **Allow LAN/subnet targets from day one.** Rejected: firewall bypass risk, more complex matcher, no v1 need.
3. **Accept `localhost` hostname.** Rejected: DNS rebinding; numeric-only removes the resolver from the TCB entirely.
4. **Port ranges (`127.0.0.1:8000-8100`).** Rejected: fencepost/overlap ambiguity, no v1 need, breaks backward-compatibility if the syntax changes later.
5. **Single unified ACL file with exec.** Considered but deferred: the exec and connect grant surfaces are orthogonal; merging would complicate the `deny_unknown_fields` enforcement and the separate `--exec-acl` / `--connect-acl` override flags. Left for a future config unification ADR.

---

## Validation

- **Unit tests (matrix A–C):** load/parse matrix (enabled, disabled, malformed, missing), target validation matrix (loopback accept/reject, port 0, hostname, v4-mapped, leading zeros), gate-order matrix.
- **Integration tests (matrix D):** `tests/connect_acl_unit.rs` — TOML string round-trips through `parse_connect_policy`.
- **Property tests (matrix E):** `tests/connect_acl_proptest.rs` — four proptest properties, machine-checked.
- **`--check` end-to-end:** `x0xd --check --connect-acl <valid>` exits 0 and prints summary; `x0xd --check --connect-acl <malformed>` and `<non-loopback>` exit non-zero.
- **API coverage test:** `tests/api_coverage.rs` requires `/diagnostics/connect` in ENDPOINTS and `daemon_api_diagnostics_connect` as a coverage marker.
