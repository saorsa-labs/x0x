## Scope restriction (stated up front)

ADR-0064 **slice 1 only** (Guard A): the persistent fork-quarantine marker is **set and gated ONLY for owner-axis groups** (OwnerCertified / Home — those that already go through `seal_commit_owner_certified` and the verified owner head attestation). For **non-owner-axis groups behaviour is byte-for-byte unchanged** — proven by `adr0064_non_owner_axis_conflict_never_sets_marker` (evidence still records per ADR-0059; the marker never appears, counters stay zero).

Explicitly out of scope (per David's decision boundary and the blueprint's slicing):
- **No `OwnerMandate` type** — that is slice 2.
- **No manual unquarantine REST/CLI surface.**
- Clear rule is exactly: owner-axis only, via the **existing verified head attestation on adoption** or a **local owner-certified seal**; contested-branch higher commits must NOT clear (negative-control test included).
- No new enum variants on any wire/persisted enum (#451 mixed-fleet hazard); only `#[serde(default)]` struct fields. Old v0.41.4 binaries ignore the field (a rewrite by an old binary drops it — downgrade loses containment, never bricks).

## What landed

- `ForkQuarantine { revision, state_hash, committed_by, observed_at_ms, snapshot, no_anchor }` + `ForkSnapshot { terminal_commit, conflicting_commit }` (header-only — redaction by construction, no TreeKEM/shared-secret material can enter) as `#[serde(default, skip_serializing_if)]` fields on `GroupInfo`; the field participates in the #470 full-record equality used by the compare-and-restore rollback. `GroupInfo::is_fork_quarantined()` + `terminal_commit_header()`.
- Marker set **only** from evidence that passes `evaluate_fork_evidence_candidate`'s admin+signature checks, **inside the existing `persist_named_groups_mutation` compare-and-restore path** (same first-complete-wins mutation as the evidence record — never a separate file). Covers the live apply path, the listener-restart admission path, and journal recovery.
- `reject_fork_quarantined()` wired into the six membership-gated routes — `send_group_public_message`, `treekem_group_encrypt`, `treekem_group_decrypt`, `secure_group_encrypt`, `secure_group_decrypt`, `secure_group_reseal` — refusing with typed **409 `fork_quarantined`**. Inbound metadata events are deliberately NOT gated (the anchored clearing commit must still arrive; queue admission untouched per #492).
- Bootstrap strip (`signed_public_bootstrap_snapshot`) / reject (`validate_public_group_bootstrap`), exactly like `invite_lineage`; `/groups/:id` JSON exposes the marker; diagnostics counters `fork_quarantine_set` / `fork_quarantine_refusals` added to `GroupCounters` and the snapshot merge.
- Docs: one section in `docs/trust-and-connectivity.md` (marker, 409 error, owner-axis-only scope, non-owner-axis out of scope pending ADR follow-up). No Accepted ADR body edited.

## Fault-matrix rows covered (with test names)

| Fault-matrix row | Test |
|---|---|
| Stale removal, owner-axis arm | `hs_f2_membership_cluster::adr0064_owner_axis_stale_removal_sets_quarantine_and_gates_routes` (marker + snapshot asserted, 409 on secure encrypt, seal clears) |
| Restart mid-quarantine | `hs_f2_membership_cluster::adr0064_restart_preserves_marker_and_gate_still_refuses` (persist → `load_named_groups_merged` → marker verbatim → 409 on `secure_group_encrypt`) |
| Partition / per-node scope | `fork_quarantine::adr0064_bootstrap_snapshot_strips_and_rejects_marker` (strip outbound, reject inbound, clean control validates) |
| Equal-revision fork negative control | `fork_quarantine::adr0064_equal_revision_contested_commit_cannot_clear` (contested-branch N+3 refused, marker stays; a self-chaining canonical apply also does NOT clear) |
| Crash between journal writes (forced persist failure) | `fork_quarantine::adr0064_forced_persist_failure_leaves_marker_retryable` (`SaveFault::Error` via the #470 cell → marker rolled back, nothing counted → retry installs durably) |
| Non-owner-axis untouched | `fork_quarantine::adr0064_non_owner_axis_conflict_never_sets_marker` |
| No false quarantine (unauthenticated evidence) | `fork_quarantine::adr0064_unauthenticated_conflict_never_sets_marker` (`conflict_unauthenticated` fires instead) |
| Gate parity with the ADR-0038 reverify gate | `adr0038_owner_certified::fork_quarantine_gate_parity_with_reverify_gate` (same 409 shape; one seal clears both containment kinds) |

All tests use in-process `secure_endpoint_test_state`/`owner_authority_state` fixtures — no live x0xd, no production-network harness.

## Gates (exact commands + exit codes, on the pushed tree `5777d41`)

| Command | Exit |
|---|---|
| `cargo fmt --all` | 0 |
| `cargo clippy --all-features --all-targets -- -D warnings` | 0 (zero warnings) |
| `cargo check --workspace --all-targets` | 0 (zero errors) |
| `cargo nextest run --all-features -E 'test(hs_f2) \| test(quarantine) \| test(adr0038) \| test(named_group_d4) \| test(state_commit)'` | 0 — **125/125 passed** |
| `scripts/check-panics.sh` | 0 (no unwrap/expect/panic/todo in production code) |

**Does not close #468/#469/#472** — slices 2–5 (OwnerMandate, capability/grace enforcement, alternate-chain ancestor walk, runbook) remain.

---

## Round 2 (REQUEST-CHANGES applied — all five items)

**1. Merge regression fixed** — the round-1 hunk had dropped `dst.causal_applied = …` from `merge_counters` (present on origin/main). Restored, and `merge_counters` is now module-scoped with `groups::diagnostics::tests::merge_counters_sums_every_field` driving **every** merged field with distinct non-zero values on both sides and asserting each per-field sum — a future dropped (or doubled) line fails that test.

**2. Clear rule reworked (maintainer decision — ADR-0064 §3, owner anchor = owner key).** The round-1 clear fired from the shared `seal_commit_owner_certified` wrapper used by ~22 routine mutation sites, on an agent-key seal with only an ADR-0038 verdict, with no revision check. Now:
- The shared wrapper **never clears** (`seal_commit_with_owner_certs` only lifts the ADR-0038 restore flag, as before round 1).
- A local seal counts as an owner anchor ONLY via the **explicit seal route** (`POST /groups/:id/state/seal` → `owner_certified_seal_with_eviction` → new `GroupInfo::clear_fork_quarantine_on_explicit_owner_seal`), and only when ALL hold: (i) sealed revision **strictly greater** than `marker.revision`; (ii) the local install **holds the owner USER key**, fenced exactly like #469 A1b (`owner_key_unavailable`: key loaded AND derived user id == policy owner — an agent-key seal with only a certificate verdict is not an anchor); (iii) owner-axis group (unchanged).
- The tier-1 adoption clear now also requires the terminal revision to be **strictly greater** than the evidenced revision.
- No new gates on routine mutations (they leave the marker in place, as required).

**3. Tests** — new/changed, all failing on the round-1 tree by construction:
- (a) `fork_quarantine::adr0064_routine_rename_mutation_does_not_clear` — drives the REAL rename route (`update_named_group`) on a quarantined owner-axis group: 200, marker stays.
- (b) `fork_quarantine::adr0064_explicit_seal_at_evidence_revision_does_not_clear` — authenticated evidence at revision 3 above our head (rev 2); explicit seal lands at 3 == evidence → refuses; the next seal (4 > 3) clears.
- (c) `fork_quarantine::adr0064_explicit_seal_without_owner_user_key_does_not_clear` — keyless-owner admin fixture (no local user key; roster certified by an owner key held elsewhere): explicit seal succeeds at revision 3 > evidence 2 and still must not clear.
- (d) positive explicit-seal clear — `fork_quarantine::adr0064_equal_revision_contested_commit_cannot_clear` (reworked) and the renamed hs_f2 test below.
- (e) `hs_f2…::adr0064_adoption_clear_requires_strictly_greater_revision` — r3-stage joiner stub (sealed base commit; a bare invite stub cannot hold evidence) seats the marker: positive arm clears on the attestation-anchored adoption, negative arm at revision == terminal seats the joiner but does NOT clear.
- (f) honesty rename: `hs_f2…::adr0064_owner_axis_stale_removal_sets_quarantine_and_gates_routes` → `…_twin_conflict_quarantines_gates_and_owner_seal_clears`, with the doc comment stating it is two equal-revision twins sealed by the same local key (StaleRevision), **not** the full #468 stale-removal shape — that shape is only partially covered here via (e) + (a)/(b).
- (g) the tautological contested-apply arm (PrevHashMismatch never reached the clear path) is replaced by arms that REACH the clear rule and are refused by the strictly-greater / owner-key checks, per (a)+(b).

**4. Docs** — `docs/trust-and-connectivity.md` now states that for owner-axis groups the authoritative record is the `home-suite-groups.json` sidecar (`named_groups.json` holds the legacy placeholder, which also carries the marker), and describes the clear rule exactly as implemented (explicit seal route + owner user key + strictly greater revision, or tier-1 attestation-verified adoption with strictly greater revision).

**5. Residual recorded (not fixed in this slice, per review):** clears never reset `invite_lineage.fork_evidence`, so `evaluate_fork_evidence_candidate` silences later forks on that node after the first clear — containment is **one-shot per group per node** until the slice-4 clear-rule work resets the evidence gate on clear.

### Round 2 gates (exact commands + exit codes)

| Command | Exit |
|---|---|
| `cargo fmt --all` | 0 |
| `cargo clippy --all-features --all-targets -- -D warnings` | 0 (zero warnings) |
| `cargo check --workspace --all-targets` | 0 (zero errors) |
| `cargo nextest run --all-features -E 'test(hs_f2) \| test(quarantine) \| test(adr0038) \| test(named_group_d4) \| test(state_commit)'` | 0 — **129/129 passed** |
| `scripts/check-panics.sh` | 0 |

**Does not close #468/#469/#472** (unchanged).
