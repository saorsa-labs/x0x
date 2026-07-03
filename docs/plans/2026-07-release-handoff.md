# Handoff: x0x production release (post-v0.27 hardening + security foundations)

**Date:** 2026-07-03. **Author:** release-orchestration session (Claude), handing off to the dev team.
**Goal:** a tagged, soak-verified production release with two security foundations in place — key expiry/revocation (#130) and a default-deny connection ACL (#131) — so the machine-to-machine connectivity sprint (tailnet, #132) starts on solid ground. #132 itself is explicitly OUT of this release.

**Definition of done**
1. `src/server/mod.rs` decomposition (#125) complete: `mod.rs` < ~2,000 lines, `x0x routes` snapshot byte-identical at every step.
2. Sweep issues closed: #139, #142, #145, #153 (and #149/#127 — already done).
3. #130 and #131 merged, each after an INDEPENDENT security review confirming the properties in the real code path (not just tests): default-deny, fail-closed, no-breaking-change for old keys.
4. Release tagged via the normal release train (which is CI-gated since #138); fleet soak with the existing harnesses shows no regression vs the v0.27.x baseline; focused review of the whole diff since v0.27; readiness summary written.

---

## 1. Already merged to main (verified; main CI green at `3fba957`)

| Change | Commit/PR | Verification done |
|---|---|---|
| auth.rs extraction + token hygiene (#127/WS1.6: constant-time compare, session-token-only `?token=`) | #151, #155 | code-read in src/server/auth.rs; #127 closed with evidence |
| state.rs extraction | #156 | diff read (pure move), snapshot guard, CI |
| ws.rs + sse.rs extraction (mod.rs 25,217 → 23,883) | `efe775a` — **landed as an accidental direct push, not a PR** (see §5 process notes); post-hoc verified | independent line-level diff audit (pure move; snapshots byte-identical); main CI green; deviation documented on #125 |
| WS stalled-reader harness (#149) + real fix: Close(1013) now reaches the wire (cleanup granted the writer a 3s close-flush grace instead of immediate abort) | #157 | diff read; strict `assert_eq!(close_code, Some(1013))` e2e; negative sanity check against a healthy client |

## 2. In-flight work — exact recovery state

### 2a. Routes extraction, first group — worktree ALIVE, work UNCOMMITTED
- Worktree: `.claude/worktrees/agent-a0663e5c3e7f564e3` on branch `eng-a/125-ws1.4-routes-1` (based on `efe775a`; rebase onto current main is trivial — #157 only touched ws.rs).
- Staged there: new `src/server/routes/{mod,contacts,identity,machines}.rs` + matching `mod.rs` shrink. It was mid-validation (full nextest) when stopped.
- To finish: run the full gate (`cargo fmt --all -- --check && cargo clippy --all-targets --all-features -- -D warnings && cargo nextest run --all-features --workspace`), confirm `tests/snapshots/server-routes.*` untouched and the enforcing tests (`route_set_matches_registry`, `manifest_matches_registry`) pass, commit `refactor(125/WS1.4): extract routes/ (contacts, identity, machines) (#125)`, push **with explicit refspec** (see §5), PR, merge on green.
- Then repeat for the remaining registry categories (enumerate: `grep 'category:' src/api/mod.rs | sort -u`) at 2–3 categories per PR — largest families (groups/named-groups, tasks, kv, exec, upgrade, diagnostics, presence…) until `mod.rs` < ~2,000 lines. Constraints per PR: mechanical move only; colocated `#[cfg(test)]` moves with handlers; `pub(super)` visibility; snapshots never regenerated.

### 2b. #139 timing-brittle e2e — worktree ALIVE, work UNCOMMITTED
- Worktree: `.claude/worktrees/agent-a75dd846e9c1c0157` on branch `test/139-convergence-timeout-budget` (based on `6b7ac7b`; rebase needed).
- Uncommitted change in `tests/named_group_join_metadata_event.rs` (inspect `git -C <worktree> diff` — the timeout/budget change lives in that file's shared convergence helpers).
- Intent (from issue #139, do not weaken semantics): derive the convergence wait budget from node count with a generous multiplier (target: a legitimate 130–160s 3-daemon convergence passes; keep per-poll cadence relaxed). Do NOT remove the test from CI.
- Verify: run the target test twice on a quiet machine (`--run-ignored=all` if ignored), full gate, PR.

### 2c. #145/#142 announce-loop self-contact — WORK LOST, FULL SPEC PRESERVED
- The implementing worktree was cleaned before push (local branch `fix/145-announce-self-contact` exists but points at plain main — delete it or reset it). The complete consumer audit (7 consumers, all does-not-depend) **and the exact fix + test spec are preserved as a comment on issue #145** (2026-07-03). Reimplementation is ~30 min from that spec. It was once validated at 1947/1956 nextest with only pre-existing unrelated failures.
- Closing #145 with that fix also closes #142 (rationale in the issue comment).

### 2d. #130 / #131 implementations — NOT STARTED (stopped at spawn), PLANS COMPLETE
See §4.

## 3. Remaining Phase-1 items (do before #130/#131 merge)

- **#153 — task-list REST handlers must enforce group membership** (security-relevant, feeds symphony XSY-0021 isolation): handlers at the task-lists routes (currently `src/server/mod.rs` ~2275, will move into `routes/tasks.rs`) must (1) recognize group-scoped IDs `x0x.group.<group_id>.symphony.<list_id>`, (2) consult named-group/MLS membership for the requesting agent, (3) return 403 for non-members on read AND write. Schedule after the tasks routes are extracted to avoid churn. Un-`#[ignore]` the XSY-0021 two-daemon isolation test as the acceptance proof. Treat as security-relevant: independent review that non-membership ⇒ deny in the real handler path.
- **Pre-existing local flakes** observed repeatedly during this session (fail on loaded machines, pass on quiet/CI): `named_group_join_metadata_event` family, `peer_lifecycle_integration::direct_send_without_require_ack_omits_ack_block`. #139's fix addresses the first family. Don't paper over new failures by attributing to these without reproducing them on unmodified main first.

## 4. Phase 2 — the two security foundations

Complete, code-grounded implementation plans (file/line-referenced, stepwise with per-step acceptance criteria and [SEC] flags) are in this directory:
- **`2026-07-issue-130-key-lifecycle-plan.md`** → ADR-0018. Key points: expiry only network-enforced on AgentCertificate (`not_after`, signature-covered, v1-byte-identical message when absent so old certs verify forever); magic-prefixed v2 key-file container with legacy-format writes when no expiry (downgrade-safe); grow-only revocation set (self-revocation + issuer-revocation only; no un-revoke ⇒ no replay class); gossip topic `x0x.revocation.v1` + heartbeat rebroadcast for partition tolerance; five enforcement points with revocation beating `bypass_verified` while plain-unverified does NOT regress the #99 MemberRemoved paths; `POST /identity/renew` with zero downtime (cert re-issue + re-announce; machine/agent keys untouched); 300s clock skew via one shared helper.
- **`2026-07-issue-131-connect-acl-plan.md`** → ADR-0019. Key points: v1 = fail-closed policy engine + `connect-acl.toml` + `--connect-acl` flag + `--check`/startup validation + `/diagnostics/connect` + pure `evaluate_connect_gate()` — the tailnet forwarder (T4) becomes its first caller; the plan explains why there is genuinely no runtime flow to gate yet. LoadMode REUSED from exec (compile-time semantic lock: missing-at-default=disabled, missing-at-explicit=hard error, malformed=hard error); `deny_unknown_fields` (APPROVED divergence from exec — file the exec retrofit follow-up issue); loopback-only numeric-IP targets (localhost/hostnames rejected, v4-mapped rejected, port 0 rejected — all load-time errors); gate order = information-leak property (unverified > trust > disabled > pair > target); full #141-mirror test matrices + property tests (accept iff loopback ∧ port≠0).

**Merge protocol for both (non-negotiable):** green CI is necessary but not sufficient. An independent reviewer (not the implementer) must read the enforcing code and confirm on the real code path: every ambiguous ACL case denies; expiry absence is valid but presence is enforced; revocation is fail-closed everywhere including the group-metadata gate; old key files/certs load and verify unchanged. Verify subagent/team claims against the actual diff — this session caught one agent-reported "done" that was not (and past sessions caught outright fabrication).

## 5. Process notes / incidents from this session (read before starting)

1. **Push discipline.** One agent's `git push -u origin <branch>` silently fast-forwarded **origin/main** because the worktree had `push.default=upstream` with upstream = origin/main. Rule: `git config push.default simple` in every fresh worktree, and push with an explicit refspec (`git push origin HEAD:refs/heads/<branch>`). The incident commit was fully verified post-hoc (see #125 comment); main was deliberately not rewound.
2. **Disk.** Four parallel cargo builds + 78 GB of stale incremental debris filled the disk to 0 bytes and wedged every process. Keep ≤2–3 concurrent full builds; prune `target/` debris periodically (sibling projects' targets were ~220 GB before cleanup).
3. **Worktree work loss.** A completed agent worktree was auto-cleaned with uncommitted changes (the #145 fix). Rule: commit early on the branch and push before long validation runs.
4. **Unrelated open PRs** #152/#159 (symphony GUI, other workstream) and #88 (design doc): not part of this release; don't let the release tag wait on them.

## 6. Phase 3 — certification

1. **Pre-tag:** all of §2–§4 merged; `just check` green locally; main CI + Integration & Soak workflow green; CHANGELOG updated; version bump per the release skill (`gsd-commit-and-release` flow — note version_sync in SKILL.md and that the release train is CI-gated, #138/#128).
2. **Tag + release:** minor bump (new features: identity lifecycle, connect ACL) → v0.28.0. crates.io publish + GH release per the existing release workflow; fleet self-upgrades (watch it).
3. **Soak:** use the existing harnesses — `tests/launch_readiness.py` SLO gates (GO/NO-GO windows), `tests/e2e_deploy.sh` fleet deploy, 6h minimum soak on the isolated test plane (ports 13600/6483 — NEVER the prod plane), comparing against the v0.27.x baseline metrics (peer counts 12–15, drop_full=0 windows, per-peer timeout ceilings per `docs/plans/2026-07-production-hardening-and-tailnet.md` §review protocol). New for this release: confirm revocation propagation and renew-no-downtime on two fleet nodes, and `x0xd --check` with a valid + invalid connect ACL on one node.
4. **Focused review:** full diff `git log v0.27.0..HEAD` — one reviewer per area (server decomposition = snapshot/manifest guarantees; identity/revocation = security properties; connect = matrices; ws = 1013 semantics), then a readiness summary: what changed, what was verified, explicit confirmation that #130 + #131 properties hold, known residual risks (pre-existing flakes, the QUIC-connection-linger limitation noted in ADR-0018).

## 7. Suggested sequencing (dependency-safe)

```
[A] routes-1 PR (recover worktree)          [B] #139 PR (recover worktree)   [C] #145/#142 reimplement (30 min)
        ↓ merge                                       ↓ merge                          ↓ merge
[A2..A4] remaining routes PRs (serial) ──────────────────────────────────────────────────
        ↓ (tasks routes landed)
[D] #153 membership enforcement (independent review)
                                        [E] #130 per plan (parallel with A2+, rebase late)   [F] #131 per plan (parallel, rebase late)
        ↓ all merged, independent security reviews done
[G] tag v0.28.0 → fleet soak → focused review → readiness report
```
A/B/C/E/F can start immediately in parallel (≤3 concurrent builds); D waits for the tasks-routes extraction; G waits for everything.
