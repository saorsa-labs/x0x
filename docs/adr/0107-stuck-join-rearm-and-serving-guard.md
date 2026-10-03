# ADR 0107: Stuck Join Re-arm and Current-Roster Serving Guard (0088 S8 (a))

- **Status:** Proposed
- **Date:** 2026-10-03
- **Decision owners:** David Irvine
- **Author:** Codex
- **Reviewers:** Claude (cross-model r1, r2); Codex (implementation review of #1190)
- **Supersedes:** none
- **Superseded by:** none
- **Related:** [#1150](https://github.com/saorsa-labs/x0x/issues/1150), [#1149](https://github.com/saorsa-labs/x0x/issues/1149), [PR #1148](https://github.com/saorsa-labs/x0x/pull/1148) (merged); ADR 0088 S8 (a), L3/G7 and L4 ([PR #1160](https://github.com/saorsa-labs/x0x/pull/1160), Proposed), D39, D54, D55; ADR 0106, ADR 0012, ADR 0016 §6–7, ADR 0085, ADR 0087 rule 8; [#818](https://github.com/saorsa-labs/x0x/issues/818). Serves **R3** (all my machines connected).

David's rulings (2026-10-03), quoted here because D54/D55 are not on `main`: D54 rejects “committed in-process red tests count as harness-first” and states that “D16's harness-first rule stands as written.” D55 grants a harness-first exception for **#1150 (a) only**: “It ships in v0.46.1 with its committed red test, and the W3-H harness case follows later.”

This ADR covers **only S8 (a)** of the Proposed ADR 0088 group liveness contract: a bounded v0.46.1 joiner re-arm plus the authority-side serving guard it needs for L4. Authority re-Welcome, S8 (b), is future work in a separate ADR filed **after S4 is Accepted**. This slice does not claim full L1/L2 recovery.

## Context

A Home TreeKEM join can time out after the authority seals the device's add but before the device installs its Welcome. The authority holds an Active seat; the device has no keys. A fresh invite does not repair this (#1150):

1. The authority's `MemberJoined` step 7 rejects an already-Active joiner as an idempotent replay (`src/server/routes/named_groups.rs:13397–13402`). It stages no new result or Welcome.
2. A fresh invite's base already contains the seat. `base_seats_joiner` (around line 18413) persists local `active` from that snapshot.
3. The original `MemberAdded`, carrying the Welcome, is now stale at the base's revision and is dropped. The joiner stays keyless.

There are two timeout shapes in `src/server/routes/named_groups.rs`:

- **Shape A (carry):** an intermediate state-only apply leaves a durable `not_member` row. This is exactly #1148's `UnseatedJoinRemnant` (classifier around lines 17714–17725): local lineage has no seated revision and the local roster has no joiner entry. The classifier cannot distinguish an add never sealed on the authority (#1148) from a sealed add whose result was missed (#1150). `clear_stale_not_member_join_row` (around line 17746, called around line 18207) currently clears either shape.
- **Shape B (no carry):** no intermediate apply occurred. The timeout finalizer removes the pending stub and row (around lines 34196–34210); there is no pre-seat row to retain or re-arm.

PR #1148 must keep clearing genuine unseated remnants for owner remove-member + re-invite recovery. ADR 0106's fresh-invite fallback alone is ineffective when the authority still seats the device. #1149 also shows why an invite's base-seated snapshot is not current admission: the authority can mint it, then ban or revoke the device before redemption. For non-TreeKEM joins, local roster presence can even confirm the poll without a current authority response.

Staged results (`state.pending_join_results`, keyed `group:member`, around lines 33103/33165) and Welcomes (`state.pending_welcomes`, around line 35815) currently survive removal, ban and certificate revocation. Neither the `FetchRequest` arm (around lines 34899–35090) nor `handle_welcome_fetch_request` (around line 36240) checks the current committed roster before serving. Re-arm without that guard would turn the #1149 carry case into keyed `active` after a ban or revocation.

## Decision Drivers

- Restore the stuck join without weakening signature, authority, chain, owner-certificate, revocation or fork checks (0088 L4).
- Bound the local retry and require current authority eligibility before serving the original artifacts.
- Report membership truthfully; a roster seat alone does not prove usable TreeKEM keys or current admission.
- Keep the v0.46.1 delivery and its test exception explicit (D55).

## Considered Options

1. **Carry-remnant re-arm plus current-roster serving guard** (chosen): bounded recovery without a new admission/rekey rule; broader recovery requires a separate ADR.
2. **Always clear the row and use a fresh invite's base.** Rejected when the base seats the joiner: it recreates the stale-event/keyless state and #1149's admission problem. #1148's clear remains correct outside the re-arm trigger.
3. **Re-add on every Active `MemberJoined`.** Rejected: ordinary replays would trigger rekeys, bypass the confirmation distinction and permit competing admins to seal siblings.

## Decision

### Joiner re-arm — v0.46.1, S8 (a) (D55)

**Trigger and discriminator:** when an invite is redeemed while an `UnseatedJoinRemnant` exists **and the verified invite base seats the joiner**, re-arm the retained pre-seat revision and verified chain prefix. Skip **both** `clear_stale_not_member_join_row` and the `base_seats_joiner` shortcut. The invite base supplies the discriminator; the local remnant classifier alone does not establish whether the authority sealed the add. Otherwise #1148's clear stands. Removed, banned, withdrawn or quarantined local state must not be reclassified as a retryable remnant.

Re-arm must still drop any leftover `treekem_groups` entry for the key, preserving that part of the skipped clear helper (around lines 17763–17767). A leftover entry must not satisfy the join poll's key-presence confirmation; confirmation requires installing the recovered Welcome in this bound attempt.

Register a new current, bound attempt and re-fetch the authority's **still-staged original join result**, including the device's own `MemberAdded` and Welcome. Apply through the ordinary bound path, including ADR 0106's intervening events where needed, then install the Welcome and confirm only when the keys are present. Reject stale attempts and keep all signature, authority, chain, owner-certificate, revocation and fork checks.

The joiner's TreeKEM identity is **re-derived deterministically** from its existing agent secret and group ID by `agent_treekem_seed` (around line 27040, ADR 0012). With that same identity, the original Welcome remains decryptable after a joiner restart. Nothing new is stored; **`PreparedMember` secrets must never be serialized**. Recovery after joiner restart still requires the durable carry remnant and the authority's original caches.

Step 7 remains unchanged: the re-armed attempt's ordinary `MemberJoined` volley is rejected as an already-Active replay (about 20 times over the 120 s poll). Those rejections are harmless and stage no new result; the redundant volley may be suppressed for this recovery path. Recovery depends on fetching the original artifacts. Commits **after** the original seal still require ordinary catch-up, including the #818 limitations; restoring the Welcome alone does not reach the current head.

### Authority-side serving guard — required in S8 (a)

In **both** the join-result `FetchRequest` arm and the Welcome serve path, serve only while the recipient is **Active, not banned, and its certificate is valid on the current committed roster** under the group's admission policy. Historical invite or seal evidence is insufficient. Check removal, certificate revocation/expiry and group withdrawal/quarantine at serving time. Keep the existing authenticated sender/member binding and Welcome group/recipient checks. Unknown or invalid current evidence fails closed.

For **`OwnerCertified` groups**, use the certificate **embedded in the current committed roster entry**, which `MemberJoined` binds into the `MemberAdded` commit (around line 13411), and verify it with `verify_cert_against_owner` against the policy owner, recipient, **current revocation set and current time**. A current **`MemberCertStatus::Clean`** roster verdict may supply this check, subject to the digest policy below. `DigestPending`, `InGrace` and failed verdicts fail closed. `InGrace` also covers stale evidence during certificate rotation, not just missing evidence. Grace alone does not permit serving. Do **not** use the announce/discovery cache (`owner_cert_evidence_for`) as the serving certificate source: #842 first joins can carry the certificate inline before any announcement arrives. Non-`OwnerCertified` groups skip the certificate check, retaining the other serving guards.

**Open question for David:** does a currently verifying roster-embedded certificate remain sufficient when its digest differs from the latest announced digest? #1190 currently accepts that certificate if the other serving checks pass. This differs from requiring a current `Clean` roster verdict, which can report stale rotation evidence as `InGrace`. David has not ruled on this policy choice.

The serving linearization point is the eligibility check and egress handoff under the group membership lock, atomic with respect to committed removal, ban and revocation. Artifact selection alone is insufficient. This applies to inline JoinResults, control-blob-copied JoinResults at both staging and chunk egress, Welcome frames and queued retries. Cancel unsent retries and copied payloads when eligibility is lost. Bytes already transmitted cannot be recalled.

Purge a departing admission's staged join results, Welcomes and copied payloads inside the committed removal or ban mutation's critical section. Apply this to API mutations, direct/gossip apply and replay. Revocation invalidation may be lazy only if every remaining egress path fails closed at its own eligibility check. Purge does not replace the serving guard: it also catches certificate expiry or invalidity since staging.

Dispatch fetch handling through bounded supervised tasks. The Welcome listener's receive and ACK processing must stay responsive while any group lock is held. No wire or persisted-format change and no new authority admission rule is introduced.

### Bounds, failure exit and merge gate

**Cache and inviter limits:** `PENDING_JOIN_RESULT_TTL` and `PENDING_WELCOME_TTL` are each 10 minutes from staging and in memory. Both original artifacts must remain on the original authority; retry does not restart their lifetime. The presented invite's **inviter must be the device that sealed the original add**: `validate_join_result_inviter` (around line 33107) requires both sender and `MemberAdded` actor to match the expected inviter from this invite. The original inviter is not persisted in the remnant; another admin's invite cannot establish that binding after restart. Cache expiry or an authority restart loses this route. Only the joiner restart is recoverable within these bounds, not authority restart or any-admin recovery under L1/L2.

**No-carry limit:** shape B is **out of scope** for this slice. The finalizer's stub/row deletion stays; there is nothing to re-arm. A fresh base-seated invite can still leave this device keyless. The TreeKEM poll remains 120 s, whereas the non-TreeKEM poll already runs the full `PENDING_JOIN_RESULT_TTL` (around lines 33058–33062). The shorter TreeKEM window and its typed timeout versus a later authority refusal must be named in ADR 0088 **G7**, whose decision on L3 remains open; this ADR does not settle G7 or extend the poll/stub lifetime.

**Failed re-arm:** use the existing typed `TimedOut` or `Refused` join-attempt outcome, expose the cause through the existing outcome/status surface, and do not confirm keyed membership. The REST reason `rearm_original_result_unavailable` aggregates failures to obtain the original recovery artifacts. It does not establish the authority's precise refusal cause. For an otherwise eligible device, the operator exit is **owner remove-member + re-invite**, including after missing caches, inviter mismatch or a no-carry timeout. This workaround does not override a ban or invalid/revoked certificate. L3/G7 must account for this bounded result and explicit exit rather than a silent pending state.

**Acceptance and merge:** ADR 0107 must first land **Proposed on `main`**, then be **Accepted by David before any S8 (a) code governed here merges**, including re-arm and the serving guard (ADR 0088 §4 and ADR 0087 rule 8). The contract's acceptance order still applies. D55 waives **only harness-first**: v0.46.1 requires a committed in-process red test, failing before the fix and green after it; W3-H follows. In-process tests do not otherwise meet D54. D55 waives neither slice acceptance nor safety review. One ADR has one status; acceptance freezes all of 0107, so it cannot also carry a still-deferred S8 (b) decision.

## Future work — separate S8 (b) ADR

Authority re-Welcome after staging loss, and general base-seated/unconfirmed-membership repair for #1149, are deferred to a follow-up ADR **filed after S4 is Accepted**. Constraints for that proposal:

- Use S4's Accepted designated-first committer, bound and handoff rules under the membership lock; prevent competing admins from sealing siblings. Do not change step 7 here.
- Define authenticated confirmation, not local roster presence or a joiner's assertion of lost keys; confirmed Active replays stay no-ops and a legacy absent flag proves no confirmation.
- Re-check current membership, certificate validity/revocation and containment before serving or re-adding; a stale invite or unconfirmed flag cannot restore a revoked or banned identity.
- Specify any persisted unconfirmed state under ADR 0085 (new magic for changed positional layouts, frozen released decoder, lazy rewrite, released fixtures and downgrade behaviour), any new wire contract under ADR 0093, and harness-first reproduction plus separate acceptance before code merges.

## Consequences

### Positive

- A carry-remnant retry within the staging window can install the original Welcome without a new membership commit.
- Current-roster serving guards prevent the retry from granting keys after removal, ban or certificate revocation.

### Negative / Trade-offs

- v0.46.1 still depends on the original sealer/inviter and its volatile caches. Shape B, staging loss and post-seal catch-up remain limitations; #1150 is not fully closed.
- The guard closes the #1149 carry re-arm key-release hazard. General stale-base admission reporting, including non-TreeKEM local confirmation, still needs the separate follow-up ADR.

### Neutral / Operational

- Release notes must state the cache/inviter, no-carry and catch-up limits, typed failure and owner remove-member + re-invite exit. Accepted ADR 0106 stays immutable; this ADR records the bounded correction to its fallback.

## Validation

- **Shape A, new committed red/green:** seal an add on a real in-process authority; deliver only the carry so the durable `UnseatedJoinRemnant` survives timeout; keep the **original** `pending_join_results` and `pending_welcomes`; redeem a fresh invite from the original sealer whose base seats the joiner. Assert a new bound attempt, unchanged pre-seat prefix, both clear and base-seat shortcut skipped, usable TreeKEM keys and confirmed membership. Seed a leftover `treekem_groups` entry and prove re-arm drops it and cannot confirm before installing the recovered Welcome. Disabling re-arm reproduces the keyless failure. Cover joiner restart with the same agent identity, deterministic Welcome decryption and no serialized `PreparedMember` secrets.
- **Existing #1150 characterization:** `d39_1150_fresh_invite_alone_leaves_keyless_device_keyless` in `src/server/routes/named_groups/tests/issue1139_back_to_back_join.rs` **cannot flip as written**: its round-trip helper clears `pending_join_results` around line 1117. Keep its cache-loss limitation coverage and add the new cache-preserving red test above; do not manufacture a pass by staging a new add.
- **Shape B, separate limitation control:** use `d39_timed_out_without_carry` to prove timeout removes the stub and row. Assert this slice does not re-arm absent state or claim key recovery; preserve the known fresh-invite limitation and verify owner remove-member + re-invite restores eligible membership with keys. Do not combine this with the carry test.
- **#1148 compatibility:** keep `d39_a_not_member_owner_removes_delivered_then_fresh_invite_recovers_keys` and `d39_a_not_member_owner_removes_undelivered_then_fresh_invite_recovers_keys` green. A fresh base that does not seat the joiner still clears the remnant and starts the normal join; removal, ban, withdrawal and quarantine are never cleared as remnants.
- **#1149 + carry, must not gain keys:** `d39_r2_recovered_remnant_takes_the_same_seated_invite_path` **flips in S8 (a)** from snapshot-only `active` to re-arm followed by a non-active `Refused` or typed `TimedOut` outcome. Extend it with original caches intact, an invite minted before the ban, and separate post-seal ban/removal/certificate-revocation cases. Exercise **both** serving paths, including cached copies and Welcome transfer cancellation; no result/Welcome may be served to the ineligible member and the joiner must **never end keyed-active**. Exercise certificate expiry/invalidity too. Only the remnant variant flips in this slice; keep `d39_r2_preexisting_seated_invite_without_row_reports_active` unchanged as the separate no-row reporting limitation, not evidence that re-arm safely recovers keys.
- **Independent serving guards:** prove each guard with the independent join-result, Welcome and control-blob caches intact. Cache absence or another path's purge must not explain refusal. Copy a JoinResult into a control blob before removal; refuse subsequent staging and chunk egress. Cover unsent Welcome frames, copied payloads and queued retries after removal, ban and revocation, including lazy revocation invalidation.
- **Deterministic check-to-egress race:** use barriers to race removal, ban and revocation commits against each serving path. Prove the eligibility check and handoff are atomic for inline results, blob staging, blob chunks, Welcome frames and retries. A commit that wins blocks egress. A handoff that wins may already have transmitted bytes; cancellation must stop the remaining unsent work.
- **Purge and listener progress:** verify purge inside the committed mutation's critical section for API removal/ban, direct/gossip apply and replay. Hold a group lock and prove the Welcome listener still receives frames and processes ACKs. Prove fetch tasks are bounded and supervised.
- **Serving non-regressions:** ordinary eligible first joins still receive their staged results and key material for **both TreeKEM and GSS**, including #842 inline-certificate joins with announce/discovery evidence absent. The **#1139 / ADR 0106 intervening-events carry** still serves and applies the intervening events before the joiner's own event. Exercise both serving paths where applicable. Prove `OwnerCertified` serving uses the roster-embedded certificate with current revocation/time inputs (or a current `Clean` roster verdict), refuses `DigestPending`/`InGrace` and failed evidence, and allows non-`OwnerCertified` groups without a certificate.
- **Digest policy distinction:** characterize #1190's acceptance of a currently verifying embedded certificate despite an announced-digest mismatch. Separately prove `InGrace` fails closed for missing and stale rotation evidence. Final expected behavior for the mismatch case follows David's ruling on the Open question.
- **Bounds and concurrency:** expire either staged artifact and restart the authority separately; neither may claim recovery or confirmation. An invite from a different admin fails the inviter binding. Retry does not extend either TTL. Cover stale-attempt rejection, eligibility changes racing with serving, harmless/suppressed step-7 volleys with no new commit, and post-seal commits still needing ordinary catch-up. Failed re-arm exposes `TimedOut`/`Refused` with its cause and the eligible-device workaround; document the 120 s/10-minute G7 gap.
- **REST failure reason:** assert `rearm_original_result_unavailable` when original recovery artifacts cannot be obtained. Cover cache loss, inviter mismatch and ineligibility separately. The aggregated reason must not claim a precise authority refusal cause.
- **Governance and harness:** 0107 stays Proposed until David accepts it on `main`, before the re-arm/guard code merges. Add the equivalent W3-H carry and safety cases after S8 (a), per D55; S8 (b) validation belongs to its later ADR, under D54.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human review**. Only David Irvine marks it Accepted. Accepted ADRs are immutable: create a new superseding ADR rather than editing an Accepted ADR.
