# ADR 0110: Revocation Eviction, Designated First

- **Status:** Proposed
- **Date:** 2026-10-04
- **Decision owners:** David Irvine
- **Author:** Codex (GPT-6)
- **Reviewers:** Claude (cross-model r1, r2)
- **Amends:** [ADR 0016](./0016-role-based-group-authority-flat-admin.md) §6, upon acceptance: designated-first rekey for revocation, certificate expiry and self-leave. ADR 0016 Decisions 1 and 2 and [ADR 0064](./0064-owner-anchored-fork-authority.md) Decision 2, upon acceptance: two named signer exceptions, for the self-rebind (D129) and the owner recovery commit (D126) only, approved by D146 (§4). [ADR 0088](./0088-group-liveness-contract.md) §2, upon acceptance: three named entries, for legacy members across a new S4 commit (D76, confirmed by D118, extended by D153), for an ordinary group whose admins are all revoked (D126), and for an `OwnerCertified` group waiting for its owner (D152) (§6). [ADR 0085](./0085-persisted-binary-formats-are-versioned.md) rule 4, upon acceptance and for S4's own `.evs` and `.evjournal` files only: a damaged file is quarantined and rebuilt by ADR 0108 §5a (D120, §5). Rule 5 is not amended.
- **Supersedes:** [ADR 0038](./0038-home-owner-certified-personal-space.md) in part, upon acceptance: its "evict at next seal" revocation path becomes bounded eviction.
- **Superseded by:** none
- **Goal served:** R3 (all my machines connected) and the shared-places core.
- **Related:** [#1113](https://github.com/saorsa-labs/x0x/issues/1113), [#1164](https://github.com/saorsa-labs/x0x/issues/1164); D16, D34(2), D40, D54, D58, D60, D63, D64, D65, D69–D76, D117, D118, D120, D122, D126–D129, D135; ADR 0014, 0038, 0064, 0085, 0087, 0089, 0093, 0094, 0106, 0107, 0108, 0113.

Slice S4 of [ADR 0088](./0088-group-liveness-contract.md).
Verified agent revocation, signed self-leave and certificate expiry (D71) create durable cryptographic-exclusion work.
The lowest eligible roster admin acts first (D74); others hand off the evidence and wait before staggered fallback.
This proposal preserves removal authority and adds a capability-gated crypto-only transition for an already-Removed seat.
It defines `certificate_rebind_v1`, which keeps a renewed seat without eviction (D129), and the exits when no eligible admin remains (D126).
W, the completion bound, Δ and the restart sync wait come from W3-H harness p99.9 measurements (D69, D73).

## Context

Code citations refer to baseline `8b35dd1f447774e1a952166f32910fc41b512623`.
ADR 0038 relies on a later seal to evict a revoked Home member.
The verdict marks a positively revoked active seat `Failed` before certificate-grace handling (`src/groups/mod.rs:1543–1551`).
The explicit seal route calls the eviction engine (`src/server/routes/named_groups.rs:21785–21789`).
That engine removes a TreeKEM leaf, seals the roster and persists both states (`21548–21595`), or rotates GSS and builds survivor envelopes (`21633–21682`).
It returns `None` for non-OwnerCertified groups (`21285–21296`); ordinary groups must reuse the admin-removal path (`20979–21041`).
Revocation intake does not schedule either path: v1 verifies records, saves best-effort asynchronously and evicts discovery entries (`src/lib.rs:9676–9773`, especially `9700–9725`).

[#1113](https://github.com/saorsa-labs/x0x/issues/1113), assigned to S4 by 0088, is the roster-only self-leave gap.
Local leave emits no TreeKEM removal or epoch (`src/server/routes/named_groups.rs:20873–20885`).
Receivers allow that self-leave, but reject a self-authored TreeKEM payload (`12036–12049`); they install crypto removal only when its payload exists (`12139–12165`).
A target that self-left before being revoked can therefore be Removed in the roster and still hold a leaf.
S4 closes both triggers; roster exclusion alone is never proof of cryptographic exclusion.
An indefinite wait breaks **L1/L2**; **L4** forbids unsigned or unchained repair.
D64 makes **L3** a hard rule for every slice: each block this ADR adds or touches ends in a typed refusal or a typed, visible wait that names its cause.

Certificate expiry is judged against the local wall clock with a 300 s tolerance (`src/identity.rs:450`, `460–465`), through `verify_cert_against_owner` (`src/groups/owner_cert.rs:378–379`).
D60 requires every class-K delivery and resend to refuse an ineligible recipient, including an expired seat. Today's code does not do this.
`publish_secure_share` builds the envelope, publishes it on the metadata topic, and schedules a direct delivery and a delayed resend, with no eligibility check (`src/server/routes/named_groups.rs:1916–1959`). The eviction engine sends survivor envelopes the same way (`21735–21742`).
An expired seat leaves today only through the explicit seal route or a routine seal re-check.
After S7 stops routine re-checks, a seated TreeKEM member with an expired certificate could derive later epochs until an admin acts (ADR 0113 Q2); D71 closes that window here.

Legacy readers parse `named_groups.json` and `home-suite-groups.json` as JSON maps; changing either envelope aborts startup (`src/server/mod.rs:735–737`).
The Home parse error even recommends removing the file (`src/server/routes/named_groups.rs:30377–30381`).
S4 must preserve #451's legacy-safe views and ADR 0094's trial rollback contract.
The existing atomic persistence path holds the global `named_groups_persistence_lock` while writing (`27371`); its `.hsjournal` precedent avoids the legacy `*.journal` scan (`27390–27400`).
Ordinary sibling commits create a no-anchor fork marker cleared only manually (`4301`); a short fallback window can turn fleet delay into indefinite quarantine.

The public [rulings digest](../design/x0x-direction.md#5-decisions-d01d55) covers D34/D40 but ends at D55. Later rulings apply inline:

- **D58 (2026-10-03):** “accept all ADRs here now” — 0088, 0094, 0095 and 0096 were Accepted as written; their Open questions remain open. This does not accept S4.
- **D60 (2026-10-03):** “G11 = require current eligibility.” Every class-K GSS envelope delivery/resend requires current recipient eligibility and current secret epoch, including after agent/machine revocation, certificate expiry, verdict change or quarantine; entitlement is not fixed at commit. This is a requirement, not today's behaviour (above); §3 makes guarded egress a prerequisite of every S4 key send.
- **D63 (2026-10-04):** “bind every slice in ADR 0088” — S4 is 0110, drafted Proposed and reviewed across models; separate acceptance order and D16/D54 harness-first still bind code.
- **D64, D65, D69–D76, D117, D118, D120, D122, D126–D129, D135 (2026-10-04):** recorded in [Rulings and open questions](#rulings-and-open-questions).

## Decision Drivers

- One eligible reachable admin suffices; no owner, original sealer or quorum is required.
- Restart preserves signed evidence and unfinished work without publishing a stale sibling.
- Delayed designation discovery, fsync and CPU stalls must be measured in the fallback budget.
- Downgrade starts normally with legacy-readable files and intact new sidecars.

## Considered Options

| Option | Reason |
|---|---|
| Durable designated-first worker for revocation, certificate expiry and self-leave | Chosen; implements D34(2)/D40/D71 and closes #1113. |
| Expiry as a delivery refusal only | Rejected (D71); after S7 an expired seated member reads later epochs until an admin acts. |
| Lowest reachable admin first | Rejected (D74); local reachability views differ and can cause sibling rekeys. |
| Fixed 2 s W and 5 s completion | Rejected (D69); one lost frame or stall can cause sibling rekeys and ordinary-group quarantine. |
| Hold crypto-only commits on a survivor's last advert, or commit past known legacy survivors | Rejected (D76); the first lets a dead device block removal (L1), the second strands known survivors. |
| New versioned obligation sidecar and separate journal; legacy files unchanged | Chosen; preserves #451, 0085 and 0094 rollback safety. |
| Tagged v2 envelopes in existing JSON maps, or append obligations to the postcard journal | Rejected; legacy startup and journal replay would break. |
| Evict only at the next seal, or leave roster-only | Rejected; an idle group retains a former member's keys indefinitely. |
| Every observer seals immediately | Rejected; eager races create sibling rekeys. |
| Wait indefinitely for the lowest roster admin | Rejected; an offline device defeats L1. |
| Owner/admin quorum or an election/lease protocol | Rejected for S4; no quorum is required and this slice adds no consensus. |
| No rebinding, or admin-only rebinding | Rejected (D129); every renewal would cost a rekey, and an every-admin-expired group would have no exit. |
| Announced renewals keep a seat | Rejected (D135); eviction would depend on cache state that differs between nodes. |
| Deletion as the only exit, or a no-exit typed wait | Rejected (D126); the first loses owner-certified groups and Homes, the second leaves the group stuck. |
| Operator repair of an unreadable S4 file | Rejected (D120); S4 quarantines and rebuilds its own files. |

## Decision

### 1. Triggers, intake and obligation

After full signature and issuer-authority verification, an **Agent-subject revocation** creates work for each live group where the target has a seat or a retained cryptographic leaf.
A verified, chained **self-leave** creates the same work after the roster-only leave applies, including receipt through catch-up.
A **certificate expiry** of an Active seat in a group with `OwnerCertified` admission creates the same bounded work (D71); §1a defines it.
Key each obligation by **(stable group ID, target agent ID)**, with a set of verified revocation hashes, self-leave commit hashes and expired-certificate digests.
Persist signed records and authorizing evidence; duplicates and extra hashes for the same excluded leaf do not create another worker, extend a window or undo that exclusion's completion.
An already-Removed target completes only with verified cryptographic exclusion on the current chain; SignedPublic needs only roster exclusion.
If the target was validly re-admitted later, reconcile its seat/leaf incarnation and current revocation before deciding completion; old exclusion cannot certify a new leaf. A still-applicable/new agent revocation opens work for that current leaf under the same (group, target) key; an old self-leave proof alone cannot remove a later valid admission.

All revocation routes share one post-verification choke point **after `verify_and_insert` returns `Ok(true)`**.
These include v1 receive (`src/lib.rs:9676`), v2 binding receive (`9860`), v3 share-grant intake (`3814`), and local `apply_and_publish_revocation` (`11709–11722`), reached by `revoke_as_owner` (`11682–11700`) and local self-revocation.
Only Agent subjects schedule seat exclusion; other subjects still invalidate affected serving immediately.
Hook startup loads (`storage::load_revocation_set`, v2/v3 loads, `src/lib.rs:16952`, `17034–17041`) and any evidence/catch-up ingestion through the same verified intake/reconciliation logic.
Do not rely on the v1 asynchronous save: the obligation and its verified evidence require a durability barrier before S4 acknowledges durable work or seals.
Release the revocation-set lock before taking membership/persistence locks; queued notifications and startup reconciliation close missed-hook gaps.
Scan loaded rosters and crypto state read-only at startup and after catch-up; defer sidecar creation/writes and S4 execution until §5's host-commit gate.
A failed persist exposes `waiting_for_durable_intake`; retain the in-memory serving denial and retry without claiming durable completion.

**Machine and binding revocations deny that device only (D70).** They block every delivery and resend to the revoked machine (§3); the portable agent keeps its seat until that agent itself is revoked.
Grant revocations do not imply group-wide Agent-subject removal either.
Missing certificates and anonymous announcements are not eviction triggers; retain their existing verdict rules until the assigned slices replace them.

#### 1a. Certificate expiry trigger and clock skew (D71)

**Scope.** Expiry scope depends only on the admission policy.
Expiry creates work in every group whose admission is `OwnerCertified`, including Home, under either confidentiality setting; admission and confidentiality are independent axes (`src/groups/policy.rs:27–53`, `70–76`).
Groups with any other admission policy have no owner-certificate check (ADR 0107), so expiry creates no work there.
This adds to ADR 0038's seal-time expiry re-check; it does not replace it. S7 retires that re-check only once S4 is in effect (0088 §3).

**Selected certificate.** For each Active seat, the selected certificate is the one the current committed roster binds to that seat: its embedded bytes, or bytes that match its committed `certificate_digest`.
ADR 0107's serving guard uses the same source, so every node on the same head selects the same certificate. A certificate held only in an announce or discovery cache is never selected.
Its signed `not_after` is the expiry time; a certificate with no `not_after` never expires. Other verification failures (signature, owner chain, agent binding) are not expiry and keep their existing verdict rules.
If this node lacks the bytes for a digest-only seat, it shows `waiting_for_certificate_evidence` for that seat, naming the committed digest, while the existing seat-certificate fetch runs (`warranted_fetch_for_pending_seats`, `src/server/routes/named_groups.rs:22556`). A verified expiry hand-off that carries matching bytes also supplies them. All holders offline is 0088 §2 item 8.
An expiry trigger names one committed digest; a seat whose committed certificate changes needs its own expiry.

**Who decides, and against which clock.** Each admin decides expiry for itself, against its own wall clock (UTC Unix seconds).
No shared clock exists, and a monotonic clock cannot be compared with an absolute `not_after`.
The expiry tolerance is **τ = 300 s**, today's `EXPIRY_CLOCK_SKEW_SECS` (D127), so eviction and D60's delivery refusal use one test.
- **Own trigger:** an admin's own trigger fires when its wall clock passes the selected certificate's `not_after + τ`. D60 requires the delivery refusal to use the same test (§3). The node schedules this check from the committed `not_after` and repeats it at wake, at startup and after catch-up, so a missed timer never loses a trigger.
- **Hand-off:** a verified expiry hand-off (§4) names the committed digest and may carry its bytes. It starts a receiver's T_obs only once the receiver selects the same certificate and its own wall clock has passed the raw `not_after`. Before that, the receiver keeps the hand-off and starts T_obs when both hold.
- **Effect:** no node evicts before the certificate's signed expiry on its own clock. Skew σ between admin clocks adds nothing to the fallback budget while σ ≤ τ; beyond τ it adds σ − τ, which the W measurement must cover (§2).
- **Budgets:** from T_obs on, §2's budgets run on the suspend-inclusive monotonic clock. A later wall-clock change neither renews W nor restarts a budget.

**What renewal cancels (D135).** Only a verified `certificate_rebind_v1` commit (§4a, D129) that binds a renewed certificate into the seat cancels expiry work.
The renewal must be for the same owner and agent, must verify, and must be unexpired on the node's clock; it then becomes the selected certificate.
The row moves to `terminated` with cause `certificate_valid`, and no removal is made.
The rebinding commit is new. Today no commit can rebind a renewed certificate into an Active seat:
`MemberJoined` rejects an Active member (`src/server/routes/named_groups.rs:13547–13549`), both direct-add routes reject an existing member (`19154–19156`, `19365–19369`), `set_member_certificate` refuses bytes whose digest differs from the committed one (`src/groups/mod.rs:1731–1734`), and seals never rebind a surviving seat (`1425–1430`).
**An announced renewal no longer keeps a seat (D135).** A renewal held only in an announce or discovery cache cancels nothing. It may supply the bytes for a rebinding commit; without that commit the seat is evicted at its expiry, and the agent rejoins with the renewed certificate.
This replaces, for S4's expiry work, today's seal ladder that seats an announce-resolved certificate (`src/groups/mod.rs:1420–1423`); that seal-time ladder itself stays until S7 replaces it.
A renewal never cancels revocation or self-leave work on the same key.
Before every seal, re-check under the membership lock against the current head and wall clock. If the node's clock is no longer past the raw `not_after`, it does not seal; the row stays `pending`, showing the expiry time it waits for, until the clock passes it again, and no budget renews.

**Commit.** Remove an expired seat with the ordinary signed `MemberRemoved`.
In an `MlsEncrypted` group its matching TreeKEM removal or GSS rotation goes with it, as for a revoked seated target (§3).
In an `OwnerCertified` `SignedPublic` group the roster removal alone completes the work, with no crypto transition; today's engine already skips the rotation there (`src/server/routes/named_groups.rs:21625–21640`).
Expiry eviction records no ban. The agent may rejoin through a fresh invite with a valid certificate; 0088 §2 item 2 still refuses an expired joiner, and an old exclusion never certifies a new leaf.

**Designation ignores expiry.** Designation and fallback ranks (§2) never evaluate certificate expiry, so a clock difference cannot split the designation. The target itself is never designated or ranked.
An admin whose own selected certificate is expired on its clock may not seal: it marks `local_committer_ineligible`, hands off, and the next rank falls back after W.
If no admin other than the target holds an unexpired selected certificate, the obligation shows `waiting_for_admin_certificate_renewal`, naming those admins. Its exit is the self-rebind (D126, D129): §4b(2).

**L4 for expiry.** No acceptance rule changes.
Any current admin may already remove a member (ADR 0016), so receivers accept the resulting `MemberRemoved` under existing checks and do not re-judge expiry on their own clock.
Expiry only schedules work; it grants no authority. Selecting only the committed certificate gives every node the same input, so only clock skew can make admins disagree.
A clock more than τ fast can make an admin evict early, by at most its offset minus τ. An admin could already do that by hand, so this is an availability cost to the target, not an authority gain.
A forged or replayed expiry hand-off cannot shorten another node's budget: the receiver checks the bytes against its own committed digest, verifies the certificate's signature, owner chain and agent binding, and acts only on its own clock.

**Mixed versions.** Old binaries keep today's expiry handling and evict an expired seat only at an explicit or routine seal.
They accept the resulting `MemberRemoved` unchanged. A legacy admin's own removal of the seat completes the obligation if its crypto exclusion matches; in a `SignedPublic` group the roster removal alone completes it.
Expiry hand-off goes only to `eviction_handoff_v1` receivers.

### 2. Designation, hand-off and staggered fallback

An eligible committer is Active and Admin-or-higher on the current committed parent roster and passes current signer-revocation, owner-policy and containment checks.
For designation and ranks only, skip the certificate-expiry part of these checks (§1a).
Order IDs by raw 32 bytes; legacy `Owner` is Admin-equivalent.
**The lowest eligible roster admin is designated (D74)**, whether or not it has a direct QUIC connection; all others wait.
This gives one designation on every node with the same head; lack of a direct connection or a stale presence record never grants early authority.
A reachable higher admin waits up to W for an offline lower one; D74 accepts that delay.
**D74 governs everywhere (D122).** "Online" in D88 and in 0088 §3's "lowest online active-admin" (D40) reads as "eligible on the roster"; the others fall back after W.
Operationally, reachable means an authenticated direct or routed exchange with that agent succeeds against current machine/binding evidence.
`unresolved_designated_admin` means hand-off has neither reached such an exchange nor returned a definitive current routing/eligibility failure; it preserves priority through W, not forever.

Each observing admin forwards signed trigger evidence to **every eligible admin** using `EvictionHandoffV1` (§4).
Define **T_obs** for each admin as the earlier of its own first hand-off dispatch attempt and its earliest verified hand-off receipt. Record dispatch before route resolution and the admitted physical write; for the designated admin, local verified intake is self-hand-off. Unroutable/unsupported results are recorded against that attempt. Route resolution itself consumes W, so an unresolved route cannot prevent the fallback clock from starting. For expiry, §1a limits when a receipt counts.
This is not the earlier gossip-observation timestamp. Persist observation, first-dispatch and earliest verified hand-off receipt timestamps and remaining budgets; an earlier verified hand-off may shorten a budget, while duplicates, retries and unrelated commits never extend or restart it.
Hand-off is authenticated evidence transfer, not a lease or exclusive-authority receipt; the receiver verifies it independently.
Fan-out gives all eligible compatible ranks a start within one hand-off latency, even when their own observations are far apart; the measurement gate must cover this delivery/verification skew.

Let **W** be the designated window and **Δ** the fallback stagger.
Only the designated admin starts a target exclusion before W expires.
Other eligible admins are ranked from r = 1 in raw-ID order excluding the designated admin; rank r may start at **T_obs + W + (r − 1)·Δ**.
Until then each shows `waiting_for_designated_admin`, naming the designated ID and its own fallback time.

**Timing values come from measurement (D69, D73).**
- **W and the completion bound:** each is set from the W3-H harness p99.9 of hand-off delivery-and-verification skew, plus persistence (fsync), CPU-stall and seal-and-propagation time, with margin (D69). For expiry triggers, W also covers inter-admin clock skew beyond τ (§1a). The draft's 2 s / 5 s suggestion is withdrawn.
- **Δ:** at least the measured p99.9 seal-and-head-propagation time; the harness compares 2 s to 5 s (D73).
- **Restart sync wait:** at least the measured p99.9 head catch-up, provisionally 10 s to 30 s (D73).
- **Accept waits for these numbers.** `s4_timing_measurement` (Validation) produces them from main's existing primitives, so it does not need S4 code. The authors then propose each value with its margin, and David accepts the values with the ADR.

Re-derive eligibility/ranks on a verified new roster without granting a fresh W; re-read head and evidence under the membership lock before **every** seal.
No verified exclusion may have landed, and the replica must have completed a current catch-up round first.
On restart, even an expired saved budget requires a catch-up round or the bounded restart sync wait above; never fallback on an unrefreshed head.
A round can use any authenticated holder, not a particular peer or quorum. If no other holder is reachable, the bounded wait may finish discovery (D73), followed by re-loading the complete verified durable local head/crypto; no known higher/conflicting head or incomplete replay may remain unresolved. If the wait expires with unresolved head evidence, expose `waiting_for_head_sync` and continue catch-up; expiry alone cannot authorize a known stale seal. All holders of missing head evidence offline is item 8; failure to progress with an available holder is a defect.
Clock rollback cannot renew the window; preserve remaining suspend-inclusive monotonic budget and boot identity rather than trusting wall time.
The bound applies while one eligible compatible admin and required evidence are reachable; offline survivor ACKs are not part of it.

A stale parent requires refresh, re-validation and re-signing, never publication of a pre-signed stale transition.
A timeout sibling retains fork evidence and quarantine. Ordinary no-anchor forks require manual admin action under 0088 §2 item 7; S4 adds no fork choice or cross-gap adoption.

#### Amendment to ADR 0016 §6

Upon acceptance, replace its first two TreeKEM-bound committer bullets with:

- **Involuntary remove/ban without pending S4 exclusion:** the initiating admin commits the rekey, under existing authority and stale-head checks.
- **Revocation or certificate-expiry eviction, or responsive rekey after self-leave:** use ADR 0110's designated-first hand-off, window and ranked fallback. The lowest eligible roster admin on the leave/current verified revision acts first (D74); a later head re-derives eligibility without resetting the window. This replaces lazy waiting for that particular admin's next online pass.
- **Manual remove, ban or explicit seal affecting an S4 target during the window:** a non-designated admin queues and hands off the request and returns `waiting_for_designated_admin`; it must not rekey that target early. After its ranked fallback time, it re-reads the head and may seal once. A verified removal/ban from any authorized admin completes the obligation if its crypto exclusion matches, including a legacy admin's event.

Intercept incidental target eviction inside `owner_certified_seal_with_eviction` too (`src/server/routes/named_groups.rs:21789`, revocation verdict `src/groups/mod.rs:1543–1551`).
An explicit/unrelated seal that would evict the pending target must defer that seal or route it to the designated worker; it cannot bypass the discipline.
This changes local scheduling, not the receiver's authority to accept a valid admin commit, and preserves 0016's last-admin invariant and concurrency limits.

### 3. Commit, evidence, restart and egress

Serialize roster, crypto state and obligation transitions under the group membership lock and existing persistence-lock order.
For a seated revoked or expired target, reuse ordinary signed `MemberRemoved`, with its matching TreeKEM removal/epoch in an `MlsEncrypted` group; ordinary groups use `20979–21041`, Home and other `OwnerCertified` groups may use the OwnerCertified engine.
For an already-Removed self-leaver, remove its retained leaf through the crypto-only signed transition in §4; never restore the seat to enable removal.
For grandfathered GSS, rotate once and envelope only eligible survivors. For SignedPublic, roster exclusion completes any trigger without a crypto event. That includes expiry in an `OwnerCertified` `SignedPublic` group (§1a).
Before S5, obtain removal evidence through `resolve_member_treekem_kp_for_removal_locked` → `request_member_key_package_catchup` (`8732–8775`, `10416`).
A miss exposes `waiting_for_member_key_package`, resumes when authenticated evidence arrives, and never treats a missing package as an absent leaf.
S5 owns new fetch-by-hash/oversized carriers; S4 does not widen 0089 lookup permissions or depend on S5 for an existing available-holder route.

Persist roster, crypto snapshot, obligation phase and exact outgoing event before publication (§5).
After restart with `committed_delivery_pending`, **re-sync the head before any resend**.
If the recorded exclusion is on the verified current chain and epoch, finish its eligible delivery without another rekey.
If another exclusion landed on a competing branch, do not publish the saved event: persist fork evidence, enter `waiting_for_fork_resolution`, and name manual admin resolution for ordinary groups (existing owner-anchor recovery for Home).
If a compatible exclusion superseded it on the same chain, complete work and discard obsolete delivery; never resend old key material after an epoch change.
If the head cannot be established, retain `waiting_for_head_sync`; a crash-after-commit is not permission to publish a sibling.
Use shared verified-chain delivery, not an authority catch-up log (D54); survivor convergence, not a transport ACK, proves delivery.

Invalidate staged results/Welcomes and cancel unsent transfers to ineligible recipients. A recipient that then asks gets ADR 0107's typed refusal, naming the failed eligibility input.
Every envelope, recovery response, Welcome and class-K delivery/resend uses ADR 0107's serving guard plus D60 **under the membership lock immediately before each physical write**.
**Guarded egress is a prerequisite, not today's behaviour.** Today's share path and the engine's survivor envelopes skip this check, publish on the metadata topic and resend after a delay (Context).
Before any S4 path sends class-K material, S4's code routes it through one guarded egress point that applies the inputs below at each write, with no topic publication and no unguarded delayed resend. PR #1190 plans the same guard; S4 may reuse it but does not wait for it. Until guarded egress lands, S4 claims no D60 behaviour.
Inputs are current roster membership/role and ban/withdrawal, agent revocation, authenticated recipient machine and agent-machine binding revocation, current certificate signature/issuer/expiry and verdict where required, quarantine/containment, and current secret epoch.
Ordinary groups gain a current **agent-revocation serving gate** even though 0107 skips OwnerCertified certificate checks for them.
Machine/binding revocation blocks delivery to that origin, including envelopes/resends/Welcomes, without removing a still-valid portable agent's seat (D70). A request from that device gets a typed refusal naming the machine or binding revocation.
There is no hidden transport resend or gossip fallback for key material; each new exchange re-admits and selects the current artifact/epoch.
Already delivered bytes and previously granted epochs cannot be recalled.
The [join-artifact lifecycle work on PR #1190](https://github.com/saorsa-labs/x0x/pull/1190) is related work; S4 supplies and validates these guards without depending on that PR merging.

### 4. Wire, acceptance and visible exits

Existing seated-target `MemberRemoved` encoding and validation stay unchanged.
New wire shapes are explicitly capability-gated under ADR 0093:

- **`eviction_handoff_v1`:** understands typed authenticated `EvictionHandoffV1` on the existing direct-message carrier. Its versioned body carries stable group ID, target ID, observed parent head, and one or more of: signed revocation records with issuer evidence, signed self-leave commit/chain proof, the target's expired committed certificate digest with its bytes when available (§1a), or a renewed certificate for the target's seat, sent by the seat's own agent after its self-rebind cutoff (§4a). It is advisory evidence; the receiver verifies every record and current chain/authority, deduplicates by §1's key, and schedules only a verified trigger. No key material travels here.
- **`crypto_exclusion_v1`:** understands signed `CryptoExclusionV1` metadata for an already-Removed target with a retained leaf. The versioned body carries group ID, actor, target, prior head, next revision, roster-removal/self-leave proof hash, target leaf KeyPackage hash (TreeKEM), TreeKEM commit and next epoch or GSS next secret epoch, and signed `GroupStateCommit`. An outer agent signature in domain `x0x.crypto-exclusion.v1` binds the canonical body including crypto payload hashes and commit header. The roster stays Removed; the chain advances and the crypto binding/epoch changes together. There is no admission or restoration.

A receiver checks an eligible current parent-roster admin signature, chained prior removal proof, target/leaf binding, exact next revision/epoch, unchanged membership, last-admin invariant, policy/containment, and cryptographic removal proof before atomic install.
This is a **new L4 acceptance rule for the crypto-only event**, not a relaxation of legacy `MemberRemoved`: only a current authorized admin may exclude a leaf of a verifiably removed target, and no membership or authority is gained.
Do not assume released readers accept repeated `MemberRemoved` on a Removed seat; use released-reader controls and this distinct gated shape.
Gate each new typed send on the recipient's current verified capability; unknown/expired support first requests an authenticated advert refresh. Missing support exposes per-recipient `waiting_for_receiver_upgrade` and retains delivery for upgrade, never false completion.
**Legacy survivors follow the draft rule (D76): hold the crypto-only commit while any Active survivor has a current verified advert lacking `crypto_exclusion_v1`, and strand the rest until they upgrade.** Expose `waiting_for_receiver_upgrade` on the obligation, naming each holding survivor, as today's limitation 9 toward legacy members. Advancing the chain revision and TreeKEM epoch past such a survivor would strand it: its frontier-gap queue would hold every later commit, violating 0088's per-slice legacy degradation and R3. Under ADR 0093 semantics, unknown/expired capability state and offline survivors do not hold the commit, preserving L1; this requires no all-member capability quorum. A stranded survivor shows on every upgraded member as per-member `waiting_for_receiver_upgrade`, naming the gap revision. Both waits are permanent for a device that never upgrades; §6 records them as a named amendment to 0088 §2. Seated-target revocations and expiry evictions are unaffected: they use the legacy `MemberRemoved`. Do not send an unsupported peer a disguised repeated `MemberRemoved` or restore the target for compatibility.
New wire bodies use distinct typed prefixes (`X0XEVH1` for hand-off and `X0XCE1` for crypto exclusion) and explicit v1 postcard shapes with exact consumption; the outer crypto signature covers that deterministic body. Crypto-only delivery/catch-up uses per-recipient gated direct metadata delivery, never ungated metadata-topic publication. Reuse current carrier size/admission limits; an oversized proof waits for the existing authorized evidence route, not an invented S5 carrier.
**The new `CryptoExclusionV1` body never goes inside a container legacy binaries decode**, including ADR 0106's `intervening_events: Vec<NamedGroupMetadataEvent>` (`src/server/routes/named_groups.rs:1213`). That enum is internally tagged with `#[serde(tag = "event")]` (`1505–1512`); an unknown variant is a hard decode error of the #451 class. Across a crypto-only gap, capable joiners use capability-gated catch-up on the distinct new carrier and verify each chain link before resuming ordinary membership-event carry. Legacy joiners receive an existing attempt-bound typed refusal where supported, or expose `waiting_for_receiver_upgrade`; never embed the new body in their join-result carry or another legacy-decoded wrapper.
A capable joiner shows `waiting_for_head_sync` while its gated catch-up crosses the gap. The admin that serves its join result also serves ADR 0108's `JoinPendingNotice` (§8, D117) with cause `crypto_only_gap`, a cause S4 registers against that section with no detail, on the joiner's existing join-result poll under ADR 0107's guard as amended by ADR 0108 §8 for a joiner that is not yet a member (D145). If the existing 120 s poll ends first, the joiner's `TimedOut` carries that cause, never a silent stop (D64). S4 defines no notice shape of its own; a joiner without 0108's notice capability keeps today's cause-free timeout, as 0108 states.
Hand-off to an unsupported designated admin records the unsupported attempt and waits for W, showing `waiting_for_designated_admin` with cause `designated_admin_unsupported`; a compatible fallback can use legacy removal for a seated target.

Each new bit's number is **allocated at acceptance, in acceptance order, as the next free bit in the README registry**. No number or README registry row is added now; the accepting PR allocates and fixes each name atomically.
Existing optional `peer_evidence_v1` remains under ADR 0089's budgets/authorization and establishes no committer authority.
Keep current signature, parent-roster authority, prev-hash, owner mandate, fork, revocation and TreeKEM adoption-exclusion checks (`src/groups/state_commit.rs:850–913`) for every existing commit kind; keep last-admin checks (`735–746`). `CryptoExclusionV1` and admin-signed `CertificateRebindV1` are signed by an eligible admin and need no exception.

**Named exceptions to Accepted authority rules (D126, D129; approved by David in D146).** Two new commit kinds have a signer that is not an admin on the parent roster. Each exception covers only that commit kind, under the receiver checks of §4a or §4b(1); every other commit is checked exactly as today.
- **Self-rebind (`CertificateRebindV1` signed by the seat's own agent, D129).** ADR 0016 Decision 1 decides authority by role on the committed parent roster. This commit is accepted from a non-admin signer only when the signer is the seat's own agent and the commit changes only that seat's certificate and digest. ADR 0064 Decision 2's ancestor walk, which requires an active-admin committer at each predecessor, accepts such a link under the same checks. The link is not an owner anchor and never clears an ADR 0064 quarantine marker.
- **Owner recovery (`OwnerRecoveryV1`, D126).** ADR 0016 Decisions 1 and 2 let only an admin on the parent roster promote or remove. This commit is accepted from the promoted member, who is not yet an admin, only under a verified `OwnerRecoveryMandateV1` from the group's owner and only while no eligible admin remains. It is the "signed mandate layer above the chain" that ADR 0016 Decision 2 names as the path for such authority. ADR 0064 Decision 2's ancestor walk accepts the link under the same checks. The mandate is a new owner-signed object; ADR 0064 Decision 1's `MemberAdded` owner mandate is unchanged. A receiver that holds an ADR 0064 quarantine marker for the group refuses the commit (`recovery_group_quarantined`), and the commit never counts as an owner anchor for clearing that marker.
- ADR 0016 Decision 3's last-admin invariant applies to both, unchanged.

A revoked signer cannot use its revoked key to remove itself.
**No eligible admin remains (D75, D126)** when verified Agent-subject revocations cover every Admin-or-higher Active seat. This is not 0088 §2 item 3, because those seats can still be Active.
Every member shows `waiting_for_eligible_admin_revocation`, with the revoked admin IDs, the blocked exclusion and the exit that applies, and no secrets.
**Member sends are refused with that typed state**, so no new message reaches a revoked key; admission and other admin operations return the same state.
The exit depends on the admission policy (§4b): an owner-signed recovery commit for `OwnerCertified` groups, and the deletion exit `group_admin_revoked` for every other group.
For a genuinely admin-empty roster, retain `waiting_for_active_admin` under item 3.
A local worker that is demoted, removed or revoked, or that self-left, stops sealing/delivery immediately, marks `local_committer_ineligible`, and hands work off while still authorized.
A demoted worker stays a member and keeps its pending rows until verified completion (D72). A worker that leaves or is removed ends local retention once it has handed its evidence to an eligible admin, or at once if it may no longer send (D128); the shared revocation records and the verified chain still carry the evidence.
Do not erase the shared obligation or claim exclusion complete merely because this local worker stopped. An absent local membership ends its local scheduling responsibility, not the group's exclusion requirement.
Signed deletion terminates work under item 5 (phase `terminated`, cause `group_deleted`). No-anchor forks wait under item 7 as `waiting_for_fork_resolution`. All evidence holders offline waits under item 8, in the state that names the missing evidence (`waiting_for_member_key_package` or `waiting_for_head_sync`). An available holder must enable progress.
Other deadline misses are defects, not new may-block-forever entries.

### 4a. Certificate rebinding commit (D129, D135)

`certificate_rebind_v1` binds a renewed certificate into an Active seat in place. It is the only way a renewal keeps a seat (§1a).

- **Wire.** The capability `certificate_rebind_v1` understands a signed `CertificateRebindV1` commit with typed prefix `X0XCRB1` and an explicit v1 postcard shape with exact consumption. The body carries group ID, seat agent ID, signer ID, prior head, next revision, the old committed certificate digest, the new certificate bytes and the signed `GroupStateCommit`. An outer agent signature in domain `x0x.certificate-rebind.v1` binds the canonical body. It changes only that seat's committed certificate and digest; role, membership, TreeKEM leaf and epoch stay unchanged. It carries no key material.
- **Who may sign (D129).** Any eligible current admin, for any Active seat; or the seat's own agent, for its own seat only.
- **When it is made: cutoff, then hand to the admin (D155).** The cutoff is `not_after − τ` of the seat's selected certificate (§1a), the committed certificate being replaced, on the agent's own clock.
  - **Before the cutoff,** the seat's own agent self-rebinds once it holds a verified renewal (D129).
  - **After the cutoff,** the agent's own API refuses a self-rebind with `rebind_window_closed`. The agent instead hands the renewal to every eligible admin in an `EvictionHandoffV1` (§4), and shows `waiting_for_admin_rebind`, naming the designated admin, until a rebind or a removal for its seat lands.
  - **The designated admin commits it.** No admin starts expiry work before the raw `not_after` on its own clock (§1a). From that point, the designated expiry worker (§2) commits the rebind instead of `MemberRemoved` when it holds a verified renewal for the seat, from the hand-off or any other source including an announce cache, and the mixed-version rule below allows it; otherwise it evicts. Fallback ranks follow §2, so an offline designated admin costs at most W.
  - **The cutoff narrows the race; it does not remove it.** The agent commits only before `not_after − τ` by its own clock and admins act only after `not_after` by theirs, so the two decision windows are separated by τ minus the relative clock offset between the agent and the admin; with that offset within τ they do not overlap. A valid pre-cutoff self-rebind can still be undelivered when the designated admin seals against the same parent after expiry. Each admin re-reads the head under the membership lock before every seal (§2), which stops it once the rebind has arrived. A sibling pair that still forms, from a delayed pre-cutoff self-rebind or from skew beyond τ, falls under §2's fork containment: every node keeps the fork evidence and shows `waiting_for_fork_resolution`, no node applies both siblings, and in an `OwnerCertified` group ADR 0064's owner-anchored recovery resolves the fork. S4 adds no fork choice.
  - **Receivers do not enforce the cutoff,** because they cannot see the agent's clock. The cutoff is the agent's sending rule; a late self-rebind grants nothing, and fork containment covers a race.
  - **Every admin expired.** §4b(2) applies, and an admin's own self-rebind is allowed after its cutoff.
- **Receiver checks (L4: a new acceptance rule).** The receiver accepts the commit only if all of these hold:
  - the signer is an eligible current admin on the parent roster, or the seat's own agent under §4's named exception; the signer is not revoked; prev-hash, containment and fork checks pass as for any commit;
  - the seat is Active, not Removed or banned, and its committed digest equals the old digest in the body;
  - the new certificate verifies against the group owner for that agent, is not revoked, is unexpired at `not_after + τ` on the receiver's clock, and has a later `not_after` than the committed one;
  - nothing else changes.

  A failed check refuses the commit with a typed reason: `rebind_signer_ineligible`, `rebind_seat_not_active`, `rebind_digest_mismatch`, `rebind_certificate_invalid` or `rebind_not_later`.
- **Security.** The owner's signature is the only authority for the certificate's content, so the commit grants no membership, role or key. The later-`not_after` rule stops replay of an older certificate. A stolen agent key can bind only certificates the owner already signed for that agent. A revoked agent cannot rebind, because revocation outranks the seat.
- **Mixed versions (D129).** Released binaries cannot follow the commit, and a revision they cannot apply would strand them. So the commit is used only when every Active member's current verified advert sets `certificate_rebind_v1`. Otherwise the seat is evicted as in §1a, and an unknown or offline member disables rebinding rather than blocking eviction. The one exception is §4b(2).
- **Egress.** Delivery and catch-up use per-recipient gated direct metadata delivery, as for `CryptoExclusionV1` (§4). It is never published on the ungated metadata topic or placed in a legacy-decoded container, and it carries no class-K material.
- **Effect on S4 rows.** A verified rebind on the current chain terminates that seat's expiry work with cause `certificate_valid`. A rebind that arrives after the removal is refused with `rebind_seat_not_active`.

### 4b. Exits when no eligible admin remains (D126)

**(1) `OwnerCertified` groups, including Home: owner-signed recovery commit.**
- **Trigger.** Verified Agent-subject revocations cover every Admin-or-higher Active seat in a group with `OwnerCertified(U)` admission.
- **Mandate.** The owner signs `OwnerRecoveryMandateV1` with user key U, on a node that holds U's key, through a local owner API, in domain `x0x.owner-recovery.v1`. The mandate names the group ID, the parent head it applies to, each revoked admin with the hashes of its verified revocation records, and one promoted member with its committed certificate digest. The owner's node sends it to that member over the existing direct-message carrier, gated on `owner_recovery_v1`.
- **Commit.** The promoted member authors one chained `OwnerRecoveryV1` commit under the mandate, with typed prefix `X0XORC1`, an explicit v1 postcard shape with exact consumption, and an outer agent signature over the canonical body and the embedded mandate. It removes each revoked admin's seat: with its TreeKEM leaf in a TreeKEM group, with one GSS rotation in a GSS `MlsEncrypted` group, or the roster seat alone in a `SignedPublic` group. It sets the promoted member's role to Admin. Nothing else changes.
- **Receiver checks (L4: a new acceptance rule).** The owner signature verifies against the group policy's owner U. The parent head equals the mandate's head. Every named admin has a verified Agent-subject revocation, checked through §1's choke point, and no eligible admin remains on the parent roster. The promoted member is Active, not revoked or banned, signs the commit, and holds an unexpired selected certificate that verifies against U. The cryptographic removal proof matches, and the last-admin invariant holds afterwards. Typed refusals: `recovery_not_needed` (an eligible admin exists), `recovery_head_mismatch`, `recovery_signer_not_owner`, `recovery_member_ineligible`, `recovery_proof_invalid` and `recovery_group_quarantined`. The signer exception is named in §4.
- **Security.** U already roots trust in this group: it signs every member's certificate, and ADR 0064's owner anchor resolves its forks. The rule widens U's power in one state only, when verified revocations leave no eligible admin, and only to promote one current certified member. A revoked admin cannot use it. A mandate is bound to one parent head, so it cannot be replayed later. A stolen U key could already certify any agent; with this rule it can also choose the new admin once every admin is revoked.
- **Typed states.** Until the commit lands, members show `waiting_for_eligible_admin_revocation` with exit `owner_recovery`. The owner's node shows `waiting_for_recovery_member`, naming the promoted member, until that member is reachable and commits. An owner who never signs leaves the group in the named §2 entry "OwnerCertified group waiting for its owner" (D152, §6).
- **Egress.** The mandate and the commit carry no class-K material. GSS survivor envelopes after the commit use §3's guarded egress (D60).
- **Mixed versions.** Released binaries cannot follow `OwnerRecoveryV1`. It follows the D76 rule: hold while a known Active member's current verified advert lacks `owner_recovery_v1`, and strand unknown, expired or offline legacy members until they upgrade. A released binary never receives the new body in a container it decodes. §6's legacy-member entry covers this commit (D153).

**(2) Every admin expired: self-rebind (D126, D129).**
- **Which exit applies.** The self-rebind applies, not the owner recovery commit. Expiry is not compromise, so the expired admins' keys stay trusted, and the self-rebind changes only one certificate. The owner recovery commit serves only revoked admins.
- **Mechanism.** The owner renews one admin's certificate. That admin's own agent signs `certificate_rebind_v1` for its own seat (§4a), even after its cutoff, because no eligible admin exists to take a hand-off (D155). The admin is then eligible and runs the pending expiry work under §1a and §2.
- **Mixed versions.** §4a's rule would disable rebinding whenever an Active member lacks `certificate_rebind_v1`, and here no eligible admin remains to evict instead. So in this case only, the self-rebind follows the D76 rule: hold while a known Active member's current verified advert lacks the capability, and strand unknown, expired or offline legacy members until they upgrade. The obligation shows `waiting_for_admin_certificate_renewal` until a renewal arrives, then `waiting_for_receiver_upgrade` while a hold applies. §6's legacy-member entry covers this case (D153).
- **Owner who never renews.** If the owner never renews an admin's certificate, the group stays in the named §2 entry "OwnerCertified group waiting for its owner" (D152, §6).

**(3) Every other group: deletion exit `group_admin_revoked` (D126).**
- **Trigger.** Verified Agent-subject revocations cover every Admin-or-higher Active seat in a group without `OwnerCertified` admission. No owner key exists, so no signer can repair the group.
- **Mechanism.** No signed event is needed, and none is possible. Each node derives the outcome from verified revocation records and its verified head, after a current catch-up round (§2). It then ends the group locally: sends, admission, invites, seals and key delivery return the definitive typed refusal `group_admin_revoked`, naming the revoked admin IDs. Local history stays readable; nothing is deleted.
- **Re-create offer.** The refusal carries a re-create offer: the current non-revoked members, and the group's name and policy. A member that accepts creates a new group through the existing create API, becomes its admin, and invites those members. It is a new group, with a new ID and new keys; no history, key or authority carries over. Several members may each re-create; S4 does not coordinate that.
- **Late evidence.** A node that later verifies a head with an eligible admin was behind. It clears `group_admin_revoked` and resumes, because the state is derived, not signed.
- **L4.** No acceptance rule changes. The state only refuses and grants nothing. A forged revocation cannot cause it, because §1 verifies issuer authority. Anyone able to revoke every admin could already stop the group under D75.
- **Mixed versions.** Released binaries do not know the state. They keep sending, and those messages can reach the revoked admins' keys; that is today's behaviour toward legacy members.
- **Egress.** None; the exit sends nothing. §6 records it as a named amendment to 0088 §2.

**Joiners (D154).** While no eligible admin exists, any Active member that receives a joiner's join-result poll serves ADR 0108's `JoinPendingNotice` with the single cause `no_eligible_admin`, under 0108 §8's signer rule for that cause and the D145 amendment of ADR 0107. The notice grants nothing. The joiner's `TimedOut` at 120 s then carries `no_eligible_admin`. This applies in all three cases above; in §4b(3) it also applies after `group_admin_revoked`.

### 5. Separate versioned persistence and mixed versions

**Never change either legacy JSON format:** `named_groups.json` and `home-suite-groups.json` remain released-reader-safe maps, existing #451 placeholders are left unchanged; S4 adds none. Ordinary membership changes still use their existing encoders.
Use S4's own `<data_dir>/revocation-evictions.evs` sidecar with the 10-byte header **`X0XEVICT1\0`**, followed by its frozen v1 postcard body, consumed exactly (header layout below).
Use new `<data_dir>/treekem/<stable-group-id>.evjournal` journals with the distinct 8-byte header **`X0XEVJ1\0`**, followed by their own frozen v1 postcard body, consumed exactly. Legacy `*.journal` and `.hsjournal` scans ignore both extensions.
Do not add fields to `TreeKemNamedPersistJournal` or alter its postcard layout; it replays before load (`src/server/mod.rs:726`).
Rows hold group/target, hash sets and signed evidence (for expiry, the committed certificate digest and `not_after`), observation/hand-off time, boot identity/remaining W and stagger budgets, designated/ranked IDs, phase, typed waiting cause, parent/result head and epoch, and exact outgoing event.
Phases are `pending`, `prepared`, `committed_delivery_pending`, `complete`, and `terminated` (cause `group_deleted` or `certificate_valid`); waiting causes do not destroy the phase/evidence.
Never serialize transient TreeKEM `PreparedMember` secrets.
**Retention (D72, D128):**
- Keep each pending row and its signed evidence until verified completion or a signed group deletion. Resource pressure never drops pending work; a failed write shows `waiting_for_durable_intake`.
- Drop a completed row's signed evidence bodies 30 days after verified completion, once its exclusion is on the verified chain. Keep a compact record (group, target, trigger hashes, result head and epoch) until a signed group deletion, at most 4,096 per group, oldest first out.
- This is safe because the revocation store keeps the revocation records and §1 re-derives completion from the verified chain, so a late duplicate never causes a new rekey.
- Drop `terminated` rows once the deletion or cancellation is durable.
- A node that leaves or is removed ends local retention once it has handed its evidence to an eligible admin, or at once if it may no longer send (§4).

Create or materially write S4 files **only after ADR 0094 host commit**, never after instance health alone. Outside an upgrade trial, ordinary operation may create them lazily on its first verified trigger persist.
During the trial, scan/read existing files without rewrite, enforce in-memory serving denials, retain queued work as `waiting_for_host_commit`, and re-scan on host commit; retain rollback-readable legacy revocation saves.
Do not run S4 exclusion or journal replay that mutates persisted state before this gate.
Freeze decoders for each **released new sidecar/journal layout**, not every legacy JSON map; a later positional layout gets a new magic. Rewrite lazily on a material persist, never a boot migration.

Every new file barrier uses temp write, fsync, atomic rename and directory fsync. Transaction order under membership/persistence locks: fsync a prepared `.evjournal` with evidence, exact event and matching parent/result/epoch; then use the **unchanged** legacy roster/crypto transaction and its existing `.journal`/`.hsjournal` commit barriers; fsync the reconciled S4 sidecar; only then publish and retire the S4 journal.
The S4 journal is never an independent license to install a speculative roster/crypto after-image.
Startup order: inspect S4 formats read-only to contain affected groups; run existing rollback-readable legacy TreeKEM and Home journal recovery in their current order, then load merged rosters/crypto. Reconcile `.evjournal` and `.evs` read-only against that verified state before key serving; initialize stores and report trial health without waiting for host commit. After host commit, perform S4 reconciliation writes/replay and release queued S4 execution. The host gate must not deadlock 0094's store-initialization health prerequisite.
A matching committed result promotes delivery-pending; an unchanged parent with no legacy commit evidence returns to pending and abandons speculative preparation; a different/competing head triggers catch-up/fork containment. Never replay stale S4 state over a newer roster.
**Unreadable S4 files (D120).** S4 quarantines and rebuilds its own files by ADR 0108 §5a, the shared sidecar quarantine lifecycle. §5a defines classification, the `txid` transaction, resume, history, the generic states `sidecar_unavailable`, `sidecar_newer_format` and `sidecar_quarantine_failed` (each with its `file` field), and the generic fault cases. S4 adds only the items below. Daemon startup and unrelated groups stay available throughout.
- **Files.** `<data_dir>/revocation-evictions.evs`, and each `<data_dir>/treekem/<stable-group-id>.evjournal`.
- **Header layout.**
  - `.evs`: 10 bytes, the family prefix `X0XEVICT`, one ASCII version digit and a NUL terminator. Version 1 is `X0XEVICT1\0`.
  - `.evjournal`: 8 bytes, the family prefix `X0XEVJ`, one ASCII version digit and a NUL terminator. Version 1 is `X0XEVJ1\0`.
  - A version digit is valid from `1` to `9`; there is no padding. The highest version this binary supports is 1 for both files. The frozen v1 postcard body follows the header and must be consumed exactly. The `.evs` v1 body begins with `rebuilt_from`, the `txid` list §5a requires.
  - Each prefix is reserved for its path forever, so every future layout is `X0XEVICT<n>\0` or `X0XEVJ<n>\0` with a higher `n` (§5a).
- **Rebuild source for §5a step 4 (`.evs`).**
  - Revocation work: from the local revocation store and the current rosters. Other admins' hand-offs re-supply records.
  - Self-leave work: from the verified chain and current crypto state, refreshed from any holder by existing catch-up.
  - Expiry work: from committed certificates and the clock (§1a), with missing bytes from the seat-certificate fetch.
  - Completion: re-derived from the verified chain (D128). A delivery-pending row whose exclusion is on the chain becomes `complete`.
- **Rebuild for a `.evjournal`.** Journals are created per transaction, so §5a step 4 writes no replacement journal and a missing journal is the normal state. The unchanged legacy roster/crypto transaction stays authoritative: a committed result is on the chain; otherwise the preparation is abandoned and the row returns to `pending`.
- **Local-only state no holder has.** T_obs, first-dispatch and hand-off receipt times, remaining budgets and boot identity; unsupported-attempt records; speculative `prepared` state; exact outgoing events; completed rows' compact records. The outcome:
  - Rebuilt rows start `pending` with T_obs at rebuild time, so this node acts later, never earlier, and only after a current catch-up round (§2).
  - A prepared exclusion with no legacy commit is abandoned, as the startup rule above says.
  - A survivor that missed a key envelope from a lost row recovers it through the existing guarded recovery path. S4 never resends from a lost row.
  - Compact records are re-derived from the chain when needed.
- **S4 states.** While a file is rebuilt, the groups with S4 work in it show `rebuilding_obligation_store`; if group identity cannot be decoded, every group with S4 work does. Their S4 seals and key sends wait, and in-memory serving denials from the revocation set still apply. If the rebuild needs a head that no reachable holder has, the group shows `waiting_for_head_sync` (0088 §2 item 8).
- **Memory-only durability.** While §5a runs a file memory-only, S4 seals only triggers whose evidence is durable elsewhere: a revocation record in the revocation store, a self-leave on the verified chain, or a committed certificate. Any other trigger shows `waiting_for_durable_intake`. A memory-only `.evjournal` means that group's S4 work runs without its own journal.
- **ADR 0094 trial.** During a trial, S4 starts no quarantine transaction. A damaged file runs memory-only until host commit, and the transaction follows host commit.
- **Quarantined copies (D148).** S4 keeps them as ADR 0108 §5a states: never deleted automatically, and diagnostics list each copy with its size. A group's `.evjournal` copies go when that group's own files are deleted. `revocation-evictions.evs` holds every group's work, so its copies go only when an operator removes them.
- **Amendment to ADR 0085 rule 4 only.** S4 amends rule 4 for its own `.evs` and `.evjournal` files only, as ruled by David (D120) and as §5a specifies. Rule 5 is not amended. ADR 0085 is Accepted and is not edited; ADR 0089's rule for its own file is unchanged.

**Downgrade:** old binaries ignore S4 files and retain ADR 0038's evict-at-next-seal behaviour; daemon startup stays available. No S4 bound is claimed there.
**Re-upgrade:** reconcile saved obligations against the current roster/crypto and verified chain, including removals/rekeys that happened on the old binary; do not restore stale seats or resend obsolete epochs.
**Old → new:** verify legacy self-leave/removal normally and schedule or reconcile crypto exclusion.
**New → old:** seated-target removals retain their encoding; hand-off/new crypto-only events are gated and must not be sent to unsupported receivers or embedded in legacy-decoded containers. Active survivors with current verified adverts lacking `crypto_exclusion_v1` hold crypto-only commits with obligation-level `waiting_for_receiver_upgrade`; unknown/offline survivors do not hold them and stay stranded until they upgrade (D76, §6). Joiners crossing an existing crypto-only gap follow §4's gated catch-up or typed refusal/waiting path. Expiry triggers degrade as §1a states.
A legacy admin may stay idle or race a valid removal; new admins wait then fallback, while mixed fleets retain legacy scheduling limits. The crypto-only upgrade hold leaves seated-target revocations on legacy `MemberRemoved` unaffected. No compatible admin means legacy behaviour, not S4 completion.

### 6. Amendments to ADR 0088 §2 (D76, D118, D126, D152, D153)

This ADR amends ADR 0088 §2 with three named entries, upon acceptance, each ruled by David. ADR 0088 is Accepted and is not edited. The entries are named, not numbered, because several slices add entries.

- **Legacy member across a new S4 commit (D76; confirmed by David in D118).** The member runs a binary without the capability the commit needs. Two waits follow, and both are permanent for a device that never upgrades:
  - **Hold.** While an Active survivor has a current verified advert lacking `crypto_exclusion_v1`, the crypto-only exclusion of an already-Removed target does not commit. This covers a self-leaver and a target revoked after it self-left; meanwhile that target's retained leaf can still derive new epochs. Typed state: obligation-level `waiting_for_receiver_upgrade`, naming each holding survivor, visible on every upgraded member. Exits: the survivor upgrades and refreshes its advert; it stops being Active; or its advert expires, after which the commit proceeds and the stranded wait below applies to it.
  - **Stranded.** A legacy survivor that was unknown, expired or offline when the crypto-only exclusion committed cannot cross that revision and epoch gap. Typed state: per-member `waiting_for_receiver_upgrade`, naming the member and the gap revision, visible on every upgraded member. Exit: the member upgrades, then uses §4's gated catch-up.
  - **Extension (D153).** The same hold and stranded waits, with the same states and exits, apply to `OwnerRecoveryV1` (§4b(1)) and to the every-admin-expired self-rebind (§4b(2)), with `owner_recovery_v1` or `certificate_rebind_v1` as the capability.

  A released binary cannot show either new state itself; it shows today's frontier-gap behaviour. Seated-target revocations, expiry evictions and ordinary rebinds (§4a) create neither wait.
- **Ordinary group whose admins are all revoked (D126).** Verified Agent-subject revocations cover every Admin-or-higher Active seat in a group without `OwnerCertified` admission. This is a definitive entry: every member operation returns the typed refusal `group_admin_revoked`, naming the revoked admins (§4b(3)). There is no exit for the group. Members may accept the re-create offer, which makes a new group.
- **OwnerCertified group waiting for its owner (D152).** An `OwnerCertified` group, including Home, has no eligible admin, and its only exits need the owner: the recovery mandate (§4b(1)) or a renewed admin certificate (§4b(2)). This is a waiting entry. Typed state: `waiting_for_eligible_admin_revocation` (exit `owner_recovery`) or `waiting_for_admin_certificate_renewal`, naming the admins, on every member. Exit: the owner signs a recovery mandate or renews an admin's certificate. A lost or unused owner key leaves the group waiting; no member-quorum or other non-owner exit exists.

## Consequences

- Positive: revocation, certificate expiry and self-leave no longer need an unrelated seal or original admin; #1113 is in scope. After S7, an expired seated member no longer reads later epochs until an admin acts (D71).
- Positive: legacy startup remains safe; crashes retain evidence without automatic stale-event publication.
- Cost: an Active survivor whose current verified advert lacks `crypto_exclusion_v1` holds crypto-only exclusion at `waiting_for_receiver_upgrade` until upgrade or the hold no longer applies; seated-target revocations still use legacy `MemberRemoved`. A pinned device that stays online holds it forever (D76, §6). Timeout races still require containment.
- Not protected: a legacy survivor that is offline, or whose advert has expired, when the crypto-only exclusion commits does not hold it. On return it cannot cross the chain and epoch gap, because the gated catch-up is never served to it. It stays stranded until it upgrades, which a pinned install may never do. A closed laptop during a self-leave is the typical case. David accepted this (D76); §6 records it.
- Cost: measured fallback values (D69, D73) make removal slower than the withdrawn 2 s suggestion, and David's Accept waits for the harness numbers.
- Positive: a routine renewal keeps the member in its groups through `certificate_rebind_v1`, signed by an admin or by the member's own agent (D129).
- Positive: an `OwnerCertified` group or Home whose admins are all revoked recovers through its owner, and an every-admin-expired group recovers through a self-rebind (D126).
- Cost: until its exit runs, a group with no eligible admin stops, and member sends are refused (D75). An ordinary group in that state ends for good (`group_admin_revoked`); members can only re-create it as a new group (D126).
- Cost: an announced renewal no longer keeps a seat (D135). Each renewal needs a rebinding commit, and rebinding is off while any Active member lacks `certificate_rebind_v1`; then the seat is evicted and the agent rejoins. An admin clock more than τ fast can evict up to its offset minus τ early.
- Cost: two new acceptance rules (`CertificateRebindV1`, `OwnerRecoveryV1`) and their wire shapes, approved by David (D146, D151).
- Cost: an `OwnerCertified` group with no eligible admin waits for its owner; a lost owner key leaves it waiting (D152). A renewal that reaches the agent after its cutoff needs a reachable eligible admin to commit it (D155).
- Cost: a damaged S4 file is quarantined and rebuilt by ADR 0108 §5a (D120). Local timing, prepared state and outgoing events are lost, so a rebuilt node acts later, never earlier.
- Operational: seal-time certificate re-checks stay until S7, after S4 is Accepted and shipped.

## Validation

[#1164](https://github.com/saorsa-labs/x0x/issues/1164) tracks the not-yet-built W3-H harness. Recommend a separate S4 case-tracking issue; no issue creation or test result is claimed here.
Each **red** case must be committed and demonstrated red on `main` before S4 code merges (D16/D54); in-process tests alone do not meet this gate. Controls pass before and after.
Use real participants in CI's fresh loopback-only Linux namespace with deterministic clock, schedule seed, crash barriers and recorded public API calls.
For each case below, create/invite/join through public group APIs; let A < D < E be admins, B the target and C a survivor. Run Home and ordinary TreeKEM, with GSS/SignedPublic variants where applicable.
Let t = 0 be trigger submission via local revoke API or authenticated revocation receive; advance a virtual clock for worker budgets. Public head/status/message APIs assert results; crash hooks observe durability barriers without fabricating obligations. Default delivery is 100 ms per frame, in send order; departures from it are named below. Control baselines use public manual seal/remove to reach existing crypto/persistence barriers on main; S4-only phase/status assertions are additional post-fix checks, not claimed passing baseline controls.
**Healthy exit H:** reachable survivors have one coherent verified roster/head and epoch, C decrypts new traffic, B's retained old keys cannot; no publish return/transport ACK substitutes for H.
**Typed states (D64):** a case passes only if the waiting side sees the named state or refusal through public status APIs; a silent wait or a bare timeout fails. Each state in this ADR has a case:
`waiting_for_durable_intake` (`s4_restart_intake_prepare`); `waiting_for_designated_admin` and `unresolved_designated_admin` (`s4_fallback_rank_manual`, `s4_designated_late_observation`); `waiting_for_head_sync` (`s4_restart_stale_head`); `waiting_for_member_key_package` (`s4_evidence_holder`); `waiting_for_fork_resolution` (`s4_crash_commit_fallback`); `waiting_for_receiver_upgrade` and the join `TimedOut` (`s4_mixed_wire`); `waiting_for_eligible_admin_revocation`, `waiting_for_active_admin` and `local_committer_ineligible` (`s4_local_authority_exit`); `waiting_for_host_commit` (`s4_sidecar_rollback`); `rebuilding_obligation_store` (`s4_sidecar_rebuild`); ADR 0108 §5a's `sidecar_unavailable`, `sidecar_newer_format` and `sidecar_quarantine_failed` for S4's files (`s4_sidecar_lifecycle`); machine/binding refusals (`s4_intake_and_egress`); `waiting_for_certificate_evidence`, `waiting_for_admin_certificate_renewal` and `certificate_valid` (`s4_certificate_expiry_skew`); the `rebind_*` refusals, `rebind_window_closed` and `waiting_for_admin_rebind` (`s4_certificate_rebind`); `waiting_for_recovery_member`, the `recovery_*` refusals and the `no_eligible_admin` notice cause (`s4_owner_recovery`); `group_admin_revoked` (`s4_ordinary_admin_revoked`); the `crypto_only_gap` notice cause (`s4_mixed_wire`).

| Case / baseline | Nodes, deterministic delivery and public steps | Assertion |
|---|---|---|
| `s4_idle_revocation_one_admin` / red | A,B,C; stop owner/original sealer. At t=0 revoke B through issuer API, deliver verified evidence to A, deliver all later frames on fixed schedule; never call seal. | H within accepted bound; main remains seated at its old epoch. Repeat self-revocation and ordinary groups. |
| `s4_self_leave_crypto_only` / red | A,B,C; at t=0 B calls leave, deliver its roster-only commit to A/C at t=100 ms; send no other mutation. Repeat revocation arriving after that leave. | B stays Removed, one admin crypto-only transition excludes its retained leaf and H holds; main retains the leaf. |
| `s4_designated_late_observation` / control + red fallback | A,D,E,B,C; D observes at t=0, hand-off reaches A at t=100 ms, original gossip reaches A only at t=W/2. Fixed subsequent delivery; then repeat with A stalled for W+Δ and D reachable. Add a variant where E observes at t=0, sends hand-off to every eligible admin with 100 ms delivery, and D's own observation arrives at least Δ later. | No early D/E sibling is the safety control; E's hand-off sets D's T_obs within one hand-off latency, so ranked D fallback precedes E despite observation skew. Automatic healthy exclusion and stalled-A ranked D fallback must reach H (red on idle main). |
| `s4_dropped_eager_frame` / control + red | A,D,B,C; D observes first; drop initial eager revocation and hand-off frames to A, flush IHAVE at 100 ms, deliver retry only after the 1.5 s per-peer timeout floor. Repeat total A loss while D/C remain reachable. | No premature sibling in recovered schedule (control); total loss gives D fallback after W, current-head sync and H (red). |
| `s4_netem_cpu_tail` / control + red | A,D,E,B,C; run netem profiles with 375 ms Sydney or 230 ms Singapore RTT reference plus ±100 ms jitter and 1% loss from a recorded seeded delivery trace; drop an eager frame, drive public unrelated persistence writes, impose 2-vCPU contention and a deterministic t=0..30 s stall on A. Apply each reference as an RTT profile with half per direction. Clock records hand-off and lock/fsync tails; repeat A blocked past accepted W. | Controls produce no early competing seal; fallback case reaches H if reachable/evidence prerequisites hold. Report any sibling quarantine as budget failure, never a pass. Main's idle exclusion is red. |
| `s4_restart_intake_prepare` / red | A,B,C; crash A after durable trigger intake, then separately after prepared journal before legacy commit. Restart same identity/data; catch-up to C completes at t=500 ms after restart. Send duplicate triggers at t=100 ms. Add a run where A's first intake write fails, then succeeds at t=1 s. | Evidence/budgets survive, catch-up precedes seal, no duplicate crypto epoch; H. The failed write shows `waiting_for_durable_intake` while serving denial holds. Main loses or never schedules work. |
| `s4_crash_commit_fallback` / control | A,D,B,C; partition A from D/C after hand-off. Crash A after durable exclusion before publish; advance D past W, sync its pre-A head and let D commit/deliver exclusion. Restart A; deliver D's head/proof before releasing A's resend. | A publishes no saved sibling; fork evidence and typed manual-resolution exit survive. On main, public manual remove reaches the same pre-publication barrier; the no-sibling-publication/fork-containment assertions are controls. Post-fix, the durable delivery-pending recovery must meet them too. A cannot claim H across a real fork. |
| `s4_restart_stale_head` / control + red resume | A,D,B,C; save pending work on A, stop it, let D's remove/ban API commit exclusion; restart A with expired W, delay head catch-up until t=500 ms. Repeat catch-up unavailable past proposed sync wait. | No fallback before sync; learned exclusion completes without another rotation. No evidence exposes `waiting_for_head_sync`; successful resume is red on idle main. |
| `s4_fallback_rank_manual` / control + red | A,D,E,B,C; hold A past W, deliver all heads in order. D/E call target remove, ban and explicit seal APIs before W, then advance clock across W and W+Δ. | Requests queue with `waiting_for_designated_admin` naming A; D may act at W, E only at W+Δ after re-read, never if D exclusion landed. Main's non-designated manual APIs rekey immediately, so the no-early-seal/queued-resume assertion is red; after the fix D/E obey W/Δ. |
| `s4_evidence_holder` / red resume | A,B,C plus holder D; A lacks B's KeyPackage. Revoke B; hold D offline until t=W+Δ, then let authenticated existing catch-up finish on fixed delivery. | Typed `waiting_for_member_key_package`, no fake absent-leaf completion; on D's return H without an API seal. All-holders-offline is item-8 control. |
| `s4_intake_and_egress` / red + controls | A,B,C; use v1 receive, local owner revoke and restart-loaded verified agent records separately. Stage join artifacts via invite/poll APIs; after staging revoke agent, then separately machine/binding, expire certificate or quarantine; invoke result/Welcome polling and scheduled resend at fixed times. | Agent-trigger H is red. Every physical key write rechecks current inputs/epoch; affected recipients receive no keys, ordinary agent-revocation gate included. Guarded egress is red on main: today's share path publishes on the metadata topic and resends to a revoked or expired recipient. A machine- or binding-revoked device gets the typed refusal while its agent stays seated (D70). Invalid issuer/signature and eligible first joins are controls. |
| `s4_local_authority_exit` / control | A,D,B,C; pending work on A, then D's public role/remove API demotes/removes A, or A leaves, or issuer revokes A before seal admission. Repeat with A as sole admin, revoked at t=0; B and C call the send API at t=1 s. Repeat with a genuinely admin-empty roster. | A stops writes/seals as `local_committer_ineligible` without erasing evidence; D resumes. Sole admin revoked: B and C see `waiting_for_eligible_admin_revocation` naming A, and their sends are refused with it (D75); never mislabeled admin-empty. Admin-empty shows `waiting_for_active_admin`. The exits are tested in `s4_owner_recovery` and `s4_ordinary_admin_revoked`. |
| `s4_sidecar_rollback` / control + red durability | A,B,C; use released data-dir fixtures with provenance/SHA256. Revoke during 0094 trial; inject rollback before host commit, then repeat host commit and each S4/legacy journal fsync crash barrier. Downgrade using released 0.45.0/0.46.1, mutate via old removal/seal APIs, re-upgrade. | No trial S4 writes or legacy-format rewrite; old startup succeeds and ignores new extensions; reconcile current head without restoring stale state. Post-commit durable scheduling is red on main. Unreadable S4 files follow `s4_sidecar_rebuild`. |
| `s4_mixed_wire` / control + red upgraded route | Released 0.45.0/0.46.1 A or D with a new survivor C and new member B; choose A < D admins with D new and A released in one run, and reverse artifact roles in another; self-leave or revoke via APIs. Give an Active legacy survivor a current verified advert lacking `crypto_exclusion_v1`, then upgrade receivers and refresh adverts at t=W+Δ; repeat with unknown/expired adverts and offline survivors. After a permitted crypto-only commit, join capable and legacy receivers whose from_revision predates it through ADR 0106's join-result path. | Legacy removals still decode/decrypt both directions; the known Active legacy survivor holds crypto-only revision/epoch advancement with obligation-level `waiting_for_receiver_upgrade`, while unknown/offline survivors do not hold it. No new typed body reaches an unsupported peer or legacy-decoded container, including intervening_events. Capable joiners verify gated catch-up across the gap and converge; legacy joiners get a supported typed refusal or `waiting_for_receiver_upgrade` without a decode error. Upgraded members show per-member `waiting_for_receiver_upgrade` naming each stranded or holding survivor (D76). A capable joiner whose catch-up outlasts the 120 s poll ends in a `TimedOut` that carries ADR 0108's pending cause notice with cause `crypto_only_gap` (D117). Upgraded H is red on main; legacy lower-ID idle admin cannot prevent compatible seated-target fallback. |
| `s4_certificate_expiry_skew` / red + controls | Home (OwnerCertified, owner user U); admins A < D < E, target B, survivor C. Each node has a fixed wall-clock offset over shared virtual time; monotonic clocks follow virtual time; 100 ms delivery. Create and admit through public APIs; issue B's certificate with `not_after` = t=60 s through the public certificate API; call no seal. Runs: (1) all offsets 0; (2) A −τ/2, D +τ/2; (3) A −(τ + W/2); (4) D +2τ; (5a) U's renewal for B reaches A, D, E only by announce at t=55 s; (5b) at t=55 s, already past B's cutoff (`not_after − τ` = t=−240 s), B calls the self-rebind API and then hands the renewal to A, D and E; separately, an admin tries to rebind 1 s after (5a)'s exclusion commits; (5c) after the eviction in (5a), B joins again through a fresh invite with the renewed certificate; (6) A's wall clock steps back by W after its T_obs; (7) A, D and E certificates also expire at t=60 s; (8) repeat (1) in an `OwnerCertified` `SignedPublic` group; (9) restart A with B's seat digest-only and its bytes held only by D. | (1)(2) H within the accepted bound with one exclusion; no node seals before its own clock passes raw `not_after`; no eviction before true t=60 s while offsets ≤ τ; D seals nothing before its T_obs + W. (3) D falls back after W; any sibling is reported as a budget failure. (4) D evicts no earlier than true t=60 s − τ, and its hand-off starts no T_obs on A or E before their clocks pass t=60 s. (5a) The announced renewal cancels nothing; B is evicted. (5b) B's API refuses with `rebind_window_closed` (D155), and B shows `waiting_for_admin_rebind` naming A. A commits the rebind once its expiry work for B starts, no earlier than t=60 s and within the accepted bound. No `MemberRemoved` lands, and rows end `terminated` with `certificate_valid`. The late rebind is refused with `rebind_seat_not_active`. This is red on main, which has no rebinding commit. (5c) B's new seat selects the renewed certificate; this is a control. (6) No budget renews. (7) `waiting_for_admin_certificate_renewal` names A, D, E; after U renews A at t=60 s + 2W, A self-rebinds, then evicts B, and H holds (D126). (8) B is Removed on every survivor's head with no crypto event and no epoch change. (9) A shows `waiting_for_certificate_evidence` naming B's digest until D's bytes arrive, then proceeds. Every run: no key delivery or resend to B after each sender's own expiry point. H is red on main, which never evicts without a seal; no-early-eviction and renewal assertions are controls. |
| `s4_timing_measurement` / control (measurement) | A,D,E,B,C, Home and ordinary TreeKEM, real time on main. Netem profiles and CPU contention as in `s4_netem_cpu_tail`, with concurrent unrelated persistence writes; recorded seeds. Over at least 10,000 trials per profile, measure: direct-message delivery and verification of a signed revocation record from D to A and E (hand-off skew proxy); public manual remove to C's verified head (seal and propagation); fsync barrier time; restart of A to current head (head catch-up). | Reports each p99.9 with raw samples, seeds and host profile. The proposed W, completion bound, Δ and restart sync wait each meet or exceed the p99.9 they cover plus the stated margin. Runs on main with existing primitives; it needs no S4 code. |
| `s4_certificate_rebind` / red | Home (owner U); admins A < D, member B, survivor C; B's certificate has `not_after` = t=600 s; U issues B's renewal at t=100 s. Runs: (1) B self-rebinds at t=200 s; (2) B is offline and the renewal reaches A only by announce; (3) an Active member L runs released 0.46.1, whose current advert lacks `certificate_rebind_v1`; (4) a rebind carries an older certificate; (5) a renewal is signed by another user key; (6) U's renewal reaches B at its clock's `not_after − τ/2`, after the cutoff (D155); B calls the self-rebind API, then A is offline until t=600 s + W; (7) a revoked agent tries to self-rebind; (8) every admin's certificate expires at t=600 s and U renews A's at t=700 s, first with L online and current, then with L offline; (9) as (8), but U never renews over 24 virtual hours; (10) B self-rebinds at t=200 s, before its cutoff, but the harness holds that commit's delivery to A, D and C until t=600 s + W + 1 s, past expiry. | (1) B keeps its seat, role, leaf and epoch; only its committed digest changes; no `MemberRemoved`. (2) At expiry the designated admin A commits the rebind instead of the removal; H holds with no rekey. (3) No rebind; B is evicted at expiry (§1a). (4), (5) and (7) are refused with `rebind_not_later`, `rebind_certificate_invalid` and `rebind_signer_ineligible`. (6) B's API refuses with `rebind_window_closed`; B hands the renewal to A and D and shows `waiting_for_admin_rebind` naming A; with A offline, D commits the rebind after its fallback time, no earlier than raw `not_after`; B keeps its seat, and no self-rebind and admin commit share a parent. (8) A self-rebinds; with L online the obligation shows `waiting_for_receiver_upgrade` naming L until L upgrades; with L offline the commit proceeds and L is shown stranded. (9) Every member keeps `waiting_for_admin_certificate_renewal` naming A and D for the whole run, and no other exit fires (D152). (10) A seals B's removal on the old parent; when the delayed rebind arrives, every node keeps the fork evidence and shows `waiting_for_fork_resolution`, and no node applies both siblings; the owner-anchored recovery of ADR 0064 then resolves it. Red on main: no rebinding commit exists. |
| `s4_owner_recovery` / red | Home and an `OwnerCertified` non-Home TreeKEM group, plus a `SignedPublic` variant. Owner node O holds U's key; sole admin A; members B, C. At t=0 revoke A through the issuer API and deliver it to B and C at t=100 ms. At t=1 s B and C call send. At t=2 s O signs a mandate naming B, delivered to B at t=2.1 s. Variants: the mandate names a revoked or expired member; names an older head; arrives while D is still an eligible admin; is signed by a non-owner key; is replayed on a later head; B is offline until t=10 s; a released 0.46.1 member L is online and current, then offline; O never signs over 24 virtual hours; a joiner J with a valid invite polls B during the wait. | Before the commit, B and C see `waiting_for_eligible_admin_revocation` with exit `owner_recovery`, and sends are refused. After it, B is Admin and A is Removed with its leaf excluded (roster only for `SignedPublic`); C decrypts new traffic, A's keys cannot, and sends resume. The variants refuse with `recovery_member_ineligible`, `recovery_head_mismatch`, `recovery_not_needed`, `recovery_signer_not_owner`, and `recovery_head_mismatch` again for the replay. B offline shows `waiting_for_recovery_member` on O. L online holds with `waiting_for_receiver_upgrade`; L offline is shown stranded. With O silent, every member keeps `waiting_for_eligible_admin_revocation` with exit `owner_recovery` for the whole run, and no other exit fires (D152). J's poll gets 0108's `JoinPendingNotice` signed by B with cause `no_eligible_admin`, and its 120 s `TimedOut` carries that cause (D154). Red on main: no exit exists, A stays seated, and new messages reach A's key. |
| `s4_ordinary_admin_revoked` / red | Ordinary InviteOnly TreeKEM group; sole admin A; members B, C. At t=0 revoke A; deliver it to B at t=100 ms and to C at t=1 s. At t=2 s B and C call send, invite and status. Variant: A had promoted D in a commit that B first learns by catch-up at t=3 s. Variant: B accepts the re-create offer at t=4 s. Variant: a joiner J with a valid invite polls C at t=3 s. | After a current catch-up round, send, invite and seal on B and C return `group_admin_revoked` naming A; status carries the re-create offer listing B and C; local history stays readable; no key reaches A. With D on the verified head, B clears the state and resumes. The re-created group has a new ID, B as admin and C invited, and carries no history. J gets 0108's `JoinPendingNotice` signed by C with cause `no_eligible_admin` (D154). Red on main: there is no typed state, and sends still reach A's key. |
| `s4_sidecar_lifecycle` / red | S4 instantiates every ADR 0108 §5a fault case for `revocation-evictions.evs` and for one `.evjournal`: cut points, fsync failures, resume crashes, pending copies, history and classification. On S4's layout the header damage forms are a missing prefix, a header truncated to 9 bytes (`.evs`) or 7 bytes (`.evjournal`), version byte `0` or a non-digit, and a missing NUL terminator; the newer valid versions are `X0XEVICT2\0` and `X0XEVJ2\0`. | Each case meets §5a's assertions for that file. Red on main, where no binary quarantines. |
| `s4_sidecar_rebuild` / red | A,B,C with pending revocation, self-leave and expiry work. Damage the `.evs` body and restart A, first with one holder of the head online, then with none. Separately damage a `.evjournal` between its prepare and the legacy commit, once with the commit landed and once without. Separately leave a newer-version `.evs` and send A a new trigger whose evidence is not yet in the revocation store. Repeat the `.evs` case inside an ADR 0094 trial. | Affected groups show `rebuilding_obligation_store`; rebuilt rows match the derivable set and complete with no duplicate rekey, acting no earlier than a fresh T_obs. The landed journal commit is recognised from the chain; without it the preparation is abandoned and the row is `pending`. With the newer file, the new trigger shows `waiting_for_durable_intake`. With no holder, `waiting_for_head_sync`. In a trial, no quarantine transaction starts before host commit. Red on main: main has no S4 store or rebuild. |

Record red/control/green SHAs, artifacts, seeds, delivery schedules, netem parameters, CPU/lock/fsync traces, measured p99.9 completion/skew and decryption results in the implementation PR.
Cover clock rollback, last-admin refusal, concurrent valid legacy removal, signed delete, no-anchor fork/manual exit, owner-offline operation and forbidden re-admission.
Preserve 0106 intervening-event carry for legacy-understood events, with §4's gated catch-up or typed refusal/waiting across a crypto-only gap, and 0107 serving controls, #842 inline-certificate first joins, no serialized `PreparedMember` secrets, and no authority/evidence lookup widening.

## Rulings and open questions

**Still blocking David's Accept:**
- the measured values for W, the completion bound, Δ and the restart sync wait (D69, D73);
- 0088's acceptance order: S4 is accepted after S2 (ADR 0108, which owns the cited §5a lifecycle, §8's `JoinPendingNotice` and its `no_eligible_admin` signer rule, and the D145 amendment of ADR 0107) and S8(a) (ADR 0107).

No open question remains.

David ruled S4's questions on 2026-10-04 (D64, D65, D69–D76):

- **Former Q7 and 0088 G7, L3 (D64):** L3 is a hard rule for every slice. Every block this ADR adds or touches ends in a typed refusal or a typed, visible wait that names its cause, including the 120 s join poll and upgrade waits (§4). Validation asserts each state.
- **Acceptance order (D65):** "S8" in 0088's order means S8(a), ADR 0107. S8(b), ADR 0114, follows S4, and S5 does not wait for 0114.
- **Former Q1, W and the completion bound (D69):** set both from the W3-H harness p99.9 of hand-off skew plus disk, CPU and propagation time, with margin (§2). The 2 s / 5 s suggestion is withdrawn, and Accept waits for the numbers. Review inputs for the measurement: a 100 ms IHAVE flush, a 1.5 s per-peer retry floor for a lost eager frame, #656's 2-vCPU stalls of up to 30 s, and about 375 ms Sydney and 230 ms Singapore RTT.
- **Former Q2, machine-only and binding-only revocation (D70):** deny that device only. The agent keeps its seat until the agent itself is revoked (§1, §3).
- **ADR 0113 Q2 and the former §1 exclusion, certificate expiry (D71):** expiry is an S4 trigger with the same bounded eviction work as a revocation (§1a). τ is set by D127.
- **Former Q3, retention (D72):** keep pending evidence until verified completion or a signed group deletion (§5). D128 sets the limits for completed evidence.
- **Former Q4, Δ and the restart sync wait (D73):** Δ is at least the measured p99.9 seal-and-propagation time, compared at 2 s to 5 s. The restart sync wait is at least the measured p99.9 head catch-up, provisionally 10 s to 30 s. After it, a node uses its verified local head only if it found no other holder and no conflicting evidence (§2). Accept waits for the numbers.
- **Former Q5, designation (D74):** the lowest eligible roster admin is designated, reachable or not; the others wait W, then fall back in rank order (§2).
- **Former Q6, sole eligible admin revoked (D75):** every member sees `waiting_for_eligible_admin_revocation`, and member sends are blocked (§4). D126 rules the exits.
- **Former Q8, legacy survivors (D76):** the draft rule. Hold only for known Active legacy survivors, and strand the rest until they upgrade (§4). The pinned-device hold and the stranded wait are not on 0088 §2, so §6 adds them as a named amendment, which D118 confirms.

David ruled round 2 on 2026-10-04 (D117, D118, D120, D122, D126–D129, D135):

- **Joiner cause notice (D117):** S4 reuses ADR 0108's `JoinPendingNotice` (§8). It registers the cause `crypto_only_gap` (no detail) against that section, uses the reserved `prerequisite_commit_pending` where an eviction must land first, and defines no notice of its own (§4).
- **Named §2 additions (D118):** the legacy-member entry for the crypto-only exclusion is confirmed (§6).
- **Unreadable sidecar files (D120, against the recommendation):** S4 quarantines and rebuilds its own `.evs` and `.evjournal` files by ADR 0108 §5a, the shared lifecycle. It names only its files, its `X0XEVICT`/`X0XEVJ` header layout, its rebuild source (the revocation store, the verified chain and holders) and the outcome for local-only state (§5). This amends ADR 0085 rule 4 for those files only; rule 5 is not amended.
- **Designation (D122):** D74 governs everywhere; "online" in D88 and 0088 §3 reads as "eligible on the roster" (§2).
- **Round-1 Q1, exits when no eligible admin remains (D126; the recovery signer is a named exception to ADR 0016 Decisions 1 and 2 and ADR 0064 Decision 2, §4):** an owner-signed recovery commit for `OwnerCertified` groups (§4b(1)); the self-rebind when every admin has expired (§4b(2)); the deletion exit `group_admin_revoked` with a re-create offer for every other group, as a named §2 entry (§4b(3), §6). The design blocks Accept until David reviews it.
- **Round-1 Q2, expiry tolerance (D127):** τ = 300 s, today's `EXPIRY_CLOCK_SKEW_SECS` (§1a).
- **Round-1 Q3, completed-evidence limits (D128):** drop evidence bodies 30 days after verified completion; keep a compact record, at most 4,096 per group, until group deletion; a node that leaves ends local retention after handing its evidence to an eligible admin, or at once if it may no longer send (§4, §5).
- **Round-1 Q4, rebinding commit (D129):** S4 defines `certificate_rebind_v1`; an eligible admin or the seat's own agent may sign it (§4a). The agent's signing is a named exception to ADR 0016 Decision 1 and ADR 0064 Decision 2 (§4). D155 sets the cutoff.
- **Announced renewals (D135):** only a rebinding commit keeps an expiring seat; an announced renewal alone does not (§1a).

David ruled round 3 on 2026-10-04 (D145, D146, D148, D151–D155):

- **Notices to a joiner that is not yet a member (D145):** ADR 0108 §8 owns a named amendment to ADR 0107: signed, attempt-bound notices and refusals that carry no keys, Welcome or roster may go to the requesting joiner's verified machine. S4's `crypto_only_gap` and `no_eligible_admin` notices use it (§4, §4b).
- **Named exceptions to Accepted authority rules (D146):** the self-rebind and owner-recovery signer exceptions to ADR 0016 Decisions 1 and 2 and ADR 0064 Decision 2 are approved, each scoped to its own commit kind (§4).
- **Quarantined copies (D148):** kept as ADR 0108 §5a states, until an operator removes them or the group's own files are deleted; diagnostics list each copy and its size (§5).
- **Rebinding and owner-recovery designs (D151):** §4a and §4b are approved as written.
- **An owner who never acts (D152, former Q1):** a named §2 entry, "OwnerCertified group waiting for its owner", typed `waiting_for_eligible_admin_revocation` or `waiting_for_admin_certificate_renewal`; exit: the owner signs or renews (§4b, §6).
- **Legacy members across the new exit commits (D153, former Q2):** §6's D76 entry extends to `OwnerRecoveryV1` and the every-admin-expired self-rebind, with the same hold and stranded rule.
- **Joiner notice with no eligible admin (D154, former Q3):** any Active member may serve 0108's `JoinPendingNotice` with the single cause `no_eligible_admin`, under 0108 §8's signer rule. It grants nothing (§4b).
- **Self-rebind cutoff (D155, former Q4):** before `not_after − τ` of the seat's selected certificate the agent self-rebinds; after it, the agent's API refuses with `rebind_window_closed`, and the agent hands the renewal to the designated admin, who commits it (§4a). ADR 0113's H7-6(e) follows this rule.

## Follow-ups

- Clarify the host-commit gate when M2 is absent, including the current helper's health commit (§5).
- Ensure hand-off-verified revocation records also enter the RevocationSet through §1's post-verification choke point.
- Ensure a queued manual ban is still applied after the designated removal (§2).
- Consider per-group `.evs` files to reduce the blast radius of an undecodable obligation store (§5).
- Make `s4_netem_cpu_tail` a deterministic gate; `s4_timing_measurement` now does the real-time p99.9 measurement.

## Notes for AI-assisted work

Only David Irvine marks this ADR Accepted; Accepted ADRs remain immutable.
Acceptance order: 0088, then S2 and **S8(a) (ADR 0107)**, then S4 and S3, then S5, S6, S7. S8(b) (ADR 0114) follows S4, as 0107 specifies; “S8” in the earlier order means S8(a) (D65).
Land S4 **Proposed on main** before governed code merges; David must accept S4 before its code merges, and each red W3-H case must be committed and shown red on main first.
No D55 exception applies to S4. D63 permits drafting bound slices now, not skipping acceptance or harness-first.
Use the single `named_groups.rs` code lane; acceptance allocates capability names/numbers together. Values and policy still open above remain recommendations until David rules them.
