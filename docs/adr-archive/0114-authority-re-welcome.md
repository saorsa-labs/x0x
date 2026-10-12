# ADR 0114: Authority Re-Welcome for Unconfirmed Join Rows

- **Status:** Proposed
- **Date:** 2026-10-04
- **Decision owners:** David Irvine
- **Author:** Codex (GPT-6)
- **Reviewers:** Claude (cross-model r1, r2)
- **Slice:** Slice S8 (b) of [ADR 0088](./0088-group-liveness-contract.md).
- **Supersedes:** none upon acceptance. ADR 0088's supersession table assigns no supersession to S8 (b).
- **Amends:** ADR 0016 §6, widened to repair rekeys alongside S4’s revocation amendment (D88, §3); ADR 0064 Decision §1, for repair adds only (D87, ruled by D146, §3); ADR 0088 §2, by two named entries (§6): S8(b) manual-exit repair (D118, D166) and skipped-epoch ciphertext (D168); and ADR 0085 rule 4, for S8(b)'s own damaged sidecar files only (D120, §5). §7 also makes one named relaxation of 0088 L4's TreeKEM adoption exclusion, for §7 terminals only (D166). Each takes effect when this ADR is Accepted.
- **Superseded by:** none
- **Goal served:** **R3** (all my machines connected) and the shared-places core.
- **Related:** [#1150](https://github.com/saorsa-labs/x0x/issues/1150), [#1149](https://github.com/saorsa-labs/x0x/issues/1149), [#1146](https://github.com/saorsa-labs/x0x/issues/1146), [#1191](https://github.com/saorsa-labs/x0x/issues/1191), [#1164](https://github.com/saorsa-labs/x0x/issues/1164); ADR 0106, 0107, 0085, 0087, 0089 and 0093; S2 = ADR 0108 (its `JoinPendingNotice`, D117), S4 = ADR 0110, S3 = ADR 0109 and S5 = ADR 0111 (their beyond-retention states route to §7), S6 = ADR 0112.

**Decision in brief.** Separate local join confirmation from the signed roster. Serve a usable staged Welcome first.
If staging is lost, a designated admin replaces a never-confirmed seat's TreeKEM leaf without a new invite, but only on an admission-time marker that any admin can verify (D86, D136).
A **confirmed** member behind every holder's retention gets the same replacement through the **retention re-Welcome** (§7, D119). Two vouchers from its last verified roster, or the owner, anchor it.
A Home repair carries a repair mandate signed by the owner device or by a promoted admin (D87).
These are new acceptance rules with their own security argument (0088 L4); D39 and 0088 alone did not authorize them.
Confirmed Active replays remain no-ops. The #1191 fix ships with the full slice, not ahead of it (D91).

The [public rulings digest](../design/x0x-direction.md) records the rulings this ADR cites: D16, D34, D37–D55, D60, D63–D65, D81, D84–D92, D97, D117–D120, D122, D136–D138, D146, D148 and D166–D168.
D63 binds S8(b) to 0114 and permits drafting it now as Proposed. It does not move S8(b) into the first acceptance batch.
"S8" in 0088's order means S8(a), ADR 0107 (D65). S8(b) is accepted **after S4**, as Accepted ADR 0107 requires and D88 confirms; S5 does not wait for 0114.
D60 requires current recipient eligibility and the current secret epoch for every class-K delivery or resend still under x0x's control.

## Context

Code citations below describe source behaviour at `8b35dd1f447774e1a952166f32910fc41b512623`; they are not runtime reproductions.

| Failure | Current mechanism | Contract gap |
|---|---|---|
| #1150: sealed seat, no usable keys | Active `MemberJoined` returns before staging (`src/server/routes/named_groups.rs:13544–13549`). The original result and Welcome expire after 10 minutes in memory (`src/server/routes/named_groups.rs:33211–33243`) | L1: recovery depends on the original sealer. L2: cache loss has no automatic exit |
| #1149: historical seat becomes local admission | The base-seat branch records `seated_at_revision` and persists the install (`src/server/routes/named_groups.rs:18539–18577`). The non-TreeKEM poll confirms on `has_member`, while TreeKEM confirms on map presence (`src/server/routes/named_groups.rs:35736–35747`) | L4: historical eligibility is not current authority confirmation. L2: keyless Active is not completion |
| #1146 residual: refused or timed-out row prevents a fresh attempt | The remnant clear is restricted to never-seated, non-withdrawn, non-quarantined rows (`src/server/routes/named_groups.rs:17865–17892`). This correct restriction cannot repair an authority's still-Active seat | L1/L2: legitimate later admission must have an exit |
| #1191: remove + re-invite gets 409 until restart | A seated timeout returns `NotApplicable` before removing its attempt (`src/server/routes/named_groups.rs:34254–34300`). A superseded poll returns without finalization (`src/server/routes/named_groups.rs:35906–35910`). A different invite then hits the attempt fingerprint gate (`src/server/routes/named_groups.rs:34723–34729`) | L2: local bookkeeping blocks recovery. L3, a hard rule (D64): the block must explain itself |

Group metadata persists as JSON, with migration from the old flat roster (`src/groups/mod.rs:551–558`).
The loader reads a raw group map and merges the authoritative Home sidecar (`src/server/routes/named_groups.rs:30318–30340`, `30504–30532`).
The committed roster projection binds role, state, KeyPackage hash and certificate digest (`src/groups/state_commit.rs:138–172`).
The TreeKEM wrapper rejects duplicate agents and duplicate leaf identities (`src/mls/treekem.rs:252–277`).
Deleting that guard would orphan a live leaf; recovery must remove the old leaf first.

ADR 0107 remains the bounded carry-remnant path, with its original-inviter check (`src/server/routes/named_groups.rs:33264–33278`).
S8 (b) supplies a separate authenticated recovery exchange after that path cannot complete.

S8(b) adds a **typed wire protocol and persisted local state**, beyond 0088's description of a “protocol rule”.
Released binaries parse both `named_groups.json` and `home-suite-groups.json` as raw maps (`src/server/routes/named_groups.rs:30321–30329`, `30373–30383`).
A parse failure aborts startup (`src/server/mod.rs:735–737`), the #451 downgrade brick.
`TreeKemNamedPersistJournal.named_groups_json` also embeds a raw map (`src/server/routes/named_groups.rs:27217–27221`, `27631–27701`).
Released startup scans replay `*.journal`; S8(b) must change neither that body nor the legacy JSON formats.
ADR 0094 forbids format-upgrade writes before host commit, **including lazy rewrites** (0094:262–263).

## Decision Drivers

- Complete eligible repair with any one reachable active admin that holds the required verified state.
- Keep 0107's current-roster serving guard, certificate source and fail-closed verdicts.
- Preserve signed-chain validation, TreeKEM exclusion, owner authority and fork containment.
- Reproduce each failure in W3-H before S8(b) code; D55's S8(a) exception does not apply, and #1191 gets no exception either (D91).
- Every block this slice adds or touches ends in a typed refusal or a typed wait that names its cause (L3, D64).

## Considered Options

1. **Staged-first service, then designated leaf replacement** (chosen). Closes staging loss for seats with verifiable never-confirmed evidence, under D86's and D87's new acceptance rules; D136 fixes the evidence.
2. **Persist every result and Welcome indefinitely.** Rejected: retained key material, stale epochs and original-sealer dependence; D54 chooses S5, not an authority catch-up log.
3. **Re-add on every Active replay or signed lost-key claim.** Rejected: rekey churn and sibling seals. D86 keeps the replacement trigger apart from this: it needs recorded never-confirmed evidence, so a bare signed claim never triggers it.
4. **Confirm from the invite base or crypto-map presence.** Rejected for new recovery: reproduces #1149. Legacy keyed members keep existing semantics during migration; D84 keeps today's checks toward old authorities only.
5. **Require the owner or original inviter for every repair.** Rejected by L1. The existing bounded S8(a) staged path still needs the original sealer; D87 rules Home mandate authority.
6. **Manual remove + re-invite only.** Retained as D43's final exit and the confirmed-key-loss remedy (D85); inadequate as the sole never-confirmed repair path under L1/L2, and as the sole exit for a confirmed member behind retention (D119).
7. **Wrap the two legacy JSON maps.** Rejected: breaks released startup and journals. Use an S8(b)-owned sidecar and an inert legacy placeholder instead.
8. **A named §2 entry for a confirmed member behind retention, with D43's manual exit only.** Rejected by D119, against the recommendation: §7 repairs that member.

## Decision

### 1. Roster, local confirmation and attempt ownership

The signed roster remains authoritative. Local confirmation lives outside its hash in the S8(b) sidecar.

| Local state | Meaning and allowed behaviour |
|---|---|
| `Unknown` | No new confirmation record. An existing member with usable keys keeps legacy read/write and Active semantics; absence of a receipt does not authorize replacement. |
| `Unconfirmed` | This attempt has not installed its required keys and received current authority confirmation. Expose `membership_state: "unconfirmed"` and the typed wait `waiting_for_authority_terminal`, naming the selected authority; no secure read/write or successful completed-join outcome. |
| `Confirmed` | Durable usable keys and attempt-bound authority confirmation, or a keyed legacy migration validated as below. |
| `LegacyAuthorityPending` | A new base-seated attempt finds no eligible admin on its verified roster with a current verified `authority_rewelcome_v1` advert. Expose `authority_upgrade_required`. A qualifying attempt completes as `LegacyCompatible` (D84). An encrypted keyless attempt ends at its existing poll deadline with typed `TimedOut(authority_upgrade_required)`, releases ownership and keeps a retryable local record. |
| `LegacyCompatible` | Completed under today's checks toward a legacy authority (D84). Expose `membership_state: "active"` with `authority_confirmation: "legacy_compatible"`. Never reported as `Confirmed`; never a receipt or never-confirmed evidence. A later bound confirmation probe to a capable admin moves it to `Confirmed` without rekey. |
| `ConfirmedKeysMissing` | A previously confirmed member has lost usable keys. Expose `confirmed_keys_missing`; never replace its leaf automatically (D85). End the attempt with `Refused(manual_reinvite_required)` and expose D43's remedy (§6). |

A keyed `Unknown` becomes `Confirmed` without rekey after ordinary chain verification, local key/epoch consistency checks and durable migration recording.
After host commit, a keyed member runs one bound confirmation probe per seat generation once a capable admin is reachable. Its verified receipt is the confirmation evidence that §7 needs. No receipt is required to preserve the legacy member's existing service.
For SignedPublic, verify the current local chain and seat without a crypto check. Never manufacture an old authority receipt.
A keyless `Unknown` has no recorded never-confirmed evidence, so it never triggers replacement (D86). It ends in `Refused(manual_reinvite_required)`, reason `no_never_confirmed_record`, with D43's remedy (§6).
After host commit, persist new base-seated attempts as `Unconfirmed` before acknowledging that the attempt started; that acknowledgement is not join completion.
Before host commit, refuse a new base-seated attempt with `Refused(host_commit_pending)` before installing its row or acknowledging a start. Retry after ADR 0094's host commit; existing keyed members retain legacy service.
A new encrypted join needs current authority confirmation and usable installed keys. SignedPublic needs confirmation but no keys. D84's `LegacyCompatible` completion is the one exception.
Do not clear removed, banned, withdrawn or quarantined state. Keep #1148's genuine-unseated clear and 0107's re-arm discriminators.

**Old-authority completion (D84).** This is the one named exception to the confirmation rule above. J uses it only while no eligible admin on its verified roster has a current verified `authority_rewelcome_v1` advert; once one has, the new path applies.
J then completes under today's checks. A SignedPublic attempt needs no keys. An encrypted attempt also needs usable installed keys for its verified head's epoch; without them it ends `TimedOut(authority_upgrade_required)`, never keyless Active.
**Security (L4):** the exception adds no chain acceptance rule. It grants no seat or key that today's binary would not grant toward that authority, so it keeps today's exposure, including #1149's, toward legacy authorities only. SignedPublic holds no secret. A `LegacyCompatible` member that later loses its keys is treated as confirmed key loss (D85).
**Mixed versions:** today's working SignedPublic rejoins keep working against v0.45.0 and v0.46.1 authorities; encrypted keyless attempts now end typed instead of reporting keyless Active.

**Poll deadline (L3, D64).** An attempt that reaches its poll deadline (120 s for TreeKEM) without a terminal ends `TimedOut(<cause>)`, naming its last typed wait. Its local record stays retryable and shows `waiting_for_authority_terminal`.
A capable authority that reaches a terminal for that attempt after J's deadline, including a typed refusal such as #946's `certificate_evidence_unavailable`, sends it to J through the gated exchange (§2) while J is reachable. Every §4 trigger on J also re-sends the bound request. So a later refusal reaches J.

**Pending cause (D117).** S8(b) defines no pending message of its own. While a capable authority holds an S8(b) attempt without a terminal, it serves ADR 0108's signed, attempt-bound `JoinPendingNotice`: on the join-result poll, and as the interim answer on the gated exchange (§2). It serves it under ADR 0107's guard and D60's eligibility check, exactly as ADR 0108 §8 states. J's `TimedOut` at the poll deadline then carries the notice's cause.
A node advertises `authority_rewelcome_v1` only if it also sets `join_pending_notice_v1`. S8(b) registers these causes against ADR 0108 §8, and co-owns `authority_catching_up` there:

| Cause | Detail | Meaning and exit |
|---|---|---|
| `authority_catching_up` | `revision` | The designated admin re-syncs its head after a restart before it seals (D73). Exit: the head is reached, or S4's fallback |
| `repair_designated_wait` | none | The attempt waits for the designated admin's window or S4's fallback (D74, D88). Exit: a terminal within the repair bound |
| `repair_staging_lookup` | none | The designated admin waits for the sealer's staging answer, capped at 10 s (D89) |
| `repair_backoff` | `count`: seconds until retry | The authority waits out D90's backoff after a failed delivery |
| `receipt_evidence_pending` | none | An admin fetches a receipt verification record (§2) |

The notice grants nothing, as ADR 0108 §8's L4 states; J never treats it as admission.

Every exit releases only its own attempt ID, including `NotApplicable`, cancellation and superseded polls after group removal.
Release polls, tasks, inviter pins and control-blob references; retain committed seats and outcomes. Old finalizers cannot release a newer attempt or overwrite confirmation.
This #1191 bookkeeping fix ships with the full S8(b) slice, not ahead of it (D91). Its W3-H case is committed and shown red on main before the slice's code merges, like every other S8(b) case. An in-process test may supplement it, never replace it. Until the slice ships, #1191's 409 `join_already_pending` stays a tracked defect.

### 2. Authenticated recovery, receipts and transports

Define canonical `AuthorityRewelcomeV1` request, response and receipt messages with separate agent-signature domains for each type.
Bind group/member IDs, authenticated machine, attempt ID, nonce, original seat-generation commit hash, local revision/hash, requested KeyPackage hash, J's recorded confirmation state for that seat generation (D86) and the request cause: `never_confirmed` (§3) or `beyond_retention` (§7).
The request includes the member-signed TreeKEM KeyPackage, or identity-bound GSS recipient KEM key, and required identity evidence.
Re-verify ADR 0089 EvidenceV1 at use. Stored capability bytes are not a current advert; S2/S5 retain certificate-disclosure and carry ownership.
The response binds the request digest, selected authority, current parent/head hashes and terminal result or typed refusal.
Authority derives from an eligible active-admin seat in the verified parent roster; ordinary InviteV4 and 0106/0107 bindings do not change.
Check attempt currency under the membership lock before each mutation. Verify every ordinary chain link; never adopt TreeKEM state across a gap.
Small carries retain 0106's exact bounds. Larger/non-add gaps use S5; stale-base self-recovery uses S3. A Welcome alone does not prove catch-up to a later head.

After durable installation, J persists a signed receipt binding response digest, terminal commit, Welcome hash, seat generation and installed epoch. In an encrypted group it also binds the retention commitment (§7, D167).
For encrypted groups it also proves possession with a keyed BLAKE3 MAC over the canonical receipt transcript.
Derive its 32-byte key with `blake3::derive_key("x0x/authority-rewelcome/receipt-key/v1", canonical(epoch_exporter_secret, group_id, terminal_commit, seat_generation))`.
Use a separate `x0x/authority-rewelcome/receipt-mac/v1` transcript domain. Canonical fields are length-delimited; compare MACs in constant time.
SignedPublic uses only the agent signature. David ruled this BLAKE3 construction, not HMAC/HKDF-SHA256 (D92).
Persist before sending. Retry a lost receipt rather than rekey after a lost ACK. Old-generation receipts cannot confirm replacement seats.
A receipt proves past installation, not present eligibility or permission to release keys. Missing authority receipt state alone never triggers repair.
Known confirmed Active requests return confirmation without a commit; ordinary Active `MemberJoined` replays stay no-ops.

The **gated recovery exchange** is authenticated pinned direct QUIC between currently verified machines, with current `authority_rewelcome_v1` adverts, canonical signatures, bounded frames/control blobs, replay binding and fair admission.
J fans the same signed request out directly to every currently eligible reachable capable admin from its verified roster, using authenticated resolution; no gossip request fan-out.
Each observer sends the exact request to the designated admin and capable fallback admins in an admin-signed carrier, then records the hand-off.
Before verifying the carrier's admin signature, apply cheap binding/frame checks, digest deduplication and a bounded rate limit keyed by authenticated `(group, forwarding admin)`. Bound signature-verification work separately for each forwarding admin: one carrier per 30 s with a burst of two (D90).
Verify the carrier against the forwarding machine and current Admin seat. Verify the original request against J's current machine binding. Admins that never receive it start no timer.
Requests, J→authority receipts, receipt ACKs and admin→admin receipt queries/replies use registered pinned direct exchanges with deadlines, fair admission and fresh machine/pairing checks.
A receipt query names one group/member/generation/request digest. Only eligible active admins receive receipt bytes; they verify the original signature and possession binding and deduplicate by generation.
The verifying admin persists an `AuthorityReceiptVerifiedV1` record, signed in its own domain, binding the full receipt digest, seat generation, receipt epoch, retention commitment and verified parent/head. Receipt exchange carries this record as well as J’s original receipt.
Another admin checks J's signature, the receipt's epoch and chain binding, and the verifier's Admin authority at that head. It need not fetch or export an old epoch secret.
If it has neither local verification material nor a valid verification record, expose `receipt_evidence_unavailable` and fetch the record through the gated exchange or S5. Missing evidence proves neither a valid MAC nor permission to replace a leaf.
Any response containing class-R or class-K bytes additionally uses §4's unconditional serving admission; receipts and request metadata cannot carry hidden key material.
No inbox, metadata-topic or transport-relay copy is used by this protocol. The bound sealer→designated-admin→J staging path uses pinned direct exchanges.

### 3. Serve first, designation, mandate and atomic replacement

The designated admin checks for usable staging **before** preparing a replacement.
Only the original sealer holds the in-memory S8(a) result/Welcome (0107:71); another admin cannot recreate it from a roster entry.
For S8(b), the sealer releases staging **only on a bound request from the designated admin**, never because J's request reached it through fan-out or forwarding. Bind the lookup and sealer's signed answer to the recovery request digest, attempt, generation and selected authority.
Relay a usable staged artifact through the designated admin under §4, including current eligibility checks for both exchanges. The sealer sends no independent terminal or artifact directly to J for this recovery.
The designated admin durably selects either staged delivery or replacement before sending J a terminal. A signed staging decline or lookup deadline expiry permits it to consider replacement. The lookup deadline is the exchange cap, `min(now + 10 s, staging artifact deadline)` (D89). A late staging answer after replacement selection is discarded. If staged delivery was selected, retry that same terminal rather than replacing its leaf while delivery is outstanding.
Use only staging matching the attempt, generation, KeyPackage and current epoch; preserve the original 10-minute artifact deadline. Copies/retries never extend it.
J accepts one terminal response/sequence per attempt; duplicates are idempotent and competing terminals are rejected with fork evidence where applicable.
Cache expiry, authority restart and no-carry timeout create retryable work, subject to the repair budget below. They do not authorize unlimited fresh rekeys.
Actually unseated identities use S6. GSS recovery reseals only the current secret to the verified recipient KEM key. SignedPublic returns current-seat confirmation without rekey.

Reuse S4's **designated window**, **completion bound**, online observation, hand-off, restart and fallback ordering as finally Accepted in 0110 (D88). S8(b) has no scheduling constants of its own.
D69 sizes S4's window and completion bound from harness p99.9 measurement, and D73 sets its fallback stagger and restart sync wait; their final numbers come with S4's acceptance.

**ADR 0016 §6 amendment (D88).** For an authorized repair replacement, the eligible committer excludes the requesting seat J and any admin without current verified TreeKEM state or required evidence.
The lowest eligible active-admin agent ID on the verified roster commits first, reachable or not (D74). D122 rules that D74 governs everywhere: "online" in D88 and 0088 §3 reads as "eligible on the roster". The others fall back after S4's window, under S4's Accepted hand-off and restart rules.
This widens S4's amendment of ADR 0016 §6 from revocation evictions to repair rekeys. Re-read current parent and request generation under the lock before sealing.
After restart, synchronize the head before serving or fallback. A landed terminal satisfies that generation; competitors must re-read it, not seal siblings.
Local locks do not form a distributed mutex. Timeout partitions may still race (D40); retain fork evidence/quarantine and manual exit for unanchored forks.

**Repair bounds (D89).** The **repair bound** is S4's Accepted designated window plus its completion bound plus 120 s for terminal delivery and install.
It bounds every verified-marker hold on a receiver, J's buffered candidate and J's repair completion. Each node persists its deadline when it first verifies the marked removal.
At most three links (remove, add, role) are buffered, within the existing control-blob byte cap. Each physical exchange, including the sealer lookup, is capped at `min(now + 10 s, artifact deadline)`.
ADR 0107's poll windows and its 10-minute staging lifetime stay unchanged. The final numbers follow S4's timing ruling (D69).

**Leaf replacement acceptance rule (D86, D136).** A designated admin may replace a never-confirmed seat's leaf without a new invite only on recorded never-confirmed evidence that it verifies itself. D136 rules that this evidence is the **admission-time obligation marker**, with these necessary conditions:
- the seat's current generation carries a verified `AdmissionReceiptObligationV1` (below);
- J's S8(b) record shows the attempt for that generation as `Unconfirmed` (or `LegacyAuthorityPending`) since before its start was acknowledged, and never `Confirmed` or `LegacyCompatible`. J's signed request carries that state, although no other node can check it;
- the designated admin holds no verified receipt and no `AuthorityReceiptVerifiedV1` record for that generation, locally or through the receipt query (§2);
- current entitlement, current admin authority and complete chain validation.

Absence of a receipt alone is never evidence, and J's assertion alone is never enough. A seat without a valid marker, including every seat sealed before the upgrade, ends in `Refused(manual_reinvite_required)`, reason `no_never_confirmed_record`, and uses D43's manual exit (§6).

**Admission-time obligation marker (D136).** A capable authority that seals a seat after its host commit, for a joiner whose current verified advert sets `authority_rewelcome_v1`, attaches an additive, serde-defaulted `AdmissionReceiptObligationV1` to the seating event.
The committing actor signs its canonical, length-delimited transcript with its agent key in the separate `x0x/authority-rewelcome/admission-obligation/v1` domain. It binds group ID, the actor ID, J's agent ID, the seating commit's `state_hash`, `prev_state_hash` and `revision`, J's committed KeyPackage hash, and `unreceipted_replacements`, the seat's budget count (§4). Like the repair mandate, it lies outside `GroupStateCommit.signable_bytes` and is protected by its own signature (`src/groups/state_commit.rs:476–497`).
It travels on every chain path: the sealed event log, `member_recovery_history`, 0106 `intervening_events` and S5 holder fetch. Any admin verifies it against the seating commit's `committed_by` actor and that actor's Admin seat at the parent, so it works while the sealer is offline. J finds its own marker by seat generation and KeyPackage hash.
Every seating event a capable authority produces carries a marker, the repair add included.
A stripped, garbled or transplanted marker fails, is ignored and is counted by reason. The seat is then treated as having none, which can only push it to the manual exit. Forging a marker needs the sealer's agent key. A legacy sealer or a legacy joiner gets no marker.
**Security (L4):** this is a new acceptance rule. D39 and 0088 say “re-Welcome”, not this removal/add rule. The marker proves that a capable authority sealed this exact seat and expects a receipt, and the receipt check refuses any generation an admin has verified as confirmed. D136 accepts the residual: a post-upgrade J that installed its keys and then withheld its receipt can still trigger at most two replacement seals (D90), then the manual exit.
Replacement never admits a new identity, gives the seat a different role or skips a chain check.
**Mixed versions:** legacy decoders ignore the additive field, and seats sealed by released binaries carry none.

**Repair mandate (D87).** `RepairMandateV1` uses its own `x0x/owner-axis/repair-mandate/v1` signature domain, never the invite-secret mandate domain.
Bind owner user ID, group/genesis, authority ID, J, request digest, original and replacement seat generations, requested KeyPackage hash, parent commit hash, expected terminal roster hash, both native epochs, certificate digest, policy hash and exact terminal role.
The original generation is the seating commit hash. Derive the replacement generation from the domain-separated request digest, parent and KeyPackage hash; it is not the hash of a commit containing the mandate. The expected terminal hash is the roster projection hash, not the enclosing state commit hash, avoiding a circular signature preimage.
The owner-device form is signed by the loaded matching owner USER key; it consumes no new or fabricated `invite_secret`.
A promoted admin without that key signs the **promoted-admin form** (D87) with its agent key, in its own `x0x/owner-axis/repair-mandate-admin/v1` domain, with the same bindings.
A receiver accepts that form only if the signer holds a current Admin seat at the owner-anchored parent, the bound policy hash matches that parent's owner policy, and every member of the expected terminal roster has a valid owner certificate against that owner. It never pretends an agent certificate delegates USER signing authority.
**Exception to ADR 0064 Decision §1 (D87, ruled by D146).** 0064 §1 requires an owner USER-key `OwnerMandate` on an owner-axis `MemberAdded`, and its §1b state machine refuses an absent mandate from a recorded-capable authority after grace. The promoted-admin form relaxes this for exactly one case: a repair `MemberAdded` that restores an existing seat under §3's bindings. A valid `RepairMandateV1` of either form satisfies 0064 §1 for that add only. Every other add is unchanged and still needs the USER-key `OwnerMandate`.
**Security (L4):** this is a new mandate acceptance rule, for repair only. Either form authorizes one replacement of one existing seat, bound to its request, parent, generations, KeyPackage and exact role.
It never admits a new identity, gives the seat a different role or policy, or stands in for an owner mandate on an ordinary add. The certificate check bounds the promoted-admin form to the owner's current members.
S2 (0108) is required to supply every member's certificate bytes (#1023/#1143); S5 handles unavailable evidence and owns its typed wait.
Never omit the mandate and rely on grace. A recorded-capable receiver past grace otherwise rejects `MemberAdded` as `owner_mandate_missing` (`named_groups.rs:11675–11750`).
Before replacement starts, require a current verified `authority_rewelcome_v1` advert from **every current roster member that may receive the chain**, including offline survivors. A member without a current advert is legacy for this check; cached capability cannot establish offline support. Any missing support returns `Refused(repair_receiver_upgrade_required)` without removal, naming each member without a current advert.
D87 accepts this capability floor as an explicit L1 limit in mixed groups. It is part of §6's named §2 entry, and it clears when those adverts appear.

Prepare removal/add on cloned named/native state. Remove the old leaf, then add the requested KeyPackage at the next epoch; preserve group ID, policy, data and certificate commitments.
Repair `MemberAdded` uses **`welcome_ref` only, `treekem_welcome_b64: None`**. Never put the Welcome or a key-bearing wrapper on metadata gossip.
Carry `RepairMandateV1` **inside the chain-carried repair `MemberAdded`**, in a new optional `repair_mandate` field with `#[serde(default)]`; absent on ordinary adds, ignored by legacy decoders. Group events have no signature of their own: only `GroupStateCommit` is signed, and its `signable_bytes` covers commit fields, not this additive field (`src/groups/state_commit.rs:476–497`). The mandate is protected by its own domain-separated signature and bindings. Keep it in the sealed event log and `member_recovery_history`, not only the direct response wrapper.
Mark repair `MemberRemoved` with an additive, serde-defaulted `RepairRemovalMarkerV1`. The committing actor signs its canonical, length-delimited transcript with its agent key in the separate `x0x/authority-rewelcome/removal-marker/v1` domain. Bind group ID, committing actor ID, removal target J, the removal commit's `state_hash`, `prev_state_hash` and `revision`, request digest, both seat generations and expected terminal roster hash. It identifies the matching add and any required role-restoration link.
The gated recovery response carries the complete signed sequence. On **every apply path**, first perform ordinary removal commit, chain and actor-authority validation. Hold the removal only if the marker's signature and all bindings verify against that exact commit and target, using the verified agent key of its `committed_by` actor. An absent, malformed, transplanted or otherwise failing marker is ignored and counted by reason; apply the valid commit as an **ordinary removal**, never suppress it or wait for an add because of that marker. Stripping or garbling a real marker can cause a brief ordinary removal before a valid add re-adds J under ordinary chain and mandate checks; it cannot defeat revocation.
For a verified marker, hold live roster/native state unchanged only within the repair bounds (D89), showing the typed wait `repair_pending_verification` with the missing link and the deadline, while the matching add, embedded mandate and required role restoration verify. Validate the whole sequence on clones, then persist/apply **all-or-nothing**. If the add/mandate is absent, invalid or mismatched, it cannot restore J; if the complete sequence has not verified by the bound, persist/apply the committed removal and its native exclusion state, end pending work as `RepairRemovalApplied(add_not_verified)`, and cancel J's attempt. A conflicting chain instead records fork evidence and enters typed `ForkQuarantined`; it must not continue service at the old epoch. Never hold indefinitely; retries or restart cannot extend the persisted deadline.
These rules cover direct wrappers, offline-member catch-up, chain replay, 0106 `intervening_events`, S5 holder fetch and `member_recovery_history`. A lone repair add cannot bypass a pending verified removal or ordinary chain checks. After fallback applies the removal, any late add must pass ordinary contiguous-chain, current-authority and mandate validation; the expired repair cannot grant terminal confirmation.
0106 retains its Accepted add-only carry bounds: a gap containing the marked removal requires S5, rather than widening 0106 or accepting only the add. An add-only carry still preserves and verifies the embedded mandate wherever applicable.
Do not gossip the repair pair; initially publish it by targeted pinned direct delivery. Later catch-up must carry the same signed fields and use the same atomic apply rule. Legacy decoders ignoring additive fields is decode compatibility only: any legacy or unadvertised member blocks sealing, so publish neither half to it.

| Original role | Replacement rule |
|---|---|
| `Member` | Ordinary `MemberAdded` restores Member exactly. |
| `Admin` | Append ordinary `MemberRoleUpdated(Admin)` within the atomic terminal sequence. |
| Legacy `Owner` | `Refused(repair_role_not_restorable)` with D43's remedy (§6, D138); Owner is not assignable (`src/groups/member.rs:24–25`). |
| `Moderator` or `Guest` | Same typed refusal; current role assignment accepts only Admin/Member. In particular Guest→Member would widen privilege. |

No unsupported role enters preparation; a role changing concurrently invalidates the prepared sequence.
Persist the entire sequence, terminal crypto snapshot and generation before publication. Failed preparation/persist publishes nothing and preserves original usable state.
Crash recovery completes one recorded transaction; re-sync the head before delivery and suppress obsolete publication. Competing committed heads retain fork evidence.

J keeps keyless repair bookkeeping only for its outstanding bound request.
Treat a removal with a verified commit-and-actor-bound marker as completed repair only after the contiguous chain adds J with the requested KeyPackage and a valid bound mandate within the repair bound.
Until then buffer the candidate sequence within the same persisted bound, grant no membership or keys, and show `repair_pending_verification`. If the full sequence does not verify by the bound, apply the committed removal and native exclusion state with `RepairRemovalApplied(add_not_verified)`, or record conflicting-chain evidence as `ForkQuarantined` without old-epoch service; never retain an indefinite pending removal.
A genuine removal with an absent or failing marker is applied immediately through ordinary chain validation and cancels the attempt; ignore and count the marker. The commit authorizes removal independently of the marker, including S4 revocation eviction and ban.
J buffers at most one candidate per attempt: at most three links (remove, add, role) within the existing control-blob byte cap, for at most the repair bound (D89). No unbounded event history.
Only its terminal Welcome may be installed, without skipping links or adopting across a gap.
Epochs between the original seat and replacement were **entitled but never installed**. They are not 0088 §2 item 4's never-admitted epochs; catch-up remains subject to current eligibility and S3/S5. Their ciphertext stays unreadable to J, because D60 lets holders deliver only the current epoch secret. J shows `history_gap {from_epoch, to_epoch}`, a named §2 entry with no exit (§6, D168).

### 4. All egress, repair budgets and triggers

Every class-R and class-K byte uses **`Agent::send_direct_pinned_admitted`**, or a path with the same single-exchange seam properties, unconditionally.
This includes the recovery response, staged-result wrapper, replacement Welcome, every control-blob chunk, GSS reseal and survivor share when removal rotates a secret.
Never use `send_direct_with_config`, metadata topics, inbox or relay for those bytes. Each physical retry is application-owned and admitted afresh immediately before its write; no hidden transport resend or gossip fallback.
Select artifacts and check eligibility under the membership lock. Register egress before release; ordered invalidations quiesce, abort and await all tasks/streams before committing the invalidation.
The synchronous write seam rechecks current roster, agent/machine revocation, pairing, time, staging and certificate evidence without blocking. Contention withholds, then retries through fresh admission.
Use fair per-group/global admission, duplicate coalescing, per-exchange deadlines and a whole-task deadline. Timeout resets unfinished streams and releases tickets/handles generation-safely.
Each exchange uses #1190's `min(now + 10 s, artifact deadline)` cap (D89); retries cannot extend the artifact/task horizon.

For each delivery/resend require Active, no ban/revocation, valid current machine binding, and no withdrawal, deletion or quarantine.
OwnerCertified recipients require a roster-embedded valid certificate or current `Clean` verdict; `DigestPending`, `InGrace`, invalid/unknown evidence fails closed. Discovery evidence cannot replace roster certificates.
For class K additionally require the **current secret epoch** (D60), including all survivor shares; do not reuse a join-only admission predicate for survivors.
Purge definitive invalidations and obsolete epochs; withholding retains only bounded pending work. Bytes already handed off cannot be recalled.
The [lifecycle note pinned to e645ce2](https://github.com/saorsa-labs/x0x/blob/e645ce2/docs/design/join-artifact-serving-lifecycle.md) on [PR #1190](https://github.com/saorsa-labs/x0x/pull/1190) defines the serving seam and its evidence; it is not yet proof of main's implementation.
**S8(b) code waits until that admitted path and its required lifecycle fixes are on main.**

Before ML-DSA verification, apply cheap frame/binding checks, duplicate digest lookup and a rate limit keyed by authenticated `(group, member)` (not spoofed body IDs): one request per 30 s, burst two (D90). #656 motivates limiting verify cost.
A dropped request gets an unsigned typed `RateLimited(retry_after)` on the same authenticated exchange, which costs no signature; J shows `waiting_for_rate_limit` until then.
Maintain a durable per-seat repair budget across nonce changes, attempts, expiries, replacement generations and restarts: at most two automatic replacement seals without a receipt (D90). Reset only after verified completion/receipt, not staging expiry.
**Budget evidence (D137).** The budget must survive restarts, sidecar loss and history pruning. So the count is signed into the seat's own admission-time marker (§3) as `unreceipted_replacements`:
- 0 for an ordinary admission;
- for a repair add, 1 if an admin holds a verified receipt for the previous generation, otherwise the previous generation's count plus 1. A committing admin that cannot find the previous generation's receipt record counts it as unreceipted (fail closed).

The designated admin applies resets before it reads any marker:
- If it holds, or the receipt query returns, a verified receipt or `AuthorityReceiptVerifiedV1` for the seat's current generation, the seat is confirmed and its budget is fresh. No marker is needed. Every §7 repair is this case, because §7's check 2 requires that evidence.
- Only for an unconfirmed current generation does it read the count from that generation's marker; a count of 2 means `repair_budget_exhausted`. Never-confirmed repair requires that marker anyway (D136), so its budget needs no older history. If the seating event has been pruned from every holder, no never-confirmed repair runs, and the seat ends `no_never_confirmed_record` with D43's exit.

No new refusal is needed. The sidecar copy is a cache of this count.
A missing receipt retries the same result first. After a failed replacement delivery, back off 1 minute, then 10 minutes for each later failure (D90); J and the authority show `waiting_for_repair_backoff` with its end time.
Exhausting the budget returns `Refused(repair_budget_exhausted)` with D43's manual exit (§6). Rate-limit, budget and backoff state all survive restarts.
**Retention (D137).** Keep a seat's limiter, budget and backoff record while that seat generation is on the roster and unconfirmed. Delete it when a receipt for that generation is verified, keeping only that generation's `AuthorityReceiptVerifiedV1`. Keep an exhausted budget until an ordinary removal, a ban or a signed group deletion, so restarts, nonces and new attempts cannot reset it; D43's fresh invite then starts a new generation with a new budget. Drop limiter entries for identities that leave the roster. The sidecar holds at most one record per current `(group, member)` and per current `(group, forwarding admin)`, plus pending removals.
Counters include preverify rate-limit drops, verifies, duplicate/coalesced requests, staged hits/misses, replacements, missing receipts, backoff waits, budget exits, mandate/role refusals, admitted/withheld/purged bytes, deadline resets and persistence writes.

Triggers are explicit: verified request intake; the existing S4 worker after hand-off/fallback deadline; startup sidecar reconciliation after host commit; staging expiry/delivery failure; receipt retry; a later eligible attempt resuming bounded work; and a member entering 0109's `readmission_required` or 0111's `catchup_beyond_retention` (§7).
No separate unbounded recovery loop or authority history is added. S4 worker and startup scan are required, not contradicted by that statement.
Admin absence exposes `waiting_for_admin` (0088 §2 item 3) and holder absence `waiting_for_holder` (§2 item 8), each naming what it waits for. Restoration of eligibility wakes retained work; cache loss is not an I8 exception.

### 5. Capability, storage and mixed versions

Name `authority_rewelcome_v1` / `CapabilityRegistry::AUTHORITY_REWELCOME_V1`: requests, forwarding carriers, responses, receipts/verification records, repair mandate and atomic repair acceptance are implemented together.
Its number is **allocated at acceptance, in acceptance order, as the next free bit in the README registry**. No numeric bit or registry row is added now.
Require current verified machine-bound adverts before either side sends a new payload. Advertise only when the whole protocol is ready.
Unknown/expired/card-only/absent support exposes a typed upgrade reason; it never licenses a probe with an unknown payload.

Keep **both legacy JSON stores as parseable raw maps**. S4/0110 and S6/0112 each own their sidecars; no shared envelope or merged slice state.
For each `Unconfirmed` row on J, write an inert entry in **both `named_groups.json` and `home-suite-groups.json` wherever the row appears**. No real seated Home-Suite entry may override the named placeholder on released load.
The placeholder keeps `members_v2` **non-empty**, with every entry `Removed` and **no entry at all for J**. Retain a non-J roster identity as Removed; if none exists, omit the row from both files instead. An empty roster is forbidden: released `migrate_from_v1()` would seat the creator as Admin.
Keep only pending local `invite_lineage` with `seated_at_revision: None`, no withdrawal or quarantine, and no secret, key/snapshot reference or invite-minting state. Released #1148 must classify it as `UnseatedJoinRemnant`, so a fresh invite can clear it and start a new join. Never erase genuine withdrawal, removal, ban or fork evidence to manufacture this placeholder.
For Home-policy groups, preserve released-compatible Home identity/policy metadata and the canonical owner-sync pointer where present.
**Home activation (D81).** S8(b) writes a Home placeholder only after released v0.45.0 and v0.46.1 binaries, including runs with no owner-sync pointer, show no duplicate Home and no `home.json` change through reload and provisioning (Validation).
If any of those controls fails, Home activation stays blocked. Home groups then get no S8(b) placeholder or record and keep today's join paths with S8(a)'s typed outcomes, and a repair request for a Home seat ends in `Refused(home_activation_blocked)` (§6).
A default-policy, `home = None` placeholder alone never establishes safety.
Keep verified remote roster/seat-generation evidence in the S8(b) sidecar, not a forged signed projection. Authority-side rosters keep their real seats; local confirmation is separate.
Keyed `Unknown` and `Confirmed` rows retain their valid legacy membership/keys; `ConfirmedKeysMissing` exposes no secret.

Use `<data_dir>/authority-rewelcome.rwstate`, magic **`X0RWS1\0\0`**, followed by a canonical bincode `AuthorityRewelcomeStateV1` body.
The body is `AuthorityRewelcomeStateV1 { version, rebuilt_from, records }`, in that order. `version` is a `u32` equal to 1. `records` holds bounded records keyed by `(group, member)` containing local state, verified base, generations, attempt/outcome, signed receipt, one repair obligation, budget/backoff and delivery phase.
A prepared transaction uses `<data_dir>/authority-rewelcome-<transaction_id>.rwjournal`, magic **`X0JRW1\0\0`**, and canonical bincode `AuthorityRewelcomeJournalV1 { version, rebuilt_from, transaction_id, group, expected_parent, request_digest, old_generation, replacement_generation, signed_sequence, terminal_crypto_snapshot_ref, legacy_raw_map_bytes, sidecar_state, phase }`. `phase` includes a terminal value `Discarded { head_committed: bool }`.
**`rebuilt_from` (ADR 0108 §5a).** In both V1 bodies it is the second field, right after `version`: a vector of at most 255 `[u8;16]` §5a transaction IDs. The bound is a decode limit; a longer vector is damage. An ordinary write keeps the field as it is, and the next rebuild replaces it. A file written outside a rebuild has an empty vector. If more than 255 pending copies verify, step 4's replacement lists the first 255 in `txid` order, and the rest are finalized as history in the same pass beside the valid replacement (ADR 0108 §5a, Coverage).
There is **no released predecessor** for either type. Freeze V1 decoders once released.
**Header layout (ADR 0108 §5a).** Both files follow ADR 0108 §5a's shared lifecycle; this ADR names only their layout. The family prefix is the first five bytes: `X0RWS` for `.rwstate`, `X0JRW` for `.rwjournal`. Each prefix is reserved for its file path forever. Byte 5 is the version field, one ASCII digit from `1` to `9`; bytes 6–7 are two zero bytes of padding, which end the header. The highest supported version is 1, and the body `version` must equal the header version, because a layout change always takes a new header version (ADR 0085). Versions above 9 need a later ADR to extend this layout before any release uses them. A valid header at version 2 to 9 is newer under §5a; every other non-supported form is damage.

No `PreparedMember` secrets are serialized; use 0107's deterministic identity derivation and existing crypto-snapshot custody. Journal references must bind the snapshot hash and transaction.

**Quarantine and rebuild (D120).** S8(b) quarantines a damaged `.rwstate` or `.rwjournal` by ADR 0108 §5a's transaction, resume, history and failure rules, at startup after host commit. Legacy service continues throughout. The table below is §5a's step 4 for these files: what the replacement is rebuilt from, and the outcome for local-only state that no holder has.
While step 4 runs, repair operations wait in the slice-only state `rewelcome_rebuilding {file, txid}`.
**Valid replacements.** A rebuilt `.rwstate` is a V1 file holding the table's rebuilt records, with `rebuilt_from` set to the transactions it covers. A damaged `.rwjournal`'s transaction is always discarded. Its replacement is a V1 tombstone at the same path: `transaction_id` from the file name, `rebuilt_from` set, `phase: Discarded { head_committed }` from the reconciliation, and every other field empty or zero. Replay treats a `Discarded` journal as a no-op. After §5a's step 5 has finalized the copy, ordinary retirement deletes the tombstone, a readable file. A later start then finds only history copies, which means no prepared transaction. A missing `.rwstate` after host commit, including one that has only history copies, is built from the same sources as on a first start; a missing `.rwjournal` means no prepared transaction.

Quarantined copies follow ADR 0108 §5a's retention rule (D148): they are never deleted automatically, except with the group's own files, and diagnostics list each copy and its size.
**This ADR amends ADR 0085 rule 4 for `.rwstate`, `.rwjournal` and their `.tmp-<txid>` replacement files only (D120).** Rule 4 leaves an unreadable file untouched and waits for an operator; S8(b) quarantines and rebuilds it under §5a, never deleting or truncating the original bytes. Rule 5 is not amended.

| State | Rebuilt from | Safe outcome when no holder has it |
|---|---|---|
| Seat generations, roster, admission-time markers, repair markers and mandates | The verified chain, through S5 holder fetch | Not applicable |
| `AuthorityReceiptVerifiedV1` records | Other admins, through the receipt query (§2) | `receipt_evidence_unavailable`; 0088 §2 item 8 while every holder is offline |
| Replacement seals without a receipt, per seat | Verified receipts first: a receipted current generation has a fresh budget. Otherwise the `unreceipted_replacements` count in the current generation's marker (§4), so an exhausted budget stays exhausted (D137) | If an unconfirmed seat's seating event is pruned, no never-confirmed repair runs (`no_never_confirmed_record`); §7 does not need the marker |
| Rate-limit buckets and backoff timers | Local only | Buckets start with no tokens, so the next request waits one 30 s interval. A seat with an unreceipted replacement on the chain waits the 10-minute backoff |
| Authority-side repair obligations and delivery phase | Local only | Lost. J's retained request re-creates the obligation on its next §4 trigger. A terminal whose Welcome was lost costs one more replacement seal, within the budget |
| A prepared `.rwjournal` transaction | Local only | Reconcile against the verified head. If its legacy `.journal` pair committed, the head stands and J's next request is served as above. If not, nothing was published. Either way the transaction is discarded |
| J's local attempt records | Local only | A keyed row becomes `Unknown` and keeps legacy service. A keyless seated row becomes `Unconfirmed` only if its seat carries a valid marker for J's KeyPackage hash; the receipt query and the D90 budget then bound it, as D136 accepts. Any other keyless row becomes keyless `Unknown`, with `no_never_confirmed_record` |
| J's unverified receipt; §7 voucher progress | Local only | J's next confirmation probe or request re-derives them |
| M's §7 retention-token wraps (D167) | Local only | Lost. While M is current, its next confirmation probe at a capable admin creates a new token and receipt. Behind retention, M ends `confirmed_keys_missing` with D43's exit |

In §5a's memory-only states (`sidecar_unavailable`, `sidecar_newer_format`, `sidecar_quarantine_failed`), S8(b) rebuilds from holders at each start, and budgets come from receipts and markers as above.
**Security (L4):** the rebuild adds no acceptance rule. Everything it restores is signed or re-verified, and lost local state only moves a seat toward the stricter outcome. **Mixed versions:** no released binary reads either extension.

Never put S8(b) state in `*.journal` or modify `TreeKemNamedPersistJournal`'s positional layout/raw-map body. Never put S8(b) state in Home's `*.hsjournal` namespace either.
First replay existing `.journal`/`.hsjournal` as today. After host commit, replay S8(b) `.rwjournal` and reconcile other slices' sidecars against the verified head before exposing repair operations.
If a legacy replay changed the head, reconcile or retain fork evidence; do not blindly overwrite it with an S8(b) snapshot.
Persist the `.rwjournal` transaction first. Publish the full terminal legacy roster/crypto pair through the existing unchanged `.journal` (and Home paired `.hsjournal`) transaction, never an intermediate removal-only view.
Embedded JSON remains a released raw map, with no S8(b) envelope or positional journal fields. Preserve the additive signed repair event fields wherever chain history is carried; legacy decoders ignore them. Then persist S8(b) state and mark delivery pending. Partial writes replay idempotently before serving.
On J, keep both legacy views inert and retain no installed legacy key/snapshot reference until durable confirmation. Prepared keys stay in the new transaction's custody.
The confirmed install uses the ordinary released-compatible roster/crypto transaction. Downgrade can therefore replay a complete compatible pair or retain J as a non-member, without needing `.rwjournal` replay.
Retire a completed transaction only after all required durable views agree. A downgrade during an incomplete transaction is an explicit W3-H crash/downgrade gate, not an assumed safe state.

**First behaviour-changing sidecar/journal write is after ADR 0094 host commit.** No startup scan, migration or lazy rewrite before that barrier. Pre-commit execution defers new repair, refuses new base-seated attempts as in §1, and writes only rollback-readable legacy state.
Old binaries ignore `.rwstate`/`.rwjournal` and parse both raw maps. Downgrade safety requires both loaded views to leave J a non-member with no keys or Active admin seat, while preserving the released fresh-invite exit; the controls below must prove this, including Home.
Old authority binaries cannot provide the new bounded recovery; they keep today's behaviour. Downgrade must not resurrect a partial repair or overwrite a newer verified head.
Re-upgrade verifies the sidecar, reconciles generation/roster/crypto state, classifies lost keys and resumes the bounded obligation. No format-induced startup refusal is acceptable.

| Direction | Behaviour |
|---|---|
| Old J → new authority | No new wire payload; ordinary Active replay remains a no-op, with D43's legacy remove/re-invite exit. |
| New J → old authority | Normal unseated admission stays legacy. Base-seated attempts use `LegacyAuthorityPending`: SignedPublic attempts, and encrypted attempts with usable keys, complete as `LegacyCompatible` (D84); encrypted keyless attempts end `TimedOut(authority_upgrade_required)`. SignedPublic rejoin compatibility is specifically tested. |
| New authority → old or unadvertised survivors | Repair returns a typed upgrade refusal before removal. Additive fields remain decodable, but neither half is sealed or delivered to unsupported receivers; never inline Welcome bytes. |
| New ↔ new | Bound confirmation/receipt, staged-first repair and one terminal per attempt. Stale gaps need S3/S5; new unseated any-admin admission needs S6. |

**Beyond retention (D97, D119).** A confirmed member behind every holder's retention is repaired by the retention re-Welcome (§7).

### 6. Typed blocks and the named §2 entry (L3, D64)

D64 makes L3 a hard rule for every slice. Every block S8(b) adds or touches ends in one of these typed states, and each names what it waits for.

| Block | Typed state | Exit |
|---|---|---|
| Attempt awaiting its authority | `waiting_for_authority_terminal`, naming the authority; at the poll deadline `TimedOut(<last wait>)` | Terminal pushed by the authority, or fetched on the next §4 trigger (§1) |
| Base-seated attempt before host commit | `Refused(host_commit_pending)` | Retry after ADR 0094's host commit |
| No capable authority | `authority_upgrade_required`; encrypted keyless: `TimedOut(authority_upgrade_required)` | A capable admin appears, `LegacyCompatible` (D84), or D43's remedy |
| Confirmed key loss | `Refused(manual_reinvite_required)`, `confirmed_keys_missing` | D43's remedy (D85) |
| No never-confirmed record | `Refused(manual_reinvite_required)`, `no_never_confirmed_record` | D43's remedy (D86) |
| Receiver without a current advert | `Refused(repair_receiver_upgrade_required)`, naming those members | Adverts appear, or D43's remedy (D87) |
| Role that cannot be restored | `Refused(repair_role_not_restorable)` | D43's remedy (D138) |
| Pre-verify rate limit | `RateLimited(retry_after)`; J shows `waiting_for_rate_limit` | The retry time (D90) |
| Failed replacement delivery | `waiting_for_repair_backoff`, with its end time | The end time (D90) |
| Repair budget spent | `Refused(repair_budget_exhausted)` | D43's remedy (D90) |
| Marked removal awaiting its add | `repair_pending_verification`, naming the missing link and the deadline | The verified sequence, or `RepairRemovalApplied(add_not_verified)` at the repair bound; a late add passes ordinary validation |
| Conflicting chain | `ForkQuarantined` | An admin's manual act (0088 §2 item 7) |
| Receipt evidence missing | `receipt_evidence_unavailable` | The record arrives through the gated exchange or S5; 0088 §2 item 8 while every holder is offline |
| No admin or no holder online | `waiting_for_admin`, `waiting_for_holder` | 0088 §2 items 3 and 8 |
| Home activation blocked | `Refused(home_activation_blocked)` | The released-binary controls pass (D81), or D43's remedy |
| Confirmed member behind retention | `waiting_for_authority_terminal` with cause `beyond_retention`, then `readmission_pending_vouchers {vouchers, asked}` | §7's terminal and its second voucher; 0088 §2 item 8 while every voucher holder is offline |
| Admin can still serve catch-up | `Refused(catchup_available)` | S5 or S3 catch-up resumes (§7) |
| No confirmation record | `Refused(manual_reinvite_required)`, `no_confirmation_record` | D43's remedy (D166) |
| No second voucher possible | `Refused(manual_reinvite_required)`, `readmission_uncorroborated` | D43's remedy (D166) |
| Retention token missing or wrong | `Refused(manual_reinvite_required)`, `confirmed_keys_missing` | D43's remedy (D85, D167) |
| Skipped-epoch ciphertext | `history_gap {from_epoch, to_epoch}` | None: a named §2 entry (D168) |
| Sidecar rebuild | `rewelcome_rebuilding {file, txid}` | §5a's step 4 ends (§5) |
| Sidecar memory-only | `sidecar_unavailable {file, cause}`, `sidecar_newer_format {file, version}`, `sidecar_quarantine_failed {file, txid, step, error}` (ADR 0108 §5a) | Not a block: S8(b) runs from a memory-only rebuild and retries at the next load; a re-upgrade restores a newer file |

**Named §2 amendments (D118, D166, D168).** This ADR amends ADR 0088 §2 with two named entries. David ruled the first entry's reasons through the options he chose in D81, D84, D85, D86, D87, D90, D136, D138 and D166, and confirmed the entry in D118:

- **S8(b) manual-exit repair.** Automatic repair or base-seated completion of a seat may end in a typed terminal refusal whose exit is D43's remedy, for exactly these reasons: `confirmed_keys_missing` (D85); `no_never_confirmed_record` (D86, D136); `repair_budget_exhausted` (D90); `repair_receiver_upgrade_required` (D87); `TimedOut(authority_upgrade_required)` for an encrypted keyless attempt with no capable authority (D84); `home_activation_blocked` (D81); `repair_role_not_restorable` (D138); and §7's residuals `no_confirmation_record` and `readmission_uncorroborated` (D166).
- **Exit:** D43's remedy. An admin removes the member while it is online; the member restarts and redeems a fresh invite. That is ordinary admission, which completes under L1. The two upgrade reasons also clear by themselves when the missing adverts appear, and the retained record then retries.
- A **confirmed** member behind every holder's retention is no longer in the D43-only class: §7 repairs it (D119). Only §7's two residuals keep the manual exit (D166).
- In L3's terms this is a waiting entry: the refusal is typed and visible, and it names the act it waits for.

The second entry, ruled by David (D168):

- **Skipped-epoch ciphertext.** A member re-seated by §3 or §7 cannot decrypt ciphertext from the epochs between its old seat and its new one. Those epochs were entitled, so §2 item 4 (never admitted) does not cover them. Holders cannot help, because D60 lets them deliver only the current epoch secret.
- **Typed state:** `history_gap {from_epoch, to_epoch}`, shown on the member's group info and history APIs. It is definitive.
- **Exit:** none for that ciphertext. Current store state, such as KV images, still arrives through S5 (D94).

0088 is Accepted and is not edited; both entries take effect when this ADR is Accepted.

### 7. Retention re-Welcome for confirmed members (D119)

**Name.** The **retention re-Welcome** is S8(b)'s repair for a confirmed member behind every holder's retention. ADR 0109's `readmission_required {cause: base_beyond_retention}` and ADR 0111's `catchup_beyond_retention` route to it by this name.
D97 treats the case as admission, and D119 puts it in S8(b), against the recommendation. It reuses §2's exchange, §3's atomic replacement, marker, mandate and role table, and §4's egress and budget. Only its trigger, its evidence and the member's acceptance rule are new.

**Trigger.** Member M enters one of the two states above. M sends a signed `AuthorityRewelcomeV1` request with cause `beyond_retention`, its last verified head (`revision`, `state_hash`) and a fresh KeyPackage, through §2's fan-out. Retries follow §4's triggers and D90's limits.

**Evidence.** The designated admin (D74, D88, D122) checks all of these itself:
1. **Seat:** M is Active on its current verified roster, with a current machine binding, and is not banned, revoked, withdrawn or quarantined. An OwnerCertified M needs a valid certificate, as in §4.
2. **Confirmation:** a verified receipt or `AuthorityReceiptVerifiedV1` exists for M's current seat generation, held locally or fetched by the receipt query. If none exists: `Refused(manual_reinvite_required)`, reason `no_confirmation_record`.
3. **Keys:** M must show that it kept its installed group-key state, not just its identity. A challenge to M's leaf key proves nothing here: TreeKEM leaf identity keys re-derive from the agent secret (`src/mls/treekem.rs:19–25`; `named_groups.rs:27196–27198`), so a member that lost its group snapshot can still answer one. M proves it with its **retention token** (below, D167). A missing, unwrappable or mismatched token is confirmed key loss: `confirmed_keys_missing` (D85), and nothing is sealed.
4. **Beyond retention:** the admin's own retained log lacks the commit after M's claimed base, and M's current seat was seated before the admin's `oldest_held_revision`, since no base can be older than M's own seating. Otherwise the admin answers `Refused(catchup_available)` and serves S5 or S3 catch-up. No rekey follows.

A SignedPublic M holds no keys. The admin skips check 3, seals nothing, and returns a signed terminal head for M to adopt under the voucher rule below.

**Retention token (D167).** This is the evidence for check 3 in an encrypted group. A SignedPublic member has no keys and no token.
- **Derive.** Each time M confirms a seat generation — the receipt after an installation (§2), the post-upgrade confirmation probe (§1), or the receipt after a §3 or §7 replacement — it derives `K_ret = blake3::derive_key("x0x/authority-rewelcome/retention-token/v1", canonical(epoch_secret, group_id, seat_generation))`. `epoch_secret` is the same confirmed-epoch secret the receipt MAC uses (§2), and the canonical fields are length-delimited.
- **Commit.** The receipt binds `retention_commitment = blake3::derive_key("x0x/authority-rewelcome/retention-commitment/v1", K_ret)`. The verifying admin's `AuthorityReceiptVerifiedV1` binds the same value, so any admin can check it later without the receipt or an old epoch secret. Each token belongs to exactly one receipt, named by its digest and epoch. A later receipt for the same generation, at a later epoch, carries a new token; an admin keeps the newest record it holds per generation (D137), so another admin may still hold an older one.
- **Keep.** M stores `K_ret` only wrapped, in its `.rwstate` record for that seat, keyed by its receipt's digest and epoch. The wrap is XChaCha20-Poly1305, which x0x already uses for sealed KV and CRDT state, with a random 24-byte nonce. Its key is `blake3::derive_key("x0x/authority-rewelcome/retention-wrap/v1", canonical(epoch_secret_of_current_epoch, group_id, seat_generation))`, and the associated data is `(group_id, member, seat_generation, wrap_epoch)`. The plaintext `K_ret` is never persisted.
- **Holds.** Every admin answer to a receipt, an ACK or the typed `receipt_epoch_unverifiable`, names `holds`: the receipt digest of the `AuthorityReceiptVerifiedV1` that admin keeps for M's generation, or none. M records each eligible admin's latest `holds`. A token is acknowledged when M holds an ACK from an admin that persisted its record.
- **Which tokens M keeps.** Per generation, M tracks two slots for each eligible admin X, plus the outstanding token, and keeps exactly the tokens in some slot:
  - **named(X):** the token named in X's latest `holds`, if any. The newest acknowledged token is always named, by its ACK;
  - **pending(X):** the newest token delivered to X after X's latest answer, if any, because X may have verified that receipt and lost the answer. A new answer from X clears pending(X). When M assigns X a new pending token, X's older pending token leaves that slot; M drops it unless another slot still holds it;
  - **outstanding:** the one receipt M is still trying to get answered.

  Each admin fills at most two slots, so M holds at most **2E + 1** tokens, where E is the number of eligible admins on M's verified roster. A token leaves named(X) only when a newer answer from X replaces it, and that answer reports X's current record. So M never drops a token that an admin's latest answer reports, and every record an admin last reported has its token kept. Every kept token is listed for reveal.
- **Refresh.** An outstanding receipt that can no longer be verified would otherwise block every later confirmation. This happens when it is delayed until every admin has discarded that epoch's MAC material, for example after a GSS rotation, even though M holds current keys.
  - M abandons it and starts one fresh confirmation for its current epoch once at least one eligible admin has answered `receipt_epoch_unverifiable` for it, and every other eligible admin M can reach has answered the same or timed out at the exchange cap (§4). An unreachable, offline or timed-out admin never blocks a refresh.
  - The abandoned token stays as that silent admin's pending token if it was delivered to one. Otherwise it is dropped unless an answer names it.
  - If no eligible admin answers at all, M keeps retrying in `waiting_for_admin` (0088 §2 items 3 and 8).
  - Otherwise M keeps retrying the exact outstanding receipt and starts no other confirmation for that generation.
- **Residual.** An admin that stays reachable but times out through several refreshes keeps only its newest pending token. It may hold an older receipt's record that M dropped. When online it can fetch a kept token's record from any other holder by the receipt query. If every holder of a kept token is offline at §7 time, the designated admin waits in `receipt_evidence_unavailable` (0088 §2 item 8).
- **Re-wrap.** When M installs a new epoch for that group, it first writes `.rwstate` holding, for each token it keeps, both the old wrap and a new wrap under the new epoch's key, durably. Only then does it persist the new epoch's crypto snapshot. It drops the old wrap on a later write, after that snapshot is durable. A crash at any point therefore leaves at least one wrap that the durable snapshot can open. If both wraps are lost, the token is lost, and the case reads as key loss (fail closed).
- **Reveal.** For check 3, M's signed reply first lists the receipt digest and epoch of each token it keeps. The designated admin picks one, newest first, for which it holds or fetches by the receipt query (§2) the `AuthorityReceiptVerifiedV1` of **exactly that receipt**. M then unwraps that token with its last installed epoch's secret and returns `K_ret` once, in its signed reply on the gated pinned exchange, bound to the request digest and to that receipt's digest and epoch.
- **Compare.** The admin recomputes the commitment and compares it in constant time with the commitment in that exact record. A record for another receipt of the same generation is never a mismatch: it means the admin must fetch the named record first.
  - While no named record can be fetched and an admin that may hold one is offline, the state is `receipt_evidence_unavailable` (0088 §2 item 8).
  - If every eligible admin answers that it holds none of the named records, the case is `no_confirmation_record` (check 2).
  - Only a different commitment in the exact named record is `confirmed_keys_missing`.

  A token is used once: the replacement starts a new generation, whose next receipt carries a new token.
- **Security (L4).** `K_ret` is a domain-separated KDF output; revealing it exposes no epoch secret. Only a member that kept its snapshot at its last installed epoch can unwrap it. Losing the snapshot loses the token, so D85's manual exit still governs confirmed key loss. A third party cannot present it, because the reveal sits inside M's signed reply over M's verified machine. Residual: a member that lost its snapshot could get `K_ret` from a colluding member that kept the confirmation epoch's secret. That buys only a rekey of a seat that is already Active, within the D90 budget.
- **Mixed versions.** S8(b) has no released predecessor, so every S8(b) receipt carries the commitment. A legacy confirmed member gets its token from its first post-upgrade confirmation probe; one that fell behind before any probe has no receipt and ends `no_confirmation_record` (check 2).
- **Cost.** One `.rwstate` write per installed epoch per group, and one receipt field.


**Rekey.** When all four checks pass, the designated admin runs §3's atomic replacement unchanged. It removes M's old leaf, adds the requested KeyPackage at the next epoch and restores M's role. It carries the removal marker, the Home repair mandate (D87) and §3's receiver floor, and survivors apply it under §3's verified-marker rules. The terminal response binds M's request digest, the terminal head and its roster projection hash.

**M's acceptance rule.** M cannot link the terminal head to its own last verified head; that is why it is behind retention. So M accepts the terminal as **admission**, not catch-up. It installs fresh group state at the terminal head, as a new joiner does, and never splices that head into the chain it held.
It does so only when the terminal has **two vouchers**: two distinct identities on M's last verified roster, other than M, that attest to the same terminal head.
- The signer counts as a voucher if it held an Admin seat on that roster.
- A holder counts when its S5 head answer (`group_head_v1`, ADR 0111), over a pinned direct exchange, equals the terminal head or chains forward from it. M checks that forward chain on a cloned state before it commits anything.
- In an owner-certified group, an owner-device `RepairMandateV1`, signed by the owner USER key that M already verified, is enough on its own. The promoted-admin form is not, because M cannot check the signer's current Admin seat.

While M waits for a second voucher, it shows `readmission_pending_vouchers {vouchers, asked}`. While every holder M can ask is offline, that wait is 0088 §2 item 8.
If M's last verified roster has no second identity that could vouch, and there is no owner anchor, M ends in `Refused(manual_reinvite_required)`, reason `readmission_uncorroborated`. A holder head that conflicts with the terminal is fork evidence: M installs nothing and enters `ForkQuarantined`.
On acceptance M installs the terminal Welcome, persists and sends its receipt (§2), and resumes ordinary S5 catch-up from the terminal head. It keeps keys only for epochs it already installed.

**Catch-up path.** After installation M is an ordinary member at the terminal head. Later commits come through S5's walk, and current store state, such as KV images (D94), comes from S5 holders. Ciphertext from the epochs M skipped stays unreadable, because D60 lets holders deliver only the current epoch secret. M shows `history_gap {from_epoch, to_epoch}` (§6, D168).

**Abuse budget.** D90 and D137 apply per seat, unchanged: one pre-verify request per `(group, member)` per 30 s (burst two), the same allowance per forwarding admin, at most two replacement seals without a receipt and then D43's manual exit, and backoff of 1 then 10 minutes. Check 4 caps truthful repeats: once M is re-seated, it cannot claim beyond retention again until retention moves past its new seat. M's voucher queries use S5's requester limits (D98).

**Security (L4).** This is a new acceptance rule on both sides.
- The admin side admits no new identity: M's seat is already Active on the admin's verified roster. Checks 1 to 3 keep out removed, banned, key-lost and unconfirmed seats, so §3's D136 rule still governs never-confirmed seats. The rekey is §3's, with its marker, mandate, receiver floor and budget.
- **Named relaxation of 0088 L4's TreeKEM adoption exclusion (D166).** 0088 L4 lists the TreeKEM adoption exclusion as fail-closed. David ruled this one relaxation of it: on M's side, M adopts a head it cannot link to its own last verified head. The relaxation covers only a confirmed member's §7 terminal, anchored by two vouchers from M's last verified roster or by the owner-device mandate. It never covers ordinary catch-up, 0106 carries or §3 repair. M adopts only as admission. It discards the old state, and two vouchers from its last verified roster, or the owner, must agree. A single removed former admin cannot fork M alone. The residual: two colluding identities from M's last verified roster can still mislead M, and later fork evidence still quarantines it.
- Egress uses §4's admitted path under ADR 0107's guard and D60. The voucher head queries use S5's serving guard (ADR 0111 §5).

**Mixed versions.** All of this sits under `authority_rewelcome_v1`; there is no new bit. A released M sends nothing, and its 0109 or 0111 state names D43's exit. Against legacy admins, M shows `authority_upgrade_required`. A legacy survivor triggers `repair_receiver_upgrade_required` (§3). A holder without S5's head query cannot vouch. Vouchers count only with current verified, machine-bound adverts.

**Harness.** W3-H case `s8b_retention_rewelcome` (Validation). §7's code also waits for S3's and S5's states and S5's head query on main.

## Consequences

### Positive

- Local status distinguishes a real seat, an installed join and missing keys without wedging keyed legacy members.
- Eligible staging-loss repair has a durable bounded exit under D86's, D136's and D87's acceptance rules.
- A confirmed member behind every holder's retention has an automatic exit (§7, D119).
- Legacy stores stay parseable on downgrade; S8(b) owns its new persisted state.
- Every block in this slice is typed and names its cause (D64).

### Negative / Trade-offs

- Replacement rotates TreeKEM and may need a role commit, atomic receiver support and new Home mandate validation.
- Receipt-less seats from before the upgrade cannot prove that installation never happened, so they keep the manual exit (D86, D136). Confirmed key loss keeps it too (D85): an explicit L1 gap, recorded as §6's named §2 entry.
- `LegacyCompatible` keeps today's checks, and today's exposure, toward legacy authorities (D84).
- Users keep hitting #1191's 409 until the full slice ships (D91).
- The retention re-Welcome rekeys the group and relaxes the TreeKEM adoption exclusion for one case, bounded by two vouchers or the owner (§7).
- The sidecar rebuild loses local-only state; §5 lists each safe outcome (D120).
- Direct-only delivery must prove Home/mixed-version liveness; partial-transaction downgrade needs explicit evidence.

### Neutral / Operational

- 0088's order is contract → S2 and **S8(a)/0107** → S4 and S3 → S5 → S6 → S7 (D65). **S8(b) is accepted after S4** (D88), not in the first batch; S5 does not wait for it.
- S2's certificate rule is a prerequisite for Home replacement code.
- Governed code requires this ADR Proposed on main, David's acceptance, W3-H red evidence and one `named_groups.rs` landing lane.
- Repair code also waits for Accepted/implemented S4 scheduling, S2 certificates, applicable S3/S5 recovery, and the #1190 admitted egress path on main. These gates also hold the #1191 fix, which ships with the slice (D91). §7's code also waits for S3's and S5's states and S5's head query on main.

## Validation

W3-H (#1164) does not yet exist. These are required specifications, **not completed tests**; recommend a dedicated tracking issue for these S8(b) cases.
Cases that expect leaf replacement need a seat sealed by a capable authority after its host commit, so that it carries the admission-time marker (D136). Every re-seat case also asserts `history_gap {from_epoch, to_epoch}` for the skipped epochs (D168).
Commit every red case and demonstrate it red on **main with S8(a)/#1190 merged** before S8(b) code merges. In-process tests supplement, never replace D16/D54.
Record full main SHA, #1190 merge SHA/ancestry, released artifact hashes, harness commit, schedule seed, public API transcript and exact red assertion per variant.
Current main is `3f09dda021e74c70ac3210f810193fadd43b74bc`; it does not contain `e645ce2` and is **not the eligible baseline**. No post-#1190 main SHA can yet be honestly pinned.
Selecting and recording that actual full SHA after merge is a mandatory unresolved gate; do not label this worktree or the old source-citation SHA the harness baseline.
Run only in the isolated loopback Linux namespace. All cases use a deterministic clock, explicit ordered delivery, dropped frames and restart cuts; no wall-clock sleeps as proof.

| Case / nodes | Public-API steps and delivery schedule | Exact baseline assertion → fixed assertion |
|---|---|---|
| `s8b_1150_staging_loss`: A admin, J | Create Home/TreeKEM via API; invite/join J, deliver an intermediate carry but drop J's result/Welcome. Advance past the poll deadline, then original 10-minute staging horizon. Retry via a fresh base-seated invite. Repeat no-carry, restart-A and no-retained-row variants separately. | Carry: typed `TimedOut`/`Refused`, no usable keys or bound recovery after cache loss, **not keyless Active** after S8(a). No-row variant: baseline can report Active without usable keys; no-carry variant: typed timeout and no usable repair. Assert each failing automatic-completion expectation separately. Fixed: bounded terminal confirmation, one leaf, durable keys and two-way encrypted traffic. |
| `s8b_any_admin_handoff`: A < D admins, J | Admit J, lose artifacts as above, take A offline; J fans request to D. Separate connected run sends request to both, delays designated A past 0110's Accepted window, then allows D fallback. Restart D after obligation persist and after terminal persist. | Promoted D cannot repair lost staging; J has no usable terminal Welcome by the repair bound (D89). Fixed: eligible lowest admin first, no early fallback, one connected terminal; restart re-syncs before resend. |
| `s8b_owner_mandate_past_grace`: O owner USER-key device/admin, E enforcing survivor, J | Create Home, seat E/J, record O as mandate-capable on E, advance beyond grace; lose J staging and request repair. O is designated committer. Deliver a removal with a verified marker followed by missing/invalid repair mandate in fault variants; then complete valid pair. Repeat with promoted D, O offline, all member certificates fetched through S2 APIs. **Catch-up variants:** take E offline after its current advert is verified, seal repair before that advert expires, then return E after delivery. Fetch the chain through offline-member catch-up and `member_recovery_history`; separately offer the add through 0106 `intervening_events`, then fetch the non-add gap through S5's public recovery API. Expire/remove E's advert before sealing in a separate capability control. | **Red:** baseline cannot repair; a naïve ordinary pair removes J then rejects add as `owner_mandate_missing`. Fixed on every direct/catch-up path: a verified-marker incomplete pair preserves roster/epoch only while bounded pending verification; at the bound apply removal/native exclusion with typed exit, or quarantine a conflicting chain without old-epoch service. A valid pair uses the add's embedded mandate and restores J past grace atomically. 0106 cannot skip the removal gap; S5 supplies the complete sequence. **Control:** no current E advert refuses with `repair_receiver_upgrade_required` naming E, before removal. The promoted variant uses D87's promoted-admin form; no fake USER signature or omitted mandate. **Promoted-form controls:** E rejects a form whose signer lacks a current Admin seat at the parent, whose terminal roster has a member without a valid owner certificate, or whose role or policy hash differs. |
| `s8b_removal_marker_tamper` **control**: A committer, H holder/relay, E capable survivor, J | Obtain an earlier valid repair marker for J. In separate runs, API-trigger a genuine S4 revocation eviction and a ban of J. H attaches a garbage or tampered marker, or transplants the earlier validly signed marker, onto each genuine removal without changing its commit. Include same-actor transplants and absent-marker controls; separately strip/garble a real repair marker before delivering its valid add. Exercise every applicable direct/catch-up/replay/history apply path, with E and J as receivers. | New-path safety control, not a claimed baseline red reproduction. Fixed: marker binds the exact actor, target, removal hashes and revision; tampered/transplanted markers fail and are ignored/counted, absent markers are counted separately. Genuine eviction/ban applies immediately with native exclusion and attempt cancellation; no add wait or continued old-epoch service. A stripped/garbled real marker permits at worst brief removal before a valid contiguous add re-adds J. |
| `s8b_marked_removal_no_add` **control**: A committer, E capable survivor, J | Deliver a genuine repair removal with its valid exact-commit/actor marker, drop every add, and advance the deterministic clock to the repair bound (D89). Repeat with invalid/mismatched add or mandate; retry and restart E/J while pending. Run separately with conflicting-chain evidence. | New-path safety control, not a claimed baseline red reproduction. Fixed: hold only before the persisted deadline; at the bound durably apply removal/native exclusion, expose `RepairRemovalApplied(add_not_verified)`, cancel J's attempt and release pending work. Conflict records evidence as `ForkQuarantined` without old-epoch service. Retry/restart never resets the bound; no indefinite hold. A late add requires ordinary chain/authority/mandate validation and cannot complete the expired attempt. |
| `s8b_staged_replacement_race` **control**: S original sealer, A designated admin, J | API join J through S and retain matching staging; fan J's recovery request to both S/A, delivering it to S first. A issues the bound lookup. Hold S's signed staged answer until after the 10 s lookup cap (D89); let A select and persist replacement, then release the old artifact before and after J's replacement result in separate schedules. Also deliver staging to A before the deadline, lose A's terminal ACK and retry. | Baseline has no S8(b) replacement; this is a new-path race control. Fixed: fan-out alone makes S emit no artifact to J; a late lookup answer cannot become a competing terminal or install the old leaf. One replacement terminal, one installed leaf, usable keys and two-way encrypted traffic. Staged-first variant retries the same terminal, seals no replacement and spends no replacement budget. |
| `s8b_1149_current_confirmation`: A, J | Admit J and mint base-seated invite; withhold add/ban from J. Ban J via API, redeem stale invite. Run no-row and carry variants in TreeKEM/GSS/SignedPublic. Repeat removal, agent/machine revocation, certificate expiry/verdict change and withdrawal. | No-row: baseline reports Active without a current bound authority decision (encrypted variants also lack usable keys). Carry: baseline ends typed `Refused`/`TimedOut`; assert **absence of a current request-bound authority refusal**, rather than unsafe keyed Active. Fixed: current bound terminal refusal, no keys/secure access, all variants. |
| `s8b_1191_attempt_exit`: A, J | Timeout J without carry, redeem base-seated invite, remove J on A, deliver removal, API re-invite on same running J. Schedule old finalizer after newer attempt starts. | Baseline POST join returns 409 `join_already_pending`. Fixed: new attempt starts; `NotApplicable`, superseded, cancellation and terminal cleanup cannot erase it. This case gates the slice's merge like every other case (D91); an in-process test may supplement it, never replace it. |
| `s8b_legacy_authority_compat`: A admin on released v0.46.1 (repeat on v0.45.0), J candidate | Create a SignedPublic group and a TreeKEM group on A via API; admit J, then mint invites whose base already seats J. Restart J on the candidate after simulated host commit and redeem. In the TreeKEM no-row variant drop every Welcome to J. Advance the deterministic clock past the poll deadline. Then upgrade A to the candidate after host commit and fire J's retained record. | SignedPublic is a **control**: the rejoin completes on baseline and must still complete, now shown as `authority_confirmation: legacy_compatible`, with two-way signed traffic. TreeKEM no-row is **red**: baseline reports Active without usable keys (#1149). Fixed: `TimedOut(authority_upgrade_required)` at the deadline, no keyless Active, a retryable record; after A upgrades, a bounded typed terminal. A seat sealed by the released binary has no admission-time marker, so it ends `no_never_confirmed_record` with D43's remedy (D136). A `LegacyCompatible` J never counts as `Confirmed`, a receipt or never-confirmed evidence. |
| `s8b_never_confirmed_evidence` **control**: A, D admins, J | (1) Seal J's seat on released v0.46.1, drop its Welcome, then upgrade all three after host commit. (2) On the candidate, confirm J, let A verify its receipt, then delete J's keys through a fault hook. (3) Inject a J-signed never-confirmed request for (2)'s generation, delivered to D. (4) Confirm J but drop its receipt before any admin verifies it, delete its keys, and inject repeated false requests across restarts. (5) Inject a J-signed never-confirmed assertion for (1)'s pre-upgrade seat, delivered to D. | Control for D86's and D136's rule, not a claimed baseline red. Fixed: (1) `Refused(manual_reinvite_required)`, `no_never_confirmed_record`, nothing sealed; D43's remedy then completes. (2) `confirmed_keys_missing`, no replacement. (3) D refuses after the receipt query; nothing sealed. (4) At most two replacement seals, then `repair_budget_exhausted`, across restarts. (5) D refuses `no_never_confirmed_record` and seals nothing (D136). |
| `s8b_poll_deadline_typed`: A candidate authority, J | API join J through A; hold A's terminal past J's 120 s TreeKEM poll deadline. Make the certificate fetch fail so A stages #946's `certificate_evidence_unavailable` at its 10-minute deadline. Deliver nothing else; make no manual retry. | **Red:** on baseline J's poll ends and J never sees A's later refusal. Fixed: J shows `TimedOut(waiting_for_authority_terminal)`, then the retained typed wait, then A's pushed typed refusal, with no manual retry (D64). |
| `s8b_admission_marker_tamper` **control** (D136): A sealer, D designated admin, H relay, J | Seat J on the candidate, with its marker, and drop its Welcome; take A offline. H strips the marker, garbles it, or transplants another seat's valid marker onto J's seating event, on each chain path in turn. | New-path control. Fixed: D verifies the genuine marker with A offline and replaces J's leaf once. Every stripped, garbled or transplanted marker fails, is counted, and ends `no_never_confirmed_record`; nothing is sealed. |
| `s8b_retention_token` (D167): A designated admin, D admin, B holder, both A and B with a commit-log cap of 4; M candidate member | Create a TreeKEM group via API, admit B and M, confirm M, and let A verify its receipt and commitment. Hold M, drive six commits and release it. Variants: (1) the main path; (2) delete M's crypto snapshot but keep its agent key and sidecar; (3) delete M's `.rwstate` wraps but keep the snapshot; (4) crash M during an epoch install after the double-wrap write, and again after the snapshot write and before the old wrap is dropped; (5) M sends a tampered token; (6) M replays a revealed token for the new generation; (7) A offline, so D fetches the verification record through the receipt query; (8) **delayed receipt:** M re-probes at a later epoch, and its new receipt reaches A only after M falls behind, so M holds the acknowledged old token and the unacknowledged new one; run again with the new receipt verified by A but its ACK to M lost; **control:** after one acknowledged receipt, trigger several more confirmations while every ACK to M is lost, so M starts no second outstanding receipt, retries the same one, and never holds more than 2E + 1 tokens; **delayed-first-receipt control:** hold M's first receipt until a GSS rotation makes every admin discard that epoch's MAC material, then deliver it, once with admins answering `receipt_epoch_unverifiable` (M drops it and refreshes) and once with no answer from any admin (M waits in `waiting_for_admin`, then refreshes on the first typed answer); the fresh receipt is acknowledged, tokens that no answer names are dropped, and a later §7 completes on the fresh token; **refresh then ACK loss:** A verifies R1, keeps only its record and loses its ACK; on R2, A answers `receipt_epoch_unverifiable` with `holds: R1`, so M keeps R1 as named and refreshes; a later §7 completes on R1 or on the fresh receipt; **retention gap:** the same, then M falls beyond retention before any newer ACK, and §7 completes by revealing named R1; **staggered admins:** E = 3; the latest holds of A, B and C name R0, R1 and R2; two staggered refreshes leave R3 pending at B and R4 pending at C, with R5 outstanding; then B and C answer in turn, so M holds at most 2E + 1 tokens throughout, drops each superseded pending token unless another slot holds it, keeps every token a latest answer names, and §7 completes on any named token; **successive expiry:** R1 is pending at admin B, R2 is delayed until its MAC epoch expires, reachable A answers `receipt_epoch_unverifiable` for R2 while B is offline, so M refreshes to R3 without waiting for B, keeps R1 as B's pending token, never exceeds 2E + 1 tokens, and §7 completes once A acknowledges R3, or on R1 when B returns holding it; (9) **stale admin record:** A verifies and acknowledges M's newer receipt, while designated admin D holds only the older record; run again with A offline until after M's request. | **Red** for (1): baseline M has no automatic exit. Fixed: (1) and (4) unwrap, match the commitment and give one replacement seal with two-way encrypted traffic; (7) completes with D; (8) completes on whichever token has a record (the old one, then the new one); (9) D fetches the newer record from A and completes, and with A offline D waits in `receipt_evidence_unavailable`, then completes. Neither (8) nor (9) ever ends `confirmed_keys_missing`. Controls: (2), (3), (5) and (6) end `confirmed_keys_missing` with no seal, though M can still answer a leaf-key challenge. |
| `s8b_retention_rewelcome` (D119): A designated admin and B holder, both with a commit-log cap of 4 set by test configuration; M candidate member; X former admin in one variant | Create a TreeKEM group on A via API, admit B and M, confirm M and verify its receipt. Hold every frame to and from M, and drive six membership commits on A via API. Release M; its S5 walk ends `catchup_beyond_retention`. Variants: (1) B offline until M shows `readmission_pending_vouchers`, then B returns; (2) a group of only A and M; (3) a Home whose owner device O is the designated admin, with B offline; (4) M's group crypto snapshot deleted through a fault hook while its agent key is kept; (5) M claims an old base while A still retains its next commit; (6) X, removed while M was held, sends M a forged terminal; (7) M is a released-binary keyed fixture that fell behind before any confirmation probe; (8) B runs released v0.46.1. | **Red** for the main path: baseline M stays in `catchup_beyond_retention` with only D43's exit. Fixed: one replacement seal; M installs at the terminal head on the vouchers of A and B, sends its receipt and exchanges encrypted traffic with B at the current epoch. Controls: (1) a typed wait, then completion; (2) `readmission_uncorroborated`; (3) completion on the owner mandate; (4) `confirmed_keys_missing` and no seal, although M can still answer a leaf-key challenge; (5) `catchup_available`, no seal; (6) M installs nothing, and B's conflicting head yields `ForkQuarantined`; (7) `no_confirmation_record`; (8) `repair_receiver_upgrade_required` naming B, before removal. |
| `s8b_sidecar_quarantine_rebuild` **control** (D120): A, D admins, J | Instantiate ADR 0108 §5a's fault cases for `.rwstate` and `.rwjournal`, with this layout's header forms (for example `X0RWS1` with non-zero padding, version `0`, a prefix-only truncation and a valid `X0RWS2\0\0`). Rebuild cases: through APIs build J confirmed, with its receipt verified by D; a second seat with two unreceipted replacement seals; a keyless seat with a valid marker; a receipted seat whose seating event is pruned; and a pending `.rwjournal`. **Exhaust, prune, corrupt:** exhaust a seat's budget, prune its markers from every holder, then damage A's `.rwstate`. Damage A's and then J's sidecar and restart. | New-path control, apart from §5a's red cases. Fixed: `rewelcome_rebuilding` shows, then clears; D's verification record is fetched again; the second seat still ends `repair_budget_exhausted`; the receipted seat keeps a fresh budget; J's keyless marked seat re-derives `Unconfirmed`, an unmarked one ends `no_never_confirmed_record`; the pruned exhausted seat gets no seal and ends `no_never_confirmed_record`; the pending `.rwjournal` reconciles against the verified head. |
| `s8b_1146_refusal_order` **control**: A, B, J | While J pending, API add B; deliver B's signed add before J's consumed-invite refusal, restart J, redeem fresh addressed invite. Deliver genuine ban/removal/quarantine in separate negative controls. | Post-#1148/#1190 baseline may already recover genuine unseated J; preserve that behaviour and typed consumed-invite refusal. Banned/removed/quarantined rows never clear. Still-seated staging loss belongs to the #1150 red case. |
| `s8b_keyed_unknown_upgrade` **control**: A, B | Create released keyed TreeKEM/GSS/SignedPublic fixtures through APIs, restart candidate after simulated host commit with no receipt sidecar, call info/send/secure APIs and confirmation probe; restart again. | Existing keyed members stay usable and migrate Unknown→Confirmed with **zero** new membership commits/epochs. No pre-host-commit sidecar write. Deliberately missing keys become typed Unconfirmed/ConfirmedKeysMissing, never keyed Active. |

Also fix the schedule for removal-before-response: J receives one removal with a verified exact-commit/actor marker, then matching add and mandate within the repair bound; terminal confirmation requires the whole verified chain. Missing/mismatched/late add preserves pre-repair state only until the bound, then applies the committed removal/native exclusion with typed exit, or records a conflicting-chain fork in typed quarantine without old-epoch service. A genuine ordinary removal, including one carrying a failing marker, is applied immediately as a terminal-removal control.
Test every role, unsupported-role refusal before mutation, serve-first when only the original sealer has staging, one terminal per attempt and never-installed entitled epochs separately from never-admitted epochs.
A non-receipting J repeats signed requests across staging expiries, new nonces and restarts (D90): at most two replacement seals; at most one pre-verify request per 30 s, burst two, per `(group, member)` and per `(group, forwarding admin)`, each drop answered `RateLimited`; backoff of 1 then 10 minutes, shown as `waiting_for_repair_backoff`; all across restarts; then `Refused(repair_budget_exhausted)` and D43's manual exit.
Every case asserts the typed state at each block it reaches, including the poll deadline (D64).
Lost receipt/ACK retries no rekey. Confirmed Active/duplicate replay seals nothing. Failed clone/prepare/persist leaves original usable state. Atomic receiver verification preserves both roster and native epoch only within the verified-marker pending bound; its terminal fallback enforces removal or fork quarantine.
Egress covers every producer listed in §4, copies/chunks, every physical resend, deadlines, quiesce races, fair admission under floods, revocation/expiry at the seam and survivor epoch moves.
Retain all 0106 carry/preflight/bounds/stale-attempt and 0107 carry/no-carry/certificate/current-roster controls.
Force post-handoff sibling races; preserve quarantine rather than silent adoption. All eight 0088 §2 controls remain: revoked/banned, invalid certificate, no admin, never-admitted epochs, signed deletion, post-removal catch-up, unanchored fork and all evidence holders offline. The S8(b) manual-exit entry that D118 confirms gets a case for each reason, in the evidence, retention, budget, mixed-version, Home and role cases above.
Mixed versions use released **v0.45.0 and v0.46.1**, add **v0.46.2 once shipped**, both directions and legacy survivors. Test SignedPublic rejoin compatibility, typed bounded upgrade exit, absent/expired/offline advert gating, additive repair-field decoding and terminal native convergence.
Storage uses released raw-map fixtures with provenance/hashes, both legacy files and existing embedded-journal bytes; unknown/corrupt/trailing new bodies remain intact.
Test every crash cut and downgrade with pending/committed transactions: old daemon starts, sees J non-member/no secrets, never half-seats J; re-upgrade reconciles without duplicate rekey or obsolete head overwrite.
**Released-load controls (A admin, J; non-Home and Home variants):** create the group and J's pending join through public APIs, simulate host commit, persist the candidate Unconfirmed views, and stop at each journal crash cut before durable confirmation. Restart the released v0.45.0 and v0.46.1 binaries on that same data directory. Through info/member/invite APIs assert J has no seat or keys, no Active admin exists, invite mint fails and no commit/revision advance occurs; include a creator-identity reload to exercise `migrate_from_v1`. Check both loaded files, not only `named_groups.json`. After durable confirmation, use a separate control proving the complete compatible roster/key pair reloads. These are safety controls, not claimed red reproductions.
On released **v0.46.1**, obtain a fresh addressed invite from live A and redeem it on downgraded J: **a fresh invite starts a new join**, rather than an idempotent `not_member` result or `join_already_pending`. The pending placeholder must pass #1148's never-seated/no-J-entry classifier. Re-upgrade must reconcile this later attempt without resurrecting old work.
For Home J, also invoke the Home provisioning/owner-sync APIs under a deterministic delivery schedule. Assert the canonical Home ID is unchanged, no duplicate Home is created and `home.json` bytes remain unchanged. Run on both released binaries, including the no-owner-sync-pointer case, through reload and provisioning (D81). If any released control fails, Home activation stays blocked and a Home repair request ends `Refused(home_activation_blocked)`. Test that pre-host-commit base-seated admission refuses with `host_commit_pending` before any row or sidecar write, then starts Unconfirmed after host commit.
The live harness must prove durable confirmation and bidirectional encrypted traffic; documentation/governance success does not close any runtime gate.

## Rulings and open questions

**Still blocks David's Accept:** only acceptance order and harness numbers. (1) S4, ADR 0110, Accepted first (D88), with the measured window, completion bound, fallback stagger and restart sync wait (D69, D73), which give the repair bound its final numbers (D89). (2) S2, ADR 0108, Accepted with its `JoinPendingNotice` (D117) and §5a lifecycle (D120, D148), which §1 and §5 reuse. §7's code also waits for S3's and S5's states and S5's head query on main; that gates code, not Accept. No open question remains.

David ruled Q1–Q10 on 2026-10-04 (D64, D65, D81, D84–D92, D97):

- **Q1, old-authority compatibility:** `LegacyCompatible` completion under today's checks, visibly marked as lacking new confirmation; encrypted keyless attempts end in a bounded typed timeout (D84). §1 states it as the one named exception, with its L4 argument.
- **Q2, confirmed key loss:** the manual exit is enough. Keep `Refused(manual_reinvite_required)` and D43's remedy (D85). This explicit L1 gap is part of §6's named §2 entry.
- **Q3, leaf replacement trigger:** only with recorded never-confirmed evidence; receipt-less older seats use the manual exit (D86). D136 later fixed the evidence as the admission-time marker.
- **Q4, Home repair mandate:** the owner-device form and the promoted-admin form (D87). The capability floor stays an explicit L1 limit in mixed groups (§3, §6).
- **Q5, scheduling:** widen ADR 0016 §6 to repair rekeys; fallback uses S4's Accepted rules; 0114 is accepted after S4 (D88). D122 later confirmed that D74 governs designation.
- **Q6, bounds:** S4's final window and completion bound plus 120 s; ADR 0107's poll windows and 10-minute staging lifetime unchanged; at most three buffered links within existing byte caps; a 10 s exchange cap that also bounds the sealer lookup (D89). The final numbers follow S4's timing ruling (D69), which waits for harness numbers.
- **Q7, abuse budget:** the recommended rates, budget and backoff, all surviving restarts (D90). D137 later fixed retention.
- **Q8, #1191:** ships with the full S8(b) slice, not early (D91, against the recommendation). Its W3-H case comes first, as for the rest of the slice.
- **Q9, receipt MAC:** domain-separated BLAKE3 `derive_key` and keyed MAC, as specified (D92).
- **Q10, G7:** L3 is a hard rule for every slice, including the poll and upgrade or backoff waits (D64). §6 lists this slice's typed blocks.
- **Order:** "S8" in 0088's order means S8(a), ADR 0107. 0114 follows S4, and S5 does not wait for 0114 (D65).
- **Home placeholder:** Home activation is lifted only behind the released-binary controls; any failed control blocks it (D81, §5).
- **Behind retention:** D97 treats a member behind every holder's retention as admission, through S8(b) or a later ADR. D119 later widened S8(b) to repair a confirmed member (§7).

David ruled round 2 on 2026-10-04 (D117–D120, D122, D136–D138):

- **Pending cause notice:** reuse ADR 0108's `JoinPendingNotice` (D117). §1 registers S8(b)'s causes and serves the notice under ADR 0107's guard.
- **Named §2 additions:** all four confirmed, including the S8(b) manual-exit repair entry (D118, §6).
- **Confirmed member behind retention:** widen S8(b) now (D119, against the recommendation). §7 defines the **retention re-Welcome**, the stable name that ADR 0109 and ADR 0111 cite.
- **Unreadable sidecar:** automatic quarantine and rebuild (D120, against the recommendation). §5 applies ADR 0108 §5a's shared lifecycle, states what is rebuilt, what is lost and each safe outcome, and amends ADR 0085 rule 4 for S8(b)'s own files. Rule 5 is not amended, and each family prefix is reserved for its path.
- **Lowest roster admin:** D74 governs everywhere; "online" in D88 and 0088 §3 reads as "eligible on the roster" (D122, §3).
- **Never-confirmed evidence:** the admission-time marker, now normative in §3 (D136). It closes round 1's evidence question.
- **Budget record retention:** the proposal, accepted (D137, §4). It closes round 1's retention question.
- **Unrestorable roles:** part of the S8(b) manual-exit entry (D138, §6). It closes round 1's role question.

David ruled round 3 on 2026-10-04 (D146, D148, D166–D168):

- **Exceptions to Accepted rules:** approved, including §3's exception to ADR 0064 Decision §1 for repair adds (D146, D87).
- **Quarantined copies:** kept until an operator removes them or the group's own files are deleted, with each copy and its size in diagnostics. §5 cites ADR 0108 §5a (D148). It closes round 2's retention question.
- **§7 adoption exception, vouchers and residuals:** as proposed (D166). §7 states the named relaxation of 0088 L4. The anchor is two vouchers or the owner-device mandate. `no_confirmation_record` and `readmission_uncorroborated` join the S8(b) manual-exit entry.
- **Proof of kept group keys:** the retention token, now normative in §7 with its harness case (D167).
- **Skipped-epoch ciphertext:** a named §2 entry typed `history_gap {from_epoch, to_epoch}`, with no exit; current store state still arrives through S5 (D168, §6).

No open question remains for David.

## Notes for AI-assisted work

Only David Irvine marks this ADR Accepted. Claude's cross-model r1 requested changes; r2 reported APPROVE-WITH-NITS with the final decision-text corrections addressed here.
Claude recorded David's 2026-10-04 rulings, rounds 1 to 3, at his instruction; the Status stays Proposed. This revision still requires David's acceptance.
Accepted ADRs 0088, 0094, 0106 and 0107 remain unchanged. No governed implementation is claimed by this documentation revision. The implementing PR will update API/CLI documentation and polling behaviour under the code gates above.
