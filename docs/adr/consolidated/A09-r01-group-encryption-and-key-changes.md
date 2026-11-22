# A09 Group Encryption and Key Changes

- **Status:** Accepted (David, course-correction directive, 7 Nov 2026, ruling 2)
- **Revision:** 1
- **Date:** 2026-10-05
- **Decision owner:** David Irvine
- **Direction:** Confirmed by David (D198) on 2026-10-05 for this team review.
- **Replacement activation:** Active since 7 November 2026. The 15 accepted slots are the live decision authority.
- **Supersedes:** The archived numbered records mapped to this slot in [TRANSFER.md](TRANSFER.md). The archive stays the historical record. Existing implementation gates remain in force.

David accepted the 15 slots at their current revisions on 7 November 2026 (course-correction directive, ruling 2). They are the live decision authority. The numbered records stay in [docs/adr-archive](../../adr-archive/ARCHIVE.md) as the historical record. [docs/adr-archive/move.json](../../adr-archive/move.json) records the archive transfer David accepted on 10 October 2026. Use the [index](README.md) for the current rules.

Group encryption must follow committed membership. A roster change alone does not prove that a departed member can no longer decrypt later traffic.

## Context

x0x has TreeKEM and legacy GSS paths. Group messages, key-value data and task data must apply compatible access rules. Self-leave, revocation and certificate expiry also require cryptographic handling.

## Decision

We will use one target group-encryption model based on TreeKEM. Legacy GSS remains supported only for the approved transition and maintenance needs.

Do not stop GSS creation or remove a legacy path until the replacement supports the required admission and recovery operations. Use signed capability checks and a tested compatibility plan.

A cryptographic epoch identifies the key state for protected content. Bind group identity and epoch into encryption and verification. Seal new content only under the currently committed usable epoch.

Signed-public groups remain a separate explicit policy. Their signatures provide authenticity; they do not make the content private.

## Membership and key release

Release current key material only to a currently eligible recipient. Check membership, certificate rules, revocation, group state and the secret epoch at the time of each delivery or resend.

A previous eligibility check does not authorize a later resend after removal or revocation.

Keep historical access separate. A current member is not automatically entitled to every previous key or retained content object.

Every departure that requires exclusion must cause a key transition. This includes admin removal, verified revocation, applicable certificate expiry and signed self-leave.

The remaining authorized participants perform the key transition. A leaver cannot prove its own exclusion by removing itself only from the visible roster.

## Ordering and recovery

Coordinate membership state, key state and their durable records. On restart, complete or safely refuse an unfinished transition. Do not publish content from an uncommitted or stale state.

### TreeKEM self-leave

Two accepted records govern the rekey after a TreeKEM self-leave (D274, 14 Oct 2026, and 16 Oct 2026, PR #1337; archived as [T-self-leave-rekey-committer](../../adr-archive/transient/T-self-leave-rekey-committer.md) and [T-self-leave-catchup-author](../../adr-archive/transient/T-self-leave-catchup-author.md)).

The committer election stays ADR 0016 decision 6: the lowest active admin by raw agent id commits the responsive rekey, every active admin stays eligible, and other admins hold off until a capability bit that rides an existing signed advertisement is accepted. A mixed group waits until the lowest admin runs this code or is removed. ADR 0016 decision 6 is the rule that the current code implements, because the ADR 0110 S4 code is not yet merged. When S4 lands, ADR 0110's measured wait and ranked fallback govern the self-leave rekey, together with the rekey after a revocation or certificate-expiry eviction (ADR 0110, described below). One JSON file per group at `data_dir/treekem-self-leave-outbox/<blake3 of the group key>.json` records the roster-only self-leave, unpublished rekeys and published rekeys, so a restart can serve them on catch-up; it is not the TreeKEM journal. The rekey is saved with its commit bytes before the epoch is durable, a published rekey is kept for catch-up and not sent again, and a retry that finds a pending record for the current head restores that record's saved post-commit tree rather than minting a second commit. D274's acceptance includes the consequence that a node that seals while it does not know it is behind can quarantine the group; no seal timeout and no second committer are added.

On the catch-up recovery path only, a `MemberRemoved` applies as its verified signer when the transport sender is an active member, `verify_structure` succeeds and the event actor equals `committed_by`; the roster checks then run against that signer. A self-leave still requires the signer to be the removed member, and an admin removal still requires the signer to be an active admin. The direct path does not change: a transport sender who is not the signer cannot apply a `MemberRemoved` by writing the actor field. A truncated membership page opens a catch-up fence for that peer only; a later page from another peer or a member-keyed KeyPackage reply does not close it, and the fence closes when that peer returns a non-truncated membership page. [A15](A15-r01-compatibility-validation-and-decision-rules.md) carries the relay commit-binding rule and the accepted v0.48 mixed-version break for the digest-bound rekey seal.

Future-epoch content may be held under defined size and time limits while the required state arrives. Report expiry and recovery failure. Do not silently present such content as applied.

D34 rules automatic revocation eviction and rekeying within a bound. D40
specifies designated-first, with fallback after the bound; D74 refines the
selection to the lowest roster admin, without reachability data. David
accepted ADR 0110 on 20 Oct 2026 (Group 2, #1357, option B). The timing
values are the W3-H p99.9 measured numbers (D69/D73). The implementing PR
body records them before any timing-dependent code merges. The fixed 2 s /
5 s values stay rejected (D69). This draft does not choose new bounds.

On 7 Nov 2026 03:46 GMT David approved a change to ADR 0110 §2 head
sync (#1597 item 5b): "Yes, stop counting those older revisions as
conflicting-head evidence and allow responder_state_revision with a
compatibility default." The TreeKEM catch-up answer gets the optional
field `responder_state_revision`; old peers omit it and keep the old
rule. A holder is far behind when this node cannot link its head through
the retained commit log and its revision is below the retained floor.
Such a holder adds no conflicting-head evidence. It does not confirm the
round. A sibling fork that split below the window is not detected. ADR
0110 stays Accepted and its text is unchanged. The code and this slot
carry the change.

**Amendment, 14 Nov 2026 (Claude, under David's delegation of 10 Nov 2026; #1583).** A removal of an Active TreeKEM seat needs that member's KeyPackage. The authority-attested form reached other members only in one direct message from the seating admin, because gossip `MemberAdded` carries no `member_joined_recovery`. A member that missed that message could not remove the seat. Decision (option 1, no wire change): KeyPackage recovery accepts the member's own signed `MemberJoined` for an Active seat, as it already did for a Removed seat (#1113), only when the bytes hash to the `treekem_key_package_hash` that the verified roster commits for the seat. Catch-up also serves that form. The admin-signed roster commit already names the bytes, so a member cannot substitute a fresh package. Option 2 (publish `member_joined_recovery` on gossip) is not taken.

On 14 Nov 2026 Claude decided two ADR 0110 follow-ups under David's
delegation of design decisions of 10 Nov 2026
([#1581](https://github.com/saorsa-labs/x0x/issues/1581)). (1) The §2
row budget counts host suspend. The in-boot part of a row's budget is the
larger of the monotonic delta and the delta of the suspend-inclusive boot
clock (`CLOCK_BOOTTIME` on Linux, `CLOCK_MONOTONIC` on Apple platforms).
Neither clock is ever set back, so W still never renews; after a sleep
the fallback is no longer late. Test builds, W3-H included, keep the
virtual clock alone. (2) The owner-recovery mandate route and its
receiver answer `waiting_for_active_admin` (HTTP 409) when the parent
roster has no Active admin seat at all, per ADR 0088 §2 item 3 and ADR
0110 §4. `recovery_not_needed` keeps its ADR meaning: an eligible admin
exists. A promoted member keeps a mandate refused with either cause and
retries it, as before. ADR 0110 stays Accepted and its text is unchanged.

On 15 Nov 2026 Claude recorded the limit of a machine revocation for
TreeKEM group content, under David's delegation of design decisions of 10
Nov 2026 ([#1929](https://github.com/saorsa-labs/x0x/issues/1929),
option 3; the #1928 W3-H row found it). A machine revocation denies
delivery, transport and requests to that device, and the agent keeps its
seat (D70). It does not protect TreeKEM group content against a device
that still holds the agent key. The leaf keys derive from the agent key
and the group id (`derive_identity_seed`), so the device can open every
later UpdatePath sealed to the agent's leaf, and removing the leaf and
rejoining from another device restores the same key. To cut a lost or
stolen device off group content, revoke the agent or remove the member.
Per-device TreeKEM leaves (#1929 option 1) would close the gap and are a
separate project. ADR 0110 stays Accepted and its text is unchanged.

On 15 Nov 2026 Claude decided when the §2 restart sync wait ends head
discovery, under David's delegation of design decisions of 10 Nov 2026
([#1581](https://github.com/saorsa-labs/x0x/issues/1581),
`s4_restart_stale_head`), to carry out David's rulings of 29 Oct 2026
00:15/00:40 GMT. A group that had an unsealed (pending or prepared) row
in the `.evs` file this boot loaded needs a holder's confirmation of its
head before S4 seals in it, while any holder exists. The elapsed restart
sync wait alone does not end discovery for that group, inside the wait or
past it, and the row keeps `waiting_for_head_sync`. The first
confirmation of the group's head since the boot lifts the rule. Every
other group keeps D73: the bounded wait ends discovery when no holder
answers. A committed row's delivery is not gated, because it resends its
saved event and seals nothing new. A node that restarted with pending
work on a head loaded from disk thus never seals that stale head, and
another admin's fallback still covers the row. ADR 0110 stays Accepted
and its text is unchanged.

On 15 Nov 2026 Claude decided how S4 knows that a local worker lost its
committer authority, under David's delegation of design decisions of 10
Nov 2026 ([#1581](https://github.com/saorsa-labs/x0x/issues/1581),
`s4_local_authority_exit`, ADR 0110 §4 L274 and L275, D72). A local node
that is no longer an Active admin was the row's worker when the row's
last stored derivation named it the designated admin or a fallback rank.
Such a node marks `local_committer_ineligible` naming the designated
admin, the same as a revoked worker. A stored mark keeps it after the
stored derivation moves to another admin, and across a restart, while no
override replaces the row's stored waiting cause (rebuilding, the
host-commit gate, the fork wait, `waiting_for_receiver_upgrade`, rebind).
After such an override, once the derivation no longer names the node, the
row shows `waiting_for_designated_admin` again; there is no separate
worker-history state. A member that never was a committer for the row
keeps `waiting_for_designated_admin`. The leave form is not covered: a leave
drops the local group record, so no row is left to mark. ADR 0110 stays
Accepted and its text is unchanged.

Amendment of 14 Nov 2026 (#1427), made under the design delegation of
10 Nov 2026. A TreeKEM member that was down longer than the last
metadata resend (60 s) can have missed a commit, and with no later
traffic nothing else asks for it. After its start, such a member asks the
other members of each TreeKEM group for a catch-up page, on the bounded
epoch-ahead rounds, as the group's one epoch-ahead task. While a cycle
moves the group, the next cycle asks for the epoch after the new one (at
most 16 cycles), so a member several commits behind reaches the tip. It
asks again after the network join ends, in either order of the join and
the start, since the start rounds can end before a slow bootstrap reaches
a member. The daemon records its up time every 15 s to measure the
outage, and keeps an outage record until each group's catch-up succeeds
(a cycle after a move brings no newer epoch, or a member reports the
local head), so the next start asks again. A first start and a shorter outage ask
nothing, since the resends cover them. Each served page goes through the usual response
checks. Not covered yet: a member that stays up through a network
outage, and a serving node that restarted since the commit (its catch-up
log is in memory). A saved log must not serve a commit that S4 still
holds as delivery-pending after a restart. No wire format or API changes.

On 15 Nov 2026 Claude decided the D70 caller refusal under David's
delegation of design decisions of 10 Nov 2026
([#1597](https://github.com/saorsa-labs/x0x/issues/1597) item 4). A
direct send whose resolved recipient machine is revoked answers the typed
`DmError::RecipientMachineRevoked { machine }`, and `POST /direct/send`
maps it to HTTP 403 `recipient_machine_revoked`. The check runs before the
ADR-0043 pairing check, on the discovery-cached machine and on the
capability-advert binding. A machine revocation evicts the recipient from
the discovery caches, so when no discovery entry is left the check reads
the newest retained authenticated or announced binding, which outlives
that eviction; a later announcement from a clean machine replaces it. A revoked binding keeps its existing typed
answer, `recipient_pairing_denied` (`PairingDenial::BindingRevoked`). The
S4 designated hand-off reads the new error as a policy refusal, like the
pairing denial. A request from a revoked device keeps the #1657 typed
catch-up refusal. The internal guarded S4 sends keep their withhold-and-retry
path; they report to no caller. ADR 0110 stays Accepted and its text is
unchanged.

Amendment of 15 Nov 2026 (#1427), made under the design delegation of
10 Nov 2026. A node keeps its TreeKEM catch-up log on disk
(`treekem-catchup-log/`, one file per group, local state, never sent) and
loads it at start, after the S4 store. So a node that restarted after it
signed or applied a commit still serves it to a member that was offline at
the time. The saved log of a group the node no longer stores is removed,
and deleting a group removes its files. One rule protects S4: a removal or
ban whose target has an S4 row (ADR 0110), in any phase, is not loaded
from the saved log. S4 owns the delivery of that commit: an open row
resends it only after the group's head is synced, and a closed row can
hold a sibling that lost to another admin's commit (the W3-H 1581e fork).
The adds and approvals of that target in the same file are held back too,
so a held removal cannot leave its member served through an old add. A start catch-up cycle that hands its target to another
running catch-up task waits for that task to end before it judges the
cycle. The saved file is written by rename without fsync, so a crash can
lose the latest copy; the node then falls back to the behaviour before
this change (the commit is not served after its restart). The file is
JSON and carries a format version. A file of another version, a damaged
one, or one written before the version field existed is skipped with a
warning and overwritten by the next save. A requester that the log shows removed or banned
after its cached add is not served through that add. Not covered yet: a
member that stays up through a network outage.
No wire format or API changes.

Second amendment of 15 Nov 2026 (#1427), made under the design delegation
of 10 Nov 2026. It changes one rule of the amendment above and closes its
open item. At restore, only the adds and approvals of a held target that
come before its last held removal in the file are held back. A later add
is a re-add after the removal, and it is served as usual. A member that
stays up through a network outage now asks too. The daemon watches its
connected peer count. When the first peer connects after the node had no
connected peer for longer than the last metadata resend (60 s), it runs
the start catch-up for each TreeKEM group and writes the outage record,
so a restart during that pass still asks. At most one such pass runs at
a time, and each needs a new isolation longer than the resend, so
reconnects cannot cause a storm. A shorter isolation asks nothing. Not
covered: a node that keeps some connected peers but loses every other
member of a group. No wire format or API changes.

Third amendment of 15 Nov 2026 (#1427), made under the design delegation
of 10 Nov 2026. It bounds the reconnect pass of the amendment above. A
reconnect that comes while a pass runs is kept: one more pass runs when
the current pass ends. A pass runs in rounds. The first round gives each
group a turn. At most 4 turns run at a time, and each turn starts after
a random wait of up to 10 s, so a member set that heals at once spreads
its requests. A turn holds its slot for at most 120 s. The group's
catch-up keeps running after its turn, and a later turn, of this pass or
of a later pass, does not start a second catch-up for the group while it
runs; that catch-up then asks once more when it ends, so a group a later
pass marked pending is asked after the mark. A reconnect that waits ends
the current turns and starts no further turn, since the next pass asks
for every group. The pass runs another round, for the groups that are
still pending, after waits of 60 s, 300 s and 900 s; a new reconnect
ends those waits and starts a new pass. The outage record is written and removed
under one lock, so a removal never follows a new pass's mark. No wire
format or API changes.

Fourth amendment of 16 Nov 2026 (#1427, #1936 review follow-up), made
under the design delegation of 10 Nov 2026. When a later pass marks a
group pending while the group's catch-up from an earlier turn still
runs, the end of that older catch-up does not remove the mark, so it
does not remove the outage record either. The mark carries the group through
the second ask and the later rounds of that pass. The record carries it
through a restart. This holds for every end of the older catch-up,
including a member that reports the local head: that page can answer a
request from before the later isolation. The daemon has one gate, and
every removal of a mark goes through it. The second ask removes the mark
as usual when the group is current. No wire format or API changes.

Fifth amendment of 16 Nov 2026 (#1427), recorded by Claude under the
design delegation of 10 Nov 2026. A start or reconnect catch-up cycle
asks for the next epoch without having seen it. Its target is now kept
apart from epoch-ahead traffic and is not higher-head evidence for the
ADR 0110 §2 seal gate; S4's own head round still asks the holders. Before
this, a reconnect pass held every S4 seal of the group while it ran, and
a revocation eviction could miss its completion bound (W3-H row
`w3h_1357_red_s4_idle_revocation_one_admin_home`, which failed about two
runs in five without the shim, where the pass's random wait is not
controlled). Epoch-ahead traffic that arrives during the cycle makes the
target evidence as before. The flag stays set for the life of the
group's catch-up entry: a later probe on the same entry, even for a
higher epoch, keeps the seals held until the entry ends. That can wait
longer than needed but never seals early. No wire format or API changes.

On 16 Nov 2026 Claude recorded how run (5a) of the ADR 0110 row
`s4_certificate_expiry_skew` is read, under David's delegation of design
decisions of 10 Nov 2026
([#1581](https://github.com/saorsa-labs/x0x/issues/1581)). The row says
that a renewal reaching the admins only by announce cancels nothing and
that B is evicted. That text predates §4a. §4a (L289) and
`s4_certificate_rebind` run (2) have the designated expiry worker commit
the rebind instead of `MemberRemoved` when it holds a verified renewal
from any source, an announce cache included. The two agree on D135: the
announce alone cancels nothing, and only a rebinding commit keeps the
seat. Run (5a) therefore passes when nothing moves before raw
`not_after`, and the designated admin then commits the rebind within the
completion bound from its trigger, with no epoch change. When the
mixed-version rule forbids a rebind, the seat is evicted, as run (3) of
`s4_certificate_rebind` states. No code, wire format or API changes. ADR
0110 stays Accepted and its text is unchanged.

On 16 Nov 2026 Claude decided what a seated revoked non-admin member
means for the owner-recovery seal, under David's delegation of design
decisions of 10 Nov 2026
([#1973](https://github.com/saorsa-labs/x0x/issues/1973); ADR 0110
§4b(1), ADR-0038 review B3). The recovery commit removes only the named
revoked admins and promotes one member. A revoked below-Admin seat that
is still seated no longer refuses the recovery seal: the seal tolerates
it, as an S4 removal seal tolerates the group's other open S4 targets
(ADR 0110 §3, ADR-0038 B3). The tolerated seat keeps its seat, and the
recovery does not exclude it cryptographically: the commit keeps its
TreeKEM leaf and builds its GSS envelope for it. D60 guarded egress
withholds delivery while this node holds the seat's verified
revocation, so the seat gets neither the recovery frame nor the share
that follows it. The seat's own S4 row performs the exclusion and the
rekey: ADR 0110 §1 opens that row for every seated revoked target, and
it commits under the admin the recovery seats. Stated plainly: if the
recovery commits at epoch e0+1, the revoked seat E keeps its leaf and a
key envelope for e0+1 is built for it; only D60 egress withholding keeps
E out, until E's own S4 row removes it and rekeys at e0+2. This is the
same exposure as ADR-0038 B3. Every other failing seat
keeps the all-clean refusal. A refused recovery seal that names failing
members keeps a typed wait, `waiting_for_member_eviction`, naming them.
A grace or digest-pending hold is not eviction work, so it never joins
`named`. When failing members stand beside the hold, they stay named
until the hold ends. When a hold refuses the seal alone, the refusal is
`OwnerCertMemberPending`, and the promoted member's status stays at the
bare `mandate_received` until the hold ends. A tolerated seat can still
stall the recovery after the seal: it reaches the D76 receiver-upgrade
hold and the "survivor has no roster KEM key" deferral like any other
member, and those holds are not new in this change. The tolerance
covers verified revocations only. An expired below-Admin seat keeps the
refusal, so when every admin is revoked the recovery and that seat's
expiry row still wait on each other; the exit is the owner
re-certifying the expired seat, not the recovery. Before this, the
recovery could never commit while a revoked member was seated, and that
member's eviction waited for the admin the recovery would seat, so the
group stayed without an admin (#1973). The `OwnerRecoveryV1` body still
removes exactly the named admins; no wire format changes. The local
status of a promoted member can name the new wait cause. ADR 0110 stays
Accepted and its text is unchanged.

On 20 Nov 2026 the Claude orchestrator decided the expired-seat case
under David's delegation of design decisions of 10 Nov 2026 and A15 as
amended on 12 Nov 2026
([#2004](https://github.com/saorsa-labs/x0x/issues/2004)). This replaces
the last rule of the paragraph above: an expired below-Admin seat no
longer keeps the refusal. The owner-recovery seal also tolerates an
Active below-Admin seat whose committed certificate's S4 expiry is due,
by the rule of the seat's own expiry row (`now > not_after + τ`). The
creator seat is not tolerated this way, because no expiry row ever
targets it (Engineer ruling of 1 Nov 2026), so it keeps the refusal. A seat
whose certificate expired less than τ ago is not yet due and is treated
as before. A seat whose certificate bytes this node does not hold, or
whose renewal fetch is in flight, is a digest-pending or grace hold, not
a failure, and still holds the seal. The tolerated expired seat keeps
its seat and its TreeKEM leaf at the recovery epoch e0+1, as a tolerated
revoked seat does. Delivery to it is withheld:
- the owner-recovery egress adds an expiry check to D60, so the
  recovery commit, the only carrier of that epoch's path secrets, is
  never written to a seat whose expiry is due;
- the ADR 0107 member check at the guarded admission already refuses an
  expired certificate;
- the TreeKEM catch-up page handler answers nothing to a requester whose
  seat expiry is due. It returns at once, as for a revoked requester, so
  the cached-add fallback that serves a recent joiner does not serve it
  either.

The seat's own S4 expiry row then removes it and rekeys at e0+2 under
the admin the recovery seated. Before this, every admin revoked plus one
seated expired member was a deadlock; the only exit was the owner
re-certifying that member. The `OwnerRecoveryV1` body is unchanged: it
removes exactly the named admins, and no wire format changes.

On 20 Nov 2026 Claude, under David's delegation of design decisions of
10 Nov 2026 and A15 as amended on 12 Nov 2026, made the wait for an
expired creator typed
([#2120](https://github.com/saorsa-labs/x0x/issues/2120)). Correction to
the #2004 paragraph above: the creator seat does not "keep the refusal"
as a failure. `owner_cert_verdict` holds a creator whose own committed
certificate is expired at digest-pending, or in grace while a digest
announced for it has bytes that have not resolved here, and never fails
it. The creator holds the seal only when it is the only hold: then the
recovery seal is refused as `OwnerCertMemberPending`. When other
below-Admin seats also fail, recovery proceeds past the held creator, by
David's decision of 20 Nov 2026
([#2133](https://github.com/saorsa-labs/x0x/issues/2133)): the creator
stays seated, gets no key material for the recovery epoch, and stays so
until the owner re-certifies it. This change does not alter that case.

On an `OwnerCertMemberPending` refusal the recovery takes a second
verdict over fresh evidence and classes the creator at that evidence's
clock. A digest-pending creator ends only when the owner re-certifies
the creator's agent, so the promoted member's wait is
`waiting_for_creator_certificate_renewal` at once, naming the creator,
and its status carries `"remedy": "owner_recertifies_creator"`. A
creator in grace (a digest announced, its bytes not resolved here, which
can be a renewal or a re-announce of the expired certificate) keeps the
bare `mandate_received` for the missing-evidence grace (300 s) counted
from the first refusal that held the creator, then gets the same typed
wait, so a fetch that never completes does not hide the remedy. The
count is in memory: a restart starts it again. Any other grace or
digest-pending hold keeps the bare `mandate_received`, because it ends
when its fetch lands. Once the renewed certificate resolves, the next
recovery attempt commits and the wait ends with the mandate. When the
creator is the only hold, recovery does not proceed past it; the owner
re-certifying the creator is the exit.
No wire format changes; the local status gains the new cause and the
`remedy` field.

[A08](A08-r01-groups-home-membership-and-repair.md) defines valid group-state and fork recovery. A09 must not bypass that authority to obtain keys faster.

On 20 Nov 2026 David decided the mixed case of owner recovery with an
expired creator ([#2133](https://github.com/saorsa-labs/x0x/issues/2133)),
and Claude records it here under his delegation of 10 Nov 2026 and A15.
The creator holds the recovery seal only when it is the only hold. When
every admin is revoked and another below-Admin seat is also tolerated
(revoked, or with a due expiry), recovery proceeds past the held creator:
it commits, and the creator stays seated until the owner re-certifies it.
What the creator gets depends on the plane:
- **GSS plane.** A creator whose committed certificate is expired gets
  no key material written to it in any automatic rekey until it is
  re-certified: not for the recovery epoch, and not for a later epoch
  such as the tolerated seat's eviction rekey. Every share write passes
  the class-K serving guard, which reads the certificate embedded in the
  committed seat: an expired one is a definitive refusal and the share is
  dropped (a seat with a digest but no bytes is withheld, not dropped).
  The recovery frame and the TreeKEM catch-up also refuse a seat whose
  expiry is due (#2004). This is how the code already behaved; this
  paragraph states it for every rekey, not only for recovery. After the
  owner re-certifies the creator and its seat commits the renewed
  certificate, its next catch-up seals it the current secret. One local
  path is outside this rule: `POST /groups/:id/secure/reseal` seals the
  current secret to any Active seat with no certificate check and returns
  the envelope to the local owner caller only, who decides whether to
  hand it over; it delivers nothing.
- **TreeKEM plane.** The creator keeps its leaf, and what it can derive
  depends on whether a commit is withheld from it. A recovery that
  carries a TreeKEM commit moves the epoch, and that commit travels only
  in the recovery frame, which is refused to the creator. A commit applies
  only at the next epoch and the new epoch derives from the previous
  epoch's secret, so the creator cannot apply any later public commit or
  read a later epoch. Two known limits remain
  ([#2139](https://github.com/saorsa-labs/x0x/issues/2139)). (i) The
  withholding is delivery only: the recovery commit itself is encrypted to
  the creator's leaf, so a leaked frame gives the creator that epoch and
  every later one. (ii) A recovery that carries no TreeKEM commit (the
  revoked admins hold no leaf) leaves the creator in step, so it follows
  every later public commit and reads every later epoch. A non-creator
  seat whose expiry is due is in the same position until it is evicted;
  one seal-route call evicts it together with a revoked seat, while
  the S4 worker gives each target its own transition, so another commit
  can land first.

No wire format changes.

On 21 Nov 2026 the orchestrator session recorded the state of
[#2139](https://github.com/saorsa-labs/x0x/issues/2139) under David's
delegation of design decisions of 10 Nov 2026 (A15). **The TreeKEM gap is
OPEN.** It waits for a fix or for David to accept it. This paragraph
accepts nothing.
- **What is true now.** In limits (i), (ii) and (iii) the held creator
  keeps its leaf and can read every later TreeKEM epoch, with **no time
  limit**, until the owner acts (re-certifies it, or removes it through an
  admin). In those limits TreeKEM **does not meet** David's rule of 20 Nov
  2026 that the creator "gets no new keys". Only the GSS plane meets it.
- **Limit (iii).** The recovery-frame gate refuses only a seat whose expiry
  is due (past `not_after` plus τ, 300 s). A creator whose certificate is
  still inside τ at the recovery, or becomes due only after it, is served
  the recovery frame. On TreeKEM it then follows every later commit. On
  GSS each later share write checks the committed certificate again.
- **What a fix needs.** The wire `TreeKemCommit` carries
  `removed_leaves`, a list, so one commit can remove a revoked admin's leaf
  and the creator's leaf without changing the commit count that
  `validate_against_parent` checks. The library that x0x uses
  (saorsa-mls 0.3.8) has no public producer for such a commit:
  `remove_member` removes one leaf, and the multi-leaf `make_commit` is
  private. A fix also leaves an Active seat with no leaf, which the other
  TreeKEM paths do not expect. A recovery that adds a separate commit, or
  a commit when no revoked admin holds a leaf (limit ii), changes the
  count, and every current peer refuses it as `RecoveryProofInvalid`.
  Limit (i) has the same cost, because a commit keeps a live leaf out of
  its path secrets only by removing that leaf.
- **Receiver tightening (this change).** A received TreeKEM recovery may
  remove the revoked seats' leaves and no other leaf. Before this change
  the receiver checked only that the revoked seats' leaves were gone, so a
  mandated recovery actor could also drop a valid member's leaf and every
  receiver accepted it. Now every recovery commit must add no leaf and
  remove one leaf, the tree's active leaf count must fall by exactly the
  number of commits, and every non-revoked seat whose leaf was present
  before must still be present after. If not, the recovery is refused as
  `RecoveryProofInvalid` and the tree is rolled back. Every honest author
  already meets this (`commit_treekem` makes one single-leaf removal per
  leafed revoked seat). This check also refuses a future recovery that
  removes the creator's leaf in the same commit. That fix therefore needs
  a new recovery body version and a receiver capability gate after all.
- **Restoring a leaf, mixed versions.** No leaf is removed today, so
  nothing restores one. When the owner re-certifies the creator, the
  `seat_expiry_due` return of the catch-up handler and the recovery-frame
  gate no longer apply to it. A peer on an earlier release accepts a
  recovery that removes other leaves too; the senders that this release
  ships never make one.
- **Correction to item 4 above.** The seal route, like the S4 worker,
  gives each failing seat its own transition (one TreeKEM commit for each
  evicted seat). One seal-route call runs them one after the other, so on
  TreeKEM another commit can land before a seat's own eviction on both
  routes.
- **Correction to the GSS bullet above.** `POST /groups/:id/secure/reseal`
  is a session-bearer route: the owner API token or a session token is
  enough. The local daemon must be an Active member of the group that
  holds the current secret; it need not be an admin. The route seals the
  secret to any Active seat with a KEM key, with no certificate check, and
  returns the envelope to the caller. It sends nothing.

Tests: `issue2139_treekem_leafless_recovery` pins limit (ii) at the daemon
level with the real recovery attempt, limit (iii) at the frame gate, and
the receiver's leaf rule. `issue2133_treekem_leaf_known_limit` shows that
a creator one commit behind is refused with `InvalidEpoch`. These tests
show the gap; they do not accept it. No wire format changes.

Amendment of 22 Nov 2026 ([#2135](https://github.com/saorsa-labs/x0x/issues/2135)
item 2). **Decision by David, 22 Nov 2026: bind the commit identity into the
state hash**, and accept the wire change, handled by versioning. The rollout
rule, the sticky capability record, the target rule and the S4 row rule below
were set by the orchestrator session under A15 on 22 Nov 2026. ADR 0110 stays
Accepted and unchanged; this change builds what its §3 requires. #2135 stays
open for GSS (below).
- **The fault.** An admin's TreeKEM removal or ban sealed only
  `treekem:epoch=<n>`. Two admins that remove the same member from the same
  parent therefore made the same roster state hash, while their TreeKEM
  commits, and so their epoch keys, differ. A node that held one took the
  other for a duplicate, and a survivor that reported that head counted as
  converged. The fork was silent (W3-H 1581e).
- **Commit identity.** The BLAKE3-256 digest of the exact TreeKEM commit
  bytes that the event carries, in the signed binding
  `treekem:epoch=<n>:commit=<hex>`. This is the form that the self-leave
  rekey (#1337) and the crypto-only exclusion already seal. The state hash
  function is unchanged; only its binding input changes. The commit bytes
  carry the committer's leaf signature and fresh path secrets, so two
  admins' commits (or two attempts by one admin) differ. A replay of one
  commit has the same bytes and the same state hash, so it stays a
  duplicate. Each receiver checks the digest against the carried bytes
  before it applies the commit; a binding over other bytes is refused.
- **Rollout rule (mixed versions).** New capability bit 22,
  `removal_commit_binding_v1`. An admin seals the commit-bound form on its
  TreeKEM `MemberRemoved` or `MemberBanned` only while the target and every
  other Active or Pending member is ready. The target counts because it
  receives its own removal or ban and must apply it to tear down. A member
  is ready when its current verified advert sets the bit, or when the
  **sticky record** holds the bit for it. So a member that is offline,
  partitioned, past the 900 s advert TTL or withholding its advert stays
  ready once a verified advert has shown the bit while it was a member, and
  a member never seen with it is not ready. Only a verified advert signed
  later than the one that set the record, and without the bit (a downgrade
  that advertises), clears it and means not ready; a replayed older advert
  changes nothing. Otherwise the admin seals the legacy form. Receivers of
  this release accept both forms.
- **The sticky record.** It is kept per agent, because the bit is a
  property of the agent's binary and the advert is per agent, and only for
  agents that are Active or Pending members of a group this node is in (its
  scope). Adverts from other agents on the mesh create no record and cannot
  push one out, so the record has no other size limit than the local
  membership. The daemon refreshes the scope every 5 s from its groups. A
  record is dropped when its agent is a member of none of this node's groups
  any more, which for a removal target happens after its removal committed,
  when the gate no longer needs it. An agent that enters the scope with a
  current verified advert showing the bit is recorded at once, so an advert
  seen before the agent joined counts. Each entry keeps the bit and the
  signed `created_at` of the advert that set it. It lives in the capability
  store and in `<data_dir>/sticky-capabilities.json` (JSON, version 1, mode
  0600, at most 8 MiB read), loaded at startup after the scope is set and
  written (new temp file, fsync, rename) only when it changes. An
  unreadable file is ignored and a bad entry is logged and skipped, so the
  gate falls back to current adverts. Old binaries ignore the file.
- **Old nodes.** Released nodes from 0.48.1 verify and apply a commit-bound
  `MemberRemoved`. A released node rebuilds the legacy binding for a
  `MemberBanned`, and 0.47 and older do that for both kinds, so the
  state-hash check fails and the commit is refused (fail closed: it is not
  applied, and the node stays behind at the frontier). A 0.49.0 node shows
  this only as a debug trace (`treekem.trace`, stage `member_banned_apply`,
  outcome `REJECTED`) and a stale head, so
  the visible sign is on upgraded members, which see that node's head lag.
  Such a node meets the new form only when it advertised the bit and then
  downgraded without a new advert (the sticky record still says ready). A
  mixed group with a member never seen with the bit keeps the legacy form,
  and its known limit, until that member upgrades: two legacy-form removals
  of one member still look the same. A legacy-form removal and a
  commit-bound removal of the same member have different hashes, so that
  fork is found.
- **Detection.** A competing commit with a different hash takes the existing
  fork-evidence path of ADR 0064: the node keeps its own head and installs
  the `fork_quarantine` marker (`no_anchor` in an ordinary group). This also
  covers an honest race: two admins that remove the same target at about the
  same time now fork, and each node that took the marker waits for the
  manual clear and the re-seat. ADR 0110 §3 intends this; before, the same
  race forked silently.
- **S4 rows (ADR 0110 §3).** While a group holds the marker, an open row
  that holds a saved removal event or crypto-only frame stops its delivery,
  keeps the saved event and never sends it, and waits as
  `waiting_for_fork_resolution`. When the marker competes with the saved transition (the rule in
  the Exit bullet), the stored wait names the competing commit's
  signer: the saved event is fork evidence. The completion pass completes
  no row of that group, because this node's chain may be the branch the
  group did not take. The `.evs` is written only when the wait changes, not
  on each worker pass. The persisted evidence is the marker in the group
  record (the two commit headers, a fixed size) and the saved event and
  wait in the frozen `.evs` v1 row. No new field.
- **Exit.** ADR 0110 §2 says that S4 adds no fork choice, and §3 names
  manual admin resolution under ADR 0088 §2 item 7. So this change adds no
  branch choice and no new route, and the orchestrator's A15 ruling (resolve
  to the lowest admin's commit by D74 and re-key) is not built, as that
  ruling allowed when ADR 0110 says otherwise. The exit is the existing
  manual clear (`POST /groups/:id/quarantine/clear`) or an owner-anchored
  clear. When the marker is gone the row is classified against this node's
  chain. The marker competed with the saved transition unless the marker's
  competing commit chains on the transition's own result or on a later
  commit of this node's retained chain above it (then the transition is
  common ancestry); a deeper commit of a competing branch competes too,
  and so does a marker whose competing commit's parent this node does not
  retain: its saved event is dropped unsent, and a survivor that still
  lacks the transition gets it by chain catch-up. If
  the stored wait names a competing signer, or the chain holds a competing
  child of the parent, the saved event is dropped unpublished and the row
  completes from this node's chain. Otherwise a saved removal resumes as at
  a restart (delivery after the head sync), and a crypto-only frame on the
  current head resumes its delivery; any other frame stays as catch-up
  evidence. A saved event that cannot be decoded is released once. The
  stored wait keeps this rule across a restart after the clear. This node's
  keys still differ from the other branch's; the exit for that is the
  existing manual re-seat (A08, ADR 0109 §3).
- **Failed rollback.** The routes now make the TreeKEM commit before the
  seal. If the seal fails, the tree is restored from its snapshot. If that
  restore fails, the daemon unloads the in-memory tree and then answers 500
  `treekem_rollback_failed`, so no later operation uses the advanced tree:
  they answer "TreeKEM group not loaded" until the durable tree, which
  never held the commit, is reloaded (a restart or the next rebind). Only that reply and an error log name
  the failure; group status does not show it.
- **Known limits.** (1) An admin on the other branch keeps resending its
  removal to the forked node every 5 s until the manual exit, because that
  node never reports the result head; there is no backoff cap. (2) A GSS
  removal still binds only `gss:epoch=<n>`, so two admins' GSS rotations for
  one member's removal still look the same. #2135 stays open for it. (3) A
  node downgraded to 0.49.x has no fork release rule: a row whose marker was
  cleared before the downgrade may resume its delivery there. (4) An agent
  on two machines with different binaries has one sticky record; a newer
  advert from the older machine drops it. (5) A group with a member or
  target never seen with the bit (every mixed-version group right after the
  release) keeps the legacy binding and can still fork silently.
- **#2139.** The new owner-recovery body version planned there is a
  separate marker: its own body prefix and capability bit, on another commit
  kind. Bit 22 governs only the binding of `MemberRemoved` and
  `MemberBanned`. A receiver checks each marker by itself; neither implies
  the other.

Wire: capability bit 22 and the commit-bound binding on two event kinds
behind it. Storage: the new `sticky-capabilities.json`. No route change.

## Security claims

State the exact properties of each released path. Post-quantum signatures and key encapsulation do not alone prove forward secrecy or recovery after key compromise.

Do not claim RFC 9420 wire interoperability merely because a component is called MLS or uses TreeKEM. Such a claim requires the applicable protocol and interoperability evidence.

Members can retain plaintext already received. Revocation can stop future access; it cannot erase those copies.

Local files and backups follow [A02](A02-r01-identity-keys-and-device-enrollment.md)'s local protection policy.

## Consequences

Removed members lose access to future protected content after the required key change. Key changes and crash recovery require strict ordering. Old copies of plaintext cannot be recalled.

## Alternatives

Keeping two permanent crypto systems increases the number of permission and recovery paths.

Immediate removal of the legacy system can strand supported peers. We choose a controlled transition with clear release gates.

## Current implementation

Both group crypto paths exist. With members remaining, self-leave updates the roster and removes local key state, but does not rotate the remaining members' keys. Full automatic revocation eviction and rekeying remain incomplete. Old ADR 0110 (Accepted 20 Oct 2026; S4 code not yet merged) contains important mechanics that this summary must preserve or explicitly supersede.

## Validation

Verify that a removed member cannot decrypt newly protected content after the exclusion transition. Cover key resend, restart, cold catch-up, stale certificates and concurrent admins.

Test old and new peers across activation. Check both confidentiality and progress.

## Matters to settle

Complete the legacy exit criteria and exact exclusion bounds. Reconcile the new record with the accepted and proposed membership rules before acceptance.

## Existing decision records

Read the [design direction and rulings digest](../../design/x0x-direction.md)
and the [rulings transfer map](TRANSFER.md#rulings) with these records.

These records are the primary sources for this draft. This mapping does not complete the clause by clause transfer required by A15.

[ADR 0010 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0010-gss-before-mls-treekem-for-v1-secure-groups.md) · [ADR 0012 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0012-treekem-default-secure-groups.md) · [ADR 0014 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0014-treekem-self-leave-owner-driven-rekey.md) · [ADR 0024 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0024-gss-rotation-on-admin-remove-fail-closed.md) · [ADR 0027 Accepted](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0027-active-recipient-group-key-sealing.md) · [ADR 0110 Proposed](https://github.com/saorsa-labs/x0x/blob/eacf68591dffcb6f949e2a12bc6f05cfb6e8d481/docs/adr/0110-revocation-eviction-designated-first.md)

Decision source snapshot: 5 October 2026, commit `eacf68591dffcb6f949e2a12bc6f05cfb6e8d481`. Implementation checked on 12 October 2026 at commit `8cb6488331e6c1226913104ddb99ca4ec18bec37`.

[All 15 ADRs](README.md)
