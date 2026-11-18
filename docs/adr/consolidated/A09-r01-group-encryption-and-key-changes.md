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

[A08](A08-r01-groups-home-membership-and-repair.md) defines valid group-state and fork recovery. A09 must not bypass that authority to obtain keys faster.

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
