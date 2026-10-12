# ADR 0088: Group Liveness Contract (I8)

- **Status:** Accepted
- **Accepted:** 2026-10-03 by David Irvine (D58, as written: the Proposed text merged via #1160, commit 9369e0c; his instruction to Claude directly). The Open questions remain open for later rulings. The status change was applied by Claude at his instruction.
- **Date:** 2026-10-03
- **Decision owners:** David Irvine
- **Reviewers:** Codex (cross-model review of the text), Root
- **Supersedes:** ADR 0038 (in stages; as a whole only once S2, S4 and S7 are all Accepted), ADR 0060, ADR 0069; in part ADR 0064 Decision §3 and ADR 0066 §2. Each supersession takes effect only when the slice ADR named in the supersession table is Accepted.
- **Superseded by:** none
- **Related:** charter invariant I8; rulings D16, D34, D37–D42, D54, D55; ADR 0106 (slice S1); ADR 0016, 0007, 0059, 0062, 0085, 0087, 0089, 0093; #1139, #1143, #1023, #811, #818, #871, #824, #1113, #1146, #1149, #1150, #646. Serves vision **R3** (all my machines connected) and the "shared places" core.

**Naming.** This ADR is **group liveness (0088)**: membership, admission, catch-up and repair inside named groups and Home. ADR 0104 (prov.) is the separate transport liveness ADR, which supersedes ADR 0002. Reviews and briefs should name 0088 as "group liveness".

## Context

Charter invariant I8 reads: *only an enumerated list of rules may block forever. Admission, catch-up and data repair complete when any one active admin or holder is online.*

The shipped group protocol does not meet I8. Each gap below has been a live failure:

- **Specific devices are required.**
  - Only the inviter can redeem an invite.
  - A Home seal needs every member's certificate bytes, so an offline owner device blocks a promoted admin (#1023, #1143).
  - Each fix so far has been a per-case certificate-carry patch (#970, #1025, #1056, #1132).
- **Stale members do not converge.**
  - A joiner whose invite predates another seal waits forever (#1139, fixed for small gaps by ADR 0106).
  - Ownerless stale-base chains are quarantined with no way out (#818).
  - A forked node has no re-seat path (#871).
  - Partial views fail closed (#811).
- **Revocation is evict-at-next-seal (ADR 0038).** It depends on a seal happening, and the D34(2) bound is not met.
- **Rows get stuck.** A refused or timed-out join can leave a durable row that blocks the documented remedy (#1146, #1150).

On 2026-09-29 David chose the full D16 option:
- a promoted admin carrying the evidence may admit while the owner is offline;
- any active admin may redeem invites;
- stale ordinary-group joiners catch up;
- Home becomes an explicit owner group, checked at admission;
- the simulation harness reproduces each failure first.

D34 closes the D16 holes:
1. ownerless attestation;
2. bounded revocation eviction;
3. K certificates inline plus fetch-by-hash, owned by this ADR.

D37 rules the shape: a **short contract ADR** plus one ADR per mechanism, each reproduced and Accepted separately. ADR 0106 is the first slice.

## Decision Drivers

- One written rule says which waits may be permanent. Today each defect is argued case by case.
- Safety rules stay. Liveness comes from supplying verified evidence, never from skipping a check.
- Each wire or storage change is reviewed, reproduced and Accepted on its own (ADR 0087 rule 8, ADR 0085, ADR 0093).
- Accepted ADRs stay byte-identical (`scripts/adr-governance.py`), so supersession is recorded here and in the README only.
- The contract itself is small enough to be decided in W3-0.

## Considered Options

1. **One ADR** covering the contract and every mechanism. Nothing could merge until all of it was accepted and reproduced.
2. **A contract plus slice ADRs** (chosen, D37). This ADR states the contract, the may-block-forever list, the supersession table and the slice list. Each mechanism is its own ADR.
3. **Split Home from ordinary groups.** This contradicts the D32 overlay, which names one instrument (0088) for 0038, 0060, 0069 and 0062, and it would need an overlay rewrite.

## Decision

### §1 The contract

Definitions:
- **Group:** a named group, including Home.
- **Active admin:** an active seat with the Admin role on the committed roster.
- **Holder:** any active member that holds the bytes an operation needs (a commit, roster or state snapshot, a certificate, an epoch key it was admitted to, or store data), verifiable against a committed hash.
- **Liveness operations:**
  - **Admission:** seating the holder of a valid invite.
  - **Eviction:** removing a revoked or banned identity and rekeying.
  - **Catch-up:** a member reaching the group's current committed state.
  - **Repair:** restoring data or key material that a member is entitled to.

**L1. Any one is enough.** Admission and eviction complete within a bounded time when any one active admin is online and reachable. Catch-up and repair complete when any one holder is online and reachable. No operation may depend on a particular device: the owner device, the inviter, the creator or the original sealer.

**L2. Only the list may block forever.** An operation may wait without bound only for a reason on the §2 list. Any other indefinite wait, pending state or quarantine with no exit is a defect against this ADR.

**L3. Blocks explain themselves.** Whether L3 binds every slice, or stays a goal, is pending G7. As drafted, a block on the §2 list is never a silent pending state, and it takes one of two forms:
- **Definitive** entries (§2 items 1, 2, 4, 5 and 6) end the request with a typed, terminal refusal that the waiting side sees. ADR 0066 §5 already says a refusal must explain itself; the #946 `certificate_evidence_unavailable` refusal is the existing example.
- **Waiting** entries (§2 items 3, 7 and 8) are not terminal. The operation stays retryable and resumes when an admin or a holder is online, or an admin acts. Its state is typed and visible, and it names what it waits for.

**L4. No safety is traded.** These rules stay fail-closed: signature, sender authority, prev-hash linkage, owner mandate, fork evidence, revocation and the TreeKEM adoption exclusion. A slice meets L1 by carrying or fetching verified evidence. A slice that adds or relaxes an acceptance rule states that explicitly, with its own security argument (as ADR 0106 states it adds none).

### §2 May block forever (D54)

1. Re-admission of a revoked or banned identity.
2. An OwnerCertified joiner whose certificate fails against the group's owner: invalid, wrong owner, revoked or expired.
3. No active admin is ever online (admission, eviction).
4. Decryption of epochs the member was never admitted to.
5. A group its owner deleted. After a signed delete, nothing for that group completes.
6. A removed member's catch-up on epochs after its removal.
7. An ordinary group forked with no owner anchor. It stays quarantined until an admin acts by hand (ADR 0066).
8. Evidence whose holders are all offline. A fetch waits until one holder is online.

Everything else completes under L1.

### §3 Supersession table

Supersessions and amendments take effect when the named slice is Accepted. Until then the README status overlay governs new work.

| ADR | Effect | Through slice | What changes |
|---|---|---|---|
| 0038 Home: the seal-time owner-certificate verdict | Amended (interim) | S2 | A Home-scoped owner certificate and a new verdict rule. The check still runs at seal; an anonymous public announce no longer invalidates the Home-scoped certificate |
| 0038 Home: evict at next seal | Superseded in part | S4 | Revocation is by bounded eviction |
| 0038 Home: seal-time re-checks | Superseded in part | S7, only once S4 is in effect | The certificate is checked at admission only, and seals stop re-checking. This retirement waits until S4's revocation enforcement is Accepted and shipped, because the re-check is today's revocation path |
| 0038 Home: the auto-provisioned personal space | Superseded in part | S7 | Home is an explicit owner group, with the existing Home adopted in place |
| 0038 as a whole | Superseded | S2, S4 and S7 | Only once all three are Accepted. Until then, every 0038 provision not yet replaced stays in force |
| 0060 Home is elected | Superseded | S7 | Election stops; the existing canonical Home is adopted in place (D42) |
| 0069 Home waits for owner sync | Superseded | S7 | Auto-provisioning stops |
| 0064 Decision §3 | Superseded in part | S3 | A node quarantined on a stale base catches up and clears its own marker under an admin's signed terminal snapshot. A forked node gets a re-seat path (#871) only with an admin's explicit manual authorisation |
| 0066 §2 | Superseded in part | S3 | Self-recovery only (D41): the snapshot lets a node recover itself, never anyone else. Automatic stale-base catch-up is separate from unanchored-fork recovery, which stays a manual admin act (§2 item 7) |
| 0062 Home persistence pair | Decided (D54) | none | Accepted (record) of its option 1, which #617 shipped and D42 keeps. No slice dependency; its status line changes in a separate PR |
| 0016 §6 | Amended | S4 | The deterministic committer rule extends to revocation evictions (D40): the lowest online active-admin agent ID evicts and rekeys first. Any other online admin acts only if nothing lands within the bound. S4 proposes the bound's value |
| 0007 consent | Amended | S2 | D38: owning a Home implies consent only to disclosure of the owner certificate to that Home's members, delivered directly and checked at seal. Public identity announces stay anonymous unless the owner consents explicitly, as today. An anonymous public announce must not invalidate the Home-scoped certificate |
| 0059 InviteV4, 0064 §1a | Amended | S6 | Inviter pinning and the mandate preimage allow any-admin redemption |

### §4 Slices

S1 (ADR 0106) is the historical Accepted slice, with its own gate. It was reproduced in process, and its carry is gated by the existing in-message opt-in `accepts_control_blob_ref`, not by an ADR 0093 bit. The requirements below bind S2–S8.

Each later slice is its own ADR. Each one:
- names the L-rule and the holes it closes;
- has its failure reproduced in the W3-H harness before its fix (D16, D54). The only exception is S8 (a), the joiner re-arm for #1150: it ships in v0.46.1 with its committed in-process red test, and its W3-H case follows (D55);
- puts any new wire change behind an ADR 0093 capability bit;
- versions any persisted state per ADR 0085;
- is Accepted by David before its code merges (ADR 0087 rule 8).

| Slice | Closes | Rulings | Wire or storage |
|---|---|---|---|
| S1 = ADR 0106 (Accepted) | #1139, small gaps | D16 hole (a) | additive field |
| S2 Home-scoped owner certificate plus verdict rule (interim: still checked at seal; the seal-time re-checks retire later, in S7): disclosed to Home members only; public announces stay anonymous; an anonymous public announce never invalidates the Home-scoped certificate | #1143, then #1023's structural part | D38 | wire, probably the ADR 0089 EvidenceV1 carrier; size it first |
| S3 Ownerless attestation, self-recovery only: automatic stale-base catch-up; unanchored-fork re-seat only under an admin's manual authorisation (§2 item 7) | #818 part 2, #871 | D34(1), D41 | wire plus a 0093 bit; a quarantine "retired" state |
| S4 Revocation eviction, designated first: the lowest online active-admin ID first, any other online admin after the bound | #1113 | D34(2), D40 | protocol rule; a persisted obligation; the bound value is proposed in S4 |
| S5 Evidence size K plus fetch-by-hash from any holder; the single carry rule | #811 family, the certificate-carry family, the #646 primitive; catch-up as control blobs | D34(3), D54 | wire plus a 0093 bit; a holder store. No persisted authority catch-up log (D54) |
| S6 Any-admin invite redemption | offline-inviter gap | D16 | wire plus a bit |
| S7 Home as an explicit owner group, adopted in place; the admission-only check replaces the seal-time re-checks once S4 is in effect | #824 residual, #1023 structure | D16, D42 | no new closed-enum Tier-1 kind; a mixed-version check |
| S8 Stuck join rows: (a) joiner re-arm, then (b) authority re-Welcome | #1150, #1149, #1146 residual | D39 findings, D55 for (a) | (a) none; ships in v0.46.1 (D55); (b) a protocol rule reusing S4's committer |

**Acceptance order:** this contract, then S2 and S8, then S4 and S3, then S5, then S6, then S7. Slice code that touches `named_groups.rs` lands on one lane at a time.

## Rulings and open questions

David ruled G2–G6 on 2026-10-03 (D54, D55):

- **G2, the §2 list:** the draft plus items 5–8 (D54).
- **G3, catch-up storage:** fetch-by-hash from any holder (S5), not a persisted authority catch-up log. Catch-up as control blobs belongs under S5 (D54).
- **G4, harness first:** in-process red tests do NOT count. D16 stands: the W3-H harness reproduces each failure first (D54). The one exception is S8 (a) for #1150 (D55).
- **G5, ADR 0062:** Accepted (record) of option 1, which #617 shipped (D54).
- **G6, per-case certificate-carry patches:** stopped. S2 (#1143) is a rule change, and S5 is the single carry rule (D54). No new carry patch lands outside them.

Still open for David:

- **G7, typed terminal blocks (L3).** Should L3 bind every slice, including the 120 s join poll that gives up before the 10-minute #946 refusal is staged? Or should it stay a goal?

## Consequences

### Positive

- One rule decides whether a wait is a defect, so triage stops arguing case by case.
- Each mechanism is reviewed and reproduced alone, as ADR 0106 was.
- Home and ordinary groups share one contract and one evidence path.

### Negative / Trade-offs

- Supersession is staged, so the overlay and this table must be kept in step until S7 lands.
- Slices add wire contracts that later slices must keep (for example 0106's `intervening_events`).
- L1 widens who may act (any admin, any holder). Each slice must show this does not widen who may decide.

### Neutral / Operational

- Until the slices land, Home failures stay known limitations unless they are security defects (D02).
- Mixed-version behaviour is per slice. Each wire slice degrades to today's behaviour toward peers without its capability bit.

## Validation

- Each slice ADR carries its red/green reproduction and names the L-rule it satisfies.
- The W3-H harness gets one case per L-rule and per §2 entry. §2 entries must end in a typed outcome (L3). Every other case must complete with only one admin or holder online (L1).
- Review triggers:
  - a new defect class that §2 neither lists nor rules out;
  - a slice that needs a new acceptance rule (L4);
  - the end of W3, when the supersession table must be complete.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human review**. Only David Irvine marks it Accepted. Accepted ADRs are immutable: create a new superseding ADR rather than editing an Accepted ADR.
