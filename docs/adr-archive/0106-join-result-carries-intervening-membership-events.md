# ADR 0106: Join Results Carry the Intervening Membership Events

- **Status:** Accepted
- **Accepted:** 2026-10-01 by David Irvine (as written; relayed by Root, who verified the r2 diff at c06dbd3). The status change was applied by Claude (x0x-32) at his instruction.
- **Date:** 2026-09-30
- **Decision owners:** David Irvine
- **Reviewers:** Root (cross-model review: Codex or OMP)
- **Supersedes:** none
- **Superseded by:** none
- **Related:** #1139, PR #1140 (implementation and tests), #818 and #846 (TreeKEM stale-base catch-up), ADR 0088 (prov.: group liveness contract, D16), ADR 0038 (Home), ADR 0064, ADR 0087 rule 8. Serves vision **R3** (all my machines connected: a new device must be able to join its owner's Home).

This is a slice of the provisional ADR 0088 liveness contract. It closes one case of D16/D34 hole (a), the stale-base TreeKEM joiner, without deciding the rest of 0088.

## Context

A Home device joins through an invite that carries the group's base state (revision r). If the authority seals any other membership commit between minting that invite and sealing this joiner's add, the joiner's own `MemberAdded` commit arrives at r+2 and chains from r+1. The joiner's stub holds only r. The rc5 home-b1 gate hit exactly this: two seat invites were minted up front, and the second device joined after the first device's add had sealed.

Today nothing converges that joiner:

1. The r+2 apply fails `PrevHashMismatch`.
2. TreeKEM never adopts across a gap (`try_adopt_member_added_across_gap`, the deliberate #458 r6 exclusion). The chain the join result already carries ([r+1] as `RetainedCommit`s) is used only to classify the gap, never applied.
3. The #818 classifier either queues r+2 and requests TreeKEM catch-up, or declines silently. With an empty served chain it logs nothing and does not queue.
4. When the #818 path does fire, the catch-up page is sent as one plain direct message. A single Home `MemberAdded` is about 51.5 KB, over the 49,152-byte DM budget, so the page is never delivered.

The joiner's poll re-fetches the same result every ~2 s until it times out after 120 s, leaving a seat on the authority's roster with no TreeKEM state. The repro in PR #1140 is deterministic and in-process. It shows that if the joiner applies r+1 first, r+1 takes the existing pre-Welcome state-only path, and r+2 then applies gaplessly and the Welcome installs.

## Decision Drivers

- The joiner already has everything else it needs. Only the r+1 event is missing, and the authority holds it.
- No new acceptance rule, and no weakening of the TreeKEM adoption exclusion or of the #818/ADR 0064 fork handling.
- Mixed versions (0.45 ↔ 0.46) must degrade to today's behaviour, not break.
- Bounded work and size for both sides; no new transport.
- Small enough for v0.46 under the Home-freeze exception David granted on 2026-09-30.

## Considered Options

1. **Carry the intervening membership events in the join result** (chosen).
2. **Allow TreeKEM adoption across the gap** for a pre-Welcome joiner under a tier-1 owner anchor. This reconstructs state from the served `RetainedCommit` chain. It adds a new acceptance rule to a security gate that was excluded on purpose (#458 r6), so it needs its own design and review. Rejected for v0.46.
3. **Send TreeKEM catch-up pages as control blobs** so that #818 works for Home. It still needs a second round trip, and it depends on the classifier's branch, which can decline silently. It adds a new blob kind. Deferred: worth doing, but it does not fix #1139 alone.
4. **Document the limitation** ("request a fresh invite after any other device joined"). David ruled first this way, then revised it to a v0.46 fix.

## Decision

`JoinResultMessage::Result` gains one field:

```rust
#[serde(default, skip_serializing_if = "Vec::is_empty")]
intervening_events: Vec<NamedGroupMetadataEvent>,
```

**Authority.** When a `FetchRequest` carries `from_revision`, and the joiner can pull a control blob (the fetch is verified, sets `accepts_control_blob_ref` and carries an `attempt_id`, which is the blob path's own predicate), the authority takes, from its own TreeKEM membership event log (`treekem_event_log`, written at seal time), the `MemberAdded` events whose commit revision lies strictly between `from_revision` and the carried event's commit revision. It sends them only when all three hold:

- they cover **every** revision in that gap exactly once;
- there are at most **8** of them (`JOIN_RESULT_INTERVENING_EVENT_CAP`);
- no revision has two different logged commits.

Otherwise it sends an empty list, which is today's behaviour. Events are sent exactly as logged and never modified. A gap that contains any other commit (a rename, a removal) is never covered, so it is never partially sent. A joiner that cannot pull a blob never receives the carry, so the carry can never push an otherwise-inline result past the 49,152-byte DM budget and suppress its delivery.

**Joiner.**

- **Binding.** It applies carried events only for a **bound** join attempt on a verified message; an unbound result applies no carry. Each event goes through the bound apply, which re-checks the attempt's currency **under the group's membership lock**. An attempt that goes stale after the handler's pre-check therefore stops further applies.
- **Preflight, before any mutation.** The whole list is rejected unless:
  - every entry is a `MemberAdded` for this group, with a commit;
  - there are at most 8 entries;
  - revisions are unique and contiguous;
  - the last revision is exactly the terminal revision − 1;
  - the first revision is at or below the joiner's local revision + 1, so the list reaches its stub.
- **Apply.** It applies the list in revision order through the **ordinary** metadata apply, before the result's own event:
  - It skips events at or below its local revision.
  - Each event gets exactly the checks it would get if gossip had delivered it: signature, sender authority, prev-hash linkage, owner mandate, TreeKEM pre-Welcome handling.
  - If the ordinary apply refuses an event, the walk stops and **keeps the prefix already accepted**. Each accepted link is a valid, verified commit in its own right, exactly as if gossip had delivered it, and the joiner is left at a later consistent revision.

The join result's own event then follows the unchanged path, including the #818 classification, the adoption refusal and the chain and attestation context.

**Bounds.**
- At most 8 events, about 400 KB, carried only inside the join-result control blob. The blob path already exists for this message, since the live result is 95 KB, and its cap is 8 MiB.
- The control-blob validator rejects a result with more than 8 events.
- A larger gap, or an authority that restarted since the seal (the log is in memory), falls back to today's path.

**Mixed versions.**
- A 0.45 joiner does not advertise `accepts_control_blob_ref`, so it never receives the key and behaves as today.
- A 0.45 authority never sends the key; the field defaults to empty, so a 0.46 joiner behaves as today.
- A fixed authority with nothing to carry omits the key, so the wire is byte-identical to today.

## Consequences

### Positive

- A Home device whose invite predates another seal converges from its own join result, with no second round trip. It no longer depends on the #818 classifier's silent branches or on the DM-capped catch-up.
- There is no new trust rule, and the security review surface is the existing apply path.

### Negative / Trade-offs

- Larger join results when a gap exists, up to about 400 KB. This affects only the join handshake.
- Recovery depends on the authority's **in-memory** log. After an authority restart, or for a gap longer than 8, the joiner still depends on #818 catch-up, which for Home stays undeliverable until option 3 lands. The limitation narrows but does not vanish; the release note keeps "request a fresh invite" as the fallback.
- Other members' Welcomes and commits ride along unmodified. That is harmless, because the joiner's apply path ignores what does not concern it, but it costs bytes.

### Neutral / Operational

- The trace stage `join_result_intervening_event` (debug) records each applied revision and whether it was accepted.
- #818 classification, ADR 0064 quarantine and the #846 attested-sequence gate are untouched.

## Validation

- **Red/green:** `issue1139_join_result_alone_converges_second_joiner` fails with the joiner apply disabled and passes with it. With it, J2 ends `active` with TreeKEM installed and no catch-up requested.
- **Mixed versions:** `issue1139_legacy_join_result_alone_leaves_second_joiner_pending` and `issue1139_intervening_events_field_is_additive_on_the_wire` cover omit-when-empty, decoding without the key, and the legacy behaviour.
- **Bounds:** `issue1139_authority_serves_only_complete_bounded_gaps` covers the complete-gap rule, the cap, no gap, the joiner past the terminal, and a lost log. `issue1139_joiner_ignores_stale_foreign_or_oversized_carries` covers a stale attempt, a foreign group, and too many events.
- **Preflight and binding:**
  - `issue1139_preflight_rejects_malformed_lists` covers every preflight rule.
  - `issue1139_malformed_carry_applies_no_prefix` shows that a valid first link followed by a bad entry applies nothing.
  - `issue1139_unbound_result_does_not_apply_carry` covers the unbound result.
  - `issue1139_carry_only_for_blob_capable_bound_fetches` covers the authority's legacy gate.
- **Live gate:** the v0.46.0 Home gate rows 3a/3b run with the harness's up-front invite minting unchanged (the stale-invite shape), and must pass.
- **Review trigger:** revisit when ADR 0088 decides the full liveness contract, or when catch-up moves to control blobs (option 3).

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human review**. Accepted ADRs are immutable: create a new superseding ADR rather than editing an Accepted ADR.
