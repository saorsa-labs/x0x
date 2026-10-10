# ADR 0108: Home-Scoped Owner Certificate and Seal Verdict (0088 S2)

- **Status:** Accepted
- **Accepted:** 2026-10-05 by David Irvine (D178, as written: the Proposed text on main at 6544555, which records rulings D64–D173). The status change was applied by Claude at his direct instruction.
- **Date:** 2026-10-04
- **Decision owners:** David Irvine
- **Author:** Codex (GPT-6)
- **Reviewers:** Claude (cross-model r1, r2)
- **Slice:** Slice S2 of [ADR 0088](./0088-group-liveness-contract.md).
- **Amends, upon acceptance:** [ADR 0038](./0038-home-owner-certified-personal-space.md), A Home-scoped owner certificate and a new verdict rule (interim; including the direct disclosure channel that 0038:50–51 excludes); [ADR 0007](./0007-three-layer-identity-model.md), consent for disclosure to Home members only, with two named, ruled exceptions (D68, D96, kept by D124); [ADR 0088](./0088-group-liveness-contract.md) §2, one named entry (D96, confirmed by D118, §7); [ADR 0085](./0085-persisted-binary-formats-are-versioned.md) rule 4, for `home-owner-certificates.hscert` only (D120, §5); rule 5 is kept; [ADR 0107](./0107-stuck-join-rearm-and-serving-guard.md) serving guard, one named rule, "pre-admission signed replies" (D145, §8).
- **Supersedes:** none
- **Superseded by:** none
- **Goal served:** **R3** (all my machines connected) and the shared-places core.
- **Related:** D16, D35, D38, D40, D54, D60, D63, D64, D65, D66, D67, D68, D96, D117, D118, D120, D123, D124, D125, D145, D148, D149, D150, D154, D171, D172, D173; [direction digest](../design/x0x-direction.md); ADR 0085, 0087, 0089, 0093, 0106, 0107; [#1143](https://github.com/saorsa-labs/x0x/issues/1143), [#1023](https://github.com/saorsa-labs/x0x/issues/1023), [#1164](https://github.com/saorsa-labs/x0x/issues/1164), [#1107](https://github.com/saorsa-labs/x0x/issues/1107).

Keep owner-issued certificates in a Home scope and deliver them directly to its members.
An anonymous public announce never invalidates a certificate in that scope.
Every seal still checks certificates until S7 retires those checks after S4 ships.

## Context

The promoted admin in #1143 holds the creator's certificate but cannot seal an add while the creator is offline.
The join stays pending because the creator's public announce is anonymous.
This breaks **L1**: a particular owner device must act despite an online admin holding the evidence.
It also breaks **L2**: anonymity is not on the eight-item may-block-forever list.
D64 makes L3 a hard rule for every slice. §6 lists each block S2 adds or touches and its typed state. §8 defines `JoinPendingNotice`, the signed notice that tells a joiner why its join is held (D117).
L4 requires a stated argument for changing the certificate acceptance rule.

Current behaviour is grounded at commit `8b35dd1f447774e1a952166f32910fc41b512623`:

| Current path | Evidence |
|---|---|
| The evidence builder records the latest public digest even when no certificate is present. | `src/server/routes/named_groups.rs:22397–22415` |
| Both the pure failure check and the grace-aware verdict reject embedded bytes when that digest differs. Neither distinguishes an anonymous digest. | `src/groups/mod.rs:1462–1475`, `:1575–1588` |
| The seal gathers evidence for all active seats and refuses a verdict that is not all clean. | `src/server/routes/named_groups.rs:22513–22541`, `:22638–22665` |
| The regression test uses an ordinary PublicRequestSecure + OwnerCertified group, without Home metadata; retain its pending expectation. Add a Home twin with the opposite expectation. | `src/server/routes/named_groups/tests/r19_cert_carry.rs:45–93` (`anonymous_announce_invalidates_hand_installed_cert`) |
| Digest-only seats remain pending until matching bytes hydrate them. Hydration does not change their commitment. | `src/groups/mod.rs:1564–1573`, `:1743–1786` |

#1023 initially asked for another certificate carry while keeping the verdict unchanged.
Its later triage separates missing bytes from #1143's false contradiction.
D54 stops per-case carry patches: S2 changes the rule; S5 owns the general carry and fetch rule.
S2 closes the false contradiction and gives Home evidence a disclosure scope.
It does not close #1023's all-holders-offline case or remove its seal-time structural dependency.
Those parts remain with S5 and S7. ADR 0088's S2 row says “then #1023's structural part”; read it with its S5/S7 rows, not as retirement of the seal dependency in S2.
The [#1023 triage of 2026-10-03](https://github.com/saorsa-labs/x0x/issues/1023) assigns completed carry to #1025/#1056 and the remaining false contradiction to #1143; the general carry and structural retirement stay staged.

D38 derives implied disclosure consent from ownership of this committed Home, not `user_identity_consented`.
That consent survives restart by construction: revalidate Home metadata and policy, rather than restore a global flag.
S2 does not persist the global consent flag, carry certificates on stream/exec/forward/SyncV1 opens, or fix ADR 0070 owner trust ([#1107](https://github.com/saorsa-labs/x0x/issues/1107)).
The restart proof must avoid those owner-trust gates; #1107 is an excluded confounder, not claimed fixed.

## Decision Drivers

- D38 gives consent to Home members only. Public disclosure still needs explicit consent.
- An admin with valid committed evidence must not need the creator's live announce.
- Evidence must survive restart without becoming a public certificate cache.
- S2 must work before S5 and preserve the staged supersessions in ADR 0088.

## Considered Options

1. **Scoped direct evidence plus a scoped verdict** (chosen). Separates disclosure from public discovery and retains the seal gate.
2. **Always publish the owner's certificate.** Rejected by D38's Home-members-only refinement.
3. **Ignore the anonymous digest in the existing global cache only.** Rejected: it supplies no scoped disclosure path and does not implement all of D38.
4. **Add another roster or JoinResult certificate sidecar.** Rejected by D54. S5 owns the single general carry rule.
5. **Remove seal checks now.** Rejected: S7 owns retirement, after S4's bounded revocation enforcement is Accepted and shipped.
6. **Reuse EvidenceV1 Hello/Lookup unchanged.** Rejected: those messages have no Home scope and Lookup permits other relationship contexts.

## Decision

### 1. Scope and certificate identity

"Owner certificate" means an existing owner-issued `AgentCertificate` for a Home seat, including the creator's seat.
Its signature and expiry encoding stay unchanged (`src/identity.rs:487–515`, `:530–542`).
The disclosure context is `(group_id, owner_user_id, subject_agent_id, committed_certificate_digest)`.
Use fixed 32-byte IDs and the roster's BLAKE3 certificate digest, not the public announce digest.
The existing digest hashes canonical bincode certificate bytes (`src/groups/owner_cert.rs:321–329`).

Define a per-group predicate: verified Home metadata covered by the current state hash, policy equal to `home_policy(owner)`, and not withdrawn; serving also excludes deleted or quarantined state.
Use the exact policy check at `src/server/routes/home.rs:68–76`.
Do not use `resolve_home` (`:320–366`): it needs the local user keypair and selects one Home, whereas this predicate works for each committed group without that keypair.
Do not extend implied consent to every ordinary OwnerCertified group or to another Home of the same owner.
S7 owns adoption and election changes; S2 introduces no Tier-1 kind or Home replacement.
An invite alone does not make its holder a member entitled to receive this evidence.
The joiner's existing submission of its own admission certificate stays unchanged.

### 2. Direct delivery on EvidenceV1

Name the ADR 0093 registry-v1 capability **`home_owner_certificate_v1`**.
It means support for this scoped exchange, carrier redaction and Home verdict rule.
Its number is allocated at acceptance, in acceptance order, as the next free bit in the README registry.
Do not allocate a number or add a registry row here; the accepting PR updates the registry and constants together.
Require both `home_owner_certificate_v1` and `peer_evidence_v1` in a current verified, machine-bound advert before a scoped send.
Unknown, expired, card-only or stored capabilities do not authorize a send.
Refresh the advert through the existing route; expose missing support as retryable `recipient_upgrade_required`.
Do not probe an unknown receiver with certificate bytes; other ADR 0093 sends retain their existing gates.

Reuse stream protocol `EvidenceV1 = 0x06`; retain Put/Ack frame types 7/8 and add the small completion receipt needed to suppress other holders:

| Type | Frozen fixed-integer bincode body |
|---|---|
| 7, `HomeCertificatePutV1` | A vector of 1..K certificate entries, each with four `[u8; 32]` context fields in the order above, then `certificate: Vec<u8>` |
| 8, `HomeCertificateAckV1` | Typed `Accepted(generation)`, `Retry(reason)` or `Refused(reason)`, encoded by explicit `u8` tags; Accepted adds the recipient's `u64` recovery generation and 16-byte store incarnation, and Retry/Refused add one `u8` reason |
| 9, `HomeCertificateReceiptV1` | Four context fields, then recipient `[u8;32]`, then the recipient's `u64` recovery generation and `[u8;16]` store incarnation; no certificate bytes |
| 10, `HomeCertificateWithdrawV1` | `group_id`, `owner_user_id` and recipient, each `[u8;32]`, then the recipient's `u64` recovery generation and `[u8;16]` store incarnation (D120, below) |
| 11, `HomeCertificateWithdrawAckV1` | Typed `Applied` (tag 0), or `Stale` (tag 1) followed by the holder's recorded `u64` generation for that recipient |

K = 1 for S2; S5 (ADR 0111) raises it to K = 4 at its acceptance (D93). The V1 vector shape is frozen now; validate its 1..K bound before accepting any entry. The V1 Ack covers the whole frame, all-or-nothing: Accepted means every entry was stored; any Retry or Refused means none was. A Receipt names one context per entry. So a later K > 1 needs no new Ack shape.
Carry each certificate's existing `to_storage_bytes()` encoding verbatim.
On wire and file intake, require `to_storage_bytes(decoded) == received_certificate_bytes` and recompute the canonical roster digest.
`from_storage_bytes` uses permissive `bincode::deserialize` (`src/identity.rs:810,813`); decoding alone does not reject trailing bytes.
Each Put stream carries one Put and one Ack; a receipt-only stream carries one Receipt with no reply, and a withdraw stream carries one Withdraw and one WithdrawAck. Types 1–6 and their bodies stay unchanged.
No announcement, advert or user key is added to this body.
Derive each sender/recipient agent from verified current evidence binding it to the live transport machine; refuse an ambiguous binding.
The pre-identity admission of EvidenceV1 alone grants no right to send or receive Home evidence.

Ack has a frozen manual tagged encoding, not bincode's four-byte Rust enum discriminant: Accepted=0, followed by the `u64` generation and the 16-byte incarnation; Retry=1; Refused=2.
The reason is a typed `u8`: Retry uses context_unavailable=0, recipient_upgrade_required=1, capacity=2, persistence_failed=3, busy=4, ambiguous_binding=5 (bindings move under ADR 0089, so this must stay retryable); Refused uses invalid_certificate=0, digest_mismatch=1, ineligible=2, malformed=3.
Unknown tags/reasons or extra bytes are protocol errors and never acceptance.
Accepted means durable evidence acceptance, never membership admission or key installation; persist the sender's acknowledgement receipt and stop that pair's retries.
Retry sends no receipt and waits for its named condition to clear; the sender re-attempts only inside its own 30 s slot (D66, below); re-admit each attempt.
Refused terminates that context/recipient delivery, persists the visible terminal cause and cancels retries across reconnect/restart; a newly verified context or eligibility change may create a fresh delivery.
Timeout, lost Ack or transport failure stays unacknowledged and retries idempotently; no transport-layer automatic replay.

Use one designated pusher per context/recipient, with ordered fallback in the D40 pattern; independent all-holder pushes are forbidden.
Ranks come from committed state, never from a node's discovery view (D66, below). A candidate must hold verified matching bytes before it can act.
The first rank gets the first attempt; later ranks get successive fallback slots only after no acknowledged completion in earlier slots. A rank without bytes lets its slot lapse.
The recipient returns Accepted for an already-durable duplicate, then sends Receipt directly to the other N−2 candidate holders to suppress later fallback slots.
Authenticate a Receipt as coming from its named recipient on the live bound machine, require current matching Home context/membership and persist it as an Accepted receipt; a pusher cannot assert another recipient's acceptance. Gate Receipt by the same capabilities; never gossip or forward it. Lost Receipt can permit a counted duplicate in a later fallback slot.

**Recovery generation (D120).** Every acceptance is bound to the recipient's durable store identity: a recovery generation plus a store incarnation. A late acceptance from before a rebuild therefore cannot suppress recovery. The generation is a logical (Lamport) counter and never uses wall time.
- **Recipient side.** Each node's sidecar header holds its `store_generation: u64` and `store_incarnation: [u8;16]` (§5). A new store takes generation `g + 1`, where `g` is the highest generation this node can still read, including from damaged or pending copies' headers; with none readable it starts at 1. It takes a fresh random incarnation. A `Stale(recorded)` reply sets the generation to `max(current, recorded + 1)`, using checked addition, so the counter never goes down: after `Stale(100)` gives 101, a delayed `Stale(5)` leaves it at 101. Each bump runs under the sidecar's writer lock (§5a) and is persisted in the header before any message carries the new value. A crash after the persist and before the resend restarts with the bumped value. If the addition would overflow, the node stops sending Withdraws and shows `home_cert_store_generation_exhausted`; at one bump per `Stale` this is unreachable in practice. Accepted Acks, Receipts and Withdraws carry the generation and the incarnation.
- **What is claimed.** Holders compare the pair `(incarnation, generation)`, never the number alone. A store that lost its header restarts at 1 and can reuse a number its lost store used. Under its new incarnation that is a detected collision, which gets `Stale` and then a bump. S2 does not claim that generation numbers are never reused. It claims that no receipt from a lost incarnation is ever restored.
- **Holder side.** A holder persists, for each `(Home, recipient)`, the recorded generation and incarnation, and stores each Accepted receipt at that generation.
- **Invariant.** A holder never keeps an Accepted receipt for a recipient below that recipient's recorded generation. Every raise of the recorded generation, from an Ack, a Receipt or a Withdraw, handles the lower receipts for that `(Home, recipient)` in the same atomic write. If the incarnation changed, the old store is gone, so they are deleted. If it is the same incarnation, the store only bumped its counter after a `Stale` reply, so they are relabelled to the new generation and kept.
- **Accept rule.** An Accepted from an Ack or a Receipt is handled like this:
  - generation above the recorded one: raise the recorded generation and incarnation, handle the lower receipts as above, and record this receipt, all in one atomic write;
  - equal generation and equal incarnation: record the receipt;
  - equal generation but a different incarnation: a collision, so discard it;
  - lower generation: discard it.

  A discarded Accepted leaves the pair outstanding.
- **Withdraw rule.** A Withdraw must come from the authenticated named recipient, an active member of that Home.
  - Above the recorded generation: raise, handle the lower receipts as above, reply `Applied`.
  - Equal generation and incarnation: delete any receipt still below it, reply `Applied`.
  - Equal generation with a different incarnation, or a lower generation: reply `Stale(recorded generation)` and change nothing.
- **Collision recovery.** A rebuilt node may start at or below a generation that a holder recorded for its lost store, because the old header is unreadable. That holder answers `Stale`, and the node persists `max(current, recorded + 1)` before it sends again; a holder that was offline does the same when it returns. Until a holder has applied the node's Withdraw, it discards the node's Acks and Receipts, so a lost store's generation never restores an old receipt. A later bump within the same store only relabels receipts. The cost is one `Stale` round trip per such holder and counted re-pushes, never a false acceptance.
- **Within one store** a recipient never loses bytes. Any loss starts a new store, with a new incarnation and a generation above every one it can read. So an Accepted that matches the recorded generation and incarnation is always true.
- **Why a Lamport counter.** David asked whether a logical clock should replace wall time here (note on D171). Safety already rests on the incarnation and the `Stale` negotiation; wall time only made a `Stale` round trip less likely. A Lamport counter keeps both invariants without trusting any clock. A per-holder vector of `(incarnation, counter)` was also considered and rejected. There is one writer, the recipient, so a total order per recipient is enough; a vector adds per-holder state on the recipient and on the wire and buys no extra safety.

A slot holder alone retries within its slot; a late earlier holder must wait for a new round instead of racing the current rank.

**Slots and rounds (D66).** Each fallback and retry slot lasts 30 s.
- **Anchor.** The anchor of a `(context, recipient)` pair is the signed `GroupStateCommit` that triggered its delivery: the latest commit that created the pair (seated the subject's digest or the recipient) or changed its candidates (seated or removed one). Every node derives it from committed state.
- **Ranks.** Rank the active seats on the anchor commit's verified roster, other than the recipient, by agent ID. Every node with that commit computes the same ranks.
- **Slots (D172).** The anchor time is the anchor commit's signed `committed_at`, in milliseconds (`src/groups/state_commit.rs:465,495`). It is the same on every node, so nodes that capture or load the anchor at different times still share one schedule. Wall time is read once at each load or first apply: the phase is `p = wall_now − committed_at` in milliseconds, with no rounding. After that, slots advance by the monotonic clock: slot `s = floor((p + monotonic ms since that read) / 30,000)`. Keeping the fraction means a node that loads at t = 15 s reaches slot 1 at t = 30 s, like every other node. **Future-dated anchor (D173).** If `committed_at` is ahead of the node's wall time, the node holds at the shared anchor. It sends nothing for those pairs, shows the typed wait `anchor_future_dated { committed_at }`, and re-reads wall time until it passes `committed_at`. Slot 0 then begins, so only the first rank may push, and D172's phase applies from that read. No node uses a local time in place of the anchor, so staggered capture can never cause a burst. Cost, as ruled: if the first rank is offline, the push waits as long as the signer's clock error, after which the next ranks follow 30 s apart. A later commit that re-anchors the pairs also ends the wait. Slot `s` belongs to rank `s mod R`, where R is the number of ranked seats; after the last rank a new round starts at the first.
- **Restart.** Reconnect and restart never reset the anchor, because its proof is durable (below). A restart reads wall time once to compute `p`, so a restarted node rejoins the shared schedule at its true phase; it does not start its own. After a wall-clock rollback across a restart, `p` can be smaller than before, down to 0: the node repeats at most the slots it already passed, which costs counted duplicates and at most one round of delay, and the schedule still advances every 30 s.
- **Lapse.** A ranked seat that has left, lacks verified bytes or lacks the two capabilities lets its slot lapse. Each legacy seat therefore adds one lapsed 30 s slot per round.
- **Divergent views.** A node whose view is quarantined, or whose head is not a verified committed state, computes no rank and sends nothing. It shows the typed wait `rank_view_unreconciled` (§6) until verified reconciliation.
- **Skew.** Clock skew between nodes, or a rollback before a restart, can overlap adjacent slots. The result is a counted duplicate that Accepted absorbs.
- **Durable anchor.** `commit_log` keeps only the newest 4,096 commits per group (`COMMIT_LOG_CAP`, `src/groups/mod.rs:753`). An anchor commit and its roster can therefore leave committed history while a pair is still outstanding. Each node keeps its own anchor proof in the S2 sidecar (§5): the signed anchor commit plus the roster projection that its `roster_root` commits to. Ranks and slots derive only from that retained proof, never from `commit_log`. A restart reloads it, so the schedule survives both restart and history truncation.
- **Missing proof (D123).** A node with no verified anchor proof for an outstanding pair re-anchors that pair on its current verified head. This happens after snapshot catch-up, a long downgrade, a quarantine rebuild (§5) or a first start whose anchor already left `commit_log`. The node captures the head's signed commit and roster projection as the proof, persists it with the pair record in one atomic write, and ranks from it. Nodes at the same head derive the same anchor and share one schedule. A node that still holds the original proof keeps using it. Two views can overlap; the cost is counted duplicates, at most one sender per slot per view. A re-anchor never grants authority. A node whose view is quarantined or unverified does not re-anchor; it waits as `rank_view_unreconciled`.

A slot grants no authority. Every send still passes the eligibility checks in §4, and the receiver's checks are unchanged.
New committed seats, reconnects and eligible seal retries make a node check its unacknowledged `(context, recipient)` pairs; it sends only in its own slot. Persist receipts in the scoped sidecar before suppressing work across restart.
Lost receipt persistence can cause duplicates in later fallback slots; Accepted is idempotent and restores the receipt. It never causes an all-holder burst.
Sealing does not wait for all recipients to acknowledge.
S5 (ADR 0111) reuses this Home push and its scope rather than starting a parallel push; it adds its general retrieval/inline-K rule without duplicate distributions. Any later retirement of this push needs an explicit successor decision.

#### Existing certificate carriers: Home egress is part of S2

| Carrier today | Home rule under S2 |
|---|---|
| #970 `JoinResult.roster_certificates_b64` | Interim until S5 (ADR 0111) is in effect: serve only directly to the currently committed, authenticated recipient under ADR 0107; no public blob or gossip fallback. |
| #1023 `MemberAdded.roster_certificates_b64` | Interim until S5 (ADR 0111) is in effect: retain in guarded direct member copies; drop from the gossip copy. |
| `MemberJoined` admission certificate and `MemberAdded.certificate_b64` (joiner's own certificate) | Retain on the gossiped copy as a **named interim exception, ruled by David (D68)**. It stays until S5 (ADR 0111) removes it; guarded direct copies stay unchanged. |
| #946 `GroupCertFetchResponse.cert_json_b64` | **Named, ruled, time-limited exception (D96, §7)**: upgraded Home holders keep answering #946 as today, including metadata-topic answers, until D35's minimum supported version drops the peers that need it. |

The #1023 sidecar is built at `src/server/routes/named_groups/seat_cert_fetch.rs:696–732,752–789`, attached at `named_groups.rs:14061`, and published with `certificate_b64` at `:14051,14080`; equivalent publish paths include `:19290,19298,19562,19570`.
#946 currently publishes answers at `seat_cert_fetch.rs:403–425`; its topic answers are the D96 exception (§7).
The joiner's own certificate is on `MemberJoined` at `named_groups.rs:33647`, published at `:33685` and re-sent at `:33482`. ADR 0028 relays that signed event unchanged, so the certificate cannot be stripped. Every receiver rejects an OwnerCertified `MemberAdded` without `certificate_b64` (`named_groups.rs:11249–11255`); dropping it would introduce a new acceptance rule. Both joiner-certificate fields therefore remain the named interim exception.
David ruled that S5 owns that change (D68). S5 (ADR 0111) adds the digest-only-add rule, with its security argument and mixed-version plan, and fills the bytes by fetch-by-hash. S2 adds no rule for these fields. The exception ends where S5's rule is in effect, under S5's mixed-version plan: in a Home where every active seat and the joiner set S5's capability in a current verified advert. In a Home with any seat that lacks it, or whose advert is unknown, the exception continues until that seat upgrades or leaves, or until D35's minimum supported version. A later ruling sets that version (D125).
David kept this exposure and named it (D124); the ADR README's ADR 0007 overlay lists it. Exposure until then: each Home join publishes the joiner's own owner certificate on gossip, where non-member mesh peers receive it. The certificate links the owner's user ID to that agent.
The metadata topic is plaintext and its mesh can contain non-members (`src/gossip/pubsub.rs:1203–1228`, non-member-mesh test around `:5072`); a topic subscription is not membership authentication.
Redact only the gossip projection, retaining the committed certificate digest and signed commitment; never rewrite signed bytes. Apart from the two named exceptions (D68 joiner certificate, D96 #946), if any nested artifact contains certificate bytes, withhold that artifact from gossip and deliver it directly under the same guard.
Audit all event, state/snapshot, recovery, blob and retransmission serializers for nested copies; apart from those two named exceptions, no owner-certificate bytes may leave a Home node except to a directly authenticated member of that Home.
The joiner's existing submission of its own admission certificate remains unchanged (it is gossiped; see the D68 exception above).
S5's K inline certificates follow the same Home rule. S5 ends the D68 exception, and its general carry rule cannot restore other gossip leakage.
Legacy nodes can still leak through today's carriers: upgraded nodes enforce this rule on every own write, and S2 makes no fleet-wide privacy claim while legacy senders remain.

### 3. Size before implementation

The fixed ML-DSA-65 sizes are 1,952 bytes per key and 3,309 bytes per signature (`src/upgrade/signature.rs:14–17`).
The three vectors add 24 bytes of lengths; issuance adds 8 bytes.
The expiry encoding and storage marker follow `src/identity.rs:766–804`.
These are calculated encoded sizes at S2 K = 1, not measured transport throughput; Put includes the outer certificate-entry vector's 8-byte length prefix.

| Bytes | No expiry | With expiry |
|---|---:|---:|
| Canonical certificate for roster hashing | 7,246 | 7,254 |
| Certificate storage bytes carried by Put | 7,245 | 7,258 |
| Put at K=1, including 8-byte entry-vector length, 128-byte context, 8-byte certificate-vector length, 5-byte frame and 1-byte protocol prefix | 7,395 | 7,408 |
| Accepted Ack (5-byte frame + 1-byte tag + 8-byte generation + 16-byte incarnation; same EvidenceV1 stream) | 30 | 30 |
| Retry/Refused Ack (adds one reason byte) | 7 | 7 |
| Put plus Accepted Ack | **7,425** | **7,438** |
| Put plus Retry/Refused Ack | 7,402 | 7,415 |
| Receipt (184-byte body + 5-byte frame + 1-byte protocol prefix) | 190 | 190 |
| Withdraw (120-byte body + 5-byte frame + 1-byte protocol prefix) | 126 | 126 |
| WithdrawAck: Applied / Stale | 6 / 14 | 6 / 14 |

With one designated pusher, the successful no-loss costs below use the worst-case expiring certificate. Put/Ack costs include Accepted Acks; the total column also counts one 190-byte Receipt to each other candidate. These are not transport throughput or a loss-independent bound.

| Distribution at N active seats | Put/Ack pairs | N=5 Put/Ack bytes | N=5 receipt bytes | N=5 total application bytes |
|---|---:|---:|---:|---:|
| One changed certificate to all other seats | N−1 | 29,752 | 2,280 | 32,032 |
| One cold member gets the N−1 existing certificates | N−1 | 29,752 | 2,280 | 32,032 |
| Initial complete fleet distribution | N(N−1) | 148,760 | 11,400 | 160,160 |
| Reconnect/fleet restart with all Accepted receipts durably stored | 0 | 0 | 0 | 0 |
| Restart with q unacknowledged pairs (q≤20 for one N=5 distribution) | q | 7,438 × q | 570 × q | 8,008 × q |
| One duplicate/fallback wave covering all fleet pairs after lost Acks/receipts | N(N−1) | 148,760 | 11,400 | 160,160 |
| All-local, acknowledged seal | 0 | 0 | 0 | 0 |

Receipt traffic is `190 × (N−2)` per successful pair; N=2 has no other candidate to notify.
Each Retry/Refused adds one byte to its attempted pair; a lost Ack costs the Put alone, and each actual retry/fallback adds a separately counted exchange.
The rejected all-holder policy costs `(N−1)^2` pairs (119,008 bytes at N=5) for one cold member, and `N(N−1)^2` pairs (595,040 bytes) for a fleet restart without receipts.
Designation removes that sender multiplier; losses, changed rosters and fallback rounds can still add duplicates. Do not claim a universal traffic bound under faults.
A seal retry distributing q eligible unacknowledged pairs costs `[7,438 + 190 × (N−2)] × q` on success; verification remains per active seat.
QUIC/TLS overhead, capability refresh and existing commit/Welcome traffic are excluded. Every failed attempt, repeated Receipt or capability exchange must be counted separately; no coordination traffic is hidden in the successful totals.
Each V1 Put carries a vector of 1..K certificate entries, with K = 1 for S2; S5 (ADR 0111) may raise K at its acceptance. Do not repeat acknowledged bytes in every seal.
Keep ADR 0089's 32 KiB frame cap, 5 s deadline, per-machine stream/rate limits and global budgets; charge all frames to them.
Fair scheduling by Home, the 16 MiB file cap and pruning are ruled (D67); §5 states them.

### 4. Verdict and L4 security argument

Add scoped bytes as an extra committed-bytes source in `OwnerCertEvidence`, selected only by the per-group Home predicate and matching committed seat digest.
Evaluate `owner_cert_verdict(&mut self, ...)` on the real roster, not a hydrated clone: preserve its stamps and clears of `certificate_missing_since_ms` (`src/groups/mod.rs:1509,1538–1542,1595–1600,1630–1635`).
Matching scoped bytes satisfy the digest-only seat before its DigestPending branch; they leave the roster root and legacy byte fields unchanged.
The two production evaluation sites are `src/server/routes/named_groups.rs:21305,22638`; `owner_cert_admission_failures` (`src/groups/mod.rs:1432`) has no caller today, but keep its pure semantics consistent.
Newly scoped bytes persist only in the scoped file, never in legacy roster or public-cache files.
Re-check owner, subject, signature, expiry and current revocation at each use.
Use the existing verifier (`src/groups/owner_cert.rs:345–380`).

**Acceptance rule relaxed:** for this Home verdict, the canonical anonymous public digest is absence of public disclosure.
It is never a contradiction, never a warranted certificate fetch, and never starts missing-evidence grace for an otherwise valid scoped certificate.
A valid matching scoped or roster-embedded certificate yields `Clean` despite that anonymous digest.
A different certificate-bearing public digest retains today's stale-evidence handling; S2 does not decide certificate rotation policy.
Absent bytes stay pending. Invalid, wrong-owner, wrong-agent, expired or revoked evidence never becomes clean.
Ordinary groups retain their current rules.

An anonymous digest now has the same effect as no discovery entry, which already permits clean committed evidence (`src/groups/mod.rs:1463,1576`).
Only the subject agent's authenticated bound machine can sign its announce; an arbitrary third party cannot manufacture this absence signal.
Residual risk: an anonymous announce after re-issue erases the public rotation signal, so an older, valid committed certificate can seat again. S2 neither detects nor solves that rotation case; revocation remains the kill switch (`src/groups/owner_cert.rs:337–344`).

The security argument is separation of consent scopes: anonymity says nothing about the owner's signed binding inside Home.
Transport delivery adds no authority to the certificate; the owner signature and committed digest establish it.
No signature, sender-authority, prev-hash, owner-mandate, fork, revocation or TreeKEM adoption check is relaxed.
Seals still require all active seats clean; missing evidence is not permission to seal.

Before every Put or resend, require sender, subject and recipient to be active in this Home and not banned or revoked.
For third-party certificates require current Clean sender/recipient evidence and valid current machine bindings.
Allow a self-subject Put (`subject = sender`): verify the sender's own certificate against its committed digest and owner, and allow an active committed recipient with a current authenticated binding even if its own certificate bytes are DigestPending.
Check bans, agent/machine/binding revocations, known expiry and definitive invalid evidence; this narrowly scoped certificate bootstrap avoids the mutual-digest deadlock. It grants no Clean verdict, admission or class-K entitlement to the recipient.
Refuse withdrawn, deleted or quarantined Home state.
Apply ADR 0107's serving guard to every join/recovery artifact and D60 to class-K material: “every delivery and resend requires current recipient eligibility and the current secret epoch” (David, 2026-10-03), including agent/machine/binding revocation, expiry, verdict change and quarantine.
For scoped-only Home seats, ADR 0107 uses its permitted current `Clean` verdict alternative, computed from scoped committed bytes; it does not require writing those bytes into the roster or use discovery as authority.
The self-subject Put bootstrap exception cannot authorize a join artifact, Welcome or K share.
Linearize selection, the immediate pre-write eligibility/epoch check, and each physical exchange with membership invalidations under the Home membership lock; re-admit every resend.
Track and cancel in-flight disclosure before removal, ban or deletion commits; check current revocation, expiry and bindings at each transport handoff.
Use one bounded direct QUIC exchange with no hidden resend, gossip fallback or relay.
The receiver repeats these checks against its verified local committed roster; missing context is retryable and grants no evidence authority.
Keep scoped bytes out of public announces, public blob fetch, AgentCards, general EvidenceV1 Lookup and unrelated grant/trust views.
Any existing output fed by scoped bytes must enforce this same disclosure scope; already delivered bytes cannot be recalled from a former member.
The [join-artifact lifecycle note on #1190](https://github.com/saorsa-labs/x0x/blob/e645ce253bac6fc36b1dffd2398836da1f0096e8/docs/design/join-artifact-serving-lifecycle.md) is related work on serving and egress only.
S2 does not depend on that branch, its caches or its implementation.

### 5. Persisted state and mixed versions

Use a separate `<data_dir>/home-owner-certificates.hscert`, new extension and magic **`X0HCV1\0\0`**; old binaries do not scan this extension.
Freeze the V1 body as a header, then six ordered vectors. The header is `store_generation: u64` and `store_incarnation: [u8;16]`, this node's store identity (§2), then `rebuilt_from`, a vector of at most 255 `[u8;16]` transaction IDs (§5a; the bound is a decode limit). Ordinary rewrites keep `rebuilt_from`; the next rebuild replaces it.
1. certificate entries (four context fields, storage-byte vector);
2. Accepted receipts (four context fields, recipient `[u8;32]`, the recipient's `u64` generation);
3. terminal Refused deliveries (four context fields, recipient `[u8;32]`, typed `u8` refusal reason);
4. outstanding pairs (four context fields, recipient `[u8;32]`, anchor key `[u8;32]`);
5. anchor proofs (anchor key, then the proof below);
6. recorded recipient identities (`group_id [u8;32]`, recipient `[u8;32]`, `u64` generation, `[u8;16]` incarnation).

Sort each vector by its fixed-field tuple. Reject duplicates, conflicting Accepted and Refused entries, a pair that is also Accepted or Refused, a pair whose anchor key has no proof, a proof that no pair references, and an Accepted receipt whose generation differs from the recorded one for its recipient. A newly verified context/eligibility change clears the obsolete refusal atomically; restart alone does not.

**Anchor proofs (D66).** They keep each outstanding pair's schedule independent of `commit_log` retention.
- **Key.** The anchor key is the 32 bytes that the anchor's `state_hash` hex decodes to. Refuse a `state_hash` that does not decode to exactly 32 bytes.
- **Proof.** Store the signed commit fields byte-for-byte as signed, in `signable_bytes` order (`src/groups/state_commit.rs:476–497`), then `signer_public_key` and `signature`. Then store the roster projection entries sorted by agent ID: agent ID string, role byte, state byte, optional certificate-digest string, each exactly as `roster_root` hashes it (`:107–130`). Never re-encode a hashed or signed field.
- **Check at load and at use.** The signature verifies (`verify_structure`, `:554`). The projection re-derives the commit's `roster_root` (`roster_root_of_projection`, `:184`, as `RetainedCommit::roster_root_consistent` does at `:237`). The commit's group matches the pair's context, and its revision is not above the node's verified head. A proof that fails makes the file unreadable: it is never used, and the file is quarantined and rebuilt (D120, below).
- **Capture.** When a node applies a commit that creates or re-anchors outstanding pairs, it writes their pair records and the new proof in one atomic sidecar write, before its first send for those pairs. The proof comes from the commit being applied, so capture needs no history lookup. At startup, a node captures any outstanding pair that has no record from `commit_log` if its anchor is still there; otherwise it re-anchors the pair on its current verified head (D123, §2).
- **Lifetime.** Remove a pair record in the same atomic write that persists its Accepted receipt or Refused delivery, re-anchors it, or prunes it under D67. Remove a proof once no pair references it. Never remove a proof that an outstanding pair references.
- **Size.** About 12 KB per proof for a 5-seat Home with today's hex fields; the signature and signer key are most of it. Each pair record is 192 bytes. A Home usually has one live proof, because any seat change re-anchors every outstanding pair. Proofs count toward the 16 MiB cap. A proof that would exceed it is not written, and its pairs wait as `retry(capacity)`.

Use `DefaultOptions::new().with_fixint_encoding().reject_trailing_bytes()` for wire and file bodies, with bounded decoding (`src/evidence_wire.rs:45–50`); bare DefaultOptions is varint.
Require exact body consumption and canonical certificate re-encoding equality on file as on wire; validate signatures/commitments before use and membership/revocation again at use.
Persist accepted bytes before Accepted Ack, and sender receipts before durable retry suppression: temp file, fsync file, atomic rename, fsync directory (ADR 0089 §3). A write failure yields Retry(persistence_failed); duplicate Put is idempotent.
Do not append fields to `peer-evidence.bin` or persist derived `Clean` verdicts.
Retain ADR 0089's 10 KiB certificate limit.

**Cap, pruning and fairness (D67).**
- **Cap.** The file holds at most 16 MiB, about 2,270 entries at 7.4 KB each. A Put that would take it past the cap answers `Retry(capacity)`, stores nothing and leaves the file unchanged. Capacity pressure never yields usable unverified evidence.
- **Pruning.** Prune a certificate entry, Accepted receipt, Refused delivery or recorded generation only after a verified commit invalidates the membership of its subject or recipient in this Home: removal, ban, revocation, withdrawal or a signed Home delete. Never prune for an active seat. A quarantined or unreconciled view never prunes. Pruning uses the same atomic rewrite as any other change.
- **Fairness.** Schedule Puts, Receipts and intake fairly by Home inside ADR 0089's existing per-machine and global budgets. When several Homes have due work, serve them round-robin by Home, so no Home starves another. S2 adds no new rate or budget.

Keep `named_groups.json` and `home-suite-groups.json` in their unchanged legacy-safe JSON formats (#451); do not place scoped bytes or new fields there. S2 writes no legacy-view placeholder; existing #451 behaviour is unchanged.
Defer any first sidecar write that changes host behaviour until ADR 0094's host commit where applicable.
Follow ADR 0085: new magic for a changed body, frozen released decoders, lazy rewrite, atomic replace and released-binary fixtures.
No released binary yet writes X0HCV1: before code merges supply a golden encoder fixture, covering the header and all six vectors including anchor proofs, plus SHA-256 and provenance; the first release writing it supplies the actual released-binary fixture, retained by every later decoder test.

**Unreadable file: quarantine and rebuild (D120).** David ruled that each slice quarantines an unreadable sidecar and rebuilds it from holders, against the recommendation (D120). S2 follows the shared lifecycle in §5a for `<data_dir>/home-owner-certificates.hscert`. Only the S2-specific parts are stated here.
- **Header layout.** The 8-byte magic is the family prefix `X0HCV`, then a version of 1 to 3 ASCII digits with no leading zero, then zero bytes to fill 8 bytes; a 3-digit version leaves no terminator. The highest supported version is 1. The prefix is reserved for this path forever (§5a), so `X0HCV2\0\0` and later are newer, and anything else is damage. No released binary scans the `home-owner-certificates.hscert.q-*` or `.tmp-*` names that §5a creates.
- **Memory-only behaviour.** In `sidecar_unavailable`, `sidecar_newer_format` or `sidecar_quarantine_failed` for this file, intake verifies bytes and holds them in memory for the process, and answers `Retry(persistence_failed)`. In `sidecar_newer_format` the node sends no Withdraw, because its durable store is intact for the re-upgrade. Other holders still serve the group (L1).
- **Replacement (§5a step 4).** An empty V1 file with a new store identity (§2), whose generation is above any this node can read, including the pending copy's header, and `rebuilt_from` set to the transactions it covers.
- **Missing file.** If the path is absent and no pending copy exists, S2 creates a new store with a new identity. If this node already holds a Home seat, it starts the rebuild below.

**Rebuild source.** Once the replacement is durable (§5a step 4), S2 refills it:
- **From holders.** The other seats still hold Accepted receipts for this node at its old generation, so they would never push again. While any committed context in a Home is missing locally, the node sends `HomeCertificateWithdrawV1` with its new generation and incarnation to every other active seat of that Home. A higher generation voids that holder's receipts for this node (§2). Each pair becomes outstanding again, is re-anchored on the holder's current head (D123), and the designated holder pushes in its slot. S5's fetch adds a second source once it is in effect.
- **Retries are condition-driven.** The node re-sends a Withdraw to a holder on each new connection to it, and on a retry interval while a connection stays open, for as long as a context in that Home is missing. It does this even after an `Applied`, because a holder that later rebuilds its own store may accept a stale Ack. It re-sends at most once per 30 s of monotonic time per `(Home, holder)`, about 126 bytes each, and stops when nothing in that Home is missing (D150, D171). This interval is separate from D66's push slots, which keep pacing push ranking, so a wall-clock rollback cannot delay a Withdraw. A `Stale(recorded)` reply makes the node persist `max(current, recorded + 1)` in its header first, then re-send (§2). A lost Withdraw or WithdrawAck is therefore retried without a reconnect, and a clock that ran backwards cannot stall the rebuild.
- **Re-derived locally.** Outstanding pairs come from the committed roster. Anchor proofs are re-captured from `commit_log`, or re-anchored on the current head (D123).
- **Local state no holder has.** This node's Accepted receipts, terminal Refused deliveries and recorded recipient identities are its own records, so they are lost. Each lost receipt costs one counted re-push in this node's slot; the recipient answers Accepted with its generation and incarnation and sends Receipts, which restore it. Each lost refusal costs one counted attempt; the recipient refuses again if its cause still holds. A refusal whose cause has cleared is not restored, which is correct. Lost recorded identities are re-learned from the next Ack, Receipt or Withdraw. A stale Ack accepted meanwhile is corrected by that recipient's Withdraw retries.
- **Typed state.** `home_cert_store_rebuilding { txid, since, missing, generation }` on `/diagnostics/groups`, where `missing` counts committed contexts this node still lacks bytes for. It ends when `missing` reaches zero, once one holder is online (L1). All holders offline is §2 item 8.
- **Withdraw security (L4).** A Withdraw grants nothing. Only the named recipient can void its own receipts, and the result is at most one counted re-push per pair to a member that is already entitled to those bytes. A raised generation voids only receipts; it never changes a verdict, a seat or a key.
- **Retention.** §5a's retention rule applies (D148). This file holds every Home's evidence, so it is no group's own file: its copies stay until an operator removes them. Each copy is at most 16 MiB.

**Amendment to ADR 0085 rule 4 (D120).** This ADR amends ADR 0085 rule 4 for `home-owner-certificates.hscert` only, ruled by David (D120). Rule 4 says the software never overwrites a file it cannot read. For a damaged file, S2 moves the file aside unchanged by §5a's transaction and writes a new file at its path only after those bytes are durable and verified under the pending name. ADR 0085 rule 5 is unchanged: a recognised newer version is never quarantined. ADR 0089's unreadable-file rule still governs `peer-evidence.bin`; S2 does not change it.

Older binaries ignore this separate file and keep today's verdict; re-upgrade validates and reuses it.
They may still reproduce #1143. Downgrade never implies successful Home recovery.

New to old: send no scoped frames without `home_owner_certificate_v1`; Home certificate gossip stays redacted even for a legacy receiver except for the two named exceptions (D68, D96); keep existing join/commit formats and their limitations. A legacy seat is still ranked, and its slot lapses (D66). #946 runs unchanged in both directions (D96).
Old to new: old announces and commits decode unchanged; a committed valid Home certificate survives anonymous announces under the new verdict.
New code does not infer fresh capability bits from stored evidence.
One upgraded admin with the required bytes can pass its seal gate; legacy admins retain the old refusal.
This is not a claim that every mixed-version Home converges before S5–S7.

### 5a. Shared sidecar quarantine lifecycle (D120)

Every ADR 0088 slice, and ADR 0080, quarantines and rebuilds its own unreadable sidecar files by this one lifecycle. Each slice names only its own files, their family prefixes and header layout, its rebuild source, and the outcome for state no holder has. This section is normative for all of them; a slice that cites it adds no lifecycle text of its own.

**Writer exclusion.** Each file has one writer lock that serializes every write to `F`. Classification, every quarantine step, resume and finalize run while holding it, from the first read of `F` to the last fsync of `D`. Ordinary persists of `F` wait for the lock and then use their normal atomic write. So the bytes that classification hashes are the bytes step 1 renames.

**Classification at load, before any decode.**
- A read error leaves the file untouched. The slice runs memory-only for that file as `sidecar_unavailable { file, cause: read_error }` and retries at the next load.
- The family prefix is reserved for the file's path forever, and every future format keeps it with a higher version. A header is *valid* only when it is complete and every byte matches the slice's layout: prefix, version field, terminator and padding.
- **Newer:** a valid header whose version is above the highest this binary supports. It is never quarantined. It stays byte-identical at its path, and the slice runs memory-only as `sidecar_newer_format { file, version }`. ADR 0085 rule 5 is kept.
- **Damage:** anything else that is not a valid supported file. That covers a missing prefix, a truncated header (even one that keeps the prefix), an invalid version, a bad terminator or padding, and a supported version whose body fails to decode. Damage starts a quarantine transaction.

**The quarantine transaction.** Each transaction has a random 128-bit `txid`; no step uses wall-clock time to tell transactions apart. Let `F` be the file and `D` its directory. `h` is the first 16 bytes of BLAKE3 over the bytes read at classification.
1. Rename `F` to `F.q-<txid>-<h>.pending` in `D`.
2. fsync `D`.
3. Re-read the pending copy and check its BLAKE3 against `h`.
4. Build the replacement as the slice specifies. Write it to `F.tmp-<txid>`, fsync it, rename it to `F`, and fsync `D`. The replacement's header records `rebuilt_from`, the list of `txid`s it covers.
5. Rename `F.q-<txid>-<h>.pending` to `F.q-<txid>-<h>`, which marks it as history, and fsync `D`.

No replacement is written before steps 2 and 3 succeed. The original bytes are always at `F`, in a pending copy, or in a history copy, and the lifecycle never deletes them.

**Retention (D148).** Pending and history copies are never deleted automatically. An operator may remove them. When a group's own files are deleted, for example after a signed group delete, that group's copies are deleted with them. A file shared by several groups is no group's own file, so its copies stay until an operator removes them. Each slice's diagnostics surface lists every copy with its file, `txid`, state (pending or history) and size. The cost is disk use after repeated corruption; no slice keeps a retention question of its own.

**Resume at startup.** Each `F.q-<txid>-<h>.pending` in `D` is one unfinished transaction, identified by its `txid`. Resume runs under the writer lock, in this order:
1. **Barrier.** Repeat the fsync of `D` (step 2). Only after it succeeds does the node read, check or write anything.
2. **Verify.** In `txid` order, check each pending copy against the `h` in its name (step 3). A copy that fails stays pending and shows `sidecar_quarantine_failed { step: verify }`. No replacement covers it, and the next load retries it. The copies that pass form the set `V`.
3. **Classify `F`** exactly as at load:
   - **Missing:** if `V` is empty (every pending copy failed verification), write no replacement: the slice runs memory-only as `sidecar_quarantine_failed { step: verify }` and the next load retries. Otherwise remove any `F.tmp-*` left by these transactions, then build one replacement (step 4) that covers `V`.
   - **Valid and supported:** keep `F`. Each `txid` in `V` is finalized (step 5), whether or not `F` lists it in `rebuilt_from`; a listed `txid` means step 4 already completed, and an unlisted one needs no rebuild.
   - **Newer or unreadable:** keep `F` byte-identical and run memory-only as `sidecar_newer_format` or `sidecar_unavailable`. Leave every pending copy as it is. A binary that can read `F` resumes them later.
   - **Damaged:** quarantine `F` as its own transaction, with a new `txid` (steps 1 to 3). If it verifies, add its `txid` to `V`. `F` is now missing, so apply the missing-file rule above: if `V` is still empty, write no replacement; otherwise build one replacement that covers `V`.
4. **Finalize.** Run step 5 for each `txid` in `V`, in `txid` order.

**Coverage.** One replacement's `rebuilt_from` lists every `txid` in `V` when step 4 runs, including a `txid` just created for a newly damaged `F`. If `V` exceeds the slice's bound, the replacement lists the first `txid`s in order. The rest are finalized as history beside the valid `F`, which needs no further rebuild.

Finalize is idempotent. If the pending name is gone and the history name exists, only fsync `D`. A crash at any point, including during a resume, leaves a state from which these rules resume again.

**History.** A copy without `.pending` is history. It never triggers a resume or a rebuild, whether `F` is present or absent. If `F` is absent and only history copies exist, the slice applies its rule for a missing file. That is not a resume.

**Failures.** A failed step shows `sidecar_quarantine_failed { file, txid, step, error }`, with `step` one of `rename`, `fsync`, `verify`, `replace` or `finalize`. The slice runs memory-only for that file and retries at the next load. A `verify` failure keeps that pending copy, and no replacement covers it. When other copies verify, the replacement covers only those (Resume, step 3); when none verify, no replacement is written.

**Harness.** Each slice instantiates these W3-H fault cases for its files. Each is red on `main`, where no binary quarantines, unless the slice marks it as a control.
- **Cut points:** after each step's rename or fsync call.
- **fsync failures:** at steps 2, 4 and 5.
- **Resume crashes:** a crash during a resume, and a second crash in the same resume.
- **Pending copies:** a pending copy beside a healthy `F` that is not from this transaction; one beside the completed replacement; one with `F` missing.
- **Resume with a bad `F`:** a pending copy beside an `F` that was damaged after its replacement, which must start a new transaction and end with one replacement listing both `txid`s; beside a newer `F`, and beside an unreadable `F`, both of which must stay byte-identical with the pending copy untouched.
- **Several pending copies:** three pending copies, one of which fails verify. The replacement lists the two that pass, the failed one stays pending, and the next load finalizes it as history beside the valid `F`.
- **Writer exclusion:** an ordinary persist issued between classification and step 1, and another during a resume. Each waits for the lock, step 3 passes, and the persist then lands in the replacement.
- **History:** history copies with `F` present and with `F` absent. Neither may trigger a rebuild.
- **Classification:** header damage forms (missing prefix, truncated, invalid version, bad padding), a newer valid version, a read error, and a clock rollback between two corruptions, which must have no effect.
- **Retention (D148):** three corruptions in a row leave every copy in place, and diagnostics list each with its size. Deleting a group's own files deletes that group's copies and no others. Nothing else deletes a copy.

**ADR 0085.** Each slice amends ADR 0085 rule 4 for its own named files only, as ruled by David (D120). Rule 5 is not amended.

### 6. Typed blocks (L3, D64)

D64 makes L3 a hard rule: every block S2 adds or touches ends in a typed refusal or a typed, visible wait that names what it waits for.
Authority and sender states show on the existing `/diagnostics/groups` surface (`src/api/mod.rs:674`). The joiner's state shows on `/groups/:id/join-status` (`:1309`).

| Block | Typed state | Names | Exit |
|---|---|---|---|
| Home seal with an active seat whose committed digest has no local bytes | `OwnerCertMemberPending` (existing), recorded per join attempt | subject agent ID, committed digest, that pair's delivery state | matching bytes from one holder (L1). All holders offline is §2 item 8 |
| Joiner's poll while that seal waits | `pending_cause` on `/groups/:id/join-status` from §8's notice; at the 120 s TreeKEM deadline `TimedOut(owner_certificate_pending)`; with no verified notice `TimedOut(no_admission_result)` | the registered cause and its detail, or the group and authority polled | a Result or Refused replaces it. After `TimedOut`, ADR 0107's exit: a fresh invite |
| Pair waiting for its slot | `awaiting_slot` | anchor commit, rank, slot start | its slot starts, or Accepted or a Receipt lands |
| Pair after `Retry(reason)` | `retry(reason)` | the reason's condition, listed below | the condition clears; the next attempt is in the holder's slot |
| Pair after `Refused(reason)`, or after the sender's own eligibility check fails | `refused(reason)`, persisted and terminal | the reason | a newly verified context or eligibility change starts a fresh delivery. A deleted Home is §2 item 5 |
| Quarantined or unverified view | `rank_view_unreconciled` | local head or quarantine marker | verified reconciliation |
| Anchor dated ahead of local wall time (D173) | `anchor_future_dated` | the anchor commit and its `committed_at` | wall time passes `committed_at`, or a later commit re-anchors the pairs |
| Pair with no verified anchor proof (§5) | re-anchored at once on the current verified head (D123); `awaiting_slot` then names the new anchor | the new anchor commit | its slot under the new anchor. An unverified view waits as `rank_view_unreconciled` |
| Full sidecar | `Retry(capacity)` to the sender | `capacity` | pruning after a membership invalidation (D67) |
| Damaged sidecar, quarantined and rebuilding (D120) | `home_cert_store_rebuilding` | the `txid`, the `missing` count and the new generation | `missing` reaches zero once one holder is online (L1). All holders offline is §2 item 8 |
| Sidecar read error (§5a) | `sidecar_unavailable { file, cause: read_error }`; memory-only, and intake answers `Retry(persistence_failed)` | the file and the cause | a successful read at the next load |
| Quarantine step failed (§5a) | `sidecar_quarantine_failed { file, txid, step, error }`; memory-only, and intake answers `Retry(persistence_failed)` | the file, the transaction, the step (`rename`, `fsync`, `verify`, `replace` or `finalize`) and the I/O error | that step succeeds when retried at the next load |
| Newer-version sidecar (§5a, ADR 0085 rule 5) | `sidecar_newer_format { file, version }`; memory-only, and intake answers `Retry(persistence_failed)` | the file and the version found | a binary that reads that version |
| Withdraw answered `Stale` | part of `home_cert_store_rebuilding`; the node raises its generation and re-sends | the holder and its recorded generation | an `Applied` reply |
| Generation counter would overflow | `home_cert_store_generation_exhausted`; no Withdraw is sent | the current generation | none in practice: one bump per `Stale` cannot reach the `u64` limit |
| Joiner without S5's capability, all holders offline for 10 minutes | the #946 `certificate_evidence_unavailable` refusal | see §7 | see §7 |

Each Retry reason names its condition:
- `context_unavailable`: the recipient lacks the committed context. It names the anchor commit.
- `recipient_upgrade_required`: a current advert with both capabilities. This is an upgrade wait.
- `capacity`: free space in the recipient's sidecar.
- `persistence_failed`: a durable write.
- `busy`: room in the ADR 0089 budgets. This is a backoff wait.
- `ambiguous_binding`: one verified machine binding (ADR 0089).

No S2 block is a bare pending state. Sealing never waits for push acknowledgements.

### 7. Named, ruled exception: #946 in Home (D96)

David ruled to keep #946 for legacy peers until D35's minimum supported version drops them (D96). He chose this against the recommendation, which was to retire it early in Home. In round 2 he kept both Home disclosures to non-members and named them (D124); the ADR README's ADR 0007 overlay lists this one and the D68 joiner certificate.
S2 treats every other Home scope leak as a security defect. This one is a named, ruled, time-limited exception, not a precedent.

**Mechanism.** S2 does not change #946.
- Upgraded Home holders keep answering #946 requests on the metadata topic as today.
- Authorities keep staging the 10-minute `certificate_evidence_unavailable` refusal (`CERT_EVIDENCE_DEADLINE_MS`, `seat_cert_fetch.rs:55`) for joiners without S5's capability. Before S5 ships, no peer has that capability.
- S5 (ADR 0111) defines which requesters still get #946 answers once it ships.

**Exposure, stated plainly.**
- Each #946 answer in a Home publishes one owner certificate, JSON-encoded, on the Home's plaintext metadata topic. Each responder sends at most one answer per digest per group every 30 s (`seat_cert_fetch.rs:45`).
- Every peer in that topic's mesh receives it, including non-members (`src/gossip/pubsub.rs:1203–1228`).
- The certificate carries the owner's user public key, the subject agent's public key and the owner's signature (`src/identity.rs:487–515`). Any receiver can link the owner's user ID to that agent. An anonymous public announce withholds exactly this link, and D38 limits it to Home members.
- Delivered bytes cannot be recalled.
- While any peer still needs #946, S2 makes no Home privacy claim against non-member mesh peers.
- **End date.** The exception ends when D35's minimum supported version drops the last release that needs #946. David left that version to a later ruling (D125), so the exception has no date until then.

**L4.** No acceptance rule is relaxed. The exposure is to privacy, not authority. A received certificate proves only the owner's existing signed binding. A Home verdict accepts bytes only against the committed digest of an active seat, so a non-member gains no evidence authority.

**Amendment to ADR 0088 §2.** This ADR amends ADR 0088 §2 with one named entry, ruled by David (D96) and confirmed as a named §2 entry (D118):
- **#946 legacy refusal.** A joiner without S5's capability may receive a terminal refusal after 10 minutes of continuous digest-only seal refusals, although §2 item 8 says such a fetch waits.
- **Typed state:** the existing signed `JoinRefusalReceipt` with reason `certificate_evidence_unavailable` (`JoinRefusalReason`, `named_groups.rs:1234–1247`; staged at `:33871`). The joiner sees `Refused` with that reason in `last_join_outcome` on `/groups/:id/join-status`. The authority records it on `/diagnostics/groups`.
- **Exit:** for that attempt, an admin issues a fresh invite once a holder is online. The entry ends at D35's minimum supported version. S5 already drops this refusal for peers with its capability.
- **Residual:** a released TreeKEM joiner's 120 s poll ends before the refusal is staged, so it sees today's cause-free `TimedOut`. Released binaries cannot change, so D64 binds only upgraded joiners here; they get §8's notice.

This is one §2 entry. If ADR 0111 also records D96, both ADRs name this same entry.

**Mixed versions.** Legacy and upgraded nodes keep exchanging #946 as today. Legacy Home members keep their only certificate fetch.

### 8. Join pending notice (D117)

David ruled that one signed, attempt-bound notice carries the cause of a held join to the joiner, that S2 owns it, and that later slices reuse it (D117).
Its stable name is **`JoinPendingNotice`**. Other ADRs cite it by that name and register their causes against this section. David approved this design (D149).

**Capability.** Name the ADR 0093 registry-v1 capability **`join_pending_notice_v1`**. It means the node serves and understands `JoinPendingNotice` on the join-result poll.
Its number is allocated at acceptance, in acceptance order, as the next free bit in the README registry. It is separate from `home_owner_certificate_v1`, because ordinary groups use the notice too.

**Wire shape.** The join-result poll keeps its JSON `JoinResultMessage` (`named_groups.rs:1141–1219`).
- `FetchRequest` gains four fields, omitted when unset: `accepts_pending_notice: bool`; `held_notice_hash: Option<String>`, the BLAKE3 hex of the canonical bytes of the notice the joiner already holds for this attempt; `notice_only: bool`; and `attempt_evidence: Option<Box<NamedGroupMetadataEvent>>`, the joiner's own signed `MemberJoined` for this attempt. The last two are used only for notice-only polling (D154, below).
- `JoinResultMessage` gains one arm: `Pending { notice: Box<JoinPendingNotice> }`.
- `JoinPendingNotice` has these fields, in order: `group_id`, `member_agent_id`, `signer_agent_id`, `attempt_id`, `cause`, `detail`, `issued_at_ms`, `nonce`, `signature_b64`, and an optional `signer_public_key_b64`. The key is present only on a member-signed `no_eligible_admin` notice (D154, below). It is not part of the canonical bytes; the joiner derives `signer_agent_id` from it.
- `cause` is a registered name of 1 to 64 bytes from `[a-z0-9_]`.
- `detail` has three optional fields. Each is present only when the cause's registry row names it: `count: u32`; `revision: u64`; `digests`, at most K committed certificate digests as 64-character hex (K = 4, D93).
- The signature is ML-DSA-65 by the signer's agent key over the canonical bytes. These are the domain `x0x.named_group.join_pending.v1`; the string fields `group_id`, `member_agent_id`, `signer_agent_id`, `attempt_id` and `cause`, each u32-BE length-prefixed; for `count` and `revision`, a presence byte and the big-endian value; a u32-BE digest count and each digest length-prefixed; `issued_at_ms` as u64 BE; and the length-prefixed `nonce`. This mirrors `canonical_join_refusal_bytes` (`:1301–1316`) under its own domain.
- A notice is about 5 KB, almost all of it the base64 signature.

**Authority: staging.**
- When a join attempt's admission blocks for a cause that a registry row names, the authority stages a notice for that `(group, member, attempt)`. In S2, a Home seal that refuses with `OwnerCertMemberPending` stages `owner_certificate_pending`, with `count` set to the number of pending seats.
- A notice lives in memory only, like a staged refusal. It is dropped when a Result or Refused is staged for the attempt, when its cause clears, when the joiner is removed, banned or revoked, when the group is withdrawn or deleted, or at the existing 10-minute join staging lifetime (`PENDING_JOIN_RESULT_TTL`).
- The authority signs lazily at the first capable serve and caches the signed bytes until the cause or detail changes.
- Signing is rate-limited per `(group, member)` and globally, and staged notices are capped. The values are Q3.

**Authority: serving rule.** Selection keeps one critical section under the group membership lock (#477 A4), in this order: a staged Result, then a staged Refused, then a staged notice. Serve `Pending` only when all of these hold:
- the `FetchRequest` arrived on verified ingress, and its sender is `member_agent_id`;
- it carries `accepts_pending_notice: true` and the staged notice's `attempt_id`;
- the joiner's current verified, machine-bound advert sets `join_pending_notice_v1`. If the advert is unknown, refresh it through the existing route and serve nothing until it verifies;
- `held_notice_hash` differs from the staged notice's hash. Otherwise send nothing, because the joiner already holds it;
- ADR 0107's guard passes as amended by D145 (below).

Each serve is one direct exchange, admitted immediately before its write, with no hidden resend and no gossip, relay or blob fallback (cross-slice rule 5). Eligibility is re-checked at every serve.

**Amendment to ADR 0107: pre-admission signed replies (D145).** This ADR amends ADR 0107's serving guard with one named rule, ruled by David (D145). Other ADRs cite it as "ADR 0108's pre-admission signed replies"; ADR 0112 (S6) reuses it for its signed refusals and releases.
- **What 0107 keeps.** Staged results, Welcomes, keys, roster and certificate bytes still go only to an Active recipient whose certificate is valid on the current roster. Nothing in this amendment relaxes that.
- **What it allows.** A signed, attempt-bound reply that carries no key, Welcome, roster entry or certificate bytes may go to the requesting joiner's verified machine before the joiner is Active. Two replies qualify in S2: `JoinPendingNotice` and the #477 `JoinRefusalReceipt`. Today's refusal receipts gain this as their basis.
- **Conditions for every such reply.** It answers an authenticated, attempt-bound request from the joiner: the request arrived on verified ingress from the joiner's bound machine, its sender is the joiner, and it names the attempt that the reply names. The signer signs the reply with its own agent key, and it goes in one direct exchange, with no hidden resend and no gossip, relay or blob fallback.
- **Protocol bindings.** In S2 the request is a join-result `FetchRequest`, for a notice or a refusal receipt, including a notice-only `FetchRequest` (D154). In ADR 0112 (S6) it is the redemption envelope or the status probe for that attempt; ADR 0112 names their attempt fields. Another ADR that reuses this amendment names its own request and how it binds the attempt.
- **Extra conditions for a notice.** The joiner holds no Removed or Banned seat and no revoked agent, machine or binding. In an OwnerCertified group, its submitted admission certificate verifies against the policy owner with the current revocation set and time; if it fails, the attempt is refused under §2 item 2 and never left pending. The attempt is the member's current attempt. The group is not withdrawn, quarantined or deleted.
- **L4.** Such a reply tells the joiner only an outcome or a cause. It grants no seat, key, roster or epoch, so it adds no acceptance rule. The notice carries no key material, so D60's epoch check has nothing to bind; D60's eligibility check applies at every serve.
- **Mixed versions.** The amendment changes no wire format. A released authority already serves refusal receipts this way; released joiners never ask for notices.

**Joiner.** A joiner that sets `join_pending_notice_v1` sends `accepts_pending_notice` and `held_notice_hash` on every poll.
- It verifies a notice as it verifies a `JoinRefusalReceipt` (`:33742`). The signer key pinned for the expected authority must derive `signer_agent_id`; group, member and attempt must match; and the freshness checks apply (the 10-minute lifetime and the 300 s future-skew bound). A notice that fails is dropped.
- For a `no_eligible_admin` notice from another signer, `signer_public_key_b64` must derive `signer_agent_id`, and that agent must hold an Active seat in the joiner's local stub roster, the invite-committed base state it already verifies receipts against. Any other cause from a signer other than the pinned authority is dropped.
- **Current notice.** While the joiner has a live verified connection to its expected authority, the authority's latest notice is current; a member-signed notice does not replace it, because the authority would itself report `no_eligible_admin`. While it has no such connection, the newest verified notice by `issued_at_ms` is current, whoever signed it. So a newer member-signed `no_eligible_admin` supersedes an obsolete authority notice, and when the authority reconnects its latest notice is current again. Older notices are ignored.
- `/groups/:id/join-status` shows `join_state: pending_authority_commit` with `pending_cause { cause, detail, issued_at_ms, signer_agent_id }`.
- A cause name it does not know is shown as `unrecognized_cause` with the raw name. It is never a decode failure.
- At its poll deadline the attempt ends `TimedOut`, with `reason` set to the last verified cause. With no verified notice the reason is `no_admission_result`, which names the group and the authority it polled.
- The notice never extends the poll and never confirms membership. A later Result or Refused replaces it. A slice that keeps an attempt open past its deadline says so in its own ADR.

**Signer rule (D154).** The authority signs every notice, with one exception. While no eligible admin exists, nobody could sign one, and the joiner's poll would end without a cause, which D64 forbids. So any Active member that receives the joiner's verified `FetchRequest` may sign and serve a notice with the single cause `no_eligible_admin`, and no detail. It does so only when its current verified committed roster has no Active admin that S4 (ADR 0110) treats as eligible to admit. It never signs any other cause. The same serving rule, amendment conditions and rate limits (Q3) apply.

**Notice-only polling (D154).** A joiner normally polls only its expected authority. While it has no live verified connection to that authority, it may also poll other members for a notice:
- **Targets.** Members that hold an Active seat in its local stub roster and whose current verified advert sets `join_pending_notice_v1`. It sends one notice-only request per existing poll interval, rotating through them in agent-ID order. A notice from the authority never stops it: each disconnected period starts polling afresh. It stops only once it holds a verified member-signed notice received during the current disconnected period, and resumes if that notice is dropped or the authority reconnects and disconnects again.
- **Request.** A `FetchRequest` with `notice_only: true`, `accepts_pending_notice: true`, the `attempt_id`, `held_notice_hash`, and `attempt_evidence`, the joiner's own signed `MemberJoined`.
- **Member's checks.** A member answers only on verified ingress from the joiner's bound machine. It verifies the `MemberJoined` signature and group, and that `attempt_id` equals BLAKE3 of its canonical bytes and raw signature (`member_joined_attempt_id`, `named_groups.rs:1323`). It applies the amendment's notice conditions against its own committed roster, including the joiner's admission certificate from that event. It confirms that no eligible admin exists.
- **Answer.** At most one `Pending` with `no_eligible_admin`, signed by the member and carrying `signer_public_key_b64`. Otherwise it sends nothing. A notice-only request never yields a Result, Refused, Welcome, key or roster, so it cannot admit, refuse or seat.
- **Cost.** One request of about 10 KB, mostly the `MemberJoined` and its certificate, per poll interval, until the first verified notice. The joiner's own certificate goes only to authenticated Active members on direct channels.

**Registered causes.** This table is the initial registry. S2 defines its own row in full. For the other rows S2 fixes only the name and the detail shape; the owning slice defines the trigger and the exit in its own ADR. A later ADR may register a new cause in its own text by citing this section. No ADR may change an existing row's meaning.

| Cause | Detail | Owner | Meaning |
|---|---|---|---|
| `owner_certificate_pending` | `count` | S2 (this ADR) | The authority's Home seal waits for the owner-certificate bytes of `count` existing seats. Exit: the bytes arrive from one holder (L1), or the attempt ends |
| `evidence_pending` | `digests` | S5 (ADR 0111) | The authority is fetching these committed certificates by hash |
| `prerequisite_commit_pending` | `count` | S4 (ADR 0110), S7 (ADR 0113) | `count` other commits, such as an eviction, must land before this add can seal |
| `authority_catching_up` | `revision` | S3 (ADR 0109), S8(b) (ADR 0114) | The authority must reach a verified head past `revision` before it can seal |
| `no_eligible_admin` | none | S2 signer rule (this ADR); trigger and exit S4 (ADR 0110) | No Active admin is eligible to admit. Any Active member may sign it (D154) |

**Disclosure.** A notice tells an invite holder only that this authority holds its attempt, the cause class and the bounded detail. Detail may name counts, revisions and committed certificate digests. It never carries agent IDs, user IDs, certificate bytes, roster entries, key material or invite secrets.

**L4.**
- The notice adds no acceptance rule and grants nothing: no seat, key, certificate, roster or epoch. A joiner never treats it as admission.
- The authority's pinned key signs it, bound to group, member and attempt. A third party cannot forge one, and an old notice cannot move to another attempt. A replay for the same attempt can only show an older cause, which the newest-first rule ignores.
- A member-signed `no_eligible_admin` notice can only claim that no eligible admin exists. A member that lies gains nothing: it cannot outrank a connected authority's notice, and a later Result or Refused replaces it. While the authority is unreachable, a lying member can show a false `no_eligible_admin` until the authority reconnects; it still cannot admit or refuse. A member removed after the invite's base state may still sign one; it can mislead the cause but cannot admit or refuse.
- An authority can misstate the cause. It can already refuse or stay silent, so a false cause adds no power; the joiner still needs a verified Result to join.
- The rate limits (Q3) bound signing and verifying cost, and `held_notice_hash` sends each notice once per change.

**Mixed versions.**
- A released joiner never sends `accepts_pending_notice`. It never receives `Pending` and keeps today's cause-free `TimedOut` (D117).
- A released authority ignores the new request fields, because serde skips unknown fields. An upgraded joiner then ends `TimedOut(no_admission_result)`.
- A joiner with an older registry shows a newer cause as `unrecognized_cause`.
- A joiner sends notice-only requests only to members whose advert sets the bit. A released member that got one anyway would find nothing staged and answer nothing.
- Nothing is persisted, so no sidecar or D120 rule applies to notices.

## Consequences

- **Positive:** anonymous public identity and an offline creator no longer defeat locally held Home evidence.
- **Trade-off:** scoped persistence and guarded direct delivery add work; legacy peers and unavailable bytes retain limitations. Each fallback rank can add 30 s, and each legacy rank adds a lapsed slot (D66).
- **Trade-off (D68, D96):** two named owner-certificate exposures to non-member mesh peers remain. The joiner's own certificate stays on Home gossip until S5 removes it, and in a Home with any seat lacking S5's capability until that seat upgrades or leaves, or until D35's minimum supported version. #946 answers stay until D35's minimum supported version, which a later ruling sets (D125). David kept both and named them (D124).
- **Trade-off (D117, D120):** S2 adds one wire shape and capability for the join pending notice, about 5 KB per cause change. An unreadable sidecar costs a rebuild: lost receipts and refusals each cost one counted attempt.
- **Operational:** no release date is promised from the size calculation. Outside the two named, ruled exceptions (D68, D96), scope leaks are security defects, not Home known limitations.

## Validation

The W3-H harness (#1164) does not exist yet; these are specified cases, not claimed runs. Recommend a dedicated S2 tracking issue linked to #1164.
Each red case must be committed and shown red on main before S2 code merges; in-process red tests alone do not satisfy D16/D54.
Run daemon cases only in the isolated loopback-only Linux namespace; macOS fails closed.
All cases use a deterministic clock t=0, public create/admit/promote/invite/redeem APIs, and a scheduled transport that records every write; advance time only at the named barriers. Fixtures prepare signed metadata/capabilities, never inject discovered certificate bytes.

- **`s2_home_anonymous_owner_offline` (red baseline):** nodes O (creator), X (holder), A (promoted admin), J (joiner). At t=0 create Home O, admit X/A and commit A's promotion; deliver O's certificate through the actual member path and verify its digest on A. At t=1 O emits a machine-signed anonymous announce; deliver it to A, then disconnect O. At t=2 redeem J's valid A-issued invite with other evidence already present. Main returns OwnerCertMemberPending for O; S2 completes the authoritative add and J's Welcome/key installation without O. Anonymous public output stays unchanged. Repeat with creator/admin identities permuted.
- **`s2_home_scoped_evidence_restart` (red baseline, store isolation):** same nodes; at t=0 drive the trimmed-sidecar shape of `trimmed_member_added_all_holders_offline_stays_pending` (`r19_cert_carry.rs:1329`), but keep X online with O's bytes. A is seated/promoted from a real trimmed MemberAdded and has only O's committed digest; no JoinResult, #946 answer or discovery entry may supply O's bytes. At t=1 X establishes the authenticated binding and sends the real scoped Put; A persists it before Accepted, then disconnect O/X and restart A at t=2 with empty discovery and unchanged digest-only legacy roster. At t=3 redeem J's invite and seal using only the new sidecar as O's byte source. Main remains pending/no scoped durable recovery; S2 seals and installs J's keys. Delete/disable only the new sidecar in a negative run and require pending again. Avoid ADR 0070 owner-trust APIs; #1107 is excluded. Keep the old membership-carried restart shape as a separate red verdict reproduction, not evidence for the new store.
- **`s2_home_ordinary_group_twin` (control + red):** nodes A/J, clock t=0; create the ordinary PublicRequestSecure + OwnerCertified shape via APIs. Preserve `anonymous_announce_invalidates_hand_installed_cert` as the fail-closed ordinary-group control. At t=1 deliver A's own signed anonymous announce; its seal stays pending on main and S2. Repeat with committed Home metadata/policy: only that twin changes from red/pending to Clean and successful seal. Exercise both production verdict sites and assert real-roster grace stamps survive evaluations/restart.
- **`s2_home_all_egress_privacy` (red baseline):** O/X/A plus stranger S, grant-only G, invite-only J and other-Home H; t=0 create the memberships and attach S to the non-member topic mesh. At t=1 drive each #970, #1023, MemberJoined admission certificate (publish and resend), MemberAdded.certificate_b64 and #946 carrier, the ADR 0028 unchanged MemberJoined relay, all gossip publish/recovery/blob paths, and Put. Capture EVERY egress, including publishes before mesh delivery, and decode nested JSON/base64/bincode/storage encodings. Search every byte string/candidate certificate for a canonical digest equal to ANY Home member certificate, including locally held/embedded bytes rather than only the new store. Main leaks to the topic; S2 explicitly permits only the joiner's own certificate on gossiped MemberJoined (including its unchanged ADR 0028 relay) and MemberAdded.certificate_b64 under the named D68 exception (until S5 is in effect), plus today's #946 answers under the named D96 exception (§7). Assert those exceptions explicitly; every other certificate egress on gossip is forbidden and certificate bytes otherwise leave only on bound direct member channels. At t=2 race removal/ban/withdrawal/expiry/agent-machine-binding revocation/verdict/quarantine and connection replacement with writes; no subsequent cancelled send/resend may leak. K paths also require the current epoch. Record public announces/cards/Lookup unchanged.
- **`s2_home_designated_push_and_ack` (control for counts, red for new protocol):** five active nodes, t=0 commit one shared delivery trigger and freeze candidate ranks; all hold the same certificate. Deliver first-rank traffic before fallback and require four Puts, 29,752 Put/Ack bytes plus 2,280 Receipt bytes, total 32,032 application bytes; deliver/persist all receipts before later slots. Give a cold recipient four existing certificates and require four Puts, not sixteen. Restart all nodes after fsync'd Accepted receipts: zero certificate re-push. Delay or drop Receipt and assert only the named recipient can authorize retry suppression; count the resulting fallback duplicates. In separate schedules lose Put, Ack or receipt fsync; advance the shared clock by the ruled 30 s slot (D66), admit only the scheduled rank, and count every duplicate. Exercise each typed Retry/Refused reason: condition-cleared retry, terminal cancellation, no receipt on failure and no false membership confirmation. Two digest-only nodes exchange self-subject Puts through authenticated bindings without a mutual-cert deadlock; the exception never releases K/join artifacts.
- **Exit/non-regressions (controls):** with one holder/admin reachable and no faults, complete each Home add within the existing 120 s TreeKEM window; loss/fallback scenarios use the D66 schedule and expose the §6 typed states. Preserve ADR 0106 carry and ADR 0107 serving guards. Keep wrong-owner/agent, signature, expiry, revocation, commitment mismatch, non-anonymous replacement, fork/TreeKEM-adoption exclusions and ordinary groups fail-closed. All holders offline stays a typed, retryable seal wait under 0088 §2 item 8, except the D96 entry (§7) for a joiner without S5's capability; return one holder and resume without owner bypass. Cover malformed/duplicate/oversize frames, canonical re-encoding, trailing bytes, deadlines, budgets and fairness.
- **Mixed versions/storage (controls):** at t=0 pair candidate with released v0.45.0/v0.46.0 in both directions and a peer advertising only `peer_evidence_v1`; no new frame without `home_owner_certificate_v1`, no certificate-bearing Home gossip fallback outside the D68 and D96 exceptions, legacy verdict limitations visible, and a legacy rank's slot lapses (D66). After t=1 accepted Put/fsync, crash before/after file rename, directory fsync and Ack; restart with empty discovery, lose Ack, downgrade, then re-upgrade. Old binaries start on unchanged legacy JSON and leave `.hscert` byte-identical; a damaged file of a supported version is quarantined unchanged and rebuilt (D120), and a newer family version stays in place (ADR 0085 rule 5). Downgrade across more than 4,096 commits, then re-upgrade: retained anchor proofs reload; a pair created while downgraded is captured from `commit_log` if its anchor is still there, and is otherwise re-anchored on the current head (D123). Load golden and, once available, first-released X0HCV1 fixtures with SHA-256 checks.
- **`s2_home_push_rounds` (red baseline; D66):** nodes R (cold recipient) and holders P1–P4, ranked by agent ID; all hold the same verified certificate. At t=0 commit C seating R, with `committed_at` = 0. The schedule drops P1's Put at t=0. At t=15 s restart P2 and reconnect every node; deliver P2's Put at t=30 s. Assert: P2 sends nothing before t=30 s and sends at t=30 s, not t=45 s, because its phase keeps the 15 s fraction; its slot follows C's `committed_at` and not its restart, each slot has exactly one sender, and R's Receipts suppress P3 and P4. Variants: (a) P1 runs released v0.46.1, its slot lapses, and P2 sends at t=30 s; (b) P3 is quarantined, never sends, shows `rank_view_unreconciled`, and the others' schedule is unchanged; (c) P2's clock runs 40 s fast, which gives one counted duplicate, an idempotent Accepted and no new authority; (d) at t=20 s commit C2 removing P2, and every node re-anchors to C2; (e) **staggered capture (D172), control for alignment:** C's `committed_at` is t=0 and every clock is correct. P1–P4 capture C at t=90, 60, 30 and 0 s respectively, as if they had been offline. Assert: at every instant exactly one rank is scheduled, and at t=90 s only rank 3 is; a 10-minute wall-clock rollback during the run changes nothing until a restart, and across a restart it repeats at most one round; (e2) **future-dated anchor (D173):** the same staggered capture, with `committed_at` 1 hour ahead of every clock and P1 offline. Assert: for the hour, every holder shows `anchor_future_dated` and nobody sends; when wall time passes `committed_at`, slot 0 begins and lapses because P1 is offline; P2 pushes 30 s later, and no slot ever has more than one sender. Variants: with P1 online, P1 pushes as soon as wall time passes `committed_at`; a later commit C2 with a correct time re-anchors the pairs and ends the wait at once. Main has no scoped push, so the case is red.
- **`s2_home_store_cap_and_prune` (red baseline; D67):** node A in Homes H1 and H2, holder X. At t=0 seat H1 members through the public APIs until delivered certificates fill A's sidecar to within one entry of 16 MiB. At t=1 X's next Put gets `Retry(capacity)` with the file byte-identical and no Accepted. At t=2 commit removal of ten H1 seats; A prunes only their entries and receipts in one atomic rewrite. X's next-slot Put then gets Accepted. Assert that no active seat's entry is ever pruned, that a quarantined A never prunes, and that a crash during the prune rewrite leaves the old or the new file whole. Fairness: give H1 and H2 due pairs above ADR 0089's per-machine budget; sends alternate by Home and both drain. Main has no sidecar, so the case is red.
- **`s2_home_typed_waits` (red baseline; D64):** nodes O, X, A and J. At t=0 create the Home with O's bytes on X only and A digest-only for O. Drive each §6 row with scheduled faults: drop X's Puts, take every holder offline, quarantine A, corrupt the sidecar, fill it, and withhold one capability. Assert that each typed state appears on its named surface with its cause by the next poll, and that no block shows a bare pending state. J's `TimedOut` at t=120 s must name `owner_certificate_pending`, carried by §8's notice (D117). Main shows a cause-free `TimedOut` and no pair states, so the case is red.
- **`s2_home_946_legacy_exception` (control; D96):** A (S2 authority), X (S2 holder), L (released v0.46.1 TreeKEM joiner), L2 (released non-TreeKEM joiner) and S (non-member on the metadata topic mesh). At t=0 create the Home with A digest-only for O. Schedule 1: L redeems an A-issued invite, A publishes the #946 request, X answers on the topic, and A seals. Assert that S receives that answer, at most one per digest per responder per 30 s, and no other certificate. Schedule 2: X is offline before the join. L's poll ends at t=120 s in a cause-free `TimedOut`; at t=600 s A stages the signed `certificate_evidence_unavailable` receipt, and L2 sees `Refused` with that reason. Main and S2 behave the same, so the case is a control: S2 must not change #946.
- **`s2_home_anchor_survives_log_truncation` (red baseline; D66):** nodes R (cold recipient) and holders P1, P2 and P3, ranked by agent ID. At t=0 commit C seating R, with `committed_at` = 0; the schedule drops every Put in slot 0. From t=1 s to t=20 s an admin makes 4,100 `group update` calls (name or description only, no seat change), so every node's `commit_log` drops C while C stays the anchor. At t=40 s, inside slot 1 (30–60 s), restart P2. Assert: P2 reloads C's proof from its sidecar, verifies its signature and roster root, and sends in slot 1, not on a schedule taken from its restart; P3 sends nothing before t=60 s. Then deliver R's Accepted and Receipts: every node removes the pair record and C's proof in one atomic write, and a crash during that write leaves the old or the new file whole. Negative runs: (a) before the restart a fixture removes C's proof and the pair record from P2's sidecar. P2 finds no anchor in `commit_log` and re-anchors on its current head H (D123). It sends in H's schedule, and P3 keeps C's. Count the duplicates: at most one sender per slot per view, and R's Accepted absorbs each one. (b) a fixture flips one byte of C's stored signature. P2 quarantines the file unchanged, rebuilds (D120), and uses no unverified proof. Main has no scoped push or anchor store, so the case is red.
- **`s2_join_pending_notice` (red baseline; D117):** nodes O (creator, offline), X (holder of O's bytes, offline at t=0), A (promoted admin and authority, digest-only for O), J (candidate joiner with `join_pending_notice_v1`), L (released v0.46.1 joiner) and S (non-member on the Home metadata topic). Polls run every 2 s on the deterministic clock. At t=0 J redeems an A-issued invite, and A's seal refuses with `OwnerCertMemberPending`. Assert: J's next poll gets exactly one `Pending` with `owner_certificate_pending` and `count` = 1, verified under A's pinned key; join-status shows it; later polls that carry its hash get nothing more. At t=120 s J ends `TimedOut(owner_certificate_pending)`. Variants: (a) X comes online at t=60 s; the push lands, A seals, J's next poll gets the Result and J is Active; (b) at t=30 s A bans J; no notice is served after the ban commits; (c) L joins the same way, never gets `Pending`, and ends with today's cause-free `TimedOut` (control); (d) J polls a released v0.46.1 authority and ends `TimedOut(no_admission_result)`; (e) a notice replayed under another attempt, or signed by S, is dropped and join-status is unchanged; (f) a flagged `FetchRequest` on unverified ingress gets no notice; (g) J's advert is unknown to A; A refreshes it and serves the notice only after it verifies; (h) **no eligible admin (D154):** J's inviter I is Active but no admin is eligible under S4; I serves `no_eligible_admin`, J verifies it under the key it carries against I's Active seat in J's stub roster, and J ends `TimedOut(no_eligible_admin)`; (i) a `no_eligible_admin` notice signed by S, or by a seat not Active in J's stub roster, is dropped; (j) while J is connected to A, a member-signed notice with a newer time does not replace A's notice; (l) **offline inviter (D154):** A goes offline at t=10 s and no admin is eligible; J sends notice-only requests to members B and C in agent-ID order with its `MemberJoined`; B verifies the attempt and the conditions and serves `no_eligible_admin`; C is not polled again; J ends `TimedOut(no_eligible_admin)`; a notice-only request never yields a Result, Refused or key; (m) **supersession:** A serves `owner_certificate_pending` at t=0, goes offline at t=20 s, and at t=30 s every admin becomes ineligible under S4's rule (fixture). Although J holds A's notice, J starts notice-only polling at t=20 s and keeps polling until B's notice arrives. B's newer `no_eligible_admin` supersedes A's notice before the 120 s deadline, and J's timeout names it. When A reconnects, A's latest notice is current again; (k) **pre-admission replies (D145):** a refusal receipt is still served to J before it is Active, and a staged Result, Welcome or key is never served to J before it is Active. In every run S receives no notice bytes, and each notice is sent once per cause change. Main has no `Pending` arm, so the case is red.
- **`s2_home_store_quarantine_rebuild` (red baseline; D120):** node A in a Home with holders X and Y and members R and Q. At t=0 A's sidecar holds certificate entries, Accepted receipts for A's pushes to R, a Refused delivery to Q and one anchor proof. Stop A, flip one body byte, and start A at t=1. Assert: §5a's transaction preserves the old bytes with an unchanged SHA-256 and writes a new V1 file with a new incarnation and a higher generation; A shows `home_cert_store_rebuilding` with its `missing` count; A sends a Withdraw to every other seat of the Home; X and Y void their receipts, re-anchor, push in their slots, and `missing` reaches zero. A Withdraw sent by S, or naming another recipient, is ignored. A re-pushes each formerly acknowledged pair once in its own slot, and R's Accepted and Receipts restore the receipts. The attempt to Q meets the same refusal and records it again. Variants: (a) all holders offline: the state stays typed and names `missing` (§2 item 8), then completes when X returns; (b) a file without the `X0HCV` prefix is quarantined unchanged and rebuilt; (c) **dropped Withdraw, no reconnect:** the schedule drops A's first Withdraw to X and keeps the connection open; A re-sends after 30 s of monotonic time (D171), X answers `Applied`, and the rebuild completes with no reconnect; (c2) **rollback:** the same, with a 10-minute wall-clock rollback right after the dropped Withdraw; A still re-sends within 30 s of monotonic time; (d) a dropped WithdrawAck behaves the same; (e) a released v0.46.1 binary on the same data directory starts and leaves every file unchanged. Main has no sidecar, so the case is red.
- **`s2_home_store_lifecycle` (D120):** S2 instantiates ADR 0108 §5a's fault cases for `home-owner-certificates.hscert`, red on `main` except where §5a marks a control. S2's header variants are `X0HCV1\0` plus a non-zero byte, the 6-byte file `X0HCV1`, `X0HCV0\0\0`, `X0HCV01\0` and a missing prefix, each damage, and `X0HCV2\0\0`, which is newer and must stay byte-identical. S2-specific assertions: in every memory-only state intake answers `Retry(persistence_failed)`; in `sidecar_newer_format` the node sends no Withdraw; the replacement has a new incarnation and a generation above any it can read.
- **`s2_home_receipt_generation_order` (red baseline; D120):** nodes A (recipient), X and Y (holders). At t=0 A accepts X's Put at generation g1; the schedule delays A's Accepted Ack to X and A's Receipt to Y. Damage A's file and restart A at t=1; A rebuilds at g2 > g1 and its Withdraws reach X and Y first. At t=2 deliver the delayed Ack and Receipt. Assert: neither X nor Y records Accepted from them; the pairs stay outstanding; X pushes in its slot; A answers Accepted at g2, which X records. Variants: (a) restart X between the Withdraw and the late Ack; its persisted recorded generation still rejects the Ack; (b) A's damaged header is unreadable, so A starts at generation 1, below g1; X answers `Stale(g1)`; A persists g1 + 1, re-sends and gets `Applied`; a wall-clock rollback anywhere in this run changes nothing; (c) X's own store is rebuilt and then accepts a stale Ack at g1; A's next Withdraw retry at g2 voids it and the push resumes; (d) **Receipt before Withdraw, two contexts:** X holds g1 receipts for A's contexts c1 and c2; after A rebuilds at g2, A's Receipt for c1 at g2 reaches X before A's Withdraw. X raises to g2 and deletes c2's g1 receipt in the same atomic write, then pushes c2 in its slot. The later Withdraw at g2 gets `Applied` and finds nothing left; (e) **equal-generation collision:** A's last readable header gives g1 − 1, so its new generation equals g1, with a new incarnation. X discards A's Acks and Receipts at g1, and answers A's Withdraw with `Stale(g1)`. A persists a higher generation, re-sends, gets `Applied`, and X deletes the old g1 receipts. No pair is ever recorded as Accepted from the collided store; (f) **same-store bump:** X has applied A's Withdraw at g2 and holds new receipts; Y, offline until now, recorded g3 > g2 for A's lost store and answers `Stale(g3)`; A persists g3 + 1; X sees the higher generation with the same incarnation and relabels its receipts, with no deletion and no re-push; (g) **reordered replies:** A gets `Stale(100)` and then a delayed `Stale(5)`; its generation goes to 101 and stays there; (h) **crash after persist:** A crashes after persisting a bump and before resending; it restarts with the bumped value and its next Withdraw carries it. Main has no generation, so the case is red.

Land this ADR Proposed on main, obtain cross-model review and David's acceptance before any S2 governed code merges.
Restate 0088's acceptance order: contract, then S2 and S8(a), then S4 and S3, then S5, then S6, then S7. “S8” here means ADR 0107 S8(a); S8(b) (ADR 0114) is Accepted only after S4 as ADR 0107 requires (D65).
S2's prerequisites are the Accepted contract, red-on-main W3-H evidence, capability allocation and sidecar/wire fixtures; S2 does not wait for S5. Seal-check retirement waits for S7 after S4 is Accepted and shipped.
Use the single `named_groups.rs` code lane. D55's harness exception applies only to S8(a), never S2.

## Rulings and open questions

**Blocks David's Accept:** none of this ADR's open questions. Accept follows ADR 0088's acceptance order: S2 with S8(a), after the Accepted contract. Q3 blocks code only.

David ruled on 2026-10-04 (D64, D65, D66, D67, D68, D96):

- **G7, L3 binds every slice (D64):** a hard rule. Every block S2 adds or touches ends in a typed refusal or a typed, visible wait that names its cause, including the 120 s join poll and upgrade or backoff waits. §6 lists them. §8's notice (D117) covers the joiner's 120 s poll.
- **"S8" in the order (D65):** S8 means S8(a), ADR 0107. S8(b), ADR 0114, follows S4. S5 does not wait for ADR 0114.
- **Push timing and rounds (D66):** the recommended policy, now normative in §2. A 30 s fallback and retry slot. Shared rounds are anchored to the signed commit that triggered delivery and ranked on that commit's verified roster. Reconnect or restart never resets the anchor. Divergent views wait for reconciliation. Each node keeps every outstanding pair's anchor proof in the S2 sidecar (§5), so `commit_log` truncation cannot reset it either.
- **File cap, pruning and fairness (D67):** the recommended limits, now normative in §5. A 16 MiB cap with a retryable `capacity` answer. Pruning of departed seats only after their membership is invalidated. Fair scheduling by Home inside ADR 0089's existing budgets.
- **Joiner's own certificate on Home gossip (D68):** S5 owns its removal. S5 (ADR 0111) adds the digest-only-add rule, with its security argument and mixed-version plan, and fills the bytes by fetch-by-hash. S2 keeps the named interim exception in §2 until S5 is in effect.
- **#946 in Home (D96, against the recommendation):** keep #946 topic answers and the 10-minute refusal for legacy peers until D35's minimum supported version drops them. §7 records this as a named, ruled, time-limited exception, states its exposure, and amends ADR 0088 §2 with one named entry.

David ruled round 2 on 2026-10-04 (D117, D118, D120, D123, D124, D125):

- **Cause notice for the 120 s timeout (D117):** one signed, attempt-bound notice, owned by S2, served on the join-result poll under ADR 0107's guard, and reused by later slices. §8 defines `JoinPendingNotice`, the capability `join_pending_notice_v1`, its serving rule and its cause registry. S2's acceptance waits for the review of this design. This closes former Q1.
- **Named §2 additions (D118):** David confirmed the named ADR 0088 §2 entries, including this ADR's "#946 legacy refusal" (§7), which is now a ruled entry.
- **Unreadable sidecar (D120, against the recommendation):** automatic quarantine and rebuild from holders, now in §5. A recognised newer version is never quarantined; it stays in place and S2 runs memory-only (ADR 0085 rule 5 kept). A damaged file is quarantined by the shared lifecycle in §5a, which every slice cites, then rebuilt. `HomeCertificateWithdrawV1` and a durable recovery generation make holders push again, and a late Ack or Receipt from before the rebuild cannot restore Accepted. Withdraws retry while bytes are missing. Lost local receipts and refusals are re-derived by counted re-attempts. This amends ADR 0085 rule 4 only, for this one file.
- **Push pair with no anchor proof (D123):** re-anchor on the current verified head, now in §2 and §5. This closes former Q2.
- **Two Home disclosures to non-members (D124):** both kept and named, the D68 joiner certificate and the D96 #946 answers. The ADR README's ADR 0007 overlay lists both.
- **End date for the D68 and D96 exceptions (D125):** a later ruling sets D35's minimum supported version. Until then, both exceptions have no date.

David ruled round 3 on 2026-10-04 (D145, D148, D149, D150, D154):

- **Replies to a joiner that is not yet a member (D145):** a named amendment to ADR 0107, "pre-admission signed replies", owned by §8. Signed, attempt-bound notices and refusals that carry no key, Welcome or roster may go to the requesting joiner's verified machine. ADR 0112 reuses it by name, and #477 refusal receipts gain this basis. This closes former Q5.
- **Keeping quarantined copies (D148):** never deleted automatically; an operator may remove them, and a group's copies go when that group's own files are deleted. Diagnostics list each copy with its size. §5a owns the rule, and every slice cites it. This closes former Q4.
- **The `JoinPendingNotice` design (D149):** approved.
- **Withdraw retry interval (D150):** once per D66 30 s slot per `(Home, holder)`, about 126 bytes each, stopping when nothing is missing (§5). This closes former Q6.
- **Notice when no eligible admin exists (D154):** any Active member may sign and serve the notice with the single cause `no_eligible_admin`. It grants nothing. §8's signer rule now says so, and ADR 0110 cites it. While the joiner cannot reach its authority, it polls Active members notice-only, with its signed `MemberJoined` as attempt evidence, and a newer member notice supersedes an obsolete authority notice.

David ruled Q7, Q8 and Q9 on 2026-10-04 and 2026-10-05 (D171, D172, D173):

- **The clock for Withdraw retries (D171):** option (a). Withdraw retries use a monotonic 30 s interval per `(Home, holder)`, separate from D66's slots, and push ranking keeps D66 (§5). This closes former Q7. **D171 note:** David asked whether a vector clock should replace wall time here. §2's recovery generation is now a Lamport counter that never uses wall time; a per-holder vector of `(incarnation, counter)` is recorded there as rejected, because one writer needs only a total order. Checking D66 for the same wall-clock risk exposed former Q8.
- **D66 slots with a future-dated anchor (D172):** option (a). Wall time is read once, at load or on first apply, to place the anchor; after that, slots advance by the monotonic clock (§2). The anchor keeps its fractional phase. This closes former Q8.
- **Placing a future-dated anchor (D173):** option (a). Every node uses the signed `committed_at` as its shared anchor. Until wall time passes it, nodes hold with the typed wait `anchor_future_dated`; then only the first rank may push. Cost, as ruled: a stall as long as the signer's clock error when the first rank is offline, and no burst. This closes former Q9.

Still open for David:

- **Q3 (blocks code): notice signing limits (D117, D154).** Proposal: reuse the join-refusal values as separate tokens, so a notice never delays a refusal, and apply the same per-`(group, member)` token to member-signed `no_eligible_admin` notices. That is one signature per `(group, member)` every 30 s, 20 signatures per minute globally, and at most 1,024 staged notices (`named_groups.rs:33991–33995`). This needs David's ruling.

## Follow-ups

- **Restart harness hook:** add `s2_strip_owner_certificate_from_direct_member_added` to remove O's certificate from the direct MemberAdded roster sidecar, leaving its committed digest intact, so the restart case isolates scoped persistence.
- **S2 duplicate bytes:** count the interim direct #970/#1023 sidecar bytes duplicated by Put in the size table.
- **Length:** shorten this ADR in a later editorial pass while preserving the decision, named exceptions and validation gates.

## Notes for AI-assisted work

Only David Irvine marks this ADR Accepted. Accepted ADRs remain byte-identical.
Record changed decisions in a successor ADR; do not edit 0007, 0038 or 0088.
