# ADR 0111: Evidence Size K and Fetch-by-Hash from Any Holder (0088 S5)

- **Status:** Proposed
- **Date:** 2026-10-04
- **Decision owners:** David Irvine
- **Author:** Claude (Opus)
- **Reviewers:** Codex (cross-model review, r1 REQUEST-CHANGES addressed in r2). The text added for David's 2026-10-04 rulings is not yet reviewed.
- **Slice:** Slice S5 of [ADR 0088](./0088-group-liveness-contract.md) (group liveness)
- **Supersedes:** none. ADR 0088's supersession table assigns nothing to S5.
- **Amends:**
  - ADR 0088 §2, by one named entry ruled by David (D96) and confirmed by him (D118): "#946 legacy refusal" (§8). ADR 0108 records the same entry; this ADR restates it and adds no second one. ADR 0088 itself is not edited.
  - ADR 0085 rule 4, for S5's holder files only, ruled by David (D120). A damaged holder file is quarantined by ADR 0108 §5a, with its bytes preserved, and rebuilt from holders, instead of being left in place (§6). Rule 5 is not amended. ADR 0085 itself is not edited.
- **Superseded by:** none
- **Goal served:** R3 (all my machines connected) and the shared-places core.
- **Related:** D34(3), D35, D38, D43, D54, D60, D63, D64, D65, D68, D93–D98, D117–D120, D125, D133, D148, D157, D158; ADR 0088 L1–L4, §2, G6, G7; [ADR 0106](./0106-join-result-carries-intervening-membership-events.md) (its deferred option 3); [ADR 0107](./0107-stuck-join-rearm-and-serving-guard.md) (serving guard); [ADR 0108](./0108-home-scoped-owner-certificate.md) (S2: the Home push and its named interim exceptions); [ADR 0109](./0109-ownerless-attestation-self-recovery.md) (S3: `base_beyond_retention`); [ADR 0112](./0112-any-admin-invite-redemption.md) (S6); [ADR 0114](./0114-authority-re-welcome.md) (S8 (b)); [ADR 0089](./0089-relationship-peer-evidence-survives-restart.md) (`EvidenceV1`); [ADR 0085](./0085-persisted-binary-formats-are-versioned.md); [ADR 0093](./0093-capability-advert-registry.md); [ADR 0087](./0087-repository-and-release-governance.md) rule 8; ADR 0028; #811, #1023, #1143, #646, #1164, #818, #946, #970, #1025. Related work only: the join-artifact serving lifecycle note on the #1190 branch.

Two rulings used here are not in the public digest. D60 (2026-10-03): every delivery and resend of key-bearing material needs the recipient's **current** eligibility; entitlement is not fixed at the committing epoch. D63 (2026-10-04): each 0088 slice gets its own ADR, drafted Proposed and Accepted separately; S5 is ADR 0111.

**Gates.**
- **Acceptance order** (0088 §4): the contract, then S2 and S8, then S4 and S3, then S5. "S8" there means S8 (a), ADR 0107, already Accepted (D65). S8 (b), ADR 0114, is Accepted after S4, as ADR 0107 states, and S5 does not wait for it (D65). S5 is Accepted only after S2 (0108), S4 (0110) and S3 (0109) are Accepted.
- **Merge:** this ADR lands Proposed on `main` before any code it governs merges to any branch. David Accepts it before S5's implementation merges to `main` (0088 §4, ADR 0087 rule 8).
- **Harness first** (D16, D54): every red case in Validation is committed to W3-H and shown red on `main` before S5's code merges. No exception applies.
- **One lane:** S5 code that touches `named_groups.rs` takes the single lane (0088 §4).
- **L3 is a hard rule** (D64): every block this ADR adds or touches ends in a typed refusal or a typed, visible wait that names what it waits for (§8).

## Context

ADR 0088 L1 says catch-up and repair complete when any one holder is online. Four evidence paths fall short today.

**1. Missed membership events come from the author's memory.**
- Each node logs applied TreeKEM membership events in memory only, 128 per group (`treekem_event_log`, `src/server/state.rs:1105-1107`; cap at `src/server/routes/named_groups.rs:72`). A restart loses the log.
- A member with a gap asks the peers that `admit_treekem_pending_event` names (`named_groups.rs:8796-8818`). The answer is one plain direct message with at most one event (`named_groups.rs:81`, `:10121-10142`). A Home `MemberAdded` is about 51.5 KB, over the 49,152 B limit (`src/dm.rs:43`), so the page is never delivered (ADR 0106, Context point 4).
- Even a delivered page fails when the holder did not author the event. The apply requires `actor == sender` (`named_groups.rs:11300-11303`). The signed `GroupStateCommit` covers the state fields, not the whole event (`src/groups/state_commit.rs:476-496`). So only the author can serve its events.
- ADR 0106 closes gaps of at most 8 from the authority's live log. Longer gaps, or an authority restart, still fail. This breaks **L1**: catch-up depends on the author.

**2. Certificates ride per-case sidecars.**
- Seats carry a certificate digest. The bytes ride two unsigned sidecars: on `JoinResult` (#970, `named_groups.rs:1191-1201`) and on `MemberAdded` (#1023, `named_groups.rs:1565-1583`). Each holds up to 32 (`seat_cert_fetch.rs:665`) and is trimmed from the end to fit (`named_groups.rs:34778-34817`, `seat_cert_fetch.rs:752-791`). Trimming can drop a required certificate (the #1025 review P1).
- One certificate is about 7.25 KB in bincode (`src/identity.rs:487-516`), about 9.7 KB as base64. A full sidecar is about 310 KB, sent to every member.
- A missing certificate is fetched by #946 on the group's metadata topic (`seat_cert_fetch.rs:112-160`, `:423`). Metadata traffic is plain JSON (`named_groups.rs:2955-2967`), so every subscriber sees the answer. The topic mesh can include non-members (`src/gossip/pubsub.rs:1203-1228`; the non-member mesh test at `:5072`), so today's Home sidecars and answers reach peers that D38 excludes.
- The joiner's own certificate also rides Home gossip: on `MemberJoined` (`named_groups.rs:33647`, published at `:33685`) and as `MemberAdded.certificate_b64`, which every receiver requires (`named_groups.rs:11249-11255`). ADR 0108 keeps both as a named interim exception, and D68 gives their removal to S5.
- After 10 minutes #946 stages a terminal `certificate_evidence_unavailable` refusal (`seat_cert_fetch.rs:55`, `named_groups.rs:33905-33925`). §2 item 8 says such a fetch waits until a holder is online.
- Each fix so far was a per-case patch (#970, #1025, #1056, #1132). G6 stops them. The remaining #1023 case is "every holder offline" (`r19_cert_carry.rs:1329`), which is §2 item 8. The verdict defect (#1143) is S2.

**3. The invite carries the whole base roster.** A v4 invite signs the full projection (`src/groups/invite.rs:123-130`, `:322-323`). It is capped at 20 Active+Banned entries by the command-DM wrapper (`invite.rs:201-217`), so invites stop past 20 members (#646).

**4. Private-KV history (#811) is not proven fixed.** KV history already moves from any holder (`src/kv/sync.rs:349-353`; image digests, `src/kv/retained_paging.rs:1-6`). #811 still lacks its test.

S5 reuses the control-blob pull (exact bytes, BLAKE3, 8 MiB, per-recipient staging; `control_blob.rs:9-42`, `:153-200`, `:543-553`). It also reuses what members already persist in `named_groups.json` (`src/server/mod.rs:710`): seat certificates (`src/groups/member.rs:174`) and the `commit_log` of signed commits with projections (`src/groups/mod.rs:706-722`).

## Decision Drivers

- L1: catch-up and repair need any one holder, never the author, inviter or creator.
- L3 (D64): every block S5 adds or touches is typed and visible.
- L4: every fetched byte is authenticated by signed evidence. Holders serve only currently eligible requesters (ADR 0107, D60).
- One carry rule with a fixed size bound (G6, goal E).
- No persisted authority catch-up log (D54).
- Mixed versions degrade to today's paths.

## Considered Options

1. **A persisted authority catch-up log.** Rejected by D54. Catch-up stays dependent on the authority (L1).
2. **Raise the inline caps.** Rejected. Size grows with the roster on every message, trimming still drops evidence, and G6 stops per-case carries.
3. **Widen the #946 topic fetch to every kind.** Rejected. Answers are broadcast in plain JSON to every subscriber, so no per-requester guard is possible.
4. **Use ADR 0089 `EvidenceV1` (stream 0x06) as the carrier.** Rejected for object bytes: a 32 KiB message cap, one request per stream, and pre-identity admission under relationship scope, not group eligibility. It stays the way to find a holder's machine and KEM key after a restart.
5. **Re-verify relayed events from the gossip envelope.** Rejected. It ties evidence to saorsa-gossip internals, and events delivered by direct message have no reusable envelope.
6. **A DHT or global store.** Rejected. Named groups are DHT-free, and a global store discloses beyond members.
7. **Author-signed event evidence, a guarded direct fetch by hash from any member holder, and an inline cap K** (chosen).
8. **For the joiner's Home certificate, apply a digest-only add first and check the certificate later.** Rejected. Receivers would install a TreeKEM epoch that includes an unverified leaf. §3a holds the add until the check passes.

## Decision

### 1. Objects and the evidence that authenticates them

| Kind | Address | Bytes served | Requester accepts only when |
|---|---|---|---|
| `certificate` | BLAKE3 of bincode `AgentCertificate` (`seat_cert_fetch.rs:97-101`) | the whole certificate | it hashes to a seat digest on the requester's committed roster, or to the `certificate_digest` of a held add whose roster root it verified (§3a); then today's hydrate checks (`seat_cert_fetch.rs:915`) |
| `commit_event` | the commit's `state_hash` | the canonical event with its `author_evidence` (§2) | the author evidence and the commit signature verify, and the commit's `state_hash` equals the address; then the apply in §2 |
| `roster_projection` | `roster_root` | only the root-covered fields: agent ID, role, state and certificate digest | they re-derive the address (`state_commit.rs:183-196`), and the address equals a root in a signed commit the requester holds, or, for a pending joiner, the root its signed invite binds (§5) |
| `kv_image`, only if C2 is red (D94) | the retained image's `image_id` (`src/kv/retained_paging.rs:27-32`) | the whole serialized image, at most the control-blob limit | it hashes to an `image_id` that a store mutation the requester has verified names; then the store's ordinary merge checks |

A fetched projection never carries `treekem_key_package_hash`. The root does not cover it (`state_commit.rs:110-114`, `:138-147`). A consumer that needs it takes it from evidence that covers it: the add commit's `security_binding`, or a signed invite view.

**KV images (D94).** S5 builds the `kv_image` kind only if control case C2 is red on `main`. If C2 is green, #811 closes as not reproduced and no `kv_image` code lands. A holder serves a `kv_image` under §5's guard, and only to a requester that the store's current access policy lets read it. An image over the control-blob limit (8 MiB) gets `group_object_refused_v1 { too_large }` (§5), and that store keeps today's KV paging.

### 2. Author evidence and the fetched-event apply

- **Minting.** When a capable authority seals a commit-bearing metadata event, it adds an optional field `author_evidence { signer_public_key, signature }`. The field is serde-default and omitted when absent, as in ADR 0106. The signature is ML-DSA-65 over `x0x/group-event-evidence-v1\0 ‖ group_id ‖ state_hash ‖ event_digest`, with length prefixes.
- **Digest (RFC 8785 JCS).** `event_digest` is the BLAKE3 of the JCS bytes of the event value, after the top-level members `author_evidence` and `roster_certificates_b64` are removed.
  - **Parse once.** The receiver parses the received bytes once into a JSON value. The parser rejects duplicate keys at any depth, invalid UTF-8 and lone surrogates. Verification and apply consume that one value: the event is deserialized from it and never re-parsed from the bytes.
  - **Bytes.** Object keys are sorted by UTF-16 code units at every depth. Arrays keep their order. There is no whitespace. A string escapes only `"`, `\` and U+0000–U+001F (as `\b`, `\f`, `\n`, `\r`, `\t` or lowercase `\u00xx`). Every other character is literal UTF-8.
  - **Numbers.** Every number must be an integer with magnitude at most 2^53 − 1, written in plain decimal (I-JSON). Any other number makes the evidence invalid: the authority does not mint it, and the receiver falls back to the legacy author-only rule.
  - **Coverage.** Every other member is covered, including members a newer version adds, such as §3a's `certificate_digest`.
  - **Minting.** The authority serializes the event, parses its own output with the same parser, and signs the digest of that value.
- **Signer.** It must be the commit's signer: `signer_public_key` and `committed_by`.
- **Budget.** The evidence never moves an event onto a transport that a legacy receiver may not support (#970's rule). If it would, it is omitted, and that event stays servable only by its author.
- **Apply.** A fetched event is applied through the ordinary metadata apply with an explicit origin `Fetched { author, holder }`. Every check that compares the transport sender (for example `actor == sender`) compares the verified author. The holder is never treated as the sender. All other checks run unchanged: the actor's current role, revocation, prev-hash linkage, owner mandate, TreeKEM rules and the #846 gate (`named_groups.rs:10282-10303`).
- **Not a carry.** A fetched event never satisfies a bound join-attempt rule, and it is never re-published.
- **Legacy events.** An event without evidence is accepted from a holder only when the holder is its author, which is today's rule.

### 3. The single carry rule (K)

- **K = 4** (D93). A live `MemberAdded` or `JoinResult` carries at most 4 certificates inline, in today's order (local seat first, then by agent ID). The event subject's own `certificate_b64` is not counted.
- Every other certificate is already named by its committed seat digest, and is fetched by hash. No new reference field is needed. Trimming now costs latency only.
- No other message carries certificates. Any future carry uses this rule (G6).
- **Home groups (D38).** D38 discloses a Home owner's certificate only to that Home's members. The metadata topic is plaintext gossip whose mesh can include non-members (Context, item 2). So in Home groups:
  - the gossiped `MemberAdded` carries no roster sidecar, whatever the adverts say, and the `JoinResult` carries none either;
  - certificates leave a node only on direct, member-authenticated channels: S5's fetch by hash (§4, under §5's guard) or S2's direct Put. Two exceptions are named: the joiner's own certificate in a Home with a seat that lacks the bit (§3a), and #946 answers to legacy requesters (D96, §4);
  - **S5 reuses S2's direct Put** as the Home push half of this rule. It does not retire it, and it is not a second carry rule. Under S5 a Put carries at most K certificates, goes only to a recipient that passes §5's guard, and uses §5's single admitted exchange;
  - the joiner's own certificate follows §3a.
- **Ordinary groups:** K inline on the gossiped copy stays.
- **Sizing.** 4 × 9.7 KB ≈ 38.7 KB, against about 310 KB today. The primary user has 2–5 machines (ADR 0095). With K = 4, one ordinary event, or one S2 Put in a Home, covers every other seat of a 5-seat group.
- **Mixed fleet (ordinary groups).** The published `MemberAdded` uses K only when every active seat's current verified advert sets the bit. A `JoinResult` uses K only when the joiner's advert does. Otherwise today's sidecar stays.

### 3a. The joiner's own certificate in a Home: digest-only add (D68)

D68 makes S5 remove the joiner's own certificate from Home gossip. This ends ADR 0108's named interim exception for `MemberJoined.certificate_b64` and `MemberAdded.certificate_b64` in every Home where the rule below is active.

- **Joiner.** A capable joiner whose inviter's current verified advert sets the bit omits `certificate_b64` from every gossiped copy of its Home `MemberJoined`: the first publish, each resend and the stored volley. Its direct copy to the inviter keeps it. The field is outside the joiner's signature (`canonical_member_joined_bytes`, `named_groups.rs:2812`), so no signed bytes change, and ADR 0028 relays the gossiped copy unchanged. Toward an inviter whose advert lacks the bit or is unknown, the joiner sends today's copies.
- **Authority intake.** A capable authority treats the gossiped copy and the direct copy as one attempt, because they carry the same signed bytes. It takes the certificate from the direct copy. It never refuses or consumes a Home join on a copy without the certificate.
- **Digest-only add.** When every active seat and the joiner set the bit in a current verified advert, a capable authority seals the Home add in digest-only form. The `MemberAdded` carries a new serde-default field `certificate_digest` (the seat digest, §1) and no `certificate_b64`. Any nested copy of the joiner's `MemberJoined` in it (for example `member_joined_recovery`, `named_groups.rs:1539`) also has no `certificate_b64`. The author evidence (§2) covers `certificate_digest`.
- **Receiver: hold, fetch, verify, then apply.** A capable receiver handles a digest-only Home add the same way however it arrives: by gossip, direct copy, #818 page, S5 fetch or ADR 0106's carry.
  1. It runs every check that does not need the bytes: the commit signature, the actor's role, prev-hash linkage, the owner mandate, the TreeKEM payload fields, and the roster root. The roster with the joiner seated at `certificate_digest` must re-derive the commit's `roster_root`.
  2. It takes the bytes from local verified evidence: S2's scoped store, or an earlier fetch still in memory. Otherwise it fetches the `certificate` object by that digest (§4). It asks the add's actor, the joiner and any active member. A holder serves it from either source in §6.
  3. It runs today's certificate check on those bytes (`named_groups.rs:11249-11295`). The bytes must hash to the digest and decode, the certificate must verify against the group owner, and the joiner must not be in the local revocation set.
  - Only after step 3 does it apply the add, TreeKEM commit included. Until then the add is held, not applied, and later events wait behind it, as at any gap. Its typed state is `subject_certificate_pending` (§8). A held add is kept in memory only; after a restart the node learns it again by catch-up (§4).
  - If step 3 fails, the receiver rejects the add as today and records `subject_certificate_invalid` (§8). Bytes that do not hash to the digest do not fail the add: the receiver discards them and asks another holder.
- **Mixed versions.** Old receivers reject an OwnerCertified add without `certificate_b64` (`named_groups.rs:11249-11255`). So while any active seat or the joiner lacks the bit, or its advert is unknown, the authority seals today's shape. An old inviter receives today's `MemberJoined`. In such a Home the joiner's own certificate still reaches the gossip mesh. ADR 0108's named interim exception continues there, and only there, until the last seat without the bit upgrades or leaves, or the minimum supported version (D35) drops it. That version is not set yet; David will set it in a later ruling (D125), so this exception has no end date until then. A seat that downgrades after a digest-only add cannot apply that add. It stays behind, without stopping, until it upgrades again.
- **L4:** see §9.

### 4. Fetch, head discovery and catch-up

- **Request:** a verified direct message `group_object_fetch_v1 { group_id, kind, digest, request_id }`, with an optional `invite` only for §5's pre-member rule. **Head query:** `group_head_v1 { group_id, request_id }`. The holder answers a head query with its latest committed event as a `commit_event` object and its `oldest_held_revision`. Head queries pass the same guard (§5).
- Requests go only to peers whose current verified advert sets the bit.
- **Answer:** the object inline when it fits 49,152 B; otherwise a control-blob reference of a new kind `GroupObject`, staged for that requester only. Otherwise `group_object_absent_v1 { request_id }` or `group_object_refused_v1 { request_id, reason }` (§5). A `GroupObject` reference is admitted only when it answers this node's outstanding request to that holder.
- **Holders:** any active member on the requester's committed roster, except itself. For a held add (§3a), also its actor and its joiner. The requester asks several at once and never waits on a named device.
- **Requester limits (D98):** at most 16 outstanding fetches per node, at most 3 holders asked at once for one object, and one request per (digest, holder) per 30 s.
- **Timeouts (D98):** 10 s for an inline answer; the existing 115 s for a blob pull. A timeout counts as one holder tried, and the fetch moves on to the next holder.
- **Head discovery triggers:** daemon start; each new connection to an active member; any received event with a gap (today's #818 trigger); and a head probe every 5 minutes while a group is open (D98). A stale head from one holder only delays convergence. A forked head goes to the existing fork handling.
- **Catch-up as control blobs (D54).** From a verified head newer than its own, the member fetches `commit_event` by each `prev_state_hash` in turn, until it reaches an event that chains from its local `state_hash`. It then applies forward (§2). The walk stops at the first refusal, keeps the accepted prefix, as in ADR 0106, and reports `catchup_refused` (§8).
- **Beyond retention (D97).** The next event a member needs may be older than every answering holder's `oldest_held_revision`, with no holder serving it. The member then stops the walk and reports `catchup_beyond_retention` (§8). TreeKEM needs every commit, so no holder can repair this. D97 treats the case as admission: any admin re-Welcomes the member. S5 detects and reports it; S5 does not re-Welcome.
  - S8 (b) (ADR 0114) repairs both cases once it is Accepted: a never-confirmed seat through its never-confirmed repair, and a confirmed member through its retention re-Welcome, which D119 adds to S8 (b). S5 routes `catchup_beyond_retention` to that repair by name and defines no repair of its own. ADR 0114 owns the mechanism, its acceptance rule and its typed states.
  - Until ADR 0114 is Accepted and shipped, the exit is D43's manual remove and re-invite, which the typed state names.
  - When ADR 0109's admins answer `base_beyond_retention`, the node tries S5's walk first. The walk can rescue only a node that applies by the ordinary path. It cannot clear a node that 0109 has marked, or a pre-Welcome joiner: those still need 0109's admin attestation, which an admin signs only from a base in its own `commit_log`. S5 adds no attestation from fetched chains. So for such a node, and whenever S5's holders cannot serve the gap, the case ends in 0109's `readmission_required` or `catchup_beyond_retention`, with the same exit.
- **#946 and #818 for legacy peers (D96).** ADR 0106's carry stays. #818 keeps running beside S5 for legacy peers. #946 keeps running for legacy peers in all groups, Home included, until the minimum supported version (D35) drops peers without the bit.
  - A capable holder answers a #946 request as today, on the metadata topic, when the requester's current verified advert lacks the bit or is unknown. It does not answer a requester that sets the bit; that requester uses S5.
  - A capable requester sends a #946 request only while some active seat lacks the bit, and only after its S5 fetch for that digest has had no bytes for one inline timeout.
  - In a Home these topic answers still reach non-member mesh peers. This is the cost David accepted in D96.

### 5. Serving guard (L4)

A holder serves an object, or answers a head query, only while **all** of these hold:
- the request is verified, the sender is the requester, and the sender is not revoked (`control_blob.rs:595-604`);
- the holder is an active member, and the group is not withdrawn, deleted (§2 item 5) or fork-quarantined (ADR 0064/0066; ADR 0107 §Decision);
- the requester is **Active and not banned on the current committed roster**, with ADR 0107's certificate rule for `OwnerCertified` groups: the roster-embedded certificate with the current revocation set and time, or a current `Clean` verdict. A removed member is never eligible (§2 item 6). Home disclosure therefore stays with current members (D38). The one exception is the pre-member rule below (D95).
- A joiner whose add is sealed is Active on every holder that applied it. Today's #818 "target of a cached add" exception (`named_groups.rs:10058-10073`) is not carried over.

**Pre-member roster fetch (D95).** A pending joiner that is not on the holder's roster may fetch one object: the `roster_projection` at the root its signed invite binds. The request carries that invite in `invite`. The holder serves it only while all of these hold:
- the request and holder conditions above hold;
- the invite verifies as the join path verifies it today, names this group, and has not expired;
- the requested root is the root the invite's signed base state binds, and the holder holds a signed commit with that root (`commit_log`);
- when the invite is addressed, the sender is its intended joiner;
- the sender is not Banned or Removed on the holder's current committed roster.

A pre-member gets no other kind and no other root. This discloses only the root-covered fields that the invite already binds. A v4 invite carries them inline (`invite.rs:123-130`). Above the 20-entry cap, ADR 0112's V5 view signs the base `roster_root` and omits the projection (ADR 0112 §1). A pending joiner asks its inviter and the other base admins it can reach through an authenticated peer relationship and a current advert (ADR 0112 §2). How it finds a holder confers no authority; the holder admits it only by the invite.
- **Ownership.** S5 owns this serving rule (0088's S5 row: "the #646 primitive"). ADR 0112 owns the invite shape. #646 closes when both have shipped. S6 is Accepted after S5, so ADR 0112's V5 path depends on this rule.
- **Scope.** D95 rules only the roster at the invite's root. The S5 fetch serves a pending joiner nothing else. The one other disclosure to a joiner before it accepts membership is the promotion chain below (D133), and it never uses the fetch surface.

**Promotion chain on the redeemer's result path (D133).** This is the disclosure rule that ADR 0112 uses. A redeeming admin B that is not on joiner J's invite base may carry its promotion chain to J. Only that chain, and only on B's own direct, guarded result path.
- **What.** The promotion chain is the signed `commit_event` objects (§1, §2) that link J's invite base state to the predecessor of J's add. It includes the commit that gave B its current Admin role. Nothing else goes with it: no other commit, no projection, and no certificate outside those events.
- **When.** B sends it only with a result that seats J, after B has sealed J's add. On a refusal B sends no chain.
- **How.** B sends it only on its own direct result to J: inline, as ADR 0106 events, or as a `GroupObject` blob staged for J only. Each exchange is admitted under the membership lock (§5), with ADR 0107's guard and D60's current eligibility: J must be Active, not banned, and certificate-valid on B's current roster. It never goes on gossip, on the S5 fetch surface, or from any other holder.
- **Joiner check.** J verifies each commit as §2 does (author evidence and commit signature, or the legacy author-only rule), the linkage from its invite's base state hash, and B's Admin role at the predecessor. J accepts the result only if every check passes.
- **Failure (L3).** S5 names the detail. A failed check gives `promotion_chain_invalid { state_hash, reason }`. A commit without author evidence that B did not author gives `promotion_chain_unverifiable { state_hash, author }`. ADR 0112's outcome for both is `redeemer_authority_unproven { redeemer }` (ADR 0112 §2). J's join status shows that outcome, with S5's detail as its cause, and J does not accept the result.
- **No failover.** B has already sealed J's add, so the attempt may have committed. J keeps that attempt open. Under ADR 0112's failover rule (D99), it starts no fresh redemption, at another admin or with another invite. It first recovers and verifies the original terminal: from B again, where each retry is a fresh admitted exchange, or, once the commit reaches any holder, as ADR 0112 recovers an original result. Until then J waits in `redemption_unresolved`, naming B (the ADR 0088 §2 entry of D99, confirmed by D118).
- **L4.** The chain adds no authority. J accepts only signed commits that link from its signed invite base, and B cannot forge them. J's own acceptance rules are unchanged. When B sends the chain, J is already a current member on B's roster, so a Home's certificates stay with Home members (D38).
- **Disclosure (D133, D157).** J learns B's promotion history before it has accepted membership. The chain also shows every other commit between J's invite base and the predecessor, for example joins made after the invite. David accepted this whole disclosure (D157): J is already seated when it receives the chain, and it would see the roster anyway. No redacted proof is used.
- **Mixed versions.** The chain rides only S6's V5 redemption (ADR 0112), so both ends set S6's bit and S5's bit. A chain commit sealed by a legacy authority has no author evidence. J can verify it only if B authored it; otherwise `promotion_chain_unverifiable`, which is `redeemer_authority_unproven` in ADR 0112.

**Answers to a refused requester (L3).**
- A requester with no seat on the holder's committed roster, and no valid invite for the pre-member rule, gets `group_object_absent_v1`. That is the same answer as "not held", so S5 adds no membership oracle. A forged or invalid invite gets the same answer.
- A requester with a seat that fails the guard gets `group_object_refused_v1 { request_id, reason }`, with reason `removed`, `banned`, `revoked` or `certificate_not_current`. That requester already knows the holder from its own roster, so the answer discloses only its own status. A pending joiner with a valid but expired invite gets `invite_expired`.
- Holder-side states (not an active member, withdrawn, deleted, quarantined) answer `absent`, and the requester tries another holder.
- **Responder limits (D98):** the existing staging caps (`control_blob.rs:14-20`) and 8 requests per requester per 10 s. Over a limit, a requester that passes the guard gets the retryable `refused { capacity }` or `refused { rate_limited }`, with `retry_after`. Any other requester gets `absent`.

**Every physical exchange is admitted afresh, under the membership lock** (cross-slice rule 5; ADR 0107's linearization). This covers each inline answer, each head answer, each pre-member (D95) answer, each promotion-chain exchange (D133), each blob chunk and each retry.
- For each exchange the holder takes the group's membership lock. It then selects the artifact, checks the requester's current eligibility (§5's guard, or the D95 conditions), and makes the one transport write. Only then does it release the lock. It makes one single-exchange send with no transport-level resend. Each retry is a new request, admitted again.
- Every membership change takes the same lock: removal, ban, revocation, a verdict change, withdrawal, deletion, local leave and quarantine. So each write happens wholly before or wholly after such a change, never across it. Certificate expiry needs no lock, because each admission checks the current time.
- Today the chunk path copies the bytes and only then spawns the send (`control_blob.rs:633-657`). So the S5 chunk task takes the lock and re-admits for every chunk, inside the task.
- Object bytes never use gossip or the gossip-capable direct-message fallback.
- No S5 write is in progress while a membership change holds the lock. After the change, the holder cancels that requester's S5 tasks and purges its staged copies. A task already waiting for the lock re-checks eligibility after the change and sends nothing.
- These are the class-R properties of the #1190 lifecycle note (related work). S5 requires the properties; it does not depend on that branch merging.
- S5 never serves Welcomes or class-K key envelopes. D60's epoch-bound share admission stays the separate guard for them.

### 6. Holder store (ADR 0085)

- **Serving sources.** Projections are served from `named_groups.json`. Certificates are served from the seat certificates in `named_groups.json` and, in a Home, also from S2's scoped store (`home-owner-certificates.hscert`, ADR 0108 §5). S5 adds no file for them.
- **Where fetched certificates persist.**
  - In a Home, a fetched certificate persists only in S2's scoped store, as an S2 entry with its disclosure context (group, owner, subject, committed digest), under S2's write, cap and pruning rules. It never goes into `named_groups.json`.
  - A certificate fetched for a held add (§3a) has no committed context until the add applies, so it stays in memory until then. A restart before that fetches it again.
  - In an ordinary group, a fetched certificate is stored as today's hydrate stores it (`seat_cert_fetch.rs:915`).
  - If the persist fails, including S2's `Retry(capacity)`, the node still uses the verified bytes for the apply in progress, and fetches them again after a restart.
- **New persisted state:** one file per event, `<data_dir>/group-holder/<stable_group_id>/<state_hash>.ev`. Each file is magic `X0GHE1\0\0`, then bincode `HeldEventV1 { revision, committed: bool, rebuilt_from: Vec<[u8; 16]>, event_json }`, consumed exactly. `event_json` is the JCS bytes (§2) of the event value with only `roster_certificates_b64` removed. `rebuilt_from` lists the quarantine `txid`s a replacement covers (ADR 0108 §5a); it is empty for an ordinary write.
- **Order and durability.**
  - Before persisting the roster for a sealed or applied commit, the node writes the event's file with `committed = false`: a temp file, fsync, rename, then fsync of the directory.
  - After the roster persist succeeds, it rewrites the file with `committed = true` by the same method.
  - On restart it reconciles. It first classifies each `<state_hash>.ev` file by ADR 0108 §5a, before any decode or delete:
    - **A read error** or **a newer valid version:** the file is kept byte-identical at its path, whether or not its `state_hash` is on the committed chain. It runs memory-only (`sidecar_unavailable` or `sidecar_newer_format`), and reconcile never deletes it.
    - **Damage:** the file is quarantined by §5a with its bytes preserved, whether or not its `state_hash` is on the committed chain. Only then does §6's rebuild rule decide whether step 4 writes a replacement.
    - **A valid version-1 file:** if its `state_hash` is on the committed chain (`commit_log` or head), it becomes committed. Otherwise it is deleted. Reconcile deletes only such valid, readable, off-chain files.
  - Quarantine copies (`.q-` names) and temp files (`.tmp-` names) are never touched by reconcile; ADR 0108 §5a governs them.
  - An uncommitted file is never served. A crashed seal therefore cannot leak a commit that might be replaced at the same revision. A held add (§3a) is not applied, so it has no file.
- **Failure:** a failed write is logged and never blocks the commit; coverage drops by one event.
- **Unreadable file: quarantine and rebuild (D120).** David ruled that S5 quarantines an unreadable holder file and rebuilds it from holders, instead of waiting for an operator. S5 follows the shared lifecycle in ADR 0108 §5a: its classification, transaction, resume, history, failure states (`sidecar_unavailable`, `sidecar_newer_format`, `sidecar_quarantine_failed`, each with a `file` field) and fault cases. S5 adds only what is specific to its files:
  - **Files.** Each `<data_dir>/group-holder/<stable_group_id>/<state_hash>.ev` is one §5a file `F`, and its group directory is `D`.
  - **Header layout.** 8 bytes: the family prefix `X0GHE` (bytes 0–4), a version field of one ASCII digit (byte 5), the terminator `\0` (byte 6) and one padding byte `\0` (byte 7). Version `0` is invalid. The highest version this binary supports is 1 (`X0GHE1\0\0`). The prefix `X0GHE` is reserved for this path forever.
  - **Memory-only.** When §5a runs a holder file memory-only, the node may fetch that event (§4), verify it as §2 does, and serve it from memory for this run. It writes nothing at `F`.
  - **Rebuild source (step 4).** If the file's `state_hash` is on the committed chain and within retention, the node fetches that `commit_event` from other holders by S5's fetch (§4) and verifies it as §2 does. It writes the replacement as a committed `HeldEventV1`, with `revision` from the verified event and `rebuilt_from` set as §5a says. While it waits for a holder, the group shows `holder_store_rebuilding { state_hash, txid, since, holders_tried }` (§2 item 8). A legacy event without author evidence comes only from its author (`awaiting_author`, §8).
  - **No rebuild.** This applies only after classification has quarantined a damaged file. If the `state_hash` is not on the committed chain, a valid copy would have been deleted at reconcile, so none is rebuilt. If it is beyond retention, the event drops out of coverage. In both cases step 4 writes no replacement, and the transaction goes to step 5. A missing file with only history copies follows the same rule.
  - **Local-only state.** None. Every byte in a holder file is a copy of a signed committed event that other holders retain, and `committed` and `revision` are re-derived from `commit_log`. Nothing the node decides comes from this store (D54), so a quarantine or a rebuild never changes its group state or `named_groups.json`. Only its serving coverage drops until the rebuild completes.
  - **Bound (D158).** The node runs step 4 for one `state_hash` once per daemon run. If that rebuild fails, the file shows `sidecar_unavailable { file, cause: rebuild_bound }` and waits for the next daemon start.
  - **Directory failure.** If the node cannot list a group's directory, that group's holder store shows `sidecar_unavailable { file: D, cause: read_error }` for the run. The node answers `absent` for that group's events and retries at the next start.
  - **Amendment to ADR 0085 rule 4 (D120), scoped to S5's holder files.** Rule 4 says an unreadable file "is left untouched". For a damaged `group-holder/<stable_group_id>/<state_hash>.ev`, S5 instead quarantines it by ADR 0108 §5a and rebuilds it. Its bytes are never truncated or overwritten, and never deleted except with the group's own files under §5a's retention rule (D148). Rule 5 is not amended.
- **Deletion:** on local removal, ban, withdrawal or signed delete, the node deletes the group's holder directory: its `<state_hash>.ev` files, temp files and quarantine copies. That follows ADR 0108 §5a's retention rule (D148): a quarantine copy is never deleted automatically, except with its group's own files, and an operator may remove one. §5a's diagnostics list each copy with its size.
- **Downgrade:** older binaries never open `group-holder/`. Upgrading again reconciles the store.
- **Not an authority log (D54):** every member keeps its own copy; any member serves it; requests are by hash; nothing is decided from it.
- **Retention (D98):** 128 committed events per group, today's in-memory cap; at 51.5 KB each that is about 6.6 MB. Caps: 16 MiB per group and 256 MiB per node. Over a cap, the oldest committed events go first. A member that falls behind them is handled in §4 (D97).
- The implementing PR adds round-trip, fail-closed and crash-point tests. The first release that writes the format supplies the released fixture (ADR 0085 rule 6).

### 7. Capability bit and mixed versions

- **Bit:** `group_object_fetch_v1`: "answers and sends S5 requests, mints and verifies `author_evidence`, accepts `GroupObject` blobs, keeps a holder store, and holds and applies digest-only Home adds". It is named here. Its number is the next unallocated bit when this ADR is Accepted. It is advertised only after the holder store has reconciled.
- **New to old:** old peers never receive S5 requests. In ordinary groups, sidecars stay legacy-sized while a relevant advert lacks the bit or is unknown. In Home groups the gossiped roster sidecar is gone for every member (D38); an old Home member recovers certificates through S2's Put or #946, which stays for legacy peers until the minimum supported version (D35, D96). An old Home seat or joiner keeps today's add shape (§3a). Old receivers ignore `author_evidence`. #946 and #818 still run.
- **Old to new:** a new holder answers #946 from requesters without the bit (§4) and #818 as today. Legacy events stay author-served. 0.45 peers see no new message.
- Unknown capability state is not positive evidence. Requests wait for a current advert that shows the bit, and the wait names the holders that lack it (§8).

### 8. Waits and refusals (L2, L3)

L3 binds S5 as a hard rule (D64). Every block S5 adds or touches ends in one of the typed states below. The waiting side sees each one, with what it waits for, through the group's status surface.

**Waits** (retryable; each resumes when the named holder or condition appears):
- `evidence_pending { kind, digest, since, holders_tried, holders_without_bit, next_attempt_at }`: no eligible holder has served the object (§2 item 8). It stays retryable across join-attempt deadlines and resumes when any holder comes online. Holders without the bit are named, so an upgrade wait is visible, and `next_attempt_at` shows the requester's backoff (§4).
- `subject_certificate_pending { revision, agent, digest, since, holders_tried }`: a held digest-only add (§3a; §2 item 8).
- `awaiting_author { state_hash, author }`: a legacy event without author evidence that only its author may serve (§2). This is today's path toward legacy authorities; 0088 lets each slice degrade to it toward peers without the bit.
- `awaiting_evidence { digests, since }`: a capable joiner whose authority reports `evidence_pending` (below).
- A retryable `refused { capacity }` or `refused { rate_limited }` (§5) waits until `retry_after` and counts as one holder tried.
- `holder_store_rebuilding { state_hash, txid, since, holders_tried }`: a quarantined holder file waits for a holder to serve its event (§6, D120; §2 item 8). ADR 0108 §5a's `sidecar_unavailable`, `sidecar_newer_format` and `sidecar_quarantine_failed` (§6) block no S5 operation; for S5 they report reduced serving coverage.

**Refusals** (terminal for that request):
- `group_object_refused_v1` with `removed` (§2 item 6), `banned` or `revoked` (§2 item 1), `certificate_not_current` (§2 item 2), `invite_expired` or `too_large` (§1, §5).
- `subject_certificate_invalid { revision, agent, digest, failure }`: the fetched certificate fails today's check (§3a; §2 item 2).
- `catchup_refused { state_hash, reason }`: the walk stopped at a refused event, and the accepted prefix stays (§4). A fork goes to the existing fork handling (§2 item 7).
- `catchup_beyond_retention { own_revision, oldest_held_revision, holders }`: the member needs re-admission (§4, D97). The state names the exit: ADR 0114's never-confirmed repair or its retention re-Welcome (D119), once ADR 0114 is Accepted; until then D43's manual remove and re-invite. It reopens if a holder that retains the next event answers.
- `promotion_chain_invalid { state_hash, reason }` and `promotion_chain_unverifiable { state_hash, author }`: S5's detail for ADR 0112's `redeemer_authority_unproven`. They end that result, not the attempt: J stays in ADR 0112's `redemption_unresolved` until it recovers the original terminal (§5, D133).

**The joiner's 120 s poll (D64).** For a joiner that sets the bit, the authority does not stage the #946 terminal refusal while an S5 fetch for a required digest is pending. It answers the joiner's join-result poll with ADR 0108's signed pending cause notice (D117), with cause `evidence_pending` and the missing digests. S5 defines no notice of its own. The joiner's attempt then shows `awaiting_evidence { digests, since }`, and it does not end at the 120 s poll deadline. It polls again on each reconnect to the authority and at the head-probe interval. It ends on the seal, on a typed refusal, or on a local leave.

**Amendment to ADR 0088 §2 (D96, confirmed by D118).** This ADR amends ADR 0088 §2 with one named entry, ruled by David (D96). David confirmed it as a named §2 entry (D118). It is the same entry that ADR 0108 records, under the same name. S2 is Accepted first, so 0108's record takes effect first. This ADR restates it and adds no second entry.
- **#946 legacy refusal.** A joiner without S5's capability (its current verified advert lacks the bit, or is unknown) may receive a terminal refusal after 10 minutes in which the authority cannot obtain a required seat certificate, although §2 item 8 says such a fetch waits.
- **Typed state:** the existing signed `JoinRefusalReceipt` with reason `certificate_evidence_unavailable` (`seat_cert_fetch.rs:55`; `named_groups.rs:1266`, `:1282`). The joiner sees `Refused` with that reason in its join outcome.
- **Exit:** for that attempt, an admin issues a fresh invite once a holder is online. The entry ends at the minimum supported version (D35). That version is not set yet; David will set it in a later ruling (D125), so the entry has no end date until then. Toward a joiner with the bit, S5 never stages this refusal; that joiner gets the retryable wait above, so an upgrade also leaves the entry.
- **Residual:** a released joiner's own 120 s poll ends before the refusal is staged, so it sees today's `TimedOut` without the cause (ADR 0107). S5 cannot change released binaries, so D64's 120 s poll requirement is met for capable joiners only.

### 9. Security argument (L4)

- **Two acceptance rules change.**
- **First: authorship of a fetched commit-bearing event may be proven by a detached author signature over its canonical digest (§2), instead of by the transport sender.**
  - That signature is the same ML-DSA-65 key over the complete security-relevant content, so it is at least as strong as sender authentication of the same bytes.
  - A replay applies only at its own place in the chain (prev-hash linkage).
  - The author's current authority and revocation are still checked at apply time. The holder gains no authority.
- **Second (D68): a Home `MemberAdded` without `certificate_b64` is held, not rejected, when it carries a `certificate_digest` that the signed commit's roster root binds (§3a).**
  - The add is applied only after today's certificate check passes, on bytes that hash to that digest. The check moves from ingress to apply. It never runs on fewer inputs, and it uses the revocation set at apply time, which is at least as current.
  - The authority's commit signature and author evidence bind the digest, and the digest pins exact bytes. A holder cannot substitute another certificate.
  - No receiver installs the TreeKEM commit before the check passes. An admin that seals an outsider whose certificate fails gains nothing it cannot gain today: every capable receiver refuses the add (Considered option 8).
  - The cost is latency: a held add waits for one holder (§2 item 8). Disclosure narrows: the certificate leaves a node only on guarded direct channels (D38). The `certificate_digest` on gossip is a commitment, not the certificate.
- **Every other fetched object has today's checks.** A certificate, projection or KV image is accepted only when it hashes to a value bound by signed evidence. Hash-uncovered fields are never accepted (§1).
- **Serving (§5) adds a guard and two bounded disclosures.** The guard narrows who receives bytes. Typed refusals go only to requesters that hold a seat, so they disclose only the requester's own status. The pre-member rule (D95) discloses only what the presented invite already discloses. The promotion chain (D133) goes only from the redeeming admin to a joiner it has just seated, on its guarded result path, and grants no authority. A `kv_image`, if built (D94), also needs the store's read policy.
- A malicious holder can withhold or serve wrong bytes. Wrong bytes fail verification, and the requester tries another holder. Withholding costs time only.

## Consequences

### Positive

- Catch-up and certificate repair complete from any member holder, across author restarts and for gaps longer than 8. This closes ADR 0106's deferred option 3.
- Sidecars shrink from about 310 KB to at most about 39 KB.
- One carry rule replaces per-case patches. #646 and later slices reuse one primitive.
- In a Home whose seats all set the bit, the joiner's own certificate leaves a node only on guarded direct channels (D68).
- An unreadable holder file is rebuilt from holders without an operator (D120).
- An invite made before an admin's promotion still works at that admin (D133).
- Every S5 block is typed and visible (D64). A member behind retention gets a typed state and a named exit instead of a silent wait (D97).

### Negative / Trade-offs

- One extra ML-DSA-65 signature per commit (about 4.4 KB as base64) and one verify per fetched event.
- A new persisted directory with two writes per commit, and a new request surface.
- A Home join needs one certificate fetch by each receiver that lacks the bytes, and a held add delays the events behind it (§3a).
- Events sealed by legacy authorities stay author-served.
- A member behind every holder's retention waits for ADR 0114's repair (D97, D119). Until ADR 0114 is Accepted and shipped, its exit is D43's manual remove and re-invite.
- A damaged holder file costs a refetch, and its quarantine copy stays on disk until an operator removes it or the group's files are deleted (D120, D148). Repeated corruption uses disk.
- A joiner redeeming at a promoted admin learns that admin's promotion history, and the other commits after its invite base, before it accepts membership (D133).
- In ordinary groups the metadata topic still carries up to K certificates per add, in plain JSON.
- In a Home with any seat that lacks the bit, the joiner's own certificate still reaches the gossip mesh (§3a). #946 answers to legacy requesters reach it in every Home until the minimum supported version (D35). Legacy joiners keep a 10-minute refusal that ADR 0088 §2 did not list; it is now the named entry "#946 legacy refusal" (D96, §8). Old Home members lose the inline sidecar.
- A seat that downgrades after a digest-only add lags until it upgrades again.

### Neutral / Operational

- #946 and #818 stay for legacy peers until the minimum supported version (D35) drops them (D96).
- If C2 is red, S5 adds a fourth object kind, `kv_image` (D94).
- The bit number follows acceptance order. S3 and S6 also need bits.

## Validation

W3-H (#1164) does not exist yet. Each case below is a specification: nodes, steps, assertion and baseline. All cases run on W3-H's deterministic clock. Messages are delivered in step order unless a step drops or delays one, and each step completes before the next starts. Steps use public APIs only. **Gate:** each red case is committed and shown red on `main` before S5's code merges. The run is recorded on the implementing PR. A tracking issue should list these cases.

**Red cases (must be red on `main`):**
- **H1, Home catch-up from a non-author holder.**
  - Nodes: owner device A (authority), admin B, plain member C, member D, joiners E and F.
  - Steps:
    1. A, B, C and D converge on a Home TreeKEM group.
    2. D stops.
    3. A seals the adds of E and F.
    4. A restarts, then stops.
    5. D starts.
    6. (a) No further event is sent. (b) B seals one more add.
  - Assert: within 120 s D's state hash and TreeKEM epoch equal C's, and D decrypts a message C sends.
  - Baseline on `main`: red. In (a) D is never told the head. In (b) the #818 page from B fails `actor == sender`.
- **H2, long joiner gap.**
  - Nodes: authority A, devices K1–K9, joiner J.
  - Steps:
    1. A mints J's invite.
    2. A seals the adds of K1–K9.
    3. A restarts.
    4. J redeems the invite. A seals J's add and delivers the result.
    5. A stops.
  - Assert: within 120 s J is Active with TreeKEM installed, fetched from the K devices.
  - Baseline on `main`: red. The 9-event gap is over ADR 0106's cap, and A's log is gone.
- **H3, §2 item 8 resumes, and the joiner's poll stays visible (D64).**
  - Nodes: an OwnerCertified Home of 7 seats. Owner device O is the creator. A2 is a promoted admin. P is a plain member. J is a capable joiner.
  - Setup: the harness makes A2's seat for O digest-only.
  - Steps:
    1. O and P stop.
    2. J redeems at A2, and A2 attempts to seal.
    3. At minute 12, P starts, and J retries.
  - Assert: before minute 12, A2 reports `evidence_pending` naming O's digest, and no terminal refusal. J's attempt shows `awaiting_evidence` naming that digest from its first poll after A2's wait begins, and it does not end at 120 s. Within 60 s of P's start, A2 holds O's certificate. The seal completes on J's retry.
  - Baseline on `main`: red. J's poll ends at 120 s without naming the missing certificate, and the terminal refusal fires at 10 minutes.
- **H4, the joiner's own certificate stays off Home gossip (D68).**
  - Nodes: owner device O (authority), members B and C, joiner J, all candidate binaries; stranger S, a non-member attached to the Home's metadata topic mesh.
  - Schedule: gossip reaches every mesh peer, S included. S2's Put to C is dropped. The harness holds C's copies of the add until step 4.
  - Steps:
    1. O, B and C converge on a Home TreeKEM group.
    2. J redeems its invite at O, and O seals J's add.
    3. B receives the add, takes J's certificate from O, and applies it.
    4. O stops. The harness partitions C from B and J, then delivers the gossiped add to C.
    5. At +60 s the partition heals.
    6. Variant (b): with B and C online, the harness, acting as O, seals the add of outsider X, whose certificate does not chain to the owner.
  - Assert:
    - S captures no egress that decodes, at any nesting, to J's certificate. Decode as ADR 0108's `s2_home_all_egress_privacy` does.
    - During the partition, C reports `subject_certificate_pending` naming J's digest and has not installed the new TreeKEM epoch. Within 60 s of the heal, C applies the add, J's seat is Clean, and C's TreeKEM epoch equals B's.
    - (b): B and C report `subject_certificate_invalid` for X, and neither installs the TreeKEM epoch that adds X.
  - Baseline on `main`: red. S receives J's certificate on the gossiped `MemberJoined` and `MemberAdded`. Variant (b) is a control: green on `main`, and it must stay green.
- **H5, a member behind every holder's retention (D97).**
  - Nodes: admin A, member B, confirmed member D.
  - Steps:
    1. A, B and D converge on a TreeKEM group.
    2. D stops.
    3. A makes 129 signed metadata changes (for example renames), one more than the retention cap.
    4. D starts.
  - Assert: within 120 s, D reports `catchup_beyond_retention` naming its revision, the holders' oldest held revision and D43's manual exit. D applies no partial chain and installs no later epoch.
  - Baseline on `main`: red. D reports no typed state that names retention.
  - The re-Welcome itself is not asserted here. It belongs to ADR 0114's retention re-Welcome (§7) (D119).

**Controls (expected green on `main`; they must stay green):**
- **C1, certificate from an online plain holder.** As H3, but P stays online. Baseline: green through the #946 topic answer. **Exit:** green with zero #946 topic answers from P (the "group-scoped certificate answer sent" counter), and the certificate delivered by the S5 direct path. Every seat sets the bit, so no #946 request is sent (D96).
- **C2, #811 exactly as asked.**
  - Steps: in a private group, owner O and admin A write store history, and plain member P holds it. J is seated and never opens the store. O and A stop. J opens the store cold.
  - Assert: J reads the full history within 120 s.
  - Baseline: run first. If it is red, S5 builds the `kv_image` kind (D94), and C2 becomes a red case under the gate. If it is green, #811 closes as not reproduced.
- **C3, legacy #946 in a Home (D96).**
  - Nodes: capable owner device O (authority) and capable members P and Q; a member L and a joiner J0 on the released v0.46.x binary; stranger S on the Home's metadata mesh.
  - Steps:
    1. The harness makes L's seat for P digest-only, and L requests P's certificate by #946.
    2. The harness makes O's and L's seats for Q digest-only. P and Q stop.
    3. J0 redeems at O, and O attempts to seal. The clock runs 11 minutes.
  - Assert: a capable holder (O or P) answers L's #946 request on the topic, as today, and S sees that answer. O stages `certificate_evidence_unavailable` toward J0 at 10 minutes (the named §2 entry "#946 legacy refusal", §8). New with S5: no #946 answer goes to a requester that sets the bit.
  - Baseline: green on `main` for the first two assertions. They must stay green until the minimum supported version (D35) drops legacy peers.

**Exit tests:** H1–H5 and H8 green; H6 and H7 green once ADR 0112's V5 redemption has merged; H9 and C1–C4 unchanged or better; the H8 lifecycle row passes.
- Rejections: wrong hash; bad author or commit signature; a mismatched signer; a projection carrying an uncovered field; a root no signed commit binds; a forked chain (the #846 gate fires); a legacy event from a non-author holder; a digest-only add whose `certificate_digest` the roster root does not bind.
- **Digest test vectors** (committed with the implementation, each with its expected BLAKE3):
  - nested objects whose keys sort differently by UTF-16 code unit and by code point (for example U+E000 against U+1F600);
  - integers 0 and 2^53 − 1 accepted; 2^53, `1.0` and `1e3` make the evidence invalid;
  - non-ASCII text given literally and as `\u` escapes yields one digest; U+001F becomes `\u001f`;
  - whitespace variants of one value yield one digest;
  - a duplicate key, at the top level and nested, is rejected;
  - an unknown member is retained and covered, so changing it fails verification;
  - changing `roster_certificates_b64` or `author_evidence` does not change the digest.
- **Home disclosure:** a non-member peer in a Home's metadata mesh receives no roster-sidecar certificate and no S5 answer from a capable node. When every seat and the joiner set the bit, it receives no copy of the joiner's own certificate (H4). Its only permitted certificate egress on the topic is #946 answers to legacy requesters (D96). Members still converge through S5 fetch or S2's Put.
- Store crash points: before the uncommitted write, between it and the roster persist, and between the persist and the committed write. After each, committed events are servable and uncommitted ones are never served.

**Serving guard:**
- Removed, banned, revoked, expired and verdict-changed requesters each get `refused` with that reason and no bytes, inline and by chunk. Withdrawn and quarantined holders, and a stranger, answer `absent`.
- An invalidation that races an in-flight chunk aborts it before its write. A retry is admitted afresh.
- Over the responder limits, a seated requester gets the retryable `refused`, and a stranger gets `absent`.
- The D95 rule has a red case (H6) and a separate control (C4), below.

**D95 cases.**
- **H6, invite-bound roster fetch above the cap (red on `main`).**
  - Nodes: admin A (issuer); admin H, an Admin on the invite's base roster that stays online; 23 further members (25 Active seats); joiner J.
  - Setup: before step 3, J and H have an authenticated peer relationship, with H's agent bound to its machine by ADR 0089 `EvidenceV1`, and J holds H's current verified advert showing the bit.
  - Steps:
    1. The 25 seats converge.
    2. A mints an invite for J through the public invite API. Above the cap this is ADR 0112's V5 view, which binds the base root R.
    3. A stops. H stays online.
    4. J calls the public join API.
    5. J's join flow sends H one `group_object_fetch_v1 { group_id, kind: roster_projection, digest: R, request_id, invite }`, carrying the signed invite. A request to A, if sent, times out and counts as one holder tried.
  - Assert: H admits the request under §5's D95 conditions, inside the membership lock, and answers with the projection at R, inline or as a `GroupObject` blob. Within 120 s, J re-derives R from it. J makes no other pre-member fetch.
  - Baseline on `main`: red. A cannot mint an invite past 20 entries (#646, `invite.rs:201-217`).
  - Gate: H6 is committed red on `main` before S5's code merges. It turns green only once ADR 0112's V5 invite has also merged; it mirrors the D95 variant of ADR 0112's `s6_promoted_admin_stale_invite`.
- **C4, no roster to anyone else (control: green on `main`, must stay green).**
  - Nodes: admin A, member H, banned identity Z holding an older valid invite, stranger X with a forged invite.
  - Steps: A stops. Z and X each call the public join API with their invites.
  - Assert: H sends Z and X no roster projection and no other object bytes. On `main` there is no pre-member fetch, so this holds today.
  - New with S5 (typed answers, not on `main`): Z gets `refused { banned }`, X gets `absent`, and an expired copy of J's invite gets `refused { invite_expired }`. J's requests for another root or for a `commit_event` get `absent`.

**D120 cases.** H8 is a red case, so it is in the pre-code gate like every other red case (Gates).
- **H8, holder-file rebuild through S5 (red on `main`).**
  - Nodes: authority A and members B, C and D, all candidate binaries, on the deterministic clock.
  - Schedule: messages are delivered in step order. D is partitioned from B for the whole case, so D can catch up only through C; C can reach B. In variant (b), C is also partitioned from B until +60 s after step 4.
  - Steps:
    1. A, B, C and D converge. D stops. A seals three events E1–E3, and B and C hold them.
    2. A stops. C stops. The harness damages the body of C's E1 and E2 files, keeping a valid version-1 header.
    3. C starts.
    4. D starts.
  - Assert:
    - C quarantines E1 and E2 by ADR 0108 §5a, with their bytes preserved, before it writes any replacement. It shows `holder_store_rebuilding`.
    - Within 60 s of C reaching B, C holds verified copies of E1 and E2 fetched by S5, each listing its `txid` in `rebuilt_from`, and serves E1–E3 to D. Within 120 s of step 4, D's state hash equals B's. In (b), C shows `holder_store_rebuilding` naming B until the partition heals.
    - C's group state and `named_groups.json` never change.
  - Baseline on `main`: red. With A offline, C cannot serve events it did not author (`actor == sender`), and `main` keeps no copy across C's restart, so D never catches up.
- **H8 lifecycle row.** S5 instantiates ADR 0108 §5a's W3-H fault cases for its holder files (`group-holder/<stable_group_id>/<state_hash>.ev`), with H8's nodes and S5's fetch as the rebuild source. As §5a allows, S5 marks two of them as controls: the newer-valid-version case and the history cases. They hold on `main`, because no released binary opens `group-holder/`.
- **H9, no rebuild for an event off the chain or beyond retention.** As H8, but C's damaged file is for an event that is not on the committed chain, and in variant (b) for one beyond retention. Assert: C quarantines it with its bytes preserved, writes no replacement, finalizes the copy as history, and serves `absent` for it. Baseline on `main`: control (`main` never opens the file); new with S5: the quarantine and the history copy.

**D133 case.**
- **H7, promotion chain only on the redeemer's result path.** It runs inside the promoted-admin run of ADR 0112's `s6_promoted_admin_stale_invite`, which is red on `main`.
  - Nodes: as that case, where B is promoted after J's invite base, plus stranger S on the group's metadata mesh and member C.
  - Steps:
    1. While still a pending joiner, J asks C for a `commit_event` on the chain.
    2. J redeems at B, and B seals J's add.
    3. B returns its result with the promotion chain.
    4. Variant (b): the harness drops one link from the chain. Variant (c): it replaces one commit with a forged one.
  - Assert:
    - C answers J's step-1 request with `absent`.
    - J receives the chain only from B, only after its add is sealed, and only on B's direct result path. S and C send J no chain bytes before J's add is sealed.
    - J verifies the chain and accepts the result.
    - In (b) and (c), J reports `redeemer_authority_unproven` with S5's `promotion_chain_invalid` detail and does not accept the result. J sends no request to another admin and redeems no other invite. It stays in `redemption_unresolved` naming B until it recovers and verifies the original terminal.
  - Baseline on `main`: red, as ADR 0112 records (main's inviter pin prevents admission). The disclosure assertions are new with S5 and S6. H7 goes green only once ADR 0112's V5 redemption has merged.

**Non-regressions:** ADR 0106's carry; ADR 0107's guard; the R19 suite; KV sync tests; D60 share admission unchanged.

**Mixed versions:** with the released v0.46.x binary in the harness, no S5 message reaches it. Legacy sidecars, #946 and #818 behave as today in both directions. Old receivers apply events that carry `author_evidence`. With one released seat in a Home, the authority seals today's add shape and that seat applies it; a released inviter receives today's `MemberJoined`. A downgrade leaves `group-holder/` untouched.

## Rulings and open questions

**Blocking David's Accept:** no open question remains. Accept waits only for the acceptance order (S2, S4 and S3 Accepted first), for ADR 0108's pending cause notice (D117), which §8 reuses, and for a cross-model review of the round-2 and round-3 text.

David ruled G7 and Q1–Q8 on 2026-10-04 (D64, D65, D68, D93–D98):

- **G7, L3 binds every slice (D64):** a hard rule. Every block S5 adds or touches ends in a typed refusal or a typed, visible wait, including the joiner's 120 s poll and upgrade and backoff waits (§8).
- **Q1, K (D93):** K = 4 (§3).
- **Q2, KV history (#811) (D94):** if C2 is red, retained KV images become a fourth object kind, `kv_image`, served under the same guard (§1, §5).
- **Q3, pre-member roster fetch (#646) (D95):** a pending joiner with a signed invite that binds the root may fetch that roster (§5). This rules the roster at the invite's root only. ADR 0112 §1 defines the V5 invite that binds only that root above the 20-entry cap.
- **Q4, #946 retirement (D96), against the recommendation:** #946 topic answers and the 10-minute refusal stay for legacy peers in all groups, Home included, until the minimum supported version (D35) (§4). The legacy-joiner refusal is the named ADR 0088 §2 entry "#946 legacy refusal", the same entry ADR 0108 records (§8).
- **Q5, retention exhaustion (D97):** treated as admission. Any admin re-Welcomes the member (§4). D119 below puts confirmed members in S8 (b) too.
- **Q6, operational values (D98):** accepted as recommended (§4, §5, §6).
- **Q7, "S8" in the order (D65):** "S8" means S8 (a), ADR 0107. ADR 0114 follows S4, and S5 does not wait for it (Gates).
- **Q8, the joiner's own certificate on Home gossip (D68):** S5 removes it, with the digest-only add (§3a), its security argument (§9) and its mixed-version plan (§3a, §7).

David ruled round 2 on 2026-10-04 (D117, D118, D119, D120, D125, D133):

- **Q9, the promotion chain for a joiner before membership (D133):** yes, narrowly. The redeeming admin may carry its promotion chain to the joiner: only that chain, and only on its own direct, guarded result path (§5). This ADR owns the disclosure rule; ADR 0112 uses it. A chain that fails is ADR 0112's `redeemer_authority_unproven`, and the attempt stays open under D99's failover rule; J never fails over while B's add may have committed.
- **Confirmed member behind retention (D119), against the recommendation:** S8 (b) is widened now, so ADR 0114 also repairs confirmed members. S5 routes `catchup_beyond_retention` to ADR 0114's retention re-Welcome (§7) and defines none itself (§4, §8).
- **Unreadable sidecar files (D120), against the recommendation:** automatic quarantine and rebuild. S5 follows ADR 0108 §5a's shared lifecycle and adds only its file names, its `X0GHE` header layout, S5's fetch as the rebuild source and its no-rebuild cases. This amends ADR 0085 rule 4 for S5's holder files only; rule 5 is not amended (§6).
- **Named §2 entries (D118):** David confirmed "#946 legacy refusal" as a named ADR 0088 §2 entry (§8).
- **End date of the D96 and D68 exceptions (D125):** set in a later ruling. Until then neither exception has an end date (§3a, §8).
- **The joiner's 120 s timeout cause (D117):** ADR 0108's `JoinPendingNotice` (its §8). S5 owns the `evidence_pending` cause registered there, and that cause rides the notice (this ADR's §8).

David ruled round 3 on 2026-10-04 (D148, D157, D158):

- **What the promotion chain shows the joiner (D157):** accepted. J receives the chain only after its add is sealed, and it includes every commit from J's invite base to the predecessor, other changes included (§5).
- **Q11, rebuild attempts per holder file (D158):** once per file per run. A failed rebuild waits for the next daemon start (§6).
- **Q12, retention of holder quarantine copies (D148):** ADR 0108 §5a's retention rule applies. A copy is kept until an operator removes it or its group's own files are deleted, and diagnostics list each copy with its size (§6).

No question is still open. Q9 is ruled (D133, D157), Q11 (D158) and Q12 (D148). Q10 is withdrawn: ADR 0112 §1 already defines the invite that binds only the root (D95 above).

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human review**. Only David Irvine marks it Accepted. Accepted ADRs are immutable: create a new superseding ADR rather than editing an Accepted ADR.
