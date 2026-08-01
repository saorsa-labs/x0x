# Grounding for ADR 0028: Authenticated Causal-Predecessor Delivery

- **Status:** Frozen proposal grounding
- **Frozen:** 2026-08-01
- **Decision:** [ADR 0028](../adr/0028-authenticated-causal-predecessor-delivery.md)
- **Reference implementation:**
  [join and roster propagation](../design/groups-join-roster-propagation.md)
- **Evidence union:** `0bf0da5b9c8a1a58594c027c0f472ad7c7ddf55d`
- **Evidence tree:** `da690e07e6e4822bd971b6be290afbc2d68b7d7e`
- **Preserved run:** `/tmp/x0x-union-runs/1785594802/`
- **Independent review:** Dario, conditional PASS at `d904cba7` / tree
  `131336d7`; all measurable claims in that revision reproduced

This record freezes the facts used to propose ADR 0028. Repository citations
below resolve at the evidence union unless a different pin is stated. Mutable
mechanisms, constants, pseudocode, and rollout policy belong in the linked
reference chapter, not here. Citation ranges end on the final content line of
the cited construct and omit an immediately following closing delimiter.

## G-001 — The complete family stopped at 3 passed / 2 failed

The preserved `family-stdout.log` records one complete serial run of
`tests/active_recipient_sealing_gates.rs`:

```text
test result: FAILED. 3 passed; 2 failed; 0 ignored; 0 measured; 0 filtered out; finished in 280.16s
```

The failed rows are:

- `active_recipient_production_gate_and_predicate_reversion_mutation`; and
- `removed_member_recipient_not_active_and_persisted_state_pin`.

Both stop at the unchanged R2 barrier because Bob's authenticated members
view does not contain both Bob and Charlie within 30 seconds before the admin
delete. The other three rows pass. The run directory holds 16 non-empty files:
one 4,070-byte family output and 15 daemon logs, one Alice/Bob/Charlie set for
each row, ranging from 1,718 to 3,563 bytes.

Supports: Context, the scope of the Decision, and Validation control 6.

## G-002 — Bob lacks Charlie's requester-authored predecessor

The two failed rows have identical relevant event populations. In each row,
Alice records two `apply_metadata_event_entry` events for
`join_request_created`; Bob records one. In row PID `31458`, Alice's two
request senders are:

```text
ec1d451b89b5de15d07c79aedb531798ece46fc4965ef4593e29577a52a803c3
810a255792b14105b7d2add59460600790645129ec652ed2675dd7dcc23c30eb
```

Bob records only the first sender—his own request—and no
`join_request_created` apply entry for the second requester, Charlie. Row PID
`29750` has the same count split. Bob imported the group card before either
request, so there is no independent path that can populate Charlie's pending
request locally.

Evidence files:

- `/tmp/x0x-union-runs/1785594802/test-alice-31458.start.log`;
- `/tmp/x0x-union-runs/1785594802/test-bob-31458.start.log`;
- `/tmp/x0x-union-runs/1785594802/test-alice-29750.start.log`; and
- `/tmp/x0x-union-runs/1785594802/test-bob-29750.start.log`.

Supports: Context and the need for predecessor delivery.

## G-003 — Approval transport is no longer the missing property

Bob's PID `31458` log records four
`direct_classified_metadata_event` / `apply_metadata_event_entry` pairs for
`join_request_approved` after the active-member fan-out repair. The same four
direct pairs occur in PID `29750`. Bob also records a gossip-side approval
entry, so total apply-entry counts must not be mislabeled as direct receipts.

The receiver trace does not identify a direct receipt as the immediate or the
delayed scheduled attempt. The four direct pairs are consistent with two
approvals and two scheduled deliveries per approval, but that split is an
inference from source shape and timing, not a trace fact.

The non-TreeKEM approval producer publishes the signed approval and then
directly plus delayed-delivers it to every non-local active member and the new
requester (`src/server/routes/named_groups.rs:11182-11215`).

Supports: rejecting a timeout-only or approval-only correction.

## G-004 — The request producer has no active-witness delivery path

`create_join_request` constructs `JoinRequestCreated` and publishes it only to
the metadata topic (`src/server/routes/named_groups.rs:10985-10996`). The
computed `creator_hex` is explicitly reserved for a future direct notification
and is otherwise unused (`:10971-10975,10997`). No request-side sibling of the
active-member approval fan-out follows the publish.

Metadata pubsub messages are origin-authenticated V2 envelopes. Their signature
binds the origin AgentId, topic, and exact payload, and verification derives the
AgentId from the embedded ML-DSA-65 public key
(`src/gossip/pubsub.rs:1013-1053,1082-1139,1161-1206`). Re-publishing decoded
JSON under an authority's identity would therefore authenticate the authority,
not the requester.

Supports: the origin-preserving authenticated-relay requirement.

## G-005 — Apply correctly requires the signed causal predecessor

The `JoinRequestCreated` arm requires the authenticated sender to equal
`requester_agent_id`, requires `RequestAccess`, rejects active/banned/duplicate
requests, applies the `NonMemberRequest` state commit, records the pending
request, and persists the new state
(`src/server/routes/named_groups.rs:5472-5559`).

The `JoinRequestApproved` arm first authenticates an active admin actor, then
requires `info.join_requests[request_id]` to exist, remain pending, and name the
same requester before it validates and applies the authority commit
(`src/server/routes/named_groups.rs:5561-5655`). With Charlie's request absent,
Bob returns before roster mutation. This is the intended fail-closed behavior.

The common state apply verifies commit structure, exact group, monotonic
revision, and equality between the commit's `prev_state_hash` and the
receiver's current `state_hash` before authorizing the signer
(`src/groups/state_commit.rs:676-747`; call site
`src/server/routes/named_groups.rs:2060-2080`). The state commit carries the
signer public key and verifies that it derives `committed_by`
(`src/groups/state_commit.rs:355-375,454-496`).

Supports: preserving both requester authentication and the signed state chain.

## G-006 — The state commit alone is not the complete request-payload proof

The signed roster root intentionally excludes `Pending` entries and includes
only `Active` and `Banned` members
(`src/groups/state_commit.rs:68-99`). `GroupInfo::state_hash` composes that
roster root with policy, public metadata, revision, previous hash, security
binding, and withdrawal state (`src/groups/mod.rs:464-480`). Consequently, the
requester's `GroupStateCommit` proves author, chain position, and committed
state, but the current pending-request fields are also protected by the
origin-signed V2 pubsub payload.

An authority relay must therefore preserve and re-verify the original signed
envelope (or an equivalently complete requester signature over the canonical
request payload). Relaying decoded fields and trusting the authority as their
author would not satisfy the tampered/wrong-request control.

Supports: Decision and Validation control 4.

## G-007 — The existing gap machinery does not cover this predecessor

`treekem_state_frontier_gap_reason` returns `None` for every non-TreeKEM group
before evaluating revision or state-hash gaps
(`src/server/routes/named_groups.rs:2531-2566`). Its queue admission for
`JoinRequestApproved` additionally requires a locally pending request and
TreeKEM commit/epoch fields
(`src/server/routes/named_groups.rs:2457-2528`). The missing predecessor is
therefore neither classified nor recoverable through the current frontier log.

Supports: choosing a narrow request-access causal queue instead of claiming
the TreeKEM mechanism already solves the problem.

## G-008 — Request ancestry is not state-chain adjacency

In the failed PID `31458` row, Alice's observed order is request(B), approve(B),
request(C), approve(C), with the middle events 58 milliseconds apart. That
interleaving makes each captured approval adjacent to its matching request, but
it does not establish adjacency as a valid mechanism rule.

`GroupInfo::seal_commit` sets a new commit's `prev_state_hash` from the
authority's last committed `state_hash`, after all earlier stateful events
(`src/groups/mod.rs:525-535`). Apply independently requires that signed value
to equal the receiver's current state hash
(`src/groups/state_commit.rs:701-712`), and finalization advances the receiver
to the commit's signed state (`src/groups/mod.rs:661-669`). Therefore a queued
approval must be retried after state advances; its matching request need not be
the immediately preceding commit.

Supports: the non-adjacent drain rule and the batched multi-request control.

## Artifact manifest

SHA-256 values freeze the 16 files inspected under the preserved run directory:

```text
3cc53d69ead2723d1183d02c55d5b739717c8192bb2acd0add6f97983692822a  family-stdout.log
7dcfb01bad863480901cd069772b7a09732fbe04e23d0ece6fbac67f7638b54f  test-alice-16258.start.log
7729d21aaa347aa4785a248f086ee486cce7c721787a3baddffedf53453ae6b9  test-alice-21937.start.log
95fc43f1c812920aee4138a5ff18d82ab90960270b65055d1fba89e0b2e498ec  test-alice-29750.start.log
487d9adc4508cd61237fc637c849d443fbc5a304a8364f991e40e6ec70bb36ad  test-alice-31458.start.log
0d0778d66a801645822440e1fa6440988ab9cd8590c4f1d4657a409f857441a3  test-alice-59693.start.log
5aefcfc47e9ca773a5ad9eda9d516f76be9489121c8de50d2d0a9b4bf4199d43  test-bob-16258.start.log
010ccb6bc36318104127a448139ee253038d5ed5cdef386d3ed0d706a073cf5d  test-bob-21937.start.log
e6149132989fd4277ff2fcf4f90813704bd0b99cfc9834d0ada95ca6df66bafc  test-bob-29750.start.log
5ccf1fd2cd24a2f2f75a1d3ef6a1fbddd1fb9740bcdab50607a674fd646a6e88  test-bob-31458.start.log
4e08fbc84732dbe0c8030c86430c94f6d83f99f72f2eedfefabc4471a4c487a6  test-bob-59693.start.log
2c78ee087fec9f528138898fabe2bdb6791052a32d88e6af3ab1fca6fdbc81f9  test-charlie-16258.start.log
8ea44218599e0179f75310931034516f8381b31d0664557d789ac229e1a9871a  test-charlie-21937.start.log
126ea202859406e7064d696e8e9b844f4d08cc95b4e0a4528e7ebdbe3bf4f0d0  test-charlie-29750.start.log
4d9320f7a6899d73a2a8b67062fa0ce13d7423b8a44a4869055e6e7434827005  test-charlie-31458.start.log
69dc0f565f329ff9f717378184e54257e9dc87cb86905de89309ced22e107cdc  test-charlie-59693.start.log
```

## G-009 — Scope and non-claims

This evidence establishes one non-TreeKEM request-access causal-delivery gap on
the exact union and preserved run above. It does not establish that every
approval receipt was immediate or delayed, that a finite retry schedule can
cross an indefinitely long partition, or that the current TreeKEM gap log
should become a general event log. It also does not authorize removal of the
pending-request check or acceptance of an authority-authored substitute for a
requester-authored predecessor.

In both failed rows, the Alice and Charlie logs share one byte-identical
`join_request_created` trace line, including its microsecond timestamp. Bob's
log shares no such line. This unexplained attribution oddity does not affect
the Alice-versus-Bob population claims above, but implementation validation
must not assume every preserved filename proves a strictly independent trace
source without additional process evidence.

The proposal is not accepted and no production, testnet, deployment, push, or
pull-request action is grounded by this record.
