# Forward openers known only from evidence (#1107)

Status: implemented on the branch for this change. Authority: A03
amendment of 11 Nov 2026.

## Problem

A receiver admits an attested forward (`ForwardV2`) only when its
discovery cache holds the opener's agent. After the receiver restarts, or
before the opener's identity announce reaches it, the cache is empty. The
stream was then refused at dispatch (`deny_not_verified`), and the forward
gate refused with `agent_not_in_discovery_cache` (now
`agent_not_in_discovery_cache_or_evidence`). This held even when the
receiver's evidence store already had a verified record and certificate for
that agent, and owner trust already reads that store.

## Rule

On a discovery-cache miss, the forward gate may take the opener's machine
and certificate from a usable ADR 0089 evidence record. All of these must
hold:

1. The stream proves the agent key. The `ForwardV2` header is signed by the
   key that hashes to the agent ID, over bytes that bind this recipient
   machine and a fresh time. A machine-signed announce alone is never
   enough, because any machine can claim any agent.
2. The record names the transport-authenticated peer machine.
3. The certificate verifies, is current, chains to the local owner, and no
   agent, machine or owner revocation applies at the time of the check.
4. The record came through EvidenceV1 admission (a related peer or the
   bounded pool), and the store's point-of-use check (`usable`) passes.

An opener found this way is admitted for owner trust only. Contact rules
and share grants still need the discovery path. The ShareGrant path is
denied for evidence-source openers at the `authorize_attested_opener` gate
(`src/forward.rs`).

The gate writes nothing to the discovery cache, the authenticated binding
registry or the capability registry. It does not cache the result. The
existing rule stays: those registries are never seeded from evidence.

## Code

- `src/forward.rs` `opener_view`: discovery cache first, then the evidence
  store. Both `decide_inbound_attested_with_authority` and
  `authorize_attested_opener` use it. The re-check on a live stream uses the
  nonblocking store read and reports `Busy` when the store is contended.
- `src/lib.rs` `route_enrolled_owner_sync`: an enrolled owner machine with
  no known agent may now open `ForwardV2` as well as `SyncV1`. The stream
  goes only to the forward acceptor, whose gate applies the rule above.
  Other stream kinds stay denied.
- `src/forward.rs` `spawn_stream_handler`: that stream carries no agent; its
  admission slot is keyed by the machine. Any other agentless stream is
  still reset.
- `src/forward/teardown.rs` `reevaluate`: for an attested inbound stream
  from a machine with no agent in the discovery cache, the machine-level
  gate is skipped (it has nothing to check and would deny). The forwarder's
  gate re-reads the evidence record and re-checks owner trust and every
  revocation, so the stream is torn down when the record stops being usable
  or a revocation applies.

## Opener side

No new message. On every new connection to a related peer the opener
already sends its EvidenceV1 Hello (announce and capability advert). The
receiver reports whether it holds the certificate; on a miss the opener
sends it in a CERTIFICATE continuation. The Hello runs at most once per
peer per 60 s (`HELLO_INTERVAL`), not once per certificate. A failure
there never blocks the open: the forward is then decided as before this
change.

## SyncV1

Not changed. The SyncV1 `Proof` is a signature by the owner key, not by an
agent key, so rule 1 does not hold. An enrolled machine with no known
agent is still admitted for SyncV1 on its enrollment (#1040).

## Mixed versions

No wire change. A released receiver keeps refusing the forward until it
sees the announce, as before. A released opener is admitted by a new
receiver when the receiver holds its evidence.

## Tests

`src/peer_evidence_forward_opener_tests.rs`: admitted from evidence with an
empty cache (registries stay empty); denied, with the reason asserted, when
the header is not signed by the agent key, when the transport machine is
another enrolled machine, when a discovery entry names another machine
(not overridden), when the agent, the machine or the binding is revoked,
when the certificate expires after ingest, and when it is from another
owner. `src/forward.rs`: an enrolled machine with no known agent that is
revoked before the header read is dropped without a panic; and
`forward_from_evidence_only_opener_survives_registration_reauth` drives the
real path (enrollment routing, acceptor, `handle_inbound`, registration and
its reauth pass) with an empty discovery cache, checks bytes still flow
after the reauth, and checks that revoking the opener tears the stream
down. Without the `reevaluate` change that test fails. `src/owner_trust/tests.rs`: `ForwardV2` from an enrolled machine
with no known agent reaches the forward acceptor; a machine that is not
enrolled gets nothing.
