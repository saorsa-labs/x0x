# T-relay-refuse-unsigned-inner-v1: Refuse unsigned messages at relay ingress

- **Status:** Proposed
- **Target slot:** A06
- **Date:** 2026-10-17
- **Decision owners:** David Irvine
- **Reviewers:** pending
- **Supersedes:** none
- **Related:** issues #1114, #1225 and #1226; charter I3 and I12
- **Requirement:** R6, agents collaborate across machines; supporting goal E

## Context

A valid outer gossip signature identifies the forwarding machine. It does not
prove that the inner message has an author signature. Issue #1114 prevents an
unsigned inner V1 message from reaching a local subscriber. A relay can still
forward that message or advertise its identifier for later retrieval. This
spends relay capacity on traffic that the destination must refuse.

This proposal extends that refusal to relay ingress. It does not add a wire
version, change a signed message, or change an acknowledged delivery obligation.
The separate #1225 change removes unsigned publication from the SDK.

## Proposed decision

The composite topic validator must return `Drop` when the inner payload decodes
as unsigned V1. Apply this check before content validators and relay fan-out
budgets, after the existing outer signature checks. Use the same validator for
normal ingress and frames replayed after outer-key recovery.

The classifier follows the inner decoder's dispatch. A leading byte of zero or
one selects V1. Its two-byte topic length must fit within the payload, and the
topic must be valid UTF-8. Empty topics and empty message bodies are valid V1
shapes and are refused. Signed V2/V3 prefixes and unsupported versions never fall
back to V1. Existing handling of other malformed envelopes stays in place.

A refused message must not reach local delivery, eager forwarding, IHAVE
advertisement, IWANT retrieval, or anti-entropy serving. The existing gossip
cache may retain its identifier for duplicate suppression, marked as refused.
Do not remove this marker and permit repeated forwarding attempts.

Expose `relay_fanout.unsigned_inner_v1_dropped` on `GET /diagnostics/gossip`.
This process-local counter counts validator refusals after outer admission.
Duplicate cache hits and frames rejected earlier do not increment it. It resets
on restart. It adds a reason to the existing total validator-drop counter.

## Alternatives and consequences

Keeping the subscriber-only check avoids a relay change but wastes bandwidth.
Checking only the outer signature permits this attack because the attacker can
sign with a machine key. Re-verifying all inner signatures at every relay adds
work beyond this fix.

This change uses a bounded topic-length check without copying the payload. Valid
signed traffic keeps its existing delivery and relay policy. It does not claim
a measured fleet saving or complete inner-signature enforcement at relays.

## Validation and acceptance

Pure tests cover version dispatch, malformed lengths, UTF-8, and refusal before
fan-out or content work. An isolated wire test must prove no eager or lazy
forwarding or later IWANT service. Same-ID duplicates count once. Rewrapping the
same rejected bytes under a fresh ID must not restore service (saorsa-gossip
#116). Signed
V2 and V3 controls must still pass on subscribed and relay-only topics.

David must decide this Proposed record before the relay policy and diagnostic
API are treated as accepted. The upstream replay fix must reach the pinned
dependency before this implementation is complete. Keep the consolidated pack at 15. Do not fold this
record or change an Accepted ADR in this work.
