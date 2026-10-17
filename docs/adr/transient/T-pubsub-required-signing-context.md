# T-pubsub-required-signing-context: require an author for pub/sub

- **Status:** Proposed
- **Date:** 2026-10-17
- **Target slot:** A06
- **Requirements:** R6 (agents collaborate across machines), goal E (efficient communication)
- **Issue:** [#1225](https://github.com/saorsa-labs/x0x/issues/1225)
- **Supersedes:** None. This closes the remaining unsigned publish path after #1114.

## Context

A pub/sub frame has two authentication layers. The outer PlumTree frame
identifies a transport sender. The inner x0x envelope identifies the agent
that wrote the message. A valid outer signature does not supply a missing
inner author.

Issue #1114 removed unsigned inner V1 delivery to applications. However,
`PubSubManager` still accepts an absent signing context and emits inner V1
when that caller publishes. The daemon already supplies an author context.
The remaining callers are tests, the dispatch benchmark, and Rust embedders.
Their unsigned traffic consumes resources even though no x0x subscriber can
deliver it.

The issue assigns this public constructor change to the v0.47 train. This
record describes the API follow-up and does not change a version or claim
that a released artifact includes it. The CHANGELOG entry stays Unreleased.

## Decision

Require `Arc<SigningContext>` in each public `PubSubManager` constructor and
in `GossipRuntime::new`, which constructs that manager. Store the context
without an `Option`. A caller must identify the author before it can obtain
a manager. Remove the unsigned branch from the common network publish path.
A signing or encoding failure returns the existing error and never falls
back to V1.

Ordinary network publications keep the existing signed inner V2 format.
The explicit Signed KV V3 publisher keeps its current format and adoption
gates. Same-daemon `local:` topics still bypass PlumTree and return no wire
envelope. Their sender comes from the required local context.

Retain the V1 decoder and rejection tests. Keep its encoder only in test
builds so hostile input can still reach the actual receive guards. Relay
ingress policy is a separate issue, #1226, and is outside this change.
No outer format, transport, persisted format, dependency, or compatibility
grant changes.

## Alternatives and consequences

A typed publish error with optional construction would also stop emission.
Required construction gives every publishing method the same guarantee and
makes an absent signer a compile-time error. It requires source migration
for Rust embedders, including callers that only subscribe. Existing signed
callers pass their context directly instead of wrapping it in `Some`.

Do not weaken a test by discarding its unsigned attack input. Inject that
input below the public publisher and retain the rejection counter and signed
positive control. The dispatch benchmark must use signed inner and outer
frames, with an explicit Full participant, to reach relay processing.

## Validation

Compile all targets and the benchmark. Compile-fail examples cover each
constructor without a signer. Capture a real outbound EAGER frame and verify
its inner author, signature, topic and payload. Retain V3, local delivery,
unsigned rejection, revocation, fan-out and subscriber lifecycle tests.
Run network-capable tests only in the existing Linux isolation boundary.
Record unsupported-host refusals as missing evidence, never as a pass.
