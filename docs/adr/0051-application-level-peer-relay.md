# ADR 0051: Peer Relay (X0X-0070) Is a Default-Off, One-Hop DM Fallback

- **Status:** Proposed
- **Date:** 2026-08-29
- **Decision owners:** David Irvine (direction), omp (drafting)
- **Reviewers:** pending
- **Supersedes:** none
- **Superseded by:** none
- **Related:** ADR-0011 and ADR-0021 (both cite X0X-0070 as existing); ADR-0034/0035 (relay role model). Backfill record for shipped behavior.

## Context

`src/peer_relay.rs` implements application-level DM relay (X0X-0070) that
ADRs 0011/0021 cite as precedent without any ADR deciding it. It wraps an
already-encrypted/signed `DmEnvelope` after direct delivery fails; the
relay forwards the inner envelope verbatim, one hop only
(`src/peer_relay.rs:1-27`).

## Decision Drivers

- Symmetric-NAT/no-inbound peers still need DM delivery.
- A relay must not be able to read, retarget, or substitute payload — and
  must not become an open forwarder.
- Shipping ahead of ADR-0035's role model must not pre-empt it.

## Considered Options

1. ant-quic MASQUE transport relay only.
2. Always-on relaying through bootstrap nodes.
3. Default-off, policy-gated, one-hop signed fallback for DMs (chosen).

## Decision

1. Fallback triggers on direct-delivery failure — default 3 failures in
   60 s — and relay envelopes older than 30 s are stale
   (`src/peer_relay.rs:79-89`).
2. A `RelayedDm` is `{header, inner: DmEnvelope}` — no nesting; the
   ML-DSA-signed `RelayHeader` binds version, destination/source agents,
   source public key, and timestamp, with full binding verification on
   `verify()` (`src/peer_relay.rs:125-205,227-252`).
3. Policy is fail-closed and **disabled by default**: enablement,
   contact-required forwarding, sender 10/min, global 100/min, 1 MiB/min
   caps (`RelayPolicy`, `src/peer_relay.rs:317-365`); refusals are
   explicit (`bad signature, stale, disabled, not contact, blocked,
   rate-limited, bandwidth exceeded`, `src/peer_relay.rs:255-283`) and
   quotas are reserved atomically before send
   (`src/peer_relay.rs:863-927,944-974`).
4. `select_relay` picks the first eligible candidate from a
   caller-prefiltered list (`src/peer_relay.rs:766-783`) — deliberately
   simpler than ADR-0035's spread selection, which remains the target
   model, not current behavior.

## Consequences

### Positive

- Reachability-challenged peers get DMs; the relay learns nothing and can
  alter nothing; abuse is rate-bounded.

### Negative / Trade-offs

- Default-off means the reachability win requires operator opt-in; relay
  path adds one signed hop of metadata exposure to the relay peer.

### Neutral / Operational

- Terminology: ADR-0034's `--relay` couples Full gossip participation with
  relay advertisement; ADR-0035's promoted relay may stay gossip-Leaf.
  This ADR concerns neither role policy — only the X0X-0070 fallback
  mechanism.

## Validation

- Unit tests over header verify/freshness, disposition gates, quota
  reservation, and failure-window state (`src/peer_relay.rs:708-764`).

## Notes for AI-assisted work

AI tools may draft this ADR but must not mark it Accepted without human
review. Accepted ADRs are immutable — supersede, don't edit.
