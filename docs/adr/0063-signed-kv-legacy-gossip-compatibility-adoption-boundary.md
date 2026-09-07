# ADR 0063: Signed KV legacy gossip compatibility adoption boundary

- **Status:** Proposed (draft; not accepted)
- **Date:** 2026-09-06
- **Decision owner:** David Irvine
- **Reviewers:** Pending
- **Supersedes:** None
- **Related:** x0x #517, #515; saorsa-gossip #46, [#48](https://github.com/saorsa-labs/saorsa-gossip/pull/48), [ADR-013](https://github.com/saorsa-labs/saorsa-gossip/blob/5307e59270b2eead28e948b2206cf8cc04f149d5/docs/adr/ADR-013-explicit-legacy-gossip-egress.md)

## Context

Gossip #48 merged at `5307e59270b2eead28e948b2206cf8cc04f149d5`
(branch tip `4340773c38b688a674a313ff99ba22445083fffc`). This satisfies
library gate G0 only. Its disabled compatibility facility requires receive
connection provenance, guarded egress and a paired x0x V3 inner envelope.
Stock x0x V2 signs `topic || payload` without the topic length: moving the
boundary between `T` and `T/state-sync` can preserve the signed bytes.
A library merge does not prove x0x receive/apply or mixed-version acceptance.

## Decision drivers

- Authenticate the topic boundary and retain the original author's signature.
- Admit only explicitly audited Signed KV topics, authors and receiver profiles.
- Keep connection provenance through every queue hop and fail closed on reconnect.
- Separate preparation, implementation, acceptance and human enablement.

## Considered options

1. Reinterpret V2 as V3: rejected; the V2 topic boundary is ambiguous.
2. Switch every publisher to V3 now: rejected; stock receivers cannot consume it.
3. Add explicit V3 pairing APIs, then adopt them through audited Signed KV
   registration after the transport prerequisites: selected.

## Decision

Reserve inner byte `0x03` for a signed V3 envelope. Its wire fields are:

```text
0x03 || author[32] || key_len:u16be || key || sig_len:u16be || signature
     || topic_len:u16be || topic || payload[remainder]
```

The ML-DSA-65 preimage is exactly:

```text
x0x-msg-v3 || author[32] || topic_len:u16be || topic || payload[remainder]
```

The topic length counts UTF-8 bytes. Payload is terminal; extensions require a
new version with a length-prefixed payload. V3 limits the full envelope to
1 MiB, public keys to exactly 1952 bytes and signatures to exactly 3309 bytes.
Author identity must derive from the embedded public key. Strict
V3 decoding rejects V2, unknown versions, relabeled signatures, malformed
fields and invalid signatures. There is no V2 fallback for this facility.
Unsigned V1 has no version tag. Generic dispatch accepts V1 only for leading
`0x00`/`0x01`; `0x04`–`0xff` are unsupported versions. Its encoder limits
topics to 511 UTF-8 bytes. This rejects historical longer unsigned topics.
A stock decoder can interpret `0x03` as a V1 length and rely on accidental
UTF-8 failure to reject key bytes; the paired build explicitly closes that path.

The preparation adds `PubSubManager::publish_signed_kv_v3` and
`decode_signed_kv_v3`. Publication requires signing and a network topic;
verification does not establish store authorization. Existing generic
publishers and KvStoreSync callers remain on V2 until the adoption audit.
Generic reception dispatches V3 to the strict verifier. V2 remains explicitly
V2 on ordinary traffic. No automatic version negotiation or legacy grant is
inferred from a received envelope.

The future compatibility registration covers only exact concrete topics of
`AccessPolicy::Signed` stores: the delta/full-state topic `T` and its
`T/state-sync` topic. No namespace wildcard; no registration of Allowlisted,
Encrypted, AppendOnly, SelfKeyed, presence, membership, DM or group traffic.
Preserve Signed writer/owner authorization, owner-announce checks and the
state-request receive/apply checks. Known author rosters and positive verifier
revisions must reflect the audited paired build.

The required receiver profile is
`x0x/0.30.1+signed-kv-inner-v3;saorsa-gossip-pubsub/0.5.66`.
This names a required patched profile, not an existing accepted release.
Its pubsub `0.5.66` component does not identify code containing #48; upstream
profile revision and a fresh audit remain necessary before grants can be used.
Stock v0.30.1 is ineligible. Authors must re-sign V2 data; relays forward the
inner bytes verbatim. Fresh audit, verifier revisions and grants are required.

`enabled = false` remains the default. Only explicit local operator policy may
issue finite, session-bound, exact-topic grants with issuer/reason and
monotonically increasing revisions. No grant survives a reconnect or restart.
Missing/corrupt/rolled-back floor journals, expired/revoked grants, stale
sessions and `RejectV1` must fail closed. No reset-floor or auto-enable surface.
Leaf pass-through refusal and existing timeout/admission controls stay intact.

Inbound `AuthenticatedSession` must be constructed from the generation stamped
by ant-quic on the actual reader connection, including pre-auth buffer entries,
and carried through every queue. A lookup of the current peer connection after
dequeue cannot establish provenance. Guarded egress must pin the selected
connection, revalidate after waits and stream allocation, and never retry
selected legacy bytes on a replacement connection. G2 cannot close without G1.

## Consequences

The V3 primitives can be reviewed before transport publication, but do not
activate KvStoreSync or legacy compatibility. Older application receivers
need a paired patch and audit. Authentic stock-binary gates remain required;
where stock cannot consume V3, record the failure/hold without substituting a
patched binary or weakening the historical predicates. Registry gossip
`0.5.75` predates #48 despite the same workspace version. See the
[dependency strategy and gate ledger](../legacy-compat.md).

## Validation

Local pairing tests cover independent canonical preimages (including UTF-8),
production publication verified by gossip's crypto API, both-direction
`T`/`T/state-sync` boundary rewrites, V2 relabeling, malformed/truncated input,
author mismatch, terminal-payload tampering, size/shape bounds, default V2
publication, and signing/local-topic refusal. Crypto API verification and
canonical preimage fixtures are not execution of #48's `SignedKvTopic` verifier;
that integration is still blocked on G4.
Run the required ordered Rust gates on the exact pushed tree.

G0 is MET. G1–G8 are OPEN: published ant-quic provenance; x0x provenance and
guarded egress; policy/registration and receive/apply audit; complete dependency
bump; real-daemon efficiency/fail-closed gates; both authentic mixed-version
phases with original deadlines; unchanged ten-run convergence; David's explicit
enablement decision. Local tests close none of these acceptance gates.

x0x #515 remains draft. This ADR authorizes no merge, undraft, tag, daemon
operation, deploy or product work on #530, #531 or #274.

## Notes for AI-assisted work

AI-assisted draft. Only human review may mark this ADR Accepted.
