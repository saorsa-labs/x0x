# Signed KV legacy compatibility: preparation and holds

Status: **disabled; preparation only** (`enabled = false`), 2026-09-06. There is no operator
activation endpoint or configuration switch in this patch. See
[proposed ADR-0063](adr/0063-signed-kv-legacy-gossip-compatibility-adoption-boundary.md).

## What is available

`PubSubManager::publish_signed_kv_v3(topic, payload)` signs and publishes inner
version `0x03`, returning the original envelope. It requires a signing context
and refuses `local:` topics. `decode_signed_kv_v3(bytes)` strictly authenticates
that format; `decode_auto` dispatches `0x03` to it without fallback. These APIs
do not register topics or grants. KvStoreSync and ordinary publishers are not
switched to them in this preparation patch. Routing Signed KV through these
APIs is part of the pending G3 receive/apply and registration audit.

The preimage is `x0x-msg-v3 || author[32] || topic_len:u16be || topic || payload`.
The length is in bytes; payload consumes the remainder. Relabeling V2 cannot
produce V3. Ordinary V2 traffic remains V2; it is not eligible for the new
facility. V3 enforces the gossip verifier's 1 MiB envelope ceiling, 1952-byte
public key and 3309-byte signature. Unsigned V1 topics are limited to 511 UTF-8
bytes: high bytes `0x02` and `0x03` dispatch to signed formats; `0x04`–`0xff`
are rejected as unsupported versions, never retried as V1. This deliberately
rejects historical long V1 topics to reserve unambiguous version dispatch.

## Publication audit and bump strategy

Gossip [#48](https://github.com/saorsa-labs/saorsa-gossip/pull/48) merged at
`5307e59270b2eead28e948b2206cf8cc04f149d5`, branch tip
`4340773c38b688a674a313ff99ba22445083fffc`. G0 is MET only.

The workspace at that merge declares **0.5.75**. The registry's existing
[pubsub 0.5.75](https://crates.io/crates/saorsa-gossip-pubsub/0.5.75) and
[transport 0.5.75](https://crates.io/crates/saorsa-gossip-transport/0.5.75)
were published on August 27. Downloaded archive metadata identifies
`6e17f02047017f07f8aa1d82052cdeb2409dfbf1` with `dirty: true`; their source lacks
`AuthenticatedSession`, `handle_authenticated_message` and the V3 verifier.
**Do not bump to registry 0.5.75 and claim #48 adoption.**

Published [ant-quic 0.27.48](https://crates.io/crates/ant-quic/0.27.48) identifies
`79ec79158455c8084bc994ecfb338372ad60a89a` and lacks `recv_with_generation` and
`current_connection_generation`. A tag/version alone does not satisfy G1.
Current Cargo.toml requirements (`gossip 0.5.74`, `ant-quic 0.27.47`) and the
lockfile are retained. The existing lockfile already resolves registry gossip
`0.5.75` and ant-quic `0.27.48`; neither contains the required facility. **Gossip release bump HOLD; ant-quic G1 bump HOLD.**

Selected strategy: **wait for a verified 0.5.76 or later publication containing
#48**; this draft retains the current dependencies. No draft git pin is active.

For a separate reproducible integration branch before publication, pin **all
11** direct gossip crates to the same merge revision using this pattern:

```toml
saorsa-gossip-pubsub = { git = "https://github.com/saorsa-labs/saorsa-gossip", rev = "5307e59270b2eead28e948b2206cf8cc04f149d5" }
```

Apply it to coordinator, crdt-sync, groups, identity, membership, presence,
pubsub, rendezvous, runtime, transport and types. Commit the resulting lockfile;
inspect `cargo tree` for duplicate registry/git type universes. Do not mix git
pubsub with registry transport/types. A path experiment must instead use a
separate clean checkout at that exact SHA and coherent `[patch.crates-io]`
entries for the whole family, with the checkout SHA recorded; machine-local
paths are not a publishable dependency strategy. Neither strategy is activated
by this PR or counted as G4. Once a new registry release actually contains #48,
verify archive source/checksums, pin the coherent family and rerun exact-tree
gates. Do not invent the future version.

## Acceptance ledger

| Gate | State | Remaining evidence |
| --- | --- | --- |
| G0 | MET | Library merge #48 at `5307e592` only |
| G1 | OPEN / HOLD | Published ant-quic reader/pre-auth generation stamping, live-generation and pinned-send contract with reconnect/reuse tests |
| G2 | OPEN / HOLD on G1 | End-to-end receive tokens into `handle_authenticated_message` and guarded egress; no post-dequeue lookup |
| G3 | OPEN | Signed-only exact-topic registration, V3 publication routing, receive/apply audit, owner/state-request checks, floor policy, grants, audit/counters; default false |
| G4 | OPEN / HOLD | Published #48-containing gossip and G1 ant-quic; complete bumped tree green |
| G5 | OPEN | Real-daemon fail-closed, spoof/expiry/queue tests and measured verification/relay overhead |
| G6 | OPEN | Both authentic v0.30.1 mixed-version phases, original predicates/deadlines, both directions |
| G7 | OPEN | Unchanged ten-run convergence on exact candidate binaries; hashes and resolved dependencies |
| G8 | OPEN | David's explicit enablement decision |

Local tests compare canonical preimage bytes and verify production signatures
with the resolved gossip identity crypto API, including matching author IDs.
They do **not** run #48's `SignedKvTopic` verifier: it is absent from the
resolved registry pubsub crate. That actual pubsub integration test, with
exact-topic and roster admission, remains a G4 exit requirement.

The H1 profile requires a patched `+signed-kv-inner-v3` receiver. It does not
prove stock v0.30.1 compatibility. Keep that distinction in G6 evidence;
never replace the authentic binary with a patched one and call the gate green.
No timeout padding, weakened predicate or library-fixture substitution.
#515 stays DRAFT. No tag, deploy, live-daemon action, or #530/#531/#274 work.
