# communitas#11 — first message after join (proof)

**Date**: 2026-04-29
**Branch**: `fix/communitas-11-first-message-after-join`
**Test harness**: `tests/e2e_first_message_after_join.sh`

## Symptom

When Bob joined a `SignedPublic` named group via invite, the very first
message Alice sent was permanently lost on Bob's daemon. Subsequent messages
arrived normally. This is the modern equivalent of the original
saorsa-gossip-stack MSG-005 race that communitas#11 was filed against on
2026-02-05.

## Root cause

`spawn_public_message_listener` (subscribes to
`x0x.groups.public.<stable_id>`) was only invoked from
`POST /groups/:id/send` (sender-side pre-subscribe) and
`GET /groups/:id/messages` (reader-side poll-triggered). Neither
`create_named_group`, `join_group_via_invite`, `import_group_card`, nor the
daemon-startup persistence-load path called it. While Bob's daemon was
unsubscribed, Plumtree-routed messages arrived at his pubsub layer and were
dropped because no subscriber existed. Plumtree cannot backfill messages on
a topic that had no subscriber at receive time, so the first message was
gone for good — only Bob's first `GET /messages` poll spawned the listener,
and it could only catch *future* messages.

## Fix

A new helper `ensure_named_group_listeners` spawns both the metadata listener
*and* the public-message listener (gated on `confidentiality != MlsEncrypted`,
matching the GET-handler convention). All four group-insertion sites in
`src/bin/x0xd.rs` now call this helper instead of the metadata-only spawner:

| line  | site                               |
|-------|------------------------------------|
| 1268  | daemon startup — load persisted    |
| 6588  | `create_named_group`               |
| 7243  | `join_group_via_invite`            |
| 9115  | `import_group_card`                |

## Pre-fix evidence (`prefix-results.csv`)

`build/repro_group_first_message.sh` against unfixed `x0xd 0.19.8`,
2 trials × 3 delays:

| delay (ms) | trials | bob_saw |
|-----------:|-------:|--------:|
|          0 |      2 |       0 |
|        500 |      2 |       0 |
|       2000 |      2 |       0 |
| **total**  | **6**  | **0**   |

`alice_saw=1` in every trial — proves the publish path is sound and the
loss is purely on the receiver.

## Post-fix evidence (`postfix-results.csv`)

Same harness, fixed `x0xd`, 5 trials × 5 delays:

| delay (ms) | trials | bob_saw | rate |
|-----------:|-------:|--------:|-----:|
|          0 |      5 |       5 | 100% |
|        100 |      5 |       5 | 100% |
|        500 |      5 |       5 | 100% |
|       2000 |      5 |       5 | 100% |
|       5000 |      5 |       5 | 100% |
| **total**  | **25** |  **25** | **100%** |

## Regression test

`tests/e2e_first_message_after_join.sh` — fails pre-fix, passes post-fix
(20/20 across 0/100/500/2000 ms delay buckets in CI mode).

## Quality gates

- `cargo fmt --all -- --check` — clean
- `cargo clippy --bin x0xd --all-features -- -D warnings` — clean
- `cargo nextest run --all-features --workspace` — 1030/1030
- `cargo nextest run --all-features --test named_group_integration --run-ignored all` — 23/23
