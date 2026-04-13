# Phase C.2 Proof Report — Distributed Discovery Index

> **Honesty clause.** C.2 landed the shard-based discovery code path and
> is well-covered by unit + integration tests. **Live end-to-end proof
> is incomplete**: positive cross-peer shard convergence was not
> demonstrated in any of the three archived e2e runs, the current
> `/groups/discover` endpoint is path-ambiguous due to dual-publish
> coexistence with the legacy bridge topic, and several positive-path
> claims (LTC delivery, AE repair, restart persistence) remain logic-
> tested only. C.2 is **not** presented here as "fully proven" or as
> "real discovery, proven in e2e." Proof-hardening tasks required for
> final signoff are tracked in
> [`.planning/c2-proof-hardening.md`](../../.planning/c2-proof-hardening.md).

## Scope of C.2

Implement partition-tolerant, DHT-free group discovery per
`docs/design/named-groups-full-model.md` §"Distributed Discovery Index":

1. **Shard computation.** Tag / name / exact-id shards via
   `BLAKE3(domain || lowercase(key)) % 65536`.
2. **Topic fan-out.** `PublicDirectory` groups publish to every
   relevant shard (one per tag up to `MAX_TAGS_PER_GROUP`, one per
   name word up to `MAX_NAME_WORDS`, exactly one exact-id shard).
3. **Privacy contract.** `Hidden` stays local; `ListedToContacts` goes
   to Trusted/Known contacts only via direct-message framing
   (`X0X-LTC-CARD-V1\n<card-json>`); `PublicDirectory` uses shards.
4. **Shard listener.** Verifies card signatures, supersedes by
   revision, evicts on withdrawal, defensively drops leaked
   non-PublicDirectory cards.
5. **Anti-entropy.** Periodic `Digest` emission (60s); `Pull`
   reconciliation on observed gaps.
6. **Subscription persistence.** Set in
   `~/.x0x/directory-subscriptions.json`; staggered resubscribe at
   startup (0–30s jitter).
7. **Four new endpoints**: `GET /groups/discover/nearby`,
   `GET /groups/discover/subscriptions`,
   `POST /groups/discover/subscribe`,
   `DELETE /groups/discover/subscribe/:kind/:shard`.

## What is actually proven

### Logic / unit / integration

- `src/groups/discovery.rs`: **20 unit tests** — shard determinism,
  topic format, tag normalise/dedupe/cap, name-word extraction,
  privacy gate for all three discoverabilities, cache supersession +
  withdrawal + LRU, search, digest determinism, pull-target
  correctness, message roundtrip, subscription CRUD.
- `tests/named_group_discovery.rs`: **18 integration tests** covering
  the same surface at the crate-public API level.
- `cargo nextest` full run: **582/582 pass, 1 skip**.
- `cargo fmt --all -- --check` clean, `cargo clippy --all-features
  --all-targets -- -D warnings` clean.

This covers correctness of the shard primitives, cache semantics,
AE digest/pull logic, privacy-gate functions, subscription JSON
round-trip, and signed-card verification. It does **not** cover live
cross-daemon shard-plane convergence.

### Negative privacy proofs (e2e)

Archived runs `tests/proof-reports/named-groups-c2-run{1,2,3}.log` do
demonstrate:

- Bad-kind subscribe rejected; valid subscribe returns shard+topic.
- `Hidden` group does NOT appear in bob's `/groups/discover` or
  `/groups/discover/nearby`.
- `ListedToContacts` group does NOT appear in bob's
  `/groups/discover/nearby`.
- `GET /groups/discover/subscriptions` returns the persisted count;
  `DELETE` lowers it.

These are all **negative** proofs (absence of leakage).

### What the archived runs did NOT demonstrate

- **Positive live shard convergence.** The "bob discovered
  PublicDirectory group via shard gossip" check logged `INFO` (not
  `PASS`) on all three runs — the 90s window elapsed without bob's
  `/groups/discover` surfacing alice's card. Pre-existing gossip-mesh
  timing on the local `--no-hard-coded-bootstrap` harness is the most
  likely cause, but we did **not** positively prove shard delivery.
- **Path attribution.** `GET /groups/discover` merges three sources:
  legacy `group_card_cache` (bridge topic) + `directory_cache` (shard
  cache) + locally synthesised cards. Even if bob had seen the card
  via this endpoint, we could not distinguish shard delivery from
  bridge-topic delivery. The daemon still dual-publishes on
  `GLOBAL_GROUP_DISCOVERY_TOPIC = "x0x.discovery.groups"` for
  back-compat.
- **LTC positive delivery.** We proved LTC does not leak to
  `/discover/nearby`. We did **not** prove that a Trusted/Known
  contact actually receives and caches the card via the direct-msg
  `X0X-LTC-CARD-V1` path, nor that an Unknown/Blocked peer fails to
  receive it.
- **Live anti-entropy repair.** The digest/pull logic is covered in
  unit + integration. We did **not** demonstrate a late subscriber
  missing the initial publish, then converging via digest/pull after
  subscription.
- **Subscription persistence across restart.** The JSON round-trip is
  logic-tested. We did **not** demonstrate subscribe → restart daemon
  → subscriptions restored → shard listener active after restart.

### Corrected run summary

The three archived runs have **91 assertions each, 59 pass / 32 fail
overall per run**. The D.3 section scored 18/18 and the C.2 section
scored 16/16 on every run; the 32 failures are in pre-existing
sections 2 / 5 / 7 (P0-1 public-request discovery timing, P0-6 patch
convergence, authz 404 checks) that also fail on pre-C.2 code on this
host. They are environmental, not C.2 regressions — but calling these
"three clean e2e runs" overclaimed. They are "three runs with the D.3
and C.2 sections clean; overall suite has unrelated pre-existing
environmental failures."

## Privacy enforcement (two-sided) — this much IS proven

| Plane | Publish-side guard | Receive-side guard |
|---|---|---|
| `Hidden` | `to_group_card` returns `None` | N/A — never emitted |
| `ListedToContacts` | `may_publish_to_public_shards() == false` skips shards; LTC direct-send fan-out to Trusted/Known | LTC listener accepts only LTC cards; shard listener drops LTC cards if they appear on public topic |
| `PublicDirectory` | `shards_for_public()` computes all shards | Shard listener verifies sig, supersedes by revision, evicts on withdrawal |

The publish-time and receive-time privacy gates are enforced in code
and exercised by unit tests (`may_publish_to_public_shards`,
`handle_directory_message` drop paths) plus the e2e negative-leak
checks above.

## Live paths using C.2 vs deferred

**Now using shards / C.2:**
- Every `publish_group_card_to_discovery` call for `PublicDirectory`
  groups fans to shards.
- Shard listener processes `Card`/`Digest`/`Pull` and updates local
  cache.
- ListedToContacts distribution via per-contact direct-message.
- `/groups/discover`, `/groups/discover/nearby`,
  `/groups/discover/subscriptions`, `/groups/discover/subscribe`.
- Daemon startup resubscribe from persisted set with staggered jitter.
- Legacy `x0x.discovery.groups` bridge topic **still dual-published**
  for back-compat. Deprecation/removal is proof-hardening / D.4 scope.

**Deferred / proof-debt** (see `.planning/c2-proof-hardening.md`):
- FOAF-weighted ranking in `/groups/discover/nearby`.
- Incremental digest/pull over the LTC contact channel (current path
  pushes full signed cards on each authority seal).
- Deprecation of the legacy bridge topic.
- A path-attributed discovery proof (e.g. debug endpoint tagging
  source = shard | bridge | LTC | local, or a bridge-disabled run).

## Honest label

**Phase C.2 landed in code and is well-covered by unit / integration
tests. Live end-to-end proof of shard-delivered public discovery and
anti-entropy convergence is incomplete and tracked as proof-debt.**

The code is strong enough that Phase E can proceed without building on
fake discovery — shards are real code, privacy gates are real, and the
C.2 primitives are exercised by the existing /discover/nearby path.
C.2 signoff remains open until the proof-debt items close.

## Commands run

```bash
cargo fmt --all -- --check
cargo clippy --all-features --all-targets -- -D warnings
cargo nextest run --lib --test named_group_state_commit \
  --test named_group_discovery --test api_coverage
cargo build --release --bin x0xd --bin x0x
bash tests/e2e_named_groups.sh > tests/proof-reports/named-groups-c2-run{1,2,3}.log 2>&1
```
