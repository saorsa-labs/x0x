# Signed KV legacy compatibility: preparation and holds

Status: **disabled; preparation only** (`enabled = false`), updated 2026-09-07.
There is no operator activation endpoint or configuration switch. See
[proposed ADR-0063](adr/0063-signed-kv-legacy-gossip-compatibility-adoption-boundary.md).

**Authority split (do not conflate):**

- **Modern release** follows Accepted saorsa-gossip [ADR-014](https://github.com/saorsa-labs/saorsa-gossip/blob/main/docs/adr/ADR-014-modern-only-release-support.md)
  (RejectV1 default, modern-only receipt, stock not in modern predicate). G1–G8
  below do **not** block modern release.
- **Legacy/V3 facility** (this document) stays disabled until G1–G8 evidence and
  explicit G8 enablement. Prep being CLEAN does **not** renew a G4 modern-release
  block and does **not** activate product G4.

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

## Publication audit (historical → current)

Gossip [#48](https://github.com/saorsa-labs/saorsa-gossip/pull/48) merged at
`5307e59270b2eead28e948b2206cf8cc04f149d5`. G0 is MET.

**Cleared (2026-09-07):** the old “wait for a verified 0.5.76 publication
containing #48” and “Gossip release bump HOLD” lines are **stale**. Registry
[pubsub 0.5.76](https://crates.io/crates/saorsa-gossip-pubsub/0.5.76)
(checksum `f75f756d26e5011e17d15aa5cfaad17b5d56b8be37ab1003f9fd2592181ee09d`,
published 2026-09-06) contains `SignedKvTopic` / `x0x-msg-v3`. Current x0x
`Cargo.toml` requires the coherent **0.5.76** gossip family and
**ant-quic 0.27.50**. Do **not** renew a publication-only G4 block against
modern release or against reading those crates.

**Moved (2026-09-11):** x0x now requires the coherent **0.5.77** gossip family
(saorsa-gossip#54, stranded-publish recovery). The #501 meter premise — the
`saorsa-gossip-pubsub` lock pin checked by
`paired_controlled_load_bus_eager_attempts_default_vs_optout` and
`scripts/ci/derive-legacy-bus-attempts.py` — moved with it to registry
[pubsub 0.5.77](https://crates.io/crates/saorsa-gossip-pubsub/0.5.77)
(checksum `73b1d21df86ce58ee075f88e2d9d978e746f313d089be2fcfe46fe484214789f`).

**Moved (2026-09-12):** x0x now requires the coherent **0.5.78** gossip family
(saorsa-gossip#56, PlumTree dedups inbound EAGER before the ML-DSA-65 verify).
The #501 meter premise (the `saorsa-gossip-pubsub` lock pin checked by
`paired_controlled_load_bus_eager_attempts_default_vs_optout` and
`scripts/ci/derive-legacy-bus-attempts.py`) moved with it to registry
[pubsub 0.5.78](https://crates.io/crates/saorsa-gossip-pubsub/0.5.78)
(checksum `a4003d64b7d2edbea274e14a30d5997aa8fd316a5b1cc9634310982f0287a863`).

**Still historical warning:** registry **0.5.75** (Aug 27) predates #48 despite
the earlier workspace version string — never treat 0.5.75 as #48 adoption.

**G1 ant-quic facility (separate from publication):** a tag/version alone does
not prove `recv_with_generation` / `current_connection_generation`. G1 remains
OPEN for the V3 facility until published reader/pre-auth generation stamping
and pinned-send contracts are evidenced. That does **not** reinstate a global
gossip bump hold.

Optional integration-branch git pins (all 11 gossip crates to one revision)
remain a reproducible experiment pattern only — not counted as G4 close and not
activated by prep.

## Acceptance ledger (V3 / legacy facility only)

| Gate | State | Remaining evidence |
| --- | --- | --- |
| G0 | MET | Library merge #48 at `5307e592` |
| G0b publication | MET | Registry gossip **0.5.76** family with #48/`SignedKvTopic` (checksum-verified); x0x tree pinned to 0.5.76 |
| G1 | OPEN | Published ant-quic reader/pre-auth generation stamping, live-generation and pinned-send contract with reconnect/reuse tests |
| G2 | OPEN / blocked on G1 | End-to-end receive tokens into `handle_authenticated_message` and guarded egress; no post-dequeue lookup |
| G3 | OPEN | Signed-only exact-topic registration, V3 publication routing, receive/apply audit, owner/state-request checks, floor policy, grants, audit/counters; default false |
| G4 | OPEN (facility) | Remaining: actual `SignedKvTopic` verifier + exact-topic/roster integration on the adopted tree, complete green facility train. **Not** a modern-release blocker; **not** “waiting on 0.5.76 publication” |
| G5 | OPEN | Real-daemon fail-closed, spoof/expiry/queue tests and measured verification/relay overhead |
| G6 | OPEN | Future compatibility matrix under its own profile (patched V3 pair ≠ stock). Authentic stock evidence stays FAIL where recorded (#517 / run 34058040463); modern release uses ADR-014 `not_in_modern_predicate` |
| G7 | OPEN | Facility candidate convergence on exact binaries/deps when that train runs |
| G8 | OPEN | David's explicit **facility enablement** decision (`enabled = false` until then) |

Local pairing tests compare canonical preimage bytes and verify production
signatures with the resolved gossip identity crypto API. Running #48's
`SignedKvTopic` verifier with exact-topic/roster admission remains a **facility
G4** exit item — available now that 0.5.76 is published; still not done by prep
alone.

The H1 profile requires a patched `+signed-kv-inner-v3` receiver. It does not
prove stock v0.30.1 compatibility. Keep that distinction in G6 evidence;
never replace the authentic binary with a patched one and call a stock gate green.
No timeout padding, weakened predicate or library-fixture substitution.

**#515 / undraft / tag:** not held by G4 publication anymore. Undraft, tag,
deploy, and live-daemon work follow modern-release owners (ADR-014 receipt,
RejectV1 product, CI) and remain out of scope for this disabled facility.
No product G4 activation from this doc.

## 2026-09-13 — meter producer premise moved to saorsa-gossip-pubsub 0.5.79

The #501 legacy-bus meter refuses to measure against an unpinned producer, so
the exact published version and crates.io checksum are pinned in
`src/legacy_bus_interop_tests.rs`, `scripts/ci/derive-legacy-bus-attempts.py`
and its test fixture. saorsa-gossip 0.5.79 adds `ValidationAction::LazyForward`
(saorsa-gossip#59) for the x0x #674 C2/C3 relay fan-out work, so the premise
moves from 0.5.78 to **0.5.79**, checksum `2070b36d7e26e8fdebd3a0d84f7aae8f30bebb607e2fdcf3e916faf43da336dc`.
Note for #674 baselines: 0.5.79 also changes what `relay_msgs` counts (an
`if !eager_peers.is_empty()` guard on the relay meter), so relay counter
baselines taken on 0.5.78 are not directly comparable, and the IWANT serve
path still does not record publish origin — read `outbound_by_kind["eager"]`
alongside `relay_bytes` when accounting relay egress.

## 2026-09-14 — meter producer premise moved to saorsa-gossip-pubsub 0.5.81

saorsa-gossip 0.5.81 is the first release carrying the #58 dedupe read-probe
(saorsa-gossip PR #67 merged at 17:35Z on 2026-09-13; the v0.5.80 tag was cut
at 15:52Z, so 0.5.80 does **not** contain it). It also carries bounded
per-topic peer state (saorsa-gossip#41), the background-task shutdown
lifecycle (#42), the rate-limited recovery bypass during active suppression
(#29), and the WAN send-timeout tunables (PR #72 — production constants:
`PER_PEER_REPUBLISH_TIMEOUT` 2500->4000 ms, `PEER_TIMEOUT_WINDOW` 30->60 s,
`PEER_TIMEOUT_THRESHOLD` 5->8). The #501 meter premise therefore moves from
0.5.80 to **0.5.81**, checksum
`9b97359a1c57af33c5fe8c7ef5458b382db3ca47b86e68575fb352835999d887`.

Note on ordering, recorded because it cost a CI outage: 0.5.81 was published
*before* this pin bump landed. The x0x pin is a caret range and `Cargo.lock`
is gitignored, so every fresh CI resolve immediately picked up 0.5.81 and the
meter refused to run against an unpinned producer — turning every open PR red
until this merged. Prepare the pin bump PR first, then publish, then merge it
immediately.


## 2026-09-13 (b) — meter producer premise moved to saorsa-gossip-pubsub 0.5.80

saorsa-gossip 0.5.80 carries two cooling fixes root-caused from x0x#611
(saorsa-gossip#62: the #32 cooling floor becomes a replacement gate, so a
local CPU stall can no longer strand a topic at eager degree 1 for the 120 s
cooldown; saorsa-gossip#63: Bulk-priority topics can self-recover from
cooling via one bounded probe per cooldown expiry, which covers every x0x
announce/discovery/caps/release lane). The #501 meter premise therefore moves
from 0.5.79 to **0.5.80**, checksum `2f019ae3c17a73197ff7c48b5078caa2d03b669b7c0b724e30d2037e44e868b6`.


## 2026-09-21 — meter producer premise moved to saorsa-gossip-pubsub 0.5.84

saorsa-gossip 0.5.84 publishes the pubsub fixes merged in PR #84
(`IntentLimit` recovery-intent admission fairness, merge `8ea1cfd`) and
PR #85 (zero disabled-limiter dispatch overhead and bounded late-offer
catch-up, merge `5da7906`). Release PR #86 merged as `24882f2`. The #501
meter producer premise therefore moves to **0.5.84**, checksum
`ed849eabb8d24a1a28aed78a2dd5909ac2726618f81205071a45d028ce757bf3`.

The checksum was independently verified against both the crates.io sparse
index record (published 2026-09-21 18:35:55 UTC, not yanked) and the SHA-256
of the downloaded
`saorsa-gossip-pubsub-0.5.84.crate`. This dependency update makes the
fixes available to x0x; it is not evidence that either delivery regression is
fixed on the fleet. Runtime and fleet acceptance remain separate gates.

## 2026-09-18 — meter producer premise moved to saorsa-gossip-pubsub 0.5.83

saorsa-gossip 0.5.83 carries the #504 slice-2 Leaf egress work
(saorsa-gossip PR #82, merged `05fc664`, release `cea70b8`, tag `v0.5.83`):
`BytePolicy`, `LeafEgressConfig.policy`, and the `LeafEgressSnapshot`
counters including `shed_suppressed`. The #501 meter premise therefore moves
to **0.5.83**, checksum
`7886ce7293eecce58e59be0fa48f1fee5262af7a9e4e02be305dc12e94166912`
(verified two ways: the `Cargo.lock` entry produced by `cargo fetch` against
the caret pins, and `shasum -a 256` of
`~/.cargo/registry/cache/*/saorsa-gossip-pubsub-0.5.83.crate`).

The x0x consumer default is `byte_policy = "observe_only"`, so the producer
still meters rather than sheds and #501 measurements stay comparable across
this bump. A capture taken with `byte_policy = "shed_normal"` is **not**
comparable to any earlier baseline and must say so.

**The premise had split in two.** The 0.5.82 bump (#722) moved only
`src/legacy_bus_interop_tests.rs` and left
`scripts/ci/derive-legacy-bus-attempts.py` (plus its fixture) asserting
0.5.81, and added no entry here. The Rust assertion and the Python
`PRODUCER_PIN_MISMATCH` check therefore disagreed for four days. It went
unnoticed because the derive script is an offline evidence tool, not a CI
gate, so nothing turned red. This bump brings all three sites to 0.5.83 in
one step — it does not stop at 0.5.82, which is no longer the version x0x
builds against — and removes the mechanism that allowed the drift: the
script now owns a single `PUBSUB_VERSION` constant, and the test fixture
derives its lock text from `module.PUBSUB_VERSION` and `module.PUBSUB_SHA`
instead of repeating the version literal. The premise is now one value per
half (Rust, Python) rather than four.

## 2026-09-14 — #613: the measured arms' ingress joins the record, and the t1 cut waits for it

Two defects in how the #501 meter *reads* the measured arms, both found by
running the fixture rather than from the issue narrative. Neither changes
what the oracle requires.

**1. The record began at saorsa-gossip's decode.** `raw_sample` captured the
arm's egress, participation and `stage_stats()`. Every one of those starts
after x0x's own receive pump has handed the frame to the gossip dispatcher.
That pump drops PubSub frames when its bounded forward channel is full
(`recv_pump.pubsub.dropped_full`) and proactively sheds recoverable control
frames near overload (`shed_priority`, ADR 0013) — both silent to every
counter the record carried. So "the generator's frames never reached this
host" and "they reached it and x0x discarded them" produced an identical
failure line, and each occurrence had to be hand-classified. The sample now
carries `recv_pump` (per stream and per peer), and the D5 failure reasons
carry a one-line `ingress[...]` summary keyed on the generator's machine ID,
so the panic message alone separates the two.

Measured on this fixture on a quiet 18-core host: the pump is nowhere near
its limit — `max_depth` 2-3 against `capacity` 10,000, `dropped_full` 0,
`shed_priority` 0, and D5's decoded EAGER count exactly equal to
`produced_total`. Local shedding is therefore excluded *for these runs*; it
was never excluded for the CI occurrences because it was never sampled.

**2. The t1 cut was taken with nothing drained.** The oracle compares a
generator count accumulated across the whole load against the arms' counters
read at one instant, and that instant was the return of the 200th publish. A
publish returns when the *send* succeeded, not when the receiver has
processed the frame, so the old cut measured "how much had this arm processed
by the time I looked". Measured: D5's bus eager egress was 189 at the old cut
instant and 200 three seconds later — 5.5% of the load still in flight on an
idle host. Under runner starvation that fraction has no bound and `delta == 0`
is its limit. `measure` now waits for both measured arms to stop advancing —
ingress **and** the bus egress the oracle actually reads — before cutting,
and records `load.quiescence` including whether quiescence was actually
reached. This is a premise repair, not a tolerance: the oracle's requirement
is unchanged, the instant it reads is now a valid one.

The egress term is load-bearing, and its absence was the blocking finding on
the first version of this barrier. The oracle reads `sample_rows` over
`egress.outbound_by_topic_named`, and that lags ingress: in the table above,
D5 had already produced and decoded 201 at the old cut instant — ingress
essentially complete — while its bus eager egress read 189. A barrier
stabilising on ingress alone would have reported quiescent while the very
quantity the oracle measures was still draining, i.e. it would have repaired
the wrong half. Including egress cannot mask anything on the O5 arm either:
the value that arm's oracle requires is 0, stable on the first poll, so the
term tightens O5 rather than loosening it.

`load.elapsed_ns` deliberately excludes the barrier. It is the generator's
load phase and feeds `load_achieved_per_second` in the CI derivation;
billing the drain to it would understate the achieved rate by roughly the
barrier's duration and report a load the fixture did sustain as one it did
not. The barrier's own cost lives in `load.quiescence.waited_ms`.

**The cut moved — read this before distrusting the meter.** If you are
debugging a #613-class failure on a record that has `load.quiescence`, the
t1 sample is no longer taken at the last publish. What the barrier can and
cannot do:

- It is **bounded**: four consecutive unchanged 250 ms polls — 1 s of
  stillness, because 500 ms is thin on exactly the starved runners this
  targets, where one scheduling gap of that length would read as a drained
  pipeline — over `(recv_pump.pubsub.produced_total,
  recv_pump.pubsub.dequeued_total, stages.message_kinds.eager, plus that
  arm's bus outbound msgs)` on *both* measured arms, capped at 20 s and
  wrapped in a 30 s labelled deadline so a wedged arm is still caught and
  still attributed to this label. Measured cost on a passing run: ~1.5-1.8 s.
- The bus kinds it watches are **per arm, and are the arm's own oracle
  kinds**: D5 `eager + ihave` (#674 active dissemination), O5 `eager +
  ihave + iwant + anti_entropy` (no bus egress of any kind). Both arms read
  them from `D5_BUS_ORACLE_KINDS` / `O5_BUS_ORACLE_KINDS`, the same consts
  `validate_measurement` sums, so the reset condition covers exactly the
  verdict it protects by construction rather than by two lists agreeing —
  and `load.quiescence.bus_kinds_watched` records which kinds were in force
  for the run. A barrier watching a narrower quantity than the oracle
  judges on is what produced the 189-vs-200 gap; these consts are what stop
  it recurring if either oracle's kinds change.
- On **timeout** it does not fail, retry or widen anything — it stops
  waiting, records `"quiescent": false` with the elapsed `waited_ms`, and
  the t1 cut is taken exactly as before. A `false` there means the arms
  were still moving after 20 s, which is itself evidence and is why the
  flag is recorded rather than asserted.
- It **cannot manufacture counts**. A barrier only gives already-sent work
  time to be processed. If frames were genuinely dropped, refused or never
  forwarded, waiting produces no additional counts, the oracle still reads
  zero dissemination, and the test still fails — now with the
  `ingress[...]` attribution above. That is the property that separates
  this from a loosened threshold: a tolerance says "a gap of N is
  acceptable", whereas this says "measure after the system has finished,
  not mid-flight", which is what the meter always claimed to measure.

Not established by this change: whether the CI occurrences of #613 are that
drain artefact. They did not reproduce locally (3/3 PASS on x0x v0.44.0 /
saorsa-gossip-pubsub 0.5.80, D5 receiving 197-212 of 200 bus publications),
and this repo has no way to run the Coverage Gate's contention locally. The
next CI occurrence will say which of the three ingress situations it was.

Also refuted while checking: the `DeliverOnly`-empties-`eager_peers`
mechanism proposed on #613 cannot apply to the bus topic. x0x registers base
content validators only on the identity, machine, revocation and
`x0x.discovery.groups` topics (`src/storm_control.rs`), and with no base
validator `RelayFanout::verdict` (`src/gossip/relay_fanout.rs`) can only
return `ForwardAndDeliver` or `LazyForward` — and `LazyForward` queues the
IHAVE that the #674 oracle already counts (observed live: 18 IHAVE msgs on
D5's bus row in one local run).
