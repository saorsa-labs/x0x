# #1396: bytes per frame and verifies per second — v0.45.0 vs v0.48.1, loopback

Recorded 20 Oct 2026. Scope per David's 20 Oct 2026 lane ruling: a local
loopback measurement on one Mac. No testnet, no production host, no fleet
run. The issue's original "same hosts" interleaved run stays with the ops
lane (D14; the 26 h soak is #1172).

## Method

- Release binaries, not local builds: `x0xd` v0.45.0
  (sha256 `10435f1a9c2531137e1828934b4be7b187caeccb9b326e81c3f2d4d80da58122`)
  and v0.48.1
  (sha256 `a63a4a3791d5ad98b69e028f5f415531e93bf2be537b65f019a7852c58fbb5d3`).
  Each daemon reported its own version on `/health`.
- Two daemons per leg: `pub` publishes, `sub` subscribes and verifies.
  Hermetic loopback pair: `mdns_enabled = false`,
  `--no-hard-coded-bootstrap`, private `network_id` per leg, `sub`
  bootstraps to `pub`'s 127.0.0.1 QUIC port, `[update] enabled = false`.
  This is the repo's #648 hermetic pattern.
- Load: 2000 REST publishes per run, one fixed payload per run (256 B, then
  4096 B, deterministic content). `sub` subscribes to the topic before the
  run. No pacing: publish as fast as the API accepts.
- Sampling: full `GET /diagnostics/gossip` from both daemons immediately
  before and after each run. Bytes per frame = Δ`inbound_by_topic` (class
  `other`, kind `eager`) bytes / frames on `sub`; the `pub` outbound
  `outbound_by_kind` deltas are byte-identical. Verify counters are read
  on `sub` (the receiver). Verify rate = Δ`pubsub_stages.verify.count`
  (and, on v0.48.1, Δ`inner_envelope_verify.count`) over the wall seconds
  between the two snapshot fetches; the per-verify mean is
  Δ`total_ns`/Δ`count` over the same pair. Wall clock is the denominator
  for both versions: v0.45.0 has no `uptime_secs` in
  `/diagnostics/gossip`.
- Legs interleaved A/B/A/B: v0.45.0, v0.48.1, v0.45.0, v0.48.1, full
  teardown between legs.

## Results

Every run delivered 2000/2000 frames, 0 HTTP failures, and `sub` held a
peer connection to `pub` throughout. A/B/A/B drift: 0.0 % on bytes per
frame (both versions reproduced their number exactly), 0.1–5.2 % on rates.

Bytes per frame (`sub` inbound, class `other`, kind `eager`):

| Payload | v0.45.0 | v0.48.1 | Δ | Cut |
|---|---|---|---|---|
| 256 B | 10 941 B | 9 026 B | −1 915 B | 17.5 % |
| 4096 B | 14 781 B | 12 866 B | −1 915 B | 13.0 % |

The saving is a constant −1 915 B per frame, independent of payload. Fixed
overhead per frame (bytes per frame minus payload): v0.45.0 = 10 685 B,
v0.48.1 = 8 770 B.

Verify work under the same load. All verify counters are on `sub` (the
receiver; `pub`'s verify deltas are 0 in seven of eight runs and 1 in
leg 2 at 256 B), before→after deltas, per-verify mean =
Δ`total_ns`/Δ`count`:

| Leg | Version, payload | Outer Δcount | Inner Δcount | Outer mean | Inner mean | Outer rate |
|---|---|---|---|---|---|---|
| 1 | v0.45.0, 256 B | 2000 | — | 88.87 µs | — | 1180 /s |
| 2 | v0.48.1, 256 B | 2001 | 2000 | 83.69 µs | 78.06 µs | 1103 /s |
| 3 | v0.45.0, 256 B | 2000 | — | 88.28 µs | — | 1190 /s |
| 4 | v0.48.1, 256 B | 2000 | 2000 | 86.74 µs | 79.68 µs | 1159 /s |
| 1 | v0.45.0, 4096 B | 2000 | — | 87.45 µs | — | 1156 /s |
| 2 | v0.48.1, 4096 B | 2000 | 2000 | 87.80 µs | 83.65 µs | 1099 /s |
| 3 | v0.45.0, 4096 B | 2000 | — | 86.95 µs | — | 1115 /s |
| 4 | v0.48.1, 4096 B | 2000 | 2000 | 87.68 µs | 83.76 µs | 1058 /s |

Outer = `pubsub_stages.verify`; inner = `inner_envelope_verify`, which only
v0.48.1 exposes. Outer counts are 2000 per 2000-message run in seven of
eight runs; the one exception is leg 2 at 256 B, where a single extra
outer verify (inner stayed at 2000) is background traffic on the same
inbound path. Inner counts are exactly 2000 in every v0.48.1 run. No run
dropped an eager duplicate pre-verify
(Δ`eager_duplicate_dropped_pre_verify` = 0 on both daemons, every run).

The two verifies do not cost the same. The outer stage verify costs
86.95–88.87 µs on v0.45.0 and 83.69–87.80 µs on v0.48.1 (the 256 B
v0.48.1 runs are the low end); the inner envelope verify is consistently
cheaper, 78.06–83.76 µs, and sits below every outer mean in its run.
Combined, v0.48.1 spends ~162–171 µs verifying each delivered message.
The cross-version-comparable outer rate is flat: v0.45.0 1115–1190 /s
versus v0.48.1 1058–1159 /s, a difference inside the A/B/A/B drift, so
v0.48.1 shows no cut in verify rate. Publish throughput: 1117–1191 msg/s
(v0.45.0) versus 1061–1163 msg/s (v0.48.1).

## Verdict against the 20 % target

Not met in this local measurement. The best case is a 17.5 % cut in bytes
per frame (256 B payload); verifies per second did not fall. What blocks
the cut:

1. **The frame is dominated by fixed cryptographic material.** The 8 770 B
   per-frame overhead on v0.48.1 decomposes as two ML-DSA-65 signatures
   (3 309 B each) plus one public key (1 952 B) plus roughly 200 B of
   framing. The 1 915 B saved between v0.45.0 and v0.48.1 equals one
   ML-DSA-65 public key. The issue's 20 % target is a cut against the
   v0.45.0 baseline (#1396: "v0.45 against current"), so the targets are
   8 752.8 B/frame at 256 B (0.8 × 10 941) and 11 824.8 B/frame at
   4 096 B (0.8 × 14 781). From v0.48.1's 9 026 / 12 866 B that leaves a
   further cut of 273.2 B/frame at 256 B and 1 041.2 B/frame at 4 096 B
   (274 / 1 042 B in whole bytes). Both gaps exceed the ~200 B of framing,
   so the bytes can only come from the remaining per-frame public key or
   one of the two signatures. Both are wire-format changes (key-cache or
   announce-referenced keys; the `key_cache_control` outbound kind already
   exists in v0.48.1's stage stats and points at that direction, #1170 /
   PR #1435 on hold). Fenced: needs David.
2. **Verify work is protocol-pinned.** Every delivered message pays one
   counted outer verify on both versions (86.95–88.87 µs on v0.45.0,
   83.69–87.80 µs on v0.48.1), and on v0.48.1 additionally one counted
   inner envelope verify (78.06–83.76 µs) — about 162–171 µs of verify
   CPU per message on v0.48.1, where both layers are counted. A 20 %
   cut at the same message rate needs fewer or cheaper verifies per
   message, and the cheap lever is already spent: the pinned dependency
   drops cached duplicates before the verify (point 4). What remains is
   collapsing the two envelope layers, or batch/aggregate signatures.
   All wire or protocol changes. Fenced: needs David.
3. **Counter comparability.** v0.45.0 has no `inner_envelope_verify` and no
   `uptime_secs` in `/diagnostics/gossip`, so only `pubsub_stages.verify`
   compares across versions, and its stage internals may differ between
   releases.
4. **Scope.** One relaying peer, no fan-out. Fleet verify load does not
   scale with eager fan-out degree. In the pinned saorsa-gossip-pubsub
   0.5.90, an inbound EAGER frame whose msg_id is already cached is
   dropped before the ML-DSA-65 verify (crate `src/lib.rs:10546–10593`,
   the `eager_duplicate_dropped_pre_verify` counter incrementing at
   `lib.rs:10590`; the crate's own comment puts such duplicates at ~28 %
   of inbound EAGER on a bootstrap node, `lib.rs:10517`); the first copy
   of a message is verified once (`verify_message_signature` called at
   `lib.rs:10604`, recorded at `lib.rs:8396`); and forwarding serializes
   the verified frame once and hands the same bytes to every eager peer
   with no signature work on the send path (serialize at `lib.rs:10848`,
   send at `lib.rs:10874`). x0x registers no topics, so all x0x traffic
   takes the dedup-first path (`lib.rs:10524`). A relay's verify load
   therefore scales with its admitted incoming EAGER rate — the first
   copy of each message, plus concurrent-duplicate races that pay one
   verify (`lib.rs:10618–10644`) — while fan-out degree adds only
   outbound bytes. The inner envelope verify is x0x-side
   (`src/gossip/pubsub.rs:4775` in this repo): it runs once per envelope
   delivered to a subscriber and never on the forwarding path
   (`src/gossip/pubsub.rs:95`). Fleet absolute rates can still differ
   from this loopback pair; the same-hosts interleaved fleet run remains
   the ops-lane item (D14, #1172).

## Evidence

Raw snapshots (48 full `/diagnostics/gossip` captures), the field
availability matrix, per-leg driver scripts, daemon configs and logs are in
`~/x0x-zcode/evidence/1396/` on the measurement host (not committed).
`results.json` there holds the machine-readable derivation. `verify-table.py`
in the same directory recomputes the whole verify table (counts, per-verify
means, rates, duplicate drops) directly from the raw snapshots into
`verify-table.md` / `verify-table.json`; the verify figures in this file
match its output.
