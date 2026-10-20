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
  `outbound_by_kind` deltas are byte-identical. Verify rate =
  Δ`pubsub_stages.verify.count` (and, on v0.48.1,
  Δ`inner_envelope_verify.count`) over the wall seconds between the two
  snapshot fetches. Wall clock is the denominator for both versions:
  v0.45.0 has no `uptime_secs` in `/diagnostics/gossip`.
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

Verify work under the same load:

| Metric | v0.45.0 | v0.48.1 |
|---|---|---|
| `pubsub_stages.verify` count per 2000 messages | 2000 (one per message) | 2000 (one per message) |
| `inner_envelope_verify` count per 2000 messages | counter absent | 2000 (one per message) |
| Stage verify rate | 1115–1190 /s | 1058–1159 /s |
| Mean stage verify time | 87–89 µs | 87–89 µs |
| Publish throughput | 1117–1191 msg/s | 1061–1163 msg/s |

The cross-version-comparable verify rate is flat: v0.48.1 shows no cut (the
small difference is inside the A/B/A/B drift). v0.48.1 additionally counts
the inner-envelope verify that v0.45.0 performed but did not count.

## Verdict against the 20 % target

Not met in this local measurement. The best case is a 17.5 % cut in bytes
per frame (256 B payload); verifies per second did not fall. What blocks
the cut:

1. **The frame is dominated by fixed cryptographic material.** The 8 770 B
   per-frame overhead on v0.48.1 decomposes as two ML-DSA-65 signatures
   (3 309 B each) plus one public key (1 952 B) plus roughly 200 B of
   framing. The 1 915 B saved between v0.45.0 and v0.48.1 equals one
   ML-DSA-65 public key. The next 20 % of total frame bytes at a 256 B
   payload needs at least ~1 805 B more per frame; the only places it can
   come from are the remaining per-frame public key or one of the two
   signatures. Both are wire-format changes (key-cache or
   announce-referenced keys; the `key_cache_control` outbound kind already
   exists in v0.48.1's stage stats and points at that direction, #1170 /
   PR #1435 on hold). Fenced: needs David.
2. **Verify work is protocol-pinned.** Both versions run exactly one outer
   verify plus one inner verify per delivered message, and each costs
   ~87 µs. A 20 % cut at the same message rate needs fewer verify calls
   per message — dedup or lazy forwarding before verify, or signature
   aggregation. All wire or protocol changes. Fenced: needs David.
3. **Counter comparability.** v0.45.0 has no `inner_envelope_verify` and no
   `uptime_secs` in `/diagnostics/gossip`, so only `pubsub_stages.verify`
   compares across versions, and its stage internals may differ between
   releases.
4. **Scope.** One relaying peer, no fan-out. A fleet relay's verify load
   scales with its eager fan-out degree, so fleet numbers can differ from
   these. The same-hosts interleaved fleet run remains the ops-lane item
   (D14, #1172).

## Evidence

Raw snapshots (48 full `/diagnostics/gossip` captures), the field
availability matrix, per-leg driver scripts, daemon configs and logs are in
`~/x0x-zcode/evidence/1396/` on the measurement host (not committed).
`results.json` there holds the machine-readable derivation; the numbers in
this file were re-derived from the raw snapshots before committing.
