# #501 component evidence packet

These five real, separate-peer lib selectors form one component candidate. They do not establish public Leaf savings, completed forwarding, a hard bandwidth cap, a new default or Tester final acceptance.

| Exact selector under `legacy_bus_interop_tests::` | Required evidence |
|---|---|
| `bus_only_interop_default_positive_and_optout_negative` | D typed decrypt/trust positive; O bounded300ms non-observation after its separate bus publish; same O inner ciphertext succeeds targeted |
| `optout_sender_bus_fallback_reaches_bus_only_receiver` | L2 targeted subscription absent before/after; actual typed decrypt; same-request production fallback trace; v1 ACK |
| `optout_receiver_still_receives_modern_targeted_dm` | O3 verified typed delivery through signed targeted gossip while its bus subscription stays absent |
| `default_keeps_bus_subscription_and_optout_does_not` | Real Agent post-join default/opt-out subscription states |
| `paired_controlled_load_bus_eager_attempts_default_vs_optout` | Four-node fresh topology, literal lifetime universe, raw t0/t1, fixed200×4096-byte generator workload, positive/default and zero/opt-out attempt oracles |

The first two helper sends intentionally bypass `Agent::send_direct` route selection: `send_via_gossip` is the production seam under test. Inner v1 means enqueue ACK semantics; current signed outer V2 does not imply a durable inner v2 receipt. A fanout count is context, not delivery.

No selector result is inherited from another invocation. Execute each separately with `--exact` only after the reviewed isolated execution packet is admitted. Use the unchanged `scripts/ci/nextest-isolated.sh`, existing `quic-localhost` group, actual selected build lock and nextest binary reuse custody. Retain successful per-test output using nextest's `--success-output immediate`; ordinary Suite success suppressing that output is insufficient for the numerical packet. This document does not authorize execution or specify an unreviewed host setup.

The measurement prints `ISSUE501_MEASUREMENT ` followed by raw JSON at setup, t0, t1, validation and completion. Raw input contains fixture identities and must remain private. Completion preserves the captured pre-shutdown facts and is emitted only after orderly Agent shutdown. Interrupted or failed prefixes remain evidence, never a passing empty measurement. The compiled-in actual lock digest and streaming hash of the executing test binary must match the separately retained build/reuse records. The local fixture lock is not a substitute for a hosted build's lock.

Derive arithmetic after retaining the unmodified output and actual lock bytes:

```
python3 scripts/ci/derive-legacy-bus-attempts.py --raw PRIVATE_PER_TEST_OUTPUT --lock RETAINED_CARGO_LOCK
```

The tool emits hashes, counts and deltas, with no raw identities. `CONSISTENT` means its arithmetic and declared premises agree; it expressly leaves execution acceptance UNVERIFIED. Bind that output to the exact source tree/full tracked hash+mode manifest, build input map, actual lock bytes/package checksum, executing binary hash, exactly one started/terminal named test, admitted lo-only namespace, supervisor child pid/exit/reaped=true and admitted exit receipt. Missing selection, custody or completeness means UNRUN/INCONCLUSIVE, never PASS. A separate Root-reviewed execution packet must make these bindings before accepting the five results. No launcher/environment whitelist changes are needed.

The topic universe is a source-review premise over this exact fixture's complete process lifetime. It comprises the13 literal identity/revocation/move/blob/capability/bus topics plus each of four actual agent shards, machine shards and raw domain-separated inbox IDs (at most25 before full-key deduplication). Fresh anonymous homes have no user shards. Presence uses its separate manager; no group, rendezvous, release or arbitrary application topic is started here. Full32-byte IDs are derived through existing production functions and retained before their eight-byte projections are checked. Observed subscriptions and shortened row counts do not prove completeness; an unenumerated colliding topic is not detected by those observations. Any construction/helper/source change requires renewed universe review.

Raw rates are send-attempt bytes. All four message kinds are retained. Repair counts are a subset of eager, never added again. Rolling60s rates include warm-up and are context only; exceed counts are samples. Participation counters classify cumulative totals by current membership and do not give per-message origin/path attribution. W5 observations have no hop attribution. The2s settle and10s nominal controlled workload are not a public idle field window; no result here may be compared with #504's reported residential estimate.

Receipt fields to complete with actual evidence (no values are inferred from this template): exact source head/tree and pins; dependency lock/archive/binary hashes; five selector terminal outcomes; three named selector1 checkpoint outcomes; retained raw-output hashes; measurement derivation/hash; full lifetime-universe source review; per-invocation isolation/reaping/source binding; all missing/failed premises. Keep public field acceptance, policy adoption and Tester final10/10 explicitly open.
