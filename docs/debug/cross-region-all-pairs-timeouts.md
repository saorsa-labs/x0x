# Debug brief — cross-region all-pairs DM timeouts

**Filed:** 2026-04-30
**Scope:** x0x v0.19.16 + ant-quic 0.27.3 + saorsa-gossip 0.5.19
**Severity:** medium — single-pair flows are healthy; the failure surfaces under simultaneous many-pair contention.
**Reproducer:** `bash tests/e2e_vps.sh` against the 6-VPS fleet on 0.19.16.
**Latest evidence:** `proofs/full-suite-20260429T214746Z/03-vps/`

---

## What's broken

`e2e_vps.sh` runs an all-pairs matrix: 6 VPS nodes, 30 directed pairs, each pair connected via `/agents/connect` then exercised via `POST /direct/send`. On the 2026-04-30 run, the connect step reported `Direct | Coordinated | AlreadyConnected` for **all 30 pairs**, but:

- **12/30 REST sends** returned `curl_failed` (the SSH-tunneled curl exceeded its 18 s `-m` cap and was retried once before the harness gave up).
- **16/30 receives** missing on `/direct/events` after a 15 s settle.
- **2/2 CLI direct sends** (Sydney→SFO, NYC→Helsinki) missed recipient proof.
- **2/2 large-file offers** (NYC→SFO, 1M and 16M via `POST /files/send`) timed out the same way.

The `e2e_first_message_after_join` test still passes 24/24 cross-region in the same proof run, so a single isolated send between two cross-continent peers is fine. The regression is specific to **simultaneous many-pair contention**.

## What you actually need to find

Why does a send that the connectivity layer believes is `Direct/Coordinated/AlreadyConnected` (i) take >18 s on the wire, or (ii) come back from x0xd as `{"ok":false,"error":"timeout"}` after ~10 s, when the same pair works fine in isolation?

There are at least three different tails. The fix probably touches the third.

## Manual repro (the three modes)

All run while the rest of the fleet is otherwise idle. Times below are real. The `gossip_inbox` and `raw_quic` strings are returned in the `path` field of `/direct/send`'s success body; investigate them in `src/dm/` and `src/network.rs`.

### Mode 1 — `raw_quic` (works fast)
```text
Singapore -> NYC : ok=true, path=raw_quic, ~sub-second
```
This is the happy path: `connect_to_agent` succeeded with a real QUIC connection and `/direct/send` wrote on it. Nothing to debug here; this is what every pair *should* do.

### Mode 2 — `gossip_inbox` (works slowly, exceeds 18 s harness cap)
```text
NYC -> Sydney : ok=true, path=gossip_inbox, took ~30 s with curl -m 30
```
The send succeeded but went through the gossip relay path, not direct QUIC. Total round-trip exceeded the harness's 18 s budget, hence the harness saw `curl_failed`. The interesting question: **why did this pair fall back to gossip_inbox when `/agents/connect` for the same pair just reported `Direct` or `Coordinated`?** Either the connection was reaped between connect and send, or `/direct/send` is using a different lookup that misses the just-established connection.

### Mode 3 — `ok:false`, x0xd internal retry budget exhausted
```text
Sydney -> Singapore :
  {"detail":"timed out after 1 retries over 10.509450026s","error":"timeout","ok":false}
```
This is the pair x0xd actually gives up on — not a transport timeout, an *internal retry budget* of ~10 s. **Find where that budget lives.** Search for `retries_used`, `over .*retries`, or the `path` selection logic in `src/dm/` / `src/bin/x0xd.rs`. It may be that the retry loop is busy-waiting on a connection that's stuck in a half-open state.

## Anchor data

Failures on 2026-04-30 (every directed pair that involved Sydney, plus a few asymmetric ones):

```
NYC→Sydney, SFO→Sydney, Helsinki→Sydney
Nuremberg→SFO, Nuremberg→Helsinki
Singapore→NYC, Singapore→SFO, Singapore→Helsinki
Sydney→NYC, Sydney→SFO, Sydney→Helsinki, Sydney→Singapore
```

Things that are not the bug:
- It is **not** SSH flakiness — manual `ssh root@<node> 'curl http://127.0.0.1:12600/health'` returns instantly on every node.
- It is **not** the recently-fixed first-message-after-join issue — that test still passes 24/24 in the same proof run.
- It is **not** a deploy problem — `e2e_deploy.sh` shows 24/24 pre-flight pass with healthy peers (5–12 each) on every node.

## Suggested investigation order

1. **Reproduce mode 3 in isolation.** Run `bash tests/e2e_vps.sh` once to warm the cache, capture the failing pair list, then send Sydney→Singapore manually with a 30 s `-m` and observe whether you get `ok:true (gossip_inbox)` or the same `ok:false`. If the failure is reproducible in isolation, mode 3 is its own bug; if not, mode 3 only emerges under matrix load (queue contention, hole-punch coordinator contention, etc.).
2. **Trace `path` selection.** In x0xd, `/direct/send` decides `raw_quic` vs `gossip_inbox` based on connection state. Log the full decision (peer connection state, last-activity timestamp, NAT info) and see whether mode-2 sends are using `gossip_inbox` because the QUIC connection was *closed*, or because the lookup failed even though it was alive.
3. **Audit the 10 s retry budget.** Find the constant. If it is intentionally low (e.g. to keep `/direct/send` snappy for direct paths), the call should *not* retry on `gossip_inbox` paths the same way. Either lift the cap when falling back to gossip, or surface a 503-style "use gossip" hint to the caller.
4. **Check coordinator availability under matrix load.** With 30 simultaneous `/agents/connect` calls, every cross-continent pair may be trying to use the same bootstrap as a NAT-traversal coordinator. Inspect `/diagnostics/connectivity` (added v0.17.2) on every node during the matrix run — coordinator queue depth would surface here.

## Acceptance for the fix

`bash tests/e2e_vps.sh` should produce **0/30 send fails and 0/30 receive misses** on a freshly-deployed fleet, with the existing 18 s harness curl cap unchanged. Add to `proofs/` a run before and after.

## Don't fix by raising the harness timeout

The 18 s cap is the SLO that callers see. A user-facing `/direct/send` taking >18 s to deliver to a Direct/Coordinated peer is a real product issue, not a test artefact. If the only path that works in 18 s is `raw_quic`, the bug is that we're falling back to `gossip_inbox` when we shouldn't — or that the retry budget kills slow-but-progressing direct sends.
