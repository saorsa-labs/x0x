# 0.21.2 Welcome-fetch retry — why we tried it, why we think it failed (2nd opinion wanted)

**Date:** 2026-06-05
**Status:** NO-GO, not released. `main`/prod stay on 0.21.1. Branch `fix/welcome-fetch-retry` unmerged.
**Purpose:** independent review. We attempted a fix for the high-churn TreeKEM convergence
gap, soaked it, and it came out **worse** than baseline — but the comparison is
**confounded** (different time-of-day). Read the evidence and the CONFOUNDS section and
judge for yourself; our "why it failed" is a hypothesis, flagged with confidence levels.

---

## 1. TL;DR

- **What 0.21.2 was:** one change — `fetch_treekem_welcome` re-issues the Welcome-blob
  `FetchRequest` every 20s within its existing 90s budget (instead of one request + a single
  90s wait), to "ride out" a transient peer cooldown.
- **Result:** 150-iteration testnet churn soak → **71/150 (47%)**, *worse* than the
  **117/150 (78%)** baseline on 0.21.1. All 79 fails were `converge_member_m2`. X0X-0074d=0
  and invalid-epoch=0 throughout (overflow + state-chain fixes held).
- **Why we think it failed (hypothesis):** the failing leg is **raw-QUIC Welcome-*chunk
  delivery*** (anchor→member), not `FetchRequest` loss — so a request-level retry can't help
  it, and (verified) it *amplifies* the anchor's blob re-serves.
- **BUT the comparison is not controlled:** baseline ran daytime, retry ran overnight, and
  overnight transport failures were ~16× higher. We cannot cleanly separate "the fix
  regressed it" from "overnight infra was worse." See CONFOUNDS.

---

## 2. Why we did it (the hypothesis chain)

1. **The gap:** 0.21.1 fixed multi-member TreeKEM convergence (single + low-churn work), but a
   3.5h soak showed **78%** under sustained churn. The fails were `Welcome not processed`,
   correlated with `failed to fetch TreeKEM Welcome` and heavy peer cooling — not a state/
   overflow bug (`invalid epoch=0`, `X0X-0074d=0`). Documented as a known limitation in 0.21.1.
2. **The dig** (`handoff/cooling-vs-welcome-fetch-2026-06-04.md`): saorsa-gossip 0.5.62's
   cooling (esp. commit `15fda29`, cool-on-Critical-gate-saturation for 30–300s) can suppress
   Critical sends to a peer; we hypothesised this starved the Welcome fetch.
3. **The chosen mitigation (x0x side):** `fetch_treekem_welcome` sent a *single* `FetchRequest`
   and waited the full 90s on one oneshot with no re-request. A 30s cooldown inside that window
   would kill the whole fetch. So: re-issue the request periodically (every 20s, ~4 attempts)
   to survive a cooldown. The responder keys offer/chunk state on `welcome_id`, which we
   believed made duplicate requests idempotent/safe.

This was explicitly the *cheap, surgical* option; the dig's recommended *root* fix is upstream
(saorsa-gossip#24: make Critical bypass cooling at the claim layer).

---

## 3. The exact change (branch `fix/welcome-fetch-retry`, x0xd.rs)

`fetch_treekem_welcome` previously: insert receive-state → register one oneshot waiter → send
one `FetchRequest` → `tokio::time::timeout(WELCOME_FETCH_TIMEOUT=90s, rx)`. Now: same setup,
then a loop that `select!`s the oneshot against a `WELCOME_FETCH_RETRY_INTERVAL=20s` sleep and
**re-sends the same `FetchRequest`** on each interval until the blob arrives or the 90s
deadline passes. The waiter stays registered across retries; only the request is re-sent.

---

## 4. The two soaks (side by side — note the confound)

| | 0.21.1 baseline | 0.21.2 retry |
|---|---|---|
| When (UTC) | 16:21–20:47 (**daytime**) | 23:37–04:39 (**overnight**) |
| Convergence | **117/150 (78%)** | **71/150 (47%)** |
| Fail step | mostly `converge_member_m1` (19) + m2 (3) + others | **all `converge_member_m2` (79)** |
| X0X-0074d | 0 fleet-wide | 0 fleet-wide |
| invalid-epoch | 0 fleet-wide | 0 fleet-wide |
| `ant_quic send failed` (member, window) | ~507 in a 25-min collapse | **7991** over the soak |
| anchor `failed_send_welcome_blob` | (not measured) | **2018** |
| member `timed_out_waiting_welcome` | n/a | 423 |
| member `retry_send_failed` | n/a | **0** (retries sent fine) |
| peer cooling (nuremberg `timeout_cooled`) | 161→**4840** | →**1859** (LOWER) |

---

## 5. Why we think it failed (hypotheses, with confidence)

**H-A — the retry targets the wrong leg (HIGH confidence).** `retry_send_failed=0` means the
retried `FetchRequest`s (member→anchor) all sent successfully, yet the Welcome still never
arrived (`timed_out_waiting_welcome=423`). The blockage is the **anchor→member chunk
delivery**: anchor `failed_send_welcome_blob=2018`, member `ant_quic send failed=7991`. A
retry of the *request* leg cannot fix a failing *delivery* leg.

**H-B — the Welcome blob is on raw-QUIC and fails terminally (HIGH confidence, code-verified).**
`send_welcome_blob_message` uses `file_transfer_send_config` (`prefer_raw_quic_if_connected:
true`, `stop_fallback_on_raw_error: true`). So Welcome chunks go over raw QUIC, and a raw-QUIC
send failure is terminal (no gossip fallback). That matches the dominant `ant_quic send failed`
signal and explains why the cooling-focused retry (a pubsub-path concern) doesn't touch it.

**H-C — the retry amplifies the failing serves (MEDIUM-HIGH, code-verified mechanism).**
`handle_welcome_fetch_request` (x0xd.rs:18031) spawns a **full `stream_welcome_blob`** (Offer +
all chunks) on *every* request, with **no in-progress/dedup guard**. So a 20s retry against a
slow/stalled transfer spawns a *second concurrent full re-serve* of the same blob → duplicate
chunks + multiplied raw-QUIC sends. This plausibly inflates the anchor's 2018 failed serves and
the member's 7991 `ant_quic send failed`. (The receiver dedups chunks by `welcome_id`, so it's
*correctness*-safe, but not *load*-safe.)

**H-D — load shifted from cooling-starvation to transport failure (MEDIUM).** In the baseline,
cooling was high (4840) and fails were mixed m1/m2; in the retry soak, cooling was *lower*
(1859) but `ant_quic send failed` was very high (7991) and all fails were m2. The dominant
failure mode appears to have moved to raw-QUIC transport failure — consistent with H-B/H-C, but
also consistent with worse overnight links (see CONFOUNDS).

---

## 6. CONFOUNDS — what is NOT established (read before concluding)

- **No controlled A/B.** Baseline = daytime, retry = overnight. Overnight `ant_quic send
  failed` was ~16× the daytime rate. A large part of the 78%→47% drop could be **infra/
  cross-region degradation**, not the fix. We did **not** re-run 0.21.1 overnight for a fair
  comparison.
- **Lower cooling in the retry soak partially undercuts the amplification story.** If the retry
  mainly amplified load, we might expect *higher* cooling, not lower (1859 < 4840). Possible
  explanations: fewer iterations reached the heavy-cooling regime, or the overnight bottleneck
  was raw-QUIC transport (which doesn't show as pubsub cooling). Unresolved.
- **"All fails = m2"** could be the fix, or overnight conditions, or simply that the m2 Welcome
  is larger (3-member tree → more chunks → more exposure to per-chunk raw-QUIC send failures).
  Not isolated.
- We did **not** directly observe a duplicate FetchRequest spawning a concurrent re-serve in
  the live logs; H-C is a code-path inference, not a measured event count.

**Bottom line we're confident in:** a `FetchRequest`-level retry structurally cannot fix a
failing *chunk-delivery* leg, and the code path makes it amplify. **What we're NOT confident
in:** the precise magnitude of the regression attributable to the fix vs the overnight infra.

---

## 7. What a 2nd opinion should scrutinise / next experiments

1. **Controlled A/B:** run 0.21.1 and 0.21.2 soaks back-to-back at the *same* time-of-day
   (or interleaved), so the 78% vs 47% comparison isn't time-confounded. This is the single
   most important missing data point.
2. **Characterise `ant_quic send failed=7991`** — is it cross-region infra (which links? is it
   the known APAC/overnight degradation?), or a transport reliability issue under sustained
   load? It's the dominant signal and upstream of everything.
3. **Verify H-C amplification with counts** — instrument `stream_welcome_blob` spawns per
   `welcome_id` during a failing run; confirm/deny concurrent re-serves.
4. **Is the retry premise even right?** The cooling-starvation theory predicts the *FetchRequest*
   or pubsub-Critical path is suppressed; but the data says the *raw-QUIC chunk* path fails.
   Did we mis-target from the start? (The dig itself flagged that the Welcome blob is raw-QUIC,
   so cooling — a pubsub concern — may never have been the Welcome's problem; cooling bit the
   *membership DMs*, a different leg.)
5. **Better fix candidates than this retry:**
   - dig #4 (x0x): drop `stop_fallback_on_raw_error` for the Welcome path → failing raw-QUIC
     chunks fall back to the gossip Critical path → then saorsa-gossip#24 matters.
   - Add an in-progress guard to `handle_welcome_fetch_request` so duplicate requests don't
     re-serve (removes the amplification regardless of retry policy).
   - Fix the transport layer if `ant_quic send failed` is a bug, not infra.

---

## 7b. UPDATE (2026-06-05) — #5 done first: the real cause is `Peer not found`, and the confound is large

Characterising `ant_quic send failed` from the existing soaks (recommended step #5) materially
reframes the diagnosis:

- **The transport error is `error=Peer not found: PeerId(...)`** — the target peer is **not in
  ant-quic's connection table at send time** (connection dropped / idle-evicted under churn),
  i.e. a **connection-lifecycle** failure, NOT raw packet loss and NOT pubsub cooling.
- **The Welcome-specific failure on the anchor:** `Welcome blob final ack wait failed: timeout
  waiting for final chunk ack >= 1; last_acked=<none>` — m2 **never ACKed any chunk**, because
  the chunks couldn't be sent to it (`Peer not found`). anchor `Peer not found` total in the
  retry window: **3,954**.
- **Confound quantified:** member `send failed` totals were **1,278 (daytime baseline) vs
  9,864 (overnight retry) — ~7.7×**, growing through the night (peak 02–03 UTC), concentrated
  on specific flapping peers. So a large part of 78%→47% is plausibly **overnight connectivity
  degradation, not the fix.** (The controlled same-day A/B is running to settle this.)

**Revised hypothesis (supersedes H-B "raw network loss"):** under sustained churn, ant-quic
connections to peers are **evicted/dropped** (the pool has `idle_evict_after_secs=300`,
`max_connections=50`); when the anchor tries to stream a Welcome to a member whose connection
was just evicted, the chunk sends fail `Peer not found` and the transfer dies. The retry can't
help (re-request still finds the peer "not found") and amplifies (each re-request re-serves).

**This shifts the best fix toward connection management, not request retry:**
- Ensure/re-establish the member connection before (and during) Welcome serve; re-dial on
  `Peer not found` instead of failing terminally.
- Dig #4 (gossip fallback for Welcome) becomes more attractive: gossip can *relay* through the
  mesh and does not require a live direct connection to the target, so it can route around a
  `Peer not found`.
- An in-progress/dedup guard (step #3) still removes the amplification regardless.

## 8. Repro / code map

- Repro: `python3 tests/e2e_treekem_membership.py --anchor sfo --member helsinki --member2
  nuremberg --iterations 150 --settle-secs 90` (testnet, API 13600). Convergence asserted by
  the member encrypting on `secure_plane=="treekem"`.
- Welcome pull: `WelcomeBlobMessage` (x0xd.rs ~5697); request side `fetch_treekem_welcome`
  (x0xd.rs ~17901, the changed fn) + `WELCOME_FETCH_TIMEOUT=90s` / new
  `WELCOME_FETCH_RETRY_INTERVAL=20s` (~17554); serve side `handle_welcome_fetch_request`
  (x0xd.rs:18031) → `stream_welcome_blob` (full Offer+chunks, no in-progress guard);
  transport config `file_transfer_send_config()` (raw-QUIC preferred, no fallback).
- Evidence files: `proofs/treekem-soak-retry-20260604T233730Z/RESULT.md` (this attempt) and
  `proofs/treekem-soak-20260604T162134Z/RESULT.md` (the 0.21.1 baseline).
- Background: `handoff/cooling-vs-welcome-fetch-2026-06-04.md` (the dig), saorsa-gossip#24
  (root cooling fix), `handoff/treekem-convergence-SECOND-OPINION-2026-06-04.md` (how the
  convergence bug was originally found).
