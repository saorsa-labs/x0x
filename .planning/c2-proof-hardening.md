# Phase C.2 — Proof-Hardening Tracker

Status: **open** — Phase C.2 code landed in commit `5cffeb6`
(`feat(groups): phase C.2 — distributed discovery index via shard gossip`),
but final signoff requires these four positive-path proofs before C.2
can be called "strongly proven". See
`tests/proof-reports/PHASE_C2_REPORT.md` for the honest current-state
report.

Until these close, **do not** claim "C.2 fully proven" or "real
discovery proven in e2e".

---

## A. Shard-specific positive proof

**Problem.** `GET /groups/discover` merges legacy `group_card_cache`
(bridge topic `x0x.discovery.groups`) + `directory_cache` (shards) +
locally synthesised cards. Even when bob sees alice's card via that
endpoint, we cannot attribute it to the shard plane while dual-publish
remains on.

**Acceptance options (pick one):**

1. **Path-tagged discovery source.** Add an internal `source: &str` tag
   to each cache entry (`"shard" | "bridge" | "ltc" | "local"`) and
   surface it via a debug/test endpoint (e.g. `GET /groups/discover?debug=1`
   or a dedicated `/__debug/discovery-source`). E2E asserts bob sees
   source = `"shard"` for alice's `PublicDirectory` card.
2. **`/groups/discover/nearby` as authoritative shard witness.** Make
   this endpoint read **only** from `directory_cache` (no bridge, no
   local synthesised cards). The existing code is already close — just
   remove the local-synthesised merge. Then e2e asserts bob's nearby
   shows the group.
3. **Bridge-disabled variant.** Add a config flag
   `--no-bridge-discovery` (or env `X0X_DISABLE_BRIDGE_DISCOVERY=1`)
   that skips the legacy publish path. Run the C.2 section with this
   flag on. If bob sees the card, it must have come via shards.

Recommend option 2 for lowest friction. The bridge topic stays alive
for back-compat with pre-C.2 peers, but the proof endpoint is clean.

---

## B. Live anti-entropy repair proof

**Problem.** `Digest`/`Pull` logic is unit- and integration-tested,
not live-proven. An uninformed reviewer cannot distinguish "AE works"
from "initial card happened to arrive".

**Acceptance.** E2E scenario:

1. Alice creates `PublicDirectory` group and seals (first card goes out).
2. Bob is either:
   a. not subscribed yet, OR
   b. disconnected / no messages received (simulate by subscribing
      AFTER alice publishes).
3. Bob subscribes to the relevant shard.
4. Without any further publishes from alice, within the next digest
   interval (60s + jitter) bob receives a `Digest` from a peer that
   has the card, emits a `Pull`, and caches the card.
5. Proof: bob's `/groups/discover/nearby` shows the group.

Implementation may require a shorter `DIRECTORY_DIGEST_INTERVAL_SECS`
for test runs (e.g. env-overridable to 5s).

---

## C. LTC positive + negative delivery proof

**Problem.** We proved LTC does not leak to public nearby. We have NOT
proven Trusted contacts actually receive the card, nor that
Unknown/Blocked peers do not.

**Acceptance.** E2E scenario with three daemons alice / bob / charlie:

1. Alice adds bob as `Trusted`, charlie as `Unknown` (or `Blocked`).
2. Alice creates `ListedToContacts` group and seals.
3. Within 30s (configurable) bob's local `group_card_cache` contains
   alice's card (check via `GET /groups/cards/<group_id>` on bob).
4. Bob's `GET /groups/discover/nearby` does NOT show the LTC group
   (contact-scoped, not public).
5. Charlie's `GET /groups/cards/<group_id>` returns 404 (never
   received the LTC direct-msg).
6. Charlie's `GET /groups/discover/nearby` does not show it.

Note: LTC delivery currently fires on every authority seal. If bob is
offline during the seal, he misses it. A follow-up is to store-and-
forward on reconnect — that's also proof-debt if the test requires
offline-robust delivery; for v1 we can gate the test on bob-online-at-seal.

---

## D. Subscription persistence across restart

**Problem.** JSON round-trip is logic-tested. Restart resubscribe is
not live-tested.

**Acceptance.** E2E scenario:

1. Bob subscribes to a tag shard, then a name shard, then an id shard.
2. `GET /groups/discover/subscriptions` returns 3.
3. Stop bob's daemon gracefully.
4. Verify `~/.x0x/directory-subscriptions.json` on disk contains 3
   entries.
5. Restart bob's daemon.
6. Within the jitter window + 10s slack, `GET /groups/discover/subscriptions`
   returns 3 again.
7. Alice publishes a card on one of bob's subscribed shards; bob's
   cache picks it up (uses path-tagged proof from A).

---

## Execution notes

- These four proofs are **e2e-shaped** and will live in a new section
  of `tests/e2e_named_groups.sh`, or preferably a dedicated
  `tests/e2e_c2_convergence.sh` that can run in isolation without the
  rest of the named-groups suite's pre-existing environmental noise.
- Acceptance option 2 for (A) is the cheapest to add and unblocks the
  positive proofs for (B) and (D) by making `/discover/nearby` a
  shard-plane-only witness.
- (C) requires either a contact-bootstrap step in the e2e or importing
  contact cards explicitly via `POST /contacts/add`.
- Proof-hardening should land as its own commit:
  `test(groups): phase C.2 proof-hardening — live shard convergence + LTC + restart`

## Signoff gate

C.2 is not signed off until all four acceptance scenarios pass in **3
consecutive clean runs** archived under
`tests/proof-reports/named-groups-c2-hardening-run{1,2,3}.log`. At that
point `PHASE_C2_REPORT.md` can be updated to strike the proof-debt
disclaimers, and this tracker closed.

Tracking lives here until that happens.
