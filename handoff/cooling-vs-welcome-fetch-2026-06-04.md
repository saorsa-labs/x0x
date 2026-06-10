# Cooling vs critical Welcome-fetch — root mechanism + fix directions

**Date:** 2026-06-04
**For:** saorsa-gossip team (root fix) + x0x (surgical mitigation)
**Why:** the 3.5h TreeKEM churn soak (0.5.62) passed the overflow check (X0X-0074d=0
fleet-wide) but only 117/150 convergence (78%); the residual fails are transport-starvation,
not a TreeKEM/state bug. This explains exactly why. Evidence:
`proofs/treekem-soak-20260604T162134Z/RESULT.md`.

## The mechanism (verified in source, file:line)

**Two suppression layers disagree about Critical priority.**

1. **Admission layer — Critical is exempt (correct).** `AdmissionControl::admit`
   (`saorsa-gossip/crates/pubsub/src/admission.rs:359`) special-cases Critical: *always
   admit*, never consults `is_peer_cooled` (admission.rs:368-376; `is_peer_cooled` read only
   in `admit_bulk`, :431). Module doc states this is the intended contract (:18-30). So the
   `filter_peers_through_admission*` paths never drop a Critical send for cooling.

2. **Claim / Critical-gate layer — Critical IS skipped when cooled (the bug).** This runs
   *before* admission and is the real gate. `claim_send_attempt_at` (`lib.rs:2162`) returns
   **`None` whenever `suppressed_until > now`, with NO priority check**. The `None` arm
   (`lib.rs:4318-4339`) skips the send; for Critical it just records
   `record_critical_cooling()` instead of an error — but the send is dropped identically.

**0.5.62 made this strictly worse.** Commit `15fda29` ("cool peers on critical gate
saturation") added `record_critical_gate_overflow_with_context_at` (`lib.rs:2758`): when a
peer's 64-deep Critical FIFO (`OUTBOUND_CRITICAL_QUEUE_PER_PEER=64`, `lib.rs:219`) overflows,
it now **actively cools the peer** (`suppressed_until = now + cooldown`, ~`lib.rs:2786`) and
prunes it from the eager mesh. Cooldown = **30s initial, ×2 escalating to 300s max**
(`timing.rs:41,47`). The author's own test `test_x0x_0074d_gate_overflow_immediately_cools_peer`
(`lib.rs:12119`) proves it: post-overflow `is_peer_suppressed_at(target)==true` (:12160) and
the next Critical claim returns empty (:12163-12166).

**Soak signature match:** `Critical gate saturation ×156` on helsinki → each cooled the peer
≥30s → during those windows subsequent Critical sends (membership DMs + any gossip-path
Welcome frames) to that peer were skipped → `failed to fetch TreeKEM Welcome ×22`,
`timed out polling anchor ×13`, convergence > 90s budget → fail. Self-recovers when cooldown
expires.

## Welcome-blob transport specifics (x0x)

The `WelcomeBlobMessage` protocol (FetchRequest→Offer→Chunk×N→ChunkAck→Complete,
`x0xd.rs:5697`) is sent via `send_welcome_blob_message` (`x0xd.rs:17851`) →
`send_direct_with_config(..., file_transfer_send_config())`. `file_transfer_send_config()`
(`x0xd.rs:2510`) sets `prefer_raw_quic_if_connected: true` + `stop_fallback_on_raw_error: true`.
So:
- **Raw QUIC up:** Welcome rides raw QUIC, never touches pubsub cooling; fails only via
  `ant_quic send failed` (the soak's ×507) — **terminal, no gossip fallback**
  (`lib.rs:3130-3139`).
- **Raw QUIC down:** terminal — never reaches the gossip-inbox Critical path at all.

The DM inbox topic IS `TopicPriority::Critical` (`x0x/src/gossip/pubsub.rs:694,1041`). The
*direct* cooling-skip therefore bites the **membership/roster/invite/join-result DMs** that
use the **default** `direct_message_send_config()` (gossip-inbox Critical path:
`x0xd.rs:6924,6965,7432,7583,17689,17796`), while the Welcome blob itself is more exposed to
the terminal `ant_quic send failed`. A churned member often has **neither** a healthy
raw-QUIC link (→ terminal ant-quic failure) **nor** an uncooled Critical gossip path (→
Critical-skip) → the 22% miss.

## Fix directions

| # | Fix | Repo | Risk | Notes |
|---|-----|------|------|-------|
| **1** | **Make Critical truly bypass cooling at the claim/gate layer** — allow a cooled peer to still be claimed for `TopicPriority::Critical` Data sends in `claim_send_attempt_at`/its caller (`lib.rs:2162`/`4251`/`4318`). Aligns the claim layer with the admission-layer "Critical always admits" contract. | **saorsa-gossip** | med | The principled root fix. Critical is still FIFO-bounded at 64, so back-pressured not unbounded. |
| **2** | **Soften cooling-on-gate-saturation for Critical** — revert `15fda29` to "drop the one overflow, keep the peer hot", or use a short non-escalating cooldown for Critical-gate overflow. | **saorsa-gossip** | med | Reintroduces some WARN spam under overload (what 15fda29 suppressed). |
| **3** | **Bounded retry of the Welcome FetchRequest within `WELCOME_FETCH_TIMEOUT`** — `fetch_treekem_welcome` (`x0xd.rs:17901`) sends ONE FetchRequest and waits 90s on a single oneshot with no re-request. A 30s cooldown fits inside 90s, so re-issuing the FetchRequest 2-3× across the window rides out a cooldown. Responder state keys on `welcome_id` (idempotent). | **x0x** | low | Lowest-risk, most surgical; independent of gossip changes. **Recommended first.** |
| **4** | **Allow gossip-inbox fallback for the Welcome path** (don't set `stop_fallback_on_raw_error` for Welcome) so a raw-QUIC failure can still route over the Critical gossip mesh. | **x0x** | low-med | Pushes chunked base64 through pubsub fanout (file-transfer comment `x0xd.rs:2517` warns against for big files; a Welcome blob is far smaller). |

**Recommendation:** ship **#3** (x0x) first — cheap, isolated, fits the existing 90s budget;
fix **#1** (saorsa-gossip) as the correct long-term alignment, since the claim-layer skip of
cooled Critical peers directly contradicts the admission layer's documented "Critical always
admits" contract, and that contradiction is the root mechanism.

**Validation bar for any of these:** re-run the 150-iteration churn soak
(`tests/e2e_treekem_membership.py --member2 --iterations 150 --settle-secs 90`) and require
convergence ≥ ~95% with X0X-0074d=0 + invalid-epoch=0 maintained. None of these fixes should
ride the current 0.21.1 overflow-fix release — they need their own validate+soak cycle.
