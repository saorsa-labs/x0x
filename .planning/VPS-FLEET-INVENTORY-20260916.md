# VPS fleet inventory for credited / live e2e (PREFLIGHT blocker 4)

**Source:** `TEST_SUITE_GUIDE.md`, `tests/e2e_deploy.sh`, `tests/x0x_network.py`  
**Tip:** e178834 / 0.45.0  
**Clarification (David via Jarvis, 2026-09-16):** credited/live e2e uses the **VPS fleet**, not the Grok Bot Linux sandbox.

## Hosts (same IPs for testnet + prod; ports/services differ)

| Name | IP | Region | Provider | Notes |
|---|---|---|---|---|
| nyc | 142.93.199.50 | New York, US | DigitalOcean | Anchor for §7b mesh tunnel; saorsa-2 |
| sfo | 147.182.234.192 | San Francisco, US | DigitalOcean | saorsa-3 |
| helsinki | 65.21.157.229 | Helsinki, FI | Hetzner | saorsa-6 |
| nuremberg | 116.203.101.172 | Nuremberg, DE | Hetzner | saorsa-7 |
| singapore | 152.42.210.67 | Singapore, SG | DigitalOcean | saorsa-8 |
| sydney | 170.64.176.102 | Sydney, AU | DigitalOcean | saorsa-9 |

## Networks on each host

| Network | UDP gossip | API | systemd unit | Token file (local) |
|---|---|---|---|---|
| **testnet** (default for e2e) | 6483 | 13600 | `x0xd-testnet.service` (+ test runner `x0x-test-runner-testnet`) | `tests/.vps-tokens-test.env` |
| **prod** | 5483 | 12600 | `x0xd.service` | `tests/.vps-tokens-prod.env` |

Same six IPs carry **both** prod and testnet daemons (plus historically a third process on some measurements — see #656).

## Co-tenant risks (relevant to credited soak / live e2e)

1. **3 daemons × 2 vCPU** pattern on bootstrap hosts makes per-daemon `%CPU` invalid (#656 / PR #733 docs). Credited acceptance must use bytes/s, verify/s, delivery matrices — not pcpu.
2. **Prod + testnet co-resident:** a testnet deploy/restart (`e2e_deploy.sh`) can disturb the host while **prod** is live. Prefer testnet-only operations; avoid `--network prod` unless explicitly authorized. Rolling restarts use ~15s stagger to reduce bootstrap storms.
3. **Shared public mesh:** fleet e2e (§7b) is behavioural evidence on the live mesh; credited modern-only soak is a **separate** sealed loopback path — still needs a Linux host with `sudo -n` / netns. If credited runs *on* a VPS, pick one host and quarantine load (no concurrent 3-way overload), or use a dedicated runner node — **confirm with Jarvis which VPS (or dedicated) is the credited runner**.
4. **Token harvest:** `e2e_deploy.sh` overwrites local token files via SSH — treat as fleet-changing.
5. **APAC/Hetzner latency** under load historically correlated with API timeouts (#656); prefer NYC/SFO for orchestrator anchor when possible (§7b default NYC).

## Recommended next ask for Jarvis

- Which **single** VPS (or new dedicated host) is the credited PREFLIGHT runner with passwordless `sudo -n`?
- Confirm testnet-only for dry-fence / soak (prod untouched).
