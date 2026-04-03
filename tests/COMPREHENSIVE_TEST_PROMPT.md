# x0x Comprehensive End-to-End Certification Test

## Mission

Certify that **100% of x0x functionality** works correctly across **all 5 interfaces** (CLI, curl/REST, embedded GUI, communitas Dioxus, communitas Swift) and **all 6 VPS bootstrap nodes**, with every function tested a **minimum of 5 times** across different contexts. This is a full-stack, cross-interface, cross-network certification.

---

## Test Infrastructure

### Interfaces Under Test

| # | Interface | How to Access | Auth |
|---|-----------|--------------|------|
| 1 | **CLI** (`x0x`) | `x0x [--name instance] <command>` | Auto-discovers token |
| 2 | **curl (REST API)** | `curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:$PORT/...` | Bearer token |
| 3 | **GUI** (embedded HTML) | `x0x gui` → Chrome, use Claude Chrome MCP tools | Browser session |
| 4 | **Dioxus app** | `cd ../communitas && cargo run -p communitas-dioxus` | Auto-discovers x0xd |
| 5 | **Swift app** | Open `../communitas/communitas-apple` in Xcode, build & run | Auto-discovers x0xd |

### Network Nodes Under Test

| Node | IP | Region | SSH |
|------|----|---------|----|
| saorsa-2 | 142.93.199.50 | NYC, US | `ssh root@142.93.199.50` |
| saorsa-3 | 147.182.234.192 | SFO, US | `ssh root@147.182.234.192` |
| saorsa-6 | 65.21.157.229 | Helsinki, FI | `ssh root@65.21.157.229` |
| saorsa-7 | 116.203.101.172 | Nuremberg, DE | `ssh root@116.203.101.172` |
| saorsa-8 | 149.28.156.231 | Singapore, SG | `ssh root@149.28.156.231` |
| saorsa-9 | 45.77.176.184 | Tokyo, JP | `ssh root@45.77.176.184` |

VPS API: port 12600 (localhost only, SSH tunnel required). Token: `/root/.local/share/x0x/api-token`

### Local Test Instances

Spawn **3 named local instances** to test multi-agent scenarios:

```bash
# Instance 1: Alice (port 12701)
x0xd --name alice --api-port 12701 &
ALICE_TOKEN=$(cat ~/.local/share/x0x-alice/api-token)

# Instance 2: Bob (port 12702)
x0xd --name bob --api-port 12702 &
BOB_TOKEN=$(cat ~/.local/share/x0x-bob/api-token)

# Instance 3: Charlie (port 12703, seedless bootstrap for isolation test)
x0xd --name charlie --api-port 12703 --no-bootstrap &
CHARLIE_TOKEN=$(cat ~/.local/share/x0x-charlie/api-token)
```

---

## Phase 0: Pre-Flight & Infrastructure (20 assertions)

### 0.1 Build Verification
- [ ] `cargo build --release` succeeds with zero warnings
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` passes
- [ ] `cargo nextest run --all-features --workspace` — all tests pass
- [ ] `cargo doc --all-features --no-deps` — zero doc warnings
- [ ] Release binary exists and runs: `./target/release/x0x --version`
- [ ] Release daemon exists: `./target/release/x0xd --version`

### 0.2 VPS Health (all 6 nodes)
For EACH of the 6 VPS nodes:
- [ ] SSH accessible: `ssh -o ConnectTimeout=5 root@$IP 'hostname'`
- [ ] Service running: `ssh root@$IP 'systemctl is-active x0x-bootstrap'`
- [ ] Health endpoint: `ssh root@$IP 'curl -s http://127.0.0.1:12600/health'` returns `{"ok":true}`
- [ ] Version matches expected: check `/health` version field
- [ ] Peers connected: `ssh root@$IP 'curl -s http://127.0.0.1:12600/peers'` shows peers > 0

### 0.3 Local Instance Startup
- [ ] Alice starts and responds to health check
- [ ] Bob starts and responds to health check
- [ ] Charlie starts (seedless) and responds to health check
- [ ] All three have distinct agent IDs
- [ ] All three have distinct machine IDs

---

## Phase 1: Identity & Agent (100 assertions — 20 functions × 5 each)

### 1.1 Health Check (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | CLI | `x0x --name alice health` | `ok: true`, version present |
| 2 | curl | `GET /health` on alice | JSON `{"ok":true,"version":"..."}` |
| 3 | GUI | Open GUI, check status bar | Green connection indicator |
| 4 | VPS (NYC) | `curl /health` via SSH tunnel | `ok: true` |
| 5 | VPS (Tokyo) | `curl /health` via SSH tunnel | `ok: true` |

### 1.2 Agent Identity (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | CLI | `x0x --name alice agent` | agent_id, machine_id returned |
| 2 | curl | `GET /agent` on bob | agent_id, machine_id, addresses |
| 3 | GUI | Dashboard → identity card | Shows agent ID, machine ID |
| 4 | Dioxus | Dashboard view | Displays local agent identity |
| 5 | Swift | Dashboard view | Displays local agent identity |

### 1.3 Agent Card Generation (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | CLI | `x0x --name alice agent card` | Returns card with `x0x://agent/...` link |
| 2 | curl | `GET /agent/card` on alice | JSON with card_data, link |
| 3 | CLI | `x0x --name bob agent card` | Different card from alice |
| 4 | GUI | Dashboard → Share Identity | Card displayed with copy button |
| 5 | VPS | `curl /agent/card` on NYC node | VPS agent card returned |

### 1.4 Agent Card Import (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | CLI | Export alice card → import to bob via CLI | Bob's contacts contain alice |
| 2 | curl | `POST /agent/card/import` alice card to bob | 200 OK, contact created |
| 3 | curl | `POST /agent/card/import` bob card to alice | 200 OK, contact created |
| 4 | GUI | Import contact modal → paste card | Contact appears in sidebar |
| 5 | curl | Import VPS node card to alice | VPS node in alice contacts |

### 1.5 Identity Announcement (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | CLI | `x0x --name alice announce` | Success, identity broadcast |
| 2 | curl | `POST /announce` on bob | 200 OK |
| 3 | curl | `POST /announce` on alice | Re-announce succeeds |
| 4 | VPS | `curl -X POST /announce` on NYC | VPS re-announces |
| 5 | CLI | `x0x --name charlie announce` | Charlie announces (even seedless) |

### 1.6 User ID (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | CLI | `x0x --name alice agent user-id` | Returns user_id or null |
| 2 | curl | `GET /agent/user-id` on alice | JSON response |
| 3 | curl | `GET /agent/user-id` on bob | JSON response |
| 4 | VPS | `GET /agent/user-id` on Helsinki | JSON response |
| 5 | VPS | `GET /agent/user-id` on Singapore | JSON response |

### 1.7 Status (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | CLI | `x0x --name alice status` | Uptime, version, peer count |
| 2 | curl | `GET /status` on bob | Full status JSON |
| 3 | GUI | Status bar | Shows peer count, connection state |
| 4 | Dioxus | Dashboard → status section | Connectivity info displayed |
| 5 | VPS | `GET /status` on Nuremberg | VPS status with uptime |

### 1.8 Constitution (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | CLI | `x0x --name alice constitution` | Markdown constitution text |
| 2 | curl | `GET /constitution` on alice | Markdown text |
| 3 | curl | `GET /constitution/json` on alice | JSON with version metadata |
| 4 | GUI | Constitution page | Rendered constitution |
| 5 | VPS | `GET /constitution` on SFO | Same constitution on VPS |

### 1.9 Network Status (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | CLI | `x0x --name alice peers` | Peer list with IDs |
| 2 | curl | `GET /peers` on alice | JSON peer array |
| 3 | curl | `GET /network/status` on alice | NAT type, addresses, relay info |
| 4 | curl | `GET /network/bootstrap-cache` on bob | Cache stats |
| 5 | GUI | Network page | Peer visualization |

### 1.10 Shutdown & Restart (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | CLI | `x0x --name charlie stop` then restart | Clean shutdown, clean restart |
| 2 | curl | `POST /shutdown` on charlie | 200 OK, process exits |
| 3 | CLI | Start charlie again | Fresh instance, new session |
| 4 | curl | Health check after restart | `ok: true` |
| 5 | CLI | Verify agent_id preserved after restart | Same agent_id (keys persisted) |

### 1.11 Speakable Identity Words (5×)

Four-word speakable identities encode agent IDs into memorable 4-word phrases via `four-word-networking::IdentityEncoder`. The CLI injects `identity_words` and `location_words` client-side into JSON responses (the REST API does not return these fields — they are computed by the CLI binary).

| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | CLI | `x0x --name alice agent` | Response includes `identity_words` field (4 space-separated words) |
| 2 | CLI | `x0x --name bob agent` | Different `identity_words` from alice |
| 3 | CLI | `x0x --name alice status` | Response includes `identity_words` (agent) and `location_words` array (one entry per external address, each with `addr` and `location_words` fields) |
| 4 | CLI | `x0x --name alice agent` then `x0x --name alice status` | `identity_words` matches between both commands (same agent_id) |
| 5 | CLI | `x0x --json --name alice agent` | JSON output contains `"identity_words":"word1 word2 word3 word4"` string |

### 1.12 Introduction Card (5×)

Trust-gated introduction card served at `GET /introduction`. Filters visible fields and services by the requesting peer's trust level.

| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | CLI | `x0x --name alice agent introduction` | Card with `identity_words`, `services`, `display_name` |
| 2 | curl | `GET /introduction` on alice (no `?peer=`) | Unknown-level card: agent_id, identity_words, public services only, no machine_id |
| 3 | curl | `GET /introduction?peer=$BOB_HEX` where bob is `known` | Known-level card: includes machine_id, certificate status, broader services |
| 4 | curl | `GET /introduction?peer=$TRUSTED_HEX` | Trusted-level card: all fields, all services, signature |
| 5 | curl | `GET /introduction?peer=$BLOCKED_HEX` | 403 Forbidden, `{"error":"blocked"}` |

### 1.13 Find Agent by Identity Words (5×)

`x0x find` decodes 4 identity words to a 6-byte agent ID prefix and searches discovered agents. Requires the daemon to be running (calls `ensure_running` before validation).

| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | CLI | Get bob's identity words from `x0x --name bob agent`, then `x0x --name alice find <bob's 4 words>` | Finds bob with matching `agent_id` prefix, output includes `identity_words` |
| 2 | CLI | `x0x --name alice find alpha beta gamma delta` (valid dictionary words, no matching agent) | Stderr: "No agents found matching those words." |
| 3 | CLI | `x0x --name alice find <agent words> @ <user words>` (9 tokens with `@` separator) | Full identity search filters by both agent_id and user_id prefix |
| 4 | CLI | `x0x --name alice find notaword notaword notaword notaword` (words not in dictionary) | Error: "failed to decode agent identity words — check spelling" |
| 5 | CLI | `x0x --name alice find too few` (only 2 words) | Error: "agent identity requires exactly 4 words (got 2)" |

### 1.14 Connect by Location Words (5×)

`x0x connect` decodes 4 location words to an IP:port address via `FourWordAdaptiveEncoder`, then searches discovered agents for a matching address and connects. Word count is validated before daemon check.

| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | CLI | Get location words from `x0x --name bob status` (`location_words[0].location_words`), then `x0x --name alice connect <4 words>` | Decodes to bob's address, finds bob in discovered agents, connects |
| 2 | CLI | `x0x --name alice connect notaword notaword notaword notaword` (words not in dictionary) | Error: "failed to decode location words — check spelling" |
| 3 | CLI | `x0x --name alice connect word1 word2 word3` (only 3 words) | Error: "location words require exactly 4 words (got 3)" (fails before daemon check) |
| 4 | CLI | `x0x --name alice connect <valid words for address with no discovered agent>` | Error: "no discovered agent at {addr}. Make sure the target agent has announced..." |
| 5 | VPS | Get VPS node location words from `x0x status` on VPS, use from local `x0x connect` | Cross-network connect via location words succeeds |

---

## Phase 2: Contacts & Trust (100 assertions — 20 functions × 5 each)

### 2.1 Add Contact (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | CLI | `x0x --name alice contacts add --agent-id $BOB_ID` | Contact added |
| 2 | curl | `POST /contacts` on bob with alice's ID | 200 OK |
| 3 | GUI | People → Add Contact modal | Contact appears |
| 4 | Dioxus | People view → add contact | Contact in list |
| 5 | Swift | Contacts view → add | Contact displayed |

### 2.2 List Contacts (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | CLI | `x0x --name alice contacts list` | Shows bob |
| 2 | curl | `GET /contacts` on alice | JSON array with bob |
| 3 | GUI | People page | Contact list rendered |
| 4 | Dioxus | People view | Contact list shown |
| 5 | Swift | Contacts view | Contact list shown |

### 2.3 Update Contact Trust (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | CLI | `x0x --name alice contacts trust --agent-id $BOB_ID --level trusted` | Trust updated |
| 2 | curl | `POST /contacts/trust` on alice | 200 OK |
| 3 | curl | `PATCH /contacts/$BOB_ID` on alice | Trust level changed |
| 4 | GUI | Contact detail → change trust level | Badge updates |
| 5 | curl | Set trust to `known`, verify, set to `trusted` | Round-trip works |

### 2.4 Trust Evaluation (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | curl | `POST /trust/evaluate` with trusted agent+machine | `Accept` |
| 2 | curl | `POST /trust/evaluate` with blocked agent | `Reject` |
| 3 | curl | `POST /trust/evaluate` with unknown agent | `Unknown` |
| 4 | curl | `POST /trust/evaluate` with pinned+wrong machine | `RejectMachineMismatch` |
| 5 | curl | `POST /trust/evaluate` with known agent | `AcceptWithFlag` |

### 2.5 Machine Records (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | curl | `GET /contacts/$BOB_ID/machines` | Machine list |
| 2 | curl | `POST /contacts/$BOB_ID/machines` | Machine added |
| 3 | curl | `POST /contacts/$BOB_ID/machines/$MID/pin` | Machine pinned |
| 4 | curl | `DELETE /contacts/$BOB_ID/machines/$MID/pin` | Machine unpinned |
| 5 | curl | `DELETE /contacts/$BOB_ID/machines/$MID` | Machine removed |

### 2.6 Contact Revocation (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | curl | `POST /contacts/$AGENT/revoke` with reason | Revoked |
| 2 | curl | `GET /contacts/$AGENT/revocations` | Revocation record present |
| 3 | CLI | Revoke a contact via CLI | Success |
| 4 | curl | Re-add revoked contact | Can re-add |
| 5 | curl | Check revocation history persists | History intact |

### 2.7 Remove Contact (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | CLI | `x0x --name alice contacts remove --agent-id $TARGET` | Removed |
| 2 | curl | `DELETE /contacts/$TARGET` on bob | 200 OK |
| 3 | GUI | Contact → remove | Contact disappears |
| 4 | curl | Verify contact no longer in list | Not in `GET /contacts` |
| 5 | curl | Re-add removed contact | Can re-add |

### 2.8 Block Contact (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | curl | Set trust to `blocked` on alice for target | Blocked |
| 2 | curl | Verify blocked agent filtered from discovery | Not in discovered list |
| 3 | curl | Verify blocked agent's messages filtered | Messages dropped |
| 4 | curl | Unblock (set to `known`) | Agent visible again |
| 5 | CLI | Block and unblock via CLI | Round-trip works |

---

## Phase 3: Discovery & Presence (75 assertions — 15 functions × 5 each)

### 3.1 Discovered Agents (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | CLI | `x0x --name alice agents list` | Shows discovered agents |
| 2 | curl | `GET /agents/discovered` on alice | JSON array |
| 3 | curl | `GET /agents/discovered/$BOB_ID` on alice | Bob's details |
| 4 | GUI | Dashboard → discovered agents | Agent cards displayed |
| 5 | VPS | `GET /agents/discovered` on NYC | Shows bootstrap peers |

### 3.2 Presence Online (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | CLI | `x0x --name alice presence online` | Online agent list |
| 2 | curl | `GET /presence/online` on alice | JSON array of agent IDs |
| 3 | curl | `GET /presence` on bob | Alias works same |
| 4 | GUI | People → online indicator | Green dots on online agents |
| 5 | VPS | `GET /presence/online` on Helsinki | VPS sees online agents |

### 3.3 FOAF Discovery (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | CLI | `x0x --name alice presence foaf` | FOAF-discovered agents |
| 2 | curl | `GET /presence/foaf` on alice | Agent IDs from random walk |
| 3 | curl | `GET /presence/foaf` on bob | Different walk results possible |
| 4 | VPS | `GET /presence/foaf` on Tokyo | VPS FOAF discovery |
| 5 | VPS | `GET /presence/foaf` on Singapore | Cross-region FOAF |

### 3.4 Find Agent by ID (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | CLI | `x0x --name alice presence find $BOB_ID` | Found or not-found |
| 2 | curl | `GET /presence/find/$BOB_ID` on alice | Agent details |
| 3 | curl | `GET /presence/find/$ALICE_ID` on bob | Cross-lookup works |
| 4 | curl | `GET /presence/find/$NONEXISTENT` | 404 or not-found |
| 5 | VPS | `GET /presence/find/$LOCAL_ID` on NYC | VPS finds local agent |

### 3.5 Presence Status (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | CLI | `x0x --name alice presence status $BOB_ID` | Status info |
| 2 | curl | `GET /presence/status/$BOB_ID` on alice | JSON with last_seen |
| 3 | curl | `GET /presence/status/$ALICE_ID` on bob | Alice's status |
| 4 | VPS | `GET /presence/status/$VPS_ID` on NYC | VPS peer status |
| 5 | curl | Status of unknown agent | Appropriate response |

### 3.6 Presence Events SSE (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | curl | `GET /presence/events` on alice (SSE stream) | Online/offline events |
| 2 | CLI | `x0x --name alice presence events` | Stream events |
| 3 | GUI | Real-time presence updates | Badge changes live |
| 4 | Dioxus | Presence badges update | Online/offline transitions |
| 5 | Swift | Presence indicators | Real-time updates |

### 3.7 Agent Reachability (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | curl | `GET /agents/reachability/$BOB_ID` on alice | NAT info, addresses |
| 2 | curl | `GET /agents/reachability/$VPS_ID` on alice | VPS reachability |
| 3 | CLI | Check reachability for discovered agent | Info returned |
| 4 | curl | Reachability for unknown agent | Error response |
| 5 | VPS | Cross-VPS reachability check | Direct/coordinated info |

### 3.8 Find Agents by User (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | curl | `GET /users/$USER_ID/agents` | Agent list for user |
| 2 | curl | Query for user with no agents | Empty list |
| 3 | CLI | Find agents by user ID | Results shown |
| 4 | curl | Query own user ID | Own agent in results |
| 5 | curl | Query on different instance | Same results |

---

## Phase 4: Messaging — Pub/Sub (50 assertions — 10 functions × 5 each)

### 4.1 Subscribe to Topic (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | CLI | `x0x --name alice subscribe --topic test-1` | Subscription ID returned |
| 2 | curl | `POST /subscribe` on bob, topic `test-1` | subscription_id in response |
| 3 | curl | Subscribe alice to `test-2` | Different subscription |
| 4 | curl | Subscribe bob to `test-2` | Both on same topic |
| 5 | VPS | Subscribe NYC node to `test-vps` | VPS subscription works |

### 4.2 Publish to Topic (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | CLI | `x0x --name alice publish --topic test-1 --message "hello"` | Published |
| 2 | curl | `POST /publish` on bob, topic `test-1`, payload "world" | 200 OK |
| 3 | GUI | Space → send message | Message published to topic |
| 4 | Dioxus | Channel → send message | Published via gossip |
| 5 | Swift | Channel → send message | Published via gossip |

### 4.3 Receive on Topic (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | curl | SSE `GET /events` on bob after alice publishes | Message received |
| 2 | curl | SSE on alice after bob publishes | Cross-direction works |
| 3 | GUI | Space chat after publish | Message appears in feed |
| 4 | Dioxus | Channel after publish | Message in conversation |
| 5 | Swift | Channel after publish | Message in conversation |

### 4.4 Unsubscribe (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | CLI | `x0x --name alice unsubscribe --id $SUB_ID` | Unsubscribed |
| 2 | curl | `DELETE /subscribe/$SUB_ID` on bob | 200 OK |
| 3 | curl | Publish after unsubscribe | No events received |
| 4 | curl | Re-subscribe to same topic | New subscription works |
| 5 | curl | Unsubscribe non-existent ID | Error response |

### 4.5 Cross-Network Pub/Sub (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | Local→VPS | Alice publishes, NYC receives | Cross-network delivery |
| 2 | VPS→Local | NYC publishes, alice receives | Reverse direction |
| 3 | VPS→VPS | NYC publishes, Tokyo receives | Cross-continent |
| 4 | Multi-sub | All 3 local + 2 VPS subscribe, alice publishes | All 5 receive |
| 5 | Local→VPS | Bob publishes, Helsinki + Singapore receive | Multi-region fan-out |

---

## Phase 5: Direct Messaging (50 assertions)

### 5.1 Connect to Agent (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | CLI | `x0x --name alice direct connect --agent-id $BOB_ID` | Connected |
| 2 | curl | `POST /agents/connect` on alice to bob | ConnectOutcome returned |
| 3 | curl | `POST /agents/connect` on bob to alice | Bidirectional |
| 4 | curl | Connect to VPS node | Direct or coordinated outcome |
| 5 | curl | Connect to non-existent agent | Error response |

### 5.2 Send Direct Message (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | CLI | `x0x --name alice direct send --to $BOB_ID --message "hi"` | Sent |
| 2 | curl | `POST /direct/send` on alice to bob | 200 OK |
| 3 | GUI | DM conversation → send | Message sent |
| 4 | Dioxus | DM view → compose & send | Delivered |
| 5 | Swift | Direct message → send | Delivered |

### 5.3 Receive Direct Message (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | curl | SSE `GET /direct/events` on bob | Alice's message arrives |
| 2 | curl | SSE on alice after bob sends | Bob's reply arrives |
| 3 | GUI | DM conversation | Incoming message appears |
| 4 | Dioxus | DM view | Real-time message receipt |
| 5 | Swift | DM view | Real-time message receipt |

### 5.4 List Direct Connections (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | CLI | `x0x --name alice direct connections` | Bob listed |
| 2 | curl | `GET /direct/connections` on alice | JSON array |
| 3 | curl | `GET /direct/connections` on bob | Alice listed |
| 4 | GUI | Network → connections | Connection list |
| 5 | curl | After disconnect, connection removed | Clean state |

### 5.5 Cross-Network Direct Messaging (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | Local→VPS | Alice sends direct to NYC node | Delivered |
| 2 | VPS→Local | NYC sends direct to alice | Received |
| 3 | VPS→VPS | NYC sends to Tokyo | Cross-continent DM |
| 4 | Local→VPS | Bob sends to Helsinki | European delivery |
| 5 | VPS→VPS | Singapore sends to Nuremberg | Asia→Europe DM |

### 5.6 Direct Message WebSocket (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | curl | Connect WS `/ws/direct` on alice | WebSocket opens |
| 2 | curl | Send DM, verify WS receives it | Real-time delivery |
| 3 | GUI | DM conversation live updates | Messages appear instantly |
| 4 | curl | `GET /ws/sessions` | Session listed |
| 5 | curl | Close WS, verify cleanup | Session removed |

---

## Phase 6: MLS Encrypted Groups (50 assertions)

### 6.1 Create MLS Group (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | CLI | `x0x --name alice groups create --name "test-mls"` | Group ID returned |
| 2 | curl | `POST /mls/groups` on alice | 200 OK, group_id |
| 3 | curl | `POST /mls/groups` on bob | Different group |
| 4 | VPS | Create MLS group on NYC | VPS group created |
| 5 | curl | Create with same name | Allowed (different IDs) |

### 6.2 Add Member (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | curl | `POST /mls/groups/$GID/members` add bob to alice's group | Member added |
| 2 | curl | Add charlie to alice's group | Third member |
| 3 | curl | Add VPS node to group | Remote member |
| 4 | curl | Add already-present member | Error or idempotent |
| 5 | CLI | Add member via CLI | Success |

### 6.3 Remove Member (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | curl | `DELETE /mls/groups/$GID/members/$CHARLIE_ID` | Removed |
| 2 | curl | Re-add charlie after removal | Can rejoin |
| 3 | curl | Remove non-member | Error response |
| 4 | curl | Remove self | Appropriate behavior |
| 5 | CLI | Remove member via CLI | Success |

### 6.4 Encrypt/Decrypt (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | curl | Alice encrypts → bob decrypts | Plaintext matches |
| 2 | curl | Bob encrypts → alice decrypts | Bidirectional |
| 3 | curl | Encrypt with non-member → cannot decrypt | Fails correctly |
| 4 | curl | Multiple encrypt/decrypt cycles | All succeed |
| 5 | curl | Large payload encrypt/decrypt | Works for big data |

### 6.5 Welcome Message (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | curl | `POST /mls/groups/$GID/welcome` for bob | Welcome blob returned |
| 2 | curl | Welcome for charlie | Different welcome |
| 3 | curl | Welcome for non-member | Error |
| 4 | curl | Welcome for VPS node | Remote welcome |
| 5 | curl | Multiple welcomes for same member | Idempotent or error |

### 6.6 List/Get MLS Groups (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | CLI | `x0x --name alice groups list` | Groups listed |
| 2 | curl | `GET /mls/groups` on alice | JSON array |
| 3 | curl | `GET /mls/groups/$GID` on alice | Group details, members |
| 4 | curl | Get non-existent group | 404 |
| 5 | curl | List after create/delete cycle | Accurate list |

---

## Phase 7: Named Groups & Spaces (75 assertions)

### 7.1 Create Named Group (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | CLI | `x0x --name alice group create --name "Alpha Space"` | Group created |
| 2 | curl | `POST /groups` on alice | 200 OK, group_id |
| 3 | GUI | Spaces → Create Space modal | Space appears in sidebar |
| 4 | Dioxus | Create Space dialog | Space created, navigated to |
| 5 | Swift | Create Space | Space in sidebar |

### 7.2 List Named Groups (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | CLI | `x0x --name alice group list` | Shows "Alpha Space" |
| 2 | curl | `GET /groups` on alice | JSON array |
| 3 | GUI | Sidebar spaces section | Groups listed |
| 4 | Dioxus | Sidebar | Groups shown |
| 5 | Swift | Sidebar | Groups shown |

### 7.3 Group Info (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | CLI | `x0x --name alice group info --id $GID` | Full details |
| 2 | curl | `GET /groups/$GID` on alice | JSON with name, members, creator |
| 3 | GUI | Click space → info | Details panel |
| 4 | Dioxus | Space view | Group details displayed |
| 5 | Swift | Space view | Group details displayed |

### 7.4 Generate Invite (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | CLI | `x0x --name alice group invite --id $GID` | Invite link/token |
| 2 | curl | `POST /groups/$GID/invite` on alice | Invite data returned |
| 3 | GUI | Space → Invite → copy link | Invite link generated |
| 4 | Dioxus | Space → invite button | Link generated |
| 5 | Swift | Space → invite | Link generated |

### 7.5 Join Group via Invite (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | CLI | Bob joins alice's group via invite token | Success |
| 2 | curl | `POST /groups/join` on bob with alice's invite | 200 OK |
| 3 | GUI | Join Space modal → paste invite | Space appears |
| 4 | Dioxus | Join via invite link | Space joined |
| 5 | Swift | Join via invite link | Space joined |

### 7.6 Set Display Name in Group (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | curl | `PUT /groups/$GID/display-name` on alice | Name set |
| 2 | curl | Set bob's display name | Different name |
| 3 | CLI | Set display name via CLI | Success |
| 4 | curl | Change existing display name | Updated |
| 5 | curl | Verify display name in group info | Reflected |

### 7.7 Leave Group (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | CLI | `x0x --name bob group leave --id $GID` | Left group |
| 2 | curl | `DELETE /groups/$GID` on bob | 200 OK |
| 3 | GUI | Space → Leave | Space removed from sidebar |
| 4 | curl | Rejoin after leave (new invite) | Can rejoin |
| 5 | curl | Verify member count decremented | Accurate count |

### 7.8 Cross-Network Named Groups (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | Local→VPS | Alice creates group, NYC joins | Cross-network group |
| 2 | VPS→Local | VPS creates group, bob joins | Reverse direction |
| 3 | Mixed | Group with alice + bob + 2 VPS nodes | Multi-party |
| 4 | curl | All members see each other in group info | Consistent view |
| 5 | curl | Leave/rejoin across network | Works reliably |

---

## Phase 8: CRDT Task Lists (50 assertions)

### 8.1 Create Task List (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | CLI | `x0x --name alice tasks create --name "Sprint 1"` | List created |
| 2 | curl | `POST /task-lists` on alice | list_id returned |
| 3 | GUI | Kanban → create board | Board created |
| 4 | Dioxus | Kanban view → create | List created |
| 5 | Swift | Board view → create | List created |

### 8.2 Add Task (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | CLI | `x0x --name alice tasks add --list $LID --title "Task 1"` | Task added |
| 2 | curl | `POST /task-lists/$LID/tasks` on alice | task_id returned |
| 3 | curl | Add 3 more tasks | All created |
| 4 | GUI | Kanban → add card | Card appears |
| 5 | Dioxus | Add task to board | Task shown |

### 8.3 List Tasks (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | CLI | `x0x --name alice tasks show --list $LID` | All tasks listed |
| 2 | curl | `GET /task-lists/$LID/tasks` on alice | JSON array |
| 3 | GUI | Kanban board | Cards visible |
| 4 | Dioxus | Board view | Tasks displayed |
| 5 | Swift | Board view | Tasks displayed |

### 8.4 Claim Task (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | CLI | `x0x --name alice tasks claim --list $LID --task $TID` | Claimed |
| 2 | curl | `PATCH /task-lists/$LID/tasks/$TID` action=claim on bob | Claimed by bob |
| 3 | GUI | Kanban → drag to "In Progress" | Card moves |
| 4 | curl | Verify claimed_by field | Correct agent_id |
| 5 | curl | Claim already-claimed task | Appropriate response |

### 8.5 Complete Task (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | CLI | `x0x --name alice tasks complete --list $LID --task $TID` | Completed |
| 2 | curl | `PATCH /task-lists/$LID/tasks/$TID` action=complete | Done |
| 3 | GUI | Kanban → drag to "Done" | Card moves |
| 4 | curl | Verify completed_by field | Correct agent_id |
| 5 | curl | Complete unclaimed task | Appropriate response |

### 8.6 CRDT Convergence (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | curl | Alice adds task, bob sees it via gossip | Converged |
| 2 | curl | Bob claims task, alice sees claim | Converged |
| 3 | curl | Both add tasks concurrently | Both appear |
| 4 | curl | Alice completes, bob verifies | State matches |
| 5 | curl | 3-way: alice+bob+charlie all modify | All converge |

### 8.7 List All Task Lists (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | CLI | `x0x --name alice tasks list` | All lists shown |
| 2 | curl | `GET /task-lists` on alice | JSON array |
| 3 | GUI | Sidebar → task lists | Lists displayed |
| 4 | curl | After creating multiple lists | All present |
| 5 | curl | On bob after joining | Joined lists visible |

---

## Phase 9: Key-Value Stores (50 assertions)

### 9.1 Create KV Store (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | CLI | `x0x --name alice store create --name "config"` | Store created |
| 2 | curl | `POST /stores` on alice | store_id returned |
| 3 | GUI | (via API) | Store created |
| 4 | curl | Create multiple stores | All created |
| 5 | curl | Create on bob | Bob's own store |

### 9.2 Put Value (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | CLI | `x0x --name alice store put --id $SID --key name --value "Alice"` | Stored |
| 2 | curl | `PUT /stores/$SID/name` with body | 200 OK |
| 3 | curl | Put multiple keys | All stored |
| 4 | curl | Overwrite existing key | Updated |
| 5 | curl | Large value | Stored correctly |

### 9.3 Get Value (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | CLI | `x0x --name alice store get --id $SID --key name` | "Alice" returned |
| 2 | curl | `GET /stores/$SID/name` | Value in response |
| 3 | curl | Get non-existent key | 404 or null |
| 4 | curl | Get after overwrite | Latest value |
| 5 | curl | Get on bob after CRDT sync | Same value |

### 9.4 List Keys (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | CLI | `x0x --name alice store keys --id $SID` | Key list |
| 2 | curl | `GET /stores/$SID/keys` | JSON array |
| 3 | curl | After adding multiple keys | All present |
| 4 | curl | After removing a key | Removed key absent |
| 5 | curl | On bob after sync | Same keys |

### 9.5 Remove Key (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | CLI | `x0x --name alice store rm --id $SID --key temp` | Removed |
| 2 | curl | `DELETE /stores/$SID/temp` | 200 OK |
| 3 | curl | Get removed key | 404 or null |
| 4 | curl | Remove non-existent key | Error response |
| 5 | curl | Remove syncs to bob | Bob sees removal |

### 9.6 Join Store (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | curl | `POST /stores/$SID/join` on bob | Joined |
| 2 | curl | Bob reads alice's keys | All visible |
| 3 | curl | Bob writes, alice reads | Bidirectional sync |
| 4 | curl | Join non-existent store | Error |
| 5 | curl | Join already-joined store | Idempotent |

### 9.7 KV CRDT Convergence (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | curl | Alice writes key, bob reads after sync | Same value |
| 2 | curl | Both write same key concurrently | LWW resolves |
| 3 | curl | Alice deletes, bob sees deletion | Converged |
| 4 | curl | 3-way: alice+bob+charlie all write | All converge |
| 5 | curl | Rapid updates → final state consistent | Consistent |

### 9.8 List Stores (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | CLI | `x0x --name alice store list` | All stores |
| 2 | curl | `GET /stores` on alice | JSON array |
| 3 | curl | After creating multiple | All present |
| 4 | curl | On bob after joining | Joined stores listed |
| 5 | curl | Stores have correct names | Name matches |

---

## Phase 10: File Transfer (25 assertions)

### 10.1 Send File (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | CLI | `x0x --name alice send-file --to $BOB_ID --file test.txt` | Transfer initiated |
| 2 | curl | `POST /files/send` on alice | transfer_id returned |
| 3 | GUI | Files → send file | Upload started |
| 4 | Dioxus | File browser → send | Transfer started |
| 5 | Swift | File → share to agent | Transfer started |

### 10.2 Accept/Reject Transfer (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | curl | `POST /files/accept/$TID` on bob | Accepted, download starts |
| 2 | curl | `POST /files/reject/$TID2` on bob | Rejected |
| 3 | CLI | Accept via CLI | File received |
| 4 | curl | Accept non-existent transfer | Error |
| 5 | curl | Accept already-accepted | Idempotent or error |

### 10.3 Transfer Status (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | curl | `GET /files/transfers` on alice | Transfer list |
| 2 | curl | `GET /files/transfers/$TID` on alice | Status details |
| 3 | CLI | `x0x --name alice transfers` | List shown |
| 4 | curl | Status after completion | Completed state |
| 5 | curl | Status after rejection | Rejected state |

---

## Phase 11: WebSocket & Real-Time (25 assertions)

### 11.1 General WebSocket (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | curl | Connect `ws://127.0.0.1:12701/ws?token=$TOKEN` | Connected |
| 2 | curl | Send message via WS | Delivered |
| 3 | curl | Receive event via WS | Event arrives |
| 4 | GUI | WebSocket-backed real-time updates | Live updates |
| 5 | curl | `GET /ws/sessions` | Active session listed |

### 11.2 Direct WebSocket (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | curl | Connect `/ws/direct` on alice | Connected |
| 2 | curl | DM appears on WS | Real-time delivery |
| 3 | Dioxus | DM updates in real-time | Via WebSocket |
| 4 | Swift | DM updates in real-time | Via WebSocket |
| 5 | curl | Multiple concurrent WS sessions | All active |

### 11.3 SSE Events (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | curl | `GET /events` on alice | SSE stream opens |
| 2 | curl | Publish → event arrives on SSE | Gossip events |
| 3 | curl | `GET /presence/events` | Presence SSE |
| 4 | curl | Multiple SSE consumers | All receive |
| 5 | curl | Close and reopen SSE | Clean reconnect |

---

## Phase 12: Self-Update & Upgrade (10 assertions)

### 12.1 Check Upgrade (5×)
| # | Interface | Action | Expected |
|---|-----------|--------|----------|
| 1 | CLI | `x0x --name alice upgrade` | Check result |
| 2 | curl | `GET /upgrade` on alice | JSON response |
| 3 | curl | `GET /upgrade` on bob | Same version info |
| 4 | VPS | `GET /upgrade` on NYC | VPS upgrade check |
| 5 | VPS | `GET /upgrade` on Tokyo | Consistent across network |

---

## Phase 13: GUI-Specific Testing via Chrome (50 assertions)

Use Claude Chrome MCP integration (`mcp__Claude_in_Chrome__*` tools) for all GUI tests.

### 13.1 GUI Launch & Navigation (5×)
| # | Action | Expected |
|---|--------|----------|
| 1 | `x0x --name alice gui` → navigate to localhost | GUI loads, dark theme |
| 2 | Click Dashboard | Dashboard renders with identity card |
| 3 | Click Spaces | Spaces list loads |
| 4 | Click People | Contact list displays |
| 5 | Click Network | Peer visualization renders |

### 13.2 GUI Identity Card (5×)
| # | Action | Expected |
|---|--------|----------|
| 1 | Dashboard → identity section | Agent ID displayed |
| 2 | Copy agent ID button | ID copied to clipboard |
| 3 | Share identity button | Card/link generated |
| 4 | View machine ID | Machine ID shown |
| 5 | Refresh dashboard | Stats update |

### 13.3 GUI Space Management (5×)
| # | Action | Expected |
|---|--------|----------|
| 1 | Create Space → fill name → submit | Space appears in sidebar |
| 2 | Click space → view chat | Chat interface loads |
| 3 | Send message in space | Message appears in feed |
| 4 | Generate invite link | Link displayed for copying |
| 5 | Leave space | Removed from sidebar |

### 13.4 GUI Contact Management (5×)
| # | Action | Expected |
|---|--------|----------|
| 1 | People → Add Contact | Import modal opens |
| 2 | Paste agent card → import | Contact appears in list |
| 3 | Click contact → view details | Detail panel opens |
| 4 | Change trust level | Badge updates |
| 5 | Remove contact | Disappears from list |

### 13.5 GUI Direct Messaging (5×)
| # | Action | Expected |
|---|--------|----------|
| 1 | Click contact → DM | DM conversation opens |
| 2 | Type message → send | Message appears in conversation |
| 3 | Receive reply | Reply shows in real-time |
| 4 | Scroll message history | Older messages load |
| 5 | Message reactions (if supported) | Reaction added |

### 13.6 GUI Real-Time Features (5×)
| # | Action | Expected |
|---|--------|----------|
| 1 | Status bar shows peer count | Accurate count |
| 2 | Presence indicators update | Online/offline badges change |
| 3 | New message notification | Toast or badge appears |
| 4 | Network reconnection | Auto-reconnects after brief disconnect |
| 5 | Agent discovery updates | New agents appear in dashboard |

### 13.7 GUI Constitution & About (5×)
| # | Action | Expected |
|---|--------|----------|
| 1 | Click Constitution | Full text rendered |
| 2 | Click About | Version info displayed |
| 3 | Settings page | Configuration options shown |
| 4 | Search functionality | Results returned |
| 5 | Status bar version | Matches binary version |

### 13.8 GUI Kanban/Tasks (5×)
| # | Action | Expected |
|---|--------|----------|
| 1 | Create task board | Board appears |
| 2 | Add task card | Card in board |
| 3 | Drag card between columns | Card moves |
| 4 | Edit task details | Changes saved |
| 5 | Complete task | Moves to done |

### 13.9 GUI KV Store (5×)
| # | Action | Expected |
|---|--------|----------|
| 1 | Wiki page → create | Page created |
| 2 | Edit wiki content | Content saved |
| 3 | View stored data | Data displayed |
| 4 | Delete data entry | Entry removed |
| 5 | Verify CRDT sync | Other instance sees changes |

### 13.10 GUI Error Handling (5×)
| # | Action | Expected |
|---|--------|----------|
| 1 | Stop daemon → GUI shows offline | Offline indicator |
| 2 | Restart daemon → GUI reconnects | Auto-reconnect |
| 3 | Invalid action → error toast | Error message displayed |
| 4 | Network timeout → retry | Retry indicator |
| 5 | Large data load → no crash | Graceful handling |

---

## Phase 14: Communitas Dioxus App (50 assertions)

### 14.1 App Launch & Auth (5×)
| # | Action | Expected |
|---|--------|----------|
| 1 | Launch app with x0xd running | App connects, shows dashboard |
| 2 | Verify daemon status indicator | Green/connected |
| 3 | Dashboard shows agent identity | Correct ID |
| 4 | Sidebar loads spaces/contacts | Data populated |
| 5 | Re-launch after daemon restart | Reconnects automatically |

### 14.2 Dioxus Messaging (5×)
| # | Action | Expected |
|---|--------|----------|
| 1 | Open channel → send message | Message appears |
| 2 | Receive message from bob | Real-time arrival |
| 3 | Message threading (reply) | Thread created |
| 4 | Emoji reactions | Reaction added |
| 5 | @mention autocomplete | Suggestion dropdown |

### 14.3 Dioxus Spaces (5×)
| # | Action | Expected |
|---|--------|----------|
| 1 | Create space | Space in sidebar |
| 2 | Invite bob | Invite link generated |
| 3 | View space members | Member list accurate |
| 4 | Space settings | Editable |
| 5 | Leave space | Removed from nav |

### 14.4 Dioxus Contacts (5×)
| # | Action | Expected |
|---|--------|----------|
| 1 | View people list | All contacts shown |
| 2 | Add contact | New contact appears |
| 3 | Change trust | Badge updates |
| 4 | View contact details | Full info panel |
| 5 | Presence badges | Online/offline correct |

### 14.5 Dioxus Network View (5×)
| # | Action | Expected |
|---|--------|----------|
| 1 | Open network tab | Peer info displayed |
| 2 | Discovered agents list | Agents shown |
| 3 | Connection status | NAT info, addresses |
| 4 | Bootstrap cache info | Stats shown |
| 5 | Refresh network view | Updated data |

### 14.6 Dioxus Direct Messages (5×)
| # | Action | Expected |
|---|--------|----------|
| 1 | Open DM conversation | Chat loads |
| 2 | Send DM | Delivered |
| 3 | Receive DM | Real-time |
| 4 | DM history | Persisted |
| 5 | Multiple DM conversations | All accessible |

### 14.7 Dioxus Files & Wiki (5×)
| # | Action | Expected |
|---|--------|----------|
| 1 | File browser | Files listed |
| 2 | Upload file | Transfer initiated |
| 3 | Wiki page create | Page created |
| 4 | Wiki edit | Content saved |
| 5 | Wiki view | Rendered correctly |

### 14.8 Dioxus Kanban (5×)
| # | Action | Expected |
|---|--------|----------|
| 1 | Create board | Board visible |
| 2 | Add card | Card displayed |
| 3 | Move card | Drag & drop works |
| 4 | Edit card details | Changes saved |
| 5 | CRDT sync with bob | Both see same board |

### 14.9 Dioxus Constitution & Settings (5×)
| # | Action | Expected |
|---|--------|----------|
| 1 | View constitution | Text rendered |
| 2 | View about | Version info |
| 3 | Settings page | Options displayed |
| 4 | Onboarding (first launch) | Flow completes |
| 5 | Offline mode | Graceful degradation |

### 14.10 Dioxus Error Handling (5×)
| # | Action | Expected |
|---|--------|----------|
| 1 | Daemon disconnection | Offline UI |
| 2 | Daemon reconnection | Auto-recovery |
| 3 | Network error | Error boundary |
| 4 | Invalid data | Graceful handling |
| 5 | Large dataset | No performance crash |

---

## Phase 15: Communitas Swift/macOS App (50 assertions)

### 15.1–15.10: Same categories as Dioxus (Phase 14)

Mirror all Dioxus tests for the Swift app:
- 15.1 App Launch & Auth (5×)
- 15.2 Swift Messaging (5×)
- 15.3 Swift Spaces (5×)
- 15.4 Swift Contacts (5×)
- 15.5 Swift Network View (5×)
- 15.6 Swift Direct Messages (5×)
- 15.7 Swift Files & Wiki (5×)
- 15.8 Swift Kanban/Board (5×)
- 15.9 Swift Constitution & Settings (5×)
- 15.10 Swift Error Handling (5×)

---

## Phase 16: Cross-Interface Verification (75 assertions)

The most critical phase — verify that actions in ONE interface are visible in ALL others.

### 16.1 Contact Created in CLI → Visible Everywhere (5×)
| # | Create via | Verify in | Expected |
|---|-----------|-----------|----------|
| 1 | CLI (alice) | curl `GET /contacts` | Present |
| 2 | CLI (alice) | GUI People page | Visible |
| 3 | CLI (alice) | Dioxus People view | Visible |
| 4 | CLI (alice) | Swift Contacts view | Visible |
| 5 | CLI (alice) | VPS (if federated) | Visible |

### 16.2 Space Created in GUI → Visible Everywhere (5×)
| # | Create via | Verify in | Expected |
|---|-----------|-----------|----------|
| 1 | GUI | CLI `group list` | Listed |
| 2 | GUI | curl `GET /groups` | In JSON |
| 3 | GUI | Dioxus sidebar | In list |
| 4 | GUI | Swift sidebar | In list |
| 5 | GUI | VPS node (after join) | Present |

### 16.3 Message Sent in Dioxus → Received Everywhere (5×)
| # | Send via | Receive in | Expected |
|---|---------|------------|----------|
| 1 | Dioxus | CLI events | Message content matches |
| 2 | Dioxus | curl SSE | Message arrives |
| 3 | Dioxus | GUI chat | Message appears |
| 4 | Dioxus | Swift channel | Message displayed |
| 5 | Dioxus | VPS subscriber | Message delivered |

### 16.4 DM Sent in Swift → Received in GUI (5×)
| # | Send via | Receive in | Expected |
|---|---------|------------|----------|
| 1 | Swift | GUI DM | Message appears |
| 2 | Swift | Dioxus DM | Message appears |
| 3 | Swift | CLI direct events | Message arrives |
| 4 | Swift | curl SSE | Message content |
| 5 | Swift | VPS node (if connected) | Delivered |

### 16.5 KV Store Written in curl → Read in GUI (5×)
| # | Write via | Read in | Expected |
|---|----------|---------|----------|
| 1 | curl | CLI `store get` | Same value |
| 2 | curl | GUI wiki/data view | Data displayed |
| 3 | curl | Dioxus wiki view | Content shown |
| 4 | curl | Swift data view | Content shown |
| 5 | curl (bob) | curl (alice) after sync | Converged |

### 16.6 Task Created in GUI → Synced to Dioxus (5×)
| # | Create via | Verify in | Expected |
|---|-----------|-----------|----------|
| 1 | GUI kanban | Dioxus kanban | Task appears |
| 2 | GUI kanban | Swift board | Task appears |
| 3 | GUI kanban | CLI tasks show | Listed |
| 4 | GUI kanban | curl `GET /task-lists/$LID/tasks` | In JSON |
| 5 | Dioxus complete → GUI | Marked done in GUI |

### 16.7 Trust Change in CLI → Reflected in GUIs (5×)
| # | Change via | Verify in | Expected |
|---|-----------|-----------|----------|
| 1 | CLI block agent | GUI badge | Shows "blocked" |
| 2 | CLI unblock | Dioxus badge | Shows new level |
| 3 | CLI trust | Swift badge | Shows "trusted" |
| 4 | curl set trust | GUI | Badge updates |
| 5 | curl set trust | CLI contacts list | Level matches |

### 16.8 Presence Visible Across All (5×)
| # | Agent | Verify in | Expected |
|---|-------|-----------|----------|
| 1 | Alice online | Bob's GUI | Green badge |
| 2 | Alice online | Bob's Dioxus | Green indicator |
| 3 | Alice online | Bob's Swift | Online status |
| 4 | Alice online | VPS presence endpoint | In online list |
| 5 | Alice offline (shutdown) | All UIs | Badge turns grey |

### 16.9 MLS Group Cross-Interface (5×)
| # | Action | Interface | Expected |
|---|--------|-----------|----------|
| 1 | Create MLS in CLI | curl list | Group present |
| 2 | Add member via curl | CLI shows member | Member in list |
| 3 | Encrypt via curl | Decrypt via CLI | Plaintext matches |
| 4 | Create via VPS | Local sees it | Federated group |
| 5 | Remove member via CLI | curl shows removed | Consistent state |

### 16.10 Full Round-Trip: Create→Invite→Join→Message→Verify (5×)
| # | Scenario | Expected |
|---|----------|----------|
| 1 | CLI create space → GUI invite → Dioxus join → Swift message → curl verify | All see message |
| 2 | GUI create → CLI invite → Swift join → Dioxus message → VPS verify | End-to-end |
| 3 | Dioxus create → Swift invite → CLI join → curl message → GUI verify | All interfaces |
| 4 | Swift create → curl invite → GUI join → CLI message → Dioxus verify | Reverse flow |
| 5 | VPS create → CLI join → GUI message → Dioxus verify → Swift verify | Network + local |

---

## Phase 17: VPS Cross-Region Testing (60 assertions)

### 17.1 All 6 Nodes Health (6 assertions, one per node)
For EACH node (NYC, SFO, Helsinki, Nuremberg, Singapore, Tokyo):
- [ ] Health returns `ok: true`

### 17.2 Cross-Region Direct Messaging (6×)
| # | From | To | Expected |
|---|------|-----|----------|
| 1 | NYC | SFO | Delivered <5s |
| 2 | NYC | Tokyo | Delivered <10s |
| 3 | Helsinki | Singapore | Delivered <10s |
| 4 | Nuremberg | NYC | Delivered <5s |
| 5 | Singapore | SFO | Delivered <10s |
| 6 | Tokyo | Helsinki | Delivered <10s |

### 17.3 Cross-Region Pub/Sub (6×)
| # | Publisher | Subscribers | Expected |
|---|----------|-------------|----------|
| 1 | NYC | All 5 others | All receive |
| 2 | Tokyo | All 5 others | All receive |
| 3 | Helsinki | NYC + Singapore | Both receive |
| 4 | SFO | Nuremberg + Tokyo | Both receive |
| 5 | Singapore | Helsinki + NYC | Both receive |
| 6 | Nuremberg | SFO + Tokyo | Both receive |

### 17.4 Cross-Region MLS Groups (6×)
| # | Scenario | Expected |
|---|----------|----------|
| 1 | Create on NYC, members on SFO + Helsinki | Encrypt/decrypt works |
| 2 | Create on Tokyo, members on Singapore + Nuremberg | Works |
| 3 | 6-node group with all regions | All can encrypt/decrypt |
| 4 | Remove member, verify can't decrypt new | Access revoked |
| 5 | Re-add member | Can decrypt again |
| 6 | Rotate keys | All members get new epoch |

### 17.5 Cross-Region Named Groups (6×)
| # | Scenario | Expected |
|---|----------|----------|
| 1 | NYC creates, Tokyo joins | Both see group |
| 2 | Helsinki invites, Singapore joins | Invite works cross-region |
| 3 | Nuremberg sets display name | Visible to SFO |
| 4 | SFO creates, all 5 join | 6-member group |
| 5 | Tokyo leaves | Member count decrements |
| 6 | Full lifecycle on each node | All endpoints work |

### 17.6 Cross-Region KV Stores (6×)
| # | Writer | Reader | Expected |
|---|--------|--------|----------|
| 1 | NYC writes key | Tokyo reads | Same value |
| 2 | Helsinki writes | SFO reads | Converged |
| 3 | Both NYC+Singapore write same key | LWW resolves | Consistent |
| 4 | Nuremberg deletes key | Tokyo confirms | Deleted |
| 5 | Rapid multi-region writes | All converge | Consistent |
| 6 | Large value written on SFO | Helsinki reads | Full data |

### 17.7 Cross-Region Presence (6×)
| # | Scenario | Expected |
|---|----------|----------|
| 1 | NYC checks presence | Sees all 5 peers online |
| 2 | Tokyo FOAF discovery | Finds agents across regions |
| 3 | Helsinki finds Singapore by ID | Located |
| 4 | All 6 nodes check `/presence/online` | Consistent view |
| 5 | SFO checks `/presence/status/$TOKYO_ID` | Online with last_seen |
| 6 | Nuremberg FOAF | Returns multi-region agents |

### 17.8 Cross-Region Contacts & Trust (6×)
| # | Scenario | Expected |
|---|----------|----------|
| 1 | NYC adds Tokyo as contact | Contact stored |
| 2 | Helsinki blocks Singapore | Blocked agent filtered |
| 3 | Nuremberg trusts SFO | Trust evaluation: Accept |
| 4 | Tokyo evaluates unknown agent | Unknown decision |
| 5 | SFO pins machine for Helsinki | Pin works |
| 6 | Full contact lifecycle on each node | All endpoints |

### 17.9 Local→VPS Integration (6×)
| # | Scenario | Expected |
|---|----------|----------|
| 1 | Alice (local) → NYC direct message | Delivered |
| 2 | Bob (local) → Tokyo pub/sub | Message received |
| 3 | Alice creates group, NYC joins | Cross-network group |
| 4 | VPS publishes, alice subscribes | Message arrives locally |
| 5 | Local KV store, VPS joins | Data syncs |
| 6 | Local task list, VPS joins | Tasks sync |

### 17.10 VPS→Local Integration (6×)
| # | Scenario | Expected |
|---|----------|----------|
| 1 | NYC sends DM to alice | Local receives |
| 2 | Helsinki publishes, bob subscribed | Bob receives |
| 3 | Tokyo creates group, alice joins | Local sees group |
| 4 | Singapore writes KV, alice reads | Value synced |
| 5 | Nuremberg creates task, alice sees | Task synced |
| 6 | SFO sends file to bob | Transfer initiated |

---

## Phase 18: Stress & Edge Cases (30 assertions)

### 18.1 Rapid Operations (5×)
| # | Test | Expected |
|---|------|----------|
| 1 | 100 messages in 10 seconds on one topic | All delivered |
| 2 | 50 concurrent subscriptions | All active |
| 3 | 20 KV store writes/second | All persisted |
| 4 | 10 simultaneous direct connections | All established |
| 5 | Create 20 groups rapidly | All created |

### 18.2 Large Payloads (5×)
| # | Test | Expected |
|---|------|----------|
| 1 | 1MB message payload | Delivered |
| 2 | 100KB KV store value | Stored and retrieved |
| 3 | Long topic name (1000 chars) | Works or appropriate error |
| 4 | 1000 contacts | List returns all |
| 5 | 100 tasks in one list | All listed |

### 18.3 Error Recovery (5×)
| # | Test | Expected |
|---|------|----------|
| 1 | Kill daemon, restart, verify state | State recovered |
| 2 | Network disconnect → reconnect | Bootstrap cache aids recovery |
| 3 | Invalid API token | 401 Unauthorized |
| 4 | Malformed JSON body | 400 Bad Request |
| 5 | Non-existent endpoint | 404 Not Found |

### 18.4 Concurrent Multi-Agent (5×)
| # | Test | Expected |
|---|------|----------|
| 1 | Alice+Bob+Charlie all publish simultaneously | All messages delivered |
| 2 | All three write to same KV key | LWW resolves consistently |
| 3 | All three modify same task list | CRDT converges |
| 4 | All three send DMs to each other | All 6 messages delivered |
| 5 | All three create groups, invite each other | All groups work |

### 18.5 Security Boundary (5×)
| # | Test | Expected |
|---|------|----------|
| 1 | Request without auth token | 401 |
| 2 | Request with wrong token | 401 |
| 3 | Blocked agent's messages filtered | Silently dropped |
| 4 | MLS decrypt without membership | Fails |
| 5 | Trust evaluation with blocked agent | Reject |

### 18.6 Seedless Bootstrap (5×)
| # | Test | Expected |
|---|------|----------|
| 1 | Charlie (no bootstrap) health | Works locally |
| 2 | Charlie cannot discover network agents | Empty or limited |
| 3 | Charlie can create local groups | Works |
| 4 | Charlie can create local KV stores | Works |
| 5 | Connect charlie to alice manually | Connection established |

---

## Assertion Summary

| Phase | Category | Assertions |
|-------|----------|------------|
| 0 | Pre-Flight & Infrastructure | 20 |
| 1 | Identity & Agent (incl. speakable identity, introduction card, find, connect) | 100 |
| 2 | Contacts & Trust | 100 |
| 3 | Discovery & Presence | 75 |
| 4 | Messaging — Pub/Sub | 50 |
| 5 | Direct Messaging | 50 |
| 6 | MLS Encrypted Groups | 50 |
| 7 | Named Groups & Spaces | 75 |
| 8 | CRDT Task Lists | 50 |
| 9 | Key-Value Stores | 50 |
| 10 | File Transfer | 25 |
| 11 | WebSocket & Real-Time | 25 |
| 12 | Self-Update | 10 |
| 13 | GUI via Chrome | 50 |
| 14 | Communitas Dioxus | 50 |
| 15 | Communitas Swift | 50 |
| 16 | Cross-Interface Verification | 75 |
| 17 | VPS Cross-Region | 60 |
| 18 | Stress & Edge Cases | 30 |
| **TOTAL** | | **~995** |

---

## Execution Instructions

### Order of Operations

1. **Phase 0**: Build, VPS health, local instance startup
2. **Phases 1–12**: Feature-by-feature testing (CLI + curl primary, GUI/Dioxus/Swift where applicable)
3. **Phase 13**: Full GUI testing via Chrome MCP
4. **Phase 14**: Full Dioxus app testing
5. **Phase 15**: Full Swift app testing
6. **Phase 16**: Cross-interface verification (CRITICAL — this proves integration)
7. **Phase 17**: VPS cross-region (CRITICAL — this proves network)
8. **Phase 18**: Stress and edge cases

### Tools to Use

- **CLI**: `./target/release/x0x --name <instance> <command>`
- **curl**: `curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:$PORT/<endpoint>`
- **GUI**: `x0x gui` + Claude Chrome MCP tools (`mcp__Claude_in_Chrome__*`)
- **Dioxus**: `cd ../communitas && cargo run -p communitas-dioxus`
- **Swift**: Build and run from Xcode (`../communitas/communitas-apple`)
- **VPS**: `ssh -o ConnectTimeout=10 root@$IP 'curl -s -H "Authorization: Bearer $(cat /root/.local/share/x0x/api-token)" http://127.0.0.1:12600/<endpoint>'`

### Pass Criteria

- **100%** of assertions must pass
- **Every endpoint** tested via at least 2 different interfaces
- **Every function** tested minimum 5 times across contexts
- **Every VPS node** individually validated
- **Cross-interface communication** verified for all data types
- **CRDT convergence** verified with ≥3 agents for all CRDT types

### Failure Handling

If any assertion fails:
1. Log the exact failure (interface, endpoint, expected vs actual)
2. Categorize: bug, configuration issue, network issue, or test issue
3. Do NOT skip — fix the root cause and re-test
4. Track regression patterns across interfaces

---

## Certification Statement

Upon completion of all 995+ assertions with 100% pass rate:

> **x0x v{VERSION} is certified for production use across all interfaces (CLI, REST API, GUI, Dioxus, Swift) and all 6 global bootstrap nodes. Every endpoint, every function, every interface has been validated with cross-network communication confirmed.**
