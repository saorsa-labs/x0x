# x0x Capabilities Reference

This document summarizes the capabilities exposed by the x0x Rust library, the `x0xd` daemon, and the `x0x` CLI. It is intended for agents and tools building on top of x0x.

See also:
- [api-reference.md](api-reference.md) — full REST and WebSocket reference
- [api.md](api.md) — compact endpoint map

## Identity

### Core identity operations

| Capability | Rust API | REST API | CLI |
|---|---|---|---|
| Get agent ID | `agent.agent_id()` | `GET /agent` | `x0x agent` |
| Get machine ID | `agent.machine_id()` | `GET /agent` | `x0x agent` |
| Get user ID | `agent.user_id()` | `GET /agent` and `GET /agent/user-id` | `x0x agent`, `x0x agent user-id` |
| Get agent certificate | `agent.agent_certificate()` | included when relevant in identity workflows | — |
| Announce identity | `agent.announce_identity(include_user_identity, human_consent).await` | `POST /announce` | `x0x announce [--include-user] [--consent]` |
| Generate shareable agent card | library card helpers | `GET /agent/card` | `x0x agent card` |
| Import agent card | library card helpers | `POST /agent/card/import` | `x0x agent import <card>` |

### Discovery

| Capability | Rust API | REST API | CLI |
|---|---|---|---|
| List discovered agents (TTL-filtered) | `agent.discovered_agents().await` | `GET /agents/discovered` | `x0x agents list` |
| List all discovered agents | `agent.discovered_agents_unfiltered().await` | `GET /agents/discovered?unfiltered=true` | `x0x agents list --unfiltered` |
| Get one discovered agent | `agent.discovered_agent(agent_id).await` | `GET /agents/discovered/:agent_id` | `x0x agents get <agent_id>` |
| Find agent on the network | daemon-assisted lookup | `POST /agents/find/:agent_id` | `x0x agents find <agent_id>` |
| List agents by user | `agent.find_agents_by_user(user_id).await` | `GET /users/:user_id/agents` | `x0x agents by-user <user_id>` |
| Get presence (alive agents) | `agent.presence().await` | `GET /presence` | `x0x presence` |
| Get reachability info | `agent.reachability(&agent_id).await` | `GET /agents/reachability/:agent_id` | `x0x agents reachability <agent_id>` |

### Connectivity

| Capability | Rust API | REST API | CLI |
|---|---|---|---|
| Join network | `agent.join_network().await` | handled automatically by daemon startup | `x0x start` / `x0xd` |
| Connect to agent | `agent.connect_to_agent(&agent_id).await` | `POST /agents/connect` | `x0x direct connect <agent_id>` |
| Check connected agents | `agent.connected_agents().await` | `GET /direct/connections` | `x0x direct connections` |
| Check network diagnostics | `agent.network()` + node status | `GET /network/status` | `x0x network status` |

## Trust and contacts

### Contact management

| Capability | Rust API | REST API | CLI |
|---|---|---|---|
| List contacts | `agent.contacts().read().await.list()` | `GET /contacts` | `x0x contacts list` |
| Add contact | `store.add(contact)` | `POST /contacts` | `x0x contacts add <agent_id> --trust <level>` |
| Remove contact | `store.remove(&agent_id)` | `DELETE /contacts/:agent_id` | `x0x contacts remove <agent_id>` |
| Update trust / identity type | `store.set_trust(...)`, `store.set_identity_type(...)` | `PATCH /contacts/:agent_id` | `x0x contacts update ...` |
| Quick trust update | `store.set_trust(...)` | `POST /contacts/trust` | `x0x trust set <agent_id> <level>` |
| Revoke contact | revocation helpers in contact store | `POST /contacts/:agent_id/revoke` | `x0x contacts revoke <agent_id> --reason ...` |
| List revocations | revocation helpers in contact store | `GET /contacts/:agent_id/revocations` | `x0x contacts revocations <agent_id>` |
| Evaluate trust | `TrustEvaluator::evaluate(...)` | `POST /trust/evaluate` | `x0x trust evaluate <agent_id> <machine_id>` |

### Machine pinning

| Capability | Rust API | REST API | CLI |
|---|---|---|---|
| Add machine record | `store.add_machine(&agent_id, record)` | `POST /contacts/:agent_id/machines` | `x0x machines add <agent_id> <machine_id> [--pin]` |
| Remove machine record | `store.remove_machine(&agent_id, &machine_id)` | `DELETE /contacts/:agent_id/machines/:machine_id` | `x0x machines remove <agent_id> <machine_id>` |
| Pin machine | `store.pin_machine(&agent_id, &machine_id)` | `POST /contacts/:agent_id/machines/:machine_id/pin` | `x0x machines pin <agent_id> <machine_id>` |
| Unpin machine | `store.unpin_machine(&agent_id, &machine_id)` | `DELETE /contacts/:agent_id/machines/:machine_id/pin` | `x0x machines unpin <agent_id> <machine_id>` |
| List machines | `store.machines(&agent_id)` | `GET /contacts/:agent_id/machines` | `x0x machines list <agent_id>` |

### Trust levels

| Level | Meaning |
|---|---|
| `Blocked` | Messages are dropped and the agent is rejected |
| `Unknown` | Default state for unknown identities |
| `Known` | Identity is recognized but not fully trusted |
| `Trusted` | Identity is explicitly trusted |

### Identity types

| Type | Meaning |
|---|---|
| `Anonymous` | No machine constraint |
| `Known` | Machine observed but not constrained |
| `Trusted` | Trusted identity, accepted from any machine |
| `Pinned` | Only accepted from pinned machine IDs |

## Messaging

### Gossip pub/sub

| Capability | Rust API | REST API | CLI |
|---|---|---|---|
| Subscribe to topic | `agent.subscribe("topic").await` | `POST /subscribe` | `x0x subscribe <topic>` |
| Publish to topic | `agent.publish("topic", payload).await` | `POST /publish` | `x0x publish <topic> <payload>` |
| Unsubscribe | drop the subscription / daemon subscription tracking | `DELETE /subscribe/:id` | `x0x unsubscribe <id>` |
| Stream events | daemon SSE | `GET /events` | `x0x events` |

### Direct messaging

| Capability | Rust API | REST API | CLI |
|---|---|---|---|
| Send direct message | `agent.send_direct(&agent_id, payload).await` | `POST /direct/send` | `x0x direct send <agent_id> <message>` |
| Receive direct message stream | `agent.recv_direct().await`, `agent.subscribe_direct()` | `GET /direct/events` | `x0x direct events` |
| Check direct connections | `agent.connected_agents().await` | `GET /direct/connections` | `x0x direct connections` |

### WebSocket messaging

| Capability | REST API | CLI |
|---|---|---|
| General-purpose WebSocket | `GET /ws` | — |
| Direct-message WebSocket | `GET /ws/direct` | — |
| List active WS sessions | `GET /ws/sessions` | `x0x ws sessions` |

## Collaborative data

### Task lists (CRDT)

| Capability | Rust API | REST API | CLI |
|---|---|---|---|
| Create task list | `agent.create_task_list(name, topic).await` | `POST /task-lists` | `x0x tasks create <name> <topic>` |
| List task lists | daemon handle registry | `GET /task-lists` | `x0x tasks list` |
| Show tasks | `handle.list_tasks().await` | `GET /task-lists/:id/tasks` | `x0x tasks show <list_id>` |
| Add task | `handle.add_task(title, description).await` | `POST /task-lists/:id/tasks` | `x0x tasks add ...` |
| Claim task | handle update ops | `PATCH /task-lists/:id/tasks/:tid` with `{"action":"claim"}` | `x0x tasks claim ...` |
| Complete task | handle update ops | `PATCH /task-lists/:id/tasks/:tid` with `{"action":"complete"}` | `x0x tasks complete ...` |

### Key-value stores

| Capability | Rust API | REST API | CLI |
|---|---|---|---|
| Create store | `agent.create_kv_store(name, topic).await` | `POST /stores` | `x0x store create <name> <topic>` |
| Join store | `agent.join_kv_store(topic).await` | `POST /stores/:id/join` | `x0x store join <topic>` |
| List stores | daemon handle registry | `GET /stores` | `x0x store list` |
| List keys | `handle.keys().await` | `GET /stores/:id/keys` | `x0x store keys <store_id>` |
| Put value | `handle.put(key, value, content_type).await` | `PUT /stores/:id/:key` | `x0x store put <store_id> <key> <value>` |
| Get value | `handle.get(key).await` | `GET /stores/:id/:key` | `x0x store get <store_id> <key>` |
| Remove value | `handle.delete(key).await` | `DELETE /stores/:id/:key` | `x0x store rm <store_id> <key>` |

## Groups

### MLS encrypted groups

| Capability | Rust API | REST API | CLI |
|---|---|---|---|
| Create group | `MlsGroup::new(...)` and daemon helpers | `POST /mls/groups` | `x0x groups create` |
| List groups | daemon group registry | `GET /mls/groups` | `x0x groups list` |
| Get group | daemon group registry | `GET /mls/groups/:id` | `x0x groups get <group_id>` |
| Add member | MLS helpers | `POST /mls/groups/:id/members` | `x0x groups add-member ...` |
| Remove member | MLS helpers | `DELETE /mls/groups/:id/members/:agent_id` | `x0x groups remove-member ...` |
| Encrypt | cipher helpers | `POST /mls/groups/:id/encrypt` | `x0x groups encrypt <group_id> <payload>` |
| Decrypt | cipher helpers | `POST /mls/groups/:id/decrypt` | `x0x groups decrypt ... --epoch <n>` |
| Create welcome | welcome helpers | `POST /mls/groups/:id/welcome` | `x0x groups welcome <group_id> <agent_id>` |

### Named groups

| Capability | Rust API | REST API | CLI |
|---|---|---|---|
| Create named group | group helpers | `POST /groups` | `x0x group create <name>` |
| List named groups | daemon registry | `GET /groups` | `x0x group list` |
| Get group info | daemon registry | `GET /groups/:id` | `x0x group info <group_id>` |
| Invite to group | invite helpers | `POST /groups/:id/invite` | `x0x group invite <group_id>` |
| Join via invite | invite helpers | `POST /groups/join` | `x0x group join <invite>` |
| Set display name | group metadata helpers | `PUT /groups/:id/display-name` | `x0x group set-name <group_id> <name>` |
| Leave group | daemon group registry | `DELETE /groups/:id` | `x0x group leave <group_id>` |

## File transfers

| Capability | REST API | CLI |
|---|---|---|
| Start outgoing transfer | `POST /files/send` | `x0x send-file <agent_id> <path>` |
| List transfers | `GET /files/transfers` | `x0x transfers` |
| Inspect transfer | `GET /files/transfers/:id` | `x0x transfer-status <transfer_id>` |
| Accept transfer | `POST /files/accept/:id` | `x0x accept-file <transfer_id>` |
| Reject transfer | `POST /files/reject/:id` | `x0x reject-file <transfer_id> [--reason ...]` |

## Operations and tooling

| Capability | REST API | CLI |
|---|---|---|
| Check health | `GET /health` | `x0x health` |
| Runtime status | `GET /status` | `x0x status` |
| Bootstrap cache stats | `GET /network/bootstrap-cache` | `x0x network cache` |
| Check for upgrades | `GET /upgrade` | `x0x upgrade` |
| Open embedded GUI | `GET /gui` | `x0x gui` |
| List daemon instances | local discovery | `x0x instances` |
| Start daemon | local process spawn | `x0x start` |
| Stop daemon | `POST /shutdown` | `x0x stop` |
| Run diagnostics | daemon + local probes | `x0x doctor` |

## Network constants

| Constant | Value |
|---|---|
| `IDENTITY_HEARTBEAT_INTERVAL_SECS` | 300 (5 minutes) |
| `IDENTITY_TTL_SECS` | 900 (15 minutes) |
| `IDENTITY_ANNOUNCE_TOPIC` | `"x0x.identity.announce.v1"` |
| Default x0xd API bind | `127.0.0.1:12700` |
| Default bootstrap UDP port | `5483` |

## NAT traversal outcomes

`connect_to_agent()` returns one of:

| Outcome | Meaning |
|---|---|
| `Direct(addr)` | Connected directly without coordination |
| `Coordinated(addr)` | Connected after NAT traversal coordination |
| `Unreachable` | Agent found but could not be reached |
| `NotFound` | Agent was not found in discovery cache |

## Trust decision outcomes

`TrustEvaluator::evaluate()` returns one of:

| Decision | Meaning |
|---|---|
| `Accept` | Identity and machine are accepted |
| `AcceptWithFlag` | Identity is accepted but should be treated cautiously |
| `RejectMachineMismatch` | Contact is pinned to a different machine |
| `RejectBlocked` | Identity is explicitly blocked |
| `Unknown` | Contact is not yet known |

## REST API quick reference

Base URL: `http://127.0.0.1:12700`

```text
GET  /health
GET  /status
POST /shutdown

GET  /agent
GET  /agent/user-id
GET  /agent/card
POST /agent/card/import
POST /announce

GET  /peers
GET  /presence
GET  /network/status
GET  /network/bootstrap-cache

POST   /publish
POST   /subscribe
DELETE /subscribe/:id
GET    /events

GET  /agents/discovered
GET  /agents/discovered/:agent_id
POST /agents/find/:agent_id
GET  /agents/reachability/:agent_id
GET  /users/:user_id/agents

GET    /contacts
POST   /contacts
POST   /contacts/trust
PATCH  /contacts/:agent_id
DELETE /contacts/:agent_id
POST   /contacts/:agent_id/revoke
GET    /contacts/:agent_id/revocations
GET    /contacts/:agent_id/machines
POST   /contacts/:agent_id/machines
DELETE /contacts/:agent_id/machines/:machine_id
POST   /contacts/:agent_id/machines/:machine_id/pin
DELETE /contacts/:agent_id/machines/:machine_id/pin
POST   /trust/evaluate

POST /agents/connect
POST /direct/send
GET  /direct/connections
GET  /direct/events

POST   /mls/groups
GET    /mls/groups
GET    /mls/groups/:id
POST   /mls/groups/:id/members
DELETE /mls/groups/:id/members/:agent_id
POST   /mls/groups/:id/encrypt
POST   /mls/groups/:id/decrypt
POST   /mls/groups/:id/welcome

POST   /groups
GET    /groups
GET    /groups/:id
POST   /groups/:id/invite
POST   /groups/join
PUT    /groups/:id/display-name
DELETE /groups/:id

GET    /task-lists
POST   /task-lists
GET    /task-lists/:id/tasks
POST   /task-lists/:id/tasks
PATCH  /task-lists/:id/tasks/:tid

GET    /stores
POST   /stores
POST   /stores/:id/join
GET    /stores/:id/keys
PUT    /stores/:id/:key
GET    /stores/:id/:key
DELETE /stores/:id/:key

POST /files/send
GET  /files/transfers
GET  /files/transfers/:id
POST /files/accept/:id
POST /files/reject/:id

GET /upgrade
GET /ws
GET /ws/direct
GET /ws/sessions
GET /gui
GET /gui/
```
