# x0xd API Reference

Base URL: `http://127.0.0.1:12700`

This is the shorter, at-a-glance API map for `x0xd`. For the full reference, request/response examples, and WebSocket protocol details, see [api-reference.md](api-reference.md).

## System

| Method | Path | CLI | Description |
|---|---|---|---|
| GET | `/health` | `x0x health` | Health probe |
| GET | `/status` | `x0x status` | Runtime status |
| POST | `/shutdown` | `x0x stop` | Graceful shutdown |

## Identity

| Method | Path | CLI | Description |
|---|---|---|---|
| GET | `/agent` | `x0x agent` | Local identity |
| POST | `/announce` | `x0x announce` | Re-announce identity |
| GET | `/agent/user-id` | `x0x agent user-id` | User ID if configured |
| GET | `/agent/card` | `x0x agent card` | Shareable identity card |
| POST | `/agent/card/import` | `x0x agent import` | Import identity card |

## Network

| Method | Path | CLI | Description |
|---|---|---|---|
| GET | `/peers` | `x0x peers` | Connected peers |
| GET | `/presence` | `x0x presence` | Presence view |
| GET | `/network/status` | `x0x network status` | NAT / connectivity diagnostics |
| GET | `/network/bootstrap-cache` | `x0x network cache` | Bootstrap cache stats |

## Gossip messaging

| Method | Path | CLI | Description |
|---|---|---|---|
| POST | `/publish` | `x0x publish` | Publish to a topic |
| POST | `/subscribe` | `x0x subscribe` | Subscribe to a topic |
| DELETE | `/subscribe/:id` | `x0x unsubscribe` | Unsubscribe |
| GET | `/events` | `x0x events` | SSE message stream |

## Discovery

| Method | Path | CLI | Description |
|---|---|---|---|
| GET | `/agents/discovered` | `x0x agents list` | List discovered agents |
| GET | `/agents/discovered/:agent_id` | `x0x agents get` | Get one discovered agent |
| POST | `/agents/find/:agent_id` | `x0x agents find` | Actively look up an agent |
| GET | `/agents/reachability/:agent_id` | `x0x agents reachability` | Reachability heuristics |
| GET | `/users/:user_id/agents` | `x0x agents by-user` | Agents linked to a user |

## Contacts and trust

| Method | Path | CLI | Description |
|---|---|---|---|
| GET | `/contacts` | `x0x contacts list` | List contacts |
| POST | `/contacts` | `x0x contacts add` | Add contact |
| POST | `/contacts/trust` | `x0x trust set` | Quick trust update |
| PATCH | `/contacts/:agent_id` | `x0x contacts update` | Update contact |
| DELETE | `/contacts/:agent_id` | `x0x contacts remove` | Remove contact |
| POST | `/contacts/:agent_id/revoke` | `x0x contacts revoke` | Revoke contact |
| GET | `/contacts/:agent_id/revocations` | `x0x contacts revocations` | List revocations |
| GET | `/contacts/:agent_id/machines` | `x0x machines list` | List machines |
| POST | `/contacts/:agent_id/machines` | `x0x machines add` | Add machine |
| DELETE | `/contacts/:agent_id/machines/:machine_id` | `x0x machines remove` | Remove machine |
| POST | `/contacts/:agent_id/machines/:machine_id/pin` | `x0x machines pin` | Pin machine |
| DELETE | `/contacts/:agent_id/machines/:machine_id/pin` | `x0x machines unpin` | Unpin machine |
| POST | `/trust/evaluate` | `x0x trust evaluate` | Evaluate trust decision |

## Direct messaging

| Method | Path | CLI | Description |
|---|---|---|---|
| POST | `/agents/connect` | `x0x direct connect` | Connect to agent |
| POST | `/direct/send` | `x0x direct send` | Send direct message |
| GET | `/direct/connections` | `x0x direct connections` | List direct connections |
| GET | `/direct/events` | `x0x direct events` | SSE direct-message stream |

## MLS groups

| Method | Path | CLI | Description |
|---|---|---|---|
| POST | `/mls/groups` | `x0x groups create` | Create encrypted group |
| GET | `/mls/groups` | `x0x groups list` | List encrypted groups |
| GET | `/mls/groups/:id` | `x0x groups get` | Group details |
| POST | `/mls/groups/:id/members` | `x0x groups add-member` | Add member |
| DELETE | `/mls/groups/:id/members/:agent_id` | `x0x groups remove-member` | Remove member |
| POST | `/mls/groups/:id/encrypt` | `x0x groups encrypt` | Encrypt payload |
| POST | `/mls/groups/:id/decrypt` | `x0x groups decrypt` | Decrypt payload |
| POST | `/mls/groups/:id/welcome` | `x0x groups welcome` | Create welcome message |

## Named groups

| Method | Path | CLI | Description |
|---|---|---|---|
| POST | `/groups` | `x0x group create` | Create named group |
| GET | `/groups` | `x0x group list` | List groups |
| GET | `/groups/:id` | `x0x group info` | Group info |
| POST | `/groups/:id/invite` | `x0x group invite` | Generate invite link |
| POST | `/groups/join` | `x0x group join` | Join from invite |
| PUT | `/groups/:id/display-name` | `x0x group set-name` | Set display name |
| DELETE | `/groups/:id` | `x0x group leave` | Leave or delete group |

## Collaborative data

### Task lists

| Method | Path | CLI | Description |
|---|---|---|---|
| GET | `/task-lists` | `x0x tasks list` | List task lists |
| POST | `/task-lists` | `x0x tasks create` | Create task list |
| GET | `/task-lists/:id/tasks` | `x0x tasks show` | Show tasks |
| POST | `/task-lists/:id/tasks` | `x0x tasks add` | Add task |
| PATCH | `/task-lists/:id/tasks/:tid` | `x0x tasks claim` / `x0x tasks complete` | Update task state |

### Stores

| Method | Path | CLI | Description |
|---|---|---|---|
| GET | `/stores` | `x0x store list` | List stores |
| POST | `/stores` | `x0x store create` | Create store |
| POST | `/stores/:id/join` | `x0x store join` | Join store |
| GET | `/stores/:id/keys` | `x0x store keys` | List keys |
| PUT | `/stores/:id/:key` | `x0x store put` | Put value |
| GET | `/stores/:id/:key` | `x0x store get` | Get value |
| DELETE | `/stores/:id/:key` | `x0x store rm` | Remove value |

## File transfers

| Method | Path | CLI | Description |
|---|---|---|---|
| POST | `/files/send` | `x0x send-file` | Start outgoing transfer |
| GET | `/files/transfers` | `x0x transfers` | List transfers |
| GET | `/files/transfers/:id` | `x0x transfer-status` | Inspect one transfer |
| POST | `/files/accept/:id` | `x0x accept-file` | Accept transfer |
| POST | `/files/reject/:id` | `x0x reject-file` | Reject transfer |

## Upgrade, WebSocket, and GUI

| Method | Path | CLI | Description |
|---|---|---|---|
| GET | `/upgrade` | `x0x upgrade` | Check for updates |
| GET | `/ws` | — | General-purpose WebSocket |
| GET | `/ws/direct` | — | Direct-message WebSocket |
| GET | `/ws/sessions` | `x0x ws sessions` | List WebSocket sessions |
| GET | `/gui` | `x0x gui` | Open embedded GUI |
| GET | `/gui/` | — | Alias for `/gui` |

## Notes

- Success responses are usually flattened: `{"ok":true,...}`.
- Error responses use: `{"ok":false,"error":"..."}`.
- For request/response examples and the WebSocket message schema, see [api-reference.md](api-reference.md).
