# x0xd API quick reference

Base URL: `http://127.0.0.1:12700`

| Method | Path | Status | Description |
|---|---|---|---|
| GET | `/health` | [working] | Health status, version, peer count, and uptime. |
| GET | `/agent` | [working] | Local agent identity (agent ID, machine ID, optional user ID). |
| GET | `/peers` | [working] | Connected peer IDs from the gossip network. |
| POST | `/publish` | [working] | Publish a base64 payload to a topic. |
| POST | `/subscribe` | [working] | Create a topic subscription and return a subscription ID. |
| DELETE | `/subscribe/:id` | [working] | Remove a previously created subscription. |
| GET | `/events` | [working] | Server-Sent Events stream for subscription messages and runtime events. |
| GET | `/presence` | [stub] | List currently visible online agents (placeholder endpoint). |
| GET | `/contacts` | [working] | List local contact entries with trust levels. |
| POST | `/contacts` | [working] | Add a contact with trust level and optional label. |
| POST | `/contacts/trust` | [working] | Quick trust-level update using `agent_id` + `level`. |
| PATCH | `/contacts/:agent_id` | [working] | Update trust level for an existing contact. |
| DELETE | `/contacts/:agent_id` | [working] | Remove a contact from the local trust store. |
| GET | `/task-lists` | [working] | List in-memory collaborative task lists. |
| POST | `/task-lists` | [working] | Create a collaborative task list bound to a topic. |
| GET | `/task-lists/:id/tasks` | [working] | List tasks for a task list ID. |
| POST | `/task-lists/:id/tasks` | [working] | Add a task to a task list. |
| PATCH | `/task-lists/:id/tasks/:tid` | [working] | Update a task action (`claim` or `complete`). |

Detailed request/response examples for common flows are documented in `verify.md` and `patterns.md`.

Comprehensive API documentation (full request/response schemas and exhaustive error cases for every endpoint) is planned for a future phase. [planned]
