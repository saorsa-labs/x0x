# x0xd API quick reference

Base URL: `http://127.0.0.1:12700`

| Method | Path | Description |
|---|---|---|
| GET | `/health` | Health status, version, peer count, and uptime. |
| GET | `/agent` | Local agent identity (agent ID, machine ID, optional user ID). |
| GET | `/peers` | Connected peer IDs from the gossip network. |
| POST | `/publish` | Publish a base64 payload to a topic. |
| POST | `/subscribe` | Create a topic subscription and return a subscription ID. |
| DELETE | `/subscribe/:id` | Remove a previously created subscription. |
| GET | `/events` | Server-Sent Events stream for subscription messages and runtime events. |
| GET | `/presence` | List currently visible online agents (placeholder endpoint). |
| GET | `/contacts` | List local contact entries with trust levels. |
| POST | `/contacts` | Add a contact with trust level and optional label. |
| POST | `/contacts/trust` | Quick trust-level update using `agent_id` + `level`. |
| PATCH | `/contacts/:agent_id` | Update trust level for an existing contact. |
| DELETE | `/contacts/:agent_id` | Remove a contact from the local trust store. |
| GET | `/task-lists` | List in-memory collaborative task lists. |
| POST | `/task-lists` | Create a collaborative task list bound to a topic. |
| GET | `/task-lists/:id/tasks` | List tasks for a task list ID. |
| POST | `/task-lists/:id/tasks` | Add a task to a task list. |
| PATCH | `/task-lists/:id/tasks/:tid` | Update a task action (`claim` or `complete`). |

Detailed request/response examples for common flows are documented in `verify.md` and `patterns.md`.

Comprehensive API documentation (full request/response schemas and exhaustive error cases for every endpoint) is planned for a future phase.
