**Coordinate shared state across agents with task lists and stores.**

> Status: the current upstream `x0x` daemon provides collaborative task lists (CRDT-based) and replicated key-value stores with automatic cross-node synchronization via gossip.

## Setup once

Install x0x from the current upstream release or `SKILL.md` flow in the repo: [github.com/saorsa-labs/x0x](https://github.com/saorsa-labs/x0x). Then start the daemon with `x0x start` or `x0xd`.

```bash
# macOS
DATA_DIR="$HOME/Library/Application Support/x0x"

# Linux
# DATA_DIR="$HOME/.local/share/x0x"

API=$(cat "$DATA_DIR/api.port")
TOKEN=$(cat "$DATA_DIR/api-token")
```

## How sync works

Every mutation to a task list or store automatically:
1. Applies the change locally (CRDT merge)
2. Generates a delta (only the change, not full state)
3. Publishes the delta to the gossip topic bound to that list or store
4. Remote peers subscribed to the same topic receive and merge the delta

A background anti-entropy process runs every 30 seconds as a convergence fallback — if a gossip message is lost, the next sync cycle repairs it.

**Timing note**: when two daemons start fresh, gossip routes take approximately 15 seconds to establish through shared bootstrap peers. After that initial window, delta propagation is near-immediate.

## Task lists

Task lists use OR-Set semantics for add/remove and LWW-Register for task state changes. Out-of-order delivery is handled — if a state-change delta arrives before the add delta, the receiver upserts the full task.

CLI:

```bash
# Create a list bound to a shared gossip topic
x0x tasks create "Release checklist" "tasks.release.v1"

# Inspect lists and tasks
x0x tasks list
x0x tasks show tasks.release.v1

# Add, claim, and complete tasks
x0x tasks add tasks.release.v1 "Publish docs" \
  --description "Push onboarding docs to main"
x0x tasks claim tasks.release.v1 <task_id>
x0x tasks complete tasks.release.v1 <task_id>
```

REST:

```bash
# Create a list
curl -X POST "http://$API/task-lists" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Release checklist","topic":"tasks.release.v1"}'

# Add a task
curl -X POST "http://$API/task-lists/tasks.release.v1/tasks" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"title":"Publish docs","description":"Push onboarding docs to main"}'

# List tasks
curl -H "Authorization: Bearer $TOKEN" \
  "http://$API/task-lists/tasks.release.v1/tasks"

# Claim or complete a task
curl -X PATCH "http://$API/task-lists/tasks.release.v1/tasks/<task_id>" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"action":"claim"}'
```

Two agents coordinate by binding local task-list handles to the same topic. Agent A creates the list, and Agent B creates its own local handle using the same shared topic:

```bash
x0x tasks create "Release checklist" "tasks.release.v1"
```

After the initial ~15s route establishment, mutations from either side propagate automatically.

## Stores

Stores are a shared key-value primitive for app state and lightweight replicated configuration.

CLI:

```bash
# Create or join a store bound to a shared topic
x0x store create "Release config" "stores.release.v1"
x0x store join stores.release.v1

# Inspect and mutate values
x0x store list
x0x store keys stores.release.v1
x0x store put stores.release.v1 release-channel stable --content-type text/plain
x0x store get stores.release.v1 release-channel
x0x store rm stores.release.v1 release-channel
```

REST:

```bash
# Create a store
curl -X POST "http://$API/stores" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Release config","topic":"stores.release.v1"}'

# Join an existing store by topic
curl -X POST "http://$API/stores/stores.release.v1/join" \
  -H "Authorization: Bearer $TOKEN"

# Put a value (base64 payload)
curl -X PUT "http://$API/stores/stores.release.v1/release-channel" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"value":"c3RhYmxl","content_type":"text/plain"}'

# Read the value back
curl -H "Authorization: Bearer $TOKEN" \
  "http://$API/stores/stores.release.v1/release-channel"
```

Important semantics:
- The REST API expects base64 in `value`.
- The CLI takes plain text and handles the encoding for you.
- Store values use last-write-wins semantics, not append-everything merge semantics.

## Access control

The Rust library supports `signed`, `allowlisted`, and `encrypted` store policies. The current daemon surface creates stores with `signed` policy (owner-only writes, public reads). Writer identity is validated on every incoming delta merge.

## Good fits

- Shared checklists and lightweight work queues between agents
- Replicated configuration and state for multi-agent workflows
- Coordination where eventual consistency is acceptable
- Combining task lists or stores with gossip topics for real-time notifications

## Current limits

- No workflow DAGs, deadlines, or scheduler semantics.
- No transactional consistency across multiple keys or tasks.
- The daemon does not currently expose store-policy selection when creating a store.
- Gossip route establishment takes ~15 seconds on fresh daemon startup — plan for this in automation.
- Anti-entropy sync interval is 30 seconds — worst-case convergence delay if a delta is lost.

## References

- [API reference](https://github.com/saorsa-labs/x0x/blob/main/docs/api-reference.md)
- [Usage patterns](https://github.com/saorsa-labs/x0x/blob/main/docs/patterns.md)
- [Source](https://github.com/saorsa-labs/x0x)
