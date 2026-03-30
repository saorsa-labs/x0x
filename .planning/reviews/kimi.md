# Kimi K2 External Review
**Date**: 2026-03-30
**Grade**: B+

## Findings

### MEDIUM severity
- [MEDIUM] src/presence.rs:91-92 - `machine_public_key: Vec::new()` in fallback path creates empty key; downstream code expecting a valid public key may fail
- [MEDIUM] src/presence.rs:260-275 - AgentOffline emission doesn't clean up associated state
- [MEDIUM] src/lib.rs:2069 - TTL parameter documented as 1-5 but no validation in code
- [MEDIUM] src/lib.rs:2088 - Error mapping with map_err loses context (anyhow error chain dropped)
- [MEDIUM] src/presence.rs:180-183 - Two separate mutexes for beacon_handle/event_handle could be inconsistent

### LOW severity
- [LOW] src/presence.rs:50-59 - O(n) lookup in peer_to_agent_id; a reverse index would be better
- [LOW] src/presence.rs:186 - `let _ =` discards send error; should at minimum log at debug level
- [LOW] src/presence.rs:293-294 - Explicit drop(cache_snapshot) unnecessary due to RAII
- [LOW] src/presence.rs:176 - event_handle uses tokio::sync::Mutex; std::sync::Mutex sufficient for brief holds
- [LOW] src/presence.rs:252 - `previous = current` clones HashSet; std::mem::swap would be more efficient
- [LOW] src/presence.rs:104-109 - AgentId fallback using PeerId bytes needs clearer documentation

## Summary
Implementation is functional and well-structured. Key concerns are the empty machine_public_key in fallback
DiscoveredAgent entries, lack of TTL validation, and silent event send failures.
