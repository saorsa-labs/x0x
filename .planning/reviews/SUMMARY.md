# External Review Summary - Task 5

## Quick Status: NEEDS FIXES (Grade D)

### Critical Issues (Must Fix)
1. **API Spec Violation**: Missing EventEmitter pattern - need `agent.on('eventType', callback)` not `agent.on(callback)`
2. **Broadcast Bug**: Channel lagged errors kill forwarding instead of continuing
3. **Fatal Error Strategy**: JS exceptions will abort process

### Must Fix Before Merging
- [ ] Implement event-specific handlers: `on_connected()`, `on_disconnected()`, `on_message()`, `on_task_updated()`
- [ ] Fix broadcast receiver to handle `RecvError::Lagged` separately
- [ ] Add Agent Drop implementation to stop background tasks
- [ ] Change ErrorStrategy::Fatal to CalleeHandled or handle errors
- [ ] Replace tokio::spawn with napi runtime spawn

### What Codex Got Right
- ThreadsafeFunction usage is technically sound
- Cancellation mechanism (oneshot + tokio::select!) is idiomatic
- Async mutex pattern is correct

### Next Steps
1. Fix the 5 critical issues above
2. Write tests for event-specific handlers
3. Re-run Codex review
4. Verify no background tasks leak after Agent drop

---

See `codex.md` for full review details.
