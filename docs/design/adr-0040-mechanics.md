# ADR-0040 mechanics — implementation notes

Follow-up status per shipped component (tracking the review chain r1–r7):

- **Signed delegation envelope** (blockers 25/26): shipped. Own-key signing,
  digest-referenced send-as attribution, attenuation, depth cap, global
  id-uniqueness registry reconstructed at startup.
- **Effectiveness rule** (blocker 28): shipped. Durable group-history commit
  is the single source of truth; DM-v2 durable-ACK is a notification only;
  crash/restart re-derives from history (rowid-fresh cached index,
  total-or-nothing rescans).
- **Structured mentions**: shipped. Daemon-side `mentions` routing with WS
  events; v1/v2 signed-byte identity preserved when absent (v3 domain when
  present).
- **Credential slot** (blocker 29): deferred as ordered (needs per-agent
  recipient envelopes + a use-broker; a group-sealed slot is not scoped).

## Signed task-ownership transfer: DEFERRED (v1 descope)

The signed `OwnerTransfer` chain (blocker 27) was **removed from v1**
(review round 7, Option B) after successive equivocation-resolution schemes
(timestamp fold → hash-chain walk → registered-target tiebreak) each proved
grindable or incomplete under signer-controlled ranking bytes:

- wall-clock ordering is backdatable by the signer;
- edge-digest fork tiebreaks mix signer-controlled timestamps (grindable);
- to-agent-identity ranking requires a registration oracle at BOTH sign
  time and admission on every path, and rollback grinding against
  registered keys remained reachable.

**v1 ships without signed owner-transfer; ADR-0040 as accepted described
it — deferred pending a non-grindable equivocation-resolution scheme;
tracked as follow-up** (candidate: registered-target hash-chain with an
enrollment-bound key directory). Recorded in the `docs/adr/README.md`
Errata; the Accepted ADR body is untouched per the immutability policy.
The `TaskItem`/`TaskListDelta` wire formats are byte-identical to
pre-ADR-0040; claim/complete attestations and the advisory assignee are
unchanged.
