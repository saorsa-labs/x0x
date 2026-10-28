# ADR-0021 mechanics — DM origin-machine attestation mechanics

> Extracted 2026-08-29 from the immutable [ADR 0021](../adr/0021-dm-origin-machine-attestation.md) per the
> 2026-08-23 ADR audit. The ADR remains the complete decision record; the
> sections below are the attestation format, verification, and move-policy
> mechanics relocated verbatim so this file is their maintained home — future updates
> belong here, not in the ADR.

### Signed material

`DmOriginAttestation` (new struct in `src/dm.rs`):

| field | purpose |
|---|---|
| `attestation_version: u16` | format version (1); unknown versions fail closed |
| `protocol_version: u16` | mirrors the envelope's DM protocol version |
| `sender_agent_id: [u8; 32]` | the DM principal |
| `sender_machine_id: [u8; 32]` | claimed origin machine |
| `machine_public_key: Vec<u8>` | self-certifying ML-DSA-65 machine key |
| `recipient_agent_id: [u8; 32]` | replay scope |
| `request_id: [u8; 16]` | binds the attestation to one logical DM (retries reuse it) |
| `created_at_unix_ms / expires_at_unix_ms: u64` | freshness/expiry window (mirrors envelope) |
| `signature: Vec<u8>` | ML-DSA-65 over the bytes below, by the machine secret key |

Signed bytes (deterministic, domain-separated — mirrors
`ForwardV2Header::signable_bytes`):

```
"x0x-dm-origin-attestation.v1"
|| attestation_version.be || protocol_version.be
|| request_id || sender_agent_id || sender_machine_id
|| len32be(machine_public_key) || machine_public_key
|| recipient_agent_id
|| created_at_unix_ms.be || expires_at_unix_ms.be
```

---

### Verification (receiver, zero prior state)

In `InboxPipeline::handle_incoming`, after the existing envelope-signature
and sender-match checks:

1. **Attestation present and valid** → the attested `MachineId` wins.
   Verification is self-contained: `machine_public_key` parses;
   `MachineId::from_public_key(key) == sender_machine_id` (hash binding);
   every mirrored field equals the envelope's; the ML-DSA-65 signature
   verifies. The retained #184 binding is **refreshed** with the attested
   machine (`created_at_unix_ms / 1000`, keeping the cache's
   seconds-granularity ordering coherent with announcement-sourced
   bindings).
2. **Attestation present but invalid** (any check fails, including unknown
   `attestation_version`) → **hard drop**. No fallback: a present-but-bad
   attestation is an attack or corruption signal, never a legacy peer.
3. **Attestation absent** (legacy peer) → the existing #184 path:
   retained-binding match enforced when a binding exists; claimed-machine
   fallback otherwise.

The EP3 revocation gate then runs against the **resolved** machine id, so a
revoked origin A fails even when the envelope claims unrevoked B: claiming B
requires B's machine signature (unforgeable), and carrying A's valid
attestation names A, which EP3 rejects.

### Absent attestation after a machine revocation (#1659)

David approved this receiver rule on 28 Oct 2026 at 02:08 GMT (D283).
The wire format is unchanged.

When this receiver can attribute a revoked machine to an agent, the DM
inbox requires that sender's origin (device) attestation and refuses an
unattested DM from an older pre-#213 peer. The same rule covers an
unattested ACK on the DM lane. An ACK is delivery evidence. It must not
be accepted from a device this receiver would refuse a DM from. The
trigger is the same for both: only once the agent has a machine
revocation. That is a deliberate partial override of ADR 0021's
accept-with-binding-fallback transition policy, and it applies only when
the link is known here. A sender this receiver cannot link to a revoked
machine keeps that policy. The check runs before the body match.

`InboxPipeline::handle_incoming` is the check. The per-agent inbox topic
and the compatibility gossip bus both use that function.

The inbox attributes these machines to the sender:

- every verified machine the authenticated-binding cache has accepted for
  the sender. An identity announcement records its machine when that
  announcement is accepted. A DM records its machine only after decryption
  succeeds. An ACK records its machine only when the trust check admits it
  and a local waiter matches. A refused DM, an undecryptable DM, and an
  unsolicited ACK do not take a slot. The set includes the retained
  binding, a machine a later binding replaced, and a verified machine that
  lost timestamp selection. Evicting a retained binding does not drop this
  set. One agent can record 8 machines. A ninth machine for that agent is
  not recorded. The cache holds 65,536 pairs in three shares. Trusted
  or Known contacts use the remainder, 45,056 pairs. Protected
  non-contacts use 16,384 pairs. A protected non-contact is a member of
  a group whose admission needs an invite or approval (invite-only,
  request-access, or owner-certified), or a grant party, and is not a
  Trusted or Known contact. OpenJoin membership does not protect a
  peer. Strangers, including OpenJoin co-members, share a bounded LRU
  of 4,096 pairs. That share stays available when the other shares are
  full. A new pair past a non-contact share evicts the least-recently
  used pair in that share. That evicted machine is no longer attributed.
  A stranger insert does not evict a contact pair or a protected
  non-contact pair. A stranger flood that evicts a stranger pair is a
  residual. Standing is chosen again on every record and on every
  contact change. Deleting or downgrading a contact keeps protection
  that still comes from a qualifying group or a grant. A library
  embedder that does not run the `x0xd` probe gets contact-only
  protection. After an eviction frees one of an agent's slots, a later
  admitted machine is recorded again. 4,096 overflowed agents can be named.
  Overflow does not refuse an unattested DM or ACK by itself. A
  revocation of an unrecorded machine is not attributed, and an
  unattested DM or ACK that claims a different, clean machine can still
  be accepted. That loss of attribution is a residual. A valid
  attestation is still accepted. The set is process memory. It lasts
  until process restart, including a self-update restart.
  The daemon does not persist the set. Rebuilding a replaced machine from
  disk would need a new stored format, which this rule does not add. When
  the stranger pool evicts or the name list fills, the cache emits a
  rate-limited warning on a monotonic clock. An unattested refusal that
  also finds an overflowed set is an internal counter and the same kind of
  warning. It is not a field of `GET /diagnostics/dm`.
- a machine on the sender's contact
- a machine named by a binding tombstone for that agent (indexed by agent)
- the machine the envelope claims

An older pre-#213 peer of that sender is refused the same way. A valid
origin attestation is still accepted. EP3 still drops an attested DM whose
resolved machine is revoked. A machine-revocation record still expires
under the existing revocation TTL, and this refusal ends with that record.

A sender with none of those machines revoked keeps the absent-attestation
path above. Attribution overflow does not change that. A machine
revocation for some other device does not change that sender's path. A
cold receiver that cannot attribute the revoked machine to the sender
still follows the ADR 0021 claim fallback. That fallback is the remaining
strip residual: an unattested envelope whose origin attestation was
removed, claiming a machine this receiver cannot attribute.

Restart residual. A machine known only through the in-memory accepted
set is not attributed after a restart. The revocation record for that
machine can still be stored. An unattested DM that claims a different,
clean machine is accepted again, because the inbox can no longer
attribute the revoked machine to the sender. Contacts, binding
tombstones, the claimed machine, and a retained binding that has been
rebuilt in this process still count. Those records already persist.
The accepted-machine history does not.

Cap residual. A machine past the per-agent cap of 8 is not in the
accepted set. Revoking that machine does not make an unattested DM that
claims a different, clean machine fail. An unattested DM that claims a
clean machine this receiver still attributes can be accepted. A stranger
pair the LRU evicted is the same kind of gap for that one machine. The
next verified announcement or decrypted DM from that stranger can take a
slot again. An agent that passed the cap records again after a stranger
eviction frees one of its slots.

Tombstone residual. A binding tombstone that names a revoked machine
keeps refusing that agent's unattested DMs for as long as the revocation
record is held. Decommissioning the machine does not clear the refusal.

An attacker who holds the agent key can mint a fresh machine and a
valid attestation. This check does not stop that DM. A binding tombstone
blocks only the named agent-and-machine pair. The attacker can still
attest from another machine. Containing an agent-key compromise requires
an agent revocation.

The relay `DeliverLocally` path (`RelayDisposition::DeliverLocally` in
`src/lib.rs`) takes the envelope's claimed machine and does not apply this
refusal. Relay delivery is off unless `[peer_relay] enabled = true`.

---

### Portable-agent move policy (A → B)

A move is legitimate when the agent keyholder starts sending from machine B.

- **Per-DM authentication.** Each DM authenticates its own origin machine;
  there is no session or registration step. B's first attested DM is
  accepted immediately, even with zero receiver state and even while the
  retained binding still says A — the valid fresh attestation supersedes
  (and refreshes) the stale binding.
- **Freshness and order.** The attestation mirrors the envelope's
  `created_at/expires_at`, already window-validated (30 s future skew;
  ≤ 10 min lifetime). The retained-binding cache orders updates by
  timestamp (seconds): a later announcement or attestation may move the
  binding; an older one cannot roll it back.
- **Overlap.** During a move, DMs may briefly arrive from both A and B.
  Both verify independently; delivery is per-DM, so overlap is benign.
- **Revocation interaction.** Revoking A after a valid move does not affect
  B-attested DMs (EP3 checks the resolved machine, B). A-attested DMs in
  flight when A is revoked are dropped by EP3 — intended fail-closed.
