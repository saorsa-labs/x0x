# #1108 slice 3 — owner revokes its own Machine: design note

Status: for decision. No code is written. Facts are from main `e79ae2d81`.
Author: Claude, 10 Nov 2026. Authority for the goal: David's ruling A on
#1108, 20 Oct 2026 ("add the owner Machine revocation issuer path").

## 1. What is wrong today

- `verify_authority` (`src/revocation.rs`) accepts a Machine record only when
  the issuer key hashes to the machine id. Only the machine can revoke
  itself. An owner cannot revoke a lost device.
- The one-id `POST /identity/revoke` always signs with the daemon's **agent**
  key. With `machine_id` set to the daemon's own machine it returns `403`,
  although the daemon holds the machine key.

## 2. The hard part: who may say "this machine is mine"?

Other peers must be able to check an owner-signed Machine revocation. For
that they need proof that the machine belongs to that owner. Three kinds of
evidence exist or could exist:

| Evidence | Who signed it | What it proves | Problem |
|---|---|---|---|
| `OwnerEnrollment` (`src/owner_sync.rs`) | Owner only | The owner says the machine is theirs | **Not consent.** `POST /sync/devices/enroll` takes any `machine_id`. An owner can enroll a stranger's machine id. If peers took this as proof, any user could revoke any machine on the network. Also, only the owner's own devices hold it. |
| V3 machine announce + agent certificate | Machine signs the announce; owner signs the certificate | The machine itself said "I host agent A", and the owner certified A | Proves the machine hosts **one** of the owner's agents, not that the owner owns the machine. A machine can host agents of two owners. Then owner U could kill owner V's agents on a shared machine. |
| Enrollment **acceptance** (new) | Machine key | "Machine M accepts user U as its owner" | Does not exist yet. A device that is already lost cannot sign one. |

So an owner-signed Machine revocation that other peers obey needs a new
machine-signed statement. No evidence that exists today is safe to use
network-wide.

## 3. Options

### Option A — "lose-device" from records that exist today (no wire change)

`x0x owner lose-device <machine>` / `POST /owner/devices/:machine_id/lose`
does, with the owner key, on any of the owner's devices:

1. For each of the owner's agents known on that machine: an owner-signed
   **binding tombstone** `(agent, machine, epoch)` on the v2 carrier
   (`Agent::revoke_binding`, exists).
2. For each agent **pinned** to that machine: an owner-signed **agent**
   revocation (`revoke_as_owner`, exists). A roaming agent keeps its
   identity and loses only this machine.
3. Unenroll the machine from the owner device set (exists; stops owner
   sync and Home access for it).

- Signed bytes, wire, storage: no change. Released receivers already
  enforce all three record kinds.
- Effect: every agent the owner certified is dead on that machine,
  everywhere. The owner cannot hurt another owner's agents on a shared
  machine.
- Limit: the machine **key** is not revoked. The thief can run the machine
  with a new agent that has no certificate. That agent is a stranger to
  every peer and has none of the owner's rights. An owner agent certified
  *after* the action and bound to that machine would need a new tombstone.
- `verify_authority` does not change. This does not add the "owner Machine
  issuer path" in the literal sense of the ruling.

### Option B — true Machine revocation with a machine-signed acceptance (new carrier)

1. **At enrollment**, the enrolled machine signs an acceptance:
   `"x0x-machine-accepts-owner-v1" ‖ machine_id ‖ owner_user_id ‖ accepted_at_ms`
   with its machine key. One machine accepts at most one owner at a time.
   The owner's devices keep it next to the enrollment (owner sync).
2. **To revoke**, the owner signs an ordinary record: subject
   `Machine(machine_id)`, issuer = owner key. The record's signed bytes do
   not change (`x0x-revocation-v1 ‖ 0x02 ‖ machine_id ‖ issuer ‖ revoked_at ‖
   reason`).
3. **On the wire**, the record travels with its evidence on a new topic
   `x0x.revocation.v4`: `Vec<{ record, acceptance }>`. New store file
   `revocations-v4.bin` (same pattern as v2 and v3).
4. **`verify_authority`** gains one path for Machine subjects: the
   acceptance signature verifies under a key that hashes to the subject
   machine id, and it names the user id of the record's issuer.

- Size: record ≈ 5.3 KB, acceptance ≈ 5.3 KB (1952-byte key, 3309-byte
  signature). About 10.6 KB per revoked machine.
- Replay: a revocation is permanent and idempotent, so replaying it does
  nothing new. Replaying an old acceptance lets the *former* owner revoke a
  machine that kept its key after it changed hands. That is accepted: a
  machine that changes owner must get a new key.
- Released receivers: they do not subscribe to `x0x.revocation.v4`, so they
  never decode it. They do not crash and do not enforce it. If someone puts
  the bare record on v1, a released receiver rejects that one record
  ("issuer is neither the subject nor the certifying user") and keeps the
  rest of the batch.
- **The record must not ride v1, v2 or v3.** A node that waits for a
  revocation resync (#1116) opens a carrier only when every record in a
  trusted snapshot verifies. A record that old nodes cannot verify would
  keep their v1 carrier closed.
- Downgrade: until a peer upgrades, the machine is not revoked on that
  peer. Option A's records cover that gap.
- Limit: a device that was enrolled before this change, and is already
  lost, has no acceptance. Option B cannot revoke it.

### Option C — accept announce + certificate as evidence

Same carrier as B, but the evidence is a retained V3 machine announce plus
the agent certificate. It works for devices that are already lost.
I do not recommend it: it gives an owner power over a shared machine and
over any machine that ever announced one of the owner's agents, and the
evidence is about 12.5 KB.

## 4. The own-machine `403` (falls out, no wire change)

In the one-id form of `POST /identity/revoke`, when `machine_id` is this
daemon's own machine, sign with the daemon's **machine** key. That is a
self-revocation, which `verify_authority` and every released receiver
already accept. Require the durable token. Warn in the response that the
daemon's transport identity is dead after it. A third party with no
authority keeps its `403`; that answer is correct.

## 5. Recommendation

1. **Now, one PR, no wire change:** Option A (`lose-device`) and the
   own-machine fix of §4. This gives the lost-device response that A03
   asks for ("revoke the applicable machine or agent authority, end live
   access"), works against devices that are already lost, and every
   released node enforces it.
2. **Then, as its own decision:** Option B for a true Machine revocation.
   It needs a new signed object, a new topic and a new store file, so it
   needs a `FOR ENGINEER` approval. Its extra value over A is small: it
   also stops the machine key from being used for agents with no
   certificate.
3. **Not C.**

Questions for the decision:

- Is Option A enough to count as "the owner Machine revocation issuer
  path", or is Option B required as well?
- May a machine have more than one owner? Option B assumes one.

## 6. Tests each option would need (RED first)

- A: after `lose-device`, a peer that holds the records refuses each owner
  agent on that machine and still accepts a roaming agent on another
  machine; another owner's agent on the same machine is not touched; the
  call needs the owner key and the durable token.
- §4: own-machine revoke returns `200`, and a second daemon accepts the
  record; another machine's id returns `403`.
- B: a record with a valid acceptance is accepted; an owner-only
  enrollment as evidence is refused; an acceptance for another owner or
  another machine is refused; the bare record on v1 is refused and the
  rest of the batch is applied; a v4 file does not load as v1.
