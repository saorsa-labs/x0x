# ADR 0070: Owner Trust and Share Grants

<!-- File name: docs/adr/0070-owner-trust-and-share-grants.md -->

- **Status:** Accepted
- **Accepted:** 2026-09-25 by David Irvine ("accept ADR-0070, 0071 and 0072"; design choices 1–4 decided the same day, recorded on PR #896; status change applied by Claude at his instruction)
- **Date:** 2026-09-25
- **Decision owners:** David Irvine (direction), Claude (drafting)
- **Reviewers:** pending (cross-model review required before acceptance)
- **Supersedes:** none
- **Superseded by:** none
- **Extends (edits nothing in):** ADR-0019 (connect ACL), ADR-0046 (exec ACL),
  ADR-0018 (revocation subjects). ADR-0038 Home admission is unaffected (see §6).
- **Related:** ADR-0007, ADR-0022, ADR-0036, ADR-0037, ADR-0041, ADR-0043, ADR-0044;
  vision-alignment audit 2026-09-25 (requirements R3, R5, R7; "Missing ADRs" item 1)

## Context

Three vision requirements fail for one reason: **trust in x0x is per-`AgentId`
contact state and per-`(AgentId, MachineId)` TOML, and never consults the owner
`UserId`.**

- **R3 — "all my machines connected."** `owner_sync` enrollment
  (`OwnerEnrollment`, `src/owner_sync.rs`) is owner-signed, yet grants no trust:
  the ADR-0041 sync stream itself only runs after the ADR-0022 machine gates
  (including contact trust) already passed. `Agent::open_peer_stream`
  (`src/lib.rs`) consults only `contact_store` via `TrustEvaluator::evaluate`
  (`src/trust.rs`), which returns `Unknown` for any agent absent from contacts.
  The connect ACL (`ConnectAllowEntry`, `src/connect/acl.rs`) and exec ACL
  (`AllowEntry`, `src/exec/acl.rs`) are exact `(AgentId, MachineId)` TOML
  entries loaded once at startup, with no REST/CLI edit and no reload;
  `src/connect/` has zero owner/enrollment references. Every new machine pair
  therefore needs enroll + `Trusted` on both sides + hand-edited ACL files.
- **R5 — "share a subset of my agents with another human."** Nothing exists.
  `Contact`/`TrustLevel` carry no `UserId`; there is no grant object, endpoint
  or issue.
- **R7 — "machine-resident agents reachable by all my agents or by sharees."**
  `Pinned(MachineId)` placement exists (ADR-0037), but access is either all-open
  (`Trusted` contact) or per-agent TOML; there is no owner- or sharee-scoped
  policy.

The cryptographic material already exists: `AgentCertificate` (ADR-0007) binds
an agent key to a user key with optional signature-covered `not_after`;
`OwnerEnrollment` binds a `MachineId` to the owner key; ADR-0018's
`RevocationRecord`/`RevocationSet` gossip revocations on `x0x.revocation.v1`
with fail-closed enforcement. What is missing is a decision to *use* them as
authorization inputs.

## Decision Drivers

- One owner action should connect all of that owner's agents and machines.
- Sharing must be explicit, scoped (which agents, which capabilities), expiring
  and revocable — never a side effect of contacts or group membership.
- Default-closed stays default-closed: connect/exec never open without a rule.
- Reuse ADR-0007/0018/0036 primitives; no new crypto, no DHT (ADR-0006).
- Explicit local denial (`Blocked`, revocation) always wins over any grant.

## Considered Options

1. **Contacts-only trust (today).** Each pair of agents marks the other
   `Trusted`; ACLs hand-edited. Fails R3 (O(n²) manual steps per owner, and
   nothing ties the result to the owner — a stolen agent key stays trusted until
   every peer edits contacts), fails R5 (contacts are all-or-nothing per agent,
   no capability scope, no expiry, no owner-signed revocation), fails R7 (no way
   to say "any of my agents" or "Bob's agents").
2. **Per-agent TOML ACLs only.** Exact pairs in `connect-acl.toml` /
   `exec-acl.toml`. Fails R3 (every new agent/machine needs a file edit and a
   restart on every host), fails R5 (the grantor cannot express "all of Bob's
   agents" — Bob's future agents are unknowable pairs), and cannot be revoked
   remotely.
3. **Group membership as a proxy for sharing.** Put shared agents and the
   grantee's agents in a named group; treat membership as authorization. Fails
   R5/R7: membership is a messaging/encryption relation, not a capability set
   (no per-cap scope such as "connect to port 22 only"); group admins other than
   the owner can add members, so authority leaks to non-owners; removal
   semantics are MLS epoch/fork machinery (ADR-0064/0066), far heavier than a
   revocation; and reusing Home for this would violate ADR-0038.
4. **Owner trust + signed ShareGrant + editable ACLs (chosen).**

## Decision

### 1. Owner trust

Let *local owner* be the `UserId` of this install's active `user.key`
(ADR-0036). A remote `(AgentId, MachineId)` pair is **owner-trusted** when all
hold:

- the agent presents a valid, unexpired `AgentCertificate` whose user key
  derives to the local owner `UserId`;
- the machine holds a current `OwnerEnrollment` signed by that same owner key
  (owner device set, `OwnerSyncStore::is_enrolled`);
- neither the agent, the machine, nor the ADR-0043 binding is in the local
  `RevocationSet`, and the agent is not `Blocked` in contacts.

Installs without an owner have no owner trust. Evaluation points:

- **Trust evaluation:** `TrustEvaluator` gains an owner-trust input; an
  owner-trusted pair yields `Accept` where it would otherwise be `Unknown`.
  Order: revocation → `Blocked` → machine-pin mismatch → owner trust → existing
  rules. Owner trust never overrides an explicit denial.
- **Stream gate (`open_peer_stream` / accept loop):** owner-trusted pairs pass
  the trust step with no contact entry, which removes the ADR-0041 bootstrap
  circularity.
- **Connect ACL / exec ACL:** a new principal selector `principal = "owner"`
  matches any owner-trusted pair. Targets (connect) and exact argv (exec,
  ADR-0046) remain explicit per entry. No entry ⇒ denied, as today. The shipped
  default files contain no `owner` entries; one `x0x acl add` enables them.

Revocation of an agent, machine or binding through ADR-0018 removes owner trust
at the next evaluation; deleting the enrollment (`DELETE /sync/devices/:id`)
removes the machine from the device set.

### 2. ShareGrant

A new owner-signed object:

```
ShareGrant {
  grant_id:   [u8; 32]           // random
  owner:      UserId             // grantor; signer
  grantee:    Grantee            // User(UserId) | Agent(AgentId) — Agent only
                                 //   when the grantee has no user identity
  agents:     Vec<AgentId>       // non-empty subset; each must hold an
                                 //   AgentCertificate from `owner`
  caps:       BTreeSet<ShareCap> // Dm | Exec | Connect { ports: Vec<u16> } | GroupInvite
  not_before: u64                // unix seconds
  expiry:     u64                // unix seconds; mandatory
  signature:  Vec<u8>            // ML-DSA-65 by owner key over a
                                 //   domain-separated canonical encoding
}
```

- **Issuance and distribution:** the owner signs on any owner install
  (`POST /grants`, `x0x grants add`). The grant is delivered by DM to the
  grantee's agents and to each shared agent's daemon (owner-trusted, §1). A
  shared agent verifies the signature against *its own* owner `UserId`, so a
  grant naming it but signed by anyone else is inert. The grantee also attaches
  the grant `grant_id` when opening a DM/stream so a daemon that missed delivery
  can request it.
- **Grantee match:** `User(u)` matches a requester whose `AgentCertificate`
  chains to `u`; `Agent(a)` matches exactly `a`. The requester's machine still
  passes the ADR-0022 identity gates.
- **Enforcement points (on the shared agent's daemon):**
  - *DM acceptance:* `Dm` promotes the grantee from `Unknown` to `Accept` for
    DMs addressed to a shared agent.
  - *Exec ACL:* entries may use `principal = "grant"`; they match only a
    grantee holding a current grant with `Exec` covering the target agent.
    Argv allowlisting (ADR-0046) is unchanged.
  - *Connect ACL:* `principal = "grant"` entries match only if the requested
    loopback target port is in the grant's `Connect { ports }`.
  - *Group admission:* `GroupInvite` lets shared agents accept invites from the
    grantee without a contact entry. It never satisfies
    `GroupAdmission::OwnerCertified`.
- **Revocation:** `RevokedSubject` gains `ShareGrant(grant_id)`; authority rule:
  the issuer key must derive to the grant's `owner` (owner-key only, like
  `AgentMachineBinding`). Gossiped and persisted via the existing ADR-0018 path.
- **Fallback:** unknown, not-yet-valid, expired, revoked, malformed or
  wrong-owner grant ⇒ evaluate as if no grant existed (today's behaviour;
  connect/exec default-closed).
- **No transitive re-sharing:** a grantee cannot issue grants over agents it
  does not own; `agents` must all be certified by the signer.

### 3. ACL and grant management

- REST on the ADR-0044 loopback plane (owner/durable token only; rider and
  session tokens are refused): `GET/POST/DELETE /acl/connect`,
  `GET/POST/DELETE /acl/exec`, `POST /acl/reload`, `GET/POST/DELETE /grants`.
  CLI mirrors: `x0x acl …`, `x0x grants …`, via the shared endpoint registry.
- The operator TOML file stays the **floor**: API-added entries persist in a
  daemon-owned overlay file in the instance data dir; `GET` shows the origin of
  each entry; file entries cannot be removed via API (`409`).
- Hot reload on `POST /acl/reload` and `SIGHUP`. Startup remains fail-closed
  (ADR-0019/0046). On reload, a malformed file or overlay is rejected, the last
  validated ACL stays active, and the error is surfaced in `/diagnostics`.

### 4. Non-goals (anti-creep)

No roaming or key moves (ADR-0037/0043 unchanged); no Home changes; no new
group crypto or MLS changes; no global DHT or grant directory; no transitive
re-sharing; no grants over machines or groups (agents only); no UI design
beyond REST/CLI parity.

### 5. Slicing

Each slice ships alone and carries a test that proves the intent, including the
negative case.

1. **Owner trust.** Two daemons, same owner, no contacts, no ACL edits: stream
   opens and trust = `Accept`. *Intent tests:* (a) a third daemon with a
   *different* owner is still `Unknown` and its stream is refused; (b) same
   owner but machine not enrolled ⇒ refused; (c) after `POST /identity/revoke`
   of the agent, the previously accepted pair is refused; (d) `Blocked` beats
   owner trust; (e) connect/exec with no `owner` entry remain denied.
2. **ACL REST/CLI + reload.** Add an entry via API, connect succeeds without
   restart; delete it, connect denied. *Intent tests:* deleting a file-floor
   entry returns 409 and access persists; a malformed reload keeps last-good
   and does not widen access; a rider token cannot mutate ACLs.
3. **ShareGrant.** Owner A grants user B `{Dm, Connect{22}}` over agent A1.
   *Intent tests:* B's agent DMs A1 and connects to :22; B is denied :80 and
   denied A2 (not in `agents`); user C is denied everything; after grant
   revocation or expiry B is denied again; a grant signed by B over A1 is
   inert; a `GroupInvite` grant does not admit B to A's Home.

### 6. ADR-0038 is unaffected

ADR-0038's "no other human can ever join" is a property of Home admission
(`OwnerCertified(UserId)`). Grants share *agents*, not the Home: no grant cap
satisfies `OwnerCertified`, and slice 3 tests it.

## Consequences

### Positive

- R3: one enrollment per machine connects all of an owner's agents; no contact
  or TOML edits between one's own machines.
- R5/R7: a human can expose a chosen subset of agents, per capability, with
  expiry and remote revocation, to another human's current and future agents.
- ACLs become operable without restarts, while the file floor keeps operator
  control.

### Negative / Trade-offs

- Owner-key compromise now also grants trust across all the owner's machines
  and over all grants. Mitigated by ADR-0018 revocation and mandatory grant
  expiry, not eliminated.
- `Grantee::User` trusts every agent the grantee certifies, including future
  ones; grantors who want narrower scope use `Grantee::Agent`.
- Revocation is eventually consistent (gossip); expiry bounds the window.
- Another persisted object store (grants) and an overlay ACL file to audit.

### Neutral / Operational

- New principal selectors in ACL TOML are additive; existing exact-pair files
  keep their meaning.
- `RevokedSubject` gains a variant. Because `x0x.revocation.v1` gossips the
  full `Vec<RevocationRecord>`, slice 3 must first establish (as ADR-0043's
  `AgentMachineBinding` variant had to) that an older daemon receiving an
  unknown variant does not reject the whole set; unverified here.

## Validation

- The slice tests in §5 run in CI (not `#[ignore]`), each with its negative case.
- Audit check: `grep -rn 'owner' src/connect/ src/exec/` is non-zero after slice
  1, and every enforcement point has a test that fails if the grant/owner check
  is removed.
- Review trigger: deriving authorization from group membership, or re-sharing.

## Notes for AI-assisted work

AI tools may draft this ADR but must not mark it Accepted without human
review. Accepted ADRs are immutable — supersede, don't edit.
