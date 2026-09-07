# #449 Adoption eligibility: what entitles an owner-certified agent to a Home seat?

- **Status:** Design options for a human decision. **NOT implemented. No code.**
- **Date:** 2026-09-07
- **Author:** Claude (drafting), for David Irvine (decision)
- **Feeds:** [ADR 0060](../adr/0060-one-home-per-owner.md) *Deliberately not decided here* (item 3)
- **Must reconcile with:** [ADR 0039](../adr/0039-agent-harness-boundary.md) (Accepted, immutable)
- **Related:** issue #449; `449-single-home-per-owner.md`, `449-p4-retirement-fence.md`

## The question, in one sentence

When the losing device in the ADR-0060 Home election asks to be seated in the
owner's canonical Home, what evidence lets the winning device conclude that the
requesting agent is one of the owner's **devices** (entitled to an automatic
seat) rather than an ADR-0039 **API-key rider** sub-agent (which must not be
auto-seated)?

## Verified constraints

Each claim was read in source in this worktree at `c7abfe6`. Line numbers are
this commit's.

1. **Synced journal lines lose the hosting mode.** `apply_journal_line`
   (`src/owner_sync.rs:2492-2530`) materialises a synced record with
   `mode: crate::profile::CertMode::Acp` hardcoded at `src/owner_sync.rs:2519`,
   with the reason stated in the comment at `:2515-2518`. A `Rider` issued on
   device A therefore lands on device B as `Acp`. **Confirmed** (the brief's
   estimate of 2567-2577 was off by roughly 75 lines; the behaviour is exactly
   as described).
2. **The journal wins ties.** `owner_issued_certificates`
   (`src/lib.rs:12008-12089`) seeds `best` from journal lines (`:12028-12037`)
   and keeps the journal entry on an equal `issued_at` (`:12072-12073`).
   **Confirmed.** **Additional finding, not in the brief:** the live-certificate
   branch ALSO hardcodes `mode: profile::CertMode::Acp` (`src/lib.rs:12083`), so
   a discovery-derived roster entry reads `Acp` even when it displaces nothing.
   Mode is trustworthy only for lines this device itself wrote at issue time.
3. **The certificate carries no hosting mode.** `AgentCertificate`
   (`src/identity.rs:487-516`) has exactly five fields: user public key, agent
   public key, signature, `issued_at`, `not_after`. `IssuedCertRecord::from_cert`
   (`src/profile.rs:303-318`) therefore has nothing to read and hardcodes
   `mode: CertMode::Acp` at `:314`. Mode reaches a record only through
   `from_cert_with_mode` (`src/profile.rs:326-347`). **Confirmed.**
4. **The device set is keyed by machine and there is no machine-to-agent
   binding in Tier 1.** `OwnerEnrollment` (`src/owner_sync.rs:437-451`) is keyed
   by `machine_id: [u8; 32]`. `SyncKind` has exactly four variants
   (`src/owner_sync.rs:158-198`), with `ALL` of length four at `:174-179`.
   `SyncValue::MachineNames` (`:219-225`) is keyed by machine hex and carries
   only `display_name` and `machine_name`. **Confirmed.** Two corrections worth
   having:
   - `OwnerEnrollment` is **not** a Tier-1 record. It is local device-set state
     persisted per device (`OwnerSyncStore::enroll`, `:1057-1082`), minted by
     `POST /sync/devices/enroll` (`src/server/routes/sync.rs:312-370`). The
     device set does not replicate; each device is enrolled by hand.
   - Agent ids **do** already travel Tier 1, inside `HomePointer`:
     `primary_agent: String` and `roster: Vec<HomeRosterEntry>` where
     `HomeRosterEntry` is `{agent_id, role, state}` (`:202-207`, `:229-235`).
     Every record also carries `clock.writer_machine` (`:260-269`). That is a
     latent, partial machine-to-agent association, self-asserted by the writer.
5. **A join needs invite fields the pointer does not carry.**
   `populate_invite_base_state_v4` (`src/server/routes/identity.rs:383-428`)
   sets `genesis_creation_nonce`, `base_state_revision` and `base_state_hash` at
   `:392-394`, plus `intended_joiner` at `:423`. `SyncValue::HomePointer`
   (`src/owner_sync.rs:229-235`) carries `group_id`, `policy`, `roster`,
   `primary_agent`, `provisioned_at_ms` and none of those. **Confirmed.** A Home
   invite additionally requires an owner countersignature, because the policy
   carries an `OwnerCertified` axis (`src/groups/invite.rs:158-162`, verified at
   `:937`).
6. **The issuing daemon knows the mode, and keeps that knowledge local.**
   `POST /owner/agents` accepts `mode` as `acp` or `rider`
   (`src/server/routes/owner.rs:74-83`) and writes it through
   `from_cert_with_mode` into the local journal file (`:109-135`). Rider tokens
   are a separate local file, `<data_dir>/rider-tokens.json`
   (`src/server/rider_auth.rs:43-44`, loaded at `:279`), and `RiderTokenRecord`
   carries `sub_agent_id` (`:166-197`). **Confirmed:** the minting daemon knows,
   and nothing about that knowledge travels Tier 1.

Three further constraints govern every option below.

7. **Every Tier-1 participant proves possession of the owner secret key.** The
   session gate is machine identity, plus enrollment, plus an ML-DSA signature
   over `nonce || prover machine || verifier machine || owner id`
   (`src/owner_sync.rs:9-32`, message built at `:697-710`, exchanged at
   `:1688-1712`). Records are signed by a `UserKeypair` (`:354-376`). A rider
   holds a scoped REST token and never the owner key, so a rider cannot enter a
   sync session or mint any record. The forgery boundary is the owner key
   itself, not any individual field.
8. **Any change to a signed value's shape invalidates pre-upgrade signatures.**
   `verify()` re-serialises `self.value` with bincode (`src/owner_sync.rs:398`)
   and checks the signature over those bytes (`:412`). Bincode is positional and
   cannot recover an absent trailing field, as documented at
   `src/identity.rs:501-507`. Appending a field to `IssuanceJournal` is in the
   same hazard class as inserting an enum variant.
9. **There is no protocol feature negotiation, only strict equality.**
   `SYNC_PROTOCOL_VERSION` is `2` (`src/owner_sync.rs:93`) and a mismatch aborts
   the session (`:1659-1663`). Bumping it stops all owner sync with old peers,
   including profile, names and journal, not just the new capability.

## Options

### (a) Carry hosting mode in signed Tier-1 state

**Mechanism.** Make mode a replicated fact so `apply_journal_line` stops
inventing `Acp`. Two shapes: **(a1)** append `mode` to
`SyncValue::IssuanceJournal`; **(a2)** add a fifth `SyncKind`.

**New wire or signed state.** (a1) a new field in an existing signed value.
(a2) a new kind plus a new value variant.

**Compatibility hazard.** (a1) hits constraint 8 directly: the re-serialise in
`verify()` means every pre-upgrade journal record fails signature verification
on the new binary, and new records fail on old peers. (a2) hits constraints 8
and 9: appending the variant avoids shifting `IssuanceJournal`'s discriminant,
but a closed four-kind enum on an unchanged protocol version cannot decode the
fifth kind, and raising the version breaks all sync with old peers. Both need a
staged rollout or a versioned record envelope that does not exist today.

**ADR-0039 reconciliation.** This is the option that most needs care. ADR-0039
says sub-agents "are Home-eligible via their owner-signed certificate" and
"Home/delegation policy is mode-agnostic". Replicating mode does not by itself
amend that. Using mode to **deny** a Home seat does. Any implementation of (a)
must ship with an ADR amending 0039's mode-agnostic sentence, not a filter
buried in code. That is the precise failure ADR-0060 refused to repeat.

**Failure modes.** A wrong mode is durable: the journal is append-only
(`src/profile.rs:349-356`) and there is no correction path. Every existing
journal line predates the field and would default to `Acp`, so the first
rollout mislabels the entire installed base as device agents, which is the
permissive direction. Forgery needs the owner key (constraint 7), so a rider
cannot forge it, but any enrolled device can assert any mode for any agent.

**Does not solve.** Nothing about join mechanics (constraint 5). It also does
not make mode meaningful for agents discovered live rather than issued locally
(the additional finding in constraint 2).

### (b) Derive eligibility from the enrolled-device set

**Mechanism.** Stop asking about certificates. A seat goes to an agent that a
currently enrolled machine vouches for as the agent it runs as. Riders are
excluded structurally, because no machine runs as them.

**New wire or signed state.** A machine-to-agent binding, which does not exist
(constraint 4). Concretely, the smallest form is a new field
`agent_id: Option<String>` on `SyncValue::MachineNames`, keyed by machine hex,
asserted by that machine and signed by the owner key it holds. Signer: the owner
key, as every Tier-1 record already is. Alternatively `OwnerEnrollment` grows an
`agent_id`, but the enrollment set is local and unreplicated, so that binding
would never reach the winning device without also replicating enrollments, which
is a larger change.

**Compatibility hazard.** Same as (a1): a new field on a signed value hits
constraint 8. `MachineNames` records are the highest-churn Tier-1 kind, so the
break is immediately visible rather than latent, which is a mild advantage.

**ADR-0039 reconciliation.** Cleaner than (a). ADR-0039 grants Home eligibility
via the certificate; (b) does not withdraw that. It says the **automatic** seat
follows machine enrollment, leaving an explicitly invited rider as eligible as
ever. The 0039 text that must be honoured is the deny-by-default scope: "Rider
scopes are deny-by-default (send to Home + explicitly named groups, bounded
history read)". A rider already reaches Home by scope without holding a roster
seat, so declining to auto-seat riders removes no granted capability.

**Failure modes.** The binding is self-asserted. A compromised enrolled device
can claim to run as any agent id and obtain that agent's seat. Stale bindings
survive an agent-key rotation on that machine. An unenrolled device that holds
the owner key gets nothing, which is correct but will read as a bug.

**Does not solve.** Join mechanics (constraint 5). Also does nothing for
ACP-attached sub-agents that legitimately want Home and are not the machine's
daemon agent; under (b) they still need option (c).

### (c) Explicit per-device owner action, no inference

**Mechanism.** The owner runs a command. Either on the winner, naming the
joiner, or on the joiner, requesting a seat that the winner surfaces for
approval. The winner mints a v4 addressed invite with `intended_joiner` set
(`src/server/routes/identity.rs:423`) through the existing mint authority, and
the joiner uses the existing join path. No eligibility rule is inferred
anywhere.

**New wire or signed state.** **None.** No new `SyncKind`, no new field on any
signed value, no protocol change. The invite path already exists and already
carries every field constraint 5 requires. Transport for the invite is the open
question, not the invite itself.

**Compatibility hazard.** None in the Tier-1 layer. Old peers are unaffected
because nothing about owner sync changes.

**ADR-0039 reconciliation.** Perfect, by not engaging. Home eligibility stays
mode-agnostic exactly as 0039 states, because the owner decides per agent rather
than a rule deciding per class. Nothing in 0039 is amended.

**Failure modes.** The owner seats the wrong agent, which is a human error with
a human remedy, and the roster shows it. Or the owner does nothing, and #449's
duplicate persists indefinitely, which is precisely today's `adoption_pending`
state (`src/server/routes/home.rs:1097`) plus a way out.

**Does not solve.** It is not automatic. A fleet of many devices means many
manual acts. It also does not answer the underlying question; it makes the
question unnecessary.

### (d) Bind the agent id into the existing owner-key possession proof

Found in source, not on the brief's list. The sync handshake already runs the
one signal a rider provably cannot produce: an owner-key signature over a fresh
nonce (constraint 7). It binds machines today (`proof_message`,
`src/owner_sync.rs:697-710`). Extending the signed message to
`nonce || prover machine || verifier machine || owner id || prover agent id`
would make the peer's agent id an authenticated, freshly proven claim rather
than a stored assertion, and no stored record shape changes at all.

**New wire or signed state.** No new record kind and no change to any stored
signed value. The `Proof` frame itself stays `{ signature: Vec<u8> }`
(`src/owner_sync.rs:680`); only the message being signed grows, and the agent id
must be carried somewhere for the verifier to reconstruct it, which means a
field on `Hello` or a new frame.

**Compatibility hazard.** Constraint 9. An old peer signs the four-part message
and a new peer expects five, so both sides fail `ChallengeFailed` and all sync
stops between mixed versions. This needs the protocol version bump, and the
version gate is strict equality, so the break is total rather than graceful.
This is the same wall option (a2) hits.

**ADR-0039 reconciliation.** Same as (b): it grants an automatic seat to proven
owner-key-holding devices without withdrawing certificate-based eligibility from
anyone.

**Failure modes.** Freshness is the strength here. There is no stale binding,
because the claim is proven per session. A compromised device still claims any
agent id, so it is no stronger than (b) against a stolen owner key, which
constraint 7 says is the real boundary anyway.

**Does not solve.** Join mechanics (constraint 5), and it only covers agents
that themselves run a sync session, so an ACP sub-agent still needs (c).

## Comparison

| | new signed state | protocol change | old-peer impact | ADR-0039 | forgeable by | operator burden |
|---|---|---|---|---|---|---|
| (a1) mode field | field on `IssuanceJournal` | no | pre-upgrade journal signatures invalid both ways | **needs an amendment to 0039** | any enrolled device | none |
| (a2) fifth kind | new kind and variant | yes, version bump | all sync stops with old peers | **needs an amendment to 0039** | any enrolled device | none |
| (b) device set | field on `MachineNames` | no | pre-upgrade names signatures invalid both ways | compatible, no amendment | any enrolled device | enroll each device |
| (c) owner action | **none** | **none** | **none** | compatible, no amendment | nobody, it is a human act | one act per device |
| (d) proof binding | none stored | yes, version bump | all sync stops with old peers | compatible, no amendment | any enrolled device | none |

## Recommendation

**Ship (c) now. Treat (d) as the eventual automatic path. Do not ship (a).**

The reasoning is that (c) is the only option whose cost is bounded and known. It
needs no new signed state, no protocol version, and no amendment to an Accepted
ADR, so it cannot reproduce any of the three defects that withdrew the first
adoption attempt. It converts #449 from "the duplicate is permanent" to "the
duplicate has an exit", which is the actual user-visible complaint, and it does
so while the owner is the only party who can decide which agents are their
devices. `GET /home` already reports `adoption_pending`, so the missing piece is
one command, not a mechanism.

(a) should be rejected on its reconciliation cost rather than its wire cost.
Replicating mode would create a rule that denies riders a Home seat, and
ADR-0039 Accepted says Home policy is mode-agnostic. That is a real amendment to
an immutable ADR and should be argued on its merits in its own ADR, not acquired
as a side effect of fixing a duplicate-Home bug. The durable-mislabel failure
mode makes it worse: the first rollout stamps the entire installed base `Acp`.

(d) is the technically strongest automatic signal, because it is the only one
that is fresh rather than stored and the only one a rider structurally cannot
produce. Its blocker is the strict-equality version gate, which is a fleet
rollout problem rather than a design problem. If a protocol version bump is
being taken for another reason, (d) should ride along.

**Two uncertainties resolved on orchestrator review (source, not run).**

First, (c) needs NO new transport at all. The baseline is the existing manual
invite string plus `x0x group join --home` with the expected-owner pin
(`src/bin/x0x.rs:1290-1293`, #469 A3) — the same path any Home join uses today.
`MAX_VALUE_BYTES` (`src/owner_sync.rs:134`, 64 KiB) only matters if invite
delivery is later automated over Tier 1, which is a separate, optional step.
(c)'s "no new state" advantage therefore stands as stated.

Second, the machine-to-agent binding in (b) and (d) IS well-defined under
multi-instance: `machine.key` is loaded from the identity directory
(`src/server/mod.rs:566`), and a `--name` instance's identity directory is its
own (`storage::x0x_instance_dir`, `src/storage.rs:476-478`), so each daemon
instance on one host has a DISTINCT `MachineId`. "One machine, several
daemons" is really "several machine identities", which is the right shape.

**Remaining uncertainty.** Nothing here was run, so "all sync stops on a
version mismatch" is read from the code path at `src/owner_sync.rs:1659-1663`,
not observed.

## Open questions for David

1. Is manual seating acceptable as the shipped answer to #449, or must adoption
   be automatic before the issue closes?
2. Are you willing to amend ADR-0039's mode-agnostic Home eligibility? If not,
   (a) is off the table permanently and the choice is (b) against (c) against (d).
3. Is a protocol version bump that breaks owner sync with every pre-upgrade
   daemon acceptable, given that the fleet self-updates? That single answer
   decides whether (a2) and (d) are reachable at all.
4. Should an explicitly invited rider be able to hold a Home roster seat, or is
   scope-based Home access, which ADR-0039 already grants, the intended ceiling?
5. Does the owner ever run more than one daemon instance per machine under one
   owner key, and if so should each instance get its own Home seat?
