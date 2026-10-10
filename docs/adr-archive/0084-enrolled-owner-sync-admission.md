# ADR 0084: Admit Owner Sync from Enrolled Machines on Verified Enrollment Alone

- **Status:** Accepted
- **Accepted:** 2026-09-28 by David Irvine (charter decision D06: keep #1044, file this ADR retroactively rather than revert; accepted on the round-2 text addressing Codex round-1 findings 1–4; the SyncV1-acceptor machine-revocation re-check is required before the v0.46.0 rc; status change applied by Claude at his instruction)
- **Date:** 2026-09-28
- **Decision owners:** David Irvine (decision), Claude x0x-32 (drafting)
- **Reviewers:** Codex (cross-model review); David Irvine (acceptance)
- **Supersedes:** none
- **Superseded by:** none
- **Amends:** ADR-0041. Its Decision says owner-to-owner sync runs "over
  authenticated streams (ADR-0022 identity gate + ML-DSA owner signatures)", and
  its Trade-offs bound a compromised owner machine by "owner-key authentication
  and the connect-ACL gate (ADR-0022)". This ADR adds one narrow admission path
  that skips the agent-level identity gate and the connect ACL.
- **Vision requirement:** R3 (all my machines connected).
- **Related:** #1040, #843, #824, #1044 (merged into `codex/final-acceptance-candidate`
  at e803709), #1050 (`PeerStream::agent()` follow-up), charter decision D06
  (`.planning/x0x-charter-2026-09-28.md`), ADR-0018, ADR-0022, ADR-0038,
  ADR-0041

> **Retroactive.** The code shipped into the v0.46.0 candidate (#1044) before
> this ADR existed. That broke the rule that security-bound changes need an ADR
> first (charter §4.4 item 11). This ADR records the change so that it can be
> accepted or rejected. **If it is rejected,** revert 03cbc0c, 81e193c and 7653608
> (and #1050) on main before the v0.46.0 release candidate. Until it is decided, the
> v0.46.0 release notes say "SyncV1 enrollment admission is pending ADR review".

## Context

- **How the gate works.** The inbound stream gate (ADR-0022) resolves a
  transport-authenticated machine to the agents announced on it. It denies a
  machine with no known agent as `deny_not_verified`.
- **What a restart does.** An owner device that has just restarted has an empty
  discovery cache until an identity announcement arrives over gossip. Until
  then it:
  - **denied** its own enrolled owner machine's ADR-0041 `SyncV1` stream
    (`inbound traffic from machine with no known agent — denied`), and
  - **could not dial** that machine (`machine not in discovery cache`).
- **What it cost.** Home stayed `provisioning_pending` (#824).
  - In the R19k run, gossip delivered the identity after about 60 s.
  - In R20, on saturated testnet hosts, it had not arrived after more than
    120 s, and the Home e2e row failed (#843; root cause in
    `omp-reports/takeover-20260921/x0x32-r20-home.md`).
  - The peer did not re-announce: announcements are periodic, not triggered by
    connection.
- **Why the old gate was stricter than it needed to be.** The gate asks "which
  agent is this?", but owner sync does not need an agent identity. The
  owner-signed `OwnerEnrollment` for the machine, plus the owner-key possession
  proof inside the SyncV1 session, already carry the trust that ADR-0041
  requires.

## Decision Drivers

- **R3:** a restarted owner machine must reconnect to its own machines without
  waiting on gossip liveness.
- **Least widening:** no stream kind other than `SyncV1` and no path other than
  owner sync may be admitted without the agent-level gate.
- **Fail closed:** revoked, expired, deleted or unverifiable enrollments must be
  denied, with no cached verdict.
- **Authenticated identity:** a dial may use untrusted address hints, but
  it must reach only the enrolled machine's peer id.

## Considered Options

1. **Enrollment-only SyncV1 admission and dial** (as merged in #1044).
2. **Keep ADR-0041 as written** and fix only the liveness side: re-announce when
   an enrolled machine connects, and dial more aggressively. This leaves the
   restart deadlock tied to gossip delivery, which is exactly what failed on
   loaded hosts.
3. **Persist the discovery cache across restarts**, so that the gate knows the
   agent immediately. That is a larger storage-format change, and a stale agent
   list would pass the full gate with stale trust. It also does not help a
   first contact after an agent key rotation.
4. **Revert #1044** and ship v0.46.0 with Home listed as a known limitation.

## Decision

We will take option 1, in its merged form (#1044, with #1050 as a follow-up):

1. **Inbound admission.**
   - **Which machines qualify.** Only a transport-authenticated machine with
     **no known agent** in the discovery cache, and which is in this device's
     **verified owner enrollment set**:
     - its `OwnerEnrollment` signature chains to the local owner key;
     - the enrollment is current (not expired, not deleted);
     - the machine is not in the ADR-0018 revocation set.
   - **What happens after the prefix read.** The enrollment is re-verified. The
     gate re-checks, under the discovery-cache lock and atomically with the
     handoff, that the machine **still** has no known agent.
     - If an agent became known in the meantime, the stream takes the normal
       ADR-0022 gate (trust, revocation, connect ACL).
     - Otherwise only `SyncV1` is admitted, and only to the **registered
       owner-sync acceptor**, never the default channel.
     - Any other protocol is `deny_not_verified`, as it was before.
   - **No cache.** The enrollment is verified on every admission. There is no
     verification cache.
   - **Logging.** Admissions log `outcome = "admit_enrolled_owner_sync"`.
2. **The session proof is unchanged.** The SyncV1 session still requires the
   owner-key possession proof (ADR-0041). Enrollment admission only gets the
   stream to the point where that proof can run.
3. **Outbound dial.**
   - When no agent is known on an enrolled machine, the owner-sync pass dials
     it by machine id.
   - Enrollments carry no addresses, so the address source is the
     bootstrap-cache entry for that PeerId. **Those addresses are hints, not
     trusted data:** the cache is also filled from identity announcements
     (`src/lib.rs` ~9094–9114, ~9847–9863).
   - Every dial is peer-authenticated (QUIC peer id = enrolled machine id),
     so a wrong or poisoned address cannot reach an impostor. It can only
     waste a dial attempt or delay sync until a good address is learned.
   - An existing connection is reused.
4. **Re-announce.** When an enrolled owner machine connects, the device
   re-announces its identity and starts a sync pass. This happens at most once
   per machine every 60 s (`OWNER_REANNOUNCE_MIN_INTERVAL`). Owner sync does
   **not** depend on it.
5. **Nothing else widens:**
   - A machine with any known agent takes the normal agent-level gate.
   - The shared gate used by the datagram lane and by forwards is unchanged.
   - An enrollment-admitted stream carries an empty agent list, and its
     acceptor uses `PeerStream::peer` only. #1050 makes `agent()` return
     `Option`, so that no other consumer can assume an agent.

## Consequences

### Positive

- A restarted owner device syncs with its enrolled machines within one sync
  pass, whatever the gossip load. The #843 row becomes deterministic.
- The trust that owner sync relies on (owner signature plus session key proof)
  is now the trust the gate checks, rather than a proxy for it (the announced
  agent).

### Negative / Trade-offs

- **Denials this path skips.** On this path the discovery cache has no agent
  for the machine, so the agent-level ADR-0022 gate does not run. That gate
  would otherwise apply (`src/lib.rs` ~14065–14139):
  - agent revocation;
  - agent-certificate expiry;
  - blocked-contact and pinning checks;
  - retired-binding and placement enforcement;
  - the connect ACL.

  Only these machine-level checks apply here:
  - machine revocation (ADR-0018);
  - owner-signed, current enrollment;
  - the owner-key session proof.
- **The ADR-0041 bound on a compromised owner machine becomes weaker.**
  - Before, a machine holding a valid enrollment also needed a known agent that
    passed trust and the connect ACL.
  - Now the enrollment alone reaches the SyncV1 acceptor, and a local
    connect-ACL deny of that machine does **not** block owner sync while it
    has no known agent.
  - What remains: revocation (ADR-0018), enrollment deletion or expiry, and
    the owner-key session proof.
  - To stop a machine syncing, the owner must revoke or un-enroll it. An ACL
    entry is not enough.
- **Enrollment freshness and removal:**
  - Expiry is checked with the 5-minute clock-skew grace
    (`ENROLL_EXPIRY_SKEW_MS`), so an enrollment admits for up to 5 minutes
    after its stated expiry.
  - `unenroll` deletes the record without a tombstone. Deletion is local to
    this device. If an old, still-unexpired owner-signed enrollment for that
    machine is later re-inserted locally, for example by restoring
    `sync/devices.json` from a backup or re-running `enroll`, admission comes
    back. This is not a remote replay path, because enrollments are not
    accepted from the network.
  - An admitted owner-sync session is **not** re-checked while it is open. A
    revocation, expiry or unenroll takes effect on the next admission, not
    inside a live session.
- **Revocation race at admission.**
  - `is_enrolled_owner_machine` checks the revocation set and then releases
    that lock before the enrollment check and the discovery-lock handoff.
  - The SyncV1 acceptor (`owner_sync.rs` `handle_inbound`) re-checks
    enrollment but not machine revocation.
  - So a machine revocation that lands inside that window does not stop the
    session that is already being admitted.
  - **Required follow-up before the v0.46.0 release candidate:** the acceptor
    re-checks the machine revocation set, with a test in which the revocation
    lands after the gate and before the acceptor.
- **Two admission paths now exist for one stream kind.** They converge on the
  same acceptor, and the atomic re-check decides between them. W3's single
  `Authority::decide` (charter D17) should fold both into one decision function.
- **The code shipped before this ADR** (D06).

### Neutral / Operational

- A non-enrolled machine costs a map lookup, never an ML-DSA verification, so
  there is no new verification-flood surface on this path.
- The re-announce adds at most one network-wide announcement per enrolled
  machine per 60 s.
- Mixed versions: a 0.45 peer still denies an enrollment-only stream from a
  0.46 device until gossip identifies it. The 0.45 behaviour is unchanged
  (`.planning/mixed-version-matrix-0.46.md`).

## Validation

These tests are in #1044:

- **The deadlock repro.**
  `restarted_owner_device_with_empty_discovery_cache_syncs_both_ways_and_settles_home`
  (`src/server/routes/home.rs`, commit 7653608) is red without the fix.
- **The admission matrix**, in `src/owner_trust/tests.rs`:
  - an enrolled machine with no known agent is admitted for `SyncV1` and gets
    no other stream kind;
  - a non-enrolled machine is denied, and so is a foreign-owner, expired,
    deleted or revoked enrollment. "Revoked mid-admission" covers a
    revocation that lands before the post-prefix re-check, **not** one that
    lands between that re-check and the acceptor (see the revocation race
    under Trade-offs);
  - a known agent takes the shared gate;
  - an agent learned during the prefix read takes the shared gate, including
    the connect ACL;
  - the admission closure runs only while no agent is known;
  - no device store, or no owner, admits nothing.

**Release gate:** the Home rows 3a–3c of the v0.46.0 gate (charter §8) on the
sealed testnet. #1040 stays open until this ADR is decided.

## Notes for AI-assisted work

- Do not add a verification cache to `is_enrolled_owner_machine`.
- Do not route enrollment-admitted streams to the default channel.
- Treat every dial address as an untrusted hint. Rely only on peer-id
  authentication, never on where an address came from.
- Any new stream kind that wants enrollment-only admission needs its own ADR.
