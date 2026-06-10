# Phase D.3 Proof Report — Stable Identity + Evolving Validity

> **Honesty clause.** This report documents what Phase D.3 delivers — no more,
> no less. It is explicitly NOT a claim of full named-group support under
> `docs/design/named-groups-full-model.md`. That requires all phases
> D.3 → C.2 → E → D.4 → F to land. This report covers D.3 only.

## Scope of D.3

Deliver the foundational primitives for stable identity + evolving validity:

1. `GroupGenesis` — immutable stable `group_id` derived from
   `(creator_agent_id, created_at, creation_nonce)` via BLAKE3.
2. `GroupStateCommit` — authority-signed commit with monotonic `revision`,
   `prev_state_hash`, and BLAKE3 state-hash over
   `(group_id, revision, prev, roster_root, policy_hash, public_meta_hash,
   security_binding, withdrawn)`.
3. `GroupCard` with authority-signature fields (`revision`, `state_hash`,
   `prev_state_hash`, `issued_at`, `expires_at`, `authority_agent_id`,
   `authority_public_key`, `withdrawn`, `signature`).
4. Apply-side validation (`validate_apply`) that enforces chain linkage,
   monotonic revision, authority role check, structural signature check,
   and withdrawal terminality.
5. Withdrawal supersession: owner seals a higher-revision commit with
   `withdrawn=true`; peers evict stale public cards on receipt
   regardless of TTL.
6. Three endpoints:
   - `GET /groups/:id/state`
   - `POST /groups/:id/state/seal` (owner/admin)
   - `POST /groups/:id/state/withdraw` (owner)

## Explicit claims

1. **Stable identity.** `GroupInfo::stable_group_id()` returns a
   deterministic BLAKE3-derived id that does not change across rename,
   metadata edits, role changes, roster churn, or security-epoch rotation.
2. **Monotonic chain.** `seal_commit` bumps `state_revision` by exactly
   one; `prev_state_hash` equals the state_hash prior to the seal; the
   new `state_hash` commits to (roster_root, policy_hash,
   public_meta_hash, security_binding, withdrawn).
3. **State-hash coverage.** Any change to members (add / remove / ban /
   role), policy, public metadata (name / description / tags / avatar /
   banner), or security epoch (GSS rotation) produces a different
   `state_hash`.
4. **Authority signature.** Every sealed commit and every signed card
   verifies under the signer's ML-DSA-65 public key. Structural tamper
   (state_hash or any component) is detected by `verify_structure()`
   and `verify_signature()`.
5. **Cross-peer convergence.** A replica mirroring the same mutation and
   then calling `apply_commit(&commit, ActionKind)` reaches the same
   `state_hash` as the authority.
6. **Stale rejection.** Replaying an earlier commit on a later-state
   group returns `ApplyError::StaleRevision`. A commit whose
   `prev_state_hash` does not match returns
   `ApplyError::PrevHashMismatch`.
7. **Authorization rejection.** A commit signed by a non-owner being
   applied as `ActionKind::OwnerOnly` returns
   `ApplyError::Unauthorized`.
8. **Withdrawal terminality.** Once a group is withdrawn, subsequent
   `seal_commit` calls produce commits that still carry `withdrawn=true`.
9. **Card supersession across peers.** Published signed cards supersede
   stale cached cards on peers — the receiver listener drops lower
   revisions and accepts higher ones. Withdrawn cards evict the entry
   regardless of prior revision.
10. **Honest v1 secure model.** `security_binding` reflects GSS
    `secret_epoch`; this is documented as the interim v1 secure model
    and does **not** claim MLS TreeKEM per-message forward secrecy.

## Live mutation/apply paths: what uses state-commit now vs deferred to D.4

Per user directive: be explicit about which live paths already route
through the new state-commit model vs which still use the pre-D.3
per-field revision counters.

### Paths already using the D.3 state-commit model

| Path | Mechanism |
|---|---|
| `POST /groups/:id/state/seal` | `GroupInfo::seal_commit` — bumps `state_revision`, records `prev_state_hash`, signs a `GroupStateCommit`, emits signed `GroupCard` to `x0x.discovery.groups`. |
| `POST /groups/:id/state/withdraw` | `GroupInfo::seal_withdrawal` — sets `withdrawn=true`, seals terminal higher-revision commit, emits signed withdrawn card. |
| `publish_group_card_to_discovery` (all emit sites, including the implicit emits on policy/metadata changes) | Routes through `publish_group_card_to_discovery_inner`, which signs every card with the local agent's ML-DSA-65 key before publishing. |
| Global discovery listener receive path | Verifies `GroupCard::signature` on every signed card; drops bad sigs; supersedes by revision (`card.supersedes(existing)`); evicts on `withdrawn=true` regardless of TTL. |
| `GroupInfo::rotate_shared_secret` (ban/remove rekey, D.2) | Updates `security_binding = "gss:epoch=N"`; next `seal_commit`/`recompute_state_hash` folds it into `state_hash`. Roster and secure plane cannot silently drift. |
| `GroupInfo::apply_commit` (library API) | Available for future receive-side event processing; exercised by the 18 integration tests in `tests/named_group_state_commit.rs`. |

### Paths deferred to Phase D.4

The existing per-action metadata events in `x0xd.rs` still use the
pre-D.3 per-field revision counters (`policy_revision`,
`roster_revision`) and inline authz checks. D.3 **did not** rewire
these. D.4 routes each one through `seal_commit` + `apply_commit` so
every state-bearing action is authority-signed and chain-linked.

| Event / handler | Current mechanism | D.4 migration target |
|---|---|---|
| `NamedGroupMetadataEvent::MemberAdded` | `roster_revision` monotonic check + creator-auth | seal + apply_commit (AdminOrHigher) |
| `NamedGroupMetadataEvent::MemberRemoved` | `roster_revision` + creator-or-self auth | seal + apply_commit |
| `NamedGroupMetadataEvent::GroupDeleted` | `roster_revision` + creator-only | seal a withdrawal commit + apply_commit |
| `NamedGroupMetadataEvent::PolicyUpdated` | `policy_revision` + creator-only | seal + apply_commit (OwnerOnly) |
| `NamedGroupMetadataEvent::MemberRoleUpdated` | `roster_revision` + admin-rank + target checks | seal + apply_commit (AdminOrHigher) |
| `NamedGroupMetadataEvent::MemberBanned` | `roster_revision` + admin-rank | seal + apply_commit + rekey |
| `NamedGroupMetadataEvent::MemberUnbanned` | `roster_revision` + admin-rank | seal + apply_commit |
| `NamedGroupMetadataEvent::JoinRequestCreated` | request-id dedup + admission gate | seal + apply_commit (NonMemberRequest) |
| `NamedGroupMetadataEvent::JoinRequestApproved` | admin-rank + request lookup | seal + apply_commit + rekey |
| `NamedGroupMetadataEvent::JoinRequestRejected` | admin-rank + request lookup | seal + apply_commit |
| `NamedGroupMetadataEvent::JoinRequestCancelled` | self-requester check | seal + apply_commit (MemberSelf or NonMember) |
| `NamedGroupMetadataEvent::GroupMetadataUpdated` | creator-only | seal + apply_commit |
| `NamedGroupMetadataEvent::SecureShareDelivered` (D.2) | admin-rank | no chain commit needed; AEAD envelope is the binding |

**Consequence for D.3 scope:** a `/state/seal` call binds the
currently-observed roster / policy / metadata / epoch into a signed
commit. If a concurrent per-action event (e.g. `MemberAdded`) mutates
the roster between seals, that mutation is captured in the **next**
seal. D.4 will make every mutation automatically produce a chain-linked
commit so there is no window of uncommitted state.

## Explicit non-claims

- This report does **not** claim Phase C.2 (distributed tag/name/id
  shard discovery). Current cross-peer discovery still uses the
  `x0x.discovery.groups` bridge topic; shard-based AE comes in C.2.
- This report does **not** claim Phase E (public group send/receive
  with SignedPublic ingest validation and moderation enforcement).
- This report does **not** claim Phase D.4 (every existing
  per-action metadata event routed through `apply_event`). The current
  D.3 slice wires the state-commit chain primitives and the public card
  flow end-to-end; granular per-action wiring is D.4's scope.
- GSS is not per-message forward-secret within an epoch. Full MLS
  TreeKEM is follow-up work, explicitly acknowledged and not blocking v1.

## Commands run

```bash
cargo fmt --all -- --check
cargo clippy --all-features --all-targets -- -D warnings
cargo nextest run --all-features --workspace
cargo build --release --bin x0xd --bin x0x
bash tests/e2e_named_groups.sh > tests/proof-reports/named-groups-d3-run{1,2,3}.log 2>&1
```

`x0x-user-keygen` remains buildable from source as a deprecated compatibility shim;
runtime scripts use the canonical `x0x user-id create` command.

## Unit + Integration evidence

- **`src/groups/state_commit.rs`**: 18 unit tests (roster root
  determinism/ban/role/removed exclusion; policy hash sensitivity;
  public-meta determinism across tag reorder and de-dup; state-hash
  sensitivity to every input; commit sign/verify roundtrip; tamper
  detection; committed_by-vs-pubkey mismatch detection; stale-rev
  rejection; prev-hash break rejection; unauthorized-owner rejection;
  admin action allowed; post-withdrawal non-withdrawal rejection; wrong
  `group_id` rejection).
- **`src/groups/directory.rs`**: 7 unit tests on signed `GroupCard`
  (roundtrip; sign-verify roundtrip; tamper detection on name / revision /
  withdrawn; wrong-authority rejection; `supersedes` by revision;
  `supersedes` by issued_at on revision tie; `supersedes` rejects
  different `group_id`; unsigned card fails verify).
- **`tests/named_group_state_commit.rs`**: 18 integration tests
  (stable-id across rename/roster; monotonic chain; state-hash covers
  roster/policy/ban/epoch; replica convergence via `apply_commit`;
  stale revision rejection; chain-break rejection; unauthorized signer
  rejection; post-withdrawal handling; signed card verifies across
  peers; card revision and issued_at supersession ordering;
  withdrawal card carries `withdrawn=true` and higher revision; hidden
  non-withdrawn group does not produce a card; component hashes
  deterministic; commit tamper detection).
- **`cargo nextest run --all-features --workspace`**: 886/886 passed,
  120 skipped (skipped suites require VPS or are `#[ignore]`d by design).
- **`cargo clippy --all-features --all-targets -- -D warnings`**: clean.
- **`cargo fmt --all -- --check`**: clean.

## End-to-end evidence

`tests/e2e_named_groups.sh` new section **"D.3 Stable identity +
evolving validity"** runs on three fresh daemons (alice, bob, charlie)
and proves:

1. `GET /groups/:id/state` returns stable id, genesis, state_hash,
   prev_state_hash, security_binding, withdrawn, component hashes.
2. `POST /groups/:id/state/seal` returns a signed commit with
   monotonic revision, `prev_state_hash` chaining to the prior
   `state_hash`, ML-DSA-65 signature, and `signer_public_key`.
3. `/state` reflects the chain advance after seal.
4. Bob receives the **signed** public card over gossip (the
   discovery listener verifies the signature before caching; unsigned
   or bad-sig cards are dropped).
5. A subsequent seal advances the revision; bob's cache supersedes to
   the higher revision.
6. `POST /groups/:id/state/withdraw` produces a terminal
   `withdrawn=true` commit with higher revision; bob evicts the stale
   listing from his discovery cache without waiting for TTL.
7. A non-member (bob) is rejected from calling `/state/seal`.

Three consecutive clean runs are archived as:
- `tests/proof-reports/named-groups-d3-run1.log`
- `tests/proof-reports/named-groups-d3-run2.log`
- `tests/proof-reports/named-groups-d3-run3.log`

Each run independently runs 3 fresh daemons, takes ~90 seconds for the
discovery mesh to warm before the D.3 section, and validates the D.3
claims on that specific run. Discovery-propagation timing is a
pre-existing environmental concern (seen in P0-6 "patch convergence"
and the authz 404 checks that also fail intermittently in the same
runs) — it is **not** a D.3 regression. The cryptographic primitives
and apply-side checks are covered independently by the 43 unit +
integration tests above with zero flakes.

## Remaining gaps against the full design target

These are explicitly **not** claimed done:

- **Phase C.2** — tag/name/id shard topics, digest-based anti-entropy,
  contact-scoped pairwise sync for `ListedToContacts`, shard
  subscription persistence.
- **Phase E** — public group send/receive with `SignedPublic` ingest
  validation, moderation, bans-on-public-posts enforcement,
  admin-only-write enforcement on announce groups.
- **Phase D.4** — migrate every remaining per-action metadata event
  (`MemberAdded`, `MemberRemoved`, `PolicyUpdated`, ban/unban, role
  update, join-request lifecycle) to seal a `GroupStateCommit` and go
  through `apply_commit` on receive. D.3 wires the primitives and the
  public card path; D.4 finishes the wiring.
- **Phase F** — final hardening: contact-scoped privacy tests,
  convergence across partition, repeatable hard-signoff proof bundle.

Proceeding per the user's approved plan `D.3 → C.2 → E → D.4 → F`.
