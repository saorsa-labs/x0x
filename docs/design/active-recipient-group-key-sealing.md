# Active-Recipient Group-Key Sealing

- **Status:** Draft reference implementation
- **Governing decision:** [ADR 0027](../adr/0027-active-recipient-group-key-sealing.md)
- **Source baseline:** `e04b73a73fd44ebeb7af661bcf623dbd20b2f88e`

## Citation coordinates

Resolves at: `e04b73a73fd44ebeb7af661bcf623dbd20b2f88e`.

Repository-baseline citations in this chapter resolve at
`e04b73a73fd44ebeb7af661bcf623dbd20b2f88e`. Each later mechanism section
must carry its own `Resolves at:` pin to that baseline or a later exact source
commit.

## 1. Production predicate and contract

Resolves at: `e04b73a73fd44ebeb7af661bcf623dbd20b2f88e`.

Recipient selection establishes active membership before sealing. The
implementation removes the contradictory "known member" versus "active
member" comments so the contract is active membership.

The predicate runs in the authority-bearing recipient-selection path. It does
not move roster lookup into the shared, roster-agnostic
`seal_group_secret_to_recipient` primitive.

## 2. Inactive-versus-absent wire identity

Resolves at: `e04b73a73fd44ebeb7af661bcf623dbd20b2f88e`.

An existing but inactive roster entry returns HTTP 409 with a parseable
`reason: "recipient_not_active"`. An absent recipient retains the current HTTP
404 and `"recipient is not a member"` error.

The uniform `api_error` body gains an optional `reason` field. The addition is
backwards-compatible for existing consumers and supplies a durable identity;
a new prose sentence alone would not. Success behavior is unchanged.

## 3. Production-rule gate

Resolves at: `e04b73a73fd44ebeb7af661bcf623dbd20b2f88e`.

After terminal removal, the gate proves:

- Alice holds E+1;
- Bob's retained roster entry still has a usable KEM public key; and
- the same production reseal request succeeds for active Charlie.

Production reseal to Bob must then return HTTP 409 with
`reason: "recipient_not_active"` before sealing. A generic non-2xx is
insufficient because a missing key or secret later in the handler would pass
it.

## 4. Production mutation

Resolves at: `e04b73a73fd44ebeb7af661bcf623dbd20b2f88e`.

Change only the reseal recipient predicate from active membership back to the
current bare `members_v2.get` lookup, holding the gate prerequisites fixed.
The active-recipient condition must be the sole attributed catcher:
reseal-to-Bob reaches HTTP 200 instead of the designated inactive-recipient
identity.

One integration-test identity is compliant for this mutation set: active
pre-removal Bob and active Charlie satisfy both the active-membership predicate
and the bare-lookup mutation, while retained-but-Removed Bob is the only
divergence.

The executable receipt preserves the condition-attribution invariant: each
mutation arm violates one named condition and produces no other condition's
attribution. If that invariant breaks, repair the mutation or observation.
Splitting the fixture into multiple Rust test functions may improve failure
locality, but ADR 0025 does not require that topology.

## 5. Compile-time-exception evidence

Resolves at: `e04b73a73fd44ebeb7af661bcf623dbd20b2f88e`.

The Bob-lane integration-test call path itself chooses Bob as recipient for
current-epoch E+1 material and invokes the shared public
`seal_group_secret_to_recipient` primitive. That call path exists only in the
separate integration-test target and is not linked into the production daemon,
which the test drives as an external normal `x0xd`.

The evidence identifies that excluded test call path and its target boundary.
The shared roster-agnostic primitive remains compiled into and used by
production; it is not the object claimed by the exception. ADR 0025's
[governed chapter](./required-gates-observation-completeness.md) cross-links
this evidence when describing the control's observation purpose.

## 6. Deferred open-envelope product decision

Resolves at: `e04b73a73fd44ebeb7af661bcf623dbd20b2f88e`.

The production `/groups/secure/open-envelope` endpoint is documented as an
"ADVERSARIAL TEST endpoint," but is registered unconditionally and exposed
through the production CLI and GUI. This chapter does not preserve, restrict,
or remove it.

A follow-up product ADR will trace the authentication boundary and choose
keep, restrict, or compile-time-excluded test-only disposition. The
active-recipient production gate does not depend on this endpoint.

## 7. Acceptance-time recipient-selection accounting

Resolves at: `e04b73a73fd44ebeb7af661bcf623dbd20b2f88e`.

Grounding inventories the recipient-selection paths surveyed at the source
baseline. It is not the acceptance instrument for a universal rule.

At the acceptance commit, an executable receipt:

- derives the sealing-mechanism set by a stated, re-runnable rule: enumerate
  the complete public API surface of the group-key envelope module or modules
  (today `src/groups/kem_envelope.rs`), including associated functions and
  methods on public types; classify each surface entry carrying a signature
  as a sealing mechanism when that signature takes or returns group key
  material or recipient-openable ciphertext, and otherwise as out of scope;
  record each entry without a signature as out of scope by inapplicability;
  record the rule's output — the complete module surface and each entry's
  classification or inapplicability disposition — rather than accepting a
  typed mechanism list;
- discovers authority-bearing production call paths that choose the recipient,
  including paths that reach a sealing mechanism through a delegated wrapper;
- records the exact source path and function for every discovered call path;
- reconciles discovery and the recorded inventory in both directions; and
- accounts for each path exactly once as establishing active membership before
  sealing or as carrying evidence that the recipient-selecting path itself is
  excluded from production builds at compile time.

The check fails on an unaccounted discovered path, a recorded path absent from
discovery, a predicate after sealing, a predicate on the wrong recipient, or
an exception that proves only runtime unreachability. It must not assume that
`seal_group_secret_to_recipient` is the only sealing mechanism.

A differential control adds an otherwise valid production path through a
different named mechanism or delegated wrapper without the active-membership
predicate. The accounting check must fail and attribute that path; the
manual-reseal product gate may remain green.

## 8. Execution reachability and coverage status

Resolves at: `e04b73a73fd44ebeb7af661bcf623dbd20b2f88e`.

Active-recipient controls do not establish coverage merely by existing as
ignored tests, appearing in a test-list receipt, or having a hand-run command.
They count only after ADR 0025's single execution authority classifies every
identity and reaches the controls from each declared required context through
the registry-derived dispatcher and selector.

Until that reachability and closed outcome accounting exist, repository and CI
status must describe the active-recipient property as not covered. Landing an
ignored stub or CI-only job does not discharge ADR 0027 Validation and does not
make its status a merge gate.

---

## Extracted from ADR-0027 (2026-08-29)

> Relocated verbatim from the immutable ADR body per the 2026-08-23 ADR audit;
> this chapter is the maintained home for it.

### G-001 — Manual reseal selects a retained inactive roster entry

Resolves at:
`e04b73a73fd44ebeb7af661bcf623dbd20b2f88e`.

Supports: Context and Decision.

Removal marks Bob's `members_v2` entry `Removed` but retains the entry and KEM
key (`src/groups/mod.rs:972-978`). `secure_group_reseal` requires the caller
to be active but selects the recipient with a bare `members_v2.get`
(`src/server/routes/named_groups.rs:12459-12466`). At this pin, Alice can
therefore reseal her locally present current-epoch secret to removed Bob.

The production `secure/open-envelope` route has no roster lookup and rejects
only a withdrawn-group conflict before and after crypto
(`src/server/routes/named_groups.rs:10107-10113,10159-10173,12548-12598`).
An absent removed-self record is not withdrawn, so Bob can open that envelope
after terminal 404 and use the recovered key against survivor content. This
observation grounds the defect; the endpoint's product disposition remains
deferred.

---

### G-002 — Current local state retains one logical secret and epoch pair

Resolves at:
`e04b73a73fd44ebeb7af661bcf623dbd20b2f88e`.

Supports: the current-epoch scope.

`GroupInfo` retains one logical `shared_secret` / `secret_epoch` pair, not a
previous-secret collection; `rotate_shared_secret` replaces that pair with
the newly generated secret and incremented epoch
(`src/groups/mod.rs:143-149,418-436`).

Separately, the surveyed production GSS envelope producers expose no explicit
previous-epoch selection surface: the admin-remove and ban producers seal a
freshly rotated pair, while the approval and manual-reseal producers seal the
daemon's one locally present pair
(`src/server/routes/named_groups.rs:8595-8642,10499-10560,11050-11087,12472-12504`).
None of those surveyed producers accepts a caller-selected secret or epoch or
reads a historical-key source.

Re-review this boundary for every new or changed recipient-selecting path and
every new source of group key material, whether request input, persistence,
cache, derivation, or otherwise. A `GroupInfo` schema change is one trigger,
not the trigger.

---

### G-003 — The bounded survey does not establish global epoch currency

Resolves at:
`e04b73a73fd44ebeb7af661bcf623dbd20b2f88e`.

Supports: the current-epoch scope and Consequences.

`secure_group_reseal` reads one daemon's local record under its local lock and
does not consult a global-current oracle
(`src/server/routes/named_groups.rs:12451-12480`). In an asynchronous
multi-daemon system, its locally present pair may be older than another
daemon's accepted state.

A future explicit previous-epoch selector triggers the need for an
epoch-relative entitlement decision. Policy for a locally
stale-but-present pair is a separate consistency question that this
active-member rule does not answer.

---

### G-004 — The call path, not the primitive, holds recipient authority

Resolves at:
`e04b73a73fd44ebeb7af661bcf623dbd20b2f88e`.

Supports: Decision and the compile-time exception.

Public `seal_group_secret_to_recipient` has no group or roster input
(`src/groups/kem_envelope.rs:133-167`) and is called by the production manual
reseal handler
(`src/server/routes/named_groups.rs:12498-12504`). The primitive may therefore
remain shared and compiled into production; each production call path that
chooses its named recipient must establish active membership first.

---

### G-005 — Authentication does not erase the recipient-selection threat

Resolves at:
`e04b73a73fd44ebeb7af661bcf623dbd20b2f88e`.

Supports: Context, Decision Drivers, and the threat boundary in Validation.

The route sits behind router-wide authentication
(`src/server/mod.rs:1252-1259,1370-1374`), which accepts a durable bearer or
session token without a per-request agent identity
(`src/server/auth.rs:54-73`; `src/server/routes/tasks.rs:24-31`). The reseal
handler instead derives the acting member from the daemon's own agent
identity.

The guard therefore fails closed against accidental, buggy, and malicious
authenticated product requests that try to select an inactive recipient,
including an API client that does not possess the raw group secret. It does
not contain daemon/host compromise or any principal able to extract the secret
and invoke the roster-agnostic sealing primitive outside the guarded call
path, as the current handler documentation acknowledges
(`src/server/routes/named_groups.rs:12421-12424`).

The function comment says "known member" and matches the current code, while
the request-field comment says "active member." The implementation must remove
that contradictory contract when this decision lands.
