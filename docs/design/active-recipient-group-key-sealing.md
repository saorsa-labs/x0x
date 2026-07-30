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
  methods on public types; classify each surface entry as a sealing mechanism
  when its signature takes or returns group key material or
  recipient-openable ciphertext, and otherwise as out of scope, including
  entries without a signature; record the rule's output — the complete module
  surface and each entry's classification — rather than accepting a typed
  mechanism list;
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
