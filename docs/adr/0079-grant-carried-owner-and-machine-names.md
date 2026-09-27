# ADR 0079: Grant-Carried Owner and Machine Names as ADR-0074 §1 Name Defaults

<!-- File name: docs/adr/0079-grant-carried-owner-and-machine-names.md -->

- **Status:** Accepted
- **Accepted:** 2026-09-27 by David Irvine (grant-only design chosen 2026-09-27 (X0U3 announcement rejected); status change applied by Claude at his instruction)
- **Date:** 2026-09-27
- **Decision owners:** David Irvine (direction decided 2026-09-27, simplified to
  grant-only the same day; only David may accept)
- **Reviewers:** pending (cross-model review required before acceptance)
- **Supersedes:** none. It **amends the defaults in Accepted ADR-0074 §1** by
  supersession *if accepted*; ADR-0074 itself is not edited.
- **Superseded by:** none
- **Serves:** vision **R4** (connectivity better than Tailscale: names that work
  with no typing of hex ids) and **R5** (share a subset of my agents: a grantee
  can name what was shared with them)
- **Related:** ADR-0074 §1 (names); ADR-0070 §2 (`ShareGrant` format); ADR-0041
  (`OwnerEnrollment`, synced `machine_name`); ADR-0036 (`human_name`,
  `owner_name`); ADR-0077 (grant redelivery outbox); #960; slice-1 branch
  `feat/960-s1-names` (`src/names.rs`)

## Context

ADR-0074 §1 sets two defaults. When a `ShareGrant` is accepted, an owner label
defaults to "the announced `owner_name`". A shared machine is "labelled at
grant acceptance". Neither default can be computed today:

- No `owner_name` is announced. It exists only on signed agent cards
  (`src/groups/card.rs`, v2 domain). Cards are signed by the **agent** key and
  exchanged out of band.
- A `ShareGrant` (ADR-0070, `src/share_grant.rs`) carries only agent ids. It
  does not carry the owner's name or machine names.

So slice 1 binds owner petnames only from card import or explicitly. The
grantee labels shared machines by hand (`x0x names machine label`), and only
machines that host an active granted agent.

`ShareGrant` is strict positional bincode. It is decoded with
`reject_trailing_bytes`, then re-encoded to check the bytes are canonical, and
its signature covers a fixed `signed_bytes()` layout. **Appending a field
breaks every old verifier**: `#[serde(default)]` does not help, because
bincode is not self-describing. Old peers would refuse the grant: the ACK is
withheld and nothing is stored. A new carrier is therefore needed.

A new typed DM prefix also cannot go to old peers. An old peer sends an
unknown prefix to its generic DM inbox as a junk message and releases a
durable ACK. So a new envelope must go only to peers that advertise support
for it.

## Decision Drivers

- The ADR-0074 defaults must be computable with no typing.
- A name must never silently point at a key the user did not mean. ADR-0074
  §1 pins names at first use.
- Names must be bound to the owner **user** key, so they cannot be spoofed.
- Old peers must keep working, with no flag day.
- Add the least new wire under the ADR-0072 scope freeze, and expose the least
  to the network.

## Considered Options

1. **Append optional fields to `ShareGrant`.** Rejected: it breaks strict
   decoding and the signature on every old peer (see Context).
2. **A grant envelope that carries the unchanged v1 grant plus a separately
   signed names section (owner name and machine names).** It is sent only to
   grantees that advertise support. This option is chosen.
3. **A `ShareGrant` v2 with one new signature over the v1 fields plus names.**
   Rejected. One `grant_id` would have two differently signed forms, so
   receivers would need conflict rules and the store format would change.
   Old owner daemons that enforce the grant would still need the v1 form.
4. **Also announce `owner_name` network-wide, in a user-signed `X0U3`
   `UserAnnouncement` envelope.** **Rejected by David Irvine on 2026-09-27.**
   It added a third wire element and exposed the name network-wide, for a
   small gain: the grant already carries the name to the only party that
   needs it.
5. **Take `owner_name` from the `X0A4` identity beat.** Rejected: the beat is
   machine-signed, not signed by the user key.

## Decision

### 1. The grant carries owner and machine names

- **Carrier:** a new typed DM. Its bytes are `x0x-sharegrant-v2\0` ‖ bincode
  of three fields:
  - `grant`: the unchanged v1 `ShareGrant` with its v1 signature.
  - `names`: `owner_name: Option<String>` and
    `machines: Vec<{machine_id, machine_name}>`.
  - `names_signature`.
- **owner_name:** the owner's ADR-0036 `human_name`, trimmed. It is 1–128
  bytes of UTF-8 with no control characters (as `SelfProfile::validate_name`).
- **machines:** the owner install lists each machine that has a synced
  `machine_name` and, by its own ADR-0041 enrollment and current
  announcements, hosts at least one of `grant.agents`.
  - Ids are sorted and unique, with at most `MAX_GRANT_AGENTS` (64) entries.
  - Names follow the `owner_name` limits.
  - The worst-case envelope is about 22 KiB, so the decode bound rises from
    32 to 48 KiB for this prefix only.
- **Signing:** the grant's owner **user** key signs
  `"x0x-sharegrant-names-v1" ‖ SHA-256(grant.signed_bytes()) ‖ owner_name ‖ machines`.
  The encoding uses length prefixes, fixed-width ids and a presence tag for
  `owner_name`. This binds the names to exactly this grant and to the key that
  `owner` hashes to. Names cannot be moved to another grant or attributed to
  another user.
- **Receiver:**
  - It verifies `grant` by the unchanged v1 rules, then verifies
    `names_signature` under `grant.owner_public_key`. If either fails, the
    whole envelope is refused: Malformed, ACK withheld.
  - It stores the grant in `share-grants.bin` byte-identical to a v1 delivery.
    A v1 copy and a v2 copy of one `grant_id` are therefore an idempotent
    `Duplicate`.
  - It puts the names only into the grantee's name store.
- **Who gets v2:**
  - Shared-agent daemons, which enforce the grant, always get v1.
  - Grantee agents get v2 only if they advertise a signed `share_grant_names`
    capability extension on `DM_CAPABILITY_DIGEST_TOPIC`. It is modelled on
    #448's `DigestSupportExtension`: the same agent key, the same
    agent+machine binding, and its own sign domain.
  - Any other or unknown grantee gets v1 and labels by hand, as in slice 1.
  - ADR-0077 outbox entries record the envelope version, and a retry resends
    the same bytes.
- **Opting out:** the owner can leave out names for a grant
  (`include_names: false`, CLI `--no-names`). That grant is sent as v1.
- **Freeze justification:** there are two new wire elements, the
  `x0x-sharegrant-v2` prefix and the capability extension. Both are
  point-to-point or capability metadata, and neither adds a network-wide
  broadcast of personal data. They are the minimum that makes the R4/R5 naming
  defaults work without breaking old peers.

### 2. These are defaults only (amends ADR-0074 §1)

"The announced `owner_name`" in ADR-0074 §1 is read as **the owner-signed
`owner_name` in the grant's names section**.

- **Label mapping:** the slice-1 `label_from_display` rule.
  - ASCII letters are lowercased.
  - Each run of whitespace, `_`, `.` or `-` becomes one `-`.
  - Leading and trailing separators are dropped.
  - There is **no default** if the name has any other character, the result
    is empty or longer than 63, or the result is reserved (`me`, `agent`,
    `machine`). The user then binds explicitly.
- **Owner label:** this default is considered only when a verified grant is
  stored or a signed card is imported, and only if that `UserId` has no
  petname yet. Sources, in order:
  1. The grant's names section.
  2. The signed card's `owner_name`.
- **Contact gate:** a stranger can send anyone a grant. So a default is applied
  directly only if the grant's owner is a Known or Trusted contact. Otherwise
  it is kept as a *suggestion*. The local owner applies it with one command
  (`x0x names accept <label>`).
- **Machine labels:** each listed machine with no label under that owner gets
  its default recorded with source `grant`. Resolution still applies the
  slice-1 check: the machine must currently host an active granted agent, or
  the name does not resolve.
- **No silent rebinding:** labels and pins stay frozen at first bind.
  - A default is **reported and not applied** in two cases: a later grant
    carries a different name, or the default's label is already bound to
    another key or machine.
  - These are reported as `default_conflict` in the grant-receipt result,
    `GET /names` and `x0x names list`.
  - Only the local owner rebinds, by removing the label first.

### 3. Privacy and visibility

- `owner_name` and machine names are **never broadcast**. They travel only
  inside the end-to-end encrypted grant DM. Only grantee agents that receive a
  v2 grant see them. Relays, other peers and non-capable grantees do not.
  Presence visibility (`Social`/`Network`) is not involved.
- A grant shows machine names only for machines that host the shared agents.
- `--no-names` per grant withholds both names, and that grant is sent as v1.

## Consequences

### Positive

- The ADR-0074 defaults become computable. A grantee gets `<agent>.<owner>`
  and `machine:<label>.<owner>` names with no typing, which serves R4 and R5.
- Names are bound to the owner user key and to one grant. Pins keep their
  first-use guarantee.
- Nothing personal is exposed network-wide.
- Old peers keep working unchanged, because they receive the v1 grant.

### Negative / Trade-offs

- There are two new wire elements under the ADR-0072 freeze.
- An owner who has granted nothing yields no owner-name default. The card
  fallback remains.
- A grantee that has not advertised support yet labels by hand until the
  owner re-issues the grant.
- A stranger can grant with a look-alike name. The contact gate and conflict
  reporting are the mitigation.
- A non-ASCII name gets no default until Unicode normalization is decided.

### Neutral / Operational

- The name store gains fields: `source` (`grant`, `card`, `explicit`) and
  pending suggestions. `GET /names` reports conflicts and suggestions.
- `share-grants.bin` does not change format. No profile or announcement
  changes.

## Validation

- **Grant envelope:**
  - The names signature binds the grant digest, so names swapped between
    grants fail.
  - A tampered `owner_name` or machine name fails.
  - v1 and v2 deliveries of one `grant_id` are `Duplicate`.
  - A grantee without the capability receives v1 only.
  - The 64-entry, 128-byte and 48 KiB bounds hold.
- **Name defaults:**
  - A default applies once and is never rebound.
  - A conflicting later name is reported, not applied.
  - A stranger's grant only yields a suggestion.
  - A machine default does not resolve after the grant is revoked or expires.
- **Mixed fleet (e2e):** an old grantee receives a v1 grant and keeps working.
- **Review triggers:**
  - reports of label squatting through look-alike names;
  - users needing owner names without any grant;
  - a Unicode-normalization decision.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human review**. Accepted ADRs are immutable: create a new superseding ADR rather than editing an Accepted ADR.
