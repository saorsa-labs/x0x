# ADR 0015: No App-Layer At-Rest Encryption or Secondary Passwords

- **Status:** Accepted (2026-06-10, approved by David Irvine)
- **Date:** 2026-06-10
- **Decision owners:** David Irvine
- **Reviewers:** x0x maintainers
- **Supersedes:** none
- **Superseded by:** none
- **Related:** PR #88 (encrypted KvStore design — explicitly scopes at-rest
  encryption out), PR #87 (KvStore `Encrypted` policy guardrail)

## Context

x0x stores local state in the user's home directory (`~/.x0x/`): ML-DSA-65
identity keys (`machine.key`, `agent.key`, `user.key`), agent certificates,
the KV store cache, group state, and TreeKEM epoch secrets. The encrypted
KvStore design discussion (PR #88) raised the question of whether x0x should
also encrypt this local data at rest, which would imply some form of
passphrase or unlock step.

The tension:

- x0xd is an **unattended daemon**. It starts at boot, restarts itself during
  self-upgrade, and runs headless on VPS nodes. A passphrase-protected store
  means either a human types a password at every daemon start (which breaks
  the always-on agent model and is impossible on headless nodes), or the
  decryption key is stored on disk next to the encrypted data (which provides
  no real protection).
- Once an attacker executes code in the user's session, app-layer at-rest
  encryption is moot: they can read decrypted state from the running daemon's
  memory or simply query the daemon's own localhost REST API. OS user
  isolation is the boundary; when it is broken, *all* of the user's local
  data is exposed, not just x0x's.
- Stolen or disposed hardware is already covered by full-disk encryption
  (FileVault is on by default on modern macOS; LUKS/BitLocker equivalents
  exist elsewhere).
- Mainstream desktop apps do not prompt for secondary passwords outside of
  dedicated password managers and wallets. Adding one would be a significant
  UX regression for marginal protection.

What app-layer measures *can* still address, without any password prompt, are
the dumb exfiltration paths: backups (Time Machine), cloud-sync folders
accidentally covering `~/.x0x`, file-grab malware that copies home
directories without executing in the user's session, and other local users
on shared machines. The asset that matters most for those paths is not the
KV cache — it is the ML-DSA secret keys and group epoch secrets, whose
compromise is silent, durable, network-wide identity theft rather than a
local data leak.

## Decision Drivers

- Unattended daemon lifecycle: boot start, self-upgrade restarts, headless
  VPS deployments with no user session or OS keystore.
- UX: no secondary passwords; match platform norms.
- Honest threat modelling: do not ship encryption that a live attacker in
  the user's session trivially bypasses, and do not imply protection we do
  not provide.
- Key material (identity keys, epoch secrets) has a different blast radius
  than cached data and may deserve stronger handling where it costs nothing.

## Considered Options

1. **Passphrase-encrypted local store.** Strong against offline file theft,
   but breaks unattended startup and headless nodes, or degrades into
   key-next-to-data theater. Significant UX cost.
2. **No app-layer at-rest encryption; rely on OS user isolation and
   full-disk encryption.** Zero UX cost. Honest: the local cache is exactly
   as protected as the rest of the user's data. Leaves backup/sync
   exfiltration of key files unaddressed.
3. **Option 2, plus best-effort OS-keystore wrapping of identity key files**
   (macOS Keychain/Secure Enclave, Windows DPAPI, Linux libsecret) where a
   user session exists, with the current plain-file format as the fallback
   for headless nodes. No prompt, no password — keys unlock with the user's
   login session. This is the pattern Signal Desktop adopted after its
   key-next-to-database approach was criticised.

## Decision

We adopt **Option 2 now, with Option 3 as an explicitly sanctioned future
enhancement**:

- x0x will **not** implement app-layer at-rest encryption for the KV cache,
  group state, or other daemon data, and will **never** require a secondary
  password or unlock step. Local confidentiality at rest is delegated to OS
  user isolation and full-disk encryption.
- Key files under `~/.x0x/` remain plain files with owner-only permissions.
  Wrapping them with the platform keystore (no prompt, file fallback for
  headless) is a sanctioned follow-up if and when it is prioritised; it must
  remain invisible to users and optional for headless deployments.
- Documentation must state plainly that local x0x state is protected by the
  OS, not by x0x — including the caveat that a group's end-to-end
  confidentiality on the wire does not extend to members' local disks and
  backups. This matches the honesty direction of the KvStore `Encrypted`
  policy guardrail (PR #87).
- Encrypted-on-gossip work (PR #88) is unaffected: that design concerns
  transport confidentiality for group-scoped sync, not local storage.

## Consequences

### Positive

- No UX regression: no passwords, no unlock prompts, daemon starts
  unattended everywhere including headless VPS nodes.
- Honest security posture: we do not ship encryption that fails against the
  attacker it implies protection from.
- Simpler storage code; no key-management lifecycle for local data.

### Negative / Trade-offs

- `~/.x0x` contents (including identity secret keys) are readable by
  anything running as the user, and travel in plaintext inside backups and
  cloud-synced folders until the keystore follow-up lands.
- A group's confidentiality is bounded by the weakest member's local disk
  hygiene; this must be documented rather than fixed at this layer.

### Neutral / Operational

- Users with stricter requirements can place `~/.x0x` on encrypted volumes
  or per-directory encryption of their choosing; nothing in x0x prevents it.
- The keystore follow-up (Option 3) can land later without a storage-format
  migration visible to applications.

## Validation

- No code path in x0x prompts for, stores, or derives a local-storage
  passphrase; CI grep/test can assert no such surface appears.
- Key and state files are created with owner-only permissions (0600/0700);
  covered by storage tests.
- `docs/` security/trust documentation states the local-storage threat model
  (OS isolation + full-disk encryption; local disks/backups are outside the
  group E2EE boundary).
- Revisit trigger: if x0x ever gains a desktop-first interactive mode where a
  user session is always present, re-evaluate Option 3 promotion to default
  via a superseding ADR.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without
human review**. Accepted ADRs are immutable: create a new superseding ADR
rather than editing an Accepted ADR.
