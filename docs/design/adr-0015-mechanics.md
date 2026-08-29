# ADR-0015 mechanics — at-rest encryption options, validation & AI-notes

> Extracted 2026-08-29 from the immutable [ADR 0015](../adr/0015-no-app-layer-at-rest-encryption.md) per the
> 2026-08-23 ADR audit. The ADR remains the complete decision record; the
> sections below are the considered options, validation inventory, and AI-work
> notes relocated verbatim so this file is their maintained home — future
> updates belong here, not in the ADR.

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

---

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

---

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without
human review**. Accepted ADRs are immutable: create a new superseding ADR
rather than editing an Accepted ADR.
